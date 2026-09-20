//! Async orchestration for the name-service app: verified reads (availability,
//! pricing, lifecycle status), the write flows (commit/reveal + renew +
//! set-recipient for the commit-reveal registrars, one-shot register for XNS),
//! reverse-lookup discovery and the cross-namespace search.
//!
//! ## Trust model
//!
//! Every read that gates a payment or an ownership claim goes through the
//! Helios-verified mainnet path ([`ens::verified_call_raw`]) and **fails closed**:
//! a value that didn't cross the light client's proof path is an `Err`, never a
//! number we send ETH against. All namespaces are pinned to [`Chain::Mainnet`]
//! regardless of the chain the wallet is viewing.
//!
//! ## Two registry families
//!
//! - **Commit-reveal** — ENS / GNS / WNS ([`registrar::Namespace`]): a two-tx
//!   commit→wait→reveal registration, an expiry + grace window, renewal, and a
//!   settable recipient (`setAddr`).
//! - **XNS** ([`super::xns`]): a single payable `registerName`, permanent +
//!   immutable + non-transferable names (no renew, no re-point), one name per
//!   address, and permissionless `label@namespace` namespaces.
//!
//! [`Registry`] is the unified handle the UI and coordinator pass around;
//! [`Registry::legacy`] bridges to [`registrar::Namespace`] for the commit-reveal
//! path.
//!
//! ## Discovery is reverse-lookup, not enumeration
//!
//! None of these registries is enumerable, so [`reverse_owned_names`] reads each
//! namespace's reverse record for the active account — the (single) primary name
//! that resolves *back* to it, forward-verified. Each hit is then re-checked
//! through [`name_status`] for its lifecycle facts.

use std::time::{SystemTime, UNIX_EPOCH};

use alloy::network::Ethereum;
use alloy::primitives::{Address, B256, Bytes, TxHash, U256};
use alloy::providers::RootProvider;

use crate::chain::Chain;
use crate::cow::onchain::send_contract_call;
use crate::names::ens::{self, verified_call_raw};
use crate::net::BalanceFetcher;
use crate::wallet::KaoSigner;

use super::registrar::{
    self, Namespace, RegisterPlan, decode_address, decode_bool, decode_price_pair, decode_u256,
};
use super::xns;

/// Default headroom (in basis points) added over a read price when sending a
/// register/renew transaction for the **commit-reveal** registrars. Absorbs ENS
/// Chainlink ETH/USD drift and GNS/WNS dutch-auction premium decay between the
/// price read and the mine; all three refund any excess, so this is a safety
/// margin, not a real cost. XNS prices are a fixed per-namespace storage value
/// (no oracle), so XNS sends the exact price with no buffer.
pub const PRICE_BUFFER_BPS: u16 = 300; // +3%

/// Current unix time in seconds. Centralized so the lifecycle math has one clock.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Add `bps` basis points of headroom to `total` (saturating).
fn with_buffer(total: U256, bps: u16) -> U256 {
    let extra = total.saturating_mul(U256::from(bps)) / U256::from(10_000u64);
    total.saturating_add(extra)
}

// ── unified registry handle ─────────────────────────────────────────────────

/// A namespace the wallet can search, register and manage — either one of the
/// three commit-reveal registrars or an XNS namespace (`xns`, `crops`, any
/// permissionless one). The single currency the UI and coordinator pass around.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registry {
    Ens,
    Gns,
    Wns,
    /// XNS `label@namespace`; the string is the (already lowercase, validated)
    /// XNS namespace, e.g. `"eth"` / `"xns"` / `"crops"`.
    Xns {
        namespace: String,
    },
}

impl Registry {
    /// The XNS namespaces shown by default in the cross-namespace search,
    /// alongside `.eth` / `.gwei` / `.wei`. Custom namespaces still work — they're
    /// reached by typing an explicit `label@namespace`.
    pub const XNS_DEFAULTS: [&'static str; 3] = ["eth", "xns", "crops"];

    /// The default search targets for a bare label: ENS, GNS, WNS and the
    /// shown XNS namespaces.
    pub fn defaults() -> Vec<Registry> {
        let mut v = vec![Registry::Ens, Registry::Gns, Registry::Wns];
        for ns in Registry::XNS_DEFAULTS {
            v.push(Registry::Xns {
                namespace: ns.to_string(),
            });
        }
        v
    }

    /// Bridge to the commit-reveal [`Namespace`]; `None` for XNS.
    pub fn legacy(&self) -> Option<Namespace> {
        match self {
            Registry::Ens => Some(Namespace::Ens),
            Registry::Gns => Some(Namespace::Gns),
            Registry::Wns => Some(Namespace::Wns),
            Registry::Xns { .. } => None,
        }
    }

    pub fn from_legacy(ns: Namespace) -> Registry {
        match ns {
            Namespace::Ens => Registry::Ens,
            Namespace::Gns => Registry::Gns,
            Namespace::Wns => Registry::Wns,
        }
    }

    pub fn is_xns(&self) -> bool {
        matches!(self, Registry::Xns { .. })
    }

    pub fn xns_namespace(&self) -> Option<&str> {
        match self {
            Registry::Xns { namespace } => Some(namespace),
            _ => None,
        }
    }

    /// Short uppercase badge (`"ENS"` / `"GNS"` / `"WNS"` / `"XNS"`).
    pub fn badge(&self) -> &'static str {
        match self {
            Registry::Ens => "ENS",
            Registry::Gns => "GNS",
            Registry::Wns => "WNS",
            Registry::Xns { .. } => "XNS",
        }
    }

    /// The suffix: `.eth` / `.gwei` / `.wei` for the registrars, or
    /// `@{namespace}` for XNS.
    pub fn tld(&self) -> String {
        match self {
            Registry::Ens => ".eth".to_string(),
            Registry::Gns => ".gwei".to_string(),
            Registry::Wns => ".wei".to_string(),
            Registry::Xns { namespace } => format!("@{namespace}"),
        }
    }

    /// `label` + this registry's suffix, e.g. `"vitalik.eth"` / `"rat@cheese"`.
    pub fn full_name(&self, label: &str) -> String {
        format!("{label}{}", self.tld())
    }

    /// The contract the registration transaction calls — the ENS/GNS/WNS
    /// controller (commit, then reveal/register), or the XNS registry. Shown in
    /// the pre-sign review so a user approving a blind-signing prompt on a
    /// hardware wallet can verify the destination, since the calldata itself
    /// isn't device-decodable.
    pub fn registrar_contract(&self) -> Address {
        match self {
            Registry::Ens => registrar::ENS_CONTROLLER,
            Registry::Gns => Namespace::Gns.nft_contract().expect("nft namespace"),
            Registry::Wns => Namespace::Wns.nft_contract().expect("nft namespace"),
            Registry::Xns { .. } => xns::XNS_REGISTRY,
        }
    }

    /// Commit-reveal registrars support renewal and re-pointing (`setAddr`); XNS
    /// names are permanent + immutable, so neither applies. Gates the Manage
    /// affordance, which offers both.
    pub fn supports_renew(&self) -> bool {
        self.legacy().is_some()
    }
    /// Whether registration needs the two-step commit→wait→reveal flow (true for
    /// ENS/GNS/WNS) versus a single transaction (false for XNS).
    pub fn is_commit_reveal(&self) -> bool {
        self.legacy().is_some()
    }

    /// A stable order for display/sorting: ENS, GNS, WNS, then XNS.
    fn rank(&self) -> u8 {
        match self {
            Registry::Ens => 0,
            Registry::Gns => 1,
            Registry::Wns => 2,
            Registry::Xns { .. } => 3,
        }
    }
}

// ── query parsing ───────────────────────────────────────────────────────────

/// A parsed search-bar query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    /// A bare label (no TLD) → search the [`Registry::defaults`] with it.
    Bare(String),
    /// An explicit `label.tld` or `label@namespace` → search just this one registry.
    One { registry: Registry, label: String },
}

/// Parse free search-bar input. A bare word becomes a cross-namespace
/// [`Query::Bare`]; `name.eth` / `name.gwei` / `name.wei` route to the matching
/// registrar; `name@namespace` routes to that XNS namespace (existence is
/// checked on-chain during the search). A dotted unknown TLD is rejected —
/// v2 XNS identifiers use `@`, not `.`.
pub fn parse_query(input: &str) -> Result<Query, String> {
    let t = input.trim();
    if t.is_empty() {
        return Err("type a name to search".to_string());
    }
    if t.contains('@') {
        let (label, namespace) = t.split_once('@').expect("contains @");
        if namespace.contains('@') {
            return Err("enter a single name, e.g. alice@xns".to_string());
        }
        if label.is_empty() {
            return Err("type a label before the @".to_string());
        }
        if namespace.is_empty() {
            return Err("type a namespace after the @".to_string());
        }
        let lc_ns = namespace.to_ascii_lowercase();
        if !xns::is_valid_label(&lc_ns) {
            return Err("that doesn't look like a valid namespace".to_string());
        }
        return Ok(Query::One {
            registry: Registry::Xns { namespace: lc_ns },
            label: label.to_string(),
        });
    }
    match t.rsplit_once('.') {
        None => Ok(Query::Bare(t.to_string())),
        Some((label, tld)) => {
            if label.is_empty() {
                return Err("type a label before the dot".to_string());
            }
            if label.contains('.') {
                return Err("enter a single label, e.g. vitalik.eth".to_string());
            }
            let lc_tld = tld.to_ascii_lowercase();
            let registry = match lc_tld.as_str() {
                "eth" => Registry::Ens,
                "gwei" => Registry::Gns,
                "wei" => Registry::Wns,
                _ => {
                    return Err("XNS names use @, e.g. alice@xns".to_string());
                }
            };
            Ok(Query::One {
                registry,
                label: label.to_string(),
            })
        }
    }
}

/// Parse an explicit single name (for manual "add a name you own"). Rejects bare
/// labels — the user must say which namespace.
pub fn parse_one_name(input: &str) -> Result<(Registry, String), String> {
    match parse_query(input)? {
        Query::One { registry, label } => Ok((registry, label)),
        Query::Bare(_) => Err("include a namespace, e.g. vitalik.eth or alice@xns".to_string()),
    }
}

/// Normalize a raw label for `registry`, applying the right rules: ENSIP-15 for
/// the commit-reveal registrars, XNS's `[a-z0-9-]` rules for XNS.
fn normalize_for(registry: &Registry, label: &str) -> Result<String, String> {
    if registry.is_xns() {
        xns::normalize_label(label)
            .ok_or_else(|| "labels are 1–20 chars, lowercase letters/digits/hyphens".to_string())
    } else {
        let n = ens::normalize(label)?;
        if n.is_empty() || n.contains('.') {
            return Err("enter a single label".to_string());
        }
        Ok(n)
    }
}

// ── availability + pricing (commit-reveal registrars) ───────────────────────

/// Whether `label` (bare, already normalized) is registerable right now in the
/// commit-reveal registrar `ns`.
pub async fn availability(
    net: &dyn BalanceFetcher,
    ns: Namespace,
    label: &str,
) -> Result<bool, String> {
    let (to, cd) = ns.availability_call(label);
    let out = verified_call_raw(net, to, cd).await?;
    Ok(decode_bool(&out))
}

/// A registration price quote, split so the UI can show base rent and any
/// temporary premium separately. For XNS, `base` is the flat namespace price,
/// `premium` is zero and `duration_secs` is 0 (names are permanent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterQuote {
    pub base: U256,
    pub premium: U256,
    pub total: U256,
    pub duration_secs: u64,
}

/// Verified registration cost for `label` in the commit-reveal registrar `ns`.
pub async fn register_quote(
    net: &dyn BalanceFetcher,
    ns: Namespace,
    label: &str,
    duration_secs: u64,
) -> Result<RegisterQuote, String> {
    let (to, cd) = ns.price_call(label, duration_secs);
    let priced = verified_call_raw(net, to, cd).await?;
    let (base, premium) = match ns {
        Namespace::Ens => decode_price_pair(&priced),
        Namespace::Gns | Namespace::Wns => {
            let fee = decode_u256(&priced);
            let premium = match ns.premium_call(label) {
                Some((pto, pcd)) => decode_u256(&verified_call_raw(net, pto, pcd).await?),
                None => U256::ZERO,
            };
            (fee, premium)
        }
    };
    Ok(RegisterQuote {
        base,
        premium,
        total: base.saturating_add(premium),
        duration_secs,
    })
}

/// Verified renewal cost for `label` in `ns` (renewals never pay the premium).
pub async fn renew_quote(
    net: &dyn BalanceFetcher,
    ns: Namespace,
    label: &str,
    duration_secs: u64,
) -> Result<U256, String> {
    let (to, cd) = ns.price_call(label, duration_secs);
    let priced = verified_call_raw(net, to, cd).await?;
    Ok(match ns {
        Namespace::Ens => decode_price_pair(&priced).0,
        Namespace::Gns | Namespace::Wns => decode_u256(&priced),
    })
}

// ── lifecycle status ────────────────────────────────────────────────────────

/// Where a name sits in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameState {
    /// Never registered (or fully expired and released).
    Unregistered,
    /// Registered and currently resolving.
    Active,
    /// Past expiry but inside the grace window — owner-only renewal; doesn't
    /// resolve. (Commit-reveal registrars only.)
    Grace,
    /// Permanent and immutable — an XNS name, which never expires.
    Permanent,
}

/// Classify a commit-reveal name from its expiry timestamp.
pub fn name_state(expires_at: u64, now: u64, grace: u64) -> NameState {
    if expires_at == 0 {
        return NameState::Unregistered;
    }
    if now <= expires_at {
        NameState::Active
    } else if now <= expires_at.saturating_add(grace) {
        NameState::Grace
    } else {
        NameState::Unregistered
    }
}

/// One owned/queried name with its verified on-chain facts.
#[derive(Debug, Clone)]
pub struct NameStatus {
    pub registry: Registry,
    /// Bare, normalized label (no TLD).
    pub label: String,
    /// Beautified full name for display, e.g. `vitalik.eth` / `rat@crops`.
    pub full: String,
    /// Expiry timestamp (unix seconds); `None` for permanent (XNS) names, 0 if
    /// unregistered.
    pub expires_at: Option<u64>,
    /// Clock the lifecycle was evaluated against.
    pub now: u64,
    /// Current owner / registrant, if the name exists.
    pub owner: Option<Address>,
    /// Address the name currently resolves to (may differ from `owner` for the
    /// commit-reveal registrars; always equals `owner` for immutable XNS names).
    pub recipient: Option<Address>,
}

impl NameStatus {
    pub fn state(&self) -> NameState {
        match self.expires_at {
            None => {
                if self.owner.is_some() {
                    NameState::Permanent
                } else {
                    NameState::Unregistered
                }
            }
            Some(exp) => name_state(exp, self.now, registrar::GRACE_PERIOD),
        }
    }

    /// Seconds until expiry (0 once expired or for permanent names).
    pub fn seconds_remaining(&self) -> u64 {
        self.expires_at
            .map(|e| e.saturating_sub(self.now))
            .unwrap_or(0)
    }

    pub fn owned_by(&self, who: Address) -> bool {
        self.owner == Some(who)
    }
}

/// Verified lifecycle + ownership + recipient for `label` in `registry`.
pub async fn name_status(
    net: &dyn BalanceFetcher,
    registry: &Registry,
    label: &str,
) -> Result<NameStatus, String> {
    match registry.legacy() {
        Some(ns) => legacy_name_status(net, ns, label).await,
        None => xns_name_status(net, registry.xns_namespace().unwrap_or(""), label).await,
    }
}

/// Status for a commit-reveal name. Expiry is fail-closed (it gates renewal);
/// owner + recipient are best-effort (tolerate a revert / unset record → `None`).
async fn legacy_name_status(
    net: &dyn BalanceFetcher,
    ns: Namespace,
    label: &str,
) -> Result<NameStatus, String> {
    let now = now_secs();
    let (eto, ecd) = ns.expiry_call(label);
    let expires_at = decode_u256(&verified_call_raw(net, eto, ecd).await?);
    let expires_at: u64 = expires_at.try_into().unwrap_or(u64::MAX);

    let (oto, ocd) = ns.owner_of_call(label);
    let owner = match verified_call_raw(net, oto, ocd).await {
        Ok(b) => {
            let a = decode_address(&b);
            (a != Address::ZERO).then_some(a)
        }
        Err(_) => None,
    };

    let full = format!("{label}{}", ns.tld());
    let recipient = super::resolve_name(net, &full).await.ok().flatten();

    Ok(NameStatus {
        registry: Registry::from_legacy(ns),
        label: label.to_string(),
        full: ens::beautify(&full),
        expires_at: Some(expires_at),
        now,
        owner,
        recipient,
    })
}

/// Status for an XNS name. There's no expiry/owner-of: the forward `getAddress`
/// *is* the owner (1:1, non-transferable) and the recipient (immutable), so one
/// verified read gives both. A zero address means unregistered.
async fn xns_name_status(
    net: &dyn BalanceFetcher,
    namespace: &str,
    label: &str,
) -> Result<NameStatus, String> {
    let now = now_secs();
    let (to, cd) = xns::get_address_call(label, namespace);
    let addr = decode_address(&verified_call_raw(net, to, cd).await?);
    let owner = (addr != Address::ZERO).then_some(addr);
    Ok(NameStatus {
        registry: Registry::Xns {
            namespace: namespace.to_string(),
        },
        label: label.to_string(),
        full: format!("{label}@{namespace}"),
        expires_at: None,
        now,
        owner,
        // XNS names are immutable: the resolved address is the owner.
        recipient: owner,
    })
}

// ── cross-namespace search ──────────────────────────────────────────────────

/// The outcome of checking one `label.registry` candidate.
#[derive(Debug, Clone)]
pub enum HitStatus {
    /// Free to register (with a price quote, when one could be read).
    Available { quote: Option<RegisterQuote> },
    /// Already registered. `owner` is populated for XNS (free from the read) and
    /// `None` for the registrars (the UI cross-references its owned list).
    Taken { owner: Option<Address> },
    /// Can't be offered: invalid label, namespace missing, private/exclusive, or
    /// a read failure. Carries a short human-readable reason.
    Unavailable { reason: String },
}

/// One row of the cross-namespace search.
#[derive(Debug, Clone)]
pub struct SearchHit {
    pub registry: Registry,
    /// Normalized label (as it would be registered/resolved).
    pub label: String,
    /// Full display name, e.g. `rat@crops`.
    pub full: String,
    pub status: HitStatus,
}

/// Check `label` across `registries` concurrently, one [`SearchHit`] each (in the
/// same order). Never errors as a whole — a per-target failure becomes
/// [`HitStatus::Unavailable`] so the rest of the row set still renders.
pub async fn search(
    net: &dyn BalanceFetcher,
    label: &str,
    registries: Vec<Registry>,
) -> Vec<SearchHit> {
    let futures = registries.into_iter().map(|r| search_one(net, r, label));
    futures::future::join_all(futures).await
}

async fn search_one(net: &dyn BalanceFetcher, registry: Registry, raw_label: &str) -> SearchHit {
    // Normalize for the registry; an invalid label is reported in-row, not as a
    // dropped result.
    let label = match normalize_for(&registry, raw_label) {
        Ok(l) => l,
        Err(reason) => {
            return SearchHit {
                full: registry.full_name(raw_label),
                registry,
                label: raw_label.to_string(),
                status: HitStatus::Unavailable { reason },
            };
        }
    };
    let full = registry.full_name(&label);
    let status = match registry.legacy() {
        Some(ns) => legacy_search(net, ns, &label).await,
        None => xns_search(net, registry.xns_namespace().unwrap_or(""), &label).await,
    };
    SearchHit {
        registry,
        label,
        full,
        status,
    }
}

async fn legacy_search(net: &dyn BalanceFetcher, ns: Namespace, label: &str) -> HitStatus {
    let available = match availability(net, ns, label).await {
        Ok(a) => a,
        Err(_) => {
            return HitStatus::Unavailable {
                reason: "couldn't check — try again".to_string(),
            };
        }
    };
    if !available {
        return HitStatus::Taken { owner: None };
    }
    // Indicative 1-year price; the actual register reads the price fresh.
    let quote = register_quote(net, ns, label, registrar::ens_duration_secs(1))
        .await
        .ok();
    HitStatus::Available { quote }
}

async fn xns_search(net: &dyn BalanceFetcher, namespace: &str, label: &str) -> HitStatus {
    // One verified read gates existence + price + public/exclusivity. A revert
    // (nonexistent namespace) fails closed → "no such namespace".
    let (ito, icd) = xns::namespace_info_call(namespace);
    let info = match verified_call_raw(net, ito, icd).await {
        Ok(b) => match xns::decode_namespace_info(&b) {
            Some(i) => i,
            None => {
                return HitStatus::Unavailable {
                    reason: format!("no “@{namespace}” namespace"),
                };
            }
        },
        Err(_) => {
            return HitStatus::Unavailable {
                reason: format!("no “@{namespace}” namespace"),
            };
        }
    };
    let now = now_secs();
    if info.is_private {
        return HitStatus::Unavailable {
            reason: "private namespace — owner only".to_string(),
        };
    }
    if info.in_exclusivity(now) {
        return HitStatus::Unavailable {
            reason: "in exclusivity — owner only".to_string(),
        };
    }
    // Availability: getAddress == 0 (names are permanent + immutable).
    let (ato, acd) = xns::get_address_call(label, namespace);
    let addr = match verified_call_raw(net, ato, acd).await {
        Ok(b) => decode_address(&b),
        Err(_) => {
            return HitStatus::Unavailable {
                reason: "couldn't check — try again".to_string(),
            };
        }
    };
    if addr != Address::ZERO {
        return HitStatus::Taken { owner: Some(addr) };
    }
    HitStatus::Available {
        quote: Some(RegisterQuote {
            base: info.price,
            premium: U256::ZERO,
            total: info.price,
            duration_secs: 0, // permanent
        }),
    }
}

// ── reverse-lookup discovery ────────────────────────────────────────────────

/// Discover names that resolve to `owner` by reading each namespace's reverse
/// record — the primary name pointing *back* at the account, forward-verified.
/// Returns at most one name per namespace (that's all a reverse record holds);
/// names registered to the account but not set as a reverse record won't appear
/// (the UI offers manual add for those).
///
/// A per-namespace read failure degrades that namespace to "no name" rather than
/// failing the whole scan — discovery only hides names, never fabricates
/// ownership (every hit is re-verified through [`name_status`], whose own reads
/// fail closed).
pub async fn reverse_owned_names(
    net: &dyn BalanceFetcher,
    owner: Address,
) -> Result<Vec<NameStatus>, String> {
    let (ens_r, gns_r, wns_r, xns_r) = futures::future::join4(
        ens::lookup_address(net, owner),
        crate::names::gns::GNS.lookup_address(net, owner),
        crate::names::wns::WNS.lookup_address(net, owner),
        super::xns_lookup_address(net, owner),
    )
    .await;

    // Turn each reverse name into a (registry, bare-label) target.
    let mut targets: Vec<(Registry, String)> = Vec::new();
    // ENS: accept only `.eth` (the registrar's scope), normalized to its label.
    if let Ok(Some(name)) = &ens_r {
        let lc = name.to_ascii_lowercase();
        if let Some(stem) = lc.strip_suffix(".eth")
            && let Ok(label) = ens::normalize(stem)
            && !label.is_empty()
            && !label.contains('.')
        {
            targets.push((Registry::Ens, label));
        }
    }
    if let Ok(Some(name)) = &gns_r
        && let Some(label) = xns_or_legacy_label(Namespace::Gns, name)
    {
        targets.push((Registry::Gns, label));
    }
    if let Ok(Some(name)) = &wns_r
        && let Some(label) = xns_or_legacy_label(Namespace::Wns, name)
    {
        targets.push((Registry::Wns, label));
    }
    // XNS: `label@namespace`, already lowercase/validated by the reverse helper.
    if let Ok(Some(name)) = &xns_r
        && let Some((label, namespace)) = name.split_once('@')
    {
        targets.push((
            Registry::Xns {
                namespace: namespace.to_string(),
            },
            label.to_string(),
        ));
    }

    // Re-verify each on-chain; keep names the account still holds.
    let mut out: Vec<NameStatus> = Vec::new();
    for (registry, label) in targets {
        if let Ok(status) = name_status(net, &registry, &label).await
            && status.owner.is_some()
            && status.state() != NameState::Unregistered
        {
            out.push(status);
        }
    }
    out.sort_by(|a, b| {
        a.registry
            .rank()
            .cmp(&b.registry.rank())
            .then(a.full.cmp(&b.full))
    });
    Ok(out)
}

/// Normalize a GNS/WNS reverse-resolved name back to its bare label.
fn xns_or_legacy_label(ns: Namespace, name: &str) -> Option<String> {
    let lc = name.to_ascii_lowercase();
    let stem = ns.strip_tld(&lc);
    let label = ens::normalize(&stem).ok()?;
    (!label.is_empty() && !label.contains('.')).then_some(label)
}

// ── write flows ─────────────────────────────────────────────────────────────

async fn mainnet_provider(net: &dyn BalanceFetcher) -> Result<RootProvider<Ethereum>, String> {
    net.provider(Chain::Mainnet)
        .await
        .ok_or_else(|| "no Ethereum mainnet RPC configured".to_string())
}

// The `*_call_for` builders compute the `(to, value, calldata)` for each write
// (including any verified price/commitment read) WITHOUT broadcasting. The
// `submit_*` wrappers broadcast from an EOA via `send_contract_call`; the
// Safe-mode flow wraps the same tuple in a Mainnet `execTransaction` instead, so
// a name registered/renewed/repointed from a Safe is owned by the Safe (its
// address is the registrant baked into the commitment / the `msg.sender` the
// registrars and the resolver authorize against).

/// `(to, value, calldata)` for commit-reveal step 1: computes the commitment
/// on-chain (verified) and returns the `commit(commitment)` call.
pub async fn commit_call_for(
    net: &dyn BalanceFetcher,
    plan: &RegisterPlan,
) -> Result<(Address, U256, Bytes), String> {
    let (mto, mcd) = plan.namespace.make_commitment_call(plan);
    let commitment = registrar::decode_b256(&verified_call_raw(net, mto, mcd).await?);
    if commitment == B256::ZERO {
        return Err("could not compute commitment".to_string());
    }
    Ok(plan.namespace.commit_call(commitment))
}

/// `(to, value, calldata)` for commit-reveal step 2: reads the price (verified),
/// adds the safety buffer, and returns the reveal/register call with the value.
pub async fn register_call_for(
    net: &dyn BalanceFetcher,
    plan: &RegisterPlan,
) -> Result<(Address, U256, Bytes), String> {
    let quote = register_quote(net, plan.namespace, &plan.label, plan.duration_secs).await?;
    let value = with_buffer(quote.total, PRICE_BUFFER_BPS);
    Ok(plan.namespace.register_call(plan, value))
}

/// `(to, value, calldata)` for a one-shot XNS registration: confirms the
/// namespace is public + open and reads its exact price. XNS binds the name and
/// its resolution to `msg.sender`, immutably — so from a Safe the inner call's
/// `msg.sender` (the Safe) becomes the permanent owner.
pub async fn register_xns_call_for(
    net: &dyn BalanceFetcher,
    namespace: &str,
    label: &str,
) -> Result<(Address, U256, Bytes), String> {
    let (ito, icd) = xns::namespace_info_call(namespace);
    let info = xns::decode_namespace_info(&verified_call_raw(net, ito, icd).await?)
        .ok_or_else(|| "namespace not found".to_string())?;
    if !info.public_open(now_secs()) {
        return Err("this namespace isn't open for public registration".to_string());
    }
    // XNS price is a fixed storage value (no oracle) and excess is refunded —
    // send it exactly.
    Ok(xns::register_call(label, namespace, info.price))
}

/// `(to, value, calldata)` to renew ("prolong") a commit-reveal name.
pub async fn renew_call_for(
    net: &dyn BalanceFetcher,
    ns: Namespace,
    label: &str,
    duration_secs: u64,
) -> Result<(Address, U256, Bytes), String> {
    let cost = renew_quote(net, ns, label, duration_secs).await?;
    let value = with_buffer(cost, PRICE_BUFFER_BPS);
    Ok(ns.renew_call(label, duration_secs, value))
}

/// `(to, value, calldata)` to point a commit-reveal name at `recipient`. No
/// network read, no value — the resolver authorizes the caller against the
/// name's owner, so from a Safe the inner `msg.sender` must be that owner Safe.
pub fn set_recipient_call_for(
    ns: Namespace,
    label: &str,
    recipient: Address,
) -> (Address, U256, Bytes) {
    ns.set_addr_call(label, recipient)
}

/// Step 1 of commit-reveal registration: compute the commitment on-chain
/// (verified) and broadcast `commit(commitment)`. Returns the commit tx hash.
pub async fn submit_commit(
    net: &dyn BalanceFetcher,
    signer: &KaoSigner,
    plan: &RegisterPlan,
) -> Result<TxHash, String> {
    let provider = mainnet_provider(net).await?;
    let (to, value, cd) = commit_call_for(net, plan).await?;
    send_contract_call(&provider, signer, Chain::Mainnet, to, value, cd).await
}

/// Step 2 of commit-reveal registration: read the price (verified), add the
/// safety buffer, and broadcast the reveal/register with the value attached.
pub async fn submit_register(
    net: &dyn BalanceFetcher,
    signer: &KaoSigner,
    plan: &RegisterPlan,
) -> Result<TxHash, String> {
    let provider = mainnet_provider(net).await?;
    let (to, v, cd) = register_call_for(net, plan).await?;
    send_contract_call(&provider, signer, Chain::Mainnet, to, v, cd).await
}

/// One-shot XNS registration: re-read the namespace (verified) to confirm it's
/// public + open and to get the exact price, then broadcast `registerName` with
/// that price attached. The name is registered to (and resolves to) the signer —
/// XNS binds both to `msg.sender`, immutably.
pub async fn submit_register_xns(
    net: &dyn BalanceFetcher,
    signer: &KaoSigner,
    namespace: &str,
    label: &str,
) -> Result<TxHash, String> {
    let provider = mainnet_provider(net).await?;
    let (to, value, cd) = register_xns_call_for(net, namespace, label).await?;
    send_contract_call(&provider, signer, Chain::Mainnet, to, value, cd).await
}

/// Renew ("prolong") a commit-reveal name.
pub async fn submit_renew(
    net: &dyn BalanceFetcher,
    signer: &KaoSigner,
    ns: Namespace,
    label: &str,
    duration_secs: u64,
) -> Result<TxHash, String> {
    let provider = mainnet_provider(net).await?;
    let (to, v, cd) = renew_call_for(net, ns, label, duration_secs).await?;
    send_contract_call(&provider, signer, Chain::Mainnet, to, v, cd).await
}

/// Point a commit-reveal name at `recipient`. No value sent.
pub async fn submit_set_recipient(
    net: &dyn BalanceFetcher,
    signer: &KaoSigner,
    ns: Namespace,
    label: &str,
    recipient: Address,
) -> Result<TxHash, String> {
    let provider = mainnet_provider(net).await?;
    let (to, v, cd) = set_recipient_call_for(ns, label, recipient);
    send_contract_call(&provider, signer, Chain::Mainnet, to, v, cd).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CallMock;
    use alloy::primitives::{Bytes, address};

    fn bool_word(b: bool) -> Bytes {
        let mut w = [0u8; 32];
        w[31] = b as u8;
        Bytes::from(w.to_vec())
    }

    fn addr_word(a: Address) -> Bytes {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(a.as_slice());
        Bytes::from(w.to_vec())
    }

    /// ABI-encode a `string` return: offset(0x20) + length + padded bytes.
    fn abi_string(s: &str) -> Bytes {
        let b = s.as_bytes();
        let mut buf = Vec::new();
        let mut off = [0u8; 32];
        off[31] = 0x20;
        buf.extend_from_slice(&off);
        let mut len = [0u8; 32];
        len[24..].copy_from_slice(&(b.len() as u64).to_be_bytes());
        buf.extend_from_slice(&len);
        buf.extend_from_slice(b);
        let pad = (32 - b.len() % 32) % 32;
        buf.resize(buf.len() + pad, 0);
        Bytes::from(buf)
    }

    /// The real on-chain XNS name `wehi@crops` and the address it resolves to.
    /// Pinned so the forward / reverse / discovery paths are exercised against a
    /// concrete, registered name rather than only synthetic fixtures.
    const WEHI: Address = address!("0xa1491eFf7CaC231440C8C0E6FaC043D8965C451f");
    fn crops() -> Registry {
        Registry::Xns {
            namespace: "crops".to_string(),
        }
    }

    // ── parsing ──────────────────────────────────────────────────────────────

    #[test]
    fn parse_query_routes_all_namespaces() {
        assert_eq!(parse_query("rat").unwrap(), Query::Bare("rat".to_string()));
        assert_eq!(
            parse_query("vitalik.eth").unwrap(),
            Query::One {
                registry: Registry::Ens,
                label: "vitalik".to_string()
            }
        );
        assert_eq!(
            parse_query("apoorv.gwei").unwrap(),
            Query::One {
                registry: Registry::Gns,
                label: "apoorv".to_string()
            }
        );
        // Arbitrary XNS namespace via `@`.
        assert_eq!(
            parse_query("rat@cheese").unwrap(),
            Query::One {
                registry: Registry::Xns {
                    namespace: "cheese".to_string()
                },
                label: "rat".to_string()
            }
        );
        assert_eq!(
            parse_query("alice@eth").unwrap(),
            Query::One {
                registry: Registry::Xns {
                    namespace: "eth".to_string()
                },
                label: "alice".to_string()
            }
        );
        assert!(parse_query("").is_err());
        assert!(parse_query(".eth").is_err());
        assert!(parse_query("a.b.eth").is_err(), "multi-dot label");
        assert!(
            parse_query("cow.crops").unwrap_err().contains('@'),
            "v1 dotted XNS shape must point at the new @"
        );
        assert!(parse_query("cow.NOT_A_NAMESPACE!").is_err());
        assert!(parse_query("@xns").is_err());
        assert!(parse_query("alice@").is_err());
        assert!(parse_query("a@b@c").is_err());
    }

    #[test]
    fn parse_one_name_requires_a_namespace() {
        assert!(parse_one_name("rat").is_err(), "bare label rejected");
        assert_eq!(
            parse_one_name("alice@xns").unwrap(),
            (
                Registry::Xns {
                    namespace: "xns".to_string()
                },
                "alice".to_string()
            )
        );
    }

    #[test]
    fn registry_capabilities_and_naming() {
        let ens = Registry::Ens;
        assert!(ens.is_commit_reveal() && ens.supports_renew());
        assert_eq!(ens.tld(), ".eth");
        assert_eq!(ens.full_name("vitalik"), "vitalik.eth");

        let xns = Registry::Xns {
            namespace: "crops".to_string(),
        };
        assert!(!xns.is_commit_reveal());
        assert!(!xns.supports_renew());
        assert_eq!(xns.tld(), "@crops");
        assert_eq!(xns.full_name("cow"), "cow@crops");
        assert_eq!(xns.badge(), "XNS");
        assert_eq!(xns.legacy(), None);
        assert_eq!(Registry::from_legacy(Namespace::Wns), Registry::Wns);
    }

    #[test]
    fn defaults_cover_six_namespaces() {
        let d = Registry::defaults();
        assert_eq!(d.len(), 6);
        assert!(d.contains(&Registry::Ens));
        assert!(d.contains(&Registry::Xns {
            namespace: "eth".to_string()
        }));
        assert!(d.contains(&Registry::Xns {
            namespace: "xns".to_string()
        }));
        assert!(d.contains(&Registry::Xns {
            namespace: "crops".to_string()
        }));
    }

    // ── lifecycle ────────────────────────────────────────────────────────────

    #[test]
    fn buffer_adds_basis_points() {
        let one = U256::from(1_000_000_000_000_000_000u128);
        assert_eq!(
            with_buffer(one, 300),
            one + one * U256::from(3u64) / U256::from(100u64)
        );
        assert_eq!(with_buffer(U256::ZERO, 300), U256::ZERO);
    }

    #[test]
    fn name_state_lifecycle_boundaries() {
        let grace = registrar::GRACE_PERIOD;
        assert_eq!(name_state(0, 100, grace), NameState::Unregistered);
        assert_eq!(name_state(100, 100, grace), NameState::Active);
        assert_eq!(name_state(100, 101, grace), NameState::Grace);
        assert_eq!(name_state(100, 100 + grace, grace), NameState::Grace);
        assert_eq!(name_state(100, 101 + grace, grace), NameState::Unregistered);
    }

    #[test]
    fn xns_namestatus_is_permanent() {
        let s = NameStatus {
            registry: Registry::Xns {
                namespace: "xns".to_string(),
            },
            label: "alice".to_string(),
            full: "alice@xns".to_string(),
            expires_at: None,
            now: now_secs(),
            owner: Some(address!("0x000000000000000000000000000000000000bEEF")),
            recipient: Some(address!("0x000000000000000000000000000000000000bEEF")),
        };
        assert_eq!(s.state(), NameState::Permanent);
        assert_eq!(s.seconds_remaining(), 0);
        // No owner → unregistered, even with a None expiry.
        let none = NameStatus {
            owner: None,
            ..s.clone()
        };
        assert_eq!(none.state(), NameState::Unregistered);
    }

    // ── verified reads ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn availability_decodes_bool() {
        let net = CallMock::new();
        let (to, cd) = Namespace::Gns.availability_call("apoorv");
        net.set_call(to, cd, bool_word(true), true);
        assert!(availability(&net, Namespace::Gns, "apoorv").await.unwrap());
    }

    #[tokio::test]
    async fn unverified_read_fails_closed() {
        let net = CallMock::new();
        let (to, cd) = Namespace::Wns.availability_call("z0r0z");
        net.set_call(to, cd, bool_word(true), false);
        assert!(availability(&net, Namespace::Wns, "z0r0z").await.is_err());
    }

    #[tokio::test]
    async fn xns_name_status_reports_owner_and_permanent() {
        let net = CallMock::new();
        let owner = address!("0x000000000000000000000000000000000000bEEF");
        let (to, cd) = xns::get_address_call("alice", "crops");
        net.set_call(to, cd, addr_word(owner), true);
        let r = Registry::Xns {
            namespace: "crops".to_string(),
        };
        let s = name_status(&net, &r, "alice").await.unwrap();
        assert_eq!(s.owner, Some(owner));
        assert_eq!(s.recipient, Some(owner), "XNS recipient == owner");
        assert_eq!(s.state(), NameState::Permanent);
        assert_eq!(s.full, "alice@crops");
    }

    #[tokio::test]
    async fn xns_search_available_quotes_namespace_price() {
        let net = CallMock::new();
        // Namespace info: price=1000, public, created long ago (not exclusive).
        let owner = address!("0x000000000000000000000000000000000000bEEF");
        let mut info = vec![0u8; 128];
        info[24..32].copy_from_slice(&1000u64.to_be_bytes()); // price (low bytes)
        info[44..64].copy_from_slice(owner.as_slice()); // owner
        info[88..96].copy_from_slice(&1u64.to_be_bytes()); // createdAt=1 (past exclusivity)
        info[127] = 0; // public
        let (ito, icd) = xns::namespace_info_call("crops");
        net.set_call(ito, icd, Bytes::from(info), true);
        // getAddress == 0 → available.
        let (ato, acd) = xns::get_address_call("cow", "crops");
        net.set_call(ato, acd, addr_word(Address::ZERO), true);

        let hits = search(
            &net,
            "cow",
            vec![Registry::Xns {
                namespace: "crops".to_string(),
            }],
        )
        .await;
        assert_eq!(hits.len(), 1);
        match &hits[0].status {
            HitStatus::Available { quote: Some(q) } => assert_eq!(q.total, U256::from(1000u64)),
            other => panic!("expected available with price, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn xns_search_taken_reports_owner() {
        let net = CallMock::new();
        let owner = address!("0x000000000000000000000000000000000000bEEF");
        let mut info = vec![0u8; 128];
        info[24..32].copy_from_slice(&1000u64.to_be_bytes());
        info[44..64].copy_from_slice(owner.as_slice());
        info[88..96].copy_from_slice(&1u64.to_be_bytes());
        let (ito, icd) = xns::namespace_info_call("crops");
        net.set_call(ito, icd, Bytes::from(info), true);
        let (ato, acd) = xns::get_address_call("cow", "crops");
        net.set_call(ato, acd, addr_word(owner), true); // taken by `owner`
        let hits = search(
            &net,
            "cow",
            vec![Registry::Xns {
                namespace: "crops".to_string(),
            }],
        )
        .await;
        assert!(matches!(
            hits[0].status,
            HitStatus::Taken { owner: Some(_) }
        ));
    }

    #[tokio::test]
    async fn xns_search_unknown_namespace_is_unavailable() {
        // getNamespaceInfo reverts (mock: unverified/empty) for a missing
        // namespace → fail-closed → Unavailable, never a wrong price.
        let net = CallMock::new();
        let hits = search(
            &net,
            "cow",
            vec![Registry::Xns {
                namespace: "ghost".to_string(),
            }],
        )
        .await;
        assert!(matches!(hits[0].status, HitStatus::Unavailable { .. }));
    }

    #[tokio::test]
    async fn legacy_register_quote_sums_base_and_premium() {
        let net = CallMock::new();
        let (to, cd) = Namespace::Ens.price_call("vitalik", registrar::YEAR_SECONDS);
        let mut ret = vec![0u8; 64];
        ret[31] = 5;
        ret[63] = 2;
        net.set_call(to, cd, Bytes::from(ret), true);
        let q = register_quote(&net, Namespace::Ens, "vitalik", registrar::YEAR_SECONDS)
            .await
            .unwrap();
        assert_eq!(q.total, U256::from(7u64));
    }

    // ── the real wehi@crops ↔ 0xa149…451f mapping, both directions ───────────

    #[tokio::test]
    async fn wehi_crops_status_is_owned_and_permanent() {
        // Forward: name_status reads getAddress("wehi","crops"); the resolved
        // address IS the owner + recipient (XNS is immutable + non-transferable).
        let net = CallMock::new();
        let (to, cd) = xns::get_address_call("wehi", "crops");
        net.set_call(to, cd, addr_word(WEHI), true);
        let s = name_status(&net, &crops(), "wehi").await.unwrap();
        assert_eq!(s.full, "wehi@crops");
        assert_eq!(s.owner, Some(WEHI));
        assert_eq!(s.recipient, Some(WEHI));
        assert_eq!(s.state(), NameState::Permanent);
    }

    #[tokio::test]
    async fn reverse_lookup_discovers_wehi_crops() {
        // …and vice versa — the full reverse-discovery round-trip: addr →
        // getName → "wehi@crops", forward-verified, then re-checked via
        // name_status. ENS/GNS/WNS reverse legs are unmocked (no record), so XNS
        // is the only hit.
        let net = CallMock::new();
        let (gto, gcd) = xns::get_name_call(WEHI);
        net.set_call(gto, gcd, abi_string("wehi@crops"), true);
        let (fto, fcd) = xns::get_address_call("wehi", "crops");
        net.set_call(fto, fcd, addr_word(WEHI), true);

        let names = reverse_owned_names(&net, WEHI).await.unwrap();
        assert_eq!(names.len(), 1, "only the XNS name resolves back to WEHI");
        assert_eq!(names[0].full, "wehi@crops");
        assert_eq!(names[0].registry, crops());
        assert_eq!(names[0].owner, Some(WEHI));
        assert!(names[0].owned_by(WEHI));
    }
}
