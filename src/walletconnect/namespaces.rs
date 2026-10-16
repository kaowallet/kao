//! Proposal → [`ProposalPlan`]: which chains, methods and events a session gets, for exactly one
//! identity. Pure; [`plan_proposal`] is the only producer of [`Grant`].
//!
//! The crate's `build_approved_namespaces` has three traps this module exists to close:
//! it panics when `supported` is keyed by a chain-scoped key, it fails with 5103 for a
//! supported chain without an account, and an empty proposal grants *everything supported*. So
//! `supported` is only ever `{"eip155": <one identity on its served chains>}`, every chain gets that
//! identity's account, a proposal naming no Ethereum chain is refused before the crate sees it,
//! and the crate's answer is re-checked against the identity before it becomes a [`Grant`].

use std::collections::{BTreeMap, BTreeSet};

use wallet_connect::rpc::ErrorObject;
use wallet_connect::sign::namespaces::normalize;
use wallet_connect::sign::{
    Proposal, ProposalNamespace, ProposalNamespaces, SessionNamespaces, SupportedNamespace,
    build_approved_namespaces,
};

use super::types::*;
use super::{caip2, parse_eip155};
use crate::chain::Chain;
use crate::sanitize::sanitize_display;

pub const SERVED_METHODS: &[&str] = &[
    "personal_sign",
    "eth_signTypedData_v4",
    "eth_signTypedData",
    "eth_sendTransaction",
    "wallet_switchEthereumChain",
    "eth_accounts",
    "eth_requestAccounts",
    "eth_chainId",
];
/// Granted ONLY when the dapp *requires* them; refused per call (4200).
pub const REFUSED_METHODS: &[&str] = &[
    "eth_sign",
    "eth_signTransaction",
    "eth_signTypedData_v3",
    "eth_sendRawTransaction",
    "wallet_addEthereumChain",
    "wallet_watchAsset",
    "wallet_getCapabilities",
    "wallet_sendCalls",
    "wallet_getCallsStatus",
    "wallet_showCallsStatus",
    "wallet_grantPermissions",
    "wallet_getPermissions",
    "wallet_requestPermissions",
    "wallet_registerOnboarding",
    "wallet_scanQRCode",
    "eth_decrypt",
    "eth_getEncryptionPublicKey",
    "personal_ecRecover",
];
pub const EVENTS: &[&str] = &["accountsChanged", "chainChanged"];

const EIP155: &str = "eip155";
/// The approval card lists at most this many chain / method lines (a dapp can
/// ask for thousands); required and usable ones are kept first.
const MAX_PLAN_LINES: usize = 64;
/// Display bound for a dapp-supplied method/chain/namespace name.
const MAX_NAME_CHARS: usize = 48;

/// Bounds on what one proposal may name, over all its namespaces (required + optional). The plan
/// is computed on the UI thread on every mirror and the crate's `normalize` is quadratic, so a
/// proposal past any of them is refused before it is planned or shown. Generous for real dapps
/// (dozens of chains and methods), tiny next to the ≈ 50k chains one 1 MiB relay frame holds.
const MAX_PROPOSAL_NAMESPACES: usize = 64;
const MAX_PROPOSAL_CHAINS: usize = 512;
const MAX_PROPOSAL_METHODS: usize = 512;
const MAX_PROPOSAL_EVENTS: usize = 64;

const UNSERVED_CHAIN: &str = "Kao can't serve a chain this dapp requires.";
const TOO_LARGE: &str = "This connection request is too large for Kao to review.";
const NO_CHAIN: &str = "The dapp asked for no Ethereum chain.";
const NOTHING_IN_COMMON: &str = "Kao and this dapp have no chain in common.";

fn method_support(method: &str, caps: &IdentityCaps) -> MethodSupport {
    let capable = match method {
        "personal_sign" => caps.messages(),
        "eth_signTypedData_v4" | "eth_signTypedData" => caps.typed_data(),
        "eth_sendTransaction" => caps.transactions(),
        m if SERVED_METHODS.contains(&m) => Ok(()),
        m if REFUSED_METHODS.contains(&m) => return MethodSupport::Refused,
        _ => return MethodSupport::Unknown,
    };
    match capable {
        Ok(()) => MethodSupport::Served,
        Err(_) => MethodSupport::CapabilityRefused,
    }
}

/// Keyed ONLY "eip155"; only `caps.identity` on `chains ∩ caps.chains`.
///
/// One account per listed chain, so the crate's "no accounts for chain"
/// (5103) can't trigger; a Safe is additionally pinned to its own chain.
/// Methods are limited to the two policy lists (the caller decides which
/// refused ones a dapp required); events to [`EVENTS`].
fn supported_for(
    caps: &IdentityCaps,
    chains: &[u64],
    methods: &[String],
) -> BTreeMap<String, SupportedNamespace> {
    let mut ids: Vec<u64> = Vec::new();
    for &c in chains {
        if exposable(caps, c) && !ids.contains(&c) {
            ids.push(c);
        }
    }
    let mut granted: Vec<String> = Vec::new();
    for m in methods {
        let known = SERVED_METHODS.contains(&m.as_str()) || REFUSED_METHODS.contains(&m.as_str());
        if known && !granted.contains(m) {
            granted.push(m.clone());
        }
    }
    let ns = SupportedNamespace {
        chains: ids.iter().map(|c| caip2(*c)).collect(),
        methods: granted,
        events: EVENTS.iter().map(|e| e.to_string()).collect(),
        accounts: ids.iter().map(|c| caps.identity.caip10(*c)).collect(),
    };
    BTreeMap::from([(EIP155.to_string(), ns)])
}

/// The identity may appear on `chain`: served now, and — for a Safe — its own chain.
fn exposable(caps: &IdentityCaps, chain: u64) -> bool {
    caps.serves_chain(chain)
        && match caps.identity {
            WcIdentity::Eoa { .. } => true,
            WcIdentity::Safe { chain_id, .. } => chain_id == chain,
        }
}

/// A proposal past the [`MAX_PROPOSAL_CHAINS`]-style bounds: 5104 / 5100 / 5101 / 5102 by what
/// overflows. Counts list lengths only — O(namespaces), whatever the dapp sent.
pub fn proposal_too_large(p: &Proposal) -> Option<ProposalBlock> {
    let all = || {
        p.required_namespaces
            .values()
            .chain(p.optional_namespaces.values())
    };
    let namespaces = p.required_namespaces.len() + p.optional_namespaces.len();
    let chains: usize = all().map(|ns| ns.chains.as_ref().map_or(0, Vec::len)).sum();
    let methods: usize = all().map(|ns| ns.methods.len()).sum();
    let events: usize = all().map(|ns| ns.events.len()).sum();
    let reason = |n: usize, what: &str, max: usize| {
        format!("It names {n} {what}; Kao reviews at most {max}.")
    };
    if namespaces > MAX_PROPOSAL_NAMESPACES {
        let r = reason(namespaces, "namespaces", MAX_PROPOSAL_NAMESPACES);
        return Some(block(5104, TOO_LARGE, r));
    }
    if chains > MAX_PROPOSAL_CHAINS {
        let r = reason(chains, "chains", MAX_PROPOSAL_CHAINS);
        return Some(block(5100, TOO_LARGE, r));
    }
    if methods > MAX_PROPOSAL_METHODS {
        let r = reason(methods, "methods", MAX_PROPOSAL_METHODS);
        return Some(block(5101, TOO_LARGE, r));
    }
    if events > MAX_PROPOSAL_EVENTS {
        let r = reason(events, "events", MAX_PROPOSAL_EVENTS);
        return Some(block(5102, TOO_LARGE, r));
    }
    None
}

/// What connecting would grant `caps.identity` for this proposal, or the code that refuses it.
/// Pure; the only producer of `Grant`.
pub fn plan_proposal(
    p: &Proposal,
    caps: &IdentityCaps,
    chain_label: &dyn Fn(u64) -> String,
) -> ProposalPlan {
    // Bounded before anything else touches it (the book never shows such a card either).
    if let Some(block) = proposal_too_large(p) {
        return ProposalPlan {
            identity: caps.identity,
            identity_label: caps.label.clone(),
            chains: Vec::new(),
            methods: Vec::new(),
            caveats: Vec::new(),
            verdict: Err(block),
        };
    }
    let required = normalize(&p.required_namespaces);
    let optional = normalize(&p.optional_namespaces);
    let none = ProposalNamespace::default();
    let req = Requested::of(required.get(EIP155).unwrap_or(&none));
    let opt = Requested::of(optional.get(EIP155).unwrap_or(&none));

    let verdict = decide(&required, &req, &opt, caps, chain_label);
    let granted: &[u64] = match &verdict {
        Ok(g) => &g.chains,
        Err(_) => &[],
    };
    ProposalPlan {
        identity: caps.identity,
        identity_label: caps.label.clone(),
        chains: chain_lines(&req, &opt, caps, granted, chain_label),
        methods: method_lines(&req, &opt, caps),
        caveats: caveats(caps, &req, &opt),
        verdict,
    }
}

/// One normalized eip155 namespace, its chain refs parsed strictly.
struct Requested<'a> {
    ns: &'a ProposalNamespace,
    /// Valid `eip155:N` chains, in the dapp's order, deduplicated.
    chains: Vec<u64>,
    /// Refs that aren't canonical `eip155:N` (dropped when optional, fatal when required).
    bad: Vec<&'a str>,
}

impl<'a> Requested<'a> {
    fn of(ns: &'a ProposalNamespace) -> Self {
        let mut chains = Vec::new();
        let mut seen = BTreeSet::new();
        let mut bad = Vec::new();
        for c in ns.chains.as_deref().unwrap_or_default() {
            match parse_eip155(c) {
                Some(id) if seen.insert(id) => chains.push(id),
                Some(_) => {}
                None => bad.push(c.as_str()),
            }
        }
        Self { ns, chains, bad }
    }

    fn has_method(&self, m: &str) -> bool {
        self.ns.methods.iter().any(|x| x == m)
    }

    /// The namespace as handed to the crate: only the valid chains, canonical.
    fn for_crate(&self) -> ProposalNamespace {
        ProposalNamespace {
            chains: Some(self.chains.iter().map(|c| caip2(*c)).collect()),
            methods: self.ns.methods.clone(),
            events: self.ns.events.clone(),
        }
    }
}

fn block(code: i64, message: &'static str, reason: impl Into<String>) -> ProposalBlock {
    ProposalBlock {
        code,
        message,
        reason: sanitize_display(&reason.into(), 240).into_owned(),
    }
}

fn shown(s: &str) -> String {
    sanitize_display(s, MAX_NAME_CHARS).into_owned()
}

fn decide(
    required: &ProposalNamespaces,
    req: &Requested<'_>,
    opt: &Requested<'_>,
    caps: &IdentityCaps,
    chain_label: &dyn Fn(u64) -> String,
) -> Result<Grant, ProposalBlock> {
    // 2. A required non-Ethereum namespace can't be satisfied.
    if let Some(key) = required.keys().find(|k| k.as_str() != EIP155) {
        return Err(block(
            5104,
            "This dapp requires a non-Ethereum chain.",
            format!(
                "It requires the “{}” namespace; Kao connects Ethereum accounts only.",
                shown(key)
            ),
        ));
    }
    // 3. Requested chains; a required ref that isn't a chain id is fatal.
    if let Some(bad) = req.bad.first() {
        return Err(block(
            5100,
            UNSERVED_CHAIN,
            format!(
                "It requires “{}”, which isn't an Ethereum chain id.",
                shown(bad)
            ),
        ));
    }
    if req.chains.is_empty() && opt.chains.is_empty() {
        // Closes the crate's "nothing requested ⇒ grant everything" path.
        return Err(block(
            5100,
            NO_CHAIN,
            "The request names no Ethereum network to connect to.",
        ));
    }
    // 4. Every required chain must be one this identity can be exposed on.
    let missing: Vec<u64> = req
        .chains
        .iter()
        .copied()
        .filter(|c| !exposable(caps, *c))
        .collect();
    if !missing.is_empty() {
        return Err(block(
            5100,
            UNSERVED_CHAIN,
            missing_chains_reason(caps, &req.chains, &missing, chain_label),
        ));
    }
    // 5. Required methods must be known (served, or refused-but-grantable);
    //    required events must be ones Kao can emit.
    if let Some(m) =
        req.ns.methods.iter().find(|m| {
            !SERVED_METHODS.contains(&m.as_str()) && !REFUSED_METHODS.contains(&m.as_str())
        })
    {
        return Err(block(
            5101,
            "Kao doesn't support a method this dapp requires.",
            format!("It requires {}, which Kao doesn't support.", shown(m)),
        ));
    }
    if let Some(e) = req.ns.events.iter().find(|e| !EVENTS.contains(&e.as_str())) {
        return Err(block(
            5102,
            "Kao doesn't support an event this dapp requires.",
            format!(
                "It requires the {} event, which Kao doesn't emit.",
                shown(e)
            ),
        ));
    }

    // 6. What Kao offers: this identity on the requested chains it can serve;
    //    served methods the dapp asked for, plus refused ones it *requires* (so older
    //    dapps that list e.g. eth_sign as required still connect; those are refused per call).
    let mut chains: Vec<u64> = Vec::new();
    let mut seen = BTreeSet::new();
    for &c in req.chains.iter().chain(&opt.chains) {
        if exposable(caps, c) && seen.insert(c) {
            chains.push(c);
        }
    }
    let mut methods: Vec<String> = Vec::new();
    for m in req.ns.methods.iter().chain(&opt.ns.methods) {
        let grantable = SERVED_METHODS.contains(&m.as_str())
            || (REFUSED_METHODS.contains(&m.as_str()) && req.has_method(m));
        // Grantable names come from two short fixed lists, so `methods` stays tiny.
        if grantable && !methods.contains(m) {
            methods.push(m.clone());
        }
    }
    let supported = supported_for(caps, &chains, &methods);

    // 7. The crate builds the namespaces from eip155-only, chain-filtered input.
    let mut req_ns = ProposalNamespaces::new();
    if required.contains_key(EIP155) {
        req_ns.insert(EIP155.to_string(), req.for_crate());
    }
    let mut opt_ns = ProposalNamespaces::new();
    if !opt.chains.is_empty() {
        opt_ns.insert(EIP155.to_string(), opt.for_crate());
    }
    if req_ns.is_empty() && opt_ns.is_empty() {
        return Err(block(
            5100,
            NO_CHAIN,
            "The request names no Ethereum network to connect to.",
        ));
    }
    let mut ns = match build_approved_namespaces(&req_ns, &opt_ns, &supported) {
        Ok(ns) => ns,
        Err(e) => {
            // Steps 2–5 pre-check everything the crate checks; reaching this is a bug.
            tracing::error!(
                code = e.code,
                "walletconnect: the crate refused a pre-checked proposal"
            );
            return Err(block(
                5100,
                UNSERVED_CHAIN,
                "Kao couldn't match what this dapp requires.",
            ));
        }
    };
    if ns.get(EIP155).is_none_or(|n| n.accounts.is_empty()) {
        let asked: Vec<String> = req
            .chains
            .iter()
            .chain(&opt.chains)
            .take(4)
            .map(|c| chain_label(*c))
            .collect();
        return Err(block(
            5100,
            NOTHING_IN_COMMON,
            format!(
                "It asked for {}; none of them is available for {}.",
                asked.join(", "),
                caps.label
            ),
        ));
    }

    // 8. The crate's answer must expose exactly this identity, on chains it
    //    can serve, with only policy methods and events.
    if !post_check(&ns, caps, req) {
        tracing::error!("walletconnect: approved namespaces failed Kao's post-check");
        return Err(block(
            5103,
            "Kao couldn't build a session for this dapp.",
            "Kao couldn't match its account to what this dapp asked for.",
        ));
    }

    // 9. The dapp's preferred chain first: the first required chain, else the
    //    first optional one (dapps take accounts[0] as the active address).
    let Some(granted) = ns.get_mut(EIP155) else {
        return Err(block(5100, NOTHING_IN_COMMON, "Nothing was granted."));
    };
    let granted_ids: Vec<u64> = granted
        .accounts
        .iter()
        .filter_map(|a| account_chain(a))
        .collect();
    if let Some(&pref) = req
        .chains
        .iter()
        .chain(&opt.chains)
        .find(|c| granted_ids.contains(c))
    {
        to_front(&mut granted.accounts, &caps.identity.caip10(pref));
        if let Some(chains) = granted.chains.as_mut() {
            to_front(chains, &caip2(pref));
        }
    }
    let grant = Grant {
        chains: granted
            .accounts
            .iter()
            .filter_map(|a| account_chain(a))
            .collect(),
        methods: granted.methods.clone(),
        events: granted.events.clone(),
        namespaces: ns,
    };
    Ok(grant)
}

fn to_front(v: &mut Vec<String>, item: &str) {
    if let Some(i) = v.iter().position(|x| x == item) {
        let x = v.remove(i);
        v.insert(0, x);
    }
}

/// `eip155:<id>:<address>` → id (strict).
fn account_chain(account: &str) -> Option<u64> {
    let (chain, _address) = account.rsplit_once(':')?;
    parse_eip155(chain)
}

fn post_check(ns: &SessionNamespaces, caps: &IdentityCaps, req: &Requested<'_>) -> bool {
    if ns.len() != 1 {
        return false;
    }
    let Some(n) = ns.get(EIP155) else {
        return false;
    };
    if n.accounts.is_empty() {
        return false;
    }
    let account_ok = |a: &String| {
        account_chain(a).is_some_and(|c| exposable(caps, c) && *a == caps.identity.caip10(c))
    };
    let chains = n.chains.as_deref().unwrap_or_default();
    let chain_ok = |c: &String| {
        parse_eip155(c)
            .is_some_and(|id| exposable(caps, id) && n.accounts.contains(&caps.identity.caip10(id)))
    };
    let method_ok = |m: &String| {
        SERVED_METHODS.contains(&m.as_str())
            || (REFUSED_METHODS.contains(&m.as_str()) && req.has_method(m))
    };
    n.accounts.iter().all(account_ok)
        && chains.iter().all(chain_ok)
        && n.methods.iter().all(method_ok)
        && n.events.iter().all(|e| EVENTS.contains(&e.as_str()))
}

/// "Ethereum, Base and 2 more".
fn chain_list(chains: &[u64], chain_label: &dyn Fn(u64) -> String) -> String {
    let labels: Vec<String> = chains.iter().take(4).map(|c| chain_label(*c)).collect();
    let more = chains.len().saturating_sub(labels.len());
    let mut list = labels.join(", ");
    if more > 0 {
        list.push_str(&format!(" and {more} more"));
    }
    list
}

fn missing_chains_reason(
    caps: &IdentityCaps,
    required: &[u64],
    missing: &[u64],
    chain_label: &dyn Fn(u64) -> String,
) -> String {
    let list = chain_list(missing, chain_label);
    match caps.identity {
        // A Safe is on one network, so no Safe serves a dapp that requires several.
        WcIdentity::Safe { .. } if required.len() > 1 => format!(
            "It requires {}. A Safe connects on its own network only — connect an account (not a \
             Safe) instead.",
            chain_list(required, chain_label)
        ),
        // Kao keeps Safes on its built-in networks only.
        WcIdentity::Safe { chain_id, .. }
            if missing.iter().all(|&id| Chain::from_chain_id(id).is_some()) =>
        {
            format!(
                "It requires {list}, but this Safe is on {} — switch to a Safe or account on \
                 {list}.",
                chain_label(chain_id)
            )
        }
        WcIdentity::Safe { chain_id, .. } => format!(
            "It requires {list}, but this Safe is on {} — connect an account on {list} instead \
             (add it under Settings › Networks).",
            chain_label(chain_id)
        ),
        WcIdentity::Eoa { .. } if missing.len() == 1 => {
            format!("It requires {list} — add it under Settings › Networks.")
        }
        WcIdentity::Eoa { .. } => {
            format!("It requires {list} — add them under Settings › Networks.")
        }
    }
}

fn chain_lines(
    req: &Requested<'_>,
    opt: &Requested<'_>,
    caps: &IdentityCaps,
    granted: &[u64],
    chain_label: &dyn Fn(u64) -> String,
) -> Vec<ChainLine> {
    let mut lines: Vec<ChainLine> = Vec::new();
    let mut seen = BTreeSet::new();
    let required: BTreeSet<u64> = req.chains.iter().copied().collect();
    let granted: BTreeSet<u64> = granted.iter().copied().collect();
    for &id in req.chains.iter().chain(&opt.chains) {
        if !seen.insert(id) {
            continue;
        }
        let label = if exposable(caps, id) {
            chain_label(id)
        } else {
            format!("{} (not available)", chain_label(id))
        };
        lines.push(ChainLine {
            chain_id: id,
            label: sanitize_display(&label, MAX_NAME_CHARS).into_owned(),
            required: required.contains(&id),
            granted: granted.contains(&id),
            unverified: Chain::from_chain_id(id).is_none(),
        });
    }
    if lines.len() > MAX_PLAN_LINES {
        lines.retain(|l| l.required || l.granted);
        lines.truncate(MAX_PLAN_LINES);
    }
    lines
}

fn method_lines(req: &Requested<'_>, opt: &Requested<'_>, caps: &IdentityCaps) -> Vec<MethodLine> {
    let mut lines: Vec<MethodLine> = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let required: BTreeSet<&str> = req.ns.methods.iter().map(String::as_str).collect();
    for m in req.ns.methods.iter().chain(&opt.ns.methods) {
        if !seen.insert(m.as_str()) {
            continue;
        }
        lines.push(MethodLine {
            name: shown(m),
            required: required.contains(m.as_str()),
            support: method_support(m, caps),
        });
    }
    if lines.len() > MAX_PLAN_LINES {
        lines.retain(|l| l.required || l.support != MethodSupport::Unknown);
        lines.truncate(MAX_PLAN_LINES);
    }
    lines
}

/// What the user should know before connecting, for what the dapp asked for.
fn caveats(caps: &IdentityCaps, req: &Requested<'_>, opt: &Requested<'_>) -> Vec<String> {
    let asks = |m: &str| req.has_method(m) || opt.has_method(m);
    let typed = asks("eth_signTypedData_v4") || asks("eth_signTypedData");
    let messages = typed || asks("personal_sign");
    let txs = asks("eth_sendTransaction");
    let mut out = Vec::new();
    match &caps.kind {
        IdentityKind::Eoa(EoaCaps {
            kind: EoaKind::Ledger,
            ..
        }) if typed => out.push(
            "Your Ledger shows only hashes for typed data — Kao shows the same fingerprints \
             to compare."
                .to_string(),
        ),
        IdentityKind::Eoa(EoaCaps {
            kind: EoaKind::Trezor,
            ..
        }) if typed => out.push(
            "Kao can't sign typed data with a Trezor — those requests will be refused.".to_string(),
        ),
        IdentityKind::Eoa(_) => {}
        IdentityKind::Safe(s) => {
            if let Some(why) = &s.signing_block {
                out.push(format!(
                    "This Safe can't sign from Kao: {}",
                    sanitize_display(why, 160)
                ));
                return out;
            }
            if messages && !s.fallback_handler {
                out.push(
                    "This Safe's fallback handler can't validate message signatures \
                     (EIP-1271), so it can't sign messages."
                        .to_string(),
                );
            } else if messages && s.local_signers < s.threshold {
                out.push(format!(
                    "Message signatures need {} owner keys in Kao; Kao holds {}.",
                    s.threshold, s.local_signers
                ));
            }
            if txs && s.local_signers == 0 {
                out.push("Kao holds none of this Safe's owner keys.".to_string());
            } else if txs && s.local_signers < s.threshold {
                out.push(format!(
                    "Kao holds {} of the {} owner keys this Safe needs: transactions will be \
                     proposed to co-signers.",
                    s.local_signers, s.threshold
                ));
            }
        }
    }
    out
}

pub fn proposal_reject_error(block: &ProposalBlock) -> ErrorObject {
    ErrorObject::new(block.code, block.message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::walletconnect::testkit;
    use alloy::primitives::{Address, address};
    use wallet_connect::crypto::{PublicKey, Topic};
    use wallet_connect::sign::{Metadata, Participant, Relay};

    const ADDR: Address = address!("ab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb");
    const SAFE: Address = address!("1111111111111111111111111111111111111111");

    // The crate's own test fixtures (tests/common/mod.rs), adapted.
    const TEST_ETHEREUM_CHAIN: &str = "eip155:1";
    const TEST_ARBITRUM_CHAIN: &str = "eip155:42161";
    const TEST_AVALANCHE_CHAIN: &str = "eip155:43114";
    const TEST_CHAINS: [&str; 2] = [TEST_ETHEREUM_CHAIN, TEST_ARBITRUM_CHAIN];
    const TEST_METHODS: [&str; 4] = [
        "eth_sendTransaction",
        "eth_signTransaction",
        "personal_sign",
        "eth_signTypedData",
    ];
    const TEST_EVENTS: [&str; 2] = ["chainChanged", "accountsChanged"];

    fn eoa(kind: EoaKind, chains: &[u64]) -> IdentityCaps {
        testkit::eoa_caps(ADDR, kind, false, chains)
    }

    fn local(chains: &[u64]) -> IdentityCaps {
        eoa(EoaKind::Local, chains)
    }

    fn safe(threshold: u32, local_signers: u32) -> IdentityCaps {
        testkit::safe_identity_caps(SAFE, 1, threshold, 3, local_signers)
    }

    fn ns(chains: &[&str], methods: &[&str], events: &[&str]) -> ProposalNamespace {
        ProposalNamespace::new(
            chains.iter().copied(),
            methods.iter().copied(),
            events.iter().copied(),
        )
    }

    fn map(entries: Vec<(&str, ProposalNamespace)>) -> ProposalNamespaces {
        entries
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect()
    }

    fn proposal(required: ProposalNamespaces, optional: ProposalNamespaces) -> Proposal {
        Proposal {
            id: 7,
            pairing_topic: Topic::new("ab".repeat(32)),
            expiry_timestamp: 1_000,
            relays: vec![Relay::default()],
            proposer: Participant {
                public_key: PublicKey::from_bytes([3; 32]),
                metadata: Metadata::new("Dapp", "", "https://dapp.example"),
            },
            required_namespaces: required,
            optional_namespaces: optional,
            session_properties: None,
            scoped_properties: None,
        }
    }

    fn label(id: u64) -> String {
        match id {
            1 => "Ethereum".into(),
            10 => "OP Mainnet".into(),
            8453 => "Base".into(),
            42161 => "Arbitrum".into(),
            other => format!("Chain {other}"),
        }
    }

    fn plan(p: &Proposal, caps: &IdentityCaps) -> ProposalPlan {
        plan_proposal(p, caps, &label)
    }

    fn grant(p: &Proposal, caps: &IdentityCaps) -> Grant {
        match plan(p, caps).verdict {
            Ok(g) => g,
            Err(b) => panic!("expected a grant, got {b:?}"),
        }
    }

    fn blocked(p: &Proposal, caps: &IdentityCaps) -> ProposalBlock {
        match plan(p, caps).verdict {
            Ok(g) => panic!("expected a block, got {g:?}"),
            Err(b) => b,
        }
    }

    fn accounts(g: &Grant) -> Vec<String> {
        g.namespaces["eip155"].accounts.clone()
    }

    fn acct(chain: u64) -> String {
        format!("eip155:{chain}:{}", ADDR.to_checksum(None))
    }

    fn modern(chains: &[&str]) -> Proposal {
        proposal(
            ProposalNamespaces::new(),
            map(vec![("eip155", ns(chains, SERVED_METHODS, EVENTS))]),
        )
    }

    #[test]
    fn plan_exposes_only_the_active_identity() {
        let caps = local(&[1, 8453, 10]);
        let g = grant(&modern(&["eip155:1", "eip155:8453"]), &caps);
        assert_eq!(g.namespaces.len(), 1);
        assert_eq!(accounts(&g), vec![acct(1), acct(8453)]);
        assert_eq!(g.chains, vec![1, 8453]);
        // A Safe identity exposes the Safe — never an owner EOA.
        let g = grant(&modern(&["eip155:1"]), &safe(1, 1));
        assert_eq!(
            accounts(&g),
            vec![format!("eip155:1:{}", SAFE.to_checksum(None))]
        );
    }

    #[test]
    fn plan_never_grants_unserved_chains() {
        let caps = local(&[1, 8453]);
        let p = modern(&["eip155:1", "eip155:42161", "eip155:8453"]);
        let plan = plan(&p, &caps);
        let g = plan.verdict.clone().unwrap();
        assert_eq!(g.chains, vec![1, 8453]);
        assert!(!accounts(&g).iter().any(|a| a.starts_with("eip155:42161:")));
        let arb = plan.chains.iter().find(|l| l.chain_id == 42161).unwrap();
        assert!(!arb.granted && !arb.required && arb.unverified);
        assert_eq!(arb.label, "Arbitrum (not available)");
        let base = plan.chains.iter().find(|l| l.chain_id == 8453).unwrap();
        assert!(base.granted && !base.unverified);
        assert_eq!(base.label, "Base");
    }

    #[test]
    fn plan_rejects_required_non_eip155_with_5104() {
        let p = proposal(
            map(vec![
                ("eip155", ns(&["eip155:1"], &["personal_sign"], &[])),
                (
                    "solana",
                    ns(
                        &["solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ"],
                        &["solana_signMessage"],
                        &[],
                    ),
                ),
            ]),
            ProposalNamespaces::new(),
        );
        let b = blocked(&p, &local(&[1]));
        assert_eq!(b.code, 5104);
        assert_eq!(b.message, "This dapp requires a non-Ethereum chain.");
        assert_eq!(proposal_reject_error(&b), ErrorObject::new(5104, b.message));
    }

    #[test]
    fn plan_ignores_optional_non_eip155_without_panic() {
        let p = proposal(
            ProposalNamespaces::new(),
            map(vec![
                (
                    "eip155",
                    ns(&["eip155:1"], &["personal_sign"], &["chainChanged"]),
                ),
                (
                    "solana",
                    ns(&["solana:mainnet"], &["solana_signMessage"], &[]),
                ),
                (
                    "polkadot",
                    ns(&["polkadot:91b171bb158e2d3848fa23a9f1c25182"], &[], &[]),
                ),
            ]),
        );
        let g = grant(&p, &local(&[1]));
        assert_eq!(g.namespaces.keys().collect::<Vec<_>>(), vec!["eip155"]);
        assert_eq!(g.methods, vec!["personal_sign"]);
        // Only non-eip155 optional namespaces: nothing to offer, refused — not "grant everything".
        let only_sol = proposal(
            ProposalNamespaces::new(),
            map(vec![("solana", ns(&["solana:mainnet"], &[], &[]))]),
        );
        assert_eq!(blocked(&only_sol, &local(&[1])).code, 5100);
    }

    #[test]
    fn plan_normalizes_inline_chain_keys() {
        let mut inline = ns(&[], &["personal_sign"], &["chainChanged"]);
        inline.chains = None;
        let mut inline_opt = ns(&[], &["eth_sendTransaction"], &[]);
        inline_opt.chains = None;
        let p = proposal(
            map(vec![("eip155:1", inline)]),
            map(vec![("eip155:8453", inline_opt)]),
        );
        let g = grant(&p, &local(&[1, 8453]));
        assert_eq!(g.chains, vec![1, 8453]);
        assert_eq!(g.namespaces.keys().collect::<Vec<_>>(), vec!["eip155"]);
        assert_eq!(g.methods, vec!["personal_sign", "eth_sendTransaction"]);
        assert_eq!(g.events, vec!["chainChanged"]);
    }

    #[test]
    fn plan_rejects_empty_proposal() {
        let empty = proposal(ProposalNamespaces::new(), ProposalNamespaces::new());
        let b = blocked(&empty, &local(&[1, 8453]));
        assert_eq!(b.code, 5100);
        assert_eq!(b.message, "The dapp asked for no Ethereum chain.");
        // An eip155 namespace that names no valid chain is just as empty.
        let no_chains = proposal(
            ProposalNamespaces::new(),
            map(vec![(
                "eip155",
                ns(&["eip155:01", "eip155:"], SERVED_METHODS, EVENTS),
            )]),
        );
        assert_eq!(blocked(&no_chains, &local(&[1])).code, 5100);
        // Requested chains that exist but none served: refused, nothing granted.
        let b = blocked(&modern(&["eip155:42161"]), &local(&[1]));
        assert_eq!(b.code, 5100);
        assert_eq!(b.message, "Kao and this dapp have no chain in common.");
    }

    #[test]
    fn safe_plan_rejects_required_other_chain() {
        let caps = safe(1, 1);
        let p = proposal(
            map(vec![(
                "eip155",
                ns(&["eip155:8453"], &["personal_sign"], &[]),
            )]),
            ProposalNamespaces::new(),
        );
        let b = blocked(&p, &caps);
        assert_eq!(b.code, 5100);
        assert!(
            b.reason.contains("this Safe is on Ethereum"),
            "{}",
            b.reason
        );
        assert!(b.reason.contains("Base"), "{}", b.reason);
        // Optional other chains are simply not granted; the Safe gets its own chain only.
        let g = grant(&modern(&["eip155:8453", "eip155:1", "eip155:10"]), &caps);
        assert_eq!(g.chains, vec![1]);
        // A Safe identity can't leak onto another chain even if caps claim it.
        let mut wide = caps.clone();
        wide.chains = vec![1, 8453];
        assert_eq!(
            grant(&modern(&["eip155:8453", "eip155:1"]), &wide).chains,
            vec![1]
        );
    }

    /// A Safe connects on its own network only, so no Safe can serve a dapp that requires two:
    /// the advice names every required network and points to an account — never to a Safe on
    /// the other network, whose card would then send the user back.
    #[test]
    fn safe_blocked_by_several_required_chains_points_to_an_account() {
        let p = proposal(
            map(vec![(
                "eip155",
                ns(&["eip155:1", "eip155:8453"], &["personal_sign"], &[]),
            )]),
            ProposalNamespaces::new(),
        );
        for caps in [safe(1, 1), testkit::safe_identity_caps(SAFE, 8453, 1, 3, 1)] {
            let b = blocked(&p, &caps);
            assert_eq!(b.code, 5100);
            assert!(
                b.reason.contains("Ethereum") && b.reason.contains("Base"),
                "{}",
                b.reason
            );
            assert!(
                b.reason.contains("connect an account (not a Safe)"),
                "{}",
                b.reason
            );
            assert!(!b.reason.contains("switch to"), "{}", b.reason);
        }
    }

    /// A dapp requiring a network no Safe in Kao can be on (only built-in ones can) is pointed to
    /// an account on it, and to adding that network first — never to a Safe there.
    #[test]
    fn safe_blocked_by_a_chain_no_safe_can_be_on_points_to_an_account() {
        let p = proposal(
            map(vec![(
                "eip155",
                ns(&["eip155:42161"], &["personal_sign"], &[]),
            )]),
            ProposalNamespaces::new(),
        );
        let b = blocked(&p, &safe(1, 1));
        assert_eq!(b.code, 5100);
        assert!(
            b.reason.contains("this Safe is on Ethereum"),
            "{}",
            b.reason
        );
        assert!(!b.reason.contains("a Safe or account"), "{}", b.reason);
        assert!(b.reason.contains("Settings › Networks"), "{}", b.reason);
        assert!(b.reason.contains("account on"), "{}", b.reason);
    }

    #[test]
    fn refused_methods_granted_only_when_required() {
        let p = proposal(
            map(vec![(
                "eip155",
                ns(&["eip155:1"], &["personal_sign", "eth_sign"], &[]),
            )]),
            map(vec![(
                "eip155",
                ns(
                    &["eip155:1"],
                    &[
                        "eth_signTransaction",
                        "eth_sendTransaction",
                        "wallet_sendCalls",
                    ],
                    &[],
                ),
            )]),
        );
        let plan = plan(&p, &local(&[1]));
        let g = plan.verdict.clone().unwrap();
        assert!(
            g.methods.contains(&"eth_sign".to_string()),
            "required ⇒ granted"
        );
        assert!(g.methods.contains(&"eth_sendTransaction".to_string()));
        assert!(
            !g.methods.contains(&"eth_signTransaction".to_string()),
            "optional ⇒ not granted"
        );
        assert!(!g.methods.contains(&"wallet_sendCalls".to_string()));
        let line = |m: &str| plan.methods.iter().find(|l| l.name == m).unwrap().clone();
        assert_eq!(line("eth_sign").support, MethodSupport::Refused);
        assert!(line("eth_sign").required);
        assert_eq!(line("eth_signTransaction").support, MethodSupport::Refused);
        assert!(!line("eth_signTransaction").required);
    }

    #[test]
    fn unknown_required_method_is_5101() {
        let p = proposal(
            map(vec![(
                "eip155",
                ns(&["eip155:1"], &["personal_sign", "wallet_foo"], &[]),
            )]),
            ProposalNamespaces::new(),
        );
        let b = blocked(&p, &local(&[1]));
        assert_eq!(b.code, 5101);
        assert!(b.reason.contains("wallet_foo"));
        // An unknown required event is 5102; unknown optional ones are just not granted.
        let p = proposal(
            map(vec![("eip155", ns(&["eip155:1"], &[], &["message"]))]),
            ProposalNamespaces::new(),
        );
        assert_eq!(blocked(&p, &local(&[1])).code, 5102);
        let p = proposal(
            ProposalNamespaces::new(),
            map(vec![(
                "eip155",
                ns(&["eip155:1"], &["wallet_foo"], &["message"]),
            )]),
        );
        let g = grant(&p, &local(&[1]));
        assert!(g.methods.is_empty() && g.events.is_empty());
    }

    #[test]
    fn unsupported_required_chain_is_5100_naming_it() {
        let p = proposal(
            map(vec![(
                "eip155",
                ns(&["eip155:1", "eip155:42161"], &["personal_sign"], &[]),
            )]),
            ProposalNamespaces::new(),
        );
        let b = blocked(&p, &local(&[1]));
        assert_eq!(b.code, 5100);
        assert!(
            b.reason.contains("Arbitrum") && b.reason.contains("Settings"),
            "{}",
            b.reason
        );
        // A required ref that isn't a canonical chain id is 5100 too.
        let p = proposal(
            map(vec![("eip155", ns(&["eip155:01"], &[], &[]))]),
            ProposalNamespaces::new(),
        );
        assert_eq!(blocked(&p, &local(&[1])).code, 5100);
    }

    #[test]
    fn supported_is_keyed_eip155_only() {
        let caps = local(&[1, 8453]);
        let methods = vec![
            "personal_sign".to_string(),
            "made_up".to_string(),
            "eth_sign".to_string(),
        ];
        let s = supported_for(&caps, &[8453, 1, 42161, 1], &methods);
        assert_eq!(s.keys().collect::<Vec<_>>(), vec!["eip155"]);
        let n = &s["eip155"];
        assert_eq!(n.chains, vec!["eip155:8453", "eip155:1"]);
        assert_eq!(
            n.accounts,
            vec![acct(8453), acct(1)],
            "one account per chain"
        );
        assert_eq!(n.methods, vec!["personal_sign", "eth_sign"]);
        assert_eq!(n.events, vec!["accountsChanged", "chainChanged"]);
        // A Safe is pinned to its chain.
        let mut s = safe(1, 1);
        s.chains = vec![1, 8453];
        assert_eq!(
            supported_for(&s, &[1, 8453], &[])["eip155"].chains,
            vec!["eip155:1"]
        );
        // No servable chain: still keyed "eip155", just empty.
        let empty = supported_for(&caps, &[42161], &methods);
        assert!(empty["eip155"].chains.is_empty() && empty["eip155"].accounts.is_empty());
    }

    #[test]
    fn plan_never_echoes_session_properties() {
        let mut p = modern(&["eip155:1"]);
        let mut props = serde_json::Map::new();
        props.insert(
            "capabilities".into(),
            serde_json::json!("{\"secret\":\"dapp-data\"}"),
        );
        p.session_properties = Some(props.clone());
        p.scoped_properties = Some(props);
        let g = grant(&p, &local(&[1]));
        let json = serde_json::to_string(&g.namespaces).unwrap();
        assert!(
            !json.contains("capabilities") && !json.contains("secret"),
            "{json}"
        );
    }

    #[test]
    fn accounts_preferred_chain_first() {
        let caps = local(&[1, 10, 8453]);
        // Optional-only: the dapp's first listed chain leads.
        let g = grant(&modern(&["eip155:8453", "eip155:1"]), &caps);
        assert_eq!(accounts(&g)[0], acct(8453));
        assert_eq!(g.chains[0], 8453);
        assert_eq!(
            g.namespaces["eip155"].chains.as_ref().unwrap()[0],
            "eip155:8453"
        );
        // A required chain beats every optional one.
        let p = proposal(
            map(vec![(
                "eip155",
                ns(&["eip155:10"], &["personal_sign"], &[]),
            )]),
            map(vec![(
                "eip155",
                ns(&["eip155:1", "eip155:8453"], &["personal_sign"], &[]),
            )]),
        );
        let g = grant(&p, &caps);
        assert_eq!(accounts(&g)[0], acct(10));
        assert_eq!(g.chains, vec![10, 1, 8453]);
    }

    #[test]
    fn optional_only_modern_proposal_full_grant() {
        let caps = local(&[1, 8453, 10]);
        let g = grant(&modern(&["eip155:1", "eip155:8453", "eip155:10"]), &caps);
        assert_eq!(g.chains, vec![1, 8453, 10]);
        assert_eq!(g.methods, SERVED_METHODS.to_vec());
        assert_eq!(g.events, EVENTS.to_vec());
        assert_eq!(accounts(&g), vec![acct(1), acct(8453), acct(10)]);
    }

    #[test]
    fn granted_events_subset() {
        let p = proposal(
            ProposalNamespaces::new(),
            map(vec![(
                "eip155",
                ns(
                    &["eip155:1"],
                    &["personal_sign"],
                    &["chainChanged", "message", "connect", "accountsChanged"],
                ),
            )]),
        );
        let g = grant(&p, &local(&[1]));
        // Kao's two events, in Kao's order; "message" / "connect" are not granted.
        assert_eq!(g.events, vec!["accountsChanged", "chainChanged"]);
    }

    #[test]
    fn crate_fixture_required_namespaces_v1() {
        // tests/common: required eip155 {TEST_METHODS, TEST_CHAINS, TEST_EVENTS}.
        let p = proposal(
            map(vec![(
                "eip155",
                ns(&TEST_CHAINS, &TEST_METHODS, &TEST_EVENTS),
            )]),
            ProposalNamespaces::new(),
        );
        // Arbitrum isn't served by default — required, so refused.
        assert_eq!(blocked(&p, &local(&[1])).code, 5100);
        // Served: granted, including the *required* refused eth_signTransaction.
        let g = grant(&p, &local(&[1, 42161]));
        assert_eq!(g.chains, vec![1, 42161]);
        assert_eq!(accounts(&g), vec![acct(1), acct(42161)]);
        for m in TEST_METHODS {
            assert!(g.methods.contains(&m.to_string()), "{m}");
        }
    }

    #[test]
    fn crate_fixture_required_namespaces_v2_inline_key() {
        // tests/common v2: an extra inline `eip155:43114` key, folded into eip155.
        let mut avalanche = ns(&[], &TEST_METHODS, &TEST_EVENTS);
        avalanche.chains = None;
        let p = proposal(
            map(vec![
                ("eip155", ns(&TEST_CHAINS, &TEST_METHODS, &TEST_EVENTS)),
                (TEST_AVALANCHE_CHAIN, avalanche),
            ]),
            ProposalNamespaces::new(),
        );
        let g = grant(&p, &local(&[1, 42161, 43114]));
        let mut chains = g.chains.clone();
        chains.sort_unstable();
        assert_eq!(chains, vec![1, 42161, 43114]);
        assert_eq!(g.namespaces.len(), 1);
    }

    #[test]
    fn ledger_card_caveat_present() {
        let plan = plan(&modern(&["eip155:1"]), &eoa(EoaKind::Ledger, &[1]));
        assert!(
            plan.caveats.iter().any(|c| c.contains("Ledger")),
            "{:?}",
            plan.caveats
        );
        // Trezor: typed data is granted (per-request 4200), and the card says so.
        let plan = plan_proposal(&modern(&["eip155:1"]), &eoa(EoaKind::Trezor, &[1]), &label);
        assert!(
            plan.caveats.iter().any(|c| c.contains("Trezor")),
            "{:?}",
            plan.caveats
        );
        let typed = plan
            .methods
            .iter()
            .find(|l| l.name == "eth_signTypedData_v4")
            .unwrap();
        assert_eq!(typed.support, MethodSupport::CapabilityRefused);
        assert!(
            plan.verdict
                .unwrap()
                .methods
                .contains(&"eth_signTypedData_v4".to_string())
        );
        // Local: no caveats.
        assert!(
            plan_proposal(&modern(&["eip155:1"]), &local(&[1]), &label)
                .caveats
                .is_empty()
        );
    }

    #[test]
    fn safe_propose_only_caveat() {
        let plan = plan(&modern(&["eip155:1"]), &safe(2, 1));
        assert!(
            plan.caveats
                .iter()
                .any(|c| c.contains("proposed to co-signers")),
            "{:?}",
            plan.caveats
        );
        assert!(
            plan.caveats.iter().any(|c| c.contains("need 2 owner keys")),
            "{:?}",
            plan.caveats
        );
        let ps = plan
            .methods
            .iter()
            .find(|l| l.name == "personal_sign")
            .unwrap();
        assert_eq!(ps.support, MethodSupport::CapabilityRefused);
        // Enough local owners: no caveats.
        assert!(
            plan_proposal(&modern(&["eip155:1"]), &safe(2, 2), &label)
                .caveats
                .is_empty()
        );
    }

    /// A Safe whose fallback handler isn't one that validates EIP-1271 — a token-callback or
    /// custom handler, or one Kao couldn't read — has a handler: the caveat says what it can't do.
    #[test]
    fn safe_handler_caveat_says_it_cant_validate_messages() {
        let mut caps = safe(1, 1);
        if let IdentityKind::Safe(s) = &mut caps.kind {
            s.fallback_handler = false;
        }
        let plan = plan(&modern(&["eip155:1"]), &caps);
        assert!(
            plan.caveats
                .iter()
                .any(|c| c.contains("fallback handler can't validate message signatures")),
            "{:?}",
            plan.caveats
        );
        assert!(
            !plan
                .caveats
                .iter()
                .any(|c| c.contains("no fallback handler")),
            "{:?}",
            plan.caveats
        );
    }

    #[test]
    fn method_support_matrix() {
        let l = local(&[1]);
        assert_eq!(method_support("personal_sign", &l), MethodSupport::Served);
        assert_eq!(method_support("eth_chainId", &l), MethodSupport::Served);
        assert_eq!(method_support("eth_sign", &l), MethodSupport::Refused);
        assert_eq!(method_support("wallet_foo", &l), MethodSupport::Unknown);
        let none = safe(1, 0);
        assert_eq!(
            method_support("eth_sendTransaction", &none),
            MethodSupport::CapabilityRefused
        );
        assert_eq!(
            method_support("wallet_switchEthereumChain", &none),
            MethodSupport::Served
        );
    }

    #[test]
    fn plan_lines_are_bounded_and_sanitized() {
        let chains: Vec<String> = (2..300u64).map(|c| format!("eip155:{c}")).collect();
        let chain_refs: Vec<&str> = chains.iter().map(String::as_str).collect();
        let methods: Vec<String> = (0..300).map(|i| format!("evil\u{202E}{i}")).collect();
        let method_refs: Vec<&str> = methods.iter().map(String::as_str).collect();
        let p = proposal(
            ProposalNamespaces::new(),
            map(vec![("eip155", ns(&chain_refs, &method_refs, &[]))]),
        );
        let plan = plan(&p, &local(&[1]));
        assert!(plan.chains.len() <= MAX_PLAN_LINES);
        assert!(plan.methods.len() <= MAX_PLAN_LINES);
        assert!(plan.methods.iter().all(|l| !l.name.contains('\u{202E}')));
        assert_eq!(plan.verdict.unwrap_err().code, 5100);
    }

    /// `wc_mirror` plans the card on the UI thread after every stream item: a proposal naming tens
    /// of thousands of chains (≈ 1 MiB, one relay frame) must cost next to nothing, and is refused.
    #[test]
    fn oversized_proposal_plans_in_bounded_time() {
        let chains: Vec<String> = std::iter::once("eip155:1".to_string())
            .chain((0..16_000u64).map(|i| format!("eip155:{}", 100_000 + i)))
            .collect();
        let chain_refs: Vec<&str> = chains.iter().map(String::as_str).collect();
        let p = proposal(
            ProposalNamespaces::new(),
            map(vec![(
                "eip155",
                ns(&chain_refs, &["personal_sign"], &["chainChanged"]),
            )]),
        );
        let started = std::time::Instant::now();
        let plan = plan(&p, &local(&[1, 10, 8453]));
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_millis(100),
            "planning took {took:?}"
        );
        assert_eq!(plan.verdict.unwrap_err().code, 5100);
        assert!(plan.chains.len() <= MAX_PLAN_LINES);
    }

    /// At the bound a proposal is still planned (and granted) — cheaply.
    #[test]
    fn plan_at_the_size_bound_is_cheap() {
        let chains: Vec<String> = (1..MAX_PROPOSAL_CHAINS as u64)
            .chain([8453])
            .map(|c| format!("eip155:{c}"))
            .collect();
        let chain_refs: Vec<&str> = chains.iter().map(String::as_str).collect();
        let p = proposal(
            ProposalNamespaces::new(),
            map(vec![("eip155", ns(&chain_refs, SERVED_METHODS, EVENTS))]),
        );
        assert_eq!(proposal_too_large(&p), None);
        let started = std::time::Instant::now();
        let g = grant(&p, &local(&[1, 10, 8453]));
        assert!(started.elapsed() < std::time::Duration::from_millis(250));
        assert_eq!(g.chains, vec![1, 10, 8453]);
    }

    #[test]
    fn proposal_size_bounds_pick_the_matching_code() {
        let many = |n: usize, prefix: &str| -> Vec<String> {
            (0..n).map(|i| format!("{prefix}{i}")).collect()
        };
        let refs = |v: &[String]| v.iter().map(String::clone).collect::<Vec<_>>();
        let chains = many(MAX_PROPOSAL_CHAINS, "eip155:");
        let mut p = modern(&["eip155:1"]);
        let code = |p: &Proposal| proposal_too_large(p).map(|b| b.code);
        assert_eq!(code(&p), None);
        // Required and optional count together.
        p.required_namespaces.insert(
            "eip155".into(),
            ProposalNamespace {
                chains: Some(refs(&chains)),
                methods: Vec::new(),
                events: Vec::new(),
            },
        );
        assert_eq!(code(&p), Some(5100));
        let mut p = modern(&["eip155:1"]);
        if let Some(n) = p.optional_namespaces.get_mut("eip155") {
            n.methods = many(MAX_PROPOSAL_METHODS + 1, "m");
        }
        assert_eq!(code(&p), Some(5101));
        let mut p = modern(&["eip155:1"]);
        if let Some(n) = p.optional_namespaces.get_mut("eip155") {
            n.events = many(MAX_PROPOSAL_EVENTS + 1, "e");
        }
        assert_eq!(code(&p), Some(5102));
        let mut p = modern(&["eip155:1"]);
        for i in 0..MAX_PROPOSAL_NAMESPACES {
            p.optional_namespaces
                .insert(format!("eip155:{}", i + 2), ProposalNamespace::default());
        }
        assert_eq!(code(&p), Some(5104));
        let block = proposal_too_large(&p).expect("too large");
        assert_eq!(proposal_reject_error(&block).message, TOO_LARGE);
    }
}
