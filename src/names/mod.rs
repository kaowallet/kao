//! Unified name-service resolution: dispatches forward (`name → address`) and
//! reverse (`address → name`) lookups across the supported namespaces — ENS
//! (`.eth` and DNS names, [`crate::names::ens`]), GNS (`.gwei`, [`crate::names::gns`]),
//! WNS (`.wei`, [`crate::names::wns`]) and XNS (`label@namespace`, [`crate::names::xns`]).
//!
//! ENS sits behind a registry→resolver indirection. GNS and WNS are
//! *single-contract* namespaces: one `NameNFT` contract is both the registry
//! and the resolver, exposing the ENS-compatible `addr(bytes32)` (forward)
//! alongside a convenience `reverseResolve(address) → string` (reverse). The
//! shared [`NftNameService`] core handles those two. XNS v2 is a separate
//! single-contract registry whose identifiers use `@` rather than `.`, so they
//! never collide with the domain-style systems.
//!
//! Every read inherits [`crate::names::ens`]'s trust model: it goes through the
//! Helios-verified mainnet path ([`crate::names::ens::verified_call`]) and **fails
//! closed** when the light client can't verify it. A resolved address feeds the
//! signed Send recipient, imported watch-only accounts and Safe owners, so an
//! unverified RPC answer is an error, never a trusted address. Names are
//! normalized (UTS-46 / ENSIP-15 for dotted names; XNS's own `[a-z0-9-]` rules
//! for `@` names) before hashing or display, and reverse results are
//! additionally forward-verified — so neither a hostile RPC nor a namespace
//! owner can fabricate a name on a review surface.
//!
//! Forward dispatch is by syntax (`.` → ENS/GNS/WNS, `@` → XNS); reverse tries
//! ENS first (most established), then GNS, then WNS, then XNS, returning the
//! first verified match.

use alloy::primitives::{Address, B256};

use self::ens::{beautify, decode_address, decode_string, namehash, normalize, verified_call};
use crate::net::BalanceFetcher;

// Per-service resolver modules (ENS multi-contract; GNS/WNS single-contract
// NameNFTs; XNS permissionless `label@namespace`). The whole name-service
// subsystem lives under `src/names/`.
pub mod ens;
pub mod gns;
pub mod wns;
pub mod xns;
// The registration/management app layer that builds on the resolvers.
pub mod manage;
pub mod registrar;

/// `keccak256("reverseResolve(address)")[..4]` — the GNS/WNS convenience
/// reverse lookup. Verified against the signature in the unit tests below.
pub(crate) const REVERSE_RESOLVE_SELECTOR: [u8; 4] = [0x9a, 0xf8, 0xb7, 0xaa];

/// `keccak256("addr(bytes32)")[..4]`. The `NameNFT` contract is its own
/// resolver, so forward resolution is a single `addr(node)` against it — no
/// ENS-style `registry.resolver(node)` hop. Same selector ENS's resolver uses.
pub(crate) const ADDR_SELECTOR: [u8; 4] = [0x3b, 0x3b, 0x57, 0xde];

/// A single-contract, ENS-compatible namespace (GNS / WNS).
///
/// One on-chain `NameNFT` contract is simultaneously the registry and the
/// resolver: token ids are `uint256(namehash(name))` (EIP-137), `addr(bytes32)`
/// resolves a node to an address, and `reverseResolve(address)` returns the
/// primary name (already self-verified on-chain, but we re-verify — see
/// [`NftNameService::lookup_address`]). [`crate::names::gns`] and [`crate::names::wns`]
/// supply the deployment constants.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NftNameService {
    /// The `NameNFT` contract (registry + resolver) on Ethereum mainnet.
    pub(crate) registry: Address,
    /// Lowercase TLD suffix including the leading dot, e.g. `".gwei"`.
    pub(crate) tld: &'static str,
}

impl NftNameService {
    /// Forward resolution: `label{tld} → 0xAddress`.
    ///
    /// The input is normalized (ENSIP-15) first; an unnormalisable name returns
    /// `Err`. `Ok(None)` when the name is inactive / has no `addr` record / the
    /// record is the zero address. A read that could not be verified by the
    /// light client returns `Err` (the resolved address becomes a signed
    /// recipient — never trust an unverified answer).
    pub(crate) async fn resolve_name(
        &self,
        net: &dyn BalanceFetcher,
        name: &str,
    ) -> Result<Option<Address>, String> {
        let normalized = normalize(name)?;
        self.addr(net, namehash(&normalized)).await
    }

    /// Reverse resolution with normalization + forward verification:
    /// `0xAddress → label{tld}`.
    ///
    /// Returns `Ok(Some(name))` only when the contract's `reverseResolve`
    /// returns a non-empty name that (1) normalizes cleanly under ENSIP-15,
    /// (2) carries this namespace's TLD, and (3) forward-resolves back to the
    /// original address. The contract already enforces (3) on-chain, but we
    /// re-check on our side: normalization can rewrite the bytes, and a hostile
    /// resolver could otherwise return a name whose normalized form points
    /// elsewhere. Anything short of all three returns `Ok(None)`. An
    /// unverified read returns `Err`; the display call sites map that to "no
    /// name", so a hostile RPC can never fabricate one.
    pub(crate) async fn lookup_address(
        &self,
        net: &dyn BalanceFetcher,
        addr: Address,
    ) -> Result<Option<String>, String> {
        let raw = verified_call(
            net,
            self.registry,
            REVERSE_RESOLVE_SELECTOR,
            address_word(addr),
        )
        .await?;
        let claimed = match decode_string(&raw) {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(None),
        };
        let normalized = match normalize(&claimed) {
            Ok(n) => n,
            Err(_) => return Ok(None),
        };
        // The contract appends our TLD to every reverse result; reject anything
        // that doesn't carry it (defence against a resolver answering with a
        // name outside this namespace, and against the empty-name root node).
        if !normalized.ends_with(self.tld) {
            return Ok(None);
        }
        if self.addr(net, namehash(&normalized)).await? != Some(addr) {
            return Ok(None);
        }
        Ok(Some(beautify(&normalized)))
    }

    /// One verified `addr(bytes32)` read against the registry, decoded to a
    /// non-zero address (`None` for short data or the zero address).
    async fn addr(&self, net: &dyn BalanceFetcher, node: B256) -> Result<Option<Address>, String> {
        let result = verified_call(net, self.registry, ADDR_SELECTOR, node).await?;
        if result.len() < 32 {
            return Ok(None);
        }
        let addr = decode_address(&result);
        Ok(if addr == Address::ZERO {
            None
        } else {
            Some(addr)
        })
    }
}

/// ABI-encode an address as a single left-padded 32-byte word — the argument
/// `reverseResolve(address)` expects (and the shape [`verified_call`] feeds as
/// its `node`).
fn address_word(addr: Address) -> B256 {
    let mut buf = [0u8; 32];
    buf[12..].copy_from_slice(addr.as_slice());
    B256::from(buf)
}

/// Loose gate: "the user typed something name-shaped". A dotted, non-hex
/// string (ENS / GNS / WNS) or an XNS `label@namespace` qualifies — fine where
/// the user has committed to entering a name (Send recipient, watch-only
/// import, Safe-owner import) and a miss just surfaces "no address record".
/// Dotted names delegate to [`ens::looks_like_ens`] so the heuristic (and its
/// hardening against Unicode-dot homographs) stays in one place. For surfaces
/// where a stray `chrome.com` paste must NOT fire an on-chain lookup, use
/// [`looks_like_known_name`].
pub fn looks_like_name(input: &str) -> bool {
    ens::looks_like_ens(input) || looks_like_xns_name(input)
}

/// Strict gate: the input is a name this wallet can actually hold — a
/// first-class TLD (`.eth` / `.gwei` / `.wei`) with a non-empty label, or an
/// XNS-shaped `label@namespace`. Used by the contacts form and the transaction
/// builder, where the looser [`looks_like_name`] would eagerly fire a lookup on
/// any pasted domain.
pub fn looks_like_known_name(input: &str) -> bool {
    if looks_like_xns_name(input) {
        return true;
    }
    let lc = input.trim().to_ascii_lowercase();
    [
        ".eth",
        crate::names::gns::GNS.tld,
        crate::names::wns::WNS.tld,
    ]
    .iter()
    .any(|tld| {
        lc.strip_suffix(tld)
            .is_some_and(|stem| !stem.is_empty() && !stem.ends_with('.'))
    })
}

/// The registry a name's **syntax alone** identifies: `@` → XNS, `.gwei` → GNS,
/// `.wei` → WNS, anything else dotted → ENS.
///
/// v2's `@` separator makes this unambiguous — `alice@eth` is XNS and
/// `alice.eth` is ENS — so there is no longer a "could be either" case.
pub fn namespace_label(name: &str) -> Option<&'static str> {
    let lc = name.trim().to_ascii_lowercase();
    if looks_like_xns_name(&lc) {
        Some("XNS")
    } else if lc.ends_with(crate::names::gns::GNS.tld) {
        Some("GNS")
    } else if lc.ends_with(crate::names::wns::WNS.tld) {
        Some("WNS")
    } else {
        Some("ENS")
    }
}

/// Which registry vouched for a resolved name.
///
/// Returned alongside the address so the UI can badge the name with the
/// service that answered. v2's `@` vs `.` split means the syntax usually
/// already says, but the lookup is still the source of truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registry {
    Ens,
    Gns,
    Wns,
    Xns,
}

impl Registry {
    /// The short badge shown beside a resolved name.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ens => "ENS",
            Self::Gns => "GNS",
            Self::Wns => "WNS",
            Self::Xns => "XNS",
        }
    }
}

/// Whether `input` could be an XNS `label@namespace` name.
///
/// v2 identifiers use ASCII `@` as the separator (never `.`), so they cannot
/// collide with ENS / GNS / WNS. The only test available is the contract's own
/// grammar: exactly one `@`, both halves lowercase `[a-z0-9-]` of 1–20
/// characters. That rejects emails like `user@gmail.com` (the namespace half
/// would contain a dot) and every `0x…` address. A Unicode `@` homograph is
/// not ASCII `@` and does not match.
pub fn looks_like_xns_name(input: &str) -> bool {
    split_xns_name(input).is_some()
}

/// Split a well-formed XNS identifier into `(label, namespace)`, both already
/// lowercased and validated. `None` when the string is not XNS-shaped.
pub fn split_xns_name(input: &str) -> Option<(String, String)> {
    let lc = input.trim().to_ascii_lowercase();
    let (label, namespace) = lc.split_once('@')?;
    if namespace.contains('@') {
        return None;
    }
    let label = xns::normalize_label(label)?;
    let namespace = xns::normalize_label(namespace)?;
    Some((label, namespace))
}

/// Forward resolution dispatched by syntax, discarding which registry answered.
/// Signature mirrors [`ens::resolve_name`] so the call sites are
/// namespace-agnostic.
pub async fn resolve_name(net: &dyn BalanceFetcher, name: &str) -> Result<Option<Address>, String> {
    Ok(resolve_name_tagged(net, name).await?.map(|(addr, _)| addr))
}

/// Forward resolution that also reports which registry vouched for the name.
///
/// - `label@namespace` → XNS only.
/// - `.gwei` → GNS, `.wei` → WNS.
/// - everything else dotted → ENS.
///
/// v2's `@` vs `.` split is the whole reason this used to ask XNS *and* ENS
/// for the same string. A name can no longer be both, so each syntax has
/// exactly one authority. An `Err` from the chosen read propagates (fail
/// closed): the resolved address may become a signed recipient.
pub async fn resolve_name_tagged(
    net: &dyn BalanceFetcher,
    name: &str,
) -> Result<Option<(Address, Registry)>, String> {
    let lc = name.trim().to_ascii_lowercase();
    if let Some((label, namespace)) = split_xns_name(&lc) {
        return Ok(xns_forward(net, &label, &namespace)
            .await?
            .map(|a| (a, Registry::Xns)));
    }
    if lc.ends_with(crate::names::gns::GNS.tld) {
        return Ok(crate::names::gns::GNS
            .resolve_name(net, name)
            .await?
            .map(|a| (a, Registry::Gns)));
    }
    if lc.ends_with(crate::names::wns::WNS.tld) {
        return Ok(crate::names::wns::WNS
            .resolve_name(net, name)
            .await?
            .map(|a| (a, Registry::Wns)));
    }
    Ok(ens::resolve_name(net, name)
        .await?
        .map(|a| (a, Registry::Ens)))
}

/// Verified forward resolution of an XNS `label@namespace` to a non-zero address.
/// Both parts are validated against XNS's own rules (lowercase `[a-z0-9-]`, 1–20)
/// before any read — an invalid name can't be registered, so it can't resolve.
/// `Ok(None)` for an unregistered / malformed name; `Err` on an unverified read
/// (the resolved address may become a signed recipient — never trust an
/// unverified answer).
pub(crate) async fn xns_forward(
    net: &dyn BalanceFetcher,
    label: &str,
    namespace: &str,
) -> Result<Option<Address>, String> {
    let (Some(label), Some(namespace)) =
        (xns::normalize_label(label), xns::normalize_label(namespace))
    else {
        return Ok(None);
    };
    let (to, cd) = xns::get_address_call(&label, &namespace);
    let out = ens::verified_call_raw(net, to, cd).await?;
    let addr = decode_address(&out);
    Ok((addr != Address::ZERO).then_some(addr))
}

/// Verified reverse lookup for the XNS primary (and only) name of `addr`, with
/// forward-verification. v2 returns `label@namespace` (no bare names); anything
/// that isn't that shape is discarded so XNS can't put a spoofy string on a
/// signing surface. Confirms the name forward-resolves back to `addr` before
/// trusting it. `Err` on an unverified read; the call sites render no name on
/// `Err`.
pub(crate) async fn xns_lookup_address(
    net: &dyn BalanceFetcher,
    addr: Address,
) -> Result<Option<String>, String> {
    let (to, cd) = xns::get_name_call(addr);
    let raw = ens::verified_call_raw(net, to, cd).await?;
    let name = match decode_string(&raw) {
        Some(s) if !s.is_empty() => s,
        _ => return Ok(None),
    };
    let Some((label, namespace)) = split_xns_name(&name) else {
        return Ok(None);
    };
    if xns_forward(net, &label, &namespace).await? != Some(addr) {
        return Ok(None);
    }
    Ok(Some(format!("{label}@{namespace}")))
}

/// A name carries a reserved suffix another registry is authoritative for
/// (`.gwei` / `.wei`) or is XNS-shaped (`label@namespace`).
///
/// Such a name is authoritative **only** when its own contract resolves it
/// (see [`NftNameService::lookup_address`], [`xns_lookup_address`]). In
/// particular ENS must never be trusted to vouch for one: ENS reverse records
/// are free-form and an attacker can set their address's ENS reverse to
/// `victim.gwei` (or `victim@xns`) and self-register a matching ENS *forward*
/// record — which would forward-verify through the ENS registry and otherwise
/// sail onto a signing-review surface as a "verified" name with no relationship
/// to the real holder.
fn is_reserved_namespace_name(name: &str) -> bool {
    let lc = name.to_ascii_lowercase();
    lc.ends_with(crate::names::gns::GNS.tld)
        || lc.ends_with(crate::names::wns::WNS.tld)
        || looks_like_xns_name(&lc)
}

/// Reverse resolution across every namespace, with precedence
/// ENS > GNS > WNS > XNS: the first namespace (in that order) that returns a
/// verified name wins. The four lookups run **concurrently** — a displayed
/// address with no name (the common case) would otherwise pay four sequential
/// mainnet round-trips.
///
/// A verified-path error takes precedence over a lower-priority namespace's
/// name (fail closed): if a higher-priority lookup couldn't be verified we
/// surface the `Err` rather than a name the light client couldn't vouch for,
/// and the call sites render no name on `Err`. `Ok(None)` only when all four
/// have no (verifiable) name.
///
/// ENS is *not* authoritative for the `.gwei` / `.wei` suffixes or for XNS
/// `@` names: an ENS-resolved name in a reserved shape is discarded
/// ([`is_reserved_namespace_name`]) so only that namespace's own contract can
/// put such a label on screen.
pub async fn lookup_address(
    net: &dyn BalanceFetcher,
    addr: Address,
) -> Result<Option<String>, String> {
    let (ens_res, gns_res, wns_res, xns_res) = futures::future::join4(
        ens::lookup_address(net, addr),
        crate::names::gns::GNS.lookup_address(net, addr),
        crate::names::wns::WNS.lookup_address(net, addr),
        xns_lookup_address(net, addr),
    )
    .await;

    // Resolve in priority order; a higher-priority Err short-circuits before a
    // lower-priority name is considered, matching a fail-closed sequential walk.
    match ens_res {
        Err(e) => return Err(e),
        // ENS may not vouch for a `.gwei`/`.wei`/`label@namespace` name —
        // fall through to the owning namespace's contract, which is the only
        // authority for it.
        Ok(Some(name)) if !is_reserved_namespace_name(&name) => return Ok(Some(name)),
        _ => {}
    }
    match gns_res {
        Err(e) => return Err(e),
        Ok(Some(name)) => return Ok(Some(name)),
        _ => {}
    }
    match wns_res {
        Err(e) => return Err(e),
        Ok(Some(name)) => return Ok(Some(name)),
        _ => {}
    }
    match xns_res {
        Err(e) => return Err(e),
        Ok(Some(name)) => return Ok(Some(name)),
        _ => {}
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CallMock;
    use alloy::primitives::{Bytes, address, keccak256};

    const REGISTRY: Address = address!("0x5555555555555555555555555555555555555555");
    const TARGET: Address = address!("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");

    /// A test namespace pointed at [`REGISTRY`] with the `.gwei` TLD; the
    /// resolution logic is identical for every single-contract namespace.
    const NS: NftNameService = NftNameService {
        registry: REGISTRY,
        tld: ".gwei",
    };

    /// `selector` + 32-byte arg, exactly as `verified_call` encodes it.
    fn calldata(selector: [u8; 4], node: B256) -> Bytes {
        let mut d = Vec::with_capacity(36);
        d.extend_from_slice(&selector);
        d.extend_from_slice(node.as_slice());
        Bytes::from(d)
    }

    /// Left-pad a 20-byte address into a 32-byte ABI word.
    fn abi_address(a: Address) -> Bytes {
        Bytes::from(address_word(a).as_slice().to_vec())
    }

    /// ABI-encode a short `string` return: offset(0x20) + length + bytes.
    fn abi_string(s: &str) -> Bytes {
        let bytes = s.as_bytes();
        let mut buf = Vec::new();
        let mut offset = [0u8; 32];
        offset[31] = 0x20;
        buf.extend_from_slice(&offset);
        let mut len_word = [0u8; 32];
        len_word[24..].copy_from_slice(&(bytes.len() as u64).to_be_bytes());
        buf.extend_from_slice(&len_word);
        buf.extend_from_slice(bytes);
        // Pad the data to a 32-byte multiple.
        let pad = (32 - bytes.len() % 32) % 32;
        buf.resize(buf.len() + pad, 0);
        Bytes::from(buf)
    }

    /// Wire `net` so the *full* ENS reverse path resolves `addr` to `name`:
    /// the registry→resolver hop for the reverse node, the `name(node)` record,
    /// and the forward-verification hop (registry→resolver→`addr(node)`) that
    /// `ens::lookup_address` performs before trusting the name. Mirrors how the
    /// real ENS registry/resolver answer, so the dispatcher's ENS leg behaves
    /// end-to-end. `resolver` is an arbitrary resolver contract.
    fn mock_ens_reverse(net: &CallMock, addr: Address, name: &str, resolver: Address) {
        let reverse_node = namehash(&format!("{addr:x}.addr.reverse"));
        net.set_call(
            ens::ENS_REGISTRY,
            calldata(ens::RESOLVER_SELECTOR, reverse_node),
            abi_address(resolver),
            true,
        );
        net.set_call(
            resolver,
            calldata(ens::NAME_SELECTOR, reverse_node),
            abi_string(name),
            true,
        );
        let fwd = namehash(&normalize(name).unwrap());
        net.set_call(
            ens::ENS_REGISTRY,
            calldata(ens::RESOLVER_SELECTOR, fwd),
            abi_address(resolver),
            true,
        );
        net.set_call(
            resolver,
            calldata(ADDR_SELECTOR, fwd),
            abi_address(addr),
            true,
        );
    }

    /// Pre-load a single-contract namespace's reverse + forward records so
    /// `NftNameService::lookup_address` resolves `addr` → `name` against
    /// `registry`.
    fn mock_nft_reverse(net: &CallMock, registry: Address, addr: Address, name: &str) {
        net.set_call(
            registry,
            calldata(REVERSE_RESOLVE_SELECTOR, address_word(addr)),
            abi_string(name),
            true,
        );
        let node = namehash(&normalize(name).unwrap());
        net.set_call(
            registry,
            calldata(ADDR_SELECTOR, node),
            abi_address(addr),
            true,
        );
    }

    #[test]
    fn reverse_selector_matches_signature() {
        assert_eq!(
            &keccak256(b"reverseResolve(address)").as_slice()[..4],
            REVERSE_RESOLVE_SELECTOR.as_slice(),
        );
    }

    #[test]
    fn addr_selector_matches_signature() {
        assert_eq!(
            &keccak256(b"addr(bytes32)").as_slice()[..4],
            ADDR_SELECTOR.as_slice(),
        );
    }

    #[test]
    fn address_word_left_pads() {
        let word = address_word(TARGET);
        assert_eq!(&word.0[..12], &[0u8; 12]);
        assert_eq!(&word.0[12..], TARGET.as_slice());
    }

    #[test]
    fn looks_like_known_name_accepts_known_tlds() {
        assert!(looks_like_known_name("alice.eth"));
        assert!(looks_like_known_name("alice.gwei"));
        assert!(looks_like_known_name("alice.wei"));
        assert!(looks_like_known_name("alice@xns"));
        assert!(looks_like_known_name("alice@eth"));
        assert!(looks_like_known_name("SUB.alice.GWEI"));
    }

    #[test]
    fn looks_like_known_name_rejects_other_dotted_strings() {
        // The whole point of the strict gate: a pasted domain must not fire.
        assert!(!looks_like_known_name("chrome.com"));
        assert!(!looks_like_known_name("vitalik.xyz"));
        assert!(!looks_like_known_name("alice.xns")); // v1 shape is not XNS
        assert!(!looks_like_known_name(".eth"));
        assert!(!looks_like_known_name("foo..gwei"));
        assert!(!looks_like_known_name(
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        ));
    }

    #[test]
    fn looks_like_name_accepts_xns_at_names() {
        assert!(looks_like_name("alice@xns"));
        assert!(looks_like_name("wehi@crops"));
        assert!(looks_like_name("vitalik.eth"));
        assert!(!looks_like_name("alice")); // bare names are gone in v2
        assert!(!looks_like_name("alice＠xns")); // fullwidth @ is not ASCII @
    }

    #[tokio::test]
    async fn forward_resolves_verified_addr() {
        let net = CallMock::new();
        let node = namehash(&normalize("alice.gwei").unwrap());
        net.set_call(
            REGISTRY,
            calldata(ADDR_SELECTOR, node),
            abi_address(TARGET),
            true,
        );
        assert_eq!(
            NS.resolve_name(&net, "alice.gwei").await.unwrap(),
            Some(TARGET)
        );
    }

    #[tokio::test]
    async fn forward_fails_closed_when_unverified() {
        // The resolved address becomes a signed recipient — an unverified read
        // must error, not return Some(addr).
        let net = CallMock::new();
        let node = namehash(&normalize("alice.gwei").unwrap());
        net.set_call(
            REGISTRY,
            calldata(ADDR_SELECTOR, node),
            abi_address(TARGET),
            false,
        );
        assert!(NS.resolve_name(&net, "alice.gwei").await.is_err());
    }

    #[tokio::test]
    async fn forward_none_for_zero_address() {
        let net = CallMock::new();
        let node = namehash(&normalize("alice.gwei").unwrap());
        net.set_call(
            REGISTRY,
            calldata(ADDR_SELECTOR, node),
            abi_address(Address::ZERO),
            true,
        );
        assert_eq!(NS.resolve_name(&net, "alice.gwei").await.unwrap(), None);
    }

    #[tokio::test]
    async fn reverse_returns_forward_verified_name() {
        let net = CallMock::new();
        let node = namehash(&normalize("alice.gwei").unwrap());
        net.set_call(
            REGISTRY,
            calldata(REVERSE_RESOLVE_SELECTOR, address_word(TARGET)),
            abi_string("alice.gwei"),
            true,
        );
        net.set_call(
            REGISTRY,
            calldata(ADDR_SELECTOR, node),
            abi_address(TARGET),
            true,
        );
        assert_eq!(
            NS.lookup_address(&net, TARGET).await.unwrap(),
            Some("alice.gwei".to_string()),
        );
    }

    #[tokio::test]
    async fn reverse_rejects_forward_mismatch() {
        // reverseResolve claims a name, but it forward-resolves to a DIFFERENT
        // address — the classic reverse-record spoof. Must return None.
        let other = address!("0x1111111111111111111111111111111111111111");
        let net = CallMock::new();
        let node = namehash(&normalize("alice.gwei").unwrap());
        net.set_call(
            REGISTRY,
            calldata(REVERSE_RESOLVE_SELECTOR, address_word(TARGET)),
            abi_string("alice.gwei"),
            true,
        );
        net.set_call(
            REGISTRY,
            calldata(ADDR_SELECTOR, node),
            abi_address(other),
            true,
        );
        assert_eq!(NS.lookup_address(&net, TARGET).await.unwrap(), None);
    }

    #[tokio::test]
    async fn reverse_rejects_name_without_our_tld() {
        // A resolver that answers with someone else's TLD (or the bare root)
        // must not be displayed as one of ours.
        let net = CallMock::new();
        net.set_call(
            REGISTRY,
            calldata(REVERSE_RESOLVE_SELECTOR, address_word(TARGET)),
            abi_string("alice.eth"),
            true,
        );
        assert_eq!(NS.lookup_address(&net, TARGET).await.unwrap(), None);
    }

    #[tokio::test]
    async fn reverse_fails_closed_when_unverified() {
        let net = CallMock::new();
        net.set_call(
            REGISTRY,
            calldata(REVERSE_RESOLVE_SELECTOR, address_word(TARGET)),
            abi_string("alice.gwei"),
            false,
        );
        assert!(NS.lookup_address(&net, TARGET).await.is_err());
    }

    #[tokio::test]
    async fn dispatch_routes_gwei_to_gns_contract() {
        // Prove the TLD router targets the real GNS contract, not ENS: only the
        // GNS registry is mocked, so a correct route returns TARGET while a
        // misroute (to ENS) would return None.
        let net = CallMock::new();
        let node = namehash(&normalize("alice.gwei").unwrap());
        net.set_call(
            crate::names::gns::GNS.registry,
            calldata(ADDR_SELECTOR, node),
            abi_address(TARGET),
            true,
        );
        assert_eq!(
            resolve_name(&net, "alice.gwei").await.unwrap(),
            Some(TARGET)
        );
    }

    #[tokio::test]
    async fn dispatch_routes_wei_to_wns_contract() {
        let net = CallMock::new();
        let node = namehash(&normalize("alice.wei").unwrap());
        net.set_call(
            crate::names::wns::WNS.registry,
            calldata(ADDR_SELECTOR, node),
            abi_address(TARGET),
            true,
        );
        assert_eq!(resolve_name(&net, "alice.wei").await.unwrap(), Some(TARGET));
    }

    #[tokio::test]
    async fn dispatch_reverse_falls_through_to_gns() {
        // ENS has no record (empty mock → registry.resolver returns zero), so
        // the dispatcher falls through to GNS and returns its verified name.
        let net = CallMock::new();
        let node = namehash(&normalize("alice.gwei").unwrap());
        net.set_call(
            crate::names::gns::GNS.registry,
            calldata(REVERSE_RESOLVE_SELECTOR, address_word(TARGET)),
            abi_string("alice.gwei"),
            true,
        );
        net.set_call(
            crate::names::gns::GNS.registry,
            calldata(ADDR_SELECTOR, node),
            abi_address(TARGET),
            true,
        );
        assert_eq!(
            lookup_address(&net, TARGET).await.unwrap(),
            Some("alice.gwei".to_string()),
        );
    }

    #[test]
    fn namespace_label_names_only_what_the_syntax_settles() {
        assert_eq!(namespace_label("apoorv.gwei"), Some("GNS"));
        assert_eq!(namespace_label("alice.wei"), Some("WNS"));
        assert_eq!(namespace_label("vitalik.eth"), Some("ENS"));
        assert_eq!(namespace_label("APOORV.GWEI"), Some("GNS"));
        assert_eq!(namespace_label("carol@xns"), Some("XNS"));
        assert_eq!(namespace_label("alice@eth"), Some("XNS"));
        assert_eq!(namespace_label("dave@crops"), Some("XNS"));
        // Multi-dot can't be an XNS name (labels hold no `@` split that
        // validates), so ENS is the only registry left that could hold it.
        assert_eq!(namespace_label("sub.domain.com"), Some("ENS"));
        // v1 dotted XNS shape is no longer XNS — `.xns` is just a dotted name.
        assert_eq!(namespace_label("carol.xns"), Some("ENS"));
    }

    #[test]
    fn reserved_namespace_name_detects_gwei_wei_and_xns() {
        assert!(is_reserved_namespace_name("victim.gwei"));
        assert!(is_reserved_namespace_name("VICTIM.WEI"));
        assert!(is_reserved_namespace_name("sub.victim.gwei"));
        assert!(is_reserved_namespace_name("victim@xns"));
        assert!(is_reserved_namespace_name("alice@eth"));
        assert!(!is_reserved_namespace_name("alice.eth"));
        assert!(!is_reserved_namespace_name("alice.xyz"));
        assert!(!is_reserved_namespace_name("victim.xns"));
    }

    #[tokio::test]
    async fn dispatch_routes_xns_to_xns_contract() {
        // `alice@xns` must hit the XNS contract via getAddress(label, namespace),
        // not ENS. Only XNS is mocked, so a misroute would return None.
        let net = CallMock::new();
        let (to, cd) = xns::get_address_call("alice", "xns");
        net.set_call(to, cd, abi_address(TARGET), true);
        assert_eq!(resolve_name(&net, "alice@xns").await.unwrap(), Some(TARGET));
    }

    #[tokio::test]
    async fn xns_forward_fails_closed_when_unverified() {
        let net = CallMock::new();
        let (to, cd) = xns::get_address_call("alice", "xns");
        net.set_call(to, cd, abi_address(TARGET), false);
        assert!(resolve_name(&net, "alice@xns").await.is_err());
    }

    #[tokio::test]
    async fn xns_reverse_returns_forward_verified_name() {
        let net = CallMock::new();
        let (gto, gcd) = xns::get_name_call(TARGET);
        net.set_call(gto, gcd, abi_string("alice@crops"), true);
        let (fto, fcd) = xns::get_address_call("alice", "crops");
        net.set_call(fto, fcd, abi_address(TARGET), true);
        assert_eq!(
            xns_lookup_address(&net, TARGET).await.unwrap(),
            Some("alice@crops".to_string()),
        );
    }

    #[tokio::test]
    async fn xns_reverse_accepts_eth_namespace() {
        // v2 unblocked `@eth`. A reverse of `vitalik@eth` must display, not
        // be discarded as colliding with ENS's `.eth`.
        let net = CallMock::new();
        let (gto, gcd) = xns::get_name_call(TARGET);
        net.set_call(gto, gcd, abi_string("vitalik@eth"), true);
        let (fto, fcd) = xns::get_address_call("vitalik", "eth");
        net.set_call(fto, fcd, abi_address(TARGET), true);
        assert_eq!(
            xns_lookup_address(&net, TARGET).await.unwrap(),
            Some("vitalik@eth".to_string()),
        );
    }

    #[tokio::test]
    async fn xns_reverse_rejects_bare_name() {
        // v2 removed bare names; a reverse without `@` must not display.
        let net = CallMock::new();
        let (gto, gcd) = xns::get_name_call(TARGET);
        net.set_call(gto, gcd, abi_string("vitalik"), true);
        assert_eq!(xns_lookup_address(&net, TARGET).await.unwrap(), None);
    }

    #[tokio::test]
    async fn xns_reverse_rejects_dotted_v1_shape() {
        // A v1 `label.namespace` reverse must not display — v2 identifiers
        // are `label@namespace`.
        let net = CallMock::new();
        let (gto, gcd) = xns::get_name_call(TARGET);
        net.set_call(gto, gcd, abi_string("alice.crops"), true);
        assert_eq!(xns_lookup_address(&net, TARGET).await.unwrap(), None);
    }

    // The real wehi@crops ↔ 0xa149…451f pair, both directions, at the
    // dispatcher level.
    #[tokio::test]
    async fn wehi_crops_forward_resolves_to_real_address() {
        let net = CallMock::new();
        let wehi = address!("0xa1491eFf7CaC231440C8C0E6FaC043D8965C451f");
        let (to, cd) = xns::get_address_call("wehi", "crops");
        net.set_call(to, cd, abi_address(wehi), true);
        assert_eq!(
            xns_forward(&net, "wehi", "crops").await.unwrap(),
            Some(wehi)
        );
        assert_eq!(resolve_name(&net, "wehi@crops").await.unwrap(), Some(wehi));
    }

    #[tokio::test]
    async fn wehi_crops_reverse_resolves_from_real_address() {
        let net = CallMock::new();
        let wehi = address!("0xa1491eFf7CaC231440C8C0E6FaC043D8965C451f");
        let (gto, gcd) = xns::get_name_call(wehi);
        net.set_call(gto, gcd, abi_string("wehi@crops"), true);
        // Forward-verification leg: getAddress("wehi","crops") == wehi.
        let (fto, fcd) = xns::get_address_call("wehi", "crops");
        net.set_call(fto, fcd, abi_address(wehi), true);
        assert_eq!(
            xns_lookup_address(&net, wehi).await.unwrap(),
            Some("wehi@crops".to_string()),
        );
    }

    #[tokio::test]
    async fn reverse_falls_through_to_xns_after_others() {
        // ENS/GNS/WNS have no record; XNS does. The precedence walk should reach
        // XNS and return its forward-verified name.
        let net = CallMock::new();
        let (gto, gcd) = xns::get_name_call(TARGET);
        net.set_call(gto, gcd, abi_string("alice@xns"), true);
        let (fto, fcd) = xns::get_address_call("alice", "xns");
        net.set_call(fto, fcd, abi_address(TARGET), true);
        assert_eq!(
            lookup_address(&net, TARGET).await.unwrap(),
            Some("alice@xns".to_string()),
        );
    }

    #[tokio::test]
    async fn dispatch_routes_eth_to_ens_two_hop_path() {
        // A `.eth` name must take the ENS registry→resolver path, not a
        // single-contract path. Only ENS is mocked; a misroute to GNS/WNS
        // (unmocked) would return None instead of TARGET.
        let net = CallMock::new();
        let resolver = address!("0x1111111111111111111111111111111111111111");
        let node = namehash(&normalize("vitalik.eth").unwrap());
        net.set_call(
            ens::ENS_REGISTRY,
            calldata(ens::RESOLVER_SELECTOR, node),
            abi_address(resolver),
            true,
        );
        net.set_call(
            resolver,
            calldata(ADDR_SELECTOR, node),
            abi_address(TARGET),
            true,
        );
        assert_eq!(
            resolve_name(&net, "vitalik.eth").await.unwrap(),
            Some(TARGET)
        );
    }

    #[tokio::test]
    async fn dispatch_uppercase_gwei_routes_and_resolves() {
        // Dispatch lowercases only for the suffix test and forwards the
        // ORIGINAL-case name; normalize() must lowercase the label so the
        // namehash still matches the mocked node.
        let net = CallMock::new();
        let node = namehash(&normalize("alice.gwei").unwrap());
        net.set_call(
            crate::names::gns::GNS.registry,
            calldata(ADDR_SELECTOR, node),
            abi_address(TARGET),
            true,
        );
        assert_eq!(
            resolve_name(&net, "ALICE.GWEI").await.unwrap(),
            Some(TARGET)
        );
    }

    #[tokio::test]
    async fn dispatch_rejects_confusable_gwei_name() {
        // A bidi-override label must be rejected before any on-chain read,
        // exactly like the ENS path — normalize() fails closed.
        let net = CallMock::new();
        assert!(resolve_name(&net, "vit\u{202e}alik.gwei").await.is_err());
        assert!(resolve_name(&net, "vit\u{202e}alik.wei").await.is_err());
    }

    #[tokio::test]
    async fn reverse_discards_ens_resolved_reserved_tld_name() {
        // Cross-namespace impersonation: an attacker sets their address's ENS
        // reverse record to "victim.gwei" and self-registers a matching ENS
        // forward record, so the bare ENS path *would* return it. The
        // dispatcher must NOT trust ENS for a `.gwei` name — only the GNS
        // contract is authoritative, and it has no record here.
        let net = CallMock::new();
        let resolver = address!("0x1111111111111111111111111111111111111111");
        mock_ens_reverse(&net, TARGET, "victim.gwei", resolver);
        // Bare ENS would hand back the fabricated name…
        assert_eq!(
            ens::lookup_address(&net, TARGET).await.unwrap(),
            Some("victim.gwei".to_string()),
        );
        // …but the dispatcher rejects it (GNS/WNS contracts have no record).
        assert_eq!(lookup_address(&net, TARGET).await.unwrap(), None);
    }

    #[tokio::test]
    async fn reverse_prefers_ens_over_gns() {
        // Both ENS (.eth) and GNS (.gwei) verify a name for the same address;
        // ENS wins per the documented precedence.
        let net = CallMock::new();
        let resolver = address!("0x1111111111111111111111111111111111111111");
        mock_ens_reverse(&net, TARGET, "alice.eth", resolver);
        mock_nft_reverse(&net, crate::names::gns::GNS.registry, TARGET, "alice.gwei");
        assert_eq!(
            lookup_address(&net, TARGET).await.unwrap(),
            Some("alice.eth".to_string()),
        );
    }

    #[tokio::test]
    async fn reverse_prefers_gns_over_wns() {
        // ENS empty; GNS (.gwei) and WNS (.wei) both verify a name. GNS wins.
        let net = CallMock::new();
        mock_nft_reverse(&net, crate::names::gns::GNS.registry, TARGET, "alice.gwei");
        mock_nft_reverse(&net, crate::names::wns::WNS.registry, TARGET, "bob.wei");
        assert_eq!(
            lookup_address(&net, TARGET).await.unwrap(),
            Some("alice.gwei".to_string()),
        );
    }

    // ── XNS v2 `label@namespace` ─────────────────────────────────────────────

    const OTHER: Address = address!("0x1111111111111111111111111111111111111111");

    /// Wire XNS's `getAddress(label, namespace)` to answer `addr`.
    fn mock_xns_forward(net: &CallMock, label: &str, namespace: &str, addr: Address) {
        let (to, cd) = xns::get_address_call(label, namespace);
        net.set_call(to, cd, abi_address(addr), true);
    }

    /// Wire the ENS forward path (`registry.resolver(node)` → `resolver.addr(node)`).
    fn mock_ens_forward(net: &CallMock, name: &str, addr: Address) {
        let resolver = address!("0x4444444444444444444444444444444444444444");
        let node = namehash(name);
        net.set_call(
            ens::ENS_REGISTRY,
            calldata(ens::RESOLVER_SELECTOR, node),
            abi_address(resolver),
            true,
        );
        net.set_call(
            resolver,
            calldata([0x3b, 0x3b, 0x57, 0xde], node),
            abi_address(addr),
            true,
        );
    }

    /// A namespace nobody registered with *this wallet* still has to resolve,
    /// because XNS namespaces are permissionless.
    #[tokio::test]
    async fn an_arbitrary_xns_namespace_resolves() {
        let net = CallMock::new();
        mock_xns_forward(&net, "dave", "crops", TARGET);
        assert_eq!(
            resolve_name_tagged(&net, "dave@crops").await.unwrap(),
            Some((TARGET, Registry::Xns)),
        );
        // And through the untagged wrapper every other surface uses.
        assert_eq!(
            resolve_name(&net, "dave@crops").await.unwrap(),
            Some(TARGET)
        );
    }

    /// The v2 point: `alice.eth` is ENS, `alice@eth` is XNS, and they never
    /// collide. Each syntax has exactly one authority, so wiring both records
    /// to different addresses still resolves each name on its own path.
    #[tokio::test]
    async fn at_eth_and_dot_eth_do_not_collide() {
        let net = CallMock::new();
        mock_xns_forward(&net, "alice", "eth", TARGET);
        mock_ens_forward(&net, "alice.eth", OTHER);
        assert_eq!(
            resolve_name_tagged(&net, "alice@eth").await.unwrap(),
            Some((TARGET, Registry::Xns)),
        );
        assert_eq!(
            resolve_name_tagged(&net, "alice.eth").await.unwrap(),
            Some((OTHER, Registry::Ens)),
        );
    }

    /// A dotted name is never asked of XNS, even when XNS would happily claim
    /// the same label+namespace. `dave.crops` is an ENS (DNS) question.
    #[tokio::test]
    async fn a_dotted_name_is_never_asked_of_xns() {
        let net = CallMock::new();
        mock_xns_forward(&net, "dave", "crops", TARGET);
        mock_ens_forward(&net, "dave.crops", OTHER);
        assert_eq!(
            resolve_name_tagged(&net, "dave.crops").await.unwrap(),
            Some((OTHER, Registry::Ens)),
        );
        // And the `@` form still hits XNS.
        assert_eq!(
            resolve_name_tagged(&net, "dave@crops").await.unwrap(),
            Some((TARGET, Registry::Xns)),
        );
    }

    /// ENS reverse of an XNS-shaped name must not display. UTS-46 rejects `@`,
    /// so the ENS path never even produces one; [`is_reserved_namespace_name`]
    /// is the extra belt if that ever changed.
    #[test]
    fn ens_normalize_rejects_xns_at_names() {
        assert!(
            ens::normalize("victim@xns").is_err(),
            "ENS must not be able to vouch for an XNS identifier"
        );
        assert!(is_reserved_namespace_name("victim@xns"));
    }

    #[test]
    fn xns_shape_is_the_contracts_own_grammar() {
        for ok in [
            "a@b",
            "dave@crops",
            "team-1@my-ns",
            "carol@xns",
            "alice@eth",
            // Case-folded before the grammar check, exactly as `normalize_label`
            // folds it before the read — so a name typed in caps still resolves.
            "Dave@CROPS",
        ] {
            assert!(looks_like_xns_name(ok), "{ok}");
        }
        for bad in [
            "user@gmail.com",                             // namespace can't hold a dot
            "notanaddress",                               // no namespace
            "toolongalabelfortheXNScontract@ns",          // over 20 chars
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", // an address
            "alice.eth",                                  // dotted → ENS
            "alice.gwei",
            "alice.wei",
            "alice.xns", // v1 shape
            "dave.crops",
            "alice@@xns", // extra @
            "@xns",       // empty label
            "alice@",     // empty namespace
        ] {
            assert!(!looks_like_xns_name(bad), "{bad}");
        }
    }
}
