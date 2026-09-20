//! XNS v2 (<https://github.com/Walodja1987/xns>) — the permissionless
//! `label@namespace` name service.
//!
//! This is the **pure** layer for XNS: the mainnet contract address, the ABI
//! (via `sol!`, so byte layouts are correct by construction), calldata builders,
//! return decoders and label validation. It performs no I/O — the async,
//! verified orchestration lives in [`super::manage`].
//!
//! ## Why XNS doesn't reuse [`super::registrar::Namespace`]
//!
//! XNS is a different model from the commit-reveal registrars (ENS / GNS / WNS):
//!
//! - **One contract, one call to register.** `registerName(label, namespace)` is
//!   a single payable transaction — no commit/reveal, no 60s wait.
//! - **Permanent & immutable.** Names never expire, can't be renewed, can't be
//!   re-pointed (no `setAddr`) and can't be transferred. The address a name
//!   resolves to is fixed at registration.
//! - **One name per address.** `registerName` reverts if the caller already holds
//!   a name, so an account can own at most one XNS name (across every namespace).
//! - **Permissionless namespaces.** A name is `label@namespace` where `namespace`
//!   is an arbitrary registered string (`eth`, `xns`, `crops`, …) — every
//!   namespace lives in the *same* contract. `getNamespaceInfo` is the gate: it
//!   reverts for a namespace that doesn't exist, and otherwise returns its price,
//!   owner, creation time (for the 7-day exclusivity window) and public/private
//!   flag.
//!
//! v2 dropped the v1 `label.namespace` / bare-name special cases so XNS no
//! longer collides with domain-style systems: `alice.eth` is ENS, `alice@eth`
//! is XNS. The v1 registry remains on-chain as history; this wallet talks only
//! to v2.
//!
//! All reads ride the same Helios-verified mainnet path and fail closed as the
//! rest of [`crate::names`]; a `getNamespaceInfo` revert (nonexistent namespace)
//! surfaces as `Err`, so we never offer to register against an unverifiable
//! price.

use alloy::primitives::{Address, Bytes, U256, address};
use alloy::sol_types::SolCall;

/// XNS v2 registry + resolver, Ethereum mainnet (same address on Sepolia).
/// Registers, resolves and reverse-resolves every namespace.
/// <https://etherscan.io/address/0x6e797ba2d3103aF167918e71a7E01DE40D45f74b>
pub(crate) const XNS_REGISTRY: Address = address!("0x6e797ba2d3103aF167918e71a7E01DE40D45f74b");

/// Exclusivity window (7 days) after a public namespace is created, during which
/// only the namespace owner may register a name in it. `registerName` reverts
/// inside it, so we gate public registration on `created_at + this < now`.
pub const XNS_EXCLUSIVITY_PERIOD: u64 = 7 * 86_400;

/// The maximum length of an XNS label or namespace (the contract's own bound).
pub const XNS_MAX_LEN: usize = 20;

/// XNS contract ABI. Only the calls this wallet makes; `getNamespaceInfo` carries
/// price + owner + createdAt + isPrivate, so a single read covers existence,
/// pricing, the exclusivity window and the public/private gate.
///
/// v2 also exposes `getAddress(string fullName)` (`label@namespace`) and
/// `registerNameForOwnedContract`; we keep using the two-arg forms so label and
/// namespace stay validated on our side before any read or write.
pub(crate) mod abi {
    use alloy::sol;
    sol! {
        function getAddress(string label, string namespace) external view returns (address);
        function getName(address addr) external view returns (string);
        function getNamespaceInfo(string namespace) external view returns (
            uint256 pricePerName,
            address owner,
            uint64 createdAt,
            bool isPrivate
        );
        function registerName(string label, string namespace) external payable;
    }
}

/// `(to, calldata)` for forward resolution of `label@namespace`. Decode with
/// [`super::registrar::decode_address`]; the zero address means "not registered"
/// (and, since names are permanent + immutable, therefore available).
pub fn get_address_call(label: &str, namespace: &str) -> (Address, Bytes) {
    (
        XNS_REGISTRY,
        Bytes::from(
            abi::getAddressCall {
                label: label.to_string(),
                namespace: namespace.to_string(),
            }
            .abi_encode(),
        ),
    )
}

/// `(to, calldata)` for the reverse lookup of `addr`'s primary (and only) name.
/// Decode with [`crate::names::ens::decode_string`]; an empty string means no
/// name. v2 always returns `label@namespace` (no bare names).
pub fn get_name_call(addr: Address) -> (Address, Bytes) {
    (
        XNS_REGISTRY,
        Bytes::from(abi::getNameCall { addr }.abi_encode()),
    )
}

/// `(to, calldata)` for a namespace's metadata. **Reverts on-chain for a
/// namespace that doesn't exist**, so in the verified path a nonexistent
/// namespace surfaces as `Err` — which is exactly the fail-closed behaviour we
/// want before quoting a price. Decode with [`decode_namespace_info`].
pub fn namespace_info_call(namespace: &str) -> (Address, Bytes) {
    (
        XNS_REGISTRY,
        Bytes::from(
            abi::getNamespaceInfoCall {
                namespace: namespace.to_string(),
            }
            .abi_encode(),
        ),
    )
}

/// `(to, value, calldata)` for `registerName(label, namespace)`. `value` is the
/// price to attach; the contract refunds any excess, but XNS prices are a fixed
/// per-namespace storage value (no oracle drift) so the caller sends it exactly.
pub fn register_call(label: &str, namespace: &str, value: U256) -> (Address, U256, Bytes) {
    (
        XNS_REGISTRY,
        value,
        Bytes::from(
            abi::registerNameCall {
                label: label.to_string(),
                namespace: namespace.to_string(),
            }
            .abi_encode(),
        ),
    )
}

/// Decoded `getNamespaceInfo` return: a namespace's registration parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceInfo {
    /// Flat price every name in this namespace costs (wei).
    pub price: U256,
    /// The namespace owner (non-zero for an existing namespace).
    pub owner: Address,
    /// Unix second the namespace was created (drives the exclusivity window).
    pub created_at: u64,
    /// Private namespaces are owner-only forever — no public `registerName`.
    pub is_private: bool,
}

impl NamespaceInfo {
    /// Whether public `registerName` is open right now: the namespace must be
    /// public and past its 7-day exclusivity window.
    pub fn public_open(&self, now: u64) -> bool {
        !self.is_private && now > self.created_at.saturating_add(XNS_EXCLUSIVITY_PERIOD)
    }

    /// Whether the namespace is still inside its post-creation exclusivity window.
    pub fn in_exclusivity(&self, now: u64) -> bool {
        now <= self.created_at.saturating_add(XNS_EXCLUSIVITY_PERIOD)
    }
}

/// Decode the four static words of `getNamespaceInfo`:
/// `(uint256 price, address owner, uint64 createdAt, bool isPrivate)`. `None`
/// for short data or a zero owner (a nonexistent namespace, which the contract
/// would have reverted on anyway).
pub fn decode_namespace_info(data: &[u8]) -> Option<NamespaceInfo> {
    if data.len() < 128 {
        return None;
    }
    let price = U256::from_be_slice(&data[0..32]);
    let owner = Address::from_slice(&data[44..64]);
    if owner == Address::ZERO {
        return None;
    }
    let created_at = u64::from_be_bytes(data[88..96].try_into().ok()?);
    let is_private = data[127] != 0;
    Some(NamespaceInfo {
        price,
        owner,
        created_at,
        is_private,
    })
}

/// Whether `s` is a valid XNS label *or* namespace, mirroring the contract's
/// `_isValidLabelOrNamespace`: 1–20 chars, only `[a-z0-9-]`, no leading/trailing
/// hyphen and no consecutive hyphens. (Note: only ASCII is allowed, so byte
/// length equals character count.)
pub fn is_valid_label(s: &str) -> bool {
    let b = s.as_bytes();
    let len = b.len();
    if len == 0 || len > XNS_MAX_LEN {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        let ok = c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-';
        if !ok {
            return false;
        }
        if c == b'-' && i > 0 && b[i - 1] == b'-' {
            return false;
        }
    }
    b[0] != b'-' && b[len - 1] != b'-'
}

/// Lowercase + validate a user-typed XNS label/namespace. Returns the normalized
/// (lowercased) string if valid, else `None`. We lowercase for input ergonomics
/// — the contract only accepts lowercase, and the on-chain key is derived from
/// these exact bytes, so the lowercased form is what gets registered/resolved.
pub fn normalize_label(s: &str) -> Option<String> {
    let lc = s.trim().to_ascii_lowercase();
    is_valid_label(&lc).then_some(lc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::keccak256;

    #[test]
    fn selectors_match_signatures() {
        // Pinned against `cast sig` (independently computed), so a drift in the
        // sol! signatures is a loud test failure, not a silent wrong-method call.
        assert_eq!(abi::getAddressCall::SELECTOR, [0x79, 0x1b, 0x6d, 0x60]);
        assert_eq!(abi::getNameCall::SELECTOR, [0x5f, 0xd4, 0xb0, 0x8a]);
        assert_eq!(
            abi::getNamespaceInfoCall::SELECTOR,
            [0x44, 0x29, 0xa5, 0x9c]
        );
        assert_eq!(abi::registerNameCall::SELECTOR, [0xff, 0x21, 0xce, 0x9c]);
        // And cross-check one against keccak directly.
        assert_eq!(
            &keccak256(b"registerName(string,string)").as_slice()[..4],
            abi::registerNameCall::SELECTOR.as_slice(),
        );
    }

    #[test]
    fn v2_registry_is_the_live_contract() {
        assert_eq!(
            XNS_REGISTRY,
            address!("0x6e797ba2d3103aF167918e71a7E01DE40D45f74b")
        );
    }

    #[test]
    fn get_address_call_roundtrips_label_and_namespace() {
        let (to, data) = get_address_call("rat", "cheese");
        assert_eq!(to, XNS_REGISTRY);
        assert_eq!(&data[0..4], &[0x79, 0x1b, 0x6d, 0x60]);
        let d = abi::getAddressCall::abi_decode(&data).unwrap();
        assert_eq!(d.label, "rat");
        assert_eq!(d.namespace, "cheese");
    }

    #[test]
    fn register_call_carries_value_and_args() {
        let value = U256::from(1_000u64);
        let (to, v, data) = register_call("cow", "crops", value);
        assert_eq!(to, XNS_REGISTRY);
        assert_eq!(v, value);
        assert_eq!(&data[0..4], &[0xff, 0x21, 0xce, 0x9c]);
        let d = abi::registerNameCall::abi_decode(&data).unwrap();
        assert_eq!(d.label, "cow");
        assert_eq!(d.namespace, "crops");
    }

    #[test]
    fn namespace_info_decodes_four_words() {
        // price=7, owner=0x..beef, createdAt=1_700_000_000, isPrivate=true.
        let owner = address!("0x000000000000000000000000000000000000bEEF");
        let mut buf = vec![0u8; 128];
        buf[31] = 7;
        buf[44..64].copy_from_slice(owner.as_slice());
        buf[88..96].copy_from_slice(&1_700_000_000u64.to_be_bytes());
        buf[127] = 1;
        let info = decode_namespace_info(&buf).unwrap();
        assert_eq!(info.price, U256::from(7u64));
        assert_eq!(info.owner, owner);
        assert_eq!(info.created_at, 1_700_000_000);
        assert!(info.is_private);
        // Short data / zero owner → None.
        assert!(decode_namespace_info(&[0u8; 64]).is_none());
        assert!(decode_namespace_info(&[0u8; 128]).is_none(), "zero owner");
    }

    #[test]
    fn public_open_and_exclusivity_window() {
        let info = NamespaceInfo {
            price: U256::ZERO,
            owner: address!("0x000000000000000000000000000000000000bEEF"),
            created_at: 1_000,
            is_private: false,
        };
        // Inside the 7-day window → exclusive, not open.
        assert!(info.in_exclusivity(1_000 + XNS_EXCLUSIVITY_PERIOD));
        assert!(!info.public_open(1_000 + XNS_EXCLUSIVITY_PERIOD));
        // One second past → open.
        assert!(!info.in_exclusivity(1_001 + XNS_EXCLUSIVITY_PERIOD));
        assert!(info.public_open(1_001 + XNS_EXCLUSIVITY_PERIOD));
        // Private is never publicly open.
        let priv_ns = NamespaceInfo {
            is_private: true,
            ..info
        };
        assert!(!priv_ns.public_open(1_001 + XNS_EXCLUSIVITY_PERIOD));
    }

    #[test]
    fn label_validation_mirrors_contract_rules() {
        assert!(is_valid_label("rat"));
        assert!(is_valid_label("cow-boy"));
        assert!(is_valid_label("a1b2c3"));
        assert!(is_valid_label("x")); // 1 char ok
        assert!(is_valid_label("eth")); // unblocked in v2
        assert!(is_valid_label(&"a".repeat(20))); // 20 ok
        assert!(!is_valid_label(&"a".repeat(21)), "21 too long");
        assert!(!is_valid_label(""), "empty");
        assert!(!is_valid_label("-rat"), "leading hyphen");
        assert!(!is_valid_label("rat-"), "trailing hyphen");
        assert!(!is_valid_label("ra--t"), "consecutive hyphens");
        assert!(!is_valid_label("Rat"), "uppercase");
        assert!(!is_valid_label("rät"), "non-ascii");
        assert!(!is_valid_label("ra_t"), "underscore");
        assert!(!is_valid_label("ra.t"), "dot");
        assert!(!is_valid_label("ra@t"), "at");
    }

    #[test]
    fn normalize_lowercases_then_validates() {
        assert_eq!(normalize_label("  Cow ").as_deref(), Some("cow"));
        assert_eq!(normalize_label("RAT").as_deref(), Some("rat"));
        // Lowercasing can't rescue structurally-invalid input.
        assert_eq!(normalize_label("ra_t"), None);
        assert_eq!(normalize_label("-x"), None);
    }
}
