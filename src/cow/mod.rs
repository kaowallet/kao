//! CoW Protocol (CoW Swap) integration — intent-based swapping via the
//! off-chain orderbook.
//!
//! A swap on CoW is an EIP-712-signed *intent* (the [`order::Order`]), not a
//! transaction: the user signs an order off-chain, it's POSTed to CoW's
//! orderbook ([`api`]), and solvers settle it on-chain through the
//! GPv2Settlement contract. Selling an ERC-20 first needs a one-time approval
//! to the [`VAULT_RELAYER`] ([`onchain`]); selling native ETH goes through the
//! [`ethflow`] contract instead (an on-chain `createOrder` with the ETH as
//! `msg.value`).
//!
//! ## Privacy posture
//!
//! Like the rest of Kao, every call here rides the process-wide `ALL_PROXY`
//! tunnel automatically (the shared client in [`crate::indexer::http_client`]).
//! Crucially, **nothing in this module fires until the UI calls it in response
//! to an explicit user action** (a "Get quote" / "Place order" click). There is
//! no background quoting or polling before the user opts in — status polling
//! only starts *after* an order has been deliberately placed.
//!
//! ## Supported networks
//!
//! CoW's orderbook runs on **Mainnet and Base only** — there is no Optimism
//! deployment (`api.cow.fi/optimism` 404s), even though the periphery contracts
//! exist there. [`supported`] / [`api_base`] gate the whole feature.

use alloy::primitives::{Address, B256, address, keccak256};

use crate::chain::Chain;

pub mod api;
pub mod composer;
pub mod ethflow;
pub mod history;
pub mod onchain;
pub mod order;
pub mod safe_sig;
pub mod tracked;

// ── Canonical contract addresses (same CREATE2 address on every CoW chain) ───

/// GPv2Settlement — the EIP-712 `verifyingContract` every order is signed
/// against, and the contract solvers settle through.
pub const SETTLEMENT: Address = address!("0x9008D19f58AAbD9eD0D60971565AA8510560ab41");

/// GPv2VaultRelayer — the spender a seller must ERC-20-`approve` before an
/// ERC-20 sell order can settle. It is the ONLY contract allowed to pull the
/// user's sell tokens, and it can only move them into settlement — approving
/// the settlement contract directly would never let an order fill.
pub const VAULT_RELAYER: Address = address!("0xC92E8bdf79f0507f65a392b0ab4667716BFE0110");

/// CoWSwapEthFlow (v1.1.0+) — places native-ETH sell orders on the user's
/// behalf (the user calls `createOrder` with ETH as `msg.value`; the contract
/// signs the resulting WETH order via EIP-1271). Same address on Mainnet and
/// Base. NOTE: the deprecated v1.0.0 deployment at
/// `0x40a50cf069e992aa4536211b23f286ef88752187` must NOT be used.
pub const ETHFLOW: Address = address!("0xbA3cB449bD2B4ADddBc894D8697F5170800EAdeC");

/// Our partner / referral code, stamped into every order's appData as
/// `appCode`. CoW attributes order volume to integrators by this string —
/// it is the only referral mechanism in the appData schema (the metadata
/// object is closed, and `metadata.referrer` takes an on-chain *address*,
/// not a code). CoW's analytics group Kao's flow under this exact value, so
/// changing it re-buckets attribution; keep it stable.
pub const APP_CODE: &str = "KAOWALLET";

/// The CoW appData schema version we emit — the latest published schema
/// (`@cowprotocol/sdk-app-data`'s `LATEST_APP_DATA_VERSION`).
pub const APP_DATA_VERSION: &str = "1.15.0";

/// Build the CoW **market-order** appData document and its keccak256 hash for a
/// given slippage (in bips).
///
/// Returns `(full_json, hash)`: `full_json` is the deterministic JSON string
/// (**keys sorted ascending at every level, no whitespace**) we POST as the
/// order's `appData` pre-image — and, for the native EthFlow path, upload via
/// `PUT /app_data`. `hash` is `keccak256(full_json)`, the `bytes32` the order's
/// signature commits to.
///
/// The load-bearing field is `metadata.orderClass.orderClass = "market"`.
/// Without it the orderbook books the order as a **limit** order, which a solver
/// only fills when the limit price leaves enough room to cover the settlement
/// fee — so a near-market swap with tight slippage sits OPEN forever. Our old
/// `"{}"` appData had no orderClass and fell into exactly that trap. Shape and
/// serialization mirror `@cowprotocol/sdk-app-data`'s `generateAppDataFromDoc`
/// (json-stringify-deterministic → keccak256); `APP_CODE`/`APP_DATA_VERSION`
/// contain no JSON-special characters, so direct interpolation is safe.
pub fn market_app_data(slippage_bips: u16) -> (String, B256) {
    let full_json = format!(
        r#"{{"appCode":"{APP_CODE}","metadata":{{"orderClass":{{"orderClass":"market"}},"quote":{{"slippageBips":{slippage_bips}}}}},"version":"{APP_DATA_VERSION}"}}"#
    );
    let hash = keccak256(full_json.as_bytes());
    (full_json, hash)
}

// ── Network gating ───────────────────────────────────────────────────────────

/// Whether CoW's orderbook runs on `chain`. Mainnet and Base only.
pub fn supported(chain: Chain) -> bool {
    api_base(chain).is_some()
}

/// Orderbook REST base URL for `chain` (no trailing slash), or `None` if CoW
/// has no orderbook there. Optimism is deliberately absent — there is no CoW
/// deployment, so the feature is hidden on it.
pub fn api_base(chain: Chain) -> Option<&'static str> {
    match chain {
        Chain::Mainnet => Some("https://api.cow.fi/mainnet/api/v1"),
        Chain::Base => Some("https://api.cow.fi/base/api/v1"),
        Chain::Optimism => None,
    }
}

/// CoW Explorer web URL for a placed order, addressed by its `uid` (the
/// `0x`-prefixed 56-byte order UID). The Explorer keys non-Mainnet chains by a
/// slug in the path (`/base/…`); Mainnet has no prefix. `None` on chains
/// without a CoW deployment (same gate as [`api_base`]), so callers can render
/// the link only when an order can actually exist.
pub fn explorer_order_url(chain: Chain, uid: &str) -> Option<String> {
    let net = match chain {
        Chain::Mainnet => "",
        Chain::Base => "/base",
        Chain::Optimism => return None,
    };
    Some(format!("https://explorer.cow.fi{net}/orders/{uid}"))
}

/// Wrapped-native (WETH) token for `chain` — the ERC-20 a native-ETH sell is
/// quoted and settled against. `None` on chains without a CoW orderbook.
pub fn wrapped_native(chain: Chain) -> Option<Address> {
    match chain {
        Chain::Mainnet => Some(address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")),
        Chain::Base => Some(address!("0x4200000000000000000000000000000000000006")),
        Chain::Optimism => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::keccak256;

    #[test]
    fn market_app_data_is_deterministic_and_self_consistent() {
        let (json, hash) = market_app_data(50);
        // Exact pre-image: keys ascending at every level, compact (no spaces),
        // orderClass=market present. A drift here re-introduces the limit-order
        // trap or makes the signed hash unreproducible from the POSTed string.
        assert_eq!(
            json,
            r#"{"appCode":"KAOWALLET","metadata":{"orderClass":{"orderClass":"market"},"quote":{"slippageBips":50}},"version":"1.15.0"}"#
        );
        // The signed hash MUST be keccak256 of the exact POSTed pre-image.
        assert_eq!(hash, keccak256(json.as_bytes()));
        // Keys are emitted in ascending order at every level.
        assert!(json.find("appCode").unwrap() < json.find("metadata").unwrap());
        assert!(json.find("metadata").unwrap() < json.find("version").unwrap());
        assert!(json.find("orderClass").unwrap() < json.find("quote").unwrap());
        // Slippage is interpolated as a bare integer.
        assert!(json.contains(r#""slippageBips":50"#));
    }

    #[test]
    fn supported_chains_are_mainnet_and_base_only() {
        assert!(supported(Chain::Mainnet));
        assert!(supported(Chain::Base));
        // Optimism has no CoW orderbook — must stay unsupported.
        assert!(!supported(Chain::Optimism));
    }

    #[test]
    fn api_base_slugs() {
        assert_eq!(
            api_base(Chain::Mainnet),
            Some("https://api.cow.fi/mainnet/api/v1")
        );
        assert_eq!(
            api_base(Chain::Base),
            Some("https://api.cow.fi/base/api/v1")
        );
        assert_eq!(api_base(Chain::Optimism), None);
    }

    #[test]
    fn explorer_order_url_per_chain() {
        let uid = "0xabc123";
        // Mainnet has no path prefix; Base is keyed by its slug.
        assert_eq!(
            explorer_order_url(Chain::Mainnet, uid).as_deref(),
            Some("https://explorer.cow.fi/orders/0xabc123")
        );
        assert_eq!(
            explorer_order_url(Chain::Base, uid).as_deref(),
            Some("https://explorer.cow.fi/base/orders/0xabc123")
        );
        // No CoW deployment on Optimism — no order can exist, so no link.
        assert_eq!(explorer_order_url(Chain::Optimism, uid), None);
    }

    #[test]
    fn explorer_link_exists_exactly_where_orders_can() {
        // The link is renderable on precisely the chains CoW runs on.
        for c in Chain::ALL {
            assert_eq!(explorer_order_url(c, "0x00").is_some(), supported(c));
        }
    }

    #[test]
    fn wrapped_native_matches_supported() {
        // WETH is defined exactly on the chains CoW supports.
        for c in Chain::ALL {
            assert_eq!(wrapped_native(c).is_some(), supported(c));
        }
    }

    #[test]
    fn ethflow_is_not_the_deprecated_v1_deployment() {
        // Sending ETH to the stale v1.0.0 contract would be a fund-loss bug.
        assert_ne!(
            ETHFLOW,
            address!("0x40a50cf069e992aa4536211b23f286ef88752187")
        );
    }
}
