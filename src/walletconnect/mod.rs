//! WalletConnect v2, wallet side.
//!
//! Ownership: `App` owns one [`runtime::WcSlot`]. The [`runtime::WcRuntime`] inside it holds the
//! `SignClient`, Kao's [`book::WcBook`], a `closed` flag and the tokio handle it spawns every relay side
//! effect on — so nothing WalletConnect sends depends on an iced `Task` surviving a dashboard rebuild.
//! Lazy network: nothing here dials until the user pastes a `wc:` link and presses Connect.
//! Proxy: the relay socket goes through [`transport::KaoConnector`] — SOCKS5h whenever a proxy is
//! installed or exported by the environment Kao was launched from, fail closed. Sessions are in-memory only and end on lock / quit.

pub mod book;
#[cfg(test)]
mod e2e_tests;
pub mod message;
pub mod namespaces;
pub mod request;
pub mod runtime;
#[cfg(test)]
pub(crate) mod testkit;
pub mod transport;
pub mod typed;
pub mod types;

use std::time::Duration;

use crate::chain::{Chain, NetworkId};

pub use types::*;
pub use wallet_connect::crypto::Topic;

pub const MAX_DAPP_NAME_CHARS: usize = 40;
pub const MAX_DAPP_HOST_CHARS: usize = 80;
pub const MAX_DAPP_URL_CHARS: usize = 80;
pub const MAX_DAPP_DESCRIPTION_CHARS: usize = 140;
pub const MAX_SUMMARY_CHARS: usize = 80;
pub const MAX_SESSIONS: usize = 16;
pub const MAX_QUEUE_PER_SESSION: usize = 8;
pub const MAX_QUEUE_TOTAL: usize = 32;
pub const MAX_AUTO_ANSWERS_PER_MIN: u32 = 30;
pub const MAX_NOTICES: usize = 20;
pub const ANSWERED_MEMORY: usize = 4096;
/// Kao's own deadline for a request (also the cap on a dapp-supplied expiry). Never applied once Signing.
pub const KAO_REQUEST_TTL_SECS: u64 = 60 * 60;
pub const AUTO_OPEN_MAX_AGE_SECS: u64 = 10 * 60;
/// The crate sweeps expiries up to 5 s late; treat `now + margin >= dapp expiry` as dead.
pub const EXPIRY_MARGIN_SECS: u64 = 5;
pub const PAIRING_WAIT_DEFAULT_SECS: u64 = 5 * 60;
pub const PAIRING_WAIT_MAX_SECS: u64 = 10 * 60;
pub const PAIRING_HINT_AFTER_SECS: u64 = 15;
pub const IDLE_RETIRE_SECS: u64 = 30;
pub const REJECT_STREAK_PAUSE: u32 = 3;
pub const ATTENTION_MIN_INTERVAL: Duration = Duration::from_secs(10);
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_TYPED_DATA_BYTES: usize = 256 * 1024;
pub const MAX_TYPED_JSON_DEPTH: usize = 32;
pub const MAX_TYPED_TYPES: usize = 64;
pub const MAX_TYPED_ROWS: usize = 400;
pub const MAX_TX_DATA_BYTES: usize = 128 * 1024;
pub const QUOTE_MAX_AGE: Duration = Duration::from_secs(90);
pub const TEARDOWN_PER_PHASE: Duration = Duration::from_secs(2);
pub const QUIT_TEARDOWN_BUDGET: Duration = Duration::from_secs(5);
/// Safe Transaction Service `origin` for WC proposals — a constant, so co-signers never see dapp strings.
pub const SAFE_PROPOSE_ORIGIN: &str = "Kao:walletconnect";
const KAO_WC_URL: &str = "https://github.com/kaowallet/kao";

/// What dapps see as the wallet. No icons: there is nothing for a dapp to make us fetch.
pub fn kao_metadata() -> wallet_connect::sign::Metadata {
    wallet_connect::sign::Metadata::new("Kao Wallet", "Kao desktop wallet", KAO_WC_URL)
}

pub fn now_secs() -> u64 {
    wallet_connect::time::now_secs()
}

pub fn caip2(chain_id: u64) -> String {
    format!("eip155:{chain_id}")
}

/// Strict CAIP-2 for eip155: canonical decimal, no sign, no leading zero (unless "0"), fits u64.
pub fn parse_eip155(caip2: &str) -> Option<u64> {
    let r = caip2.strip_prefix("eip155:")?;
    if r.is_empty() || !r.bytes().all(|b| b.is_ascii_digit()) || (r.len() > 1 && r.starts_with('0'))
    {
        return None;
    }
    r.parse().ok()
}

/// Chains Kao can serve to a dapp right now: built-ins with ≥ 1 execution RPC, then enabled
/// custom networks. Getters only — safe in tests.
pub fn served_chain_ids() -> Vec<u64> {
    let mut v: Vec<u64> = Chain::ALL
        .iter()
        .filter(|c| !crate::settings::rpcs(**c).is_empty())
        .map(|c| c.chain_id())
        .collect();
    v.extend(
        crate::settings::enabled_custom_networks()
            .iter()
            .map(|n| n.chain_id),
    );
    v
}

/// Built-in via `Chain::from_chain_id`, else an **enabled** custom network.
pub fn network_id_for(chain_id: u64) -> Option<NetworkId> {
    if let Some(c) = Chain::from_chain_id(chain_id) {
        return Some(NetworkId::Builtin(c));
    }
    crate::settings::custom_network(chain_id)
        .filter(|n| n.enabled)
        .map(|_| NetworkId::Custom(chain_id))
}

pub fn chain_label(chain_id: u64) -> String {
    match network_id_for(chain_id) {
        Some(n) => n.display_name(),
        None => format!("Chain {chain_id}"),
    }
}

/// The native currency's symbol: a built-in chain's own, else the custom network's (the user's
/// text, sanitized and clamped), else the custom-network default.
pub fn native_symbol(chain_id: u64) -> String {
    match Chain::from_chain_id(chain_id) {
        Some(c) => c.native_symbol().to_string(),
        None => crate::settings::custom_network(chain_id)
            .map(|n| crate::sanitize::sanitize_display(&n.currency_symbol, 12).into_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| crate::settings::DEFAULT_CUSTOM_SYMBOL.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_eip155_strict() {
        assert_eq!(parse_eip155("eip155:1"), Some(1));
        assert_eq!(parse_eip155("eip155:0"), Some(0));
        assert_eq!(parse_eip155("eip155:8453"), Some(8453));
        assert_eq!(
            parse_eip155(&format!("eip155:{}", u64::MAX)),
            Some(u64::MAX)
        );
        for bad in [
            "eip155:",
            "eip155:01",
            "eip155:-1",
            "eip155:+1",
            "eip155: 1",
            "eip155:1 ",
            "eip155:0x1",
            "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
            "eip155:18446744073709551616", // u64::MAX + 1
            "eip155:١",                    // non-ASCII digit
            "cosmos:1",
            "EIP155:1",
            "1",
            "",
        ] {
            assert_eq!(parse_eip155(bad), None, "{bad:?} must not parse");
        }
        assert_eq!(caip2(8453), "eip155:8453");
        assert_eq!(parse_eip155(&caip2(10)), Some(10));
    }

    /// Default settings seed a Mainnet execution RPC, so Mainnet is always
    /// served. Getters only — no setter is ever called from a test.
    #[test]
    fn served_chain_ids_defaults_include_mainnet() {
        let served = served_chain_ids();
        assert!(served.contains(&Chain::Mainnet.chain_id()), "{served:?}");
        assert_eq!(network_id_for(1), Some(NetworkId::Builtin(Chain::Mainnet)));
        assert_eq!(chain_label(1), Chain::Mainnet.display_name());
        // An id that is neither built-in nor a configured custom network.
        assert_eq!(network_id_for(987_654_321), None);
        assert_eq!(chain_label(987_654_321), "Chain 987654321");
    }

    /// Nothing in Kao's own metadata gives a dapp something to make us fetch
    /// or open.
    #[test]
    fn kao_metadata_has_no_icons() {
        let m = kao_metadata();
        assert!(m.icons.is_empty());
        assert!(m.verify_url.is_none());
        assert!(m.redirect.is_none());
        assert_eq!(m.url, KAO_WC_URL);
        assert_eq!(m.name, "Kao Wallet");
    }
}
