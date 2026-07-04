// The Indexer trait is not yet wired into the UI; these implementations
// satisfy the trait API surface that future wallet/portfolio screens will
// consume. Keep the dead-code lint silenced module-wide until then so warnings
// don't drown out genuine ones.
#![allow(dead_code)]

//! Third-party indexers for transaction history and ERC-20 balance fan-out.
//!
//! These are NOT light-client verified. Native ETH balance verification stays
//! in `crate::net` (Helios). The indexer trades trust for coverage and speed:
//! one HTTP round-trip discovers every token an address holds, including
//! assets the bundled `portfolio::TOKEN_LIST` doesn't know about.
//!
//! Three implementations live in this module: Blockscout (no key), Etherscan
//! (V2 API), and Alchemy. The active provider is chosen via
//! `crate::settings::indexer_provider`.

use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use alloy::primitives::{Address, B256, U256};
use async_trait::async_trait;
use tracing::debug;

use crate::chain::Chain;
use crate::portfolio::{DiscoveredToken, LiveToken};
use crate::settings::{self, IndexerProvider};

mod alchemy;
mod blockscout;
mod drpc;
mod etherscan;
pub mod onchain;

pub use alchemy::AlchemyClient;
pub use blockscout::BlockscoutClient;
pub use drpc::{DrpcClient, KaoClient};
pub use etherscan::EtherscanClient;

/// Outcome of a single transaction relative to the queried address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxStatus {
    Success,
    Failure,
    Pending,
}

/// Direction of value flow relative to the queried address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxDirection {
    In,
    Out,
    SelfTransfer,
}

/// Provider-agnostic transaction summary. Fields the indexer doesn't surface
/// are `None` rather than zero so the UI can distinguish "missing" from "0".
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct IndexedTx {
    pub hash: B256,
    pub block_number: u64,
    /// Unix seconds.
    pub timestamp: u64,
    pub from: Address,
    /// `None` for contract creation.
    pub to: Option<Address>,
    /// Native ETH value in wei.
    pub value: U256,
    pub gas_used: Option<u64>,
    pub gas_price: Option<u128>,
    pub status: TxStatus,
    pub direction: TxDirection,
    /// Decoded function name when the provider supplies it.
    pub method: Option<String>,
    /// `Some(_)` when this row represents an ERC-20 transfer rather than a
    /// pure native-ETH transaction. The outer `value` for ERC-20 rows is
    /// usually zero (the actual amount lives in `token.amount_raw`); the
    /// renderer should prefer the token fields when present.
    pub token: Option<TokenTransfer>,
    /// Chain this row was fetched from. Stamped by the caller after the
    /// per-chain `Indexer` returns its rows so the merged activity feed
    /// can render a chain badge per row and route the explorer URL to
    /// the right network.
    pub chain: Chain,
}

/// Token transfer details attached to an `IndexedTx`. Captured from the
/// indexer's token-transfer endpoint (or the on-chain log fallback) so
/// the activity feed can format `1.23 USDC` or `BAYC #4321` instead of
/// `0 ETH` for a token send.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TokenTransfer {
    pub contract: Address,
    pub symbol: String,
    pub decimals: u8,
    /// ERC-20 amount in smallest unit; for ERC-721 this is `1`.
    pub amount_raw: U256,
    /// `true` for ERC-721 / NFT rows. Renderer shows `SYMBOL #N` instead
    /// of decimal-formatted amount.
    pub is_nft: bool,
    /// `Some(id)` for ERC-721; `None` for ERC-20.
    pub token_id: Option<U256>,
}

/// Provider-agnostic token holding. Mirrors `portfolio::LiveToken` but is
/// distinct because the indexer's price/logo come from the indexer (or are
/// missing), whereas `LiveToken` carries on-chain Uniswap prices and bundled
/// logo IDs. Callers wanting Helios-verified data must use
/// `portfolio::fetch_portfolio` instead.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct IndexedToken {
    pub symbol: String,
    pub name: String,
    /// `None` for native ETH; `Some(addr)` for ERC-20s.
    pub contract: Option<Address>,
    pub decimals: u8,
    pub balance_raw: U256,
    pub balance_f64: f64,
    /// Display string formatted with the same rules as `portfolio::LiveToken`.
    pub balance: String,
    /// `None` when the indexer doesn't price this asset.
    pub usd_price: Option<f64>,
    pub usd_value: Option<f64>,
    /// Remote URL — indexers serve full URLs, unlike the bundled token-logo IDs
    /// the curated portfolio uses.
    pub logo_url: Option<String>,
}

/// Source of unverified transaction history and balance fan-out.
#[async_trait]
pub trait Indexer: Send + Sync + std::fmt::Debug {
    /// Most recent transactions involving `addr`, newest first, up to `limit`.
    async fn transactions(&self, addr: Address, limit: usize) -> Result<Vec<IndexedTx>, String>;

    /// Native ETH plus every ERC-20 the indexer knows `addr` holds, with
    /// prices when the provider supplies them. NOT light-client verified.
    async fn balances(&self, addr: Address) -> Result<Vec<IndexedToken>, String>;
}

/// Format a `reqwest::Error` for an error string or log line **without**
/// including the request URL. Every indexer in this module embeds its
/// API key in the URL (path segment for Alchemy/dRPC/Etherscan, query
/// string for Blockscout), so the default `Display` impl — which ends
/// with `for url (...)` — would leak the key into any log line that
/// surfaces the error.
///
/// `without_url()` clears that keyed URL, but reqwest's own `Display` is
/// then terse to the point of uselessness: a transport failure renders as
/// just `"error sending request"` with no hint of *why* (DNS, connection
/// refused, TLS, timeout). So we also walk the [`std::error::Error::source`]
/// chain and append each underlying cause. Those inner hyper/io errors
/// carry transport-level detail only — a host:port at most — and never the
/// request URL's path or query, so surfacing them stays key-safe.
///
/// Always route reqwest errors through this helper instead of writing
/// `format!("…: {e}")` directly. See `feedback_reqwest_url_leak.md`.
pub(crate) fn redact_url_in_err(e: reqwest::Error) -> String {
    let e = e.without_url();
    let mut msg = e.to_string();
    let mut src = std::error::Error::source(&e);
    while let Some(cause) = src {
        let cause_msg = cause.to_string();
        // Skip a cause that just restates the message already appended
        // (some wrappers re-`Display` their inner error verbatim).
        if !msg.ends_with(&cause_msg) {
            msg.push_str(": ");
            msg.push_str(&cause_msg);
        }
        src = cause.source();
    }
    msg
}

/// Shared `reqwest::Client` for every indexer impl. One TLS pool per process,
/// reused across account switches and provider changes.
pub(crate) fn http_client() -> Option<&'static reqwest::Client> {
    static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            // Build failure means the TLS backend couldn't initialize — an
            // unrecoverable environment fault. Cache `None` and let callers
            // surface a network error rather than panicking a UI task (which
            // would take down the whole window). The failure is deterministic,
            // so caching it is correct: a retry would fail identically.
            reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .user_agent(concat!("kao/", env!("CARGO_PKG_VERSION")))
                .build()
                .map_err(|e| tracing::error!("failed to build shared HTTP client: {e}"))
                .ok()
        })
        .as_ref()
}

/// `http_client()` or a uniform error string for the indexer / Safe-service
/// call sites.
pub(crate) fn http_client_or_err() -> Result<&'static reqwest::Client, String> {
    http_client().ok_or_else(|| "HTTP client unavailable (TLS init failed)".to_string())
}

/// Token `decimals` from an indexer's metadata, or a **logged** fallback to 18.
/// Indexer JSON is untrusted and can omit or garble `decimals`; defaulting
/// silently would rescale a balance/amount by up to 10^12 (a 6-decimal USDC
/// rendered as 18), so surface the gap. Live balances are re-read on-chain;
/// this keeps the indexer/activity-feed fallback visible (`RUST_LOG=kao=warn`).
pub(crate) fn decimals_or_default(parsed: Option<u8>, token: impl std::fmt::Display) -> u8 {
    parsed.unwrap_or_else(|| {
        tracing::warn!(%token, "token decimals missing/unparseable from indexer; defaulting to 18 — displayed scale may be wrong");
        18
    })
}

/// A parsed token amount, or a **logged** fallback to zero. A silent
/// `unwrap_or(U256::ZERO)` on untrusted indexer data would hide a real balance
/// or transfer behind a plausible "0"; this records the parse failure instead.
pub(crate) fn amount_or_zero_logged<E: std::fmt::Display>(
    parsed: Result<U256, E>,
    token: impl std::fmt::Display,
) -> U256 {
    parsed.unwrap_or_else(|e| {
        tracing::warn!(%token, error = %e, "unparseable amount from indexer; showing 0");
        U256::ZERO
    })
}

/// Build an indexer for `chain` matching the user's settings.
///
/// Mainnet keeps the full provider matrix (Blockscout / Etherscan /
/// Alchemy / None). For L2 chains we currently only wire up Alchemy —
/// it natively supports per-chain scoping via its `networks` slug.
/// Blockscout and Etherscan are mainnet-only on the public side; rather
/// than route L2 fetches at a mainnet-shaped indexer we return
/// `NoopIndexer`, which the dashboard treats as "no indexer answer; use
/// the on-chain walk fallback". The on-chain walk on L2 surfaces native
/// ETH (the curated L2 token list is empty); per-chain Blockscout /
/// Etherscan support is a follow-up.
///
/// Falls back to `NoopIndexer` whenever the chosen provider isn't viable
/// for the requested chain (missing API key, mainnet-only provider on
/// L2). The previous mainnet-only behavior is preserved for
/// `Chain::Mainnet` callers.
#[allow(dead_code)]
pub fn build_indexer_for(chain: Chain) -> Arc<dyn Indexer> {
    // Route Blockscout per chain. Mainnet honors any
    // `settings::blockscout_base_url` override (so a user can point at
    // a self-hosted instance or a non-canonical mirror); L2 chains use
    // the canonical Blockscout deployment URL — Blockscout runs as
    // separate instances per chain and the user's mainnet API key
    // wouldn't auth against `base.blockscout.com` anyway, so we drop
    // the key on L2.
    let blockscout = |c: Chain| -> Arc<dyn Indexer> {
        match c {
            Chain::Mainnet => Arc::new(BlockscoutClient::new(
                settings::blockscout_base_url(),
                settings::blockscout_api_key(),
            )),
            Chain::Base | Chain::Optimism => Arc::new(BlockscoutClient::new(
                Some(c.default_blockscout_url().to_string()),
                None,
            )),
        }
    };
    let noop = || -> Arc<dyn Indexer> { Arc::new(NoopIndexer) };
    let provider = settings::indexer_provider();
    match (chain, provider) {
        (_, IndexerProvider::Blockscout) => blockscout(chain),
        (Chain::Mainnet, IndexerProvider::Etherscan) => match settings::etherscan_api_key() {
            Some(key) => Arc::new(EtherscanClient::new(key)),
            None => blockscout(Chain::Mainnet),
        },
        (_, IndexerProvider::Alchemy) => match settings::alchemy_api_key() {
            Some(key) => Arc::new(AlchemyClient::new(key, chain)),
            // Per-chain key fallback differs by chain: mainnet drops
            // to Blockscout (matching pre-L2 behavior), L2 drops to
            // Blockscout's canonical instance for that chain so the
            // user still gets per-chain portfolio data.
            None => blockscout(chain),
        },
        (_, IndexerProvider::Drpc) => match settings::drpc_api_key() {
            Some(key) => Arc::new(DrpcClient::new(key, chain)),
            None => blockscout(chain),
        },
        // The Kao proxy holds the dRPC key and supports every chain we do,
        // so there's no per-chain fallback — it answers for all of them.
        (_, IndexerProvider::Kao) => Arc::new(KaoClient::new(settings::kao_server_url(), chain)),
        (_, IndexerProvider::None) => noop(),
        // L2 + Etherscan: Etherscan v2 supports multi-chain via
        // `chainid` but our `EtherscanClient` doesn't carry that yet.
        // Fall through to the canonical Blockscout instance so L2
        // portfolio still resolves; per-chain Etherscan is a follow-up.
        (Chain::Base | Chain::Optimism, IndexerProvider::Etherscan) => blockscout(chain),
    }
}

/// Parse an RFC 3339 timestamp (`YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)`)
/// to unix seconds. Used by Blockscout (`timestamp`) and Alchemy
/// (`metadata.blockTimestamp`); both encode the same way. Returns 0 on a
/// malformed input rather than failing the whole tx-list response over a
/// single bad timestamp.
pub(crate) fn parse_iso8601(s: &str) -> u64 {
    let b = s.as_bytes();
    if b.len() < 19 {
        return 0;
    }
    let y = parse_digits(&b[0..4]) as i32;
    let mo = parse_digits(&b[5..7]);
    let d = parse_digits(&b[8..10]);
    let h = parse_digits(&b[11..13]);
    let mi = parse_digits(&b[14..16]);
    let se = parse_digits(&b[17..19]);
    let days = days_from_civil(y, mo, d);
    if days < 0 {
        return 0;
    }
    days as u64 * 86_400 + h as u64 * 3600 + mi as u64 * 60 + se as u64
}

fn parse_digits(b: &[u8]) -> u32 {
    let mut v = 0u32;
    for &c in b {
        if !c.is_ascii_digit() {
            return v;
        }
        v = v * 10 + (c - b'0') as u32;
    }
    v
}

/// Howard Hinnant's "days from civil" — proleptic Gregorian days since the
/// 1970-01-01 epoch. Public-domain algorithm.
fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = (y - era * 400) as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as i64 + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era as i64 * 146_097 + doe - 719_468
}

/// Project the indexer's token-holdings rows down to *just* the
/// (address, symbol, name, decimals) tuples the on-chain Multicall3 walk
/// needs for discovery. Indexer-reported balances and prices are
/// intentionally dropped — those round-trip through Multicall3 against
/// the chain RPC instead, so the user never trusts an indexer's
/// unverified balance.
///
/// Native ETH rows (`contract: None`) are filtered out because
/// `portfolio::fetch_portfolio_with_discovery` already handles native
/// ETH via `Multicall3.getEthBalance`.
pub fn into_discovered_tokens(tokens: Vec<IndexedToken>) -> Vec<DiscoveredToken> {
    tokens
        .into_iter()
        .filter_map(|t| {
            t.contract.map(|address| DiscoveredToken {
                symbol: t.symbol,
                name: t.name,
                address,
                decimals: t.decimals,
            })
        })
        .collect()
}

/// Convert indexer-fetched tokens to the dashboard's `LiveToken` shape so
/// the existing portfolio UI can render them without touching every call
/// site. Indexer-supplied prices may be missing — those map to `0.0` in
/// `LiveToken` so the column sort behaves the same way as the on-chain
/// portfolio path. Logos resolve at render time from `(chain, contract)`
/// against the bundled SVG set; tokens not in the bundle render the
/// kaomoji fallback avatar.
///
/// **Native-row identity is chain-authoritative, never indexer-supplied.**
/// A `contract: None` row is the native gas coin, and the send flow keys off
/// exactly that (`build_plan` maps `None` → `SendToken::Native`). The row's
/// `symbol`/`name`/`decimals` flow straight into the send review's title,
/// intent banner, and revm balance-change card, so if we trusted the
/// indexer's fields here a hostile or compromised indexer could label a
/// native-ETH transfer as, say, `USDC` — the user reviews and signs a "token"
/// send that is actually plain ETH (review != signed). We therefore overwrite
/// the native row's identity with the chain's own native currency and pin its
/// decimals to 18, matching what the trusted on-chain portfolio path already
/// hardcodes. The (unverified) indexer balance is kept — that is the
/// documented L2 trade-off and only feeds display + a soft gas check, not the
/// asset being signed.
pub fn into_live_tokens(chain: Chain, tokens: Vec<IndexedToken>) -> Vec<LiveToken> {
    tokens
        .into_iter()
        .filter(|t| {
            if t.balance_raw.is_zero() {
                debug!(
                    chain = %chain.label(),
                    symbol = %t.symbol,
                    "dropping zero-balance token from indexer",
                );
                false
            } else {
                true
            }
        })
        .map(|t| {
            let is_native = t.contract.is_none();
            LiveToken {
                symbol: if is_native {
                    chain.native_symbol().to_string()
                } else {
                    t.symbol
                },
                name: if is_native {
                    chain.native_name().to_string()
                } else {
                    t.name
                },
                balance: t.balance,
                balance_f64: t.balance_f64,
                balance_raw: t.balance_raw,
                decimals: if is_native { 18 } else { t.decimals },
                contract: t.contract,
                usd_price: t.usd_price.unwrap_or(0.0),
                usd_value: t.usd_value.unwrap_or(0.0),
                chain: chain.into(),
            }
        })
        .collect()
}

/// Classify a tx's direction relative to `owner`. Centralized so each impl
/// doesn't reimplement the self-transfer edge case.
pub fn classify_direction(from: Address, to: Option<Address>, owner: Address) -> TxDirection {
    let from_owner = from == owner;
    let to_owner = to == Some(owner);
    match (from_owner, to_owner) {
        (true, true) => TxDirection::SelfTransfer,
        (true, false) => TxDirection::Out,
        (false, true) => TxDirection::In,
        // Indexers may surface txs that touch `owner` via internal calls or
        // logs without `owner` being either endpoint of the outer tx.
        // Treat that as inbound — it's the conservative default for "this
        // address received something".
        (false, false) => TxDirection::In,
    }
}

/// Indexer that returns empty results for everything. Selected when the user
/// picks `IndexerProvider::None` — the wallet still works (balances come
/// from the on-chain `portfolio` walk; tx history is just empty).
#[derive(Debug, Default)]
pub struct NoopIndexer;

#[async_trait]
impl Indexer for NoopIndexer {
    async fn transactions(&self, _addr: Address, _limit: usize) -> Result<Vec<IndexedTx>, String> {
        Ok(Vec::new())
    }

    async fn balances(&self, _addr: Address) -> Result<Vec<IndexedToken>, String> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_indexer_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoopIndexer>();
        assert_send_sync::<Arc<dyn Indexer>>();
    }

    #[test]
    fn iso8601_known_epochs() {
        assert_eq!(parse_iso8601("1970-01-01T00:00:00.000000Z"), 0);
        assert_eq!(parse_iso8601("2024-01-01T00:00:00.000000Z"), 1_704_067_200);
        assert_eq!(parse_iso8601("2024-06-15T12:34:56.000000Z"), 1_718_454_896);
    }

    /// `into_discovered_tokens` is the discovery-mode hand-off: it must
    /// drop the indexer's native-ETH row (since `fetch_portfolio_with_discovery`
    /// handles ETH on its own via `Multicall3.getEthBalance`) and forward
    /// each ERC-20 row's metadata without touching the indexer's reported
    /// balance/price fields — those flow through Multicall3 instead, so
    /// the user never trusts an unverified balance from the indexer.
    #[test]
    fn into_discovered_tokens_drops_native_eth_and_keeps_metadata() {
        let usdc: Address = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
            .parse()
            .unwrap();
        let beef: Address = "0x000000000000000000000000000000000000beef"
            .parse()
            .unwrap();
        let tokens = vec![
            IndexedToken {
                symbol: "ETH".into(),
                name: "Ethereum".into(),
                contract: None,
                decimals: 18,
                balance_raw: U256::from(999u64),
                balance_f64: 1.0,
                balance: "1".into(),
                usd_price: Some(3000.0),
                usd_value: Some(3000.0),
                logo_url: None,
            },
            IndexedToken {
                symbol: "USDC".into(),
                name: "USD Coin".into(),
                contract: Some(usdc),
                decimals: 6,
                balance_raw: U256::from(123_456u64),
                balance_f64: 0.123456,
                balance: "0.123456".into(),
                // Bogus indexer-reported price; must not leak into the
                // discovered row.
                usd_price: Some(99.0),
                usd_value: Some(12.0),
                logo_url: None,
            },
            IndexedToken {
                symbol: "BEEF".into(),
                name: "Beef".into(),
                contract: Some(beef),
                decimals: 9,
                balance_raw: U256::from(1u8),
                balance_f64: 0.0,
                balance: "0".into(),
                usd_price: None,
                usd_value: None,
                logo_url: None,
            },
        ];
        let discovered = into_discovered_tokens(tokens);
        assert_eq!(discovered.len(), 2, "native ETH row must be dropped");
        assert_eq!(discovered[0].address, usdc);
        assert_eq!(discovered[0].symbol, "USDC");
        assert_eq!(discovered[0].decimals, 6);
        assert_eq!(discovered[1].address, beef);
        assert_eq!(discovered[1].decimals, 9);
    }

    #[test]
    fn into_live_tokens_assigns_native_eth_logo_and_zeroes_missing_prices() {
        let usdc: Address = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
            .parse()
            .unwrap();
        let unknown: Address = "0x000000000000000000000000000000000000beef"
            .parse()
            .unwrap();
        let tokens = vec![
            IndexedToken {
                symbol: "ETH".into(),
                name: "Ethereum".into(),
                contract: None,
                decimals: 18,
                balance_raw: alloy::primitives::U256::from(1u8),
                balance_f64: 0.000000000000000001,
                balance: "0.0000".into(),
                usd_price: Some(2000.0),
                usd_value: Some(0.0),
                logo_url: None,
            },
            IndexedToken {
                symbol: "USDC".into(),
                name: "USD Coin".into(),
                contract: Some(usdc),
                decimals: 6,
                balance_raw: alloy::primitives::U256::from(1u8),
                balance_f64: 0.000001,
                balance: "0.000001".into(),
                usd_price: None, // indexer didn't supply a price
                usd_value: None,
                logo_url: None,
            },
            IndexedToken {
                symbol: "BEEF".into(),
                name: "Random".into(),
                contract: Some(unknown),
                decimals: 18,
                balance_raw: alloy::primitives::U256::from(1u8),
                balance_f64: 0.0,
                balance: "0".into(),
                usd_price: None,
                usd_value: None,
                logo_url: None,
            },
        ];
        let live = into_live_tokens(Chain::Mainnet, tokens);
        assert_eq!(live[0].contract, None, "native ETH preserved");
        assert_eq!(live[1].contract, Some(usdc));
        assert_eq!(live[2].contract, Some(unknown));
        assert_eq!(
            live[1].usd_price, 0.0,
            "missing indexer price collapses to 0"
        );
        assert_eq!(live[1].usd_value, 0.0);
        for tk in &live {
            assert_eq!(tk.chain, Chain::Mainnet.into());
        }
    }

    /// Security regression for the native-row spoof: a hostile/compromised L2
    /// indexer that returns a `contract: None` (native) row wearing an ERC-20's
    /// symbol/name/decimals must NOT be able to make the send review call a
    /// native-ETH transfer "USDC". `into_live_tokens` pins the native row's
    /// identity to the chain's own coin regardless of what the indexer claimed;
    /// only the (unverified) balance is carried through.
    #[test]
    fn into_live_tokens_pins_native_row_identity_over_indexer() {
        let tokens = vec![IndexedToken {
            // Attacker-controlled: a native row masquerading as USDC.
            symbol: "USDC".into(),
            name: "USD Coin".into(),
            contract: None,
            decimals: 6,
            balance_raw: alloy::primitives::U256::from(5u8),
            balance_f64: 5.0,
            balance: "5".into(),
            usd_price: Some(1.0),
            usd_value: Some(5.0),
            logo_url: None,
        }];
        let live = into_live_tokens(Chain::Base, tokens);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].contract, None, "still a native row");
        assert_eq!(live[0].symbol, "ETH", "spoofed native symbol overridden");
        assert_eq!(live[0].name, "Ethereum", "spoofed native name overridden");
        assert_eq!(live[0].decimals, 18, "native decimals pinned to 18");
        // The (unverified) balance is the documented L2 trade-off; it is kept.
        assert_eq!(live[0].balance_raw, alloy::primitives::U256::from(5u8));
    }

    #[test]
    fn into_live_tokens_drops_zero_balance_entries() {
        let usdc: Address = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
            .parse()
            .unwrap();
        let tokens = vec![
            IndexedToken {
                symbol: "ETH".into(),
                name: "Ethereum".into(),
                contract: None,
                decimals: 18,
                balance_raw: alloy::primitives::U256::ZERO,
                balance_f64: 0.0,
                balance: "0".into(),
                usd_price: Some(2000.0),
                usd_value: Some(0.0),
                logo_url: None,
            },
            IndexedToken {
                symbol: "USDC".into(),
                name: "USD Coin".into(),
                contract: Some(usdc),
                decimals: 6,
                balance_raw: alloy::primitives::U256::ZERO,
                balance_f64: 0.0,
                balance: "0".into(),
                usd_price: Some(1.0),
                usd_value: Some(0.0),
                logo_url: None,
            },
        ];
        let live = into_live_tokens(Chain::Optimism, tokens);
        assert!(
            live.is_empty(),
            "all zero-balance tokens must be filtered out"
        );
    }

    #[test]
    fn classify_direction_covers_all_cases() {
        let me = Address::repeat_byte(0x11);
        let other = Address::repeat_byte(0x22);
        assert_eq!(classify_direction(me, Some(other), me), TxDirection::Out);
        assert_eq!(classify_direction(other, Some(me), me), TxDirection::In);
        assert_eq!(
            classify_direction(me, Some(me), me),
            TxDirection::SelfTransfer,
        );
        assert_eq!(classify_direction(me, None, me), TxDirection::Out);
        assert_eq!(classify_direction(other, None, me), TxDirection::In);
    }

    #[test]
    fn iso8601_short_returns_zero() {
        assert_eq!(parse_iso8601(""), 0);
        assert_eq!(parse_iso8601("2024"), 0);
        assert_eq!(parse_iso8601("2024-01-01"), 0);
    }

    #[test]
    fn iso8601_with_timezone_offset_ignored() {
        // Only the first 19 chars of the timestamp are parsed — fractions
        // and timezones are ignored.
        assert_eq!(parse_iso8601("2024-01-01T00:00:00+05:30"), 1_704_067_200,);
    }

    #[test]
    fn noop_indexer_returns_empty_vecs() {
        let n = NoopIndexer;
        let addr = Address::ZERO;
        let txs = futures::executor::block_on(n.transactions(addr, 10)).unwrap();
        let bals = futures::executor::block_on(n.balances(addr)).unwrap();
        assert!(txs.is_empty());
        assert!(bals.is_empty());
    }

    #[test]
    fn http_client_singleton() {
        let a = http_client().unwrap();
        let b = http_client().unwrap();
        assert!(std::ptr::eq(a, b));
    }

    #[test]
    fn redact_appends_underlying_cause() {
        // A builder error for a malformed URL wraps the url parse error as
        // its `source()`. The helper must surface that cause instead of
        // collapsing to reqwest's terse top-level message — that's the
        // whole point of the verbose-logging change.
        let err = http_client().unwrap().get("not a url").build().unwrap_err();
        let redacted = redact_url_in_err(err);
        assert!(
            redacted.contains(": "),
            "expected an appended cause after the top-level message, got: {redacted:?}"
        );
    }

    #[test]
    fn build_indexer_for_returns_for_every_chain() {
        // Doesn't matter which provider — just that the function returns
        // an Arc<dyn Indexer> without panicking for each chain. Settings
        // state is whatever the process default is; the function falls
        // back to NoopIndexer when no key is configured.
        for chain in [Chain::Mainnet, Chain::Base, Chain::Optimism] {
            let _idx: Arc<dyn Indexer> = build_indexer_for(chain);
        }
    }
}
