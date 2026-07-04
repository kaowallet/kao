//! Live ERC-20 portfolio: token metadata, on-chain balance reads, and
//! Uniswap V3 on-chain price lookups. Replaces the hardcoded `TOKENS` array
//! that the dashboard used to carry.
//!
//! Prices are derived entirely on-chain by reading `slot0()` from Uniswap V3
//! pools — no external API calls, no API keys, no rate limits. ETH/USD comes
//! from the USDC/WETH 0.05 % pool; each ERC-20 is priced via its most-liquid
//! WETH pool.

use alloy::eips::BlockId;
use alloy::network::Ethereum;
use alloy::primitives::{Address, Bytes, U256, address, keccak256};
use alloy::providers::{Provider, RootProvider};
use alloy::sol;
use alloy::sol_types::SolCall;
use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tracing::{debug, trace, warn};

use crate::chain::{Chain, NetworkId};
use crate::wallet::short_address;

// ── Retry on RPC rate-limit ─────────────────────────────────────────────────

/// Public RPCs throttle aggressively (often returning HTTP 429 with a
/// `rate-limited until …` body) when the dashboard fans out a balance + price
/// batch. Without retrying, the user sees a spurious "$0.00" for the throttled
/// token until the next refresh tick. Retry the inner call with exponential
/// backoff when the transport surfaces a 429.
const RETRY_MAX_ATTEMPTS: u32 = 4;
const RETRY_INITIAL_DELAY: Duration = Duration::from_millis(500);
const RETRY_MAX_DELAY: Duration = Duration::from_secs(8);

fn is_rate_limited(msg: &str) -> bool {
    msg.contains("429")
        || msg.contains("rate-lim")
        || msg.contains("rate lim")
        || msg.contains("Too Many Requests")
}

pub(crate) async fn with_rate_limit_retry<T, E, F, Fut>(label: &str, f: F) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    with_retry_if(label, is_rate_limited, f).await
}

/// Like `with_rate_limit_retry`, but also retries provider-side request
/// timeouts (dRPC free tier kills any request over 2 s — its public
/// upstreams intermittently blow that budget even on a plain
/// `eth_getCode`). For single-shot reads the request can't be made
/// smaller, so a straight backoff-retry is the only remedy; `multicall3`
/// keeps timeouts out of its retry wrapper because shrinking the chunk
/// is the better response there.
pub(crate) async fn with_transient_retry<T, E, F, Fut>(label: &str, f: F) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    with_retry_if(label, |m| is_rate_limited(m) || is_provider_timeout(m), f).await
}

async fn with_retry_if<T, E, F, Fut>(
    label: &str,
    retryable: impl Fn(&str) -> bool,
    f: F,
) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut delay = RETRY_INITIAL_DELAY;
    for attempt in 1..=RETRY_MAX_ATTEMPTS {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) if attempt < RETRY_MAX_ATTEMPTS && retryable(&e.to_string()) => {
                warn!(
                    label,
                    attempt,
                    delay_ms = delay.as_millis() as u64,
                    error = %e,
                    "transient rpc error; retrying",
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(RETRY_MAX_DELAY);
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!("loop returns on success or final error");
}

// ── Multicall3 ──────────────────────────────────────────────────────────────

/// Canonical Multicall3 deployment. Same address on every chain we
/// support — Mainnet, Base, Optimism — so a single constant suffices.
/// Used to batch every per-refresh `eth_call` (native ETH balance,
/// ERC-20 `balanceOf`s, Uniswap V3 `slot0()` reads) into one round trip
/// per batch.
const MULTICALL3: Address = address!("0xcA11bde05977b3631167028862bE2a173976CA11");

sol! {
    struct Call3 {
        address target;
        bool allowFailure;
        bytes callData;
    }

    /// Renamed from the canonical `Result` to dodge the clash with
    /// `std::result::Result` in generated code paths.
    struct MultiResult {
        bool success;
        bytes returnData;
    }

    function aggregate3(Call3[] calls) external returns (MultiResult[] memory results);
    function getEthBalance(address addr) external view returns (uint256 balance);
}

// ── Uniswap V3 constants ────────────────────────────────────────────────────

/// Fee tier of the USDC/WETH pool used to derive ETH/USD on every chain.
/// 0.05% is the highest-liquidity tier on Mainnet, Base, and Optimism.
const ETH_PRICE_FEE: u32 = 500; // 0.05 %

/// Pool init-code hash — same byte-for-byte across every Uniswap V3
/// deployment (Mainnet, Base, Optimism), so we don't key it by chain.
#[rustfmt::skip]
const POOL_INIT_CODE_HASH: [u8; 32] = [
    0xe3, 0x4f, 0x19, 0x9b, 0x19, 0xb2, 0xb4, 0xf4,
    0x7f, 0x68, 0x44, 0x26, 0x19, 0xd5, 0x55, 0x52,
    0x7d, 0x24, 0x4f, 0x78, 0xa3, 0x29, 0x7e, 0xa8,
    0x93, 0x25, 0xf8, 0x43, 0xf8, 0x7b, 0x8b, 0x54,
];

/// Uniswap V3 factory address. Mainnet and Optimism share the same
/// canonical address; Base has its own deployment.
fn factory_for(chain: Chain) -> Address {
    match chain {
        Chain::Mainnet | Chain::Optimism => {
            address!("0x1f98431c8ad98523631ae4a59f267346ea31f984")
        }
        Chain::Base => address!("0x33128a8fC17869897dcE68Ed026d694621f6FDfD"),
    }
}

/// Canonical WETH (or wrapped-native) address for the chain. Both L2s use
/// the OP-Stack predeploy at 0x4200…0006.
fn weth_for(chain: Chain) -> Address {
    match chain {
        Chain::Mainnet => address!("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
        Chain::Base | Chain::Optimism => {
            address!("0x4200000000000000000000000000000000000006")
        }
    }
}

/// Canonical (native) USDC address for the chain. Used as the
/// quote-currency leg of the ETH/USD pool.
fn usdc_for(chain: Chain) -> Address {
    match chain {
        Chain::Mainnet => address!("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
        Chain::Base => address!("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
        Chain::Optimism => address!("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"),
    }
}

// ── Curated token list ───────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum PriceSource {
    /// Price derived from a Uniswap V3 pool paired with WETH at a known
    /// fee tier. Used for staples whose deepest pool is well-known
    /// (USDC/USDT/DAI on 0.05 %, WBTC/LINK/UNI on 0.3 %, etc.).
    UniswapWethPool { fee: u32 },
    /// Try Uniswap V3 WETH pools at 0.05 % → 0.3 % → 1 % until one of
    /// them returns a non-zero `slot0`. Used for tokens sourced from the
    /// bundled Superchain Token List, which doesn't carry fee-tier info.
    UniswapWethPoolProbe,
    /// 1:1 peg with ETH (for WETH itself).
    EthPeg,
}

struct TokenMeta {
    symbol: Cow<'static, str>,
    name: Cow<'static, str>,
    address: Address,
    decimals: u8,
    price_source: PriceSource,
}

/// Compile-time-borrowed shape used by the static `MAINNET_OVERLAY` /
/// `BASE_OVERLAY` / `OPTIMISM_OVERLAY` arrays. Materialized into
/// `TokenMeta` (with `Cow::Borrowed`) at `LazyLock` init time.
struct OverlayEntry {
    symbol: &'static str,
    name: &'static str,
    address: Address,
    decimals: u8,
    price_source: PriceSource,
}

impl OverlayEntry {
    fn to_meta(&self) -> TokenMeta {
        TokenMeta {
            symbol: Cow::Borrowed(self.symbol),
            name: Cow::Borrowed(self.name),
            address: self.address,
            decimals: self.decimals,
            price_source: self.price_source,
        }
    }
}

/// Mainnet curated overlay. Today this is the *entire* Mainnet list —
/// the bundled Superchain tokenlist.json doesn't include the staples
/// (no USDC/USDT/WETH/UNI/LINK on chainId 1), so swapping Mainnet over
/// to it would regress coverage. Will be replaced by a richer Mainnet
/// tokenlist later.
const MAINNET_OVERLAY: &[OverlayEntry] = &[
    OverlayEntry {
        symbol: "USDC",
        name: "USD Coin",
        address: address!("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
        decimals: 6,
        price_source: PriceSource::UniswapWethPool { fee: 500 },
    },
    OverlayEntry {
        symbol: "USDT",
        name: "Tether",
        address: address!("0xdac17f958d2ee523a2206206994597c13d831ec7"),
        decimals: 6,
        price_source: PriceSource::UniswapWethPool { fee: 500 },
    },
    OverlayEntry {
        symbol: "WBTC",
        name: "Wrapped BTC",
        address: address!("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"),
        decimals: 8,
        price_source: PriceSource::UniswapWethPool { fee: 3000 },
    },
    OverlayEntry {
        symbol: "WETH",
        name: "Wrapped Ether",
        address: address!("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
        decimals: 18,
        price_source: PriceSource::EthPeg,
    },
    OverlayEntry {
        symbol: "LINK",
        name: "Chainlink",
        address: address!("0x514910771af9ca656af840dff83e8264ecf986ca"),
        decimals: 18,
        price_source: PriceSource::UniswapWethPool { fee: 3000 },
    },
    OverlayEntry {
        symbol: "UNI",
        name: "Uniswap",
        address: address!("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"),
        decimals: 18,
        price_source: PriceSource::UniswapWethPool { fee: 3000 },
    },
    OverlayEntry {
        symbol: "DAI",
        name: "Dai",
        address: address!("0x6b175474e89094c44da98b954eedeac495271d0f"),
        decimals: 18,
        price_source: PriceSource::UniswapWethPool { fee: 3000 },
    },
];

/// Base core overlay. Two jobs: (1) staples the Superchain Token List omits
/// (native USDC + canonical WETH + Coinbase BTC), and (2) preferred tokens the
/// list *does* carry but which would otherwise be buried — the overlay always
/// sorts to the front of `curated_tokens`, so listing the major stablecoins
/// here promotes them into the swap picker's popular set instead of letting
/// the alphabetically-first long-tail (0xBTC, ABT, ADS, ADX, AIKEK, …) take
/// those slots. Overlay entries win on address collision (see `merge_overlay`),
/// so the dedup against the bundled list is harmless.
const BASE_OVERLAY: &[OverlayEntry] = &[
    OverlayEntry {
        symbol: "USDC",
        name: "USD Coin",
        address: address!("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
        decimals: 6,
        price_source: PriceSource::UniswapWethPool { fee: 500 },
    },
    OverlayEntry {
        symbol: "WETH",
        name: "Wrapped Ether",
        address: address!("0x4200000000000000000000000000000000000006"),
        decimals: 18,
        price_source: PriceSource::EthPeg,
    },
    OverlayEntry {
        symbol: "cbBTC",
        name: "Coinbase Wrapped BTC",
        address: address!("0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf"),
        decimals: 8,
        price_source: PriceSource::UniswapWethPool { fee: 500 },
    },
    // Major stablecoins — already in the bundled list, promoted here so the
    // swap picker shows them up top rather than long-tail junk. Thin/varied
    // Base liquidity, so each probes fee tiers rather than pinning one.
    OverlayEntry {
        symbol: "DAI",
        name: "Dai Stablecoin",
        address: address!("0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb"),
        decimals: 18,
        price_source: PriceSource::UniswapWethPoolProbe,
    },
    OverlayEntry {
        symbol: "crvUSD",
        name: "Curve.Fi USD Stablecoin",
        address: address!("0x417Ac0e078398C154EdFadD9Ef675d30Be60Af93"),
        decimals: 18,
        price_source: PriceSource::UniswapWethPoolProbe,
    },
    OverlayEntry {
        symbol: "fxUSD",
        name: "f(x) USD",
        address: address!("0x63525b8f9a78251611ada0a05724eeef48100fbd"),
        decimals: 18,
        price_source: PriceSource::UniswapWethPoolProbe,
    },
    OverlayEntry {
        symbol: "eUSD",
        name: "Electronic Dollar",
        address: address!("0xCfA3Ef56d303AE4fAabA0592388F19d7C3399FB4"),
        decimals: 18,
        price_source: PriceSource::UniswapWethPoolProbe,
    },
    OverlayEntry {
        symbol: "USDT",
        name: "Tether USD",
        address: address!("0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2"),
        decimals: 6,
        price_source: PriceSource::UniswapWethPoolProbe,
    },
];

/// Optimism core overlay. Like Base, but carries the bridged USDT/WBTC/LINK
/// the Superchain list also drops, plus the OP token itself.
const OPTIMISM_OVERLAY: &[OverlayEntry] = &[
    OverlayEntry {
        symbol: "USDC",
        name: "USD Coin",
        address: address!("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"),
        decimals: 6,
        price_source: PriceSource::UniswapWethPool { fee: 500 },
    },
    OverlayEntry {
        symbol: "USDT",
        name: "Tether",
        address: address!("0x94b008aA00579c1307B0EF2c499aD98a8ce58e58"),
        decimals: 6,
        price_source: PriceSource::UniswapWethPool { fee: 500 },
    },
    OverlayEntry {
        symbol: "WETH",
        name: "Wrapped Ether",
        address: address!("0x4200000000000000000000000000000000000006"),
        decimals: 18,
        price_source: PriceSource::EthPeg,
    },
    OverlayEntry {
        symbol: "WBTC",
        name: "Wrapped BTC",
        address: address!("0x68f180fcCe6836688e9084f035309E29Bf0A2095"),
        decimals: 8,
        price_source: PriceSource::UniswapWethPool { fee: 3000 },
    },
    OverlayEntry {
        symbol: "LINK",
        name: "Chainlink",
        address: address!("0x350a791Bfc2C21F9Ed5d10980Dad2e2638ffa7f6"),
        decimals: 18,
        price_source: PriceSource::UniswapWethPool { fee: 3000 },
    },
    OverlayEntry {
        symbol: "OP",
        name: "Optimism",
        address: address!("0x4200000000000000000000000000000000000042"),
        decimals: 18,
        price_source: PriceSource::UniswapWethPool { fee: 3000 },
    },
];

// ── Bundled Superchain Token List ───────────────────────────────────────────

/// Bundled-tokenlist entries to drop entirely — dead or junk tokens that only
/// surface because they sort first alphabetically and would otherwise crowd the
/// swap picker's popular set. Matched by address at parse time.
const TOKENLIST_BLOCKLIST: &[Address] = &[
    // 0xBitcoin (Base) — a long-abandoned mineable ERC-20; replaced in the
    // popular set by USDT.
    address!("0xc4D4FD4F4459730d176844c170F2bB323c87Eb3B"),
];

/// The Superchain Token List, embedded at compile time. Already shipped
/// with the binary for SVG-logo lookup; reused here for L2 ERC-20
/// metadata. Mainnet entries (chainId 1) are dropped at parse time —
/// the list lacks the L1 staples we care about, so Mainnet relies on
/// `MAINNET_OVERLAY` exclusively for now.
const TOKENLIST_JSON: &str = include_str!("../assets/tokenlist.json");

#[derive(serde::Deserialize)]
struct TokenListFile {
    #[serde(default)]
    tokens: Vec<TokenListEntry>,
}

#[derive(serde::Deserialize)]
struct TokenListEntry {
    #[serde(rename = "chainId")]
    chain_id: u64,
    address: String,
    #[serde(default)]
    symbol: String,
    #[serde(default)]
    name: String,
    decimals: u8,
}

/// Parse the embedded tokenlist into `(Optimism_entries, Base_entries)`.
/// Returns owned `TokenMeta` rows (Cow::Owned strings). Each entry's
/// price source is `UniswapWethPoolProbe` — the bundled list doesn't
/// carry fee tiers, so we pick one at price-time.
fn parse_tokenlist() -> (Vec<TokenMeta>, Vec<TokenMeta>) {
    let parsed: TokenListFile =
        serde_json::from_str(TOKENLIST_JSON).expect("bundled tokenlist.json must parse");
    let mut optimism = Vec::new();
    let mut base = Vec::new();
    for entry in parsed.tokens {
        // Only chainIds we actually wire into the wallet today.
        let bucket = match entry.chain_id {
            10 => &mut optimism,
            8453 => &mut base,
            _ => continue,
        };
        let Ok(addr) = Address::from_str(&entry.address) else {
            debug!(address = %entry.address, "skipping tokenlist entry with unparseable address");
            continue;
        };
        if TOKENLIST_BLOCKLIST.contains(&addr) {
            continue;
        }
        bucket.push(TokenMeta {
            symbol: Cow::Owned(entry.symbol),
            name: Cow::Owned(entry.name),
            address: addr,
            decimals: entry.decimals,
            price_source: PriceSource::UniswapWethPoolProbe,
        });
    }
    (optimism, base)
}

/// Build a per-chain `Vec<TokenMeta>` by union-merging an overlay (small,
/// hand-curated, with explicit fee tiers) onto the bundled tokenlist.
/// Dedup by lowercase address; the overlay wins on collision so its
/// known fee tier sticks instead of falling back to a pool-probe.
fn merge_overlay(overlay: &[OverlayEntry], tokenlist: Vec<TokenMeta>) -> Vec<TokenMeta> {
    let mut seen: std::collections::HashSet<Address> = overlay.iter().map(|e| e.address).collect();
    let mut out: Vec<TokenMeta> = overlay.iter().map(OverlayEntry::to_meta).collect();
    for tk in tokenlist {
        if seen.insert(tk.address) {
            out.push(tk);
        }
    }
    out
}

/// Token a caller has discovered out-of-band (e.g. an indexer's
/// `balances` enumeration) and wants the on-chain walk to price + size
/// alongside the chain's curated overlay. The indexer's own
/// balance/price fields are dropped — those round-trip through
/// Multicall3 here, since the indexer's snapshot isn't light-client
/// verified.
#[derive(Debug, Clone)]
pub struct DiscoveredToken {
    pub symbol: String,
    pub name: String,
    pub address: Address,
    pub decimals: u8,
}

/// Union the chain's curated token list with caller-supplied discovered
/// rows. The curated overlay wins on address collision so its known
/// Uniswap fee tier sticks; otherwise we'd downgrade a staple to a
/// pool-probe and burn an extra Multicall3 subcall per refresh.
/// Discovered tokens default to `UniswapWethPoolProbe` because the
/// indexer doesn't carry fee-tier info.
fn merge_discovered(base: &[TokenMeta], discovered: &[DiscoveredToken]) -> Vec<TokenMeta> {
    let mut seen: std::collections::HashSet<Address> = base.iter().map(|t| t.address).collect();
    let mut out: Vec<TokenMeta> = base
        .iter()
        .map(|t| TokenMeta {
            symbol: t.symbol.clone(),
            name: t.name.clone(),
            address: t.address,
            decimals: t.decimals,
            price_source: t.price_source,
        })
        .collect();
    for d in discovered {
        if seen.insert(d.address) {
            out.push(TokenMeta {
                symbol: Cow::Owned(d.symbol.clone()),
                name: Cow::Owned(d.name.clone()),
                address: d.address,
                decimals: d.decimals,
                price_source: PriceSource::UniswapWethPoolProbe,
            });
        }
    }
    out
}

static MAINNET_TOKENS: LazyLock<Vec<TokenMeta>> = LazyLock::new(|| {
    // Mainnet stays on the curated overlay alone — see `MAINNET_OVERLAY`.
    MAINNET_OVERLAY.iter().map(OverlayEntry::to_meta).collect()
});

static OPTIMISM_TOKENS: LazyLock<Vec<TokenMeta>> = LazyLock::new(|| {
    let (optimism, _) = parse_tokenlist();
    merge_overlay(OPTIMISM_OVERLAY, optimism)
});

static BASE_TOKENS: LazyLock<Vec<TokenMeta>> = LazyLock::new(|| {
    let (_, base) = parse_tokenlist();
    merge_overlay(BASE_OVERLAY, base)
});

/// Per-chain token metadata used by the on-chain portfolio walk. L2 lists
/// are union of the chain's core overlay (USDC, USDT, WETH, …) and the
/// bundled Superchain tokenlist — so a user with no indexer configured
/// still sees their L2 ERC-20s, not just native ETH.
fn tokens_for(chain: Chain) -> &'static [TokenMeta] {
    match chain {
        Chain::Mainnet => MAINNET_TOKENS.as_slice(),
        Chain::Base => BASE_TOKENS.as_slice(),
        Chain::Optimism => OPTIMISM_TOKENS.as_slice(),
    }
}

/// Curated token metadata for `chain` as `(symbol, address, decimals)` triples.
/// Used by the swap composer's buy-token picker so it shares the wallet's vetted
/// list (and bundled logos) rather than a separate hand-maintained address set:
/// Mainnet is the curated overlay; L2s add the bundled Superchain tokenlist.
pub fn curated_tokens(chain: Chain) -> Vec<(String, Address, u8)> {
    tokens_for(chain)
        .iter()
        .map(|m| (m.symbol.to_string(), m.address, m.decimals))
        .collect()
}

// ── LiveToken ────────────────────────────────────────────────────────────────

/// A single portfolio entry with live data.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct LiveToken {
    pub symbol: String,
    pub name: String,
    pub balance: String,
    pub balance_f64: f64,
    /// Raw on-chain balance in the token's smallest units.
    /// Carried alongside `balance_f64` so the Send flow can compare an entered
    /// amount to the held balance without re-parsing the formatted string.
    pub balance_raw: U256,
    pub decimals: u8,
    /// `None` for native ETH; `Some(addr)` for ERC-20s. The Send flow reads
    /// this to choose between an ETH-value transfer and a `transfer(...)`
    /// calldata to the contract.
    pub contract: Option<Address>,
    pub usd_price: f64,
    pub usd_value: f64,
    /// Which network this entry was fetched from. The asset-row UI reads
    /// this to suffix L2 / custom entries with their network (e.g.
    /// "USDC (Base)", "ETH (Sepolia)") while leaving Mainnet entries bare.
    /// Custom networks carry `NetworkId::Custom(chain_id)`.
    pub chain: NetworkId,
}

// ── Cache ────────────────────────────────────────────────────────────────────

/// In-memory portfolio cache keyed by `(owner, network)`. Shared across
/// the `App` and each `WalletScreen` rebuild so account switches can
/// render the previously-fetched token list immediately while a fresh
/// fetch refreshes it in the background. Each network has its own slot so
/// a Base portfolio refresh doesn't clobber the cached Mainnet rows, and a
/// custom network gets its own slot keyed by `NetworkId::Custom(chain_id)`.
/// Process-lifetime only — cleared on app restart.
pub type PortfolioCache = Arc<Mutex<HashMap<(Address, NetworkId), Vec<LiveToken>>>>;

pub fn new_cache() -> PortfolioCache {
    Arc::new(Mutex::new(HashMap::new()))
}

// ── ERC-20 balance helpers ───────────────────────────────────────────────────

/// `balanceOf(address)` — first 4 bytes of keccak256("balanceOf(address)")
const BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];

fn balance_of_calldata(owner: Address) -> Bytes {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&BALANCE_OF_SELECTOR);
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(owner.as_slice());
    Bytes::from(data)
}

/// Hard cap on the `decimals` we'll honour when scaling a balance for
/// display. Real ERC-20 tokens top out at 18; anything beyond this is
/// garbled or hostile metadata. The cap also keeps the divisor finite:
/// `10u64.pow(20)` already overflows u64 (panics in debug builds, silently
/// wraps in release, where `overflow-checks` are off) — see
/// [`decimals_or_default`](crate::indexer::decimals_or_default), which feeds
/// this from untrusted indexer/contract metadata with no upper bound.
const MAX_DISPLAY_DECIMALS: u8 = 36;

pub(crate) fn format_token_balance(raw: U256, decimals: u8) -> (String, f64) {
    if raw.is_zero() {
        return ("0".into(), 0.0);
    }
    let decimals = if decimals > MAX_DISPLAY_DECIMALS {
        warn!(
            decimals,
            max = MAX_DISPLAY_DECIMALS,
            "token decimals exceed sane maximum; clamping for display"
        );
        MAX_DISPLAY_DECIMALS
    } else {
        decimals
    };
    // f64 exponentiation saturates to a finite value instead of wrapping the
    // way integer `pow` would; combined with the clamp above the divisor is
    // always a sane, non-zero scale factor.
    let divisor = 10f64.powi(decimals as i32);
    let raw_f64 = raw.to_string().parse::<f64>().unwrap_or(0.0);
    let value = raw_f64 / divisor;
    let formatted = if value >= 1000.0 {
        format!("{:.2}", value)
    } else if value >= 1.0 {
        format!("{:.4}", value)
    } else {
        format!("{:.6}", value)
    };
    (formatted, value)
}

pub(crate) fn format_eth_balance(raw: U256) -> (String, f64) {
    let formatted = alloy::primitives::utils::format_ether(raw);
    let f = formatted.parse::<f64>().unwrap_or(0.0);
    let display = if f >= 1000.0 {
        format!("{:.2}", f)
    } else {
        format!("{:.4}", f)
    };
    (display, f)
}

// ── Uniswap V3 price helpers ────────────────────────────────────────────────

/// Compute the CREATE2 address of a Uniswap V3 pool. `factory` is the
/// chain-specific Uniswap V3 factory deployment.
fn pool_address(factory: Address, token_a: Address, token_b: Address, fee: u32) -> Address {
    let (token0, token1) = if token_a < token_b {
        (token_a, token_b)
    } else {
        (token_b, token_a)
    };

    // salt = keccak256(abi.encode(token0, token1, fee))
    let mut encoded = [0u8; 96];
    encoded[12..32].copy_from_slice(token0.as_slice());
    encoded[44..64].copy_from_slice(token1.as_slice());
    // fee (uint24) right-aligned in the last 32-byte word
    encoded[93] = ((fee >> 16) & 0xFF) as u8;
    encoded[94] = ((fee >> 8) & 0xFF) as u8;
    encoded[95] = (fee & 0xFF) as u8;
    let salt = keccak256(encoded);

    // CREATE2: keccak256(0xff ++ factory ++ salt ++ init_code_hash)[12..]
    let mut buf = Vec::with_capacity(85);
    buf.push(0xff);
    buf.extend_from_slice(factory.as_slice());
    buf.extend_from_slice(salt.as_slice());
    buf.extend_from_slice(&POOL_INIT_CODE_HASH);
    let hash = keccak256(&buf);
    Address::from_slice(&hash[12..])
}

/// `slot0()` selector — first 4 bytes of keccak256("slot0()")
const SLOT0_SELECTOR: [u8; 4] = [0x38, 0x50, 0xc7, 0xbd];

/// Convert `sqrtPriceX96` to a float ratio (token1 / token0 in smallest units).
fn sqrt_price_to_raw(sqrt_price_x96: U256) -> f64 {
    let s: f64 = sqrt_price_x96.to_string().parse().unwrap_or(0.0);
    let q96: f64 = (1u128 << 96) as f64;
    (s / q96).powi(2)
}

/// Derive ETH/USD from the chain's USDC/WETH pool by inverting the USDC
/// price quoted in ETH. The token0/token1 ordering depends on the
/// chain — Base has `USDC > WETH` so the USDC leg is token1, while
/// Mainnet and Optimism have `USDC < WETH` (USDC is token0). Routing
/// through `token_price_in_eth` handles both cases without us
/// hand-tracking the inversion per chain.
fn eth_usd_from_sqrt_price(sqrt_price_x96: U256, usdc_addr: Address, weth_addr: Address) -> f64 {
    let usdc_in_eth = token_price_in_eth(sqrt_price_x96, usdc_addr, 6, weth_addr);
    if usdc_in_eth == 0.0 {
        return 0.0;
    }
    1.0 / usdc_in_eth
}

/// Given a WETH-paired pool's `sqrtPriceX96`, compute the token's ETH price.
///
/// If the token address < WETH it is token0 (WETH is token1):
///   `token_in_eth = raw_price × 10^(token_dec − 18)`
///
/// Otherwise WETH is token0 (token is token1):
///   `token_in_eth = 10^(token_dec − 18) / raw_price`
fn token_price_in_eth(
    sqrt_price_x96: U256,
    token_addr: Address,
    token_decimals: u8,
    weth_addr: Address,
) -> f64 {
    let raw = sqrt_price_to_raw(sqrt_price_x96);
    if raw == 0.0 {
        return 0.0;
    }
    let dec_diff = token_decimals as i32 - 18;
    if token_addr < weth_addr {
        // token is token0, WETH is token1
        raw * 10f64.powi(dec_diff)
    } else {
        // WETH is token0, token is token1
        10f64.powi(dec_diff) / raw
    }
}

// ── Fetch portfolio ─────────────────────────────────────────────────────────

/// Fee tiers tried in order when a token's `PriceSource` is `Probe`.
/// Order matches Uniswap's TVL distribution: stables sit on 0.05 %,
/// blue-chip ERC-20s on 0.3 %, exotics on 1 %. We stop at the first
/// fee tier whose `slot0` returns a non-zero `sqrtPriceX96` AND whose
/// pool holds at least `MIN_POOL_WETH_WEI` of WETH — anything else means
/// the pool isn't deployed, has no liquidity, or has been abandoned with
/// an out-of-band spot price.
const PROBE_FEES: [u32; 3] = [500, 3000, 10000];

/// Minimum WETH balance a Uniswap V3 pool must hold for us to trust its
/// `slot0` quote. Pools below this floor are abandoned single-sided
/// positions whose spot can be off by 10+ orders of magnitude (see e.g.
/// the Base WALLET/WETH 1 % pool, which sat at ~$64 of TVL and quoted
/// WALLET at ~10^19 USD/token). 0.1 WETH is roughly $200–$400 across the
/// chains we support — high enough to filter dead pools, low enough that
/// legitimately thin long-tail pools still price.
const MIN_POOL_WETH_WEI: U256 = U256::from_limbs([100_000_000_000_000_000u64, 0, 0, 0]); // 1e17 = 0.1 WETH

/// Starting subcall count per `aggregate3` round trip. dRPC's free tier
/// kills any request running longer than 2 s, and a single eth_call
/// executing ~330 `balanceOf`s against Base state exceeds that on its
/// public upstreams (HTTP 408, code 30). How many subcalls fit under
/// the budget varies with upstream load, so this is only the optimistic
/// opening bid — `multicall3` halves it on timeout.
const MULTICALL_CHUNK: usize = 100;

/// Floor for the timeout-driven halving. Below this the per-request
/// overhead dominates and shrinking further can't help; keep retrying
/// at this size until the budget runs out instead.
const MULTICALL_CHUNK_MIN: usize = 10;

/// Provider-timeout retries one `multicall3` call may burn before
/// giving up. Paired with the backoff below, the budget spans ~30 s —
/// free-tier 408s come in congestion windows (observed: every request
/// on a chain failing for several seconds straight), so retries that
/// all land inside the same window are wasted.
const MULTICALL_TIMEOUT_RETRIES: u32 = 6;

/// Process-wide chunk-size ratchet, shared across refreshes. Upstream
/// speed is a property of the provider, not of one portfolio walk —
/// once a size times out, later walks start from the size that worked
/// instead of rediscovering it 2 s at a time. Only ever shrinks;
/// restart the app to reset after switching providers.
static MULTICALL_CHUNK_RATCHET: AtomicUsize = AtomicUsize::new(MULTICALL_CHUNK);

/// Match a provider-side per-request timeout (dRPC free tier: HTTP 408
/// with `{"message":"Request timeout on the free tier…","code":30}`) or
/// a client-side socket timeout. Distinct from `is_rate_limited` — the
/// fix is a smaller request, not a longer backoff.
fn is_provider_timeout(msg: &str) -> bool {
    msg.contains("HTTP error 408") || msg.contains("Request timeout") || msg.contains("timed out")
}

/// Issue one logical Multicall3 `aggregate3` read, split into chunked
/// round trips so no single eth_call outlives a free-tier provider's
/// per-request timeout. Chunks start at the ratcheted size and halve on
/// every timeout (down to `MULTICALL_CHUNK_MIN`). All chunks are pinned
/// to the same `block`, so the caller still observes one consistent
/// state snapshot. Each chunk is wrapped in `with_rate_limit_retry` so
/// 429s back off instead of zeroing the portfolio. Returns the
/// per-subcall (success, returnData) rows in the same order the caller
/// queued them.
pub(crate) async fn multicall3(
    provider: &RootProvider<Ethereum>,
    block: BlockId,
    label: &str,
    calls: Vec<Call3>,
) -> Result<Vec<MultiResult>, String> {
    let mut chunk_size = MULTICALL_CHUNK_RATCHET.load(Ordering::Relaxed);
    let mut timeout_budget = MULTICALL_TIMEOUT_RETRIES;
    let mut timeout_delay = RETRY_INITIAL_DELAY;
    let mut out: Vec<MultiResult> = Vec::with_capacity(calls.len());
    let mut idx = 0;
    while idx < calls.len() {
        let end = (idx + chunk_size).min(calls.len());
        let chunk = &calls[idx..end];
        let calldata = Bytes::from(
            aggregate3Call {
                calls: chunk.to_vec(),
            }
            .abi_encode(),
        );
        let raw = with_rate_limit_retry(label, || async {
            let tx = alloy::rpc::types::TransactionRequest::default()
                .to(MULTICALL3)
                .input(alloy::rpc::types::TransactionInput::new(calldata.clone()));
            provider.call(tx).block(block).await
        })
        .await;
        let raw = match raw {
            Ok(raw) => raw,
            Err(e) => {
                let msg = e.to_string();
                if timeout_budget == 0 || !is_provider_timeout(&msg) {
                    return Err(format!("{label}: {msg}"));
                }
                timeout_budget -= 1;
                if chunk_size > MULTICALL_CHUNK_MIN {
                    chunk_size = (chunk_size / 2).max(MULTICALL_CHUNK_MIN);
                    MULTICALL_CHUNK_RATCHET.fetch_min(chunk_size, Ordering::Relaxed);
                }
                warn!(
                    label,
                    chunk_size,
                    retries_left = timeout_budget,
                    delay_ms = timeout_delay.as_millis() as u64,
                    error = %msg,
                    "provider timeout; backing off, then retrying with smaller multicall chunk",
                );
                tokio::time::sleep(timeout_delay).await;
                timeout_delay = (timeout_delay * 2).min(RETRY_MAX_DELAY);
                continue;
            }
        };
        let decoded =
            aggregate3Call::abi_decode_returns(&raw).map_err(|e| format!("{label} decode: {e}"))?;
        // Callers index results positionally; a short chunk would shift
        // every later row onto the wrong token.
        if decoded.len() != chunk.len() {
            return Err(format!(
                "{label}: chunk returned {} results for {} calls",
                decoded.len(),
                chunk.len(),
            ));
        }
        out.extend(decoded);
        idx = end;
    }
    Ok(out)
}

/// Crate-internal façade over `multicall3` that hides the sol-generated
/// `Call3`/`MultiResult` types so callers in other modules don't need to
/// import them. Each input is `(target, calldata)`; each output is
/// `(success, returnData)` in the same order. All subcalls are issued
/// with `allowFailure = true` so a single reverting token doesn't blank
/// the whole batch.
pub(crate) async fn multicall_pairs(
    provider: &RootProvider<Ethereum>,
    block: BlockId,
    label: &str,
    calls: Vec<(Address, Bytes)>,
) -> Result<Vec<(bool, Bytes)>, String> {
    let calls3: Vec<Call3> = calls
        .into_iter()
        .map(|(target, data)| Call3 {
            target,
            allowFailure: true,
            callData: data,
        })
        .collect();
    let raw = multicall3(provider, block, label, calls3).await?;
    Ok(raw.into_iter().map(|r| (r.success, r.returnData)).collect())
}

/// Decode a raw `MultiResult.returnData` as a 32-byte uint. Returns
/// `U256::ZERO` for `success=false`, short returns, or empty data —
/// every site that reads a `balanceOf` or `slot0` result wants exactly
/// this fallback.
fn decode_u256(r: &MultiResult) -> U256 {
    if !r.success || r.returnData.len() < 32 {
        return U256::ZERO;
    }
    U256::from_be_slice(&r.returnData[..32])
}

/// Walk `(slot0, weth_balance)` pairs in fee-tier order and return the
/// first `sqrtPriceX96` whose pool holds at least `MIN_POOL_WETH_WEI`.
/// Backs `PriceSource::UniswapWethPoolProbe`: 0.05 % is checked first,
/// then 0.3 %, then 1 %. Returns `U256::ZERO` when no candidate pool is
/// both deployed and liquid enough to trust.
fn first_liquid_sqrt(results: &[MultiResult]) -> U256 {
    for pair in results.chunks_exact(2) {
        let sqrt = decode_u256(&pair[0]);
        let weth_bal = decode_u256(&pair[1]);
        if !sqrt.is_zero() && weth_bal >= MIN_POOL_WETH_WEI {
            return sqrt;
        }
    }
    U256::ZERO
}

/// Plan describing how to interpret a slice of batch-2 results for one
/// held token: either no subcall (peg), one subcall (known fee), or
/// three subcalls (probe 0.05/0.3/1 %).
enum PricePlan {
    EthPeg,
    Single { result_idx: usize },
    Probe { start_idx: usize },
}

/// Fetch the full portfolio for `owner` on `chain`: native ETH plus
/// every ERC-20 in `tokens_for(chain)` the address holds, with prices
/// quoted on-chain from the chain's Uniswap V3 deployment. No external
/// APIs, no API keys.
///
/// Implementation: two `Multicall3.aggregate3` round trips per refresh.
/// Batch 1 issues the native-ETH read, the ETH/USD `slot0` read, and
/// every token's `balanceOf` in one shot. Batch 2 issues `slot0` for
/// each held token's WETH pool (fixed fee tier when known, or the
/// 0.05 %/0.3 %/1 % probe when sourced from the bundled tokenlist).
/// Result: 2 RPC round trips regardless of token-list size, vs. 1+N+M
/// in the previous sequential design.
///
/// `provider` is supplied by the caller (typically the per-chain
/// `NetworkClient` fallback) so account switches reuse one HTTP
/// transport instead of building a fresh TLS pool every dashboard
/// rebuild. The caller is responsible for handing in a provider that
/// actually points at `chain`'s execution RPC.
pub async fn fetch_portfolio(
    owner: Address,
    chain: Chain,
    provider: &RootProvider<Ethereum>,
) -> Result<Vec<LiveToken>, String> {
    fetch_portfolio_for_tokens(owner, chain, provider, tokens_for(chain)).await
}

/// Same as `fetch_portfolio`, but also includes caller-supplied
/// discovered tokens (e.g. ERC-20s an indexer's `balances` call
/// enumerated for this address). The chain's curated overlay still wins
/// on address collision so known Uniswap fee tiers are preserved.
///
/// The indexer's reported balances and prices are intentionally
/// discarded — discovery is *only* used to learn which token contracts
/// to interrogate. All balances and prices then flow through Multicall3
/// against the chain RPC, so the user never sees an indexer-claimed
/// balance the on-chain state doesn't back.
pub async fn fetch_portfolio_with_discovery(
    owner: Address,
    chain: Chain,
    provider: &RootProvider<Ethereum>,
    discovered: &[DiscoveredToken],
) -> Result<Vec<LiveToken>, String> {
    let merged = merge_discovered(tokens_for(chain), discovered);
    fetch_portfolio_for_tokens(owner, chain, provider, &merged).await
}

/// Refetch balances + prices for a *specific* set of token contracts on
/// `chain` (plus native ETH, which the walk always reads). Used by the
/// post-swap targeted refresh: refetching just the two assets an order
/// touched is far cheaper than the full multi-chain portfolio walk, while
/// still going through Multicall3 against the chain RPC so the user never
/// sees an unverified balance.
///
/// Each requested token's metadata is taken from the chain's curated list
/// when present (so a known Uniswap fee tier sticks); otherwise it falls
/// back to the caller-supplied `DiscoveredToken` fields with the same
/// 0.05 %/0.3 %/1 % pool-probe used for indexer-discovered tokens. Returns
/// only non-zero rows, exactly like the full walk.
pub async fn fetch_token_balances(
    owner: Address,
    chain: Chain,
    provider: &RootProvider<Ethereum>,
    tokens: &[DiscoveredToken],
) -> Result<Vec<LiveToken>, String> {
    let curated = tokens_for(chain);
    let mut list: Vec<TokenMeta> = Vec::with_capacity(tokens.len());
    let mut seen: std::collections::HashSet<Address> = std::collections::HashSet::new();
    for d in tokens {
        if !seen.insert(d.address) {
            continue;
        }
        match curated.iter().find(|m| m.address == d.address) {
            Some(meta) => list.push(TokenMeta {
                symbol: meta.symbol.clone(),
                name: meta.name.clone(),
                address: meta.address,
                decimals: meta.decimals,
                price_source: meta.price_source,
            }),
            None => list.push(TokenMeta {
                symbol: Cow::Owned(d.symbol.clone()),
                name: Cow::Owned(d.name.clone()),
                address: d.address,
                decimals: d.decimals,
                price_source: PriceSource::UniswapWethPoolProbe,
            }),
        }
    }
    fetch_portfolio_for_tokens(owner, chain, provider, &list).await
}

/// Native-coin balance for a user-defined custom network.
///
/// Custom networks are unverified and carry only their native coin — there is
/// no curated token list, Uniswap pool, or indexer for an arbitrary chain — so
/// this issues a single `eth_getBalance` (latest block) against the user's RPC
/// and returns one `LiveToken`. The row is kept even at a zero balance so the
/// network stays visible in the portfolio (the user opted into seeing it).
///
/// No USD price: there's no trustworthy on-chain oracle for an arbitrary coin,
/// so `usd_price` / `usd_value` are 0 and the asset row renders a dash. The
/// network name and symbol are sanitized at this ingestion point — they're
/// user-typed and flow straight into the Send token row and dashboard list.
pub async fn fetch_native_balance(
    owner: Address,
    network: &crate::settings::CustomNetwork,
    provider: &RootProvider<Ethereum>,
) -> Result<Vec<LiveToken>, String> {
    let raw = provider
        .get_balance(owner)
        .await
        .map_err(|e| format!("eth_getBalance: {e}"))?;
    let (balance, balance_f64) = format_eth_balance(raw);
    let symbol = crate::sanitize::sanitize_display(
        network.currency_symbol.as_str(),
        crate::sanitize::MAX_TOKEN_SYMBOL_CHARS,
    )
    .into_owned();
    let name = crate::sanitize::sanitize_display(
        network.name.as_str(),
        crate::sanitize::MAX_TOKEN_NAME_CHARS,
    )
    .into_owned();
    Ok(vec![LiveToken {
        symbol,
        name,
        balance,
        balance_f64,
        balance_raw: raw,
        decimals: 18,
        contract: None,
        usd_price: 0.0,
        usd_value: 0.0,
        chain: NetworkId::Custom(network.chain_id),
    }])
}

async fn fetch_portfolio_for_tokens(
    owner: Address,
    chain: Chain,
    provider: &RootProvider<Ethereum>,
    token_list: &[TokenMeta],
) -> Result<Vec<LiveToken>, String> {
    // Pin every call in this batch to the finalized block. Public RPC fleets
    // load-balance across upstreams that drift a block or two apart at the
    // tip; a "latest" tag intermittently lands on a node that doesn't yet
    // have that header and returns -32014 / `header not found`. Finalized is
    // available on every upstream and gives a consistent state snapshot.
    let block = BlockId::finalized();

    let factory = factory_for(chain);
    let weth = weth_for(chain);
    let usdc = usdc_for(chain);
    let eth_price_pool = pool_address(factory, usdc, weth, ETH_PRICE_FEE);

    // ── Batch 1: native ETH balance + ETH/USD slot0 + every balanceOf ──
    //
    // Native ETH goes through Multicall3.getEthBalance so it shares the
    // same round trip; otherwise we'd need a separate eth_getBalance.
    let mut batch1: Vec<Call3> = Vec::with_capacity(token_list.len() + 2);
    batch1.push(Call3 {
        target: MULTICALL3,
        allowFailure: false,
        callData: Bytes::from(getEthBalanceCall { addr: owner }.abi_encode()),
    });
    batch1.push(Call3 {
        target: eth_price_pool,
        allowFailure: true,
        callData: Bytes::from(SLOT0_SELECTOR.to_vec()),
    });
    for token in token_list {
        batch1.push(Call3 {
            target: token.address,
            allowFailure: true,
            callData: balance_of_calldata(owner),
        });
    }

    let started = std::time::Instant::now();
    let batch1_results = multicall3(provider, block, "multicall3 balances", batch1).await?;
    debug!(
        chain = %chain.label(),
        elapsed = ?started.elapsed(),
        subcalls = batch1_results.len(),
        "multicall3 balances completed",
    );

    // batch1_results layout: [native_eth, eth_pool_slot0, token0, token1, …]
    let eth_balance_raw = decode_u256(&batch1_results[0]);
    let eth_usd = if let Some(pool_result) = batch1_results.get(1) {
        let sqrt = decode_u256(pool_result);
        if sqrt.is_zero() {
            warn!(chain = %chain.label(), "ETH/USD pool returned zero sqrtPriceX96");
            0.0
        } else {
            let price = eth_usd_from_sqrt_price(sqrt, usdc, weth);
            debug!(chain = %chain.label(), price = format!("${price:.2}"), "ETH/USD from Uniswap");
            price
        }
    } else {
        0.0
    };
    let token_balances: Vec<U256> = batch1_results.iter().skip(2).map(decode_u256).collect();

    // ── Batch 2: per-token slot0 + pool-WETH-balance reads ──────────────
    //
    // For every candidate Uniswap V3 pool we queue two subcalls back-to-back:
    // `slot0()` (the spot-price quote) and `WETH.balanceOf(pool)` (the
    // liquidity sanity check). The `MIN_POOL_WETH_WEI` floor on the latter
    // discards abandoned single-sided pools whose `slot0` is junk.
    let mut batch2: Vec<Call3> = Vec::new();
    let mut plans: Vec<(usize, PricePlan)> = Vec::new();

    let push_pool_pair = |batch: &mut Vec<Call3>, pool: Address| {
        batch.push(Call3 {
            target: pool,
            allowFailure: true,
            callData: Bytes::from(SLOT0_SELECTOR.to_vec()),
        });
        batch.push(Call3 {
            target: weth,
            allowFailure: true,
            callData: balance_of_calldata(pool),
        });
    };

    for (i, raw_balance) in token_balances.iter().enumerate() {
        if raw_balance.is_zero() {
            continue;
        }
        let token = &token_list[i];
        let plan = match token.price_source {
            PriceSource::EthPeg => PricePlan::EthPeg,
            PriceSource::UniswapWethPool { fee } => {
                let pool = pool_address(factory, token.address, weth, fee);
                let result_idx = batch2.len();
                push_pool_pair(&mut batch2, pool);
                PricePlan::Single { result_idx }
            }
            PriceSource::UniswapWethPoolProbe => {
                let start_idx = batch2.len();
                for fee in PROBE_FEES {
                    let pool = pool_address(factory, token.address, weth, fee);
                    push_pool_pair(&mut batch2, pool);
                }
                PricePlan::Probe { start_idx }
            }
        };
        plans.push((i, plan));
    }

    let batch2_results: Vec<MultiResult> = if batch2.is_empty() {
        Vec::new()
    } else {
        let started = std::time::Instant::now();
        let r = multicall3(provider, block, "multicall3 prices", batch2).await?;
        debug!(
            chain = %chain.label(),
            elapsed = ?started.elapsed(),
            subcalls = r.len(),
            "multicall3 prices completed",
        );
        r
    };

    // ── Build LiveToken vec ────────────────────────────────────────────
    let mut tokens: Vec<LiveToken> = Vec::with_capacity(plans.len() + 1);

    let has_eth = !eth_balance_raw.is_zero();
    if !has_eth {
        debug!(
            chain = %chain.label(),
            "dropping zero-balance native ETH",
        );
    }
    if has_eth {
        let (eth_bal_str, eth_bal_f64) = format_eth_balance(eth_balance_raw);
        tokens.push(LiveToken {
            symbol: chain.native_symbol().into(),
            name: chain.native_name().into(),
            balance: eth_bal_str,
            balance_f64: eth_bal_f64,
            balance_raw: eth_balance_raw,
            decimals: 18,
            contract: None,
            usd_price: eth_usd,
            usd_value: eth_bal_f64 * eth_usd,
            chain: chain.into(),
        });
    }

    for (token_idx, plan) in plans {
        let token = &token_list[token_idx];
        let raw_balance = token_balances[token_idx];
        let price = match plan {
            PricePlan::EthPeg => eth_usd,
            PricePlan::Single { result_idx } => {
                let sqrt = decode_u256(&batch2_results[result_idx]);
                let weth_bal = decode_u256(&batch2_results[result_idx + 1]);
                if sqrt.is_zero() || weth_bal < MIN_POOL_WETH_WEI {
                    0.0
                } else {
                    token_price_in_eth(sqrt, token.address, token.decimals, weth) * eth_usd
                }
            }
            PricePlan::Probe { start_idx } => {
                let end = start_idx + PROBE_FEES.len() * 2;
                let sqrt = first_liquid_sqrt(&batch2_results[start_idx..end]);
                if sqrt.is_zero() {
                    0.0
                } else {
                    token_price_in_eth(sqrt, token.address, token.decimals, weth) * eth_usd
                }
            }
        };
        let (bal_str, bal_f64) = format_token_balance(raw_balance, token.decimals);
        // Discovered-token metadata is attacker-controlled (the contract picks
        // its own symbol/name; an indexer relays it). Sanitize at this single
        // ingestion point — bidi/zero-width/control strip + length clamp — so
        // every downstream render (Send token row, dashboard list) is safe.
        // Bundled-allowlist tokens are clean ASCII, so this is a no-op for them.
        tokens.push(LiveToken {
            symbol: crate::sanitize::sanitize_display(
                token.symbol.as_ref(),
                crate::sanitize::MAX_TOKEN_SYMBOL_CHARS,
            )
            .into_owned(),
            name: crate::sanitize::sanitize_display(
                token.name.as_ref(),
                crate::sanitize::MAX_TOKEN_NAME_CHARS,
            )
            .into_owned(),
            balance: bal_str,
            balance_f64: bal_f64,
            balance_raw: raw_balance,
            decimals: token.decimals,
            contract: Some(token.address),
            usd_price: price,
            usd_value: bal_f64 * price,
            chain: chain.into(),
        });
    }

    // ETH first, then by USD value descending. Matches the per-chain
    // sort the dashboard relies on for stable row ordering.
    let erc20_start = if has_eth { 1 } else { 0 };
    tokens[erc20_start..].sort_by(|a, b| {
        b.usd_value
            .partial_cmp(&a.usd_value)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for tk in &tokens {
        trace!(
            owner = %short_address(owner),
            balance = %tk.balance,
            symbol = %tk.symbol,
            usd = format!("${:.2}", tk.usd_value),
            "portfolio entry",
        );
    }

    Ok(tokens)
}

#[cfg(test)]
mod pool_address_tests {
    use super::*;

    #[test]
    fn mainnet_usdc_weth_500_pool_matches_canonical() {
        // Canonical Mainnet USDC/WETH 0.05% pool — the highest-liquidity
        // ETH/USD source on L1, used as the algorithm-correctness anchor.
        let factory = factory_for(Chain::Mainnet);
        let usdc = usdc_for(Chain::Mainnet);
        let weth = weth_for(Chain::Mainnet);
        let derived = pool_address(factory, usdc, weth, 500);
        let canonical: Address = address!("0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640");
        assert_eq!(derived, canonical, "derived: {derived:?}");
    }

    #[test]
    fn base_usdc_weth_500_pool_matches_canonical() {
        // Canonical Base USDC/WETH 0.05% pool. Anchors `usdc_for(Base)` —
        // a typo in the USDC address would put `slot0` at an empty
        // address and silently zero out ETH/USD on Base.
        let factory = factory_for(Chain::Base);
        let usdc = usdc_for(Chain::Base);
        let weth = weth_for(Chain::Base);
        let derived = pool_address(factory, usdc, weth, 500);
        let canonical: Address = address!("0xd0b53D9277642d899DF5C87A3966A349A798F224");
        assert_eq!(derived, canonical, "derived: {derived:?}");
    }

    #[test]
    fn optimism_usdc_weth_500_pool_matches_canonical() {
        // Canonical Optimism USDC/WETH 0.05% pool — same regression
        // anchor as the Mainnet/Base tests above.
        let factory = factory_for(Chain::Optimism);
        let usdc = usdc_for(Chain::Optimism);
        let weth = weth_for(Chain::Optimism);
        let derived = pool_address(factory, usdc, weth, 500);
        let canonical: Address = address!("0x1fb3cf6e48F1E7B10213E7b6d87D4c073C7Fdb7b");
        assert_eq!(derived, canonical, "derived: {derived:?}");
    }
}

#[cfg(test)]
mod tokenlist_tests {
    use super::*;

    /// The bundled Superchain Token List must always parse and yield
    /// non-empty Base + Optimism vecs. A regression here means the
    /// L2 on-chain walk is back to ETH-only (no ERC-20 surfaces).
    #[test]
    fn parse_tokenlist_yields_l2_entries_and_drops_mainnet() {
        let (optimism, base) = parse_tokenlist();
        assert!(!optimism.is_empty(), "Optimism tokenlist must not be empty");
        assert!(!base.is_empty(), "Base tokenlist must not be empty");

        // cbETH on Optimism is one of the entries we sampled while
        // designing the change — pin it as a coverage anchor so a future
        // tokenlist sync that drops L2 entries fails loudly.
        let cbeth: Address = address!("0xaddb6a0412de1ba0f936dcaeb8aaa24578dcf3b2");
        assert!(
            optimism.iter().any(|t| t.address == cbeth),
            "expected cbETH on Optimism in parsed list",
        );

        // Every parsed entry should default to probing — fee tiers come
        // from the overlay, not the tokenlist.
        assert!(
            optimism
                .iter()
                .all(|t| matches!(t.price_source, PriceSource::UniswapWethPoolProbe)),
        );
    }

    /// Overlay must win on address collision — otherwise a tokenlist row
    /// with `Probe` would shadow a curated entry's known fee tier and
    /// cost an extra round trip per refresh just to rediscover it.
    #[test]
    fn merge_overlay_wins_on_address_collision() {
        // Reuse a real L2 USDC address from the Optimism overlay so the
        // collision is a realistic one — same address, different price
        // source.
        let usdc_op = address!("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85");
        let overlay = &[OverlayEntry {
            symbol: "USDC",
            name: "USD Coin",
            address: usdc_op,
            decimals: 6,
            price_source: PriceSource::UniswapWethPool { fee: 500 },
        }];
        let tokenlist = vec![TokenMeta {
            symbol: Cow::Owned("FAKE".into()),
            name: Cow::Owned("Imposter".into()),
            address: usdc_op,
            decimals: 18,
            price_source: PriceSource::UniswapWethPoolProbe,
        }];
        let merged = merge_overlay(overlay, tokenlist);
        assert_eq!(merged.len(), 1, "collision must dedupe to a single row");
        assert_eq!(merged[0].symbol, "USDC", "overlay symbol wins");
        assert!(
            matches!(
                merged[0].price_source,
                PriceSource::UniswapWethPool { fee: 500 }
            ),
            "overlay's known fee tier must beat tokenlist Probe",
        );
    }

    /// Tokenlist entries with addresses the overlay doesn't carry must
    /// pass through unchanged — that's where the bulk of L2 coverage
    /// comes from.
    #[test]
    fn merge_overlay_appends_disjoint_tokenlist_entries() {
        let only_in_tokenlist = address!("0x000096630066820566162c94874a776532705231");
        let merged = merge_overlay(
            BASE_OVERLAY,
            vec![TokenMeta {
                symbol: Cow::Owned("OBSCURE".into()),
                name: Cow::Owned("Obscure Token".into()),
                address: only_in_tokenlist,
                decimals: 18,
                price_source: PriceSource::UniswapWethPoolProbe,
            }],
        );
        assert_eq!(merged.len(), BASE_OVERLAY.len() + 1);
        assert!(merged.iter().any(|t| t.address == only_in_tokenlist));
    }

    /// The Base swap picker's "popular" set is the first 10 of
    /// `curated_tokens` (overlay first, then the alphabetical tokenlist). The
    /// major stablecoins must occupy those slots instead of the long-tail junk
    /// that sorts first alphabetically (ABT, ADS, ADX, AIKEK, …).
    #[test]
    fn base_swap_picker_top10_shows_stables_not_alphabetical_junk() {
        let curated = curated_tokens(Chain::Base);
        let top10: Vec<String> = curated
            .iter()
            .take(10)
            .map(|(sym, _, _)| sym.clone())
            .collect();
        for stable in ["DAI", "crvUSD", "fxUSD", "eUSD", "USDT"] {
            assert!(
                top10.iter().any(|s| s == stable),
                "{stable} should be a top-10 Base swap target; got {top10:?}",
            );
        }
        for junk in ["ABT", "ADS", "ADX", "AIKEK"] {
            assert!(
                !top10.iter().any(|s| s == junk),
                "{junk} should be pushed out of the top 10; got {top10:?}",
            );
        }
        // 0xBTC is blocklisted — it must not appear anywhere in the Base list.
        assert!(
            !curated.iter().any(|(sym, _, _)| sym == "0xBTC"),
            "0xBTC should be dropped from the Base token list entirely",
        );
    }
}

#[cfg(test)]
mod discovery_tests {
    use super::*;

    /// Curated overlay must win on address collision: a discovered row
    /// pointing at a staple (e.g. USDC) would otherwise shadow the
    /// overlay's known Uniswap fee tier with `UniswapWethPoolProbe`,
    /// costing an extra Multicall3 subcall per refresh to rediscover
    /// the same pool we already had pinned.
    #[test]
    fn discovered_does_not_override_overlay_fee_tier() {
        let usdc_mainnet = address!("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        let discovered = vec![DiscoveredToken {
            symbol: "FAKE".into(),
            name: "Imposter USDC".into(),
            address: usdc_mainnet,
            decimals: 18,
        }];
        let merged = merge_discovered(&MAINNET_TOKENS, &discovered);
        assert_eq!(merged.len(), MAINNET_TOKENS.len(), "collision must dedupe");
        let row = merged.iter().find(|t| t.address == usdc_mainnet).unwrap();
        assert_eq!(row.symbol, "USDC", "overlay symbol wins");
        assert_eq!(row.decimals, 6, "overlay decimals win");
        assert!(
            matches!(row.price_source, PriceSource::UniswapWethPool { fee: 500 }),
            "overlay fee tier must beat discovered Probe",
        );
    }

    /// Discovered rows the overlay doesn't carry must pass through and
    /// default to `UniswapWethPoolProbe` — the indexer doesn't surface
    /// fee tiers, so price discovery has to probe at fetch time.
    #[test]
    fn discovered_appends_new_addresses_as_probe() {
        let only_in_indexer = address!("0x0000000000000000000000000000000000beef00");
        let merged = merge_discovered(
            &MAINNET_TOKENS,
            &[DiscoveredToken {
                symbol: "BEEF".into(),
                name: "Beef Token".into(),
                address: only_in_indexer,
                decimals: 9,
            }],
        );
        assert_eq!(merged.len(), MAINNET_TOKENS.len() + 1);
        let row = merged
            .iter()
            .find(|t| t.address == only_in_indexer)
            .unwrap();
        assert_eq!(row.symbol, "BEEF");
        assert_eq!(row.decimals, 9);
        assert!(matches!(
            row.price_source,
            PriceSource::UniswapWethPoolProbe
        ));
    }

    /// Empty-discovery must collapse to the curated overlay exactly —
    /// this is the "indexer offline or no holdings" path, and it must
    /// behave identically to `fetch_portfolio`'s default token list.
    #[test]
    fn empty_discovery_returns_overlay_verbatim() {
        let merged = merge_discovered(&MAINNET_TOKENS, &[]);
        assert_eq!(merged.len(), MAINNET_TOKENS.len());
        for (m, base) in merged.iter().zip(MAINNET_TOKENS.iter()) {
            assert_eq!(m.address, base.address);
            assert_eq!(m.symbol, base.symbol);
        }
    }
}

#[cfg(test)]
mod helper_tests {
    use super::*;

    #[test]
    fn is_rate_limited_matches_known_patterns() {
        assert!(is_rate_limited("HTTP 429 Too Many Requests"));
        assert!(is_rate_limited("rate-limited by upstream"));
        assert!(is_rate_limited("rate limit reached"));
        assert!(is_rate_limited("Too Many Requests"));
        assert!(!is_rate_limited("connection refused"));
        assert!(!is_rate_limited("internal server error"));
    }

    #[test]
    fn factory_for_distinct_per_chain_except_mainnet_op() {
        let m = factory_for(Chain::Mainnet);
        let b = factory_for(Chain::Base);
        let o = factory_for(Chain::Optimism);
        // Mainnet and Optimism share the canonical Uniswap factory; Base
        // is its own deployment.
        assert_eq!(m, o);
        assert_ne!(m, b);
    }

    #[test]
    fn weth_for_l2_share_predeploy() {
        assert_eq!(weth_for(Chain::Base), weth_for(Chain::Optimism));
        assert_ne!(weth_for(Chain::Base), weth_for(Chain::Mainnet));
    }

    #[test]
    fn usdc_for_distinct_per_chain() {
        let m = usdc_for(Chain::Mainnet);
        let b = usdc_for(Chain::Base);
        let o = usdc_for(Chain::Optimism);
        let unique: std::collections::HashSet<_> = [m, b, o].into_iter().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn balance_of_calldata_layout() {
        let owner = address!("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
        let data = balance_of_calldata(owner);
        let bytes: &[u8] = data.as_ref();
        // 4-byte selector + 12-byte left padding + 20-byte address = 36 bytes.
        assert_eq!(bytes.len(), 36);
        assert_eq!(&bytes[..4], &[0x70, 0xa0, 0x82, 0x31]);
        assert_eq!(&bytes[4..16], &[0u8; 12]);
        assert_eq!(&bytes[16..], owner.as_slice());
    }

    #[test]
    fn balance_of_selector_matches_keccak() {
        // First 4 bytes of keccak256("balanceOf(address)").
        let want = &keccak256(b"balanceOf(address)")[..4];
        assert_eq!(want, BALANCE_OF_SELECTOR);
    }

    #[test]
    fn slot0_selector_matches_keccak() {
        let want = &keccak256(b"slot0()")[..4];
        assert_eq!(want, SLOT0_SELECTOR);
    }

    #[test]
    fn sqrt_price_to_raw_zero_returns_zero() {
        assert_eq!(sqrt_price_to_raw(U256::ZERO), 0.0);
    }

    #[test]
    fn sqrt_price_to_raw_q96_yields_one() {
        // sqrt = 2^96 → raw = (2^96 / 2^96)^2 = 1.0
        let q96 = U256::from(1u128) << 96;
        let raw = sqrt_price_to_raw(q96);
        assert!((raw - 1.0).abs() < 1e-9, "got {raw}");
    }

    #[test]
    fn token_price_in_eth_token0_branch() {
        // token < weth: token is token0; raw = (token1/token0) in smallest
        // units = (weth_raw / token_raw). Pass raw=1.0 (i.e., 1 WETH unit per
        // token unit), token_decimals=18, so dec_diff=0 → 1.0.
        let token = address!("0x0000000000000000000000000000000000000001");
        let weth = address!("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
        let q96 = U256::from(1u128) << 96;
        let price = token_price_in_eth(q96, token, 18, weth);
        assert!((price - 1.0).abs() < 1e-9, "got {price}");
    }

    #[test]
    fn token_price_in_eth_token1_branch() {
        // weth < token: token is token1; price = 10^(dec_diff)/raw.
        // Pick token addr > weth, decimals=18, raw=1 → 1.0.
        let weth = address!("0x0000000000000000000000000000000000000001");
        let token = address!("0xffffffffffffffffffffffffffffffffffffffff");
        let q96 = U256::from(1u128) << 96;
        let price = token_price_in_eth(q96, token, 18, weth);
        assert!((price - 1.0).abs() < 1e-9, "got {price}");
    }

    #[test]
    fn token_price_in_eth_zero_sqrt_returns_zero() {
        let token = address!("0x0000000000000000000000000000000000000001");
        let weth = address!("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
        assert_eq!(token_price_in_eth(U256::ZERO, token, 18, weth), 0.0);
    }

    #[test]
    fn eth_usd_from_sqrt_price_zero_returns_zero() {
        let usdc = address!("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        let weth = address!("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
        assert_eq!(eth_usd_from_sqrt_price(U256::ZERO, usdc, weth), 0.0);
    }

    #[test]
    fn format_token_balance_huge_decimals_does_not_overflow() {
        // `decimals` is untrusted indexer/contract metadata. 255 would make
        // `10u64.pow(255)` overflow u64 (panic in debug, wrap in release).
        // The clamp + f64 divisor must yield a finite, sane result instead.
        let raw = U256::from(1_000_000u64);
        let (s, f) = format_token_balance(raw, 255);
        assert!(f.is_finite(), "value must be finite, got {f}");
        assert!(f >= 0.0, "value must be non-negative, got {f}");
        // 1e6 / 10^36 rounds to zero at 6 dp.
        assert_eq!(s, "0.000000");
    }

    #[test]
    fn format_token_balance_at_clamp_boundary_is_finite() {
        // decimals == MAX_DISPLAY_DECIMALS and one above both stay finite and
        // (after clamping) produce the same scale.
        let raw = U256::from(5u64) * U256::from(10).pow(U256::from(36));
        let (_, at_cap) = format_token_balance(raw, MAX_DISPLAY_DECIMALS);
        let (_, over_cap) = format_token_balance(raw, 200);
        assert!(at_cap.is_finite() && over_cap.is_finite());
        assert!(
            (at_cap - over_cap).abs() < 1e-9,
            "over-cap clamps to the cap"
        );
        assert!((at_cap - 5.0).abs() < 1e-9, "5 * 10^36 / 10^36 == 5");
    }

    #[test]
    fn format_eth_balance_under_thousand_uses_four_decimals() {
        // 1.5 ETH → "1.5000"
        let raw = U256::from(15u64) * U256::from(10).pow(U256::from(17));
        let (s, f) = format_eth_balance(raw);
        assert_eq!(s, "1.5000");
        assert!((f - 1.5).abs() < 1e-9);
    }

    #[test]
    fn format_eth_balance_over_thousand_uses_two_decimals() {
        // 1234.5 ETH
        let raw = U256::from(12345u64) * U256::from(10).pow(U256::from(17));
        let (s, _) = format_eth_balance(raw);
        assert_eq!(s, "1234.50");
    }

    #[test]
    fn new_cache_is_empty_and_shareable() {
        let c1 = new_cache();
        let c2 = c1.clone();
        assert!(c1.lock().unwrap().is_empty());
        let key = (Address::ZERO, NetworkId::Builtin(Chain::Mainnet));
        c1.lock().unwrap().insert(key, Vec::new());
        // The clone shares the same lock; the insertion is visible.
        assert!(c2.lock().unwrap().contains_key(&key));
    }
}

#[cfg(test)]
mod multicall_tests {
    use super::*;
    use alloy::primitives::U256;
    use alloy::sol_types::SolCall;

    /// Round-trip the `aggregate3` calldata: encoding three balanceOf
    /// subcalls and decoding the bytes back must yield the same
    /// addresses + calldata. A silent break here would make every
    /// portfolio refresh hit the wrong tokens.
    #[test]
    fn aggregate3_calldata_round_trips() {
        let owner: Address = address!("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
        let usdc_op: Address = address!("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85");
        let usdt_op: Address = address!("0x94b008aA00579c1307B0EF2c499aD98a8ce58e58");
        let calls = vec![
            Call3 {
                target: MULTICALL3,
                allowFailure: false,
                callData: Bytes::from(getEthBalanceCall { addr: owner }.abi_encode()),
            },
            Call3 {
                target: usdc_op,
                allowFailure: true,
                callData: balance_of_calldata(owner),
            },
            Call3 {
                target: usdt_op,
                allowFailure: true,
                callData: balance_of_calldata(owner),
            },
        ];
        let encoded = aggregate3Call {
            calls: calls.clone(),
        }
        .abi_encode();
        let decoded = aggregate3Call::abi_decode(&encoded).expect("input must decode");

        assert_eq!(decoded.calls.len(), 3);
        assert_eq!(decoded.calls[0].target, MULTICALL3);
        assert!(!decoded.calls[0].allowFailure);
        assert_eq!(decoded.calls[1].target, usdc_op);
        assert!(decoded.calls[1].allowFailure);
        assert_eq!(decoded.calls[1].callData, calls[1].callData);
        assert_eq!(decoded.calls[2].target, usdt_op);
        assert_eq!(decoded.calls[2].callData, calls[2].callData);
    }

    fn raw_sqrt(value: U256) -> Bytes {
        let mut buf = vec![0u8; 32];
        let bytes = value.to_be_bytes::<32>();
        buf.copy_from_slice(&bytes);
        Bytes::from(buf)
    }

    fn ok(data: Bytes) -> MultiResult {
        MultiResult {
            success: true,
            returnData: data,
        }
    }

    fn failed() -> MultiResult {
        MultiResult {
            success: false,
            returnData: Bytes::new(),
        }
    }

    /// `decode_u256` is the single chokepoint that translates a
    /// `MultiResult` row into a U256. Its three failure modes must all
    /// collapse to zero — short data, empty data, and `success=false`
    /// — otherwise a malformed pool/token would render as a wildly
    /// wrong USD value instead of "no price".
    #[test]
    fn decode_u256_handles_failure_and_short_data() {
        let happy = ok(raw_sqrt(U256::from(123_456_789u64)));
        assert_eq!(decode_u256(&happy), U256::from(123_456_789u64));

        // success=false → zero, regardless of data length.
        let oops = failed();
        assert_eq!(decode_u256(&oops), U256::ZERO);

        // success=true but empty data → zero.
        let empty = ok(Bytes::new());
        assert_eq!(decode_u256(&empty), U256::ZERO);

        // Short data (<32 bytes) → zero. Catches a Multicall3-style
        // partial response without misinterpreting the prefix.
        let short = ok(Bytes::from(vec![0u8; 16]));
        assert_eq!(decode_u256(&short), U256::ZERO);
    }

    /// Probe order: 0.05 % is checked first, then 0.3 %, then 1 %.
    /// `first_liquid_sqrt` walks `(slot0, weth_balance)` pairs in that
    /// order and must skip any pool that's missing, has zero `slot0`,
    /// or holds less than `MIN_POOL_WETH_WEI`. Anchors the
    /// `UniswapWethPoolProbe` arm against silent reordering and against
    /// regressions of the abandoned-pool bug (Base WALLET/WETH 1 %).
    #[test]
    fn first_liquid_sqrt_skips_empty_and_thin_pools() {
        let liquid = MIN_POOL_WETH_WEI; // exactly at the floor must qualify
        let thin = MIN_POOL_WETH_WEI - U256::from(1u64);

        // [0.05 % zero, 0.3 % failed, 1 % liquid non-zero] — picks 1 %.
        let results = vec![
            ok(raw_sqrt(U256::ZERO)),
            ok(raw_sqrt(liquid)),
            failed(),
            failed(),
            ok(raw_sqrt(U256::from(42u64))),
            ok(raw_sqrt(liquid)),
        ];
        assert_eq!(first_liquid_sqrt(&results), U256::from(42u64));

        // [0.05 % non-zero but THIN, 0.3 % non-zero and liquid, …] —
        // skips the thin abandoned pool and picks 0.3 %.
        let results = vec![
            ok(raw_sqrt(U256::from(99u64))),
            ok(raw_sqrt(thin)),
            ok(raw_sqrt(U256::from(7u64))),
            ok(raw_sqrt(liquid)),
            ok(raw_sqrt(U256::from(123u64))),
            ok(raw_sqrt(liquid)),
        ];
        assert_eq!(first_liquid_sqrt(&results), U256::from(7u64));

        // Every pool is either dead or thin → zero ($0 price).
        let results = vec![
            failed(),
            failed(),
            ok(raw_sqrt(U256::from(5u64))),
            ok(raw_sqrt(thin)),
            ok(raw_sqrt(U256::ZERO)),
            ok(raw_sqrt(liquid)),
        ];
        assert_eq!(first_liquid_sqrt(&results), U256::ZERO);
    }
}
