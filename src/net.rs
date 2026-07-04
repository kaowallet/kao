//! Helios-backed verified RPC client with raw-RPC fallback. Per-chain.
//!
//! `NetworkClient` owns one Helios light-client per supported chain
//! (Mainnet via `helios_ethereum::EthereumClient`; Base / Optimism via
//! `helios_opstack::OpStackClient`). Every chain has its own client cache,
//! cooldown clock, and raw-RPC fallback — a Base RPC failure can't affect
//! Mainnet's verified path.
//!
//! When a Helios call errors (sync timeout, build failure, an RPC that
//! won't serve `eth_getProof`, etc.) the per-chain `balance` method falls
//! back to a plain `eth_getBalance` against the same execution RPC. A
//! short cooldown then skips Helios entirely so the user keeps getting
//! balances back without paying the helios attempt cost on every request.
//! After the cooldown elapses, helios is tried again.
//!
//! Mirrors the pattern in kohaku-extension's `HeliosEthersProvider`. The
//! UI reads `last_status(chain)` to surface verification state per-chain.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use alloy::network::Ethereum;
use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::providers::{Provider, RootProvider};
use alloy::rpc::client::RpcClient;
use alloy_eips::BlockId;
use async_trait::async_trait;
use rand::seq::SliceRandom;
use tokio::sync::Mutex;

use helios_ethereum::config::checkpoints::{CheckpointFallback, Slot};
use helios_ethereum::config::networks::Network as EthNetwork;
use helios_ethereum::{EthereumClient, EthereumClientBuilder};
use helios_opstack::OpStackClientBuilder;
use helios_opstack::config::Network as OpNetwork;
use tracing::{debug, error, info, warn};

use crate::chain::{Chain, PerChain};
use crate::portfolio::with_transient_retry;
use crate::settings;
use crate::wallet::short_address;

/// How recently does a helios failure have to be for us to skip helios on
/// the next request? Matches kohaku-extension's `FALLBACK_COOLDOWN_MS`.
/// Short enough that a transient hiccup doesn't keep the user on
/// unverified results for long, long enough that we don't pay the helios
/// sync cost repeatedly when the chosen exec RPC is permanently
/// incompatible (e.g. proof-window limits).
///
/// Public so the simulation auto-retry can wait out exactly this window
/// (plus a margin) before re-running on the verified path.
pub const FALLBACK_COOLDOWN: Duration = Duration::from_secs(10);

/// Verification state of the most recent balance fetch on a single chain.
/// Sampled by the dashboard to render a "Verified by Helios" / "Unverified
/// RPC" badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// No fetch has completed yet — helios is still bootstrapping or
    /// hasn't been touched this session.
    Connecting,
    /// Last fetch went through helios's light-client `eth_getProof` path.
    Verified,
    /// Last fetch went through the raw-RPC fallback. The balance is
    /// whatever the upstream returned; it has not been proved against the
    /// consensus header.
    Fallback,
    /// Both helios and the raw-RPC fallback failed. The user is staring
    /// at a stale or "—" balance.
    Unavailable,
}

impl VerificationStatus {
    fn as_u8(self) -> u8 {
        match self {
            Self::Connecting => 0,
            Self::Verified => 1,
            Self::Fallback => 2,
            Self::Unavailable => 3,
        }
    }
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Verified,
            2 => Self::Fallback,
            3 => Self::Unavailable,
            _ => Self::Connecting,
        }
    }
}

/// Network operations callers (UI screens, App) need from the RPC layer.
///
/// Held as `Arc<dyn BalanceFetcher>` so tests can substitute a
/// deterministic mock without standing up Helios. The real impl is
/// `NetworkClient`; the test impl is `MockFetcher` below.
///
/// Every method that touches per-chain state takes a `Chain` argument so
/// the dashboard can fan out balance/portfolio fetches across Mainnet,
/// Base, and Optimism in parallel. The HD-account discovery and import
/// flows pin to `Chain::Mainnet` because address-existence probing is
/// only meaningful against the canonical chain.
#[async_trait]
pub trait BalanceFetcher: Send + Sync + std::fmt::Debug {
    /// Formatted-ether balance of `addr` on `chain`, e.g. "1.234". Tries
    /// helios first; on error, falls back to a raw `eth_getBalance`
    /// against the same exec RPC and starts a short cooldown. Inspect
    /// `last_status(chain)` afterwards to see whether the value was
    /// light-client verified.
    async fn balance(&self, addr: Address, chain: Chain) -> Result<String, String>;
    /// Drop every cached client across all chains. The next per-chain
    /// `balance` call rebuilds from settings.
    #[allow(dead_code)]
    async fn invalidate(&self);
    /// Verification state of the most recent `balance` call on `chain`.
    /// Sync getter so the UI thread can read it without awaiting.
    fn last_status(&self, chain: Chain) -> VerificationStatus;
    /// Shared raw `RootProvider` against the exec RPC `chain` is using
    /// (or, if helios hasn't been built yet for that chain, a freshly-
    /// picked one cached for future calls). Returned cheaply via the
    /// provider's internal `Arc`, so callers that issue raw `eth_call` /
    /// `eth_getBalance` (e.g. the portfolio fetcher) reuse one transport
    /// across account switches instead of building a new TLS pool every
    /// dashboard rebuild. `None` only when no RPCs are configured for
    /// the chain or the chosen URL won't parse.
    async fn provider(&self, chain: Chain) -> Option<RootProvider<Ethereum>>;
    /// Raw `RootProvider` for a user-defined custom network at `rpc_url`.
    ///
    /// Custom networks are never Helios-verified, so this is a plain HTTP
    /// provider built straight from the URL the user typed — the same
    /// transport `balance`'s raw fallback uses for built-ins. `chain_id` is
    /// accepted for symmetry/logging and so an impl may key a cache on it;
    /// the default builds fresh each call, which keeps the provider in lock-
    /// step with edits to the network's RPC URL. `None` when the URL won't
    /// parse. Process-wide `ALL_PROXY` still applies to remote custom RPCs, so
    /// a configured proxy covers their traffic too — but a *loopback* RPC (a
    /// local Anvil/Hardhat node) bypasses the proxy, since a remote proxy can't
    /// reach the user's own machine and loopback never leaves it anyway. See
    /// `provider_for_url` / `is_loopback_host`.
    async fn custom_provider(
        &self,
        chain_id: u64,
        rpc_url: &str,
    ) -> Option<RootProvider<Ethereum>> {
        let _ = chain_id;
        build_fallback(rpc_url)
    }
    /// Verified contract bytecode at `addr`. Tries Helios first; on error,
    /// falls back to a raw `eth_getCode` and starts the same cooldown
    /// `balance` uses. The returned `verified` flag tells the caller
    /// whether the bytecode crossed the light-client proof path — the
    /// clear-signing pipeline surfaces an "unverified bytecode" warning
    /// when `verified == false`.
    ///
    /// Does not touch `last_status`; that badge tracks balance reads
    /// only, otherwise the verification badge would flicker with every
    /// proxy walk.
    async fn get_code(&self, addr: Address, chain: Chain) -> Result<VerifiedRead<Bytes>, String>;
    /// Verified storage slot read. Same fallback / verification shape as
    /// `get_code`. Used by the proxy walker to follow EIP-1967 / beacon
    /// implementation pointers.
    async fn get_storage_at(
        &self,
        addr: Address,
        slot: U256,
        chain: Chain,
    ) -> Result<VerifiedRead<B256>, String>;
    /// Verified `eth_call`: Helios re-executes locally against
    /// proof-verified state, so the returned bytes were computed from
    /// bytecode and storage the light client vouched for. Used by
    /// clear-signing's `symbol()` / `decimals()` probes — without this
    /// the user signs based on cosmetic metadata an RPC chose to
    /// return, which is exactly the spoofing surface the rest of the
    /// pipeline closes.
    async fn call(
        &self,
        to: Address,
        data: Bytes,
        chain: Chain,
    ) -> Result<VerifiedRead<Bytes>, String>;
    /// Verified balance as a raw `U256` — distinct from `balance()`,
    /// which formats to a UI-facing ether string and bumps the global
    /// verification badge. The simulator needs the integer for revm's
    /// `AccountInfo.balance`, and it must not race the dashboard's
    /// balance reads on the badge.
    async fn get_balance_raw(
        &self,
        addr: Address,
        chain: Chain,
    ) -> Result<VerifiedRead<U256>, String>;
    /// Verified `eth_getTransactionCount` at the latest verified head.
    /// The simulator uses this for `from`'s on-chain nonce — distinct
    /// from the *pending* nonce the broadcast path needs.
    async fn get_transaction_count(
        &self,
        addr: Address,
        chain: Chain,
    ) -> Result<VerifiedRead<u64>, String>;
    /// Verified subset of the latest block header — populates revm's
    /// `BlockEnv`. The `hash` field pins the block the simulator's
    /// state reads run against, so a reorg mid-simulation can't mix
    /// proofs across two heads.
    async fn latest_block(&self, chain: Chain) -> Result<VerifiedRead<LatestBlock>, String>;

    /// Raw `eth_getCode` that explicitly skips helios. Used by the Safe
    /// scan: helios-opstack's consensus client spawns a tokio task per
    /// build that polls the L2 beacon proxy every second forever (its
    /// `shutdown()` is a no-op upstream), so triggering a helios build
    /// for an L2 chain the user is just *probing* leaves a permanent
    /// log-spamming task behind. The scan only needs to ask "is there
    /// a Safe at this address?" — that result is informational, and
    /// the verified path takes over once the user actually broadcasts
    /// through the Safe.
    async fn get_code_raw(
        &self,
        addr: Address,
        chain: Chain,
    ) -> Result<VerifiedRead<Bytes>, String>;
    /// Raw `eth_getStorageAt` that explicitly skips helios. See
    /// [`get_code_raw`].
    async fn get_storage_at_raw(
        &self,
        addr: Address,
        slot: U256,
        chain: Chain,
    ) -> Result<VerifiedRead<B256>, String>;
    /// Raw `eth_call` that explicitly skips helios. See
    /// [`get_code_raw`].
    async fn call_raw(
        &self,
        to: Address,
        data: Bytes,
        chain: Chain,
    ) -> Result<VerifiedRead<Bytes>, String>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConfigSnapshot {
    rpcs: Vec<String>,
    consensus_rpcs: Vec<String>,
    /// Mainnet-only — None for L2 chains. OpStack doesn't take a
    /// checkpoint in `OpStackClientBuilder`; its consensus client polls
    /// the L2 beacon proxy for sequencer-signed blocks instead.
    checkpoint: Option<B256>,
}

/// Either a verified Ethereum client or a verified OP-Stack client. Both
/// expose the same shape (`get_balance`, `get_block_number`,
/// `wait_synced`, `shutdown`) via `helios_core::client::HeliosClient<N>`,
/// so a small enum dispatch is enough; we don't need a trait object.
#[derive(Clone)]
enum HeliosBackend {
    Eth(Arc<EthereumClient>),
    Op(Arc<helios_opstack::OpStackClient>),
}

impl HeliosBackend {
    async fn get_balance(&self, addr: Address, block: BlockId) -> Result<U256, String> {
        match self {
            Self::Eth(c) => c.get_balance(addr, block).await.map_err(|e| e.to_string()),
            Self::Op(c) => c.get_balance(addr, block).await.map_err(|e| e.to_string()),
        }
    }

    async fn get_code(&self, addr: Address, block: BlockId) -> Result<Bytes, String> {
        match self {
            Self::Eth(c) => c.get_code(addr, block).await.map_err(|e| e.to_string()),
            Self::Op(c) => c.get_code(addr, block).await.map_err(|e| e.to_string()),
        }
    }

    async fn get_storage_at(
        &self,
        addr: Address,
        slot: U256,
        block: BlockId,
    ) -> Result<B256, String> {
        match self {
            Self::Eth(c) => c
                .get_storage_at(addr, slot, block)
                .await
                .map_err(|e| e.to_string()),
            Self::Op(c) => c
                .get_storage_at(addr, slot, block)
                .await
                .map_err(|e| e.to_string()),
        }
    }

    /// Verified `eth_call` against `to` with `data`. Helios re-executes
    /// the call locally against proof-verified state — so what comes
    /// back has been computed against bytecode and storage that the
    /// light client cryptographically vouched for, not values an RPC
    /// provider chose to return.
    ///
    /// The boundary on this method is the type swap: our crate uses
    /// alloy 2.x but Helios's `call` takes alloy 1's `TransactionRequest`
    /// (or `OpTransactionRequest` on OP-Stack). Both share the same
    /// alloy-primitives 1.5.7 for `Address`, `Bytes`, etc., so we
    /// build the v1 request inside this method and never expose the v1
    /// type to callers.
    async fn call(&self, to: Address, data: Bytes, block: BlockId) -> Result<Bytes, String> {
        match self {
            Self::Eth(c) => {
                let req = alloy_rpc_types_eth::TransactionRequest::default()
                    .to(to)
                    .input(alloy_rpc_types_eth::TransactionInput::new(data));
                c.call(&req, block, None).await.map_err(|e| e.to_string())
            }
            Self::Op(c) => {
                let inner = alloy_rpc_types_eth::TransactionRequest::default()
                    .to(to)
                    .input(alloy_rpc_types_eth::TransactionInput::new(data));
                // `OpTransactionRequest::from(addr)` is the inherent
                // setter for the `from` field — distinct from the
                // `From<TransactionRequest>` trait we want. Use
                // `Into::into` so the trait impl is selected.
                let req: op_alloy_rpc_types::OpTransactionRequest = inner.into();
                c.call(&req, block, None).await.map_err(|e| e.to_string())
            }
        }
    }

    async fn get_block_number(&self) -> Result<U256, String> {
        match self {
            Self::Eth(c) => c.get_block_number().await.map_err(|e| e.to_string()),
            Self::Op(c) => c.get_block_number().await.map_err(|e| e.to_string()),
        }
    }

    /// Verified `eth_getTransactionCount` at the given block. The
    /// simulator reads this for `from` so revm's `TxEnv.nonce` matches
    /// what the EVM would observe at the same height. Pending nonces
    /// belong on the broadcast path, not preflight.
    async fn get_nonce(&self, addr: Address, block: BlockId) -> Result<u64, String> {
        match self {
            Self::Eth(c) => c.get_nonce(addr, block).await.map_err(|e| e.to_string()),
            Self::Op(c) => c.get_nonce(addr, block).await.map_err(|e| e.to_string()),
        }
    }

    /// Fetch the latest verified block header and extract the subset
    /// revm needs for `BlockEnv`. `full_tx = false` keeps the response
    /// small — we only read the header. Returns `Err` if Helios reports
    /// no head yet (`wait_for_head` should prevent that, but a reorg
    /// window or shutdown race can leave the cache empty).
    async fn latest_block(&self) -> Result<LatestBlock, String> {
        let id = BlockId::latest();
        match self {
            Self::Eth(c) => {
                let block = c
                    .get_block(id, false)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| "helios: no latest block".to_string())?;
                Ok(latest_from_rpc_header(&block.header))
            }
            Self::Op(c) => {
                let block = c
                    .get_block(id, false)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| "helios: no latest block".to_string())?;
                Ok(latest_from_rpc_header(&block.header))
            }
        }
    }

    async fn shutdown(&self) {
        match self {
            Self::Eth(c) => c.shutdown().await,
            Self::Op(c) => c.shutdown().await,
        }
    }
}

/// A state read paired with whether it came through Helios's verified
/// path (`true`) or the raw-RPC fallback (`false`). The badge state on
/// the dashboard tracks balance reads only — clear-signing surfaces this
/// per call so an "unverified bytecode" warning can render alongside a
/// decoded function body without affecting the global verification UI.
#[derive(Debug, Clone)]
pub struct VerifiedRead<T> {
    pub value: T,
    pub verified: bool,
}

/// Subset of block-header fields that revm's `BlockEnv` needs to simulate
/// a transaction. Pulled out so the simulator never reaches into a
/// network-specific `BlockResponse` type — both Mainnet and OP-Stack
/// flatten to this same shape. `hash` pins the block the simulator's
/// state reads run against, so a reorg mid-simulation doesn't mix proofs
/// across two heads.
#[derive(Debug, Clone)]
pub struct LatestBlock {
    pub number: u64,
    pub hash: B256,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub base_fee_per_gas: u64,
    pub prevrandao: B256,
    pub beneficiary: Address,
    pub excess_blob_gas: Option<u64>,
}

/// Helios side of a chain. Its mutex is held across the entire
/// build/sync in `get`, which serializes concurrent *verified* calls on
/// the same chain (intended — they all want the same client). Raw-RPC
/// state deliberately lives in [`RawState`] under its own lock so the
/// Safe scan's `*_raw` reads and the cooldown checks never stall behind
/// a 45-second helios sync.
#[derive(Default)]
struct ChainState {
    client: Option<HeliosBackend>,
    built_with: Option<ConfigSnapshot>,
}

/// Raw-RPC side of a chain. Guarded by a `std::sync::Mutex` (never held
/// across an `.await`) so it stays accessible while a helios build holds
/// the `ChainState` mutex.
#[derive(Default)]
struct RawState {
    /// Cached raw provider. Shared by the fallback path, the `*_raw`
    /// entry points, and `provider()` so a cooldown-period request
    /// doesn't pay TLS/transport setup every time.
    provider: Option<RootProvider<Ethereum>>,
    /// Set to `Some(Instant::now())` whenever a helios call has just
    /// errored or helios couldn't be built. Subsequent requests within
    /// `FALLBACK_COOLDOWN` skip helios entirely.
    last_fallback_at: Option<Instant>,
}

pub struct NetworkClient {
    states: PerChain<Mutex<ChainState>>,
    raw: PerChain<std::sync::Mutex<RawState>>,
    /// Most recent `VerificationStatus` per chain. Held outside the
    /// mutex so the UI can poll it without blocking on a long helios
    /// sync. Encoded as `u8` for `AtomicU8`; see
    /// `VerificationStatus::{as_u8,from_u8}`.
    statuses: PerChain<AtomicU8>,
}

impl std::fmt::Debug for NetworkClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkClient").finish_non_exhaustive()
    }
}

impl NetworkClient {
    pub fn new() -> Self {
        Self {
            states: PerChain::default(),
            raw: PerChain::default(),
            statuses: PerChain::default(),
        }
    }

    fn set_status(&self, chain: Chain, s: VerificationStatus) {
        self.statuses.get(chain).store(s.as_u8(), Ordering::Relaxed);
    }

    fn state_for(&self, chain: Chain) -> &Mutex<ChainState> {
        self.states.get(chain)
    }

    fn raw_state(&self, chain: Chain) -> std::sync::MutexGuard<'_, RawState> {
        self.raw
            .get(chain)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Resolve the shared raw provider for `chain`, building and caching
    /// one from settings when none exists yet. Single lock acquisition —
    /// callers hold the provider they got, so an `invalidate()` landing
    /// mid-request can't yank it out from under them.
    fn raw_provider(&self, chain: Chain) -> Result<RootProvider<Ethereum>, String> {
        let mut r = self.raw_state(chain);
        if let Some(p) = &r.provider {
            return Ok(p.clone());
        }
        let rpcs = settings::rpcs(chain);
        let url = rpcs
            .choose(&mut rand::thread_rng())
            .ok_or_else(|| format!("no execution RPCs configured for {}", chain.label()))?;
        let provider = build_fallback(url)
            .ok_or_else(|| format!("cannot build RPC provider for {}", chain.label()))?;
        r.provider = Some(provider.clone());
        Ok(provider)
    }

    /// Get a synced Helios client for `chain`, building (and waiting for
    /// sync) if needed. Rebuilds when the user's RPC endpoints have
    /// drifted from the last build.
    async fn get(&self, chain: Chain) -> Result<HeliosBackend, String> {
        let snapshot = current_snapshot(chain);
        let mut s = self.state_for(chain).lock().await;

        // Reuse the existing client when the *endpoints* match. The
        // checkpoint is deliberately excluded from the comparison: it's only
        // a bootstrap hint for Mainnet sync. A user-entered checkpoint
        // override flows through `invalidate()` (networks-pane save), which
        // clears `built_with` and forces the rebuild explicitly.
        if let (Some(client), Some(prev)) = (&s.client, &s.built_with)
            && prev.rpcs == snapshot.rpcs
            && prev.consensus_rpcs == snapshot.consensus_rpcs
        {
            return Ok(client.clone());
        }

        if snapshot.rpcs.is_empty() {
            return Err(format!(
                "no execution RPCs configured for {}",
                chain.label()
            ));
        }
        if snapshot.consensus_rpcs.is_empty() {
            return Err(format!(
                "no consensus RPCs configured for {}",
                chain.label()
            ));
        }
        let chosen_exec = pick_rpc(&snapshot.rpcs);
        // Point the raw provider at the same URL helios is about to use
        // so both paths share one transport. If helios's build/sync fails
        // below, the raw provider still exists for the cooldown window.
        self.raw_state(chain).provider = build_fallback(&chosen_exec);

        let consensus_order = shuffled(&snapshot.consensus_rpcs);
        info!(
            chain = %chain.label(),
            // URLs are scrubbed to scheme://host — exec/consensus RPC
            // URLs routinely carry the API key in the path or query.
            execution_rpc = %redact_urls(&chosen_exec),
            consensus_rpcs = ?consensus_order.iter().map(|u| redact_urls(u)).collect::<Vec<_>>(),
            checkpoint = ?snapshot.checkpoint,
            "building helios client",
        );
        let started = Instant::now();
        let backend = match build_backend_with_consensus_fallback(
            chain,
            &chosen_exec,
            &consensus_order,
            &snapshot,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    chain = %chain.label(),
                    elapsed = ?started.elapsed(),
                    error = %redact_urls(&e),
                    "helios build/sync failed",
                );
                return Err(e);
            }
        };
        info!(
            chain = %chain.label(),
            elapsed = ?started.elapsed(),
            "helios client built and synced",
        );

        let previous = s.client.replace(backend.clone());
        s.built_with = Some(snapshot);
        drop(s);
        spawn_shutdown(previous);
        Ok(backend)
    }

    /// Snapshot whether we should skip helios this request. Sync — reads
    /// only the raw-side lock, so it can't stall behind an in-flight
    /// helios build.
    fn in_cooldown(&self, chain: Chain) -> bool {
        self.raw_state(chain)
            .last_fallback_at
            .map(|t| t.elapsed() < FALLBACK_COOLDOWN)
            .unwrap_or(false)
    }

    /// Mark "helios just failed; route around it for a bit" and ensure a
    /// fallback provider exists for the cooldown window.
    fn start_cooldown(&self, chain: Chain) {
        let mut r = self.raw_state(chain);
        // The per-read failure that lands here is logged at debug; this
        // single info line makes the cooldown entry visible at default
        // log level — it explains every "unverified" read (and sim
        // badge) for the next window. Logged only on the transition
        // into cooldown: parallel reads (the sim's basic() fetches
        // balance/nonce/code concurrently) all land here at once, and
        // re-arms during an active window are extensions, not news.
        let already_cooling = r
            .last_fallback_at
            .map(|t| t.elapsed() < FALLBACK_COOLDOWN)
            .unwrap_or(false);
        if !already_cooling {
            info!(
                chain = %chain.label(),
                cooldown_secs = FALLBACK_COOLDOWN.as_secs(),
                "helios read failed — routing reads to raw RPC for the cooldown window",
            );
        }
        r.last_fallback_at = Some(Instant::now());
        if r.provider.is_none() {
            // Helios never even chose an exec RPC — pick one ourselves
            // so the fallback path has somewhere to send the request.
            let rpcs = settings::rpcs(chain);
            if let Some(url) = rpcs.choose(&mut rand::thread_rng()) {
                r.provider = build_fallback(url);
            }
        }
    }
}

/// Pause before the single in-place retry of a failed helios read.
/// Long enough to ride out the two transients we've actually observed —
/// the first reads right after a build/sync settle, and the gap after a
/// `helios_core` "inconsistent block history" cache clear (next unsafe
/// head lands within a block time) — short enough that a genuinely
/// down helios only delays the fallback by half a second.
const HELIOS_READ_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Run a helios read, retrying ONCE in place after a short pause.
///
/// Rationale: a single failed read starts the 10-second fallback
/// cooldown, which forces *every* read in that window — most visibly an
/// entire simulation — onto the unverified raw-RPC path. The observed
/// failures are overwhelmingly transient (post-sync settling, unsafe-
/// head reorg cache clears), so one immediate retry usually keeps the
/// whole operation on the verified path instead of poisoning it.
/// Deliberately unconditional (no error-shape predicate, unlike
/// `with_transient_retry`): helios error strings aren't stable enough
/// to classify, and the cost of a wasted retry is half a second.
async fn helios_read_with_retry<T, F>(
    what: &'static str,
    chain: Chain,
    op: impl Fn() -> F,
) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, String>>,
{
    match op().await {
        Ok(v) => Ok(v),
        Err(first) => {
            debug!(
                chain = %chain.label(),
                read = what,
                error = %redact_urls(&first),
                "helios read failed; retrying once in place",
            );
            tokio::time::sleep(HELIOS_READ_RETRY_DELAY).await;
            op().await
                .map_err(|second| format!("{first}; retry: {second}"))
        }
    }
}

/// Tell helios to stop the previous client's consensus task. Without
/// this, dropping the client leaves its spawned consensus loop running
/// for the rest of the process — and once the `shutdown_send` watch
/// sender is gone, the loop's `select!` arm on `shutdown_rx.changed()`
/// returns Err immediately every iteration without yielding, spinning CPU.
fn spawn_shutdown(backend: Option<HeliosBackend>) {
    let Some(backend) = backend else { return };
    tokio::spawn(async move {
        backend.shutdown().await;
        debug!("previous helios client shut down");
    });
}

#[async_trait]
impl BalanceFetcher for NetworkClient {
    /// Drop every cached client and tell helios to stop their consensus
    /// tasks. The next per-chain call will rebuild from current settings,
    /// picking a fresh random RPC from each chain's list.
    async fn invalidate(&self) {
        for chain in Chain::ALL {
            let previous = {
                let mut s = self.state_for(chain).lock().await;
                s.built_with = None;
                s.client.take()
            };
            spawn_shutdown(previous);
            {
                let mut r = self.raw_state(chain);
                r.provider = None;
                r.last_fallback_at = None;
            }
            self.set_status(chain, VerificationStatus::Connecting);
        }
    }

    async fn balance(&self, addr: Address, chain: Chain) -> Result<String, String> {
        // Cooldown: route straight to raw RPC, skip the helios attempt.
        if self.in_cooldown(chain) {
            return self.fallback_balance(addr, chain).await;
        }

        // Try helios. On any error, start a cooldown and fall through
        // to raw. The status is only written once the outcome is known —
        // setting `Connecting` up front would flicker the dashboard
        // badge Verified → Connecting → Verified on every healthy
        // refresh. (`Connecting` is the per-chain default at startup and
        // is restored by `invalidate()`.)
        match self.get(chain).await {
            Ok(client) => match helios_read_with_retry("balance", chain, || {
                client.get_balance(addr, BlockId::latest())
            })
            .await
            {
                Ok(raw) => {
                    self.set_status(chain, VerificationStatus::Verified);
                    Ok(alloy::primitives::utils::format_ether(raw))
                }
                Err(e) => {
                    debug!(
                        chain = %chain.label(),
                        addr = %short_address(addr),
                        error = %redact_urls(&e),
                        "helios balance failed; falling back to raw RPC",
                    );
                    self.start_cooldown(chain);
                    self.fallback_balance(addr, chain).await
                }
            },
            Err(e) => {
                warn!(
                    chain = %chain.label(),
                    error = %redact_urls(&e),
                    "helios unavailable; falling back to raw RPC",
                );
                self.start_cooldown(chain);
                self.fallback_balance(addr, chain).await
            }
        }
    }

    fn last_status(&self, chain: Chain) -> VerificationStatus {
        VerificationStatus::from_u8(self.statuses.get(chain).load(Ordering::Relaxed))
    }

    async fn provider(&self, chain: Chain) -> Option<RootProvider<Ethereum>> {
        self.raw_provider(chain).ok()
    }

    async fn get_code(&self, addr: Address, chain: Chain) -> Result<VerifiedRead<Bytes>, String> {
        if self.in_cooldown(chain) {
            return self.fallback_get_code(addr, chain).await;
        }
        match self.get(chain).await {
            Ok(client) => match helios_read_with_retry("get_code", chain, || {
                client.get_code(addr, BlockId::latest())
            })
            .await
            {
                Ok(value) => Ok(VerifiedRead {
                    value,
                    verified: true,
                }),
                Err(e) => {
                    debug!(
                        chain = %chain.label(),
                        addr = %short_address(addr),
                        error = %redact_urls(&e),
                        "helios get_code failed; falling back to raw RPC",
                    );
                    self.start_cooldown(chain);
                    self.fallback_get_code(addr, chain).await
                }
            },
            Err(e) => {
                warn!(
                    chain = %chain.label(),
                    error = %redact_urls(&e),
                    "helios unavailable for get_code; falling back to raw RPC",
                );
                self.start_cooldown(chain);
                self.fallback_get_code(addr, chain).await
            }
        }
    }

    async fn get_storage_at(
        &self,
        addr: Address,
        slot: U256,
        chain: Chain,
    ) -> Result<VerifiedRead<B256>, String> {
        if self.in_cooldown(chain) {
            return self.fallback_get_storage_at(addr, slot, chain).await;
        }
        match self.get(chain).await {
            Ok(client) => match helios_read_with_retry("get_storage_at", chain, || {
                client.get_storage_at(addr, slot, BlockId::latest())
            })
            .await
            {
                Ok(value) => Ok(VerifiedRead {
                    value,
                    verified: true,
                }),
                Err(e) => {
                    debug!(
                        chain = %chain.label(),
                        addr = %short_address(addr),
                        error = %redact_urls(&e),
                        "helios get_storage_at failed; falling back to raw RPC",
                    );
                    self.start_cooldown(chain);
                    self.fallback_get_storage_at(addr, slot, chain).await
                }
            },
            Err(e) => {
                warn!(
                    chain = %chain.label(),
                    error = %redact_urls(&e),
                    "helios unavailable for get_storage_at; falling back to raw RPC",
                );
                self.start_cooldown(chain);
                self.fallback_get_storage_at(addr, slot, chain).await
            }
        }
    }

    async fn call(
        &self,
        to: Address,
        data: Bytes,
        chain: Chain,
    ) -> Result<VerifiedRead<Bytes>, String> {
        if self.in_cooldown(chain) {
            return self.fallback_call(to, data, chain).await;
        }
        match self.get(chain).await {
            Ok(client) => match helios_read_with_retry("call", chain, || {
                client.call(to, data.clone(), BlockId::latest())
            })
            .await
            {
                Ok(value) => Ok(VerifiedRead {
                    value,
                    verified: true,
                }),
                Err(e) => {
                    debug!(
                        chain = %chain.label(),
                        addr = %short_address(to),
                        error = %redact_urls(&e),
                        "helios call failed; falling back to raw RPC",
                    );
                    self.start_cooldown(chain);
                    self.fallback_call(to, data, chain).await
                }
            },
            Err(e) => {
                warn!(
                    chain = %chain.label(),
                    error = %redact_urls(&e),
                    "helios unavailable for call; falling back to raw RPC",
                );
                self.start_cooldown(chain);
                self.fallback_call(to, data, chain).await
            }
        }
    }

    async fn get_balance_raw(
        &self,
        addr: Address,
        chain: Chain,
    ) -> Result<VerifiedRead<U256>, String> {
        if self.in_cooldown(chain) {
            return self.fallback_get_balance_raw(addr, chain).await;
        }
        match self.get(chain).await {
            Ok(client) => match helios_read_with_retry("get_balance_raw", chain, || {
                client.get_balance(addr, BlockId::latest())
            })
            .await
            {
                Ok(value) => Ok(VerifiedRead {
                    value,
                    verified: true,
                }),
                Err(e) => {
                    debug!(
                        chain = %chain.label(),
                        addr = %short_address(addr),
                        error = %redact_urls(&e),
                        "helios get_balance_raw failed; falling back to raw RPC",
                    );
                    self.start_cooldown(chain);
                    self.fallback_get_balance_raw(addr, chain).await
                }
            },
            Err(e) => {
                warn!(
                    chain = %chain.label(),
                    error = %redact_urls(&e),
                    "helios unavailable for get_balance_raw; falling back to raw RPC",
                );
                self.start_cooldown(chain);
                self.fallback_get_balance_raw(addr, chain).await
            }
        }
    }

    async fn get_transaction_count(
        &self,
        addr: Address,
        chain: Chain,
    ) -> Result<VerifiedRead<u64>, String> {
        if self.in_cooldown(chain) {
            return self.fallback_get_transaction_count(addr, chain).await;
        }
        match self.get(chain).await {
            Ok(client) => match helios_read_with_retry("get_transaction_count", chain, || {
                client.get_nonce(addr, BlockId::latest())
            })
            .await
            {
                Ok(value) => Ok(VerifiedRead {
                    value,
                    verified: true,
                }),
                Err(e) => {
                    debug!(
                        chain = %chain.label(),
                        addr = %short_address(addr),
                        error = %redact_urls(&e),
                        "helios get_transaction_count failed; falling back to raw RPC",
                    );
                    self.start_cooldown(chain);
                    self.fallback_get_transaction_count(addr, chain).await
                }
            },
            Err(e) => {
                warn!(
                    chain = %chain.label(),
                    error = %redact_urls(&e),
                    "helios unavailable for get_transaction_count; falling back to raw RPC",
                );
                self.start_cooldown(chain);
                self.fallback_get_transaction_count(addr, chain).await
            }
        }
    }

    async fn latest_block(&self, chain: Chain) -> Result<VerifiedRead<LatestBlock>, String> {
        if self.in_cooldown(chain) {
            return self.fallback_latest_block(chain).await;
        }
        match self.get(chain).await {
            Ok(client) => {
                match helios_read_with_retry("latest_block", chain, || client.latest_block()).await
                {
                    Ok(value) => Ok(VerifiedRead {
                        value,
                        verified: true,
                    }),
                    Err(e) => {
                        debug!(
                            chain = %chain.label(),
                            error = %redact_urls(&e),
                            "helios latest_block failed; falling back to raw RPC",
                        );
                        self.start_cooldown(chain);
                        self.fallback_latest_block(chain).await
                    }
                }
            }
            Err(e) => {
                warn!(
                    chain = %chain.label(),
                    error = %redact_urls(&e),
                    "helios unavailable for latest_block; falling back to raw RPC",
                );
                self.start_cooldown(chain);
                self.fallback_latest_block(chain).await
            }
        }
    }

    // The `*_raw` entry points are single-shot reads the Safe scan
    // treats as load-bearing shape signals — a transient provider
    // timeout surfacing as an Err would demote a healthy Safe to
    // "no longer looks like a Safe". Wrap them in the transient retry
    // (429s + per-request timeouts). Reverts don't match the predicate,
    // so `call_raw` probes against non-Safes still fail fast.

    async fn get_code_raw(
        &self,
        addr: Address,
        chain: Chain,
    ) -> Result<VerifiedRead<Bytes>, String> {
        with_transient_retry("get_code_raw", || self.fallback_get_code(addr, chain)).await
    }

    async fn get_storage_at_raw(
        &self,
        addr: Address,
        slot: U256,
        chain: Chain,
    ) -> Result<VerifiedRead<B256>, String> {
        with_transient_retry("get_storage_at_raw", || {
            self.fallback_get_storage_at(addr, slot, chain)
        })
        .await
    }

    async fn call_raw(
        &self,
        to: Address,
        data: Bytes,
        chain: Chain,
    ) -> Result<VerifiedRead<Bytes>, String> {
        with_transient_retry("call_raw", || self.fallback_call(to, data.clone(), chain)).await
    }
}

impl NetworkClient {
    /// Plain `eth_getCode` against the chosen exec RPC. The
    /// `verified=false` flag in the returned `VerifiedRead` lets the
    /// clear-signing UI surface "unverified bytecode" without affecting
    /// the global balance verification badge.
    ///
    /// Log/error wording on this and the other `fallback_*` methods says
    /// "raw-rpc", not "fallback": these are also the *primary* path for
    /// the `*_raw` entry points (Safe scan / Transaction-Service reads),
    /// where nothing fell back because helios was never tried.
    async fn fallback_get_code(
        &self,
        addr: Address,
        chain: Chain,
    ) -> Result<VerifiedRead<Bytes>, String> {
        let provider = self.raw_provider(chain)?;
        provider
            .get_code_at(addr)
            .await
            .map(|value| VerifiedRead {
                value,
                verified: false,
            })
            .map_err(|e| {
                let msg = redact_urls(&e.to_string());
                debug!(
                    chain = %chain.label(),
                    addr = %short_address(addr),
                    error = %msg,
                    "raw-rpc get_code failed",
                );
                msg
            })
    }

    async fn fallback_get_storage_at(
        &self,
        addr: Address,
        slot: U256,
        chain: Chain,
    ) -> Result<VerifiedRead<B256>, String> {
        let provider = self.raw_provider(chain)?;
        provider
            .get_storage_at(addr, slot)
            .await
            .map(|raw| VerifiedRead {
                value: B256::from(raw),
                verified: false,
            })
            .map_err(|e| {
                let msg = redact_urls(&e.to_string());
                debug!(
                    chain = %chain.label(),
                    addr = %short_address(addr),
                    error = %msg,
                    "raw-rpc get_storage_at failed",
                );
                msg
            })
    }

    /// Plain `eth_call` against the chosen exec RPC. The `verified=false`
    /// flag in the returned `VerifiedRead` lets clear-signing surface
    /// "metadata read couldn't be verified" — symbol/decimals ARE
    /// inert metadata the user reviews, but a deliberately-misnaming
    /// attacker would happily flip "ScamToken" to "USDC" if we trusted
    /// an unverified return blindly. The flag lets the UI flag that
    /// gap; the symbol still renders, just with a warning attached.
    async fn fallback_call(
        &self,
        to: Address,
        data: Bytes,
        chain: Chain,
    ) -> Result<VerifiedRead<Bytes>, String> {
        let provider = self.raw_provider(chain)?;
        let req = alloy::rpc::types::TransactionRequest::default()
            .to(to)
            .input(alloy::rpc::types::TransactionInput::new(data));
        provider
            .call(req)
            .await
            .map(|value| VerifiedRead {
                value,
                verified: false,
            })
            .map_err(|e| {
                let msg = redact_urls(&e.to_string());
                // Reverts land here too — the Safe scan *probes*
                // addresses with `call_raw`, so a revert on a non-Safe
                // is expected control flow, hence debug, not warn.
                debug!(
                    chain = %chain.label(),
                    addr = %short_address(to),
                    error = %msg,
                    "raw-rpc call failed",
                );
                msg
            })
    }

    async fn fallback_get_balance_raw(
        &self,
        addr: Address,
        chain: Chain,
    ) -> Result<VerifiedRead<U256>, String> {
        let provider = self.raw_provider(chain)?;
        provider
            .get_balance(addr)
            .await
            .map(|value| VerifiedRead {
                value,
                verified: false,
            })
            .map_err(|e| {
                let msg = redact_urls(&e.to_string());
                debug!(
                    chain = %chain.label(),
                    addr = %short_address(addr),
                    error = %msg,
                    "raw-rpc get_balance failed",
                );
                msg
            })
    }

    async fn fallback_get_transaction_count(
        &self,
        addr: Address,
        chain: Chain,
    ) -> Result<VerifiedRead<u64>, String> {
        let provider = self.raw_provider(chain)?;
        // Default selector is `latest` — matches the verified path
        // above. `.pending()` would mismatch the simulation block and
        // race the broadcast path's pending lookup.
        provider
            .get_transaction_count(addr)
            .await
            .map(|value| VerifiedRead {
                value,
                verified: false,
            })
            .map_err(|e| {
                let msg = redact_urls(&e.to_string());
                debug!(
                    chain = %chain.label(),
                    addr = %short_address(addr),
                    error = %msg,
                    "raw-rpc get_transaction_count failed",
                );
                msg
            })
    }

    async fn fallback_latest_block(
        &self,
        chain: Chain,
    ) -> Result<VerifiedRead<LatestBlock>, String> {
        let provider = self.raw_provider(chain)?;
        let block = provider
            .get_block(alloy::eips::BlockId::latest())
            .await
            .map_err(|e| {
                let msg = redact_urls(&e.to_string());
                debug!(
                    chain = %chain.label(),
                    error = %msg,
                    "raw-rpc latest_block failed",
                );
                msg
            })?
            .ok_or_else(|| format!("no latest block on {}", chain.label()))?;
        // alloy 2.x's `Block.header` is the same `Header<H>` shape as
        // alloy 1.x (header struct lives in `alloy-consensus`, which
        // shares the same primitives crate across major versions), so
        // the helper takes the wire-shape from either path.
        let header = LatestBlock {
            number: block.header.inner.number,
            hash: block.header.hash,
            timestamp: block.header.inner.timestamp,
            gas_limit: block.header.inner.gas_limit,
            base_fee_per_gas: block.header.inner.base_fee_per_gas.unwrap_or(0),
            prevrandao: block.header.inner.mix_hash,
            beneficiary: block.header.inner.beneficiary,
            excess_blob_gas: block.header.inner.excess_blob_gas,
        };
        Ok(VerifiedRead {
            value: header,
            verified: false,
        })
    }

    /// Plain `eth_getBalance` against the chosen exec RPC. No proof, no
    /// verification — used during the cooldown window after a helios
    /// failure.
    async fn fallback_balance(&self, addr: Address, chain: Chain) -> Result<String, String> {
        let provider = match self.raw_provider(chain) {
            Ok(p) => p,
            Err(e) => {
                self.set_status(chain, VerificationStatus::Unavailable);
                return Err(e);
            }
        };
        match provider.get_balance(addr).await {
            Ok(raw) => {
                self.set_status(chain, VerificationStatus::Fallback);
                Ok(alloy::primitives::utils::format_ether(raw))
            }
            Err(e) => {
                self.set_status(chain, VerificationStatus::Unavailable);
                let msg = redact_urls(&e.to_string());
                // warn, not debug: both helios AND the raw path are now
                // down — the user is looking at the `Unavailable` badge,
                // so this is the log line that explains it.
                warn!(
                    chain = %chain.label(),
                    addr = %short_address(addr),
                    error = %msg,
                    "raw-rpc balance failed; chain unavailable",
                );
                Err(msg)
            }
        }
    }
}

/// Flatten an alloy-1 RPC `Header` (used by both Helios and the raw
/// fallback's deserialized response) into our network-agnostic
/// `LatestBlock`. Pre-merge blocks have no base fee and no prevrandao;
/// for Kao's send-flow simulator both default to zero — the wallet
/// won't ship a tx against a pre-London chain, but defaulting is
/// cheaper than threading an extra error case through the trait.
fn latest_from_rpc_header(header: &alloy_rpc_types_eth::Header) -> LatestBlock {
    LatestBlock {
        number: header.inner.number,
        hash: header.hash,
        timestamp: header.inner.timestamp,
        gas_limit: header.inner.gas_limit,
        base_fee_per_gas: header.inner.base_fee_per_gas.unwrap_or(0),
        prevrandao: header.inner.mix_hash,
        beneficiary: header.inner.beneficiary,
        excess_blob_gas: header.inner.excess_blob_gas,
    }
}

/// Scrub every absolute URL in `s` down to `scheme://host/…`.
///
/// Alloy transport errors `Display` the full request URL (reqwest's
/// `… for url (https://host/path?query)` form), and RPC providers
/// routinely put the API key in the path (Alchemy, Infura) or query
/// string (dRPC). Logging `{e}` verbatim — or threading `e.to_string()`
/// into a UI-visible error — would leak the key. Keeping the host
/// preserves the "which upstream failed" signal without the credential.
/// The same discipline as `indexer::redact_url_in_err`, but applied to
/// already-formatted strings since alloy's error types don't expose a
/// `without_url()`.
pub(crate) fn redact_urls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find("://") {
        // Back up over the scheme (https, wss, …).
        let scheme_start = rest[..pos]
            .rfind(|c: char| !c.is_ascii_alphanumeric() && c != '+' && c != '-' && c != '.')
            .map(|i| i + 1)
            .unwrap_or(0);
        out.push_str(&rest[..scheme_start]);
        let after = &rest[pos + 3..];
        let host_end = after
            .find(|c: char| {
                c == '/'
                    || c == '?'
                    || c == '#'
                    || c == ')'
                    || c == '"'
                    || c == '\''
                    || c.is_whitespace()
            })
            .unwrap_or(after.len());
        out.push_str(&rest[scheme_start..pos + 3 + host_end]);
        // Drop the path/query/fragment up to a natural terminator.
        let tail = &after[host_end..];
        let drop_end = tail
            .find(|c: char| c == ')' || c == '"' || c == '\'' || c.is_whitespace())
            .unwrap_or(tail.len());
        if drop_end > 0 {
            out.push_str("/…");
        }
        rest = &tail[drop_end..];
    }
    out.push_str(rest);
    out
}

fn build_fallback(url: &str) -> Option<RootProvider<Ethereum>> {
    match url::Url::parse(url) {
        Ok(u) => Some(provider_for_url(u)),
        Err(e) => {
            // The unparsable input may still contain a key fragment —
            // scrub what we can rather than echoing it verbatim.
            error!(url = %redact_urls(url), error = %e, "cannot build raw provider");
            None
        }
    }
}

/// Build a raw `RootProvider` for `u`, bypassing the process-wide SOCKS proxy
/// when (and only when) the destination is loopback.
///
/// A custom network may point at a local node (`http://127.0.0.1:8545`). When
/// the user has a proxy enabled (`ALL_PROXY`, e.g. Tor), a *remote* proxy can't
/// reach the user's own loopback, so a default client — which inherits
/// `ALL_PROXY` — would send the request to the proxy and never reach the node.
/// Loopback traffic also never leaves the machine, so there is nothing to
/// anonymize by proxying it. We therefore give loopback providers a reqwest
/// client with `.no_proxy()` (direct), while every non-loopback destination
/// keeps the proxied default client unchanged — so no public/remote RPC can
/// ever slip past the proxy.
fn provider_for_url(u: url::Url) -> RootProvider<Ethereum> {
    if is_loopback_host(u.host_str()) {
        // `.no_proxy()` opts this client out of `ALL_PROXY`/`NO_PROXY` env
        // detection entirely — a genuinely direct connection to loopback.
        //
        // Built from alloy's *re-exported* reqwest, not the crate's direct
        // `reqwest` dependency: alloy 2.0.1 resolves its own (newer) reqwest,
        // and `new_http_with_client` wants a `Client` of that version. Using
        // the bare `reqwest::Client` here would be a different type.
        let client = alloy::transports::http::reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("reqwest client with no_proxy cannot fail to build");
        // `new_http_with_client` is `new_http` with a caller-supplied client:
        // same transport/`is_local` wiring, just not the default proxied one.
        RootProvider::<Ethereum>::new(RpcClient::new_http_with_client(client, u))
    } else {
        RootProvider::<Ethereum>::new_http(u)
    }
}

/// True for the hosts that must never be proxied: `localhost`, the whole IPv4
/// loopback block (`127.0.0.0/8`, via [`IpAddr::is_loopback`]), and IPv6 `::1`.
/// Matching is on the host as written in the URL (`url` strips the `[]` from an
/// IPv6 literal in `host_str`, but we strip defensively in case a caller passes
/// a bracketed form). Deliberately loopback-only: LAN/RFC1918 hosts stay
/// proxied so a wallet never reveals itself to the local network unprompted.
fn is_loopback_host(host: Option<&str>) -> bool {
    match host {
        Some(h) => {
            let h = h
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(h);
            h.eq_ignore_ascii_case("localhost")
                || h.parse::<std::net::IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false)
        }
        None => false,
    }
}

fn current_snapshot(chain: Chain) -> ConfigSnapshot {
    ConfigSnapshot {
        rpcs: settings::rpcs(chain),
        consensus_rpcs: settings::consensus_rpcs(chain),
        // Mainnet uses the user's checkpoint override (or the auto-resolved
        // fallback); L2 chains have no checkpoint concept in helios-opstack.
        checkpoint: matches!(chain, Chain::Mainnet)
            .then(|| settings::checkpoint_override().unwrap_or_else(settings::auto_checkpoint)),
    }
}

fn pick_rpc(rpcs: &[String]) -> String {
    let mut rng = rand::thread_rng();
    rpcs.choose(&mut rng).cloned().unwrap_or_default()
}

fn shuffled(rpcs: &[String]) -> Vec<String> {
    let mut out: Vec<String> = rpcs.to_vec();
    out.shuffle(&mut rand::thread_rng());
    out
}

/// Try each consensus RPC in order; return the first client that builds
/// AND passes `wait_synced`. Aggregates per-endpoint errors so the user
/// can see which ones failed and why. Dispatches to the Ethereum or
/// OP-Stack builder based on `chain`.
async fn build_backend_with_consensus_fallback(
    chain: Chain,
    execution_rpc: &str,
    consensus_rpcs: &[String],
    snap: &ConfigSnapshot,
) -> Result<HeliosBackend, String> {
    let mut errors: Vec<String> = Vec::new();
    for cl in consensus_rpcs {
        let result = match chain {
            Chain::Mainnet => build_eth_backend(execution_rpc, cl, snap).await,
            Chain::Base | Chain::Optimism => build_op_backend(chain, execution_rpc, cl).await,
        };
        match result {
            Ok(backend) => {
                if !errors.is_empty() {
                    info!(
                        chain = %chain.label(),
                        consensus_rpc = %redact_urls(cl),
                        prior_failures = errors.len(),
                        "consensus rpc succeeded after prior failures",
                    );
                }
                return Ok(backend);
            }
            Err(e) => {
                let msg = redact_urls(&e);
                warn!(chain = %chain.label(), consensus_rpc = %redact_urls(cl), error = %msg, "consensus rpc failed");
                // The aggregate bubbles into a UI-visible error string,
                // so the per-endpoint URL is scrubbed there too.
                errors.push(format!("{}: {}", redact_urls(cl), msg));
            }
        }
    }
    Err(format!(
        "all {} consensus RPC(s) failed for {}:\n  - {}",
        errors.len(),
        chain.label(),
        errors.join("\n  - ")
    ))
}

async fn build_eth_backend(
    execution_rpc: &str,
    consensus_rpc: &str,
    snap: &ConfigSnapshot,
) -> Result<HeliosBackend, String> {
    let checkpoint = snap
        .checkpoint
        .ok_or_else(|| "mainnet build missing checkpoint".to_string())?;
    let client = EthereumClientBuilder::new()
        .network(EthNetwork::Mainnet)
        .execution_rpc(execution_rpc)
        .map_err(|e| e.to_string())?
        .consensus_rpc(consensus_rpc)
        .map_err(|e| e.to_string())?
        .checkpoint(checkpoint)
        .load_external_fallback()
        .data_dir(crate::paths::data_dir().join("helios"))
        .with_file_db()
        .build()
        .map_err(|e| e.to_string())?;
    client.wait_synced().await.map_err(|e| e.to_string())?;
    let backend = HeliosBackend::Eth(Arc::new(client));
    wait_for_head(&backend).await?;
    Ok(backend)
}

async fn build_op_backend(
    chain: Chain,
    execution_rpc: &str,
    consensus_rpc: &str,
) -> Result<HeliosBackend, String> {
    let op_network = match chain {
        Chain::Base => OpNetwork::Base,
        Chain::Optimism => OpNetwork::OpMainnet,
        Chain::Mainnet => unreachable!("build_op_backend only handles L2 chains"),
    };
    // OpStackClientBuilder's `.execution_rpc(...)` / `.consensus_rpc(...)`
    // panic on URL parse failure inside the helios crate. Pre-parse here
    // so a malformed URL surfaces as a Result error, not an abort.
    let exec_url = url::Url::parse(execution_rpc).map_err(|e| format!("execution rpc url: {e}"))?;
    let consensus_url =
        url::Url::parse(consensus_rpc).map_err(|e| format!("consensus rpc url: {e}"))?;
    let client = OpStackClientBuilder::new()
        .network(op_network)
        .execution_rpc(exec_url)
        .consensus_rpc(consensus_url)
        // verify_unsafe_signer=false matches helios's default. Each
        // Network preset already ships a hardcoded sequencer signer key;
        // surfacing a runtime override would force the user to make a
        // P2P-trust decision they can't really act on.
        .verify_unsafe_signer(false)
        .build()
        .map_err(|e| e.to_string())?;
    client.wait_synced().await.map_err(|e| e.to_string())?;
    let backend = HeliosBackend::Op(Arc::new(client));
    wait_for_head(&backend).await?;
    Ok(backend)
}

/// `wait_synced()` returns once the consensus client has bootstrapped
/// and processed its first update, but the execution payload may not
/// have arrived yet — `helios::core::Node::check_head_age` returns
/// `OutOfSync(now)` when `execution.get_block(Latest)` is `None`. The
/// basic example sleeps 15s; we poll with a timeout so balance fetches
/// don't fail with a misleading "out of sync: 1.7B seconds behind" the
/// moment the dashboard opens.
async fn wait_for_head(backend: &HeliosBackend) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut delay_ms: u64 = 250;
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match backend.get_block_number().await {
            Ok(n) => {
                debug!(attempt, block = %n, "head ready");
                return Ok(());
            }
            Err(s) => {
                if !s.contains("out of sync") {
                    return Err(format!("waiting for head: {s}"));
                }
                if Instant::now() >= deadline {
                    return Err(format!(
                        "timed out waiting for execution head ({attempt} polls): {s}"
                    ));
                }
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                delay_ms = (delay_ms.saturating_mul(2)).min(2000);
            }
        }
    }
}

/// Stub `BalanceFetcher` for tests. Returns "0" for every address on
/// every chain and is a no-op on `invalidate`. The dashboard's
/// verification badge is sampled directly from `last_status` (which
/// `MockFetcher` pins to `Verified`), so screen tests don't need to
/// drive any balance-fetched message to update it.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct MockFetcher;

#[cfg(test)]
impl MockFetcher {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
#[async_trait]
impl BalanceFetcher for MockFetcher {
    async fn balance(&self, _addr: Address, _chain: Chain) -> Result<String, String> {
        Ok("0".into())
    }

    async fn invalidate(&self) {}

    fn last_status(&self, _chain: Chain) -> VerificationStatus {
        VerificationStatus::Verified
    }

    async fn provider(&self, _chain: Chain) -> Option<RootProvider<Ethereum>> {
        None
    }

    async fn get_code(&self, _addr: Address, _chain: Chain) -> Result<VerifiedRead<Bytes>, String> {
        Ok(VerifiedRead {
            value: Bytes::new(),
            verified: true,
        })
    }

    async fn get_storage_at(
        &self,
        _addr: Address,
        _slot: U256,
        _chain: Chain,
    ) -> Result<VerifiedRead<B256>, String> {
        Ok(VerifiedRead {
            value: B256::ZERO,
            verified: true,
        })
    }

    async fn call(
        &self,
        _to: Address,
        _data: Bytes,
        _chain: Chain,
    ) -> Result<VerifiedRead<Bytes>, String> {
        Ok(VerifiedRead {
            value: Bytes::new(),
            verified: true,
        })
    }

    async fn get_balance_raw(
        &self,
        _addr: Address,
        _chain: Chain,
    ) -> Result<VerifiedRead<U256>, String> {
        Ok(VerifiedRead {
            value: U256::ZERO,
            verified: true,
        })
    }

    async fn get_transaction_count(
        &self,
        _addr: Address,
        _chain: Chain,
    ) -> Result<VerifiedRead<u64>, String> {
        Ok(VerifiedRead {
            value: 0,
            verified: true,
        })
    }

    async fn latest_block(&self, _chain: Chain) -> Result<VerifiedRead<LatestBlock>, String> {
        Ok(VerifiedRead {
            value: LatestBlock {
                number: 0,
                hash: B256::ZERO,
                timestamp: 0,
                gas_limit: 30_000_000,
                base_fee_per_gas: 0,
                prevrandao: B256::ZERO,
                beneficiary: Address::ZERO,
                excess_blob_gas: None,
            },
            verified: true,
        })
    }

    async fn get_code_raw(
        &self,
        addr: Address,
        chain: Chain,
    ) -> Result<VerifiedRead<Bytes>, String> {
        self.get_code(addr, chain).await
    }

    async fn get_storage_at_raw(
        &self,
        addr: Address,
        slot: U256,
        chain: Chain,
    ) -> Result<VerifiedRead<B256>, String> {
        self.get_storage_at(addr, slot, chain).await
    }

    async fn call_raw(
        &self,
        to: Address,
        data: Bytes,
        chain: Chain,
    ) -> Result<VerifiedRead<Bytes>, String> {
        self.call(to, data, chain).await
    }
}

/// Parameterizable test double for `BalanceFetcher`. Modelled on
/// `decode::proxy::StorageMock` but adds per-(target, calldata) responses
/// for `call()` and per-address responses for `get_code()`. Used by
/// `decode::render` tests to drive the verified `eth_call` path without
/// standing up a real Helios client.
///
/// All methods return degenerate values for inputs that weren't pre-
/// loaded — that matches `MockFetcher`'s contract and keeps unrelated
/// tests reading off the configured surface only.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct CallMock {
    calls: std::sync::Mutex<std::collections::HashMap<(Address, Bytes), (Bytes, bool)>>,
    code: std::sync::Mutex<std::collections::HashMap<Address, (Bytes, bool)>>,
    storage: std::sync::Mutex<std::collections::HashMap<(Address, B256), (B256, bool)>>,
}

#[cfg(test)]
impl CallMock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-load a response for `eth_call(to, calldata)`.
    pub fn set_call(&self, to: Address, calldata: Bytes, ret: Bytes, verified: bool) {
        self.calls
            .lock()
            .unwrap()
            .insert((to, calldata), (ret, verified));
    }

    pub fn set_code(&self, addr: Address, code: Bytes, verified: bool) {
        self.code.lock().unwrap().insert(addr, (code, verified));
    }

    #[allow(dead_code)]
    pub fn set_storage(&self, addr: Address, slot: B256, value: B256, verified: bool) {
        self.storage
            .lock()
            .unwrap()
            .insert((addr, slot), (value, verified));
    }
}

#[cfg(test)]
#[async_trait]
impl BalanceFetcher for CallMock {
    async fn balance(&self, _: Address, _: Chain) -> Result<String, String> {
        Ok("0".into())
    }
    async fn invalidate(&self) {}
    fn last_status(&self, _: Chain) -> VerificationStatus {
        VerificationStatus::Verified
    }
    async fn provider(&self, _: Chain) -> Option<RootProvider<Ethereum>> {
        None
    }
    async fn get_code(&self, addr: Address, _: Chain) -> Result<VerifiedRead<Bytes>, String> {
        let (value, verified) = self
            .code
            .lock()
            .unwrap()
            .get(&addr)
            .cloned()
            .unwrap_or((Bytes::new(), true));
        Ok(VerifiedRead { value, verified })
    }
    async fn get_storage_at(
        &self,
        addr: Address,
        slot: U256,
        _: Chain,
    ) -> Result<VerifiedRead<B256>, String> {
        let slot_b256 = B256::from(slot.to_be_bytes::<32>());
        let (value, verified) = self
            .storage
            .lock()
            .unwrap()
            .get(&(addr, slot_b256))
            .copied()
            .unwrap_or((B256::ZERO, true));
        Ok(VerifiedRead { value, verified })
    }
    async fn call(
        &self,
        to: Address,
        data: Bytes,
        _: Chain,
    ) -> Result<VerifiedRead<Bytes>, String> {
        let (value, verified) = self
            .calls
            .lock()
            .unwrap()
            .get(&(to, data))
            .cloned()
            .unwrap_or((Bytes::new(), true));
        Ok(VerifiedRead { value, verified })
    }
    async fn get_balance_raw(&self, _: Address, _: Chain) -> Result<VerifiedRead<U256>, String> {
        Ok(VerifiedRead {
            value: U256::ZERO,
            verified: true,
        })
    }
    async fn get_transaction_count(
        &self,
        _: Address,
        _: Chain,
    ) -> Result<VerifiedRead<u64>, String> {
        Ok(VerifiedRead {
            value: 0,
            verified: true,
        })
    }
    async fn latest_block(&self, _: Chain) -> Result<VerifiedRead<LatestBlock>, String> {
        Ok(VerifiedRead {
            value: LatestBlock {
                number: 0,
                hash: B256::ZERO,
                timestamp: 0,
                gas_limit: 30_000_000,
                base_fee_per_gas: 0,
                prevrandao: B256::ZERO,
                beneficiary: Address::ZERO,
                excess_blob_gas: None,
            },
            verified: true,
        })
    }
    async fn get_code_raw(
        &self,
        addr: Address,
        chain: Chain,
    ) -> Result<VerifiedRead<Bytes>, String> {
        self.get_code(addr, chain).await
    }
    async fn get_storage_at_raw(
        &self,
        addr: Address,
        slot: U256,
        chain: Chain,
    ) -> Result<VerifiedRead<B256>, String> {
        self.get_storage_at(addr, slot, chain).await
    }
    async fn call_raw(
        &self,
        to: Address,
        data: Bytes,
        chain: Chain,
    ) -> Result<VerifiedRead<Bytes>, String> {
        self.call(to, data, chain).await
    }
}

/// Build a reqwest client that routes through `proxy` (a SOCKS5 `host:port`)
/// when `Some`, or connects directly when `None`. `socks5h://` keeps DNS
/// resolution on the proxy side so the destination hostname never leaks to
/// the local resolver.
///
/// Timeouts are deliberately tight: the checkpoint refresh queries providers
/// one at a time, and the bundled set routinely contains dead-but-still-listed
/// endpoints. A short `connect_timeout` makes an unreachable host fail fast
/// instead of hanging until the read timeout, and a short overall `timeout`
/// caps how long one slow service can stall the refresh before we move to the
/// next. Tor needs more room to build a circuit, so the proxied path gets a
/// longer budget.
fn proxy_http_client(proxy: Option<&str>) -> Result<reqwest::Client, String> {
    let proxied = proxy.map(str::trim).filter(|a| !a.is_empty());
    let (req_timeout, connect_timeout) = if proxied.is_some() {
        (Duration::from_secs(20), Duration::from_secs(10))
    } else {
        (Duration::from_secs(5), Duration::from_secs(3))
    };
    debug!(
        proxied = proxied.is_some(),
        req_timeout_s = req_timeout.as_secs(),
        connect_timeout_s = connect_timeout.as_secs(),
        "checkpoint refresh: building http client"
    );
    let mut builder = reqwest::Client::builder()
        .timeout(req_timeout)
        .connect_timeout(connect_timeout)
        .user_agent(concat!("kao/", env!("CARGO_PKG_VERSION")));
    match proxied {
        Some(addr) => {
            // An explicit proxy also disables reqwest's env-proxy detection,
            // so the draft address is the only thing this client honours.
            let p = reqwest::Proxy::all(format!("socks5h://{addr}"))
                .map_err(|e| format!("invalid proxy address: {e}"))?;
            builder = builder.proxy(p);
        }
        None => {
            // The manual refresh tests the *draft* proxy choice in isolation.
            // With no draft proxy we want a genuinely direct client — force it,
            // so it doesn't silently inherit a persisted `ALL_PROXY` installed
            // process-wide at startup.
            builder = builder.no_proxy();
        }
    }
    builder
        .build()
        .map_err(|e| format!("HTTP client build failed: {e}"))
}

/// Fetch the latest **mainnet** checkpoint, routing every request through
/// `proxy` (a SOCKS5 `host:port`) when set.
///
/// Helios's own [`CheckpointFallback`] builds a fixed reqwest client with no
/// proxy support and pulls its service list from GitHub (often blocked), so we
/// reimplement the discovery against a bundled set of well-known checkpoint
/// providers ([`CHECKPOINT_ENDPOINTS`]): query them one at a time until enough
/// have answered (some are dead at any time), then return the block root those
/// services agree on at the newest epoch. L2 chains have no checkpoint concept,
/// so this is mainnet only.
pub async fn fetch_latest_checkpoint(proxy: Option<String>) -> Result<B256, String> {
    let start = Instant::now();
    info!(
        via_proxy = proxy.is_some(),
        proxy = proxy.as_deref().unwrap_or("(direct)"),
        "checkpoint refresh: starting"
    );
    let result = fetch_checkpoint_via(proxy.as_deref()).await;
    let elapsed_ms = start.elapsed().as_millis();
    match &result {
        Ok(cp) => info!(checkpoint = %cp, elapsed_ms, "checkpoint refresh: resolved"),
        Err(e) => warn!(error = %e, elapsed_ms, "checkpoint refresh: failed"),
    }
    result
}

async fn fetch_checkpoint_via(proxy: Option<&str>) -> Result<B256, String> {
    let client = proxy_http_client(proxy)?;

    // 1. Use the bundled provider set directly. (Helios discovers these from a
    //    GitHub-hosted list, but that host is frequently blocked, so we skip it
    //    and query the providers straight away.)
    let endpoints = checkpoint_endpoints();
    info!(
        endpoints = endpoints.len(),
        "checkpoint refresh: querying services"
    );

    // 2. Query providers one at a time, in order, stopping as soon as `ENOUGH`
    //    have answered. Sequential (rather than a concurrent fan-out) so we
    //    don't hit every provider at once; per-request timeouts bound how long
    //    a dead one stalls us before moving to the next.
    const ENOUGH: usize = 5;
    let mut queried = 0usize;
    let mut slots = Vec::with_capacity(ENOUGH);
    for endpoint in &endpoints {
        queried += 1;
        if let Some(slot) = query_checkpoint_slot(&client, endpoint).await {
            slots.push(slot);
            if slots.len() >= ENOUGH {
                break;
            }
        }
    }
    info!(
        responded = slots.len(),
        queried, "checkpoint refresh: collected slots"
    );

    // 3. Take the block root the most services agree on at the newest epoch.
    let (root, epoch, agreement) = resolve_checkpoint(&slots)?;
    info!(
        epoch,
        agreement,
        of = slots.len(),
        "checkpoint refresh: tallied agreement"
    );
    Ok(root)
}

/// Query one checkpoint provider for its latest rooted slot. Returns `None`
/// (and logs why at debug) on request error, decode error, or a response with
/// no rooted slot, so the caller can simply move on to the next provider.
async fn query_checkpoint_slot(client: &reqwest::Client, endpoint: &url::Url) -> Option<Slot> {
    use helios_ethereum::config::checkpoints::RawSlotResponse;

    let name = endpoint.host_str().unwrap_or("?");
    let url = CheckpointFallback::construct_url(endpoint);
    let resp = match client.get(url.as_str()).send().await {
        Ok(resp) => resp,
        Err(e) => {
            debug!(
                service = %name,
                error = %crate::indexer::redact_url_in_err(e),
                "checkpoint refresh: service request failed"
            );
            return None;
        }
    };
    let raw: RawSlotResponse = match resp.json().await {
        Ok(raw) => raw,
        Err(e) => {
            debug!(
                service = %name,
                error = %crate::indexer::redact_url_in_err(e),
                "checkpoint refresh: service decode failed"
            );
            return None;
        }
    };
    let slot = raw
        .data
        .slots
        .into_iter()
        .find(|slot| slot.block_root.is_some());
    match &slot {
        Some(s) => debug!(
            service = %name,
            epoch = s.epoch,
            "checkpoint refresh: service responded"
        ),
        None => debug!(
            service = %name,
            "checkpoint refresh: service returned no rooted slot"
        ),
    }
    slot
}

/// Well-known mainnet checkpoint-sync providers we query directly.
///
/// Helios discovers these from a GitHub-hosted community list, but that host
/// is frequently blocked, so we bundle the providers instead. Any that are
/// dead simply drop out of the consensus tally, and the checkpoint is only a
/// bootstrap hint that Helios re-verifies on sync.
///
/// Mirrors the full mainnet set from the community list as of 2026-06; all
/// nine were verified live (HTTP 200 on `…/checkpointz/v1/beacon/slots`).
const CHECKPOINT_ENDPOINTS: &[&str] = &[
    "https://sync-mainnet.beaconcha.in",
    "https://beaconstate.info",
    "https://sync.invis.tools",
    "https://beaconstate.ethstaker.cc",
    "https://checkpointz.pietjepuk.net",
    "https://mainnet-checkpoint-sync.stakely.io",
    "https://mainnet.checkpoint.sigp.io",
    "https://mainnet-checkpoint-sync.attestant.io",
    "https://beaconstate-mainnet.chainsafe.io",
];

fn checkpoint_endpoints() -> Vec<url::Url> {
    CHECKPOINT_ENDPOINTS
        .iter()
        .filter_map(|u| url::Url::parse(u).ok())
        .collect()
}

/// From the latest slots gathered across checkpoint services, pick the block
/// root the most services agree on at the **newest** epoch. Returns the
/// chosen root with that epoch and the agreement count (how many services
/// reported it) for logging.
///
/// This deliberately mirrors Helios's own `fetch_latest_checkpoint_from_services`
/// (max epoch, then most-common root at that epoch) — agreement of 1 is normal
/// and expected, *not* a failure: each service reports its own latest head slot
/// via `find(block_root.is_some())`, and because they poll at slightly different
/// times they routinely land on different epochs, so the newest one is usually a
/// lone reporter. Requiring corroboration here would reject nearly every real
/// refresh. The checkpoint is only a weak-subjectivity bootstrap hint that
/// Helios re-verifies on sync — a forged root can't fabricate state, it just
/// fails to bootstrap — so trusting the newest single source is acceptable.
///
/// Slots without a block root are ignored entirely — including when deciding
/// the newest epoch, so a service that reports a higher epoch but no root
/// can't blank out the result.
fn resolve_checkpoint(slots: &[Slot]) -> Result<(B256, u64, usize), String> {
    let max_epoch = slots
        .iter()
        .filter(|s| s.block_root.is_some())
        .map(|s| s.epoch)
        .max()
        .ok_or_else(|| "no healthy checkpoint service responded".to_string())?;
    let mut tally: std::collections::HashMap<B256, usize> = std::collections::HashMap::new();
    for slot in slots.iter().filter(|s| s.epoch == max_epoch) {
        if let Some(root) = slot.block_root {
            *tally.entry(root).or_default() += 1;
        }
    }
    tally
        .into_iter()
        .max_by_key(|(_, n)| *n)
        .map(|(root, n)| (root, max_epoch, n))
        .ok_or_else(|| "no checkpoint agreed on".to_string())
}

#[cfg(test)]
mod pure_tests {
    use super::*;

    #[test]
    fn verification_status_round_trip() {
        for s in [
            VerificationStatus::Connecting,
            VerificationStatus::Verified,
            VerificationStatus::Fallback,
            VerificationStatus::Unavailable,
        ] {
            assert_eq!(VerificationStatus::from_u8(s.as_u8()), s);
        }
    }

    #[test]
    fn verification_status_from_u8_unknown_defaults_to_connecting() {
        assert_eq!(
            VerificationStatus::from_u8(0),
            VerificationStatus::Connecting
        );
        assert_eq!(
            VerificationStatus::from_u8(99),
            VerificationStatus::Connecting
        );
        assert_eq!(
            VerificationStatus::from_u8(u8::MAX),
            VerificationStatus::Connecting
        );
    }

    #[test]
    fn build_fallback_valid_url_is_some() {
        assert!(build_fallback("https://example.com").is_some());
        assert!(build_fallback("http://127.0.0.1:8545").is_some());
    }

    #[test]
    fn build_fallback_invalid_url_is_none() {
        assert!(build_fallback("not a url").is_none());
        assert!(build_fallback("").is_none());
    }

    #[test]
    fn pick_rpc_empty_returns_empty_string() {
        assert_eq!(pick_rpc(&[]), "");
    }

    #[test]
    fn pick_rpc_single_entry_always_returned() {
        for _ in 0..10 {
            assert_eq!(pick_rpc(&["only".into()]), "only");
        }
    }

    #[test]
    fn pick_rpc_picks_a_member() {
        let pool = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        for _ in 0..50 {
            let pick = pick_rpc(&pool);
            assert!(pool.iter().any(|p| p == &pick));
        }
    }

    #[test]
    fn shuffled_is_permutation() {
        let input: Vec<String> = (0..8).map(|i| format!("rpc{i}")).collect();
        let out = shuffled(&input);
        assert_eq!(out.len(), input.len());
        let mut a = input.clone();
        let mut b = out.clone();
        a.sort();
        b.sort();
        assert_eq!(a, b);
    }

    #[test]
    fn shuffled_empty_is_empty() {
        assert!(shuffled(&[]).is_empty());
    }

    #[test]
    fn latest_from_rpc_header_flattens_fields() {
        // The Header type is `alloy_rpc_types_eth::Header` from alloy v1,
        // whose `inner` is alloy_consensus v1's `Header` (different crate
        // version from alloy 2.x's `alloy::consensus::Header`). We
        // construct via Default::default() and patch the fields we care
        // about — their numeric/byte types come from alloy_primitives,
        // which is a single version across the graph.
        let mut header: alloy_rpc_types_eth::Header = alloy_rpc_types_eth::Header {
            hash: B256::from([0xbb; 32]),
            ..Default::default()
        };
        header.inner.number = 12_345;
        header.inner.gas_limit = 30_000_000;
        header.inner.timestamp = 1_700_000_000;
        header.inner.base_fee_per_gas = Some(7);
        header.inner.mix_hash = B256::from([0xaa; 32]);
        header.inner.beneficiary = Address::from([0x11; 20]);
        header.inner.excess_blob_gas = Some(42);

        let lb = latest_from_rpc_header(&header);
        assert_eq!(lb.number, 12_345);
        assert_eq!(lb.hash, B256::from([0xbb; 32]));
        assert_eq!(lb.timestamp, 1_700_000_000);
        assert_eq!(lb.gas_limit, 30_000_000);
        assert_eq!(lb.base_fee_per_gas, 7);
        assert_eq!(lb.prevrandao, B256::from([0xaa; 32]));
        assert_eq!(lb.beneficiary, Address::from([0x11; 20]));
        assert_eq!(lb.excess_blob_gas, Some(42));
    }

    #[test]
    fn latest_from_rpc_header_defaults_base_fee_to_zero() {
        let mut header: alloy_rpc_types_eth::Header = Default::default();
        header.inner.base_fee_per_gas = None;
        let lb = latest_from_rpc_header(&header);
        assert_eq!(lb.base_fee_per_gas, 0);
    }

    #[test]
    fn current_snapshot_mirrors_settings_for_each_chain() {
        for chain in Chain::ALL {
            let snap = current_snapshot(chain);
            assert_eq!(snap.rpcs, settings::rpcs(chain));
            assert_eq!(snap.consensus_rpcs, settings::consensus_rpcs(chain));
            match chain {
                Chain::Mainnet => assert!(snap.checkpoint.is_some()),
                Chain::Base | Chain::Optimism => assert!(snap.checkpoint.is_none()),
            }
        }
    }

    #[test]
    fn current_snapshot_equal_to_itself() {
        let a = current_snapshot(Chain::Mainnet);
        let b = current_snapshot(Chain::Mainnet);
        assert_eq!(a, b);
    }

    // ── cooldown / raw-state machine ─────────────────────────────────

    #[test]
    fn cooldown_starts_clear_and_flips_per_chain() {
        let net = NetworkClient::new();
        for chain in Chain::ALL {
            assert!(
                !net.in_cooldown(chain),
                "{chain}: fresh client must not start cooled down"
            );
        }
        net.start_cooldown(Chain::Base);
        assert!(net.in_cooldown(Chain::Base));
        // Per-chain isolation: a Base helios failure must not push
        // Mainnet or Optimism onto the unverified path.
        assert!(!net.in_cooldown(Chain::Mainnet));
        assert!(!net.in_cooldown(Chain::Optimism));
    }

    #[tokio::test]
    async fn invalidate_clears_cooldown_and_resets_status() {
        let net = NetworkClient::new();
        net.start_cooldown(Chain::Mainnet);
        net.set_status(Chain::Mainnet, VerificationStatus::Fallback);
        assert!(net.in_cooldown(Chain::Mainnet));
        net.invalidate().await;
        assert!(
            !net.in_cooldown(Chain::Mainnet),
            "invalidate must clear the cooldown so the next request retries helios",
        );
        for chain in Chain::ALL {
            assert_eq!(net.last_status(chain), VerificationStatus::Connecting);
        }
    }

    #[test]
    fn last_status_defaults_to_connecting_for_all_chains() {
        let net = NetworkClient::new();
        for chain in Chain::ALL {
            assert_eq!(net.last_status(chain), VerificationStatus::Connecting);
        }
    }

    #[test]
    fn raw_provider_resolves_for_mainnet_default_settings() {
        // Mainnet always has at least the seeded default RPC, so the
        // raw provider must build without a helios build ever running —
        // this is the path the Safe scan and Transaction-Service reads
        // depend on. Construction is lazy (no I/O here).
        let net = NetworkClient::new();
        assert!(net.raw_provider(Chain::Mainnet).is_ok());
        // Second resolve hits the cache and must also succeed.
        assert!(net.raw_provider(Chain::Mainnet).is_ok());
    }

    #[test]
    fn redact_urls_strips_path_and_query_keeps_host() {
        let s = "error sending request for url (https://eth-mainnet.g.alchemy.com/v2/SECRETKEY)";
        let r = redact_urls(s);
        assert!(!r.contains("SECRETKEY"), "key must be scrubbed: {r}");
        assert!(r.contains("https://eth-mainnet.g.alchemy.com/…"));
        assert!(r.ends_with(')'), "text after the URL must survive: {r}");
    }

    #[test]
    fn redact_urls_strips_query_string_keys() {
        let r = redact_urls("GET https://lb.drpc.org/ogrpc?network=ethereum&dkey=SECRET failed");
        assert!(!r.contains("SECRET"));
        assert_eq!(r, "GET https://lb.drpc.org/… failed");
    }

    #[test]
    fn redact_urls_handles_multiple_urls_and_bare_hosts() {
        let r = redact_urls("https://a.example/k1 then https://b.example then wss://c.example/k3");
        assert_eq!(
            r,
            "https://a.example/… then https://b.example then wss://c.example/…"
        );
    }

    #[test]
    fn redact_urls_no_url_is_identity() {
        assert_eq!(redact_urls("plain error, no urls"), "plain error, no urls");
        assert_eq!(redact_urls(""), "");
    }

    /// The provider-error sinks in `wallet::tx::build_quote`,
    /// `sign::broadcast::broadcast`, and `safe::tx::execute_safe_tx` route
    /// alloy transport errors through `redact_urls` before logging/returning
    /// them (findings #21/#26). Cover the exact `format!("<op>: {redacted}")`
    /// shape those sites now emit, for every key placement a configured RPC
    /// uses: Alchemy path key, dRPC path key, and dRPC query key.
    #[test]
    fn redact_urls_scrubs_provider_keys_in_op_error_strings() {
        let cases = [
            "estimate_gas: error sending request for url (https://eth-mainnet.g.alchemy.com/v2/ALCHEMY_KEY)",
            "broadcast failed: error sending request for url (https://lb.drpc.org/ogrpc/eth/DRPC_KEY)",
            "get_transaction_count: HTTP error for https://lb.drpc.org/ogrpc?network=ethereum&dkey=DRPC_KEY",
        ];
        for raw in cases {
            let r = redact_urls(raw);
            for secret in ["ALCHEMY_KEY", "DRPC_KEY"] {
                assert!(!r.contains(secret), "key leaked through redaction: {r}");
            }
            // The operation prefix (the useful signal) must survive.
            assert!(r.contains(':'), "op prefix lost: {r}");
        }
    }

    #[test]
    fn is_loopback_host_matches_every_loopback_spelling() {
        // The three forms a local-node RPC URL realistically uses, plus the
        // rest of the 127/8 block and a bracketed IPv6 literal.
        for h in [
            "localhost",
            "LOCALHOST",
            "127.0.0.1",
            "127.0.0.2",
            "::1",
            "[::1]",
        ] {
            assert!(is_loopback_host(Some(h)), "{h} should be loopback");
        }
    }

    #[test]
    fn is_loopback_host_rejects_remote_and_lan_hosts() {
        // Public hosts, LAN/RFC1918, and a missing host must stay proxied —
        // the bypass is deliberately loopback-only.
        for h in [
            "eth.example.com",
            "1.2.3.4",
            "192.168.1.10",
            "10.0.0.1",
            "0.0.0.0",
            "localhost.evil.com",
        ] {
            assert!(!is_loopback_host(Some(h)), "{h} must not be loopback");
        }
        assert!(!is_loopback_host(None));
    }

    #[test]
    fn is_loopback_host_resolves_from_url_host_str() {
        // Confirm the host extracted from a parsed URL feeds the check as
        // expected — including the IPv6 form `url` serializes with brackets.
        let local = url::Url::parse("http://127.0.0.1:8545").unwrap();
        assert!(is_loopback_host(local.host_str()));
        let local6 = url::Url::parse("http://[::1]:8545").unwrap();
        assert!(is_loopback_host(local6.host_str()));
        let remote = url::Url::parse("https://mainnet.example.com/v2/key").unwrap();
        assert!(!is_loopback_host(remote.host_str()));
    }

    #[test]
    fn verified_read_carries_value_and_flag() {
        let vr = VerifiedRead {
            value: 7u64,
            verified: true,
        };
        assert_eq!(vr.value, 7);
        assert!(vr.verified);
        let vr2 = VerifiedRead {
            value: 0u64,
            verified: false,
        };
        assert!(!vr2.verified);
    }

    /// A transient helios failure (post-sync settling, cache clear)
    /// must be absorbed by the single in-place retry instead of
    /// starting a cooldown that forces a whole simulation onto the
    /// unverified path.
    #[tokio::test]
    async fn helios_read_with_retry_recovers_after_one_transient_failure() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let out = helios_read_with_retry("test", Chain::Mainnet, || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    Err("block not found".to_string())
                } else {
                    Ok(42u32)
                }
            }
        })
        .await;
        assert_eq!(out.unwrap(), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 2, "exactly one retry");
    }

    /// Two consecutive failures surrender to the caller (which then
    /// starts the cooldown) — the combined error keeps both messages so
    /// the debug log shows whether the retry saw a different failure.
    #[tokio::test]
    async fn helios_read_with_retry_gives_up_after_second_failure() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let out: Result<u32, String> = helios_read_with_retry("test", Chain::Mainnet, || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err("boom".to_string()) }
        })
        .await;
        let err = out.unwrap_err();
        assert_eq!(err, "boom; retry: boom");
        assert_eq!(calls.load(Ordering::SeqCst), 2, "no third attempt");
    }
}

#[cfg(test)]
mod checkpoint_tests {
    use super::*;

    /// A `Slot` with just the two fields `resolve_checkpoint` reads. The rest
    /// come from `Slot`'s `Default`.
    fn slot(epoch: u64, root: Option<u8>) -> Slot {
        Slot {
            epoch,
            block_root: root.map(B256::repeat_byte),
            ..Default::default()
        }
    }

    #[test]
    fn newest_epoch_wins_over_a_more_popular_older_one() {
        // Epoch 10 has three votes, epoch 11 only one — the newer epoch still
        // wins. (Checkpoints only ever move forward, and a single service at
        // the newest epoch is the normal case, not an error.)
        let slots = [
            slot(10, Some(0xaa)),
            slot(10, Some(0xaa)),
            slot(10, Some(0xaa)),
            slot(11, Some(0xbb)),
        ];
        let (root, epoch, agreement) = resolve_checkpoint(&slots).unwrap();
        assert_eq!(epoch, 11);
        assert_eq!(root, B256::repeat_byte(0xbb));
        assert_eq!(agreement, 1);
    }

    #[test]
    fn within_the_newest_epoch_the_majority_root_wins() {
        // Two services say 0xbb, one says 0xaa, all at the same epoch.
        let slots = [
            slot(11, Some(0xaa)),
            slot(11, Some(0xbb)),
            slot(11, Some(0xbb)),
        ];
        let (root, _, agreement) = resolve_checkpoint(&slots).unwrap();
        assert_eq!(root, B256::repeat_byte(0xbb));
        assert_eq!(agreement, 2);
    }

    #[test]
    fn a_rootless_slot_at_a_higher_epoch_is_ignored() {
        // A service reporting a newer epoch but no block root must not hijack
        // `max_epoch` and blank out the result.
        let slots = [slot(11, Some(0xaa)), slot(12, None)];
        let (root, epoch, _) = resolve_checkpoint(&slots).unwrap();
        assert_eq!(epoch, 11);
        assert_eq!(root, B256::repeat_byte(0xaa));
    }

    #[test]
    fn no_slots_is_an_error() {
        assert!(resolve_checkpoint(&[]).is_err());
    }

    #[test]
    fn slots_without_any_root_is_an_error() {
        let slots = [slot(11, None), slot(12, None)];
        assert!(resolve_checkpoint(&slots).is_err());
    }

    #[test]
    fn proxy_client_builds_direct_proxied_and_treats_blank_as_direct() {
        assert!(proxy_http_client(None).is_ok(), "direct");
        assert!(proxy_http_client(Some("127.0.0.1:9050")).is_ok(), "socks5");
        // Whitespace-only is "no proxy" (direct), not an error.
        assert!(proxy_http_client(Some("   ")).is_ok(), "blank → direct");
    }

    #[test]
    fn proxy_client_rejects_an_unparseable_address() {
        // A space inside the authority makes the `socks5h://` URL invalid.
        assert!(proxy_http_client(Some("bad addr")).is_err());
    }

    #[test]
    fn checkpoint_endpoints_all_parse_and_build_slot_urls() {
        use helios_ethereum::config::checkpoints::CheckpointFallback;
        let eps = checkpoint_endpoints();
        // Every bundled entry must parse — `filter_map` would silently drop a
        // typo'd URL, so guard the count.
        assert_eq!(
            eps.len(),
            CHECKPOINT_ENDPOINTS.len(),
            "a checkpoint endpoint failed to parse"
        );
        assert!(!eps.is_empty());
        // And each must produce the canonical slots query URL.
        for ep in &eps {
            let slots = CheckpointFallback::construct_url(ep);
            assert!(
                slots.as_str().ends_with("/checkpointz/v1/beacon/slots"),
                "unexpected slot URL: {slots}"
            );
        }
    }
}
