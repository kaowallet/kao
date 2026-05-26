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
use alloy_eips::BlockId;
use async_trait::async_trait;
use rand::seq::SliceRandom;
use tokio::sync::Mutex;

use helios_ethereum::config::checkpoints::CheckpointFallback;
use helios_ethereum::config::networks::Network as EthNetwork;
use helios_ethereum::{EthereumClient, EthereumClientBuilder};
use helios_opstack::OpStackClientBuilder;
use helios_opstack::config::Network as OpNetwork;
use tracing::{debug, error, info, warn};

use crate::chain::{Chain, PerChain};
use crate::settings;
use crate::wallet::short_address;

/// How recently does a helios failure have to be for us to skip helios on
/// the next request? Matches kohaku-extension's `FALLBACK_COOLDOWN_MS`.
/// Short enough that a transient hiccup doesn't keep the user on
/// unverified results for long, long enough that we don't pay the helios
/// sync cost repeatedly when the chosen exec RPC is permanently
/// incompatible (e.g. proof-window limits).
const FALLBACK_COOLDOWN: Duration = Duration::from_secs(10);

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

#[derive(Default)]
struct ChainState {
    client: Option<HeliosBackend>,
    built_with: Option<ConfigSnapshot>,
    chosen_rpc: Option<String>,
    /// Cached raw provider against `chosen_rpc`. Used by the fallback
    /// path so a cooldown-period request doesn't pay TLS/transport setup
    /// every time.
    fallback: Option<RootProvider<Ethereum>>,
    /// Set to `Some(Instant::now())` whenever a helios call has just
    /// errored or helios couldn't be built. Subsequent requests within
    /// `FALLBACK_COOLDOWN` skip helios entirely.
    last_fallback_at: Option<Instant>,
}

pub struct NetworkClient {
    states: PerChain<Mutex<ChainState>>,
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
            statuses: PerChain::default(),
        }
    }

    fn set_status(&self, chain: Chain, s: VerificationStatus) {
        self.statuses.get(chain).store(s.as_u8(), Ordering::Relaxed);
    }

    fn state_for(&self, chain: Chain) -> &Mutex<ChainState> {
        self.states.get(chain)
    }

    /// Get a synced Helios client for `chain`, building (and waiting for
    /// sync) if needed. Rebuilds when the user's settings have drifted
    /// from the last build.
    async fn get(&self, chain: Chain) -> Result<HeliosBackend, String> {
        let snapshot = current_snapshot(chain);
        let mut s = self.state_for(chain).lock().await;

        if let (Some(client), Some(prev)) = (&s.client, &s.built_with)
            && prev == &snapshot
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
        // Build the raw fallback provider eagerly against the same URL
        // helios is about to use. If helios's build/sync fails below, the
        // fallback still exists for the cooldown window.
        s.fallback = build_fallback(&chosen_exec);
        s.chosen_rpc = Some(chosen_exec.clone());

        let consensus_order = shuffled(&snapshot.consensus_rpcs);
        info!(
            chain = %chain.label(),
            execution_rpc = %chosen_exec,
            consensus_rpcs = ?consensus_order,
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
                    error = %e,
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

    /// Snapshot whether we should skip helios this request.
    async fn in_cooldown(&self, chain: Chain) -> bool {
        let s = self.state_for(chain).lock().await;
        s.last_fallback_at
            .map(|t| t.elapsed() < FALLBACK_COOLDOWN)
            .unwrap_or(false)
    }

    /// Mark "helios just failed; route around it for a bit" and ensure a
    /// fallback provider exists for the cooldown window.
    async fn start_cooldown(&self, chain: Chain) {
        let mut s = self.state_for(chain).lock().await;
        s.last_fallback_at = Some(Instant::now());
        if s.fallback.is_none() {
            // Helios never even chose an exec RPC — pick one ourselves
            // so the fallback path has somewhere to send the request.
            let rpcs = settings::rpcs(chain);
            if let Some(url) = rpcs.choose(&mut rand::thread_rng()) {
                s.fallback = build_fallback(url);
                s.chosen_rpc = Some(url.clone());
            }
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
            let mut s = self.state_for(chain).lock().await;
            let previous = s.client.take();
            s.built_with = None;
            s.chosen_rpc = None;
            s.fallback = None;
            s.last_fallback_at = None;
            drop(s);
            spawn_shutdown(previous);
            self.set_status(chain, VerificationStatus::Connecting);
        }
    }

    async fn balance(&self, addr: Address, chain: Chain) -> Result<String, String> {
        // Cooldown: route straight to raw RPC, skip the helios attempt.
        if self.in_cooldown(chain).await {
            return self.fallback_balance(addr, chain).await;
        }

        // Try helios. On any error, start a cooldown and fall through
        // to raw.
        self.set_status(chain, VerificationStatus::Connecting);
        match self.get(chain).await {
            Ok(client) => match client.get_balance(addr, BlockId::latest()).await {
                Ok(raw) => {
                    self.set_status(chain, VerificationStatus::Verified);
                    Ok(alloy::primitives::utils::format_ether(raw))
                }
                Err(e) => {
                    debug!(
                        chain = %chain.label(),
                        addr = %short_address(addr),
                        error = %e,
                        "helios balance failed; falling back to raw RPC",
                    );
                    self.start_cooldown(chain).await;
                    self.fallback_balance(addr, chain).await
                }
            },
            Err(e) => {
                warn!(
                    chain = %chain.label(),
                    error = %e,
                    "helios unavailable; falling back to raw RPC",
                );
                self.start_cooldown(chain).await;
                self.fallback_balance(addr, chain).await
            }
        }
    }

    fn last_status(&self, chain: Chain) -> VerificationStatus {
        VerificationStatus::from_u8(self.statuses.get(chain).load(Ordering::Relaxed))
    }

    async fn provider(&self, chain: Chain) -> Option<RootProvider<Ethereum>> {
        let mut s = self.state_for(chain).lock().await;
        if let Some(p) = &s.fallback {
            return Some(p.clone());
        }
        // Helios hasn't built yet — pick an RPC ourselves and cache it
        // so subsequent portfolio fetches and the helios fallback path
        // share one transport.
        let rpcs = settings::rpcs(chain);
        let url = rpcs.choose(&mut rand::thread_rng())?.clone();
        let provider = build_fallback(&url)?;
        s.fallback = Some(provider.clone());
        s.chosen_rpc = Some(url);
        Some(provider)
    }

    async fn get_code(&self, addr: Address, chain: Chain) -> Result<VerifiedRead<Bytes>, String> {
        if self.in_cooldown(chain).await {
            return self.fallback_get_code(addr, chain).await;
        }
        match self.get(chain).await {
            Ok(client) => match client.get_code(addr, BlockId::latest()).await {
                Ok(value) => Ok(VerifiedRead {
                    value,
                    verified: true,
                }),
                Err(e) => {
                    debug!(
                        chain = %chain.label(),
                        addr = %short_address(addr),
                        error = %e,
                        "helios get_code failed; falling back to raw RPC",
                    );
                    self.start_cooldown(chain).await;
                    self.fallback_get_code(addr, chain).await
                }
            },
            Err(e) => {
                warn!(
                    chain = %chain.label(),
                    error = %e,
                    "helios unavailable for get_code; falling back to raw RPC",
                );
                self.start_cooldown(chain).await;
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
        if self.in_cooldown(chain).await {
            return self.fallback_get_storage_at(addr, slot, chain).await;
        }
        match self.get(chain).await {
            Ok(client) => match client.get_storage_at(addr, slot, BlockId::latest()).await {
                Ok(value) => Ok(VerifiedRead {
                    value,
                    verified: true,
                }),
                Err(e) => {
                    debug!(
                        chain = %chain.label(),
                        addr = %short_address(addr),
                        error = %e,
                        "helios get_storage_at failed; falling back to raw RPC",
                    );
                    self.start_cooldown(chain).await;
                    self.fallback_get_storage_at(addr, slot, chain).await
                }
            },
            Err(e) => {
                warn!(
                    chain = %chain.label(),
                    error = %e,
                    "helios unavailable for get_storage_at; falling back to raw RPC",
                );
                self.start_cooldown(chain).await;
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
        if self.in_cooldown(chain).await {
            return self.fallback_call(to, data, chain).await;
        }
        match self.get(chain).await {
            Ok(client) => match client.call(to, data.clone(), BlockId::latest()).await {
                Ok(value) => Ok(VerifiedRead {
                    value,
                    verified: true,
                }),
                Err(e) => {
                    debug!(
                        chain = %chain.label(),
                        addr = %short_address(to),
                        error = %e,
                        "helios call failed; falling back to raw RPC",
                    );
                    self.start_cooldown(chain).await;
                    self.fallback_call(to, data, chain).await
                }
            },
            Err(e) => {
                warn!(
                    chain = %chain.label(),
                    error = %e,
                    "helios unavailable for call; falling back to raw RPC",
                );
                self.start_cooldown(chain).await;
                self.fallback_call(to, data, chain).await
            }
        }
    }

    async fn get_balance_raw(
        &self,
        addr: Address,
        chain: Chain,
    ) -> Result<VerifiedRead<U256>, String> {
        if self.in_cooldown(chain).await {
            return self.fallback_get_balance_raw(addr, chain).await;
        }
        match self.get(chain).await {
            Ok(client) => match client.get_balance(addr, BlockId::latest()).await {
                Ok(value) => Ok(VerifiedRead {
                    value,
                    verified: true,
                }),
                Err(e) => {
                    debug!(
                        chain = %chain.label(),
                        addr = %short_address(addr),
                        error = %e,
                        "helios get_balance_raw failed; falling back to raw RPC",
                    );
                    self.start_cooldown(chain).await;
                    self.fallback_get_balance_raw(addr, chain).await
                }
            },
            Err(e) => {
                warn!(
                    chain = %chain.label(),
                    error = %e,
                    "helios unavailable for get_balance_raw; falling back to raw RPC",
                );
                self.start_cooldown(chain).await;
                self.fallback_get_balance_raw(addr, chain).await
            }
        }
    }

    async fn get_transaction_count(
        &self,
        addr: Address,
        chain: Chain,
    ) -> Result<VerifiedRead<u64>, String> {
        if self.in_cooldown(chain).await {
            return self.fallback_get_transaction_count(addr, chain).await;
        }
        match self.get(chain).await {
            Ok(client) => match client.get_nonce(addr, BlockId::latest()).await {
                Ok(value) => Ok(VerifiedRead {
                    value,
                    verified: true,
                }),
                Err(e) => {
                    debug!(
                        chain = %chain.label(),
                        addr = %short_address(addr),
                        error = %e,
                        "helios get_transaction_count failed; falling back to raw RPC",
                    );
                    self.start_cooldown(chain).await;
                    self.fallback_get_transaction_count(addr, chain).await
                }
            },
            Err(e) => {
                warn!(
                    chain = %chain.label(),
                    error = %e,
                    "helios unavailable for get_transaction_count; falling back to raw RPC",
                );
                self.start_cooldown(chain).await;
                self.fallback_get_transaction_count(addr, chain).await
            }
        }
    }

    async fn latest_block(&self, chain: Chain) -> Result<VerifiedRead<LatestBlock>, String> {
        if self.in_cooldown(chain).await {
            return self.fallback_latest_block(chain).await;
        }
        match self.get(chain).await {
            Ok(client) => match client.latest_block().await {
                Ok(value) => Ok(VerifiedRead {
                    value,
                    verified: true,
                }),
                Err(e) => {
                    debug!(
                        chain = %chain.label(),
                        error = %e,
                        "helios latest_block failed; falling back to raw RPC",
                    );
                    self.start_cooldown(chain).await;
                    self.fallback_latest_block(chain).await
                }
            },
            Err(e) => {
                warn!(
                    chain = %chain.label(),
                    error = %e,
                    "helios unavailable for latest_block; falling back to raw RPC",
                );
                self.start_cooldown(chain).await;
                self.fallback_latest_block(chain).await
            }
        }
    }
}

impl NetworkClient {
    /// Plain `eth_getCode` against the chosen exec RPC. The
    /// `verified=false` flag in the returned `VerifiedRead` lets the
    /// clear-signing UI surface "unverified bytecode" without affecting
    /// the global balance verification badge.
    async fn fallback_get_code(
        &self,
        addr: Address,
        chain: Chain,
    ) -> Result<VerifiedRead<Bytes>, String> {
        let provider = self.fallback_provider(chain).await?;
        provider
            .get_code_at(addr)
            .await
            .map(|value| VerifiedRead {
                value,
                verified: false,
            })
            .map_err(|e| {
                debug!(
                    chain = %chain.label(),
                    addr = %short_address(addr),
                    error = %e,
                    "fallback get_code failed",
                );
                e.to_string()
            })
    }

    async fn fallback_get_storage_at(
        &self,
        addr: Address,
        slot: U256,
        chain: Chain,
    ) -> Result<VerifiedRead<B256>, String> {
        let provider = self.fallback_provider(chain).await?;
        provider
            .get_storage_at(addr, slot)
            .await
            .map(|raw| VerifiedRead {
                value: B256::from(raw),
                verified: false,
            })
            .map_err(|e| {
                debug!(
                    chain = %chain.label(),
                    addr = %short_address(addr),
                    error = %e,
                    "fallback get_storage_at failed",
                );
                e.to_string()
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
        let provider = self.fallback_provider(chain).await?;
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
                debug!(
                    chain = %chain.label(),
                    addr = %short_address(to),
                    error = %e,
                    "fallback call failed",
                );
                e.to_string()
            })
    }

    async fn fallback_get_balance_raw(
        &self,
        addr: Address,
        chain: Chain,
    ) -> Result<VerifiedRead<U256>, String> {
        let provider = self.fallback_provider(chain).await?;
        provider
            .get_balance(addr)
            .await
            .map(|value| VerifiedRead {
                value,
                verified: false,
            })
            .map_err(|e| {
                debug!(
                    chain = %chain.label(),
                    addr = %short_address(addr),
                    error = %e,
                    "fallback get_balance_raw failed",
                );
                e.to_string()
            })
    }

    async fn fallback_get_transaction_count(
        &self,
        addr: Address,
        chain: Chain,
    ) -> Result<VerifiedRead<u64>, String> {
        let provider = self.fallback_provider(chain).await?;
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
                debug!(
                    chain = %chain.label(),
                    addr = %short_address(addr),
                    error = %e,
                    "fallback get_transaction_count failed",
                );
                e.to_string()
            })
    }

    async fn fallback_latest_block(
        &self,
        chain: Chain,
    ) -> Result<VerifiedRead<LatestBlock>, String> {
        let provider = self.fallback_provider(chain).await?;
        let block = provider
            .get_block(alloy::eips::BlockId::latest())
            .await
            .map_err(|e| {
                debug!(
                    chain = %chain.label(),
                    error = %e,
                    "fallback latest_block failed",
                );
                e.to_string()
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

    /// Resolve the cached fallback provider for `chain`. Used by every
    /// `fallback_*` method; threads "no RPCs configured" / "URL parse
    /// failure" through as `Err`.
    async fn fallback_provider(&self, chain: Chain) -> Result<RootProvider<Ethereum>, String> {
        let s = self.state_for(chain).lock().await;
        s.fallback
            .clone()
            .ok_or_else(|| format!("no fallback RPC available for {}", chain.label()))
    }

    /// Plain `eth_getBalance` against the chosen exec RPC. No proof, no
    /// verification — used during the cooldown window after a helios
    /// failure.
    async fn fallback_balance(&self, addr: Address, chain: Chain) -> Result<String, String> {
        let provider = {
            let s = self.state_for(chain).lock().await;
            s.fallback.clone()
        };
        let Some(provider) = provider else {
            self.set_status(chain, VerificationStatus::Unavailable);
            return Err(format!("no fallback RPC available for {}", chain.label()));
        };
        match provider.get_balance(addr).await {
            Ok(raw) => {
                self.set_status(chain, VerificationStatus::Fallback);
                Ok(alloy::primitives::utils::format_ether(raw))
            }
            Err(e) => {
                self.set_status(chain, VerificationStatus::Unavailable);
                debug!(
                    chain = %chain.label(),
                    addr = %short_address(addr),
                    error = %e,
                    "fallback balance failed",
                );
                Err(e.to_string())
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

fn build_fallback(url: &str) -> Option<RootProvider<Ethereum>> {
    match url::Url::parse(url) {
        Ok(u) => Some(RootProvider::<Ethereum>::new_http(u)),
        Err(e) => {
            error!(url = %url, error = %e, "cannot build fallback provider");
            None
        }
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
    use rand::seq::SliceRandom;
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
                        consensus_rpc = %cl,
                        prior_failures = errors.len(),
                        "consensus rpc succeeded after prior failures",
                    );
                }
                return Ok(backend);
            }
            Err(e) => {
                warn!(chain = %chain.label(), consensus_rpc = %cl, error = %e, "consensus rpc failed");
                errors.push(format!("{cl}: {e}"));
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
        let mut header: alloy_rpc_types_eth::Header = Default::default();
        header.hash = B256::from([0xbb; 32]);
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
}

/// Spawn a background task that fetches the latest community-fallback
/// checkpoint and, if our built-in is older than the freshness threshold,
/// updates `settings::auto_checkpoint`. No-ops when the built-in is
/// fresh. Mainnet only — L2 chains have no checkpoint concept.
pub fn refresh_auto_checkpoint() {
    if settings::builtin_is_fresh() {
        return;
    }
    tokio::spawn(async move {
        let cf = match CheckpointFallback::new().build().await {
            Ok(cf) => cf,
            Err(e) => {
                warn!(error = %e, "checkpoint fallback build failed");
                return;
            }
        };
        match cf.fetch_latest_checkpoint(&EthNetwork::Mainnet).await {
            Ok(latest) => {
                info!(checkpoint = %latest, "refreshed auto checkpoint");
                settings::set_auto_checkpoint(latest);
            }
            Err(e) => warn!(error = %e, "checkpoint fetch failed"),
        }
    });
}
