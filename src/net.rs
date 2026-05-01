//! Helios-backed verified RPC client with raw-RPC fallback.
//!
//! Owns a single shared `EthereumClient` that all balance/call queries flow
//! through. The client is rebuilt on a rotation timer (so a multi-RPC list
//! distributes load over time) and whenever the user's settings change.
//!
//! When a helios call errors (sync timeout, build failure, an RPC that won't
//! serve `eth_getProof` for the verified head — e.g. 1rpc.io's narrow proof
//! window), `balance` falls back to a plain `eth_getBalance` call against the
//! same execution RPC. The result is **unverified** in that case. A short
//! cooldown after each fallback skips helios entirely so the user keeps
//! getting balances back without paying the helios attempt cost on every
//! request. After the cooldown elapses, helios is tried again.
//!
//! Mirrors the pattern in kohaku-extension's `HeliosEthersProvider`. The UI
//! reads `last_status()` to surface verification state in the header badge.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use alloy::network::Ethereum;
use alloy::primitives::{Address, B256};
use alloy::providers::{Provider, RootProvider};
use alloy_eips::BlockId;
use async_trait::async_trait;
use rand::seq::SliceRandom;
use tokio::sync::Mutex;

use helios_ethereum::config::checkpoints::CheckpointFallback;
use helios_ethereum::config::networks::Network;
use helios_ethereum::{EthereumClient, EthereumClientBuilder};
use tracing::{debug, error, info, warn};

use crate::settings;
use crate::wallet::short_address;

/// How recently does a helios failure have to be for us to skip helios on the
/// next request? Matches kohaku-extension's `FALLBACK_COOLDOWN_MS`. Short
/// enough that a transient hiccup doesn't keep the user on unverified results
/// for long, long enough that we don't pay the helios sync cost repeatedly
/// when the chosen exec RPC is permanently incompatible (e.g. proof-window
/// limits).
const FALLBACK_COOLDOWN: Duration = Duration::from_secs(10);

/// Verification state of the most recent balance fetch. Sampled by the
/// dashboard to render a "Verified by Helios" / "Unverified RPC" badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// No fetch has completed yet — helios is still bootstrapping or hasn't
    /// been touched this session.
    Connecting,
    /// Last fetch went through helios's light-client `eth_getProof` path.
    Verified,
    /// Last fetch went through the raw-RPC fallback. The balance is whatever
    /// the upstream returned; it has not been proved against the consensus
    /// header.
    Fallback,
    /// Both helios and the raw-RPC fallback failed. The user is staring at a
    /// stale or "—" balance.
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
/// The dashboard, HD-account picker, and settings save flow all hold this as
/// `Arc<dyn BalanceFetcher>` rather than `Arc<NetworkClient>` so tests can
/// substitute a deterministic mock without standing up Helios. The real impl
/// is `NetworkClient`; the test impl is `MockFetcher` below.
#[async_trait]
pub trait BalanceFetcher: Send + Sync + std::fmt::Debug {
    /// Formatted-ether balance of `addr`, e.g. "1.234". Tries helios first;
    /// on error, falls back to a raw `eth_getBalance` against the same exec
    /// RPC and starts a short cooldown. Inspect `last_status` afterwards to
    /// see whether the value was light-client verified.
    async fn balance(&self, addr: Address) -> Result<String, String>;
    /// Drop the cached client. The next `balance` call rebuilds from settings.
    async fn invalidate(&self);
    /// Verification state of the most recent `balance` call. Sync getter so
    /// the UI thread can read it without awaiting.
    fn last_status(&self) -> VerificationStatus;
    /// Shared raw `RootProvider` against the same exec RPC helios is using
    /// (or, if helios hasn't been built yet, a freshly-picked one cached for
    /// future calls). Returned cheaply via the provider's internal `Arc`, so
    /// callers that issue raw `eth_call` / `eth_getBalance` (e.g. the
    /// portfolio fetcher) reuse one transport across account switches
    /// instead of building a new TLS pool every dashboard rebuild.
    /// `None` only when no RPCs are configured or the chosen URL won't
    /// parse.
    async fn provider(&self) -> Option<RootProvider<Ethereum>>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConfigSnapshot {
    rpcs: Vec<String>,
    consensus_rpcs: Vec<String>,
    checkpoint: B256,
}

struct ClientState {
    client: Option<Arc<EthereumClient>>,
    built_with: Option<ConfigSnapshot>,
    chosen_rpc: Option<String>,
    /// Cached raw provider against `chosen_rpc`. Used by the fallback path so
    /// a cooldown-period request doesn't pay TLS/transport setup every time.
    fallback: Option<RootProvider<Ethereum>>,
    /// Set to `Some(Instant::now())` whenever a helios call has just errored
    /// or helios couldn't be built. Subsequent requests within
    /// `FALLBACK_COOLDOWN` skip helios entirely.
    last_fallback_at: Option<Instant>,
}

pub struct NetworkClient {
    state: Mutex<ClientState>,
    /// Most recent `VerificationStatus`. Held outside the mutex so the UI can
    /// poll it without blocking on a long helios sync. Encoded as `u8` for
    /// `AtomicU8`; see `VerificationStatus::{as_u8,from_u8}`.
    status: AtomicU8,
}

impl std::fmt::Debug for NetworkClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkClient").finish_non_exhaustive()
    }
}

impl NetworkClient {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(ClientState {
                client: None,
                built_with: None,
                chosen_rpc: None,
                fallback: None,
                last_fallback_at: None,
            }),
            status: AtomicU8::new(VerificationStatus::Connecting.as_u8()),
        }
    }

    fn set_status(&self, s: VerificationStatus) {
        self.status.store(s.as_u8(), Ordering::Relaxed);
    }

    /// Get a synced Helios client, building (and waiting for sync) if needed.
    /// Rebuilds when the user's settings have drifted from the last build.
    async fn get(&self) -> Result<Arc<EthereumClient>, String> {
        let snapshot = current_snapshot();
        let mut s = self.state.lock().await;

        if let (Some(client), Some(prev)) = (&s.client, &s.built_with)
            && prev == &snapshot
        {
            return Ok(client.clone());
        }

        if snapshot.rpcs.is_empty() {
            return Err("no execution RPCs configured".into());
        }
        if snapshot.consensus_rpcs.is_empty() {
            return Err("no consensus RPCs configured".into());
        }
        let chosen_exec = pick_rpc(&snapshot.rpcs);
        // Build the raw fallback provider eagerly against the same URL helios
        // is about to use. If helios's build/sync fails below, the fallback
        // still exists for the cooldown window.
        s.fallback = build_fallback(&chosen_exec);
        s.chosen_rpc = Some(chosen_exec.clone());

        let consensus_order = shuffled(&snapshot.consensus_rpcs);
        info!(
            execution_rpc = %chosen_exec,
            consensus_rpcs = ?consensus_order,
            checkpoint = %snapshot.checkpoint,
            "building helios client",
        );
        let started = Instant::now();
        let client =
            match build_with_consensus_fallback(&chosen_exec, &consensus_order, &snapshot).await {
                Ok(c) => c,
                Err(e) => {
                    warn!(
                        elapsed = ?started.elapsed(),
                        error = %e,
                        "helios build/sync failed",
                    );
                    return Err(e);
                }
            };
        info!(elapsed = ?started.elapsed(), "helios client built and synced");

        let arc = Arc::new(client);
        let previous = s.client.replace(arc.clone());
        s.built_with = Some(snapshot);
        drop(s);
        spawn_shutdown(previous);
        Ok(arc)
    }

    /// Snapshot whether we should skip helios this request.
    async fn in_cooldown(&self) -> bool {
        let s = self.state.lock().await;
        s.last_fallback_at
            .map(|t| t.elapsed() < FALLBACK_COOLDOWN)
            .unwrap_or(false)
    }

    /// Mark "helios just failed; route around it for a bit" and ensure a
    /// fallback provider exists for the cooldown window.
    async fn start_cooldown(&self) {
        let mut s = self.state.lock().await;
        s.last_fallback_at = Some(Instant::now());
        if s.fallback.is_none() {
            // Helios never even chose an exec RPC — pick one ourselves so the
            // fallback path has somewhere to send the request.
            let rpcs = settings::rpcs();
            if let Some(url) = rpcs.choose(&mut rand::thread_rng()) {
                s.fallback = build_fallback(url);
                s.chosen_rpc = Some(url.clone());
            }
        }
    }
}

/// Tell helios to stop the previous client's consensus task. Without this,
/// dropping the `Arc<EthereumClient>` leaves its spawned consensus loop
/// running for the rest of the process — and once the `shutdown_send` watch
/// sender is gone, the loop's `select!` arm on `shutdown_rx.changed()`
/// returns Err immediately every iteration without yielding, spinning CPU.
fn spawn_shutdown(client: Option<Arc<EthereumClient>>) {
    let Some(client) = client else { return };
    tokio::spawn(async move {
        client.shutdown().await;
        debug!("previous helios client shut down");
    });
}

#[async_trait]
impl BalanceFetcher for NetworkClient {
    /// Drop the cached client and tell helios to stop the consensus task.
    /// The next call will rebuild from current settings, picking a fresh
    /// random RPC from the list.
    async fn invalidate(&self) {
        let mut s = self.state.lock().await;
        let previous = s.client.take();
        s.built_with = None;
        s.chosen_rpc = None;
        s.fallback = None;
        s.last_fallback_at = None;
        drop(s);
        spawn_shutdown(previous);
        self.set_status(VerificationStatus::Connecting);
    }

    async fn balance(&self, addr: Address) -> Result<String, String> {
        // Cooldown: route straight to raw RPC, skip the helios attempt.
        if self.in_cooldown().await {
            return self.fallback_balance(addr).await;
        }

        // Try helios. On any error, start a cooldown and fall through to raw.
        self.set_status(VerificationStatus::Connecting);
        match self.get().await {
            Ok(client) => match client.get_balance(addr, BlockId::latest()).await {
                Ok(raw) => {
                    self.set_status(VerificationStatus::Verified);
                    Ok(alloy::primitives::utils::format_ether(raw))
                }
                Err(e) => {
                    debug!(addr = %short_address(addr), error = %e, "helios balance failed; falling back to raw RPC");
                    self.start_cooldown().await;
                    self.fallback_balance(addr).await
                }
            },
            Err(e) => {
                warn!(error = %e, "helios unavailable; falling back to raw RPC");
                self.start_cooldown().await;
                self.fallback_balance(addr).await
            }
        }
    }

    fn last_status(&self) -> VerificationStatus {
        VerificationStatus::from_u8(self.status.load(Ordering::Relaxed))
    }

    async fn provider(&self) -> Option<RootProvider<Ethereum>> {
        let mut s = self.state.lock().await;
        if let Some(p) = &s.fallback {
            return Some(p.clone());
        }
        // Helios hasn't built yet — pick an RPC ourselves and cache it so
        // subsequent portfolio fetches and the helios fallback path share
        // one transport.
        let rpcs = settings::rpcs();
        let url = rpcs.choose(&mut rand::thread_rng())?.clone();
        let provider = build_fallback(&url)?;
        s.fallback = Some(provider.clone());
        s.chosen_rpc = Some(url);
        Some(provider)
    }
}

impl NetworkClient {
    /// Plain `eth_getBalance` against the chosen exec RPC. No proof, no
    /// verification — used during the cooldown window after a helios failure.
    async fn fallback_balance(&self, addr: Address) -> Result<String, String> {
        let provider = {
            let s = self.state.lock().await;
            s.fallback.clone()
        };
        let Some(provider) = provider else {
            self.set_status(VerificationStatus::Unavailable);
            return Err("no fallback RPC available".into());
        };
        match provider.get_balance(addr).await {
            Ok(raw) => {
                self.set_status(VerificationStatus::Fallback);
                Ok(alloy::primitives::utils::format_ether(raw))
            }
            Err(e) => {
                self.set_status(VerificationStatus::Unavailable);
                debug!(addr = %short_address(addr), error = %e, "fallback balance failed");
                Err(e.to_string())
            }
        }
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

fn current_snapshot() -> ConfigSnapshot {
    ConfigSnapshot {
        rpcs: settings::rpcs(),
        consensus_rpcs: settings::consensus_rpcs(),
        checkpoint: settings::checkpoint_override().unwrap_or_else(settings::auto_checkpoint),
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

/// Try each consensus RPC in order; return the first client that builds AND
/// passes `wait_synced`. Aggregates per-endpoint errors so the user can see
/// which ones failed and why.
async fn build_with_consensus_fallback(
    execution_rpc: &str,
    consensus_rpcs: &[String],
    snap: &ConfigSnapshot,
) -> Result<EthereumClient, String> {
    let mut errors: Vec<String> = Vec::new();
    for cl in consensus_rpcs {
        match build_client(execution_rpc, cl, snap).await {
            Ok(client) => {
                if !errors.is_empty() {
                    info!(
                        consensus_rpc = %cl,
                        prior_failures = errors.len(),
                        "consensus rpc succeeded after prior failures",
                    );
                }
                return Ok(client);
            }
            Err(e) => {
                warn!(consensus_rpc = %cl, error = %e, "consensus rpc failed");
                errors.push(format!("{cl}: {e}"));
            }
        }
    }
    Err(format!(
        "all {} consensus RPC(s) failed:\n  - {}",
        errors.len(),
        errors.join("\n  - ")
    ))
}

async fn build_client(
    execution_rpc: &str,
    consensus_rpc: &str,
    snap: &ConfigSnapshot,
) -> Result<EthereumClient, String> {
    let client = EthereumClientBuilder::new()
        .network(Network::Mainnet)
        .execution_rpc(execution_rpc)
        .map_err(|e| e.to_string())?
        .consensus_rpc(consensus_rpc)
        .map_err(|e| e.to_string())?
        .checkpoint(snap.checkpoint)
        .load_external_fallback()
        .data_dir(crate::paths::data_dir().join("helios"))
        .with_file_db()
        .build()
        .map_err(|e| e.to_string())?;
    client.wait_synced().await.map_err(|e| e.to_string())?;
    wait_for_head(&client).await?;
    Ok(client)
}

/// `wait_synced()` returns once the consensus client has bootstrapped and
/// processed its first update, but the execution payload may not have arrived
/// yet — `helios::core::Node::check_head_age` returns `OutOfSync(now)` when
/// `execution.get_block(Latest)` is `None`. The basic example sleeps 15s; we
/// poll with a timeout so balance fetches don't fail with a misleading "out of
/// sync: 1.7B seconds behind" the moment the dashboard opens.
async fn wait_for_head(client: &EthereumClient) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut delay_ms: u64 = 250;
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match client.get_block_number().await {
            Ok(n) => {
                debug!(attempt, block = %n, "head ready");
                return Ok(());
            }
            Err(e) => {
                let s = e.to_string();
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

/// Stub `BalanceFetcher` for tests. Returns "0" for every address and is a
/// no-op on `invalidate`. Tests that need to exercise specific balance
/// responses should drive the screen via `Message::BalanceFetched` directly
/// rather than waiting for an in-flight `Task::perform`.
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
    async fn balance(&self, _addr: Address) -> Result<String, String> {
        Ok("0".into())
    }

    async fn invalidate(&self) {}

    fn last_status(&self) -> VerificationStatus {
        VerificationStatus::Verified
    }

    async fn provider(&self) -> Option<RootProvider<Ethereum>> {
        None
    }
}

/// Spawn a background task that fetches the latest community-fallback
/// checkpoint and, if our built-in is older than the freshness threshold,
/// updates `settings::auto_checkpoint`. No-ops when the built-in is fresh.
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
        match cf.fetch_latest_checkpoint(&Network::Mainnet).await {
            Ok(latest) => {
                info!(checkpoint = %latest, "refreshed auto checkpoint");
                settings::set_auto_checkpoint(latest);
            }
            Err(e) => warn!(error = %e, "checkpoint fetch failed"),
        }
    });
}
