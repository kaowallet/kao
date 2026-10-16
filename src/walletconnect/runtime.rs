//! The App-owned WalletConnect runtime: [`WcSlot`] (where it lives), [`WcRuntime`] (the `SignClient`,
//! the [`WcBook`], a `closed` flag and the tokio handle every relay side effect is spawned on), the
//! event stream the dashboard subscribes to, liveness checks for the signing tasks, saving the
//! state to the vault, restoring it, suspend and teardown.
//! WalletConnect network effects never ride an iced `Task`: App drops a dashboard's tasks when it
//! rebuilds the dashboard, and an answer, rejection or disconnect must survive that.
//!
//! Background work holds the runtime only weakly: the *forwarder* (crate `SignEvent`s → book or
//! stream) and the *housekeeper* (1 s `book.tick`) stop once the last [`WcRuntime`] clone is
//! dropped; op tasks hold a strong clone only while their network call runs. The book's
//! `std::sync::Mutex` is only ever held for a synchronous critical section (never across `.await`).
//!
//! Saved state: every [`Effects`] the book returns goes through one of four sinks — [`WcRuntime::apply`]
//! (the dashboard's ops), `apply_background` (the forwarder, the housekeeper, op completions), the
//! teardown's and the suspend's own loops. Their history (`log`) goes to the runtime's
//! epoch-bound [`VaultSession`]; their `persist` saves a [`WcStateRecord`] — off the UI thread,
//! `Now` coalesced, `Soon` after [`PERSIST_SOON_AFTER`] — but never from a closed runtime: after a
//! lock only the suspend's [`VaultFlush`] writes, and Turn off clears the saved state itself.
//!
//! Restore ([`WcSlot::begin_restore`]): at the first dashboard of an unlock, saved sessions that
//! are still alive are restored onto a new client — everything it will do worked out from the
//! saved record before Kao dials — with the book seeded before the forwarder runs. A restore that
//! can't finish never disconnects a dapp, and one a lock (or Forget) stops mid-dial is aborted
//! before it can take what the relay keeps for the saved identity. The dashboard follows the
//! restore's phases through [`WcSlot::restore_watch`] — there is no runtime, so no event stream.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tracing::{debug, info, warn};
use wallet_connect::auth::IdentityKey;
use wallet_connect::crypto::Topic;
use wallet_connect::relay::RelayClientOptions;
use wallet_connect::rpc::ErrorObject;
use wallet_connect::sign::{
    ApproveParams, PendingRequest, Proposal, SessionEvent, SignClient, SignEvent, SignEvents,
    Snapshot,
};
use zeroize::Zeroizing;

use super::book::{
    BookSeed, FLAP_RETIRE_REASON, HoldEnd, RestoreWork, SafeExecHolds, WcBook, answer_signature,
};
use super::persist::{PersistedDelivery, SeedHex, WC_STATE_VERSION, WcStateRecord};
use super::transport::{self, ConnectorShutdown, KaoConnector, Timeouts};
use super::types::*;
use super::{
    EXPIRY_MARGIN_SECS, QUIT_TEARDOWN_BUDGET, TEARDOWN_PER_PHASE, caip2, kao_metadata, now_secs,
    request,
};
use crate::vault::{
    AccountRef, AckRecord, DappRecord, Delivery, EndReason, NewConnection, Vault, VaultFlush,
    VaultSession,
};

const RESPOND_TIMEOUT: Duration = Duration::from_secs(20);
const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Relay-level request timeout: every publish/subscribe gives up after this (crate default: 30 s).
const RELAY_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Cap of the crate's reconnect backoff.
const RELAY_MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Housekeeper period: deadlines, paste windows, idle tracking.
const HOUSEKEEPING_EVERY: Duration = Duration::from_secs(1);
/// Session requests handed to the stream that no dashboard has taken yet, at most — overall and
/// per session. Admission (where the queue caps hold) runs only on a dashboard, so while none
/// listens these bound what a dapp can pile up; room for more than admission would ever queue.
const MAX_BACKLOG: usize = super::MAX_QUEUE_TOTAL + super::MAX_QUEUE_PER_SESSION;
const MAX_BACKLOG_PER_SESSION: usize = 2 * super::MAX_QUEUE_PER_SESSION;
/// A `Persist::Soon` change is saved this long after the first one, so a burst is saved once.
const PERSIST_SOON_AFTER: Duration = Duration::from_secs(2);
/// A restore that failed in a way that may clear up by itself (the relay unreachable at boot, a
/// proxy not up yet) tries again after these many seconds, then every last one.
const RESTORE_BACKOFF_SECS: [u64; 4] = [5, 15, 30, 60];
/// Why a restore waits for the user instead of dialing: the route got less private than the one
/// the saved sessions were made under.
pub const RESTORE_PROXY_OFF: &str =
    "Kao's proxy is off now — reconnecting would show your IP to the relay.";
/// Why a restore waits for the user: it stopped before it could finish.
const RESTORE_INTERRUPTED: &str = "Reconnecting your saved dapps stopped — try again.";
/// Why a restore waits for the user: a runtime (or a start) got to the slot first.
const RESTORE_BUSY: &str = "WalletConnect was busy — reconnect your saved dapps in a moment.";
/// The relay URL a test runtime reports (the in-process relay has none).
#[cfg(test)]
pub(crate) const TEST_RELAY_URL: &str = "wss://relay.kao.test";

/// Process-wide, never 0.
pub fn next_generation() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    loop {
        let g = NEXT.fetch_add(1, Ordering::Relaxed);
        if g != 0 {
            return g;
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// App-owned home of the runtime. Shared (Arc) with every dashboard.
#[derive(Clone, Default)]
pub struct WcSlot(Arc<Mutex<SlotInner>>);

#[derive(Default)]
struct SlotInner {
    rt: Option<WcRuntime>,
    starting: bool,
    closed: bool,
    /// Why the last runtime retired itself, until a dashboard shows it. Recorded here because the
    /// runtime's own stream may be cancelled (its subscription goes with the runtime) before the
    /// dashboard polls the notice, and its book's activity ring dies with it.
    retired: Option<RetireNotice>,
    /// Teardowns still running, shared with every successor slot (see [`Teardowns`]).
    teardowns: Teardowns,
    /// The holds on Safes whose dapp transaction Kao executed and hasn't seen mined, shared with
    /// every runtime installed here and every successor slot: the chain doesn't forget an
    /// execution in flight when the relay goes off or the wallet locks.
    holds: SafeExecHolds,
    /// The App's vault, shared with every successor slot (the restore state is not).
    vault: Vault,
    /// Saved sessions being restored, or waiting for the user. Changed only by the restore code,
    /// under this lock; never carried to a successor (a lock drops it — the saved state stays).
    restore: RestoreState,
    /// The vault epoch whose saved state this slot already looked at: `begin_restore` acts once
    /// per unlock, however often a dashboard is built.
    restore_checked: Option<VaultSession>,
    /// Numbers each restore run, so a run the user forgot (or a lock ended) can tell.
    restore_runs: u64,
    /// Bumped on every change of `restore` (and when the slot closes): what the dashboard watches
    /// while a restore runs or waits ([`WcSlot::restore_watch`]).
    restore_rev: RestoreRevision,
}

/// A slot's restore revision: a process-unique id (the dashboard's subscription identity) and the
/// counter itself.
struct RestoreRevision {
    id: u64,
    tx: tokio::sync::watch::Sender<u64>,
}

impl Default for RestoreRevision {
    fn default() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self {
            id: NEXT.fetch_add(1, Ordering::Relaxed),
            tx: tokio::sync::watch::Sender::new(0),
        }
    }
}

impl SlotInner {
    /// The restore changed: wake whoever watches it. Under the slot lock, with the change.
    fn restore_changed(&self) {
        self.restore_rev.tx.send_modify(|n| *n = n.wrapping_add(1));
    }
}

/// The slot's restore revision, for the dashboard: an iced subscription over
/// [`restore_watch_stream`] wakes it at every restore phase change, so the pane (and the
/// launcher row) follow a retry loop that runs with no runtime and no event stream. Hash / Eq by
/// the slot's id: a dashboard rebuilt over the same slot keeps its subscription.
#[derive(Clone)]
pub struct RestoreWatch {
    id: u64,
    rx: tokio::sync::watch::Receiver<u64>,
    /// The slot itself, weakly (the watch never keeps a replaced slot alive): the stream ends a
    /// restore that lapsed while it waited.
    slot: Weak<Mutex<SlotInner>>,
}

impl PartialEq for RestoreWatch {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for RestoreWatch {}

impl Hash for RestoreWatch {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.id.hash(h)
    }
}

impl fmt::Debug for RestoreWatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RestoreWatch(slot {})", self.id)
    }
}

/// How often, at most, the restore watch re-reads the wall clock while it waits for a lapse.
const LAPSE_RECHECK_SECS: u64 = 60;

/// One `()` per restore change after the watch was taken — none for the state it was taken in,
/// which the dashboard mirrored already. Ends with the slot.
///
/// It is also where a restore that lapsed ends ([`WcSlot::end_lapsed_restore`]): one waiting for
/// the user never tries again by itself, so once every saved dapp and owed disconnect it holds has
/// expired, the stream ends it at that moment — on the executor, never the UI thread — and wakes
/// the dashboard for that change like any other. Should nothing watch (a runtime runs beside a
/// restore waiting for the user, so the dashboard follows its events instead), the pane's view
/// counts both as 0 until the user retries or forgets. The lapse is judged by the wall clock,
/// re-read at least every [`LAPSE_RECHECK_SECS`].
pub fn restore_watch_stream(w: &RestoreWatch) -> futures::stream::BoxStream<'static, ()> {
    use futures::StreamExt;
    futures::stream::unfold(
        (w.rx.clone(), w.slot.clone()),
        |(mut rx, slot)| async move {
            loop {
                let lapses_at = slot.upgrade().and_then(|s| WcSlot(s).restore_lapses_at());
                let lapsed = async move {
                    match lapses_at {
                        Some(at) => {
                            // The timer runs on `Instant`, which stands still while the machine
                            // sleeps: re-read the wall clock at least once a minute rather than
                            // trust one long sleep across a lid close.
                            let wait = at.saturating_sub(now_secs()).min(LAPSE_RECHECK_SECS);
                            tokio::time::sleep(Duration::from_secs(wait)).await;
                        }
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    changed = rx.changed() => {
                        changed.ok()?;
                        return Some(((), (rx, slot)));
                    }
                    () = lapsed => {
                        if slot.upgrade().is_some_and(|s| WcSlot(s).end_lapsed_restore()) {
                            // One wake for the change it just made.
                            rx.mark_unchanged();
                            return Some(((), (rx, slot)));
                        }
                        // Not yet by the clock, or the restore moved on: look again.
                    }
                }
            }
        },
    )
    .boxed()
}

/// A retired runtime's reason, for the dashboard: Kao's own fixed copy, never dapp data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetireNotice {
    pub text: String,
    /// The relay rejected Kao (flapping): a toast and a failed paste, not just a status line.
    pub error: bool,
}

/// Teardowns still running — lock, Turn off, retire, quit, a suspend, a vault writer's drain. Each
/// runs on its runtime's own tokio handle (so it no longer depends on iced polling a `Task`), or
/// on the writer's own thread, and is counted until it ends, so a quit can wait for every one
/// (bounded by `QUIT_TEARDOWN_BUDGET`) before the process exits and cuts a dapp's
/// `wc_sessionDelete` or the last save short — and an unlock can wait for the last epoch's.
#[derive(Clone)]
struct Teardowns(Arc<tokio::sync::watch::Sender<usize>>);

impl Default for Teardowns {
    fn default() -> Self {
        Self(Arc::new(tokio::sync::watch::Sender::new(0)))
    }
}

/// Counts one teardown as running until dropped — when it ends, or when its task is dropped.
struct Running(Arc<tokio::sync::watch::Sender<usize>>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n = n.saturating_sub(1));
    }
}

impl Teardowns {
    /// Count one more as running, until the returned guard drops.
    fn begin(&self) -> Running {
        self.0.send_modify(|n| *n += 1);
        Running(self.0.clone())
    }

    fn spawn(&self, rt: WcRuntime) -> tokio::task::JoinHandle<()> {
        let running = self.begin();
        let handle = rt.inner.handle.clone();
        handle.spawn(async move {
            let _running = running;
            rt.teardown(TEARDOWN_PER_PHASE).await;
        })
    }

    fn running(&self) -> usize {
        *self.0.borrow()
    }

    /// Resolves once no teardown is running.
    fn idle(&self) -> impl Future<Output = ()> + Send + use<> {
        let mut rx = self.0.subscribe();
        async move {
            let _ = rx.wait_for(|n| *n == 0).await;
        }
    }
}

/// Saved sessions on their way back ([`WcSlot::begin_restore`]).
#[derive(Default)]
enum RestoreState {
    #[default]
    Idle,
    /// A restore loop runs: dialing, or sleeping until its next try.
    Running(RestoreRun),
    /// Stopped until the user reconnects (Retry / Reconnect anyway) or forgets the sessions.
    NeedsYou(RestoreWait),
}

/// What a restore needs at every try: the saved record (decrypted — dropped with the restore
/// state, which a lock drops), the vault epoch it belongs to, and how to reach the relay.
#[derive(Clone)]
struct RestoreJob {
    record: Arc<WcStateRecord>,
    /// The session expiry (unix s), in the saved client state, of each saved binding still alive
    /// when the restore began: what [`Self::live_sessions`] counts.
    expiries: Arc<[u64]>,
    /// The same for each session alive then that no binding covers — a disconnect the restore
    /// still owes its dapp: what [`Self::live_unbound`] counts.
    unbound_expiries: Arc<[u64]>,
    session: VaultSession,
    dial: RestoreDial,
}

/// How many of `expiries` are still alive at `now`, as [`plan_restore`] counts them.
fn alive_at(expiries: &[u64], now: u64) -> usize {
    let deadline = now.saturating_add(EXPIRY_MARGIN_SECS);
    expiries.iter().filter(|&&e| e > deadline).count()
}

impl RestoreJob {
    /// Saved bindings whose session is still alive at `now` (as [`plan_restore`] counts them):
    /// the dapps the pane says wait to reconnect — never one that expired meanwhile.
    fn live_sessions(&self, now: u64) -> usize {
        alive_at(&self.expiries, now)
    }

    /// Owed disconnects whose session is still alive at `now`: once it expired the dapp no
    /// longer holds it, and there is nothing left to tell.
    fn live_unbound(&self, now: u64) -> usize {
        alive_at(&self.unbound_expiries, now)
    }

    /// From when (unix s) nothing this restore holds is alive any more — no saved dapp to bring
    /// back, no disconnect to deliver — so a try would find nothing to dial for
    /// ([`WcSlot::end_lapsed_restore`]).
    fn lapses_at(&self) -> u64 {
        self.expiries
            .iter()
            .chain(self.unbound_expiries.iter())
            .max()
            .map_or(0, |e| e.saturating_sub(EXPIRY_MARGIN_SECS))
    }
}

struct RestoreRun {
    run: u64,
    job: RestoreJob,
    /// `Connecting` or `RetryingAt`.
    phase: RestorePhase,
    /// Wakes a loop sleeping until its next try (Retry now, Forget, a lock).
    wake: Arc<tokio::sync::Notify>,
    /// The connector switch of the try dialing now (or last): a lock or Forget aborts it, so a
    /// dial in flight ends before it subscribes, and a socket already open writes nothing more —
    /// no acknowledgement of what the relay kept for this identity while Kao was away.
    shutdown: Option<ConnectorShutdown>,
}

impl RestoreRun {
    /// The slot no longer wants this run: stop its sleep and abort its dial.
    fn stop(&self) {
        self.wake.notify_one();
        if let Some(shutdown) = &self.shutdown {
            shutdown.abort();
        }
    }
}

struct RestoreWait {
    job: RestoreJob,
    error: String,
    direct_override: bool,
}

impl RestoreState {
    /// When (unix s) a restore with no try under way — waiting for the user, or sleeping until
    /// its next try — has nothing left alive ([`RestoreJob::lapses_at`]). None with no restore,
    /// or while a try runs: that try plans for itself.
    fn lapses_at(&self) -> Option<u64> {
        match self {
            Self::Running(r) if matches!(r.phase, RestorePhase::RetryingAt { .. }) => {
                Some(r.job.lapses_at())
            }
            Self::NeedsYou(w) => Some(w.job.lapses_at()),
            Self::Idle | Self::Running(_) => None,
        }
    }
}

/// Counts only: the restore state holds the saved record.
impl fmt::Debug for RestoreState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => f.write_str("Idle"),
            Self::Running(r) => write!(
                f,
                "Running(run {}, {} sessions, {:?})",
                r.run,
                r.job.record.session_count(),
                r.phase
            ),
            Self::NeedsYou(w) => write!(f, "NeedsYou({} sessions)", w.job.record.session_count()),
        }
    }
}

/// How a restore reaches the relay at each try.
#[derive(Clone)]
enum RestoreDial {
    /// The relay, project id and route in Kao's settings (read again at each try), through Kao's
    /// own connector.
    Settings,
    /// Tests: the in-process relay — under the same client id the saved runtime used.
    #[cfg(test)]
    Test(TestDial),
}

#[cfg(test)]
#[derive(Clone)]
struct TestDial {
    connector: Arc<dyn wallet_connect::relay::Connector>,
    relay_url: url::Url,
    route: RouteKind,
}

/// A test connector behind `shutdown`, as [`KaoConnector`] is behind its own: no dial once closed
/// (a dial in flight is abandoned), and once aborted its connections carry nothing more either
/// way — so the restore tests see what a lock does to a production restore mid-dial.
#[cfg(test)]
fn switched(
    connector: Arc<dyn wallet_connect::relay::Connector>,
    shutdown: ConnectorShutdown,
) -> impl wallet_connect::relay::Connector {
    use wallet_connect::relay::Connection;
    move || {
        let (connector, shutdown) = (connector.clone(), shutdown.clone());
        async move {
            let refused = || wallet_connect::Error::Transport("WalletConnect is shut down".into());
            let conn = tokio::select! {
                conn = connector.connect() => conn?,
                () = shutdown.closed() => return Err(refused()),
            };
            if shutdown.is_closed() {
                return Err(refused());
            }
            let (kao_end, io_end) = Connection::pair();
            let Connection {
                sender: to_relay,
                receiver: mut from_relay,
            } = conn;
            let Connection {
                sender: to_kao,
                receiver: mut from_kao,
            } = io_end;
            let up = shutdown.clone();
            tokio::spawn(async move {
                loop {
                    let frame = tokio::select! {
                        f = from_kao.recv() => f,
                        () = up.aborted() => None,
                    };
                    let Some(f) = frame.filter(|_| !up.is_aborted()) else {
                        break;
                    };
                    if to_relay.send(f).is_err() {
                        break;
                    }
                }
            });
            tokio::spawn(async move {
                loop {
                    let frame = tokio::select! {
                        f = from_relay.recv() => f,
                        () = shutdown.aborted() => None,
                    };
                    let Some(f) = frame.filter(|_| !shutdown.is_aborted()) else {
                        break;
                    };
                    if to_kao.send(f).is_err() {
                        break;
                    }
                }
            });
            Ok(kao_end)
        }
    }
}

impl fmt::Debug for WcSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never blocks: a Debug while the slot is locked just prints the name.
        match self.0.try_lock() {
            Ok(s) => match &s.rt {
                Some(rt) => write!(f, "WcSlot(gen {})", rt.inner.generation),
                None => f.write_str("WcSlot(empty)"),
            },
            Err(_) => f.write_str("WcSlot"),
        }
    }
}

impl WcSlot {
    /// A slot over a vault of its own (tests; the App builds its slot with [`Self::with_vault`]).
    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_vault(Vault::new())
    }

    /// The App's slot, over the App's vault.
    pub fn with_vault(vault: Vault) -> Self {
        Self(Arc::new(Mutex::new(SlotInner {
            vault,
            ..SlotInner::default()
        })))
    }

    /// The vault this slot (and every successor) persists to.
    pub fn vault(&self) -> Vault {
        self.lock().vault.clone()
    }

    fn lock(&self) -> MutexGuard<'_, SlotInner> {
        lock(&self.0)
    }

    pub fn get(&self) -> Option<WcRuntime> {
        self.lock().rt.clone()
    }

    pub fn is_closed(&self) -> bool {
        self.lock().closed
    }

    pub fn is_starting(&self) -> bool {
        self.lock().starting
    }

    /// false when a runtime exists, a start (or a restore) is in flight, or the slot is closed.
    pub fn begin_start(&self) -> bool {
        let mut s = self.lock();
        if s.closed || s.starting || s.rt.is_some() {
            return false;
        }
        s.starting = true;
        true
    }

    pub fn start_failed(&self) {
        self.lock().starting = false;
    }

    /// Ok: installed (and the runtime gets a Weak back-reference for `retire`). Err(rt): closed or
    /// occupied — the caller tears `rt` down.
    pub fn install(&self, rt: WcRuntime) -> Result<(), WcRuntime> {
        let mut s = self.lock();
        s.starting = false;
        if s.closed || s.rt.is_some() {
            debug!(
                generation = rt.inner.generation,
                closed = s.closed,
                "runtime install refused"
            );
            return Err(rt);
        }
        self.install_locked(&mut s, rt);
        Ok(())
    }

    fn install_locked(&self, s: &mut SlotInner, rt: WcRuntime) {
        let _ = rt.inner.slot.set(Arc::downgrade(&self.0));
        // The runtime defers by the slot's holds, and its dashboard looks again when one lifts.
        rt.with_book(|b| b.share_safe_execs(&s.holds));
        let wake = Arc::downgrade(&rt.inner);
        s.holds.on_lift(move || {
            if let Some(inner) = wake.upgrade() {
                WcRuntime { inner }.notify_changed();
            }
        });
        s.rt = Some(rt);
        // A new runtime makes the last one's reason history.
        s.retired = None;
    }

    /// The runtime iff it is still `generation` — a retire never takes a successor's.
    fn take_if_generation(s: &mut SlotInner, generation: u64) -> Option<WcRuntime> {
        s.rt.take_if(|rt| rt.inner.generation == generation)
    }

    #[cfg(test)]
    pub fn take_generation(&self, generation: u64) -> Option<WcRuntime> {
        Self::take_if_generation(&mut self.lock(), generation)
    }

    /// For `retire`: take the runtime iff still `generation` and, under the same lock, record why
    /// (for the dashboard); hands back the registry its teardown is counted in.
    fn retire_generation(&self, generation: u64, notice: RetireNotice) -> Option<Teardowns> {
        let mut s = self.lock();
        Self::take_if_generation(&mut s, generation)?;
        s.retired = Some(notice);
        Some(s.teardowns.clone())
    }

    /// The last retire's reason, once (the dashboard shows it). Also why a restore forgot the
    /// saved sessions without dialing (the relay changed).
    pub fn take_retire_notice(&self) -> Option<RetireNotice> {
        self.lock().retired.take()
    }

    /// Lock / quit: closed forever; returns the runtime to suspend or tear down. A restore in
    /// flight stops (it can no longer install; the saved state stays as it was).
    pub fn close(&self) -> Option<WcRuntime> {
        let mut s = self.lock();
        s.closed = true;
        s.starting = false;
        if let RestoreState::Running(run) = &s.restore {
            run.stop();
        }
        s.restore = RestoreState::Idle;
        s.restore_changed();
        s.rt.take()
    }

    /// The fresh, empty slot that replaces this one on lock. It shares this slot's teardown
    /// registry, so a quit right after a lock still waits for the lock's suspend or teardown (and
    /// an unlock for the old epoch's), its holds on executions still unmined, and the vault — not
    /// the restore state.
    pub fn successor(&self) -> WcSlot {
        let s = self.lock();
        WcSlot(Arc::new(Mutex::new(SlotInner {
            teardowns: s.teardowns.clone(),
            holds: s.holds.clone(),
            vault: s.vault.clone(),
            ..SlotInner::default()
        })))
    }

    /// Mark `rt` closed — synchronously, so nothing it would still send leaves from here on — then
    /// run its bounded teardown on its own tokio handle, counted until it ends. The handle resolves
    /// when it does; dropping it doesn't stop the teardown.
    pub fn spawn_teardown(&self, rt: WcRuntime) -> tokio::task::JoinHandle<()> {
        rt.mark_closed();
        let teardowns = self.lock().teardowns.clone();
        teardowns.spawn(rt)
    }

    /// Teardowns this slot (and its predecessors) still has running.
    #[cfg(test)]
    pub fn teardowns_running(&self) -> usize {
        self.lock().teardowns.running()
    }

    /// Lock / quit with a data key: mark `rt` closed — synchronously, like
    /// [`Self::spawn_teardown`], so a signature still in flight broadcasts nothing — then suspend
    /// it (the sessions stay; the final state goes through `flush`), counted in the teardown
    /// registry until both the suspend and the writer's drain behind `flush` end. The handle
    /// resolves when the suspend does.
    pub fn spawn_suspend(&self, rt: WcRuntime, flush: VaultFlush) -> tokio::task::JoinHandle<()> {
        rt.mark_closed();
        let running = self.lock().teardowns.begin();
        let handle = rt.inner.handle.clone();
        handle.spawn(async move {
            rt.suspend(TEARDOWN_PER_PHASE, flush, Box::new(running))
                .await;
        })
    }

    /// Count a lock's vault-writer drain in the teardown registry (a quit, and the next unlock,
    /// wait for it). Registers synchronously — no tokio needed; the writer thread drops the guard
    /// once it has drained (at once when there is nothing to drain).
    pub fn track_flush(&self, flush: VaultFlush) {
        let running = self.lock().teardowns.begin();
        flush.finish_with(Box::new(running));
    }

    /// Quit: close the slot for good, end its runtime — suspend it when `flush` can persist (the
    /// dapps stay connected for the next launch), else tear it down and count the flush — and
    /// return what the process must wait for before it exits: every teardown still running (this
    /// one, a lock's, a retire's, a writer drain), bounded by `QUIT_TEARDOWN_BUDGET` — or `None`
    /// when nothing is running.
    pub fn quit(&self, flush: VaultFlush) -> Option<impl Future<Output = ()> + Send + use<>> {
        match self.close() {
            Some(rt) if flush.can_persist() => {
                self.spawn_suspend(rt, flush);
            }
            Some(rt) => {
                self.spawn_teardown(rt);
                self.track_flush(flush);
            }
            None => self.track_flush(flush),
        }
        let teardowns = self.lock().teardowns.clone();
        if teardowns.running() == 0 {
            return None;
        }
        let idle = teardowns.idle();
        Some(async move {
            // Bounded: a dead relay can't trap the window open.
            let _ = tokio::time::timeout(QUIT_TEARDOWN_BUDGET, idle).await;
        })
    }

    /// Resolves once nothing in the teardown registry is running (an earlier lock's suspend or
    /// teardown, a writer drain), or after `budget`. Unlock waits on this before it loads.
    pub fn wait_idle(&self, budget: Duration) -> impl Future<Output = ()> + Send + use<> {
        let idle = self.lock().teardowns.idle();
        async move {
            let _ = tokio::time::timeout(budget, idle).await;
        }
    }

    /// The restore the pane shows, while one runs or waits for the user. `sessions` counts the
    /// saved dapps still alive, `pending_disconnects` the disconnects it still owes whose session
    /// is alive — `sessions` 0 with some of those: only a disconnect left to deliver. Both 0: what
    /// it held expired while it waited, and the restore watch ends it
    /// ([`restore_watch_stream`]). Side-effect free: the dashboard polls it from its views.
    pub fn restore_view(&self) -> Option<RestoreView> {
        let now = now_secs();
        match &self.lock().restore {
            RestoreState::Idle => None,
            RestoreState::Running(r) => Some(RestoreView {
                sessions: r.job.live_sessions(now),
                pending_disconnects: r.job.live_unbound(now),
                phase: r.phase.clone(),
            }),
            RestoreState::NeedsYou(w) => Some(RestoreView {
                sessions: w.job.live_sessions(now),
                pending_disconnects: w.job.live_unbound(now),
                phase: RestorePhase::NeedsYou {
                    error: w.error.clone(),
                    direct_override: w.direct_override,
                },
            }),
        }
    }

    /// What the dashboard subscribes to while [`Self::restore_view`] is `Some`: it changes with
    /// every restore phase change, and when the restore ends — including the end its stream
    /// brings to a restore that lapsed ([`restore_watch_stream`]).
    pub fn restore_watch(&self) -> RestoreWatch {
        let s = self.lock();
        RestoreWatch {
            id: s.restore_rev.id,
            rx: s.restore_rev.tx.subscribe(),
            slot: Arc::downgrade(&self.0),
        }
    }

    /// When the restore here lapses ([`RestoreState::lapses_at`]); None once the slot closed.
    fn restore_lapses_at(&self) -> Option<u64> {
        let s = self.lock();
        if s.closed {
            return None;
        }
        s.restore.lapses_at()
    }

    /// End a restore that lapsed — every saved dapp and owed disconnect it held expired while it
    /// waited for the user or for its next try — through the nothing-alive path its next try (or
    /// Retry) would take: each binding ends `Expired`, every signature it still owed is given up,
    /// the open records nothing backs end `Lost`, and the saved state is cleared. A try under
    /// way is left to plan for itself. true iff it ended one.
    ///
    /// The work is in memory (a plan, vault ops queued for the writer), like Forget's.
    fn end_lapsed_restore(&self) -> bool {
        let now = now_secs();
        let (job, runtime_beside) = {
            let mut s = self.lock();
            if s.closed || s.restore.lapses_at().is_none_or(|at| now < at) {
                return false;
            }
            let job = match std::mem::take(&mut s.restore) {
                RestoreState::Running(r) => {
                    s.starting = false;
                    r.stop();
                    r.job
                }
                RestoreState::NeedsYou(w) => w.job,
                RestoreState::Idle => return false,
            };
            s.restore_changed();
            (job, s.rt.is_some())
        };
        let plan = plan_restore(&job.record, now)
            .inspect_err(|why| warn!("wc: {why}; nothing to restore"))
            .ok();
        end_saved_state(
            &job.session,
            &job.record,
            plan.as_ref(),
            EndReason::Lost,
            now,
        );
        if !runtime_beside {
            // A runtime started beside a restore waiting for the user (RESTORE_BUSY) owns its
            // records, as Forget leaves them.
            job.session.end_open_connections_except(
                &[],
                lost_at(&job.record, now),
                EndReason::Lost,
            );
        }
        job.session.clear_wc_state();
        info!(
            ended = plan.as_ref().map_or(0, |p| p.ended.len()),
            "wc: the saved sessions expired while their restore waited"
        );
        true
    }

    /// Dashboard entry: take the saved state from the vault (once per unlock), decide, and return
    /// the restore future to run in `Task::perform` (the loop with backoff), or None.
    ///
    /// No saved state (or none worth restoring) ends any connection record still open — it ended
    /// while Kao was closed. Saved state with nothing alive to dial for is dropped here, at once,
    /// as a try would drop it ([`end_saved_state`]). A configuration that can't start, or a slot
    /// already busy, waits for the user (`RestorePhase::NeedsYou`).
    pub fn begin_restore(&self) -> Option<impl Future<Output = RestoreOutcome> + Send + use<>> {
        self.begin_restore_via(RestoreDial::Settings)
    }

    fn begin_restore_via(
        &self,
        dial: RestoreDial,
    ) -> Option<impl Future<Output = RestoreOutcome> + Send + use<>> {
        let vault = self.vault();
        let session = vault.session();
        {
            let mut s = self.lock();
            if s.closed
                || !session.is_current()
                || s.restore_checked
                    .as_ref()
                    .is_some_and(VaultSession::is_current)
            {
                return None;
            }
            s.restore_checked = Some(session.clone());
            if s.rt.is_some() || s.starting || !matches!(s.restore, RestoreState::Idle) {
                // A runtime got here first: whatever it saves replaces the record.
                return None;
            }
        }
        let now = now_secs();
        let blob = vault.take_wc_state();
        let decoded = blob.as_deref().map(|b| WcStateRecord::decode(b));
        drop(blob);
        // With no readable saved state, nothing says when the open records' sessions went: they
        // end now. With one, at its save ([`lost_at`]).
        let record = match decoded {
            None => {
                session.end_open_connections_except(&[], now, EndReason::Lost);
                return None;
            }
            Some(Err(e)) => {
                warn!("wc: {e}; nothing to restore");
                session.end_open_connections_except(&[], now, EndReason::Lost);
                session.clear_wc_state();
                return None;
            }
            Some(Ok(record)) => record,
        };
        let plan = match plan_restore(&record, now) {
            Ok(plan) => plan,
            Err(why) => {
                warn!("wc: {why}; nothing to restore");
                end_saved_state(&session, &record, None, EndReason::Lost, now);
                session.end_open_connections_except(&[], lost_at(&record, now), EndReason::Lost);
                session.clear_wc_state();
                return None;
            }
        };
        if plan.seed.sessions.is_empty() && plan.work.unbound.is_empty() {
            // No binding alive, and no session the dapps still hold either (one a disconnect
            // never reached is still worth a dial: the restore tells that dapp) — no run.
            end_saved_state(&session, &record, Some(&plan), EndReason::Lost, now);
            session.end_open_connections_except(&[], lost_at(&record, now), EndReason::Lost);
            session.clear_wc_state();
            info!(
                ended = plan.ended.len(),
                "wc: no saved session left to restore"
            );
            return None;
        }
        let expiries: Arc<[u64]> = plan.seed.sessions.iter().map(|s| s.expiry).collect();
        let unbound_expiries: Arc<[u64]> = plan.unbound_expiries.iter().copied().collect();
        // Each try plans again (time passes): the client state this one holds goes now.
        drop(plan);
        let record = Arc::new(record);
        // A configuration that can't start waits for the user (it fails closed, as a paste would).
        let config_error = match &dial {
            RestoreDial::Settings => config_from_settings(0).err().map(|e| e.to_string()),
            #[cfg(test)]
            RestoreDial::Test(_) => None,
        };
        let job = RestoreJob {
            record,
            expiries,
            unbound_expiries,
            session,
            dial,
        };
        let mut s = self.lock();
        if s.closed {
            // Locked meanwhile: the saved state stays for the next unlock.
            return None;
        }
        if let Some(error) = config_error {
            s.restore = RestoreState::NeedsYou(RestoreWait {
                job,
                error,
                direct_override: false,
            });
            s.restore_changed();
            return None;
        }
        if s.starting || s.rt.is_some() {
            s.restore = RestoreState::NeedsYou(RestoreWait {
                job,
                error: RESTORE_BUSY.to_string(),
                direct_override: false,
            });
            s.restore_changed();
            return None;
        }
        let run = Self::start_restore_run(&mut s, job);
        drop(s);
        Some(restore_loop(self.clone(), run, false))
    }

    /// Running, from `job`: one start at a time, so nothing else starts while it runs.
    fn start_restore_run(s: &mut SlotInner, job: RestoreJob) -> u64 {
        s.starting = true;
        s.restore_runs = s.restore_runs.wrapping_add(1);
        let run = s.restore_runs;
        s.restore = RestoreState::Running(RestoreRun {
            run,
            job,
            phase: RestorePhase::Connecting,
            wake: Arc::new(tokio::sync::Notify::new()),
            shutdown: None,
        });
        s.restore_changed();
        run
    }

    /// The user pressed Reconnect (`allow_direct`: Reconnect anyway, over a less private route).
    /// Wakes a loop sleeping until its next try (None), or returns a new restore of saved sessions
    /// waiting for the user.
    pub fn retry_restore(
        &self,
        allow_direct: bool,
    ) -> Option<impl Future<Output = RestoreOutcome> + Send + use<>> {
        let mut s = self.lock();
        match &s.restore {
            RestoreState::Idle => return None,
            RestoreState::Running(r) => {
                if matches!(r.phase, RestorePhase::RetryingAt { .. }) {
                    r.wake.notify_one();
                }
                return None;
            }
            RestoreState::NeedsYou(_) => {}
        }
        if s.closed || s.starting || s.rt.is_some() {
            return None;
        }
        let RestoreState::NeedsYou(wait) = std::mem::take(&mut s.restore) else {
            return None;
        };
        let run = Self::start_restore_run(&mut s, wait.job);
        drop(s);
        Some(restore_loop(self.clone(), run, allow_direct))
    }

    /// Forget the saved sessions without telling the dapps: each one still alive
    /// `ConnectionEnded{Forgotten}` (one that expired meanwhile `Expired`, at its expiry), the
    /// signature deliveries the state carried recorded, every signature it still owed
    /// `NotDelivered`, and the saved state cleared. A try still dialing (`Connecting`) is aborted
    /// and can no longer install — nor disconnect or write anything.
    pub fn forget_restore(&self) {
        let job = {
            let mut s = self.lock();
            let job = match std::mem::take(&mut s.restore) {
                RestoreState::Idle => return,
                RestoreState::Running(r) => {
                    s.starting = false;
                    r.stop();
                    r.job
                }
                RestoreState::NeedsYou(w) => w.job,
            };
            s.restore_changed();
            job
        };
        let now = now_secs();
        let plan = plan_restore(&job.record, now).ok();
        // No `end_open_connections_except` here: a runtime may run beside a restore waiting for
        // the user (RESTORE_BUSY), and its records are its own.
        end_saved_state(
            &job.session,
            &job.record,
            plan.as_ref(),
            EndReason::Forgotten,
            now,
        );
        job.session.clear_wc_state();
        info!(
            sessions = plan.as_ref().map(|p| p.seed.sessions.len()),
            "wc: saved sessions forgotten"
        );
    }

    /// The job of restore run `run`, if it is still the one running (the phase goes back to
    /// Connecting for the try about to start), with what wakes its sleep.
    fn restore_next_try(&self, run: u64) -> Option<(RestoreJob, Arc<tokio::sync::Notify>)> {
        let mut s = self.lock();
        match &mut s.restore {
            RestoreState::Running(r) if r.run == run => {
                r.phase = RestorePhase::Connecting;
                let next = (r.job.clone(), r.wake.clone());
                s.restore_changed();
                Some(next)
            }
            _ => None,
        }
    }

    /// Run `run` failed in a way worth retrying: it sleeps until `at` (unix s). false once it
    /// isn't the run any more.
    fn restore_retrying(&self, run: u64, at: u64, error: String) -> bool {
        let mut s = self.lock();
        match &mut s.restore {
            RestoreState::Running(r) if r.run == run => {
                r.phase = RestorePhase::RetryingAt { at, error };
                s.restore_changed();
                true
            }
            _ => false,
        }
    }

    /// Run `run` stops until the user acts. false once it isn't the run any more.
    fn restore_needs_you(&self, run: u64, error: String, direct_override: bool) -> bool {
        let mut s = self.lock();
        if !matches!(&s.restore, RestoreState::Running(r) if r.run == run) {
            return false;
        }
        let RestoreState::Running(r) = std::mem::take(&mut s.restore) else {
            return false;
        };
        s.starting = false;
        s.restore = RestoreState::NeedsYou(RestoreWait {
            job: r.job,
            error,
            direct_override,
        });
        s.restore_changed();
        true
    }

    /// Run `run` is over with nothing installed (nothing alive to restore, or forgotten for a
    /// changed relay). false once it isn't the run any more.
    fn restore_finished(&self, run: u64, notice: Option<RetireNotice>) -> bool {
        let mut s = self.lock();
        if !matches!(&s.restore, RestoreState::Running(r) if r.run == run) {
            return false;
        }
        s.restore = RestoreState::Idle;
        s.starting = false;
        if notice.is_some() {
            s.retired = notice;
        }
        s.restore_changed();
        true
    }

    /// Install `rt`, restored by run `run` — iff that run still runs and the slot is open and
    /// empty — and end the restore under the same lock. Err(rt): refused; the caller shuts it
    /// down without telling any dapp.
    fn install_restored(&self, rt: WcRuntime, run: u64) -> Result<(), WcRuntime> {
        let mut s = self.lock();
        let ours = matches!(&s.restore, RestoreState::Running(r) if r.run == run);
        if !ours || s.closed || s.rt.is_some() {
            debug!(
                generation = rt.inner.generation,
                closed = s.closed,
                "restored runtime install refused"
            );
            return Err(rt);
        }
        s.restore = RestoreState::Idle;
        s.starting = false;
        self.install_locked(&mut s, rt);
        s.restore_changed();
        Ok(())
    }

    /// Run `run` still runs here (the slot open, not forgotten): the try may go on.
    fn restore_still_runs(&self, run: u64) -> bool {
        let s = self.lock();
        !s.closed && matches!(&s.restore, RestoreState::Running(r) if r.run == run)
    }

    /// Just before run `run`'s try dials: keep its connector switch where a lock or Forget finds
    /// it — iff the run still runs here. false: don't dial.
    fn arm_restore(&self, run: u64, shutdown: ConnectorShutdown) -> bool {
        let mut s = self.lock();
        let closed = s.closed;
        match &mut s.restore {
            RestoreState::Running(r) if r.run == run && !closed => {
                r.shutdown = Some(shutdown);
                true
            }
            _ => false,
        }
    }

    fn teardowns_idle(&self) -> impl Future<Output = ()> + Send + use<> {
        self.lock().teardowns.idle()
    }

    /// Count something in the teardown registry until the guard drops.
    fn begin_teardown(&self) -> Running {
        self.lock().teardowns.begin()
    }

    /// [`Self::begin_restore`] over the in-process relay (`relay_url` / `route` stand for what
    /// the settings would say).
    #[cfg(test)]
    pub(crate) fn begin_restore_over<C: wallet_connect::relay::Connector>(
        &self,
        connector: C,
        relay_url: &str,
        route: RouteKind,
    ) -> Option<impl Future<Output = RestoreOutcome> + Send + use<C>> {
        self.begin_restore_via(RestoreDial::Test(TestDial {
            connector: Arc::new(connector),
            relay_url: url::Url::parse(relay_url).expect("a test relay URL"),
            route,
        }))
    }
}

/// [`WcSlot::begin_restore`] over the in-process relay, run to its end — `Nothing` when it doesn't
/// start. Tests restore under the SAME relay client id the saved runtime used, as production
/// reuses the relay identity: the relay never re-pushes what that id already took.
#[cfg(test)]
pub(crate) async fn restore_with_connector<C: wallet_connect::relay::Connector>(
    slot: &WcSlot,
    connector: C,
    relay_url: &str,
    route: RouteKind,
) -> RestoreOutcome {
    match slot.begin_restore_over(connector, relay_url, route) {
        Some(restore) => restore.await,
        None => RestoreOutcome::Nothing,
    }
}

#[derive(Clone)]
pub struct WcConfig {
    pub relay_url: url::Url,
    pub project_id: Option<String>,
    pub route: Route,
    pub generation: u64,
}

/// The project id goes into the relay's connect URL, so like that URL it is never formatted:
/// presence only.
impl fmt::Debug for WcConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WcConfig")
            .field("relay_host", &self.relay_url.host_str())
            .field("project_id", &self.project_id.as_ref().map(|_| "<set>"))
            .field("route", &self.route)
            .field("generation", &self.generation)
            .finish()
    }
}

/// settings::effective_* + the effective proxy ([`effective_proxy_url`]) + settings::proxy_enabled()
/// → transport::route_for. NeedsProjectId only for the DEFAULT relay without an effective project id.
pub fn config_from_settings(generation: u64) -> Result<WcConfig, StartError> {
    let relay = crate::settings::effective_walletconnect_relay_url();
    let relay_url = url::Url::parse(relay.trim()).map_err(|_| StartError::BadRelayUrl)?;
    let project_id = crate::settings::effective_walletconnect_project_id();
    // The public relay refuses clients without a project id; a self-hosted one may not need it.
    if is_default_relay(&relay_url) && project_id.is_none() {
        return Err(StartError::NeedsProjectId);
    }
    let proxy = effective_proxy_url();
    let route = route_for_effective(&relay_url, proxy.as_ref(), crate::settings::proxy_enabled())
        .map_err(StartError::Route)?;
    Ok(WcConfig {
        relay_url,
        project_id,
        route,
        generation,
    })
}

fn is_default_relay(relay: &url::Url) -> bool {
    let default = wallet_connect::relay::rpc::DEFAULT_RELAY_URL;
    url::Url::parse(default).is_ok_and(|d| {
        d.scheme() == relay.scheme()
            && d.host_str() == relay.host_str()
            && d.port_or_known_default() == relay.port_or_known_default()
    })
}

/// The proxy the relay socket must go through: the one Kao installed this launch, else one the
/// user exported themselves, in the order reqwest reads them for an `https` destination (the relay
/// is `wss`): `HTTPS_PROXY`, `https_proxy`, then `ALL_PROXY`, `all_proxy`. reqwest honours an
/// exported value for every RPC and indexer call even with Kao's own proxy setting off, so
/// WalletConnect must not be the one connection that goes direct. `route_for` tunnels a
/// `socks5h://` value and refuses anything else (an exported `http://` proxy, `socks5://`) rather
/// than dial around it.
///
/// Known gap: reqwest (its `system-proxy` feature, via hyper-util's `Matcher::from_system`) also
/// honours the macOS / Windows *system* HTTPS proxy when nothing is exported. Kao can't read that
/// setting without a direct dependency on hyper-util (or the platform crates behind it), which it
/// doesn't take; with only a system proxy configured the relay dials direct while reqwest proxies.
/// `config_view` then reports no proxy, so the pane says the connection is direct.
fn effective_proxy_url() -> Option<(String, ProxySource)> {
    effective_proxy_source_from(proxy_env::installed_url(), |key| std::env::var(key).ok())
}

/// Where the relay's proxy came from, so a proxy Kao can't use is blamed on the right thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxySource {
    /// Kao's own proxy setting, installed this launch.
    Installed,
    /// The named variable of the environment Kao was launched from.
    Exported(&'static str),
}

/// [`effective_proxy_url`] over an injectable environment (tests never touch the real one).
///
/// An empty value counts as unset. reqwest stops at the first name that is *set* (an empty
/// `HTTPS_PROXY` hides `https_proxy`); skipping empties instead can only route the relay through a
/// proxy where reqwest goes direct — never the other way round.
fn effective_proxy_source_from(
    installed: Option<&str>,
    env: impl Fn(&str) -> Option<String>,
) -> Option<(String, ProxySource)> {
    if let Some(url) = installed {
        return Some((url.to_owned(), ProxySource::Installed));
    }
    // reqwest's order: the https-specific names before ALL_PROXY; upper case wins.
    ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
        .into_iter()
        .find_map(|key| {
            env(key)
                .filter(|v| !v.is_empty())
                .map(|v| (v, ProxySource::Exported(key)))
        })
}

/// [`effective_proxy_source_from`], the proxy alone.
#[cfg(test)]
fn effective_proxy_from(
    installed: Option<&str>,
    env: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    effective_proxy_source_from(installed, env).map(|(url, _)| url)
}

/// [`transport::route_for`] over the effective proxy. A proxy the environment exported (Kao's own
/// setting is off) that can't carry the relay is reported by its variable's name, so the user isn't
/// sent to a Kao setting that has nothing to fix — and the value, which may embed credentials, is
/// never repeated.
fn route_for_effective(
    relay: &url::Url,
    proxy: Option<&(String, ProxySource)>,
    proxy_intent: bool,
) -> Result<Route, RouteError> {
    transport::route_for(relay, proxy.map(|(url, _)| url.as_str()), proxy_intent).map_err(
        |e| match (e, proxy.map(|(_, source)| *source)) {
            (
                RouteError::ProxyScheme | RouteError::ProxyUnparseable,
                Some(ProxySource::Exported(var)),
            ) => RouteError::ExportedProxyUnusable { var },
            (e, _) => e,
        },
    )
}

pub fn config_view() -> WcConfigView {
    let proxy = if effective_proxy_url().is_some() {
        ProxyView::Proxied
    } else if crate::settings::proxy_enabled() {
        ProxyView::RestartPending
    } else {
        ProxyView::None
    };
    WcConfigView {
        project_source: crate::settings::walletconnect_project_source(),
        relay_custom: crate::settings::walletconnect_relay_url(),
        default_relay: wallet_connect::relay::rpc::DEFAULT_RELAY_URL,
        proxy,
    }
}

/// Subscription identity = generation only.
#[derive(Clone)]
pub struct WcEventSource {
    generation: u64,
    rx: Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<WcStreamItem>>>,
    backlog: Arc<Mutex<Backlog>>,
    /// A `Changed` waits in the stream: another one adds nothing (it carries no data, and the
    /// dashboard mirrors the book as it is when it takes one) — see [`WcRuntime::notify_changed`].
    changed_queued: Arc<AtomicBool>,
}

/// Session requests the forwarder handed to the stream that no dashboard has taken yet: counted
/// in by the forwarder ([`Backlog::enter`]), out by [`event_stream`] as a dashboard takes each.
#[derive(Debug, Default)]
struct Backlog {
    total: usize,
    per_session: std::collections::BTreeMap<Topic, usize>,
}

impl Backlog {
    /// Count a request on `topic` in — unless that would pass [`MAX_BACKLOG`] or
    /// [`MAX_BACKLOG_PER_SESSION`].
    fn enter(&mut self, topic: &Topic) -> bool {
        let session = self.per_session.get(topic).copied().unwrap_or(0);
        if self.total >= MAX_BACKLOG || session >= MAX_BACKLOG_PER_SESSION {
            return false;
        }
        self.total += 1;
        *self.per_session.entry(topic.clone()).or_default() += 1;
        true
    }

    /// A dashboard took a request on `topic`.
    fn taken(&mut self, topic: &Topic) {
        self.total = self.total.saturating_sub(1);
        if let Some(n) = self.per_session.get_mut(topic) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.per_session.remove(topic);
            }
        }
    }
}

fn lock_backlog(backlog: &Mutex<Backlog>) -> MutexGuard<'_, Backlog> {
    backlog.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Hash for WcEventSource {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.generation.hash(h)
    }
}

impl fmt::Debug for WcEventSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WcEventSource(gen {})", self.generation)
    }
}

/// `+ use<>` is REQUIRED: in edition 2024 the opaque type would otherwise capture `src`'s lifetime,
/// and an iced subscription needs a `'static` stream. `unfold(rx, |rx| lock().await.recv().await)`;
/// `recv` is cancel-safe, so a stream dropped mid-`recv` (iced cancelling the subscription) loses
/// nothing: items buffer in the unbounded channel until a stream polls again. The stream ends once
/// the runtime is gone (every sender dropped).
pub fn event_stream(
    src: &WcEventSource,
) -> impl futures::Stream<Item = (u64, WcStreamItem)> + Send + use<> {
    let generation = src.generation;
    let state = (
        src.rx.clone(),
        src.backlog.clone(),
        src.changed_queued.clone(),
    );
    futures::stream::unfold(state, move |(rx, backlog, changed)| async move {
        let item = rx.lock().await.recv().await?;
        match &item {
            WcStreamItem::Request { req, .. } => lock_backlog(&backlog).taken(&req.topic),
            WcStreamItem::Changed => changed.store(false, Ordering::SeqCst),
            WcStreamItem::Ui(_) => {}
        }
        Some(((generation, item), (rx, backlog, changed)))
    })
}

#[derive(Clone)]
pub struct WcRuntime {
    inner: Arc<Inner>,
}

struct Inner {
    client: SignClient,
    book: Mutex<WcBook>,
    closed: AtomicBool,
    generation: u64,
    route: RouteKind,
    /// iced's tokio runtime, captured in `start`: every network effect is spawned here.
    handle: tokio::runtime::Handle,
    notify: UnboundedSender<WcStreamItem>,
    source: WcEventSource,
    /// The slot this runtime was installed in — `retire` takes itself out of it.
    slot: OnceLock<Weak<Mutex<SlotInner>>>,
    /// Held across `approve_with` → `bind_session`; the forwarder takes it before handing a request
    /// to the dashboard, so no request can overtake its session's binding.
    approve_gate: tokio::sync::Mutex<()>,
    /// Kao's connector's off switch, closed by `mark_closed`: a reconnect the crate has in flight
    /// can't reach the relay after lock / quit / retire. `None` for a test connector.
    connector_shutdown: Option<ConnectorShutdown>,
    /// The vault epoch this runtime was started (or restored) in: its history and saved state go
    /// here, and nowhere once that epoch has ended.
    vault: VaultSession,
    /// The relay identity's seed, saved with the sessions: a restore over the same kind of route
    /// reuses it, so the relay doesn't push again what this identity already took.
    identity_seed: Zeroizing<[u8; 32]>,
    /// The relay's origin (scheme, host, port), saved with the sessions: a restore against another
    /// relay can't reach them.
    relay_url: String,
    persist: PersistState,
}

/// When and how the runtime saves its state.
#[derive(Default)]
struct PersistState {
    /// A save is spawned and hasn't begun: another `Now` adds nothing.
    scheduled: AtomicBool,
    /// When the state first changed since the last save, for a `Soon` (the housekeeper saves it
    /// [`PERSIST_SOON_AFTER`] later) — or for any change while the vault session can't persist
    /// yet, kept until it can.
    dirty_since: Mutex<Option<Instant>>,
    /// A change came while the vault session couldn't persist (a keyless epoch): the housekeeper
    /// saves at its first tick once the session gets its data key — "Reset saved history and
    /// connections…", or the wallet's first save — whatever `Persist` the change asked for.
    awaiting_key: AtomicBool,
    /// Held across a whole save — capture, encode, hand to the vault — and taken by Turn off once
    /// the runtime is closed: a save already under way lands before Turn off's clear, and none
    /// starts after it.
    saving: Mutex<()>,
    /// History a restored runtime makes before it is installed, applied at install — or dropped
    /// with a restore the slot refused, which must leave the vault as it was. `None`: recorded as
    /// it comes.
    held: Mutex<Option<Vec<LogEffect>>>,
    /// Message signature deliveries learned once the runtime closed or its vault epoch ended (a
    /// lock's suspend delivered an answer, a dapp stopped waiting meanwhile): the vault session
    /// can no longer take them, so the state the suspend saves carries them to the next unlock.
    late_deliveries: Mutex<Vec<PersistedDelivery>>,
}

/// What [`WcRuntime::start_inner`] builds a runtime from, besides its connector.
struct StartParts {
    generation: u64,
    route: RouteKind,
    connector_shutdown: Option<ConnectorShutdown>,
    vault: VaultSession,
    identity_seed: Zeroizing<[u8; 32]>,
    relay_url: String,
    /// A restore: the client state to resume, and the bindings to seed the book with before the
    /// forwarder runs.
    restore: Option<(Snapshot, BookSeed)>,
}

impl StartParts {
    /// A fresh test runtime over the in-process relay: persists nowhere (a dead vault session).
    #[cfg(test)]
    fn test(
        generation: u64,
        route: RouteKind,
        connector_shutdown: Option<ConnectorShutdown>,
    ) -> Self {
        Self {
            generation,
            route,
            connector_shutdown,
            vault: Vault::new().session(),
            identity_seed: Zeroizing::new(IdentityKey::generate().seed()),
            relay_url: TEST_RELAY_URL.to_string(),
            restore: None,
        }
    }
}

impl fmt::Debug for WcRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WcRuntime(gen {})", self.inner.generation)
    }
}

/// The relay as the saved state keeps it: its origin (scheme, host, port) — never the path or the
/// query.
fn relay_origin(relay: &url::Url) -> String {
    relay.origin().ascii_serialization()
}

/// `a` and `b` are one relay: scheme, host and port (as [`is_default_relay`] compares them) — what
/// a restore checks the saved sessions' relay against the configured one with. A URL that doesn't
/// parse is never the same relay.
pub fn same_relay(a: &str, b: &str) -> bool {
    match (url::Url::parse(a), url::Url::parse(b)) {
        (Ok(a), Ok(b)) => {
            a.scheme() == b.scheme()
                && a.host_str() == b.host_str()
                && a.port_or_known_default() == b.port_or_known_default()
        }
        _ => false,
    }
}

/// How private a route is: a proxy (or a relay on this computer) hides Kao's IP; a direct dial
/// shows it.
fn privacy(route: RouteKind) -> u8 {
    match route {
        RouteKind::Direct => 0,
        RouteKind::Proxied | RouteKind::Loopback => 1,
    }
}

impl WcRuntime {
    /// A fresh relay identity; KaoConnector::new(cfg.relay_url, cfg.project_id, identity, cfg.route,
    /// Timeouts::for_route(&cfg.route)); start_inner(..). `vault`: the epoch it persists to.
    pub async fn start(cfg: WcConfig, vault: VaultSession) -> Result<WcRuntime, String> {
        // A fresh start gets a fresh relay identity. Its seed is saved with the sessions it makes
        // (they link it anyway), and only a restore of those, over the same kind of route, reuses it.
        let identity = IdentityKey::generate();
        let identity_seed = Zeroizing::new(identity.seed());
        let kind = transport::route_kind(&cfg.relay_url, &cfg.route);
        let relay_url = relay_origin(&cfg.relay_url);
        let timeouts = Timeouts::for_route(&cfg.route);
        let connector =
            KaoConnector::new(cfg.relay_url, cfg.project_id, identity, cfg.route, timeouts);
        let shutdown = connector.shutdown_handle();
        Self::start_inner(
            connector,
            StartParts {
                generation: cfg.generation,
                route: kind,
                connector_shutdown: Some(shutdown),
                vault,
                identity_seed,
                relay_url,
                restore: None,
            },
        )
        .await
    }

    /// A runtime over any connector — the tests' path (`RelayServer::connector`). Production starts
    /// through [`Self::start`], whose `KaoConnector` is also switched off by `mark_closed`. Persists
    /// nowhere (a dead vault session).
    #[cfg(test)]
    pub async fn start_with_connector<C: wallet_connect::relay::Connector>(
        connector: C,
        generation: u64,
        route: RouteKind,
    ) -> Result<WcRuntime, String> {
        Self::start_inner(connector, StartParts::test(generation, route, None)).await
    }

    /// [`Self::start_with_connector`], persisting to `vault`'s epoch.
    #[cfg(test)]
    pub async fn start_with_connector_in<C: wallet_connect::relay::Connector>(
        connector: C,
        generation: u64,
        route: RouteKind,
        vault: VaultSession,
    ) -> Result<WcRuntime, String> {
        Self::start_inner(
            connector,
            StartParts {
                vault,
                ..StartParts::test(generation, route, None)
            },
        )
        .await
    }

    /// `Handle::try_current()` (no runtime → Err); SignClient::builder(kao_metadata()).connector(c)
    /// .relay_options(RelayClientOptions{ request_timeout: 15 s, reconnect: true, max_backoff: 30 s })
    /// (+ the snapshot to resume, for a restore).build(); a restore's book is seeded HERE, before
    /// the FORWARDER (Weak) and HOUSEKEEPER (Weak, 1 s) are spawned — what the relay delivered
    /// while Kao was away is already waiting for them.
    async fn start_inner<C: wallet_connect::relay::Connector>(
        connector: C,
        parts: StartParts,
    ) -> Result<WcRuntime, String> {
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| "WalletConnect needs Kao's async runtime.".to_string())?;
        let StartParts {
            generation,
            route,
            connector_shutdown,
            vault,
            identity_seed,
            relay_url,
            restore,
        } = parts;
        let (snapshot, seed) = match restore {
            Some((snapshot, seed)) => (Some(snapshot), Some(seed)),
            None => (None, None),
        };
        let mut builder = SignClient::builder(kao_metadata())
            .connector(connector)
            .relay_options(RelayClientOptions {
                request_timeout: RELAY_REQUEST_TIMEOUT,
                reconnect: true,
                max_backoff: RELAY_MAX_BACKOFF,
            });
        if let Some(snapshot) = snapshot {
            builder = builder.snapshot(snapshot);
        }
        let (client, sign_rx) = builder.build().await.map_err(|e| {
            // The connector's own errors are already redacted; redact again in case the
            // crate wrapped something with a URL in it.
            let why = match e {
                wallet_connect::Error::Transport(m) => m,
                other => other.to_string(),
            };
            format!(
                "Couldn't reach the relay: {}",
                transport::redact_transport_error(&why)
            )
        })?;
        let mut book = WcBook::new();
        let restored = seed.is_some();
        if let Some(seed) = seed {
            book.seed(seed);
        }
        let (tx, rx) = unbounded_channel();
        let inner = Arc::new(Inner {
            client,
            book: Mutex::new(book),
            closed: AtomicBool::new(false),
            generation,
            route,
            handle: handle.clone(),
            notify: tx.clone(),
            source: WcEventSource {
                generation,
                rx: Arc::new(tokio::sync::Mutex::new(rx)),
                backlog: Arc::default(),
                changed_queued: Arc::default(),
            },
            slot: OnceLock::new(),
            approve_gate: tokio::sync::Mutex::new(()),
            connector_shutdown,
            vault,
            identity_seed,
            relay_url,
            persist: PersistState {
                held: Mutex::new(restored.then(Vec::new)),
                ..PersistState::default()
            },
        });
        handle.spawn(forward(Arc::downgrade(&inner), sign_rx, tx));
        handle.spawn(housekeeping(Arc::downgrade(&inner)));
        info!(
            generation,
            ?route,
            restored,
            "WalletConnect runtime started"
        );
        Ok(WcRuntime { inner })
    }

    pub fn generation(&self) -> u64 {
        self.inner.generation
    }

    /// Why this runtime may connect no new dapp, if it may not: it dials its relay directly while
    /// Kao's proxy setting (`proxy_intent`) is on — the proxy applies from the next launch, and a
    /// start now would be refused for the same reason. Dapps already connected stay.
    pub fn route_refusal(&self, proxy_intent: bool) -> Option<RouteError> {
        (proxy_intent && self.inner.route == RouteKind::Direct)
            .then_some(RouteError::RestartPending)
    }

    pub fn events(&self) -> WcEventSource {
        self.inner.source.clone()
    }

    /// Short critical section; NEVER hold across .await.
    pub fn with_book<R>(&self, f: impl FnOnce(&mut WcBook) -> R) -> R {
        let mut book = lock(&self.inner.book);
        f(&mut book)
    }

    pub fn snapshot(&self, now: u64) -> WcSnapshot {
        let mut snap = self.with_book(|b| b.snapshot(now));
        snap.generation = self.inner.generation;
        snap.route = self.inner.route;
        snap.relay_url = self.inner.relay_url.clone();
        snap
    }

    /// The raw proposal behind the card (for `plan_proposal`).
    pub fn card_proposal(&self) -> Option<Proposal> {
        self.with_book(|b| b.proposal().map(|c| c.proposal.clone()))
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    pub fn mark_closed(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        if let Some(s) = &self.inner.connector_shutdown {
            s.close();
        }
    }

    /// !closed ∧ state ∈ {InReview, Signing} ∧ gone.is_none() ∧ (no dapp deadline ∨ now + 5 < deadline)
    /// ∧ client.pending_requests() contains (key.topic, key.id).
    pub fn is_live(&self, key: &WcKey) -> bool {
        if self.is_closed() {
            return false;
        }
        let now = now_secs();
        let in_book = self.with_book(|b| {
            b.request(key).is_some_and(|q| {
                matches!(
                    q.state,
                    QueueState::InReview { .. } | QueueState::Signing { .. }
                ) && q.gone.is_none()
                    && q.dapp_deadline
                        .is_none_or(|d| now.saturating_add(EXPIRY_MARGIN_SECS) < d)
            })
        });
        // The crate sweeps expiries up to 5 s late and forgets requests of deleted sessions
        // silently — it must still hold this exact (topic, id).
        in_book && self.client_holds(key)
    }

    /// The client still holds request `key` (unanswered, unexpired, its session alive).
    fn client_holds(&self, key: &WcKey) -> bool {
        self.inner
            .client
            .pending_requests()
            .iter()
            .any(|p| p.id == key.id && p.topic == key.topic)
    }

    /// `Arc::new(move || if rt.is_live(&key) { Ok(()) } else { Err(STILL_WANTED_REFUSAL.into()) })`.
    ///
    /// Holds the runtime weakly: once the runtime is gone, the guard refuses.
    pub fn before_send_guard(&self, key: WcKey) -> crate::sign::broadcast::BeforeSend {
        let weak = Arc::downgrade(&self.inner);
        Arc::new(move || {
            let live = weak
                .upgrade()
                .is_some_and(|inner| WcRuntime { inner }.is_live(&key));
            if live {
                Ok(())
            } else {
                Err(crate::sign::broadcast::STILL_WANTED_REFUSAL.to_string())
            }
        })
    }

    /// Gone if !is_live; else the noted class (taken) or Retryable.
    pub fn failure_class(&self, key: &WcKey) -> FailureClass {
        if !self.is_live(key) {
            return FailureClass::Gone;
        }
        self.with_book(|b| b.take_failure(key))
            .unwrap_or(FailureClass::Retryable)
    }

    pub fn note_failure(&self, key: &WcKey, class: FailureClass) {
        self.with_book(|b| b.note_failure(key, class));
    }

    /// [`WcBook::note_unconfirmed`] — saved at once: a restore must then tell the dapp
    /// "unconfirmed", never "cancelled".
    pub fn note_unconfirmed(&self, key: &WcKey, tx: UnconfirmedTx) {
        self.with_book(|b| b.note_unconfirmed(key, tx));
        self.schedule_persist();
    }

    /// [`WcBook::void_unconfirmed`].
    pub fn void_unconfirmed(&self, key: &WcKey, hash: alloy::primitives::B256) {
        let fx = self.with_book(|b| b.void_unconfirmed(key, hash, now_secs()));
        self.apply_background(fx);
    }

    /// [`WcBook::hold_safe_exec`] until `settled` resolves with how `executor`'s execution ended
    /// (mined or replaced, or given up on), then lift it — which wakes the dashboard of whichever
    /// runtime is installed by then, whose pump looks again. The hold is the slot's ([`SafeExecHolds`]), not
    /// this runtime's: its watch runs on until it settles, through Turn off, an idle retire or a
    /// lock, so a dapp paired again meanwhile can't pin the same nonce. A nonce already held keeps
    /// its running watch and `settled` is dropped unpolled; a hold that goes first (`executor`
    /// refused as invalid on any node) drops it mid-watch.
    pub fn hold_safe_exec(
        &self,
        safe: crate::wallet::SafeKey,
        nonce: u64,
        executor: alloy::primitives::B256,
        settled: impl Future<Output = HoldEnd> + Send + 'static,
    ) {
        let Some((holds, gone)) = self.with_book(|b| {
            let gone = b.hold_safe_exec(safe, nonce, executor, now_secs())?;
            Some((b.safe_execs(), gone))
        }) else {
            return;
        };
        debug!(
            nonce,
            "wc: holding the Safe's next transaction until this execution is mined"
        );
        self.inner.handle.spawn(async move {
            tokio::select! {
                end = settled => {
                    holds.release(safe, nonce, executor, end, now_secs());
                }
                // Lifted already, or taken over by a later execution's hold: nothing left to watch.
                _ = gone => {}
            }
        });
    }

    // ── effect-executing ops: sync; network work spawned on the runtime's handle ──

    /// Runs `fx.net` on the runtime and records `fx.log` / `fx.persist`; hands `fx.ui` back to
    /// the (dashboard) caller.
    pub fn apply(&self, fx: Effects) -> Vec<UiEffect> {
        for e in fx.net {
            self.spawn_net(e);
        }
        self.record(fx.log, fx.persist);
        fx.ui
    }

    pub fn admit(
        &self,
        req: &PendingRequest,
        received_at: u64,
        admitted: Result<Admitted, Refusal>,
    ) -> Vec<UiEffect> {
        if self.is_closed() {
            return Vec::new();
        }
        let fx = self.with_book(|b| b.on_request(req, received_at, admitted, now_secs()));
        self.apply(fx)
    }

    /// parse_pairing_uri → expect_pairing (BEFORE the network) → spawn client.pair(uri).
    pub fn pair(&self, uri: zeroize::Zeroizing<String>, now: u64) -> Result<(), &'static str> {
        if self.is_closed() {
            return Err(request::RUNTIME_CLOSED);
        }
        let parsed = request::parse_pairing_uri(&uri, now)?;
        let superseded = self.with_book(|b| {
            if b.connect_blocked() {
                return None;
            }
            // A paste still waiting for its proposal gives way to this one (the user gave up on it).
            let fx = b.supersede_pairing(&parsed.topic);
            // Registered before anything reaches the relay, so the proposal it brings — which the
            // relay may deliver before `pair` even returns — finds its paste.
            b.expect_pairing(parsed.topic.clone(), now, parsed.expiry);
            Some(fx)
        });
        let Some(superseded) = superseded else {
            return Err("Finish the current connection request first.");
        };
        self.apply_background(superseded);
        let rt = self.clone();
        let topic = parsed.topic;
        self.inner.handle.spawn(async move {
            // `uri` (it carries the symKey) is zeroized when this task drops it.
            let result =
                match tokio::time::timeout(RESPOND_TIMEOUT, rt.inner.client.pair(&uri)).await {
                    Ok(r) => r.map(|_| ()),
                    Err(_) => Err(wallet_connect::Error::Timeout),
                };
            drop(uri);
            rt.with_book(|b| match &result {
                Ok(()) => b.pairing_started(&topic, now_secs()),
                Err(e) => b.pairing_failed(&topic, request::pairing_uri_error(e).to_string()),
            });
            if let Err(e) = &result {
                debug!(kind = error_kind(e), "pairing failed");
            }
            rt.apply_background(Effects {
                changed: true,
                ..Default::default()
            });
        });
        Ok(())
    }

    /// begin_approve → spawn { approve_gate; ticket.matches(proposals()); approve_with; bind_session;
    /// release gate; await ack → on_ack }.
    pub fn approve(&self, ticket: ApproveTicket) -> Result<(), &'static str> {
        if self.is_closed() {
            return Err(request::RUNTIME_CLOSED);
        }
        let proposal = self.with_book(|b| b.begin_approve(ticket.proposal_id))?;
        if !ticket.matches(&proposal) {
            let fx = self.with_book(|b| b.approve_failed(ticket.proposal_id, CHANGED.to_string()));
            self.apply_background(fx);
            return Err(CHANGED);
        }
        let rt = self.clone();
        self.inner.handle.spawn(async move {
            let ack = rt.approve_task(&ticket).await;
            let Some((topic, ack)) = ack else {
                return;
            };
            // The settle ack can take minutes: don't keep the runtime alive for it.
            let weak = Arc::downgrade(&rt.inner);
            drop(rt);
            let result = match ack.await {
                Ok(()) => Ok(()),
                Err(wallet_connect::Error::Peer(e)) => {
                    // The code only: the message is the dapp's own text.
                    info!(code = e.code, "wc: the dapp refused the session settlement");
                    Err(AckFailure::Refused)
                }
                Err(wallet_connect::Error::Closed) => Err(AckFailure::Closed),
                Err(_) => Err(AckFailure::Timeout),
            };
            if let Some(inner) = weak.upgrade() {
                let rt = WcRuntime { inner };
                let fx = rt.with_book(|b| b.on_ack(&topic, result));
                rt.apply_background(fx);
            }
        });
        Ok(())
    }

    /// Approve under the gate; on success returns the session topic and its settle-ack future.
    async fn approve_task(
        &self,
        ticket: &ApproveTicket,
    ) -> Option<(Topic, wallet_connect::sign::Pending<()>)> {
        let id = ticket.proposal_id;
        let _gate = self.inner.approve_gate.lock().await;
        if self.is_closed() {
            return None;
        }
        // The proposal the user saw must still be the one in the client: the crate keys proposals
        // by id alone, so a colliding id from another pairing would replace it silently.
        if !self
            .inner
            .client
            .proposals()
            .iter()
            .any(|p| ticket.matches(p))
        {
            let fx = self.with_book(|b| b.approve_failed(id, CHANGED.to_string()));
            self.apply_background(fx);
            return None;
        }
        // While the relay reconnects, the approve's first network step fails before anything is
        // published: not trying is the same outcome, minus the doubt — the card stays for a retry.
        // A failure after this point is sorted out below by what the crate still holds.
        if !self.inner.client.relay().is_connected() {
            let fx = self.with_book(|b| b.approve_failed(id, RECONNECTING.to_string()));
            self.apply_background(fx);
            return None;
        }
        let params = ApproveParams {
            id,
            namespaces: ticket.grant.namespaces.clone(),
            // Never echoed: the approval carries only what Kao grants, not the dapp's unchecked
            // properties.
            session_properties: None,
            scoped_properties: None,
        };
        match self.inner.client.approve_with(params).await {
            Ok(approved) => {
                let topic = approved.session.topic.clone();
                // Under `saving`, as Turn off's `forget_saved` ends the history: it either finds
                // this session bound (and ends its record), or closed the runtime first — then
                // the record opened here ends here, as Turn off would have ended it. (After a
                // lock the vault epoch is over and drops both; the next restore repairs a live
                // session's record.)
                let saving = lock(&self.inner.persist.saving);
                let mut fx =
                    self.with_book(|b| b.bind_session(&approved.session, ticket, now_secs()));
                if self.is_closed() {
                    fx.log.push(LogEffect::ConnectionEnded {
                        topic: topic.to_string(),
                        at: now_secs(),
                        reason: EndReason::TurnedOff,
                    });
                }
                self.record_log(std::mem::take(&mut fx.log));
                drop(saving);
                self.apply_background(fx);
                info!(
                    generation = self.inner.generation,
                    "WalletConnect session approved"
                );
                Some((topic, approved.acknowledged))
            }
            Err(e) => {
                debug!(kind = error_kind(&e), "approve failed");
                // The crate answers a proposal for good once that answer may have reached the
                // dapp, and keeps (returns `Ok`) any session whose settle may have. So a failure
                // that leaves the proposal in the client sent the dapp nothing it could act on.
                let still_held = self
                    .inner
                    .client
                    .proposals()
                    .iter()
                    .any(|p| ticket.matches(p));
                let fx = match e {
                    // Refused before anything reached the dapp: the card stays, with the reason.
                    wallet_connect::Error::NoProposal(_) | wallet_connect::Error::Expired(_) => {
                        self.with_book(|b| b.approve_failed(id, CHANGED.to_string()))
                    }
                    // The relay refused the answer or never got it: approving again is safe.
                    _ if still_held => {
                        self.with_book(|b| b.approve_failed(id, NOTHING_SENT.to_string()))
                    }
                    // The answer may have reached the dapp but the settle surely didn't: the dapp
                    // holds no session, and the proposal is spent, so there is nothing to retry.
                    // The card goes; the user reconnects from the dapp.
                    _ => self.with_book(|b| b.approve_abandoned(id)),
                };
                self.apply_background(fx);
                None
            }
        }
    }

    pub fn reject_proposal(&self, id: u64, error: ErrorObject) {
        if self.with_book(|b| b.begin_reject(id)) {
            self.spawn_net(NetEffect::RejectProposal { id, error });
        }
    }

    pub fn answer(&self, key: &WcKey, answer: Answer) -> Vec<UiEffect> {
        let fx = self.with_book(|b| b.answer(key, answer));
        self.apply(fx)
    }

    pub fn disconnect(&self, topic: &Topic) -> Vec<UiEffect> {
        let fx = self.with_book(|b| b.user_disconnect(topic, GoneReason::UserDisconnected));
        self.apply(fx)
    }

    pub fn reject_all_from(&self, topic: &Topic) -> Vec<UiEffect> {
        let fx = self.with_book(|b| b.reject_all_from(topic));
        self.apply(fx)
    }

    pub fn resume(&self, topic: &Topic) {
        let fx = self.with_book(|b| b.resume(topic));
        self.apply_background(fx);
    }

    pub fn reconcile(&self, available: &[WcIdentity]) -> Vec<UiEffect> {
        let fx = self.with_book(|b| b.reconcile(available));
        self.apply(fx)
    }

    pub fn flush_outbox(&self) {
        for e in self.with_book(WcBook::undelivered) {
            self.spawn_net(e);
        }
    }

    /// Take from the slot (Weak) iff still this generation — recording the reason there for the
    /// dashboard — mark closed, end the history of every session and clear the saved state (Turn
    /// off forgets the dapps it disconnects; an idle or flapping retire has none), spawn the
    /// (counted) teardown, and wake the dashboard, which reads the reason from the slot.
    pub fn retire(&self, reason: &str) {
        if self.is_closed() {
            return;
        }
        let flapping = reason == FLAP_RETIRE_REASON;
        let notice = RetireNotice {
            text: reason.to_string(),
            error: flapping,
        };
        let teardowns = match self.inner.slot.get().map(Weak::upgrade) {
            // Never installed, or the App that owned the slot is gone: nobody else tears it down.
            None | Some(None) => None,
            Some(Some(slot)) => {
                match WcSlot(slot).retire_generation(self.inner.generation, notice) {
                    Some(teardowns) => Some(teardowns),
                    // A lock / quit closed the slot first and is suspending (or tearing down)
                    // this runtime already.
                    None => return,
                }
            }
        };
        self.mark_closed();
        if teardowns.is_some() {
            // Synchronously, before the teardown: whatever saves later, nothing can bring these
            // sessions back.
            self.forget_saved(EndReason::TurnedOff);
        }
        info!(
            generation = self.inner.generation,
            reason, "WalletConnect retired"
        );
        // Only a wake-up: this runtime is out of the slot already, so the dashboard drops every
        // item it still sends and takes the reason from the slot instead.
        self.notify_changed();
        match teardowns {
            // Counted, so a quit right after still waits for the dapps to be told.
            Some(teardowns) => {
                teardowns.spawn(self.clone());
            }
            None => {
                self.inner
                    .handle
                    .spawn(self.clone().teardown(TEARDOWN_PER_PHASE));
            }
        }
    }

    /// A closed runtime's sessions leave the history (`reason`) and the saved state is cleared —
    /// after any save already under way (it holds `saving`), and before any later one could
    /// start (they see `closed` first).
    fn forget_saved(&self, reason: EndReason) {
        let _saving = lock(&self.inner.persist.saving);
        let topics: Vec<String> =
            self.with_book(|b| b.sessions().iter().map(|s| s.topic.to_string()).collect());
        let now = now_secs();
        for topic in &topics {
            self.inner.vault.connection_ended(topic, now, reason);
        }
        self.inner.vault.clear_wc_state();
    }

    /// closed=true; wait out an approve in flight; book.teardown(); answers (≤ per_phase, less that
    /// wait) → disconnects (≤ per_phase) → shutdown(). Saves nothing: the saved state is cleared by
    /// whoever ends the sessions this way (Turn off), or was never written (no data key). How each
    /// answer's delivery ended is booked, so a message signature's history learns it — and an
    /// answer the last try didn't deliver is given up (`NotDelivered`): nothing sends it again.
    pub async fn teardown(self, per_phase: Duration) {
        self.mark_closed();
        // An approve may already have published its settle and be waiting for the relay's ack:
        // the dapp holds that session, and if the book were snapshotted now (a busy card, nothing
        // bound) it would get no disconnect. So wait for the approve to bind it first — bounded,
        // and charged to the answers phase so the whole teardown stays within its budget. An
        // approve that only takes the gate after this sees `closed` and does nothing.
        let started = tokio::time::Instant::now();
        let gate = tokio::time::timeout(per_phase, self.inner.approve_gate.lock()).await;
        let fx = self.with_book(WcBook::teardown);
        drop(gate);
        let answers_budget = per_phase.saturating_sub(started.elapsed());
        for e in fx.ui {
            let _ = self.inner.notify.send(WcStreamItem::Ui(e));
        }
        self.notify_changed();
        self.record_log(fx.log);
        let this = &self;
        let client = &self.inner.client;
        let mut answers = Vec::new();
        let mut disconnects = Vec::new();
        for e in fx.net {
            match e {
                NetEffect::Respond { key, answer } => {
                    answers.push(futures::future::Either::Left(async move {
                        let result = this.respond_once(&key, answer, per_phase).await;
                        debug!(
                            id = key.id,
                            ok = matches!(result, RespondResult::Delivered),
                            "teardown answer"
                        );
                        // A message signature's delivery reaches the history (Turn off's epoch
                        // is still current; otherwise it is kept as a late delivery).
                        let fx = this.with_book(|b| b.on_responded(&key, result));
                        this.record_log(fx.log);
                    }))
                }
                NetEffect::RejectProposal { id, error } => {
                    answers.push(futures::future::Either::Right(async move {
                        let r = tokio::time::timeout(per_phase, client.reject(id, error)).await;
                        debug!(id, ok = matches!(r, Ok(Ok(()))), "teardown reject");
                    }))
                }
                NetEffect::Disconnect { topic } => disconnects.push(async move {
                    let r = tokio::time::timeout(per_phase, client.disconnect(&topic)).await;
                    debug!(ok = matches!(r, Ok(Ok(()))), "teardown disconnect");
                }),
                // Pairings and events die with the client.
                NetEffect::DeletePairing { .. }
                | NetEffect::Emit { .. }
                | NetEffect::Retire { .. } => {}
            }
        }
        let _ = tokio::time::timeout(answers_budget, futures::future::join_all(answers)).await;
        let _ = tokio::time::timeout(per_phase, futures::future::join_all(disconnects)).await;
        client.shutdown();
        // Shut down first: no answer still on its way can be delivered after it is given up.
        let fx = self.with_book(WcBook::abandon_outbox);
        self.record_log(fx.log);
        info!(
            generation = self.inner.generation,
            "WalletConnect runtime torn down"
        );
    }

    /// Lock / quit with a data key (`mark_closed` already done, synchronously, by
    /// `WcSlot::spawn_suspend`): wait out an approve in flight; `book.suspend()` — requests answered
    /// as by a teardown, **no** disconnect; an early save through `flush` (so a good record
    /// exists even if the tail is cut); the answers phase (gate wait + answers ≤ `per_phase`);
    /// `client.shutdown()`; the final save — the client state as shut down, the bindings, the
    /// answers still owed — through `flush`; then `flush.finish_with(guard)`, so `guard` (the
    /// teardown registry's count) drops only once the writer has drained. ≤ 2 × `per_phase`.
    ///
    /// History it makes is dropped by the vault's epoch check — the epoch ended with the lock; the
    /// next restore ends whatever that leaves open and opens a record for a live session that has
    /// none. Signature deliveries it learns are kept instead, as late deliveries, and go
    /// out with the final save, for the next unlock to record. Owed disconnects get a last try.
    pub async fn suspend(self, per_phase: Duration, flush: VaultFlush, guard: Box<dyn Send>) {
        self.mark_closed();
        let started = tokio::time::Instant::now();
        let gate = tokio::time::timeout(per_phase, self.inner.approve_gate.lock()).await;
        let (fx, early) = {
            let mut book = lock(&self.inner.book);
            let fx = book.suspend();
            let early = flush.can_persist().then(|| self.record_of(&book));
            (fx, early)
        };
        drop(gate);
        if let Some(record) = early {
            flush.save_wc_state(record.encode());
        }
        let answers_budget = per_phase.saturating_sub(started.elapsed());
        for e in fx.ui {
            let _ = self.inner.notify.send(WcStreamItem::Ui(e));
        }
        self.notify_changed();
        self.record_log(fx.log);
        let this = &self;
        let mut answers: Vec<futures::future::BoxFuture<'_, ()>> = Vec::new();
        for e in fx.net {
            match e {
                NetEffect::Respond { key, answer } => answers.push(Box::pin(async move {
                    let result = this.respond_once(&key, answer, per_phase).await;
                    // Delivered → out of the owed answers the final save keeps (and into its
                    // late deliveries, for a message signature).
                    let fx = this.with_book(|b| b.on_responded(&key, result));
                    this.record_log(fx.log);
                })),
                NetEffect::RejectProposal { id, error } => {
                    let client = &self.inner.client;
                    answers.push(Box::pin(async move {
                        let r = tokio::time::timeout(per_phase, client.reject(id, error)).await;
                        debug!(id, ok = matches!(r, Ok(Ok(()))), "suspend reject");
                    }))
                }
                // A disconnect the user asked for that hasn't reached the relay: its last try,
                // as a teardown gives it. Delivered → the crate drops the session, so the saved
                // state no longer holds it; failed again → it stays there, unbound, for the
                // restore to tell the dapp.
                NetEffect::Disconnect { topic } => answers.push(Box::pin(async move {
                    let client = &this.inner.client;
                    let sent = tokio::time::timeout(per_phase, client.disconnect(&topic))
                        .await
                        .unwrap_or(Err(wallet_connect::Error::Timeout));
                    let held = client.session(&topic).is_some();
                    let result = request::respond_result(&sent, held);
                    debug!(
                        ok = matches!(result, RespondResult::Delivered),
                        "suspend disconnect"
                    );
                    let fx = this.with_book(|b| b.on_disconnected(&topic, result));
                    this.record_log(fx.log);
                })),
                // A suspend disconnects no bound session; pairings and events wait with the client.
                NetEffect::DeletePairing { .. }
                | NetEffect::Emit { .. }
                | NetEffect::Retire { .. } => {}
            }
        }
        let _ = tokio::time::timeout(answers_budget, futures::future::join_all(answers)).await;
        // Shut down first, then take the state: nothing the relay pushes after the save is lost.
        self.inner.client.shutdown();
        if flush.can_persist() {
            let record = self.with_book(|b| self.record_of(b));
            flush.save_wc_state(record.encode());
        }
        flush.finish_with(guard);
        info!(
            generation = self.inner.generation,
            "WalletConnect suspended; dapps stay connected"
        );
    }

    /// One delivery attempt of `answer` for `key`, classed as the book needs it.
    async fn respond_once(
        &self,
        key: &WcKey,
        answer: Result<Value, ErrorObject>,
        within: Duration,
    ) -> RespondResult {
        let sent = tokio::time::timeout(
            within,
            self.inner.client.respond(&key.topic, key.id, answer),
        )
        .await
        .unwrap_or(Err(wallet_connect::Error::Timeout));
        // Whatever the error, the crate keeps the request while its session lives: then the
        // answer is still owed, not "gone".
        request::respond_result(&sent, self.client_holds(key))
    }

    // ── saved state ──

    /// The state record as of now: the client state FIRST, then the bindings and owed answers
    /// from `book` (locked by the caller) — so every binding's session is in the client state.
    fn record_of(&self, book: &WcBook) -> WcStateRecord {
        let snapshot = self.inner.client.snapshot();
        let (sessions, next_ordinal) = book.bindings();
        WcStateRecord {
            v: WC_STATE_VERSION,
            saved_at: now_secs(),
            relay_url: self.inner.relay_url.clone(),
            route_kind: self.inner.route.into(),
            identity_seed: Some(SeedHex::new(*self.inner.identity_seed)),
            snapshot,
            next_ordinal,
            sessions,
            outbox: book.outbox_entries(),
            deliveries: lock(&self.inner.persist.late_deliveries).clone(),
        }
    }

    /// The record a save would write now (tests).
    #[cfg(test)]
    pub fn state_record(&self) -> WcStateRecord {
        self.with_book(|b| self.record_of(b))
    }

    /// Save the state now: under the book lock — skipped once closed — the client state first,
    /// then the bindings and owed answers; encoded with the lock released; handed to the vault
    /// session (a no-op unless its epoch is current and has a data key). Never on the UI thread:
    /// callers are the spawned save ([`Self::schedule_persist`]) and the housekeeper.
    fn persist_now(&self) {
        let _saving = lock(&self.inner.persist.saving);
        if lock(&self.inner.persist.held).is_some() {
            // A restored runtime not installed yet: the install saves.
            return;
        }
        if !self.inner.vault.can_persist() {
            return;
        }
        let record = {
            let book = lock(&self.inner.book);
            if self.is_closed() {
                return;
            }
            *lock(&self.inner.persist.dirty_since) = None;
            self.record_of(&book)
        };
        let blob = record.encode();
        drop(record);
        if blob.is_empty() {
            return;
        }
        self.inner.vault.save_wc_state(blob);
    }

    /// `Persist::Now`: one save spawned on the runtime's handle, coalescing every `Now` until it
    /// begins. While the vault session can't persist, the change is kept for the housekeeper
    /// instead ([`Self::persist_if_due`]).
    fn schedule_persist(&self) {
        if self.is_closed() {
            return;
        }
        if !self.inner.vault.can_persist() {
            self.keep_until_keyed();
            return;
        }
        if self.inner.persist.scheduled.swap(true, Ordering::SeqCst) {
            return;
        }
        let weak = Arc::downgrade(&self.inner);
        self.inner.handle.spawn(async move {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            let rt = WcRuntime { inner };
            rt.inner.persist.scheduled.store(false, Ordering::SeqCst);
            rt.persist_now();
        });
    }

    /// `Persist::Soon`: the housekeeper saves [`PERSIST_SOON_AFTER`] after the first change.
    fn mark_dirty(&self) {
        if self.is_closed() {
            return;
        }
        if !self.inner.vault.can_persist() {
            self.keep_until_keyed();
            return;
        }
        lock(&self.inner.persist.dirty_since).get_or_insert_with(Instant::now);
    }

    /// A change the vault session can't take yet: kept dirty until it gets a data key — or for
    /// good, for a runtime whose epoch ended (its session never persists again).
    fn keep_until_keyed(&self) {
        lock(&self.inner.persist.dirty_since).get_or_insert_with(Instant::now);
        self.inner
            .persist
            .awaiting_key
            .store(true, Ordering::SeqCst);
    }

    /// The housekeeper's half of `Soon` — and of every change kept while the vault session
    /// couldn't persist: once it can, saved at once.
    fn persist_if_due(&self) {
        if !self.inner.vault.can_persist() {
            // The dirt stays for when the key arrives.
            return;
        }
        let kept_while_keyless = self
            .inner
            .persist
            .awaiting_key
            .swap(false, Ordering::SeqCst);
        let due = {
            let mut dirty = lock(&self.inner.persist.dirty_since);
            let due = dirty
                .is_some_and(|since| kept_while_keyless || since.elapsed() >= PERSIST_SOON_AFTER);
            if due {
                *dirty = None;
            }
            due
        };
        if due {
            self.persist_now();
        }
    }

    /// The `log` / `persist` half of an [`Effects`].
    fn record(&self, log: Vec<LogEffect>, persist: Persist) {
        self.record_log(log);
        match persist {
            Persist::Now => self.schedule_persist(),
            Persist::Soon => self.mark_dirty(),
            Persist::None => {}
        }
    }

    /// History into the vault session (epoch-checked there) — or held, for a restored runtime
    /// that isn't installed yet. A signature delivery learned once this runtime closed or its
    /// epoch ended is also kept as a late delivery: the suspend's final save carries it to the
    /// next unlock, where the vault session that drops it here can no longer be.
    fn record_log(&self, log: Vec<LogEffect>) {
        if log.is_empty() {
            return;
        }
        let mut held = lock(&self.inner.persist.held);
        if let Some(waiting) = held.as_mut() {
            waiting.extend(log);
            return;
        }
        drop(held);
        let late = self.is_closed() || !self.inner.vault.is_current();
        for e in log {
            if late
                && let LogEffect::MessageDelivery {
                    topic,
                    request_id,
                    delivery,
                    signature,
                } = &e
            {
                lock(&self.inner.persist.late_deliveries).push(PersistedDelivery {
                    topic: Topic::new(topic.clone()),
                    id: *request_id,
                    delivery: *delivery,
                    signature: signature.clone(),
                });
            }
            write_log(&self.inner.vault, e);
        }
    }

    /// A restored runtime was installed: the history it held goes to the vault, and from here on
    /// it records as it comes.
    fn release_held_log(&self) {
        let mut held = lock(&self.inner.persist.held);
        for e in held.take().unwrap_or_default() {
            write_log(&self.inner.vault, e);
        }
    }

    // ── private ──

    /// Execute one network effect on the runtime's handle; its result goes straight back into the
    /// book, and the dashboard hears about it through the stream. Once closed, only answers still
    /// go out (they let a dapp stop waiting); teardown handles everything else.
    fn spawn_net(&self, e: NetEffect) {
        if self.is_closed()
            && !matches!(
                e,
                NetEffect::Respond { .. } | NetEffect::RejectProposal { .. }
            )
        {
            debug!("runtime closed; network effect skipped");
            return;
        }
        let rt = self.clone();
        match e {
            NetEffect::Respond { key, answer } => {
                self.inner.handle.spawn(async move {
                    let result = rt.respond_once(&key, answer, RESPOND_TIMEOUT).await;
                    let fx = rt.with_book(|b| b.on_responded(&key, result));
                    rt.apply_background(fx);
                });
            }
            NetEffect::RejectProposal { id, error } => {
                self.inner.handle.spawn(async move {
                    let sent =
                        tokio::time::timeout(RESPOND_TIMEOUT, rt.inner.client.reject(id, error))
                            .await
                            .unwrap_or(Err(wallet_connect::Error::Timeout));
                    let result = match sent {
                        // Expired or answered meanwhile: either way it is off the card.
                        Ok(()) | Err(wallet_connect::Error::NoProposal(_)) => Ok(()),
                        Err(e) => {
                            debug!(kind = error_kind(&e), "reject failed");
                            Err("Couldn't reach the relay — try again.".to_string())
                        }
                    };
                    let fx = rt.with_book(|b| b.proposal_rejected(id, result));
                    rt.apply_background(fx);
                });
            }
            NetEffect::Disconnect { topic } => {
                self.inner.handle.spawn(async move {
                    let sent = tokio::time::timeout(
                        DISCONNECT_TIMEOUT,
                        rt.inner.client.disconnect(&topic),
                    )
                    .await
                    .unwrap_or(Err(wallet_connect::Error::Timeout));
                    // A failed send leaves the session with the crate: the dapp still has to be told.
                    let held = rt.inner.client.session(&topic).is_some();
                    let result = request::respond_result(&sent, held);
                    let fx = rt.with_book(|b| b.on_disconnected(&topic, result));
                    rt.apply_background(fx);
                });
            }
            NetEffect::DeletePairing { topic } => {
                self.inner.handle.spawn(async move {
                    let sent = tokio::time::timeout(
                        DISCONNECT_TIMEOUT,
                        rt.inner.client.disconnect(&topic),
                    )
                    .await;
                    match &sent {
                        Ok(Err(e)) => debug!(kind = error_kind(e), "pairing delete failed"),
                        // The crate forgot the pairing.
                        Ok(Ok(())) => rt.mark_dirty(),
                        Err(_) => {}
                    }
                });
            }
            NetEffect::Emit {
                topic,
                chain_id,
                name,
                data,
            } => {
                // Best effort: the dapp's own switch handling doesn't depend on it.
                self.inner.handle.spawn(async move {
                    let sent = tokio::time::timeout(
                        RESPOND_TIMEOUT,
                        rt.inner.client.emit(
                            &topic,
                            &caip2(chain_id),
                            SessionEvent::new(name, data),
                        ),
                    )
                    .await;
                    if let Ok(Err(e)) = &sent {
                        debug!(kind = error_kind(e), event = name, "emit failed");
                    }
                });
            }
            NetEffect::Retire { reason } => rt.retire(&reason),
        }
    }

    /// For effects produced off the dashboard's update (forwarder, housekeeper, op completions):
    /// network effects run here, history and saves are recorded, UI effects and `Changed` go out
    /// through the event stream.
    fn apply_background(&self, fx: Effects) {
        for e in fx.net {
            self.spawn_net(e);
        }
        self.record(fx.log, fx.persist);
        for e in fx.ui {
            let _ = self.inner.notify.send(WcStreamItem::Ui(e));
        }
        if fx.changed {
            self.notify_changed();
        }
    }

    /// Wake the dashboard to mirror the book — one `Changed` in the stream at a time, so changes
    /// made while no dashboard takes items (a dapp's flood, refused) don't pile up there.
    fn notify_changed(&self) {
        if !self
            .inner
            .source
            .changed_queued
            .swap(true, Ordering::SeqCst)
        {
            let _ = self.inner.notify.send(WcStreamItem::Changed);
        }
    }

    /// Everything the forwarder can apply without the wallet's descriptors.
    fn on_sign_event(&self, event: SignEvent) {
        let now = now_secs();
        let fx = match event {
            SignEvent::RelayConnected => self.with_book(|b| b.on_relay(true, now)),
            SignEvent::RelayDisconnected => self.with_book(|b| b.on_relay(false, now)),
            SignEvent::SessionProposal(p) => self.with_book(|b| b.on_proposal(p, now)),
            SignEvent::SessionDelete { topic, .. } => {
                self.with_book(|b| b.on_session_gone(&topic, GoneReason::DappDisconnected))
            }
            SignEvent::SessionExpire { topic } => {
                self.with_book(|b| b.on_session_gone(&topic, GoneReason::SessionExpired))
            }
            SignEvent::SessionRequestExpire { id, topic } => {
                self.with_book(|b| b.on_request_expired(&WcKey { topic, id }))
            }
            SignEvent::ProposalExpire { id } => self.with_book(|b| b.on_proposal_expired(id)),
            SignEvent::PairingExpire { topic } | SignEvent::PairingDelete { topic, .. } => {
                self.with_book(|b| b.on_pairing_gone(&topic))
            }
            SignEvent::SessionExtend { topic, expiry, .. } => {
                self.with_book(|b| b.on_session_extended(&topic, expiry))
            }
            // Pings are answered by the crate; SessionConnect / SessionUpdate / SessionEvent are
            // dapp-side events a wallet must ignore (the crate does no controller check on them).
            other => {
                debug!(event = sign_event_name(&other), "sign event ignored");
                return;
            }
        };
        self.apply_background(fx);
    }

    /// A late settlement acknowledgement sets the client's `acknowledged` without an event (a
    /// restored session has no waiter for it at all): pick it up for the sessions still
    /// unconfirmed.
    fn refresh_acks(&self) {
        let unconfirmed = self.with_book(|b| b.unconfirmed_sessions());
        let acked: Vec<Topic> = unconfirmed
            .into_iter()
            .filter(|t| self.inner.client.session(t).is_some_and(|s| s.acknowledged))
            .collect();
        if acked.is_empty() {
            return;
        }
        let fx = self.with_book(|b| {
            let mut fx = Effects::default();
            for topic in &acked {
                fx.merge(b.late_ack(topic));
            }
            fx
        });
        self.apply_background(fx);
    }

    #[cfg(test)]
    pub(crate) fn client(&self) -> &SignClient {
        &self.inner.client
    }
}

/// One history event into the vault session.
fn write_log(vault: &VaultSession, e: LogEffect) {
    match e {
        LogEffect::ConnectionOpened(rec) => vault.connection_opened(rec),
        LogEffect::ConnectionAcked { topic, ack } => vault.connection_acked(&topic, ack),
        LogEffect::ConnectionEnded { topic, at, reason } => {
            vault.connection_ended(&topic, at, reason)
        }
        LogEffect::MessageSigned(rec) => vault.message_signed(rec),
        LogEffect::MessageDelivery {
            topic,
            request_id,
            delivery,
            signature,
        } => vault.message_delivery(&topic, request_id, delivery, signature),
    }
}

/// The signature deliveries a saved record carries ([`WcStateRecord::deliveries`]) into the
/// history — before that record is cleared or replaced. Idempotent.
fn apply_deliveries(session: &VaultSession, record: &WcStateRecord) {
    for d in &record.deliveries {
        session.message_delivery(d.topic.as_str(), d.id, d.delivery, d.signature.clone());
    }
}

/// When a connection ends `Lost` that saved state `record` (or its absence from it) vouches for:
/// the last moment Kao knew how things stood — the save, never later than `now` — not the unlock
/// that found out, which can be days after. Where no readable saved state exists, nothing better
/// than `now` is known.
fn lost_at(record: &WcStateRecord, now: u64) -> u64 {
    record.saved_at.min(now)
}

/// Saved state `record` is dropped without a restore (nothing alive, another relay, Forget, an
/// unreadable client state): the history ends each of its bindings — `plan`'s expired and lost
/// ones at their own times, every one still alive for `live` (now — or, for `Lost`, at the save:
/// [`lost_at`]) — learns the signature deliveries
/// the plan worked out, marks every message signature the record still owed `NotDelivered`
/// (nothing will send it again), then takes the deliveries the record itself carries (known
/// facts, applied last). Without a plan (the client state is unreadable), every binding ends
/// `live` and every owed signature is given up. The caller clears the state.
fn end_saved_state(
    session: &VaultSession,
    record: &WcStateRecord,
    plan: Option<&RestorePlan>,
    live: EndReason,
    now: u64,
) {
    // Forgotten / RelayChanged happen now; Lost happened while Kao was closed.
    let live_at = match live {
        EndReason::Lost => lost_at(record, now),
        _ => now,
    };
    let owed = match plan {
        Some(plan) => {
            for (topic, at, reason) in &plan.ended {
                session.connection_ended(topic, *at, *reason);
            }
            for s in &plan.seed.sessions {
                session.connection_ended(s.topic.as_str(), live_at, live);
            }
            for d in &plan.deliveries {
                session.message_delivery(d.topic.as_str(), d.id, d.delivery, d.signature.clone());
            }
            plan.work.owed.as_slice()
        }
        None => {
            for saved in &record.sessions {
                session.connection_ended(saved.topic.as_str(), live_at, live);
            }
            record.outbox.as_slice()
        }
    };
    for answer in owed.iter().filter(|a| a.signed_message) {
        session.message_delivery(
            answer.topic.as_str(),
            answer.id,
            Delivery::NotDelivered,
            None,
        );
    }
    apply_deliveries(session, record);
}

const CHANGED: &str = "The request changed — reconnect from the dapp.";
/// The card's reason when Connect is pressed while the relay reconnects.
const RECONNECTING: &str = "Kao is reconnecting to the relay — try again in a moment.";
const NOTHING_SENT: &str =
    "The relay didn't take the connection — nothing reached the dapp. Try again.";

// ───────────────────────────── restore ─────────────────────────────

/// Everything a restore does, worked out from the saved record alone before Kao dials — never from
/// a live client, which may already be taking what the relay kept for it.
struct RestorePlan {
    /// The saved client state, less the sessions that expired (and everything of theirs) and the
    /// pairings that did.
    snapshot: Snapshot,
    seed: BookSeed,
    work: RestoreWork,
    /// The session expiry (unix s) of each of `work.unbound`, in its order.
    unbound_expiries: Vec<u64>,
    /// Saved bindings that won't come back: `(topic, at, reason)` — expired, or missing from the
    /// saved client state.
    ended: Vec<(String, u64, EndReason)>,
    /// Owed message signatures the saved client state no longer holds a request for. On a live
    /// session whose request couldn't have expired by the save, delivered — with the signature,
    /// which the history keeps from then on: the crate drops such a request only once its answer
    /// went out. Otherwise not delivered, without it: their session went, or the crate may have
    /// dropped the request at its deadline, unanswered, and nothing sends the answer again.
    deliveries: Vec<PersistedDelivery>,
}

/// Work out [`RestorePlan`] from `record` at `now`. Sessions within [`EXPIRY_MARGIN_SECS`] of
/// their expiry count as expired. Err: the saved client state can't be read back.
///
/// The client state is pruned in its JSON form (the crate's `State` is private); that `Value`
/// holds the session keys as hex and isn't zeroized — the residual risk `persist` documents.
fn plan_restore(record: &WcStateRecord, now: u64) -> Result<RestorePlan, String> {
    const UNREADABLE: &str = "the saved WalletConnect client state is unreadable";
    let mut state = serde_json::to_value(&record.snapshot).map_err(|_| UNREADABLE.to_string())?;
    let deadline = now.saturating_add(EXPIRY_MARGIN_SECS);
    // topic → (expiry, acknowledged)
    let mut alive: BTreeMap<String, (u64, bool)> = BTreeMap::new();
    let mut expired: BTreeMap<String, u64> = BTreeMap::new();
    if let Some(sessions) = state.get("sessions").and_then(Value::as_object) {
        for (topic, s) in sessions {
            let expiry = s.get("expiry").and_then(Value::as_u64).unwrap_or(0);
            let acked = s
                .get("acknowledged")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if expiry <= deadline {
                expired.insert(topic.clone(), expiry);
            } else {
                alive.insert(topic.clone(), (expiry, acked));
            }
        }
    }
    let mut dead_pairings = BTreeSet::new();
    let mut pairings = Vec::new();
    if let Some(saved) = state.get("pairings").and_then(Value::as_object) {
        for (topic, p) in saved {
            match p.get("expiry").and_then(Value::as_u64) {
                Some(expiry) if expiry > now => pairings.push(Topic::new(topic.clone())),
                _ => {
                    dead_pairings.insert(topic.clone());
                }
            }
        }
    }
    prune_state(&mut state, &expired, &dead_pairings);

    let mut sessions = Vec::new();
    let mut ended = Vec::new();
    for saved in &record.sessions {
        let topic = saved.topic.as_str();
        if let Some(&(expiry, acked)) = alive.get(topic) {
            sessions.push(BoundSession {
                topic: saved.topic.clone(),
                pairing_topic: saved.pairing_topic.clone(),
                ordinal: saved.ordinal,
                identity: saved.identity.into(),
                identity_label: saved.identity_label.clone(),
                chains: saved.chains.clone(),
                methods: saved.methods.clone(),
                events: saved.events.clone(),
                dapp: (&saved.dapp).into(),
                expiry,
                // No waiter survives a restart: a late acknowledgement is picked up from the
                // client (`refresh_acks`).
                ack: if acked {
                    AckState::Confirmed
                } else {
                    AckState::Unconfirmed
                },
                paused: saved.paused,
                reject_streak: 0,
            });
        } else if let Some(&expiry) = expired.get(topic) {
            ended.push((topic.to_string(), expiry.min(now), EndReason::Expired));
        } else {
            ended.push((topic.to_string(), lost_at(record, now), EndReason::Lost));
        }
    }
    let bound: BTreeSet<&str> = sessions.iter().map(|s| s.topic.as_str()).collect();
    let (unbound, unbound_expiries): (Vec<Topic>, Vec<u64>) = alive
        .iter()
        .filter(|(t, _)| !bound.contains(t.as_str()))
        .map(|(t, &(expiry, _))| (Topic::new(t.clone()), expiry))
        .unzip();
    // (topic, id) of every request the restored client will hold.
    let pending: BTreeSet<(String, u64)> = state
        .get("pendingRequests")
        .and_then(Value::as_object)
        .map(|requests| {
            requests
                .values()
                .filter_map(|r| {
                    let topic = r.get("topic")?.as_str()?.to_string();
                    let id = r.get("id")?.as_u64()?;
                    Some((topic, id))
                })
                .collect()
        })
        .unwrap_or_default();
    let mut owed = Vec::new();
    let mut owed_keys = BTreeSet::new();
    let mut deliveries = Vec::new();
    for answer in &record.outbox {
        let key = (answer.topic.to_string(), answer.id);
        let on_bound = bound.contains(answer.topic.as_str());
        if on_bound && pending.contains(&key) {
            owed_keys.insert(key);
            owed.push(answer.clone());
        } else if answer.signed_message {
            // The crate also drops a request at its dapp deadline (its expiry sweep), answered
            // or not: past that by the save, a missing request says nothing about delivery.
            let expirable = answer
                .dapp_deadline
                .is_some_and(|d| d <= record.saved_at.saturating_add(EXPIRY_MARGIN_SECS));
            let (delivery, signature) = if on_bound && !expirable {
                (Delivery::Delivered, answer_signature(&answer.answer))
            } else {
                (Delivery::NotDelivered, None)
            };
            deliveries.push(PersistedDelivery {
                topic: answer.topic.clone(),
                id: answer.id,
                delivery,
                signature,
            });
        }
    }
    let stale: Vec<WcKey> = pending
        .iter()
        .filter(|(topic, _)| bound.contains(topic.as_str()))
        .filter(|key| !owed_keys.contains(*key))
        .map(|(topic, id)| WcKey {
            topic: Topic::new(topic.clone()),
            id: *id,
        })
        .collect();
    let snapshot: Snapshot = serde_json::from_value(state).map_err(|_| UNREADABLE.to_string())?;
    Ok(RestorePlan {
        snapshot,
        seed: BookSeed {
            sessions,
            next_ordinal: record.next_ordinal,
            now,
        },
        work: RestoreWork {
            owed,
            stale,
            unbound,
            pairings,
        },
        unbound_expiries,
        ended,
        deliveries,
    })
}

/// Drop from the saved client state (its JSON form) the `expired` sessions — with their keys,
/// pending requests, outgoing request records and last ids — and the `dead_pairings` with their
/// keys, so the restored client never subscribes to a dead topic.
fn prune_state(
    state: &mut Value,
    expired: &BTreeMap<String, u64>,
    dead_pairings: &BTreeSet<String>,
) {
    let gone = |topic: &str| expired.contains_key(topic);
    if let Some(sessions) = state.get_mut("sessions").and_then(Value::as_object_mut) {
        sessions.retain(|topic, _| !gone(topic));
    }
    if let Some(saved) = state.get_mut("pairings").and_then(Value::as_object_mut) {
        saved.retain(|topic, _| !dead_pairings.contains(topic));
    }
    if let Some(keys) = state.get_mut("symKeys").and_then(Value::as_object_mut) {
        keys.retain(|topic, _| !gone(topic) && !dead_pairings.contains(topic));
    }
    let of_a_gone_topic = |v: &Value| v.get("topic").and_then(Value::as_str).is_some_and(gone);
    for table in ["pendingRequests", "history"] {
        if let Some(rows) = state.get_mut(table).and_then(Value::as_object_mut) {
            rows.retain(|_, row| !of_a_gone_topic(row));
        }
    }
    if let Some(ids) = state.get_mut("lastIds").and_then(Value::as_object_mut) {
        ids.retain(|key, _| key.split_once('/').is_none_or(|(topic, _)| !gone(topic)));
    }
}

/// Why the pane says WalletConnect is off after a restore found another relay configured: the
/// saved dapps still alive it forgot (`live`) — or, with none, the disconnects it still owed
/// (`unbound`) that no dapp will now hear (only those make a restore with no live dapp dial).
fn relay_changed_notice(live: usize, unbound: usize) -> String {
    const ANOTHER_RELAY: &str = "WalletConnect uses another relay now";
    match (live, unbound) {
        (0, 0 | 1) => format!("Kao couldn't finish disconnecting a dapp: {ANOTHER_RELAY}."),
        (0, n) => format!("Kao couldn't finish disconnecting {n} dapps: {ANOTHER_RELAY}."),
        (1, _) => format!("Kao forgot 1 saved dapp: {ANOTHER_RELAY}."),
        (n, _) => format!("Kao forgot {n} saved dapps: {ANOTHER_RELAY}."),
    }
}

/// Why a restore try didn't install.
enum TryFailed {
    /// Worth trying again by itself (the relay unreachable): after a backoff.
    Retry(String),
    /// Waits for the user: Kao's own copy, and whether Reconnect anyway applies.
    NeedsYou {
        error: String,
        direct_override: bool,
    },
}

/// Where a restore try dials: the relay, the route's kind, and how to connect.
struct Target {
    relay_url: url::Url,
    route: RouteKind,
    connect: TargetConnect,
}

enum TargetConnect {
    Kao(WcConfig),
    #[cfg(test)]
    Test(Arc<dyn wallet_connect::relay::Connector>),
}

fn restore_target(dial: &RestoreDial) -> Result<Target, StartError> {
    match dial {
        RestoreDial::Settings => {
            let cfg = config_from_settings(next_generation())?;
            Ok(Target {
                relay_url: cfg.relay_url.clone(),
                route: transport::route_kind(&cfg.relay_url, &cfg.route),
                connect: TargetConnect::Kao(cfg),
            })
        }
        #[cfg(test)]
        RestoreDial::Test(t) => Ok(Target {
            relay_url: t.relay_url.clone(),
            route: t.route,
            connect: TargetConnect::Test(t.connector.clone()),
        }),
    }
}

/// The restore loop of slot run `run`: try; on a failure worth retrying sleep (5 s, 15 s, 30 s,
/// 60 s, then every 60 s — or until Retry now) and try again; stop when it installs, needs the
/// user, finds nothing to restore, or is no longer the slot's run (forgotten, a lock).
async fn restore_loop(slot: WcSlot, run: u64, allow_direct: bool) -> RestoreOutcome {
    let _dropped = RestoreRunGuard {
        slot: slot.clone(),
        run,
    };
    let mut failures = 0usize;
    loop {
        let Some((job, wake)) = slot.restore_next_try(run) else {
            return RestoreOutcome::Stopped;
        };
        match restore_try(&slot, run, &job, allow_direct).await {
            Ok(outcome) => return outcome,
            Err(TryFailed::NeedsYou {
                error,
                direct_override,
            }) => {
                info!(direct_override, "wc: restore waits for the user");
                return if slot.restore_needs_you(run, error, direct_override) {
                    RestoreOutcome::Waiting
                } else {
                    RestoreOutcome::Stopped
                };
            }
            Err(TryFailed::Retry(error)) => {
                let secs = RESTORE_BACKOFF_SECS[failures.min(RESTORE_BACKOFF_SECS.len() - 1)];
                failures = failures.saturating_add(1);
                info!(failures, retry_in = secs, "wc: restore failed; retrying");
                if !slot.restore_retrying(run, now_secs().saturating_add(secs), error) {
                    return RestoreOutcome::Stopped;
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
                    _ = wake.notified() => {}
                }
            }
        }
    }
}

/// Every way [`restore_loop`] ends moves the slot's restore out of its run — except its future
/// being dropped unfinished: then the saved sessions wait for the user instead of looking forever
/// like a restore that runs (and blocking every start).
struct RestoreRunGuard {
    slot: WcSlot,
    run: u64,
}

impl Drop for RestoreRunGuard {
    fn drop(&mut self) {
        if self
            .slot
            .restore_needs_you(self.run, RESTORE_INTERRUPTED.to_string(), false)
        {
            debug!("wc: a restore was dropped unfinished");
        }
    }
}

/// One restore try (DESIGN §3.4): plan from the record; nothing alive → clear, no dial; another
/// relay → forget, no dial; a less private route → the user decides, no dial; then build the client
/// on the pruned state with the seeded book and install it — or, refused (a lock, Forget), shut it
/// down without a word to any dapp and leave the vault as it was.
async fn restore_try(
    slot: &WcSlot,
    run: u64,
    job: &RestoreJob,
    allow_direct: bool,
) -> Result<RestoreOutcome, TryFailed> {
    let record = &job.record;
    let session = &job.session;
    if !session.is_current() {
        // The unlock it belongs to ended: the saved state stays on disk for the next one.
        slot.restore_finished(run, None);
        return Ok(RestoreOutcome::Stopped);
    }
    let now = now_secs();
    let plan = match plan_restore(record, now) {
        Ok(plan) => plan,
        Err(why) => {
            warn!("wc: {why}; nothing to restore");
            if !slot.restore_finished(run, None) {
                return Ok(RestoreOutcome::Stopped);
            }
            end_saved_state(session, record, None, EndReason::Lost, now);
            session.end_open_connections_except(&[], lost_at(record, now), EndReason::Lost);
            session.clear_wc_state();
            return Ok(RestoreOutcome::Nothing);
        }
    };
    if plan.seed.sessions.is_empty() && plan.work.unbound.is_empty() {
        // Nothing alive to dial for (the lazy-network rule). A session a dapp still holds that no
        // binding covers is worth the dial: the restore tells that dapp it's gone.
        if !slot.restore_finished(run, None) {
            return Ok(RestoreOutcome::Stopped);
        }
        end_saved_state(session, record, Some(&plan), EndReason::Lost, now);
        session.end_open_connections_except(&[], lost_at(record, now), EndReason::Lost);
        session.clear_wc_state();
        info!(
            ended = plan.ended.len(),
            "wc: no saved session left to restore"
        );
        return Ok(RestoreOutcome::Nothing);
    }
    let target = restore_target(&job.dial).map_err(|e| TryFailed::NeedsYou {
        error: e.to_string(),
        direct_override: false,
    })?;
    if !same_relay(&record.relay_url, target.relay_url.as_str()) {
        let notice = RetireNotice {
            text: relay_changed_notice(plan.seed.sessions.len(), plan.work.unbound.len()),
            error: false,
        };
        if !slot.restore_finished(run, Some(notice)) {
            return Ok(RestoreOutcome::Stopped);
        }
        end_saved_state(session, record, Some(&plan), EndReason::RelayChanged, now);
        session.end_open_connections_except(&[], lost_at(record, now), EndReason::Lost);
        session.clear_wc_state();
        info!(
            sessions = plan.seed.sessions.len(),
            "wc: the relay changed; saved sessions forgotten"
        );
        return Ok(RestoreOutcome::Nothing);
    }
    let saved_route = record.route_kind.into();
    if privacy(target.route) < privacy(saved_route) && !allow_direct {
        return Err(TryFailed::NeedsYou {
            error: RESTORE_PROXY_OFF.to_string(),
            direct_override: true,
        });
    }
    // An earlier lock's suspend may still hold the relay under this identity: let it finish.
    let _ = tokio::time::timeout(QUIT_TEARDOWN_BUDGET, slot.teardowns_idle()).await;
    // A lock, a quit or Forget may have landed meanwhile: then nothing dials under the saved
    // identity — the relay keeps what it holds for it, for the next unlock.
    if !slot.restore_still_runs(run) || !session.is_current() {
        slot.restore_finished(run, None);
        return Ok(RestoreOutcome::Stopped);
    }
    // The relay keeps what it pushed per client id: the saved identity, over the same kind of
    // route, takes up exactly where the last runtime left off. A changed route gets a fresh one.
    let identity = match (&record.identity_seed, target.route == saved_route) {
        (Some(seed), true) => IdentityKey::from_seed(*seed.expose()),
        _ => IdentityKey::generate(),
    };
    let parts = StartParts {
        generation: next_generation(),
        route: target.route,
        connector_shutdown: None,
        vault: session.clone(),
        identity_seed: Zeroizing::new(identity.seed()),
        relay_url: relay_origin(&target.relay_url),
        restore: Some((plan.snapshot, plan.seed)),
    };
    // Counted from the dial until the install is decided: the next unlock's restore (same relay
    // identity) waits for a try a lock stopped half-way.
    let running = slot.begin_teardown();
    let started = match target.connect {
        TargetConnect::Kao(cfg) => {
            let timeouts = Timeouts::for_route(&cfg.route);
            let connector =
                KaoConnector::new(cfg.relay_url, cfg.project_id, identity, cfg.route, timeouts);
            let shutdown = connector.shutdown_handle();
            if !slot.arm_restore(run, shutdown.clone()) || !session.is_current() {
                slot.restore_finished(run, None);
                return Ok(RestoreOutcome::Stopped);
            }
            let parts = StartParts {
                connector_shutdown: Some(shutdown),
                ..parts
            };
            WcRuntime::start_inner(connector, parts).await
        }
        #[cfg(test)]
        TargetConnect::Test(connector) => {
            let shutdown = ConnectorShutdown::default();
            if !slot.arm_restore(run, shutdown.clone()) || !session.is_current() {
                slot.restore_finished(run, None);
                return Ok(RestoreOutcome::Stopped);
            }
            let parts = StartParts {
                connector_shutdown: Some(shutdown.clone()),
                ..parts
            };
            WcRuntime::start_inner(switched(connector, shutdown), parts).await
        }
    };
    let rt = match started {
        Ok(rt) => rt,
        Err(why) => {
            drop(running);
            return Err(TryFailed::Retry(why));
        }
    };
    if let Err(refused) = slot.install_restored(rt.clone(), run) {
        // A lock, a quit or Forget got there first (and aborted the connection, so nothing more
        // left for the relay). Never a disconnect, never a vault write: the saved state stays as
        // it was, for the next unlock.
        refused.mark_closed();
        refused.inner.client.shutdown();
        drop(running);
        info!("wc: restore stopped before it installed");
        return Ok(RestoreOutcome::Stopped);
    }
    drop(running);
    // History: what the plan found before the dial, the signature deliveries the saved state
    // knew of, what the runtime made while it waited to be installed, an open record for every
    // live session that lacks one (its opening was dropped with a lock's ended epoch), then every
    // record still open that no live session backs.
    for (topic, at, reason) in &plan.ended {
        session.connection_ended(topic, *at, *reason);
    }
    for d in &plan.deliveries {
        session.message_delivery(d.topic.as_str(), d.id, d.delivery, d.signature.clone());
    }
    apply_deliveries(session, record);
    rt.release_held_log();
    let fx = rt.with_book(|b| b.apply_restore(plan.work));
    rt.apply_background(fx);
    let connected_at = record.saved_at.min(now);
    let open: Vec<NewConnection> = rt.with_book(|b| {
        b.sessions()
            .into_iter()
            .map(|s| NewConnection {
                topic: s.topic.to_string(),
                dapp: DappRecord::from(&s.dapp),
                account: AccountRef::from((s.identity, s.identity_label.clone())),
                chains: s.chains.clone(),
                connected_at,
                ack: match s.ack {
                    AckState::Pending => AckRecord::Pending,
                    AckState::Confirmed => AckRecord::Confirmed,
                    AckState::Unconfirmed => AckRecord::Unconfirmed,
                },
            })
            .collect()
    });
    let live: Vec<String> = open.iter().map(|c| c.topic.clone()).collect();
    for rec in open {
        session.ensure_open_connection(rec);
    }
    session.end_open_connections_except(&live, lost_at(record, now), EndReason::Lost);
    rt.schedule_persist();
    info!(
        generation = rt.generation(),
        sessions = live.len(),
        "WalletConnect sessions restored"
    );
    Ok(RestoreOutcome::Restored {
        sessions: live.len(),
        generation: rt.generation(),
    })
}

/// FORWARDER: applies every crate event that needs no wallet context to the book (even while no
/// dashboard exists) and hands session requests to the dashboard through the stream.
async fn forward(weak: Weak<Inner>, mut sign_rx: SignEvents, tx: UnboundedSender<WcStreamItem>) {
    while let Some(event) = sign_rx.recv().await {
        let Some(inner) = weak.upgrade() else {
            break;
        };
        let rt = WcRuntime { inner };
        if let SignEvent::SessionRequest(req) = event {
            // The client took it (and the relay won't push it to this identity again): save.
            rt.record(Vec::new(), Persist::Now);
            // Bind barrier: wait out an approve that may still be binding this request's session.
            drop(rt.inner.approve_gate.lock().await);
            if rt.is_closed() {
                continue;
            }
            let received_at = now_secs();
            // The queue caps hold at admission, which only a dashboard runs. While none takes
            // requests (the user is on another screen), a flood past the backlog is refused here,
            // through the book like any refusal, rather than held without bound.
            if !lock_backlog(&rt.inner.source.backlog).enter(&req.topic) {
                debug!(id = req.id, "wc: request backlog full; refusing");
                let fx = rt.with_book(|b| {
                    b.on_request(&req, received_at, Err(Refusal::limit()), received_at)
                });
                rt.apply_background(fx);
                continue;
            }
            let _ = tx.send(WcStreamItem::Request { req, received_at });
            continue;
        }
        rt.on_sign_event(event);
    }
    debug!("WalletConnect forwarder stopped");
}

/// HOUSEKEEPER: `book.tick` every second until the runtime closes or is dropped — plus late
/// settlement acknowledgements, and the `Soon` save once it is due.
async fn housekeeping(weak: Weak<Inner>) {
    let mut every = tokio::time::interval(HOUSEKEEPING_EVERY);
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        every.tick().await;
        let Some(inner) = weak.upgrade() else {
            break;
        };
        let rt = WcRuntime { inner };
        if rt.is_closed() {
            break;
        }
        let fx = rt.with_book(|b| b.tick(now_secs()));
        rt.apply_background(fx);
        rt.refresh_acks();
        rt.persist_if_due();
    }
}

fn sign_event_name(e: &SignEvent) -> &'static str {
    match e {
        SignEvent::SessionProposal(_) => "SessionProposal",
        SignEvent::SessionConnect(_) => "SessionConnect",
        SignEvent::SessionRequest(_) => "SessionRequest",
        SignEvent::SessionEvent { .. } => "SessionEvent",
        SignEvent::SessionUpdate { .. } => "SessionUpdate",
        SignEvent::SessionExtend { .. } => "SessionExtend",
        SignEvent::SessionPing { .. } => "SessionPing",
        SignEvent::SessionDelete { .. } => "SessionDelete",
        SignEvent::SessionExpire { .. } => "SessionExpire",
        SignEvent::SessionRequestExpire { .. } => "SessionRequestExpire",
        SignEvent::ProposalExpire { .. } => "ProposalExpire",
        SignEvent::PairingPing { .. } => "PairingPing",
        SignEvent::PairingDelete { .. } => "PairingDelete",
        SignEvent::PairingExpire { .. } => "PairingExpire",
        SignEvent::RelayConnected => "RelayConnected",
        SignEvent::RelayDisconnected => "RelayDisconnected",
        _ => "other",
    }
}

/// Error variant only — crate error text can echo topics, URIs or relay strings.
fn error_kind(e: &wallet_connect::Error) -> &'static str {
    use wallet_connect::Error as E;
    match e {
        E::InvalidKey(_) => "InvalidKey",
        E::InvalidEnvelope(_) => "InvalidEnvelope",
        E::Decryption => "Decryption",
        E::InvalidUri(_) => "InvalidUri",
        E::InvalidJwt(_) => "InvalidJwt",
        E::InvalidCaip(_) => "InvalidCaip",
        E::InvalidPayload(_) => "InvalidPayload",
        E::Transport(_) => "Transport",
        E::Disconnected => "Disconnected",
        E::Timeout => "Timeout",
        E::Relay(_) => "Relay",
        E::Peer(_) => "Peer",
        E::Protocol(_) => "Protocol",
        E::NoSession(_) => "NoSession",
        E::NoPairing(_) => "NoPairing",
        E::NoProposal(_) => "NoProposal",
        E::NoRequest(_) => "NoRequest",
        E::Expired(_) => "Expired",
        E::Closed => "Closed",
        E::Json(_) => "Json",
    }
}

#[cfg(test)]
mod restore_tests;

#[cfg(test)]
mod tests {
    use std::hash::DefaultHasher;

    use alloy::primitives::{Address, address};
    use futures::StreamExt;
    use serde_json::{Value, json};
    use wallet_connect::relay::RelayServer;
    use wallet_connect::sign::SessionRequest;

    use super::*;
    use crate::sign::broadcast::STILL_WANTED_REFUSAL;
    use crate::walletconnect::book::IDLE_RETIRE_REASON;
    use crate::walletconnect::testkit::{self, RawPeer};
    use crate::walletconnect::{AckState, IDLE_RETIRE_SECS, caip2};

    const ADDR: Address = address!("ab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb");

    fn source(generation: u64) -> (UnboundedSender<WcStreamItem>, WcEventSource) {
        let (tx, rx) = unbounded_channel();
        let src = WcEventSource {
            generation,
            rx: Arc::new(tokio::sync::Mutex::new(rx)),
            backlog: Arc::default(),
            changed_queued: Arc::default(),
        };
        (tx, src)
    }

    fn hash_of(src: &WcEventSource) -> u64 {
        let mut h = DefaultHasher::new();
        src.hash(&mut h);
        h.finish()
    }

    async fn runtime(relay: &RelayServer) -> WcRuntime {
        WcRuntime::start_with_connector(
            relay.connector("kao"),
            next_generation(),
            RouteKind::Loopback,
        )
        .await
        .expect("runtime starts")
    }

    type DappCall = tokio::task::JoinHandle<wallet_connect::Result<Value>>;

    /// The dapp asks for personal_sign; the test plays the coordinator up to Signing.
    async fn signing_request(
        kao: &WcRuntime,
        dapp: &SignClient,
        topic: &Topic,
    ) -> (WcKey, DappCall) {
        let (dapp, t) = (dapp.clone(), topic.clone());
        let call = tokio::spawn(async move {
            let params = testkit::personal_sign_params("hi", ADDR);
            dapp.request(&t, &caip2(1), SessionRequest::new("personal_sign", params))
                .await
        });
        let (req, at) = testkit::next_request(&kao.events()).await;
        let key = WcKey {
            topic: req.topic.clone(),
            id: req.id,
        };
        kao.admit(&req, at, Ok(testkit::admitted_personal(ADDR, 1, "hi")));
        kao.with_book(|b| {
            assert!(b.mark_in_review(&key, 1));
            assert!(b.mark_signing(&key, 1));
        });
        (key, call)
    }

    #[test]
    fn next_generation_is_unique_and_nonzero() {
        let a = next_generation();
        let b = next_generation();
        assert!(a != 0 && b != 0 && a != b);
    }

    #[test]
    fn event_stream_hash_is_generation() {
        let (_tx1, a) = source(7);
        let (_tx2, b) = source(7);
        let (_tx3, c) = source(8);
        assert_eq!(
            hash_of(&a),
            hash_of(&b),
            "another channel, same generation: same id"
        );
        assert_ne!(hash_of(&a), hash_of(&c));
        assert_eq!(format!("{a:?}"), "WcEventSource(gen 7)");
    }

    #[tokio::test]
    async fn event_stream_survives_cancel_and_restart() {
        let (tx, src) = source(7);
        {
            // iced cancels the subscription while it waits in `recv`.
            let mut stream = std::pin::pin!(event_stream(&src));
            assert!(
                tokio::time::timeout(Duration::from_millis(50), stream.next())
                    .await
                    .is_err()
            );
        }
        tx.send(WcStreamItem::Changed).expect("open");
        tx.send(WcStreamItem::Ui(UiEffect::Attention))
            .expect("open");
        let (generation, first) = testkit::next_item(&src).await;
        assert_eq!(generation, 7);
        assert!(matches!(first, WcStreamItem::Changed));
        // A second restart still finds the next item: nothing lost, nothing duplicated.
        let (_, second) = testkit::next_item(&src).await;
        assert!(matches!(second, WcStreamItem::Ui(UiEffect::Attention)));
        drop(tx);
        let mut stream = std::pin::pin!(event_stream(&src));
        assert!(
            stream.next().await.is_none(),
            "ends once the runtime is gone"
        );
    }

    #[test]
    fn slot_begin_start_is_exclusive() {
        let slot = WcSlot::new();
        assert!(slot.begin_start());
        assert!(slot.is_starting());
        assert!(!slot.begin_start(), "one start at a time");
        slot.start_failed();
        assert!(!slot.is_starting());
        assert!(slot.begin_start(), "a failed start can be retried");
        assert!(slot.close().is_none());
        assert!(slot.is_closed() && !slot.is_starting());
        assert!(!slot.begin_start(), "a closed slot never starts again");
    }

    #[tokio::test]
    async fn slot_close_refuses_install() {
        let relay = RelayServer::new();
        let slot = WcSlot::new();
        let rt = runtime(&relay).await;
        slot.install(rt.clone()).expect("installs");
        assert_eq!(slot.get().map(|r| r.generation()), Some(rt.generation()));
        assert!(!slot.begin_start(), "occupied");
        let other = runtime(&relay).await;
        let refused = slot.install(other.clone()).expect_err("occupied");
        assert_eq!(refused.generation(), other.generation());
        let closed = slot.close().expect("returns the runtime to tear down");
        assert_eq!(closed.generation(), rt.generation());
        assert!(slot.get().is_none());
        assert!(slot.install(other).is_err());
    }

    #[tokio::test]
    async fn install_into_closed_slot_is_refused() {
        // A lock lands while the start task is still connecting.
        let relay = RelayServer::new();
        let slot = WcSlot::new();
        assert!(slot.begin_start());
        let rt = runtime(&relay).await;
        assert!(slot.close().is_none());
        let refused = slot.install(rt).expect_err("closed slot");
        // The caller tears the orphan down; nothing is left in the slot.
        refused.mark_closed();
        refused.clone().teardown(Duration::from_millis(200)).await;
        assert!(slot.get().is_none() && slot.is_closed());
        assert!(!refused.client().relay().is_connected());
    }

    #[tokio::test]
    async fn take_generation_mismatch_is_none() {
        let relay = RelayServer::new();
        let slot = WcSlot::new();
        let rt = runtime(&relay).await;
        slot.install(rt.clone()).expect("installs");
        assert!(slot.take_generation(rt.generation() + 1_000).is_none());
        assert!(slot.get().is_some());
        assert!(slot.take_generation(rt.generation()).is_some());
        assert!(slot.get().is_none());
        assert!(
            !slot.is_closed(),
            "a retired runtime leaves the slot reusable"
        );
    }

    /// Kao's proxy setting turned on mid-session refuses new dapps only on a runtime that dials a
    /// remote relay directly — never one already proxied, or a relay on this machine.
    #[tokio::test]
    async fn only_a_direct_route_is_refused_while_the_proxy_waits_for_a_restart() {
        let relay = RelayServer::new();
        for (name, route, refused) in [
            ("direct", RouteKind::Direct, true),
            ("proxied", RouteKind::Proxied, false),
            ("loopback", RouteKind::Loopback, false),
        ] {
            let rt =
                WcRuntime::start_with_connector(relay.connector(name), next_generation(), route)
                    .await
                    .expect("runtime starts");
            assert_eq!(
                rt.route_refusal(true),
                refused.then_some(RouteError::RestartPending),
                "{route:?}"
            );
            assert_eq!(rt.route_refusal(false), None, "{route:?}");
        }
    }

    #[tokio::test]
    async fn snapshot_carries_generation_and_route() {
        let relay = RelayServer::new();
        let rt = runtime(&relay).await;
        let snap = rt.snapshot(now_secs());
        assert_eq!(snap.generation, rt.generation());
        assert_eq!(snap.route, RouteKind::Loopback);
        assert_eq!(
            format!("{rt:?}"),
            format!("WcRuntime(gen {})", rt.generation())
        );
    }

    /// The snapshot carries the relay the live runtime uses — the origin its saved state keeps —
    /// for the pane to compare with the configured one.
    #[tokio::test]
    async fn snapshot_carries_the_relay_the_runtime_uses() {
        let relay = RelayServer::new();
        let rt = runtime(&relay).await;
        let snap = rt.snapshot(now_secs());
        assert_eq!(snap.relay_url, TEST_RELAY_URL);
        assert_eq!(snap.relay_url, rt.state_record().relay_url);
        assert!(same_relay(
            &snap.relay_url,
            "wss://relay.kao.test/?projectId=x"
        ));
        assert!(!same_relay(&snap.relay_url, "wss://another-relay.kao.test"));
    }

    /// One relay is one scheme, host and port: never the path, the query or an explicit default
    /// port; a URL that doesn't parse is never the same relay.
    #[test]
    fn same_relay_compares_scheme_host_and_port() {
        let default = "wss://relay.walletconnect.org";
        for same in [
            "wss://relay.walletconnect.org",
            "wss://relay.walletconnect.org/",
            "wss://relay.walletconnect.org:443",
            "wss://relay.walletconnect.org/v1?projectId=abc",
            "WSS://Relay.WalletConnect.org",
        ] {
            assert!(same_relay(default, same), "{same}");
            assert!(same_relay(same, default), "{same}");
        }
        for other in [
            "wss://relay.walletconnect.com",
            "ws://relay.walletconnect.org",
            "wss://relay.walletconnect.org:8443",
            "relay.walletconnect.org",
            "",
        ] {
            assert!(!same_relay(default, other), "{other}");
            assert!(!same_relay(other, default), "{other}");
        }
        assert!(!same_relay("", ""), "nothing to compare");
    }

    /// A hold's watch runs until it settles, and then lifts its hold — or until the hold goes
    /// first (its transaction refused as invalid on any node), which drops the watch on the spot.
    #[tokio::test]
    async fn a_hold_that_goes_first_drops_its_watch() {
        use std::time::Duration;
        let relay = RelayServer::new();
        let rt = runtime(&relay).await;
        let safe = ([0x5a; 20], 1);
        let identity = WcIdentity::Safe {
            address: Address::from(safe.0),
            chain_id: safe.1,
        };
        let executor = alloy::primitives::B256::repeat_byte(0xe1);
        let (tell, dropped) = tokio::sync::oneshot::channel::<()>();
        rt.hold_safe_exec(safe, 5, executor, async move {
            let _tell = tell;
            std::future::pending::<HoldEnd>().await
        });
        assert_eq!(rt.with_book(|b| b.safe_exec_held(&identity)), Some(5));
        let holds = rt.with_book(|b| b.safe_execs());
        assert!(holds.release_voided(safe, executor, now_secs()));
        tokio::time::timeout(Duration::from_secs(5), dropped)
            .await
            .expect("the watch is dropped")
            .expect_err("never settled");
        assert_eq!(rt.with_book(|b| b.safe_exec_held(&identity)), None);

        let (settle, settled) = tokio::sync::oneshot::channel::<()>();
        let next = alloy::primitives::B256::repeat_byte(0xe2);
        rt.hold_safe_exec(safe, 5, next, async move {
            let _ = settled.await;
            HoldEnd::Settled
        });
        assert_eq!(rt.with_book(|b| b.safe_exec_held(&identity)), Some(5));
        settle.send(()).expect("the watch is running");
        tokio::time::timeout(Duration::from_secs(5), async {
            while rt.with_book(|b| b.safe_exec_held(&identity)).is_some() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the settled watch lifts its hold");
    }

    #[tokio::test]
    async fn is_live_false_after_mark_closed() {
        let (_relay, dapp, _events, kao, _slot) = testkit::harness().await;
        let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
        let (key, _call) = signing_request(&kao, &dapp, &topic).await;
        let guard = kao.before_send_guard(key.clone());
        assert!(kao.is_live(&key));
        assert_eq!(guard(), Ok(()));
        kao.note_failure(&key, FailureClass::Stale);
        assert_eq!(kao.failure_class(&key), FailureClass::Stale);
        assert_eq!(
            kao.failure_class(&key),
            FailureClass::Retryable,
            "taken once"
        );
        kao.mark_closed();
        assert!(!kao.is_live(&key));
        assert_eq!(guard(), Err(STILL_WANTED_REFUSAL.to_string()));
        assert_eq!(kao.failure_class(&key), FailureClass::Gone);
    }

    #[test]
    fn config_debug_never_prints_the_project_id() {
        let cfg = WcConfig {
            relay_url: url::Url::parse("wss://relay.walletconnect.org/?projectId=abc").unwrap(),
            project_id: Some("0123456789abcdef0123456789abcdef".into()),
            route: Route::Direct,
            generation: 7,
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("0123456789abcdef"), "{dbg}");
        assert!(!dbg.contains("projectId"), "{dbg}");
        assert!(
            dbg.contains("<set>") && dbg.contains("relay.walletconnect.org"),
            "{dbg}"
        );
    }

    #[test]
    fn effective_proxy_prefers_installed_then_exported_all_proxy() {
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |key: &str| {
                vars.iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| (*v).to_string())
            }
        };
        let installed = Some("socks5h://127.0.0.1:9050");
        // What Kao installed is what reqwest uses too (it set ALL_PROXY itself).
        assert_eq!(
            effective_proxy_from(installed, env(&[("ALL_PROXY", "socks5h://10.0.0.1:1080")])),
            Some("socks5h://127.0.0.1:9050".to_string())
        );
        // Nothing installed: a user-exported value still routes (or refuses) the relay.
        assert_eq!(
            effective_proxy_from(None, env(&[("ALL_PROXY", "socks5h://10.0.0.1:1080")])),
            Some("socks5h://10.0.0.1:1080".to_string())
        );
        assert_eq!(
            effective_proxy_from(None, env(&[("all_proxy", "http://corp:3128")])),
            Some("http://corp:3128".to_string())
        );
        assert_eq!(
            effective_proxy_from(
                None,
                env(&[
                    ("ALL_PROXY", "socks5h://a:1"),
                    ("all_proxy", "socks5h://b:2")
                ])
            ),
            Some("socks5h://a:1".to_string()),
            "upper case wins, as in reqwest"
        );
        assert_eq!(
            effective_proxy_from(
                None,
                env(&[("ALL_PROXY", ""), ("all_proxy", "socks5h://b:2")])
            ),
            Some("socks5h://b:2".to_string()),
            "an empty value is no value"
        );
        assert_eq!(effective_proxy_from(None, env(&[])), None);
        assert_eq!(effective_proxy_from(None, env(&[("ALL_PROXY", "")])), None);
    }

    /// An exported proxy Kao can't tunnel through still refuses to start, but the error names the
    /// variable that set it — not Kao's (off) proxy setting — and never repeats its value, which
    /// may carry credentials. Kao's own unusable setting keeps its copy.
    #[test]
    fn exported_unusable_proxy_is_blamed_by_its_variable_name() {
        let relay = url::Url::parse("wss://relay.walletconnect.org").unwrap();
        let start_error = |installed: Option<&str>, var: &'static str, value: &'static str| {
            let eff = effective_proxy_source_from(installed, |k: &str| {
                (k == var).then(|| value.to_string())
            });
            StartError::Route(route_for_effective(&relay, eff.as_ref(), false).unwrap_err())
                .to_string()
        };
        for (var, value) in [
            ("HTTPS_PROXY", "http://user:hunter2@127.0.0.1:7890"),
            ("https_proxy", "socks5://127.0.0.1:1080"),
            ("ALL_PROXY", "http://corp:3128"),
            ("all_proxy", "socks5h://no-port"),
        ] {
            let shown = start_error(None, var, value);
            assert!(!shown.contains("Kao's proxy setting"), "{var}: {shown}");
            assert!(shown.contains(var), "{var}: {shown}");
            assert!(
                !shown.contains(value) && !shown.contains("hunter2"),
                "the value never reaches the UI: {shown}"
            );
        }
        // Kao's own setting installed a proxy it can't use: that one is Kao's to fix.
        let shown = start_error(
            Some("http://kao:1"),
            "HTTPS_PROXY",
            "socks5h://127.0.0.1:9050",
        );
        assert!(shown.contains("Kao's proxy setting"), "{shown}");
        // A usable exported proxy still carries the relay.
        let eff = effective_proxy_source_from(None, |k: &str| {
            (k == "https_proxy").then(|| "socks5h://127.0.0.1:9050".to_string())
        });
        assert_eq!(
            eff.as_ref().map(|(_, s)| *s),
            Some(ProxySource::Exported("https_proxy"))
        );
        assert_eq!(
            route_for_effective(&relay, eff.as_ref(), false),
            Ok(Route::Socks5h {
                proxy: "127.0.0.1:9050".into()
            })
        );
    }

    /// An exported proxy reqwest would use is never bypassed: a SOCKS5h one carries the relay, and
    /// anything Kao can't tunnel through refuses to start rather than go direct.
    #[test]
    fn exported_proxy_routes_or_refuses_never_direct() {
        let relay = url::Url::parse("wss://relay.walletconnect.org").unwrap();
        let exported =
            |v: &'static str| move |key: &str| (key == "ALL_PROXY").then(|| v.to_string());
        let socks = effective_proxy_from(None, exported("socks5h://127.0.0.1:9150"));
        assert_eq!(
            transport::route_for(&relay, socks.as_deref(), false),
            Ok(Route::Socks5h {
                proxy: "127.0.0.1:9150".into()
            })
        );
        let http = effective_proxy_from(None, exported("http://corp:3128"));
        assert_eq!(
            transport::route_for(&relay, http.as_deref(), false),
            Err(RouteError::ProxyScheme)
        );
    }

    /// Lock, quit (a suspend or a teardown) and retire all go through `mark_closed`, so each one
    /// also switches Kao's connector off: a reconnect the crate has in flight never reaches the
    /// relay afterwards.
    #[tokio::test]
    async fn mark_closed_switches_the_connector_off() {
        let relay = RelayServer::new();
        let off = ConnectorShutdown::default();
        let kao = WcRuntime::start_inner(
            relay.connector("kao"),
            StartParts::test(next_generation(), RouteKind::Loopback, Some(off.clone())),
        )
        .await
        .expect("starts on the in-process relay");
        assert!(!off.is_closed());
        kao.mark_closed();
        assert!(off.is_closed());

        // retire() and teardown() mark the runtime closed on their way.
        let off = ConnectorShutdown::default();
        let kao = WcRuntime::start_inner(
            relay.connector("kao-2"),
            StartParts::test(next_generation(), RouteKind::Loopback, Some(off.clone())),
        )
        .await
        .expect("starts on the in-process relay");
        kao.teardown(Duration::from_millis(200)).await;
        assert!(off.is_closed());
    }

    #[tokio::test]
    async fn is_live_false_after_session_delete() {
        let (_relay, dapp, _events, kao, _slot) = testkit::harness().await;
        let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
        let (key, call) = signing_request(&kao, &dapp, &topic).await;
        assert!(kao.is_live(&key));
        dapp.disconnect(&topic).await.expect("dapp disconnects");
        testkit::settle(|| !kao.is_live(&key)).await;
        assert!(!kao.is_live(&key));
        // The forwarder marked the signing entry gone without any dashboard around.
        let gone = kao.with_book(|b| b.request(&key).and_then(|q| q.gone));
        assert_eq!(gone, Some(GoneReason::DappDisconnected));
        assert!(kao.with_book(|b| b.session(&topic).is_none()));
        assert!(
            tokio::time::timeout(Duration::from_secs(5), call)
                .await
                .expect("dapp call ends")
                .expect("task")
                .is_err()
        );
    }

    #[tokio::test]
    async fn is_live_false_within_expiry_margin() {
        let (relay, dapp, _events, kao, _slot) = testkit::harness().await;
        let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
        let key = testkit::session_key(&dapp, &topic);
        let mut raw = RawPeer::attach(&relay, "raw");
        let now = now_secs();
        let params = testkit::personal_sign_params("hi", ADDR);
        for (id, expiry) in [(42, now + 3), (43, now + 120)] {
            let request =
                json!({ "method": "personal_sign", "params": params, "expiryTimestamp": expiry });
            raw.inject_request(&topic, &key, id, 1, request).await;
        }
        for _ in 0..2 {
            let (req, at) = testkit::next_request(&kao.events()).await;
            let k = WcKey {
                topic: req.topic.clone(),
                id: req.id,
            };
            kao.admit(&req, at, Ok(testkit::admitted_personal(ADDR, 1, "hi")));
            kao.with_book(|b| {
                assert!(b.mark_in_review(&k, req.id));
                assert!(b.mark_signing(&k, req.id));
            });
        }
        let short = WcKey {
            topic: topic.clone(),
            id: 42,
        };
        let long = WcKey {
            topic: topic.clone(),
            id: 43,
        };
        // Still pending in the crate, but inside the 5 s sweep margin: dead for Kao.
        assert!(kao.client().pending_requests().iter().any(|p| p.id == 42));
        assert!(!kao.is_live(&short));
        assert!(kao.is_live(&long));
        assert_eq!(kao.failure_class(&short), FailureClass::Gone);
    }

    #[tokio::test]
    async fn before_send_guard_refuses_once_the_runtime_is_gone() {
        let relay = RelayServer::new();
        let rt = runtime(&relay).await;
        let key = WcKey {
            topic: Topic::new("ab".repeat(32)),
            id: 1,
        };
        let guard = rt.before_send_guard(key);
        assert!(guard().is_err(), "nothing queued under this key");
        drop(rt);
        assert_eq!(guard(), Err(STILL_WANTED_REFUSAL.to_string()));
    }

    #[tokio::test]
    async fn approve_gate_orders_request_after_bind() {
        let (_relay, dapp, _events, kao, _slot) = testkit::harness().await;
        let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
        // Hold the gate as an in-flight approve would.
        let gate = kao.inner.approve_gate.lock().await;
        let (d, t) = (dapp.clone(), topic.clone());
        let _call = tokio::spawn(async move {
            let params = testkit::personal_sign_params("hi", ADDR);
            d.request(&t, &caip2(1), SessionRequest::new("personal_sign", params))
                .await
        });
        let held = testkit::drain_for(&kao.events(), Duration::from_millis(300)).await;
        assert!(
            !held
                .iter()
                .any(|i| matches!(i, WcStreamItem::Request { .. })),
            "no request reaches the dashboard while a binding may be in flight"
        );
        drop(gate);
        let (req, _) = testkit::next_request(&kao.events()).await;
        assert_eq!(req.topic, topic);
        assert!(kao.with_book(|b| b.session(&req.topic).is_some()));
    }

    /// No dashboard drains the stream while the user is on another screen, so the queue caps —
    /// enforced at admission — don't run. A connected dapp's flood still can't pile up without
    /// bound: past a backlog admission would never queue anyway, each request is refused at the
    /// door (−32005), and the requests let through still reach the next dashboard.
    #[tokio::test]
    async fn a_flood_while_no_dashboard_listens_is_refused_at_the_door() {
        let (_relay, dapp, _events, kao, _slot) = testkit::harness().await;
        let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
        let n = 200usize;
        let calls: Vec<DappCall> = (0..n)
            .map(|i| {
                let (dapp, t) = (dapp.clone(), topic.clone());
                tokio::spawn(async move {
                    let params = testkit::personal_sign_params(&format!("m{i}"), ADDR);
                    dapp.request(&t, &caip2(1), SessionRequest::new("personal_sign", params))
                        .await
                })
            })
            .collect();
        let held = MAX_BACKLOG_PER_SESSION;
        testkit::settle_within(Duration::from_secs(20), || {
            calls.iter().filter(|c| c.is_finished()).count() >= n - held
        })
        .await;
        assert!(
            kao.client().pending_requests().len() <= held,
            "the crate holds {} unanswered requests",
            kao.client().pending_requests().len()
        );
        let mut answered = 0;
        let mut waiting = Vec::new();
        for call in calls {
            if call.is_finished() {
                let got = call.await.expect("the dapp task");
                assert!(
                    matches!(&got, Err(wallet_connect::Error::Peer(e)) if e.code == codes::LIMIT_EXCEEDED),
                    "{got:?}"
                );
                answered += 1;
            } else {
                waiting.push(call);
            }
        }
        assert_eq!(answered, n - held, "refused at the door");
        testkit::settle(|| kao.with_book(|b| b.outbox_len() == 0)).await;
        // The next dashboard gets the ones let through — the stream didn't grow with the flood
        // past them — and once it drains them, the door opens again.
        let items = testkit::drain_for(&kao.events(), Duration::from_millis(500)).await;
        let buffered = items
            .iter()
            .filter(|i| matches!(i, WcStreamItem::Request { .. }))
            .count();
        assert_eq!(buffered, held);
        assert!(
            items.len() <= held + 4,
            "{} items waited in the stream",
            items.len()
        );
        let (_key, _call) = signing_request(&kao, &dapp, &topic).await;
        drop(waiting);
    }

    #[tokio::test]
    async fn forwarder_flushes_outbox_on_reconnect() {
        let (relay, dapp, _events, kao, _slot) = testkit::harness().await;
        let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
        let (key, call) = signing_request(&kao, &dapp, &topic).await;
        relay.disconnect_all();
        kao.answer(&key, Answer::Result(json!("0xfeed")));
        let got = tokio::time::timeout(Duration::from_secs(10), call)
            .await
            .expect("the answer arrives after the reconnect")
            .expect("task");
        assert_eq!(got.expect("a result"), json!("0xfeed"));
        testkit::settle(|| kao.snapshot(now_secs()).undelivered == 0).await;
        assert!(kao.client().pending_requests().is_empty());
        assert!(kao.with_book(|b| b.outbox_len() == 0));
    }

    #[tokio::test]
    async fn idle_runtime_retires_after_grace() {
        let (_relay, _dapp, _events, kao, slot) = testkit::harness().await;
        let now = now_secs();
        let retire = |fx: &Effects| fx.net.iter().any(|e| matches!(e, NetEffect::Retire { .. }));
        let fx = kao.with_book(|b| b.tick(now));
        assert!(!retire(&fx));
        kao.apply(fx);
        assert!(slot.get().is_some());
        let fx = kao.with_book(|b| b.tick(now + IDLE_RETIRE_SECS));
        assert!(retire(&fx));
        kao.apply(fx);
        // Taken out of the slot right away; the slot can start a fresh runtime later.
        assert!(slot.get().is_none());
        assert!(kao.is_closed());
        assert!(!slot.is_closed());
        assert_eq!(
            slot.take_retire_notice(),
            Some(RetireNotice {
                text: IDLE_RETIRE_REASON.to_string(),
                error: false
            })
        );
        testkit::settle(|| !kao.client().relay().is_connected()).await;
        assert!(
            !kao.client().relay().is_connected(),
            "the relay socket is closed"
        );
    }

    #[tokio::test]
    async fn retire_leaves_a_runtime_it_no_longer_owns() {
        let (_relay, _dapp, _events, kao, slot) = testkit::harness().await;
        // A lock took the runtime first; its own teardown owns it now.
        let taken = slot.close().expect("installed");
        kao.retire("idle");
        assert!(!kao.is_closed());
        assert_eq!(taken.generation(), kao.generation());

        // A runtime that never made it into a slot retires itself.
        let relay = RelayServer::new();
        let orphan = runtime(&relay).await;
        orphan.retire("idle");
        assert!(orphan.is_closed());
    }

    /// A retire leaves its reason in the slot for the dashboard — once; a new runtime clears it.
    #[tokio::test]
    async fn retire_records_its_reason_in_the_slot() {
        let (relay, _dapp, _events, kao, slot) = testkit::harness().await;
        kao.retire(FLAP_RETIRE_REASON);
        assert_eq!(
            slot.take_retire_notice(),
            Some(RetireNotice {
                text: FLAP_RETIRE_REASON.to_string(),
                error: true
            })
        );
        assert_eq!(slot.take_retire_notice(), None, "once");
        let idle = runtime(&relay).await;
        slot.install(idle.clone()).expect("installs");
        idle.retire(IDLE_RETIRE_REASON);
        let next = runtime(&relay).await;
        slot.install(next).expect("installs");
        assert_eq!(
            slot.take_retire_notice(),
            None,
            "the next runtime makes it history"
        );
        // A runtime a lock took first records nothing: the lock owns its teardown.
        let taken = slot.close().expect("installed");
        taken.retire(IDLE_RETIRE_REASON);
        assert_eq!(slot.take_retire_notice(), None);
    }

    /// Quit waits for every teardown still running — a retire's, a keyless lock's — and for nothing
    /// when none is: exiting would cut their session deletes.
    #[tokio::test]
    async fn quit_waits_for_teardowns_still_running() {
        let empty = WcSlot::new();
        assert!(
            empty.quit(VaultFlush::none()).is_none(),
            "nothing running: exit at once"
        );
        assert!(empty.is_closed());

        // Turn off / idle / flap: the runtime has left the slot, its teardown runs on.
        let (_relay, dapp, _events, kao, slot) = testkit::harness().await;
        let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
        kao.retire("You turned WalletConnect off.");
        let wait = slot
            .quit(VaultFlush::none())
            .expect("the retire's teardown is still running");
        wait.await;
        assert!(!kao.client().relay().is_connected(), "torn down by then");
        assert!(kao.client().sessions().is_empty());
        testkit::settle(|| !dapp.sessions().iter().any(|s| s.topic == topic)).await;
        assert!(!dapp.sessions().iter().any(|s| s.topic == topic));

        // A lock without a data key (nothing to suspend into): the slot's successor keeps count of
        // the old slot's teardown. With a key it suspends instead (`restore_tests`).
        let (_relay, dapp, _events, kao, slot) = testkit::harness().await;
        let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
        let next = slot.successor();
        assert!(!next.is_closed() && next.get().is_none());
        let rt = slot.close().expect("installed");
        drop(slot.spawn_teardown(rt));
        assert!(kao.is_closed(), "closed synchronously");
        let wait = next
            .quit(VaultFlush::none())
            .expect("the lock's teardown is still running");
        wait.await;
        assert!(!kao.client().relay().is_connected(), "torn down by then");
        testkit::settle(|| !dapp.sessions().iter().any(|s| s.topic == topic)).await;
        assert!(!dapp.sessions().iter().any(|s| s.topic == topic));
        assert!(
            next.quit(VaultFlush::none()).is_none(),
            "nothing left to wait for"
        );
    }

    #[tokio::test]
    async fn closed_runtime_admits_and_pairs_nothing() {
        let (_relay, _dapp, _events, kao, _slot) = testkit::harness().await;
        kao.mark_closed();
        let req = PendingRequest {
            id: 1,
            topic: Topic::new("cd".repeat(32)),
            chain_id: caip2(1),
            request: SessionRequest::new("personal_sign", json!([])),
        };
        assert!(
            kao.admit(
                &req,
                now_secs(),
                Ok(testkit::admitted_personal(ADDR, 1, "hi"))
            )
            .is_empty()
        );
        assert!(kao.with_book(|b| {
            b.request(&WcKey {
                topic: req.topic.clone(),
                id: 1,
            })
            .is_none()
        }));
        assert!(
            kao.pair(zeroize::Zeroizing::new("wc:x".into()), now_secs())
                .is_err()
        );
    }

    // ── a man in the middle between Kao and the in-process relay ──

    /// What the tap does with one frame.
    pub(super) enum Tap {
        Pass,
        /// Kao → relay only: answer the request with a relay JSON-RPC error instead of sending it.
        Fail,
        /// Pass it on once this is notified.
        HoldUntil(Arc<tokio::sync::Notify>),
        /// Drop it and the whole connection (the crate reconnects).
        Cut,
    }

    fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
        m.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn is_publish(v: &Value, tag: u64) -> bool {
        v["method"] == "irn_publish" && v["params"]["tag"] == tag
    }

    /// A relay response (no method) to request `id`.
    fn is_ack_of(v: &Value, id: &Mutex<Option<Value>>) -> bool {
        v.get("method").is_none() && lock(id).as_ref().is_some_and(|id| v.get("id") == Some(id))
    }

    /// Kao's connector: its FIRST connection runs every frame past `up` (Kao → relay) and `down`
    /// (relay → Kao); reconnects go straight to the relay.
    pub(super) fn tapped(
        server: RelayServer,
        up: impl Fn(&Value) -> Tap + Send + Sync + 'static,
        down: impl Fn(&Value) -> Tap + Send + Sync + 'static,
    ) -> impl wallet_connect::relay::Connector {
        use wallet_connect::relay::Connection;
        let (up, down) = (Arc::new(up), Arc::new(down));
        let first = Arc::new(AtomicBool::new(true));
        move || {
            let (server, up, down) = (server.clone(), up.clone(), down.clone());
            let tap = first.swap(false, Ordering::SeqCst);
            async move {
                let real = server.accept("kao");
                if !tap {
                    return Ok(real);
                }
                let (kao_end, mitm) = Connection::pair();
                let Connection {
                    sender: to_relay,
                    receiver: mut from_relay,
                } = real;
                let Connection {
                    sender: to_kao,
                    receiver: mut from_kao,
                } = mitm;
                let (cut_tx, cut_rx) = tokio::sync::watch::channel(false);
                let (to_kao_up, cut_up, mut cut_seen) = (to_kao.clone(), cut_tx.clone(), cut_rx);
                tokio::spawn(async move {
                    loop {
                        let frame = tokio::select! {
                            f = from_kao.recv() => f,
                            _ = cut_seen.changed() => None,
                        };
                        let Some(f) = frame else { break };
                        let v: Value = serde_json::from_str(&f).unwrap_or_default();
                        match up(&v) {
                            Tap::Pass => {}
                            Tap::Fail => {
                                let error = json!({ "id": v["id"], "jsonrpc": "2.0",
                                    "error": { "code": -32603, "message": "internal error" } });
                                let _ = to_kao_up.send(error.to_string());
                                continue;
                            }
                            Tap::HoldUntil(n) => n.notified().await,
                            Tap::Cut => {
                                let _ = cut_up.send(true);
                                break;
                            }
                        }
                        if to_relay.send(f).is_err() {
                            break;
                        }
                    }
                });
                let mut cut_seen = cut_tx.subscribe();
                tokio::spawn(async move {
                    loop {
                        let frame = tokio::select! {
                            f = from_relay.recv() => f,
                            _ = cut_seen.changed() => None,
                        };
                        let Some(f) = frame else { break };
                        let v: Value = serde_json::from_str(&f).unwrap_or_default();
                        match down(&v) {
                            Tap::Pass | Tap::Fail => {}
                            Tap::HoldUntil(n) => n.notified().await,
                            Tap::Cut => {
                                let _ = cut_tx.send(true);
                                break;
                            }
                        }
                        if to_kao.send(f).is_err() {
                            break;
                        }
                    }
                });
                Ok(kao_end)
            }
        }
    }

    /// Kao over `connector`, with the dapp's link pasted and its card up.
    async fn card_over(
        connector: impl wallet_connect::relay::Connector,
        dapp: &SignClient,
    ) -> (WcRuntime, Proposal, wallet_connect::sign::ConnectResponse) {
        card_over_in(connector, dapp, Vault::new().session()).await
    }

    /// [`card_over`], persisting to `vault`'s epoch.
    async fn card_over_in(
        connector: impl wallet_connect::relay::Connector,
        dapp: &SignClient,
        vault: VaultSession,
    ) -> (WcRuntime, Proposal, wallet_connect::sign::ConnectResponse) {
        let kao = WcRuntime::start_with_connector_in(
            connector,
            next_generation(),
            RouteKind::Loopback,
            vault,
        )
        .await
        .expect("starts on the in-process relay");
        let resp = testkit::dapp_connect(
            dapp,
            std::collections::BTreeMap::new(),
            testkit::modern_optional(&[1]),
        )
        .await;
        let uri = testkit::uri_of(&resp);
        kao.with_book(|b| b.expect_pairing(resp.pairing_topic.clone(), now_secs(), None));
        kao.client().pair(&uri).await.expect("Kao pairs");
        let p = testkit::wait_card(&kao).await;
        (kao, p, resp)
    }

    fn eoa_ticket(p: &Proposal) -> ApproveTicket {
        let caps = testkit::local_eoa_caps(ADDR);
        testkit::ticket(p, &caps, testkit::manual_grant(p, ADDR, &[1]))
    }

    /// Approving while the relay reconnects would fail at the approve's first network step,
    /// before anything reaches the dapp — so it isn't tried: the card stays, saying why, and
    /// approving again once the relay is back connects the dapp.
    #[tokio::test]
    async fn approve_during_a_relay_reconnect_keeps_the_card() {
        let relay = RelayServer::new();
        let (dapp, _dapp_events) = testkit::dapp_client(&relay, "dapp").await;
        let (kao, p, resp) = card_over(relay.connector("kao"), &dapp).await;
        relay.disconnect_all();
        testkit::settle(|| !kao.client().relay().is_connected()).await;
        kao.approve(eoa_ticket(&p)).expect("approve starts");
        testkit::settle(|| kao.with_book(|b| !b.proposal().is_some_and(|c| c.busy))).await;
        let card = kao.with_book(|b| b.proposal().cloned());
        assert!(
            card.as_ref()
                .and_then(|c| c.error.as_deref())
                .is_some_and(|e| e.contains("reconnecting")),
            "the card stays, saying why: {card:?}"
        );
        assert!(kao.with_book(|b| b.snapshot(now_secs()).sessions.is_empty()));
        testkit::settle_within(Duration::from_secs(10), || {
            kao.client().relay().is_connected()
        })
        .await;
        kao.approve(eoa_ticket(&p))
            .expect("approved once the relay is back");
        tokio::time::timeout(Duration::from_secs(10), resp.approval)
            .await
            .expect("the dapp hears back")
            .expect("the dapp is connected");
    }

    /// A Turn off (or a lock / quit without a data key) landing while an approve waits for the
    /// relay's ack of its settle: the dapp already holds the session, so the teardown must wait for
    /// the approve to bind it and then disconnect it — never leave the dapp a session Kao forgot.
    #[tokio::test]
    async fn teardown_waits_for_an_approve_in_flight() {
        let relay = RelayServer::new();
        let (dapp, _dapp_events) = testkit::dapp_client(&relay, "dapp").await;
        let settle_id: Arc<Mutex<Option<Value>>> = Arc::default();
        let settle_sent = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let (id_up, sent, id_down, held) = (
            settle_id.clone(),
            settle_sent.clone(),
            settle_id.clone(),
            release.clone(),
        );
        let connector = tapped(
            relay.clone(),
            move |v| {
                if is_publish(v, 1102) {
                    *lock(&id_up) = Some(v["id"].clone());
                    sent.notify_one();
                }
                Tap::Pass
            },
            // The relay's ack of the settle publish takes a round trip.
            move |v| match is_ack_of(v, &id_down) {
                true => Tap::HoldUntil(held.clone()),
                false => Tap::Pass,
            },
        );
        let (kao, p, resp) = card_over(connector, &dapp).await;
        kao.approve(eoa_ticket(&p)).expect("approve starts");
        tokio::time::timeout(Duration::from_secs(3), settle_sent.notified())
            .await
            .expect("the settle reached the relay");
        assert!(kao.with_book(|b| b.proposal().is_some_and(|c| c.busy)));
        assert!(
            kao.with_book(|b| b.sessions().is_empty()),
            "nothing bound yet"
        );

        kao.mark_closed();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            release.notify_one();
        });
        kao.clone().teardown(Duration::from_millis(500)).await;
        let approval = tokio::time::timeout(Duration::from_secs(3), resp.approval).await;
        assert!(matches!(approval, Ok(Ok(_))), "the dapp settled");
        testkit::settle(|| dapp.sessions().is_empty()).await;
        assert!(
            dapp.sessions().is_empty(),
            "the teardown disconnected the session the approve bound"
        );
    }

    /// Turn off while an approve waits for the relay's ack of its settle: Turn off ends the history
    /// of the sessions bound so far, and the session the approve binds afterwards must not stay
    /// "Connected now" in Connection history — its record ends `TurnedOff`, whether the approve
    /// binds within the teardown's wait for it or only once the teardown shut the client down.
    #[tokio::test]
    async fn turn_off_during_an_approve_ends_the_record_it_opens() {
        for release_after in [Some(Duration::from_millis(100)), None] {
            let vault = testkit::keyed_vault();
            let relay = RelayServer::new();
            let (dapp, _dapp_events) = testkit::dapp_client(&relay, "dapp").await;
            let settle_id: Arc<Mutex<Option<Value>>> = Arc::default();
            let settle_sent = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            let (id_up, sent, id_down, held) = (
                settle_id.clone(),
                settle_sent.clone(),
                settle_id.clone(),
                release.clone(),
            );
            let connector = tapped(
                relay.clone(),
                move |v| {
                    if is_publish(v, 1102) {
                        *lock(&id_up) = Some(v["id"].clone());
                        sent.notify_one();
                    }
                    Tap::Pass
                },
                // The relay's ack of the settle publish waits (or never comes).
                move |v| match is_ack_of(v, &id_down) {
                    true => Tap::HoldUntil(held.clone()),
                    false => Tap::Pass,
                },
            );
            let (kao, p, _resp) = card_over_in(connector, &dapp, vault.session()).await;
            let slot = WcSlot::with_vault(vault.clone());
            slot.install(kao.clone()).expect("installs");
            kao.approve(eoa_ticket(&p)).expect("approve starts");
            tokio::time::timeout(Duration::from_secs(3), settle_sent.notified())
                .await
                .expect("the settle reached the relay");
            assert!(vault.connections().is_empty(), "nothing bound yet");

            kao.retire("You turned WalletConnect off.");
            if let Some(after) = release_after {
                tokio::spawn(async move {
                    tokio::time::sleep(after).await;
                    release.notify_one();
                });
            }
            slot.quit(VaultFlush::none())
                .expect("the teardown runs")
                .await;
            testkit::settle_within(Duration::from_secs(5), || !vault.connections().is_empty())
                .await;
            let records = vault.connections();
            assert_eq!(records.len(), 1, "{release_after:?}: {records:?}");
            assert!(
                !records[0].is_open(),
                "{release_after:?}: never \"Connected now\" after Turn off: {records:?}"
            );
            assert_eq!(
                records[0].end,
                Some(EndReason::TurnedOff),
                "{release_after:?}"
            );
            vault.wait_writer_idle().await;
            assert!(
                matches!(vault.last_saved_wc_state(), Some(None)),
                "{release_after:?}: and nothing saved the state back"
            );
        }
    }

    /// The socket dies after the settle reached the relay, losing the relay's ack: the dapp holds
    /// the session, and so does Kao — bound, never offered for a second settle, and confirmed by
    /// the dapp's acknowledgement once the relay is back.
    #[tokio::test]
    async fn a_settle_whose_relay_ack_is_lost_keeps_the_session_the_dapp_holds() {
        let relay = RelayServer::new();
        let (dapp, _dapp_events) = testkit::dapp_client(&relay, "dapp").await;
        let settle_id: Arc<Mutex<Option<Value>>> = Arc::default();
        let (id_up, id_down) = (settle_id.clone(), settle_id.clone());
        let connector = tapped(
            relay.clone(),
            move |v| {
                if is_publish(v, 1102) {
                    *lock(&id_up) = Some(v["id"].clone());
                }
                Tap::Pass
            },
            // The relay's ack is lost with the socket.
            move |v| match is_ack_of(v, &id_down) {
                true => Tap::Cut,
                false => Tap::Pass,
            },
        );
        let (kao, p, resp) = card_over(connector, &dapp).await;
        let (uri, resp_topic) = (testkit::uri_of(&resp), resp.pairing_topic.clone());
        kao.approve(eoa_ticket(&p)).expect("approve starts");
        let approval = tokio::time::timeout(Duration::from_secs(3), resp.approval).await;
        let Ok(Ok(dapp_session)) = approval else {
            panic!("the dapp settled: {approval:?}");
        };
        testkit::settle(|| kao.with_book(|b| b.session(&dapp_session.topic).is_some())).await;
        assert!(
            kao.with_book(|b| b.session(&dapp_session.topic).is_some()),
            "Kao bound the session the dapp holds"
        );
        assert!(
            kao.with_book(|b| b.proposal().is_none()),
            "the card is done"
        );
        testkit::settle_within(Duration::from_secs(10), || {
            kao.with_book(|b| {
                b.session(&dapp_session.topic)
                    .is_some_and(|s| s.ack == AckState::Confirmed)
            })
        })
        .await;
        assert_eq!(
            kao.with_book(|b| b.session(&dapp_session.topic).map(|s| s.ack)),
            Some(AckState::Confirmed),
            "the dapp's acknowledgement arrives once the relay is back"
        );
        let notices = kao.snapshot(now_secs()).notices;
        assert!(
            !notices.iter().any(|n| n.error),
            "nothing went wrong to report: {notices:?}"
        );
        assert_eq!(
            kao.approve(eoa_ticket(&p)),
            Err(crate::walletconnect::book::APPROVE_GONE),
            "a second settle for the same proposal is refused"
        );
        // The proposal was answered for good: pasting the link again brings no card back.
        kao.with_book(|b| b.expect_pairing(resp_topic.clone(), now_secs(), None));
        kao.client().pair(&uri).await.expect("Kao pairs again");
        assert!(kao.client().proposals().is_empty());
        assert!(kao.with_book(|b| b.proposal().is_none()));
        assert_eq!(kao.with_book(|b| b.sessions().len()), 1);
    }

    /// The relay refuses the answer to the proposal: nothing reached the dapp, so the card stays,
    /// saying so, and approving again connects the dapp.
    #[tokio::test]
    async fn an_approve_whose_answer_the_relay_refused_can_be_retried() {
        let relay = RelayServer::new();
        let (dapp, _dapp_events) = testkit::dapp_client(&relay, "dapp").await;
        let failed = Arc::new(AtomicBool::new(false));
        let f = failed.clone();
        let connector = tapped(
            relay.clone(),
            move |v| match is_publish(v, 1101) && !f.swap(true, Ordering::SeqCst) {
                true => Tap::Fail,
                false => Tap::Pass,
            },
            |_| Tap::Pass,
        );
        let (kao, p, resp) = card_over(connector, &dapp).await;
        kao.approve(eoa_ticket(&p)).expect("approve starts");
        testkit::settle(|| kao.with_book(|b| !b.proposal().is_some_and(|c| c.busy))).await;
        assert!(
            failed.load(Ordering::SeqCst),
            "the relay refused the answer"
        );
        let card = kao.with_book(|b| b.proposal().cloned());
        assert_eq!(
            card.as_ref().and_then(|c| c.error.as_deref()),
            Some(NOTHING_SENT),
            "the card stays, saying why: {card:?}"
        );
        assert!(kao.with_book(|b| b.sessions().is_empty()));
        kao.approve(eoa_ticket(&p)).expect("approving again starts");
        let session = tokio::time::timeout(Duration::from_secs(5), resp.approval)
            .await
            .expect("the dapp hears back")
            .expect("the dapp is connected");
        testkit::settle(|| kao.with_book(|b| b.session(&session.topic).is_some())).await;
        assert_eq!(kao.with_book(|b| b.sessions().len()), 1);
    }

    /// The relay refuses the settle after the answer went out: the dapp holds no session and the
    /// proposal is spent, so the card goes and the user is told to reconnect from the dapp.
    #[tokio::test]
    async fn an_approve_whose_settle_the_relay_refused_is_abandoned() {
        let relay = RelayServer::new();
        let (dapp, _dapp_events) = testkit::dapp_client(&relay, "dapp").await;
        let failed = Arc::new(AtomicBool::new(false));
        let f = failed.clone();
        let connector = tapped(
            relay.clone(),
            move |v| match is_publish(v, 1102) && !f.swap(true, Ordering::SeqCst) {
                true => Tap::Fail,
                false => Tap::Pass,
            },
            |_| Tap::Pass,
        );
        let (kao, p, _resp) = card_over(connector, &dapp).await;
        kao.approve(eoa_ticket(&p)).expect("approve starts");
        testkit::settle(|| kao.with_book(|b| b.proposal().is_none())).await;
        assert!(
            failed.load(Ordering::SeqCst),
            "the relay refused the settle"
        );
        assert!(
            kao.with_book(|b| b.proposal().is_none()),
            "no card to retry from"
        );
        assert!(kao.with_book(|b| b.sessions().is_empty()));
        assert!(
            kao.client().sessions().is_empty(),
            "the crate dropped it too"
        );
        let notices = kao.snapshot(now_secs()).notices;
        assert!(
            notices
                .iter()
                .any(|n| n.error && n.text.contains("reconnect from the dapp")),
            "{notices:?}"
        );
        assert_eq!(
            kao.approve(eoa_ticket(&p)),
            Err(crate::walletconnect::book::APPROVE_GONE)
        );
    }

    /// Kao's 60-min TTL never cuts a signing short — only the dapp's own deadline does.
    #[tokio::test]
    async fn kao_ttl_never_cuts_signing_short() {
        let (relay, dapp, _events, kao, _slot) = testkit::harness().await;
        let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
        let key = testkit::session_key(&dapp, &topic);
        let mut raw = RawPeer::attach(&relay, "raw");
        let now = now_secs();
        let params = testkit::personal_sign_params("hi", ADDR);
        let long =
            json!({ "method": "personal_sign", "params": params, "expiryTimestamp": now + 7_200 });
        raw.inject_request(&topic, &key, 50, 1, long).await;
        let open = json!({ "method": "personal_sign", "params": params });
        raw.inject_request(&topic, &key, 51, 1, open).await;
        // Received just under an hour ago, so Kao's TTL has (almost) run out for both.
        let received = now - crate::walletconnect::KAO_REQUEST_TTL_SECS + 3;
        for _ in 0..2 {
            let (req, _at) = testkit::next_request(&kao.events()).await;
            let k = WcKey {
                topic: req.topic.clone(),
                id: req.id,
            };
            kao.admit(
                &req,
                received,
                Ok(testkit::admitted_personal(ADDR, 1, "hi")),
            );
            kao.with_book(|b| {
                assert!(b.mark_in_review(&k, req.id));
                assert!(b.mark_signing(&k, req.id));
            });
        }
        let key_of = |id| WcKey {
            topic: topic.clone(),
            id,
        };
        assert!(kao.client().pending_requests().iter().any(|p| p.id == 50));
        assert!(
            kao.is_live(&key_of(51)),
            "no dapp deadline: signing goes on"
        );
        assert!(
            kao.is_live(&key_of(50)),
            "the dapp waits another hour: signing goes on"
        );
    }

    /// A relay JSON-RPC error on a disconnect leaves the session with the crate: Kao keeps the
    /// topic doomed and re-sends, so the dapp is told.
    #[tokio::test]
    async fn relay_error_on_disconnect_is_retried() {
        let relay = RelayServer::new();
        let (dapp, _dapp_events) = testkit::dapp_client(&relay, "dapp").await;
        let failed = Arc::new(AtomicBool::new(false));
        let f = failed.clone();
        let connector = tapped(
            relay.clone(),
            move |v| match is_publish(v, 1112) && !f.swap(true, Ordering::SeqCst) {
                true => Tap::Fail,
                false => Tap::Pass,
            },
            |_| Tap::Pass,
        );
        let kao =
            WcRuntime::start_with_connector(connector, next_generation(), RouteKind::Loopback)
                .await
                .expect("starts on the in-process relay");
        let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
        kao.disconnect(&topic);
        testkit::settle(|| failed.load(Ordering::SeqCst) && kao.with_book(|b| b.is_idle())).await;
        testkit::settle(|| !dapp.sessions().iter().any(|s| s.topic == topic)).await;
        assert!(
            failed.load(Ordering::SeqCst),
            "the relay refused the first delete"
        );
        assert!(
            !dapp.sessions().iter().any(|s| s.topic == topic),
            "the dapp was told"
        );
        assert!(kao.client().session(&topic).is_none());
    }

    /// The same for an answer: a relay JSON-RPC error is not "the dapp stopped waiting".
    #[tokio::test]
    async fn relay_error_on_answer_is_retried() {
        let relay = RelayServer::new();
        let (dapp, _dapp_events) = testkit::dapp_client(&relay, "dapp").await;
        let failed = Arc::new(AtomicBool::new(false));
        let f = failed.clone();
        let connector = tapped(
            relay.clone(),
            move |v| match is_publish(v, 1109) && !f.swap(true, Ordering::SeqCst) {
                true => Tap::Fail,
                false => Tap::Pass,
            },
            |_| Tap::Pass,
        );
        let kao =
            WcRuntime::start_with_connector(connector, next_generation(), RouteKind::Loopback)
                .await
                .expect("starts on the in-process relay");
        let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
        let (key, call) = signing_request(&kao, &dapp, &topic).await;
        kao.answer(&key, Answer::Result(json!("0xfeed")));
        let got = tokio::time::timeout(Duration::from_secs(5), call)
            .await
            .expect("the dapp gets the answer")
            .expect("task");
        assert!(
            failed.load(Ordering::SeqCst),
            "the relay refused the first answer"
        );
        assert_eq!(got.expect("a result"), json!("0xfeed"));
        testkit::settle(|| kao.with_book(|b| b.outbox_len() == 0)).await;
        let notices = kao.snapshot(now_secs()).notices;
        assert!(
            !notices.iter().any(|n| n.text.contains("stopped waiting")),
            "{notices:?}"
        );
    }

    /// reqwest proxies every https call through an exported `HTTPS_PROXY` / `https_proxy` (before
    /// `ALL_PROXY`), so the relay never dials direct while one is set: a SOCKS5h one carries it,
    /// anything else refuses to start.
    #[test]
    fn exported_https_proxy_routes_or_refuses_never_direct() {
        let relay = url::Url::parse("wss://relay.walletconnect.org").unwrap();
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |key: &str| {
                vars.iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| (*v).to_string())
            }
        };
        let route = |eff: Option<String>| transport::route_for(&relay, eff.as_deref(), false);
        for name in ["HTTPS_PROXY", "https_proxy"] {
            let vars: &'static [(&'static str, &'static str)] = match name {
                "HTTPS_PROXY" => &[("HTTPS_PROXY", "socks5h://127.0.0.1:9050")],
                _ => &[("https_proxy", "socks5h://127.0.0.1:9050")],
            };
            assert_eq!(
                route(effective_proxy_from(None, env(vars))),
                Ok(Route::Socks5h {
                    proxy: "127.0.0.1:9050".into()
                }),
                "{name}"
            );
        }
        assert_eq!(
            route(effective_proxy_from(
                None,
                env(&[("https_proxy", "http://corp:3128")])
            )),
            Err(RouteError::ProxyScheme)
        );
        // reqwest's order for an https destination: HTTPS_PROXY, https_proxy, then ALL_PROXY.
        assert_eq!(
            effective_proxy_from(
                None,
                env(&[
                    ("ALL_PROXY", "socks5h://all:1"),
                    ("https_proxy", "socks5h://lower:2"),
                    ("HTTPS_PROXY", "socks5h://upper:3"),
                ])
            ),
            Some("socks5h://upper:3".to_string())
        );
        assert_eq!(
            effective_proxy_from(
                None,
                env(&[
                    ("ALL_PROXY", "socks5h://all:1"),
                    ("https_proxy", "socks5h://lower:2")
                ])
            ),
            Some("socks5h://lower:2".to_string())
        );
        // What Kao installed still wins.
        assert_eq!(
            effective_proxy_from(
                Some("socks5h://kao:9"),
                env(&[("HTTPS_PROXY", "socks5h://upper:3")])
            ),
            Some("socks5h://kao:9".to_string())
        );
    }
}
