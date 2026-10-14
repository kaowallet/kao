//! The App-owned WalletConnect runtime: [`WcSlot`] (where it lives), [`WcRuntime`] (the `SignClient`,
//! the [`WcBook`], a `closed` flag and the tokio handle every relay side effect is spawned on), the
//! event stream the dashboard subscribes to, liveness checks for the signing tasks, and teardown.
//! WalletConnect network effects never ride an iced `Task`: App drops a dashboard's tasks when it
//! rebuilds the dashboard, and an answer, rejection or disconnect must survive that.
//!
//! Background work holds the runtime only weakly: the *forwarder* (crate `SignEvent`s → book or
//! stream) and the *housekeeper* (1 s `book.tick`) stop once the last [`WcRuntime`] clone is
//! dropped; op tasks hold a strong clone only while their network call runs. The book's
//! `std::sync::Mutex` is only ever held for a synchronous critical section (never across `.await`).

use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};
use std::time::Duration;

use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tracing::{debug, info};
use wallet_connect::auth::IdentityKey;
use wallet_connect::crypto::Topic;
use wallet_connect::relay::RelayClientOptions;
use wallet_connect::rpc::ErrorObject;
use wallet_connect::sign::{
    ApproveParams, PendingRequest, Proposal, SessionEvent, SignClient, SignEvent, SignEvents,
};

use super::book::{FLAP_RETIRE_REASON, HoldEnd, SafeExecHolds, WcBook};
use super::transport::{self, ConnectorShutdown, KaoConnector, Timeouts};
use super::types::*;
use super::{EXPIRY_MARGIN_SECS, TEARDOWN_PER_PHASE, caip2, kao_metadata, now_secs, request};

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
}

/// A retired runtime's reason, for the dashboard: Kao's own fixed copy, never dapp data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetireNotice {
    pub text: String,
    /// The relay rejected Kao (flapping): a toast and a failed paste, not just a status line.
    pub error: bool,
}

/// Teardowns still running — lock, Turn off, retire, quit. Each runs on its runtime's own tokio
/// handle (so it no longer depends on iced polling a `Task`) and is counted until it ends, so a
/// quit can wait for every one (bounded by `QUIT_TEARDOWN_BUDGET`) before the process exits and
/// cuts a dapp's `wc_sessionDelete` short.
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
    fn spawn(&self, rt: WcRuntime) -> tokio::task::JoinHandle<()> {
        self.0.send_modify(|n| *n += 1);
        let running = Running(self.0.clone());
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
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, SlotInner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
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

    /// false when a runtime exists, a start is in flight, or the slot is closed.
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
        Ok(())
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

    /// The last retire's reason, once (the dashboard shows it).
    pub fn take_retire_notice(&self) -> Option<RetireNotice> {
        self.lock().retired.take()
    }

    /// Lock / quit: closed forever; returns the runtime to tear down.
    pub fn close(&self) -> Option<WcRuntime> {
        let mut s = self.lock();
        s.closed = true;
        s.starting = false;
        s.rt.take()
    }

    /// The fresh, empty slot that replaces this one on lock. It shares this slot's teardown
    /// registry, so a quit right after a lock still waits for the lock's teardown, and its holds on
    /// executions still unmined.
    pub fn successor(&self) -> WcSlot {
        let s = self.lock();
        WcSlot(Arc::new(Mutex::new(SlotInner {
            teardowns: s.teardowns.clone(),
            holds: s.holds.clone(),
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

    /// Quit: close the slot for good, tear its runtime down, and return what the process must
    /// wait for before it exits — every teardown still running (this one, a lock's, a retire's),
    /// bounded by `QUIT_TEARDOWN_BUDGET` — or `None` when nothing is running.
    pub fn quit(&self) -> Option<impl Future<Output = ()> + Send + use<>> {
        if let Some(rt) = self.close() {
            self.spawn_teardown(rt);
        }
        let teardowns = self.lock().teardowns.clone();
        if teardowns.running() == 0 {
            return None;
        }
        let idle = teardowns.idle();
        Some(async move {
            // Bounded: a dead relay can't trap the window open.
            let _ = tokio::time::timeout(super::QUIT_TEARDOWN_BUDGET, idle).await;
        })
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
}

impl fmt::Debug for WcRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WcRuntime(gen {})", self.inner.generation)
    }
}

impl WcRuntime {
    /// Fresh IdentityKey; KaoConnector::new(cfg.relay_url, cfg.project_id, identity, cfg.route,
    /// Timeouts::for_route(&cfg.route)); start_with_connector(..).
    pub async fn start(cfg: WcConfig) -> Result<WcRuntime, String> {
        // Never persisted: a fresh relay identity per runtime keeps unlocks unlinkable.
        let identity = IdentityKey::generate();
        let kind = transport::route_kind(&cfg.relay_url, &cfg.route);
        let timeouts = Timeouts::for_route(&cfg.route);
        let connector =
            KaoConnector::new(cfg.relay_url, cfg.project_id, identity, cfg.route, timeouts);
        let shutdown = connector.shutdown_handle();
        Self::start_inner(connector, cfg.generation, kind, Some(shutdown)).await
    }

    /// A runtime over any connector — the tests' path (`RelayServer::connector`). Production starts
    /// through [`Self::start`], whose `KaoConnector` is also switched off by `mark_closed`.
    #[cfg(test)]
    pub async fn start_with_connector<C: wallet_connect::relay::Connector>(
        connector: C,
        generation: u64,
        route: RouteKind,
    ) -> Result<WcRuntime, String> {
        Self::start_inner(connector, generation, route, None).await
    }

    /// `Handle::try_current()` (no runtime → Err); SignClient::builder(kao_metadata()).connector(c).relay_options(
    /// RelayClientOptions{ request_timeout: 15 s, reconnect: true, max_backoff: 30 s }).build();
    /// spawns the FORWARDER (Weak) and HOUSEKEEPER (Weak, 1 s).
    async fn start_inner<C: wallet_connect::relay::Connector>(
        connector: C,
        generation: u64,
        route: RouteKind,
        connector_shutdown: Option<ConnectorShutdown>,
    ) -> Result<WcRuntime, String> {
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| "WalletConnect needs Kao's async runtime.".to_string())?;
        let (client, sign_rx) = SignClient::builder(kao_metadata())
            .connector(connector)
            .relay_options(RelayClientOptions {
                request_timeout: RELAY_REQUEST_TIMEOUT,
                reconnect: true,
                max_backoff: RELAY_MAX_BACKOFF,
            })
            .build()
            .await
            .map_err(|e| {
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
        let (tx, rx) = unbounded_channel();
        let inner = Arc::new(Inner {
            client,
            book: Mutex::new(WcBook::new()),
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
        });
        handle.spawn(forward(Arc::downgrade(&inner), sign_rx, tx));
        handle.spawn(housekeeping(Arc::downgrade(&inner)));
        info!(generation, ?route, "WalletConnect runtime started");
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
        let mut book = self
            .inner
            .book
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        f(&mut book)
    }

    pub fn snapshot(&self, now: u64) -> WcSnapshot {
        let mut snap = self.with_book(|b| b.snapshot(now));
        snap.generation = self.inner.generation;
        snap.route = self.inner.route;
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
        in_book
            && self
                .inner
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

    /// [`WcBook::note_unconfirmed`].
    pub fn note_unconfirmed(&self, key: &WcKey, tx: UnconfirmedTx) {
        self.with_book(|b| b.note_unconfirmed(key, tx));
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

    /// Runs `fx.net` on the runtime; hands `fx.ui` back to the (dashboard) caller.
    pub fn apply(&self, fx: Effects) -> Vec<UiEffect> {
        for e in fx.net {
            self.spawn_net(e);
        }
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
                let fx = self.with_book(|b| b.bind_session(&approved.session, ticket, now_secs()));
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
        self.with_book(|b| b.resume(topic));
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
    /// dashboard — mark closed, spawn the (counted) teardown, and wake the dashboard, which reads
    /// the reason from the slot.
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
                    // A lock / quit closed the slot first and is tearing this runtime down already.
                    None => return,
                }
            }
        };
        self.mark_closed();
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

    /// closed=true; wait out an approve in flight; book.teardown(); answers (≤ per_phase, less that
    /// wait) → disconnects (≤ per_phase) → shutdown().
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
        let client = &self.inner.client;
        let mut answers = Vec::new();
        let mut disconnects = Vec::new();
        for e in fx.net {
            match e {
                NetEffect::Respond { key, answer } => {
                    answers.push(futures::future::Either::Left(async move {
                        let r = tokio::time::timeout(
                            per_phase,
                            client.respond(&key.topic, key.id, answer),
                        )
                        .await;
                        debug!(id = key.id, ok = matches!(r, Ok(Ok(()))), "teardown answer");
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
        info!(
            generation = self.inner.generation,
            "WalletConnect runtime torn down"
        );
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
                    let sent = tokio::time::timeout(
                        RESPOND_TIMEOUT,
                        rt.inner.client.respond(&key.topic, key.id, answer),
                    )
                    .await
                    .unwrap_or(Err(wallet_connect::Error::Timeout));
                    // Whatever the error, the crate keeps the request while its session lives:
                    // then the answer is still owed, not "gone".
                    let held = rt
                        .inner
                        .client
                        .pending_requests()
                        .iter()
                        .any(|p| p.id == key.id && p.topic == key.topic);
                    let result = request::respond_result(&sent, held);
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
                    if let Ok(Err(e)) = &sent {
                        debug!(kind = error_kind(e), "pairing delete failed");
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
    /// network effects run here, UI effects and `Changed` go out through the event stream.
    fn apply_background(&self, fx: Effects) {
        for e in fx.net {
            self.spawn_net(e);
        }
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
                self.with_book(|b| b.on_session_extended(&topic, expiry));
                Effects {
                    changed: true,
                    ..Default::default()
                }
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

    #[cfg(test)]
    pub(crate) fn client(&self) -> &SignClient {
        &self.inner.client
    }
}

const CHANGED: &str = "The request changed — reconnect from the dapp.";
/// The card's reason when Connect is pressed while the relay reconnects.
const RECONNECTING: &str = "Kao is reconnecting to the relay — try again in a moment.";
const NOTHING_SENT: &str =
    "The relay didn't take the connection — nothing reached the dapp. Try again.";

/// FORWARDER: applies every crate event that needs no wallet context to the book (even while no
/// dashboard exists) and hands session requests to the dashboard through the stream.
async fn forward(weak: Weak<Inner>, mut sign_rx: SignEvents, tx: UnboundedSender<WcStreamItem>) {
    while let Some(event) = sign_rx.recv().await {
        let Some(inner) = weak.upgrade() else {
            break;
        };
        let rt = WcRuntime { inner };
        if let SignEvent::SessionRequest(req) = event {
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

/// HOUSEKEEPER: `book.tick` every second until the runtime closes or is dropped.
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

    /// Lock, quit and retire all go through `mark_closed`, so each one also switches Kao's
    /// connector off: a reconnect the crate has in flight never reaches the relay afterwards.
    #[tokio::test]
    async fn mark_closed_switches_the_connector_off() {
        let relay = RelayServer::new();
        let off = ConnectorShutdown::default();
        let kao = WcRuntime::start_inner(
            relay.connector("kao"),
            next_generation(),
            RouteKind::Loopback,
            Some(off.clone()),
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
            next_generation(),
            RouteKind::Loopback,
            Some(off.clone()),
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

    /// Quit waits for every teardown still running — a retire's, a lock's — and for nothing when
    /// none is: exiting would cut their session deletes.
    #[tokio::test]
    async fn quit_waits_for_teardowns_still_running() {
        let empty = WcSlot::new();
        assert!(empty.quit().is_none(), "nothing running: exit at once");
        assert!(empty.is_closed());

        // Turn off / idle / flap: the runtime has left the slot, its teardown runs on.
        let (_relay, dapp, _events, kao, slot) = testkit::harness().await;
        let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
        kao.retire("You turned WalletConnect off.");
        let wait = slot.quit().expect("the retire's teardown is still running");
        wait.await;
        assert!(!kao.client().relay().is_connected(), "torn down by then");
        assert!(kao.client().sessions().is_empty());
        testkit::settle(|| !dapp.sessions().iter().any(|s| s.topic == topic)).await;
        assert!(!dapp.sessions().iter().any(|s| s.topic == topic));

        // A lock: the slot's successor keeps count of the old slot's teardown.
        let (_relay, dapp, _events, kao, slot) = testkit::harness().await;
        let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
        let next = slot.successor();
        assert!(!next.is_closed() && next.get().is_none());
        let rt = slot.close().expect("installed");
        drop(slot.spawn_teardown(rt));
        assert!(kao.is_closed(), "closed synchronously");
        let wait = next.quit().expect("the lock's teardown is still running");
        wait.await;
        assert!(!kao.client().relay().is_connected(), "torn down by then");
        testkit::settle(|| !dapp.sessions().iter().any(|s| s.topic == topic)).await;
        assert!(!dapp.sessions().iter().any(|s| s.topic == topic));
        assert!(next.quit().is_none(), "nothing left to wait for");
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
    enum Tap {
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

    fn is_publish(v: &Value, tag: u64) -> bool {
        v["method"] == "irn_publish" && v["params"]["tag"] == tag
    }

    /// A relay response (no method) to request `id`.
    fn is_ack_of(v: &Value, id: &Mutex<Option<Value>>) -> bool {
        v.get("method").is_none() && lock(id).as_ref().is_some_and(|id| v.get("id") == Some(id))
    }

    /// Kao's connector: its FIRST connection runs every frame past `up` (Kao → relay) and `down`
    /// (relay → Kao); reconnects go straight to the relay.
    fn tapped(
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
        let kao =
            WcRuntime::start_with_connector(connector, next_generation(), RouteKind::Loopback)
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

    /// A lock / quit / Turn off landing while an approve waits for the relay's ack of its settle:
    /// the dapp already holds the session, so the teardown must wait for the approve to bind it
    /// and then disconnect it — never leave the dapp a session Kao forgot.
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
