//! [`WcBook`]: Kao's WalletConnect state — sessions bound to their approval-time identity, the
//! (topic, id)-keyed request queue, the answered set, the outbox, the proposal card and pairing
//! expectations. Plain data driven by explicit `now`; every method returns the [`Effects`] the
//! runtime executes. [`WcBook::answer`] is the exactly-once choke point for dapp answers.
//!
//! Every answer a dapp receives leaves through the outbox: it is recorded as answered, kept until
//! the relay confirms delivery, and re-sent (same bytes) after a reconnect. The crate's own pending
//! check is the backstop against a second delivery.
//!
//! Notices: everything the book reports is recorded in its activity ring (`snapshot().notices`).
//! A `UiEffect::Notice` is raised in addition only when the notice deserves a toast — it is already
//! in the ring, so the dashboard toasts it and must not push it again.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::Value;
use tracing::{debug, error, warn};
use wallet_connect::crypto::Topic;
use wallet_connect::rpc::ErrorObject;
use wallet_connect::sign::{PendingRequest, Proposal, SdkError, Session};

use super::request;
use super::types::*;
use super::{
    ANSWERED_MEMORY, AUTO_OPEN_MAX_AGE_SECS, EXPIRY_MARGIN_SECS, IDLE_RETIRE_SECS,
    KAO_REQUEST_TTL_SECS, MAX_AUTO_ANSWERS_PER_MIN, MAX_NOTICES, MAX_QUEUE_PER_SESSION,
    MAX_QUEUE_TOTAL, MAX_SESSIONS, PAIRING_WAIT_DEFAULT_SECS, PAIRING_WAIT_MAX_SECS,
    REJECT_STREAK_PAUSE,
};

/// `Retire` reason (and notice text) when nothing has needed the relay for [`IDLE_RETIRE_SECS`].
pub(crate) const IDLE_RETIRE_REASON: &str =
    "WalletConnect was idle, so Kao closed the relay connection.";
/// `Retire` reason (and notice text) when the relay keeps dropping fresh connections.
pub(crate) const FLAP_RETIRE_REASON: &str = "The WalletConnect relay keeps closing the connection — \
     check the project ID and relay URL in WalletConnect settings.";
/// Pairing failure once the paste's window passed (or the dapp dropped the pairing) with no proposal.
const NO_PROPOSAL_ARRIVED: &str = "No connection request arrived — get a fresh link from the dapp.";
/// An approve that failed half-way: the dapp may hold a session Kao doesn't, so no retry.
const APPROVE_ABANDONED: &str = "Couldn't finish connecting — reconnect from the dapp.";
/// `begin_approve` refusals. They reach the proposal card verbatim as its error line.
pub(crate) const APPROVE_GONE: &str = "This connection request is no longer available.";
pub(crate) const APPROVE_BUSY: &str = "Kao is already connecting this dapp.";
pub(crate) const APPROVE_TOO_MANY: &str = "Too many dapps are connected — disconnect one first.";
/// Abandoned proposal ids remembered (a re-paste of the link re-emits the proposal).
const MAX_ABANDONED: usize = 64;
/// Bound on proposal rejections owed to dapps ([`WcBook::owe_reject`]).
const MAX_OWED_REJECTS: usize = 64;

/// A relay connection that dies younger than this counts towards the flap detector.
const FLAP_LIFETIME_SECS: u64 = 5;
/// Flap detector window and threshold: this many short-lived connections inside the window.
const FLAP_WINDOW_SECS: u64 = 60;
const FLAP_COUNT: usize = 4;
/// Length of one no-UI answer budget window.
const BUDGET_WINDOW_SECS: u64 = 60;
/// At most one refusal toast per session this often — a refusing flood stays in the ring.
const REFUSAL_TOAST_GAP_SECS: u64 = 10;
/// Re-sends right after a failure while the relay still looks connected; beyond this, an
/// undelivered answer waits for the next `RelayConnected` or the housekeeper's backoff.
const QUICK_RESENDS: u32 = 2;
/// The housekeeper's re-send delay after the quick re-sends (a relay can refuse a publish on a
/// socket that stays up, so no reconnect would ever flush it): doubling per failure, capped.
const RESEND_BACKOFF_SECS: u64 = 5;
const RESEND_BACKOFF_MAX_SECS: u64 = 60;
/// Clamp on a refusal's user-facing detail when it is copied into a notice.
const MAX_NOTICE_DETAIL_CHARS: usize = 160;
/// Clamp on a dapp-supplied method name in a notice.
const MAX_NOTICE_METHOD_CHARS: usize = 48;

/// Bounded memory of answered keys: a replay of one of these is answered −32600.
#[derive(Debug, Default)]
struct AnsweredSet {
    order: VecDeque<WcKey>,
    keys: BTreeSet<WcKey>,
}

impl AnsweredSet {
    fn contains(&self, key: &WcKey) -> bool {
        self.keys.contains(key)
    }

    fn insert(&mut self, key: WcKey) {
        if self.keys.insert(key.clone()) {
            self.order.push_back(key);
        }
        while self.order.len() > ANSWERED_MEMORY {
            if let Some(oldest) = self.order.pop_front() {
                self.keys.remove(&oldest);
            }
        }
    }
}

/// An answer on its way to a dapp.
#[derive(Debug)]
struct Outgoing {
    answer: Result<Value, ErrorObject>,
    /// A Respond for it is running on the runtime right now.
    in_flight: bool,
    /// Failed deliveries since the relay last (re)connected.
    attempts: u32,
    /// Past its quick re-sends: when the housekeeper re-sends it while the relay stays up.
    retry_at: u64,
    /// The pane row for a reviewed request whose answer hasn't reached the relay yet.
    row: Option<PendingRow>,
    /// Sanitized dapp host, for notices about this answer.
    host: String,
}

#[derive(Debug, Clone)]
struct PendingRow {
    view: RequestView,
    received_at: u64,
    dapp_deadline: Option<u64>,
}

/// A Kao-initiated `disconnect(topic)` that hasn't reached the relay yet ("doomed" topic).
#[derive(Debug, Default)]
struct Resend {
    in_flight: bool,
    attempts: u32,
    /// As [`Outgoing::retry_at`].
    retry_at: u64,
}

/// A proposal rejection Kao owes a dapp with no card to retry it from.
#[derive(Debug)]
struct OwedReject {
    error: ErrorObject,
    in_flight: bool,
    /// As [`Outgoing::attempts`].
    attempts: u32,
    /// As [`Outgoing::retry_at`].
    retry_at: u64,
}

#[derive(Debug, Clone, Copy)]
struct Budget {
    window_start: u64,
    spent: u32,
}

/// Safe → the dapp transaction Kao executed there and hasn't seen mined: the Safe nonce it took and
/// the transaction executing it. Until it is mined, the chain and the Transaction Service both
/// still offer that nonce as free, so the Safe's next dapp transaction waits
/// ([`WcBook::next_reviewable`]). One map is shared by the slot, the slots that succeed it on a
/// lock, and the book of every runtime installed in them: a hold outlives the dashboard, the
/// runtime and the lock it was made under. Its watch lifts it ([`Self::release`]) — or the node
/// refusing the executing transaction as invalid on any node does ([`Self::release_voided`]),
/// which ends the watch too.
#[derive(Clone, Default)]
pub struct SafeExecHolds(Arc<Mutex<HeldNonces>>);

#[derive(Default)]
struct HeldNonces {
    by_safe: BTreeMap<crate::wallet::SafeKey, Held>,
    /// Each Safe's last hold that lifted with its execution settled: the span it held (unix s). A
    /// transaction it kept back doesn't age through that span ([`WcBook::next_reviewable`]).
    lifted: BTreeMap<crate::wallet::SafeKey, HeldSpan>,
    /// Each Safe's last execution whose watch gave up on it ([`HoldEnd::GaveUp`]): it may still
    /// take the nonce it was sent for, which a review pinning that nonce says
    /// ([`SafeExecHolds::unmined_at`]).
    gave_up: BTreeMap<crate::wallet::SafeKey, (u64, alloy::primitives::B256)>,
    /// Told when a hold lifts: wakes the dashboard of the runtime installed last, whose pump then
    /// looks again.
    on_lift: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl HeldNonces {
    /// `executor` can no longer take `safe`'s nonce: it is no longer one a watch gave up on.
    fn settled(&mut self, safe: crate::wallet::SafeKey, executor: alloy::primitives::B256) {
        if self.gave_up.get(&safe).is_some_and(|&(_, e)| e == executor) {
            self.gave_up.remove(&safe);
        }
    }
}

/// One Safe's hold.
struct Held {
    nonce: u64,
    /// The transaction executing it.
    executor: alloy::primitives::B256,
    /// When the hold began (unix s) — kept when a later nonce's execution takes it over.
    since: u64,
    /// Dropped with the hold, whichever way it goes: that is what stops its watch ([`HoldGone`]).
    _gone: tokio::sync::oneshot::Sender<()>,
}

/// From when to when (unix s) a Safe's hold kept its next dapp transaction back.
#[derive(Debug, Clone, Copy)]
struct HeldSpan {
    from: u64,
    to: u64,
}

/// How a hold's watch ended ([`SafeExecHolds::release`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldEnd {
    /// Its execution can no longer take the Safe's nonce: mined, or its executor's own nonce went
    /// to another transaction.
    Settled,
    /// The watch stopped waiting for it — the node went long without showing it as pending, or it
    /// outlasted the longest hold — but it may still be mined.
    GaveUp,
}

/// Resolves once the hold it was handed out with is gone — lifted, voided, or taken over by a
/// later nonce's — so its watch has nothing left to settle.
pub type HoldGone = tokio::sync::oneshot::Receiver<()>;

impl fmt::Debug for SafeExecHolds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.try_lock() {
            Ok(h) => write!(f, "SafeExecHolds({} held)", h.by_safe.len()),
            Err(_) => f.write_str("SafeExecHolds"),
        }
    }
}

impl SafeExecHolds {
    fn lock(&self) -> std::sync::MutexGuard<'_, HeldNonces> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hold `safe` at `nonce`, which `executor` executes, from `now`. `None` when that nonce (or a
    /// later one) is already held — its watch is already running; else what tells the new watch
    /// its hold is gone.
    pub fn hold(
        &self,
        safe: crate::wallet::SafeKey,
        nonce: u64,
        executor: alloy::primitives::B256,
        now: u64,
    ) -> Option<HoldGone> {
        let mut h = self.lock();
        let since = match h.by_safe.get(&safe) {
            Some(held) if held.nonce >= nonce => return None,
            Some(held) => held.since,
            None => now,
        };
        let (gone, watch) = tokio::sync::oneshot::channel();
        h.by_safe.insert(
            safe,
            Held {
                nonce,
                executor,
                since,
                _gone: gone,
            },
        );
        Some(watch)
    }

    /// `executor`'s execution at `nonce` on `safe` ended as `end` says. A hold since moved to a
    /// later nonce stays. Returns whether a hold was lifted — and then tells [`Self::on_lift`]'s
    /// listener.
    pub fn release(
        &self,
        safe: crate::wallet::SafeKey,
        nonce: u64,
        executor: alloy::primitives::B256,
        end: HoldEnd,
        now: u64,
    ) -> bool {
        self.lift(safe, end, now, |held| {
            held.nonce == nonce && held.executor == executor
        })
    }

    /// The node refused `executor` as invalid on any node: it can never take `safe`'s nonce, so a
    /// hold it still makes lifts, and its watch stops. Any other hold stays.
    pub fn release_voided(
        &self,
        safe: crate::wallet::SafeKey,
        executor: alloy::primitives::B256,
        now: u64,
    ) -> bool {
        self.lock().settled(safe, executor);
        self.lift(safe, HoldEnd::Settled, now, |held| {
            held.executor == executor
        })
    }

    /// Lift `safe`'s hold if `matches` it, at `now`; tell the listener. Only a settled execution
    /// stops the time held counting toward a waiting request's age; one given up on is noted as
    /// possibly still on its way.
    fn lift(
        &self,
        safe: crate::wallet::SafeKey,
        end: HoldEnd,
        now: u64,
        matches: impl FnOnce(&Held) -> bool,
    ) -> bool {
        let (listener, _held) = {
            let mut h = self.lock();
            if !h.by_safe.get(&safe).is_some_and(matches) {
                return false;
            }
            let Some(held) = h.by_safe.remove(&safe) else {
                return false;
            };
            match end {
                HoldEnd::Settled => {
                    h.lifted.insert(
                        safe,
                        HeldSpan {
                            from: held.since,
                            to: now,
                        },
                    );
                    h.settled(safe, held.executor);
                }
                HoldEnd::GaveUp => {
                    h.gave_up.insert(safe, (held.nonce, held.executor));
                }
            }
            (h.on_lift.clone(), held)
        };
        if let Some(wake) = listener {
            wake();
        }
        true
    }

    /// The unmined execution's nonce held for `identity`'s Safe, if any (never for an EOA).
    pub fn held(&self, identity: &WcIdentity) -> Option<u64> {
        let safe = safe_key(identity)?;
        self.lock().by_safe.get(&safe).map(|held| held.nonce)
    }

    /// The transaction Kao sent that may still take `nonce` on `identity`'s Safe: the execution
    /// held there, or the last one a watch gave up on there. Once the Safe's nonce is past `nonce`
    /// no review pins it again, so a record that outlived its nonce misleads no one.
    pub fn unmined_at(&self, identity: &WcIdentity, nonce: u64) -> Option<alloy::primitives::B256> {
        let safe = safe_key(identity)?;
        let h = self.lock();
        match h.by_safe.get(&safe) {
            Some(held) if held.nonce == nonce => Some(held.executor),
            _ => h
                .gave_up
                .get(&safe)
                .filter(|&&(at, _)| at == nonce)
                .map(|&(_, executor)| executor),
        }
    }

    /// The span `identity`'s Safe last held its transactions back, if a hold there ever settled.
    fn held_span(&self, identity: &WcIdentity) -> Option<HeldSpan> {
        let safe = safe_key(identity)?;
        self.lock().lifted.get(&safe).copied()
    }

    /// Who [`Self::release`] tells from now on (replacing whoever it told before).
    pub fn on_lift(&self, listener: impl Fn() + Send + Sync + 'static) {
        self.lock().on_lift = Some(Arc::new(listener));
    }
}

/// See the module docs.
#[derive(Debug)]
pub struct WcBook {
    sessions: BTreeMap<Topic, BoundSession>,
    /// FIFO; keyed by (topic, id) — JSON-RPC ids are only unique per peer.
    queue: VecDeque<QueuedRequest>,
    answered: AnsweredSet,
    outbox: BTreeMap<WcKey, Outgoing>,
    card: Option<ProposalCard>,
    /// Pasted pairing topic → until (unix s). Consumed by the first proposal on it, so
    /// each paste yields at most one card.
    expectations: BTreeMap<Topic, u64>,
    pairing: PairingState,
    relay: RelayStatus,
    connected_at: Option<u64>,
    /// When short-lived relay connections died (flap detector).
    flaps: VecDeque<u64>,
    notices: VecDeque<NoticeView>,
    next_ordinal: u32,
    refused_count: u32,
    budgets: BTreeMap<Topic, Budget>,
    refusal_toasts: BTreeMap<Topic, u64>,
    /// Proposals auto-rejected and not yet confirmed — a re-emit isn't rejected twice.
    auto_rejected: BTreeSet<u64>,
    /// Proposals whose approve failed half-way ([`Self::approve_abandoned`]): never a card again.
    abandoned: BTreeSet<u64>,
    /// Rejections of proposals no card shows ([`Self::owe_reject`]), until delivered or expired.
    owed_rejects: BTreeMap<u64, OwedReject>,
    /// Session topic → its pairing topic, until the settle ack resolves (then DeletePairing).
    ack_pairings: BTreeMap<Topic, Topic>,
    disconnects: BTreeMap<Topic, Resend>,
    idle_since: Option<u64>,
    retire_requested: bool,
    /// Last `now` the book was told — for notices raised by methods without a clock.
    clock: u64,
    /// The holds on Safes whose dapp transaction Kao executed and hasn't seen mined — this book's
    /// own until the slot shares its map ([`Self::share_safe_execs`]).
    safe_execs: SafeExecHolds,
    /// The request a [Switch to ⟨account⟩] was clicked on, for the dashboard rebuilt for that
    /// account to open ([`Self::take_pick`]).
    pick: Option<WcKey>,
}

impl Default for WcBook {
    fn default() -> Self {
        Self::new()
    }
}

impl WcBook {
    pub fn new() -> Self {
        Self {
            sessions: BTreeMap::new(),
            queue: VecDeque::new(),
            answered: AnsweredSet::default(),
            outbox: BTreeMap::new(),
            card: None,
            expectations: BTreeMap::new(),
            pairing: PairingState::Idle,
            relay: RelayStatus::Connecting,
            connected_at: None,
            flaps: VecDeque::new(),
            notices: VecDeque::new(),
            next_ordinal: 1,
            refused_count: 0,
            budgets: BTreeMap::new(),
            refusal_toasts: BTreeMap::new(),
            auto_rejected: BTreeSet::new(),
            abandoned: BTreeSet::new(),
            owed_rejects: BTreeMap::new(),
            ack_pairings: BTreeMap::new(),
            disconnects: BTreeMap::new(),
            idle_since: None,
            retire_requested: false,
            clock: 0,
            safe_execs: SafeExecHolds::default(),
            pick: None,
        }
    }

    // ── relay ──

    /// Reconnect ⇒ Respond for every undelivered outbox entry + Disconnect for doomed topics +
    /// RejectProposal for every owed rejection; ≥ 4 connections dying < 5 s within 60 s with no
    /// session/card ⇒ Retire{reason}.
    pub fn on_relay(&mut self, connected: bool, now: u64) -> Effects {
        self.tick_clock(now);
        let mut fx = Effects {
            changed: true,
            ..Default::default()
        };
        if connected {
            self.relay = RelayStatus::Connected;
            self.connected_at = Some(now);
            // A fresh connection gets fresh quick re-sends.
            self.outbox.values_mut().for_each(|o| o.attempts = 0);
            self.disconnects.values_mut().for_each(|d| d.attempts = 0);
            self.owed_rejects.values_mut().for_each(|r| r.attempts = 0);
            fx.net.extend(self.undelivered());
            return fx;
        }
        if let Some(up) = self.connected_at.take()
            && now.saturating_sub(up) < FLAP_LIFETIME_SECS
        {
            self.flaps.push_back(now);
        }
        self.flaps
            .retain(|t| now.saturating_sub(*t) < FLAP_WINDOW_SECS);
        if !matches!(self.relay, RelayStatus::Reconnecting { .. }) {
            self.relay = RelayStatus::Reconnecting { since: now };
        }
        // Sessions must not be thrown away over a flaky relay; with nothing at stake the
        // relay most likely rejects Kao (bad project id) and keeping the socket is pointless.
        if self.flaps.len() >= FLAP_COUNT
            && self.sessions.is_empty()
            && self.card.is_none()
            && !self.retire_requested
        {
            warn!(
                flaps = self.flaps.len(),
                "WalletConnect relay keeps closing; retiring"
            );
            self.retire_requested = true;
            fx.net.push(NetEffect::Retire {
                reason: FLAP_RETIRE_REASON.to_string(),
            });
        }
        fx
    }

    /// The UI reads the relay state from `snapshot`; this is for tests.
    #[cfg(test)]
    pub fn relay(&self) -> RelayStatus {
        self.relay
    }

    // ── pairing ──

    /// until = min(uri_expiry.unwrap_or(now + PAIRING_WAIT_DEFAULT_SECS), now + PAIRING_WAIT_MAX_SECS).
    pub fn expect_pairing(&mut self, topic: Topic, now: u64, uri_expiry: Option<u64>) {
        self.tick_clock(now);
        let cap = now.saturating_add(PAIRING_WAIT_MAX_SECS);
        let until = uri_expiry
            .unwrap_or_else(|| now.saturating_add(PAIRING_WAIT_DEFAULT_SECS))
            .min(cap);
        self.expectations.insert(topic.clone(), until);
        self.pairing = PairingState::Pairing { topic, since: now };
    }

    /// The crate subscribed the pairing topic: wait for the dapp's proposal. A proposal that already
    /// arrived (the relay delivers stored ones on subscribe) took the paste over; nothing to do then.
    pub fn pairing_started(&mut self, topic: &Topic, now: u64) {
        self.tick_clock(now);
        let pairing_this =
            matches!(&self.pairing, PairingState::Pairing { topic: t, .. } if t == topic);
        if let (true, Some(until)) = (pairing_this, self.expectations.get(topic).copied()) {
            self.pairing = PairingState::Waiting {
                topic: topic.clone(),
                since: now,
                until,
            };
        }
    }

    /// `message` is fixed copy (`request::pairing_uri_error`) — never the crate's error text.
    pub fn pairing_failed(&mut self, topic: &Topic, message: String) {
        self.expectations.remove(topic);
        if self.pairing_is(topic) {
            self.pairing = PairingState::Failed(message);
        }
    }

    /// PairingExpire / PairingDelete from the crate.
    pub fn on_pairing_gone(&mut self, topic: &Topic) -> Effects {
        let mut fx = Effects::default();
        if self.expectations.remove(topic).is_some() {
            fx.changed = true;
        }
        if self.pairing_is(topic) {
            self.pairing = PairingState::Failed(NO_PROPOSAL_ARRIVED.to_string());
            fx.changed = true;
        }
        let abandoned = self
            .card
            .as_ref()
            .is_some_and(|c| &c.proposal.pairing_topic == topic && !c.busy);
        if abandoned && let Some(card) = self.card.take() {
            let text = format!("{} cancelled the connection request.", card.dapp.headline());
            self.raise(&mut fx, text, false, false);
        }
        fx
    }

    /// The UI reads the pairing state from `snapshot`; this is for tests.
    #[cfg(test)]
    pub fn pairing(&self) -> &PairingState {
        &self.pairing
    }

    /// A card is open — the pane disables Connect (one card per paste). A paste still waiting
    /// for its proposal doesn't block: a fresh link supersedes it ([`Self::supersede_pairing`]).
    pub fn connect_blocked(&self) -> bool {
        self.card.is_some()
    }

    /// A new paste of `fresh` replaces every paste still waiting for its proposal: the user gave
    /// up on it (the dapp's dialog closed, or it showed a new link). Each abandoned pairing is
    /// deleted, so nothing proposes over it later. Re-pasting the same link keeps its pairing.
    pub fn supersede_pairing(&mut self, fresh: &Topic) -> Effects {
        let mut fx = Effects::default();
        let abandoned: Vec<Topic> = self
            .expectations
            .keys()
            .filter(|t| *t != fresh)
            .cloned()
            .collect();
        for topic in abandoned {
            self.expectations.remove(&topic);
            if self.pairing_is(&topic) {
                self.pairing = PairingState::Idle;
            }
            debug!("a new paste superseded one still waiting");
            fx.net.push(NetEffect::DeletePairing { topic });
            fx.changed = true;
        }
        fx
    }

    // ── proposals ──

    /// Shown iff its pairing topic has an open expectation (consumed) and no card is open; else
    /// RejectProposal(5000). Dedupe by id.
    pub fn on_proposal(&mut self, p: Proposal, now: u64) -> Effects {
        self.tick_clock(now);
        let mut fx = Effects::default();
        // The crate re-emits an unanswered proposal when the same link is pasted again.
        if self.card.as_ref().is_some_and(|c| c.proposal.id == p.id) {
            return fx;
        }
        let expected = self
            .expectations
            .get(&p.pairing_topic)
            .is_some_and(|until| now < *until);
        if expected && self.card.is_none() {
            self.expectations.remove(&p.pairing_topic);
            // Refused before it becomes a card: one Kao gave up on half-way (the crate re-emits
            // it when the link is pasted again), or one too large to even plan on the UI thread.
            let refused = if self.abandoned.contains(&p.id) {
                Some((
                    SdkError::UserRejected.error(),
                    APPROVE_ABANDONED.to_string(),
                ))
            } else {
                super::namespaces::proposal_too_large(&p).map(|block| {
                    (
                        super::namespaces::proposal_reject_error(&block),
                        format!("{} {}", block.message, block.reason),
                    )
                })
            };
            if let Some((error, why)) = refused {
                debug!(id = p.id, code = error.code, "pasted proposal refused");
                if self.pairing_is(&p.pairing_topic) {
                    self.pairing = PairingState::Failed(why.clone());
                }
                self.raise(&mut fx, why, true, false);
                self.owe_reject(p.id, error, &mut fx);
                return fx;
            }
            if self.pairing_is(&p.pairing_topic) {
                self.pairing = PairingState::Idle;
            }
            let dapp = DappLabel::from_metadata(&p.proposer.metadata);
            self.card = Some(ProposalCard {
                proposal: p,
                dapp,
                busy: false,
                error: None,
            });
            fx.ui.push(UiEffect::Attention);
            fx.changed = true;
            return fx;
        }
        // Unsolicited: no paste is waiting on this pairing any more — e.g. a dapp proposing
        // again over a pairing that already produced its one card — or a card is already open.
        if !self.auto_rejected.insert(p.id) {
            return fx;
        }
        self.refused_count = self.refused_count.saturating_add(1);
        let host = DappLabel::from_metadata(&p.proposer.metadata)
            .headline()
            .to_string();
        debug!(id = p.id, "unsolicited proposal; rejecting");
        let text = format!(
            "Rejected a connection request from {host} that didn't come from a link you pasted."
        );
        self.raise(&mut fx, text, false, false);
        self.owe_reject(p.id, SdkError::UserRejected.error(), &mut fx);
        fx
    }

    pub fn proposal(&self) -> Option<&ProposalCard> {
        self.card.as_ref()
    }

    /// Err: [`APPROVE_BUSY`] | [`APPROVE_GONE`] | [`APPROVE_TOO_MANY`] — sentences, since the
    /// card shows them as they are.
    pub fn begin_approve(&mut self, id: u64) -> Result<Proposal, &'static str> {
        let Some(card) = self.card.as_mut().filter(|c| c.proposal.id == id) else {
            return Err(APPROVE_GONE);
        };
        if card.busy {
            return Err(APPROVE_BUSY);
        }
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(APPROVE_TOO_MANY);
        }
        card.busy = true;
        card.error = None;
        Ok(card.proposal.clone())
    }

    /// Refused before anything reached the dapp: the card stays, with the reason.
    pub fn approve_failed(&mut self, id: u64, error: String) -> Effects {
        let mut fx = Effects::default();
        if let Some(card) = self.card.as_mut().filter(|c| c.proposal.id == id) {
            card.busy = false;
            card.error = Some(error);
            fx.changed = true;
        }
        fx
    }

    /// The approve failed after its answer may have reached the dapp, but before the settle could
    /// have: the crate has spent the proposal and dropped the session, so the dapp holds none and
    /// there is nothing to retry. The card goes, the user is told to reconnect from the dapp, and
    /// the proposal is rejected in case the crate still has it. A re-emit of the same id is
    /// refused too.
    pub fn approve_abandoned(&mut self, id: u64) -> Effects {
        let mut fx = Effects::default();
        let Some(card) = self.card.take_if(|c| c.proposal.id == id) else {
            return fx;
        };
        self.abandoned.insert(id);
        while self.abandoned.len() > MAX_ABANDONED {
            self.abandoned.pop_first();
        }
        if !matches!(
            self.pairing,
            PairingState::Pairing { .. } | PairingState::Waiting { .. }
        ) {
            self.pairing = PairingState::Failed(APPROVE_ABANDONED.to_string());
        }
        let text = format!(
            "Couldn't finish connecting {} — reconnect from the dapp.",
            card.dapp.headline()
        );
        self.raise(&mut fx, text, true, true);
        self.owe_reject(id, SdkError::UserRejected.error(), &mut fx);
        fx
    }

    /// Reject proposal `id`, which no card shows (so no Reject button can retry it): owed until
    /// the relay takes it or the proposal expires. One that fails goes again — at once, then on the
    /// housekeeper's backoff while the relay stays up, and with the next connection
    /// ([`Self::undelivered`]) — so the dapp's connect dialog doesn't hang till expiry.
    fn owe_reject(&mut self, id: u64, error: ErrorObject, fx: &mut Effects) {
        self.owed_rejects.insert(
            id,
            OwedReject {
                error: error.clone(),
                in_flight: true,
                attempts: 0,
                retry_at: 0,
            },
        );
        while self.owed_rejects.len() > MAX_OWED_REJECTS {
            self.owed_rejects.pop_first();
        }
        fx.net.push(NetEffect::RejectProposal { id, error });
    }

    pub fn bind_session(&mut self, session: &Session, ticket: &ApproveTicket, now: u64) -> Effects {
        self.tick_clock(now);
        let mut fx = Effects::default();
        let ordinal = self.next_ordinal;
        self.next_ordinal = self.next_ordinal.saturating_add(1);
        self.sessions.insert(
            session.topic.clone(),
            BoundSession {
                topic: session.topic.clone(),
                pairing_topic: session.pairing_topic.clone(),
                ordinal,
                identity: ticket.identity,
                identity_label: ticket.identity_label.clone(),
                chains: ticket.grant.chains.clone(),
                methods: ticket.grant.methods.clone(),
                events: ticket.grant.events.clone(),
                dapp: ticket.dapp.clone(),
                expiry: session.expiry,
                ack: AckState::Pending,
                paused: false,
                reject_streak: 0,
            },
        );
        self.ack_pairings
            .insert(session.topic.clone(), session.pairing_topic.clone());
        if self
            .card
            .as_ref()
            .is_some_and(|c| c.proposal.id == ticket.proposal_id)
        {
            self.card = None;
        }
        self.expectations.remove(&session.pairing_topic);
        let text = format!(
            "Connected {} as {}.",
            ticket.dapp.headline(),
            ticket.identity_label
        );
        self.raise(&mut fx, text, false, false);
        fx
    }

    /// Confirmed ⇒ DeletePairing; Refused ⇒ session gone + notice + DeletePairing; Timeout ⇒ Unconfirmed + DeletePairing.
    pub fn on_ack(&mut self, topic: &Topic, result: Result<(), AckFailure>) -> Effects {
        let mut fx = Effects {
            changed: true,
            ..Default::default()
        };
        let pairing = self
            .ack_pairings
            .remove(topic)
            .or_else(|| self.sessions.get(topic).map(|s| s.pairing_topic.clone()));
        match result {
            Ok(()) => {
                if let Some(s) = self.sessions.get_mut(topic) {
                    s.ack = AckState::Confirmed;
                }
            }
            Err(AckFailure::Refused) => {
                // The crate already deleted the session, silently (it emits no event for that).
                if let Some(s) = self.drop_session(topic, GoneReason::DappDisconnected, &mut fx) {
                    let text = format!("{} declined the connection.", s.dapp.headline());
                    self.raise(&mut fx, text, true, true);
                }
            }
            Err(AckFailure::Timeout) => {
                if let Some(s) = self.sessions.get_mut(topic) {
                    s.ack = AckState::Unconfirmed;
                }
            }
            Err(AckFailure::Closed) => {
                // The runtime is shutting down: the pairing dies with it.
                if let Some(s) = self.sessions.get_mut(topic) {
                    s.ack = AckState::Unconfirmed;
                }
                return fx;
            }
        }
        // The pasted pairing has done its job — drop it so nothing can propose over it again.
        if let Some(pairing_topic) = pairing {
            fx.net.push(NetEffect::DeletePairing {
                topic: pairing_topic,
            });
        }
        fx
    }

    pub fn begin_reject(&mut self, id: u64) -> bool {
        match self.card.as_mut().filter(|c| c.proposal.id == id) {
            Some(card) if !card.busy => {
                card.busy = true;
                card.error = None;
                true
            }
            _ => false,
        }
    }

    pub fn proposal_rejected(&mut self, id: u64, result: Result<(), String>) -> Effects {
        let mut fx = Effects::default();
        self.auto_rejected.remove(&id);
        let connected = self.relay == RelayStatus::Connected;
        match &result {
            Ok(()) => {
                self.owed_rejects.remove(&id);
            }
            Err(_) => {
                if let Some(owed) = self.owed_rejects.get_mut(&id) {
                    owed.in_flight = false;
                    owed.attempts = owed.attempts.saturating_add(1);
                    // A relay can refuse it on a socket that stays up: no reconnect would flush it.
                    if connected && owed.attempts <= QUICK_RESENDS {
                        owed.in_flight = true;
                        fx.net.push(NetEffect::RejectProposal {
                            id,
                            error: owed.error.clone(),
                        });
                    } else {
                        owed.retry_at = self.clock.saturating_add(resend_after(owed.attempts));
                    }
                }
            }
        }
        if let Some(card) = self.card.as_mut().filter(|c| c.proposal.id == id) {
            match result {
                Ok(()) => self.card = None,
                Err(e) => {
                    card.busy = false;
                    card.error = Some(e);
                }
            }
            fx.changed = true;
        } else if let Err(e) = result {
            debug!(id, error = %e, "auto-reject of a proposal failed");
        }
        fx
    }

    pub fn on_proposal_expired(&mut self, id: u64) -> Effects {
        let mut fx = Effects::default();
        self.auto_rejected.remove(&id);
        self.owed_rejects.remove(&id);
        if self.card.as_ref().is_some_and(|c| c.proposal.id == id)
            && let Some(card) = self.card.take()
        {
            let text = format!(
                "The connection request from {} expired.",
                card.dapp.headline()
            );
            self.raise(&mut fx, text, false, false);
        }
        fx
    }

    // ── requests ──

    /// Admission of a validated request: replay → −32600, dup → ignore, unknown session → drop
    /// silently, refusal, immediate + budget + chainChanged emit, caps, deadline, Waiting +
    /// Attention.
    pub fn on_request(
        &mut self,
        req: &PendingRequest,
        received_at: u64,
        admitted: Result<Admitted, Refusal>,
        now: u64,
    ) -> Effects {
        self.tick_clock(now);
        let mut fx = Effects::default();
        let key = WcKey {
            topic: req.topic.clone(),
            id: req.id,
        };
        if self.answered.contains(&key) {
            // Still on its way: the crate holds the request until delivery, so this is a stray.
            if self.outbox.contains_key(&key) {
                return fx;
            }
            debug!(id = key.id, "replayed request id; answering duplicate");
            let refusal = if self.spend_budget(&key.topic, now) {
                Refusal::duplicate()
            } else {
                Refusal::limit()
            };
            self.refused_count = self.refused_count.saturating_add(1);
            let host = self.host_of(&key.topic);
            self.send_answer(key, Err(refusal.error_object()), None, host, &mut fx);
            return fx;
        }
        if self.queue.iter().any(|q| q.key == key) {
            return fx;
        }
        let Some(session) = self.sessions.get(&key.topic) else {
            debug!(id = key.id, "request on a session Kao didn't bind; dropped");
            return fx;
        };
        let host = session.dapp.headline().to_string();
        let identity = session.identity;
        let admitted = match admitted {
            Ok(a) => a,
            Err(refusal) => {
                self.refuse_without_ui(key, refusal, host, &req.request.method, now, &mut fx);
                return fx;
            }
        };

        if !admitted.call.needs_review() {
            // Accounts / chain id / switch chain: answered right away, within the budget.
            if !self.spend_budget(&key.topic, now) {
                self.refused_count = self.refused_count.saturating_add(1);
                self.send_answer(
                    key,
                    Err(Refusal::limit().error_object()),
                    None,
                    host,
                    &mut fx,
                );
                return fx;
            }
            let Some(session) = self.sessions.get(&key.topic) else {
                return fx;
            };
            let answer = request::immediate_answer(&admitted.call, session, admitted.chain_id);
            // After an approved switch, chainChanged (data = the number) — only if granted. It
            // helps clients that don't handle the switch themselves; accountsChanged never goes
            // out, since a session's identity is fixed.
            let chain_changed = match (&admitted.call, &answer) {
                (WcCall::SwitchChain { chain_id }, Some(Ok(_)))
                    if session.chains.contains(chain_id)
                        && session.events.iter().any(|e| e == "chainChanged") =>
                {
                    Some(*chain_id)
                }
                _ => None,
            };
            let answer = match answer {
                Some(Ok(value)) => Ok(value),
                Some(Err(refusal)) => {
                    self.refused_count = self.refused_count.saturating_add(1);
                    Err(refusal.error_object())
                }
                None => {
                    error!(id = key.id, "no immediate answer for a no-review call");
                    Err(Refusal::failed("Kao had no answer for this call").error_object())
                }
            };
            let topic = key.topic.clone();
            self.send_answer(key, answer, None, host, &mut fx);
            if let Some(chain_id) = chain_changed {
                fx.net.push(NetEffect::Emit {
                    topic,
                    chain_id,
                    name: "chainChanged",
                    data: Value::from(chain_id),
                });
            }
            return fx;
        }

        // Flood caps.
        let per_session = self
            .queue
            .iter()
            .filter(|q| q.key.topic == key.topic)
            .count();
        if per_session >= MAX_QUEUE_PER_SESSION || self.queue.len() >= MAX_QUEUE_TOTAL {
            debug!(
                id = key.id,
                per_session,
                total = self.queue.len(),
                "queue full; refusing"
            );
            let method = &req.request.method;
            self.refuse_without_ui(key, Refusal::limit(), host, method, now, &mut fx);
            return fx;
        }

        // Kao's own deadline caps how long a request waits for review (it is answered −32603
        // then). The dapp's own expiry is kept as the dapp sent it: past it nothing reaches the
        // dapp any more, and only it — never Kao's TTL — ends a signature in progress.
        let kao_deadline = received_at.saturating_add(KAO_REQUEST_TTL_SECS);
        let dapp_deadline = req.request.expiry_timestamp;
        self.queue.push_back(QueuedRequest {
            key,
            chain_id: admitted.chain_id,
            call: admitted.call,
            summary: admitted.summary,
            identity,
            received_at,
            dapp_deadline,
            kao_deadline,
            state: QueueState::Waiting,
            notified: false,
            failure: None,
            gone: None,
            unconfirmed: None,
            past_hold: false,
        });
        fx.ui.push(UiEffect::Attention);
        fx.changed = true;
        fx
    }

    /// THE exactly-once choke point. Updates reject_streak / paused on USER_REJECTED.
    pub fn answer(&mut self, key: &WcKey, answer: Answer) -> Effects {
        self.answer_inner(key, answer, true)
    }

    pub fn on_responded(&mut self, key: &WcKey, result: RespondResult) -> Effects {
        let mut fx = Effects::default();
        let connected = self.relay == RelayStatus::Connected;
        let clock = self.clock;
        let Some(out) = self.outbox.get_mut(key) else {
            return fx;
        };
        fx.changed = true;
        match result {
            RespondResult::Delivered => {
                self.outbox.remove(key);
            }
            RespondResult::Retry(why) => {
                out.in_flight = false;
                out.attempts = out.attempts.saturating_add(1);
                debug!(id = key.id, attempts = out.attempts, why = %why, "answer not delivered; kept");
                if connected && out.attempts <= QUICK_RESENDS {
                    out.in_flight = true;
                    fx.net.push(NetEffect::Respond {
                        key: key.clone(),
                        answer: out.answer.clone(),
                    });
                } else {
                    out.retry_at = clock.saturating_add(resend_after(out.attempts));
                }
            }
            RespondResult::Gone(why) => {
                debug!(id = key.id, why = %why, "answer undeliverable; dropped");
                if let Some(out) = self.outbox.remove(key)
                    && out.answer.is_ok()
                {
                    let text = format!(
                        "{} stopped waiting before Kao's answer reached it.",
                        out.host
                    );
                    self.raise(&mut fx, text, true, true);
                }
            }
        }
        fx
    }

    pub fn on_disconnected(&mut self, topic: &Topic, result: RespondResult) -> Effects {
        let mut fx = Effects::default();
        let connected = self.relay == RelayStatus::Connected;
        let clock = self.clock;
        let Some(d) = self.disconnects.get_mut(topic) else {
            return fx;
        };
        fx.changed = true;
        match result {
            // Gone = the crate no longer knows the session: nothing left to tell the dapp.
            RespondResult::Delivered | RespondResult::Gone(_) => {
                self.disconnects.remove(topic);
            }
            RespondResult::Retry(why) => {
                d.in_flight = false;
                d.attempts = d.attempts.saturating_add(1);
                debug!(attempts = d.attempts, why = %why, "disconnect not delivered; kept");
                if connected && d.attempts <= QUICK_RESENDS {
                    d.in_flight = true;
                    fx.net.push(NetEffect::Disconnect {
                        topic: topic.clone(),
                    });
                } else {
                    d.retry_at = clock.saturating_add(resend_after(d.attempts));
                }
            }
        }
        fx
    }

    /// Outbox entries, doomed topics and owed proposal rejections not in flight (marks them in
    /// flight) — for flush.
    pub fn undelivered(&mut self) -> Vec<NetEffect> {
        let mut out = Vec::new();
        for (key, o) in self.outbox.iter_mut().filter(|(_, o)| !o.in_flight) {
            o.in_flight = true;
            out.push(NetEffect::Respond {
                key: key.clone(),
                answer: o.answer.clone(),
            });
        }
        for (topic, d) in self.disconnects.iter_mut().filter(|(_, d)| !d.in_flight) {
            d.in_flight = true;
            out.push(NetEffect::Disconnect {
                topic: topic.clone(),
            });
        }
        for (id, owed) in self.owed_rejects.iter_mut().filter(|(_, o)| !o.in_flight) {
            owed.in_flight = true;
            out.push(NetEffect::RejectProposal {
                id: *id,
                error: owed.error.clone(),
            });
        }
        out
    }

    /// SessionRequestExpire from the crate: the dapp's deadline passed and the crate forgot it.
    pub fn on_request_expired(&mut self, key: &WcKey) -> Effects {
        let mut fx = Effects::default();
        // An answer still waiting for the relay can't be delivered any more.
        if self.outbox.get(key).is_some_and(|o| !o.in_flight)
            && let Some(out) = self.outbox.remove(key)
        {
            fx.changed = true;
            if out.answer.is_ok() {
                let text = format!(
                    "{} stopped waiting before Kao's answer reached it.",
                    out.host
                );
                self.raise(&mut fx, text, true, true);
            }
        }
        let Some(pos) = self.queue.iter().position(|q| &q.key == key) else {
            return fx;
        };
        fx.changed = true;
        let state = self.queue.get(pos).map(|q| q.state);
        match state {
            Some(QueueState::Signing { .. }) => {
                if let Some(q) = self.queue.get_mut(pos) {
                    q.gone.get_or_insert(GoneReason::Expired);
                }
            }
            Some(QueueState::InReview { .. }) => {
                self.queue.remove(pos);
                fx.ui.push(UiEffect::RequestGone {
                    key: key.clone(),
                    reason: GoneReason::Expired,
                });
            }
            Some(QueueState::Waiting) | None => {
                self.queue.remove(pos);
                let text = format!(
                    "A request from {} expired before you reviewed it.",
                    self.host_of(&key.topic)
                );
                self.raise(&mut fx, text, false, false);
            }
        }
        fx
    }

    pub fn request(&self, key: &WcKey) -> Option<&QueuedRequest> {
        self.queue.iter().find(|q| &q.key == key)
    }

    pub fn state_of(&self, key: &WcKey) -> Option<QueueState> {
        self.request(key).map(|q| q.state)
    }

    /// The user picked `key` on a dashboard about to be replaced; the next one takes it.
    pub fn set_pick(&mut self, key: WcKey) {
        self.pick = Some(key);
    }

    /// The pick, once — and only while its request still waits.
    pub fn take_pick(&mut self) -> Option<WcKey> {
        self.pick
            .take()
            .filter(|k| self.state_of(k) == Some(QueueState::Waiting))
    }

    /// FIFO over Waiting with identity == active, deadline not passed, and — unless key == manual,
    /// which bypasses both — !paused and age < AUTO_OPEN_MAX_AGE_SECS (a Safe SendTransaction not
    /// aged by the time a settled hold kept it back: [`Self::waited`]); skipping Safe SendTransaction
    /// when `defer_safe_tx` or while its Safe is held ([`Self::held_behind_execution`]) — unless an
    /// execution already left for it: its review only sends those bytes again and pins nothing.
    /// None while any entry is Signing.
    pub fn next_reviewable(
        &self,
        active: Option<&WcIdentity>,
        now: u64,
        manual: Option<&WcKey>,
        defer_safe_tx: bool,
    ) -> Option<WcKey> {
        let active = active?;
        if self.has_signing() {
            return None;
        }
        self.queue
            .iter()
            .find(|q| {
                let Some(session) = self.sessions.get(&q.key.topic) else {
                    return false;
                };
                // [Review] opens a request regardless of its age or a paused session.
                let forced = manual == Some(&q.key);
                q.state == QueueState::Waiting
                    && q.gone.is_none()
                    && q.identity == *active
                    && (forced || !session.paused)
                    && now < q.kao_deadline
                    && q.dapp_deadline
                        .is_none_or(|d| now.saturating_add(EXPIRY_MARGIN_SECS) < d)
                    && (forced || self.waited(q, now) < AUTO_OPEN_MAX_AGE_SECS)
                    && !(defer_safe_tx && pins_a_safe_nonce(q))
                    && !self.waits_on_an_execution(q)
            })
            .map(|q| q.key.clone())
    }

    /// How long `q` has waited to open by itself. The time a hold on its Safe kept a Safe
    /// transaction back doesn't count, once that hold's execution settled — it was promised to
    /// open then, however long the hold lasted. Only the time it was actually held: a request
    /// already too old when the hold began stays too old.
    fn waited(&self, q: &QueuedRequest, now: u64) -> u64 {
        let held = match self.safe_execs.held_span(&q.identity) {
            Some(span) if pins_a_safe_nonce(q) => {
                span.to.saturating_sub(q.received_at.max(span.from))
            }
            _ => 0,
        };
        now.saturating_sub(q.received_at.saturating_add(held))
    }

    /// `key` is a Safe transaction waiting for Kao's unmined execution of an earlier one on its
    /// Safe: it doesn't open until that is mined or given up on, or the user reviews it anyway
    /// ([`Self::review_past_hold`]).
    pub fn held_behind_execution(&self, key: &WcKey) -> bool {
        self.request(key)
            .is_some_and(|q| self.waits_on_an_execution(q))
    }

    fn waits_on_an_execution(&self, q: &QueuedRequest) -> bool {
        pins_a_safe_nonce(q) && !q.past_hold && self.safe_exec_held(&q.identity).is_some()
    }

    /// [Review anyway] on `key`, a waiting request its Safe's hold keeps back: it alone stops
    /// waiting for the execution. Its review pins the nonce that execution may still take, and
    /// says so. `false` when `key` isn't waiting.
    pub fn review_past_hold(&mut self, key: &WcKey) -> bool {
        let Some(q) = self
            .queue
            .iter_mut()
            .find(|q| &q.key == key && q.state == QueueState::Waiting)
        else {
            return false;
        };
        q.past_hold = true;
        true
    }

    /// Kao executed a dapp transaction on `safe` at its `nonce`, with `executor`, at `now`: hold
    /// the Safe's next dapp transaction until the hold's watch lifts it
    /// ([`SafeExecHolds::release`]). `None` when that nonce (or a later one) is already held — its
    /// watch is already running.
    pub fn hold_safe_exec(
        &mut self,
        safe: crate::wallet::SafeKey,
        nonce: u64,
        executor: alloy::primitives::B256,
        now: u64,
    ) -> Option<HoldGone> {
        self.safe_execs.hold(safe, nonce, executor, now)
    }

    /// The hold's watch reporting `safe`'s execution at `nonce` settled, whichever transaction
    /// executes it, at the book's clock.
    #[cfg(test)]
    pub fn release_safe_exec(&mut self, safe: crate::wallet::SafeKey, nonce: u64) -> bool {
        self.safe_execs
            .lift(safe, HoldEnd::Settled, self.clock, |held| {
                held.nonce == nonce
            })
    }

    /// The unmined execution's nonce held for `identity`'s Safe, if any (never for an EOA).
    pub fn safe_exec_held(&self, identity: &WcIdentity) -> Option<u64> {
        self.safe_execs.held(identity)
    }

    /// The holds this book defers by, shared.
    pub fn safe_execs(&self) -> SafeExecHolds {
        self.safe_execs.clone()
    }

    /// Defer by `holds` — the slot's, which outlive this book's runtime — from now on.
    pub fn share_safe_execs(&mut self, holds: &SafeExecHolds) {
        self.safe_execs = holds.clone();
    }

    pub fn has_signing(&self) -> bool {
        self.queue
            .iter()
            .any(|q| matches!(q.state, QueueState::Signing { .. }))
    }

    /// From Waiting or InReview (re-quote) → InReview{seq}.
    pub fn mark_in_review(&mut self, key: &WcKey, seq: u64) -> bool {
        match self.entry_mut(key) {
            Some(q) if matches!(q.state, QueueState::Waiting | QueueState::InReview { .. }) => {
                q.state = QueueState::InReview { seq };
                true
            }
            _ => false,
        }
    }

    /// Only from InReview{seq} with the same seq.
    pub fn mark_signing(&mut self, key: &WcKey, seq: u64) -> bool {
        match self.entry_mut(key) {
            Some(q) if matches!(q.state, QueueState::InReview { seq: s } if s == seq) => {
                q.state = QueueState::Signing { seq };
                q.failure = None;
                true
            }
            _ => false,
        }
    }

    /// Signing{seq} → InReview{seq} (retryable failure with the overlay still open).
    pub fn back_to_review(&mut self, key: &WcKey) -> bool {
        match self.entry_mut(key) {
            Some(q) => match q.state {
                QueueState::Signing { seq } => {
                    q.state = QueueState::InReview { seq };
                    true
                }
                _ => false,
            },
            None => false,
        }
    }

    /// InReview → Waiting.
    pub fn release(&mut self, key: &WcKey) -> bool {
        match self.entry_mut(key) {
            Some(q) if matches!(q.state, QueueState::InReview { .. }) => {
                q.state = QueueState::Waiting;
                true
            }
            _ => false,
        }
    }

    /// Every InReview entry except `keep` → Waiting. Returns how many moved.
    pub fn release_reviews_except(&mut self, keep: Option<&WcKey>) -> usize {
        let mut released = 0;
        for q in self.queue.iter_mut() {
            if matches!(q.state, QueueState::InReview { .. }) && Some(&q.key) != keep {
                q.state = QueueState::Waiting;
                released += 1;
            }
        }
        released
    }

    pub fn note_failure(&mut self, key: &WcKey, class: FailureClass) {
        if let Some(q) = self.queue.iter_mut().find(|q| &q.key == key) {
            q.failure = Some(class);
        }
    }

    /// A transaction signed for `key` left the wallet unacknowledged: keep it with the request (so
    /// the request is never signed again) and class the failure. The first record stands — only
    /// its own bytes are ever re-sent, so a second one can't arise.
    pub fn note_unconfirmed(&mut self, key: &WcKey, tx: UnconfirmedTx) {
        if let Some(q) = self.queue.iter_mut().find(|q| &q.key == key) {
            q.failure = Some(FailureClass::Unconfirmed);
            q.unconfirmed.get_or_insert(tx);
        }
    }

    /// The node refused `hash`, the transaction noted for `key`, as invalid on any node: those
    /// bytes can never be mined, so nothing for the request is on its way after all. The record
    /// goes — only for exactly that transaction — the failure is classed Stale (a fresh look), and
    /// the Activity list, which named the hash as possibly on its way, says it isn't. Nor can they
    /// take a Safe's nonce: a hold they still make on the request's Safe lifts.
    pub fn void_unconfirmed(
        &mut self,
        key: &WcKey,
        hash: alloy::primitives::B256,
        now: u64,
    ) -> Effects {
        self.tick_clock(now);
        let mut fx = Effects::default();
        let Some(q) = self
            .queue
            .iter_mut()
            .find(|q| &q.key == key && q.unconfirmed.as_ref().is_some_and(|tx| tx.hash == hash))
        else {
            return fx;
        };
        q.unconfirmed = None;
        q.failure = Some(FailureClass::Stale);
        if let Some(safe) = safe_key(&q.identity) {
            self.safe_execs.release_voided(safe, hash, now);
        }
        let text = format!(
            "The network refused transaction {hash:#x} for {} as invalid — it can never be \
             mined, so nothing for that request is on its way.",
            self.host_of(&key.topic)
        );
        self.raise(&mut fx, text, false, false);
        fx
    }

    /// The unacknowledged transaction signed for `key`, if one left the wallet.
    pub fn unconfirmed(&self, key: &WcKey) -> Option<UnconfirmedTx> {
        self.queue
            .iter()
            .find(|q| &q.key == key)
            .and_then(|q| q.unconfirmed.clone())
    }

    /// What the dapp is told when Kao gives up on `key` itself, for `default`'s reason — unless a
    /// transaction signed for it may be on its way: then never "expired", "rejected" or
    /// "cancelled" ([`Refusal::unconfirmed`]).
    fn refusal_for(&self, key: &WcKey, default: Refusal) -> Refusal {
        self.unconfirmed(key)
            .map_or(default, |tx| Refusal::unconfirmed(tx.hash))
    }

    pub fn take_failure(&mut self, key: &WcKey) -> Option<FailureClass> {
        self.queue
            .iter_mut()
            .find(|q| &q.key == key)
            .and_then(|q| q.failure.take())
    }

    pub fn mark_notified(&mut self, key: &WcKey) {
        if let Some(q) = self.queue.iter_mut().find(|q| &q.key == key) {
            q.notified = true;
        }
    }

    pub fn waiting_count(&self) -> usize {
        self.queue
            .iter()
            .filter(|q| q.state == QueueState::Waiting)
            .count()
    }

    // ── sessions ──

    pub fn session(&self, topic: &Topic) -> Option<&BoundSession> {
        self.sessions.get(topic)
    }

    /// In "Session N" order.
    pub fn sessions(&self) -> Vec<&BoundSession> {
        let mut v: Vec<&BoundSession> = self.sessions.values().collect();
        v.sort_by_key(|s| s.ordinal);
        v
    }

    /// Waiting → dropped; InReview → RequestGone; Signing → gone; outbox for topic dropped; notice.
    pub fn on_session_gone(&mut self, topic: &Topic, reason: GoneReason) -> Effects {
        let mut fx = Effects::default();
        if let Some(s) = self.drop_session(topic, reason, &mut fx) {
            let text = session_end_text(s.dapp.headline(), reason);
            self.raise(&mut fx, text, false, false);
        }
        fx
    }

    pub fn on_session_extended(&mut self, topic: &Topic, expiry: u64) {
        if let Some(s) = self.sessions.get_mut(topic) {
            s.expiry = expiry;
        }
    }

    /// Kao-initiated: remove now (optimistic) + Disconnect; a failed send keeps the topic "doomed".
    pub fn user_disconnect(&mut self, topic: &Topic, reason: GoneReason) -> Effects {
        let mut fx = Effects::default();
        if let Some(s) = self.drop_session(topic, reason, &mut fx) {
            let text = session_end_text(s.dapp.headline(), reason);
            self.raise(&mut fx, text, false, false);
            self.disconnects.insert(
                topic.clone(),
                Resend {
                    in_flight: true,
                    ..Resend::default()
                },
            );
            fx.net.push(NetEffect::Disconnect {
                topic: topic.clone(),
            });
        }
        fx
    }

    /// 4001 to every Waiting request of the session — but −32603 to one whose transaction may be
    /// on its way ([`Self::refusal_for`]).
    pub fn reject_all_from(&mut self, topic: &Topic) -> Effects {
        let keys: Vec<WcKey> = self
            .queue
            .iter()
            .filter(|q| &q.key.topic == topic && q.state == QueueState::Waiting)
            .map(|q| q.key.clone())
            .collect();
        let mut fx = Effects::default();
        let mut rejected = false;
        for key in &keys {
            let unconfirmed = self.unconfirmed(key);
            let refusal = self.refusal_for(key, Refusal::user_rejected());
            fx.merge(self.answer_inner(key, Answer::Refuse(refusal), false));
            match unconfirmed {
                Some(tx) => {
                    let lead = format!(
                        "Kao told {} a request you had approved failed.",
                        self.host_of(&key.topic)
                    );
                    self.raise(&mut fx, unconfirmed_line(&lead, &tx), true, false);
                }
                None => rejected = true,
            }
        }
        // One deliberate "reject all" is one rejection for the fatigue brake.
        if rejected {
            self.note_rejection(topic, &mut fx);
        }
        fx
    }

    pub fn resume(&mut self, topic: &Topic) {
        if let Some(s) = self.sessions.get_mut(topic) {
            s.paused = false;
            s.reject_streak = 0;
        }
    }

    /// Sessions whose identity ∉ available ⇒ user_disconnect(IdentityRemoved).
    pub fn reconcile(&mut self, available: &[WcIdentity]) -> Effects {
        let removed: Vec<Topic> = self
            .sessions
            .values()
            .filter(|s| !available.contains(&s.identity))
            .map(|s| s.topic.clone())
            .collect();
        let mut fx = Effects::default();
        for topic in &removed {
            fx.merge(self.user_disconnect(topic, GoneReason::IdentityRemoved));
        }
        fx
    }

    // ── time ──

    /// Kao deadlines (Waiting: answer expired / dapp-deadline: drop; InReview: RequestGone), expectation
    /// window, backoff re-sends, budget windows, idle tracking (idle ≥ IDLE_RETIRE_SECS ⇒ Retire{reason}).
    pub fn tick(&mut self, now: u64) -> Effects {
        self.tick_clock(now);
        let mut fx = Effects::default();

        // Request deadlines. Signing is never timed out by Kao (a hardware or Safe
        // ceremony may be slow); `is_live` covers the dapp's.
        let mut dapp_gone = Vec::new();
        let mut kao_expired = Vec::new();
        for q in &self.queue {
            if matches!(q.state, QueueState::Signing { .. }) {
                continue;
            }
            if q.dapp_deadline
                .is_some_and(|d| now.saturating_add(EXPIRY_MARGIN_SECS) >= d)
            {
                dapp_gone.push((q.key.clone(), q.state));
            } else if now >= q.kao_deadline {
                kao_expired.push((q.key.clone(), q.state));
            }
        }
        for (key, state) in dapp_gone {
            // The dapp stops waiting within the margin: nothing can be signed in time; no answer.
            let host = self.host_of(&key.topic);
            let unconfirmed = self.unconfirmed(&key);
            self.queue.retain(|q| q.key != key);
            fx.changed = true;
            let in_review = matches!(state, QueueState::InReview { .. });
            if in_review {
                fx.ui.push(UiEffect::RequestGone {
                    key,
                    reason: GoneReason::Expired,
                });
            }
            match unconfirmed {
                // Reviewed and approved: its transaction's hash is all that is left of it.
                Some(tx) => {
                    let lead = format!("{host} stopped waiting for a request.");
                    self.raise(&mut fx, unconfirmed_line(&lead, &tx), true, false);
                }
                None if !in_review => {
                    let text = format!("A request from {host} expired before you reviewed it.");
                    self.raise(&mut fx, text, false, false);
                }
                None => {}
            }
        }
        for (key, state) in kao_expired {
            let host = self.host_of(&key.topic);
            let unconfirmed = self.unconfirmed(&key);
            let refusal = self.refusal_for(&key, Refusal::expired());
            fx.merge(self.answer_inner(&key, Answer::Refuse(refusal), false));
            if matches!(state, QueueState::InReview { .. }) {
                fx.ui.push(UiEffect::RequestGone {
                    key,
                    reason: GoneReason::Expired,
                });
            }
            match unconfirmed {
                Some(tx) => {
                    let lead = format!(
                        "A request from {host} waited over an hour; Kao told the dapp it failed."
                    );
                    self.raise(&mut fx, unconfirmed_line(&lead, &tx), true, false);
                }
                None => {
                    let text = format!(
                        "A request from {host} waited over an hour; Kao told the dapp it expired."
                    );
                    self.raise(&mut fx, text, false, false);
                }
            }
        }

        // Paste windows: no proposal in time ⇒ the paste failed; drop the pairing as well.
        let ended: Vec<Topic> = self
            .expectations
            .iter()
            .filter(|(_, until)| now >= **until)
            .map(|(t, _)| t.clone())
            .collect();
        for topic in ended {
            self.expectations.remove(&topic);
            if self.pairing_is(&topic) {
                self.pairing = PairingState::Failed(NO_PROPOSAL_ARRIVED.to_string());
            }
            fx.net.push(NetEffect::DeletePairing { topic });
            fx.changed = true;
        }

        // The crate sweeps proposals too; this keeps the card honest if that event is lost.
        let stale_card = self
            .card
            .as_ref()
            .filter(|c| !c.busy && c.proposal.expiry_timestamp <= now)
            .map(|c| c.proposal.id);
        if let Some(id) = stale_card {
            fx.merge(self.on_proposal_expired(id));
        }

        // Past their quick re-sends, on a relay that stays up: the backoff re-send.
        if self.relay == RelayStatus::Connected {
            let due = |in_flight: bool, attempts: u32, retry_at: u64| {
                !in_flight && attempts > 0 && now >= retry_at
            };
            for (key, o) in self.outbox.iter_mut() {
                if due(o.in_flight, o.attempts, o.retry_at) {
                    o.in_flight = true;
                    fx.net.push(NetEffect::Respond {
                        key: key.clone(),
                        answer: o.answer.clone(),
                    });
                }
            }
            for (topic, d) in self.disconnects.iter_mut() {
                if due(d.in_flight, d.attempts, d.retry_at) {
                    d.in_flight = true;
                    fx.net.push(NetEffect::Disconnect {
                        topic: topic.clone(),
                    });
                }
            }
            for (id, owed) in self.owed_rejects.iter_mut() {
                if due(owed.in_flight, owed.attempts, owed.retry_at) {
                    owed.in_flight = true;
                    fx.net.push(NetEffect::RejectProposal {
                        id: *id,
                        error: owed.error.clone(),
                    });
                }
            }
        }

        self.budgets
            .retain(|_, b| now.saturating_sub(b.window_start) < BUDGET_WINDOW_SECS);
        self.refusal_toasts
            .retain(|_, t| now.saturating_sub(*t) < REFUSAL_TOAST_GAP_SECS);
        self.flaps
            .retain(|t| now.saturating_sub(*t) < FLAP_WINDOW_SECS);

        // Lazy network both ways: once nothing needs the socket, the relay stops seeing Kao online.
        if self.is_idle() {
            let since = *self.idle_since.get_or_insert(now);
            if now.saturating_sub(since) >= IDLE_RETIRE_SECS && !self.retire_requested {
                self.retire_requested = true;
                fx.net.push(NetEffect::Retire {
                    reason: IDLE_RETIRE_REASON.to_string(),
                });
            }
        } else {
            self.idle_since = None;
        }
        fx
    }

    /// Nothing needs the relay: no session, card, paste, request, or answer/disconnect to deliver.
    pub fn is_idle(&self) -> bool {
        self.sessions.is_empty()
            && self.card.is_none()
            && self.expectations.is_empty()
            && self.queue.is_empty()
            && self.outbox.is_empty()
            && self.disconnects.is_empty()
    }

    // ── teardown & view ──

    /// 4900 to Waiting/InReview, Signing → gone(Teardown), Disconnect every session.
    ///
    /// Every answer-like effect (Respond, RejectProposal) precedes every Disconnect in `net`.
    pub fn teardown(&mut self) -> Effects {
        let mut fx = Effects {
            changed: true,
            ..Default::default()
        };
        let entries: Vec<(WcKey, QueueState)> = self
            .queue
            .iter()
            .map(|q| (q.key.clone(), q.state))
            .collect();
        for (key, state) in entries {
            match state {
                QueueState::Signing { .. } => {
                    if let Some(q) = self.entry_mut(&key) {
                        q.gone.get_or_insert(GoneReason::Teardown);
                    }
                }
                QueueState::InReview { .. } | QueueState::Waiting => {
                    if matches!(state, QueueState::InReview { .. }) {
                        fx.ui.push(UiEffect::RequestGone {
                            key: key.clone(),
                            reason: GoneReason::Teardown,
                        });
                    }
                    let unconfirmed = self.unconfirmed(&key);
                    let refusal = self.refusal_for(&key, Refusal::closing());
                    fx.merge(self.answer_inner(&key, Answer::Refuse(refusal), false));
                    if let Some(tx) = unconfirmed {
                        let lead = format!(
                            "WalletConnect closed; Kao told {} a request failed.",
                            self.host_of(&key.topic)
                        );
                        self.raise(&mut fx, unconfirmed_line(&lead, &tx), true, false);
                    }
                }
            }
        }
        // Answers and proposal rejections still waiting for the relay get one last try.
        let retries: Vec<NetEffect> = self
            .undelivered()
            .into_iter()
            .filter(|e| {
                matches!(
                    e,
                    NetEffect::Respond { .. } | NetEffect::RejectProposal { .. }
                )
            })
            .collect();
        fx.net.extend(retries);
        if let Some(card) = self.card.take()
            && !card.busy
        {
            fx.net.push(NetEffect::RejectProposal {
                id: card.proposal.id,
                error: SdkError::UserRejected.error(),
            });
        }
        self.expectations.clear();
        self.pairing = PairingState::Idle;
        // `shutdown()` alone never tells a dapp: disconnect each session first.
        let topics: BTreeSet<Topic> = self
            .sessions
            .keys()
            .chain(self.disconnects.keys())
            .cloned()
            .collect();
        self.sessions.clear();
        for topic in topics {
            self.disconnects.insert(
                topic.clone(),
                Resend {
                    in_flight: true,
                    ..Resend::default()
                },
            );
            fx.net.push(NetEffect::Disconnect { topic });
        }
        self.relay = RelayStatus::Closed;
        fx
    }

    pub fn push_notice(&mut self, text: String, error: bool, now: u64) {
        self.tick_clock(now);
        self.notices.push_back(NoticeView {
            at: now,
            text,
            error,
        });
        while self.notices.len() > MAX_NOTICES {
            self.notices.pop_front();
        }
    }

    /// generation/route are filled by the runtime.
    pub fn snapshot(&self, now: u64) -> WcSnapshot {
        let proposal = self.card.as_ref().map(|c| ProposalView {
            id: c.proposal.id,
            dapp: c.dapp.clone(),
            secs_left: c.proposal.expiry_timestamp.saturating_sub(now),
            busy: c.busy,
            error: c.error.clone(),
            plan: None,
        });
        let sessions = self
            .sessions()
            .into_iter()
            .map(|s| SessionView {
                topic: s.topic.clone(),
                ordinal: s.ordinal,
                dapp: s.dapp.clone(),
                identity: s.identity,
                identity_label: s.identity_label.clone(),
                chains: s.chains.clone(),
                pending: self.queue.iter().filter(|q| q.key.topic == s.topic).count(),
                ack: s.ack,
                paused: s.paused,
            })
            .collect();
        let mut queue: Vec<RequestView> = self
            .queue
            .iter()
            .map(|q| {
                let session = self.sessions.get(&q.key.topic);
                // Signing is never timed out by Kao: only the dapp's own deadline counts there.
                let deadline = match q.state {
                    QueueState::Signing { .. } => q.dapp_deadline,
                    _ => Some(
                        q.dapp_deadline
                            .map_or(q.kao_deadline, |d| d.min(q.kao_deadline)),
                    ),
                };
                RequestView {
                    key: q.key.clone(),
                    ordinal: session.map_or(0, |s| s.ordinal),
                    dapp_host: session.map_or_else(
                        || "unknown site".to_string(),
                        |s| s.dapp.headline().to_string(),
                    ),
                    label: q.call.label(),
                    summary: q.summary.clone(),
                    identity: q.identity,
                    identity_label: session
                        .map(|s| s.identity_label.clone())
                        .unwrap_or_default(),
                    chain_id: q.chain_id,
                    state: q.state,
                    age_secs: now.saturating_sub(q.received_at),
                    secs_left: deadline.map(|d| d.saturating_sub(now)),
                    paused: session.is_some_and(|s| s.paused),
                    undelivered: false,
                    held: self.waits_on_an_execution(q),
                }
            })
            .collect();
        // Reviewed requests whose answer failed to reach the relay at least once.
        queue.extend(
            self.outbox
                .values()
                .filter(|o| o.attempts > 0)
                .filter_map(|o| o.row.as_ref())
                .map(|r| RequestView {
                    age_secs: now.saturating_sub(r.received_at),
                    secs_left: r.dapp_deadline.map(|d| d.saturating_sub(now)),
                    ..r.view.clone()
                }),
        );
        WcSnapshot {
            generation: 0,
            route: RouteKind::Direct,
            relay: self.relay,
            pairing: self.pairing.clone(),
            proposal,
            sessions,
            queue,
            notices: self.notices.iter().cloned().collect(),
            refused_count: self.refused_count,
            undelivered: self.outbox.values().filter(|o| o.attempts > 0).count(),
        }
    }

    /// Answers not yet confirmed delivered (tests: "answered exactly once, nothing pending").
    #[cfg(test)]
    pub(crate) fn outbox_len(&self) -> usize {
        self.outbox.len()
    }

    // ── private ──

    fn answer_inner(&mut self, key: &WcKey, answer: Answer, count_streak: bool) -> Effects {
        let mut fx = Effects::default();
        if self.answered.contains(key) {
            debug!(id = key.id, "request already answered; ignored");
            return fx;
        }
        let Some(pos) = self.queue.iter().position(|q| &q.key == key) else {
            debug!(id = key.id, "no queued request to answer");
            return fx;
        };
        let Some(entry) = self.queue.get(pos) else {
            return fx;
        };
        if entry.gone.is_some() {
            // Its session or the request died while signing: nothing can reach the dapp now.
            let host = self.host_of(&key.topic);
            self.queue.remove(pos);
            fx.changed = true;
            if matches!(answer, Answer::Result(_)) {
                warn!(id = key.id, "result for a request that is gone; discarded");
                let text = format!("{host} had stopped waiting — Kao discarded the result.");
                self.raise(&mut fx, text, true, false);
            }
            return fx;
        }
        if matches!(answer, Answer::Result(_)) && !matches!(entry.state, QueueState::Signing { .. })
        {
            error!(id = key.id, state = ?entry.state, "result outside Signing refused");
            return fx;
        }
        let Some(entry) = self.queue.remove(pos) else {
            return fx;
        };
        let host = self.host_of(&key.topic);
        let row = self.pending_row(&entry, &host);
        match answer {
            Answer::Result(value) => {
                if let Some(s) = self.sessions.get_mut(&key.topic) {
                    s.reject_streak = 0;
                }
                self.send_answer(key.clone(), Ok(value), row, host, &mut fx);
            }
            Answer::Refuse(refusal) => {
                if count_streak && refusal.code == codes::USER_REJECTED {
                    self.note_rejection(&key.topic, &mut fx);
                }
                self.send_answer(key.clone(), Err(refusal.error_object()), row, host, &mut fx);
            }
            Answer::Abandon => {
                debug!(id = key.id, "request abandoned without an answer");
                fx.changed = true;
            }
        }
        fx
    }

    /// Mark `key` answered and hand the runtime a Respond. Every dapp answer goes through here.
    fn send_answer(
        &mut self,
        key: WcKey,
        answer: Result<Value, ErrorObject>,
        row: Option<PendingRow>,
        host: String,
        fx: &mut Effects,
    ) {
        self.answered.insert(key.clone());
        if self.outbox.contains_key(&key) {
            error!(
                id = key.id,
                "second answer for a key in the outbox; dropped"
            );
            return;
        }
        self.outbox.insert(
            key.clone(),
            Outgoing {
                answer: answer.clone(),
                in_flight: true,
                attempts: 0,
                retry_at: 0,
                row,
                host,
            },
        );
        fx.net.push(NetEffect::Respond { key, answer });
        fx.changed = true;
    }

    /// Answer a refusal with no review, and say so: in the activity list always (within the
    /// budget), as a toast at most every `REFUSAL_TOAST_GAP_SECS` per session. The book alone
    /// decides that toast — the dashboard adds none of its own, so a refusing flood can't take
    /// over the toast slot.
    fn refuse_without_ui(
        &mut self,
        key: WcKey,
        refusal: Refusal,
        host: String,
        method: &str,
        now: u64,
        fx: &mut Effects,
    ) {
        self.refused_count = self.refused_count.saturating_add(1);
        if self.spend_budget(&key.topic, now) {
            let toast = self.refusal_toast_due(&key.topic, now);
            // A capability gap or an unsupported method is something the user can act on: name it.
            let text = if refusal.code == codes::UNSUPPORTED_METHOD {
                refusal_line(&host, method, &refusal.detail)
            } else {
                let detail =
                    crate::sanitize::sanitize_display(&refusal.detail, MAX_NOTICE_DETAIL_CHARS);
                format!("Refused a request from {host}: {detail}.")
            };
            self.raise(fx, text, true, toast);
            self.send_answer(key, Err(refusal.error_object()), None, host, fx);
        } else {
            // Over budget: a flood. Answer cheaply and keep it out of the activity list.
            self.send_answer(key, Err(Refusal::limit().error_object()), None, host, fx);
        }
    }

    /// One no-UI answer from this session's per-minute budget (a flood brake).
    fn spend_budget(&mut self, topic: &Topic, now: u64) -> bool {
        let b = self.budgets.entry(topic.clone()).or_insert(Budget {
            window_start: now,
            spent: 0,
        });
        if now.saturating_sub(b.window_start) >= BUDGET_WINDOW_SECS {
            *b = Budget {
                window_start: now,
                spent: 0,
            };
        }
        if b.spent >= MAX_AUTO_ANSWERS_PER_MIN {
            return false;
        }
        b.spent += 1;
        true
    }

    fn refusal_toast_due(&mut self, topic: &Topic, now: u64) -> bool {
        match self.refusal_toasts.get(topic) {
            Some(last) if now.saturating_sub(*last) < REFUSAL_TOAST_GAP_SECS => false,
            _ => {
                self.refusal_toasts.insert(topic.clone(), now);
                true
            }
        }
    }

    /// Fatigue brake: REJECT_STREAK_PAUSE consecutive user rejections pause auto-open.
    fn note_rejection(&mut self, topic: &Topic, fx: &mut Effects) {
        let Some(s) = self.sessions.get_mut(topic) else {
            return;
        };
        s.reject_streak = s.reject_streak.saturating_add(1);
        if s.reject_streak >= REJECT_STREAK_PAUSE && !s.paused {
            s.paused = true;
            let text = format!(
                "Requests from {} no longer open on their own after {} rejections — \
                 resume them under Apps › WalletConnect.",
                s.dapp.headline(),
                REJECT_STREAK_PAUSE
            );
            self.raise(fx, text, false, true);
        }
    }

    /// Remove a session and everything queued on it. Waiting requests vanish (the crate dropped
    /// them with the session), an open review is told why, and a signing task is marked gone so its
    /// `before_send` / `is_live` checks refuse before anything irreversible.
    fn drop_session(
        &mut self,
        topic: &Topic,
        reason: GoneReason,
        fx: &mut Effects,
    ) -> Option<BoundSession> {
        let removed = self.sessions.remove(topic);
        self.budgets.remove(topic);
        self.refusal_toasts.remove(topic);
        let before = self.queue.len();
        let mut gone_reviews = Vec::new();
        self.queue.retain_mut(|q| {
            if &q.key.topic != topic {
                return true;
            }
            match q.state {
                QueueState::Waiting => false,
                QueueState::InReview { .. } => {
                    gone_reviews.push(q.key.clone());
                    false
                }
                QueueState::Signing { .. } => {
                    q.gone.get_or_insert(reason);
                    true
                }
            }
        });
        fx.ui.extend(
            gone_reviews
                .into_iter()
                .map(|key| UiEffect::RequestGone { key, reason }),
        );
        // The crate forgot this topic's requests: queued answers can't be delivered. Answers
        // already in flight resolve on their own (as Gone).
        let lost: Vec<WcKey> = self
            .outbox
            .iter()
            .filter(|(k, o)| &k.topic == topic && !o.in_flight)
            .map(|(k, _)| k.clone())
            .collect();
        let mut lost_result = None;
        for k in lost {
            if let Some(o) = self.outbox.remove(&k)
                && o.answer.is_ok()
            {
                lost_result = Some(o.host);
            }
        }
        if let Some(host) = lost_result {
            let text = format!("{host} went away before Kao's answer reached it.");
            self.raise(fx, text, true, true);
        }
        if removed.is_some() || before != self.queue.len() {
            fx.changed = true;
        }
        removed
    }

    fn pending_row(&self, q: &QueuedRequest, host: &str) -> Option<PendingRow> {
        let session = self.sessions.get(&q.key.topic)?;
        Some(PendingRow {
            view: RequestView {
                key: q.key.clone(),
                ordinal: session.ordinal,
                dapp_host: host.to_string(),
                label: q.call.label(),
                summary: q.summary.clone(),
                identity: q.identity,
                identity_label: session.identity_label.clone(),
                chain_id: q.chain_id,
                state: q.state,
                age_secs: 0,
                secs_left: None,
                paused: false,
                undelivered: true,
                held: false,
            },
            received_at: q.received_at,
            dapp_deadline: q.dapp_deadline,
        })
    }

    /// A live (not gone) queue entry.
    fn entry_mut(&mut self, key: &WcKey) -> Option<&mut QueuedRequest> {
        self.queue
            .iter_mut()
            .find(|q| &q.key == key && q.gone.is_none())
    }

    fn pairing_is(&self, topic: &Topic) -> bool {
        matches!(
            &self.pairing,
            PairingState::Pairing { topic: t, .. } | PairingState::Waiting { topic: t, .. } if t == topic
        )
    }

    fn host_of(&self, topic: &Topic) -> String {
        self.sessions
            .get(topic)
            .map_or_else(|| "A dapp".to_string(), |s| s.dapp.headline().to_string())
    }

    /// Record a notice in the ring; also raise it as a toast when asked.
    fn raise(&mut self, fx: &mut Effects, text: String, error: bool, toast: bool) {
        if toast {
            fx.ui.push(UiEffect::Notice { text: text.clone() });
        }
        let at = self.clock;
        self.push_notice(text, error, at);
        fx.changed = true;
    }

    fn tick_clock(&mut self, now: u64) {
        self.clock = self.clock.max(now);
    }
}

/// The Activity line for a request refused without a review, naming what was refused: the dapp's
/// RPC method, or the request's kind when only that is left. Both it and the detail are sanitized
/// and clamped, since a method name is the dapp's own text.
pub(crate) fn refusal_line(host: &str, what: &str, detail: &str) -> String {
    let what = crate::sanitize::sanitize_display(what, MAX_NOTICE_METHOD_CHARS);
    let detail = crate::sanitize::sanitize_display(detail, MAX_NOTICE_DETAIL_CHARS);
    format!("Refused “{what}” from {host}: {detail}.")
}

/// The Activity line for a request Kao let go of while its transaction may be on its way: `lead`
/// (what became of the request), then the hash to look up — the only place it outlives the request.
fn unconfirmed_line(lead: &str, tx: &UnconfirmedTx) -> String {
    format!(
        "{lead} Its transaction {:#x} may still be on its way — Kao couldn't confirm the network \
         received it, so look its hash up before asking the dapp again.",
        tx.hash
    )
}

/// A Safe transaction that takes the Safe's next nonce when reviewed: one no execution has left
/// for yet (a review reopened on one that did only sends those bytes again).
fn pins_a_safe_nonce(q: &QueuedRequest) -> bool {
    q.unconfirmed.is_none() && q.identity.is_safe() && matches!(q.call, WcCall::SendTransaction(_))
}

/// `identity`'s Safe, as [`SafeExecHolds`] keys it (never an EOA).
fn safe_key(identity: &WcIdentity) -> Option<crate::wallet::SafeKey> {
    match identity {
        WcIdentity::Safe { address, chain_id } => Some((address.into_array(), *chain_id)),
        WcIdentity::Eoa { .. } => None,
    }
}

/// The housekeeper's re-send delay after the `attempts`-th failure (past the quick re-sends).
fn resend_after(attempts: u32) -> u64 {
    let doublings = attempts.saturating_sub(QUICK_RESENDS + 1).min(4);
    (RESEND_BACKOFF_SECS << doublings).min(RESEND_BACKOFF_MAX_SECS)
}

fn session_end_text(host: &str, reason: GoneReason) -> String {
    match reason {
        GoneReason::DappDisconnected => format!("{host} disconnected."),
        GoneReason::SessionExpired => format!("The session with {host} expired."),
        GoneReason::UserDisconnected => format!("Disconnected {host}."),
        GoneReason::IdentityRemoved => {
            format!("Disconnected {host}: the account it used is no longer available in Kao.")
        }
        GoneReason::Expired | GoneReason::Teardown => format!("The session with {host} ended."),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use alloy::primitives::{Address, Bytes, address};
    use serde_json::json;
    use wallet_connect::crypto::PublicKey;
    use wallet_connect::sign::{Metadata, Participant, Relay, SessionNamespaces, SessionRequest};

    use super::*;

    const NOW: u64 = 1_800_000_000;
    const ADDR: Address = address!("ab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb");
    const SAFE: Address = address!("1111111111111111111111111111111111111111");

    fn topic(n: u8) -> Topic {
        Topic::new(format!("{n:02x}").repeat(32))
    }

    fn pairing(n: u8) -> Topic {
        topic(n.wrapping_add(0x80))
    }

    fn eoa() -> WcIdentity {
        WcIdentity::Eoa { address: ADDR }
    }

    fn safe() -> WcIdentity {
        WcIdentity::Safe {
            address: SAFE,
            chain_id: 8453,
        }
    }

    fn meta() -> Metadata {
        Metadata::new("Uniswap Interface", "Swap", "https://app.uniswap.org")
    }

    fn proposal(id: u64, pairing_topic: Topic, expiry: u64) -> Proposal {
        Proposal {
            id,
            pairing_topic,
            expiry_timestamp: expiry,
            relays: vec![Relay::default()],
            proposer: Participant {
                public_key: PublicKey::from_bytes([id.to_le_bytes()[0]; 32]),
                metadata: meta(),
            },
            required_namespaces: BTreeMap::new(),
            optional_namespaces: BTreeMap::new(),
            session_properties: None,
            scoped_properties: None,
        }
    }

    fn session(topic: Topic, pairing_topic: Topic) -> Session {
        Session {
            topic,
            pairing_topic,
            relay: Relay::default(),
            expiry: NOW + 7 * 86_400,
            acknowledged: false,
            controller: PublicKey::from_bytes([1; 32]),
            namespaces: SessionNamespaces::new(),
            required_namespaces: BTreeMap::new(),
            optional_namespaces: BTreeMap::new(),
            session_properties: None,
            scoped_properties: None,
            local: Participant {
                public_key: PublicKey::from_bytes([1; 32]),
                metadata: Metadata::default(),
            },
            peer: Participant {
                public_key: PublicKey::from_bytes([2; 32]),
                metadata: meta(),
            },
        }
    }

    fn ticket(p: &Proposal, identity: WcIdentity, events: &[&str]) -> ApproveTicket {
        ApproveTicket {
            proposal_id: p.id,
            pairing_topic: p.pairing_topic.clone(),
            proposer_key: p.proposer.public_key,
            grant: Grant {
                namespaces: SessionNamespaces::new(),
                chains: vec![1, 8453],
                methods: vec!["personal_sign".into(), "wallet_switchEthereumChain".into()],
                events: events.iter().map(|e| e.to_string()).collect(),
            },
            identity,
            identity_label: "Account 1".into(),
            dapp: DappLabel::from_metadata(&p.proposer.metadata),
        }
    }

    /// Bind a session on `topic(n)` (paired over `pairing(n)`) for `identity`.
    fn bound(book: &mut WcBook, n: u8, identity: WcIdentity) -> Topic {
        let t = topic(n);
        let p = proposal(1_000 + u64::from(n), pairing(n), NOW + 300);
        book.bind_session(
            &session(t.clone(), pairing(n)),
            &ticket(&p, identity, &["chainChanged"]),
            NOW,
        );
        t
    }

    fn req(t: &Topic, id: u64, expiry: Option<u64>) -> PendingRequest {
        PendingRequest {
            id,
            topic: t.clone(),
            chain_id: "eip155:1".into(),
            request: SessionRequest {
                method: "personal_sign".into(),
                params: json!(["0x6869", ADDR.to_checksum(None)]),
                expiry_timestamp: expiry,
            },
        }
    }

    fn personal() -> Admitted {
        Admitted {
            chain_id: 1,
            call: WcCall::PersonalSign(PersonalSign {
                from: ADDR,
                message: Bytes::from_static(b"hi"),
                shape: MessageShape::Text {
                    lines: vec!["hi".into()],
                },
                siwe: None,
            }),
            summary: "Sign message".into(),
        }
    }

    fn key(t: &Topic, id: u64) -> WcKey {
        WcKey {
            topic: t.clone(),
            id,
        }
    }

    /// A dapp transaction from the Safe on Base.
    fn safe_tx() -> Admitted {
        Admitted {
            chain_id: 8453,
            call: WcCall::SendTransaction(TxIntent {
                from: SAFE,
                to: ADDR,
                value: alloy::primitives::U256::ZERO,
                data: Bytes::new(),
                chain_id: 8453,
                dapp_gas: None,
                ignored: IgnoredTxFields::default(),
            }),
            summary: "Send transaction".into(),
        }
    }

    /// An executor transaction's hash.
    fn exec(b: u8) -> alloy::primitives::B256 {
        alloy::primitives::B256::repeat_byte(b)
    }

    /// Queue a personal_sign `id` on `t` (no dapp expiry).
    fn queue(book: &mut WcBook, t: &Topic, id: u64) -> Effects {
        book.on_request(&req(t, id, None), NOW, Ok(personal()), NOW)
    }

    fn responds(fx: &Effects) -> Vec<(WcKey, Result<Value, ErrorObject>)> {
        fx.net
            .iter()
            .filter_map(|e| match e {
                NetEffect::Respond { key, answer } => Some((key.clone(), answer.clone())),
                _ => None,
            })
            .collect()
    }

    fn error_code(fx: &Effects) -> Option<i64> {
        match responds(fx).as_slice() {
            [(_, Err(e))] => Some(e.code),
            _ => None,
        }
    }

    fn retires(fx: &Effects) -> usize {
        fx.net
            .iter()
            .filter(|e| matches!(e, NetEffect::Retire { .. }))
            .count()
    }

    fn to_signing(book: &mut WcBook, k: &WcKey, seq: u64) {
        assert!(book.mark_in_review(k, seq));
        assert!(book.mark_signing(k, seq));
    }

    // ── proposals ──

    #[test]
    fn unsolicited_proposal_is_auto_rejected() {
        let mut book = WcBook::new();
        let fx = book.on_proposal(proposal(7, pairing(1), NOW + 300), NOW);
        assert!(book.proposal().is_none());
        assert_eq!(
            fx.net,
            vec![NetEffect::RejectProposal {
                id: 7,
                error: SdkError::UserRejected.error()
            }]
        );
        assert_eq!(SdkError::UserRejected.error().code, 5000);
        assert!(
            fx.ui.is_empty(),
            "no attention, no toast for an unsolicited proposal"
        );
        // The crate re-emits it when nothing answered yet: rejected once only.
        assert!(
            book.on_proposal(proposal(7, pairing(1), NOW + 300), NOW)
                .net
                .is_empty()
        );
        assert_eq!(book.snapshot(NOW).refused_count, 1);
    }

    #[test]
    fn proposal_after_expectation_window_rejected() {
        let mut book = WcBook::new();
        book.expect_pairing(pairing(1), NOW, None);
        let until = NOW + PAIRING_WAIT_DEFAULT_SECS;
        let fx = book.on_proposal(proposal(7, pairing(1), until + 300), until);
        assert!(book.proposal().is_none());
        assert!(matches!(
            fx.net.as_slice(),
            [NetEffect::RejectProposal { id: 7, .. }]
        ));
        // The housekeeper closes the window: the paste failed, its pairing goes.
        let fx = book.tick(until);
        assert!(matches!(book.pairing(), PairingState::Failed(_)));
        assert!(
            fx.net
                .contains(&NetEffect::DeletePairing { topic: pairing(1) })
        );
    }

    #[test]
    fn expectation_window_follows_the_link_but_is_capped() {
        let mut book = WcBook::new();
        book.expect_pairing(pairing(1), NOW, Some(NOW + 120));
        book.pairing_started(&pairing(1), NOW + 1);
        assert_eq!(
            book.pairing(),
            &PairingState::Waiting {
                topic: pairing(1),
                since: NOW + 1,
                until: NOW + 120
            }
        );
        book.expect_pairing(pairing(2), NOW, Some(NOW + 3_600));
        book.pairing_started(&pairing(2), NOW);
        assert!(matches!(
            book.pairing(),
            PairingState::Waiting { until, .. } if *until == NOW + PAIRING_WAIT_MAX_SECS
        ));
        assert!(
            !book.connect_blocked(),
            "a waiting paste gives way to a fresh link"
        );
    }

    #[test]
    fn second_proposal_same_paste_rejected() {
        let mut book = WcBook::new();
        book.expect_pairing(pairing(1), NOW, None);
        assert!(
            book.on_proposal(proposal(7, pairing(1), NOW + 300), NOW)
                .net
                .is_empty()
        );
        let fx = book.on_proposal(proposal(8, pairing(1), NOW + 300), NOW + 1);
        assert!(matches!(
            fx.net.as_slice(),
            [NetEffect::RejectProposal { id: 8, .. }]
        ));
        assert_eq!(book.proposal().map(|c| c.proposal.id), Some(7));
        // A proposal on another pasted pairing still can't open a second card.
        book.expect_pairing(pairing(2), NOW, None);
        let fx = book.on_proposal(proposal(9, pairing(2), NOW + 300), NOW + 2);
        assert!(matches!(
            fx.net.as_slice(),
            [NetEffect::RejectProposal { id: 9, .. }]
        ));
    }

    #[test]
    fn expected_proposal_is_shown() {
        let mut book = WcBook::new();
        book.expect_pairing(pairing(1), NOW, None);
        assert!(!book.connect_blocked(), "only a card blocks");
        let fx = book.on_proposal(proposal(7, pairing(1), NOW + 300), NOW + 2);
        assert!(fx.net.is_empty());
        assert_eq!(fx.ui, vec![UiEffect::Attention]);
        assert!(fx.changed);
        let card = book.proposal().expect("card");
        assert_eq!(card.dapp.headline(), "app.uniswap.org");
        assert_eq!(book.pairing(), &PairingState::Idle);
        // The paste is consumed; the late pair() completion doesn't revive "waiting".
        book.pairing_started(&pairing(1), NOW + 3);
        assert_eq!(book.pairing(), &PairingState::Idle);
        assert!(
            book.connect_blocked(),
            "Connect stays disabled while the card is open"
        );
        // Pasting the same link again re-emits the same proposal: nothing changes.
        let fx = book.on_proposal(proposal(7, pairing(1), NOW + 300), NOW + 4);
        assert!(fx.net.is_empty() && !fx.changed);
    }

    #[test]
    fn dapp_dropping_the_pairing_fails_the_paste_and_the_card() {
        let mut book = WcBook::new();
        book.expect_pairing(pairing(1), NOW, None);
        book.on_pairing_gone(&pairing(1));
        assert!(matches!(book.pairing(), PairingState::Failed(_)));
        book.expect_pairing(pairing(2), NOW, None);
        book.on_proposal(proposal(7, pairing(2), NOW + 300), NOW);
        book.on_pairing_gone(&pairing(2));
        assert!(book.proposal().is_none());
        assert!(!book.connect_blocked());
    }

    // ── approve ──

    #[test]
    fn double_approve_is_ignored() {
        let mut book = WcBook::new();
        book.expect_pairing(pairing(1), NOW, None);
        book.on_proposal(proposal(7, pairing(1), NOW + 300), NOW);
        assert!(book.begin_approve(7).is_ok());
        assert_eq!(book.begin_approve(7), Err(APPROVE_BUSY));
        assert!(!book.begin_reject(7), "no reject while approving");
        assert_eq!(book.begin_approve(8), Err(APPROVE_GONE));
        book.approve_failed(7, "Relay offline — try again.".into());
        let card = book.proposal().expect("card stays");
        assert!(!card.busy);
        assert_eq!(card.error.as_deref(), Some("Relay offline — try again."));
        assert!(
            book.begin_approve(7).is_ok(),
            "a failed approve can be retried"
        );
    }

    #[test]
    fn session_cap_blocks_approve() {
        let mut book = WcBook::new();
        for n in 0..MAX_SESSIONS {
            bound(&mut book, n as u8, eoa());
        }
        book.expect_pairing(pairing(100), NOW, None);
        book.on_proposal(proposal(7, pairing(100), NOW + 300), NOW);
        assert_eq!(book.begin_approve(7), Err(APPROVE_TOO_MANY));
        assert!(!book.proposal().is_some_and(|c| c.busy));
    }

    #[test]
    fn bind_session_clears_card_and_numbers_sessions() {
        let mut book = WcBook::new();
        book.expect_pairing(pairing(1), NOW, None);
        let p = proposal(7, pairing(1), NOW + 300);
        book.on_proposal(p.clone(), NOW);
        book.begin_approve(7).expect("approve");
        book.bind_session(&session(topic(1), pairing(1)), &ticket(&p, eoa(), &[]), NOW);
        let t2 = bound(&mut book, 2, safe());
        assert!(book.proposal().is_none());
        let s = book.session(&topic(1)).expect("bound");
        assert_eq!(
            (s.ordinal, s.identity, s.ack),
            (1, eoa(), AckState::Pending)
        );
        assert_eq!(book.session(&t2).map(|s| s.ordinal), Some(2));
        assert_eq!(
            book.sessions()
                .iter()
                .map(|s| s.ordinal)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    // ── exactly once ──

    #[test]
    fn answered_request_replay_answers_duplicate() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        queue(&mut book, &t, 5);
        let k = key(&t, 5);
        to_signing(&mut book, &k, 1);
        let fx = book.answer(&k, Answer::Result(json!("0xsig")));
        assert_eq!(responds(&fx), vec![(k.clone(), Ok(json!("0xsig")))]);
        // While the answer is still on its way the crate holds the request: a re-emit is a stray.
        assert!(queue(&mut book, &t, 5).net.is_empty());
        book.on_responded(&k, RespondResult::Delivered);
        let fx = queue(&mut book, &t, 5);
        assert_eq!(error_code(&fx), Some(codes::INVALID_REQUEST));
        assert_eq!(
            responds(&fx)[0].1,
            Err(ErrorObject::new(-32600, "Duplicate request id."))
        );
        assert!(book.request(&k).is_none(), "a replay is never queued");
    }

    #[test]
    fn same_id_on_two_topics_are_distinct() {
        let mut book = WcBook::new();
        let a = bound(&mut book, 1, eoa());
        let b = bound(&mut book, 2, eoa());
        assert!(!queue(&mut book, &a, 9).ui.is_empty());
        assert!(
            !queue(&mut book, &b, 9).ui.is_empty(),
            "same id, other topic: queued too"
        );
        assert_eq!(book.waiting_count(), 2);
        let fx = book.answer(&key(&a, 9), Answer::Refuse(Refusal::user_rejected()));
        assert_eq!(responds(&fx)[0].0, key(&a, 9));
        assert_eq!(book.state_of(&key(&b, 9)), Some(QueueState::Waiting));
        book.on_responded(&key(&a, 9), RespondResult::Delivered);
        // A replay on `a` is a duplicate; `b` is still its own pending request.
        assert_eq!(
            error_code(&queue(&mut book, &a, 9)),
            Some(codes::INVALID_REQUEST)
        );
        assert_eq!(book.state_of(&key(&b, 9)), Some(QueueState::Waiting));
    }

    #[test]
    fn answer_is_idempotent() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        queue(&mut book, &t, 5);
        let k = key(&t, 5);
        let first = book.answer(&k, Answer::Refuse(Refusal::user_rejected()));
        assert_eq!(error_code(&first), Some(codes::USER_REJECTED));
        assert!(
            book.answer(&k, Answer::Refuse(Refusal::user_rejected()))
                .net
                .is_empty()
        );
        assert!(book.answer(&k, Answer::Abandon).net.is_empty());
        // Nothing queued under this key: a stray answer is ignored too.
        assert!(
            book.answer(&key(&t, 6), Answer::Refuse(Refusal::failed("x")))
                .net
                .is_empty()
        );
    }

    #[test]
    fn ok_answer_refused_unless_signing() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        queue(&mut book, &t, 5);
        let k = key(&t, 5);
        assert!(book.answer(&k, Answer::Result(json!("0x"))).net.is_empty());
        assert!(book.mark_in_review(&k, 3));
        assert!(book.answer(&k, Answer::Result(json!("0x"))).net.is_empty());
        assert_eq!(book.state_of(&k), Some(QueueState::InReview { seq: 3 }));
        assert!(!book.mark_signing(&k, 2), "only from the same review");
        assert!(book.mark_signing(&k, 3));
        assert_eq!(
            responds(&book.answer(&k, Answer::Result(json!("0x")))).len(),
            1
        );
    }

    #[test]
    fn cancel_after_signed_does_not_double_respond() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        queue(&mut book, &t, 5);
        let k = key(&t, 5);
        to_signing(&mut book, &k, 1);
        assert_eq!(
            responds(&book.answer(&k, Answer::Result(json!("0xhash")))).len(),
            1
        );
        let late = book.answer(&k, Answer::Refuse(Refusal::user_rejected()));
        assert!(late.net.is_empty());
        assert_eq!(book.snapshot(NOW).sessions[0].pending, 0);
    }

    // ── signing is serialized; the pump's picks ──

    #[test]
    fn next_reviewable_none_while_any_signing() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        queue(&mut book, &t, 1);
        queue(&mut book, &t, 2);
        assert_eq!(
            book.next_reviewable(Some(&eoa()), NOW, None, false),
            Some(key(&t, 1))
        );
        to_signing(&mut book, &key(&t, 1), 1);
        assert!(book.has_signing());
        assert_eq!(book.next_reviewable(Some(&eoa()), NOW, None, false), None);
        assert_eq!(
            book.next_reviewable(Some(&eoa()), NOW, Some(&key(&t, 2)), false),
            None,
            "not even [Review] opens a second request while one signs"
        );
    }

    #[test]
    fn next_reviewable_filters() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        let s = bound(&mut book, 2, safe());
        // Only the active identity's requests.
        queue(&mut book, &s, 1);
        assert_eq!(book.next_reviewable(Some(&eoa()), NOW, None, false), None);
        assert_eq!(book.next_reviewable(None, NOW, None, false), None);
        assert_eq!(
            book.next_reviewable(Some(&safe()), NOW, None, false),
            Some(key(&s, 1))
        );
        // A sibling Safe on another chain is a different identity.
        let sibling = WcIdentity::Safe {
            address: SAFE,
            chain_id: 1,
        };
        assert_eq!(book.next_reviewable(Some(&sibling), NOW, None, false), None);
        // Old requests wait for [Review].
        queue(&mut book, &t, 2);
        let later = NOW + AUTO_OPEN_MAX_AGE_SECS;
        assert_eq!(book.next_reviewable(Some(&eoa()), later, None, false), None);
        assert_eq!(
            book.next_reviewable(Some(&eoa()), later, Some(&key(&t, 2)), false),
            Some(key(&t, 2))
        );
        // A Safe transaction waits while the Safe's queue is loading; its messages don't.
        let tx = Admitted {
            chain_id: 8453,
            call: WcCall::SendTransaction(TxIntent {
                from: SAFE,
                to: ADDR,
                value: alloy::primitives::U256::ZERO,
                data: Bytes::new(),
                chain_id: 8453,
                dapp_gas: None,
                ignored: IgnoredTxFields::default(),
            }),
            summary: "Send transaction".into(),
        };
        let mut book = WcBook::new();
        let s = bound(&mut book, 2, safe());
        book.on_request(&req(&s, 3, None), NOW, Ok(tx), NOW);
        queue(&mut book, &s, 4);
        assert_eq!(
            book.next_reviewable(Some(&safe()), NOW, None, true),
            Some(key(&s, 4))
        );
        assert_eq!(
            book.next_reviewable(Some(&safe()), NOW, None, false),
            Some(key(&s, 3))
        );
        // An execution Kao sent on this Safe and hasn't seen mined holds its transactions too,
        // whatever the dashboard says. Holds are per Safe: another Safe's execution, or this one
        // settling at an older nonce, lifts nothing.
        let this = (SAFE.into_array(), 8453);
        let other = (SAFE.into_array(), 1);
        assert!(book.hold_safe_exec(this, 7, exec(0xe7), NOW).is_some());
        assert!(
            book.hold_safe_exec(this, 7, exec(0xe7), NOW).is_none(),
            "already held: one watch"
        );
        assert!(book.hold_safe_exec(other, 2, exec(0xe2), NOW).is_some());
        assert_eq!(
            book.next_reviewable(Some(&safe()), NOW, None, false),
            Some(key(&s, 4))
        );
        assert!(!book.release_safe_exec(other, 7));
        assert!(!book.release_safe_exec(this, 6));
        assert!(book.release_safe_exec(other, 2));
        assert_eq!(book.safe_exec_held(&safe()), Some(7));
        assert_eq!(
            book.next_reviewable(Some(&safe()), NOW, None, false),
            Some(key(&s, 4))
        );
        assert!(book.release_safe_exec(this, 7));
        assert_eq!(
            book.next_reviewable(Some(&safe()), NOW, None, false),
            Some(key(&s, 3))
        );
    }

    /// The holds are the slot's, shared by every book that defers by them, and they never hold
    /// back the request whose own execution left unacknowledged: its review only sends those bytes
    /// again. The pane is told which requests wait, and the listener hears when a hold lifts.
    #[test]
    fn execution_holds_are_shared_and_spare_the_latched_request() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let tx = || Admitted {
            chain_id: 8453,
            call: WcCall::SendTransaction(TxIntent {
                from: SAFE,
                to: ADDR,
                value: alloy::primitives::U256::ZERO,
                data: Bytes::new(),
                chain_id: 8453,
                dapp_gas: None,
                ignored: IgnoredTxFields::default(),
            }),
            summary: "Send transaction".into(),
        };
        let holds = SafeExecHolds::default();
        let lifted = Arc::new(AtomicUsize::new(0));
        let told = lifted.clone();
        holds.on_lift(move || {
            told.fetch_add(1, Ordering::SeqCst);
        });
        let this = (SAFE.into_array(), 8453);
        assert!(holds.hold(this, 7, exec(0xe7), NOW).is_some());
        let mut book = WcBook::new();
        book.share_safe_execs(&holds);
        let s = bound(&mut book, 2, safe());
        book.on_request(&req(&s, 3, None), NOW, Ok(tx()), NOW);
        book.on_request(&req(&s, 4, None), NOW, Ok(tx()), NOW);
        assert_eq!(book.safe_exec_held(&safe()), Some(7));
        assert_eq!(book.next_reviewable(Some(&safe()), NOW, None, false), None);
        let held = |book: &WcBook| -> Vec<bool> {
            book.snapshot(NOW).queue.iter().map(|r| r.held).collect()
        };
        assert_eq!(held(&book), vec![true, true]);
        book.note_unconfirmed(
            &key(&s, 4),
            UnconfirmedTx {
                hash: alloy::primitives::B256::repeat_byte(0x99),
                raw: Bytes::from_static(&[0x02]),
                nonce: 1,
            },
        );
        assert_eq!(
            book.next_reviewable(Some(&safe()), NOW, None, true),
            Some(key(&s, 4)),
            "nor while the Safe's queue loads: it pins nothing"
        );
        assert_eq!(held(&book), vec![true, false]);
        assert!(book.held_behind_execution(&key(&s, 3)));
        assert!(!book.held_behind_execution(&key(&s, 4)));
        assert!(
            !holds.release(this, 7, exec(0xe8), HoldEnd::Settled, NOW),
            "another transaction at that nonce isn't the held one"
        );
        assert_eq!(lifted.load(Ordering::SeqCst), 0);
        assert!(holds.release(this, 7, exec(0xe7), HoldEnd::Settled, NOW));
        assert_eq!(lifted.load(Ordering::SeqCst), 1);
        assert!(!book.held_behind_execution(&key(&s, 3)));
        assert_eq!(held(&book), vec![false, false]);
        assert_eq!(
            book.next_reviewable(Some(&safe()), NOW, None, false),
            Some(key(&s, 3))
        );
    }

    /// A hold is its executing transaction's: another at the same nonce settling, or refused,
    /// lifts nothing. That very transaction refused as invalid on any node lifts it — through the
    /// request it was noted for, too — and every way a hold goes stops its watch.
    #[test]
    fn a_hold_lifts_only_for_its_own_executor_and_stops_its_watch() {
        use tokio::sync::oneshot::error::TryRecvError;
        let holds = SafeExecHolds::default();
        let this = (SAFE.into_array(), 8453);
        let mut watch = holds.hold(this, 7, exec(0xe7), NOW).expect("held");
        assert!(!holds.release(this, 7, exec(0xe8), HoldEnd::Settled, NOW));
        assert!(!holds.release_voided(this, exec(0xe8), NOW));
        assert!(!holds.release_voided((SAFE.into_array(), 1), exec(0xe7), NOW));
        assert_eq!(watch.try_recv(), Err(TryRecvError::Empty));
        assert!(holds.release_voided(this, exec(0xe7), NOW));
        assert_eq!(
            watch.try_recv(),
            Err(TryRecvError::Closed),
            "the watch stops"
        );
        assert_eq!(holds.held(&safe()), None);
        // A later nonce's hold takes over: the earlier watch has nothing left to settle.
        let mut earlier = holds.hold(this, 7, exec(0xe7), NOW).expect("held");
        let _later = holds.hold(this, 8, exec(0xe8), NOW).expect("held");
        assert_eq!(earlier.try_recv(), Err(TryRecvError::Closed));
        assert!(!holds.release(this, 7, exec(0xe7), HoldEnd::Settled, NOW));
        assert_eq!(holds.held(&safe()), Some(8));

        let mut book = WcBook::new();
        book.share_safe_execs(&holds);
        let s = bound(&mut book, 2, safe());
        book.on_request(&req(&s, 3, None), NOW, Ok(safe_tx()), NOW);
        book.note_unconfirmed(
            &key(&s, 3),
            UnconfirmedTx {
                hash: exec(0xe8),
                raw: Bytes::from_static(&[0x02]),
                nonce: 1,
            },
        );
        assert!(book.void_unconfirmed(&key(&s, 3), exec(0xe8), NOW).changed);
        assert_eq!(book.safe_exec_held(&safe()), None);
    }

    /// A Safe transaction a hold kept back opens by itself once the hold lifts, however long it
    /// waited: it ages from the lift.
    #[test]
    fn a_held_safe_tx_ages_from_the_lift() {
        let holds = SafeExecHolds::default();
        let this = (SAFE.into_array(), 8453);
        let mut book = WcBook::new();
        book.share_safe_execs(&holds);
        let s = bound(&mut book, 2, safe());
        let _watch = holds.hold(this, 7, exec(0xe7), NOW);
        book.on_request(&req(&s, 3, None), NOW, Ok(safe_tx()), NOW);
        let later = NOW + AUTO_OPEN_MAX_AGE_SECS + 60;
        assert_eq!(
            book.next_reviewable(Some(&safe()), later, None, false),
            None
        );
        assert!(holds.release(this, 7, exec(0xe7), HoldEnd::Settled, later));
        assert_eq!(
            book.next_reviewable(Some(&safe()), later, None, false),
            Some(key(&s, 3))
        );
        assert_eq!(
            book.next_reviewable(Some(&safe()), later + AUTO_OPEN_MAX_AGE_SECS, None, false),
            None,
            "and ages from there"
        );
    }

    /// A hold whose watch gave up on its execution — the node stopped showing it, or it outlasted
    /// the longest hold — lifts, but that execution may still be mined: what it kept back is not
    /// promised to open by itself, so a request held past the auto-open age waits for [Review],
    /// and a review pinning that nonce can name the execution that may take it.
    #[test]
    fn a_hold_given_up_on_lifts_without_resetting_the_age() {
        let holds = SafeExecHolds::default();
        let this = (SAFE.into_array(), 8453);
        let mut book = WcBook::new();
        book.share_safe_execs(&holds);
        let s = bound(&mut book, 2, safe());
        let _watch = holds.hold(this, 7, exec(0xe7), NOW);
        book.on_request(&req(&s, 3, None), NOW, Ok(safe_tx()), NOW);
        let later = NOW + AUTO_OPEN_MAX_AGE_SECS + 60;
        assert!(holds.release(this, 7, exec(0xe7), HoldEnd::GaveUp, later));
        assert_eq!(book.safe_exec_held(&safe()), None);
        assert!(!book.held_behind_execution(&key(&s, 3)));
        assert_eq!(
            book.next_reviewable(Some(&safe()), later, None, false),
            None,
            "a request held past the auto-open age needs [Review] after a hold given up on"
        );
        assert_eq!(
            book.next_reviewable(Some(&safe()), later, Some(&key(&s, 3)), false),
            Some(key(&s, 3))
        );
        assert_eq!(holds.unmined_at(&safe(), 7), Some(exec(0xe7)));
        assert_eq!(holds.unmined_at(&safe(), 8), None);
        book.on_request(&req(&s, 4, None), later, Ok(safe_tx()), later);
        assert_eq!(
            book.next_reviewable(Some(&safe()), later, None, false),
            Some(key(&s, 4)),
            "a fresh one still opens by itself"
        );
        // A later execution held at that nonce is the one a review there may collide with; once
        // it settles, nothing Kao sent may take the nonce any more.
        let _next = holds.hold(this, 7, exec(0xe8), later);
        assert_eq!(holds.unmined_at(&safe(), 7), Some(exec(0xe8)));
        assert!(holds.release(this, 7, exec(0xe8), HoldEnd::Settled, later));
        assert_eq!(holds.unmined_at(&safe(), 7), Some(exec(0xe7)));
        assert!(!holds.release_voided(this, exec(0xe7), later));
        assert_eq!(
            holds.unmined_at(&safe(), 7),
            None,
            "refused as invalid on any node, it can never take the nonce"
        );
    }

    /// A hold credits a waiting request only with the time it actually held it: one already past
    /// the auto-open age before the hold began stays waiting for [Review] once it lifts, and one
    /// that waited a little before the hold keeps that little.
    #[test]
    fn a_hold_credits_only_the_time_it_held_a_request() {
        let holds = SafeExecHolds::default();
        let this = (SAFE.into_array(), 8453);
        let mut book = WcBook::new();
        book.share_safe_execs(&holds);
        let s = bound(&mut book, 2, safe());
        book.on_request(&req(&s, 3, None), NOW, Ok(safe_tx()), NOW);
        let stale = NOW + AUTO_OPEN_MAX_AGE_SECS + 300;
        assert_eq!(
            book.next_reviewable(Some(&safe()), stale, None, false),
            None
        );
        let _watch = holds.hold(this, 7, exec(0xe7), stale + 5);
        assert!(holds.release(this, 7, exec(0xe7), HoldEnd::Settled, stale + 12));
        assert_eq!(
            book.next_reviewable(Some(&safe()), stale + 12, None, false),
            None,
            "a request stale before the hold began opened by itself after it"
        );

        let mut book = WcBook::new();
        let holds = SafeExecHolds::default();
        book.share_safe_execs(&holds);
        let s = bound(&mut book, 2, safe());
        book.on_request(&req(&s, 3, None), NOW, Ok(safe_tx()), NOW);
        let began = NOW + 300;
        let _first = holds.hold(this, 7, exec(0xe7), began);
        // Taken over by a later nonce's execution: still the same hold, from when it began.
        let _second = holds.hold(this, 8, exec(0xe8), began + 600);
        let lifted = began + 1200;
        assert!(holds.release(this, 8, exec(0xe8), HoldEnd::Settled, lifted));
        assert_eq!(
            book.next_reviewable(Some(&safe()), lifted, None, false),
            Some(key(&s, 3)),
            "it waited 300 s outside the hold"
        );
        assert_eq!(
            book.next_reviewable(
                Some(&safe()),
                lifted + AUTO_OPEN_MAX_AGE_SECS - 300,
                None,
                false
            ),
            None
        );
    }

    /// [Review anyway] on a held request: that request alone stops waiting for the execution.
    #[test]
    fn reviewing_past_a_hold_frees_only_that_request() {
        let holds = SafeExecHolds::default();
        let this = (SAFE.into_array(), 8453);
        let mut book = WcBook::new();
        book.share_safe_execs(&holds);
        let s = bound(&mut book, 2, safe());
        let _watch = holds.hold(this, 7, exec(0xe7), NOW);
        book.on_request(&req(&s, 3, None), NOW, Ok(safe_tx()), NOW);
        book.on_request(&req(&s, 4, None), NOW, Ok(safe_tx()), NOW);
        assert_eq!(book.next_reviewable(Some(&safe()), NOW, None, false), None);
        assert!(!book.review_past_hold(&key(&s, 9)), "no such request");
        assert!(book.review_past_hold(&key(&s, 4)));
        assert!(book.held_behind_execution(&key(&s, 3)));
        assert!(!book.held_behind_execution(&key(&s, 4)));
        let held: Vec<bool> = book.snapshot(NOW).queue.iter().map(|r| r.held).collect();
        assert_eq!(held, vec![true, false]);
        assert_eq!(
            book.next_reviewable(Some(&safe()), NOW, Some(&key(&s, 4)), false),
            Some(key(&s, 4))
        );
        assert_eq!(
            book.next_reviewable(Some(&safe()), NOW, None, true),
            None,
            "still not while the Safe's queue loads"
        );
        assert_eq!(holds.unmined_at(&safe(), 7), Some(exec(0xe7)));
    }

    // ── flood caps ──

    #[test]
    fn queue_caps_per_session() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        for id in 0..MAX_QUEUE_PER_SESSION as u64 {
            assert!(queue(&mut book, &t, id).net.is_empty());
        }
        let fx = queue(&mut book, &t, 99);
        assert_eq!(error_code(&fx), Some(codes::LIMIT_EXCEEDED));
        assert_eq!(book.waiting_count(), MAX_QUEUE_PER_SESSION);
        assert!(book.request(&key(&t, 99)).is_none());
    }

    #[test]
    fn queue_caps_global() {
        let mut book = WcBook::new();
        let per = MAX_QUEUE_PER_SESSION as u64;
        let sessions = (MAX_QUEUE_TOTAL / MAX_QUEUE_PER_SESSION) as u8;
        for n in 0..sessions {
            let t = bound(&mut book, n, eoa());
            for id in 0..per {
                assert!(queue(&mut book, &t, id).net.is_empty());
            }
        }
        let other = bound(&mut book, 200, eoa());
        assert_eq!(
            error_code(&queue(&mut book, &other, 1)),
            Some(codes::LIMIT_EXCEEDED)
        );
        assert_eq!(book.waiting_count(), MAX_QUEUE_TOTAL);
    }

    #[test]
    fn auto_answer_budget_enforced() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        let refusal = || {
            Err(Refusal::unsupported(
                "eth_sign is disabled in Kao.",
                "eth_sign",
            ))
        };
        for id in 0..u64::from(MAX_AUTO_ANSWERS_PER_MIN) {
            let fx = book.on_request(&req(&t, id, None), NOW, refusal(), NOW);
            assert_eq!(error_code(&fx), Some(codes::UNSUPPORTED_METHOD));
        }
        let fx = book.on_request(&req(&t, 100, None), NOW + 59, refusal(), NOW + 59);
        assert_eq!(
            error_code(&fx),
            Some(codes::LIMIT_EXCEEDED),
            "over budget: cheap -32005"
        );
        // Exactly one answer per request regardless.
        assert_eq!(responds(&fx).len(), 1);
        // The budget is per session…
        let other = bound(&mut book, 2, eoa());
        let fx = book.on_request(&req(&other, 1, None), NOW + 59, refusal(), NOW + 59);
        assert_eq!(error_code(&fx), Some(codes::UNSUPPORTED_METHOD));
        // …and per minute.
        let fx = book.on_request(&req(&t, 101, None), NOW + 60, refusal(), NOW + 60);
        assert_eq!(error_code(&fx), Some(codes::UNSUPPORTED_METHOD));
    }

    #[test]
    fn refusals_toast_at_most_every_ten_seconds() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        let refusal = || {
            Err(Refusal::unsupported(
                "Trezor can't sign EIP-712 typed data.",
                "Trezor",
            ))
        };
        let toasts = |fx: &Effects| {
            fx.ui
                .iter()
                .filter(|e| matches!(e, UiEffect::Notice { .. }))
                .count()
        };
        assert_eq!(
            toasts(&book.on_request(&req(&t, 1, None), NOW, refusal(), NOW)),
            1
        );
        assert_eq!(
            toasts(&book.on_request(&req(&t, 2, None), NOW, refusal(), NOW + 9)),
            0
        );
        assert_eq!(
            toasts(&book.on_request(&req(&t, 3, None), NOW, refusal(), NOW + 10)),
            1
        );
        let notices = book.snapshot(NOW + 10).notices;
        let refusals: Vec<&NoticeView> = notices.iter().filter(|n| n.error).collect();
        assert_eq!(refusals.len(), 3, "every refusal is in the activity list");
        assert!(refusals[0].text.contains("app.uniswap.org"));
    }

    #[test]
    fn requests_on_unknown_sessions_are_dropped_silently() {
        let mut book = WcBook::new();
        let fx = book.on_request(&req(&topic(9), 1, None), NOW, Ok(personal()), NOW);
        assert!(fx.net.is_empty() && fx.ui.is_empty() && !fx.changed);
        let fx = book.on_request(
            &req(&topic(9), 2, None),
            NOW,
            Err(Refusal::unauthorized("x")),
            NOW,
        );
        assert!(fx.net.is_empty());
    }

    // ── request lifetime ──

    #[test]
    fn requests_without_expiry_get_kao_deadline() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        queue(&mut book, &t, 1);
        let q = book.request(&key(&t, 1)).expect("queued");
        assert_eq!(q.dapp_deadline, None);
        assert_eq!(q.kao_deadline, NOW + KAO_REQUEST_TTL_SECS);
        assert!(book.tick(NOW + KAO_REQUEST_TTL_SECS - 1).net.is_empty());
        let fx = book.tick(NOW + KAO_REQUEST_TTL_SECS);
        assert_eq!(
            responds(&fx),
            vec![(
                key(&t, 1),
                Err(ErrorObject::new(
                    -32603,
                    "Request expired before it was reviewed."
                ))
            )]
        );
        assert!(book.request(&key(&t, 1)).is_none());
    }

    /// Kao's TTL caps how long any request waits for review; the dapp's own expiry is kept as sent.
    #[test]
    fn dapp_expiry_capped_to_60_min() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        book.on_request(&req(&t, 1, Some(NOW + 7_200)), NOW, Ok(personal()), NOW);
        book.on_request(&req(&t, 2, Some(NOW + 600)), NOW, Ok(personal()), NOW);
        let q1 = book.request(&key(&t, 1)).expect("queued");
        assert_eq!(q1.dapp_deadline, Some(NOW + 7_200));
        assert_eq!(q1.kao_deadline, NOW + KAO_REQUEST_TTL_SECS);
        assert_eq!(
            book.request(&key(&t, 2)).and_then(|q| q.dapp_deadline),
            Some(NOW + 600)
        );
        // The row counts down to whichever comes first.
        let rows = book.snapshot(NOW).queue;
        assert_eq!(rows[0].secs_left, Some(KAO_REQUEST_TTL_SECS));
        assert_eq!(rows[1].secs_left, Some(600));
        // Within the margin of the dapp's own deadline a waiting request just goes (no answer).
        let fx = book.tick(NOW + 600 - EXPIRY_MARGIN_SECS);
        assert!(responds(&fx).is_empty());
        assert!(book.request(&key(&t, 2)).is_none());
        assert!(book.request(&key(&t, 1)).is_some());
        // Kao's TTL tells the dapp that still waits (−32603).
        let fx = book.tick(NOW + KAO_REQUEST_TTL_SECS);
        assert_eq!(
            responds(&fx)
                .into_iter()
                .map(|(k, a)| (k, a.err().map(|e| e.code)))
                .collect::<Vec<_>>(),
            vec![(key(&t, 1), Some(codes::INTERNAL))]
        );
    }

    /// A dapp that waits longer than Kao's TTL is answered −32603 at the TTL — never dropped
    /// unanswered as if the dapp itself had stopped waiting.
    #[test]
    fn long_dapp_expiry_is_answered_at_kao_ttl() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        book.on_request(&req(&t, 1, Some(NOW + 7_200)), NOW, Ok(personal()), NOW);
        book.on_request(&req(&t, 2, None), NOW, Ok(personal()), NOW);
        let fx = book.tick(NOW + KAO_REQUEST_TTL_SECS - EXPIRY_MARGIN_SECS);
        assert!(responds(&fx).is_empty());
        assert!(
            book.request(&key(&t, 1)).is_some(),
            "the dapp still waits for it"
        );
        let fx = book.tick(NOW + KAO_REQUEST_TTL_SECS);
        let expired: Vec<(WcKey, Option<i64>)> = responds(&fx)
            .into_iter()
            .map(|(k, a)| (k, a.err().map(|e| e.code)))
            .collect();
        assert_eq!(
            expired,
            vec![
                (key(&t, 1), Some(codes::INTERNAL)),
                (key(&t, 2), Some(codes::INTERNAL))
            ]
        );
    }

    /// The relay can refuse a publish (rate limit, internal error) on a socket that stays up, so
    /// no reconnect will ever flush it: the housekeeper re-sends with a backoff.
    #[test]
    fn undelivered_answers_and_disconnects_are_resent_while_connected() {
        let mut book = WcBook::new();
        book.on_relay(true, NOW);
        let t = bound(&mut book, 1, eoa());
        let doomed = bound(&mut book, 2, eoa());
        queue(&mut book, &t, 1);
        to_signing(&mut book, &key(&t, 1), 1);
        book.answer(&key(&t, 1), Answer::Result(json!("0x01")));
        book.user_disconnect(&doomed, GoneReason::UserDisconnected);
        let refused = || RespondResult::Retry("relay error".into());
        for _ in 0..=QUICK_RESENDS {
            book.on_responded(&key(&t, 1), refused());
            book.on_disconnected(&doomed, refused());
        }
        let resent = |fx: &Effects| {
            let answers = responds(fx).len();
            let disconnects = fx
                .net
                .iter()
                .filter(|e| matches!(e, NetEffect::Disconnect { topic } if *topic == doomed))
                .count();
            (answers, disconnects)
        };
        assert_eq!(resent(&book.tick(NOW + 1)), (0, 0), "not right away");
        assert_eq!(resent(&book.tick(NOW + 600)), (1, 1), "re-sent later");
        assert_eq!(
            resent(&book.tick(NOW + 601)),
            (0, 0),
            "once: it is in flight"
        );
    }

    /// A proposal too large to plan on the UI thread never becomes a card.
    #[test]
    fn oversized_proposal_is_rejected_without_a_card() {
        let mut book = WcBook::new();
        let mut p = proposal(1, pairing(1), NOW + 300);
        let chains: Vec<String> = (0..20_000u64).map(|c| format!("eip155:{c}")).collect();
        p.optional_namespaces.insert(
            "eip155".into(),
            wallet_connect::sign::ProposalNamespace {
                chains: Some(chains),
                methods: vec!["personal_sign".into()],
                events: vec!["chainChanged".into()],
            },
        );
        book.expect_pairing(pairing(1), NOW, None);
        let fx = book.on_proposal(p, NOW);
        assert!(book.proposal().is_none(), "no card");
        let rejected: Vec<i64> = fx
            .net
            .iter()
            .filter_map(|e| match e {
                NetEffect::RejectProposal { id: 1, error } => Some(error.code),
                _ => None,
            })
            .collect();
        assert_eq!(rejected, vec![5100]);
        assert!(matches!(book.pairing(), PairingState::Failed(_)));
        assert!(book.is_idle(), "the paste is used up");
    }

    /// A refused method is named in the (throttled) notice the book raises.
    #[test]
    fn unsupported_method_refusal_names_the_method() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        let mut r = req(&t, 1, None);
        r.request.method = "eth_signTypedData_v4".into();
        let refusal = Refusal::unsupported("Trezor can't sign EIP-712 typed data.", "Trezor");
        let fx = book.on_request(&r, NOW, Err(refusal), NOW);
        let toast = fx.ui.iter().find_map(|e| match e {
            UiEffect::Notice { text } => Some(text.clone()),
            _ => None,
        });
        assert_eq!(
            toast.as_deref(),
            Some("Refused “eth_signTypedData_v4” from app.uniswap.org: Trezor.")
        );
    }

    /// An approve that failed after the network was involved leaves no card to retry
    /// from; the dapp is told no, and the same proposal never becomes a card again.
    #[test]
    fn abandoned_approve_is_never_offered_again() {
        let mut book = WcBook::new();
        let p = proposal(1, pairing(1), NOW + 300);
        book.expect_pairing(pairing(1), NOW, None);
        book.on_proposal(p.clone(), NOW);
        assert!(book.begin_approve(1).is_ok());
        let fx = book.approve_abandoned(1);
        assert!(book.proposal().is_none(), "no card to retry from");
        assert!(matches!(
            fx.net.as_slice(),
            [NetEffect::RejectProposal { id: 1, error }] if error.code == 5000
        ));
        assert!(fx.ui.iter().any(|e| matches!(
            e,
            UiEffect::Notice { text } if text.contains("reconnect from the dapp")
        )));
        assert!(
            book.snapshot(NOW)
                .notices
                .iter()
                .any(|n| n.error && n.text.contains("reconnect from the dapp"))
        );
        assert!(matches!(book.pairing(), PairingState::Failed(_)));
        assert_eq!(book.begin_approve(1).err(), Some(APPROVE_GONE));
        // The crate re-emits it when the same link is pasted again.
        book.expect_pairing(pairing(1), NOW + 5, None);
        let fx = book.on_proposal(p, NOW + 5);
        assert!(book.proposal().is_none(), "never a card again");
        assert!(matches!(
            fx.net.as_slice(),
            [NetEffect::RejectProposal { id: 1, .. }]
        ));
        assert!(matches!(book.pairing(), PairingState::Failed(_)));
        // A stale result for an abandoned card changes nothing.
        assert!(book.approve_abandoned(1).net.is_empty());
    }

    /// A "no" Kao owes a dapp for a proposal with no card — abandoned half-way, or unsolicited —
    /// that couldn't be sent (the relay was down) is sent again once the relay is back, until it
    /// goes or the proposal expires: otherwise the dapp's connect dialog hangs until then.
    #[test]
    fn an_undelivered_proposal_rejection_is_sent_again_on_reconnect() {
        let rejects = |fx: &Effects| -> Vec<u64> {
            fx.net
                .iter()
                .filter_map(|e| match e {
                    NetEffect::RejectProposal { id, .. } => Some(*id),
                    _ => None,
                })
                .collect()
        };
        let mut book = WcBook::new();
        book.on_relay(true, NOW);
        // Abandoned half-way: its rejection fails while the relay is down.
        book.expect_pairing(pairing(1), NOW, None);
        book.on_proposal(proposal(1, pairing(1), NOW + 300), NOW);
        assert!(book.begin_approve(1).is_ok());
        assert_eq!(rejects(&book.approve_abandoned(1)), vec![1]);
        book.on_relay(false, NOW + 1);
        book.proposal_rejected(1, Err("Couldn't reach the relay — try again.".into()));
        // Unsolicited: auto-rejected, and that fails too.
        assert_eq!(
            rejects(&book.on_proposal(proposal(2, pairing(2), NOW + 300), NOW + 1)),
            vec![2]
        );
        book.proposal_rejected(2, Err("Couldn't reach the relay — try again.".into()));

        let fx = book.on_relay(true, NOW + 30);
        assert_eq!(rejects(&fx), vec![1, 2], "both owed again once connected");
        assert!(
            rejects(&book.on_relay(true, NOW + 31)).is_empty(),
            "not while in flight"
        );
        book.proposal_rejected(1, Ok(()));
        book.proposal_rejected(2, Err("Couldn't reach the relay — try again.".into()));
        book.on_proposal_expired(2);
        assert!(
            rejects(&book.on_relay(true, NOW + 60)).is_empty(),
            "delivered, or expired: nothing owed"
        );
        assert!(rejects(&book.teardown()).is_empty());
    }

    /// The relay can refuse a rejection (a request timeout, a JSON-RPC error) on a socket that
    /// stays up, so no reconnect ever flushes it: it goes again at once, then on the housekeeper's
    /// backoff — as an undelivered answer does — until it lands or the proposal expires.
    #[test]
    fn an_owed_proposal_rejection_is_resent_while_the_relay_stays_up() {
        let rejects = |fx: &Effects| -> Vec<u64> {
            fx.net
                .iter()
                .filter_map(|e| match e {
                    NetEffect::RejectProposal { id, .. } => Some(*id),
                    _ => None,
                })
                .collect()
        };
        let failed = || Err("Couldn't reach the relay — try again.".to_string());
        let mut book = WcBook::new();
        book.on_relay(true, NOW);
        assert_eq!(
            rejects(&book.on_proposal(proposal(2, pairing(2), NOW + 300), NOW)),
            vec![2]
        );
        for _ in 0..QUICK_RESENDS {
            assert_eq!(rejects(&book.proposal_rejected(2, failed())), vec![2]);
        }
        // Past the quick re-sends: nothing at once, then the housekeeper's backoff.
        assert!(rejects(&book.proposal_rejected(2, failed())).is_empty());
        let resent = (1..RESEND_BACKOFF_MAX_SECS)
            .find(|t| rejects(&book.tick(NOW + t)).contains(&2))
            .expect("re-sent while the relay stayed connected");
        assert!(resent >= RESEND_BACKOFF_SECS, "{resent}");
        assert!(
            rejects(&book.tick(NOW + resent + 1)).is_empty(),
            "not while in flight"
        );
        book.proposal_rejected(2, Ok(()));
        assert!(
            (0..2 * RESEND_BACKOFF_MAX_SECS)
                .all(|t| rejects(&book.tick(NOW + resent + t)).is_empty()),
            "delivered: nothing owed"
        );
    }

    #[test]
    fn a_new_paste_supersedes_one_still_waiting() {
        let mut book = WcBook::new();
        book.expect_pairing(pairing(1), NOW, None);
        book.pairing_started(&pairing(1), NOW);
        let fx = book.supersede_pairing(&pairing(2));
        assert!(matches!(
            fx.net.as_slice(),
            [NetEffect::DeletePairing { topic }] if *topic == pairing(1)
        ));
        assert_eq!(book.pairing(), &PairingState::Idle);
        book.expect_pairing(pairing(2), NOW, None);
        // The old link's proposal, should it still come, isn't the paste's any more.
        let fx = book.on_proposal(proposal(1, pairing(1), NOW + 300), NOW);
        assert!(book.proposal().is_none());
        assert!(matches!(
            fx.net.as_slice(),
            [NetEffect::RejectProposal { id: 1, .. }]
        ));
        // Re-pasting the same link keeps its pairing.
        assert!(book.supersede_pairing(&pairing(2)).net.is_empty());
        let fx = book.on_proposal(proposal(2, pairing(2), NOW + 300), NOW);
        assert!(fx.net.is_empty());
        assert_eq!(book.proposal().map(|c| c.proposal.id), Some(2));
    }

    /// Only an open card blocks a new paste; a paste still waiting does not.
    #[test]
    fn a_waiting_paste_does_not_block_a_new_one() {
        let mut book = WcBook::new();
        book.expect_pairing(pairing(1), NOW, None);
        book.pairing_started(&pairing(1), NOW);
        assert!(matches!(book.pairing(), PairingState::Waiting { .. }));
        assert!(!book.connect_blocked());
        let p = proposal(2, pairing(2), NOW + 300);
        book.expect_pairing(pairing(2), NOW, None);
        book.on_proposal(p, NOW);
        assert!(book.connect_blocked(), "a card is open");
    }

    #[test]
    fn tick_expires_waiting_but_not_signing() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        queue(&mut book, &t, 1);
        queue(&mut book, &t, 2);
        queue(&mut book, &t, 3);
        to_signing(&mut book, &key(&t, 2), 7);
        assert!(book.mark_in_review(&key(&t, 3), 8));
        let fx = book.tick(NOW + KAO_REQUEST_TTL_SECS + 5);
        let answered: Vec<WcKey> = responds(&fx).into_iter().map(|(k, _)| k).collect();
        assert_eq!(answered, vec![key(&t, 1), key(&t, 3)]);
        assert!(fx.ui.contains(&UiEffect::RequestGone {
            key: key(&t, 3),
            reason: GoneReason::Expired
        }));
        assert_eq!(
            book.state_of(&key(&t, 2)),
            Some(QueueState::Signing { seq: 7 })
        );
        assert!(book.request(&key(&t, 2)).is_some_and(|q| q.gone.is_none()));
    }

    #[test]
    fn crate_request_expiry_drops_waiting_flags_review_and_signing() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        for id in 1..=3 {
            queue(&mut book, &t, id);
        }
        assert!(book.mark_in_review(&key(&t, 2), 1));
        to_signing(&mut book, &key(&t, 3), 2);
        assert!(book.on_request_expired(&key(&t, 1)).ui.is_empty());
        assert!(book.request(&key(&t, 1)).is_none());
        let fx = book.on_request_expired(&key(&t, 2));
        assert_eq!(
            fx.ui,
            vec![UiEffect::RequestGone {
                key: key(&t, 2),
                reason: GoneReason::Expired
            }]
        );
        book.on_request_expired(&key(&t, 3));
        assert_eq!(
            book.request(&key(&t, 3)).and_then(|q| q.gone),
            Some(GoneReason::Expired)
        );
        // The signing task finishing later answers nothing.
        assert!(
            book.answer(&key(&t, 3), Answer::Result(json!("0x")))
                .net
                .is_empty()
        );
        assert!(!book.has_signing());
    }

    // ── sessions ──

    #[test]
    fn reconcile_disconnects_removed_identity() {
        let mut book = WcBook::new();
        let e = bound(&mut book, 1, eoa());
        let s = bound(&mut book, 2, safe());
        queue(&mut book, &s, 1);
        let fx = book.reconcile(&[eoa()]);
        assert_eq!(fx.net, vec![NetEffect::Disconnect { topic: s.clone() }]);
        assert!(book.session(&s).is_none());
        assert!(book.session(&e).is_some());
        assert!(book.request(&key(&s, 1)).is_none());
        assert!(
            book.snapshot(NOW)
                .notices
                .iter()
                .any(|n| n.text.contains("no longer available"))
        );
        // Nothing else to remove.
        assert!(book.reconcile(&[eoa()]).net.is_empty());
    }

    #[test]
    fn settle_refusal_removes_session() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        queue(&mut book, &t, 1);
        let fx = book.on_ack(&t, Err(AckFailure::Refused));
        assert!(book.session(&t).is_none());
        assert!(book.request(&key(&t, 1)).is_none());
        assert_eq!(fx.net, vec![NetEffect::DeletePairing { topic: pairing(1) }]);
        assert!(fx.ui.iter().any(|e| matches!(
            e,
            UiEffect::Notice { text } if text.contains("declined")
        )));
        assert!(
            book.snapshot(NOW)
                .notices
                .iter()
                .any(|n| n.error && n.text.contains("declined"))
        );
    }

    #[test]
    fn pairing_deleted_after_ack() {
        let mut book = WcBook::new();
        let a = bound(&mut book, 1, eoa());
        let b = bound(&mut book, 2, eoa());
        let c = bound(&mut book, 3, eoa());
        let fx = book.on_ack(&a, Ok(()));
        assert_eq!(fx.net, vec![NetEffect::DeletePairing { topic: pairing(1) }]);
        assert_eq!(book.session(&a).map(|s| s.ack), Some(AckState::Confirmed));
        let fx = book.on_ack(&b, Err(AckFailure::Timeout));
        assert_eq!(fx.net, vec![NetEffect::DeletePairing { topic: pairing(2) }]);
        assert_eq!(book.session(&b).map(|s| s.ack), Some(AckState::Unconfirmed));
        // Shutting down: the pairing dies with the client.
        assert!(book.on_ack(&c, Err(AckFailure::Closed)).net.is_empty());
        // The ack of a session the user already disconnected still drops its pairing.
        let d = bound(&mut book, 4, eoa());
        book.user_disconnect(&d, GoneReason::UserDisconnected);
        assert_eq!(
            book.on_ack(&d, Ok(())).net,
            vec![NetEffect::DeletePairing { topic: pairing(4) }]
        );
    }

    #[test]
    fn session_gone_drops_waiting_flags_inreview_marks_signing_gone() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        let other = bound(&mut book, 2, eoa());
        for id in 1..=3 {
            queue(&mut book, &t, id);
        }
        queue(&mut book, &other, 1);
        assert!(book.mark_in_review(&key(&t, 2), 1));
        to_signing(&mut book, &key(&t, 3), 2);
        let fx = book.on_session_gone(&t, GoneReason::DappDisconnected);
        assert_eq!(
            fx.ui,
            vec![UiEffect::RequestGone {
                key: key(&t, 2),
                reason: GoneReason::DappDisconnected
            }]
        );
        assert!(book.request(&key(&t, 1)).is_none());
        assert!(book.request(&key(&t, 2)).is_none());
        let signing = book.request(&key(&t, 3)).expect("kept while its task runs");
        assert_eq!(signing.gone, Some(GoneReason::DappDisconnected));
        assert!(!book.back_to_review(&key(&t, 3)));
        assert!(!book.mark_in_review(&key(&t, 3), 9));
        // The task's result reaches nobody; the entry goes.
        assert!(
            book.answer(&key(&t, 3), Answer::Result(json!("0x")))
                .net
                .is_empty()
        );
        assert!(book.request(&key(&t, 3)).is_none());
        assert_eq!(book.state_of(&key(&other, 1)), Some(QueueState::Waiting));
        assert!(
            book.snapshot(NOW)
                .notices
                .iter()
                .any(|n| n.text == "app.uniswap.org disconnected.")
        );
    }

    #[test]
    fn user_disconnect_dooms_topic_until_delivered() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        book.on_relay(true, NOW);
        let fx = book.user_disconnect(&t, GoneReason::UserDisconnected);
        assert_eq!(fx.net, vec![NetEffect::Disconnect { topic: t.clone() }]);
        assert!(book.session(&t).is_none(), "removed optimistically");
        assert!(!book.is_idle(), "a disconnect still has to reach the dapp");
        book.on_relay(false, NOW + 10);
        let fx = book.on_disconnected(&t, RespondResult::Retry("Disconnected".into()));
        assert!(fx.net.is_empty(), "relay down: wait for the reconnect");
        let fx = book.on_relay(true, NOW + 20);
        assert_eq!(fx.net, vec![NetEffect::Disconnect { topic: t.clone() }]);
        book.on_disconnected(&t, RespondResult::Delivered);
        assert!(book.is_idle());
    }

    // ── outbox ──

    #[test]
    fn outbox_retries_only_on_retry_class() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        book.on_relay(true, NOW);
        for id in 1..=3 {
            queue(&mut book, &t, id);
            to_signing(&mut book, &key(&t, id), id);
            book.answer(&key(&t, id), Answer::Result(json!(format!("0x0{id}"))));
        }
        // Delivered and Gone are final.
        assert!(
            book.on_responded(&key(&t, 1), RespondResult::Delivered)
                .net
                .is_empty()
        );
        let fx = book.on_responded(&key(&t, 2), RespondResult::Gone("NoRequest".into()));
        assert!(fx.net.is_empty());
        assert!(fx.ui.iter().any(|e| matches!(e, UiEffect::Notice { .. })));
        // Retry while the relay still looks connected: a quick re-send, bounded.
        for _ in 0..QUICK_RESENDS {
            let fx = book.on_responded(&key(&t, 3), RespondResult::Retry("Timeout".into()));
            assert_eq!(responds(&fx), vec![(key(&t, 3), Ok(json!("0x03")))]);
        }
        assert!(
            book.on_responded(&key(&t, 3), RespondResult::Retry("Timeout".into()))
                .net
                .is_empty()
        );
        let snap = book.snapshot(NOW);
        assert_eq!(snap.undelivered, 1);
        assert!(
            snap.queue
                .iter()
                .any(|r| r.key == key(&t, 3) && r.undelivered)
        );
        // The next connection re-sends the same answer, once.
        book.on_relay(false, NOW + 1);
        let fx = book.on_relay(true, NOW + 2);
        assert_eq!(responds(&fx), vec![(key(&t, 3), Ok(json!("0x03")))]);
        assert!(book.undelivered().is_empty(), "already in flight");
        book.on_responded(&key(&t, 3), RespondResult::Delivered);
        assert_eq!(book.snapshot(NOW).undelivered, 0);
        assert!(book.request(&key(&t, 3)).is_none());
    }

    #[test]
    fn flush_marks_undelivered_in_flight() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        queue(&mut book, &t, 1);
        book.answer(&key(&t, 1), Answer::Refuse(Refusal::user_rejected()));
        book.on_responded(&key(&t, 1), RespondResult::Retry("Disconnected".into()));
        let first = book.undelivered();
        assert_eq!(first.len(), 1);
        assert!(book.undelivered().is_empty());
    }

    // ── fatigue ──

    #[test]
    fn reject_streak_pauses_and_resume_clears() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        let mut toasted = false;
        for id in 1..=u64::from(REJECT_STREAK_PAUSE) {
            queue(&mut book, &t, id);
            let fx = book.answer(&key(&t, id), Answer::Refuse(Refusal::user_rejected()));
            toasted |= fx.ui.iter().any(|e| matches!(e, UiEffect::Notice { .. }));
        }
        assert!(toasted);
        assert!(book.session(&t).is_some_and(|s| s.paused));
        queue(&mut book, &t, 10);
        assert_eq!(book.next_reviewable(Some(&eoa()), NOW, None, false), None);
        assert_eq!(
            book.next_reviewable(Some(&eoa()), NOW, Some(&key(&t, 10)), false),
            Some(key(&t, 10)),
            "[Review] still opens it"
        );
        book.resume(&t);
        let s = book.session(&t).expect("session");
        assert!(!s.paused && s.reject_streak == 0);
        assert_eq!(
            book.next_reviewable(Some(&eoa()), NOW, None, false),
            Some(key(&t, 10))
        );
        // A non-user refusal doesn't count; a signed answer resets the streak.
        book.answer(
            &key(&t, 10),
            Answer::Refuse(Refusal::failed("prepare failed")),
        );
        assert_eq!(book.session(&t).map(|s| s.reject_streak), Some(0));
        queue(&mut book, &t, 11);
        book.answer(&key(&t, 11), Answer::Refuse(Refusal::user_rejected()));
        queue(&mut book, &t, 12);
        to_signing(&mut book, &key(&t, 12), 1);
        book.answer(&key(&t, 12), Answer::Result(json!("0x")));
        assert_eq!(book.session(&t).map(|s| s.reject_streak), Some(0));
    }

    #[test]
    fn reject_all_answers_waiting_only() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        for id in 1..=3 {
            queue(&mut book, &t, id);
        }
        assert!(book.mark_in_review(&key(&t, 3), 1));
        let fx = book.reject_all_from(&t);
        let answered: Vec<(WcKey, i64)> = responds(&fx)
            .into_iter()
            .map(|(k, a)| (k, a.err().map_or(0, |e| e.code)))
            .collect();
        assert_eq!(answered, vec![(key(&t, 1), 4001), (key(&t, 2), 4001)]);
        assert_eq!(
            book.state_of(&key(&t, 3)),
            Some(QueueState::InReview { seq: 1 })
        );
        assert_eq!(book.session(&t).map(|s| s.reject_streak), Some(1));
    }

    #[test]
    fn release_reviews_moves_inreview_to_waiting() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        for id in 1..=3 {
            queue(&mut book, &t, id);
        }
        assert!(book.mark_in_review(&key(&t, 1), 1));
        to_signing(&mut book, &key(&t, 2), 2);
        book.release_reviews_except(None);
        assert_eq!(book.state_of(&key(&t, 1)), Some(QueueState::Waiting));
        assert_eq!(
            book.state_of(&key(&t, 2)),
            Some(QueueState::Signing { seq: 2 })
        );
        assert!(book.back_to_review(&key(&t, 2)));
        assert_eq!(
            book.state_of(&key(&t, 2)),
            Some(QueueState::InReview { seq: 2 })
        );
        assert!(book.release(&key(&t, 2)));
        assert!(!book.release(&key(&t, 2)));
    }

    #[test]
    fn release_reviews_except_keeps_the_shown_review() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        for id in 1..=4 {
            queue(&mut book, &t, id);
        }
        assert!(book.mark_in_review(&key(&t, 1), 1));
        assert!(book.mark_in_review(&key(&t, 2), 2));
        to_signing(&mut book, &key(&t, 3), 3);
        assert_eq!(book.release_reviews_except(Some(&key(&t, 2))), 1);
        assert_eq!(book.state_of(&key(&t, 1)), Some(QueueState::Waiting));
        assert_eq!(
            book.state_of(&key(&t, 2)),
            Some(QueueState::InReview { seq: 2 })
        );
        assert_eq!(
            book.state_of(&key(&t, 3)),
            Some(QueueState::Signing { seq: 3 })
        );
        assert_eq!(book.state_of(&key(&t, 4)), Some(QueueState::Waiting));
        assert_eq!(book.release_reviews_except(None), 1);
        assert_eq!(book.state_of(&key(&t, 2)), Some(QueueState::Waiting));
        assert_eq!(book.release_reviews_except(None), 0);
    }

    #[test]
    fn failure_class_is_taken_once() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        queue(&mut book, &t, 1);
        book.note_failure(&key(&t, 1), FailureClass::Stale);
        assert_eq!(book.take_failure(&key(&t, 1)), Some(FailureClass::Stale));
        assert_eq!(book.take_failure(&key(&t, 1)), None);
        book.mark_notified(&key(&t, 1));
        assert!(book.request(&key(&t, 1)).is_some_and(|q| q.notified));
    }

    /// An unacknowledged transaction stays with its request through every state change — taking
    /// the failure class, a new signing claim, a release to the queue — and the first record
    /// stands.
    #[test]
    fn unconfirmed_transaction_outlives_the_failure_and_the_review() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        queue(&mut book, &t, 1);
        let k = key(&t, 1);
        let tx = |b: u8| UnconfirmedTx {
            hash: alloy::primitives::B256::repeat_byte(b),
            raw: Bytes::from(vec![b; 3]),
            nonce: 5,
        };
        assert_eq!(book.unconfirmed(&k), None);
        assert!(book.mark_in_review(&k, 7) && book.mark_signing(&k, 7));
        book.note_unconfirmed(&k, tx(0xaa));
        assert_eq!(book.take_failure(&k), Some(FailureClass::Unconfirmed));
        assert!(book.back_to_review(&k) && book.mark_signing(&k, 7));
        book.note_unconfirmed(&k, tx(0xbb));
        assert!(book.back_to_review(&k) && book.release(&k));
        assert_eq!(book.state_of(&k), Some(QueueState::Waiting));
        assert_eq!(
            book.unconfirmed(&k),
            Some(tx(0xaa)),
            "the first record stands"
        );
        assert_eq!(book.unconfirmed(&key(&t, 2)), None);
    }

    /// Only a refusal of the very transaction noted lets go of it: then nothing for the request
    /// is on its way, it may be signed afresh, and Activity says so.
    #[test]
    fn a_refused_transaction_lets_go_of_its_request() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        queue(&mut book, &t, 1);
        let k = key(&t, 1);
        let tx = UnconfirmedTx {
            hash: alloy::primitives::B256::repeat_byte(0xaa),
            raw: Bytes::from(vec![0xaa; 3]),
            nonce: 5,
        };
        to_signing(&mut book, &k, 7);
        book.note_unconfirmed(&k, tx.clone());
        assert_eq!(book.take_failure(&k), Some(FailureClass::Unconfirmed));

        // Another hash, or another request: nothing moves.
        let other = alloy::primitives::B256::repeat_byte(0xbb);
        assert!(!book.void_unconfirmed(&k, other, NOW).changed);
        assert!(!book.void_unconfirmed(&key(&t, 2), tx.hash, NOW).changed);
        assert_eq!(book.unconfirmed(&k), Some(tx.clone()));

        assert!(book.void_unconfirmed(&k, tx.hash, NOW).changed);
        assert_eq!(book.unconfirmed(&k), None);
        assert_eq!(book.take_failure(&k), Some(FailureClass::Stale));
        let hash = format!("{:#x}", tx.hash);
        assert!(
            book.snapshot(NOW)
                .notices
                .iter()
                .any(|n| n.text.contains(&hash) && n.text.contains("never be mined")),
            "Activity takes the hash back"
        );
        // Back to review and released: Reject all is a plain rejection again.
        assert!(book.back_to_review(&k) && book.release(&k));
        assert_eq!(error_code(&book.reject_all_from(&t)), Some(4001));
    }

    /// Kao giving up on a request whose transaction may be on its way — its own deadline, Reject
    /// all, closing — never tells the dapp it expired, was rejected or was cancelled: the user
    /// approved it, and it may yet be mined. Nor does the dapp's own deadline drop it as "expired
    /// before you reviewed it". Each time, the Activity list keeps the transaction's hash.
    #[test]
    fn giving_up_on_an_unconfirmed_request_keeps_its_transaction_in_view() {
        let tx = UnconfirmedTx {
            hash: alloy::primitives::B256::repeat_byte(0xaa),
            raw: Bytes::from(vec![0xaa; 3]),
            nonce: 5,
        };
        let hash = format!("{:#x}", tx.hash);
        let latched = |book: &mut WcBook, expiry: Option<u64>| {
            let t = bound(book, 1, eoa());
            book.on_request(&req(&t, 1, expiry), NOW, Ok(personal()), NOW);
            let k = key(&t, 1);
            to_signing(book, &k, 7);
            book.note_unconfirmed(&k, tx.clone());
            assert!(book.back_to_review(&k));
            (t, k)
        };
        let kept_in_view = |book: &WcBook, case: &str| {
            let notices = book.snapshot(NOW).notices;
            assert!(
                notices
                    .iter()
                    .any(|n| n.error && n.text.contains(&hash) && n.text.contains("on its way")),
                "{case}: the hash left the Activity list: {notices:?}"
            );
        };
        let told_failed = |fx: &Effects, case: &str| {
            let answers = responds(fx);
            let [(_, Err(e))] = answers.as_slice() else {
                panic!("{case}: one answer, a refusal: {fx:?}");
            };
            assert_eq!(
                (e.code, e.message.as_str()),
                (codes::INTERNAL, Refusal::failed("").message),
                "{case}: told the dapp {e:?}"
            );
        };

        // Kao's own deadline, on the latched review.
        let mut book = WcBook::new();
        let (_, k) = latched(&mut book, None);
        let fx = book.tick(book.request(&k).expect("queued").kao_deadline);
        told_failed(&fx, "Kao's deadline");
        kept_in_view(&book, "Kao's deadline");

        // Reject all, with the request back in the queue.
        let mut book = WcBook::new();
        let (t, k) = latched(&mut book, None);
        assert!(book.release(&k));
        let fx = book.reject_all_from(&t);
        told_failed(&fx, "Reject all");
        kept_in_view(&book, "Reject all");
        assert_eq!(
            book.session(&t).map(|s| s.reject_streak),
            Some(0),
            "nothing the user rejected"
        );

        // Closing, on the latched review.
        let mut book = WcBook::new();
        latched(&mut book, None);
        let fx = book.teardown();
        told_failed(&fx, "closing");
        kept_in_view(&book, "closing");

        // The dapp's deadline, with the request back in the queue: nobody to answer.
        let mut book = WcBook::new();
        let (_, k) = latched(&mut book, Some(NOW + 600));
        assert!(book.release(&k));
        let fx = book.tick(NOW + 600);
        assert!(responds(&fx).is_empty());
        kept_in_view(&book, "the dapp's deadline");
        assert!(
            !book
                .snapshot(NOW)
                .notices
                .iter()
                .any(|n| n.text.contains("before you reviewed it")),
            "it was reviewed and approved"
        );
    }

    // ── relay and idle ──

    #[test]
    fn flapping_with_nothing_at_stake_retires() {
        let mut book = WcBook::new();
        let mut retired = 0;
        for i in 0..6u64 {
            book.on_relay(true, NOW + i * 10);
            retired += retires(&book.on_relay(false, NOW + i * 10 + 1));
        }
        assert_eq!(retired, 1, "retired once, after the fourth flap");
        assert!(matches!(book.relay(), RelayStatus::Reconnecting { .. }));

        // With a session at stake Kao keeps reconnecting.
        let mut book = WcBook::new();
        bound(&mut book, 1, eoa());
        for i in 0..6u64 {
            book.on_relay(true, NOW + i * 10);
            assert_eq!(retires(&book.on_relay(false, NOW + i * 10 + 1)), 0);
        }

        // Healthy connections that later drop are not flaps.
        let mut book = WcBook::new();
        for i in 0..6u64 {
            book.on_relay(true, NOW + i * 100);
            assert_eq!(retires(&book.on_relay(false, NOW + i * 100 + 30)), 0);
        }
    }

    #[test]
    fn idle_tracking() {
        let mut book = WcBook::new();
        assert!(book.is_idle());
        assert_eq!(retires(&book.tick(NOW)), 0);
        assert_eq!(retires(&book.tick(NOW + IDLE_RETIRE_SECS - 1)), 0);
        assert_eq!(retires(&book.tick(NOW + IDLE_RETIRE_SECS)), 1);
        assert_eq!(
            retires(&book.tick(NOW + 2 * IDLE_RETIRE_SECS)),
            0,
            "asked once"
        );

        // Anything at stake resets the clock.
        let mut book = WcBook::new();
        book.tick(NOW);
        book.expect_pairing(pairing(1), NOW + 20, None);
        assert!(!book.is_idle());
        assert_eq!(retires(&book.tick(NOW + IDLE_RETIRE_SECS)), 0);
        book.pairing_failed(&pairing(1), "That isn't a valid WalletConnect link.".into());
        assert!(book.is_idle());
        assert_eq!(retires(&book.tick(NOW + IDLE_RETIRE_SECS + 1)), 0);
        assert_eq!(retires(&book.tick(NOW + 2 * IDLE_RETIRE_SECS + 1)), 1);

        let mut book = WcBook::new();
        bound(&mut book, 1, eoa());
        assert!(!book.is_idle());
        assert_eq!(retires(&book.tick(NOW + 10 * IDLE_RETIRE_SECS)), 0);
    }

    // ── view & teardown ──

    #[test]
    fn snapshot_contains_no_raw_metadata() {
        let mut book = WcBook::new();
        book.expect_pairing(pairing(1), NOW, None);
        let mut p = proposal(7, pairing(1), NOW + 300);
        p.proposer.metadata = Metadata {
            name: "Uni\u{202e}swap".into(),
            description: "Totally \u{200b}legit".into(),
            url: "https://app.uniswap.org/swap?x=1".into(),
            icons: vec!["https://tracker.example/pixel.png".into()],
            verify_url: Some("https://verify.example".into()),
            redirect: None,
        };
        book.on_proposal(p, NOW);
        let snap = book.snapshot(NOW + 10);
        let debug = format!("{snap:?}");
        assert!(!debug.contains('\u{202e}') && !debug.contains('\u{200b}'));
        assert!(!debug.contains("tracker.example") && !debug.contains("verify.example"));
        let card = snap.proposal.expect("card");
        assert_eq!(card.dapp.headline(), "app.uniswap.org");
        assert_eq!(card.secs_left, 290);
        assert!(card.plan.is_none(), "the coordinator fills the plan");
    }

    #[test]
    fn snapshot_rows_and_countdowns() {
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        book.on_request(&req(&t, 1, Some(NOW + 600)), NOW, Ok(personal()), NOW);
        queue(&mut book, &t, 2);
        to_signing(&mut book, &key(&t, 2), 4);
        let snap = book.snapshot(NOW + 100);
        assert_eq!(snap.sessions.len(), 1);
        assert_eq!(snap.sessions[0].pending, 2);
        let row = &snap.queue[0];
        assert_eq!(
            (
                row.ordinal,
                row.dapp_host.as_str(),
                row.label,
                row.age_secs,
                row.secs_left
            ),
            (1, "app.uniswap.org", "Sign message", 100, Some(500))
        );
        assert_eq!(
            snap.queue[1].secs_left, None,
            "Kao never times out a signing request"
        );
    }

    #[test]
    fn teardown_effects_order() {
        let mut book = WcBook::new();
        let a = bound(&mut book, 1, eoa());
        let b = bound(&mut book, 2, safe());
        for id in 1..=3 {
            queue(&mut book, &a, id);
        }
        assert!(book.mark_in_review(&key(&a, 2), 1));
        to_signing(&mut book, &key(&a, 3), 2);
        book.expect_pairing(pairing(9), NOW, None);
        book.on_proposal(proposal(77, pairing(9), NOW + 300), NOW);
        let fx = book.teardown();

        let first_disconnect = fx
            .net
            .iter()
            .position(|e| matches!(e, NetEffect::Disconnect { .. }))
            .expect("disconnects");
        assert!(fx.net[..first_disconnect].iter().all(|e| matches!(
            e,
            NetEffect::Respond { .. } | NetEffect::RejectProposal { .. }
        )));
        assert!(
            fx.net[first_disconnect..]
                .iter()
                .all(|e| matches!(e, NetEffect::Disconnect { .. }))
        );
        let answered: Vec<(WcKey, i64)> = responds(&fx)
            .into_iter()
            .map(|(k, a)| (k, a.err().map_or(0, |e| e.code)))
            .collect();
        assert_eq!(answered, vec![(key(&a, 1), 4900), (key(&a, 2), 4900)]);
        assert!(fx.net.contains(&NetEffect::RejectProposal {
            id: 77,
            error: SdkError::UserRejected.error()
        }));
        let disconnected: BTreeSet<Topic> = fx
            .net
            .iter()
            .filter_map(|e| match e {
                NetEffect::Disconnect { topic } => Some(topic.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(disconnected, BTreeSet::from([a.clone(), b]));
        assert!(fx.ui.contains(&UiEffect::RequestGone {
            key: key(&a, 2),
            reason: GoneReason::Teardown
        }));
        assert_eq!(
            book.request(&key(&a, 3)).and_then(|q| q.gone),
            Some(GoneReason::Teardown)
        );
        assert_eq!(book.relay(), RelayStatus::Closed);
        assert!(book.sessions().is_empty() && book.proposal().is_none());
    }

    #[test]
    fn notices_ring_is_bounded() {
        let mut book = WcBook::new();
        for i in 0..(MAX_NOTICES as u64 + 5) {
            book.push_notice(format!("n{i}"), false, NOW + i);
        }
        let notices = book.snapshot(NOW).notices;
        assert_eq!(notices.len(), MAX_NOTICES);
        assert_eq!(notices[0].text, "n5");
    }

    #[test]
    fn answered_memory_is_bounded() {
        let mut set = AnsweredSet::default();
        for id in 0..(ANSWERED_MEMORY as u64 + 10) {
            set.insert(key(&topic(1), id));
        }
        assert_eq!(set.keys.len(), ANSWERED_MEMORY);
        assert!(!set.contains(&key(&topic(1), 0)));
        assert!(set.contains(&key(&topic(1), ANSWERED_MEMORY as u64 + 9)));
    }

    #[test]
    fn switch_chain_emits_chain_changed_only_when_granted() {
        let switch = |chain_id| Admitted {
            chain_id: 1,
            call: WcCall::SwitchChain { chain_id },
            summary: "Switch network".into(),
        };
        let mut book = WcBook::new();
        let t = bound(&mut book, 1, eoa());
        let fx = book.on_request(&req(&t, 1, None), NOW, Ok(switch(8453)), NOW);
        assert_eq!(responds(&fx), vec![(key(&t, 1), Ok(Value::Null))]);
        assert!(fx.net.contains(&NetEffect::Emit {
            topic: t.clone(),
            chain_id: 8453,
            name: "chainChanged",
            data: json!(8453)
        }));
        // Not granted → no event; a chain outside the session → 4902, no event.
        let p = proposal(5, pairing(5), NOW + 300);
        book.bind_session(&session(topic(5), pairing(5)), &ticket(&p, eoa(), &[]), NOW);
        let fx = book.on_request(&req(&topic(5), 1, None), NOW, Ok(switch(8453)), NOW);
        assert!(!fx.net.iter().any(|e| matches!(e, NetEffect::Emit { .. })));
        let fx = book.on_request(&req(&t, 2, None), NOW, Ok(switch(10)), NOW);
        assert_eq!(error_code(&fx), Some(codes::UNRECOGNIZED_CHAIN));
        assert!(!fx.net.iter().any(|e| matches!(e, NetEffect::Emit { .. })));
    }
}
