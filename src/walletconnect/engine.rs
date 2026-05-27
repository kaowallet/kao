// Phase 2 scaffolding — the App-level integration that consumes
// `WcEngineHandle` / `event_rx` lands in Phase 5 (persistence + restore)
// and Phase 6 (UI). Items in this module are designed to be used by Iced
// from `src/app/mod.rs`, hence the public surface that Phase 2 doesn't
// itself reference.
#![allow(dead_code)]

//! WalletConnect Sign v2 engine.
//!
//! The engine owns the relay transport and all session state, talks to the
//! UI through two `mpsc` channels (commands in, events out), and runs an
//! async select-loop in a background `tokio` task.
//!
//! Concurrency model
//! -----------------
//! A single task drives both the inbound stream and the command channel via
//! `tokio::select!`. Command handlers are async — `ApproveProposal` makes
//! one subscribe + two publish round-trips against the relay before
//! returning — which means inbound messages briefly queue while a command
//! is in flight. That's acceptable for v1: relay RTTs are ~50ms, and the
//! inbound channel is unbounded so nothing is dropped. Sharded
//! per-session tasks would be premature here.
//!
//! Pairing handshake (the only place this gets gnarly)
//! ---------------------------------------------------
//!
//! ```text
//!  user pastes wc: URI
//!     │
//!     ▼
//!  cmd PairWithUri
//!     │  parse URI, store Pairing, subscribe(pairing_topic)
//!     ▼
//!  event Paired
//!
//!  (dApp publishes wc_sessionPropose on pairing topic)
//!     │
//!     ▼
//!  inbound on pairing_topic
//!     │  decrypt under pairing symKey, parse SessionProposeParams
//!     │  generate wallet ephemeral keypair, ECDH+HKDF → session symKey
//!     │  derive session_topic = sha256(session_sym_key)
//!     ▼
//!  event ProposalReceived
//!     │
//!     │  user approves (UI shows modal, decides namespaces+accounts)
//!     ▼
//!  cmd ApproveProposal
//!     │  subscribe(session_topic) ── must complete before next publish
//!     │  publish wc_sessionPropose-response on pairing topic
//!     │  publish wc_sessionSettle-request on session topic
//!     ▼
//!  event SessionSettled
//! ```
//!
//! The subscribe-before-publish ordering on `session_topic` is load-bearing:
//! if we publish `wc_sessionSettle` before the relay acks our subscribe,
//! the dApp's immediate `wc_sessionSettle` response can arrive *before* our
//! subscription is registered and be dropped silently.

use std::collections::{BTreeMap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::json;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::walletconnect::crypto::{
    EphemeralKeypair, PublicKey, SymKey, Topic, decode_envelope_type0, derive_session_key,
    derive_topic, encode_envelope_type0, envelope_from_b64, envelope_to_b64,
};
use crate::walletconnect::protocol::{
    Controller, DEFAULT_SESSION_LIFETIME, ERROR_INVALID_PARAMS, ERROR_UNAUTHORIZED_CHAIN,
    ERROR_UNAUTHORIZED_METHOD, ERROR_USER_REJECTED, JsonRpcError, JsonRpcRequest, JsonRpcResponse,
    JsonRpcResult, JsonRpcVersion, NamespaceProposal, NamespaceSettled, PeerMetadata, RelayInfo,
    SessionDeleteParams, SessionProposeParams, SessionProposeResult, SessionRequestParams,
    SessionSettleParams, TAG_SESSION_PROPOSE_RES, TAG_SESSION_REQUEST_RES, TAG_SESSION_SETTLE_REQ,
    TTL_SESSION_PROPOSE, TTL_SESSION_REQUEST, TTL_SESSION_SETTLE,
};
use crate::walletconnect::session::{Pairing, PendingProposal, PendingRequest, Session};
use crate::walletconnect::transport::{
    InboundMessage, PublishMessage, RelayTransport, TransportError, TransportEvent,
};
use crate::walletconnect::uri;

// ── Public API surface ───────────────────────────────────────────────────

/// Handle returned by [`spawn`]. The UI layer holds one of these and sends
/// commands; it does not (and cannot) directly inspect engine state. All
/// state-altering paths go through commands so the engine remains the
/// single owner of the session map.
#[derive(Debug, Clone)]
pub struct WcEngineHandle {
    cmd_tx: mpsc::UnboundedSender<WcCommand>,
}

impl WcEngineHandle {
    /// Send a command. Returns `Err(())` only if the engine task has shut
    /// down, in which case the UI should surface "WalletConnect disconnected"
    /// and stop offering pairing. The failed command is dropped — there's
    /// nothing useful the caller can do with it once the engine is gone, and
    /// returning it would leak the command's 176-byte `ApproveProposal`
    /// variant up the call stack via every `send()` result.
    pub fn send(&self, cmd: WcCommand) -> Result<(), ()> {
        self.cmd_tx.send(cmd).map_err(|_| ())
    }
}

/// Commands flow UI → engine. Each variant carries either the data needed
/// to start a flow (URI for pairing) or the user's decision on a previously
/// emitted event (proposal/request approval).
#[derive(Debug)]
pub enum WcCommand {
    /// User pasted a `wc:` URI. The engine parses, subscribes to the pairing
    /// topic, and replies with `Paired` (success) or `Error` (parse failure
    /// or relay rejection).
    PairWithUri { uri: String },
    /// User approved a `ProposalReceived`. `namespaces` is the concrete
    /// settled form: which chains, methods, events, and CAIP-10 accounts the
    /// wallet is willing to expose for this session.
    ApproveProposal {
        proposal_id: u64,
        namespaces: BTreeMap<String, NamespaceSettled>,
        wallet_metadata: PeerMetadata,
    },
    /// User rejected a `ProposalReceived`. Engine publishes a JSON-RPC error
    /// response on the pairing topic and discards the pending proposal.
    RejectProposal { proposal_id: u64, reason: String },
    /// User approved a `RequestReceived`. `result` is the raw JSON-RPC
    /// result value (signature hex string, tx hash, etc.) the engine will
    /// publish on the session topic.
    ApproveRequest {
        request_id: u64,
        result: serde_json::Value,
    },
    /// User rejected a `RequestReceived`. Engine publishes a JSON-RPC error
    /// response on the session topic. Default error mirrors EIP-1193 `4001`
    /// when the caller doesn't supply one — same semantics as MetaMask's
    /// "User denied transaction signature" path.
    RejectRequest {
        request_id: u64,
        error: Option<JsonRpcError>,
    },
    /// Terminate a session. Engine publishes `wc_sessionDelete` on the
    /// session topic, unsubscribes, and emits `SessionDeleted`.
    Disconnect { topic: Topic, reason: String },
}

/// Events flow engine → UI.
#[derive(Debug, Clone)]
pub enum WcEvent {
    /// Pairing subscription acknowledged. UI can now show "waiting for
    /// dApp…" — the dApp will publish the proposal shortly.
    Paired { pairing_topic: Topic },
    /// dApp's `wc_sessionPropose` arrived. UI shows the approval modal.
    ProposalReceived {
        proposal_id: u64,
        peer: PeerMetadata,
        required_namespaces: BTreeMap<String, NamespaceProposal>,
        optional_namespaces: BTreeMap<String, NamespaceProposal>,
    },
    /// Session is live. UI updates the "Connected dApps" list.
    SessionSettled {
        topic: Topic,
        peer: PeerMetadata,
        namespaces: BTreeMap<String, NamespaceSettled>,
        expiry: u64,
    },
    /// dApp sent a `wc_sessionRequest`. UI dispatches per-method modals
    /// (personal_sign, eth_sendTransaction, …).
    RequestReceived {
        request_id: u64,
        session_topic: Topic,
        peer: PeerMetadata,
        chain_id: String,
        method: String,
        params: serde_json::Value,
    },
    /// Session terminated, either by dApp or by local `Disconnect`.
    SessionDeleted { topic: Topic, reason: String },
    /// Non-fatal engine error. `context` names the flow it came from so the
    /// UI can either log it (background) or surface it (foreground action).
    Error { context: String, message: String },
}

/// Spawn the engine on the current tokio runtime. Returns a handle for
/// sending commands and a receiver for engine events.
///
/// Construction takes the transport plus the inbound stream that the
/// transport's adapter exposed at connect time. The split exists because
/// reown-rust's `Client::new` requires the inbound handler to be supplied
/// at construction; the adapter writes inbound messages into the channel,
/// the engine reads them here.
///
/// `initial_sessions` seeds the runtime session map from persisted state at
/// startup. The engine subscribes to every restored topic in one
/// `batch_subscribe` call before entering its select loop — the relay
/// replays any buffered `wc_sessionRequest` / `wc_sessionDelete` messages
/// within their per-tag TTL once we're subscribed. Pass an empty vec for a
/// fresh session.
pub fn spawn(
    transport: Box<dyn RelayTransport>,
    inbound_rx: mpsc::UnboundedReceiver<InboundMessage>,
    transport_events_rx: mpsc::UnboundedReceiver<TransportEvent>,
    initial_sessions: Vec<crate::walletconnect::session::PersistedSession>,
) -> (WcEngineHandle, mpsc::UnboundedReceiver<WcEvent>) {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (event_tx, event_rx) = mpsc::unbounded_channel();

    let runner = WcEngineRunner::new(
        transport,
        inbound_rx,
        transport_events_rx,
        cmd_rx,
        event_tx,
        initial_sessions,
    );
    tokio::spawn(runner.run());

    (WcEngineHandle { cmd_tx }, event_rx)
}

// ── Engine runner (state) ────────────────────────────────────────────────

pub(super) struct WcEngineRunner {
    transport: Box<dyn RelayTransport>,
    inbound_rx: mpsc::UnboundedReceiver<InboundMessage>,
    /// Out-of-band transport lifecycle stream — fires on relay
    /// disconnect/reconnect. The relay drops every subscription on
    /// disconnect, so we re-`batch_subscribe` every known topic when
    /// `Reconnected` arrives.
    transport_events_rx: mpsc::UnboundedReceiver<TransportEvent>,
    cmd_rx: mpsc::UnboundedReceiver<WcCommand>,
    event_tx: mpsc::UnboundedSender<WcEvent>,

    pairings: HashMap<Topic, Pairing>,
    /// `proposal_id` → pending proposal. We dual-index by pairing topic
    /// (below) so inbound dispatch can find the pairing fast.
    pending_proposals: HashMap<u64, PendingProposal>,
    /// `pairing_topic` → `proposal_id`. After the first proposal arrives on
    /// a pairing we ignore subsequent proposals on the same topic — pairings
    /// are single-use per spec.
    proposal_by_pairing: HashMap<Topic, u64>,
    sessions: HashMap<Topic, Session>,
    pending_requests: HashMap<u64, PendingRequest>,

    next_proposal_id: u64,
    next_request_id: u64,
    next_jsonrpc_id: u64,

    /// Topics to `batch_subscribe` once before the run loop starts. Populated
    /// from `initial_sessions` in `new()`; drained on the first tick of
    /// `run()`. After draining the engine is in steady-state and this is
    /// always empty.
    pending_initial_subscribe: Vec<Topic>,
}

impl WcEngineRunner {
    fn new(
        transport: Box<dyn RelayTransport>,
        inbound_rx: mpsc::UnboundedReceiver<InboundMessage>,
        transport_events_rx: mpsc::UnboundedReceiver<TransportEvent>,
        cmd_rx: mpsc::UnboundedReceiver<WcCommand>,
        event_tx: mpsc::UnboundedSender<WcEvent>,
        initial_sessions: Vec<crate::walletconnect::session::PersistedSession>,
    ) -> Self {
        let mut sessions = HashMap::new();
        let mut pending_initial_subscribe = Vec::with_capacity(initial_sessions.len());
        for persisted in initial_sessions {
            let session = persisted.hydrate();
            pending_initial_subscribe.push(session.topic);
            sessions.insert(session.topic, session);
        }
        Self {
            transport,
            inbound_rx,
            transport_events_rx,
            cmd_rx,
            event_tx,
            pairings: HashMap::new(),
            pending_proposals: HashMap::new(),
            proposal_by_pairing: HashMap::new(),
            sessions,
            pending_requests: HashMap::new(),
            next_proposal_id: 1,
            next_request_id: 1,
            next_jsonrpc_id: fresh_jsonrpc_id_seed(),
            pending_initial_subscribe,
        }
    }

    async fn run(mut self) {
        self.restore_initial_sessions().await;
        loop {
            tokio::select! {
                Some(cmd) = self.cmd_rx.recv() => {
                    self.handle_command(cmd).await;
                }
                Some(msg) = self.inbound_rx.recv() => {
                    self.handle_inbound(msg).await;
                }
                Some(ev) = self.transport_events_rx.recv() => {
                    self.handle_transport_event(ev).await;
                }
                else => {
                    debug!("WcEngine: all channels closed, shutting down");
                    break;
                }
            }
        }
    }

    /// React to relay lifecycle events from the transport. On `Reconnected`
    /// we re-batch_subscribe to every pairing + session topic we hold —
    /// the relay drops subscription state on disconnect, so without this
    /// the wallet would go permanently mute for live sessions after the
    /// first hour-long relay rotation. `Disconnected` is currently
    /// information-only (logged + surfaced as an Error event); the
    /// reconnect backoff lives inside the transport.
    pub(super) async fn handle_transport_event(&mut self, ev: TransportEvent) {
        match ev {
            TransportEvent::Disconnected { reason } => {
                tracing::warn!(%reason, "WalletConnect transport disconnected, awaiting reconnect");
                self.emit_error("transport", format!("relay disconnected: {reason}"));
            }
            TransportEvent::Reconnected => {
                let topics: Vec<Topic> = self
                    .pairings
                    .keys()
                    .copied()
                    .chain(self.sessions.keys().copied())
                    .collect();
                if topics.is_empty() {
                    tracing::info!("WalletConnect transport reconnected, no topics to restore");
                    return;
                }
                tracing::info!(
                    count = topics.len(),
                    "WalletConnect transport reconnected, re-subscribing to known topics",
                );
                if let Err(e) = self.transport.batch_subscribe(&topics).await {
                    self.emit_error(
                        "transport",
                        format!("post-reconnect batch_subscribe failed: {e}"),
                    );
                }
            }
        }
    }

    /// Subscribe to every persisted session topic in one round trip before
    /// entering the steady-state select loop. The relay buffers messages
    /// for the per-tag TTL (5 minutes for sessionRequest, 30 days for
    /// sessionDelete) and replays them on subscription-ack — anything
    /// queued while the wallet was offline surfaces as normal inbound
    /// messages on the next iteration.
    ///
    /// On a `batch_subscribe` failure we emit an Error event but keep
    /// running; individual sessions will retry on first inbound activity.
    /// Hard-failing here would mean the user has to relaunch to recover
    /// from a transient relay hiccup.
    pub(super) async fn restore_initial_sessions(&mut self) {
        if self.pending_initial_subscribe.is_empty() {
            return;
        }
        let topics = std::mem::take(&mut self.pending_initial_subscribe);
        tracing::info!(
            count = topics.len(),
            "WcEngine: restoring persisted sessions, batch-subscribing",
        );
        if let Err(e) = self.transport.batch_subscribe(&topics).await {
            self.emit_error("restore", format!("batch_subscribe: {e}"));
        }
    }

    // ── Command dispatch ─────────────────────────────────────────────

    pub(super) async fn handle_command(&mut self, cmd: WcCommand) {
        match cmd {
            WcCommand::PairWithUri { uri } => self.cmd_pair(uri).await,
            WcCommand::ApproveProposal {
                proposal_id,
                namespaces,
                wallet_metadata,
            } => {
                self.cmd_approve_proposal(proposal_id, namespaces, wallet_metadata)
                    .await
            }
            WcCommand::RejectProposal {
                proposal_id,
                reason,
            } => self.cmd_reject_proposal(proposal_id, reason).await,
            WcCommand::ApproveRequest { request_id, result } => {
                self.cmd_approve_request(request_id, result).await
            }
            WcCommand::RejectRequest { request_id, error } => {
                self.cmd_reject_request(request_id, error).await
            }
            WcCommand::Disconnect { topic, reason } => self.cmd_disconnect(topic, reason).await,
        }
    }

    async fn cmd_pair(&mut self, uri: String) {
        let invitation = match uri::parse(&uri) {
            Ok(inv) => inv,
            Err(e) => {
                self.emit_error("pair", format!("invalid wc: URI — {e}"));
                return;
            }
        };

        // Subscribe BEFORE recording the pairing locally. If the relay
        // rejects the subscribe (auth failure, project-id banned, …) we'd
        // rather not have a half-state `pairings` entry referencing a
        // topic we don't actually receive on.
        if let Err(e) = self.transport.subscribe(invitation.topic).await {
            self.emit_error("pair", format!("relay subscribe failed: {e}"));
            return;
        }

        let pairing = Pairing {
            topic: invitation.topic,
            sym_key: invitation.sym_key,
            created_at: std::time::Instant::now(),
        };
        self.pairings.insert(invitation.topic, pairing);
        self.emit(WcEvent::Paired {
            pairing_topic: invitation.topic,
        });
    }

    async fn cmd_approve_proposal(
        &mut self,
        proposal_id: u64,
        namespaces: BTreeMap<String, NamespaceSettled>,
        wallet_metadata: PeerMetadata,
    ) {
        let pending = match self.pending_proposals.remove(&proposal_id) {
            Some(p) => p,
            None => {
                self.emit_error(
                    "approve_proposal",
                    format!("unknown proposal_id {proposal_id}"),
                );
                return;
            }
        };
        // Drop the pairing-topic → proposal_id index entry too.
        self.proposal_by_pairing.remove(&pending.pairing_topic);

        // Subscribe to the session topic BEFORE publishing the settle —
        // see module docs for the race this guards against.
        if let Err(e) = self.transport.subscribe(pending.session_topic).await {
            self.emit_error("approve_proposal", format!("session subscribe failed: {e}"));
            // Best-effort cleanup: try to tell the dApp we couldn't approve.
            // Use the standard "internal error" code so the dApp can decide
            // to retry vs. abandon.
            self.publish_proposal_error_response(&pending, "session subscribe failed")
                .await;
            return;
        }

        // Clone the pairing symKey out before any &mut self call.
        let pairing_sym_key = match self.pairings.get(&pending.pairing_topic) {
            Some(p) => p.sym_key.clone(),
            None => {
                // Should be unreachable: pending proposals are only created
                // off of an inbound message on a known pairing topic.
                self.emit_error("approve_proposal", "pairing missing".into());
                return;
            }
        };

        // 1) Publish wc_sessionPropose response on pairing topic.
        let response_payload = JsonRpcResponse {
            id: pending.jsonrpc_id,
            jsonrpc: JsonRpcVersion,
            payload: JsonRpcResult::Success {
                result: serde_json::to_value(SessionProposeResult {
                    relay: RelayInfo {
                        protocol: pending.relay_protocol.clone(),
                        data: None,
                    },
                    responder_public_key: pending.wallet_public_key.to_hex(),
                })
                .expect("static result struct cannot fail to serialise"),
            },
        };
        if let Err(e) = self
            .publish_encrypted(
                pending.pairing_topic,
                &pairing_sym_key,
                &response_payload,
                TAG_SESSION_PROPOSE_RES,
                TTL_SESSION_PROPOSE,
                false,
            )
            .await
        {
            self.emit_error("approve_proposal", format!("publish propose-response: {e}"));
            return;
        }

        // 2) Publish wc_sessionSettle request on session topic.
        let expiry = unix_seconds_from_now(DEFAULT_SESSION_LIFETIME);
        let settle = JsonRpcRequest {
            id: self.next_jsonrpc_id(),
            jsonrpc: JsonRpcVersion,
            method: "wc_sessionSettle".to_string(),
            params: serde_json::to_value(SessionSettleParams {
                relay: RelayInfo {
                    protocol: pending.relay_protocol.clone(),
                    data: None,
                },
                controller: Controller {
                    public_key: pending.wallet_public_key.to_hex(),
                    metadata: wallet_metadata.clone(),
                },
                namespaces: namespaces.clone(),
                session_properties: None,
                expiry,
            })
            .expect("settle params"),
        };
        if let Err(e) = self
            .publish_encrypted(
                pending.session_topic,
                &pending.session_sym_key,
                &settle,
                TAG_SESSION_SETTLE_REQ,
                TTL_SESSION_SETTLE,
                false,
            )
            .await
        {
            self.emit_error("approve_proposal", format!("publish settle: {e}"));
            return;
        }

        let session = Session {
            topic: pending.session_topic,
            sym_key: pending.session_sym_key,
            peer_metadata: pending.peer_metadata.clone(),
            namespaces: namespaces.clone(),
            expiry,
            relay_protocol: pending.relay_protocol.clone(),
        };
        self.sessions.insert(pending.session_topic, session);

        self.emit(WcEvent::SessionSettled {
            topic: pending.session_topic,
            peer: pending.peer_metadata.clone(),
            namespaces,
            expiry,
        });
    }

    async fn cmd_reject_proposal(&mut self, proposal_id: u64, reason: String) {
        let pending = match self.pending_proposals.remove(&proposal_id) {
            Some(p) => p,
            None => {
                self.emit_error(
                    "reject_proposal",
                    format!("unknown proposal_id {proposal_id}"),
                );
                return;
            }
        };
        self.proposal_by_pairing.remove(&pending.pairing_topic);
        let _ = self
            .publish_proposal_error_response(&pending, &reason)
            .await;
    }

    async fn cmd_approve_request(&mut self, request_id: u64, result: serde_json::Value) {
        let pending = match self.pending_requests.remove(&request_id) {
            Some(p) => p,
            None => {
                self.emit_error(
                    "approve_request",
                    format!("unknown request_id {request_id}"),
                );
                return;
            }
        };
        let session_sym = match self.sessions.get(&pending.session_topic) {
            Some(s) => s.sym_key.clone(),
            None => {
                self.emit_error("approve_request", "session vanished".into());
                return;
            }
        };
        let response = JsonRpcResponse {
            id: pending.jsonrpc_id,
            jsonrpc: JsonRpcVersion,
            payload: JsonRpcResult::Success { result },
        };
        if let Err(e) = self
            .publish_encrypted(
                pending.session_topic,
                &session_sym,
                &response,
                TAG_SESSION_REQUEST_RES,
                TTL_SESSION_REQUEST,
                false,
            )
            .await
        {
            self.emit_error("approve_request", format!("publish: {e}"));
        }
    }

    async fn cmd_reject_request(&mut self, request_id: u64, error: Option<JsonRpcError>) {
        let pending = match self.pending_requests.remove(&request_id) {
            Some(p) => p,
            None => {
                self.emit_error("reject_request", format!("unknown request_id {request_id}"));
                return;
            }
        };
        let session_sym = match self.sessions.get(&pending.session_topic) {
            Some(s) => s.sym_key.clone(),
            None => {
                self.emit_error("reject_request", "session vanished".into());
                return;
            }
        };
        let error = error.unwrap_or(JsonRpcError {
            code: ERROR_USER_REJECTED,
            message: "User rejected".to_string(),
            data: None,
        });
        let response = JsonRpcResponse {
            id: pending.jsonrpc_id,
            jsonrpc: JsonRpcVersion,
            payload: JsonRpcResult::Error { error },
        };
        if let Err(e) = self
            .publish_encrypted(
                pending.session_topic,
                &session_sym,
                &response,
                TAG_SESSION_REQUEST_RES,
                TTL_SESSION_REQUEST,
                false,
            )
            .await
        {
            self.emit_error("reject_request", format!("publish: {e}"));
        }
    }

    async fn cmd_disconnect(&mut self, topic: Topic, reason: String) {
        let session = match self.sessions.remove(&topic) {
            Some(s) => s,
            None => {
                self.emit_error("disconnect", "unknown session".into());
                return;
            }
        };
        let delete = JsonRpcRequest {
            id: self.next_jsonrpc_id(),
            jsonrpc: JsonRpcVersion,
            method: "wc_sessionDelete".to_string(),
            params: serde_json::to_value(SessionDeleteParams {
                code: 6000,
                message: reason.clone(),
            })
            .expect("delete params"),
        };
        let _ = self
            .publish_encrypted(
                topic,
                &session.sym_key,
                &delete,
                crate::walletconnect::protocol::TAG_SESSION_DELETE_REQ,
                crate::walletconnect::protocol::TTL_SESSION_DELETE,
                false,
            )
            .await;
        let _ = self.transport.unsubscribe(topic).await;
        self.emit(WcEvent::SessionDeleted { topic, reason });
    }

    // ── Inbound dispatch ─────────────────────────────────────────────

    pub(super) async fn handle_inbound(&mut self, msg: InboundMessage) {
        // Decide which symKey to decrypt under: is this a pairing topic
        // (proposal awaited) or a session topic (request/delete/etc)?
        if let Some(pairing_topic) = self.pairings.keys().find(|t| **t == msg.topic).copied() {
            self.handle_pairing_inbound(pairing_topic, msg).await;
        } else if self.sessions.contains_key(&msg.topic) {
            self.handle_session_inbound(msg).await;
        } else {
            debug!(
                topic = %msg.topic,
                tag = msg.tag,
                "WcEngine: inbound message on unknown topic, ignoring"
            );
        }
    }

    async fn handle_pairing_inbound(&mut self, pairing_topic: Topic, msg: InboundMessage) {
        // Lookup pairing — cloned out of the map to avoid holding a borrow
        // across the &mut self emits below.
        let pairing_sym_key = match self.pairings.get(&pairing_topic) {
            Some(p) => p.sym_key.clone(),
            None => return,
        };

        let plaintext = match decrypt_envelope(&pairing_sym_key, &msg.message_b64) {
            Ok(pt) => pt,
            Err(e) => {
                warn!(topic = %pairing_topic, error = %e, "pairing decrypt failed");
                return;
            }
        };

        let request: JsonRpcRequest = match serde_json::from_slice(&plaintext) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "pairing payload is not a JSON-RPC request");
                return;
            }
        };

        if request.method != "wc_sessionPropose" {
            // Pairings receive exactly one method (sessionPropose). Anything
            // else is either spec-newer (forward-compat: log + ignore) or
            // misbehaving.
            debug!(method = %request.method, "unexpected method on pairing topic");
            return;
        }

        // Reject duplicate proposals on the same pairing — pairings are
        // single-use per spec, and a second propose suggests either a
        // confused dApp or a malicious replay.
        if self.proposal_by_pairing.contains_key(&pairing_topic) {
            warn!(topic = %pairing_topic, "duplicate wc_sessionPropose, ignoring");
            return;
        }

        let params: SessionProposeParams = match serde_json::from_value(request.params) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "wc_sessionPropose params malformed");
                return;
            }
        };

        let peer_pub = match PublicKey::from_hex(&params.proposer.public_key) {
            Ok(pk) => pk,
            Err(e) => {
                warn!(error = %e, "proposer.publicKey hex malformed");
                return;
            }
        };
        let wallet_kp = EphemeralKeypair::generate();
        let wallet_pub = *wallet_kp.public();
        let session_sym_key = match derive_session_key(wallet_kp, &peer_pub) {
            Ok(k) => k,
            Err(e) => {
                warn!(error = %e, "ECDH derivation failed");
                return;
            }
        };
        let session_topic = derive_topic(&session_sym_key);
        let relay_protocol = params
            .relays
            .first()
            .map(|r| r.protocol.clone())
            .unwrap_or_else(|| "irn".to_string());

        let proposal_id = self.next_proposal_id();
        let peer_metadata = params.proposer.metadata.clone();
        let required = params.required_namespaces.clone();
        let optional = params.optional_namespaces.clone();

        let pending = PendingProposal {
            proposal_id,
            pairing_topic,
            jsonrpc_id: request.id,
            peer_public_key: peer_pub,
            wallet_public_key: wallet_pub,
            session_sym_key,
            session_topic,
            peer_metadata: peer_metadata.clone(),
            required_namespaces: required.clone(),
            optional_namespaces: optional.clone(),
            relay_protocol,
        };
        self.pending_proposals.insert(proposal_id, pending);
        self.proposal_by_pairing.insert(pairing_topic, proposal_id);

        self.emit(WcEvent::ProposalReceived {
            proposal_id,
            peer: peer_metadata,
            required_namespaces: required,
            optional_namespaces: optional,
        });
    }

    async fn handle_session_inbound(&mut self, msg: InboundMessage) {
        let sym_key = match self.sessions.get(&msg.topic) {
            Some(s) => s.sym_key.clone(),
            None => return,
        };
        let plaintext = match decrypt_envelope(&sym_key, &msg.message_b64) {
            Ok(pt) => pt,
            Err(e) => {
                warn!(topic = %msg.topic, error = %e, "session decrypt failed");
                return;
            }
        };

        // Parse as Value first so we can route on `method`/`result` without
        // committing to a request vs. response structure. This handles both
        // inbound requests (sessionRequest, sessionDelete, sessionPing) and
        // responses to our outbound requests (settle ack, delete ack).
        let value: serde_json::Value = match serde_json::from_slice(&plaintext) {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "session payload is not JSON");
                return;
            }
        };

        if value.get("method").is_some() {
            self.handle_session_request(msg.topic, value).await;
        } else {
            // It's a response — match on id, fulfil pending awaiters.
            // Phase 2 doesn't track outbound awaiters (we don't await
            // sessionSettle's response), so just log it.
            debug!(topic = %msg.topic, "received session response (no awaiter)");
        }
    }

    async fn handle_session_request(&mut self, topic: Topic, value: serde_json::Value) {
        let req: JsonRpcRequest = match serde_json::from_value(value) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "session request malformed");
                return;
            }
        };

        match req.method.as_str() {
            "wc_sessionRequest" => {
                let params: SessionRequestParams = match serde_json::from_value(req.params) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!(error = %e, "wc_sessionRequest params malformed");
                        return;
                    }
                };

                // Reject inner-expiry-past requests immediately. The relay
                // can buffer requests for up to 5 minutes; a request that
                // expired in transit must not be presented to the user
                // (the dApp's UI will have given up by now).
                if let Some(expiry) = params.request.expiry {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    if now >= expiry {
                        debug!(method = %params.request.method, "wc_sessionRequest already expired");
                        return;
                    }
                }

                // Phase 7 hardening: chain + method authorization gate.
                //
                // The dApp can only ask the wallet for things the session
                // explicitly approved at `wc_sessionSettle`. Anything else —
                // a chain id we don't have an account for, or a method the
                // user never opted in to — must be refused at the engine
                // boundary, not at the per-method dispatcher. Reasons:
                //   1. The UI shouldn't even render a modal for an
                //      out-of-scope method/chain — clicking "approve" on a
                //      thing we'll then refuse looks broken.
                //   2. Two scope-violation surfaces (engine + dispatcher)
                //      mean the user-rejection error path could diverge;
                //      keeping the gate here ensures spec-compliant
                //      `ERROR_UNAUTHORIZED_CHAIN` / `ERROR_UNAUTHORIZED_METHOD`
                //      codes regardless of how methods.rs evolves.
                //   3. Defence-in-depth against a sessionSettle drift bug
                //      that would let the dApp request `wallet_*` methods
                //      we never published in our namespace methods list.
                if let Some(err) =
                    self.check_session_scope(topic, &params.chain_id, &params.request.method)
                {
                    let session_sym = self.sessions.get(&topic).map(|s| s.sym_key.clone());
                    if let Some(sym) = session_sym {
                        let response = JsonRpcResponse {
                            id: req.id,
                            jsonrpc: JsonRpcVersion,
                            payload: JsonRpcResult::Error { error: err },
                        };
                        let _ = self
                            .publish_encrypted(
                                topic,
                                &sym,
                                &response,
                                TAG_SESSION_REQUEST_RES,
                                TTL_SESSION_REQUEST,
                                false,
                            )
                            .await;
                    }
                    return;
                }

                // Per-account scope: the request's `from` (if any) must be a
                // CAIP-10 account the session was settled with. Catches the
                // dApp asking us to sign as account A on a session that
                // only approved account B — the method dispatcher checks
                // the same invariant against the *active* signer, this
                // check enforces it against the *session's* approved set
                // before the user ever sees the modal.
                if let Some(err) = self.check_request_account_scope(
                    topic,
                    &params.chain_id,
                    &params.request.method,
                    &params.request.params,
                ) {
                    let session_sym = self.sessions.get(&topic).map(|s| s.sym_key.clone());
                    if let Some(sym) = session_sym {
                        let response = JsonRpcResponse {
                            id: req.id,
                            jsonrpc: JsonRpcVersion,
                            payload: JsonRpcResult::Error { error: err },
                        };
                        let _ = self
                            .publish_encrypted(
                                topic,
                                &sym,
                                &response,
                                TAG_SESSION_REQUEST_RES,
                                TTL_SESSION_REQUEST,
                                false,
                            )
                            .await;
                    }
                    return;
                }

                let request_id = self.next_request_id();
                let peer = self
                    .sessions
                    .get(&topic)
                    .map(|s| s.peer_metadata.clone())
                    .unwrap_or_else(|| PeerMetadata {
                        name: String::new(),
                        description: String::new(),
                        url: String::new(),
                        icons: vec![],
                        redirect: None,
                    });
                let chain_id = params.chain_id.clone();
                let method = params.request.method.clone();
                let inner_params = params.request.params.clone();

                self.pending_requests.insert(
                    request_id,
                    PendingRequest {
                        request_id,
                        session_topic: topic,
                        jsonrpc_id: req.id,
                        chain_id: chain_id.clone(),
                        method: method.clone(),
                        params: inner_params.clone(),
                        expiry: params.request.expiry,
                        received_at: std::time::Instant::now(),
                    },
                );

                self.emit(WcEvent::RequestReceived {
                    request_id,
                    session_topic: topic,
                    peer,
                    chain_id,
                    method,
                    params: inner_params,
                });
            }
            "wc_sessionDelete" => {
                let params: SessionDeleteParams =
                    serde_json::from_value(req.params).unwrap_or(SessionDeleteParams {
                        code: 0,
                        message: String::new(),
                    });
                self.sessions.remove(&topic);
                let _ = self.transport.unsubscribe(topic).await;
                self.emit(WcEvent::SessionDeleted {
                    topic,
                    reason: params.message,
                });
            }
            "wc_sessionPing" => {
                // Cheap to ack: empty result, same id, on session topic.
                let session_sym = match self.sessions.get(&topic) {
                    Some(s) => s.sym_key.clone(),
                    None => return,
                };
                let response = JsonRpcResponse {
                    id: req.id,
                    jsonrpc: JsonRpcVersion,
                    payload: JsonRpcResult::Success {
                        result: json!(true),
                    },
                };
                let _ = self
                    .publish_encrypted(
                        topic,
                        &session_sym,
                        &response,
                        crate::walletconnect::protocol::TAG_SESSION_PING_RES,
                        crate::walletconnect::protocol::TTL_SESSION_PING,
                        false,
                    )
                    .await;
            }
            other => {
                // Spec-newer method — respond invalid-method so the dApp
                // doesn't hang waiting. Use the request's `id`.
                let session_sym = match self.sessions.get(&topic) {
                    Some(s) => s.sym_key.clone(),
                    None => return,
                };
                let response = JsonRpcResponse {
                    id: req.id,
                    jsonrpc: JsonRpcVersion,
                    payload: JsonRpcResult::Error {
                        error: JsonRpcError {
                            code: ERROR_INVALID_PARAMS,
                            message: format!("unsupported method: {other}"),
                            data: None,
                        },
                    },
                };
                let _ = self
                    .publish_encrypted(
                        topic,
                        &session_sym,
                        &response,
                        TAG_SESSION_REQUEST_RES,
                        TTL_SESSION_REQUEST,
                        false,
                    )
                    .await;
            }
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────

    /// Verify a `wc_sessionRequest`'s chain id and method against the
    /// session's approved namespaces. Returns `None` if the request is in
    /// scope; returns the [`JsonRpcError`] the dApp should see if not.
    ///
    /// Lookup keys:
    ///   - `chain_id` is CAIP-2 (`eip155:N`); the namespace key is the
    ///     part before `:` (`eip155`).
    ///   - The chain must appear in `namespace.chains`.
    ///   - The method must appear in `namespace.methods`.
    ///
    /// Missing session is treated as "method unauthorized" — by the time
    /// this runs we've already decrypted under the session's symKey, so
    /// session-missing-from-map is a logic error; emit a safe error code
    /// rather than panicking.
    fn check_session_scope(
        &self,
        topic: Topic,
        chain_id: &str,
        method: &str,
    ) -> Option<JsonRpcError> {
        let session = self.sessions.get(&topic)?;
        let ns_key = chain_id.split(':').next().unwrap_or("");
        let namespace = match session.namespaces.get(ns_key) {
            Some(ns) => ns,
            None => {
                return Some(JsonRpcError {
                    code: ERROR_UNAUTHORIZED_CHAIN,
                    message: format!("session has no namespace for {ns_key}"),
                    data: None,
                });
            }
        };
        if !namespace.chains.iter().any(|c| c == chain_id) {
            return Some(JsonRpcError {
                code: ERROR_UNAUTHORIZED_CHAIN,
                message: format!("chain {chain_id} not in approved scope"),
                data: None,
            });
        }
        if !namespace.methods.iter().any(|m| m == method) {
            return Some(JsonRpcError {
                code: ERROR_UNAUTHORIZED_METHOD,
                message: format!("method {method} not in approved scope"),
                data: None,
            });
        }
        None
    }

    /// Verify the request's `from` address (when the method carries one) is
    /// one of the CAIP-10 accounts settled in this session's namespace.
    ///
    /// Returns `None` when:
    ///   - the method doesn't carry an address (`wc_sessionPing`, etc.),
    ///   - the params can't be parsed to extract one (defer to the method
    ///     dispatcher's `ERROR_INVALID_PARAMS`),
    ///   - the session/namespace is missing (caller's earlier scope check
    ///     already failed and we never reach here in practice).
    ///
    /// Returns `Some(ERROR_UNAUTHORIZED_METHOD)` when an address was extracted
    /// but doesn't match any settled account. The dApp gets a clear refusal
    /// before the user is shown a modal — closing the confused-deputy gap
    /// where a session for account A could elicit a signature from account B
    /// (e.g. after the user switched the active account mid-session).
    fn check_request_account_scope(
        &self,
        topic: Topic,
        chain_id: &str,
        method: &str,
        params: &serde_json::Value,
    ) -> Option<JsonRpcError> {
        let requested = extract_request_from_address(method, params)?;
        let session = self.sessions.get(&topic)?;
        let ns_key = chain_id.split(':').next().unwrap_or("");
        let namespace = session.namespaces.get(ns_key)?;

        // CAIP-10: "<namespace>:<reference>:<address>". The wallet stamps
        // accounts lowercased via `{:#x}`; the dApp may send checksum-case.
        // Compare the trailing address segment as parsed `Address` so casing
        // is irrelevant.
        let approved = namespace
            .accounts
            .iter()
            .filter(|a| {
                // Restrict comparison to entries for this request's chain;
                // signing as A on mainnet doesn't license signing as A on
                // Optimism unless the session settled both explicitly.
                a.rsplit_once(':')
                    .map(|(prefix, _)| prefix == chain_id)
                    .unwrap_or(false)
            })
            .filter_map(|a| a.rsplit_once(':').and_then(|(_, addr)| addr.parse().ok()))
            .any(|a: alloy::primitives::Address| a == requested);

        if approved {
            None
        } else {
            Some(JsonRpcError {
                code: ERROR_UNAUTHORIZED_METHOD,
                message: format!(
                    "request from {requested:#x} is not a settled account on {chain_id}",
                ),
                data: None,
            })
        }
    }

    /// Drop pending session-requests older than the relay's
    /// `wc_sessionRequest` TTL (5 minutes). The dApp's UI has already given
    /// up by this point — surfacing the modal would let the user "approve"
    /// a request whose response can never reach the dApp.
    ///
    /// Returns the ids of pruned entries so callers can update UI state
    /// (close stale modals, hide queue badges) accordingly.
    pub(super) fn prune_stale_requests(&mut self) -> Vec<u64> {
        let now = std::time::Instant::now();
        let ttl = TTL_SESSION_REQUEST;
        let stale: Vec<u64> = self
            .pending_requests
            .iter()
            .filter_map(|(id, r)| {
                if now.duration_since(r.received_at) >= ttl {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();
        for id in &stale {
            self.pending_requests.remove(id);
        }
        if !stale.is_empty() {
            tracing::debug!(
                count = stale.len(),
                "WcEngine: pruned stale wc_sessionRequest entries past TTL",
            );
        }
        stale
    }

    async fn publish_proposal_error_response(&mut self, pending: &PendingProposal, reason: &str) {
        let pairing_sym = match self.pairings.get(&pending.pairing_topic) {
            Some(p) => p.sym_key.clone(),
            None => return,
        };
        let response = JsonRpcResponse {
            id: pending.jsonrpc_id,
            jsonrpc: JsonRpcVersion,
            payload: JsonRpcResult::Error {
                error: JsonRpcError {
                    code: ERROR_USER_REJECTED,
                    message: reason.to_string(),
                    data: None,
                },
            },
        };
        let _ = self
            .publish_encrypted(
                pending.pairing_topic,
                &pairing_sym,
                &response,
                TAG_SESSION_PROPOSE_RES,
                TTL_SESSION_PROPOSE,
                false,
            )
            .await;
    }

    /// Serialise, seal, base64-encode, and publish a single JSON-RPC
    /// payload. All outbound traffic flows through here so the encrypt-
    /// then-publish steps stay paired with the right tag/TTL.
    async fn publish_encrypted<T: Serialize>(
        &mut self,
        topic: Topic,
        sym_key: &SymKey,
        payload: &T,
        tag: u32,
        ttl: std::time::Duration,
        prompt: bool,
    ) -> Result<(), TransportError> {
        let plaintext =
            serde_json::to_vec(payload).map_err(|e| TransportError::Encoding(e.to_string()))?;
        let envelope = encode_envelope_type0(sym_key, &plaintext);
        let message_b64 = envelope_to_b64(&envelope);
        self.transport
            .publish(PublishMessage {
                topic,
                message_b64,
                tag,
                ttl,
                prompt,
            })
            .await
    }

    fn emit(&self, event: WcEvent) {
        if self.event_tx.send(event).is_err() {
            // UI has dropped the receiver. The engine task will exit on the
            // next select! iteration when the cmd_rx also closes.
            warn!("WcEngine: event channel closed, UI receiver gone");
        }
    }

    fn emit_error(&self, context: &str, message: String) {
        info!(context, message, "WcEngine: emitting error event");
        self.emit(WcEvent::Error {
            context: context.to_string(),
            message,
        });
    }

    fn next_proposal_id(&mut self) -> u64 {
        let id = self.next_proposal_id;
        self.next_proposal_id += 1;
        id
    }

    fn next_request_id(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        id
    }

    fn next_jsonrpc_id(&mut self) -> u64 {
        let id = self.next_jsonrpc_id;
        self.next_jsonrpc_id += 1;
        id
    }
}

// ── Free helpers ─────────────────────────────────────────────────────────

#[derive(Debug)]
enum DecryptError {
    Base64,
    Crypto(crate::walletconnect::crypto::CryptoError),
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Base64 => f.write_str("invalid base64"),
            Self::Crypto(e) => write!(f, "{e}"),
        }
    }
}

fn decrypt_envelope(sym_key: &SymKey, message_b64: &str) -> Result<Vec<u8>, DecryptError> {
    let envelope = envelope_from_b64(message_b64).map_err(|_| DecryptError::Base64)?;
    decode_envelope_type0(sym_key, &envelope).map_err(DecryptError::Crypto)
}

fn unix_seconds_from_now(d: std::time::Duration) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|now| now.as_secs() + d.as_secs())
        .unwrap_or_else(|_| d.as_secs())
}

/// Seed the JSON-RPC id space with the current millisecond timestamp so two
/// engines on the same wall clock don't collide on their first outbound
/// request. The wire only requires monotonic-per-session, but a globally
/// non-overlapping seed makes log triage easier.
fn fresh_jsonrpc_id_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1)
}

/// Pull the request's `from` Ethereum address out of a method's inner params.
///
/// Returns `None` when the method doesn't carry one (`wc_sessionPing`,
/// `wallet_switchEthereumChain`, …) or when the params don't parse — in the
/// latter case the per-method dispatcher will surface `ERROR_INVALID_PARAMS`
/// itself; the engine-level account check only fires when we can confidently
/// pin down the requested account.
///
/// `personal_sign` accepts either `[message, address]` or
/// `[address, message]` — same dual-order tolerance as the dispatcher.
fn extract_request_from_address(
    method: &str,
    params: &serde_json::Value,
) -> Option<alloy::primitives::Address> {
    use alloy::primitives::Address;
    let arr = params.as_array()?;
    match method {
        "personal_sign" => {
            if arr.len() < 2 {
                return None;
            }
            let a = arr[0].as_str()?;
            let b = arr[1].as_str()?;
            // Whichever side parses as an address is the address; if both
            // do, prefer the spec order `[message, address]`.
            match (a.parse::<Address>(), b.parse::<Address>()) {
                (Ok(_), Ok(b_addr)) => Some(b_addr),
                (Err(_), Ok(b_addr)) => Some(b_addr),
                (Ok(a_addr), Err(_)) => Some(a_addr),
                (Err(_), Err(_)) => None,
            }
        }
        "eth_signTypedData" | "eth_signTypedData_v4" => arr.first()?.as_str()?.parse().ok(),
        "eth_sendTransaction" | "eth_signTransaction" => arr
            .first()?
            .as_object()?
            .get("from")?
            .as_str()?
            .parse()
            .ok(),
        _ => None,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────
//
// Drive the engine command-by-command and inbound-by-inbound using a stub
// transport that records publishes and replays scripted inbounds. The full
// pairing handshake fits in one test from end to end.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::walletconnect::crypto::{
        EphemeralKeypair, SymKey, derive_session_key as crypto_derive_session_key, derive_topic,
        encode_envelope_type0, envelope_to_b64,
    };
    use crate::walletconnect::protocol::{
        InnerRequest, JsonRpcResult, PeerMetadata, Proposer, SessionProposeParams,
        SessionRequestParams, TAG_SESSION_PROPOSE_REQ, TAG_SESSION_REQUEST_REQ,
    };
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// Records every publish; succeeds every call. Tests inspect
    /// `published` to assert on outbound traffic.
    #[derive(Default)]
    struct RecordingTransport {
        published: Mutex<Vec<PublishMessage>>,
        subscribed: Mutex<Vec<Topic>>,
    }

    #[async_trait::async_trait]
    impl RelayTransport for RecordingTransport {
        async fn subscribe(&self, topic: Topic) -> Result<(), TransportError> {
            self.subscribed.lock().unwrap().push(topic);
            Ok(())
        }
        async fn batch_subscribe(&self, topics: &[Topic]) -> Result<(), TransportError> {
            self.subscribed.lock().unwrap().extend_from_slice(topics);
            Ok(())
        }
        async fn publish(&self, msg: PublishMessage) -> Result<(), TransportError> {
            self.published.lock().unwrap().push(msg);
            Ok(())
        }
        async fn unsubscribe(&self, _topic: Topic) -> Result<(), TransportError> {
            Ok(())
        }
    }

    /// Build an engine wired to a recording transport + capture channels.
    fn build_engine() -> (
        WcEngineRunner,
        Arc<RecordingTransport>,
        mpsc::UnboundedSender<InboundMessage>,
        mpsc::UnboundedReceiver<WcEvent>,
    ) {
        let transport = Arc::new(RecordingTransport::default());
        let transport_box: Box<dyn RelayTransport> = {
            // Box over a clone of the Arc so the test can still inspect it.
            // RecordingTransport doesn't actually need Arc internally; we
            // wrap because `RelayTransport: Send + Sync` and we want the
            // test to keep its own handle on the recorder.
            struct Shared(Arc<RecordingTransport>);
            #[async_trait::async_trait]
            impl RelayTransport for Shared {
                async fn subscribe(&self, t: Topic) -> Result<(), TransportError> {
                    self.0.subscribe(t).await
                }
                async fn batch_subscribe(&self, t: &[Topic]) -> Result<(), TransportError> {
                    self.0.batch_subscribe(t).await
                }
                async fn publish(&self, m: PublishMessage) -> Result<(), TransportError> {
                    self.0.publish(m).await
                }
                async fn unsubscribe(&self, t: Topic) -> Result<(), TransportError> {
                    self.0.unsubscribe(t).await
                }
            }
            Box::new(Shared(transport.clone()))
        };
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (tev_tx, tev_rx) = mpsc::unbounded_channel::<TransportEvent>();
        // The cmd_tx / tev_tx aren't used in handle_command tests; we
        // drive the handler entry points directly. Keep them alive so the
        // channels don't close mid-test.
        std::mem::forget(cmd_tx);
        std::mem::forget(tev_tx);
        let engine =
            WcEngineRunner::new(transport_box, in_rx, tev_rx, cmd_rx, event_tx, Vec::new());
        (engine, transport, in_tx, event_rx)
    }

    /// Same as `build_engine` but seeds the engine with persisted sessions
    /// so the restore-path tests can assert the initial subscribe and the
    /// session-already-known dispatch.
    fn build_engine_with_sessions(
        sessions: Vec<crate::walletconnect::session::PersistedSession>,
    ) -> (
        WcEngineRunner,
        Arc<RecordingTransport>,
        mpsc::UnboundedSender<InboundMessage>,
        mpsc::UnboundedReceiver<WcEvent>,
    ) {
        let transport = Arc::new(RecordingTransport::default());
        let transport_box: Box<dyn RelayTransport> = {
            struct Shared(Arc<RecordingTransport>);
            #[async_trait::async_trait]
            impl RelayTransport for Shared {
                async fn subscribe(&self, t: Topic) -> Result<(), TransportError> {
                    self.0.subscribe(t).await
                }
                async fn batch_subscribe(&self, t: &[Topic]) -> Result<(), TransportError> {
                    self.0.batch_subscribe(t).await
                }
                async fn publish(&self, m: PublishMessage) -> Result<(), TransportError> {
                    self.0.publish(m).await
                }
                async fn unsubscribe(&self, t: Topic) -> Result<(), TransportError> {
                    self.0.unsubscribe(t).await
                }
            }
            Box::new(Shared(transport.clone()))
        };
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (tev_tx, tev_rx) = mpsc::unbounded_channel::<TransportEvent>();
        std::mem::forget(cmd_tx);
        std::mem::forget(tev_tx);
        let engine = WcEngineRunner::new(transport_box, in_rx, tev_rx, cmd_rx, event_tx, sessions);
        (engine, transport, in_tx, event_rx)
    }

    fn dapp_metadata() -> PeerMetadata {
        PeerMetadata {
            name: "TestDapp".to_string(),
            description: "test".to_string(),
            url: "https://test.example".to_string(),
            icons: vec![],
            redirect: None,
        }
    }

    fn wallet_metadata() -> PeerMetadata {
        PeerMetadata {
            name: "Kao".to_string(),
            description: "Kao wallet".to_string(),
            url: "https://kao.example".to_string(),
            icons: vec![],
            redirect: None,
        }
    }

    fn make_pair_uri(sym_key: &SymKey) -> String {
        let topic = derive_topic(sym_key);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        format!(
            "wc:{}@2?relay-protocol=irn&symKey={}&expiryTimestamp={}",
            topic.to_hex(),
            hex::encode(sym_key.as_bytes()),
            now
        )
    }

    fn inject_propose_msg(
        in_tx: &mpsc::UnboundedSender<InboundMessage>,
        pairing_topic: Topic,
        pairing_sym_key: &SymKey,
        dapp_kp: &EphemeralKeypair,
        jsonrpc_id: u64,
    ) {
        let propose = JsonRpcRequest {
            id: jsonrpc_id,
            jsonrpc: JsonRpcVersion,
            method: "wc_sessionPropose".to_string(),
            params: serde_json::to_value(SessionProposeParams {
                relays: vec![RelayInfo {
                    protocol: "irn".to_string(),
                    data: None,
                }],
                proposer: Proposer {
                    public_key: dapp_kp.public().to_hex(),
                    metadata: dapp_metadata(),
                },
                required_namespaces: {
                    let mut m = BTreeMap::new();
                    m.insert(
                        "eip155".to_string(),
                        NamespaceProposal {
                            chains: vec!["eip155:1".to_string()],
                            methods: vec!["personal_sign".to_string()],
                            events: vec!["chainChanged".to_string()],
                        },
                    );
                    m
                },
                optional_namespaces: BTreeMap::new(),
                session_properties: None,
                expiry: None,
            })
            .unwrap(),
        };
        let plaintext = serde_json::to_vec(&propose).unwrap();
        let env = encode_envelope_type0(pairing_sym_key, &plaintext);
        in_tx
            .send(InboundMessage {
                topic: pairing_topic,
                message_b64: envelope_to_b64(&env),
                tag: TAG_SESSION_PROPOSE_REQ,
                published_at: None,
            })
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pair_subscribes_and_emits_paired() {
        let (mut engine, transport, _in_tx, mut event_rx) = build_engine();
        let sym = SymKey::random();
        let uri = make_pair_uri(&sym);
        let pairing_topic = derive_topic(&sym);

        engine.handle_command(WcCommand::PairWithUri { uri }).await;

        assert_eq!(
            transport.subscribed.lock().unwrap().as_slice(),
            &[pairing_topic]
        );
        match event_rx.try_recv() {
            Ok(WcEvent::Paired { pairing_topic: t }) => assert_eq!(t, pairing_topic),
            other => panic!("expected Paired, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pair_with_invalid_uri_emits_error() {
        let (mut engine, transport, _in_tx, mut event_rx) = build_engine();
        engine
            .handle_command(WcCommand::PairWithUri {
                uri: "not-a-wc-uri".into(),
            })
            .await;
        assert!(transport.subscribed.lock().unwrap().is_empty());
        match event_rx.try_recv() {
            Ok(WcEvent::Error { context, .. }) => assert_eq!(context, "pair"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn propose_is_decrypted_and_emitted() {
        let (mut engine, _transport, in_tx, mut event_rx) = build_engine();
        let pairing_sym = SymKey::random();
        let pairing_topic = derive_topic(&pairing_sym);
        let uri = make_pair_uri(&pairing_sym);
        engine.handle_command(WcCommand::PairWithUri { uri }).await;
        let _ = event_rx.try_recv(); // Paired

        let dapp_kp = EphemeralKeypair::generate();
        inject_propose_msg(&in_tx, pairing_topic, &pairing_sym, &dapp_kp, 42);

        // Pull the message off the channel and feed it to the engine.
        let msg = tokio::time::timeout(Duration::from_millis(50), engine.inbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        engine.handle_inbound(msg).await;

        match event_rx.try_recv().unwrap() {
            WcEvent::ProposalReceived {
                proposal_id,
                peer,
                required_namespaces,
                ..
            } => {
                assert_eq!(proposal_id, 1);
                assert_eq!(peer.name, "TestDapp");
                assert!(required_namespaces.contains_key("eip155"));
            }
            other => panic!("expected ProposalReceived, got {other:?}"),
        }
        // The pending proposal must be indexed.
        assert!(engine.pending_proposals.contains_key(&1));
        assert!(engine.proposal_by_pairing.contains_key(&pairing_topic));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn approve_proposal_subscribes_session_and_publishes_both() {
        let (mut engine, transport, in_tx, mut event_rx) = build_engine();
        let pairing_sym = SymKey::random();
        let pairing_topic = derive_topic(&pairing_sym);
        let uri = make_pair_uri(&pairing_sym);
        engine.handle_command(WcCommand::PairWithUri { uri }).await;
        let _ = event_rx.try_recv();

        let dapp_kp = EphemeralKeypair::generate();
        inject_propose_msg(&in_tx, pairing_topic, &pairing_sym, &dapp_kp, 42);
        let msg = engine.inbound_rx.recv().await.unwrap();
        engine.handle_inbound(msg).await;
        let _ = event_rx.try_recv(); // ProposalReceived

        // Snapshot the engine-derived session topic + wallet pub.
        let pending = engine.pending_proposals.get(&1).unwrap();
        let session_topic = pending.session_topic;
        let wallet_pub_hex = pending.wallet_public_key.to_hex();
        let session_sym_for_check = pending.session_sym_key.clone();

        // Verify the dApp side would arrive at the same symKey via ECDH.
        let wallet_pub = PublicKey::from_hex(&wallet_pub_hex).unwrap();
        let dapp_derived = crypto_derive_session_key(dapp_kp, &wallet_pub).unwrap();
        assert_eq!(
            dapp_derived.as_bytes(),
            session_sym_for_check.as_bytes(),
            "wallet and dApp must derive the same session symKey"
        );

        let mut approved_ns = BTreeMap::new();
        approved_ns.insert(
            "eip155".to_string(),
            NamespaceSettled {
                chains: vec!["eip155:1".to_string()],
                accounts: vec!["eip155:1:0x1111111111111111111111111111111111111111".to_string()],
                methods: vec!["personal_sign".to_string()],
                events: vec!["chainChanged".to_string()],
            },
        );

        engine
            .handle_command(WcCommand::ApproveProposal {
                proposal_id: 1,
                namespaces: approved_ns.clone(),
                wallet_metadata: wallet_metadata(),
            })
            .await;

        // Subscribe was called for pairing topic AND session topic (in order).
        let subs = transport.subscribed.lock().unwrap().clone();
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0], pairing_topic);
        assert_eq!(subs[1], session_topic);

        // Two publishes: propose-response on pairing topic, then settle on
        // session topic. Order matters — the dApp can race-subscribe to the
        // session topic only after seeing responderPublicKey.
        let pubs = transport.published.lock().unwrap().clone();
        assert_eq!(pubs.len(), 2);
        assert_eq!(pubs[0].topic, pairing_topic);
        assert_eq!(pubs[0].tag, TAG_SESSION_PROPOSE_RES);
        assert_eq!(pubs[1].topic, session_topic);
        assert_eq!(pubs[1].tag, TAG_SESSION_SETTLE_REQ);

        // SessionSettled event fired with the right namespaces.
        match event_rx.try_recv().unwrap() {
            WcEvent::SessionSettled {
                topic, namespaces, ..
            } => {
                assert_eq!(topic, session_topic);
                assert_eq!(namespaces, approved_ns);
            }
            other => panic!("expected SessionSettled, got {other:?}"),
        }
        assert!(engine.sessions.contains_key(&session_topic));
        assert!(engine.pending_proposals.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn session_request_emits_received_event() {
        // Drive through pair → propose → approve so we have a live session,
        // then inject a wc_sessionRequest on the session topic.
        let (mut engine, transport, in_tx, mut event_rx) = build_engine();
        let pairing_sym = SymKey::random();
        let pairing_topic = derive_topic(&pairing_sym);
        engine
            .handle_command(WcCommand::PairWithUri {
                uri: make_pair_uri(&pairing_sym),
            })
            .await;
        let _ = event_rx.try_recv();

        let dapp_kp = EphemeralKeypair::generate();
        inject_propose_msg(&in_tx, pairing_topic, &pairing_sym, &dapp_kp, 42);
        let msg = engine.inbound_rx.recv().await.unwrap();
        engine.handle_inbound(msg).await;
        let _ = event_rx.try_recv();

        let session_sym = engine
            .pending_proposals
            .get(&1)
            .unwrap()
            .session_sym_key
            .clone();
        let session_topic = engine.pending_proposals.get(&1).unwrap().session_topic;

        let mut ns = BTreeMap::new();
        ns.insert(
            "eip155".to_string(),
            NamespaceSettled {
                chains: vec!["eip155:1".to_string()],
                accounts: vec!["eip155:1:0x1111111111111111111111111111111111111111".to_string()],
                methods: vec!["personal_sign".to_string()],
                events: vec!["chainChanged".to_string()],
            },
        );
        engine
            .handle_command(WcCommand::ApproveProposal {
                proposal_id: 1,
                namespaces: ns,
                wallet_metadata: wallet_metadata(),
            })
            .await;
        let _ = event_rx.try_recv();
        transport.published.lock().unwrap().clear();

        // Inject a session request (dApp asks wallet to personal_sign).
        let req = JsonRpcRequest {
            id: 99,
            jsonrpc: JsonRpcVersion,
            method: "wc_sessionRequest".to_string(),
            params: serde_json::to_value(SessionRequestParams {
                chain_id: "eip155:1".to_string(),
                request: InnerRequest {
                    method: "personal_sign".to_string(),
                    params: json!(["0x48656c6c6f", "0x1111111111111111111111111111111111111111"]),
                    expiry: None,
                },
            })
            .unwrap(),
        };
        let plaintext = serde_json::to_vec(&req).unwrap();
        let env = encode_envelope_type0(&session_sym, &plaintext);
        in_tx
            .send(InboundMessage {
                topic: session_topic,
                message_b64: envelope_to_b64(&env),
                tag: TAG_SESSION_REQUEST_REQ,
                published_at: None,
            })
            .unwrap();
        let msg = engine.inbound_rx.recv().await.unwrap();
        engine.handle_inbound(msg).await;

        match event_rx.try_recv().unwrap() {
            WcEvent::RequestReceived {
                request_id,
                method,
                chain_id,
                ..
            } => {
                assert_eq!(request_id, 1);
                assert_eq!(method, "personal_sign");
                assert_eq!(chain_id, "eip155:1");
            }
            other => panic!("expected RequestReceived, got {other:?}"),
        }
        assert_eq!(engine.pending_requests.len(), 1);

        // Approve it; verify the engine publishes the response on the
        // session topic, encrypted under the session symKey.
        engine
            .handle_command(WcCommand::ApproveRequest {
                request_id: 1,
                result: json!("0xabcdef"),
            })
            .await;
        let pubs = transport.published.lock().unwrap();
        assert_eq!(pubs.len(), 1);
        assert_eq!(pubs[0].topic, session_topic);
        assert_eq!(pubs[0].tag, TAG_SESSION_REQUEST_RES);

        // Decrypt the response and check it carries the result we approved.
        let env = envelope_from_b64(&pubs[0].message_b64).unwrap();
        let pt = decode_envelope_type0(&session_sym, &env).unwrap();
        let resp: JsonRpcResponse = serde_json::from_slice(&pt).unwrap();
        assert_eq!(resp.id, 99);
        match resp.payload {
            JsonRpcResult::Success { result } => assert_eq!(result, json!("0xabcdef")),
            JsonRpcResult::Error { .. } => panic!("expected success result"),
        }
        assert!(engine.pending_requests.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reject_request_publishes_4001_style_error() {
        // Build live session, inject sessionRequest, reject it.
        let (mut engine, transport, in_tx, mut event_rx) = build_engine();
        let pairing_sym = SymKey::random();
        let pairing_topic = derive_topic(&pairing_sym);
        engine
            .handle_command(WcCommand::PairWithUri {
                uri: make_pair_uri(&pairing_sym),
            })
            .await;
        let _ = event_rx.try_recv();
        let dapp_kp = EphemeralKeypair::generate();
        inject_propose_msg(&in_tx, pairing_topic, &pairing_sym, &dapp_kp, 42);
        let msg = engine.inbound_rx.recv().await.unwrap();
        engine.handle_inbound(msg).await;
        let _ = event_rx.try_recv();
        let session_sym = engine
            .pending_proposals
            .get(&1)
            .unwrap()
            .session_sym_key
            .clone();
        let session_topic = engine.pending_proposals.get(&1).unwrap().session_topic;
        let mut ns = BTreeMap::new();
        ns.insert(
            "eip155".to_string(),
            NamespaceSettled {
                chains: vec!["eip155:1".to_string()],
                accounts: vec!["eip155:1:0x1111111111111111111111111111111111111111".to_string()],
                methods: vec!["personal_sign".to_string()],
                events: vec!["chainChanged".to_string()],
            },
        );
        engine
            .handle_command(WcCommand::ApproveProposal {
                proposal_id: 1,
                namespaces: ns,
                wallet_metadata: wallet_metadata(),
            })
            .await;
        let _ = event_rx.try_recv();
        transport.published.lock().unwrap().clear();

        // Inject request.
        let req = JsonRpcRequest {
            id: 77,
            jsonrpc: JsonRpcVersion,
            method: "wc_sessionRequest".to_string(),
            params: serde_json::to_value(SessionRequestParams {
                chain_id: "eip155:1".to_string(),
                request: InnerRequest {
                    method: "personal_sign".to_string(),
                    params: json!(["0xdead", "0x1111111111111111111111111111111111111111"]),
                    expiry: None,
                },
            })
            .unwrap(),
        };
        let env = encode_envelope_type0(&session_sym, &serde_json::to_vec(&req).unwrap());
        in_tx
            .send(InboundMessage {
                topic: session_topic,
                message_b64: envelope_to_b64(&env),
                tag: TAG_SESSION_REQUEST_REQ,
                published_at: None,
            })
            .unwrap();
        let msg = engine.inbound_rx.recv().await.unwrap();
        engine.handle_inbound(msg).await;
        let _ = event_rx.try_recv();

        engine
            .handle_command(WcCommand::RejectRequest {
                request_id: 1,
                error: None,
            })
            .await;

        let pubs = transport.published.lock().unwrap();
        assert_eq!(pubs.len(), 1);
        let env = envelope_from_b64(&pubs[0].message_b64).unwrap();
        let pt = decode_envelope_type0(&session_sym, &env).unwrap();
        let resp: JsonRpcResponse = serde_json::from_slice(&pt).unwrap();
        match resp.payload {
            JsonRpcResult::Error { error } => {
                assert_eq!(error.code, ERROR_USER_REJECTED);
            }
            JsonRpcResult::Success { .. } => panic!("expected error result"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn duplicate_propose_on_pairing_is_ignored() {
        let (mut engine, _transport, in_tx, mut event_rx) = build_engine();
        let pairing_sym = SymKey::random();
        let pairing_topic = derive_topic(&pairing_sym);
        engine
            .handle_command(WcCommand::PairWithUri {
                uri: make_pair_uri(&pairing_sym),
            })
            .await;
        let _ = event_rx.try_recv();

        let dapp_kp_1 = EphemeralKeypair::generate();
        inject_propose_msg(&in_tx, pairing_topic, &pairing_sym, &dapp_kp_1, 42);
        let msg = engine.inbound_rx.recv().await.unwrap();
        engine.handle_inbound(msg).await;
        let _ = event_rx.try_recv(); // ProposalReceived

        // Second propose on the same pairing topic — pairings are single-
        // use, must be ignored. Use a different ephemeral keypair so this
        // is unambiguously a "second proposal" rather than a replay.
        let dapp_kp_2 = EphemeralKeypair::generate();
        inject_propose_msg(&in_tx, pairing_topic, &pairing_sym, &dapp_kp_2, 43);
        let msg = engine.inbound_rx.recv().await.unwrap();
        engine.handle_inbound(msg).await;

        // No new event.
        assert!(event_rx.try_recv().is_err());
        // Still exactly one pending proposal.
        assert_eq!(engine.pending_proposals.len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn session_delete_inbound_drops_session() {
        let (mut engine, _transport, in_tx, mut event_rx) = build_engine();
        let pairing_sym = SymKey::random();
        let pairing_topic = derive_topic(&pairing_sym);
        engine
            .handle_command(WcCommand::PairWithUri {
                uri: make_pair_uri(&pairing_sym),
            })
            .await;
        let _ = event_rx.try_recv();
        let dapp_kp = EphemeralKeypair::generate();
        inject_propose_msg(&in_tx, pairing_topic, &pairing_sym, &dapp_kp, 42);
        let msg = engine.inbound_rx.recv().await.unwrap();
        engine.handle_inbound(msg).await;
        let _ = event_rx.try_recv();
        let session_sym = engine
            .pending_proposals
            .get(&1)
            .unwrap()
            .session_sym_key
            .clone();
        let session_topic = engine.pending_proposals.get(&1).unwrap().session_topic;
        let mut ns = BTreeMap::new();
        ns.insert(
            "eip155".to_string(),
            NamespaceSettled {
                chains: vec!["eip155:1".to_string()],
                accounts: vec![],
                methods: vec![],
                events: vec![],
            },
        );
        engine
            .handle_command(WcCommand::ApproveProposal {
                proposal_id: 1,
                namespaces: ns,
                wallet_metadata: wallet_metadata(),
            })
            .await;
        let _ = event_rx.try_recv();

        // dApp sends wc_sessionDelete.
        let delete = JsonRpcRequest {
            id: 88,
            jsonrpc: JsonRpcVersion,
            method: "wc_sessionDelete".to_string(),
            params: serde_json::to_value(SessionDeleteParams {
                code: 6000,
                message: "User disconnected".to_string(),
            })
            .unwrap(),
        };
        let env = encode_envelope_type0(&session_sym, &serde_json::to_vec(&delete).unwrap());
        in_tx
            .send(InboundMessage {
                topic: session_topic,
                message_b64: envelope_to_b64(&env),
                tag: crate::walletconnect::protocol::TAG_SESSION_DELETE_REQ,
                published_at: None,
            })
            .unwrap();
        let msg = engine.inbound_rx.recv().await.unwrap();
        engine.handle_inbound(msg).await;

        match event_rx.try_recv().unwrap() {
            WcEvent::SessionDeleted { topic, reason } => {
                assert_eq!(topic, session_topic);
                assert_eq!(reason, "User disconnected");
            }
            other => panic!("expected SessionDeleted, got {other:?}"),
        }
        assert!(!engine.sessions.contains_key(&session_topic));
    }

    // ── Restore tests ────────────────────────────────────────────────

    fn persisted_session(
        topic_byte: u8,
        sym_byte: u8,
    ) -> crate::walletconnect::session::PersistedSession {
        use crate::walletconnect::session::{PersistedPeerMetadata, PersistedSession};
        // Seed with a permissive `eip155:1` + personal_sign scope so the
        // restored session can answer the inbound-request test under
        // Phase 7's scope check. The restore-only tests that don't drive
        // session-requests are unaffected by what's in the map.
        let mut namespaces = BTreeMap::new();
        namespaces.insert(
            "eip155".to_string(),
            NamespaceSettled {
                chains: vec!["eip155:1".to_string()],
                accounts: vec!["eip155:1:0x1111111111111111111111111111111111111111".to_string()],
                methods: vec!["personal_sign".to_string()],
                events: vec!["chainChanged".to_string()],
            },
        );
        PersistedSession {
            topic: [topic_byte; 32],
            sym_key: [sym_byte; 32],
            peer_metadata: PersistedPeerMetadata {
                name: format!("dapp-{topic_byte:02x}"),
                description: "restored test session".to_string(),
                url: "https://restored.example".to_string(),
                icons: vec![],
                redirect: None,
            },
            namespaces,
            expiry: 1_700_000_000,
            relay_protocol: "irn".to_string(),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn restore_seeds_session_map_and_batch_subscribes() {
        // Engine constructed with two persisted sessions: both should land
        // in `self.sessions` immediately, and the first run-step should
        // batch_subscribe all topics in one call.
        let s1 = persisted_session(0xAA, 0x11);
        let s2 = persisted_session(0xBB, 0x22);
        let topic_a = Topic::from_bytes([0xAA; 32]);
        let topic_b = Topic::from_bytes([0xBB; 32]);

        let (mut engine, transport, _in_tx, mut event_rx) =
            build_engine_with_sessions(vec![s1, s2]);

        // Sessions are in the map before any async work runs.
        assert_eq!(engine.sessions.len(), 2);
        assert!(engine.sessions.contains_key(&topic_a));
        assert!(engine.sessions.contains_key(&topic_b));

        // Restore phase issues batch_subscribe.
        engine.restore_initial_sessions().await;
        let subs = transport.subscribed.lock().unwrap();
        assert_eq!(subs.len(), 2);
        assert!(subs.contains(&topic_a));
        assert!(subs.contains(&topic_b));
        // No error event emitted on the happy path.
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn restore_no_op_when_empty() {
        let (mut engine, transport, _in_tx, mut event_rx) = build_engine();
        engine.restore_initial_sessions().await;
        assert!(transport.subscribed.lock().unwrap().is_empty());
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn restore_failure_emits_error_but_continues() {
        // Construct a transport that fails batch_subscribe — verify the
        // engine logs the error rather than panicking.
        #[derive(Default)]
        struct FailingTransport;
        #[async_trait::async_trait]
        impl RelayTransport for FailingTransport {
            async fn subscribe(&self, _: Topic) -> Result<(), TransportError> {
                Ok(())
            }
            async fn batch_subscribe(&self, _: &[Topic]) -> Result<(), TransportError> {
                Err(TransportError::ConnectionLost)
            }
            async fn publish(&self, _: PublishMessage) -> Result<(), TransportError> {
                Ok(())
            }
            async fn unsubscribe(&self, _: Topic) -> Result<(), TransportError> {
                Ok(())
            }
        }
        let (_in_tx, in_rx) = mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let (tev_tx, tev_rx) = mpsc::unbounded_channel::<TransportEvent>();
        std::mem::forget(cmd_tx);
        std::mem::forget(tev_tx);
        let mut engine = WcEngineRunner::new(
            Box::new(FailingTransport),
            in_rx,
            tev_rx,
            cmd_rx,
            event_tx,
            vec![persisted_session(0xAA, 0x11)],
        );
        engine.restore_initial_sessions().await;
        // Error event emitted.
        match event_rx.try_recv().unwrap() {
            WcEvent::Error { context, .. } => assert_eq!(context, "restore"),
            other => panic!("expected Error, got {other:?}"),
        }
        // Session is still in the map — the dApp's next inbound on this
        // topic will be missed (we never subscribed), but the engine
        // hasn't entered a broken state.
        assert_eq!(engine.sessions.len(), 1);
    }

    /// Inbound session-request on a restored session must dispatch
    /// normally — the sym_key is in the session map from `new()`, the
    /// inbound handler should decrypt with it and emit `RequestReceived`.
    #[tokio::test(flavor = "current_thread")]
    async fn restored_session_handles_inbound_request() {
        let sym = SymKey::from_bytes([0x88; 32]);
        let topic = derive_topic(&sym);
        let mut persisted = persisted_session(topic.as_bytes()[0], sym.as_bytes()[0]);
        persisted.topic = *topic.as_bytes();
        persisted.sym_key = *sym.as_bytes();

        let (mut engine, _transport, in_tx, mut event_rx) =
            build_engine_with_sessions(vec![persisted]);
        engine.restore_initial_sessions().await;

        // Inject a wc_sessionRequest as if the relay replayed it after we
        // resubscribed.
        let req = JsonRpcRequest {
            id: 42,
            jsonrpc: JsonRpcVersion,
            method: "wc_sessionRequest".to_string(),
            params: serde_json::to_value(crate::walletconnect::protocol::SessionRequestParams {
                chain_id: "eip155:1".to_string(),
                request: crate::walletconnect::protocol::InnerRequest {
                    method: "personal_sign".to_string(),
                    params: json!(["0xdead", "0x1111111111111111111111111111111111111111"]),
                    expiry: None,
                },
            })
            .unwrap(),
        };
        let env = encode_envelope_type0(&sym, &serde_json::to_vec(&req).unwrap());
        in_tx
            .send(InboundMessage {
                topic,
                message_b64: envelope_to_b64(&env),
                tag: crate::walletconnect::protocol::TAG_SESSION_REQUEST_REQ,
                published_at: None,
            })
            .unwrap();
        let msg = engine.inbound_rx.recv().await.unwrap();
        engine.handle_inbound(msg).await;

        match event_rx.try_recv().unwrap() {
            WcEvent::RequestReceived { method, .. } => assert_eq!(method, "personal_sign"),
            other => panic!("expected RequestReceived, got {other:?}"),
        }
    }

    // ── Phase 7 hardening tests ──────────────────────────────────────

    /// Drive through pair → propose → approve with a *narrow* approved
    /// scope (chains=[eip155:1], methods=[personal_sign]). Then inject
    /// session requests for: a chain outside the approved set, a method
    /// outside the approved set, and a happy-path one — verify the
    /// out-of-scope ones produce JSON-RPC error responses on the session
    /// topic with the spec-mandated codes, and only the happy-path
    /// request emits `RequestReceived`.
    #[tokio::test(flavor = "current_thread")]
    async fn out_of_scope_chain_and_method_are_rejected_at_engine() {
        let (mut engine, transport, in_tx, mut event_rx) = build_engine();
        let pairing_sym = SymKey::random();
        let pairing_topic = derive_topic(&pairing_sym);
        engine
            .handle_command(WcCommand::PairWithUri {
                uri: make_pair_uri(&pairing_sym),
            })
            .await;
        let _ = event_rx.try_recv();
        let dapp_kp = EphemeralKeypair::generate();
        inject_propose_msg(&in_tx, pairing_topic, &pairing_sym, &dapp_kp, 42);
        let msg = engine.inbound_rx.recv().await.unwrap();
        engine.handle_inbound(msg).await;
        let _ = event_rx.try_recv();
        let session_sym = engine
            .pending_proposals
            .get(&1)
            .unwrap()
            .session_sym_key
            .clone();
        let session_topic = engine.pending_proposals.get(&1).unwrap().session_topic;

        // Narrow approval: only personal_sign on Mainnet.
        let mut ns = BTreeMap::new();
        ns.insert(
            "eip155".to_string(),
            NamespaceSettled {
                chains: vec!["eip155:1".to_string()],
                accounts: vec!["eip155:1:0x1111111111111111111111111111111111111111".to_string()],
                methods: vec!["personal_sign".to_string()],
                events: vec!["chainChanged".to_string()],
            },
        );
        engine
            .handle_command(WcCommand::ApproveProposal {
                proposal_id: 1,
                namespaces: ns,
                wallet_metadata: wallet_metadata(),
            })
            .await;
        let _ = event_rx.try_recv();
        transport.published.lock().unwrap().clear();

        // Helper: inject a session request with given chain + method.
        let inject_req = |id: u64, chain: &str, method: &str| {
            let req = JsonRpcRequest {
                id,
                jsonrpc: JsonRpcVersion,
                method: "wc_sessionRequest".to_string(),
                params: serde_json::to_value(SessionRequestParams {
                    chain_id: chain.to_string(),
                    request: InnerRequest {
                        method: method.to_string(),
                        params: json!([]),
                        expiry: None,
                    },
                })
                .unwrap(),
            };
            let env = encode_envelope_type0(&session_sym, &serde_json::to_vec(&req).unwrap());
            in_tx
                .send(InboundMessage {
                    topic: session_topic,
                    message_b64: envelope_to_b64(&env),
                    tag: TAG_SESSION_REQUEST_REQ,
                    published_at: None,
                })
                .unwrap();
        };

        // Helper: snapshot the recorded publishes into owned data so the
        // following async work doesn't accidentally hold the mutex across
        // an await (clippy's `await_holding_lock`).
        let take_pubs = |label: &str| -> Vec<PublishMessage> {
            let mut guard = transport.published.lock().unwrap();
            let out = std::mem::take(&mut *guard);
            tracing::debug!(target: "wc_engine_test", label, count = out.len(), "snapshot pubs");
            out
        };

        // Out-of-scope chain (eip155:10 — not in approved chains).
        inject_req(100, "eip155:10", "personal_sign");
        let msg = engine.inbound_rx.recv().await.unwrap();
        engine.handle_inbound(msg).await;
        // No RequestReceived event emitted.
        assert!(event_rx.try_recv().is_err());
        // Error response published on session topic with code 3005.
        let pubs = take_pubs("chain");
        assert_eq!(pubs.len(), 1);
        let pt = decode_envelope_type0(
            &session_sym,
            &envelope_from_b64(&pubs[0].message_b64).unwrap(),
        )
        .unwrap();
        let resp: JsonRpcResponse = serde_json::from_slice(&pt).unwrap();
        assert_eq!(resp.id, 100);
        match resp.payload {
            JsonRpcResult::Error { error } => assert_eq!(error.code, ERROR_UNAUTHORIZED_CHAIN),
            _ => panic!("expected unauthorized-chain error"),
        }

        // Out-of-scope method (eth_sendTransaction — not in approved methods).
        inject_req(101, "eip155:1", "eth_sendTransaction");
        let msg = engine.inbound_rx.recv().await.unwrap();
        engine.handle_inbound(msg).await;
        assert!(event_rx.try_recv().is_err());
        let pubs = take_pubs("method");
        assert_eq!(pubs.len(), 1);
        let pt = decode_envelope_type0(
            &session_sym,
            &envelope_from_b64(&pubs[0].message_b64).unwrap(),
        )
        .unwrap();
        let resp: JsonRpcResponse = serde_json::from_slice(&pt).unwrap();
        assert_eq!(resp.id, 101);
        match resp.payload {
            JsonRpcResult::Error { error } => assert_eq!(error.code, ERROR_UNAUTHORIZED_METHOD),
            _ => panic!("expected unauthorized-method error"),
        }

        // Happy path: in-scope chain + method → RequestReceived emitted,
        // no auto-published error response.
        inject_req(102, "eip155:1", "personal_sign");
        let msg = engine.inbound_rx.recv().await.unwrap();
        engine.handle_inbound(msg).await;
        match event_rx.try_recv().unwrap() {
            WcEvent::RequestReceived { method, .. } => assert_eq!(method, "personal_sign"),
            other => panic!("expected RequestReceived, got {other:?}"),
        }
        // No auto-error publish (only the user's eventual approve/reject
        // produces an outbound).
        assert!(transport.published.lock().unwrap().is_empty());
    }

    /// `check_request_account_scope` rejects sign requests whose `from`
    /// isn't in the session's settled CAIP-10 accounts. Closes the
    /// confused-deputy gap where a session for account A could be used to
    /// elicit a signature from a different account.
    #[test]
    fn check_request_account_scope_rejects_unsettled_from() {
        let (mut engine, _transport, _in_tx, _event_rx) = build_engine();
        let sym = SymKey::random();
        let topic = derive_topic(&sym);
        let mut namespaces = BTreeMap::new();
        namespaces.insert(
            "eip155".to_string(),
            NamespaceSettled {
                chains: vec!["eip155:1".to_string()],
                accounts: vec!["eip155:1:0x1111111111111111111111111111111111111111".to_string()],
                methods: vec![
                    "personal_sign".to_string(),
                    "eth_signTypedData_v4".to_string(),
                ],
                events: vec![],
            },
        );
        engine.sessions.insert(
            topic,
            Session {
                topic,
                sym_key: sym,
                peer_metadata: wallet_metadata(),
                namespaces,
                expiry: 1_700_000_000,
                relay_protocol: "irn".to_string(),
            },
        );

        // Settled account → None (in scope), either param order accepted.
        let settled = "0x1111111111111111111111111111111111111111";
        let other = "0x2222222222222222222222222222222222222222";

        assert!(
            engine
                .check_request_account_scope(
                    topic,
                    "eip155:1",
                    "personal_sign",
                    &json!(["0xfeed", settled]),
                )
                .is_none()
        );
        // Legacy [address, message] order.
        assert!(
            engine
                .check_request_account_scope(
                    topic,
                    "eip155:1",
                    "personal_sign",
                    &json!([settled, "0xfeed"]),
                )
                .is_none()
        );
        // Checksum case shouldn't matter — same address.
        let checksum = "0x1111111111111111111111111111111111111111";
        assert!(
            engine
                .check_request_account_scope(
                    topic,
                    "eip155:1",
                    "personal_sign",
                    &json!(["0xfeed", checksum]),
                )
                .is_none()
        );

        // Different address → UNAUTHORIZED_METHOD.
        let err = engine
            .check_request_account_scope(
                topic,
                "eip155:1",
                "personal_sign",
                &json!(["0xfeed", other]),
            )
            .unwrap();
        assert_eq!(err.code, ERROR_UNAUTHORIZED_METHOD);

        // Same gate applies to eth_signTypedData_v4.
        let err = engine
            .check_request_account_scope(
                topic,
                "eip155:1",
                "eth_signTypedData_v4",
                &json!([other, {"types":{},"primaryType":"X","domain":{},"message":{}}]),
            )
            .unwrap();
        assert_eq!(err.code, ERROR_UNAUTHORIZED_METHOD);

        // Method without an address → no gate (returns None and defers to
        // the per-method dispatcher's own validation).
        assert!(
            engine
                .check_request_account_scope(topic, "eip155:1", "wc_sessionPing", &json!({}),)
                .is_none()
        );

        // Unparseable params → defer (no gate).
        assert!(
            engine
                .check_request_account_scope(
                    topic,
                    "eip155:1",
                    "personal_sign",
                    &json!(["just one element"]),
                )
                .is_none()
        );
    }

    /// `check_session_scope` directly — pure function exercise to lock
    /// the per-error-code policy in place.
    #[test]
    fn check_session_scope_rejects_with_spec_codes() {
        let (mut engine, _transport, _in_tx, _event_rx) = build_engine();
        let sym = SymKey::random();
        let topic = derive_topic(&sym);
        let mut namespaces = BTreeMap::new();
        namespaces.insert(
            "eip155".to_string(),
            NamespaceSettled {
                chains: vec!["eip155:1".to_string()],
                accounts: vec![],
                methods: vec!["personal_sign".to_string()],
                events: vec![],
            },
        );
        engine.sessions.insert(
            topic,
            Session {
                topic,
                sym_key: sym,
                peer_metadata: wallet_metadata(),
                namespaces,
                expiry: 1_700_000_000,
                relay_protocol: "irn".to_string(),
            },
        );

        // In-scope: returns None.
        assert!(
            engine
                .check_session_scope(topic, "eip155:1", "personal_sign")
                .is_none()
        );

        // Wrong chain: ERROR_UNAUTHORIZED_CHAIN.
        let err = engine
            .check_session_scope(topic, "eip155:8453", "personal_sign")
            .unwrap();
        assert_eq!(err.code, ERROR_UNAUTHORIZED_CHAIN);

        // Wrong namespace (solana:101 → no `solana` key in our namespaces):
        // also classified as UNAUTHORIZED_CHAIN — the dApp can't ask for a
        // chain we never advertised.
        let err = engine
            .check_session_scope(topic, "solana:101", "personal_sign")
            .unwrap();
        assert_eq!(err.code, ERROR_UNAUTHORIZED_CHAIN);

        // Wrong method: ERROR_UNAUTHORIZED_METHOD.
        let err = engine
            .check_session_scope(topic, "eip155:1", "eth_sendTransaction")
            .unwrap();
        assert_eq!(err.code, ERROR_UNAUTHORIZED_METHOD);

        // Missing session entirely: defensive — never panics, returns
        // None (caller's job to handle session lookup separately).
        let unknown = Topic::from_bytes([0xff; 32]);
        assert!(
            engine
                .check_session_scope(unknown, "eip155:1", "personal_sign")
                .is_none()
        );
    }

    #[test]
    fn prune_stale_requests_drops_only_those_past_ttl() {
        let (mut engine, _transport, _in_tx, _event_rx) = build_engine();
        let topic = Topic::from_bytes([0xAA; 32]);

        // Fresh request (just received).
        engine.pending_requests.insert(
            1,
            PendingRequest {
                request_id: 1,
                session_topic: topic,
                jsonrpc_id: 100,
                chain_id: "eip155:1".to_string(),
                method: "personal_sign".to_string(),
                params: json!([]),
                expiry: None,
                received_at: std::time::Instant::now(),
            },
        );
        // Stale request (1 hour ago — well past the 5-minute TTL).
        engine.pending_requests.insert(
            2,
            PendingRequest {
                request_id: 2,
                session_topic: topic,
                jsonrpc_id: 101,
                chain_id: "eip155:1".to_string(),
                method: "personal_sign".to_string(),
                params: json!([]),
                expiry: None,
                received_at: std::time::Instant::now() - std::time::Duration::from_secs(60 * 60),
            },
        );

        let pruned = engine.prune_stale_requests();
        assert_eq!(pruned, vec![2]);
        assert!(engine.pending_requests.contains_key(&1));
        assert!(!engine.pending_requests.contains_key(&2));

        // No-op on second call: the stale one is already gone.
        let pruned2 = engine.prune_stale_requests();
        assert!(pruned2.is_empty());
    }

    // ── Transport reconnect tests ────────────────────────────────────
    //
    // Reconnect-handling exists because the relay drops every topic
    // subscription on disconnect. If the engine doesn't re-subscribe
    // after `TransportEvent::Reconnected`, live sessions silently
    // stop receiving inbound traffic — which is exactly what bit us
    // on the load-balancing (code 4010) hour-rotation drop.

    #[tokio::test(flavor = "current_thread")]
    async fn transport_reconnected_resubscribes_pairings_and_sessions() {
        // Seed with a persisted session so `sessions` has an entry, then
        // pair fresh so `pairings` has one too. After clearing the
        // recorder, fire `Reconnected` and confirm the engine re-issues
        // batch_subscribe with both topics.
        let session_topic = Topic::from_bytes([0xAA; 32]);
        let (mut engine, transport, _in_tx, mut event_rx) =
            build_engine_with_sessions(vec![persisted_session(0xAA, 0x11)]);
        engine.restore_initial_sessions().await;

        // Add a pairing the normal way.
        let pairing_sym = SymKey::random();
        let pairing_topic = derive_topic(&pairing_sym);
        engine
            .handle_command(WcCommand::PairWithUri {
                uri: make_pair_uri(&pairing_sym),
            })
            .await;
        // Drain "Paired" + restore subscribes so the post-reconnect
        // assertion only sees what reconnect itself published.
        while event_rx.try_recv().is_ok() {}
        transport.subscribed.lock().unwrap().clear();

        engine
            .handle_transport_event(TransportEvent::Reconnected)
            .await;

        let subs = transport.subscribed.lock().unwrap();
        assert_eq!(subs.len(), 2, "expected both topics, got {subs:?}");
        assert!(subs.contains(&session_topic));
        assert!(subs.contains(&pairing_topic));
        // Reconnected on the happy path is silent — no error events.
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transport_reconnected_with_no_topics_is_noop() {
        // Fresh engine, no pairings, no sessions. Reconnected must not
        // call `batch_subscribe([])` — the relay treats that as an
        // error and we'd spam the log.
        let (mut engine, transport, _in_tx, mut event_rx) = build_engine();
        engine
            .handle_transport_event(TransportEvent::Reconnected)
            .await;
        assert!(transport.subscribed.lock().unwrap().is_empty());
        assert!(event_rx.try_recv().is_err());
    }

    /// The actual user-facing regression this whole feature exists to
    /// prevent: after the relay drops (4010 load-balance, network blip,
    /// whatever) and the transport reconnects, an inbound session_request
    /// on a previously-live session must still decrypt and emit
    /// `RequestReceived`. The relay-side subscription was lost on
    /// disconnect, so this implicitly validates that the engine
    /// re-subscribed AND that nothing in the session map was wiped.
    #[tokio::test(flavor = "current_thread")]
    async fn session_survives_reconnect_and_decrypts_inbound_request() {
        let sym = SymKey::from_bytes([0x77; 32]);
        let topic = derive_topic(&sym);
        let mut persisted = persisted_session(topic.as_bytes()[0], sym.as_bytes()[0]);
        persisted.topic = *topic.as_bytes();
        persisted.sym_key = *sym.as_bytes();

        let (mut engine, transport, in_tx, mut event_rx) =
            build_engine_with_sessions(vec![persisted]);
        engine.restore_initial_sessions().await;
        transport.subscribed.lock().unwrap().clear();
        while event_rx.try_recv().is_ok() {}

        // Relay drops, then reconnects. Engine must re-subscribe to the
        // session topic — without this, the dApp's next request would go
        // to /dev/null.
        engine
            .handle_transport_event(TransportEvent::Disconnected {
                reason: "code 4010 load balancing".into(),
            })
            .await;
        engine
            .handle_transport_event(TransportEvent::Reconnected)
            .await;
        assert!(
            transport.subscribed.lock().unwrap().contains(&topic),
            "session topic must be re-subscribed after reconnect",
        );

        // Drain the synthetic "Disconnected → Error" event before the
        // real assertion.
        while event_rx.try_recv().is_ok() {}

        // dApp's session_request finally arrives via the new subscription.
        // The sym key must still be in the engine's session map for this
        // to decrypt; if reconnect had wiped sessions, decrypt would fail
        // silently and we'd never see RequestReceived.
        let req = JsonRpcRequest {
            id: 99,
            jsonrpc: JsonRpcVersion,
            method: "wc_sessionRequest".to_string(),
            params: serde_json::to_value(SessionRequestParams {
                chain_id: "eip155:1".to_string(),
                request: InnerRequest {
                    method: "personal_sign".to_string(),
                    params: json!(["0xfeed", "0x1111111111111111111111111111111111111111"]),
                    expiry: None,
                },
            })
            .unwrap(),
        };
        let env = encode_envelope_type0(&sym, &serde_json::to_vec(&req).unwrap());
        in_tx
            .send(InboundMessage {
                topic,
                message_b64: envelope_to_b64(&env),
                tag: TAG_SESSION_REQUEST_REQ,
                published_at: None,
            })
            .unwrap();
        let msg = engine.inbound_rx.recv().await.unwrap();
        engine.handle_inbound(msg).await;

        match event_rx.try_recv().unwrap() {
            WcEvent::RequestReceived {
                method, chain_id, ..
            } => {
                assert_eq!(method, "personal_sign");
                assert_eq!(chain_id, "eip155:1");
            }
            other => panic!("expected RequestReceived, got {other:?}"),
        }
    }

    /// A reconnect must not silently drop a pending proposal: the user
    /// could be staring at the approval modal when the relay rotates.
    /// Walking pair → proposal → reconnect → approve verifies the
    /// publish still goes out and the session settles, i.e. nothing in
    /// the proposal/session pipeline depends on relay liveness.
    #[tokio::test(flavor = "current_thread")]
    async fn pending_proposal_survives_reconnect_and_can_be_approved() {
        let (mut engine, transport, in_tx, mut event_rx) = build_engine();
        let pairing_sym = SymKey::random();
        let pairing_topic = derive_topic(&pairing_sym);
        engine
            .handle_command(WcCommand::PairWithUri {
                uri: make_pair_uri(&pairing_sym),
            })
            .await;
        let dapp_kp = EphemeralKeypair::generate();
        inject_propose_msg(&in_tx, pairing_topic, &pairing_sym, &dapp_kp, 42);
        let msg = engine.inbound_rx.recv().await.unwrap();
        engine.handle_inbound(msg).await;
        // Drain Paired + ProposalReceived.
        while event_rx.try_recv().is_ok() {}

        // Relay drops mid-flight; transport reconnects.
        engine
            .handle_transport_event(TransportEvent::Disconnected {
                reason: "code 4010".into(),
            })
            .await;
        engine
            .handle_transport_event(TransportEvent::Reconnected)
            .await;
        while event_rx.try_recv().is_ok() {}

        // pending_proposals entry must still be there — the user can
        // approve as if nothing happened.
        assert!(
            engine.pending_proposals.contains_key(&1),
            "proposal must survive reconnect",
        );
        let pre_publish_count = transport.published.lock().unwrap().len();

        let mut ns = BTreeMap::new();
        ns.insert(
            "eip155".to_string(),
            NamespaceSettled {
                chains: vec!["eip155:1".to_string()],
                accounts: vec!["eip155:1:0x1111111111111111111111111111111111111111".to_string()],
                methods: vec!["personal_sign".to_string()],
                events: vec!["chainChanged".to_string()],
            },
        );
        engine
            .handle_command(WcCommand::ApproveProposal {
                proposal_id: 1,
                namespaces: ns,
                wallet_metadata: wallet_metadata(),
            })
            .await;

        // Approve must publish both the propose-response and the
        // sessionSettle (two new publishes since the snapshot above).
        let post = transport.published.lock().unwrap().len();
        assert_eq!(
            post - pre_publish_count,
            2,
            "approve_proposal must publish propose-response + sessionSettle after reconnect",
        );
        // And the SessionSettled event must fire.
        let mut got_settled = false;
        while let Ok(ev) = event_rx.try_recv() {
            if let WcEvent::SessionSettled { .. } = ev {
                got_settled = true;
                break;
            }
        }
        assert!(got_settled, "expected SessionSettled after approve");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transport_reconnected_resubscribe_failure_emits_error() {
        // After reconnect, batch_subscribe fails. Engine must surface
        // this as an Error rather than panicking — the worst case is
        // the user sees "WalletConnect offline" and relaunches, which
        // is bad UX but not data loss.
        #[derive(Default)]
        struct FailingTransport;
        #[async_trait::async_trait]
        impl RelayTransport for FailingTransport {
            async fn subscribe(&self, _: Topic) -> Result<(), TransportError> {
                Ok(())
            }
            async fn batch_subscribe(&self, _: &[Topic]) -> Result<(), TransportError> {
                Err(TransportError::ConnectionLost)
            }
            async fn publish(&self, _: PublishMessage) -> Result<(), TransportError> {
                Ok(())
            }
            async fn unsubscribe(&self, _: Topic) -> Result<(), TransportError> {
                Ok(())
            }
        }
        let (_in_tx, in_rx) = mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let (tev_tx, tev_rx) = mpsc::unbounded_channel::<TransportEvent>();
        std::mem::forget(cmd_tx);
        std::mem::forget(tev_tx);
        let mut engine = WcEngineRunner::new(
            Box::new(FailingTransport),
            in_rx,
            tev_rx,
            cmd_rx,
            event_tx,
            vec![persisted_session(0xCC, 0x33)],
        );
        // Don't run restore — it'd emit its own error and clutter the
        // assertion. Instead, hop straight to the reconnect path.
        engine
            .handle_transport_event(TransportEvent::Reconnected)
            .await;
        match event_rx.try_recv().unwrap() {
            WcEvent::Error { context, message } => {
                assert_eq!(context, "transport");
                assert!(
                    message.contains("post-reconnect"),
                    "expected 'post-reconnect' marker in {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }
}
