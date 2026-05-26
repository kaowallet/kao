// Phase 2 scaffolding — used by Phase 5's app-level integration.
#![allow(dead_code)]

//! `reown-rust`-backed [`RelayTransport`] implementation.
//!
//! [`reown-com/reown-rust`](https://github.com/reown-com/reown-rust)'s
//! `relay_client::websocket::Client` is the canonical WebSocket transport
//! to `wss://relay.walletconnect.com`. This module bridges its API to the
//! engine's [`RelayTransport`] trait so the engine itself stays transport-
//! agnostic and unit-testable against a stub.
//!
//! Construction
//! ------------
//! `connect()` builds an ed25519 keypair, mints a relay JWT, opens the
//! WebSocket, installs a `ConnectionHandler` that funnels every inbound
//! `PublishedMessage` into the returned `mpsc::UnboundedReceiver`, and
//! returns both halves to the caller — the engine owns the transport via
//! `Box<dyn>` and the receiver directly.
//!
//! Identity
//! --------
//! The ed25519 keypair generated here is the **relay-side** client
//! identity, used solely for JWT signing of the relay subscription
//! request. It is independent of every other key in Kao (wallet signing
//! keys, x25519 session keys). The caller picks whether to persist it or
//! mint a fresh one each launch; Kao persists it in the wallet header
//! (Phase 5) so the relay sees a stable `did:key` across restarts.

use std::time::Duration;

use relay_client::{
    ConnectionOptions,
    error::ClientError,
    websocket::{Client, CloseFrame, ConnectionHandler, PublishedMessage},
};
use relay_rpc::{
    auth::{AuthToken, RELAY_WEBSOCKET_ADDRESS, ed25519_dalek::SigningKey},
    domain::{ProjectId, Topic as ReownTopic},
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::warn;

use crate::walletconnect::crypto::{TOPIC_LEN, Topic};
use crate::walletconnect::transport::{
    InboundMessage, PublishMessage, RelayTransport, TransportError, TransportEvent,
};

/// One-second timeout floor for transport futures. Relay RTT is typically
/// 50-200ms; capping individual ops at 10s avoids "stuck forever" UX when
/// the network half-drops without closing the WebSocket.
const OP_TIMEOUT: Duration = Duration::from_secs(10);

/// Default relay JWT TTL. The relay requires re-authentication on each
/// connection; an hour is generous and matches the upstream example.
const DEFAULT_JWT_TTL: Duration = Duration::from_secs(60 * 60);

/// Reconnect backoff floor. The relay's load-balancing close (code 4010)
/// is the dominant disconnect cause; the rebalanced node is usually ready
/// immediately, so starting at 1s recovers fast without hammering on
/// genuine outages.
const RECONNECT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Reconnect backoff ceiling. After enough failures we cap at 30s rather
/// than minutes — the user's online expectation is that a relaunch fixes
/// it within seconds, so we'd rather burn a few extra failed attempts
/// than make them wait minutes after their network comes back.
const RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(30);

pub struct ReownTransport {
    client: Client,
    /// Background task that watches for relay disconnects and re-runs
    /// `client.connect()` with exponential backoff. Aborted on `Drop` so a
    /// dropped transport doesn't keep the reown client (and its event loop)
    /// resurrected forever via the cloned `Client` handle it holds.
    reconnect_task: JoinHandle<()>,
}

impl Drop for ReownTransport {
    fn drop(&mut self) {
        self.reconnect_task.abort();
    }
}

/// Per-engine handler that forwards inbound relay messages into the engine's
/// inbound channel. Kept dead simple — any decryption / dispatch happens in
/// the engine, never here.
struct EngineHandler {
    inbound_tx: mpsc::UnboundedSender<InboundMessage>,
    /// Signal channel into the background reconnect task. On disconnect we
    /// hand the reason string across; the task owns the backoff loop and
    /// the user-facing `TransportEvent` emissions.
    disconnect_tx: mpsc::UnboundedSender<String>,
}

impl ConnectionHandler for EngineHandler {
    fn connected(&mut self) {
        tracing::info!("WalletConnect relay connected");
    }

    fn disconnected(&mut self, frame: Option<CloseFrame>) {
        tracing::warn!(?frame, "WalletConnect relay disconnected");
        let reason = match &frame {
            Some(f) => format!("relay close code={:?} reason={}", f.code, f.reason),
            None => "relay disconnected (no close frame)".to_string(),
        };
        // Send-failure here only happens if the reconnect task has been
        // aborted (transport dropped) — nothing left to do.
        let _ = self.disconnect_tx.send(reason);
    }

    fn message_received(&mut self, message: PublishedMessage) {
        // reown's `Topic` is `Arc<str>` (lowercase hex). Decode to our
        // 32-byte form; if the relay ever sends a malformed topic, drop
        // the message and log — engine state lookups are keyed on the
        // 32-byte form so we can't deliver anyway.
        let topic = match parse_reown_topic(&message.topic) {
            Some(t) => t,
            None => {
                warn!(raw = %message.topic.as_ref(), "relay sent malformed topic");
                return;
            }
        };
        let _ = self.inbound_tx.send(InboundMessage {
            topic,
            message_b64: message.message.to_string(),
            tag: message.tag,
            published_at: Some(message.published_at.timestamp()),
        });
    }

    fn inbound_error(&mut self, error: ClientError) {
        tracing::warn!(%error, "WalletConnect relay inbound error");
    }

    fn outbound_error(&mut self, error: ClientError) {
        tracing::warn!(%error, "WalletConnect relay outbound error");
    }
}

impl ReownTransport {
    /// Open a connection to the relay and wire up the inbound + events
    /// channels. Returns the transport (boxed for `RelayTransport` dispatch),
    /// the receiver the engine reads inbound messages from, and the receiver
    /// the engine watches for [`TransportEvent`]s (reconnect notifications).
    pub async fn connect(
        project_id: impl Into<String>,
        identity_key: SigningKey,
    ) -> Result<
        (
            Self,
            mpsc::UnboundedReceiver<InboundMessage>,
            mpsc::UnboundedReceiver<TransportEvent>,
        ),
        TransportError,
    > {
        Self::connect_at(
            project_id,
            identity_key,
            RELAY_WEBSOCKET_ADDRESS.to_string(),
        )
        .await
    }

    /// Variant with a custom relay address — used by tests against a local
    /// echo server and by users who self-host the relay (Settings override).
    pub async fn connect_at(
        project_id: impl Into<String>,
        identity_key: SigningKey,
        address: String,
    ) -> Result<
        (
            Self,
            mpsc::UnboundedReceiver<InboundMessage>,
            mpsc::UnboundedReceiver<TransportEvent>,
        ),
        TransportError,
    > {
        let project_id: ProjectId = project_id.into().into();
        let opts = mint_connection_options(&project_id, &identity_key, &address)?;

        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (disconnect_tx, disconnect_rx) = mpsc::unbounded_channel();
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let handler = EngineHandler {
            inbound_tx,
            disconnect_tx,
        };
        let client = Client::new(handler);
        client
            .connect(&opts)
            .await
            .map_err(|e| TransportError::Other(format!("relay connect: {e}")))?;

        let reconnect_task = tokio::spawn(reconnect_loop(
            client.clone(),
            project_id,
            identity_key,
            address,
            disconnect_rx,
            events_tx,
        ));

        Ok((
            Self {
                client,
                reconnect_task,
            },
            inbound_rx,
            events_rx,
        ))
    }
}

/// Mint a fresh `ConnectionOptions` (each contains a one-hour JWT signed by
/// the identity key). Factored so the reconnect task can re-mint on each
/// attempt — the JWT TTL is bounded, and we don't know how long the
/// connection lived before dropping.
fn mint_connection_options(
    project_id: &ProjectId,
    identity_key: &SigningKey,
    address: &str,
) -> Result<ConnectionOptions, TransportError> {
    let auth = AuthToken::new("http://localhost") // Origin; placeholder for desktop.
        .aud(address)
        .ttl(DEFAULT_JWT_TTL)
        .as_jwt(identity_key)
        .map_err(|e| TransportError::Encoding(format!("relay JWT: {e}")))?;
    Ok(ConnectionOptions::new(project_id.clone(), auth).with_address(address))
}

/// Background reconnect loop. Drains disconnect signals from the
/// `ConnectionHandler`; for each, emits `Disconnected` to the engine,
/// retries `client.connect()` with exponential backoff until it succeeds,
/// then emits `Reconnected` so the engine knows to re-subscribe.
///
/// Exits when either:
/// * the `disconnect_tx` is dropped (transport gone, reown event loop
///   torn down), or
/// * the `events_tx` peer (engine) is dropped — no point emitting into a
///   closed channel.
async fn reconnect_loop(
    client: Client,
    project_id: ProjectId,
    identity_key: SigningKey,
    address: String,
    mut disconnect_rx: mpsc::UnboundedReceiver<String>,
    events_tx: mpsc::UnboundedSender<TransportEvent>,
) {
    while let Some(reason) = disconnect_rx.recv().await {
        tracing::info!(reason = %reason, "WalletConnect relay reconnect: starting");
        if events_tx
            .send(TransportEvent::Disconnected { reason })
            .is_err()
        {
            return;
        }

        let mut backoff = RECONNECT_INITIAL_BACKOFF;
        loop {
            tokio::time::sleep(backoff).await;
            match mint_connection_options(&project_id, &identity_key, &address) {
                Ok(opts) => match client.connect(&opts).await {
                    Ok(()) => {
                        tracing::info!("WalletConnect relay reconnect: succeeded");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            backoff_secs = backoff.as_secs(),
                            "WalletConnect relay reconnect attempt failed",
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!(error = %e, "WalletConnect JWT mint failed during reconnect");
                }
            }
            backoff = (backoff * 2).min(RECONNECT_MAX_BACKOFF);
        }

        // Drain any extra disconnect signals queued while we were
        // reconnecting — the upstream loop already raced to the new
        // connection, so we only want to fire one Reconnected per cycle.
        while disconnect_rx.try_recv().is_ok() {}

        if events_tx.send(TransportEvent::Reconnected).is_err() {
            return;
        }
    }
}

#[async_trait::async_trait]
impl RelayTransport for ReownTransport {
    async fn subscribe(&self, topic: Topic) -> Result<(), TransportError> {
        let reown_topic = ReownTopic::from(Arc::<str>::from(topic.to_hex()));
        tokio::time::timeout(OP_TIMEOUT, self.client.subscribe(reown_topic))
            .await
            .map_err(|_| TransportError::Other("subscribe timed out".into()))?
            .map_err(|e| TransportError::Other(format!("subscribe: {e}")))?;
        Ok(())
    }

    async fn batch_subscribe(&self, topics: &[Topic]) -> Result<(), TransportError> {
        if topics.is_empty() {
            return Ok(());
        }
        let reown_topics: Vec<ReownTopic> = topics
            .iter()
            .map(|t| ReownTopic::from(Arc::<str>::from(t.to_hex())))
            .collect();
        tokio::time::timeout(OP_TIMEOUT, self.client.batch_subscribe(reown_topics))
            .await
            .map_err(|_| TransportError::Other("batch_subscribe timed out".into()))?
            .map_err(|e| TransportError::Other(format!("batch_subscribe: {e}")))?;
        Ok(())
    }

    async fn publish(&self, msg: PublishMessage) -> Result<(), TransportError> {
        let reown_topic = ReownTopic::from(Arc::<str>::from(msg.topic.to_hex()));
        tokio::time::timeout(
            OP_TIMEOUT,
            self.client.publish(
                reown_topic,
                Arc::<str>::from(msg.message_b64),
                None,
                msg.tag,
                msg.ttl,
                msg.prompt,
            ),
        )
        .await
        .map_err(|_| TransportError::Other("publish timed out".into()))?
        .map_err(|e| TransportError::Other(format!("publish: {e}")))?;
        Ok(())
    }

    async fn unsubscribe(&self, topic: Topic) -> Result<(), TransportError> {
        let reown_topic = ReownTopic::from(Arc::<str>::from(topic.to_hex()));
        tokio::time::timeout(OP_TIMEOUT, self.client.unsubscribe(reown_topic))
            .await
            .map_err(|_| TransportError::Other("unsubscribe timed out".into()))?
            .map_err(|e| TransportError::Other(format!("unsubscribe: {e}")))?;
        Ok(())
    }
}

/// Decode reown's `Arc<str>` topic back into our 32-byte form. Reown stores
/// topics in lowercase hex (matching the relay's wire format) — the inverse
/// of `Topic::to_hex()`.
fn parse_reown_topic(t: &ReownTopic) -> Option<Topic> {
    let s: &str = t.as_ref();
    if s.len() != TOPIC_LEN * 2 {
        return None;
    }
    let mut bytes = [0u8; TOPIC_LEN];
    hex::decode_to_slice(s, &mut bytes).ok()?;
    Some(Topic::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reown_topic_round_trip() {
        let original = Topic::from_bytes([0x42; 32]);
        let as_reown = ReownTopic::from(Arc::<str>::from(original.to_hex()));
        let back = parse_reown_topic(&as_reown).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn rejects_short_topic_hex() {
        let bad = ReownTopic::from(Arc::<str>::from("deadbeef".to_string()));
        assert!(parse_reown_topic(&bad).is_none());
    }
}
