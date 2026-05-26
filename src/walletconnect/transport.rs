// Phase 1 scaffolding — see `walletconnect/mod.rs`.
#![allow(dead_code)]

//! Relay-transport abstraction.
//!
//! The Sign-protocol engine doesn't care whether the underlying transport
//! is `reown-rust`'s WebSocket relay client, a `tokio-tungstenite` echo
//! server (for tests), or a future self-hosted relay. It only needs the
//! four primitives below.
//!
//! Phase 1 defines the trait shape. The concrete `reown-rust` adapter
//! lands in Phase 2 alongside the engine that consumes this trait — the
//! shape of the adapter (channel-based vs. callback-based, owned-runtime
//! vs. lent-runtime) depends on the engine's needs and is premature to
//! lock down before the engine exists.

use std::time::Duration;

use crate::walletconnect::crypto::Topic;

/// Tag-carrying publish payload. The relay uses `tag` to apply per-method
/// retention policy; see `protocol::TAG_*` constants.
#[derive(Debug, Clone)]
pub struct PublishMessage {
    pub topic: Topic,
    /// Base64-encoded envelope bytes — already the on-wire form. The
    /// engine produces this from `crypto::envelope_to_b64` after sealing.
    pub message_b64: String,
    pub tag: u32,
    pub ttl: Duration,
    /// `prompt=true` triggers push-notification dispatch on the relay side
    /// (when the dApp/wallet has registered Web3Inbox). Wallets typically
    /// don't set this; dApps do, for `sessionRequest`.
    pub prompt: bool,
}

/// A message read from the relay. The engine decrypts and dispatches based
/// on `topic` (which session/pairing) and tag.
#[derive(Debug, Clone)]
pub struct InboundMessage {
    pub topic: Topic,
    pub message_b64: String,
    pub tag: u32,
    /// `published_at` is set by the relay; messages buffered across the
    /// wallet being offline carry their original publish timestamp.
    /// `None` for live messages where the relay didn't backfill it.
    pub published_at: Option<i64>,
}

/// Out-of-band transport lifecycle events. Sit on a separate channel from
/// [`InboundMessage`] so the engine can react to reconnect *without* needing
/// the transport to fabricate synthetic relay messages.
///
/// The relay drops every subscription on disconnect — on `Reconnected` the
/// engine MUST re-`batch_subscribe` every pairing and session topic it knows
/// about, otherwise inbound messages on those topics will silently never
/// arrive again.
#[derive(Debug, Clone)]
pub enum TransportEvent {
    /// The relay closed the underlying connection. The transport is
    /// already attempting to reconnect with backoff; `reason` is whatever
    /// the close frame (or wrapping error) said, for UI surfacing.
    Disconnected { reason: String },
    /// Reconnect succeeded. Caller must re-subscribe to every topic it
    /// expects to receive on.
    Reconnected,
}

/// Transport-layer errors. Concrete adapter implementations map their
/// native error types onto these — the engine doesn't need to know whether
/// the underlying failure was DNS, TLS, or relay-rejected.
#[derive(Debug)]
pub enum TransportError {
    /// Not connected or connection dropped. Adapter may auto-reconnect on
    /// the next call; the engine retries on `ConnectionLost`.
    ConnectionLost,
    /// Relay returned a JSON-RPC error.
    RelayRejected { code: i32, message: String },
    /// Local-side serialisation or auth-token error.
    Encoding(String),
    /// Any other transport failure (DNS, TLS, generic IO).
    Other(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionLost => f.write_str("relay connection lost"),
            Self::RelayRejected { code, message } => {
                write!(f, "relay rejected request: code {code}, {message}")
            }
            Self::Encoding(s) => write!(f, "encoding error: {s}"),
            Self::Other(s) => write!(f, "transport error: {s}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// The trait the engine consumes. Adapter implementations are async — the
/// trait is intentionally narrow (four methods, no extension points) so a
/// test mock fits in a few dozen lines.
///
/// We use `async_trait` to keep the trait dyn-compatible. The engine holds
/// a `Box<dyn RelayTransport>` so switching between the reown-rust adapter
/// and a test mock is just an alternate construction in the engine setup.
#[async_trait::async_trait]
pub trait RelayTransport: Send + Sync {
    /// Subscribe to a single topic. Returns when the relay has acked the
    /// subscription — required ordering so the caller can safely publish on
    /// the same topic afterwards without racing (critical for sessionSettle,
    /// see the plan's Phase 2 notes).
    async fn subscribe(&self, topic: Topic) -> Result<(), TransportError>;

    /// Subscribe to many topics in a single round trip. Used on engine
    /// startup to resume every persisted session at once — N sessions take
    /// one RTT instead of N. Empty slice is a no-op.
    async fn batch_subscribe(&self, topics: &[Topic]) -> Result<(), TransportError>;

    /// Publish a single envelope to its topic. Returns when the relay has
    /// acked receipt; replies (if any) arrive separately via the inbound
    /// stream the engine reads from.
    async fn publish(&self, msg: PublishMessage) -> Result<(), TransportError>;

    /// Unsubscribe from a topic. Idempotent — unsubscribing from a topic
    /// the relay doesn't know about returns `Ok(())`.
    async fn unsubscribe(&self, topic: Topic) -> Result<(), TransportError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// In-memory transport used by Phase-2 engine tests. Drops every
    /// publish into a local buffer; subscribe is a no-op.
    struct StubTransport {
        published: Mutex<Vec<PublishMessage>>,
    }

    #[async_trait::async_trait]
    impl RelayTransport for StubTransport {
        async fn subscribe(&self, _topic: Topic) -> Result<(), TransportError> {
            Ok(())
        }
        async fn batch_subscribe(&self, _topics: &[Topic]) -> Result<(), TransportError> {
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

    /// Smoke test: confirms the trait is object-safe (can build a
    /// `Box<dyn>` of it) and that an in-memory impl actually compiles.
    /// Regression-guards against accidental `&self` → `&mut self` flips
    /// or generic-method additions that would break dyn dispatch.
    #[tokio::test(flavor = "current_thread")]
    async fn trait_is_dyn_compatible() {
        let stub: Box<dyn RelayTransport> = Box::new(StubTransport {
            published: Mutex::new(Vec::new()),
        });
        let topic = Topic::from_bytes([0u8; 32]);
        stub.subscribe(topic).await.unwrap();
        stub.publish(PublishMessage {
            topic,
            message_b64: "AAAA".to_string(),
            tag: 1100,
            ttl: Duration::from_secs(300),
            prompt: false,
        })
        .await
        .unwrap();
    }
}
