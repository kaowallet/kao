// Phase 2 scaffolding — engine state currently sits in `engine.rs`. Once
// persistence (Phase 5) lands, parts of `PersistedSession` will be wired
// into `wallet/store.rs` and these allows come off.
#![allow(dead_code)]

//! WalletConnect Sign v2 session state.
//!
//! A "pairing" is the short-lived channel established from the `wc:` URI;
//! its symKey is shared with the dApp via the URI itself. The wallet
//! receives one `wc_sessionPropose` on this channel, ECDHs to derive a new
//! per-session symKey, and the long-lived "session" then runs on a fresh
//! topic under the new key.
//!
//! Lifecycle (wallet side):
//!
//! ```text
//!  pair(uri) ──► Pending::Pairing    (subscribed to pairing topic, awaiting propose)
//!                     │
//!                     │   inbound wc_sessionPropose
//!                     ▼
//!                Pending::Proposal   (ECDH done, awaiting user approval)
//!                     │
//!                     │   user approves
//!                     ▼
//!                Settled              (session topic subscribed, settle published)
//!                     │
//!                     │   wc_sessionDelete (either side)
//!                     ▼
//!                  Deleted
//! ```

use std::collections::BTreeMap;
use std::time::Duration;

use crate::walletconnect::crypto::{PublicKey, SymKey, Topic};
use crate::walletconnect::protocol::{NamespaceProposal, NamespaceSettled, PeerMetadata};

/// A pairing waiting for its first `wc_sessionPropose`. Created when the user
/// pastes a `wc:` URI. The pairing topic + symKey come straight from the URI;
/// the dApp will publish `wc_sessionPropose` on this topic exactly once.
///
/// Pairings have a short relay TTL (5 minutes per spec); if no proposal
/// arrives in that window the dApp's invitation has lapsed and we should
/// remove the pairing.
#[derive(Debug)]
pub struct Pairing {
    pub topic: Topic,
    pub sym_key: SymKey,
    /// Wall-clock at which the pairing was created. The relay's pairing-TTL
    /// is 5 minutes — older pairings are stale even if we haven't received
    /// a propose yet.
    pub created_at: std::time::Instant,
}

/// A `wc_sessionPropose` that has been received and decrypted but not yet
/// approved or rejected by the user. The ECDH is already done — wallet has
/// its ephemeral pub, derived session symKey, and derived session topic. We
/// hold onto all three so that approval is a single subscribe+publish call.
///
/// The original JSON-RPC `id` from the dApp's `wc_sessionPropose` request is
/// preserved verbatim: the response we publish on the pairing topic must
/// echo it so the dApp matches the response back to its outstanding request.
#[derive(Debug)]
pub struct PendingProposal {
    /// Engine-local id surfaced to the UI. The UI sends this back in
    /// `WcCommand::Approve/RejectProposal` — never the JSON-RPC id, since
    /// that's a network-supplied value the UI shouldn't echo.
    pub proposal_id: u64,
    /// Pairing topic the proposal arrived on. We publish the
    /// `wc_sessionPropose` response back on this same topic.
    pub pairing_topic: Topic,
    /// The JSON-RPC `id` from the dApp's request. Echoed in the response.
    pub jsonrpc_id: u64,
    /// dApp's ephemeral x25519 public key (from `proposer.publicKey`).
    pub peer_public_key: PublicKey,
    /// Wallet's ephemeral x25519 public key (sent in `responderPublicKey`).
    pub wallet_public_key: PublicKey,
    /// Derived session symKey. Becomes the `Session::sym_key` on approval.
    pub session_sym_key: SymKey,
    /// `sha256(session_sym_key)` — the topic the new session will use.
    pub session_topic: Topic,
    pub peer_metadata: PeerMetadata,
    pub required_namespaces: BTreeMap<String, NamespaceProposal>,
    pub optional_namespaces: BTreeMap<String, NamespaceProposal>,
    pub relay_protocol: String,
}

/// A live, settled session. Keyed in the engine by `topic`. The wallet
/// publishes responses to inbound `wc_sessionRequest`s on this same topic
/// under `sym_key`.
#[derive(Debug)]
pub struct Session {
    pub topic: Topic,
    pub sym_key: SymKey,
    pub peer_metadata: PeerMetadata,
    /// Approved namespaces, in settled form (concrete `accounts` field
    /// populated). The wallet exposes this verbatim back to the dApp as
    /// the truth of "what this session can do".
    pub namespaces: BTreeMap<String, NamespaceSettled>,
    /// Unix seconds at which the session expires. `wc_sessionExtend` updates
    /// this; on expiry the wallet emits `wc_sessionDelete` to the dApp.
    pub expiry: u64,
    pub relay_protocol: String,
}

impl Session {
    /// Lifetime check against the wall clock. Doesn't auto-trigger
    /// deletion — the engine's tick handler runs the actual emit.
    pub fn is_expired(&self) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() >= self.expiry)
            .unwrap_or(false)
    }
}

/// A `wc_sessionRequest` awaiting user decision. The engine emits one
/// `WcEvent::RequestReceived` per request and the UI replies with
/// `ApproveRequest`/`RejectRequest`.
#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub request_id: u64,
    pub session_topic: Topic,
    pub jsonrpc_id: u64,
    pub chain_id: String,
    pub method: String,
    pub params: serde_json::Value,
    /// Optional per-request expiry from `request.expiryTimestamp`. Requests
    /// past expiry must not be processed — the engine drops them and the
    /// UI counterpart auto-prunes the modal slot.
    pub expiry: Option<u64>,
    /// Wall-clock at which the request was received. Used together with
    /// the session-request TTL (5 minutes) to decide when to garbage-
    /// collect requests the user never got to.
    pub received_at: std::time::Instant,
}

/// Persistence-shaped twin of [`PeerMetadata`].
///
/// [`PeerMetadata`] uses `skip_serializing_if = "Option::is_none"` on
/// `redirect` so the on-the-wire JSON omits absent fields. That's the right
/// shape for JSON but breaks postcard's positional schema (no length-prefix
/// on optional fields, so a writer that skipped a field produces bytes a
/// reader can't reconstruct). This type re-declares the same fields without
/// the JSON-specific attribute set so it survives a postcard round-trip
/// inside the redb store.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedPeerMetadata {
    pub name: String,
    pub description: String,
    pub url: String,
    pub icons: Vec<String>,
    pub redirect: Option<PersistedRedirect>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedRedirect {
    pub native: Option<String>,
    pub universal: Option<String>,
}

impl From<PeerMetadata> for PersistedPeerMetadata {
    fn from(m: PeerMetadata) -> Self {
        Self {
            name: m.name,
            description: m.description,
            url: m.url,
            icons: m.icons,
            redirect: m.redirect.map(|r| PersistedRedirect {
                native: r.native,
                universal: r.universal,
            }),
        }
    }
}

impl From<PersistedPeerMetadata> for PeerMetadata {
    fn from(p: PersistedPeerMetadata) -> Self {
        Self {
            name: p.name,
            description: p.description,
            url: p.url,
            icons: p.icons,
            redirect: p
                .redirect
                .map(|r| crate::walletconnect::protocol::Redirect {
                    native: r.native,
                    universal: r.universal,
                }),
        }
    }
}

/// Snapshot of session state suitable for serialising to disk.
///
/// Stored in `wallet.redb`'s `wc_sessions` table keyed by 32-byte topic,
/// encrypted with the wallet's master key under AAD `b"wc_sessions:" ||
/// topic`. Mirror of [`Session`] minus runtime-only fields. `sym_key` is
/// the load-bearing secret — losing it means losing the ability to
/// decrypt the session's relay messages on next launch.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedSession {
    pub topic: [u8; 32],
    pub sym_key: [u8; 32],
    pub peer_metadata: PersistedPeerMetadata,
    pub namespaces: BTreeMap<String, NamespaceSettled>,
    pub expiry: u64,
    pub relay_protocol: String,
}

impl PersistedSession {
    /// Hydrate a runtime [`Session`] from a persisted record. The reverse
    /// (`Session::to_persisted`) lives next to the engine's mutation path.
    pub fn hydrate(self) -> Session {
        Session {
            topic: Topic::from_bytes(self.topic),
            sym_key: SymKey::from_bytes(self.sym_key),
            peer_metadata: self.peer_metadata.into(),
            namespaces: self.namespaces,
            expiry: self.expiry,
            relay_protocol: self.relay_protocol,
        }
    }
}

impl Session {
    pub fn to_persisted(&self) -> PersistedSession {
        PersistedSession {
            topic: *self.topic.as_bytes(),
            sym_key: *self.sym_key.as_bytes(),
            peer_metadata: self.peer_metadata.clone().into(),
            namespaces: self.namespaces.clone(),
            expiry: self.expiry,
            relay_protocol: self.relay_protocol.clone(),
        }
    }
}

/// Spec-defined pairing TTL. Pairings older than this haven't received a
/// `wc_sessionPropose` and the relay has stopped buffering for them.
pub const PAIRING_TTL: Duration = Duration::from_secs(5 * 60);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::walletconnect::crypto::derive_topic;

    #[test]
    fn session_persistence_round_trip() {
        let sym = SymKey::from_bytes([0x55; 32]);
        let topic = derive_topic(&sym);
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
        let session = Session {
            topic,
            sym_key: sym,
            peer_metadata: PeerMetadata {
                name: "TestDapp".to_string(),
                description: "test".to_string(),
                url: "https://test.example".to_string(),
                icons: vec![],
                redirect: None,
            },
            namespaces,
            expiry: 1700000000,
            relay_protocol: "irn".to_string(),
        };

        // postcard is what `wallet/store.rs` uses for encrypted-at-rest
        // payloads. The `PersistedPeerMetadata` twin avoids the JSON
        // `skip_serializing_if` attribute set that breaks postcard's
        // positional schema.
        let persisted = session.to_persisted();
        let bytes = postcard::to_allocvec(&persisted).unwrap();
        let back: PersistedSession = postcard::from_bytes(&bytes).unwrap();
        let hydrated = back.hydrate();

        assert_eq!(hydrated.topic, session.topic);
        assert_eq!(hydrated.sym_key.as_bytes(), session.sym_key.as_bytes());
        assert_eq!(hydrated.expiry, session.expiry);
        assert_eq!(hydrated.namespaces, session.namespaces);
        assert_eq!(hydrated.peer_metadata, session.peer_metadata);
    }

    #[test]
    fn session_persistence_round_trip_preserves_redirect() {
        // Redirect carrying both native and universal links — exercises
        // the nested Option<Option<String>> path that broke postcard
        // before the persisted-twin types landed.
        let sym = SymKey::from_bytes([0x77; 32]);
        let topic = derive_topic(&sym);
        let session = Session {
            topic,
            sym_key: sym,
            peer_metadata: PeerMetadata {
                name: "Linker".to_string(),
                description: "deep-linker dApp".to_string(),
                url: "https://linker.example".to_string(),
                icons: vec!["https://linker.example/icon.png".to_string()],
                redirect: Some(crate::walletconnect::protocol::Redirect {
                    native: Some("linker://".to_string()),
                    universal: Some("https://linker.example/wc".to_string()),
                }),
            },
            namespaces: BTreeMap::new(),
            expiry: 0,
            relay_protocol: "irn".to_string(),
        };
        let bytes = postcard::to_allocvec(&session.to_persisted()).unwrap();
        let hydrated: PersistedSession = postcard::from_bytes(&bytes).unwrap();
        let session2 = hydrated.hydrate();
        let r = session2.peer_metadata.redirect.unwrap();
        assert_eq!(r.native.as_deref(), Some("linker://"));
        assert_eq!(r.universal.as_deref(), Some("https://linker.example/wc"));
    }

    #[test]
    fn session_expiry_is_unix_seconds() {
        let session = Session {
            topic: Topic::from_bytes([0u8; 32]),
            sym_key: SymKey::from_bytes([0u8; 32]),
            peer_metadata: PeerMetadata {
                name: String::new(),
                description: String::new(),
                url: String::new(),
                icons: vec![],
                redirect: None,
            },
            namespaces: BTreeMap::new(),
            expiry: 0, // Unix epoch — definitely in the past.
            relay_protocol: "irn".to_string(),
        };
        assert!(session.is_expired());
    }
}
