//! The WalletConnect state Kao saves in the vault so sessions survive a lock, a quit or a reboot:
//! the crate's `Snapshot` (keys, pairings, sessions, pending work), Kao's own bindings (which
//! account each session is bound to), the outbox of answers not yet delivered, and the relay
//! identity seed (reused at restore so the relay doesn't re-push what Kao already took).
//!
//! Stored as `serde_json` (`#[serde(default)]`-tolerant) inside the vault's `wc_state` row, sealed
//! under the wallet's data key. Every type that holds key material or answers has a hand-written
//! `Debug` (counts only).
//!
//! A message signature that hasn't reached its dapp lives only in this record's outbox — so a
//! restore can send it again — and leaves with its entry; once delivered it belongs to the
//! signed-message history (a delivery learned after a lock travels in [`WcStateRecord::deliveries`]).
//!
//! Residual risk: the crate's `State` / `SymKey` aren't zeroized, and serde temporaries leave
//! copies in freed memory; at-rest encryption is the protection, not memory hygiene.
//!
//! Trust: a record decoded here was written by Kao and authenticated by the vault's AEAD, so the
//! dapp strings in it ([`DappRecord`]) were sanitized at ingress and are converted back verbatim
//! (re-sanitizing would re-clamp an already clamped string).

use std::fmt;

use alloy::primitives::{B256, Bytes, hex};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tracing::warn;
use wallet_connect::crypto::Topic;
use wallet_connect::rpc::ErrorObject;
use zeroize::Zeroizing;

use super::types::{DappLabel, RouteKind, WcIdentity};
use crate::vault::{AccountRef, DappRecord, Delivery};

/// [`WcStateRecord::v`] this build writes.
pub const WC_STATE_VERSION: u32 = 1;

/// Everything a restore needs, saved under the vault's `wc_state` row.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WcStateRecord {
    /// [`WC_STATE_VERSION`].
    pub v: u32,
    /// Unix seconds.
    pub saved_at: u64,
    pub relay_url: String,
    /// The route the sessions were made under (a restore never quietly downgrades it).
    pub route_kind: PersistedRoute,
    /// The relay identity's seed; zeroized on drop.
    pub identity_seed: Option<SeedHex>,
    pub snapshot: wallet_connect::sign::Snapshot,
    pub next_ordinal: u32,
    pub sessions: Vec<PersistedSession>,
    /// Undelivered answers (write-ahead), re-sent at restore.
    pub outbox: Vec<PersistedAnswer>,
    /// Message signatures whose delivery became known after the vault epoch ended (a lock's
    /// suspend delivered them, or a dapp stopped waiting meanwhile): the history learns it at the
    /// next unlock, whatever becomes of the sessions.
    pub deliveries: Vec<PersistedDelivery>,
}

impl WcStateRecord {
    /// `serde_json` straight into a zeroizing buffer sized by a first counting pass, so the
    /// plaintext never leaves copies behind in a growing `Vec`.
    ///
    /// Serialization can't fail for this type in practice (every map key serializes as a string);
    /// if it ever did, the error is logged (shape only) and the buffer comes back empty — which a
    /// restore reads as undecodable, i.e. nothing to restore.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut counter = ByteCounter(0);
        if serde_json::to_writer(&mut counter, self).is_err() {
            warn!("WalletConnect state could not be encoded");
            return Zeroizing::new(Vec::new());
        }
        let mut out = Zeroizing::new(Vec::with_capacity(counter.0));
        if serde_json::to_writer(&mut *out, self).is_err() {
            warn!("WalletConnect state could not be encoded");
            out.clear();
        }
        out
    }

    /// Parse a saved record. The error never quotes the input (serde_json's messages can).
    pub fn decode(b: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(b).map_err(|e| {
            format!(
                "saved WalletConnect state is unreadable ({:?} at line {}, column {})",
                e.classify(),
                e.line(),
                e.column()
            )
        })
    }

    /// Saved sessions Kao bound to an account.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

/// Counts only: the record holds the relay identity, session keys and answers.
impl fmt::Debug for WcStateRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WcStateRecord")
            .field("v", &self.v)
            .field("saved_at", &self.saved_at)
            .field("route_kind", &self.route_kind)
            .field("identity_seed", &self.identity_seed.is_some())
            .field("snapshot", &self.snapshot)
            .field("next_ordinal", &self.next_ordinal)
            .field("sessions", &self.sessions.len())
            .field("outbox", &self.outbox.len())
            .field("deliveries", &self.deliveries.len())
            .finish_non_exhaustive()
    }
}

/// `std::io::Write` that only counts bytes (the first pass of [`WcStateRecord::encode`]).
struct ByteCounter(usize);

impl std::io::Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// One session Kao bound (the book's binding), keyed by its topic in the snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersistedSession {
    pub topic: Topic,
    pub pairing_topic: Topic,
    #[serde(default)]
    pub ordinal: u32,
    pub identity: PersistedIdentity,
    #[serde(default)]
    pub identity_label: String,
    #[serde(default)]
    pub chains: Vec<u64>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default)]
    pub dapp: DappRecord,
    /// Unix seconds (the dapp's session expiry).
    #[serde(default)]
    pub expiry: u64,
    #[serde(default)]
    pub paused: bool,
}

/// [`WcIdentity`] as saved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistedIdentity {
    Eoa {
        address: alloy::primitives::Address,
    },
    Safe {
        address: alloy::primitives::Address,
        chain_id: u64,
    },
}

/// An answer accepted but not known delivered — re-sent at restore, never refused.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PersistedAnswer {
    pub topic: Topic,
    pub id: u64,
    pub answer: Result<serde_json::Value, ErrorObject>,
    /// The transaction this answer may stand for (a refusal must then say "unconfirmed").
    #[serde(default)]
    pub unconfirmed_tx: Option<B256>,
    /// The answer is a message signature (its delivery updates the signed-message history).
    #[serde(default)]
    pub signed_message: bool,
    /// The dapp's own deadline for the request (unix seconds), if it set one: past it the crate
    /// drops the request unanswered, so a restore can't take a missing request for a delivered
    /// answer.
    #[serde(default)]
    pub dapp_deadline: Option<u64>,
}

/// Never the answer itself (a signature or a transaction hash).
impl fmt::Debug for PersistedAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let topic: String = self.topic.as_str().chars().take(8).collect();
        f.debug_struct("PersistedAnswer")
            .field("topic", &format_args!("{topic}…"))
            .field("id", &self.id)
            .field("ok", &self.answer.is_ok())
            .field("unconfirmed_tx", &self.unconfirmed_tx.is_some())
            .field("signed_message", &self.signed_message)
            .field("dapp_deadline", &self.dapp_deadline)
            .finish()
    }
}

/// How a message signature's delivery ended, learned too late for the vault epoch it was signed
/// in ([`WcStateRecord::deliveries`]).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PersistedDelivery {
    pub topic: Topic,
    pub id: u64,
    pub delivery: Delivery,
    /// The raw signature of a `Delivered` one — it reached the dapp, so the history keeps it.
    #[serde(default)]
    pub signature: Option<Bytes>,
}

/// Never the signature.
impl fmt::Debug for PersistedDelivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let topic: String = self.topic.as_str().chars().take(8).collect();
        f.debug_struct("PersistedDelivery")
            .field("topic", &format_args!("{topic}…"))
            .field("id", &self.id)
            .field("delivery", &self.delivery)
            .field("signature", &self.signature.is_some())
            .finish()
    }
}

/// [`RouteKind`] as saved. A record missing it reads as `Proxied` — the most private, so a restore
/// over a direct route then asks the user first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistedRoute {
    #[default]
    Proxied,
    Direct,
    Loopback,
}

impl From<RouteKind> for PersistedRoute {
    fn from(k: RouteKind) -> Self {
        match k {
            RouteKind::Proxied => Self::Proxied,
            RouteKind::Direct => Self::Direct,
            RouteKind::Loopback => Self::Loopback,
        }
    }
}

impl From<PersistedRoute> for RouteKind {
    fn from(k: PersistedRoute) -> Self {
        match k {
            PersistedRoute::Proxied => Self::Proxied,
            PersistedRoute::Direct => Self::Direct,
            PersistedRoute::Loopback => Self::Loopback,
        }
    }
}

/// The relay identity's 32-byte seed (`IdentityKey::seed`), hex in JSON, zeroized on drop.
#[derive(Clone)]
pub struct SeedHex(Zeroizing<[u8; 32]>);

impl SeedHex {
    pub fn new(seed: [u8; 32]) -> Self {
        Self(Zeroizing::new(seed))
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SeedHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SeedHex(..)")
    }
}

impl Serialize for SeedHex {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let encoded = Zeroizing::new(hex::encode(self.0.as_slice()));
        s.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for SeedHex {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = Zeroizing::new(String::deserialize(d)?);
        let mut seed = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(s.as_str(), seed.as_mut_slice())
            .map_err(|_| serde::de::Error::custom("identity seed is not 32 bytes of hex"))?;
        Ok(Self(seed))
    }
}

// ───────────────────────────── conversions ─────────────────────────────

impl From<&DappLabel> for DappRecord {
    fn from(d: &DappLabel) -> Self {
        Self {
            name: d.name.clone(),
            host: d.host.clone(),
            url: d.url.clone(),
            description: d.description.clone(),
            insecure_scheme: d.insecure_scheme,
        }
    }
}

impl From<DappLabel> for DappRecord {
    fn from(d: DappLabel) -> Self {
        Self {
            name: d.name,
            host: d.host,
            url: d.url,
            description: d.description,
            insecure_scheme: d.insecure_scheme,
        }
    }
}

impl From<DappRecord> for DappLabel {
    fn from(d: DappRecord) -> Self {
        Self {
            name: d.name,
            host: d.host,
            url: d.url,
            description: d.description,
            insecure_scheme: d.insecure_scheme,
        }
    }
}

impl From<&DappRecord> for DappLabel {
    fn from(d: &DappRecord) -> Self {
        d.clone().into()
    }
}

impl From<WcIdentity> for PersistedIdentity {
    fn from(i: WcIdentity) -> Self {
        match i {
            WcIdentity::Eoa { address } => Self::Eoa { address },
            WcIdentity::Safe { address, chain_id } => Self::Safe { address, chain_id },
        }
    }
}

impl From<PersistedIdentity> for WcIdentity {
    fn from(i: PersistedIdentity) -> Self {
        match i {
            PersistedIdentity::Eoa { address } => Self::Eoa { address },
            PersistedIdentity::Safe { address, chain_id } => Self::Safe { address, chain_id },
        }
    }
}

/// `(identity, the label Kao shows for it)` → the history's account reference.
impl From<(WcIdentity, String)> for AccountRef {
    fn from((identity, label): (WcIdentity, String)) -> Self {
        match identity {
            WcIdentity::Eoa { address } => Self::Eoa { address, label },
            WcIdentity::Safe { address, chain_id } => Self::Safe {
                address,
                chain_id,
                label,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;

    fn session(topic: &str) -> PersistedSession {
        PersistedSession {
            topic: Topic::new(topic),
            pairing_topic: Topic::new("pp"),
            ordinal: 2,
            identity: PersistedIdentity::Safe {
                address: Address::repeat_byte(0x22),
                chain_id: 8453,
            },
            identity_label: "Treasury".into(),
            chains: vec![8453],
            methods: vec!["personal_sign".into()],
            events: vec![],
            dapp: DappRecord {
                name: "Example".into(),
                host: Some("example.org".into()),
                ..Default::default()
            },
            expiry: 1_900_000_000,
            paused: false,
        }
    }

    #[test]
    fn record_round_trips_and_debug_is_counts_only() {
        let rec = WcStateRecord {
            v: WC_STATE_VERSION,
            relay_url: "wss://relay.example".into(),
            route_kind: PersistedRoute::Direct,
            identity_seed: Some(SeedHex::new([0xab; 32])),
            next_ordinal: 3,
            sessions: vec![session("t1")],
            outbox: vec![PersistedAnswer {
                topic: Topic::new("t1"),
                id: 9,
                answer: Ok(serde_json::json!("0xdeadbeef")),
                unconfirmed_tx: None,
                signed_message: true,
                dapp_deadline: Some(1_900_000_100),
            }],
            deliveries: vec![PersistedDelivery {
                topic: Topic::new("t1"),
                id: 8,
                delivery: Delivery::Delivered,
                signature: Some(Bytes::from(vec![0xcd; 65])),
            }],
            ..Default::default()
        };
        let bytes = rec.encode();
        assert_eq!(bytes.len(), bytes.capacity(), "sized by the counting pass");
        let back = WcStateRecord::decode(&bytes).unwrap();
        assert_eq!(back.session_count(), 1);
        assert_eq!(back.sessions, rec.sessions);
        assert_eq!(back.outbox, rec.outbox);
        assert_eq!(back.deliveries, rec.deliveries);
        assert_eq!(back.identity_seed.unwrap().expose(), &[0xab; 32]);
        assert_eq!(back.route_kind, PersistedRoute::Direct);
        let dbg = format!("{rec:?} {:?}", rec.deliveries);
        assert!(
            !dbg.contains("abab") && !dbg.contains("dead") && !dbg.contains("cdcd"),
            "{dbg}"
        );
    }

    #[test]
    fn decode_errors_never_quote_the_input() {
        let err = WcStateRecord::decode(br#"{"v":"secret-text"}"#).unwrap_err();
        assert!(!err.contains("secret"), "{err}");
        let empty = WcStateRecord::decode(b"{}").unwrap();
        assert_eq!(empty.route_kind, PersistedRoute::Proxied);
        assert_eq!(empty.session_count(), 0);
        assert!(
            empty.deliveries.is_empty(),
            "a record from before deliveries"
        );
    }

    /// An answer saved before deadlines were (no `dapp_deadline`) reads as one without a deadline.
    #[test]
    fn an_answer_saved_without_a_deadline_reads_as_none() {
        let record = WcStateRecord::decode(
            br#"{"outbox":[{"topic":"t1","id":4,"answer":{"Ok":"0x01"},"signed_message":true}]}"#,
        )
        .expect("decodes");
        assert_eq!(record.outbox.len(), 1);
        assert_eq!(record.outbox[0].dapp_deadline, None);
        assert!(record.outbox[0].signed_message);
    }

    /// The checked-in golden record (`testkit/wc_state_v1.json`, built once from a testkit session:
    /// one session, a request left pending) decodes to its session with its key. A crate bump that
    /// renamed a snapshot field would decode it with that field empty (`State` is
    /// `#[serde(default)]`) — every session then lost at restore — and fails here instead.
    #[test]
    fn golden_record_decodes_with_its_sessions_and_keys() {
        let record = WcStateRecord::decode(include_bytes!("testkit/wc_state_v1.json"))
            .expect("the golden record decodes");
        assert_eq!(record.v, WC_STATE_VERSION);
        assert_eq!(record.session_count(), 1);
        let s = &record.sessions[0];
        assert_eq!(
            s.identity,
            PersistedIdentity::Eoa {
                address: alloy::primitives::address!("ab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb")
            }
        );
        assert_eq!((s.ordinal, s.identity_label.as_str()), (1, "Account 1"));
        assert_eq!(s.chains, vec![1]);
        assert_eq!(s.dapp.host.as_deref(), Some("dapp.example"));
        assert_eq!(record.route_kind, PersistedRoute::Loopback);
        assert!(record.identity_seed.is_some());
        let state = serde_json::to_value(&record.snapshot).expect("serializes");
        let key = state["symKeys"][s.topic.as_str()]
            .as_str()
            .expect("the session's key");
        assert_eq!(key.len(), 64);
        assert_eq!(state["sessions"][s.topic.as_str()]["expiry"], s.expiry);
        assert_eq!(
            state["pendingRequests"].as_object().map(|p| p.len()),
            Some(1)
        );
        // What Kao saves again still carries all of it.
        let again = WcStateRecord::decode(&record.encode()).expect("re-decodes");
        assert_eq!(
            serde_json::to_value(&again.snapshot).expect("serializes"),
            state
        );
    }

    #[test]
    fn conversions_round_trip() {
        let id = WcIdentity::Safe {
            address: Address::repeat_byte(1),
            chain_id: 10,
        };
        assert_eq!(WcIdentity::from(PersistedIdentity::from(id)), id);
        assert_eq!(
            AccountRef::from((id, "Vault".to_string())),
            AccountRef::Safe {
                address: Address::repeat_byte(1),
                chain_id: 10,
                label: "Vault".into(),
            }
        );
        let label = DappLabel {
            name: "n".into(),
            host: Some("h.example".into()),
            url: "https://h.example".into(),
            description: "d".into(),
            insecure_scheme: false,
        };
        assert_eq!(DappLabel::from(DappRecord::from(&label)), label);
        for k in [RouteKind::Proxied, RouteKind::Direct, RouteKind::Loopback] {
            assert_eq!(RouteKind::from(PersistedRoute::from(k)), k);
        }
    }
}
