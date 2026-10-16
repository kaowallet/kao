//! The records Kao keeps in the vault: WalletConnect connection history and signed-message history
//! (what dapps had signed over WalletConnect, and Kao's own CoW Protocol order signatures).
//!
//! Plain data. Every struct is `#[serde(default)]` so a field can be added later without a format
//! break (the vault stores these as `serde_json`, not postcard — see the module doc of
//! [`crate::vault`]); enums that a defaulted struct holds have a `Default` for the same reason.
//!
//! Dapp strings in here ([`DappRecord`], `primary_type`) were sanitized at ingress (`DappLabel`,
//! the typed-data model) before they were recorded; they are rendered only in mono boxes or as
//! "calls itself …", like everywhere else. A CoW record's token symbols ([`CowOrderRecord`]) come
//! from token metadata, not a dapp, but are just as untrusted: the pane sanitizes them on display.
//!
//! [`SignedRecord`], [`NewSigned`] and [`SignedPayload`] carry what was signed and the signature,
//! so their `Debug` is hand-written and prints neither.

use std::fmt;

use alloy::primitives::{Address, B256, Bytes, U256};
use serde::{Deserialize, Serialize};

// ───────────────────────────── shared parts ─────────────────────────────

/// The dapp as Kao recorded it — a `DappLabel` at the time (`walletconnect::persist` converts).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DappRecord {
    pub name: String,
    pub host: Option<String>,
    pub url: String,
    pub description: String,
    pub insecure_scheme: bool,
}

/// The account a connection or signature was for, with the label Kao showed for it then.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountRef {
    Eoa {
        address: Address,
        #[serde(default)]
        label: String,
    },
    Safe {
        address: Address,
        chain_id: u64,
        #[serde(default)]
        label: String,
    },
}

/// Only so the `#[serde(default)]` records can default a missing field; never a real account.
impl Default for AccountRef {
    fn default() -> Self {
        Self::Eoa {
            address: Address::ZERO,
            label: String::new(),
        }
    }
}

impl AccountRef {
    pub fn address(&self) -> Address {
        match self {
            Self::Eoa { address, .. } | Self::Safe { address, .. } => *address,
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Self::Eoa { label, .. } | Self::Safe { label, .. } => label,
        }
    }
}

// ───────────────────────────── connections ─────────────────────────────

/// Whether the dapp acknowledged the session settlement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AckRecord {
    #[default]
    Pending,
    Confirmed,
    Unconfirmed,
}

/// Why a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndReason {
    YouDisconnected,
    DappDisconnected,
    DappDeclined,
    Expired,
    AccountRemoved,
    TurnedOff,
    Forgotten,
    RelayChanged,
    /// Found still open with no live session behind it (it ended while Kao was closed or locked).
    Lost,
}

impl EndReason {
    /// The user-facing sentence for the history row.
    pub fn sentence(self) -> &'static str {
        match self {
            Self::YouDisconnected => "You disconnected",
            Self::DappDisconnected => "The dapp disconnected",
            Self::DappDeclined => "The dapp declined the connection",
            Self::Expired => "Expired",
            Self::AccountRemoved => "Its account was removed from Kao",
            Self::TurnedOff => "You turned WalletConnect off",
            Self::Forgotten => "You told Kao to forget it",
            Self::RelayChanged => "The relay changed",
            Self::Lost => "Ended while Kao was closed",
        }
    }
}

/// One WalletConnect connection, open (`ended_at == None`) or ended.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionRecord {
    /// The row id (per table, `max + 1`). The vault's row key is authoritative over this field.
    pub id: u64,
    pub topic: String,
    pub dapp: DappRecord,
    pub account: AccountRef,
    pub chains: Vec<u64>,
    /// Unix seconds.
    pub connected_at: u64,
    pub ack: AckRecord,
    /// Unix seconds; `None` while the connection is open.
    pub ended_at: Option<u64>,
    pub end: Option<EndReason>,
}

impl ConnectionRecord {
    /// Still open: no end recorded yet. Open records are never pruned or cleared.
    pub fn is_open(&self) -> bool {
        self.ended_at.is_none()
    }
}

/// A connection to record (the vault assigns the id; it starts open).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NewConnection {
    pub topic: String,
    pub dapp: DappRecord,
    pub account: AccountRef,
    pub chains: Vec<u64>,
    pub connected_at: u64,
    pub ack: AckRecord,
}

// ───────────────────────────── signed messages ─────────────────────────────

/// Whether a signed answer reached the dapp — for a CoW signature, whether the orderbook took it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Delivery {
    /// Not known to have reached the dapp (also the default for a record missing the field — the
    /// signature-on-disk rule then keeps only its hash). A CoW record stays here when Kao locked
    /// or quit before the orderbook answered.
    #[default]
    Sending,
    Delivered,
    NotDelivered,
}

/// Where a signature request came from: a dapp over WalletConnect, or Kao's own CoW swap (an order,
/// or the off-chain cancellation of one), whose delivery is the orderbook taking it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignOrigin {
    WalletConnect {
        topic: String,
        request_id: u64,
        /// The session's ordinal as the pane showed it ("dapp #3").
        #[serde(default)]
        session_ordinal: u32,
        #[serde(default)]
        dapp: DappRecord,
    },
    /// A CoW Protocol sell order: the GPv2 `Order` (EIP-712), signed by the account or, for a
    /// Safe, an EIP-1271 SafeMessage over its digest.
    CowOrder {
        #[serde(default)]
        order: CowOrderRecord,
    },
    /// The off-chain cancellation of a CoW order (`OrderCancellations`, EIP-712 — or a Safe's
    /// EIP-1271 SafeMessage over its digest). `order` is the order it cancels, as Kao tracked it.
    CowCancel {
        #[serde(default)]
        order: CowOrderRecord,
    },
}

/// The CoW order a signature placed or cancelled, for the history row: what it sells and the least
/// it buys. Symbols are token metadata — untrusted, sanitized on display.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CowOrderRecord {
    /// The order's UID: `0x` + 56 bytes (`orderDigest ‖ owner ‖ validTo`).
    pub uid: String,
    pub sell_token: Address,
    pub sell_symbol: String,
    pub sell_decimals: u8,
    /// Atoms sold.
    pub sell_amount: U256,
    pub buy_token: Address,
    pub buy_symbol: String,
    pub buy_decimals: u8,
    /// The least the order buys, in atoms (the signed `buyAmount`).
    pub buy_amount: U256,
    /// Unix seconds.
    pub valid_to: u32,
}

/// Only so the `#[serde(default)]` records can default a missing field.
impl Default for SignOrigin {
    fn default() -> Self {
        Self::WalletConnect {
            topic: String::new(),
            request_id: 0,
            session_ordinal: 0,
            dapp: DappRecord::default(),
        }
    }
}

/// Exactly what was signed: the message bytes (hex in JSON) or the typed-data JSON.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignedPayload {
    Message {
        #[serde(with = "hex_bytes")]
        bytes: Vec<u8>,
    },
    TypedData {
        json: String,
    },
}

impl Default for SignedPayload {
    fn default() -> Self {
        Self::Message { bytes: Vec::new() }
    }
}

impl SignedPayload {
    /// Bytes of payload held (the vault's size-based pruning counts these).
    pub fn len(&self) -> usize {
        match self {
            Self::Message { bytes } => bytes.len(),
            Self::TypedData { json } => json.len(),
        }
    }
}

impl fmt::Debug for SignedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message { bytes } => write!(f, "Message({} bytes)", bytes.len()),
            Self::TypedData { json } => write!(f, "TypedData({} bytes)", json.len()),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignedKind {
    /// `personal_sign` by an EOA.
    #[default]
    Message,
    /// EIP-712 typed data by an EOA: a dapp's `eth_signTypedData(_v4)`, or a CoW order /
    /// cancellation.
    TypedData,
    /// Either of the above by a Safe (an EIP-1271 SafeMessage its owners signed).
    SafeMessage,
}

/// One ERC-8213 fingerprint row, under the label the review showed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DigestRow {
    pub label: String,
    pub hash: B256,
}

/// One signed message.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SignedRecord {
    /// The row id (per table, `max + 1`). The vault's row key is authoritative over this field.
    pub id: u64,
    /// Unix seconds.
    pub at: u64,
    pub origin: SignOrigin,
    pub account: AccountRef,
    pub chain_id: u64,
    pub kind: SignedKind,
    /// The typed data's `primaryType` (sanitized), for `TypedData` / a typed `SafeMessage`.
    pub primary_type: Option<String>,
    pub payload: SignedPayload,
    pub digests: Vec<DigestRow>,
    /// The raw signature. In memory from the moment it is recorded; in this record's row only once
    /// `delivery == Delivered` (a signature that never reached the dapp — or the CoW orderbook — is
    /// not kept as a usable bearer token) — otherwise `None` here after a reload, with only
    /// `signature_hash` / `signature_len`, until a delivery hands it back
    /// (`VaultSession::message_delivery`). An undelivered WalletConnect answer's signature is on
    /// disk only in the encrypted saved-state outbox, for the re-send, and leaves with its outbox
    /// entry; an undelivered CoW signature isn't on disk at all (Kao never re-sends one).
    pub signature: Option<Bytes>,
    /// `keccak256(signature)`.
    pub signature_hash: B256,
    pub signature_len: u32,
    pub delivery: Delivery,
}

impl fmt::Debug for SignedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedRecord")
            .field("id", &self.id)
            .field("at", &self.at)
            .field("kind", &self.kind)
            .field("chain_id", &self.chain_id)
            .field("payload", &self.payload)
            .field("digests", &self.digests.len())
            .field("signature_kept", &self.signature.is_some())
            .field("signature_len", &self.signature_len)
            .field("delivery", &self.delivery)
            .finish_non_exhaustive()
    }
}

/// A signature to record: [`SignedRecord`] minus the id, with the raw signature (the vault
/// derives `signature_hash` / `signature_len` from it).
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NewSigned {
    pub at: u64,
    pub origin: SignOrigin,
    pub account: AccountRef,
    pub chain_id: u64,
    pub kind: SignedKind,
    pub primary_type: Option<String>,
    pub payload: SignedPayload,
    pub digests: Vec<DigestRow>,
    pub signature: Bytes,
    pub delivery: Delivery,
}

impl fmt::Debug for NewSigned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewSigned")
            .field("at", &self.at)
            .field("kind", &self.kind)
            .field("chain_id", &self.chain_id)
            .field("payload", &self.payload)
            .field("digests", &self.digests.len())
            .field("signature_len", &self.signature.len())
            .field("delivery", &self.delivery)
            .finish_non_exhaustive()
    }
}

/// `Vec<u8>` as a `0x`-prefixed hex string (accepts it with or without the prefix).
mod hex_bytes {
    use alloy::primitives::hex;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode_prefixed(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(|_| serde::de::Error::custom("payload bytes are not hex"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_tolerate_missing_fields() {
        let c: ConnectionRecord = serde_json::from_str(r#"{"topic":"ab"}"#).unwrap();
        assert_eq!(c.topic, "ab");
        assert!(c.is_open());
        assert_eq!(c.ack, AckRecord::Pending);
        let s: SignedRecord = serde_json::from_str(r#"{"id":3}"#).unwrap();
        assert_eq!(s.id, 3);
        assert_eq!(s.delivery, Delivery::Sending);
    }

    #[test]
    fn signed_record_round_trips_and_hex_encodes_bytes() {
        let rec = SignedRecord {
            id: 7,
            payload: SignedPayload::Message {
                bytes: b"hello".to_vec(),
            },
            signature: Some(Bytes::from_static(&[1, 2, 3])),
            account: AccountRef::Safe {
                address: Address::repeat_byte(0x11),
                chain_id: 8453,
                label: "Treasury".into(),
            },
            ..Default::default()
        };
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("0x68656c6c6f"), "{json}");
        let back: SignedRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn debug_prints_neither_payload_nor_signature() {
        let rec = NewSigned {
            payload: SignedPayload::TypedData {
                json: "{\"secret\":1}".into(),
            },
            signature: Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
            ..Default::default()
        };
        let dbg = format!("{rec:?}");
        assert!(!dbg.contains("secret") && !dbg.contains("dead"), "{dbg}");
        let full = SignedRecord {
            payload: SignedPayload::Message {
                bytes: b"secret".to_vec(),
            },
            signature: Some(Bytes::from_static(&[0xde, 0xad])),
            ..Default::default()
        };
        let dbg = format!("{full:?}");
        assert!(!dbg.contains("secret") && !dbg.contains("dead"), "{dbg}");
    }

    /// The CoW origins round-trip, and one missing its order (or any order field) still decodes.
    #[test]
    fn cow_origins_round_trip_and_tolerate_missing_fields() {
        let order = CowOrderRecord {
            uid: format!("0x{}", "ab".repeat(56)),
            sell_token: Address::repeat_byte(0x01),
            sell_symbol: "WETH".into(),
            sell_decimals: 18,
            sell_amount: U256::from(10).pow(U256::from(18)),
            buy_token: Address::repeat_byte(0x02),
            buy_symbol: "USDC".into(),
            buy_decimals: 6,
            buy_amount: U256::from(2_400_000_000u64),
            valid_to: 1_900_000_000,
        };
        for origin in [
            SignOrigin::CowOrder {
                order: order.clone(),
            },
            SignOrigin::CowCancel {
                order: order.clone(),
            },
        ] {
            let rec = SignedRecord {
                id: 4,
                origin,
                kind: SignedKind::TypedData,
                ..Default::default()
            };
            let json = serde_json::to_string(&rec).unwrap();
            let back: SignedRecord = serde_json::from_str(&json).unwrap();
            assert_eq!(back, rec);
        }
        let bare: SignedRecord = serde_json::from_str(r#"{"origin":{"CowCancel":{}}}"#).unwrap();
        assert_eq!(
            bare.origin,
            SignOrigin::CowCancel {
                order: CowOrderRecord::default()
            }
        );
        let partial: SignedRecord =
            serde_json::from_str(r#"{"origin":{"CowOrder":{"order":{"sell_symbol":"DAI"}}}}"#)
                .unwrap();
        assert!(
            matches!(&partial.origin, SignOrigin::CowOrder { order } if order.sell_symbol == "DAI")
        );
    }

    #[test]
    fn end_reason_sentences() {
        assert_eq!(EndReason::Lost.sentence(), "Ended while Kao was closed");
        assert_eq!(
            EndReason::DappDeclined.sentence(),
            "The dapp declined the connection"
        );
    }
}
