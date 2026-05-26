// Phase 1 scaffolding — see `walletconnect/mod.rs`.
#![allow(dead_code)]

//! WalletConnect Sign v2 pairing URI parser.
//!
//! Spec: <https://specs.walletconnect.com/2.0/specs/clients/core/pairing/pairing-uri>
//!
//! Shape:
//!
//! ```text
//! wc:<topic-hex64>@2?relay-protocol=irn&symKey=<hex64>&expiryTimestamp=<unix>[&methods=…]
//! ```
//!
//! Mandatory: scheme, topic, version=2, `relay-protocol`, `symKey`. The
//! `expiryTimestamp` field is recommended-but-not-required by the published
//! spec; if present we honour it strictly. `methods` is preserved verbatim
//! as a hint and not interpreted here — the spec is still churning on its
//! encoding (CSV vs URL-encoded JSON array) and pairing decisions don't
//! turn on it.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::walletconnect::crypto::{CryptoError, SYM_KEY_LEN, SymKey, Topic};

/// A `wc:` URI that has passed every structural and crypto check the parser
/// can perform offline. The wallet still needs to evaluate `expiry_age()`
/// against the wall clock before pairing — a URI minted hours ago has been
/// sitting on a clipboard too long, and the symKey-leak window is larger
/// than the pairing-handshake window we care about.
#[derive(Debug, Clone)]
pub struct PairingInvitation {
    pub topic: Topic,
    pub sym_key: SymKey,
    pub relay_protocol: String,
    /// Optional relay-side routing hint (`relay-data` query param). Always
    /// echoed back to the relay during subscription if present.
    pub relay_data: Option<String>,
    /// Unix-seconds expiry. `None` means the URI omitted the field; older
    /// dApps still do.
    pub expiry: Option<u64>,
    /// Raw `methods` query value, undecoded. Not authoritative — the
    /// authoritative method list is in `wc_sessionPropose` request body.
    pub methods_hint: Option<String>,
}

impl PairingInvitation {
    /// `true` iff the URI has an `expiry` field that is in the past relative
    /// to the system clock. Returns `false` if no `expiry` was set.
    pub fn is_expired(&self) -> bool {
        let Some(exp) = self.expiry else {
            return false;
        };
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(now) => now.as_secs() >= exp,
            // System clock is before the Unix epoch — treat as "expiry not
            // checkable" rather than "expired" (matches user intent better
            // when the clock is wonky and the URI was just generated).
            Err(_) => false,
        }
    }

    /// Seconds since the URI was minted, if we can infer it. Returns `None`
    /// when no `expiry` is present or the clock is misaligned. Used by the
    /// UI to warn about URIs older than ~60s — the symKey lives in the
    /// user's clipboard until they paste it, and a long-cached URI hints at
    /// either shoulder-surfing or that the dApp's invitation has been
    /// shared somewhere it shouldn't.
    ///
    /// Note: we approximate "age" as `pairingTtl - timeLeft` using the
    /// spec's pairing TTL of 5 minutes. If the dApp uses a different TTL
    /// the number is off but still monotonic — the UI uses it for a
    /// warning threshold, not a contract.
    pub fn approximate_age_secs(&self) -> Option<u64> {
        const PAIRING_TTL_SECS: u64 = 5 * 60;
        let exp = self.expiry?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        if exp <= now {
            return None;
        }
        let remaining = exp - now;
        if remaining > PAIRING_TTL_SECS {
            return None;
        }
        Some(PAIRING_TTL_SECS - remaining)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum UriError {
    /// Input didn't start with `wc:`.
    NotWcScheme,
    /// Missing the `@<version>` segment.
    MissingVersion,
    /// Version was something other than `2`. v1 URIs are unsupported here.
    UnsupportedVersion(String),
    /// The topic was not 64 lowercase hex characters.
    InvalidTopic,
    /// No query string after the version.
    MissingQuery,
    /// Required `relay-protocol` query parameter was missing.
    MissingRelayProtocol,
    /// Required `symKey` query parameter was missing.
    MissingSymKey,
    /// `symKey` was not 64 hex characters.
    InvalidSymKey,
    /// `expiryTimestamp` was present but not a valid u64.
    InvalidExpiry,
    /// `expiryTimestamp` is in the past — the URI is stale and the
    /// pairing would be refused by the dApp anyway.
    Expired,
    /// Underlying crypto-side error decoding the topic or symKey hex.
    Crypto(CryptoError),
}

impl std::fmt::Display for UriError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotWcScheme => f.write_str("not a wc: URI"),
            Self::MissingVersion => f.write_str("missing @<version> segment"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported WalletConnect version: {v}"),
            Self::InvalidTopic => f.write_str("topic must be 64 hex characters"),
            Self::MissingQuery => f.write_str("URI is missing its query string"),
            Self::MissingRelayProtocol => f.write_str("missing relay-protocol parameter"),
            Self::MissingSymKey => f.write_str("missing symKey parameter"),
            Self::InvalidSymKey => f.write_str("symKey must be 64 hex characters"),
            Self::InvalidExpiry => f.write_str("expiryTimestamp must be a positive integer"),
            Self::Expired => f.write_str("URI has expired"),
            Self::Crypto(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for UriError {}

impl From<CryptoError> for UriError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

/// Parse and validate a `wc:` pairing URI. Returns `Err(UriError::Expired)`
/// when the URI carries an `expiryTimestamp` in the past — the dApp's relay
/// subscription has already lapsed, so attempting to pair would silently
/// fail. Callers wanting to surface expiry differently can match on the
/// error variant.
pub fn parse(uri: &str) -> Result<PairingInvitation, UriError> {
    let rest = uri.strip_prefix("wc:").ok_or(UriError::NotWcScheme)?;

    // Split on '@' once. Both halves must be non-empty.
    let (topic_str, after_at) = rest.split_once('@').ok_or(UriError::MissingVersion)?;
    if topic_str.is_empty() {
        return Err(UriError::InvalidTopic);
    }

    // Validate topic shape first — exact length + valid hex.
    if topic_str.len() != 64 {
        return Err(UriError::InvalidTopic);
    }
    let topic = Topic::from_hex(topic_str).map_err(|_| UriError::InvalidTopic)?;

    // Split version from query on '?'.
    let (version, query) = after_at.split_once('?').ok_or(UriError::MissingQuery)?;
    if version != "2" {
        return Err(UriError::UnsupportedVersion(version.to_string()));
    }

    let mut relay_protocol: Option<String> = None;
    let mut relay_data: Option<String> = None;
    let mut sym_key_hex: Option<String> = None;
    let mut expiry: Option<u64> = None;
    let mut methods_hint: Option<String> = None;

    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        match k.as_ref() {
            "relay-protocol" => relay_protocol = Some(v.into_owned()),
            "relay-data" => relay_data = Some(v.into_owned()),
            "symKey" => sym_key_hex = Some(v.into_owned()),
            "expiryTimestamp" => {
                let parsed: u64 = v.parse().map_err(|_| UriError::InvalidExpiry)?;
                expiry = Some(parsed);
            }
            "methods" => methods_hint = Some(v.into_owned()),
            // Forward-compatibility: silently ignore unknown params so we
            // don't break against future spec additions. The relay sees
            // them anyway since topic/symKey are what determine pairing.
            _ => {}
        }
    }

    let relay_protocol = relay_protocol.ok_or(UriError::MissingRelayProtocol)?;
    if relay_protocol.is_empty() {
        return Err(UriError::MissingRelayProtocol);
    }
    let sym_key_hex = sym_key_hex.ok_or(UriError::MissingSymKey)?;
    if sym_key_hex.len() != 64 {
        return Err(UriError::InvalidSymKey);
    }
    let mut sym_key_bytes = [0u8; SYM_KEY_LEN];
    hex::decode_to_slice(&sym_key_hex, &mut sym_key_bytes).map_err(|_| UriError::InvalidSymKey)?;
    let sym_key = SymKey::from_bytes(sym_key_bytes);

    // Cross-check: `sha256(symKey)` MUST equal `topic`. The dApp computes
    // this same equality; if they disagree, either the URI was corrupted in
    // transit (clipboard mangling, QR scan error) or it was synthesised by
    // someone who didn't have the matching symKey. Either way the pairing
    // would fail on the relay; surfacing it here gives the user a clear
    // error instead of a silent timeout.
    let derived = crate::walletconnect::crypto::derive_topic(&sym_key);
    if derived != topic {
        return Err(UriError::InvalidTopic);
    }

    let invitation = PairingInvitation {
        topic,
        sym_key,
        relay_protocol,
        relay_data,
        expiry,
        methods_hint,
    };

    if invitation.is_expired() {
        return Err(UriError::Expired);
    }

    Ok(invitation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::walletconnect::crypto::{SymKey, derive_topic};

    fn make_uri(sym_key: &SymKey, expiry: Option<u64>, extras: &str) -> String {
        let topic = derive_topic(sym_key);
        let mut s = format!(
            "wc:{}@2?relay-protocol=irn&symKey={}",
            topic.to_hex(),
            hex::encode(sym_key.as_bytes())
        );
        if let Some(e) = expiry {
            s.push_str(&format!("&expiryTimestamp={e}"));
        }
        if !extras.is_empty() {
            s.push('&');
            s.push_str(extras);
        }
        s
    }

    fn future_expiry() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 5 * 60
    }

    #[test]
    fn parses_well_formed_uri() {
        let sym_key = SymKey::from_bytes([0x42; 32]);
        let uri = make_uri(&sym_key, Some(future_expiry()), "");
        let inv = parse(&uri).unwrap();
        assert_eq!(inv.relay_protocol, "irn");
        assert_eq!(inv.sym_key.as_bytes(), &[0x42; 32]);
        assert_eq!(inv.topic, derive_topic(&sym_key));
        assert!(!inv.is_expired());
    }

    #[test]
    fn parses_uri_without_expiry() {
        let sym_key = SymKey::from_bytes([0x11; 32]);
        let uri = make_uri(&sym_key, None, "");
        let inv = parse(&uri).unwrap();
        assert_eq!(inv.expiry, None);
        assert!(!inv.is_expired());
    }

    #[test]
    fn preserves_methods_hint() {
        let sym_key = SymKey::from_bytes([0x33; 32]);
        let uri = make_uri(
            &sym_key,
            Some(future_expiry()),
            "methods=%5B%22wc_sessionPropose%22%5D",
        );
        let inv = parse(&uri).unwrap();
        assert_eq!(inv.methods_hint.as_deref(), Some("[\"wc_sessionPropose\"]"));
    }

    #[test]
    fn ignores_unknown_query_params() {
        let sym_key = SymKey::from_bytes([0x44; 32]);
        let uri = make_uri(
            &sym_key,
            Some(future_expiry()),
            "future-param=hello&another=world",
        );
        assert!(parse(&uri).is_ok());
    }

    #[test]
    fn rejects_non_wc_scheme() {
        assert!(matches!(
            parse("https://example.com"),
            Err(UriError::NotWcScheme)
        ));
        assert!(matches!(parse(""), Err(UriError::NotWcScheme)));
        // Case-sensitive, per the spec.
        assert!(matches!(
            parse("WC:foo@2?bar=1"),
            Err(UriError::NotWcScheme)
        ));
    }

    #[test]
    fn rejects_missing_version() {
        assert!(matches!(parse("wc:abc"), Err(UriError::MissingVersion)));
    }

    #[test]
    fn rejects_v1_uris() {
        // A v1 URI shape gets caught at the version check, not at topic
        // length — that's fine; the message is still actionable.
        let uri = format!("wc:{}@1?bridge=irn", "a".repeat(64));
        assert!(matches!(parse(&uri), Err(UriError::UnsupportedVersion(v)) if v == "1"));
    }

    #[test]
    fn rejects_bad_topic_length() {
        let uri = "wc:short@2?relay-protocol=irn&symKey=00";
        assert!(matches!(parse(uri), Err(UriError::InvalidTopic)));
    }

    #[test]
    fn rejects_topic_symkey_mismatch() {
        // Topic that doesn't equal sha256(symKey) — should fail the
        // cross-check even though both fields are hex-shape-valid.
        let bad_topic = "f".repeat(64);
        let sym_key_hex = hex::encode([0u8; 32]);
        let uri = format!(
            "wc:{bad_topic}@2?relay-protocol=irn&symKey={sym_key_hex}&expiryTimestamp={}",
            future_expiry()
        );
        assert!(matches!(parse(&uri), Err(UriError::InvalidTopic)));
    }

    #[test]
    fn rejects_missing_relay_protocol() {
        let sym_key = SymKey::from_bytes([0x55; 32]);
        let topic = derive_topic(&sym_key).to_hex();
        let sym_key_hex = hex::encode(sym_key.as_bytes());
        let uri = format!("wc:{topic}@2?symKey={sym_key_hex}");
        assert!(matches!(parse(&uri), Err(UriError::MissingRelayProtocol)));
    }

    #[test]
    fn rejects_missing_sym_key() {
        let sym_key = SymKey::from_bytes([0x66; 32]);
        let topic = derive_topic(&sym_key).to_hex();
        let uri = format!("wc:{topic}@2?relay-protocol=irn");
        assert!(matches!(parse(&uri), Err(UriError::MissingSymKey)));
    }

    #[test]
    fn rejects_bad_sym_key_length() {
        let topic = "0".repeat(64);
        let uri = format!("wc:{topic}@2?relay-protocol=irn&symKey=deadbeef");
        assert!(matches!(parse(&uri), Err(UriError::InvalidSymKey)));
    }

    #[test]
    fn rejects_bad_sym_key_hex() {
        let topic = "0".repeat(64);
        let bad_hex = "z".repeat(64);
        let uri = format!("wc:{topic}@2?relay-protocol=irn&symKey={bad_hex}");
        assert!(matches!(parse(&uri), Err(UriError::InvalidSymKey)));
    }

    #[test]
    fn rejects_expired_uris() {
        // Expiry 1 hour in the past.
        let past = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600;
        let sym_key = SymKey::from_bytes([0x77; 32]);
        let uri = make_uri(&sym_key, Some(past), "");
        assert!(matches!(parse(&uri), Err(UriError::Expired)));
    }

    #[test]
    fn rejects_invalid_expiry_format() {
        let sym_key = SymKey::from_bytes([0x88; 32]);
        let topic = derive_topic(&sym_key).to_hex();
        let sym_key_hex = hex::encode(sym_key.as_bytes());
        let uri = format!(
            "wc:{topic}@2?relay-protocol=irn&symKey={sym_key_hex}&expiryTimestamp=not-a-number"
        );
        assert!(matches!(parse(&uri), Err(UriError::InvalidExpiry)));
    }

    #[test]
    fn approximate_age_is_monotonic() {
        // Just after minting, age should be near 0; with 1 minute already
        // elapsed (i.e. expiry only 4 minutes away), age should be ~60s.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sym_key = SymKey::from_bytes([0x99; 32]);

        let fresh = make_uri(&sym_key, Some(now + 5 * 60), "");
        let fresh = parse(&fresh).unwrap();
        let fresh_age = fresh.approximate_age_secs().unwrap();
        assert!(
            fresh_age <= 2,
            "fresh URI age should be ~0, got {fresh_age}"
        );

        let aged = make_uri(&sym_key, Some(now + 4 * 60), "");
        let aged = parse(&aged).unwrap();
        let aged_age = aged.approximate_age_secs().unwrap();
        assert!(
            (58..=62).contains(&aged_age),
            "1-minute-old URI age should be ~60s, got {aged_age}"
        );
    }
}
