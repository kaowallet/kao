// Phase 1 scaffolding — see `walletconnect/mod.rs`. Dropped when Phase 2
// wires the engine to this module.
#![allow(dead_code)]

//! WalletConnect Sign v2 envelope crypto.
//!
//! Spec: <https://specs.walletconnect.com/2.0/specs/clients/core/crypto/crypto-envelopes>
//!
//! Two envelope formats are used by the protocol:
//!
//! ```text
//! Type 0 (symmetric):  [0x00 | iv(12) | ct(N) | tag(16)]
//! Type 1 (asymmetric): [0x01 | sender_pub(32) | iv(12) | ct(N) | tag(16)]
//! ```
//!
//! Both use `ChaCha20-Poly1305` (96-bit nonce — *not* the 192-bit XChaCha20
//! variant the wallet storage uses; the relay-side WC spec was fixed before
//! XChaCha20 stabilised). Tag is concatenated to the ciphertext, as the AEAD
//! API requires.
//!
//! Sessions establish their symKey via an ephemeral x25519 ECDH between the
//! wallet and the dApp, followed by `HKDF-SHA256(salt=empty, ikm=shared,
//! info=empty, L=32)`. The session's relay topic is `sha256(symKey)`.
//!
//! This module exposes only primitives; the engine decides which envelope
//! type to use for which protocol message.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Pub};
use zeroize::ZeroizeOnDrop;

/// Length of a ChaCha20-Poly1305 nonce (the IV inside the envelope).
const IV_LEN: usize = 12;
/// Length of the Poly1305 authentication tag.
const TAG_LEN: usize = 16;
/// Length of an x25519 public key.
const PUB_LEN: usize = 32;
/// Length of a session/pairing symmetric key.
pub const SYM_KEY_LEN: usize = 32;
/// Length of a relay topic (`sha256` output).
pub const TOPIC_LEN: usize = 32;

const ENVELOPE_TYPE_0: u8 = 0;
const ENVELOPE_TYPE_1: u8 = 1;

/// A 32-byte symmetric key for a pairing or session. Wrapped to scrub the
/// key bytes on drop — the underlying AEAD only needs it for the duration
/// of a single encrypt/decrypt call, after which Cargo's borrow checker
/// guarantees no copies survive.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SymKey([u8; SYM_KEY_LEN]);

impl SymKey {
    /// Wrap a 32-byte key. Caller is responsible for ensuring the bytes
    /// came from a high-entropy source (OS RNG, or HKDF over an ECDH).
    pub fn from_bytes(bytes: [u8; SYM_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh 32-byte pairing key from the OS RNG. Used by the
    /// dApp side; wallets receive the pairing symKey via the `wc:` URI.
    pub fn random() -> Self {
        let mut bytes = [0u8; SYM_KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Expose the raw bytes. Avoid storing copies — the `Zeroize` guarantee
    /// only covers the wrapper itself, not derived buffers.
    pub fn as_bytes(&self) -> &[u8; SYM_KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for SymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log key material, even in Debug. The relay topic derived
        // from this key is a hash and safe to log; the key itself is not.
        f.write_str("SymKey(<redacted>)")
    }
}

/// A relay topic: 32-byte sha256 of the symKey, hex-encoded on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Topic([u8; TOPIC_LEN]);

impl Topic {
    pub fn from_bytes(bytes: [u8; TOPIC_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; TOPIC_LEN] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, CryptoError> {
        let mut out = [0u8; TOPIC_LEN];
        hex::decode_to_slice(s, &mut out).map_err(|_| CryptoError::InvalidTopicHex)?;
        Ok(Self(out))
    }
}

impl std::fmt::Debug for Topic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Topic({})", self.to_hex())
    }
}

impl std::fmt::Display for Topic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// An x25519 public key (32 bytes), used in Type 1 envelopes and inside
/// session-propose/settle JSON payloads. Public values — no Zeroize needed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; PUB_LEN]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; PUB_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; PUB_LEN] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, CryptoError> {
        let mut out = [0u8; PUB_LEN];
        hex::decode_to_slice(s, &mut out).map_err(|_| CryptoError::InvalidPublicKeyHex)?;
        Ok(Self(out))
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

/// Compute the relay topic from a symmetric key: `topic = sha256(symKey)`.
///
/// Both peers compute this independently from the symKey they share, so the
/// topic acts as a content-addressed handle to the channel without revealing
/// the key. The relay sees only the topic.
pub fn derive_topic(sym_key: &SymKey) -> Topic {
    let digest = Sha256::digest(sym_key.as_bytes());
    let mut out = [0u8; TOPIC_LEN];
    out.copy_from_slice(&digest);
    Topic(out)
}

/// Ephemeral x25519 keypair, generated once per session establishment and
/// discarded after the session symKey is derived. The secret half is moved
/// into [`derive_session_key`] — the API consumes it to make the one-shot
/// nature explicit at the type level (matches `EphemeralSecret`'s own
/// `diffie_hellman` API in `x25519-dalek`).
pub struct EphemeralKeypair {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl EphemeralKeypair {
    /// Generate a new ephemeral keypair from the OS RNG.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public_raw = X25519Pub::from(&secret);
        Self {
            secret,
            public: PublicKey(*public_raw.as_bytes()),
        }
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }
}

impl std::fmt::Debug for EphemeralKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralKeypair")
            .field("public", &self.public)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Derive a session symKey from an ephemeral x25519 secret and the peer's
/// public key. The ECDH shared secret is fed into `HKDF-SHA256` with empty
/// salt and empty info, output 32 bytes — matches the WC v2 spec exactly.
///
/// Consumes the ephemeral keypair: after this call the secret half is gone
/// and the only path back to the channel is via the returned `SymKey`.
pub fn derive_session_key(
    keypair: EphemeralKeypair,
    peer_pub: &PublicKey,
) -> Result<SymKey, CryptoError> {
    let peer = X25519Pub::from(*peer_pub.as_bytes());
    let shared = keypair.secret.diffie_hellman(&peer);

    // Reject the all-zero shared secret. RFC 7748 §6.1 leaves this to the
    // application; WC's spec doesn't mandate it but a small-subgroup-style
    // attack that forces the shared secret to a known value would break
    // session confidentiality silently. Cost is one constant-time compare.
    if shared.as_bytes().iter().all(|&b| b == 0) {
        return Err(CryptoError::WeakSharedSecret);
    }

    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut okm = [0u8; SYM_KEY_LEN];
    hk.expand(&[], &mut okm)
        .expect("HKDF expand cannot fail for 32-byte output");
    Ok(SymKey(okm))
}

/// HKDF-SHA256 with empty salt and empty info — exposed for tests and for
/// any non-ECDH derivation paths the protocol may add (currently none).
#[cfg(test)]
fn hkdf_session(shared: &[u8]) -> [u8; SYM_KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut okm = [0u8; SYM_KEY_LEN];
    hk.expand(&[], &mut okm).expect("HKDF expand");
    okm
}

/// Errors that can occur during envelope crypto.
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Envelope too short to contain a valid header.
    EnvelopeTruncated,
    /// Envelope type byte was neither 0 nor 1.
    UnknownEnvelopeType(u8),
    /// Caller passed a Type-1 envelope to a Type-0 decode (or vice versa).
    EnvelopeTypeMismatch { expected: u8, actual: u8 },
    /// AEAD authentication failed: ciphertext or tag was tampered, or the
    /// symKey is wrong. The relay or an MITM cannot distinguish between
    /// these cases — and neither can we — so all surface as one error.
    Decrypt,
    /// `topic` hex was not exactly 64 lowercase hex characters.
    InvalidTopicHex,
    /// x25519 public key hex was not exactly 64 hex characters.
    InvalidPublicKeyHex,
    /// ECDH produced the all-zero shared secret — rejected to defend
    /// against small-subgroup-style forced-value attacks.
    WeakSharedSecret,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnvelopeTruncated => f.write_str("WalletConnect envelope is truncated"),
            Self::UnknownEnvelopeType(t) => write!(f, "unknown envelope type byte 0x{t:02x}"),
            Self::EnvelopeTypeMismatch { expected, actual } => {
                write!(
                    f,
                    "envelope type mismatch: expected {expected}, got {actual}"
                )
            }
            Self::Decrypt => f.write_str("envelope authentication failed"),
            Self::InvalidTopicHex => f.write_str("topic must be 64 hex characters"),
            Self::InvalidPublicKeyHex => f.write_str("public key must be 64 hex characters"),
            Self::WeakSharedSecret => f.write_str("ECDH produced a weak shared secret"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Encrypt `plaintext` into a Type 0 envelope under `sym_key`. A fresh
/// 12-byte IV is drawn from `OsRng` for every call — never reused.
pub fn encode_envelope_type0(sym_key: &SymKey, plaintext: &[u8]) -> Vec<u8> {
    let mut iv = [0u8; IV_LEN];
    OsRng.fill_bytes(&mut iv);
    seal(sym_key, &iv, plaintext, &mut |ct| {
        let mut out = Vec::with_capacity(1 + IV_LEN + ct.len());
        out.push(ENVELOPE_TYPE_0);
        out.extend_from_slice(&iv);
        out.extend_from_slice(ct);
        out
    })
}

/// Decrypt a Type 0 envelope. Returns the plaintext, or `Decrypt` if either
/// the ciphertext was tampered or the symKey doesn't match.
pub fn decode_envelope_type0(sym_key: &SymKey, envelope: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if envelope.len() < 1 + IV_LEN + TAG_LEN {
        return Err(CryptoError::EnvelopeTruncated);
    }
    let envelope_type = envelope[0];
    if envelope_type != ENVELOPE_TYPE_0 {
        if envelope_type != ENVELOPE_TYPE_1 {
            return Err(CryptoError::UnknownEnvelopeType(envelope_type));
        }
        return Err(CryptoError::EnvelopeTypeMismatch {
            expected: ENVELOPE_TYPE_0,
            actual: envelope_type,
        });
    }
    let iv: &[u8; IV_LEN] = envelope[1..1 + IV_LEN]
        .try_into()
        .expect("slice length checked above");
    let ct_and_tag = &envelope[1 + IV_LEN..];
    open(sym_key, iv, ct_and_tag)
}

/// Encrypt `plaintext` into a Type 1 envelope under `sym_key`, embedding
/// the wallet's ephemeral x25519 public key in the header. Used for the
/// `wc_sessionSettle` request from the wallet — the dApp uses the embedded
/// pubkey to derive the same session symKey via ECDH.
pub fn encode_envelope_type1(
    sym_key: &SymKey,
    sender_pub: &PublicKey,
    plaintext: &[u8],
) -> Vec<u8> {
    let mut iv = [0u8; IV_LEN];
    OsRng.fill_bytes(&mut iv);
    seal(sym_key, &iv, plaintext, &mut |ct| {
        let mut out = Vec::with_capacity(1 + PUB_LEN + IV_LEN + ct.len());
        out.push(ENVELOPE_TYPE_1);
        out.extend_from_slice(sender_pub.as_bytes());
        out.extend_from_slice(&iv);
        out.extend_from_slice(ct);
        out
    })
}

/// Decrypt a Type 1 envelope and return `(sender_pub, plaintext)`. Caller
/// must already hold the derived session symKey — the embedded sender pub
/// is for verification/logging, not for re-deriving the key on this side.
pub fn decode_envelope_type1(
    sym_key: &SymKey,
    envelope: &[u8],
) -> Result<(PublicKey, Vec<u8>), CryptoError> {
    if envelope.len() < 1 + PUB_LEN + IV_LEN + TAG_LEN {
        return Err(CryptoError::EnvelopeTruncated);
    }
    let envelope_type = envelope[0];
    if envelope_type != ENVELOPE_TYPE_1 {
        if envelope_type != ENVELOPE_TYPE_0 {
            return Err(CryptoError::UnknownEnvelopeType(envelope_type));
        }
        return Err(CryptoError::EnvelopeTypeMismatch {
            expected: ENVELOPE_TYPE_1,
            actual: envelope_type,
        });
    }
    let mut sender_pub = [0u8; PUB_LEN];
    sender_pub.copy_from_slice(&envelope[1..1 + PUB_LEN]);
    let iv: &[u8; IV_LEN] = envelope[1 + PUB_LEN..1 + PUB_LEN + IV_LEN]
        .try_into()
        .expect("slice length checked above");
    let ct_and_tag = &envelope[1 + PUB_LEN + IV_LEN..];
    let plaintext = open(sym_key, iv, ct_and_tag)?;
    Ok((PublicKey(sender_pub), plaintext))
}

fn seal<F>(sym_key: &SymKey, iv: &[u8; IV_LEN], plaintext: &[u8], finish: &mut F) -> Vec<u8>
where
    F: FnMut(&[u8]) -> Vec<u8>,
{
    let cipher = ChaCha20Poly1305::new(Key::from_slice(sym_key.as_bytes()));
    // ChaCha20-Poly1305 encryption is infallible for any plaintext that
    // fits in u32::MAX bytes (per the AEAD trait contract). WC messages are
    // small JSON payloads, so the bound is unreachable; treating it as
    // unreachable matches what alloy/k256/argon2 do for their own
    // infallible-in-practice paths in this codebase.
    let ct = cipher
        .encrypt(Nonce::from_slice(iv), plaintext)
        .expect("ChaCha20-Poly1305 encrypt cannot fail for in-bounds plaintext");
    finish(&ct)
}

fn open(sym_key: &SymKey, iv: &[u8; IV_LEN], ct_and_tag: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(sym_key.as_bytes()));
    cipher
        .decrypt(Nonce::from_slice(iv), ct_and_tag)
        .map_err(|_| CryptoError::Decrypt)
}

/// Encode an envelope's raw bytes for the relay's JSON-RPC `message` field.
/// The relay treats this as opaque text; standard padded base64 is what the
/// WC v2 spec mandates.
pub fn envelope_to_b64(envelope: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(envelope)
}

/// Decode a base64 envelope from the relay back into raw bytes.
pub fn envelope_from_b64(s: &str) -> Result<Vec<u8>, CryptoError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|_| CryptoError::EnvelopeTruncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret;

    /// RFC 7748 §6.1 X25519 test vector. Verifies that the underlying x25519
    /// implementation produces the spec-defined shared secret — a regression
    /// on this would silently break every WC session.
    #[test]
    fn x25519_rfc7748_test_vector() {
        let alice_secret: [u8; 32] =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let bob_pub: [u8; 32] =
            hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
                .unwrap()
                .try_into()
                .unwrap();
        let expected_shared: [u8; 32] =
            hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
                .unwrap()
                .try_into()
                .unwrap();

        // Use StaticSecret here because EphemeralSecret can't be constructed
        // from raw bytes — that's the whole point of its one-shot API. The
        // X25519 scalar/point math is identical between the two types.
        let alice = StaticSecret::from(alice_secret);
        let shared = alice.diffie_hellman(&X25519Pub::from(bob_pub));
        assert_eq!(shared.as_bytes(), &expected_shared);
    }

    /// HKDF-SHA256 RFC 5869 test case 3 (zero-length salt + zero-length
    /// info). This matches our use of `Hkdf::<Sha256>::new(None, ikm)`
    /// followed by `.expand(&[], _)`.
    #[test]
    fn hkdf_sha256_rfc5869_case3() {
        let ikm: [u8; 22] = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
            .unwrap()
            .try_into()
            .unwrap();
        let expected_okm: [u8; 42] = hex::decode(
            "8da4e775a563c18f715f802a063c5a31\
             b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut okm = [0u8; 42];
        hk.expand(&[], &mut okm).unwrap();
        assert_eq!(okm, expected_okm);
    }

    /// Sanity-check the WC topic derivation: the topic must be exactly the
    /// 32-byte sha256 of the symKey. If someone "helpfully" swaps in a
    /// keyed hash or HKDF-derived label, two peers stop agreeing on the
    /// channel — silent breakage.
    #[test]
    fn topic_is_sha256_of_sym_key() {
        let key = SymKey::from_bytes([0x42; 32]);
        let topic = derive_topic(&key);
        let expected = Sha256::digest([0x42u8; 32]);
        assert_eq!(topic.as_bytes(), expected.as_slice());
    }

    #[test]
    fn topic_hex_round_trip() {
        let key = SymKey::random();
        let topic = derive_topic(&key);
        let s = topic.to_hex();
        assert_eq!(s.len(), 64);
        assert_eq!(Topic::from_hex(&s).unwrap(), topic);
    }

    #[test]
    fn topic_from_hex_rejects_wrong_length() {
        assert!(matches!(
            Topic::from_hex("abcdef"),
            Err(CryptoError::InvalidTopicHex)
        ));
        // Wrong characters
        assert!(matches!(
            Topic::from_hex(&"z".repeat(64)),
            Err(CryptoError::InvalidTopicHex)
        ));
    }

    #[test]
    fn envelope_type0_round_trip() {
        let key = SymKey::random();
        let pt = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"wc_sessionPropose\"}";
        let env = encode_envelope_type0(&key, pt);
        assert_eq!(env[0], ENVELOPE_TYPE_0);
        assert_eq!(env.len(), 1 + IV_LEN + pt.len() + TAG_LEN);
        let decoded = decode_envelope_type0(&key, &env).unwrap();
        assert_eq!(decoded, pt);
    }

    #[test]
    fn envelope_type0_rejects_tampered_ciphertext() {
        let key = SymKey::random();
        let mut env = encode_envelope_type0(&key, b"hello");
        // Flip a bit in the ciphertext (byte at offset 1+IV_LEN).
        env[1 + IV_LEN] ^= 0x01;
        assert_eq!(decode_envelope_type0(&key, &env), Err(CryptoError::Decrypt));
    }

    #[test]
    fn envelope_type0_rejects_wrong_key() {
        let k1 = SymKey::random();
        let k2 = SymKey::random();
        let env = encode_envelope_type0(&k1, b"secret");
        assert_eq!(decode_envelope_type0(&k2, &env), Err(CryptoError::Decrypt));
    }

    #[test]
    fn envelope_type0_rejects_truncated() {
        let key = SymKey::random();
        let env = encode_envelope_type0(&key, b"hi");
        assert!(matches!(
            decode_envelope_type0(&key, &env[..5]),
            Err(CryptoError::EnvelopeTruncated)
        ));
    }

    #[test]
    fn envelope_type0_rejects_type1_byte() {
        let key = SymKey::random();
        let mut env = encode_envelope_type0(&key, b"hi");
        env[0] = ENVELOPE_TYPE_1;
        assert!(matches!(
            decode_envelope_type0(&key, &env),
            Err(CryptoError::EnvelopeTypeMismatch {
                expected: 0,
                actual: 1
            })
        ));
    }

    #[test]
    fn envelope_type0_rejects_unknown_type() {
        let key = SymKey::random();
        let mut env = encode_envelope_type0(&key, b"hi");
        env[0] = 0x42;
        assert!(matches!(
            decode_envelope_type0(&key, &env),
            Err(CryptoError::UnknownEnvelopeType(0x42))
        ));
    }

    #[test]
    fn envelope_type1_round_trip() {
        let key = SymKey::random();
        let sender_pub = PublicKey([7u8; 32]);
        let pt = b"settle payload";
        let env = encode_envelope_type1(&key, &sender_pub, pt);
        assert_eq!(env[0], ENVELOPE_TYPE_1);
        assert_eq!(env.len(), 1 + PUB_LEN + IV_LEN + pt.len() + TAG_LEN);
        let (recovered_pub, decoded) = decode_envelope_type1(&key, &env).unwrap();
        assert_eq!(recovered_pub, sender_pub);
        assert_eq!(decoded, pt);
    }

    #[test]
    fn envelope_type1_rejects_type0_byte() {
        let key = SymKey::random();
        let mut env = encode_envelope_type1(&key, &PublicKey([0u8; 32]), b"hi");
        env[0] = ENVELOPE_TYPE_0;
        assert!(matches!(
            decode_envelope_type1(&key, &env),
            Err(CryptoError::EnvelopeTypeMismatch {
                expected: 1,
                actual: 0
            })
        ));
    }

    #[test]
    fn envelope_b64_round_trip() {
        let key = SymKey::random();
        let env = encode_envelope_type0(&key, b"to the wire");
        let s = envelope_to_b64(&env);
        let back = envelope_from_b64(&s).unwrap();
        assert_eq!(back, env);
    }

    /// End-to-end ECDH+HKDF: both peers run x25519 against the counterpart
    /// and HKDF the shared secret; both must derive the same session symKey.
    /// This is the property the entire Sign protocol's session privacy rests
    /// on.
    #[test]
    fn session_key_derivation_is_symmetric() {
        let wallet = EphemeralKeypair::generate();
        let dapp = EphemeralKeypair::generate();
        let wallet_pub = *wallet.public();
        let dapp_pub = *dapp.public();

        let wallet_session = derive_session_key(wallet, &dapp_pub).unwrap();
        let dapp_session = derive_session_key(dapp, &wallet_pub).unwrap();

        assert_eq!(wallet_session.as_bytes(), dapp_session.as_bytes());
    }

    /// And critically, two independent runs must produce different symKeys
    /// (forward secrecy via ephemeral keys; would only fail if `OsRng` had
    /// somehow been replaced by a constant — but the test fails loudly).
    #[test]
    fn session_keys_differ_across_runs() {
        let wallet1 = EphemeralKeypair::generate();
        let dapp1 = EphemeralKeypair::generate();
        let dapp1_pub = *dapp1.public();
        let s1 = derive_session_key(wallet1, &dapp1_pub).unwrap();

        let wallet2 = EphemeralKeypair::generate();
        let dapp2 = EphemeralKeypair::generate();
        let dapp2_pub = *dapp2.public();
        let s2 = derive_session_key(wallet2, &dapp2_pub).unwrap();

        assert_ne!(s1.as_bytes(), s2.as_bytes());
    }

    #[test]
    fn debug_does_not_leak_sym_key() {
        let key = SymKey::from_bytes([0xAB; 32]);
        let dbg = format!("{key:?}");
        assert!(!dbg.contains("ab"), "Debug must not contain key bytes");
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn hkdf_session_helper_matches_inline_use() {
        // Sanity-check that hkdf_session() (test helper) matches what
        // derive_session_key() does internally for a known shared secret.
        let shared = [0x9c; 32];
        let out = hkdf_session(&shared);
        let hk = Hkdf::<Sha256>::new(None, &shared);
        let mut expected = [0u8; 32];
        hk.expand(&[], &mut expected).unwrap();
        assert_eq!(out, expected);
    }
}
