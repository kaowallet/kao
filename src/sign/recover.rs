//! Signer recovery checks for message signatures — the `from == signer` wall
//! for signatures that never reach [`super::broadcast`] (WalletConnect
//! `personal_sign` / typed data). A signature is answered to a dapp only after
//! it recovers to the address the review showed.
//!
//! The broadcast primitive refuses a transaction whose signature recovers to
//! anyone but the reviewed sender. A bare signature has no such gate
//! downstream: it leaves the wallet as an answer and is only ever checked by
//! whoever the dapp hands it to. These are that gate, run by every task that
//! hands a signature out.

use alloy::primitives::{Address, B256, Bytes, Signature};
use tracing::warn;

use crate::wallet::short_address;

/// The EIP-191 signature over `message` must recover to `expected`.
///
/// `message` is the exact bytes that were signed; the `"\x19Ethereum Signed
/// Message:\n" ‖ len` prefix is applied here, exactly as
/// `KaoSigner::sign_eth_message` applies it before signing.
pub fn assert_message_signer(
    sig: &Signature,
    message: &[u8],
    expected: Address,
) -> Result<(), String> {
    let recovered = sig
        .recover_address_from_msg(message)
        .map_err(|e| format!("could not recover the signer from the signature: {e}"))?;
    same_signer(recovered, expected)
}

/// A signature over the 32-byte `digest` (e.g. an EIP-712 signing hash) must
/// recover to `expected`.
pub fn assert_prehash_signer(
    sig: &Signature,
    digest: B256,
    expected: Address,
) -> Result<(), String> {
    let recovered = sig
        .recover_address_from_prehash(&digest)
        .map_err(|e| format!("could not recover the signer from the signature: {e}"))?;
    same_signer(recovered, expected)
}

/// r‖s‖v (65 bytes, v ∈ {27,28}) — the form a dapp is answered with.
///
/// `Signature::as_bytes` always writes the Electrum `v` (`27 + y_parity`),
/// whatever form the signer produced it in, so a hardware signature and a
/// software one serialize the same way.
pub fn signature_bytes(sig: &Signature) -> Bytes {
    Bytes::from(sig.as_bytes().to_vec())
}

fn same_signer(recovered: Address, expected: Address) -> Result<(), String> {
    if recovered == expected {
        return Ok(());
    }
    // short_address: log lines never carry full user addresses.
    warn!(
        expected = %short_address(expected),
        recovered = %short_address(recovered),
        "recover: signature does not recover to the reviewed signer",
    );
    Err(format!(
        "the signature recovers to {}, not the reviewed {} — refusing to use it",
        short_address(recovered),
        short_address(expected),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{eip191_hash_message, keccak256};
    use alloy::signers::SignerSync;
    use alloy::signers::local::PrivateKeySigner;

    fn key(seed: u8) -> PrivateKeySigner {
        PrivateKeySigner::from_bytes(&B256::repeat_byte(seed)).expect("valid test key")
    }

    #[test]
    fn assert_message_signer_accepts_the_signer() {
        let k = key(0x11);
        let msg = b"Sign in to app.example";
        let sig = k.sign_message_sync(msg).unwrap();
        assert_eq!(assert_message_signer(&sig, msg, k.address()), Ok(()));
    }

    #[test]
    fn assert_message_signer_rejects_other_key() {
        let signer = key(0x11);
        let reviewed = key(0x22).address();
        let msg = b"Sign in to app.example";
        let sig = signer.sign_message_sync(msg).unwrap();
        let err = assert_message_signer(&sig, msg, reviewed).unwrap_err();
        assert!(err.contains("refusing"), "{err}");
        // The same key over different bytes recovers to some third address —
        // never to the reviewed signer.
        let other = signer.sign_message_sync(b"something else").unwrap();
        assert!(assert_message_signer(&other, msg, signer.address()).is_err());
    }

    #[test]
    fn assert_prehash_signer_accepts_the_signer() {
        let k = key(0x33);
        let digest = keccak256(b"typed data digest");
        let sig = k.sign_hash_sync(&digest).unwrap();
        assert_eq!(assert_prehash_signer(&sig, digest, k.address()), Ok(()));
    }

    #[test]
    fn assert_prehash_signer_rejects_other_key() {
        let signer = key(0x33);
        let reviewed = key(0x44).address();
        let digest = keccak256(b"typed data digest");
        let sig = signer.sign_hash_sync(&digest).unwrap();
        assert!(assert_prehash_signer(&sig, digest, reviewed).is_err());
        // The prehash wall is not the message wall: an EIP-191 signature over
        // the digest's bytes does not pass as a signature over the digest
        // itself — only over its EIP-191 hash.
        let personal = signer.sign_message_sync(digest.as_slice()).unwrap();
        assert!(assert_prehash_signer(&personal, digest, signer.address()).is_err());
        assert_eq!(
            assert_prehash_signer(&personal, eip191_hash_message(digest), signer.address()),
            Ok(())
        );
    }

    #[test]
    fn signature_bytes_v_is_27_or_28() {
        for seed in 1..=16u8 {
            let k = key(seed);
            let sig = k.sign_message_sync(&[seed; 7]).unwrap();
            let bytes = signature_bytes(&sig);
            assert_eq!(bytes.len(), 65, "r‖s‖v");
            let v = bytes[64];
            assert!(v == 27 || v == 28, "v = {v}");
            assert_eq!(v, 27 + u8::from(sig.v()), "v carries the parity");
            assert_eq!(&bytes[..32], sig.r().to_be_bytes::<32>().as_slice());
            assert_eq!(&bytes[32..64], sig.s().to_be_bytes::<32>().as_slice());
        }
    }
}
