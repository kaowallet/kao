//! EIP-1271 signing for CoW orders placed *from a Safe*.
//!
//! An EOA signs a CoW order with a 65-byte ECDSA signature the orderbook
//! recovers directly (`signingScheme: "eip712"`). A Safe holds no key of its
//! own: the orderbook validates a Safe order by calling
//! `Safe.isValidSignature(orderDigest, signature)` (EIP-1271) and checking the
//! magic return `0x1626ba7e`. The `signature` we submit must be what the Safe's
//! `CompatibilityFallbackHandler` expects — owner signatures over the **Safe
//! message hash**: the EIP-712 `SafeMessage(bytes message)` whose `message` is
//! the abi-encoded CoW order digest, hashed under the *Safe's own* domain (not
//! CoW's). That wrapping is the subtle, easy-to-get-wrong part, so before
//! POSTing we verify the assembled blob against the live contract with
//! [`verify_eip1271_on_chain`]: a wrong derivation (or a since-changed owner
//! set / threshold) fails closed with a clear error instead of POSTing an order
//! the orderbook would reject anyway.
//!
//! Owners sign through [`KaoSigner::sign_eip712`], so software **and** hardware
//! (Ledger / Trezor) owners work — the same path the Safe-TX send flow uses.

use alloy::primitives::{Address, B256, Bytes, FixedBytes};
use alloy::sol;
use alloy::sol_types::{SolCall, SolStruct};

use crate::chain::Chain;
use crate::net::BalanceFetcher;
use crate::safe::tx::{assemble_signatures, safe_domain};
use crate::wallet::KaoSigner;

sol! {
    /// Safe's `SafeMessage(bytes message)` — the struct its `isValidSignature`
    /// wraps an arbitrary 32-byte hash in (as `abi.encode(hash)`) before running
    /// `checkSignatures`. Field name/order are load-bearing: alloy derives the
    /// EIP-712 typehash from them, pinned by `safe_message_typehash_matches_spec`.
    struct SafeMessage {
        bytes message;
    }

    /// EIP-1271 standard validation entrypoint. Returns the magic value
    /// `0x1626ba7e` when `_signature` is valid for the Safe's owner set and
    /// threshold over `_dataHash`.
    function isValidSignature(bytes32 _dataHash, bytes _signature) external view returns (bytes4);
}

/// `isValidSignature(bytes32,bytes)`'s "signature is valid" magic return.
const EIP1271_MAGIC: FixedBytes<4> = FixedBytes([0x16, 0x26, 0xba, 0x7e]);

/// The Safe message hash for an arbitrary 32-byte `data_hash` (here, a CoW
/// order digest): the EIP-712 hash of `SafeMessage { message: abi.encode(data_hash) }`
/// under the Safe's own domain. This is exactly the digest the Safe recovers
/// owner signatures against inside `isValidSignature`.
///
/// `abi.encode(bytes32)` is the 32 bytes verbatim, so `message` is just
/// `data_hash`'s bytes.
pub fn safe_message_hash(data_hash: B256, safe: Address, chain: Chain) -> B256 {
    let msg = SafeMessage {
        message: Bytes::from(data_hash.as_slice().to_vec()),
    };
    msg.eip712_signing_hash(&safe_domain(safe, chain))
}

/// The ERC-8213 [`crate::sign::digest::Eip712Digests`] of the `SafeMessage` an
/// owner signs over `data_hash` (a CoW order digest). `digest` equals
/// [`safe_message_hash`]; the domain / message component hashes let the review's
/// fingerprints section show all three.
pub fn safe_message_digests(
    data_hash: B256,
    safe: Address,
    chain: Chain,
) -> crate::sign::digest::Eip712Digests {
    let msg = SafeMessage {
        message: Bytes::from(data_hash.as_slice().to_vec()),
    };
    crate::sign::digest::Eip712Digests::of(&msg, &safe_domain(safe, chain))
}

/// Build the EIP-1271 `signature` blob for an arbitrary EIP-712 `data_hash`
/// (a CoW order digest when placing, an `OrderCancellations` digest when
/// cancelling): each owner signs the Safe message hash via EIP-712
/// (`SafeMessage`), with an `eth_sign` fallback for hardware/app-versions that
/// reject typed-data; the per-owner blobs are then assembled Safe-style
/// (ascending by signer address). Mirrors the v-byte conventions of
/// [`crate::safe::tx::sign_owner`]: `{27,28}` for EIP-712, `{31,32}` for
/// `eth_sign`.
pub async fn sign_eip1271_digest(
    owners: &[KaoSigner],
    data_hash: B256,
    safe: Address,
    chain: Chain,
) -> Result<Bytes, String> {
    if owners.is_empty() {
        return Err("eip1271: no owners to sign with".to_string());
    }
    let domain = safe_domain(safe, chain);
    let msg = SafeMessage {
        message: Bytes::from(data_hash.as_slice().to_vec()),
    };
    // Identical to `msg.eip712_signing_hash(&domain)` — routed through the
    // helper so the two stay in lockstep and the `eth_sign` fallback signs the
    // same digest the EIP-712 path commits to.
    let message_hash = safe_message_hash(data_hash, safe, chain);
    let mut sigs = Vec::with_capacity(owners.len());
    for owner in owners {
        let blob = match owner.sign_eip712(&msg, &domain).await {
            Ok(sig) => Bytes::from(sig.as_bytes().to_vec()),
            Err(eip712_err) => {
                // eth_sign fallback: sign the message hash as an EIP-191
                // personal message and bump v by 4 (`{27,28}` → `{31,32}`),
                // matching Safe's eth_sign branch in `checkSignatures`. EIP-712
                // failing is the expected fallback trigger (older Ledger apps), so
                // surface the eth_sign attempt's (already-friendly) error if that
                // also fails rather than leaking both raw status words.
                tracing::debug!(error = %eip712_err, "eip1271 owner eip712 sign failed; falling back to eth_sign");
                let sig = owner
                    .sign_eth_message(message_hash.as_slice())
                    .await
                    .map_err(|eth_err| crate::wallet::friendly_signer_error(&eth_err))?;
                let mut b = sig.as_bytes().to_vec();
                b[64] += 4;
                Bytes::from(b)
            }
        };
        sigs.push((owner.address(), blob));
    }
    assemble_signatures(sigs)
}

/// Verify, against the live Safe, that `signature` makes
/// `isValidSignature(data_hash, signature)` return the EIP-1271 magic value —
/// i.e. the orderbook will accept the order (or cancellation). Defense-in-depth
/// before sending, in the spirit of the Safe-TX pre-sign cross-checks: a
/// derivation bug, a stale owner set, or an unmet threshold fails here with a
/// clear message rather than as an opaque orderbook rejection (or, worse, a
/// silently limit-classified order). Uses `call_raw` (skips helios), the same
/// trust posture as the rest of the read-only Safe inspection.
pub async fn verify_eip1271_on_chain(
    net: &dyn BalanceFetcher,
    safe: Address,
    chain: Chain,
    data_hash: B256,
    signature: &Bytes,
) -> Result<(), String> {
    let calldata = isValidSignatureCall {
        _dataHash: data_hash,
        _signature: signature.clone(),
    }
    .abi_encode();
    let ret = net.call_raw(safe, Bytes::from(calldata), chain).await?;
    let magic = isValidSignatureCall::abi_decode_returns(&ret.value)
        .map_err(|e| format!("isValidSignature decode: {e}"))?;
    if magic == EIP1271_MAGIC {
        Ok(())
    } else {
        Err(format!(
            "Safe rejected the EIP-1271 order signature (isValidSignature returned \
             {magic:#x}, not the 0x1626ba7e magic) — refusing to submit the order",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::keccak256;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::sol_types::SolValue;

    fn safe_addr() -> Address {
        Address::from([0x5au8; 20])
    }

    #[test]
    fn safe_message_typehash_matches_spec() {
        // If the `sol!` field name/order ever drifts, the typehash diverges
        // and every EIP-1271 signature we build is rejected on-chain. Pin it.
        let canonical = b"SafeMessage(bytes message)";
        assert_eq!(
            <SafeMessage as SolStruct>::eip712_encode_type().as_bytes(),
            &canonical[..]
        );
    }

    #[test]
    fn safe_message_hash_matches_manual_derivation() {
        // keccak256(0x1901 ‖ safeDomainSeparator ‖ hashStruct), where
        // hashStruct = keccak256(SAFE_MSG_TYPEHASH ‖ keccak256(abi.encode(digest))).
        let digest = B256::repeat_byte(0xCD);
        let safe = safe_addr();
        let chain = Chain::Mainnet;

        let type_hash = keccak256(b"SafeMessage(bytes message)");
        // `message` = abi.encode(bytes32) = the 32 bytes verbatim.
        let encoded_message = digest.abi_encode();
        let struct_hash = keccak256((type_hash, keccak256(&encoded_message)).abi_encode());
        let domain_sep = safe_domain(safe, chain).separator();
        let mut preimage = Vec::with_capacity(2 + 32 + 32);
        preimage.extend_from_slice(&[0x19, 0x01]);
        preimage.extend_from_slice(domain_sep.as_slice());
        preimage.extend_from_slice(struct_hash.as_slice());
        let manual = keccak256(&preimage);

        assert_eq!(safe_message_hash(digest, safe, chain), manual);
    }

    #[test]
    fn safe_message_digests_agree_with_the_hash() {
        // The ERC-8213 triple's `digest` is exactly what an owner signs
        // (`safe_message_hash`), and its components reconstruct that digest — so
        // the review can show Domain/Message hashes that verifiably compose to it.
        let digest = B256::repeat_byte(0x7e);
        let safe = safe_addr();
        let chain = Chain::Mainnet;
        let d = safe_message_digests(digest, safe, chain);
        assert_eq!(d.digest, safe_message_hash(digest, safe, chain));
        assert_eq!(d.domain_hash, safe_domain(safe, chain).separator());
        assert_eq!(
            crate::sign::digest::Eip712Digests::from_parts(d.domain_hash, d.message_hash),
            d,
        );
    }

    #[test]
    fn safe_message_hash_is_chain_and_safe_specific() {
        let digest = B256::repeat_byte(0x01);
        let a = safe_message_hash(digest, safe_addr(), Chain::Mainnet);
        let b = safe_message_hash(digest, safe_addr(), Chain::Base);
        let c = safe_message_hash(digest, Address::from([0x11u8; 20]), Chain::Mainnet);
        assert_ne!(a, b, "domain must bind the chain id");
        assert_ne!(a, c, "domain must bind the verifying Safe");
    }

    #[tokio::test]
    async fn single_owner_blob_recovers_to_owner_over_message_hash() {
        // Full local round-trip of the 1/1 case: the assembled blob must be a
        // 65-byte EIP-712 signature (v∈{27,28}) that recovers to the owner
        // over the Safe message hash — exactly what the Safe's checkSignatures
        // does inside isValidSignature. The contract side is covered by
        // `verify_eip1271_on_chain` at runtime.
        let signer = PrivateKeySigner::random();
        let owner = signer.address();
        let ks = KaoSigner::Local(signer);
        let safe = safe_addr();
        let chain = Chain::Mainnet;
        let digest = B256::repeat_byte(0x42);

        let blob = sign_eip1271_digest(&[ks], digest, safe, chain)
            .await
            .unwrap();
        assert_eq!(blob.len(), 65, "one owner → one 65-byte signature");
        assert!(matches!(blob[64], 27 | 28), "EIP-712 v byte");

        let message_hash = safe_message_hash(digest, safe, chain);
        let sig = alloy::primitives::Signature::from_raw(&blob).unwrap();
        assert_eq!(
            sig.recover_address_from_prehash(&message_hash).unwrap(),
            owner,
            "blob must recover to the owner over the Safe message hash"
        );
    }

    #[tokio::test]
    async fn multi_owner_blob_is_sorted_and_concatenated() {
        // Two owners → 130 bytes, sorted ascending by signer address (Safe's
        // checkSignatures requirement). Each 65-byte slice recovers to its
        // owner; the lower address comes first.
        let s1 = PrivateKeySigner::random();
        let s2 = PrivateKeySigner::random();
        let (a1, a2) = (s1.address(), s2.address());
        let owners = vec![KaoSigner::Local(s1), KaoSigner::Local(s2)];
        let safe = safe_addr();
        let chain = Chain::Mainnet;
        let digest = B256::repeat_byte(0x7e);

        let blob = sign_eip1271_digest(&owners, digest, safe, chain)
            .await
            .unwrap();
        assert_eq!(blob.len(), 130);

        let message_hash = safe_message_hash(digest, safe, chain);
        let first = alloy::primitives::Signature::from_raw(&blob[..65])
            .unwrap()
            .recover_address_from_prehash(&message_hash)
            .unwrap();
        let second = alloy::primitives::Signature::from_raw(&blob[65..])
            .unwrap()
            .recover_address_from_prehash(&message_hash)
            .unwrap();
        assert!(
            first < second,
            "owner signatures sorted ascending by address"
        );
        assert_eq!(
            [first, second]
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>(),
            [a1, a2]
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>(),
            "both owners present"
        );
    }

    #[tokio::test]
    async fn no_owners_is_an_error() {
        let err = sign_eip1271_digest(&[], B256::ZERO, safe_addr(), Chain::Mainnet)
            .await
            .unwrap_err();
        assert!(err.contains("no owners"), "got: {err}");
    }
}
