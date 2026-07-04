//! ERC-8213 — *Wallet Signature and Calldata Digest Display*.
//!
//! The standard defines four digest values a wallet must **display** so a signer
//! can independently verify — against a hardware-wallet screen or a co-signer —
//! exactly what a signature authorizes:
//!
//! - **Calldata Digest** = `keccak256( uint256(len(calldata)) ‖ calldata )`.
//!   The length is a 32-byte big-endian `uint256` (the prefix stops two different
//!   calldatas that share a prefix from colliding). `chainId` is deliberately
//!   **not** mixed in, so the same calldata yields the same digest across forks —
//!   the property an auditor cross-checking a transaction wants. (chainId already
//!   lives in the EIP-712 domain hash, where it belongs.)
//! - **EIP-712 Digest** = `keccak256( 0x1901 ‖ domainSeparator ‖ hashStruct(message) )`.
//! - **Domain Hash** = `domainSeparator` = `hashStruct(eip712Domain)`.
//! - **Message Hash** = `hashStruct(message)`.
//!
//! This module is the single canonical computation for those values; the review
//! overlay (`ui::wallet_dashboard::sign_review`) renders them under the exact
//! ERC-8213 labels below.

use alloy::primitives::{B256, U256, keccak256};
use alloy::sol_types::{Eip712Domain, SolStruct};

/// The exact labels ERC-8213 mandates a wallet display each value under. Used
/// verbatim by the review UI so a signer reads the standard's terminology.
pub const CALLDATA_DIGEST_LABEL: &str = "Calldata Digest";
pub const EIP712_DIGEST_LABEL: &str = "EIP-712 Digest";
pub const DOMAIN_HASH_LABEL: &str = "Domain Hash";
pub const MESSAGE_HASH_LABEL: &str = "Message Hash";

/// ERC-8213 **Calldata Digest**: `keccak256( uint256(len(calldata)) ‖ calldata )`.
///
/// The 32-byte big-endian length prefix is part of the pre-image; `chainId` is
/// intentionally omitted (see the module docs). An empty calldata hashes the
/// length word alone (32 zero bytes) — callers that want "no digest for a plain
/// value transfer" should test `calldata.is_empty()` themselves.
pub fn calldata_digest(calldata: &[u8]) -> B256 {
    let mut buf = Vec::with_capacity(32 + calldata.len());
    buf.extend_from_slice(&U256::from(calldata.len()).to_be_bytes::<32>());
    buf.extend_from_slice(calldata);
    keccak256(&buf)
}

/// The three ERC-8213 EIP-712 values for one typed-data signature. Kept together
/// so a caller computes them once (at review-prepare time, from the exact message
/// that will be signed) and the UI can never show one that disagrees with the
/// others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eip712Digests {
    /// `domainSeparator = hashStruct(eip712Domain)`.
    pub domain_hash: B256,
    /// `hashStruct(message)`.
    pub message_hash: B256,
    /// `keccak256( 0x1901 ‖ domainSeparator ‖ hashStruct(message) )` — the 32
    /// bytes the signer's key actually signs over.
    pub digest: B256,
}

impl Eip712Digests {
    /// Compute all three from a concrete typed-data message and its domain. The
    /// two component hashes come from alloy (`domain.separator()`,
    /// `message.eip712_hash_struct()`) and `digest` is reconstructed via
    /// [`from_parts`](Self::from_parts). By the EIP-712 spec that reconstruction is
    /// exactly [`SolStruct::eip712_signing_hash`] — the hash the wallet's signers
    /// produce — so the reviewed digest matches the signed one byte-for-byte
    /// (pinned by `from_parts_matches_the_signing_hash`).
    pub fn of<S: SolStruct>(message: &S, domain: &Eip712Domain) -> Self {
        Self::from_parts(domain.separator(), message.eip712_hash_struct())
    }

    /// Reconstruct the triple from a precomputed domain separator and struct
    /// hash — the ERC-8213 combination a verifier holds when shown "Domain Hash"
    /// and "Message Hash" (display option b): `digest = keccak256( 0x1901 ‖
    /// domainSeparator ‖ hashStruct(message) )`.
    pub fn from_parts(domain_hash: B256, message_hash: B256) -> Self {
        let mut preimage = [0u8; 66];
        preimage[0] = 0x19;
        preimage[1] = 0x01;
        preimage[2..34].copy_from_slice(domain_hash.as_slice());
        preimage[34..66].copy_from_slice(message_hash.as_slice());
        Self {
            domain_hash,
            message_hash,
            digest: keccak256(preimage),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, b256, hex};
    use alloy::sol;

    // The canonical 260-byte Uniswap V3 `exactInputSingle` calldata from the
    // ERC-8213 reference site (app/lib/example.ts). Its digest is pinned below.
    const EXAMPLE_CALLDATA: &[u8] = &hex!(
        "414bf389000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000000000000000bb8000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa960450000000000000000000000000000000000000000000000000000000070dbd880000000000000000000000000000000000000000000000000000000003b9aca0000000000000000000000000000000000000000000000000005d423c655aa00000000000000000000000000000000000000000000000000000000000000000000"
    );

    #[test]
    fn calldata_digest_matches_reference_vector() {
        // Independently computed with foundry `cast keccak` over
        // `uint256(260) ‖ EXAMPLE_CALLDATA`.
        assert_eq!(
            calldata_digest(EXAMPLE_CALLDATA),
            b256!("6b0d1315be5f95c110698e70b199a15b90b47aeb5485368f7542b09caf3b0eee"),
        );
    }

    #[test]
    fn calldata_digest_of_empty_is_keccak_of_length_word() {
        // Pre-image is the 32-byte length word alone (all zero) → the well-known
        // keccak256 of 32 zero bytes.
        assert_eq!(
            calldata_digest(&[]),
            b256!("290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"),
        );
    }

    #[test]
    fn length_prefix_prevents_collision() {
        // The length prefix is what makes these differ: without it a trailing
        // zero byte would be ambiguous.
        assert_ne!(calldata_digest(&[]), calldata_digest(&[0x00]));
        assert_ne!(calldata_digest(&[0x00]), calldata_digest(&[0x00, 0x00]));
        // Same bytes, different length framing must not alias.
        assert_ne!(calldata_digest(&[0xaa]), calldata_digest(&[0xaa, 0x00]));
    }

    // The ERC-8213 site's canonical EIP-712 example: a Permit2 `PermitTransferFrom`
    // (app/lib/example.ts). Reconstructed here as an alloy `SolStruct` so
    // `Eip712Digests::of` is exercised against the standard's own vectors.
    sol! {
        struct TokenPermissions { address token; uint256 amount; }
        struct PermitTransferFrom {
            TokenPermissions permitted;
            address spender;
            uint256 nonce;
            uint256 deadline;
        }
    }

    fn example_permit() -> (PermitTransferFrom, Eip712Domain) {
        let message = PermitTransferFrom {
            permitted: TokenPermissions {
                token: address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
                amount: U256::from(1_000_000_000u64),
            },
            spender: address!("E592427A0AEce92De3Edee1F18E0157C05861564"),
            nonce: U256::ZERO,
            deadline: U256::from(1_893_456_000u64),
        };
        // Permit2's domain: name + chainId + verifyingContract (no version).
        let domain = Eip712Domain {
            name: Some("Permit2".into()),
            version: None,
            chain_id: Some(U256::from(1)),
            verifying_contract: Some(address!("000000000022D473030F116dDEE9F6B43aC78BA3")),
            salt: None,
        };
        (message, domain)
    }

    #[test]
    fn eip712_digests_match_permit2_reference_vectors() {
        let (message, domain) = example_permit();
        let d = Eip712Digests::of(&message, &domain);
        // All three independently computed with foundry `cast`.
        assert_eq!(
            d.domain_hash,
            b256!("866a5aba21966af95d6c7ab78eb2b2fc913915c28be3b9aa07cc04ff903e3f28"),
        );
        assert_eq!(
            d.message_hash,
            b256!("7d1be9b8c7677c8cc6adba965260e35822632ef4eb35ddd5d6aafe26cb1ef882"),
        );
        assert_eq!(
            d.digest,
            b256!("01e5a64a608f03873d795fe77fe6bcd1a15692ee25bc02dd638b8fbc3753625c"),
        );
    }

    #[test]
    fn from_parts_reconstructs_the_digest() {
        let (message, domain) = example_permit();
        let d = Eip712Digests::of(&message, &domain);
        // Rebuilding from just the two component hashes must yield the same triple.
        assert_eq!(Eip712Digests::from_parts(d.domain_hash, d.message_hash), d);
    }

    #[test]
    fn from_parts_matches_the_signing_hash() {
        // The `0x1901` reconstruction (`from_parts`, which `of` delegates to) must
        // equal alloy's `eip712_signing_hash` — the exact hash the wallet's CoW /
        // Safe signers commit to. This is the reviewed==signed guarantee for the
        // EIP-712 fingerprints, independent of `of`'s own implementation.
        let (message, domain) = example_permit();
        assert_eq!(
            Eip712Digests::of(&message, &domain).digest,
            message.eip712_signing_hash(&domain),
        );
    }
}
