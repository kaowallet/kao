//! EIP-7702 batch encoding — let a plain EOA execute N calls atomically by
//! delegating its account code to a batch-executor and self-calling
//! `executeBatch(Call[])`, the EOA analogue of the Safe MultiSend path.
//!
//! The delegate is the **Ethereum Foundation `Simple7702Account`**
//! ([`EF_SIMPLE_7702_ACCOUNT`]) — the eth-infinitism/account-abstraction
//! reference implementation. It is deliberately the *only* delegate this
//! wallet uses: it is audited, and it is the single contract Ledger
//! recognises at the device level, so its `SIGN_EIP7702_AUTHORIZATION`
//! screen shows a meaningful contract instead of a blind-sign warning.
//!
//! Execution shape (self-sponsored — authority == transaction sender):
//! - an authorization tuple `(chain_id, EF_SIMPLE_7702_ACCOUNT, nonce+1)` is
//!   signed by the account (see [`crate::wallet::KaoSigner::sign_authorization`]),
//! - the outer `TxEip7702` has `to = the account itself`, `value = 0`,
//!   `input = executeBatch(calls)`, and carries the signed authorization,
//! - `Simple7702Account.executeBatch` loops the calls, `CALL`ing each as the
//!   account (`msg.sender == address(this)`), drawing each sub-call's `value`
//!   from the account's own balance — atomic, like MultiSend.
//!
//! Because the delegation designator persists on-chain, a subsequent batch
//! from an account **already** delegated to the EF contract needs no fresh
//! authorization (see [`delegated_to`]) — it is broadcast as an ordinary
//! EIP-1559 call to `executeBatch`.

use alloy::dyn_abi::DynSolValue;
use alloy::eips::eip7702::Authorization;
use alloy::primitives::{Address, Bytes, U256, address};

use super::QueuedCall;

/// The Ethereum Foundation `Simple7702Account` delegate
/// (eth-infinitism/account-abstraction). The account's code is set to
/// `0xef0100 ‖ EF_SIMPLE_7702_ACCOUNT` for the duration of the delegation.
///
/// The prepare step additionally verifies this address has code on-chain
/// before signing (a delegation to a code-less address would brick the
/// account), mirroring the MultiSend deployment check.
pub const EF_SIMPLE_7702_ACCOUNT: Address = address!("0x4Cd241E8d1510e30b2076397afc7508Ae59C66c9");

/// `keccak256("executeBatch((address,uint256,bytes)[])")[..4]`.
pub const EXECUTE_BATCH_SELECTOR: [u8; 4] = [0x34, 0xfc, 0xd5, 0xbe];

/// The 3-byte EIP-7702 delegation designator prefix: an account delegated
/// via a `SetCode` tx has code `0xef0100 ‖ <20-byte delegate address>`.
const DELEGATION_PREFIX: [u8; 3] = [0xef, 0x01, 0x00];

/// ABI-encode `executeBatch(Call[])` for the queued calls, where
/// `struct Call { address target; uint256 value; bytes data; }`.
///
/// The bytes produced here are exactly what is simulated, reviewed, and
/// signed — same guarantee as [`super::encode::encode_call`]. Encoding goes
/// through alloy's `DynSolValue` (identical head/tail layout to a compiled
/// `executeBatch` call), so there is no hand-rolled offset math.
pub fn encode_execute_batch(calls: &[QueuedCall]) -> Bytes {
    let elems: Vec<DynSolValue> = calls
        .iter()
        .map(|c| {
            DynSolValue::Tuple(vec![
                DynSolValue::Address(c.to),
                DynSolValue::Uint(c.value, 256),
                DynSolValue::Bytes(c.data.to_vec()),
            ])
        })
        .collect();
    // A single dynamic-array argument: wrap in a param tuple so `abi_encode_params`
    // lays down the `offset ‖ length ‖ elements` head/tail encoding.
    let args = DynSolValue::Tuple(vec![DynSolValue::Array(elems)]).abi_encode_params();
    let mut out = Vec::with_capacity(4 + args.len());
    out.extend_from_slice(&EXECUTE_BATCH_SELECTOR);
    out.extend_from_slice(&args);
    Bytes::from(out)
}

/// Recover the `Call[]` from `executeBatch` calldata — the inverse of
/// [`encode_execute_batch`], decoded through the same alloy type so the round
/// trip is exact.
///
/// The sign review builds its per-call clear-signing panels from *this*, not
/// from the queue the calldata was encoded from: what the user reads is derived
/// from the bytes that will actually be executed.
pub fn decode_execute_batch(calldata: &[u8]) -> Result<Vec<(Address, U256, Bytes)>, String> {
    use alloy::dyn_abi::DynSolType;
    if calldata.len() < 4 || calldata[..4] != EXECUTE_BATCH_SELECTOR {
        return Err("not an executeBatch(Call[]) call".into());
    }
    let ty = DynSolType::Array(Box::new(DynSolType::Tuple(vec![
        DynSolType::Address,
        DynSolType::Uint(256),
        DynSolType::Bytes,
    ])));
    let decoded = DynSolType::Tuple(vec![ty])
        .abi_decode_params(&calldata[4..])
        .map_err(|e| format!("malformed executeBatch calldata: {e}"))?;
    let DynSolValue::Tuple(mut outer) = decoded else {
        return Err("malformed executeBatch calldata".into());
    };
    let Some(DynSolValue::Array(items)) = outer.pop() else {
        return Err("malformed executeBatch calldata".into());
    };
    items
        .into_iter()
        .map(|item| match item {
            DynSolValue::Tuple(fields) => match fields.as_slice() {
                [
                    DynSolValue::Address(to),
                    DynSolValue::Uint(value, _),
                    DynSolValue::Bytes(data),
                ] => Ok((*to, *value, Bytes::from(data.clone()))),
                _ => Err("unexpected executeBatch call shape".to_string()),
            },
            _ => Err("unexpected executeBatch call shape".to_string()),
        })
        .collect()
}

/// Build the authorization tuple to sign for delegating `authority`'s account
/// to the EF delegate on `chain_id`.
///
/// `auth_nonce` is the nonce the tuple commits to. For the self-sponsored
/// case (authority == sender), this MUST be the account's pending nonce **+
/// 1**: the outer `0x04` transaction consumes the current nonce first, so the
/// authorization is validated against the incremented value.
pub fn build_authorization(chain_id: u64, auth_nonce: u64) -> Authorization {
    Authorization {
        chain_id: U256::from(chain_id),
        address: EF_SIMPLE_7702_ACCOUNT,
        nonce: auth_nonce,
    }
}

/// Build the authorization tuple that **removes** an account's delegation.
///
/// EIP-7702 gives the zero address a special meaning: an authorization to
/// `0x0` does not write a designator, it clears the account's code and resets
/// its code hash to the empty hash. The account is a plain EOA again.
///
/// This is a *sibling* of [`build_authorization`] rather than a `delegate`
/// parameter on it, and deliberately so. The delegates this wallet will sign
/// for are meant to be readable off the source — [`EF_SIMPLE_7702_ACCOUNT`] to
/// install, zero to remove, and nothing else. A free `delegate: Address`
/// parameter would let the wallet sign an authorization for any address handed
/// to it, including one read off-chain from an incumbent it did not install,
/// and the only thing left deciding what gets signed would be the caller. Two
/// named constructors keep that decision in this module.
///
/// `auth_nonce` follows the same rule as [`build_authorization`]: the
/// revocation is self-sponsored, so the outer transaction consumes the
/// account's nonce first and the tuple commits to that value **+ 1**.
pub fn build_revocation(chain_id: u64, auth_nonce: u64) -> Authorization {
    Authorization {
        chain_id: U256::from(chain_id),
        address: Address::ZERO,
        nonce: auth_nonce,
    }
}

/// What one EIP-7702 authorization tuple costs up front, in gas.
///
/// The protocol charges `PER_EMPTY_ACCOUNT_COST` per tuple and refunds
/// `PER_EMPTY_ACCOUNT_COST - PER_AUTH_BASE_COST` (12,500) when the authority
/// already exists in the trie — which it always does here, since it is the
/// account paying for the transaction.
///
/// The refund is not a discount on the limit. EIP-3529 caps a transaction's
/// total refund at `gas_used / 5`, so a revocation using ~36,800 gas gets at
/// most ~7,400 back, and a gas limit set to the post-refund figure fails
/// intrinsic validation before it executes. Budget the full cost.
pub const PER_AUTH_GAS: u64 = 25_000;

/// A safe gas limit for a bare revocation transaction: the 21,000 intrinsic
/// plus one authorization, with headroom. The transaction has no calldata and
/// executes no code — by the time the frame runs, the authorization has
/// already cleared the account — so nothing here scales with user input.
pub const REVOKE_GAS_LIMIT: u64 = 21_000 + PER_AUTH_GAS + 10_000;

/// If `code` is an EIP-7702 delegation designator (`0xef0100 ‖ address`),
/// return the delegate address; otherwise `None`. Used to skip re-authorizing
/// an account that already delegates to [`EF_SIMPLE_7702_ACCOUNT`].
pub fn delegated_to(code: &[u8]) -> Option<Address> {
    if code.len() == 23 && code[..3] == DELEGATION_PREFIX {
        Some(Address::from_slice(&code[3..23]))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::dyn_abi::DynSolType;
    use alloy::primitives::{B256, U256, address, keccak256};

    fn call(to: Address, value: u64, data: &[u8]) -> QueuedCall {
        QueuedCall {
            id: 1,
            to,
            value: U256::from(value),
            data: Bytes::from(data.to_vec()),
            title: "t".into(),
            detail: "d".into(),
            signature: None,
            decoded_args: Vec::new(),
        }
    }

    #[test]
    fn execute_batch_selector_is_canonical() {
        let hash = keccak256(b"executeBatch((address,uint256,bytes)[])");
        assert_eq!(&hash[..4], &EXECUTE_BATCH_SELECTOR);
    }

    #[test]
    fn ef_delegate_address_is_pinned() {
        // Guards against a typo in the constant — the EF Simple7702Account.
        assert_eq!(
            EF_SIMPLE_7702_ACCOUNT,
            address!("0x4Cd241E8d1510e30b2076397afc7508Ae59C66c9")
        );
    }

    #[test]
    fn encode_execute_batch_round_trips_via_alloy() {
        // Two calls with distinct target/value/data must decode back through
        // alloy's Call[] decoder to prove the ABI wrapping is standard.
        let a = address!("0x000000000000000000000000000000000000000A");
        let b = address!("0x000000000000000000000000000000000000000B");
        let calls = vec![call(a, 5, &[0x12, 0x34]), call(b, 0, &[0xaa, 0xbb, 0xcc])];
        let cd = encode_execute_batch(&calls);
        assert_eq!(&cd[..4], &EXECUTE_BATCH_SELECTOR);

        let ty = DynSolType::Array(Box::new(DynSolType::Tuple(vec![
            DynSolType::Address,
            DynSolType::Uint(256),
            DynSolType::Bytes,
        ])));
        let decoded = DynSolType::Tuple(vec![ty])
            .abi_decode_params(&cd[4..])
            .unwrap();
        let arr = match decoded {
            DynSolValue::Tuple(mut v) => match v.remove(0) {
                DynSolValue::Array(a) => a,
                other => panic!("expected array, got {other:?}"),
            },
            other => panic!("expected tuple, got {other:?}"),
        };
        assert_eq!(arr.len(), 2);
        // First element round-trips target/value/data.
        match &arr[0] {
            DynSolValue::Tuple(t) => {
                assert_eq!(t[0], DynSolValue::Address(a));
                assert_eq!(t[1], DynSolValue::Uint(U256::from(5u64), 256));
                assert_eq!(t[2], DynSolValue::Bytes(vec![0x12, 0x34]));
            }
            other => panic!("expected call tuple, got {other:?}"),
        }
    }

    #[test]
    fn decode_execute_batch_recovers_what_was_encoded() {
        // The sign review builds its per-call panels from this decode, so a
        // drift between encoder and decoder would show the user the wrong
        // batch. Round-trip every field.
        let a = address!("0x000000000000000000000000000000000000000A");
        let b = address!("0x000000000000000000000000000000000000000B");
        let calls = vec![call(a, 5, &[0x12, 0x34]), call(b, 0, &[])];
        let out = decode_execute_batch(&encode_execute_batch(&calls)).expect("round trip");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], (a, U256::from(5u64), Bytes::from(vec![0x12, 0x34])));
        assert_eq!(out[1], (b, U256::ZERO, Bytes::new()));
    }

    #[test]
    fn decode_execute_batch_rejects_foreign_and_malformed_calldata() {
        assert!(decode_execute_batch(&[]).is_err());
        assert!(decode_execute_batch(&[0xde, 0xad, 0xbe, 0xef]).is_err());
        // Right selector, garbage body.
        let mut bad = EXECUTE_BATCH_SELECTOR.to_vec();
        bad.extend_from_slice(&[0xff; 16]);
        assert!(decode_execute_batch(&bad).is_err());
    }

    #[test]
    fn build_authorization_targets_ef_delegate() {
        let auth = build_authorization(1, 7);
        assert_eq!(auth.chain_id, U256::from(1u64));
        assert_eq!(auth.address, EF_SIMPLE_7702_ACCOUNT);
        assert_eq!(auth.nonce, 7);
    }

    #[test]
    fn delegated_to_recognises_and_rejects() {
        // 0xef0100 ‖ EF delegate → recovered.
        let mut code = vec![0xef, 0x01, 0x00];
        code.extend_from_slice(EF_SIMPLE_7702_ACCOUNT.as_slice());
        assert_eq!(delegated_to(&code), Some(EF_SIMPLE_7702_ACCOUNT));

        // Wrong prefix, wrong length, and empty → None.
        assert_eq!(delegated_to(&[0xef, 0x02, 0x00]), None);
        assert_eq!(delegated_to(&code[..22]), None);
        assert_eq!(delegated_to(&[]), None);
        // A normal contract's runtime code is not a designator.
        assert_eq!(delegated_to(&[0x60, 0x80, 0x60, 0x40]), None);
    }

    #[test]
    fn build_revocation_targets_the_zero_address() {
        let auth = build_revocation(1, 7);
        assert_eq!(auth.chain_id, U256::from(1u64));
        assert_eq!(
            auth.address,
            Address::ZERO,
            "a revocation is an authorization to 0x0 — any other address INSTALLS a delegation"
        );
        assert_eq!(auth.nonce, 7);
    }

    #[test]
    fn install_and_revoke_are_the_only_two_tuples_and_they_differ() {
        // Same chain and nonce, so the only thing separating the digest the
        // user checks on their device from its exact inverse is the delegate.
        let install = build_authorization(1, 3);
        let revoke = build_revocation(1, 3);
        assert_ne!(install.address, revoke.address);
        assert_ne!(
            install.signature_hash(),
            revoke.signature_hash(),
            "installing and revoking must never share a digest"
        );
    }

    /// `keccak256(MAGIC ‖ rlp([chain_id, address, nonce]))`, with the preimage
    /// assembled by hand.
    ///
    /// Every other assertion that touches this digest recomputes it with the
    /// same production expression it is meant to be checking, so none of them
    /// can see a change to the preimage — a different MAGIC byte, a reordered
    /// field, a chain id that stopped being encoded. This is the one signature
    /// in the wallet whose effect outlives its transaction; it gets a vector
    /// that does not go through `Authorization` at all.
    fn expected_auth_digest(chain_id_byte: u8, delegate: Address, nonce_byte: Option<u8>) -> B256 {
        let mut rlp = Vec::new();
        // chain_id: a single byte < 0x80 encodes as itself.
        rlp.push(chain_id_byte);
        // address: a 20-byte string → 0x80 + 20.
        rlp.push(0x94);
        rlp.extend_from_slice(delegate.as_slice());
        // nonce: 0 is the empty string (0x80); otherwise a single byte < 0x80.
        rlp.push(nonce_byte.unwrap_or(0x80));
        // list header: payload is 23 bytes, well under 56 → 0xc0 + len.
        let mut preimage = vec![0x05u8, 0xc0 + rlp.len() as u8];
        preimage.extend_from_slice(&rlp);
        keccak256(preimage)
    }

    #[test]
    fn the_authorization_digest_matches_a_hand_built_preimage() {
        // Install, mainnet, nonce 0.
        assert_eq!(
            build_authorization(1, 0).signature_hash(),
            expected_auth_digest(0x01, EF_SIMPLE_7702_ACCOUNT, None),
        );
        // Install, mainnet, nonce 7 — moves the last RLP item off the 0x80
        // empty-string encoding, so a nonce dropped from the preimage shows up.
        assert_eq!(
            build_authorization(1, 7).signature_hash(),
            expected_auth_digest(0x01, EF_SIMPLE_7702_ACCOUNT, Some(0x07)),
        );
        // Revocation, mainnet, nonce 7.
        assert_eq!(
            build_revocation(1, 7).signature_hash(),
            expected_auth_digest(0x01, Address::ZERO, Some(0x07)),
        );
        // A different chain must move the digest — a 7702 authorization that
        // dropped its chain scoping would be valid on every chain at once.
        assert_ne!(
            build_authorization(1, 0).signature_hash(),
            build_authorization(8, 0).signature_hash(),
        );
    }
}
