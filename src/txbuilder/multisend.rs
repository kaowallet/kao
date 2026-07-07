//! MultiSend encoding — pack N queued calls into ONE atomic Safe
//! transaction.
//!
//! The Safe executes a batch by **delegatecalling** the canonical
//! `MultiSendCallOnly` library, which loops over a tightly-packed byte
//! blob and `CALL`s each sub-transaction *as the Safe*. Because the outer
//! op is a delegatecall, `address(this)` inside the library is the Safe,
//! so every inner call has `msg.sender == Safe` — exactly as if the Safe
//! had made each call itself, but atomic: if any sub-call reverts, the
//! whole `execTransaction` reverts.
//!
//! `MultiSendCallOnly` (not plain `MultiSend`) is used deliberately: it
//! reverts if any *inner* operation is a delegatecall, so the batch can
//! only ever perform plain calls — the Safe's own storage can't be
//! rewritten by the batch.
//!
//! Per-sub-transaction wire format (`abi.encodePacked`, no inter-field
//! padding):
//! ```text
//!   operation  1 byte   (always 0x00 = CALL)
//!   to        20 bytes  (address)
//!   value     32 bytes  (uint256, big-endian)
//!   dataLen   32 bytes  (uint256, big-endian)
//!   data      dataLen bytes
//! ```
//! then all sub-transactions concatenated and wrapped as the single
//! `bytes` argument of `multiSend(bytes)` (selector `0x8d80ff0a`).

use alloy::primitives::{Address, Bytes, U256, address};

use crate::safe::tx::{Operation, SafeTxInput};

use super::{QueuedCall, TxBuilderError};

/// `keccak256("multiSend(bytes)")[..4]`.
pub const MULTISEND_SELECTOR: [u8; 4] = [0x8d, 0x80, 0xff, 0x0a];

/// Canonical `MultiSendCallOnly` deployments from
/// <https://github.com/safe-global/safe-deployments>. Both are deployed at
/// the same address on Mainnet, Base, and Optimism (deterministic CREATE2
/// via the Safe singleton factory). Which one to use is keyed off the
/// Safe's own version so the batch runs against the contract family the
/// Safe was deployed with. The address is additionally checked to have
/// code on-chain before signing (`net.get_code`) — a delegatecall to a
/// code-less address would silently succeed and burn the Safe's nonce
/// without performing the batch.
pub const MULTISEND_CALL_ONLY_1_3_0: Address =
    address!("0x40A2aCCbd92BCA938b02010E17A5b8929b49130D");
pub const MULTISEND_CALL_ONLY_1_4_1: Address =
    address!("0x9641d764fc13c8B624c04430C7356C1C7C8102e2");

/// The `MultiSendCallOnly` address matching a Safe `version`. Kao only
/// signs for Safe 1.3.0–1.5.x (`ensure_signable_version`); 1.3.x uses the
/// 1.3.0 library, 1.4.x/1.5.x use the 1.4.1 library.
pub fn multisend_call_only(version: &str) -> Result<Address, TxBuilderError> {
    let mut parts = version.split('.');
    match (parts.next(), parts.next()) {
        (Some("1"), Some("3")) => Ok(MULTISEND_CALL_ONLY_1_3_0),
        (Some("1"), Some("4")) | (Some("1"), Some("5")) => Ok(MULTISEND_CALL_ONLY_1_4_1),
        _ => Err(TxBuilderError::Assembly(format!(
            "no MultiSend deployment known for Safe version {version}"
        ))),
    }
}

/// Pack the queued calls into the `transactions` blob. Inner operation is
/// hard-coded to `CALL` (0) — `MultiSendCallOnly` rejects anything else.
pub fn encode_packed(calls: &[QueuedCall]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in calls {
        out.push(0u8); // operation = CALL
        out.extend_from_slice(c.to.as_slice()); // 20 bytes
        out.extend_from_slice(&c.value.to_be_bytes::<32>()); // 32 bytes
        out.extend_from_slice(&U256::from(c.data.len()).to_be_bytes::<32>()); // 32 bytes
        out.extend_from_slice(&c.data); // dataLen bytes
    }
    out
}

/// Wrap a packed `transactions` blob as `multiSend(bytes)` calldata:
/// `selector ‖ offset(0x20) ‖ length ‖ blob(padded to 32)`.
pub fn encode_multisend_calldata(packed: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(4 + 64 + packed.len().next_multiple_of(32));
    out.extend_from_slice(&MULTISEND_SELECTOR);
    // ABI head for a single dynamic `bytes` arg: offset to the data = 0x20.
    out.extend_from_slice(&U256::from(32u64).to_be_bytes::<32>());
    // length of the blob.
    out.extend_from_slice(&U256::from(packed.len()).to_be_bytes::<32>());
    // the blob, right-padded to a 32-byte boundary.
    out.extend_from_slice(packed);
    let pad = packed.len().next_multiple_of(32) - packed.len();
    out.extend(std::iter::repeat_n(0u8, pad));
    Bytes::from(out)
}

/// Build the wrapping `SafeTxInput` for a batch: a delegatecall to the
/// version-matched `MultiSendCallOnly` carrying the packed calls. The outer
/// value is zero — sub-call ETH is drawn from the Safe's balance during
/// each inner `CALL`.
pub fn build_multisend_input(
    calls: &[QueuedCall],
    safe_version: &str,
) -> Result<SafeTxInput, TxBuilderError> {
    if calls.is_empty() {
        return Err(TxBuilderError::Assembly("batch is empty".into()));
    }
    let to = multisend_call_only(safe_version)?;
    let data = encode_multisend_calldata(&encode_packed(calls));
    Ok(SafeTxInput {
        to,
        value: U256::ZERO,
        data,
        operation: Operation::DelegateCall,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Bytes, U256, address, bytes, keccak256};

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
    fn multisend_selector_is_canonical() {
        let hash = keccak256(b"multiSend(bytes)");
        assert_eq!(&hash[..4], &MULTISEND_SELECTOR);
    }

    #[test]
    fn packs_single_call_with_exact_widths() {
        let to = address!("0x00000000000000000000000000000000deadBEEF");
        let packed = encode_packed(&[call(to, 0, &[0x12, 0x34])]);
        // 1 (op) + 20 (to) + 32 (value) + 32 (len) + 2 (data) = 87
        assert_eq!(packed.len(), 1 + 20 + 32 + 32 + 2);
        assert_eq!(packed[0], 0x00); // CALL
        assert_eq!(&packed[1..21], to.as_slice());
        assert_eq!(U256::from_be_slice(&packed[21..53]), U256::ZERO); // value
        assert_eq!(U256::from_be_slice(&packed[53..85]), U256::from(2u64)); // dataLen
        assert_eq!(&packed[85..87], &[0x12, 0x34]);
    }

    #[test]
    fn packs_value_and_two_calls_in_order() {
        let a = address!("0x000000000000000000000000000000000000000A");
        let b = address!("0x000000000000000000000000000000000000000B");
        let packed = encode_packed(&[call(a, 5, &[]), call(b, 0, &[0xff])]);
        // first sub-tx: 1+20+32+32+0 = 85 bytes, value 5
        assert_eq!(packed[0], 0);
        assert_eq!(&packed[1..21], a.as_slice());
        assert_eq!(U256::from_be_slice(&packed[21..53]), U256::from(5u64));
        assert_eq!(U256::from_be_slice(&packed[53..85]), U256::ZERO); // 0-length data
        // second sub-tx starts at offset 85
        assert_eq!(packed[85], 0);
        assert_eq!(&packed[86..106], b.as_slice());
    }

    #[test]
    fn multisend_calldata_abi_layout() {
        // Single sub-tx with 2 bytes of data → packed length 87.
        let to = address!("0x00000000000000000000000000000000deadBEEF");
        let packed = encode_packed(&[call(to, 0, &[0x12, 0x34])]);
        let cd = encode_multisend_calldata(&packed);
        assert_eq!(&cd[..4], &MULTISEND_SELECTOR);
        // offset word = 0x20
        assert_eq!(U256::from_be_slice(&cd[4..36]), U256::from(32u64));
        // length word = 87
        assert_eq!(U256::from_be_slice(&cd[36..68]), U256::from(packed.len()));
        // data starts at 68, padded to a 32-byte boundary (87 → 96)
        assert_eq!(&cd[68..68 + packed.len()], &packed[..]);
        assert_eq!(cd.len(), 4 + 32 + 32 + 96);
        // padding bytes are zero
        assert!(cd[68 + packed.len()..].iter().all(|&b| b == 0));
    }

    #[test]
    fn multisend_calldata_decodes_back_via_alloy() {
        // Round-trip the `bytes` arg through alloy's decoder to prove the
        // ABI wrapping is standard (a struct-of-bytes decode must recover
        // the exact packed blob).
        use alloy::dyn_abi::{DynSolType, DynSolValue};
        let to = address!("0x00000000000000000000000000000000deadBEEF");
        let packed = encode_packed(&[call(to, 7, &[0xaa, 0xbb, 0xcc])]);
        let cd = encode_multisend_calldata(&packed);
        let ty = DynSolType::Bytes;
        let decoded = DynSolType::Tuple(vec![ty])
            .abi_decode_params(&cd[4..])
            .unwrap();
        match decoded {
            DynSolValue::Tuple(mut v) => match v.remove(0) {
                DynSolValue::Bytes(b) => assert_eq!(b, packed),
                other => panic!("expected bytes, got {other:?}"),
            },
            other => panic!("expected tuple, got {other:?}"),
        }
    }

    #[test]
    fn version_routing_maps_to_libraries() {
        assert_eq!(
            multisend_call_only("1.3.0").unwrap(),
            MULTISEND_CALL_ONLY_1_3_0
        );
        assert_eq!(
            multisend_call_only("1.3.12").unwrap(),
            MULTISEND_CALL_ONLY_1_3_0
        );
        assert_eq!(
            multisend_call_only("1.4.1").unwrap(),
            MULTISEND_CALL_ONLY_1_4_1
        );
        assert_eq!(
            multisend_call_only("1.5.0").unwrap(),
            MULTISEND_CALL_ONLY_1_4_1
        );
        assert!(multisend_call_only("1.2.0").is_err());
        assert!(multisend_call_only("2.0.0").is_err());
    }

    #[test]
    fn build_input_is_delegatecall_zero_value() {
        let a = address!("0x000000000000000000000000000000000000000A");
        let input = build_multisend_input(&[call(a, 3, &[0x01])], "1.4.1").unwrap();
        assert_eq!(input.operation, Operation::DelegateCall);
        assert_eq!(input.to, MULTISEND_CALL_ONLY_1_4_1);
        assert_eq!(input.value, U256::ZERO); // outer value always zero
        assert_eq!(&input.data[..4], &MULTISEND_SELECTOR);
    }

    #[test]
    fn build_input_rejects_empty_batch() {
        assert!(build_multisend_input(&[], "1.4.1").is_err());
    }

    #[test]
    fn empty_packed_is_empty() {
        assert!(encode_packed(&[]).is_empty());
        // and a real-world approve+supply blob is a multiple of nothing in
        // particular — just non-empty and selector-prefixed once wrapped.
        let _ = bytes!("8d80ff0a");
    }
}
