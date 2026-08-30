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

/// One sub-transaction recovered from a packed MultiSend blob. Produced by
/// [`decode_multisend_calldata`] — the review's clear-signing panels are built
/// from *these*, not from the queue they were packed from, so what the user
/// reads is derived from the exact bytes the Safe will delegatecall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedCall {
    /// Inner operation byte. Always `0` (CALL) for a blob this wallet built;
    /// `MultiSendCallOnly` reverts on anything else, but it is surfaced so a
    /// foreign blob can be shown for what it is.
    pub operation: u8,
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
}

/// The most sub-calls this wallet will unpack from one blob.
///
/// Not a protocol limit and deliberately not [`MAX_BATCH_CALLS`](super::MAX_BATCH_CALLS):
/// that one caps what this wallet *composes*, where 64 is what a person can
/// still read. This caps what it will *decode* from someone else's blob, which
/// is a different question — a co-owner's batch is not bound by our composer,
/// and refusing to render one would also refuse to sign it.
///
/// So the ceiling sits above anything that could ever execute. Each record is
/// at least 85 bytes and each sub-`CALL` costs thousands of gas, so a batch of
/// this size exceeds the block gas limit by a wide margin and could never be
/// mined on any chain here — refusing it costs no real work. What it stops is
/// the degenerate case: a ~1 MB blob unpacks to ~12,000 records, and the pane
/// that renders them lays out one card per call every frame with no
/// virtualization (the same cost `MAX_BATCH_CALLS` cites), while the sign path
/// resolves one address per call over the network.
pub const MAX_DECODED_CALLS: usize = 1024;

/// Unpack a `transactions` blob back into its sub-transactions. The inverse of
/// [`encode_packed`]; errors on a truncated or over-long record rather than
/// showing a partial batch, and on a blob carrying more than
/// [`MAX_DECODED_CALLS`] records.
pub fn decode_packed(packed: &[u8]) -> Result<Vec<PackedCall>, TxBuilderError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < packed.len() {
        if out.len() == MAX_DECODED_CALLS {
            return Err(TxBuilderError::Assembly(format!(
                "MultiSend blob carries too many sub-calls (over {MAX_DECODED_CALLS})"
            )));
        }
        // operation(1) ‖ to(20) ‖ value(32) ‖ dataLen(32) — 85-byte header.
        let header_end = i
            .checked_add(85)
            .ok_or_else(|| TxBuilderError::Assembly("MultiSend blob is malformed".into()))?;
        if header_end > packed.len() {
            return Err(TxBuilderError::Assembly(
                "MultiSend blob ends mid-header".into(),
            ));
        }
        let operation = packed[i];
        let to = Address::from_slice(&packed[i + 1..i + 21]);
        let value = U256::from_be_slice(&packed[i + 21..i + 53]);
        let len = U256::from_be_slice(&packed[i + 53..i + 85]);
        let len = usize::try_from(len)
            .map_err(|_| TxBuilderError::Assembly("MultiSend sub-call length overflows".into()))?;
        let data_end = header_end.checked_add(len).ok_or_else(|| {
            TxBuilderError::Assembly("MultiSend sub-call length overflows".into())
        })?;
        if data_end > packed.len() {
            return Err(TxBuilderError::Assembly(
                "MultiSend blob ends mid-payload".into(),
            ));
        }
        out.push(PackedCall {
            operation,
            to,
            value,
            data: Bytes::copy_from_slice(&packed[header_end..data_end]),
        });
        i = data_end;
    }
    Ok(out)
}

/// Recover the sub-transactions from `multiSend(bytes)` calldata: check the
/// selector, read the ABI header, then unpack the blob. Used by the sign review
/// to clear-sign each inner call of the batch it is about to sign.
pub fn decode_multisend_calldata(calldata: &[u8]) -> Result<Vec<PackedCall>, TxBuilderError> {
    if calldata.len() < 4 + 64 || calldata[..4] != MULTISEND_SELECTOR {
        return Err(TxBuilderError::Assembly(
            "not a multiSend(bytes) call".into(),
        ));
    }
    let offset = usize::try_from(U256::from_be_slice(&calldata[4..36]))
        .map_err(|_| TxBuilderError::Assembly("MultiSend offset overflows".into()))?;
    // The blob's length word sits at `4 + offset`; its bytes follow.
    //
    // Every step past the offset word is checked, including the two `+ 32`s
    // that used to be bare. `usize::try_from` above admits anything up to
    // `usize::MAX`, so an offset word chosen to land `len_at` near the top
    // overflowed the header bound: a panic in debug, and in release — where
    // this crate sets no `overflow-checks` — a wrap to a small number that
    // slipped past the truncation guard and panicked on the slice range
    // instead. The calldata is a pending transaction fetched from the Safe
    // Transaction Service and decoded inside `view()`, so that was a remote
    // crash any co-owner could trigger on every render, with no signature from
    // the victim required.
    let len_at = 4usize
        .checked_add(offset)
        .ok_or_else(|| TxBuilderError::Assembly("MultiSend offset overflows".into()))?;
    let start = len_at
        .checked_add(32)
        .ok_or_else(|| TxBuilderError::Assembly("MultiSend offset overflows".into()))?;
    if start > calldata.len() {
        return Err(TxBuilderError::Assembly(
            "MultiSend calldata is truncated".into(),
        ));
    }
    let len = usize::try_from(U256::from_be_slice(&calldata[len_at..start]))
        .map_err(|_| TxBuilderError::Assembly("MultiSend length overflows".into()))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| TxBuilderError::Assembly("MultiSend length overflows".into()))?;
    if end > calldata.len() {
        return Err(TxBuilderError::Assembly(
            "MultiSend calldata is truncated".into(),
        ));
    }
    decode_packed(&calldata[start..end])
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

    // ── decode (the sign review reads the batch back out of the blob) ──

    #[test]
    fn decode_packed_round_trips_every_field() {
        let a = address!("0x000000000000000000000000000000000000000A");
        let b = address!("0x000000000000000000000000000000000000000B");
        // Mixed shapes: value + empty data, then zero-value + odd-length data
        // (so the walk can't be passing by luck on 32-byte alignment).
        let calls = [call(a, 5, &[]), call(b, 0, &[0xff; 37])];
        let out = decode_packed(&encode_packed(&calls)).expect("round trip");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].operation, 0, "MultiSendCallOnly allows CALL only");
        assert_eq!(out[0].to, a);
        assert_eq!(out[0].value, U256::from(5u64));
        assert!(out[0].data.is_empty());
        assert_eq!(out[1].to, b);
        assert_eq!(out[1].value, U256::ZERO);
        assert_eq!(&out[1].data[..], &[0xff; 37]);
    }

    #[test]
    fn decode_multisend_calldata_recovers_the_batch_that_was_built() {
        let a = address!("0x000000000000000000000000000000000000000A");
        let b = address!("0x000000000000000000000000000000000000000B");
        let calls = [call(a, 7, &[0x12, 0x34]), call(b, 0, &[0xab])];
        let input = build_multisend_input(&calls, "1.4.1").unwrap();
        let out = decode_multisend_calldata(&input.data).expect("round trip");
        assert_eq!(out.len(), 2);
        // What the review will display == what the Safe will delegatecall.
        for (got, want) in out.iter().zip(calls.iter()) {
            assert_eq!(got.to, want.to);
            assert_eq!(got.value, want.value);
            assert_eq!(got.data, want.data);
        }
    }

    #[test]
    fn decode_rejects_a_blob_it_cannot_fully_account_for() {
        let a = address!("0x000000000000000000000000000000000000000A");
        let packed = encode_packed(&[call(a, 0, &[0x11, 0x22, 0x33])]);
        // Cut the payload short: the header still claims 3 data bytes.
        assert!(decode_packed(&packed[..packed.len() - 1]).is_err());
        // Cut mid-header.
        assert!(decode_packed(&packed[..40]).is_err());
        // A record whose length word is absurd must not be trusted either.
        let mut lying = packed.clone();
        lying[53..85].copy_from_slice(&U256::from(u64::MAX).to_be_bytes::<32>());
        assert!(decode_packed(&lying).is_err());
    }

    #[test]
    fn decode_multisend_calldata_rejects_a_foreign_selector() {
        assert!(decode_multisend_calldata(&[0u8; 100]).is_err());
        assert!(decode_multisend_calldata(&MULTISEND_SELECTOR).is_err());
    }

    #[test]
    fn empty_packed_is_empty() {
        assert!(encode_packed(&[]).is_empty());
        // and a real-world approve+supply blob is a multiple of nothing in
        // particular — just non-empty and selector-prefixed once wrapped.
        let _ = bytes!("8d80ff0a");
    }

    /// `multiSend(bytes)` calldata whose ABI offset word is `value`, followed by
    /// `tail` where the blob's length word would sit. Well-formed everywhere the
    /// decoder looks before it trusts the offset.
    fn calldata_with_offset(value: U256, tail: &[u8]) -> Vec<u8> {
        let mut cd = Vec::new();
        cd.extend_from_slice(&MULTISEND_SELECTOR);
        cd.extend_from_slice(&value.to_be_bytes::<32>());
        cd.extend_from_slice(tail);
        cd
    }

    #[test]
    fn an_absurd_offset_is_refused_not_panicked_on() {
        // `len_at = 4 + offset` succeeds at usize::MAX, then `len_at + 32`
        // overflowed: a panic in debug, and in release (this crate sets no
        // overflow-checks) a wrap to 31 that slips past the truncation guard
        // and panics on `&calldata[usize::MAX..31]` instead.
        //
        // The input is remote and unauthenticated by the victim: it arrives as
        // a pending transaction from the Safe Transaction Service and is
        // decoded inside `view()`, so any co-owner could crash the wallet on
        // every render of the queue detail pane by proposing one transaction.
        for offset in [
            U256::from(usize::MAX - 4),
            U256::from(usize::MAX),
            U256::from(usize::MAX - 35),
            U256::MAX,
        ] {
            let cd = calldata_with_offset(offset, &[0u8; 32]);
            assert!(
                decode_multisend_calldata(&cd).is_err(),
                "offset {offset} must be refused, not panicked on",
            );
        }
    }

    #[test]
    fn an_offset_past_the_end_is_refused() {
        // The ordinary truncation case still errors, and still says so.
        let cd = calldata_with_offset(U256::from(4096u64), &[0u8; 32]);
        assert!(decode_multisend_calldata(&cd).is_err());
    }

    #[test]
    fn a_well_formed_offset_still_round_trips() {
        // The guard must not have narrowed the accepted range: the canonical
        // 0x20 offset a real MultiSend carries keeps decoding.
        let a = address!("0x000000000000000000000000000000000000000A");
        let calls = vec![call(a, 1, &[0xAA, 0xBB])];
        let cd = encode_multisend_calldata(&encode_packed(&calls));
        let back = decode_multisend_calldata(&cd).expect("canonical calldata decodes");
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].to, a);
        assert_eq!(back[0].value, U256::from(1u64));
        assert_eq!(&back[0].data[..], &[0xAA, 0xBB]);
    }

    #[test]
    fn a_blob_with_more_records_than_the_ceiling_is_refused() {
        // Each record is >= 85 bytes, so a ~1 MB blob unpacks to ~12k cards —
        // one per call in `view()`, on the pane whose lack of virtualization is
        // the documented reason the compose-side cap exists at all.
        let mut packed = Vec::new();
        for _ in 0..(MAX_DECODED_CALLS + 1) {
            packed.push(0u8);
            packed.extend_from_slice(&[0u8; 20]);
            packed.extend_from_slice(&[0u8; 32]);
            packed.extend_from_slice(&[0u8; 32]);
        }
        let err = decode_packed(&packed).expect_err("over the ceiling");
        assert!(
            err.to_string().contains("too many"),
            "the refusal should say what the limit was: {err}",
        );
        // One under the ceiling is still fine — the cap sits above anything
        // that could be mined, so it never refuses real work.
        let ok = &packed[..packed.len() - 85];
        assert_eq!(
            decode_packed(ok).expect("at the ceiling").len(),
            MAX_DECODED_CALLS
        );
    }
}
