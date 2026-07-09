//! Flash approval — append `approve(spender, 0)` revokes to a batch so no
//! ERC-20 allowance survives the transaction.
//!
//! Atomic batching (Safe MultiSend or the EIP-7702 `executeBatch` path) lets
//! us wrap `approve(spender, exact)` → operation and, on the same all-or-
//! nothing transaction, reset the allowance back to zero. If any call reverts
//! the whole batch reverts; on success the allowance is provably 0. This
//! designs out the dangling-approval risk class (a standing allowance drained
//! long after the interaction).
//!
//! Detection is selector-based on the raw calldata, so it catches both
//! ABI-composed and raw-hex `approve` calls uniformly: a call is a non-zero
//! approval iff its data is `approve(address,uint256)` (selector
//! [`APPROVE_SELECTOR`]) with a non-zero amount word. The revoke is a plain
//! `approve(spender, 0)` back to the same token, appended after every original
//! call and deduped per `(token, spender)`.

use alloy::primitives::{Address, Bytes, U256};

use super::{DecodedArg, QueuedCall};

/// `keccak256("approve(address,uint256)")[..4]`.
pub const APPROVE_SELECTOR: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

/// If `data` is a non-zero `approve(address,uint256)` call, return its
/// `spender`; otherwise `None`. Zero-amount approvals (revokes) and non-approve
/// or malformed (<68-byte) calldata return `None`.
fn nonzero_approve_spender(data: &[u8]) -> Option<Address> {
    if data.len() < 4 + 64 || data[..4] != APPROVE_SELECTOR {
        return None;
    }
    // amount is the second 32-byte word; a zero amount is already a revoke.
    if U256::from_be_slice(&data[4 + 32..4 + 64]).is_zero() {
        return None;
    }
    // spender is right-aligned in the first word.
    Some(Address::from_slice(&data[4 + 12..4 + 32]))
}

/// The deduped `(token, spender)` pairs the batch grants a non-zero allowance
/// to, in first-seen order. These are the allowances a flash-approval revoke
/// would reset. Pure — used for both the wrap and the UI hint/count.
pub fn revoke_targets(calls: &[QueuedCall]) -> Vec<(Address, Address)> {
    let mut out: Vec<(Address, Address)> = Vec::new();
    for c in calls {
        if let Some(spender) = nonzero_approve_spender(&c.data) {
            let pair = (c.to, spender);
            if !out.contains(&pair) {
                out.push(pair);
            }
        }
    }
    out
}

/// Count the `approve(_, 0)` (allowance-reset) calls in a batch — the
/// disclosure the review shows ("resets N approval(s) to 0"). Counts any
/// zero-amount approval, whether appended by [`wrap_with_revoke`] or composed
/// by hand.
pub fn revoke_count(calls: &[QueuedCall]) -> usize {
    calls
        .iter()
        .filter(|c| {
            c.data.len() >= 4 + 64
                && c.data[..4] == APPROVE_SELECTOR
                && U256::from_be_slice(&c.data[4 + 32..4 + 64]).is_zero()
        })
        .count()
}

/// ABI-encode `approve(spender, 0)` calldata: `selector ‖ spender(32) ‖ 0(32)`.
fn revoke_calldata(spender: Address) -> Bytes {
    let mut out = Vec::with_capacity(4 + 64);
    out.extend_from_slice(&APPROVE_SELECTOR);
    out.extend_from_slice(&[0u8; 12]); // left pad to a 32-byte word
    out.extend_from_slice(spender.as_slice());
    out.extend_from_slice(&[0u8; 32]); // amount = 0
    Bytes::from(out)
}

/// The token label for a revoke card, recovered from the source approve's
/// `title` (`"USDC.approve"` → `"USDC"`); falls back to the short address.
fn token_label(calls: &[QueuedCall], token: Address) -> String {
    calls
        .iter()
        .find(|c| c.to == token && nonzero_approve_spender(&c.data).is_some())
        .and_then(|c| c.title.split('.').next())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| crate::wallet::short_address(token))
}

/// Return `calls` followed by one `approve(spender, 0)` revoke per
/// `(token, spender)` the batch grants a non-zero allowance to. Ids for the
/// appended calls start at `start_id`. A batch with no non-zero approvals is
/// returned unchanged (cloned).
pub fn wrap_with_revoke(calls: &[QueuedCall], start_id: u64) -> Vec<QueuedCall> {
    let targets = revoke_targets(calls);
    let mut out: Vec<QueuedCall> = calls.to_vec();
    for (i, (token, spender)) in targets.into_iter().enumerate() {
        let label = token_label(calls, token);
        out.push(QueuedCall {
            id: start_id + i as u64,
            to: token,
            value: U256::ZERO,
            data: revoke_calldata(spender),
            title: format!("Revoke {label}"),
            detail: format!("{} → 0", crate::wallet::short_address(spender)),
            signature: Some("approve(address,uint256)".to_string()),
            decoded_args: vec![
                DecodedArg {
                    name: "spender".to_string(),
                    ty: "address".to_string(),
                    value: spender.to_string(),
                },
                DecodedArg {
                    name: "amount".to_string(),
                    ty: "uint256".to_string(),
                    value: "0".to_string(),
                },
            ],
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::txbuilder::abi;
    use crate::txbuilder::encode::build_contract_call;
    use alloy::primitives::{address, keccak256};

    const USDC: Address = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    const SPENDER: Address = address!("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2");

    fn approve(amount: &str) -> QueuedCall {
        let usdc = abi::known_by_address(crate::chain::Chain::Mainnet, USDC).unwrap();
        let m = usdc.methods.iter().find(|m| m.name == "approve").unwrap();
        build_contract_call(
            1,
            USDC,
            "USDC",
            m,
            &[SPENDER.to_string(), amount.into()],
            "0",
        )
        .unwrap()
    }

    #[test]
    fn approve_selector_is_canonical() {
        let hash = keccak256(b"approve(address,uint256)");
        assert_eq!(&hash[..4], &APPROVE_SELECTOR);
    }

    #[test]
    fn nonzero_approve_appends_one_revoke() {
        let batch = vec![approve("5000000000")];
        let targets = revoke_targets(&batch);
        assert_eq!(targets, vec![(USDC, SPENDER)]);

        let wrapped = wrap_with_revoke(&batch, 100);
        assert_eq!(wrapped.len(), 2);
        let revoke = &wrapped[1];
        assert_eq!(revoke.to, USDC);
        assert_eq!(revoke.value, U256::ZERO);
        assert_eq!(&revoke.data[..4], &APPROVE_SELECTOR);
        assert_eq!(Address::from_slice(&revoke.data[16..36]), SPENDER);
        assert_eq!(U256::from_be_slice(&revoke.data[36..68]), U256::ZERO);
        assert_eq!(revoke.title, "Revoke USDC");
        assert_eq!(revoke.id, 100);
        // The appended revoke is itself a zero approval → not a new target.
        assert!(revoke_targets(&wrapped).len() == 1);
    }

    #[test]
    fn revoke_count_counts_zero_approvals() {
        let batch = vec![approve("5000000000")];
        assert_eq!(
            revoke_count(&batch),
            0,
            "a non-zero approve is not a revoke"
        );
        let wrapped = wrap_with_revoke(&batch, 1);
        assert_eq!(
            revoke_count(&wrapped),
            1,
            "the appended approve(_,0) counts"
        );
        // A hand-composed approve(_, 0) also counts.
        assert_eq!(revoke_count(&[approve("0")]), 1);
    }

    #[test]
    fn duplicate_approves_dedupe_to_one_revoke() {
        let batch = vec![approve("5000000000"), approve("1")];
        assert_eq!(revoke_targets(&batch), vec![(USDC, SPENDER)]);
        let wrapped = wrap_with_revoke(&batch, 10);
        assert_eq!(wrapped.len(), 3, "two approves → +1 revoke");
    }

    #[test]
    fn zero_approve_and_non_approve_yield_no_revoke() {
        // An explicit revoke (amount 0) and a transfer are not targets.
        let usdc = abi::known_by_address(crate::chain::Chain::Mainnet, USDC).unwrap();
        let transfer = usdc.methods.iter().find(|m| m.name == "transfer").unwrap();
        let xfer = build_contract_call(
            2,
            USDC,
            "USDC",
            transfer,
            &[SPENDER.to_string(), "1".into()],
            "0",
        )
        .unwrap();
        let batch = vec![approve("0"), xfer];
        assert!(revoke_targets(&batch).is_empty());
        assert_eq!(wrap_with_revoke(&batch, 1).len(), 2, "unchanged");
    }

    #[test]
    fn malformed_short_approve_is_ignored() {
        // Selector present but truncated calldata (<68 bytes) → not a target.
        let mut short = QueuedCall {
            id: 1,
            to: USDC,
            value: U256::ZERO,
            data: Bytes::from(APPROVE_SELECTOR.to_vec()),
            title: "raw".into(),
            detail: "d".into(),
            signature: None,
            decoded_args: Vec::new(),
        };
        assert!(revoke_targets(std::slice::from_ref(&short)).is_empty());
        // Also a raw-hex non-zero approve IS detected (selector-based).
        let mut data = Vec::from(APPROVE_SELECTOR);
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(SPENDER.as_slice());
        data.extend_from_slice(&U256::from(7u64).to_be_bytes::<32>());
        short.data = Bytes::from(data);
        assert_eq!(
            revoke_targets(std::slice::from_ref(&short)),
            vec![(USDC, SPENDER)]
        );
    }
}
