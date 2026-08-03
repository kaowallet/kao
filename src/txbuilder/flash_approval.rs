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

/// `keccak256("increaseAllowance(address,uint256)")[..4]`. Not something the
/// wrapper appends, but it raises an allowance just as `approve` does, so the
/// verdict below has to see it — otherwise a batch ending in
/// `increaseAllowance` could still be described as leaving nothing standing.
pub const INCREASE_ALLOWANCE_SELECTOR: [u8; 4] = [0x39, 0x50, 0x93, 0x51];

/// Approval-granting calls the verdict recognises but cannot **score**, and so
/// cannot promise anything about.
///
/// The flash-approval guarantee is an absolute claim ("every allowance this
/// batch grants is reset before it ends"), and an absolute claim is only worth
/// making if the scan behind it is exhaustive. It isn't: it reads ERC-20
/// `approve`/`increaseAllowance` and nothing else. A batch pairing
/// `approve(USDC, router, 1000)` with `setApprovalForAll(attacker, true)` over
/// an NFT collection would score `standing = []`, and the review would print
/// the guarantee over a permanent blanket operator approval.
///
/// Rather than chase every approval shape, the ones below are detected purely
/// so the guarantee can be **withheld** — they land in
/// [`AllowanceVerdict::unmodelled`] and the copy drops to naming them.
const UNMODELLED_GRANTS: [([u8; 4], &str); 3] = [
    // setApprovalForAll(address,bool) — ERC-721/1155 blanket operator rights.
    ([0xa2, 0x2c, 0xb4, 0x65], "setApprovalForAll"),
    // permit(address,address,uint256,uint256,uint8,bytes32,bytes32) — EIP-2612.
    ([0xd5, 0x05, 0xac, 0xcf], "permit"),
    // DAI-style permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32).
    ([0x8f, 0xcb, 0xaf, 0x0c], "permit"),
];

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

/// What a batch does to ERC-20 allowances, as the review should describe it.
///
/// This replaces a bare count of `approve(_, 0)` calls. A count is not a
/// verdict: it says nothing about *which* allowances were reset, so a batch
/// holding `approve(USDC, attacker, MAX)` alongside an unrelated hand-composed
/// `approve(DAI, x, 0)` counted 1 and earned the sentence "no allowance is
/// left standing" — a false safety assertion on the last screen before a
/// signature.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowanceVerdict {
    /// `(token, spender)` pairs this batch leaves holding a non-zero
    /// allowance when it ends. Non-empty ⇒ the flash-approval guarantee does
    /// not hold and the survivors have to be named.
    pub standing: Vec<(Address, Address)>,
    /// `(token, spender)` pairs the batch ends at zero — whether the revoke
    /// was appended by [`wrap_with_revoke`] or composed by hand.
    pub reset: Vec<(Address, Address)>,
    /// `(target, call name)` for approval grants this scan recognises but
    /// can't score (see [`UNMODELLED_GRANTS`]). Any entry here withholds the
    /// absolute guarantee: the batch grants something the verdict cannot
    /// promise was reset.
    pub unmodelled: Vec<(Address, &'static str)>,
}

impl AllowanceVerdict {
    /// True when the batch touches no approval this scan recognises — nothing
    /// to disclose.
    pub fn is_empty(&self) -> bool {
        self.standing.is_empty() && self.reset.is_empty() && self.unmodelled.is_empty()
    }

    /// The disclosure line for the review, or `None` when the batch grants and
    /// resets nothing. The absolute claim is made *only* when nothing stands
    /// **and** nothing unscoreable was granted.
    pub fn disclosure(&self) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        // An unscoreable grant is not evidence of danger — it is the absence of
        // evidence of safety, so it withholds the guarantee rather than
        // sharpening the warning.
        if self.standing.is_empty() && !self.unmodelled.is_empty() {
            let what = self
                .unmodelled
                .iter()
                .map(|(t, n)| format!("{n} on {}", crate::wallet::short_address(*t)))
                .collect::<Vec<_>>()
                .join(", ");
            return Some(format!(
                "⚠ This batch grants approvals this wallet can't account for ({what}), so it \
                 can't promise nothing is left standing — read those calls yourself."
            ));
        }
        let names = |pairs: &[(Address, Address)]| {
            pairs
                .iter()
                .map(|(t, s)| {
                    format!(
                        "{} → {}",
                        crate::wallet::short_address(*t),
                        crate::wallet::short_address(*s)
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        if self.standing.is_empty() {
            return Some(format!(
                "Resets {} approval{} to 0 in the same transaction (flash approval — every \
                 allowance this batch grants is reset before it ends): {}.",
                self.reset.len(),
                if self.reset.len() == 1 { "" } else { "s" },
                names(&self.reset),
            ));
        }
        let mut s = format!(
            "⚠ {} approval{} still standing when this batch ends: {}.",
            self.standing.len(),
            if self.standing.len() == 1 {
                " is"
            } else {
                "s are"
            },
            names(&self.standing),
        );
        if !self.reset.is_empty() {
            s.push_str(&format!(
                " ({} other{} reset to 0: {}.)",
                self.reset.len(),
                if self.reset.len() == 1 { "" } else { "s" },
                names(&self.reset),
            ));
        }
        Some(s)
    }
}

/// The allowance each `(token, spender)` pair the batch touches is left at.
///
/// Walks the calls in execution order and keeps the **last** allowance-setting
/// call per pair, which is what survives an atomic batch: a later
/// `approve(spender, 0)` resets an earlier grant, and a later grant (whether
/// `approve` or `increaseAllowance`) undoes an earlier reset. Selector-based,
/// so it reads raw-hex and ABI-composed calls alike.
///
/// Scope, stated because the review's copy leans on it: this accounts for the
/// ERC-20 allowances *this batch* sets. An allowance granted in some earlier
/// transaction and never touched here is outside what a batch can speak to.
/// Approval grants of other shapes are collected into
/// [`AllowanceVerdict::unmodelled`] so the copy can decline to make a promise
/// rather than make one it can't keep.
pub fn allowance_verdict(calls: &[QueuedCall]) -> AllowanceVerdict {
    // (token, spender) → whether the last call left it non-zero, in
    // first-seen order so the disclosure reads in batch order.
    let mut seen: Vec<((Address, Address), bool)> = Vec::new();
    let mut v = AllowanceVerdict::default();
    for c in calls {
        if let Some(what) = unmodelled_grant(&c.data) {
            let entry = (c.to, what);
            if !v.unmodelled.contains(&entry) {
                v.unmodelled.push(entry);
            }
            continue;
        }
        let Some((spender, nonzero)) = allowance_effect(&c.data) else {
            continue;
        };
        let pair = (c.to, spender);
        match seen.iter_mut().find(|(p, _)| *p == pair) {
            Some((_, state)) => *state = nonzero,
            None => seen.push((pair, nonzero)),
        }
    }
    for (pair, nonzero) in seen {
        if nonzero {
            v.standing.push(pair);
        } else {
            v.reset.push(pair);
        }
    }
    v
}

/// The name of the approval-granting call `data` makes, when it is one this
/// scan recognises but cannot score. `None` for everything else — including
/// ordinary non-approval calls, which are simply not approvals.
fn unmodelled_grant(data: &[u8]) -> Option<&'static str> {
    let sel: [u8; 4] = data.get(..4)?.try_into().ok()?;
    UNMODELLED_GRANTS
        .iter()
        .find(|(s, _)| *s == sel)
        .map(|(_, name)| *name)
}

/// `(spender, leaves_a_non_zero_allowance)` for an allowance-setting call.
/// `None` when the call doesn't set an allowance at all.
///
/// `increaseAllowance` is treated as leaving a non-zero allowance: its amount
/// word is a *delta*, so a zero delta leaves whatever was already there, which
/// this can't know and must not claim is zero.
fn allowance_effect(data: &[u8]) -> Option<(Address, bool)> {
    if data.len() < 4 + 64 {
        return None;
    }
    let spender = Address::from_slice(&data[4 + 12..4 + 32]);
    let amount = U256::from_be_slice(&data[4 + 32..4 + 64]);
    match data[..4].try_into().ok()? {
        APPROVE_SELECTOR => Some((spender, !amount.is_zero())),
        INCREASE_ALLOWANCE_SELECTOR => Some((spender, true)),
        _ => None,
    }
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

    /// Every selector this module keys safety copy off is pinned to its own
    /// keccak preimage — a mistyped byte here would silently stop detecting
    /// the thing it names, and the failure mode is a false guarantee.
    #[test]
    fn every_watched_selector_is_canonical() {
        for (sig, sel) in [
            (
                "increaseAllowance(address,uint256)".as_bytes(),
                INCREASE_ALLOWANCE_SELECTOR,
            ),
            (
                "setApprovalForAll(address,bool)".as_bytes(),
                UNMODELLED_GRANTS[0].0,
            ),
            (
                "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)".as_bytes(),
                UNMODELLED_GRANTS[1].0,
            ),
            (
                "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)".as_bytes(),
                UNMODELLED_GRANTS[2].0,
            ),
        ] {
            assert_eq!(
                &keccak256(sig)[..4],
                &sel,
                "selector drifted for {}",
                std::str::from_utf8(sig).unwrap()
            );
        }
    }

    /// The guarantee is absolute, so the scan behind it has to be exhaustive —
    /// and it isn't. A batch pairing a fully-revoked ERC-20 approve with an
    /// NFT `setApprovalForAll` must not earn it.
    #[test]
    fn an_unscoreable_grant_withholds_the_guarantee() {
        let nft = address!("0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D");
        let mut blanket = approve("0");
        blanket.to = nft;
        let mut data = Vec::from(UNMODELLED_GRANTS[0].0); // setApprovalForAll
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(SPENDER.as_slice());
        data.extend_from_slice(&U256::from(1u64).to_be_bytes::<32>()); // true
        blanket.data = Bytes::from(data);

        // The ERC-20 side is spotless: granted and revoked in the same batch.
        let batch = wrap_with_revoke(&[approve("5000000000")], 50);
        let v = allowance_verdict(&[batch, vec![blanket]].concat());

        assert_eq!(v.standing, vec![], "the ERC-20 grant really is reset");
        assert_eq!(v.reset, vec![(USDC, SPENDER)]);
        assert_eq!(v.unmodelled, vec![(nft, "setApprovalForAll")]);
        let d = v.disclosure().unwrap();
        assert!(
            !d.contains("every allowance this batch grants is reset"),
            "an unscoreable grant must withhold the guarantee: {d}"
        );
        assert!(
            d.contains("setApprovalForAll"),
            "and name what it can't score: {d}"
        );
    }

    #[test]
    fn an_eip2612_permit_also_withholds_the_guarantee() {
        let token = address!("0x6B175474E89094C44Da98b954EedeAC495271d0F");
        let mut p = approve("0");
        p.to = token;
        let mut data = Vec::from(UNMODELLED_GRANTS[1].0); // permit
        data.extend_from_slice(&[0u8; 64]);
        p.data = Bytes::from(data);
        let v = allowance_verdict(&[p]);
        assert_eq!(v.unmodelled, vec![(token, "permit")]);
        assert!(v.disclosure().unwrap().contains("can't account for"));
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
    fn verdict_tracks_the_last_allowance_per_pair() {
        // A bare non-zero approve leaves an allowance standing.
        let batch = vec![approve("5000000000")];
        let v = allowance_verdict(&batch);
        assert_eq!(v.standing, vec![(USDC, SPENDER)]);
        assert!(v.reset.is_empty());

        // Wrapped, the appended approve(_,0) is the last word on that pair.
        let v = allowance_verdict(&wrap_with_revoke(&batch, 1));
        assert!(v.standing.is_empty());
        assert_eq!(v.reset, vec![(USDC, SPENDER)]);
        assert!(
            v.disclosure()
                .unwrap()
                .contains("every allowance this batch grants is reset"),
            "a fully-revoked batch earns the guarantee"
        );
    }

    /// The regression this type exists for: a count of zero-approvals said "1"
    /// for a batch whose *other* approval was left at MAX, and the review
    /// printed "no allowance is left standing" over it.
    #[test]
    fn unrelated_revoke_does_not_earn_the_guarantee() {
        let dai = address!("0x6B175474E89094C44Da98b954EedeAC495271d0F");
        let other = address!("0x1111111111111111111111111111111111111111");
        let mut zero_on_dai = approve("0");
        zero_on_dai.to = dai;
        zero_on_dai.data = revoke_calldata(other);

        let v = allowance_verdict(&[approve("5000000000"), zero_on_dai]);
        assert_eq!(
            v.standing,
            vec![(USDC, SPENDER)],
            "the MAX approve survives"
        );
        assert_eq!(v.reset, vec![(dai, other)]);
        let d = v.disclosure().unwrap();
        assert!(d.starts_with("⚠ 1 approval is still standing"), "got {d}");
        assert!(
            !d.contains("every allowance this batch grants is reset"),
            "the guarantee must not be claimed while an allowance stands: {d}"
        );
    }

    /// `increaseAllowance` raises an allowance without ever writing a non-zero
    /// `approve`, so a verdict blind to it would call the batch clean.
    #[test]
    fn increase_allowance_after_a_revoke_leaves_it_standing() {
        let mut inc = approve("0");
        let mut data = Vec::from(INCREASE_ALLOWANCE_SELECTOR);
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(SPENDER.as_slice());
        data.extend_from_slice(&U256::from(1u64).to_be_bytes::<32>());
        inc.data = Bytes::from(data);

        let v = allowance_verdict(&[approve("5000000000"), approve("0"), inc]);
        assert_eq!(v.standing, vec![(USDC, SPENDER)]);
        assert!(v.reset.is_empty());
    }

    #[test]
    fn a_batch_touching_no_allowance_discloses_nothing() {
        let v = allowance_verdict(&[]);
        assert!(v.is_empty());
        assert!(v.disclosure().is_none());
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
