//! Recognising a Safe's own administrative calls — the ones it can only make
//! to itself.
//!
//! Every method here sits behind Safe's `authorized` modifier, which requires
//! `msg.sender == address(this)`. The only way to satisfy that is a transaction
//! the Safe executes *on itself*, which is exactly what a Transaction Builder
//! batch can contain: `MultiSendCallOnly` is reached by `DELEGATECALL`, so each
//! packed sub-call runs with the Safe as `msg.sender`, and a sub-call addressed
//! to the Safe reconfigures the multisig.
//!
//! That makes an imported bundle a governance attack surface. `addOwnerWithThreshold(attacker, 1)`
//! packed as call three of "claim + stake" passes every check the Builder had:
//! it is a well-formed call to a real address with real calldata, the batch
//! simulates clean, and the review renders it as an ordinary leg. Naming the
//! effect is the difference between that and a line the user can act on.
//!
//! Selectors are **derived from the signature strings** rather than written
//! down. A mistyped constant here fails open — the call renders as ordinary —
//! which is the one direction this module must not be wrong in.

use alloy::primitives::keccak256;

/// The `authorized`-gated methods, paired with what each one does in the terms
/// a user reasons about. Sourced from the Safe v1.3.0 / v1.4.1 singleton
/// (`OwnerManager`, `ModuleManager`, `GuardManager`, `FallbackManager`).
///
/// `setup` is included even though it can only run once: a batch containing it
/// against an already-initialised Safe is either a bug or an attempt at one,
/// and either way is worth saying out loud.
const AUTHORIZED_METHODS: &[(&str, &str)] = &[
    (
        "addOwnerWithThreshold(address,uint256)",
        "adds an owner to this Safe and sets the number of signatures it needs",
    ),
    (
        "removeOwner(address,address,uint256)",
        "removes an owner from this Safe and sets the number of signatures it needs",
    ),
    (
        "swapOwner(address,address,address)",
        "replaces one of this Safe's owners with a different address",
    ),
    (
        "changeThreshold(uint256)",
        "changes how many owner signatures this Safe requires",
    ),
    (
        "setGuard(address)",
        "replaces this Safe's transaction guard — the contract that can veto \
         every future transaction",
    ),
    (
        "enableModule(address)",
        "enables a module, which can then move funds from this Safe with no \
         owner signatures at all",
    ),
    (
        "disableModule(address,address)",
        "disables one of this Safe's modules",
    ),
    (
        "setFallbackHandler(address)",
        "replaces this Safe's fallback handler — the contract that answers \
         calls the Safe itself doesn't implement",
    ),
    (
        "setup(address[],uint256,address,bytes,address,address,uint256,address)",
        "re-runs this Safe's initialiser, which would set its entire owner set \
         and threshold",
    ),
];

/// The 4-byte selector of a Solidity function signature.
fn selector_of(signature: &str) -> [u8; 4] {
    let h = keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// What a call to a Safe's own address would change about the multisig.
///
/// `Some(effect)` when `calldata` carries one of the `authorized` selectors.
/// `None` for anything else — including calldata too short to carry a selector.
/// A `None` here does **not** mean the call is safe; it means this module can't
/// name what it does, and the caller should say so rather than stay quiet (an
/// unrecognised call to the Safe itself is more alarming than a recognised one,
/// not less).
pub fn authorized_effect(calldata: &[u8]) -> Option<&'static str> {
    if calldata.len() < 4 {
        return None;
    }
    let sel = &calldata[..4];
    AUTHORIZED_METHODS
        .iter()
        .find(|(sig, _)| selector_of(sig) == sel)
        .map(|(_, effect)| *effect)
}

/// The signature of the `authorized` method `calldata` calls, for the log line
/// and for tests. Same matching as [`authorized_effect`].
pub fn authorized_signature(calldata: &[u8]) -> Option<&'static str> {
    if calldata.len() < 4 {
        return None;
    }
    let sel = &calldata[..4];
    AUTHORIZED_METHODS
        .iter()
        .find(|(sig, _)| selector_of(sig) == sel)
        .map(|(sig, _)| *sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published selectors for the Safe singleton's `authorized` methods.
    /// Pinned against the derivation so a signature string edited into
    /// something plausible-but-wrong (a `uint256` where the ABI says `uint8`,
    /// a dropped argument) is caught here rather than by failing to warn about
    /// a live governance call.
    #[test]
    fn selectors_match_the_published_safe_abi() {
        for (sig, expected) in [
            ("addOwnerWithThreshold(address,uint256)", "0x0d582f13"),
            ("removeOwner(address,address,uint256)", "0xf8dc5dd9"),
            ("swapOwner(address,address,address)", "0xe318b52b"),
            ("changeThreshold(uint256)", "0x694e80c3"),
            ("setGuard(address)", "0xe19a9dd9"),
            ("enableModule(address)", "0x610b5925"),
            ("disableModule(address,address)", "0xe009cfde"),
            ("setFallbackHandler(address)", "0xf08a0323"),
        ] {
            let got = format!("0x{}", alloy::hex::encode(selector_of(sig)));
            assert_eq!(got, expected, "{sig}");
        }
    }

    #[test]
    fn every_listed_method_is_recognised_from_its_own_selector() {
        for (sig, _) in AUTHORIZED_METHODS {
            let cd = selector_of(sig).to_vec();
            assert_eq!(authorized_signature(&cd), Some(*sig));
            assert!(authorized_effect(&cd).is_some(), "{sig}");
        }
    }

    #[test]
    fn an_ordinary_call_is_not_an_admin_call() {
        // `approve(address,uint256)` — the selector a batch is full of.
        assert!(authorized_effect(&[0x09, 0x5e, 0xa7, 0xb3]).is_none());
        // `transfer(address,uint256)`.
        assert!(authorized_effect(&[0xa9, 0x05, 0x9c, 0xbb]).is_none());
    }

    #[test]
    fn calldata_too_short_to_carry_a_selector_is_not_a_match() {
        // A bare value transfer to the Safe. Not an admin call — but the caller
        // still flags it as a self-call, which is the point of returning None
        // rather than a "nothing to see here".
        assert!(authorized_effect(&[]).is_none());
        assert!(authorized_effect(&[0x0d, 0x58, 0x2f]).is_none());
    }

    #[test]
    fn no_two_listed_methods_collide() {
        let mut seen = Vec::new();
        for (sig, _) in AUTHORIZED_METHODS {
            let s = selector_of(sig);
            assert!(!seen.contains(&s), "duplicate selector for {sig}");
            seen.push(s);
        }
    }
}
