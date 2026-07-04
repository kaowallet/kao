//! Who authorizes a signature: the single EOA-vs-Safe decision, and the address
//! the review shows as `from`.

use alloy::primitives::Address;

/// Which flow is asking for a Safe context. The two flows that can sign from a
/// Safe have different constraints — CoW serves several chains, the name
/// registries are Mainnet-pinned — so the caller says which one it needs.
#[derive(Debug, Clone, Copy)]
pub enum SafeNeed {
    Swap,
    Name,
}

/// The identity that will authorize a signature. Built once when a review opens,
/// it is the single source of the address shown as `from` — so a review can never
/// display one address while another signs (the PP-Safe bug class).
///
/// There is **no `ViewOnly` variant, by design**: a watch-only account is
/// unrepresentable here, which is the strongest fail-closed — a review is simply
/// never built for a signer that can't sign. The context carries only public
/// addresses (never key material), so it is safe to hold in UI state.
#[derive(Debug, Clone)]
pub enum SignerContext {
    /// A single externally-owned account signs directly.
    Eoa { address: Address },
    /// A Safe signs (an N-owner ceremony); `safe` is the contract that appears as
    /// `from` and owns the action.
    Safe { safe: Address },
}

impl SignerContext {
    /// The address the review shows as `from` and that the signature is attributed
    /// to on-chain.
    pub fn display_from(&self) -> Address {
        match self {
            SignerContext::Eoa { address } => *address,
            SignerContext::Safe { safe } => *safe,
        }
    }
}
