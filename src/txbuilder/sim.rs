//! Glue between the queued batch and the revm batch simulator in
//! `wallet::sim`. The heavy lifting (shared-state sequential execution,
//! revert-step detection, transfer extraction) lives there, co-located with
//! the `HeliosDb` revm plumbing; here we just map [`QueuedCall`]s to
//! [`BatchStep`]s and re-export the result types the UI renders.

pub use crate::wallet::sim::{BatchOutcome, BatchSimResult, BatchStep, simulate_batch};

use super::QueuedCall;

/// Project the queued calls onto the sub-call steps the simulator executes,
/// in order. `from` is supplied by the caller: the active Safe, or the EOA
/// itself.
///
/// This faithfully models both batch shapes without any delegate-specific
/// setup: `simulate_batch` runs each step from `from` against shared,
/// committed state and halts at the first revert. That is exactly the
/// on-chain behaviour of the Safe MultiSend **and** of an EIP-7702
/// `Simple7702Account.executeBatch` — in the 7702 case each inner call runs
/// as the account (`msg.sender == from`, value drawn from `from`'s balance,
/// atomic all-or-nothing), which is what a `from = EOA` sequential sim
/// already reproduces. The delegate contract only loops the calls; it adds no
/// observable state the simulation must reconstruct.
pub fn to_steps(calls: &[QueuedCall]) -> Vec<BatchStep> {
    calls
        .iter()
        .map(|c| BatchStep {
            to: c.to,
            value: c.value,
            input: c.data.clone(),
        })
        .collect()
}
