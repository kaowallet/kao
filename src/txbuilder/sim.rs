//! Glue between the queued batch and the revm batch simulator in
//! `wallet::sim`. The heavy lifting (shared-state sequential execution,
//! revert-step detection, transfer extraction) lives there, co-located with
//! the `HeliosDb` revm plumbing; here we just map [`QueuedCall`]s to
//! [`BatchStep`]s and re-export the result types the UI renders.

pub use crate::wallet::sim::{BatchOutcome, BatchSimResult, BatchStep, simulate_batch};

use super::QueuedCall;

/// Project the queued calls onto the sub-call steps the simulator executes,
/// in order. `from` is supplied by the caller (the active Safe, or the EOA
/// for a single-call preflight).
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
