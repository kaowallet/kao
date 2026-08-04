//! Glue between the queued batch and the revm batch simulator in
//! `wallet::sim`. The heavy lifting (shared-state sequential execution,
//! revert-step detection, transfer extraction) lives there, co-located with
//! the `HeliosDb` revm plumbing; here we just map [`QueuedCall`]s to
//! [`BatchStep`]s and re-export the result types the UI renders.

pub use crate::wallet::sim::{BatchOutcome, BatchSimResult, BatchStep, GasFit, simulate_batch};

use super::QueuedCall;

/// Project the queued calls onto the sub-call steps the simulator executes,
/// in order. `from` is supplied by the caller: the active Safe, or the EOA
/// itself.
///
/// `simulate_batch` runs each step from `from` against shared, committed state
/// and halts at the first revert. That reproduces the part of both batch
/// shapes that matters most — each sub-call runs as `from`, over state the
/// previous sub-calls already wrote, so an `approve` → `supply` pair behaves
/// the way it will on chain — and it is why a preflight is worth running.
///
/// It is an **approximation**, not the transaction. This used to claim it was
/// "exactly the on-chain behaviour"; it is not, and a preflight that overstates
/// itself is worse than one that doesn't run. What it does not model:
///
/// - **Transient storage does not carry across steps.** Each step is a
///   separate revm transaction, so EIP-1153 `tstore` is wiped between
///   sub-calls; on chain the whole batch is one transaction and it persists.
///   Anything using a transient reentrancy lock or transient accounting
///   (Uniswap v4, Balancer v3, Permit2-style flows) can pass here and revert
///   on chain, or the reverse.
/// - **`tx.origin` is `from`.** On chain it is whoever broadcasts — for a Safe
///   batch, the executor EOA, never the Safe. An `origin == msg.sender`
///   EOA-check passes in simulation and fails on chain.
/// - **No `execTransaction` wrapper (Safe).** Signature verification, the
///   nonce increment, the `MultiSendCallOnly` delegatecall frame, and — the
///   one with teeth — any **transaction guard** installed on the Safe are all
///   absent. A guard that will reject this batch is invisible here, which is
///   why the review names the guard separately when one is set.
/// - **No delegation designator is *installed* (EOA/7702).** The simulator
///   reads each account's real code, so an EOA already delegated to the batch
///   executor is modelled correctly — but one that is about to be delegated by
///   the very authorization in this transaction still has no code here, so a
///   callee gating on `msg.sender.code.length` sees the opposite of what it
///   will see on chain. This is the first-delegation case, which is also the
///   one the user is least familiar with.
/// - **Gas is not the transaction's gas.** Each step pays its own intrinsic
///   cost and runs under its own limit, so the total over-counts by
///   `(N − 1) × 21000` (the real transaction pays one intrinsic, not none) and
///   omits the wrapper's overhead entirely. The one thing it no longer misses
///   is the aggregate: [`BatchSimResult::gas_fit`] measures the sum against the
///   gas limit of the block it ran against, so a batch that cannot be mined at
///   all stops reading as a pass.
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
