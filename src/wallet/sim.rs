//! Local revm preflight for the Send flow.
//!
//! `simulate_tx` runs the transaction the user is about to sign against
//! Helios-verified state and returns:
//!   - revert reason (if the tx would revert), decoded from
//!     `Error(string)` / `Panic(uint256)` ABI envelopes;
//!   - exact gas the EVM metered (independent of the upstream RPC's
//!     `eth_estimateGas` heuristic);
//!   - ERC-20 / ERC-721 transfers the user would observe, extracted from
//!     `Transfer(address,address,uint256)` logs.
//!
//! Advisory: the review screen surfaces the result alongside the existing
//! `eth_estimateGas` cost, never replaces it. A revert here shows the user
//! a "Sign anyway" override — it must not hard-block, because a stale-state
//! false negative would strand a legitimate send.
//!
//! Async/sync bridge: `simulate_tx` is async, fetches the verified
//! `LatestBlock` outside of revm, then runs the EVM inside
//! `tokio::task::spawn_blocking` with a captured `Handle`. The synchronous
//! `Database::basic` / `storage` callbacks reach back into the async runtime
//! via `Handle::block_on` for each cache miss. We avoid `block_in_place`
//! because that requires a multi-thread tokio runtime — and iced's tokio
//! integration doesn't guarantee one.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use alloy::primitives::{Address, B256, Bytes, Log, TxKind, U256, keccak256};
use revm::context::result::{ExecutionResult, Output};
use revm::context::{BlockEnv, CfgEnv, TxEnv};
use revm::context_interface::block::BlobExcessGasAndPrice;
use revm::database_interface::DBErrorMarker;
use revm::primitives::{HashMap as RevmHashMap, KECCAK_EMPTY, hardfork::SpecId};
use revm::state::{Account, AccountInfo, Bytecode};
use revm::{
    Context, Database, DatabaseCommit, ExecuteCommitEvm, ExecuteEvm, MainBuilder, MainContext,
};
use tokio::runtime::Handle;
use tracing::{debug, info, warn};

use crate::chain::Chain;
use crate::net::{BalanceFetcher, LatestBlock};
use crate::wallet::tx::SendPlan;

// ============================================================================
// Error type
// ============================================================================

/// A `SimError` aborts the simulation before producing a result. An EVM
/// revert is NOT a `SimError` — it's a successful simulation with a
/// `SimOutcome::Revert` outcome.
#[derive(Debug, Clone)]
pub enum SimError {
    /// Network couldn't return verified state (Helios or the fallback
    /// RPC both failed for a required read).
    State(String),
    /// revm refused to execute — e.g. caller balance below value + max
    /// gas cost, malformed tx env. Distinct from an EVM revert.
    Evm(String),
    /// The `spawn_blocking` task panicked or was cancelled.
    Join(String),
}

impl fmt::Display for SimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(s) => write!(f, "state: {s}"),
            Self::Evm(s) => write!(f, "evm: {s}"),
            Self::Join(s) => write!(f, "join: {s}"),
        }
    }
}

/// `Database::Error` must implement both `DBErrorMarker` (revm's marker)
/// and `core::error::Error`. `String` already implements the marker but
/// not `Error`; a one-field newtype is the cheapest way to satisfy both.
#[derive(Debug, Clone)]
struct DbError(String);

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DbError {}
impl DBErrorMarker for DbError {}

// ============================================================================
// Result types
// ============================================================================

// `output`/`raw` on the success / revert variants are public for the
// state-diff and debug-tooling follow-ups (return-bytes inspector, raw
// revert hexdump). They're carried even though v1's UI only renders the
// decoded reason.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum SimOutcome {
    /// EVM executed successfully. `output` is the return-data bytes.
    Success { output: Bytes },
    /// EVM hit a `REVERT` opcode (or a Solidity `require` / `revert`). The
    /// `reason` is the decoded `Error(string)` / `Panic(uint256)` message
    /// (or a hex fallback); `raw` is the unparsed return data.
    Revert { reason: String, raw: Bytes },
    /// EVM halted (out of gas, stack overflow, invalid opcode, etc.).
    /// `reason` is the debug-formatted `HaltReason` enum.
    Halt { reason: String },
    /// No simulation was run — either the chain doesn't support
    /// simulation in this build, or `simulate_tx` errored upstream.
    /// The review screen renders an inline notice and keeps the
    /// existing Confirm button.
    Unavailable,
}

// `from`/`to` are public for the upcoming "you send … / you receive …"
// attribution UI; v1 only renders the amount + symbol but downstream
// consumers need the parties.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct TokenTransfer {
    /// ERC-20 / ERC-721 contract that emitted the event.
    pub token: Address,
    pub from: Address,
    pub to: Address,
    /// ERC-20: amount in token-base units. ERC-721: tokenId.
    pub value: U256,
    /// True iff the log carried 4 topics (ERC-721's indexed `tokenId`).
    /// ERC-20 always emits 3-topic Transfer logs.
    pub is_nft: bool,
}

#[derive(Debug, Clone)]
pub struct SimulationResult {
    pub outcome: SimOutcome,
    pub gas_used: u64,
    pub transfers: Vec<TokenTransfer>,
    /// True iff every state read the simulator did went through Helios's
    /// verified path. False if any read fell through to the raw-RPC
    /// fallback during the simulation's cooldown window.
    pub verified: bool,
    /// Base fee of the block the sim was pinned to, in wei. Lets the UI
    /// denominate `gas_used` in ETH (`gas_used × base_fee ≈ fee`)
    /// without a second fee fetch. An approximation by design: it
    /// excludes the priority tip and, for Safe inner calls, the
    /// `execTransaction` overhead. `0` when unavailable.
    pub base_fee_per_gas: u64,
}

impl SimulationResult {
    /// Placeholder when simulation couldn't run at all — e.g. the active
    /// chain doesn't support simulation in this build, or the network
    /// handle wasn't ready. The review screen renders an inline
    /// "Simulation unavailable on this chain" notice and keeps the
    /// existing Confirm button.
    pub fn unavailable() -> Self {
        Self {
            outcome: SimOutcome::Unavailable,
            gas_used: 0,
            transfers: Vec::new(),
            verified: false,
            base_fee_per_gas: 0,
        }
    }

    pub fn is_revert(&self) -> bool {
        matches!(
            self.outcome,
            SimOutcome::Revert { .. } | SimOutcome::Halt { .. }
        )
    }

    /// The EVM executed to completion. Combined with `verified`, drives
    /// the auto-retry ("success but on fallback state — try once more on
    /// the verified path") and the Re-simulate button visibility (a
    /// verified success is the one result not worth re-running).
    pub fn is_success(&self) -> bool {
        matches!(self.outcome, SimOutcome::Success { .. })
    }

    /// Symmetry with `is_revert`. Intentional public API for future
    /// callers that need to branch on "have we run a sim at all?";
    /// retained even though the v1 UI inspects `outcome` directly.
    #[allow(dead_code)]
    pub fn is_unavailable(&self) -> bool {
        matches!(self.outcome, SimOutcome::Unavailable)
    }
}

// ============================================================================
// HeliosDb
// ============================================================================

struct HeliosDb {
    network: Arc<dyn BalanceFetcher>,
    chain: Chain,
    handle: Handle,
    accounts: HashMap<Address, AccountInfo>,
    storage: HashMap<(Address, U256), U256>,
    /// Addresses whose storage was locally cleared by a committed tx
    /// (CREATE or SELFDESTRUCT). A storage miss on one of these reads as
    /// zero rather than re-fetching stale on-chain state — only relevant
    /// on the batch path, where state is committed between sub-calls.
    cleared: HashSet<Address>,
    /// `true` while every read so far went through Helios's verified
    /// path. Flipped to `false` the first time a read returns
    /// `VerifiedRead { verified: false, .. }`. The simulator surfaces
    /// this on the review screen so the user can tell whether the
    /// simulation result inherits Helios's trust guarantee or is
    /// running against fallback-RPC state.
    all_verified: bool,
}

impl HeliosDb {
    fn new(network: Arc<dyn BalanceFetcher>, chain: Chain, handle: Handle) -> Self {
        Self {
            network,
            chain,
            handle,
            accounts: HashMap::new(),
            storage: HashMap::new(),
            cleared: HashSet::new(),
            all_verified: true,
        }
    }
}

impl Database for HeliosDb {
    type Error = DbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, DbError> {
        if let Some(info) = self.accounts.get(&address) {
            return Ok(Some(info.clone()));
        }
        let net = self.network.clone();
        let chain = self.chain;
        let (balance, nonce, code) = self
            .handle
            .block_on(async move {
                tokio::try_join!(
                    net.get_balance_raw(address, chain),
                    net.get_transaction_count(address, chain),
                    net.get_code(address, chain),
                )
            })
            .map_err(|e| DbError(format!("basic({address}): {e}")))?;
        if !balance.verified || !nonce.verified || !code.verified {
            self.all_verified = false;
        }
        let bytecode = Bytecode::new_raw(code.value.clone());
        let code_hash = if code.value.is_empty() {
            KECCAK_EMPTY
        } else {
            keccak256(&code.value)
        };
        let info = AccountInfo {
            balance: balance.value,
            nonce: nonce.value,
            code_hash,
            code: Some(bytecode),
        };
        self.accounts.insert(address, info.clone());
        Ok(Some(info))
    }

    fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, DbError> {
        // We always populate `AccountInfo.code` in `basic`, so revm
        // never falls through to a code-by-hash lookup. If it ever
        // does, surface it loudly — silently returning empty bytecode
        // would let a buggy execution path run with the wrong code.
        Err(DbError(
            "code_by_hash unimplemented — code is always inlined via basic()".into(),
        ))
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, DbError> {
        if let Some(value) = self.storage.get(&(address, slot)) {
            return Ok(*value);
        }
        // A locally created/destructed account starts with empty storage;
        // an unset slot is zero, not whatever the chain held before.
        if self.cleared.contains(&address) {
            return Ok(U256::ZERO);
        }
        let net = self.network.clone();
        let chain = self.chain;
        let read = self
            .handle
            .block_on(async move { net.get_storage_at(address, slot, chain).await })
            .map_err(|e| DbError(format!("storage({address}, slot {slot}): {e}")))?;
        if !read.verified {
            self.all_verified = false;
        }
        let value = U256::from_be_bytes(read.value.0);
        self.storage.insert((address, slot), value);
        Ok(value)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, DbError> {
        // Servicing this needs a verified `eth_getBlockByNumber`, which
        // `BalanceFetcher` does not expose. Surfacing the gap is deliberate:
        // returning zero would be a *wrong* execution rather than a missing
        // one, and a preflight that quietly computes the wrong answer is worse
        // than one that declines. The caller renders this string, so it is
        // written for the person reading it — the batch composer, who can hit
        // it through any callee that reads BLOCKHASH.
        Err(DbError(format!(
            "this batch reads the hash of block {number}, which Kao's preflight can't supply — \
             the simulation can't run, but the batch itself may be fine"
        )))
    }
}

/// Commit an executed tx's state changes back into the cache so a later
/// sub-call in the same batch observes them (e.g. `approve` then a
/// `supply` that spends the allowance). Mirrors revm's own in-memory
/// commit: skip untouched accounts, reset self-destructed / freshly-created
/// accounts to empty storage, and write through each changed slot's present
/// value. Only exercised by [`simulate_batch`]; the single-call path uses
/// `replay()` and never commits.
impl DatabaseCommit for HeliosDb {
    fn commit(&mut self, changes: RevmHashMap<Address, Account>) {
        for (address, account) in changes {
            if !account.is_touched() {
                continue;
            }
            if account.is_selfdestructed() {
                self.accounts.insert(address, AccountInfo::default());
                self.storage.retain(|(a, _), _| *a != address);
                self.cleared.insert(address);
                continue;
            }
            if account.is_created() {
                // New account: its prior on-chain storage (if any) is gone.
                self.storage.retain(|(a, _), _| *a != address);
                self.cleared.insert(address);
            }
            self.accounts.insert(address, account.info);
            for (slot, value) in account.storage {
                self.storage.insert((address, slot), value.present_value());
            }
        }
    }
}

// ============================================================================
// simulate_call / simulate_tx
// ============================================================================

/// Generous tx-level gas cap. With `disable_block_gas_limit = true` set on
/// the CfgEnv, the EVM only enforces the tx's own gas cap; setting it to
/// the mainnet block limit keeps even gas-heavy paths from artificially
/// running out during preflight while the *measured* `gas_used` stays
/// faithful to what the tx actually consumes.
const SIM_GAS_LIMIT: u64 = 30_000_000;

/// A fully-resolved call to preflight. Caller-agnostic: `from` may be an
/// EOA (the send flow) or a contract such as a Safe (`disable_eip3607`
/// on the CfgEnv permits a caller with code).
///
/// `nonce`: pass the real account nonce for EOA sends; pass `0` for
/// contract callers. `build_cfg` sets `disable_nonce_check = true`, so
/// the value is never compared against state — it only feeds CREATE
/// address derivation, and every sim here is a CALL.
#[derive(Debug, Clone)]
pub struct CallSpec {
    pub chain: Chain,
    pub from: Address,
    pub to: Address,
    pub value: U256,
    pub input: Bytes,
    pub nonce: u64,
}

pub async fn simulate_tx(
    network: Arc<dyn BalanceFetcher>,
    plan: &SendPlan,
    nonce: u64,
) -> Result<SimulationResult, SimError> {
    // Local preflight needs a Helios-verified state source, which only the
    // built-in chains have. Custom (unverified) networks return an error the
    // caller degrades to `SimulationResult::unavailable()`. In practice the
    // send path gates this on `NetworkId::supports_simulation()` first, so a
    // custom plan never reaches here — this is the type-level backstop.
    let Some(chain) = plan.chain.builtin() else {
        return Err(SimError::State(
            "simulation unsupported on custom network".into(),
        ));
    };
    let (to, value, input) = plan.tx_target();
    let spec = CallSpec {
        chain,
        from: plan.from,
        to,
        value,
        input,
        nonce,
    };
    simulate_call(network, &spec).await
}

pub async fn simulate_call(
    network: Arc<dyn BalanceFetcher>,
    spec: &CallSpec,
) -> Result<SimulationResult, SimError> {
    let chain = spec.chain;
    info!(
        chain = %chain.label(),
        chain_id = chain.chain_id(),
        from = %spec.from,
        "sim: starting",
    );

    let latest = network.latest_block(chain).await.map_err(SimError::State)?;
    let block_verified = latest.verified;
    let block = latest.value;
    debug!(
        chain = %chain.label(),
        block_number = block.number,
        block_hash = %block.hash,
        verified = block_verified,
        "sim: pinned latest block",
    );

    let (to, value, input) = (spec.to, spec.value, spec.input.clone());
    let from = spec.from;
    let nonce = spec.nonce;
    let chain_id = chain.chain_id();
    let base_fee_per_gas = block.base_fee_per_gas;
    let handle = Handle::current();

    let result = tokio::task::spawn_blocking(move || -> Result<SimulationResult, SimError> {
        let mut db = HeliosDb::new(network, chain, handle);
        if !block_verified {
            db.all_verified = false;
        }
        let block_env = build_block_env(&block);
        let tx_env = build_tx_env(from, to, value, input, nonce, chain_id);
        let cfg = build_cfg(chain_id);

        let ctx = Context::mainnet()
            .with_block(block_env)
            .with_tx(tx_env)
            .with_cfg(cfg);
        let mut evm = ctx.with_db(&mut db).build_mainnet();
        let res = evm.replay().map_err(|e| SimError::Evm(format!("{e:?}")))?;
        let verified = db.all_verified;
        Ok(materialize(res.result, verified, base_fee_per_gas))
    })
    .await
    .map_err(|e| SimError::Join(e.to_string()))??;

    info!(
        chain = %chain.label(),
        gas_used = result.gas_used,
        transfers = result.transfers.len(),
        verified = result.verified,
        reverted = result.is_revert(),
        "sim: done",
    );
    Ok(result)
}

// ============================================================================
// Batch simulation (Transaction Builder)
// ============================================================================

/// One sub-call of a batch. Mirrors the inner semantics of a MultiSend
/// delegatecall: each sub-call runs with `msg.sender == from` (the Safe)
/// against state carried over from the previous sub-call.
#[derive(Debug, Clone)]
pub struct BatchStep {
    pub to: Address,
    pub value: U256,
    pub input: Bytes,
}

/// Aggregate outcome of simulating a whole batch.
#[derive(Debug, Clone)]
pub enum BatchOutcome {
    /// Every sub-call executed successfully.
    Success,
    /// Sub-call `step` (0-based) reverted; the real batch reverts atomically.
    Revert { step: usize, reason: String },
    /// Sub-call `step` halted (out of gas / invalid opcode / …).
    Halt { step: usize, reason: String },
    /// The simulator could not produce a verdict, and here is why.
    ///
    /// Distinct from [`Self::Unavailable`], which says only "no answer". The
    /// error string used to be dropped on the floor by the caller, so a Helios
    /// outage, a `BLOCKHASH` read the db can't service, and a batch whose value
    /// exceeds the sender's balance all rendered as the same shrug — followed
    /// by advice to re-run a preflight that, for most of those, can never
    /// succeed.
    Error(String),
    /// Simulation couldn't run (unsupported chain / upstream error).
    Unavailable,
}

#[derive(Debug, Clone)]
pub struct BatchSimResult {
    pub outcome: BatchOutcome,
    /// Sum of gas metered by the executed sub-calls. Advisory: excludes the
    /// MultiSend loop, the `execTransaction` wrapper, and signature-check
    /// overhead — the review pairs it with a real `eth_estimateGas` at
    /// execute time.
    pub gas_used: u64,
    /// Net token transfers observed across all sub-calls. Only meaningful on
    /// `Success` — a reverting batch performs no net transfer, so it's
    /// cleared.
    pub transfers: Vec<TokenTransfer>,
    pub verified: bool,
    pub base_fee_per_gas: u64,
    /// The block this ran against. A verdict is only a statement about the
    /// state at one height; without the height, a "Simulation passed" from
    /// twenty minutes and a hundred blocks ago is indistinguishable from one
    /// taken a second before the review opened.
    pub block: u64,
}

impl BatchSimResult {
    pub fn unavailable() -> Self {
        Self {
            outcome: BatchOutcome::Unavailable,
            gas_used: 0,
            transfers: Vec::new(),
            verified: false,
            base_fee_per_gas: 0,
            block: 0,
        }
    }

    /// The simulator failed outright — `reason` is what to tell the user.
    pub fn errored(reason: impl Into<String>) -> Self {
        Self {
            outcome: BatchOutcome::Error(reason.into()),
            ..Self::unavailable()
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self.outcome, BatchOutcome::Success)
    }

    pub fn is_revert(&self) -> bool {
        matches!(
            self.outcome,
            BatchOutcome::Revert { .. } | BatchOutcome::Halt { .. }
        )
    }
}

/// Simulate a batch of sub-calls as one atomic unit.
///
/// Each step runs from `from` (the Safe) against *shared, committed* state,
/// so a `supply` sees the allowance a preceding `approve` granted. Execution
/// stops at the first revert/halt — exactly where the on-chain MultiSend
/// would revert the whole batch — and reports which step failed and why.
///
/// This models the *inner* effect of the MultiSend delegatecall (each
/// sub-call as the Safe), not the full `execTransaction` wrapper. Like the
/// single-call preflight it is advisory: a stale-state false negative must
/// never hard-block a legitimate batch.
pub async fn simulate_batch(
    network: Arc<dyn BalanceFetcher>,
    chain: Chain,
    from: Address,
    steps: Vec<BatchStep>,
) -> Result<BatchSimResult, SimError> {
    if steps.is_empty() {
        return Err(SimError::Evm("empty batch".into()));
    }
    info!(
        chain = %chain.label(),
        from = %from,
        steps = steps.len(),
        "batch sim: starting",
    );

    let latest = network.latest_block(chain).await.map_err(SimError::State)?;
    let block_verified = latest.verified;
    let block = latest.value;
    let chain_id = chain.chain_id();
    let base_fee_per_gas = block.base_fee_per_gas;
    let block_number = block.number;
    let handle = Handle::current();

    let result = tokio::task::spawn_blocking(move || -> Result<BatchSimResult, SimError> {
        let mut db = HeliosDb::new(network, chain, handle);
        if !block_verified {
            db.all_verified = false;
        }
        let block_env = build_block_env(&block);
        let cfg = build_cfg(chain_id);
        let ctx = Context::mainnet().with_block(block_env).with_cfg(cfg);
        let mut evm = ctx.with_db(&mut db).build_mainnet();

        let mut gas_used: u64 = 0;
        let mut transfers: Vec<TokenTransfer> = Vec::new();
        let mut outcome = BatchOutcome::Success;
        for (i, step) in steps.iter().enumerate() {
            let tx_env = build_tx_env(from, step.to, step.value, step.input.clone(), 0, chain_id);
            let res = match evm.transact_commit(tx_env) {
                Ok(r) => r,
                // revm refuses a step whose `value` exceeds the sender's
                // balance in its upfront check, before the EVM runs, and
                // reports it as an *error* rather than a Revert. It is a real
                // prediction about this batch — the chain would do the same —
                // so it belongs in the outcome, not in the error channel where
                // it degrades to "simulation unavailable". Mirrors the same
                // translation in `safe::sim::simulate_safe_inner`.
                Err(e) => {
                    let msg = format!("{e:?}");
                    if msg.contains("LackOfFund") {
                        outcome = BatchOutcome::Revert {
                            step: i,
                            reason: "sender's balance is below this call's value".to_string(),
                        };
                        break;
                    }
                    return Err(SimError::Evm(msg));
                }
            };
            gas_used = gas_used.saturating_add(res.gas_used());
            match res {
                ExecutionResult::Success { logs, .. } => {
                    transfers.extend(extract_transfers(&logs));
                }
                ExecutionResult::Revert { output, .. } => {
                    let reason = decode_revert_reason(&output).unwrap_or_else(|| {
                        if output.is_empty() {
                            "reverted without reason".to_string()
                        } else {
                            format!("0x{}", alloy::hex::encode(output.as_ref()))
                        }
                    });
                    outcome = BatchOutcome::Revert { step: i, reason };
                    break;
                }
                ExecutionResult::Halt { reason, .. } => {
                    outcome = BatchOutcome::Halt {
                        step: i,
                        reason: format!("{reason:?}"),
                    };
                    break;
                }
            }
        }
        // A reverting batch performs no net transfer — don't show one.
        if !matches!(outcome, BatchOutcome::Success) {
            transfers.clear();
        }
        let verified = db.all_verified;
        Ok(BatchSimResult {
            outcome,
            gas_used,
            transfers,
            verified,
            base_fee_per_gas,
            block: block_number,
        })
    })
    .await
    .map_err(|e| SimError::Join(e.to_string()))??;

    info!(
        chain = %chain.label(),
        gas_used = result.gas_used,
        transfers = result.transfers.len(),
        verified = result.verified,
        reverted = result.is_revert(),
        "batch sim: done",
    );
    Ok(result)
}

fn build_block_env(block: &LatestBlock) -> BlockEnv {
    // Prague's blob base-fee update fraction. We don't simulate blob
    // txs (send flow is native ETH or ERC-20 transfer, neither carries
    // blobs), so this is only here to satisfy revm's BlockEnv shape —
    // the value is correct for Prague-and-later mainnet headers.
    const PRAGUE_BLOB_FRACTION: u64 = 5_007_716;
    // revm's Cancun+ execution refuses to start with
    // `blob_excess_gas_and_price = None` (it returns
    // `InvalidHeader::ExcessBlobGasNotSet`). Mainnet headers since
    // Cancun activation always carry the field, but a pre-Cancun block
    // header or a fallback-RPC response missing the field would crash
    // every simulation. Helios's own EVM defaults to `(0, fraction)`
    // in that case — we mirror that so a missing field falls back to a
    // zero-blob-load block instead of a hard error.
    let blob = block
        .excess_blob_gas
        .map(|g| BlobExcessGasAndPrice::new(g, PRAGUE_BLOB_FRACTION))
        .unwrap_or_else(|| BlobExcessGasAndPrice::new(0, PRAGUE_BLOB_FRACTION));
    BlockEnv {
        number: U256::from(block.number),
        beneficiary: block.beneficiary,
        timestamp: U256::from(block.timestamp),
        gas_limit: block.gas_limit,
        basefee: block.base_fee_per_gas,
        difficulty: U256::ZERO,
        prevrandao: Some(block.prevrandao),
        blob_excess_gas_and_price: Some(blob),
    }
}

fn build_tx_env(
    from: Address,
    to: Address,
    value: U256,
    input: Bytes,
    nonce: u64,
    chain_id: u64,
) -> TxEnv {
    // `gas_price = 0` and `gas_priority_fee = None` matter for a real
    // reason, not laziness: revm reserves `gas_limit × gas_price` from
    // the caller's balance upfront before executing the tx (the EIP-1559
    // `LackOfFundForMaxFee` check). With our 30M `gas_limit` and a
    // mainnet fee of ~20 gwei that's ~0.6 ETH locked up — a routine
    // user with less than that on the chain would see *every* sim
    // bounce with `LackOfFundForMaxFee` and degrade to "unavailable".
    // Helios does the same thing in its `call` / `estimate_gas` path
    // (see `helios/ethereum/src/evm.rs::tx_env`: `gas_price()` falls
    // back to `0` for an unsigned `TransactionRequest`). Combined with
    // `disable_base_fee = true` on the CfgEnv this lets the tx execute
    // for free during preflight; `gas_used` is independent of
    // `gas_price`, so accuracy is unaffected.
    TxEnv {
        tx_type: 2, // EIP-1559
        caller: from,
        gas_limit: SIM_GAS_LIMIT,
        gas_price: 0,
        kind: TxKind::Call(to),
        value,
        data: input,
        nonce,
        chain_id: Some(chain_id),
        gas_priority_fee: None,
        ..TxEnv::default()
    }
}

fn build_cfg(chain_id: u64) -> CfgEnv {
    let mut cfg = CfgEnv::default();
    cfg.chain_id = chain_id;
    // Mainnet 2026 — Prague activated May 2025. Hard-coded for now;
    // when the OP-stack follow-up lands, derive from chain + timestamp
    // via helios's `get_spec_id_for_block_timestamp`.
    cfg.spec = SpecId::PRAGUE;
    // `optional_*` features unlock these on the CfgEnv (matched in
    // Cargo.toml). All four together mean: simulate the tx as it
    // would execute, but don't reject it just because the on-chain
    // nonce hasn't caught up or the base fee window slipped — the
    // user is about to sign right now, not at the block we pinned.
    cfg.disable_block_gas_limit = true;
    cfg.disable_eip3607 = true; // EOA-with-code (EIP-7702) tolerance
    cfg.disable_base_fee = true;
    cfg.disable_nonce_check = true;
    cfg
}

fn materialize(result: ExecutionResult, verified: bool, base_fee_per_gas: u64) -> SimulationResult {
    let gas_used = result.gas_used();
    let (outcome, logs) = match result {
        ExecutionResult::Success { output, logs, .. } => {
            let bytes = match output {
                Output::Call(b) => b,
                Output::Create(b, _) => b,
            };
            (SimOutcome::Success { output: bytes }, logs)
        }
        ExecutionResult::Revert { output, .. } => {
            let reason = decode_revert_reason(&output).unwrap_or_else(|| {
                if output.is_empty() {
                    "reverted without reason".to_string()
                } else {
                    format!("0x{}", alloy::hex::encode(output.as_ref()))
                }
            });
            (
                SimOutcome::Revert {
                    reason,
                    raw: output,
                },
                Vec::new(),
            )
        }
        ExecutionResult::Halt { reason, .. } => (
            SimOutcome::Halt {
                reason: format!("{reason:?}"),
            },
            Vec::new(),
        ),
    };
    let transfers = extract_transfers(&logs);
    if matches!(outcome, SimOutcome::Halt { .. }) {
        warn!("sim: EVM halted (gas_used={gas_used})");
    }
    SimulationResult {
        outcome,
        gas_used,
        transfers,
        verified,
        base_fee_per_gas,
    }
}

// ============================================================================
// Revert reason decoding
// ============================================================================

/// keccak256("Error(string)")[..4] — Solidity's `require(false, "msg")`
/// and `revert("msg")` both wrap the reason in this envelope.
const ERROR_STRING_SELECTOR: [u8; 4] = [0x08, 0xc3, 0x79, 0xa0];
/// keccak256("Panic(uint256)")[..4] — Solidity's compiler-inserted
/// runtime checks (overflow, array-out-of-bounds, etc.) revert with this
/// envelope.
const PANIC_UINT_SELECTOR: [u8; 4] = [0x4e, 0x48, 0x7b, 0x71];

pub fn decode_revert_reason(output: &Bytes) -> Option<String> {
    if output.len() < 4 {
        return None;
    }
    let selector: [u8; 4] = output[..4].try_into().ok()?;
    let body = &output[4..];

    if selector == ERROR_STRING_SELECTOR {
        // ABI layout: offset (32B) || length (32B) || data (padded to 32B)
        if body.len() < 64 {
            return None;
        }
        let len_u256 = U256::from_be_slice(&body[32..64]);
        let len = usize::try_from(len_u256).ok()?;
        let end = 64usize.checked_add(len)?;
        if body.len() < end {
            return None;
        }
        std::str::from_utf8(&body[64..end])
            .ok()
            .map(|s| s.to_string())
    } else if selector == PANIC_UINT_SELECTOR && body.len() >= 32 {
        let code = U256::from_be_slice(&body[..32]);
        Some(panic_code_to_message(code))
    } else {
        None
    }
}

fn panic_code_to_message(code: U256) -> String {
    // Solidity's documented Panic codes. Anything above 0xff is non-
    // standard; surface the raw hex so the user can look it up.
    if code > U256::from(0xffu64) {
        return format!("panic 0x{code:x}");
    }
    let code_u8 = code.byte(0);
    let label = match code_u8 {
        0x00 => "generic compiler-inserted panic",
        0x01 => "assertion failed",
        0x11 => "arithmetic overflow or underflow",
        0x12 => "division or modulo by zero",
        0x21 => "invalid enum value",
        0x22 => "storage byte array incorrectly encoded",
        0x31 => "pop() on an empty array",
        0x32 => "array index out of bounds",
        0x41 => "allocation too large or out of memory",
        0x51 => "called an uninitialized internal function",
        _ => "unknown panic",
    };
    format!("panic 0x{code_u8:02x}: {label}")
}

// ============================================================================
// Transfer extraction
// ============================================================================

fn transfer_topic() -> B256 {
    keccak256("Transfer(address,address,uint256)")
}

pub fn extract_transfers(logs: &[Log]) -> Vec<TokenTransfer> {
    let sig = transfer_topic();
    let mut out = Vec::new();
    for log in logs {
        let topics = log.topics();
        if topics.first() != Some(&sig) {
            continue;
        }
        if topics.len() < 3 {
            continue;
        }
        let from = address_from_topic(&topics[1]);
        let to = address_from_topic(&topics[2]);
        let (value, is_nft) = if topics.len() >= 4 {
            // ERC-721: tokenId is indexed (topic[3]); data is empty.
            (U256::from_be_bytes(topics[3].0), true)
        } else if log.data.data.len() >= 32 {
            // ERC-20: amount is the first 32 bytes of the log data.
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&log.data.data[..32]);
            (U256::from_be_bytes(buf), false)
        } else {
            continue;
        };
        out.push(TokenTransfer {
            token: log.address,
            from,
            to,
            value,
            is_nft,
        });
    }
    out
}

fn address_from_topic(topic: &B256) -> Address {
    // An indexed `address` is right-aligned in a 32-byte topic; bytes
    // 0..12 are zero-padding, bytes 12..32 are the address.
    let mut buf = [0u8; 20];
    buf.copy_from_slice(&topic.0[12..]);
    Address::from(buf)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{LogData, address, b256, bytes};

    #[test]
    fn decode_error_string_revert() {
        // From a real USDC `transfer` revert: "ERC20: transfer amount exceeds balance"
        // Encoded as: selector(4) || offset(32, = 0x20) || length(32) || string-padded
        let mut bytes_vec: Vec<u8> = Vec::new();
        bytes_vec.extend_from_slice(&ERROR_STRING_SELECTOR);
        // offset = 32
        bytes_vec.extend_from_slice(&{
            let mut b = [0u8; 32];
            b[31] = 0x20;
            b
        });
        let msg = b"ERC20: transfer amount exceeds balance";
        // length = msg.len()
        bytes_vec.extend_from_slice(&{
            let mut b = [0u8; 32];
            b[24..32].copy_from_slice(&(msg.len() as u64).to_be_bytes());
            b
        });
        bytes_vec.extend_from_slice(msg);
        // pad to 32-byte boundary
        let pad = (32 - msg.len() % 32) % 32;
        bytes_vec.extend_from_slice(&vec![0u8; pad]);
        let out = Bytes::from(bytes_vec);
        let decoded = decode_revert_reason(&out).expect("decoded");
        assert_eq!(decoded, "ERC20: transfer amount exceeds balance");
    }

    #[test]
    fn decode_panic_overflow() {
        // selector(4) || code 0x11 left-padded to 32
        let mut bytes_vec: Vec<u8> = Vec::new();
        bytes_vec.extend_from_slice(&PANIC_UINT_SELECTOR);
        let mut code = [0u8; 32];
        code[31] = 0x11;
        bytes_vec.extend_from_slice(&code);
        let out = Bytes::from(bytes_vec);
        let decoded = decode_revert_reason(&out).expect("decoded");
        assert!(
            decoded.contains("0x11"),
            "expected panic code in message, got {decoded}"
        );
        assert!(
            decoded.contains("overflow") || decoded.contains("underflow"),
            "expected overflow label, got {decoded}"
        );
    }

    #[test]
    fn decode_empty_revert_returns_none() {
        assert!(decode_revert_reason(&Bytes::new()).is_none());
    }

    #[test]
    fn decode_unknown_selector_returns_none() {
        let out =
            bytes!("deadbeef0000000000000000000000000000000000000000000000000000000000000000");
        assert!(decode_revert_reason(&out).is_none());
    }

    #[test]
    fn extract_erc20_transfer() {
        // USDC `Transfer(from, to, 1_000_000)` — 6-decimal "1 USDC"
        let usdc: Address = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        let from: Address = address!("000000000000000000000000000000000000beEF");
        let to: Address = address!("000000000000000000000000000000000000dEaD");
        let topic0 = transfer_topic();
        let mut topic1_bytes = [0u8; 32];
        topic1_bytes[12..].copy_from_slice(from.as_slice());
        let mut topic2_bytes = [0u8; 32];
        topic2_bytes[12..].copy_from_slice(to.as_slice());
        let mut data = [0u8; 32];
        let amount = 1_000_000u64;
        data[24..].copy_from_slice(&amount.to_be_bytes());

        let log = Log {
            address: usdc,
            data: LogData::new_unchecked(
                vec![topic0, B256::from(topic1_bytes), B256::from(topic2_bytes)],
                Bytes::from(data.to_vec()),
            ),
        };
        let transfers = extract_transfers(&[log]);
        assert_eq!(transfers.len(), 1);
        let t = &transfers[0];
        assert_eq!(t.token, usdc);
        assert_eq!(t.from, from);
        assert_eq!(t.to, to);
        assert_eq!(t.value, U256::from(amount));
        assert!(!t.is_nft);
    }

    #[test]
    fn extract_erc721_transfer_flagged_nft() {
        let nft_contract: Address = address!("00000000000000000000000000000000000A721C");
        let from: Address = address!("000000000000000000000000000000000000beEF");
        let to: Address = address!("000000000000000000000000000000000000dEaD");
        let topic0 = transfer_topic();
        let mut topic1_bytes = [0u8; 32];
        topic1_bytes[12..].copy_from_slice(from.as_slice());
        let mut topic2_bytes = [0u8; 32];
        topic2_bytes[12..].copy_from_slice(to.as_slice());
        // tokenId = 42 as topic[3]
        let token_id_topic: B256 = {
            let mut b = [0u8; 32];
            b[31] = 42;
            B256::from(b)
        };

        let log = Log {
            address: nft_contract,
            data: LogData::new_unchecked(
                vec![
                    topic0,
                    B256::from(topic1_bytes),
                    B256::from(topic2_bytes),
                    token_id_topic,
                ],
                Bytes::new(),
            ),
        };
        let transfers = extract_transfers(&[log]);
        assert_eq!(transfers.len(), 1);
        let t = &transfers[0];
        assert!(t.is_nft);
        assert_eq!(t.value, U256::from(42u64));
    }

    #[test]
    fn extract_skips_non_transfer_logs() {
        let unrelated_topic: B256 =
            b256!("dead0000beef0000dead0000beef0000dead0000beef0000dead0000beef0000");
        let log = Log {
            address: Address::ZERO,
            data: LogData::new_unchecked(vec![unrelated_topic], Bytes::new()),
        };
        assert!(extract_transfers(&[log]).is_empty());
    }

    #[test]
    fn unavailable_placeholder_is_safe_default() {
        let r = SimulationResult::unavailable();
        assert_eq!(r.gas_used, 0);
        assert!(r.transfers.is_empty());
        assert!(!r.verified);
        assert!(!r.is_revert());
        assert!(r.is_unavailable());
    }

    #[test]
    fn transfer_topic_matches_canonical_keccak() {
        // Pin the topic-0 hash for ERC-20 Transfer events. If alloy ever
        // changes its keccak implementation, this guards against silently
        // mis-matching live event filters.
        let expected = b256!("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");
        assert_eq!(transfer_topic(), expected);
    }

    /// Regression: `simulate_tx` used to bounce off `LackOfFundForMaxFee`
    /// for any caller without ~0.6 ETH of headroom, because revm reserves
    /// `gas_limit × gas_price` upfront. We now set `gas_price = 0` for
    /// preflight to avoid that. The `MockFetcher` returns zero balance
    /// for every address, so a tx that succeeded with the old code would
    /// have to have a zero-funded caller — i.e. the same condition this
    /// test reproduces. If gas_price ever drifts back to nonzero, this
    /// test fails because the upfront balance check rejects the tx.
    #[tokio::test]
    async fn simulate_native_transfer_with_zero_balance_caller_succeeds() {
        // Sweep every chain Kao supports. Mainnet exercises the original
        // `LackOfFundForMaxFee` regression (gas_price=0 fix); Base and
        // Optimism additionally exercise the L2 path — stock revm with
        // `SpecId::PRAGUE` correctly meters a native ETH transfer on
        // OP-stack chains because the send flow touches no OP-specific
        // precompiles. If a future revm bump introduces chain-id
        // -conditional behavior that breaks L2 sim, this test fails
        // loudly here instead of silently in production.
        for chain in Chain::ALL {
            assert_simulate_native_succeeds_on(chain).await;
        }
    }

    async fn assert_simulate_native_succeeds_on(chain: Chain) {
        use crate::net::MockFetcher;
        use crate::wallet::tx::{SendPlan, SendToken};
        use alloy::primitives::address;

        assert!(
            chain.supports_simulation(),
            "{} no longer supports simulation — update or remove this test",
            chain.label(),
        );
        let network: Arc<dyn BalanceFetcher> = Arc::new(MockFetcher::new());
        let plan = SendPlan {
            from: address!("000000000000000000000000000000000000beEF"),
            recipient: address!("000000000000000000000000000000000000dEaD"),
            token: SendToken::Native,
            amount_units: U256::ZERO,
            chain: chain.into(),
        };
        let result = simulate_tx(network, &plan, /* nonce */ 0)
            .await
            .unwrap_or_else(|e| panic!("{} sim should not fail: {e}", chain.label()));
        assert!(
            matches!(result.outcome, SimOutcome::Success { .. }),
            "{}: expected Success, got {:?}",
            chain.label(),
            result.outcome,
        );
        assert_eq!(
            result.gas_used,
            21000,
            "{}: native transfer should meter 21000 gas",
            chain.label(),
        );
        assert!(result.transfers.is_empty());
    }

    /// Pins the "contract callers pass nonce 0" decision: `disable_nonce_check`
    /// means TxEnv.nonce is never compared against state, so a hard-coded 0
    /// is safe for any CALL — the field only feeds CREATE address derivation.
    /// If a future revm bump starts enforcing the nonce again, this fails.
    #[tokio::test]
    async fn simulate_call_contract_caller_with_nonce_zero_succeeds() {
        use crate::net::MockFetcher;
        use alloy::primitives::address;

        let network: Arc<dyn BalanceFetcher> = Arc::new(MockFetcher::new());
        let spec = CallSpec {
            chain: Chain::Mainnet,
            from: address!("0000000000000000000000000000000000005AFE"),
            to: address!("000000000000000000000000000000000000dEaD"),
            value: U256::ZERO,
            input: Bytes::new(),
            nonce: 0,
        };
        let result = simulate_call(network, &spec)
            .await
            .expect("sim should not fail");
        assert!(
            matches!(result.outcome, SimOutcome::Success { .. }),
            "expected Success, got {:?}",
            result.outcome,
        );
        assert_eq!(result.gas_used, 21000);
    }

    #[test]
    fn decode_error_string_empty_message() {
        // `revert("")` — selector + offset(0x20) + length(0). No string
        // body. Must decode to an empty string, not None.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&ERROR_STRING_SELECTOR);
        let mut offset = [0u8; 32];
        offset[31] = 0x20;
        buf.extend_from_slice(&offset);
        buf.extend_from_slice(&[0u8; 32]); // length = 0
        let decoded = decode_revert_reason(&Bytes::from(buf)).expect("decoded");
        assert_eq!(decoded, "");
    }

    #[test]
    fn decode_error_string_length_overflows_body_returns_none() {
        // selector + offset(0x20) + length(0xFF) but only one byte of data —
        // a malicious or truncated revert payload must not panic or read
        // past the buffer. We return None and the caller falls back to a
        // hex dump.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&ERROR_STRING_SELECTOR);
        let mut offset = [0u8; 32];
        offset[31] = 0x20;
        buf.extend_from_slice(&offset);
        let mut len = [0u8; 32];
        len[31] = 0xFF;
        buf.extend_from_slice(&len);
        buf.push(0x41); // single 'A' — not 0xFF bytes of data
        assert!(decode_revert_reason(&Bytes::from(buf)).is_none());
    }

    #[test]
    fn decode_error_string_invalid_utf8_returns_none() {
        // A revert string isn't required to be valid UTF-8 — Solidity
        // emits whatever bytes the contract gave it. We don't try to
        // sanitize; we just refuse to decode and let the caller fall
        // back to the hex dump.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&ERROR_STRING_SELECTOR);
        let mut offset = [0u8; 32];
        offset[31] = 0x20;
        buf.extend_from_slice(&offset);
        let mut len = [0u8; 32];
        len[31] = 2;
        buf.extend_from_slice(&len);
        // 0xFF 0xFE is not valid UTF-8 (continuation bytes only).
        buf.extend_from_slice(&[0xFF, 0xFE]);
        buf.extend_from_slice(&[0u8; 30]);
        assert!(decode_revert_reason(&Bytes::from(buf)).is_none());
    }

    #[test]
    fn decode_panic_division_by_zero_label() {
        // Pin Solidity's documented Panic(0x12) — `1 / 0` or `1 % 0`.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&PANIC_UINT_SELECTOR);
        let mut code = [0u8; 32];
        code[31] = 0x12;
        buf.extend_from_slice(&code);
        let decoded = decode_revert_reason(&Bytes::from(buf)).expect("decoded");
        assert!(decoded.contains("0x12"), "got {decoded}");
        assert!(
            decoded.contains("division") || decoded.contains("modulo"),
            "got {decoded}",
        );
    }

    #[test]
    fn decode_panic_array_oob_label() {
        // Solidity's Panic(0x32) — array index out of bounds.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&PANIC_UINT_SELECTOR);
        let mut code = [0u8; 32];
        code[31] = 0x32;
        buf.extend_from_slice(&code);
        let decoded = decode_revert_reason(&Bytes::from(buf)).expect("decoded");
        assert!(decoded.contains("0x32"), "got {decoded}");
        assert!(decoded.contains("out of bounds"), "got {decoded}");
    }

    #[test]
    fn decode_panic_unknown_small_code_falls_through_to_unknown() {
        // 0x99 is not in Solidity's documented panic table. We still
        // surface the code so the user can look it up, but the label is
        // "unknown panic" rather than something misleading.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&PANIC_UINT_SELECTOR);
        let mut code = [0u8; 32];
        code[31] = 0x99;
        buf.extend_from_slice(&code);
        let decoded = decode_revert_reason(&Bytes::from(buf)).expect("decoded");
        assert!(decoded.contains("0x99"), "got {decoded}");
        assert!(decoded.contains("unknown panic"), "got {decoded}");
    }

    #[test]
    fn decode_panic_oversized_code_renders_hex() {
        // A panic code above 0xff doesn't fit Solidity's single-byte
        // table at all; we degrade to the raw hex form so the message
        // doesn't claim a label we can't justify.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&PANIC_UINT_SELECTOR);
        let mut code = [0u8; 32];
        // 0x0100 — one bit past the documented range.
        code[30] = 0x01;
        buf.extend_from_slice(&code);
        let decoded = decode_revert_reason(&Bytes::from(buf)).expect("decoded");
        assert_eq!(decoded, "panic 0x100");
    }

    #[test]
    fn decode_panic_short_body_returns_none() {
        // Selector matches but body is < 32 bytes — must not panic.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&PANIC_UINT_SELECTOR);
        buf.extend_from_slice(&[0u8; 16]);
        assert!(decode_revert_reason(&Bytes::from(buf)).is_none());
    }

    #[test]
    fn extract_transfer_with_two_topics_is_skipped() {
        // A 2-topic log with the Transfer signature is malformed for both
        // ERC-20 (3 topics) and ERC-721 (4 topics). Don't fabricate a
        // transfer from a zero-`to`.
        let topic0 = transfer_topic();
        let from: Address = address!("000000000000000000000000000000000000beEF");
        let mut topic1_bytes = [0u8; 32];
        topic1_bytes[12..].copy_from_slice(from.as_slice());
        let log = Log {
            address: Address::ZERO,
            data: LogData::new_unchecked(vec![topic0, B256::from(topic1_bytes)], Bytes::new()),
        };
        assert!(extract_transfers(&[log]).is_empty());
    }

    #[test]
    fn extract_erc20_transfer_with_short_data_is_skipped() {
        // ERC-20 Transfer logs encode the amount as the first 32 bytes of
        // data. A truncated log (e.g. a buggy or hostile contract that
        // emits the right topics but a short payload) must not produce a
        // bogus zero-amount transfer.
        let topic0 = transfer_topic();
        let from: Address = address!("000000000000000000000000000000000000beEF");
        let to: Address = address!("000000000000000000000000000000000000dEaD");
        let mut topic1_bytes = [0u8; 32];
        topic1_bytes[12..].copy_from_slice(from.as_slice());
        let mut topic2_bytes = [0u8; 32];
        topic2_bytes[12..].copy_from_slice(to.as_slice());
        let log = Log {
            address: Address::ZERO,
            data: LogData::new_unchecked(
                vec![topic0, B256::from(topic1_bytes), B256::from(topic2_bytes)],
                Bytes::from(vec![0u8; 8]), // only 8 bytes of data, not 32
            ),
        };
        assert!(extract_transfers(&[log]).is_empty());
    }

    #[test]
    fn extract_returns_only_transfers_from_mixed_logs() {
        // A typical ERC-20 transfer emits an Approval *and* a Transfer
        // (or other unrelated events in the same call). Make sure the
        // filter returns exactly the Transfer rows in order.
        let usdc: Address = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        let from: Address = address!("000000000000000000000000000000000000beEF");
        let to: Address = address!("000000000000000000000000000000000000dEaD");
        let unrelated_topic: B256 =
            b256!("dead0000beef0000dead0000beef0000dead0000beef0000dead0000beef0000");
        let topic0 = transfer_topic();
        let mut topic1_bytes = [0u8; 32];
        topic1_bytes[12..].copy_from_slice(from.as_slice());
        let mut topic2_bytes = [0u8; 32];
        topic2_bytes[12..].copy_from_slice(to.as_slice());
        let mut data = [0u8; 32];
        data[24..].copy_from_slice(&5u64.to_be_bytes());

        let unrelated = Log {
            address: usdc,
            data: LogData::new_unchecked(vec![unrelated_topic], Bytes::new()),
        };
        let transfer = Log {
            address: usdc,
            data: LogData::new_unchecked(
                vec![topic0, B256::from(topic1_bytes), B256::from(topic2_bytes)],
                Bytes::from(data.to_vec()),
            ),
        };
        let transfers = extract_transfers(&[unrelated, transfer]);
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].value, U256::from(5u64));
    }

    #[test]
    fn extract_address_from_topic_ignores_high_bytes() {
        // EVM topics are 32 bytes; an indexed `address` is right-aligned
        // with the upper 12 bytes typically zero. But the EVM doesn't
        // *require* those bytes to be zero — a hand-crafted log via
        // assembly can leave dirty padding. Make sure decode ignores
        // bytes 0..12 instead of mixing them into the address.
        let to: Address = address!("000000000000000000000000000000000000dEaD");
        let from: Address = address!("000000000000000000000000000000000000beEF");
        let topic0 = transfer_topic();
        // Dirty upper 12 bytes — should be ignored.
        let mut topic1_bytes = [0xFFu8; 32];
        topic1_bytes[12..].copy_from_slice(from.as_slice());
        let mut topic2_bytes = [0u8; 32];
        topic2_bytes[12..].copy_from_slice(to.as_slice());
        let mut data = [0u8; 32];
        data[31] = 1;
        let log = Log {
            address: Address::ZERO,
            data: LogData::new_unchecked(
                vec![topic0, B256::from(topic1_bytes), B256::from(topic2_bytes)],
                Bytes::from(data.to_vec()),
            ),
        };
        let transfers = extract_transfers(&[log]);
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].from, from, "high bytes must be discarded");
    }

    #[test]
    fn is_revert_true_for_halt_outcome() {
        // The UI branches on `is_revert()` to decide whether to soften
        // the Confirm button to "Sign anyway". A Halt (OOG, invalid
        // opcode, stack overflow) is just as bad as a Revert from the
        // user's POV — pin that grouping.
        let halted = SimulationResult {
            outcome: SimOutcome::Halt {
                reason: "OutOfGas".into(),
            },
            gas_used: 30_000_000,
            transfers: Vec::new(),
            verified: true,
            base_fee_per_gas: 0,
        };
        assert!(halted.is_revert());
        assert!(!halted.is_unavailable());
    }

    #[test]
    fn is_revert_false_for_success() {
        let ok = SimulationResult {
            outcome: SimOutcome::Success {
                output: Bytes::new(),
            },
            gas_used: 21000,
            transfers: Vec::new(),
            verified: true,
            base_fee_per_gas: 0,
        };
        assert!(!ok.is_revert());
        assert!(!ok.is_unavailable());
    }

    /// Calling an address that has no deployed bytecode is, per the
    /// EVM, a successful no-op call. A real ERC-20 transfer on a chain
    /// where the token contract is missing (or where state is empty —
    /// e.g. our `MockFetcher`) would therefore *appear* to succeed
    /// without emitting any Transfer event. Pin that quirk so a future
    /// change to revm or the mock doesn't silently flip it to a
    /// Revert/Halt that would mislead the review screen.
    #[tokio::test]
    async fn simulate_erc20_transfer_to_codeless_target_is_silent_success() {
        use crate::net::MockFetcher;
        use crate::wallet::tx::{SendPlan, SendToken};
        use alloy::primitives::address;

        let network: Arc<dyn BalanceFetcher> = Arc::new(MockFetcher::new());
        let usdc: Address = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        let plan = SendPlan {
            from: address!("000000000000000000000000000000000000beEF"),
            recipient: address!("000000000000000000000000000000000000dEaD"),
            token: SendToken::Erc20 { contract: usdc },
            amount_units: U256::from(1_000_000u64),
            chain: Chain::Mainnet.into(),
        };
        let result = simulate_tx(network, &plan, /* nonce */ 0)
            .await
            .expect("sim should not fail");
        assert!(
            matches!(result.outcome, SimOutcome::Success { .. }),
            "EVM treats calls to codeless accounts as silent success, got {:?}",
            result.outcome,
        );
        assert!(
            result.transfers.is_empty(),
            "no Transfer event because no contract code ran",
        );
    }

    /// `verified` propagates upward when *any* state read fell through
    /// to the unverified fallback path. We can't exercise the full sim
    /// against a partly-unverified mock easily (the mock doesn't
    /// distinguish), but a `SimulationResult` constructed with
    /// `verified = false` must survive `is_revert` / `is_unavailable`
    /// inspection without being misclassified — the UI sources its
    /// trust badge directly from this field.
    #[tokio::test]
    async fn simulate_batch_native_transfers_sum_gas() {
        // Two native sends from a codeless caller succeed and meter
        // 21000 gas each — the batch reports their sum.
        use crate::net::MockFetcher;
        use alloy::primitives::address;

        let network: Arc<dyn BalanceFetcher> = Arc::new(MockFetcher::new());
        let safe = address!("0x0000000000000000000000000000000000005AFE");
        let steps = vec![
            BatchStep {
                to: address!("0x000000000000000000000000000000000000dEaD"),
                value: U256::ZERO,
                input: Bytes::new(),
            },
            BatchStep {
                to: address!("0x000000000000000000000000000000000000bEEF"),
                value: U256::ZERO,
                input: Bytes::new(),
            },
        ];
        let res = simulate_batch(network, Chain::Mainnet, safe, steps)
            .await
            .expect("batch sim runs");
        assert!(res.is_success(), "got {:?}", res.outcome);
        assert_eq!(res.gas_used, 42000);
        assert!(res.transfers.is_empty());
    }

    #[tokio::test]
    async fn simulate_batch_empty_errors() {
        use crate::net::MockFetcher;
        let network: Arc<dyn BalanceFetcher> = Arc::new(MockFetcher::new());
        assert!(
            simulate_batch(network, Chain::Mainnet, Address::ZERO, Vec::new())
                .await
                .is_err()
        );
    }

    #[test]
    fn unverified_success_still_reports_success() {
        let r = SimulationResult {
            outcome: SimOutcome::Success {
                output: Bytes::new(),
            },
            gas_used: 21000,
            transfers: Vec::new(),
            verified: false,
            base_fee_per_gas: 0,
        };
        assert!(!r.is_revert());
        assert!(!r.is_unavailable());
        assert!(!r.verified);
    }
}
