//! Transaction Builder app — the Apps-pane surface for composing contract
//! calls, queueing them into a batch, simulating, and handing the batch to
//! the shared sign-review overlay.
//!
//! Ephemeral UI state only. All I/O (contract-code fetch, batch simulation,
//! signing/broadcast) is bubbled to the dashboard coordinator via
//! [`Outcome`]s, which feeds results back through the `on_*` callbacks —
//! the same convention the Names and Privacy Pools apps follow.

use iced::Element;

use alloy::dyn_abi::DynSolValue;
use alloy::primitives::{Address, B256, Bytes, U256};

use crate::chain::{Chain, NetworkId};
use crate::portfolio::format_token_balance;
use crate::safe::tx::SafeTxInput;
use crate::txbuilder::abi::{self, AbiMethod, AbiSource, LoadedContract};
use crate::txbuilder::sim::{BatchOutcome, BatchSimResult};
use crate::txbuilder::templates::Template;
use crate::txbuilder::{MAX_BATCH_CALLS, QueuedCall, bundle, encode, flash_approval};
use crate::ui::kao_theme::KaoTheme;
use crate::wallet::SafeTrust;

/// Which composer mode is active. `Write` composes a state-changing call,
/// `Read` queries a `view`/`pure` method via `eth_call`, `Raw` sends custom
/// calldata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Write,
    Read,
    Raw,
}

/// A single decoded return value of a Read-tab query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRow {
    pub name: String,
    pub ty: String,
    pub value: String,
}

/// The result of a Read-tab `eth_call`, retained for display until the next
/// query. `raw` is the `0x…` return data (copyable); `rows` is its typed decode
/// against the method's declared outputs (empty when the outputs don't decode).
#[derive(Debug, Clone)]
pub enum ReadOutcome {
    Ok {
        rows: Vec<ReadRow>,
        raw: String,
        verified: bool,
    },
    Err(String),
}

/// What became of the last batch this pane dispatched.
///
/// The pane used to learn only that *something* finished: the overlay closed
/// and the queue emptied, which is exactly what a cancel looks like, and the
/// transaction hash was bound to `_hash` and dropped. A successful propose was
/// the worst of the three — indistinguishable from an accidental dismissal, so
/// the natural response was to propose the same batch a second time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settled {
    /// Mined with `status == 1`. The hash is kept so the user can look it up.
    Executed { hash: B256 },
    /// Filed on the Transaction Service at `nonce`, awaiting co-signers.
    Proposed { nonce: u64 },
    /// Mined with `status == 0` — every call rolled back and the gas was spent.
    /// The batch stays in the composer, because the user will want to fix it.
    Reverted { hash: B256 },
    /// Broadcast, and no receipt was read before the poll window closed (or
    /// there was no RPC to read one with).
    ///
    /// **Not a failure.** The transaction is in the mempool and may mine at any
    /// time, so this is the one outcome where rebuilding the batch is actively
    /// dangerous: the composer still holds it, and running it again would
    /// execute it twice if the first one lands. The strip says so and keeps the
    /// hash, which used to be dropped the moment the overlay was dismissed.
    Unconfirmed { hash: B256 },
}

/// A settled outcome together with the account and network it happened on.
///
/// The strip used to be a bare [`Settled`], and the identity/network resets
/// clear the queue but not the outcome — so switching to a different Safe left
/// a hash or a Safe nonce sitting over an account it had nothing to do with.
/// That was a mislabel while the only outcomes were `Executed` and `Proposed`;
/// with `Unconfirmed` it became advice ("this may still be pending, don't
/// rebuild it") displayed to someone with nothing pending.
///
/// Bound rather than cleared, deliberately. Clearing on switch would fix the
/// attribution by destroying the hash — and for `Unconfirmed` that hash is the
/// only way to find out whether rebuilding the batch would run it twice, which
/// is the entire reason the variant exists. Binding hides the strip off-context
/// and brings it back intact on the way back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledFor {
    pub outcome: Settled,
    /// The account that was composing when this settled.
    pub identity: Address,
    /// The network it settled on.
    pub net: NetworkId,
}

impl Settled {
    /// The transaction hash, for the outcomes that have one. `Proposed` does
    /// not: nothing has been broadcast.
    pub fn hash(&self) -> Option<B256> {
        match self {
            Self::Executed { hash } | Self::Reverted { hash } | Self::Unconfirmed { hash } => {
                Some(*hash)
            }
            Self::Proposed { .. } => None,
        }
    }
}

/// What became of a broadcast batch, as read from its receipt.
///
/// Replaces a `Result<(), String>` whose error arm conflated two opposite
/// facts. "Reverted" is a *verdict*: the transaction mined, the nonce is spent,
/// and it can never execute. "No receipt yet" is the *absence* of a verdict:
/// the transaction is live and may still mine. Both used to re-arm the overlay's
/// Confirm button with the reason in an error banner, so the second one invited
/// the user to sign and broadcast the same batch a second time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchFate {
    /// Mined with `status == 1`.
    Mined,
    /// Mined with `status == 0`.
    Reverted,
    /// No receipt within the poll window, or no RPC to read one.
    Unknown { reason: String },
}

impl BatchFate {
    /// Whether the transaction's outcome is settled. `false` means it may still
    /// be pending — the case where re-broadcasting risks a double execution.
    pub fn is_decided(&self) -> bool {
        !matches!(self, Self::Unknown { .. })
    }
}

/// The JSON import/export overlay, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Modal {
    None,
    Save,
    Load,
}

/// A sample of the pane's coarse state, taken either side of an `update`.
///
/// See [`TxBuilderApp::trace_snapshot`] for why the state is sampled rather
/// than logged at each assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceState {
    mode: Mode,
    net: NetworkId,
    batch: usize,
    modal: Modal,
    loaded: bool,
    resolving: bool,
    read_busy: bool,
    sim_busy: bool,
    sim: bool,
    errored: bool,
    settled: bool,
}

impl TraceState {
    /// Emit one DEBUG line per field that moved, naming the message that moved
    /// it. Nothing is logged when the dispatch changed no coarse state — which
    /// is most of them, since typing into a field is a message per keystroke.
    fn diff(&self, cause: &str, to: &Self) {
        for (what, from, to) in self.changes(to) {
            crate::trace::state_caused("tx_builder", cause, what, from, to);
        }
    }

    /// The fields that moved, as `(what, from, to)`.
    ///
    /// Split out from [`Self::diff`] so it can be asserted on without standing
    /// up a tracing subscriber: the failure mode this guards against is a new
    /// field being added to the pane and never reaching the snapshot, which
    /// silently shrinks what the log can show and looks exactly like a working
    /// trace.
    fn changes(&self, to: &Self) -> Vec<(&'static str, String, String)> {
        let mut out = Vec::new();
        if self == to {
            return out;
        }
        let mut log = |what, from: String, to: String| out.push((what, from, to));
        if self.mode != to.mode {
            log(
                "mode",
                mode_name(self.mode).into(),
                mode_name(to.mode).into(),
            );
        }
        if self.net != to.net {
            log("net", self.net.display_name(), to.net.display_name());
        }
        if self.batch != to.batch {
            log("batch", self.batch.to_string(), to.batch.to_string());
        }
        if self.modal != to.modal {
            log(
                "modal",
                modal_name(&self.modal).into(),
                modal_name(&to.modal).into(),
            );
        }
        if self.loaded != to.loaded {
            log("contract", self.loaded.to_string(), to.loaded.to_string());
        }
        if self.resolving != to.resolving {
            log(
                "resolving",
                self.resolving.to_string(),
                to.resolving.to_string(),
            );
        }
        if self.read_busy != to.read_busy {
            log(
                "read_busy",
                self.read_busy.to_string(),
                to.read_busy.to_string(),
            );
        }
        if self.sim_busy != to.sim_busy {
            log(
                "sim_busy",
                self.sim_busy.to_string(),
                to.sim_busy.to_string(),
            );
        }
        if self.sim != to.sim {
            log("sim_verdict", self.sim.to_string(), to.sim.to_string());
        }
        if self.errored != to.errored {
            log("error", self.errored.to_string(), to.errored.to_string());
        }
        if self.settled != to.settled {
            log("settled", self.settled.to_string(), to.settled.to_string());
        }
        out
    }

    /// Just the names of the fields that moved.
    #[cfg(test)]
    fn changed_fields(&self, to: &Self) -> Vec<&'static str> {
        self.changes(to)
            .into_iter()
            .map(|(what, ..)| what)
            .collect()
    }
}

fn mode_name(m: Mode) -> &'static str {
    match m {
        Mode::Write => "Write",
        Mode::Read => "Read",
        Mode::Raw => "Raw",
    }
}

fn modal_name(m: &Modal) -> &'static str {
    match m {
        Modal::None => "None",
        Modal::Save => "Save",
        Modal::Load => "Load",
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    Close,
    SetMode(Mode),
    // network switcher
    ToggleNetworkMenu,
    SetNetwork(NetworkId),
    // contract-call composer
    AddrChanged(String),
    RetryResolve,
    ShowAbiPaste,
    AbiPasteChanged(String),
    LoadPastedAbi,
    ToggleMethodMenu,
    PickMethod(usize),
    ArgChanged(usize, String),
    BoolArg(usize, bool),
    ValueChanged(String),
    // read composer
    ToggleReadMethodMenu,
    PickReadMethod(usize),
    ReadArgChanged(usize, String),
    ReadBoolArg(usize, bool),
    Query,
    CopyReadRaw,
    CopyReadValue(usize),
    // raw composer
    RawToChanged(String),
    RawValueChanged(String),
    RawDataChanged(String),
    // add / batch ops
    AddToBatch,
    SendSingle,
    RemoveCall(u64),
    MoveUp(u64),
    MoveDown(u64),
    ToggleExpand(u64),
    ClearBatch,
    LoadSample,
    ToggleAutoRevoke(bool),
    // templates
    ToggleTemplateMenu,
    LoadTemplate(usize),
    SaveTemplate,
    DeleteTemplate(usize),
    StartRename(usize),
    RenameChanged(String),
    CommitRename,
    CancelRename,
    // simulate / review
    Simulate,
    Review,
    // JSON modal
    OpenSave,
    OpenLoad,
    CloseModal,
    JsonChanged(String),
    CopyJson,
    ImportJson,
    // settled batch
    CopySettledHash,
    DismissSettled,
    // misc
    /// Esc was pressed while the Builder is open.
    Escape,
    DismissError,
}

impl Message {
    fn name(&self) -> &'static str {
        match self {
            Message::Close => "Close",
            Message::SetMode(_) => "SetMode",
            Message::ToggleNetworkMenu => "ToggleNetworkMenu",
            Message::SetNetwork(_) => "SetNetwork",
            Message::AddrChanged(_) => "AddrChanged",
            Message::RetryResolve => "RetryResolve",
            Message::ShowAbiPaste => "ShowAbiPaste",
            Message::AbiPasteChanged(_) => "AbiPasteChanged",
            Message::LoadPastedAbi => "LoadPastedAbi",
            Message::ToggleMethodMenu => "ToggleMethodMenu",
            Message::PickMethod(_) => "PickMethod",
            Message::ArgChanged(..) => "ArgChanged",
            Message::BoolArg(..) => "BoolArg",
            Message::ValueChanged(_) => "ValueChanged",
            Message::ToggleReadMethodMenu => "ToggleReadMethodMenu",
            Message::PickReadMethod(_) => "PickReadMethod",
            Message::ReadArgChanged(..) => "ReadArgChanged",
            Message::ReadBoolArg(..) => "ReadBoolArg",
            Message::Query => "Query",
            Message::CopyReadRaw => "CopyReadRaw",
            Message::CopyReadValue(_) => "CopyReadValue",
            Message::RawToChanged(_) => "RawToChanged",
            Message::RawValueChanged(_) => "RawValueChanged",
            Message::RawDataChanged(_) => "RawDataChanged",
            Message::AddToBatch => "AddToBatch",
            Message::SendSingle => "SendSingle",
            Message::RemoveCall(_) => "RemoveCall",
            Message::MoveUp(_) => "MoveUp",
            Message::MoveDown(_) => "MoveDown",
            Message::ToggleExpand(_) => "ToggleExpand",
            Message::ClearBatch => "ClearBatch",
            Message::LoadSample => "LoadSample",
            Message::ToggleAutoRevoke(_) => "ToggleAutoRevoke",
            Message::ToggleTemplateMenu => "ToggleTemplateMenu",
            Message::LoadTemplate(_) => "LoadTemplate",
            Message::SaveTemplate => "SaveTemplate",
            Message::DeleteTemplate(_) => "DeleteTemplate",
            Message::StartRename(_) => "StartRename",
            Message::RenameChanged(_) => "RenameChanged",
            Message::CommitRename => "CommitRename",
            Message::CancelRename => "CancelRename",
            Message::Simulate => "Simulate",
            Message::Review => "Review",
            Message::OpenSave => "OpenSave",
            Message::OpenLoad => "OpenLoad",
            Message::CloseModal => "CloseModal",
            Message::JsonChanged(_) => "JsonChanged",
            Message::CopyJson => "CopyJson",
            Message::ImportJson => "ImportJson",
            Message::CopySettledHash => "CopySettledHash",
            Message::DismissSettled => "DismissSettled",
            Message::Escape => "Escape",
            Message::DismissError => "DismissError",
        }
    }
}

/// The coordinator's answer to [`Outcome::ResolveContract`]: the runtime code
/// the composer should introspect, plus what the proxy walk found on the way
/// there.
#[derive(Debug, Clone)]
pub struct ResolvedCode {
    /// Runtime bytecode of `implementation`. Empty ⇒ nothing deployed there.
    pub code: Bytes,
    /// The contract this code belongs to: the requested address itself, or the
    /// implementation behind its proxy slots. Calls still go to the requested
    /// address.
    pub implementation: Address,
    /// False when a proxy-slot read came back over unverified RPC. The walker
    /// stops rather than following such a pointer, so the code above is the
    /// proxy's own — usually near-empty of selectors.
    pub all_verified: bool,
    /// True when the address the user typed has no contract code at all.
    ///
    /// Distinct from "no recoverable ABI": that one says the code is there and
    /// wouldn't yield selectors, this one says there is no code. Only set when
    /// the requested address *is* the implementation — behind a proxy the
    /// address necessarily has code (the proxy's own).
    pub nothing_deployed: bool,
    /// False when the *code* read itself fell through to unverified RPC.
    ///
    /// A different fact from [`Self::all_verified`], with a different remedy: a
    /// refused proxy pointer means the ABI on screen is the stub's (remedy: the
    /// implementation's ABI), whereas unverified code means an untrusted
    /// endpoint authored the entire method list (remedy: wait for the light
    /// client, or don't trust the names). Conflating them would offer the wrong
    /// advice for both.
    pub code_verified: bool,
    /// True when the address is a beacon proxy. Recognised, not followed —
    /// see [`crate::decode::proxy::is_beacon_proxy`].
    pub beacon: bool,
}

/// What the batch simulation said about the calls being sent for review.
///
/// The composer runs a real revm preflight, but running it was never a
/// precondition for signing and the overlay never saw the result — so a batch
/// that reverted at step 3 opened with a plain, enabled confirm button. This
/// carries the verdict across the boundary. It is *advisory*: a reverting
/// preflight makes the button say so rather than blocking the signature, since
/// the simulation is a sequential approximation and can diverge from chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Preflight {
    /// Simulated on a verified chain; every call succeeded. `stale` is set when
    /// the chain has moved far enough past the simulated block that the verdict
    /// is no longer a statement about the state the batch will meet; `verified`
    /// is false when some read behind it fell through to raw RPC.
    Passed { stale: bool, verified: bool },
    /// Simulated and it fails. `at` names the failing call the way the user can
    /// point at it — the simulator indexes the *effective* calls (the queue
    /// wrapped in flash-approval resets), which is not the numbering on the
    /// queue cards.
    Fails { at: String, reason: String },
    /// Every sub-call succeeded, but the batch's metered gas is at or over the
    /// gas limit of the block it was simulated against — a transaction no block
    /// can include. Not a revert and not a fee problem: it has to be split.
    ///
    /// Its own variant rather than a flag on [`Self::Passed`] because it is not
    /// a pass. The simulator runs each sub-call under its own limit with the
    /// block limit disabled, which is what makes the preflight useful on a
    /// gas-heavy call and is also why this used to render as a clean green
    /// strip.
    TooMuchGas { gas_used: u64, block_gas_limit: u64 },
    /// The simulator itself failed, and this is why. Distinct from
    /// [`Self::Missing`]: "go back and run the preflight" is useless advice for
    /// a batch whose preflight cannot succeed, and it was the advice given for
    /// every upstream error because the reason was discarded unread.
    Errored { reason: String },
    /// Simulation is available on this network but hasn't produced a verdict
    /// for the batch as it currently stands — never run.
    Missing,
    /// The network has no simulation at all (a custom, unverified chain). Not
    /// a warning in its own right: the review's own copy already says the
    /// chain can't be light-client-verified.
    Unsupported,
}

/// How long a preflight verdict stands before it stops being a claim about the
/// state the batch will actually meet.
///
/// Measured on the wall clock rather than in blocks: the app would have to
/// re-read the head to count blocks, and the property being bounded — "someone
/// else could have moved a balance or an allowance since this ran" — is a
/// function of elapsed time on every chain Kao supports. Three minutes is ~15
/// Mainnet blocks and considerably more on Base and Optimism, which is the
/// direction a staleness bound should err in.
pub const PREFLIGHT_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(180);

/// `0x` + 40 hex digits — the length at which an address field stops being
/// half-typed and starts being an answer worth contradicting.
const ADDRESS_TEXT_LEN: usize = 42;

impl Preflight {
    /// Whether the confirm button should read as a deliberate override rather
    /// than a routine confirmation.
    pub fn softens_confirm(&self) -> bool {
        match self {
            Self::Fails { .. } | Self::Errored { .. } | Self::Missing | Self::TooMuchGas { .. } => {
                true
            }
            // A verdict taken a hundred blocks ago, or one resting on reads
            // that fell through to unverified RPC, is not the clean pass the
            // routine label promises.
            Self::Passed { stale, verified } => *stale || !*verified,
            Self::Unsupported => false,
        }
    }

    /// A line for the review note when the preflight is something the user
    /// should weigh before signing. `None` when there's nothing to add.
    pub fn warning(&self) -> Option<String> {
        match self {
            Self::Unsupported => None,
            Self::Passed {
                stale: false,
                verified: true,
            } => None,
            Self::Passed { stale, verified } => {
                let mut why: Vec<&str> = Vec::new();
                if *stale {
                    why.push("the chain has moved on since it ran");
                }
                if !*verified {
                    why.push("some of the state it read couldn't be light-client-verified");
                }
                Some(format!(
                    "⚠ The preflight passed, but {} — re-run it before signing if this batch \
                     depends on balances or allowances that others can move.",
                    why.join(" and "),
                ))
            }
            Self::TooMuchGas {
                gas_used,
                block_gas_limit,
            } => Some(format!(
                "⚠ This batch meters {gas_used} gas against a block gas limit of \
                 {block_gas_limit}. No block can include a transaction this large, so it will \
                 never be mined however much you pay — and the real figure is higher still, \
                 since the preflight doesn't run the wrapper. Split it into smaller batches."
            )),
            Self::Fails { at, reason } => Some(format!(
                "⚠ Preflight FAILED at {at}: {reason}. The batch is atomic, so on-chain this \
                 reverts as a whole and costs gas for nothing."
            )),
            Self::Errored { reason } => Some(format!(
                "⚠ The preflight couldn't run: {reason}. That is a gap in what this wallet can \
                 predict, not a verdict on the batch — nothing here says whether it succeeds."
            )),
            Self::Missing => Some(
                "⚠ This batch has not been simulated. Go back and run the preflight to see \
                 whether it succeeds before committing a signature to it."
                    .to_string(),
            ),
        }
    }
}

/// Requests bubbled to the coordinator.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// Step back to the Apps launcher.
    Close,
    /// Fetch the runtime bytecode of `address` on `chain` so the composer can
    /// recover its ABI. Only bubbled for built-in chains; custom networks fall
    /// straight to the paste-ABI prompt. Answered via
    /// [`TxBuilderApp::on_contract_resolved`].
    ResolveContract {
        seq: u64,
        chain: Chain,
        address: Address,
    },
    /// Run a Read-tab `eth_call` on `net` and hand the raw return data back via
    /// [`TxBuilderApp::on_read`].
    Read {
        seq: u64,
        net: NetworkId,
        to: Address,
        data: Bytes,
    },
    /// Ask whether anything is deployed at `address`. Answered via
    /// [`TxBuilderApp::on_code_probed`].
    ///
    /// Bubbled by the two composers that can't otherwise find out: the Raw-hex
    /// tab, which never resolves anything, and the contract composer on a
    /// custom network, where there is no registry and no bytecode tier. Both
    /// could aim a call at an address holding no contract — the call then
    /// succeeds having done nothing, and any ETH attached to it is spent.
    ProbeCode {
        seq: u64,
        net: NetworkId,
        address: Address,
    },
    /// Simulate the batch on `chain` (built-in only). Answered via
    /// [`TxBuilderApp::on_sim`].
    Simulate {
        seq: u64,
        chain: Chain,
        calls: Vec<QueuedCall>,
    },
    /// Open the sign-review overlay for the batch (built-in batch / Safe) or a
    /// single call (custom-network send). The coordinator reads the app's
    /// selected network to build the request.
    Review {
        calls: Vec<QueuedCall>,
        /// What the preflight found, carried across so the overlay's confirm
        /// button can't read as a routine "sign this" over a batch the user
        /// just watched revert.
        preflight: Preflight,
        /// The simulation `preflight` was derived from, carried so the review
        /// can state what the batch moves and what it costs.
        ///
        /// Deliberately the *same* value the verdict came from, read in the
        /// same expression: derived twice, a re-read could describe a different
        /// batch than the verdict beside it, which is exactly the class of
        /// desync the rest of this flow is built to prevent. `None` when no
        /// simulation stands behind the review (never run, or an unsimulable
        /// custom network) — the economics then cover only what the calls
        /// themselves declare.
        sim: Option<Box<BatchSimResult>>,
        /// How the fee estimate is wrong, in the user's terms — derived here
        /// because the batch's shape (Safe wrapper, 7702 batch, single call) is
        /// the pane's knowledge, not the overlay's.
        fee_caveats: Vec<String>,
    },
    /// Persist the user's template list to redb.
    ///
    /// The in-memory list is *already* mutated by the time this is bubbled, so
    /// `rollback` carries what it looked like before. This was the one outcome
    /// with no failure path at all — a read-only data dir or a held redb lock
    /// made every save, rename and delete a silent no-op that only surfaced
    /// next session, and a failed *delete* was worse than a no-op: the template
    /// came back.
    PersistTemplates {
        list: Vec<Template>,
        rollback: Vec<Template>,
    },
    /// Copy text (exported JSON) to the clipboard, armed for the usual 10s
    /// auto-clear.
    CopyText(String),
    /// Copy public read-query output (a decoded value / raw return data) to the
    /// clipboard WITHOUT the auto-clear — it's not sensitive and the user
    /// wants it to survive until they paste it.
    CopyPlain(String),
}

impl Outcome {
    fn name(&self) -> &'static str {
        match self {
            Outcome::Close => "Close",
            Outcome::ResolveContract { .. } => "ResolveContract",
            Outcome::Read { .. } => "Read",
            Outcome::ProbeCode { .. } => "ProbeCode",
            Outcome::Simulate { .. } => "Simulate",
            Outcome::Review { .. } => "Review",
            Outcome::PersistTemplates { .. } => "PersistTemplates",
            Outcome::CopyText(_) => "CopyText",
            Outcome::CopyPlain(_) => "CopyPlain",
        }
    }
}

/// External context the coordinator refreshes before each message.
#[derive(Debug, Clone, Default)]
struct Ctx {
    /// The address the batch will execute **as**: the active Safe, or the
    /// plain EOA. `None` before the first `set_context`.
    ///
    /// Tracked because the queue is only meaningful for one sender. The reset
    /// used to key on the network alone, so a Mainnet EOA -> Mainnet Safe flip
    /// (or Safe A -> Safe B, which never changes chain) left the calls standing
    /// and simply re-shaped them with a different `from` — an `approve` +
    /// `supply` composed against the EOA's balances would run, and spend, from
    /// the Safe.
    identity: Option<Address>,
    /// Whether the active identity is a Safe (atomic batching via MultiSend).
    is_safe: bool,
    /// The active Safe's contract version. Decides the EIP-712 domain shape
    /// and which `MultiSendCallOnly` deployment the batch routes through, so
    /// a version outside the signable range is a standing refusal the composer
    /// states up front — see [`TxBuilderApp::safe_version_block`].
    safe_version: Option<String>,
    /// For a plain EOA: whether the active signer can authorize an EIP-7702
    /// delegation (Local / Ledger) and therefore batch N calls atomically.
    /// Trezor / view-only cannot, and stay capped at a single call.
    eoa_can_batch: bool,
    /// Whether the active identity can produce a signature at all.
    ///
    /// False for a watch-only account. The Builder's EOA arm never consulted
    /// `build_eoa_context`, so such an account got the whole clear-sign
    /// ceremony — overlay, decode, delegation card, three RPC round-trips —
    /// before the signer itself finally refused. Safe mode leaves this true:
    /// there the question is which *owner keys* are linked, which the review's
    /// own copy already answers.
    can_sign: bool,
    /// Enabled custom networks `(chain_id, name)` offered by the switcher.
    custom_networks: Vec<(u64, String)>,
}

#[derive(Debug)]
pub struct TxBuilderApp {
    /// The address the composer is acting as — the active Safe when one is
    /// selected, else the plain EOA. Refreshed by [`Self::set_context`]; it
    /// used to be written once at construction and never again, so the
    /// identity chip rendered "Safe multisig" over the *EOA's* address, which
    /// is exactly the affordance that would have shown the switch above.
    owner: Address,
    ctx: Ctx,

    /// The active network. A plain EOA drives this via the switcher; a Safe
    /// keeps it pinned to `ctx.chain`. Custom networks collapse the UI to the
    /// single-transaction composer (no batching).
    net: NetworkId,
    net_menu_open: bool,

    mode: Mode,

    // ── contract-call composer ──
    addr_input: String,
    loaded: Option<LoadedContract>,
    resolving: bool,
    /// Set when a resolve found no ABI — prompts the paste-ABI fallback.
    not_found: bool,
    /// Set when the last resolve *failed* rather than came back empty.
    ///
    /// Kept apart from `not_found` because the two want opposite responses: no
    /// ABI is a fact about the contract and the answer is to paste one; a
    /// light-client hiccup is a fact about the connection and the answer is to
    /// try again. Collapsing them steered users into hand-pasting an ABI (or
    /// dropping to raw hex) for a well-known verified contract, and re-entering
    /// the same address did nothing at all — the dedup guard treated the failed
    /// state as settled.
    resolve_error: Option<String>,
    /// Set when what is *in the box* can't be an address — a bad checksum, or
    /// hex that isn't 20 bytes. Distinct from `resolve_error` again because
    /// there is nothing to retry: the answer is to fix the text. Held back
    /// until the input reaches full length, since every prefix of a valid
    /// address is an invalid address and nobody wants to be corrected mid-word.
    addr_error: Option<String>,
    /// Set when the last resolve hit a proxy slot it could only read over
    /// unverified RPC. The pointer wasn't followed, so the ABI on screen is the
    /// proxy stub's — worth saying out loud rather than leaving the user to
    /// wonder why a well-known contract came back nearly empty.
    proxy_unverified: bool,
    /// No contract code at the composed address. Survives a pasted ABI: pasting
    /// an ABI answers "what does it expose", not "is anything there".
    pub(crate) nothing_deployed: bool,
    /// Same fact for the Raw-hex tab's `to` field, which resolves nothing and
    /// so had no way to learn it.
    pub(crate) raw_nothing_deployed: bool,
    /// Generation guard for [`Outcome::ProbeCode`]: a reply for an address the
    /// user has since retyped must not land on the new one.
    probe_seq: u64,
    /// Set when the address is a beacon proxy — a shape the walker recognises
    /// but does not follow (resolving it needs an `eth_call` on the beacon, not
    /// a storage read). Held apart from `proxy_unverified` because it is a
    /// limitation of this wallet rather than of the connection, and saying
    /// which one it is beats an empty method list with no explanation.
    proxy_beacon: bool,
    paste_open: bool,
    abi_paste: String,
    /// The address currently being resolved / loaded (dedup guard).
    resolve_target: Option<Address>,
    resolve_seq: u64,
    method_idx: usize,
    method_menu_open: bool,
    args: Vec<String>,
    value_input: String,

    // ── read composer ──
    read_idx: usize,
    read_menu_open: bool,
    read_args: Vec<String>,
    read_seq: u64,
    read_busy: bool,
    read_result: Option<ReadOutcome>,

    // ── raw composer ──
    raw_to: String,
    raw_value: String,
    raw_data: String,

    // ── batch ──
    batch: Vec<QueuedCall>,
    next_id: u64,
    expanded: Option<u64>,
    /// Flash approval: when on, `approve(spender, 0)` revokes are appended to
    /// the batch at simulate / review time so no allowance survives the tx.
    auto_revoke: bool,

    // ── simulation strip ──
    sim: Option<BatchSimResult>,
    /// When the held verdict landed, for the staleness check. `None` for a
    /// result planted directly by a test.
    sim_at: Option<std::time::Instant>,
    sim_busy: bool,
    /// Retires an in-flight simulation, exactly as `resolve_seq` / `read_seq`
    /// do for their queries. Without it `on_sim` adopted whatever landed:
    /// edit the queue mid-simulation and the previous batch's verdict became
    /// this batch's `Preflight::Passed`, which is what the review's confirm
    /// button reads.
    sim_seq: u64,

    // ── templates ──
    templates: Vec<Template>,
    template_menu_open: bool,
    /// Index of the template currently being renamed inline, plus the edit
    /// buffer; `None` when no rename is in flight.
    rename_idx: Option<usize>,
    rename_buf: String,

    // ── JSON modal ──
    modal: Modal,
    json_text: String,
    json_error: Option<String>,

    /// The last batch this pane got a definitive answer about. Persists until
    /// dismissed — a receipt is the only thing that distinguishes a batch that
    /// worked from one that reverted, and neither used to leave a trace.
    settled: Option<SettledFor>,

    error: Option<String>,
}

impl TxBuilderApp {
    pub fn new(owner: Address) -> Self {
        Self {
            owner,
            ctx: Ctx::default(),
            net: NetworkId::default(),
            net_menu_open: false,
            mode: Mode::Write,
            addr_input: String::new(),
            loaded: None,
            resolving: false,
            not_found: false,
            resolve_error: None,
            addr_error: None,
            proxy_unverified: false,
            nothing_deployed: false,
            raw_nothing_deployed: false,
            probe_seq: 0,
            proxy_beacon: false,
            paste_open: false,
            abi_paste: String::new(),
            resolve_target: None,
            resolve_seq: 0,
            method_idx: 0,
            method_menu_open: false,
            args: Vec::new(),
            value_input: "0".into(),
            read_idx: 0,
            read_menu_open: false,
            read_args: Vec::new(),
            read_seq: 0,
            read_busy: false,
            read_result: None,
            raw_to: String::new(),
            raw_value: "0".into(),
            raw_data: String::new(),
            batch: Vec::new(),
            next_id: 1,
            expanded: None,
            auto_revoke: false,
            sim: None,
            sim_at: None,
            sim_busy: false,
            sim_seq: 0,
            templates: Vec::new(),
            template_menu_open: false,
            rename_idx: None,
            rename_buf: String::new(),
            modal: Modal::None,
            json_text: String::new(),
            json_error: None,
            settled: None,
            error: None,
        }
    }

    /// Adopt the user's saved templates (loaded from redb by the coordinator).
    pub fn set_templates(&mut self, templates: Vec<Template>) {
        self.templates = templates;
    }

    /// The active network the coordinator should resolve / simulate / broadcast
    /// against.
    pub fn selected_net(&self) -> NetworkId {
        self.net
    }

    /// Coordinator refreshes chain / Safe context before dispatching a
    /// message, so message-time logic (known-contract lookup, batch cap)
    /// sees the live identity.
    ///
    /// `identity` is the address the batch will execute as — the active Safe,
    /// or the plain EOA. A change to it drops the queue for the same reason a
    /// network change does: the calls were composed for one sender's balances,
    /// allowances and permissions, and nothing in a [`QueuedCall`] records
    /// which.
    #[allow(clippy::too_many_arguments)]
    pub fn set_context(
        &mut self,
        identity: Address,
        chain: Chain,
        is_safe: bool,
        safe_version: Option<String>,
        eoa_can_batch: bool,
        can_sign: bool,
        custom_networks: Vec<(u64, String)>,
    ) {
        self.traced("set_context", move |s| {
            let prev_identity = s.ctx.identity;
            s.ctx = Ctx {
                identity: Some(identity),
                is_safe,
                safe_version,
                eoa_can_batch,
                can_sign,
                custom_networks,
            };
            s.owner = identity;
            // Identity first: a Safe->EOA flip usually moves the network too,
            // and the identity notice is the one that explains the drop.
            let mut explained = false;
            if let Some(prev) = prev_identity
                && prev != identity
            {
                explained = s.on_identity_reset(prev, identity);
            }
            // A Safe can only transact on its own chain — pin the selector
            // there.
            //
            // Selecting a Safe usually moves both axes at once. The identity
            // reset above has already dropped the queue and explained why, so
            // re-running the network reset here would find nothing to drop and
            // clear that explanation on its way past — the drop would go
            // unexplained in the one case where the most has changed. When the
            // identity moved, the network re-pin does its housekeeping
            // silently instead.
            if is_safe {
                let pinned = NetworkId::Builtin(chain);
                if s.net != pinned {
                    let from = s.net;
                    s.net = pinned;
                    s.repin_network(from, explained);
                }
            } else if let NetworkId::Custom(id) = s.net {
                // A plain EOA keeps its selection across context refreshes,
                // except when the selected custom network was removed
                // underneath it.
                if !s.ctx.custom_networks.iter().any(|(cid, _)| *cid == id) {
                    let from = s.net;
                    s.net = NetworkId::Builtin(Chain::Mainnet);
                    s.repin_network(from, explained);
                }
            }
        })
    }

    /// The network moved underneath the composer. `already_explained` is set
    /// when an identity reset in the same refresh has already cleared the queue
    /// and put its own (more specific) notice on screen.
    fn repin_network(&mut self, from: NetworkId, already_explained: bool) {
        if already_explained {
            self.net_menu_open = false;
            self.reset_composer();
            self.invalidate_sim();
        } else {
            self.on_network_reset(from);
        }
    }

    // ── coordinator callbacks ─────────────────────────────────────────

    /// The coordinator fetched the contract's runtime code (or failed) — the
    /// implementation's code when the address turned out to be a proxy. Empty
    /// code ⇒ nothing deployed there.
    pub fn on_contract_resolved(&mut self, seq: u64, result: Result<ResolvedCode, String>) {
        self.traced("on_contract_resolved", move |s| {
            if seq != s.resolve_seq {
                return; // stale — a newer address was entered
            }
            s.resolving = false;
            let Some(addr) = s.resolve_target else {
                return;
            };
            match result {
                Ok(r) => {
                    s.proxy_unverified = !r.all_verified;
                    s.proxy_beacon = r.beacon;
                    // Set before `set_loaded`, which clears it — a curated hit
                    // being augmented must keep whatever the chain just said
                    // about whether anything is deployed there.
                    let nothing_deployed = r.nothing_deployed;
                    match abi::from_bytecode_behind_proxy(
                        &r.code,
                        addr,
                        r.implementation,
                        r.code_verified,
                    ) {
                        // A curated entry is already on screen: fold the
                        // recovered selectors into it rather than replacing it,
                        // so the hand-written names win where they overlap and
                        // everything the contract actually exposes is reachable.
                        Some(recovered) => match s.loaded.take() {
                            Some(curated) if curated.source != AbiSource::Bytecode => {
                                s.set_loaded(abi::merge_recovered(curated, recovered));
                            }
                            _ => s.set_loaded(recovered),
                        },
                        // Nothing recoverable. A curated entry already loaded
                        // stands on its own — the augmenting fetch failing to
                        // add anything is not a reason to drop it.
                        None => {
                            if s.loaded.is_none() {
                                s.not_found = true;
                            }
                        }
                    }
                    s.nothing_deployed = nothing_deployed;
                }
                // A failed *fetch* says nothing about whether this contract has
                // a recoverable ABI, so it must not be reported as "no verified
                // ABI".
                Err(e) => s.resolve_error = Some(e),
            }
        })
    }

    /// Whether anything is deployed at the address a composer is pointed at.
    ///
    /// Applied to whichever field still holds `address`, so a reply that
    /// arrives after the user has moved on lands nowhere. A failed probe is
    /// silent: not being able to ask is not evidence of an empty account, and
    /// this warning must never fire on an RPC hiccup.
    pub fn on_code_probed(&mut self, seq: u64, address: Address, result: Result<bool, String>) {
        self.traced("on_code_probed", move |s| {
            if seq != s.probe_seq {
                return;
            }
            let Ok(has_code) = result else { return };
            if s.raw_to.trim().parse::<Address>() == Ok(address) {
                s.raw_nothing_deployed = !has_code;
            }
            if s.resolve_target == Some(address) {
                s.nothing_deployed = !has_code;
            }
        })
    }

    /// Bubble a code probe for `address` if it is worth asking about.
    fn probe_code(&mut self, address: Address) -> Option<Outcome> {
        self.probe_seq += 1;
        Some(Outcome::ProbeCode {
            seq: self.probe_seq,
            net: self.net,
            address,
        })
    }

    /// Batch simulation result (or failure → treated as unavailable). `seq`
    /// guards against a stale run: the batch, the network, or the acting
    /// account may all have changed since it was dispatched, and this verdict
    /// is what the review's confirm button is derived from.
    pub fn on_sim(&mut self, seq: u64, result: Result<BatchSimResult, String>) {
        self.traced("on_sim", move |s| {
            if seq != s.sim_seq {
                return; // stale — a newer batch superseded this run
            }
            s.sim_busy = false;
            // The failure reason used to be discarded here (`unwrap_or_else(|_|
            // …unavailable())`), which is how a Helios outage, an unservicable
            // `BLOCKHASH` read and a batch that can never simulate all came out
            // as the same "Simulation unavailable" — followed by advice to go
            // and run the preflight again.
            s.sim = Some(match result {
                Ok(r) => r,
                Err(e) => BatchSimResult::errored(e),
            });
            s.sim_at = Some(std::time::Instant::now());
        })
    }

    /// A Read-tab `eth_call` returned. `seq` guards against a stale query
    /// (the user changed the method / params before this landed). The raw
    /// return bytes are decoded here against the queried method's outputs.
    pub fn on_read(&mut self, seq: u64, result: Result<(Bytes, bool), String>) {
        self.traced("on_read", move |s| {
            if seq != s.read_seq {
                return; // stale — a newer query superseded this one
            }
            s.read_busy = false;
            s.read_result = Some(match result {
                Ok((bytes, verified)) => {
                    let raw = if bytes.is_empty() {
                        "0x".to_string()
                    } else {
                        format!("0x{}", alloy::hex::encode(&bytes))
                    };
                    let rows = s
                        .selected_read_method()
                        .map(|m| decode_read_rows(m, &bytes))
                        .unwrap_or_default();
                    ReadOutcome::Ok {
                        rows,
                        raw,
                        verified,
                    }
                }
                Err(e) => ReadOutcome::Err(e),
            });
        })
    }

    /// The batch was **mined successfully** — `hash` had `status == 1`. Clears
    /// the queue and leaves the hash on screen.
    ///
    /// Only reached from a receipt, never from a broadcast. A bare hash says a
    /// node accepted the transaction and nothing else: a status-0 receipt, a
    /// guard rejection and a GS013 all broadcast exactly as cleanly as a win,
    /// and this used to clear the queue for all of them with no record and
    /// nothing to retry from.
    pub fn on_executed(&mut self, hash: B256) {
        self.traced("on_executed", move |s| {
            s.batch.clear();
            s.invalidate_sim();
            s.expanded = None;
            s.error = None;
            let stamped = s.stamp(Settled::Executed { hash });
            s.settled = Some(stamped);
        })
    }

    /// The batch was filed on the Transaction Service for co-signers. Not an
    /// execution: it clears the composer the same way, but says so differently,
    /// because "queued" and "done" are not the same claim.
    /// Bind an outcome to the account and network it happened on.
    fn stamp(&self, outcome: Settled) -> SettledFor {
        SettledFor {
            outcome,
            identity: self.owner,
            net: self.net,
        }
    }

    /// The settled outcome, when it belongs to the context currently on screen.
    ///
    /// `None` while composing as someone else or on another network — the
    /// record survives, so switching back restores it, but a hash from one
    /// account is never captioned with another's.
    pub fn visible_settled(&self) -> Option<&Settled> {
        let s = self.settled.as_ref()?;
        (s.identity == self.owner && s.net == self.net).then_some(&s.outcome)
    }

    /// The pane's settled-outcome strip as the user would see it, for the
    /// coordinator's tests.
    #[cfg(test)]
    pub fn settled_state(&self) -> Option<Settled> {
        self.visible_settled().cloned()
    }

    /// The batch was broadcast and did **not** succeed. Records the hash so it
    /// survives the overlay being dismissed, and — unlike [`Self::on_executed`]
    /// — leaves the queue alone: a reverted batch is one the user wants to fix,
    /// and an unconfirmed one is one they must not rebuild blind.
    pub fn on_broadcast_unsuccessful(&mut self, hash: B256, fate: &BatchFate) {
        let settled = match fate {
            BatchFate::Reverted => Settled::Reverted { hash },
            // `Mined` never reaches here — `on_executed` handles it — but a
            // wrong guess in this direction is the safe one: it claims less.
            _ => Settled::Unconfirmed { hash },
        };
        self.traced("on_broadcast_unsuccessful", move |s| {
            let stamped = s.stamp(settled);
            s.settled = Some(stamped);
        })
    }

    pub fn on_proposed(&mut self, nonce: u64) {
        self.traced("on_proposed", move |s| {
            s.batch.clear();
            s.invalidate_sim();
            s.expanded = None;
            s.error = None;
            let stamped = s.stamp(Settled::Proposed { nonce });
            s.settled = Some(stamped);
        })
    }

    pub fn update(&mut self, msg: Message) -> Option<Outcome> {
        crate::trace_msg!("tx_builder", &msg);
        // `Message::name` used to be computed here and thrown away — a 51-arm
        // match with no reader — and no coarse transition was logged at all, so
        // `RUST_LOG=kao::gui=debug` showed this pane as a black box while every
        // other screen reported its own state machine. The name is the *cause*
        // field: several distinct paths clear the queue, and `batch: 3 -> 0` on
        // its own doesn't say which one did.
        let cause = msg.name();
        let before = self.trace_snapshot();
        let outcome = self.update_inner(msg);
        before.diff(cause, &self.trace_snapshot());
        if let Some(o) = &outcome {
            crate::trace::outcome("tx_builder", o.name());
        }
        outcome
    }

    /// Run `f` and log whatever coarse state it moved, attributed to `cause`.
    ///
    /// The wrapper on [`Self::update`] only sees messages. Everything the
    /// coordinator delivers — a resolved contract, a read result, a preflight
    /// verdict, a receipt, a context refresh — arrives through a direct method
    /// call instead, and those are precisely the transitions worth watching in
    /// a log: they're the ones the user didn't cause and can't replay.
    fn traced<R>(&mut self, cause: &str, f: impl FnOnce(&mut Self) -> R) -> R {
        let before = self.trace_snapshot();
        let out = f(self);
        before.diff(cause, &self.trace_snapshot());
        out
    }

    /// The coarse state worth a DEBUG line, sampled either side of a dispatch.
    ///
    /// Sampled rather than instrumented at each assignment site for the reason
    /// [`crate::trace`] gives: the assignments are spread over fifty-odd match
    /// arms plus a dozen coordinator callbacks, and any of them can be missed.
    /// Deliberately excludes per-keystroke fields (`addr_input`, `args`,
    /// `json_text`) — those are message-level detail, already visible at TRACE.
    fn trace_snapshot(&self) -> TraceState {
        TraceState {
            mode: self.mode,
            net: self.net,
            batch: self.batch.len(),
            modal: self.modal.clone(),
            loaded: self.loaded.is_some(),
            resolving: self.resolving,
            read_busy: self.read_busy,
            sim_busy: self.sim_busy,
            sim: self.sim.is_some(),
            errored: self.error.is_some(),
            settled: self.settled.is_some(),
        }
    }

    fn update_inner(&mut self, msg: Message) -> Option<Outcome> {
        match msg {
            Message::Close => return Some(Outcome::Close),
            Message::SetMode(m) => {
                self.mode = m;
                self.error = None;
                self.method_menu_open = false;
                self.read_menu_open = false;
            }
            Message::ToggleNetworkMenu => {
                // A Safe pins the network — the switcher is inert.
                if !self.ctx.is_safe {
                    self.net_menu_open = !self.net_menu_open;
                    self.template_menu_open = false;
                }
            }
            Message::SetNetwork(net) => {
                self.net_menu_open = false;
                if self.net != net {
                    let from = self.net;
                    self.net = net;
                    self.on_network_reset(from);
                }
            }
            Message::AddrChanged(v) => return self.on_addr_changed(v),
            Message::RetryResolve => return self.retry_resolve(),
            Message::ShowAbiPaste => {
                self.paste_open = true;
            }
            Message::AbiPasteChanged(v) => self.abi_paste = v,
            Message::LoadPastedAbi => {
                if let Ok(addr) = encode::parse_address(&self.addr_input) {
                    match abi::parse_abi_json(&self.abi_paste, addr) {
                        Ok(loaded) => {
                            self.set_loaded(loaded);
                            self.paste_open = false;
                            self.abi_paste.clear();
                        }
                        Err(e) => self.error = Some(e.to_string()),
                    }
                } else {
                    self.error = Some("enter the contract address first".into());
                }
            }
            Message::ToggleMethodMenu => self.method_menu_open = !self.method_menu_open,
            Message::PickMethod(i) => {
                self.method_idx = i;
                self.method_menu_open = false;
                self.reset_args();
            }
            Message::ArgChanged(i, v) => {
                if let Some(slot) = self.args.get_mut(i) {
                    *slot = v;
                }
            }
            Message::BoolArg(i, b) => {
                if let Some(slot) = self.args.get_mut(i) {
                    *slot = b.to_string();
                }
            }
            Message::ValueChanged(v) => self.value_input = v,
            Message::ToggleReadMethodMenu => self.read_menu_open = !self.read_menu_open,
            Message::PickReadMethod(i) => {
                self.read_idx = i;
                self.read_menu_open = false;
                self.reset_read_args();
                self.invalidate_read();
            }
            Message::ReadArgChanged(i, v) => {
                if let Some(slot) = self.read_args.get_mut(i) {
                    *slot = v;
                }
                self.invalidate_read();
            }
            Message::ReadBoolArg(i, b) => {
                if let Some(slot) = self.read_args.get_mut(i) {
                    *slot = b.to_string();
                }
                self.invalidate_read();
            }
            Message::Query => return self.on_query(),
            Message::CopyReadRaw => {
                if let Some(ReadOutcome::Ok { raw, .. }) = &self.read_result {
                    return Some(Outcome::CopyPlain(raw.clone()));
                }
            }
            Message::CopyReadValue(i) => {
                if let Some(ReadOutcome::Ok { rows, .. }) = &self.read_result
                    && let Some(r) = rows.get(i)
                {
                    return Some(Outcome::CopyPlain(r.value.clone()));
                }
            }
            Message::RawToChanged(v) => {
                self.raw_to = v;
                // The Raw tab resolves nothing, so this is its only chance to
                // learn that the address holds no contract — the wrong-chain
                // paste, where the call succeeds having done nothing and takes
                // the attached ETH with it. Cleared first: the old answer
                // belongs to the old address.
                self.raw_nothing_deployed = false;
                self.probe_seq += 1;
                if let Ok(addr) = encode::parse_address(self.raw_to.trim()) {
                    return self.probe_code(addr);
                }
            }
            Message::RawValueChanged(v) => self.raw_value = v,
            Message::RawDataChanged(v) => self.raw_data = v,
            Message::AddToBatch => self.add_to_batch(),
            Message::SendSingle => return self.send_single(),
            Message::RemoveCall(id) => {
                self.batch.retain(|c| c.id != id);
                self.invalidate_sim();
            }
            Message::MoveUp(id) => self.move_call(id, -1),
            Message::MoveDown(id) => self.move_call(id, 1),
            Message::ToggleExpand(id) => {
                self.expanded = if self.expanded == Some(id) {
                    None
                } else {
                    Some(id)
                };
            }
            Message::ClearBatch => {
                self.batch.clear();
                self.invalidate_sim();
                self.expanded = None;
            }
            Message::LoadSample => {
                self.batch = sample_batch(&mut self.next_id, self.owner);
                self.invalidate_sim();
            }
            Message::ToggleAutoRevoke(v) => {
                self.auto_revoke = v;
                // The revoke set changes what gets simulated — drop any stale sim.
                self.invalidate_sim();
            }
            Message::Simulate => {
                // Simulation is a verified-path preflight — built-in chains only.
                if let (false, Some(chain)) = (self.batch.is_empty(), self.net.builtin()) {
                    let calls = match self.effective_calls_checked() {
                        Ok(c) => c,
                        Err(e) => {
                            self.error = Some(e);
                            return None;
                        }
                    };
                    // Retire any earlier run before claiming the new sequence,
                    // so a slower predecessor can't answer for this batch.
                    self.invalidate_sim();
                    self.sim_busy = true;
                    return Some(Outcome::Simulate {
                        seq: self.sim_seq,
                        chain,
                        calls,
                    });
                }
            }
            Message::Review => {
                if self.batch.is_empty() {
                    return None;
                }
                if let Some(why) = self.no_signer_reason() {
                    self.error = Some(why);
                    return None;
                }
                let calls = match self.effective_calls_checked() {
                    Ok(c) => c,
                    Err(e) => {
                        self.error = Some(e);
                        return None;
                    }
                };
                return Some(Outcome::Review {
                    calls,
                    preflight: self.preflight(),
                    // Same `self.sim` the verdict above was derived from.
                    sim: self.sim.clone().map(Box::new),
                    fee_caveats: self.fee_caveats(),
                });
            }
            Message::ToggleTemplateMenu => {
                self.template_menu_open = !self.template_menu_open;
                self.net_menu_open = false;
                self.cancel_rename();
            }
            Message::LoadTemplate(i) => {
                if let Some(t) = self.templates.get(i).cloned() {
                    self.load_template(&t);
                }
            }
            Message::SaveTemplate => {
                // Built-in chains only: the stored bundle stamps the chain and
                // the load path enforces it, and a custom network has no
                // `Chain` to stamp. Custom nets are composer-only anyway (no
                // batch, so nothing to save).
                if let (false, Some(chain)) = (self.batch.is_empty(), self.net.builtin()) {
                    self.cancel_rename();
                    let rollback = self.templates.clone();
                    let t = Template::from_batch(
                        "Untitled batch",
                        "(｡•̀ᴗ-)✧",
                        chain,
                        self.owner,
                        &self.batch,
                    );
                    self.templates.push(t);
                    self.template_menu_open = true;
                    return Some(self.persist(rollback));
                }
            }
            Message::DeleteTemplate(i) => {
                if i < self.templates.len() {
                    self.cancel_rename();
                    let rollback = self.templates.clone();
                    self.templates.remove(i);
                    return Some(self.persist(rollback));
                }
            }
            Message::StartRename(i) => {
                if let Some(t) = self.templates.get(i) {
                    self.rename_buf = t.name.clone();
                    self.rename_idx = Some(i);
                }
            }
            Message::RenameChanged(v) => self.rename_buf = v,
            Message::CommitRename => return self.commit_rename(),
            Message::CancelRename => self.cancel_rename(),
            Message::OpenSave => {
                // Built-in only, for the reason `SaveTemplate` is: a bundle
                // stamped with a chain it wasn't composed on imports cleanly
                // somewhere it shouldn't. A custom network has no `Chain` to
                // stamp, and stamping Mainnet by default would manufacture
                // exactly that. (Unreachable today — the export button lives in
                // the batch pane, which custom networks don't get.)
                let Some(chain) = self.net.builtin() else {
                    self.error = Some(format!(
                        "A batch composed on {} can't be exported — the bundle format identifies \
                         its network by chain id, and this one isn't a network Kao verifies.",
                        self.net.display_name(),
                    ));
                    return None;
                };
                self.json_text = bundle::export(
                    chain,
                    self.ctx.is_safe.then_some(self.owner),
                    self.owner,
                    &self.batch,
                );
                self.modal = Modal::Save;
            }
            Message::OpenLoad => {
                self.json_text.clear();
                self.json_error = None;
                self.modal = Modal::Load;
            }
            Message::CloseModal => self.close_modal(),
            // The app-level Esc handler steps back to the launcher; with a
            // modal open that is never what the user meant, and `root()`
            // short-circuits to `modal_view` whenever `modal != None`, so
            // re-entering the Builder landed straight back inside it. Esc
            // closes the modal and consumes the key.
            Message::Escape => {
                if self.modal != Modal::None {
                    self.close_modal();
                } else {
                    return Some(Outcome::Close);
                }
            }
            Message::JsonChanged(v) => {
                // The box is the paste target for an untrusted file, and a
                // single-line `text_input` re-lays-out its whole content on
                // every keystroke and every frame. `bundle::import` refuses an
                // oversized bundle too, but only once "Load batch" is pressed —
                // by which point the widget has already been handed it.
                if v.len() > bundle::MAX_BUNDLE_BYTES {
                    self.json_error = Some(format!(
                        "that paste is {} bytes, and this wallet reads batches up to {} — it \
                         hasn't been put in the box",
                        v.len(),
                        bundle::MAX_BUNDLE_BYTES,
                    ));
                    return None;
                }
                self.json_text = v;
                self.json_error = None;
            }
            Message::CopyJson => return Some(Outcome::CopyText(self.json_text.clone())),
            Message::ImportJson => {
                match bundle::import(&self.json_text, self.next_id, self.net.builtin()) {
                    Ok(calls) => {
                        // Read before adopting: `json_text` is cleared with the
                        // modal, and the meta is the only record of who the
                        // batch was written for.
                        let composed_as = serde_json::from_str::<bundle::Bundle>(&self.json_text)
                            .ok()
                            .and_then(|b| b.meta.composed_as());
                        match self.adopt_batch(calls) {
                            Ok(()) => {
                                self.modal = Modal::None;
                                self.note_identity_drift(composed_as, "This bundle");
                            }
                            // Stays in the modal with the reason: the JSON is
                            // still in the box, so the user can take it
                            // somewhere that can run it rather than losing it
                            // to a closed overlay.
                            Err(e) => self.json_error = Some(e),
                        }
                    }
                    Err(e) => self.json_error = Some(e.to_string()),
                }
            }
            Message::CopySettledHash => {
                // Every outcome that has a hash offers it. The unconfirmed one
                // needs it most: looking that hash up is the only way to find
                // out whether rebuilding the batch would run it twice.
                if let Some(hash) = self.visible_settled().and_then(Settled::hash) {
                    return Some(Outcome::CopyPlain(format!("{hash:#x}")));
                }
            }
            Message::DismissSettled => self.settled = None,
            Message::DismissError => self.error = None,
        }
        None
    }

    fn on_addr_changed(&mut self, v: String) -> Option<Outcome> {
        self.addr_input = v;
        self.error = None;
        let trimmed = self.addr_input.trim();
        // A full-length string is a finished answer, so contradicting it is
        // useful; anything shorter is still being typed. Read before the parse
        // so the borrow on `addr_input` ends here.
        let looks_complete = trimmed.len() >= ADDRESS_TEXT_LEN;
        // Through `parse_address`, not `parse::<Address>()`, so a mixed-case
        // address that fails its EIP-55 checksum is refused here rather than
        // silently resolved against whatever those 20 bytes turn out to be.
        let parsed = encode::parse_address(trimmed);
        match parsed {
            Ok(addr) => {
                self.addr_error = None;
                // Already resolved / resolving this exact address — no-op.
                // A *failed* resolve is deliberately not in this list: it is
                // the one settled state worth leaving, so re-entering the same
                // address retries instead of doing nothing.
                if self.resolve_target == Some(addr)
                    && (self.loaded.is_some() || self.resolving || self.not_found)
                {
                    return None;
                }
                self.reset_composer_keep_addr();
                self.resolve_target = Some(addr);
                match self.net.builtin() {
                    // Built-in chain: curated registry first, else fetch the
                    // verified bytecode and recover the ABI.
                    Some(chain) => {
                        // A curated hit shows immediately — its names are
                        // authoritative and it needs no round trip — and then
                        // the fetch runs anyway to fill in everything the
                        // hand-written subset leaves out. `set_loaded` bumps
                        // the sequence, so the request must read it afterwards.
                        if let Some(loaded) = abi::known_by_address(chain, addr) {
                            self.set_loaded(loaded);
                        }
                        // `reset_composer_keep_addr` above already bumped the
                        // sequence, retiring any earlier fetch; this request
                        // rides whatever value it left behind.
                        self.resolving = self.loaded.is_none();
                        Some(Outcome::ResolveContract {
                            seq: self.resolve_seq,
                            chain,
                            address: addr,
                        })
                    }
                    // Custom (unverified) network: no verified-bytecode fetch
                    // and no curated registry — prompt straight for a pasted
                    // ABI. Whether anything is *deployed* there is still worth
                    // asking, and the configured RPC can answer it: pasting an
                    // ABI proves nothing about the account it is aimed at, and
                    // this is the composer with the least else to go on.
                    None => {
                        self.not_found = true;
                        self.probe_code(addr)
                    }
                }
            }
            Err(reason) => {
                self.reset_composer_keep_addr();
                self.addr_error = looks_complete.then_some(reason);
                None
            }
        }
    }

    /// Re-issue the bytecode fetch for the address already in the box, after
    /// one failed. Only reachable from the Retry affordance the failed state
    /// puts on screen.
    fn retry_resolve(&mut self) -> Option<Outcome> {
        let addr = self.resolve_target?;
        let chain = self.net.builtin()?;
        self.resolve_error = None;
        self.not_found = false;
        self.invalidate_resolve();
        self.resolving = true;
        Some(Outcome::ResolveContract {
            seq: self.resolve_seq,
            chain,
            address: addr,
        })
    }

    fn set_loaded(&mut self, loaded: LoadedContract) {
        // Installing a contract retires any resolve still in flight. Without
        // this, a curated-registry hit or a pasted ABI (neither of which issues
        // a request, so neither used to touch the sequence) leaves an older
        // bytecode fetch matching `resolve_seq` — it would land, read the *new*
        // `resolve_target`, and hand this address the other contract's methods.
        self.invalidate_resolve();
        self.resolving = false;
        self.not_found = false;
        self.resolve_error = None;
        // A curated or pasted ABI is authoritative for the address regardless
        // of what the proxy walk could or couldn't read, so the caution retires
        // with it; a bytecode load keeps it (that ABI *is* the stub's).
        if loaded.source != AbiSource::Bytecode {
            self.proxy_unverified = false;
            self.proxy_beacon = false;
        }
        self.paste_open = false;
        self.resolve_target = Some(loaded.address);
        self.method_idx = 0;
        self.method_menu_open = false;
        self.read_idx = 0;
        self.read_menu_open = false;
        self.invalidate_read();
        self.loaded = Some(loaded);
        self.reset_args();
        self.reset_read_args();
    }

    fn reset_args(&mut self) {
        let n = self
            .loaded
            .as_ref()
            .and_then(|c| c.methods.get(self.method_idx))
            .map(|m| m.inputs.len())
            .unwrap_or(0);
        self.args = vec![String::new(); n];
        self.value_input = "0".into();
    }

    fn reset_read_args(&mut self) {
        let n = self
            .selected_read_method()
            .map(|m| m.inputs.len())
            .unwrap_or(0);
        self.read_args = vec![String::new(); n];
    }

    fn reset_composer(&mut self) {
        self.addr_input.clear();
        self.reset_composer_keep_addr();
    }

    fn reset_composer_keep_addr(&mut self) {
        self.invalidate_resolve();
        self.loaded = None;
        self.resolving = false;
        self.not_found = false;
        self.resolve_error = None;
        self.addr_error = None;
        self.proxy_unverified = false;
        // Belongs to the address being left behind. Cleared here rather than in
        // `set_loaded` (which a pasted ABI also goes through) precisely because
        // pasting an ABI must NOT retire it: it answers what the address
        // exposes, not whether anything is deployed there.
        self.nothing_deployed = false;
        self.paste_open = false;
        self.resolve_target = None;
        self.method_idx = 0;
        self.method_menu_open = false;
        self.args.clear();
        self.value_input = "0".into();
        self.read_idx = 0;
        self.read_menu_open = false;
        self.read_args.clear();
        self.invalidate_read();
    }

    /// Retire any resolve still in flight. `on_contract_resolved` applies its
    /// answer to whatever `resolve_target` holds when it lands, so every change
    /// to that target — a new address, a curated hit, a pasted ABI, a network
    /// switch — has to bump the sequence or the answer gets misapplied.
    fn invalidate_resolve(&mut self) {
        self.resolve_seq += 1;
    }

    /// Retire any read still in flight, plus its displayed result. Same shape
    /// as [`Self::invalidate_resolve`]: `on_read` decodes the returned bytes
    /// against whatever method is selected when they land, so anything that
    /// changes the selection, the arguments, or the contract must bump the
    /// sequence. Clearing `read_busy` also stops a superseded query from
    /// leaving the spinner up forever — `on_read` returns on the stale-sequence
    /// check before it gets to reset the flag.
    fn invalidate_read(&mut self) {
        self.read_seq += 1;
        self.read_busy = false;
        self.read_result = None;
    }

    /// A network change invalidates every resolved-contract / query / sim piece
    /// of state — known contracts are per-chain and a call result is per-network.
    ///
    /// It invalidates the **queue** too, and that part is a safety property
    /// rather than housekeeping: a [`QueuedCall`] carries only `to`, and the
    /// same contract sits at a different address on every chain. A batch
    /// composed on one network and left standing across a switch would be
    /// packed into a MultiSend / `executeBatch` addressed at whatever happens
    /// to occupy those addresses on the new one. `from` is the network the
    /// dropped calls were composed for, named in the notice so the loss is
    /// never silent.
    fn on_network_reset(&mut self, from: NetworkId) {
        self.net_menu_open = false;
        self.reset_composer();
        self.invalidate_sim();
        let dropped = self.batch.len();
        self.batch.clear();
        self.expanded = None;
        // The old banner described the old network's context — retire it
        // before deciding whether this switch has something of its own to say.
        self.error = None;
        if dropped > 0 {
            self.error = Some(format!(
                "Batch cleared — {dropped} call{} composed for {} can't be replayed on {}.",
                if dropped == 1 { "" } else { "s" },
                from.display_name(),
                self.net.display_name(),
            ));
        }
    }

    /// Drop the queue because the account it was composed for changed.
    ///
    /// Same safety property as [`Self::on_network_reset`], one axis over: a
    /// [`QueuedCall`] records `to`/`value`/`data` and nothing about who
    /// executes them. Re-shaping the same calls under a different sender
    /// silently re-aims every balance, allowance and permission they depend
    /// on — and any preflight already run described the old sender's state.
    /// Returns whether it put a notice on screen — the caller uses that to keep
    /// a following network re-pin from clearing it.
    fn on_identity_reset(&mut self, from: Address, to: Address) -> bool {
        self.reset_composer();
        self.invalidate_sim();
        let dropped = self.batch.len();
        self.batch.clear();
        self.expanded = None;
        self.net_menu_open = false;
        self.template_menu_open = false;
        self.cancel_rename();
        self.error = None;
        if dropped == 0 {
            return false;
        }
        self.error = Some(format!(
            "Batch cleared — {dropped} call{} composed for {} can't be reused as {}: they'd run \
             against a different account's balances and approvals.",
            if dropped == 1 { "" } else { "s" },
            crate::wallet::short_address(from),
            crate::wallet::short_address(to),
        ));
        true
    }

    /// Retire any simulation still in flight, along with its verdict.
    ///
    /// The third of the three guards (`resolve_seq`, `read_seq`, `sim_seq`),
    /// and the one that was missing: `on_sim` adopted whatever landed, so a
    /// result for the previous batch became the current batch's verdict — and
    /// the review reads that verdict to decide whether Confirm says
    /// "Sign & execute now" or warns. Clearing `sim_busy` here also lets the
    /// user re-run immediately; the superseded result can no longer land.
    fn invalidate_sim(&mut self) {
        self.sim = None;
        self.sim_at = None;
        self.sim_busy = false;
        self.sim_seq += 1;
    }

    /// The preflight verdict for the batch as it currently stands, for the
    /// review overlay. `sim` is cleared by [`Self::invalidate_sim`] on every
    /// edit — and any in-flight run is retired with it — so a present result
    /// always describes the current queue.
    fn preflight(&self) -> Preflight {
        let Some(sim) = &self.sim else {
            // No verdict. On a chain we *can* simulate that's a gap worth
            // flagging; on a custom network there was never anything to run.
            return if self.net.builtin().is_some() {
                Preflight::Missing
            } else {
                Preflight::Unsupported
            };
        };
        match &sim.outcome {
            // A pass is only as good as when it was taken and what it could
            // verify. Both used to be dropped on the way to the overlay, so a
            // twenty-minute-old verdict resting on unverified RPC reads
            // produced exactly the same unsoftened confirm as one taken a
            // second ago against Helios-verified state.
            // A pass is only as good as when it was taken, what it could
            // verify, and whether the resulting transaction can be mined at
            // all. The last is checked first: no amount of freshness makes a
            // 125M-gas batch signable.
            BatchOutcome::Success => match sim.gas_fit() {
                crate::txbuilder::sim::GasFit::Exceeds {
                    gas_used,
                    block_gas_limit,
                } => Preflight::TooMuchGas {
                    gas_used,
                    block_gas_limit,
                },
                _ => Preflight::Passed {
                    stale: self.sim_is_stale(),
                    verified: sim.verified,
                },
            },
            BatchOutcome::Revert { step, reason } | BatchOutcome::Halt { step, reason } => {
                Preflight::Fails {
                    at: self.describe_step(*step),
                    reason: reason.clone(),
                }
            }
            BatchOutcome::Error(reason) => Preflight::Errored {
                reason: reason.clone(),
            },
            // The simulator ran and couldn't reach a verdict — on a built-in
            // chain that's a failed preflight, not an absent one.
            BatchOutcome::Unavailable => {
                if self.net.builtin().is_some() {
                    Preflight::Missing
                } else {
                    Preflight::Unsupported
                }
            }
        }
    }

    /// Whether the held verdict has aged past [`PREFLIGHT_STALE_AFTER`]. No
    /// timestamp (a result planted by a test, or none held) reads as fresh —
    /// staleness is an extra caution, never the only thing keeping a batch off
    /// a device.
    fn sim_is_stale(&self) -> bool {
        self.sim_at
            .is_some_and(|t| t.elapsed() >= PREFLIGHT_STALE_AFTER)
    }

    /// Surface a coordinator-side failure on the pane's error banner. Without
    /// this the builder had no error channel back from the dashboard: a request
    /// that couldn't be built was logged and dropped, so the primary button
    /// registered the click and nothing on screen changed.
    pub fn set_error(&mut self, msg: String) {
        self.traced("set_error", move |s| s.error = Some(msg))
    }

    /// The pane's current error banner text, for the coordinator's tests.
    #[cfg(test)]
    pub(crate) fn error_text(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// The calls to simulate / review / sign: the queue, wrapped in
    /// flash-approval zero-resets (before *and* after) when the toggle is on.
    /// The resets are derived here and never stored in `batch`, so the queue
    /// stays editable and reorder-safe.
    fn effective_calls(&self) -> Vec<QueuedCall> {
        if self.flash_wrapped() {
            flash_approval::wrap_with_flash_approval(&self.batch, self.next_id)
        } else {
            self.batch.clone()
        }
    }

    /// Whether [`Self::effective_calls`] is currently wrapping the queue.
    fn flash_wrapped(&self) -> bool {
        self.auto_revoke && self.can_batch()
    }

    /// [`Self::effective_calls`], refused when the wrap pushes the transaction
    /// past the queue ceiling.
    ///
    /// [`MAX_BATCH_CALLS`] was enforced on `batch` — what the user queues — and
    /// nowhere on what actually gets simulated, packed and signed. Flash
    /// approval adds a zero-reset *before* and *after* each distinct
    /// `(token, spender)` pair, so a 64-call batch of approvals leaves here as
    /// up to 192, and every reason for the cap (one card per call laid out
    /// unvirtualized, one decode round trip per leg at review, one simulated
    /// step per call) applies to the expanded list rather than the queued one.
    ///
    /// Refusing at the point of use rather than blocking the toggle: the queue
    /// can grow after the toggle is set, so a check on the toggle alone would
    /// be a gate the user walks straight past.
    fn effective_calls_checked(&self) -> Result<Vec<QueuedCall>, String> {
        let calls = self.effective_calls();
        if calls.len() <= MAX_BATCH_CALLS {
            return Ok(calls);
        }
        Err(format!(
            "With \"revoke approvals after batch\" on, these {} calls become {} — one reset \
             before and one after each approval — and this wallet runs at most \
             {MAX_BATCH_CALLS} in a transaction. Turn the toggle off, or split the batch.",
            self.batch.len(),
            calls.len(),
        ))
    }

    /// Name the effective-call at `step` in terms the user can point at.
    ///
    /// The simulator indexes [`Self::effective_calls`], while the queue cards
    /// are numbered over `batch` — two different index spaces that the revert
    /// strip and the review note both used to print as a bare `#step + 1`.
    /// With flash approval on that number could name a call the user cannot
    /// see, inspect or remove, and the prepended resets shift *every* queue
    /// position, so the mismatch is no longer just off the end.
    fn describe_step(&self, step: usize) -> String {
        if !self.flash_wrapped() {
            return format!("call #{}", step + 1);
        }
        let opens = flash_approval::prepend_count(&self.batch);
        let queued = self.batch.len();
        if step < opens {
            "the allowance reset flash approval runs before the batch".to_string()
        } else if step < opens + queued {
            format!("call #{}", step - opens + 1)
        } else {
            "the approval revoke flash approval runs after the batch".to_string()
        }
    }

    /// What the preflight verdict on screen does *not* cover, for the batch
    /// shape actually queued.
    ///
    /// [`crate::txbuilder::sim::to_steps`] enumerates the model's limits, and
    /// that docstring was brought in line with the truth — but the docstring is
    /// read by whoever maintains the simulator, and the person about to sign
    /// reads a green box that says "Simulation passed" and nothing else. Every
    /// item here is a way that box can be wrong in the user's disfavour, so it
    /// belongs beside the box.
    ///
    /// Derived from the queue rather than listed flat: a two-call Safe batch
    /// and a single EOA call have different blind spots, and a list padded with
    /// caveats that can't apply here is one the user learns to skip.
    fn sim_blind_spots(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.ctx.is_safe {
            // The wrapper is the whole difference between "these calls work"
            // and "this transaction works", and a guard can reject a batch
            // every sub-call of which succeeds here.
            out.push(
                "the execTransaction wrapper — its signature checks, and any transaction guard \
                 installed on this Safe",
            );
            // Only wrong for a Safe: for an EOA the sender really is the origin.
            out.push("tx.origin, which is the Safe here and the broadcasting account on chain");
        } else if self.effective_calls().len() > 1 {
            // The multi-call EOA path is the only one that can install a
            // designator, and the first delegation is the case the user has
            // least intuition for.
            out.push(
                "the delegation designator, if this transaction is the one installing it — a \
                 callee reading msg.sender.code.length sees the opposite here",
            );
        }
        if self.effective_calls().len() > 1 {
            out.push(
                "transient storage (EIP-1153), wiped between steps here and kept for the whole \
                 transaction on chain",
            );
        }
        out
    }

    /// A queued call that targets the account this batch would execute as.
    ///
    /// The same fact the review overlay raises, surfaced one step earlier: the
    /// queue is where an imported bundle first becomes visible, and it is the
    /// last point at which dropping the call is one click rather than a
    /// re-composition. `None` for every ordinary call.
    ///
    /// Only meaningful once a batch can be batched at all — a custom-network
    /// composer sends a single call and has no Safe to reconfigure.
    pub(crate) fn self_admin_note(&self, c: &QueuedCall) -> Option<String> {
        if c.to != self.owner {
            return None;
        }
        if !self.ctx.is_safe {
            return Some("This call is addressed to the account that would send it.".to_string());
        }
        Some(match crate::safe::admin::authorized_effect(&c.data) {
            Some(effect) => format!(
                "Runs as the Safe and {effect}. Remove it unless you meant to change the \
                 multisig itself."
            ),
            None => "Addressed to the Safe that would execute it, and this wallet doesn't \
                     recognise the call. Run this way it acts as the Safe on itself."
                .to_string(),
        })
    }

    /// How wrong the review's fee estimate is, phrased for the user.
    ///
    /// The estimate is `simulated gas × the simulated block's base fee`, which
    /// is the only fee figure this flow can honestly produce before signing: a
    /// real `eth_estimateGas` needs the assembled owner signatures on the Safe
    /// path, and on the 7702 path it needs the authorization the review exists
    /// to get agreed to. So the number is stated with its error bars rather
    /// than withheld — and the bars run in both directions.
    ///
    /// Derived from the batch's shape, like [`Self::sim_blind_spots`], so a
    /// single call on Mainnet doesn't carry the wrapper and L1-data caveats
    /// that belong to a Safe batch on Base.
    fn fee_caveats(&self) -> Vec<String> {
        let mut out =
            vec!["excludes the priority tip, which every transaction also pays".to_string()];
        // On the OP stack the L1 data fee is frequently the larger half of the
        // total, so omitting it silently would understate the cost by more than
        // the figure itself.
        if matches!(self.net.builtin(), Some(Chain::Base | Chain::Optimism)) {
            out.push(
                "excludes the L1 data fee, which on this chain is often the larger half of the \
                 total"
                    .to_string(),
            );
        }
        if self.ctx.is_safe {
            out.push(
                "excludes the execTransaction wrapper and its per-owner signature checks"
                    .to_string(),
            );
            out.push("excludes the MultiSend dispatch loop".to_string());
        } else if self.effective_calls().len() > 1 {
            out.push("excludes the executeBatch dispatch loop".to_string());
        }
        // The one caveat that runs the other way. Named because a user
        // reconciling this against the figure their device shows deserves to
        // know which direction the gap points.
        if self.effective_calls().len() > 1 {
            out.push(
                "counts the 21,000 intrinsic gas once per call, where the real transaction pays \
                 it once in total"
                    .to_string(),
            );
        }
        out
    }

    /// Whether the active identity can execute more than one call atomically —
    /// a Safe (MultiSend) or a 7702-capable EOA. Gates the flash-approval
    /// toggle: appending a revoke only makes sense if the batch can batch.
    fn can_batch(&self) -> bool {
        self.ctx.is_safe || self.ctx.eoa_can_batch
    }

    /// The `(token, spender)` allowances a flash-approval revoke would reset —
    /// used by the view to show/hide the toggle and its count hint.
    fn revoke_targets(&self) -> Vec<(Address, Address)> {
        flash_approval::revoke_targets(&self.batch)
    }

    fn move_call(&mut self, id: u64, dir: i32) {
        let Some(i) = self.batch.iter().position(|c| c.id == id) else {
            return;
        };
        let j = i as i32 + dir;
        if j < 0 || j as usize >= self.batch.len() {
            return;
        }
        self.batch.swap(i, j as usize);
        self.invalidate_sim();
    }

    fn selected_method(&self) -> Option<&AbiMethod> {
        self.loaded
            .as_ref()
            .and_then(|c| c.methods.get(self.method_idx))
    }

    fn selected_read_method(&self) -> Option<&AbiMethod> {
        self.loaded
            .as_ref()
            .and_then(|c| c.read_methods.get(self.read_idx))
    }

    /// Whether the active network is a user-defined (unverified) custom network.
    fn is_custom(&self) -> bool {
        self.net.is_custom()
    }

    /// Whether the two-pane batch layout applies. Custom networks collapse to
    /// the single-transaction composer (per the send-only, no-batch rule), so
    /// the batch pane is hidden there.
    fn batch_layout(&self) -> bool {
        !self.is_custom()
    }

    /// Human label for the active network (built-in display name, or the custom
    /// network's configured name).
    fn net_display_name(&self) -> String {
        match self.net {
            NetworkId::Builtin(c) => c.display_name().to_string(),
            NetworkId::Custom(id) => self
                .ctx
                .custom_networks
                .iter()
                .find(|(cid, _)| *cid == id)
                .map(|(_, n)| n.clone())
                .unwrap_or_else(|| format!("Chain {id}")),
        }
    }

    /// The switcher's options: the three built-ins, then any enabled custom
    /// networks.
    fn network_options(&self) -> Vec<(NetworkId, String)> {
        let mut out: Vec<(NetworkId, String)> = Chain::ALL
            .iter()
            .map(|c| (NetworkId::Builtin(*c), c.display_name().to_string()))
            .collect();
        for (id, name) in &self.ctx.custom_networks {
            out.push((NetworkId::Custom(*id), name.clone()));
        }
        out
    }

    /// Whether the currently-composed call is valid and can be queued / sent.
    fn compose_valid(&self) -> bool {
        match self.mode {
            Mode::Write => {
                let Some(m) = self.selected_method() else {
                    return false;
                };
                if self.args.len() != m.inputs.len() {
                    return false;
                }
                let args_ok = m
                    .inputs
                    .iter()
                    .zip(&self.args)
                    .all(|(inp, v)| encode::is_valid(&inp.ty, v));
                let value_ok = !m.payable || encode::parse_wei(&self.value_input).is_ok();
                args_ok && value_ok
            }
            // All three, not just the target. The CTA used to light up on a
            // valid `to` beside an unparseable value or calldata, and the
            // refusal then arrived as a banner at the foot of the page rather
            // than beside the field that caused it.
            Mode::Raw => {
                encode::parse_address(&self.raw_to).is_ok()
                    && encode::parse_wei(&self.raw_value).is_ok()
                    && encode::parse_data(&self.raw_data).is_ok()
            }
            Mode::Read => false,
        }
    }

    /// Whether the composed read query is valid (method selected, params coerce).
    fn read_valid(&self) -> bool {
        let Some(m) = self.selected_read_method() else {
            return false;
        };
        self.read_args.len() == m.inputs.len()
            && m.inputs
                .iter()
                .zip(&self.read_args)
                .all(|(inp, v)| encode::is_valid(&inp.ty, v))
    }

    /// Build the currently-composed call (Write or Raw). Never called in Read
    /// mode (reads are queried, not queued).
    fn compose_call(&self) -> Result<QueuedCall, crate::txbuilder::TxBuilderError> {
        use crate::txbuilder::TxBuilderError;
        match self.mode {
            Mode::Write => {
                let m = self
                    .selected_method()
                    .cloned()
                    .ok_or_else(|| TxBuilderError::Input("no method selected".into()))?;
                let (name, addr) = self
                    .loaded
                    .as_ref()
                    .map(|c| (c.name.clone(), c.address))
                    .unwrap_or_default();
                encode::build_contract_call(
                    self.next_id,
                    addr,
                    &name,
                    &m,
                    &self.args,
                    &self.value_input,
                )
            }
            Mode::Raw => {
                let to = encode::parse_address(&self.raw_to).map_err(TxBuilderError::Input)?;
                encode::build_raw_call(self.next_id, to, &self.raw_value, &self.raw_data)
            }
            Mode::Read => Err(TxBuilderError::Input("read methods are not sent".into())),
        }
    }

    /// Whether this identity can carry a batch to a signature at all. False
    /// only for a watch-only account, which can compose and simulate — both
    /// useful on their own — but must not be walked through a signing ceremony
    /// that ends in the signer refusing.
    fn can_sign(&self) -> bool {
        self.ctx.is_safe || self.ctx.can_sign
    }

    fn add_to_batch(&mut self) {
        // A plain EOA batches atomically only when its signer can authorize an
        // EIP-7702 delegation (Local / Ledger). Trezor / view-only cannot, so
        // they stay capped at one call.
        if !self.ctx.is_safe && !self.ctx.eoa_can_batch && !self.batch.is_empty() {
            self.error = Some(
                "This account sends one call at a time — atomic batching needs a software key \
                 or a Ledger (EIP-7702), or a Safe."
                    .into(),
            );
            return;
        }
        // The same ceiling the import path applies, so a batch built by hand
        // can always be exported and read back.
        if self.batch.len() >= MAX_BATCH_CALLS {
            self.error = Some(format!(
                "This batch already has {MAX_BATCH_CALLS} calls — as many as one transaction \
                 carries and still gets read before it is signed. Send this batch, then start \
                 the next one."
            ));
            return;
        }
        match self.compose_call() {
            Ok(call) => {
                self.next_id += 1;
                self.batch.push(call);
                self.invalidate_sim();
                self.error = None;
                // Reset params but keep the contract loaded for rapid batching.
                match self.mode {
                    Mode::Write => self.reset_args(),
                    Mode::Raw => self.raw_data.clear(),
                    Mode::Read => {}
                }
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }

    /// Custom-network "Send transaction": build the single composed call and
    /// hand it straight to the review overlay (no batch queue on custom nets).
    fn send_single(&mut self) -> Option<Outcome> {
        if let Some(why) = self.no_signer_reason() {
            self.error = Some(why);
            return None;
        }
        match self.compose_call() {
            Ok(call) => {
                self.error = None;
                Some(Outcome::Review {
                    calls: vec![call],
                    // This path only exists on custom networks, where there is
                    // no simulator to have run.
                    preflight: Preflight::Unsupported,
                    sim: None,
                    // No simulation means no gas figure, so the review shows no
                    // fee at all here and there is nothing to qualify. The
                    // native value the call carries still reaches the card.
                    fee_caveats: Vec::new(),
                })
            }
            Err(e) => {
                self.error = Some(e.to_string());
                None
            }
        }
    }

    /// Why this batch can't be taken to a signature, if it can't. `None` when
    /// the active identity can sign.
    ///
    /// Two independent reasons, both settled before the ceremony rather than
    /// inside it: no key at all (watch-only), and a Safe whose contract version
    /// this wallet won't sign for. See [`Self::safe_version_block`] for why the
    /// second one used to surface as late as it did.
    pub(super) fn no_signer_reason(&self) -> Option<String> {
        if !self.can_sign() {
            return Some(format!(
                "{} is watch-only — Kao holds no key for it, so this batch can't be signed. \
                 Compose and simulate freely; to send it, switch to an account with a key.",
                crate::wallet::short_address(self.owner),
            ));
        }
        self.safe_version_block()
    }

    /// The active Safe's version, if it is one this pane can't sign for.
    ///
    /// The Send flow answers the same question at the top of its own flow
    /// (`version_block`, `send.rs`). The Builder took the version in through
    /// `set_context` and then never read it — the field carried
    /// `#[allow(dead_code)]` — so the refusal came out of
    /// `build_txbuilder_request` at Review instead: after a whole batch had
    /// been composed, simulated green, and confirmed.
    ///
    /// Both gates are consulted. `ensure_signable_version` owns the EIP-712
    /// domain question, and `multisend_call_only` owns whether the batch can be
    /// routed at all — and because the Builder wraps even a *single* call in
    /// MultiSend, a version with no known deployment blocks the whole pane and
    /// not just multi-call batches. They agree today; checking both means a
    /// future version added to one and not the other refuses here rather than
    /// at the overlay.
    fn safe_version_block(&self) -> Option<String> {
        if !self.ctx.is_safe {
            return None;
        }
        let Some(version) = self.ctx.safe_version.as_deref() else {
            // Only reachable if the descriptor lost its version between
            // `txbuilder_identity` and here. The version decides both the
            // signing domain and the MultiSend routing, so not knowing it is a
            // refusal, not a default.
            return Some(
                "Kao hasn't read this Safe's contract version. That version picks both the \
                 signing domain and the MultiSend library the batch runs through, so there is \
                 nothing safe to assume — reopen the Safe to refresh it."
                    .into(),
            );
        };
        if let Err(e) = crate::safe::tx::ensure_signable_version(version) {
            return Some(e);
        }
        crate::txbuilder::multisend::multisend_call_only(version)
            .err()
            .map(|e| {
                format!(
                    "{e}. Every Builder batch runs through MultiSend, including a \
                              single call, so this Safe can't send from this pane."
                )
            })
    }

    /// Fire the composed read query as an `eth_call` on the active network.
    fn on_query(&mut self) -> Option<Outcome> {
        if !self.read_valid() {
            return None;
        }
        let m = self.selected_read_method()?.clone();
        let to = self.loaded.as_ref()?.address;
        let data = match encode::encode_call(&m, &self.read_args) {
            Ok(d) => d,
            Err(e) => {
                self.error = Some(e.to_string());
                return None;
            }
        };
        self.invalidate_read();
        self.read_busy = true;
        Some(Outcome::Read {
            seq: self.read_seq,
            net: self.net,
            to,
            data,
        })
    }

    /// Replace the batch with a template's calls, renumbered into the session.
    ///
    /// Refused on a custom network and on any chain other than the one the
    /// template was composed on — the same wall `bundle::import` puts in front
    /// of the JSON path, which templates used to route around.
    fn load_template(&mut self, t: &Template) {
        let Some(chain) = self.net.builtin() else {
            self.error = Some(format!(
                "\"{}\" was composed on a built-in chain and can't be loaded on {} — contract \
                 addresses don't carry across networks.",
                t.name,
                self.net.display_name(),
            ));
            self.template_menu_open = false;
            return;
        };
        let calls = match t.calls(self.next_id, chain) {
            Ok(c) => c,
            Err(e) => {
                self.error = Some(e.to_string());
                return;
            }
        };
        match self.adopt_batch(calls) {
            Ok(()) => {
                self.template_menu_open = false;
                self.cancel_rename();
                self.note_identity_drift(t.from, &format!("\"{}\"", t.name));
            }
            Err(e) => self.error = Some(e),
        }
    }

    /// Say so when a loaded batch was composed as a different account.
    ///
    /// The calls in a batch are written against one identity — its allowances,
    /// its balances, its positions — and the natural workflow is exactly the
    /// one that re-aims them: compose and test as your EOA, save it, switch to
    /// the Safe to actually run it. The chain wall has always refused a
    /// cross-chain load; this one is a *notice*, not a refusal, for two
    /// reasons. A batch of generic calls is legitimately reusable across
    /// accounts, so refusing would break a real workflow. And for an imported
    /// bundle the recorded identity is authored by whoever wrote the file, so
    /// as a wall it would stop nobody — an attacker just omits the key.
    ///
    /// Silence stays the answer when nothing was recorded (`None`): a batch
    /// saved before this existed makes no claim, and inventing one would be
    /// the same mistake `meta.chainId` made.
    fn note_identity_drift(&mut self, composed_as: Option<Address>, what: &str) {
        let Some(from) = composed_as else { return };
        if from == self.owner {
            return;
        }
        let notice = format!(
            "{what} was composed as {}, and you're composing as {}. The calls still point where \
             they did — check any allowance, balance or position they assume belongs to the \
             other account.",
            crate::wallet::short_address(from),
            crate::wallet::short_address(self.owner),
        );
        // `adopt_batch` may already have said it replaced a queue. Both facts
        // matter, and the identity one is the one that changes what executes.
        self.error = Some(match self.error.take() {
            Some(prev) => format!("{notice} {prev}"),
            None => notice,
        });
    }

    /// Replace the queue with `calls`, applying the same rules
    /// [`Self::add_to_batch`] applies one call at a time.
    ///
    /// Both wholesale paths — JSON import and template load — used to assign
    /// `self.batch` directly, which walked straight past the atomic-batching
    /// cap. A Trezor or view-only account could import six calls, simulate them
    /// green, and only learn at Review that this wallet can't sign more than
    /// one; every multi-call template was silently unusable the same way.
    /// Replacing a non-empty queue is also called out rather than done
    /// silently, since there is no undo for it.
    fn adopt_batch(&mut self, calls: Vec<QueuedCall>) -> Result<(), String> {
        if calls.is_empty() {
            return Err("that batch has no calls in it".to_string());
        }
        if calls.len() > 1 && !self.can_batch() {
            return Err(format!(
                "This batch has {} calls, and this account sends one at a time — atomic \
                 batching needs a software key or a Ledger (EIP-7702), or a Safe.",
                calls.len(),
            ));
        }
        // After the one-at-a-time reason, so the more specific refusal wins for
        // an account that could never have run this batch at any length.
        if calls.len() > MAX_BATCH_CALLS {
            return Err(format!(
                "That batch has {} calls, and this wallet queues at most {MAX_BATCH_CALLS}.",
                calls.len(),
            ));
        }
        let replaced = self.batch.len();
        self.next_id += calls.len() as u64;
        self.batch = calls;
        self.invalidate_sim();
        self.expanded = None;
        self.error = (replaced > 0).then(|| {
            format!(
                "Replaced the {replaced} call{} you had queued.",
                if replaced == 1 { "" } else { "s" },
            )
        });
        Ok(())
    }

    /// Commit an in-flight inline rename: trim, apply, persist. A blank name is
    /// rejected (keeps the rename open so the user can fix it).
    fn commit_rename(&mut self) -> Option<Outcome> {
        let idx = self.rename_idx?;
        let name = self.rename_buf.trim().to_string();
        if name.is_empty() {
            return None;
        }
        let rollback = self.templates.clone();
        let t = self.templates.get_mut(idx)?;
        t.name = name;
        self.cancel_rename();
        Some(self.persist(rollback))
    }

    /// Ask the coordinator to write the template list, handing it the
    /// pre-mutation snapshot to restore if the write fails.
    fn persist(&self, rollback: Vec<Template>) -> Outcome {
        Outcome::PersistTemplates {
            list: self.templates.clone(),
            rollback,
        }
    }

    /// Dismiss the JSON overlay and drop what was in it. `Close` never cleared
    /// `modal`, so the flag outlived the view that owned it.
    fn close_modal(&mut self) {
        self.modal = Modal::None;
        self.json_text.clear();
        self.json_error = None;
    }

    fn cancel_rename(&mut self) {
        self.rename_idx = None;
        self.rename_buf.clear();
    }

    // ── view (in tx_builder_view.rs-style helpers below) ──────────────
    pub fn view(&self, t: KaoTheme) -> Element<'_, Message> {
        view::root(self, t)
    }
}

/// A batch prepared for review + signing. Built by the dashboard
/// coordinator from the queued calls + active identity — the Safe variant
/// collapses the whole queue into one atomic MultiSend `execTransaction`;
/// the EOA variant carries a single call broadcast as an ordinary tx.
#[derive(Debug, Clone)]
pub enum BatchSignRequest {
    Safe(SafeBatchRequest),
    Eoa(EoaBatchRequest),
}

/// A Safe MultiSend batch. `input` is the deterministic MultiSend wrapper
/// (delegatecall to `MultiSendCallOnly`); `prepared` pins the reviewed
/// `(nonce, safeTxHash)` once the prepare task lands, so the owners sign
/// exactly what was shown.
#[derive(Debug, Clone)]
pub struct SafeBatchRequest {
    pub safe: Address,
    pub chain: Chain,
    pub version: String,
    pub trust: SafeTrust,
    pub threshold: u32,
    pub owner_count: usize,
    /// Indices into `accounts` for owners that can sign (Local/Ledger/Trezor).
    pub signable_indices: Vec<u32>,
    pub input: SafeTxInput,
    pub call_count: usize,
    pub prepared: Option<(u64, B256)>,
    /// Nonces already claimed by proposals sitting on this Safe's Transaction
    /// Service queue, as the dashboard last fetched them.
    ///
    /// The batch used to be pinned at the live on-chain nonce unconditionally,
    /// so proposing over an already-queued slot filed a silent competitor:
    /// whichever of the two executes voids the other, and neither the review
    /// nor the queue said a word. The prepare step pins past these instead.
    /// `None` means this wallet does **not know** what is queued — the fetch is
    /// in flight, it failed, or it never ran. Distinct from `Some(vec![])`,
    /// which is the positive finding that the queue is empty.
    ///
    /// They used to be the same value, so a Transaction Service that was slow
    /// or down produced exactly the pin an empty queue does, and the propose
    /// path filed the silent competitor this field exists to prevent. Unknown
    /// now blocks proposing rather than guessing: an execute reads the live
    /// nonce and fails honestly if something is ahead of it, but a proposal is
    /// filed and forgotten, and the collision only surfaces when a co-signer's
    /// confirmation voids someone else's.
    pub queued_nonces: Option<Vec<u64>>,
    /// Safe Transaction Service base URL for this Safe, so a batch that can't
    /// meet the threshold from locally-held keys can still be proposed for the
    /// remaining co-signers to confirm.
    pub service_base: String,
}

/// A plain-EOA batch. One or more calls executed from `from`:
///
/// - a single call, or an account that can't delegate, broadcasts as an
///   ordinary EIP-1559 transaction;
/// - N calls from a 7702-capable signer are wrapped as
///   `Simple7702Account.executeBatch` and run atomically.
///
/// Whether a fresh EIP-7702 authorization is signed is decided at **prepare**,
/// from the account's Helios-verified on-chain code, and pinned into
/// [`Self::prepared`] — see [`PreparedDelegation`] for why the send path must
/// not decide it a second time.
#[derive(Debug, Clone)]
pub struct EoaBatchRequest {
    /// The network to broadcast on. A [`NetworkId`] so the same request shape
    /// covers a built-in chain and a user-defined custom network (single call
    /// only on custom — atomic batching is built-in-chains only).
    pub net: NetworkId,
    pub from: Address,
    pub calls: Vec<QueuedCall>,
    /// The reviewed delegation decision, pinned from the prepared
    /// [`sign_review::SignStep::Delegation`] card. `None` until prepare lands,
    /// and a multi-call dispatch with `None` here is refused — the same gate
    /// [`SafeBatchRequest::prepared`] already applies to the Safe arm.
    ///
    /// For a single call this is a *disclosure*, not a commitment: it is set
    /// when the review found the account already carries a delegation, and it
    /// is deliberately not re-checked at send. The signed bytes of a single
    /// call don't commit to the account's code, so a delegation that moved
    /// between review and confirm is not a reason to refuse that transaction —
    /// and making it one would fail ordinary sends for something that isn't
    /// about them. `None` when the account carries no delegation at all.
    pub prepared: Option<PreparedDelegation>,
}

/// The EIP-7702 delegation decision as the user reviewed it.
///
/// This exists because the decision used to be made twice, from two different
/// sources: prepare read the account's code through the Helios-verified
/// fetcher, and the send task read it again over a raw RPC provider. Both
/// dropped the `verified` flag, and nothing compared the two answers. Either
/// direction of disagreement is bad, and neither is loud:
///
/// - The review says "already in place, so no new authorization is signed" and
///   the send signs one anyway — the one signature in this wallet whose effect
///   outlives its transaction, produced against a promise that it wouldn't be.
/// - The send wrongly concludes the account is already delegated, signs no
///   authorization, and broadcasts `executeBatch(Call[])` to an account with
///   no code. That does not revert: a call to a code-less address **succeeds**,
///   so the batch silently does nothing while the UI reports success and
///   clears the queue.
///
/// So the decision is made once, shown, pinned here, and re-checked against
/// chain before signing — a disagreement aborts rather than picks a side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedDelegation {
    /// The delegate the reviewed authorization points at.
    pub delegate: Address,
    /// True when the account already ran `delegate`'s code at review time, so
    /// the review told the user no new authorization would be signed.
    pub already_active: bool,
    /// The nonce the reviewed authorization committed to, and therefore the
    /// nonce its displayed ERC-8213 digest was taken over. `None` when
    /// `already_active` — nothing is signed. The send path re-derives it from
    /// the live account nonce and aborts on disagreement, so the digest the
    /// user checked against their device is the digest that gets signed.
    pub auth_nonce: Option<u64>,
}

impl EoaBatchRequest {
    /// True when this batch runs via `executeBatch` (more than one call). A
    /// single call keeps its original `to`/`value`/`data` and needs no
    /// delegation.
    pub fn is_batch(&self) -> bool {
        self.calls.len() > 1
    }

    /// A short human title for the review header.
    pub fn title(&self) -> String {
        match self.calls.split_first() {
            Some((first, [])) => first.title.clone(),
            _ => format!("Batch · {} calls", self.calls.len()),
        }
    }
}

/// Build a demo approve + supply batch (mirrors the design's sample).
fn sample_batch(next_id: &mut u64, owner: Address) -> Vec<QueuedCall> {
    let usdc = abi::known_by_address(
        Chain::Mainnet,
        alloy::primitives::address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
    );
    let aave_addr = alloy::primitives::address!("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2");
    let aave = abi::known_by_address(Chain::Mainnet, aave_addr);
    let (Some(usdc), Some(aave)) = (usdc, aave) else {
        return Vec::new();
    };
    let approve = usdc.methods.iter().find(|m| m.name == "approve");
    let supply = aave.methods.iter().find(|m| m.name == "supply");
    let (Some(approve), Some(supply)) = (approve, supply) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Ok(c) = encode::build_contract_call(
        *next_id,
        usdc.address,
        "USDC",
        approve,
        &[aave_addr.to_string(), "5000000000".into()],
        "0",
    ) {
        *next_id += 1;
        out.push(c);
    }
    if let Ok(c) = encode::build_contract_call(
        *next_id,
        aave.address,
        "Aave v3 Pool",
        supply,
        &[
            usdc.address.to_string(),
            "5000000000".into(),
            owner.to_string(),
            "0".into(),
        ],
        "0",
    ) {
        *next_id += 1;
        out.push(c);
    }
    out
}

/// Wei → short ETH string, e.g. `0.0500`.
fn wei_to_eth(v: U256) -> String {
    format_token_balance(v, 18).0
}

/// Decode an `eth_call` result into typed [`ReadRow`]s against a method's
/// declared outputs. Returns empty when the method has no outputs or the bytes
/// don't decode (a malformed / reverted response) — the raw hex is still shown.
fn decode_read_rows(m: &AbiMethod, bytes: &[u8]) -> Vec<ReadRow> {
    let Some(ty) = m.output_tuple() else {
        return Vec::new();
    };
    // Return data is ABI-encoded as function params (head-tail, no outer
    // offset), so decode against the output tuple with `abi_decode_params`.
    let vals = match ty.abi_decode_params(bytes) {
        Ok(DynSolValue::Tuple(vals)) => vals,
        _ => return Vec::new(),
    };
    m.outputs
        .iter()
        .zip(vals)
        .enumerate()
        .map(|(i, (out, val))| ReadRow {
            name: if out.name.is_empty() {
                format!("out{i}")
            } else {
                out.name.clone()
            },
            ty: out.ty_str.clone(),
            value: encode::format_sol_value(&val),
        })
        .collect()
}

// The view is large; split into its own module for readability.
mod view;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    /// The two identities the tests act as. Distinct because `set_context` now
    /// drops the queue when the acting address moves.
    /// A preflight that passed, fresh and fully verified — what every one of
    /// these tests plants, and the only shape that leaves the confirm button
    /// reading as routine.
    const PASSED_CLEAN: Preflight = Preflight::Passed {
        stale: false,
        verified: true,
    };

    const SAFE: Address = address!("0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
    const EOA: Address = address!("0x1111111111111111111111111111111111111111");

    fn safe_app() -> TxBuilderApp {
        let mut app = TxBuilderApp::new(SAFE);
        app.set_context(
            SAFE,
            Chain::Mainnet,
            true,
            Some("1.4.1".into()),
            false,
            true,
            Vec::new(),
        );
        app
    }

    /// A watch-only account: composes and simulates, but must never be walked
    /// into a signing ceremony.
    fn view_only_app() -> TxBuilderApp {
        let mut app = TxBuilderApp::new(EOA);
        app.set_context(
            EOA,
            Chain::Mainnet,
            false,
            None,
            /* eoa_can_batch */ false,
            /* can_sign */ false,
            Vec::new(),
        );
        app
    }

    /// A Safe on a version outside the signable range. Reachable in the wild:
    /// a 1.2.0 Safe is a perfectly normal deployment, Kao just can't sign for
    /// its EIP-712 domain.
    fn old_safe_app() -> TxBuilderApp {
        let mut app = TxBuilderApp::new(SAFE);
        app.set_context(
            SAFE,
            Chain::Mainnet,
            true,
            Some("1.2.0".into()),
            false,
            true,
            Vec::new(),
        );
        app
    }

    // ── 4.3a · the pane reports its own state machine ───────────────────

    /// What `RUST_LOG=kao::gui=debug` gets out of one message, without
    /// standing up a subscriber.
    fn traced_by(app: &mut TxBuilderApp, msg: Message) -> Vec<&'static str> {
        let before = app.trace_snapshot();
        app.update(msg);
        before.changed_fields(&app.trace_snapshot())
    }

    #[test]
    fn a_mode_switch_is_reported() {
        let mut app = safe_app();
        assert_eq!(traced_by(&mut app, Message::SetMode(Mode::Raw)), ["mode"]);
    }

    /// A keystroke is not a state transition. The pane sends one message per
    /// character typed into the address box; logging each at DEBUG would bury
    /// the transitions that matter under the ones that don't.
    #[test]
    fn typing_reports_nothing() {
        let mut app = safe_app();
        assert!(traced_by(&mut app, Message::AbiPasteChanged("[".into())).is_empty());
    }

    /// Several distinct paths end with an empty queue — an edit, a network
    /// switch, an identity switch, a template load, a receipt. `batch: 2 -> 0`
    /// on its own doesn't say which, which is why the message name rides along
    /// as the cause.
    #[test]
    fn clearing_the_queue_is_reported_with_its_cause() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        let before = app.trace_snapshot();
        app.update(Message::ClearBatch);
        let after = app.trace_snapshot();
        let changes = before.changes(&after);
        let batch = changes
            .iter()
            .find(|(what, ..)| *what == "batch")
            .expect("the queue emptied");
        assert_eq!((batch.1.as_str(), batch.2.as_str()), ("2", "0"));
    }

    /// The transitions worth watching are the ones the user didn't cause and
    /// can't replay — they arrive through the coordinator's direct callbacks,
    /// which the `update` wrapper never sees.
    #[test]
    fn an_async_verdict_is_reported_too() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        let Some(Outcome::Simulate { seq, .. }) = app.update(Message::Simulate) else {
            panic!("expected a Simulate");
        };
        let before = app.trace_snapshot();
        app.on_sim(seq, Err("light client is still syncing".into()));
        let reported = before.changed_fields(&app.trace_snapshot());
        assert!(reported.contains(&"sim_busy"), "{reported:?}");
        assert!(reported.contains(&"sim_verdict"), "{reported:?}");
    }

    // ── 4.3b · the Safe version is read where it can still change the plan ──

    #[test]
    fn a_signable_safe_version_blocks_nothing() {
        assert!(
            safe_app().no_signer_reason().is_none(),
            "1.4.1 is in range and routes to a MultiSend deployment"
        );
    }

    /// The regression: `Ctx::safe_version` was written by `set_context` and
    /// carried `#[allow(dead_code)]`, so the refusal came out of
    /// `build_txbuilder_request` at Review — after the batch was composed,
    /// simulated and confirmed.
    #[test]
    fn an_unsignable_safe_version_is_refused_before_anything_is_composed() {
        let app = old_safe_app();
        let why = app
            .no_signer_reason()
            .expect("1.2.0 is outside the signable range");
        assert!(why.contains("1.2.0"), "name the version: {why}");
        assert!(
            why.contains("signable range"),
            "say what the problem is: {why}"
        );
    }

    #[test]
    fn an_unsignable_safe_version_never_reaches_the_review() {
        let mut app = old_safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        assert!(
            app.update(Message::Review).is_none(),
            "no review may open for a Safe this wallet can't sign for"
        );
        assert!(app.error.as_deref().is_some_and(|e| e.contains("1.2.0")));
    }

    /// The version reaches this pane as an `Option`, and "not known yet" is a
    /// refusal rather than a default: it picks both the signing domain and the
    /// MultiSend library, so there is nothing safe to assume.
    #[test]
    fn a_safe_with_no_known_version_is_refused_too() {
        let mut app = TxBuilderApp::new(SAFE);
        app.set_context(SAFE, Chain::Mainnet, true, None, false, true, Vec::new());
        let why = app.no_signer_reason().expect("an unknown version blocks");
        assert!(why.contains("version"), "{why}");
    }

    /// Watch-only comes first: it's the more specific answer, and a watch-only
    /// EOA has no Safe version to talk about.
    #[test]
    fn watch_only_still_reports_the_missing_key() {
        let why = view_only_app().no_signer_reason().expect("no key");
        assert!(why.contains("watch-only"), "{why}");
    }

    // ── 4.4 · the export names the account that will execute ────────────

    /// `meta.safe` used to name the construction-time EOA, because `owner` was
    /// written once in `new()` and never refreshed — the same stale field that
    /// made the identity chip render "Safe multisig" over the EOA's address.
    #[test]
    fn the_exported_bundle_names_the_active_safe() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        app.update(Message::OpenSave);

        let v: serde_json::Value =
            serde_json::from_str(&app.json_text).expect("the export is valid JSON");
        let named = v["meta"]["safe"].as_str().expect("meta.safe is stamped");
        assert_eq!(
            named.to_lowercase(),
            SAFE.to_string().to_lowercase(),
            "the bundle must name the Safe that will execute it, not the EOA \
             the pane was constructed with"
        );
        assert_ne!(named.to_lowercase(), EOA.to_string().to_lowercase());
    }

    /// The mirror image: a plain EOA has no Safe, and stamping one would tell
    /// a re-importing wallet to look for a multisig that isn't there.
    #[test]
    fn an_eoa_export_stamps_no_safe() {
        let mut app = eoa_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        app.update(Message::OpenSave);

        let v: serde_json::Value = serde_json::from_str(&app.json_text).expect("valid JSON");
        assert!(
            v["meta"].get("safe").is_none(),
            "no Safe was active: {}",
            app.json_text
        );
    }

    // ── 4.1 · the preflight box states what it didn't model ─────────────

    #[test]
    fn a_safe_batch_names_the_wrapper_and_the_guard() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        let spots = app.sim_blind_spots().join(" | ");
        assert!(spots.contains("execTransaction"), "{spots}");
        assert!(spots.contains("guard"), "{spots}");
        assert!(spots.contains("tx.origin"), "{spots}");
        assert!(
            spots.contains("transient storage"),
            "two steps carry the EIP-1153 caveat: {spots}"
        );
    }

    /// The list is derived from the queue, not printed flat: an EOA has no
    /// wrapper and no guard, and telling it about them teaches the user to
    /// skip the list.
    #[test]
    fn an_eoa_batch_names_the_delegation_and_not_the_wrapper() {
        let mut app = eoa_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        let spots = app.sim_blind_spots().join(" | ");
        assert!(spots.contains("delegation designator"), "{spots}");
        assert!(!spots.contains("execTransaction"), "{spots}");
        assert!(
            !spots.contains("tx.origin"),
            "an EOA *is* the origin: {spots}"
        );
    }

    /// One call is one transaction: no delegation is installed for it and
    /// there is no "between steps" for transient storage to be wiped at.
    #[test]
    fn a_single_eoa_call_has_nothing_to_caveat() {
        let mut app = eoa_app();
        app.batch = vec![sample_batch(&mut app.next_id, app.owner).remove(0)];
        assert!(
            app.sim_blind_spots().is_empty(),
            "{:?}",
            app.sim_blind_spots()
        );
    }

    // ── 2.5 · a simulator failure is a reason, not a shrug ──────────────

    /// The Err string used to be dropped by `unwrap_or_else`, so a Helios
    /// outage and an unservicable `BLOCKHASH` both came out as "Simulation
    /// unavailable" — and then as advice to go and run the preflight again,
    /// which for most of those can never succeed.
    #[test]
    fn a_failed_simulation_carries_its_reason_to_the_review() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        let Some(Outcome::Simulate { seq, .. }) = app.update(Message::Simulate) else {
            panic!("expected a Simulate");
        };
        app.on_sim(seq, Err("light client is still syncing".into()));

        let Preflight::Errored { reason } = app.preflight() else {
            panic!("expected Errored, got {:?}", app.preflight());
        };
        assert_eq!(reason, "light client is still syncing");
        let w = app.preflight().warning().expect("a warning");
        assert!(w.contains("light client is still syncing"), "{w}");
        assert!(
            !w.contains("Go back and run the preflight"),
            "must not tell the user to retry something that can't succeed: {w}"
        );
        assert!(app.preflight().softens_confirm());
        assert!(!app.sim_busy, "the spinner has to come down either way");
    }

    #[test]
    fn a_batch_too_big_for_a_block_never_reads_as_a_pass() {
        // Every sub-call succeeded, so the simulator says Success — but the
        // sum is a transaction no builder can pack, at any price.
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        let Some(Outcome::Simulate { seq, .. }) = app.update(Message::Simulate) else {
            panic!("expected a Simulate");
        };
        app.on_sim(
            seq,
            Ok(BatchSimResult {
                outcome: BatchOutcome::Success,
                gas_used: 125_000_000,
                transfers: Vec::new(),
                verified: true,
                base_fee_per_gas: 1,
                block: 21_000_000,
                block_gas_limit: 45_000_000,
            }),
        );
        let p = app.preflight();
        assert_eq!(
            p,
            Preflight::TooMuchGas {
                gas_used: 125_000_000,
                block_gas_limit: 45_000_000,
            },
            "a clean sweep of sub-calls is not a pass if the sum can't be mined"
        );
        assert!(p.softens_confirm(), "this must not confirm as routine");
        let w = p.warning().expect("the user has to be told why");
        assert!(w.contains("block gas limit"), "{w}");
        assert!(w.contains("Split it"), "and what to do about it: {w}");
    }

    // ── 2.3 · a pass is only as good as when it was taken ───────────────

    #[test]
    fn a_pass_over_unverified_state_does_not_read_as_routine() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        let Some(Outcome::Simulate { seq, .. }) = app.update(Message::Simulate) else {
            panic!("expected a Simulate");
        };
        app.on_sim(
            seq,
            Ok(BatchSimResult {
                outcome: BatchOutcome::Success,
                gas_used: 1,
                transfers: Vec::new(),
                verified: false, // fell through to raw RPC
                base_fee_per_gas: 1,
                block: 21_000_000,
                // A realistic Mainnet ceiling: these fixtures are all
                // small, so the aggregate check never fires on them.
                block_gas_limit: 45_000_000,
            }),
        );
        let p = app.preflight();
        assert_eq!(
            p,
            Preflight::Passed {
                stale: false,
                verified: false
            }
        );
        assert!(
            p.softens_confirm(),
            "an unverified pass is not a clean pass"
        );
        assert!(p.warning().unwrap().contains("light-client-verified"));
    }

    #[test]
    fn a_pass_goes_stale_on_the_clock() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        let Some(Outcome::Simulate { seq, .. }) = app.update(Message::Simulate) else {
            panic!("expected a Simulate");
        };
        app.on_sim(
            seq,
            Ok(BatchSimResult {
                outcome: BatchOutcome::Success,
                gas_used: 1,
                transfers: Vec::new(),
                verified: true,
                base_fee_per_gas: 1,
                block: 21_000_000,
                // A realistic Mainnet ceiling: these fixtures are all
                // small, so the aggregate check never fires on them.
                block_gas_limit: 45_000_000,
            }),
        );
        assert_eq!(app.preflight(), PASSED_CLEAN, "fresh out of the simulator");

        // Wind the verdict back past the bound.
        app.sim_at = Some(std::time::Instant::now() - PREFLIGHT_STALE_AFTER);
        let p = app.preflight();
        assert_eq!(
            p,
            Preflight::Passed {
                stale: true,
                verified: true
            }
        );
        assert!(p.softens_confirm());
        assert!(p.warning().unwrap().contains("moved on since it ran"));
    }

    // ── 2.6 · a failed fetch is not "no verified ABI" ───────────────────

    /// Pasting a hand-written ABI is a lot of work, and the wrong work, when
    /// the real problem was a light-client hiccup on a verified contract.
    #[test]
    fn a_failed_resolve_is_reported_as_a_failed_resolve() {
        let mut app = safe_app();
        let addr = address!("0x1111111111111111111111111111111111111111");
        let Some(Outcome::ResolveContract { seq, .. }) =
            app.update(Message::AddrChanged(addr.to_string()))
        else {
            panic!("expected a ResolveContract");
        };
        app.on_contract_resolved(seq, Err("light client timed out".into()));

        assert_eq!(app.resolve_error.as_deref(), Some("light client timed out"));
        assert!(
            !app.not_found,
            "a fetch that failed says nothing about whether an ABI exists"
        );
    }

    /// The dedup guard treated the failed state as settled, so re-entering the
    /// same address did nothing at all — the one state where retrying is the
    /// obvious move was the one state that couldn't.
    #[test]
    fn a_failed_resolve_can_be_retried() {
        let mut app = safe_app();
        let addr = address!("0x1111111111111111111111111111111111111111");
        let Some(Outcome::ResolveContract { seq, .. }) =
            app.update(Message::AddrChanged(addr.to_string()))
        else {
            panic!("expected a ResolveContract");
        };
        app.on_contract_resolved(seq, Err("light client timed out".into()));

        let Some(Outcome::ResolveContract {
            seq: seq2, address, ..
        }) = app.update(Message::RetryResolve)
        else {
            panic!("Retry must re-issue the fetch");
        };
        assert_eq!(address, addr);
        assert_ne!(
            seq2, seq,
            "the retired attempt must not answer for this one"
        );
        assert!(app.resolving);
        assert!(app.resolve_error.is_none());
    }

    // ── 2.8 · the batching cap applies however the queue is filled ──────

    /// A Trezor / view-only account used to import six calls, simulate them
    /// green, and only learn at Review that this wallet signs one at a time.
    #[test]
    fn import_respects_the_single_call_cap() {
        let mut app = TxBuilderApp::new(EOA);
        app.set_context(EOA, Chain::Mainnet, false, None, false, true, Vec::new());
        let dead = "0x000000000000000000000000000000000000dEaD";
        app.update(Message::OpenLoad);
        app.update(Message::JsonChanged(format!(
            r#"{{"version":"1.0","chainId":"1","meta":{{"name":"x","txBuilderVersion":"y"}},
                 "transactions":[{{"to":"{dead}","value":"0","data":"0x"}},
                                 {{"to":"{dead}","value":"0","data":"0x"}}]}}"#
        )));
        app.update(Message::ImportJson);

        assert!(app.batch.is_empty(), "the cap has to bite before the queue");
        let e = app.json_error.as_deref().expect("and say why");
        assert!(e.contains("one at a time"), "{e}");
        assert_eq!(
            app.modal,
            Modal::Load,
            "the JSON stays where the user can get it"
        );
    }

    #[test]
    fn replacing_a_non_empty_queue_says_so() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        let had = app.batch.len();
        let dead = "0x000000000000000000000000000000000000dEaD";
        app.json_text = format!(
            r#"{{"version":"1.0","chainId":"1","meta":{{"name":"x","txBuilderVersion":"y"}},
                 "transactions":[{{"to":"{dead}","value":"0","data":"0x"}}]}}"#
        );
        app.update(Message::ImportJson);

        assert_eq!(app.batch.len(), 1);
        let e = app
            .error
            .as_deref()
            .expect("a replaced queue is not undoable");
        assert!(e.contains(&format!("{had} call")), "{e}");
    }

    // ── 2.9 · a watch-only account never reaches a ceremony ─────────────

    #[test]
    fn a_watch_only_account_cannot_open_the_review() {
        let mut app = view_only_app();
        app.batch = vec![sample_batch(&mut app.next_id, app.owner).remove(0)];
        assert!(
            app.update(Message::Review).is_none(),
            "no review may be built for a signer that can't sign"
        );
        let e = app.error.as_deref().expect("and it must say why");
        assert!(e.contains("watch-only"), "{e}");
    }

    #[test]
    fn a_watch_only_account_can_still_compose_and_simulate() {
        let mut app = view_only_app();
        app.batch = vec![sample_batch(&mut app.next_id, app.owner).remove(0)];
        assert!(
            matches!(
                app.update(Message::Simulate),
                Some(Outcome::Simulate { .. })
            ),
            "composing and simulating are useful on their own"
        );
    }

    // ── 2.13 · Esc belongs to the modal while one is open ───────────────

    #[test]
    fn escape_closes_the_json_modal_instead_of_the_app() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        app.update(Message::OpenSave);
        assert_eq!(app.modal, Modal::Save);

        assert!(
            app.update(Message::Escape).is_none(),
            "Esc is consumed by the modal, not bubbled as Close"
        );
        assert_eq!(app.modal, Modal::None);
        assert!(
            app.json_text.is_empty(),
            "and the overlay's contents go with it"
        );

        // With no modal open it steps back to the launcher as before.
        assert!(matches!(app.update(Message::Escape), Some(Outcome::Close)));
    }

    /// `Close` never cleared `modal`, so the flag outlived the view that owned
    /// it and re-entering the Builder landed straight back inside the overlay.
    #[test]
    fn closing_the_modal_actually_clears_it() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        app.update(Message::OpenSave);
        app.update(Message::CloseModal);
        assert_eq!(app.modal, Modal::None);
    }

    // ── 2.7 · a persist that fails has something to roll back to ────────

    #[test]
    fn persisting_templates_carries_the_pre_change_list() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        app.update(Message::SaveTemplate);
        let Some(Outcome::PersistTemplates { list, rollback }) = app.update(Message::SaveTemplate)
        else {
            panic!("expected a PersistTemplates");
        };
        assert_eq!(list.len(), 2);
        assert_eq!(
            rollback.len(),
            1,
            "the coordinator needs the list as it was, to put back on a failed write"
        );
    }

    // ── 2.1 · a broadcast is not an outcome ─────────────────────────────

    #[test]
    fn a_mined_batch_clears_the_queue_and_leaves_its_hash() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        let hash = B256::repeat_byte(0x7A);
        app.on_executed(hash);
        assert!(app.batch.is_empty());
        assert_eq!(app.visible_settled(), Some(&Settled::Executed { hash }));
        assert!(matches!(
            app.update(Message::CopySettledHash),
            Some(Outcome::CopyPlain(_))
        ));
    }

    /// A successful propose used to be indistinguishable from an accidental
    /// dismissal, so the natural response was to propose the batch again.
    #[test]
    fn a_proposed_batch_says_queued_rather_than_done() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        app.on_proposed(7);
        assert!(app.batch.is_empty());
        assert_eq!(app.visible_settled(), Some(&Settled::Proposed { nonce: 7 }));
        assert!(
            app.update(Message::CopySettledHash).is_none(),
            "a proposal has no transaction hash to copy — nothing was sent"
        );
    }

    /// Mainnet USDC — a known contract, so pasting its address resolves the ABI
    /// synchronously (no light-client round-trip).
    fn usdc() -> Address {
        address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
    }

    #[test]
    fn known_address_loads_contract_synchronously_and_still_fetches() {
        let mut app = safe_app();
        let out = app.update(Message::AddrChanged(usdc().to_string()));
        // The curated entry is on screen with no round trip — its names are
        // authoritative and shouldn't wait on the network…
        assert!(app.loaded.is_some());
        assert_eq!(app.loaded.as_ref().unwrap().name, "USDC");
        assert!(!app.resolving, "nothing to wait for — the menu is usable");
        // …and the fetch goes out anyway, because the curated list is a
        // hand-written subset and everything it omits is otherwise unreachable.
        assert!(
            matches!(out, Some(Outcome::ResolveContract { .. })),
            "a curated hit must still fetch bytecode to fill in the rest",
        );
    }

    #[test]
    fn recovered_methods_fill_in_a_curated_contract_without_displacing_it() {
        let mut app = safe_app();
        app.update(Message::AddrChanged(usdc().to_string()));
        let curated = app.loaded.clone().expect("curated USDC");
        let before = curated.methods.len();
        let kept = curated.methods[0].clone();

        // The augmenting fetch lands: one selector the registry already lists
        // (under its declared name) and one it doesn't.
        let extra = AbiMethod {
            // `increaseAllowance` — a real USDC method the curated subset
            // (transfer / approve / transferFrom) leaves out.
            name: "increaseAllowance".into(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            payable: false,
            selector: [0x39, 0x50, 0x93, 0x51],
            signature: "increaseAllowance(address,uint256)".into(),
            provenance: abi::MethodProvenance::SelectorOnly,
            inferred_mutability: None,
        };
        let collision = AbiMethod {
            name: "not_the_declared_name".into(),
            ..extra.clone()
        };
        let recovered = LoadedContract {
            methods: vec![
                AbiMethod {
                    selector: kept.selector,
                    ..collision
                },
                extra,
            ],
            source: AbiSource::Bytecode,
            ..curated.clone()
        };

        let merged = abi::merge_recovered(curated, recovered);
        assert_eq!(
            merged.methods.len(),
            before + 1,
            "only the genuinely new selector is added",
        );
        assert_eq!(
            merged.methods[0].name, kept.name,
            "the declared name survives a selector collision",
        );
        assert!(
            merged.methods.iter().any(|m| m.name == "increaseAllowance"),
            "and the method the curated subset omitted is now reachable",
        );
        assert_eq!(
            merged.source,
            AbiSource::Known,
            "still the curated contract"
        );
    }

    #[test]
    fn unknown_address_bubbles_resolve() {
        let mut app = safe_app();
        let addr = address!("0x00000000000000000000000000000000C0FFEE00");
        let out = app.update(Message::AddrChanged(addr.to_string()));
        match out {
            Some(Outcome::ResolveContract { address, .. }) => assert_eq!(address, addr),
            other => panic!("expected ResolveContract, got {other:?}"),
        }
        assert!(app.resolving);
    }

    #[test]
    fn add_to_batch_queues_a_call_and_resets_args() {
        let mut app = safe_app();
        app.update(Message::AddrChanged(usdc().to_string())); // USDC, method 0 = transfer
        let to = address!("0x000000000000000000000000000000000000dEaD");
        app.update(Message::ArgChanged(0, to.to_string()));
        app.update(Message::ArgChanged(1, "1000000".into()));
        assert!(app.compose_valid());
        app.update(Message::AddToBatch);
        assert_eq!(app.batch.len(), 1);
        // args reset for rapid batching, contract still loaded
        assert!(app.args.iter().all(|a| a.is_empty()));
        assert!(app.loaded.is_some());
    }

    #[test]
    fn eoa_without_7702_caps_batch_at_one() {
        let mut app = TxBuilderApp::new(EOA);
        app.set_context(EOA, Chain::Mainnet, false, None, false, true, Vec::new()); // EOA, cannot delegate
        app.update(Message::AddrChanged(usdc().to_string()));
        let to = address!("0x000000000000000000000000000000000000dEaD");
        app.update(Message::ArgChanged(0, to.to_string()));
        app.update(Message::ArgChanged(1, "1".into()));
        app.update(Message::AddToBatch);
        assert_eq!(app.batch.len(), 1);
        // second add is blocked with an explanatory error
        app.update(Message::ArgChanged(0, to.to_string()));
        app.update(Message::ArgChanged(1, "2".into()));
        app.update(Message::AddToBatch);
        assert_eq!(app.batch.len(), 1, "non-7702 EOA batch stays capped at 1");
        assert!(app.error.is_some());
    }

    #[test]
    fn eoa_with_7702_can_batch_multiple() {
        let mut app = TxBuilderApp::new(EOA);
        app.set_context(EOA, Chain::Mainnet, false, None, true, true, Vec::new()); // EOA, Local/Ledger
        let to = address!("0x000000000000000000000000000000000000dEaD");
        app.update(Message::AddrChanged(usdc().to_string()));
        app.update(Message::ArgChanged(0, to.to_string()));
        app.update(Message::ArgChanged(1, "1".into()));
        app.update(Message::AddToBatch);
        // a second call is now allowed (EIP-7702 atomic batch)
        app.update(Message::ArgChanged(0, to.to_string()));
        app.update(Message::ArgChanged(1, "2".into()));
        app.update(Message::AddToBatch);
        assert_eq!(app.batch.len(), 2, "7702-capable EOA batches N calls");
        assert!(app.error.is_none());
    }

    #[test]
    fn auto_revoke_wraps_effective_calls_at_both_ends() {
        use crate::txbuilder::abi;
        use crate::txbuilder::encode::build_contract_call;
        let usdc = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
        let spender = address!("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2");
        let c = abi::known_by_address(Chain::Mainnet, usdc).unwrap();
        let approve = c.methods.iter().find(|m| m.name == "approve").unwrap();
        let approve_call = build_contract_call(
            1,
            usdc,
            "USDC",
            approve,
            &[spender.to_string(), "5000".into()],
            "0",
        )
        .unwrap();

        let mut app = safe_app(); // is_safe → can_batch
        app.batch = vec![approve_call];
        app.next_id = 2;

        // Off: unchanged.
        assert_eq!(app.effective_calls().len(), 1);
        // On: opened at zero, then the approve, then closed at zero. The
        // opening reset is what keeps a zero-first token from reverting the
        // whole atomic batch on an allowance left standing by some earlier tx.
        app.auto_revoke = true;
        let eff = app.effective_calls();
        assert_eq!(eff.len(), 3);
        for i in [0, 2] {
            assert_eq!(eff[i].to, usdc);
            assert_eq!(U256::from_be_slice(&eff[i].data[36..68]), U256::ZERO);
        }
        assert_eq!(
            U256::from_be_slice(&eff[1].data[36..68]),
            U256::from(5000u64),
            "the user's own approve keeps its amount, in the middle",
        );
        // The queue itself is untouched — the wrap is derived, never stored.
        assert_eq!(app.batch.len(), 1);
        // A non-batching EOA never wraps (nothing to batch into). Switching
        // identity drops the queue by design, so re-compose it as the EOA.
        app.set_context(EOA, Chain::Mainnet, false, None, false, true, Vec::new());
        assert!(app.batch.is_empty(), "the identity switch drops the batch");
        app.batch = vec![eff[1].clone()];
        assert_eq!(app.effective_calls().len(), 1, "no batching → no wrap");
    }

    /// The revert strip and the review note both index the *effective* calls,
    /// while the queue cards are numbered over `batch`. With flash approval on
    /// those are different spaces, and printing the raw index pointed at calls
    /// the user cannot see, inspect or remove.
    #[test]
    fn a_failing_step_is_named_in_the_queues_own_numbering() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        let queued = app.batch.len();
        assert!(queued >= 2, "sample batch is worth indexing into");

        // No wrap: effective index == queue index.
        assert_eq!(app.describe_step(0), "call #1");
        assert_eq!(app.describe_step(queued - 1), format!("call #{queued}"));

        app.auto_revoke = true;
        let opens = flash_approval::prepend_count(&app.batch);
        assert!(opens > 0, "the sample batch approves something");
        // Shifted by the prepends, and the synthesized calls are named for
        // what they are rather than given a card number that doesn't exist.
        assert!(app.describe_step(0).contains("before the batch"));
        assert_eq!(app.describe_step(opens), "call #1");
        assert_eq!(
            app.describe_step(opens + queued - 1),
            format!("call #{queued}")
        );
        assert!(
            app.describe_step(opens + queued)
                .contains("after the batch"),
            "got {}",
            app.describe_step(opens + queued)
        );
    }

    #[test]
    fn reorder_and_remove() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        assert_eq!(app.batch.len(), 2);
        let first = app.batch[0].id;
        let second = app.batch[1].id;
        app.update(Message::MoveDown(first));
        assert_eq!(app.batch[0].id, second);
        app.update(Message::RemoveCall(second));
        assert_eq!(app.batch.len(), 1);
        assert_eq!(app.batch[0].id, first);
    }

    #[test]
    fn simulate_bubbles_and_review_bubbles() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        match app.update(Message::Simulate) {
            Some(Outcome::Simulate { calls, .. }) => assert_eq!(calls.len(), 2),
            other => panic!("expected Simulate, got {other:?}"),
        }
        assert!(app.sim_busy);
        match app.update(Message::Review) {
            Some(Outcome::Review {
                calls, preflight, ..
            }) => {
                assert_eq!(calls.len(), 2);
                // Simulate was fired but hasn't landed — the review must not
                // present an unsimulated batch as if it had passed.
                assert_eq!(preflight, Preflight::Missing);
            }
            other => panic!("expected Review, got {other:?}"),
        }
    }

    #[test]
    fn review_carries_a_failing_preflight_across_to_the_overlay() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        app.on_sim(
            app.sim_seq,
            Ok(BatchSimResult {
                outcome: BatchOutcome::Revert {
                    step: 1,
                    reason: "ERC20: transfer amount exceeds balance".into(),
                },
                gas_used: 41_000,
                transfers: Vec::new(),
                verified: true,
                base_fee_per_gas: 1,
                block: 21_000_000,
                // A realistic Mainnet ceiling: these fixtures are all
                // small, so the aggregate check never fires on them.
                block_gas_limit: 45_000_000,
            }),
        );
        let Some(Outcome::Review { preflight, .. }) = app.update(Message::Review) else {
            panic!("expected Review");
        };
        assert_eq!(
            preflight,
            Preflight::Fails {
                at: "call #2".to_string(),
                reason: "ERC20: transfer amount exceeds balance".into(),
            },
        );
        assert!(preflight.softens_confirm(), "the button must say so");
        let w = preflight.warning().expect("a warning line");
        // Steps are 0-based internally and 1-based on screen, matching the cards.
        assert!(w.contains("call #2"), "{w}");
        assert!(w.contains("exceeds balance"), "{w}");
    }

    #[test]
    fn review_reports_a_passing_preflight_without_softening() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        app.on_sim(
            app.sim_seq,
            Ok(BatchSimResult {
                outcome: BatchOutcome::Success,
                gas_used: 41_000,
                transfers: Vec::new(),
                verified: true,
                base_fee_per_gas: 1,
                block: 21_000_000,
                // A realistic Mainnet ceiling: these fixtures are all
                // small, so the aggregate check never fires on them.
                block_gas_limit: 45_000_000,
            }),
        );
        let Some(Outcome::Review { preflight, .. }) = app.update(Message::Review) else {
            panic!("expected Review");
        };
        assert_eq!(preflight, PASSED_CLEAN);
        assert!(!preflight.softens_confirm());
        assert!(preflight.warning().is_none(), "nothing to warn about");
    }

    #[test]
    fn editing_the_batch_downgrades_a_passing_preflight_to_missing() {
        // The sim describes the queue it ran against. Once that queue changes,
        // an unsimulated batch must not inherit the old verdict's clean button.
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        app.on_sim(
            app.sim_seq,
            Ok(BatchSimResult {
                outcome: BatchOutcome::Success,
                gas_used: 41_000,
                transfers: Vec::new(),
                verified: true,
                base_fee_per_gas: 1,
                block: 21_000_000,
                // A realistic Mainnet ceiling: these fixtures are all
                // small, so the aggregate check never fires on them.
                block_gas_limit: 45_000_000,
            }),
        );
        let removed = app.batch[0].id;
        app.update(Message::RemoveCall(removed));
        let Some(Outcome::Review { preflight, .. }) = app.update(Message::Review) else {
            panic!("expected Review");
        };
        assert_eq!(preflight, Preflight::Missing);
        assert!(preflight.softens_confirm());
    }

    /// A resolve answer for a plain (non-proxy) address: the code is the
    /// target's own and every read on the way was verified.
    fn plain_code(target: Address, code: &[u8]) -> ResolvedCode {
        ResolvedCode {
            nothing_deployed: false,
            code: Bytes::copy_from_slice(code),
            implementation: target,
            all_verified: true,
            code_verified: true,
            beacon: false,
        }
    }

    #[test]
    fn stale_resolve_is_dropped() {
        let mut app = safe_app();
        let a = address!("0x00000000000000000000000000000000C0FFEE00");
        app.update(Message::AddrChanged(a.to_string()));
        let stale_seq = app.resolve_seq;
        // user types a different address before the first resolve returns
        let b = address!("0x00000000000000000000000000000000BEEF0000");
        app.update(Message::AddrChanged(b.to_string()));
        // the stale answer must not clobber the new target
        app.on_contract_resolved(stale_seq, Ok(plain_code(a, &[])));
        assert!(!app.not_found, "stale resolve result ignored");
        assert_eq!(app.resolve_target, Some(b));
    }

    #[test]
    fn a_curated_hit_retires_an_in_flight_resolve() {
        let mut app = eoa_app();
        let unknown = address!("0x00000000000000000000000000000000C0FFEE00");
        app.update(Message::AddrChanged(unknown.to_string()));
        let stale_seq = app.resolve_seq;
        assert!(app.resolving);

        // The user pastes a curated address before the fetch returns. That
        // resolves synchronously from the registry and issues no request of its
        // own, so it has to retire the outstanding sequence explicitly.
        app.update(Message::AddrChanged(usdc().to_string()));
        let curated_methods = app.loaded.as_ref().expect("USDC loaded").methods.len();

        // The stale answer carries recoverable selectors. Applied, it would
        // hand USDC the other contract's method list while every composed call
        // still went to USDC.
        let code = crate::decode::bytecode::tiny_transfer_runtime();
        app.on_contract_resolved(stale_seq, Ok(plain_code(unknown, &code)));

        let c = app.loaded.as_ref().expect("still USDC");
        assert_eq!(c.address, usdc(), "call target unchanged");
        assert_eq!(c.source, AbiSource::Known, "curated ABI not displaced");
        assert_eq!(c.methods.len(), curated_methods);
    }

    #[test]
    fn a_pasted_abi_retires_an_in_flight_resolve() {
        let mut app = eoa_app();
        let addr = address!("0x00000000000000000000000000000000C0FFEE00");
        app.update(Message::AddrChanged(addr.to_string()));
        let stale_seq = app.resolve_seq;

        app.update(Message::ShowAbiPaste);
        app.update(Message::AbiPasteChanged(
            r#"[{"type":"function","name":"stake","stateMutability":"nonpayable",
                 "inputs":[],"outputs":[]}]"#
                .into(),
        ));
        app.update(Message::LoadPastedAbi);
        assert_eq!(app.loaded.as_ref().unwrap().source, AbiSource::Pasted);

        // A pasted ABI is authoritative for the address; a bytecode answer that
        // was already in flight must not silently replace it.
        let code = crate::decode::bytecode::tiny_transfer_runtime();
        app.on_contract_resolved(stale_seq, Ok(plain_code(addr, &code)));

        let c = app.loaded.as_ref().expect("still the pasted ABI");
        assert_eq!(c.source, AbiSource::Pasted, "bytecode must not displace it");
        assert!(c.methods.iter().any(|m| m.name == "stake"));
    }

    #[test]
    fn proxy_load_keeps_the_proxy_as_the_call_target() {
        let mut app = safe_app();
        let proxy = address!("0x00000000000000000000000000000000C0FFEE00");
        let impl_addr = address!("0x00000000000000000000000000000000BEEF0000");
        app.update(Message::AddrChanged(proxy.to_string()));
        app.on_contract_resolved(
            app.resolve_seq,
            Ok(ResolvedCode {
                nothing_deployed: false,
                code: Bytes::from(crate::decode::bytecode::tiny_transfer_runtime()),
                implementation: impl_addr,
                all_verified: true,
                code_verified: true,
                beacon: false,
            }),
        );
        let loaded = app.loaded.as_ref().expect("proxy ABI loaded");
        // Methods came from the implementation; the call still goes to the proxy.
        assert_eq!(loaded.address, proxy);
        assert_eq!(loaded.proxy_impl, Some(impl_addr));
        assert!(!app.proxy_unverified);
    }

    #[test]
    fn a_mixed_case_address_failing_its_checksum_never_resolves() {
        let mut app = safe_app();
        // USDC with the leading `A` lowercased: parses as hex, fails EIP-55.
        let out = app.update(Message::AddrChanged(
            "0xa0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".into(),
        ));
        assert!(out.is_none(), "no fetch may be issued for a bad checksum");
        assert!(app.loaded.is_none());
        assert!(app.resolve_target.is_none());
        let err = app.addr_error.as_deref().expect("refusal must be visible");
        assert!(err.contains("EIP-55"), "unexpected reason: {err}");
    }

    #[test]
    fn a_half_typed_address_is_not_corrected_mid_word() {
        let mut app = safe_app();
        app.update(Message::AddrChanged("0xA0b8699".into()));
        assert!(
            app.addr_error.is_none(),
            "every prefix of a valid address is invalid; do not nag"
        );
        // Full length and still not hex — now it is a finished, wrong answer.
        app.update(Message::AddrChanged(format!("0x{}", "z".repeat(40))));
        assert!(app.addr_error.is_some());
        // And a good address clears it again.
        app.update(Message::AddrChanged(
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".into(),
        ));
        assert!(app.addr_error.is_none());
    }

    #[test]
    fn unverified_proxy_slot_raises_the_caution() {
        let mut app = safe_app();
        let proxy = address!("0x00000000000000000000000000000000C0FFEE00");
        app.update(Message::AddrChanged(proxy.to_string()));
        // The walker refused to follow the pointer, so it hands back the
        // proxy's own (selector-less) code with the flag cleared.
        app.on_contract_resolved(
            app.resolve_seq,
            Ok(ResolvedCode {
                nothing_deployed: false,
                code: Bytes::new(),
                implementation: proxy,
                all_verified: false,
                code_verified: true,
                beacon: false,
            }),
        );
        assert!(app.not_found);
        assert!(
            app.proxy_unverified,
            "user must be told why the ABI came back empty"
        );
    }

    #[test]
    fn pasted_abi_retires_the_proxy_caution() {
        let mut app = safe_app();
        let proxy = address!("0x00000000000000000000000000000000C0FFEE00");
        app.update(Message::AddrChanged(proxy.to_string()));
        app.on_contract_resolved(
            app.resolve_seq,
            Ok(ResolvedCode {
                nothing_deployed: false,
                code: Bytes::new(),
                implementation: proxy,
                all_verified: false,
                code_verified: true,
                beacon: false,
            }),
        );
        assert!(app.proxy_unverified);
        // Pasting the implementation's ABI is authoritative — the caution goes.
        app.update(Message::AbiPasteChanged(
            r#"[{"type":"function","name":"transfer","stateMutability":"nonpayable",
                "inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}]}]"#
                .into(),
        ));
        app.update(Message::LoadPastedAbi);
        assert!(app.loaded.is_some(), "pasted ABI loaded");
        assert!(!app.proxy_unverified);
    }

    #[test]
    fn retyping_the_address_clears_the_proxy_caution() {
        let mut app = safe_app();
        let a = address!("0x00000000000000000000000000000000C0FFEE00");
        app.update(Message::AddrChanged(a.to_string()));
        app.on_contract_resolved(
            app.resolve_seq,
            Ok(ResolvedCode {
                nothing_deployed: false,
                code: Bytes::new(),
                implementation: a,
                all_verified: false,
                code_verified: true,
                beacon: false,
            }),
        );
        assert!(app.proxy_unverified);
        let b = address!("0x00000000000000000000000000000000BEEF0000");
        app.update(Message::AddrChanged(b.to_string()));
        assert!(
            !app.proxy_unverified,
            "caution must not follow the user to a different address"
        );
    }

    // ── Network switcher ─────────────────────────────────────────────────

    fn eoa_app() -> TxBuilderApp {
        let mut app = TxBuilderApp::new(EOA);
        // EOA, 7702-capable, with one enabled custom network (Sepolia).
        app.set_context(
            EOA,
            Chain::Mainnet,
            false,
            None,
            true,
            true,
            vec![(11155111, "Sepolia".into())],
        );
        app
    }

    #[test]
    fn eoa_can_switch_builtin_network() {
        let mut app = eoa_app();
        assert_eq!(app.selected_net(), NetworkId::Builtin(Chain::Mainnet));
        app.update(Message::SetNetwork(NetworkId::Builtin(Chain::Base)));
        assert_eq!(app.selected_net(), NetworkId::Builtin(Chain::Base));
        assert!(app.batch_layout(), "built-in nets keep the batch layout");
    }

    #[test]
    fn switching_builtin_networks_drops_the_batch() {
        let mut app = eoa_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        app.expanded = Some(app.batch[0].id);
        assert_eq!(app.batch.len(), 2);

        app.update(Message::SetNetwork(NetworkId::Builtin(Chain::Base)));

        // A QueuedCall carries only `to`, and the same contract sits at a
        // different address on Base — replaying these would target whatever
        // happens to occupy those addresses there.
        assert!(
            app.batch.is_empty(),
            "queue must not survive a chain change"
        );
        assert!(app.expanded.is_none());
        let note = app.error.as_deref().unwrap_or_default();
        assert!(
            note.contains("Ethereum Mainnet"),
            "notice names the origin chain: {note}"
        );
        assert!(
            note.contains("Base"),
            "notice names the destination chain: {note}"
        );
    }

    #[test]
    fn safe_pinning_a_different_chain_drops_the_batch() {
        let mut app = eoa_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);

        // Selecting a Safe re-pins the network on the next context refresh —
        // the same re-homing as an explicit switch, and just as unsafe to let
        // Mainnet-composed calls ride through.
        app.set_context(
            SAFE,
            Chain::Base,
            true,
            Some("1.4.1".into()),
            false,
            true,
            Vec::new(),
        );

        assert_eq!(app.selected_net(), NetworkId::Builtin(Chain::Base));
        assert!(
            app.batch.is_empty(),
            "an implicit re-pin drops the queue too"
        );
    }

    /// The gap the chain-only reset left: an EOA→Safe flip on the *same*
    /// chain never touched the network, so the queue rode through and
    /// `build_txbuilder_request` re-shaped the same calls with a different
    /// `from` — spending the Safe's balances and allowances instead.
    #[test]
    fn switching_identity_on_the_same_chain_drops_the_batch() {
        let mut app = eoa_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        assert!(!app.batch.is_empty());

        app.set_context(
            SAFE,
            Chain::Mainnet, // same chain — the network reset never fires
            true,
            Some("1.4.1".into()),
            false,
            true,
            Vec::new(),
        );

        assert_eq!(
            app.selected_net(),
            NetworkId::Builtin(Chain::Mainnet),
            "the network did not move"
        );
        assert!(app.batch.is_empty(), "the identity did, so the queue drops");
        let e = app.error.clone().expect("the drop is explained");
        assert!(e.contains("different account's balances"), "{e}");
    }

    /// Selecting a Safe on another chain moves both axes at once. The queue
    /// still drops, and the notice explaining it must survive the network
    /// re-pin that follows — that reset finds an empty queue and would
    /// otherwise clear the banner on its way past.
    #[test]
    fn an_identity_and_network_switch_together_still_explains_the_drop() {
        let mut app = eoa_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        app.set_context(
            SAFE,
            Chain::Base,
            true,
            Some("1.4.1".into()),
            false,
            true,
            Vec::new(),
        );
        assert_eq!(app.selected_net(), NetworkId::Builtin(Chain::Base));
        assert!(app.batch.is_empty());
        let e = app.error.clone().expect("the drop must still be explained");
        assert!(e.contains("different account's balances"), "{e}");
    }

    /// Safe A → Safe B never changes chain at all.
    #[test]
    fn switching_between_safes_drops_the_batch() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        let other = address!("0xB0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0");
        app.set_context(
            other,
            Chain::Mainnet,
            true,
            Some("1.4.1".into()),
            false,
            true,
            Vec::new(),
        );
        assert!(app.batch.is_empty());
        assert_eq!(
            app.owner, other,
            "the identity chip follows the active Safe"
        );
    }

    /// A refresh that changes nothing must not clear a queue the user is
    /// building — `set_context` runs before every message.
    #[test]
    fn an_unchanged_context_refresh_keeps_the_batch() {
        let mut app = eoa_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        let n = app.batch.len();
        for _ in 0..3 {
            app.set_context(
                EOA,
                Chain::Mainnet,
                false,
                None,
                true,
                true,
                vec![(11155111, "Sepolia".into())],
            );
        }
        assert_eq!(app.batch.len(), n);
        assert!(app.error.is_none());
    }

    /// `on_sim` was the one async callback with no staleness check, so a
    /// verdict for the previous batch became this batch's — and `preflight()`
    /// is what decides whether Confirm reads "Sign & execute now".
    #[test]
    fn a_superseded_simulation_result_is_dropped() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);

        // Dispatch a run and capture its sequence.
        let Some(Outcome::Simulate { seq, .. }) = app.update(Message::Simulate) else {
            panic!("simulate should bubble");
        };
        assert!(app.sim_busy);

        // The user edits the queue while it is in flight.
        let victim = app.batch[0].id;
        app.update(Message::RemoveCall(victim));

        // The old run lands with a clean bill of health.
        app.on_sim(
            seq,
            Ok(BatchSimResult {
                outcome: BatchOutcome::Success,
                gas_used: 41_000,
                base_fee_per_gas: 0,
                transfers: Vec::new(),
                verified: true,
                block: 21_000_000,
                // A realistic Mainnet ceiling: these fixtures are all
                // small, so the aggregate check never fires on them.
                block_gas_limit: 45_000_000,
            }),
        );

        assert!(app.sim.is_none(), "a stale verdict must not be adopted");
        assert_eq!(
            app.preflight(),
            Preflight::Missing,
            "the edited batch has no verdict, and the review must say so"
        );
    }

    #[test]
    fn a_current_simulation_result_is_kept() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        let Some(Outcome::Simulate { seq, .. }) = app.update(Message::Simulate) else {
            panic!("simulate should bubble");
        };
        app.on_sim(
            seq,
            Ok(BatchSimResult {
                outcome: BatchOutcome::Success,
                gas_used: 41_000,
                base_fee_per_gas: 0,
                transfers: Vec::new(),
                verified: true,
                block: 21_000_000,
                // A realistic Mainnet ceiling: these fixtures are all
                // small, so the aggregate check never fires on them.
                block_gas_limit: 45_000_000,
            }),
        );
        assert_eq!(app.preflight(), PASSED_CLEAN);
        assert!(!app.sim_busy);
    }

    #[test]
    fn switching_networks_with_an_empty_queue_retires_the_old_banner() {
        let mut app = eoa_app();
        app.error = Some("atomic batching needs a software key or a Ledger".into());
        app.update(Message::SetNetwork(NetworkId::Builtin(Chain::Base)));
        assert!(
            app.error.is_none(),
            "a banner describing the old network doesn't outlive it"
        );
    }

    #[test]
    fn safe_pins_network_and_ignores_switch() {
        let mut app = TxBuilderApp::new(SAFE);
        app.set_context(
            SAFE,
            Chain::Base,
            true,
            Some("1.4.1".into()),
            false,
            true,
            Vec::new(),
        );
        assert_eq!(app.selected_net(), NetworkId::Builtin(Chain::Base));
        // A Safe pins the network — the switcher is inert.
        app.update(Message::ToggleNetworkMenu);
        assert!(!app.net_menu_open, "Safe never opens the switcher");
        app.update(Message::SetNetwork(NetworkId::Builtin(Chain::Optimism)));
        // set_context runs before every message and re-pins to the Safe's chain.
        app.set_context(
            SAFE,
            Chain::Base,
            true,
            Some("1.4.1".into()),
            false,
            true,
            Vec::new(),
        );
        assert_eq!(app.selected_net(), NetworkId::Builtin(Chain::Base));
    }

    #[test]
    fn custom_network_hides_batch_and_single_sends() {
        let mut app = eoa_app();
        app.update(Message::SetNetwork(NetworkId::Custom(11155111)));
        assert!(app.is_custom());
        assert!(!app.batch_layout(), "custom nets drop the batch UI");
        // Compose a raw call and "Send transaction" → a one-call review, no batch.
        app.update(Message::SetMode(Mode::Raw));
        let to = address!("0x000000000000000000000000000000000000dEaD");
        app.update(Message::RawToChanged(to.to_string()));
        match app.update(Message::SendSingle) {
            Some(Outcome::Review {
                calls, preflight, ..
            }) => {
                assert_eq!(calls.len(), 1);
                assert_eq!(
                    preflight,
                    Preflight::Unsupported,
                    "no simulator on a custom net"
                );
            }
            other => panic!("expected single-call Review, got {other:?}"),
        }
        assert!(app.batch.is_empty(), "single send never touches the batch");
    }

    #[test]
    fn a_paste_over_the_read_limit_never_reaches_the_box() {
        let mut app = safe_app();
        app.update(Message::OpenLoad);
        let huge = "a".repeat(bundle::MAX_BUNDLE_BYTES + 1);
        app.update(Message::JsonChanged(huge));
        assert!(app.json_text.is_empty(), "the widget was never handed it");
        assert!(app.json_error.is_some());
        assert_eq!(
            app.modal,
            Modal::Load,
            "the user still needs somewhere to put the file"
        );
    }

    /// N identical queued calls, for the shape-derived caveat tests.
    fn n_calls(n: u64) -> Vec<QueuedCall> {
        (0..n)
            .map(|i| QueuedCall {
                id: i,
                to: Address::repeat_byte(0xC1),
                value: U256::ZERO,
                data: Bytes::from(vec![0x01]),
                title: "t".into(),
                detail: "d".into(),
                signature: None,
                decoded_args: Vec::new(),
            })
            .collect()
    }

    /// `approve(spender, amount)` calldata.
    fn approve_calldata(spender: Address, amount: u64) -> Vec<u8> {
        let mut d = vec![0x09, 0x5e, 0xa7, 0xb3];
        d.extend_from_slice(
            alloy::primitives::B256::left_padding_from(spender.as_slice()).as_slice(),
        );
        d.extend_from_slice(&U256::from(amount).to_be_bytes::<32>());
        d
    }

    #[test]
    fn an_address_with_no_code_says_so_and_keeps_saying_it() {
        // The wrong-chain paste. Every downstream signal reads as success: the
        // ABI pastes fine, a call to a code-less account does not revert, and
        // the receipt comes back status 1 with the ETH gone.
        let mut app = safe_app();
        let addr = address!("0x00000000000000000000000000000000C0FFEE00");
        app.update(Message::AddrChanged(addr.to_string()));
        app.on_contract_resolved(
            app.resolve_seq,
            Ok(ResolvedCode {
                code: Bytes::new(),
                implementation: addr,
                all_verified: true,
                code_verified: true,
                beacon: false,
                nothing_deployed: true,
            }),
        );
        assert!(
            app.nothing_deployed,
            "the emptiness is recorded, not dropped"
        );

        // Pasting an ABI answers "what does it expose", not "is anything
        // there" — so the warning has to survive it.
        app.update(Message::ShowAbiPaste);
        app.update(Message::AbiPasteChanged(
            r#"[{"type":"function","name":"deposit","inputs":[],"stateMutability":"payable"}]"#
                .into(),
        ));
        app.update(Message::LoadPastedAbi);
        assert!(app.loaded.is_some(), "the pasted ABI loads");
        assert!(
            app.nothing_deployed,
            "and the address still has no contract behind it",
        );

        // A different address clears it.
        app.update(Message::AddrChanged(usdc().to_string()));
        assert!(!app.nothing_deployed);
    }

    #[test]
    fn the_raw_tab_asks_whether_anything_is_deployed() {
        // The Raw tab resolves nothing, so this probe is its only chance to
        // learn that the address holds no contract.
        let mut app = safe_app();
        let addr = address!("0x00000000000000000000000000000000C0FFEE00");
        let out = app.update(Message::RawToChanged(addr.to_string()));
        let Some(Outcome::ProbeCode { seq, address, .. }) = out else {
            panic!("a complete address must be probed, got {out:?}");
        };
        assert_eq!(address, addr);

        app.on_code_probed(seq, addr, Ok(false));
        assert!(app.raw_nothing_deployed, "empty account is reported");

        // A contract there says nothing.
        app.on_code_probed(seq, addr, Ok(true));
        assert!(!app.raw_nothing_deployed);
    }

    #[test]
    fn a_failed_or_stale_code_probe_never_raises_the_warning() {
        let mut app = safe_app();
        let addr = address!("0x00000000000000000000000000000000C0FFEE00");
        let Some(Outcome::ProbeCode { seq, .. }) =
            app.update(Message::RawToChanged(addr.to_string()))
        else {
            panic!("expected a probe");
        };

        // Not being able to ask is not evidence of an empty account — this
        // warning must never fire on an RPC hiccup.
        app.on_code_probed(seq, addr, Err("connection reset".into()));
        assert!(!app.raw_nothing_deployed);

        // And a reply for an address the user has since retyped lands nowhere.
        let other = address!("0x00000000000000000000000000000000C0FFEE11");
        app.update(Message::RawToChanged(other.to_string()));
        app.on_code_probed(seq, addr, Ok(false));
        assert!(
            !app.raw_nothing_deployed,
            "a superseded probe must not caption the new address",
        );
    }

    #[test]
    fn a_custom_network_composer_still_asks_about_code() {
        // No registry and no bytecode tier there, so this box is the whole
        // answer — and "is anything deployed" is still answerable over the
        // configured RPC.
        let mut app = safe_app();
        app.net = NetworkId::Custom(31337);
        let addr = address!("0x00000000000000000000000000000000C0FFEE00");
        let out = app.update(Message::AddrChanged(addr.to_string()));
        assert!(app.not_found, "still prompts for a pasted ABI");
        let Some(Outcome::ProbeCode { seq, address, net }) = out else {
            panic!("expected a code probe, got {out:?}");
        };
        assert_eq!(address, addr);
        assert_eq!(net, NetworkId::Custom(31337));
        app.on_code_probed(seq, addr, Ok(false));
        assert!(app.nothing_deployed);
    }

    #[test]
    fn an_unrecovered_parameter_list_is_not_reported_as_no_parameters() {
        use abi::MethodProvenance as P;
        // A declaration can say "takes nothing"; evmole returning an empty
        // vec cannot — it returns one both for a zero-argument method and for
        // a function whose body it could not reach.
        assert!(P::Declared.declares_argument_list());
        assert!(P::Matched.declares_argument_list());
        assert!(
            P::Ambiguous {
                alternatives: vec!["a()".into()]
            }
            .declares_argument_list(),
            "4byte supplied the types even though the name is ambiguous",
        );
        assert!(!P::SelectorOnly.declares_argument_list());
        assert!(
            !P::Mismatched {
                claimed: vec!["a()".into()]
            }
            .declares_argument_list(),
        );
        // And the caution now keys on what was actually recovered, not on the
        // label. Empty is the sharp case — a bare 4-byte call — and gets said
        // so; a recovered list is milder and must not carry the same alarm, or
        // the alarm stops being read.
        let bare = AbiMethod {
            name: "0x1e83409a".into(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            payable: false,
            selector: [0x1e, 0x83, 0x40, 0x9a],
            signature: "0x1e83409a()".into(),
            provenance: P::SelectorOnly,
            inferred_mutability: None,
        };
        let c = bare.caution().expect("the bare-selector case warns");
        assert!(c.contains("4-byte"), "{c}");
        assert!(c.contains("Paste the ABI"), "it names the remedy: {c}");

        let typed = AbiMethod {
            inputs: vec![abi::AbiParam {
                name: String::new(),
                ty: alloy::dyn_abi::DynSolType::Address,
                ty_str: "address".into(),
            }],
            ..bare.clone()
        };
        let c = typed.caution().expect("still worth a note");
        assert!(!c.contains("4-byte"), "but not the same alarm: {c}");

        // A declared ABI stays silent.
        assert!(
            AbiMethod {
                provenance: P::Declared,
                ..bare
            }
            .caution()
            .is_none(),
        );
    }

    #[test]
    fn a_settled_outcome_is_hidden_off_the_account_it_happened_on() {
        // The resets clear the queue and not the strip, so an unconfirmed
        // broadcast used to follow the user to a different Safe — where
        // "may still be pending, don't rebuild this batch" is advice for
        // someone else's account.
        let mut app = safe_app();
        let hash = alloy::primitives::B256::repeat_byte(0x7A);
        app.on_broadcast_unsuccessful(hash, &BatchFate::Unknown { reason: "t".into() });
        assert_eq!(
            app.visible_settled(),
            Some(&Settled::Unconfirmed { hash }),
            "visible on the account that broadcast it",
        );

        let was = app.owner;
        app.owner = EOA;
        app.on_identity_reset(was, EOA);
        assert_eq!(app.visible_settled(), None, "and not on another account");

        // Bound, not destroyed: that hash is the only way to find out whether
        // rebuilding the batch would run it twice, so switching back has to
        // bring it back rather than having thrown it away.
        app.owner = was;
        assert_eq!(
            app.visible_settled(),
            Some(&Settled::Unconfirmed { hash }),
            "switching back restores it intact",
        );
    }

    #[test]
    fn a_settled_outcome_is_hidden_off_the_network_it_happened_on() {
        let mut app = safe_app();
        let hash = alloy::primitives::B256::repeat_byte(0x7A);
        app.on_executed(hash);
        assert!(app.visible_settled().is_some());

        let was = app.net;
        app.net = NetworkId::Builtin(Chain::Base);
        app.on_network_reset(was);
        assert_eq!(
            app.visible_settled(),
            None,
            "a Mainnet hash is not a Base hash",
        );
        app.net = was;
        assert!(app.visible_settled().is_some(), "and comes back");
    }

    #[test]
    fn copying_the_settled_hash_respects_the_active_context() {
        // The copy button reads the same record the strip does — otherwise a
        // hidden outcome could still be copied out under the wrong caption.
        let mut app = safe_app();
        let hash = alloy::primitives::B256::repeat_byte(0x7A);
        app.on_executed(hash);
        assert!(matches!(
            app.update(Message::CopySettledHash),
            Some(Outcome::CopyPlain(_)),
        ));

        let was = app.owner;
        app.owner = EOA;
        app.on_identity_reset(was, EOA);
        assert!(
            app.update(Message::CopySettledHash).is_none(),
            "nothing to copy while the outcome belongs to another account",
        );
    }

    #[test]
    fn flash_approval_cannot_push_the_transaction_past_the_queue_ceiling() {
        // The cap was enforced on what the user queues and nowhere on what
        // actually gets simulated, packed and signed. A zero-reset before and
        // after each approval nearly triples the list.
        let mut app = safe_app();
        app.batch = (0..MAX_BATCH_CALLS as u64)
            .map(|i| QueuedCall {
                id: i,
                to: Address::repeat_byte(0xC1),
                value: U256::ZERO,
                // A distinct spender per call, so each is its own
                // (token, spender) pair and earns its own pair of resets.
                data: Bytes::from(approve_calldata(Address::repeat_byte(i as u8 + 1), 100)),
                title: "t".into(),
                detail: "d".into(),
                signature: None,
                decoded_args: Vec::new(),
            })
            .collect();
        app.auto_revoke = true;
        assert!(
            app.effective_calls().len() > MAX_BATCH_CALLS,
            "precondition: the wrap really does exceed the cap",
        );

        assert!(app.update(Message::Review).is_none(), "review is refused");
        let e = app.error.as_deref().expect("with a reason");
        assert!(e.contains("revoke approvals"), "{e}");
        assert!(e.contains(&MAX_BATCH_CALLS.to_string()), "{e}");

        app.error = None;
        assert!(app.update(Message::Simulate).is_none(), "so is simulate");
        assert!(app.error.is_some(), "and it says why");

        // Turning the toggle off puts it back inside the cap.
        app.auto_revoke = false;
        app.error = None;
        assert!(
            app.update(Message::Review).is_some(),
            "un-wrapped, the same queue reviews fine",
        );
    }

    #[test]
    fn loading_a_template_composed_as_another_account_says_so() {
        // The natural workflow is the dangerous one: compose and test as your
        // EOA, save, switch to the Safe to run it. The calls still point where
        // they did.
        let mut app = safe_app();
        let t = Template::from_batch(
            "Weekly claim",
            "(°ᴗ°)",
            Chain::Mainnet,
            EOA,
            &[QueuedCall {
                id: 1,
                to: Address::repeat_byte(0xC1),
                value: U256::ZERO,
                data: Bytes::from(vec![0x01, 0x02, 0x03, 0x04]),
                title: "t".into(),
                detail: "d".into(),
                signature: None,
                decoded_args: Vec::new(),
            }],
        );
        app.load_template(&t);
        assert_eq!(app.batch.len(), 1, "it still loads — a notice, not a wall");
        let e = app
            .error
            .as_deref()
            .expect("and says who it was written for");
        assert!(e.contains("Weekly claim"), "{e}");
        assert!(e.contains("composed as"), "{e}");
    }

    #[test]
    fn loading_a_template_composed_as_this_account_stays_quiet() {
        // The warning has to be rare to be read.
        let mut app = safe_app();
        let t = Template::from_batch(
            "Mine",
            "(°ᴗ°)",
            Chain::Mainnet,
            SAFE,
            &[QueuedCall {
                id: 1,
                to: Address::repeat_byte(0xC1),
                value: U256::ZERO,
                data: Bytes::from(vec![0x01, 0x02, 0x03, 0x04]),
                title: "t".into(),
                detail: "d".into(),
                signature: None,
                decoded_args: Vec::new(),
            }],
        );
        app.load_template(&t);
        assert_eq!(app.batch.len(), 1);
        assert!(app.error.is_none(), "{:?}", app.error);
    }

    #[test]
    fn the_queue_flags_a_call_addressed_to_the_active_safe() {
        // The queue is where an imported bundle first becomes visible, and the
        // last point at which dropping the call is one click.
        let app = safe_app();
        let mut add_owner =
            alloy::primitives::keccak256(b"addOwnerWithThreshold(address,uint256)")[..4].to_vec();
        add_owner.extend_from_slice(
            alloy::primitives::B256::left_padding_from(EOA.as_slice()).as_slice(),
        );
        add_owner.extend_from_slice(&U256::from(1u64).to_be_bytes::<32>());

        let governance = QueuedCall {
            id: 1,
            to: SAFE,
            value: U256::ZERO,
            data: Bytes::from(add_owner),
            title: "t".into(),
            detail: "d".into(),
            signature: None,
            decoded_args: Vec::new(),
        };
        let ordinary = QueuedCall {
            to: Address::repeat_byte(0xC1),
            ..governance.clone()
        };

        let note = app
            .self_admin_note(&governance)
            .expect("a call to the Safe is flagged in the queue");
        assert!(note.contains("adds an owner"), "{note}");
        assert!(
            app.self_admin_note(&ordinary).is_none(),
            "and an ordinary call is not",
        );
    }

    #[test]
    fn the_queue_flag_keys_on_the_active_identity_not_a_constant() {
        // Same calldata, EOA identity: there is no Safe to reconfigure, so the
        // Safe-specific wording must not appear.
        let app = eoa_app();
        let c = QueuedCall {
            id: 1,
            to: SAFE,
            value: U256::ZERO,
            data: Bytes::from(vec![0x01, 0x02, 0x03, 0x04]),
            title: "t".into(),
            detail: "d".into(),
            signature: None,
            decoded_args: Vec::new(),
        };
        assert!(
            app.self_admin_note(&c).is_none(),
            "a Safe address is just an address when no Safe is active",
        );
        let self_call = QueuedCall { to: EOA, ..c };
        let note = app.self_admin_note(&self_call).expect("self-call flagged");
        assert!(!note.contains("multisig"), "{note}");
    }

    #[test]
    fn fee_caveats_name_only_what_applies_to_this_batch() {
        // A single Mainnet EOA call: no wrapper, no L2 data fee, and the
        // intrinsic gas is counted exactly once, so the tip is the only gap.
        let mut app = eoa_app();
        app.batch = n_calls(1);
        let c = app.fee_caveats();
        assert_eq!(c.len(), 1, "{c:?}");
        assert!(c[0].contains("priority tip"), "{c:?}");
    }

    #[test]
    fn fee_caveats_flag_the_l1_data_fee_only_on_the_op_stack() {
        let mut app = eoa_app();
        app.batch = n_calls(1);
        assert!(
            !app.fee_caveats().iter().any(|c| c.contains("L1 data fee")),
            "Mainnet has no L1 data fee to exclude",
        );
        app.update(Message::SetNetwork(NetworkId::Builtin(Chain::Base)));
        app.batch = n_calls(1);
        assert!(
            app.fee_caveats().iter().any(|c| c.contains("L1 data fee")),
            "on Base it is often the larger half of the cost",
        );
    }

    #[test]
    fn fee_caveats_disclose_the_intrinsic_over_count_only_on_a_batch() {
        // The one caveat that runs the *other* way: the estimate is too high,
        // not too low. Naming it is what lets a user reconcile this figure
        // against the one their device shows.
        let mut app = eoa_app();
        app.batch = n_calls(1);
        assert!(!app.fee_caveats().iter().any(|c| c.contains("21,000")));
        app.batch = n_calls(3);
        assert!(
            app.fee_caveats().iter().any(|c| c.contains("21,000")),
            "three calls pay three intrinsics here and one on chain",
        );
    }

    #[test]
    fn a_safe_batch_discloses_the_wrapper_the_estimate_cannot_see() {
        let mut app = safe_app();
        app.batch = n_calls(2);
        let c = app.fee_caveats();
        assert!(c.iter().any(|x| x.contains("execTransaction")), "{c:?}");
        assert!(c.iter().any(|x| x.contains("MultiSend")), "{c:?}");
    }

    #[test]
    fn the_review_carries_the_simulation_its_verdict_came_from() {
        // The economics and the preflight verdict must describe the same run —
        // derived twice, they could describe different batches.
        let mut app = safe_app();
        app.batch = n_calls(2);
        app.sim = Some(BatchSimResult {
            outcome: BatchOutcome::Success,
            gas_used: 210_000,
            transfers: Vec::new(),
            verified: true,
            base_fee_per_gas: 12_000_000_000,
            block: 1,
            block_gas_limit: 30_000_000,
        });
        let Some(Outcome::Review { sim, preflight, .. }) = app.update(Message::Review) else {
            panic!("review outcome");
        };
        assert!(matches!(preflight, Preflight::Passed { .. }));
        let sim = sim.expect("the verdict's own simulation rides along");
        assert_eq!(sim.gas_used, 210_000);
    }

    #[test]
    fn add_to_batch_stops_at_the_queue_ceiling() {
        let mut app = safe_app();
        app.batch = (0..MAX_BATCH_CALLS as u64)
            .map(|i| QueuedCall {
                id: i,
                to: Address::repeat_byte(0xC1),
                value: U256::ZERO,
                data: Bytes::from(vec![0x01]),
                title: "t".into(),
                detail: "d".into(),
                signature: None,
                decoded_args: Vec::new(),
            })
            .collect();
        app.next_id = MAX_BATCH_CALLS as u64;
        app.update(Message::SetMode(Mode::Raw));
        app.update(Message::RawToChanged(
            "0x000000000000000000000000000000000000dEaD".into(),
        ));
        app.update(Message::AddToBatch);
        assert_eq!(app.batch.len(), MAX_BATCH_CALLS, "the ceiling holds");
        let err = app.error.as_deref().unwrap_or_default();
        assert!(err.contains(&MAX_BATCH_CALLS.to_string()), "{err}");
    }

    #[test]
    fn adopt_batch_refuses_an_over_long_batch_after_the_single_call_reason() {
        let call = |i: u64| QueuedCall {
            id: i,
            to: Address::repeat_byte(0xC1),
            value: U256::ZERO,
            data: Bytes::from(vec![0x01]),
            title: "t".into(),
            detail: "d".into(),
            signature: None,
            decoded_args: Vec::new(),
        };
        let long: Vec<_> = (0..MAX_BATCH_CALLS as u64 + 10).map(call).collect();

        // An account that can't batch at all gets the more specific reason —
        // its problem isn't the length.
        let mut eoa = eoa_app();
        eoa.set_context(EOA, Chain::Mainnet, false, None, false, true, Vec::new());
        let err = eoa.adopt_batch(long.clone()).unwrap_err();
        assert!(err.contains("one at a time"), "{err}");

        // A Safe can batch, so for it the length is the problem.
        let mut safe = safe_app();
        let err = safe.adopt_batch(long).unwrap_err();
        assert!(err.contains(&MAX_BATCH_CALLS.to_string()), "{err}");
        assert!(safe.batch.is_empty(), "nothing was adopted");
    }

    #[test]
    fn raw_mode_cta_stays_off_until_the_value_and_the_data_parse() {
        let mut app = eoa_app();
        app.update(Message::SetMode(Mode::Raw));
        app.update(Message::RawToChanged(
            "0x000000000000000000000000000000000000dEaD".into(),
        ));
        assert!(app.compose_valid(), "a target alone is a valid raw call");

        app.update(Message::RawValueChanged("12.5".into()));
        assert!(!app.compose_valid(), "wei is an integer");

        app.update(Message::RawValueChanged("0".into()));
        app.update(Message::RawDataChanged("0xzz".into()));
        assert!(!app.compose_valid(), "calldata must be hex");

        app.update(Message::RawDataChanged("0xabc".into()));
        assert!(!app.compose_valid(), "odd-length hex is not bytes");

        app.update(Message::RawDataChanged("0xdeadbeef".into()));
        assert!(app.compose_valid());
    }

    #[test]
    fn a_raw_call_that_would_be_refused_is_never_queued() {
        // The refusal is a dark CTA plus a reason under the field — not a
        // banner at the foot of the page after the button was pressed.
        let mut app = eoa_app();
        app.update(Message::SetMode(Mode::Raw));
        app.update(Message::RawToChanged(
            "0x000000000000000000000000000000000000dEaD".into(),
        ));
        app.update(Message::RawDataChanged("0xabc".into()));
        assert!(!app.compose_valid());
        assert!(
            app.error.is_none(),
            "nothing was attempted, so nothing failed"
        );
        assert!(app.batch.is_empty());
    }

    #[test]
    fn removed_custom_network_falls_back_to_mainnet() {
        let mut app = eoa_app();
        app.update(Message::SetNetwork(NetworkId::Custom(11155111)));
        assert!(app.is_custom());
        // Next context refresh no longer lists that custom network.
        app.set_context(EOA, Chain::Mainnet, false, None, true, true, Vec::new());
        assert_eq!(app.selected_net(), NetworkId::Builtin(Chain::Mainnet));
    }

    // ── Read tab ─────────────────────────────────────────────────────────

    #[test]
    fn read_query_bubbles_eth_call_and_decodes() {
        let mut app = eoa_app();
        app.update(Message::AddrChanged(usdc().to_string())); // known → read_methods present
        app.update(Message::SetMode(Mode::Read));
        // read_methods[0] = balanceOf(address) -> uint256
        let holder = address!("0x000000000000000000000000000000000000bEEF");
        app.update(Message::ReadArgChanged(0, holder.to_string()));
        assert!(app.read_valid());
        let seq = match app.update(Message::Query) {
            Some(Outcome::Read { seq, net, to, .. }) => {
                assert_eq!(net, NetworkId::Builtin(Chain::Mainnet));
                assert_eq!(to, usdc());
                seq
            }
            other => panic!("expected Read outcome, got {other:?}"),
        };
        assert!(app.read_busy);
        // Feed a decoded uint256 return of 12345.
        let ret = U256::from(12_345u64).to_be_bytes::<32>();
        app.on_read(seq, Ok((Bytes::from(ret.to_vec()), true)));
        assert!(!app.read_busy);
        match &app.read_result {
            Some(ReadOutcome::Ok {
                rows,
                raw,
                verified,
            }) => {
                assert!(*verified);
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].ty, "uint256");
                assert_eq!(rows[0].value, "12345");
                assert!(raw.starts_with("0x"));
            }
            other => panic!("expected decoded read result, got {other:?}"),
        }

        // Read output is public — copies use the no-auto-clear path so the value
        // survives in the clipboard until the user pastes it.
        match app.update(Message::CopyReadValue(0)) {
            Some(Outcome::CopyPlain(v)) => assert_eq!(v, "12345"),
            other => panic!("expected CopyPlain, got {other:?}"),
        }
        assert!(matches!(
            app.update(Message::CopyReadRaw),
            Some(Outcome::CopyPlain(_))
        ));
    }

    #[test]
    fn stale_read_result_is_dropped() {
        let mut app = eoa_app();
        app.update(Message::AddrChanged(usdc().to_string()));
        app.update(Message::SetMode(Mode::Read));
        app.update(Message::ReadArgChanged(
            0,
            Address::repeat_byte(1).to_string(),
        ));
        app.update(Message::Query);
        let stale = app.read_seq;
        // A newer query supersedes it.
        app.update(Message::ReadArgChanged(
            0,
            Address::repeat_byte(2).to_string(),
        ));
        app.update(Message::Query);
        app.on_read(stale, Ok((Bytes::new(), true)));
        // The stale answer must not populate the result.
        assert!(app.read_busy, "still awaiting the current query");
    }

    #[test]
    fn switching_the_read_method_retires_an_in_flight_query() {
        let mut app = eoa_app();
        app.update(Message::AddrChanged(usdc().to_string()));
        app.update(Message::SetMode(Mode::Read));
        app.update(Message::ReadArgChanged(
            0,
            Address::repeat_byte(1).to_string(),
        ));
        app.update(Message::Query);
        let stale = app.read_seq;
        assert!(app.read_busy);

        // `on_read` decodes the returned bytes against whatever method is
        // selected when they land. Picking a different one mid-flight (here
        // balanceOf → allowance) must retire the answer, not reinterpret a
        // uint256 balance as the next method's return shape.
        app.update(Message::PickReadMethod(1));
        app.on_read(stale, Ok((Bytes::from(vec![0xAAu8; 32]), true)));

        assert!(
            app.read_result.is_none(),
            "stale answer must not be decoded against the new method"
        );
        assert!(!app.read_busy, "a superseded query stops the spinner");
    }

    #[test]
    fn a_new_contract_retires_an_in_flight_query() {
        let mut app = eoa_app();
        app.update(Message::AddrChanged(usdc().to_string()));
        app.update(Message::SetMode(Mode::Read));
        app.update(Message::ReadArgChanged(
            0,
            Address::repeat_byte(1).to_string(),
        ));
        app.update(Message::Query);
        let stale = app.read_seq;

        // Same hazard one level up: the answer belongs to the old contract.
        app.update(Message::AddrChanged(
            address!("0x00000000000000000000000000000000C0FFEE00").to_string(),
        ));
        app.on_read(stale, Ok((Bytes::from(vec![0xAAu8; 32]), true)));

        assert!(
            app.read_result.is_none(),
            "answer belongs to the old target"
        );
        assert!(!app.read_busy);
    }

    // ── Templates ────────────────────────────────────────────────────────

    #[test]
    fn save_current_batch_persists_and_load_restores() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        let n = app.batch.len();
        let out = app.update(Message::SaveTemplate);
        match out {
            Some(Outcome::PersistTemplates { list, .. }) => {
                assert_eq!(list.len(), 1);
                assert_eq!(list[0].call_count, n);
            }
            other => panic!("expected PersistTemplates, got {other:?}"),
        }
        assert_eq!(app.templates.len(), 1);
        // Clear then reload the saved template → the batch comes back.
        app.update(Message::ClearBatch);
        assert!(app.batch.is_empty());
        app.update(Message::LoadTemplate(0));
        assert_eq!(app.batch.len(), n);
    }

    #[test]
    fn delete_template_persists_removal() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        app.update(Message::SaveTemplate);
        assert_eq!(app.templates.len(), 1);
        match app.update(Message::DeleteTemplate(0)) {
            Some(Outcome::PersistTemplates { list, .. }) => assert!(list.is_empty()),
            other => panic!("expected PersistTemplates, got {other:?}"),
        }
        assert!(app.templates.is_empty());
    }

    #[test]
    fn rename_template_commits_and_persists() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        app.update(Message::SaveTemplate);
        assert_eq!(app.templates[0].name, "Untitled batch");

        app.update(Message::StartRename(0));
        assert_eq!(app.rename_idx, Some(0));
        app.update(Message::RenameChanged("  Payroll run  ".into()));
        match app.update(Message::CommitRename) {
            Some(Outcome::PersistTemplates { list, .. }) => assert_eq!(list[0].name, "Payroll run"),
            other => panic!("expected PersistTemplates, got {other:?}"),
        }
        assert_eq!(app.templates[0].name, "Payroll run", "trimmed + applied");
        assert!(app.rename_idx.is_none(), "rename cleared after commit");
    }

    #[test]
    fn blank_rename_is_rejected() {
        let mut app = safe_app();
        app.batch = sample_batch(&mut app.next_id, app.owner);
        app.update(Message::SaveTemplate);
        app.update(Message::StartRename(0));
        app.update(Message::RenameChanged("   ".into()));
        // A blank name doesn't commit and keeps the rename open to fix.
        assert!(app.update(Message::CommitRename).is_none());
        assert_eq!(app.templates[0].name, "Untitled batch");
        assert_eq!(app.rename_idx, Some(0));
    }
}
