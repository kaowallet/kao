//! Transaction Builder app — the Apps-pane surface for composing contract
//! calls, queueing them into a batch, simulating, and handing the batch to
//! the shared sign-review overlay.
//!
//! Ephemeral UI state only. All I/O (contract-code fetch, batch simulation,
//! signing/broadcast) is bubbled to the dashboard coordinator via
//! [`Outcome`]s, which feeds results back through the `on_*` callbacks —
//! the same convention the Names and Privacy Pools apps follow.

use iced::Element;

use alloy::primitives::{Address, B256, Bytes, U256};

use crate::chain::Chain;
use crate::portfolio::format_token_balance;
use crate::safe::tx::SafeTxInput;
use crate::txbuilder::abi::{self, LoadedContract};
use crate::txbuilder::sim::BatchSimResult;
use crate::txbuilder::{QueuedCall, bundle, encode};
use crate::ui::kao_theme::KaoTheme;
use crate::wallet::SafeTrust;

/// Which composer mode is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Call,
    Raw,
}

/// The JSON import/export overlay, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Modal {
    None,
    Save,
    Load,
}

#[derive(Debug, Clone)]
pub enum Message {
    Close,
    SetMode(Mode),
    // contract-call composer
    AddrChanged(String),
    PickKnown(usize),
    ShowAbiPaste,
    AbiPasteChanged(String),
    LoadPastedAbi,
    ToggleMethodMenu,
    PickMethod(usize),
    ArgChanged(usize, String),
    BoolArg(usize, bool),
    ValueChanged(String),
    // raw composer
    RawToChanged(String),
    RawValueChanged(String),
    RawDataChanged(String),
    // add / batch ops
    AddToBatch,
    RemoveCall(u64),
    MoveUp(u64),
    MoveDown(u64),
    ToggleExpand(u64),
    ClearBatch,
    LoadSample,
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
    // misc
    DismissError,
}

impl Message {
    fn name(&self) -> &'static str {
        match self {
            Message::Close => "Close",
            Message::SetMode(_) => "SetMode",
            Message::AddrChanged(_) => "AddrChanged",
            Message::PickKnown(_) => "PickKnown",
            Message::ShowAbiPaste => "ShowAbiPaste",
            Message::AbiPasteChanged(_) => "AbiPasteChanged",
            Message::LoadPastedAbi => "LoadPastedAbi",
            Message::ToggleMethodMenu => "ToggleMethodMenu",
            Message::PickMethod(_) => "PickMethod",
            Message::ArgChanged(..) => "ArgChanged",
            Message::BoolArg(..) => "BoolArg",
            Message::ValueChanged(_) => "ValueChanged",
            Message::RawToChanged(_) => "RawToChanged",
            Message::RawValueChanged(_) => "RawValueChanged",
            Message::RawDataChanged(_) => "RawDataChanged",
            Message::AddToBatch => "AddToBatch",
            Message::RemoveCall(_) => "RemoveCall",
            Message::MoveUp(_) => "MoveUp",
            Message::MoveDown(_) => "MoveDown",
            Message::ToggleExpand(_) => "ToggleExpand",
            Message::ClearBatch => "ClearBatch",
            Message::LoadSample => "LoadSample",
            Message::Simulate => "Simulate",
            Message::Review => "Review",
            Message::OpenSave => "OpenSave",
            Message::OpenLoad => "OpenLoad",
            Message::CloseModal => "CloseModal",
            Message::JsonChanged(_) => "JsonChanged",
            Message::CopyJson => "CopyJson",
            Message::ImportJson => "ImportJson",
            Message::DismissError => "DismissError",
        }
    }
}

/// Requests bubbled to the coordinator.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// Step back to the Apps launcher.
    Close,
    /// Fetch the runtime bytecode of `address` so the composer can recover
    /// its ABI. Answered via [`TxBuilderApp::on_contract_resolved`].
    ResolveContract { seq: u64, address: Address },
    /// Simulate the batch. Answered via [`TxBuilderApp::on_sim`].
    Simulate { calls: Vec<QueuedCall> },
    /// Open the sign-review overlay for the batch.
    Review { calls: Vec<QueuedCall> },
    /// Copy text (exported JSON) to the clipboard.
    CopyText(String),
}

impl Outcome {
    fn name(&self) -> &'static str {
        match self {
            Outcome::Close => "Close",
            Outcome::ResolveContract { .. } => "ResolveContract",
            Outcome::Simulate { .. } => "Simulate",
            Outcome::Review { .. } => "Review",
            Outcome::CopyText(_) => "CopyText",
        }
    }
}

/// External context the coordinator refreshes before each message.
#[derive(Debug, Clone)]
struct Ctx {
    chain: Chain,
    /// Whether the active identity is a Safe (atomic batching via MultiSend).
    is_safe: bool,
    /// The active Safe's contract version, for the MultiSend routing hint.
    #[allow(dead_code)]
    safe_version: Option<String>,
    /// For a plain EOA: whether the active signer can authorize an EIP-7702
    /// delegation (Local / Ledger) and therefore batch N calls atomically.
    /// Trezor / view-only cannot, and stay capped at a single call.
    eoa_can_batch: bool,
}

impl Default for Ctx {
    fn default() -> Self {
        Self {
            chain: Chain::Mainnet,
            is_safe: false,
            safe_version: None,
            eoa_can_batch: false,
        }
    }
}

#[derive(Debug)]
pub struct TxBuilderApp {
    #[allow(dead_code)]
    owner: Address,
    ctx: Ctx,

    mode: Mode,

    // ── contract-call composer ──
    addr_input: String,
    loaded: Option<LoadedContract>,
    resolving: bool,
    /// Set when a resolve found no ABI — prompts the paste-ABI fallback.
    not_found: bool,
    paste_open: bool,
    abi_paste: String,
    /// The address currently being resolved / loaded (dedup guard).
    resolve_target: Option<Address>,
    resolve_seq: u64,
    method_idx: usize,
    method_menu_open: bool,
    args: Vec<String>,
    value_input: String,

    // ── raw composer ──
    raw_to: String,
    raw_value: String,
    raw_data: String,

    // ── batch ──
    batch: Vec<QueuedCall>,
    next_id: u64,
    expanded: Option<u64>,

    // ── simulation strip ──
    sim: Option<BatchSimResult>,
    sim_busy: bool,

    // ── JSON modal ──
    modal: Modal,
    json_text: String,
    json_error: Option<String>,

    error: Option<String>,
}

impl TxBuilderApp {
    pub fn new(owner: Address) -> Self {
        Self {
            owner,
            ctx: Ctx::default(),
            mode: Mode::Call,
            addr_input: String::new(),
            loaded: None,
            resolving: false,
            not_found: false,
            paste_open: false,
            abi_paste: String::new(),
            resolve_target: None,
            resolve_seq: 0,
            method_idx: 0,
            method_menu_open: false,
            args: Vec::new(),
            value_input: "0".into(),
            raw_to: String::new(),
            raw_value: "0".into(),
            raw_data: String::new(),
            batch: Vec::new(),
            next_id: 1,
            expanded: None,
            sim: None,
            sim_busy: false,
            modal: Modal::None,
            json_text: String::new(),
            json_error: None,
            error: None,
        }
    }

    /// Coordinator refreshes chain / Safe context before dispatching a
    /// message, so message-time logic (known-contract lookup, batch cap)
    /// sees the live identity.
    pub fn set_context(
        &mut self,
        chain: Chain,
        is_safe: bool,
        safe_version: Option<String>,
        eoa_can_batch: bool,
    ) {
        // A chain change invalidates a resolved contract (known addresses
        // are per-chain).
        if self.ctx.chain != chain {
            self.reset_composer();
        }
        self.ctx = Ctx {
            chain,
            is_safe,
            safe_version,
            eoa_can_batch,
        };
    }

    // ── coordinator callbacks ─────────────────────────────────────────

    /// The coordinator fetched the contract's runtime code (or failed).
    /// `code` empty ⇒ no contract at that address.
    pub fn on_contract_resolved(&mut self, seq: u64, code: Result<Bytes, String>) {
        if seq != self.resolve_seq {
            return; // stale — a newer address was entered
        }
        self.resolving = false;
        let Some(addr) = self.resolve_target else {
            return;
        };
        match code {
            Ok(bytes) => match abi::from_bytecode(&bytes, addr) {
                Some(loaded) => self.set_loaded(loaded),
                None => self.not_found = true,
            },
            Err(_) => self.not_found = true,
        }
    }

    /// Batch simulation result (or failure → treated as unavailable).
    pub fn on_sim(&mut self, result: Result<BatchSimResult, String>) {
        self.sim_busy = false;
        self.sim = Some(result.unwrap_or_else(|_| BatchSimResult::unavailable()));
    }

    /// The batch was executed successfully — clear it so the composer is
    /// ready for the next one.
    pub fn on_executed(&mut self) {
        self.batch.clear();
        self.sim = None;
        self.expanded = None;
    }

    pub fn update(&mut self, msg: Message) -> Option<Outcome> {
        crate::trace_msg!("tx_builder", &msg);
        let name = msg.name();
        let outcome = self.update_inner(msg);
        if let Some(o) = &outcome {
            crate::trace::outcome("tx_builder", o.name());
        }
        let _ = name;
        outcome
    }

    fn update_inner(&mut self, msg: Message) -> Option<Outcome> {
        match msg {
            Message::Close => return Some(Outcome::Close),
            Message::SetMode(m) => {
                self.mode = m;
                self.error = None;
            }
            Message::AddrChanged(v) => return self.on_addr_changed(v),
            Message::PickKnown(i) => {
                let known = abi::known_for_chain(self.ctx.chain);
                if let Some(k) = known.get(i) {
                    self.addr_input = k.address.to_string();
                    if let Some(loaded) = abi::known_by_address(self.ctx.chain, k.address) {
                        self.set_loaded(loaded);
                    }
                }
            }
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
            Message::RawToChanged(v) => self.raw_to = v,
            Message::RawValueChanged(v) => self.raw_value = v,
            Message::RawDataChanged(v) => self.raw_data = v,
            Message::AddToBatch => self.add_to_batch(),
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
            Message::Simulate => {
                if !self.batch.is_empty() {
                    self.sim_busy = true;
                    self.sim = None;
                    return Some(Outcome::Simulate {
                        calls: self.batch.clone(),
                    });
                }
            }
            Message::Review => {
                if !self.batch.is_empty() {
                    return Some(Outcome::Review {
                        calls: self.batch.clone(),
                    });
                }
            }
            Message::OpenSave => {
                self.json_text = bundle::export(
                    self.ctx.chain,
                    self.ctx.is_safe.then_some(self.owner),
                    &self.batch,
                );
                self.modal = Modal::Save;
            }
            Message::OpenLoad => {
                self.json_text.clear();
                self.json_error = None;
                self.modal = Modal::Load;
            }
            Message::CloseModal => self.modal = Modal::None,
            Message::JsonChanged(v) => {
                self.json_text = v;
                self.json_error = None;
            }
            Message::CopyJson => return Some(Outcome::CopyText(self.json_text.clone())),
            Message::ImportJson => match bundle::import(&self.json_text, self.next_id) {
                Ok(calls) => {
                    self.next_id += calls.len() as u64;
                    self.batch = calls;
                    self.invalidate_sim();
                    self.modal = Modal::None;
                }
                Err(e) => self.json_error = Some(e.to_string()),
            },
            Message::DismissError => self.error = None,
        }
        None
    }

    fn on_addr_changed(&mut self, v: String) -> Option<Outcome> {
        self.addr_input = v;
        self.error = None;
        let trimmed = self.addr_input.trim();
        match trimmed.parse::<Address>() {
            Ok(addr) => {
                // Already resolved / resolving this exact address — no-op.
                if self.resolve_target == Some(addr)
                    && (self.loaded.is_some() || self.resolving || self.not_found)
                {
                    return None;
                }
                self.reset_composer_keep_addr();
                self.resolve_target = Some(addr);
                if let Some(loaded) = abi::known_by_address(self.ctx.chain, addr) {
                    self.set_loaded(loaded);
                    None
                } else {
                    self.resolving = true;
                    self.resolve_seq += 1;
                    Some(Outcome::ResolveContract {
                        seq: self.resolve_seq,
                        address: addr,
                    })
                }
            }
            Err(_) => {
                self.reset_composer_keep_addr();
                None
            }
        }
    }

    fn set_loaded(&mut self, loaded: LoadedContract) {
        self.resolving = false;
        self.not_found = false;
        self.paste_open = false;
        self.resolve_target = Some(loaded.address);
        self.method_idx = 0;
        self.method_menu_open = false;
        self.loaded = Some(loaded);
        self.reset_args();
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

    fn reset_composer(&mut self) {
        self.addr_input.clear();
        self.reset_composer_keep_addr();
    }

    fn reset_composer_keep_addr(&mut self) {
        self.loaded = None;
        self.resolving = false;
        self.not_found = false;
        self.paste_open = false;
        self.resolve_target = None;
        self.method_idx = 0;
        self.method_menu_open = false;
        self.args.clear();
        self.value_input = "0".into();
    }

    fn invalidate_sim(&mut self) {
        self.sim = None;
        self.sim_busy = false;
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

    fn selected_method(&self) -> Option<&abi::AbiMethod> {
        self.loaded
            .as_ref()
            .and_then(|c| c.methods.get(self.method_idx))
    }

    /// Whether the currently-composed call is valid and can be queued.
    fn compose_valid(&self) -> bool {
        match self.mode {
            Mode::Call => {
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
            Mode::Raw => encode::parse_address(&self.raw_to).is_ok(),
        }
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
        let built = match self.mode {
            Mode::Call => {
                let Some(m) = self.selected_method().cloned() else {
                    return;
                };
                let name = self
                    .loaded
                    .as_ref()
                    .map(|c| c.name.clone())
                    .unwrap_or_default();
                let addr = self
                    .loaded
                    .as_ref()
                    .map(|c| c.address)
                    .unwrap_or(Address::ZERO);
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
                let to = match encode::parse_address(&self.raw_to) {
                    Ok(a) => a,
                    Err(e) => {
                        self.error = Some(e);
                        return;
                    }
                };
                encode::build_raw_call(self.next_id, to, &self.raw_value, &self.raw_data)
            }
        };
        match built {
            Ok(call) => {
                self.next_id += 1;
                self.batch.push(call);
                self.invalidate_sim();
                self.error = None;
                // Reset params but keep the contract loaded for rapid batching.
                match self.mode {
                    Mode::Call => {
                        self.reset_args();
                    }
                    Mode::Raw => {
                        self.raw_data.clear();
                    }
                }
            }
            Err(e) => self.error = Some(e.to_string()),
        }
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
}

/// A plain-EOA batch. One or more calls executed from `from`:
///
/// - a single call, or an account that can't delegate, broadcasts as an
///   ordinary EIP-1559 transaction;
/// - N calls from a 7702-capable signer are wrapped as
///   `Simple7702Account.executeBatch` and run atomically.
///
/// Whether a fresh EIP-7702 authorization is signed is decided in the send
/// task from the account's live on-chain code (authoritative at signing
/// time): if the account is already delegated to the EF `Simple7702Account`,
/// the batch is a plain call to the delegated code; otherwise the send signs
/// a delegation authorization first.
#[derive(Debug, Clone)]
pub struct EoaBatchRequest {
    pub chain: Chain,
    pub from: Address,
    pub calls: Vec<QueuedCall>,
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

// The view is large; split into its own module for readability.
mod view;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    fn safe_app() -> TxBuilderApp {
        let mut app = TxBuilderApp::new(Address::repeat_byte(0x5a));
        app.set_context(Chain::Mainnet, true, Some("1.4.1".into()), false);
        app
    }

    #[test]
    fn known_pick_loads_contract_synchronously() {
        let mut app = safe_app();
        let out = app.update(Message::PickKnown(0)); // USDC
        assert!(out.is_none(), "known contracts resolve without I/O");
        assert!(app.loaded.is_some());
        assert!(!app.resolving);
        assert_eq!(app.loaded.as_ref().unwrap().name, "USDC");
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
        app.update(Message::PickKnown(0)); // USDC, method 0 = transfer
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
        let mut app = TxBuilderApp::new(Address::repeat_byte(0x11));
        app.set_context(Chain::Mainnet, false, None, false); // EOA, can't delegate
        app.update(Message::PickKnown(0));
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
        let mut app = TxBuilderApp::new(Address::repeat_byte(0x11));
        app.set_context(Chain::Mainnet, false, None, true); // EOA, Local/Ledger
        let to = address!("0x000000000000000000000000000000000000dEaD");
        app.update(Message::PickKnown(0));
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
            Some(Outcome::Simulate { calls }) => assert_eq!(calls.len(), 2),
            other => panic!("expected Simulate, got {other:?}"),
        }
        assert!(app.sim_busy);
        match app.update(Message::Review) {
            Some(Outcome::Review { calls }) => assert_eq!(calls.len(), 2),
            other => panic!("expected Review, got {other:?}"),
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
        app.on_contract_resolved(stale_seq, Ok(Bytes::new()));
        assert!(!app.not_found, "stale resolve result ignored");
        assert_eq!(app.resolve_target, Some(b));
    }
}
