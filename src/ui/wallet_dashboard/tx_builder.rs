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
use crate::txbuilder::sim::BatchSimResult;
use crate::txbuilder::templates::Template;
use crate::txbuilder::{QueuedCall, bundle, encode, flash_approval};
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
    // network switcher
    ToggleNetworkMenu,
    SetNetwork(NetworkId),
    // contract-call composer
    AddrChanged(String),
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
    // misc
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
    /// Simulate the batch on `chain` (built-in only). Answered via
    /// [`TxBuilderApp::on_sim`].
    Simulate {
        chain: Chain,
        calls: Vec<QueuedCall>,
    },
    /// Open the sign-review overlay for the batch (built-in batch / Safe) or a
    /// single call (custom-network send). The coordinator reads the app's
    /// selected network to build the request.
    Review { calls: Vec<QueuedCall> },
    /// Persist the user's template list to redb.
    PersistTemplates(Vec<Template>),
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
            Outcome::Simulate { .. } => "Simulate",
            Outcome::Review { .. } => "Review",
            Outcome::PersistTemplates(_) => "PersistTemplates",
            Outcome::CopyText(_) => "CopyText",
            Outcome::CopyPlain(_) => "CopyPlain",
        }
    }
}

/// External context the coordinator refreshes before each message.
#[derive(Debug, Clone, Default)]
struct Ctx {
    /// Whether the active identity is a Safe (atomic batching via MultiSend).
    is_safe: bool,
    /// The active Safe's contract version, for the MultiSend routing hint.
    #[allow(dead_code)]
    safe_version: Option<String>,
    /// For a plain EOA: whether the active signer can authorize an EIP-7702
    /// delegation (Local / Ledger) and therefore batch N calls atomically.
    /// Trezor / view-only cannot, and stay capped at a single call.
    eoa_can_batch: bool,
    /// Enabled custom networks `(chain_id, name)` offered by the switcher.
    custom_networks: Vec<(u64, String)>,
}

#[derive(Debug)]
pub struct TxBuilderApp {
    #[allow(dead_code)]
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
    /// Set when the last resolve hit a proxy slot it could only read over
    /// unverified RPC. The pointer wasn't followed, so the ABI on screen is the
    /// proxy stub's — worth saying out loud rather than leaving the user to
    /// wonder why a well-known contract came back nearly empty.
    proxy_unverified: bool,
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
    sim_busy: bool,

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
            proxy_unverified: false,
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
            sim_busy: false,
            templates: Vec::new(),
            template_menu_open: false,
            rename_idx: None,
            rename_buf: String::new(),
            modal: Modal::None,
            json_text: String::new(),
            json_error: None,
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
    pub fn set_context(
        &mut self,
        chain: Chain,
        is_safe: bool,
        safe_version: Option<String>,
        eoa_can_batch: bool,
        custom_networks: Vec<(u64, String)>,
    ) {
        self.ctx = Ctx {
            is_safe,
            safe_version,
            eoa_can_batch,
            custom_networks,
        };
        // A Safe can only transact on its own chain — pin the selector there.
        if is_safe {
            let pinned = NetworkId::Builtin(chain);
            if self.net != pinned {
                let from = self.net;
                self.net = pinned;
                self.on_network_reset(from);
            }
        } else if let NetworkId::Custom(id) = self.net {
            // A plain EOA keeps its selection across context refreshes, except
            // when the selected custom network was removed underneath it.
            if !self.ctx.custom_networks.iter().any(|(cid, _)| *cid == id) {
                let from = self.net;
                self.net = NetworkId::Builtin(Chain::Mainnet);
                self.on_network_reset(from);
            }
        }
    }

    // ── coordinator callbacks ─────────────────────────────────────────

    /// The coordinator fetched the contract's runtime code (or failed) — the
    /// implementation's code when the address turned out to be a proxy. Empty
    /// code ⇒ nothing deployed there.
    pub fn on_contract_resolved(&mut self, seq: u64, result: Result<ResolvedCode, String>) {
        if seq != self.resolve_seq {
            return; // stale — a newer address was entered
        }
        self.resolving = false;
        let Some(addr) = self.resolve_target else {
            return;
        };
        match result {
            Ok(r) => {
                self.proxy_unverified = !r.all_verified;
                match abi::from_bytecode_behind_proxy(&r.code, addr, r.implementation) {
                    Some(loaded) => self.set_loaded(loaded),
                    None => self.not_found = true,
                }
            }
            Err(_) => self.not_found = true,
        }
    }

    /// Batch simulation result (or failure → treated as unavailable).
    pub fn on_sim(&mut self, result: Result<BatchSimResult, String>) {
        self.sim_busy = false;
        self.sim = Some(result.unwrap_or_else(|_| BatchSimResult::unavailable()));
    }

    /// A Read-tab `eth_call` returned. `seq` guards against a stale query
    /// (the user changed the method / params before this landed). The raw
    /// return bytes are decoded here against the queried method's outputs.
    pub fn on_read(&mut self, seq: u64, result: Result<(Bytes, bool), String>) {
        if seq != self.read_seq {
            return; // stale — a newer query superseded this one
        }
        self.read_busy = false;
        self.read_result = Some(match result {
            Ok((bytes, verified)) => {
                let raw = if bytes.is_empty() {
                    "0x".to_string()
                } else {
                    format!("0x{}", alloy::hex::encode(&bytes))
                };
                let rows = self
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
            Message::RawToChanged(v) => self.raw_to = v,
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
                    self.sim_busy = true;
                    self.sim = None;
                    return Some(Outcome::Simulate {
                        chain,
                        calls: self.effective_calls(),
                    });
                }
            }
            Message::Review => {
                if !self.batch.is_empty() {
                    return Some(Outcome::Review {
                        calls: self.effective_calls(),
                    });
                }
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
                if !self.batch.is_empty() {
                    self.cancel_rename();
                    let t = Template::from_batch("Untitled batch", "(｡•̀ᴗ-)✧", &self.batch);
                    self.templates.push(t);
                    self.template_menu_open = true;
                    return Some(Outcome::PersistTemplates(self.templates.clone()));
                }
            }
            Message::DeleteTemplate(i) => {
                if i < self.templates.len() {
                    self.cancel_rename();
                    self.templates.remove(i);
                    return Some(Outcome::PersistTemplates(self.templates.clone()));
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
                self.json_text = bundle::export(
                    self.net.builtin().unwrap_or(Chain::Mainnet),
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
                match self.net.builtin() {
                    // Built-in chain: curated registry first, else fetch the
                    // verified bytecode and recover the ABI.
                    Some(chain) => {
                        if let Some(loaded) = abi::known_by_address(chain, addr) {
                            self.set_loaded(loaded);
                            None
                        } else {
                            // `reset_composer_keep_addr` above already bumped
                            // the sequence, retiring any earlier fetch; this
                            // request rides the value it left behind.
                            self.resolving = true;
                            Some(Outcome::ResolveContract {
                                seq: self.resolve_seq,
                                chain,
                                address: addr,
                            })
                        }
                    }
                    // Custom (unverified) network: no verified-bytecode fetch and
                    // no curated registry — prompt straight for a pasted ABI.
                    None => {
                        self.not_found = true;
                        None
                    }
                }
            }
            Err(_) => {
                self.reset_composer_keep_addr();
                None
            }
        }
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
        // A curated or pasted ABI is authoritative for the address regardless
        // of what the proxy walk could or couldn't read, so the caution retires
        // with it; a bytecode load keeps it (that ABI *is* the stub's).
        if loaded.source != AbiSource::Bytecode {
            self.proxy_unverified = false;
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
        self.proxy_unverified = false;
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

    fn invalidate_sim(&mut self) {
        self.sim = None;
        self.sim_busy = false;
    }

    /// The calls to simulate / review / sign: the queue, plus flash-approval
    /// revokes appended when the toggle is on. Revokes are derived here (never
    /// stored in `batch`) so the queue stays editable and reorder-safe.
    fn effective_calls(&self) -> Vec<QueuedCall> {
        if self.auto_revoke && self.can_batch() {
            flash_approval::wrap_with_revoke(&self.batch, self.next_id)
        } else {
            self.batch.clone()
        }
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
            Mode::Raw => encode::parse_address(&self.raw_to).is_ok(),
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
        match self.compose_call() {
            Ok(call) => {
                self.error = None;
                Some(Outcome::Review { calls: vec![call] })
            }
            Err(e) => {
                self.error = Some(e.to_string());
                None
            }
        }
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
    fn load_template(&mut self, t: &Template) {
        match t.calls(self.next_id) {
            Ok(calls) => {
                self.next_id += calls.len() as u64;
                self.batch = calls;
                self.invalidate_sim();
                self.expanded = None;
                self.template_menu_open = false;
                self.cancel_rename();
                self.error = None;
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }

    /// Commit an in-flight inline rename: trim, apply, persist. A blank name is
    /// rejected (keeps the rename open so the user can fix it).
    fn commit_rename(&mut self) -> Option<Outcome> {
        let idx = self.rename_idx?;
        let name = self.rename_buf.trim().to_string();
        if name.is_empty() {
            return None;
        }
        let t = self.templates.get_mut(idx)?;
        t.name = name;
        self.cancel_rename();
        Some(Outcome::PersistTemplates(self.templates.clone()))
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
/// Whether a fresh EIP-7702 authorization is signed is decided in the send
/// task from the account's live on-chain code (authoritative at signing
/// time): if the account is already delegated to the EF `Simple7702Account`,
/// the batch is a plain call to the delegated code; otherwise the send signs
/// a delegation authorization first.
#[derive(Debug, Clone)]
pub struct EoaBatchRequest {
    /// The network to broadcast on. A [`NetworkId`] so the same request shape
    /// covers a built-in chain and a user-defined custom network (single call
    /// only on custom — atomic batching is built-in-chains only).
    pub net: NetworkId,
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
            value: format_sol_value(&val),
        })
        .collect()
}

/// Humanise a decoded [`DynSolValue`] for the read-result panel: checksummed
/// address, decimal integer, `0x…` hex, or a bracketed list for compounds.
fn format_sol_value(v: &DynSolValue) -> String {
    match v {
        DynSolValue::Address(a) => a.to_checksum(None),
        DynSolValue::Bool(b) => b.to_string(),
        DynSolValue::Int(i, _) => i.to_string(),
        DynSolValue::Uint(u, _) => u.to_string(),
        DynSolValue::FixedBytes(b, sz) => format!("0x{}", alloy::hex::encode(&b[..(*sz).min(32)])),
        DynSolValue::Bytes(b) => format!("0x{}", alloy::hex::encode(b)),
        DynSolValue::String(s) => s.clone(),
        DynSolValue::Array(items) | DynSolValue::FixedArray(items) => {
            let inner: Vec<String> = items.iter().map(format_sol_value).collect();
            format!("[{}]", inner.join(", "))
        }
        DynSolValue::Tuple(items) => {
            let inner: Vec<String> = items.iter().map(format_sol_value).collect();
            format!("({})", inner.join(", "))
        }
        other => format!("{other:?}"),
    }
}

// The view is large; split into its own module for readability.
mod view;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    fn safe_app() -> TxBuilderApp {
        let mut app = TxBuilderApp::new(Address::repeat_byte(0x5a));
        app.set_context(
            Chain::Mainnet,
            true,
            Some("1.4.1".into()),
            false,
            Vec::new(),
        );
        app
    }

    /// Mainnet USDC — a known contract, so pasting its address resolves the ABI
    /// synchronously (no light-client round-trip).
    fn usdc() -> Address {
        address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
    }

    #[test]
    fn known_address_loads_contract_synchronously() {
        let mut app = safe_app();
        let out = app.update(Message::AddrChanged(usdc().to_string()));
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
        let mut app = TxBuilderApp::new(Address::repeat_byte(0x11));
        app.set_context(Chain::Mainnet, false, None, false, Vec::new()); // EOA, cannot delegate
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
        let mut app = TxBuilderApp::new(Address::repeat_byte(0x11));
        app.set_context(Chain::Mainnet, false, None, true, Vec::new()); // EOA, Local/Ledger
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
    fn auto_revoke_appends_revoke_to_effective_calls() {
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
        // On: one revoke appended.
        app.auto_revoke = true;
        let eff = app.effective_calls();
        assert_eq!(eff.len(), 2);
        assert_eq!(eff[1].to, usdc);
        assert_eq!(U256::from_be_slice(&eff[1].data[36..68]), U256::ZERO);
        // A non-batching EOA never appends (nothing to batch into).
        app.set_context(Chain::Mainnet, false, None, false, Vec::new());
        assert_eq!(app.effective_calls().len(), 1, "no batching → no revoke");
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
            Some(Outcome::Review { calls }) => assert_eq!(calls.len(), 2),
            other => panic!("expected Review, got {other:?}"),
        }
    }

    /// A resolve answer for a plain (non-proxy) address: the code is the
    /// target's own and every read on the way was verified.
    fn plain_code(target: Address, code: &[u8]) -> ResolvedCode {
        ResolvedCode {
            code: Bytes::copy_from_slice(code),
            implementation: target,
            all_verified: true,
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
                code: Bytes::from(crate::decode::bytecode::tiny_transfer_runtime()),
                implementation: impl_addr,
                all_verified: true,
            }),
        );
        let loaded = app.loaded.as_ref().expect("proxy ABI loaded");
        // Methods came from the implementation; the call still goes to the proxy.
        assert_eq!(loaded.address, proxy);
        assert_eq!(loaded.proxy_impl, Some(impl_addr));
        assert!(!app.proxy_unverified);
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
                code: Bytes::new(),
                implementation: proxy,
                all_verified: false,
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
                code: Bytes::new(),
                implementation: proxy,
                all_verified: false,
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
                code: Bytes::new(),
                implementation: a,
                all_verified: false,
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
        let mut app = TxBuilderApp::new(Address::repeat_byte(0x11));
        // EOA, 7702-capable, with one enabled custom network (Sepolia).
        app.set_context(
            Chain::Mainnet,
            false,
            None,
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
        app.set_context(Chain::Base, true, Some("1.4.1".into()), false, Vec::new());

        assert_eq!(app.selected_net(), NetworkId::Builtin(Chain::Base));
        assert!(
            app.batch.is_empty(),
            "an implicit re-pin drops the queue too"
        );
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
        let mut app = TxBuilderApp::new(Address::repeat_byte(0x5a));
        app.set_context(Chain::Base, true, Some("1.4.1".into()), false, Vec::new());
        assert_eq!(app.selected_net(), NetworkId::Builtin(Chain::Base));
        // A Safe pins the network — the switcher is inert.
        app.update(Message::ToggleNetworkMenu);
        assert!(!app.net_menu_open, "Safe never opens the switcher");
        app.update(Message::SetNetwork(NetworkId::Builtin(Chain::Optimism)));
        // set_context runs before every message and re-pins to the Safe's chain.
        app.set_context(Chain::Base, true, Some("1.4.1".into()), false, Vec::new());
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
            Some(Outcome::Review { calls }) => assert_eq!(calls.len(), 1),
            other => panic!("expected single-call Review, got {other:?}"),
        }
        assert!(app.batch.is_empty(), "single send never touches the batch");
    }

    #[test]
    fn removed_custom_network_falls_back_to_mainnet() {
        let mut app = eoa_app();
        app.update(Message::SetNetwork(NetworkId::Custom(11155111)));
        assert!(app.is_custom());
        // Next context refresh no longer lists that custom network.
        app.set_context(Chain::Mainnet, false, None, true, Vec::new());
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
            Some(Outcome::PersistTemplates(list)) => {
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
            Some(Outcome::PersistTemplates(list)) => assert!(list.is_empty()),
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
            Some(Outcome::PersistTemplates(list)) => assert_eq!(list[0].name, "Payroll run"),
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
