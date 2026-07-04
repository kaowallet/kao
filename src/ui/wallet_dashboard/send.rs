//! Send modal — multi-step wizard (recipient → amount → review → success).
//!
//! Handles both EOA sends and Safe sends through a single adaptive `SendPane`
//! that branches on a `SendMode` enum. EOA sends go through a quote-based
//! gas estimate and clear-signing decode; Safe sends pin a reviewed
//! `(nonce, safeTxHash)` and optionally propose to co-signers via the
//! Transaction Service.
//!
//! The pane carries no signer or RPC access. It bubbles outcomes upward to
//! the dashboard, which holds the `KaoSigner` and `BalanceFetcher::provider()`
//! and runs the actual tasks. Results flow back through messages.

use std::str::FromStr;

use alloy::primitives::utils::format_units;
use alloy::primitives::{Address, B256, Bytes, TxHash, U256};
use iced::border::Radius;
use iced::keyboard;
use iced::widget::{Space, button, column, container, row, scrollable, text, text_input};
use iced::{Alignment, Background, Border, Color, Element, Length, Padding, Subscription, Task};

use super::home::{format_symbol, network_display_name, network_label};
use crate::chain::Chain;
use crate::decode::clear_sign::DecodeResult;
use crate::names;
use crate::portfolio::LiveToken;
use crate::safe::tx::{Operation, SafeTxInput};
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::{
    CopyKick, avatar, black, bold, colored_address, colored_hash_copyable, ghost_button, hint_pill,
    hover_tint, kao_fit, kao_fit_size, kao_scrollable_style, kao_text, kaomoji_for_account,
    kaomoji_for_index, modal_wrapper, mono, mono_black, mono_bold, primary_button,
    secondary_button, text_input_style, token_avatar, vspace,
};
use crate::ui::wallet_dashboard::function_panel;
use crate::ui::wallet_dashboard::sim_view;
use crate::ui::wallet_dashboard::sim_view::simulation_block;
use crate::wallet::sim::{SimOutcome, SimulationResult};
use crate::wallet::tx::{
    SendPlan, SendToken, TxQuote, erc20_transfer_calldata, parse_amount_units,
};
use crate::wallet::{
    AccountDescriptor, ContactsBook, SafeDescriptor, SafeTrust, account_address, short_address,
};

// ── Picker types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickerKind {
    Contact,
    OwnAccount,
    OwnSafe,
}

#[derive(Debug, Clone)]
pub struct PickerEntry {
    pub name: String,
    pub address: Address,
    pub kaomoji: String,
    pub kind: PickerKind,
    pub ens: Option<String>,
    pub chip: Option<&'static str>,
}

#[derive(Debug, Clone, Default)]
pub struct ContactsView {
    pub entries: Vec<PickerEntry>,
}

impl ContactsView {
    pub fn merged(
        book: &ContactsBook,
        accounts: &[AccountDescriptor],
        safes: &[SafeDescriptor],
        exclude_account: Option<usize>,
        exclude_safe: Option<usize>,
    ) -> Self {
        let mut entries: Vec<PickerEntry> = book.iter().map(picker_entry_from_contact).collect();
        let mut seen: std::collections::HashSet<Address> =
            entries.iter().map(|e| e.address).collect();
        for (idx, acc) in accounts.iter().enumerate() {
            if exclude_account == Some(idx) {
                continue;
            }
            let Some(addr) = account_address(acc) else {
                continue;
            };
            if !seen.insert(addr) {
                continue;
            }
            let chip: &'static str = match acc {
                AccountDescriptor::Local { .. } => "Local",
                AccountDescriptor::Ledger { .. } => "Ledger",
                AccountDescriptor::Trezor { .. } => "Trezor",
                AccountDescriptor::ViewOnly { .. } => "View only",
            };
            entries.push(PickerEntry {
                name: acc.display_name(idx),
                address: addr,
                kaomoji: kaomoji_for_account(idx).to_string(),
                kind: PickerKind::OwnAccount,
                ens: None,
                chip: Some(chip),
            });
        }
        for (idx, safe) in safes.iter().enumerate() {
            if exclude_safe == Some(idx) {
                continue;
            }
            let addr = safe.address();
            if !seen.insert(addr) {
                continue;
            }
            let watch_only = safe.linked_signer_indices.is_empty();
            let kao = if watch_only {
                "(◐_◐)"
            } else {
                "(◐‿◐)"
            };
            let chip = if watch_only { "Safe watch" } else { "Safe" };
            entries.push(PickerEntry {
                name: safe.display_name(idx),
                address: addr,
                kaomoji: kao.to_string(),
                kind: PickerKind::OwnSafe,
                ens: None,
                chip: Some(chip),
            });
        }
        Self { entries }
    }

    pub fn name_for(&self, addr: Address) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.address == addr)
            .map(|e| e.name.as_str())
    }
}

fn picker_entry_from_contact(c: &crate::wallet::Contact) -> PickerEntry {
    let kao = if c.kaomoji.is_empty() {
        "(◕‿◕)".to_string()
    } else {
        c.kaomoji.clone()
    };
    PickerEntry {
        name: c.name.clone(),
        address: c.address(),
        kaomoji: kao,
        kind: PickerKind::Contact,
        ens: c.ens.as_ref().map(|e| e.name.clone()),
        chip: None,
    }
}

// ── Message + Outcome + Resolution ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Message {
    /// No-op published by a copyable address click so the dashboard's "Copied!"
    /// toast animation starts (a click changes no state otherwise). Ignored.
    AddressCopied,
    SetTo(String),
    PickRecipient {
        address: Address,
        ens: Option<String>,
    },
    SetAmount(String),
    SetToken(usize),
    Max,
    Step(u8),
    BroadcastDone(Result<TxHash, String>),
    EnsResolved {
        seq: u64,
        name: String,
        result: Result<Option<Address>, String>,
    },
    AdvanceToDone,
    SendAnother,
    CopyHash,
    CopyEtherscan,
    CopyExplorerLink,
    Close,
    BoxClickIgnored,
    SaveAsContactClicked,
    AcceptEnsDivergence,
    ProposeDone(Result<(), String>),
    Key(keyboard::Event),
}

#[derive(Debug, Clone)]
enum Resolution {
    Empty,
    Invalid,
    Address(Address),
    Resolving {
        name: String,
    },
    AddressVerifying {
        pinned: Address,
        name: String,
    },
    Resolved {
        name: String,
        addr: Address,
    },
    NotFound {
        name: String,
    },
    Error {
        name: String,
        msg: String,
    },
    EnsDivergence {
        name: String,
        pinned: Address,
        fresh: Address,
    },
}

impl Resolution {
    fn recipient(&self) -> Option<Address> {
        match self {
            Resolution::Address(a)
            | Resolution::Resolved { addr: a, .. }
            | Resolution::AddressVerifying { pinned: a, .. } => Some(*a),
            _ => None,
        }
    }

    /// Variant name for the GUI state trace.
    fn name(&self) -> &'static str {
        match self {
            Resolution::Empty => "Empty",
            Resolution::Invalid => "Invalid",
            Resolution::Address(_) => "Address",
            Resolution::Resolving { .. } => "Resolving",
            Resolution::AddressVerifying { .. } => "AddressVerifying",
            Resolution::Resolved { .. } => "Resolved",
            Resolution::NotFound { .. } => "NotFound",
            Resolution::Error { .. } => "Error",
            Resolution::EnsDivergence { .. } => "EnsDivergence",
        }
    }
}

#[derive(Debug, Clone)]
pub enum Outcome {
    Closed,
    CopyText(String),
    SaveAsContact {
        address: Address,
        ens: Option<String>,
    },
}

impl Outcome {
    /// Variant name for the GUI state trace — never the payload.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Closed => "Closed",
            Outcome::CopyText(_) => "CopyText",
            Outcome::SaveAsContact { .. } => "SaveAsContact",
        }
    }
}

// ── Mode-specific state ────────────────────────────────────────────────────

#[derive(Debug)]
struct EoaState {
    from: Address,
    broadcast_done: bool,
}

#[derive(Debug)]
struct SafeState {
    safe_address: Address,
    safe_chain: Option<Chain>,
    safe_chain_id: u64,
    safe_version: String,
    trust: SafeTrust,
    service_base: String,
    version_block: Option<String>,
    threshold: u32,
    linked_local_indices: Vec<u32>,
    signable_indices: Vec<u32>,
    unsupported_owner_kinds: Vec<&'static str>,
    /// Set once a propose succeeds — drives the success screen's copy.
    proposed: bool,
}

// The Safe arm carries a lot more state (owner set, simulation, tx-service
// context) than the EOA arm, and there's only ever one live `SendMode` per open
// modal — boxing it would just add an indirection to every field access for no
// real gain. Same call as the other single-instance sign enums in this crate.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum SendMode {
    Eoa(EoaState),
    Safe(SafeState),
}

const SAFE_TOTAL_STEPS: u8 = 3;

// ── SendPane ───────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct SendPane {
    step: u8,
    to: String,
    resolution: Resolution,
    resolution_seq: u64,
    last_dispatched_seq: Option<u64>,
    amount: String,
    token_idx: usize,
    busy: bool,
    error: Option<String>,
    last_tx_hash: Option<TxHash>,
    mode: SendMode,
}

/// Cheap names of the pane's coarse state, captured before/after a
/// dispatch in the `update` wrapper so every transition is logged no
/// matter which arm performed it.
struct TraceSnapshot {
    step: &'static str,
    busy: bool,
    error: bool,
    resolution: &'static str,
    proposed: bool,
    tx_hash: bool,
}

impl SendPane {
    pub fn new_eoa(from: Address) -> Self {
        Self {
            step: 0,
            to: String::new(),
            resolution: Resolution::Empty,
            resolution_seq: 0,
            last_dispatched_seq: None,
            amount: String::new(),
            token_idx: 0,
            busy: false,
            error: None,
            last_tx_hash: None,
            mode: SendMode::Eoa(EoaState {
                from,
                broadcast_done: false,
            }),
        }
    }

    pub fn new_safe(safe: &SafeDescriptor, accounts: &[AccountDescriptor]) -> Self {
        let mut linked_local_indices = Vec::new();
        let mut signable_indices = Vec::new();
        let mut unsupported_owner_kinds = Vec::new();
        for &idx in &safe.linked_signer_indices {
            match accounts.get(idx as usize) {
                // Local **and** hardware owners can sign: software via a
                // local key, Ledger/Trezor on-device through EIP-712. Only
                // view-only owners (no key material) are unsupported.
                Some(
                    acc @ (AccountDescriptor::Local { .. }
                    | AccountDescriptor::Ledger { .. }
                    | AccountDescriptor::Trezor { .. }),
                ) => {
                    signable_indices.push(idx);
                    if matches!(acc, AccountDescriptor::Local { .. }) {
                        linked_local_indices.push(idx);
                    }
                }
                Some(AccountDescriptor::ViewOnly { .. }) => {
                    unsupported_owner_kinds.push("View only")
                }
                None => {}
            }
        }
        let chain = Chain::ALL
            .iter()
            .find(|c| c.chain_id() == safe.chain_id)
            .copied();
        Self {
            step: 0,
            to: String::new(),
            resolution: Resolution::Empty,
            resolution_seq: 0,
            last_dispatched_seq: None,
            amount: String::new(),
            token_idx: 0,
            busy: false,
            error: None,
            last_tx_hash: None,
            mode: SendMode::Safe(SafeState {
                safe_address: safe.address(),
                safe_chain: chain,
                safe_chain_id: safe.chain_id,
                safe_version: safe.version.clone(),
                trust: safe.trust.clone(),
                service_base: safe.tx_service_base().to_string(),
                version_block: crate::safe::tx::ensure_signable_version(&safe.version).err(),
                threshold: safe.threshold,
                linked_local_indices,
                signable_indices,
                unsupported_owner_kinds,
                proposed: false,
            }),
        }
    }

    fn eoa(&self) -> Option<&EoaState> {
        match &self.mode {
            SendMode::Eoa(s) => Some(s),
            _ => None,
        }
    }
    fn safe(&self) -> Option<&SafeState> {
        match &self.mode {
            SendMode::Safe(s) => Some(s),
            _ => None,
        }
    }
    pub fn is_eoa(&self) -> bool {
        matches!(self.mode, SendMode::Eoa(_))
    }
    pub fn is_safe(&self) -> bool {
        matches!(self.mode, SendMode::Safe(_))
    }

    pub fn busy(&self) -> bool {
        self.busy
    }
    pub fn token_idx(&self) -> usize {
        self.token_idx
    }
    /// The raw amount string the user typed (e.g. `"1.5"`), snapshotted into the
    /// sign-review overlay so the review shows exactly what was entered.
    pub fn amount_str(&self) -> &str {
        &self.amount
    }
    /// The ENS/name the recipient resolved to, if any — used as the review's
    /// recipient label when the address isn't a saved contact.
    pub fn recipient_display_name(&self) -> Option<String> {
        match &self.resolution {
            Resolution::Resolved { name, .. } => Some(name.clone()),
            _ => None,
        }
    }
    pub fn apply_max(&mut self, amount_str: String) {
        self.amount = amount_str;
    }

    pub fn take_pending_ens(&mut self) -> Option<(u64, String)> {
        match &self.resolution {
            Resolution::Resolving { name } | Resolution::AddressVerifying { name, .. }
                if self.last_dispatched_seq != Some(self.resolution_seq) =>
            {
                let seq = self.resolution_seq;
                self.last_dispatched_seq = Some(seq);
                Some((seq, name.clone()))
            }
            _ => None,
        }
    }

    fn set_to(&mut self, raw: String) {
        self.to = raw;
        self.resolution_seq = self.resolution_seq.wrapping_add(1);
        let trimmed = self.to.trim();
        self.resolution = if trimmed.is_empty() {
            Resolution::Empty
        } else if let Ok(addr) = Address::from_str(trimmed) {
            // The zero address is a burn hole, never a real recipient —
            // surface it as invalid rather than letting it ride into a plan.
            if addr.is_zero() {
                Resolution::Invalid
            } else {
                Resolution::Address(addr)
            }
        } else if names::looks_like_name(trimmed) {
            Resolution::Resolving {
                name: trimmed.to_string(),
            }
        } else {
            Resolution::Invalid
        };
    }

    fn parsed_amount(&self, decimals: u8) -> Option<U256> {
        let trimmed = self.amount.trim();
        if trimmed.is_empty() || trimmed.starts_with('-') {
            return None;
        }
        parse_amount_units(trimmed, decimals).ok()
    }

    pub fn build_plan(&self, portfolio: &[LiveToken]) -> Option<SendPlan> {
        let eoa = self.eoa()?;
        let recipient = self.resolution.recipient()?;
        // Defence in depth behind `set_to`/`recipient()`: never build a plan
        // that sends to the zero address, regardless of how `recipient` was
        // populated (typed, pasted, picked from a contact, or ENS-resolved).
        if recipient.is_zero() {
            return None;
        }
        let token = portfolio.get(self.token_idx)?;
        let amount_units = parse_amount_units(&self.amount, token.decimals).ok()?;
        if amount_units.is_zero() || amount_units > token.balance_raw {
            return None;
        }
        let send_token = match token.contract {
            None => SendToken::Native,
            Some(addr) => SendToken::Erc20 { contract: addr },
        };
        Some(SendPlan {
            from: eoa.from,
            recipient,
            token: send_token,
            amount_units,
            chain: token.chain,
        })
    }

    /// True when this wallet holds at least `threshold` *signable* linked
    /// owners (Local or hardware) — enough to sign and broadcast the Safe
    /// transaction directly, rather than proposing to remote co-signers.
    /// A 1/1 Safe owned by a single Ledger/Trezor satisfies this.
    pub fn has_enough_signable_signers(&self) -> bool {
        self.safe()
            .is_some_and(|s| (s.signable_indices.len() as u32) >= s.threshold)
    }
    pub fn has_any_signable(&self) -> bool {
        self.safe().is_some_and(|s| !s.signable_indices.is_empty())
    }

    fn can_continue_recipient(&self) -> bool {
        match &self.mode {
            SendMode::Eoa(_) => {
                self.resolution.recipient().is_some()
                    && !matches!(self.resolution, Resolution::EnsDivergence { .. })
            }
            SendMode::Safe(s) => {
                s.safe_chain.is_some()
                    && s.version_block.is_none()
                    && s.trust.permits_signing()
                    && self.has_any_signable()
                    && self.resolution.recipient().is_some()
                    && !matches!(self.resolution, Resolution::EnsDivergence { .. })
            }
        }
    }

    pub fn outgoing_request(&self, portfolio: &[LiveToken]) -> Option<SafeSendRequest> {
        let s = self.safe()?;
        if s.version_block.is_some() {
            return None;
        }
        if s.trust.signing_block_reason().is_some() {
            return None;
        }
        let recipient = self.resolution.recipient()?;
        // Same zero-address guard as `build_plan`. Every Safe signing path
        // (prepare / broadcast / propose) re-derives the request here, so one
        // check keeps a zero-recipient SafeTx from ever being built or signed.
        if recipient.is_zero() {
            return None;
        }
        let token = portfolio.get(self.token_idx)?;
        let amount_units = self.parsed_amount(token.decimals)?;
        let send_token = match token.contract {
            None => SendToken::Native,
            Some(addr) => SendToken::Erc20 { contract: addr },
        };
        Some(SafeSendRequest {
            safe_address: s.safe_address,
            chain: s.safe_chain?,
            version: s.safe_version.clone(),
            trust: s.trust.clone(),
            service_base: s.service_base.clone(),
            recipient,
            amount_units,
            token: send_token,
            threshold: s.threshold,
            signable_indices: s.signable_indices.clone(),
            // The reviewed `(nonce, safeTxHash)` pin is computed by the overlay's
            // prepare and stitched into the request there (`SignReviewPrepared`),
            // so the request built here for opening the review carries none yet.
            prepared: None,
        })
    }

    pub fn mark_busy(&mut self) {
        // Dashboard-driven flip (outside this pane's update wrapper), so
        // log it here to keep the busy flag observable in the trace.
        if !self.busy {
            crate::trace::state("send", "busy", false, true);
        }
        self.busy = true;
        self.error = None;
    }

    // ── Trace helpers ────────────────────────────────────────────────────

    /// Semantic step name for the GUI state trace.
    fn step_name(&self) -> &'static str {
        match (&self.mode, self.step) {
            (SendMode::Eoa(_), 0) | (SendMode::Safe(_), 0) => "recipient",
            (SendMode::Eoa(_), 1) | (SendMode::Safe(_), 1) => "amount",
            (SendMode::Eoa(_), 2) | (SendMode::Safe(_), 2) => "review",
            (SendMode::Eoa(_), 3) => "broadcast",
            (SendMode::Eoa(_), _) => "success",
            (SendMode::Safe(_), _) => "done",
        }
    }

    fn trace_snapshot(&self) -> TraceSnapshot {
        let proposed = matches!(&self.mode, SendMode::Safe(s) if s.proposed);
        TraceSnapshot {
            step: self.step_name(),
            busy: self.busy,
            error: self.error.is_some(),
            resolution: self.resolution.name(),
            proposed,
            tx_hash: self.last_tx_hash.is_some(),
        }
    }

    pub fn update(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("send", &msg);
        let before = self.trace_snapshot();
        let (task, outcome) = self.update_inner(msg);
        let after = self.trace_snapshot();
        if before.step != after.step {
            crate::trace::state("send", "step", before.step, after.step);
        }
        if before.busy != after.busy {
            crate::trace::state("send", "busy", before.busy, after.busy);
        }
        if before.error != after.error {
            let s = |shown: bool| if shown { "shown" } else { "none" };
            crate::trace::state("send", "error", s(before.error), s(after.error));
        }
        if before.resolution != after.resolution {
            crate::trace::state("send", "resolution", before.resolution, after.resolution);
        }
        if before.proposed != after.proposed {
            crate::trace::state("send", "proposed", before.proposed, after.proposed);
        }
        if before.tx_hash != after.tx_hash {
            let s = |set: bool| if set { "set" } else { "none" };
            crate::trace::state("send", "tx_hash", s(before.tx_hash), s(after.tx_hash));
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("send", o.name());
        }
        (task, outcome)
    }

    fn update_inner(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        match msg {
            // Copy-toast kick — the widget already copied + marked the toast.
            Message::AddressCopied => (Task::none(), None),
            Message::SetTo(s) => {
                self.set_to(s);
                self.error = None;
                (Task::none(), None)
            }
            Message::PickRecipient { address, ens } => {
                self.resolution_seq = self.resolution_seq.wrapping_add(1);
                self.to = address.to_checksum(None);
                self.resolution = match ens {
                    Some(name) => Resolution::AddressVerifying {
                        pinned: address,
                        name,
                    },
                    None => Resolution::Address(address),
                };
                (Task::none(), None)
            }
            Message::EnsResolved { seq, name, result } => {
                if seq != self.resolution_seq {
                    return (Task::none(), None);
                }
                match &self.resolution {
                    Resolution::Resolving { name: pending } if pending == &name => {
                        self.resolution = match result {
                            Ok(Some(addr)) => Resolution::Resolved { name, addr },
                            Ok(None) => Resolution::NotFound { name },
                            Err(msg) => Resolution::Error { name, msg },
                        };
                    }
                    Resolution::AddressVerifying {
                        pinned,
                        name: pending,
                    } if pending == &name => {
                        let pinned = *pinned;
                        self.resolution = match result {
                            Ok(Some(fresh)) if fresh == pinned => Resolution::Address(pinned),
                            Ok(Some(fresh)) => Resolution::EnsDivergence {
                                name,
                                pinned,
                                fresh,
                            },
                            Ok(None) | Err(_) => Resolution::Address(pinned),
                        };
                    }
                    _ => {}
                }
                (Task::none(), None)
            }
            Message::AcceptEnsDivergence => {
                if let Resolution::EnsDivergence { fresh, .. } = self.resolution.clone() {
                    self.resolution = Resolution::Address(fresh);
                }
                (Task::none(), None)
            }
            Message::SaveAsContactClicked => {
                let (addr, ens) = match &self.resolution {
                    Resolution::Address(a) => (*a, None),
                    Resolution::Resolved { addr, name } => (*addr, Some(name.clone())),
                    _ => return (Task::none(), None),
                };
                (
                    Task::none(),
                    Some(Outcome::SaveAsContact { address: addr, ens }),
                )
            }
            Message::SetAmount(s) => {
                self.amount = s;
                self.error = None;
                (Task::none(), None)
            }
            Message::SetToken(i) => {
                self.token_idx = i;
                if let SendMode::Safe(_) = &self.mode {
                    self.amount.clear();
                }
                self.error = None;
                (Task::none(), None)
            }
            Message::Max => (Task::none(), None),
            Message::Step(s) => {
                match &self.mode {
                    SendMode::Eoa(_) => {
                        if s <= 4 {
                            self.step = s;
                        }
                    }
                    // Safe collects recipient (0) + amount (1); "Review →" is
                    // intercepted by the dashboard to open the sign-review overlay
                    // (Step(2) never reaches the pane), and the success screen (3)
                    // is reached from the overlay's result. Only 0/1 land here.
                    SendMode::Safe(_) => match s {
                        0 => self.step = 0,
                        1 if self.can_continue_recipient() => self.step = 1,
                        _ => {}
                    },
                }
                (Task::none(), None)
            }
            Message::BroadcastDone(result) => {
                self.busy = false;
                match &mut self.mode {
                    SendMode::Eoa(eoa) => match result {
                        Ok(hash) => {
                            self.last_tx_hash = Some(hash);
                            eoa.broadcast_done = true;
                            self.error = None;
                        }
                        // The overlay stays up showing the failure (see the
                        // coordinator's `SendBroadcastReturn`); the pane just
                        // records the error and clears busy for the retry.
                        Err(e) => {
                            self.error = Some(e);
                        }
                    },
                    SendMode::Safe(_) => match result {
                        Ok(hash) => {
                            self.last_tx_hash = Some(hash);
                            self.error = None;
                            self.step = 3;
                        }
                        Err(e) => {
                            self.error = Some(e);
                        }
                    },
                }
                (Task::none(), None)
            }
            Message::AdvanceToDone => {
                if let SendMode::Eoa(eoa) = &self.mode
                    && eoa.broadcast_done
                {
                    self.step = 4;
                }
                (Task::none(), None)
            }
            Message::SendAnother => {
                if let SendMode::Eoa(eoa) = &self.mode {
                    let from = eoa.from;
                    *self = Self::new_eoa(from);
                }
                (Task::none(), None)
            }
            Message::CopyHash => match self.last_tx_hash {
                Some(h) => (Task::none(), Some(Outcome::CopyText(format!("{h:#x}")))),
                None => (Task::none(), None),
            },
            Message::CopyEtherscan => match self.last_tx_hash {
                Some(h) if self.is_eoa() => (
                    Task::none(),
                    Some(Outcome::CopyText(format!("https://etherscan.io/tx/{h:#x}"))),
                ),
                _ => (Task::none(), None),
            },
            Message::CopyExplorerLink => {
                match (self.last_tx_hash, self.safe().and_then(|s| s.safe_chain)) {
                    (Some(h), Some(chain)) => {
                        let url = format!("{}/tx/{h:#x}", chain.default_blockscout_url());
                        (Task::none(), Some(Outcome::CopyText(url)))
                    }
                    _ => (Task::none(), None),
                }
            }
            Message::ProposeDone(Ok(())) => {
                if let SendMode::Safe(s) = &mut self.mode {
                    self.busy = false;
                    s.proposed = true;
                    self.error = None;
                    self.step = 3;
                }
                (Task::none(), None)
            }
            Message::ProposeDone(Err(e)) => {
                if self.is_safe() {
                    self.busy = false;
                    self.error = Some(e);
                }
                (Task::none(), None)
            }
            Message::Close => (Task::none(), Some(Outcome::Closed)),
            Message::BoxClickIgnored => (Task::none(), None),
            Message::Key(keyboard::Event::KeyPressed { key, .. }) => {
                if let keyboard::Key::Named(keyboard::key::Named::Escape) = key {
                    match &self.mode {
                        SendMode::Eoa(_) => {
                            if matches!(self.step, 1 | 2) && !self.busy {
                                self.step -= 1;
                                (Task::none(), None)
                            } else {
                                (Task::none(), Some(Outcome::Closed))
                            }
                        }
                        SendMode::Safe(_) => (Task::none(), Some(Outcome::Closed)),
                    }
                } else {
                    (Task::none(), None)
                }
            }
            Message::Key(_) => (Task::none(), None),
        }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        keyboard::listen().map(Message::Key)
    }

    // ── View ────────────────────────────────────────────────────────────

    pub fn view<'a>(
        &'a self,
        t: KaoTheme,
        portfolio: &'a [LiveToken],
        contacts: ContactsView,
        progress: f32,
    ) -> Element<'a, Message> {
        // Safe pre-flight guards
        if let SendMode::Safe(s) = &self.mode {
            if s.safe_chain.is_none() {
                let body = column![
                    safe_step_header(t, 0),
                    safe_progress_bar(t, 0),
                    vspace(20),
                    unsupported_chain_banner(t, s.safe_chain_id),
                    vspace(16),
                    primary_button(t, "Close", true).on_press(Message::Close),
                ]
                .width(Length::Fill);
                return wrap_safe_modal(t, progress, body.into());
            }
            if let Some(reason) = &s.version_block {
                let body = column![
                    safe_step_header(t, 0),
                    safe_progress_bar(t, 0),
                    vspace(20),
                    banner(t, "Unsupported Safe version", reason.clone()),
                    vspace(16),
                    primary_button(t, "Close", true).on_press(Message::Close),
                ]
                .width(Length::Fill);
                return wrap_safe_modal(t, progress, body.into());
            }
            if let Some(reason) = s.trust.signing_block_reason() {
                let body = column![
                    safe_step_header(t, 0),
                    safe_progress_bar(t, 0),
                    vspace(20),
                    banner(t, "Unrecognized Safe implementation", reason.to_string()),
                    vspace(16),
                    primary_button(t, "Close", true).on_press(Message::Close),
                ]
                .width(Length::Fill);
                return wrap_safe_modal(t, progress, body.into());
            }
            if !self.has_any_signable() {
                let body = column![
                    safe_step_header(t, 0),
                    safe_progress_bar(t, 0),
                    vspace(20),
                    preflight_banner(
                        t,
                        s.threshold,
                        s.linked_local_indices.len(),
                        &s.unsupported_owner_kinds
                    ),
                    vspace(16),
                    primary_button(t, "Close", true).on_press(Message::Close),
                ]
                .width(Length::Fill);
                return wrap_safe_modal(t, progress, body.into());
            }
        }

        let recipient_name: Option<String> = self
            .resolution
            .recipient()
            .and_then(|a| contacts.name_for(a).map(|s| s.to_string()));
        let recipient_in_book = self
            .resolution
            .recipient()
            .map(|a| contacts.name_for(a).is_some())
            .unwrap_or(false);

        match &self.mode {
            SendMode::Eoa(_) => {
                // Review (step 2) and broadcast/waiting (step 3) now live in the
                // unified `sign_review` overlay, which stacks over this pane; the
                // pane hosts recipient (0) / amount (1) and the success screen (4).
                let inner: Element<'_, Message> = match self.step {
                    0 => self.step_recipient(
                        t,
                        contacts.entries,
                        recipient_name.clone(),
                        recipient_in_book,
                    ),
                    1 => self.step_amount(t, portfolio, recipient_name.clone()),
                    _ => self.step_success_eoa(t, portfolio, recipient_name),
                };

                let step_kao = match self.step {
                    0 => "(・・;)ゞ",
                    1 => "( •̀ω•́ )✧",
                    2 => "(・_・ヾ",
                    3 => "( ˙▿˙ )",
                    _ => "ヽ(・∀・)ﾉ",
                };
                let head_title = match self.step {
                    3 => "Broadcasting",
                    4 => "Complete",
                    _ => "Send",
                };
                let mut head_col = column![].spacing(2);
                head_col = head_col.push(text(head_title).size(22).color(t.text).font(black()));
                if self.step < 3 {
                    head_col = head_col.push(
                        text(format!("Step {} of 3", self.step + 1))
                            .size(12)
                            .color(t.sub)
                            .font(mono()),
                    );
                }
                let mut head = row![head_col, Space::new().width(Length::Fill)]
                    .align_y(Alignment::Start)
                    .width(Length::Fill);
                if self.step != 2 {
                    head = head.push(kao_text(t, step_kao, 30.0));
                }

                let mut content = column![head].spacing(0);
                content = content.push(Space::new().height(20));
                if self.step < 3 {
                    content = content.push(self.eoa_progress_bar(t));
                    content = content.push(Space::new().height(16));
                }
                content = content.push(inner);
                modal_wrapper(
                    t,
                    440.0,
                    progress,
                    Message::Close,
                    Message::BoxClickIgnored,
                    content.into(),
                )
            }
            SendMode::Safe(_) => {
                // Review (step 2) now lives in the unified sign-review overlay,
                // which stacks over this pane; the pane hosts recipient (0),
                // amount (1), and the success screen (3).
                let body: Element<'_, Message> = match self.step {
                    0 => self.view_recipient_safe(t, contacts.entries, recipient_in_book),
                    1 => self.step_amount(t, portfolio, recipient_name.clone()),
                    _ => self.view_success_safe(t, recipient_name, portfolio),
                };
                wrap_safe_modal(t, progress, body)
            }
        }
    }

    fn eoa_progress_bar<'a>(&self, t: KaoTheme) -> Element<'a, Message> {
        let mut r = row![].spacing(5).width(Length::Fill);
        for i in 0..3u8 {
            let col = if i <= self.step.min(2) {
                t.a1
            } else {
                t.border
            };
            r = r.push(
                container(Space::new().width(Length::Fill).height(4))
                    .width(Length::Fill)
                    .style(move |_| container::Style {
                        background: Some(Background::Color(col)),
                        border: Border {
                            color: col,
                            width: 0.0,
                            radius: Radius::from(2),
                        },
                        ..container::Style::default()
                    }),
            );
        }
        r.into()
    }

    fn step_recipient<'a>(
        &'a self,
        t: KaoTheme,
        snapshot: Vec<PickerEntry>,
        recipient_name: Option<String>,
        recipient_in_book: bool,
    ) -> Element<'a, Message> {
        // Safe adds a summary card at top
        let safe_card: Element<'_, Message> = match &self.mode {
            SendMode::Safe(s) => {
                let chain = s.safe_chain.expect("safe_chain gated by view()");
                column![
                    safe_summary(t, s.safe_address, chain),
                    Space::new().height(16)
                ]
                .into()
            }
            _ => Space::new().height(0).into(),
        };

        let label = text("TO").size(11).color(t.sub).font(if self.is_safe() {
            mono_bold()
        } else {
            bold()
        });
        let input = text_input("0x… address or a name (.eth / .gwei / .wei)", &self.to)
            .on_input(Message::SetTo)
            .padding(Padding::from([12, 14]))
            .size(15)
            .font(mono())
            .style(move |_, status| text_input_style(t, status));

        let parse_hint: Element<'_, Message> = match &self.resolution {
            Resolution::Empty => Space::new().height(0).into(),
            Resolution::Address(addr) => match &recipient_name {
                Some(name) => container(
                    row![
                        text(format!("✓ {name}  ·  "))
                            .size(11)
                            .color(t.up)
                            .font(bold()),
                        text(short_address_str(&format!("{addr:#x}")))
                            .size(11)
                            .color(t.sub)
                            .font(mono()),
                    ]
                    .align_y(Alignment::Center),
                )
                .padding(Padding::from([4, 0]))
                .into(),
                None => container(
                    row![
                        text("✓ valid address").size(11).color(t.up).font(bold()),
                        Space::new().width(8),
                        text(short_address_str(&format!("{addr:#x}")))
                            .size(11)
                            .color(t.sub)
                            .font(mono()),
                    ]
                    .align_y(Alignment::Center),
                )
                .padding(Padding::from([4, 0]))
                .into(),
            },
            Resolution::AddressVerifying { pinned, name } => container(
                column![
                    row![
                        text(format!("✓ {name}  ·  "))
                            .size(11)
                            .color(t.up)
                            .font(bold()),
                        text(short_address_str(&format!("{pinned:#x}")))
                            .size(11)
                            .color(t.sub)
                            .font(mono()),
                    ]
                    .align_y(Alignment::Center),
                    text("(verifying name…)").size(10).color(t.sub),
                ]
                .spacing(2),
            )
            .padding(Padding::from([4, 0]))
            .into(),
            Resolution::Resolved { name, addr } => container(
                row![
                    text(format!("✓ {name} →  "))
                        .size(11)
                        .color(t.up)
                        .font(bold()),
                    text(short_address_str(&format!("{addr:#x}")))
                        .size(11)
                        .color(t.sub)
                        .font(mono()),
                ]
                .align_y(Alignment::Center),
            )
            .padding(Padding::from([4, 0]))
            .into(),
            Resolution::Resolving { name } => container(
                text(format!("(；・∀・) resolving {name}…"))
                    .size(11)
                    .color(t.sub)
                    .font(bold()),
            )
            .padding(Padding::from([4, 0]))
            .into(),
            Resolution::NotFound { name } => container(
                text(format!("\u{201C}{name}\u{201D} has no address record"))
                    .size(11)
                    .color(t.down)
                    .font(bold()),
            )
            .padding(Padding::from([4, 0]))
            .into(),
            Resolution::Error { name, msg } => container(
                text(format!(
                    "Name lookup for \u{201C}{name}\u{201D} failed: {msg}"
                ))
                .size(11)
                .color(t.down)
                .font(bold()),
            )
            .padding(Padding::from([4, 0]))
            .into(),
            Resolution::EnsDivergence {
                name,
                pinned,
                fresh,
            } => {
                let b = column![
                    text(format!(
                        "⚠ \u{201C}{name}\u{201D} now resolves to a different address"
                    ))
                    .size(12)
                    .color(t.down)
                    .font(bold()),
                    Space::new().height(4),
                    row![
                        text("pinned: ").size(11).color(t.sub),
                        text(short_address_str(&format!("{pinned:#x}")))
                            .size(11)
                            .color(t.sub)
                            .font(mono())
                    ],
                    row![
                        text("now:    ").size(11).color(t.sub),
                        text(short_address_str(&format!("{fresh:#x}")))
                            .size(11)
                            .color(t.text)
                            .font(mono())
                    ],
                    Space::new().height(6),
                    secondary_button(t, "Use new address").on_press(Message::AcceptEnsDivergence),
                ]
                .spacing(2);
                container(b)
                    .padding(Padding::from([8, 10]))
                    .style(move |_| container::Style {
                        background: Some(Background::Color(t.ab1)),
                        border: Border {
                            color: t.down,
                            width: 1.0,
                            radius: Radius::from(8),
                        },
                        text_color: Some(t.text),
                        ..container::Style::default()
                    })
                    .into()
            }
            Resolution::Invalid => container(
                text("Not a valid 0x… address or name")
                    .size(11)
                    .color(t.down)
                    .font(bold()),
            )
            .padding(Padding::from([4, 0]))
            .into(),
        };

        let save_cta: Element<'_, Message> = match &self.resolution {
            Resolution::Address(_) | Resolution::Resolved { .. } if !recipient_in_book => {
                container(
                    secondary_button(t, "+ Save as contact")
                        .on_press(Message::SaveAsContactClicked),
                )
                .padding(Padding::from([6, 0]))
                .into()
            }
            _ => Space::new().height(0).into(),
        };

        let recent_label = text("RECIPIENTS").size(11).color(t.sub).font(bold());
        let contacts_block: Element<'_, Message> = if snapshot.is_empty() {
            container(
                text("No saved contacts yet — add some in Settings → Contacts")
                    .size(11)
                    .color(t.sub),
            )
            .padding(Padding::from([6, 4]))
            .into()
        } else {
            let mut col = column![].spacing(2);
            for entry in snapshot.into_iter() {
                col = col.push(picker_row(t, entry, &self.to));
            }
            scrollable(col)
                .height(Length::Fixed(168.0))
                .width(Length::Fill)
                .style(move |_, status| kao_scrollable_style(t, status))
                .into()
        };

        let can_continue = self.can_continue_recipient();
        let continue_btn =
            primary_button(t, "Continue →", can_continue).on_press_maybe(if can_continue {
                Some(Message::Step(1))
            } else {
                None
            });

        column![
            safe_card,
            label,
            Space::new().height(6),
            input,
            parse_hint,
            save_cta,
            Space::new().height(12),
            recent_label,
            Space::new().height(4),
            contacts_block,
            Space::new().height(16),
            continue_btn,
        ]
        .width(Length::Fill)
        .into()
    }

    // Safe-specific recipient view wraps step_recipient with safe header
    fn view_recipient_safe<'a>(
        &'a self,
        t: KaoTheme,
        snapshot: Vec<PickerEntry>,
        recipient_in_book: bool,
    ) -> Element<'a, Message> {
        let inner = self.step_recipient(t, snapshot, None, recipient_in_book);
        let body = column![
            safe_step_header(t, 0),
            safe_progress_bar(t, 0),
            vspace(20),
            inner,
        ]
        .width(Length::Fill);
        body.into()
    }

    fn step_amount<'a>(
        &'a self,
        t: KaoTheme,
        portfolio: &'a [LiveToken],
        recipient_name: Option<String>,
    ) -> Element<'a, Message> {
        let recipient = self.resolution.recipient();
        let recipient_kao = "(￣ω￣)";
        let recipient_summary: Element<'_, Message> = match recipient {
            Some(addr) => {
                let mut col = column![
                    container(avatar(t, recipient_kao, 52.0, t.ab2))
                        .width(Length::Fill)
                        .center_x(Length::Fill),
                    Space::new().height(8),
                ]
                .align_x(Alignment::Center);
                let header_label: Option<String> = recipient_name.clone().or_else(|| {
                    if let Resolution::Resolved { name, .. } = &self.resolution {
                        Some(name.clone())
                    } else {
                        None
                    }
                });
                if let Some(name) = header_label {
                    col = col.push(
                        container(text(name).size(13).color(t.text).font(bold()))
                            .width(Length::Fill)
                            .center_x(Length::Fill),
                    );
                    col = col.push(Space::new().height(4));
                }
                col = col.push(colored_address(t, addr));
                col.into()
            }
            None => column![
                container(
                    text("Recipient parse failed")
                        .size(13)
                        .color(t.down)
                        .font(bold())
                )
                .width(Length::Fill)
                .center_x(Length::Fill),
            ]
            .into(),
        };

        let mut tabs = row![].spacing(7).width(Length::Fill);
        for (i, tk) in portfolio.iter().take(4).enumerate() {
            tabs = tabs.push(self.token_tab(t, i, tk));
        }

        let token = portfolio.get(self.token_idx);
        let token_bal = token.map(|t| t.balance.as_str()).unwrap_or("0");
        let token_sym_with_chain = token
            .map(|t| format_symbol(&t.symbol, t.chain))
            .unwrap_or_else(|| "ETH".into());
        let amount_input = text_input("0.00", &self.amount)
            .on_input(Message::SetAmount)
            .padding(14)
            .size(34)
            .font(mono_black())
            .align_x(Alignment::Center)
            .style(move |_theme, status| text_input_style(t, status));

        let parsed_amount = token.and_then(|tk| parse_amount_units(&self.amount, tk.decimals).ok());
        let amount_valid = match (parsed_amount, token) {
            (Some(amt), Some(tk)) => !amt.is_zero() && amt <= tk.balance_raw,
            _ => false,
        };
        let amount_hint: Element<'_, Message> = if self.amount.trim().is_empty() {
            Space::new().height(0).into()
        } else if !amount_valid {
            container(
                text(match (parsed_amount, token) {
                    (None, _) => "Not a valid amount".to_string(),
                    (Some(amt), Some(tk)) if amt > tk.balance_raw => {
                        format!("Exceeds balance ({} {})", tk.balance, tk.symbol)
                    }
                    _ => "Amount must be > 0".to_string(),
                })
                .size(11)
                .color(t.down)
                .font(bold()),
            )
            .padding(Padding::from([4, 0]))
            .into()
        } else {
            Space::new().height(0).into()
        };

        let bal_line = row![
            text(format!("Balance: {} {}", token_bal, token_sym_with_chain))
                .size(12)
                .color(t.sub),
            Space::new().width(Length::Fill),
            ghost_button(t, text("Max").size(12).color(t.a1).font(bold()))
                .padding(Padding::from([2, 6]))
                .on_press(Message::Max),
        ]
        .width(Length::Fill);

        let back_btn = secondary_button(t, "← Back").on_press(Message::Step(0));
        let can_review = amount_valid && self.can_continue_recipient();
        let review_btn = primary_button(t, "Review →", can_review).on_press_maybe(if can_review {
            Some(Message::Step(2))
        } else {
            None
        });
        let action_row = row![
            container(back_btn).width(Length::FillPortion(1)),
            Space::new().width(9),
            container(review_btn).width(Length::FillPortion(2)),
        ]
        .width(Length::Fill);

        column![
            recipient_summary,
            Space::new().height(20),
            tabs,
            Space::new().height(14),
            amount_input,
            amount_hint,
            Space::new().height(7),
            bal_line,
            Space::new().height(16),
            action_row,
        ]
        .width(Length::Fill)
        .into()
    }

    fn token_tab<'a>(&self, t: KaoTheme, i: usize, tk: &'a LiveToken) -> Element<'a, Message> {
        let active = i == self.token_idx;
        let border_col = if active { t.a1 } else { t.border };
        let bg = if active { t.ab1 } else { t.card };
        let inner = column![
            kao_text(t, kaomoji_for_index(i), 11.0),
            Space::new().height(1),
            text(&tk.symbol).size(12).color(t.text).font(bold()),
            text(network_label(tk.chain))
                .size(9)
                .color(t.sub)
                .font(mono()),
        ]
        .align_x(Alignment::Center)
        .spacing(0);

        button(inner)
            .width(Length::Fill)
            .padding(Padding::from([8, 4]))
            .on_press(Message::SetToken(i))
            .style(move |_theme, status| button::Style {
                background: Some(Background::Color(match status {
                    button::Status::Hovered | button::Status::Pressed => hover_tint(bg, t.text),
                    _ => bg,
                })),
                text_color: t.text,
                border: Border {
                    color: border_col,
                    width: 1.5,
                    radius: Radius::from(10),
                },
                ..button::Style::default()
            })
            .into()
    }

    // ── EOA-specific view steps ─────────────────────────────────────────

    fn step_success_eoa<'a>(
        &'a self,
        t: KaoTheme,
        portfolio: &'a [LiveToken],
        recipient_name: Option<String>,
    ) -> Element<'a, Message> {
        let token_sym = portfolio
            .get(self.token_idx)
            .map(|t| t.symbol.as_str())
            .unwrap_or("ETH");
        let big_kao = container(kao_fit(t, "ヽ(・∀・)ﾉ", 320.0, 76.0))
            .width(Length::Fill)
            .center_x(Length::Fill);
        let title = container(text("Sent!").size(26).color(t.text).font(black()))
            .width(Length::Fill)
            .center_x(Length::Fill);
        let recipient_short = recipient_name.unwrap_or_else(|| match &self.resolution {
            Resolution::Resolved { name, .. } => name.clone(),
            _ => self
                .resolution
                .recipient()
                .map(|a| short_address_str(&format!("{a:#x}")))
                .unwrap_or_else(|| self.to.clone()),
        });
        let detail = container(
            text(format!(
                "{} {} → {}",
                self.amount, token_sym, recipient_short
            ))
            .size(15)
            .color(t.sub),
        )
        .width(Length::Fill)
        .center_x(Length::Fill);
        let confirmed_badge = container(text("✓ Confirmed").size(12).color(t.up).font(bold()))
            .padding(Padding::from([5, 12]))
            .style(move |_| container::Style {
                background: Some(Background::Color(with_alpha(t.up, 0.12))),
                border: Border {
                    color: t.up,
                    width: 1.0,
                    radius: Radius::from(8),
                },
                text_color: Some(t.up),
                ..container::Style::default()
            });
        let badge_wrap = container(confirmed_badge)
            .width(Length::Fill)
            .center_x(Length::Fill);
        let hash_card: Element<'_, Message> = match self.last_tx_hash {
            Some(h) => {
                let hash_str = format!("{h:#x}");
                let hash_display = short_address_str(&hash_str);
                let copy_btn = secondary_button(t, "Copy hash").on_press(Message::CopyHash);
                let etherscan_btn =
                    secondary_button(t, "Etherscan").on_press(Message::CopyEtherscan);
                container(
                    column![
                        text(format!("TX: {hash_display}"))
                            .size(12)
                            .color(t.sub)
                            .font(mono()),
                        Space::new().height(8),
                        row![
                            container(copy_btn).width(Length::FillPortion(1)),
                            Space::new().width(8),
                            container(etherscan_btn).width(Length::FillPortion(1))
                        ]
                        .width(Length::Fill),
                    ]
                    .width(Length::Fill),
                )
                .padding(Padding::from([12, 14]))
                .width(Length::Fill)
                .style(move |_| container::Style {
                    background: Some(Background::Color(t.card_alt)),
                    border: Border {
                        color: t.border,
                        width: 1.0,
                        radius: Radius::from(12),
                    },
                    text_color: Some(t.text),
                    ..container::Style::default()
                })
                .into()
            }
            None => Space::new().height(0).into(),
        };
        let done_btn = secondary_button(t, "Done").on_press(Message::Close);
        let send_another_btn =
            primary_button(t, "Send another", true).on_press(Message::SendAnother);
        let action_row = row![
            container(done_btn).width(Length::FillPortion(1)),
            Space::new().width(9),
            container(send_another_btn).width(Length::FillPortion(2)),
        ]
        .width(Length::Fill);
        column![
            Space::new().height(8),
            big_kao,
            Space::new().height(16),
            title,
            Space::new().height(6),
            detail,
            Space::new().height(10),
            badge_wrap,
            Space::new().height(14),
            hash_card,
            Space::new().height(16),
            action_row,
        ]
        .width(Length::Fill)
        .into()
    }

    // ── Safe-specific view steps ────────────────────────────────────────

    fn view_success_safe<'a>(
        &'a self,
        t: KaoTheme,
        recipient_name: Option<String>,
        portfolio: &'a [LiveToken],
    ) -> Element<'a, Message> {
        let s = self.safe().unwrap();
        let token = portfolio.get(self.token_idx);
        let decimals = token.map(|tk| tk.decimals).unwrap_or(18);
        let symbol = token.map(|tk| tk.symbol.as_str()).unwrap_or("ETH");
        let amount_wei = self.parsed_amount(decimals).unwrap_or(U256::ZERO);
        let amount_str = format_units(amount_wei, decimals)
            .map(|v| sim_view::trim_trailing_decimal_zeros(&v))
            .unwrap_or_else(|_| "?".into());
        // Post-success display only — but still avoid inventing a zero
        // address for the label if the recipient is somehow absent.
        let recipient_label = recipient_name.unwrap_or_else(|| match &self.resolution {
            Resolution::Resolved { name, .. } => name.clone(),
            _ => self
                .resolution
                .recipient()
                .map(short_address)
                .unwrap_or_else(|| "unknown recipient".into()),
        });
        let hash_display = match self.last_tx_hash {
            Some(h) => {
                let hx = format!("{h:#x}");
                if hx.len() > 14 {
                    format!("{}…{}", &hx[..8], &hx[hx.len() - 6..])
                } else {
                    hx
                }
            }
            None => "—".to_string(),
        };

        let close_btn = primary_button(t, "Close (ﾉ◕ヮ◕)ﾉ*:･ﾟ✧", true).on_press(Message::Close);

        if s.proposed {
            let need = s.threshold.saturating_sub(1).max(1);
            return column![
                vspace(8), kao_fit(t, "(ﾉ≧▽≦)ﾉ", 320.0, 76.0), vspace(16),
                container(text("Proposed!").size(26).color(t.text).font(black())).width(Length::Fill).center_x(Length::Fill),
                vspace(6),
                container(text(format!("{amount_str} {symbol} → {recipient_label}")).size(15).color(t.sub)).width(Length::Fill).center_x(Length::Fill),
                vspace(8),
                container(text(format!("Queued for co-signers — {need} more signature{} needed. Find it under Pending transactions.",
                    if need == 1 { "" } else { "s" })).size(13).color(t.sub)).width(Length::Fill).center_x(Length::Fill),
                vspace(18), close_btn,
            ].width(Length::Fill).into();
        }

        let copy_hash_btn = secondary_button(t, "Copy hash").on_press(Message::CopyHash);
        let copy_link_btn =
            secondary_button(t, "Copy explorer link").on_press(Message::CopyExplorerLink);
        let copy_row = row![
            container(copy_hash_btn).width(Length::FillPortion(1)),
            Space::new().width(9),
            container(copy_link_btn).width(Length::FillPortion(1)),
        ]
        .align_y(Alignment::Center);

        column![
            vspace(8),
            kao_fit(t, "ヽ(・∀・)ﾉ", 320.0, 76.0),
            vspace(16),
            container(text("Sent!").size(26).color(t.text).font(black()))
                .width(Length::Fill)
                .center_x(Length::Fill),
            vspace(6),
            container(
                text(format!("{amount_str} {symbol} → {recipient_label}"))
                    .size(15)
                    .color(t.sub)
            )
            .width(Length::Fill)
            .center_x(Length::Fill),
            vspace(4),
            container(hint_pill(t, "✓ Confirmed"))
                .width(Length::Fill)
                .center_x(Length::Fill),
            vspace(8),
            container(text(hash_display).size(12).color(t.sub).font(mono()))
                .width(Length::Fill)
                .center_x(Length::Fill),
            vspace(14),
            copy_row,
            vspace(16),
            close_btn,
        ]
        .width(Length::Fill)
        .into()
    }
} // end impl SendPane

// ── Free helpers ────────────────────────────────────────────────────────────

pub(crate) fn sim_row<'a, M: 'a>(
    t: KaoTheme,
    chain: crate::chain::NetworkId,
    contract: Option<Address>,
    name: String,
    after: Option<String>,
    delta: String,
    delta_color: Color,
) -> Element<'a, M> {
    let mut name_col = column![text(name).size(13).color(t.text).font(bold())].spacing(1);
    if let Some(after_text) = after {
        name_col = name_col.push(text(after_text).size(10).color(t.sub).font(mono()));
    }
    // Built-in networks can show a chain/token logo; a custom network has no
    // bundled logo, so it falls back to the kaomoji avatar.
    let avatar_el = match chain.builtin() {
        Some(c) => token_avatar(t, c, contract, "(•◡•)", 30.0, t.ab2),
        None => avatar(t, "(•◡•)", 30.0, t.ab2),
    };
    container(
        row![
            avatar_el,
            Space::new().width(11),
            name_col,
            Space::new().width(Length::Fill),
            text(delta).size(14).color(delta_color).font(mono_bold()),
        ]
        .align_y(Alignment::Center)
        .padding(Padding::from([10, 0])),
    )
    .clip(true)
    .width(Length::Fill)
    .into()
}

pub(crate) fn divider_line<'a, M: 'a>(t: KaoTheme) -> Element<'a, M> {
    container(Space::new().width(Length::Fill).height(1))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.border)),
            ..container::Style::default()
        })
        .into()
}

// ── Sign-review overlay: EOA send step ───────────────────────────────────────

/// A fully-prepared EOA send, snapshotted for review inside the unified
/// `sign_review` overlay. Carries every value the review renders — the quote
/// (gas / nonce / fees / revm sim), the decoded call, the recipient's display
/// metadata, and the token figures — so the overlay reproduces the old inline
/// review without needing live pane/portfolio state. Built by the coordinator's
/// `spawn_send_prepare`; the `quote` inside (with its `plan`) drives the
/// broadcast, so reviewed == signed.
#[derive(Debug, Clone)]
pub struct SendReview {
    pub chain: crate::chain::NetworkId,
    pub recipient: Address,
    pub recipient_name: Option<String>,
    pub recipient_in_book: bool,
    pub recipient_kao: String,
    pub recipient_chip: Option<&'static str>,
    pub amount: String,
    pub token_symbol: String,
    pub token_contract: Option<Address>,
    pub token_balance_before: f64,
    pub usd_price: f64,
    pub eth_usd_price: f64,
    /// `true` when the sender lacks the ETH to cover gas (+ the amount, for a
    /// native send). Precomputed against the reviewed quote + on-chain balance;
    /// disables Confirm and shows the "need ETH for gas" banner.
    pub has_insufficient_eth: bool,
    pub quote: TxQuote,
    pub decoded: Box<DecodeResult>,
    /// ERC-8213 Calldata Digest of the transaction being signed — `Some` for an
    /// ERC-20 transfer (the `transfer()` calldata), `None` for a native send
    /// (empty calldata, so the standard prescribes no digest). Computed at review
    /// build from [`crate::wallet::tx::SendPlan::tx_target`].
    pub calldata_digest: Option<B256>,
}

impl SendReview {
    /// Whether any read backing this review is unverified — the decode fell back
    /// to an unverified RPC, or the local sim ran on unverified state. Mirrors the
    /// old inline review so the primary action softens to "Sign anyway ⚠".
    fn reads_unverified(&self) -> bool {
        let decode_unverified = match self.decoded.as_ref() {
            DecodeResult::ClearSigned { all_verified, .. } => !all_verified,
            DecodeResult::Fallback {
                all_verified,
                heuristic,
                ..
            } => !(*all_verified && heuristic.all_verified),
            DecodeResult::Heuristic(c) => !c.all_verified,
            DecodeResult::Empty => false,
        };
        let sim_ok = !self.quote.sim.is_revert()
            && !matches!(self.quote.sim.outcome, SimOutcome::Unavailable);
        decode_unverified || (sim_ok && !self.quote.sim.verified)
    }

    /// The primary-button label for this review (matches the old inline review).
    pub fn confirm_label(&self) -> String {
        if self.has_insufficient_eth {
            "Need ETH for gas".to_string()
        } else if self.quote.sim.is_revert() || self.reads_unverified() {
            "Sign anyway ⚠".to_string()
        } else {
            "Sign & Send".to_string()
        }
    }

    /// Whether Confirm must be blocked — only when there isn't enough ETH for gas
    /// (an unverified/reverting sim is a deliberate "sign anyway", not a block).
    pub fn confirm_disabled(&self) -> bool {
        self.has_insufficient_eth
    }
}

/// Render the EOA send review body inside the `sign_review` overlay — the intent
/// banner, the revm balance-change card, the recipient card, the (collapsible)
/// decoded call data, the verification badges, and the insufficient-ETH banner.
/// Generic over the host message type so the overlay owns the calldata toggle;
/// everything else is display-only. The simulation-block fallback is only used
/// for the revert/unavailable case (which never renders per-transfer rows), so
/// it needs no portfolio.
pub(crate) fn render_send_review<'a, M: 'a + Clone + CopyKick>(
    t: KaoTheme,
    r: &'a SendReview,
    show_calldata: bool,
    toggle_msg: M,
) -> Element<'a, M> {
    let token_sym = r.token_symbol.as_str();
    let chain = r.chain;
    let amount_f = r.amount.parse::<f64>().unwrap_or(0.0);
    let usd_value = amount_f * r.usd_price;
    let sim_reverted = r.quote.sim.is_revert();
    let sim_unavailable = matches!(r.quote.sim.outcome, SimOutcome::Unavailable);

    let recipient_short = r
        .recipient_name
        .clone()
        .unwrap_or_else(|| short_address_str(&format!("{:#x}", r.recipient)));

    // ── Intent banner ──
    let intent_kao = if r.has_insufficient_eth {
        "(・_・;)"
    } else {
        "( ◜◡◝ )"
    };
    let intent_text = container(
        row![
            text("You're sending ").size(15).color(t.text).font(bold()),
            text(format!("{} {}", r.amount, token_sym))
                .size(15)
                .color(t.a1)
                .font(bold()),
            text(" to ").size(15).color(t.text).font(bold()),
            text(format!("{}.", recipient_short.clone()))
                .size(15)
                .color(t.a1)
                .font(bold()),
        ]
        .align_y(Alignment::Center),
    )
    .clip(true)
    .width(Length::Fill);
    let usd_sub = if r.usd_price > 0.0 {
        format!("on {} · ≈ ${usd_value:.2}", network_display_name(chain))
    } else {
        format!("on {}", network_display_name(chain))
    };
    let intent_banner = container(
        row![
            kao_text(t, intent_kao, 22.0),
            Space::new().width(12),
            column![
                intent_text,
                text(usd_sub).size(12).color(t.sub).font(bold())
            ]
            .spacing(3),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill),
    )
    .padding(Padding::from([15, 17]))
    .width(Length::Fill)
    .style(move |_| container::Style {
        background: Some(Background::Color(t.ab1)),
        border: Border {
            color: with_alpha(t.a1, 0.27),
            width: 1.0,
            radius: Radius::from(15),
        },
        text_color: Some(t.text),
        ..container::Style::default()
    });

    // ── Balance-change card ──
    let balance_changes_card: Element<'_, M> = if sim_reverted || sim_unavailable {
        simulation_block(t, &r.quote.sim, chain, &[])
    } else {
        let mut changes_col = column![].spacing(0).width(Length::Fill);
        let balance_before = r.token_balance_before;
        let balance_after = balance_before - amount_f;
        changes_col = changes_col.push(sim_row(
            t,
            chain,
            r.token_contract,
            format!("Your {token_sym}"),
            Some(format!("{:.2} → {:.2}", balance_before, balance_after)),
            format!("− {} {token_sym}", r.amount),
            t.down,
        ));
        changes_col = changes_col.push(divider_line(t));
        let eth_str = format_units(r.quote.eth_cost_wei, 18u8).unwrap_or_else(|_| "0".into());
        let eth_short = trim_eth_display(&eth_str);
        let gas_usd = eth_str.parse::<f64>().unwrap_or(0.0) * r.eth_usd_price;
        let gas_sub = if r.eth_usd_price > 0.0 {
            format!("≈ ${gas_usd:.2} · paid in ETH")
        } else {
            "paid in ETH".into()
        };
        changes_col = changes_col.push(sim_row(
            t,
            chain,
            None,
            "Network fee".into(),
            Some(gas_sub),
            format!("− {eth_short} ETH"),
            t.down,
        ));
        changes_col = changes_col.push(divider_line(t));
        changes_col = changes_col.push(sim_row(
            t,
            chain,
            r.token_contract,
            format!("{recipient_short} receives"),
            None,
            format!("+ {} {token_sym}", r.amount),
            t.up,
        ));
        let header_row = row![
            text("AFTER THIS TRANSACTION")
                .size(10)
                .color(t.sub)
                .font(mono_bold()),
            Space::new().width(Length::Fill),
            hint_pill(t, "⟁ simulated · revm"),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill);
        container(column![header_row, Space::new().height(2), changes_col].width(Length::Fill))
            .padding(
                Padding::new(4.0)
                    .top(12.0)
                    .left(16.0)
                    .right(16.0)
                    .bottom(13.0),
            )
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(t.card_alt)),
                border: Border {
                    color: t.border,
                    width: 1.0,
                    radius: Radius::from(15),
                },
                text_color: Some(t.text),
                ..container::Style::default()
            })
            .into()
    };

    // ── Recipient card ──
    let recipient_card: Element<'_, M> = {
        let addr = r.recipient;
        let kao = r.recipient_kao.clone();
        let mut header_row = row![text("RECIPIENT").size(10).color(t.sub).font(mono_bold())]
            .align_y(Alignment::Center);
        if r.recipient_in_book {
            header_row = header_row.push(Space::new().width(Length::Fill));
            header_row = header_row.push(
                container(
                    text("✓ matches saved contact")
                        .size(10)
                        .color(t.up)
                        .font(mono_bold()),
                )
                .padding(Padding::from([3, 8]))
                .style(move |_| container::Style {
                    background: Some(Background::Color(with_alpha(t.up, 0.08))),
                    border: Border {
                        color: with_alpha(t.up, 0.22),
                        width: 1.0,
                        radius: Radius::from(6),
                    },
                    ..container::Style::default()
                }),
            );
        }
        let display_name = r
            .recipient_name
            .clone()
            .unwrap_or_else(|| short_address_str(&format!("{addr:#x}")));
        let mut name_col =
            column![text(display_name).size(14).color(t.text).font(bold())].spacing(1);
        if let Some(chip) = r.recipient_chip {
            name_col = name_col.push(text(chip).size(11).color(t.sub).font(bold()));
        }
        let name_row = row![
            avatar_owned::<M>(t, kao, 30.0),
            Space::new().width(10),
            name_col
        ]
        .align_y(Alignment::Center);
        let addr_container = container(colored_address::<M>(t, addr))
            .padding(Padding::from([10, 12]))
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(with_alpha(t.bg, 0.5))),
                border: Border {
                    color: t.border,
                    width: 1.0,
                    radius: Radius::from(10),
                },
                ..container::Style::default()
            });
        container(
            column![
                header_row,
                Space::new().height(8),
                name_row,
                Space::new().height(10),
                addr_container
            ]
            .width(Length::Fill),
        )
        .padding(Padding::from([13, 16]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card_alt)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(15),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
    };

    // ── Decoded call data (collapsible) ──
    let calldata_block: Element<'_, M> =
        if function_panel::view::<M>(t, Some(r.decoded.as_ref()), false).is_some() {
            let fn_name: Option<String> = match r.decoded.as_ref() {
                DecodeResult::ClearSigned { model, .. } | DecodeResult::Fallback { model, .. } => {
                    Some(model.intent.clone())
                }
                DecodeResult::Heuristic(decoded) => decoded.function_name.clone(),
                DecodeResult::Empty => None,
            };
            let pill_label: Option<String> = fn_name.map(|name| {
                // Truncate by *chars*, not bytes: a decoded intent/function name
                // can carry attacker-controlled token metadata (e.g. a multibyte
                // symbol), and a byte slice landing mid-codepoint would panic the
                // review render.
                if name.chars().count() > 30 {
                    format!("{}…", name.chars().take(28).collect::<String>())
                } else {
                    name
                }
            });
            let caret = if show_calldata { "▾" } else { "▸" };
            let mut toggle_row = row![
                text(caret).size(12).color(t.sub).font(mono()),
                Space::new().width(6),
                text("Decoded call data")
                    .size(13)
                    .color(t.text)
                    .font(bold()),
            ]
            .align_y(Alignment::Center)
            .spacing(0);
            if let Some(label) = pill_label {
                toggle_row = toggle_row.push(Space::new().width(8));
                toggle_row = toggle_row.push(
                    container(text(format!("{label}()")).size(10).color(t.a1).font(mono()))
                        .padding(Padding::from([2, 7]))
                        .style(move |_| container::Style {
                            border: Border {
                                color: with_alpha(t.a1, 0.22),
                                width: 1.0,
                                radius: Radius::from(6),
                            },
                            ..container::Style::default()
                        }),
                );
            }
            toggle_row = toggle_row.push(Space::new().width(Length::Fill));
            toggle_row = toggle_row.push(
                text(if show_calldata {
                    "hide"
                } else {
                    "for the paranoid"
                })
                .size(11)
                .color(t.sub)
                .font(mono()),
            );
            let toggle_btn: Element<'_, M> = button(toggle_row.width(Length::Fill))
                .width(Length::Fill)
                .padding(Padding::from([13, 16]))
                .on_press(toggle_msg)
                .style(move |_theme, _status| button::Style {
                    background: Some(Background::Color(Color::TRANSPARENT)),
                    text_color: t.text,
                    ..button::Style::default()
                })
                .into();
            let expanded: Element<'_, M> = if show_calldata {
                match function_panel::view::<M>(t, Some(r.decoded.as_ref()), false) {
                    Some(panel) => container(panel)
                        .padding(Padding::from([0, 13]).bottom(13.0))
                        .width(Length::Fill)
                        .style(move |_| container::Style {
                            background: Some(Background::Color(t.bg)),
                            border: Border {
                                color: t.border,
                                width: 1.0,
                                radius: Radius::from(11),
                            },
                            ..container::Style::default()
                        })
                        .into(),
                    None => Space::new().height(0).into(),
                }
            } else {
                Space::new().height(0).into()
            };
            container(column![toggle_btn, expanded].spacing(0).width(Length::Fill))
                .width(Length::Fill)
                .style(move |_| container::Style {
                    background: Some(Background::Color(t.card_alt)),
                    border: Border {
                        color: t.border,
                        width: 1.0,
                        radius: Radius::from(15),
                    },
                    ..container::Style::default()
                })
                .into()
        } else {
            Space::new().height(0).into()
        };

    // ── Verification badges ──
    let good_badge = |label: &'a str| -> Element<'a, M> {
        container(text(label).size(10).color(t.up).font(mono_bold()))
            .padding(Padding::from([3, 7]))
            .style(move |_| container::Style {
                background: Some(Background::Color(with_alpha(t.up, 0.06))),
                border: Border {
                    color: with_alpha(t.up, 0.22),
                    width: 1.0,
                    radius: Radius::from(6),
                },
                ..container::Style::default()
            })
            .into()
    };
    let warn_badge = |label: &'a str| -> Element<'a, M> {
        container(text(label).size(10).color(t.down).font(mono_bold()))
            .padding(Padding::from([3, 7]))
            .style(move |_| container::Style {
                background: Some(Background::Color(with_alpha(t.down, 0.08))),
                border: Border {
                    color: with_alpha(t.down, 0.30),
                    width: 1.0,
                    radius: Radius::from(6),
                },
                ..container::Style::default()
            })
            .into()
    };
    let sim_ok = !sim_reverted && !sim_unavailable;
    let sim_verified = r.quote.sim.verified;
    let badges_row: Element<'_, M> = if sim_ok {
        let helios = if sim_verified {
            good_badge("✓ Verified by Helios")
        } else {
            warn_badge("⚠ Unverified · fallback RPC")
        };
        row![
            good_badge("✓ Simulated locally · revm"),
            Space::new().width(7),
            helios
        ]
        .align_y(Alignment::Center)
        .into()
    } else {
        Space::new().height(0).into()
    };

    // ── Insufficient-ETH banner ──
    let gas_warning: Element<'_, M> = if r.has_insufficient_eth {
        let gas_eth_str = {
            let s = format_units(r.quote.eth_cost_wei, 18u8).unwrap_or_else(|_| "0".into());
            trim_eth_display(&s)
        };
        container(
            row![
                kao_text(t, "(；・_・)", 20.0),
                Space::new().width(11),
                column![
                    text("Can't sign yet — not enough ETH for gas")
                        .size(13)
                        .color(t.down)
                        .font(bold()),
                    Space::new().height(3),
                    text(format!(
                        "This network fee is paid in ETH. You need ≈ {} ETH on {}, but your ETH balance on this chain is 0.",
                        gas_eth_str,
                        network_display_name(chain)
                    ))
                    .size(12)
                    .color(t.sub),
                ]
                .width(Length::Fill),
            ]
            .align_y(Alignment::Center)
            .width(Length::Fill),
        )
        .padding(Padding::from([13, 15]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(t.down, 0.08))),
            border: Border {
                color: with_alpha(t.down, 0.35),
                width: 1.0,
                radius: Radius::from(14),
            },
            ..container::Style::default()
        })
        .into()
    } else {
        Space::new().height(0).into()
    };

    column![
        intent_banner,
        Space::new().height(13),
        balance_changes_card,
        Space::new().height(13),
        recipient_card,
        Space::new().height(13),
        calldata_block,
        Space::new().height(10),
        badges_row,
        Space::new().height(13),
        gas_warning,
    ]
    .width(Length::Fill)
    .into()
}

// ── Sign-review overlay: Safe send step ──────────────────────────────────────

/// A fully-prepared Safe send, snapshotted for review inside the unified
/// `sign_review` overlay. Carries the reviewed figures (intent, the revm inner
/// sim, recipient) plus the exact `safeTxHash` the owners sign and the signing
/// owner set. The `SignAction::SafeSend` alongside pins the same `(nonce, hash)`,
/// so the execute/propose ceremony signs exactly what's shown.
#[derive(Debug, Clone)]
pub struct SafeSendReview {
    pub chain: Chain,
    pub amount_str: String,
    pub symbol: String,
    /// `false` when the reviewed amount/symbol could NOT be re-derived from a
    /// Helios-verified on-chain `decimals()`/`symbol()` read and fell back to
    /// the untrusted indexer's metadata. A lying indexer's `decimals` scales
    /// both the raw `amount_units` being signed and (previously) this display,
    /// so when it can't be verified the amount is tagged "(unverified)" and the
    /// execute/propose action softens to "… anyway ⚠". Mirrors the EOA path's
    /// verified-decimals rendering.
    pub amount_verified: bool,
    pub token_contract: Option<Address>,
    pub recipient: Address,
    pub recipient_name: Option<String>,
    pub recipient_in_book: bool,
    pub nonce: u64,
    pub safe_tx_hash: B256,
    /// ERC-8213 digests of the `SafeTx` EIP-712 signature the owners produce.
    /// `eip712.digest` equals `safe_tx_hash`; the domain / message hashes let the
    /// fingerprints section show all three components.
    pub eip712: crate::sign::digest::Eip712Digests,
    /// ERC-8213 Calldata Digest of the Safe's **inner** call — `Some` for an
    /// ERC-20 transfer, `None` for a native transfer (empty inner calldata).
    pub inner_calldata_digest: Option<B256>,
    pub threshold: u32,
    pub owner_count: usize,
    /// The signable owner addresses that will sign now (execute path). Fewer than
    /// `threshold` in the propose-only case; display-only.
    pub signing_addresses: Vec<Address>,
    pub sim: SimulationResult,
}

impl SafeSendReview {
    /// Whether the revm inner-sim predicts a revert — softens the overlay's
    /// action labels to "… anyway ⚠", mirroring the old inline Safe review.
    pub fn sim_reverts(&self) -> bool {
        self.sim.is_revert()
    }

    /// Whether the reviewed action must be softened to "… anyway ⚠": either the
    /// inner sim reverts, or the amount/symbol couldn't be verified on-chain.
    pub fn needs_confirm_override(&self) -> bool {
        self.sim_reverts() || !self.amount_verified
    }
}

/// Decide the reviewed amount string, symbol, and verification flag for a Safe
/// send, preferring a Helios-verified on-chain read over the untrusted indexer.
///
/// The raw `amount_units` that will be signed was scaled by the indexer's
/// `decimals` at plan time, and the Safe review formatted its display with the
/// same untrusted `decimals` — so a lying/stale indexer could mis-scale the
/// transfer while the review stayed internally consistent (finding #16). Here
/// we reformat the amount from a Helios-verified `decimals()` read: an honest
/// indexer yields the same figure, a dishonest one yields the true (often
/// wildly different) on-chain figure. When no verified read is available
/// (`verified_meta` is `None`, or `verified` is `false`), we keep a
/// best-effort display but return `amount_verified = false` so the UI tags it
/// and softens the action. Native sends carry no ERC-20 decimals risk (the
/// native row's identity is chain-pinned at ingestion), so they pass through.
pub(crate) fn resolve_safe_amount_display(
    amount_units: U256,
    token: &SendToken,
    verified_meta: Option<(crate::decode::render::TokenInfo, bool)>,
    indexer_amount_str: String,
    indexer_symbol: String,
) -> (String, String, bool) {
    match token {
        SendToken::Native => (indexer_amount_str, indexer_symbol, true),
        SendToken::Erc20 { .. } => match verified_meta {
            Some((info, verified)) => {
                let amount = format_units(amount_units, info.decimals)
                    .map(|v| sim_view::trim_trailing_decimal_zeros(&v))
                    .unwrap_or_else(|_| "?".to_string());
                (amount, info.symbol, verified)
            }
            None => (indexer_amount_str, indexer_symbol, false),
        },
    }
}

/// Render the Safe send review body inside the `sign_review` overlay — intent
/// banner, revm balance-change card, recipient card, the exact `safeTxHash` the
/// owners commit to, the signing owner set, and verification badges. Purely
/// display (the execute/propose actions live in the overlay's action row), so it
/// is generic over the host message type.
pub(crate) fn render_safe_send_review<'a, M: 'a + CopyKick>(
    t: KaoTheme,
    r: &'a SafeSendReview,
) -> Element<'a, M> {
    let chain = r.chain;
    let amount_str = r.amount_str.as_str();
    let symbol = r.symbol.as_str();
    let amount_unverified = !r.amount_verified;
    let recip_label = r
        .recipient_name
        .clone()
        .unwrap_or_else(|| short_address(r.recipient));

    // Intent banner
    let intent_banner = container(
        column![
            row![
                kao_text(t, "(•̀ᴗ•́)و", 16.0),
                Space::new().width(8),
                text(if amount_unverified {
                    format!("Sending {amount_str} {symbol}  (unverified)")
                } else {
                    format!("Sending {amount_str} {symbol}")
                })
                .size(14)
                .color(t.a1)
                .font(bold()),
            ]
            .align_y(Alignment::Center),
            text(format!("on {}", chain.display_name()))
                .size(11)
                .color(t.sub)
                .font(mono()),
        ]
        .spacing(2),
    )
    .clip(true)
    .padding(Padding::from([12, 14]))
    .width(Length::Fill)
    .style(move |_| container::Style {
        background: Some(Background::Color(t.ab1)),
        border: Border {
            color: with_alpha(t.a1, 0.27),
            width: 1.0,
            radius: Radius::from(12),
        },
        text_color: Some(t.text),
        ..container::Style::default()
    });

    // Balance-change card
    let balance_card: Element<'_, M> = {
        let header_row = row![
            text("AFTER THIS TRANSACTION")
                .size(10)
                .color(t.sub)
                .font(mono_bold()),
            Space::new().width(8),
            hint_pill(t, "⟁ simulated · revm"),
        ]
        .align_y(Alignment::Center);
        let mut col = column![header_row, vspace(6)]
            .spacing(0)
            .width(Length::Fill);
        col = col.push(sim_row(
            t,
            chain.into(),
            r.token_contract,
            symbol.to_string(),
            None,
            format!("-{amount_str}"),
            t.down,
        ));
        col = col.push(divider_line(t));
        let gas_str = sim_view::format_gas_fee_eth(r.sim.gas_used, r.sim.base_fee_per_gas)
            .unwrap_or_else(|| "?".into());
        col = col.push(sim_row(
            t,
            chain.into(),
            None,
            "Gas".to_string(),
            None,
            format!("-{gas_str}"),
            t.down,
        ));
        col = col.push(divider_line(t));
        col = col.push(sim_row(
            t,
            chain.into(),
            r.token_contract,
            recip_label.clone(),
            None,
            format!("+{amount_str}"),
            t.up,
        ));
        if r.sim.is_revert() {
            col =
                col.push(vspace(6))
                    .push(sim_view::simulation_block(t, &r.sim, chain.into(), &[]));
        }
        review_card(t, col.into())
    };

    // Recipient card
    let mut recip_col = column![
        row![
            text("RECIPIENT").size(10).color(t.sub).font(mono_bold()),
            Space::new().width(Length::Fill)
        ]
        .align_y(Alignment::Center),
        vspace(8),
    ]
    .width(Length::Fill);
    if r.recipient_in_book {
        recip_col = recip_col.push(hint_pill(t, "✓ matches saved contact"));
        recip_col = recip_col.push(vspace(6));
    }
    let mut recip_inner = column![].spacing(4).width(Length::Fill);
    if let Some(name) = &r.recipient_name {
        recip_inner = recip_inner.push(
            row![
                avatar(t, "(￣ω￣)", 30.0, t.ab2),
                Space::new().width(10),
                text(name.clone()).size(14).color(t.text).font(bold())
            ]
            .align_y(Alignment::Center),
        );
    }
    let addr_sub = container(colored_address::<M>(t, r.recipient))
        .padding(Padding::from([6, 10]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(t.card, 0.5))),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(8),
            },
            ..container::Style::default()
        });
    recip_inner = recip_inner.push(addr_sub);
    recip_col = recip_col.push(recip_inner);
    let recipient_card = review_card(t, recip_col.into());

    // Safe-tx hash card — the exact bytes every owner commits to. Named and
    // click-to-copy: for a first-time signer it isn't obvious what this string
    // is or that it's actionable, so spell out both.
    let hash_card = review_card(
        t,
        column![
            text("VERIFY BEFORE SIGNING")
                .size(10)
                .color(t.sub)
                .font(mono_bold()),
            vspace(2),
            text("SafeTx hash · click to copy")
                .size(12)
                .color(t.text)
                .font(bold()),
            vspace(6),
            colored_hash_copyable::<M>(t, r.safe_tx_hash),
            vspace(6),
            text(
                "This is the fingerprint of this exact transaction — every owner signs it. \
                 It must match on your signing device and your co-signers' before you approve."
            )
            .size(10)
            .color(t.sub),
            vspace(4),
            text(format!("Safe nonce {}", r.nonce))
                .size(10)
                .color(t.sub)
                .font(mono()),
        ]
        .width(Length::Fill)
        .into(),
    );

    // Signing card
    let threshold_label = format!("{} of {}", r.threshold, r.owner_count);
    let mut owners_col = column![].spacing(4);
    for (i, addr) in r.signing_addresses.iter().enumerate() {
        let kao = kaomoji_for_index(i);
        owners_col = owners_col.push(
            row![
                avatar(t, kao, 26.0, t.ab1),
                Space::new().width(8),
                text(short_address(*addr))
                    .size(12)
                    .color(t.text)
                    .font(mono())
            ]
            .align_y(Alignment::Center),
        );
    }
    let signing_card = review_card(
        t,
        column![
            text("SIGNING").size(10).color(t.sub).font(mono_bold()),
            vspace(8),
            text(format!("Threshold: {threshold_label}"))
                .size(13)
                .color(t.text)
                .font(bold()),
            vspace(6),
            text("Signing with").size(11).color(t.sub).font(mono_bold()),
            vspace(4),
            owners_col,
        ]
        .width(Length::Fill)
        .into(),
    );

    // Verification badges
    let mut badges = row![hint_pill(t, "✓ Hash verified on-chain")].spacing(6);
    if r.sim.is_success() && r.sim.verified {
        badges = badges.push(hint_pill(t, "✓ Simulation passed"));
    }
    if amount_unverified {
        // The token's `decimals`/`symbol` couldn't be re-read through Helios, so
        // the amount above rests on the untrusted indexer. Flag it in the same
        // red badge language the EOA review uses for unverified reads.
        badges = badges.push(
            container(
                text("⚠ Amount unverified · indexer decimals")
                    .size(10)
                    .color(t.down)
                    .font(mono_bold()),
            )
            .padding(Padding::from([3, 7]))
            .style(move |_| container::Style {
                background: Some(Background::Color(with_alpha(t.down, 0.08))),
                border: Border {
                    color: with_alpha(t.down, 0.30),
                    width: 1.0,
                    radius: Radius::from(6),
                },
                ..container::Style::default()
            }),
        );
    }
    let badges_row = container(badges)
        .padding(Padding::from([4, 0]))
        .width(Length::Fill);

    column![
        intent_banner,
        vspace(10),
        balance_card,
        vspace(10),
        recipient_card,
        vspace(10),
        hash_card,
        vspace(10),
        signing_card,
        vspace(6),
        badges_row,
    ]
    .width(Length::Fill)
    .into()
}

fn picker_row<'a>(t: KaoTheme, entry: PickerEntry, current_input: &str) -> Element<'a, Message> {
    let addr = entry.address;
    let checksum = addr.to_checksum(None);
    let selected = current_input.eq_ignore_ascii_case(&checksum);
    let bg = if selected { t.ab2 } else { Color::TRANSPARENT };
    let short = short_address_str(&format!("{addr:#x}"));
    let check = if selected { "✓" } else { " " };
    let mut name_row = row![text(entry.name.clone()).size(14).color(t.text).font(bold())]
        .align_y(Alignment::Center);
    if let Some(chip) = entry.chip {
        let chip_color = match entry.kind {
            PickerKind::OwnSafe => t.a2,
            _ => t.sub,
        };
        name_row = name_row
            .push(Space::new().width(8))
            .push(text(chip).size(10).color(chip_color).font(mono()));
    }
    let row_content = row![
        avatar_owned(t, entry.kaomoji.clone(), 34.0),
        Space::new().width(12),
        column![name_row, text(short).size(11).color(t.sub).font(mono())]
            .spacing(0)
            .width(Length::Fill),
        text(check).size(16).color(t.a2),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);
    let pick_msg = Message::PickRecipient {
        address: addr,
        ens: entry.ens.clone(),
    };
    button(row_content)
        .padding(Padding::from([9, 10]))
        .width(Length::Fill)
        .on_press(pick_msg)
        .style(move |_theme, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => hover_tint(bg, t.text),
                _ => bg,
            })),
            text_color: t.text,
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(11),
            },
            ..button::Style::default()
        })
        .into()
}

pub(crate) fn avatar_owned<'a, M: 'a>(t: KaoTheme, kao: String, size: f32) -> Element<'a, M> {
    let inner_pad: f32 = 4.0;
    let budget = (size - 2.0 * inner_pad).max(8.0);
    let max_font = (size * 0.40).max(10.0);
    let font_size = kao_fit_size(&kao, budget, max_font);
    container(text(kao).size(font_size).color(t.text))
        .width(Length::Fixed(size))
        .height(Length::Fixed(size))
        .center_x(Length::Fixed(size))
        .center_y(Length::Fixed(size))
        .style(move |_| container::Style {
            background: Some(Background::Color(t.ab2)),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(size / 2.0),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
}

pub(crate) fn short_address_str(s: &str) -> String {
    if s.len() >= 12 {
        format!("{}…{}", &s[..6], &s[s.len() - 4..])
    } else {
        s.to_string()
    }
}

pub(crate) fn trim_eth_display(s: &str) -> String {
    let Some(dot) = s.find('.') else {
        return s.to_string();
    };
    let (int_part, dot_frac) = s.split_at(dot);
    let frac = &dot_frac[1..];
    let leading_zeros = frac.bytes().take_while(|b| *b == b'0').count();
    let keep = leading_zeros + 3;
    let truncated: String = frac.chars().take(keep).collect();
    let final_frac = truncated.trim_end_matches('0');
    if final_frac.is_empty() {
        int_part.to_string()
    } else {
        format!("{int_part}.{final_frac}")
    }
}

fn banner<'a>(t: KaoTheme, title: &'a str, body: String) -> Element<'a, Message> {
    container(
        column![
            text(title).size(14).color(t.down).font(bold()),
            vspace(4),
            text(body).size(12).color(t.sub),
        ]
        .spacing(0),
    )
    .padding(Padding::from([14, 16]))
    .width(Length::Fill)
    .style(move |_| container::Style {
        background: Some(Background::Color(with_alpha(t.down, 0.06))),
        border: Border {
            color: with_alpha(t.down, 0.3),
            width: 1.0,
            radius: Radius::from(12),
        },
        text_color: Some(t.text),
        ..container::Style::default()
    })
    .into()
}

fn preflight_banner<'a>(
    t: KaoTheme,
    threshold: u32,
    local_count: usize,
    kinds: &[&str],
) -> Element<'a, Message> {
    let mut lines = column![].spacing(4);
    lines = lines.push(
        text(format!(
            "This Safe requires {threshold} signature(s) to send."
        ))
        .size(13)
        .color(t.text)
        .font(bold()),
    );
    lines = lines.push(
        text(format!(
            "This wallet has {local_count} local key(s) that can sign."
        ))
        .size(12)
        .color(t.sub),
    );
    if !kinds.is_empty() {
        let joined = kinds.join(", ");
        lines = lines.push(
            text(format!("Unsupported signer types: {joined}"))
                .size(12)
                .color(t.sub),
        );
    }
    container(
        column![
            text("Can't send from this Safe")
                .size(14)
                .color(t.down)
                .font(bold()),
            vspace(6),
            lines,
        ]
        .spacing(0),
    )
    .padding(Padding::from([14, 16]))
    .width(Length::Fill)
    .style(move |_| container::Style {
        background: Some(Background::Color(with_alpha(t.down, 0.06))),
        border: Border {
            color: with_alpha(t.down, 0.3),
            width: 1.0,
            radius: Radius::from(12),
        },
        text_color: Some(t.text),
        ..container::Style::default()
    })
    .into()
}

fn unsupported_chain_banner<'a>(t: KaoTheme, chain_id: u64) -> Element<'a, Message> {
    banner(
        t,
        "Unsupported chain",
        format!(
            "This Safe is on chain ID {chain_id}, which Kao doesn't support for signing yet. \
         Sending is restricted to avoid a chainId mismatch in the EIP-712 domain."
        ),
    )
}

fn wrap_safe_modal<'a>(
    t: KaoTheme,
    progress: f32,
    content: Element<'a, Message>,
) -> Element<'a, Message> {
    modal_wrapper(
        t,
        560.0,
        progress,
        Message::Close,
        Message::BoxClickIgnored,
        content,
    )
}

fn review_card<'a, M: 'a>(t: KaoTheme, content: Element<'a, M>) -> Element<'a, M> {
    container(content)
        .padding(Padding::from([12, 14]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(14),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
}

fn safe_step_header<'a>(t: KaoTheme, step: u8) -> Element<'a, Message> {
    let (kao, title) = match step {
        0 => ("(づ ◕‿◕ )づ", "Send from Safe"),
        1 => ("(•̀ᴗ•́)و", "Send from Safe"),
        2 => ("( •̀ω•́ )✧", "Send from Safe"),
        _ => ("ヽ(・∀・)ﾉ", "Complete"),
    };
    let step_label = format!(
        "Step {} of {SAFE_TOTAL_STEPS}",
        step.saturating_add(1).min(SAFE_TOTAL_STEPS)
    );
    row![
        kao_text(t, kao, 30.0),
        Space::new().width(12),
        column![
            text(title).size(22).color(t.text).font(black()),
            text(step_label).size(12).color(t.sub).font(mono())
        ]
        .spacing(0),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill)
    .into()
}

fn safe_progress_bar<'a>(t: KaoTheme, step: u8) -> Element<'a, Message> {
    let mut bar = row![].spacing(5).width(Length::Fill);
    for i in 0..SAFE_TOTAL_STEPS {
        let active = i <= step.min(2);
        let seg = container(Space::new().width(Length::Fill).height(4.0))
            .width(Length::FillPortion(1))
            .style(move |_| container::Style {
                background: Some(Background::Color(if active { t.a1 } else { t.border })),
                border: Border {
                    color: Color::TRANSPARENT,
                    width: 0.0,
                    radius: Radius::from(2),
                },
                ..container::Style::default()
            });
        bar = bar.push(seg);
    }
    container(bar).padding(Padding::from([16, 0])).into()
}

fn safe_summary<'a>(t: KaoTheme, safe: Address, chain: Chain) -> Element<'a, Message> {
    let head = row![
        avatar(t, "(◐‿◐)", 34.0, t.ab2),
        Space::new().width(10),
        column![
            text("From Safe").size(11).color(t.sub).font(mono_bold()),
            text(chain.display_name())
                .size(12)
                .color(t.text)
                .font(bold())
        ]
        .spacing(2)
        .width(Length::Fill),
    ]
    .align_y(Alignment::Center);
    container(column![head, vspace(8), colored_address(t, safe)].spacing(0))
        .padding(Padding::from([12, 14]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card_alt)),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(14),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
}

// ── SafeSendRequest + PreparedSafeTx ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SafeSendRequest {
    pub safe_address: Address,
    pub chain: Chain,
    pub version: String,
    pub trust: SafeTrust,
    pub service_base: String,
    pub recipient: Address,
    pub amount_units: U256,
    pub token: SendToken,
    pub threshold: u32,
    pub signable_indices: Vec<u32>,
    pub prepared: Option<PreparedSafeTx>,
}

impl SafeSendRequest {
    pub fn safe_tx_input(&self) -> SafeTxInput {
        match &self.token {
            SendToken::Native => SafeTxInput {
                to: self.recipient,
                value: self.amount_units,
                data: Bytes::new(),
                operation: Operation::Call,
            },
            SendToken::Erc20 { contract } => SafeTxInput {
                to: *contract,
                value: U256::ZERO,
                data: erc20_transfer_calldata(self.recipient, self.amount_units),
                operation: Operation::Call,
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PreparedSafeTx {
    pub nonce: u64,
    pub safe_tx_hash: B256,
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::{Contact, ContactEns, SafeTrust};

    fn local_account(seed: u8, name: Option<&str>) -> AccountDescriptor {
        let mut bytes = [seed; 32];
        if bytes.iter().all(|b| *b == 0) {
            bytes[0] = 1;
        }
        AccountDescriptor::Local {
            name: name.map(str::to_string),
            key_bytes: bytes.into(),
        }
    }

    fn view_only_account(byte: u8, name: Option<&str>) -> AccountDescriptor {
        AccountDescriptor::ViewOnly {
            name: name.map(str::to_string),
            address: [byte; 20],
        }
    }

    fn safe_desc(addr_byte: u8, name: Option<&str>, linked: Vec<u32>) -> SafeDescriptor {
        SafeDescriptor {
            name: name.map(str::to_string),
            chain_id: 1,
            address: [addr_byte; 20],
            version: "1.4.1".into(),
            trust: SafeTrust::Canonical,
            threshold: 1,
            owners: vec![[0u8; 20]; linked.len().max(1)],
            modules: Vec::new(),
            guard: None,
            fallback_handler: None,
            linked_signer_indices: linked,
            sibling_chains: Vec::new(),
            cached_at: 0,
            tx_service_url: None,
        }
    }

    fn contact(addr_byte: u8, name: &str, ens: Option<&str>) -> Contact {
        Contact {
            name: name.to_string(),
            address: [addr_byte; 20],
            kaomoji: String::new(),
            notes: String::new(),
            ens: ens.map(|n| ContactEns {
                name: n.to_string(),
                last_resolved_addr: [addr_byte; 20],
            }),
        }
    }

    #[test]
    fn merged_view_orders_contacts_before_own_addresses() {
        let mut book = ContactsBook::new();
        book.upsert(contact(0xaa, "alice", None));
        let accounts = vec![local_account(1, Some("hot wallet"))];
        let safes = vec![safe_desc(0xcc, Some("treasury"), vec![0])];
        let view = ContactsView::merged(&book, &accounts, &safes, None, None);
        assert_eq!(view.entries.len(), 3);
        assert_eq!(view.entries[0].name, "alice");
        assert_eq!(view.entries[0].kind, PickerKind::Contact);
        assert_eq!(view.entries[1].name, "hot wallet");
        assert_eq!(view.entries[1].kind, PickerKind::OwnAccount);
        assert_eq!(view.entries[1].chip, Some("Local"));
        assert_eq!(view.entries[2].name, "treasury");
        assert_eq!(view.entries[2].kind, PickerKind::OwnSafe);
        assert_eq!(view.entries[2].chip, Some("Safe"));
    }

    #[test]
    fn merged_view_excludes_active_account_in_eoa_mode() {
        let book = ContactsBook::new();
        let accounts = vec![
            local_account(1, Some("hot")),
            local_account(2, Some("cold")),
        ];
        let view = ContactsView::merged(&book, &accounts, &[], Some(0), None);
        let names: Vec<_> = view.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["cold"]);
    }

    #[test]
    fn merged_view_excludes_active_safe_in_safe_mode() {
        let book = ContactsBook::new();
        let safes = vec![
            safe_desc(0xc0, Some("treasury"), vec![]),
            safe_desc(0xc1, Some("ops"), vec![]),
        ];
        let view = ContactsView::merged(&book, &[], &safes, None, Some(0));
        let names: Vec<_> = view.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["ops"]);
    }

    #[test]
    fn merged_view_dedupes_when_own_account_is_also_a_contact() {
        let mut book = ContactsBook::new();
        book.upsert(contact(0x42, "alice (pinned)", Some("alice.eth")));
        let accounts = vec![view_only_account(0x42, Some("watched"))];
        let view = ContactsView::merged(&book, &accounts, &[], None, None);
        assert_eq!(view.entries.len(), 1);
        assert_eq!(view.entries[0].name, "alice (pinned)");
        assert_eq!(view.entries[0].kind, PickerKind::Contact);
        assert_eq!(view.entries[0].ens.as_deref(), Some("alice.eth"));
    }

    #[test]
    fn merged_view_renders_watch_only_safe_chip() {
        let book = ContactsBook::new();
        let safes = vec![safe_desc(0xcd, Some("public dao"), vec![])];
        let view = ContactsView::merged(&book, &[], &safes, None, None);
        assert_eq!(view.entries.len(), 1);
        assert_eq!(view.entries[0].kind, PickerKind::OwnSafe);
        assert_eq!(view.entries[0].chip, Some("Safe watch"));
    }

    #[test]
    fn merged_view_carries_contact_ens_through_picker_entry() {
        let mut book = ContactsBook::new();
        book.upsert(contact(0xab, "vitalik", Some("vitalik.eth")));
        let view = ContactsView::merged(&book, &[], &[], None, None);
        assert_eq!(view.entries[0].ens.as_deref(), Some("vitalik.eth"));
        let accounts = vec![local_account(1, Some("hot"))];
        let view = ContactsView::merged(&ContactsBook::new(), &accounts, &[], None, None);
        assert!(view.entries[0].ens.is_none());
    }

    #[test]
    fn name_for_resolves_across_all_picker_kinds() {
        let mut book = ContactsBook::new();
        book.upsert(contact(0xaa, "alice", None));
        let accounts = vec![local_account(1, Some("hot"))];
        let safes = vec![safe_desc(0xcc, Some("treasury"), vec![0])];
        let view = ContactsView::merged(&book, &accounts, &safes, None, None);
        let alice_addr = Address::from([0xaa; 20]);
        assert_eq!(view.name_for(alice_addr), Some("alice"));
        let hot_addr = view
            .entries
            .iter()
            .find(|e| matches!(e.kind, PickerKind::OwnAccount))
            .unwrap()
            .address;
        assert_eq!(view.name_for(hot_addr), Some("hot"));
        let safe_addr = Address::from([0xcc; 20]);
        assert_eq!(view.name_for(safe_addr), Some("treasury"));
        assert!(view.name_for(Address::ZERO).is_none());
    }

    // ── Safe-specific tests (migrated from safe_send.rs) ────────────────

    fn safe_only(threshold: u32, linked: Vec<u32>) -> SafeDescriptor {
        SafeDescriptor {
            name: None,
            chain_id: 1,
            address: [0x5A; 20],
            version: "1.4.1".into(),
            trust: SafeTrust::Canonical,
            threshold,
            owners: vec![[0u8; 20]; linked.len().max(threshold as usize)],
            modules: Vec::new(),
            guard: None,
            fallback_handler: None,
            linked_signer_indices: linked,
            sibling_chains: Vec::new(),
            cached_at: 0,
            tx_service_url: None,
        }
    }

    fn local_account_simple(seed: u8) -> AccountDescriptor {
        let mut bytes = [seed; 32];
        if bytes.iter().all(|b| *b == 0) {
            bytes[0] = 1;
        }
        AccountDescriptor::Local {
            name: None,
            key_bytes: bytes.into(),
        }
    }

    fn test_portfolio() -> Vec<LiveToken> {
        vec![LiveToken {
            symbol: "ETH".into(),
            name: "Ether".into(),
            chain: Chain::Mainnet.into(),
            contract: None,
            decimals: 18,
            balance: "1.0".into(),
            balance_raw: U256::from(1_000_000_000_000_000_000u64),
            balance_f64: 1.0,
            usd_price: 3000.0,
            usd_value: 3000.0,
        }]
    }

    #[test]
    fn unknown_chain_blocks_outgoing_request() {
        let mut desc = safe_only(1, vec![0]);
        desc.chain_id = 999999;
        let pane = SendPane::new_safe(&desc, &[local_account_simple(1)]);
        assert!(pane.safe().unwrap().safe_chain.is_none());
        assert!(pane.outgoing_request(&test_portfolio()).is_none());
    }

    #[test]
    fn set_to_rejects_zero_address() {
        let mut pane = SendPane::new_safe(&safe_only(1, vec![0]), &[local_account_simple(1)]);
        pane.set_to("0x0000000000000000000000000000000000000000".into());
        assert!(
            matches!(pane.resolution, Resolution::Invalid),
            "zero address must resolve to Invalid, got {:?}",
            pane.resolution,
        );
    }

    fn token_info(symbol: &str, decimals: u8) -> crate::decode::render::TokenInfo {
        crate::decode::render::TokenInfo {
            symbol: symbol.to_string(),
            decimals,
        }
    }

    /// A verified on-chain read whose `decimals` matches the indexer yields the
    /// same figure and is trusted.
    #[test]
    fn resolve_safe_amount_verified_matching_decimals() {
        // 100 USDC at 6 decimals.
        let units = U256::from(100_000_000u64);
        let erc20 = SendToken::Erc20 {
            contract: Address::repeat_byte(0x11),
        };
        let (amount, symbol, verified) = resolve_safe_amount_display(
            units,
            &erc20,
            Some((token_info("USDC", 6), true)),
            "100".into(),
            "USDC".into(),
        );
        assert_eq!(amount, "100");
        assert_eq!(symbol, "USDC");
        assert!(verified);
    }

    /// A lying indexer (claimed 18 decimals so `amount_units` was scaled by
    /// 10^18) is exposed: the verified 6-decimal read reformats the SAME raw
    /// units to the true, wildly-larger on-chain figure, and stays verified.
    #[test]
    fn resolve_safe_amount_verified_exposes_indexer_lie() {
        // User thought "100 TKN"; indexer's 18-dec lie made units = 100 * 10^18.
        let units = U256::from(100u64) * U256::from(10u64).pow(U256::from(18u64));
        let erc20 = SendToken::Erc20 {
            contract: Address::repeat_byte(0x22),
        };
        let (amount, symbol, verified) = resolve_safe_amount_display(
            units,
            &erc20,
            Some((token_info("TKN", 6), true)),
            "100".into(), // the deceptive indexer-consistent display
            "TKN".into(),
        );
        // 100e18 / 10^6 = 100,000,000,000,000 — the truth the user must see.
        assert_eq!(amount, "100000000000000");
        assert_eq!(symbol, "TKN");
        assert!(verified);
    }

    /// An unverified (Helios-fallback) read still reformats but flags the amount
    /// so the UI tags it and softens the action.
    #[test]
    fn resolve_safe_amount_unverified_read_flags() {
        let units = U256::from(5_000_000u64);
        let erc20 = SendToken::Erc20 {
            contract: Address::repeat_byte(0x33),
        };
        let (amount, symbol, verified) = resolve_safe_amount_display(
            units,
            &erc20,
            Some((token_info("DAI", 6), false)),
            "5".into(),
            "DAI".into(),
        );
        assert_eq!(amount, "5");
        assert_eq!(symbol, "DAI");
        assert!(!verified, "fallback read must not be trusted");
    }

    /// A failed read (`None`) falls back to the indexer display but is flagged
    /// unverified.
    #[test]
    fn resolve_safe_amount_read_failure_falls_back_unverified() {
        let units = U256::from(1u64);
        let erc20 = SendToken::Erc20 {
            contract: Address::repeat_byte(0x44),
        };
        let (amount, symbol, verified) =
            resolve_safe_amount_display(units, &erc20, None, "1.23".into(), "WHO".into());
        assert_eq!(amount, "1.23");
        assert_eq!(symbol, "WHO");
        assert!(!verified);
    }

    /// Native sends carry no ERC-20 decimals risk (the native row's identity is
    /// chain-pinned at ingestion), so they pass through as verified.
    #[test]
    fn resolve_safe_amount_native_passthrough() {
        let (amount, symbol, verified) = resolve_safe_amount_display(
            U256::from(10u64),
            &SendToken::Native,
            None,
            "0.5".into(),
            "ETH".into(),
        );
        assert_eq!(amount, "0.5");
        assert_eq!(symbol, "ETH");
        assert!(verified);
    }

    #[test]
    fn build_plan_rejects_zero_recipient() {
        // A picked zero address bypasses `set_to`'s parse guard, so
        // `build_plan` must independently refuse it before producing a
        // signable plan.
        let mut pane = SendPane::new_eoa(Address::repeat_byte(0xAB));
        pane.amount = "0.1".into();
        // Control: the identical setup with a real recipient builds a plan,
        // so a `None` below can only be the zero-address guard firing.
        let _ = pane.update(Message::PickRecipient {
            address: Address::repeat_byte(0xCD),
            ens: None,
        });
        assert!(
            pane.build_plan(&test_portfolio()).is_some(),
            "control: a non-zero recipient should build a plan",
        );
        let _ = pane.update(Message::PickRecipient {
            address: Address::ZERO,
            ens: None,
        });
        assert!(
            pane.build_plan(&test_portfolio()).is_none(),
            "build_plan must reject a zero recipient",
        );
    }

    #[test]
    fn send_review_confirm_gate_blocks_when_eth_insufficient() {
        // The sign-review overlay derives its Confirm button state from the
        // reviewed figures. A send that can't cover its own gas must be *blocked*
        // (not merely softened), so a user can never sign it — the fund-safety
        // invariant the old inline review enforced, now on the overlay.
        use crate::wallet::sim::SimulationResult;
        let plan = SendPlan {
            from: Address::repeat_byte(0xAB),
            recipient: Address::repeat_byte(0xCD),
            token: SendToken::Native,
            amount_units: U256::from(1u64),
            chain: Chain::Mainnet.into(),
        };
        let make = |has_insufficient_eth: bool| SendReview {
            chain: plan.chain,
            recipient: plan.recipient,
            recipient_name: None,
            recipient_in_book: false,
            recipient_kao: "(・_・)".to_string(),
            recipient_chip: None,
            amount: "1".to_string(),
            token_symbol: "ETH".to_string(),
            token_contract: None,
            token_balance_before: 1.0,
            usd_price: 0.0,
            eth_usd_price: 0.0,
            has_insufficient_eth,
            quote: TxQuote {
                plan: plan.clone(),
                gas_limit: 21_000,
                max_fee_per_gas: 1,
                max_priority_fee_per_gas: 1,
                nonce: 0,
                eth_cost_wei: U256::from(21_000u64),
                sim: SimulationResult::unavailable(),
            },
            decoded: Box::new(DecodeResult::Empty),
            calldata_digest: None,
        };

        let funded = make(false);
        assert!(!funded.confirm_disabled(), "a funded send must be signable");
        assert_eq!(funded.confirm_label(), "Sign & Send");

        let broke = make(true);
        assert!(
            broke.confirm_disabled(),
            "a send that can't cover gas must be blocked from signing",
        );
        assert_eq!(broke.confirm_label(), "Need ETH for gas");
    }

    #[test]
    fn outgoing_request_rejects_zero_recipient() {
        let mut pane = SendPane::new_safe(&safe_only(1, vec![0]), &[local_account_simple(1)]);
        pane.amount = "0.001".into();
        // Control, mirroring `outgoing_request_uses_resolved_recipient`.
        let _ = pane.update(Message::PickRecipient {
            address: Address::repeat_byte(0xCD),
            ens: None,
        });
        assert!(
            pane.outgoing_request(&test_portfolio()).is_some(),
            "control: a non-zero recipient should build a request",
        );
        let _ = pane.update(Message::PickRecipient {
            address: Address::ZERO,
            ens: None,
        });
        assert!(
            pane.outgoing_request(&test_portfolio()).is_none(),
            "outgoing_request must reject a zero recipient",
        );
    }

    #[test]
    fn unrecognized_safe_blocks_continue_and_outgoing_request() {
        let mut desc = safe_only(1, vec![0]);
        desc.trust = SafeTrust::UnrecognizedImpl;
        let mut pane = SendPane::new_safe(&desc, &[local_account_simple(1)]);
        pane.amount = "0.001".into();
        let _ = pane.update(Message::PickRecipient {
            address: Address::repeat_byte(0xCD),
            ens: None,
        });

        assert!(pane.has_any_signable(), "control: linked signer exists");
        assert!(
            !pane.can_continue_recipient(),
            "unrecognized Safe must not advance to review"
        );
        assert!(
            pane.outgoing_request(&test_portfolio()).is_none(),
            "unrecognized Safe must not build a signable request"
        );
    }

    #[test]
    fn ens_resolved_with_stale_seq_is_dropped() {
        let mut pane = SendPane::new_safe(&safe_only(1, vec![0]), &[local_account_simple(1)]);
        pane.set_to("vitalik.eth".to_string());
        let _ = pane.take_pending_ens().unwrap();
        pane.set_to("kao.eth".to_string());
        let stale = Address::repeat_byte(0x42);
        let _ = pane.update(Message::EnsResolved {
            seq: 1,
            name: "vitalik.eth".to_string(),
            result: Ok(Some(stale)),
        });
        assert!(matches!(pane.resolution, Resolution::Resolving { .. }));
    }

    #[test]
    fn pick_recipient_with_ens_enters_address_verifying() {
        let mut pane = SendPane::new_safe(&safe_only(1, vec![0]), &[local_account_simple(1)]);
        let addr = Address::repeat_byte(0x77);
        let _ = pane.update(Message::PickRecipient {
            address: addr,
            ens: Some("vitalik.eth".to_string()),
        });
        match &pane.resolution {
            Resolution::AddressVerifying { pinned, name } => {
                assert_eq!(*pinned, addr);
                assert_eq!(name, "vitalik.eth");
            }
            other => panic!("expected AddressVerifying, got {other:?}"),
        }
        assert!(pane.take_pending_ens().is_some());
    }

    #[test]
    fn pick_recipient_without_ens_settles_directly() {
        let mut pane = SendPane::new_safe(&safe_only(1, vec![0]), &[local_account_simple(1)]);
        let addr = Address::repeat_byte(0x55);
        let _ = pane.update(Message::PickRecipient {
            address: addr,
            ens: None,
        });
        assert!(matches!(pane.resolution, Resolution::Address(_)));
        assert!(pane.take_pending_ens().is_none());
    }

    #[test]
    fn ens_divergence_blocks_continue_until_accepted() {
        let mut pane = SendPane::new_safe(&safe_only(1, vec![0]), &[local_account_simple(1)]);
        pane.amount = "0.1".into();
        let pinned = Address::repeat_byte(0x11);
        let _ = pane.update(Message::PickRecipient {
            address: pinned,
            ens: Some("vitalik.eth".to_string()),
        });
        assert!(pane.can_continue_recipient());
        let (seq, name) = pane.take_pending_ens().unwrap();
        let fresh = Address::repeat_byte(0x99);
        let _ = pane.update(Message::EnsResolved {
            seq,
            name,
            result: Ok(Some(fresh)),
        });
        assert!(matches!(pane.resolution, Resolution::EnsDivergence { .. }));
        assert!(!pane.can_continue_recipient());
        let _ = pane.update(Message::AcceptEnsDivergence);
        assert!(matches!(pane.resolution, Resolution::Address(a) if a == fresh));
        assert!(pane.can_continue_recipient());
    }

    #[test]
    fn save_as_contact_emits_outcome_for_address_input() {
        let mut pane = SendPane::new_safe(&safe_only(1, vec![0]), &[local_account_simple(1)]);
        pane.set_to("0x000000000000000000000000000000000000dEaD".into());
        let (_, outcome) = pane.update(Message::SaveAsContactClicked);
        let (addr, ens) = match outcome {
            Some(Outcome::SaveAsContact { address, ens }) => (address, ens),
            other => panic!("expected SaveAsContact, got {other:?}"),
        };
        assert_eq!(
            addr,
            "0x000000000000000000000000000000000000dEaD"
                .parse::<Address>()
                .unwrap()
        );
        assert!(ens.is_none());
    }

    #[test]
    fn save_as_contact_carries_ens_name_when_resolved() {
        let mut pane = SendPane::new_safe(&safe_only(1, vec![0]), &[local_account_simple(1)]);
        pane.set_to("vitalik.eth".to_string());
        let (seq, name) = pane.take_pending_ens().unwrap();
        let addr = Address::repeat_byte(0xab);
        let _ = pane.update(Message::EnsResolved {
            seq,
            name,
            result: Ok(Some(addr)),
        });
        let (_, outcome) = pane.update(Message::SaveAsContactClicked);
        let (got_addr, ens) = match outcome {
            Some(Outcome::SaveAsContact { address, ens }) => (address, ens),
            other => panic!("expected SaveAsContact, got {other:?}"),
        };
        assert_eq!(got_addr, addr);
        assert_eq!(ens.as_deref(), Some("vitalik.eth"));
    }

    #[test]
    fn outgoing_request_uses_resolved_recipient() {
        let mut pane = SendPane::new_safe(&safe_only(1, vec![0]), &[local_account_simple(1)]);
        pane.set_to("0x000000000000000000000000000000000000dEaD".into());
        pane.amount = "0.001".into();
        let req = pane.outgoing_request(&test_portfolio()).unwrap();
        assert_eq!(
            req.recipient,
            "0x000000000000000000000000000000000000dEaD"
                .parse::<Address>()
                .unwrap()
        );
        pane.set_to("0x000000000000000000000000000000000000beef".into());
        let req = pane.outgoing_request(&test_portfolio()).unwrap();
        assert_eq!(
            req.recipient,
            "0x000000000000000000000000000000000000bEEf"
                .parse::<Address>()
                .unwrap()
        );
    }
}
