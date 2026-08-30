//! Safe transaction detail modal — full view of one queued multisig tx
//! plus the collaborative actions: **Confirm** (add my signature),
//! **Execute** (broadcast once threshold is met), and **Reject** (queue a
//! same-nonce cancellation).
//!
//! The pane is a viewer + intent emitter, like `safe_send`: it carries no
//! signer or RPC access. On open the dashboard loads the full
//! `SafeTxDetail` (owners + their signatures) and pushes it in via
//! [`SafeTxDetailPane::set_detail`]; the action buttons bubble
//! [`Outcome`]s the dashboard turns into signed service calls, with the
//! result fed back through [`SafeTxDetailPane::set_action_result`].

use alloy::primitives::{Address, B256};
use iced::border::Radius;
use iced::keyboard;
use iced::widget::text::Wrapping;
use iced::widget::{Space, column, container, row, scrollable, text};
use iced::{Alignment, Background, Border, Color, Element, Length, Padding, Subscription, Task};

use crate::chain::Chain;
use crate::portfolio::LiveToken;
use crate::safe::SafeTx;
use crate::safe::service::{PendingSafeTx, SafeTxDetail, SafeTxState};
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::{
    bold, colored_address, colored_hash_copyable, kao_fit, kao_scrollable_style, modal_wrapper,
    mono, mono_black, mono_bold, primary_button, secondary_button, section_card,
    small_secondary_button,
};
use crate::ui::wallet_dashboard::sim_view;
use crate::wallet::sim::SimulationResult;
use crate::wallet::{SafeTrust, short_address};

#[derive(Debug, Clone)]
pub enum Message {
    /// No-op published by a copyable address click so the dashboard's "Copied!"
    /// toast animation starts (a click changes no state otherwise). Ignored.
    AddressCopied,
    Close,
    BoxClickIgnored,
    Confirm,
    Execute,
    Reject,
    /// User pressed the Re-simulate button in the SIMULATION card.
    RetrySims,
    Key(keyboard::Event),
}

#[derive(Debug, Clone)]
pub enum Outcome {
    Closed,
    /// Sign this tx with one of my linked owners and POST the
    /// confirmation.
    Confirm,
    /// Assemble the collected signatures and broadcast `execTransaction`.
    Execute,
    /// Propose a same-nonce rejection.
    Reject,
    /// Re-spawn the inner/exec preflight tasks for the loaded detail.
    /// The pane already cleared its sim state (back to "simulating…").
    RetrySims,
}

impl Outcome {
    /// Variant name for the GUI state trace.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Closed => "Closed",
            Outcome::Confirm => "Confirm",
            Outcome::Execute => "Execute",
            Outcome::Reject => "Reject",
            Outcome::RetrySims => "RetrySims",
        }
    }
}

/// Coarse simulation-result name for the GUI state trace.
fn sim_name(sim: &SimulationResult) -> &'static str {
    if sim.is_success() {
        if sim.verified {
            "success"
        } else {
            "success_unverified"
        }
    } else if sim.is_revert() {
        "revert"
    } else {
        "unavailable"
    }
}

#[derive(Debug)]
pub struct SafeTxDetailPane {
    safe: Address,
    chain: Chain,
    /// `VERSION()` snapshot from the SafeDescriptor at open. The
    /// dashboard gates Confirm/Reject on
    /// `safe::tx::ensure_signable_version` with this — signing for a
    /// pre-1.3 domain shape is refused before any signer is built.
    version: String,
    /// Trust snapshot from the active SafeDescriptor at open. Only
    /// canonical implementations may emit signing/execution outcomes.
    trust: SafeTrust,
    /// Transaction-service base for THIS Safe (custom mirror or the
    /// public default), snapshotted at open so every action in the
    /// modal talks to the same service the queue row came from.
    service_base: String,
    /// Lean record the row was opened from — renders immediately while
    /// the full detail loads.
    pending: PendingSafeTx,
    /// Every owner of the Safe (for the signed/pending checklist).
    owners: Vec<Address>,
    /// Owner addresses this wallet can actually sign with (Local or
    /// hardware; not view-only).
    signable: Vec<Address>,
    /// Whether the wallet holds a Local account that can pay gas to
    /// execute. Gates the Execute button.
    has_local_executor: bool,
    /// Full detail (owners' signatures + reconstructed tx), loaded async.
    detail: Option<SafeTxDetail>,
    loading: bool,
    error: Option<String>,
    /// An action (confirm/execute/reject) is in flight.
    busy: bool,
    /// Last action result: `(message, is_error)`.
    notice: Option<(String, bool)>,
    /// Inner-call preflight: the SafeTx body simulated as if the Safe
    /// were the caller. Injected by the dashboard after the detail
    /// loads (only the loaded `detail.tx` is the authoritative SafeTx).
    /// `None` while in flight; never spawned for delegatecall — the
    /// SIMULATION card carries the skip note instead.
    inner_sim: Option<SimulationResult>,
    /// Full `execTransaction` preflight with the gathered signatures.
    /// Only spawned when the tx is next-up for execution and this
    /// wallet holds a local executor. Catches GS-code failures (bad
    /// sigs, stale nonce); faithful even for delegatecall.
    exec_sim: Option<SimulationResult>,
    /// One automatic verified-retry per (re)load for each sim — set the
    /// moment an unverified-success result is consumed, so a second
    /// unverified result stays on screen (with the Re-simulate button)
    /// instead of looping.
    inner_sim_auto_retried: bool,
    exec_sim_auto_retried: bool,
    /// The action in flight is an Execute (vs Confirm/Reject). Lets
    /// `set_action_result` know a success means "broadcast submitted".
    pending_execute: bool,
    /// An `execTransaction` broadcast for this tx succeeded from this
    /// modal. The Transaction Service won't reflect the execution until
    /// it indexes the mined tx (seconds to minutes), so post-action
    /// reloads keep returning the stale "ready to execute" state — this
    /// flag drives the optimistic UI meanwhile: badge "Execution
    /// submitted", all action buttons hidden (the tx is on the wire;
    /// re-signing or re-executing can only waste gas).
    exec_submitted: bool,
}

impl SafeTxDetailPane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        safe: Address,
        chain: Chain,
        version: String,
        trust: SafeTrust,
        service_base: String,
        pending: PendingSafeTx,
        owners: Vec<Address>,
        signable: Vec<Address>,
        has_local_executor: bool,
    ) -> Self {
        Self {
            safe,
            chain,
            version,
            trust,
            service_base,
            pending,
            owners,
            signable,
            has_local_executor,
            detail: None,
            loading: true,
            error: None,
            busy: false,
            notice: None,
            inner_sim: None,
            exec_sim: None,
            inner_sim_auto_retried: false,
            exec_sim_auto_retried: false,
            pending_execute: false,
            exec_submitted: false,
        }
    }

    pub fn safe(&self) -> Address {
        self.safe
    }
    pub fn chain(&self) -> Chain {
        self.chain
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn service_base(&self) -> &str {
        &self.service_base
    }
    pub fn nonce(&self) -> u64 {
        self.pending.nonce
    }
    pub fn safe_tx_hash(&self) -> B256 {
        self.pending.safe_tx_hash
    }
    /// First owner this wallet can sign with (any state) — the signer for
    /// a rejection, which doesn't care whether the target was signed.
    pub fn signable_owner(&self) -> Option<Address> {
        self.signable.first().copied()
    }
    pub fn busy(&self) -> bool {
        self.busy
    }
    pub fn loaded_detail(&self) -> Option<&SafeTxDetail> {
        self.detail.as_ref()
    }

    /// State driving the badge + action gating. Prefers the freshly-loaded
    /// detail's state (which a post-action reload refreshes) over the
    /// list-time `pending.state` snapshot, so the badge advances after a
    /// confirm/execute without closing the modal.
    fn effective_state(&self) -> SafeTxState {
        self.detail
            .as_ref()
            .map(|d| d.state)
            .unwrap_or(self.pending.state)
    }

    /// Safe operation byte for the badge/warning: `0` call,
    /// `1` delegatecall. Prefers the loaded detail's reconstructed tx
    /// (authoritative — it's what the execute path encodes) over the
    /// list-time snapshot.
    fn effective_operation(&self) -> u8 {
        self.detail
            .as_ref()
            .map(|d| d.tx.operation)
            .unwrap_or(self.pending.operation)
    }

    /// The calldata this transaction actually carries, preferring the loaded
    /// `SafeTx` over the list snapshot for the same reason
    /// [`Self::effective_operation`] does: the loaded record is the one the
    /// hash was computed over.
    fn effective_data(&self) -> &[u8] {
        self.detail
            .as_ref()
            .map(|d| d.tx.data.as_ref())
            .unwrap_or(self.pending.data.as_ref())
    }

    /// The sub-calls packed inside a MultiSend batch, when this transaction is
    /// one.
    ///
    /// `None` when it isn't — an ordinary Safe transaction has nothing to
    /// unpack. `Some(Err)` when it is addressed to a canonical MultiSend
    /// library by `DELEGATECALL` and the blob will *not* parse, which is the
    /// one case that must be said out loud: silently falling back to the hex
    /// dump would present a batch this wallet cannot account for as though
    /// there were nothing to account for.
    ///
    /// This is what a co-signer had instead of a batch: `to` = 0x9641…02e2,
    /// `operation` = 1, and 742 bytes of `0x8d80ff0a…`. Everything needed to
    /// unpack it was already in the tree — [`decode_multisend_calldata`] is the
    /// inverse the Builder's own review has used since it started clear-signing
    /// batches — and only the proposing side was ever calling it.
    fn batch_contents(
        &self,
    ) -> Option<Result<Vec<crate::txbuilder::multisend::PackedCall>, String>> {
        use crate::txbuilder::multisend::{
            MULTISEND_CALL_ONLY_1_3_0, MULTISEND_CALL_ONLY_1_4_1, decode_multisend_calldata,
        };
        let to = self
            .detail
            .as_ref()
            .map(|d| d.tx.to)
            .unwrap_or(self.pending.to);
        let is_multisend = matches!(to, MULTISEND_CALL_ONLY_1_3_0 | MULTISEND_CALL_ONLY_1_4_1);
        if !is_multisend || self.effective_operation() != 1 {
            return None;
        }
        Some(decode_multisend_calldata(self.effective_data()).map_err(|e| e.to_string()))
    }

    /// Owner addresses that this wallet controls and that have **not** yet
    /// signed — the candidates for Confirm. Empty until detail loads.
    pub fn unsigned_signable(&self) -> Vec<Address> {
        let Some(detail) = &self.detail else {
            return Vec::new();
        };
        let signed = detail.owners_signed();
        self.signable
            .iter()
            .copied()
            .filter(|a| !signed.contains(a))
            .collect()
    }

    pub fn set_detail(&mut self, result: Result<SafeTxDetail, String>) {
        self.loading = false;
        // Sims describe a specific loaded detail — a (re)load
        // invalidates them; the dashboard re-spawns the tasks.
        self.inner_sim = None;
        self.exec_sim = None;
        self.inner_sim_auto_retried = false;
        self.exec_sim_auto_retried = false;
        match result {
            Ok(d) => {
                self.detail = Some(d);
                self.error = None;
            }
            Err(e) => self.error = Some(e),
        }
    }

    /// Store the inner-sim result. Returns `true` when the dashboard
    /// should dispatch the one automatic verified-retry: the sim
    /// succeeded but ran on fallback state, and this load hasn't
    /// retried yet.
    pub fn set_inner_sim(&mut self, result: SimulationResult) -> bool {
        let auto = result.is_success() && !result.verified && !self.inner_sim_auto_retried;
        if auto {
            self.inner_sim_auto_retried = true;
        }
        crate::trace::state("safe_tx_detail", "inner_sim", "…", sim_name(&result));
        self.inner_sim = Some(result);
        auto
    }

    /// Exec-sim sibling of [`Self::set_inner_sim`], same return contract.
    pub fn set_exec_sim(&mut self, result: SimulationResult) -> bool {
        let auto = result.is_success() && !result.verified && !self.exec_sim_auto_retried;
        if auto {
            self.exec_sim_auto_retried = true;
        }
        crate::trace::state("safe_tx_detail", "exec_sim", "…", sim_name(&result));
        self.exec_sim = Some(result);
        auto
    }

    pub fn mark_busy(&mut self) {
        self.busy = true;
        self.notice = None;
    }

    pub fn set_action_result(&mut self, result: Result<String, String>) {
        self.busy = false;
        // A successful Execute means the broadcast left this wallet —
        // flip to the optimistic submitted state regardless of what the
        // (lagging) Transaction Service says on the next reload.
        if result.is_ok() && self.pending_execute {
            self.exec_submitted = true;
        }
        self.pending_execute = false;
        self.notice = Some(match result {
            Ok(msg) => (msg, false),
            Err(e) => (e, true),
        });
    }

    /// True once an `execTransaction` broadcast succeeded from this
    /// modal. The dashboard skips the exec-time preflight in this state
    /// — simulating an already-submitted execution only produces
    /// GS-revert noise.
    pub fn exec_submitted(&self) -> bool {
        self.exec_submitted
    }

    pub fn update(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("safe_tx_detail", &msg);
        let busy_before = self.busy;
        let (task, outcome) = self.update_inner(msg);
        if busy_before != self.busy {
            crate::trace::state("safe_tx_detail", "busy", busy_before, self.busy);
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("safe_tx_detail", o.name());
        }
        (task, outcome)
    }

    fn update_inner(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        match msg {
            // Copy-toast kick — the widget already copied + marked the toast.
            Message::AddressCopied => (Task::none(), None),
            Message::Close => (Task::none(), Some(Outcome::Closed)),
            Message::BoxClickIgnored => (Task::none(), None),
            // Swallow action presses while one is already in flight so a
            // double-tap can't fire two signatures / broadcasts.
            Message::Confirm if !self.busy && self.action_availability().0 => {
                self.pending_execute = false;
                (Task::none(), Some(Outcome::Confirm))
            }
            Message::Execute if !self.busy && self.action_availability().1 => {
                self.pending_execute = true;
                (Task::none(), Some(Outcome::Execute))
            }
            Message::Reject if !self.busy && self.action_availability().2 => {
                self.pending_execute = false;
                (Task::none(), Some(Outcome::Reject))
            }
            Message::Confirm | Message::Execute | Message::Reject => (Task::none(), None),
            Message::RetrySims => {
                if self.detail.is_none() {
                    return (Task::none(), None);
                }
                // Back to "simulating…" and re-open the auto-retry
                // budget; the dashboard re-spawns the tasks.
                self.inner_sim = None;
                self.exec_sim = None;
                self.inner_sim_auto_retried = false;
                self.exec_sim_auto_retried = false;
                (Task::none(), Some(Outcome::RetrySims))
            }
            Message::Key(keyboard::Event::KeyPressed { key, .. }) => {
                if let keyboard::Key::Named(keyboard::key::Named::Escape) = key {
                    (Task::none(), Some(Outcome::Closed))
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

    pub fn view<'a>(
        &'a self,
        t: KaoTheme,
        portfolio: &'a [LiveToken],
        progress: f32,
    ) -> Element<'a, Message> {
        let is_rejection = self.pending.to == self.safe && self.pending.value.is_zero();

        let header_kao = container(kao_fit(t, "(￣ー￣)ゞ", 220.0, 48.0))
            .width(Length::Fill)
            .center_x(Length::Fill);
        let title_text = if is_rejection {
            "On-chain rejection"
        } else {
            "Safe transaction"
        };
        let title = container(text(title_text).size(14).color(t.sub).font(bold()))
            .width(Length::Fill)
            .center_x(Length::Fill);

        // Hero: value (or "Cancels nonce N" for a rejection).
        let hero: Element<'_, Message> = if is_rejection {
            text(format!("Cancels nonce {}", self.pending.nonce))
                .size(22)
                .color(t.text)
                .font(mono_black())
                .into()
        } else {
            text(format!("{} ETH", format_eth(self.pending.value)))
                .size(30)
                .color(t.text)
                .font(mono_black())
                .into()
        };
        let hero = container(hero).width(Length::Fill).center_x(Length::Fill);

        // Optimistic override: our own execution is broadcast but the
        // Transaction Service hasn't indexed it yet — the stale "Ready
        // to execute" badge would invite a double-execute.
        let state = self.effective_state();
        let badge_chip: Element<'_, Message> =
            if self.exec_submitted && !matches!(state, SafeTxState::Executed { .. }) {
                chip("Execution submitted".to_string(), t.up)
            } else {
                state_badge(t, state)
            };
        let badge = container(badge_chip)
            .width(Length::Fill)
            .center_x(Length::Fill);

        // Field stack — grouped into bordered section cards so all the
        // load-bearing facts are visible (and visually separated)
        // before anything is signed.
        let mut fields = column![].spacing(14).width(Length::Fill);
        // Operation warning FIRST (unboxed) — a delegatecall runs
        // arbitrary code under the Safe's identity (it can swap owners,
        // drain funds, or replace the implementation), so it must never
        // read like a plain transfer. Unknown bytes (>1) are flagged
        // too: the Safe contract would reject them, so a record
        // carrying one is service garbage at best.
        let operation = self.effective_operation();
        if operation != 0 {
            fields = fields.push(operation_warning(t, operation));
        }

        let mut tx_col = column![].spacing(8).width(Length::Fill);
        if !is_rejection {
            tx_col = tx_col.push(field(t, "To", colored_address(t, self.pending.to)));
        }
        tx_col = tx_col.push(simple_field(
            t,
            "Network",
            self.chain.display_name().to_string(),
        ));
        tx_col = tx_col.push(simple_field(t, "Nonce", self.pending.nonce.to_string()));
        // Native ETH movement doesn't emit a Transfer event, so the
        // simulation's transfer rows never carry it — this row does
        // (same as the EOA flow's "Sending" row).
        tx_col = tx_col.push(simple_field(
            t,
            "Value",
            format!("{} ETH", format_eth(self.pending.value)),
        ));
        fields = fields.push(section_card(t, "TRANSACTION", tx_col.into()));

        // What the batch actually does. Directly under TRANSACTION, because the
        // rows above it ("To: 0x9641…02e2", "Value: 0 ETH") describe the
        // MultiSend library and say nothing about the calls being authorised.
        if let Some(contents) = self.batch_contents() {
            fields = fields.push(match contents {
                Ok(calls) => {
                    let n = calls.len();
                    let mut col = column![
                        text(format!(
                            "{n} call{} executed atomically, in this order. If any one reverts, \
                             the whole batch reverts.",
                            if n == 1 { "" } else { "s" }
                        ))
                        .size(11)
                        .color(t.sub),
                    ]
                    .spacing(8)
                    .width(Length::Fill);
                    for (i, c) in calls.iter().enumerate() {
                        col = col.push(sub_call_row(t, i, n, c, self.safe));
                    }
                    section_card(t, "BATCH CONTENTS", col.into())
                }
                Err(e) => section_card(
                    t,
                    "BATCH CONTENTS",
                    column![
                        text("⚠ This is a MultiSend batch and its contents could not be decoded.")
                            .size(12)
                            .color(t.down)
                            .font(bold()),
                        Space::new().height(4),
                        text(format!(
                            "{e}. Do not confirm this transaction: the calls it would run cannot \
                             be shown, so there is nothing here to review."
                        ))
                        .size(11)
                        .color(t.text),
                    ]
                    .width(Length::Fill)
                    .into(),
                ),
            });
        }

        if let Some(detail) = &self.detail {
            let signed_fields = non_default_signed_fields(&detail.tx);
            if !signed_fields.is_empty() {
                let mut signed_col = column![].spacing(8).width(Length::Fill);
                signed_col = signed_col.push(
                    text("These non-default fields are part of the Safe hash.")
                        .size(11)
                        .color(t.sub),
                );
                for field in signed_fields {
                    signed_col = signed_col.push(wrapped_field(t, field.label, field.value));
                }
                fields = fields.push(section_card(
                    t,
                    "NON-DEFAULT SIGNED FIELDS",
                    signed_col.into(),
                ));
            }
        }

        // The full safeTxHash, chunked and coloured like addresses.
        // This is THE cross-device verification anchor: it's what every
        // owner signs, what the Transaction Service keys this record
        // by, and what a hardware wallet / the Safe web app shows a
        // co-signer. Compare chunk-by-chunk before confirming.
        let mut verify = column![
            text("EIP-712 Digest (SafeTx hash) · click to copy")
                .size(12)
                .color(t.text)
                .font(bold()),
            Space::new().height(6),
            colored_hash_copyable(t, self.pending.safe_tx_hash),
            Space::new().height(6),
            text("Verify this exact hash on your signing device and with co-signers.")
                .size(11)
                .color(t.sub),
        ]
        .width(Length::Fill);
        // ERC-8213 fingerprints: the safeTxHash above IS the EIP-712 Digest; add
        // its Domain / Message component hashes (from the authoritative loaded
        // `SafeTx`, so they reconstruct that exact digest) plus the inner call's
        // Calldata Digest. A signer can then verify any of the four labelled
        // values against their device or a co-signer.
        let mut prints: Vec<(&str, B256)> = Vec::new();
        if let Some(detail) = &self.detail {
            let e = crate::sign::digest::Eip712Digests::of(
                &detail.tx,
                &crate::safe::tx::safe_domain(self.safe, self.chain),
            );
            prints.push((crate::sign::digest::DOMAIN_HASH_LABEL, e.domain_hash));
            prints.push((crate::sign::digest::MESSAGE_HASH_LABEL, e.message_hash));
        }
        if !self.pending.data.is_empty() {
            prints.push((
                crate::sign::digest::CALLDATA_DIGEST_LABEL,
                crate::sign::digest::calldata_digest(&self.pending.data),
            ));
        }
        if !prints.is_empty() {
            verify = verify.push(Space::new().height(12));
            verify = verify.push(
                text("ERC-8213 fingerprints")
                    .size(11)
                    .color(t.sub)
                    .font(mono_bold()),
            );
            for (label, hash) in prints {
                verify = verify.push(Space::new().height(6));
                verify = verify.push(text(label).size(11).color(t.sub).font(mono()));
                verify = verify.push(Space::new().height(3));
                verify = verify.push(colored_hash_copyable(t, hash));
            }
        }
        fields = fields.push(section_card(t, "VERIFY BEFORE SIGNING", verify.into()));

        fields = fields.push(section_card(t, "SIMULATION", self.sim_block(t, portfolio)));

        // Owners checklist.
        let owners_title = format!(
            "OWNERS ({} of {})",
            self.detail
                .as_ref()
                .map(|d| d.owners_signed().len())
                .unwrap_or(0),
            self.detail
                .as_ref()
                .map(|d| d.confirmations_required)
                .unwrap_or(0),
        );
        fields = fields.push(section_card(t, &owners_title, self.owners_block(t)));

        // Result / error notices.
        if let Some(err) = &self.error {
            fields = fields.push(notice_line(t, err, true));
        }
        if let Some((msg, is_err)) = &self.notice {
            fields = fields.push(notice_line(t, msg, *is_err));
        }

        let actions = self.actions(t);

        let body = column![
            header_kao,
            Space::new().height(8),
            title,
            Space::new().height(10),
            hero,
            Space::new().height(8),
            badge,
            Space::new().height(22),
            fields,
            Space::new().height(20),
            actions,
        ]
        .width(Length::Fill)
        .align_x(Alignment::Center);

        let scrollable_body = scrollable(container(body).width(Length::Fill))
            .height(Length::Shrink)
            .style(move |_, s| kao_scrollable_style(t, s));

        modal_wrapper(
            t,
            560.0,
            progress,
            Message::Close,
            Message::BoxClickIgnored,
            scrollable_body.into(),
        )
    }

    /// Body of the SIMULATION card: the inner-call preflight (or the
    /// delegatecall skip note), plus the metered gas and — when the tx
    /// is next-up and this wallet can execute — the full
    /// `execTransaction` preflight under an "If executed now" caption.
    fn sim_block<'a>(&'a self, t: KaoTheme, portfolio: &'a [LiveToken]) -> Element<'a, Message> {
        let mut col = column![].spacing(6).width(Length::Fill);
        if self.effective_operation() != 0 {
            // A plain-CALL sim of a delegatecall would run the target's
            // code against the *target's* storage — a wrong answer, not
            // a preview. Better to decline visibly.
            col = col.push(
                text("Skipped — a delegatecall can't be previewed as a plain call.")
                    .size(11)
                    .color(t.sub),
            );
        } else if self.detail.is_none() {
            col = col.push(
                text("Waiting for transaction detail…")
                    .size(11)
                    .color(t.sub)
                    .font(mono()),
            );
        } else {
            match &self.inner_sim {
                None => {
                    col = col.push(
                        text("(；・∀・) simulating…")
                            .size(11)
                            .color(t.sub)
                            .font(mono()),
                    );
                }
                Some(sim) => {
                    col = col.push(sim_view::simulation_block(
                        t,
                        sim,
                        self.chain.into(),
                        portfolio,
                    ));
                    if sim.gas_used > 0 {
                        // Denominate in ETH at the sim's pinned base fee
                        // when one is known; the raw count alone isn't a
                        // human quantity. Falls back to just the count
                        // for blocks without a base fee.
                        let gas = sim_view::format_gas(sim.gas_used);
                        let value = match sim_view::format_gas_fee_eth(
                            sim.gas_used,
                            sim.base_fee_per_gas,
                        ) {
                            Some(fee) => format!("≈ {fee} ETH · {gas} gas"),
                            None => format!("{gas} gas"),
                        };
                        col = col.push(simple_field(t, "Est. fee", value));
                    }
                }
            }
        }
        if self.exec_sim_applicable() {
            col = col.push(Space::new().height(4));
            col = col.push(
                text("IF EXECUTED NOW")
                    .size(10)
                    .color(t.sub)
                    .font(mono_bold()),
            );
            match &self.exec_sim {
                None => {
                    col = col.push(
                        text("(；・∀・) simulating…")
                            .size(11)
                            .color(t.sub)
                            .font(mono()),
                    );
                }
                Some(sim) => {
                    col = col.push(sim_view::simulation_block(
                        t,
                        sim,
                        self.chain.into(),
                        portfolio,
                    ));
                }
            }
        }
        if self.sims_retryable() {
            // Compact, right-aligned: a re-run is a secondary affordance
            // and must not compete with the primary action buttons.
            col = col.push(
                container(small_secondary_button(t, "↻ Re-simulate").on_press(Message::RetrySims))
                    .width(Length::Fill)
                    .align_x(Alignment::End),
            );
        }
        col.into()
    }

    /// Whether the execute-time sim applies: the tx is next in line and
    /// this wallet holds a local gas payer — the same conditions the
    /// dashboard uses to spawn the exec-sim task.
    fn exec_sim_applicable(&self) -> bool {
        self.detail.is_some()
            && !self.exec_submitted
            && self.has_local_executor
            && matches!(
                self.effective_state(),
                SafeTxState::AwaitingExecution { is_next: true, .. }
            )
    }

    /// Show the Re-simulate button when at least one *landed* sim isn't
    /// a verified success — unverified, unavailable, or a revert against
    /// possibly-stale state are all worth a manual re-run. Hidden while
    /// results are still in flight and for the delegatecall skip.
    fn sims_retryable(&self) -> bool {
        let stale = |s: &Option<SimulationResult>| {
            s.as_ref().is_some_and(|s| !(s.is_success() && s.verified))
        };
        let inner_retryable =
            self.detail.is_some() && self.effective_operation() == 0 && stale(&self.inner_sim);
        let exec_retryable = self.exec_sim_applicable() && stale(&self.exec_sim);
        inner_retryable || exec_retryable
    }

    /// Owners signed/pending list. Shows a loading line until detail
    /// lands, then a ✓/○ row per owner with a "you" tag on owners this
    /// wallet controls. The "OWNERS (x of y)" caption lives on the
    /// section card wrapping this block.
    fn owners_block<'a>(&'a self, t: KaoTheme) -> Element<'a, Message> {
        let mut col = column![].width(Length::Fill);

        if self.loading {
            col = col.push(
                text("Loading signatures…")
                    .size(12)
                    .color(t.sub)
                    .font(mono()),
            );
            return col.into();
        }
        let signed = self
            .detail
            .as_ref()
            .map(|d| d.owners_signed())
            .unwrap_or_default();
        for owner in &self.owners {
            let has = signed.contains(owner);
            let (glyph, gcolor) = if has { ("✓", t.up) } else { ("○", t.sub) };
            let mine = self.signable.contains(owner);
            let name = if mine {
                format!("{} (you)", short_address(*owner))
            } else {
                short_address(*owner)
            };
            col = col.push(
                row![
                    text(glyph).size(13).color(gcolor).font(bold()),
                    Space::new().width(8),
                    text(name).size(12).color(t.text).font(mono()),
                ]
                .align_y(Alignment::Center)
                .padding(Padding::from([2, 0]))
                .width(Length::Fill),
            );
        }
        col.into()
    }

    /// `(confirm, execute, reject)` availability for the effective state
    /// and this wallet's capabilities. Pure — drives the button row and
    /// is unit-tested. Callers also gate on `detail` being loaded.
    fn action_availability(&self) -> (bool, bool, bool) {
        // Once our own execution is on the wire, every further action
        // is at best a no-op and at worst wasted gas — regardless of
        // the (lagging) service state.
        if self.exec_submitted {
            return (false, false, false);
        }
        if self.trust.signing_block_reason().is_some() {
            return (false, false, false);
        }
        let state = self.effective_state();
        let can_confirm = matches!(state, SafeTxState::AwaitingConfirmations { .. })
            && !self.unsigned_signable().is_empty();
        let can_execute = matches!(state, SafeTxState::AwaitingExecution { is_next: true, .. })
            && self.has_local_executor;
        let can_reject = matches!(
            state,
            SafeTxState::AwaitingConfirmations { .. } | SafeTxState::AwaitingExecution { .. }
        ) && !self.signable.is_empty();
        (can_confirm, can_execute, can_reject)
    }

    /// `(confirm, execute)` button labels, softened by the advisory
    /// sims: a predicted revert relabels to "… anyway ⚠" but never
    /// disables — a stale-state false negative must not strand a
    /// legitimate action. Execute prefers the exec-sim verdict (it runs
    /// the real `checkSignatures` path) and falls back to the inner sim
    /// when no exec sim ran. Pure — unit-tested as a matrix.
    fn action_labels(&self) -> (&'static str, &'static str) {
        let inner_revert = self.inner_sim.as_ref().is_some_and(|s| s.is_revert());
        let exec_revert = self
            .exec_sim
            .as_ref()
            .map(|s| s.is_revert())
            .unwrap_or(inner_revert);
        (
            if inner_revert {
                "Sign anyway ⚠"
            } else {
                "Confirm"
            },
            if exec_revert {
                "Execute anyway ⚠"
            } else {
                "Execute"
            },
        )
    }

    /// Action buttons, gated by the loaded state + this wallet's
    /// capabilities. Hidden entirely for terminal states (Replaced /
    /// Executed) and while detail is still loading.
    fn actions<'a>(&'a self, t: KaoTheme) -> Element<'a, Message> {
        if self.detail.is_none() {
            return Space::new().height(0).into();
        }
        let busy = self.busy;
        let state = self.effective_state();
        let mut buttons: Vec<Element<'a, Message>> = Vec::new();

        let (can_confirm, can_execute, can_reject) = self.action_availability();
        let (confirm_label, execute_label) = self.action_labels();

        if can_confirm {
            let mut b = primary_button(t, if busy { "Signing…" } else { confirm_label }, !busy);
            if !busy {
                b = b.on_press(Message::Confirm);
            }
            buttons.push(container(b).width(Length::FillPortion(1)).into());
        }
        if can_execute {
            let mut b = primary_button(t, if busy { "Executing…" } else { execute_label }, !busy);
            if !busy {
                b = b.on_press(Message::Execute);
            }
            buttons.push(container(b).width(Length::FillPortion(1)).into());
        }
        if can_reject {
            let mut b = secondary_button(t, if busy { "…" } else { "Reject" });
            if !busy {
                b = b.on_press(Message::Reject);
            }
            buttons.push(container(b).width(Length::FillPortion(1)).into());
        }

        if buttons.is_empty() {
            // Terminal or nothing actionable for this wallet — explain why
            // rather than showing dead buttons.
            let why = if self.exec_submitted && !matches!(state, SafeTxState::Executed { .. }) {
                "Execution submitted — waiting for the network to confirm."
            } else if let Some(reason) = self.trust.signing_block_reason() {
                reason
            } else {
                match state {
                    SafeTxState::Executed { .. } => "Already executed.",
                    SafeTxState::Replaced => "Replaced — this nonce was consumed.",
                    SafeTxState::AwaitingExecution { is_next: false, .. } => {
                        "Waiting on an earlier-nonce transaction first."
                    }
                    _ => "No actions available for your linked owners.",
                }
            };
            return text(why).size(12).color(t.sub).font(mono()).into();
        }

        let mut r = row![].width(Length::Fill);
        for (i, b) in buttons.into_iter().enumerate() {
            if i > 0 {
                r = r.push(Space::new().width(10));
            }
            r = r.push(b);
        }
        r.into()
    }
}

// ── small view helpers ───────────────────────────────────────────────────────

fn field<'a>(t: KaoTheme, label: &'a str, value: Element<'a, Message>) -> Element<'a, Message> {
    column![
        text(label.to_string()).size(13).color(t.sub).font(bold()),
        Space::new().height(4),
        value,
    ]
    .width(Length::Fill)
    .spacing(0)
    .into()
}

fn simple_field<'a>(t: KaoTheme, label: &'a str, value: String) -> Element<'a, Message> {
    row![
        text(label.to_string()).size(13).color(t.sub),
        Space::new().width(Length::Fill),
        text(value).size(13).color(t.text).font(mono_bold()),
    ]
    .align_y(Alignment::Center)
    .padding(Padding::from([2, 0]))
    .width(Length::Fill)
    .into()
}

fn wrapped_field<'a>(t: KaoTheme, label: &'a str, value: String) -> Element<'a, Message> {
    column![
        text(label.to_string()).size(13).color(t.sub),
        Space::new().height(2),
        text(value)
            .size(12)
            .color(t.text)
            .font(mono_bold())
            .wrapping(Wrapping::WordOrGlyph),
    ]
    .width(Length::Fill)
    .spacing(0)
    .into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SignedField {
    label: &'static str,
    value: String,
}

fn non_default_signed_fields(tx: &SafeTx) -> Vec<SignedField> {
    let mut fields = Vec::new();

    if !tx.data.is_empty() {
        fields.push(SignedField {
            label: "data",
            value: format_calldata(tx.data.as_ref()),
        });
    }
    if tx.operation != 0 {
        fields.push(SignedField {
            label: "operation",
            value: format_operation(tx.operation),
        });
    }
    if !tx.safeTxGas.is_zero() {
        fields.push(SignedField {
            label: "safeTxGas",
            value: tx.safeTxGas.to_string(),
        });
    }
    if !tx.baseGas.is_zero() {
        fields.push(SignedField {
            label: "baseGas",
            value: tx.baseGas.to_string(),
        });
    }
    if !tx.gasPrice.is_zero() {
        fields.push(SignedField {
            label: "gasPrice",
            value: tx.gasPrice.to_string(),
        });
    }
    if tx.gasToken != Address::ZERO {
        fields.push(SignedField {
            label: "gasToken",
            value: tx.gasToken.to_checksum(None),
        });
    }
    if tx.refundReceiver != Address::ZERO {
        fields.push(SignedField {
            label: "refundReceiver",
            value: tx.refundReceiver.to_checksum(None),
        });
    }

    fields
}

/// One packed sub-call of a MultiSend batch.
///
/// No ERC-7730 decode: this modal renders synchronously and the clear-sign
/// pipeline is async, so the honest offer is the mechanical facts — who it
/// calls, what it moves, which selector, how many bytes — rather than a
/// half-decode dressed up as a description. The one thing that *is* derivable
/// here without a network round trip is the case that matters most, and it is
/// the reason a co-signer needs this section at all: a call addressed to the
/// Safe itself runs as the Safe, and that is how the multisig's own owner set
/// and threshold get changed.
fn sub_call_row<'a>(
    t: KaoTheme,
    index: usize,
    total: usize,
    call: &crate::txbuilder::multisend::PackedCall,
    safe: Address,
) -> Element<'a, Message> {
    let mut col = column![
        text(format!("{} of {total}", index + 1))
            .size(11)
            .color(t.sub)
            .font(bold()),
    ]
    .spacing(4)
    .width(Length::Fill);

    if call.to == safe {
        let effect = match crate::safe::admin::authorized_effect(&call.data) {
            Some(e) => format!("Runs as this Safe and {e}."),
            None => "Addressed to this Safe, and this wallet does not recognise the call. Run \
                     this way it acts as the Safe on itself."
                .to_string(),
        };
        col = col.push(
            container(
                column![
                    text("⚠ TARGETS THIS SAFE")
                        .size(11)
                        .color(t.down)
                        .font(bold()),
                    Space::new().height(2),
                    text(effect).size(11).color(t.text),
                ]
                .width(Length::Fill),
            )
            .padding(8)
            .width(Length::Fill)
            .style(move |_: &iced::Theme| container::Style {
                background: Some(t.card_alt.into()),
                border: iced::Border {
                    color: t.down,
                    width: 1.0,
                    radius: 8.0.into(),
                },
                ..Default::default()
            }),
        );
    }

    col = col.push(field(t, "To", colored_address(t, call.to)));
    if !call.value.is_zero() {
        col = col.push(simple_field(
            t,
            "Value",
            format!("{} ETH", format_eth(call.value)),
        ));
    }
    // Captured before the styling closure so it doesn't borrow `call`.
    let targets_safe = call.to == safe;
    // A nested delegatecall inside the blob is refused outright on the signing
    // side; here it is only ever displayed, so name it rather than drop it.
    if call.operation != 0 {
        col = col.push(simple_field(
            t,
            "Operation",
            format!("{} — NESTED DELEGATECALL", call.operation),
        ));
    }
    if call.data.is_empty() {
        col = col.push(simple_field(t, "Calldata", "none (plain transfer)".into()));
    } else {
        let selector = if call.data.len() >= 4 {
            format!("0x{}", alloy::hex::encode(&call.data[..4]))
        } else {
            "malformed (under 4 bytes)".to_string()
        };
        col = col.push(simple_field(
            t,
            "Selector",
            format!("{selector} · {} bytes", call.data.len()),
        ));
        col = col.push(wrapped_field(t, "data", format_calldata(&call.data)));
    }

    container(col)
        .padding(10)
        .width(Length::Fill)
        .style(move |_: &iced::Theme| container::Style {
            background: Some(t.card.into()),
            border: iced::Border {
                color: if targets_safe { t.down } else { t.border },
                width: 1.0,
                radius: 10.0.into(),
            },
            ..Default::default()
        })
        .into()
}

fn format_operation(operation: u8) -> String {
    match operation {
        1 => "1 (delegatecall)".to_string(),
        other => format!("{other} (unknown)"),
    }
}

fn format_calldata(bytes: &[u8]) -> String {
    let hex = alloy::hex::encode(bytes);
    let rendered = if hex.len() <= 96 {
        hex
    } else {
        format!("{}…{}", &hex[..64], &hex[hex.len() - 16..])
    };
    format!("0x{rendered} ({} bytes)", bytes.len())
}

/// Loud red banner for non-call operations. Delegatecall gets the full
/// explanation; any other non-zero byte is flagged as malformed.
fn operation_warning<'a>(t: KaoTheme, operation: u8) -> Element<'a, Message> {
    let (title, msg) = if operation == 1 {
        (
            "⚠ DELEGATECALL",
            "This transaction runs arbitrary code AS the Safe. It can change owners, \
             drain all funds, or replace the Safe's implementation. Only sign if you \
             built it yourself or fully trust the proposer.",
        )
    } else {
        (
            "⚠ Unknown operation",
            "This record carries an operation byte the Safe contract doesn't define. \
             It cannot execute as-is — treat it as malformed and reject it.",
        )
    };
    container(
        column![
            text(title).size(12).color(t.down).font(bold()),
            Space::new().height(2),
            text(msg).size(11).color(t.text),
        ]
        .spacing(0),
    )
    .padding(Padding::from([10, 12]))
    .width(Length::Fill)
    .style(move |_| container::Style {
        background: Some(Background::Color(with_alpha(t.down, 0.10))),
        border: Border {
            color: with_alpha(t.down, 0.45),
            width: 1.0,
            radius: Radius::from(10),
        },
        ..container::Style::default()
    })
    .into()
}

fn notice_line<'a>(t: KaoTheme, msg: &str, is_err: bool) -> Element<'a, Message> {
    let color = if is_err { t.down } else { t.up };
    container(text(msg.to_string()).size(12).color(color).font(mono()))
        .width(Length::Fill)
        .into()
}

/// Filled status chip — same color language as the queue rows in `home`.
fn state_badge<'a>(t: KaoTheme, state: SafeTxState) -> Element<'a, Message> {
    let (label, accent): (String, Color) = match state {
        SafeTxState::AwaitingConfirmations { have, required } => {
            (format!("{have}/{required} signatures"), t.a1)
        }
        SafeTxState::AwaitingExecution { is_next: true, .. } => {
            ("Ready to execute".to_string(), t.up)
        }
        SafeTxState::AwaitingExecution { is_next: false, .. } => ("Queued".to_string(), t.sub),
        SafeTxState::Replaced => ("Replaced".to_string(), t.down),
        SafeTxState::Executed { success: true } => ("Executed".to_string(), t.up),
        SafeTxState::Executed { success: false } => ("Failed".to_string(), t.down),
    };
    chip(label, accent)
}

/// The bare chip behind [`state_badge`] — also used for the optimistic
/// "Execution submitted" override, which isn't a service state.
fn chip<'a>(label: String, accent: Color) -> Element<'a, Message> {
    container(text(label).size(11).color(accent).font(bold()))
        .padding(Padding::from([3, 8]))
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(accent, 0.12))),
            border: Border {
                color: with_alpha(accent, 0.3),
                width: 1.0,
                radius: Radius::from(7),
            },
            ..container::Style::default()
        })
        .into()
}

fn format_eth(wei: alloy::primitives::U256) -> String {
    if wei.is_zero() {
        return "0".to_string();
    }
    let s = alloy::primitives::utils::format_ether(wei);
    let f = s.parse::<f64>().unwrap_or(0.0);
    if f >= 1.0 {
        format!("{f:.4}")
    } else {
        let s = format!("{f:.6}");
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safe::SafeTx;
    use crate::safe::service::ServiceConfirmation;
    use alloy::primitives::{Bytes, U256};

    fn owner(b: u8) -> Address {
        Address::repeat_byte(b)
    }

    fn zero_safe_tx() -> SafeTx {
        SafeTx {
            to: Address::ZERO,
            value: U256::ZERO,
            data: Bytes::new(),
            operation: 0,
            safeTxGas: U256::ZERO,
            baseGas: U256::ZERO,
            gasPrice: U256::ZERO,
            gasToken: Address::ZERO,
            refundReceiver: Address::ZERO,
            nonce: U256::from(5u64),
        }
    }

    #[test]
    fn non_default_signed_fields_empty_for_plain_safe_tx() {
        assert!(non_default_signed_fields(&zero_safe_tx()).is_empty());
    }

    #[test]
    fn non_default_signed_fields_detects_relay_and_refund_values() {
        let mut tx = zero_safe_tx();
        tx.safeTxGas = U256::from(100u64);
        tx.baseGas = U256::from(50u64);
        tx.gasPrice = U256::from(7u64);
        tx.gasToken = owner(0x22);
        tx.refundReceiver = owner(0x33);

        let fields = non_default_signed_fields(&tx);
        let labels: Vec<_> = fields.iter().map(|field| field.label).collect();
        assert_eq!(
            labels,
            vec![
                "safeTxGas",
                "baseGas",
                "gasPrice",
                "gasToken",
                "refundReceiver"
            ]
        );
        assert_eq!(fields[0].value, "100");
        assert_eq!(fields[1].value, "50");
        assert_eq!(fields[2].value, "7");
        assert_eq!(fields[3].value, owner(0x22).to_checksum(None));
        assert_eq!(fields[4].value, owner(0x33).to_checksum(None));
    }

    #[test]
    fn non_default_signed_fields_include_calldata_and_operation() {
        let mut tx = zero_safe_tx();
        tx.data = Bytes::from(vec![0xab, 0xcd]);
        tx.operation = 1;

        let fields = non_default_signed_fields(&tx);
        assert_eq!(
            fields,
            vec![
                SignedField {
                    label: "data",
                    value: "0xabcd (2 bytes)".to_string()
                },
                SignedField {
                    label: "operation",
                    value: "1 (delegatecall)".to_string()
                }
            ]
        );
    }

    fn pending(state: SafeTxState) -> PendingSafeTx {
        PendingSafeTx {
            safe_tx_hash: B256::ZERO,
            to: owner(0xaa),
            value: U256::ZERO,
            data: Bytes::new(),
            operation: 0,
            nonce: 5,
            state,
            submission_ts: 0,
        }
    }

    fn detail(state: SafeTxState, signed: Vec<Address>) -> SafeTxDetail {
        SafeTxDetail {
            safe_tx_hash: B256::ZERO,
            tx: zero_safe_tx(),
            state,
            confirmations: signed
                .into_iter()
                .map(|o| ServiceConfirmation {
                    owner: o,
                    signature: Bytes::new(),
                })
                .collect(),
            confirmations_required: 2,
        }
    }

    /// Pane with two Safe owners; `signable` are the ones this wallet
    /// controls. `has_exec` toggles the local gas payer.
    fn pane_with_trust(
        signable: Vec<Address>,
        has_exec: bool,
        pending_state: SafeTxState,
        trust: SafeTrust,
    ) -> SafeTxDetailPane {
        SafeTxDetailPane::new(
            Address::ZERO,
            Chain::Mainnet,
            "1.4.1".to_string(),
            trust,
            crate::safe::service::DEFAULT_TX_SERVICE_BASE.to_string(),
            pending(pending_state),
            vec![owner(0x11), owner(0x22)],
            signable,
            has_exec,
        )
    }

    fn pane(
        signable: Vec<Address>,
        has_exec: bool,
        pending_state: SafeTxState,
    ) -> SafeTxDetailPane {
        pane_with_trust(signable, has_exec, pending_state, SafeTrust::Canonical)
    }

    /// A MultiSend blob wrapping `calls`, as the Builder's propose path files
    /// it — built with the real encoder so a change to either side shows up
    /// here rather than in front of a co-signer.
    fn multisend_blob(calls: &[(Address, u64, Vec<u8>)]) -> Bytes {
        use crate::txbuilder::{QueuedCall, multisend};
        let queued: Vec<QueuedCall> = calls
            .iter()
            .enumerate()
            .map(|(i, (to, value, data))| QueuedCall {
                id: i as u64,
                to: *to,
                value: alloy::primitives::U256::from(*value),
                data: Bytes::from(data.clone()),
                title: "t".into(),
                detail: "d".into(),
                signature: None,
                decoded_args: Vec::new(),
            })
            .collect();
        multisend::encode_multisend_calldata(&multisend::encode_packed(&queued))
    }

    fn pane_with_batch(safe: Address, to: Address, data: Bytes, operation: u8) -> SafeTxDetailPane {
        let state = SafeTxState::AwaitingConfirmations {
            have: 0,
            required: 2,
        };
        let mut p = pane(vec![], false, state);
        p.safe = safe;
        let mut d = detail(state, vec![]);
        d.tx.to = to;
        d.tx.data = data;
        d.tx.operation = operation;
        p.set_detail(Ok(d));
        p
    }

    #[test]
    fn a_multisend_proposal_unpacks_into_its_sub_calls() {
        // What a co-signer had instead: to = 0x9641…02e2, operation = 1, and a
        // few hundred bytes of 0x8d80ff0a…
        use crate::txbuilder::multisend::MULTISEND_CALL_ONLY_1_4_1;
        let safe = owner(0x5A);
        let blob = multisend_blob(&[
            (owner(0xC1), 0, vec![0x01, 0x02, 0x03, 0x04]),
            (owner(0xC2), 5, Vec::new()),
        ]);
        let p = pane_with_batch(safe, MULTISEND_CALL_ONLY_1_4_1, blob, 1);
        let calls = p
            .batch_contents()
            .expect("recognised as a batch")
            .expect("and decodes");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].to, owner(0xC1));
        assert_eq!(calls[0].data.as_ref(), &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(calls[1].to, owner(0xC2));
        assert_eq!(calls[1].value, alloy::primitives::U256::from(5u64));
    }

    #[test]
    fn an_ordinary_safe_transaction_has_no_batch_section() {
        // The section must not appear for a plain transfer, or it becomes
        // furniture the reader stops seeing.
        let p = pane_with_batch(owner(0x5A), owner(0xC1), Bytes::from(vec![0x01]), 0);
        assert!(p.batch_contents().is_none());
    }

    #[test]
    fn a_delegatecall_to_something_other_than_multisend_is_not_unpacked() {
        // Claiming to unpack a delegatecall to an unknown library would be
        // asserting a shape this wallet has no reason to believe.
        let p = pane_with_batch(owner(0x5A), owner(0xDD), Bytes::from(vec![0x01]), 1);
        assert!(p.batch_contents().is_none());
    }

    #[test]
    fn a_multisend_blob_that_will_not_parse_is_reported_not_hidden() {
        // The failure mode that matters: falling back to the hex dump would
        // present a batch this wallet cannot account for as though there were
        // nothing to account for.
        use crate::txbuilder::multisend::MULTISEND_CALL_ONLY_1_3_0;
        let junk = Bytes::from(vec![0x8d, 0x80, 0xff, 0x0a, 0xde, 0xad]);
        let p = pane_with_batch(owner(0x5A), MULTISEND_CALL_ONLY_1_3_0, junk, 1);
        assert!(
            p.batch_contents().expect("recognised").is_err(),
            "a blob that won't parse must surface as an error",
        );
    }

    #[test]
    fn a_sub_call_addressed_to_the_safe_is_recognised_as_governance() {
        // Blockers 2 and 3 meet here: the co-signer is the person who most
        // needs to be told that call 2 hands the multisig to someone else.
        use crate::txbuilder::multisend::MULTISEND_CALL_ONLY_1_4_1;
        let safe = owner(0x5A);
        let mut add_owner =
            alloy::primitives::keccak256(b"addOwnerWithThreshold(address,uint256)")[..4].to_vec();
        add_owner.extend_from_slice(B256::left_padding_from(owner(0xBB).as_slice()).as_slice());
        add_owner.extend_from_slice(&alloy::primitives::U256::from(1u64).to_be_bytes::<32>());
        let blob = multisend_blob(&[
            (owner(0xC1), 0, vec![0x01, 0x02, 0x03, 0x04]),
            (safe, 0, add_owner),
        ]);
        let p = pane_with_batch(safe, MULTISEND_CALL_ONLY_1_4_1, blob, 1);
        let calls = p.batch_contents().unwrap().unwrap();
        assert_ne!(calls[0].to, safe);
        assert_eq!(calls[1].to, safe, "the governance call targets the Safe");
        assert!(
            crate::safe::admin::authorized_effect(&calls[1].data)
                .is_some_and(|e| e.contains("adds an owner")),
            "and its effect is nameable without a network round trip",
        );
    }

    #[test]
    fn unsigned_signable_excludes_already_signed() {
        let mut p = pane(
            vec![owner(0x11), owner(0x22)],
            true,
            SafeTxState::AwaitingConfirmations {
                have: 1,
                required: 2,
            },
        );
        p.set_detail(Ok(detail(
            SafeTxState::AwaitingConfirmations {
                have: 1,
                required: 2,
            },
            vec![owner(0x11)],
        )));
        assert_eq!(p.unsigned_signable(), vec![owner(0x22)]);
    }

    #[test]
    fn unsigned_signable_empty_before_detail_loads() {
        let p = pane(
            vec![owner(0x11)],
            true,
            SafeTxState::AwaitingConfirmations {
                have: 0,
                required: 2,
            },
        );
        assert!(p.unsigned_signable().is_empty());
    }

    #[test]
    fn effective_state_prefers_loaded_detail() {
        // List-time snapshot said "awaiting confirmations"; the reload
        // says it's now executable. The fresher detail must win.
        let mut p = pane(
            vec![owner(0x11)],
            true,
            SafeTxState::AwaitingConfirmations {
                have: 1,
                required: 2,
            },
        );
        p.set_detail(Ok(detail(
            SafeTxState::AwaitingExecution {
                required: 2,
                is_next: true,
            },
            vec![owner(0x11), owner(0x22)],
        )));
        assert_eq!(
            p.effective_state(),
            SafeTxState::AwaitingExecution {
                required: 2,
                is_next: true
            }
        );
    }

    #[test]
    fn actions_awaiting_confirmations_allow_confirm_and_reject() {
        let mut p = pane(
            vec![owner(0x22)],
            true,
            SafeTxState::AwaitingConfirmations {
                have: 1,
                required: 2,
            },
        );
        p.set_detail(Ok(detail(
            SafeTxState::AwaitingConfirmations {
                have: 1,
                required: 2,
            },
            vec![owner(0x11)],
        )));
        // (confirm, execute, reject): signable owner 0x22 hasn't signed →
        // confirm; state isn't AwaitingExecution → no execute; reject ok.
        assert_eq!(p.action_availability(), (true, false, true));
    }

    #[test]
    fn actions_ready_to_execute() {
        let mut p = pane(
            vec![owner(0x11)],
            true,
            SafeTxState::AwaitingExecution {
                required: 2,
                is_next: true,
            },
        );
        p.set_detail(Ok(detail(
            SafeTxState::AwaitingExecution {
                required: 2,
                is_next: true,
            },
            vec![owner(0x11), owner(0x22)],
        )));
        // threshold met & next → execute + reject; nothing to confirm.
        assert_eq!(p.action_availability(), (false, true, true));
    }

    #[test]
    fn actions_execute_needs_local_executor() {
        let mut p = pane(
            vec![owner(0x11)],
            false, // no local gas payer
            SafeTxState::AwaitingExecution {
                required: 2,
                is_next: true,
            },
        );
        p.set_detail(Ok(detail(
            SafeTxState::AwaitingExecution {
                required: 2,
                is_next: true,
            },
            vec![owner(0x11), owner(0x22)],
        )));
        assert!(!p.action_availability().1);
    }

    #[test]
    fn actions_blocked_for_unrecognized_safe_impl() {
        let mut p = pane_with_trust(
            vec![owner(0x22)],
            true,
            SafeTxState::AwaitingConfirmations {
                have: 1,
                required: 2,
            },
            SafeTrust::UnrecognizedImpl,
        );
        p.set_detail(Ok(detail(
            SafeTxState::AwaitingConfirmations {
                have: 1,
                required: 2,
            },
            vec![owner(0x11)],
        )));

        assert_eq!(p.action_availability(), (false, false, false));
        assert!(p.update(Message::Confirm).1.is_none());
        assert!(p.update(Message::Reject).1.is_none());

        let mut ready = pane_with_trust(
            vec![owner(0x11)],
            true,
            SafeTxState::AwaitingExecution {
                required: 2,
                is_next: true,
            },
            SafeTrust::UnrecognizedImpl,
        );
        ready.set_detail(Ok(detail(
            SafeTxState::AwaitingExecution {
                required: 2,
                is_next: true,
            },
            vec![owner(0x11), owner(0x22)],
        )));

        assert_eq!(ready.action_availability(), (false, false, false));
        assert!(ready.update(Message::Execute).1.is_none());
    }

    #[test]
    fn actions_blocked_when_not_next() {
        let mut p = pane(
            vec![owner(0x11)],
            true,
            SafeTxState::AwaitingExecution {
                required: 2,
                is_next: false,
            },
        );
        p.set_detail(Ok(detail(
            SafeTxState::AwaitingExecution {
                required: 2,
                is_next: false,
            },
            vec![owner(0x11), owner(0x22)],
        )));
        // Can't execute (earlier nonce blocks it) but can still reject.
        assert_eq!(p.action_availability(), (false, false, true));
    }

    #[test]
    fn actions_none_for_terminal_states() {
        for state in [
            SafeTxState::Executed { success: true },
            SafeTxState::Executed { success: false },
            SafeTxState::Replaced,
        ] {
            let mut p = pane(vec![owner(0x11)], true, state);
            p.set_detail(Ok(detail(state, vec![owner(0x11)])));
            assert_eq!(p.action_availability(), (false, false, false));
        }
    }

    #[test]
    fn actions_none_without_signable_owner() {
        // Watch-only on this Safe: no signable owners → no confirm/reject
        // even though the state would otherwise allow them.
        let mut p = pane(
            vec![],
            false,
            SafeTxState::AwaitingConfirmations {
                have: 1,
                required: 2,
            },
        );
        p.set_detail(Ok(detail(
            SafeTxState::AwaitingConfirmations {
                have: 1,
                required: 2,
            },
            vec![owner(0x11)],
        )));
        assert_eq!(p.action_availability(), (false, false, false));
    }

    #[test]
    fn effective_operation_prefers_loaded_detail() {
        // List-time snapshot said plain call; the loaded detail
        // reconstructs a delegatecall (it's what execute would encode)
        // — the warning must key off the authoritative one.
        let state = SafeTxState::AwaitingConfirmations {
            have: 0,
            required: 2,
        };
        let mut p = pane(vec![], false, state);
        assert_eq!(p.effective_operation(), 0);
        let mut d = detail(state, vec![]);
        d.tx.operation = 1;
        p.set_detail(Ok(d));
        assert_eq!(p.effective_operation(), 1);
    }

    fn ok_sim() -> SimulationResult {
        SimulationResult {
            outcome: crate::wallet::sim::SimOutcome::Success {
                output: Bytes::new(),
            },
            gas_used: 21000,
            transfers: Vec::new(),
            verified: true,
            base_fee_per_gas: 0,
        }
    }

    fn revert_sim() -> SimulationResult {
        SimulationResult {
            outcome: crate::wallet::sim::SimOutcome::Revert {
                reason: "GS026".to_string(),
                raw: Bytes::new(),
            },
            gas_used: 0,
            transfers: Vec::new(),
            verified: true,
            base_fee_per_gas: 0,
        }
    }

    #[test]
    fn set_detail_resets_sims() {
        // A (re)load invalidates both sims — they described the
        // previous detail; the dashboard re-spawns the tasks.
        let state = SafeTxState::AwaitingConfirmations {
            have: 1,
            required: 2,
        };
        let mut p = pane(vec![owner(0x11)], true, state);
        p.set_detail(Ok(detail(state, vec![owner(0x11)])));
        p.set_inner_sim(ok_sim());
        p.set_exec_sim(revert_sim());
        assert!(p.inner_sim.is_some());
        assert!(p.exec_sim.is_some());
        p.set_detail(Ok(detail(state, vec![owner(0x11)])));
        assert!(p.inner_sim.is_none());
        assert!(p.exec_sim.is_none());
    }

    #[test]
    fn action_labels_soften_on_revert() {
        let state = SafeTxState::AwaitingConfirmations {
            have: 1,
            required: 2,
        };
        let mut p = pane(vec![owner(0x11)], true, state);

        // No sims yet → default labels.
        assert_eq!(p.action_labels(), ("Confirm", "Execute"));

        // Inner success → still default.
        p.set_inner_sim(ok_sim());
        assert_eq!(p.action_labels(), ("Confirm", "Execute"));

        // Inner revert, no exec sim → both soften (Execute falls back
        // to the inner verdict).
        p.set_inner_sim(revert_sim());
        assert_eq!(p.action_labels(), ("Sign anyway ⚠", "Execute anyway ⚠"));

        // Exec success overrides the inner fallback for Execute — it
        // ran the real checkSignatures path.
        p.set_exec_sim(ok_sim());
        assert_eq!(p.action_labels(), ("Sign anyway ⚠", "Execute"));

        // Exec revert + inner success → only Execute softens.
        p.set_inner_sim(ok_sim());
        p.set_exec_sim(revert_sim());
        assert_eq!(p.action_labels(), ("Confirm", "Execute anyway ⚠"));
    }

    fn unverified_ok_sim() -> SimulationResult {
        SimulationResult {
            verified: false,
            ..ok_sim()
        }
    }

    #[test]
    fn set_sims_request_auto_retry_once_for_unverified_success() {
        let state = SafeTxState::AwaitingConfirmations {
            have: 1,
            required: 2,
        };
        let mut p = pane(vec![owner(0x11)], true, state);
        p.set_detail(Ok(detail(state, vec![owner(0x11)])));

        // First unverified success → retry; second → no loop.
        assert!(p.set_inner_sim(unverified_ok_sim()));
        assert!(!p.set_inner_sim(unverified_ok_sim()));
        // Exec sim has its own budget.
        assert!(p.set_exec_sim(unverified_ok_sim()));
        assert!(!p.set_exec_sim(unverified_ok_sim()));

        // Verified success and reverts never auto-retry.
        let mut p2 = pane(vec![owner(0x11)], true, state);
        p2.set_detail(Ok(detail(state, vec![owner(0x11)])));
        assert!(!p2.set_inner_sim(ok_sim()));
        assert!(!p2.set_exec_sim(revert_sim()));

        // A reload re-opens the budget.
        p.set_detail(Ok(detail(state, vec![owner(0x11)])));
        assert!(p.set_inner_sim(unverified_ok_sim()));
    }

    #[test]
    fn retry_sims_message_clears_state_and_emits_outcome() {
        let state = SafeTxState::AwaitingConfirmations {
            have: 1,
            required: 2,
        };
        let mut p = pane(vec![owner(0x11)], true, state);
        // Before detail loads there's nothing to re-run.
        let (_, outcome) = p.update(Message::RetrySims);
        assert!(outcome.is_none());

        p.set_detail(Ok(detail(state, vec![owner(0x11)])));
        let _ = p.set_inner_sim(unverified_ok_sim());
        let _ = p.set_exec_sim(revert_sim());
        let (_, outcome) = p.update(Message::RetrySims);
        assert!(matches!(outcome, Some(Outcome::RetrySims)));
        // Back to "simulating…" with a fresh auto-retry budget.
        assert!(p.inner_sim.is_none());
        assert!(p.exec_sim.is_none());
        assert!(p.set_inner_sim(unverified_ok_sim()));
    }

    /// A successful Execute flips to the optimistic submitted state:
    /// the Transaction Service won't reflect the execution until it
    /// indexes the mined tx, so the stale "ready to execute" reload
    /// must not resurrect the action buttons.
    #[test]
    fn execute_success_hides_actions_despite_stale_reload() {
        let ready = SafeTxState::AwaitingExecution {
            required: 2,
            is_next: true,
        };
        let mut p = pane(vec![owner(0x11)], true, ready);
        p.set_detail(Ok(detail(ready, vec![owner(0x11), owner(0x22)])));
        assert_eq!(p.action_availability(), (false, true, true));

        let (_, outcome) = p.update(Message::Execute);
        assert!(matches!(outcome, Some(Outcome::Execute)));
        p.mark_busy();
        p.set_action_result(Ok("Executed · 0xabc".to_string()));
        assert!(p.exec_submitted());
        assert_eq!(p.action_availability(), (false, false, false));
        // The post-action reload returns the same stale state — the
        // optimistic flag must survive it.
        p.set_detail(Ok(detail(ready, vec![owner(0x11), owner(0x22)])));
        assert!(p.exec_submitted());
        assert_eq!(p.action_availability(), (false, false, false));
        // No exec-sim block either: simulating an already-submitted
        // execution is GS-revert noise.
        assert!(!p.exec_sim_applicable());
    }

    #[test]
    fn failed_execute_keeps_actions_available() {
        let ready = SafeTxState::AwaitingExecution {
            required: 2,
            is_next: true,
        };
        let mut p = pane(vec![owner(0x11)], true, ready);
        p.set_detail(Ok(detail(ready, vec![owner(0x11), owner(0x22)])));
        let _ = p.update(Message::Execute);
        p.mark_busy();
        p.set_action_result(Err("rpc lost".to_string()));
        assert!(!p.exec_submitted());
        // Retrying the execution must stay possible.
        assert_eq!(p.action_availability(), (false, true, true));
    }

    #[test]
    fn confirm_success_does_not_enter_submitted_state() {
        let state = SafeTxState::AwaitingConfirmations {
            have: 1,
            required: 2,
        };
        let mut p = pane(vec![owner(0x22)], true, state);
        p.set_detail(Ok(detail(state, vec![owner(0x11)])));
        let _ = p.update(Message::Confirm);
        p.mark_busy();
        p.set_action_result(Ok("Confirmed".to_string()));
        assert!(!p.exec_submitted());
        // Still awaiting more signatures — confirm/reject stay live.
        assert_eq!(p.action_availability(), (true, false, true));
    }

    #[test]
    fn set_action_result_clears_busy_and_records_notice() {
        let mut p = pane(
            vec![owner(0x11)],
            true,
            SafeTxState::AwaitingConfirmations {
                have: 0,
                required: 2,
            },
        );
        p.mark_busy();
        assert!(p.busy());
        p.set_action_result(Err("nope".to_string()));
        assert!(!p.busy());
        assert_eq!(p.notice, Some(("nope".to_string(), true)));
    }

    #[test]
    fn set_detail_error_stops_loading_without_detail() {
        let mut p = pane(
            vec![owner(0x11)],
            true,
            SafeTxState::AwaitingConfirmations {
                have: 0,
                required: 2,
            },
        );
        assert!(p.loading);
        p.set_detail(Err("offline".to_string()));
        assert!(!p.loading);
        assert!(p.loaded_detail().is_none());
        assert_eq!(p.error.as_deref(), Some("offline"));
    }
}
