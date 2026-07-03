//! Unified **sign-review gate** — the clear-signing confirmation surface every
//! app signature passes through before the key is ever touched.
//!
//! The Send flow already clear-signs its transactions (decode → `function_panel`).
//! The two in-app surfaces — CoW Swap and the Names registrar — used to sign with
//! no decoded review at all (CoW signed its EIP-712 order the moment the user hit
//! "Place order"; Names blind-signed every registrar call behind a thin "verify
//! the contract" card). This overlay closes that gap: the coordinator *prepares*
//! the exact bytes the user is about to authorize, decodes every raw transaction
//! through the same `decode_transaction` pipeline Send uses, and renders them here
//! with an explicit **Confirm & sign** / **Cancel** gate. Only on Confirm does the
//! coordinator run the (unchanged) signing task.
//!
//! It renders as the top-most `stack!` layer over whatever app is active, so it
//! works identically for the Swap modal, the Apps-pane composer, and the Names
//! pane without any of them losing their own state on Cancel.
//!
//! Two kinds of thing get reviewed:
//! - **Raw transactions** ([`ReviewLeg`]) — ERC-20 approvals, the EthFlow
//!   `createOrder` call, and every registrar call (commit/register/renew/setAddr).
//!   These carry a full [`DecodeResult`] rendered by [`function_panel`].
//! - **The CoW EIP-712 order** ([`OrderReview`]) — *not* calldata, so it can't go
//!   through `function_panel`; it gets a purpose-built panel spelling out every
//!   signed field (sell/buy/receiver/min-received/expiry/kind/fee/settlement).

use std::time::Instant;

use alloy::primitives::{Address, B256, Bytes, U256};
use iced::keyboard;
use iced::widget::text::Wrapping;
use iced::widget::{Space, column, container, row, scrollable, text};
use iced::{Alignment, Element, Length, Padding};

use crate::chain::Chain;
use crate::cow::api::QuoteResponse;
use crate::cow::composer::SwapDraft;
use crate::decode::clear_sign::DecodeResult;
use crate::names::registrar::{Namespace, RegisterPlan};
use crate::sign::typed::{IntoTypedModel, TypedDataModel, TypedRow, TypedValue};
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    bold, bullet_wave, colored_address, kao_scrollable_style, modal_wrapper, mono, mono_bold,
    primary_button, secondary_button,
};
use crate::wallet::tx::{SendPlan, TxQuote};

use super::CowHost;

const MODAL_WIDTH: f32 = 520.0;
const FORM_MAX_HEIGHT: f32 = 520.0;

#[derive(Debug, Clone)]
pub enum Message {
    Confirm,
    Cancel,
    BoxClickIgnored,
    Key(keyboard::Event),
    /// No-op published by a copyable address click so the dashboard's "Copied!"
    /// toast animation starts (a click changes no state otherwise). Ignored.
    AddressCopied,
    /// Expand/collapse the "for the paranoid" decoded-calldata block on a Send
    /// review step (the only interactive control inside a reviewed step).
    ToggleCalldata,
}

/// A single raw transaction the user will sign, decoded for review through the
/// same pipeline the Send screen uses.
#[derive(Debug, Clone)]
pub struct ReviewLeg {
    /// Human label for this leg, e.g. "Approve USDC for CoW" or "Register cow.eth".
    pub title: String,
    pub to: Address,
    pub value: U256,
    pub chain: Chain,
    pub decoded: Box<DecodeResult>,
}

/// The CoW GPv2 order the user signs as EIP-712 typed data. Every field here is a
/// field of the signed message (or derived from it) so the review matches the
/// signature byte-for-byte.
#[derive(Debug, Clone)]
pub struct OrderReview {
    pub chain: Chain,
    pub sell_amount: String,
    pub sell_symbol: String,
    pub buy_amount: String,
    pub buy_symbol: String,
    pub min_received: String,
    pub receiver: Address,
    /// Unix expiry (`validTo`).
    pub valid_to: u32,
    pub slippage_bps: u16,
    pub settlement: Address,
    /// Native-ETH (EthFlow) order — settles on-chain and costs gas, vs. a gasless
    /// off-chain ERC-20 order.
    pub native: bool,
}

impl IntoTypedModel for OrderReview {
    /// The exact rows the CoW order panel has always shown — now expressed as a
    /// generic [`TypedDataModel`] so `typed_panel` can render it (and any future
    /// EIP-712 message) uniformly. All unit/precision/relative-time formatting is
    /// done here, so the model stays render-only.
    fn to_typed_model(&self) -> TypedDataModel {
        TypedDataModel {
            type_name: "CoW order — EIP-712 signature".to_string(),
            headline: Some(format!(
                "Sell {} {} for at least {} {}",
                self.sell_amount, self.sell_symbol, self.min_received, self.buy_symbol
            )),
            rows: vec![
                TypedRow::text(
                    "You sell",
                    format!("{} {}", self.sell_amount, self.sell_symbol),
                ),
                TypedRow::text(
                    "Receive (est.)",
                    format!("{} {}", self.buy_amount, self.buy_symbol),
                ),
                TypedRow::text(
                    "Min received",
                    format!(
                        "{} {} · {} slippage",
                        self.min_received,
                        self.buy_symbol,
                        slippage_label(self.slippage_bps)
                    ),
                ),
                TypedRow::addr("Receiver", self.receiver),
                TypedRow::text("Order type", "Sell · fill-or-kill"),
                TypedRow::text("Solver fee", "taken from price (signed fee 0)"),
                TypedRow::text("Expires", format_expiry(self.valid_to)),
                TypedRow::addr("Settlement", self.settlement),
                TypedRow::text("Network", self.chain.display_name()),
                TypedRow::text(
                    "Settles",
                    if self.native {
                        "on-chain (native ETH) · costs gas"
                    } else {
                        "off-chain via solvers · gasless"
                    },
                ),
            ],
        }
    }
}

/// A Safe `execTransaction` the owners sign as EIP-712 (`SafeTx`). Wraps the
/// decoded **inner** call (EthFlow `createOrder` for a native swap, or the ERC-20
/// vault-relayer approve) plus the exact 32-byte `safeTxHash` each owner signs,
/// pinned at the nonce read when the review was prepared. Carries only public tx
/// fields + hashes — no key material.
#[derive(Debug, Clone)]
pub struct SafeExecReview {
    pub safe: Address,
    pub nonce: u64,
    pub threshold: u8,
    pub owner_count: u8,
    /// The exact 32 bytes each owner signs — identical to what `sign_owner` will
    /// consume at dispatch (nonce-pinned).
    pub safe_tx_hash: B256,
    /// The decoded inner call the Safe will `execTransaction`. Always a raw tx, so
    /// it reuses [`ReviewLeg`] and its `leg_card` renderer verbatim.
    pub inner: Box<ReviewLeg>,
}

/// A CoW ERC-20 order authorized via EIP-1271 (a Safe `SafeMessage`). The order
/// rows plus the exact `safe_message_hash(order_digest, safe, chain)` each owner
/// signs over the order digest. Nonce-free (a message hash, not a `SafeTx`).
#[derive(Debug, Clone)]
pub struct SafeMessageReview {
    pub order: OrderReview,
    pub safe: Address,
    pub threshold: u8,
    pub owner_count: u8,
    /// CoW EIP-712 order hash — what the orderbook validates the signature against.
    pub order_digest: B256,
    /// `safe_message_hash(order_digest, safe, chain)` — the 32 bytes each owner
    /// signs. A pure function of `(order_digest, safe, chain)`, so no pin needed.
    pub message_hash: B256,
}

/// One reviewable step in a signature. A review is an ordered list of these: an
/// EOA swap is `[Typed(order), RawTx(approve)…]`; a Safe swap is
/// `[SafeExec(approve)?, SafeMessage(order)]` or `[SafeExec(createOrder)]`; a
/// name/pool write is just raw-tx steps. Every step carries the exact artifact
/// (calldata or 32-byte hash) the user authorizes, so reviewed == signed.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum SignStep {
    /// A raw transaction the user signs (approval, EthFlow `createOrder`, a
    /// registrar call, a pool deposit), decoded for review.
    RawTx(ReviewLeg),
    /// EIP-712 typed data the user signs (the CoW GPv2 order, EOA path).
    Typed(OrderReview),
    /// A Safe `execTransaction` (native `createOrder` / ERC-20 approve): the inner
    /// call plus the `safeTxHash` each owner signs.
    SafeExec(SafeExecReview),
    /// A CoW order authorized via EIP-1271 from a Safe: the order plus the
    /// `SafeMessage` hash each owner signs.
    SafeMessage(SafeMessageReview),
    /// An EOA send: the full inline review (intent, revm balance-change sim, gas,
    /// recipient, decoded call) snapshotted for the overlay. Carries the quote +
    /// plan that drive the broadcast, so reviewed == signed.
    Send(super::send::SendReview),
}

/// Pins the reviewed Safe artifacts so `cow_place_order_safe` signs exactly what
/// the review displayed. `SafeTx` isn't `Clone`, so we pin the `nonce` (the tx
/// rebuild is pure + deterministic) plus the hashes for an equality assert. Copy
/// — plain scalars/hashes, no key material.
#[derive(Debug, Clone, Copy)]
pub struct CowSafePin {
    /// Nonce the reviewed `execTransaction` was built at (native `createOrder` or
    /// ERC-20 approve). Unused when `exec_hash` is `None`.
    pub exec_nonce: u64,
    /// safeTxHash shown for the `execTransaction`, if the review had one (native,
    /// or ERC-20 with a short allowance). `None` for an ERC-20 swap needing no
    /// approval.
    pub exec_hash: Option<B256>,
    /// `safe_message_hash` shown for the EIP-1271 order, if any (ERC-20 path).
    pub msg_hash: Option<B256>,
}

/// What the coordinator runs when the user confirms. Holds the fully-prepared
/// action (commit secret already minted, draft+quote captured) so the signed
/// transaction is exactly what was reviewed.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum SignAction {
    Cow {
        host: CowHost,
        draft: SwapDraft,
        quote: QuoteResponse,
        /// Filled once a Safe prepare task lands (scanned from the steps in the
        /// `SignReviewPrepared` handler). `None` for an EOA swap (nothing to pin).
        prepared: Option<CowSafePin>,
    },
    CowCancel {
        host: CowHost,
        uid: String,
    },
    Name {
        sign: NameSign,
    },
    PrivacyPool {
        sign: PoolSign,
    },
    /// An EOA send. `plan` is known when the review opens; `quote` is filled once
    /// the prepare task lands (gas / nonce / fees), and the two together drive the
    /// broadcast at confirm — the same numbers the `SignStep::Send` step displays.
    Send {
        plan: SendPlan,
        quote: Option<TxQuote>,
    },
}

/// A prepared Privacy Pools EOA transaction to sign. A deposit carries an
/// optional ERC-20 approve leg then the Entrypoint deposit; the calldata is
/// final (deposits need no proof), so the reviewed bytes == the signed bytes.
#[derive(Debug, Clone)]
pub enum PoolSign {
    Deposit {
        chain: Chain,
        symbol: String,
        /// The Entrypoint the deposit targets.
        to: Address,
        /// ETH sent for a native deposit, `0` for an ERC-20 deposit.
        value: U256,
        calldata: Bytes,
        /// `(token, approve calldata)` sent to the token before an ERC-20 deposit.
        approve: Option<(Address, Bytes)>,
    },
    /// Ragequit (original-depositor exit) — the commitment proof is already
    /// generated, so `calldata` is the final `Pool.ragequit(proof)`.
    Ragequit {
        chain: Chain,
        symbol: String,
        pool: Address,
        calldata: Bytes,
    },
}

/// A prepared name-registry write. Commit/Register carry the *minted* plan so the
/// reviewed commitment matches the later reveal.
#[derive(Debug, Clone)]
pub enum NameSign {
    Commit(RegisterPlan),
    Register(RegisterPlan),
    RegisterXns {
        namespace: String,
        label: String,
    },
    Renew {
        namespace: Namespace,
        label: String,
        years: u32,
    },
    SetRecipient {
        namespace: Namespace,
        label: String,
        recipient: Address,
    },
}

/// Coordinator-held overlay state: what to show, and what to do on confirm.
#[derive(Debug, Clone)]
pub struct SignReview {
    pub title: String,
    pub subtitle: Option<String>,
    /// The reviewed steps, rendered top-to-bottom: an optional leading EIP-712
    /// typed-data step (a swap's order), then the decoded raw-tx legs. The order
    /// is known at open; the raw legs are appended when the prepare task lands.
    pub steps: Vec<SignStep>,
    /// True until the prepare task lands the decoded raw-tx legs.
    pub legs_loading: bool,
    /// A trailing context note (e.g. "gasless off-chain signature").
    pub note: Option<String>,
    /// Drops stale prepare results after the user has moved on.
    pub seq: u64,
    pub action: SignAction,
    /// Set once the user confirms and the signing task is in flight: the overlay
    /// stays open showing a "waiting for a signature" notice (so a hardware
    /// wallet prompt isn't left facing a blank screen) until the broadcast
    /// resolves. `None` before confirm; the elapsed time drives the animation.
    pub signing_since: Option<Instant>,
    /// A broadcast error surfaced back onto the still-open overlay (the Send flow
    /// keeps its review up so the user can read the failure and retry Confirm,
    /// rather than dropping them onto a blank host pane). `None` unless a dispatch
    /// resolved with an error.
    pub error: Option<String>,
    /// Overrides the "Confirm & sign" button label (e.g. the Send flow's
    /// "Sign & Send" / "Sign anyway ⚠" / "Need ETH for gas"). `None` → default.
    pub confirm_label: Option<String>,
    /// Blocks Confirm even once the steps are ready (e.g. a Send with too little
    /// ETH for gas). Independent of `legs_loading`.
    pub confirm_disabled: bool,
    /// Expand state for the Send step's "for the paranoid" decoded-calldata block.
    pub show_calldata: bool,
}

impl SignReview {
    /// Coarse phase name for the GUI state trace: "prepare" while the legs are
    /// still being built/decoded, "confirm" once they're shown and the gate is
    /// live, "signing" after the user confirmed and the signing task runs. The
    /// transitions themselves happen in the coordinator (`wallet_dashboard`),
    /// which diffs this name across its dispatch.
    pub fn phase(&self) -> &'static str {
        if self.signing_since.is_some() {
            "signing"
        } else if self.legs_loading {
            "prepare"
        } else {
            "confirm"
        }
    }

    /// Build a pending review whose legs are still being prepared.
    pub fn pending(
        title: String,
        subtitle: Option<String>,
        steps: Vec<SignStep>,
        note: Option<String>,
        seq: u64,
        action: SignAction,
    ) -> Self {
        let review = Self {
            title,
            subtitle,
            steps,
            legs_loading: true,
            note,
            seq,
            action,
            signing_since: None,
            error: None,
            confirm_label: None,
            confirm_disabled: false,
            show_calldata: false,
        };
        // Coordinator-driven open: every caller assigns this straight into the
        // overlay slot (guarded by an is-already-open early return), so the
        // open transition is traced at the one construction site.
        crate::trace::state("sign_review", "phase", "closed", review.phase());
        review
    }
}

/// Render the overlay. `progress` drives the shared modal open/close ease.
pub fn view<'a>(t: KaoTheme, review: &'a SignReview, progress: f32) -> Element<'a, Message> {
    let mut body = column![].spacing(0).width(Length::Fill);

    // ── Header ────────────────────────────────────────────────────────────
    body = body.push(
        text("Review & sign")
            .size(12)
            .color(t.sub)
            .font(mono_bold()),
    );
    body = body.push(Space::new().height(4));
    body = body.push(text(&review.title).size(19).color(t.text).font(bold()));
    if let Some(sub) = &review.subtitle {
        body = body.push(Space::new().height(4));
        body = body.push(text(sub).size(12).color(t.sub).font(mono()));
    }
    body = body.push(Space::new().height(16));

    // ── Reviewed steps: the EIP-712 order (if any) then the decoded raw-tx legs ──
    // Spacing preserves the original layout: 12px after a typed-data step, 10px
    // between raw-tx legs.
    for (i, step) in review.steps.iter().enumerate() {
        if i > 0 {
            let gap = if matches!(review.steps[i - 1], SignStep::Typed(_)) {
                12
            } else {
                10
            };
            body = body.push(Space::new().height(gap));
        }
        body = body.push(step_card(t, step, review.show_calldata));
    }

    if review.legs_loading {
        // A leading typed step (a swap's order) keeps its 12px gap before the
        // "preparing" card, matching the old order→legs spacing.
        if matches!(review.steps.last(), Some(SignStep::Typed(_))) {
            body = body.push(Space::new().height(12));
        }
        body = body.push(card(
            t,
            column![
                text("Preparing…").size(12).color(t.sub).font(bold()),
                Space::new().height(4),
                text("(・_・;) decoding the transaction you'll sign")
                    .size(12)
                    .color(t.sub)
                    .font(mono()),
            ]
            .into(),
        ));
    }

    if let Some(note) = &review.note {
        body = body.push(Space::new().height(12));
        body = body.push(text(note).size(11).color(t.sub).font(mono()));
    }

    // A broadcast error surfaced back onto the still-open review (Send retry path).
    if let Some(err) = &review.error {
        body = body.push(Space::new().height(12));
        body = body.push(
            text(format!("(╥﹏╥) {err}"))
                .size(12)
                .color(t.down)
                .font(bold()),
        );
    }

    // ── Actions ───────────────────────────────────────────────────────────
    // Once confirmed, the overlay swaps its buttons for a live "waiting for a
    // signature" notice and stays open until the signing task resolves — so a
    // hardware-wallet prompt isn't left facing a blank screen, and the reviewed
    // bytes stay visible above it. Otherwise show the Confirm / Cancel gate.
    body = body.push(Space::new().height(20));
    if let Some(since) = review.signing_since {
        body = body.push(waiting_card(t, since.elapsed().as_secs_f32()));
    } else {
        // Confirm stays disabled while legs are still decoding so the user can't
        // approve bytes they haven't been shown yet, and while a step-level guard
        // blocks it (a Send with too little ETH for gas). The label can be
        // overridden per-flow (Send's "Sign & Send" / "Sign anyway ⚠").
        let label = review.confirm_label.as_deref().unwrap_or("Confirm & sign");
        let enabled = !review.legs_loading && !review.confirm_disabled;
        let confirm = primary_button(t, label, enabled);
        let confirm = if enabled {
            confirm.on_press(Message::Confirm)
        } else {
            confirm
        };
        let actions = row![
            container(secondary_button(t, "Cancel").on_press(Message::Cancel))
                .width(Length::FillPortion(1)),
            Space::new().width(10),
            container(confirm).width(Length::FillPortion(1)),
        ]
        .width(Length::Fill);
        body = body.push(actions);
    }

    // Inset the content from the right so the scrollbar rides in its own gutter
    // instead of overlapping the cards (notably the full address rows).
    let scroll_body = scrollable(container(body).width(Length::Fill).padding(Padding {
        top: 0.0,
        right: 14.0,
        bottom: 0.0,
        left: 0.0,
    }))
    .height(Length::Shrink)
    .style(move |_, s| kao_scrollable_style(t, s));
    let bounded = container(scroll_body).max_height(FORM_MAX_HEIGHT);

    // While the signing task is in flight the review can't be dismissed (a
    // hardware signature can't be aborted from here), so a backdrop click is a
    // no-op; before confirm it cancels as usual.
    let on_backdrop = if review.signing_since.is_some() {
        Message::BoxClickIgnored
    } else {
        Message::Cancel
    };
    modal_wrapper(
        t,
        MODAL_WIDTH,
        progress,
        on_backdrop,
        Message::BoxClickIgnored,
        bounded.into(),
    )
}

/// The post-confirm "waiting for a signature" panel: a font-safe bouncing-bullet
/// animator (shared with the ZK proving screen) over a short notice. Shown in
/// place of the Confirm / Cancel gate while the signing task runs.
fn waiting_card<'a>(t: KaoTheme, elapsed: f32) -> Element<'a, Message> {
    card(
        t,
        column![
            text(bullet_wave(elapsed))
                .size(15)
                .color(t.a3)
                .font(mono_bold()),
            Space::new().height(8),
            text("Waiting for a signature")
                .size(14)
                .color(t.text)
                .font(bold()),
            Space::new().height(4),
            text(
                "Confirm the transaction on your device — this window stays open until it's signed."
            )
            .size(12)
            .color(t.sub)
            .font(mono()),
        ]
        .align_x(Alignment::Center)
        .width(Length::Fill)
        .into(),
    )
}

/// Render one reviewed step: a raw-tx leg through `function_panel`, or an EIP-712
/// typed-data step through `typed_panel`.
fn step_card<'a>(t: KaoTheme, step: &'a SignStep, show_calldata: bool) -> Element<'a, Message> {
    match step {
        SignStep::RawTx(leg) => leg_card(t, leg),
        SignStep::Typed(order) => order_panel(t, order),
        SignStep::SafeExec(x) => safe_exec_panel(t, x),
        SignStep::SafeMessage(m) => safe_message_panel(t, m),
        SignStep::Send(r) => {
            super::send::render_send_review(t, r, show_calldata, Message::ToggleCalldata)
        }
    }
}

/// A Safe `execTransaction` step: the ceremony header (N-of-M owners, Safe
/// address, nonce), the decoded inner call (via the shared `leg_card`), and the
/// exact `safeTxHash` each owner signs on their device.
fn safe_exec_panel<'a>(t: KaoTheme, x: &'a SafeExecReview) -> Element<'a, Message> {
    let mut col = column![
        text("Safe transaction — execTransaction")
            .size(11)
            .color(t.sub)
            .font(bold()),
        Space::new().height(2),
        text(format!(
            "{}-of-{} owners must sign",
            x.threshold, x.owner_count
        ))
        .size(13)
        .color(t.text)
        .font(bold()),
        Space::new().height(8),
    ]
    .spacing(0)
    .width(Length::Fill);
    col = col.push(addr_kv(t, "Safe", x.safe));
    col = col.push(kv(t, "Nonce", x.nonce.to_string()));
    col = col.push(Space::new().height(8));
    col = col.push(text("Safe will execute").size(11).color(t.sub).font(bold()));
    col = col.push(Space::new().height(4));
    col = col.push(leg_card(t, x.inner.as_ref()));
    col = col.push(Space::new().height(8));
    col = col.push(hash_row(
        t,
        "Each owner signs (SafeTx hash)",
        x.safe_tx_hash,
    ));
    card(t, col.into())
}

/// A CoW order authorized via EIP-1271 from a Safe: the order rows (same as the
/// EOA `typed_panel`) plus the order digest and the `SafeMessage` hash each owner
/// signs.
fn safe_message_panel<'a>(t: KaoTheme, m: &'a SafeMessageReview) -> Element<'a, Message> {
    let model = m.order.to_typed_model();
    let mut col = column![text(model.type_name).size(11).color(t.sub).font(bold())]
        .spacing(0)
        .width(Length::Fill);
    if let Some(headline) = model.headline {
        col = col.push(Space::new().height(2));
        col = col.push(text(headline).size(13).color(t.text).font(bold()));
    }
    col = col.push(Space::new().height(8));
    for TypedRow { label, value } in model.rows {
        col = match value {
            TypedValue::Text(v) => col.push(kv(t, label, v)),
            TypedValue::Addr(a) => col.push(addr_kv(t, label, a)),
        };
    }
    col = col.push(Space::new().height(10));
    col = col.push(
        text(format!(
            "Authorized via EIP-1271 — {}-of-{} owners sign",
            m.threshold, m.owner_count
        ))
        .size(11)
        .color(t.sub)
        .font(bold()),
    );
    col = col.push(Space::new().height(4));
    col = col.push(addr_kv(t, "Authorizing Safe", m.safe));
    col = col.push(hash_row(t, "Order digest (CoW EIP-712)", m.order_digest));
    col = col.push(hash_row(
        t,
        "Each owner signs (SafeMessage hash)",
        m.message_hash,
    ));
    card(t, col.into())
}

/// A 32-byte hash field: label on top, the full lowercase `0x…` value in its own
/// bordered box below, glyph-wrapped so a 66-char hash never overflows the panel.
/// Like [`addr_kv`], but hashes aren't addresses so they render as plain mono.
fn hash_row<'a>(t: KaoTheme, label: impl Into<String>, hash: B256) -> Element<'a, Message> {
    let inner = container(
        text(format!("{hash:#x}"))
            .size(11)
            .font(mono_bold())
            .color(t.text)
            .wrapping(Wrapping::Glyph),
    )
    .width(Length::Fill)
    .padding(Padding::from([6, 8]))
    .style(move |_| container::Style {
        background: Some(iced::Background::Color(t.card)),
        border: iced::Border {
            color: t.border,
            width: 1.0,
            radius: iced::border::Radius::from(8),
        },
        text_color: Some(t.text),
        ..container::Style::default()
    });
    column![
        text(label.into()).size(12).color(t.sub),
        Space::new().height(4),
        inner,
    ]
    .spacing(0)
    .padding(Padding::from([2, 0]))
    .width(Length::Fill)
    .into()
}

/// The CoW order review panel. Maps the [`OrderReview`] into a generic
/// [`TypedDataModel`] and hands it to [`typed_panel`] — so the order and any
/// future EIP-712 message share one renderer instead of a bespoke panel each.
fn order_panel<'a>(t: KaoTheme, o: &OrderReview) -> Element<'a, Message> {
    typed_panel(t, o.to_typed_model())
}

/// Render a [`TypedDataModel`] as a single card — header, optional headline, then
/// one row per field. The typed-data analogue of `function_panel`: no calldata to
/// decode, so it spells out the signed fields the orderbook/contract recovers the
/// signature against. Consumes the model so its owned strings move straight into
/// the widgets.
fn typed_panel<'a>(t: KaoTheme, model: TypedDataModel) -> Element<'a, Message> {
    let mut col = column![text(model.type_name).size(11).color(t.sub).font(bold())]
        .spacing(0)
        .width(Length::Fill);

    if let Some(headline) = model.headline {
        col = col.push(Space::new().height(2));
        col = col.push(text(headline).size(13).color(t.text).font(bold()));
    }
    col = col.push(Space::new().height(8));

    for TypedRow { label, value } in model.rows {
        col = match value {
            TypedValue::Text(v) => col.push(kv(t, label, v)),
            TypedValue::Addr(a) => col.push(addr_kv(t, label, a)),
        };
    }

    card(t, col.into())
}

/// A decoded raw-transaction leg: destination + value, then the shared
/// `function_panel` clear-signing render of its calldata.
fn leg_card<'a>(t: KaoTheme, leg: &'a ReviewLeg) -> Element<'a, Message> {
    let mut col = column![
        text(&leg.title).size(13).color(t.text).font(bold()),
        Space::new().height(6),
    ]
    .spacing(0)
    .width(Length::Fill);

    col = col.push(addr_kv(t, "To", leg.to));
    col = col.push(kv(t, "Network", leg.chain.display_name()));
    col = col.push(kv(t, "Value", format!("{} ETH", format_eth(leg.value))));

    if let Some(panel) =
        super::function_panel::view::<Message>(t, Some(leg.decoded.as_ref()), false)
    {
        col = col.push(Space::new().height(8));
        col = col.push(panel);
    }

    card(t, col.into())
}

fn kv<'a>(t: KaoTheme, label: impl Into<String>, value: impl Into<String>) -> Element<'a, Message> {
    row![
        text(label.into()).size(12).color(t.sub),
        Space::new().width(Length::Fill),
        text(value.into()).size(12).color(t.text).font(mono_bold()),
    ]
    .align_y(Alignment::Center)
    .padding(Padding::from([2, 0]))
    .width(Length::Fill)
    .into()
}

/// An address field: label on top, then the *full* checksummed address in its own
/// full-width card below. Stacking (rather than right-aligning on the label row)
/// is what gives the 42-char address the room to render in full instead of being
/// clipped at the panel edge.
fn addr_kv<'a>(t: KaoTheme, label: impl Into<String>, addr: Address) -> Element<'a, Message> {
    let inner = container(colored_address(t, addr))
        .width(Length::Fill)
        .padding(Padding::from([6, 8]))
        .style(move |_| container::Style {
            background: Some(iced::Background::Color(t.card)),
            border: iced::Border {
                color: t.border,
                width: 1.0,
                radius: iced::border::Radius::from(8),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        });
    column![
        text(label.into()).size(12).color(t.sub),
        Space::new().height(4),
        inner,
    ]
    .spacing(0)
    .padding(Padding::from([2, 0]))
    .width(Length::Fill)
    .into()
}

fn card<'a>(t: KaoTheme, content: Element<'a, Message>) -> Element<'a, Message> {
    container(content)
        .padding(Padding::from([12, 14]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(iced::Background::Color(t.card_alt)),
            border: iced::Border {
                color: t.border,
                width: 1.0,
                radius: iced::border::Radius::from(12),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
}

fn slippage_label(bps: u16) -> String {
    // 50 bps → "0.5%", 200 → "2%".
    let pct = bps as f64 / 100.0;
    if (pct.fract()).abs() < f64::EPSILON {
        format!("{pct:.0}%")
    } else {
        format!("{pct}%")
    }
}

fn format_eth(v: U256) -> String {
    if v.is_zero() {
        return "0".to_string();
    }
    let raw = alloy::primitives::utils::format_ether(v);
    let f = raw.parse::<f64>().unwrap_or(0.0);
    if f >= 1.0 {
        format!("{f:.4}")
    } else {
        let s = format!("{f:.8}");
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

/// `validTo` rendered as an absolute UTC instant plus a relative "in N min" so a
/// user can sanity-check the order's lifetime before signing.
fn format_expiry(valid_to: u32) -> String {
    let now = crate::names::manage::now_secs();
    let abs = format_iso_utc(valid_to as u64);
    if now == 0 || (valid_to as u64) <= now {
        return abs;
    }
    let secs = (valid_to as u64).saturating_sub(now);
    let rel = if secs < 90 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{} min", secs / 60)
    } else {
        format!("{} hr", secs / 3600)
    };
    format!("{abs} (in {rel})")
}

/// `YYYY-MM-DD HH:MM UTC` from unix seconds (Howard Hinnant's civil-day algo —
/// the same one `tx_details` uses, kept inline to avoid a chrono dependency).
fn format_iso_utc(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = unix_secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02} UTC")
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slippage_label_formats_bps() {
        assert_eq!(slippage_label(50), "0.5%");
        assert_eq!(slippage_label(200), "2%");
        assert_eq!(slippage_label(10), "0.1%");
    }

    #[test]
    fn format_eth_trims_and_floors() {
        assert_eq!(format_eth(U256::ZERO), "0");
        // 1 ETH exactly.
        assert_eq!(
            format_eth(U256::from(1_000_000_000_000_000_000u128)),
            "1.0000"
        );
    }

    #[test]
    fn format_iso_utc_epoch() {
        assert_eq!(format_iso_utc(0), "1970-01-01 00:00 UTC");
    }

    #[test]
    fn cow_order_maps_to_the_expected_typed_rows() {
        // Pins the CoW order review content: a dropped/renamed row fails here, and
        // this mapping is exactly what `typed_panel` renders — so it doubles as the
        // pixel-identical guard for the panel refactor.
        let o = OrderReview {
            chain: Chain::Mainnet,
            sell_amount: "1.5".into(),
            sell_symbol: "WETH".into(),
            buy_amount: "4200".into(),
            buy_symbol: "USDC".into(),
            min_received: "4158".into(),
            receiver: Address::repeat_byte(0xAA),
            valid_to: 1_600_000_000, // 2020 — always past, so `Expires` is deterministic
            slippage_bps: 50,
            settlement: Address::repeat_byte(0x55),
            native: false,
        };
        let m = o.to_typed_model();

        assert_eq!(m.type_name, "CoW order — EIP-712 signature");
        assert_eq!(
            m.headline.as_deref(),
            Some("Sell 1.5 WETH for at least 4158 USDC")
        );
        let labels: Vec<&str> = m.rows.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "You sell",
                "Receive (est.)",
                "Min received",
                "Receiver",
                "Order type",
                "Solver fee",
                "Expires",
                "Settlement",
                "Network",
                "Settles",
            ],
        );
        assert_eq!(m.rows[0].value, TypedValue::Text("1.5 WETH".into()));
        assert_eq!(m.rows[1].value, TypedValue::Text("4200 USDC".into()));
        assert_eq!(
            m.rows[2].value,
            TypedValue::Text("4158 USDC · 0.5% slippage".into())
        );
        assert_eq!(m.rows[3].value, TypedValue::Addr(o.receiver));
        assert_eq!(m.rows[7].value, TypedValue::Addr(o.settlement));
        assert_eq!(
            m.rows[9].value,
            TypedValue::Text("off-chain via solvers · gasless".into())
        );
    }
}
