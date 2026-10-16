//! Settings → Signed messages: what the user signed for dapps over WalletConnect — `personal_sign`,
//! typed data, and both through a Safe (an EIP-1271 SafeMessage) — newest first, from the vault.
//!
//! The pane is a viewer: the dashboard seeds it from `Vault::signed()` and reseeds it whenever the
//! vault's revision moves (`set_records`), and a confirmed "Clear history" goes straight to the
//! vault as [`Outcome::Clear`]. Messages carry record ids, never payloads or signatures, so the
//! trace sees nothing that was signed.
//!
//! Dapp strings (host, claimed name, `primaryType`, the payload itself) were sanitized at ingress
//! and are drawn only in bordered mono boxes or as the dapp's claim, like the review drew them; a
//! message is shown as the review showed it — text by the review's own rule
//! (`walletconnect::message::classify`), else hex under the reason — never with characters dropped.
//!
//! A signature is shown (and copyable) only once it reached the dapp. Until then its record keeps
//! only its fingerprint: the signature itself waits, encrypted, in the saved WalletConnect state,
//! so Kao can send it again after a restart, and leaves the disk with it. One that never reached
//! the dapp is not kept at all.

use std::collections::BTreeSet;

use alloy::primitives::hex;
use iced::border::Radius;
use iced::widget::text::Wrapping;
use iced::widget::{Space, button, column, container, row, text};
use iced::{Alignment, Background, Border, Element, Length, Padding, Task};

use super::activity::format_relative;
use super::sign_review::format_iso_utc;
use crate::sanitize::{escape_unsafe_display, sanitize_display};
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    BadgeKind, black, bold, colored_hash_copyable, ghost_button, hover_tint, kao_scrollable_style,
    mono, mono_bold, mono_box, privacy_badge, small_danger_button, small_secondary_button,
};
use crate::vault::{Delivery, SignOrigin, SignedKind, SignedPayload, SignedRecord, Unreadable};
use crate::walletconnect::{BinaryReason, MessageShape};

/// Records listed per page ("Show more" adds another).
pub const PAGE: usize = 50;
/// Lines of a payload drawn before "… N more lines".
const MAX_PAYLOAD_LINES: usize = 300;
/// Hex-dump width.
const HEX_BYTES_PER_LINE: usize = 16;
/// `primaryType` clamp on the row header.
const MAX_PRIMARY_TYPE_CHARS: usize = 40;

const NOTE: &str = "Messages and typed data you signed for dapps over WalletConnect. Kept \
     encrypted in your wallet.";
/// An answer the dapp hasn't confirmed yet: its signature waits in the saved WalletConnect state.
const SENDING_SIGNATURE: &str = "Kao keeps this signature (encrypted) until the dapp gets it, so \
     it can send it again after a restart.";
/// An answer that never reached the dapp: its signature was dropped with it.
const NOT_DELIVERED_SIGNATURE: &str = "Signature not kept — it never reached the dapp.";
/// The empty list while some records exist that Kao couldn't read (or their key is gone).
pub(super) const NONE_SHOWN: &str = "No records Kao can show.";
/// The history panes' note while the wallet file's saved state can't be read
/// (`Unreadable::key_unavailable`): a lasting fault, not a hiccup — nothing is shown, and nothing
/// new is saved until the user resets it. Wallet saves don't depend on it, so it promises nothing
/// about them.
pub(super) const KEY_UNAVAILABLE_NOTE: &str = "Kao can't read the history saved in your wallet \
     file, so none of it is shown. Until that's fixed, new history and WalletConnect connections \
     aren't saved — they're gone when Kao locks or quits.";
/// The way out of [`KEY_UNAVAILABLE_NOTE`], and its confirm.
pub(super) const RESET_LABEL: &str = "Reset saved history and connections…";
pub(super) const RESET_CONFIRM: &str = "Delete the saved history and connections Kao can't read?";
pub(super) const RESET_CONFIRM_DETAIL: &str = "The signed messages, connection history and \
     WalletConnect connections saved in your wallet file are deleted, and the dapps of those \
     connections aren't told. Your accounts, Safes and contacts stay. Kao can't undo this. From \
     then on, Kao saves new history and connections again.";

#[derive(Debug, Clone)]
pub enum Message {
    /// No-op published by a copyable hash click so the dashboard's "Copied!" toast animation
    /// starts. Ignored.
    AddressCopied,
    Back,
    /// Expand / collapse the record with this id.
    Toggle(u64),
    ShowMore,
    /// [Copy] on a delivered record's signature (by id; the pane looks it up).
    CopySignature(u64),
    /// First step of "Clear history"; never clears anything by itself.
    AskClear,
    ConfirmClear,
    CancelClear,
    /// First step of "Reset saved history and connections…" (only while the wallet file's saved
    /// state can't be read); never resets anything by itself.
    AskReset,
    ConfirmReset,
    CancelReset,
}

#[derive(Clone)]
pub enum Outcome {
    /// Back to the settings root.
    Closed,
    /// The user confirmed clearing every signed-message record (and any unreadable row).
    Clear,
    /// The user confirmed resetting the saved history and connections the wallet file can't read.
    Reset,
    /// Copy this to the clipboard (the dashboard's auto-clearing copy).
    CopyText(String),
}

impl Outcome {
    /// Variant name for the GUI state trace — never the payload.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Closed => "Closed",
            Outcome::Clear => "Clear",
            Outcome::Reset => "Reset",
            Outcome::CopyText(_) => "CopyText",
        }
    }
}

/// The variant only: `CopyText` carries a signature.
impl std::fmt::Debug for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

pub struct SignedMessagesPane {
    /// Newest first.
    records: Vec<SignedRecord>,
    unreadable: Unreadable,
    /// How many records are listed (pages of [`PAGE`]).
    shown: usize,
    expanded: BTreeSet<u64>,
    confirm_clear: bool,
    confirm_reset: bool,
    /// Whether the vault saves new records (it has its data key this session).
    can_persist: bool,
}

/// Counts only: the records hold what was signed.
impl std::fmt::Debug for SignedMessagesPane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedMessagesPane")
            .field("records", &self.records.len())
            .field("shown", &self.shown)
            .field("expanded", &self.expanded.len())
            .field("confirm_clear", &self.confirm_clear)
            .field("confirm_reset", &self.confirm_reset)
            .finish()
    }
}

impl SignedMessagesPane {
    pub fn new(records: Vec<SignedRecord>, unreadable: Unreadable) -> Self {
        Self {
            records,
            unreadable,
            shown: PAGE,
            expanded: BTreeSet::new(),
            confirm_clear: false,
            confirm_reset: false,
            can_persist: true,
        }
    }

    /// Clear removes the readable records and the unreadable rows alike (`Vault::clear_signed`).
    fn clearable(&self) -> usize {
        self.records.len() + self.unreadable.signed
    }

    /// Whether the vault saves new records: the unreadable note promises they're kept only then.
    pub fn set_can_persist(&mut self, can_persist: bool) {
        self.can_persist = can_persist;
    }

    /// The vault changed: show what it holds now. Expanded rows stay expanded while their record
    /// does; a staged Clear stands only while there is something to clear, a staged reset only
    /// while the saved state still can't be read.
    pub fn set_records(&mut self, records: Vec<SignedRecord>, unreadable: Unreadable) {
        let ids: BTreeSet<u64> = records.iter().map(|r| r.id).collect();
        self.expanded.retain(|id| ids.contains(id));
        self.records = records;
        self.unreadable = unreadable;
        if self.clearable() == 0 {
            self.confirm_clear = false;
        }
        if !unreadable.key_unavailable {
            self.confirm_reset = false;
        }
    }

    pub fn update(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("signed_messages", &msg);
        let confirming_before = self.confirm_clear;
        let resetting_before = self.confirm_reset;
        let expanded_before = self.expanded.len();
        let (task, outcome) = self.update_inner(msg);
        if confirming_before != self.confirm_clear {
            crate::trace::state(
                "signed_messages",
                "confirm_clear",
                confirming_before,
                self.confirm_clear,
            );
        }
        if resetting_before != self.confirm_reset {
            crate::trace::state(
                "signed_messages",
                "confirm_reset",
                resetting_before,
                self.confirm_reset,
            );
        }
        if expanded_before != self.expanded.len() {
            crate::trace::state(
                "signed_messages",
                "expanded",
                expanded_before,
                self.expanded.len(),
            );
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("signed_messages", o.name());
        }
        (task, outcome)
    }

    fn update_inner(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        match msg {
            Message::AddressCopied => (Task::none(), None),
            Message::Back => {
                self.confirm_clear = false;
                self.confirm_reset = false;
                (Task::none(), Some(Outcome::Closed))
            }
            Message::Toggle(id) => {
                if !self.expanded.remove(&id) && self.records.iter().any(|r| r.id == id) {
                    self.expanded.insert(id);
                }
                (Task::none(), None)
            }
            Message::ShowMore => {
                self.shown = self.shown.saturating_add(PAGE);
                (Task::none(), None)
            }
            Message::CopySignature(id) => {
                let sig = self
                    .records
                    .iter()
                    .find(|r| r.id == id)
                    .and_then(shown_signature);
                match sig {
                    Some(sig) => (
                        Task::none(),
                        Some(Outcome::CopyText(hex::encode_prefixed(sig))),
                    ),
                    None => (Task::none(), None),
                }
            }
            Message::AskClear => {
                self.confirm_clear = self.clearable() > 0;
                (Task::none(), None)
            }
            Message::ConfirmClear => {
                if !std::mem::take(&mut self.confirm_clear) || self.clearable() == 0 {
                    return (Task::none(), None);
                }
                (Task::none(), Some(Outcome::Clear))
            }
            Message::CancelClear => {
                self.confirm_clear = false;
                (Task::none(), None)
            }
            Message::AskReset => {
                self.confirm_reset = self.unreadable.key_unavailable;
                (Task::none(), None)
            }
            Message::ConfirmReset => {
                if !std::mem::take(&mut self.confirm_reset) || !self.unreadable.key_unavailable {
                    return (Task::none(), None);
                }
                (Task::none(), Some(Outcome::Reset))
            }
            Message::CancelReset => {
                self.confirm_reset = false;
                (Task::none(), None)
            }
        }
    }

    pub fn view(&self, t: KaoTheme) -> Element<'_, Message> {
        let now = crate::walletconnect::now_secs();
        let header = row![
            ghost_button(t, text("← Back").size(12).color(t.sub).font(bold()))
                .padding(Padding::from([4, 8]))
                .on_press(Message::Back),
            Space::new().width(Length::Fill),
            text("Signed messages").size(14).color(t.text).font(black()),
            Space::new().width(Length::Fill),
            // Symmetry placeholder so the title centers visually.
            text("    ").size(12),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill);

        let mut body = column![
            header,
            Space::new().height(12),
            text(NOTE).size(11).color(t.sub),
        ]
        .width(Length::Fill);

        if let Some(line) = unreadable_line(
            self.unreadable.signed,
            self.unreadable,
            self.can_persist,
            "signed-message record",
        ) {
            body = body.push(Space::new().height(6));
            body = body.push(text(line).size(11).color(t.down).font(bold()));
        }
        if self.unreadable.key_unavailable {
            body = body.push(Space::new().height(8));
            body = body.push(reset_controls(
                t,
                self.confirm_reset,
                Message::AskReset,
                Message::ConfirmReset,
                Message::CancelReset,
            ));
        }
        body = body.push(Space::new().height(14));

        if self.records.is_empty() {
            body = body.push(empty_state(
                t,
                nothing_unshown(self.unreadable.signed, self.unreadable),
                "Nothing signed yet.",
                "Messages you sign for a dapp you connected with WalletConnect show up here.",
            ));
        }

        for r in self.records.iter().take(self.shown) {
            body = body
                .push(self.record_card(t, r, now))
                .push(Space::new().height(8));
        }
        if self.records.len() > self.shown {
            body = body.push(
                container(small_secondary_button(t, "Show more").on_press(Message::ShowMore))
                    .width(Length::Fill)
                    .center_x(Length::Fill),
            );
            body = body.push(Space::new().height(8));
        }

        if self.clearable() > 0 {
            body = body.push(Space::new().height(10));
            body = body.push(self.clear_controls(t));
        }

        iced::widget::scrollable(
            container(body)
                .padding(Padding::from([22, 24]))
                .width(Length::Fill),
        )
        .height(Length::Fill)
        .width(Length::Fill)
        .style(move |_, s| kao_scrollable_style(t, s))
        .into()
    }

    /// One record: the summary is a button that toggles the detail below it (the detail holds
    /// its own controls, so it sits outside the button).
    fn record_card<'a>(
        &'a self,
        t: KaoTheme,
        r: &'a SignedRecord,
        now: u64,
    ) -> Element<'a, Message> {
        let expanded = self.expanded.contains(&r.id);
        let summary = button(summary_lines(t, r, now))
            .padding(Padding::from([12, 14]))
            .width(Length::Fill)
            .on_press(Message::Toggle(r.id))
            .style(move |_theme, status| button::Style {
                background: Some(Background::Color(match status {
                    button::Status::Hovered | button::Status::Pressed => hover_tint(t.card, t.text),
                    _ => t.card,
                })),
                text_color: t.text,
                border: Border {
                    color: t.border,
                    width: 1.0,
                    radius: Radius::from(14),
                },
                ..button::Style::default()
            });
        if !expanded {
            return summary.into();
        }
        column![
            summary,
            container(detail(t, r))
                .padding(Padding::from([12, 14]))
                .width(Length::Fill)
                .style(move |_| container::Style {
                    background: Some(Background::Color(t.card_alt)),
                    border: Border {
                        color: t.border,
                        width: 1.0,
                        radius: Radius::from(14),
                    },
                    text_color: Some(t.text),
                    ..container::Style::default()
                }),
        ]
        .spacing(4)
        .width(Length::Fill)
        .into()
    }

    fn clear_controls(&self, t: KaoTheme) -> Element<'_, Message> {
        if self.confirm_clear {
            let total = self.clearable();
            let unread = self.unreadable.signed;
            let records = if total == 1 { "record" } else { "records" };
            let question = if unread == 0 && total == 1 {
                "Remove this signed-message record from Kao?".to_string()
            } else if unread == 0 {
                format!("Remove all {total} signed-message {records} from Kao?")
            } else if self.records.is_empty() {
                format!("Remove the {total} signed-message {records} Kao couldn't read?")
            } else {
                format!(
                    "Remove all {total} signed-message records from Kao, including {unread} it \
                     couldn't read?"
                )
            };
            column![
                text(question).size(12).color(t.down).font(bold()),
                Space::new().height(4),
                text(
                    "Kao can't undo this. Encrypted copies can stay inside the wallet file until \
                     its space is reused."
                )
                .size(11)
                .color(t.sub),
                Space::new().height(8),
                row![
                    Space::new().width(Length::Fill),
                    small_secondary_button(t, "Keep").on_press(Message::CancelClear),
                    small_danger_button(t, "Clear").on_press(Message::ConfirmClear),
                ]
                .spacing(6)
                .align_y(Alignment::Center)
                .width(Length::Fill),
            ]
            .width(Length::Fill)
            .into()
        } else {
            row![
                small_danger_button(t, "Clear history").on_press(Message::AskClear),
                Space::new().width(Length::Fill),
            ]
            .width(Length::Fill)
            .into()
        }
    }
}

/// The signature the pane may show: only one that reached the dapp.
fn shown_signature(r: &SignedRecord) -> Option<&[u8]> {
    match r.delivery {
        Delivery::Delivered => r.signature.as_ref().map(|b| b.as_ref()),
        Delivery::Sending | Delivery::NotDelivered => None,
    }
}

/// "N records couldn't be read …" / the key notes / that new records aren't kept, or `None` when
/// everything was read and is kept. `count`: the unreadable records of this pane's kind; `what`:
/// what one of them is called; `can_persist`: whether the vault saves new records — the note
/// promises they're kept only then.
pub(super) fn unreadable_line(
    count: usize,
    unread: Unreadable,
    can_persist: bool,
    what: &str,
) -> Option<String> {
    // It lasts (a storage fault on the wallet file), and nothing is saved while it does: the
    // pane offers the reset under it.
    if unread.key_unavailable {
        return Some(KEY_UNAVAILABLE_NOTE.to_string());
    }
    let older = if unread.key_lost {
        Some(
            "Kao couldn't read the key its history is encrypted with, so older records can't be \
             shown.",
        )
    } else {
        None
    };
    let newer = if can_persist {
        "New ones are kept again from now on."
    } else {
        "Kao can't keep new ones right now either — they're gone when Kao locks or quits."
    };
    if let Some(older) = older {
        return Some(format!("{older} {newer}"));
    }
    if !can_persist {
        return Some(
            "Kao can't keep new records right now — they're gone when Kao locks or quits."
                .to_string(),
        );
    }
    (count > 0).then(|| {
        format!(
            "{count} {what}{} couldn't be read and {} shown.",
            if count == 1 { "" } else { "s" },
            if count == 1 { "isn't" } else { "aren't" }
        )
    })
}

/// Whether an empty list means there is nothing at all: no row Kao couldn't read (`count`, this
/// pane's kind), and no key trouble that would hide some.
pub(super) fn nothing_unshown(count: usize, unread: Unreadable) -> bool {
    count == 0 && !unread.key_lost && !unread.key_unavailable
}

/// The empty list: `none_yet` + `hint` when there is truly nothing, else [`NONE_SHOWN`] — the
/// note above it says what couldn't be shown.
pub(super) fn empty_state<'a, M: 'a>(
    t: KaoTheme,
    nothing_unshown: bool,
    none_yet: &'a str,
    hint: &'a str,
) -> Element<'a, M> {
    let lines = if nothing_unshown {
        column![
            text(none_yet).size(13).color(t.sub),
            Space::new().height(4),
            text(hint).size(12).color(t.sub),
        ]
    } else {
        column![text(NONE_SHOWN).size(13).color(t.sub)]
    };
    container(lines.align_x(Alignment::Center))
        .width(Length::Fill)
        .center_x(Length::Fill)
        .padding(Padding::from([22, 0]))
        .into()
}

/// "Reset saved history and connections…", two-step: the first press stages the confirm (what is
/// deleted, and that the dapps aren't told), which offers Keep and Reset. Shared by both history
/// panes and the WalletConnect pane.
pub(super) fn reset_controls<'a, M: Clone + 'a>(
    t: KaoTheme,
    confirming: bool,
    ask: M,
    confirm: M,
    cancel: M,
) -> Element<'a, M> {
    if confirming {
        column![
            text(RESET_CONFIRM).size(12).color(t.down).font(bold()),
            Space::new().height(4),
            text(RESET_CONFIRM_DETAIL).size(11).color(t.sub),
            Space::new().height(8),
            row![
                Space::new().width(Length::Fill),
                small_secondary_button(t, "Keep").on_press(cancel),
                small_danger_button(t, "Reset").on_press(confirm),
            ]
            .spacing(6)
            .align_y(Alignment::Center)
            .width(Length::Fill),
        ]
        .width(Length::Fill)
        .into()
    } else {
        row![
            small_danger_button(t, RESET_LABEL).on_press(ask),
            Space::new().width(Length::Fill),
        ]
        .width(Length::Fill)
        .into()
    }
}

/// The dapp of a record's origin.
fn origin_dapp(r: &SignedRecord) -> (&str, &str) {
    match &r.origin {
        SignOrigin::WalletConnect { dapp, .. } => {
            (dapp.host.as_deref().unwrap_or("unknown site"), &dapp.name)
        }
    }
}

/// Lines 1-3: what kind of signature and when; the dapp (host in its box, then its claim); who
/// signed, on which network, and whether it reached the dapp.
fn summary_lines<'a>(t: KaoTheme, r: &'a SignedRecord, now: u64) -> Element<'a, Message> {
    let mut kind = row![].spacing(6).align_y(Alignment::Center);
    kind = match r.kind {
        SignedKind::Message => kind.push(text("Message").size(13).color(t.text).font(bold())),
        SignedKind::TypedData => kind.push(text("Typed data").size(13).color(t.text).font(bold())),
        SignedKind::SafeMessage => {
            kind.push(text("Safe message").size(13).color(t.text).font(bold()))
        }
    };
    // The dapp's own type name: a dapp string, so in its own mono chip.
    if let Some(pt) = r.primary_type.as_deref().filter(|p| !p.is_empty()) {
        kind = kind.push(mono_chip(
            t,
            sanitize_display(&escape_unsafe_display(pt), MAX_PRIMARY_TYPE_CHARS).into_owned(),
        ));
    }
    let (host, name) = origin_dapp(r);
    let mut who = row![
        text(format!(
            "by {} · {} · {}",
            r.account.label(),
            crate::wallet::short_address(r.account.address()),
            crate::walletconnect::chain_label(r.chain_id)
        ))
        .size(12)
        .color(t.text),
        Space::new().width(Length::Fill),
    ]
    .spacing(6)
    .align_y(Alignment::Center)
    .width(Length::Fill);
    match r.delivery {
        Delivery::Delivered => {}
        Delivery::Sending => {
            who = who.push(privacy_badge(t, BadgeKind::Caution, "Delivery unconfirmed"))
        }
        Delivery::NotDelivered => {
            who = who.push(privacy_badge(t, BadgeKind::Warning, "Not delivered"))
        }
    }
    column![
        row![
            kind,
            Space::new().width(Length::Fill),
            text(format_relative(now, r.at))
                .size(11)
                .color(t.sub)
                .font(mono()),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill),
        Space::new().height(6),
        row![
            mono_box(
                t,
                text(host.to_string())
                    .size(13)
                    .color(t.text)
                    .font(mono_bold())
                    .into()
            ),
            Space::new().width(8),
            text(format!("calls itself \"{name}\""))
                .size(12)
                .color(t.sub),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill),
        Space::new().height(6),
        who,
    ]
    .spacing(0)
    .width(Length::Fill)
    .into()
}

/// The expanded detail: when, exactly what was signed, the ERC-8213 fingerprints, the signature.
fn detail<'a>(t: KaoTheme, r: &'a SignedRecord) -> Element<'a, Message> {
    let mut col = column![
        text(format!("Signed {}", format_iso_utc(r.at)))
            .size(11)
            .color(t.sub)
            .font(mono()),
        Space::new().height(8),
    ]
    .spacing(0)
    .width(Length::Fill);

    let (label, lines) = payload_lines(&r.payload);
    col = col.push(text(label).size(11).color(t.sub).font(bold()));
    col = col.push(Space::new().height(4));
    let mut body = column![].spacing(1).width(Length::Fill);
    for line in lines {
        body = body.push(
            text(line)
                .size(12)
                .color(t.text)
                .font(mono())
                .wrapping(Wrapping::WordOrGlyph),
        );
    }
    col = col.push(mono_box(t, body.into()));

    if !r.digests.is_empty() {
        col = col.push(Space::new().height(12));
        col = col.push(
            text("ERC-8213 fingerprints")
                .size(11)
                .color(t.sub)
                .font(bold()),
        );
        for d in &r.digests {
            col = col.push(Space::new().height(6));
            col = col.push(text(d.label.clone()).size(11).color(t.sub));
            col = col.push(colored_hash_copyable(t, d.hash));
        }
    }

    col = col.push(Space::new().height(12));
    col = col.push(text("Signature").size(11).color(t.sub).font(bold()));
    col = col.push(Space::new().height(4));
    match shown_signature(r) {
        Some(sig) => {
            col = col.push(
                row![
                    container(
                        text(hex::encode_prefixed(sig))
                            .size(11)
                            .color(t.text)
                            .font(mono())
                            .wrapping(Wrapping::Glyph)
                    )
                    .width(Length::Fill),
                    small_secondary_button(t, "Copy").on_press(Message::CopySignature(r.id)),
                ]
                .spacing(8)
                .align_y(Alignment::Center)
                .width(Length::Fill),
            );
        }
        None => {
            col = col.push(
                text(match r.delivery {
                    Delivery::NotDelivered => NOT_DELIVERED_SIGNATURE,
                    Delivery::Sending => SENDING_SIGNATURE,
                    Delivery::Delivered => "Signature not kept.",
                })
                .size(12)
                .color(t.sub),
            );
        }
    }
    col = col.push(Space::new().height(6));
    col = col.push(
        text(format!(
            "Signature fingerprint (keccak256 of the {}-byte signature):",
            r.signature_len
        ))
        .size(11)
        .color(t.sub),
    );
    col = col.push(colored_hash_copyable(t, r.signature_hash));
    col.into()
}

/// What was signed, as display lines under a label: a message as the review showed it — text by
/// its rule (`message::classify`), else hex under the reason it isn't text — and typed data as
/// pretty JSON with hidden characters escaped. Clamped to [`MAX_PAYLOAD_LINES`].
fn payload_lines(p: &SignedPayload) -> (&'static str, Vec<String>) {
    let (label, lines) = match p {
        SignedPayload::Message { bytes } => match crate::walletconnect::message::classify(bytes) {
            MessageShape::Text { lines } => ("Message", lines),
            MessageShape::Binary { reason, .. } => (
                match reason {
                    BinaryReason::NotUtf8 => "Not text — shown as hex",
                    BinaryReason::HiddenCharacters => "Hidden characters — shown as hex",
                    BinaryReason::TooLong => "Too long to show as text — shown as hex",
                    BinaryReason::OpaqueHash32 => "32-byte hash — shown as hex",
                },
                hex_lines(bytes),
            ),
        },
        SignedPayload::TypedData { json } => {
            let pretty = serde_json::from_str::<serde_json::Value>(json)
                .ok()
                .and_then(|v| serde_json::to_string_pretty(&v).ok())
                .unwrap_or_else(|| json.clone());
            (
                "Typed data",
                pretty
                    .lines()
                    .map(|l| escape_unsafe_display(l).into_owned())
                    .collect(),
            )
        }
    };
    (label, clamp_lines(lines))
}

fn hex_lines(bytes: &[u8]) -> Vec<String> {
    if bytes.is_empty() {
        return vec!["(empty)".to_string()];
    }
    bytes
        .chunks(HEX_BYTES_PER_LINE)
        .map(|chunk| {
            chunk
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

fn clamp_lines(mut lines: Vec<String>) -> Vec<String> {
    if lines.len() > MAX_PAYLOAD_LINES {
        let more = lines.len() - MAX_PAYLOAD_LINES;
        lines.truncate(MAX_PAYLOAD_LINES);
        lines.push(format!(
            "… {more} more {}",
            if more == 1 { "line" } else { "lines" }
        ));
    }
    lines
}

/// A short dapp string in its own small bordered mono chip.
fn mono_chip<'a>(t: KaoTheme, s: String) -> Element<'a, Message> {
    container(text(s).size(11).color(t.text).font(mono_bold()))
        .padding(Padding::from([2, 6]))
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card_alt)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(6),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
}

#[cfg(test)]
#[allow(unused_must_use)]
mod tests {
    use super::*;
    use crate::ui::kao_theme::ThemeKind;
    use crate::vault::{AccountRef, DappRecord, DigestRow};
    use alloy::primitives::{Address, B256, Bytes};

    fn theme() -> KaoTheme {
        KaoTheme::for_kind(ThemeKind::Void)
    }

    fn record(id: u64, kind: SignedKind, delivery: Delivery) -> SignedRecord {
        let payload = match kind {
            SignedKind::TypedData => SignedPayload::TypedData {
                json: r#"{"primaryType":"Permit","message":{"value":"1"}}"#.into(),
            },
            _ => SignedPayload::Message {
                bytes: b"Sign in to app.uniswap.org\nNonce: 42".to_vec(),
            },
        };
        SignedRecord {
            id,
            at: 1_700_000_000,
            origin: SignOrigin::WalletConnect {
                topic: "ab".repeat(32),
                request_id: id,
                session_ordinal: 1,
                dapp: DappRecord {
                    name: "Uniswap Interface".into(),
                    host: Some("app.uniswap.org".into()),
                    url: "https://app.uniswap.org".into(),
                    ..Default::default()
                },
            },
            account: AccountRef::Eoa {
                address: Address::repeat_byte(0x11),
                label: "Account 1".into(),
            },
            chain_id: 1,
            kind,
            primary_type: (kind == SignedKind::TypedData).then(|| "Permit".to_string()),
            payload,
            digests: vec![DigestRow {
                label: crate::sign::digest::EIP191_DIGEST_LABEL.into(),
                hash: B256::repeat_byte(0x22),
            }],
            signature: Some(Bytes::from(vec![0xab; 65])),
            signature_hash: B256::repeat_byte(0x33),
            signature_len: 65,
            delivery,
        }
    }

    fn render(pane: &SignedMessagesPane) -> Vec<String> {
        super::super::test_support::texts(pane.view(theme()))
    }

    #[test]
    fn renders_rows_newest_first_with_the_dapp_boxed_before_its_claim() {
        let pane = SignedMessagesPane::new(
            vec![
                record(2, SignedKind::TypedData, Delivery::Sending),
                record(1, SignedKind::Message, Delivery::Delivered),
            ],
            Unreadable::default(),
        );
        let texts = render(&pane);
        let typed = texts.iter().position(|s| s == "Typed data").unwrap();
        let message = texts.iter().position(|s| s == "Message").unwrap();
        assert!(typed < message, "newest first: {texts:?}");
        assert!(texts.iter().any(|s| s == "Permit"), "{texts:?}");
        let host = texts.iter().position(|s| s == "app.uniswap.org").unwrap();
        let claim = texts
            .iter()
            .position(|s| s == "calls itself \"Uniswap Interface\"")
            .unwrap();
        assert!(host < claim, "{texts:?}");
        assert!(
            texts.iter().any(|s| s == "! Delivery unconfirmed"),
            "{texts:?}"
        );
        assert!(
            texts
                .iter()
                .any(|s| s.starts_with("by Account 1 · ") && s.ends_with("Ethereum Mainnet")),
            "{texts:?}"
        );
        assert!(texts.iter().any(|s| s == NOTE), "{texts:?}");
        // Collapsed: nothing of the payload or the fingerprints yet.
        assert!(!texts.iter().any(|s| s == "ERC-8213 fingerprints"));
    }

    #[test]
    fn expanding_shows_the_payload_fingerprints_and_only_a_delivered_signature() {
        let mut pane = SignedMessagesPane::new(
            vec![
                record(2, SignedKind::Message, Delivery::NotDelivered),
                record(1, SignedKind::Message, Delivery::Delivered),
            ],
            Unreadable::default(),
        );
        pane.update(Message::Toggle(1));
        let texts = render(&pane);
        assert!(
            texts.iter().any(|s| s == "Sign in to app.uniswap.org"),
            "{texts:?}"
        );
        assert!(texts.iter().any(|s| s == "Nonce: 42"), "{texts:?}");
        assert!(
            texts.iter().any(|s| s == "ERC-8213 fingerprints"),
            "{texts:?}"
        );
        assert!(
            texts
                .iter()
                .any(|s| s == crate::sign::digest::EIP191_DIGEST_LABEL),
            "{texts:?}"
        );
        assert!(
            texts.iter().any(|s| s.starts_with("Signed 2023-")),
            "{texts:?}"
        );
        assert!(texts.iter().any(|s| s == "Copy"), "{texts:?}");
        let copied = pane.update(Message::CopySignature(1)).1;
        assert!(
            matches!(&copied, Some(Outcome::CopyText(s)) if s.starts_with("0xabab") && s.len() == 132)
        );

        // The undelivered one: no signature to see or copy.
        pane.update(Message::Toggle(1));
        pane.update(Message::Toggle(2));
        let texts = render(&pane);
        assert!(
            texts
                .iter()
                .any(|s| s == "Signature not kept — it never reached the dapp."),
            "{texts:?}"
        );
        assert!(!texts.iter().any(|s| s == "Copy"), "{texts:?}");
        assert!(pane.update(Message::CopySignature(2)).1.is_none());
    }

    /// An answer still on its way says where its signature is — kept, encrypted, so Kao can send
    /// it again after a restart — not that it was dropped; and the fingerprint line says whose
    /// length it states: the signature's, not what was signed.
    #[test]
    fn an_unconfirmed_signature_says_kao_keeps_it_until_the_dapp_gets_it() {
        let mut r = record(1, SignedKind::Message, Delivery::Sending);
        r.signature = None;
        let mut pane = SignedMessagesPane::new(vec![r], Unreadable::default());
        pane.update(Message::Toggle(1));
        let texts = render(&pane);
        assert!(texts.iter().any(|s| s == SENDING_SIGNATURE), "{texts:?}");
        assert!(
            !texts.iter().any(|s| s.starts_with("Signature not kept")),
            "{texts:?}"
        );
        assert!(
            texts
                .iter()
                .any(|s| s == "Signature fingerprint (keccak256 of the 65-byte signature):"),
            "{texts:?}"
        );
        assert!(
            !texts.iter().any(|s| s.contains("bytes signed")),
            "{texts:?}"
        );
    }

    /// A message is shown as the review showed it: text by the review's own rule — a long line
    /// included — and otherwise hex under the reason it isn't text.
    #[test]
    fn a_message_is_text_by_the_reviews_rule_else_hex_under_its_reason() {
        let message = |bytes: Vec<u8>| payload_lines(&SignedPayload::Message { bytes });
        // One 600-char line, as a terms-of-service sign-in often is: the review showed it as text.
        let long = "a ".repeat(300);
        assert!(matches!(
            crate::walletconnect::message::classify(long.as_bytes()),
            MessageShape::Text { .. }
        ));
        let (label, lines) = message(long.clone().into_bytes());
        assert_eq!(label, "Message");
        assert_eq!(lines, vec![long]);

        let (label, lines) = message("pay\u{202e}evil".as_bytes().to_vec());
        assert_eq!(label, "Hidden characters — shown as hex");
        assert!(lines[0].starts_with("70 61 79"), "{lines:?}");
        assert_eq!(
            message(vec![0xff, 0xfe, 0x00, 0x01]).0,
            "Not text — shown as hex"
        );
        assert_eq!(message(vec![0x11; 32]).0, "32-byte hash — shown as hex");
        assert_eq!(
            message("x".repeat(2000).into_bytes()).0,
            "Too long to show as text — shown as hex"
        );

        let long = SignedPayload::TypedData {
            json: format!(
                "{{{}}}",
                (0..400)
                    .map(|i| format!("\"k{i}\":{i}"))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        };
        let (_, lines) = payload_lines(&long);
        assert_eq!(lines.len(), MAX_PAYLOAD_LINES + 1);
        assert!(lines.last().unwrap().starts_with("… "), "{lines:?}");
    }

    /// The unreadable note promises new records are kept only while the vault can save them: a
    /// lost key re-minted says so; one not re-minted yet, or a session that can't save for another
    /// reason, says new ones are gone at the next lock; history the storage couldn't be read for
    /// says it wasn't read.
    #[test]
    fn the_unreadable_note_promises_new_records_only_while_they_are_kept() {
        let lost = Unreadable {
            key_lost: true,
            ..Default::default()
        };
        let kept = unreadable_line(0, lost, true, "record").unwrap();
        assert!(
            kept.ends_with("New ones are kept again from now on."),
            "{kept}"
        );
        let not_yet = unreadable_line(0, lost, false, "record").unwrap();
        assert!(!not_yet.contains("kept again"), "{not_yet}");
        assert!(
            not_yet.contains("gone when Kao locks or quits"),
            "{not_yet}"
        );

        let unavailable = Unreadable {
            key_unavailable: true,
            ..Default::default()
        };
        let line = unreadable_line(0, unavailable, false, "record").unwrap();
        assert_eq!(line, KEY_UNAVAILABLE_NOTE);
        assert!(!line.contains("kept again"), "{line}");

        let keyless = unreadable_line(0, Unreadable::default(), false, "record").unwrap();
        assert!(keyless.contains("can't keep new records"), "{keyless}");
        assert_eq!(
            unreadable_line(0, Unreadable::default(), true, "record"),
            None
        );

        // Through the pane.
        let mut pane = SignedMessagesPane::new(Vec::new(), lost);
        pane.set_can_persist(false);
        assert!(render(&pane).iter().any(|s| s == &not_yet));
        pane.set_can_persist(true);
        assert!(render(&pane).iter().any(|s| s == &kept));
    }

    /// Storage the wallet file can't be read from is a lasting fault: the note no longer calls it
    /// a hiccup ("just now"), says new history and connections aren't saved until it's fixed, and
    /// offers the two-step reset — which goes out only once confirmed, and only while the state
    /// still can't be read.
    #[test]
    fn unreadable_storage_says_nothing_is_saved_and_offers_the_reset() {
        let unavailable = Unreadable {
            key_unavailable: true,
            ..Default::default()
        };
        let mut pane = SignedMessagesPane::new(Vec::new(), unavailable);
        pane.set_can_persist(false);
        let texts = render(&pane);
        assert!(texts.iter().any(|s| s == KEY_UNAVAILABLE_NOTE), "{texts:?}");
        assert!(!texts.iter().any(|s| s.contains("just now")), "{texts:?}");
        assert!(KEY_UNAVAILABLE_NOTE.contains("aren't saved"));
        assert!(KEY_UNAVAILABLE_NOTE.contains("WalletConnect connections"));
        // Wallet saves don't depend on the saved history, so the note promises nothing about them.
        assert!(
            !KEY_UNAVAILABLE_NOTE.contains("wallet may not"),
            "{KEY_UNAVAILABLE_NOTE}"
        );
        assert!(texts.iter().any(|s| s == RESET_LABEL), "{texts:?}");
        assert!(texts.iter().any(|s| s == NONE_SHOWN), "{texts:?}");
        assert!(
            !texts.iter().any(|s| s == "Nothing signed yet."),
            "{texts:?}"
        );

        assert!(pane.update(Message::ConfirmReset).1.is_none(), "unstaged");
        let clicked = super::super::test_support::click_text(pane.view(theme()), RESET_LABEL);
        assert!(
            matches!(clicked.as_slice(), [Message::AskReset]),
            "{clicked:?}"
        );
        pane.update(Message::AskReset);
        let texts = render(&pane);
        assert!(texts.iter().any(|s| s == RESET_CONFIRM), "{texts:?}");
        assert!(
            texts.iter().any(|s| s.contains("aren't told")),
            "says the dapps aren't told: {texts:?}"
        );
        assert!(texts.iter().any(|s| s == RESET_CONFIRM_DETAIL), "{texts:?}");
        assert!(
            RESET_CONFIRM_DETAIL.contains("Your accounts, Safes and contacts stay.")
                && RESET_CONFIRM_DETAIL.contains("saves new history and connections again"),
            "{RESET_CONFIRM_DETAIL}"
        );
        pane.update(Message::CancelReset);
        assert!(pane.update(Message::ConfirmReset).1.is_none());
        pane.update(Message::AskReset);
        assert!(matches!(
            pane.update(Message::ConfirmReset).1,
            Some(Outcome::Reset)
        ));

        // The reset landed: readable again, so neither the note nor the reset shows.
        pane.update(Message::AskReset);
        pane.set_records(Vec::new(), Unreadable::default());
        pane.set_can_persist(true);
        assert!(pane.update(Message::ConfirmReset).1.is_none());
        let texts = render(&pane);
        assert!(!texts.iter().any(|s| s == RESET_LABEL), "{texts:?}");
        assert!(
            texts.iter().any(|s| s == "Nothing signed yet."),
            "{texts:?}"
        );
    }

    /// "Nothing signed yet." only when there's truly nothing: with rows Kao couldn't read (or their
    /// key gone), the list says nothing can be shown instead. Unreadable rows can be cleared on
    /// their own, and the confirm counts them.
    #[test]
    fn unreadable_rows_are_not_nothing_and_can_be_cleared() {
        let three_unread = Unreadable {
            signed: 3,
            ..Default::default()
        };
        let mut pane = SignedMessagesPane::new(Vec::new(), three_unread);
        let texts = render(&pane);
        assert!(texts.iter().any(|s| s == NONE_SHOWN), "{texts:?}");
        assert!(
            !texts.iter().any(|s| s == "Nothing signed yet."),
            "{texts:?}"
        );
        assert!(texts.iter().any(|s| s == "Clear history"), "{texts:?}");
        pane.update(Message::AskClear);
        let texts = render(&pane);
        assert!(
            texts
                .iter()
                .any(|s| s == "Remove the 3 signed-message records Kao couldn't read?"),
            "{texts:?}"
        );
        assert!(matches!(
            pane.update(Message::ConfirmClear).1,
            Some(Outcome::Clear)
        ));

        // Readable and unreadable together: the count covers both.
        let mut pane = SignedMessagesPane::new(
            vec![record(1, SignedKind::Message, Delivery::Delivered)],
            Unreadable {
                signed: 2,
                ..Default::default()
            },
        );
        pane.update(Message::AskClear);
        let texts = render(&pane);
        assert!(
            texts.iter().any(|s| s
                == "Remove all 3 signed-message records from Kao, including 2 it couldn't read?"),
            "{texts:?}"
        );

        // A lost key hides older records too, but leaves no row to clear.
        let mut pane = SignedMessagesPane::new(
            Vec::new(),
            Unreadable {
                key_lost: true,
                ..Default::default()
            },
        );
        let texts = render(&pane);
        assert!(texts.iter().any(|s| s == NONE_SHOWN), "{texts:?}");
        assert!(!texts.iter().any(|s| s == "Clear history"), "{texts:?}");
        pane.update(Message::AskClear);
        assert!(pane.update(Message::ConfirmClear).1.is_none());
    }

    #[test]
    fn clear_is_two_step_and_only_with_records() {
        let mut pane = SignedMessagesPane::new(
            vec![record(1, SignedKind::Message, Delivery::Delivered)],
            Unreadable::default(),
        );
        assert!(pane.update(Message::ConfirmClear).1.is_none(), "not staged");
        pane.update(Message::AskClear);
        let texts = render(&pane);
        // One record is "this" one, never "all 1".
        assert!(
            texts
                .iter()
                .any(|s| s == "Remove this signed-message record from Kao?"),
            "{texts:?}"
        );
        assert!(!texts.iter().any(|s| s.contains("all 1")), "{texts:?}");
        let mut two = SignedMessagesPane::new(
            vec![
                record(1, SignedKind::Message, Delivery::Delivered),
                record(2, SignedKind::Message, Delivery::Delivered),
            ],
            Unreadable::default(),
        );
        two.update(Message::AskClear);
        assert!(
            render(&two)
                .iter()
                .any(|s| s == "Remove all 2 signed-message records from Kao?"),
            "{:?}",
            render(&two)
        );
        pane.update(Message::CancelClear);
        assert!(pane.update(Message::ConfirmClear).1.is_none());
        pane.update(Message::AskClear);
        assert!(matches!(
            pane.update(Message::ConfirmClear).1,
            Some(Outcome::Clear)
        ));
        // The vault emptied: nothing to stage any more.
        pane.set_records(Vec::new(), Unreadable::default());
        pane.update(Message::AskClear);
        assert!(pane.update(Message::ConfirmClear).1.is_none());
        let texts = render(&pane);
        assert!(
            texts.iter().any(|s| s == "Nothing signed yet."),
            "{texts:?}"
        );
        assert!(!texts.iter().any(|s| s == "Clear history"), "{texts:?}");
    }

    #[test]
    fn pages_of_fifty_and_unreadable_notes() {
        let records: Vec<_> = (0..(PAGE as u64 + 3))
            .rev()
            .map(|id| record(id, SignedKind::Message, Delivery::Delivered))
            .collect();
        let mut pane = SignedMessagesPane::new(
            records,
            Unreadable {
                signed: 2,
                ..Default::default()
            },
        );
        let count = |p: &SignedMessagesPane| render(p).iter().filter(|s| *s == "Message").count();
        assert_eq!(count(&pane), PAGE);
        let texts_now = render(&pane);
        assert!(texts_now.iter().any(|s| s == "Show more"));
        assert!(
            texts_now
                .iter()
                .any(|s| s == "2 signed-message records couldn't be read and aren't shown."),
            "{texts_now:?}"
        );
        pane.update(Message::ShowMore);
        assert_eq!(count(&pane), PAGE + 3);
        assert!(!render(&pane).iter().any(|s| s == "Show more"));
    }

    #[test]
    fn debug_never_prints_what_was_signed() {
        let pane = SignedMessagesPane::new(
            vec![record(1, SignedKind::Message, Delivery::Delivered)],
            Unreadable::default(),
        );
        let dbg = format!(
            "{pane:?} {:?} {:?}",
            Message::CopySignature(1),
            Outcome::CopyText("0xabab".into())
        );
        assert!(!dbg.contains("Sign in") && !dbg.contains("abab"), "{dbg}");
    }
}
