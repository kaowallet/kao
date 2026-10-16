//! Settings → Connection history: every dapp the user connected with WalletConnect, open ones
//! first-class ("Connected now" — or "Waiting to reconnect" while a restore hasn't brought them
//! back yet), newest first, from the vault.
//!
//! A viewer like Settings → Signed messages: seeded from `Vault::connections()`, reseeded whenever
//! the vault's revision moves (`set_records`), and a confirmed "Clear history" goes straight to
//! the vault as [`Outcome::Clear`] — which removes the ended connections only; open ones stay, as
//! the copy says. Messages carry nothing but record ids.
//!
//! Dapp strings are drawn as everywhere: the host in a bordered mono box, the name as its claim.

use std::cmp::Ordering;

use iced::widget::{Space, column, container, row, text};
use iced::{Alignment, Element, Length, Padding, Task};

use super::activity::format_relative;
use super::sign_review::format_iso_utc;
use super::signed_messages_settings::{
    empty_state, nothing_unshown, reset_controls, unreadable_line,
};
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    BadgeKind, black, bold, card_style, ghost_button, kao_scrollable_style, mono, mono_bold,
    mono_box, privacy_badge, small_danger_button, small_secondary_button,
};
use crate::vault::{AckRecord, ConnectionRecord, EndReason, Unreadable};

/// Records listed per page ("Show more" adds another).
pub const PAGE: usize = 50;

const NOTE: &str = "Dapps you connected with WalletConnect, and how each connection ended. Kept \
     encrypted in your wallet.";

#[derive(Debug, Clone)]
pub enum Message {
    Back,
    ShowMore,
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

#[derive(Debug, Clone)]
pub enum Outcome {
    /// Back to the settings root.
    Closed,
    /// The user confirmed clearing every ended connection and unreadable row (open ones stay).
    Clear,
    /// The user confirmed resetting the saved history and connections the wallet file can't read.
    Reset,
}

impl Outcome {
    /// Variant name for the GUI state trace.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Closed => "Closed",
            Outcome::Clear => "Clear",
            Outcome::Reset => "Reset",
        }
    }
}

pub struct ConnectionsPane {
    /// Open connections first (newest first), then ended ones (latest ended first).
    records: Vec<ConnectionRecord>,
    unreadable: Unreadable,
    shown: usize,
    confirm_clear: bool,
    confirm_reset: bool,
    /// Whether the vault saves new records (it has its data key this session).
    can_persist: bool,
    /// Whether saved sessions are being restored (`WcSlot::restore_view` is `Some`): the open
    /// records are then dapps Kao hasn't reconnected yet, not live connections.
    restoring: bool,
}

/// Counts only.
impl std::fmt::Debug for ConnectionsPane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionsPane")
            .field("records", &self.records.len())
            .field("shown", &self.shown)
            .field("confirm_clear", &self.confirm_clear)
            .field("confirm_reset", &self.confirm_reset)
            .field("restoring", &self.restoring)
            .finish()
    }
}

/// Ended connections, the latest ended first (ties: the newer connection first) — the order the
/// WalletConnect pane's PAST CONNECTIONS takes its latest few in, too.
pub(super) fn latest_ended_first(a: &ConnectionRecord, b: &ConnectionRecord) -> Ordering {
    b.ended_at.cmp(&a.ended_at).then(b.id.cmp(&a.id))
}

/// Open first (they are what's live now), newest first; then the ended ones, latest ended first —
/// a long-lived connection that just ended leads them, not where it connected.
fn ordered(mut records: Vec<ConnectionRecord>) -> Vec<ConnectionRecord> {
    records.sort_by(|a, b| match (a.is_open(), b.is_open()) {
        (true, true) => b.id.cmp(&a.id),
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => latest_ended_first(a, b),
    });
    records
}

impl ConnectionsPane {
    pub fn new(records: Vec<ConnectionRecord>, unreadable: Unreadable) -> Self {
        Self {
            records: ordered(records),
            unreadable,
            shown: PAGE,
            confirm_clear: false,
            confirm_reset: false,
            can_persist: true,
            restoring: false,
        }
    }

    /// Whether the vault saves new records: the unreadable note promises they're kept only then.
    pub fn set_can_persist(&mut self, can_persist: bool) {
        self.can_persist = can_persist;
    }

    /// Whether a restore of saved sessions runs or waits: open records then say they wait to
    /// reconnect, as the WalletConnect pane's restore card does — never "Connected now".
    pub fn set_restoring(&mut self, restoring: bool) {
        self.restoring = restoring;
    }

    /// The vault changed. A staged Clear stands only while there is something to clear, a staged
    /// reset only while the saved state still can't be read.
    pub fn set_records(&mut self, records: Vec<ConnectionRecord>, unreadable: Unreadable) {
        self.records = ordered(records);
        self.unreadable = unreadable;
        if self.clearable() == 0 {
            self.confirm_clear = false;
        }
        if !unreadable.key_unavailable {
            self.confirm_reset = false;
        }
    }

    fn ended(&self) -> usize {
        self.records.iter().filter(|r| !r.is_open()).count()
    }

    /// Clear removes the ended connections and every unreadable row
    /// (`Vault::clear_ended_connections`).
    fn clearable(&self) -> usize {
        self.ended() + self.unreadable.connections
    }

    pub fn update(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("connection_history", &msg);
        let confirming_before = self.confirm_clear;
        let resetting_before = self.confirm_reset;
        let (task, outcome) = self.update_inner(msg);
        if confirming_before != self.confirm_clear {
            crate::trace::state(
                "connection_history",
                "confirm_clear",
                confirming_before,
                self.confirm_clear,
            );
        }
        if resetting_before != self.confirm_reset {
            crate::trace::state(
                "connection_history",
                "confirm_reset",
                resetting_before,
                self.confirm_reset,
            );
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("connection_history", o.name());
        }
        (task, outcome)
    }

    fn update_inner(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        match msg {
            Message::Back => {
                self.confirm_clear = false;
                self.confirm_reset = false;
                (Task::none(), Some(Outcome::Closed))
            }
            Message::ShowMore => {
                self.shown = self.shown.saturating_add(PAGE);
                (Task::none(), None)
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
            text("Connection history")
                .size(14)
                .color(t.text)
                .font(black()),
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
            self.unreadable.connections,
            self.unreadable,
            self.can_persist,
            "connection record",
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
                nothing_unshown(self.unreadable.connections, self.unreadable),
                "No connections yet.",
                "Dapps you connect with WalletConnect show up here.",
            ));
        }
        for r in self.records.iter().take(self.shown) {
            body = body
                .push(connection_card(t, r, now, self.restoring))
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

    fn clear_controls(&self, t: KaoTheme) -> Element<'_, Message> {
        let ended = self.ended();
        if self.confirm_clear {
            let open = self.records.len() - ended;
            let unread = self.unreadable.connections;
            let connections = |n: usize| if n == 1 { "connection" } else { "connections" };
            let rows = |n: usize| if n == 1 { "record" } else { "records" };
            let question = if unread == 0 {
                format!("Remove {ended} ended {} from Kao?", connections(ended))
            } else if ended == 0 {
                format!(
                    "Remove the {unread} connection {} Kao couldn't read?",
                    rows(unread)
                )
            } else {
                format!(
                    "Remove {ended} ended {} from Kao, and {unread} {} it couldn't read?",
                    connections(ended),
                    rows(unread)
                )
            };
            let mut col = column![
                text(question).size(12).color(t.down).font(bold()),
                Space::new().height(4),
            ]
            .width(Length::Fill);
            if open > 0 {
                col = col.push(
                    text(format!(
                        "{open} connected {} stay{}.",
                        if open == 1 { "dapp" } else { "dapps" },
                        if open == 1 { "s" } else { "" }
                    ))
                    .size(11)
                    .color(t.sub),
                );
            }
            col.push(
                text(
                    "Kao can't undo this. Encrypted copies can stay inside the wallet file until \
                     its space is reused.",
                )
                .size(11)
                .color(t.sub),
            )
            .push(Space::new().height(8))
            .push(
                row![
                    Space::new().width(Length::Fill),
                    small_secondary_button(t, "Keep").on_press(Message::CancelClear),
                    small_danger_button(t, "Clear").on_press(Message::ConfirmClear),
                ]
                .spacing(6)
                .align_y(Alignment::Center)
                .width(Length::Fill),
            )
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

/// [`format_relative`] inside a sentence: "connected yesterday", "ended yesterday".
fn relative_inline(now: u64, then: u64) -> String {
    let rel = format_relative(now, then);
    if rel == "Yesterday" {
        "yesterday".into()
    } else {
        rel
    }
}

/// Why a connection ended, as a clause inside a history line ("ended 5 min ago — the dapp
/// disconnected"): the record's sentence, lowercased like Kao's other copy after a dash.
fn end_clause(reason: EndReason) -> String {
    let mut chars = reason.sentence().chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_lowercase().chain(chars).collect()
    })
}

/// When and why a connection ended, for its history line: "ended 5 min ago — the dapp
/// disconnected". One that ended while Kao was closed has no time — when it really ended isn't
/// known (Kao found it gone later) — just "ended while Kao was closed".
pub(super) fn ended_phrase(at: u64, end: Option<EndReason>, now: u64) -> String {
    match end {
        Some(EndReason::Lost) => end_clause(EndReason::Lost),
        Some(reason) => format!(
            "ended {} — {}",
            relative_inline(now, at),
            end_clause(reason)
        ),
        None => format!("ended {}", relative_inline(now, at)),
    }
}

/// One connection: the dapp (host boxed, then its claim), the account and networks it was given,
/// and when it connected — and when and why it ended, or that it is connected now (or, while
/// `restoring`, that it waits to reconnect).
fn connection_card<'a>(
    t: KaoTheme,
    r: &'a ConnectionRecord,
    now: u64,
    restoring: bool,
) -> Element<'a, Message> {
    let host = r.dapp.host.as_deref().unwrap_or("unknown site");
    let chains = r
        .chains
        .iter()
        .map(|c| crate::walletconnect::chain_label(*c))
        .collect::<Vec<_>>()
        .join(", ");
    let mut top = row![
        mono_box(
            t,
            text(host.to_string())
                .size(13)
                .color(t.text)
                .font(mono_bold())
                .into()
        ),
        Space::new().width(Length::Fill),
    ]
    .spacing(6)
    .align_y(Alignment::Center)
    .width(Length::Fill);
    if r.is_open() {
        // A restore that runs or waits hasn't reconnected the saved dapps: Kao has no relay
        // connection for them, and they can't reach it.
        top = top.push(if restoring {
            privacy_badge(t, BadgeKind::Caution, "Waiting to reconnect")
        } else {
            privacy_badge(t, BadgeKind::Good, "Connected now")
        });
    }
    let when = match r.ended_at {
        Some(at) => format!(
            "Connected {} · {}",
            format_iso_utc(r.connected_at),
            ended_phrase(at, r.end, now)
        ),
        None => format!("Connected {}", relative_inline(now, r.connected_at)),
    };
    let mut col = column![
        top,
        Space::new().height(4),
        text(format!("calls itself \"{}\"", r.dapp.name))
            .size(12)
            .color(t.sub),
        Space::new().height(4),
        text(format!(
            "as {} · {} · {chains}",
            r.account.label(),
            crate::wallet::short_address(r.account.address())
        ))
        .size(12)
        .color(t.text),
        Space::new().height(4),
        text(when).size(11).color(t.sub).font(mono()),
    ]
    .spacing(0)
    .width(Length::Fill);
    if r.is_open() && r.ack == AckRecord::Unconfirmed {
        col = col.push(Space::new().height(4));
        col = col.push(
            text("The dapp never confirmed this connection.")
                .size(11)
                .color(crate::ui::kao_widgets::caution_color())
                .font(bold()),
        );
    }
    container(col)
        .padding(Padding::from([12, 14]))
        .width(Length::Fill)
        .style(move |_| card_style(t))
        .into()
}

#[cfg(test)]
#[allow(unused_must_use)]
mod tests {
    use super::super::signed_messages_settings::NONE_SHOWN;
    use super::*;
    use crate::ui::kao_theme::ThemeKind;
    use crate::vault::{AccountRef, DappRecord, EndReason};
    use alloy::primitives::Address;

    fn record(id: u64, host: &str, ended: Option<EndReason>) -> ConnectionRecord {
        ConnectionRecord {
            id,
            topic: format!("{id:064}"),
            dapp: DappRecord {
                name: format!("{host} app"),
                host: Some(host.into()),
                url: format!("https://{host}"),
                ..Default::default()
            },
            account: AccountRef::Eoa {
                address: Address::repeat_byte(0x11),
                label: "Account 1".into(),
            },
            chains: vec![1, 8453],
            connected_at: 1_700_000_000,
            ack: AckRecord::Confirmed,
            ended_at: ended.map(|_| 1_700_000_600),
            end: ended,
        }
    }

    fn render(pane: &ConnectionsPane) -> Vec<String> {
        super::super::test_support::texts(pane.view(KaoTheme::for_kind(ThemeKind::Void)))
    }

    #[test]
    fn open_connections_come_first_and_ended_ones_say_why() {
        let pane = ConnectionsPane::new(
            vec![
                record(3, "c.example", Some(EndReason::DappDisconnected)),
                record(2, "b.example", None),
                record(1, "a.example", Some(EndReason::TurnedOff)),
            ],
            Unreadable::default(),
        );
        let texts = render(&pane);
        let pos = |s: &str| texts.iter().position(|x| x == s).unwrap();
        assert!(pos("b.example") < pos("c.example") && pos("c.example") < pos("a.example"));
        assert!(pos("b.example") < pos("calls itself \"b.example app\""));
        assert!(texts.iter().any(|s| s == "✓ Connected now"), "{texts:?}");
        assert!(
            texts.iter().any(|s| s.starts_with("Connected 2023-11-14")
                && s.ends_with(" — the dapp disconnected")),
            "{texts:?}"
        );
        assert!(
            texts
                .iter()
                .any(|s| s.ends_with(" — you turned WalletConnect off")),
            "{texts:?}"
        );
        assert!(
            texts
                .iter()
                .any(|s| s == "as Account 1 · 0x1111…1111 · Ethereum Mainnet, Base"),
            "{texts:?}"
        );
    }

    #[test]
    fn clear_is_two_step_ended_only_and_says_open_ones_stay() {
        let mut pane = ConnectionsPane::new(
            vec![
                record(2, "b.example", None),
                record(1, "a.example", Some(EndReason::Expired)),
            ],
            Unreadable::default(),
        );
        pane.update(Message::AskClear);
        let texts = render(&pane);
        assert!(
            texts
                .iter()
                .any(|s| s == "Remove 1 ended connection from Kao?"),
            "{texts:?}"
        );
        assert!(
            texts.iter().any(|s| s == "1 connected dapp stays."),
            "{texts:?}"
        );
        assert!(matches!(
            pane.update(Message::ConfirmClear).1,
            Some(Outcome::Clear)
        ));
        // Only an open one left: nothing to clear, no button.
        pane.set_records(vec![record(2, "b.example", None)], Unreadable::default());
        pane.update(Message::AskClear);
        assert!(pane.update(Message::ConfirmClear).1.is_none());
        assert!(!render(&pane).iter().any(|s| s == "Clear history"));
    }

    /// "No connections yet." only when there's truly nothing; a row Kao couldn't read is not
    /// nothing — the list says nothing can be shown, and the row can be cleared (the confirm
    /// counts it).
    #[test]
    fn empty_and_unreadable() {
        let pane = ConnectionsPane::new(Vec::new(), Unreadable::default());
        let texts = render(&pane);
        assert!(
            texts.iter().any(|s| s == "No connections yet."),
            "{texts:?}"
        );
        assert!(!texts.iter().any(|s| s == "Clear history"), "{texts:?}");

        let mut pane = ConnectionsPane::new(
            Vec::new(),
            Unreadable {
                connections: 1,
                ..Default::default()
            },
        );
        let texts = render(&pane);
        assert!(texts.iter().any(|s| s == NONE_SHOWN), "{texts:?}");
        assert!(
            !texts.iter().any(|s| s == "No connections yet."),
            "{texts:?}"
        );
        assert!(
            texts
                .iter()
                .any(|s| s == "1 connection record couldn't be read and isn't shown."),
            "{texts:?}"
        );
        assert!(texts.iter().any(|s| s == "Clear history"), "{texts:?}");
        pane.update(Message::AskClear);
        let texts = render(&pane);
        assert!(
            texts
                .iter()
                .any(|s| s == "Remove the 1 connection record Kao couldn't read?"),
            "{texts:?}"
        );
        assert!(matches!(
            pane.update(Message::ConfirmClear).1,
            Some(Outcome::Clear)
        ));
        // Cleared: nothing to stage.
        pane.set_records(Vec::new(), Unreadable::default());
        pane.update(Message::AskClear);
        assert!(pane.update(Message::ConfirmClear).1.is_none());

        // Ended and unreadable together.
        let mut pane = ConnectionsPane::new(
            vec![record(1, "a.example", Some(EndReason::Expired))],
            Unreadable {
                connections: 2,
                ..Default::default()
            },
        );
        pane.update(Message::AskClear);
        let texts = render(&pane);
        assert!(
            texts.iter().any(|s| s
                == "Remove 1 ended connection from Kao, and 2 records it couldn't read?"),
            "{texts:?}"
        );

        // Key trouble hides records without leaving a row to clear.
        for unread in [
            Unreadable {
                key_lost: true,
                ..Default::default()
            },
            Unreadable {
                key_unavailable: true,
                ..Default::default()
            },
        ] {
            let pane = ConnectionsPane::new(Vec::new(), unread);
            let texts = render(&pane);
            assert!(texts.iter().any(|s| s == NONE_SHOWN), "{texts:?}");
            assert!(!texts.iter().any(|s| s == "Clear history"), "{texts:?}");
        }
    }

    /// Ended connections are listed by when they ENDED, latest first, after the open ones: a
    /// long-lived connection the user just disconnected leads them, not where it connected.
    #[test]
    fn ended_connections_list_the_latest_ended_first() {
        let ended_at = |mut r: ConnectionRecord, at: u64| {
            r.ended_at = Some(at);
            r
        };
        // As the vault hands them: newest connection first.
        let pane = ConnectionsPane::new(
            vec![
                ended_at(record(4, "d.example", Some(EndReason::Expired)), 40),
                record(3, "c.example", None),
                ended_at(record(2, "b.example", Some(EndReason::Expired)), 20),
                ended_at(record(1, "a.example", Some(EndReason::YouDisconnected)), 50),
            ],
            Unreadable::default(),
        );
        let texts = render(&pane);
        let pos = |s: &str| texts.iter().position(|x| x == s).unwrap();
        assert!(pos("c.example") < pos("a.example"), "open first: {texts:?}");
        assert!(
            pos("a.example") < pos("d.example") && pos("d.example") < pos("b.example"),
            "latest ended first: {texts:?}"
        );
    }

    /// While the wallet file's saved state can't be read, the pane says so (never "just now") and
    /// offers the two-step reset.
    #[test]
    fn unreadable_storage_offers_the_reset() {
        use super::super::signed_messages_settings::{
            KEY_UNAVAILABLE_NOTE, RESET_CONFIRM, RESET_LABEL,
        };
        let unavailable = Unreadable {
            key_unavailable: true,
            ..Default::default()
        };
        let mut pane = ConnectionsPane::new(Vec::new(), unavailable);
        pane.set_can_persist(false);
        let texts = render(&pane);
        assert!(texts.iter().any(|s| s == KEY_UNAVAILABLE_NOTE), "{texts:?}");
        assert!(texts.iter().any(|s| s == RESET_LABEL), "{texts:?}");
        assert!(pane.update(Message::ConfirmReset).1.is_none(), "unstaged");
        pane.update(Message::AskReset);
        assert!(render(&pane).iter().any(|s| s == RESET_CONFIRM));
        assert!(matches!(
            pane.update(Message::ConfirmReset).1,
            Some(Outcome::Reset)
        ));
        pane.update(Message::AskReset);
        pane.set_records(Vec::new(), Unreadable::default());
        assert!(pane.update(Message::ConfirmReset).1.is_none());
        assert!(!render(&pane).iter().any(|s| s == RESET_LABEL));
    }

    /// While a restore runs or waits, an open record is a saved dapp Kao hasn't reconnected: it
    /// waits to reconnect (a caution, as the restore card says) — never "Connected now", which
    /// comes back once the restore is over. Ended records are unchanged.
    #[test]
    fn open_connections_wait_to_reconnect_while_a_restore_is_pending() {
        let mut pane = ConnectionsPane::new(
            vec![
                record(2, "b.example", None),
                record(1, "a.example", Some(EndReason::DappDisconnected)),
            ],
            Unreadable::default(),
        );
        pane.set_restoring(true);
        let texts = render(&pane);
        assert!(
            texts.iter().any(|s| s == "! Waiting to reconnect"),
            "{texts:?}"
        );
        assert!(
            !texts.iter().any(|s| s.contains("Connected now")),
            "{texts:?}"
        );
        assert_eq!(
            texts
                .iter()
                .filter(|s| s.contains("Waiting to reconnect"))
                .count(),
            1,
            "only the open one: {texts:?}"
        );
        pane.set_restoring(false);
        let texts = render(&pane);
        assert!(texts.iter().any(|s| s == "✓ Connected now"), "{texts:?}");
        assert!(
            !texts.iter().any(|s| s.contains("Waiting to reconnect")),
            "{texts:?}"
        );
    }

    /// A connection found ended at an unlock (`Lost`) says it ended while Kao was closed, with no
    /// relative time (when it really ended isn't known) and no "ended … Ended" echo.
    #[test]
    fn a_connection_lost_while_closed_has_no_relative_end_time() {
        let now = crate::walletconnect::now_secs();
        let mut lost = record(1, "a.example", Some(EndReason::Lost));
        lost.ended_at = Some(now);
        let texts = render(&ConnectionsPane::new(vec![lost], Unreadable::default()));
        assert!(
            texts
                .iter()
                .any(|s| s == "Connected 2023-11-14 22:13 UTC · ended while Kao was closed"),
            "{texts:?}"
        );
        assert!(!texts.iter().any(|s| s.contains("just now")), "{texts:?}");
        assert!(!texts.iter().any(|s| s.contains("Ended")), "{texts:?}");
        assert_eq!(
            ended_phrase(now - 3 * 86_400, Some(EndReason::Lost), now),
            "ended while Kao was closed"
        );
    }

    /// History lines read as sentences: a time inside one is lowercase ("yesterday"), the reason
    /// after the em dash is lowercase like Kao's other copy, and every card's time line starts
    /// "Connected …" — open ones too.
    #[test]
    fn history_lines_read_as_sentences() {
        let now = crate::walletconnect::now_secs();
        let day = 86_400 + 3_600;
        let mut ended = record(2, "b.example", Some(EndReason::YouDisconnected));
        ended.ended_at = Some(now - day);
        let mut open = record(3, "c.example", None);
        open.connected_at = now - day;
        let texts = render(&ConnectionsPane::new(
            vec![open, ended],
            Unreadable::default(),
        ));
        assert!(
            texts
                .iter()
                .any(|s| s.ends_with(" · ended yesterday — you disconnected")),
            "{texts:?}"
        );
        assert!(
            texts.iter().any(|s| s == "Connected yesterday"),
            "{texts:?}"
        );
        assert!(!texts.iter().any(|s| s.contains("Yesterday")), "{texts:?}");
        assert!(
            !texts.iter().any(|s| s.starts_with("connected ")),
            "{texts:?}"
        );
        let mut recent = record(4, "d.example", None);
        recent.connected_at = now - 300;
        let texts = render(&ConnectionsPane::new(vec![recent], Unreadable::default()));
        assert!(
            texts.iter().any(|s| s == "Connected 5 min ago"),
            "{texts:?}"
        );

        // Each reason, as the clause after the dash.
        for (reason, clause) in [
            (EndReason::YouDisconnected, "you disconnected"),
            (EndReason::DappDisconnected, "the dapp disconnected"),
            (EndReason::DappDeclined, "the dapp declined the connection"),
            (EndReason::Expired, "expired"),
            (
                EndReason::AccountRemoved,
                "its account was removed from Kao",
            ),
            (EndReason::TurnedOff, "you turned WalletConnect off"),
            (EndReason::Forgotten, "you told Kao to forget it"),
            (EndReason::RelayChanged, "the relay changed"),
            (EndReason::Lost, "ended while Kao was closed"),
        ] {
            assert_eq!(end_clause(reason), clause);
        }
        assert_eq!(
            ended_phrase(now - 600, Some(EndReason::Expired), now),
            "ended 10 min ago — expired"
        );
        assert_eq!(ended_phrase(now - 600, None, now), "ended 10 min ago");
    }

    /// A session that can't save says new connections aren't kept — not that they are.
    #[test]
    fn a_session_that_cant_save_says_new_records_arent_kept() {
        let mut pane = ConnectionsPane::new(
            Vec::new(),
            Unreadable {
                key_lost: true,
                ..Default::default()
            },
        );
        pane.set_can_persist(false);
        let texts = render(&pane);
        assert!(
            texts
                .iter()
                .any(|s| s.contains("gone when Kao locks or quits") && !s.contains("kept again")),
            "{texts:?}"
        );
        pane.set_can_persist(true);
        let texts = render(&pane);
        assert!(
            texts
                .iter()
                .any(|s| s.ends_with("New ones are kept again from now on.")),
            "{texts:?}"
        );
    }
}
