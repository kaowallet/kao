//! Safes settings sub-screen — per-Safe configuration that lives
//! outside onboarding. Today that's one knob: which Safe Transaction
//! Service each Safe talks to (the public `api.safe.global` gateway or
//! a self-hosted mirror). Owned by the dashboard's Settings nav slot,
//! like `networks.rs`.
//!
//! The pane is a viewer + intent emitter: it holds a snapshot of the
//! wallet's Safes and per-row drafts, validates through
//! `safe::service::normalize_service_base`, and emits
//! [`Outcome::SetServiceUrl`] for the dashboard → App to persist. The
//! refreshed list comes back via `set_safes`, which reseeds the row —
//! so the Save button disabling itself doubles as the "saved"
//! confirmation.

use iced::widget::{Space, column, container, row, text, text_input};
use iced::{Alignment, Element, Length, Padding, Task};

use crate::chain::Chain;
use crate::safe::service::{DEFAULT_TX_SERVICE_BASE, normalize_service_base};
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    avatar, black, bold, card_style, colored_address, ghost_button, kao_scrollable_style, mono,
    mono_bold, primary_button, text_input_style,
};
use crate::wallet::SafeDescriptor;

#[derive(Debug, Clone)]
pub enum Message {
    /// No-op published by a copyable address click so the dashboard's "Copied!"
    /// toast animation starts (a click changes no state otherwise). Ignored.
    AddressCopied,
    Back,
    UrlChanged(usize, String),
    Save(usize),
}

#[derive(Debug, Clone)]
pub enum Outcome {
    /// User backed out — coordinator returns to the settings root pane.
    Closed,
    /// Persist a new transaction-service base for `wallet.safes[index]`.
    /// `None` clears the override back to the public default. Already
    /// normalized/validated by the pane.
    SetServiceUrl { index: usize, url: Option<String> },
}

impl Outcome {
    /// Variant name for the GUI state trace.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Closed => "Closed",
            Outcome::SetServiceUrl { .. } => "SetServiceUrl",
        }
    }
}

#[derive(Debug, Clone, Default)]
struct RowState {
    /// Raw input — seeded from the stored override ("" for default).
    draft: String,
    error: Option<String>,
}

#[derive(Debug)]
pub struct SafesPane {
    safes: Vec<SafeDescriptor>,
    rows: Vec<RowState>,
}

impl SafesPane {
    pub fn new(safes: Vec<SafeDescriptor>) -> Self {
        let rows = seed_rows(&safes);
        Self { safes, rows }
    }

    /// Replace the snapshot (App pushed `SafesUpdated` — after our own
    /// save or a background refresh) and reseed the drafts so each row
    /// reflects what's actually persisted.
    pub fn set_safes(&mut self, safes: Vec<SafeDescriptor>) {
        self.rows = seed_rows(&safes);
        self.safes = safes;
    }

    pub fn update(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("safes_settings", &msg);
        let errors_before = self.error_rows();
        let (task, outcome) = self.update_inner(msg);
        let errors_after = self.error_rows();
        if errors_before != errors_after {
            crate::trace::state("safes_settings", "error_rows", errors_before, errors_after);
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("safes_settings", o.name());
        }
        (task, outcome)
    }

    /// Count of rows currently showing a validation error — the pane's
    /// only coarse state worth diffing in the GUI trace (no mode enum,
    /// no busy flag).
    fn error_rows(&self) -> usize {
        self.rows.iter().filter(|r| r.error.is_some()).count()
    }

    fn update_inner(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        match msg {
            // Copy-toast kick — the widget already copied + marked the toast.
            Message::AddressCopied => (Task::none(), None),
            Message::Back => (Task::none(), Some(Outcome::Closed)),
            Message::UrlChanged(i, s) => {
                if let Some(r) = self.rows.get_mut(i) {
                    r.draft = s;
                    r.error = None;
                }
                (Task::none(), None)
            }
            Message::Save(i) => {
                let Some(r) = self.rows.get_mut(i) else {
                    return (Task::none(), None);
                };
                match normalize_service_base(&r.draft) {
                    Ok(url) => (Task::none(), Some(Outcome::SetServiceUrl { index: i, url })),
                    Err(e) => {
                        r.error = Some(e);
                        (Task::none(), None)
                    }
                }
            }
        }
    }

    pub fn view<'a>(&'a self, t: KaoTheme) -> Element<'a, Message> {
        let header = row![
            ghost_button(t, text("← Back").size(12).color(t.sub).font(bold()))
                .padding(Padding::from([4, 8]))
                .on_press(Message::Back),
            Space::new().width(Length::Fill),
            text("Safes").size(14).color(t.text).font(black()),
            Space::new().width(Length::Fill),
            // Symmetry placeholder so the title centers visually.
            text("    ").size(12),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill);

        let mut body = column![header, Space::new().height(16)].width(Length::Fill);

        if self.safes.is_empty() {
            body = body.push(
                container(
                    text("No Safes yet — add one from the account menu (´｡• ᵕ •｡`)")
                        .size(13)
                        .color(t.sub),
                )
                .width(Length::Fill)
                .center_x(Length::Fill)
                .padding(Padding::from([24, 0])),
            );
        }

        for (i, safe) in self.safes.iter().enumerate() {
            body = body
                .push(self.safe_card(t, i, safe))
                .push(Space::new().height(10));
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

    fn safe_card<'a>(
        &'a self,
        t: KaoTheme,
        i: usize,
        safe: &'a SafeDescriptor,
    ) -> Element<'a, Message> {
        let row_state = &self.rows[i];
        let stored = safe.tx_service_url.clone().unwrap_or_default();
        let dirty = row_state.draft.trim().trim_end_matches('/') != stored;

        let chain_label = Chain::from_chain_id(safe.chain_id)
            .map(|c| c.display_name().to_string())
            .unwrap_or_else(|| format!("chain {}", safe.chain_id));

        let input = text_input(DEFAULT_TX_SERVICE_BASE, &row_state.draft)
            .on_input(move |s| Message::UrlChanged(i, s))
            .on_submit(Message::Save(i))
            .padding(Padding::from([8, 10]))
            .size(13)
            .font(mono())
            .style(move |_theme, status| text_input_style(t, status));

        let save_btn = primary_button(t, "Save", dirty);
        let save_btn = if dirty {
            save_btn.on_press(Message::Save(i))
        } else {
            save_btn
        };

        let status = if safe.tx_service_url.is_some() {
            text("Custom mirror — co-signers using the public service won't see proposals made here.")
                .size(11)
                .color(t.a2)
        } else {
            text("Default · api.safe.global").size(11).color(t.sub)
        };

        // Hand-rolled `section` shape (kao_widgets::section borrows
        // `&'a str` titles; ours are per-Safe `format!`s).
        let head = row![
            avatar(t, "(◐‿◐)", 32.0, t.ab2),
            Space::new().width(10),
            column![
                text(format!("{} · {chain_label}", safe.display_name(i)))
                    .size(13)
                    .color(t.text)
                    .font(bold()),
                text(
                    "Queue, proposals and confirmations go through this service. It must \
                     serve the /tx-service/{chain} API layout. Blank = public default."
                )
                .size(11)
                .color(t.sub),
            ]
            .spacing(0)
            .width(Length::Fill),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill);

        let mut content = column![
            head,
            Space::new().height(10),
            colored_address(t, safe.address()),
            Space::new().height(10),
            text("Transaction service")
                .size(12)
                .color(t.text)
                .font(mono_bold()),
            Space::new().height(4),
            row![
                container(input).width(Length::Fill),
                Space::new().width(8),
                save_btn,
            ]
            .align_y(Alignment::Center),
            Space::new().height(4),
            status,
        ]
        .width(Length::Fill);
        if let Some(err) = &row_state.error {
            content = content.push(Space::new().height(6)).push(
                text(format!("(╥﹏╥) {err}"))
                    .size(11)
                    .color(t.down)
                    .font(bold()),
            );
        }

        container(content)
            .padding(Padding::from([14, 16]))
            .width(Length::Fill)
            .style(move |_| card_style(t))
            .into()
    }
}

fn seed_rows(safes: &[SafeDescriptor]) -> Vec<RowState> {
    safes
        .iter()
        .map(|s| RowState {
            draft: s.tx_service_url.clone().unwrap_or_default(),
            error: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::SafeTrust;

    fn safe(url: Option<&str>) -> SafeDescriptor {
        SafeDescriptor {
            name: Some("Treasury".into()),
            chain_id: 1,
            address: [0x11; 20],
            version: "1.4.1".into(),
            trust: SafeTrust::Canonical,
            threshold: 2,
            owners: vec![[0xaa; 20]],
            modules: Vec::new(),
            guard: None,
            fallback_handler: None,
            linked_signer_indices: vec![0],
            sibling_chains: Vec::new(),
            cached_at: 0,
            tx_service_url: url.map(str::to_string),
        }
    }

    #[test]
    fn save_emits_normalized_url() {
        let mut p = SafesPane::new(vec![safe(None)]);
        let _ = p.update(Message::UrlChanged(
            0,
            "https://txs.example-dao.org/".into(),
        ));
        let (_, outcome) = p.update(Message::Save(0));
        match outcome {
            Some(Outcome::SetServiceUrl { index: 0, url }) => {
                assert_eq!(url.as_deref(), Some("https://txs.example-dao.org"));
            }
            other => panic!("expected SetServiceUrl, got {other:?}"),
        }
    }

    #[test]
    fn save_blank_clears_override() {
        let mut p = SafesPane::new(vec![safe(Some("https://txs.example-dao.org"))]);
        // Seeded from the stored override.
        assert_eq!(p.rows[0].draft, "https://txs.example-dao.org");
        let _ = p.update(Message::UrlChanged(0, String::new()));
        let (_, outcome) = p.update(Message::Save(0));
        match outcome {
            Some(Outcome::SetServiceUrl { index: 0, url }) => assert!(url.is_none()),
            other => panic!("expected SetServiceUrl, got {other:?}"),
        }
    }

    #[test]
    fn invalid_url_sets_row_error_and_emits_nothing() {
        let mut p = SafesPane::new(vec![safe(None)]);
        let _ = p.update(Message::UrlChanged(0, "http://leaky.example.org".into()));
        let (_, outcome) = p.update(Message::Save(0));
        assert!(outcome.is_none());
        assert!(p.rows[0].error.is_some());
        // Editing clears the error.
        let _ = p.update(Message::UrlChanged(0, "https://ok.example.org".into()));
        assert!(p.rows[0].error.is_none());
    }

    #[test]
    fn out_of_range_indices_are_ignored() {
        // A stale message after the safes list shrank (background
        // refresh while the pane is open) must not panic or emit.
        let mut p = SafesPane::new(vec![safe(None)]);
        let (_, outcome) = p.update(Message::UrlChanged(5, "x".into()));
        assert!(outcome.is_none());
        let (_, outcome) = p.update(Message::Save(5));
        assert!(outcome.is_none());
    }

    #[test]
    fn set_safes_reseeds_drafts() {
        let mut p = SafesPane::new(vec![safe(None)]);
        let _ = p.update(Message::UrlChanged(0, "https://txs.example-dao.org".into()));
        // App round-trip lands the persisted value.
        p.set_safes(vec![safe(Some("https://txs.example-dao.org"))]);
        assert_eq!(p.rows[0].draft, "https://txs.example-dao.org");
        assert!(p.rows[0].error.is_none());
    }
}
