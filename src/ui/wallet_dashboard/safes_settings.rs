//! Safes settings sub-screen — per-Safe configuration that lives
//! outside onboarding: the Safe's name, which Safe Transaction Service
//! it talks to (the public `api.safe.global` gateway or a self-hosted
//! mirror), and removing it from Kao. Owned by the dashboard's Settings
//! nav slot, like `networks.rs`.
//!
//! The pane is a viewer + intent emitter: it holds a snapshot of the
//! wallet's Safes and per-row drafts, validates through
//! `safe::service::normalize_service_base`, and emits [`Outcome`]s for
//! the dashboard → App to persist. The refreshed list comes back via
//! `set_safes`, which reseeds the fields whose stored value changed — so
//! a Save button disabling itself doubles as the "saved" confirmation.
//!
//! Rows, messages and outcomes are keyed by `(address, chain_id)`, never
//! by position: the list can shift under the pane (a removal, a
//! background refresh) between a click and the App acting on it.

use iced::widget::{Space, column, container, row, text, text_input};
use iced::{Alignment, Element, Length, Padding, Task};

use crate::chain::Chain;
use crate::safe::service::{DEFAULT_TX_SERVICE_BASE, normalize_service_base};
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    avatar, black, bold, card_style, colored_address, ghost_button, kao_scrollable_style, mono,
    mono_bold, primary_button, small_danger_button, small_secondary_button, text_input_style,
};
use crate::wallet::{AccountDescriptor, SafeDescriptor, SafeKey};

#[derive(Debug, Clone)]
pub enum Message {
    /// No-op published by a copyable address click so the dashboard's "Copied!"
    /// toast animation starts (a click changes no state otherwise). Ignored.
    AddressCopied,
    Back,
    NameChanged(SafeKey, String),
    SaveName(SafeKey),
    UrlChanged(SafeKey, String),
    SaveUrl(SafeKey),
    /// First click on a card's "Remove": stages the inline confirm. Never
    /// removes anything by itself.
    RemoveRequested(SafeKey),
    /// Backed out of a staged removal.
    CancelRemove,
    /// The confirm half of the pair — the only path that emits
    /// [`Outcome::Remove`], and only for the Safe that is staged.
    RemoveConfirmed(SafeKey),
}

#[derive(Debug, Clone)]
pub enum Outcome {
    /// User backed out — coordinator returns to the settings root pane.
    Closed,
    /// Rename the Safe at `address` on every chain it's saved on. `None`
    /// clears back to the "Safe N" default. Already trimmed by the pane.
    Rename {
        address: [u8; 20],
        name: Option<String>,
    },
    /// Persist a new transaction-service base for the Safe keyed
    /// `(address, chain_id)`. `None` clears the override back to the
    /// public default. Already normalized/validated by the pane.
    SetServiceUrl {
        address: [u8; 20],
        chain_id: u64,
        url: Option<String>,
    },
    /// Forget the Safe keyed `(address, chain_id)` — that deployment only;
    /// the same address on other chains stays. The user has confirmed.
    Remove { address: [u8; 20], chain_id: u64 },
}

impl Outcome {
    /// Variant name for the GUI state trace.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Closed => "Closed",
            Outcome::Rename { .. } => "Rename",
            Outcome::SetServiceUrl { .. } => "SetServiceUrl",
            Outcome::Remove { .. } => "Remove",
        }
    }
}

#[derive(Debug, Clone, Default)]
struct RowState {
    /// Raw name input — seeded from the stored name ("" when unnamed).
    name_draft: String,
    /// Raw service-URL input — seeded from the stored override ("" for
    /// default).
    url_draft: String,
    /// Service-URL validation error.
    error: Option<String>,
    /// Why the dashboard refused a confirmed removal (e.g. a signature in
    /// flight with this Safe). Cleared by the next Remove / Cancel.
    remove_error: Option<String>,
}

impl RowState {
    fn seeded(s: &SafeDescriptor) -> Self {
        Self {
            name_draft: s.name().unwrap_or_default().to_string(),
            url_draft: s.tx_service_url.clone().unwrap_or_default(),
            error: None,
            remove_error: None,
        }
    }
}

#[derive(Debug)]
pub struct SafesPane {
    safes: Vec<SafeDescriptor>,
    /// Per-row drafts, parallel to `safes`.
    rows: Vec<RowState>,
    /// The Safe whose card is showing the inline "Remove …?" confirm.
    pending_remove: Option<SafeKey>,
}

impl SafesPane {
    pub fn new(safes: Vec<SafeDescriptor>) -> Self {
        let rows = safes.iter().map(RowState::seeded).collect();
        Self {
            safes,
            rows,
            pending_remove: None,
        }
    }

    /// Replace the snapshot (App pushed `SafesUpdated` — after a save, a
    /// rename, a removal or a background refresh). Rows follow their Safe
    /// by key, and each field reseeds only when its stored value changed:
    /// a just-saved field shows what persisted, while an unsaved draft in
    /// another field or on another card survives someone else's save.
    pub fn set_safes(&mut self, safes: Vec<SafeDescriptor>) {
        let rows = safes
            .iter()
            .map(|s| {
                let Some(i) = self.position(s.key()) else {
                    return RowState::seeded(s);
                };
                let (old, kept) = (&self.safes[i], &self.rows[i]);
                let fresh = RowState::seeded(s);
                let url_same = old.tx_service_url == s.tx_service_url;
                RowState {
                    name_draft: if old.name == s.name {
                        kept.name_draft.clone()
                    } else {
                        fresh.name_draft
                    },
                    url_draft: if url_same {
                        kept.url_draft.clone()
                    } else {
                        fresh.url_draft
                    },
                    error: if url_same { kept.error.clone() } else { None },
                    remove_error: kept.remove_error.clone(),
                }
            })
            .collect();
        self.rows = rows;
        self.safes = safes;
        if self
            .pending_remove
            .is_some_and(|k| self.position(k).is_none())
        {
            self.pending_remove = None;
        }
    }

    /// The dashboard refused a confirmed removal: say why on that card.
    pub fn refuse_remove(&mut self, key: SafeKey, reason: String) {
        self.pending_remove = None;
        if let Some(i) = self.position(key) {
            self.rows[i].remove_error = Some(reason);
        }
    }

    fn position(&self, key: SafeKey) -> Option<usize> {
        self.safes.iter().position(|s| s.key() == key)
    }

    pub fn update(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("safes_settings", &msg);
        let errors_before = self.error_rows();
        let confirming_before = self.pending_remove.is_some();
        let (task, outcome) = self.update_inner(msg);
        let errors_after = self.error_rows();
        if errors_before != errors_after {
            crate::trace::state("safes_settings", "error_rows", errors_before, errors_after);
        }
        let confirming_after = self.pending_remove.is_some();
        if confirming_before != confirming_after {
            crate::trace::state(
                "safes_settings",
                "confirming_remove",
                confirming_before,
                confirming_after,
            );
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("safes_settings", o.name());
        }
        (task, outcome)
    }

    /// Count of rows currently showing an error (a bad service URL or a
    /// refused removal) — with the staged removal, the pane's only coarse
    /// state worth diffing in the GUI trace.
    fn error_rows(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| r.error.is_some() || r.remove_error.is_some())
            .count()
    }

    fn update_inner(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        match msg {
            // Copy-toast kick — the widget already copied + marked the toast.
            Message::AddressCopied => (Task::none(), None),
            Message::Back => (Task::none(), Some(Outcome::Closed)),
            Message::NameChanged(key, s) => {
                if let Some(i) = self.position(key) {
                    self.rows[i].name_draft = s;
                }
                (Task::none(), None)
            }
            Message::SaveName(key) => {
                let Some(i) = self.position(key) else {
                    return (Task::none(), None);
                };
                // `SafeDescriptor::set_name`'s rule, so the draft shows
                // exactly what will persist.
                let trimmed = self.rows[i].name_draft.trim();
                let name = (!trimmed.is_empty()).then(|| trimmed.to_string());
                self.rows[i].name_draft = name.clone().unwrap_or_default();
                if name.as_deref() == self.safes[i].name() {
                    return (Task::none(), None);
                }
                (
                    Task::none(),
                    Some(Outcome::Rename {
                        address: key.0,
                        name,
                    }),
                )
            }
            Message::UrlChanged(key, s) => {
                if let Some(i) = self.position(key) {
                    self.rows[i].url_draft = s;
                    self.rows[i].error = None;
                }
                (Task::none(), None)
            }
            Message::SaveUrl(key) => {
                let Some(i) = self.position(key) else {
                    return (Task::none(), None);
                };
                let r = &mut self.rows[i];
                match normalize_service_base(&r.url_draft) {
                    Ok(url) => {
                        // Show the normalized form, so a save that changes
                        // nothing on disk still reads as saved.
                        r.url_draft = url.clone().unwrap_or_default();
                        (
                            Task::none(),
                            Some(Outcome::SetServiceUrl {
                                address: key.0,
                                chain_id: key.1,
                                url,
                            }),
                        )
                    }
                    Err(e) => {
                        r.error = Some(e);
                        (Task::none(), None)
                    }
                }
            }
            Message::RemoveRequested(key) => {
                if let Some(i) = self.position(key) {
                    self.rows[i].remove_error = None;
                    self.pending_remove = Some(key);
                }
                (Task::none(), None)
            }
            Message::CancelRemove => {
                if let Some(i) = self.pending_remove.take().and_then(|k| self.position(k)) {
                    self.rows[i].remove_error = None;
                }
                (Task::none(), None)
            }
            Message::RemoveConfirmed(key) => {
                // Only the staged Safe, and only while it's still listed.
                if self.pending_remove != Some(key) || self.position(key).is_none() {
                    return (Task::none(), None);
                }
                self.pending_remove = None;
                (
                    Task::none(),
                    Some(Outcome::Remove {
                        address: key.0,
                        chain_id: key.1,
                    }),
                )
            }
        }
    }

    /// `accounts` is the wallet's account list — only read to tell signing
    /// Safes from watch-only ones by the same rule as the account dropdown
    /// (`SafeDescriptor::has_signing_link`), so both surfaces agree.
    pub fn view<'a>(&'a self, t: KaoTheme, accounts: &[AccountDescriptor]) -> Element<'a, Message> {
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
                .push(self.safe_card(t, i, safe, safe.has_signing_link(accounts)))
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
        can_sign: bool,
    ) -> Element<'a, Message> {
        let key = safe.key();
        let row_state = &self.rows[i];
        let chain = chain_label(safe.chain_id);

        // ── Name ──
        let name_dirty = row_state.name_draft.trim() != safe.name().unwrap_or_default();
        // Placeholder = what a blank name falls back to.
        let name_input = text_input(&format!("Safe {}", i + 1), &row_state.name_draft)
            .on_input(move |s| Message::NameChanged(key, s))
            .on_submit(Message::SaveName(key))
            .padding(Padding::from([8, 10]))
            .size(13)
            .style(move |_theme, status| text_input_style(t, status));
        let name_save = primary_button(t, "Save", name_dirty);
        let name_save = if name_dirty {
            name_save.on_press(Message::SaveName(key))
        } else {
            name_save
        };

        // ── Transaction service ──
        let stored = safe.tx_service_url.clone().unwrap_or_default();
        let url_dirty = row_state.url_draft.trim().trim_end_matches('/') != stored;
        let url_input = text_input(DEFAULT_TX_SERVICE_BASE, &row_state.url_draft)
            .on_input(move |s| Message::UrlChanged(key, s))
            .on_submit(Message::SaveUrl(key))
            .padding(Padding::from([8, 10]))
            .size(13)
            .font(mono())
            .style(move |_theme, status| text_input_style(t, status));
        let url_save = primary_button(t, "Save", url_dirty);
        let url_save = if url_dirty {
            url_save.on_press(Message::SaveUrl(key))
        } else {
            url_save
        };

        let status = if safe.tx_service_url.is_some() {
            text("Custom mirror — co-signers using the public service won't see proposals made here.")
                .size(11)
                .color(t.a2)
        } else {
            text("Default · api.safe.global").size(11).color(t.sub)
        };

        // Watch-only Safes can't be made active, so this pane is the only
        // place they can be renamed — say which kind each card is.
        let total_owners = safe.owners.len().max(safe.linked_signer_indices.len());
        let role = if can_sign {
            format!("Threshold {} of {total_owners}", safe.threshold)
        } else {
            format!(
                "Threshold {} of {total_owners} · watch-only",
                safe.threshold
            )
        };
        // Hand-rolled `section` shape (kao_widgets::section borrows
        // `&'a str` titles; ours are per-Safe `format!`s).
        let head = row![
            avatar(t, "(◐‿◐)", 32.0, t.ab2),
            Space::new().width(10),
            column![
                text(format!("{} · {chain}", safe.display_name(i)))
                    .size(13)
                    .color(t.text)
                    .font(bold()),
                text(role).size(11).color(t.sub),
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
            Space::new().height(12),
            text("Name").size(12).color(t.text).font(mono_bold()),
            Space::new().height(4),
            row![
                container(name_input).width(Length::Fill),
                Space::new().width(8),
                name_save,
            ]
            .align_y(Alignment::Center),
            Space::new().height(4),
            text("Applies to this Safe on every chain")
                .size(11)
                .color(t.sub),
            Space::new().height(12),
            text("Transaction service")
                .size(12)
                .color(t.text)
                .font(mono_bold()),
            text(
                "Queue, proposals and confirmations go through this service. It must \
                 serve the /tx-service/{chain} API layout. Blank = public default."
            )
            .size(11)
            .color(t.sub),
            Space::new().height(4),
            row![
                container(url_input).width(Length::Fill),
                Space::new().width(8),
                url_save,
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

        // ── Remove ── two-step: the first click only stages this confirm,
        // which takes the trigger's place one line lower (a double-click
        // on "Remove" lands on the prompt, not on the confirm).
        content = content.push(Space::new().height(12));
        if self.pending_remove == Some(key) {
            content = content
                .push(
                    text(format!(
                        "Remove {} on {chain} from Kao? Nothing changes on-chain — you can \
                         add it again any time.",
                        safe.display_name(i)
                    ))
                    .size(12)
                    .color(t.text)
                    .font(bold()),
                )
                .push(Space::new().height(8))
                .push(
                    row![
                        Space::new().width(Length::Fill),
                        small_secondary_button(t, "Cancel").on_press(Message::CancelRemove),
                        Space::new().width(8),
                        small_danger_button(t, "Remove").on_press(Message::RemoveConfirmed(key)),
                    ]
                    .align_y(Alignment::Center),
                );
        } else {
            content = content.push(
                row![
                    Space::new().width(Length::Fill),
                    small_danger_button(t, "Remove").on_press(Message::RemoveRequested(key)),
                ]
                .align_y(Alignment::Center),
            );
        }
        if let Some(err) = &row_state.remove_error {
            content = content.push(Space::new().height(6)).push(
                text(format!("(・_・;) {err}"))
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

/// "Ethereum Mainnet" / "Base" / …, or `chain {id}` for an id Kao has no
/// built-in for.
fn chain_label(chain_id: u64) -> String {
    Chain::from_chain_id(chain_id)
        .map(|c| c.display_name().to_string())
        .unwrap_or_else(|| format!("chain {chain_id}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::SafeTrust;

    const KEY: SafeKey = ([0x11; 20], 1);

    fn safe_on(address: [u8; 20], chain_id: u64, url: Option<&str>) -> SafeDescriptor {
        SafeDescriptor {
            name: Some("Treasury".into()),
            chain_id,
            address,
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

    fn safe(url: Option<&str>) -> SafeDescriptor {
        safe_on(KEY.0, KEY.1, url)
    }

    fn renamed(mut s: SafeDescriptor, name: Option<&str>) -> SafeDescriptor {
        s.set_name(name.map(str::to_string));
        s
    }

    #[test]
    fn save_emits_normalized_url() {
        let mut p = SafesPane::new(vec![safe(None)]);
        let _ = p.update(Message::UrlChanged(
            KEY,
            "https://txs.example-dao.org/".into(),
        ));
        let (_, outcome) = p.update(Message::SaveUrl(KEY));
        match outcome {
            Some(Outcome::SetServiceUrl {
                address,
                chain_id: 1,
                url,
            }) => {
                assert_eq!(address, KEY.0);
                assert_eq!(url.as_deref(), Some("https://txs.example-dao.org"));
            }
            other => panic!("expected SetServiceUrl, got {other:?}"),
        }
        assert_eq!(
            p.rows[0].url_draft, "https://txs.example-dao.org",
            "the draft shows what will persist"
        );
    }

    #[test]
    fn save_blank_clears_override() {
        let mut p = SafesPane::new(vec![safe(Some("https://txs.example-dao.org"))]);
        // Seeded from the stored override.
        assert_eq!(p.rows[0].url_draft, "https://txs.example-dao.org");
        let _ = p.update(Message::UrlChanged(KEY, String::new()));
        let (_, outcome) = p.update(Message::SaveUrl(KEY));
        match outcome {
            Some(Outcome::SetServiceUrl { url, .. }) => assert!(url.is_none()),
            other => panic!("expected SetServiceUrl, got {other:?}"),
        }
    }

    #[test]
    fn invalid_url_sets_row_error_and_emits_nothing() {
        let mut p = SafesPane::new(vec![safe(None)]);
        let _ = p.update(Message::UrlChanged(KEY, "http://leaky.example.org".into()));
        let (_, outcome) = p.update(Message::SaveUrl(KEY));
        assert!(outcome.is_none());
        assert!(p.rows[0].error.is_some());
        // Editing clears the error.
        let _ = p.update(Message::UrlChanged(KEY, "https://ok.example.org".into()));
        assert!(p.rows[0].error.is_none());
    }

    #[test]
    fn unknown_keys_are_ignored() {
        // A stale message after the safes list shrank (a removal or a
        // background refresh while the pane is open) must not panic or
        // emit — nor land on whichever Safe slid into that slot.
        let mut p = SafesPane::new(vec![safe(None)]);
        let gone: SafeKey = ([0x99; 20], 1);
        let sibling: SafeKey = (KEY.0, 8453);
        for key in [gone, sibling] {
            for msg in [
                Message::UrlChanged(key, "x".into()),
                Message::SaveUrl(key),
                Message::NameChanged(key, "x".into()),
                Message::SaveName(key),
                Message::RemoveRequested(key),
                Message::RemoveConfirmed(key),
            ] {
                let (_, outcome) = p.update(msg);
                assert!(outcome.is_none());
            }
        }
        assert!(p.pending_remove.is_none());
        assert_eq!(p.rows[0].url_draft, "");
        assert_eq!(p.rows[0].name_draft, "Treasury");
    }

    #[test]
    fn set_safes_reseeds_drafts() {
        let mut p = SafesPane::new(vec![safe(None)]);
        let _ = p.update(Message::UrlChanged(
            KEY,
            "https://txs.example-dao.org".into(),
        ));
        // App round-trip lands the persisted value.
        p.set_safes(vec![safe(Some("https://txs.example-dao.org"))]);
        assert_eq!(p.rows[0].url_draft, "https://txs.example-dao.org");
        assert!(p.rows[0].error.is_none());
    }

    #[test]
    fn save_name_emits_a_trimmed_rename_for_the_address() {
        let mut p = SafesPane::new(vec![safe(None)]);
        assert_eq!(p.rows[0].name_draft, "Treasury", "seeded from the name");
        let _ = p.update(Message::NameChanged(KEY, "  Ops vault ".into()));
        let (_, outcome) = p.update(Message::SaveName(KEY));
        match outcome {
            Some(Outcome::Rename { address, name }) => {
                assert_eq!(address, KEY.0);
                assert_eq!(name.as_deref(), Some("Ops vault"));
            }
            other => panic!("expected Rename, got {other:?}"),
        }
        assert_eq!(p.rows[0].name_draft, "Ops vault");
    }

    #[test]
    fn blank_name_clears_back_to_the_default_and_unchanged_emits_nothing() {
        let mut p = SafesPane::new(vec![safe(None)]);
        // Enter on an untouched (or whitespace-only edited) name: nothing.
        let (_, outcome) = p.update(Message::SaveName(KEY));
        assert!(outcome.is_none());
        let _ = p.update(Message::NameChanged(KEY, " Treasury  ".into()));
        let (_, outcome) = p.update(Message::SaveName(KEY));
        assert!(outcome.is_none());

        let _ = p.update(Message::NameChanged(KEY, "   ".into()));
        let (_, outcome) = p.update(Message::SaveName(KEY));
        assert!(matches!(outcome, Some(Outcome::Rename { name: None, .. })));
    }

    #[test]
    fn set_safes_keeps_unsaved_drafts_of_fields_that_did_not_change() {
        let base: SafeKey = (KEY.0, 8453);
        let other: SafeKey = ([0x22; 20], 1);
        let mut p = SafesPane::new(vec![
            safe(None),
            safe_on(base.0, base.1, None),
            safe_on(other.0, other.1, None),
        ]);
        let _ = p.update(Message::UrlChanged(KEY, "https://half-typed".into()));
        let _ = p.update(Message::NameChanged(other, "Grants".into()));
        let _ = p.update(Message::NameChanged(base, "Old draft".into()));

        // Renaming the address lands on both of its chains; nothing else
        // changed in storage.
        p.set_safes(vec![
            renamed(safe(None), Some("Vault")),
            renamed(safe_on(base.0, base.1, None), Some("Vault")),
            safe_on(other.0, other.1, None),
        ]);
        assert_eq!(p.rows[0].name_draft, "Vault", "stored name changed");
        assert_eq!(p.rows[0].url_draft, "https://half-typed", "url draft kept");
        assert_eq!(p.rows[1].name_draft, "Vault", "sibling follows the rename");
        assert_eq!(p.rows[2].name_draft, "Grants", "other card's draft kept");
    }

    #[test]
    fn set_safes_moves_drafts_with_their_safe_when_the_list_shifts() {
        let other: SafeKey = ([0x22; 20], 1);
        let mut p = SafesPane::new(vec![safe(None), safe_on(other.0, other.1, None)]);
        let _ = p.update(Message::UrlChanged(other, "https://txs.grants.org".into()));
        let _ = p.update(Message::UrlChanged(KEY, "http://leaky.example.org".into()));
        let _ = p.update(Message::SaveUrl(KEY));
        assert!(p.rows[0].error.is_some());

        // The first Safe was removed: the second's draft must not be lost
        // or land on another card.
        p.set_safes(vec![safe_on(other.0, other.1, None)]);
        assert_eq!(p.rows.len(), 1);
        assert_eq!(p.rows[0].url_draft, "https://txs.grants.org");
        assert!(p.rows[0].error.is_none());
    }

    #[test]
    fn remove_takes_two_clicks_on_the_same_safe() {
        let other: SafeKey = ([0x22; 20], 1);
        let mut p = SafesPane::new(vec![safe(None), safe_on(other.0, other.1, None)]);

        // Confirm without a staged removal: nothing.
        let (_, outcome) = p.update(Message::RemoveConfirmed(KEY));
        assert!(outcome.is_none());

        // First click only stages; a repeat click doesn't escalate.
        let (_, outcome) = p.update(Message::RemoveRequested(KEY));
        assert!(outcome.is_none());
        let (_, outcome) = p.update(Message::RemoveRequested(KEY));
        assert!(outcome.is_none());
        assert_eq!(p.pending_remove, Some(KEY));

        // A confirm for a different card doesn't act on the staged one.
        let (_, outcome) = p.update(Message::RemoveConfirmed(other));
        assert!(outcome.is_none());

        let (_, outcome) = p.update(Message::RemoveConfirmed(KEY));
        match outcome {
            Some(Outcome::Remove { address, chain_id }) => assert_eq!((address, chain_id), KEY),
            other => panic!("expected Remove, got {other:?}"),
        }
        assert!(p.pending_remove.is_none());
    }

    #[test]
    fn cancel_unstages_the_removal() {
        let mut p = SafesPane::new(vec![safe(None)]);
        let _ = p.update(Message::RemoveRequested(KEY));
        let _ = p.update(Message::CancelRemove);
        assert!(p.pending_remove.is_none());
        let (_, outcome) = p.update(Message::RemoveConfirmed(KEY));
        assert!(outcome.is_none());
    }

    #[test]
    fn staged_removal_survives_a_refresh_but_not_the_safe_leaving() {
        let mut p = SafesPane::new(vec![safe(None)]);
        let _ = p.update(Message::RemoveRequested(KEY));
        p.set_safes(vec![safe(None)]);
        assert_eq!(p.pending_remove, Some(KEY), "background refresh");
        p.set_safes(Vec::new());
        assert!(p.pending_remove.is_none(), "the Safe is gone");
    }

    #[test]
    fn refused_removal_shows_on_its_card_until_the_next_attempt() {
        let mut p = SafesPane::new(vec![safe(None)]);
        let _ = p.update(Message::RemoveRequested(KEY));
        let _ = p.update(Message::RemoveConfirmed(KEY));
        p.refuse_remove(KEY, "busy".into());
        assert_eq!(p.rows[0].remove_error.as_deref(), Some("busy"));
        assert!(p.pending_remove.is_none());
        let _ = p.update(Message::RemoveRequested(KEY));
        assert!(p.rows[0].remove_error.is_none());
    }
}
