//! Accounts settings sub-screen — every account in the wallet, with a
//! rename field and a "Remove account" that forgets it in Kao (and, for a
//! Local account, forgets its private key). Reached from
//! Settings → Accounts and from the account dropdown's "Manage accounts".
//! Owned by the dashboard's Settings nav slot, like `safes_settings.rs`.
//!
//! Same shape as the Safes pane: a viewer + intent emitter. It holds a
//! key-free snapshot of the accounts (name, kind, address, and which Safes
//! each one signs for) plus per-row drafts, and emits [`Outcome`]s for the
//! dashboard → App to persist. The result comes back via `set_accounts`,
//! which reseeds only the fields whose stored value changed — so a Save
//! button disabling itself doubles as the "saved" confirmation.
//!
//! Rows and messages are keyed by address, never by position: removing an
//! account shifts every later one down. Outcomes carry both the position
//! the pane saw and the address it belongs to, so the App can re-check that
//! its own list still agrees before it acts.

use alloy::primitives::Address;
use iced::border::Radius;
use iced::widget::{Space, button, column, container, row, text, text_input};
use iced::{Alignment, Background, Border, Color, Element, Length, Padding, Task};

use crate::chain::Chain;
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::{
    avatar, black, bold, card_style, colored_address, ghost_button, kao_scrollable_style,
    kaomoji_for_account, mono, mono_bold, primary_button, small_danger_button,
    small_secondary_button, text_input_style,
};
use crate::wallet::{AccountDescriptor, SafeDescriptor, account_address};

/// Shown in place of an enabled "Remove account" on the wallet's only
/// account — the store refuses to load a wallet without one.
const LAST_ACCOUNT_HINT: &str = "Your wallet needs at least one account.";

/// The line above every card. It must not play removal down: for a Local
/// account it costs the key Kao holds, which each card's confirm spells out.
const PANE_INTRO: &str = "Removing an account doesn't change anything on-chain. For a Local \
                          account Kao also forgets its private key.";

#[derive(Debug, Clone)]
pub enum Message {
    /// No-op published by a copyable address click so the dashboard's "Copied!"
    /// toast animation starts (a click changes no state otherwise). Ignored.
    AddressCopied,
    Back,
    NameChanged(Address, String),
    SaveName(Address),
    /// First click on a card's "Remove account": stages the inline confirm.
    /// Never removes anything by itself.
    RemoveRequested(Address),
    /// Backed out of a staged removal.
    CancelRemove,
    /// The confirm half of the pair — the only path that emits
    /// [`Outcome::Remove`], and only for the account that is staged.
    RemoveConfirmed(Address),
}

#[derive(Debug, Clone)]
pub enum Outcome {
    /// User backed out — coordinator returns to the settings root pane.
    Closed,
    /// Rename the account the pane showed at `index` (`address`). `None`
    /// clears back to the "Account N" default. Already trimmed by the pane.
    Rename {
        index: usize,
        address: Address,
        name: Option<String>,
    },
    /// Forget the account the pane showed at `index` (`address`). The user
    /// has confirmed, and it isn't the wallet's only account.
    Remove { index: usize, address: Address },
}

impl Outcome {
    /// Variant name for the GUI state trace.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Closed => "Closed",
            Outcome::Rename { .. } => "Rename",
            Outcome::Remove { .. } => "Remove",
        }
    }
}

/// What holds an account's key — it decides what removing it costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Local,
    Ledger,
    Trezor,
    ViewOnly,
}

impl Kind {
    fn of(account: &AccountDescriptor) -> Self {
        match account {
            AccountDescriptor::Local { .. } => Kind::Local,
            AccountDescriptor::Ledger { .. } => Kind::Ledger,
            AccountDescriptor::Trezor { .. } => Kind::Trezor,
            AccountDescriptor::ViewOnly { .. } => Kind::ViewOnly,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Kind::Local => "Local",
            Kind::Ledger => "Ledger",
            Kind::Trezor => "Trezor",
            Kind::ViewOnly => "View only",
        }
    }

    /// What removing an account of this kind costs, and the confirm
    /// button's label. Only a `Local` account's key lives in Kao — removing
    /// it makes Kao forget the key, so its confirm says so. "Forget", not
    /// "erase": the save rewrites the wallet file, but redb doesn't scrub
    /// the freed pages, so the old encrypted row can linger on disk until
    /// it's overwritten. The copy promises only what is guaranteed.
    fn removal_terms(self) -> (&'static str, &'static str) {
        match self {
            Kind::Local => (
                "Kao forgets this account's private key. Unless you've backed up \
                 its seed phrase or private key elsewhere, the funds are lost for \
                 good.",
                "Forget key & remove",
            ),
            Kind::Ledger => (
                "The key stays on your Ledger — you can add the account again any time.",
                "Remove",
            ),
            Kind::Trezor => (
                "The key stays on your Trezor — you can add the account again any time.",
                "Remove",
            ),
            Kind::ViewOnly => (
                "Kao only watches this address — you can add it again any time.",
                "Remove",
            ),
        }
    }
}

/// One Safe an account is a linked signer for, as the removal warning
/// lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SignerFor {
    /// "Treasury · Ethereum Mainnet".
    label: String,
    /// Once this account is gone, no other linked account can sign for the
    /// Safe (`SafeDescriptor::signing_links`): the Safe becomes watch-only.
    /// Counts keys that can sign, not links — a view-only account or an
    /// ex-owner left linked doesn't keep it signable.
    last_signer: bool,
}

/// Key-free snapshot of one account — everything its card renders. The
/// pane never holds an `AccountDescriptor`, so no key material lives here.
#[derive(Debug, Clone)]
struct AccountRow {
    name: Option<String>,
    kind: Kind,
    /// `None` only for a `Local` account whose key bytes don't make a key
    /// (never written by Kao); such a row can't be targeted.
    address: Option<Address>,
    signer_for: Vec<SignerFor>,
}

impl AccountRow {
    /// `AccountDescriptor::display_name`'s rule.
    fn display_name(&self, idx: usize) -> String {
        match &self.name {
            Some(n) => n.clone(),
            None => format!("Account {}", idx + 1),
        }
    }
}

fn snapshot(accounts: &[AccountDescriptor], safes: &[SafeDescriptor]) -> Vec<AccountRow> {
    accounts
        .iter()
        .enumerate()
        .map(|(i, account)| {
            let idx = i as u32;
            let signer_for = safes
                .iter()
                .enumerate()
                .filter(|(_, s)| s.linked_signer_indices.contains(&idx))
                .map(|(si, s)| SignerFor {
                    label: format!("{} · {}", s.display_name(si), chain_label(s.chain_id)),
                    last_signer: !s.signing_links(accounts).any(|l| l != idx),
                })
                .collect();
            AccountRow {
                name: account.name().map(str::to_string),
                kind: Kind::of(account),
                address: account_address(account),
                signer_for,
            }
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
struct RowState {
    /// Raw name input — seeded from the stored name ("" when unnamed).
    name_draft: String,
    /// Why the dashboard refused a confirmed removal (e.g. a signature in
    /// flight). Cleared by the next Remove / Cancel.
    remove_error: Option<String>,
}

impl RowState {
    fn seeded(a: &AccountRow) -> Self {
        Self {
            name_draft: a.name.clone().unwrap_or_default(),
            remove_error: None,
        }
    }
}

#[derive(Debug)]
pub struct AccountsPane {
    accounts: Vec<AccountRow>,
    /// Per-row drafts, parallel to `accounts`.
    rows: Vec<RowState>,
    /// The account the dashboard signs with (gets the "Active" chip).
    active_index: usize,
    /// The account whose card is showing the inline "Remove …?" confirm.
    pending_remove: Option<Address>,
}

impl AccountsPane {
    pub fn new(
        accounts: &[AccountDescriptor],
        safes: &[SafeDescriptor],
        active_index: usize,
    ) -> Self {
        let accounts = snapshot(accounts, safes);
        let rows = accounts.iter().map(RowState::seeded).collect();
        Self {
            accounts,
            rows,
            active_index,
            pending_remove: None,
        }
    }

    /// Replace the snapshot (an account was renamed or removed, or the Safes
    /// it signs for changed). Rows follow their account by address, and a
    /// name draft reseeds only when the stored name changed: a just-saved
    /// name shows what persisted, while an unsaved draft on another card
    /// survives. A staged removal survives too, as long as its account is
    /// still listed and isn't the last one.
    pub fn set_accounts(
        &mut self,
        accounts: &[AccountDescriptor],
        safes: &[SafeDescriptor],
        active_index: usize,
    ) {
        let fresh = snapshot(accounts, safes);
        let rows = fresh
            .iter()
            .map(|a| {
                let Some(i) = a.address.and_then(|addr| self.position(addr)) else {
                    return RowState::seeded(a);
                };
                let (old, kept) = (&self.accounts[i], &self.rows[i]);
                RowState {
                    name_draft: if old.name == a.name {
                        kept.name_draft.clone()
                    } else {
                        RowState::seeded(a).name_draft
                    },
                    remove_error: kept.remove_error.clone(),
                }
            })
            .collect();
        self.rows = rows;
        self.accounts = fresh;
        self.active_index = active_index;
        if self
            .pending_remove
            .is_some_and(|a| self.position(a).is_none() || !self.can_remove_any())
        {
            self.pending_remove = None;
        }
    }

    /// The dashboard refused a confirmed removal: say why on that card.
    pub fn refuse_remove(&mut self, address: Address, reason: String) {
        self.pending_remove = None;
        if let Some(i) = self.position(address) {
            self.rows[i].remove_error = Some(reason);
        }
    }

    fn position(&self, address: Address) -> Option<usize> {
        self.accounts
            .iter()
            .position(|a| a.address == Some(address))
    }

    /// The wallet keeps at least one account.
    fn can_remove_any(&self) -> bool {
        self.accounts.len() > 1
    }

    /// Which account takes over as active when the active one at `idx` is
    /// removed — the one that slides into its slot, or the one before it
    /// when it was last (`WalletDescriptor::remove_account`'s rule).
    fn successor_of(&self, idx: usize) -> Option<usize> {
        if idx + 1 < self.accounts.len() {
            Some(idx + 1)
        } else {
            idx.checked_sub(1)
        }
    }

    pub fn update(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("accounts_settings", &msg);
        let errors_before = self.error_rows();
        let confirming_before = self.pending_remove.is_some();
        let (task, outcome) = self.update_inner(msg);
        let errors_after = self.error_rows();
        if errors_before != errors_after {
            crate::trace::state(
                "accounts_settings",
                "error_rows",
                errors_before,
                errors_after,
            );
        }
        let confirming_after = self.pending_remove.is_some();
        if confirming_before != confirming_after {
            crate::trace::state(
                "accounts_settings",
                "confirming_remove",
                confirming_before,
                confirming_after,
            );
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("accounts_settings", o.name());
        }
        (task, outcome)
    }

    /// Count of rows showing a refused removal — with the staged removal,
    /// the pane's only coarse state worth diffing in the GUI trace.
    fn error_rows(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| r.remove_error.is_some())
            .count()
    }

    fn update_inner(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        match msg {
            // Copy-toast kick — the widget already copied + marked the toast.
            Message::AddressCopied => (Task::none(), None),
            Message::Back => (Task::none(), Some(Outcome::Closed)),
            Message::NameChanged(address, s) => {
                if let Some(i) = self.position(address) {
                    self.rows[i].name_draft = s;
                }
                (Task::none(), None)
            }
            Message::SaveName(address) => {
                let Some(i) = self.position(address) else {
                    return (Task::none(), None);
                };
                // `AccountDescriptor::set_name`'s rule, so the draft shows
                // exactly what will persist.
                let trimmed = self.rows[i].name_draft.trim();
                let name = (!trimmed.is_empty()).then(|| trimmed.to_string());
                self.rows[i].name_draft = name.clone().unwrap_or_default();
                if name == self.accounts[i].name {
                    return (Task::none(), None);
                }
                (
                    Task::none(),
                    Some(Outcome::Rename {
                        index: i,
                        address,
                        name,
                    }),
                )
            }
            Message::RemoveRequested(address) => {
                if let Some(i) = self.position(address)
                    && self.can_remove_any()
                {
                    self.rows[i].remove_error = None;
                    self.pending_remove = Some(address);
                }
                (Task::none(), None)
            }
            Message::CancelRemove => {
                if let Some(i) = self.pending_remove.take().and_then(|a| self.position(a)) {
                    self.rows[i].remove_error = None;
                }
                (Task::none(), None)
            }
            Message::RemoveConfirmed(address) => {
                // Only the staged account, only while it's still listed, and
                // never the last one.
                if self.pending_remove != Some(address) || !self.can_remove_any() {
                    return (Task::none(), None);
                }
                let Some(index) = self.position(address) else {
                    return (Task::none(), None);
                };
                self.pending_remove = None;
                (Task::none(), Some(Outcome::Remove { index, address }))
            }
        }
    }

    pub fn view<'a>(&'a self, t: KaoTheme) -> Element<'a, Message> {
        let header = row![
            ghost_button(t, text("← Back").size(12).color(t.sub).font(bold()))
                .padding(Padding::from([4, 8]))
                .on_press(Message::Back),
            Space::new().width(Length::Fill),
            text("Accounts").size(14).color(t.text).font(black()),
            Space::new().width(Length::Fill),
            // Symmetry placeholder so the title centers visually.
            text("    ").size(12),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill);

        let mut body = column![
            header,
            Space::new().height(8),
            container(
                text(PANE_INTRO)
                    .size(11)
                    .color(t.sub)
                    // Two sentences can wrap on a narrow window; keep both
                    // lines centered, not just the block.
                    .align_x(iced::alignment::Horizontal::Center),
            )
            .width(Length::Fill)
            .align_x(iced::alignment::Horizontal::Center),
            Space::new().height(16),
        ]
        .width(Length::Fill);

        for (i, account) in self.accounts.iter().enumerate() {
            body = body
                .push(self.account_card(t, i, account))
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

    fn account_card<'a>(
        &'a self,
        t: KaoTheme,
        i: usize,
        account: &'a AccountRow,
    ) -> Element<'a, Message> {
        let row_state = &self.rows[i];
        let name = account.display_name(i);

        let mut chips = row![].spacing(6).align_y(Alignment::Center);
        if i == self.active_index {
            chips = chips.push(chip("Active", t.a1));
        }
        if !account.signer_for.is_empty() {
            chips = chips.push(chip("Safe signer", t.a2));
        }
        let head = row![
            avatar(t, kaomoji_for_account(i), 32.0, t.ab1),
            Space::new().width(10),
            column![
                text(name.clone()).size(13).color(t.text).font(bold()),
                text(account.kind.label())
                    .size(11)
                    .color(t.sub)
                    .font(mono()),
            ]
            .spacing(0)
            .width(Length::Fill),
            chips,
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill);

        let mut content = column![head, Space::new().height(10)].width(Length::Fill);

        let Some(address) = account.address else {
            content = content.push(
                text(
                    "Kao can't read this account's key, so it can't be renamed or \
                     removed here.",
                )
                .size(11)
                .color(t.down),
            );
            return card(t, content);
        };

        // ── Name ──
        let name_dirty = row_state.name_draft.trim() != account.name.as_deref().unwrap_or("");
        // Placeholder = what a blank name falls back to.
        let name_input = text_input(&format!("Account {}", i + 1), &row_state.name_draft)
            .on_input(move |s| Message::NameChanged(address, s))
            .on_submit(Message::SaveName(address))
            .padding(Padding::from([8, 10]))
            .size(13)
            .style(move |_theme, status| text_input_style(t, status));
        let name_save = primary_button(t, "Save", name_dirty);
        let name_save = if name_dirty {
            name_save.on_press(Message::SaveName(address))
        } else {
            name_save
        };

        content = content
            .push(colored_address(t, address))
            .push(Space::new().height(12))
            .push(text("Name").size(12).color(t.text).font(mono_bold()))
            .push(Space::new().height(4))
            .push(
                row![
                    container(name_input).width(Length::Fill),
                    Space::new().width(8),
                    name_save,
                ]
                .align_y(Alignment::Center),
            );

        // ── Remove ── two-step: the first click only stages this confirm,
        // which takes the trigger's place one line lower (a double-click on
        // "Remove account" lands on the prompt, not on the confirm).
        content = content.push(Space::new().height(12));
        if !self.can_remove_any() {
            content = content.push(
                row![
                    text(LAST_ACCOUNT_HINT).size(11).color(t.sub),
                    Space::new().width(Length::Fill),
                    disabled_danger_button(t, "Remove account"),
                ]
                .align_y(Alignment::Center),
            );
        } else if self.pending_remove == Some(address) {
            content = content.push(self.removal_confirm(t, i, account, &name, address));
        } else {
            content = content.push(
                row![
                    Space::new().width(Length::Fill),
                    small_danger_button(t, "Remove account")
                        .on_press(Message::RemoveRequested(address)),
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

        card(t, content)
    }

    /// The staged "Remove …?" block: what removing this kind of account
    /// costs, what happens to the active identity, and which Safes lose a
    /// signer (naming the ones left watch-only), then Cancel / confirm.
    fn removal_confirm<'a>(
        &'a self,
        t: KaoTheme,
        i: usize,
        account: &'a AccountRow,
        name: &str,
        address: Address,
    ) -> Element<'a, Message> {
        let (consequence, confirm_label) = account.kind.removal_terms();
        // Forgetting a Local key is the one removal that can't be undone by
        // re-adding — say it in the danger color.
        let consequence_color = if account.kind == Kind::Local {
            t.down
        } else {
            t.sub
        };
        let mut block = column![
            text(format!("Remove {name} from Kao?"))
                .size(12)
                .color(t.text)
                .font(bold()),
            Space::new().height(4),
            text(consequence).size(11).color(consequence_color),
        ]
        .width(Length::Fill);

        if i == self.active_index
            && let Some(next) = self.successor_of(i)
        {
            block = block.push(Space::new().height(6)).push(
                text(format!(
                    "You're using it right now — Kao will switch to {}.",
                    self.accounts[next].display_name(next)
                ))
                .size(11)
                .color(t.sub),
            );
        }

        if !account.signer_for.is_empty() {
            block = block.push(Space::new().height(6)).push(
                text("It's a linked signer for:")
                    .size(11)
                    .color(t.text)
                    .font(bold()),
            );
            for safe in &account.signer_for {
                let (note, color) = if safe.last_signer {
                    (
                        "no key in Kao can sign for it after this — it becomes watch-only",
                        t.down,
                    )
                } else {
                    ("your other keys still sign", t.sub)
                };
                block = block.push(
                    text(format!("· {} — {note}", safe.label))
                        .size(11)
                        .color(color),
                );
            }
        }

        block
            .push(Space::new().height(8))
            .push(
                row![
                    Space::new().width(Length::Fill),
                    small_secondary_button(t, "Cancel").on_press(Message::CancelRemove),
                    Space::new().width(8),
                    small_danger_button(t, confirm_label)
                        .on_press(Message::RemoveConfirmed(address)),
                ]
                .align_y(Alignment::Center),
            )
            .into()
    }
}

fn card<'a>(t: KaoTheme, content: iced::widget::Column<'a, Message>) -> Element<'a, Message> {
    container(content)
        .padding(Padding::from([14, 16]))
        .width(Length::Fill)
        .style(move |_| card_style(t))
        .into()
}

/// Small tinted label ("Active", "Safe signer") on a card's header.
fn chip<'a>(label: &'a str, accent: Color) -> Element<'a, Message> {
    container(text(label).size(10).color(accent).font(mono_bold()))
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

/// `small_danger_button`'s shape, faded and inert — the wallet's only
/// account can't be removed, and a red button that ignores clicks would
/// read as broken rather than unavailable.
fn disabled_danger_button<'a>(t: KaoTheme, label: &'a str) -> button::Button<'a, Message> {
    let faded = with_alpha(t.down, 0.4);
    button(text(label).size(11).color(faded).font(bold()))
        .padding(Padding::from([4, 10]))
        .style(move |_theme, _status| button::Style {
            background: Some(Background::Color(t.card_alt)),
            text_color: faded,
            border: Border {
                color: with_alpha(t.down, 0.25),
                width: 1.0,
                radius: Radius::from(8),
            },
            ..button::Style::default()
        })
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
    use crate::wallet::{LedgerHdPath, SafeTrust, SecretKeyBytes, view_only_account};

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    fn watch(byte: u8) -> AccountDescriptor {
        view_only_account(addr(byte))
    }

    fn named(mut a: AccountDescriptor, name: &str) -> AccountDescriptor {
        a.set_name(Some(name.into()));
        a
    }

    fn local(seed: u8) -> AccountDescriptor {
        AccountDescriptor::Local {
            name: None,
            key_bytes: SecretKeyBytes::new([seed; 32]),
        }
    }

    fn ledger(byte: u8) -> AccountDescriptor {
        AccountDescriptor::Ledger {
            name: None,
            path: LedgerHdPath::LedgerLive(0),
            address: [byte; 20],
        }
    }

    /// Safe "Treasury" at `[byte; 20]` owned by `owners`' addresses,
    /// linking `linked`.
    fn safe_linking(
        byte: u8,
        chain_id: u64,
        owners: &[&AccountDescriptor],
        linked: Vec<u32>,
    ) -> SafeDescriptor {
        SafeDescriptor {
            name: Some("Treasury".into()),
            chain_id,
            address: [byte; 20],
            version: "1.4.1".into(),
            trust: SafeTrust::Canonical,
            threshold: 1,
            owners: owners
                .iter()
                .map(|a| account_address(a).unwrap().into_array())
                .collect(),
            modules: Vec::new(),
            guard: None,
            fallback_handler: None,
            module_guard: None,
            linked_signer_indices: linked,
            sibling_chains: Vec::new(),
            cached_at: 0,
            tx_service_url: None,
        }
    }

    fn pane(accounts: &[AccountDescriptor]) -> AccountsPane {
        AccountsPane::new(accounts, &[], 0)
    }

    #[test]
    fn snapshot_reads_kind_address_and_the_safes_each_account_signs_for() {
        let accounts = [local(0x11), ledger(0x22), watch(0x33)];
        let owners = [&accounts[0], &accounts[1]];
        let safes = [
            safe_linking(0x55, 1, &owners, vec![0, 1]),
            safe_linking(0x66, 8453, &owners, vec![1]),
        ];
        let p = AccountsPane::new(&accounts, &safes, 0);
        let kinds: Vec<_> = p.accounts.iter().map(|a| a.kind.label()).collect();
        assert_eq!(kinds, vec!["Local", "Ledger", "View only"]);
        assert_eq!(p.accounts[0].address, account_address(&accounts[0]));
        assert_eq!(p.accounts[1].address, Some(addr(0x22)));

        assert_eq!(
            p.accounts[0].signer_for,
            vec![SignerFor {
                label: "Treasury · Ethereum Mainnet".into(),
                last_signer: false,
            }],
            "account 1 still signs Mainnet"
        );
        assert_eq!(
            p.accounts[1].signer_for,
            vec![
                SignerFor {
                    label: "Treasury · Ethereum Mainnet".into(),
                    last_signer: false,
                },
                SignerFor {
                    label: "Treasury · Base".into(),
                    last_signer: true,
                },
            ]
        );
        assert!(p.accounts[2].signer_for.is_empty());
    }

    #[test]
    fn last_signer_counts_keys_that_can_sign_not_links() {
        // Account 0 = the owners' key; 1 = a view-only watch of a co-owner
        // (the old onboarding linked those); 2 = a Ledger the owners have
        // removed on-chain; 3 = a Ledger that is still an owner.
        let accounts = [local(0x11), watch(0x22), ledger(0x33), ledger(0x44)];
        let (a, v, l) = (&accounts[0], &accounts[1], &accounts[3]);
        let safes = [
            safe_linking(0x55, 1, &[a, v], vec![0, 1]),
            safe_linking(0x66, 1, &[a], vec![0, 2]),
            safe_linking(0x77, 1, &[a, l], vec![0, 3]),
        ];
        let p = AccountsPane::new(&accounts, &safes, 0);
        let last: Vec<bool> = p.accounts[0]
            .signer_for
            .iter()
            .map(|s| s.last_signer)
            .collect();
        assert_eq!(
            last,
            vec![true, true, false],
            "a view-only or ex-owner link left behind can't sign; a co-owner key can"
        );
        // Removing the view-only account leaves the owners' key signing.
        assert!(!p.accounts[1].signer_for[0].last_signer);
        // Removing the ex-owner Ledger costs nothing it could sign.
        assert!(!p.accounts[2].signer_for[0].last_signer);
    }

    #[test]
    fn removal_copy_depends_on_where_the_key_lives() {
        let (local_says, local_confirm) = Kind::Local.removal_terms();
        // Kao forgets the key; it can't promise the bytes left the disk.
        assert!(local_says.contains("forgets"));
        assert!(!local_says.contains("erase"));
        assert!(local_says.contains("lost for good"));
        assert_eq!(local_confirm, "Forget key & remove");
        assert!(!PANE_INTRO.contains("only"), "never plays removal down");
        assert!(PANE_INTRO.contains("Local account Kao also forgets"));
        for kind in [Kind::Ledger, Kind::Trezor] {
            let (says, confirm) = kind.removal_terms();
            assert!(says.contains("stays on your"), "{kind:?}");
            assert_eq!(confirm, "Remove");
        }
        let (watch_says, _) = Kind::ViewOnly.removal_terms();
        assert!(watch_says.contains("add it again"));
    }

    #[test]
    fn save_name_emits_a_trimmed_rename_with_index_and_address() {
        let mut p = pane(&[watch(0x11), named(watch(0x22), "Cold")]);
        assert_eq!(p.rows[1].name_draft, "Cold", "seeded from the name");
        let _ = p.update(Message::NameChanged(addr(0x22), "  Savings ".into()));
        let (_, outcome) = p.update(Message::SaveName(addr(0x22)));
        match outcome {
            Some(Outcome::Rename {
                index,
                address,
                name,
            }) => {
                assert_eq!((index, address), (1, addr(0x22)));
                assert_eq!(name.as_deref(), Some("Savings"));
            }
            other => panic!("expected Rename, got {other:?}"),
        }
        assert_eq!(p.rows[1].name_draft, "Savings", "shows what will persist");
    }

    #[test]
    fn unchanged_name_emits_nothing_and_blank_clears_to_the_default() {
        let mut p = pane(&[named(watch(0x11), "Main"), watch(0x22)]);
        let (_, outcome) = p.update(Message::SaveName(addr(0x11)));
        assert!(outcome.is_none());
        let _ = p.update(Message::NameChanged(addr(0x11), " Main ".into()));
        let (_, outcome) = p.update(Message::SaveName(addr(0x11)));
        assert!(outcome.is_none());
        // An unnamed account's untouched draft is "" — never its "Account 2".
        let (_, outcome) = p.update(Message::SaveName(addr(0x22)));
        assert!(outcome.is_none());

        let _ = p.update(Message::NameChanged(addr(0x11), "   ".into()));
        let (_, outcome) = p.update(Message::SaveName(addr(0x11)));
        assert!(matches!(
            outcome,
            Some(Outcome::Rename {
                index: 0,
                name: None,
                ..
            })
        ));
    }

    #[test]
    fn remove_takes_two_clicks_on_the_same_account() {
        let mut p = pane(&[watch(0x11), watch(0x22), watch(0x33)]);

        // Confirm without a staged removal: nothing.
        let (_, outcome) = p.update(Message::RemoveConfirmed(addr(0x22)));
        assert!(outcome.is_none());

        // First click only stages; a repeat click doesn't escalate.
        for _ in 0..2 {
            let (_, outcome) = p.update(Message::RemoveRequested(addr(0x22)));
            assert!(outcome.is_none());
        }
        assert_eq!(p.pending_remove, Some(addr(0x22)));

        // A confirm for another card doesn't act on the staged one.
        let (_, outcome) = p.update(Message::RemoveConfirmed(addr(0x33)));
        assert!(outcome.is_none());

        let (_, outcome) = p.update(Message::RemoveConfirmed(addr(0x22)));
        match outcome {
            Some(Outcome::Remove { index, address }) => {
                assert_eq!((index, address), (1, addr(0x22)));
            }
            other => panic!("expected Remove, got {other:?}"),
        }
        assert!(p.pending_remove.is_none());
    }

    #[test]
    fn cancel_unstages_the_removal() {
        let mut p = pane(&[watch(0x11), watch(0x22)]);
        let _ = p.update(Message::RemoveRequested(addr(0x22)));
        let _ = p.update(Message::CancelRemove);
        assert!(p.pending_remove.is_none());
        let (_, outcome) = p.update(Message::RemoveConfirmed(addr(0x22)));
        assert!(outcome.is_none());
    }

    #[test]
    fn the_only_account_cannot_be_staged_or_removed() {
        let mut p = pane(&[watch(0x11)]);
        let _ = p.update(Message::RemoveRequested(addr(0x11)));
        assert!(p.pending_remove.is_none());
        let (_, outcome) = p.update(Message::RemoveConfirmed(addr(0x11)));
        assert!(outcome.is_none());

        // Down to one while a removal was staged: the stage drops.
        let mut p = pane(&[watch(0x11), watch(0x22)]);
        let _ = p.update(Message::RemoveRequested(addr(0x11)));
        p.set_accounts(&[watch(0x11)], &[], 0);
        assert!(p.pending_remove.is_none());
    }

    #[test]
    fn unknown_addresses_are_ignored() {
        // A stale message after the list shrank must not panic or emit —
        // nor land on whichever account slid into that slot.
        let mut p = pane(&[watch(0x11), watch(0x22)]);
        let gone = addr(0x99);
        for msg in [
            Message::NameChanged(gone, "x".into()),
            Message::SaveName(gone),
            Message::RemoveRequested(gone),
            Message::RemoveConfirmed(gone),
        ] {
            let (_, outcome) = p.update(msg);
            assert!(outcome.is_none());
        }
        assert!(p.pending_remove.is_none());
        assert!(p.rows.iter().all(|r| r.name_draft.is_empty()));
    }

    #[test]
    fn set_accounts_moves_drafts_with_their_account_and_reseeds_changed_names() {
        let mut p = pane(&[watch(0x11), watch(0x22), watch(0x33)]);
        let _ = p.update(Message::NameChanged(addr(0x33), "Half-typed".into()));
        let _ = p.update(Message::NameChanged(addr(0x22), "Also typed".into()));
        let _ = p.update(Message::RemoveRequested(addr(0x33)));

        // Account 1 was removed; the next one's default name was frozen
        // ("Account 2"), the last one's stayed unnamed.
        p.set_accounts(&[named(watch(0x22), "Account 2"), watch(0x33)], &[], 1);
        assert_eq!(p.rows.len(), 2);
        assert_eq!(p.rows[0].name_draft, "Account 2", "stored name changed");
        assert_eq!(p.rows[1].name_draft, "Half-typed", "draft followed it");
        assert_eq!(p.pending_remove, Some(addr(0x33)), "still listed");
        assert_eq!(p.active_index, 1);

        p.set_accounts(&[named(watch(0x22), "Account 2"), watch(0x44)], &[], 0);
        assert!(p.pending_remove.is_none(), "its account is gone");
        assert_eq!(p.rows[1].name_draft, "", "a new account seeds fresh");
    }

    #[test]
    fn refused_removal_shows_on_its_card_until_the_next_attempt() {
        let mut p = pane(&[watch(0x11), watch(0x22)]);
        let _ = p.update(Message::RemoveRequested(addr(0x22)));
        let _ = p.update(Message::RemoveConfirmed(addr(0x22)));
        p.refuse_remove(addr(0x22), "busy".into());
        assert_eq!(p.rows[1].remove_error.as_deref(), Some("busy"));
        assert!(p.pending_remove.is_none());
        p.set_accounts(&[watch(0x11), watch(0x22)], &[], 0);
        assert_eq!(p.rows[1].remove_error.as_deref(), Some("busy"));
        let _ = p.update(Message::RemoveRequested(addr(0x22)));
        assert!(p.rows[1].remove_error.is_none());
    }

    #[test]
    fn the_active_accounts_successor_is_the_one_that_slides_into_its_slot() {
        let p = pane(&[watch(0x11), watch(0x22), watch(0x33)]);
        assert_eq!(p.successor_of(0), Some(1));
        assert_eq!(p.successor_of(1), Some(2));
        assert_eq!(p.successor_of(2), Some(1), "last → the one before it");
        assert_eq!(pane(&[watch(0x11)]).successor_of(0), None);
    }
}
