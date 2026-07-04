use std::fmt;
use std::sync::Arc;

use alloy::primitives::Address;
use iced::border::Radius;
use iced::keyboard;
use iced::widget::{Space, column, container, row, scrollable, text};
use iced::{Alignment, Background, Border, Element, Length, Padding, Subscription, Task};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::net::BalanceFetcher;
use crate::settings;
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    auth_background, auth_card, avatar, black, bold, error_text, hint_pill, kao_hero,
    kao_scrollable_style, link_button, mono, mono_bold, screen_subtitle, screen_title,
    secondary_button, vspace,
};
use crate::wallet::{self, HdParentKey};

const PAGE_SIZE: u32 = 5;

#[derive(Clone)]
pub struct DerivedAccount {
    hd_index: u32,
    address: Address,
    key_bytes: Zeroizing<[u8; 32]>,
}

// Manual Debug: `key_bytes` is a freshly derived private key whose
// `Zeroizing` Debug would print the raw bytes — redacted.
impl fmt::Debug for DerivedAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedAccount")
            .field("hd_index", &self.hd_index)
            .field("address", &self.address)
            .field("key_bytes", &format_args!("<redacted>"))
            .finish()
    }
}

#[derive(Clone)]
pub enum Message {
    Select(u32),
    LoadMore,
    BackPressed,
    BalanceFetched {
        hd_index: u32,
        balance: Result<String, String>,
    },
    InitialReady(Result<(HdParentKey, Vec<DerivedAccount>), String>),
    MoreReady(Result<Vec<DerivedAccount>, String>),
    KeyboardEvent(keyboard::Event),
}

// Manual Debug: `InitialReady` carries the HD parent key, whose Debug
// prints the BIP32 chain code — redacted. `KeyboardEvent` can carry
// trailing phrase keystrokes from the previous screen, so character keys
// are redacted too; everything else mirrors the derived output.
impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::Select(i) => f.debug_tuple("Select").field(i).finish(),
            Message::LoadMore => f.write_str("LoadMore"),
            Message::BackPressed => f.write_str("BackPressed"),
            Message::BalanceFetched { hd_index, balance } => f
                .debug_struct("BalanceFetched")
                .field("hd_index", hd_index)
                .field("balance", balance)
                .finish(),
            Message::InitialReady(Ok((_parent, accounts))) => f
                .debug_tuple("InitialReady")
                .field(&format_args!("Ok(<parent key redacted>, {accounts:?})"))
                .finish(),
            Message::InitialReady(Err(e)) => f
                .debug_tuple("InitialReady")
                .field(&format_args!("Err({e:?})"))
                .finish(),
            Message::MoreReady(r) => f.debug_tuple("MoreReady").field(r).finish(),
            Message::KeyboardEvent(e) => {
                f.write_str("KeyboardEvent(")?;
                match e {
                    keyboard::Event::KeyPressed {
                        key: keyboard::Key::Named(n),
                        ..
                    } => write!(f, "KeyPressed({n:?})")?,
                    keyboard::Event::KeyPressed { .. } => f.write_str("KeyPressed(<redacted>)")?,
                    keyboard::Event::KeyReleased {
                        key: keyboard::Key::Named(n),
                        ..
                    } => write!(f, "KeyReleased({n:?})")?,
                    keyboard::Event::KeyReleased { .. } => {
                        f.write_str("KeyReleased(<redacted>)")?
                    }
                    keyboard::Event::ModifiersChanged(m) => write!(f, "ModifiersChanged({m:?})")?,
                }
                f.write_str(")")
            }
        }
    }
}

/// Outcome signals emitted by this screen to its parent.
#[derive(Debug, Clone)]
pub enum Outcome {
    Selected {
        key_bytes: Zeroizing<[u8; 32]>,
    },
    /// Navigate back to ImportSeedPhrase with the phrase pre-filled.
    Back {
        phrase: SecretString,
    },
}

impl Outcome {
    /// Variant name for the GUI state trace — never the payload, which
    /// carries the selected key bytes or the seed phrase.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Selected { .. } => "Selected",
            Outcome::Back { .. } => "Back",
        }
    }
}

#[derive(Debug)]
struct HdAccount {
    hd_index: u32,
    address: Address,
    key_bytes: Zeroizing<[u8; 32]>,
    balance: Option<Result<String, String>>,
    fetching: bool,
}

#[derive(Debug)]
pub struct SelectHdAccountScreen {
    phrase: SecretString,
    parent_key: Option<HdParentKey>,
    accounts: Vec<HdAccount>,
    /// Addresses already in the wallet. Derived accounts whose address
    /// matches one of these are silently skipped from the displayed list so
    /// the user can't add a duplicate.
    skip: Vec<Address>,
    next_index: u32,
    deriving: bool,
    error: Option<String>,
    network: Arc<dyn BalanceFetcher>,
}

impl SelectHdAccountScreen {
    /// Create the screen in a "deriving…" state and a task that produces the
    /// BIP32 parent key plus the first page of accounts off the UI thread.
    /// `skip` lists addresses already in the wallet — derived accounts that
    /// match one of those addresses are not shown.
    pub fn new(
        phrase: SecretString,
        skip: Vec<Address>,
        network: Arc<dyn BalanceFetcher>,
    ) -> (Self, Task<Message>) {
        let task = derive_initial_task(phrase.clone());
        let screen = Self {
            phrase,
            parent_key: None,
            accounts: Vec::new(),
            skip,
            next_index: 0,
            deriving: true,
            error: None,
            network,
        };
        (screen, task)
    }

    fn fetch_balance_tasks(&mut self) -> Task<Message> {
        let tasks: Vec<Task<Message>> = self
            .accounts
            .iter_mut()
            .filter(|a| !a.fetching && a.balance.is_none())
            .map(|a| {
                a.fetching = true;
                let address = a.address;
                let hd_index = a.hd_index;
                let network = self.network.clone();
                Task::perform(
                    async move { network.balance(address, crate::chain::Chain::Mainnet).await },
                    move |balance| Message::BalanceFetched { hd_index, balance },
                )
            })
            .collect();
        Task::batch(tasks)
    }

    pub fn update(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("select_hd", &message);
        let busy_before = self.deriving;
        let accounts_before = self.accounts.len();
        let (task, outcome) = self.update_inner(message);
        if busy_before != self.deriving {
            crate::trace::state("select_hd", "busy", busy_before, self.deriving);
        }
        if accounts_before != self.accounts.len() {
            crate::trace::state(
                "select_hd",
                "accounts",
                accounts_before,
                self.accounts.len(),
            );
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("select_hd", o.name());
        }
        (task, outcome)
    }

    fn update_inner(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        match message {
            Message::Select(hd_index) => {
                let outcome = self
                    .accounts
                    .iter()
                    .find(|a| a.hd_index == hd_index)
                    .map(|a| Outcome::Selected {
                        key_bytes: a.key_bytes.clone(),
                    });
                (Task::none(), outcome)
            }
            Message::LoadMore => {
                if self.deriving {
                    return (Task::none(), None);
                }
                let Some(parent) = self.parent_key.clone() else {
                    return (Task::none(), None);
                };
                let start = self.next_index;
                self.deriving = true;
                let task = Task::perform(
                    async move { derive_more(&parent, start) },
                    Message::MoreReady,
                );
                (task, None)
            }
            Message::BackPressed => (
                Task::none(),
                Some(Outcome::Back {
                    phrase: self.phrase.clone(),
                }),
            ),
            Message::BalanceFetched { hd_index, balance } => {
                if let Some(a) = self.accounts.iter_mut().find(|a| a.hd_index == hd_index) {
                    a.fetching = false;
                    a.balance = Some(balance);
                }
                (Task::none(), None)
            }
            Message::InitialReady(Ok((parent, derived))) => {
                self.parent_key = Some(parent);
                self.accounts = derived
                    .into_iter()
                    .filter(|d| !self.skip.contains(&d.address))
                    .map(into_hd_account)
                    .collect();
                self.next_index = PAGE_SIZE;
                self.deriving = false;
                let tasks = self.fetch_balance_tasks();
                (tasks, None)
            }
            Message::InitialReady(Err(e)) => {
                self.deriving = false;
                self.error = Some(e);
                (Task::none(), None)
            }
            Message::MoreReady(Ok(derived)) => {
                self.deriving = false;
                let added = derived.len() as u32;
                self.accounts.extend(
                    derived
                        .into_iter()
                        .filter(|d| !self.skip.contains(&d.address))
                        .map(into_hd_account),
                );
                self.next_index += added;
                let tasks = self.fetch_balance_tasks();
                (tasks, None)
            }
            Message::MoreReady(Err(e)) => {
                self.deriving = false;
                self.error = Some(e);
                (Task::none(), None)
            }
            Message::KeyboardEvent(keyboard::Event::KeyPressed { key, .. }) => match key {
                keyboard::Key::Named(keyboard::key::Named::Escape) => (
                    Task::none(),
                    Some(Outcome::Back {
                        phrase: self.phrase.clone(),
                    }),
                ),
                _ => (Task::none(), None),
            },
            Message::KeyboardEvent(_) => (Task::none(), None),
        }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        keyboard::listen().map(Message::KeyboardEvent)
    }

    pub fn view(&self) -> Element<'_, Message> {
        let t = KaoTheme::for_kind(settings::theme());

        let header = row![
            text("#")
                .size(11)
                .color(t.sub)
                .font(bold())
                .width(Length::Fixed(28.0)),
            text("Address")
                .size(11)
                .color(t.sub)
                .font(bold())
                .width(Length::Fill),
            text("Balance")
                .size(11)
                .color(t.sub)
                .font(bold())
                .width(Length::Fixed(110.0)),
            Space::new().width(80),
        ]
        .padding(Padding::from([0, 14]))
        .spacing(8);

        let body: Element<'_, Message> = if self.accounts.is_empty() {
            container(
                text("Deriving accounts…")
                    .size(13)
                    .color(t.sub)
                    .font(mono()),
            )
            .padding(Padding::from([24, 14]))
            .width(Length::Fill)
            .center_x(Length::Fill)
            .into()
        } else {
            let mut account_rows = column![].spacing(6);
            for account in &self.accounts {
                account_rows = account_rows.push(self.account_row(t, account));
            }
            scrollable(account_rows)
                .height(Length::Fixed(260.0))
                .style(move |_, s| kao_scrollable_style(t, s))
                .into()
        };

        let load_more_btn = secondary_button(t, "Load More Accounts");
        let load_more_btn = if self.deriving || self.parent_key.is_none() {
            load_more_btn
        } else {
            load_more_btn.on_press(Message::LoadMore)
        };
        let load_more = container(load_more_btn).width(Length::Fill);

        let hint = container(
            row![
                hint_pill(t, "Esc"),
                Space::new().width(6),
                text("to go back").size(11).color(t.sub),
            ]
            .align_y(Alignment::Center),
        )
        .width(Length::Fill)
        .center_x(Length::Fill);

        let mut content = column![
            kao_hero(t, "(￣ω￣)", 52.0),
            vspace(10),
            screen_title(t, "Select an Account"),
            vspace(6),
            screen_subtitle(t, "Pick which HD account to import (m/44'/60'/0'/0/N)."),
            vspace(20),
            header,
            vspace(4),
            body,
            vspace(12),
            load_more,
            vspace(14),
            hint,
        ]
        .width(Length::Fill)
        .align_x(Alignment::Center);

        if let Some(e) = &self.error {
            content = content.push(vspace(10)).push(error_text(t, e));
        }

        let card = auth_card(t, 560.0, content.into());

        let back_bar = container(link_button(t, "← Back").on_press(Message::BackPressed))
            .padding(Padding::from([12, 14]))
            .width(Length::Fill);

        let layout = column![back_bar, card]
            .width(Length::Fill)
            .height(Length::Fill);

        auth_background(t, layout.into())
    }

    fn account_row<'a>(&self, t: KaoTheme, account: &'a HdAccount) -> Element<'a, Message> {
        let addr = format!("{}", account.address);
        let addr_display = if addr.len() >= 12 {
            format!("{}…{}", &addr[..8], &addr[addr.len() - 4..])
        } else {
            addr.clone()
        };
        let balance_display = match &account.balance {
            None => "Loading…".to_string(),
            Some(Ok(eth)) => {
                let short: String = eth.chars().take(4).collect();
                format!("{short} ETH")
            }
            Some(Err(_)) => "—".to_string(),
        };
        let balance_color = match &account.balance {
            Some(Ok(_)) => t.text,
            _ => t.sub,
        };

        let kao = match account.hd_index % 4 {
            0 => "(◕‿◕✿)",
            1 => "( ´ ▽ ` )ﾉ",
            2 => "(￣ω￣)",
            _ => "(˘ᵕ˘)",
        };

        let row_inner = row![
            text(format!("{}", account.hd_index))
                .size(13)
                .color(t.sub)
                .font(mono_bold())
                .width(Length::Fixed(28.0)),
            avatar(t, kao, 32.0, t.ab2),
            Space::new().width(10),
            text(addr_display)
                .size(13)
                .color(t.text)
                .font(mono())
                .width(Length::Fill),
            text(balance_display)
                .size(12)
                .color(balance_color)
                .font(mono_bold())
                .width(Length::Fixed(110.0)),
            select_pill(t).on_press(Message::Select(account.hd_index)),
        ]
        .align_y(Alignment::Center)
        .spacing(8);

        container(row_inner)
            .padding(Padding::from([8, 14]))
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
}

fn select_pill<'a>(t: KaoTheme) -> iced::widget::Button<'a, Message> {
    use iced::widget::button;
    let label_color = iced::Color::WHITE;
    button(
        container(text("Select").size(12).color(label_color).font(black()))
            .padding(Padding::from([4, 12])),
    )
    .style(move |_theme, status| button::Style {
        background: Some(Background::Color(match status {
            button::Status::Hovered | button::Status::Pressed => {
                crate::ui::kao_theme::mix(t.a1, iced::Color::WHITE, 0.10)
            }
            _ => t.a1,
        })),
        text_color: label_color,
        border: Border {
            color: iced::Color::TRANSPARENT,
            width: 0.0,
            radius: Radius::from(10),
        },
        ..button::Style::default()
    })
}

fn into_hd_account(d: DerivedAccount) -> HdAccount {
    HdAccount {
        hd_index: d.hd_index,
        address: d.address,
        key_bytes: d.key_bytes,
        balance: None,
        fetching: false,
    }
}

fn derive_initial_task(phrase: SecretString) -> Task<Message> {
    Task::perform(
        async move {
            let parent =
                wallet::derive_parent_key(phrase.expose_secret()).map_err(|e| e.to_string())?;
            let accounts = derive_more(&parent, 0)?;
            Ok((parent, accounts))
        },
        Message::InitialReady,
    )
}

fn derive_more(parent: &HdParentKey, start: u32) -> Result<Vec<DerivedAccount>, String> {
    let raw = wallet::derive_accounts_from(parent, start, PAGE_SIZE).map_err(|e| e.to_string())?;
    Ok(raw
        .into_iter()
        .map(|(hd_index, signer)| DerivedAccount {
            hd_index,
            address: wallet::signer_address(&signer),
            key_bytes: Zeroizing::new(signer.to_bytes().into()),
        })
        .collect())
}

#[cfg(test)]
#[allow(unused_must_use)]
mod tests {
    use super::*;
    use crate::net::MockFetcher;

    const PHRASE: &str = "test test test test test test test test test test test junk";

    fn secret_phrase() -> SecretString {
        SecretString::new(PHRASE.to_string().into_boxed_str())
    }

    fn dummy_screen() -> SelectHdAccountScreen {
        let net: Arc<dyn BalanceFetcher> = Arc::new(MockFetcher::new());
        let (s, _task) = SelectHdAccountScreen::new(secret_phrase(), vec![], net);
        s
    }

    fn fake_derived(hd_index: u32, marker: u8) -> DerivedAccount {
        DerivedAccount {
            hd_index,
            address: Address::from([marker; 20]),
            key_bytes: Zeroizing::new([marker; 32]),
        }
    }

    fn fake_parent_key() -> HdParentKey {
        wallet::derive_parent_key(PHRASE).expect("parent key")
    }

    #[test]
    fn new_starts_in_deriving_state_with_no_accounts() {
        let s = dummy_screen();
        assert!(s.deriving);
        assert!(s.parent_key.is_none());
        assert!(s.accounts.is_empty());
        assert_eq!(s.next_index, 0);
    }

    #[test]
    fn initial_ready_populates_accounts_and_clears_deriving_flag() {
        let mut s = dummy_screen();
        let derived = (0..5).map(|i| fake_derived(i, (i + 1) as u8)).collect();
        s.update(Message::InitialReady(Ok((fake_parent_key(), derived))));
        assert!(!s.deriving);
        assert_eq!(s.accounts.len(), 5);
        assert_eq!(s.next_index, PAGE_SIZE);
        assert!(s.parent_key.is_some());
    }

    #[test]
    fn initial_ready_filters_addresses_already_in_skip_set() {
        let net: Arc<dyn BalanceFetcher> = Arc::new(MockFetcher::new());
        let skip = vec![Address::from([0x02; 20])];
        let (mut s, _) = SelectHdAccountScreen::new(secret_phrase(), skip, net);
        let derived = vec![
            fake_derived(0, 0x01),
            fake_derived(1, 0x02), // duplicate of skip[0]
            fake_derived(2, 0x03),
        ];
        s.update(Message::InitialReady(Ok((fake_parent_key(), derived))));
        assert_eq!(s.accounts.len(), 2);
        assert_eq!(s.accounts[0].hd_index, 0);
        assert_eq!(s.accounts[1].hd_index, 2);
    }

    #[test]
    fn initial_ready_error_records_message_without_panicking() {
        let mut s = dummy_screen();
        s.update(Message::InitialReady(Err("hd derivation crashed".into())));
        assert!(!s.deriving);
        assert_eq!(s.error.as_deref(), Some("hd derivation crashed"));
        assert!(s.accounts.is_empty());
    }

    #[test]
    fn select_emits_outcome_with_matching_key_bytes() {
        let mut s = dummy_screen();
        let derived = vec![fake_derived(0, 0xab), fake_derived(1, 0xcd)];
        s.update(Message::InitialReady(Ok((fake_parent_key(), derived))));
        let (_, outcome) = s.update(Message::Select(1));
        match outcome {
            Some(Outcome::Selected { key_bytes }) => {
                assert_eq!(*key_bytes, [0xcd; 32]);
            }
            other => panic!("expected Selected, got {other:?}"),
        }
    }

    #[test]
    fn select_unknown_index_returns_no_outcome() {
        let mut s = dummy_screen();
        let (_, outcome) = s.update(Message::Select(999));
        assert!(outcome.is_none());
    }

    #[test]
    fn back_pressed_emits_back_with_phrase_for_repopulation() {
        let mut s = dummy_screen();
        let (_, outcome) = s.update(Message::BackPressed);
        match outcome {
            Some(Outcome::Back { phrase }) => assert_eq!(phrase.expose_secret(), PHRASE),
            other => panic!("expected Back, got {other:?}"),
        }
    }

    #[test]
    fn balance_fetched_updates_account_state() {
        let mut s = dummy_screen();
        s.update(Message::InitialReady(Ok((
            fake_parent_key(),
            vec![fake_derived(0, 0x01)],
        ))));
        s.accounts[0].balance = None;
        s.accounts[0].fetching = true;
        s.update(Message::BalanceFetched {
            hd_index: 0,
            balance: Ok("0.42".into()),
        });
        assert!(!s.accounts[0].fetching);
        assert_eq!(s.accounts[0].balance, Some(Ok("0.42".into())));
    }

    #[test]
    fn more_ready_appends_and_advances_next_index() {
        let mut s = dummy_screen();
        s.update(Message::InitialReady(Ok((
            fake_parent_key(),
            vec![fake_derived(0, 0x01)],
        ))));
        // Simulate LoadMore having flipped the deriving flag.
        s.deriving = true;
        s.update(Message::MoreReady(Ok(vec![
            fake_derived(5, 0x06),
            fake_derived(6, 0x07),
        ])));
        assert!(!s.deriving);
        assert_eq!(s.accounts.len(), 3);
        assert_eq!(s.next_index, PAGE_SIZE + 2);
    }

    #[test]
    fn load_more_is_ignored_while_deriving() {
        let mut s = dummy_screen();
        // s.deriving is true from new(); LoadMore must be a no-op.
        let before_index = s.next_index;
        let (_task, outcome) = s.update(Message::LoadMore);
        assert!(outcome.is_none());
        assert_eq!(s.next_index, before_index);
    }
}
