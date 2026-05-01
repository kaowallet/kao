//! Hardware-wallet connect screen for Trezor devices.
//! Sibling to `connect_ledger.rs` — see that file for the design rationale.

use std::sync::Arc;

use alloy::primitives::Address;
use alloy::signers::Signer;
use alloy::signers::trezor::TrezorSigner;
use iced::border::Radius;
use iced::keyboard;
use iced::widget::{Space, column, container, row, scrollable, text};
use iced::{Alignment, Background, Border, Element, Length, Padding, Subscription, Task};

use crate::net::BalanceFetcher;
use crate::settings;
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    auth_background, auth_card, avatar, black, bold, error_text, hint_pill, kao_hero, link_button,
    mono, mono_bold, primary_button, screen_subtitle, screen_title, vspace,
};
use crate::wallet::{
    AccountDescriptor, CHAIN_ID, KaoSigner, SignerHandoff, TrezorHdPath, handoff_with,
};

const PROBE_COUNT: u32 = 5;

#[derive(Debug, Clone)]
pub enum Message {
    SetupProbed(Result<Vec<(u32, Address)>, String>),
    ReconnectProbed(Result<SignerHandoff, String>),
    BalanceFetched {
        hd_index: u32,
        balance: Result<String, String>,
    },
    Pick(u32),
    SignerBuilt(Result<SignerHandoff, String>),
    Retry,
    BackPressed,
    KeyboardEvent(keyboard::Event),
}

#[derive(Debug)]
pub enum Outcome {
    SetupComplete {
        account: AccountDescriptor,
        signer: KaoSigner,
    },
    ReconnectComplete {
        signer: KaoSigner,
    },
    Back,
}

#[derive(Debug, Clone)]
pub enum Mode {
    Setup,
    /// Reconnect to a previously-registered Trezor account. `expected_address`
    /// is the address that was saved at setup time; we abort if the device now
    /// returns a different one (different seed, swapped device, etc.).
    Reconnect {
        path: TrezorHdPath,
        expected_address: Address,
    },
}

#[derive(Debug)]
struct PickRow {
    hd_index: u32,
    address: Address,
    balance: Option<Result<String, String>>,
    fetching: bool,
}

#[derive(Debug)]
enum Stage {
    Connecting,
    Picking { rows: Vec<PickRow> },
    Building { picked: u32 },
    Error(String),
}

#[derive(Debug)]
pub struct ConnectTrezorScreen {
    mode: Mode,
    stage: Stage,
    network: Arc<dyn BalanceFetcher>,
}

impl ConnectTrezorScreen {
    pub fn new_setup(network: Arc<dyn BalanceFetcher>) -> (Self, Task<Message>) {
        let screen = Self {
            mode: Mode::Setup,
            stage: Stage::Connecting,
            network,
        };
        (screen, probe_setup_task())
    }

    pub fn new_reconnect(
        path: TrezorHdPath,
        expected_address: Address,
        network: Arc<dyn BalanceFetcher>,
    ) -> (Self, Task<Message>) {
        let task = reconnect_task(path.clone());
        let screen = Self {
            mode: Mode::Reconnect {
                path,
                expected_address,
            },
            stage: Stage::Connecting,
            network,
        };
        (screen, task)
    }

    pub fn update(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        match message {
            Message::SetupProbed(Ok(addrs)) => {
                let rows: Vec<PickRow> = addrs
                    .into_iter()
                    .map(|(hd_index, address)| PickRow {
                        hd_index,
                        address,
                        balance: None,
                        fetching: false,
                    })
                    .collect();
                self.stage = Stage::Picking { rows };
                (self.fetch_balance_tasks(), None)
            }
            Message::SetupProbed(Err(e)) => {
                self.stage = Stage::Error(e);
                (Task::none(), None)
            }
            Message::ReconnectProbed(Ok(cell)) => {
                let signer = match cell.lock().unwrap().take() {
                    Some(s) => s,
                    None => {
                        self.stage = Stage::Error("internal: empty signer handoff".into());
                        return (Task::none(), None);
                    }
                };
                // Verify the device returned the address we registered at
                // setup. A mismatch means a different seed is loaded, the
                // device has been swapped, or the saved descriptor was
                // tampered with — refuse rather than silently sign with the
                // wrong key.
                if let Mode::Reconnect {
                    expected_address, ..
                } = &self.mode
                {
                    let actual = signer.address();
                    if actual != *expected_address {
                        self.stage = Stage::Error(format!(
                            "Device returned {actual} but this account was set up with {expected_address}. \
                             Make sure the same device and seed are connected.",
                        ));
                        return (Task::none(), None);
                    }
                }
                (Task::none(), Some(Outcome::ReconnectComplete { signer }))
            }
            Message::ReconnectProbed(Err(e)) => {
                self.stage = Stage::Error(e);
                (Task::none(), None)
            }
            Message::BalanceFetched { hd_index, balance } => {
                if let Stage::Picking { rows } = &mut self.stage
                    && let Some(r) = rows.iter_mut().find(|r| r.hd_index == hd_index)
                {
                    r.fetching = false;
                    r.balance = Some(balance);
                }
                (Task::none(), None)
            }
            Message::Pick(hd_index) => {
                if !matches!(self.stage, Stage::Picking { .. }) {
                    return (Task::none(), None);
                }
                self.stage = Stage::Building { picked: hd_index };
                (
                    Task::perform(
                        async move {
                            TrezorSigner::new(
                                TrezorHdPath::TrezorLive(hd_index).to_alloy(),
                                Some(CHAIN_ID),
                            )
                            .await
                            .map(|s| handoff_with(KaoSigner::Trezor(s)))
                            .map_err(|e| e.to_string())
                        },
                        Message::SignerBuilt,
                    ),
                    None,
                )
            }
            Message::SignerBuilt(Ok(cell)) => {
                let picked = match self.stage {
                    Stage::Building { picked } => picked,
                    _ => return (Task::none(), None),
                };
                let signer = match cell.lock().unwrap().take() {
                    Some(s) => s,
                    None => {
                        self.stage = Stage::Error("internal: empty signer handoff".into());
                        return (Task::none(), None);
                    }
                };
                let address = signer.address();
                let account = AccountDescriptor::Trezor {
                    name: None,
                    path: TrezorHdPath::TrezorLive(picked),
                    address: address.into_array(),
                };
                (
                    Task::none(),
                    Some(Outcome::SetupComplete { account, signer }),
                )
            }
            Message::SignerBuilt(Err(e)) => {
                self.stage = Stage::Error(e);
                (Task::none(), None)
            }
            Message::Retry => match &self.mode {
                Mode::Setup => {
                    self.stage = Stage::Connecting;
                    (probe_setup_task(), None)
                }
                Mode::Reconnect { path, .. } => {
                    self.stage = Stage::Connecting;
                    (reconnect_task(path.clone()), None)
                }
            },
            Message::BackPressed => (Task::none(), Some(Outcome::Back)),
            Message::KeyboardEvent(keyboard::Event::KeyPressed { key, .. }) => match key {
                keyboard::Key::Named(keyboard::key::Named::Escape) => {
                    (Task::none(), Some(Outcome::Back))
                }
                _ => (Task::none(), None),
            },
            Message::KeyboardEvent(_) => (Task::none(), None),
        }
    }

    fn fetch_balance_tasks(&mut self) -> Task<Message> {
        let Stage::Picking { rows } = &mut self.stage else {
            return Task::none();
        };
        let tasks: Vec<Task<Message>> = rows
            .iter_mut()
            .filter(|r| !r.fetching && r.balance.is_none())
            .map(|r| {
                r.fetching = true;
                let hd_index = r.hd_index;
                let address = r.address;
                let network = self.network.clone();
                Task::perform(
                    async move { network.balance(address).await },
                    move |balance| Message::BalanceFetched { hd_index, balance },
                )
            })
            .collect();
        Task::batch(tasks)
    }

    pub fn subscription(&self) -> Subscription<Message> {
        keyboard::listen().map(Message::KeyboardEvent)
    }

    pub fn view(&self) -> Element<'_, Message> {
        let t = KaoTheme::for_kind(settings::theme());
        match &self.stage {
            Stage::Connecting => connecting_card(t, &self.mode),
            Stage::Picking { rows } => picking_card(t, rows),
            Stage::Building { picked } => building_card(t, *picked),
            Stage::Error(msg) => error_card(t, msg),
        }
    }
}

// ── view helpers ───────────────────────────────────────────────────────────

fn connecting_card<'a>(t: KaoTheme, mode: &Mode) -> Element<'a, Message> {
    let title = match mode {
        Mode::Setup => "Connect your Trezor",
        Mode::Reconnect { .. } => "Reconnecting to Trezor…",
    };
    let body = column![
        kao_hero(t, "(・・;)ゞ", 56.0),
        vspace(12),
        screen_title(t, title),
        vspace(6),
        screen_subtitle(
            t,
            "Plug in your Trezor and unlock it. Confirm any prompts on the device when asked.",
        ),
        vspace(20),
        container(text("…probing device").size(12).color(t.sub).font(mono()))
            .width(Length::Fill)
            .center_x(Length::Fill),
        vspace(18),
        back_hint(t),
    ]
    .width(Length::Fill)
    .align_x(Alignment::Center);

    let card = auth_card(t, 460.0, body.into());
    let back_bar = container(link_button(t, "← Back").on_press(Message::BackPressed))
        .padding(Padding::from([12, 14]))
        .width(Length::Fill);
    auth_background(
        t,
        column![back_bar, card]
            .width(Length::Fill)
            .height(Length::Fill)
            .into(),
    )
}

fn picking_card<'a>(t: KaoTheme, rows: &'a [PickRow]) -> Element<'a, Message> {
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

    let mut list = column![].spacing(6);
    for r in rows {
        list = list.push(account_row(t, r));
    }

    let body = column![
        kao_hero(t, "ʕ•ᴥ•ʔ", 52.0),
        vspace(10),
        screen_title(t, "Choose a Trezor Account"),
        vspace(6),
        screen_subtitle(
            t,
            "Pick which Trezor Live account to register (m/44'/60'/0'/0/N)."
        ),
        vspace(20),
        header,
        vspace(4),
        scrollable(list).height(Length::Fixed(260.0)),
        vspace(14),
        back_hint(t),
    ]
    .width(Length::Fill)
    .align_x(Alignment::Center);

    let card = auth_card(t, 560.0, body.into());
    let back_bar = container(link_button(t, "← Back").on_press(Message::BackPressed))
        .padding(Padding::from([12, 14]))
        .width(Length::Fill);
    auth_background(
        t,
        column![back_bar, card]
            .width(Length::Fill)
            .height(Length::Fill)
            .into(),
    )
}

fn building_card<'a>(t: KaoTheme, picked: u32) -> Element<'a, Message> {
    let body = column![
        kao_hero(t, "(￣ω￣)", 56.0),
        vspace(12),
        screen_title(t, "Confirm on your Trezor"),
        vspace(6),
        screen_subtitle(
            t,
            "Approve the address request on the device to finish setup."
        ),
        vspace(18),
        container(
            text(format!("HD account #{picked} (m/44'/60'/0'/0/{picked})"))
                .size(12)
                .color(t.sub)
                .font(mono())
        )
        .width(Length::Fill)
        .center_x(Length::Fill),
        vspace(14),
        back_hint(t),
    ]
    .width(Length::Fill)
    .align_x(Alignment::Center);
    auth_background(t, auth_card(t, 460.0, body.into()))
}

fn error_card<'a>(t: KaoTheme, msg: &'a str) -> Element<'a, Message> {
    let body = column![
        kao_hero(t, "(╥﹏╥)", 56.0),
        vspace(12),
        screen_title(t, "Couldn't connect"),
        vspace(6),
        error_text(t, msg),
        vspace(18),
        primary_button(t, "Retry", true).on_press(Message::Retry),
        vspace(12),
        back_hint(t),
    ]
    .width(Length::Fill)
    .align_x(Alignment::Center);

    let card = auth_card(t, 460.0, body.into());
    let back_bar = container(link_button(t, "← Back").on_press(Message::BackPressed))
        .padding(Padding::from([12, 14]))
        .width(Length::Fill);
    auth_background(
        t,
        column![back_bar, card]
            .width(Length::Fill)
            .height(Length::Fill)
            .into(),
    )
}

fn back_hint<'a>(t: KaoTheme) -> Element<'a, Message> {
    container(
        row![
            hint_pill(t, "Esc"),
            Space::new().width(6),
            text("to go back").size(11).color(t.sub),
        ]
        .align_y(Alignment::Center),
    )
    .width(Length::Fill)
    .center_x(Length::Fill)
    .into()
}

fn account_row<'a>(t: KaoTheme, r: &'a PickRow) -> Element<'a, Message> {
    let addr = format!("{}", r.address);
    let addr_display = format!("{}…{}", &addr[..8], &addr[addr.len() - 4..]);
    let balance_display = match &r.balance {
        None => "Loading…".to_string(),
        Some(Ok(eth)) => {
            let short: String = eth.chars().take(4).collect();
            format!("{short} ETH")
        }
        Some(Err(_)) => "—".to_string(),
    };
    let balance_color = match &r.balance {
        Some(Ok(_)) => t.text,
        _ => t.sub,
    };

    let kao = match r.hd_index % 4 {
        0 => "(◕‿◕✿)",
        1 => "( ´ ▽ ` )ﾉ",
        2 => "(￣ω￣)",
        _ => "(˘ᵕ˘)",
    };

    let row_inner = row![
        text(format!("{}", r.hd_index))
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
        select_pill(t).on_press(Message::Pick(r.hd_index)),
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

fn select_pill<'a>(t: KaoTheme) -> iced::widget::Button<'a, Message> {
    use iced::widget::button;
    let label_color = iced::Color::WHITE;
    iced::widget::button(
        container(text("Select").size(12).color(label_color).font(black()))
            .padding(Padding::from([4, 12])),
    )
    .style(move |_theme, status| button::Style {
        background: Some(Background::Color(match status {
            button::Status::Hovered | button::Status::Pressed => {
                crate::ui::kao_theme::mix(t.a2, iced::Color::WHITE, 0.10)
            }
            _ => t.a2,
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

// ── Async tasks ────────────────────────────────────────────────────────────

fn probe_setup_task() -> Task<Message> {
    Task::perform(
        async move {
            let signer = TrezorSigner::new(TrezorHdPath::TrezorLive(0).to_alloy(), Some(CHAIN_ID))
                .await
                .map_err(|e| e.to_string())?;

            let mut out: Vec<(u32, Address)> = Vec::with_capacity(PROBE_COUNT as usize);
            out.push((0, Signer::address(&signer)));
            for i in 1..PROBE_COUNT {
                let addr = signer
                    .get_address_with_path(&TrezorHdPath::TrezorLive(i).to_alloy())
                    .await
                    .map_err(|e| e.to_string())?;
                out.push((i, addr));
            }
            Ok(out)
        },
        Message::SetupProbed,
    )
}

fn reconnect_task(path: TrezorHdPath) -> Task<Message> {
    Task::perform(
        async move {
            TrezorSigner::new(path.to_alloy(), Some(CHAIN_ID))
                .await
                .map(|s| handoff_with(KaoSigner::Trezor(s)))
                .map_err(|e| e.to_string())
        },
        Message::ReconnectProbed,
    )
}
