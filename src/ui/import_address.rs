use std::sync::Arc;

use alloy::primitives::Address;
use iced::keyboard;
use iced::widget::{Space, column, container, row, text, text_input};
use iced::{Alignment, Element, Length, Padding, Subscription, Task};

use crate::names;
use crate::net::BalanceFetcher;
use crate::settings;
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    auth_background, auth_card, error_text, hint_pill, kao_hero, link_button, mono, primary_button,
    screen_subtitle, screen_title, text_input_style, vspace,
};

pub const ADDRESS_INPUT_ID: &str = "view_only_address_input";

#[derive(Debug, Clone)]
pub enum Message {
    AddressInput(String),
    AddPressed,
    /// Result of an ENS forward-resolution task spawned by `AddPressed`.
    /// `seq` is the input-generation counter that was current when the task
    /// was spawned; we drop the result if the user has typed since.
    EnsResolved {
        seq: u64,
        name: String,
        result: Result<Option<Address>, String>,
    },
    BackPressed,
    KeyboardEvent(keyboard::Event),
}

/// Outcome signals emitted by this screen to its parent.
#[derive(Debug, Clone)]
pub enum Outcome {
    Imported {
        address: Address,
        /// The ENS name the user typed (forward-verified at resolve time),
        /// or `None` when they entered a raw `0x…` address. Used by the
        /// caller as the default account display name.
        ens_name: Option<String>,
    },
    Back,
}

impl Outcome {
    /// Variant name for the GUI state trace.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Imported { .. } => "Imported",
            Outcome::Back => "Back",
        }
    }
}

#[derive(Debug)]
pub struct ImportAddressScreen {
    address_input: String,
    error: Option<String>,
    /// Bumped on every keystroke. ENS resolution tasks tag results with the
    /// sequence they were spawned at, so a stale lookup can't import a
    /// stale address after the user kept typing.
    input_seq: u64,
    /// `Some(seq)` while an ENS resolution task is in flight for the given
    /// sequence; `None` when idle.
    resolving: Option<u64>,
    network: Arc<dyn BalanceFetcher>,
}

impl ImportAddressScreen {
    pub fn new(network: Arc<dyn BalanceFetcher>) -> Self {
        Self {
            address_input: String::new(),
            error: None,
            input_seq: 0,
            resolving: None,
            network,
        }
    }

    pub fn update(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("import_address", &message);
        let busy_before = self.resolving.is_some();
        let (task, outcome) = self.update_inner(message);
        if busy_before != self.resolving.is_some() {
            crate::trace::state(
                "import_address",
                "busy",
                busy_before,
                self.resolving.is_some(),
            );
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("import_address", o.name());
        }
        (task, outcome)
    }

    fn update_inner(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        match message {
            Message::AddressInput(s) => {
                self.address_input = s;
                self.input_seq = self.input_seq.wrapping_add(1);
                // Any in-flight ENS lookup is now stale.
                self.resolving = None;
                self.error = None;
                (Task::none(), None)
            }
            Message::AddPressed => self.try_import(),
            Message::EnsResolved { seq, name, result } => {
                if self.resolving != Some(seq) {
                    // User kept typing — drop the result.
                    return (Task::none(), None);
                }
                self.resolving = None;
                match result {
                    Ok(Some(address)) => (
                        Task::none(),
                        Some(Outcome::Imported {
                            address,
                            ens_name: Some(name),
                        }),
                    ),
                    Ok(None) => {
                        self.error = Some(format!("“{name}” has no address record."));
                        (Task::none(), None)
                    }
                    Err(e) => {
                        self.error = Some(format!("Name lookup failed: {e}"));
                        (Task::none(), None)
                    }
                }
            }
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

    fn try_import(&mut self) -> (Task<Message>, Option<Outcome>) {
        let trimmed = self.address_input.trim().to_string();
        if trimmed.is_empty() {
            self.error = Some("Please enter an Ethereum address or name.".into());
            return (Task::none(), None);
        }
        // Hex first: a 40-char hex string with optional 0x parses straight to
        // an Address and skips a network round-trip.
        if let Ok(address) = trimmed.parse::<Address>() {
            self.error = None;
            return (
                Task::none(),
                Some(Outcome::Imported {
                    address,
                    ens_name: None,
                }),
            );
        }
        if names::looks_like_name(&trimmed) {
            self.error = None;
            let seq = self.input_seq;
            self.resolving = Some(seq);
            let network = self.network.clone();
            let name = trimmed;
            let task = Task::perform(
                async move {
                    // Verified (Helios, mainnet-only) name resolution — the
                    // resolved address is what gets imported as a watched
                    // account, so an unverified RPC answer must not be trusted.
                    let result = names::resolve_name(network.as_ref(), &name).await;
                    (seq, name, result)
                },
                |(seq, name, result)| Message::EnsResolved { seq, name, result },
            );
            return (task, None);
        }
        self.error = Some(
            "Not a valid Ethereum address or name. Expected `0x…` (40 hex chars) or a `.eth` / `.gwei` / `.wei` name.".into(),
        );
        (Task::none(), None)
    }

    pub fn subscription(&self) -> Subscription<Message> {
        keyboard::listen().map(Message::KeyboardEvent)
    }

    pub fn view(&self) -> Element<'_, Message> {
        let t = KaoTheme::for_kind(settings::theme());

        let address_input = text_input("0x… or a name (.eth / .gwei / .wei)", &self.address_input)
            .id(ADDRESS_INPUT_ID)
            .on_input(Message::AddressInput)
            .on_submit(Message::AddPressed)
            .padding(Padding::from([12, 14]))
            .size(14)
            .font(mono())
            .style(move |_theme, status| text_input_style(t, status));

        let resolving_now = self.resolving.is_some();
        let btn_label = if resolving_now {
            "Resolving name…"
        } else {
            "Watch Address →"
        };
        let add_btn =
            primary_button(t, btn_label, !resolving_now).on_press_maybe(if resolving_now {
                None
            } else {
                Some(Message::AddPressed)
            });

        let hint = container(
            row![
                hint_pill(t, "Enter"),
                Space::new().width(6),
                text("to add · ").size(11).color(t.sub),
                hint_pill(t, "Esc"),
                Space::new().width(6),
                text("to go back").size(11).color(t.sub),
            ]
            .align_y(Alignment::Center),
        )
        .width(Length::Fill)
        .center_x(Length::Fill);

        let mut content = column![
            kao_hero(t, "(◉‿◉)", 56.0),
            vspace(10),
            screen_title(t, "Watch an Address"),
            vspace(6),
            screen_subtitle(t, "Track any wallet read-only — paste an address or name."),
            vspace(22),
            address_input,
            vspace(18),
            add_btn,
            vspace(14),
            hint,
        ]
        .width(Length::Fill)
        .align_x(Alignment::Center);

        if let Some(e) = &self.error {
            content = content.push(vspace(10)).push(error_text(t, e));
        }

        let card = auth_card(t, 520.0, content.into());

        let back_bar = container(link_button(t, "← Back").on_press(Message::BackPressed))
            .padding(Padding::from([12, 14]))
            .width(Length::Fill);

        let layout = column![back_bar, card]
            .width(Length::Fill)
            .height(Length::Fill);

        auth_background(t, layout.into())
    }
}
