use iced::keyboard;
use iced::widget::{Space, column, container, row, text};
use iced::{Alignment, Element, Length, Padding, Subscription, Task};

use crate::settings;
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    auth_background, auth_card, hint_pill, kao_hero, link_button, method_card, mono,
    screen_subtitle, screen_title, vspace,
};

#[derive(Debug, Clone)]
pub enum Message {
    ImportFromSeed,
    ImportFromPrivateKey,
    CreateNewWallet,
    ConnectHardwareWallet,
    WatchAddress,
    AddSafe,
    BackPressed,
    KeyboardEvent(keyboard::Event),
}

/// The setup method chosen by the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupMethod {
    ImportFromSeed,
    ImportFromPrivateKey,
    CreateNewWallet,
    ConnectHardwareWallet,
    WatchAddress,
    AddSafe,
}

impl SetupMethod {
    fn name(self) -> &'static str {
        match self {
            SetupMethod::ImportFromSeed => "ImportFromSeed",
            SetupMethod::ImportFromPrivateKey => "ImportFromPrivateKey",
            SetupMethod::CreateNewWallet => "CreateNewWallet",
            SetupMethod::ConnectHardwareWallet => "ConnectHardwareWallet",
            SetupMethod::WatchAddress => "WatchAddress",
            SetupMethod::AddSafe => "AddSafe",
        }
    }
}

/// What happened when the user interacted with the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Selected(SetupMethod),
    /// User asked to leave the setup flow (Esc). The parent decides whether
    /// this is meaningful — fresh setup ignores it; add-account mode treats
    /// it as a return-to-dashboard signal.
    Cancel,
}

impl Outcome {
    /// Variant name for the GUI state trace.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Selected(_) => "Selected",
            Outcome::Cancel => "Cancel",
        }
    }
}

#[derive(Debug, Default)]
pub struct SetupMethodScreen {
    /// The method the user selected, once they choose.
    selected: Option<SetupMethod>,
}

impl SetupMethodScreen {
    pub fn update(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("setup_method", &message);
        let selected_before = self.selected;
        let (task, outcome) = self.update_inner(message);
        if selected_before != self.selected {
            let s = |v: Option<SetupMethod>| v.map_or("none", SetupMethod::name);
            crate::trace::state(
                "setup_method",
                "selected",
                s(selected_before),
                s(self.selected),
            );
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("setup_method", o.name());
        }
        (task, outcome)
    }

    fn update_inner(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        let pick = |this: &mut Self, m: SetupMethod| {
            this.selected = Some(m);
            (Task::none(), Some(Outcome::Selected(m)))
        };
        match message {
            Message::ImportFromSeed => pick(self, SetupMethod::ImportFromSeed),
            Message::ImportFromPrivateKey => pick(self, SetupMethod::ImportFromPrivateKey),
            Message::CreateNewWallet => pick(self, SetupMethod::CreateNewWallet),
            Message::ConnectHardwareWallet => pick(self, SetupMethod::ConnectHardwareWallet),
            Message::WatchAddress => pick(self, SetupMethod::WatchAddress),
            Message::AddSafe => pick(self, SetupMethod::AddSafe),
            Message::BackPressed => (Task::none(), Some(Outcome::Cancel)),
            Message::KeyboardEvent(event) => match event {
                keyboard::Event::KeyPressed { key, .. } => match &key {
                    keyboard::Key::Character(c) if c.as_str() == "1" => {
                        pick(self, SetupMethod::ImportFromSeed)
                    }
                    keyboard::Key::Character(c) if c.as_str() == "2" => {
                        pick(self, SetupMethod::ImportFromPrivateKey)
                    }
                    keyboard::Key::Character(c) if c.as_str() == "3" => {
                        pick(self, SetupMethod::CreateNewWallet)
                    }
                    keyboard::Key::Character(c) if c.as_str() == "4" => {
                        pick(self, SetupMethod::ConnectHardwareWallet)
                    }
                    keyboard::Key::Character(c) if c.as_str() == "5" => {
                        pick(self, SetupMethod::WatchAddress)
                    }
                    keyboard::Key::Character(c) if c.as_str() == "6" => {
                        pick(self, SetupMethod::AddSafe)
                    }
                    keyboard::Key::Named(keyboard::key::Named::Escape) => {
                        (Task::none(), Some(Outcome::Cancel))
                    }
                    _ => (Task::none(), None),
                },
                _ => (Task::none(), None),
            },
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let t = KaoTheme::for_kind(settings::theme());

        let seed_card = method_card(
            t,
            t.ab1,
            t.a1,
            "1",
            "Import from Seed",
            "Restore using a 12 or 24-word phrase",
            Message::ImportFromSeed,
        );
        let key_card = method_card(
            t,
            t.ab2,
            t.a2,
            "2",
            "Import Private Key",
            "Restore from a raw 32-byte hex key",
            Message::ImportFromPrivateKey,
        );
        let create_card = method_card(
            t,
            t.ab3,
            t.a3,
            "3",
            "Create New Wallet",
            "Generate a fresh seed phrase",
            Message::CreateNewWallet,
        );
        let hardware_card = method_card(
            t,
            t.ab1,
            t.a1,
            "4",
            "Hardware Wallet",
            "Connect a Ledger or Trezor device",
            Message::ConnectHardwareWallet,
        );
        let watch_card = method_card(
            t,
            t.ab2,
            t.a2,
            "5",
            "Watch an Address",
            "Track any wallet read-only — view-only mode",
            Message::WatchAddress,
        );
        let safe_card = method_card(
            t,
            t.ab3,
            t.a3,
            "6",
            "Add a Safe",
            "Onboard a Safe multisig as signer, proposer or observer",
            Message::AddSafe,
        );

        let hint = container(
            row![
                hint_pill(t, "1"),
                Space::new().width(4),
                hint_pill(t, "2"),
                Space::new().width(4),
                hint_pill(t, "3"),
                Space::new().width(4),
                hint_pill(t, "4"),
                Space::new().width(4),
                hint_pill(t, "5"),
                Space::new().width(4),
                hint_pill(t, "6"),
                Space::new().width(8),
                text("pick a method").size(11).color(t.sub).font(mono()),
            ]
            .align_y(Alignment::Center),
        )
        .width(Length::Fill)
        .center_x(Length::Fill);

        let grid = column![
            row![seed_card, Space::new().width(10), key_card].width(Length::Fill),
            vspace(10),
            row![create_card, Space::new().width(10), hardware_card].width(Length::Fill),
            vspace(10),
            row![watch_card, Space::new().width(10), safe_card].width(Length::Fill),
        ]
        .width(Length::Fill);

        let content = column![
            kao_hero(t, "٩(◕‿◕｡)۶", 56.0),
            vspace(10),
            screen_title(t, "Set Up Your Wallet"),
            vspace(6),
            screen_subtitle(t, "Choose how you'd like to get started."),
            vspace(22),
            grid,
            vspace(16),
            hint,
        ]
        .width(Length::Fill)
        .align_x(Alignment::Center);

        let card = auth_card(t, 520.0, content.into());

        let back_bar = container(link_button(t, "← Back").on_press(Message::BackPressed))
            .padding(Padding::from([12, 14]))
            .width(Length::Fill);

        let layout = column![back_bar, card]
            .width(Length::Fill)
            .height(Length::Fill);

        auth_background(t, layout.into())
    }

    /// Keyboard subscription for number key shortcuts.
    pub fn subscription(&self) -> Subscription<Message> {
        keyboard::listen().map(Message::KeyboardEvent)
    }
}
