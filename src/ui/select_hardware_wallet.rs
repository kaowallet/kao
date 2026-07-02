use iced::border::Radius;
use iced::keyboard;
use iced::widget::{Space, column, container, mouse_area, row, text};
use iced::{Alignment, Background, Border, Color, Element, Length, Padding, Subscription, Task};

use crate::settings;
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::{
    auth_background, auth_card, black, bold, hint_pill, kao_hero, link_button, mono,
    screen_subtitle, screen_title, vspace,
};

#[derive(Debug, Clone)]
pub enum Message {
    ConnectLedger,
    ConnectTrezor,
    BackPressed,
    KeyboardEvent(keyboard::Event),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ledger,
    Trezor,
    Back,
}

impl Outcome {
    /// Variant name for the GUI state trace.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Ledger => "Ledger",
            Outcome::Trezor => "Trezor",
            Outcome::Back => "Back",
        }
    }
}

#[derive(Debug, Default)]
pub struct SelectHardwareWalletScreen {}

struct DeviceCard<'a> {
    bg: Color,
    accent: Color,
    number: &'a str,
    label: &'a str,
    sub: &'a str,
    on_press: Message,
}

impl SelectHardwareWalletScreen {
    pub fn update(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("select_hw", &message);
        let (task, outcome) = match message {
            Message::ConnectLedger => (Task::none(), Some(Outcome::Ledger)),
            Message::ConnectTrezor => (Task::none(), Some(Outcome::Trezor)),
            Message::BackPressed => (Task::none(), Some(Outcome::Back)),
            Message::KeyboardEvent(keyboard::Event::KeyPressed { key, .. }) => match &key {
                keyboard::Key::Character(c) if c.as_str() == "1" => {
                    (Task::none(), Some(Outcome::Ledger))
                }
                keyboard::Key::Character(c) if c.as_str() == "2" => {
                    (Task::none(), Some(Outcome::Trezor))
                }
                keyboard::Key::Named(keyboard::key::Named::Escape) => {
                    (Task::none(), Some(Outcome::Back))
                }
                _ => (Task::none(), None),
            },
            Message::KeyboardEvent(_) => (Task::none(), None),
        };
        if let Some(o) = &outcome {
            crate::trace::outcome("select_hw", o.name());
        }
        (task, outcome)
    }

    pub fn view(&self) -> Element<'_, Message> {
        let t = KaoTheme::for_kind(settings::theme());

        let ledger_card = self.device_card(
            t,
            DeviceCard {
                bg: t.ab1,
                accent: t.a1,
                number: "1",
                label: "Connect Ledger",
                sub: "Sign with a Ledger hardware wallet",
                on_press: Message::ConnectLedger,
            },
        );
        let trezor_card = self.device_card(
            t,
            DeviceCard {
                bg: t.ab2,
                accent: t.a2,
                number: "2",
                label: "Connect Trezor",
                sub: "Sign with a Trezor hardware wallet",
                on_press: Message::ConnectTrezor,
            },
        );

        let hint = container(
            row![
                hint_pill(t, "1"),
                Space::new().width(4),
                hint_pill(t, "2"),
                Space::new().width(8),
                text("pick a device").size(11).color(t.sub).font(mono()),
            ]
            .align_y(Alignment::Center),
        )
        .width(Length::Fill)
        .center_x(Length::Fill);

        let back =
            container(link_button(t, "← Back").on_press(Message::BackPressed)).width(Length::Fill);

        let content = column![
            kao_hero(t, "(⌐■_■)", 56.0),
            vspace(10),
            screen_title(t, "Connect Hardware Wallet"),
            vspace(6),
            screen_subtitle(t, "Choose your device."),
            vspace(22),
            ledger_card,
            vspace(10),
            trezor_card,
            vspace(16),
            hint,
            vspace(12),
            back,
        ]
        .width(Length::Fill)
        .align_x(Alignment::Center);

        auth_background(t, auth_card(t, 460.0, content.into()))
    }

    fn device_card<'a>(&self, t: KaoTheme, card: DeviceCard<'a>) -> Element<'a, Message> {
        let DeviceCard {
            bg,
            accent,
            number,
            label,
            sub,
            on_press,
        } = card;
        let info = column![
            row![
                container(text(number).size(11).color(accent).font(black()))
                    .padding(Padding::from([2, 7]))
                    .style(move |_| container::Style {
                        background: Some(Background::Color(bg)),
                        border: Border {
                            color: with_alpha(accent, 0.3),
                            width: 1.0,
                            radius: Radius::from(6),
                        },
                        text_color: Some(accent),
                        ..container::Style::default()
                    }),
                Space::new().width(8),
                text(label).size(15).color(t.text).font(black()),
            ]
            .align_y(Alignment::Center),
            Space::new().height(2),
            text(sub).size(12).color(t.sub),
        ]
        .spacing(0);

        let row_content = row![
            container(info).width(Length::Fill),
            text("→").size(18).color(accent).font(bold()),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill);

        let styled = container(row_content)
            .padding(Padding::from([14, 16]))
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(bg)),
                border: Border {
                    color: with_alpha(accent, 0.25),
                    width: 1.5,
                    radius: Radius::from(15),
                },
                text_color: Some(t.text),
                ..container::Style::default()
            });

        mouse_area(styled)
            .on_press(on_press)
            .interaction(iced::mouse::Interaction::Pointer)
            .into()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        keyboard::listen().map(Message::KeyboardEvent)
    }
}
