//! Settings root pane — the list of category cards under the Settings nav.
//! Only "Networks" is wired up today; the others are placeholders for future
//! sub-screens.

use iced::border::Radius;
use iced::widget::{Space, button, column, container, row, text};
use iced::{Alignment, Background, Border, Element, Length, Padding};

use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{avatar, bold, card_style, hover_tint, kao_scrollable_style};

use super::Message;

const SETTINGS_ROWS: &[(&str, &str, &str)] = &[
    ("Security", "(⌐■_■)", "Seed phrase · lock screen"),
    ("Networks", "( ・∀・)ﾉ", "Mainnet · testnets · L2s"),
    (
        "Sessions",
        "(づ｡◕‿‿◕｡)づ",
        "Connected dApps · WalletConnect",
    ),
    ("Contacts", "(✿◠‿◠)", "Named addresses · saved recipients"),
    ("Notifications", "ヾ(＾∇＾)", "Price alerts · tx updates"),
    ("Appearance", "(｡◕‿◕｡)", "Theme · palette"),
    ("About Kao", "(´｡• ᵕ •｡`)", "v0.1.0 · kawaii edition"),
];

pub fn view<'a>(t: KaoTheme) -> Element<'a, Message> {
    let mut list = column![].spacing(7);
    for (label, kao, sub) in SETTINGS_ROWS {
        let on_click = match *label {
            "Networks" => Some(Message::OpenNetworksSettings),
            "Appearance" => Some(Message::OpenAppearanceSettings),
            "Contacts" => Some(Message::OpenContactsSettings),
            "Sessions" => Some(Message::OpenWcSessionsSettings),
            _ => None,
        };
        list = list.push(settings_row(t, label, kao, sub, on_click));
    }

    iced::widget::scrollable(
        container(list)
            .padding(Padding::from([22, 24]))
            .width(Length::Fill),
    )
    .height(Length::Fill)
    .width(Length::Fill)
    .style(move |_, s| kao_scrollable_style(t, s))
    .into()
}

fn settings_row<'a>(
    t: KaoTheme,
    label: &'a str,
    kao: &'a str,
    sub: &'a str,
    on_click: Option<Message>,
) -> Element<'a, Message> {
    let info = column![
        text(label).size(14).color(t.text).font(bold()),
        text(sub).size(11).color(t.sub),
    ]
    .spacing(0);

    let row = row![
        avatar(t, kao, 38.0, t.ab2),
        Space::new().width(14),
        column![info].width(Length::Fill),
        text("→").size(15).color(t.sub).font(bold()),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    // Clickable categories become buttons so they pick up the canonical
    // hover tint; placeholder rows (no `on_click`) stay bare containers
    // so hovering them doesn't promise an action that isn't wired up.
    match on_click {
        Some(msg) => button(row)
            .padding(Padding::from([15, 17]))
            .width(Length::Fill)
            .on_press(msg)
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
            })
            .into(),
        None => container(row)
            .padding(Padding::from([15, 17]))
            .width(Length::Fill)
            .style(move |_| card_style(t))
            .into(),
    }
}
