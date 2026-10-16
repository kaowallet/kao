//! Settings root pane — the list of category cards under the Settings nav. Every row opens its
//! sub-screen; below the list, a plain line says which Kao this is.

use iced::border::Radius;
use iced::widget::{Space, button, column, container, row, text};
use iced::{Alignment, Background, Border, Element, Length, Padding};

use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{avatar, bold, hover_tint, kao_scrollable_style};

use super::Message;

/// `(label, kaomoji, subtitle)`, in display order; [`row_message`] maps each label to its pane.
const SETTINGS_ROWS: &[(&str, &str, &str)] = &[
    ("Networks", "( ・∀・)ﾉ", "RPC · API · proxy · privacy"),
    ("Accounts", "(◕‿◕)", "Rename · remove"),
    ("Safes", "(◐‿◐)", "Rename · remove · transaction service"),
    ("Contacts", "(✿◠‿◠)", "Named addresses · saved recipients"),
    (
        "Signed messages",
        "(｀・ω・´)ゞ",
        "What you signed for dapps · CoW swaps",
    ),
    (
        "Connection history",
        "(・ω・)ノ",
        "Dapps you connected with WalletConnect",
    ),
    ("Appearance", "(｡◕‿◕｡)", "Theme · palette"),
];

/// The pane a root row opens.
fn row_message(label: &str) -> Message {
    match label {
        "Networks" => Message::OpenNetworksSettings,
        "Accounts" => Message::OpenAccountsSettings,
        "Safes" => Message::OpenSafesSettings,
        "Contacts" => Message::OpenContactsSettings,
        "Signed messages" => Message::OpenSignedMessagesSettings,
        "Connection history" => Message::OpenConnectionHistorySettings,
        "Appearance" => Message::OpenAppearanceSettings,
        other => unreachable!("settings row {other:?} has no pane"),
    }
}

/// The footer line: the running build's version, from Cargo.
pub(super) fn version_line() -> String {
    format!("Kao v{}", env!("CARGO_PKG_VERSION"))
}

pub fn view<'a>(t: KaoTheme) -> Element<'a, Message> {
    let mut list = column![].spacing(7);
    for (label, kao, sub) in SETTINGS_ROWS {
        list = list.push(settings_row(t, label, kao, sub, row_message(label)));
    }
    // Plain text, not a card: nothing to open.
    list = list.push(Space::new().height(14));
    list = list.push(
        container(text(version_line()).size(11).color(t.sub))
            .width(Length::Fill)
            .center_x(Length::Fill),
    );

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
    on_click: Message,
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

    // A button, so the row picks up the canonical hover tint.
    button(row)
        .padding(Padding::from([15, 17]))
        .width(Length::Fill)
        .on_press(on_click)
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
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::kao_theme::ThemeKind;

    fn theme() -> KaoTheme {
        KaoTheme::for_kind(ThemeKind::Void)
    }

    /// The rows that did nothing are gone, the new history panes are there, and the version the
    /// About row used to claim (wrongly) is now the build's own, in a plain footer.
    #[test]
    fn every_row_is_a_pane_and_the_footer_shows_the_version() {
        let texts = super::super::test_support::texts(view(theme()));
        for gone in ["Security", "Notifications", "About Kao"] {
            assert!(!texts.iter().any(|s| s == gone), "{gone}: {texts:?}");
        }
        for (label, _, _) in SETTINGS_ROWS {
            assert!(texts.iter().any(|s| s == label), "{label}: {texts:?}");
        }
        assert!(texts.iter().any(|s| s == "Signed messages"));
        assert!(texts.iter().any(|s| s == "Connection history"));
        let footer = format!("Kao v{}", env!("CARGO_PKG_VERSION"));
        assert_eq!(texts.last(), Some(&footer), "{texts:?}");
    }

    /// A click on each row's label lands on that row's button, which opens its pane.
    #[test]
    fn clicking_each_row_opens_its_pane() {
        for (label, _, _) in SETTINGS_ROWS {
            let published = super::super::test_support::click_text(view(theme()), label);
            assert_eq!(published.len(), 1, "{label}: {published:?}");
            assert_eq!(
                format!("{:?}", published[0]),
                format!("{:?}", row_message(label)),
                "{label}"
            );
        }
        // The footer is text, not a control.
        let footer = version_line();
        assert!(super::super::test_support::click_text(view(theme()), &footer).is_empty());
    }
}
