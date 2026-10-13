//! Top header strip — account or Safe name (with inline rename), Helios
//! verification badge, mood pill. The account selector and network/privacy
//! status moved into the sidebar; this strip is now just the active
//! identity's title and the at-a-glance verification + mood affordances.

use iced::border::Radius;
use iced::widget::{Space, button, container, row, text, text_input};
use iced::{Alignment, Background, Border, Color, Element, Length, Padding};

use crate::net::VerificationStatus;
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::{
    black, bold, hover_tint, kao_text, mono_bold, text_input_style, verification_badge,
};

use super::{MOOD, Message};

/// Widget id used by the dashboard's `BeginRenameAccount` handler to focus
/// the input as soon as it appears. Kept as a constant so both the header
/// (which sets it on the widget) and the coordinator (which sends focus
/// commands) refer to the same string.
pub const RENAME_INPUT_ID: &str = "wallet_dashboard_rename_input";

pub fn view<'a>(
    t: KaoTheme,
    verification: VerificationStatus,
    name: String,
    // `Some("Safe 2 of 3")` in Safe mode: shown as a badge after the
    // name (and its pencil), and the rename input asks for a Safe name.
    // `None` for an account.
    safe_badge: Option<String>,
    rename_draft: Option<&'a str>,
) -> Element<'a, Message> {
    let placeholder = if safe_badge.is_some() {
        "Safe name"
    } else {
        "Wallet name"
    };
    let title = match rename_draft {
        Some(draft) => rename_input(t, draft, placeholder),
        None => static_name(t, name),
    };
    let title_slot: Element<'a, Message> = match safe_badge {
        Some(badge) => row![title, Space::new().width(10), threshold_badge(t, badge)]
            .align_y(Alignment::Center)
            .into(),
        None => title,
    };

    let mood_pill = container(kao_text(t, MOOD, 15.0))
        .padding(Padding::from([6, 13]))
        .style(move |_| container::Style {
            background: Some(Background::Color(t.ab1)),
            border: Border {
                color: with_alpha(t.a1, 0.2),
                width: 1.0,
                radius: Radius::from(10),
            },
            ..container::Style::default()
        });

    container(
        row![
            title_slot,
            Space::new().width(Length::Fill),
            verification_badge(t, verification),
            Space::new().width(12),
            mood_pill,
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill),
    )
    .padding(Padding::from([14, 24]))
    .width(Length::Fill)
    .style(move |_| container::Style {
        border: Border {
            color: t.border,
            width: 1.0,
            radius: Radius::from(0),
        },
        ..container::Style::default()
    })
    .into()
}

/// Static "Name ✎" row — an account's or, in Safe mode, the Safe's own
/// name. Clicking the pencil swaps the slot to the editable input variant.
fn static_name<'a>(t: KaoTheme, display_name: String) -> Element<'a, Message> {
    let name = text(display_name).size(17).color(t.text).font(bold());

    let pencil = button(text("✎").size(13).color(t.sub).font(bold()))
        .padding(Padding::from([2, 6]))
        .on_press(Message::BeginRenameAccount)
        .style(move |_theme, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => {
                    hover_tint(Color::TRANSPARENT, t.text)
                }
                _ => Color::TRANSPARENT,
            })),
            text_color: t.sub,
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(8),
            },
            ..button::Style::default()
        });

    row![name, Space::new().width(6), pencil]
        .align_y(Alignment::Center)
        .into()
}

/// Safe-mode "Safe 2 of 3" pill after the name. Kept out of the name so
/// the pencil sits by what it edits, and so it stays put while the name
/// swaps to the rename input.
fn threshold_badge<'a>(t: KaoTheme, label: String) -> Element<'a, Message> {
    container(text(label).size(11).color(t.a1).font(mono_bold()))
        .padding(Padding::from([3, 8]))
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(t.a1, 0.14))),
            border: Border {
                color: with_alpha(t.a1, 0.3),
                width: 1.0,
                radius: Radius::from(6),
            },
            text_color: Some(t.a1),
            ..container::Style::default()
        })
        .into()
}

/// Editable "[input] ✓ ✗" row used while renaming. Enter (text_input
/// `on_submit`) commits; the ✗ button cancels.
fn rename_input<'a>(t: KaoTheme, draft: &'a str, placeholder: &str) -> Element<'a, Message> {
    let input = text_input(placeholder, draft)
        .id(RENAME_INPUT_ID)
        .on_input(Message::RenameInput)
        .on_submit(Message::CommitRename)
        .padding(Padding::from([4, 10]))
        .size(15)
        .width(Length::Fixed(220.0))
        .style(move |_theme, status| text_input_style(t, status));

    let commit_idle = with_alpha(t.up, 0.08);
    let commit = button(text("✓").size(13).color(t.up).font(black()))
        .padding(Padding::from([3, 8]))
        .on_press(Message::CommitRename)
        .style(move |_theme, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => hover_tint(commit_idle, t.up),
                _ => commit_idle,
            })),
            text_color: t.up,
            border: Border {
                color: with_alpha(t.up, 0.3),
                width: 1.0,
                radius: Radius::from(8),
            },
            ..button::Style::default()
        });

    let cancel = button(text("✗").size(13).color(t.sub).font(black()))
        .padding(Padding::from([3, 8]))
        .on_press(Message::CancelRename)
        .style(move |_theme, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => {
                    hover_tint(Color::TRANSPARENT, t.text)
                }
                _ => Color::TRANSPARENT,
            })),
            text_color: t.sub,
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(8),
            },
            ..button::Style::default()
        });

    row![
        input,
        Space::new().width(6),
        commit,
        Space::new().width(4),
        cancel
    ]
    .align_y(Alignment::Center)
    .into()
}
