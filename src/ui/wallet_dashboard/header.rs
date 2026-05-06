//! Top header strip — wallet name (with inline rename), address pill,
//! network row, mood pill.

use alloy::primitives::Address;
use iced::border::Radius;
use iced::widget::{Space, button, column, container, mouse_area, row, text, text_input};
use iced::{Alignment, Background, Border, Color, Element, Length, Padding};

use crate::net::VerificationStatus;
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::{
    black, bold, hover_tint, kao_text, mono, mono_bold, text_input_style, verification_badge,
};
use crate::wallet::short_address;

use super::{MOOD, Message};

/// Widget id used by the dashboard's `BeginRenameAccount` handler to focus
/// the input as soon as it appears. Kept as a constant so both the header
/// (which sets it on the widget) and the coordinator (which sends focus
/// commands) refer to the same string.
pub const RENAME_INPUT_ID: &str = "wallet_dashboard_rename_input";

pub fn view<'a>(
    t: KaoTheme,
    address: Address,
    verification: VerificationStatus,
    display_name: String,
    rename_draft: Option<&'a str>,
) -> Element<'a, Message> {
    let addr_short = short_address(address);
    // Address pill: clickable trigger that opens the account dropdown.
    let addr_pill = container(
        row![
            text(addr_short).size(22).color(t.text).font(mono_bold()),
            Space::new().width(8),
            text("▾").size(14).color(t.sub),
        ]
        .align_y(Alignment::Center),
    )
    .padding(Padding::from([4, 10]))
    .style(move |_| container::Style {
        background: Some(Background::Color(t.ab1)),
        border: Border {
            color: with_alpha(t.a1, 0.18),
            width: 1.0,
            radius: Radius::from(10),
        },
        text_color: Some(t.text),
        ..container::Style::default()
    });
    let addr_trigger: Element<'_, Message> = mouse_area(addr_pill)
        .on_press(Message::OpenAccountDropdown)
        .interaction(iced::mouse::Interaction::Pointer)
        .into();

    let net_row = row![
        text("Ethereum Mainnet").size(11).color(t.sub).font(mono()),
        Space::new().width(8),
        verification_badge(t, verification),
    ]
    .align_y(Alignment::Center);

    let title_slot: Element<'a, Message> = match rename_draft {
        Some(draft) => rename_input(t, draft),
        None => static_name(t, display_name),
    };

    let title_col = column![
        title_slot,
        Space::new().height(2),
        addr_trigger,
        Space::new().height(2),
        net_row,
    ]
    .spacing(1);

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
        row![title_col, Space::new().width(Length::Fill), mood_pill]
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

/// Static "Wallet name ✎" row. Clicking the pencil swaps the slot to the
/// editable input variant.
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

/// Editable "[input] ✓ ✗" row used while renaming. Enter (text_input
/// `on_submit`) commits; the ✗ button cancels.
fn rename_input<'a>(t: KaoTheme, draft: &'a str) -> Element<'a, Message> {
    let input = text_input("Wallet name", draft)
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
                button::Status::Hovered | button::Status::Pressed => {
                    hover_tint(commit_idle, t.up)
                }
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

    row![input, Space::new().width(6), commit, Space::new().width(4), cancel]
        .align_y(Alignment::Center)
        .into()
}
