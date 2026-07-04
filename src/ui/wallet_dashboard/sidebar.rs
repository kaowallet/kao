//! Vertical sidebar — the dashboard's primary chrome. Top to bottom: a
//! brand mark, the active-account card (opens the account dropdown), the
//! nav rows, and a network/privacy status footer. Stateless view: every
//! value it renders is threaded in from the coordinator.

use alloy::primitives::Address;
use iced::alignment::{Horizontal, Vertical};
use iced::border::Radius;
use iced::widget::text::Wrapping;
use iced::widget::{Space, button, column, container, row, text};
use iced::{Alignment, Background, Border, Color, Element, Length, Padding};

use crate::net::VerificationStatus;
use crate::settings::{self, ProxyType};
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::{
    avatar, black, bold, hover_fill, hover_tint, kao_fit, kaomoji_for_account, mono, mono_bold,
};
use crate::wallet::short_address;

use super::{HardwareStatus, Message, Nav};

/// Sidebar width. Wide enough to seat the account card (name + WALLET
/// badge + address) and the two-line nav rows without truncation.
const SIDEBAR_WIDTH: f32 = 256.0;

// Each value is a distinct, self-documenting view input threaded from the
// coordinator; bundling them into a struct would add indirection without
// real readability gain (same call the WalletScreen constructor makes).
#[allow(clippy::too_many_arguments)]
pub fn view<'a>(
    t: KaoTheme,
    nav: Nav,
    active_index: usize,
    display_name: String,
    display_addr: Address,
    is_safe: bool,
    show_apps: bool,
    hardware: Option<HardwareStatus>,
    network_name: &'a str,
    verification: VerificationStatus,
) -> Element<'a, Message> {
    let mut body = column![
        brand_header(t),
        Space::new().height(18),
        account_card(t, active_index, display_name, display_addr, is_safe),
        Space::new().height(14),
        divider(t),
        Space::new().height(14),
        nav_item(t, nav, Nav::Home, "(◕‿◕)", "Portfolio", "this account"),
    ]
    .width(Length::Fill);

    // The Apps (swap) section is hidden for identities that can't swap —
    // view-only accounts and Safe mode.
    if show_apps {
        body = body.push(Space::new().height(8));
        body = body.push(nav_item(
            t,
            nav,
            Nav::Apps,
            "(ᵔᴥᵔ)",
            "Apps",
            "on-chain apps",
        ));
    }

    body = body.push(Space::new().height(8));
    body = body.push(nav_item(
        t,
        nav,
        Nav::Activity,
        "(˘ᵕ˘)",
        "Activity",
        "history",
    ));
    body = body.push(Space::new().height(8));
    body = body.push(nav_item(
        t,
        nav,
        Nav::Settings,
        "(・ω・)",
        "Settings",
        "network · privacy",
    ));
    body = body.push(Space::new().height(Length::Fill));
    // Hardware-device card sits just above the network footer, both pinned
    // to the bottom. Only shown for hardware accounts — it's the only path
    // to reconnect a Ledger / Trezor once the device is unplugged (which
    // otherwise just hides Apps + Swap with no way back).
    if let Some(status) = hardware {
        body = body.push(hardware_footer(t, status));
        body = body.push(Space::new().height(10));
    }
    body = body.push(network_footer(t, network_name, verification));

    container(body)
        .padding(Padding {
            top: 18.0,
            right: 16.0,
            bottom: 16.0,
            left: 16.0,
        })
        .width(Length::Fixed(SIDEBAR_WIDTH))
        .height(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.sidebar)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(0),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
}

/// Brand row: a rounded-square mark with a white kaomoji face, the "Kao"
/// wordmark, and the "private by default" tagline pushed to the right.
fn brand_header<'a>(t: KaoTheme) -> Element<'a, Message> {
    let mark = container(
        text("˘ᵕ˘")
            .size(15)
            .color(Color::WHITE)
            .font(black())
            .wrapping(Wrapping::None),
    )
    .width(Length::Fixed(34.0))
    .height(Length::Fixed(34.0))
    .align_x(Horizontal::Center)
    .align_y(Vertical::Center)
    .style(move |_| container::Style {
        background: Some(Background::Color(t.a1)),
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: Radius::from(10),
        },
        text_color: Some(Color::WHITE),
        ..container::Style::default()
    });

    row![
        mark,
        Space::new().width(10),
        text("Kao").size(21).color(t.text).font(black()),
        Space::new().width(Length::Fill),
        text("private by default")
            .size(11)
            .color(t.sub)
            .font(mono())
            .wrapping(Wrapping::None),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill)
    .into()
}

/// The active-account card. The whole card is a button that opens the
/// account dropdown — the same trigger the header address pill used to be.
fn account_card<'a>(
    t: KaoTheme,
    active_index: usize,
    display_name: String,
    display_addr: Address,
    is_safe: bool,
) -> Element<'a, Message> {
    let kao = kaomoji_for_account(active_index);

    let badge_label = if is_safe { "SAFE" } else { "WALLET" };
    let badge = container(text(badge_label).size(9).color(t.a1).font(mono_bold()))
        .padding(Padding::from([2, 6]))
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(t.a1, 0.14))),
            border: Border {
                color: with_alpha(t.a1, 0.3),
                width: 1.0,
                radius: Radius::from(6),
            },
            text_color: Some(t.a1),
            ..container::Style::default()
        });

    let name_row = row![
        text(display_name).size(15).color(t.text).font(bold()),
        Space::new().width(7),
        badge,
    ]
    .align_y(Alignment::Center);

    let info = column![
        name_row,
        Space::new().height(2),
        text(short_address(display_addr))
            .size(11)
            .color(t.sub)
            .font(mono()),
    ]
    .spacing(0);

    let inner = row![
        avatar(t, kao, 38.0, t.ab1),
        Space::new().width(11),
        container(info).width(Length::Fill),
        text("▾").size(13).color(t.sub),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    button(inner)
        .padding(Padding::from([9, 11]))
        .width(Length::Fill)
        .on_press(Message::OpenAccountDropdown)
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

/// One nav row: a tinted icon chip with a kaomoji, a bold title, and a
/// muted sub-label. The active row fills with the accent tint and gains a
/// dark outline ring; idle rows are transparent with the canonical hover tint.
fn nav_item<'a>(
    t: KaoTheme,
    active_nav: Nav,
    id: Nav,
    kao: &'a str,
    title: &'a str,
    sub: &'a str,
) -> Element<'a, Message> {
    let active = active_nav == id;

    let icon_bg = if active {
        t.card
    } else {
        with_alpha(t.sub, 0.12)
    };
    let icon = container(kao_fit(t, kao, 30.0, 17.0))
        .width(Length::Fixed(40.0))
        .height(Length::Fixed(40.0))
        .align_x(Horizontal::Center)
        .align_y(Vertical::Center)
        .style(move |_| container::Style {
            background: Some(Background::Color(icon_bg)),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(11),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        });

    let info = column![
        text(title).size(14).color(t.text).font(bold()),
        text(sub).size(11).color(t.sub),
    ]
    .spacing(1);

    let inner = row![
        icon,
        Space::new().width(12),
        container(info).width(Length::Fill)
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    let row_bg = if active { t.ab1 } else { Color::TRANSPARENT };
    let border_color = if active {
        with_alpha(t.text, 0.45)
    } else {
        Color::TRANSPARENT
    };

    button(inner)
        .padding(Padding::from([8, 9]))
        .width(Length::Fill)
        .on_press(Message::SelectNav(id))
        .style(move |_theme, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed if !active => {
                    hover_tint(Color::TRANSPARENT, t.text)
                }
                _ => row_bg,
            })),
            text_color: t.text,
            border: Border {
                color: border_color,
                width: 1.5,
                radius: Radius::from(13),
            },
            ..button::Style::default()
        })
        .into()
}

/// 1px full-width hairline separating the account card from the nav rows.
fn divider<'a>(t: KaoTheme) -> Element<'a, Message> {
    container(Space::new().width(Length::Fill).height(1))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.border)),
            ..container::Style::default()
        })
        .into()
}

/// Bottom status card for the active hardware account: a connection dot,
/// the device name + connection state, and — when the device isn't
/// connected — a Reconnect button. This is the only affordance that brings
/// a Ledger / Trezor back after it's unplugged; without it the Apps and
/// Swap surfaces simply vanish with no way to restore them.
fn hardware_footer<'a>(t: KaoTheme, status: HardwareStatus) -> Element<'a, Message> {
    let (device, connected) = match status {
        HardwareStatus::Ledger { connected } => ("Ledger", connected),
        HardwareStatus::Trezor { connected } => ("Trezor", connected),
    };

    let dot_color = if connected { t.up } else { t.down };
    let state_text = if connected {
        "connected"
    } else {
        "disconnected"
    };
    let state_color = if connected { t.sub } else { t.down };

    let dot = container(Space::new())
        .width(Length::Fixed(8.0))
        .height(Length::Fixed(8.0))
        .style(move |_| container::Style {
            background: Some(Background::Color(dot_color)),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(4),
            },
            ..container::Style::default()
        });

    let top = row![
        dot,
        Space::new().width(8),
        text(device).size(13).color(t.text).font(bold()),
        Space::new().width(Length::Fill),
        text(state_text)
            .size(11)
            .color(state_color)
            .font(mono())
            .wrapping(Wrapping::None),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    let mut body = column![top].spacing(0).width(Length::Fill);
    if !connected {
        body = body.push(Space::new().height(9));
        body = body.push(reconnect_button(t, device));
    }

    // A disconnected device gets a red-tinted outline so the card reads as a
    // call to action, not just an info line.
    let outline = if connected {
        t.border
    } else {
        with_alpha(t.down, 0.45)
    };

    container(body)
        .padding(Padding::from([10, 12]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card)),
            border: Border {
                color: outline,
                width: 1.0,
                radius: Radius::from(12),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
}

/// Accent "Reconnect" action inside the hardware card. Emits
/// `Message::ReconnectHardware`, which the dashboard escalates to the App to
/// push the matching Ledger / Trezor connect screen.
fn reconnect_button<'a>(t: KaoTheme, device: &'a str) -> Element<'a, Message> {
    button(
        container(
            text(format!("Reconnect {device}"))
                .size(13)
                .color(Color::WHITE)
                .font(bold())
                .wrapping(Wrapping::None),
        )
        .width(Length::Fill)
        .align_x(Horizontal::Center)
        .padding(Padding::from([8, 0])),
    )
    .width(Length::Fill)
    .on_press(Message::ReconnectHardware)
    .style(move |_theme, status| button::Style {
        background: Some(Background::Color(match status {
            button::Status::Hovered | button::Status::Pressed => hover_fill(t.a1, Color::WHITE),
            _ => t.a1,
        })),
        text_color: Color::WHITE,
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: Radius::from(10),
        },
        ..button::Style::default()
    })
    .into()
}

/// Bottom status card: a connection dot (colored by Helios verification
/// state), the active network name, and a privacy line describing whether
/// traffic is tunnelled through the configured SOCKS proxy.
fn network_footer<'a>(
    t: KaoTheme,
    network_name: &'a str,
    verification: VerificationStatus,
) -> Element<'a, Message> {
    let dot_color = match verification {
        VerificationStatus::Verified => t.up,
        VerificationStatus::Fallback | VerificationStatus::Unavailable => t.down,
        VerificationStatus::Connecting => t.sub,
    };

    // Honest privacy posture: the wallet only hides the user's IP when a proxy
    // was actually installed at startup (`proxy_env::installed()`), NOT merely
    // when the setting is enabled. The proxy can only be installed once,
    // single-threaded, at launch, so a mid-session toggle changes stored intent
    // but leaves traffic going direct until a restart — claiming "IP hidden"
    // off the setting alone would over-claim protection in that window. The
    // cool-shades kaomoji is the "you're covered" affordance; otherwise we say
    // plainly that the IP is exposed, and flag when a restart is pending.
    let privacy_line = if proxy_env::installed() {
        match settings::proxy_type() {
            ProxyType::Tor => "via Tor · IP hidden (⌐■_■)",
            ProxyType::Socks => "via SOCKS proxy · IP hidden (⌐■_■)",
        }
    } else if settings::proxy_enabled() {
        // Enabled in settings but not routing this session — restart to apply.
        "IP exposed · restart to route via proxy"
    } else {
        "direct connection · IP exposed"
    };

    let dot = container(Space::new())
        .width(Length::Fixed(8.0))
        .height(Length::Fixed(8.0))
        .style(move |_| container::Style {
            background: Some(Background::Color(dot_color)),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(4),
            },
            ..container::Style::default()
        });

    let top = row![
        dot,
        Space::new().width(8),
        text(network_name).size(13).color(t.text).font(bold()),
    ]
    .align_y(Alignment::Center);

    let body = column![
        top,
        Space::new().height(3),
        text(privacy_line)
            .size(11)
            .color(t.sub)
            .wrapping(Wrapping::None),
    ]
    .spacing(0)
    .width(Length::Fill);

    container(body)
        .padding(Padding::from([10, 12]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card)),
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
