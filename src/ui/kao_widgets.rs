//! Shared Kao-themed widget helpers used across the auth/setup flow and the
//! wallet dashboard. Generic over the message type so each screen can use them
//! with its own local `Message` enum.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use alloy::primitives::{Address, B256};
use iced::advanced::clipboard::Kind as ClipboardKind;
use iced::advanced::widget::{Tree, tree};
use iced::advanced::{Clipboard, Layout, Shell, Widget, layout, renderer};
use iced::border::Radius;
use iced::widget::text::Wrapping;
use iced::widget::{
    Space, button, column, container, mouse_area, row, scrollable, stack, svg, text, text_input,
};
use iced::{
    Alignment, Background, Border, Color, ContentFit, Element, Event, Length, Padding, Rectangle,
    Size, mouse, touch,
};

use crate::chain::Chain;
use crate::net::VerificationStatus;
use crate::ui::kao_theme::{KaoTheme, mix, with_alpha};
use crate::ui::token_logos;

// ── Kaomoji rendering ──────────────────────────────────────────────────────

/// Render a kaomoji as a single unbreakable token. Replaces ASCII spaces with
/// non-breaking spaces (U+00A0) and disables wrapping so the layout never
/// splits a face across lines at an inner space.
pub fn kao_text<'a, M: 'a>(t: KaoTheme, kao: &str, size: f32) -> Element<'a, M> {
    text(kao.replace(' ', "\u{00A0}"))
        .size(size)
        .color(t.text)
        .wrapping(Wrapping::None)
        .into()
}

/// Approximate horizontal advance of `c` in em units (multiply by font size to
/// get pixels). Kaomojis mix ASCII parens, halfwidth/fullwidth katakana,
/// hiragana, geometric/math/box-drawing symbols, and combining marks — these
/// have wildly different widths, so a single average undersizes wide faces and
/// oversizes narrow ones.
fn glyph_advance_em(c: char) -> f32 {
    let cp = c as u32;
    match cp {
        // Combining marks (zero-width).
        0x0300..=0x036F | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0xFE20..=0xFE2F => {
            0.0
        }
        // Spacing modifier letters / IPA-ish small caps used in kaomojis (ᵔ ᵕ ᴥ).
        0x02B0..=0x02FF | 0x1D00..=0x1DBF => 0.5,
        // Fullwidth ranges: CJK punctuation, hiragana, katakana, ideographs,
        // fullwidth ASCII forms.
        0x3000..=0x303F
        | 0x3040..=0x309F
        | 0x30A0..=0x30FF
        | 0x3400..=0x4DBF
        | 0x4E00..=0x9FFF
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6 => 1.0,
        // Halfwidth katakana (ﾉ ｡ ｢ ｣).
        0xFF61..=0xFF9F => 0.55,
        // Arrows, math, box-drawing, geometric shapes, misc symbols, dingbats —
        // most CJK fonts render these at near-fullwidth.
        0x2190..=0x21FF
        | 0x2200..=0x22FF
        | 0x2500..=0x257F
        | 0x2580..=0x259F
        | 0x25A0..=0x25FF
        | 0x2600..=0x26FF
        | 0x2700..=0x27BF => 0.9,
        // Arabic-Indic and Arabic letters used decoratively (٩ ۶).
        0x0600..=0x06FF => 0.6,
        // Default: ASCII Latin / Latin-1 / general punctuation. Slightly
        // conservative so the result errs toward fitting rather than clipping.
        _ => 0.55,
    }
}

/// Pick the largest font size <= `max_size` that keeps `kao` within `max_w`
/// pixels of horizontal space. Sums per-glyph em advances rather than using a
/// single average, since kaomoji width varies a lot between ASCII-only and
/// CJK-heavy faces.
pub fn kao_fit_size(kao: &str, max_w: f32, max_size: f32) -> f32 {
    let total: f32 = kao.chars().map(glyph_advance_em).sum::<f32>().max(0.5);
    (max_w / total).min(max_size).max(6.0)
}

/// `kao_text` variant that shrinks to fit a horizontal width budget.
pub fn kao_fit<'a, M: 'a>(t: KaoTheme, kao: &str, max_w: f32, max_size: f32) -> Element<'a, M> {
    kao_text(t, kao, kao_fit_size(kao, max_w, max_size))
}

// ── Container styles ───────────────────────────────────────────────────────

pub fn fill_style(bg: Color) -> container::Style {
    container::Style {
        background: Some(Background::Color(bg)),
        text_color: None,
        border: Border::default(),
        shadow: Default::default(),
        ..container::Style::default()
    }
}

pub fn card_style(t: KaoTheme) -> container::Style {
    container::Style {
        background: Some(Background::Color(t.card)),
        text_color: Some(t.text),
        border: Border {
            color: t.border,
            width: 1.0,
            radius: Radius::from(14),
        },
        ..container::Style::default()
    }
}

// ── Text-input style ───────────────────────────────────────────────────────

pub fn text_input_style(t: KaoTheme, status: text_input::Status) -> text_input::Style {
    use iced::widget::text_input::Status;
    let border_color = match status {
        Status::Active => t.border,
        Status::Focused { .. } | Status::Hovered => t.a1,
        Status::Disabled => t.border,
    };
    text_input::Style {
        background: Background::Color(t.card_alt),
        border: Border {
            color: border_color,
            width: 1.5,
            radius: Radius::from(12),
        },
        icon: t.sub,
        placeholder: t.sub,
        value: t.text,
        selection: with_alpha(t.a1, 0.3),
    }
}

// ── Scrollable style ───────────────────────────────────────────────────────

/// Kao-themed scrollbar: thin transparent rail with a rounded
/// kao-accent scroller pill that gets brighter on hover/drag. Drop in
/// place of the iced default by passing
/// `move |_, status| kao_scrollable_style(t, status)` to
/// `scrollable.style(...)`.
pub fn kao_scrollable_style(t: KaoTheme, status: scrollable::Status) -> scrollable::Style {
    use iced::widget::scrollable::{Rail, Scroller, Status};

    // Active (idle) scroller — calm, low-contrast so it doesn't fight
    // the content for attention. Hover/drag bumps it to the primary
    // accent.
    let scroller_color = match status {
        Status::Active { .. } => with_alpha(t.a2, 0.55),
        Status::Hovered {
            is_vertical_scrollbar_hovered,
            ..
        } if is_vertical_scrollbar_hovered => t.a1,
        Status::Hovered { .. } => with_alpha(t.a2, 0.75),
        Status::Dragged { .. } => t.a1,
    };

    let rail = Rail {
        background: Some(Background::Color(with_alpha(t.border, 0.25))),
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: Radius::from(4),
        },
        scroller: Scroller {
            background: Background::Color(scroller_color),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(4),
            },
        },
    };

    scrollable::Style {
        container: container::Style::default(),
        vertical_rail: rail,
        horizontal_rail: rail,
        gap: None,
        // The auto-scroll overlay is the on-screen indicator iced shows
        // when a long fling-scroll is decelerating. Tint it so it
        // matches the rest of the chrome instead of leaking the
        // default platform palette.
        auto_scroll: scrollable::AutoScroll {
            background: Background::Color(with_alpha(t.bg, 0.9)),
            border: Border {
                color: with_alpha(t.text, 0.6),
                width: 1.0,
                radius: Radius::from(999),
            },
            shadow: Default::default(),
            icon: with_alpha(t.text, 0.8),
        },
    }
}

// ── Buttons ────────────────────────────────────────────────────────────────

/// Canonical hover background for a solid-fill button (primary action,
/// large copy/CTA buttons, quick-action chips). Lightens `idle` toward
/// `fg` by 10% — strong enough to read on a saturated accent fill.
///
/// Pair with [`hover_tint`] on chip/outline/transparent buttons. Two
/// intensities are intentional: filled buttons need more lift to feel
/// like they responded, while tinted chips at 0.10 read as alarming.
pub fn hover_fill(idle: Color, fg: Color) -> Color {
    mix(idle, fg, 0.10)
}

/// Canonical hover background for a chip / outlined / icon / link
/// button. Tints `idle` toward `intent` by 8%. `intent` is the label's
/// color (`t.text` for neutral, `t.down` for destructive, `t.up` for
/// confirm) so a destructive hover tints red without reading louder
/// than a neutral one.
///
/// When `idle` is fully transparent (e.g. plain text-only icon
/// buttons), falls back to an alpha tint of `intent` since mixing
/// against transparent produces a near-invisible result.
pub fn hover_tint(idle: Color, intent: Color) -> Color {
    if idle.a < 0.01 {
        with_alpha(intent, 0.08)
    } else {
        mix(idle, intent, 0.08)
    }
}

/// Click target for content that has no idle background of its own —
/// "← Back" links, the "Max" amount toggle, "+ Add account" rows, the
/// send-flow contact picker. Wraps `content` in a button styled with a
/// transparent idle background and the canonical hover tint, so the
/// element matches the rest of the app's hover language without any
/// border or chip visuals encroaching on the content's own layout.
///
/// Caller controls `text_color` via the wrapped content. The button's
/// own `text_color` is set to `t.text` only as a fallback for content
/// that doesn't pin its own color.
pub fn ghost_button<'a, M: Clone + 'a>(
    t: KaoTheme,
    content: impl Into<Element<'a, M>>,
) -> button::Button<'a, M> {
    button(content.into())
        .padding(0)
        .style(move |_theme, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => {
                    hover_tint(Color::TRANSPARENT, t.text)
                }
                _ => Color::TRANSPARENT,
            })),
            text_color: t.text,
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(10),
            },
            ..button::Style::default()
        })
}

/// Tinted card with a numbered chip, label and sub-label, used by the
/// initial setup-method picker and the Safe-onboarding "add a new
/// signer" picker. Click anywhere on the card to fire `on_press`.
///
/// `bg` is the card's tint (one of `t.ab1` / `t.ab2` / `t.ab3` for the
/// rotating palette); `accent` matches it (`t.a1` / `t.a2` / `t.a3`).
pub fn method_card<'a, M: Clone + 'a>(
    t: KaoTheme,
    bg: Color,
    accent: Color,
    number: &'a str,
    label: &'a str,
    sub: &'a str,
    on_press: M,
) -> Element<'a, M> {
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

/// Themed checkbox factory. Builds a `checkbox` with Kao's accent
/// fill, accent-tinted border on hover, and a white tick. Caller
/// wires `.label(...)`, `.on_toggle(...)`, and `.size(...)` as
/// usual; this returns the widget after the style is set so iced's
/// builder chain remains ergonomic.
pub fn kao_checkbox<'a, M: 'a>(t: KaoTheme, is_checked: bool) -> iced::widget::Checkbox<'a, M> {
    use iced::widget::checkbox::{self, Status};
    iced::widget::checkbox(is_checked).style(move |_theme, status| {
        let (checked, hovered) = match status {
            Status::Active { is_checked } => (is_checked, false),
            Status::Hovered { is_checked } => (is_checked, true),
            Status::Disabled { is_checked } => (is_checked, false),
        };
        let bg = if checked {
            t.a1
        } else if hovered {
            with_alpha(t.a1, 0.10)
        } else {
            Color::TRANSPARENT
        };
        // Active border on either checked OR hovered, so the tick box
        // visually previews its selectable state on pointer-over.
        let border_color = if checked || hovered { t.a1 } else { t.border };
        checkbox::Style {
            background: Background::Color(bg),
            icon_color: Color::WHITE,
            border: Border {
                color: border_color,
                width: 1.5,
                radius: Radius::from(5),
            },
            text_color: Some(t.text),
        }
    })
}

pub fn primary_button<'a, M: Clone + 'a>(
    t: KaoTheme,
    label: &'a str,
    enabled: bool,
) -> button::Button<'a, M> {
    let bg = if enabled { t.a1 } else { t.border };
    let fg = Color::WHITE;
    button(
        container(text(label.to_string()).size(16).color(fg).font(black()))
            .width(Length::Fill)
            .center_x(Length::Fill)
            .padding(Padding::from([13, 0])),
    )
    .width(Length::Fill)
    .style(move |_theme, status| button::Style {
        background: Some(Background::Color(match status {
            button::Status::Hovered | button::Status::Pressed if enabled => hover_fill(bg, fg),
            _ => bg,
        })),
        text_color: fg,
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: Radius::from(13),
        },
        ..button::Style::default()
    })
}

pub fn secondary_button<'a, M: Clone + 'a>(t: KaoTheme, label: &'a str) -> button::Button<'a, M> {
    button(
        container(text(label.to_string()).size(15).color(t.text).font(bold()))
            .width(Length::Fill)
            .center_x(Length::Fill)
            .padding(Padding::from([13, 0])),
    )
    .width(Length::Fill)
    .style(move |_theme, status| button::Style {
        background: Some(Background::Color(match status {
            button::Status::Hovered | button::Status::Pressed => hover_tint(t.card_alt, t.text),
            _ => t.card_alt,
        })),
        text_color: t.text,
        border: Border {
            color: t.border,
            width: 1.0,
            radius: Radius::from(12),
        },
        ..button::Style::default()
    })
}

/// Compact variant of `secondary_button` for inline affordances (copy
/// chips next to a field label, etc.). Smaller text and padding so it
/// doesn't dominate a row whose primary content is the value below.
pub fn small_secondary_button<'a, M: Clone + 'a>(
    t: KaoTheme,
    label: &'a str,
) -> button::Button<'a, M> {
    button(text(label.to_string()).size(11).color(t.text).font(bold()))
        .padding(Padding::from([4, 10]))
        .style(move |_theme, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => hover_tint(t.card_alt, t.text),
                _ => t.card_alt,
            })),
            text_color: t.text,
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(8),
            },
            ..button::Style::default()
        })
}

/// Subtle text-only button used for "← Back" links in the corner of auth
/// screens. Renders as a plain text label with no background.
pub fn link_button<'a, M: Clone + 'a>(t: KaoTheme, label: &'a str) -> button::Button<'a, M> {
    button(text(label.to_string()).size(13).color(t.sub).font(bold()))
        .padding(Padding::from([6, 10]))
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
                radius: Radius::from(10),
            },
            ..button::Style::default()
        })
}

// ── Avatar (kao bubble) ────────────────────────────────────────────────────

pub fn avatar<'a, M: 'a>(t: KaoTheme, kao: &'a str, size: f32, bg: Color) -> Element<'a, M> {
    let inner_pad: f32 = 4.0;
    let budget = (size - 2.0 * inner_pad).max(8.0);
    let max_font = (size * 0.40).max(10.0);
    let text_color = t.text;
    container(kao_fit(t, kao, budget, max_font))
        .width(Length::Fixed(size))
        .height(Length::Fixed(size))
        .align_x(iced::alignment::Horizontal::Center)
        .align_y(iced::alignment::Vertical::Center)
        .style(move |_| container::Style {
            background: Some(Background::Color(bg)),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(size / 2.0),
            },
            text_color: Some(text_color),
            ..container::Style::default()
        })
        .into()
}

/// Token-row avatar that prefers a bundled SVG for `(chain, contract)`
/// when one is shipped, and otherwise renders the kaomoji bubble. The
/// fallback is intentional — kaomoji on a colored chip is the wallet's
/// identity, so an unknown token shows as a kaomoji, not a sad
/// placeholder.
///
/// Bundled logos are SVGs already shaped as the icon (most are circular
/// on a transparent background), so we render them at the avatar's full
/// size with `ContentFit::Contain` and skip the colored chip behind them.
pub fn token_avatar<'a, M: 'a>(
    t: KaoTheme,
    chain: Chain,
    contract: Option<Address>,
    kao: &'a str,
    size: f32,
    bg: Color,
) -> Element<'a, M> {
    if let Some(handle) = token_logos::handle(chain, contract) {
        return container(
            svg(handle)
                .width(Length::Fixed(size))
                .height(Length::Fixed(size))
                .content_fit(ContentFit::Contain),
        )
        .width(Length::Fixed(size))
        .height(Length::Fixed(size))
        .into();
    }
    avatar(t, kao, size, bg)
}

// ── Auth screen scaffolding ────────────────────────────────────────────────

/// Wraps an auth-flow screen body in a full-window themed background.
pub fn auth_background<'a, M: 'a>(t: KaoTheme, body: Element<'a, M>) -> Element<'a, M> {
    container(body)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(move |_| fill_style(t.bg))
        .into()
}

/// A centered card on the auth-screen background, sized for forms.
pub fn auth_card<'a, M: 'a>(t: KaoTheme, width: f32, content: Element<'a, M>) -> Element<'a, M> {
    let card = container(content)
        .padding(Padding::from([30, 32]))
        .width(Length::Fixed(width))
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(24),
            },
            text_color: Some(t.text),
            shadow: iced::Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, if t.dark { 0.45 } else { 0.10 }),
                offset: iced::Vector::new(0.0, 12.0),
                blur_radius: 36.0,
            },
            ..container::Style::default()
        });
    container(card)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
}

/// A big decorative kaomoji centered above the form. Use as the visual hook
/// at the top of each auth card.
pub fn kao_hero<'a, M: 'a>(t: KaoTheme, kao: &'a str, size: f32) -> Element<'a, M> {
    container(kao_text(t, kao, size))
        .width(Length::Fill)
        .center_x(Length::Fill)
        .into()
}

pub fn screen_title<'a, M: 'a>(t: KaoTheme, label: &'a str) -> Element<'a, M> {
    container(text(label).size(26).color(t.text).font(black()))
        .width(Length::Fill)
        .center_x(Length::Fill)
        .into()
}

pub fn screen_subtitle<'a, M: 'a>(t: KaoTheme, label: &'a str) -> Element<'a, M> {
    container(text(label).size(13).color(t.sub))
        .width(Length::Fill)
        .center_x(Length::Fill)
        .into()
}

pub fn error_text<'a, M: 'a>(t: KaoTheme, msg: &'a str) -> Element<'a, M> {
    container(text(msg).size(12).color(t.down).font(bold()))
        .width(Length::Fill)
        .center_x(Length::Fill)
        .into()
}

pub fn vspace(h: u32) -> Space {
    Space::new().height(h)
}

/// Small status chip that tells the user whether the most recent network
/// reply was light-client verified, came from the unverified raw-RPC
/// fallback, or hasn't returned yet.
///
/// Mirrors the role of kohaku-extension's `NetworkVerificationBadge`. A
/// muted-grey chip means we're still bootstrapping; green means helios
/// served the answer; the theme's `down` color (orange/red-ish) means we
/// fell back to the raw RPC after a helios error and the value isn't proved.
pub fn verification_badge<'a, M: 'a>(t: KaoTheme, status: VerificationStatus) -> Element<'a, M> {
    let (label, dot, fg, bg) = match status {
        VerificationStatus::Verified => ("Verified by Helios", t.up, t.up, with_alpha(t.up, 0.12)),
        VerificationStatus::Fallback => {
            ("Unverified RPC", t.down, t.down, with_alpha(t.down, 0.12))
        }
        VerificationStatus::Unavailable => (
            "Network unavailable",
            t.down,
            t.down,
            with_alpha(t.down, 0.12),
        ),
        VerificationStatus::Connecting => ("Connecting…", t.sub, t.sub, with_alpha(t.sub, 0.10)),
    };
    container(
        row![
            // Solid dot — using a tiny fixed-size container with the dot color.
            container(Space::new())
                .width(Length::Fixed(7.0))
                .height(Length::Fixed(7.0))
                .style(move |_| container::Style {
                    background: Some(Background::Color(dot)),
                    border: Border {
                        color: Color::TRANSPARENT,
                        width: 0.0,
                        radius: Radius::from(4),
                    },
                    ..container::Style::default()
                }),
            Space::new().width(6),
            text(label).size(11).color(fg).font(mono_bold()),
        ]
        .align_y(Alignment::Center),
    )
    .padding(Padding::from([3, 8]))
    .style(move |_| container::Style {
        background: Some(Background::Color(bg)),
        border: Border {
            color: with_alpha(fg, 0.25),
            width: 1.0,
            radius: Radius::from(8),
        },
        text_color: Some(fg),
        ..container::Style::default()
    })
    .into()
}

/// Pill chip used for inline annotations like keyboard hints.
pub fn hint_pill<'a, M: 'a>(t: KaoTheme, label: &'a str) -> Element<'a, M> {
    container(text(label).size(11).color(t.sub).font(mono()))
        .padding(Padding::from([4, 9]))
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card_alt)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(8),
            },
            text_color: Some(t.sub),
            ..container::Style::default()
        })
        .into()
}

// ── Font helpers ───────────────────────────────────────────────────────────

pub fn bold() -> iced::Font {
    iced::Font {
        weight: iced::font::Weight::Bold,
        ..iced::Font::DEFAULT
    }
}

pub fn black() -> iced::Font {
    iced::Font {
        weight: iced::font::Weight::Black,
        ..iced::Font::DEFAULT
    }
}

pub fn mono() -> iced::Font {
    iced::Font {
        family: iced::font::Family::Monospace,
        ..iced::Font::DEFAULT
    }
}

pub fn mono_bold() -> iced::Font {
    iced::Font {
        family: iced::font::Family::Monospace,
        weight: iced::font::Weight::Bold,
        ..iced::Font::DEFAULT
    }
}

pub fn mono_black() -> iced::Font {
    iced::Font {
        family: iced::font::Family::Monospace,
        weight: iced::font::Weight::Black,
        ..iced::Font::DEFAULT
    }
}

#[allow(dead_code)]
pub fn align_center<'a, M: 'a>(content: Element<'a, M>) -> Element<'a, M> {
    container(content)
        .width(Length::Fill)
        .align_x(Alignment::Center)
        .into()
}

// ── Layout primitives ──────────────────────────────────────────────────────

/// Horizontal hairline separator with vertical breathing room.
/// 1px horizontal line with 12px clear space on each side. The earlier
/// implementation set the background color on the outer container with
/// 12px vertical padding inside, which made the WHOLE 25px box render
/// as a solid border-color strip instead of a thin line — looked like
/// a heavy bar on the Send review card. The shape below mirrors
/// `thin_divider` (only the inner 1px container takes the border
/// color) at the original spacing.
#[allow(dead_code)]
pub fn divider<'a, M: 'a>(t: KaoTheme) -> Element<'a, M> {
    let line = container(Space::new().width(Length::Fill).height(1))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.border)),
            ..container::Style::default()
        });
    column![Space::new().height(12), line, Space::new().height(12)].into()
}

/// Tighter sibling of `divider` — just a 1px line, no padding. Used inside
/// dropdown overlays where each row already provides spacing.
pub fn thin_divider<'a, M: 'a>(t: KaoTheme) -> Element<'a, M> {
    let line = container(Space::new().width(Length::Fill).height(1))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.border)),
            ..container::Style::default()
        });
    column![Space::new().height(6), line, Space::new().height(6)].into()
}

/// Render an Ethereum address in full, with each 4-hex-char (2-byte) chunk
/// in a different colour drawn from the active theme.
///
/// The dashboard truncates addresses to `0xabcd…ef01` for incidental
/// display (header pill, history rows) — but on confirmation screens the
/// user is about to *act* on the address, so the entire 40-hex-char form
/// must be visible. Splitting into 10 short chunks (rather than 5 long
/// ones) makes within-chunk homoglyph swaps (`0`/`O`, `1`/`l`) easier to
/// spot: a swapped char only has 3 neighbours of its own colour to hide
/// behind, and the closer colour boundaries also make whole-chunk
/// substitutions ("middle of the address looks fine at a glance") much
/// harder to pull off.
///
/// Address bytes are rendered as the EIP-55 checksum form
/// (`addr.to_checksum(None)`).
/// The address is interactive: **hovering** greys the whole thing (a clear
/// "this does something" affordance) and the cursor turns into a pointer;
/// **clicking** copies the EIP-55 checksum address to the clipboard.
///
/// The clipboard write happens inside the widget, but on click it also publishes
/// `M::copy_kick()` (see [`CopyKick`]) — a no-op message whose only job is to run
/// the host's update loop so the bottom-right "Copied!" toast's animation
/// subscription starts. Without it the click would change no app state and iced
/// would never re-evaluate the subscription, leaving the toast frozen invisible.
pub fn colored_address<'a, M: CopyKick + 'a>(t: KaoTheme, addr: Address) -> Element<'a, M> {
    CopyableAddress::new(
        address_row(t, addr, false),
        address_row(t, addr, true),
        addr.to_checksum(None),
    )
    .into()
}

/// Implemented by every screen `Message` that hosts a [`colored_address`]. The
/// widget publishes `copy_kick()` after a click-to-copy purely to wake the host's
/// update loop (a click otherwise produces no message, so the toast-animation
/// subscription would never start). The default is `None` (no kick) for screens
/// that don't show the toast; the dashboard panes override it with a no-op
/// variant they ignore in `update`.
pub trait CopyKick: Sized {
    fn copy_kick() -> Option<Self> {
        None
    }
}

/// Build the chunked-address row. `grey` paints every chunk in the muted colour
/// (the hover state); otherwise each 4-char chunk gets its palette colour.
fn address_row<'a, M: 'a>(t: KaoTheme, addr: Address, grey: bool) -> Element<'a, M> {
    let checksum = addr.to_checksum(None); // "0xAbCd...EF01" (42 chars)
    debug_assert_eq!(checksum.len(), 42);
    // `.get()` rather than `[2..]` / `[start..start + 4]`: the lengths above are
    // structurally guaranteed for a 20-byte Address, but an unchecked slice
    // would panic the whole GUI in a release build (where the debug_assert is
    // stripped) if that ever stopped holding. A short chunk renders empty.
    let body = checksum.get(2..).unwrap_or(""); // drop the "0x"

    let chunk_colors = chunk_palette(t);
    let mut spans = row![text("0x").size(14).color(t.sub).font(mono_bold())].spacing(0);

    for (i, color) in chunk_colors.iter().enumerate() {
        let start = i * 4;
        let chunk = body.get(start..start + 4).unwrap_or("").to_string();
        let color = if grey { t.sub } else { *color };
        spans = spans.push(text(chunk).size(14).color(color).font(mono_bold()));
    }

    container(spans)
        .width(Length::Fill)
        .center_x(Length::Fill)
        .padding(Padding::from([2, 0]))
        .into()
}

/// How long the bottom-right "Copied!" toast stays up after an address copy.
pub const COPY_TOAST: Duration = Duration::from_millis(1400);

/// Wall-clock instant of the most recent address copy, set by [`CopyableAddress`]
/// when it writes to the clipboard. The dashboard reads it to drive a transient
/// "Copied!" toast. It's a process-global rather than threaded UI state because
/// the copy happens inside a leaf widget that writes the clipboard directly and
/// has no message channel to the app — this is the matching direct signal back.
static LAST_COPY: Mutex<Option<Instant>> = Mutex::new(None);

/// Record that something was just copied — a `colored_address` click or a Copy
/// button (via `arm_clipboard_clear`). Drives the "Copied!" toast.
pub fn mark_copied() {
    if let Ok(mut g) = LAST_COPY.lock() {
        *g = Some(Instant::now());
    }
}

/// Progress (`0.0 → 1.0`) through the [`COPY_TOAST`] window since the last copy,
/// or `None` once the window has elapsed (or nothing has been copied). Drives
/// both the toast's fade and the redraw tick that dismisses it.
pub fn copy_toast_progress() -> Option<f32> {
    let at = (*LAST_COPY.lock().ok()?)?;
    let elapsed = at.elapsed();
    (elapsed < COPY_TOAST)
        .then(|| (elapsed.as_secs_f32() / COPY_TOAST.as_secs_f32()).clamp(0.0, 1.0))
}

/// Per-instance hover state for [`CopyableAddress`]. Tracked so a hover
/// transition can request a single repaint (the widget derives its drawn colour
/// from the cursor, so it must repaint when the cursor enters/leaves).
#[derive(Default)]
struct AddressHoverState {
    hovered: bool,
}

/// A clickable, hover-greying address. Holds two pre-built rows — `children[0]`
/// in palette colours, `children[1]` all-grey — and draws the grey one while the
/// cursor is over it. A left click copies `to_copy` to the system clipboard via
/// the widget's own `Clipboard` handle, so callers don't thread a copy message.
struct CopyableAddress<'a, Message, Theme, Renderer> {
    /// `[normal, grey]` — identical layout, so either can be drawn under the
    /// single layout node this widget produces.
    children: [Element<'a, Message, Theme, Renderer>; 2],
    to_copy: String,
}

impl<'a, Message, Theme, Renderer> CopyableAddress<'a, Message, Theme, Renderer> {
    fn new(
        normal: Element<'a, Message, Theme, Renderer>,
        grey: Element<'a, Message, Theme, Renderer>,
        to_copy: String,
    ) -> Self {
        Self {
            children: [normal, grey],
            to_copy,
        }
    }
}

impl<Message, Theme, Renderer> Widget<Message, Theme, Renderer>
    for CopyableAddress<'_, Message, Theme, Renderer>
where
    Renderer: renderer::Renderer,
    Message: CopyKick,
{
    fn tag(&self) -> tree::Tag {
        tree::Tag::of::<AddressHoverState>()
    }

    fn state(&self) -> tree::State {
        tree::State::new(AddressHoverState::default())
    }

    fn children(&self) -> Vec<Tree> {
        self.children.iter().map(Tree::new).collect()
    }

    fn diff(&self, tree: &mut Tree) {
        tree.diff_children(&self.children);
    }

    fn size(&self) -> Size<Length> {
        self.children[0].as_widget().size()
    }

    fn layout(
        &mut self,
        tree: &mut Tree,
        renderer: &Renderer,
        limits: &layout::Limits,
    ) -> layout::Node {
        // Lay out both rows (so each row's text state is populated for drawing);
        // they're identical, so the normal row's node positions either.
        let (normal, grey) = self.children.split_at_mut(1);
        let node = normal[0]
            .as_widget_mut()
            .layout(&mut tree.children[0], renderer, limits);
        let _ = grey[0]
            .as_widget_mut()
            .layout(&mut tree.children[1], renderer, limits);
        node
    }

    fn update(
        &mut self,
        tree: &mut Tree,
        event: &Event,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        _renderer: &Renderer,
        clipboard: &mut dyn Clipboard,
        shell: &mut Shell<'_, Message>,
        _viewport: &Rectangle,
    ) {
        let is_over = cursor.is_over(layout.bounds());
        let state = tree.state.downcast_mut::<AddressHoverState>();
        if state.hovered != is_over {
            state.hovered = is_over;
            // Cursor crossed the boundary — repaint so the grey/normal swap shows.
            shell.request_redraw();
        }
        if is_over
            && matches!(
                event,
                Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left))
                    | Event::Touch(touch::Event::FingerPressed { .. })
            )
        {
            clipboard.write(ClipboardKind::Standard, self.to_copy.clone());
            mark_copied();
            shell.capture_event();
            shell.request_redraw();
            // Publish the host's no-op kick message so its update loop runs and
            // the "Copied!" toast's animation subscription starts — a click on
            // its own changes no app state, so nothing would otherwise wake it.
            if let Some(kick) = Message::copy_kick() {
                shell.publish(kick);
            }
        }
    }

    fn mouse_interaction(
        &self,
        _tree: &Tree,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        _viewport: &Rectangle,
        _renderer: &Renderer,
    ) -> mouse::Interaction {
        if cursor.is_over(layout.bounds()) {
            mouse::Interaction::Pointer
        } else {
            mouse::Interaction::None
        }
    }

    fn draw(
        &self,
        tree: &Tree,
        renderer: &mut Renderer,
        theme: &Theme,
        style: &renderer::Style,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        viewport: &Rectangle,
    ) {
        // Grey row while hovered, palette row otherwise — both share `layout`.
        let idx = usize::from(cursor.is_over(layout.bounds()));
        self.children[idx].as_widget().draw(
            &tree.children[idx],
            renderer,
            theme,
            style,
            layout,
            cursor,
            viewport,
        );
    }
}

impl<'a, Message, Theme, Renderer> From<CopyableAddress<'a, Message, Theme, Renderer>>
    for Element<'a, Message, Theme, Renderer>
where
    Message: CopyKick + 'a,
    Theme: 'a,
    Renderer: 'a + renderer::Renderer,
{
    fn from(widget: CopyableAddress<'a, Message, Theme, Renderer>) -> Self {
        Element::new(widget)
    }
}

/// Ten distinct accent colours for 4-hex-char chunks. Each adjacent
/// pair flips on *both* axes — hue (rotating through the three accents
/// with stride 2) and lightness (alternating bright / deep). That dual
/// flip makes neighbours pop apart far more than a smooth gradient
/// does, and keeps homoglyph swaps from blending into a same-coloured
/// neighbour. Shared by [`colored_address`] (10 chunks, exactly one
/// cycle) and [`colored_hash_copyable`] (16 chunks, wraps — the 9→0 seam still
/// flips lightness within the a1 hue, so no two neighbours merge).
pub(crate) fn chunk_palette(t: KaoTheme) -> [Color; 10] {
    [
        t.a1,                    // 0: bright a1
        mix(t.a3, t.text, 0.55), // 1: deep a3
        t.a2,                    // 2: bright a2
        mix(t.a1, t.text, 0.55), // 3: deep a1
        t.a3,                    // 4: bright a3
        mix(t.a2, t.text, 0.55), // 5: deep a2
        mix(t.a1, t.a3, 0.5),    // 6: bright a1+a3
        mix(t.a2, t.text, 0.75), // 7: very deep a2
        mix(t.a2, t.a3, 0.5),    // 8: bright a2+a3
        mix(t.a1, t.text, 0.75), // 9: very deep a1
    ]
}

/// Render a 32-byte hash (safeTxHash, message hash) in full, chunked
/// like [`colored_address`]: 64 hex chars split into sixteen 4-char
/// chunks over two rows of eight, each chunk coloured from the shared
/// palette.
///
/// This is the verification surface for multisig signing — the same
/// grouping Ledger/Trezor and the Safe web app use when they display a
/// safeTxHash, so a user can compare chunk-by-chunk across devices and
/// co-signers. Never truncated: a prefix/suffix display is exactly what
/// a hash-collision phisher relies on.
/// A clickable, hover-greying hash — a left click copies the full `0x…` hex to
/// the clipboard, exactly like [`colored_address`]. Used where the user must
/// copy the value to compare it elsewhere (the Safe review's `safeTxHash`, which
/// has to match on every signing device and co-signer).
pub fn colored_hash_copyable<'a, M: CopyKick + 'a>(t: KaoTheme, hash: B256) -> Element<'a, M> {
    CopyableAddress::new(
        colored_hash_body(t, hash, false),
        colored_hash_body(t, hash, true),
        format!("{hash:#x}"),
    )
    .into()
}

/// The two-row chunked hash render. `grey` paints every chunk in the muted
/// colour (the copyable widget's hover state); otherwise each 4-char chunk gets
/// its palette colour.
fn colored_hash_body<'a, M: 'a>(t: KaoTheme, hash: B256, grey: bool) -> Element<'a, M> {
    let hex = format!("{hash:x}"); // 64 lowercase hex chars, no 0x
    debug_assert_eq!(hex.len(), 64);
    let chunk_colors = chunk_palette(t);

    let mut lines = column![].spacing(2);
    for line_idx in 0..2 {
        let mut spans = row![].spacing(0);
        if line_idx == 0 {
            spans = spans.push(text("0x").size(13).color(t.sub).font(mono_bold()));
        } else {
            // Two invisible chars keep the second row's chunks aligned
            // with the first row's (which carries the "0x" prefix).
            spans = spans.push(text("  ").size(13).font(mono_bold()));
        }
        for i in (line_idx * 8)..(line_idx * 8 + 8) {
            let start = i * 4;
            // `.get()` over `[start..start + 4]`: see `colored_address` — avoids
            // a release-build GUI panic if the hash hex is ever not 64 chars.
            let chunk = hex.get(start..start + 4).unwrap_or("").to_string();
            let color = if grey { t.sub } else { chunk_colors[i % 10] };
            spans = spans.push(text(chunk).size(13).color(color).font(mono_bold()));
        }
        lines = lines.push(spans);
    }

    container(lines)
        .width(Length::Fill)
        .center_x(Length::Fill)
        .padding(Padding::from([2, 0]))
        .into()
}

/// Bordered section card: an uppercase caption over the body. Groups
/// modal content into scannable units — the Safe review and Safe-tx
/// detail modals build their TRANSACTION / VERIFY / SIMULATION / …
/// stacks out of these. (Distinct from [`section`], the settings-page
/// header block.)
pub fn section_card<'a, M: 'a>(t: KaoTheme, title: &str, body: Element<'a, M>) -> Element<'a, M> {
    container(
        column![
            text(title.to_string())
                .size(11)
                .color(t.sub)
                .font(mono_bold()),
            Space::new().height(8),
            body,
        ]
        .width(Length::Fill),
    )
    .padding(Padding::from([12, 14]))
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

/// Themed card with an avatar + title/subtitle header and an arbitrary body.
/// Used for settings sections and similar grouped panels.
pub fn section<'a, M: 'a>(
    t: KaoTheme,
    title: &'a str,
    kao: &'a str,
    sub: &'a str,
    body: Element<'a, M>,
) -> Element<'a, M> {
    let head = row![
        avatar(t, kao, 32.0, t.ab2),
        Space::new().width(10),
        column![
            text(title).size(13).color(t.text).font(bold()),
            text(sub).size(11).color(t.sub),
        ]
        .spacing(0)
        .width(Length::Fill),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    container(column![head, Space::new().height(10), body].spacing(0))
        .padding(Padding::from([14, 16]))
        .width(Length::Fill)
        .style(move |_| card_style(t))
        .into()
}

/// Modal box with backdrop, animation-aware sizing/opacity, and click-out
/// dismiss. `on_backdrop` is the message emitted when the user clicks the dim
/// area outside the box; `on_box_click` is emitted (and ignored by the caller)
/// when the user clicks inside the box, so the backdrop click handler doesn't
/// fire from a child press bubbling up.
pub fn modal_wrapper<'a, M: Clone + 'a>(
    t: KaoTheme,
    width: f32,
    progress: f32,
    on_backdrop: M,
    on_box_click: M,
    content: Element<'a, M>,
) -> Element<'a, M> {
    let progress = progress.clamp(0.0, 1.0);

    // Pseudo-scale: shrink width during the transition. Iced 0.14 has no
    // widget transforms, so this is a real layout change — kept gentle (8%)
    // and bounded so text inside doesn't reflow noticeably.
    const SCALE_MIN: f32 = 0.92;
    let scale = SCALE_MIN + (1.0 - SCALE_MIN) * progress;
    let scaled_width = width * scale;

    // Box surface fades in. We can't fade text colors without threading
    // `progress` through every text() call, so we keep the background mostly
    // opaque (clamped to 0.55..1.0) — gives a "materializing" feel without
    // leaving text floating against the dimmed app behind it.
    let bg_alpha = 0.55 + 0.45 * progress;
    let border_alpha = progress;
    let shadow_alpha = (if t.dark { 0.6 } else { 0.14 }) * progress;

    let box_ = container(content)
        .padding(32)
        .width(Length::Fixed(scaled_width))
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(t.card, bg_alpha))),
            border: Border {
                color: with_alpha(t.border, border_alpha),
                width: 1.0,
                radius: Radius::from(24),
            },
            text_color: Some(t.text),
            shadow: iced::Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, shadow_alpha),
                offset: iced::Vector::new(0.0, 24.0),
                blur_radius: 64.0,
            },
            ..container::Style::default()
        });

    // `interaction(Idle)` on both layers makes iced's `stack` "levitate"
    // the cursor for widgets behind the modal so hover styles below
    // (e.g. activity-row buttons) don't light up while the modal is open.
    // See iced_widget::stack::update — the cursor is levitated only when
    // an upper layer reports a non-`None` mouse interaction.
    let positioned = mouse_area(box_)
        .on_press(on_box_click)
        .interaction(iced::mouse::Interaction::Idle);

    let backdrop_alpha = (if t.dark { 0.55 } else { 0.35 }) * progress;
    let backdrop = mouse_area(
        container(Space::new().width(Length::Fill).height(Length::Fill))
            .width(Length::Fill)
            .height(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(Color::from_rgba(
                    0.0,
                    0.0,
                    0.0,
                    backdrop_alpha,
                ))),
                ..container::Style::default()
            }),
    )
    .on_press(on_backdrop)
    .interaction(iced::mouse::Interaction::Idle);

    let modal_layer = container(positioned)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill);

    stack![backdrop, modal_layer].into()
}

// ── Wizard widgets ──────────────────────────────────────────────────────────

/// Privacy badge variant — drives the colour and icon of the badge chip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadgeKind {
    /// Green check — private, recommended.
    Good,
    /// Yellow/amber caution.
    Caution,
    /// Red/orange warning — leaks data.
    Warning,
    /// Neutral/informational.
    Info,
}

/// Colored status chip with a prefix symbol and a short label. Used by the
/// network wizard to annotate option cards with privacy posture hints.
pub fn privacy_badge<'a, M: 'a>(t: KaoTheme, kind: BadgeKind, label: &str) -> Element<'a, M> {
    let (prefix, fg, bg) = match kind {
        BadgeKind::Good => ("\u{2713}", t.up, with_alpha(t.up, 0.12)),
        BadgeKind::Caution => (
            "!",
            Color::from_rgb(0.85, 0.65, 0.0),
            with_alpha(Color::from_rgb(0.85, 0.65, 0.0), 0.12),
        ),
        BadgeKind::Warning => ("!", t.down, with_alpha(t.down, 0.12)),
        BadgeKind::Info => ("\u{2022}", t.sub, with_alpha(t.sub, 0.10)),
    };
    let label_owned = format!("{prefix} {label}");
    container(text(label_owned).size(10).color(fg).font(mono_bold()))
        .padding(Padding::from([2, 7]))
        .style(move |_| container::Style {
            background: Some(Background::Color(bg)),
            border: Border {
                color: with_alpha(fg, 0.25),
                width: 1.0,
                radius: Radius::from(6),
            },
            text_color: Some(fg),
            ..container::Style::default()
        })
        .into()
}

/// Toggle switch built from containers + mouse_area. Pill-shaped track with
/// a positioned circle that snaps between off/on. `on_toggle` fires when the
/// user clicks anywhere on the track.
pub fn kao_toggle<'a, M: Clone + 'a>(t: KaoTheme, is_on: bool, on_toggle: M) -> Element<'a, M> {
    let track_w: f32 = 44.0;
    let track_h: f32 = 24.0;
    let knob_size: f32 = 18.0;
    let knob_pad: f32 = 3.0;

    let (track_bg, knob_bg) = if is_on {
        (t.a1, Color::WHITE)
    } else {
        (with_alpha(t.sub, 0.30), with_alpha(t.text, 0.7))
    };

    let knob = container(Space::new())
        .width(Length::Fixed(knob_size))
        .height(Length::Fixed(knob_size))
        .style(move |_| container::Style {
            background: Some(Background::Color(knob_bg)),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(knob_size / 2.0),
            },
            ..container::Style::default()
        });

    // Position the knob left (off) or right (on) inside the track.
    let left_pad = if is_on {
        track_w - knob_size - knob_pad
    } else {
        knob_pad
    };

    let track = container(container(knob).padding(Padding {
        top: knob_pad,
        right: 0.0,
        bottom: 0.0,
        left: left_pad,
    }))
    .width(Length::Fixed(track_w))
    .height(Length::Fixed(track_h))
    .style(move |_| container::Style {
        background: Some(Background::Color(track_bg)),
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: Radius::from(track_h / 2.0),
        },
        ..container::Style::default()
    });

    mouse_area(track)
        .on_press(on_toggle)
        .interaction(iced::mouse::Interaction::Pointer)
        .into()
}

/// Colored fill bar for the privacy posture meter. `fraction` is 0.0–1.0.
/// Outer container (track) with inner container (fill) at variable width.
pub fn progress_bar<'a, M: 'a>(t: KaoTheme, fraction: f32, fill_color: Color) -> Element<'a, M> {
    let bar_h: f32 = 8.0;
    let fraction = fraction.clamp(0.0, 1.0);
    let track_bg = with_alpha(t.sub, 0.15);

    // The fill is a nested container whose width is set relative to parent
    // via Length::FillPortion. We use a two-column row trick: fill gets
    // `portion` parts, remainder gets `(100 - portion)` parts.
    let portion = (fraction * 100.0).round() as u16;
    let remainder = 100u16.saturating_sub(portion);

    let fill: Element<'a, M> = container(Space::new())
        .width(Length::FillPortion(portion.max(1)))
        .height(Length::Fixed(bar_h))
        .style(move |_| container::Style {
            background: Some(Background::Color(fill_color)),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(bar_h / 2.0),
            },
            ..container::Style::default()
        })
        .into();

    let empty: Element<'a, M> = Space::new()
        .width(Length::FillPortion(if remainder == 0 {
            1
        } else {
            remainder
        }))
        .height(bar_h)
        .into();

    let inner: Element<'a, M> = if portion >= 100 {
        row![fill].width(Length::Fill).into()
    } else if portion == 0 {
        row![empty].width(Length::Fill).into()
    } else {
        row![fill, empty].width(Length::Fill).into()
    };

    container(inner)
        .width(Length::Fill)
        .height(Length::Fixed(bar_h))
        .style(move |_| container::Style {
            background: Some(Background::Color(track_bg)),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(bar_h / 2.0),
            },
            ..container::Style::default()
        })
        .into()
}

// ── Kaomoji palettes ───────────────────────────────────────────────────────

/// Stable kaomoji for asset/portfolio rows; cycles after 7 entries.
pub fn kaomoji_for_index(idx: usize) -> &'static str {
    const KAOS: &[&str] = &[
        "ヽ(・∀・)ﾉ",
        "(ᵔᴥᵔ)",
        "(*´∇`*)",
        "(・ω・)",
        "٩(◕‿◕｡)۶",
        "(◕‿◕✿)",
        "(˘ᵕ˘)",
    ];
    KAOS[idx % KAOS.len()]
}

/// Stable kaomoji for the account dropdown; cycles after 8 entries. Distinct
/// palette from `kaomoji_for_index` so accounts don't collide visually with
/// the asset rows on the same screen.
pub fn kaomoji_for_account(idx: usize) -> &'static str {
    const KAOS: &[&str] = &[
        "(◕‿◕)",
        "(´｡• ᵕ •｡`)",
        "ヽ(・∀・)ﾉ",
        "(￣ω￣)",
        "( ´ ▽ ` )ﾉ",
        "(*´∇`*)",
        "٩(◕‿◕｡)۶",
        "(˘ᵕ˘)",
    ];
    KAOS[idx % KAOS.len()]
}

/// A 7-cell track with a 3-bullet cluster bouncing across it, sampled from
/// `elapsed` seconds — a font-safe "alive" indicator for indeterminate waits
/// (the ZK proving screen and the sign-review "waiting for a signature" state).
/// Uses `•`/`·` (both broadly supported) so it renders in the generic Monospace
/// family without relying on braille glyphs.
pub fn bullet_wave(elapsed: f32) -> String {
    const CELLS: usize = 7;
    const CLUSTER: usize = 3;
    let span = CELLS - CLUSTER; // head positions 0..=span
    let phase = (elapsed * 6.0) as usize % (span * 2); // ping-pong period
    let head = if phase <= span {
        phase
    } else {
        span * 2 - phase
    };
    (0..CELLS)
        .map(|i| {
            if i >= head && i < head + CLUSTER {
                '•'
            } else {
                '·'
            }
        })
        .collect()
}
