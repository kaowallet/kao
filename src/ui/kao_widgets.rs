//! Shared Kao-themed widget helpers used across the auth/setup flow and the
//! wallet dashboard. Generic over the message type so each screen can use them
//! with its own local `Message` enum.

use alloy::primitives::Address;
use iced::border::Radius;
use iced::widget::text::Wrapping;
use iced::widget::{Space, button, column, container, image, mouse_area, row, stack, text, text_input};
use iced::{Alignment, Background, Border, Color, ContentFit, Element, Length, Padding};

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

// ── Buttons ────────────────────────────────────────────────────────────────

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
            button::Status::Hovered | button::Status::Pressed if enabled => mix(bg, fg, 0.1),
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
            button::Status::Hovered | button::Status::Pressed => mix(t.card_alt, t.text, 0.06),
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

/// Subtle text-only button used for "← Back" links in the corner of auth
/// screens. Renders as a plain text label with no background.
pub fn link_button<'a, M: Clone + 'a>(t: KaoTheme, label: &'a str) -> button::Button<'a, M> {
    button(text(label.to_string()).size(13).color(t.sub).font(bold()))
        .padding(Padding::from([6, 10]))
        .style(move |_theme, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => with_alpha(t.text, 0.06),
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

/// Token-row avatar that prefers a bundled trustwallet PNG when one is
/// shipped for `logo_id`, and otherwise renders the kaomoji bubble. The
/// fallback is intentional — kaomoji on a colored chip is the wallet's
/// identity, so an unknown token shows as a kaomoji, not a sad
/// placeholder.
///
/// Trustwallet logos are square PNGs with the icon already shaped (most
/// are circular on a transparent background), so we render them at the
/// avatar's full size with `ContentFit::Contain` and skip the colored
/// chip behind them.
pub fn token_avatar<'a, M: 'a>(
    t: KaoTheme,
    logo_id: Option<&str>,
    kao: &'a str,
    size: f32,
    bg: Color,
) -> Element<'a, M> {
    if let Some(handle) = logo_id.and_then(token_logos::handle) {
        return container(
            image(handle)
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
pub fn divider<'a, M: 'a>(t: KaoTheme) -> Element<'a, M> {
    container(Space::new().width(Length::Fill).height(1))
        .width(Length::Fill)
        .padding(Padding::from([12, 0]))
        .style(move |_| container::Style {
            background: Some(Background::Color(t.border)),
            ..container::Style::default()
        })
        .into()
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
pub fn colored_address<'a, M: 'a>(t: KaoTheme, addr: Address) -> Element<'a, M> {
    let checksum = addr.to_checksum(None); // "0xAbCd...EF01" (42 chars)
    debug_assert_eq!(checksum.len(), 42);
    let body = &checksum[2..]; // drop the "0x"

    // Ten distinct accent colours for the ten 2-byte chunks. Each
    // adjacent pair flips on *both* axes — hue (rotating through the
    // three accents with stride 2) and lightness (alternating bright /
    // deep). That dual flip makes neighbours pop apart far more than a
    // smooth gradient does, and keeps homoglyph swaps from blending into
    // a same-coloured neighbour.
    let chunk_colors: [Color; 10] = [
        t.a1,                          // 0: bright a1
        mix(t.a3, t.text, 0.55),       // 1: deep a3
        t.a2,                          // 2: bright a2
        mix(t.a1, t.text, 0.55),       // 3: deep a1
        t.a3,                          // 4: bright a3
        mix(t.a2, t.text, 0.55),       // 5: deep a2
        mix(t.a1, t.a3, 0.5),          // 6: bright a1+a3
        mix(t.a2, t.text, 0.75),       // 7: very deep a2
        mix(t.a2, t.a3, 0.5),          // 8: bright a2+a3
        mix(t.a1, t.text, 0.75),       // 9: very deep a1
    ];

    let mut spans = row![
        text("0x").size(14).color(t.sub).font(mono_bold())
    ]
    .spacing(0);

    for (i, color) in chunk_colors.iter().enumerate() {
        let start = i * 4;
        let chunk = body[start..start + 4].to_string();
        spans = spans.push(
            text(chunk)
                .size(14)
                .color(*color)
                .font(mono_bold()),
        );
    }

    container(spans)
        .width(Length::Fill)
        .center_x(Length::Fill)
        .padding(Padding::from([2, 0]))
        .into()
}

/// "Label …….. value" row used in the Send review step. `big` bumps the value
/// font; `muted` greys it.
pub fn review_row<'a, M: 'a>(
    t: KaoTheme,
    label: &str,
    value: &str,
    big: bool,
    muted: bool,
) -> Element<'a, M> {
    let value_size = if big { 17 } else { 14 };
    let value_color = if muted { t.sub } else { t.text };
    let value_font = if big { mono_black() } else { mono_bold() };
    row![
        text(label.to_string()).size(13).color(t.sub),
        Space::new().width(Length::Fill),
        text(value.to_string())
            .size(value_size)
            .color(value_color)
            .font(value_font),
    ]
    .align_y(Alignment::Center)
    .padding(Padding::from([2, 0]))
    .width(Length::Fill)
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

    let positioned = mouse_area(box_).on_press(on_box_click);

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
    .on_press(on_backdrop);

    let modal_layer = container(positioned)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill);

    stack![backdrop, modal_layer].into()
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
