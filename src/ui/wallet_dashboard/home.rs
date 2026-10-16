//! Home pane — balance hero, quick actions (Send/Receive/Swap), live assets list.

use std::time::{SystemTime, UNIX_EPOCH};

use iced::border::Radius;
use iced::widget::{Space, button, column, container, row, text};
use iced::{Alignment, Background, Border, Color, Element, Length, Padding};

use super::activity::format_relative;
use super::{MOOD, Message};
use crate::chain::NetworkId;
use crate::portfolio::LiveToken;
use crate::safe::service::{PendingSafeTx, SafeTxState};
use crate::ui::kao_theme::{KaoTheme, mix, with_alpha};
use crate::ui::kao_widgets::{
    avatar, bold, card_style, hover_fill, hover_tint, kao_fit, kao_scrollable_style, kao_text,
    kaomoji_for_index, mono, mono_black, mono_bold, token_avatar,
};
use crate::wallet::short_address;

/// Kaomoji on a pending-Safe-tx row — a little "waiting" face, distinct
/// from the send/receive faces in the activity feed.
const PENDING_KAO: &str = "(・–・)";

#[allow(clippy::too_many_arguments)]
pub fn view<'a>(
    t: KaoTheme,
    can_send: bool,
    can_swap: bool,
    portfolio: &'a [LiveToken],
    portfolio_loading: bool,
    portfolio_refreshing: bool,
    safe_pending: &'a [PendingSafeTx],
    safe_pending_loading: bool,
    safe_pending_error: Option<&'a str>,
) -> Element<'a, Message> {
    let hero = balance_hero(t, portfolio);
    let actions = quick_actions(t, can_send, can_swap);
    let assets_label_row = row![
        text("ASSETS").size(11).color(t.sub).font(bold()),
        Space::new().width(Length::Fill),
        refresh_button(t, portfolio_refreshing),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);
    let mut assets = column![].spacing(5);
    if portfolio_loading {
        assets = assets.push(
            container(text("Loading portfolio…").size(13).color(t.sub))
                .padding(Padding::from([20, 0]))
                .width(Length::Fill)
                .center_x(Length::Fill),
        );
    } else {
        for (i, tk) in portfolio.iter().enumerate() {
            assets = assets.push(token_row(t, tk, i));
        }
    }

    let mut content = column![hero, Space::new().height(18), actions];

    // Pending Safe queue — only present in Safe mode (the dashboard
    // leaves the slice empty / flags false in EOA mode). Sits between the
    // quick actions and the asset list so a queued multisig tx is the
    // first thing an owner sees.
    if let Some(section) =
        pending_section(t, safe_pending, safe_pending_loading, safe_pending_error)
    {
        content = content.push(Space::new().height(18)).push(section);
    }

    let content = content
        .push(Space::new().height(18))
        .push(assets_label_row)
        .push(Space::new().height(10))
        .push(assets);

    iced::widget::scrollable(
        container(content)
            .padding(Padding::from([22, 24]))
            .width(Length::Fill),
    )
    .height(Length::Fill)
    .width(Length::Fill)
    .style(move |_, s| kao_scrollable_style(t, s))
    .into()
}

fn balance_hero<'a>(t: KaoTheme, portfolio: &[LiveToken]) -> Element<'a, Message> {
    let total: f64 = portfolio.iter().map(|tk| tk.usd_value).sum();
    let balance_text = format!("${}", format_usd(total));

    let left = column![
        text("TOTAL BALANCE").size(12).color(t.sub).font(bold()),
        Space::new().height(6),
        text(balance_text).size(42).color(t.text).font(mono_black()),
    ]
    .spacing(0);

    // Right-half of the hero. Width-bounded so the kaomoji shrinks instead of
    // wrapping at internal spaces when the window is narrow. FillPortion pairs
    // with the implicit FillPortion(1) on `left` so both sides compete for
    // space proportionally.
    let mood_big = container(kao_fit(t, MOOD, 220.0, 62.0))
        .width(Length::FillPortion(2))
        .align_x(iced::alignment::Horizontal::Right);

    let hero_row = row![container(left).width(Length::FillPortion(3)), mood_big,]
        .align_y(Alignment::Center)
        .width(Length::Fill);

    let gradient_tint = mix(t.a1, t.a2, 0.5);
    container(hero_row)
        .padding(Padding::from([26, 28]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(gradient_tint, 0.18))),
            border: Border {
                color: with_alpha(t.a1, 0.22),
                width: 1.0,
                radius: Radius::from(20),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
}

/// Refresh-balances chip. Sits at the right end of the ASSETS row.
/// While a user-initiated refresh is in flight, the glyph swaps to
/// a "loading" kaomoji and the click is suppressed so a rapid
/// double-tap can't queue two parallel fetches against the same
/// indexer.
fn refresh_button<'a>(t: KaoTheme, refreshing: bool) -> Element<'a, Message> {
    let (glyph, color) = if refreshing {
        ("(；・∀・) refreshing", t.sub)
    } else {
        ("↻ refresh", t.a1)
    };
    let label = text(glyph).size(11).color(color).font(bold());
    let bg = Color::TRANSPARENT;
    let mut b =
        button(container(label).padding(Padding::from([3, 8]))).style(move |_theme, status| {
            button::Style {
                background: Some(Background::Color(match status {
                    button::Status::Hovered | button::Status::Pressed => hover_tint(bg, t.text),
                    _ => bg,
                })),
                text_color: color,
                border: Border {
                    color: with_alpha(color, 0.25),
                    width: 1.0,
                    radius: Radius::from(8),
                },
                ..button::Style::default()
            }
        });
    if !refreshing {
        b = b.on_press(Message::RefreshPortfolio);
    }
    b.into()
}

/// The "PENDING TRANSACTIONS" block for a Safe's multisig queue. Returns
/// `None` when there's nothing to surface (not loading, no error, empty
/// queue) so the section vanishes entirely rather than leaving a bare
/// header. A non-empty queue renders one [`pending_row`] each; an empty
/// loading/errored state renders a single muted line that never blocks
/// the asset list below.
fn pending_section<'a>(
    t: KaoTheme,
    pending: &'a [PendingSafeTx],
    loading: bool,
    error: Option<&'a str>,
) -> Option<Element<'a, Message>> {
    if pending.is_empty() && !loading && error.is_none() {
        return None;
    }

    let label = text("PENDING TRANSACTIONS")
        .size(11)
        .color(t.sub)
        .font(bold());

    let mut col = column![label, Space::new().height(10)].width(Length::Fill);

    if pending.is_empty() {
        let msg = if loading {
            "Loading pending transactions…".to_string()
        } else {
            // error.is_some() here (empty + not loading is handled above).
            "Couldn't load pending transactions.".to_string()
        };
        col = col.push(text(msg).size(12).color(t.sub).font(mono()));
    } else {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut rows = column![].spacing(5);
        for (idx, tx) in pending.iter().enumerate() {
            rows = rows.push(pending_row(t, tx, now, idx));
        }
        col = col.push(rows);
    }

    Some(col.into())
}

/// One row in the pending-Safe-tx list. Non-interactive in this slice
/// (tapping into a detail/verify modal is a follow-up) — styled with the
/// same card shape as `token_row`, mirroring the activity feed's layout:
/// avatar · recipient + nonce/time · value + status badge.
fn pending_row<'a>(t: KaoTheme, tx: &PendingSafeTx, now: u64, idx: usize) -> Element<'a, Message> {
    let ab = match idx % 3 {
        0 => t.ab1,
        1 => t.ab2,
        _ => t.ab3,
    };

    let meta = if tx.submission_ts > 0 {
        format!(
            "nonce {} · {}",
            tx.nonce,
            format_relative(now, tx.submission_ts)
        )
    } else {
        format!("nonce {}", tx.nonce)
    };
    let mut left = column![
        text(format!("To {}", short_address(tx.to)))
            .size(14)
            .color(t.text)
            .font(bold()),
        Space::new().height(2),
        text(meta).size(11).color(t.sub).font(mono()),
    ]
    .spacing(0);
    // A delegatecall must never scan as a plain send, even at row level
    // — the detail modal carries the full warning, this is the tap bait.
    if tx.operation != 0 {
        left = left
            .push(Space::new().height(2))
            .push(text("⚠ delegatecall").size(11).color(t.down).font(bold()));
    }

    let value_eth = alloy::primitives::utils::format_ether(tx.value);
    let value_f = value_eth.parse::<f64>().unwrap_or(0.0);
    let value_str = if value_f == 0.0 {
        "0 ETH".to_string()
    } else if value_f >= 1.0 {
        format!("{value_f:.4} ETH")
    } else {
        let s = format!("{value_f:.6}");
        format!("{} ETH", s.trim_end_matches('0').trim_end_matches('.'))
    };

    let right = column![
        text(value_str).size(14).color(t.text).font(mono_black()),
        Space::new().height(3),
        status_badge(t, tx.state),
    ]
    .align_x(Alignment::End)
    .spacing(0);

    let row = row![
        avatar(t, PENDING_KAO, 40.0, ab),
        Space::new().width(13),
        column![left].width(Length::Fill),
        right,
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    // Whole row is a button → opens the detail/confirm/execute modal,
    // mirroring the activity feed's tappable rows.
    button(row)
        .padding(Padding::from([13, 15]))
        .width(Length::Fill)
        .on_press(Message::OpenSafeTxDetails(idx))
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

/// Small filled chip describing the FSM state. Color carries the urgency:
/// green = ready/executed, accent = collecting signatures, muted =
/// queued behind an earlier nonce, red = replaced/failed.
fn status_badge<'a>(t: KaoTheme, state: SafeTxState) -> Element<'a, Message> {
    let (label, accent): (String, Color) = match state {
        SafeTxState::AwaitingConfirmations { have, required } => {
            (format!("{have}/{required} signatures"), t.a1)
        }
        SafeTxState::AwaitingExecution { is_next: true, .. } => {
            ("Ready to execute".to_string(), t.up)
        }
        SafeTxState::AwaitingExecution { is_next: false, .. } => ("Queued".to_string(), t.sub),
        SafeTxState::Replaced => ("Replaced".to_string(), t.down),
        SafeTxState::Executed { success: true } => ("Executed".to_string(), t.up),
        SafeTxState::Executed { success: false } => ("Failed".to_string(), t.down),
    };
    container(text(label).size(10).color(accent).font(bold()))
        .padding(Padding::from([2, 6]))
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(accent, 0.12))),
            border: Border {
                color: with_alpha(accent, 0.3),
                width: 1.0,
                radius: Radius::from(6),
            },
            ..container::Style::default()
        })
        .into()
}

fn quick_actions<'a>(t: KaoTheme, can_send: bool, can_swap: bool) -> Element<'a, Message> {
    // Send and Swap are hidden entirely (not just disabled) for identities that
    // can't perform them. Send is hidden for view-only accounts and hardware
    // accounts whose device is disconnected (reconnect via the sidebar's
    // hardware card); Swap is hidden for view-only accounts and non-swappable
    // Safes. Receive always shows — it just displays the address.
    let mut actions = row![].width(Length::Fill);
    if can_send {
        actions = actions.push(quick_action(
            t,
            "Send",
            "ᕕ( ᐛ )ᕗ",
            t.ab1,
            t.a1,
            Some(Message::OpenSend),
        ));
        actions = actions.push(Space::new().width(10));
    }
    actions = actions.push(quick_action(
        t,
        "Receive",
        "(っ◕‿◕)っ",
        t.ab2,
        t.a2,
        Some(Message::OpenReceive),
    ));
    if can_swap {
        actions = actions.push(Space::new().width(10));
        actions = actions.push(quick_action(
            t,
            "Swap",
            "(⇌ω⇌)",
            t.ab3,
            t.a3,
            Some(Message::OpenSwap),
        ));
    }

    actions.into()
}

fn quick_action<'a>(
    t: KaoTheme,
    label: &'a str,
    kao: &'a str,
    bg: Color,
    accent: Color,
    on_press: Option<Message>,
) -> Element<'a, Message> {
    let content = column![
        kao_text(t, kao, 22.0),
        Space::new().height(7),
        text(label).size(13).color(accent).font(bold()),
    ]
    .align_x(Alignment::Center)
    .spacing(0);

    let mut b = button(
        container(content)
            .width(Length::Fill)
            .center_x(Length::Fill)
            .padding(Padding::from([16, 10])),
    )
    .width(Length::Fill)
    .style(move |_theme, status| button::Style {
        background: Some(Background::Color(match status {
            button::Status::Hovered | button::Status::Pressed => hover_fill(bg, accent),
            _ => bg,
        })),
        text_color: accent,
        border: Border {
            color: with_alpha(accent, 0.2),
            width: 1.5,
            radius: Radius::from(15),
        },
        ..button::Style::default()
    });
    if let Some(m) = on_press {
        b = b.on_press(m);
    }
    b.into()
}

fn token_row<'a>(t: KaoTheme, tk: &'a LiveToken, idx: usize) -> Element<'a, Message> {
    let ab = match idx % 3 {
        0 => t.ab1,
        1 => t.ab2,
        _ => t.ab3,
    };
    let kao = kaomoji_for_index(idx);
    // Built-in networks can show a chain/token logo; a custom network has no
    // bundled logo, so it falls back to the kaomoji avatar.
    let avatar = match tk.chain.builtin() {
        Some(chain) => token_avatar(t, chain, tk.contract, kao, 40.0, ab),
        None => avatar(t, kao, 40.0, ab),
    };
    let info = column![
        text(&tk.name).size(14).color(t.text).font(bold()),
        text(format!(
            "{} {}",
            tk.balance,
            format_symbol(&tk.symbol, tk.chain)
        ))
        .size(11)
        .color(t.sub)
        .font(mono()),
    ]
    .spacing(0);

    let right = if tk.usd_price > 0.0 {
        text(format!("${}", format_usd(tk.usd_value)))
            .size(14)
            .color(t.text)
            .font(mono_bold())
    } else {
        text("—").size(14).color(t.sub).font(mono_bold())
    };

    let row = row![
        avatar,
        Space::new().width(13),
        column![info].width(Length::Fill),
        right,
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    container(row)
        .padding(Padding::from([13, 15]))
        .width(Length::Fill)
        .style(move |_| card_style(t))
        .into()
}

/// Group thousands, 2 decimals. Used by both the hero total and per-token
/// USD values; co-located here because the home view is the only consumer.
pub(super) fn format_usd(n: f64) -> String {
    // Round to whole cents *before* splitting, so 24.996 carries into
    // "25.00" instead of rendering the rounded-up cents as "24.100".
    let cents = (n * 100.0).round() as i64;
    let whole = cents.unsigned_abs() / 100;
    let frac = cents.unsigned_abs() % 100;
    let mut s = String::new();
    let digits: Vec<u8> = whole.to_string().bytes().collect();
    for (i, b) in digits.iter().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            s.push(',');
        }
        s.push(*b as char);
    }
    if cents < 0 {
        s.insert(0, '-');
    }
    s.push('.');
    s.push_str(&format!("{:02}", frac));
    s
}

/// Render a token symbol with its network in parens when the token lives
/// somewhere other than Mainnet. Mainnet entries stay bare ("USDC"); L2 and
/// custom entries get a suffix ("USDC (Base)", "ETH (Sepolia)") so a portfolio
/// that spans networks is unambiguous at a glance without a separate column.
pub(super) fn format_symbol(symbol: &str, network: NetworkId) -> String {
    use crate::chain::Chain;
    match network {
        NetworkId::Builtin(Chain::Mainnet) => symbol.to_string(),
        NetworkId::Builtin(c) => format!("{symbol} ({})", c.label()),
        NetworkId::Custom(_) => format!("{symbol} ({})", network_label(network)),
    }
}

/// Sanitize a custom network's user-typed name for display, mirroring the
/// ingestion-point sanitization in `portfolio::fetch_native_balance` so the
/// name renders identically (bidi/zero-width/control chars stripped, length
/// clamped) wherever it appears. Built-in labels are static and trusted, so
/// they skip this.
fn sanitize_network_name(name: &str) -> String {
    crate::sanitize::sanitize_display(name, crate::sanitize::MAX_TOKEN_NAME_CHARS).into_owned()
}

/// Short network name for a token tab / row suffix. Built-ins use their static
/// label; a custom network resolves its user-given name from settings, falling
/// back to the chain id if the row was deleted out from under a stale render.
pub(super) fn network_label(network: NetworkId) -> String {
    match network {
        NetworkId::Builtin(c) => c.label().to_string(),
        NetworkId::Custom(id) => crate::settings::custom_network(id)
            .map(|n| sanitize_network_name(&n.name))
            .unwrap_or_else(|| format!("chain {id}")),
    }
}

/// Long network name for the review screen ("Ethereum Mainnet", "OP Mainnet").
/// Built-ins use their `display_name`; a custom network uses the user's name
/// (there's no separate long form), falling back to the chain id.
pub(super) fn network_display_name(network: NetworkId) -> String {
    match network {
        NetworkId::Builtin(c) => c.display_name().to_string(),
        NetworkId::Custom(_) => network_label(network),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::Chain;

    #[test]
    fn usd_cents_carry_into_dollars() {
        assert_eq!(format_usd(24.996), "25.00");
        assert_eq!(format_usd(999.999), "1,000.00");
        assert_eq!(format_usd(0.999), "1.00");
    }

    #[test]
    fn usd_groups_thousands_and_pads_cents() {
        assert_eq!(format_usd(0.0), "0.00");
        assert_eq!(format_usd(24.1), "24.10");
        assert_eq!(format_usd(1234567.891), "1,234,567.89");
        assert_eq!(format_usd(-0.3), "-0.30");
        assert_eq!(format_usd(-1234.5), "-1,234.50");
    }

    #[test]
    fn mainnet_symbol_has_no_suffix() {
        assert_eq!(format_symbol("USDC", Chain::Mainnet.into()), "USDC");
        assert_eq!(format_symbol("ETH", Chain::Mainnet.into()), "ETH");
    }

    #[test]
    fn l2_symbol_carries_chain_in_parens() {
        assert_eq!(format_symbol("USDC", Chain::Base.into()), "USDC (Base)");
        assert_eq!(
            format_symbol("ETH", Chain::Optimism.into()),
            "ETH (Optimism)"
        );
    }

    #[test]
    fn custom_network_symbol_carries_name_or_chain_id() {
        // No settings entry for this id in the test process → falls back to
        // "chain {id}". (The happy path, resolving the user's name, is
        // exercised via the live settings store in integration use.) Uses an
        // arbitrary id that isn't one of the seeded networks (Sepolia/Anvil),
        // whose names the live default settings would otherwise resolve.
        assert_eq!(
            format_symbol("ETH", NetworkId::Custom(987654321)),
            "ETH (chain 987654321)"
        );
    }

    #[test]
    fn custom_network_name_is_sanitized_for_display() {
        // A user-typed name carrying a bidi override (U+202E) and a zero-width
        // space (U+200B) must have those stripped before it reaches a text
        // widget, matching the ingestion-point sanitization in portfolio.rs.
        assert_eq!(
            sanitize_network_name("My\u{202E}Net\u{200B}work"),
            "MyNetwork"
        );
    }
}
