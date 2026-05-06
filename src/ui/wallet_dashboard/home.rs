//! Home pane — balance hero, quick actions (Send/Receive/Swap), live assets list.

use iced::border::Radius;
use iced::widget::{Space, button, column, container, row, text};
use iced::{Alignment, Background, Border, Color, Element, Length, Padding};

use crate::chain::Chain;
use crate::portfolio::LiveToken;
use crate::ui::kao_theme::{KaoTheme, mix, with_alpha};
use crate::ui::kao_widgets::{
    bold, card_style, hover_fill, kao_fit, kao_scrollable_style, kao_text, kaomoji_for_index,
    mono, mono_black, mono_bold, token_avatar,
};
use crate::wallet::KaoSigner;

use super::{MOOD, Message};

pub fn view<'a>(
    t: KaoTheme,
    signer: &'a KaoSigner,
    portfolio: &'a [LiveToken],
    portfolio_loading: bool,
) -> Element<'a, Message> {
    let hero = balance_hero(t, portfolio);
    let actions = quick_actions(t, signer);
    let assets_label = text("ASSETS").size(11).color(t.sub).font(bold());
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

    let content = column![
        hero,
        Space::new().height(18),
        actions,
        Space::new().height(18),
        assets_label,
        Space::new().height(10),
        assets,
    ];

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

fn quick_actions<'a>(t: KaoTheme, signer: &KaoSigner) -> Element<'a, Message> {
    // View-only accounts can't sign, so Send is disabled. Receive still works
    // because it just shows the address.
    let send_press = if signer.can_sign() {
        Some(Message::OpenSend)
    } else {
        None
    };
    row![
        quick_action(t, "Send", "ᕕ( ᐛ )ᕗ", t.ab1, t.a1, send_press),
        Space::new().width(10),
        quick_action(
            t,
            "Receive",
            "(っ◕‿◕)っ",
            t.ab2,
            t.a2,
            Some(Message::OpenReceive),
        ),
        Space::new().width(10),
        quick_action(t, "Swap", "(⇌ω⇌)", t.ab3, t.a3, Some(Message::OpenSwap)),
    ]
    .width(Length::Fill)
    .into()
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
    let avatar = token_avatar(t, tk.chain, tk.contract, kao, 40.0, ab);
    let info = column![
        text(&tk.name).size(14).color(t.text).font(bold()),
        text(format!("{} {}", tk.balance, format_symbol(&tk.symbol, tk.chain)))
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
    let whole = n.trunc() as i64;
    let frac = ((n - whole as f64).abs() * 100.0).round() as u64;
    let mut s = String::new();
    let digits: Vec<u8> = whole.abs().to_string().bytes().collect();
    for (i, b) in digits.iter().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            s.push(',');
        }
        s.push(*b as char);
    }
    if whole < 0 {
        s.insert(0, '-');
    }
    s.push('.');
    s.push_str(&format!("{:02}", frac));
    s
}

/// Render a token symbol with its chain in parens when the token lives
/// on an L2. Mainnet entries stay bare ("USDC"); L2 entries get a
/// suffix ("USDC (Base)", "ETH (Optimism)") so a portfolio that spans
/// chains is unambiguous at a glance without a separate chain column.
pub(super) fn format_symbol(symbol: &str, chain: Chain) -> String {
    match chain {
        Chain::Mainnet => symbol.to_string(),
        Chain::Base | Chain::Optimism => format!("{symbol} ({})", chain.label()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_symbol_has_no_suffix() {
        assert_eq!(format_symbol("USDC", Chain::Mainnet), "USDC");
        assert_eq!(format_symbol("ETH", Chain::Mainnet), "ETH");
    }

    #[test]
    fn l2_symbol_carries_chain_in_parens() {
        assert_eq!(format_symbol("USDC", Chain::Base), "USDC (Base)");
        assert_eq!(format_symbol("ETH", Chain::Optimism), "ETH (Optimism)");
    }
}
