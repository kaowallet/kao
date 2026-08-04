//! Shared renderer for revm-preflight results — used by the EOA Send
//! review (`send.rs`), the Safe Send review (`safe_send.rs`), and the
//! Safe tx detail modal (`safe_tx_detail.rs`). Generic over the pane's
//! message type: the block is purely informational and emits nothing.

use iced::border::Radius;
use iced::widget::{Space, column, container, row, text};
use iced::{Alignment, Background, Border, Color, Element, Length, Padding};

use crate::portfolio::LiveToken;
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{bold, mono};
use crate::wallet::sim::{SimOutcome, SimulationResult, TokenTransfer};

/// Render the revm-preflight block. Layouts:
/// - **Unavailable + L2**: small inline "Simulation unavailable on this chain".
/// - **Unavailable + Mainnet**: small inline "Simulation unavailable" (sim
///   errored — still display so the user knows what *didn't* happen).
/// - **Success**: header + per-transfer rows + verification badge.
/// - **Revert / Halt**: red banner with the decoded reason. The action
///   buttons above relabel to "… anyway ⚠"; this block carries the *why*.
pub fn simulation_block<'a, M: 'a>(
    t: KaoTheme,
    sim: &'a SimulationResult,
    chain: crate::chain::NetworkId,
    portfolio: &'a [LiveToken],
) -> Element<'a, M> {
    match &sim.outcome {
        SimOutcome::Unavailable => {
            // `supports_simulation()` now returns `true` on every Kao
            // chain (preflight runs for Mainnet, Base, Optimism), so
            // the only way to land in this branch is a genuine sim
            // failure — Helios unreachable, fallback RPC errored, or
            // revm rejected the tx env. Phrase the notice as a
            // transient miss rather than a chain-level gate.
            let msg = if !chain.supports_simulation() {
                "Simulation unavailable on this chain"
            } else {
                "Simulation unavailable — couldn't preflight this tx"
            };
            container(text(msg).size(11).color(t.sub).font(mono()))
                .padding(Padding::from([4, 0]))
                .width(Length::Fill)
                .into()
        }
        SimOutcome::Success { .. } => {
            let badge_label = if sim.verified {
                "✓ Verified by Helios"
            } else {
                "⚠ Unverified simulation"
            };
            let badge_color = if sim.verified { t.up } else { t.sub };
            let header_label = if sim.transfers.is_empty() {
                "Simulation passed ヾ(＾∇＾)"
            } else {
                "Will execute:"
            };
            let header = row![
                text(header_label).size(13).color(t.sub),
                Space::new().width(Length::Fill),
                text(badge_label).size(11).color(badge_color).font(bold()),
            ]
            .align_y(Alignment::Center)
            .width(Length::Fill);
            let mut col = column![header].spacing(4);
            for transfer in sim.transfers.iter() {
                col = col.push(transfer_row(t, transfer, chain, portfolio));
            }
            container(col)
                .padding(Padding::from([4, 0]))
                .width(Length::Fill)
                .into()
        }
        SimOutcome::Revert { reason, .. } | SimOutcome::Halt { reason } => {
            let title = match &sim.outcome {
                SimOutcome::Halt { .. } => "(╥﹏╥) Tx would halt",
                _ => "(╥﹏╥) Tx would revert",
            };
            let body: Element<'_, M> = column![
                text(title).size(13).color(t.down).font(bold()),
                Space::new().height(2),
                text(reason.clone()).size(12).color(t.down).font(mono()),
            ]
            .spacing(0)
            .into();
            container(body)
                .padding(Padding::from([8, 12]))
                .width(Length::Fill)
                .style(move |_| container::Style {
                    background: Some(Background::Color(Color { a: 0.10, ..t.down })),
                    border: Border {
                        color: t.down,
                        width: 1.0,
                        radius: Radius::from(8),
                    },
                    text_color: Some(t.down),
                    ..container::Style::default()
                })
                .into()
        }
    }
}

/// Single "+/- amount SYMBOL" row inside the simulation block.
/// Looks the token contract up in the active portfolio for a nice symbol
/// and decimals; falls back to "raw / short-address" so unknown tokens
/// still render something meaningful.
fn transfer_row<'a, M: 'a>(
    t: KaoTheme,
    transfer: &'a TokenTransfer,
    chain: crate::chain::NetworkId,
    portfolio: &'a [LiveToken],
) -> Element<'a, M> {
    // Match by (chain, contract). The portfolio is multi-chain, so we
    // can't just match on address — that'd cross-contaminate identical
    // contract addresses across L1 and L2.
    let known = portfolio
        .iter()
        .find(|p| p.chain == chain && p.contract == Some(transfer.token));
    let (label, decimals) = match known {
        Some(tk) => (tk.symbol.clone(), tk.decimals),
        None => {
            let bytes = transfer.token.as_slice();
            let head = alloy::hex::encode(&bytes[..4]);
            let tail = alloy::hex::encode(&bytes[bytes.len() - 4..]);
            (format!("0x{head}…{tail}"), 0u8)
        }
    };
    let amount_str = if transfer.is_nft {
        format!("#{}", transfer.value)
    } else if decimals == 0 {
        // Unknown token: show raw integer (the user can verify against
        // a block explorer rather than have us guess decimals).
        format!("{} units", transfer.value)
    } else {
        match alloy::primitives::utils::format_units(transfer.value, decimals) {
            Ok(s) => trim_trailing_decimal_zeros(&s),
            Err(_) => transfer.value.to_string(),
        }
    };
    row![
        text(format!("→ {amount_str} {label}"))
            .size(12)
            .color(t.text)
            .font(mono()),
    ]
    .padding(Padding::from([0, 0]))
    .width(Length::Fill)
    .into()
}

pub fn trim_trailing_decimal_zeros(s: &str) -> String {
    if !s.contains('.') {
        return s.to_string();
    }
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Approximate fee for `gas_used` at the sim's pinned base fee,
/// formatted in ETH — e.g. `Some("0.000252")` for 21 000 gas at
/// 12 gwei. `None` when either input is zero (no sim ran, or the
/// block/mocked header carried no base fee) so callers can skip the
/// row instead of rendering "0 ETH".
///
/// Deliberately an estimate: excludes the priority tip (small next to
/// the base fee) and, for Safe inner calls, the `execTransaction`
/// overhead — the UI renders it with a leading `≈`.
pub fn format_gas_fee_eth(gas_used: u64, base_fee_per_gas: u64) -> Option<String> {
    if gas_used == 0 || base_fee_per_gas == 0 {
        return None;
    }
    let wei =
        alloy::primitives::U256::from(gas_used) * alloy::primitives::U256::from(base_fee_per_gas);
    let eth = alloy::primitives::utils::format_units(wei, 18).ok()?;
    Some(trim_eth_sig_digits(&eth))
}

/// Compact an ether-formatted decimal for display: keep 3 significant
/// digits past the fractional part's leading zeros, then trim trailing
/// zeros — `"0.000014239683110688"` → `"0.0000142"`. Same strategy as
/// the EOA review's gas display (`send.rs::trim_eth_display`).
fn trim_eth_sig_digits(s: &str) -> String {
    let Some(dot) = s.find('.') else {
        return s.to_string();
    };
    let (int_part, dot_frac) = s.split_at(dot);
    let frac = &dot_frac[1..];
    let leading_zeros = frac.bytes().take_while(|b| *b == b'0').count();
    let keep = leading_zeros + 3;
    let truncated: String = frac.chars().take(keep).collect();
    let final_frac = truncated.trim_end_matches('0');
    if final_frac.is_empty() {
        int_part.to_string()
    } else {
        format!("{int_part}.{final_frac}")
    }
}

/// A wei-per-gas price formatted in gwei — `12_400_000_000` → `Some("12.4")`.
/// `None` at zero, so callers omit the clause rather than printing "0 gwei".
///
/// Same significant-digit treatment as [`format_gas_fee_eth`]: sub-gwei base
/// fees (routine on Base and Optimism) keep three digits past their leading
/// zeros instead of rounding to a flat `0`.
pub fn format_gwei(wei_per_gas: u64) -> Option<String> {
    if wei_per_gas == 0 {
        return None;
    }
    let gwei =
        alloy::primitives::utils::format_units(alloy::primitives::U256::from(wei_per_gas), 9)
            .ok()?;
    Some(trim_eth_sig_digits(&gwei))
}

/// Thousands-grouped gas figure: `21000` renders as `"21,000"`,
/// `30000000` as `"30,000,000"`.
pub fn format_gas(gas: u64) -> String {
    let s = gas.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{format_gas, format_gas_fee_eth, format_gwei};

    #[test]
    fn format_gwei_denominates_and_trims() {
        assert_eq!(format_gwei(12_400_000_000).as_deref(), Some("12.4"));
        assert_eq!(format_gwei(1_000_000_000).as_deref(), Some("1"));
        // Sub-gwei base fees are the norm on the L2s: three significant digits
        // past the leading zeros rather than a rounded-to-nothing "0".
        assert_eq!(format_gwei(6_780_000).as_deref(), Some("0.00678"));
    }

    #[test]
    fn format_gwei_skips_zero() {
        // No block was read — the clause is omitted, not printed as "0 gwei".
        assert!(format_gwei(0).is_none());
    }

    #[test]
    fn format_gas_groups_thousands() {
        assert_eq!(format_gas(0), "0");
        assert_eq!(format_gas(999), "999");
        assert_eq!(format_gas(1_000), "1,000");
        assert_eq!(format_gas(21_000), "21,000");
        assert_eq!(format_gas(1_234_567), "1,234,567");
        assert_eq!(format_gas(30_000_000), "30,000,000");
    }

    #[test]
    fn format_gas_fee_eth_denominates_at_base_fee() {
        // 21_000 gas × 12 gwei = 252_000 gwei = 0.000252 ETH.
        assert_eq!(
            format_gas_fee_eth(21_000, 12_000_000_000).as_deref(),
            Some("0.000252"),
        );
        // 3 significant digits past the leading zeros, zeros trimmed:
        // 21_000 × 0.678 gwei = 0.000014238 ETH → "0.0000142".
        assert_eq!(
            format_gas_fee_eth(21_000, 678_000_000).as_deref(),
            Some("0.0000142"),
        );
    }

    #[test]
    fn format_gas_fee_eth_skips_zero_inputs() {
        // No sim ran, or the (mocked) header carried no base fee — the
        // row must be omitted rather than claiming a free transaction.
        assert!(format_gas_fee_eth(0, 12_000_000_000).is_none());
        assert!(format_gas_fee_eth(21_000, 0).is_none());
    }
}
