//! The shared swap composer: token + amount entry, the buy-token picker, the
//! slippage control, and the quote summary. Both swap surfaces — the blocking
//! portfolio modal ([`crate::ui::wallet_dashboard::swap`]) and the non-blocking
//! Apps pane ([`crate::ui::wallet_dashboard::apps`]) — embed one of these so the
//! pre-placement UX is written exactly once.
//!
//! The composer holds only *local* state and never touches the network itself.
//! Network-bearing actions bubble up as an [`Outcome`] (a quote request, or a
//! place request once a quote is in hand); the dashboard coordinator owns the
//! HTTP + signing and feeds the result back via
//! [`Message::QuoteResult`]. This keeps the "no request until an explicit
//! action" rule trivially true — a quote only goes out when the user clicks
//! "Get quote".

use alloy::primitives::{Address, U256};
use iced::border::Radius;
use iced::widget::text::Wrapping;
use iced::widget::{Space, button, column, container, row, text, text_input};
use iced::{Alignment, Background, Border, Element, Length, Padding};

use crate::chain::Chain;
use crate::portfolio::{LiveToken, format_token_balance};
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::{
    bold, error_text, mono, mono_bold, primary_button, secondary_button, text_input_style,
    token_avatar,
};
use crate::wallet::tx::parse_amount_units;

use super::api::QuoteResponse;

/// The default slippage tolerance, in basis points (0.5%).
pub const DEFAULT_SLIPPAGE_BPS: u16 = 50;

/// EthFlow (native-ETH) orders have a documented 2% minimum slippage; signing
/// below it risks the order being rejected or never executing. Native sells are
/// floored to this regardless of the chosen tolerance.
const ETHFLOW_MIN_SLIPPAGE_BPS: u16 = 200;

/// ETH to hold back when "Max"-ing a native-ETH sell, so there's something left
/// for the EthFlow order's fee + gas. Heuristic per chain — the on-chain
/// pre-flight in `cow::onchain` is the authoritative guard.
fn native_gas_reserve(chain: Chain) -> U256 {
    match chain {
        Chain::Mainnet => U256::from(3_000_000_000_000_000u64), // ~0.003 ETH
        Chain::Base | Chain::Optimism => U256::from(10_000_000_000_000u64), // ~0.00001 ETH
    }
}

/// A picked sell asset, copied out of the portfolio row so the composer never
/// holds a fragile index into a list that can be refreshed underneath it.
#[derive(Debug, Clone)]
pub struct SellPick {
    pub symbol: String,
    /// `None` = native ETH (routed through EthFlow).
    pub contract: Option<Address>,
    pub decimals: u8,
    pub balance_raw: U256,
}

/// A picked buy token (always an ERC-20 — CoW orders buy ERC-20s).
#[derive(Debug, Clone)]
pub struct BuyPick {
    pub symbol: String,
    pub address: Address,
    pub decimals: u8,
}

/// A fully-resolved, valid swap ready to quote/place. Produced by the composer
/// once both tokens and a positive in-balance amount are chosen. The user
/// address (order receiver / signer) is the coordinator's concern, not the
/// composer's — it's filled in when the quote/place task is built.
#[derive(Debug, Clone)]
pub struct SwapDraft {
    pub chain: Chain,
    /// Selling native ETH → the EthFlow on-chain path.
    pub is_native: bool,
    /// The ERC-20 quoted/sold. For a native sell this is WETH (EthFlow sells
    /// WETH on the user's behalf).
    pub sell_token: Address,
    pub buy_token: Address,
    pub sell_amount: U256,
    pub slippage_bps: u16,
    pub sell_symbol: String,
    pub buy_symbol: String,
    pub sell_decimals: u8,
    pub buy_decimals: u8,
}

#[derive(Debug, Clone)]
pub enum Message {
    SetChain(Chain),
    SelectSell(SellPick),
    SelectBuy(BuyPick),
    SellFilter(String),
    BuyFilter(String),
    ExpandBuy,
    SetAmount(String),
    MaxAmount,
    SetSlippage(u16),
    GetQuote,
    EditQuote,
    Place,
    /// Coordinator hands the quote (or its error) back here.
    QuoteResult(Result<QuoteResponse, String>),
}

/// Network-bearing requests the coordinator must service.
// One-shot outcome, never stored in bulk — the size gap from the embedded
// QuoteResponse isn't worth boxing through every wrapping layer.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Outcome {
    RequestQuote(SwapDraft),
    RequestPlace {
        draft: SwapDraft,
        quote: QuoteResponse,
    },
}

impl Outcome {
    /// Variant name for the GUI state trace — never the payload.
    fn name(&self) -> &'static str {
        match self {
            Outcome::RequestQuote(_) => "RequestQuote",
            Outcome::RequestPlace { .. } => "RequestPlace",
        }
    }
}

#[derive(Debug)]
pub struct SwapComposer {
    /// The CoW network the swap runs on — chosen explicitly via the switch.
    chain: Chain,
    sell: Option<SellPick>,
    buy: Option<BuyPick>,
    /// Case-insensitive symbol filters for the two token pickers.
    sell_filter: String,
    buy_filter: String,
    /// Whether the buy picker is expanded past the popular-N cap. (The sell
    /// picker shows all holdings and scrolls, so it has no expand state.)
    buy_expanded: bool,
    amount: String,
    slippage_bps: u16,
    quote: Option<QuoteResponse>,
    quoting: bool,
    error: Option<String>,
}

impl Default for SwapComposer {
    fn default() -> Self {
        Self::new()
    }
}

impl SwapComposer {
    pub fn new() -> Self {
        Self {
            chain: Chain::Mainnet,
            sell: None,
            buy: None,
            sell_filter: String::new(),
            buy_filter: String::new(),
            buy_expanded: false,
            amount: String::new(),
            slippage_bps: DEFAULT_SLIPPAGE_BPS,
            quote: None,
            quoting: false,
            error: None,
        }
    }

    /// Reset to a blank slate (used by the Apps pane after a successful place,
    /// keeping the chosen slippage).
    pub fn reset(&mut self) {
        // Called by the host outside `update`, so the wrapper diff can't see
        // these transitions — log the coarse ones here.
        if self.quote.is_some() {
            crate::trace::state("composer", "quote", "some", "none");
        }
        if self.quoting {
            crate::trace::state("composer", "quoting", true, false);
        }
        if self.error.is_some() {
            crate::trace::state("composer", "error", "some", "none");
        }
        self.sell = None;
        self.buy = None;
        self.sell_filter.clear();
        self.buy_filter.clear();
        self.buy_expanded = false;
        self.amount.clear();
        self.quote = None;
        self.quoting = false;
        self.error = None;
    }

    pub fn update(&mut self, msg: Message) -> Option<Outcome> {
        crate::trace_msg!("composer", &msg);
        let chain_before = self.chain;
        let quoting_before = self.quoting;
        let quote_before = self.quote.is_some();
        let error_before = self.error.is_some();
        let outcome = self.update_inner(msg);
        if chain_before != self.chain {
            crate::trace::state(
                "composer",
                "chain",
                chain_before.label(),
                self.chain.label(),
            );
        }
        if quoting_before != self.quoting {
            crate::trace::state("composer", "quoting", quoting_before, self.quoting);
        }
        let p = |present: bool| if present { "some" } else { "none" };
        if quote_before != self.quote.is_some() {
            crate::trace::state(
                "composer",
                "quote",
                p(quote_before),
                p(self.quote.is_some()),
            );
        }
        if error_before != self.error.is_some() {
            crate::trace::state(
                "composer",
                "error",
                p(error_before),
                p(self.error.is_some()),
            );
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("composer", o.name());
        }
        outcome
    }

    fn update_inner(&mut self, msg: Message) -> Option<Outcome> {
        match msg {
            Message::SetChain(chain) => {
                if self.chain != chain {
                    // Tokens are chain-specific — drop selections + filters + quote.
                    self.chain = chain;
                    self.sell = None;
                    self.buy = None;
                    self.sell_filter.clear();
                    self.buy_filter.clear();
                    self.buy_expanded = false;
                    self.amount.clear();
                    self.invalidate_quote();
                }
                None
            }
            Message::SelectSell(pick) => {
                if self.buy.as_ref().map(|b| b.address) == pick.contract {
                    self.buy = None; // can't buy what you're selling
                }
                self.sell = Some(pick);
                self.invalidate_quote();
                None
            }
            Message::SelectBuy(pick) => {
                self.buy = Some(pick);
                self.invalidate_quote();
                None
            }
            // Filters are view-only — they never touch the selection or quote.
            Message::SellFilter(s) => {
                self.sell_filter = s;
                None
            }
            Message::BuyFilter(s) => {
                self.buy_filter = s;
                None
            }
            Message::ExpandBuy => {
                self.buy_expanded = true;
                None
            }
            Message::SetAmount(s) => {
                // Digits + one dot only — mirrors the Send amount field.
                if s.chars().all(|c| c.is_ascii_digit() || c == '.')
                    && s.chars().filter(|c| *c == '.').count() <= 1
                {
                    self.amount = s;
                    self.invalidate_quote();
                }
                None
            }
            Message::MaxAmount => {
                if let Some(sell) = &self.sell {
                    if sell.contract.is_none() {
                        // Native ETH is the gas token — never offer 100%. Leave
                        // headroom for the EthFlow order's fee + gas (a heuristic;
                        // the on-chain pre-flight is the real guard).
                        let max_raw = sell
                            .balance_raw
                            .saturating_sub(native_gas_reserve(self.chain));
                        if max_raw.is_zero() {
                            // Balance is at/below the gas reserve — explain the
                            // "Max = 0" instead of silently filling in 0.
                            self.amount.clear();
                            self.quote = None;
                            self.error = Some(
                                "Your ETH balance is too low to swap after leaving room for gas."
                                    .into(),
                            );
                            return None;
                        }
                        let (s, _) = format_token_balance(max_raw, sell.decimals);
                        self.amount = s;
                    } else {
                        let (s, _) = format_token_balance(sell.balance_raw, sell.decimals);
                        self.amount = s;
                    }
                    self.invalidate_quote();
                }
                None
            }
            Message::SetSlippage(bps) => {
                self.slippage_bps = bps;
                // Slippage only affects the signed min-out, computed at place
                // time, so the existing quote stays valid — just re-render.
                None
            }
            Message::GetQuote => match self.draft() {
                Some(draft) => {
                    self.quoting = true;
                    self.error = None;
                    Some(Outcome::RequestQuote(draft))
                }
                None => {
                    self.error = Some(self.why_invalid());
                    None
                }
            },
            Message::EditQuote => {
                self.invalidate_quote();
                None
            }
            Message::Place => match (self.draft(), self.quote.clone()) {
                (Some(draft), Some(quote)) => Some(Outcome::RequestPlace { draft, quote }),
                _ => None,
            },
            Message::QuoteResult(Ok(q)) => {
                self.quoting = false;
                self.quote = Some(q);
                self.error = None;
                None
            }
            Message::QuoteResult(Err(e)) => {
                self.quoting = false;
                self.quote = None;
                self.error = Some(e);
                None
            }
        }
    }

    /// Surface an error from the coordinator (e.g. a failed placement) into the
    /// composer so it renders inline.
    pub fn set_error(&mut self, e: String) {
        // Called by the host outside `update` — log the appearance here.
        if self.error.is_none() {
            crate::trace::state("composer", "error", "none", "some");
        }
        self.error = Some(e);
    }

    fn invalidate_quote(&mut self) {
        self.quote = None;
        self.error = None;
    }

    /// Slippage actually applied, enforcing the EthFlow floor for native sells.
    fn effective_slippage_bps(&self) -> u16 {
        if self.sell.as_ref().is_some_and(|s| s.contract.is_none()) {
            self.slippage_bps.max(ETHFLOW_MIN_SLIPPAGE_BPS)
        } else {
            self.slippage_bps
        }
    }

    fn parsed_amount(&self) -> Option<U256> {
        let sell = self.sell.as_ref()?;
        let amt = parse_amount_units(&self.amount, sell.decimals).ok()?;
        if amt.is_zero() || amt > sell.balance_raw {
            return None;
        }
        Some(amt)
    }

    fn draft(&self) -> Option<SwapDraft> {
        let sell = self.sell.as_ref()?;
        let buy = self.buy.as_ref()?;
        let amount = self.parsed_amount()?;
        let is_native = sell.contract.is_none();
        let sell_token = match sell.contract {
            Some(c) => c,
            None => super::wrapped_native(self.chain)?,
        };
        Some(SwapDraft {
            chain: self.chain,
            is_native,
            sell_token,
            buy_token: buy.address,
            sell_amount: amount,
            slippage_bps: self.effective_slippage_bps(),
            sell_symbol: sell.symbol.clone(),
            buy_symbol: buy.symbol.clone(),
            sell_decimals: sell.decimals,
            buy_decimals: buy.decimals,
        })
    }

    fn why_invalid(&self) -> String {
        if self.sell.is_none() {
            "Pick a token to sell".into()
        } else if self.buy.is_none() {
            "Pick a token to receive".into()
        } else if self.amount.trim().is_empty() {
            "Enter an amount".into()
        } else if self.parsed_amount().is_none() {
            "Amount exceeds your balance".into()
        } else {
            "Invalid swap".into()
        }
    }

    // ── View ────────────────────────────────────────────────────────────────

    /// The scrollable part of the composer: network switch, token pickers,
    /// slippage, and the quote summary. The action buttons are split out into
    /// [`Self::view_actions`] so a host can pin them below a scroll region.
    pub fn view_body<'a>(
        &'a self,
        t: KaoTheme,
        portfolio: &'a [LiveToken],
    ) -> Element<'a, Message> {
        let mut body = column![
            self.network_row(t),
            self.sell_section(t, portfolio),
            self.buy_section(t),
            self.slippage_row(t),
        ]
        .spacing(14)
        .width(Length::Fill);

        if let Some(q) = &self.quote {
            body = body.push(self.quote_summary(t, q));
        }
        if let Some(e) = &self.error {
            body = body.push(error_text(t, e));
        }

        body.into()
    }

    /// The action row: "Get quote" before a quote exists, or "Edit / Place
    /// order" once it does. Hosts render this pinned (always visible) below the
    /// scrolling body.
    pub fn view_actions<'a>(&self, t: KaoTheme) -> Element<'a, Message> {
        if self.quote.is_some() {
            row![
                secondary_button(t, "Edit").on_press(Message::EditQuote),
                Space::new().width(10),
                primary_button(t, "Place order", true).on_press(Message::Place),
            ]
            .width(Length::Fill)
            .into()
        } else {
            let ready = self.draft().is_some();
            let label = if self.quoting {
                "Getting quote…"
            } else {
                "Get quote"
            };
            let mut btn = primary_button(t, label, ready && !self.quoting);
            if ready && !self.quoting {
                btn = btn.on_press(Message::GetQuote);
            }
            btn.into()
        }
    }

    fn sell_section<'a>(&'a self, t: KaoTheme, portfolio: &'a [LiveToken]) -> Element<'a, Message> {
        // Only the user's holdings on the selected network are sellable.
        let eligible: Vec<&LiveToken> = portfolio
            .iter()
            .filter(|tk| tk.chain.builtin() == Some(self.chain) && !tk.balance_raw.is_zero())
            .collect();

        let mut col = column![label_row(t, "You pay")].spacing(8);
        if eligible.is_empty() {
            col = col.push(
                text(format!("No balances to swap on {}", self.chain.label()))
                    .size(12)
                    .color(t.sub),
            );
        } else {
            if eligible.len() > SEARCH_THRESHOLD {
                col = col.push(search_input(t, &self.sell_filter, Message::SellFilter));
            }
            let needle = self.sell_filter.trim().to_lowercase();
            let filtering = !needle.is_empty();
            let matches: Vec<&LiveToken> = eligible
                .iter()
                .copied()
                .filter(|tk| needle.is_empty() || tk.symbol.to_lowercase().contains(&needle))
                .collect();

            // Show all holdings (the user's own list, bounded) and let the grid
            // scroll when it's taller than VISIBLE_ROWS — no "show more" here.
            // A hard cap still bounds rendering for spam-heavy wallets.
            let _ = filtering;
            let total = matches.len();
            let shown = total.min(EXPANDED_LIMIT);

            if matches.is_empty() {
                col = col.push(text("No tokens match").size(12).color(t.sub));
            } else {
                let mut cells: Vec<Element<'a, Message>> = Vec::with_capacity(shown);
                for tk in matches.into_iter().take(shown) {
                    let selected = match &self.sell {
                        Some(s) => s.contract == tk.contract,
                        None => false,
                    };
                    let (bal, _) = format_token_balance(tk.balance_raw, tk.decimals);
                    let pick = SellPick {
                        symbol: tk.symbol.clone(),
                        contract: tk.contract,
                        decimals: tk.decimals,
                        balance_raw: tk.balance_raw,
                    };
                    cells.push(token_chip(
                        t,
                        self.chain,
                        tk.contract,
                        &tk.symbol,
                        Some(&bal),
                        selected,
                        Message::SelectSell(pick),
                    ));
                }
                col = col.push(token_grid(cells));
                if total > shown {
                    col = col.push(
                        text(format!("+{} more — refine your search", total - shown))
                            .size(11)
                            .color(t.sub)
                            .font(mono()),
                    );
                }
            }
        }

        if let Some(sell) = &self.sell {
            let (bal, _) = format_token_balance(sell.balance_raw, sell.decimals);
            let amount_input = text_input("0.0", &self.amount)
                .on_input(Message::SetAmount)
                .padding(Padding::from([12, 14]))
                .size(20)
                .style(move |_, status| text_input_style(t, status));

            let max_btn = button(text("MAX").size(10).color(t.a1).font(mono_bold()))
                .padding(Padding::from([6, 10]))
                .on_press(Message::MaxAmount)
                .style(move |_, status| button::Style {
                    background: Some(Background::Color(match status {
                        button::Status::Hovered | button::Status::Pressed => with_alpha(t.a1, 0.16),
                        _ => with_alpha(t.a1, 0.10),
                    })),
                    text_color: t.a1,
                    border: Border {
                        color: with_alpha(t.a1, 0.3),
                        width: 1.0,
                        radius: Radius::from(8),
                    },
                    ..button::Style::default()
                });

            col = col.push(
                row![amount_input, Space::new().width(8), max_btn].align_y(Alignment::Center),
            );
            col = col.push(
                text(format!("Balance: {bal} {}", sell.symbol))
                    .size(11)
                    .color(t.sub)
                    .font(mono()),
            );
            if sell.contract.is_none() {
                // Native ETH goes through EthFlow — an on-chain order, not a
                // gasless signature, and with a 2% minimum slippage.
                col = col.push(
                    text("Selling ETH is an on-chain order — keep ETH for gas; uses ≥2% slippage.")
                        .size(10)
                        .color(t.sub)
                        .font(mono()),
                );
            }
        }

        col.into()
    }

    fn buy_section<'a>(&self, t: KaoTheme) -> Element<'a, Message> {
        let sell_contract = self.sell.as_ref().and_then(|s| s.contract);
        // The wallet's vetted per-network token list (long on Base via the
        // bundled Superchain list); shares logos with the portfolio.
        let curated = crate::portfolio::curated_tokens(self.chain);

        let mut col = column![label_row(t, "You receive")].spacing(8);
        if curated.len() > SEARCH_THRESHOLD {
            col = col.push(search_input(t, &self.buy_filter, Message::BuyFilter));
        }
        let needle = self.buy_filter.trim().to_lowercase();
        let filtering = !needle.is_empty();
        // Filter the data first (cheap) — only build chips for what's shown, so a
        // long list never renders hundreds of widgets.
        let matches: Vec<(String, Address, u8)> = curated
            .into_iter()
            .filter(|(sym, addr, _)| {
                Some(*addr) != sell_contract
                    && (needle.is_empty() || sym.to_lowercase().contains(&needle))
            })
            .collect();

        let total = matches.len();
        let limit = if self.buy_expanded || filtering {
            EXPANDED_LIMIT
        } else {
            POPULAR_LIMIT
        };
        let shown = total.min(limit);

        if matches.is_empty() {
            col = col.push(text("No tokens match").size(12).color(t.sub));
            return col.into();
        }

        let mut cells: Vec<Element<'a, Message>> = Vec::with_capacity(shown);
        for (sym, addr, dec) in matches.into_iter().take(shown) {
            let selected = self.buy.as_ref().map(|b| b.address) == Some(addr);
            let pick = BuyPick {
                symbol: sym.clone(),
                address: addr,
                decimals: dec,
            };
            cells.push(token_chip(
                t,
                self.chain,
                Some(addr),
                &sym,
                None,
                selected,
                Message::SelectBuy(pick),
            ));
        }

        col = col.push(token_grid(cells));
        let expandable = !filtering && !self.buy_expanded;
        col = list_overflow_footer(col, t, total, shown, expandable, Message::ExpandBuy);
        col.into()
    }

    fn network_row<'a>(&self, t: KaoTheme) -> Element<'a, Message> {
        let mut chips = row![text("Network").size(11).color(t.sub).font(mono())]
            .spacing(8)
            .align_y(Alignment::Center);
        // Driven by the supported-chain set so the switch reflects exactly the
        // networks CoW runs on (Mainnet + Base today).
        for chain in Chain::ALL.into_iter().filter(|c| super::supported(*c)) {
            let selected = self.chain == chain;
            chips = chips.push(pill_chip(
                t,
                chain.label(),
                selected,
                Message::SetChain(chain),
            ));
        }
        chips.into()
    }

    fn slippage_row<'a>(&self, t: KaoTheme) -> Element<'a, Message> {
        let mut chips = row![text("Max slippage").size(11).color(t.sub).font(mono())]
            .spacing(8)
            .align_y(Alignment::Center);
        for (label, bps) in [("0.1%", 10u16), ("0.5%", 50), ("1%", 100), ("2%", 200)] {
            let selected = self.slippage_bps == bps;
            chips = chips.push(pill_chip(t, label, selected, Message::SetSlippage(bps)));
        }
        chips.into()
    }

    fn quote_summary<'a>(&self, t: KaoTheme, q: &QuoteResponse) -> Element<'a, Message> {
        let sell = self.sell.as_ref();
        let buy = self.buy.as_ref();
        let (sell_dec, sell_sym) = sell
            .map(|s| (s.decimals, s.symbol.as_str()))
            .unwrap_or((18, "?"));
        let (buy_dec, buy_sym) = buy
            .map(|b| (b.decimals, b.symbol.as_str()))
            .unwrap_or((18, "?"));

        let (buy_str, buy_f) = format_token_balance(q.quote.buy_amount, buy_dec);
        let min_raw =
            super::order::apply_slippage(q.quote.buy_amount, self.effective_slippage_bps());
        let (min_str, _) = format_token_balance(min_raw, buy_dec);
        let (_, sell_f) = format_token_balance(q.quote.sell_amount, sell_dec);
        let (fee_str, _) = format_token_balance(q.quote.fee_amount, sell_dec);

        let rate = if sell_f > 0.0 {
            format!("1 {sell_sym} ≈ {:.6} {buy_sym}", buy_f / sell_f)
        } else {
            "—".into()
        };

        let rows = column![
            summary_line(t, "Receive (est.)", &format!("{buy_str} {buy_sym}")),
            summary_line(t, "Rate", &rate),
            summary_line(t, "Min received", &format!("{min_str} {buy_sym}"),),
            summary_line(t, "Network fee", &format!("{fee_str} {sell_sym}")),
        ]
        .spacing(6);

        container(rows)
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
}

// ── Small view helpers ───────────────────────────────────────────────────────

fn label_row<'a>(t: KaoTheme, label: &str) -> Element<'a, Message> {
    text(label.to_string())
        .size(11)
        .color(t.sub)
        .font(mono_bold())
        .into()
}

fn summary_line<'a>(t: KaoTheme, label: &str, value: &str) -> Element<'a, Message> {
    row![
        text(label.to_string()).size(12).color(t.sub),
        Space::new().width(Length::Fill),
        text(value.to_string()).size(12).color(t.text).font(bold()),
    ]
    .width(Length::Fill)
    .into()
}

/// Number of token columns in the picker grid.
const GRID_COLS: usize = 3;

/// Token-count past which a picker shows a search box.
const SEARCH_THRESHOLD: usize = 6;

/// How many tokens a picker shows before "Show more" (the popular set). Keeping
/// the default small also keeps rendering snappy on long lists (e.g. Base).
const POPULAR_LIMIT: usize = 10;

/// Hard cap on rendered tokens even when expanded / searching, so a huge list
/// never rebuilds hundreds of widgets at once — past this, refine the search.
const EXPANDED_LIMIT: usize = 60;

/// Small search box that filters a token grid by symbol. `on_input` is the
/// message constructor (`Message::SellFilter` / `Message::BuyFilter`).
fn search_input<'a>(
    t: KaoTheme,
    value: &str,
    on_input: fn(String) -> Message,
) -> Element<'a, Message> {
    text_input("Search tokens…", value)
        .on_input(on_input)
        .padding(Padding::from([8, 12]))
        .size(13)
        .style(move |_, status| text_input_style(t, status))
        .into()
}

/// A full-width "Show more (N)" button revealing the rest of a capped list.
fn show_more_button<'a>(t: KaoTheme, remaining: usize, msg: Message) -> Element<'a, Message> {
    button(
        text(format!("Show more ({remaining}) ▾"))
            .size(12)
            .color(t.a1)
            .font(bold()),
    )
    .padding(Padding::from([6, 12]))
    .width(Length::Fill)
    .on_press(msg)
    .style(move |_, status| button::Style {
        background: Some(Background::Color(match status {
            button::Status::Hovered | button::Status::Pressed => with_alpha(t.a1, 0.10),
            _ => t.card_alt,
        })),
        text_color: t.a1,
        border: Border {
            color: with_alpha(t.a1, 0.25),
            width: 1.0,
            radius: Radius::from(10),
        },
        ..button::Style::default()
    })
    .into()
}

/// Footer under a token grid when more tokens exist than are shown: a
/// "Show more" button when the list can still expand, otherwise a hint to refine
/// the search (the expanded cap was hit).
fn list_overflow_footer<'a>(
    col: iced::widget::Column<'a, Message>,
    t: KaoTheme,
    total: usize,
    shown: usize,
    expandable: bool,
    expand_msg: Message,
) -> iced::widget::Column<'a, Message> {
    if total <= shown {
        return col;
    }
    let remaining = total - shown;
    if expandable {
        col.push(show_more_button(t, remaining, expand_msg))
    } else {
        col.push(
            text(format!("+{remaining} more — refine your search"))
                .size(11)
                .color(t.sub)
                .font(mono()),
        )
    }
}

/// Lay `cells` out as a grid of [`GRID_COLS`] equal-width columns. The grid does
/// NOT scroll itself — the surface it lives in does (the modal body scrollable,
/// or the Apps pane's outer scrollable), so there's a single scrollbar rather
/// than nested ones.
fn token_grid<'a>(mut cells: Vec<Element<'a, Message>>) -> Element<'a, Message> {
    // A single row's cells fill the full width (wider cards) rather than being
    // pinned to a fraction by phantom padding columns.
    let single_row = cells.len() <= GRID_COLS;

    let mut grid = column![].spacing(8).width(Length::Fill);
    while !cells.is_empty() {
        let take = cells.len().min(GRID_COLS);
        let mut r = row![].spacing(8).width(Length::Fill);
        for cell in cells.drain(0..take) {
            r = r.push(container(cell).width(Length::FillPortion(1)));
        }
        // Pad a short final row (in a multi-row grid) so columns stay aligned.
        if !single_row {
            for _ in take..GRID_COLS {
                r = r.push(Space::new().width(Length::FillPortion(1)));
            }
        }
        grid = grid.push(r);
    }

    grid.into()
}

fn token_chip<'a>(
    t: KaoTheme,
    chain: Chain,
    contract: Option<Address>,
    symbol: &str,
    balance: Option<&str>,
    selected: bool,
    msg: Message,
) -> Element<'a, Message> {
    // Layout: logo · symbol (left, vertically centered) … balance (right,
    // vertically centered). Buy chips carry no balance, so they're just
    // logo · symbol.
    let mut inner = row![
        token_avatar(t, chain, contract, "(◕‿◕)", 20.0, t.ab1),
        Space::new().width(8),
        text(symbol.to_string())
            .size(13)
            .color(t.text)
            .font(bold())
            .wrapping(Wrapping::None),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    if let Some(bal) = balance {
        inner = inner.push(Space::new().width(Length::Fill));
        inner = inner.push(
            text(bal.to_string())
                .size(11)
                .color(t.sub)
                .font(mono())
                .wrapping(Wrapping::None),
        );
    }

    button(inner)
        .padding(Padding::from([8, 12]))
        .width(Length::Fill)
        .on_press(msg)
        .style(move |_, status| {
            let bg = if selected {
                with_alpha(t.a1, 0.16)
            } else {
                match status {
                    button::Status::Hovered | button::Status::Pressed => with_alpha(t.sub, 0.10),
                    _ => t.card_alt,
                }
            };
            button::Style {
                background: Some(Background::Color(bg)),
                text_color: t.text,
                border: Border {
                    color: if selected { t.a1 } else { t.border },
                    width: 1.5,
                    radius: Radius::from(11),
                },
                ..button::Style::default()
            }
        })
        .into()
}

/// Small pill toggle used for the network + slippage selectors.
fn pill_chip<'a>(t: KaoTheme, label: &str, selected: bool, msg: Message) -> Element<'a, Message> {
    button(text(label.to_string()).size(11).color(t.text).font(bold()))
        .padding(Padding::from([4, 10]))
        .on_press(msg)
        .style(move |_, status| {
            let bg = if selected {
                with_alpha(t.a1, 0.16)
            } else {
                match status {
                    button::Status::Hovered | button::Status::Pressed => with_alpha(t.sub, 0.10),
                    _ => t.card_alt,
                }
            };
            button::Style {
                background: Some(Background::Color(bg)),
                text_color: t.text,
                border: Border {
                    color: if selected { t.a1 } else { t.border },
                    width: 1.0,
                    radius: Radius::from(8),
                },
                ..button::Style::default()
            }
        })
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    fn weth_pick() -> SellPick {
        SellPick {
            symbol: "WETH".into(),
            contract: Some(address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")),
            decimals: 18,
            balance_raw: U256::from(2_000_000_000_000_000_000u64), // 2 WETH
        }
    }

    fn usdc_buy() -> BuyPick {
        BuyPick {
            symbol: "USDC".into(),
            address: address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
            decimals: 6,
        }
    }

    #[test]
    fn draft_requires_tokens_and_valid_amount() {
        let mut c = SwapComposer::new();
        assert!(c.draft().is_none());
        c.update(Message::SelectSell(weth_pick()));
        c.update(Message::SelectBuy(usdc_buy()));
        assert!(c.draft().is_none(), "no amount yet");
        c.update(Message::SetAmount("1.5".into()));
        let d = c.draft().expect("valid draft");
        assert_eq!(d.sell_amount, U256::from(1_500_000_000_000_000_000u64));
        assert_eq!(d.chain, Chain::Mainnet);
        assert!(!d.is_native);
    }

    #[test]
    fn over_balance_amount_is_invalid() {
        let mut c = SwapComposer::new();
        c.update(Message::SelectSell(weth_pick()));
        c.update(Message::SelectBuy(usdc_buy()));
        c.update(Message::SetAmount("5".into())); // > 2 WETH balance
        assert!(c.draft().is_none());
    }

    #[test]
    fn native_sell_routes_through_weth() {
        let mut c = SwapComposer::new();
        c.update(Message::SetChain(Chain::Base));
        c.update(Message::SelectSell(SellPick {
            symbol: "ETH".into(),
            contract: None,
            decimals: 18,
            balance_raw: U256::from(10).pow(U256::from(18)),
        }));
        c.update(Message::SelectBuy(BuyPick {
            symbol: "USDC".into(),
            address: address!("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
            decimals: 6,
        }));
        c.update(Message::SetAmount("0.5".into()));
        let d = c.draft().unwrap();
        assert!(d.is_native);
        assert_eq!(d.chain, Chain::Base);
        assert_eq!(
            d.sell_token,
            super::super::wrapped_native(Chain::Base).unwrap()
        );
    }

    #[test]
    fn get_quote_emits_request_when_valid() {
        let mut c = SwapComposer::new();
        c.update(Message::SelectSell(weth_pick()));
        c.update(Message::SelectBuy(usdc_buy()));
        c.update(Message::SetAmount("1".into()));
        let out = c.update(Message::GetQuote);
        assert!(matches!(out, Some(Outcome::RequestQuote(_))));
    }

    #[test]
    fn switching_network_clears_selections() {
        let mut c = SwapComposer::new(); // mainnet
        c.update(Message::SelectSell(weth_pick()));
        c.update(Message::SelectBuy(usdc_buy()));
        c.update(Message::SetAmount("1".into()));
        assert!(c.sell.is_some() && c.buy.is_some());
        c.update(Message::SetChain(Chain::Base));
        assert!(c.sell.is_none(), "sell cleared on network switch");
        assert!(c.buy.is_none(), "buy cleared on network switch");
        assert_eq!(c.amount, "");
        // Same-network re-select is a no-op (keeps state).
        c.update(Message::SetChain(Chain::Base));
        assert_eq!(c.chain, Chain::Base);
    }

    #[test]
    fn filters_are_view_only_and_cleared_on_network_switch() {
        let mut c = SwapComposer::new();
        c.update(Message::SelectSell(weth_pick()));
        c.update(Message::SellFilter("us".into()));
        c.update(Message::BuyFilter("we".into()));
        assert_eq!(c.sell_filter, "us");
        assert_eq!(c.buy_filter, "we");
        // Filtering must not deselect the chosen token.
        assert!(c.sell.is_some());
        // Switching networks resets the filters.
        c.update(Message::SetChain(Chain::Base));
        assert_eq!(c.sell_filter, "");
        assert_eq!(c.buy_filter, "");
    }

    #[test]
    fn native_sell_floors_slippage_to_2pct() {
        let mut c = SwapComposer::new();
        c.update(Message::SetChain(Chain::Base));
        c.update(Message::SetSlippage(50)); // user picks 0.5%
        c.update(Message::SelectSell(SellPick {
            symbol: "ETH".into(),
            contract: None,
            decimals: 18,
            balance_raw: U256::from(10).pow(U256::from(18)),
        }));
        c.update(Message::SelectBuy(BuyPick {
            symbol: "USDC".into(),
            address: address!("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
            decimals: 6,
        }));
        c.update(Message::SetAmount("0.1".into()));
        assert_eq!(
            c.draft().unwrap().slippage_bps,
            200,
            "native ETH must be floored to EthFlow's 2% minimum"
        );
    }

    #[test]
    fn erc20_sell_uses_chosen_slippage() {
        let mut c = SwapComposer::new();
        c.update(Message::SetSlippage(50));
        c.update(Message::SelectSell(weth_pick())); // ERC-20
        c.update(Message::SelectBuy(usdc_buy()));
        c.update(Message::SetAmount("1".into()));
        assert_eq!(c.draft().unwrap().slippage_bps, 50);
    }

    #[test]
    fn native_max_reserves_gas() {
        let mut c = SwapComposer::new(); // mainnet
        c.update(Message::SelectSell(SellPick {
            symbol: "ETH".into(),
            contract: None,
            decimals: 18,
            balance_raw: U256::from(10).pow(U256::from(18)), // 1 ETH
        }));
        c.update(Message::MaxAmount);
        let amt = parse_amount_units(&c.amount, 18).unwrap();
        assert!(
            amt < U256::from(10).pow(U256::from(18)),
            "native Max must hold back gas, not sell 100%"
        );
        assert!(amt > U256::ZERO);
    }

    #[test]
    fn native_max_with_dust_balance_warns_instead_of_zero() {
        let mut c = SwapComposer::new(); // mainnet
        c.update(Message::SelectSell(SellPick {
            symbol: "ETH".into(),
            contract: None,
            decimals: 18,
            balance_raw: U256::from(18_000_000_000_000u64), // 0.000018 ETH — below the reserve
        }));
        c.update(Message::MaxAmount);
        assert_eq!(c.amount, "", "dust Max must not fill in a misleading 0");
        assert!(c.error.is_some(), "should explain why Max is unavailable");
    }

    #[test]
    fn erc20_max_uses_full_balance() {
        let mut c = SwapComposer::new();
        c.update(Message::SelectSell(weth_pick())); // 2 WETH (ERC-20)
        c.update(Message::MaxAmount);
        let amt = parse_amount_units(&c.amount, 18).unwrap();
        assert!(
            amt >= U256::from(1_999_000_000_000_000_000u64),
            "ERC-20 Max should use ~full balance"
        );
    }

    #[test]
    fn amount_field_rejects_non_numeric() {
        let mut c = SwapComposer::new();
        c.update(Message::SelectSell(weth_pick()));
        c.update(Message::SetAmount("1.2.3".into()));
        assert_ne!(c.amount, "1.2.3");
        c.update(Message::SetAmount("abc".into()));
        assert_ne!(c.amount, "abc");
        c.update(Message::SetAmount("1.5".into()));
        assert_eq!(c.amount, "1.5");
    }
}
