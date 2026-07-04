//! Transaction details modal — full info for a single row in the activity
//! pane plus an explorer URL the user can copy.
//!
//! The pane is a passive viewer: it owns a cloned `IndexedTx` and the
//! owner address (so it can colour from/to consistently with the
//! activity row), and it bubbles `CopyText`/`Closed` outcomes upward to
//! the dashboard's existing clipboard plumbing.

use std::time::{SystemTime, UNIX_EPOCH};

use iced::keyboard;
use iced::widget::{Space, column, container, row, scrollable, text};
use iced::{Alignment, Element, Length, Padding, Subscription, Task};

use crate::indexer::{IndexedTx, TxDirection, TxStatus};
use crate::portfolio::format_token_balance;
use crate::settings::{self, IndexerProvider};
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    black, bold, colored_address, kao_fit, kao_scrollable_style, modal_wrapper, mono, mono_black,
    mono_bold, secondary_button, small_secondary_button,
};
use crate::wallet::ContactsBook;

#[derive(Debug, Clone)]
pub enum Message {
    /// No-op published by a copyable address click so the dashboard's "Copied!"
    /// toast animation starts (a click changes no state otherwise). Ignored.
    AddressCopied,
    CopyHash,
    CopyExplorerUrl,
    CopyFrom,
    CopyTo,
    /// User tapped copy on the Token contract / Collection field. Only
    /// emitted when the row carries an ERC-20 / NFT contract.
    CopyAsset,
    Close,
    BoxClickIgnored,
    Key(keyboard::Event),
}

#[derive(Debug, Clone)]
pub enum Outcome {
    Closed,
    CopyText(String),
}

impl Outcome {
    /// Variant name for the GUI state trace.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Closed => "Closed",
            Outcome::CopyText(_) => "CopyText",
        }
    }
}

#[derive(Debug)]
pub struct TxDetailsPane {
    tx: IndexedTx,
    /// Resolved at construction time so `view` doesn't reread settings on
    /// every redraw. The provider's hosted explorer (Blockscout web UI)
    /// is preferred when the user is using Blockscout; otherwise we fall
    /// back to Etherscan.
    explorer_url: String,
    /// Pre-formatted button label ("Copy Etherscan link" / "Copy
    /// Blockscout link"). Stored on the pane because `secondary_button`
    /// borrows the label by reference; building it inside `view` would
    /// produce a value that doesn't outlive the function.
    copy_url_label: String,
}

impl TxDetailsPane {
    pub fn new(tx: IndexedTx) -> Self {
        let (explorer_url, explorer_label) = explorer_for(&tx);
        let copy_url_label = format!("Copy {explorer_label} link");
        Self {
            tx,
            explorer_url,
            copy_url_label,
        }
    }

    pub fn update(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("tx_details", &msg);
        let (task, outcome) = match msg {
            // Copy-toast kick — the widget already copied + marked the toast.
            Message::AddressCopied => (Task::none(), None),
            Message::CopyHash => (
                Task::none(),
                Some(Outcome::CopyText(format!("{:#x}", self.tx.hash))),
            ),
            Message::CopyExplorerUrl => (
                Task::none(),
                Some(Outcome::CopyText(self.explorer_url.clone())),
            ),
            Message::CopyFrom => (
                Task::none(),
                Some(Outcome::CopyText(self.tx.from.to_checksum(None))),
            ),
            Message::CopyTo => match self.tx.to {
                Some(addr) => (
                    Task::none(),
                    Some(Outcome::CopyText(addr.to_checksum(None))),
                ),
                None => (Task::none(), None),
            },
            Message::CopyAsset => match self.tx.token.as_ref() {
                Some(tok) => (
                    Task::none(),
                    Some(Outcome::CopyText(tok.contract.to_checksum(None))),
                ),
                None => (Task::none(), None),
            },
            Message::Close => (Task::none(), Some(Outcome::Closed)),
            Message::BoxClickIgnored => (Task::none(), None),
            Message::Key(keyboard::Event::KeyPressed { key, .. }) => {
                if let keyboard::Key::Named(keyboard::key::Named::Escape) = key {
                    (Task::none(), Some(Outcome::Closed))
                } else {
                    (Task::none(), None)
                }
            }
            Message::Key(_) => (Task::none(), None),
        };
        if let Some(o) = &outcome {
            crate::trace::outcome("tx_details", o.name());
        }
        (task, outcome)
    }

    pub fn subscription(&self) -> Subscription<Message> {
        keyboard::listen().map(Message::Key)
    }

    pub fn view<'a>(
        &'a self,
        t: KaoTheme,
        progress: f32,
        contacts: &ContactsBook,
    ) -> Element<'a, Message> {
        let kao = match self.tx.direction {
            TxDirection::In => "(っ◕‿◕)っ",
            TxDirection::Out => "ᕕ( ᐛ )ᕗ",
            TxDirection::SelfTransfer => "(･ω･)ﾉ",
        };
        let header_kao = container(kao_fit(t, kao, 220.0, 52.0))
            .width(Length::Fill)
            .center_x(Length::Fill);

        let direction_label = match self.tx.direction {
            TxDirection::In => "Received",
            TxDirection::Out => "Sent",
            TxDirection::SelfTransfer => "Self transfer",
        };
        let title = container(text(direction_label).size(14).color(t.sub).font(bold()))
            .width(Length::Fill)
            .center_x(Length::Fill);

        // ── Hero amount block ────────────────────────────────────────────
        // Two-line presentation: big signed number on top, token symbol
        // (or "ETH"/"NFT #N") underneath, so the eye lands on the
        // magnitude first and the asset second. Splitting the previous
        // single-line `±X.YYY SYM` into discrete lines is the change the
        // user asked for — "what token + what amount" is now scannable.
        let parts = amount_parts(&self.tx, self.tx.direction);
        let amount_color = match self.tx.direction {
            TxDirection::In if self.has_movement() => t.up,
            _ => t.text,
        };
        let amount_top = text(parts.amount)
            .size(34)
            .color(amount_color)
            .font(mono_black());
        let amount_bottom = text(parts.label).size(16).color(t.text).font(black());
        let amount = container(
            column![amount_top, Space::new().height(2), amount_bottom].align_x(Alignment::Center),
        )
        .width(Length::Fill)
        .center_x(Length::Fill);

        let status_text = match self.tx.status {
            TxStatus::Success => "✓ Success",
            TxStatus::Failure => "× Failed",
            TxStatus::Pending => "⋯ Pending",
        };
        let status_color = match self.tx.status {
            TxStatus::Success => t.up,
            TxStatus::Failure => t.down,
            TxStatus::Pending => t.sub,
        };
        let status = container(text(status_text).size(12).color(status_color).font(bold()))
            .width(Length::Fill)
            .center_x(Length::Fill);

        // ── Field stack ──────────────────────────────────────────────────
        let mut fields = column![].spacing(14).width(Length::Fill);

        // Asset: only present for ERC-20 / ERC-721. Showing the token
        // contract address is the load-bearing detail for verifying that
        // a "USDC" label isn't a look-alike scam token. Native ETH rows
        // skip this block entirely — the contract is meaningless there.
        if let Some(tok) = &self.tx.token {
            fields = fields.push(field(
                t,
                if tok.is_nft {
                    "Collection"
                } else {
                    "Token contract"
                },
                colored_address(t, tok.contract),
                Some(Message::CopyAsset),
            ));
        }

        // Contact-aware From/To: when the counterparty matches a saved
        // contact, render the name above the colored chunked address
        // so the user gets a quick "oh, this is Friend" recognition.
        // The chunked address remains the load-bearing identifier.
        let from_name: Option<String> = contacts.name_for(self.tx.from).map(str::to_string);
        fields = fields.push(field(
            t,
            "From",
            named_address_block(t, from_name, colored_address(t, self.tx.from)),
            Some(Message::CopyFrom),
        ));
        match self.tx.to {
            Some(addr) => {
                let to_name: Option<String> = contacts.name_for(addr).map(str::to_string);
                fields = fields.push(field(
                    t,
                    "To",
                    named_address_block(t, to_name, colored_address(t, addr)),
                    Some(Message::CopyTo),
                ));
            }
            None => {
                fields = fields.push(field(
                    t,
                    "To",
                    text("Contract creation")
                        .size(13)
                        .color(t.sub)
                        .font(mono())
                        .into(),
                    None,
                ));
            }
        }

        // Chain (always shown so a merged feed is unambiguous about which
        // network a tx settled on).
        fields = fields.push(simple_field(
            t,
            "Network",
            self.tx.chain.display_name().to_string(),
        ));

        if self.tx.block_number > 0 {
            fields = fields.push(simple_field(t, "Block", self.tx.block_number.to_string()));
        }

        if self.tx.timestamp > 0 {
            fields = fields.push(simple_field(t, "When", format_when(self.tx.timestamp)));
        }

        if let (Some(used), Some(price)) = (self.tx.gas_used, self.tx.gas_price) {
            let fee_wei = (used as u128).saturating_mul(price);
            let fee =
                alloy::primitives::utils::format_ether(alloy::primitives::U256::from(fee_wei));
            let f = fee.parse::<f64>().unwrap_or(0.0);
            fields = fields.push(simple_field(t, "Fee", format!("{} ETH", trim_amount(f))));
        }

        if let Some(method) = &self.tx.method
            && !method.is_empty()
        {
            fields = fields.push(simple_field(t, "Method", method.clone()));
        }

        // Hash: short form (0x1111…1111). The full 66-char hash used to
        // wrap to two ugly lines and dwarf every other field. Users who
        // need the canonical form get it from Copy or the explorer.
        fields = fields.push(field(
            t,
            "Hash",
            text(short_hash(&self.tx.hash))
                .size(14)
                .color(t.text)
                .font(mono_bold())
                .into(),
            Some(Message::CopyHash),
        ));

        // ── Action buttons ───────────────────────────────────────────────
        let actions = row![
            container(
                secondary_button(t, &self.copy_url_label).on_press(Message::CopyExplorerUrl),
            )
            .width(Length::FillPortion(1)),
            Space::new().width(10),
            container(secondary_button(t, "Copy hash").on_press(Message::CopyHash))
                .width(Length::FillPortion(1)),
        ]
        .width(Length::Fill);

        let body = column![
            header_kao,
            Space::new().height(8),
            title,
            Space::new().height(10),
            amount,
            Space::new().height(8),
            status,
            Space::new().height(22),
            fields,
            Space::new().height(20),
            actions,
        ]
        .width(Length::Fill)
        .align_x(Alignment::Center);

        // The full address rendering can push the modal taller than the
        // window in compact themes; wrap in a scrollable so the user can
        // still reach the action buttons.
        let scrollable_body = scrollable(container(body).width(Length::Fill))
            .height(Length::Shrink)
            .style(move |_, s| kao_scrollable_style(t, s));

        modal_wrapper(
            t,
            420.0,
            progress,
            Message::Close,
            Message::BoxClickIgnored,
            scrollable_body.into(),
        )
    }

    fn has_movement(&self) -> bool {
        match &self.tx.token {
            Some(tok) => !tok.amount_raw.is_zero(),
            None => !self.tx.value.is_zero(),
        }
    }
}

// ── Field helpers ───────────────────────────────────────────────────────────

/// Label-on-top, value-below row. `copy` adds a small trailing copy
/// affordance; `None` renders plain.
fn field<'a>(
    t: KaoTheme,
    label: &'a str,
    value: Element<'a, Message>,
    copy: Option<Message>,
) -> Element<'a, Message> {
    let label = text(label.to_string()).size(13).color(t.sub).font(bold());
    let header = match copy {
        Some(msg) => row![
            label,
            Space::new().width(Length::Fill),
            small_secondary_button(t, "Copy").on_press(msg),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill),
        None => row![label].width(Length::Fill),
    };
    column![header, Space::new().height(4), value]
        .width(Length::Fill)
        .spacing(0)
        .into()
}

/// Single-line `label / value` field for plain strings. Compact form
/// used by Block / Fee / Method / When.
fn simple_field<'a>(t: KaoTheme, label: &'a str, value: String) -> Element<'a, Message> {
    row![
        text(label.to_string()).size(13).color(t.sub),
        Space::new().width(Length::Fill),
        text(value).size(13).color(t.text).font(mono_bold()),
    ]
    .align_y(Alignment::Center)
    .padding(Padding::from([2, 0]))
    .width(Length::Fill)
    .into()
}

// ── Formatting helpers ──────────────────────────────────────────────────────

/// Hero-amount split: top line is the signed magnitude (`+5.000`,
/// `−0.0024`, or `BAYC` for NFTs); bottom line is the asset label
/// (`USDC`, `ETH`, `#4321`). Splitting them lets the modal hierarchy
/// answer "how much" and "what" with two distinct visual weights.
struct AmountParts {
    amount: String,
    label: String,
}

fn amount_parts(tx: &IndexedTx, direction: TxDirection) -> AmountParts {
    let recv = matches!(direction, TxDirection::In | TxDirection::SelfTransfer);
    let sign = if recv { "+" } else { "−" };
    if let Some(tok) = &tx.token {
        let symbol = if tok.symbol.is_empty() {
            if tok.is_nft { "NFT" } else { "tokens" }.to_string()
        } else {
            tok.symbol.clone()
        };
        if tok.is_nft {
            // ERC-721: top line carries the collection symbol (the most
            // recognizable handle), bottom line carries the token id so
            // both pieces render at distinct sizes.
            let id = tok
                .token_id
                .map(|id| format!("#{id}"))
                .unwrap_or_else(|| "—".to_string());
            return AmountParts {
                amount: format!("{sign}{symbol}"),
                label: id,
            };
        }
        let amount = if tok.amount_raw.is_zero() {
            "0".to_string()
        } else {
            let (_, f) = format_token_balance(tok.amount_raw, tok.decimals);
            format!("{sign}{}", trim_amount(f))
        };
        return AmountParts {
            amount,
            label: symbol,
        };
    }
    if tx.value.is_zero() {
        return AmountParts {
            amount: "0".to_string(),
            label: "ETH".to_string(),
        };
    }
    let raw = alloy::primitives::utils::format_ether(tx.value);
    let f = raw.parse::<f64>().unwrap_or(0.0);
    AmountParts {
        amount: format!("{sign}{}", trim_amount(f)),
        label: "ETH".to_string(),
    }
}

/// Short-hash form for the modal's Hash field: `0x1111…1111`. The full
/// hash is still copyable via the field's Copy affordance and the
/// "Copy hash" action button.
fn short_hash(hash: &alloy::primitives::B256) -> String {
    let full = format!("{hash:#x}");
    if full.len() <= 12 {
        return full;
    }
    format!("{}…{}", &full[..6], &full[full.len() - 4..])
}

fn trim_amount(f: f64) -> String {
    if f >= 1.0 {
        format!("{f:.4}")
    } else {
        let s = format!("{f:.6}");
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

/// "2026-05-01 10:49 UTC". The activity row already shows the relative
/// "3 hrs ago" form; this modal adds an absolute timestamp so the user
/// can correlate against external records (block explorer, exchange
/// statements, etc.).
fn format_when(unix_secs: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let abs = format_iso_utc(unix_secs);
    if now == 0 || unix_secs > now {
        return abs;
    }
    let diff = now.saturating_sub(unix_secs);
    let relative = if diff < 60 {
        "just now".to_string()
    } else if diff < 3600 {
        format!("{} min ago", diff / 60)
    } else if diff < 86_400 {
        let hrs = diff / 3600;
        format!("{hrs} hr{} ago", if hrs == 1 { "" } else { "s" })
    } else {
        let days = diff / 86_400;
        format!("{days} day{} ago", if days == 1 { "" } else { "s" })
    };
    format!("{abs} ({relative})")
}

/// Stack a contact name (when present) on top of a colored address
/// element, returning a single Element suitable for the field-block
/// `value` slot. When `name` is `None`, the address is returned as-is
/// so existing layouts (no contact match) stay unchanged.
fn named_address_block<'a>(
    t: KaoTheme,
    name: Option<String>,
    address: Element<'a, Message>,
) -> Element<'a, Message> {
    match name {
        Some(n) => column![
            text(n).size(13).color(t.text).font(bold()),
            iced::widget::Space::new().height(4),
            address,
        ]
        .width(Length::Fill)
        .spacing(0)
        .into(),
        None => address,
    }
}

/// `YYYY-MM-DD HH:MM UTC` from unix seconds. Reuses the same civil-day
/// algorithm the indexer already trusts for parsing — kept inline so we
/// don't drag a chrono dependency in for a single label.
fn format_iso_utc(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = unix_secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02} UTC")
}

/// Inverse of `days_from_civil` from the indexer module — Howard
/// Hinnant's public-domain algorithm. Accepts proleptic Gregorian days
/// since 1970-01-01 and returns (year, month, day).
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Build a `(url, label)` pair for the active indexer's web explorer,
/// routed to the chain the row came from. Blockscout users get the
/// canonical Blockscout instance for the chain (their mainnet override
/// applies only to Mainnet rows); everyone else gets the canonical
/// per-chain Etherscan-family explorer.
fn explorer_for(tx: &IndexedTx) -> (String, String) {
    use crate::chain::Chain;
    let hash = format!("{:#x}", tx.hash);
    match settings::indexer_provider() {
        IndexerProvider::Blockscout => {
            let base = if tx.chain == Chain::Mainnet {
                settings::blockscout_base_url()
                    .unwrap_or_else(|| tx.chain.default_blockscout_url().to_string())
            } else {
                tx.chain.default_blockscout_url().to_string()
            };
            let trimmed = base.trim_end_matches('/');
            (format!("{trimmed}/tx/{hash}"), "Blockscout".to_string())
        }
        _ => {
            let (url, label) = match tx.chain {
                Chain::Mainnet => ("https://etherscan.io", "Etherscan"),
                Chain::Base => ("https://basescan.org", "BaseScan"),
                Chain::Optimism => ("https://optimistic.etherscan.io", "Optimistic Etherscan"),
            };
            (format!("{url}/tx/{hash}"), label.to_string())
        }
    }
}
