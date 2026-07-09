//! Apps pane — surface 2 of the CoW integration. A persistent, non-blocking
//! workspace. It opens on an **app launcher** (a "Swap" card + the live order
//! list); clicking Swap reveals the inline composer. Placed orders keep
//! tracking their status while the user navigates elsewhere.
//!
//! Pane state is the shared [`SwapComposer`] plus which view is showing; the
//! tracked-order list lives on the dashboard coordinator (so it survives leaving
//! this pane) and is threaded into [`AppsPane::view`].

use iced::border::Radius;
use iced::keyboard;
use iced::widget::{Space, button, column, container, row, scrollable, text};
use iced::{Alignment, Background, Border, Element, Length, Padding, Subscription};

use alloy::primitives::Address;

use crate::cow::api::QuoteResponse;
use crate::cow::composer::{self, SwapComposer, SwapDraft};
use crate::cow::tracked::{OrderStatus, TrackedOrder};
use crate::portfolio::{LiveToken, format_token_balance};

use super::names_app::{self, NamesApp};
use super::pool_app::{self, PoolApp};
use super::tx_builder::{self, TxBuilderApp};
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::{
    avatar, bold, ghost_button, kao_scrollable_style, mono, mono_bold, screen_subtitle,
    screen_title,
};

// Carries composer messages (with an embedded QuoteResponse); not stored in
// bulk, so the size gap isn't worth boxing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Message {
    /// Open the Swap app from the launcher.
    OpenSwapApp,
    /// Open the Names app from the launcher.
    OpenNamesApp,
    /// Open the Privacy Pools app from the launcher.
    OpenPrivacyPoolsApp,
    /// Open the Transaction Builder app from the launcher.
    OpenTxBuilderApp,
    /// Messages for the embedded Names app.
    Names(names_app::Message),
    /// Messages for the embedded Privacy Pools app.
    Pool(pool_app::Message),
    /// Messages for the embedded Transaction Builder app.
    TxBuilder(tx_builder::Message),
    /// Return from a sub-app to the launcher.
    BackHome,
    Composer(composer::Message),
    Cancel(String),
    /// Copy an order's CoW Explorer URL to the clipboard.
    CopyExplorerLink(String),
    /// User asked to refresh the tracked orders' status now.
    RefreshOrders,
    /// Raw keyboard event — only subscribed inside the Swap app, where Esc
    /// steps back to the launcher.
    Key(keyboard::Event),
}

/// Which Apps view is showing: the launcher, or one of the sub-apps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppsView {
    Launcher,
    Swap,
    Names,
    PrivacyPools,
    TxBuilder,
}

impl AppsView {
    /// Variant name for the GUI state trace.
    fn name(self) -> &'static str {
        match self {
            AppsView::Launcher => "Launcher",
            AppsView::Swap => "Swap",
            AppsView::Names => "Names",
            AppsView::PrivacyPools => "PrivacyPools",
            AppsView::TxBuilder => "TxBuilder",
        }
    }
}

// `Request*`-prefixed by design (these are the requests the pane bubbles up);
// one-shot, so the QuoteResponse size gap isn't worth boxing.
#[allow(clippy::large_enum_variant, clippy::enum_variant_names)]
#[derive(Debug, Clone)]
pub enum Outcome {
    RequestQuote(SwapDraft),
    RequestPlace {
        draft: SwapDraft,
        quote: QuoteResponse,
    },
    RequestCancel {
        uid: String,
    },
    /// Copy text to the clipboard (an order's CoW Explorer link). The
    /// coordinator owns the clipboard write + auto-clear, mirroring TxDetails.
    CopyText(String),
    /// Poll the tracked orders' status on demand.
    RefreshOrders,
    /// A request bubbled up from the embedded Names app (verified read or
    /// signed transaction); the coordinator services it and feeds the result
    /// back via [`AppsPane::names_pane`].
    Name(names_app::Outcome),
    /// A request bubbled up from the embedded Privacy Pools app; the coordinator
    /// services it (discover/sync/quote/prove/submit, seed plumbing) and feeds
    /// the result back via [`AppsPane::pool_pane`].
    Pool(pool_app::Outcome),
    /// A request bubbled up from the embedded Transaction Builder app
    /// (resolve a contract, simulate a batch, or open the sign-review for
    /// it); the coordinator services it and feeds results back via
    /// [`AppsPane::txbuilder_pane`].
    TxBuilder(tx_builder::Outcome),
}

impl Outcome {
    /// Variant name for the GUI state trace — never the payload.
    fn name(&self) -> &'static str {
        match self {
            Outcome::RequestQuote(_) => "RequestQuote",
            Outcome::RequestPlace { .. } => "RequestPlace",
            Outcome::RequestCancel { .. } => "RequestCancel",
            Outcome::CopyText(_) => "CopyText",
            Outcome::RefreshOrders => "RefreshOrders",
            Outcome::Name(_) => "Name",
            Outcome::Pool(_) => "Pool",
            Outcome::TxBuilder(_) => "TxBuilder",
        }
    }
}

#[derive(Debug)]
pub struct AppsPane {
    composer: SwapComposer,
    names: NamesApp,
    pool: PoolApp,
    tx_builder: TxBuilderApp,
    view: AppsView,
}

impl AppsPane {
    pub fn new(owner: Address) -> Self {
        Self {
            composer: SwapComposer::new(),
            names: NamesApp::new(owner),
            pool: PoolApp::new(),
            tx_builder: TxBuilderApp::new(owner),
            view: AppsView::Launcher,
        }
    }

    /// Mutable access to the Transaction Builder app so the coordinator can
    /// deliver async results (resolved contract code, batch simulation,
    /// post-execute cleanup).
    pub fn txbuilder_pane(&mut self) -> &mut TxBuilderApp {
        &mut self.tx_builder
    }

    /// Refresh the builder's identity context (active chain + whether a Safe
    /// is active) before it processes a message, so batch-cap and known-
    /// contract lookup see the live identity.
    pub fn set_txbuilder_context(
        &mut self,
        chain: crate::chain::Chain,
        is_safe: bool,
        safe_version: Option<String>,
        eoa_can_batch: bool,
    ) {
        self.tx_builder
            .set_context(chain, is_safe, safe_version, eoa_can_batch);
    }

    /// Mutable access to the Privacy Pools app so the coordinator can deliver
    /// async results (synced state, quotes, proving progress, backup phrase).
    pub fn pool_pane(&mut self) -> &mut PoolApp {
        &mut self.pool
    }

    /// Mutable access to the Names app so the coordinator can deliver async
    /// results (`on_scan` / `on_commit` / …).
    pub fn names_pane(&mut self) -> &mut NamesApp {
        &mut self.names
    }

    pub fn on_quote(&mut self, result: Result<QuoteResponse, String>) {
        self.composer.update(composer::Message::QuoteResult(result));
    }

    /// Placement succeeded — clear the composer but stay on the Swap app, where
    /// the new order now appears in the list below (non-blocking). Returning to
    /// the launcher here would yank the user out of the app they're using.
    pub fn placement_done(&mut self) {
        self.composer.reset();
    }

    pub fn placement_failed(&mut self, e: String) {
        self.composer.set_error(e);
    }

    pub fn update(&mut self, msg: Message) -> Option<Outcome> {
        // Pool's Tick is a ~16ms animation frame (proving spinner / loading
        // skeleton) — tracing it would drown the stream.
        if !matches!(msg, Message::Pool(pool_app::Message::Tick)) {
            crate::trace_msg!("apps", &msg);
        }
        let view_before = self.view.name();
        let outcome = self.update_inner(msg);
        if view_before != self.view.name() {
            crate::trace::state("apps", "view", view_before, self.view.name());
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("apps", o.name());
        }
        outcome
    }

    fn update_inner(&mut self, msg: Message) -> Option<Outcome> {
        match msg {
            Message::OpenSwapApp => {
                self.view = AppsView::Swap;
                None
            }
            Message::OpenNamesApp => {
                self.view = AppsView::Names;
                // Kick off the reverse-lookup scan the first time it's opened.
                self.names.on_open().map(Outcome::Name)
            }
            Message::OpenPrivacyPoolsApp => {
                self.view = AppsView::PrivacyPools;
                // Load the identity + sync the first time it's opened.
                self.pool.on_open().map(Outcome::Pool)
            }
            Message::OpenTxBuilderApp => {
                self.view = AppsView::TxBuilder;
                None
            }
            Message::Names(child) => self.names.update(child).map(Outcome::Name),
            Message::TxBuilder(child) => match self.tx_builder.update(child) {
                // The "← Apps" link steps back to the launcher rather than
                // bubbling to the dashboard.
                Some(tx_builder::Outcome::Close) => {
                    self.view = AppsView::Launcher;
                    None
                }
                other => other.map(Outcome::TxBuilder),
            },
            Message::Pool(child) => match self.pool.update(child) {
                // The pane's "← Apps" link steps back to the launcher rather
                // than bubbling to the dashboard.
                Some(pool_app::Outcome::Close) => {
                    self.view = AppsView::Launcher;
                    None
                }
                other => other.map(Outcome::Pool),
            },
            Message::BackHome => {
                self.view = AppsView::Launcher;
                None
            }
            Message::Composer(cm) => match self.composer.update(cm) {
                Some(composer::Outcome::RequestQuote(draft)) => Some(Outcome::RequestQuote(draft)),
                Some(composer::Outcome::RequestPlace { draft, quote }) => {
                    Some(Outcome::RequestPlace { draft, quote })
                }
                None => None,
            },
            Message::Cancel(uid) => Some(Outcome::RequestCancel { uid }),
            Message::CopyExplorerLink(url) => Some(Outcome::CopyText(url)),
            Message::RefreshOrders => Some(Outcome::RefreshOrders),
            Message::Key(event) => {
                // Esc inside the Swap app steps back to the launcher (the same
                // as the "← Apps" link), rather than doing nothing.
                if let keyboard::Event::KeyPressed {
                    key: keyboard::Key::Named(keyboard::key::Named::Escape),
                    ..
                } = event
                    && matches!(
                        self.view,
                        AppsView::Swap
                            | AppsView::Names
                            | AppsView::PrivacyPools
                            | AppsView::TxBuilder
                    )
                {
                    self.view = AppsView::Launcher;
                }
                None
            }
        }
    }

    /// Listen for Esc only while the Swap app is open, so it can step back to
    /// the launcher. The launcher itself has nothing to step back to, so it
    /// subscribes to nothing.
    pub fn subscription(&self) -> Subscription<Message> {
        match self.view {
            AppsView::Swap => keyboard::listen().map(Message::Key),
            // Names also needs its own 1s tick for the commit→reveal countdown.
            AppsView::Names => Subscription::batch([
                keyboard::listen().map(Message::Key),
                self.names.subscription().map(Message::Names),
            ]),
            // Privacy Pools needs Esc-to-back plus its own tick (quote-expiry
            // countdown / proving animation).
            AppsView::PrivacyPools => Subscription::batch([
                keyboard::listen().map(Message::Key),
                self.pool.subscription().map(Message::Pool),
            ]),
            // Esc steps back to the launcher.
            AppsView::TxBuilder => keyboard::listen().map(Message::Key),
            AppsView::Launcher => Subscription::none(),
        }
    }

    pub fn view<'a>(
        &'a self,
        t: KaoTheme,
        portfolio: &'a [LiveToken],
        orders: &[&'a TrackedOrder],
        names_available: bool,
        recipients: super::send::ContactsView,
    ) -> Element<'a, Message> {
        let content = match self.view {
            AppsView::Launcher => self.launcher_view(t, orders, names_available),
            AppsView::Swap => self.swap_view(t, portfolio, orders),
            // Names is unavailable for a non-Mainnet Safe (the launcher hides the
            // card). Fall back to the launcher if we landed on the Names view
            // before switching to such an identity.
            AppsView::Names if !names_available => self.launcher_view(t, orders, names_available),
            AppsView::Names => self.names.view(t).map(Message::Names),
            AppsView::PrivacyPools => self.pool.view(t, portfolio, recipients).map(Message::Pool),
            AppsView::TxBuilder => self.tx_builder.view(t).map(Message::TxBuilder),
        };

        // Center the bounded (max-width 560) content within the full-width
        // scroll area. Centering has to live on the inner container: the
        // scrollable fills the pane, so its own child is what needs to be
        // both Fill-width and center-aligned — an outer `center_x` on the
        // scrollable itself is a no-op (it already fills).
        let scroller = scrollable(
            container(content)
                .center_x(Length::Fill)
                .padding(Padding::from([28, 32])),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .style(move |_, status| kao_scrollable_style(t, status));

        container(scroller)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    /// The app launcher: a card per available app. The order list lives inside
    /// the Swap app; the card shows a count of open orders. `names_available`
    /// gates the Names card — names register/resolve against the active identity
    /// (an EOA, or a Mainnet Safe), so it's hidden for a non-Mainnet Safe.
    fn launcher_view<'a>(
        &self,
        t: KaoTheme,
        orders: &[&'a TrackedOrder],
        names_available: bool,
    ) -> Element<'a, Message> {
        let open_count = orders.iter().filter(|o| !o.status.is_terminal()).count();
        let swap_sub = if open_count > 0 {
            format!("Trade via CoW Protocol · {open_count} open")
        } else {
            "Trade tokens via CoW Protocol".to_string()
        };
        let subtitle = if names_available {
            "On-chain apps — swaps and name registration"
        } else {
            "On-chain apps — swaps"
        };

        let mut col = column![
            screen_title(t, "Apps"),
            Space::new().height(6),
            screen_subtitle(t, subtitle),
            Space::new().height(20),
            app_card(t, "(⇌ω⇌)", "Swap", &swap_sub, Message::OpenSwapApp),
        ];
        if names_available {
            col = col.push(Space::new().height(10)).push(app_card(
                t,
                "(✎ω✎)",
                "Names",
                "Search & register .eth / .gwei / .wei / .xns names",
                Message::OpenNamesApp,
            ));
        }
        // Privacy Pools is its own EOA-independent identity with its own chain
        // selector (Ethereum + Optimism), so the card is always available.
        col = col.push(Space::new().height(10)).push(app_card(
            t,
            "(≖ᴗ≖)",
            "Privacy Pools",
            "Deposit & withdraw privately with ZK proofs",
            Message::OpenPrivacyPoolsApp,
        ));
        // Transaction Builder works for both a plain EOA (single call) and a
        // Safe (atomic MultiSend batch), so the card is always available.
        col = col.push(Space::new().height(10)).push(app_card(
            t,
            "( •̀ω•́ )✧",
            "Transaction Builder",
            "Compose contract calls & batch them atomically",
            Message::OpenTxBuilderApp,
        ));
        col.width(Length::Fill).max_width(560).into()
    }

    /// The Swap app: a back link, the inline composer, and the live order list
    /// (with an on-demand fetch button). The Apps pane has its own outer
    /// scrollbar, so everything renders inline here.
    fn swap_view<'a>(
        &'a self,
        t: KaoTheme,
        portfolio: &'a [LiveToken],
        orders: &[&'a TrackedOrder],
    ) -> Element<'a, Message> {
        let composer_inner = column![
            self.composer.view_body(t, portfolio).map(Message::Composer),
            Space::new().height(14),
            self.composer.view_actions(t).map(Message::Composer),
        ]
        .width(Length::Fill);
        let composer_card = container(composer_inner)
            .padding(Padding::from([16, 18]))
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(t.card)),
                border: Border {
                    color: t.border,
                    width: 1.0,
                    radius: Radius::from(16),
                },
                text_color: Some(t.text),
                ..container::Style::default()
            });

        // Orders header: label + a fetch button. The button is always present —
        // "Fetch" pulls the address's full CoW order history, so it must be
        // reachable even from a fresh session with no orders listed yet.
        let orders_header = row![
            text("YOUR ORDERS").size(11).color(t.sub).font(mono_bold()),
            Space::new().width(Length::Fill),
            fetch_button(t),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill);

        let mut content = column![
            ghost_button(t, text("← Apps").size(13).color(t.sub).font(bold()))
                .on_press(Message::BackHome),
            Space::new().height(10),
            screen_title(t, "Swap"),
            Space::new().height(6),
            screen_subtitle(
                t,
                "Trade via CoW Protocol — MEV-protected; ERC-20 orders are gasless"
            ),
            Space::new().height(18),
            composer_card,
            Space::new().height(22),
            orders_header,
            Space::new().height(8),
        ]
        .width(Length::Fill)
        .max_width(560);

        if orders.is_empty() {
            content = content.push(
                text("No orders yet — place a swap above, or tap Fetch to load your history.")
                    .size(12)
                    .color(t.sub),
            );
        } else {
            let mut list = column![].spacing(8).width(Length::Fill);
            for o in orders {
                list = list.push(order_row(t, o));
            }
            content = content.push(list);
        }

        content.into()
    }
}

/// Small on-demand "Fetch" button that re-polls tracked-order status.
fn fetch_button<'a>(t: KaoTheme) -> Element<'a, Message> {
    button(text("↻ Fetch").size(11).color(t.a1).font(bold()))
        .padding(Padding::from([4, 10]))
        .on_press(Message::RefreshOrders)
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
        })
        .into()
}

/// Small "↗ Explorer" button on an order row that copies its CoW Explorer
/// link. Shares `fetch_button`'s accent-pill styling for a consistent row.
fn explorer_button<'a>(t: KaoTheme, url: String) -> Element<'a, Message> {
    button(text("↗ Explorer").size(11).color(t.a1).font(bold()))
        .padding(Padding::from([4, 10]))
        .on_press(Message::CopyExplorerLink(url))
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
        })
        .into()
}

/// A launcher card for one app: kaomoji chip, title, sub-label, and a chevron.
/// The whole card is the click target.
fn app_card<'a>(
    t: KaoTheme,
    kao: &'a str,
    title: &'a str,
    sub: &str,
    msg: Message,
) -> Element<'a, Message> {
    let info = column![
        text(title.to_string()).size(15).color(t.text).font(bold()),
        text(sub.to_string()).size(12).color(t.sub),
    ]
    .spacing(2);

    let inner = row![
        avatar(t, kao, 40.0, t.ab3),
        Space::new().width(12),
        container(info).width(Length::Fill),
        text("→").size(18).color(t.a3).font(bold()),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    button(inner)
        .padding(Padding::from([14, 16]))
        .width(Length::Fill)
        .on_press(msg)
        .style(move |_, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => with_alpha(t.a3, 0.10),
                _ => t.card,
            })),
            text_color: t.text,
            border: Border {
                color: with_alpha(t.a3, 0.25),
                width: 1.5,
                radius: Radius::from(16),
            },
            ..button::Style::default()
        })
        .into()
}

fn order_row<'a>(t: KaoTheme, o: &'a TrackedOrder) -> Element<'a, Message> {
    let (sell_s, _) = format_token_balance(o.sell_amount, o.sell_decimals);
    let (buy_s, _) = format_token_balance(o.buy_amount, o.buy_decimals);

    let title = text(format!(
        "{sell_s} {} → {} {}",
        o.sell_symbol, buy_s, o.buy_symbol
    ))
    .size(13)
    .color(t.text)
    .font(bold());

    let sub_text = match (o.status, o.executed) {
        (OrderStatus::Fulfilled, Some((_, got))) => {
            let (got_s, _) = format_token_balance(got, o.buy_decimals);
            format!("received {got_s} {}", o.buy_symbol)
        }
        _ => format!(
            "min {buy_s} {} · {}",
            o.buy_symbol,
            if o.is_ethflow {
                "ETH order"
            } else {
                "limit-protected"
            }
        ),
    };

    let info = column![
        title,
        Space::new().height(2),
        text(sub_text).size(11).color(t.sub).font(mono()),
    ]
    .spacing(0)
    .width(Length::Fill);

    let mut right = row![status_badge(t, o.status)].align_y(Alignment::Center);

    // CoW Explorer link for the placed order (copies to clipboard). `None`
    // only on chains without a CoW deployment, where no order can exist.
    if let Some(url) = crate::cow::explorer_order_url(o.chain, &o.uid) {
        right = right.push(Space::new().width(8));
        right = right.push(explorer_button(t, url));
    }

    // Off-chain cancel is only wired for ERC-20 orders; EthFlow orders cancel
    // on-chain (deferred) and so show no cancel affordance in v1.
    if !o.status.is_terminal() && !o.is_ethflow {
        right = right.push(Space::new().width(8));
        right = right.push(
            button(text("Cancel").size(11).color(t.down).font(bold()))
                .padding(Padding::from([4, 10]))
                .on_press(Message::Cancel(o.uid.clone()))
                .style(move |_, status| button::Style {
                    background: Some(Background::Color(match status {
                        button::Status::Hovered | button::Status::Pressed => {
                            with_alpha(t.down, 0.10)
                        }
                        _ => t.card_alt,
                    })),
                    text_color: t.down,
                    border: Border {
                        color: with_alpha(t.down, 0.3),
                        width: 1.0,
                        radius: Radius::from(8),
                    },
                    ..button::Style::default()
                }),
        );
    }

    container(
        row![info, right]
            .align_y(Alignment::Center)
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

fn status_badge<'a>(t: KaoTheme, status: OrderStatus) -> Element<'a, Message> {
    let (fg, bg) = match status {
        OrderStatus::Fulfilled => (t.up, with_alpha(t.up, 0.12)),
        OrderStatus::Cancelled | OrderStatus::Expired => (t.down, with_alpha(t.down, 0.12)),
        OrderStatus::Open | OrderStatus::PresignaturePending => (t.sub, with_alpha(t.sub, 0.12)),
    };
    container(text(status.label()).size(10).color(fg).font(mono_bold()))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn esc_event() -> keyboard::Event {
        keyboard::Event::KeyPressed {
            key: keyboard::Key::Named(keyboard::key::Named::Escape),
            modified_key: keyboard::Key::Named(keyboard::key::Named::Escape),
            physical_key: keyboard::key::Physical::Code(keyboard::key::Code::Escape),
            location: keyboard::Location::Standard,
            modifiers: keyboard::Modifiers::default(),
            text: None,
            repeat: false,
        }
    }

    #[test]
    fn esc_steps_back_from_swap_app_to_launcher() {
        let mut pane = AppsPane::new(Address::ZERO);
        assert_eq!(pane.view, AppsView::Launcher);
        pane.update(Message::OpenSwapApp);
        assert_eq!(pane.view, AppsView::Swap);
        // Esc inside the Swap app returns to the launcher — same as "← Apps".
        let out = pane.update(Message::Key(esc_event()));
        assert!(
            out.is_none(),
            "stepping back is internal, no outcome bubbles up"
        );
        assert_eq!(pane.view, AppsView::Launcher);
    }

    #[test]
    fn esc_on_launcher_is_a_noop() {
        let mut pane = AppsPane::new(Address::ZERO);
        pane.update(Message::Key(esc_event()));
        assert_eq!(
            pane.view,
            AppsView::Launcher,
            "launcher has nothing to step back to",
        );
    }
}
