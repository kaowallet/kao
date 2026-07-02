//! Account picker overlay anchored under the sidebar account card. Lists all
//! accounts in the unlocked wallet and an "Add new address" action.
//!
//! TEA component: owns no internal state today (it's a pure view of the
//! coordinator's accounts + active_index), but wrapping it in the standard
//! shape keeps the coordinator's `Message` enum decoupled from the dropdown's
//! internal events and gives the dropdown its own keyboard subscription.

use iced::border::Radius;
use iced::keyboard;
use iced::widget::{Space, button, column, container, mouse_area, row, scrollable, stack, text};
use iced::{Alignment, Background, Border, Color, Element, Length, Padding, Subscription, Task};

use crate::chain::Chain;
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::{
    avatar, black, bold, ghost_button, hover_tint, kao_scrollable_style, kaomoji_for_account, mono,
    thin_divider,
};
use crate::wallet::{
    AccountDescriptor, SafeDescriptor, account_is_safe_signer, account_short_address, short_address,
};

#[derive(Debug, Clone)]
pub enum Message {
    Select(usize),
    SelectSafe(usize),
    Add,
    Close,
    BoxClickIgnored,
    Key(keyboard::Event),
}

#[derive(Debug, Clone)]
pub enum Outcome {
    Switch(usize),
    SelectSafe(usize),
    Add,
    Closed,
}

impl Outcome {
    /// Variant name for the GUI state trace.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Switch(_) => "Switch",
            Outcome::SelectSafe(_) => "SelectSafe",
            Outcome::Add => "Add",
            Outcome::Closed => "Closed",
        }
    }
}

#[derive(Debug, Default)]
pub struct AccountDropdown;

impl AccountDropdown {
    pub fn new() -> Self {
        Self
    }

    pub fn update(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("account_dropdown", &msg);
        // Stateless overlay — no coarse state to diff; log outcomes only.
        let (task, outcome) = self.update_inner(msg);
        if let Some(o) = &outcome {
            crate::trace::outcome("account_dropdown", o.name());
        }
        (task, outcome)
    }

    fn update_inner(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        match msg {
            Message::Select(idx) => (Task::none(), Some(Outcome::Switch(idx))),
            Message::SelectSafe(idx) => (Task::none(), Some(Outcome::SelectSafe(idx))),
            Message::Add => (Task::none(), Some(Outcome::Add)),
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
        }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        keyboard::listen().map(Message::Key)
    }

    pub fn view<'a>(
        &self,
        t: KaoTheme,
        accounts: &'a [AccountDescriptor],
        safes: &'a [SafeDescriptor],
        active_index: usize,
        active_safe: Option<usize>,
    ) -> Element<'a, Message> {
        // Backdrop: full-window mouse_area to catch outside clicks.
        let backdrop = mouse_area(
            container(Space::new().width(Length::Fill).height(Length::Fill))
                .width(Length::Fill)
                .height(Length::Fill),
        )
        .on_press(Message::Close);

        // Build the panel: one row per account, then any Safes inline
        // (matching the user's flow language "The Safe then appears in
        // the account list"), then "Add new address". Safes carry no
        // signing handle yet in 3b, so they render as non-clickable
        // info rows — the affordance comes back when the Safe-TX flow
        // lands in a future stage.
        let mut list = column![].spacing(2).width(Length::Fill);
        // When a Safe is the active context, suppress the EOA active
        // marker — otherwise both the active Safe and the underlying
        // executor EOA would show ◉ at the same time.
        let eoa_active_index = if active_safe.is_some() {
            usize::MAX
        } else {
            active_index
        };
        for (idx, account) in accounts.iter().enumerate() {
            let is_signer = account_is_safe_signer(idx as u32, safes);
            list = list.push(account_row(t, idx, account, eoa_active_index, is_signer));
        }
        for (idx, safe) in safes.iter().enumerate() {
            list = list.push(safe_row(t, idx, safe, active_safe == Some(idx)));
        }
        list = list.push(thin_divider(t));
        list = list.push(add_account_row(t));

        let panel = container(
            scrollable(list)
                .height(Length::Shrink)
                .style(move |_, s| kao_scrollable_style(t, s)),
        )
        .padding(Padding::from([10, 8]))
        .width(Length::Fixed(296.0))
        .max_height(360.0)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(14),
            },
            text_color: Some(t.text),
            shadow: iced::Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, if t.dark { 0.6 } else { 0.16 }),
                offset: iced::Vector::new(0.0, 12.0),
                blur_radius: 32.0,
            },
            ..container::Style::default()
        });

        // Anchor the panel just under the sidebar account card (the trigger).
        // The sidebar is 256 wide with 16px padding; an 18px-tall brand row
        // and an ~56px-tall card sit above, so the card's bottom lands ~128
        // from the window top. Left-align the panel with the card at ~16 from
        // the window left; the 296-wide panel overhangs into the content pane.
        let layer = container(column![
            Space::new().height(128.0),
            row![
                Space::new().width(16.0),
                mouse_area(panel).on_press(Message::BoxClickIgnored),
                Space::new().width(Length::Fill),
            ],
            Space::new().height(Length::Fill),
        ])
        .width(Length::Fill)
        .height(Length::Fill);

        stack![backdrop, layer].into()
    }
}

fn account_row<'a>(
    t: KaoTheme,
    idx: usize,
    account: &'a AccountDescriptor,
    active_index: usize,
    is_safe_signer: bool,
) -> Element<'a, Message> {
    let active = idx == active_index;
    let kao = kaomoji_for_account(idx);
    let label = account.display_name(idx);
    let addr_text = account_short_address(account);
    let kind = match account {
        AccountDescriptor::Local { .. } => "Local",
        AccountDescriptor::Ledger { .. } => "Ledger",
        AccountDescriptor::Trezor { .. } => "Trezor",
        AccountDescriptor::ViewOnly { .. } => "View Only",
    };

    let mut kind_row = row![
        text(label).size(13).color(t.text).font(bold()),
        Space::new().width(8),
        text(kind).size(10).color(t.sub).font(mono()),
    ]
    .align_y(Alignment::Center);
    if is_safe_signer {
        // Tiny accent-tinted chip telling the user this account is
        // load-bearing for at least one Safe in the wallet.
        kind_row = kind_row
            .push(Space::new().width(6))
            .push(text("Safe signer").size(10).color(t.a1).font(mono()));
    }
    let info = column![kind_row, text(addr_text).size(11).color(t.sub).font(mono())].spacing(1);

    let check = if active {
        text("◉").size(14).color(t.a1)
    } else {
        text("○").size(14).color(t.sub)
    };

    let inner = row![
        avatar(t, kao, 32.0, t.ab1),
        Space::new().width(10),
        container(info).width(Length::Fill),
        check,
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    let bg = if active { t.ab1 } else { Color::TRANSPARENT };
    button(inner)
        .padding(Padding::from([6, 8]))
        .width(Length::Fill)
        .on_press(Message::Select(idx))
        .style(move |_theme, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => hover_tint(bg, t.text),
                _ => bg,
            })),
            text_color: t.text,
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(10),
            },
            ..button::Style::default()
        })
        .into()
}

/// Render one Safe row.
///
/// Signing Safes (`linked_signer_indices` non-empty) are clickable
/// and emit `Message::SelectSafe(idx)` — the dashboard then opens
/// the Safe-send modal. Watch-only Safes (no linked owners in this
/// wallet) stay non-clickable: there's no signing path, so the click
/// would be a false affordance.
///
/// Layout mirrors `account_row`: avatar + info column + active
/// indicator on the right (◉ when this Safe is the active context,
/// ○ otherwise). Background is transparent until hover/active, so
/// the row sits flush with the surrounding accounts instead of
/// reading as a permanently-highlighted strip.
fn safe_row<'a>(
    t: KaoTheme,
    idx: usize,
    safe: &'a SafeDescriptor,
    active: bool,
) -> Element<'a, Message> {
    let watch_only = safe.linked_signer_indices.is_empty();
    let label = safe.display_name(idx);
    let chain_label = chain_label_for_id(safe.chain_id);
    let badge_text = if watch_only { "Safe (watch)" } else { "Safe" };
    // Watch-only Safes mute the text colors but keep the same row
    // structure. The strong bg tint used to be a substitute for the
    // missing active marker — now that the row carries ◉/○, that
    // visual crutch is gone and watch-only just reads as "muted".
    let (text_color, sub_color) = if watch_only {
        (t.sub, with_alpha(t.sub, 0.7))
    } else {
        (t.text, t.sub)
    };

    let kind_row = row![
        text(label).size(13).color(text_color).font(bold()),
        Space::new().width(8),
        text(badge_text).size(10).color(t.a2).font(mono()),
        Space::new().width(6),
        text(chain_label).size(10).color(sub_color).font(mono()),
    ]
    .align_y(Alignment::Center);
    let info = column![
        kind_row,
        text(short_address(safe.address()))
            .size(11)
            .color(sub_color)
            .font(mono()),
    ]
    .spacing(1);

    // (◐‿◐) for signing Safes (two-eyes hint at multi-sig); (◐_◐) for
    // watch-only (same shape but a flat mouth — no "joy of signing").
    let kao = if watch_only {
        "(◐_◐)"
    } else {
        "(◐‿◐)"
    };
    // Active indicator: ◉ when this Safe is the open context, ○
    // otherwise (only when signable — watch-only Safes can't be the
    // active context, so the slot stays empty for them).
    let trailing: Element<'_, Message> = if watch_only {
        Space::new().width(0).into()
    } else if active {
        text("◉").size(14).color(t.a1).into()
    } else {
        text("○").size(14).color(t.sub).into()
    };
    let inner = row![
        avatar(t, kao, 32.0, t.ab1),
        Space::new().width(10),
        container(info).width(Length::Fill),
        trailing,
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    if watch_only {
        // Non-clickable but the row body still rounds + tints on
        // hover-less; muted bg keeps observe-only Safes visually
        // distinct without the wider chip treatment.
        container(inner)
            .padding(Padding::from([6, 8]))
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(with_alpha(t.ab2, 0.3))),
                border: Border {
                    color: Color::TRANSPARENT,
                    width: 0.0,
                    radius: Radius::from(10),
                },
                text_color: Some(text_color),
                ..container::Style::default()
            })
            .into()
    } else {
        let bg = if active { t.ab1 } else { Color::TRANSPARENT };
        button(inner)
            .padding(Padding::from([6, 8]))
            .width(Length::Fill)
            .on_press(Message::SelectSafe(idx))
            .style(move |_theme, status| button::Style {
                background: Some(Background::Color(match status {
                    button::Status::Hovered | button::Status::Pressed => hover_tint(bg, t.text),
                    _ => bg,
                })),
                text_color,
                border: Border {
                    color: Color::TRANSPARENT,
                    width: 0.0,
                    radius: Radius::from(10),
                },
                ..button::Style::default()
            })
            .into()
    }
}

fn chain_label_for_id(chain_id: u64) -> &'static str {
    // Map back to Chain so we render the display label the rest of the
    // app uses ("Ethereum Mainnet" / "OP Mainnet" / "Base"). An
    // unknown chain_id (e.g. a future addition saved by a newer Kao)
    // renders as "?" — the row is still readable and the staleness is
    // visible.
    Chain::ALL
        .iter()
        .find(|c| c.chain_id() == chain_id)
        .map(|c| c.display_name())
        .unwrap_or("?")
}

fn add_account_row<'a>(t: KaoTheme) -> Element<'a, Message> {
    let inner = row![
        text("＋").size(15).color(t.a1).font(black()),
        Space::new().width(10),
        text("Add new address").size(13).color(t.text).font(bold()),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    ghost_button(t, inner)
        .padding(Padding::from([8, 8]))
        .width(Length::Fill)
        .on_press(Message::Add)
        .into()
}
