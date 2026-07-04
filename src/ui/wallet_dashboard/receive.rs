//! Receive modal — QR code + copy-to-clipboard.

use std::time::Duration;

use alloy::primitives::Address;
use iced::border::Radius;
use iced::keyboard;
use iced::widget::{Space, button, column, container, qr_code, text};
use iced::{Alignment, Background, Border, Color, Element, Length, Padding, Subscription, Task};

use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{black, colored_address, hover_fill, kao_fit, modal_wrapper};

#[derive(Debug, Clone)]
pub enum Message {
    Copy,
    CopyReset,
    /// No-op kick published by the click-to-copy address so the update loop
    /// runs after a copy (see [`crate::ui::kao_widgets::CopyKick`]).
    AddressCopied,
    Close,
    BoxClickIgnored,
    Key(keyboard::Event),
}

#[derive(Debug, Clone)]
pub enum Outcome {
    Closed,
}

impl Outcome {
    /// Variant name for the GUI state trace.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Closed => "Closed",
        }
    }
}

#[derive(Debug)]
pub struct ReceivePane {
    address: Address,
    qr: Option<qr_code::Data>,
    copied: bool,
}

impl ReceivePane {
    pub fn new(address: Address) -> Self {
        // An Ethereum address always fits in a QR code, so this realistically
        // never fails — but fall back to `None` (the view shows a placeholder)
        // rather than panicking the whole GUI if encoding ever errors.
        let qr = qr_code::Data::new(format!("{:#x}", address)).ok();
        Self {
            address,
            qr,
            copied: false,
        }
    }

    pub fn update(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("receive", &msg);
        let copied_before = self.copied;
        let (task, outcome) = self.update_inner(msg);
        if copied_before != self.copied {
            crate::trace::state("receive", "copied", copied_before, self.copied);
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("receive", o.name());
        }
        (task, outcome)
    }

    fn update_inner(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        match msg {
            Message::Copy => {
                self.copied = true;
                // EIP-55 checksum form — the same string the click-to-copy
                // address renders and copies, so both affordances agree.
                let addr = self.address.to_checksum(None);
                let task = Task::batch([
                    iced::clipboard::write(addr).map(|_: ()| Message::CopyReset),
                    Task::perform(
                        async {
                            tokio::time::sleep(Duration::from_millis(2200)).await;
                        },
                        |_| Message::CopyReset,
                    ),
                ]);
                (task, None)
            }
            Message::CopyReset => {
                self.copied = false;
                (Task::none(), None)
            }
            // The click-to-copy address wrote the clipboard itself; this kick
            // just wakes the update loop and needs no state change.
            Message::AddressCopied => (Task::none(), None),
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

    pub fn view<'a>(&'a self, t: KaoTheme, progress: f32) -> Element<'a, Message> {
        let header_kao = container(kao_fit(t, "(っ◕‿◕)っ", 260.0, 52.0))
            .width(Length::Fill)
            .center_x(Length::Fill);

        let title = container(text("Receive").size(21).color(t.text).font(black()))
            .width(Length::Fill)
            .center_x(Length::Fill);
        let sub = container(text("Share your address").size(13).color(t.sub))
            .width(Length::Fill)
            .center_x(Length::Fill);

        let dark_cell = if t.dark {
            t.text
        } else {
            Color::from_rgb8(30, 30, 30)
        };
        let light_cell = if t.dark { t.card_alt } else { Color::WHITE };
        let qr_box: Element<'_, Message> = if let Some(qr_data) = &self.qr {
            let qr = qr_code(qr_data)
                .total_size(300.0)
                .style(move |_| qr_code::Style {
                    cell: dark_cell,
                    background: light_cell,
                });
            container(qr)
                .width(Length::Fill)
                .align_x(iced::alignment::Horizontal::Center)
                .into()
        } else {
            container(text("QR code unavailable").size(13).color(t.sub))
                .width(Length::Fill)
                .align_x(iced::alignment::Horizontal::Center)
                .into()
        };

        // Colored, click-to-copy address (same widget the review screens use):
        // each 4-hex chunk gets a palette colour, hovering greys it, and a click
        // copies the EIP-55 checksum form to the clipboard.
        let addr_box = container(colored_address(t, self.address))
            .padding(Padding::from([12, 14]))
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(t.card_alt)),
                border: Border {
                    color: t.border,
                    width: 1.0,
                    radius: Radius::from(11),
                },
                text_color: Some(t.sub),
                ..container::Style::default()
            });

        let btn_label = if self.copied {
            "Copied! ٩(◕‿◕｡)۶"
        } else {
            "Copy Address (ﾉ◕ヮ◕)ﾉ"
        };
        let btn_bg = if self.copied { t.up } else { t.a2 };
        let copy_btn = button(
            container(text(btn_label).size(15).color(Color::WHITE).font(black()))
                .width(Length::Fill)
                .center_x(Length::Fill)
                .padding(Padding::from([13, 0])),
        )
        .width(Length::Fill)
        .style(move |_theme, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => {
                    hover_fill(btn_bg, Color::WHITE)
                }
                _ => btn_bg,
            })),
            text_color: Color::WHITE,
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(13),
            },
            ..button::Style::default()
        })
        .on_press(Message::Copy);

        let content = column![
            header_kao,
            Space::new().height(8),
            title,
            Space::new().height(4),
            sub,
            Space::new().height(22),
            qr_box,
            Space::new().height(20),
            addr_box,
            Space::new().height(14),
            copy_btn,
        ]
        .width(Length::Fill)
        .align_x(Alignment::Center);

        modal_wrapper(
            t,
            480.0,
            progress,
            Message::Close,
            Message::BoxClickIgnored,
            content.into(),
        )
    }
}
