//! Receive modal — QR code + copy-to-clipboard.

use std::time::Duration;

use alloy::primitives::Address;
use iced::border::Radius;
use iced::keyboard;
use iced::widget::{Space, button, column, container, qr_code, text};
use iced::{Alignment, Background, Border, Color, Element, Length, Padding, Subscription, Task};

use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{black, hover_fill, kao_fit, modal_wrapper, mono};

#[derive(Debug, Clone)]
pub enum Message {
    Copy,
    CopyReset,
    Close,
    BoxClickIgnored,
    Key(keyboard::Event),
}

#[derive(Debug, Clone)]
pub enum Outcome {
    Closed,
}

#[derive(Debug)]
pub struct ReceivePane {
    address: Address,
    qr: qr_code::Data,
    copied: bool,
}

impl ReceivePane {
    pub fn new(address: Address) -> Self {
        let qr = qr_code::Data::new(format!("{:#x}", address))
            .expect("an Ethereum address always fits in a QR code");
        Self {
            address,
            qr,
            copied: false,
        }
    }

    pub fn update(&mut self, msg: Message) -> (Task<Message>, Option<Outcome>) {
        match msg {
            Message::Copy => {
                self.copied = true;
                let addr = format!("{:#x}", self.address);
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
        let addr = format!("{:#x}", self.address);

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
        let qr = qr_code(&self.qr)
            .total_size(180.0)
            .style(move |_| qr_code::Style {
                cell: dark_cell,
                background: light_cell,
            });
        let qr_box = container(qr)
            .width(Length::Fill)
            .align_x(iced::alignment::Horizontal::Center);

        let addr_box = container(
            text(addr)
                .size(13)
                .color(t.sub)
                .font(mono())
                .wrapping(text::Wrapping::WordOrGlyph),
        )
        .padding(Padding::from([10, 14]))
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
            360.0,
            progress,
            Message::Close,
            Message::BoxClickIgnored,
            content.into(),
        )
    }
}
