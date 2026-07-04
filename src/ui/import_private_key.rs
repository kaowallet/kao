use std::fmt;

use alloy::primitives::B256;
use iced::keyboard;
use iced::widget::{Space, column, container, row, text, text_input};
use iced::{Alignment, Element, Length, Padding, Subscription, Task};
use zeroize::Zeroizing;

use crate::settings;
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    auth_background, auth_card, error_text, hint_pill, kao_hero, link_button, mono, primary_button,
    screen_subtitle, screen_title, text_input_style, vspace,
};
use crate::wallet;

pub const KEY_INPUT_ID: &str = "private_key_input";

#[derive(Clone)]
pub enum Message {
    // The key is secret text the user typed — `SecretInput` redacts it
    // from the derived-Debug trace stream.
    KeyInput(crate::trace::SecretInput),
    ImportPressed,
    BackPressed,
    KeyboardEvent(keyboard::Event),
}

// Manual Debug: the keyboard subscription receives every key event the
// focused key input ignores (all `KeyReleased`s in particular), so a
// derived impl would leak typed key characters into the trace stream —
// character keys are redacted, named keys (Enter, Escape, …) stay legible.
impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::KeyInput(s) => f.debug_tuple("KeyInput").field(s).finish(),
            Message::ImportPressed => f.write_str("ImportPressed"),
            Message::BackPressed => f.write_str("BackPressed"),
            Message::KeyboardEvent(e) => {
                f.write_str("KeyboardEvent(")?;
                match e {
                    keyboard::Event::KeyPressed {
                        key: keyboard::Key::Named(n),
                        ..
                    } => write!(f, "KeyPressed({n:?})")?,
                    keyboard::Event::KeyPressed { .. } => f.write_str("KeyPressed(<redacted>)")?,
                    keyboard::Event::KeyReleased {
                        key: keyboard::Key::Named(n),
                        ..
                    } => write!(f, "KeyReleased({n:?})")?,
                    keyboard::Event::KeyReleased { .. } => {
                        f.write_str("KeyReleased(<redacted>)")?
                    }
                    keyboard::Event::ModifiersChanged(m) => write!(f, "ModifiersChanged({m:?})")?,
                }
                f.write_str(")")
            }
        }
    }
}

/// Outcome signals emitted by this screen to its parent.
#[derive(Debug, Clone)]
pub enum Outcome {
    Imported { key_bytes: Zeroizing<[u8; 32]> },
    Back,
}

impl Outcome {
    /// Variant name for the GUI state trace — never the payload, which
    /// carries the raw key bytes.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Imported { .. } => "Imported",
            Outcome::Back => "Back",
        }
    }
}

#[derive(Debug, Default)]
pub struct ImportPrivateKeyScreen {
    /// Live `text_input` buffer. `Zeroizing<String>` zeros the heap allocation
    /// each time the input is replaced and on screen drop.
    key_input: Zeroizing<String>,
    error: Option<String>,
}

impl ImportPrivateKeyScreen {
    pub fn update(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("import_key", &message);
        let (task, outcome) = self.update_inner(message);
        if let Some(o) = &outcome {
            crate::trace::outcome("import_key", o.name());
        }
        (task, outcome)
    }

    fn update_inner(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        match message {
            Message::KeyInput(s) => {
                self.key_input = s.take();
                (Task::none(), None)
            }
            Message::ImportPressed => (Task::none(), self.try_import()),
            Message::BackPressed => (Task::none(), Some(Outcome::Back)),
            Message::KeyboardEvent(keyboard::Event::KeyPressed { key, .. }) => match key {
                keyboard::Key::Named(keyboard::key::Named::Escape) => {
                    (Task::none(), Some(Outcome::Back))
                }
                _ => (Task::none(), None),
            },
            Message::KeyboardEvent(_) => (Task::none(), None),
        }
    }

    fn try_import(&mut self) -> Option<Outcome> {
        let trimmed = self.key_input.trim();
        if trimmed.is_empty() {
            self.error = Some("Please enter a private key.".into());
            return None;
        }
        let bytes: B256 = match trimmed.parse() {
            Ok(b) => b,
            Err(_) => {
                self.error = Some(
                    "Invalid private key — expected 32 bytes as 64 hex characters (0x prefix optional).".into(),
                );
                return None;
            }
        };
        match wallet::signer_from_bytes(&bytes) {
            Ok(_signer) => {
                self.error = None;
                Some(Outcome::Imported {
                    key_bytes: Zeroizing::new(bytes.into()),
                })
            }
            Err(e) => {
                self.error = Some(format!("Invalid key: {e}"));
                None
            }
        }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        keyboard::listen().map(Message::KeyboardEvent)
    }

    pub fn view(&self) -> Element<'_, Message> {
        let t = KaoTheme::for_kind(settings::theme());

        let key_input = text_input("0x…", self.key_input.as_str())
            .id(KEY_INPUT_ID)
            .on_input(|s| Message::KeyInput(s.into()))
            .on_submit(Message::ImportPressed)
            .padding(Padding::from([12, 14]))
            .size(14)
            .font(mono())
            .style(move |_theme, status| text_input_style(t, status));

        let import_btn =
            primary_button(t, "Import Wallet →", true).on_press(Message::ImportPressed);

        let hint = container(
            row![
                hint_pill(t, "Enter"),
                Space::new().width(6),
                text("to import · ").size(11).color(t.sub),
                hint_pill(t, "Esc"),
                Space::new().width(6),
                text("to go back").size(11).color(t.sub),
            ]
            .align_y(Alignment::Center),
        )
        .width(Length::Fill)
        .center_x(Length::Fill);

        let mut content = column![
            kao_hero(t, "(⌐■_■)", 56.0),
            vspace(10),
            screen_title(t, "Import from Private Key"),
            vspace(6),
            screen_subtitle(t, "Paste your 32-byte private key as a hex string."),
            vspace(22),
            key_input,
            vspace(18),
            import_btn,
            vspace(14),
            hint,
        ]
        .width(Length::Fill)
        .align_x(Alignment::Center);

        if let Some(e) = &self.error {
            content = content.push(vspace(10)).push(error_text(t, e));
        }

        let card = auth_card(t, 520.0, content.into());

        let back_bar = container(link_button(t, "← Back").on_press(Message::BackPressed))
            .padding(Padding::from([12, 14]))
            .width(Length::Fill);

        let layout = column![back_bar, card]
            .width(Length::Fill)
            .height(Length::Fill);

        auth_background(t, layout.into())
    }
}

#[cfg(test)]
#[allow(unused_must_use)]
mod tests {
    use super::*;
    use alloy::primitives::Address;

    /// Hardhat default account #0 private key. The corresponding address is
    /// also a known constant so importing it has a predictable outcome.
    const HARDHAT_PK_0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const HARDHAT_ADDR_0: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    #[test]
    fn empty_input_errors() {
        let mut s = ImportPrivateKeyScreen::default();
        let (_, outcome) = s.update(Message::ImportPressed);
        assert!(outcome.is_none());
        assert!(s.error.is_some());
    }

    #[test]
    fn malformed_hex_errors() {
        let mut s = ImportPrivateKeyScreen::default();
        s.update(Message::KeyInput("not_a_hex_string".into()));
        let (_, outcome) = s.update(Message::ImportPressed);
        assert!(outcome.is_none());
        assert!(s.error.unwrap().contains("Invalid private key"));
    }

    #[test]
    fn accepts_hex_with_0x_prefix_and_yields_expected_address() {
        let mut s = ImportPrivateKeyScreen::default();
        s.update(Message::KeyInput(HARDHAT_PK_0.into()));
        let (_, outcome) = s.update(Message::ImportPressed);
        match outcome {
            Some(Outcome::Imported { key_bytes }) => {
                let b256 = B256::from(*key_bytes);
                let signer = wallet::signer_from_bytes(&b256).unwrap();
                let expected: Address = HARDHAT_ADDR_0.parse().unwrap();
                assert_eq!(signer.address(), expected);
            }
            other => panic!("expected Imported, got {other:?}"),
        }
        assert!(s.error.is_none());
    }

    #[test]
    fn accepts_hex_without_0x_prefix() {
        let mut s = ImportPrivateKeyScreen::default();
        s.update(Message::KeyInput(
            HARDHAT_PK_0.trim_start_matches("0x").into(),
        ));
        let (_, outcome) = s.update(Message::ImportPressed);
        assert!(matches!(outcome, Some(Outcome::Imported { .. })));
    }

    #[test]
    fn back_pressed_emits_back() {
        let mut s = ImportPrivateKeyScreen::default();
        let (_, outcome) = s.update(Message::BackPressed);
        assert!(matches!(outcome, Some(Outcome::Back)));
    }
}
