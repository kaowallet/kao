use std::fmt;

use iced::keyboard;
use iced::widget::{Space, column, container, row, text, text_input};
use iced::{Alignment, Element, Length, Padding, Subscription, Task};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::settings;
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    auth_background, auth_card, error_text, hint_pill, kao_hero, link_button, mono, primary_button,
    screen_subtitle, screen_title, text_input_style, vspace,
};
use crate::wallet;

pub const PHRASE_INPUT_ID: &str = "seed_phrase_input";

#[derive(Clone)]
pub enum Message {
    // The phrase is secret text the user typed — `SecretInput` redacts it
    // from the derived-Debug trace stream.
    PhraseInput(crate::trace::SecretInput),
    ConfirmPressed,
    BackPressed,
    KeyboardEvent(keyboard::Event),
}

// Manual Debug: the keyboard subscription receives every key event the
// focused phrase input ignores (all `KeyReleased`s in particular), so a
// derived impl would leak typed phrase characters into the trace stream —
// character keys are redacted, named keys (Enter, Escape, …) stay legible.
impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::PhraseInput(s) => f.debug_tuple("PhraseInput").field(s).finish(),
            Message::ConfirmPressed => f.write_str("ConfirmPressed"),
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
    Confirmed { phrase: SecretString },
    Back,
}

impl Outcome {
    /// Variant name for the GUI state trace — never the payload, which
    /// carries the seed phrase.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Confirmed { .. } => "Confirmed",
            Outcome::Back => "Back",
        }
    }
}

#[derive(Debug, Default)]
pub struct ImportSeedPhraseScreen {
    /// Live `text_input` buffer. `Zeroizing<String>` zeros the heap allocation
    /// each time the input is replaced (every keystroke) and on screen drop.
    phrase_input: Zeroizing<String>,
    error: Option<String>,
}

impl ImportSeedPhraseScreen {
    /// Pre-fill the phrase input (used when navigating back from SelectHdAccount).
    pub fn with_phrase(phrase: SecretString) -> Self {
        Self {
            phrase_input: Zeroizing::new(phrase.expose_secret().to_string()),
            error: None,
        }
    }

    pub fn update(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("import_seed", &message);
        let (task, outcome) = self.update_inner(message);
        if let Some(o) = &outcome {
            crate::trace::outcome("import_seed", o.name());
        }
        (task, outcome)
    }

    fn update_inner(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        match message {
            Message::PhraseInput(s) => {
                self.phrase_input = s.take();
                (Task::none(), None)
            }
            Message::ConfirmPressed => (Task::none(), self.try_confirm()),
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

    fn try_confirm(&mut self) -> Option<Outcome> {
        let normalized: Zeroizing<String> = Zeroizing::new(
            self.phrase_input
                .split_whitespace()
                .map(|w| w.to_lowercase())
                .collect::<Vec<_>>()
                .join(" "),
        );

        if normalized.is_empty() {
            self.error = Some("Please enter your seed phrase.".into());
            return None;
        }

        let word_count = normalized.split_whitespace().count();
        if word_count != 12 && word_count != 24 {
            self.error = Some(format!(
                "A seed phrase must be 12 or 24 words, but you entered {word_count}."
            ));
            return None;
        }

        match wallet::validate_mnemonic(&normalized) {
            Ok(()) => {
                self.error = None;
                // Reallocate into a `Box<str>` and wrap in `SecretString`.
                // The intermediate allocation is brief; `normalized` zeros on
                // scope exit and `SecretString` takes over from there.
                let phrase = SecretString::new(Box::from(normalized.as_str()));
                Some(Outcome::Confirmed { phrase })
            }
            Err(e) => {
                self.error = Some(format!("Invalid seed phrase: {e}"));
                None
            }
        }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        keyboard::listen().map(Message::KeyboardEvent)
    }

    pub fn view(&self) -> Element<'_, Message> {
        let t = KaoTheme::for_kind(settings::theme());

        let phrase_input = text_input("word1 word2 word3 …", self.phrase_input.as_str())
            .id(PHRASE_INPUT_ID)
            .on_input(|s| Message::PhraseInput(s.into()))
            .on_submit(Message::ConfirmPressed)
            .padding(Padding::from([12, 14]))
            .size(14)
            .font(mono())
            .style(move |_theme, status| text_input_style(t, status));

        let confirm_btn = primary_button(t, "Continue →", true).on_press(Message::ConfirmPressed);

        let hint = container(
            row![
                hint_pill(t, "Enter"),
                Space::new().width(6),
                text("to continue · ").size(11).color(t.sub),
                hint_pill(t, "Esc"),
                Space::new().width(6),
                text("to go back").size(11).color(t.sub),
            ]
            .align_y(Alignment::Center),
        )
        .width(Length::Fill)
        .center_x(Length::Fill);

        let mut content = column![
            kao_hero(t, "(っ◕‿◕)っ", 56.0),
            vspace(10),
            screen_title(t, "Import from Seed Phrase"),
            vspace(6),
            screen_subtitle(t, "Enter your 12 or 24-word BIP39 recovery phrase."),
            vspace(22),
            phrase_input,
            vspace(18),
            confirm_btn,
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

    /// Same Hardhat default mnemonic used in `wallet/mod.rs` derivation tests.
    const VALID: &str = "test test test test test test test test test test test junk";

    #[test]
    fn empty_phrase_errors_without_outcome() {
        let mut s = ImportSeedPhraseScreen::default();
        let (_, outcome) = s.update(Message::ConfirmPressed);
        assert!(outcome.is_none());
        assert!(s.error.is_some());
    }

    #[test]
    fn wrong_word_count_errors_with_count_in_message() {
        let mut s = ImportSeedPhraseScreen::default();
        s.update(Message::PhraseInput("test test test test test".into()));
        let (_, outcome) = s.update(Message::ConfirmPressed);
        assert!(outcome.is_none());
        let err = s.error.unwrap();
        assert!(err.contains("12 or 24"));
        assert!(err.contains('5'));
    }

    #[test]
    fn invalid_checksum_errors() {
        let mut s = ImportSeedPhraseScreen::default();
        // 12 valid BIP39 words but the checksum doesn't add up.
        s.update(Message::PhraseInput(
            "test test test test test test test test test test test test".into(),
        ));
        let (_, outcome) = s.update(Message::ConfirmPressed);
        assert!(outcome.is_none());
        assert!(s.error.unwrap().to_lowercase().contains("invalid"));
    }

    #[test]
    fn valid_phrase_emits_confirmed_with_normalized_whitespace_and_case() {
        let mut s = ImportSeedPhraseScreen::default();
        // Mixed case, leading/trailing whitespace, tabs, and double spaces.
        let messy = " \tTEST  test test  test\ttest test test test test test test JUNK ";
        s.update(Message::PhraseInput(messy.into()));
        let (_, outcome) = s.update(Message::ConfirmPressed);
        match outcome {
            Some(Outcome::Confirmed { phrase }) => assert_eq!(phrase.expose_secret(), VALID),
            other => panic!("expected Confirmed, got {other:?}"),
        }
        assert!(s.error.is_none());
    }

    #[test]
    fn back_pressed_emits_back() {
        let mut s = ImportSeedPhraseScreen::default();
        let (_, outcome) = s.update(Message::BackPressed);
        assert!(matches!(outcome, Some(Outcome::Back)));
    }

    #[test]
    fn with_phrase_constructor_prefills_input() {
        let s = ImportSeedPhraseScreen::with_phrase(SecretString::new(
            "foo bar".to_string().into_boxed_str(),
        ));
        assert_eq!(s.phrase_input.as_str(), "foo bar");
        assert!(s.error.is_none());
    }
}
