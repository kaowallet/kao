use alloy::primitives::Address;
use iced::border::Radius;
use iced::keyboard;
use iced::widget::operation::focus as focus_widget;
use iced::widget::{Space, column, container, row, text, text_input};
use iced::{Alignment, Background, Border, Element, Length, Padding, Subscription, Task};

use rand::seq::SliceRandom;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::settings;
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    auth_background, auth_card, error_text, hint_pill, kao_hero, link_button, mono, mono_bold,
    primary_button, screen_subtitle, screen_title, text_input_style, vspace,
};

fn input_id(blank_pos: usize) -> iced::widget::Id {
    iced::widget::Id::from(format!("verify_input_{blank_pos}"))
}

const BLANK_COUNT: usize = 4;

#[derive(Debug, Clone)]
pub enum Message {
    WordInput(usize, String),
    WordSubmitted(usize),
    Verify,
    BackPressed,
    KeyboardEvent(keyboard::Event),
}

/// Outcome signals emitted by this screen to its parent.
#[derive(Debug, Clone)]
pub enum Outcome {
    Verified,
    /// Navigate back to ShowSeed, reconstructing it from the carried data.
    Back {
        phrase: SecretString,
        key_bytes: Zeroizing<[u8; 32]>,
        address: Address,
    },
}

#[derive(Debug)]
pub struct VerifySeedScreen {
    full_phrase: SecretString,
    key_bytes: Zeroizing<[u8; 32]>,
    address: Address,
    blank_indices: Vec<usize>,
    inputs: Vec<Zeroizing<String>>,
    verified: bool,
    focused: usize,
    error: Option<String>,
}

impl VerifySeedScreen {
    pub fn new(
        seed_phrase: SecretString,
        key_bytes: Zeroizing<[u8; 32]>,
        address: Address,
    ) -> Self {
        let word_count = seed_phrase.expose_secret().split_whitespace().count();

        let mut all_indices: Vec<usize> = (0..word_count).collect();
        let mut rng = rand::thread_rng();
        all_indices.shuffle(&mut rng);
        let mut blank_indices = all_indices[..BLANK_COUNT].to_vec();
        blank_indices.sort();

        Self {
            full_phrase: seed_phrase,
            key_bytes,
            address,
            blank_indices,
            inputs: (0..BLANK_COUNT)
                .map(|_| Zeroizing::new(String::new()))
                .collect(),
            verified: false,
            focused: 0,
            error: None,
        }
    }

    pub fn focus_initial_task(&self) -> Task<Message> {
        focus_widget(input_id(0))
    }

    fn verify(&mut self) -> bool {
        let exposed = self.full_phrase.expose_secret();
        let words: Vec<&str> = exposed.split_whitespace().collect();
        let all_correct = self.blank_indices.iter().enumerate().all(|(i, &word_idx)| {
            self.inputs[i].trim().to_lowercase() == words[word_idx].to_lowercase()
        });
        if all_correct {
            self.verified = true;
            self.error = None;
        } else {
            self.error = Some("One or more words are incorrect. Please try again.".into());
        }
        all_correct
    }

    fn back_outcome(&self) -> Outcome {
        Outcome::Back {
            phrase: self.full_phrase.clone(),
            key_bytes: self.key_bytes.clone(),
            address: self.address,
        }
    }

    pub fn update(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        match message {
            Message::WordInput(idx, val) => {
                if idx < self.inputs.len() {
                    // Replacing the Zeroizing<String> drops the old buffer,
                    // which zeros it before deallocation.
                    self.inputs[idx] = Zeroizing::new(val);
                }
                (Task::none(), None)
            }
            Message::WordSubmitted(idx) => {
                if idx + 1 < self.inputs.len() {
                    self.focused = idx + 1;
                    (focus_widget(input_id(idx + 1)), None)
                } else if !self.verified {
                    let outcome = self.verify().then_some(Outcome::Verified);
                    (Task::none(), outcome)
                } else {
                    (Task::none(), None)
                }
            }
            Message::Verify => {
                let outcome = self.verify().then_some(Outcome::Verified);
                (Task::none(), outcome)
            }
            Message::BackPressed => (Task::none(), Some(self.back_outcome())),
            Message::KeyboardEvent(keyboard::Event::KeyPressed { key, modifiers, .. }) => match key
            {
                keyboard::Key::Named(keyboard::key::Named::Escape) => {
                    (Task::none(), Some(self.back_outcome()))
                }
                keyboard::Key::Named(keyboard::key::Named::Tab) => {
                    let task = if modifiers.shift() {
                        if self.focused > 0 {
                            self.focused -= 1;
                            focus_widget(input_id(self.focused))
                        } else {
                            Task::none()
                        }
                    } else if self.focused + 1 < self.inputs.len() {
                        self.focused += 1;
                        focus_widget(input_id(self.focused))
                    } else {
                        Task::none()
                    };
                    (task, None)
                }
                _ => (Task::none(), None),
            },
            Message::KeyboardEvent(_) => (Task::none(), None),
        }
    }

    pub fn into_wallet_data(self) -> (Zeroizing<[u8; 32]>, Address) {
        (self.key_bytes, self.address)
    }

    pub fn subscription(&self) -> Subscription<Message> {
        keyboard::listen().map(Message::KeyboardEvent)
    }

    pub fn view(&self) -> Element<'_, Message> {
        let t = KaoTheme::for_kind(settings::theme());

        let exposed = self.full_phrase.expose_secret();
        let words: Vec<&str> = exposed.split_whitespace().collect();
        let mut rows = column![].spacing(8);
        for (chunk_start, chunk) in words.chunks(4).enumerate() {
            let mut row_el = row![].spacing(8);
            for (i, _) in chunk.iter().enumerate() {
                let global_idx = chunk_start * 4 + i;
                if let Some(blank_pos) = self.blank_indices.iter().position(|&bi| bi == global_idx)
                {
                    let input = text_input("?", self.inputs[blank_pos].as_str())
                        .id(input_id(blank_pos))
                        .on_input(move |v| Message::WordInput(blank_pos, v))
                        .on_submit(Message::WordSubmitted(blank_pos))
                        .padding(Padding::from([6, 8]))
                        .size(13)
                        .font(mono_bold())
                        .style(move |_theme, status| text_input_style(t, status))
                        .width(Length::Fill);
                    row_el = row_el.push(blank_cell(t, global_idx + 1, input.into()));
                } else {
                    row_el = row_el.push(filled_cell(t, global_idx + 1, words[global_idx]));
                }
            }
            rows = rows.push(row_el);
        }

        let verify_btn = if self.verified {
            primary_button(t, "✓ Verified", true)
        } else {
            primary_button(t, "Verify ✓", true).on_press(Message::Verify)
        };

        let hint = container(
            row![
                hint_pill(t, "Tab"),
                Space::new().width(6),
                text("between blanks · ").size(11).color(t.sub),
                hint_pill(t, "Enter"),
                Space::new().width(6),
                text("to verify · ").size(11).color(t.sub),
                hint_pill(t, "Esc"),
                Space::new().width(6),
                text("back").size(11).color(t.sub),
            ]
            .align_y(Alignment::Center),
        )
        .width(Length::Fill)
        .center_x(Length::Fill);

        let mut content = column![
            kao_hero(t, "( •̀ω•́ )✧", 56.0),
            vspace(10),
            screen_title(t, "Verify Your Seed Phrase"),
            vspace(6),
            screen_subtitle(t, "Fill in the missing words to confirm you saved it."),
            vspace(22),
            rows,
            vspace(18),
            verify_btn,
            vspace(14),
            hint,
        ]
        .width(Length::Fill)
        .align_x(Alignment::Center);

        if let Some(e) = &self.error {
            content = content.push(vspace(10)).push(error_text(t, e));
        }

        let card = auth_card(t, 560.0, content.into());

        let back_bar = container(link_button(t, "← Back").on_press(Message::BackPressed))
            .padding(Padding::from([12, 14]))
            .width(Length::Fill);

        let layout = column![back_bar, card]
            .width(Length::Fill)
            .height(Length::Fill);

        auth_background(t, layout.into())
    }
}

fn filled_cell<'a>(t: KaoTheme, num: usize, word: &'a str) -> Element<'a, Message> {
    let inner = row![
        text(format!("{num:>2}")).size(11).color(t.sub).font(mono()),
        Space::new().width(6),
        text(word).size(13).color(t.text).font(mono_bold()),
    ]
    .align_y(Alignment::Center);

    container(inner)
        .padding(Padding::from([8, 10]))
        .width(Length::Fixed(120.0))
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card_alt)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(10),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
}

fn blank_cell<'a>(t: KaoTheme, num: usize, input: Element<'a, Message>) -> Element<'a, Message> {
    let inner = row![
        text(format!("{num:>2}")).size(11).color(t.sub).font(mono()),
        Space::new().width(6),
        container(input).width(Length::Fill),
    ]
    .align_y(Alignment::Center);

    container(inner)
        .padding(Padding::from([2, 6]))
        .width(Length::Fixed(120.0))
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card_alt)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(10),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "test test test test test test test test test test test junk";

    fn secret_phrase() -> SecretString {
        SecretString::new(PHRASE.to_string().into_boxed_str())
    }

    fn dummy_screen() -> VerifySeedScreen {
        VerifySeedScreen::new(
            secret_phrase(),
            Zeroizing::new([0xab; 32]),
            Address::from([0x11; 20]),
        )
    }

    fn fill_blanks_correctly(s: &mut VerifySeedScreen) {
        let blanks = s.blank_indices.clone();
        let words: Vec<String> = s
            .full_phrase
            .expose_secret()
            .split_whitespace()
            .map(|w| w.to_string())
            .collect();
        for (i, &word_idx) in blanks.iter().enumerate() {
            s.inputs[i] = Zeroizing::new(words[word_idx].clone());
        }
    }

    #[test]
    fn challenge_picks_four_unique_in_range_indices() {
        let s = dummy_screen();
        assert_eq!(s.blank_indices.len(), BLANK_COUNT);
        let word_count = s.full_phrase.expose_secret().split_whitespace().count();
        for &idx in &s.blank_indices {
            assert!(idx < word_count, "blank idx {idx} out of range");
        }
        let mut sorted = s.blank_indices.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), BLANK_COUNT, "blank indices must be unique");
    }

    #[test]
    fn verify_with_correct_words_emits_verified() {
        let mut s = dummy_screen();
        fill_blanks_correctly(&mut s);
        let (_, outcome) = s.update(Message::Verify);
        assert!(matches!(outcome, Some(Outcome::Verified)));
        assert!(s.verified);
        assert!(s.error.is_none());
    }

    #[test]
    fn verify_with_wrong_words_records_error_and_no_outcome() {
        let mut s = dummy_screen();
        for input in s.inputs.iter_mut() {
            *input = Zeroizing::new("wrong".into());
        }
        let (_, outcome) = s.update(Message::Verify);
        assert!(outcome.is_none());
        assert!(!s.verified);
        assert!(s.error.is_some());
    }

    #[test]
    fn verify_is_case_insensitive_and_trims_whitespace() {
        let mut s = dummy_screen();
        let blanks = s.blank_indices.clone();
        let words: Vec<String> = s
            .full_phrase
            .expose_secret()
            .split_whitespace()
            .map(|w| w.to_string())
            .collect();
        for (i, &word_idx) in blanks.iter().enumerate() {
            s.inputs[i] = Zeroizing::new(format!("  {}  ", words[word_idx].to_uppercase()));
        }
        let (_, outcome) = s.update(Message::Verify);
        assert!(matches!(outcome, Some(Outcome::Verified)));
    }

    #[test]
    fn back_pressed_returns_phrase_and_keys_unmodified() {
        let key_bytes = [0xab; 32];
        let address = Address::from([0x11; 20]);
        let mut s = VerifySeedScreen::new(secret_phrase(), Zeroizing::new(key_bytes), address);
        let (_, outcome) = s.update(Message::BackPressed);
        match outcome {
            Some(Outcome::Back {
                phrase,
                key_bytes: kb,
                address: a,
            }) => {
                assert_eq!(phrase.expose_secret(), PHRASE);
                assert_eq!(*kb, key_bytes);
                assert_eq!(a, address);
            }
            other => panic!("expected Back, got {other:?}"),
        }
    }

    #[test]
    fn word_submitted_advances_focus_until_last_then_verifies() {
        let mut s = dummy_screen();
        fill_blanks_correctly(&mut s);
        // Submitting on the last blank triggers verification.
        let last = BLANK_COUNT - 1;
        let (_, outcome) = s.update(Message::WordSubmitted(last));
        assert!(matches!(outcome, Some(Outcome::Verified)));
    }
}
