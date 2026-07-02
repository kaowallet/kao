use iced::keyboard;
use iced::widget::operation::focus as focus_widget;
use iced::widget::{Space, column, container, row, text, text_input};
use iced::{Alignment, Element, Length, Padding, Subscription, Task};
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::settings;
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    auth_background, auth_card, error_text, hint_pill, kao_hero, mono, primary_button,
    screen_subtitle, screen_title, text_input_style, vspace,
};

/// Widget IDs for focus management.
pub const PASSWORD_INPUT_ID: &str = "password_input";
pub const CONFIRM_INPUT_ID: &str = "confirm_input";

#[derive(Debug, Clone)]
pub enum Message {
    PasswordInput(crate::trace::SecretInput),
    ConfirmInput(crate::trace::SecretInput),
    CreatePressed,
    PasswordSubmitted,
    ConfirmSubmitted,
    KeyboardEvent(keyboard::Event),
}

/// Outcome signals emitted by this screen to its parent.
#[derive(Debug)]
pub enum Outcome {
    /// User picked a valid passphrase. The parent should hold this for the
    /// remainder of the setup flow (to encrypt the wallet on save).
    Created(SecretString),
}

impl Outcome {
    /// Variant name for the GUI state trace — never the payload, which
    /// carries the chosen passphrase.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Created(_) => "Created",
        }
    }
}

#[derive(Debug, Default)]
pub struct CreatePasswordScreen {
    /// Live `text_input` buffers. `Zeroizing<String>` zeros the heap
    /// allocation each time the input is replaced (every keystroke) and
    /// on screen drop.
    password: Zeroizing<String>,
    confirm: Zeroizing<String>,
    error: Option<String>,
    /// Tracks which field currently has focus for Tab navigation.
    focused: Focus,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Focus {
    #[default]
    Password,
    Confirm,
}

impl Focus {
    fn name(self) -> &'static str {
        match self {
            Focus::Password => "Password",
            Focus::Confirm => "Confirm",
        }
    }
}

impl CreatePasswordScreen {
    pub fn update(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("create_password", &message);
        let focus_before = self.focused;
        let (task, outcome) = self.update_inner(message);
        if focus_before != self.focused {
            crate::trace::state(
                "create_password",
                "focus",
                focus_before.name(),
                self.focused.name(),
            );
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("create_password", o.name());
        }
        (task, outcome)
    }

    fn update_inner(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        match message {
            Message::PasswordInput(p) => {
                self.password = p.take();
                (Task::none(), None)
            }
            Message::ConfirmInput(c) => {
                self.confirm = c.take();
                (Task::none(), None)
            }
            Message::PasswordSubmitted => {
                self.focused = Focus::Confirm;
                (focus_widget(CONFIRM_INPUT_ID), None)
            }
            Message::ConfirmSubmitted | Message::CreatePressed => {
                let outcome = self.try_create();
                (Task::none(), outcome)
            }
            Message::KeyboardEvent(event) => match event {
                keyboard::Event::KeyPressed {
                    key: keyboard::Key::Named(keyboard::key::Named::Tab),
                    modifiers,
                    ..
                } => {
                    let task = if modifiers.shift() {
                        match self.focused {
                            Focus::Password => Task::none(),
                            Focus::Confirm => {
                                self.focused = Focus::Password;
                                focus_widget(PASSWORD_INPUT_ID)
                            }
                        }
                    } else {
                        match self.focused {
                            Focus::Password => {
                                self.focused = Focus::Confirm;
                                focus_widget(CONFIRM_INPUT_ID)
                            }
                            Focus::Confirm => Task::none(),
                        }
                    };
                    (task, None)
                }
                _ => (Task::none(), None),
            },
        }
    }

    fn try_create(&mut self) -> Option<Outcome> {
        if self.password.len() < 8 {
            self.error = Some("Password must be at least 8 characters".into());
            return None;
        }
        if self.password.as_str() != self.confirm.as_str() {
            self.error = Some("Passwords do not match".into());
            return None;
        }
        self.error = None;
        // Take both buffers so the previous heap allocations zero on drop.
        // `Box::from(&str)` reallocates into a fresh buffer that
        // `SecretString` then owns and zeros.
        let taken = std::mem::take(&mut self.password);
        let _confirm = std::mem::take(&mut self.confirm);
        let secret = SecretString::new(Box::from(taken.as_str()));
        Some(Outcome::Created(secret))
    }

    pub fn view(&self) -> Element<'_, Message> {
        let t = KaoTheme::for_kind(settings::theme());

        let password_input = text_input("Password", self.password.as_str())
            .id(PASSWORD_INPUT_ID)
            .secure(true)
            .on_input(|s| Message::PasswordInput(s.into()))
            .on_submit(Message::PasswordSubmitted)
            .padding(Padding::from([12, 14]))
            .size(14)
            .font(mono())
            .style(move |_theme, status| text_input_style(t, status));

        let confirm_input = text_input("Confirm password", self.confirm.as_str())
            .id(CONFIRM_INPUT_ID)
            .secure(true)
            .on_input(|s| Message::ConfirmInput(s.into()))
            .on_submit(Message::ConfirmSubmitted)
            .padding(Padding::from([12, 14]))
            .size(14)
            .font(mono())
            .style(move |_theme, status| text_input_style(t, status));

        let create_btn =
            primary_button(t, "Create Password ✓", true).on_press(Message::CreatePressed);

        let hint_row = container(
            row![
                hint_pill(t, "Tab"),
                Space::new().width(6),
                text("between fields, ").size(11).color(t.sub),
                hint_pill(t, "Enter"),
                Space::new().width(6),
                text("to confirm").size(11).color(t.sub),
            ]
            .align_y(Alignment::Center),
        )
        .width(Length::Fill)
        .center_x(Length::Fill);

        let mut content = column![
            kao_hero(t, "(´｡• ᵕ •｡`)", 56.0),
            vspace(10),
            screen_title(t, "Welcome to Kao"),
            vspace(6),
            screen_subtitle(t, "Set a password to encrypt your wallet on this device."),
            vspace(24),
            password_input,
            vspace(10),
            confirm_input,
            vspace(20),
            create_btn,
            vspace(14),
            hint_row,
        ]
        .width(Length::Fill)
        .align_x(Alignment::Center);

        if let Some(e) = &self.error {
            content = content.push(vspace(10)).push(error_text(t, e));
        }

        auth_background(t, auth_card(t, 420.0, content.into()))
    }

    /// Keyboard subscription for Tab key handling.
    pub fn subscription(&self) -> Subscription<Message> {
        keyboard::listen().map(Message::KeyboardEvent)
    }
}

#[cfg(test)]
#[allow(unused_must_use)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn fill(screen: &mut CreatePasswordScreen, password: &str, confirm: &str) {
        screen.update(Message::PasswordInput(password.into()));
        screen.update(Message::ConfirmInput(confirm.into()));
    }

    #[test]
    fn rejects_password_shorter_than_eight_chars() {
        let mut s = CreatePasswordScreen::default();
        fill(&mut s, "short", "short");
        let (_, outcome) = s.update(Message::CreatePressed);
        assert!(outcome.is_none());
        assert!(s.error.as_deref().unwrap().contains("8 characters"));
    }

    #[test]
    fn rejects_mismatched_confirmation() {
        let mut s = CreatePasswordScreen::default();
        fill(&mut s, "longenough1", "longenough2");
        let (_, outcome) = s.update(Message::CreatePressed);
        assert!(outcome.is_none());
        assert!(s.error.as_deref().unwrap().contains("do not match"));
    }

    #[test]
    fn create_pressed_returns_secret_when_valid() {
        let mut s = CreatePasswordScreen::default();
        fill(&mut s, "longenough1", "longenough1");
        let (_, outcome) = s.update(Message::CreatePressed);
        match outcome {
            Some(Outcome::Created(secret)) => assert_eq!(secret.expose_secret(), "longenough1"),
            None => panic!("expected Created outcome"),
        }
        // Sensitive fields are zeroed/cleared once the secret is handed off.
        assert!(s.password.is_empty());
        assert!(s.confirm.is_empty());
        assert!(s.error.is_none());
    }

    #[test]
    fn confirm_submitted_is_equivalent_to_create_pressed() {
        let mut s = CreatePasswordScreen::default();
        fill(&mut s, "longenough1", "longenough1");
        let (_, outcome) = s.update(Message::ConfirmSubmitted);
        assert!(matches!(outcome, Some(Outcome::Created(_))));
    }

    #[test]
    fn password_submitted_focuses_confirm_field() {
        let mut s = CreatePasswordScreen::default();
        s.update(Message::PasswordInput("longenough1".into()));
        let (_, outcome) = s.update(Message::PasswordSubmitted);
        assert!(outcome.is_none());
        assert_eq!(s.focused, Focus::Confirm);
    }
}
