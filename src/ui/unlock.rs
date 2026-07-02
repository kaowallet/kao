use iced::widget::{Space, column, container, row, text, text_input};
use iced::{Alignment, Element, Length, Padding, Task};
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::settings;
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    auth_background, auth_card, error_text, hint_pill, kao_hero, mono, primary_button,
    screen_subtitle, screen_title, text_input_style, vspace,
};
use crate::wallet::{self, WalletDescriptor, WalletError};

pub const PASSWORD_INPUT_ID: &str = "unlock_password_input";

/// Structured failure modes from the unlock async task. We classify here
/// rather than storing a `String` so the update handler can dispatch
/// distinct UI behaviour for each: wrong-password just refreshes the
/// inline error label, and Other falls back to a generic error string.
#[derive(Debug, Clone)]
pub enum UnlockError {
    WrongPassword,
    /// Anything else worth showing verbatim (IO, …). Pre-formatted so the
    /// view doesn't have to pattern-match on `WalletError`.
    Other(String),
}

#[derive(Debug, Clone)]
pub enum Message {
    PasswordInput(crate::trace::SecretInput),
    UnlockPressed,
    PasswordSubmitted,
    UnlockResult(Result<WalletDescriptor, UnlockError>),
}

/// Outcome signals emitted by this screen to its parent.
#[derive(Debug)]
pub enum Outcome {
    Unlocked {
        passphrase: SecretString,
        descriptor: WalletDescriptor,
    },
}

impl Outcome {
    /// Variant name for the GUI state trace — never the payload, which
    /// carries the session passphrase.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Unlocked { .. } => "Unlocked",
        }
    }
}

/// Map a `WalletError` from the loader into the unlock screen's
/// dispatch-friendly error enum.
fn classify(e: WalletError) -> UnlockError {
    match e {
        // Encryption is the variant the wallet store uses for
        // wrong-password (the AEAD auth-check fails to decrypt). Any
        // other Encryption error is rare and bug-shaped — for the
        // unlock screen, "looks like a wrong password" is a fine
        // heuristic since the user can re-try and a real corruption
        // would surface persistently.
        WalletError::Encryption(_) => UnlockError::WrongPassword,
        other => UnlockError::Other(other.to_string()),
    }
}

#[derive(Debug, Default)]
pub struct UnlockScreen {
    /// Live `text_input` buffer. `Zeroizing<String>` zeros the heap allocation
    /// each time the input is replaced (every keystroke) and on screen drop.
    password: Zeroizing<String>,
    error: Option<String>,
    unlocking: bool,
}

impl UnlockScreen {
    pub fn update(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("unlock", &message);
        let busy_before = self.unlocking;
        let (task, outcome) = self.update_inner(message);
        if busy_before != self.unlocking {
            crate::trace::state("unlock", "busy", busy_before, self.unlocking);
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("unlock", o.name());
        }
        (task, outcome)
    }

    fn update_inner(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        match message {
            Message::PasswordInput(p) => {
                self.password = p.take();
                (Task::none(), None)
            }
            Message::PasswordSubmitted | Message::UnlockPressed => (self.try_unlock(), None),
            Message::UnlockResult(Ok(descriptor)) => {
                self.unlocking = false;
                // Take the buffer so the previous heap allocation gets
                // zeroed on drop. `Box::from(&str)` reallocates into a
                // fresh buffer that `SecretString` then owns and zeros.
                let taken = std::mem::take(&mut self.password);
                let passphrase = SecretString::new(Box::from(taken.as_str()));
                (
                    Task::none(),
                    Some(Outcome::Unlocked {
                        passphrase,
                        descriptor,
                    }),
                )
            }
            Message::UnlockResult(Err(UnlockError::WrongPassword)) => {
                self.unlocking = false;
                self.error = Some("Incorrect password".to_string());
                (Task::none(), None)
            }
            Message::UnlockResult(Err(UnlockError::Other(msg))) => {
                self.unlocking = false;
                self.error = Some(msg);
                (Task::none(), None)
            }
        }
    }

    fn try_unlock(&mut self) -> Task<Message> {
        if self.password.is_empty() || self.unlocking {
            return Task::none();
        }
        self.error = None;
        self.unlocking = true;

        // Clone into another `Zeroizing<String>` so the async-task copy
        // gets wiped after the SecretString takes over. The original
        // `self.password` stays put so the user doesn't have to retype on
        // a wrong-password error.
        let password = self.password.clone();
        Task::perform(
            async move {
                // `load_descriptor` runs Argon2id (~250–500ms on desktop).
                // Without `spawn_blocking` it stalls the iced runtime —
                // input events queue up and the unlocking-spinner state
                // never gets to repaint. Match `save_descriptor_task` in
                // `app/mod.rs` which already handles this for the symmetric
                // save path.
                let join = tokio::task::spawn_blocking(move || {
                    let passphrase = SecretString::new(Box::from(password.as_str()));
                    wallet::load_descriptor(&passphrase)
                })
                .await;
                match join {
                    Ok(Ok(desc)) => Ok(desc),
                    Ok(Err(e)) => Err(classify(e)),
                    Err(join_err) => Err(UnlockError::Other(format!(
                        "unlock task panicked: {join_err}"
                    ))),
                }
            },
            Message::UnlockResult,
        )
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

        let (btn_label, enabled) = if self.unlocking {
            ("(・・;)ゞ unlocking…", false)
        } else {
            ("Unlock ✓", true)
        };
        let unlock_btn = {
            let mut b = primary_button(t, btn_label, enabled);
            if enabled {
                b = b.on_press(Message::UnlockPressed);
            }
            b
        };

        let hint = container(
            row![
                hint_pill(t, "Enter"),
                Space::new().width(6),
                text("to unlock").size(11).color(t.sub),
            ]
            .align_y(Alignment::Center),
        )
        .width(Length::Fill)
        .center_x(Length::Fill);

        let mut content = column![
            kao_hero(t, "(˘ᵕ˘)", 56.0),
            vspace(10),
            screen_title(t, "Welcome Back"),
            vspace(6),
            screen_subtitle(
                t,
                "Enter your password to decrypt the wallet on this device."
            ),
            vspace(24),
            password_input,
            vspace(20),
            unlock_btn,
            vspace(14),
            hint,
        ]
        .width(Length::Fill)
        .align_x(Alignment::Center);

        if let Some(e) = &self.error {
            content = content.push(vspace(10)).push(error_text(t, e));
        }

        auth_background(t, auth_card(t, 400.0, content.into()))
    }
}
