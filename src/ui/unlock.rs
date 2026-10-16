use std::sync::Arc;

use iced::widget::{Space, column, container, row, text, text_input};
use iced::{Alignment, Element, Length, Padding, Task};
use secrecy::SecretString;
use tracing::warn;
use zeroize::Zeroizing;

use crate::settings;
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    auth_background, auth_card, error_text, hint_pill, kao_hero, mono, primary_button,
    screen_subtitle, screen_title, text_input_style, vspace,
};
use crate::wallet::{self, Unlocked, WalletError};
use crate::walletconnect::QUIT_TEARDOWN_BUDGET;
use crate::walletconnect::runtime::WcSlot;

/// How long an unlock waits for the last lock's WalletConnect suspend and vault drain before it
/// reads the store anyway: the suspend's own bound, plus slack for the writer's last batch.
const PREVIOUS_EPOCH_BUDGET: std::time::Duration =
    QUIT_TEARDOWN_BUDGET.saturating_add(std::time::Duration::from_secs(1));

pub const PASSWORD_INPUT_ID: &str = "unlock_password_input";

/// Another Kao process holds the wallet (`WalletError::InUse`) — at unlock, or creating a wallet.
pub const ALREADY_OPEN: &str = "Kao is already open in another window — close it first.";

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
    /// `Arc`: the message must be `Clone`, and `Unlocked` holds the data key and the sealed rows
    /// (its `Debug` prints counts only).
    UnlockResult(Result<Arc<Unlocked>, UnlockError>),
}

/// Outcome signals emitted by this screen to its parent.
#[derive(Debug)]
pub enum Outcome {
    Unlocked {
        passphrase: SecretString,
        unlocked: Arc<Unlocked>,
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
        // Another Kao process has the wallet: not a password problem.
        WalletError::InUse => UnlockError::Other(ALREADY_OPEN.to_string()),
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

/// How the instance lock is taken: `wallet::acquire_instance_lock`, or a test's stand-in.
pub(crate) type AcquireInstanceLock = fn() -> Result<(), WalletError>;
/// How an unlock reads the store: `wallet::load_wallet`, or a test's stand-in.
type LoadWallet = fn(&SecretString) -> Result<Unlocked, WalletError>;

/// Take the process-wide instance lock (with `acquire`) before this process reads or creates the
/// wallet: a second Kao process on the same file would write over this one's history rows and
/// saved WalletConnect state. Only another process holding it refuses (`InUse`); a lock Kao can't
/// take for any other reason (a filesystem without locks, say) is logged, and Kao goes ahead as it
/// did before the lock existed rather than lock the user out of their wallet.
pub(crate) fn claim_instance_with(acquire: AcquireInstanceLock) -> Result<(), WalletError> {
    match acquire() {
        Err(WalletError::InUse) => Err(WalletError::InUse),
        Err(e) => {
            warn!(error = %e, "couldn't take the instance lock; going ahead without it");
            Ok(())
        }
        Ok(()) => Ok(()),
    }
}

/// The store read behind an unlock: the instance lock, then the wallet — never the wallet while
/// another process holds it.
fn load_for_unlock_with(
    acquire: AcquireInstanceLock,
    load: LoadWallet,
    passphrase: &SecretString,
) -> Result<Unlocked, WalletError> {
    claim_instance_with(acquire)?;
    load(passphrase)
}

/// What a real unlock takes the lock and reads the store with (a test swaps both, so it never
/// reaches the user's wallet).
#[derive(Clone, Copy)]
struct UnlockIo {
    acquire: AcquireInstanceLock,
    load: LoadWallet,
}

impl Default for UnlockIo {
    fn default() -> Self {
        Self {
            acquire: wallet::acquire_instance_lock,
            load: wallet::load_wallet,
        }
    }
}

impl std::fmt::Debug for UnlockIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UnlockIo")
    }
}

/// The unlock's off-thread work: first `previous_epoch` — the last lock's WalletConnect suspend
/// may still be saving (bounded by the caller), and its final state must be on disk before the
/// store is read — then `load` on the blocking pool.
async fn unlock_after<P, L>(previous_epoch: P, load: L) -> Result<Arc<Unlocked>, UnlockError>
where
    P: Future<Output = ()>,
    L: FnOnce() -> Result<Unlocked, WalletError> + Send + 'static,
{
    previous_epoch.await;
    // `load_wallet` runs Argon2id (~250–500ms on desktop). Without
    // `spawn_blocking` it stalls the iced runtime — input events queue up and
    // the unlocking-spinner state never gets to repaint. Match
    // `save_descriptor_task` in `app/mod.rs` which already handles this for
    // the symmetric save path.
    match tokio::task::spawn_blocking(load).await {
        Ok(Ok(unlocked)) => Ok(Arc::new(unlocked)),
        Ok(Err(e)) => Err(classify(e)),
        Err(join_err) => Err(UnlockError::Other(format!(
            "unlock task panicked: {join_err}"
        ))),
    }
}

#[derive(Debug, Default)]
pub struct UnlockScreen {
    /// Live `text_input` buffer. `Zeroizing<String>` zeros the heap allocation
    /// each time the input is replaced (every keystroke) and on screen drop.
    password: Zeroizing<String>,
    error: Option<String>,
    unlocking: bool,
    /// The App's WalletConnect slot — after a lock, the successor of the one
    /// that was suspended, sharing its teardown registry. The unlock waits for
    /// that registry to go idle (the last epoch's suspend and its vault drain)
    /// before it reads the store, so it loads the state the suspend saved and
    /// its record ids can't collide with the old writer's.
    slot: WcSlot,
    io: UnlockIo,
}

impl UnlockScreen {
    /// The unlock screen over the App's current WalletConnect slot.
    pub fn new(slot: WcSlot) -> Self {
        Self {
            slot,
            ..Self::default()
        }
    }

    /// The slot this screen's unlock waits on (tests).
    #[cfg(test)]
    pub fn slot(&self) -> &WcSlot {
        &self.slot
    }

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
            Message::UnlockResult(Ok(unlocked)) => {
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
                        unlocked,
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
        Task::perform(self.unlock_job(password), Message::UnlockResult)
    }

    /// What Unlock runs: the instance lock and the store read (`io`) behind the previous epoch's
    /// wait.
    fn unlock_job(
        &self,
        password: Zeroizing<String>,
    ) -> impl Future<Output = Result<Arc<Unlocked>, UnlockError>> + Send + use<> {
        let UnlockIo { acquire, load } = self.io;
        self.unlock_future(password, move |pw| load_for_unlock_with(acquire, load, pw))
    }

    /// Everything an unlock runs, in one place (a test drives it with a probe `load`): wait for
    /// the previous epoch — this slot's teardown registry going idle, bounded — then `load` the
    /// store on the blocking pool with `password`.
    fn unlock_future<L>(
        &self,
        password: Zeroizing<String>,
        load: L,
    ) -> impl Future<Output = Result<Arc<Unlocked>, UnlockError>> + Send + use<L>
    where
        L: FnOnce(&SecretString) -> Result<Unlocked, WalletError> + Send + 'static,
    {
        let previous_epoch = self.slot.wait_idle(PREVIOUS_EPOCH_BUDGET);
        unlock_after(previous_epoch, move || {
            let passphrase = SecretString::new(Box::from(password.as_str()));
            load(&passphrase)
        })
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;
    use crate::walletconnect::testkit;

    const ADDR: alloy::primitives::Address =
        alloy::primitives::address!("ab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb");

    /// The store is read only after the previous epoch's wait resolves.
    #[tokio::test]
    async fn the_load_waits_for_the_previous_epoch() {
        let (done, previous) = tokio::sync::oneshot::channel::<()>();
        let loaded = Arc::new(AtomicBool::new(false));
        let flag = loaded.clone();
        let unlock = tokio::spawn(unlock_after(
            async {
                let _ = previous.await;
            },
            move || {
                flag.store(true, Ordering::SeqCst);
                Err(WalletError::NotFound)
            },
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!loaded.load(Ordering::SeqCst), "nothing read yet");
        done.send(()).unwrap();
        let result = unlock.await.unwrap();
        assert!(loaded.load(Ordering::SeqCst));
        assert!(matches!(result, Err(UnlockError::Other(_))));
    }

    /// What an unlock right after a lock waits for: the lock's WalletConnect teardown (or suspend),
    /// counted in the registry the successor slot — the one the unlock screen holds — shares.
    #[tokio::test]
    async fn unlock_waits_for_the_last_locks_teardown() {
        let (_relay, dapp, _events, rt, slot) = testkit::harness().await;
        testkit::connect_raw(&rt, &dapp, ADDR, &[1]).await;
        let next = slot.successor();
        let old = slot.close().expect("installed");
        drop(slot.spawn_teardown(old));
        assert_eq!(next.teardowns_running(), 1);
        let screen = UnlockScreen::new(next.clone());
        let seen = Arc::new(AtomicUsize::new(usize::MAX));
        let probe = (next.clone(), seen.clone());
        // Exactly what `try_unlock` runs, with a probe for the store read.
        let result = screen
            .unlock_future(Zeroizing::new("pw".to_string()), move |_| {
                probe.1.store(probe.0.teardowns_running(), Ordering::SeqCst);
                Err(WalletError::NotFound)
            })
            .await;
        assert!(result.is_err());
        assert_eq!(
            seen.load(Ordering::SeqCst),
            0,
            "loaded only once the lock's teardown ended"
        );
    }

    /// Another Kao process holding the wallet is said as such — never "Incorrect password", which
    /// sends the user to retype a password that was right.
    #[tokio::test]
    async fn a_wallet_open_in_another_process_is_not_a_wrong_password() {
        assert!(matches!(
            classify(WalletError::InUse),
            UnlockError::Other(ref m) if m == ALREADY_OPEN
        ));
        let mut screen = UnlockScreen::new(WcSlot::default());
        let result = screen
            .unlock_future(Zeroizing::new("pw".to_string()), |_| {
                Err(WalletError::InUse)
            })
            .await;
        screen.unlocking = true;
        let (_, outcome) = screen.update(Message::UnlockResult(result));
        assert!(outcome.is_none());
        assert_eq!(screen.error.as_deref(), Some(ALREADY_OPEN));
    }

    /// Set by the probe store reads below, one flag per test (they run in parallel).
    static READ_WHILE_IN_USE: AtomicBool = AtomicBool::new(false);
    static READ_WITHOUT_A_LOCK: AtomicBool = AtomicBool::new(false);

    /// The unlock takes the instance lock before it reads the store: with another Kao process
    /// holding it, the wallet is never read and the screen says the wallet is open elsewhere.
    #[tokio::test]
    async fn an_unlock_reads_nothing_while_another_process_holds_the_lock() {
        let mut screen = UnlockScreen::new(WcSlot::default());
        screen.io = UnlockIo {
            acquire: || Err(WalletError::InUse),
            load: |_| {
                READ_WHILE_IN_USE.store(true, Ordering::SeqCst);
                Err(WalletError::NotFound)
            },
        };
        let result = screen.unlock_job(Zeroizing::new("pw".to_string())).await;
        assert!(
            !READ_WHILE_IN_USE.load(Ordering::SeqCst),
            "the wallet was read under another process's lock"
        );
        screen.unlocking = true;
        let (_, outcome) = screen.update(Message::UnlockResult(result));
        assert!(outcome.is_none());
        assert_eq!(screen.error.as_deref(), Some(ALREADY_OPEN));
    }

    /// A lock Kao can't take for any other reason (no file locks on this filesystem, say) doesn't
    /// keep the user out: the unlock reads the wallet as before the lock existed.
    #[tokio::test]
    async fn a_lock_that_cant_be_taken_still_unlocks() {
        let mut screen = UnlockScreen::new(WcSlot::default());
        screen.io = UnlockIo {
            acquire: || Err(WalletError::Io(std::io::Error::other("no locks here"))),
            load: |_| {
                READ_WITHOUT_A_LOCK.store(true, Ordering::SeqCst);
                Err(WalletError::NotFound)
            },
        };
        let result = screen.unlock_job(Zeroizing::new("pw".to_string())).await;
        assert!(
            READ_WITHOUT_A_LOCK.load(Ordering::SeqCst),
            "the wallet was read"
        );
        assert!(
            matches!(result, Err(UnlockError::Other(ref m)) if m != ALREADY_OPEN),
            "{result:?}"
        );
    }

    /// A real unlock screen takes the real lock and reads the real store.
    #[test]
    fn a_real_unlock_uses_the_real_lock_and_store() {
        let io = UnlockScreen::new(WcSlot::default()).io;
        assert!(std::ptr::fn_addr_eq(
            io.acquire,
            wallet::acquire_instance_lock as AcquireInstanceLock
        ));
        assert!(std::ptr::fn_addr_eq(
            io.load,
            wallet::load_wallet as LoadWallet
        ));
    }
}
