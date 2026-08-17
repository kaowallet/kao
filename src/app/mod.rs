use std::sync::{Arc, RwLock};

use iced::border::Radius;
use iced::widget::operation::focus as focus_widget;
use iced::widget::{Space, column, container, mouse_area, row, stack, text};
use iced::{Alignment, Background, Border, Element, Length, Padding, Subscription};
use secrecy::SecretString;
use tracing::{debug, error, warn};

use crate::net::{BalanceFetcher, NetworkClient};
use crate::portfolio::{self, PortfolioCache};
use crate::settings;
use crate::ui::connect_ledger::{
    ConnectLedgerScreen, Message as ConnectLedgerMessage, Outcome as ConnectLedgerOutcome,
};
use crate::ui::connect_trezor::{
    ConnectTrezorScreen, Message as ConnectTrezorMessage, Outcome as ConnectTrezorOutcome,
};
use crate::ui::create_password::{
    CreatePasswordScreen, Message as CreatePasswordMessage, Outcome as CreatePasswordOutcome,
};
use crate::ui::import_address::{
    ImportAddressScreen, Message as ImportAddressMessage, Outcome as ImportAddressOutcome,
};
use crate::ui::import_private_key::{
    ImportPrivateKeyScreen, Message as ImportPrivateKeyMessage, Outcome as ImportPrivateKeyOutcome,
};
use crate::ui::import_seed_phrase::{
    ImportSeedPhraseScreen, Message as ImportSeedPhraseMessage, Outcome as ImportSeedPhraseOutcome,
};
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::bold;
use crate::ui::network_setup::{
    Message as NetworkSetupMessage, NetworkSetupScreen, Outcome as NetworkSetupOutcome, WizardMode,
};
use crate::ui::safe_onboarding::{
    Message as SafeOnboardingMessage, Outcome as SafeOnboardingOutcome, SafeOnboardingScreen,
};
use crate::ui::select_hardware_wallet::{
    Message as SelectHardwareWalletMessage, Outcome as SelectHardwareWalletOutcome,
    SelectHardwareWalletScreen,
};
use crate::ui::select_hd_account::{
    Message as SelectHdAccountMessage, Outcome as SelectHdAccountOutcome, SelectHdAccountScreen,
};
use crate::ui::setup_method::{
    Message as SetupMethodMessage, Outcome as SetupMethodOutcome, SetupMethod, SetupMethodScreen,
};
use crate::ui::show_seed::{
    Message as ShowSeedMessage, Outcome as ShowSeedOutcome, ShowSeedScreen,
};
use crate::ui::unlock::{Message as UnlockMessage, Outcome as UnlockOutcome, UnlockScreen};
use crate::ui::verify_seed::{
    Message as VerifySeedMessage, Outcome as VerifySeedOutcome, VerifySeedScreen,
};
use crate::ui::wallet_dashboard::{
    Message as WalletDashboardMessage, Outcome as WalletDashboardOutcome, WalletScreen,
};
use crate::wallet::{self, AccountDescriptor, Contact, ContactsBook, KaoSigner, WalletDescriptor};
use alloy::signers::local::PrivateKeySigner;

// ── Messages ─────────────────────────────────────────────────────────────────

/// Top-level app messages.
#[derive(Debug, Clone)]
pub enum Message {
    ConnectLedger(ConnectLedgerMessage),
    ConnectTrezor(ConnectTrezorMessage),
    CreatePassword(CreatePasswordMessage),
    ImportAddress(ImportAddressMessage),
    ImportPrivateKey(ImportPrivateKeyMessage),
    ImportSeedPhrase(ImportSeedPhraseMessage),
    SafeOnboarding(SafeOnboardingMessage),
    SelectHardwareWallet(SelectHardwareWalletMessage),
    SelectHdAccount(SelectHdAccountMessage),
    NetworkSetup(NetworkSetupMessage),
    SetupMethod(SetupMethodMessage),
    ShowSeed(ShowSeedMessage),
    Unlock(UnlockMessage),
    VerifySeed(VerifySeedMessage),
    WalletDashboard(WalletDashboardMessage),
    /// Result of an off-thread `wallet::save_descriptor`. Emitted only to
    /// surface errors — successful saves are silent.
    WalletSaved(Result<(), String>),
    /// Result of the post-unlock Safe refresh batch. Carries one entry
    /// per Safe in the order they live in `wallet.safes`. Each entry
    /// is `Ok((new_descriptor, diff))` on a successful refresh, or
    /// `Err(reason)` for that Safe alone (other Safes may have
    /// succeeded). Fires at most once per unlock.
    SafesRefreshed(crate::safe::RefreshBatch),
    /// Result of an off-thread `wallet::load_contacts`. Carries the
    /// loaded vec on success; errors are logged and the in-memory book
    /// stays empty.
    ContactsLoaded(Result<Vec<Contact>, String>),
    /// Result of an off-thread `wallet::save_contacts`. Errors only —
    /// the in-memory book was already updated synchronously when the
    /// save was dispatched.
    ContactsSaved(Result<(), String>),
    WalletError(String),
    /// Auto-dismiss tick for the wallet-error toast. Carries the
    /// generation counter the timer was spawned with — a newer error
    /// supersedes by bumping the counter, which makes the older
    /// timer's dismissal a no-op when it fires.
    DismissError {
        generation: u64,
    },
}

// ── Screens ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum Screen {
    /// Ask the user to create a new wallet passphrase (first-run only).
    CreatePassword(CreatePasswordScreen),
    /// Ask the user for the existing passphrase to decrypt wallet.enc.
    Unlock(UnlockScreen),
    /// 4-step network setup wizard (RPC, API, Safe TX, Proxy). Shown once
    /// after the user creates their initial passphrase.
    NetworkSetup(NetworkSetupScreen),
    /// Choose how to set up the wallet (create new, import seed, import key,
    /// or open the hardware-wallet sub-screen).
    SetupMethod(SetupMethodScreen),
    /// Sub-screen of SetupMethod: pick which hardware wallet brand to use.
    SelectHardwareWallet(SelectHardwareWalletScreen),
    ShowSeed(ShowSeedScreen),
    VerifySeed(VerifySeedScreen),
    ImportAddress(ImportAddressScreen),
    ImportPrivateKey(ImportPrivateKeyScreen),
    ImportSeedPhrase(ImportSeedPhraseScreen),
    SafeOnboarding(SafeOnboardingScreen),
    SelectHdAccount(SelectHdAccountScreen),
    ConnectLedger(ConnectLedgerScreen),
    ConnectTrezor(ConnectTrezorScreen),
    /// Boxed because `WalletScreen` is much larger than every other variant
    /// (~700+ bytes vs tens). Without the indirection, every `mem::replace`
    /// on `App::screen` would memcpy the full payload.
    Wallet(Box<WalletScreen>),
}

impl Screen {
    /// Stable short name for the GUI state trace (see `crate::trace`).
    fn name(&self) -> &'static str {
        match self {
            Screen::CreatePassword(_) => "CreatePassword",
            Screen::Unlock(_) => "Unlock",
            Screen::NetworkSetup(_) => "NetworkSetup",
            Screen::SetupMethod(_) => "SetupMethod",
            Screen::SelectHardwareWallet(_) => "SelectHardwareWallet",
            Screen::ShowSeed(_) => "ShowSeed",
            Screen::VerifySeed(_) => "VerifySeed",
            Screen::ImportAddress(_) => "ImportAddress",
            Screen::ImportPrivateKey(_) => "ImportPrivateKey",
            Screen::ImportSeedPhrase(_) => "ImportSeedPhrase",
            Screen::SafeOnboarding(_) => "SafeOnboarding",
            Screen::SelectHdAccount(_) => "SelectHdAccount",
            Screen::ConnectLedger(_) => "ConnectLedger",
            Screen::ConnectTrezor(_) => "ConnectTrezor",
            Screen::Wallet(_) => "Wallet",
        }
    }
}

// ── App ──────────────────────────────────────────────────────────────────────

/// Why the setup screens are on screen. `FreshWallet` means we're creating
/// the first account ever for a new wallet file. `AddAccount` means the
/// wallet is already unlocked and the user asked to add another account
/// from the dashboard dropdown — completion appends to the existing list,
/// back-navigation returns to the dashboard.
#[derive(Debug)]
enum SetupContext {
    FreshWallet,
    AddAccount,
}

/// Parked SafeOnboarding state while the user is inside an add-signer
/// sub-flow (seed phrase / private key / hardware). When this is `Some`,
/// the on-screen import sub-screen is a sub-flow of SafeOnboarding rather
/// than a top-level setup step — its success outcome routes through
/// `finish_add_signer` (validates the derived address against
/// `allowed_owners` and resumes the parked SafeOnboardingScreen), and
/// its Back outcome restores the parked screen at the picker.
struct PendingAddSigner {
    allowed_owners: Vec<alloy::primitives::Address>,
    stash: Box<crate::ui::safe_onboarding::SafeOnboardingScreen>,
}

pub struct App {
    screen: Screen,
    /// Passphrase held for the duration of the unlocked session so we can
    /// re-save the wallet file when accounts are added or switched. Zeroized
    /// on Drop via `SecretString`. Cleared on lock (not yet implemented).
    passphrase: Option<SecretString>,
    /// The currently-loaded wallet descriptor. Populated after unlock or
    /// fresh-setup completion. Carries the full account list and active
    /// index across screen transitions (e.g. through hardware reconnect or
    /// the add-account setup flow).
    wallet: Option<WalletDescriptor>,
    /// The dedicated Privacy Pools mnemonic, held for the session (like
    /// `passphrase`) so the pool app can derive its account and re-show the
    /// backup phrase without a second Argon2 pass. Loaded lazily on first
    /// dashboard entry; `pp_loaded` records that the (possibly-absent) load ran.
    pp_seed: Option<SecretString>,
    pp_loaded: bool,
    /// Why the setup screens are on screen, if at all.
    setup_context: Option<SetupContext>,
    /// Active signer parked here while the user is in the add-account flow,
    /// so backing out can drop straight back into the dashboard without a
    /// hardware reconnect.
    pending_signer: Option<KaoSigner>,
    /// Shared Helios-backed RPC client. Lives for the lifetime of the
    /// process so the consensus sync only happens once. Held as a trait
    /// object so tests can substitute a deterministic mock.
    network: Arc<dyn BalanceFetcher>,
    /// Process-lifetime portfolio cache keyed by address. The dashboard
    /// reads it on construction (so account switches feel instant) and
    /// writes through every successful fetch.
    portfolio_cache: PortfolioCache,
    /// Named-address book. Loaded asynchronously after unlock; lives
    /// behind an `Arc<RwLock<…>>` so the dashboard's view function and
    /// the Settings → Contacts pane share a single canonical copy
    /// without rebuilding the dashboard on every edit. iced views are
    /// single-threaded, so the lock is always uncontested in practice;
    /// it exists to keep the type plumbing honest, not for contention.
    contacts: Arc<RwLock<ContactsBook>>,
    /// Whether the contacts book on screen is the whole book on disk.
    ///
    /// `false` from unlock until a load succeeds, and permanently after one
    /// fails. It gates saving, because the contacts table is written by
    /// **wipe-and-reinsert**: persisting an in-memory book that is missing rows
    /// deletes those rows for good.
    ///
    /// The path this closes is short and entirely silent. One row fails to
    /// decode — a missed migration rung, a row written by a newer build, disk
    /// bit-rot — and `load_contacts_from` fails the *whole* load. That error
    /// used to reach nothing but a `warn!`, so the book stayed empty, the
    /// unlock succeeded, and the Contacts pane rendered as though the user had
    /// never saved anyone. Adding or deleting one contact then wrote that empty
    /// book over every row. No error was shown at any point.
    contacts_loaded: bool,
    /// Latest wallet-error toast, or `None` when nothing is on screen.
    /// Cleared by the auto-dismiss `Task::perform` spawned when the
    /// toast lands, or replaced by a newer error mid-lifetime.
    toast: Option<ToastState>,
    /// Monotonic counter bumped on every fresh error so an older
    /// dismissal task firing late can no-op against a newer toast.
    toast_gen: u64,
    /// Set when the user triggered a hardware reconnect from the dashboard
    /// (Send on a disconnected device, or the sidebar's Reconnect button).
    /// Carries the dashboard nav the user was on so a successful reconnect
    /// restores it (and a Back drops them back to the read-only dashboard
    /// with the same tab). `None` means the current connect-screen session
    /// is not a reconnect.
    send_reconnect: Option<crate::ui::wallet_dashboard::Nav>,
    /// Whether the in-flight reconnect (see `send_reconnect`) should re-open
    /// the Send modal on success. True for a Send-triggered reconnect, false
    /// for the sidebar Reconnect button, which just restores the dashboard.
    reconnect_open_send: bool,
    /// Stack of parked SafeOnboardingScreens, innermost-last. Set by
    /// the add-signer flow: each `begin_add_signer_flow` pushes; each
    /// resume (back / finish) pops. A stack (rather than `Option`)
    /// is required because the nested-Safe sub-flow opens another
    /// SafeOnboardingScreen on top of the parent.
    pending_add_signer: Vec<PendingAddSigner>,
}

/// Single-toast state. We don't queue — a fresher error replaces the
/// previous message rather than stacking, so the user always reads the
/// most relevant signal.
#[derive(Debug)]
struct ToastState {
    msg: String,
    generation: u64,
}

/// Auto-dismiss timeout for the wallet-error toast. Long enough to read
/// a sentence comfortably, short enough that a missed glance gets a
/// second chance via the dismiss button.
const TOAST_LIFETIME_SECS: u64 = 5;

impl App {
    pub fn new() -> (Self, iced::Task<Message>) {
        crate::settings::load();
        let network: Arc<dyn BalanceFetcher> = Arc::new(NetworkClient::new());
        let portfolio_cache = portfolio::new_cache();

        let contacts = Arc::new(RwLock::new(ContactsBook::new()));
        let exists = wallet::wallet_exists();
        crate::trace::state(
            "app",
            "screen",
            "startup",
            if exists { "Unlock" } else { "CreatePassword" },
        );
        if exists {
            let app = App {
                screen: Screen::Unlock(UnlockScreen::default()),
                passphrase: None,
                wallet: None,
                pp_seed: None,
                pp_loaded: false,
                setup_context: None,
                pending_signer: None,
                network,
                portfolio_cache,
                contacts,
                // A wallet file exists, so contacts may exist too — nothing may
                // be written over them until a load has said what they are.
                // Flipped by `Message::ContactsLoaded`, which unlock dispatches.
                contacts_loaded: false,
                toast: None,
                toast_gen: 0,
                send_reconnect: None,
                reconnect_open_send: false,
                pending_add_signer: Vec::new(),
            };
            let task = focus_widget(crate::ui::unlock::PASSWORD_INPUT_ID).map(Message::Unlock);
            (app, task)
        } else {
            let app = App {
                screen: Screen::CreatePassword(CreatePasswordScreen::default()),
                passphrase: None,
                wallet: None,
                pp_seed: None,
                pp_loaded: false,
                setup_context: None,
                pending_signer: None,
                network,
                portfolio_cache,
                contacts,
                // No wallet file, so no contacts table: the empty book on
                // screen *is* the whole book on disk. A fresh wallet never
                // dispatches a contacts load (only unlock does), so starting
                // this `false` would block the first contact from ever saving.
                contacts_loaded: true,
                toast: None,
                toast_gen: 0,
                send_reconnect: None,
                reconnect_open_send: false,
                pending_add_signer: Vec::new(),
            };
            let task = focus_widget(crate::ui::create_password::PASSWORD_INPUT_ID)
                .map(Message::CreatePassword);
            (app, task)
        }
    }

    /// Persist a freshly-built account and enter the dashboard with the
    /// already-instantiated signer. Branches on `setup_context`:
    /// `FreshWallet` creates a new single-account wallet; `AddAccount`
    /// appends to the existing wallet and makes the new account active.
    /// In `AddAccount`, refuses to add an address that's already in the
    /// wallet — the user is dropped back at the dashboard with the previous
    /// active account.
    fn save_account_and_enter_dashboard(
        &mut self,
        account: AccountDescriptor,
        signer: KaoSigner,
    ) -> iced::Task<Message> {
        let Some(passphrase) = self.passphrase.as_ref() else {
            return iced::Task::perform(
                async { "missing passphrase; cannot save wallet".to_string() },
                Message::WalletError,
            );
        };

        let descriptor = match self.setup_context {
            Some(SetupContext::AddAccount) => {
                let Some(mut wallet) = self.wallet.take() else {
                    return iced::Task::perform(
                        async { "missing wallet for add-account flow".to_string() },
                        Message::WalletError,
                    );
                };
                let new_address = wallet::account_address(&account);
                if let Some(addr) = new_address
                    && wallet.contains_address(addr)
                {
                    // Duplicate — refuse the add and put the wallet back.
                    self.wallet = Some(wallet);
                    let cancel = self.cancel_add_account();
                    let warn = iced::Task::perform(
                        async { "address already in wallet; not adding a duplicate".to_string() },
                        Message::WalletError,
                    );
                    return iced::Task::batch(vec![warn, cancel]);
                }
                wallet.accounts.push(account);
                wallet.active_index = wallet.accounts.len() - 1;
                wallet
            }
            Some(SetupContext::FreshWallet) | None => WalletDescriptor::single(account),
        };

        debug!(
            accounts = descriptor.accounts.len(),
            active = descriptor.active_index,
            "save_account_and_enter_dashboard",
        );
        let save = save_descriptor_task(descriptor.clone(), passphrase.clone());
        self.setup_context = None;
        self.pending_signer = None;
        self.wallet = Some(descriptor);
        iced::Task::batch(vec![save, self.enter_dashboard(signer, None)])
    }

    /// Build the dashboard for the currently-loaded wallet and the given
    /// active signer. Caller is responsible for ensuring `self.wallet` is
    /// set and its `active_index` matches `signer`. `initial_nav` lets
    /// callers preserve the user's current tab across rebuilds (account
    /// switch); `None` lands on Home, the default for first-unlock and
    /// post-setup flows.
    fn enter_dashboard(
        &mut self,
        signer: KaoSigner,
        initial_nav: Option<crate::ui::wallet_dashboard::Nav>,
    ) -> iced::Task<Message> {
        let (accounts, safes, active_index) = match &self.wallet {
            Some(w) => (w.accounts.clone(), w.safes.clone(), w.active_index),
            None => (Vec::new(), Vec::new(), 0),
        };
        let started = std::time::Instant::now();
        let screen = WalletScreen::new(
            signer,
            accounts.clone(),
            safes,
            active_index,
            self.network.clone(),
            self.portfolio_cache.clone(),
            self.contacts.clone(),
            initial_nav,
        );
        let address = screen.address_for_log();
        let verify_task = screen
            .refresh_verification_task()
            .map(Message::WalletDashboard);
        let portfolio_task = screen.fetch_portfolio_task().map(Message::WalletDashboard);
        // History is fetched lazily on the first switch to the Activity
        // tab — no eager round-trip on dashboard entry.
        // Reverse-ENS lookup. No-ops when the active account is already
        // named, so account switches don't pile up redundant lookups.
        let ens_task = screen.fetch_ens_name_task().map(Message::WalletDashboard);
        self.screen = Screen::Wallet(Box::new(screen));
        // Load the Privacy Pools identity (once per session) and push it into
        // the fresh dashboard so the pool app can sync/prove immediately.
        self.load_pp_identity();
        debug!(
            active_index,
            addr = %address,
            built_in = ?started.elapsed(),
            "entered dashboard; verify+portfolio+ens fetch queued",
        );
        iced::Task::batch(vec![verify_task, portfolio_task, ens_task])
    }

    // ── Privacy Pools identity plumbing ──────────────────────────────────────
    // The pool seed is a wallet-global secret separate from the account keys, so
    // the App owns it (like `passphrase`) and pushes the derived account into the
    // dashboard. Load is Argon2-gated, so it runs at most once per session.

    /// Load the pool seed (once) and push the derived account into the dashboard.
    fn load_pp_identity(&mut self) {
        if !self.pp_loaded {
            if let Some(pw) = self.passphrase.as_ref() {
                match wallet::load_pp_seed(pw) {
                    Ok(seed) => self.pp_seed = seed,
                    Err(e) => {
                        warn!(error = %e, "privacy pools: loading the saved pool seed failed")
                    }
                }
            }
            self.pp_loaded = true;
        }
        let account = self.pp_seed.as_ref().and_then(|p| {
            match crate::pool::account::account_from_phrase(p) {
                Ok(a) => Some(a),
                Err(e) => {
                    error!(error = %e, "privacy pools: deriving the pool account failed");
                    None
                }
            }
        });
        if let Screen::Wallet(ws) = &mut self.screen {
            ws.set_pp_account(account);
        }
    }

    /// Persist + adopt a pool mnemonic: derive the account, push it into the
    /// dashboard, and (on create) show the masked backup.
    fn adopt_pp_seed(&mut self, phrase: SecretString, show_backup: bool) {
        let account = match crate::pool::account::account_from_phrase(&phrase) {
            Ok(a) => Some(a),
            Err(e) => {
                error!(error = %e, "privacy pools: deriving the pool account failed");
                None
            }
        };
        self.pp_seed = Some(phrase.clone());
        self.pp_loaded = true;
        if let Screen::Wallet(ws) = &mut self.screen {
            ws.set_pp_account(account);
            if show_backup {
                ws.show_pool_backup(phrase);
            }
        }
    }

    fn pool_error(&mut self, e: String) {
        if let Screen::Wallet(ws) = &mut self.screen {
            ws.set_pool_error(e);
        }
    }

    /// Generate a fresh pool identity, persist it, and show its backup phrase.
    fn pool_create_identity(&mut self) -> iced::Task<Message> {
        let Some(pw) = self.passphrase.clone() else {
            self.pool_error("wallet is locked".into());
            return iced::Task::none();
        };
        let phrase = match wallet::generate_pp_mnemonic() {
            Ok(p) => p,
            Err(e) => {
                self.pool_error(e.to_string());
                return iced::Task::none();
            }
        };
        if let Err(e) = wallet::save_pp_seed(&phrase, &pw) {
            self.pool_error(e.to_string());
            return iced::Task::none();
        }
        self.adopt_pp_seed(phrase, true);
        iced::Task::none()
    }

    /// Persist + adopt a restored pool mnemonic (already BIP39-validated).
    fn pool_restore_identity(&mut self, phrase: SecretString) -> iced::Task<Message> {
        let Some(pw) = self.passphrase.clone() else {
            self.pool_error("wallet is locked".into());
            return iced::Task::none();
        };
        if let Err(e) = wallet::save_pp_seed(&phrase, &pw) {
            self.pool_error(e.to_string());
            return iced::Task::none();
        }
        self.adopt_pp_seed(phrase, false);
        iced::Task::none()
    }

    fn pool_reveal_backup(&mut self) -> iced::Task<Message> {
        if let Some(seed) = self.pp_seed.clone()
            && let Screen::Wallet(ws) = &mut self.screen
        {
            ws.show_pool_backup(seed);
        }
        iced::Task::none()
    }

    /// Routes the active account of `self.wallet` to the right destination.
    /// Local: build the signer synchronously and enter the dashboard.
    /// Hardware/ViewOnly: enter the dashboard with a `ViewOnly` placeholder
    /// signer — the dashboard is read-only by default (balances/history/
    /// portfolio all use the saved address), so the device only needs to be
    /// reconnected at sign time. `can_sign()` is false for the placeholder,
    /// which the dashboard already uses to gate the Send button.
    fn enter_active_from_wallet(
        &mut self,
        initial_nav: Option<crate::ui::wallet_dashboard::Nav>,
    ) -> iced::Task<Message> {
        let Some(wallet) = self.wallet.as_ref() else {
            return iced::Task::perform(
                async { "no wallet loaded".to_string() },
                Message::WalletError,
            );
        };
        match wallet.active().clone() {
            AccountDescriptor::Local { key_bytes, .. } => {
                let b = key_bytes.to_b256();
                match wallet::signer_from_bytes(&b) {
                    Ok(s) => self.enter_dashboard(KaoSigner::Local(s), initial_nav),
                    Err(e) => {
                        iced::Task::perform(async move { e.to_string() }, Message::WalletError)
                    }
                }
            }
            AccountDescriptor::Ledger { address, .. }
            | AccountDescriptor::Trezor { address, .. }
            | AccountDescriptor::ViewOnly { address, .. } => {
                let addr = alloy::primitives::Address::from(address);
                self.enter_dashboard(KaoSigner::ViewOnly(addr), initial_nav)
            }
        }
    }

    /// Push the matching hardware-wallet reconnect screen because the user
    /// clicked Send on a hardware account whose device wasn't connected at
    /// unlock. `nav` is the dashboard tab to restore on success or Back.
    /// Falls back to a wallet-error toast when the active account isn't a
    /// hardware variant (shouldn't happen — the dashboard only emits
    /// `NeedsHardwareReconnect` for Ledger/Trezor).
    fn request_send_reconnect(
        &mut self,
        nav: crate::ui::wallet_dashboard::Nav,
        open_send: bool,
    ) -> iced::Task<Message> {
        let Some(wallet) = self.wallet.as_ref() else {
            return iced::Task::perform(
                async { "no wallet loaded".to_string() },
                Message::WalletError,
            );
        };
        match wallet.active().clone() {
            AccountDescriptor::Ledger { path, address, .. } => {
                let expected = alloy::primitives::Address::from(address);
                let (screen, task) =
                    ConnectLedgerScreen::new_reconnect(path, expected, self.network.clone());
                self.screen = Screen::ConnectLedger(screen);
                self.send_reconnect = Some(nav);
                self.reconnect_open_send = open_send;
                task.map(Message::ConnectLedger)
            }
            AccountDescriptor::Trezor { path, address, .. } => {
                let expected = alloy::primitives::Address::from(address);
                let (screen, task) =
                    ConnectTrezorScreen::new_reconnect(path, expected, self.network.clone());
                self.screen = Screen::ConnectTrezor(screen);
                self.send_reconnect = Some(nav);
                self.reconnect_open_send = open_send;
                task.map(Message::ConnectTrezor)
            }
            _ => iced::Task::perform(
                async { "send-reconnect: active account is not a hardware wallet".to_string() },
                Message::WalletError,
            ),
        }
    }

    /// Land the user back on the dashboard with the freshly-reconnected
    /// hardware signer and auto-open the Send modal so they don't have to
    /// click Send a second time. Falls back to entering without auto-open
    /// when this isn't a send-reconnect session.
    fn finish_send_reconnect(&mut self, signer: KaoSigner) -> iced::Task<Message> {
        let nav = self.send_reconnect.take();
        let open_send = std::mem::take(&mut self.reconnect_open_send);
        let enter = self.enter_dashboard(signer, nav);
        if open_send {
            iced::Task::batch(vec![
                enter,
                iced::Task::done(Message::WalletDashboard(
                    crate::ui::wallet_dashboard::Message::OpenSend,
                )),
            ])
        } else {
            enter
        }
    }

    /// Handle the user pressing Back on a connect screen. Sends them
    /// back to the dashboard if this was a send-triggered reconnect;
    /// otherwise falls through to the setup-mode behavior (which locks
    /// the wallet if one exists, or returns to the hardware-wallet
    /// picker if we're in initial setup).
    fn connect_back(&mut self) -> iced::Task<Message> {
        if let Some(nav) = self.send_reconnect.take() {
            self.reconnect_open_send = false;
            return self.enter_active_from_wallet(Some(nav));
        }
        self.screen = if wallet::wallet_exists() {
            self.passphrase = None;
            self.wallet = None;
            self.pp_seed = None;
            self.pp_loaded = false;
            Screen::Unlock(UnlockScreen::default())
        } else {
            Screen::SelectHardwareWallet(SelectHardwareWalletScreen::default())
        };
        iced::Task::none()
    }

    /// Drop back to the dashboard without going through setup again, using
    /// the signer the user had before they entered the add-account flow.
    /// Used when the user backs out of the SetupMethod / its sub-screens.
    /// Append `primary` plus any `siblings` to `wallet.safes`, persist
    /// the wallet, and route back to the dashboard.
    ///
    /// v1 (stage 3a) requires an existing wallet — Safes must be added
    /// in `AddAccount` context. Calling this with no loaded wallet
    /// surfaces a toast and bails (the storage layer would refuse
    /// anyway since a wallet with safes but no accounts can't be
    /// loaded back). Dedup is (address, chain_id) per `contains_safe`.
    fn save_safe_and_return_to_dashboard(
        &mut self,
        primary: crate::wallet::SafeDescriptor,
        siblings: Vec<crate::wallet::SafeDescriptor>,
    ) -> iced::Task<Message> {
        let Some(passphrase) = self.passphrase.as_ref() else {
            return iced::Task::perform(
                async { "missing passphrase; cannot save Safe".to_string() },
                Message::WalletError,
            );
        };
        let Some(mut wallet) = self.wallet.take() else {
            return iced::Task::perform(
                async { "no wallet loaded; add an account before adding a Safe".to_string() },
                Message::WalletError,
            );
        };
        let mut added = 0usize;
        let mut skipped = 0usize;
        for s in std::iter::once(primary).chain(siblings) {
            let addr = alloy::primitives::Address::from(s.address);
            if wallet.contains_safe(addr, s.chain_id) {
                skipped += 1;
            } else {
                wallet.safes.push(s);
                added += 1;
            }
        }
        debug!(added, skipped, total = wallet.safes.len(), "Safe(s) saved");
        let save = save_descriptor_task(wallet.clone(), passphrase.clone());
        self.wallet = Some(wallet);
        iced::Task::batch(vec![save, self.cancel_add_account()])
    }

    /// Process the post-unlock Safe-refresh batch. For each successful
    /// refresh: replace `wallet.safes[idx]` with the new descriptor;
    /// collect any user-facing change summaries. After the batch:
    /// - if any diff was non-empty, save the wallet once for the whole batch
    /// - if any user-facing alerts collected, surface them as a toast
    /// - push the updated safes vec into the WalletScreen so its
    ///   dropdown stops rendering stale labels
    ///
    /// Refresh errors are logged but never toasted — a single
    /// unreachable RPC shouldn't interrupt the user every unlock.
    fn handle_safes_refreshed(
        &mut self,
        results: crate::safe::RefreshBatch,
    ) -> iced::Task<Message> {
        let Some(wallet) = self.wallet.as_mut() else {
            // Unlock was undone (re-lock?) between the spawn and the
            // result landing. Drop the refresh; we'll re-spawn on
            // next unlock.
            return iced::Task::none();
        };
        let mut any_changed = false;
        let mut alerts: Vec<String> = Vec::new();
        // Pre-resolve linked-signer addresses per safe so summarize can
        // tell apart "your owner removed" from "someone else's owner
        // removed". Use the existing accounts vec.
        for (idx, result) in results {
            match result {
                Err(e) => {
                    warn!(safe_idx = idx, error = %e, "Safe refresh failed");
                }
                Ok((new_desc, diff)) => {
                    if let Some(slot) = wallet.safes.get_mut(idx) {
                        let linked_addrs: Vec<alloy::primitives::Address> = slot
                            .linked_signer_indices
                            .iter()
                            .filter_map(|i| wallet.accounts.get(*i as usize))
                            .filter_map(wallet::account_address)
                            .collect();
                        let mut summarized =
                            crate::safe::summarize_user_facing_changes(&diff, &linked_addrs);
                        if !summarized.is_empty() {
                            // Prefix each alert with the Safe's name so a
                            // user with multiple Safes can tell which one
                            // changed.
                            let safe_name = new_desc.display_name(idx);
                            for s in summarized.drain(..) {
                                alerts.push(format!("{safe_name}: {s}"));
                            }
                        }
                        if !diff.is_empty() {
                            any_changed = true;
                        }
                        *slot = new_desc;
                    } else {
                        // Safe was removed between spawn and result —
                        // discard silently.
                        warn!(safe_idx = idx, "Safe refresh result has no slot to land in");
                    }
                }
            }
        }

        // Build the follow-up tasks: push the updated safes into the
        // dashboard, persist if anything changed, surface a toast if
        // we collected alerts.
        let updated_safes = wallet.safes.clone();
        let push_to_dashboard = iced::Task::done(Message::WalletDashboard(
            crate::ui::wallet_dashboard::Message::SafesUpdated(updated_safes),
        ));
        let mut tasks = vec![push_to_dashboard];
        if any_changed && let Some(passphrase) = self.passphrase.as_ref() {
            tasks.push(save_descriptor_task(wallet.clone(), passphrase.clone()));
        }
        if !alerts.is_empty() {
            let msg = alerts.join(" · ");
            tasks.push(iced::Task::done(Message::WalletError(msg)));
        }
        iced::Task::batch(tasks)
    }

    /// Persist a per-Safe transaction-service override. Mirrors the
    /// contacts-save shape: mutate the in-memory wallet synchronously,
    /// dispatch the disk write off-thread, and push the updated list
    /// into the dashboard so its copy (and the open Settings → Safes
    /// pane) reseeds from what actually persisted.
    fn set_safe_service_url(&mut self, index: usize, url: Option<String>) -> iced::Task<Message> {
        let Some(wallet) = self.wallet.as_mut() else {
            warn!("set_safe_service_url: no wallet loaded");
            return iced::Task::none();
        };
        let Some(slot) = wallet.safes.get_mut(index) else {
            warn!(index, "set_safe_service_url: no Safe at index");
            return iced::Task::none();
        };
        slot.tx_service_url = url;
        let push = iced::Task::done(Message::WalletDashboard(
            WalletDashboardMessage::SafesUpdated(wallet.safes.clone()),
        ));
        let save = match self.passphrase.as_ref() {
            Some(pw) => save_descriptor_task(wallet.clone(), pw.clone()),
            None => {
                warn!("set_safe_service_url: no passphrase held; skipping disk write");
                iced::Task::none()
            }
        };
        iced::Task::batch(vec![push, save])
    }

    fn cancel_add_account(&mut self) -> iced::Task<Message> {
        self.setup_context = None;
        if let Some(signer) = self.pending_signer.take() {
            return self.enter_dashboard(signer, None);
        }
        // No parked signer (shouldn't happen) — fall back to a full reload
        // of the active account.
        self.enter_active_from_wallet(None)
    }

    fn begin_add_signer_flow(
        &mut self,
        method: crate::ui::safe_onboarding::SignerMethod,
        allowed_owners: Vec<alloy::primitives::Address>,
    ) -> iced::Task<Message> {
        use crate::ui::safe_onboarding::SignerMethod;
        let placeholder = Screen::SetupMethod(SetupMethodScreen::default());
        let prev = std::mem::replace(&mut self.screen, placeholder);
        let Screen::SafeOnboarding(parked) = prev else {
            warn!("begin_add_signer_flow: screen was not SafeOnboarding");
            return iced::Task::none();
        };
        self.pending_add_signer.push(PendingAddSigner {
            allowed_owners,
            stash: Box::new(parked),
        });
        match method {
            SignerMethod::SeedPhrase => {
                self.screen = Screen::ImportSeedPhrase(ImportSeedPhraseScreen::default());
                focus_widget(crate::ui::import_seed_phrase::PHRASE_INPUT_ID)
                    .map(Message::ImportSeedPhrase)
            }
            SignerMethod::PrivateKey => {
                self.screen = Screen::ImportPrivateKey(ImportPrivateKeyScreen::default());
                focus_widget(crate::ui::import_private_key::KEY_INPUT_ID)
                    .map(Message::ImportPrivateKey)
            }
            SignerMethod::Hardware => {
                self.screen = Screen::SelectHardwareWallet(SelectHardwareWalletScreen::default());
                iced::Task::none()
            }
            SignerMethod::NestedSafe => {
                let existing = self.existing_accounts_snapshot();
                let screen = SafeOnboardingScreen::new(self.network.clone(), existing);
                self.screen = Screen::SafeOnboarding(screen);
                focus_widget(crate::ui::safe_onboarding::ADDRESS_INPUT_ID)
                    .map(Message::SafeOnboarding)
            }
        }
    }

    /// Snapshot of the wallet's accounts in the shape SafeOnboarding's
    /// RoleSelection step needs. Returns an empty Vec when no wallet is
    /// loaded (fresh-setup add-Safe path).
    fn existing_accounts_snapshot(&self) -> Vec<crate::ui::safe_onboarding::ExistingAccount> {
        self.wallet
            .as_ref()
            .map(|w| {
                w.accounts
                    .iter()
                    .enumerate()
                    .filter_map(|(idx, acc)| {
                        wallet::account_address(acc).map(|addr| {
                            crate::ui::safe_onboarding::ExistingAccount {
                                account_idx: idx as u32,
                                address: addr,
                                label: acc.display_name(idx),
                            }
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// If an add-signer sub-flow is active, restore the parked
    /// SafeOnboardingScreen and return its task. Otherwise invoke
    /// `fallback` for the normal Back behavior. Used by every import
    /// sub-screen's Back arm.
    fn back_or_restore_safe_onboarding(
        &mut self,
        fallback: impl FnOnce(&mut Self) -> iced::Task<Message>,
    ) -> iced::Task<Message> {
        if let Some(pending) = self.pending_add_signer.pop() {
            self.screen = Screen::SafeOnboarding(*pending.stash);
            return iced::Task::none();
        }
        fallback(self)
    }

    /// Route a freshly-imported `Local` account: into the add-signer
    /// flow if one is parked, otherwise straight to the dashboard.
    /// Centralizes the same conditional that every import handler
    /// would otherwise inline.
    fn route_imported_local(
        &mut self,
        account: AccountDescriptor,
        signer: PrivateKeySigner,
    ) -> iced::Task<Message> {
        if !self.pending_add_signer.is_empty() {
            let addr = wallet::signer_address(&signer);
            self.finish_add_signer(account, addr)
        } else {
            self.save_account_and_enter_dashboard(account, KaoSigner::Local(signer))
        }
    }

    /// Route a freshly-imported hardware account: into the add-signer
    /// flow if one is parked, otherwise straight to the dashboard.
    /// Surfaces an explicit error if the address can't be derived (a
    /// `ViewOnly`/programming-error case — `Ledger`/`Trezor` carry
    /// their address inline).
    fn route_imported_hardware(
        &mut self,
        account: AccountDescriptor,
        signer: KaoSigner,
    ) -> iced::Task<Message> {
        if self.pending_add_signer.is_empty() {
            return self.save_account_and_enter_dashboard(account, signer);
        }
        match wallet::account_address(&account) {
            Some(addr) => self.finish_add_signer(account, addr),
            None => {
                self.pending_add_signer.pop();
                iced::Task::done(Message::WalletError(
                    "add-signer: imported account has no address".to_string(),
                ))
            }
        }
    }

    /// Resume the parent SafeOnboardingScreen after an inner one
    /// finished. Validates the inner's primary address against the
    /// parent's `allowed_owners`, appends inner safe descriptors
    /// (primary + any siblings the user selected) to the wallet,
    /// persists, and informs the parent screen of the new link.
    /// On rejection, the inner Safe is NOT persisted and the parent
    /// is restored with an error.
    fn finish_add_nested_safe(
        &mut self,
        primary: crate::wallet::SafeDescriptor,
        siblings: Vec<crate::wallet::SafeDescriptor>,
    ) -> iced::Task<Message> {
        let Some(pending) = self.pending_add_signer.pop() else {
            warn!("finish_add_nested_safe: no pending state");
            return iced::Task::none();
        };
        let PendingAddSigner {
            allowed_owners,
            mut stash,
        } = pending;
        let primary_addr = alloy::primitives::Address::from(primary.address);
        if !allowed_owners.contains(&primary_addr) {
            stash.apply_signer_import_error(format!(
                "Nested Safe {primary_addr} is not an owner of this Safe."
            ));
            self.screen = Screen::SafeOnboarding(*stash);
            return iced::Task::none();
        }

        let Some(mut wallet) = self.wallet.take() else {
            warn!("finish_add_nested_safe: no wallet loaded");
            stash.apply_signer_import_error("No wallet loaded — try again.".to_string());
            self.screen = Screen::SafeOnboarding(*stash);
            return iced::Task::none();
        };
        let mut added = 0usize;
        for s in std::iter::once(primary).chain(siblings) {
            let addr = alloy::primitives::Address::from(s.address);
            if !wallet.contains_safe(addr, s.chain_id) {
                wallet.safes.push(s);
                added += 1;
            }
        }
        debug!(added, "nested Safe(s) saved");
        let save = match self.passphrase.as_ref() {
            Some(passphrase) => save_descriptor_task(wallet.clone(), passphrase.clone()),
            None => {
                warn!("finish_add_nested_safe: no passphrase held; skipping save");
                iced::Task::none()
            }
        };
        self.wallet = Some(wallet);

        stash.apply_added_nested_safe(primary_addr);
        self.screen = Screen::SafeOnboarding(*stash);
        save
    }

    fn finish_add_signer(
        &mut self,
        account: AccountDescriptor,
        address: alloy::primitives::Address,
    ) -> iced::Task<Message> {
        let Some(pending) = self.pending_add_signer.pop() else {
            warn!("finish_add_signer: no pending add-signer state");
            return iced::Task::none();
        };
        let PendingAddSigner {
            allowed_owners,
            mut stash,
        } = pending;

        if !allowed_owners.contains(&address) {
            stash.apply_signer_import_error(format!(
                "Imported address {address} is not an owner of this Safe."
            ));
            self.screen = Screen::SafeOnboarding(*stash);
            return iced::Task::none();
        }

        // A hardware wallet can re-derive the same address via a
        // different HD path, so the screen's owner-set filter isn't
        // a tight enough duplicate guard on its own.
        let Some(mut wallet) = self.wallet.take() else {
            warn!("finish_add_signer: no wallet loaded");
            stash.apply_signer_import_error("No wallet loaded — try again.".to_string());
            self.screen = Screen::SafeOnboarding(*stash);
            return iced::Task::none();
        };
        if wallet.contains_address(address) {
            self.wallet = Some(wallet);
            stash
                .apply_signer_import_error(format!("Address {address} is already in your wallet."));
            self.screen = Screen::SafeOnboarding(*stash);
            return iced::Task::none();
        }
        let new_idx = wallet.accounts.len() as u32;
        let label = account.display_name(new_idx as usize);
        wallet.accounts.push(account);

        // Signer addition is permanent regardless of whether the user
        // later confirms the Safe — they may have already keyed in a
        // mnemonic they don't want to retype.
        let save = match self.passphrase.as_ref() {
            Some(passphrase) => save_descriptor_task(wallet.clone(), passphrase.clone()),
            None => {
                warn!("finish_add_signer: no passphrase held; skipping save");
                iced::Task::none()
            }
        };
        self.wallet = Some(wallet);

        stash.apply_added_signer(crate::ui::safe_onboarding::ExistingAccount {
            account_idx: new_idx,
            address,
            label,
        });
        self.screen = Screen::SafeOnboarding(*stash);
        save
    }

    /// Persist `active_index = idx` and rebuild the dashboard for that
    /// account. Local accounts swap in synchronously; hardware accounts
    /// transition to the matching reconnect screen.
    ///
    /// The disk write runs off-thread because the Argon2id KDF takes a few
    /// hundred ms per save and would otherwise freeze the UI on every account
    /// switch. The in-memory `active_index` is updated immediately, so the
    /// dashboard rebuild doesn't have to wait for the save to complete.
    fn switch_account(&mut self, idx: usize) -> iced::Task<Message> {
        let Some(wallet) = self.wallet.as_mut() else {
            debug!(idx, "switch: no wallet loaded; ignoring");
            return iced::Task::none();
        };
        if idx >= wallet.accounts.len() {
            warn!(
                idx,
                accounts = wallet.accounts.len(),
                "switch: index out of range; ignoring",
            );
            return iced::Task::none();
        }
        let prev = wallet.active_index;
        wallet.active_index = idx;
        debug!(prev, next = idx, "switch account");
        let switch_started = std::time::Instant::now();
        let save = match self.passphrase.as_ref() {
            Some(passphrase) => save_descriptor_task(wallet.clone(), passphrase.clone()),
            None => {
                warn!("switch: no passphrase held; skipping save");
                iced::Task::none()
            }
        };
        self.pending_signer = None;
        // Preserve the active dashboard tab across the rebuild — switching
        // accounts while reading the Activity feed shouldn't yank the
        // user back to Home.
        let preserved_nav = if let Screen::Wallet(screen) = &self.screen {
            Some(screen.current_nav())
        } else {
            None
        };
        let enter = self.enter_active_from_wallet(preserved_nav);
        debug!(
            scheduled_in = ?switch_started.elapsed(),
            "switch: dashboard handoff scheduled (argon2 save runs in background)",
        );
        iced::Task::batch(vec![save, enter])
    }

    /// Move the user from the dashboard into the setup flow to add another
    /// account. The signer of the currently-active account is parked so a
    /// cancel can return to the dashboard cheaply.
    fn begin_add_account(&mut self) -> iced::Task<Message> {
        // Refuse to leave the dashboard while ANY signing op is in flight (a
        // Send/Safe broadcast OR a CoW / name-service write): the signer has been
        // moved into the in-flight task, so `into_signer()` would return a
        // `KaoSigner::ViewOnly` placeholder and the user would silently lose their
        // real signer when that task finished and tried to put it back.
        if let Screen::Wallet(screen) = &self.screen
            && screen.is_signing_busy()
        {
            warn!("add-account refused: signing op in flight");
            return iced::Task::perform(
                async {
                    "transaction in flight; finish or cancel before adding an account".to_string()
                },
                Message::WalletError,
            );
        }
        // Take the signer out of the dashboard screen and stash it.
        let placeholder = Screen::SetupMethod(SetupMethodScreen::default());
        let prev = std::mem::replace(&mut self.screen, placeholder);
        if let Screen::Wallet(screen) = prev {
            self.pending_signer = Some(screen.into_signer());
        }
        self.setup_context = Some(SetupContext::AddAccount);
        iced::Task::none()
    }

    /// Apply a name change to the currently-active account in the loaded
    /// wallet and persist the descriptor. The dashboard has already mirrored
    /// the change into its own `accounts` clone for snappy UI; this is the
    /// source-of-truth update + disk write.
    fn rename_active_account(&mut self, name: Option<String>) -> iced::Task<Message> {
        let Some(wallet) = self.wallet.as_mut() else {
            warn!("rename: no wallet loaded; ignoring");
            return iced::Task::none();
        };
        let idx = wallet.active_index;
        let Some(acc) = wallet.accounts.get_mut(idx) else {
            warn!(idx, "rename: active index out of range; ignoring");
            return iced::Task::none();
        };
        acc.set_name(name);
        match self.passphrase.as_ref() {
            Some(passphrase) => save_descriptor_task(wallet.clone(), passphrase.clone()),
            None => {
                warn!("rename: no passphrase held; skipping save");
                iced::Task::none()
            }
        }
    }

    pub fn update(&mut self, message: Message) -> iced::Task<Message> {
        crate::trace_msg!("app", &message);
        // Diff the coarse app state across the dispatch so every transition
        // is logged no matter which arm (or helper) performed it.
        let screen_before = self.screen.name();
        let toast_before = self.toast.is_some();
        let active_before = self.wallet.as_ref().map(|w| w.active_index);
        let accounts_before = self.wallet.as_ref().map(|w| w.accounts.len());

        let task = self.update_inner(message);

        let screen_after = self.screen.name();
        if screen_before != screen_after {
            crate::trace::state("app", "screen", screen_before, screen_after);
        }
        if toast_before != self.toast.is_some() {
            let s = |shown: bool| if shown { "shown" } else { "none" };
            crate::trace::state("app", "toast", s(toast_before), s(self.toast.is_some()));
        }
        let fmt_opt = |v: Option<usize>| v.map_or("none".to_string(), |i| i.to_string());
        let active_after = self.wallet.as_ref().map(|w| w.active_index);
        if active_before != active_after {
            crate::trace::state(
                "app",
                "active_account",
                fmt_opt(active_before),
                fmt_opt(active_after),
            );
        }
        let accounts_after = self.wallet.as_ref().map(|w| w.accounts.len());
        if accounts_before != accounts_after {
            crate::trace::state(
                "app",
                "accounts",
                fmt_opt(accounts_before),
                fmt_opt(accounts_after),
            );
        }
        task
    }

    fn update_inner(&mut self, message: Message) -> iced::Task<Message> {
        match message {
            // ── CreatePassword ──────────────────────────────────────
            Message::CreatePassword(msg) => {
                let Screen::CreatePassword(screen) = &mut self.screen else {
                    return iced::Task::none();
                };
                let (cmd, outcome) = screen.update(msg);
                if let Some(CreatePasswordOutcome::Created(passphrase)) = outcome {
                    self.passphrase = Some(passphrase);
                    self.setup_context = Some(SetupContext::FreshWallet);
                    self.screen =
                        Screen::NetworkSetup(NetworkSetupScreen::new(WizardMode::Onboarding));
                    return iced::Task::none();
                }
                cmd.map(Message::CreatePassword)
            }

            // ── Unlock ──────────────────────────────────────────────
            Message::Unlock(msg) => {
                let Screen::Unlock(screen) = &mut self.screen else {
                    return iced::Task::none();
                };
                let (cmd, outcome) = screen.update(msg);
                if let Some(UnlockOutcome::Unlocked {
                    passphrase,
                    descriptor,
                }) = outcome
                {
                    // Hold the passphrase for the unlocked session so we
                    // can re-save the wallet file on add/switch account.
                    // Clone the passphrase into the session slot and move the
                    // original into the contacts task — avoids re-fetching from
                    // `self.passphrase` with an `.expect()` that would panic the
                    // whole app if the invariant ever changed under refactoring.
                    self.passphrase = Some(passphrase.clone());
                    self.wallet = Some(descriptor);
                    let load_contacts = load_contacts_task(passphrase);
                    // Refresh-on-app-open: kick off a parallel
                    // re-inspect for every Safe so the dashboard
                    // renders against verified-fresh owner sets and
                    // any chain-side changes since last open get
                    // surfaced (owner removals affecting the user,
                    // unknown modules added, etc.). Skipped when the
                    // wallet has zero Safes — no work, no toast risk.
                    let refresh_safes = match self.wallet.as_ref() {
                        Some(w) if !w.safes.is_empty() => {
                            let net = self.network.clone();
                            let safes = w.safes.clone();
                            iced::Task::perform(
                                crate::safe::refresh_all_safes(net, safes),
                                Message::SafesRefreshed,
                            )
                        }
                        _ => iced::Task::none(),
                    };
                    return iced::Task::batch(vec![
                        self.enter_active_from_wallet(None),
                        load_contacts,
                        refresh_safes,
                    ]);
                }
                cmd.map(Message::Unlock)
            }

            // ── NetworkSetup ───────────────────────────────────────
            Message::NetworkSetup(msg) => {
                let Screen::NetworkSetup(screen) = &mut self.screen else {
                    return iced::Task::none();
                };
                let (cmd, outcome) = screen.update(msg);
                match outcome {
                    Some(NetworkSetupOutcome::Completed) => {
                        self.screen = Screen::SetupMethod(SetupMethodScreen::default());
                        iced::Task::none()
                    }
                    Some(NetworkSetupOutcome::Back) => {
                        self.passphrase = None;
                        self.pp_seed = None;
                        self.pp_loaded = false;
                        self.setup_context = None;
                        self.screen = Screen::CreatePassword(CreatePasswordScreen::default());
                        focus_widget(crate::ui::create_password::PASSWORD_INPUT_ID)
                            .map(Message::CreatePassword)
                    }
                    Some(NetworkSetupOutcome::Closed) => {
                        // Settings mode — shouldn't happen at this level.
                        iced::Task::none()
                    }
                    None => cmd.map(Message::NetworkSetup),
                }
            }

            // ── SetupMethod ─────────────────────────────────────────
            Message::SetupMethod(msg) => {
                let Screen::SetupMethod(screen) = &mut self.screen else {
                    return iced::Task::none();
                };
                let (cmd, outcome) = screen.update(msg);
                match outcome {
                    Some(SetupMethodOutcome::Selected(method)) => match method {
                        SetupMethod::CreateNewWallet => match ShowSeedScreen::generate() {
                            Ok(show_screen) => {
                                self.screen = Screen::ShowSeed(show_screen);
                                iced::Task::none()
                            }
                            Err(e) => iced::Task::perform(
                                async move { e.to_string() },
                                Message::WalletError,
                            ),
                        },
                        SetupMethod::ImportFromSeed => {
                            self.screen =
                                Screen::ImportSeedPhrase(ImportSeedPhraseScreen::default());
                            focus_widget(crate::ui::import_seed_phrase::PHRASE_INPUT_ID)
                                .map(Message::ImportSeedPhrase)
                        }
                        SetupMethod::ImportFromPrivateKey => {
                            self.screen =
                                Screen::ImportPrivateKey(ImportPrivateKeyScreen::default());
                            focus_widget(crate::ui::import_private_key::KEY_INPUT_ID)
                                .map(Message::ImportPrivateKey)
                        }
                        SetupMethod::ConnectHardwareWallet => {
                            self.screen =
                                Screen::SelectHardwareWallet(SelectHardwareWalletScreen::default());
                            iced::Task::none()
                        }
                        SetupMethod::WatchAddress => {
                            self.screen = Screen::ImportAddress(ImportAddressScreen::new(
                                self.network.clone(),
                            ));
                            focus_widget(crate::ui::import_address::ADDRESS_INPUT_ID)
                                .map(Message::ImportAddress)
                        }
                        SetupMethod::AddSafe => {
                            // Wallet is `None` during fresh setup — the
                            // empty snapshot means RoleSelection shows
                            // "no matched owners" and the user proceeds
                            // watch-only or backs out.
                            let existing = self.existing_accounts_snapshot();
                            self.screen = Screen::SafeOnboarding(SafeOnboardingScreen::new(
                                self.network.clone(),
                                existing,
                            ));
                            focus_widget(crate::ui::safe_onboarding::ADDRESS_INPUT_ID)
                                .map(Message::SafeOnboarding)
                        }
                    },
                    Some(SetupMethodOutcome::Cancel) => {
                        if matches!(self.setup_context, Some(SetupContext::AddAccount)) {
                            self.cancel_add_account()
                        } else {
                            // Fresh setup: step back to the network wizard so
                            // users can revise RPC/API/proxy choices.
                            self.screen = Screen::NetworkSetup(NetworkSetupScreen::new(
                                WizardMode::Onboarding,
                            ));
                            iced::Task::none()
                        }
                    }
                    None => cmd.map(Message::SetupMethod),
                }
            }

            // ── SelectHardwareWallet ────────────────────────────────
            Message::SelectHardwareWallet(msg) => {
                let Screen::SelectHardwareWallet(screen) = &mut self.screen else {
                    return iced::Task::none();
                };
                let (cmd, outcome) = screen.update(msg);
                match outcome {
                    Some(SelectHardwareWalletOutcome::Ledger) => {
                        let (screen, task) = ConnectLedgerScreen::new_setup(self.network.clone());
                        self.screen = Screen::ConnectLedger(screen);
                        task.map(Message::ConnectLedger)
                    }
                    Some(SelectHardwareWalletOutcome::Trezor) => {
                        let (screen, task) = ConnectTrezorScreen::new_setup(self.network.clone());
                        self.screen = Screen::ConnectTrezor(screen);
                        task.map(Message::ConnectTrezor)
                    }
                    Some(SelectHardwareWalletOutcome::Back) => self
                        .back_or_restore_safe_onboarding(|s| {
                            s.screen = Screen::SetupMethod(SetupMethodScreen::default());
                            iced::Task::none()
                        }),
                    None => cmd.map(Message::SelectHardwareWallet),
                }
            }

            // ── ImportSeedPhrase ────────────────────────────────────
            Message::ImportSeedPhrase(msg) => {
                let Screen::ImportSeedPhrase(screen) = &mut self.screen else {
                    return iced::Task::none();
                };
                let (cmd, outcome) = screen.update(msg);
                match outcome {
                    Some(ImportSeedPhraseOutcome::Confirmed { phrase }) => {
                        let skip = self
                            .wallet
                            .as_ref()
                            .map(|w| w.addresses())
                            .unwrap_or_default();
                        let (screen, task) =
                            SelectHdAccountScreen::new(phrase, skip, self.network.clone());
                        self.screen = Screen::SelectHdAccount(screen);
                        task.map(Message::SelectHdAccount)
                    }
                    Some(ImportSeedPhraseOutcome::Back) => {
                        self.back_or_restore_safe_onboarding(|s| {
                            s.screen = Screen::SetupMethod(SetupMethodScreen::default());
                            iced::Task::none()
                        })
                    }
                    None => cmd.map(Message::ImportSeedPhrase),
                }
            }

            // ── SelectHdAccount ─────────────────────────────────────
            Message::SelectHdAccount(msg) => {
                let Screen::SelectHdAccount(screen) = &mut self.screen else {
                    return iced::Task::none();
                };
                let (cmd, outcome) = screen.update(msg);
                match outcome {
                    Some(SelectHdAccountOutcome::Selected { key_bytes }) => {
                        let b256 = alloy::primitives::B256::from_slice(key_bytes.as_slice());
                        match wallet::signer_from_bytes(&b256) {
                            Ok(signer) => {
                                let account = wallet::local_account(&signer);
                                self.route_imported_local(account, signer)
                            }
                            Err(e) => iced::Task::perform(
                                async move { e.to_string() },
                                Message::WalletError,
                            ),
                        }
                    }
                    Some(SelectHdAccountOutcome::Back { phrase }) => {
                        self.screen =
                            Screen::ImportSeedPhrase(ImportSeedPhraseScreen::with_phrase(phrase));
                        focus_widget(crate::ui::import_seed_phrase::PHRASE_INPUT_ID)
                            .map(Message::ImportSeedPhrase)
                    }
                    None => cmd.map(Message::SelectHdAccount),
                }
            }

            // ── SafeOnboarding ──────────────────────────────────────
            Message::SafeOnboarding(msg) => {
                let Screen::SafeOnboarding(screen) = &mut self.screen else {
                    return iced::Task::none();
                };
                let (cmd, outcome) = screen.update(msg);
                match outcome {
                    Some(SafeOnboardingOutcome::Done { primary, siblings }) => {
                        if !self.pending_add_signer.is_empty() {
                            self.finish_add_nested_safe(*primary, siblings)
                        } else {
                            self.save_safe_and_return_to_dashboard(*primary, siblings)
                        }
                    }
                    Some(SafeOnboardingOutcome::Back) => {
                        // Nested: pop the parent and resume it. Top-level
                        // back falls through to the usual fresh/add-account
                        // split.
                        self.back_or_restore_safe_onboarding(|s| {
                            if matches!(s.setup_context, Some(SetupContext::AddAccount)) {
                                s.cancel_add_account()
                            } else {
                                s.screen = Screen::SetupMethod(SetupMethodScreen::default());
                                iced::Task::none()
                            }
                        })
                    }
                    Some(SafeOnboardingOutcome::RequestAddSigner {
                        method,
                        allowed_owners,
                    }) => self.begin_add_signer_flow(method, allowed_owners),
                    None => cmd.map(Message::SafeOnboarding),
                }
            }

            // ── ImportAddress (view-only) ───────────────────────────
            Message::ImportAddress(msg) => {
                let Screen::ImportAddress(screen) = &mut self.screen else {
                    return iced::Task::none();
                };
                let (cmd, outcome) = screen.update(msg);
                match outcome {
                    Some(ImportAddressOutcome::Imported { address, ens_name }) => {
                        let mut account = wallet::view_only_account(address);
                        // Use the ENS name (already forward-verified at
                        // resolve time — this came from a forward lookup, so
                        // there's no impersonation risk) as the default
                        // account name.
                        if let Some(name) = ens_name {
                            account.set_name(Some(name));
                        }
                        self.save_account_and_enter_dashboard(account, KaoSigner::ViewOnly(address))
                    }
                    Some(ImportAddressOutcome::Back) => {
                        self.screen = Screen::SetupMethod(SetupMethodScreen::default());
                        iced::Task::none()
                    }
                    None => cmd.map(Message::ImportAddress),
                }
            }

            // ── ImportPrivateKey ────────────────────────────────────
            Message::ImportPrivateKey(msg) => {
                let Screen::ImportPrivateKey(screen) = &mut self.screen else {
                    return iced::Task::none();
                };
                let (cmd, outcome) = screen.update(msg);
                match outcome {
                    Some(ImportPrivateKeyOutcome::Imported { key_bytes }) => {
                        let b256 = alloy::primitives::B256::from_slice(key_bytes.as_slice());
                        match wallet::signer_from_bytes(&b256) {
                            Ok(signer) => {
                                let account = wallet::local_account(&signer);
                                self.route_imported_local(account, signer)
                            }
                            Err(e) => iced::Task::perform(
                                async move { e.to_string() },
                                Message::WalletError,
                            ),
                        }
                    }
                    Some(ImportPrivateKeyOutcome::Back) => {
                        self.back_or_restore_safe_onboarding(|s| {
                            s.screen = Screen::SetupMethod(SetupMethodScreen::default());
                            iced::Task::none()
                        })
                    }
                    None => cmd.map(Message::ImportPrivateKey),
                }
            }

            // ── ShowSeed ────────────────────────────────────────────
            Message::ShowSeed(msg) => {
                let Screen::ShowSeed(screen) = &mut self.screen else {
                    return iced::Task::none();
                };
                let (cmd, outcome) = screen.update(msg);
                match outcome {
                    Some(ShowSeedOutcome::Continue) => {
                        let current = std::mem::replace(
                            &mut self.screen,
                            Screen::SetupMethod(SetupMethodScreen::default()),
                        );
                        if let Screen::ShowSeed(show_screen) = current {
                            let (phrase, key_bytes, address) = show_screen.into_wallet_data();
                            let verify_screen = VerifySeedScreen::new(phrase, key_bytes, address);
                            let focus_cmd =
                                verify_screen.focus_initial_task().map(Message::VerifySeed);
                            self.screen = Screen::VerifySeed(verify_screen);
                            return iced::Task::batch(vec![cmd.map(Message::ShowSeed), focus_cmd]);
                        }
                        iced::Task::none()
                    }
                    Some(ShowSeedOutcome::Back) => {
                        self.screen = Screen::SetupMethod(SetupMethodScreen::default());
                        iced::Task::none()
                    }
                    None => cmd.map(Message::ShowSeed),
                }
            }

            // ── VerifySeed ──────────────────────────────────────────
            Message::VerifySeed(msg) => {
                let Screen::VerifySeed(screen) = &mut self.screen else {
                    return iced::Task::none();
                };
                let (cmd, outcome) = screen.update(msg);
                match outcome {
                    Some(VerifySeedOutcome::Verified) => {
                        let current = std::mem::replace(
                            &mut self.screen,
                            Screen::SetupMethod(SetupMethodScreen::default()),
                        );
                        if let Screen::VerifySeed(verify_screen) = current {
                            let (key_bytes, _address) = verify_screen.into_wallet_data();
                            let b256 = alloy::primitives::B256::from_slice(key_bytes.as_slice());
                            match wallet::signer_from_bytes(&b256) {
                                Ok(signer) => {
                                    let account = wallet::local_account(&signer);
                                    self.save_account_and_enter_dashboard(
                                        account,
                                        KaoSigner::Local(signer),
                                    )
                                }
                                Err(e) => iced::Task::perform(
                                    async move { e.to_string() },
                                    Message::WalletError,
                                ),
                            }
                        } else {
                            iced::Task::none()
                        }
                    }
                    Some(VerifySeedOutcome::Back {
                        phrase,
                        key_bytes,
                        address,
                    }) => {
                        self.screen = Screen::ShowSeed(ShowSeedScreen::from_existing(
                            phrase, key_bytes, address,
                        ));
                        iced::Task::none()
                    }
                    None => cmd.map(Message::VerifySeed),
                }
            }

            // ── ConnectLedger ───────────────────────────────────────
            Message::ConnectLedger(msg) => {
                let Screen::ConnectLedger(screen) = &mut self.screen else {
                    return iced::Task::none();
                };
                let (cmd, outcome) = screen.update(msg);
                match outcome {
                    Some(ConnectLedgerOutcome::SetupComplete { account, signer }) => {
                        self.route_imported_hardware(account, signer)
                    }
                    Some(ConnectLedgerOutcome::ReconnectComplete { signer }) => {
                        self.finish_send_reconnect(signer)
                    }
                    Some(ConnectLedgerOutcome::Back) => {
                        self.back_or_restore_safe_onboarding(Self::connect_back)
                    }
                    None => cmd.map(Message::ConnectLedger),
                }
            }

            // ── ConnectTrezor ───────────────────────────────────────
            Message::ConnectTrezor(msg) => {
                let Screen::ConnectTrezor(screen) = &mut self.screen else {
                    return iced::Task::none();
                };
                let (cmd, outcome) = screen.update(msg);
                match outcome {
                    Some(ConnectTrezorOutcome::SetupComplete { account, signer }) => {
                        self.route_imported_hardware(account, signer)
                    }
                    Some(ConnectTrezorOutcome::ReconnectComplete { signer }) => {
                        self.finish_send_reconnect(signer)
                    }
                    Some(ConnectTrezorOutcome::Back) => {
                        self.back_or_restore_safe_onboarding(Self::connect_back)
                    }
                    None => cmd.map(Message::ConnectTrezor),
                }
            }

            // ── Wallet ──────────────────────────────────────────────
            Message::WalletDashboard(msg) => {
                let Screen::Wallet(screen) = &mut self.screen else {
                    return iced::Task::none();
                };
                let (cmd, outcome) = screen.update(msg);
                match outcome {
                    Some(WalletDashboardOutcome::Switch(idx)) => self.switch_account(idx),
                    Some(WalletDashboardOutcome::Add) => self.begin_add_account(),
                    Some(WalletDashboardOutcome::RenameActive(name)) => {
                        let save = self.rename_active_account(name);
                        iced::Task::batch(vec![cmd.map(Message::WalletDashboard), save])
                    }
                    Some(WalletDashboardOutcome::NeedsHardwareReconnect { open_send }) => {
                        let nav = screen.current_nav();
                        self.request_send_reconnect(nav, open_send)
                    }
                    Some(WalletDashboardOutcome::SaveContacts(new_contacts)) => {
                        // Refuse to write a book that isn't known to be the
                        // whole book. The table is persisted by wipe-and-
                        // reinsert, so saving a partial list is not a partial
                        // save — it deletes every row the list is missing.
                        if !self.contacts_loaded {
                            error!("contacts save refused — the book on screen is incomplete");
                            return iced::Task::batch(vec![
                                cmd.map(Message::WalletDashboard),
                                iced::Task::done(Message::WalletError(
                                    "Kao couldn't read your contacts this session, so it won't \
                                     save over them. Your saved contacts are untouched on disk — \
                                     restart to try loading them again."
                                        .to_string(),
                                )),
                            ]);
                        }
                        // Update the in-memory book synchronously so the
                        // dashboard's view picks up the change on the very
                        // next redraw, then dispatch the disk write off
                        // the UI thread (Argon2 verifies the password
                        // before writing — same ~250ms cost as save_descriptor).
                        if let Ok(mut book) = self.contacts.write() {
                            *book = ContactsBook::from_vec(new_contacts.clone());
                        } else {
                            warn!("contacts lock poisoned; skipping in-memory update");
                        }
                        let save = match self.passphrase.as_ref() {
                            Some(pw) => save_contacts_task(new_contacts, pw.clone()),
                            None => {
                                warn!("save contacts: no passphrase held; skipping disk write");
                                iced::Task::none()
                            }
                        };
                        iced::Task::batch(vec![cmd.map(Message::WalletDashboard), save])
                    }
                    Some(WalletDashboardOutcome::SetSafeServiceUrl { index, url }) => {
                        let save = self.set_safe_service_url(index, url);
                        iced::Task::batch(vec![cmd.map(Message::WalletDashboard), save])
                    }
                    Some(WalletDashboardOutcome::PoolCreateIdentity) => {
                        let t = self.pool_create_identity();
                        iced::Task::batch(vec![cmd.map(Message::WalletDashboard), t])
                    }
                    Some(WalletDashboardOutcome::PoolRestoreIdentity(phrase)) => {
                        let t = self.pool_restore_identity(phrase);
                        iced::Task::batch(vec![cmd.map(Message::WalletDashboard), t])
                    }
                    Some(WalletDashboardOutcome::PoolRevealBackup) => {
                        let t = self.pool_reveal_backup();
                        iced::Task::batch(vec![cmd.map(Message::WalletDashboard), t])
                    }
                    None => cmd.map(Message::WalletDashboard),
                }
            }

            // ── Background wallet save ──────────────────────────────
            Message::WalletSaved(result) => {
                if let Err(e) = result {
                    error!(error = %e, "wallet save error");
                }
                iced::Task::none()
            }

            // ── Post-unlock Safe refresh batch ──────────────────────
            Message::SafesRefreshed(results) => self.handle_safes_refreshed(results),

            // ── Contacts background load/save ───────────────────────
            Message::ContactsLoaded(result) => {
                match result {
                    Ok(vec) => {
                        if let Ok(mut book) = self.contacts.write() {
                            *book = ContactsBook::from_vec(vec);
                            self.contacts_loaded = true;
                        } else {
                            warn!("contacts lock poisoned; skipping load");
                        }
                    }
                    // Loud, and latching. The book stays empty either way, but
                    // an empty book that is *known* to be incomplete must not
                    // be written back over the rows it is missing.
                    Err(e) => {
                        error!(error = %e, "contacts load failed — saving is disabled this session");
                        return iced::Task::done(Message::WalletError(format!(
                            "Couldn't read your contacts ({e}). They're still on disk — Kao won't \
                             save over them this session. Restart to try again."
                        )));
                    }
                }
                iced::Task::none()
            }
            Message::ContactsSaved(result) => {
                if let Err(e) = result {
                    error!(error = %e, "contacts save error");
                }
                iced::Task::none()
            }

            // ── Error handling ──────────────────────────────────────
            Message::WalletError(e) => {
                error!(error = %e, "wallet error");
                self.toast_gen = self.toast_gen.wrapping_add(1);
                let generation = self.toast_gen;
                self.toast = Some(ToastState { msg: e, generation });
                // Schedule the auto-dismiss tick. Generation-tagged so a
                // late firing can't clear a newer toast: replacement
                // bumps the counter, and the stale `DismissError`
                // arrives with `g != self.toast_gen` and no-ops.
                iced::Task::perform(
                    async move {
                        tokio::time::sleep(std::time::Duration::from_secs(TOAST_LIFETIME_SECS))
                            .await;
                        generation
                    },
                    |generation| Message::DismissError { generation },
                )
            }
            Message::DismissError { generation } => {
                if self
                    .toast
                    .as_ref()
                    .is_some_and(|s| s.generation == generation)
                {
                    self.toast = None;
                }
                iced::Task::none()
            }
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let screen: Element<'_, Message> = match &self.screen {
            Screen::CreatePassword(screen) => screen.view().map(Message::CreatePassword),
            Screen::Unlock(screen) => screen.view().map(Message::Unlock),
            Screen::NetworkSetup(screen) => screen.view().map(Message::NetworkSetup),
            Screen::SetupMethod(screen) => screen.view().map(Message::SetupMethod),
            Screen::SelectHardwareWallet(screen) => {
                screen.view().map(Message::SelectHardwareWallet)
            }
            Screen::ShowSeed(screen) => screen.view().map(Message::ShowSeed),
            Screen::VerifySeed(screen) => screen.view().map(Message::VerifySeed),
            Screen::ImportAddress(screen) => screen.view().map(Message::ImportAddress),
            Screen::ImportPrivateKey(screen) => screen.view().map(Message::ImportPrivateKey),
            Screen::ImportSeedPhrase(screen) => screen.view().map(Message::ImportSeedPhrase),
            Screen::SafeOnboarding(screen) => screen.view().map(Message::SafeOnboarding),
            Screen::SelectHdAccount(screen) => screen.view().map(Message::SelectHdAccount),
            Screen::ConnectLedger(screen) => screen.view().map(Message::ConnectLedger),
            Screen::ConnectTrezor(screen) => screen.view().map(Message::ConnectTrezor),
            Screen::Wallet(screen) => screen.view().map(Message::WalletDashboard),
        };

        match &self.toast {
            None => screen,
            Some(state) => {
                let t = KaoTheme::for_kind(settings::theme());
                stack![screen, error_toast(t, state)].into()
            }
        }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        match &self.screen {
            Screen::CreatePassword(screen) => screen.subscription().map(Message::CreatePassword),
            Screen::Unlock(_) => Subscription::none(),
            Screen::NetworkSetup(screen) => screen.subscription().map(Message::NetworkSetup),
            Screen::SetupMethod(screen) => screen.subscription().map(Message::SetupMethod),
            Screen::SelectHardwareWallet(screen) => {
                screen.subscription().map(Message::SelectHardwareWallet)
            }
            Screen::ShowSeed(screen) => screen.subscription().map(Message::ShowSeed),
            Screen::ImportAddress(screen) => screen.subscription().map(Message::ImportAddress),
            Screen::ImportPrivateKey(screen) => {
                screen.subscription().map(Message::ImportPrivateKey)
            }
            Screen::ImportSeedPhrase(screen) => {
                screen.subscription().map(Message::ImportSeedPhrase)
            }
            Screen::SafeOnboarding(screen) => screen.subscription().map(Message::SafeOnboarding),
            Screen::SelectHdAccount(screen) => screen.subscription().map(Message::SelectHdAccount),
            Screen::ConnectLedger(screen) => screen.subscription().map(Message::ConnectLedger),
            Screen::ConnectTrezor(screen) => screen.subscription().map(Message::ConnectTrezor),
            Screen::VerifySeed(screen) => screen.subscription().map(Message::VerifySeed),
            Screen::Wallet(screen) => screen.subscription().map(Message::WalletDashboard),
        }
    }
}

/// Bottom-center toast for the latest wallet error. Auto-dismisses
/// after `TOAST_LIFETIME_SECS`; the ✕ chip on the right lets the user
/// clear it sooner. The container width is capped (`max_width(480)`) so
/// the toast looks like a chip on wide windows but still wraps cleanly
/// on narrow ones, and the rest of the overlay is `Space` so pointer
/// events on the screen below pass through.
fn error_toast<'a>(t: KaoTheme, state: &'a ToastState) -> Element<'a, Message> {
    let generation = state.generation;
    let dismiss = mouse_area(
        container(text("✕").size(13).color(t.down).font(bold())).padding(Padding::from([2, 6])),
    )
    .on_press(Message::DismissError { generation })
    .interaction(iced::mouse::Interaction::Pointer);

    let body = row![
        text("⚠").size(14).color(t.down).font(bold()),
        Space::new().width(8),
        container(text(state.msg.as_str()).size(12).color(t.down).font(bold())).width(Length::Fill),
        Space::new().width(10),
        dismiss,
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);

    let card = container(body)
        .padding(Padding::from([10, 14]))
        .width(Length::Fill)
        .max_width(480.0)
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(t.down, 0.18))),
            border: Border {
                color: with_alpha(t.down, 0.5),
                width: 1.0,
                radius: Radius::from(12),
            },
            text_color: Some(t.down),
            ..container::Style::default()
        });

    // Pin to the bottom-center of the window: column[Space::Fill, row]
    // so the card hugs the bottom, with horizontal centering inside the
    // row and 16px breathing room from the window edge.
    let centered = row![
        Space::new().width(Length::Fill),
        card,
        Space::new().width(Length::Fill),
    ]
    .width(Length::Fill);

    column![
        Space::new().height(Length::Fill),
        centered,
        Space::new().height(16),
    ]
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

/// Dispatch `wallet::save_descriptor` to tokio's blocking pool. The Argon2id
/// KDF runs a few hundred ms per save, which would freeze the UI loop if run
/// inline. The timing logs below exist so a future regression — e.g. someone
/// calling `wallet::save_descriptor` on the UI thread again, or the Argon2id
/// work factor drifting up — is obvious in stderr. If you ever see `[save]
/// elapsed` near or above ~16ms appearing on the UI thread (look for
/// `[switch] dashboard handoff scheduled in <large>`), the save has snuck
/// back onto the iced event loop.
fn save_descriptor_task(
    descriptor: WalletDescriptor,
    passphrase: SecretString,
) -> iced::Task<Message> {
    iced::Task::perform(
        async move {
            debug!("save descriptor: dispatching to spawn_blocking");
            let started = std::time::Instant::now();
            let join = tokio::task::spawn_blocking(move || {
                let kdf_started = std::time::Instant::now();
                let result = wallet::save_descriptor(&descriptor, &passphrase);
                debug!(elapsed = ?kdf_started.elapsed(), "save descriptor: argon2+write finished");
                result
            })
            .await;
            let outcome = match join {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e.to_string()),
                Err(join_err) => Err(format!("wallet save panicked: {join_err}")),
            };
            debug!(elapsed = ?started.elapsed(), ok = outcome.is_ok(), "save descriptor: done");
            outcome
        },
        Message::WalletSaved,
    )
}

/// Off-thread `wallet::load_contacts`. The Argon2id KDF runs on the file's
/// stored params (~250ms in production), so the load must not block the UI
/// thread. Result lands as `Message::ContactsLoaded`; failures log and
/// leave the in-memory book empty rather than blocking unlock.
fn load_contacts_task(passphrase: SecretString) -> iced::Task<Message> {
    iced::Task::perform(
        async move {
            let join =
                tokio::task::spawn_blocking(move || wallet::load_contacts(&passphrase)).await;
            match join {
                Ok(Ok(vec)) => Ok(vec),
                Ok(Err(e)) => Err(e.to_string()),
                Err(join_err) => Err(format!("contacts load panicked: {join_err}")),
            }
        },
        Message::ContactsLoaded,
    )
}

/// Off-thread `wallet::save_contacts`. Mirrors `save_descriptor_task`:
/// Argon2 verifies the password against the stored auth_check, then the
/// contacts table is rewritten in a single redb txn. The in-memory book
/// has already been updated synchronously by the caller, so a save error
/// only diverges disk from memory until the next save (or the next load
/// on relaunch).
fn save_contacts_task(contacts: Vec<Contact>, passphrase: SecretString) -> iced::Task<Message> {
    iced::Task::perform(
        async move {
            let join =
                tokio::task::spawn_blocking(move || wallet::save_contacts(&contacts, &passphrase))
                    .await;
            match join {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e.to_string()),
                Err(join_err) => Err(format!("contacts save panicked: {join_err}")),
            }
        },
        Message::ContactsSaved,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::MockFetcher;
    use crate::ui::create_password::CreatePasswordScreen;
    use alloy::primitives::B256;

    fn build_app(screen: Screen) -> App {
        let network: Arc<dyn BalanceFetcher> = Arc::new(MockFetcher::new());
        App {
            screen,
            passphrase: None,
            wallet: None,
            contacts_loaded: true,
            pp_seed: None,
            pp_loaded: false,
            setup_context: None,
            pending_signer: None,
            network,
            portfolio_cache: portfolio::new_cache(),
            contacts: Arc::new(RwLock::new(ContactsBook::new())),
            toast: None,
            toast_gen: 0,
            send_reconnect: None,
            reconnect_open_send: false,
            pending_add_signer: Vec::new(),
        }
    }

    fn placeholder_screen() -> Screen {
        Screen::CreatePassword(CreatePasswordScreen::default())
    }

    /// Build a Local descriptor whose key bytes are non-zero (so secp256k1
    /// validation passes) and unique per `seed`.
    fn local_signer_and_account(seed: u8) -> (KaoSigner, AccountDescriptor) {
        let mut key = [0xab; 32];
        key[0] = seed;
        let signer = wallet::signer_from_bytes(&B256::from(key)).expect("valid key");
        let account = wallet::local_account(&signer);
        (KaoSigner::Local(signer), account)
    }

    #[test]
    fn switch_account_with_no_wallet_loaded_is_a_noop() {
        let mut app = build_app(placeholder_screen());
        let _ = app.switch_account(5);
        assert!(matches!(app.screen, Screen::CreatePassword(_)));
        assert!(app.wallet.is_none());
    }

    #[test]
    fn switch_account_out_of_range_is_a_noop() {
        let mut app = build_app(placeholder_screen());
        let (_, account) = local_signer_and_account(1);
        app.wallet = Some(WalletDescriptor::single(account));
        let _ = app.switch_account(99);
        assert!(matches!(app.screen, Screen::CreatePassword(_)));
        assert_eq!(app.wallet.as_ref().unwrap().active_index, 0);
    }

    #[test]
    fn switch_account_to_valid_local_index_updates_state_and_enters_dashboard() {
        let mut app = build_app(placeholder_screen());
        let (_, a0) = local_signer_and_account(1);
        let (_, a1) = local_signer_and_account(2);
        app.wallet = Some(WalletDescriptor {
            accounts: vec![a0, a1],
            safes: Vec::new(),
            active_index: 0,
        });
        let _ = app.switch_account(1);
        assert_eq!(app.wallet.as_ref().unwrap().active_index, 1);
        assert!(matches!(app.screen, Screen::Wallet(_)));
    }

    #[test]
    fn save_account_with_no_passphrase_leaves_state_unchanged() {
        let mut app = build_app(placeholder_screen());
        let (signer, account) = local_signer_and_account(1);
        let _task = app.save_account_and_enter_dashboard(account, signer);
        // No passphrase held → save bails out before touching wallet/screen.
        assert!(app.wallet.is_none());
        assert!(matches!(app.screen, Screen::CreatePassword(_)));
    }

    #[test]
    fn save_account_in_add_mode_refuses_duplicate_address() {
        let mut app = build_app(placeholder_screen());
        let (signer, dup) = local_signer_and_account(1);
        app.wallet = Some(WalletDescriptor::single(dup.clone()));
        // Park a pending signer so cancel_add_account can land on the dashboard.
        let (parked_signer, _) = local_signer_and_account(1);
        app.pending_signer = Some(parked_signer);
        app.passphrase = Some(SecretString::new("pw".to_string().into_boxed_str()));
        app.setup_context = Some(SetupContext::AddAccount);

        let _task = app.save_account_and_enter_dashboard(dup, signer);
        // Wallet must still hold exactly one account (no duplicate appended).
        assert_eq!(app.wallet.as_ref().unwrap().accounts.len(), 1);
        // The add-account flow was cancelled — context cleared, dashboard rebuilt.
        assert!(app.setup_context.is_none());
        assert!(matches!(app.screen, Screen::Wallet(_)));
    }

    #[test]
    fn save_account_appends_in_add_mode_when_address_is_new() {
        let mut app = build_app(placeholder_screen());
        let (_, existing) = local_signer_and_account(1);
        app.wallet = Some(WalletDescriptor::single(existing));
        app.passphrase = Some(SecretString::new("pw".to_string().into_boxed_str()));
        app.setup_context = Some(SetupContext::AddAccount);

        let (new_signer, new_account) = local_signer_and_account(2);
        let _task = app.save_account_and_enter_dashboard(new_account, new_signer);
        let w = app.wallet.as_ref().unwrap();
        assert_eq!(w.accounts.len(), 2);
        // New account becomes active.
        assert_eq!(w.active_index, 1);
        assert!(app.setup_context.is_none());
        assert!(matches!(app.screen, Screen::Wallet(_)));
    }

    #[test]
    fn save_account_in_fresh_wallet_mode_creates_single_account_descriptor() {
        let mut app = build_app(placeholder_screen());
        app.passphrase = Some(SecretString::new("pw".to_string().into_boxed_str()));
        app.setup_context = Some(SetupContext::FreshWallet);
        let (signer, account) = local_signer_and_account(1);
        let _task = app.save_account_and_enter_dashboard(account, signer);
        let w = app.wallet.as_ref().unwrap();
        assert_eq!(w.accounts.len(), 1);
        assert_eq!(w.active_index, 0);
        assert!(app.setup_context.is_none());
        assert!(matches!(app.screen, Screen::Wallet(_)));
    }

    #[test]
    fn begin_add_account_sets_context_and_navigates_to_setup() {
        let mut app = build_app(placeholder_screen());
        let _ = app.begin_add_account();
        assert!(matches!(app.setup_context, Some(SetupContext::AddAccount)));
        assert!(matches!(app.screen, Screen::SetupMethod(_)));
    }
}
