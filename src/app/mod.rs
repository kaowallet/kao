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
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::bold;
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
use crate::ui::select_hardware_wallet::{
    Message as SelectHardwareWalletMessage, Outcome as SelectHardwareWalletOutcome,
    SelectHardwareWalletScreen,
};
use crate::ui::select_hd_account::{
    Message as SelectHdAccountMessage, Outcome as SelectHdAccountOutcome, SelectHdAccountScreen,
};
use crate::ui::select_indexer::{
    Message as SelectIndexerMessage, Outcome as SelectIndexerOutcome, SelectIndexerScreen,
};
use crate::ui::select_rpc::{
    Message as SelectRpcMessage, Outcome as SelectRpcOutcome, SelectRpcScreen,
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
    SelectHardwareWallet(SelectHardwareWalletMessage),
    SelectHdAccount(SelectHdAccountMessage),
    SelectIndexer(SelectIndexerMessage),
    SelectRpc(SelectRpcMessage),
    SetupMethod(SetupMethodMessage),
    ShowSeed(ShowSeedMessage),
    Unlock(UnlockMessage),
    VerifySeed(VerifySeedMessage),
    WalletDashboard(WalletDashboardMessage),
    /// Result of an off-thread `wallet::save_descriptor`. Emitted only to
    /// surface errors — successful saves are silent.
    WalletSaved(Result<(), String>),
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
    DismissError { generation: u64 },
}

// ── Screens ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum Screen {
    /// Ask the user to create a new wallet passphrase (first-run only).
    CreatePassword(CreatePasswordScreen),
    /// Ask the user for the existing passphrase to decrypt wallet.enc.
    Unlock(UnlockScreen),
    /// Pick the RPC source to use for on-chain reads (defaults or custom).
    /// Shown once, after the user creates their initial passphrase.
    SelectRpc(SelectRpcScreen),
    /// Pick the third-party indexer (transaction history + unverified
    /// balances). Shown once, right after `SelectRpc`.
    SelectIndexer(SelectIndexerScreen),
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
    SelectHdAccount(SelectHdAccountScreen),
    ConnectLedger(ConnectLedgerScreen),
    ConnectTrezor(ConnectTrezorScreen),
    /// Boxed because `WalletScreen` is much larger than every other variant
    /// (~700+ bytes vs tens). Without the indirection, every `mem::replace`
    /// on `App::screen` would memcpy the full payload.
    Wallet(Box<WalletScreen>),
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
    /// Latest wallet-error toast, or `None` when nothing is on screen.
    /// Cleared by the auto-dismiss `Task::perform` spawned when the
    /// toast lands, or replaced by a newer error mid-lifetime.
    toast: Option<ToastState>,
    /// Monotonic counter bumped on every fresh error so an older
    /// dismissal task firing late can no-op against a newer toast.
    toast_gen: u64,
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
        crate::net::refresh_auto_checkpoint();
        let network: Arc<dyn BalanceFetcher> = Arc::new(NetworkClient::new());
        let portfolio_cache = portfolio::new_cache();

        let contacts = Arc::new(RwLock::new(ContactsBook::new()));
        if wallet::wallet_exists() {
            let app = App {
                screen: Screen::Unlock(UnlockScreen::default()),
                passphrase: None,
                wallet: None,
                setup_context: None,
                pending_signer: None,
                network,
                portfolio_cache,
                contacts,
                toast: None,
                toast_gen: 0,
            };
            let task = focus_widget(crate::ui::unlock::PASSWORD_INPUT_ID).map(Message::Unlock);
            (app, task)
        } else {
            let app = App {
                screen: Screen::CreatePassword(CreatePasswordScreen::default()),
                passphrase: None,
                wallet: None,
                setup_context: None,
                pending_signer: None,
                network,
                portfolio_cache,
                contacts,
                toast: None,
                toast_gen: 0,
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
        iced::Task::batch(vec![save, self.enter_dashboard(signer)])
    }

    /// Build the dashboard for the currently-loaded wallet and the given
    /// active signer. Caller is responsible for ensuring `self.wallet` is
    /// set and its `active_index` matches `signer`.
    fn enter_dashboard(&mut self, signer: KaoSigner) -> iced::Task<Message> {
        let (accounts, active_index) = match &self.wallet {
            Some(w) => (w.accounts.clone(), w.active_index),
            None => (Vec::new(), 0),
        };
        let started = std::time::Instant::now();
        let screen = WalletScreen::new(
            signer,
            accounts.clone(),
            active_index,
            self.network.clone(),
            self.portfolio_cache.clone(),
            self.contacts.clone(),
        );
        let address = screen.address_for_log();
        let balance_task = screen.fetch_balance_task().map(Message::WalletDashboard);
        let portfolio_task = screen.fetch_portfolio_task().map(Message::WalletDashboard);
        let history_task = screen.fetch_history_task().map(Message::WalletDashboard);
        // Reverse-ENS lookup. No-ops when the active account is already
        // named, so account switches don't pile up redundant lookups.
        let ens_task = screen.fetch_ens_name_task().map(Message::WalletDashboard);
        self.screen = Screen::Wallet(Box::new(screen));
        debug!(
            active_index,
            addr = %address,
            built_in = ?started.elapsed(),
            "entered dashboard; balance+portfolio+history+ens fetch queued",
        );
        iced::Task::batch(vec![balance_task, portfolio_task, history_task, ens_task])
    }

    /// Routes the active account of `self.wallet` to the right destination.
    /// Local: build signer synchronously and enter dashboard immediately.
    /// Hardware: push the matching connect screen in reconnect mode while
    /// the device handshake runs.
    fn enter_active_from_wallet(&mut self) -> iced::Task<Message> {
        let Some(wallet) = self.wallet.as_ref() else {
            return iced::Task::perform(
                async { "no wallet loaded".to_string() },
                Message::WalletError,
            );
        };
        match wallet.active().clone() {
            AccountDescriptor::Local { key_bytes, .. } => {
                let b = alloy::primitives::B256::from_slice(&key_bytes);
                match wallet::signer_from_bytes(&b) {
                    Ok(s) => self.enter_dashboard(KaoSigner::Local(s)),
                    Err(e) => {
                        iced::Task::perform(async move { e.to_string() }, Message::WalletError)
                    }
                }
            }
            AccountDescriptor::Ledger { path, address, .. } => {
                let expected = alloy::primitives::Address::from(address);
                let (screen, task) =
                    ConnectLedgerScreen::new_reconnect(path, expected, self.network.clone());
                self.screen = Screen::ConnectLedger(screen);
                task.map(Message::ConnectLedger)
            }
            AccountDescriptor::Trezor { path, address, .. } => {
                let expected = alloy::primitives::Address::from(address);
                let (screen, task) =
                    ConnectTrezorScreen::new_reconnect(path, expected, self.network.clone());
                self.screen = Screen::ConnectTrezor(screen);
                task.map(Message::ConnectTrezor)
            }
            AccountDescriptor::ViewOnly { address, .. } => {
                let addr = alloy::primitives::Address::from(address);
                self.enter_dashboard(KaoSigner::ViewOnly(addr))
            }
        }
    }

    /// Drop back to the dashboard without going through setup again, using
    /// the signer the user had before they entered the add-account flow.
    /// Used when the user backs out of the SetupMethod / its sub-screens.
    fn cancel_add_account(&mut self) -> iced::Task<Message> {
        self.setup_context = None;
        if let Some(signer) = self.pending_signer.take() {
            return self.enter_dashboard(signer);
        }
        // No parked signer (shouldn't happen) — fall back to a full reload
        // of the active account.
        self.enter_active_from_wallet()
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
        let enter = self.enter_active_from_wallet();
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
        // Refuse to leave the dashboard while a send is in flight: the
        // signer has been moved into the broadcast task, so
        // `into_signer()` would return a `KaoSigner::ViewOnly` placeholder
        // and the user would silently lose their real signer when the
        // broadcast task finished and tried to put it back.
        if let Screen::Wallet(screen) = &self.screen
            && screen.is_send_busy()
        {
            warn!("add-account refused: send in flight");
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
                    self.screen = Screen::SelectRpc(SelectRpcScreen::default());
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
                    self.passphrase = Some(passphrase);
                    self.wallet = Some(descriptor);
                    let load_contacts = load_contacts_task(
                        self.passphrase
                            .as_ref()
                            .expect("passphrase just set")
                            .clone(),
                    );
                    return iced::Task::batch(vec![
                        self.enter_active_from_wallet(),
                        load_contacts,
                    ]);
                }
                cmd.map(Message::Unlock)
            }

            // ── SelectRpc ───────────────────────────────────────────
            Message::SelectRpc(msg) => {
                let Screen::SelectRpc(screen) = &mut self.screen else {
                    return iced::Task::none();
                };
                let (cmd, outcome) = screen.update(msg);
                match outcome {
                    Some(SelectRpcOutcome::UseDefaults) => {
                        let exec: Vec<String> = crate::settings::default_rpcs()
                            .iter()
                            .map(|s| s.to_string())
                            .collect();
                        let consensus: Vec<String> = crate::settings::default_consensus_rpcs()
                            .iter()
                            .map(|s| s.to_string())
                            .collect();
                        crate::settings::set_rpcs(crate::chain::Chain::Mainnet, exec);
                        crate::settings::set_consensus_rpcs(
                            crate::chain::Chain::Mainnet,
                            consensus,
                        );
                        // Seed L2 chains with their per-chain defaults from
                        // `chain.rs` so the dashboard's per-chain portfolio
                        // fan-out actually runs for Base/Optimism — the loop
                        // skips chains whose RPC list is empty.
                        for chain in [crate::chain::Chain::Base, crate::chain::Chain::Optimism] {
                            crate::settings::set_rpcs(
                                chain,
                                vec![chain.default_exec_url().to_string()],
                            );
                            crate::settings::set_consensus_rpcs(
                                chain,
                                vec![chain.default_consensus_url().to_string()],
                            );
                        }
                        self.screen = Screen::SelectIndexer(SelectIndexerScreen::new(None));
                        iced::Task::none()
                    }
                    Some(SelectRpcOutcome::Custom { exec, consensus }) => {
                        // Persist every chain whose slot the screen
                        // populated. Empty slots (typical for L2 in the
                        // Custom path when the user wiped the row) leave
                        // those chains unconfigured — the dashboard's
                        // per-chain fan-out skips chains with no RPC.
                        for chain in crate::chain::Chain::ALL {
                            let e = exec.get(chain).trim();
                            if !e.is_empty() {
                                crate::settings::set_rpcs(chain, vec![e.to_string()]);
                            }
                            let c = consensus.get(chain).trim();
                            if !c.is_empty() {
                                crate::settings::set_consensus_rpcs(
                                    chain,
                                    vec![c.to_string()],
                                );
                            }
                        }
                        // SelectIndexer's auto-detect keys off the
                        // Mainnet RPC URL (Alchemy / Etherscan reuse).
                        let mainnet_url =
                            exec.get(crate::chain::Chain::Mainnet).clone();
                        self.screen = Screen::SelectIndexer(SelectIndexerScreen::new(
                            Some(&mainnet_url),
                        ));
                        iced::Task::none()
                    }
                    Some(SelectRpcOutcome::Back) => {
                        self.passphrase = None;
                        self.setup_context = None;
                        self.screen = Screen::CreatePassword(CreatePasswordScreen::default());
                        focus_widget(crate::ui::create_password::PASSWORD_INPUT_ID)
                            .map(Message::CreatePassword)
                    }
                    None => cmd.map(Message::SelectRpc),
                }
            }

            // ── SelectIndexer ───────────────────────────────────────
            Message::SelectIndexer(msg) => {
                let Screen::SelectIndexer(screen) = &mut self.screen else {
                    return iced::Task::none();
                };
                let (cmd, outcome) = screen.update(msg);
                match outcome {
                    Some(SelectIndexerOutcome::Back) => {
                        self.screen = Screen::SelectRpc(SelectRpcScreen::default());
                        iced::Task::none()
                    }
                    Some(out) => {
                        apply_indexer_outcome(out);
                        self.screen = Screen::SetupMethod(SetupMethodScreen::default());
                        iced::Task::none()
                    }
                    None => cmd.map(Message::SelectIndexer),
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
                    },
                    Some(SetupMethodOutcome::Cancel) => {
                        if matches!(self.setup_context, Some(SetupContext::AddAccount)) {
                            self.cancel_add_account()
                        } else {
                            // Fresh setup: step back one — to the indexer
                            // picker — so users can flip from e.g. Etherscan
                            // to None without re-picking RPC.
                            let rpc = crate::settings::rpcs(crate::chain::Chain::Mainnet)
                                .into_iter()
                                .next();
                            self.screen = Screen::SelectIndexer(SelectIndexerScreen::new(
                                rpc.as_deref(),
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
                    Some(SelectHardwareWalletOutcome::Back) => {
                        self.screen = Screen::SetupMethod(SetupMethodScreen::default());
                        iced::Task::none()
                    }
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
                        self.screen = Screen::SetupMethod(SetupMethodScreen::default());
                        iced::Task::none()
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
                    }
                    Some(ImportPrivateKeyOutcome::Back) => {
                        self.screen = Screen::SetupMethod(SetupMethodScreen::default());
                        iced::Task::none()
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
                        self.save_account_and_enter_dashboard(account, signer)
                    }
                    Some(ConnectLedgerOutcome::ReconnectComplete { signer }) => {
                        self.enter_dashboard(signer)
                    }
                    Some(ConnectLedgerOutcome::Back) => {
                        // Setup mode: back to the hardware-wallet picker.
                        // Reconnect mode (after unlock): back to unlock so the
                        // user can retry or pick a different wallet file. The
                        // wallet is locked again in that case.
                        self.screen = if wallet::wallet_exists() {
                            self.passphrase = None;
                            self.wallet = None;
                            Screen::Unlock(UnlockScreen::default())
                        } else {
                            Screen::SelectHardwareWallet(SelectHardwareWalletScreen::default())
                        };
                        iced::Task::none()
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
                        self.save_account_and_enter_dashboard(account, signer)
                    }
                    Some(ConnectTrezorOutcome::ReconnectComplete { signer }) => {
                        self.enter_dashboard(signer)
                    }
                    Some(ConnectTrezorOutcome::Back) => {
                        self.screen = if wallet::wallet_exists() {
                            self.passphrase = None;
                            self.wallet = None;
                            Screen::Unlock(UnlockScreen::default())
                        } else {
                            Screen::SelectHardwareWallet(SelectHardwareWalletScreen::default())
                        };
                        iced::Task::none()
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
                    Some(WalletDashboardOutcome::SaveContacts(new_contacts)) => {
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

            // ── Contacts background load/save ───────────────────────
            Message::ContactsLoaded(result) => {
                match result {
                    Ok(vec) => {
                        if let Ok(mut book) = self.contacts.write() {
                            *book = ContactsBook::from_vec(vec);
                        } else {
                            warn!("contacts lock poisoned; skipping load");
                        }
                    }
                    Err(e) => warn!(error = %e, "contacts load failed"),
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
                self.toast = Some(ToastState {
                    msg: e,
                    generation,
                });
                // Schedule the auto-dismiss tick. Generation-tagged so a
                // late firing can't clear a newer toast: replacement
                // bumps the counter, and the stale `DismissError`
                // arrives with `g != self.toast_gen` and no-ops.
                iced::Task::perform(
                    async move {
                        tokio::time::sleep(std::time::Duration::from_secs(
                            TOAST_LIFETIME_SECS,
                        ))
                        .await;
                        generation
                    },
                    |generation| Message::DismissError { generation },
                )
            }
            Message::DismissError { generation } => {
                if self.toast.as_ref().is_some_and(|s| s.generation == generation) {
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
            Screen::SelectRpc(screen) => screen.view().map(Message::SelectRpc),
            Screen::SelectIndexer(screen) => screen.view().map(Message::SelectIndexer),
            Screen::SetupMethod(screen) => screen.view().map(Message::SetupMethod),
            Screen::SelectHardwareWallet(screen) => {
                screen.view().map(Message::SelectHardwareWallet)
            }
            Screen::ShowSeed(screen) => screen.view().map(Message::ShowSeed),
            Screen::VerifySeed(screen) => screen.view().map(Message::VerifySeed),
            Screen::ImportAddress(screen) => screen.view().map(Message::ImportAddress),
            Screen::ImportPrivateKey(screen) => screen.view().map(Message::ImportPrivateKey),
            Screen::ImportSeedPhrase(screen) => screen.view().map(Message::ImportSeedPhrase),
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
            Screen::SelectRpc(screen) => screen.subscription().map(Message::SelectRpc),
            Screen::SelectIndexer(screen) => screen.subscription().map(Message::SelectIndexer),
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
        container(text("✕").size(13).color(t.down).font(bold()))
            .padding(Padding::from([2, 6])),
    )
    .on_press(Message::DismissError { generation })
    .interaction(iced::mouse::Interaction::Pointer);

    let body = row![
        text("⚠").size(14).color(t.down).font(bold()),
        Space::new().width(8),
        container(text(state.msg.as_str()).size(12).color(t.down).font(bold()))
            .width(Length::Fill),
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
            let join = tokio::task::spawn_blocking(move || wallet::load_contacts(&passphrase)).await;
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
            let join = tokio::task::spawn_blocking(move || {
                wallet::save_contacts(&contacts, &passphrase)
            })
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

/// Persist the user's indexer choice. Each branch sets the provider plus
/// any provider-specific config; fields the outcome doesn't carry are left
/// untouched so a re-run of setup doesn't wipe an unrelated existing key.
fn apply_indexer_outcome(outcome: SelectIndexerOutcome) {
    use crate::settings::{self, IndexerProvider};
    match outcome {
        SelectIndexerOutcome::Alchemy { api_key } => {
            settings::set_alchemy_api_key(Some(api_key));
            settings::set_indexer_provider(IndexerProvider::Alchemy);
        }
        SelectIndexerOutcome::Drpc { api_key } => {
            settings::set_drpc_api_key(Some(api_key));
            settings::set_indexer_provider(IndexerProvider::Drpc);
        }
        SelectIndexerOutcome::Blockscout { base_url, api_key } => {
            settings::set_blockscout_base_url(base_url);
            settings::set_blockscout_api_key(api_key);
            settings::set_indexer_provider(IndexerProvider::Blockscout);
        }
        SelectIndexerOutcome::Etherscan { api_key } => {
            settings::set_etherscan_api_key(Some(api_key));
            settings::set_indexer_provider(IndexerProvider::Etherscan);
        }
        SelectIndexerOutcome::NoIndexer => {
            settings::set_indexer_provider(IndexerProvider::None);
        }
        SelectIndexerOutcome::Back => {
            // Handled by the caller — back navigation doesn't touch settings.
        }
    }
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
            setup_context: None,
            pending_signer: None,
            network,
            portfolio_cache: portfolio::new_cache(),
            contacts: Arc::new(RwLock::new(ContactsBook::new())),
            toast: None,
            toast_gen: 0,
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
