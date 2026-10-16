use std::sync::{Arc, RwLock};

use iced::border::Radius;
use iced::widget::operation::focus as focus_widget;
use iced::widget::{Space, column, container, mouse_area, row, stack, text};
use iced::{Alignment, Background, Border, Element, Length, Padding, Subscription};
use secrecy::SecretString;
use tracing::{debug, error, info, warn};

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
    Message as WalletDashboardMessage, Outcome as WalletDashboardOutcome,
    POOL_IDENTITY_STILL_UNREAD, POOL_IDENTITY_UNREAD, WalletScreen,
};
use crate::vault::{Vault, VaultFlush};
use crate::wallet::{
    self, AccountDescriptor, Contact, ContactsBook, KaoSigner, SafeUpsert, WalletDescriptor,
};
use crate::walletconnect::runtime::WcSlot;
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
    /// Result of an off-thread `wallet::save_descriptor`: the wallet's data
    /// key on success, and whether that save minted it — or `None` when the
    /// descriptor saved but its key couldn't be settled (the vault is left
    /// alone). Frees the wallet file for whatever queued behind it (see
    /// `DbGate`); an error surfaces as a toast.
    WalletSaved(Result<Option<(wallet::DataKey, wallet::KeyOrigin)>, String>),
    /// Result of an off-thread `wallet::reset_sealed` the user asked for (the saved history and
    /// connections couldn't be read): the fresh data key it minted, which the vault adopts, or
    /// why it failed (a toast).
    SealedReset(Result<(wallet::DataKey, wallet::KeyOrigin), String>),
    /// Result of the post-unlock Safe refresh batch. Carries one entry
    /// per Safe in the unlock-time snapshot. Each entry is
    /// `Ok((new_descriptor, diff))` on a successful refresh, or
    /// `Err(reason)` for that Safe alone (other Safes may have
    /// succeeded). Lands by `(address, chain_id)`, never by position.
    /// Fires at most once per unlock.
    SafesRefreshed(crate::safe::RefreshBatch),
    /// Result of an off-thread `wallet::load_contacts`. Carries the
    /// loaded vec on success; errors are logged and the in-memory book
    /// stays empty. Frees the wallet file like `WalletSaved`.
    ContactsLoaded(Result<Vec<Contact>, String>),
    /// Result of an off-thread `wallet::save_contacts`. Errors only —
    /// the in-memory book was already updated synchronously when the
    /// save was dispatched. Frees the wallet file like `WalletSaved`.
    ContactsSaved(Result<(), String>),
    /// Something went wrong: red ⚠ toast, logged at `error!`.
    WalletError(String),
    /// Something the user should know that went fine ("Removed Account 2",
    /// "Treasury on Base is already in your wallet"): neutral toast, logged
    /// at `info!`. Same slot and lifetime as `WalletError`.
    Notice(String),
    /// Auto-dismiss tick for the toast. Carries the generation counter
    /// the timer was spawned with — a newer toast supersedes by bumping
    /// the counter, which makes the older timer's dismissal a no-op when
    /// it fires.
    DismissToast {
        generation: u64,
    },
    /// The window's close button / the OS asked to quit: suspend WalletConnect
    /// (its state saved for the next start; the full teardown without a data
    /// key) and wait for that and every other teardown or vault drain still
    /// running (bounded), then exit. A second request quits at once.
    CloseRequested(iced::window::Id),
    /// A lock's WalletConnect suspend (or teardown) finished. Ack only — the
    /// runtime it ended is already out of the slot.
    WcTornDown,
    /// The quit-time WalletConnect wait finished (or ran out of time).
    Exit,
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
    /// on Drop via `SecretString`. Cleared on lock (`lock_wallet`) and when
    /// the network wizard backs out to create-password.
    passphrase: Option<SecretString>,
    /// The currently-loaded wallet descriptor. Populated after unlock or
    /// fresh-setup completion. Carries the full account list and active
    /// index across screen transitions (e.g. through hardware reconnect or
    /// the add-account setup flow).
    wallet: Option<WalletDescriptor>,
    /// The dedicated Privacy Pools mnemonic, held for the session (like
    /// `passphrase`) so the pool app can derive its account and re-show the
    /// backup phrase without a second Argon2 pass. Loaded lazily on first
    /// dashboard entry; `pp_loaded` records that the (possibly-absent) load
    /// succeeded. A load that failed leaves it `false` — retried at the next
    /// dashboard entry or from the pool app's "Try again" — and the pool app
    /// offers no "Create identity" meanwhile: a seed that couldn't be read is
    /// not a seed that doesn't exist.
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
    /// Latest toast (error or notice), or `None` when nothing is on
    /// screen. Cleared by the auto-dismiss `Task::perform` spawned when
    /// the toast lands, or replaced by a newer one mid-lifetime.
    toast: Option<ToastState>,
    /// Monotonic counter bumped on every fresh toast so an older
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
    /// Who has `wallet.redb` open off-thread, and what waits for it.
    db: DbGate,
    /// The unlock-time legacy repair (`repair_sibling_signer_links_once`)
    /// changed the wallet in memory — its links and/or its marker — but
    /// nothing has saved it yet. Saved by the Safe-refresh completion, or
    /// by any earlier `persist_wallet`.
    safes_dirty: bool,
    /// Where the WalletConnect runtime lives (sessions, request queue,
    /// answers). App-owned so it outlives every dashboard rebuild; each
    /// dashboard gets a clone (`set_wc_slot`). Empty until the user presses
    /// Connect, or until the dashboard entry restores sessions saved at the
    /// last lock or quit. Closed and replaced by a fresh slot on lock: the old
    /// runtime is suspended (its state saved, dapps not told) and the next
    /// unlock restores it.
    wc_slot: WcSlot,
    /// The encrypted store of WalletConnect state and history (App-owned,
    /// shared with `wc_slot` and every successor). Unlocked with the wallet
    /// (each unlock is a new epoch), locked with it.
    vault: Vault,
    /// A quit is in progress (WalletConnect teardown running): a second
    /// close request exits immediately.
    closing: bool,
    /// A `wallet::reset_sealed` the user asked for is running: a second one
    /// now would mint another key under the first, and the vault would adopt
    /// whichever landed first — not the one on disk. Cleared when it lands.
    sealed_reset_running: bool,
    /// How creating a wallet takes the process-wide instance lock:
    /// `wallet::acquire_instance_lock` (what `App::new` installs), or a
    /// test's stand-in that leaves the real lock alone.
    create_acquire: crate::ui::unlock::AcquireInstanceLock,
}

/// How the App reads the pool seed: `wallet::load_pp_seed`, or a test's stand-in.
type PpSeedLoad = fn(&SecretString) -> Result<Option<SecretString>, wallet::WalletError>;

/// How the App resets the sealed tables: `wallet::reset_sealed`, or a test's stand-in.
type SealedResetFn =
    fn(&SecretString) -> Result<(wallet::DataKey, wallet::KeyOrigin), wallet::WalletError>;

/// Off-thread work on `wallet.redb`, one op at a time.
///
/// redb locks the file exclusively and doesn't wait: opening it while
/// another open is alive fails at once with `DatabaseAlreadyOpen`. Three
/// kinds of App work open it off the UI thread — wallet saves, the
/// unlock-time contacts load and contacts saves — so they take turns here.
/// Whatever is requested while the file is busy is queued, never dropped,
/// and goes out when the running op lands (`App::db_op_landed`):
///
/// * wallet saves coalesce into ONE save of the then-latest `App::wallet`;
/// * contacts saves coalesce into one save of the latest book;
/// * a contacts load requested while busy simply waits its turn.
///
/// Every completion (`WalletSaved`, `ContactsLoaded`, `ContactsSaved`)
/// frees the gate, error or not, so no failure leaves it stuck.
///
/// Serialization itself is the store's job: every `wallet.redb` open in
/// `wallet::store` holds a process-wide per-path lock, and the passphrase-
/// and data-key-keyed ops wait for it rather than fail. What the gate adds
/// is coalescing (one save of the latest wallet, the latest contacts book)
/// and ordering (neither kind starves the other), and it keeps a pile of
/// Argon2 passes from queueing behind the store lock.
///
/// Not gated:
///
/// * the vault's writer thread (`crate::vault`): WalletConnect state and
///   history, sealed under the data key — no Argon2, short batches, and it
///   waits for the store lock like the gated ops do.
/// * the Privacy Pools seed, synchronously on the UI thread. `load_pp_seed`
///   runs at a dashboard entry until it has succeeded once; it waits for the
///   store lock (a running gated op or vault batch delays it, never fails
///   it), and a load that fails anyway is retried, never read as "no seed".
///   `save_pp_seed` (restore identity) and `create_pp_seed` (create, which
///   never overwrites an existing seed) refuse while the gate is busy
///   (`App::pool_seed_write_blocked`) rather than stall the UI thread
///   behind a save.
/// * the pool note cache (`save_pp_notes` and friends, in the dashboard).
///   It is advisory — a failed write only costs a re-scan — and it never
///   waits: a busy store just logs.
/// * the user's reset of the sealed tables (`wallet::reset_sealed`, see
///   `App::request_sealed_reset_with`): rare, one at a time, and off the UI
///   thread; it waits for the store lock like the vault's writer does.
#[derive(Debug, Default)]
struct DbGate {
    /// The op holding the file right now.
    running: Option<DbOp>,
    /// A wallet save waits; it writes the wallet as it is when it starts.
    wallet_save_queued: bool,
    /// The unlock-time contacts load waits.
    contacts_load_queued: bool,
    /// A contacts save waits, with the latest book to write.
    contacts_save_queued: Option<Vec<Contact>>,
}

/// What a close request does (`App::close_requested`): exit at once, or once `F` — what must
/// finish before the process may exit — has.
enum QuitStep<F> {
    Now,
    After(F),
}

/// One kind of gated `wallet.redb` op (see `DbGate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DbOp {
    WalletSave,
    ContactsLoad,
    ContactsSave,
}

impl DbOp {
    /// Stable short name for the GUI state trace (see `crate::trace`).
    fn name(self) -> &'static str {
        match self {
            DbOp::WalletSave => "saving",
            DbOp::ContactsLoad => "loading_contacts",
            DbOp::ContactsSave => "saving_contacts",
        }
    }
}

impl DbGate {
    /// Coarse state for the GUI trace: the running op (or `idle`) plus a
    /// suffix per queued op — e.g. `saving`, `saving+queued` (a wallet
    /// save waits), `loading_contacts+queued`, `saving+contacts_queued`.
    fn name(&self) -> String {
        let mut name = self.running.map_or("idle", DbOp::name).to_string();
        if self.wallet_save_queued {
            name.push_str("+queued");
        }
        if self.contacts_load_queued {
            name.push_str("+contacts_load_queued");
        }
        if self.contacts_save_queued.is_some() {
            name.push_str("+contacts_queued");
        }
        name
    }

    /// A wallet save is running or waiting — it will report for every edit
    /// made so far.
    fn wallet_save_pending(&self) -> bool {
        self.wallet_save_queued || self.running == Some(DbOp::WalletSave)
    }
}

/// Single-toast state. We don't queue — a fresher toast replaces the
/// previous message rather than stacking, so the user always reads the
/// most relevant signal.
#[derive(Debug)]
struct ToastState {
    msg: String,
    generation: u64,
    kind: ToastKind,
}

/// How a toast reads: a failure (`Message::WalletError`) or an
/// informational notice (`Message::Notice`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToastKind {
    Error,
    Notice,
}

/// Auto-dismiss timeout for the toast. Long enough to read a sentence
/// comfortably, short enough that a missed glance gets a second chance via
/// the dismiss button.
const TOAST_LIFETIME_SECS: u64 = 5;

impl App {
    pub fn new() -> (Self, iced::Task<Message>) {
        crate::settings::load();
        let network: Arc<dyn BalanceFetcher> = Arc::new(NetworkClient::new());
        Self::with_network(network, wallet::wallet_exists())
    }

    /// [`Self::new`] past the settings load, over `network`: the unlock screen when a wallet file
    /// `exists`, else create-password — with the production store, lock and save wiring.
    fn with_network(network: Arc<dyn BalanceFetcher>, exists: bool) -> (Self, iced::Task<Message>) {
        let portfolio_cache = portfolio::new_cache();

        let contacts = Arc::new(RwLock::new(ContactsBook::new()));
        let vault = Vault::new();
        crate::trace::state(
            "app",
            "screen",
            "startup",
            if exists { "Unlock" } else { "CreatePassword" },
        );
        if exists {
            let wc_slot = WcSlot::with_vault(vault.clone());
            let app = App {
                screen: Screen::Unlock(UnlockScreen::new(wc_slot.clone())),
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
                db: DbGate::default(),
                safes_dirty: false,
                wc_slot,
                vault,
                closing: false,
                sealed_reset_running: false,
                create_acquire: wallet::acquire_instance_lock,
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
                db: DbGate::default(),
                safes_dirty: false,
                wc_slot: WcSlot::with_vault(vault.clone()),
                vault,
                closing: false,
                sealed_reset_running: false,
                create_acquire: wallet::acquire_instance_lock,
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
        if self.passphrase.is_none() {
            return iced::Task::perform(
                async { "missing passphrase; cannot save wallet".to_string() },
                Message::WalletError,
            );
        }

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
        self.setup_context = None;
        self.pending_signer = None;
        self.wallet = Some(descriptor);
        let save = self.persist_wallet("add account");
        iced::Task::batch(vec![save, self.enter_dashboard(signer, None)])
    }

    /// Persist `self.wallet`. Every save of the loaded wallet goes through
    /// here.
    ///
    /// Saves go through the `DbGate`: redb holds an exclusive file lock for
    /// the whole save (two Argon2 passes included), so a save opened while
    /// another save or a contacts load/save holds the file fails with
    /// `DatabaseAlreadyOpen` and its edit is gone after a restart. While the
    /// file is busy, further calls just note that a save is needed; when the
    /// running op lands, ONE save of the *latest* `self.wallet` goes out and
    /// covers every edit made in between.
    ///
    /// Callers must return (or batch) the task: dropping it would leave the
    /// gate marked busy and park every later save. `why` only labels the
    /// log line.
    fn persist_wallet(&mut self, why: &'static str) -> iced::Task<Message> {
        let (Some(wallet), Some(passphrase)) = (self.wallet.as_ref(), self.passphrase.as_ref())
        else {
            warn!(
                why,
                "persist: no wallet or passphrase held; skipping disk write"
            );
            return iced::Task::none();
        };
        if let Some(running) = self.db.running {
            debug!(
                why,
                running = running.name(),
                "persist: wallet file busy; queued a save"
            );
            self.db.wallet_save_queued = true;
            // The queued save writes the then-current wallet, repair included.
            self.safes_dirty = false;
            return iced::Task::none();
        }
        debug!(why, "persist: dispatching wallet save");
        let save = save_descriptor_task(wallet.clone(), passphrase.clone());
        self.db.running = Some(DbOp::WalletSave);
        self.safes_dirty = false;
        save
    }

    /// Write the contacts book, through the `DbGate` like `persist_wallet`.
    /// The caller has already put `contacts` in the in-memory book; while
    /// the file is busy, the latest book waits and is written when it
    /// frees up.
    fn persist_contacts(&mut self, contacts: Vec<Contact>) -> iced::Task<Message> {
        let Some(passphrase) = self.passphrase.as_ref() else {
            warn!("save contacts: no passphrase held; skipping disk write");
            return iced::Task::none();
        };
        if let Some(running) = self.db.running {
            debug!(
                running = running.name(),
                "save contacts: wallet file busy; queued"
            );
            self.db.contacts_save_queued = Some(contacts);
            return iced::Task::none();
        }
        self.db.running = Some(DbOp::ContactsSave);
        save_contacts_task(contacts, passphrase.clone())
    }

    /// Read the contacts book off-thread (once per unlock), through the
    /// `DbGate`. Lands as `Message::ContactsLoaded`.
    fn start_contacts_load(&mut self) -> iced::Task<Message> {
        let Some(passphrase) = self.passphrase.as_ref() else {
            warn!("load contacts: no passphrase held; skipping");
            return iced::Task::none();
        };
        if let Some(running) = self.db.running {
            debug!(
                running = running.name(),
                "load contacts: wallet file busy; queued"
            );
            self.db.contacts_load_queued = true;
            return iced::Task::none();
        }
        self.db.running = Some(DbOp::ContactsLoad);
        load_contacts_task(passphrase.clone())
    }

    /// `finished` landed (successfully or not) and let go of the wallet
    /// file: free the gate and start whatever queued behind it — one op;
    /// the rest wait for that one. The other kind goes first (contacts
    /// after a wallet save, the wallet after a contacts op), so a burst of
    /// one kind can't starve the other.
    fn db_op_landed(&mut self, finished: DbOp) -> iced::Task<Message> {
        if self.db.running != Some(finished) {
            // Nothing of this kind was running (a stray completion): leave
            // whatever is running alone — it frees the gate when it lands.
            warn!(
                finished = finished.name(),
                running = self.db.running.map_or("idle", DbOp::name),
                "wallet file: completion for an op that wasn't running",
            );
            return iced::Task::none();
        }
        self.db.running = None;
        let order = if finished == DbOp::WalletSave {
            [DbOp::ContactsLoad, DbOp::ContactsSave, DbOp::WalletSave]
        } else {
            [DbOp::WalletSave, DbOp::ContactsLoad, DbOp::ContactsSave]
        };
        for op in order {
            let task = match op {
                DbOp::WalletSave if std::mem::take(&mut self.db.wallet_save_queued) => {
                    self.persist_wallet("queued")
                }
                DbOp::ContactsLoad if std::mem::take(&mut self.db.contacts_load_queued) => {
                    self.start_contacts_load()
                }
                DbOp::ContactsSave => match self.db.contacts_save_queued.take() {
                    Some(contacts) => self.persist_contacts(contacts),
                    None => continue,
                },
                _ => continue,
            };
            if self.db.running.is_some() {
                return task;
            }
            // It couldn't start (no wallet or passphrase held, already
            // logged); the next queued op still may.
        }
        iced::Task::none()
    }

    /// Coarse state of the wallet-file gate for the GUI trace (`DbGate::name`).
    fn save_state_name(&self) -> String {
        self.db.name()
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
        // Hand the fresh dashboard the WalletConnect slot: it re-mirrors any
        // live sessions, puts reviews the old dashboard had open back in the
        // queue, re-sends answers stranded while no dashboard existed, and
        // pumps the queue.
        let wc_task = match &mut self.screen {
            Screen::Wallet(ws) => ws
                .set_wc_slot(self.wc_slot.clone())
                .map(Message::WalletDashboard),
            _ => iced::Task::none(),
        };
        // Load the Privacy Pools identity (once per session) and push it into
        // the fresh dashboard so the pool app can sync/prove immediately.
        self.load_pp_identity();
        debug!(
            active_index,
            addr = %address,
            built_in = ?started.elapsed(),
            "entered dashboard; verify+portfolio+ens fetch queued",
        );
        iced::Task::batch(vec![verify_task, portfolio_task, ens_task, wc_task])
    }

    // ── Privacy Pools identity plumbing ──────────────────────────────────────
    // The pool seed is a wallet-global secret separate from the account keys, so
    // the App owns it (like `passphrase`) and pushes the derived account into the
    // dashboard. Load is Argon2-gated, so it runs at most once per session.

    /// Load the pool seed (until a load succeeds) and push the derived account
    /// into the dashboard.
    ///
    /// Opens `wallet.redb` synchronously, outside the `DbGate`; the store's
    /// path lock makes it wait for whatever holds the file (a gated op, a
    /// vault batch) instead of failing on it. A load that fails anyway leaves
    /// `pp_loaded` false: the next dashboard entry (or the pool app's "Try
    /// again") loads again, and until then the pool app says it couldn't read
    /// the identity instead of offering to create one over it.
    fn load_pp_identity(&mut self) {
        self.load_pp_identity_with(wallet::load_pp_seed);
    }

    /// [`Self::load_pp_identity`] reading the seed with `load` (a test's stand-in for the store).
    fn load_pp_identity_with(&mut self, load: PpSeedLoad) {
        if !self.pp_loaded {
            match self.passphrase.as_ref().map(load) {
                Some(Ok(seed)) => {
                    self.pp_seed = seed;
                    self.pp_loaded = true;
                }
                // No wallet file yet — a fresh wallet whose first save hasn't
                // landed — so no seed in it either.
                Some(Err(wallet::WalletError::NotFound)) => self.pp_loaded = true,
                Some(Err(e)) => warn!(
                    error = %e,
                    "privacy pools: loading the saved pool seed failed — retried at the next \
                     dashboard entry"
                ),
                // Nothing to load with (only before a passphrase exists): no
                // seed this session can be read either way.
                None => self.pp_loaded = true,
            }
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
        let unreadable = !self.pp_loaded;
        if let Screen::Wallet(ws) = &mut self.screen {
            ws.set_pp_account(account);
            ws.set_pp_identity_unreadable(unreadable);
        }
    }

    /// The pool app's "Try again" after a failed seed load: load again now,
    /// and say so when it fails again (the card alone wouldn't change).
    fn retry_pp_identity(&mut self) -> iced::Task<Message> {
        self.retry_pp_identity_with(wallet::load_pp_seed)
    }

    fn retry_pp_identity_with(&mut self, load: PpSeedLoad) -> iced::Task<Message> {
        if !self.pp_loaded {
            self.load_pp_identity_with(load);
            if !self.pp_loaded {
                self.pool_error(POOL_IDENTITY_STILL_UNREAD.to_string());
            }
        }
        iced::Task::none()
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
            // A restore over an identity this session couldn't read replaced it.
            ws.set_pp_identity_unreadable(false);
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

    /// Why `save_pp_seed` must not run right now, if it mustn't: it opens
    /// `wallet.redb` synchronously, outside the `DbGate`, and would fail on
    /// the lock of a gated op still running. Asking again once it lands
    /// works (nothing gated can start while the synchronous save runs).
    fn pool_seed_write_blocked(&self) -> Option<String> {
        let running = self.db.running?;
        debug!(
            running = running.name(),
            "privacy pools: seed write deferred — wallet file busy"
        );
        Some("Kao is still writing your wallet file — try again in a moment.".to_string())
    }

    /// Generate a fresh pool identity, persist it, and show its backup phrase.
    ///
    /// Never over an existing one: refused while this session's seed load
    /// hasn't succeeded (the seed may be there, unread), and the store's
    /// `create_pp_seed` refuses a row that exists anyway.
    fn pool_create_identity(&mut self) -> iced::Task<Message> {
        let Some(pw) = self.passphrase.clone() else {
            self.pool_error("wallet is locked".into());
            return iced::Task::none();
        };
        if !self.pp_loaded {
            warn!("privacy pools: create refused — this session's seed load hasn't succeeded");
            self.pool_error(POOL_IDENTITY_UNREAD.to_string());
            return iced::Task::none();
        }
        if let Some(why) = self.pool_seed_write_blocked() {
            self.pool_error(why);
            return iced::Task::none();
        }
        let phrase = match wallet::generate_pp_mnemonic() {
            Ok(p) => p,
            Err(e) => {
                self.pool_error(e.to_string());
                return iced::Task::none();
            }
        };
        if let Err(e) = wallet::create_pp_seed(&phrase, &pw) {
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
        if let Some(why) = self.pool_seed_write_blocked() {
            self.pool_error(why);
            return iced::Task::none();
        }
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

    /// The toast for a wallet save that failed with `e`. It never points to the sealed-state
    /// reset: wallet saves don't depend on the data key (`save_descriptor` settles it after the
    /// commit), so an unreadable saved history can't be why a save failed, and the reset wouldn't
    /// fix it.
    fn wallet_save_failed_toast(e: &str) -> String {
        format!(
            "Kao couldn't save your wallet ({e}). Your latest change works for now but may be \
             gone after a restart."
        )
    }

    /// The user confirmed "Reset saved history and connections": the vault couldn't read the
    /// wallet file's sealed tables this session (`key_unavailable`), so nothing new is saved
    /// until they're reset. `reset` (`wallet::reset_sealed`) runs off the UI thread with the held
    /// passphrase and lands as `SealedReset`. One at a time, and only while there's something to
    /// reset.
    fn request_sealed_reset_with(&mut self, reset: SealedResetFn) -> iced::Task<Message> {
        if self.sealed_reset_running {
            debug!("sealed reset: one is already running");
            return iced::Task::none();
        }
        if !self.vault.unreadable().key_unavailable {
            debug!("sealed reset: the saved state is readable — nothing to reset");
            return iced::Task::none();
        }
        let Some(pw) = self.passphrase.clone() else {
            warn!("sealed reset refused: the wallet is locked");
            return iced::Task::none();
        };
        self.sealed_reset_running = true;
        info!("resetting the saved history and connections at the user's request");
        iced::Task::perform(run_sealed_reset(pw, reset), Message::SealedReset)
    }

    /// A reset landed: the vault adopts the key it minted (its mint cleared the tables, so this
    /// epoch's ids are free) and the panes stop saying nothing is saved; a failure is a toast.
    fn sealed_reset_landed(
        &mut self,
        result: Result<(wallet::DataKey, wallet::KeyOrigin), String>,
    ) -> iced::Task<Message> {
        self.sealed_reset_running = false;
        let (key, origin) = match result {
            Ok(minted) => minted,
            Err(e) => {
                error!(error = %e, "resetting the saved history and connections failed");
                return iced::Task::done(Message::WalletError(format!(
                    "Kao couldn't reset the saved history and connections ({e})."
                )));
            }
        };
        info!(
            ?origin,
            "saved history and connections reset: handing the vault the fresh key"
        );
        self.vault.set_key(key, origin);
        if let Screen::Wallet(ws) = &mut self.screen {
            ws.refresh_history_views();
        }
        if !self.vault.can_persist() {
            // Locked meanwhile (the next unlock reads the reset tables), or the vault
            // refused the key: nothing to tell.
            return iced::Task::none();
        }
        iced::Task::done(Message::Notice(
            "Kao reset the saved history and connections — it saves them again from now on."
                .to_string(),
        ))
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
        if wallet::wallet_exists() {
            return self.lock_wallet();
        }
        self.screen = Screen::SelectHardwareWallet(SelectHardwareWalletScreen::default());
        iced::Task::none()
    }

    /// Lock: forget the passphrase, the decrypted wallet and the pool seed,
    /// and land on the unlock screen.
    fn lock_wallet(&mut self) -> iced::Task<Message> {
        // The vault's epoch ends first: its records and data key leave memory
        // now, and nothing a runtime still does can reach the next unlock's.
        let flush = self.vault.lock();
        self.passphrase = None;
        self.wallet = None;
        self.pp_seed = None;
        self.pp_loaded = false;
        // Locking suspends WalletConnect: dapps stay connected (they aren't
        // told anything), the state goes to disk through `flush`, and the next
        // unlock restores it. Without a data key, the full teardown instead.
        let suspend = self.suspend_wc(flush);
        // The unlock screen holds the successor slot: its unlock waits for
        // this suspend (and the writer's drain) before reading the store.
        self.screen = Screen::Unlock(UnlockScreen::new(self.wc_slot.clone()));
        suspend
    }

    /// Lock path: replace the slot, close the old one, and end its runtime.
    /// With a data key (`flush.can_persist()`) it is suspended — waiting and
    /// in-review requests are answered 4900, sessions stay (no dapp hears a
    /// disconnect), and the final state is saved through `flush`. Without
    /// one, today's full teardown: every session is disconnected (dapps hear
    /// 6000), and the flush's drain is counted on its own. The next unlock
    /// gets a fresh slot.
    ///
    /// Both run on the runtime's own tokio handle, not inside the returned
    /// task, and the fresh slot (sharing the old one's teardown registry)
    /// keeps count of them: a quit right after the lock (iced then never
    /// polls this task again) waits for them, and so does the next unlock.
    fn suspend_wc(&mut self, flush: VaultFlush) -> iced::Task<Message> {
        let next = self.wc_slot.successor();
        let old = std::mem::replace(&mut self.wc_slot, next);
        match old.close() {
            Some(rt) => {
                // `spawn_teardown` / `spawn_suspend` mark it closed
                // synchronously, before any task runs: from here `before_send`
                // refuses, so a signature still in flight broadcasts nothing.
                // Suspend needs a data key to save into; without one, the
                // full teardown.
                let running = if flush.can_persist() {
                    old.spawn_suspend(rt, flush)
                } else {
                    let running = old.spawn_teardown(rt);
                    old.track_flush(flush);
                    running
                };
                iced::Task::perform(running, |_| Message::WcTornDown)
            }
            None => {
                old.track_flush(flush);
                iced::Task::none()
            }
        }
    }

    /// Drop back to the dashboard without going through setup again, using
    /// the signer the user had before they entered the add-account flow.
    /// Used when the user backs out of the SetupMethod / its sub-screens.
    /// Add `primary` plus any `siblings` to `wallet.safes`, persist the
    /// wallet, and route back to the dashboard.
    ///
    /// v1 (stage 3a) requires an existing wallet — Safes must be added
    /// in `AddAccount` context. Calling this with no loaded wallet
    /// surfaces a toast and bails (the storage layer would refuse
    /// anyway since a wallet with safes but no accounts can't be
    /// loaded back).
    ///
    /// A Safe already saved under the same `(address, chain_id)` is merged,
    /// not skipped (`WalletDescriptor::upsert_safe`): its new signer links
    /// are added, so adding a watch-only Safe again with your key links it.
    /// The Safe keeps one name on every chain (see `upsert_safes`). A
    /// notice says which entries were already there.
    fn save_safe_and_return_to_dashboard(
        &mut self,
        primary: crate::wallet::SafeDescriptor,
        siblings: Vec<crate::wallet::SafeDescriptor>,
    ) -> iced::Task<Message> {
        if self.passphrase.is_none() {
            return iced::Task::perform(
                async { "missing passphrase; cannot save Safe".to_string() },
                Message::WalletError,
            );
        }
        let Some(wallet) = self.wallet.as_mut() else {
            return iced::Task::perform(
                async { "no wallet loaded; add an account before adding a Safe".to_string() },
                Message::WalletError,
            );
        };
        let notice = upsert_safes(wallet, std::iter::once(primary).chain(siblings));
        let save = self.persist_wallet("add Safe");
        let mut tasks = vec![save, self.cancel_add_account()];
        tasks.extend(notice.map(|msg| iced::Task::done(Message::Notice(msg))));
        iced::Task::batch(tasks)
    }

    /// Process the post-unlock Safe-refresh batch. Each successful
    /// refresh lands on the live entry with the same `(address,
    /// chain_id)` and updates only its cached on-chain fields; any
    /// user-facing change summaries are collected. After the batch:
    /// - if any diff was non-empty (or the unlock repair left the Safes
    ///   dirty), save the wallet once for the whole batch
    /// - if any user-facing alerts collected, surface them as a toast
    /// - push the updated safes vec into the WalletScreen so its
    ///   dropdown stops rendering stale labels
    ///
    /// Never by position, never the whole descriptor: the batch was
    /// spawned from a snapshot taken at unlock, and a Helios first sync
    /// can keep it in flight for a while. A Safe removed, renamed,
    /// relinked or re-pointed meanwhile must stay that way — a positional
    /// whole-slot write would resurrect a removed Safe onto its
    /// neighbour's slot and revert names, links and service URLs.
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
        for (spawn_idx, result) in results {
            let (fresh, diff) = match result {
                Ok(refreshed) => refreshed,
                Err(e) => {
                    warn!(safe_idx = spawn_idx, error = %e, "Safe refresh failed");
                    continue;
                }
            };
            let Some(live_idx) = wallet.safe_index(fresh.address, fresh.chain_id) else {
                // Removed between spawn and result — nothing to land on.
                debug!(
                    safe_idx = spawn_idx,
                    "Safe refresh result dropped: Safe no longer in the wallet",
                );
                continue;
            };
            let slot = &wallet.safes[live_idx];
            // Resolve linked-signer addresses from the LIVE entry so
            // summarize can tell apart "your owner removed" from "someone
            // else's owner removed" even if the links moved since unlock.
            let linked_addrs: Vec<alloy::primitives::Address> = slot
                .linked_signer_indices
                .iter()
                .filter_map(|i| wallet.accounts.get(*i as usize))
                .filter_map(wallet::account_address)
                .collect();
            let mut summarized = crate::safe::summarize_user_facing_changes(&diff, &linked_addrs);
            if !summarized.is_empty() {
                // Prefix each alert with the Safe's current name so a
                // user with multiple Safes can tell which one changed.
                let safe_name = slot.display_name(live_idx);
                for s in summarized.drain(..) {
                    alerts.push(format!("{safe_name}: {s}"));
                }
            }
            if !diff.is_empty() {
                any_changed = true;
            }
            wallet.safes[live_idx].refresh_onchain_from(&fresh);
        }

        // Build the follow-up tasks: push the updated safes into the
        // dashboard, persist if anything changed, surface a toast if
        // we collected alerts.
        let updated_safes = wallet.safes.clone();
        let push_to_dashboard = iced::Task::done(Message::WalletDashboard(
            crate::ui::wallet_dashboard::Message::SafesUpdated(updated_safes),
        ));
        let mut tasks = vec![push_to_dashboard];
        if any_changed || self.safes_dirty {
            tasks.push(self.persist_wallet("safe refresh"));
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
    fn set_safe_service_url(
        &mut self,
        address: [u8; 20],
        chain_id: u64,
        url: Option<String>,
    ) -> iced::Task<Message> {
        let Some(wallet) = self.wallet.as_mut() else {
            warn!("set_safe_service_url: no wallet loaded");
            return iced::Task::none();
        };
        let Some(index) = wallet.safe_index(address, chain_id) else {
            warn!(chain_id, "set_safe_service_url: Safe not in wallet");
            return iced::Task::none();
        };
        wallet.safes[index].tx_service_url = url;
        self.push_safes_and_persist("safe service url")
    }

    /// Rename the Safe at `address` on every chain it's saved on (header
    /// pencil in Safe mode, or Settings → Safes). Same shape as
    /// `set_safe_service_url`; the dashboard already mirrored the name, and
    /// the push re-syncs it with what will persist.
    fn rename_safe(&mut self, address: [u8; 20], name: Option<String>) -> iced::Task<Message> {
        let Some(wallet) = self.wallet.as_mut() else {
            warn!("rename_safe: no wallet loaded");
            return iced::Task::none();
        };
        if wallet.rename_safe(address, name) == 0 {
            warn!("rename_safe: Safe not in wallet");
            return iced::Task::none();
        }
        self.push_safes_and_persist("rename safe")
    }

    /// Forget the Safe keyed `(address, chain_id)` — that chain only
    /// (Settings → Safes, after its inline confirm). Nothing happens
    /// on-chain. The pushed list makes the dashboard drop it, leaving Safe
    /// mode if it was the active one; the dashboard refuses to ask for that
    /// while a signature is in flight with it.
    fn remove_safe(&mut self, address: [u8; 20], chain_id: u64) -> iced::Task<Message> {
        let Some(wallet) = self.wallet.as_mut() else {
            warn!("remove_safe: no wallet loaded");
            return iced::Task::none();
        };
        let Some(removed) = wallet.remove_safe(address, chain_id) else {
            warn!(chain_id, "remove_safe: Safe not in wallet");
            return iced::Task::none();
        };
        info!(
            safe = %crate::wallet::short_address(removed.address()),
            chain_id,
            "removed Safe from wallet"
        );
        self.push_safes_and_persist("remove safe")
    }

    /// After a Safe edit to `self.wallet`: push the full list into the
    /// dashboard (`SafesUpdated` re-resolves its active Safe by key and
    /// reseeds an open Settings → Safes pane) and persist.
    fn push_safes_and_persist(&mut self, why: &'static str) -> iced::Task<Message> {
        let Some(wallet) = self.wallet.as_ref() else {
            return iced::Task::none();
        };
        let push = iced::Task::done(Message::WalletDashboard(
            WalletDashboardMessage::SafesUpdated(wallet.safes.clone()),
        ));
        let save = self.persist_wallet(why);
        iced::Task::batch(vec![push, save])
    }

    /// Rename any account (Settings → Accounts). `address` is the account
    /// the pane showed at `index`; if this list disagrees (it moved since),
    /// nothing is renamed rather than whichever account slid into the slot.
    /// The dashboard already mirrored the name, so nothing is pushed back.
    fn rename_account(
        &mut self,
        index: usize,
        address: alloy::primitives::Address,
        name: Option<String>,
    ) -> iced::Task<Message> {
        let Some(wallet) = self.wallet.as_mut() else {
            warn!("rename account: no wallet loaded");
            return iced::Task::none();
        };
        let Some(account) = wallet
            .accounts
            .get_mut(index)
            .filter(|a| wallet::account_address(a) == Some(address))
        else {
            warn!(
                index,
                "rename account: that position no longer holds that account"
            );
            return iced::Task::none();
        };
        account.set_name(name);
        self.persist_wallet("rename account")
    }

    /// Forget the account at `index` (Settings → Accounts, after its inline
    /// confirm). Nothing happens on-chain; a `Local` account's key is
    /// forgotten (its old ciphertext may linger in redb's freed pages).
    ///
    /// Refused — with a toast, changing nothing — while a signature is in
    /// flight or under review (the dashboard refuses first; this is the
    /// backstop), when `index` no longer holds `address`, and for the
    /// wallet's last account. Otherwise `WalletDescriptor::remove_account`
    /// remaps every index-based reference in one edit, the wallet persists,
    /// and the dashboard catches up:
    ///
    /// * the active account went → rebuild the dashboard for the account
    ///   that took its place (`enter_active_from_wallet`, keeping the nav)
    ///   and reopen Settings → Accounts, where the user was;
    /// * any other account went → update the live dashboard in place via
    ///   `AccountsUpdated`. Same signer, so a connected Ledger/Trezor stays
    ///   connected and the open pane stays open.
    fn remove_account(
        &mut self,
        index: usize,
        address: alloy::primitives::Address,
    ) -> iced::Task<Message> {
        if let Screen::Wallet(screen) = &self.screen
            && screen.is_signing_or_reviewing()
        {
            warn!("remove account refused: signing op in flight");
            return iced::Task::done(Message::WalletError(
                "Kao is signing right now — finish or cancel that first, then remove the account."
                    .to_string(),
            ));
        }
        let Some(wallet) = self.wallet.as_mut() else {
            warn!("remove account: no wallet loaded");
            return iced::Task::none();
        };
        if wallet.accounts.get(index).and_then(wallet::account_address) != Some(address) {
            warn!(
                index,
                "remove account refused: that position no longer holds that account"
            );
            return iced::Task::done(Message::WalletError(
                "Your account list changed before that went through — nothing was removed. \
                 Try again."
                    .to_string(),
            ));
        }
        // `active()`'s clamp, so a stale stored index can't misroute this.
        let was_active = wallet.active_index.min(wallet.accounts.len() - 1) == index;
        let removed = match wallet.remove_account(index) {
            Ok(removed) => removed,
            Err(e) => {
                warn!(error = %e, "remove account refused");
                return iced::Task::done(Message::WalletError(e.to_string()));
            }
        };
        info!(
            index,
            account = ?removed.address.map(wallet::short_address),
            unlinked_safes = removed.unlinked_safes.len(),
            left_without_signing_key = removed.left_without_signing_key.len(),
            was_active,
            "removed account from wallet",
        );
        let notice = removal_notice(wallet, &removed);
        self.pending_signer = None;
        let save = self.persist_wallet("remove account");
        let dashboard = if was_active {
            let nav = match &self.screen {
                Screen::Wallet(screen) => Some(screen.current_nav()),
                _ => None,
            };
            let enter = self.enter_active_from_wallet(nav);
            if let Screen::Wallet(screen) = &mut self.screen {
                screen.open_accounts_settings();
            }
            enter
        } else if let (Screen::Wallet(screen), Some(wallet)) =
            (&mut self.screen, self.wallet.as_ref())
        {
            // Applied now rather than via `Task::done`, so no message can
            // reach the App while the dashboard still holds the old
            // positions. `AccountsUpdated` never yields an outcome.
            let (task, _) = screen.update(WalletDashboardMessage::AccountsUpdated {
                accounts: wallet.accounts.clone(),
                safes: wallet.safes.clone(),
                active_index: wallet.active_index,
            });
            task.map(Message::WalletDashboard)
        } else {
            iced::Task::none()
        };
        iced::Task::batch(vec![
            save,
            dashboard,
            iced::Task::done(Message::Notice(notice)),
        ])
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
                let screen = SafeOnboardingScreen::new(self.network.clone(), existing)
                    .with_existing_safes(self.existing_safes_snapshot());
                self.screen = Screen::SafeOnboarding(screen);
                focus_widget(crate::ui::safe_onboarding::ADDRESS_INPUT_ID)
                    .map(Message::SafeOnboarding)
            }
        }
    }

    /// Snapshot of the wallet's accounts in the shape SafeOnboarding's
    /// Review step needs. Returns an empty Vec when no wallet is
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
                                view_only: matches!(acc, AccountDescriptor::ViewOnly { .. }),
                            }
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Snapshot of the wallet's saved Safes (name and links per `(address,
    /// chain_id)`) for SafeOnboarding's Review. Empty when no wallet is
    /// loaded.
    fn existing_safes_snapshot(&self) -> Vec<crate::ui::safe_onboarding::ExistingSafe> {
        self.wallet.as_ref().map_or_else(Vec::new, |w| {
            w.safes
                .iter()
                .map(crate::ui::safe_onboarding::ExistingSafe::from)
                .collect()
        })
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

        let Some(wallet) = self.wallet.as_mut() else {
            warn!("finish_add_nested_safe: no wallet loaded");
            stash.apply_signer_import_error("No wallet loaded — try again.".to_string());
            self.screen = Screen::SafeOnboarding(*stash);
            return iced::Task::none();
        };
        // Same merge-not-skip as the top-level add.
        let notice = upsert_safes(wallet, std::iter::once(primary).chain(siblings));
        let save = self.persist_wallet("add nested Safe");

        stash.apply_added_nested_safe(primary_addr);
        self.screen = Screen::SafeOnboarding(*stash);
        let mut tasks = vec![save];
        tasks.extend(notice.map(|msg| iced::Task::done(Message::Notice(msg))));
        iced::Task::batch(tasks)
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
        self.wallet = Some(wallet);
        let save = self.persist_wallet("add Safe signer");

        let added = crate::ui::safe_onboarding::ExistingAccount {
            account_idx: new_idx,
            address,
            label,
            // Only key-bearing imports reach the add-signer sub-flow.
            view_only: false,
        };
        // Inside a nested-Safe sub-flow the parent screen(s) are still
        // parked below this one, holding account snapshots from before the
        // import. Tell each, so a parent whose Safe the new key also owns
        // lists and ticks it instead of reading watch-only and offering
        // the key as unclaimed (whose import would then be refused as a
        // duplicate).
        if !self.pending_add_signer.is_empty() {
            for parked in &mut self.pending_add_signer {
                parked.stash.note_account(added.clone());
            }
            debug!(
                parked = self.pending_add_signer.len(),
                "add Safe signer: parent screens told about the new account"
            );
        }
        stash.apply_added_signer(added);
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
        let save = self.persist_wallet("switch account");
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
        self.persist_wallet("rename account")
    }

    /// Take over a freshly unlocked wallet: hold the passphrase for the
    /// session, repair Safes saved before sibling chains inherited signer
    /// links, enter the dashboard, and kick off the contacts load and the
    /// Safe refresh.
    fn adopt_unlocked_wallet(
        &mut self,
        passphrase: SecretString,
        unlocked: Arc<wallet::Unlocked>,
    ) -> iced::Task<Message> {
        let wallet::Unlocked {
            mut descriptor,
            data_key,
            key_status,
            sealed,
        } = Arc::unwrap_or_clone(unlocked);
        // A key row that was there but unreadable (`Lost`), or one the unlock
        // couldn't write (no key, nothing wrong reading): a wallet save mints
        // the key, and nothing else would run one this session — without it,
        // what the vault records is gone at the next lock. A key the storage
        // couldn't be read for (`Unavailable`) is left alone: a save would
        // find the same key, which this epoch must not adopt.
        let mint_key = key_status == wallet::KeyStatus::Lost
            || (data_key.is_none() && key_status == wallet::KeyStatus::Ok);
        // Hold the passphrase for the unlocked session so we
        // can re-save the wallet file on add/switch account.
        self.passphrase = Some(passphrase);
        // The vault's epoch starts before the dashboard is built, so its
        // WalletConnect slot sees this unlock's saved state.
        self.vault.unlock(data_key, key_status, sealed);
        // Repair BEFORE the refresh below snapshots the Safes, so the
        // snapshot (and the dashboard) already carry the links. Only a
        // wallet saved before the repair shipped gets it, once: the marker
        // flips with it, links repaired or not, and must reach disk.
        // Not saved here — the contacts load takes the file first. The
        // refresh completion saves it (`safes_dirty`), or any earlier
        // `persist_wallet`; if neither happens this session, the repair
        // just runs again next unlock.
        self.safes_dirty = match descriptor.repair_sibling_signer_links_once() {
            None => false,
            Some(repaired) => {
                info!(
                    count = repaired.len(),
                    positions = ?repaired,
                    "unlock: one-time repair of sibling-chain Safes saved watch-only",
                );
                true
            }
        };
        self.wallet = Some(descriptor);
        // Enter first: its one synchronous pool-seed read must run before
        // the gated contacts load below opens the file.
        let enter = self.enter_active_from_wallet(None);
        let load_contacts = self.start_contacts_load();
        // Queued behind the contacts load; it lands as `WalletSaved` with
        // the minted key, which the vault adopts.
        let mint = if mint_key {
            info!(?key_status, "unlock: no data key — a wallet save mints one");
            self.persist_wallet("mint data key")
        } else {
            iced::Task::none()
        };
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
        iced::Task::batch(vec![enter, load_contacts, mint, refresh_safes])
    }

    /// The create-password screen; `acquire` takes the instance lock before a new wallet's
    /// session starts (`wallet::acquire_instance_lock`, or a test's stand-in).
    fn create_password_with(
        &mut self,
        msg: CreatePasswordMessage,
        acquire: crate::ui::unlock::AcquireInstanceLock,
    ) -> iced::Task<Message> {
        let Screen::CreatePassword(screen) = &mut self.screen else {
            return iced::Task::none();
        };
        let (cmd, outcome) = screen.update(msg);
        if let Some(CreatePasswordOutcome::Created(passphrase)) = outcome {
            // A second Kao process on the same wallet file would write
            // over this one's history and saved WalletConnect state.
            if crate::ui::unlock::claim_instance_with(acquire).is_err() {
                screen.set_error(crate::ui::unlock::ALREADY_OPEN.to_string());
                return cmd.map(Message::CreatePassword);
            }
            self.passphrase = Some(passphrase);
            // A fresh wallet's vault epoch starts keyless: nothing is on
            // disk to seal into until the first wallet save mints the
            // data key (`WalletSaved`), and what it records meanwhile
            // waits in memory for that key.
            self.vault
                .unlock(None, wallet::KeyStatus::Ok, wallet::SealedLoad::default());
            self.setup_context = Some(SetupContext::FreshWallet);
            self.screen = Screen::NetworkSetup(NetworkSetupScreen::new(WizardMode::Onboarding));
            return iced::Task::none();
        }
        cmd.map(Message::CreatePassword)
    }

    pub fn update(&mut self, message: Message) -> iced::Task<Message> {
        crate::trace_msg!("app", &message);
        // Diff the coarse app state across the dispatch so every transition
        // is logged no matter which arm (or helper) performed it.
        let screen_before = self.screen.name();
        let toast_before = self.toast.is_some();
        let active_before = self.wallet.as_ref().map(|w| w.active_index);
        let accounts_before = self.wallet.as_ref().map(|w| w.accounts.len());
        let safes_before = self.wallet.as_ref().map(|w| w.safes.len());
        let save_before = self.save_state_name();

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
        let safes_after = self.wallet.as_ref().map(|w| w.safes.len());
        if safes_before != safes_after {
            crate::trace::state("app", "safes", fmt_opt(safes_before), fmt_opt(safes_after));
        }
        let save_after = self.save_state_name();
        if save_before != save_after {
            crate::trace::state("app", "wallet_db", save_before, save_after);
        }
        task
    }

    fn update_inner(&mut self, message: Message) -> iced::Task<Message> {
        match message {
            // ── CreatePassword ──────────────────────────────────────
            Message::CreatePassword(msg) => self.create_password_with(msg, self.create_acquire),

            // ── Unlock ──────────────────────────────────────────────
            Message::Unlock(msg) => {
                let Screen::Unlock(screen) = &mut self.screen else {
                    return iced::Task::none();
                };
                let (cmd, outcome) = screen.update(msg);
                if let Some(UnlockOutcome::Unlocked {
                    passphrase,
                    unlocked,
                }) = outcome
                {
                    return self.adopt_unlocked_wallet(passphrase, unlocked);
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
                        // The passphrase goes, so the vault's (keyless) epoch
                        // ends with it; its drain counts until it's done.
                        let flush = self.vault.lock();
                        self.wc_slot.track_flush(flush);
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
                            // empty snapshot means Review shows "none of
                            // your accounts own this Safe" and the user
                            // proceeds watch-only or backs out.
                            let existing = self.existing_accounts_snapshot();
                            self.screen = Screen::SafeOnboarding(
                                SafeOnboardingScreen::new(self.network.clone(), existing)
                                    .with_existing_safes(self.existing_safes_snapshot()),
                            );
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
                    // A dashboard message landing off-screen (locked, or in a
                    // hardware reconnect / add-account flow). Only a finished
                    // WalletConnect signature needs anything: its dapp is
                    // answered from here, so it never waits on a dashboard
                    // that may not come back.
                    crate::ui::wallet_dashboard::handle_orphan_message(msg, &self.wc_slot);
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
                        let save = self.persist_contacts(new_contacts);
                        iced::Task::batch(vec![cmd.map(Message::WalletDashboard), save])
                    }
                    Some(WalletDashboardOutcome::SetSafeServiceUrl {
                        address,
                        chain_id,
                        url,
                    }) => {
                        let save = self.set_safe_service_url(address, chain_id, url);
                        iced::Task::batch(vec![cmd.map(Message::WalletDashboard), save])
                    }
                    Some(WalletDashboardOutcome::RenameSafe { address, name }) => {
                        let save = self.rename_safe(address, name);
                        iced::Task::batch(vec![cmd.map(Message::WalletDashboard), save])
                    }
                    Some(WalletDashboardOutcome::RemoveSafe { address, chain_id }) => {
                        let save = self.remove_safe(address, chain_id);
                        iced::Task::batch(vec![cmd.map(Message::WalletDashboard), save])
                    }
                    Some(WalletDashboardOutcome::RenameAccount {
                        index,
                        address,
                        name,
                    }) => {
                        let save = self.rename_account(index, address, name);
                        iced::Task::batch(vec![cmd.map(Message::WalletDashboard), save])
                    }
                    Some(WalletDashboardOutcome::RemoveAccount { index, address }) => {
                        let removal = self.remove_account(index, address);
                        iced::Task::batch(vec![cmd.map(Message::WalletDashboard), removal])
                    }
                    Some(WalletDashboardOutcome::PoolCreateIdentity) => {
                        let t = self.pool_create_identity();
                        iced::Task::batch(vec![cmd.map(Message::WalletDashboard), t])
                    }
                    Some(WalletDashboardOutcome::PoolRetryIdentity) => {
                        let t = self.retry_pp_identity();
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
                    Some(WalletDashboardOutcome::ResetSealedHistory) => {
                        let t = self.request_sealed_reset_with(wallet::reset_sealed);
                        iced::Task::batch(vec![cmd.map(Message::WalletDashboard), t])
                    }
                    Some(WalletDashboardOutcome::Notice(s)) => iced::Task::batch(vec![
                        cmd.map(Message::WalletDashboard),
                        iced::Task::done(Message::Notice(s)),
                    ]),
                    None => cmd.map(Message::WalletDashboard),
                }
            }

            // ── Background wallet save ──────────────────────────────
            Message::WalletSaved(result) => {
                // Whatever queued meanwhile goes out now — for wallet edits
                // made while that save ran, one save of the latest wallet
                // covers them all.
                let next = self.db_op_landed(DbOp::WalletSave);
                let e = match result {
                    Ok(None) => {
                        // The descriptor is on disk; the key row couldn't be
                        // settled (the store logged why). The vault keeps
                        // whatever key it has, or stays keyless.
                        debug!("wallet saved without a data key: the vault is left alone");
                        return next;
                    }
                    Ok(Some((key, origin))) => {
                        // A keyless vault epoch (a fresh wallet's, or one whose
                        // unlock couldn't read the data key) gets the key the
                        // save just made sure of: what it buffered reaches disk.
                        // The vault decides whether the key's origin lets this
                        // epoch adopt it.
                        if self.vault.is_unlocked() && !self.vault.can_persist() {
                            info!(?origin, "wallet saved: handing the vault its data key");
                            self.vault.set_key(key, origin);
                            // The history panes and the WalletConnect pane say
                            // whether Kao keeps what it records: tell them now.
                            if let Screen::Wallet(ws) = &mut self.screen {
                                ws.refresh_history_views();
                            }
                        }
                        return next;
                    }
                    Err(e) => e,
                };
                error!(error = %e, "wallet save error");
                if self.db.wallet_save_pending() {
                    // A follow-up writes everything this one held, so it
                    // gets to report; one transient failure isn't worth a
                    // toast if the retry lands.
                    return next;
                }
                iced::Task::batch(vec![
                    next,
                    iced::Task::done(Message::WalletError(Self::wallet_save_failed_toast(&e))),
                ])
            }

            // ── User-requested reset of the sealed tables ───────────
            Message::SealedReset(result) => self.sealed_reset_landed(result),

            // ── Post-unlock Safe refresh batch ──────────────────────
            Message::SafesRefreshed(results) => self.handle_safes_refreshed(results),

            // ── Contacts background load/save ───────────────────────
            Message::ContactsLoaded(result) => {
                let next = self.db_op_landed(DbOp::ContactsLoad);
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
                        return iced::Task::batch(vec![
                            next,
                            iced::Task::done(Message::WalletError(format!(
                                "Couldn't read your contacts ({e}). They're still on disk — Kao \
                                 won't save over them this session. Restart to try again."
                            ))),
                        ]);
                    }
                }
                next
            }
            Message::ContactsSaved(result) => {
                let next = self.db_op_landed(DbOp::ContactsSave);
                if let Err(e) = result {
                    error!(error = %e, "contacts save error");
                }
                next
            }

            // ── Error handling ──────────────────────────────────────
            Message::WalletError(e) => {
                error!(error = %e, "wallet error");
                self.show_toast(ToastKind::Error, e)
            }
            Message::Notice(msg) => {
                info!(notice = %msg, "notice");
                self.show_toast(ToastKind::Notice, msg)
            }
            Message::DismissToast { generation } => {
                if self
                    .toast
                    .as_ref()
                    .is_some_and(|s| s.generation == generation)
                {
                    self.toast = None;
                }
                iced::Task::none()
            }

            // ── Quit ────────────────────────────────────────────────
            Message::CloseRequested(window) => match self.close_requested() {
                QuitStep::Now => {
                    info!(?window, "close requested — quitting now");
                    iced::exit()
                }
                QuitStep::After(wait) => {
                    info!(
                        ?window,
                        "quit requested — saving WalletConnect and history first"
                    );
                    iced::Task::perform(wait, |()| Message::Exit)
                }
            },
            Message::WcTornDown => iced::Task::none(),
            Message::Exit => iced::exit(),
        }
    }

    /// What a close request does: exit at once, or once `wait` — what must finish first — has.
    /// A second close while the first one's wait runs means "now".
    fn close_requested(&mut self) -> QuitStep<impl Future<Output = ()> + Send + use<>> {
        if self.closing {
            return QuitStep::Now;
        }
        match self.begin_quit() {
            None => QuitStep::Now,
            Some(wait) => QuitStep::After(wait),
        }
    }

    /// The first close request: nothing starts from here on (`closing`, and
    /// the slot closes for good), the vault's epoch ends, and the slot ends
    /// its runtime — suspended, so its dapps reconnect at the next unlock.
    /// Returns what the process must wait for before it exits, bounded by
    /// QUIT_TEARDOWN_BUDGET so a dead relay can't trap the window open:
    /// everything still running — this suspend and its final save, a lock's
    /// teardown, a retire's session deletes, a vault writer's drain. Exiting
    /// sooner would cut them short. `None` when nothing runs.
    fn begin_quit(&mut self) -> Option<impl Future<Output = ()> + Send + use<>> {
        self.closing = true;
        let flush = self.vault.lock();
        self.wc_slot.quit(flush)
    }

    /// Put `msg` in the toast slot (replacing whatever is there) and
    /// schedule its auto-dismiss.
    fn show_toast(&mut self, kind: ToastKind, msg: String) -> iced::Task<Message> {
        self.toast_gen = self.toast_gen.wrapping_add(1);
        let generation = self.toast_gen;
        self.toast = Some(ToastState {
            msg,
            generation,
            kind,
        });
        // Generation-tagged so a late firing can't clear a newer toast:
        // replacement bumps the counter, and the stale `DismissToast`
        // arrives with `g != self.toast_gen` and no-ops.
        iced::Task::perform(
            async move {
                tokio::time::sleep(std::time::Duration::from_secs(TOAST_LIFETIME_SECS)).await;
                generation
            },
            |generation| Message::DismissToast { generation },
        )
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
                stack![screen, toast_view(t, state)].into()
            }
        }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        // On every screen: `main` turns off iced's exit-on-close, so this is
        // the only way the window's close button quits.
        Subscription::batch([
            self.screen_subscription(),
            iced::window::close_requests().map(Message::CloseRequested),
        ])
    }

    fn screen_subscription(&self) -> Subscription<Message> {
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

/// Bottom-center toast for the latest error or notice. Auto-dismisses
/// after `TOAST_LIFETIME_SECS`; the ✕ chip on the right lets the user
/// clear it sooner. The container width is capped (`max_width(480)`) so
/// the toast looks like a chip on wide windows but still wraps cleanly
/// on narrow ones, and the rest of the overlay is `Space` so pointer
/// events on the screen below pass through.
///
/// An error is red with a ⚠; a notice reports something that went fine,
/// so it gets the positive accent, a ✓ and body-colored text instead.
fn toast_view<'a>(t: KaoTheme, state: &'a ToastState) -> Element<'a, Message> {
    let generation = state.generation;
    let (accent, glyph, msg_color) = match state.kind {
        ToastKind::Error => (t.down, "⚠", t.down),
        ToastKind::Notice => (t.up, "✓", t.text),
    };
    let dismiss = mouse_area(
        container(text("✕").size(13).color(accent).font(bold())).padding(Padding::from([2, 6])),
    )
    .on_press(Message::DismissToast { generation })
    .interaction(iced::mouse::Interaction::Pointer);

    let body = row![
        text(glyph).size(14).color(accent).font(bold()),
        Space::new().width(8),
        container(
            text(state.msg.as_str())
                .size(12)
                .color(msg_color)
                .font(bold())
        )
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
            background: Some(Background::Color(with_alpha(accent, 0.18))),
            border: Border {
                color: with_alpha(accent, 0.5),
                width: 1.0,
                radius: Radius::from(12),
            },
            text_color: Some(msg_color),
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
                Ok(Ok(saved)) => Ok(saved),
                Ok(Err(e)) => Err(e.to_string()),
                Err(join_err) => Err(format!("wallet save panicked: {join_err}")),
            };
            debug!(elapsed = ?started.elapsed(), ok = outcome.is_ok(), "save descriptor: done");
            outcome
        },
        Message::WalletSaved,
    )
}

/// `reset` (`wallet::reset_sealed`) on the blocking pool: it runs Argon2 to check the passphrase,
/// then waits for the store lock.
async fn run_sealed_reset(
    passphrase: SecretString,
    reset: SealedResetFn,
) -> Result<(wallet::DataKey, wallet::KeyOrigin), String> {
    match tokio::task::spawn_blocking(move || reset(&passphrase)).await {
        Ok(Ok(minted)) => Ok(minted),
        Ok(Err(e)) => Err(e.to_string()),
        Err(join_err) => Err(format!("reset task panicked: {join_err}")),
    }
}

/// Fold onboarded Safe descriptors into `wallet` (`upsert_safe` each) and
/// return the notice for the ones that were already saved — `None` when
/// every one was new.
///
/// One Safe address keeps one name on every chain. A chain added without a
/// name takes the saved one (`upsert_safe`); a name the user gave in Review
/// that differs from a saved entry's is their explicit choice, so it
/// renames the Safe everywhere (`rename_safe`). Review prefills the saved
/// name, so leaving it untouched renames nothing.
fn upsert_safes(
    wallet: &mut WalletDescriptor,
    incoming: impl IntoIterator<Item = wallet::SafeDescriptor>,
) -> Option<String> {
    let mut added = 0usize;
    // (position, newly linked) for each entry that was already saved;
    // worded after the renames so the notice uses the final name.
    let mut already: Vec<(usize, usize)> = Vec::new();
    let mut renames: Vec<([u8; 20], String)> = Vec::new();
    for safe in incoming {
        if let Some(name) = safe.name()
            && !renames.iter().any(|(address, _)| *address == safe.address)
            && wallet
                .safes
                .iter()
                .any(|s| s.address == safe.address && s.name() != Some(name))
        {
            renames.push((safe.address, name.to_owned()));
        }
        match wallet.upsert_safe(safe) {
            SafeUpsert::Added => added += 1,
            SafeUpsert::Merged {
                index,
                newly_linked,
            } => already.push((index, newly_linked)),
            SafeUpsert::Unchanged(index) => already.push((index, 0)),
        }
    }
    for (address, name) in renames {
        let renamed = wallet.rename_safe(address, Some(name));
        debug!(renamed, "add Safe: Review name applied to every chain");
    }
    let notes: Vec<String> = already
        .into_iter()
        .map(|(index, newly_linked)| match newly_linked {
            0 => format!("{} is already in your wallet", safe_label(wallet, index)),
            1 => format!(
                "{} was already in your wallet — linked 1 signer",
                safe_label(wallet, index)
            ),
            n => format!(
                "{} was already in your wallet — linked {n} signers",
                safe_label(wallet, index)
            ),
        })
        .collect();
    debug!(
        added,
        already_saved = notes.len(),
        total = wallet.safes.len(),
        "Safe(s) saved",
    );
    (!notes.is_empty()).then(|| notes.join(" · "))
}

/// "Treasury on Base" — how the add-Safe toasts name `wallet.safes[index]`.
fn safe_label(wallet: &WalletDescriptor, index: usize) -> String {
    let Some(safe) = wallet.safes.get(index) else {
        return format!("Safe {}", index + 1);
    };
    let chain = crate::chain::Chain::from_chain_id(safe.chain_id)
        .map(|c| c.display_name().to_string())
        .unwrap_or_else(|| format!("chain {}", safe.chain_id));
    format!("{} on {chain}", safe.display_name(index))
}

/// The toast after an account removal: "Removed Account 2", plus each Safe
/// it left without a key Kao can sign with ("· Treasury on Base is
/// watch-only now") — a leftover view-only or ex-owner link doesn't count.
/// `wallet` is the wallet after the removal.
fn removal_notice(wallet: &WalletDescriptor, removed: &wallet::RemovedAccount) -> String {
    let mut notice = format!("Removed {}", removed.name);
    for &(address, chain_id) in &removed.left_without_signing_key {
        if let Some(index) = wallet.safe_index(address, chain_id) {
            notice.push_str(&format!(
                " · {} is watch-only now",
                safe_label(wallet, index)
            ));
        }
    }
    notice
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
    use crate::ui::wallet_dashboard::{SignTag, WcSignKind};
    use crate::walletconnect::runtime::WcRuntime;
    use crate::walletconnect::{WcKey, codes as wc_codes, testkit};
    use alloy::primitives::B256;

    fn build_app(screen: Screen) -> App {
        let network: Arc<dyn BalanceFetcher> = Arc::new(MockFetcher::new());
        let vault = Vault::new();
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
            db: DbGate::default(),
            safes_dirty: false,
            wc_slot: WcSlot::with_vault(vault.clone()),
            vault,
            closing: false,
            sealed_reset_running: false,
            // Tests never take the real process lock (it would leave a lock file in the
            // per-process sandbox); `App::new`'s wiring is pinned on its own.
            create_acquire: || Ok(()),
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
            sibling_links_repaired: true,
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
        // Skip the pool-seed load, which would open the real wallet file.
        app.pp_loaded = true;
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
        // Skip the pool-seed load, which would open the real wallet file.
        app.pp_loaded = true;
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
        // Skip the pool-seed load, which would open the real wallet file.
        app.pp_loaded = true;
        app.setup_context = Some(SetupContext::FreshWallet);
        let (signer, account) = local_signer_and_account(1);
        let _task = app.save_account_and_enter_dashboard(account, signer);
        let w = app.wallet.as_ref().unwrap();
        assert_eq!(w.accounts.len(), 1);
        assert_eq!(w.active_index, 0);
        assert!(app.setup_context.is_none());
        assert!(matches!(app.screen, Screen::Wallet(_)));
        assert_eq!(
            app.save_state_name(),
            "saving",
            "the first save creates the file"
        );
    }

    #[test]
    fn begin_add_account_sets_context_and_navigates_to_setup() {
        let mut app = build_app(placeholder_screen());
        let _ = app.begin_add_account();
        assert!(matches!(app.setup_context, Some(SetupContext::AddAccount)));
        assert!(matches!(app.screen, Screen::SetupMethod(_)));
    }

    // ── Wallet persistence, Safe refresh, add-Safe merge ────────────────

    fn test_pw() -> SecretString {
        SecretString::new("pw".to_string().into_boxed_str())
    }

    /// Safe at `[byte; 20]` on `chain_id`, owned by `owners`, linking
    /// `linked`.
    fn safe_at(
        byte: u8,
        chain_id: u64,
        owners: Vec<alloy::primitives::Address>,
        linked: Vec<u32>,
        sibling_chains: Vec<u64>,
    ) -> wallet::SafeDescriptor {
        wallet::SafeDescriptor {
            name: None,
            chain_id,
            address: [byte; 20],
            version: "1.4.1".into(),
            trust: wallet::SafeTrust::Canonical,
            threshold: 1,
            owners: owners.into_iter().map(|a| a.into_array()).collect(),
            modules: Vec::new(),
            guard: None,
            fallback_handler: None,
            module_guard: None,
            linked_signer_indices: linked,
            sibling_chains,
            cached_at: 10,
            tx_service_url: None,
        }
    }

    /// An unlocked App holding `wallet` and a passphrase. `pp_loaded` is
    /// set so entering the dashboard never opens the real wallet file to
    /// look for a pool seed.
    fn unlocked_app(wallet: WalletDescriptor) -> App {
        let mut app = build_app(placeholder_screen());
        app.passphrase = Some(test_pw());
        app.pp_loaded = true;
        app.wallet = Some(wallet);
        app
    }

    fn wallet_of(
        accounts: Vec<AccountDescriptor>,
        safes: Vec<wallet::SafeDescriptor>,
    ) -> WalletDescriptor {
        WalletDescriptor {
            accounts,
            safes,
            active_index: 0,
            sibling_links_repaired: true,
        }
    }

    /// A refresh result for `snapshot` reporting a threshold change to
    /// `threshold`, the way `refresh_one` builds it: user fields copied
    /// from the snapshot, on-chain fields fresh.
    fn refreshed(
        snapshot: &wallet::SafeDescriptor,
        threshold: u32,
    ) -> Result<(wallet::SafeDescriptor, crate::safe::RefreshDiff), String> {
        let mut fresh = snapshot.clone();
        fresh.threshold = threshold;
        fresh.cached_at = 99;
        let diff = crate::safe::RefreshDiff {
            changes: vec![crate::safe::SafeChange::ThresholdChanged {
                from: snapshot.threshold,
                to: threshold,
            }],
        };
        Ok((fresh, diff))
    }

    #[test]
    fn persist_wallet_coalesces_saves_while_one_is_in_flight() {
        let (_, a0) = local_signer_and_account(1);
        let mut app = unlocked_app(WalletDescriptor::single(a0));

        let first = app.persist_wallet("test");
        assert!(first.units() > 0, "the first save is dispatched");
        assert_eq!(app.save_state_name(), "saving");

        // Overlapping requests only mark a follow-up — a second open of the
        // file would fail on redb's lock.
        assert_eq!(app.persist_wallet("test").units(), 0);
        assert_eq!(app.persist_wallet("test").units(), 0);
        assert_eq!(app.save_state_name(), "saving+queued");

        // The first save lands: exactly one follow-up goes out.
        let follow_up = app.update(Message::WalletSaved(Ok(Some((
            test_key(),
            wallet::KeyOrigin::Existing,
        )))));
        assert!(follow_up.units() > 0);
        assert_eq!(app.save_state_name(), "saving");

        // The follow-up lands: nothing left to do.
        let done = app.update(Message::WalletSaved(Ok(Some((
            test_key(),
            wallet::KeyOrigin::Existing,
        )))));
        assert_eq!(done.units(), 0);
        assert_eq!(app.save_state_name(), "idle");
    }

    #[test]
    fn persist_wallet_without_passphrase_dispatches_nothing() {
        let (_, a0) = local_signer_and_account(1);
        let mut app = build_app(placeholder_screen());
        app.wallet = Some(WalletDescriptor::single(a0));
        assert_eq!(app.persist_wallet("test").units(), 0);
        assert_eq!(app.save_state_name(), "idle");
    }

    #[test]
    fn rapid_account_switches_share_the_save_pipeline() {
        let (_, a0) = local_signer_and_account(1);
        let (_, a1) = local_signer_and_account(2);
        let mut app = unlocked_app(wallet_of(vec![a0, a1], vec![]));
        let _ = app.switch_account(1);
        let _ = app.switch_account(0);
        assert_eq!(
            app.save_state_name(),
            "saving+queued",
            "the second switch must not open the file while the first save holds it",
        );
        assert_eq!(app.wallet.as_ref().unwrap().active_index, 0);
    }

    #[test]
    fn wallet_save_error_toasts_unless_a_follow_up_retries() {
        let (_, a0) = local_signer_and_account(1);
        let mut app = unlocked_app(WalletDescriptor::single(a0));

        // Lone failure: the only task left is the toast.
        let _ = app.persist_wallet("test");
        let toast = app.update(Message::WalletSaved(Err("Database already open".into())));
        assert_eq!(app.save_state_name(), "idle");
        assert_eq!(toast.units(), 1);

        // Failure with a queued follow-up: the retry carries every edit
        // and reports for both, so no toast yet.
        let _ = app.persist_wallet("test");
        let _ = app.persist_wallet("test");
        let retry = app.update(Message::WalletSaved(Err("Database already open".into())));
        assert_eq!(
            app.save_state_name(),
            "saving",
            "the follow-up save went out"
        );
        assert_eq!(retry.units(), 1);
    }

    #[test]
    fn safe_refresh_lands_by_key_after_a_mid_refresh_removal() {
        let (_, a0) = local_signer_and_account(1);
        // Snapshot taken at unlock: [A, B, C]. The user then removed A.
        let snapshot = [
            safe_at(0xa1, 1, vec![], vec![0], vec![]),
            safe_at(0xb2, 1, vec![], vec![0], vec![]),
            safe_at(0xc3, 8453, vec![], vec![], vec![]),
        ];
        let mut app = unlocked_app(wallet_of(vec![a0], snapshot[1..].to_vec()));

        let batch = snapshot
            .iter()
            .enumerate()
            .map(|(i, s)| (i, refreshed(s, 2 + i as u32)))
            .collect();
        let _ = app.handle_safes_refreshed(batch);

        let w = app.wallet.as_ref().unwrap();
        let keys: Vec<_> = w.safes.iter().map(wallet::SafeDescriptor::key).collect();
        assert_eq!(
            keys,
            vec![([0xb2; 20], 1), ([0xc3; 20], 8453)],
            "the removed Safe must not come back, nor land on its neighbour's slot",
        );
        assert_eq!(w.safes[0].threshold, 3, "B got B's result");
        assert_eq!(w.safes[1].threshold, 4, "C got C's result");
        assert_eq!(w.safes[0].linked_signer_indices, vec![0]);
        assert!(w.safes[1].linked_signer_indices.is_empty());
        assert_eq!(app.save_state_name(), "saving", "diffs were non-empty");
    }

    #[test]
    fn safe_refresh_keeps_edits_made_while_it_was_in_flight() {
        let (_, a0) = local_signer_and_account(1);
        let owner = wallet::account_address(&a0).unwrap();
        let snapshot = safe_at(0x55, 1, vec![owner], vec![], vec![]);
        // Meanwhile: renamed, linked, re-pointed, sibling noted.
        let mut live = snapshot.clone();
        live.set_name(Some("Vault".into()));
        live.linked_signer_indices = vec![0];
        live.tx_service_url = Some("https://txs.example.org".into());
        live.sibling_chains = vec![8453];
        let mut app = unlocked_app(wallet_of(vec![a0], vec![live]));

        let (mut fresh, diff) = refreshed(&snapshot, 2).unwrap();
        fresh.owners.push([0x77; 20]);
        let _ = app.handle_safes_refreshed(vec![(0, Ok((fresh, diff)))]);

        let s = &app.wallet.as_ref().unwrap().safes[0];
        assert_eq!(s.name(), Some("Vault"));
        assert_eq!(s.linked_signer_indices, vec![0]);
        assert_eq!(s.tx_service_url.as_deref(), Some("https://txs.example.org"));
        assert_eq!(s.sibling_chains, vec![8453]);
        assert_eq!(s.threshold, 2, "on-chain fields still refresh");
        assert_eq!(s.owners, vec![owner.into_array(), [0x77; 20]]);
        assert_eq!(s.cached_at, 99);
    }

    #[test]
    fn safe_refresh_saves_only_for_real_changes_or_a_pending_repair() {
        let (_, a0) = local_signer_and_account(1);
        let safe = safe_at(0x55, 1, vec![], vec![0], vec![]);

        // Nothing changed on chain, nothing repaired: no save.
        let mut app = unlocked_app(wallet_of(vec![a0.clone()], vec![safe.clone()]));
        let quiet = (safe.clone(), crate::safe::RefreshDiff::default());
        let _ = app.handle_safes_refreshed(vec![(0, Ok(quiet))]);
        assert_eq!(app.save_state_name(), "idle");

        // The unlock repair left the Safes dirty: the refresh completion
        // saves them even though the batch itself changed nothing.
        let mut app = unlocked_app(wallet_of(vec![a0], vec![safe]));
        app.safes_dirty = true;
        let _ = app.handle_safes_refreshed(vec![(0, Err("rpc down".into()))]);
        assert_eq!(app.save_state_name(), "saving");
        assert!(!app.safes_dirty);
    }

    /// A wallet as a build before the one-time repair saved it: no marker.
    fn legacy(mut wallet: WalletDescriptor) -> WalletDescriptor {
        wallet.sibling_links_repaired = false;
        wallet
    }

    /// Unlock `wallet` into a fresh App, the way `Message::Unlock` does.
    fn unlock(wallet: WalletDescriptor) -> App {
        let mut app = build_app(placeholder_screen());
        app.pp_loaded = true;
        let _ = app.adopt_unlocked_wallet(test_pw(), unlocked_of(wallet));
        app
    }

    /// What `load_wallet` hands the unlock screen for `descriptor`: with its data key.
    fn unlocked_of(descriptor: WalletDescriptor) -> Arc<wallet::Unlocked> {
        unlocked_with(descriptor, Some(test_key()), wallet::KeyStatus::Ok)
    }

    fn unlocked_with(
        descriptor: WalletDescriptor,
        data_key: Option<wallet::DataKey>,
        key_status: wallet::KeyStatus,
    ) -> Arc<wallet::Unlocked> {
        Arc::new(wallet::Unlocked {
            descriptor,
            data_key,
            key_status,
            sealed: wallet::SealedLoad::default(),
        })
    }

    fn test_key() -> wallet::DataKey {
        wallet::DataKey::for_test([0x42; 32])
    }

    #[test]
    fn unlock_repairs_a_legacy_wallet_before_the_refresh_snapshot() {
        let (_, a0) = local_signer_and_account(1);
        let owner = wallet::account_address(&a0).unwrap();
        let mut app = unlock(legacy(wallet_of(
            vec![a0],
            vec![
                safe_at(0x55, 1, vec![owner], vec![0], vec![8453]),
                safe_at(0x55, 8453, vec![owner], vec![], vec![1]),
            ],
        )));

        let w = app.wallet.as_ref().unwrap();
        assert_eq!(w.safes[1].linked_signer_indices, vec![0], "Base repaired");
        assert!(w.sibling_links_repaired, "and marked, to be saved with it");
        assert!(app.safes_dirty);
        assert_eq!(
            app.save_state_name(),
            "loading_contacts",
            "no wallet save at unlock — the contacts load holds the file"
        );
        assert!(matches!(app.screen, Screen::Wallet(_)));

        // The contacts load lands first; the refresh completion then
        // persists the repair.
        let _ = app.update(Message::ContactsLoaded(Ok(Vec::new())));
        assert_eq!(app.save_state_name(), "idle");
        let _ = app.handle_safes_refreshed(Vec::new());
        assert_eq!(app.save_state_name(), "saving");
        assert!(!app.safes_dirty);
    }

    #[test]
    fn unlock_marks_a_legacy_wallet_repaired_even_with_nothing_to_repair() {
        let (_, a0) = local_signer_and_account(1);
        let app = unlock(legacy(wallet_of(
            vec![a0],
            vec![safe_at(0x55, 1, vec![], vec![0], vec![])],
        )));
        assert!(app.wallet.as_ref().unwrap().sibling_links_repaired);
        assert!(app.safes_dirty, "the marker itself must reach disk");
    }

    #[test]
    fn unlock_of_a_wallet_already_repaired_changes_nothing() {
        let (_, a0) = local_signer_and_account(1);
        let mut app = build_app(placeholder_screen());
        app.pp_loaded = true;
        app.safes_dirty = true; // stale flag from an earlier session
        let descriptor = wallet_of(vec![a0], vec![safe_at(0x55, 1, vec![], vec![0], vec![])]);
        let _ = app.adopt_unlocked_wallet(test_pw(), unlocked_of(descriptor));
        assert!(!app.safes_dirty);
    }

    #[test]
    fn a_chain_left_watch_only_on_purpose_stays_so_across_unlocks() {
        let (_, a0) = local_signer_and_account(1);
        let owner = wallet::account_address(&a0).unwrap();
        // Added on Mainnet + Base with the only key unticked: both
        // watch-only, listing each other.
        let mut app = unlocked_app(wallet_of(
            vec![a0],
            vec![
                safe_at(0x55, 1, vec![owner], vec![], vec![8453]),
                safe_at(0x55, 8453, vec![owner], vec![], vec![1]),
            ],
        ));
        app.setup_context = Some(SetupContext::AddAccount);
        // Added again with the key ticked and Base excluded: only Mainnet
        // comes in, linked. The upsert keeps Mainnet's `sibling_chains`, so
        // the pair now has exactly the legacy bug's shape.
        let _ = app.save_safe_and_return_to_dashboard(
            safe_at(0x55, 1, vec![owner], vec![0], vec![]),
            vec![],
        );
        let saved = app.wallet.clone().unwrap();
        assert_eq!(saved.safes[0].linked_signer_indices, vec![0]);
        assert_eq!(saved.safes[0].sibling_chains, vec![8453]);

        let next = unlock(saved);
        let w = next.wallet.as_ref().unwrap();
        assert!(
            w.safes[1].linked_signer_indices.is_empty(),
            "Base stays watch-only, as the user left it"
        );
        assert!(!next.safes_dirty);
    }

    // ── The wallet-file gate (`DbGate`) ──────────────────────────────

    fn contact(byte: u8) -> Contact {
        Contact {
            name: format!("Friend {byte}"),
            address: [byte; 20],
            kaomoji: String::new(),
            notes: String::new(),
            ens: None,
        }
    }

    #[test]
    fn a_refresh_landing_during_the_contacts_load_queues_its_save() {
        let (_, a0) = local_signer_and_account(1);
        let owner = wallet::account_address(&a0).unwrap();
        let wallet = legacy(wallet_of(
            vec![a0],
            vec![
                safe_at(0x55, 1, vec![owner], vec![0], vec![8453]),
                safe_at(0x55, 8453, vec![owner], vec![], vec![1]),
            ],
        ));

        for loaded in [Ok(vec![contact(1)]), Err("bad row".to_string())] {
            let failed = loaded.is_err();
            let mut app = unlock(wallet.clone());
            assert_eq!(app.save_state_name(), "loading_contacts");

            // Offline: the refresh fails fast, while the contacts load
            // still holds the file. Its repair save must wait, not race.
            let _ = app.handle_safes_refreshed(vec![(0, Err("rpc down".into()))]);
            assert_eq!(app.save_state_name(), "loading_contacts+queued");
            assert!(!app.safes_dirty, "the queued save carries the repair");
            assert!(app.toast.is_none(), "no 'couldn't save' toast");

            // The load lands — even failing — and the save goes out.
            let flushed = app.update(Message::ContactsLoaded(loaded));
            assert_eq!(app.save_state_name(), "saving", "failed load: {failed}");
            assert!(flushed.units() > 0);
            let _ = app.update(Message::WalletSaved(Ok(Some((
                test_key(),
                wallet::KeyOrigin::Existing,
            )))));
            assert_eq!(app.save_state_name(), "idle");
        }
    }

    #[test]
    fn a_contacts_save_during_a_wallet_save_waits_for_it() {
        let (_, a0) = local_signer_and_account(1);
        let mut app = unlocked_app(WalletDescriptor::single(a0));

        let _ = app.persist_wallet("test");
        assert_eq!(app.persist_contacts(vec![contact(1)]).units(), 0);
        assert_eq!(app.save_state_name(), "saving+contacts_queued");
        // A newer book replaces the waiting one.
        assert_eq!(
            app.persist_contacts(vec![contact(1), contact(2)]).units(),
            0
        );
        assert_eq!(app.db.contacts_save_queued.as_ref().map(Vec::len), Some(2));

        let flushed = app.update(Message::WalletSaved(Ok(Some((
            test_key(),
            wallet::KeyOrigin::Existing,
        )))));
        assert!(flushed.units() > 0);
        assert_eq!(app.save_state_name(), "saving_contacts");

        // The other way round: a wallet save waits for the contacts save,
        // and a failed contacts save still frees the file.
        let _ = app.persist_wallet("test");
        assert_eq!(app.save_state_name(), "saving_contacts+queued");
        let _ = app.update(Message::ContactsSaved(Err("disk full".into())));
        assert_eq!(app.save_state_name(), "saving");
        let _ = app.update(Message::WalletSaved(Ok(Some((
            test_key(),
            wallet::KeyOrigin::Existing,
        )))));
        assert_eq!(app.save_state_name(), "idle");
    }

    #[test]
    fn queued_ops_take_turns_so_neither_kind_starves() {
        let (_, a0) = local_signer_and_account(1);
        let mut app = unlocked_app(WalletDescriptor::single(a0));
        let _ = app.persist_wallet("test");
        let _ = app.persist_contacts(vec![contact(1)]);
        let _ = app.persist_wallet("test");
        assert_eq!(app.save_state_name(), "saving+queued+contacts_queued");

        // After a wallet save, the waiting contacts go first…
        let _ = app.update(Message::WalletSaved(Ok(Some((
            test_key(),
            wallet::KeyOrigin::Existing,
        )))));
        assert_eq!(app.save_state_name(), "saving_contacts+queued");
        // …then the wallet.
        let _ = app.update(Message::ContactsSaved(Ok(())));
        assert_eq!(app.save_state_name(), "saving");
        let _ = app.update(Message::WalletSaved(Ok(Some((
            test_key(),
            wallet::KeyOrigin::Existing,
        )))));
        assert_eq!(app.save_state_name(), "idle");
    }

    #[test]
    fn a_stray_completion_leaves_the_running_op_alone() {
        let (_, a0) = local_signer_and_account(1);
        let mut app = unlocked_app(WalletDescriptor::single(a0));
        let _ = app.start_contacts_load();
        let _ = app.persist_wallet("test");
        assert_eq!(app.save_state_name(), "loading_contacts+queued");
        assert_eq!(
            app.update(Message::WalletSaved(Ok(Some((
                test_key(),
                wallet::KeyOrigin::Existing
            )))))
            .units(),
            0
        );
        assert_eq!(
            app.save_state_name(),
            "loading_contacts+queued",
            "the load still holds the file"
        );
    }

    #[test]
    fn a_pool_seed_write_waits_for_the_wallet_file() {
        let (_, a0) = local_signer_and_account(1);
        let mut app = unlocked_app(WalletDescriptor::single(a0));
        assert!(app.pool_seed_write_blocked().is_none());
        let _ = app.persist_wallet("test");
        assert!(app.pool_seed_write_blocked().is_some());
        // Refused before it opens anything: no seed, no file touched.
        let _ = app.pool_create_identity();
        assert!(app.pp_seed.is_none());
        let _ = app.update(Message::WalletSaved(Ok(Some((
            test_key(),
            wallet::KeyOrigin::Existing,
        )))));
        assert!(app.pool_seed_write_blocked().is_none());
    }

    // ── Toasts ───────────────────────────────────────────────────────

    #[test]
    fn notices_toast_without_the_error_styling() {
        let mut app = build_app(placeholder_screen());
        let dismiss = app.update(Message::Notice("Removed Account 2".into()));
        assert_eq!(dismiss.units(), 1, "auto-dismiss scheduled");
        let toast = app.toast.as_ref().expect("shown");
        assert_eq!(toast.kind, ToastKind::Notice);
        assert_eq!(toast.msg, "Removed Account 2");
        let notice_gen = toast.generation;
        let _ = app.view();

        // An error replaces it, and the notice's late dismissal no-ops.
        let _ = app.update(Message::WalletError("Kao couldn't save".into()));
        assert_eq!(app.toast.as_ref().unwrap().kind, ToastKind::Error);
        let _ = app.view();
        let _ = app.update(Message::DismissToast {
            generation: notice_gen,
        });
        assert!(app.toast.is_some());
        let current = app.toast.as_ref().unwrap().generation;
        let _ = app.update(Message::DismissToast {
            generation: current,
        });
        assert!(app.toast.is_none());
    }

    #[test]
    fn adding_a_saved_safe_again_merges_links_instead_of_skipping() {
        let (_, a0) = local_signer_and_account(1);
        let owner = wallet::account_address(&a0).unwrap();
        // Base was saved watch-only by the old multi-chain bug.
        let mut base = safe_at(0x55, 8453, vec![owner], vec![], vec![]);
        base.set_name(Some("Treasury".into()));
        let mut app = unlocked_app(wallet_of(vec![a0], vec![base]));
        app.setup_context = Some(SetupContext::AddAccount);

        let primary = safe_at(0x55, 1, vec![owner], vec![0], vec![8453]);
        let sibling = safe_at(0x55, 8453, vec![owner], vec![0], vec![1]);
        let _ = app.save_safe_and_return_to_dashboard(primary, vec![sibling]);

        let w = app.wallet.as_ref().unwrap();
        assert_eq!(w.safes.len(), 2, "Base merged in place, Mainnet appended");
        assert_eq!(w.safes[0].linked_signer_indices, vec![0], "Base now signs");
        assert_eq!(w.safes[0].name(), Some("Treasury"), "saved name kept");
        assert_eq!(w.safes[1].key(), ([0x55; 20], 1));
        assert_eq!(
            w.safes[1].name(),
            Some("Treasury"),
            "the new chain takes the saved name"
        );
        assert_eq!(app.save_state_name(), "saving");
        assert!(matches!(app.screen, Screen::Wallet(_)));
    }

    /// What adding Safe `0x55` on Mainnet + Base from Review emits: the
    /// Review `name` on both, the key linked on both.
    fn review_add(
        owner: alloy::primitives::Address,
        name: Option<&str>,
    ) -> (wallet::SafeDescriptor, Vec<wallet::SafeDescriptor>) {
        let mut primary = safe_at(0x55, 1, vec![owner], vec![0], vec![8453]);
        let mut sibling = safe_at(0x55, 8453, vec![owner], vec![0], vec![1]);
        primary.set_name(name.map(str::to_owned));
        sibling.set_name(name.map(str::to_owned));
        (primary, vec![sibling])
    }

    #[test]
    fn adding_chains_of_a_saved_safe_keeps_one_name_per_address() {
        let (_, a0) = local_signer_and_account(1);
        let owner = wallet::account_address(&a0).unwrap();
        let mut mainnet = named(safe_at(0x55, 1, vec![owner], vec![], vec![]), "Treasury");
        mainnet.tx_service_url = Some("https://txs.example.org".into());
        let start = wallet_of(
            vec![a0],
            vec![
                named(safe_at(0x66, 1, vec![], vec![], vec![]), "Grants"),
                mainnet,
            ],
        );
        let names = |app: &App| -> Vec<Option<String>> {
            let w = app.wallet.as_ref().unwrap();
            w.safes
                .iter()
                .filter(|s| s.address == [0x55; 20])
                .map(|s| s.name().map(str::to_owned))
                .collect()
        };

        // Blank Review name: the saved name (and service URL) everywhere.
        let mut app = unlocked_app(start.clone());
        app.setup_context = Some(SetupContext::AddAccount);
        let (primary, siblings) = review_add(owner, None);
        let _ = app.save_safe_and_return_to_dashboard(primary, siblings);
        assert_eq!(names(&app), vec![Some("Treasury".into()); 2]);
        let base = &app.wallet.as_ref().unwrap().safes[2];
        assert_eq!(base.key(), ([0x55; 20], 8453));
        assert_eq!(
            base.tx_service_url.as_deref(),
            Some("https://txs.example.org")
        );

        // The saved name left as prefilled: nothing renamed.
        let mut app = unlocked_app(start.clone());
        app.setup_context = Some(SetupContext::AddAccount);
        let (primary, siblings) = review_add(owner, Some("Treasury"));
        let _ = app.save_safe_and_return_to_dashboard(primary, siblings);
        assert_eq!(names(&app), vec![Some("Treasury".into()); 2]);

        // A typed name renames the Safe on every chain, saved one included.
        let mut app = unlocked_app(start);
        app.setup_context = Some(SetupContext::AddAccount);
        let (primary, siblings) = review_add(owner, Some("Vault"));
        let _ = app.save_safe_and_return_to_dashboard(primary, siblings);
        assert_eq!(names(&app), vec![Some("Vault".into()); 2]);
        let w = app.wallet.as_ref().unwrap();
        assert_eq!(w.safes[0].name(), Some("Grants"), "other Safes untouched");
    }

    #[test]
    fn a_typed_name_heals_a_split_name_and_the_notice_uses_it() {
        let (_, a0) = local_signer_and_account(1);
        let owner = wallet::account_address(&a0).unwrap();
        // Saved before this fix: two names for one address.
        let mut w = wallet_of(
            vec![a0],
            vec![
                named(safe_at(0x55, 1, vec![owner], vec![0], vec![]), "Treasury"),
                safe_at(0x55, 8453, vec![owner], vec![], vec![]),
            ],
        );
        let (primary, siblings) = review_add(owner, Some("Treasury"));
        let notice = upsert_safes(&mut w, std::iter::once(primary).chain(siblings))
            .expect("both chains were saved");
        assert!(w.safes.iter().all(|s| s.name() == Some("Treasury")));
        assert_eq!(
            notice,
            "Treasury on Ethereum Mainnet is already in your wallet · \
             Treasury on Base was already in your wallet — linked 1 signer"
        );
    }

    #[test]
    fn upsert_toast_names_the_saved_entry_and_the_new_links() {
        let (_, a0) = local_signer_and_account(1);
        let (_, a1) = local_signer_and_account(2);
        let mut base = safe_at(0x55, 8453, vec![], vec![], vec![]);
        base.set_name(Some("Treasury".into()));
        let mut w = wallet_of(
            vec![a0, a1],
            vec![base, safe_at(0x66, 1, vec![], vec![0], vec![])],
        );

        let fresh = safe_at(0x77, 10, vec![], vec![], vec![]);
        assert_eq!(
            upsert_safes(&mut w, vec![fresh]),
            None,
            "all new → no toast"
        );

        let notice = upsert_safes(
            &mut w,
            vec![
                safe_at(0x55, 8453, vec![], vec![0, 1], vec![]),
                safe_at(0x66, 1, vec![], vec![0], vec![]),
            ],
        )
        .expect("both were already saved");
        assert_eq!(
            notice,
            "Treasury on Base was already in your wallet — linked 2 signers · \
             Safe 2 on Ethereum Mainnet is already in your wallet"
        );
        let single = upsert_safes(&mut w, vec![safe_at(0x77, 10, vec![], vec![1], vec![])]);
        assert_eq!(
            single.as_deref(),
            Some("Safe 3 on OP Mainnet was already in your wallet — linked 1 signer")
        );
    }

    #[test]
    fn nested_safe_add_merges_into_a_saved_entry() {
        let (_, a0) = local_signer_and_account(1);
        let owner = wallet::account_address(&a0).unwrap();
        let mut app = unlocked_app(wallet_of(
            vec![a0],
            vec![safe_at(0x99, 1, vec![owner], vec![], vec![])],
        ));
        let nested_addr = alloy::primitives::Address::repeat_byte(0x99);
        app.pending_add_signer.push(PendingAddSigner {
            allowed_owners: vec![nested_addr],
            stash: Box::new(SafeOnboardingScreen::new(app.network.clone(), Vec::new())),
        });

        let _ = app.finish_add_nested_safe(safe_at(0x99, 1, vec![owner], vec![0], vec![]), vec![]);

        let w = app.wallet.as_ref().unwrap();
        assert_eq!(w.safes.len(), 1);
        assert_eq!(w.safes[0].linked_signer_indices, vec![0]);
        assert!(app.pending_add_signer.is_empty());
        assert!(matches!(app.screen, Screen::SafeOnboarding(_)));
        assert_eq!(app.save_state_name(), "saving");
    }

    /// Press Confirm on the onboarding screen on display and return what
    /// it emits.
    fn confirm_onboarding(app: &mut App) -> (wallet::SafeDescriptor, Vec<wallet::SafeDescriptor>) {
        let Screen::SafeOnboarding(screen) = &mut app.screen else {
            panic!("expected the Safe onboarding screen");
        };
        let (_, outcome) = screen.update(crate::ui::safe_onboarding::Message::Confirm);
        let Some(SafeOnboardingOutcome::Done { primary, siblings }) = outcome else {
            panic!("expected Done, got {outcome:?}");
        };
        (*primary, siblings)
    }

    #[test]
    fn a_key_imported_inside_a_nested_safe_flow_reaches_the_parent() {
        use crate::chain::Chain;
        // Parent Safe P (0x55) is owned by key k and by Safe N (0x99); N
        // is owned by k. The wallet holds an unrelated account 0, not k.
        let (_, a0) = local_signer_and_account(1);
        let (_, k) = local_signer_and_account(2);
        let k_addr = wallet::account_address(&k).unwrap();
        let p_addr = alloy::primitives::Address::repeat_byte(0x55);
        let n_addr = alloy::primitives::Address::repeat_byte(0x99);
        let mut app = unlocked_app(wallet_of(vec![a0], Vec::new()));
        let snapshot = app.existing_accounts_snapshot();
        let parent = SafeOnboardingScreen::new(app.network.clone(), snapshot.clone())
            .scanned_for_test(p_addr, vec![(Chain::Mainnet, vec![k_addr, n_addr])]);
        let nested = SafeOnboardingScreen::new(app.network.clone(), snapshot)
            .scanned_for_test(n_addr, vec![(Chain::Mainnet, vec![k_addr])]);
        // P picked "Nested Safe", then N picked "Private key": two deep.
        app.pending_add_signer.push(PendingAddSigner {
            allowed_owners: vec![k_addr, n_addr],
            stash: Box::new(parent),
        });
        app.pending_add_signer.push(PendingAddSigner {
            allowed_owners: vec![k_addr],
            stash: Box::new(nested),
        });

        let _ = app.finish_add_signer(k, k_addr);

        // N is back on screen with k (account 1) ticked…
        let Screen::SafeOnboarding(n) = &app.screen else {
            panic!("the nested Review is restored");
        };
        assert!(n.ticks_signer(1));
        // …and P, still parked below it, knows k and ticks it too.
        assert_eq!(app.pending_add_signer.len(), 1);
        let p = &app.pending_add_signer[0].stash;
        assert!(p.knows_account(1));
        assert!(p.ticks_signer(1));

        // Confirming N saves it and resumes P, which links k.
        let (n_primary, n_siblings) = confirm_onboarding(&mut app);
        assert_eq!(n_primary.linked_signer_indices, vec![1]);
        let _ = app.finish_add_nested_safe(n_primary, n_siblings);
        assert!(app.pending_add_signer.is_empty());
        let (p_primary, _) = confirm_onboarding(&mut app);
        assert_eq!(p_primary.address, [0x55; 20]);
        assert_eq!(p_primary.linked_signer_indices, vec![1]);
    }

    #[test]
    fn re_adding_a_saved_safe_by_hex_keeps_its_name_and_links() {
        use crate::chain::Chain;
        // Treasury (0x55) is saved on Mainnet linking account 0. The user
        // pastes its hex address again to pick up Base.
        let (_, a0) = local_signer_and_account(1);
        let owner = wallet::account_address(&a0).unwrap();
        let mut app = unlocked_app(wallet_of(
            vec![a0],
            vec![
                named(safe_at(0x55, 1, vec![owner], vec![0], vec![]), "Treasury"),
                named(safe_at(0x66, 1, vec![], vec![], vec![]), "Grants"),
            ],
        ));
        app.setup_context = Some(SetupContext::AddAccount);
        let screen =
            SafeOnboardingScreen::new(app.network.clone(), app.existing_accounts_snapshot())
                .with_existing_safes(app.existing_safes_snapshot())
                .scanned_for_test(
                    alloy::primitives::Address::repeat_byte(0x55),
                    vec![(Chain::Mainnet, vec![owner]), (Chain::Base, vec![owner])],
                );
        // Review starts from the saved name.
        assert_eq!(screen.review_name(), Some("Treasury"));
        app.screen = Screen::SafeOnboarding(screen);
        // Unticking the key leaves Base watch-only; Mainnet's saved link
        // stays (a merge never unlinks — the role summary says so).
        if let Screen::SafeOnboarding(s) = &mut app.screen {
            let _ = s.update(crate::ui::safe_onboarding::Message::SignerToggled(0));
        }
        let (primary, siblings) = confirm_onboarding(&mut app);
        let _ = app.save_safe_and_return_to_dashboard(primary, siblings);

        let w = app.wallet.as_ref().unwrap();
        let links_on = |chain_id| {
            w.safe_index([0x55; 20], chain_id)
                .map(|i| w.safes[i].linked_signer_indices.clone())
        };
        assert_eq!(links_on(1), Some(vec![0]));
        assert_eq!(links_on(8453), Some(vec![]));
        assert!(
            w.safes
                .iter()
                .filter(|s| s.address == [0x55; 20])
                .all(|s| s.name() == Some("Treasury")),
            "one name on every chain, nothing renamed"
        );
        assert_eq!(w.safes[1].name(), Some("Grants"));
    }

    // ── Safe rename / removal / service URL (Settings → Safes, header) ──

    fn named(mut safe: wallet::SafeDescriptor, name: &str) -> wallet::SafeDescriptor {
        safe.set_name(Some(name.into()));
        safe
    }

    #[test]
    fn rename_safe_renames_the_address_on_every_chain_and_persists() {
        let (_, a0) = local_signer_and_account(1);
        let mut app = unlocked_app(wallet_of(
            vec![a0],
            vec![
                named(safe_at(0x55, 1, vec![], vec![0], vec![8453]), "Old"),
                named(safe_at(0x66, 1, vec![], vec![0], vec![]), "Grants"),
                named(safe_at(0x55, 8453, vec![], vec![], vec![1]), "Old"),
            ],
        ));

        let task = app.rename_safe([0x55; 20], Some("Treasury".into()));
        assert!(task.units() > 0, "SafesUpdated push + save");
        let names: Vec<_> = app
            .wallet
            .as_ref()
            .unwrap()
            .safes
            .iter()
            .map(|s| s.name())
            .collect();
        assert_eq!(
            names,
            vec![Some("Treasury"), Some("Grants"), Some("Treasury")]
        );
        assert_eq!(app.save_state_name(), "saving");

        // Blank clears back to the positional default.
        let _ = app.rename_safe([0x55; 20], Some("  ".into()));
        let w = app.wallet.as_ref().unwrap();
        assert_eq!(w.safes[0].display_name(0), "Safe 1");
        assert_eq!(w.safes[2].display_name(2), "Safe 3");
        assert_eq!(
            app.save_state_name(),
            "saving+queued",
            "a quick second edit shares the save pipeline"
        );
    }

    #[test]
    fn remove_safe_drops_that_chain_only_and_persists() {
        let (_, a0) = local_signer_and_account(1);
        let mut app = unlocked_app(wallet_of(
            vec![a0],
            vec![
                named(safe_at(0x55, 1, vec![], vec![0], vec![8453]), "Treasury"),
                named(safe_at(0x55, 8453, vec![], vec![0], vec![1]), "Treasury"),
                safe_at(0x66, 1, vec![], vec![0], vec![]),
            ],
        ));

        let task = app.remove_safe([0x55; 20], 1);
        assert!(task.units() > 0, "SafesUpdated push + save");
        let w = app.wallet.as_ref().unwrap();
        let keys: Vec<_> = w.safes.iter().map(wallet::SafeDescriptor::key).collect();
        assert_eq!(keys, vec![([0x55; 20], 8453), ([0x66; 20], 1)]);
        assert!(w.safes[0].sibling_chains.is_empty(), "peer forgets chain 1");
        assert_eq!(
            w.safes[1].display_name(1),
            "Safe 3",
            "the unnamed Safe after it keeps the name the user saw"
        );
        assert_eq!(app.save_state_name(), "saving");
    }

    #[test]
    fn safe_edits_for_a_key_the_wallet_lacks_change_nothing() {
        let (_, a0) = local_signer_and_account(1);
        let safes = vec![safe_at(0x55, 1, vec![], vec![0], vec![])];
        let mut app = unlocked_app(wallet_of(vec![a0], safes.clone()));

        // Same address, other chain; other address entirely.
        assert_eq!(app.remove_safe([0x55; 20], 8453).units(), 0);
        assert_eq!(app.rename_safe([0x99; 20], Some("x".into())).units(), 0);
        let url = Some("https://txs.example.org".to_string());
        assert_eq!(app.set_safe_service_url([0x55; 20], 10, url).units(), 0);

        let w = app.wallet.as_ref().unwrap();
        assert_eq!(w.safes.len(), 1);
        assert_eq!(w.safes[0].name(), None);
        assert_eq!(w.safes[0].tx_service_url, None);
        assert_eq!(app.save_state_name(), "idle");
    }

    #[test]
    fn service_url_lands_on_the_keyed_chain_only() {
        let (_, a0) = local_signer_and_account(1);
        let mut app = unlocked_app(wallet_of(
            vec![a0],
            vec![
                safe_at(0x55, 1, vec![], vec![0], vec![8453]),
                safe_at(0x55, 8453, vec![], vec![0], vec![1]),
            ],
        ));
        let url = Some("https://txs.example.org".to_string());
        let _ = app.set_safe_service_url([0x55; 20], 8453, url.clone());
        let w = app.wallet.as_ref().unwrap();
        assert_eq!(w.safes[0].tx_service_url, None);
        assert_eq!(w.safes[1].tx_service_url, url);
        assert_eq!(app.save_state_name(), "saving");
    }

    // ── Account rename / removal (Settings → Accounts) ──────────────────

    use crate::ui::wallet_dashboard::Nav;

    fn addr_of(account: &AccountDescriptor) -> alloy::primitives::Address {
        wallet::account_address(account).expect("test accounts have addresses")
    }

    fn dashboard(app: &App) -> &WalletScreen {
        match &app.screen {
            Screen::Wallet(screen) => screen,
            other => panic!("expected the dashboard, on {}", other.name()),
        }
    }

    fn dashboard_mut(app: &mut App) -> &mut WalletScreen {
        match &mut app.screen {
            Screen::Wallet(screen) => screen,
            other => panic!("expected the dashboard, on {}", other.name()),
        }
    }

    #[test]
    fn removing_another_account_remaps_in_place_and_keeps_the_live_signer() {
        let (_, a0) = local_signer_and_account(1);
        let (_, a1) = local_signer_and_account(2);
        // The active account is a Ledger whose device is connected, so the
        // dashboard holds a live signer for it (a local key stands in for
        // the device). A rebuild would drop it to the view-only placeholder.
        let (live, stand_in) = local_signer_and_account(3);
        let ledger = AccountDescriptor::Ledger {
            name: None,
            path: wallet::LedgerHdPath::LedgerLive(0),
            address: addr_of(&stand_in).into_array(),
        };
        let (gone, ledger_addr) = (addr_of(&a0), addr_of(&ledger));
        let mut app = unlocked_app(WalletDescriptor {
            accounts: vec![a0, a1, ledger],
            safes: vec![
                safe_at(0x55, 1, vec![gone, ledger_addr], vec![0, 2], vec![]),
                safe_at(0x66, 1, vec![gone], vec![0], vec![]),
            ],
            active_index: 2,
            sibling_links_repaired: true,
        });
        let _ = app.enter_dashboard(live, Some(Nav::Settings));
        dashboard_mut(&mut app).open_accounts_settings();

        let task = app.remove_account(0, gone);
        assert!(task.units() > 0, "save + toast");

        let w = app.wallet.as_ref().unwrap();
        assert_eq!(w.accounts.len(), 2);
        assert_eq!(w.active_index, 1, "the Ledger slid down one");
        assert_eq!(w.safes[0].linked_signer_indices, vec![1]);
        assert!(
            w.safes[1].linked_signer_indices.is_empty(),
            "watch-only now"
        );
        assert_eq!(app.save_state_name(), "saving");

        let screen = dashboard(&app);
        assert!(
            screen.test_signer_can_sign(),
            "same dashboard, same connected signer"
        );
        assert_eq!(screen.test_address(), ledger_addr);
        assert_eq!(screen.test_active_index(), 1);
        assert_eq!(screen.test_accounts().len(), 2);
        assert_eq!(screen.current_nav(), Nav::Settings);
        assert_eq!(
            screen.test_settings_pane(),
            "Accounts",
            "the pane stays open"
        );
    }

    #[test]
    fn removing_the_active_account_rebuilds_on_its_successor_and_reopens_accounts() {
        let accounts: Vec<_> = (1..=3).map(|s| local_signer_and_account(s).1).collect();
        let addrs: Vec<_> = accounts.iter().map(addr_of).collect();
        let mut app = unlocked_app(WalletDescriptor {
            accounts,
            safes: Vec::new(),
            active_index: 1,
            sibling_links_repaired: true,
        });
        let _ = app.enter_active_from_wallet(Some(Nav::Settings));
        dashboard_mut(&mut app).open_accounts_settings();

        let _ = app.remove_account(1, addrs[1]);
        let w = app.wallet.as_ref().unwrap();
        assert_eq!(w.accounts.len(), 2);
        assert_eq!(w.active_index, 1, "the next account took its slot");
        assert_eq!(
            w.accounts[1].name(),
            Some("Account 3"),
            "its default name froze"
        );
        assert_eq!(app.save_state_name(), "saving");

        let screen = dashboard(&app);
        assert_eq!(screen.test_address(), addrs[2], "rebuilt for the successor");
        assert_eq!(screen.test_active_index(), 1);
        assert_eq!(screen.current_nav(), Nav::Settings);
        assert_eq!(screen.test_settings_pane(), "Accounts", "back where it was");
    }

    #[test]
    fn the_last_account_cannot_be_removed() {
        let (_, a0) = local_signer_and_account(1);
        let only = addr_of(&a0);
        let mut app = unlocked_app(WalletDescriptor::single(a0));
        let task = app.remove_account(0, only);
        assert_eq!(task.units(), 1, "just the toast");
        assert_eq!(app.wallet.as_ref().unwrap().accounts.len(), 1);
        assert_eq!(app.save_state_name(), "idle");
    }

    #[test]
    fn a_removal_whose_position_moved_is_refused() {
        let (_, a0) = local_signer_and_account(1);
        let (_, a1) = local_signer_and_account(2);
        let first = addr_of(&a0);
        let mut app = unlocked_app(wallet_of(vec![a0, a1], vec![]));

        // The pane saw `first` at position 1 — it isn't there (any more).
        assert_eq!(app.remove_account(1, first).units(), 1, "just the toast");
        assert_eq!(app.remove_account(7, first).units(), 1, "out of range");
        let w = app.wallet.as_ref().unwrap();
        assert_eq!(w.accounts.len(), 2);
        assert_eq!(addr_of(&w.accounts[0]), first);
        assert_eq!(app.save_state_name(), "idle");
    }

    #[test]
    fn removing_an_account_is_refused_while_signing() {
        let (signer, a0) = local_signer_and_account(1);
        let (_, a1) = local_signer_and_account(2);
        let other = addr_of(&a1);
        let mut app = unlocked_app(wallet_of(vec![a0, a1], vec![]));
        let _ = app.enter_dashboard(signer, None);
        dashboard_mut(&mut app).test_mark_signing_busy();

        let task = app.remove_account(1, other);
        assert_eq!(task.units(), 1, "just the toast");
        assert_eq!(app.wallet.as_ref().unwrap().accounts.len(), 2);
        assert_eq!(dashboard(&app).test_accounts().len(), 2);
        assert_eq!(app.save_state_name(), "idle");
    }

    #[test]
    fn renaming_an_account_checks_its_position_still_holds_it() {
        let (_, a0) = local_signer_and_account(1);
        let (_, a1) = local_signer_and_account(2);
        let second = addr_of(&a1);
        let mut app = unlocked_app(wallet_of(vec![a0, a1], vec![]));

        assert_eq!(
            app.rename_account(0, second, Some("Cold".into())).units(),
            0
        );
        assert!(
            app.wallet
                .as_ref()
                .unwrap()
                .accounts
                .iter()
                .all(|a| a.name().is_none())
        );
        assert_eq!(app.save_state_name(), "idle");

        let _ = app.rename_account(1, second, Some(" Cold ".into()));
        let w = app.wallet.as_ref().unwrap();
        assert_eq!(w.accounts[1].name(), Some("Cold"));
        assert_eq!(w.active_index, 0, "renaming never switches");
        assert_eq!(app.save_state_name(), "saving");
    }

    #[test]
    fn the_removal_toast_names_the_safes_left_watch_only() {
        let (_, a0) = local_signer_and_account(1);
        let (_, a1) = local_signer_and_account(2);
        let (k0, k1) = (addr_of(&a0), addr_of(&a1));
        let mut w = wallet_of(
            vec![a0, a1],
            vec![
                named(safe_at(0x55, 8453, vec![k0], vec![0], vec![]), "Treasury"),
                safe_at(0x66, 1, vec![k0, k1], vec![0, 1], vec![]),
            ],
        );
        let removed = w.remove_account(0).unwrap();
        assert_eq!(
            removal_notice(&w, &removed),
            "Removed Account 1 · Treasury on Base is watch-only now"
        );

        let removed = w.remove_account(0).unwrap_err();
        assert_eq!(removed, wallet::RemoveAccountError::LastAccount);
    }

    #[test]
    fn the_removal_toast_counts_a_leftover_view_only_link_as_watch_only() {
        // The old onboarding linked view-only owners too: Treasury is
        // linked [key A, view-only V]. Removing A leaves a link, but no key
        // Kao can sign with — the toast must say so, and the live dashboard
        // must leave Safe mode on it rather than offer a Safe that fails at
        // sign time.
        let (_, a0) = local_signer_and_account(1);
        let (live, a2) = local_signer_and_account(3);
        let (k0, k2) = (addr_of(&a0), addr_of(&a2));
        let watched = alloy::primitives::Address::repeat_byte(0x77);
        let mut app = unlocked_app(WalletDescriptor {
            accounts: vec![a0, wallet::view_only_account(watched), a2],
            safes: vec![named(
                safe_at(0x55, 1, vec![k0, watched], vec![0, 1], vec![]),
                "Treasury",
            )],
            active_index: 2,
            sibling_links_repaired: true,
        });
        let _ = app.enter_dashboard(live, Some(Nav::Settings));
        dashboard_mut(&mut app).test_enter_safe_mode(0);

        let mut w = app.wallet.clone().unwrap();
        let removed = w.remove_account(0).unwrap();
        assert_eq!(w.safes[0].linked_signer_indices, vec![0], "V stays linked");
        assert_eq!(
            removal_notice(&w, &removed),
            "Removed Account 1 · Treasury on Ethereum Mainnet is watch-only now"
        );

        let _ = app.remove_account(0, k0);
        let screen = dashboard(&app);
        assert_eq!(
            screen.test_active_safe(),
            None,
            "no key in Kao signs for the active Safe any more"
        );
        assert_eq!(screen.test_address(), k2, "same account, now at 1");
    }

    // ── WalletConnect: lock, quit, off-screen answers ───────────────────

    const WC_ADDR: alloy::primitives::Address =
        alloy::primitives::address!("ab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb");

    /// A session with one `personal_sign` Kao is already signing — the dashboard's half of
    /// admission and review done by hand, as the runtime tests do.
    async fn wc_signing_request(
        rt: &WcRuntime,
        dapp: &wallet_connect::sign::SignClient,
    ) -> (WcKey, testkit::DappCall) {
        let topic = testkit::connect_raw(rt, dapp, WC_ADDR, &[1]).await;
        let params = testkit::personal_sign_params("hi", WC_ADDR);
        let call = testkit::dapp_request(dapp, &topic, 1, "personal_sign", params);
        let (req, at) = testkit::next_request(&rt.events()).await;
        let key = WcKey {
            topic: req.topic.clone(),
            id: req.id,
        };
        rt.admit(&req, at, Ok(testkit::admitted_personal(WC_ADDR, 1, "hi")));
        rt.with_book(|b| {
            assert!(b.mark_in_review(&key, 1));
            assert!(b.mark_signing(&key, 1));
        });
        (key, call)
    }

    #[tokio::test]
    async fn lock_closes_and_replaces_the_slot() {
        let (_relay, dapp, _events, rt, slot) = testkit::harness().await;
        let (key, _call) = wc_signing_request(&rt, &dapp).await;
        let mut app = build_app(placeholder_screen());
        app.wc_slot = slot.clone();
        app.passphrase = Some(SecretString::new("pw".to_string().into_boxed_str()));
        app.pp_seed = Some(SecretString::new("seed".to_string().into_boxed_str()));
        app.pp_loaded = true;
        assert!(rt.is_live(&key));

        // The lock itself — what Back on a connect screen runs when a wallet exists.
        let task = app.lock_wallet();
        assert!(matches!(app.screen, Screen::Unlock(_)));
        assert!(app.passphrase.is_none() && app.pp_seed.is_none() && !app.pp_loaded);
        assert!(task.units() > 0, "the bounded teardown runs as a task");
        // Closed synchronously, before that task ever runs: the signature in flight can no
        // longer be broadcast or answered.
        assert!(rt.is_closed());
        assert!(!rt.is_live(&key));
        // The old slot is empty and closed for good — a start racing the lock can't install.
        assert!(slot.is_closed() && slot.get().is_none());
        assert!(!slot.begin_start());
        // The next unlock starts from a fresh, empty slot.
        assert!(!app.wc_slot.is_closed() && app.wc_slot.get().is_none());
        // With nothing running there is nothing to tear down.
        assert_eq!(app.suspend_wc(VaultFlush::none()).units(), 0);
        assert!(!app.wc_slot.is_closed());
    }

    #[tokio::test]
    async fn close_request_ends_walletconnect_before_exiting() {
        let (_relay, dapp, _events, rt, slot) = testkit::harness().await;
        let (key, _call) = wc_signing_request(&rt, &dapp).await;
        let mut app = build_app(placeholder_screen());
        app.wc_slot = slot.clone();
        let window = iced::window::Id::unique();

        // The arm's decision: wait for the teardown, then exit — never exit while it runs.
        let QuitStep::After(wait) = app.close_requested() else {
            panic!("the close waits for the teardown");
        };
        assert!(app.closing);
        assert!(slot.is_closed() && slot.get().is_none());
        assert!(rt.is_closed() && !rt.is_live(&key));
        // A second close while that runs quits at once.
        assert!(matches!(app.close_requested(), QuitStep::Now));
        wait.await;
        assert_eq!(
            slot.teardowns_running(),
            0,
            "the wait ended with the teardown"
        );
        assert_eq!(app.update(Message::WcTornDown).units(), 0);

        // Through `update`: the same arm (the first close perform-then-exits).
        let (_relay, _dapp, _events, _rt, slot) = testkit::harness().await;
        let mut app = build_app(placeholder_screen());
        app.wc_slot = slot.clone();
        let task = app.update(Message::CloseRequested(window));
        assert!(app.closing && slot.is_closed());
        assert!(task.units() > 0);
    }

    #[test]
    fn close_request_without_walletconnect_exits_at_once() {
        let mut app = build_app(placeholder_screen());
        assert!(app.begin_quit().is_none(), "nothing to wait for");
        assert!(app.closing);
        assert!(app.wc_slot.is_closed(), "nothing can start while quitting");

        let mut app = build_app(placeholder_screen());
        assert!(
            matches!(app.close_requested(), QuitStep::Now),
            "nothing runs: exit at once"
        );

        let mut app = build_app(placeholder_screen());
        let _ = app.update(Message::CloseRequested(iced::window::Id::unique()));
        assert!(app.closing && app.wc_slot.is_closed());
    }

    /// A lock's teardown is still running when the window closes: iced exits as soon as the quit
    /// task resolves and never polls the lock's task again, so the teardown must run on its own
    /// and the quit must wait for it — the dapp still hears 6000.
    #[tokio::test]
    async fn quit_waits_for_a_lock_teardown_still_running() {
        let (_relay, dapp, _events, rt, slot) = testkit::harness().await;
        let topic = testkit::connect_raw(&rt, &dapp, WC_ADDR, &[1]).await;
        let mut app = build_app(placeholder_screen());
        app.wc_slot = slot.clone();
        // What process exit does to the lock's pending task.
        drop(app.suspend_wc(VaultFlush::none()));
        assert_eq!(
            app.wc_slot.teardowns_running(),
            1,
            "the fresh slot counts the lock's teardown, so the quit below waits for it"
        );
        let wait = app
            .begin_quit()
            .expect("the quit waits for the lock's teardown");
        assert!(app.closing && app.wc_slot.is_closed());
        wait.await;
        assert_eq!(
            app.wc_slot.teardowns_running(),
            0,
            "the quit's wait ended with the teardown"
        );
        testkit::settle(|| !dapp.sessions().iter().any(|s| s.topic == topic)).await;
        assert!(
            !dapp.sessions().iter().any(|s| s.topic == topic),
            "the dapp heard 6000"
        );
    }

    /// A WalletConnect signature finishing while no dashboard is on screen (a lock, a hardware
    /// reconnect, the add-account flow) still answers its dapp, from the App.
    #[tokio::test]
    async fn off_screen_signing_result_is_answered() {
        let (_relay, dapp, _events, rt, slot) = testkit::harness().await;
        let (key, call) = wc_signing_request(&rt, &dapp).await;
        let mut app = build_app(placeholder_screen());
        app.wc_slot = slot.clone();

        let task = app.update(Message::WalletDashboard(WalletDashboardMessage::Signed {
            tag: SignTag::WalletConnect {
                key: key.clone(),
                kind: WcSignKind::Personal,
            },
            signer: None,
            result: Err("the Ledger was unplugged".into()),
        }));
        assert_eq!(task.units(), 0);
        let Err(wallet_connect::Error::Peer(e)) = testkit::dapp_result(call).await else {
            panic!("the dapp hears a failure");
        };
        assert_eq!(e.code, wc_codes::INTERNAL);
        assert!(
            !e.message.contains("Ledger"),
            "the detail stays with the user"
        );
        assert_eq!(rt.with_book(|b| b.state_of(&key)), None, "answered once");
    }

    // ── Vault: create-password, saves, lock, quit (DESIGN §4) ───────────

    fn type_new_password(app: &mut App) {
        for msg in [
            CreatePasswordMessage::PasswordInput("longenough1".into()),
            CreatePasswordMessage::ConfirmInput("longenough1".into()),
            CreatePasswordMessage::CreatePressed,
        ] {
            let _ = app.update(Message::CreatePassword(msg));
        }
    }

    /// A fresh wallet's vault epoch starts keyless at create-password (nothing is on disk to seal
    /// into yet), and backing out of the network wizard — which forgets the passphrase — ends it.
    #[test]
    fn create_password_starts_a_keyless_vault_and_backing_out_ends_it() {
        let mut app = build_app(Screen::CreatePassword(CreatePasswordScreen::default()));
        type_new_password(&mut app);
        assert!(matches!(app.screen, Screen::NetworkSetup(_)));
        assert!(app.vault.is_unlocked() && !app.vault.can_persist());

        let _ = app.update(Message::NetworkSetup(NetworkSetupMessage::Back));
        assert!(matches!(app.screen, Screen::CreatePassword(_)));
        assert!(app.passphrase.is_none());
        assert!(
            !app.vault.is_unlocked(),
            "the epoch ends with the passphrase"
        );
    }

    /// Creating a wallet takes the instance lock first: with another Kao process holding it, no
    /// session starts — the vault stays locked, no passphrase is held, and the form says the
    /// wallet is open elsewhere. A lock that can't be taken for any other reason doesn't keep the
    /// user out.
    #[test]
    fn creating_a_wallet_another_process_holds_is_refused() {
        let type_both = |app: &mut App| {
            for msg in [
                CreatePasswordMessage::PasswordInput("longenough1".into()),
                CreatePasswordMessage::ConfirmInput("longenough1".into()),
            ] {
                let _ = app.update(Message::CreatePassword(msg));
            }
        };
        let mut app = build_app(Screen::CreatePassword(CreatePasswordScreen::default()));
        type_both(&mut app);
        let _ = app.create_password_with(CreatePasswordMessage::CreatePressed, || {
            Err(wallet::WalletError::InUse)
        });
        assert!(!app.vault.is_unlocked(), "no vault epoch");
        assert!(app.passphrase.is_none(), "no passphrase held");
        assert!(app.setup_context.is_none());
        let Screen::CreatePassword(screen) = &app.screen else {
            panic!("still on create-password");
        };
        assert_eq!(screen.error(), Some(crate::ui::unlock::ALREADY_OPEN));

        type_both(&mut app);
        let _ = app.create_password_with(CreatePasswordMessage::CreatePressed, || {
            Err(wallet::WalletError::Io(std::io::Error::other(
                "no locks here",
            )))
        });
        assert!(matches!(app.screen, Screen::NetworkSetup(_)));
        assert!(app.vault.is_unlocked() && app.passphrase.is_some());
    }

    /// Create-password through `update` asks the App's own acquire for the instance lock — a
    /// refusal there keeps the session from starting — and the App `App::new` builds (with a
    /// wallet file or without) carries the real lock, as the unlock screen does. Test apps carry a
    /// stand-in, so no test takes the real process lock.
    #[test]
    fn creating_a_wallet_goes_through_the_apps_instance_lock() {
        let mut app = build_app(Screen::CreatePassword(CreatePasswordScreen::default()));
        app.create_acquire = || Err(wallet::WalletError::InUse);
        type_new_password(&mut app);
        assert!(!app.vault.is_unlocked() && app.passphrase.is_none());
        let Screen::CreatePassword(screen) = &app.screen else {
            panic!("still on create-password");
        };
        assert_eq!(screen.error(), Some(crate::ui::unlock::ALREADY_OPEN));

        let real = wallet::acquire_instance_lock as crate::ui::unlock::AcquireInstanceLock;
        assert!(!std::ptr::fn_addr_eq(
            build_app(placeholder_screen()).create_acquire,
            real
        ));
        for exists in [false, true] {
            let (app, _) = App::with_network(Arc::new(MockFetcher::new()), exists);
            assert!(
                std::ptr::fn_addr_eq(app.create_acquire, real),
                "wallet file exists: {exists}"
            );
            assert_eq!(
                matches!(app.screen, Screen::Unlock(_)),
                exists,
                "the screen follows the wallet file"
            );
        }
    }

    /// An unlock whose sealed tables the storage couldn't read (`Unavailable`), with a dashboard.
    fn unlocked_unavailable() -> App {
        let mut app = build_app(placeholder_screen());
        app.pp_loaded = true;
        let wallet = WalletDescriptor::single(local_signer_and_account(1).1);
        let _ = app.adopt_unlocked_wallet(
            test_pw(),
            unlocked_with(wallet, None, wallet::KeyStatus::Unavailable),
        );
        assert!(app.vault.unreadable().key_unavailable);
        app
    }

    fn history_texts(app: &App) -> Vec<String> {
        let Screen::Wallet(ws) = &app.screen else {
            panic!("on the dashboard");
        };
        ws.test_history_pane_texts()
    }

    /// The saved history and connections couldn't be read: the confirmed reset from a history
    /// pane runs off the UI thread (one at a time); when it lands the vault adopts the key it
    /// minted and the pane stops saying nothing is saved. A failed reset is a toast and leaves the
    /// session keyless; with nothing unreadable there is nothing to reset.
    #[test]
    fn a_sealed_reset_hands_the_vault_its_fresh_key() {
        use crate::ui::wallet_dashboard::ConnectionHistoryMessage as History;
        let mut app = unlocked_unavailable();
        let _ = app.update(Message::WalletDashboard(
            WalletDashboardMessage::OpenConnectionHistorySettings,
        ));
        assert!(
            history_texts(&app)
                .iter()
                .any(|t| t.starts_with("Kao can't read the history saved in your wallet file")),
            "{:?}",
            history_texts(&app)
        );
        let _ = app.update(Message::WalletDashboard(
            WalletDashboardMessage::ConnectionHistorySettings(History::AskReset),
        ));
        // The real reset's task is built, never run: nothing here reaches a wallet file.
        let _ = app.update(Message::WalletDashboard(
            WalletDashboardMessage::ConnectionHistorySettings(History::ConfirmReset),
        ));
        assert!(app.sealed_reset_running, "the reset is on its way");
        // A second one now would mint a key over the first's.
        assert_eq!(
            app.request_sealed_reset_with(|_| panic!("not run")).units(),
            0
        );

        let notice = app.update(Message::SealedReset(Ok((
            test_key(),
            wallet::KeyOrigin::Minted,
        ))));
        assert!(!app.sealed_reset_running);
        assert!(app.vault.can_persist(), "the minted key reached the vault");
        assert!(!app.vault.unreadable().key_unavailable);
        assert_eq!(notice.units(), 1, "the user hears it worked");
        let texts = history_texts(&app);
        assert!(
            !texts
                .iter()
                .any(|t| t.starts_with("Kao can't read the history saved")),
            "{texts:?}"
        );
        assert!(!texts.iter().any(|t| t.contains("can't keep")), "{texts:?}");
        // Readable now: nothing more to reset.
        assert_eq!(
            app.request_sealed_reset_with(|_| panic!("not run")).units(),
            0
        );
        assert!(!app.sealed_reset_running);

        // A reset that fails: a toast, and the session stays keyless.
        let mut app = unlocked_unavailable();
        assert_eq!(
            app.request_sealed_reset_with(|_| panic!("not run")).units(),
            1
        );
        let toast = app.update(Message::SealedReset(Err("disk full".into())));
        assert_eq!(toast.units(), 1);
        assert!(!app.sealed_reset_running);
        assert!(!app.vault.can_persist());
        assert!(app.vault.unreadable().key_unavailable);
    }

    /// The reset runs the store call with the session passphrase on the blocking pool and reports
    /// either way.
    #[tokio::test]
    async fn a_sealed_reset_runs_with_the_session_passphrase() {
        use secrecy::ExposeSecret;
        let minted = run_sealed_reset(test_pw(), |pw| {
            assert_eq!(pw.expose_secret(), "pw");
            Ok((
                wallet::DataKey::for_test([9; 32]),
                wallet::KeyOrigin::Minted,
            ))
        })
        .await;
        assert!(matches!(minted, Ok((_, wallet::KeyOrigin::Minted))));
        let failed = run_sealed_reset(test_pw(), |_| Err(wallet::WalletError::NotFound)).await;
        assert_eq!(failed.err().as_deref(), Some("no wallet found"));
    }

    /// The panes learn from the vault, through the App, that what this session records is kept:
    /// keyless after an unlock, the WalletConnect pane says a lock disconnects the dapps and the
    /// history pane says new records aren't kept; the minting `WalletSaved` puts both back.
    #[tokio::test]
    async fn the_panes_hear_from_the_wallet_save_that_records_are_kept() {
        let (_, account) = local_signer_and_account(1);
        let address = wallet::account_address(&account).unwrap();
        let mut app = build_app(placeholder_screen());
        app.pp_loaded = true;
        app.vault
            .unlock(None, wallet::KeyStatus::Ok, wallet::SealedLoad::default());
        let (_relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&app.vault).await;
        testkit::connect_raw(&kao, &dapp, address, &[1]).await;
        app.wc_slot = slot;
        let _ = app.adopt_unlocked_wallet(
            test_pw(),
            unlocked_with(
                WalletDescriptor::single(account),
                None,
                wallet::KeyStatus::Ok,
            ),
        );
        let wc_texts = |app: &mut App| {
            let Screen::Wallet(ws) = &mut app.screen else {
                panic!("on the dashboard");
            };
            ws.test_wc_pane_texts()
        };
        let texts = wc_texts(&mut app);
        assert!(
            texts
                .iter()
                .any(|t| t.starts_with("Kao can't save your connections right now")),
            "{texts:?}"
        );
        let _ = app.update(Message::WalletDashboard(
            WalletDashboardMessage::OpenConnectionHistorySettings,
        ));
        let texts = history_texts(&app);
        assert!(
            texts.iter().any(|t| t.contains("can't keep new records")),
            "{texts:?}"
        );

        let _ = app.update(Message::ContactsLoaded(Ok(Vec::new())));
        assert_eq!(app.db.running, Some(DbOp::WalletSave), "the minting save");
        let _ = app.update(Message::WalletSaved(Ok(Some((
            test_key(),
            wallet::KeyOrigin::Minted,
        )))));
        let texts = wc_texts(&mut app);
        assert!(
            !texts
                .iter()
                .any(|t| t.starts_with("Kao can't save your connections right now")),
            "{texts:?}"
        );
        assert!(
            texts
                .iter()
                .any(|t| t.starts_with("These stay connected")
                    || t.starts_with("You changed the relay")),
            "{texts:?}"
        );
        let texts = history_texts(&app);
        assert!(!texts.iter().any(|t| t.contains("can't keep")), "{texts:?}");
    }

    /// The first wallet save of a keyless epoch hands the vault its data key; a save landing on a
    /// vault that has one, or on a locked vault, changes nothing.
    #[test]
    fn wallet_saved_hands_a_keyless_vault_its_key() {
        let mut app = build_app(placeholder_screen());
        app.wallet = Some(WalletDescriptor::single(local_signer_and_account(1).1));
        app.passphrase = Some(test_pw());

        // Locked: ignored (a save from before a lock lands after it).
        let _ = app.persist_wallet("test");
        let _ = app.update(Message::WalletSaved(Ok(Some((
            test_key(),
            wallet::KeyOrigin::Minted,
        )))));
        assert!(!app.vault.is_unlocked());

        app.vault
            .unlock(None, wallet::KeyStatus::Ok, wallet::SealedLoad::default());
        let _ = app.persist_wallet("test");
        let _ = app.update(Message::WalletSaved(Ok(Some((
            test_key(),
            wallet::KeyOrigin::Minted,
        )))));
        assert!(app.vault.can_persist(), "the save's key reached the vault");
        let rev = app.vault.revision();
        let _ = app.persist_wallet("test");
        let _ = app.update(Message::WalletSaved(Ok(Some((
            wallet::DataKey::for_test([7; 32]),
            wallet::KeyOrigin::Existing,
        )))));
        assert_eq!(app.vault.revision(), rev, "a keyed epoch keeps its key");
        // A failed save leaves a keyless vault keyless.
        let mut app = build_app(placeholder_screen());
        app.vault
            .unlock(None, wallet::KeyStatus::Ok, wallet::SealedLoad::default());
        app.db.running = Some(DbOp::WalletSave);
        let _ = app.update(Message::WalletSaved(Err("disk full".into())));
        assert!(!app.vault.can_persist());
    }

    /// A save that wrote the descriptor but couldn't settle the data key (`Ok(None)`) is a
    /// success: no toast, the next queued op goes out, and the vault keeps what it had — keyless
    /// stays keyless, a keyed epoch keeps its key.
    #[test]
    fn a_wallet_save_without_a_key_leaves_the_vault_alone() {
        let (_, a0) = local_signer_and_account(1);
        let mut app = unlocked_app(WalletDescriptor::single(a0));
        app.vault
            .unlock(None, wallet::KeyStatus::Ok, wallet::SealedLoad::default());
        let rev = app.vault.revision();
        let _ = app.persist_wallet("test");
        let _ = app.persist_wallet("test");
        assert_eq!(app.save_state_name(), "saving+queued");
        let next = app.update(Message::WalletSaved(Ok(None)));
        assert!(next.units() > 0, "the queued save went out");
        assert_eq!(app.save_state_name(), "saving");
        assert!(app.toast.is_none(), "nothing failed");
        assert!(!app.vault.can_persist(), "still keyless");
        assert_eq!(app.vault.revision(), rev, "the vault is untouched");

        let _ = app.update(Message::WalletSaved(Ok(Some((
            test_key(),
            wallet::KeyOrigin::Minted,
        )))));
        assert!(app.vault.can_persist());
        let rev = app.vault.revision();
        let _ = app.persist_wallet("test");
        let done = app.update(Message::WalletSaved(Ok(None)));
        assert_eq!(done.units(), 0, "nothing queued, and no failure toast");
        assert_eq!(app.save_state_name(), "idle");
        assert!(app.vault.can_persist(), "a keyed epoch keeps its key");
        assert_eq!(app.vault.revision(), rev);
        // A failed save in the same spot does toast: that's what the count above tells apart.
        let _ = app.persist_wallet("test");
        assert_eq!(
            app.update(Message::WalletSaved(Err("disk full".into())))
                .units(),
            1
        );
    }

    /// A failed wallet save gets the plain toast whether or not the wallet file's saved history
    /// can be read: saves don't depend on it, so the toast never sends the user to the reset.
    #[test]
    fn a_failed_save_never_points_to_the_sealed_reset() {
        let plain = App::wallet_save_failed_toast("disk full");
        assert_eq!(
            plain,
            "Kao couldn't save your wallet (disk full). Your latest change works for now but may \
             be gone after a restart."
        );
        assert!(!plain.contains("Reset saved history"), "{plain}");

        // Through `update`, with the saved state unreadable: the same plain toast, and the
        // failure lands (and frees the file) as before.
        let mut app = build_app(placeholder_screen());
        app.vault.unlock(
            None,
            wallet::KeyStatus::Unavailable,
            wallet::SealedLoad::default(),
        );
        app.db.running = Some(DbOp::WalletSave);
        let toast_task = app.update(Message::WalletSaved(Err("disk full".into())));
        assert_eq!(toast_task.units(), 1, "the toast");
        assert_eq!(app.save_state_name(), "idle");
    }

    /// An unlock without its data key — the row unreadable (`Lost`), or a key the unlock couldn't
    /// write — queues the wallet save that mints one, behind the contacts load; its `WalletSaved`
    /// hands the vault the minted key, so what the vault records this session reaches disk. An
    /// unlock with its key runs no such save, and neither does one whose key the storage couldn't
    /// be read for (`Unavailable`): a save would find that same key, which the epoch can't adopt.
    #[test]
    fn an_unlock_without_its_data_key_mints_one_with_a_wallet_save() {
        use wallet::KeyStatus;
        for (data_key, status, mints) in [
            (None, KeyStatus::Lost, true),
            (None, KeyStatus::Ok, true),
            (None, KeyStatus::Unavailable, false),
            (Some(test_key()), KeyStatus::Ok, false),
        ] {
            let mut app = build_app(placeholder_screen());
            app.pp_loaded = true;
            let wallet = WalletDescriptor::single(local_signer_and_account(1).1);
            let _ = app.adopt_unlocked_wallet(test_pw(), unlocked_with(wallet, data_key, status));
            assert_eq!(app.db.running, Some(DbOp::ContactsLoad), "{status:?}");
            assert_eq!(app.db.wallet_save_queued, mints, "{status:?}");
            if !mints {
                continue;
            }
            assert!(
                !app.vault.can_persist(),
                "{status:?}: keyless until the save lands"
            );
            let _ = app.update(Message::ContactsLoaded(Ok(Vec::new())));
            assert_eq!(app.db.running, Some(DbOp::WalletSave), "{status:?}");
            let _ = app.update(Message::WalletSaved(Ok(Some((
                test_key(),
                wallet::KeyOrigin::Minted,
            )))));
            assert!(
                app.vault.can_persist(),
                "{status:?}: the minted key reached the vault"
            );
        }
    }

    /// Lock: the vault's epoch ends before anything else (records and key out of memory), and
    /// the unlock screen holds the successor slot, so its unlock waits for whatever the lock left
    /// running in the shared teardown registry.
    #[test]
    fn lock_ends_the_vault_epoch_and_hands_the_unlock_screen_the_successor_slot() {
        let mut app = build_app(placeholder_screen());
        app.passphrase = Some(test_pw());
        app.pp_loaded = true;
        app.vault.unlock(
            Some(test_key()),
            wallet::KeyStatus::Ok,
            wallet::SealedLoad::default(),
        );
        let old = app.wc_slot.clone();
        // Nothing running: no task, and nothing for a quit to wait on.
        assert_eq!(app.lock_wallet().units(), 0);
        assert!(!app.vault.is_unlocked() && !app.vault.can_persist());
        assert!(old.is_closed() && !app.wc_slot.is_closed());
        let Screen::Unlock(unlock) = &app.screen else {
            panic!("on the unlock screen");
        };
        assert!(app.wc_slot.begin_start());
        assert!(
            unlock.slot().is_starting(),
            "the unlock screen holds the App's (successor) slot"
        );
        app.wc_slot.start_failed();
    }

    /// Without a data key, lock falls back to the full teardown: the dapp hears 6000 — as before
    /// the vault existed — and the next unlock starts empty.
    #[tokio::test]
    async fn a_keyless_lock_tears_walletconnect_down() {
        let (_relay, dapp, _events, rt, slot) = testkit::harness().await;
        let topic = testkit::connect_raw(&rt, &dapp, WC_ADDR, &[1]).await;
        let mut app = build_app(placeholder_screen());
        app.wc_slot = slot.clone();
        app.vault
            .unlock(None, wallet::KeyStatus::Ok, wallet::SealedLoad::default());
        let task = app.lock_wallet();
        assert!(task.units() > 0);
        assert!(rt.is_closed(), "closed synchronously");
        testkit::settle(|| !dapp.sessions().iter().any(|s| s.topic == topic)).await;
        assert!(
            !dapp.sessions().iter().any(|s| s.topic == topic),
            "the dapp heard 6000"
        );
    }

    /// With a data key, lock suspends: the runtime closes synchronously (nothing in flight can
    /// broadcast), but the dapp is told nothing and keeps its session for the next unlock.
    #[tokio::test]
    async fn a_lock_with_a_data_key_suspends_and_the_dapp_keeps_its_session() {
        let (_relay, dapp, _events, rt, slot) = testkit::harness().await;
        let topic = testkit::connect_raw(&rt, &dapp, WC_ADDR, &[1]).await;
        let mut app = build_app(placeholder_screen());
        app.wc_slot = slot.clone();
        app.vault.unlock(
            Some(test_key()),
            wallet::KeyStatus::Ok,
            wallet::SealedLoad::default(),
        );
        let task = app.lock_wallet();
        assert!(task.units() > 0, "the suspend runs as a task");
        assert!(rt.is_closed(), "closed synchronously");
        app.wc_slot
            .wait_idle(crate::walletconnect::QUIT_TEARDOWN_BUDGET)
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            dapp.sessions().iter().any(|s| s.topic == topic),
            "no 6000: the session stays for the next unlock"
        );
    }

    /// Quit with a data key suspends the same way, and the quit waits for it: the wait stays
    /// pending while the suspend and the writer's drain run, and by the time it resolves the
    /// suspend's final WalletConnect state was handed to the vault and nothing runs any more.
    #[tokio::test]
    async fn quit_with_a_data_key_suspends_and_waits_for_it() {
        let dir = tempfile::tempdir().unwrap();
        // A file the writer can't land on: its drain takes a few bounded attempts.
        let vault = Vault::with_store_path(dir.path().join("absent.redb"));
        vault.unlock(
            Some(test_key()),
            wallet::KeyStatus::Ok,
            wallet::SealedLoad::default(),
        );
        let (_relay, dapp, _events, rt, slot) = testkit::harness_with_vault(&vault).await;
        let topic = testkit::connect_raw(&rt, &dapp, WC_ADDR, &[1]).await;
        let mut app = build_app(placeholder_screen());
        app.wc_slot = slot.clone();
        app.vault = vault.clone();
        // What the connect saved goes, so only the suspend's final save can put one back.
        vault.session().clear_wc_state();
        assert_eq!(vault.last_saved_wc_state(), Some(None));

        let wait = app.begin_quit().expect("the suspend runs: the quit waits");
        assert!(rt.is_closed() && !app.vault.is_unlocked());
        let mut wait = std::pin::pin!(wait);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut wait)
                .await
                .is_err(),
            "still waiting while the suspend and the drain run"
        );
        assert!(app.wc_slot.teardowns_running() > 0);
        tokio::time::timeout(
            crate::walletconnect::QUIT_TEARDOWN_BUDGET + std::time::Duration::from_secs(2),
            wait,
        )
        .await
        .expect("the wait resolves");
        assert_eq!(app.wc_slot.teardowns_running(), 0, "nothing left running");
        assert!(
            matches!(vault.last_saved_wc_state(), Some(Some(_))),
            "the suspend's final save happened before the wait resolved"
        );
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(dapp.sessions().iter().any(|s| s.topic == topic));
    }

    /// A lock's vault writer still draining (here: a batch it can't land) is counted, so a quit
    /// right after waits for it instead of cutting it short.
    #[tokio::test]
    async fn quit_waits_for_a_tracked_vault_drain() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::with_store_path(dir.path().join("wallet.redb"));
        let mut app = build_app(placeholder_screen());
        app.wc_slot = WcSlot::with_vault(vault.clone());
        app.vault = vault;
        app.vault.unlock(
            Some(test_key()),
            wallet::KeyStatus::Ok,
            wallet::SealedLoad::default(),
        );
        app.vault
            .session()
            .message_signed(crate::vault::NewSigned::default());
        let _ = app.lock_wallet();
        assert!(app.wc_slot.teardowns_running() > 0, "the drain is counted");
        let wait = app.begin_quit().expect("the quit waits for the drain");
        let mut wait = std::pin::pin!(wait);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut wait)
                .await
                .is_err(),
            "pending while the drain runs"
        );
        assert!(app.wc_slot.teardowns_running() > 0, "the drain still runs");
        tokio::time::timeout(
            crate::walletconnect::QUIT_TEARDOWN_BUDGET + std::time::Duration::from_secs(2),
            wait,
        )
        .await
        .expect("the wait resolves");
        assert_eq!(
            app.wc_slot.teardowns_running(),
            0,
            "it resolved once the drain ended"
        );
    }

    // ── Privacy Pools seed safety (DESIGN §1.4) ─────────────────────────

    /// While this session's seed load hasn't succeeded, Create is refused before anything is
    /// generated or written: a seed that couldn't be read may well exist.
    #[test]
    fn a_pool_identity_is_never_created_over_an_unread_seed() {
        let mut app = build_app(placeholder_screen());
        app.passphrase = Some(test_pw());
        app.pp_loaded = false;
        let _ = app.pool_create_identity();
        assert!(app.pp_seed.is_none() && !app.pp_loaded);
        // A loaded session's retry is a no-op (no second store read).
        app.pp_loaded = true;
        let _ = app.retry_pp_identity();
        assert!(app.pp_seed.is_none() && app.pp_loaded);
    }

    /// "Try again" that fails again says so on the pool pane — the card alone wouldn't change, and
    /// the button would seem to do nothing; one that reads the seed clears the unreadable state.
    #[test]
    fn a_pool_identity_retry_that_fails_again_says_so() {
        let mut app = unlock(WalletDescriptor::single(local_signer_and_account(1).1));
        app.pp_loaded = false;
        let _ = app.retry_pp_identity_with(|_| Err(wallet::WalletError::Encryption("x".into())));
        assert!(!app.pp_loaded);
        let Screen::Wallet(ws) = &mut app.screen else {
            panic!("on the dashboard");
        };
        assert_eq!(
            ws.test_pool_error().as_deref(),
            Some(POOL_IDENTITY_STILL_UNREAD)
        );
        let _ = app.retry_pp_identity_with(|_| Ok(None));
        assert!(app.pp_loaded);
    }

    // ── Redaction by type (DESIGN §4) ───────────────────────────────────

    /// App traces whole messages before any arm runs, so the new payloads redact by type: the
    /// unlock result (data key, sealed rows), a save's data key, a pool sync, and the history
    /// panes' messages (ids only).
    #[test]
    fn new_message_payloads_redact_by_type() {
        let (_, account) = local_signer_and_account(1);
        let unlocked = Arc::new(wallet::Unlocked {
            descriptor: WalletDescriptor::single(account),
            data_key: Some(wallet::DataKey::for_test([0x5a; 32])),
            key_status: wallet::KeyStatus::Ok,
            sealed: wallet::SealedLoad {
                wc_state: Some(zeroize::Zeroizing::new(b"symKeys-SECRET".to_vec())),
                ..Default::default()
            },
        });
        let messages = [
            Message::Unlock(UnlockMessage::UnlockResult(Ok(unlocked))),
            Message::WalletSaved(Ok(Some((
                wallet::DataKey::for_test([0x5a; 32]),
                wallet::KeyOrigin::Existing,
            )))),
            Message::WalletDashboard(WalletDashboardMessage::PoolSynced {
                pool: alloy::primitives::Address::ZERO,
                chain: crate::chain::Chain::Mainnet,
                result: crate::ui::wallet_dashboard::PoolSyncResult(Err("SECRET".into())),
            }),
            Message::WalletDashboard(WalletDashboardMessage::Wc(
                crate::ui::wallet_dashboard::WcMsg::Restored(
                    crate::walletconnect::RestoreOutcome::Nothing,
                ),
            )),
        ];
        for m in messages {
            let dbg = format!("{m:?}");
            assert!(
                !dbg.contains("SECRET") && !dbg.contains("90, 90") && !dbg.contains("5a5a"),
                "{dbg}"
            );
        }
    }
}
