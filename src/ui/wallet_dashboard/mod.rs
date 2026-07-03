//! Kao Wallet dashboard — the main screen shown after unlock.
//!
//! Layout: a wide sidebar (brand mark · account card · Portfolio/Apps/
//! Activity/Settings nav rows · network-privacy footer), a slim header
//! (account title · Helios badge · mood kaomoji), and one of the content
//! panes. Send and Receive are modal overlays rendered via `stack`.

use std::mem;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use alloy::primitives::{Address, B256, Bytes, TxHash, U256};
use iced::border::Radius;
use iced::widget::operation::focus as focus_widget;
use iced::widget::{Space, column, container, row, stack, text};
use iced::{Alignment, Background, Border, Element, Length, Padding, Subscription, Task};
use tracing::{debug, error, info, warn};

mod account_dropdown;
mod activity;
mod appearance;
mod apps;
mod contacts_settings;
mod function_panel;
mod header;
mod home;
mod modal_chrome;
mod names_app;
mod nav;
mod networks;
mod pool_app;
mod receive;
mod safe_tx_detail;
mod safes_settings;
mod send;
mod settings_root;
mod sidebar;
mod sign_review;
mod sim_view;
mod swap;
mod tx_details;

use account_dropdown::AccountDropdown;
use apps::AppsPane;
use contacts_settings::ContactsPane;
use receive::ReceivePane;
use safe_tx_detail::SafeTxDetailPane;
use safes_settings::SafesPane;
use send::SafeSendRequest;
use send::SendPane;
use swap::SwapPane;
use tx_details::TxDetailsPane;

/// User mood emoji shown in the header and balance hero. Currently constant;
/// future iterations might derive it from portfolio P&L or recent activity.
pub(super) const MOOD: &str = "(´｡• ᵕ •｡`)";

/// How many transactions to ask the indexer for. Generous enough that the
/// Activity scroll view is rarely empty after a single round-trip, small
/// enough that providers without server-side paging stay responsive.
const HISTORY_LIMIT: usize = 50;

/// How many of the address's CoW orders the Apps "Fetch" action pulls per
/// chain (newest first). CoW caps a page at 1000; 100 covers essentially any
/// real user's history in one round trip without rendering a huge list. Repeat
/// fetches dedup by UID, so this is a per-fetch page size, not a hard ceiling
/// on what can accumulate.
const ACCOUNT_ORDERS_LIMIT: u16 = 100;

/// How long after a copy we wait before nuking the clipboard. Doubles as
/// the lifetime of the bottom-right "autoclear in N…" chip — the chip's
/// progress bar fills this whole duration.
const CLIPBOARD_CLEAR_SECS: u64 = 10;

use modal_chrome::ModalChrome;
pub use nav::Nav;

use crate::chain::PerChain;
use crate::cow::{
    self,
    composer::SwapDraft,
    tracked::{OrderStatus, TrackedOrder},
};
use crate::indexer::IndexedTx;
use crate::names::manage::{NameStatus, Registry, SearchHit};
use crate::names::registrar::{Namespace, RegisterPlan};
use crate::net::{BalanceFetcher, VerificationStatus};
use crate::portfolio::{DiscoveredToken, LiveToken, PortfolioCache};
use crate::settings::{self, IndexerProvider};
use crate::ui::kao_theme::with_alpha;
use crate::ui::kao_theme::{KaoTheme, ThemeKind};
use crate::ui::kao_widgets::{bold, copy_toast_progress, fill_style, mark_copied, mono};
use crate::ui::network_setup::{self, NetworkSetupScreen, WizardMode};
use crate::sign::context::{SafeNeed, SignerContext};
use crate::wallet::sim::SimulationResult;
use crate::wallet::tx::SendPlan;
use crate::wallet::{
    AccountDescriptor, Contact, ContactsBook, KaoSigner, SafeDescriptor, SignerHandoff,
    account_address, ensure_connected, handoff_with, short_address,
};

// ── colored_address copy-toast kicks ──────────────────────────────────────────
// Each screen that renders a `colored_address` implements `CopyKick` so a
// click-to-copy publishes a no-op message that wakes this screen's update loop
// and starts the bottom-right "Copied!" toast animation (see
// `kao_widgets::CopyKick` — a click changes no app state, so nothing would
// otherwise re-evaluate the toast's tick subscription). The dashboard panes
// return their `AddressCopied` variant (ignored in `update`); the standalone
// Safe-onboarding screen shows no toast and keeps the `None` default.
use crate::ui::kao_widgets::CopyKick;

impl CopyKick for send::Message {
    fn copy_kick() -> Option<Self> {
        Some(send::Message::AddressCopied)
    }
}
impl CopyKick for tx_details::Message {
    fn copy_kick() -> Option<Self> {
        Some(tx_details::Message::AddressCopied)
    }
}
impl CopyKick for sign_review::Message {
    fn copy_kick() -> Option<Self> {
        Some(sign_review::Message::AddressCopied)
    }
}
impl CopyKick for names_app::Message {
    fn copy_kick() -> Option<Self> {
        Some(names_app::Message::AddressCopied)
    }
}
impl CopyKick for contacts_settings::Message {
    fn copy_kick() -> Option<Self> {
        Some(contacts_settings::Message::AddressCopied)
    }
}
impl CopyKick for safes_settings::Message {
    fn copy_kick() -> Option<Self> {
        Some(safes_settings::Message::AddressCopied)
    }
}
impl CopyKick for safe_tx_detail::Message {
    fn copy_kick() -> Option<Self> {
        Some(safe_tx_detail::Message::AddressCopied)
    }
}
impl CopyKick for crate::ui::safe_onboarding::Message {}

// ── Messages ────────────────────────────────────────────────────────────────

/// Which swap surface a CoW task's result routes back to: the blocking modal
/// (surface 1) or the persistent Apps pane (surface 2).
#[derive(Debug, Clone, Copy)]
pub enum CowHost {
    Modal,
    Apps,
}

#[derive(Debug, Clone)]
pub enum Message {
    /// Side-effect ack from the Mainnet Helios verification refresh.
    /// The handler just samples `network.last_status(Mainnet)` to drive
    /// the header badge — no per-address state changes here, so a stale
    /// fetch landing after an account switch is harmless.
    VerificationRefreshed,
    /// The App refreshed the wallet's Safes (typically on
    /// app-open). Carries the new full safes vec — the dashboard
    /// replaces its stale clone wholesale so the account dropdown
    /// stops rendering old labels / owner sets / watch-vs-signer
    /// classifications. Sent at most once per unlock.
    SafesUpdated(Vec<SafeDescriptor>),
    /// Per-chain portfolio result. The dashboard issues one fetch per
    /// configured chain in parallel and merges by `chain` as each lands,
    /// so a slow Optimism RPC never blocks the Mainnet rows from
    /// rendering. `address` is checked on arrival so a late response
    /// can't pollute the wrong account's portfolio (or its cache slot).
    PortfolioFetched {
        address: Address,
        /// The network the rows were fetched from — a built-in chain or a
        /// user-defined custom network. Keys the cache slot and gates the
        /// merge so a custom network's rows land in their own slot.
        network: crate::chain::NetworkId,
        result: Result<Vec<LiveToken>, String>,
    },
    /// Result of a per-chain history fetch. `address` is the address it
    /// was issued against (dropped on mismatch); `chain` is the network
    /// it was fetched from. Each configured chain emits its own message
    /// so a slow L2 RPC can't stall Mainnet rows from rendering.
    HistoryFetched {
        address: Address,
        chain: crate::chain::Chain,
        result: Result<Vec<IndexedTx>, String>,
    },
    /// User clicked the "couldn't load activity" retry button.
    RetryHistory,
    /// Result of fetching the active Safe's pending multisig queue from
    /// the Safe Transaction Service. `safe` is the Safe address the fetch
    /// was issued against — dropped on arrival if the user has switched
    /// identity since (same staleness guard as `PortfolioFetched`).
    SafePendingFetched {
        safe: Address,
        chain: crate::chain::Chain,
        result: Result<Vec<crate::safe::service::PendingSafeTx>, String>,
    },
    SelectNav(Nav),
    SelectTheme(ThemeKind),
    OpenSend,
    OpenReceive,
    OpenSwap,
    OpenAccountDropdown,
    /// User clicked the sidebar's "Reconnect" button for a hardware account
    /// whose device isn't connected. Escalates to the App to push the
    /// matching connect screen (no Send modal afterwards).
    ReconnectHardware,
    /// User clicked the refresh button next to the assets list.
    /// Re-issues the portfolio fetch (and verification refresh) for
    /// the current identity. Tokens stay visible during the refresh;
    /// only the indicator on the button reflects the in-flight state.
    RefreshPortfolio,
    /// User clicked an activity row. The argument is the index into
    /// `self.history` at the moment of the click; bounds-checked when
    /// handling because the history can refresh between view and event.
    OpenTxDetails(usize),
    AccountDropdown(account_dropdown::Message),
    Receive(receive::Message),
    Send(send::Message),
    Swap(swap::Message),
    TxDetails(tx_details::Message),
    Tick,
    OpenNetworksSettings,
    #[allow(dead_code)]
    Networks(networks::Message),
    NetworkWizard(network_setup::Message),
    OpenSafesSettings,
    SafesSettings(safes_settings::Message),
    OpenAppearanceSettings,
    CloseAppearanceSettings,
    OpenContactsSettings,
    /// Open the Contacts pane in Add mode pre-filled with the given
    /// address (and optional ENS string when known). Wired from the Send
    /// pane's "Save as contact" CTA so users go straight from a fresh
    /// recipient to a contact draft.
    OpenContactsPaneWith {
        address: Address,
        ens: Option<String>,
    },
    Contacts(contacts_settings::Message),
    /// Result of a Safe-send sign+broadcast task. No signer handoff
    /// needed: the executor was derived inside the task from a
    /// linked owner's key, so nothing was moved out of the
    /// dashboard.
    SafeSendBroadcastReturn(Result<TxHash, String>),
    /// Result of a Safe-send *propose-to-service* task (vs. the direct
    /// broadcast above).
    SafeSendProposeReturn(Result<(), String>),
    /// User tapped a pending Safe queue row. Index into `safe_pending`
    /// at click time; bounds-checked on handling.
    OpenSafeTxDetails(usize),
    /// Child messages from the Safe-tx detail modal.
    SafeTxDetail(safe_tx_detail::Message),
    /// Full detail (owners + signatures) for the open queued tx landed.
    SafeTxDetailLoaded(Result<crate::safe::service::SafeTxDetail, String>),
    /// Inner-call preflight for the open queued tx landed. Tagged with
    /// the safeTxHash it was simulated for — the staleness guard (the
    /// analogue of safe_send's seq): dropped unless the detail modal is
    /// still showing that exact tx.
    SafeTxInnerSimLoaded {
        safe_tx_hash: B256,
        result: SimulationResult,
    },
    /// Execute-time (`execTransaction`) preflight for the open queued
    /// tx landed. Same safeTxHash staleness guard as the inner sim.
    SafeTxExecSimLoaded {
        safe_tx_hash: B256,
        result: SimulationResult,
    },
    /// A confirm / execute / reject action finished. `Ok` carries a short
    /// success label for the modal's notice line.
    SafeTxActionDone(Result<String, String>),
    /// Header pencil clicked — switch the title slot to an editable text
    /// input pre-filled with the active account's current display name.
    BeginRenameAccount,
    /// Each keystroke while the rename input is open.
    RenameInput(String),
    /// User pressed Enter (or clicked ✓) — commit the draft to the account.
    CommitRename,
    /// User pressed Escape (or clicked ✗) — discard the draft.
    CancelRename,
    /// Result of a sign-and-broadcast task spawned from `Message::Send(Confirm)`.
    /// Carries the signer back via `SignerHandoff` so the dashboard can put it
    /// back into `self.signer` (it had to be moved out by value to be sent to
    /// the async task — `KaoSigner` is non-`Clone`).
    SendBroadcastReturn {
        result: Result<TxHash, String>,
        signer: SignerHandoff,
    },
    /// Result of the dashboard's startup reverse-ENS lookup. Carries the
    /// address it was issued against so a quick account switch can't apply
    /// a name to the wrong account.
    EnsAutoNameResolved {
        address: Address,
        result: Result<Option<String>, String>,
    },
    /// Side-effect ack from a clipboard write. No-op handler.
    ClipboardWritten,
    /// Auto-clear timer fired. Carries the generation it was armed
    /// against; if a fresher copy bumped the counter, this dispatches
    /// nothing and returns. Otherwise it kicks the ownership-check
    /// `clipboard::read` so we don't clobber unrelated content the user
    /// copied after the wallet's copy.
    ClipboardClearArmed {
        generation: u64,
    },
    /// Result of the ownership check. Clears the system clipboard only
    /// when its current contents still match what the wallet wrote
    /// (guards against the user copying a phone number five seconds
    /// later and having it nuked at second ten).
    ClipboardClearProbe {
        generation: u64,
        /// Live system clipboard contents — redacted because the user may
        /// have copied anything (including a secret from another app)
        /// since the wallet's write.
        actual: Option<crate::trace::SecretInput>,
    },
    /// Child messages from the Apps (swap workspace) pane.
    Apps(apps::Message),
    /// User interacted with the clear-signing review overlay (confirm/cancel/esc).
    SignReview(sign_review::Message),
    /// A sign-review prepare task finished building its review steps (decoded
    /// raw-tx legs, or Safe `execTransaction` / EIP-1271 steps). `seq` round-trips
    /// so a result for a review the user cancelled or replaced is dropped. `Err`
    /// carries a build/decode failure to surface to the user.
    SignReviewPrepared {
        seq: u64,
        steps: Result<Vec<sign_review::SignStep>, String>,
    },
    /// Names app: reverse-lookup discovery finished. `owner` is the account the
    /// scan was spawned for — the handler drops it if the active account changed.
    NameReverseScanned {
        owner: Address,
        result: Result<Vec<NameStatus>, String>,
    },
    /// Names app: a manually-added name's verified status.
    NameStatusLoaded {
        owner: Address,
        result: Result<NameStatus, String>,
    },
    /// Names app: cross-namespace availability + price search finished. `seq`
    /// round-trips so the pane can drop a reply the user has since superseded.
    NameSearched {
        owner: Address,
        seq: u64,
        result: Result<Vec<SearchHit>, String>,
    },
    /// Names app: an ENS re-quote (after a duration change) finished. `years`
    /// round-trips so the pane can drop a result the user has since superseded.
    NameQuoted {
        owner: Address,
        years: u32,
        result: Result<crate::names::manage::RegisterQuote, String>,
    },
    /// Names app: the commit landed (mined). Carries the plan (with its secret)
    /// for the reveal step, and the parked signer back.
    NameCommitted {
        result: Result<(RegisterPlan, TxHash), String>,
        signer: SignerHandoff,
    },
    /// Names app: register/reveal finished. `String` is the registered name.
    NameRegistered {
        result: Result<(String, TxHash), String>,
        signer: SignerHandoff,
    },
    /// Names app: renewal finished.
    NameRenewed {
        result: Result<(String, TxHash), String>,
        signer: SignerHandoff,
    },
    /// Names app: set-recipient finished.
    NameRecipientSet {
        result: Result<(String, TxHash), String>,
        signer: SignerHandoff,
    },
    /// A CoW quote returned (or errored). Routed back to the host's composer.
    CowQuote {
        host: CowHost,
        result: Result<crate::cow::api::QuoteResponse, String>,
    },
    /// A CoW order placement finished. Carries the signer back via
    /// `SignerHandoff` (moved out for the async approve/sign path, like Send).
    CowPlaced {
        host: CowHost,
        result: Result<TrackedOrder, String>,
        signer: SignerHandoff,
    },
    /// An off-chain order cancellation finished. Signer handed back as above.
    /// `host` records which surface (Swap modal / Apps) raised the cancel so a
    /// failure can be reported back there instead of being swallowed.
    CowCancel {
        host: CowHost,
        uid: String,
        result: Result<(), String>,
        signer: SignerHandoff,
    },
    /// A tracked order's status poll returned. Errors (incl. indexer-lag 404s)
    /// are ignored so a transient miss never flips an order to a wrong state.
    CowStatus {
        uid: String,
        result: Result<crate::cow::api::OrderStatusResponse, String>,
    },
    /// Pool discovery finished for `chain` (API list verified via Helios). Shown
    /// immediately; per-pool account state then syncs in the background.
    PoolsDiscovered {
        chain: crate::chain::Chain,
        result: Result<Vec<crate::pool::PoolInfo>, String>,
    },
    /// One pool's account state finished syncing (errors are ignored so the pool
    /// still shows, just without balances). Carries the refreshed note cache to
    /// persist, and `chain` so it can be keyed/stored per network.
    PoolSynced {
        pool: Address,
        chain: crate::chain::Chain,
        result: Result<(crate::pool::sync::PoolState, crate::pool::sync::CachedNotes), String>,
    },
    /// A relayer fee quote for a withdrawal returned.
    PoolQuoted {
        result: Result<crate::pool::relayer::QuoteResponse, String>,
    },
    /// Forward name resolution for the Privacy Pools withdrawal target finished
    /// (`.eth` / `.gwei` / `.wei` / `.xns`, or a picked contact's pinned name).
    /// `seq` drops stale lookups; `name` disambiguates when the input changed.
    PoolTargetResolved {
        seq: u64,
        name: String,
        result: Result<Option<Address>, String>,
    },
    /// ASP approval status for a pool's accounts (opt-in feed) finished: the
    /// subset of the account labels that are in the approved Association Set.
    /// Drives the per-account "approved / pending review" badges.
    PoolApproval {
        pool: Address,
        result: Result<std::collections::HashSet<[u8; 32]>, String>,
    },
    /// A pool tx (deposit / self-relay withdraw / ragequit) or a relayed
    /// withdrawal finished. On success carries an optional tx hash. `signer` is
    /// `Some` for EOA paths (parked, needs reclaim), `None` for the relayed path
    /// (the relayer submits, the user signs nothing). `kind` labels the success
    /// screen (all three ops share this one result message).
    PoolSubmitted {
        result: Result<Option<String>, String>,
        signer: Option<SignerHandoff>,
        kind: pool_app::PoolTxKind,
    },
    /// A ragequit commitment proof + calldata finished building; on success the
    /// coordinator opens the clear-sign review for the `Pool.ragequit` tx.
    PoolRagequitReady {
        result: Result<sign_review::PoolSign, String>,
    },
    /// A broadcast pool deposit finished mining — re-sync so its new pool
    /// account + anonymity set appear. The immediate re-sync `set_submitted`
    /// fires runs before the deposit is on-chain, so this second pass (gated on
    /// the receipt) is what actually reflects it, without a manual refresh.
    /// `pool` is the deposited pool (if known), so its "depositing…" card
    /// animation is cleared exactly when its confirmation lands.
    PoolResync {
        chain: crate::chain::Chain,
        pool: Option<Address>,
    },
    /// Poll tick: refresh every non-terminal tracked order. Only fires while at
    /// least one such order exists (see `subscription`).
    CowPollTick,
    /// Result of the Apps "Fetch" action: the address's CoW order history for
    /// `chain`, already mapped to `TrackedOrder`s. Upserted into
    /// `tracked_orders` (dedup by UID) so orders from past sessions appear and
    /// known orders pick up fresh status. `address` guards against an account
    /// switch landing the fetch on the wrong identity.
    CowAccountOrders {
        address: Address,
        chain: crate::chain::Chain,
        result: Result<Vec<TrackedOrder>, String>,
    },
    /// Targeted balance refresh after a swap filled. Carries the two assets
    /// the order touched (the "slots": native ETH as `None`, each ERC-20 leg
    /// as `Some(addr)`) so the handler replaces *only* those rows instead of
    /// the whole network — a drained sell token disappears, a freshly-bought
    /// token appears, every other row is left alone. `address`/`network` gate
    /// the merge the same way `PortfolioFetched` does.
    SwapTokensRefetched {
        address: Address,
        network: crate::chain::NetworkId,
        slots: Vec<Option<Address>>,
        result: Result<Vec<LiveToken>, String>,
    },
}

/// Outcomes bubbled up to the parent app.
#[derive(Debug, Clone)]
pub enum Outcome {
    Switch(usize),
    Add,
    /// User edited the active account's display name. Carries the new
    /// value (or `None` to clear back to the indexed default).
    RenameActive(Option<String>),
    /// User saved a new/edited contacts list. The App writes the vec
    /// into the shared in-memory book and dispatches a disk save.
    SaveContacts(Vec<Contact>),
    /// User asked to reconnect a hardware account whose signer is the
    /// view-only placeholder (the device wasn't connected at unlock). The
    /// App pushes the matching reconnect screen and, on success, re-enters
    /// the dashboard with the live signer. `open_send` is set when the
    /// reconnect was triggered by clicking Send (so the Send modal is
    /// re-opened afterwards); the sidebar's Reconnect button leaves it
    /// false, landing the user back on the dashboard with nothing popped.
    NeedsHardwareReconnect {
        open_send: bool,
    },
    /// User changed a Safe's transaction-service mirror in Settings →
    /// Safes. The App writes it into `wallet.safes[index]`, persists,
    /// and pushes the updated list back via `Message::SafesUpdated`.
    SetSafeServiceUrl {
        index: usize,
        url: Option<String>,
    },
    /// Generate a fresh 24-word Privacy Pools mnemonic, persist it under the
    /// wallet passphrase, derive the account, and push it back via
    /// `WalletScreen::set_pp_account` + `show_pool_backup`. Needs the App's
    /// held passphrase, which the dashboard doesn't have.
    PoolCreateIdentity,
    /// Persist + adopt a restored Privacy Pools mnemonic.
    PoolRestoreIdentity(secrecy::SecretString),
    /// Re-load the pool seed and hand its phrase to the backup view.
    PoolRevealBackup,
}

impl Outcome {
    /// Variant name for the GUI state trace — never the payload, which can
    /// carry a restored pool mnemonic.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Switch(_) => "Switch",
            Outcome::Add => "Add",
            Outcome::RenameActive(_) => "RenameActive",
            Outcome::SaveContacts(_) => "SaveContacts",
            Outcome::NeedsHardwareReconnect { .. } => "NeedsHardwareReconnect",
            Outcome::SetSafeServiceUrl { .. } => "SetSafeServiceUrl",
            Outcome::PoolCreateIdentity => "PoolCreateIdentity",
            Outcome::PoolRestoreIdentity(_) => "PoolRestoreIdentity",
            Outcome::PoolRevealBackup => "PoolRevealBackup",
        }
    }
}

/// Connection state of the active account's hardware device, surfaced as a
/// status card at the bottom of the sidebar. `None` for software / view-only
/// accounts, which have no device to connect — the card is only meaningful
/// for Ledger / Trezor accounts. `connected` is false while the live signer
/// is the view-only placeholder (device not opened since unlock), which is
/// also what hides the Apps and Swap surfaces.
#[derive(Debug, Clone, Copy)]
pub enum HardwareStatus {
    Ledger { connected: bool },
    Trezor { connected: bool },
}

// ── State ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum Modal {
    None,
    // Boxed: the unified SendPane carries EoaState/SafeState + SimulationResult
    // inline, which would otherwise dominate the enum's size
    // (clippy::large_enum_variant).
    Send(Box<SendPane>),
    Receive(ReceivePane),
    Swap(SwapPane),
    AccountDropdown(AccountDropdown),
    TxDetails(TxDetailsPane),
    // Boxed: the pane carries two inline `Option<SimulationResult>`s,
    // which would otherwise dominate the enum's size
    // (clippy::large_enum_variant).
    SafeTxDetail(Box<SafeTxDetailPane>),
}

impl Modal {
    /// Variant name for the GUI state trace.
    fn name(&self) -> &'static str {
        match self {
            Modal::None => "None",
            Modal::Send(_) => "Send",
            Modal::Receive(_) => "Receive",
            Modal::Swap(_) => "Swap",
            Modal::AccountDropdown(_) => "AccountDropdown",
            Modal::TxDetails(_) => "TxDetails",
            Modal::SafeTxDetail(_) => "SafeTxDetail",
        }
    }
}

/// Which settings pane is currently rendered. The Settings nav slot can show
/// either the root list of categories or one of the deeper category screens.
#[derive(Debug)]
enum SettingsPane {
    Root,
    NetworkWizard(NetworkSetupScreen),
    Safes(SafesPane),
    Appearance,
    Contacts(ContactsPane),
}

impl SettingsPane {
    /// Variant name for the GUI state trace.
    fn name(&self) -> &'static str {
        match self {
            SettingsPane::Root => "Root",
            SettingsPane::NetworkWizard(_) => "NetworkWizard",
            SettingsPane::Safes(_) => "Safes",
            SettingsPane::Appearance => "Appearance",
            SettingsPane::Contacts(_) => "Contacts",
        }
    }
}

/// Variant name for the GUI state trace (`Nav` is defined in `nav.rs`; the
/// helper lives here with the other trace name helpers).
fn nav_name(nav: Nav) -> &'static str {
    match nav {
        Nav::Home => "Home",
        Nav::Apps => "Apps",
        Nav::Activity => "Activity",
        Nav::Settings => "Settings",
    }
}

#[derive(Debug)]
pub struct WalletScreen {
    /// Live signer kept alive for the dashboard's session. Hardware variants
    /// own a USB transport so the device must remain plugged in. The Send
    /// quick action is gated on `signer.can_sign()` to lock view-only
    /// accounts out of broadcasting transactions.
    signer: KaoSigner,
    address: Address,
    /// All accounts in the unlocked wallet, used to render the account
    /// dropdown. `accounts[active_index]` corresponds to `signer`.
    accounts: Vec<AccountDescriptor>,
    /// All Safes onboarded into this wallet. Surfaced in the account
    /// dropdown alongside accounts, both for visibility and so the
    /// `Safe signer` cross-badge can be computed for accounts that are
    /// linked owners. Updated whenever the App pushes a new
    /// `WalletDescriptor` (e.g. after Safe onboarding completes).
    safes: Vec<SafeDescriptor>,
    active_index: usize,
    theme_kind: ThemeKind,
    nav: Nav,
    modal: Modal,
    /// Open/close animation state for the Send/Receive/Swap modal slot. The
    /// account dropdown bypasses chrome (instant open/close).
    chrome: ModalChrome,
    /// Shared Helios-backed RPC client; cloned into each balance fetch task.
    network: Arc<dyn BalanceFetcher>,
    /// Verification state of the most recent Mainnet Helios call. Sampled
    /// from `network.last_status(Mainnet)` after `VerificationRefreshed`
    /// lands; rendered in the header as a small "Verified by Helios /
    /// Unverified RPC" badge.
    verification: VerificationStatus,
    /// Which Settings sub-screen is currently rendered.
    settings_pane: SettingsPane,
    /// Live portfolio entries fetched from on-chain balances + CoinGecko.
    portfolio: Vec<LiveToken>,
    /// True while a portfolio fetch is in flight.
    portfolio_loading: bool,
    /// True while a *user-initiated* refresh is in flight. The home
    /// view shows tokens normally and renders a small busy hint on
    /// the refresh button — distinct from `portfolio_loading`, which
    /// is the cold-start path that hides the asset list entirely.
    portfolio_refreshing: bool,
    /// Process-lifetime cache shared with `App` so switching back to a
    /// previously-loaded account renders its tokens immediately while a
    /// fresh fetch refreshes them in the background.
    portfolio_cache: PortfolioCache,
    /// Inline rename draft for the active account. `Some(s)` means the
    /// header is showing the rename text input; `None` means it's showing
    /// the static name + pencil affordance.
    rename_draft: Option<String>,
    /// Merged transactions across every configured chain, newest first
    /// (sorted by timestamp). Empty while every chain is still in flight
    /// or when no source returned rows.
    history: Vec<IndexedTx>,
    /// `true` while at least one per-chain history fetch is still in
    /// flight. Cleared when *every* chain has reported back.
    history_loading: bool,
    /// `true` once *any* per-chain history fetch has completed (Ok or
    /// Err) for this dashboard. Drives lazy-load: the first switch to
    /// Activity kicks off the fetch; subsequent switches re-render the
    /// cached rows. Reset to `false` only by building a fresh screen.
    history_loaded: bool,
    /// Per-chain error captured when both the indexer and the on-chain
    /// fallback failed. The activity pane shows the retry affordance
    /// only when the merged feed is empty *and* at least one chain
    /// errored — partial successes still render rows.
    history_errors: PerChain<Option<String>>,
    /// Set of chains we're still waiting on. As each chain lands the
    /// chain is removed; `history_loading` flips to `false` once empty.
    history_pending: Vec<crate::chain::Chain>,
    /// Shared contacts book. Read by the Send picker, the Send review
    /// step, the Activity feed (named counterparties), and the tx
    /// details modal; written by the Contacts settings pane on save.
    /// `Arc<RwLock<…>>` so a contact edit is visible everywhere on the
    /// next view tick without rebuilding the dashboard.
    contacts: Arc<RwLock<ContactsBook>>,
    /// When `Some(idx)`, the dashboard is in **Safe mode**: header,
    /// hero, portfolio, and quick actions key off `safes[idx]`'s
    /// address rather than the EOA `self.address`. The EOA signer
    /// stays alive for Safe-TX execution (it pays gas as the
    /// executor); only what the user *sees* re-keys. Clicking any
    /// account in the dropdown clears this back to `None`.
    active_safe: Option<usize>,
    /// The active Safe's pending multisig queue, fetched from the Safe
    /// Transaction Service and tagged with a lifecycle FSM state. Only
    /// populated in Safe mode; cleared on switch back to an EOA. Empty in
    /// EOA mode and when the active Safe has no queued transactions.
    safe_pending: Vec<crate::safe::service::PendingSafeTx>,
    /// True while the pending-queue fetch for the active Safe is in
    /// flight. Drives a muted "loading" line in the Home pane without
    /// blocking the asset list.
    safe_pending_loading: bool,
    /// Last pending-queue fetch error (service unreachable, decode
    /// failure). Rendered as a muted one-liner; never blocks the rest of
    /// the Home pane.
    safe_pending_error: Option<String>,
    /// Active clipboard auto-clear, set when the user copies anything
    /// from a child modal (Send, TxDetails). Drives the bottom-right
    /// countdown chip and the deferred ownership-checked clear.
    clipboard_clear: Option<ClipboardClearState>,
    /// Monotonic counter bumped on every fresh copy so a stale
    /// `ClipboardClearArmed` / `ClipboardClearProbe` from an older arm
    /// can't clobber the chip or the clipboard.
    clipboard_clear_gen: u64,
    /// CoW swap orders placed this session (both surfaces share this list).
    /// In-memory for v1; the poll subscription refreshes non-terminal entries.
    /// Filtered to the active address when rendered in the Apps pane.
    tracked_orders: Vec<TrackedOrder>,
    /// True while the EOA signer is parked for an in-flight CoW order op
    /// (place or cancel). During that window `self.signer` is a view-only
    /// placeholder, so `can_swap()` would read false and transiently hide the
    /// sidebar Apps tab + redirect `Nav::Apps` to the portfolio. The Apps
    /// surface keys off `apps_available()` (which ORs this in) so it stays put
    /// until the order op resolves in `CowPlaced` / `CowCancel`.
    order_op_in_flight: bool,
    /// The Apps (swap workspace) pane state — its inline swap composer. The
    /// order list it renders comes from `tracked_orders`, not the pane.
    apps: AppsPane,
    /// The clear-signing review gate, when one is open. Every in-app signature
    /// (CoW order/approval/EthFlow/cancel, name commit/register/renew/setAddr)
    /// routes through this overlay so the user reviews the decoded transaction
    /// before the key is touched. `None` means no review is pending.
    sign_review: Option<sign_review::SignReview>,
    /// Monotonic id for sign-review prepare tasks, so a decode result for a
    /// review the user has since cancelled/replaced is dropped on arrival.
    sign_review_seq: u64,
    /// The Privacy Pools account (dedicated pool mnemonic → master keys),
    /// derived by the App from the encrypted `pp` seed and pushed down here so
    /// the pool app can sync/prove. `None` until an identity exists + is loaded.
    pp_account: Option<privacy_pools::Account>,
    /// Next deposit index implied by deposits **confirmed this session**, keyed
    /// by pool address. Combined with the synced state's index so a second
    /// deposit never reuses one the chain scan hasn't caught up to — the pool
    /// contract rejects a reused precommitment with `PrecommitmentAlreadyUsed`.
    pool_session_deposits: std::collections::HashMap<Address, u64>,
    /// `(pool, index)` of the deposit currently under clear-sign review — set
    /// when the review opens, committed to `pool_session_deposits` only when the
    /// user confirms, so a cancelled review never burns an index.
    pending_pool_deposit: Option<(Address, u64)>,
    /// The pool of a deposit that has been dispatched to broadcast — carried
    /// from `dispatch_pool_sign` to `PoolSubmitted` (whose message doesn't name
    /// the pool) so that exact pool's card can animate until the deposit
    /// confirms. Taken on every `PoolSubmitted`.
    pool_deposit_in_flight: Option<Address>,
    /// Pool address → scope (decimal), populated at discovery. Lets the post-sync
    /// ASP approval fetch (which needs the `X-Pool-Scope` header) find a pool's
    /// scope from the `PoolSynced` message, which only names the pool by address.
    pool_scopes: std::collections::HashMap<Address, String>,
    /// Persisted note cache per `(chain_id, pool)` — the incremental-sync cursor
    /// and this account's recovered logs, loaded on identity set and refreshed
    /// on every sync so a re-open scans only new blocks (not from the deploy block).
    pool_note_cache: std::collections::HashMap<(u64, Address), crate::pool::sync::CachedNotes>,
    /// The account-derived key the note cache is encrypted under (see
    /// `pool::sync::notes_cipher_key`); `None` until an identity is loaded.
    pool_notes_key: Option<[u8; 32]>,
}

/// Tracks an in-flight clipboard auto-clear: when it lands, what we
/// wrote so the ownership check can decide whether to clear, and the
/// generation the timer was armed against for stale-task dispatch.
#[derive(Debug, Clone)]
struct ClipboardClearState {
    /// What the wallet wrote into the system clipboard. Compared
    /// against the live clipboard contents at probe time — if they
    /// differ, the user copied something else after us and we leave
    /// their content alone.
    expected: String,
    /// Wall-clock instant the clear is scheduled to fire. The corner
    /// chip subtracts `Instant::now()` from this each frame to draw the
    /// countdown text and the progress bar.
    deadline: Instant,
    /// Generation tag matched by the ack messages. Bumped on every
    /// fresh copy so a stale arm can't fire after a newer one.
    generation: u64,
}

impl WalletScreen {
    /// Build a fresh dashboard.
    ///
    /// `initial_nav` selects the tab the dashboard lands on. `None`
    /// defaults to Home (first-unlock and add-account flows);
    /// `Some(_)` is passed by `App::switch_account` so switching
    /// accounts while reading the Activity feed doesn't yank the user
    /// back to Home.
    // The constructor was already at clippy's 7-arg threshold before
    // safes were added; bundling into a config struct would be a wider
    // refactor of every WalletScreen::new caller for no real
    // readability gain (the arg names are already self-documenting).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signer: KaoSigner,
        accounts: Vec<AccountDescriptor>,
        safes: Vec<SafeDescriptor>,
        active_index: usize,
        network: Arc<dyn BalanceFetcher>,
        portfolio_cache: PortfolioCache,
        contacts: Arc<RwLock<ContactsBook>>,
        initial_nav: Option<Nav>,
    ) -> Self {
        let address = signer.address();
        // Seed from the cache when this address has been viewed before:
        // the user sees their tokens immediately on switch and the
        // background fetch (still kicked off by the App) refreshes
        // values silently when it lands.
        // Pull every chain's cached rows so an account switch renders
        // the full multi-chain portfolio immediately; the per-chain
        // background fetches refresh values silently as they land.
        let cached: Option<Vec<LiveToken>> = portfolio_cache.lock().ok().map(|c| {
            crate::chain::Chain::ALL
                .iter()
                .filter_map(|chain| c.get(&(address, (*chain).into())).cloned())
                .flatten()
                .collect()
        });
        let cached = cached.filter(|v: &Vec<LiveToken>| !v.is_empty());
        let (portfolio, portfolio_loading) = match cached {
            Some(p) => (p, false),
            None => (Vec::new(), true),
        };
        Self {
            signer,
            address,
            accounts,
            safes,
            active_index,
            theme_kind: settings::theme(),
            nav: initial_nav.unwrap_or(Nav::Home),
            modal: Modal::None,
            chrome: ModalChrome::new(),
            network,
            verification: VerificationStatus::Connecting,
            settings_pane: SettingsPane::Root,
            portfolio,
            portfolio_loading,
            portfolio_refreshing: false,
            portfolio_cache,
            active_safe: None,
            safe_pending: Vec::new(),
            safe_pending_loading: false,
            safe_pending_error: None,
            rename_draft: None,
            history: Vec::new(),
            history_loading: false,
            history_loaded: false,
            history_errors: PerChain::default(),
            history_pending: Vec::new(),
            contacts,
            clipboard_clear: None,
            clipboard_clear_gen: 0,
            tracked_orders: Vec::new(),
            order_op_in_flight: false,
            apps: AppsPane::new(address),
            sign_review: None,
            sign_review_seq: 0,
            pp_account: None,
            pool_session_deposits: std::collections::HashMap::new(),
            pending_pool_deposit: None,
            pool_deposit_in_flight: None,
            pool_scopes: std::collections::HashMap::new(),
            pool_note_cache: std::collections::HashMap::new(),
            pool_notes_key: None,
        }
    }

    /// Push the Privacy Pools account (or `None`) down from the App after it
    /// loads/creates/restores the pool seed. Also flips the pool pane between its
    /// Setup and Overview states.
    pub fn set_pp_account(&mut self, account: Option<privacy_pools::Account>) {
        self.pp_account = account;
        // A different identity has its own per-scope index space — drop any
        // session deposit counters so they never cross identities.
        self.pool_session_deposits.clear();
        self.pending_pool_deposit = None;
        self.pool_deposit_in_flight = None;
        // Scopes are identity-independent (pool metadata), but re-populated on
        // the next discovery — clearing keeps the map from unbounded growth.
        self.pool_scopes.clear();

        // Refresh the note-cache key + in-memory cache for this identity. If a
        // *different* identity is now active (a real switch, not the first load
        // of the session), wipe both the persisted rows and memory — the old
        // account's notes are permanently stale.
        let new_key = account.and_then(|a| crate::pool::sync::notes_cipher_key(&a).ok());
        if let (Some(old), Some(new)) = (self.pool_notes_key, new_key)
            && old != new
        {
            if let Err(e) = crate::wallet::clear_pp_notes() {
                warn!(error = %e, "privacy pools: clearing stale note cache failed");
            }
            self.pool_note_cache.clear();
        }
        self.pool_notes_key = new_key;
        if let Some(key) = new_key {
            match crate::wallet::load_all_pp_notes(&key) {
                Ok(cache) => self.pool_note_cache = cache,
                Err(e) => warn!(error = %e, "privacy pools: loading note cache failed"),
            }
        } else {
            self.pool_note_cache.clear();
        }

        self.apps.pool_pane().set_identity(account.is_some());
    }

    /// Show the pool recovery phrase in the pool app's masked backup view (the
    /// App owns the seed and hands the phrase in only for display).
    pub fn show_pool_backup(&mut self, phrase: secrecy::SecretString) {
        self.apps.pool_pane().show_backup(phrase);
    }

    /// Surface an App-side error (e.g. seed save failed) on the pool pane.
    pub fn set_pool_error(&mut self, e: String) {
        warn!(error = %e, "privacy pools: identity/seed error");
        self.apps.pool_pane().set_error(Some(e));
    }

    /// Move the live signer out of the dashboard. Used by the App when it
    /// transitions away from the dashboard (e.g. into the add-account flow)
    /// and wants to park the signer to return cheaply later.
    pub fn into_signer(self) -> KaoSigner {
        self.signer
    }

    /// Address the dashboard currently *displays* — the active Safe's
    /// address in Safe mode, otherwise the EOA. All portfolio /
    /// balance / activity / verification fetches key off this. The
    /// EOA signer (`self.signer` / `self.address`) stays in place for
    /// transaction signing; only the user-visible identity moves.
    fn display_address(&self) -> Address {
        match self.active_safe {
            Some(idx) => self
                .safes
                .get(idx)
                .map(|s| s.address())
                .unwrap_or(self.address),
            None => self.address,
        }
    }

    /// The active Safe descriptor when in Safe mode. `None` in EOA
    /// mode or if `active_safe` points at a stale index (defensive —
    /// shouldn't happen but cheaper than panicking).
    fn active_safe_descriptor(&self) -> Option<&SafeDescriptor> {
        self.active_safe.and_then(|i| self.safes.get(i))
    }

    /// Display name for the active identity — the Safe's name with its
    /// threshold badge in Safe mode, otherwise the active account's name
    /// (falling back to a positional default). Shown both in the sidebar
    /// account card and as the header title.
    fn display_name(&self) -> String {
        match self.active_safe_descriptor() {
            Some(safe) => {
                let idx = self.active_safe.unwrap_or(0);
                let base = safe.display_name(idx);
                let total_owners = safe.owners.len().max(safe.linked_signer_indices.len());
                format!("{base} — Safe {} of {}", safe.threshold, total_owners)
            }
            None => self
                .accounts
                .get(self.active_index)
                .map(|a| a.display_name(self.active_index))
                .unwrap_or_else(|| format!("Account {}", self.active_index + 1)),
        }
    }

    /// Short network label for the sidebar footer — the Safe's chain in
    /// Safe mode, otherwise "Ethereum" (the EOA's primary network; the
    /// portfolio itself may span several chains).
    fn network_short_name(&self) -> &'static str {
        match self.active_safe_descriptor() {
            Some(safe) => crate::chain::Chain::ALL
                .iter()
                .find(|c| c.chain_id() == safe.chain_id)
                .map(|c| c.label())
                .unwrap_or("Unknown chain"),
            None => "Ethereum",
        }
    }

    /// Chains whose balances/history are valid for the current
    /// display identity.
    ///
    /// In EOA mode: every chain Kao supports. The same hex EOA
    /// address is a self-custodial wallet across chains, so its
    /// per-chain balances are independently meaningful.
    ///
    /// In Safe mode: just the Safe's own chain. A Safe is a contract
    /// pinned to a specific deployment; the same address on another
    /// chain is either an unrelated contract or empty space, and
    /// rendering its balance there would mislead the user.
    fn allowed_chains(&self) -> Vec<crate::chain::Chain> {
        match self.active_safe_descriptor() {
            Some(safe) => crate::chain::Chain::ALL
                .iter()
                .copied()
                .filter(|c| c.chain_id() == safe.chain_id)
                .collect(),
            None => crate::chain::Chain::ALL.to_vec(),
        }
    }

    /// Networks whose balances are valid for the current display identity,
    /// spanning both built-in chains and user-defined custom networks.
    ///
    /// In EOA mode: every built-in chain plus every *enabled* custom network
    /// — a self-custodial EOA holds an independent balance on each. In Safe
    /// mode: just the Safe's own built-in chain. A Safe is a contract pinned
    /// to one deployment, and custom networks have no Safe support, so a Safe
    /// never spans custom networks.
    fn allowed_networks(&self) -> Vec<crate::chain::NetworkId> {
        use crate::chain::NetworkId;
        let mut out: Vec<NetworkId> = self
            .allowed_chains()
            .into_iter()
            .map(NetworkId::from)
            .collect();
        if self.active_safe_descriptor().is_none() {
            out.extend(
                settings::enabled_custom_networks()
                    .into_iter()
                    .map(|n| NetworkId::Custom(n.chain_id)),
            );
        }
        out
    }

    /// Reset `history_pending` to the set of chains the dashboard
    /// will actually fetch — `allowed_chains()` intersected with
    /// "has at least one configured RPC". Single source of truth
    /// for the three callsites that kick a history refresh.
    fn reset_history_pending(&mut self) {
        self.history_pending = self
            .allowed_chains()
            .into_iter()
            .filter(|c| !settings::rpcs(*c).is_empty())
            .collect();
    }

    /// Seed `self.portfolio` from the cache for the currently
    /// displayed address. Used on Safe-mode entry so the user sees
    /// previously-fetched token rows immediately while the live
    /// fetch refreshes them. Leaves the existing portfolio alone if
    /// the cache misses entirely on this address.
    fn seed_portfolio_from_cache(&mut self) {
        let addr = self.display_address();
        let allowed = self.allowed_networks();
        let cached: Vec<LiveToken> = match self.portfolio_cache.lock() {
            Ok(c) => allowed
                .iter()
                .filter_map(|network| c.get(&(addr, *network)).cloned())
                .flatten()
                .collect(),
            Err(_) => Vec::new(),
        };
        self.portfolio = cached;
    }

    /// Write `text` to the system clipboard and arm the deferred clear.
    /// Bumps the generation counter so any older arm fires stale and
    /// no-ops. The returned task batches the write itself with a
    /// `tokio::time::sleep` that emits `ClipboardClearArmed` once the
    /// deadline passes — the ownership check happens at that point, not
    /// here.
    fn arm_clipboard_clear(&mut self, text: String) -> Task<Message> {
        // Fire the "Copied!" toast for button-driven copies too (Copy hash,
        // explorer link, Send/Swap/TxDetails). `colored_address` clicks call
        // `mark_copied` themselves; this is the matching signal for every copy
        // that routes through here. NOT in the `ClipboardWritten` handler —
        // that also fires for the 10s auto-clear write, which must stay silent.
        mark_copied();
        self.clipboard_clear_gen = self.clipboard_clear_gen.wrapping_add(1);
        let generation = self.clipboard_clear_gen;
        self.clipboard_clear = Some(ClipboardClearState {
            expected: text.clone(),
            deadline: Instant::now() + Duration::from_secs(CLIPBOARD_CLEAR_SECS),
            generation,
        });
        let timer = Task::perform(
            async move {
                tokio::time::sleep(Duration::from_secs(CLIPBOARD_CLEAR_SECS)).await;
                generation
            },
            |generation| Message::ClipboardClearArmed { generation },
        );
        Task::batch([
            iced::clipboard::write(text).map(|_: ()| Message::ClipboardWritten),
            timer,
        ])
    }

    /// True while a send is in flight (the signer has been moved into a
    /// broadcast task and not yet reclaimed). Used by the App to refuse
    /// disruptive transitions like begin-add-account during a send — those
    /// would race with the in-flight broadcast on the signer cell.
    pub fn is_send_busy(&self) -> bool {
        match &self.modal {
            Modal::Send(p) => p.busy(),
            Modal::SafeTxDetail(p) => p.busy(),
            _ => false,
        }
    }

    /// True while *any* signing operation has the live signer parked — a Send /
    /// Safe broadcast ([`Self::is_send_busy`]) or a CoW / name-service write
    /// (`order_op_in_flight`). The App gates leaving the dashboard
    /// (begin-add-account) on this: `into_signer()` would otherwise hand back the
    /// `ViewOnly` placeholder and strand the real signer in the in-flight task's
    /// handoff. Name writes also refuse to start while this is true.
    pub fn is_signing_busy(&self) -> bool {
        self.is_send_busy() || self.order_op_in_flight
    }

    /// The active address in short `0xabcd…ef01` form. For diagnostic logs.
    pub fn address_for_log(&self) -> String {
        short_address(self.address)
    }

    /// Currently-selected sidebar tab. The App threads this through
    /// `enter_dashboard` on account switch so the user stays on the tab
    /// they were reading instead of being yanked back to Home.
    pub fn current_nav(&self) -> Nav {
        self.nav
    }

    /// Whether to show the Send button at all — it's **hidden**, not just
    /// disabled, when this is false. In EOA mode: true only when the active
    /// signer can sign right now, so a view-only account or a hardware account
    /// whose device is disconnected hides Send (reconnect the device via the
    /// sidebar's hardware card to bring it back). In Safe mode: true when the
    /// Safe is trusted and at least one linked owner is signable (`Local` **or**
    /// hardware) — the owner signer is built on demand at execute time, so the
    /// active EOA's connection is irrelevant.
    fn can_send(&self) -> bool {
        if let Some(safe) = self.active_safe_descriptor() {
            return safe.trust.permits_signing() && self.has_signable_linked_owner(safe);
        }
        self.signer.can_sign()
    }

    /// Whether the Swap quick action / modal should be live. In EOA mode:
    /// needs a signer that can actually sign (orders are EIP-712-signed;
    /// ERC-20 sells and the EthFlow path also broadcast on-chain). In Safe
    /// mode: true when we can build a valid Safe-swap context — a recognized
    /// Safe on a CoW-supported chain with ≥`threshold` signable owners — in
    /// which case orders are placed via EIP-1271 (see [`Self::build_safe_swap_ctx`]).
    /// CoW only runs on Mainnet/Base; for an EOA the composer surfaces that by
    /// listing only swappable balances, while a Safe is pinned to one chain so
    /// the gate checks it directly.
    fn can_swap(&self) -> bool {
        if self.active_safe.is_some() {
            return self.build_safe_swap_ctx().is_some();
        }
        self.signer.can_sign()
    }

    /// The address that owns / receives CoW orders for the active identity —
    /// the Safe in Safe mode, otherwise the active EOA. Used as the quote
    /// `from`, the order `receiver`, and the scope for the order list / "Fetch".
    fn order_owner(&self) -> Address {
        self.active_safe_descriptor()
            .map(|s| s.address())
            .unwrap_or(self.address)
    }

    /// Tracked CoW orders owned by the active identity ([`Self::order_owner`]),
    /// newest-first (by `valid_to`, UID as tiebreak). Drives the Apps order
    /// list: scoping by the owner keeps a Safe's orders from leaking into the
    /// EOA's view and — crucially — makes a Safe order placed via EIP-1271
    /// (owner = the Safe, not the active EOA) actually appear in Safe mode.
    fn active_cow_orders(&self) -> Vec<&TrackedOrder> {
        let owner = self.order_owner();
        let mut orders: Vec<&TrackedOrder> = self
            .tracked_orders
            .iter()
            .filter(|o| o.owner == owner)
            .collect();
        orders.sort_by(|a, b| b.valid_to.cmp(&a.valid_to).then_with(|| b.uid.cmp(&a.uid)));
        orders
    }

    /// Assemble the context needed to place a CoW order from the active Safe,
    /// or `None` when Safe swaps aren't possible: not in Safe mode, an
    /// unrecognized implementation (signing disabled), a chain CoW doesn't
    /// serve, or fewer signable owners than the threshold. The signer owners
    /// are descriptors (built into live signers inside the place task, like the
    /// Safe send flow); the executor preference is any Local key for gas, else
    /// the first signing owner pays its own.
    fn build_safe_swap_ctx(&self) -> Option<SafeSwapCtx> {
        let safe = self.active_safe_descriptor()?;
        if !safe.trust.permits_signing() {
            return None;
        }
        let chain = crate::chain::Chain::ALL
            .into_iter()
            .find(|c| c.chain_id() == safe.chain_id)?;
        if !crate::cow::supported(chain) {
            return None;
        }
        let signer_owners: Vec<AccountDescriptor> = signable_owners_of(safe, &self.accounts)
            .into_iter()
            .map(|(_, desc)| desc)
            .take(safe.threshold as usize)
            .collect();
        if (signer_owners.len() as u32) < safe.threshold {
            return None;
        }
        Some(SafeSwapCtx {
            safe: safe.address(),
            chain,
            version: safe.version.clone(),
            trust: safe.trust.clone(),
            signer_owners,
            local_executor_key: first_local_key_of(&self.accounts),
        })
    }

    /// Context for routing a name write through the active Safe, or `None` when
    /// names-from-Safe isn't possible: not in Safe mode, an unrecognized
    /// implementation, fewer signable owners than the threshold, or — because
    /// the name registries are Mainnet-pinned — a Safe that isn't a **Mainnet**
    /// deployment. The name is owned by the Safe, so the Safe's address is the
    /// registrant and the inner `execTransaction` `msg.sender`.
    fn build_safe_name_ctx(&self) -> Option<SafeNameCtx> {
        let safe = self.active_safe_descriptor()?;
        if !safe.trust.permits_signing() {
            return None;
        }
        if safe.chain_id != crate::chain::Chain::Mainnet.chain_id() {
            return None;
        }
        let owners: Vec<AccountDescriptor> = signable_owners_of(safe, &self.accounts)
            .into_iter()
            .map(|(_, desc)| desc)
            .take(safe.threshold as usize)
            .collect();
        if (owners.len() as u32) < safe.threshold {
            return None;
        }
        Some(SafeNameCtx {
            safe: safe.address(),
            owners,
            executor_key: first_local_key_of(&self.accounts),
        })
    }

    /// Build the signer context for an EOA sign: the active account, or `Err` if
    /// it's watch-only (which [`SignerContext`] makes unrepresentable, so no review
    /// is ever built for a signer that can't sign).
    fn build_eoa_context(&self) -> Result<SignerContext, String> {
        let desc = self.active_signer_descriptor();
        if matches!(desc, AccountDescriptor::ViewOnly { .. }) {
            return Err("this account is watch-only and can't sign".to_string());
        }
        // The active EOA's address — exactly what `order_owner()` returned for the
        // EOA case, so the decoded `from` is unchanged.
        Ok(SignerContext::Eoa {
            address: self.address,
        })
    }

    /// The single decision of who authorizes a review: the active Safe (per the
    /// flow's `need`) in Safe mode, else the active EOA. `Err` when there is no
    /// signable context — a watch-only EOA, or a Safe that can't sign here (wrong
    /// chain / unrecognized impl / too few signable owners). Being the one source
    /// of the address shown as `from`, it can't diverge from who actually signs.
    fn build_signer_context(&self, need: SafeNeed) -> Result<SignerContext, String> {
        if self.active_safe.is_some() {
            let safe = match need {
                SafeNeed::Swap => self.build_safe_swap_ctx().map(|c| c.safe),
                SafeNeed::Name => self.build_safe_name_ctx().map(|c| c.safe),
            };
            safe.map(|safe| SignerContext::Safe { safe })
                .ok_or_else(|| "this Safe can't sign here".to_string())
        } else {
            self.build_eoa_context()
        }
    }

    /// Whether the Apps launcher should offer the Names app for the active
    /// identity. EOA: always (reads work; writes gate at sign time, matching
    /// the pre-Safe behavior). Safe: only a Mainnet Safe with a signable owner,
    /// since names register/resolve against the Safe via `execTransaction`.
    fn names_available_for_active(&self) -> bool {
        match self.active_safe {
            Some(_) => self.build_safe_name_ctx().is_some(),
            None => true,
        }
    }

    /// Spawn the right order-placement task for the active identity, parking
    /// the active signer for the async path (Safe swaps don't use it, but
    /// parking keeps `order_op_in_flight` / the Apps reprieve consistent and
    /// the same `CowPlaced` handler restores it). Surfaces a clear error on the
    /// host pane if a Safe swap is somehow no longer placeable.
    fn place_order_task(
        &mut self,
        host: CowHost,
        draft: SwapDraft,
        quote: crate::cow::api::QuoteResponse,
    ) -> Task<Message> {
        if self.active_safe.is_some() {
            let Some(ctx) = self.build_safe_swap_ctx() else {
                let msg = "This Safe can't place swaps — it needs a recognized \
                           implementation, a signable owner, and a CoW-supported chain."
                    .to_string();
                match host {
                    CowHost::Modal => {
                        if let Modal::Swap(p) = &mut self.modal {
                            p.placement_failed(msg);
                        }
                    }
                    CowHost::Apps => self.apps.placement_failed(msg),
                }
                return Task::none();
            };
            let handoff = self.park_signer_for_order();
            spawn_cow_place_safe(self.network.clone(), host, handoff, draft, quote, ctx)
        } else {
            let desc = self.active_signer_descriptor();
            let handoff = self.park_signer_for_order();
            spawn_cow_place(
                self.network.clone(),
                host,
                handoff,
                desc,
                draft,
                quote,
                self.address,
            )
        }
    }

    /// Spawn the right off-chain cancel task for `uid`. A Safe-owned order
    /// cancels via EIP-1271 (the active Safe's owners sign the cancellation
    /// digest); an EOA order cancels with the parked EOA signer. Either path
    /// resolves through the same `CowCancel` handler. No-op if the order isn't
    /// tracked, or (for a Safe order) if a valid signing context can't be built.
    fn cancel_order_task(&mut self, host: CowHost, uid: String) -> Task<Message> {
        let Some((chain, owner)) = self
            .tracked_orders
            .iter()
            .find(|o| o.uid == uid)
            .map(|o| (o.chain, o.owner))
        else {
            return Task::none();
        };
        if self
            .active_safe_descriptor()
            .is_some_and(|s| s.address() == owner)
        {
            let Some(ctx) = self.build_safe_swap_ctx() else {
                warn!(%uid, "cow: cannot cancel Safe order — no valid signing context");
                return Task::none();
            };
            let handoff = self.park_signer_for_order();
            spawn_cow_cancel_safe(self.network.clone(), handoff, host, chain, uid, ctx)
        } else {
            let desc = self.active_signer_descriptor();
            let handoff = self.park_signer_for_order();
            spawn_cow_cancel(handoff, desc, host, chain, uid)
        }
    }

    /// Whether the Apps (Swap) surface should be available for the active
    /// identity. Same as [`Self::can_swap`], but stays true while an order is
    /// being placed or cancelled: the signer is parked as a view-only
    /// placeholder for the async sign path, which would otherwise flip
    /// `can_swap()` false and transiently yank the sidebar Apps tab (and
    /// redirect `Nav::Apps` to the portfolio) mid-order. Drives the sidebar
    /// gate and the nav fallback only — starting a *new* swap still keys off
    /// the live `can_swap()`.
    fn apps_available(&self) -> bool {
        self.can_swap() || self.order_op_in_flight
    }

    /// Hardware-device status for the active account, used to render the
    /// sidebar's connection card. `None` for software / view-only accounts.
    /// "Connected" means we hold a live signer: either it can sign, or it's
    /// momentarily parked as a placeholder for an in-flight order
    /// (`order_op_in_flight`) — the same reasoning that keeps the Apps
    /// surface up mid-order applies here, so the card doesn't flicker to
    /// "disconnected" while a swap is being signed.
    fn hardware_status(&self) -> Option<HardwareStatus> {
        let connected = self.signer.can_sign() || self.order_op_in_flight;
        match self.accounts.get(self.active_index) {
            Some(AccountDescriptor::Ledger { .. }) => Some(HardwareStatus::Ledger { connected }),
            Some(AccountDescriptor::Trezor { .. }) => Some(HardwareStatus::Trezor { connected }),
            _ => None,
        }
    }

    /// The active account's descriptor — the reconnect source for EOA hardware
    /// signing (`ensure_connected` rebuilds a dropped Ledger/Trezor from its HD
    /// path). Falls back to a view-only descriptor (which makes `ensure_connected`
    /// a no-op) if the index is ever out of range.
    fn active_signer_descriptor(&self) -> AccountDescriptor {
        self.accounts
            .get(self.active_index)
            .cloned()
            .unwrap_or(AccountDescriptor::ViewOnly {
                name: None,
                address: self.address.into_array(),
            })
    }

    /// Park the live EOA signer for an in-flight CoW order op (place/cancel),
    /// returning the handoff cell the async task signs with — the swap analogue
    /// of the Send broadcast handoff. Flags `order_op_in_flight` so the Apps
    /// surface stays available (see [`Self::apps_available`]) while the signer
    /// is momentarily a view-only placeholder; the flag is cleared when the
    /// signer is reclaimed in `CowPlaced` / `CowCancel`.
    fn park_signer_for_order(&mut self) -> SignerHandoff {
        self.order_op_in_flight = true;
        let signer = mem::replace(&mut self.signer, KaoSigner::ViewOnly(self.address));
        handoff_with(signer)
    }

    /// Reclaim the EOA signer parked for a name-service write op and clear the
    /// in-flight flag — the shared tail of every `Name*` result handler.
    ///
    /// Only a *real* signer for the *current* account is restored. Refusing a
    /// `ViewOnly` placeholder stops a stray/late reclaim from downgrading a live
    /// signer to view-only (which would silently disable signing across the whole
    /// wallet); refusing a signer whose address ≠ the active account stops an op
    /// spawned before an account switch from contaminating the new account with
    /// the old account's key. In both cases the reclaimed value is simply
    /// dropped.
    fn reclaim_order_signer(&mut self, signer: SignerHandoff) {
        self.install_reclaimed_signer(&signer);
        self.order_op_in_flight = false;
    }

    /// Safely restore a signer parked for an in-flight signing op: install it
    /// only if it's a *real* signer for the *current* account. This is the
    /// invariant that keeps the shared signer-park machinery (Send / CoW /
    /// name-service writes) safe under overlap — a `ViewOnly` placeholder (from a
    /// concurrent double-park) or a different account's key (from a mid-op
    /// account switch) is dropped rather than overwriting the live signer, so no
    /// overlap can silently strand the wallet as view-only.
    fn install_reclaimed_signer(&mut self, signer: &SignerHandoff) {
        if let Ok(mut g) = signer.lock()
            && let Some(s) = g.take()
            && s.can_sign()
            && s.address() == self.address
        {
            self.signer = s;
        }
    }

    /// Service a request bubbled up from the Names app: read-only ones spawn a
    /// verified-read task; write ones park the signer first (so the Apps surface
    /// survives the in-flight window) and mint the commit secret here, where the
    /// RNG lives.
    /// Service a Privacy Pools app request. Identity ops (create/restore/backup)
    /// need the App's passphrase, so they bubble up as an [`Outcome`]; everything
    /// else is serviced here with the network client + pool account.
    fn handle_pool_outcome(&mut self, o: pool_app::Outcome) -> (Task<Message>, Option<Outcome>) {
        use pool_app::Outcome as O;
        match o {
            O::CreateIdentity => (Task::none(), Some(Outcome::PoolCreateIdentity)),
            O::RestoreIdentity(phrase) => {
                (Task::none(), Some(Outcome::PoolRestoreIdentity(phrase)))
            }
            O::RevealBackup => (Task::none(), Some(Outcome::PoolRevealBackup)),
            O::CopyText(s) => (self.arm_clipboard_clear(s), None),
            O::Sync(chain) => {
                let base_url = self.apps.pool_pane().asp_endpoint();
                self.apps.pool_pane().set_syncing(true);
                self.apps.pool_pane().set_error(None);
                (
                    spawn_pool_discover(self.network.clone(), base_url, chain),
                    None,
                )
            }
            O::Quote(req) => (spawn_pool_quote(self.network.clone(), req), None),
            O::Deposit { info, amount } => (self.open_pool_deposit_review(info, amount), None),
            O::Submit { req, quote } => (self.pool_submit(req, quote), None),
            O::Ragequit { info, account } => (self.pool_ragequit(info, account), None),
            // Handled inside the Apps pane (steps back to the launcher); never
            // reaches the dashboard, but the match must stay exhaustive.
            O::Close => (Task::none(), None),
        }
    }

    /// Build a deposit transaction and route it through the clear-sign gate.
    /// Native deposits are one leg; ERC-20 deposits prepend an `approve`. The
    /// calldata is final (deposits need no proof), so the reviewed bytes are
    /// exactly what gets signed.
    fn open_pool_deposit_review(
        &mut self,
        info: crate::pool::PoolInfo,
        amount: U256,
    ) -> Task<Message> {
        if self.sign_review.is_some() {
            return Task::none();
        }
        // Privacy Pools has no Safe path: the deposit is signed and paid by the
        // active EOA, not the Safe. Offering it in Safe mode would show the Safe
        // as `from` (via `order_owner`) while silently spending the EOA — refuse
        // instead of misleading the user or funding from the wrong account.
        if self.active_safe.is_some() {
            warn!("privacy pools: deposit blocked — Safe mode has no pool signing path");
            self.apps.pool_pane().set_error(Some(
                "Privacy Pools deposits are signed by your account, not a Safe — \
                 switch to an account to deposit."
                    .into(),
            ));
            return Task::none();
        }
        let Some(account) = self.pp_account else {
            warn!("privacy pools: deposit blocked — no pool identity");
            self.apps
                .pool_pane()
                .set_error(Some("create a pool identity first".into()));
            return Task::none();
        };
        if amount < info.min_deposit {
            warn!(
                symbol = %info.symbol,
                "privacy pools: deposit below the pool minimum"
            );
            self.apps
                .pool_pane()
                .set_error(Some("amount is below this pool's minimum deposit".into()));
            return Task::none();
        }
        // The deposit index must be strictly beyond every index already on-chain
        // for this (account, scope) — reusing one reverts with
        // `PrecommitmentAlreadyUsed`. Take the max of the synced history and any
        // deposit already confirmed this session (the log scan can lag a
        // just-sent deposit). If neither is known we don't have the history yet:
        // block and kick a sync rather than guess index 0 over an existing note.
        let synced = self.apps.pool_pane().next_deposit_index(info.pool);
        let session = self.pool_session_deposits.get(&info.pool).copied();
        let index = match (synced, session) {
            (None, None) => {
                warn!(
                    symbol = %info.symbol,
                    "privacy pools: deposit blocked — pool history not synced yet"
                );
                self.apps.pool_pane().set_error(Some(
                    "still syncing this pool's history — try again in a moment".into(),
                ));
                let cached = self
                    .pool_note_cache
                    .get(&(info.chain.chain_id(), info.pool))
                    .cloned();
                return spawn_pool_account_sync(self.network.clone(), account, info, cached);
            }
            (s, se) => s.unwrap_or(0).max(se.unwrap_or(0)),
        };
        let dep = if info.is_native {
            crate::pool::flow::native_deposit(&account, &info, index, amount)
        } else {
            crate::pool::flow::erc20_deposit(&account, &info, index, amount)
        };
        let dep = match dep {
            Ok(d) => d,
            Err(e) => {
                error!(symbol = %info.symbol, error = %e, "privacy pools: building deposit failed");
                self.apps.pool_pane().set_error(Some(e.to_string()));
                return Task::none();
            }
        };
        let approve = (!info.is_native).then(|| {
            (
                info.asset,
                crate::pool::flow::erc20_approve_calldata(&info, amount),
            )
        });
        let sign = sign_review::PoolSign::Deposit {
            chain: info.chain,
            symbol: info.symbol.clone(),
            to: dep.to,
            value: dep.value,
            calldata: dep.calldata,
            approve,
        };
        // Remember which index this review is for; committed on confirm (see
        // `dispatch_pool_sign`) so a later deposit advances past it.
        self.pending_pool_deposit = Some((info.pool, index));
        self.open_pool_review(sign)
    }

    /// Open the clear-sign overlay for a pool EOA tx and spawn the decode.
    fn open_pool_review(&mut self, sign: sign_review::PoolSign) -> Task<Message> {
        if self.sign_review.is_some() {
            return Task::none();
        }
        // A pool tx is always signed by the active EOA — its context is the single
        // source of the decoded `from`, so the panel can't show a different address
        // than the one that signs. Deposits/ragequits are refused in Safe mode
        // upstream, and watch-only is unrepresentable, so a non-signing account
        // can't open a pool review.
        let from = match self.build_eoa_context() {
            Ok(ctx) => ctx.display_from(),
            Err(msg) => {
                self.apps.pool_pane().set_error(Some(msg));
                return Task::none();
            }
        };
        self.sign_review_seq += 1;
        let seq = self.sign_review_seq;
        let (title, subtitle, note) = pool_review_labels(&sign);
        let action = sign_review::SignAction::PrivacyPool { sign: sign.clone() };
        self.sign_review = Some(sign_review::SignReview::pending(
            title,
            subtitle,
            Vec::new(),
            note,
            seq,
            action,
        ));
        let local_names = build_local_names(&self.accounts, &self.safes, &self.contacts);
        spawn_pool_prepare(self.network.clone(), seq, from, sign, local_names)
    }

    /// User confirmed a pool EOA tx — park the signer and broadcast.
    fn dispatch_pool_sign(&mut self, sign: sign_review::PoolSign) -> Task<Message> {
        if self.is_signing_busy() {
            warn!("privacy pools: sign dispatch blocked — another signing op in progress");
            // We won't run this signature, so close the overlay (rather than
            // leaving it stuck waiting) and surface the refusal on the pane.
            self.sign_review = None;
            self.apps.pool_pane().set_error(Some(
                "another signing operation is in progress — try again in a moment".into(),
            ));
            return Task::none();
        }
        // The user confirmed — commit the reviewed deposit's index so a
        // subsequent deposit advances past it even before the re-scan lands.
        // (Ragequits carry no deposit index; a failed broadcast at worst leaves a
        // one-index gap, which note recovery tolerates.)
        if matches!(sign, sign_review::PoolSign::Deposit { .. })
            && let Some((pool, index)) = self.pending_pool_deposit.take()
        {
            let next = self.pool_session_deposits.entry(pool).or_insert(0);
            *next = (*next).max(index + 1);
            // Remember which pool this deposit is for; `PoolSubmitted` reads it
            // back to animate that exact card until the deposit confirms.
            self.pool_deposit_in_flight = Some(pool);
        }
        // Keep the review overlay up in its "waiting for a signature" phase for
        // the duration of the sign + broadcast; `PoolSubmitted` clears it once
        // the task resolves (success, rejected tx, or error).
        if let Some(review) = self.sign_review.as_mut() {
            review.signing_since = Some(Instant::now());
        }
        let desc = self.active_signer_descriptor();
        let handoff = self.park_signer_for_order();
        spawn_pool_send(self.network.clone(), handoff, desc, sign)
    }

    /// Prove + submit a withdrawal through the relayer: it POSTs the proof, the
    /// relayer submits on-chain and pays the gas — the user signs nothing.
    fn pool_submit(
        &mut self,
        req: pool_app::WithdrawRequest,
        quote: crate::pool::relayer::QuoteResponse,
    ) -> Task<Message> {
        let Some(account) = self.pp_account else {
            self.apps
                .pool_pane()
                .set_error(Some("create a pool identity first".into()));
            return Task::none();
        };
        let asp = self.apps.pool_pane().asp_url();
        let cached = self
            .pool_note_cache
            .get(&(req.info.chain.chain_id(), req.info.pool))
            .cloned();
        self.apps.pool_pane().set_proving("Private withdrawal");
        spawn_pool_relayed_withdraw(self.network.clone(), account, req, quote, asp, cached)
    }

    /// Ragequit a deposit — the original-depositor exit (no ASP needed): prove
    /// the commitment off-thread, then route the `Pool.ragequit` tx through the
    /// clear-sign gate as an EOA transaction.
    fn pool_ragequit(&mut self, info: crate::pool::PoolInfo, account: usize) -> Task<Message> {
        // Same as deposits: the ragequit tx is signed by the active EOA, so it
        // has no meaning in Safe mode — refuse rather than spend the EOA behind a
        // Safe-labelled review.
        if self.active_safe.is_some() {
            warn!("privacy pools: ragequit blocked — Safe mode has no pool signing path");
            self.apps.pool_pane().set_error(Some(
                "Privacy Pools exits are signed by your account, not a Safe — \
                 switch to an account to continue."
                    .into(),
            ));
            return Task::none();
        }
        let Some(pp) = self.pp_account else {
            self.apps
                .pool_pane()
                .set_error(Some("create a pool identity first".into()));
            return Task::none();
        };
        self.apps.pool_pane().set_proving("Ragequit exit");
        spawn_pool_ragequit_prove(self.network.clone(), pp, info, account)
    }

    fn handle_name_outcome(&mut self, o: names_app::Outcome) -> Task<Message> {
        // Serialize signing: refuse a new write-op while one is already in
        // flight, so a second park can't strand the real signer in the first
        // op's handoff. Reads (Scan/Status/Check) don't park the signer, so
        // they're exempt.
        let is_write = matches!(
            o,
            names_app::Outcome::Commit { .. }
                | names_app::Outcome::Register { .. }
                | names_app::Outcome::RegisterXns { .. }
                | names_app::Outcome::Renew { .. }
                | names_app::Outcome::SetRecipient { .. }
        );
        if is_write && self.is_signing_busy() {
            // Another signing op already holds the signer. Refuse — but the pane
            // has already flipped to a busy phase, so feed the error back so it
            // reverts (rather than stranding it, or letting a second park strand
            // the signer).
            let msg =
                "another signing operation is in progress — try again in a moment".to_string();
            let pane = self.apps.names_pane();
            match o {
                names_app::Outcome::Commit { .. } => pane.on_commit(Err(msg)),
                // Both the legacy reveal and the XNS one-shot resolve via `on_register`.
                names_app::Outcome::Register { .. } | names_app::Outcome::RegisterXns { .. } => {
                    pane.on_register(Err(msg))
                }
                names_app::Outcome::Renew { .. } => pane.on_renew(Err(msg)),
                names_app::Outcome::SetRecipient { .. } => pane.on_set_recipient(Err(msg)),
                _ => {}
            }
            return Task::none();
        }
        // A name write from a Safe routes through the Safe (the registries are
        // Mainnet-pinned and the name is owned by the Safe). If we're in Safe
        // mode but can't build that context — a non-Mainnet Safe, or no signable
        // owner — refuse rather than silently registering against the active EOA.
        let safe_name = self.build_safe_name_ctx();
        if is_write && self.active_safe.is_some() && safe_name.is_none() {
            let msg = "Names from this Safe aren't available — they need a Mainnet \
                       Safe with a signable owner. Switch to an EOA or a Mainnet Safe."
                .to_string();
            let pane = self.apps.names_pane();
            match o {
                names_app::Outcome::Commit { .. } => pane.on_commit(Err(msg)),
                names_app::Outcome::Register { .. } | names_app::Outcome::RegisterXns { .. } => {
                    pane.on_register(Err(msg))
                }
                names_app::Outcome::Renew { .. } => pane.on_renew(Err(msg)),
                names_app::Outcome::SetRecipient { .. } => pane.on_set_recipient(Err(msg)),
                _ => {}
            }
            return Task::none();
        }
        // Reads and the registrant are scoped to the active identity ([`order_owner`])
        // — the Safe in Safe mode, else the EOA. Async results are tagged with
        // this owner and dropped on arrival if the identity has since changed.
        let owner = self.order_owner();
        match o {
            names_app::Outcome::ReverseScan => spawn_name_reverse_scan(self.network.clone(), owner),
            names_app::Outcome::Status { registry, label } => {
                spawn_name_status(self.network.clone(), owner, registry, label)
            }
            names_app::Outcome::Search {
                seq,
                label,
                registries,
            } => spawn_name_search(self.network.clone(), owner, seq, label, registries),
            names_app::Outcome::Quote {
                namespace,
                label,
                years,
            } => spawn_name_quote(self.network.clone(), owner, namespace, label, years),
            // ── Write ops: prepare a clear-signing review instead of signing.
            // Each builds the exact bytes it will authorize, decodes them, and
            // opens the review overlay; the signer is parked (and the existing
            // spawn_* task run) only when the user confirms. `safe_name` was
            // validated above and is re-derived at confirm in `dispatch_name_sign`.
            names_app::Outcome::RegisterXns { namespace, label } => self.open_name_review(
                sign_review::NameSign::RegisterXns { namespace, label },
                owner,
            ),
            names_app::Outcome::Commit {
                namespace,
                label,
                years,
            } => {
                // Fresh commit/reveal nonce — never reused, kept in the plan. The
                // name is registered to `owner` (the active identity): GNS/WNS
                // reveal to `msg.sender` and ENS takes `owner` as a param, so for
                // a Safe both the commitment and the reveal's `msg.sender` are it.
                // Minted here (where the RNG lives) at review time so the reviewed
                // commitment is the one later revealed.
                let secret = B256::from(rand::random::<[u8; 32]>());
                let plan = RegisterPlan {
                    namespace,
                    label,
                    owner,
                    duration_secs: crate::names::registrar::ens_duration_secs(years),
                    secret,
                };
                self.open_name_review(sign_review::NameSign::Commit(plan), owner)
            }
            names_app::Outcome::Register { plan } => {
                self.open_name_review(sign_review::NameSign::Register(plan), owner)
            }
            names_app::Outcome::Renew {
                namespace,
                label,
                years,
            } => self.open_name_review(
                sign_review::NameSign::Renew {
                    namespace,
                    label,
                    years,
                },
                owner,
            ),
            names_app::Outcome::SetRecipient {
                namespace,
                label,
                recipient,
            } => self.open_name_review(
                sign_review::NameSign::SetRecipient {
                    namespace,
                    label,
                    recipient,
                },
                owner,
            ),
        }
    }

    // ── Clear-signing review gate ─────────────────────────────────────────────

    /// Open the review overlay for a prepared name write and spawn the task that
    /// builds + decodes its registrar call. The signer is *not* parked yet — that
    /// happens only when the user confirms (`dispatch_name_sign`).
    fn open_name_review(&mut self, sign: sign_review::NameSign, from: Address) -> Task<Message> {
        if self.sign_review.is_some() {
            return Task::none();
        }
        // The name write is authorized by the active identity's signer context (the
        // Safe in Safe mode, else the EOA). Verify the caller's `from` is exactly
        // that address and refuse a watch-only signer — the shown `from` can't
        // diverge from who signs. (A non-Mainnet / unsignable Safe is already
        // refused upstream in `handle_name_outcome`.)
        match self.build_signer_context(SafeNeed::Name) {
            Ok(ctx) if ctx.display_from() == from => {}
            Ok(ctx) => {
                warn!(
                    shown = %from,
                    signer = %ctx.display_from(),
                    "name review: shown from != signer — refusing",
                );
                return Task::none();
            }
            Err(msg) => {
                warn!(%msg, "name review: no signable context — refusing");
                return Task::none();
            }
        }
        self.sign_review_seq += 1;
        let seq = self.sign_review_seq;
        let (title, subtitle, note) = name_review_labels(&sign);
        let action = sign_review::SignAction::Name { sign: sign.clone() };
        self.sign_review = Some(sign_review::SignReview::pending(
            title,
            subtitle,
            Vec::new(),
            note,
            seq,
            action,
        ));
        let local_names = build_local_names(&self.accounts, &self.safes, &self.contacts);
        spawn_name_prepare(self.network.clone(), seq, from, sign, local_names)
    }

    /// Open the review overlay for a CoW order and spawn the task that decodes its
    /// on-chain legs (ERC-20 approval, or the native EthFlow `createOrder`). The
    /// EIP-712 order itself is shown as a dedicated panel (it's typed data, not
    /// calldata, so there's nothing for `function_panel` to decode).
    fn open_cow_review(
        &mut self,
        host: CowHost,
        draft: SwapDraft,
        quote: crate::cow::api::QuoteResponse,
    ) -> Task<Message> {
        if self.sign_review.is_some() {
            return Task::none();
        }
        self.sign_review_seq += 1;
        let seq = self.sign_review_seq;
        let user = match self.build_signer_context(SafeNeed::Swap) {
            Ok(ctx) => ctx.display_from(),
            Err(msg) => {
                // The swap surface is gated on a signable context, so this is
                // unreachable in practice — but refuse cleanly rather than open a
                // review that can't be signed.
                match host {
                    CowHost::Modal => {
                        if let Modal::Swap(p) = &mut self.modal {
                            p.placement_failed(msg);
                        }
                    }
                    CowHost::Apps => self.apps.placement_failed(msg),
                }
                return Task::none();
            }
        };
        let order = build_order_review(&draft, &quote, user);
        let title = format!(
            "Swap {} {} → {}",
            order.sell_amount, order.sell_symbol, order.buy_symbol
        );
        // The Safe signing mechanism is now shown *visually* by the SafeExec /
        // SafeMessage steps, so the note is just the gasless/gas disclosure.
        let note = Some(
            if draft.is_native {
                "Selling native ETH is an on-chain order — you'll also pay gas."
            } else {
                "ERC-20 orders are gasless — CoW solvers pay the settlement gas."
            }
            .to_string(),
        );
        // In Safe mode the prepare task emits SafeExec / SafeMessage steps that
        // render the real execTransaction + safeTxHash (and the EIP-1271 order), so
        // it needs the Safe's public context. `build_signer_context` above already
        // proved this is a signable Safe swap.
        let safe_prep = if self.active_safe.is_some() {
            self.active_safe_descriptor().and_then(|d| {
                let chain = crate::chain::Chain::ALL
                    .into_iter()
                    .find(|c| c.chain_id() == d.chain_id)?;
                Some(SafePrepCtx {
                    safe: d.address(),
                    chain,
                    version: d.version.clone(),
                    threshold: d.threshold as u8,
                    owner_count: d.owners.len() as u8,
                })
            })
        } else {
            None
        };
        // EOA: the order is the leading typed step. Safe: the SafeExec/SafeMessage
        // steps (built in prepare) carry the order, so there's no separate step.
        let initial_steps = if safe_prep.is_some() {
            Vec::new()
        } else {
            vec![sign_review::SignStep::Typed(order)]
        };
        let action = sign_review::SignAction::Cow {
            host,
            draft: draft.clone(),
            quote: quote.clone(),
        };
        self.sign_review = Some(sign_review::SignReview::pending(
            title,
            None,
            initial_steps,
            note,
            seq,
            action,
        ));
        let local_names = build_local_names(&self.accounts, &self.safes, &self.contacts);
        spawn_cow_prepare(
            self.network.clone(),
            seq,
            draft,
            quote,
            user,
            local_names,
            safe_prep,
        )
    }

    /// Open a confirm gate for an off-chain order cancellation. It's an EIP-712
    /// signature (no calldata, no value), so there are no legs to decode — just a
    /// "this is what you're cancelling" panel the user confirms.
    fn open_cow_cancel_review(&mut self, host: CowHost, uid: String) -> Task<Message> {
        if self.sign_review.is_some() {
            return Task::none();
        }
        let Some(o) = self.tracked_orders.iter().find(|o| o.uid == uid) else {
            return Task::none();
        };
        let (sell_s, _) = crate::portfolio::format_token_balance(o.sell_amount, o.sell_decimals);
        self.sign_review_seq += 1;
        let seq = self.sign_review_seq;
        let title = format!(
            "Cancel order — {} {} → {}",
            sell_s, o.sell_symbol, o.buy_symbol
        );
        let subtitle = Some(format!("Order {}", short_order_uid(&uid)));
        let note = Some(
            "Off-chain gasless cancellation — you sign an EIP-712 message; no transaction is sent."
                .to_string(),
        );
        let action = sign_review::SignAction::CowCancel { host, uid };
        let mut review =
            sign_review::SignReview::pending(title, subtitle, Vec::new(), note, seq, action);
        // Nothing to prepare/decode — enable Confirm immediately.
        review.legs_loading = false;
        self.sign_review = Some(review);
        Task::none()
    }

    /// User confirmed the review — run the (unchanged) signing task for the
    /// prepared action. Most actions close the overlay here and drive their own
    /// originating surface (Swap modal / Apps composer / Names pane) into a busy
    /// phase; Privacy Pools has no such surface, so its overlay is kept open in a
    /// "waiting for a signature" state (cleared by the `PoolSubmitted` handler).
    fn confirm_sign_review(&mut self) -> Task<Message> {
        // Ignore a stray re-confirm once a signature is already in flight.
        if self
            .sign_review
            .as_ref()
            .is_some_and(|r| r.signing_since.is_some())
        {
            return Task::none();
        }
        // Privacy Pools keeps its overlay open across the sign + broadcast.
        if let Some(review) = self.sign_review.as_ref()
            && let sign_review::SignAction::PrivacyPool { sign } = &review.action
        {
            let sign = sign.clone();
            return self.dispatch_pool_sign(sign);
        }
        let Some(review) = self.sign_review.take() else {
            return Task::none();
        };
        match review.action {
            sign_review::SignAction::Cow { host, draft, quote } => {
                // Drive the blocking Swap modal into its "placing" phase now that
                // signing actually starts; the Apps composer stays put and resets
                // itself when placement completes.
                if let CowHost::Modal = host
                    && let Modal::Swap(p) = &mut self.modal
                {
                    p.begin_placing();
                }
                self.place_order_task(host, draft, quote)
            }
            sign_review::SignAction::CowCancel { host, uid } => self.cancel_order_task(host, uid),
            sign_review::SignAction::Name { sign } => self.dispatch_name_sign(sign),
            // Normally handled above (overlay kept open); the take() fallback here
            // keeps the match exhaustive and still signs if the guard ever moves.
            sign_review::SignAction::PrivacyPool { sign } => self.dispatch_pool_sign(sign),
        }
    }

    /// User cancelled (Cancel button / Esc / backdrop). The panes were never
    /// flipped to a busy phase (that's deferred to confirm), so there's nothing to
    /// revert — just drop the pending review.
    fn cancel_sign_review(&mut self) {
        // Once a signature is in flight the overlay can't be dismissed — it can't
        // be aborted from here, so keep the "waiting for a signature" notice up
        // until the task resolves and clears it.
        if self
            .sign_review
            .as_ref()
            .is_some_and(|r| r.signing_since.is_some())
        {
            return;
        }
        self.sign_review = None;
    }

    /// A prepare task failed to build/decode the transaction — abandon the review
    /// and surface the error on the originating pane.
    fn fail_sign_review(&mut self, e: String) {
        let Some(review) = self.sign_review.take() else {
            return;
        };
        match review.action {
            sign_review::SignAction::Cow { host, .. } => match host {
                CowHost::Modal => {
                    if let Modal::Swap(p) = &mut self.modal {
                        p.placement_failed(e);
                    }
                }
                CowHost::Apps => self.apps.placement_failed(e),
            },
            // Cancellation has no prepare step, so this branch is unreachable in
            // practice; drop the review silently if it ever lands here.
            sign_review::SignAction::CowCancel { .. } => {}
            sign_review::SignAction::Name { sign } => self.fail_name_pane(&sign, e),
            sign_review::SignAction::PrivacyPool { .. } => {
                error!(error = %e, "privacy pools: clear-sign review failed");
                self.apps.pool_pane().set_error(Some(e));
            }
        }
    }

    /// Dispatch a confirmed name write to the existing (unchanged) sign+broadcast
    /// task. Re-validates the serialization + Safe-context guards at confirm time,
    /// since state may have shifted while the review was open.
    fn dispatch_name_sign(&mut self, sign: sign_review::NameSign) -> Task<Message> {
        if self.is_signing_busy() {
            self.fail_name_pane(
                &sign,
                "another signing operation is in progress — try again in a moment".to_string(),
            );
            return Task::none();
        }
        let safe_name = self.build_safe_name_ctx();
        if self.active_safe.is_some() && safe_name.is_none() {
            self.fail_name_pane(
                &sign,
                "Names from this Safe aren't available — they need a Mainnet Safe with a \
                 signable owner. Switch to an EOA or a Mainnet Safe."
                    .to_string(),
            );
            return Task::none();
        }
        // Flip the pane to its busy phase only now that we're really signing.
        self.begin_name_pane(&sign);
        // EOA hardware reconnect source (Safe paths rebuild owner signers
        // themselves, so they don't need it).
        let desc = self.active_signer_descriptor();
        let handoff = self.park_signer_for_order();
        let net = self.network.clone();
        match sign {
            sign_review::NameSign::Commit(plan) => match safe_name {
                Some(ctx) => spawn_name_commit_safe(net, handoff, ctx, plan),
                None => spawn_name_commit(net, handoff, desc, plan),
            },
            sign_review::NameSign::Register(plan) => match safe_name {
                Some(ctx) => spawn_name_register_safe(net, handoff, ctx, plan),
                None => spawn_name_register(net, handoff, desc, plan),
            },
            sign_review::NameSign::RegisterXns { namespace, label } => match safe_name {
                Some(ctx) => spawn_name_register_xns_safe(net, handoff, ctx, namespace, label),
                None => spawn_name_register_xns(net, handoff, desc, namespace, label),
            },
            sign_review::NameSign::Renew {
                namespace,
                label,
                years,
            } => match safe_name {
                Some(ctx) => spawn_name_renew_safe(net, handoff, ctx, namespace, label, years),
                None => spawn_name_renew(net, handoff, desc, namespace, label, years),
            },
            sign_review::NameSign::SetRecipient {
                namespace,
                label,
                recipient,
            } => match safe_name {
                Some(ctx) => {
                    spawn_name_set_recipient_safe(net, handoff, ctx, namespace, label, recipient)
                }
                None => spawn_name_set_recipient(net, handoff, desc, namespace, label, recipient),
            },
        }
    }

    /// Flip the Names pane into the busy phase matching `sign`, mirroring the
    /// phase the pane used to enter the instant its action button was pressed.
    fn begin_name_pane(&mut self, sign: &sign_review::NameSign) {
        let pane = self.apps.names_pane();
        match sign {
            sign_review::NameSign::Commit(_) => pane.begin_commit(),
            sign_review::NameSign::Register(_) | sign_review::NameSign::RegisterXns { .. } => {
                pane.begin_reveal()
            }
            sign_review::NameSign::Renew { .. } | sign_review::NameSign::SetRecipient { .. } => {
                pane.begin_manage()
            }
        }
    }

    /// Push an error onto the Names pane for the op `sign` would have run.
    fn fail_name_pane(&mut self, sign: &sign_review::NameSign, msg: String) {
        let pane = self.apps.names_pane();
        match sign {
            sign_review::NameSign::Commit(_) => pane.on_commit(Err(msg)),
            sign_review::NameSign::Register(_) | sign_review::NameSign::RegisterXns { .. } => {
                pane.on_register(Err(msg))
            }
            sign_review::NameSign::Renew { .. } => pane.on_renew(Err(msg)),
            sign_review::NameSign::SetRecipient { .. } => pane.on_set_recipient(Err(msg)),
        }
    }

    /// Whether `safe` has at least one linked owner this wallet can
    /// sign with — `Local` **or** hardware (Ledger / Trezor), excluding
    /// view-only. Determines whether Safe-mode Send is reachable: the
    /// solo sign-and-execute path drives the owner signer through
    /// `KaoSigner::sign_eip712` (hardware-capable) and can use the owner
    /// itself as gas-paying executor when the wallet holds no Local key.
    fn has_signable_linked_owner(&self, safe: &SafeDescriptor) -> bool {
        !signable_owners_of(safe, &self.accounts).is_empty()
    }

    /// `(address, descriptor)` for every linked owner this wallet can
    /// sign with — Local or hardware, excluding view-only. The Safe-tx
    /// detail modal uses these to drive Confirm/Reject.
    fn safe_signable_owners(&self, safe: &SafeDescriptor) -> Vec<(Address, AccountDescriptor)> {
        signable_owners_of(safe, &self.accounts)
    }

    /// The account descriptor whose address matches `addr`, if this wallet
    /// holds it. Used to rebuild a signer for a chosen owner.
    fn owner_desc_for(&self, addr: Address) -> Option<AccountDescriptor> {
        owner_desc_by_address(addr, &self.accounts)
    }

    /// First Local account key in the wallet — the gas-paying executor for
    /// execute-from-queue. `None` when the wallet is hardware/view-only
    /// only (execution then needs an external relayer).
    fn first_local_key(&self) -> Option<B256> {
        first_local_key_of(&self.accounts)
    }

    /// Mark the open Safe-tx detail modal busy (no-op if a different modal
    /// is showing). Wrapped so the action handlers can mutate the pane
    /// without holding its borrow across `self` helper calls.
    fn mark_safe_detail_busy(&mut self) {
        if let Modal::SafeTxDetail(p) = &mut self.modal {
            p.mark_busy();
        }
    }

    /// Push an action result into the open Safe-tx detail modal.
    fn set_safe_detail_result(&mut self, result: Result<String, String>) {
        if let Modal::SafeTxDetail(p) = &mut self.modal {
            p.set_action_result(result);
        }
    }

    /// Re-check the active SafeDescriptor immediately before any queued
    /// Safe action spawns. The modal carries a trust snapshot from open,
    /// but refresh-on-open can replace descriptors while the modal remains
    /// visible.
    fn active_safe_signing_block(
        &self,
        safe: Address,
        chain: crate::chain::Chain,
    ) -> Option<String> {
        let Some(desc) = self.active_safe_descriptor() else {
            return Some(
                "Safe selection changed; reopen transaction details before signing.".into(),
            );
        };
        if desc.address() != safe || desc.chain_id != chain.chain_id() {
            return Some(
                "Safe selection changed; reopen transaction details before signing.".into(),
            );
        }
        desc.trust.signing_block_reason().map(str::to_string)
    }

    /// Spawn the preflight tasks for the Safe-tx detail modal's loaded
    /// detail. `inner`/`exec` select the subset (the targeted automatic
    /// retries re-run only the sim that came back unverified);
    /// `delayed` waits out the helios fallback cooldown first. No-op
    /// when the modal is gone or the detail never loaded.
    ///
    /// Inner sim only fires for plain calls (the view renders the
    /// delegatecall skip note without a task); exec sim only when the
    /// tx is next-up and this wallet holds a local gas payer — and only
    /// the executor *address* crosses into the task, derived
    /// synchronously here.
    fn safe_detail_sim_tasks(&self, inner: bool, exec: bool, delayed: bool) -> Task<Message> {
        let Modal::SafeTxDetail(p) = &self.modal else {
            return Task::none();
        };
        let Some(d) = p.loaded_detail() else {
            return Task::none();
        };
        let (safe, chain, hash) = (p.safe(), p.chain(), p.safe_tx_hash());
        let tx = d.tx.clone();
        let mut tasks: Vec<Task<Message>> = Vec::new();
        if inner && tx.operation == 0 {
            tasks.push(spawn_safe_inner_sim_task(
                self.network.clone(),
                safe,
                chain,
                hash,
                tx.clone(),
                delayed,
            ));
        }
        let next_up = matches!(
            d.state,
            crate::safe::service::SafeTxState::AwaitingExecution { is_next: true, .. }
        );
        if exec
            && next_up
            && !p.exec_submitted()
            && let Some(key) = self.first_local_key()
            && let Ok(signer) = crate::wallet::signer_from_bytes(&key)
        {
            let confirmations: Vec<(Address, Bytes)> = d
                .confirmations
                .iter()
                .map(|c| (c.owner, c.signature.clone()))
                .collect();
            tasks.push(spawn_safe_exec_sim_task(
                self.network.clone(),
                ExecSimSpec {
                    executor: signer.address(),
                    safe,
                    chain,
                    safe_tx_hash: hash,
                    tx,
                    confirmations,
                },
                delayed,
            ));
        }
        Task::batch(tasks)
    }

    /// Issue a Mainnet `network.balance` call purely to refresh the
    /// Helios verification badge — the result is discarded; only the
    /// side-effect on `last_status(Mainnet)` matters. Without this the
    /// badge would never leave "Connecting…": `get_code`,
    /// `get_storage_at`, and `call` deliberately don't touch
    /// `last_status` so the proxy walker can't flicker the badge on
    /// every clear-signing probe, and the portfolio fetch goes through
    /// the raw fallback provider rather than helios.
    pub fn refresh_verification_task(&self) -> Task<Message> {
        // Helios verification probes the displayed address — in Safe
        // mode that's the Safe's address, which is the right thing
        // to probe because that's what the user is looking at.
        let address = self.display_address();
        let network = self.network.clone();
        Task::perform(
            async move {
                debug!(addr = %short_address(address), "dashboard: refresh helios verification");
                let started = std::time::Instant::now();
                let ok = network
                    .balance(address, crate::chain::Chain::Mainnet)
                    .await
                    .is_ok();
                debug!(
                    elapsed = ?started.elapsed(),
                    ok,
                    "dashboard: helios verification refresh completed",
                );
            },
            |_| Message::VerificationRefreshed,
        )
    }

    /// Issue one history fetch per configured chain in parallel. Mirrors
    /// the portfolio fan-out: each chain emits its own
    /// `HistoryFetched { address, chain, result }`, and the handler
    /// merges the result so a slow L2 RPC can't block Mainnet rows from
    /// rendering. Each chain tries the configured indexer first; on
    /// `IndexerProvider::None` or any error, falls back to the on-chain
    /// `eth_getLogs` walk.
    pub fn fetch_history_task(&self) -> Task<Message> {
        let address = self.display_address();
        let provider_kind = settings::indexer_provider();
        let mut tasks: Vec<Task<Message>> = Vec::new();
        for chain in self.allowed_chains() {
            if settings::rpcs(chain).is_empty() {
                // L2 chain that the user never configured — skip silently.
                continue;
            }
            let network = self.network.clone();
            tasks.push(Task::perform(
                async move {
                    debug!(
                        addr = %short_address(address),
                        chain = %chain.label(),
                        indexer = ?provider_kind,
                        "fetching history",
                    );
                    let started = std::time::Instant::now();
                    // NoopIndexer always returns Ok([]), which would never
                    // trigger the fallback. Skip it explicitly so the on-chain
                    // walk runs.
                    let primary = if matches!(provider_kind, IndexerProvider::None) {
                        Err("indexer disabled".to_string())
                    } else {
                        crate::indexer::build_indexer_for(chain)
                            .transactions(address, HISTORY_LIMIT)
                            .await
                    };
                    let result = match primary {
                        Ok(v) => Ok(v),
                        Err(primary_err) => {
                            debug!(
                                chain = %chain.label(),
                                error = %primary_err,
                                "indexer failed; falling back to on-chain",
                            );
                            match network.provider(chain).await {
                                Some(p) => crate::indexer::onchain::fetch_onchain_history(
                                    &p,
                                    address,
                                    chain,
                                    HISTORY_LIMIT,
                                )
                                .await
                                .map_err(|e| format!("indexer: {primary_err}; on-chain: {e}")),
                                None => Err(primary_err),
                            }
                        }
                    };
                    // Stamp the chain on every row regardless of source —
                    // indexer impls default to Mainnet, the on-chain walk
                    // already sets it, but stamping unconditionally keeps
                    // the merged feed honest if any source forgets.
                    let result = result.map(|mut v| {
                        for r in v.iter_mut() {
                            r.chain = chain;
                        }
                        v
                    });
                    debug!(
                        elapsed = ?started.elapsed(),
                        chain = %chain.label(),
                        ok = result.is_ok(),
                        count = result.as_ref().map(|v| v.len()).unwrap_or(0),
                        "history fetch completed",
                    );
                    (address, chain, result)
                },
                |(address, chain, result)| Message::HistoryFetched {
                    address,
                    chain,
                    result,
                },
            ));
        }
        Task::batch(tasks)
    }

    /// Issue one portfolio fetch per configured chain in parallel.
    ///
    /// A chain is "configured" when its execution RPC list in settings
    /// is non-empty — Mainnet is always configured (the built-in default
    /// seeds it); L2 chains are only configured if the user opted in
    /// via the setup flow's Alchemy / Custom RPCs path or the Networks
    /// pane. Each chain emits its own `PortfolioFetched { address, chain, result }`
    /// message; the handler merges by chain so a slow Optimism RPC
    /// can't stall the Mainnet rows from rendering.
    pub fn fetch_portfolio_task(&self) -> Task<Message> {
        let address = self.display_address();
        let provider_kind = settings::indexer_provider();
        let mut tasks: Vec<Task<Message>> = Vec::new();
        for chain in self.allowed_chains() {
            if settings::rpcs(chain).is_empty() {
                // L2 chain that the user never configured — skip silently.
                continue;
            }
            let network = self.network.clone();
            tasks.push(Task::perform(
                async move {
                    debug!(
                        addr = %short_address(address),
                        chain = %chain.label(),
                        indexer = ?provider_kind,
                        "fetching portfolio",
                    );
                    let started = std::time::Instant::now();
                    // Routing:
                    //
                    // * Mainnet uses the indexer for *discovery only* — it
                    //   enumerates the ERC-20 contracts this address holds,
                    //   then balances and Uniswap prices are read on-chain
                    //   via Multicall3. The indexer's own balance/price
                    //   fields are dropped, so a malicious or stale indexer
                    //   can't fake what the user sees. When the indexer is
                    //   `NoopIndexer` or fails, we fall back to the curated
                    //   `MAINNET_OVERLAY` (still over Multicall3).
                    // * L2 chains keep the current indexer-as-source flow:
                    //   one HTTP round-trip vs. two Multicall3 batches, and
                    //   the on-chain walk's L2 token list (overlay + bundled
                    //   Superchain tokenlist) is already its fallback.
                    let indexer = crate::indexer::build_indexer_for(chain);
                    let result = if chain == crate::chain::Chain::Mainnet {
                        let discovered = indexer
                            .balances(address)
                            .await
                            .ok()
                            .map(crate::indexer::into_discovered_tokens)
                            .unwrap_or_default();
                        match network.provider(chain).await {
                            Some(p) => {
                                crate::portfolio::fetch_portfolio_with_discovery(
                                    address,
                                    chain,
                                    &p,
                                    &discovered,
                                )
                                .await
                            }
                            None => Err(format!(
                                "no execution RPCs configured for {}",
                                chain.label()
                            )),
                        }
                    } else {
                        let from_indexer = indexer
                            .balances(address)
                            .await
                            .ok()
                            .filter(|v| !v.is_empty());
                        if let Some(tokens) = from_indexer {
                            Ok(crate::indexer::into_live_tokens(chain, tokens))
                        } else {
                            match network.provider(chain).await {
                                Some(p) => {
                                    crate::portfolio::fetch_portfolio(address, chain, &p).await
                                }
                                None => Err(format!(
                                    "no execution RPCs configured for {}",
                                    chain.label()
                                )),
                            }
                        }
                    };
                    debug!(
                        elapsed = ?started.elapsed(),
                        chain = %chain.label(),
                        ok = result.is_ok(),
                        count = result.as_ref().map(|v: &Vec<LiveToken>| v.len()).unwrap_or(0),
                        "portfolio fetch completed",
                    );
                    (address, chain, result)
                },
                |(address, chain, result)| Message::PortfolioFetched {
                    address,
                    network: crate::chain::NetworkId::Builtin(chain),
                    result,
                },
            ));
        }
        // Custom networks: native-coin-only, unverified, served by a raw
        // provider built straight from the user's RPC URL. Skipped entirely
        // in Safe mode (custom networks have no Safe support), matching
        // `allowed_networks`. Each emits its own `PortfolioFetched` so a slow
        // or dead custom RPC never stalls the built-in rows.
        if self.active_safe_descriptor().is_none() {
            for net in settings::enabled_custom_networks() {
                let network = self.network.clone();
                tasks.push(Task::perform(
                    async move {
                        let started = std::time::Instant::now();
                        let result = match network.custom_provider(net.chain_id, &net.rpc_url).await
                        {
                            Some(p) => {
                                crate::portfolio::fetch_native_balance(address, &net, &p).await
                            }
                            None => Err(format!("invalid RPC URL for {}", net.name)),
                        };
                        debug!(
                            elapsed = ?started.elapsed(),
                            chain_id = net.chain_id,
                            custom = true,
                            ok = result.is_ok(),
                            "custom network portfolio fetch completed",
                        );
                        (address, net.chain_id, result)
                    },
                    |(address, chain_id, result)| Message::PortfolioFetched {
                        address,
                        network: crate::chain::NetworkId::Custom(chain_id),
                        result,
                    },
                ));
            }
        }
        Task::batch(tasks)
    }

    /// Fetch the active Safe's pending multisig queue from the Safe
    /// Transaction Service. Returns `None` in EOA mode, when the Safe
    /// sits on a chain Kao doesn't recognize, or when that chain has no
    /// configured RPC (the queue's FSM needs the Safe's on-chain nonce,
    /// read through `network`). `Option` rather than `Task::none()` so
    /// callers can tie `safe_pending_loading` to whether a
    /// `SafePendingFetched` will actually arrive to clear it — setting
    /// the flag for a fetch that never launches leaves the queue spinner
    /// stuck forever. Mirrors `fetch_portfolio_task`'s shape otherwise:
    /// clone the shared fetcher into the task, log timing, tag the result
    /// with the `(safe, chain)` it was issued against so a late landing
    /// can't pollute another identity.
    pub fn fetch_safe_pending_task(&self) -> Option<Task<Message>> {
        let safe = self.active_safe_descriptor()?;
        let chain = crate::chain::Chain::from_chain_id(safe.chain_id)?;
        if settings::rpcs(chain).is_empty() {
            return None;
        }
        let address = safe.address();
        let threshold = safe.threshold;
        let service_base = safe.tx_service_base().to_string();
        let network = self.network.clone();
        Some(Task::perform(
            async move {
                debug!(
                    safe = %short_address(address),
                    chain = %chain.label(),
                    "fetching safe pending queue",
                );
                let started = std::time::Instant::now();
                let result = crate::safe::service::fetch_pending(
                    &*network,
                    &service_base,
                    address,
                    chain,
                    threshold,
                )
                .await;
                debug!(
                    elapsed = ?started.elapsed(),
                    ok = result.is_ok(),
                    count = result.as_ref().map(Vec::len).unwrap_or(0),
                    "safe pending fetch completed",
                );
                (address, chain, result)
            },
            |(safe, chain, result)| Message::SafePendingFetched {
                safe,
                chain,
                result,
            },
        ))
    }

    /// Reverse-resolve the active address against ENS (forward-verified)
    /// and use the result as a default account name when none is set yet.
    /// Skipped when the user has already named the account: we never
    /// overwrite an explicit choice with an inferred one. Also skipped for
    /// inputs that look like they were just imported with an ENS name —
    /// the import flow already set the name, so a second lookup is wasted
    /// work (and would noisily reapply it).
    pub fn fetch_ens_name_task(&self) -> Task<Message> {
        let address = self.address;
        let network = self.network.clone();
        let already_named = self
            .accounts
            .get(self.active_index)
            .and_then(|a| a.name())
            .is_some();
        if already_named {
            return Task::none();
        }
        Task::perform(
            async move {
                debug!(addr = %short_address(address), "name reverse lookup");
                let started = std::time::Instant::now();
                // Verified (Helios, mainnet-only) reverse lookup across ENS /
                // GNS / WNS. An unverified read fails closed inside
                // `lookup_address`, so the address simply shows without a name
                // rather than a name a hostile RPC could fabricate.
                let result = crate::names::lookup_address(network.as_ref(), address).await;
                debug!(
                    elapsed = ?started.elapsed(),
                    found = matches!(&result, Ok(Some(_))),
                    "name reverse lookup completed",
                );
                (address, result)
            },
            |(address, result)| Message::EnsAutoNameResolved { address, result },
        )
    }

    pub fn update(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        match &message {
            // Skipped: `Tick` is the 16 ms animation-frame timer (modal
            // chrome / clipboard chip / copy toast; see `subscription`) —
            // tracing it would drown the stream.
            Message::Tick => {}
            // Redacted: the Ok payload embeds each recovered note's
            // (nullifier, secret) spending keys, which the SDK types
            // Debug-print — trace the variant without the payload.
            Message::PoolSynced {
                pool,
                chain,
                result,
            } => {
                crate::trace_msg!(
                    "dashboard",
                    &format_args!(
                        "PoolSynced {{ pool: {pool}, chain: {chain:?}, ok: {} }}",
                        result.is_ok()
                    )
                );
            }
            _ => crate::trace_msg!("dashboard", &message),
        }
        // Diff the coarse dashboard state across the dispatch so every
        // transition is logged no matter which arm (or helper) performed it.
        let nav_before = nav_name(self.nav);
        let modal_before = self.modal.name();
        let pane_before = self.settings_pane.name();
        let review_before = self.sign_review.is_some();
        let rename_before = self.rename_draft.is_some();

        let (task, outcome) = self.update_inner(message);

        let nav_after = nav_name(self.nav);
        if nav_before != nav_after {
            crate::trace::state("dashboard", "nav", nav_before, nav_after);
        }
        let modal_after = self.modal.name();
        if modal_before != modal_after {
            crate::trace::state("dashboard", "modal", modal_before, modal_after);
        }
        let pane_after = self.settings_pane.name();
        if pane_before != pane_after {
            crate::trace::state("dashboard", "settings_pane", pane_before, pane_after);
        }
        let review_after = self.sign_review.is_some();
        if review_before != review_after {
            let s = |open: bool| if open { "open" } else { "none" };
            crate::trace::state(
                "dashboard",
                "sign_review",
                s(review_before),
                s(review_after),
            );
        }
        let rename_after = self.rename_draft.is_some();
        if rename_before != rename_after {
            crate::trace::state("dashboard", "renaming", rename_before, rename_after);
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("dashboard", o.name());
        }
        (task, outcome)
    }

    fn update_inner(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        match message {
            Message::VerificationRefreshed => {
                self.verification = self.network.last_status(crate::chain::Chain::Mainnet);
            }
            Message::RefreshPortfolio => {
                // Drop rows for networks no longer in scope — e.g. a custom
                // network the user just disabled or deleted. Those won't get a
                // fresh `PortfolioFetched`, so without this their stale rows
                // would linger until the next account switch.
                let allowed = self.allowed_networks();
                self.portfolio.retain(|t| allowed.contains(&t.chain));
                // Don't reset `portfolio_loading` if the portfolio is
                // already populated — the rendered tokens stay
                // visible during refresh, and the home view's
                // refresh button carries its own busy hint. Setting
                // `loading` only when empty preserves the existing
                // first-render skeleton path.
                self.portfolio_loading = self.portfolio.is_empty();
                self.portfolio_refreshing = true;
                // In Safe mode the refresh chip also reloads the pending
                // queue so freshly-signed/executed txs surface promptly.
                // The loading flag tracks whether a fetch was actually
                // issued — `None` (EOA mode, unknown chain, no RPCs)
                // means no `SafePendingFetched` will arrive to clear it.
                let pending = self.fetch_safe_pending_task();
                self.safe_pending_loading = pending.is_some();
                return (
                    Task::batch([
                        self.refresh_verification_task(),
                        self.fetch_portfolio_task(),
                        pending.unwrap_or_else(Task::none),
                    ]),
                    None,
                );
            }
            Message::SafesUpdated(safes) => {
                // Wholesale replace — refresh-on-open runs in batch
                // and returns the complete updated list, so there's
                // nothing to merge.
                self.safes = safes;
                // Keep the Settings → Safes pane (if open) in sync so
                // its drafts reseed from what actually persisted.
                if let SettingsPane::Safes(p) = &mut self.settings_pane {
                    p.set_safes(self.safes.clone());
                }
                // The pending queue's lifecycle states were derived against the
                // *old* descriptors (threshold/owners). Rebuild it against the
                // refreshed ones so a changed threshold can't leave a stale
                // have/required badge on a queued tx.
                let pending = self.fetch_safe_pending_task();
                self.safe_pending_loading = pending.is_some();
                return (pending.unwrap_or_else(Task::none), None);
            }
            Message::PortfolioFetched {
                address,
                network,
                result,
            } => {
                // Always write the (address, network) we issued the fetch
                // for into the cache — it's still the correct slot for
                // that address's data even if the user has since
                // switched away. Only the live portfolio merge is
                // gated on `address == display_address` (which in
                // Safe mode is the Safe's address).
                if let Ok(tokens) = &result
                    && let Ok(mut cache) = self.portfolio_cache.lock()
                {
                    // Only cache rows that belong to the network we fetched — a
                    // buggy/malicious provider could tag a token with another
                    // network, which would pollute this slot (and, via the
                    // merge below, the live portfolio).
                    let scoped: Vec<LiveToken> = tokens
                        .iter()
                        .filter(|t| t.chain == network)
                        .cloned()
                        .collect();
                    cache.insert((address, network), scoped);
                }
                if address != self.display_address() {
                    return (Task::none(), None);
                }
                // Cross-network rows that are no longer in scope: a stale
                // fetch issued before a Safe switch (or before a custom
                // network was disabled) can land afterwards carrying a
                // network that's no longer allowed. Drop it before merging
                // so the user never sees out-of-scope balances.
                if !self.allowed_networks().contains(&network) {
                    return (Task::none(), None);
                }
                // Loading flag clears once *any* chain lands; the user
                // sees results stream in rather than wait for the
                // slowest chain. Refresh flag follows the same
                // first-wins rule so the button's busy hint clears
                // as soon as anything new arrives.
                self.portfolio_loading = false;
                self.portfolio_refreshing = false;
                match result {
                    Ok(tokens) => {
                        // Merge by network: replace the rows belonging to
                        // `network` with the new ones, leave other networks'
                        // rows untouched. Re-sort ETH-first then by USD
                        // value descending so a late-landing network
                        // doesn't shuffle a stable row order — the
                        // original portfolio sort already maintained this.
                        self.portfolio.retain(|t| t.chain != network);
                        // Same network-scoping as the cache write: never merge
                        // a token whose `chain` differs from the one we
                        // fetched, or a stale row would survive the retain.
                        self.portfolio
                            .extend(tokens.into_iter().filter(|t| t.chain == network));
                        sort_portfolio_rows(&mut self.portfolio);
                    }
                    Err(e) => warn!(
                        chain_id = network.chain_id(),
                        error = %e,
                        "portfolio fetch failed",
                    ),
                }
            }
            Message::SafePendingFetched {
                safe,
                chain,
                result,
            } => {
                // Staleness guard: drop if the user has left this Safe
                // (switched to an EOA or a different Safe) or if the
                // active Safe has since moved off this chain. Mirrors the
                // `PortfolioFetched` address/chain guards.
                let still_active = self
                    .active_safe_descriptor()
                    .is_some_and(|s| s.address() == safe && s.chain_id == chain.chain_id());
                if !still_active {
                    return (Task::none(), None);
                }
                self.safe_pending_loading = false;
                match result {
                    Ok(pending) => {
                        self.safe_pending = pending;
                        self.safe_pending_error = None;
                    }
                    Err(e) => {
                        warn!(
                            safe = %short_address(safe),
                            chain = %chain.label(),
                            error = %e,
                            "safe pending fetch failed",
                        );
                        self.safe_pending_error = Some(e);
                    }
                }
            }
            Message::HistoryFetched {
                address,
                chain,
                result,
            } => {
                if address != self.display_address() {
                    return (Task::none(), None);
                }
                if !self.allowed_chains().contains(&chain) {
                    // Same staleness guard as PortfolioFetched — a
                    // pre-Safe-mode history fetch on a different chain
                    // shouldn't pollute the Safe's activity feed.
                    return (Task::none(), None);
                }
                self.history_loaded = true;
                // Drop this chain from the pending set; once empty,
                // history_loading flips to false. The user sees the
                // fastest chain's rows appear immediately while slower
                // chains keep loading in the background.
                self.history_pending.retain(|c| *c != chain);
                if self.history_pending.is_empty() {
                    self.history_loading = false;
                }
                match result {
                    Ok(txs) => {
                        self.history_errors.set(chain, None);
                        // Replace this chain's rows in the merged feed
                        // and re-sort newest-first by timestamp (block
                        // numbers aren't comparable across chains).
                        self.history.retain(|r| r.chain != chain);
                        self.history.extend(txs);
                        self.history.sort_by(|a, b| {
                            b.timestamp
                                .cmp(&a.timestamp)
                                .then_with(|| b.hash.cmp(&a.hash))
                        });
                        // Cap to HISTORY_LIMIT after merging so a quiet
                        // chain doesn't get squeezed out by a busy one
                        // (each chain fetched up to HISTORY_LIMIT; the
                        // merged view shows the top N by recency).
                        self.history.truncate(HISTORY_LIMIT);
                    }
                    Err(e) => {
                        warn!(
                            chain = %chain.label(),
                            error = %e,
                            "history fetch failed",
                        );
                        self.history_errors.set(chain, Some(e));
                    }
                }
            }
            Message::RetryHistory => {
                if self.history_loading {
                    return (Task::none(), None);
                }
                self.history_loading = true;
                self.history_errors = PerChain::default();
                self.reset_history_pending();
                return (self.fetch_history_task(), None);
            }
            Message::SelectNav(nav) => {
                if self.nav != nav {
                    self.settings_pane = SettingsPane::Root;
                }
                self.nav = nav;
                // Lazy-load the activity feed on the first switch into
                // the Activity tab so the dashboard doesn't pay the
                // indexer (and on-chain fallback) round-trips on every
                // account switch.
                if matches!(nav, Nav::Activity) && !self.history_loaded && !self.history_loading {
                    self.history_loading = true;
                    self.reset_history_pending();
                    return (self.fetch_history_task(), None);
                }
            }
            Message::SelectTheme(k) => {
                self.theme_kind = k;
                settings::set_theme(k);
            }
            Message::ReconnectHardware => {
                // The sidebar only shows the Reconnect button for a
                // disconnected hardware account, but guard anyway so a
                // stray message is a no-op rather than a spurious connect
                // screen for a software / view-only identity.
                if matches!(
                    self.accounts.get(self.active_index),
                    Some(AccountDescriptor::Ledger { .. } | AccountDescriptor::Trezor { .. })
                ) {
                    return (
                        Task::none(),
                        Some(Outcome::NeedsHardwareReconnect { open_send: false }),
                    );
                }
            }
            Message::OpenSend => {
                // Safe mode: route Send to the unified SendPane in
                // Safe mode. The EOA signer stays alive in
                // `self.signer` and gets moved into the broadcast
                // task at Confirm time — it pays gas as the executor.
                if let Some(safe) = self.active_safe_descriptor() {
                    self.modal = Modal::Send(Box::new(SendPane::new_safe(safe, &self.accounts)));
                    self.chrome.open();
                    return (Task::none(), None);
                }
                if !self.signer.can_sign() {
                    // Hardware accounts can sign — they just need the device
                    // reconnected. Escalate so the App can push the matching
                    // connect screen and come back with a live signer +
                    // Send modal opened. True view-only accounts have no
                    // signing material at all, so they stay no-op here.
                    if matches!(
                        self.accounts.get(self.active_index),
                        Some(AccountDescriptor::Ledger { .. } | AccountDescriptor::Trezor { .. })
                    ) {
                        return (
                            Task::none(),
                            Some(Outcome::NeedsHardwareReconnect { open_send: true }),
                        );
                    }
                    info!("send disabled: active account is view-only");
                    return (Task::none(), None);
                }
                self.modal = Modal::Send(Box::new(SendPane::new_eoa(self.address)));
                self.chrome.open();
                // Refresh portfolio + hero balance as the modal opens so
                // the token tabs and Max button work off fresh numbers
                // instead of whatever was last cached.
                return (
                    Task::batch([
                        self.refresh_verification_task(),
                        self.fetch_portfolio_task(),
                    ]),
                    None,
                );
            }
            Message::Send(child_msg) => {
                let Modal::Send(p) = &mut self.modal else {
                    return (Task::none(), None);
                };
                // ── Coordinator-side intercepts ────────────────────────
                //
                // Some pane messages need data the pane doesn't carry
                // (portfolio entries, the live signer, the network
                // provider). Handle those here, then either short-circuit
                // or forward to the pane.

                // Max: compute the largest sendable amount for the active
                // token. EOA mode subtracts the loaded gas cost for
                // native ETH; Safe mode uses the raw balance (no gas
                // deduction — the executor pays gas separately).
                if let send::Message::Max = &child_msg {
                    if let Some(tk) = self.portfolio.get(p.token_idx()) {
                        let max_str = compute_max_amount(tk, p);
                        p.apply_max(max_str);
                    }
                    return (Task::none(), None);
                }

                // Step(2): user clicked "Review →". EOA spawns a quote
                // task (gas + 1559 fees + nonce) AND a clear-signing
                // decode task. Safe is a no-op here — the prepare and
                // sim tasks fire via take_pending_prepare after the
                // pane's update.
                if let send::Message::Step(2) = &child_msg {
                    let pre_task = if p.is_eoa() {
                        let plan = p.build_plan(&self.portfolio);
                        match plan {
                            Some(pl) => {
                                let quote_seq = p.quote_started();
                                let decode_seq = p.decode_started();
                                let quote_task =
                                    spawn_quote_task(self.network.clone(), quote_seq, pl.clone());
                                let local_names =
                                    build_local_names(&self.accounts, &self.safes, &self.contacts);
                                let decode_task = spawn_decode_task(
                                    self.network.clone(),
                                    decode_seq,
                                    pl,
                                    local_names,
                                );
                                Task::batch([quote_task, decode_task])
                            }
                            None => Task::none(),
                        }
                    } else {
                        Task::none()
                    };
                    let (task, _outcome) = p.update(child_msg);
                    let task = task.map(Message::Send);
                    return (Task::batch([pre_task, task]), None);
                }

                // Confirm: mode-aware.
                // EOA: move the signer out of the dashboard, run
                // sign+broadcast in a task, route the signer back via
                // `SignerHandoff`.
                // Safe: collect linked owner keys, spawn the Safe
                // sign+broadcast task (executor derived inside).
                if let send::Message::Confirm = &child_msg {
                    if p.is_eoa() {
                        let plan = p.build_plan(&self.portfolio);
                        let quote = plan.as_ref().and_then(|pl| p.quote_for_plan(pl)).cloned();
                        info!(
                            has_plan = plan.is_some(),
                            has_quote = quote.is_some(),
                            "send: confirm clicked",
                        );
                        if let (Some(plan), Some(quote)) = (plan, quote) {
                            info!(
                                chain_id = plan.chain.chain_id(),
                                custom = plan.chain.is_custom(),
                                from = %plan.from,
                                recipient = %plan.recipient,
                                amount_units = %plan.amount_units,
                                erc20 = matches!(plan.token, crate::wallet::tx::SendToken::Erc20 { .. }),
                                gas_limit = quote.gas_limit,
                                nonce = quote.nonce,
                                "send: spawning broadcast task",
                            );
                            // Disjoint-field access (not `active_signer_descriptor`,
                            // which borrows all of `self`) because the Send pane
                            // `p` still holds `&mut self.modal` here.
                            let desc = self.accounts.get(self.active_index).cloned().unwrap_or(
                                AccountDescriptor::ViewOnly {
                                    name: None,
                                    address: self.address.into_array(),
                                },
                            );
                            let signer =
                                mem::replace(&mut self.signer, KaoSigner::ViewOnly(self.address));
                            let handoff = handoff_with(signer);
                            let pre_task = spawn_broadcast_task(
                                self.network.clone(),
                                handoff,
                                desc,
                                plan,
                                quote,
                            );
                            let (task, _outcome) = p.update(child_msg);
                            let task = task.map(Message::Send);
                            return (Task::batch([pre_task, task]), None);
                        }
                        warn!("send: confirm dropped — no current plan/quote pair");
                        return (Task::none(), None);
                    }
                    // Safe mode: solo sign-and-execute. Collect the first
                    // `threshold` signable owners (Local or hardware) and
                    // pick a gas-paying executor — a Local account if the
                    // wallet holds one, otherwise the first signing owner
                    // (a 1/1 Safe's hardware owner pays its own gas).
                    let Some(req) = p.outgoing_request(&self.portfolio) else {
                        warn!("safe-send: confirm dropped — form not ready");
                        return (Task::none(), None);
                    };
                    let signer_owners: Vec<AccountDescriptor> = req
                        .signable_indices
                        .iter()
                        .filter_map(|&idx| self.accounts.get(idx as usize).cloned())
                        .take(req.threshold as usize)
                        .collect();
                    if (signer_owners.len() as u32) < req.threshold {
                        let msg = "Not enough signable owners linked to this Safe to meet its threshold — propose to co-signers instead.".to_string();
                        let _ = p.update(send::Message::BroadcastDone(Err(msg)));
                        return (Task::none(), None);
                    }
                    let executor_key = first_local_key_of(&self.accounts);
                    info!(
                        chain = %req.chain.label(),
                        chain_id = req.chain.chain_id(),
                        safe = %req.safe_address,
                        to = %req.recipient,
                        value_wei = %req.amount_units,
                        threshold = req.threshold,
                        signers = signer_owners.len(),
                        local_executor = executor_key.is_some(),
                        "safe-send: spawning broadcast task",
                    );
                    p.mark_busy();
                    let pre_task = spawn_safe_broadcast_task(
                        self.network.clone(),
                        req,
                        signer_owners,
                        executor_key,
                    );
                    return (pre_task, None);
                }

                // Propose: Safe-only. Sign once with the first signable
                // owner and POST to the tx service for co-signers.
                if let send::Message::Propose = &child_msg {
                    let Some(req) = p.outgoing_request(&self.portfolio) else {
                        warn!("safe-send: propose dropped — form not ready");
                        return (Task::none(), None);
                    };
                    let Some(owner_desc) = req
                        .signable_indices
                        .first()
                        .and_then(|&idx| self.accounts.get(idx as usize).cloned())
                    else {
                        let _ = p.update(send::Message::ProposeDone(Err(
                            "no signable owner linked to this Safe".to_string(),
                        )));
                        return (Task::none(), None);
                    };
                    info!(
                        chain = %req.chain.label(),
                        safe = %req.safe_address,
                        to = %req.recipient,
                        value_wei = %req.amount_units,
                        "safe-send: spawning propose task",
                    );
                    p.mark_busy();
                    return (
                        spawn_safe_propose_task(self.network.clone(), owner_desc, req),
                        None,
                    );
                }

                let (task, outcome) = p.update(child_msg);

                // After pumping the pane, check whether the recipient
                // input now points at an ENS-shaped value that hasn't been
                // dispatched yet. The pane bumps a sequence on each
                // change; `take_pending_ens` returns Some exactly once
                // per sequence so a no-op repaint won't refire the lookup.
                let ens_task = match p.take_pending_ens() {
                    Some((seq, name)) => spawn_ens_resolve_task(self.network.clone(), seq, name),
                    None => Task::none(),
                };

                // Safe-only post-pump hooks: prepare+sim and sim retry.
                let prepare_task = match p.take_pending_prepare(&self.portfolio) {
                    Some((seq, req)) => Task::batch([
                        spawn_safe_prepare_task(self.network.clone(), seq, req.clone()),
                        spawn_safe_send_sim_task(self.network.clone(), seq, req, false),
                    ]),
                    None => Task::none(),
                };
                let sim_retry_task = match p.take_pending_sim_retry(&self.portfolio) {
                    Some((seq, req, delayed)) => {
                        spawn_safe_send_sim_task(self.network.clone(), seq, req, delayed)
                    }
                    None => Task::none(),
                };

                let task = task.map(Message::Send);
                match outcome {
                    Some(send::Outcome::Closed) => {
                        // Safe mode closes instantly; EOA animates.
                        if p.is_safe() {
                            self.modal = Modal::None;
                        } else {
                            self.chrome.start_close();
                        }
                        return (
                            Task::batch([task, ens_task, prepare_task, sim_retry_task]),
                            None,
                        );
                    }
                    Some(send::Outcome::CopyText(s)) => {
                        let copy_task = self.arm_clipboard_clear(s);
                        return (
                            Task::batch([task, copy_task, ens_task, prepare_task, sim_retry_task]),
                            None,
                        );
                    }
                    Some(send::Outcome::SaveAsContact { address, ens }) => {
                        let open_task = Task::done(Message::OpenContactsPaneWith { address, ens });
                        return (
                            Task::batch([task, ens_task, prepare_task, sim_retry_task, open_task]),
                            None,
                        );
                    }
                    None => {
                        return (
                            Task::batch([task, ens_task, prepare_task, sim_retry_task]),
                            None,
                        );
                    }
                }
            }
            Message::SendBroadcastReturn { result, signer } => {
                // Reclaim the signer regardless of pane state — the dashboard
                // must end up holding it again (and only if it's the real signer
                // for the current account; see `install_reclaimed_signer`).
                self.install_reclaimed_signer(&signer);
                // Pump the result into the pane if it's still open. If
                // the user closed the modal mid-broadcast we silently
                // drop the result — the tx was still sent and a future
                // balance refresh will surface it.
                if let Modal::Send(p) = &mut self.modal {
                    let success = result.is_ok();
                    match &result {
                        Ok(hash) => info!(hash = %format!("{hash:#x}"), "broadcast ok"),
                        Err(e) => warn!(error = %e, "broadcast failed"),
                    }
                    let (task, _outcome) = p.update(send::Message::BroadcastDone(result));
                    // Refresh balance + portfolio + history on success so
                    // the dashboard reflects the new state (the hero
                    // balance, held-token list, and activity feed all
                    // shift). History is gated on `history_loaded`: if
                    // the user never opened the Activity tab there's no
                    // point paying for a fetch they won't see.
                    let refresh = if success {
                        let mut tasks = vec![
                            self.refresh_verification_task(),
                            self.fetch_portfolio_task(),
                        ];
                        if self.history_loaded {
                            self.history_loading = true;
                            self.reset_history_pending();
                            tasks.push(self.fetch_history_task());
                        }
                        Task::batch(tasks)
                    } else {
                        Task::none()
                    };
                    // Delayed step 3 → 4 transition: after broadcast
                    // succeeds, wait a beat then advance to the success
                    // screen. The pane's `AdvanceToDone` handler guards on
                    // `broadcast_done`, so a stale timer (user closed the
                    // modal) is a safe no-op.
                    let advance_task = if success {
                        Task::perform(
                            async {
                                tokio::time::sleep(Duration::from_millis(2200)).await;
                            },
                            |_| Message::Send(send::Message::AdvanceToDone),
                        )
                    } else {
                        Task::none()
                    };
                    return (
                        Task::batch([task.map(Message::Send), refresh, advance_task]),
                        None,
                    );
                }
            }
            Message::EnsAutoNameResolved { address, result } => {
                // The lookup was issued against `self.address` at the time
                // it was kicked off; if the user switched accounts before
                // it landed, drop it.
                if address != self.address {
                    return (Task::none(), None);
                }
                let name = match result {
                    Ok(Some(n)) => n,
                    Ok(None) => return (Task::none(), None),
                    Err(e) => {
                        warn!(error = %e, "auto-name lookup failed");
                        return (Task::none(), None);
                    }
                };
                // Re-check the name slot — the user could have renamed
                // since we kicked off the lookup, and we never overwrite
                // an explicit choice with an inferred one.
                let acc = match self.accounts.get_mut(self.active_index) {
                    Some(a) if a.name().is_none() => a,
                    _ => return (Task::none(), None),
                };
                acc.set_name(Some(name.clone()));
                // Bubble up so the App persists the rename to disk via
                // its existing rename pipeline.
                return (Task::none(), Some(Outcome::RenameActive(Some(name))));
            }
            Message::ClipboardWritten => {}
            Message::ClipboardClearArmed { generation } => {
                // Stale arm — a fresher copy bumped the counter — drop.
                if self
                    .clipboard_clear
                    .as_ref()
                    .is_none_or(|s| s.generation != generation)
                {
                    return (Task::none(), None);
                }
                // Read the live clipboard so the next handler can decide
                // whether the value is still ours. Doing the check at
                // probe time (instead of unconditionally clearing) keeps
                // us from clobbering content the user copied in the
                // meantime from outside the wallet.
                let task =
                    iced::clipboard::read().map(move |actual| Message::ClipboardClearProbe {
                        generation,
                        actual: actual.map(Into::into),
                    });
                return (task, None);
            }
            Message::ClipboardClearProbe { generation, actual } => {
                let Some(state) = &self.clipboard_clear else {
                    return (Task::none(), None);
                };
                if state.generation != generation {
                    return (Task::none(), None);
                }
                let still_ours =
                    actual.as_ref().map(|s| s.expose()) == Some(state.expected.as_str());
                self.clipboard_clear = None;
                if still_ours {
                    let clear = iced::clipboard::write(String::new())
                        .map(|_: ()| Message::ClipboardWritten);
                    return (clear, None);
                }
                return (Task::none(), None);
            }
            Message::OpenReceive => {
                // In Safe mode, hand the Safe's address to the
                // existing Receive pane — it's address-agnostic.
                self.modal = Modal::Receive(ReceivePane::new(self.display_address()));
                self.chrome.open();
            }
            Message::Receive(child_msg) => {
                let Modal::Receive(p) = &mut self.modal else {
                    return (Task::none(), None);
                };
                let (task, outcome) = p.update(child_msg);
                let task = task.map(Message::Receive);
                match outcome {
                    Some(receive::Outcome::Closed) => {
                        self.chrome.start_close();
                        return (task, None);
                    }
                    None => return (task, None),
                }
            }
            Message::OpenSwap => {
                // The quick-action button is disabled when `can_swap()` is
                // false (view-only or Safe mode); guard here too so a stray
                // message can't open a modal that can't sign.
                if !self.can_swap() {
                    return (Task::none(), None);
                }
                self.modal = Modal::Swap(SwapPane::new());
                self.chrome.open();
            }
            Message::Swap(child_msg) => {
                let Modal::Swap(p) = &mut self.modal else {
                    return (Task::none(), None);
                };
                let (task, outcome) = p.update(child_msg);
                let task = task.map(Message::Swap);
                match outcome {
                    Some(swap::Outcome::Closed) => {
                        self.chrome.start_close();
                        return (task, None);
                    }
                    Some(swap::Outcome::RequestQuote(draft)) => {
                        let q = spawn_cow_quote(CowHost::Modal, draft, self.order_owner());
                        return (Task::batch([task, q]), None);
                    }
                    Some(swap::Outcome::RequestPlace { draft, quote }) => {
                        // Don't sign yet — open the clear-signing review. The
                        // signer is parked and the order placed only on confirm.
                        let review = self.open_cow_review(CowHost::Modal, draft, quote);
                        return (Task::batch([task, review]), None);
                    }
                    Some(swap::Outcome::RequestCancel { uid }) => {
                        let review = self.open_cow_cancel_review(CowHost::Modal, uid);
                        return (Task::batch([task, review]), None);
                    }
                    Some(swap::Outcome::CopyText(s)) => {
                        let copy = self.arm_clipboard_clear(s);
                        return (Task::batch([task, copy]), None);
                    }
                    None => return (task, None),
                }
            }
            Message::Apps(child) => {
                let outcome = self.apps.update(child);
                // After pumping the pane, dispatch a forward name resolution if
                // the Privacy Pools withdrawal target now points at a name-shaped
                // value not yet looked up. `take_pending_resolve` returns Some
                // exactly once per change, so a no-op repaint won't refire it
                // (mirrors the Send flow's post-pump `take_pending_ens`).
                let resolve_task = match self.apps.pool_pane().take_pending_resolve() {
                    Some((seq, name)) => spawn_pool_resolve_task(self.network.clone(), seq, name),
                    None => Task::none(),
                };
                let (task, out): (Task<Message>, Option<Outcome>) = match outcome {
                    Some(apps::Outcome::RequestQuote(draft)) => (
                        spawn_cow_quote(CowHost::Apps, draft, self.order_owner()),
                        None,
                    ),
                    Some(apps::Outcome::RequestPlace { draft, quote }) => {
                        (self.open_cow_review(CowHost::Apps, draft, quote), None)
                    }
                    Some(apps::Outcome::RequestCancel { uid }) => {
                        (self.open_cow_cancel_review(CowHost::Apps, uid), None)
                    }
                    Some(apps::Outcome::RefreshOrders) => {
                        // "Fetch" pulls the address's full CoW order history —
                        // this session's orders plus any from past sessions —
                        // from every chain CoW runs on, upserting each page into
                        // `tracked_orders`. (The 10s background tick still does
                        // the lightweight per-order status poll between fetches.)
                        // Scoped to the active identity — the Safe in Safe mode,
                        // else the EOA.
                        let address = self.order_owner();
                        let tasks: Vec<Task<Message>> = crate::chain::Chain::ALL
                            .into_iter()
                            .filter(|c| crate::cow::supported(*c))
                            .map(|chain| spawn_cow_account_orders(chain, address))
                            .collect();
                        (Task::batch(tasks), None)
                    }
                    Some(apps::Outcome::CopyText(s)) => (self.arm_clipboard_clear(s), None),
                    Some(apps::Outcome::Name(o)) => (self.handle_name_outcome(o), None),
                    Some(apps::Outcome::Pool(o)) => self.handle_pool_outcome(o),
                    None => (Task::none(), None),
                };
                return (Task::batch([resolve_task, task]), out);
            }
            Message::SignReview(child) => match child {
                sign_review::Message::Confirm => {
                    return (self.confirm_sign_review(), None);
                }
                sign_review::Message::Cancel
                | sign_review::Message::Key(iced::keyboard::Event::KeyPressed {
                    key: iced::keyboard::Key::Named(iced::keyboard::key::Named::Escape),
                    ..
                }) => {
                    self.cancel_sign_review();
                }
                sign_review::Message::BoxClickIgnored | sign_review::Message::Key(_) => {}
                // Copy-toast kick — the widget already copied + marked the toast;
                // processing this message is enough to start its animation tick.
                sign_review::Message::AddressCopied => {}
            },
            Message::SignReviewPrepared { seq, steps } => {
                // Drop a decode result for a review the user has since cancelled
                // or replaced (the seq guard mirrors the Send decode pipeline).
                let Some(review) = self.sign_review.as_mut() else {
                    return (Task::none(), None);
                };
                if review.seq != seq {
                    return (Task::none(), None);
                }
                match steps {
                    Ok(new_steps) => {
                        // Append the prepared steps after any leading typed step
                        // (an EOA swap's order); the reviewed set == the signed set.
                        review.steps.extend(new_steps);
                        review.legs_loading = false;
                    }
                    Err(e) => {
                        // Couldn't build/decode the transaction — abandon the
                        // review and surface the error on the originating pane
                        // rather than letting the user confirm a blank gate.
                        self.fail_sign_review(e);
                    }
                }
            }
            Message::NameReverseScanned { owner, result } => {
                if owner == self.order_owner() {
                    self.apps.names_pane().on_reverse_scan(result);
                }
            }
            Message::NameStatusLoaded { owner, result } => {
                if owner == self.order_owner() {
                    self.apps.names_pane().on_status(result);
                }
            }
            Message::NameSearched { owner, seq, result } => {
                if owner == self.order_owner() {
                    self.apps.names_pane().on_search(seq, result);
                }
            }
            Message::NameQuoted {
                owner,
                years,
                result,
            } => {
                if owner == self.order_owner() {
                    self.apps.names_pane().on_quote(years, result);
                }
            }
            Message::NameCommitted { result, signer } => {
                self.reclaim_order_signer(signer);
                self.apps.names_pane().on_commit(result);
            }
            Message::NameRegistered { result, signer } => {
                self.reclaim_order_signer(signer);
                self.apps.names_pane().on_register(result);
            }
            Message::NameRenewed { result, signer } => {
                self.reclaim_order_signer(signer);
                self.apps.names_pane().on_renew(result);
            }
            Message::NameRecipientSet { result, signer } => {
                self.reclaim_order_signer(signer);
                self.apps.names_pane().on_set_recipient(result);
            }
            Message::CowQuote { host, result } => match host {
                CowHost::Modal => {
                    if let Modal::Swap(p) = &mut self.modal {
                        p.on_quote(result);
                    }
                }
                CowHost::Apps => self.apps.on_quote(result),
            },
            Message::CowPlaced {
                host,
                result,
                signer,
            } => {
                // Always reclaim the signer, regardless of pane state.
                self.install_reclaimed_signer(&signer);
                // The order op has resolved — the signer is back, so the Apps
                // surface no longer needs the in-flight reprieve.
                self.order_op_in_flight = false;
                match result {
                    Ok(order) => {
                        let uid = order.uid.clone();
                        let chain = order.chain;
                        if !self.tracked_orders.iter().any(|o| o.uid == uid) {
                            self.tracked_orders.push(order);
                        }
                        match host {
                            CowHost::Modal => {
                                if let Modal::Swap(p) = &mut self.modal {
                                    p.begin_tracking(uid.clone());
                                }
                            }
                            CowHost::Apps => self.apps.placement_done(),
                        }
                        // Immediate status fetch so the UI isn't blank until the
                        // 10s poll tick.
                        return (spawn_cow_status(chain, uid), None);
                    }
                    Err(e) => {
                        warn!(error = %e, "cow: order placement failed");
                        match host {
                            CowHost::Modal => {
                                if let Modal::Swap(p) = &mut self.modal {
                                    p.placement_failed(e);
                                }
                            }
                            CowHost::Apps => self.apps.placement_failed(e),
                        }
                    }
                }
            }
            Message::CowCancel {
                host,
                uid,
                result,
                signer,
            } => {
                self.install_reclaimed_signer(&signer);
                self.order_op_in_flight = false;
                match result {
                    Ok(()) => {
                        if let Some(o) = self.tracked_orders.iter_mut().find(|o| o.uid == uid) {
                            o.status = OrderStatus::Cancelled;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "cow: cancel failed");
                        // Surface the failure on the originating pane instead of
                        // swallowing it — otherwise a locked-Ledger cancel looks
                        // like a no-op. Reuses the placement-error channel.
                        match host {
                            CowHost::Modal => {
                                if let Modal::Swap(p) = &mut self.modal {
                                    p.placement_failed(e);
                                }
                            }
                            CowHost::Apps => self.apps.placement_failed(e),
                        }
                    }
                }
            }
            Message::PoolsDiscovered { chain, result } => {
                let pools = match result {
                    Ok(pools) => pools,
                    Err(e) => {
                        warn!(%chain, error = %e, "privacy pools: pool discovery failed");
                        let pane = self.apps.pool_pane();
                        pane.set_syncing(false);
                        pane.set_error(Some(e));
                        return (Task::none(), None);
                    }
                };
                {
                    let pane = self.apps.pool_pane();
                    pane.set_syncing(false);
                    pane.set_pools(
                        chain,
                        pools.clone(),
                        crate::pool::relayer::default_relayers(),
                    );
                }
                // Remember each pool's scope so the post-sync ASP approval fetch
                // can find it from the pool address alone.
                for p in &pools {
                    self.pool_scopes.insert(p.pool, p.scope_decimal());
                }
                // Fill in each pool's account state in the background (getLogs
                // scan) so the pools + their metadata show immediately.
                let Some(account) = self.pp_account else {
                    return (Task::none(), None);
                };
                let tasks: Vec<Task<Message>> = pools
                    .into_iter()
                    .map(|info| {
                        let cached = self
                            .pool_note_cache
                            .get(&(chain.chain_id(), info.pool))
                            .cloned();
                        spawn_pool_account_sync(self.network.clone(), account, info, cached)
                    })
                    .collect();
                return (Task::batch(tasks), None);
            }
            Message::PoolSynced {
                pool,
                chain,
                result,
            } => {
                match result {
                    Ok((state, notes)) => {
                        // The account labels for the ASP approval check, captured
                        // before `state` is handed to the pane.
                        let labels: Vec<privacy_pools::Field> =
                            state.accounts.iter().map(|a| a.label).collect();
                        self.apps.pool_pane().set_state(pool, state);
                        // Persist only when the cache actually changed (first
                        // scan, or new activity) — a routine re-open finds
                        // nothing new, so most syncs skip the encrypt+write.
                        let key = (chain.chain_id(), pool);
                        if self.pool_note_cache.get(&key) != Some(&notes) {
                            self.pool_note_cache.insert(key, notes.clone());
                            if let Some(cipher_key) = &self.pool_notes_key
                                && let Err(e) = crate::wallet::save_pp_notes(
                                    chain.chain_id(),
                                    pool,
                                    &notes,
                                    cipher_key,
                                )
                            {
                                warn!(%pool, error = %e, "privacy pools: persisting note cache failed");
                            }
                        }
                        // Once balances are shown, chase them with the per-account
                        // ASP approval status (opt-in feed only, and only for a
                        // pool the user actually holds notes in). Decoupled so a
                        // slow/down feed never delays the balance display.
                        if !labels.is_empty()
                            && let Some(asp_url) = self.apps.pool_pane().asp_url()
                            && let Some(scope) = self.pool_scopes.get(&pool).cloned()
                        {
                            return (
                                spawn_pool_approval(asp_url, chain.chain_id(), scope, pool, labels),
                                None,
                            );
                        }
                    }
                    Err(e) => warn!(%pool, error = %e, "privacy pools: pool account sync failed"),
                }
                return (Task::none(), None);
            }
            Message::PoolApproval { pool, result } => {
                match result {
                    Ok(approved) => self.apps.pool_pane().set_pool_approvals(pool, approved),
                    Err(e) => {
                        warn!(%pool, error = %e, "privacy pools: ASP approval-status fetch failed")
                    }
                }
                return (Task::none(), None);
            }
            Message::PoolQuoted { result } => {
                let pane = self.apps.pool_pane();
                match result {
                    Ok(q) => pane.set_quote(q),
                    Err(e) => {
                        warn!(error = %e, "privacy pools: relayer fee quote failed");
                        pane.set_error(Some(e));
                    }
                }
                return (Task::none(), None);
            }
            Message::PoolTargetResolved { seq, name, result } => {
                self.apps
                    .pool_pane()
                    .set_target_resolution(seq, name, result);
                return (Task::none(), None);
            }
            Message::PoolSubmitted {
                result,
                signer,
                kind,
            } => {
                // The signing task resolved — drop the "waiting for a signature"
                // overlay that was kept open across the whole sign + broadcast.
                // Relayed withdrawals carry no overlay, so this is a no-op there.
                self.sign_review = None;
                if let Some(s) = &signer {
                    self.install_reclaimed_signer(s);
                    // The parked EOA signer is back — clear the in-flight flag,
                    // exactly like `reclaim_order_signer` / `CowPlaced`. Without
                    // this the flag stays stuck `true` after the first pool sign
                    // (success, failure, or a rejected tx), and the next
                    // `dispatch_pool_sign` is wrongly blocked as "another signing
                    // op in progress". Relayed withdrawals carry `signer: None`
                    // and never parked, so they leave the flag untouched.
                    self.order_op_in_flight = false;
                }
                // A just-broadcast deposit is one leg, sent-and-forgotten (unlike
                // the ragequit/withdraw the pane can't reflect it until it mines).
                // Capture its hash before `result` is consumed so we can re-sync
                // once it lands — the immediate re-sync below scans a chain that
                // doesn't include it yet.
                let deposit_hash = matches!(kind, pool_app::PoolTxKind::Deposit)
                    .then(|| result.as_ref().ok().and_then(|h| h.clone()))
                    .flatten()
                    .and_then(|h| h.parse::<TxHash>().ok());
                // Which pool the just-dispatched deposit funded (set in
                // `dispatch_pool_sign`). Always taken so it can't leak into a
                // later op; used below to animate that exact card until it mines.
                let deposit_pool = self.pool_deposit_in_flight.take();
                let next = {
                    let pane = self.apps.pool_pane();
                    match result {
                        // Land on the durable success screen (tx hash + explorer
                        // link) and kick a background re-sync so balances are
                        // fresh whichever way the user leaves it.
                        Ok(tx) => pane.set_submitted(kind, tx),
                        Err(e) => {
                            error!(error = %e, "privacy pools: withdrawal/deposit submission failed");
                            // Leave the proving screen first (the relayed-withdraw
                            // path is still on it) so the error isn't shown under a
                            // still-animating "Generating the ZK proof" spinner.
                            pane.reset_to_overview();
                            pane.set_error(Some(e));
                            None
                        }
                    }
                };
                if let Some(o) = next {
                    // The chain the immediate re-sync targets (Chain is Copy),
                    // captured before `o` is consumed.
                    let sync_chain = match &o {
                        pool_app::Outcome::Sync(c) => Some(*c),
                        _ => None,
                    };
                    let (task, out) = self.handle_pool_outcome(o);
                    // For a deposit, chase that immediate (premature) re-sync with
                    // one gated on the deposit mining, so the new note + anonymity
                    // set show up automatically once it's on-chain.
                    if let (Some(hash), Some(chain)) = (deposit_hash, sync_chain) {
                        // Animate exactly this pool's card until that gated
                        // re-sync lands and clears the marker (`PoolResync`).
                        if let Some(pool) = deposit_pool {
                            self.apps.pool_pane().set_pool_depositing(pool, true);
                        }
                        return (
                            Task::batch([
                                task,
                                spawn_pool_wait_and_resync(
                                    self.network.clone(),
                                    chain,
                                    hash,
                                    deposit_pool,
                                ),
                            ]),
                            out,
                        );
                    }
                    return (task, out);
                }
                return (Task::none(), None);
            }
            Message::PoolRagequitReady { result } => {
                self.apps.pool_pane().reset_to_overview();
                match result {
                    Ok(sign) => return (self.open_pool_review(sign), None),
                    Err(e) => {
                        error!(error = %e, "privacy pools: ragequit proof failed");
                        self.apps.pool_pane().set_error(Some(e));
                        return (Task::none(), None);
                    }
                }
            }
            Message::PoolResync { chain, pool } => {
                // The deposit has mined — stop that pool's "depositing…"
                // animation, then re-discover + re-scan so its note + anonymity
                // set land. Safe under the success screen: sync only mutates
                // pool/account state, never `view` (see `set_submitted`).
                if let Some(pool) = pool {
                    self.apps.pool_pane().set_pool_depositing(pool, false);
                }
                return self.handle_pool_outcome(pool_app::Outcome::Sync(chain));
            }
            Message::CowStatus { uid, result } => {
                // A just-filled order's legs, captured so the borrow on
                // `tracked_orders` is dropped before we touch `self` again.
                let mut filled: Option<SwapFillRefresh> = None;
                if let Ok(resp) = result
                    && let Some(o) = self.tracked_orders.iter_mut().find(|o| o.uid == uid)
                {
                    let was_terminal = o.status.is_terminal();
                    o.apply_status(resp.status, resp.executed());
                    // A non-terminal → Fulfilled edge is the only point where the
                    // swapped balances become stale; once terminal the poll stops,
                    // so this fires at most once per order.
                    if !was_terminal && o.status == OrderStatus::Fulfilled {
                        // Sell leg: native ETH (None) for an EthFlow order — the
                        // user spent ETH, not an ERC-20 — else the token sold.
                        let sell_slot = if o.is_ethflow {
                            None
                        } else {
                            Some(o.sell_token)
                        };
                        let slots = vec![Some(o.buy_token), sell_slot];
                        let mut fetch = vec![DiscoveredToken {
                            symbol: o.buy_symbol.clone(),
                            name: o.buy_symbol.clone(),
                            address: o.buy_token,
                            decimals: o.buy_decimals,
                        }];
                        if let Some(addr) = sell_slot {
                            fetch.push(DiscoveredToken {
                                symbol: o.sell_symbol.clone(),
                                name: o.sell_symbol.clone(),
                                address: addr,
                                decimals: o.sell_decimals,
                            });
                        }
                        filled = Some(SwapFillRefresh {
                            chain: o.chain,
                            owner: o.owner,
                            slots,
                            fetch,
                        });
                    }
                }
                if let Some(r) = filled
                    && r.owner == self.display_address()
                {
                    // Refetch just the two assets the order touched rather than
                    // the whole portfolio — see `spawn_swap_token_refresh`.
                    return (
                        spawn_swap_token_refresh(
                            self.network.clone(),
                            r.owner,
                            r.chain,
                            r.slots,
                            r.fetch,
                        ),
                        None,
                    );
                }
            }
            Message::CowPollTick => {
                let tasks: Vec<Task<Message>> = self
                    .tracked_orders
                    .iter()
                    .filter(|o| !o.status.is_terminal())
                    .map(|o| spawn_cow_status(o.chain, o.uid.clone()))
                    .collect();
                if !tasks.is_empty() {
                    return (Task::batch(tasks), None);
                }
            }
            Message::CowAccountOrders {
                address,
                chain,
                result,
            } => {
                // Stale guard: a fetch landing after an account switch.
                if address != self.address {
                    return (Task::none(), None);
                }
                match result {
                    Ok(fetched) => {
                        for o in fetched {
                            match self.tracked_orders.iter_mut().find(|e| e.uid == o.uid) {
                                // Known order (incl. this session's): refresh its
                                // status/fill, keep the richer in-session metadata.
                                Some(existing) => existing.apply_status(o.status, o.executed),
                                // New (a past-session order): add it.
                                None => self.tracked_orders.push(o),
                            }
                        }
                    }
                    Err(e) => warn!(
                        chain = %chain.label(),
                        error = %e,
                        "cow: account orders fetch failed",
                    ),
                }
            }
            Message::SwapTokensRefetched {
                address,
                network,
                slots,
                result,
            } => {
                let tokens = match result {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(
                            chain_id = network.chain_id(),
                            error = %e,
                            "post-swap token refresh failed",
                        );
                        return (Task::none(), None);
                    }
                };
                // Keep this address's cache slot consistent so a later
                // switch-away-and-back reflects the post-swap balances. The
                // slot holds only `network`'s rows, so a slot match on
                // `contract` is enough. Done regardless of the live guards
                // below — it's still the right slot for that address.
                if let Ok(mut cache) = self.portfolio_cache.lock()
                    && let Some(slot) = cache.get_mut(&(address, network))
                {
                    slot.retain(|t| !slots.contains(&t.contract));
                    slot.extend(
                        tokens
                            .iter()
                            .filter(|t| t.chain == network && slots.contains(&t.contract))
                            .cloned(),
                    );
                    sort_portfolio_rows(slot);
                }
                // Same staleness/scope guards as `PortfolioFetched`: a fill that
                // lands after the user switched identity (or off this network)
                // must not pollute what's now on screen.
                if address != self.display_address() || !self.allowed_networks().contains(&network)
                {
                    return (Task::none(), None);
                }
                // Replace only the refreshed slots; every other row stays put.
                self.portfolio
                    .retain(|t| !(t.chain == network && slots.contains(&t.contract)));
                self.portfolio.extend(
                    tokens
                        .into_iter()
                        .filter(|t| t.chain == network && slots.contains(&t.contract)),
                );
                sort_portfolio_rows(&mut self.portfolio);
            }
            Message::OpenAccountDropdown => {
                self.modal = Modal::AccountDropdown(AccountDropdown::new());
            }
            Message::OpenTxDetails(idx) => {
                let Some(tx) = self.history.get(idx).cloned() else {
                    // History refreshed in the gap between view and click;
                    // silently ignore — the user will retry against the
                    // newer list.
                    return (Task::none(), None);
                };
                self.modal = Modal::TxDetails(TxDetailsPane::new(tx));
                self.chrome.open();
            }
            Message::TxDetails(child_msg) => {
                let Modal::TxDetails(p) = &mut self.modal else {
                    return (Task::none(), None);
                };
                let (task, outcome) = p.update(child_msg);
                let task = task.map(Message::TxDetails);
                match outcome {
                    Some(tx_details::Outcome::Closed) => {
                        self.chrome.start_close();
                        return (task, None);
                    }
                    Some(tx_details::Outcome::CopyText(s)) => {
                        let copy = self.arm_clipboard_clear(s);
                        return (Task::batch([task, copy]), None);
                    }
                    None => return (task, None),
                }
            }
            Message::AccountDropdown(child_msg) => {
                let Modal::AccountDropdown(d) = &mut self.modal else {
                    return (Task::none(), None);
                };
                let (task, outcome) = d.update(child_msg);
                let task = task.map(Message::AccountDropdown);
                match outcome {
                    Some(account_dropdown::Outcome::Switch(idx)) => {
                        self.modal = Modal::None;
                        // Switching to an EOA exits Safe mode in the
                        // same gesture.
                        let was_safe = self.active_safe.is_some();
                        self.active_safe = None;
                        if was_safe {
                            // Drop the Safe's history so the EOA's
                            // history lazy-loads on the next Activity
                            // visit instead of showing stale Safe
                            // txs. The pending queue is Safe-only, so
                            // clear it outright.
                            self.history.clear();
                            self.history_loaded = false;
                            self.history_errors = PerChain::default();
                            self.safe_pending.clear();
                            self.safe_pending_error = None;
                            self.safe_pending_loading = false;
                        }
                        if idx != self.active_index && idx < self.accounts.len() {
                            // Different account: the App rebuilds the
                            // dashboard and kicks the multi-chain
                            // portfolio fetch for the new EOA there.
                            return (task, Some(Outcome::Switch(idx)));
                        }
                        // Same underlying EOA — the App does NOT rebuild,
                        // so nothing else will refresh the portfolio. If
                        // we just left Safe mode, `self.portfolio` still
                        // holds the Safe's single-chain rows (a Base Safe
                        // fetches Base only via `allowed_chains`). Re-seed
                        // from the EOA's cache (now `display_address` is
                        // the EOA and every chain is back in scope) and
                        // refetch so all the EOA's chains repopulate.
                        if was_safe {
                            self.seed_portfolio_from_cache();
                            self.portfolio_loading = self.portfolio.is_empty();
                            let refresh = Task::batch([
                                self.refresh_verification_task(),
                                self.fetch_portfolio_task(),
                            ]);
                            return (Task::batch([task, refresh]), None);
                        }
                        return (task, None);
                    }
                    Some(account_dropdown::Outcome::SelectSafe(idx)) => {
                        self.modal = Modal::None;
                        if idx < self.safes.len() {
                            self.active_safe = Some(idx);
                            // Seed the Safe portfolio from cache if
                            // we've viewed it before; kick a fresh
                            // fetch either way so on-chain state
                            // catches up. History resets so the
                            // Activity tab lazy-loads for the Safe.
                            self.seed_portfolio_from_cache();
                            self.portfolio_loading = self.portfolio.is_empty();
                            self.history.clear();
                            self.history_loaded = false;
                            self.history_errors = PerChain::default();
                            // Reset the pending queue for the newly-active
                            // Safe — no cache, so show the loading line
                            // until the service answers. Loading only
                            // when the fetch actually launches, else the
                            // spinner would never clear.
                            self.safe_pending.clear();
                            self.safe_pending_error = None;
                            let pending = self.fetch_safe_pending_task();
                            self.safe_pending_loading = pending.is_some();
                            let refresh = Task::batch([
                                self.refresh_verification_task(),
                                self.fetch_portfolio_task(),
                                pending.unwrap_or_else(Task::none),
                            ]);
                            return (Task::batch([task, refresh]), None);
                        }
                        return (task, None);
                    }
                    Some(account_dropdown::Outcome::Add) => {
                        self.modal = Modal::None;
                        return (task, Some(Outcome::Add));
                    }
                    Some(account_dropdown::Outcome::Closed) => {
                        self.modal = Modal::None;
                        return (task, None);
                    }
                    None => return (task, None),
                }
            }
            Message::SafeSendBroadcastReturn(result) => {
                if let Modal::Send(p) = &mut self.modal {
                    let success = result.is_ok();
                    match &result {
                        Ok(hash) => info!(hash = %format!("{hash:#x}"), "safe-send broadcast ok"),
                        Err(e) => warn!(error = %e, "safe-send broadcast failed"),
                    }
                    let (task, _outcome) = p.update(send::Message::BroadcastDone(result));
                    let refresh = if success {
                        Task::batch([
                            self.refresh_verification_task(),
                            self.fetch_portfolio_task(),
                        ])
                    } else {
                        Task::none()
                    };
                    return (Task::batch([task.map(Message::Send), refresh]), None);
                }
            }
            Message::SafeSendProposeReturn(result) => {
                if let Modal::Send(p) = &mut self.modal {
                    let success = result.is_ok();
                    match &result {
                        Ok(()) => info!("safe-send propose ok"),
                        Err(e) => warn!(error = %e, "safe-send propose failed"),
                    }
                    let (task, _outcome) = p.update(send::Message::ProposeDone(result));
                    // On success refresh the pending queue so the new
                    // proposal shows up the moment the user closes.
                    let refresh = if success {
                        self.fetch_safe_pending_task().unwrap_or_else(Task::none)
                    } else {
                        Task::none()
                    };
                    return (Task::batch([task.map(Message::Send), refresh]), None);
                }
            }
            Message::OpenSafeTxDetails(idx) => {
                let Some(pending) = self.safe_pending.get(idx).cloned() else {
                    // Queue refreshed between view and click — ignore.
                    return (Task::none(), None);
                };
                let Some(safe) = self.active_safe_descriptor() else {
                    return (Task::none(), None);
                };
                let Some(chain) = crate::chain::Chain::from_chain_id(safe.chain_id) else {
                    return (Task::none(), None);
                };
                let safe_addr = safe.address();
                let threshold = safe.threshold;
                let version = safe.version.clone();
                let trust = safe.trust.clone();
                let service_base = safe.tx_service_base().to_string();
                let owners: Vec<Address> = safe.owners.iter().map(|o| Address::from(*o)).collect();
                let signable: Vec<Address> = self
                    .safe_signable_owners(safe)
                    .into_iter()
                    .map(|(a, _)| a)
                    .collect();
                let has_local_executor = self.first_local_key().is_some();
                let hash = pending.safe_tx_hash;
                self.modal = Modal::SafeTxDetail(Box::new(SafeTxDetailPane::new(
                    safe_addr,
                    chain,
                    version,
                    trust,
                    service_base.clone(),
                    pending,
                    owners,
                    signable,
                    has_local_executor,
                )));
                self.chrome.open();
                return (
                    spawn_safe_detail_load_task(
                        self.network.clone(),
                        service_base,
                        safe_addr,
                        chain,
                        hash,
                        threshold,
                        /* delayed */ false,
                    ),
                    None,
                );
            }
            Message::SafeTxDetailLoaded(result) => {
                // Scope the modal borrow before calling the spawn
                // helper (which re-borrows immutably). Only the loaded
                // `detail.tx` is the authoritative SafeTx, so sims are
                // spawned here — post-action reloads re-run them for
                // free.
                {
                    let Modal::SafeTxDetail(p) = &mut self.modal else {
                        return (Task::none(), None);
                    };
                    // Staleness guard: the delayed post-action reload
                    // can land after the user opened a *different*
                    // queued tx — only apply a payload describing the
                    // tx this modal is showing.
                    if let Ok(d) = &result
                        && d.safe_tx_hash != p.safe_tx_hash()
                    {
                        return (Task::none(), None);
                    }
                    p.set_detail(result);
                }
                return (
                    self.safe_detail_sim_tasks(true, true, /* delayed */ false),
                    None,
                );
            }
            Message::SafeTxInnerSimLoaded {
                safe_tx_hash,
                result,
            } => {
                let auto = if let Modal::SafeTxDetail(p) = &mut self.modal
                    && p.safe_tx_hash() == safe_tx_hash
                {
                    p.set_inner_sim(result)
                } else {
                    false
                };
                // Succeeded on fallback state → one automatic re-run
                // once the helios cooldown has passed.
                if auto {
                    return (
                        self.safe_detail_sim_tasks(true, false, /* delayed */ true),
                        None,
                    );
                }
            }
            Message::SafeTxExecSimLoaded {
                safe_tx_hash,
                result,
            } => {
                let auto = if let Modal::SafeTxDetail(p) = &mut self.modal
                    && p.safe_tx_hash() == safe_tx_hash
                {
                    p.set_exec_sim(result)
                } else {
                    false
                };
                if auto {
                    return (
                        self.safe_detail_sim_tasks(false, true, /* delayed */ true),
                        None,
                    );
                }
            }
            Message::SafeTxActionDone(result) => {
                let Modal::SafeTxDetail(p) = &mut self.modal else {
                    return (Task::none(), None);
                };
                let ok = result.is_ok();
                match &result {
                    Ok(msg) => info!(msg, "safe-tx action ok"),
                    Err(e) => warn!(error = %e, "safe-tx action failed"),
                }
                let (safe, chain, hash, service_base) = (
                    p.safe(),
                    p.chain(),
                    p.safe_tx_hash(),
                    p.service_base().to_string(),
                );
                p.set_action_result(result);
                if !ok {
                    return (Task::none(), None);
                }
                // Reload the queue and this tx's detail so the FSM badge
                // and owner checklist reflect the new state. Twice: once
                // immediately (confirm/reject land in the service
                // synchronously) and once after a delay — an *execution*
                // only shows up after the service indexes the mined tx,
                // so the immediate reload returns the stale state and
                // the pane bridges the gap with its optimistic
                // "Execution submitted" presentation.
                let threshold = self
                    .active_safe_descriptor()
                    .map(|s| s.threshold)
                    .unwrap_or(0);
                let reload = spawn_safe_detail_load_task(
                    self.network.clone(),
                    service_base.clone(),
                    safe,
                    chain,
                    hash,
                    threshold,
                    /* delayed */ false,
                );
                let delayed_reload = spawn_safe_detail_load_task(
                    self.network.clone(),
                    service_base,
                    safe,
                    chain,
                    hash,
                    threshold,
                    /* delayed */ true,
                );
                let refresh = self.fetch_safe_pending_task().unwrap_or_else(Task::none);
                return (Task::batch([reload, delayed_reload, refresh]), None);
            }
            Message::SafeTxDetail(child) => {
                // Pump the child with a scoped &mut borrow so the rest of
                // the arm can call `self` helpers (owner lookup) without
                // overlapping the pane's borrow.
                let (task, outcome) = {
                    let Modal::SafeTxDetail(p) = &mut self.modal else {
                        return (Task::none(), None);
                    };
                    let (t, o) = p.update(child);
                    (t.map(Message::SafeTxDetail), o)
                };
                match outcome {
                    Some(safe_tx_detail::Outcome::Closed) => {
                        self.chrome.start_close();
                        return (task, None);
                    }
                    Some(safe_tx_detail::Outcome::Confirm) => {
                        // Sign with the first linked owner that hasn't
                        // signed yet, then POST the confirmation.
                        let prep = if let Modal::SafeTxDetail(p) = &self.modal {
                            p.loaded_detail().map(|d| {
                                (
                                    d.tx.clone(),
                                    d.safe_tx_hash,
                                    p.unsigned_signable().first().copied(),
                                    p.safe(),
                                    p.chain(),
                                    p.version().to_string(),
                                    p.service_base().to_string(),
                                )
                            })
                        } else {
                            None
                        };
                        let Some((tx, hash, owner, safe, chain, version, service_base)) = prep
                        else {
                            return (task, None);
                        };
                        if let Some(e) = self.active_safe_signing_block(safe, chain) {
                            self.mark_safe_detail_busy();
                            self.set_safe_detail_result(Err(e));
                            return (task, None);
                        }
                        // Version gate before any signer is built: a
                        // pre-1.3 (or unknown-shape) domain must refuse
                        // with the explainable error, not a late
                        // on-chain mismatch.
                        if let Err(e) = crate::safe::tx::ensure_signable_version(&version) {
                            self.mark_safe_detail_busy();
                            self.set_safe_detail_result(Err(e));
                            return (task, None);
                        }
                        let owner_desc = owner.and_then(|a| self.owner_desc_for(a));
                        self.mark_safe_detail_busy();
                        let Some(owner_desc) = owner_desc else {
                            self.set_safe_detail_result(Err(
                                "no linked owner left to sign with".to_string()
                            ));
                            return (task, None);
                        };
                        let confirm = spawn_safe_confirm_task(
                            self.network.clone(),
                            service_base,
                            owner_desc,
                            safe,
                            chain,
                            tx,
                            hash,
                        );
                        return (Task::batch([task, confirm]), None);
                    }
                    Some(safe_tx_detail::Outcome::Execute) => {
                        let prep = if let Modal::SafeTxDetail(p) = &self.modal {
                            p.loaded_detail().map(|d| {
                                let confs: Vec<(Address, Bytes)> = d
                                    .confirmations
                                    .iter()
                                    .map(|c| (c.owner, c.signature.clone()))
                                    .collect();
                                (d.tx.clone(), confs, p.safe(), p.chain())
                            })
                        } else {
                            None
                        };
                        let Some((tx, confirmations, safe, chain)) = prep else {
                            return (task, None);
                        };
                        if let Some(e) = self.active_safe_signing_block(safe, chain) {
                            self.mark_safe_detail_busy();
                            self.set_safe_detail_result(Err(e));
                            return (task, None);
                        }
                        let executor_key = self.first_local_key();
                        self.mark_safe_detail_busy();
                        let Some(executor_key) = executor_key else {
                            self.set_safe_detail_result(Err(
                                "need a Local account to pay gas for execution".to_string(),
                            ));
                            return (task, None);
                        };
                        let exec = spawn_safe_execute_task(
                            self.network.clone(),
                            executor_key,
                            safe,
                            chain,
                            tx,
                            confirmations,
                        );
                        return (Task::batch([task, exec]), None);
                    }
                    Some(safe_tx_detail::Outcome::Reject) => {
                        let prep = if let Modal::SafeTxDetail(p) = &self.modal {
                            Some((
                                p.safe(),
                                p.chain(),
                                p.nonce(),
                                p.signable_owner(),
                                p.version().to_string(),
                                p.service_base().to_string(),
                            ))
                        } else {
                            None
                        };
                        let Some((safe, chain, nonce, owner, version, service_base)) = prep else {
                            return (task, None);
                        };
                        if let Some(e) = self.active_safe_signing_block(safe, chain) {
                            self.mark_safe_detail_busy();
                            self.set_safe_detail_result(Err(e));
                            return (task, None);
                        }
                        // Same version gate as Confirm — a rejection is
                        // a SafeTx signature too.
                        if let Err(e) = crate::safe::tx::ensure_signable_version(&version) {
                            self.mark_safe_detail_busy();
                            self.set_safe_detail_result(Err(e));
                            return (task, None);
                        }
                        let owner_desc = owner.and_then(|a| self.owner_desc_for(a));
                        self.mark_safe_detail_busy();
                        let Some(owner_desc) = owner_desc else {
                            self.set_safe_detail_result(Err(
                                "no linked owner available to reject".to_string()
                            ));
                            return (task, None);
                        };
                        let reject = spawn_safe_reject_task(
                            self.network.clone(),
                            service_base,
                            owner_desc,
                            safe,
                            chain,
                            nonce,
                        );
                        return (Task::batch([task, reject]), None);
                    }
                    Some(safe_tx_detail::Outcome::RetrySims) => {
                        // The pane already cleared its sim state; just
                        // re-spawn both tasks immediately.
                        return (
                            Task::batch([
                                task,
                                self.safe_detail_sim_tasks(true, true, /* delayed */ false),
                            ]),
                            None,
                        );
                    }
                    None => return (task, None),
                }
            }
            Message::Tick => {
                if self.chrome.tick_settled() {
                    self.modal = Modal::None;
                }
            }
            Message::OpenNetworksSettings => {
                self.settings_pane =
                    SettingsPane::NetworkWizard(NetworkSetupScreen::new(WizardMode::Settings));
            }
            Message::OpenSafesSettings => {
                self.settings_pane = SettingsPane::Safes(SafesPane::new(self.safes.clone()));
            }
            Message::SafesSettings(child_msg) => {
                let SettingsPane::Safes(p) = &mut self.settings_pane else {
                    return (Task::none(), None);
                };
                let (task, outcome) = p.update(child_msg);
                let task = task.map(Message::SafesSettings);
                match outcome {
                    Some(safes_settings::Outcome::Closed) => {
                        self.settings_pane = SettingsPane::Root;
                        return (task, None);
                    }
                    Some(safes_settings::Outcome::SetServiceUrl { index, url }) => {
                        // Bubble to the App, which owns the wallet and
                        // the disk write; it pushes the updated list
                        // back via `SafesUpdated` (reseeding the pane).
                        return (task, Some(Outcome::SetSafeServiceUrl { index, url }));
                    }
                    None => return (task, None),
                }
            }
            Message::OpenAppearanceSettings => {
                self.settings_pane = SettingsPane::Appearance;
            }
            Message::CloseAppearanceSettings => {
                self.settings_pane = SettingsPane::Root;
            }
            Message::OpenContactsSettings => {
                self.settings_pane =
                    SettingsPane::Contacts(ContactsPane::new(self.contacts.clone()));
            }
            Message::OpenContactsPaneWith { address, ens } => {
                // From the Send pane's "Save as contact" CTA. Switch
                // the nav to Settings, close the Send modal (the chrome
                // animation drives the swap), and open the contacts
                // pane in Add mode pre-filled.
                self.nav = Nav::Settings;
                self.settings_pane = SettingsPane::Contacts(ContactsPane::new_with_prefill(
                    self.contacts.clone(),
                    address,
                    ens,
                ));
                self.chrome.start_close();
                // Drop the user straight onto the NAME input — they
                // came here to type one.
                return (
                    ContactsPane::focus_initial_task().map(Message::Contacts),
                    None,
                );
            }
            Message::Contacts(child_msg) => {
                let SettingsPane::Contacts(p) = &mut self.settings_pane else {
                    return (Task::none(), None);
                };
                let (task, outcome) = p.update(child_msg);
                // Same dispatch pattern as the Send pane: after pumping
                // the pane we ask if it has a fresh ENS-shaped input
                // that hasn't been resolved yet, and spawn a task tagged
                // with the pane's seq so stale results are dropped.
                let ens_task = match p.take_pending_ens() {
                    Some((seq, name)) => {
                        spawn_contacts_ens_resolve_task(self.network.clone(), seq, name)
                    }
                    None => Task::none(),
                };
                let task = task.map(Message::Contacts);
                match outcome {
                    Some(contacts_settings::Outcome::Closed) => {
                        self.settings_pane = SettingsPane::Root;
                        return (Task::batch([task, ens_task]), None);
                    }
                    Some(contacts_settings::Outcome::SaveRequested(vec)) => {
                        return (
                            Task::batch([task, ens_task]),
                            Some(Outcome::SaveContacts(vec)),
                        );
                    }
                    None => return (Task::batch([task, ens_task]), None),
                }
            }
            Message::BeginRenameAccount => {
                let current = self
                    .accounts
                    .get(self.active_index)
                    .map(|a| a.name().unwrap_or("").to_string())
                    .unwrap_or_default();
                self.rename_draft = Some(current);
                return (focus_widget(header::RENAME_INPUT_ID), None);
            }
            Message::RenameInput(s) => {
                if self.rename_draft.is_some() {
                    self.rename_draft = Some(s);
                }
            }
            Message::CommitRename => {
                let Some(draft) = self.rename_draft.take() else {
                    return (Task::none(), None);
                };
                // Match `AccountDescriptor::set_name`'s trim-and-collapse rule
                // so the in-memory copy and the persisted copy agree on what
                // counts as "no name set".
                let trimmed = draft.trim();
                let cleaned = if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                };
                if let Some(acc) = self.accounts.get_mut(self.active_index) {
                    acc.set_name(cleaned.clone());
                }
                return (Task::none(), Some(Outcome::RenameActive(cleaned)));
            }
            Message::CancelRename => {
                self.rename_draft = None;
            }
            Message::Networks(_child_msg) => {
                // Legacy Networks pane — routing removed; wizard handles
                // network configuration now.
            }
            Message::NetworkWizard(child_msg) => {
                let SettingsPane::NetworkWizard(p) = &mut self.settings_pane else {
                    return (Task::none(), None);
                };
                let (task, outcome) = p.update(child_msg);
                let task = task.map(Message::NetworkWizard);
                match outcome {
                    Some(network_setup::Outcome::Completed)
                    | Some(network_setup::Outcome::Closed)
                    | Some(network_setup::Outcome::Back) => {
                        self.settings_pane = SettingsPane::Root;
                        // The wizard may have changed RPC endpoints and/or
                        // added, edited, toggled, or removed custom networks.
                        // The network client rebuilds lazily from settings and
                        // custom providers are built per-fetch, so a portfolio
                        // refresh is all that's needed to reflect the new
                        // config (e.g. a freshly-added custom network appears).
                        return (
                            Task::batch([task, Task::done(Message::RefreshPortfolio)]),
                            None,
                        );
                    }
                    None => return (task, None),
                }
            }
        }
        (Task::none(), None)
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let mut subs: Vec<Subscription<Message>> = Vec::new();
        // The clear-signing overlay owns the keyboard while it's open (Esc =
        // Cancel) and suppresses the layers beneath it, so Esc can't
        // simultaneously close the modal/step back in the Apps pane underneath.
        if self.sign_review.is_some() {
            subs.push(
                iced::keyboard::listen().map(|e| Message::SignReview(sign_review::Message::Key(e))),
            );
            if self.chrome.is_animating()
                || self.clipboard_clear.is_some()
                || copy_toast_progress().is_some()
                || self
                    .sign_review
                    .as_ref()
                    .is_some_and(|r| r.signing_since.is_some())
            {
                subs.push(iced::time::every(Duration::from_millis(16)).map(|_| Message::Tick));
            }
            if self.tracked_orders.iter().any(|o| !o.status.is_terminal()) {
                subs.push(iced::time::every(Duration::from_secs(10)).map(|_| Message::CowPollTick));
            }
            return Subscription::batch(subs);
        }
        match &self.modal {
            Modal::AccountDropdown(d) => {
                subs.push(d.subscription().map(Message::AccountDropdown));
            }
            Modal::Swap(p) => {
                subs.push(p.subscription().map(Message::Swap));
            }
            Modal::Receive(p) => {
                subs.push(p.subscription().map(Message::Receive));
            }
            Modal::Send(p) => {
                subs.push(p.subscription().map(Message::Send));
            }
            Modal::TxDetails(p) => {
                subs.push(p.subscription().map(Message::TxDetails));
            }
            Modal::SafeTxDetail(p) => {
                subs.push(p.subscription().map(Message::SafeTxDetail));
            }
            Modal::None => {}
        }
        match &self.settings_pane {
            SettingsPane::NetworkWizard(p) => {
                subs.push(p.subscription().map(Message::NetworkWizard))
            }
            SettingsPane::Contacts(p) => subs.push(p.subscription().map(Message::Contacts)),
            _ => {}
        }
        // Apps tab with no modal over it: let the pane listen for Esc so the
        // Swap app can step back to its launcher. Gated on `Modal::None` so an
        // open modal keeps Esc for closing itself (never both at once).
        if matches!(self.modal, Modal::None) && matches!(self.nav, Nav::Apps) {
            subs.push(self.apps.subscription().map(Message::Apps));
        }
        if self.chrome.is_animating()
            || self.clipboard_clear.is_some()
            || copy_toast_progress().is_some()
        {
            // `time::every` actively drives ticks (and therefore redraws)
            // on a timer; `window::frames()` only observes redraws the
            // runtime already decided to do, which left the animation idle
            // between unrelated events. 16 ms (~60 Hz) is plenty for the
            // 220 ms ease — going faster just burns CPU during the modal
            // open/close transition. The clipboard countdown chip and the
            // transient "Copied!" toast ride the same subscription so they
            // animate and dismiss smoothly. The toast's window is started by
            // the address widget's `copy_kick` message (which re-runs `update`
            // and thus re-evaluates this subscription); the tick then drives
            // the fade until `copy_toast_progress` returns `None`.
            subs.push(iced::time::every(Duration::from_millis(16)).map(|_| Message::Tick));
        }
        // Poll open CoW orders every 10s while any is non-terminal. This is the
        // only background network activity in the swap feature, and it exists
        // only because the user explicitly placed an order — nothing polls
        // before that.
        if self.tracked_orders.iter().any(|o| !o.status.is_terminal()) {
            subs.push(iced::time::every(Duration::from_secs(10)).map(|_| Message::CowPollTick));
        }
        Subscription::batch(subs)
    }

    fn theme(&self) -> KaoTheme {
        KaoTheme::for_kind(self.theme_kind)
    }

    // ── View ────────────────────────────────────────────────────────────────

    pub fn view(&self) -> Element<'_, Message> {
        let t = self.theme();

        let sidebar = sidebar::view(
            t,
            self.nav,
            self.active_index,
            self.display_name(),
            self.display_address(),
            self.active_safe.is_some(),
            self.apps_available(),
            self.hardware_status(),
            self.network_short_name(),
            self.verification,
        );
        let app = row![sidebar, self.main_pane(t)]
            .width(Length::Fill)
            .height(Length::Fill);

        let background: Element<'_, Message> = container(app)
            .style(move |_| fill_style(t.bg))
            .width(Length::Fill)
            .height(Length::Fill)
            .into();

        // Snapshot the contacts book to an owned `ContactsView` for
        // any modal/pane that wants borrow-free contact data. iced
        // views are synchronous so the lock is uncontested; this
        // sidesteps the lifetime issue of holding a read guard across
        // Always render the same `stack![background, modal_layer]` tree
        // shape so iced doesn't reset child widget state when a modal
        // opens or closes. Without this, opening a modal changes the
        // tree from `Container` to `Stack(Container, Modal)`, and the
        // activity feed's scroll position (and any other internal
        // widget state below) snaps back to its default.
        let modal_layer: Element<'_, Message> = match &self.modal {
            Modal::None => Space::new().width(0).height(0).into(),
            Modal::Send(p) => {
                // Mode-aware picker: EOA excludes the active account;
                // Safe excludes the active Safe but keeps all EOAs
                // visible (withdraw-to-signer is a common flow).
                let picker = if p.is_safe() {
                    self.recipient_picker(None, self.active_safe)
                } else {
                    self.recipient_picker(Some(self.active_index), None)
                };
                p.view(t, &self.portfolio, picker, self.chrome.progress())
                    .map(Message::Send)
            }
            Modal::Receive(p) => p.view(t, self.chrome.progress()).map(Message::Receive),
            Modal::Swap(p) => {
                let tracked = p
                    .tracking_uid()
                    .and_then(|uid| self.tracked_orders.iter().find(|o| o.uid == uid));
                p.view(t, &self.portfolio, tracked, self.chrome.progress())
                    .map(Message::Swap)
            }
            Modal::AccountDropdown(d) => d
                .view(
                    t,
                    &self.accounts,
                    &self.safes,
                    self.active_index,
                    self.active_safe,
                )
                .map(Message::AccountDropdown),
            Modal::TxDetails(p) => {
                let tx_book = match self.contacts.read() {
                    Ok(g) => g.clone(),
                    Err(_) => ContactsBook::new(),
                };
                p.view(t, self.chrome.progress(), &tx_book)
                    .map(Message::TxDetails)
            }
            Modal::SafeTxDetail(p) => p
                .view(t, &self.portfolio, self.chrome.progress())
                .map(Message::SafeTxDetail),
        };
        // Clear-signing review overlay — the top-most app layer, drawn over
        // whatever modal/pane is active (Swap modal, Apps composer, or Names
        // pane) so the same gate serves them all without any of them losing
        // their own state when the user cancels. Constant tree shape (empty
        // `Space` when no review is pending), like the modal/chip layers below.
        let sign_review_layer: Element<'_, Message> = match &self.sign_review {
            None => Space::new().width(0).height(0).into(),
            // Fully opaque (progress 1.0): the overlay can sit over the Apps
            // pane where there's no modal-chrome animation to ride, so it just
            // appears rather than fading with the modal layer beneath it.
            Some(review) => sign_review::view(t, review, 1.0).map(Message::SignReview),
        };
        let composed: Element<'_, Message> =
            stack![background, modal_layer, sign_review_layer].into();

        // Bottom-right clipboard auto-clear chip rides on top of
        // whatever modal layer is currently visible. The chip is a
        // pointer-event sink only over its own card area; the rest of
        // the overlay is `Space`, so clicks on the screen below pass
        // through to the active modal/dashboard.
        //
        // Keep the tree shape constant — `stack![composed, chip_layer]`
        // whether or not a chip is showing (an empty `Space` stands in when
        // it isn't), for the same reason the modal layer above does: if the
        // root flips between `composed` and a 2-child stack, iced treats it
        // as a different widget and resets all state below — notably the
        // Apps/Activity scroll offset would jump back to the top the moment
        // a copy armed the chip.
        let chip_layer: Element<'_, Message> = match &self.clipboard_clear {
            None => Space::new().width(0).height(0).into(),
            Some(state) => clipboard_clear_chip(t, state),
        };
        // Transient bottom-right "Copied!" toast, shown briefly after an address
        // is click-copied. Top-most layer (above the clipboard chip and any
        // sign-review overlay) and a constant `Space` placeholder otherwise, so
        // the tree shape stays stable (same reasoning as the chip layer).
        let copied_layer: Element<'_, Message> = match copy_toast_progress() {
            Some(progress) => copied_toast(t, progress),
            None => Space::new().width(0).height(0).into(),
        };
        stack![composed, chip_layer, copied_layer].into()
    }

    // ── Send-flow helpers used by the broadcast Tasks ──────────────────────

    /// Build the merged recipient picker view for the Send /
    /// SafeSend modals. Combines saved contacts with the user's own
    /// accounts and Safes, dropping the active sender so the user
    /// doesn't see themselves as a destination. Lock-poisoned books
    /// degrade to the merged-without-contacts variant so own-account
    /// picking still works.
    fn recipient_picker(
        &self,
        exclude_account: Option<usize>,
        exclude_safe: Option<usize>,
    ) -> send::ContactsView {
        let empty = ContactsBook::new();
        match self.contacts.read() {
            Ok(g) => send::ContactsView::merged(
                &g,
                &self.accounts,
                &self.safes,
                exclude_account,
                exclude_safe,
            ),
            Err(_) => send::ContactsView::merged(
                &empty,
                &self.accounts,
                &self.safes,
                exclude_account,
                exclude_safe,
            ),
        }
    }

    // ── Main pane (header + body) ──────────────────────────────────────────

    fn main_pane<'a>(&'a self, t: KaoTheme) -> Element<'a, Message> {
        // Hold the read guard for the duration of `main_pane`. iced
        // views are synchronous and the lock is uncontested, so the
        // guard's lifetime safely outlives the returned Element.
        let contacts_guard = self.contacts.read().ok();
        let empty_book = ContactsBook::new();
        let contacts: &ContactsBook = match &contacts_guard {
            Some(g) => g,
            None => &empty_book,
        };
        // If Apps got hidden (switched to a view-only/Safe identity while on it),
        // fall back to the portfolio so the pane is never blank. Uses
        // `apps_available()` (not `can_swap()`) so an in-flight place/cancel —
        // which momentarily parks the signer — doesn't bounce the user off the
        // Apps pane and back mid-order.
        let active_nav = if matches!(self.nav, Nav::Apps) && !self.apps_available() {
            Nav::Home
        } else {
            self.nav
        };
        let body: Element<'_, Message> = match active_nav {
            Nav::Home => home::view(
                t,
                self.can_send(),
                self.can_swap(),
                &self.portfolio,
                self.portfolio_loading,
                self.portfolio_refreshing,
                &self.safe_pending,
                self.safe_pending_loading,
                self.safe_pending_error.as_deref(),
            ),
            Nav::Apps => {
                // Scoped to the active identity (the Safe in Safe mode, else the
                // EOA) so a switch never shows another identity's orders and a
                // Safe's EIP-1271 orders surface in Safe mode. Names is hidden
                // for Safes — it operates on the active EOA, not the Safe.
                let orders = self.active_cow_orders();
                let names_available = self.names_available_for_active();
                // The Privacy Pools withdrawal picker lists saved contacts plus
                // the wallet's own Kao accounts and Safes. Built from the
                // already-held guard rather than re-locking.
                let pool_recipients =
                    send::ContactsView::merged(contacts, &self.accounts, &self.safes, None, None);
                self.apps
                    .view(
                        t,
                        &self.portfolio,
                        &orders,
                        names_available,
                        pool_recipients,
                    )
                    .map(Message::Apps)
            }
            Nav::Activity => {
                // Show the error placeholder only when every configured
                // chain failed *and* nothing rendered. Otherwise partial
                // successes carry the feed even with one source down.
                let any_err = crate::chain::Chain::ALL
                    .iter()
                    .any(|c| self.history_errors.get(*c).is_some());
                let merged_error: Option<&str> = if any_err && self.history.is_empty() {
                    crate::chain::Chain::ALL
                        .iter()
                        .find_map(|c| self.history_errors.get(*c).as_deref())
                } else {
                    None
                };
                activity::view(
                    t,
                    self.display_address(),
                    &self.history,
                    self.history_loading,
                    merged_error,
                    contacts,
                )
            }
            Nav::Settings => match &self.settings_pane {
                SettingsPane::Root => settings_root::view(t),
                SettingsPane::NetworkWizard(p) => p.view().map(Message::NetworkWizard),
                SettingsPane::Safes(p) => p.view(t).map(Message::SafesSettings),
                SettingsPane::Appearance => appearance::view(t, self.theme_kind),
                SettingsPane::Contacts(p) => p.view(t).map(Message::Contacts),
            },
        };

        column![
            header::view(
                t,
                self.verification,
                self.display_name(),
                self.rename_draft.as_deref(),
                self.active_safe.is_some(),
            ),
            body
        ]
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }
}

// ── "Copied!" toast ─────────────────────────────────────────────────────────

/// Small bottom-right "✓ Copied!" pill shown briefly after an address is
/// click-copied (see [`crate::ui::kao_widgets::copy_toast_progress`]). `progress`
/// runs 0→1 across the toast window; it fades in, holds, then fades out.
fn copied_toast<'a>(t: KaoTheme, progress: f32) -> Element<'a, Message> {
    // Quick fade-in over the first 12%, hold, fade-out over the final 30%.
    let alpha = if progress < 0.12 {
        progress / 0.12
    } else if progress > 0.70 {
        ((1.0 - progress) / 0.30).max(0.0)
    } else {
        1.0
    };

    let card = container(
        row![
            text("✓").size(12).color(with_alpha(t.up, alpha)),
            Space::new().width(6),
            text("Copied!")
                .size(12)
                .color(with_alpha(t.text, alpha))
                .font(bold()),
        ]
        .align_y(Alignment::Center),
    )
    .padding(Padding::from([8, 14]))
    .style(move |_| container::Style {
        background: Some(Background::Color(with_alpha(t.card_alt, alpha))),
        border: Border {
            color: with_alpha(t.up, 0.4 * alpha),
            width: 1.0,
            radius: Radius::from(10),
        },
        text_color: Some(with_alpha(t.text, alpha)),
        ..container::Style::default()
    });

    // Pin to bottom-right, matching the clipboard chip's 16 px insets.
    let bottom_row = row![
        Space::new().width(Length::Fill),
        card,
        Space::new().width(16),
    ]
    .width(Length::Fill);
    column![
        Space::new().height(Length::Fill),
        bottom_row,
        Space::new().height(16),
    ]
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

// ── Clipboard auto-clear chip ──────────────────────────────────────────────

/// Bottom-right chip rendered while the clipboard auto-clear is armed.
/// Two stacked rows: the countdown text on top, a thin progress bar
/// below. The bar drains as time elapses; when the bar reaches zero
/// the `ClipboardClearArmed` task fires, the ownership check runs, and
/// the clipboard is cleared if its contents still match what we wrote.
fn clipboard_clear_chip<'a>(t: KaoTheme, state: &'a ClipboardClearState) -> Element<'a, Message> {
    let now = Instant::now();
    let total = Duration::from_secs(CLIPBOARD_CLEAR_SECS);
    let remaining = state.deadline.saturating_duration_since(now);
    // `as_secs()` truncates; the +1 unless exactly on a second boundary
    // means the user reads "10…" the moment the chip lands and
    // counts down through "1…" for the final second instead of seeing
    // a flash of "0…" before the chip disappears.
    let secs_label = remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0);
    let fraction = (remaining.as_secs_f32() / total.as_secs_f32()).clamp(0.0, 1.0);

    // Custom progress bar built from two fixed-width inner containers
    // in a row so we can theme it without leaning on the iced default.
    // 160 px is wide enough to read at-a-glance and narrow enough that
    // the chip stays compact on small windows.
    const BAR_WIDTH: f32 = 160.0;
    const BAR_HEIGHT: f32 = 4.0;
    let filled_px = BAR_WIDTH * fraction;
    let rest_px = BAR_WIDTH - filled_px;
    let filled = container(Space::new())
        .width(Length::Fixed(filled_px))
        .height(Length::Fixed(BAR_HEIGHT))
        .style(move |_| container::Style {
            background: Some(Background::Color(t.a1)),
            border: Border {
                color: iced::Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(2),
            },
            ..container::Style::default()
        });
    let rest = container(Space::new())
        .width(Length::Fixed(rest_px))
        .height(Length::Fixed(BAR_HEIGHT))
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(t.border, 0.6))),
            border: Border {
                color: iced::Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(2),
            },
            ..container::Style::default()
        });
    let bar = row![filled, rest]
        .width(Length::Fixed(BAR_WIDTH))
        .align_y(Alignment::Center);

    let label = text(format!("autoclear in {secs_label}…"))
        .size(11)
        .color(t.sub)
        .font(mono());

    let card = container(
        column![
            row![text("📋").size(11), Space::new().width(6), label].align_y(Alignment::Center),
            Space::new().height(6),
            bar,
        ]
        .width(Length::Shrink),
    )
    .padding(Padding::from([8, 12]))
    .style(move |_| container::Style {
        background: Some(Background::Color(t.card_alt)),
        border: Border {
            color: with_alpha(t.border, 0.7),
            width: 1.0,
            radius: Radius::from(10),
        },
        text_color: Some(t.text),
        ..container::Style::default()
    });

    // Pin to bottom-right: column[Space::Fill, row[Space::Fill, card]]
    // with 16 px of breathing room on the right and bottom edges.
    let bottom_row = row![
        Space::new().width(Length::Fill),
        card,
        Space::new().width(16),
    ]
    .width(Length::Fill);
    column![
        Space::new().height(Length::Fill),
        bottom_row,
        Space::new().height(16),
    ]
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

// ── Send-flow helpers ──────────────────────────────────────────────────────

/// Format the largest amount the user can send for `tk`. For native ETH, if
/// the pane already has a quote loaded we subtract the gas cost so the
/// transaction won't bounce on insufficient-funds at broadcast time.
fn compute_max_amount(tk: &LiveToken, p: &SendPane) -> String {
    use alloy::primitives::utils::format_units;
    let raw = tk.balance_raw;
    let max_raw = if tk.contract.is_none() {
        // Native ETH: leave room for gas if we already have a quote.
        match p.quote() {
            Some(q) if raw > q.eth_cost_wei => raw - q.eth_cost_wei,
            _ => raw,
        }
    } else {
        raw
    };
    let raw_str =
        format_units(max_raw, tk.decimals).unwrap_or_else(|_| tk.balance.replace(',', ""));
    trim_trailing_decimal_zeros(&raw_str)
}

/// Strip trailing zeros (and the dangling decimal point) from a decimal
/// string. `format_units` always pads to `decimals` fractional digits, so
/// "1.000000000000000000" comes back from a 1 ETH balance — pumping that
/// into the amount input shows the user a wall of zeros after the value
/// they actually care about.
fn trim_trailing_decimal_zeros(s: &str) -> String {
    if !s.contains('.') {
        return s.to_string();
    }
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() {
        "0".into()
    } else {
        trimmed.to_string()
    }
}

/// Spawn a forward ENS resolution task for the Send recipient input.
/// Returns a `Task` that resolves to a `Send::EnsResolved(...)` message
/// tagged with `seq` so the pane can drop stale lookups.
fn spawn_ens_resolve_task(
    network: Arc<dyn BalanceFetcher>,
    seq: u64,
    name: String,
) -> Task<Message> {
    Task::perform(
        async move {
            // Verified (Helios, mainnet-only) forward resolution: the
            // resolved address becomes the signed send recipient, so an
            // unverified RPC answer fails closed rather than being trusted.
            let result = crate::names::resolve_name(network.as_ref(), &name).await;
            (seq, name, result)
        },
        |(seq, name, result)| Message::Send(send::Message::EnsResolved { seq, name, result }),
    )
}

/// Forward ENS resolve for the Settings → Contacts add/edit form. Same
/// shape as `spawn_ens_resolve_task`; differs only in the message
/// constructor it routes the result through.
fn spawn_contacts_ens_resolve_task(
    network: Arc<dyn BalanceFetcher>,
    seq: u64,
    name: String,
) -> Task<Message> {
    Task::perform(
        async move {
            // Verified (Helios, mainnet-only) forward resolution; the
            // resolved address is saved as a contact and later reused as a
            // send recipient, so unverified answers fail closed.
            let result = crate::names::resolve_name(network.as_ref(), &name).await;
            (seq, name, result)
        },
        |(seq, name, result)| {
            Message::Contacts(contacts_settings::Message::EnsResolved { seq, name, result })
        },
    )
}

/// Forward name resolution for the Privacy Pools withdrawal target. Same shape
/// as `spawn_ens_resolve_task`; the resolved address becomes the relayer-signed
/// withdrawal recipient, so an unverified RPC answer fails closed rather than
/// being trusted.
fn spawn_pool_resolve_task(
    network: Arc<dyn BalanceFetcher>,
    seq: u64,
    name: String,
) -> Task<Message> {
    Task::perform(
        async move {
            let result = crate::names::resolve_name(network.as_ref(), &name).await;
            (seq, name, result)
        },
        |(seq, name, result)| Message::PoolTargetResolved { seq, name, result },
    )
}

/// Take the parked signer out of `handoff` and make sure its hardware device is
/// still reachable before signing — reconnecting a dropped Ledger/Trezor from
/// `desc`. The shared front half of every EOA signing task.
///
/// On any failure (no signer, or a reconnect that didn't take) it restores a
/// usable signer to the handoff so the result handler's reclaim still finds it,
/// then returns the error — the task aborts before touching the key.
async fn take_live_signer(
    handoff: &SignerHandoff,
    desc: &AccountDescriptor,
) -> Result<KaoSigner, String> {
    let signer = handoff
        .lock()
        .ok()
        .and_then(|mut g| g.take())
        .ok_or_else(|| "signer not available".to_string())?;
    match ensure_connected(signer, desc).await {
        Ok(live) => Ok(live),
        Err((orig, msg)) => {
            if let Ok(mut g) = handoff.lock() {
                *g = Some(orig);
            }
            Err(msg)
        }
    }
}

/// Build a snapshot of locally-known address → name mappings for the
/// clear-signing `DataProvider`. Merges own accounts, Safes, and
/// contacts so `resolve_local_name` can label addresses without
/// network calls.
///
/// Free function to avoid borrowing the whole `WalletScreen` — the
/// call site has `&mut self.modal` live, so a `&self` method won't fly.
fn build_local_names(
    accounts: &[AccountDescriptor],
    safes: &[SafeDescriptor],
    contacts: &Arc<RwLock<ContactsBook>>,
) -> std::collections::HashMap<Address, String> {
    let mut map = std::collections::HashMap::new();
    // Own accounts.
    for (i, acct) in accounts.iter().enumerate() {
        if let Some(addr) = account_address(acct) {
            map.insert(addr, acct.display_name(i));
        }
    }
    // Safes.
    for (i, safe) in safes.iter().enumerate() {
        map.insert(Address::from(safe.address), safe.display_name(i));
    }
    // Contacts (highest priority — overwrite if an address is both an
    // own account/safe and a contact).
    if let Ok(book) = contacts.read() {
        for c in book.iter() {
            map.insert(c.address(), c.name.clone());
        }
    }
    map
}

/// Spawn a clear-signing decode task. Tries ERC-7730 descriptor-based
/// formatting first; falls back to the heuristic pipeline (evmole +
/// 4byte + matcher) when no descriptor matches. Result message carries
/// `seq` so the SendPane can drop stale completions if the user backed
/// out of review and built a different plan.
fn spawn_decode_task(
    network: Arc<dyn BalanceFetcher>,
    seq: u64,
    plan: SendPlan,
    local_names: std::collections::HashMap<Address, String>,
) -> Task<Message> {
    let (to, value, calldata) = plan.tx_target();
    let network_id = plan.chain;
    let from = plan.from;
    Task::perform(
        async move {
            // Custom networks have no clear-signing (ERC-7730) registry and
            // only ever carry native, empty-calldata sends — nothing to
            // decode, so short-circuit to the native-transfer result rather
            // than routing an unverified chain through the decode pipeline.
            let decoded = match network_id.builtin() {
                Some(chain) => {
                    crate::decode::clear_sign::decode_transaction(
                        network.as_ref(),
                        chain,
                        from,
                        to,
                        calldata,
                        value,
                        local_names,
                    )
                    .await
                }
                None => crate::decode::clear_sign::DecodeResult::Empty,
            };
            (seq, decoded)
        },
        |(seq, decoded)| {
            Message::Send(send::Message::DecodedReady {
                seq,
                decoded: Box::new(decoded),
            })
        },
    )
}

// ── Sign-review prepare helpers ───────────────────────────────────────────────

/// Title / subtitle / trailing-note for a name-write review card.
fn name_review_labels(sign: &sign_review::NameSign) -> (String, Option<String>, Option<String>) {
    // A hardware wallet can't decode registrar calldata, so the in-app decode
    // below is the *only* place the user can read what they're authorizing before
    // approving the device's blind-sign prompt — call that out everywhere.
    let blind = Some(
        "Verify these details here — a hardware wallet can't decode this call and will ask you to \
         blind-sign the hash."
            .to_string(),
    );
    match sign {
        sign_review::NameSign::Commit(plan) => (
            format!("Register {}{} — commit", plan.label, plan.namespace.tld()),
            Some("Step 1 of 2 · front-run-proof commitment".to_string()),
            Some(
                "The commitment is a blinded hash — it reveals nothing on-chain and sends no ETH. \
                 The fee is paid at step 2."
                    .to_string(),
            ),
        ),
        sign_review::NameSign::Register(plan) => (
            format!("Register {}{} — reveal", plan.label, plan.namespace.tld()),
            Some("Step 2 of 2 · pays the registration fee".to_string()),
            blind,
        ),
        sign_review::NameSign::RegisterXns { namespace, label } => {
            (format!("Register {label}.{namespace}"), None, blind)
        }
        sign_review::NameSign::Renew {
            namespace,
            label,
            years,
        } => (
            format!("Renew {}{}", label, namespace.tld()),
            Some(format!(
                "+{years} year{}",
                if *years == 1 { "" } else { "s" }
            )),
            blind,
        ),
        sign_review::NameSign::SetRecipient {
            namespace, label, ..
        } => (
            format!("Set recipient for {}{}", label, namespace.tld()),
            Some("Points the name at a resolution address".to_string()),
            blind,
        ),
    }
}

/// Build the CoW order-review panel from the draft + quote the user is about to
/// authorize. Mirrors [`crate::cow::order::build_sell_order`] exactly (full sell =
/// quote sell + fee; min received = slippage-reduced buy), so the review matches
/// the EIP-712 message that gets signed.
fn build_order_review(
    draft: &SwapDraft,
    quote: &crate::cow::api::QuoteResponse,
    receiver: Address,
) -> sign_review::OrderReview {
    let q = &quote.quote;
    let full_sell = q.sell_amount.saturating_add(q.fee_amount);
    let min_raw = crate::cow::order::apply_slippage(q.buy_amount, draft.slippage_bps);
    let (sell_amount, _) = crate::portfolio::format_token_balance(full_sell, draft.sell_decimals);
    let (buy_amount, _) = crate::portfolio::format_token_balance(q.buy_amount, draft.buy_decimals);
    let (min_received, _) = crate::portfolio::format_token_balance(min_raw, draft.buy_decimals);
    sign_review::OrderReview {
        chain: draft.chain,
        sell_amount,
        sell_symbol: draft.sell_symbol.clone(),
        buy_amount,
        buy_symbol: draft.buy_symbol.clone(),
        min_received,
        receiver,
        valid_to: q.valid_to,
        slippage_bps: draft.slippage_bps,
        settlement: crate::cow::SETTLEMENT,
        native: draft.is_native,
    }
}

/// `0xabcd…ef01` short form of a 56-byte order UID hex string, for the cancel
/// review subtitle.
fn short_order_uid(uid: &str) -> String {
    if uid.len() <= 14 {
        return uid.to_string();
    }
    format!("{}…{}", &uid[..8], &uid[uid.len() - 6..])
}

/// Build + decode the registrar call for `sign` without signing it, and route the
/// decoded leg back into the open review. Mainnet-pinned: every name registry the
/// wallet supports lives on Ethereum mainnet.
fn spawn_name_prepare(
    network: Arc<dyn BalanceFetcher>,
    seq: u64,
    from: Address,
    sign: sign_review::NameSign,
    local_names: std::collections::HashMap<Address, String>,
) -> Task<Message> {
    Task::perform(
        async move {
            let (to, value, calldata, title) = build_name_call(network.as_ref(), &sign).await?;
            let decoded = crate::decode::clear_sign::decode_transaction(
                network.as_ref(),
                crate::chain::Chain::Mainnet,
                from,
                to,
                calldata,
                value,
                local_names,
            )
            .await;
            Ok(vec![sign_review::ReviewLeg {
                title,
                to,
                value,
                chain: crate::chain::Chain::Mainnet,
                decoded: Box::new(decoded),
            }])
        },
        move |legs| Message::SignReviewPrepared {
            seq,
            steps: legs.map(|v| v.into_iter().map(sign_review::SignStep::RawTx).collect()),
        },
    )
}

/// Compute the `(to, value, calldata)` + a human title for a name write, reusing
/// the same `*_call_for` builders the broadcast path uses — so the reviewed bytes
/// are the bytes that get signed.
async fn build_name_call(
    net: &dyn BalanceFetcher,
    sign: &sign_review::NameSign,
) -> Result<(Address, U256, alloy::primitives::Bytes, String), String> {
    use crate::names::manage;
    match sign {
        sign_review::NameSign::Commit(plan) => {
            let (to, value, cd) = manage::commit_call_for(net, plan).await?;
            Ok((
                to,
                value,
                cd,
                format!("Commit {}{}", plan.label, plan.namespace.tld()),
            ))
        }
        sign_review::NameSign::Register(plan) => {
            let (to, value, cd) = manage::register_call_for(net, plan).await?;
            Ok((
                to,
                value,
                cd,
                format!("Register {}{}", plan.label, plan.namespace.tld()),
            ))
        }
        sign_review::NameSign::RegisterXns { namespace, label } => {
            let (to, value, cd) = manage::register_xns_call_for(net, namespace, label).await?;
            Ok((to, value, cd, format!("Register {label}.{namespace}")))
        }
        sign_review::NameSign::Renew {
            namespace,
            label,
            years,
        } => {
            let dur = crate::names::registrar::ens_duration_secs(*years);
            let (to, value, cd) = manage::renew_call_for(net, *namespace, label, dur).await?;
            Ok((to, value, cd, format!("Renew {}{}", label, namespace.tld())))
        }
        sign_review::NameSign::SetRecipient {
            namespace,
            label,
            recipient,
        } => {
            let (to, value, cd) = manage::set_recipient_call_for(*namespace, label, *recipient);
            Ok((
                to,
                value,
                cd,
                format!("Set recipient for {}{}", label, namespace.tld()),
            ))
        }
    }
}

/// Decode a CoW order's on-chain legs (ERC-20 approval when allowance is short,
/// or the native EthFlow `createOrder`) for review, then route them into the open
/// review. An ERC-20 sell with sufficient allowance has no legs — only the
/// EIP-712 order panel is shown.
/// The minimal, public-data-only Safe context [`spawn_cow_prepare`] needs to
/// build the real `execTransaction` + `safeTxHash` for the review — unlike
/// [`SafeSwapCtx`], which holds signer descriptors we don't put in a prepare
/// closure. `Clone` so it rides the async task.
#[derive(Debug, Clone)]
struct SafePrepCtx {
    safe: Address,
    chain: crate::chain::Chain,
    version: String,
    threshold: u8,
    owner_count: u8,
}

fn spawn_cow_prepare(
    network: Arc<dyn BalanceFetcher>,
    seq: u64,
    draft: SwapDraft,
    quote: crate::cow::api::QuoteResponse,
    user: Address,
    local_names: std::collections::HashMap<Address, String>,
    safe_prep: Option<SafePrepCtx>,
) -> Task<Message> {
    Task::perform(
        async move {
            let chain = draft.chain;
            let q = &quote.quote;
            let full_sell = q.sell_amount.saturating_add(q.fee_amount);
            let (_, app_data_hash) = cow::market_app_data(draft.slippage_bps);
            let mut steps: Vec<sign_review::SignStep> = Vec::new();

            let Some(ctx) = safe_prep else {
                // ── EOA path: sign the raw createOrder / approve directly. ──
                if draft.is_native {
                    let data = cow::ethflow::build_ethflow_data(
                        draft.buy_token,
                        user,
                        full_sell,
                        q.buy_amount,
                        q.valid_to,
                        quote.id.unwrap_or_default(),
                        draft.slippage_bps,
                        app_data_hash,
                    );
                    let calldata = cow::ethflow::create_order_calldata(&data);
                    let value = cow::ethflow::msg_value(&data);
                    let decoded = crate::decode::clear_sign::decode_transaction(
                        network.as_ref(),
                        chain,
                        user,
                        cow::ETHFLOW,
                        calldata,
                        value,
                        local_names,
                    )
                    .await;
                    steps.push(sign_review::SignStep::RawTx(sign_review::ReviewLeg {
                        title: "Place on-chain order — EthFlow createOrder".to_string(),
                        to: cow::ETHFLOW,
                        value,
                        chain,
                        decoded: Box::new(decoded),
                    }));
                } else {
                    let provider =
                        match provider_for(&network, crate::chain::NetworkId::Builtin(chain)).await
                        {
                            Some(p) => p,
                            None => return Err("no execution RPC configured".to_string()),
                        };
                    let allowance =
                        cow::onchain::read_allowance(&provider, draft.sell_token, user).await?;
                    if allowance < full_sell {
                        let calldata = cow::onchain::approve_calldata(U256::MAX);
                        let decoded = crate::decode::clear_sign::decode_transaction(
                            network.as_ref(),
                            chain,
                            user,
                            draft.sell_token,
                            calldata,
                            U256::ZERO,
                            local_names,
                        )
                        .await;
                        steps.push(sign_review::SignStep::RawTx(sign_review::ReviewLeg {
                            title: format!(
                                "Approve {} for CoW (vault relayer)",
                                draft.sell_symbol
                            ),
                            to: draft.sell_token,
                            value: U256::ZERO,
                            chain,
                            decoded: Box::new(decoded),
                        }));
                    }
                }
                return Ok(steps);
            };

            // ── Safe path: build the REAL execTransaction(s) + EIP-1271 message and
            //    show the exact safeTxHash / SafeMessage hash each owner signs.
            //    `receiver = safe` matches what `cow_place_order_safe` signs. ──
            use crate::safe::tx::{
                Operation, SafeTxInput, build_safe_tx_with_nonce, current_safe_nonce,
                ensure_signable_version, safe_domain, safe_tx_hash, verify_safe_tx_before_signing,
            };
            // Fail-closed at review: a Safe we can't sign shouldn't render a gate.
            ensure_signable_version(&ctx.version)?;
            let safe = ctx.safe;
            let domain = safe_domain(safe, ctx.chain);

            if draft.is_native {
                let data = cow::ethflow::build_ethflow_data(
                    draft.buy_token,
                    safe,
                    full_sell,
                    q.buy_amount,
                    q.valid_to,
                    quote.id.unwrap_or_default(),
                    draft.slippage_bps,
                    app_data_hash,
                );
                let calldata = cow::ethflow::create_order_calldata(&data);
                let value = cow::ethflow::msg_value(&data);
                // Pin the nonce read here; cow_place_order_safe (P3b) signs at it.
                let nonce = current_safe_nonce(network.as_ref(), safe, ctx.chain).await?;
                let tx = ethflow_safe_tx(&data, nonce);
                let hash = safe_tx_hash(&tx, &domain);
                verify_safe_tx_before_signing(network.as_ref(), &tx, safe, ctx.chain, hash).await?;
                let decoded = crate::decode::clear_sign::decode_transaction(
                    network.as_ref(),
                    chain,
                    safe,
                    cow::ETHFLOW,
                    calldata,
                    value,
                    local_names,
                )
                .await;
                steps.push(sign_review::SignStep::SafeExec(sign_review::SafeExecReview {
                    safe,
                    nonce,
                    threshold: ctx.threshold,
                    owner_count: ctx.owner_count,
                    safe_tx_hash: hash,
                    inner: Box::new(sign_review::ReviewLeg {
                        title: "Place on-chain order — EthFlow createOrder".to_string(),
                        to: cow::ETHFLOW,
                        value,
                        chain,
                        decoded: Box::new(decoded),
                    }),
                }));
            } else {
                let provider =
                    match provider_for(&network, crate::chain::NetworkId::Builtin(chain)).await {
                        Some(p) => p,
                        None => return Err("no execution RPC configured".to_string()),
                    };
                let allowance =
                    cow::onchain::read_allowance(&provider, draft.sell_token, safe).await?;
                if allowance < full_sell {
                    let calldata = cow::onchain::approve_calldata(U256::MAX);
                    let nonce = current_safe_nonce(network.as_ref(), safe, ctx.chain).await?;
                    let tx = build_safe_tx_with_nonce(
                        SafeTxInput {
                            to: draft.sell_token,
                            value: U256::ZERO,
                            data: calldata.clone(),
                            operation: Operation::Call,
                        },
                        nonce,
                    );
                    let hash = safe_tx_hash(&tx, &domain);
                    verify_safe_tx_before_signing(network.as_ref(), &tx, safe, ctx.chain, hash)
                        .await?;
                    let decoded = crate::decode::clear_sign::decode_transaction(
                        network.as_ref(),
                        chain,
                        safe,
                        draft.sell_token,
                        calldata,
                        U256::ZERO,
                        local_names,
                    )
                    .await;
                    steps.push(sign_review::SignStep::SafeExec(sign_review::SafeExecReview {
                        safe,
                        nonce,
                        threshold: ctx.threshold,
                        owner_count: ctx.owner_count,
                        safe_tx_hash: hash,
                        inner: Box::new(sign_review::ReviewLeg {
                            title: format!("Approve {} for CoW (vault relayer)", draft.sell_symbol),
                            to: draft.sell_token,
                            value: U256::ZERO,
                            chain,
                            decoded: Box::new(decoded),
                        }),
                    }));
                }
                // The order itself is authorized via EIP-1271 (nonce-free, pure).
                let order = cow::order::build_sell_order(
                    draft.sell_token,
                    draft.buy_token,
                    safe,
                    full_sell,
                    q.buy_amount,
                    q.valid_to,
                    draft.slippage_bps,
                    app_data_hash,
                );
                let order_digest = cow::order::order_digest(&order, &cow::order::cow_domain(chain));
                let message_hash = cow::safe_sig::safe_message_hash(order_digest, safe, chain);
                steps.push(sign_review::SignStep::SafeMessage(sign_review::SafeMessageReview {
                    order: build_order_review(&draft, &quote, safe),
                    safe,
                    threshold: ctx.threshold,
                    owner_count: ctx.owner_count,
                    order_digest,
                    message_hash,
                }));
            }
            Ok(steps)
        },
        move |steps| Message::SignReviewPrepared { seq, steps },
    )
}

/// Resolve a raw provider for any [`NetworkId`](crate::chain::NetworkId): the
/// shared verified-path provider for a built-in chain, or a freshly-built raw
/// provider for a custom network (RPC URL looked up by chain id in settings).
/// `None` when the network has no usable RPC — a built-in with nothing
/// configured, or a custom network that was deleted / whose URL won't parse.
async fn provider_for(
    network: &Arc<dyn BalanceFetcher>,
    id: crate::chain::NetworkId,
) -> Option<alloy::providers::RootProvider<alloy::network::Ethereum>> {
    use crate::chain::NetworkId;
    match id {
        NetworkId::Builtin(chain) => network.provider(chain).await,
        NetworkId::Custom(chain_id) => {
            let cfg = settings::custom_network(chain_id)?;
            network.custom_provider(chain_id, &cfg.rpc_url).await
        }
    }
}

/// Spawn a quote task using a provider resolved from `plan.chain` — the L2 RPC
/// for an L2 send, the user's raw RPC for a custom network. The same provider
/// later serves the broadcast.
fn spawn_quote_task(network: Arc<dyn BalanceFetcher>, seq: u64, plan: SendPlan) -> Task<Message> {
    let chain = plan.chain;
    Task::perform(
        async move {
            match provider_for(&network, chain).await {
                Some(provider) => {
                    crate::wallet::tx::build_quote(&provider, network.clone(), &plan).await
                }
                None => {
                    warn!(
                        chain_id = chain.chain_id(),
                        "quote: no execution RPC configured"
                    );
                    Err("no execution RPCs configured".into())
                }
            }
        },
        move |result| Message::Send(send::Message::QuoteFetched { seq, result }),
    )
}

/// `(address, descriptor)` for every linked owner that can sign — Local
/// or hardware, excluding view-only and dangling indices. Drives the
/// detail modal's Confirm/Reject signer selection. Free function so it's
/// testable without a full `WalletScreen`.
fn signable_owners_of(
    safe: &SafeDescriptor,
    accounts: &[AccountDescriptor],
) -> Vec<(Address, AccountDescriptor)> {
    safe.linked_signer_indices
        .iter()
        .filter_map(|&idx| {
            let desc = accounts.get(idx as usize)?;
            if matches!(desc, AccountDescriptor::ViewOnly { .. }) {
                return None;
            }
            Some((account_address(desc)?, desc.clone()))
        })
        .collect()
}

/// The descriptor whose address matches `addr`, if the wallet holds it.
fn owner_desc_by_address(
    addr: Address,
    accounts: &[AccountDescriptor],
) -> Option<AccountDescriptor> {
    accounts
        .iter()
        .find(|a| account_address(a) == Some(addr))
        .cloned()
}

/// First Local account's private key — the gas-paying executor for
/// execute-from-queue. `None` if the wallet is hardware/view-only only.
fn first_local_key_of(accounts: &[AccountDescriptor]) -> Option<B256> {
    accounts.iter().find_map(|a| match a {
        AccountDescriptor::Local { key_bytes, .. } => Some(key_bytes.to_b256()),
        _ => None,
    })
}

/// Review-prep for the SafeSend modal: build the SafeTx at the live
/// nonce, run both on-chain cross-checks (domain separator +
/// `getTransactionHash`), and hand the pinned `(nonce, safeTxHash)`
/// back to the pane so the review screen shows the exact hash the
/// signer(s) will commit to. Touches no signer.
fn spawn_safe_prepare_task(
    network: Arc<dyn BalanceFetcher>,
    seq: u64,
    req: SafeSendRequest,
) -> Task<Message> {
    use crate::safe::tx::{
        build_safe_tx_with_nonce, current_safe_nonce, ensure_signable_version, safe_domain,
        safe_tx_hash, verify_safe_tx_before_signing,
    };
    let chain = req.chain;
    Task::perform(
        async move {
            let result: Result<(u64, B256), String> = async {
                if let Some(reason) = req.trust.signing_block_reason() {
                    return Err(reason.to_string());
                }
                ensure_signable_version(&req.version)?;
                let nonce = current_safe_nonce(network.as_ref(), req.safe_address, chain).await?;
                let tx = build_safe_tx_with_nonce(req.safe_tx_input(), nonce);
                let domain = safe_domain(req.safe_address, chain);
                let local = safe_tx_hash(&tx, &domain);
                verify_safe_tx_before_signing(
                    network.as_ref(),
                    &tx,
                    req.safe_address,
                    chain,
                    local,
                )
                .await?;
                Ok((nonce, local))
            }
            .await;
            (seq, result)
        },
        |(seq, result)| Message::Send(send::Message::HashReady { seq, result }),
    )
}

/// How long the automatic verified-retry waits before re-running a sim
/// that succeeded on fallback state: the helios cooldown window plus a
/// margin, so the re-run lands back on the verified path instead of
/// being short-circuited by `in_cooldown` again.
fn sim_retry_delay() -> std::time::Duration {
    crate::net::FALLBACK_COOLDOWN + std::time::Duration::from_secs(1)
}

/// Inner-call preflight for the SafeSend review: simulate the transfer
/// the Safe would make (`from = Safe`, to/value from the form) against
/// Helios-verified state. Runs in parallel with the prepare task — the
/// inner call doesn't depend on the pinned nonce. Advisory: any failure
/// degrades to `unavailable()` (same convention as the EOA quote path).
///
/// `delayed` waits out the helios fallback cooldown (plus a margin)
/// before running — the automatic verified-retry path. The pane's seq
/// guard drops the result if the user navigated away meanwhile.
fn spawn_safe_send_sim_task(
    network: Arc<dyn BalanceFetcher>,
    seq: u64,
    req: SafeSendRequest,
    delayed: bool,
) -> Task<Message> {
    use crate::safe::tx::build_safe_tx_with_nonce;
    let chain = req.chain;
    Task::perform(
        async move {
            if delayed {
                tokio::time::sleep(sim_retry_delay()).await;
            }
            // Nonce 0 is fine: the inner sim only reads to/value/data.
            let tx = build_safe_tx_with_nonce(req.safe_tx_input(), 0);
            let result =
                match crate::safe::sim::simulate_safe_inner(network, req.safe_address, &tx, chain)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(error = %e, "safe-send: inner sim failed, marking unavailable");
                        SimulationResult::unavailable()
                    }
                };
            (seq, result)
        },
        |(seq, result)| Message::Send(send::Message::SimReady { seq, result }),
    )
}

/// Rebuild the SafeTx at the `(nonce, hash)` pin the user reviewed,
/// re-running every pre-sign check. Shared front-half of the broadcast
/// and propose tasks. Fails if the review pin is missing, the live
/// nonce moved since review (another co-signer executed something), or
/// any local/on-chain hash check diverges — in every case before a
/// signature exists.
async fn rebuild_reviewed_safe_tx(
    network: &dyn BalanceFetcher,
    req: &SafeSendRequest,
) -> Result<(crate::safe::SafeTx, alloy::sol_types::Eip712Domain, B256), String> {
    use crate::safe::tx::{
        build_safe_tx_with_nonce, current_safe_nonce, ensure_signable_version, safe_domain,
        safe_tx_hash, verify_safe_tx_before_signing,
    };
    if let Some(reason) = req.trust.signing_block_reason() {
        return Err(reason.to_string());
    }
    ensure_signable_version(&req.version)?;
    let pinned = req
        .prepared
        .ok_or("internal: sign requested before the reviewed hash was ready")?;
    let live_nonce = current_safe_nonce(network, req.safe_address, req.chain).await?;
    if live_nonce != pinned.nonce {
        return Err(format!(
            "Safe nonce advanced since review ({} → {live_nonce}) — go back and review again",
            pinned.nonce,
        ));
    }
    let tx = build_safe_tx_with_nonce(req.safe_tx_input(), pinned.nonce);
    let domain = safe_domain(req.safe_address, req.chain);
    let local_hash = safe_tx_hash(&tx, &domain);
    if local_hash != pinned.safe_tx_hash {
        // Can only happen if the form and the pin desynced — a bug, but
        // the invariant "we sign only what was displayed" must hold.
        return Err("safe-tx differs from the reviewed hash — refusing to sign".to_string());
    }
    verify_safe_tx_before_signing(network, &tx, req.safe_address, req.chain, local_hash).await?;
    Ok((tx, domain, local_hash))
}

/// Spawn the Safe-TX solo sign-and-broadcast task.
///
/// 1. Build a live signer for each of the first `threshold`
///    `signer_owners` via `build_owner_signer` — `Local` or hardware.
/// 2. Rebuild the SafeTx at the reviewed `(nonce, hash)` pin and re-run
///    the on-chain cross-checks (`rebuild_reviewed_safe_tx`).
/// 3. Sign the SafeTx with each owner via `sign_owner` (EIP-712, with an
///    `eth_sign` fallback for older hardware) and assemble the blobs
///    Safe-style (ascending by address).
/// 4. Broadcast `execTransaction` from the executor: a `Local` account
///    (`local_executor_key`) when the wallet holds one — gas-only, no
///    extra device prompt — otherwise the first signing owner itself, so
///    a hardware-only 1/1 Safe pays its own gas.
///
/// The Safe validates signatures against the owner set, not `msg.sender`,
/// so the executor need not be an owner. Secret material is derived
/// inside the task, never carried across the `Task::perform` boundary.
fn spawn_safe_broadcast_task(
    network: Arc<dyn BalanceFetcher>,
    req: SafeSendRequest,
    signer_owners: Vec<AccountDescriptor>,
    local_executor_key: Option<B256>,
) -> Task<Message> {
    use crate::safe::tx::{assemble_signatures, execute_safe_tx, sign_owner};
    let chain = req.chain;
    Task::perform(
        async move {
            let provider = match network.provider(chain).await {
                Some(p) => p,
                None => {
                    warn!(chain = %chain.label(), "safe-broadcast: no execution RPC configured");
                    return Err::<TxHash, String>("no execution RPCs configured".into());
                }
            };

            // Build one live signer per owner up front. Hardware variants
            // open a USB transport here; building once lets the same
            // instance both sign the SafeTx and — when it doubles as the
            // executor — sign the outer envelope, instead of contending
            // for the device on a second connection.
            let needed = req.threshold as usize;
            let mut owner_signers = Vec::with_capacity(needed);
            for desc in signer_owners.iter().take(needed) {
                match crate::wallet::build_owner_signer(desc).await {
                    Ok(s) => owner_signers.push(s),
                    Err(e) => {
                        warn!(error = %e, "safe-broadcast: build owner signer failed");
                        // `e` is already friendly (build_owner_signer routes hardware
                        // failures through friendly_signer_error_text) — surface as-is.
                        return Err(e);
                    }
                }
            }
            if owner_signers.is_empty() || (owner_signers.len() as u32) < req.threshold {
                return Err("not enough signable owners to meet the Safe threshold".into());
            }

            let (safe_tx, domain, local_hash) =
                rebuild_reviewed_safe_tx(network.as_ref(), &req).await?;

            let mut sigs = Vec::with_capacity(owner_signers.len());
            for signer in &owner_signers {
                let pair = sign_owner(signer, &safe_tx, &domain, local_hash).await?;
                sigs.push(pair);
            }
            let packed = assemble_signatures(sigs)?;

            // Executor: prefer a Local gas payer (no extra device prompt);
            // otherwise reuse the first owner signer (hardware self-pay).
            let local_executor;
            let executor: &KaoSigner = match local_executor_key {
                Some(key) => {
                    let s = crate::wallet::signer_from_bytes(&key)
                        .map_err(|e| format!("derive executor: {e}"))?;
                    local_executor = KaoSigner::Local(s);
                    &local_executor
                }
                None => &owner_signers[0],
            };

            execute_safe_tx(
                &provider,
                executor,
                req.safe_address,
                chain,
                safe_tx,
                packed,
            )
            .await
        },
        Message::SafeSendBroadcastReturn,
    )
}

/// Propose a Safe-send tx to the Transaction Service: rebuild the SafeTx
/// at the reviewed `(nonce, hash)` pin, re-run the on-chain checks, sign
/// once as `owner_desc` (software or hardware), and POST. Co-signers
/// finish it from their own wallets. Mirrors `spawn_safe_broadcast_task`'s
/// rebuild→verify→sign front-half, but stops at the service instead of
/// broadcasting.
fn spawn_safe_propose_task(
    network: Arc<dyn BalanceFetcher>,
    owner_desc: AccountDescriptor,
    req: SafeSendRequest,
) -> Task<Message> {
    use crate::safe::tx::sign_owner;
    let chain = req.chain;
    Task::perform(
        async move {
            let (tx, domain, local) = rebuild_reviewed_safe_tx(network.as_ref(), &req).await?;
            let signer = crate::wallet::build_owner_signer(&owner_desc).await?;
            let owner_sig = sign_owner(&signer, &tx, &domain, local).await?;
            crate::safe::service::propose(
                &req.service_base,
                req.safe_address,
                chain,
                &tx,
                local,
                &owner_sig,
                Some("Kao"),
            )
            .await?;
            Ok(())
        },
        Message::SafeSendProposeReturn,
    )
}

/// Load full detail (reconstructed `SafeTx` + per-owner signatures) for
/// one queued tx, for the detail modal's owner checklist and the
/// execute-from-queue path.
/// How long the post-action *second* detail reload waits for the
/// Transaction Service to index a freshly-mined execution. The first
/// (immediate) reload covers confirm/reject, which land synchronously.
const SERVICE_REINDEX_DELAY: std::time::Duration = std::time::Duration::from_secs(8);

fn spawn_safe_detail_load_task(
    network: Arc<dyn BalanceFetcher>,
    service_base: String,
    safe: Address,
    chain: crate::chain::Chain,
    safe_tx_hash: B256,
    threshold: u32,
    delayed: bool,
) -> Task<Message> {
    Task::perform(
        async move {
            if delayed {
                tokio::time::sleep(SERVICE_REINDEX_DELAY).await;
            }
            crate::safe::service::fetch_detail(
                network.as_ref(),
                &service_base,
                safe,
                chain,
                safe_tx_hash,
                threshold,
            )
            .await
        },
        Message::SafeTxDetailLoaded,
    )
}

/// Inner-call preflight for the detail modal: the loaded SafeTx body
/// simulated as the Safe itself. Only spawned for `operation == 0`.
/// Advisory — failure degrades to `unavailable()`. Tagged with the
/// safeTxHash so a result for a closed/switched modal is dropped.
fn spawn_safe_inner_sim_task(
    network: Arc<dyn BalanceFetcher>,
    safe: Address,
    chain: crate::chain::Chain,
    safe_tx_hash: B256,
    tx: crate::safe::SafeTx,
    delayed: bool,
) -> Task<Message> {
    Task::perform(
        async move {
            if delayed {
                tokio::time::sleep(sim_retry_delay()).await;
            }
            let result =
                match crate::safe::sim::simulate_safe_inner(network, safe, &tx, chain).await {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(error = %e, "safe-detail: inner sim failed, marking unavailable");
                        SimulationResult::unavailable()
                    }
                };
            (safe_tx_hash, result)
        },
        |(safe_tx_hash, result)| Message::SafeTxInnerSimLoaded {
            safe_tx_hash,
            result,
        },
    )
}

/// Everything the execute-time preflight needs about the queued tx:
/// who pays gas, which Safe, the reconstructed SafeTx, and the
/// service-held confirmations to assemble. Bundled so the task takes
/// `(network, spec, delayed)` instead of eight loose arguments.
struct ExecSimSpec {
    executor: Address,
    safe: Address,
    chain: crate::chain::Chain,
    safe_tx_hash: B256,
    tx: crate::safe::SafeTx,
    confirmations: Vec<(Address, Bytes)>,
}

/// Execute-time preflight: assemble the service-held signatures exactly
/// like the Execute action does and simulate the full `execTransaction`
/// calldata from the local executor. Catches GS-code failures (bad
/// sigs, stale nonce) before any gas is spent. Faithful even for
/// delegatecall — revm runs the real Safe code.
///
/// Note the MockFetcher-backed tests can't truly exercise
/// `checkSignatures` (the Safe has no code in the mock, so the call is
/// a silent success) — real coverage needs a future anvil harness.
fn spawn_safe_exec_sim_task(
    network: Arc<dyn BalanceFetcher>,
    spec: ExecSimSpec,
    delayed: bool,
) -> Task<Message> {
    Task::perform(
        async move {
            if delayed {
                tokio::time::sleep(sim_retry_delay()).await;
            }
            let result = match crate::safe::tx::assemble_signatures(spec.confirmations) {
                Ok(sigs) => {
                    match crate::safe::sim::simulate_safe_execution(
                        network,
                        spec.executor,
                        spec.safe,
                        &spec.tx,
                        sigs,
                        spec.chain,
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(e) => {
                            warn!(error = %e, "safe-detail: exec sim failed, marking unavailable");
                            SimulationResult::unavailable()
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "safe-detail: signature assembly failed, exec sim unavailable");
                    SimulationResult::unavailable()
                }
            };
            (spec.safe_tx_hash, result)
        },
        |(safe_tx_hash, result)| Message::SafeTxExecSimLoaded {
            safe_tx_hash,
            result,
        },
    )
}

/// Confirm a queued tx: re-verify the safeTxHash on-chain, sign it as
/// `owner_desc` (software or hardware), and POST the confirmation. The
/// hash checks are defense-in-depth — refuse to sign if the detail we
/// loaded disagrees with what the Safe computes.
fn spawn_safe_confirm_task(
    network: Arc<dyn BalanceFetcher>,
    service_base: String,
    owner_desc: AccountDescriptor,
    safe: Address,
    chain: crate::chain::Chain,
    tx: crate::safe::SafeTx,
    safe_tx_hash: B256,
) -> Task<Message> {
    use crate::safe::tx::{
        safe_domain, safe_tx_hash as compute_hash, sign_owner, verify_safe_tx_before_signing,
    };
    Task::perform(
        async move {
            let domain = safe_domain(safe, chain);
            let local = compute_hash(&tx, &domain);
            if local != safe_tx_hash {
                return Err("safe-tx: detail hash drifted; refusing to sign".to_string());
            }
            verify_safe_tx_before_signing(network.as_ref(), &tx, safe, chain, local).await?;
            let signer = crate::wallet::build_owner_signer(&owner_desc).await?;
            let (_, sig) = sign_owner(&signer, &tx, &domain, safe_tx_hash).await?;
            crate::safe::service::confirm(&service_base, safe_tx_hash, chain, &sig).await?;
            Ok("Signature added".to_string())
        },
        Message::SafeTxActionDone,
    )
}

/// Execute a queued tx that reached threshold: assemble the signatures
/// the service collected and broadcast `execTransaction`. `executor_key`
/// is a Local account that pays gas (it need not be an owner — the Safe
/// validates signatures against its owner set, not `msg.sender`).
fn spawn_safe_execute_task(
    network: Arc<dyn BalanceFetcher>,
    executor_key: B256,
    safe: Address,
    chain: crate::chain::Chain,
    tx: crate::safe::SafeTx,
    confirmations: Vec<(Address, Bytes)>,
) -> Task<Message> {
    use crate::safe::tx::{assemble_signatures, execute_safe_tx};
    Task::perform(
        async move {
            let provider = network
                .provider(chain)
                .await
                .ok_or_else(|| "no execution RPCs configured".to_string())?;
            let executor = KaoSigner::Local(
                crate::wallet::signer_from_bytes(&executor_key).map_err(|e| e.to_string())?,
            );
            let packed = assemble_signatures(confirmations)?;
            let hash = execute_safe_tx(&provider, &executor, safe, chain, tx, packed).await?;
            Ok(format!("Executed · {hash:#x}"))
        },
        Message::SafeTxActionDone,
    )
}

/// Propose a same-nonce rejection for a queued tx: build the canonical
/// zero-value self-call at `nonce`, verify its hash on-chain, sign as
/// `owner_desc`, and POST it. Co-owners then confirm/execute it to void
/// the original.
fn spawn_safe_reject_task(
    network: Arc<dyn BalanceFetcher>,
    service_base: String,
    owner_desc: AccountDescriptor,
    safe: Address,
    chain: crate::chain::Chain,
    nonce: u64,
) -> Task<Message> {
    use crate::safe::tx::{
        build_rejection_tx, safe_domain, safe_tx_hash as compute_hash, sign_owner,
        verify_safe_tx_before_signing,
    };
    Task::perform(
        async move {
            let domain = safe_domain(safe, chain);
            let tx = build_rejection_tx(safe, nonce);
            let local = compute_hash(&tx, &domain);
            verify_safe_tx_before_signing(network.as_ref(), &tx, safe, chain, local).await?;
            let signer = crate::wallet::build_owner_signer(&owner_desc).await?;
            let owner_sig = sign_owner(&signer, &tx, &domain, local).await?;
            crate::safe::service::propose(
                &service_base,
                safe,
                chain,
                &tx,
                local,
                &owner_sig,
                Some("Kao:reject"),
            )
            .await?;
            Ok("Rejection proposed".to_string())
        },
        Message::SafeTxActionDone,
    )
}

fn spawn_broadcast_task(
    network: Arc<dyn BalanceFetcher>,
    handoff: SignerHandoff,
    desc: AccountDescriptor,
    plan: SendPlan,
    quote: crate::wallet::tx::TxQuote,
) -> Task<Message> {
    let inner = handoff.clone();
    let chain = plan.chain;
    Task::perform(
        async move {
            let provider = match provider_for(&network, chain).await {
                Some(p) => p,
                None => {
                    warn!(
                        chain_id = chain.chain_id(),
                        "broadcast: no execution RPC configured"
                    );
                    return Err::<TxHash, String>("no execution RPCs configured".into());
                }
            };
            // Take the parked signer and make sure its hardware device is still
            // reachable (reconnecting a dropped Ledger/Trezor) before signing.
            let signer = match take_live_signer(&inner, &desc).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "broadcast: signer unavailable / hardware unreachable");
                    return Err(e);
                }
            };
            let result = crate::wallet::tx::sign_and_send(&provider, &signer, plan, quote).await;
            // Put the signer back so the dashboard can reclaim it.
            if let Ok(mut g) = inner.lock() {
                *g = Some(signer);
            }
            result
        },
        move |result| Message::SendBroadcastReturn {
            result,
            signer: handoff,
        },
    )
}

// ── CoW swap tasks ────────────────────────────────────────────────────────────

/// Build the `/quote` request for a draft. A native-ETH sell quotes against the
/// EthFlow contract (eip1271, on-chain order); an ERC-20 sell quotes as the user
/// (eip712). The receiver is always the user.
fn cow_quote_request(draft: &SwapDraft, user: Address) -> crate::cow::api::QuoteRequest {
    let (from, signing_scheme, onchain_order) = if draft.is_native {
        (cow::ETHFLOW, "eip1271".to_string(), true)
    } else {
        (user, "eip712".to_string(), false)
    };
    crate::cow::api::QuoteRequest {
        sell_token: draft.sell_token,
        buy_token: draft.buy_token,
        from,
        receiver: Some(user),
        kind: "sell".to_string(),
        sell_amount_before_fee: draft.sell_amount,
        valid_for: 1800,
        // Quote with the same market-order appData we'll sign, so the orderbook
        // classifies the order consistently (mirrors the cow-sdk flow).
        app_data: cow::market_app_data(draft.slippage_bps).0,
        signing_scheme,
        onchain_order,
        partially_fillable: false,
    }
}

// ── Names app tasks ──────────────────────────────────────────────────────────
//
// Reads go through the verified mainnet path (fail-closed); writes take the
// parked signer, broadcast, then wait for the receipt so the UI only advances on
// a mined, non-reverted transaction. All pin to mainnet inside `crate::names`.

/// Discover names that resolve to the active account via reverse lookup.
fn spawn_name_reverse_scan(network: Arc<dyn BalanceFetcher>, owner: Address) -> Task<Message> {
    Task::perform(
        async move { crate::names::manage::reverse_owned_names(&*network, owner).await },
        move |result| Message::NameReverseScanned { owner, result },
    )
}

/// Verify a single manually-entered name's status.
fn spawn_name_status(
    network: Arc<dyn BalanceFetcher>,
    owner: Address,
    registry: Registry,
    label: String,
) -> Task<Message> {
    Task::perform(
        async move { crate::names::manage::name_status(&*network, &registry, &label).await },
        move |result| Message::NameStatusLoaded { owner, result },
    )
}

/// Check `label` across `registries` (availability + price) for the search bar.
fn spawn_name_search(
    network: Arc<dyn BalanceFetcher>,
    owner: Address,
    seq: u64,
    label: String,
    registries: Vec<Registry>,
) -> Task<Message> {
    Task::perform(
        async move {
            Ok::<_, String>(crate::names::manage::search(&*network, &label, registries).await)
        },
        move |result| Message::NameSearched { owner, seq, result },
    )
}

/// Re-price an ENS registration for `years` (read-only) when the user changes
/// the duration stepper, so the panel's quote tracks the term they'll pay for.
fn spawn_name_quote(
    network: Arc<dyn BalanceFetcher>,
    owner: Address,
    namespace: crate::names::registrar::Namespace,
    label: String,
    years: u32,
) -> Task<Message> {
    let duration = crate::names::registrar::ens_duration_secs(years);
    Task::perform(
        async move {
            crate::names::manage::register_quote(&*network, namespace, &label, duration).await
        },
        move |result| Message::NameQuoted {
            owner,
            years,
            result,
        },
    )
}

/// Wait for `hash` to be mined on mainnet (≈ up to 3 min). Shared tail of the
/// name write tasks so the UI only advances on a confirmed, non-reverted tx.
async fn await_mined(network: &Arc<dyn BalanceFetcher>, hash: TxHash) -> Result<(), String> {
    let provider = network
        .provider(crate::chain::Chain::Mainnet)
        .await
        .ok_or_else(|| "no Ethereum mainnet RPC configured".to_string())?;
    crate::cow::onchain::wait_for_receipt(&provider, hash, 60).await
}

/// Registration step 1: broadcast the commit and wait for it to mine.
fn spawn_name_commit(
    network: Arc<dyn BalanceFetcher>,
    handoff: SignerHandoff,
    desc: AccountDescriptor,
    plan: RegisterPlan,
) -> Task<Message> {
    let inner = handoff.clone();
    Task::perform(
        async move {
            let signer = match take_live_signer(&inner, &desc).await {
                Ok(s) => s,
                Err(e) => return Err::<(RegisterPlan, TxHash), String>(e),
            };
            let result = async {
                let hash = crate::names::manage::submit_commit(&*network, &signer, &plan).await?;
                await_mined(&network, hash).await?;
                Ok::<_, String>((plan.clone(), hash))
            }
            .await;
            if let Ok(mut g) = inner.lock() {
                *g = Some(signer);
            }
            result
        },
        move |result| Message::NameCommitted {
            result,
            signer: handoff,
        },
    )
}

/// Registration step 2: broadcast the reveal/register and wait for it to mine.
fn spawn_name_register(
    network: Arc<dyn BalanceFetcher>,
    handoff: SignerHandoff,
    desc: AccountDescriptor,
    plan: RegisterPlan,
) -> Task<Message> {
    let inner = handoff.clone();
    let name = format!("{}{}", plan.label, plan.namespace.tld());
    Task::perform(
        async move {
            let signer = match take_live_signer(&inner, &desc).await {
                Ok(s) => s,
                Err(e) => return Err::<(String, TxHash), String>(e),
            };
            let result = async {
                let hash = crate::names::manage::submit_register(&*network, &signer, &plan).await?;
                await_mined(&network, hash).await?;
                Ok::<_, String>((name, hash))
            }
            .await;
            if let Ok(mut g) = inner.lock() {
                *g = Some(signer);
            }
            result
        },
        move |result| Message::NameRegistered {
            result,
            signer: handoff,
        },
    )
}

/// XNS one-shot registration: broadcast `registerName` and wait for it to mine.
/// Reuses `Message::NameRegistered` (the pane's `on_register` handles both the
/// commit-reveal reveal and this single-step path).
fn spawn_name_register_xns(
    network: Arc<dyn BalanceFetcher>,
    handoff: SignerHandoff,
    desc: AccountDescriptor,
    namespace: String,
    label: String,
) -> Task<Message> {
    let inner = handoff.clone();
    let name = format!("{label}.{namespace}");
    Task::perform(
        async move {
            let signer = match take_live_signer(&inner, &desc).await {
                Ok(s) => s,
                Err(e) => return Err::<(String, TxHash), String>(e),
            };
            let result = async {
                let hash = crate::names::manage::submit_register_xns(
                    &*network, &signer, &namespace, &label,
                )
                .await?;
                await_mined(&network, hash).await?;
                Ok::<_, String>((name, hash))
            }
            .await;
            if let Ok(mut g) = inner.lock() {
                *g = Some(signer);
            }
            result
        },
        move |result| Message::NameRegistered {
            result,
            signer: handoff,
        },
    )
}

/// Renew ("prolong") an owned name.
fn spawn_name_renew(
    network: Arc<dyn BalanceFetcher>,
    handoff: SignerHandoff,
    desc: AccountDescriptor,
    namespace: Namespace,
    label: String,
    years: u32,
) -> Task<Message> {
    let inner = handoff.clone();
    let name = format!("{label}{}", namespace.tld());
    Task::perform(
        async move {
            let signer = match take_live_signer(&inner, &desc).await {
                Ok(s) => s,
                Err(e) => return Err::<(String, TxHash), String>(e),
            };
            let result = async {
                let duration = crate::names::registrar::ens_duration_secs(years);
                let hash = crate::names::manage::submit_renew(
                    &*network, &signer, namespace, &label, duration,
                )
                .await?;
                await_mined(&network, hash).await?;
                Ok::<_, String>((name, hash))
            }
            .await;
            if let Ok(mut g) = inner.lock() {
                *g = Some(signer);
            }
            result
        },
        move |result| Message::NameRenewed {
            result,
            signer: handoff,
        },
    )
}

/// Point an owned name at a new recipient address.
fn spawn_name_set_recipient(
    network: Arc<dyn BalanceFetcher>,
    handoff: SignerHandoff,
    desc: AccountDescriptor,
    namespace: Namespace,
    label: String,
    recipient: Address,
) -> Task<Message> {
    let inner = handoff.clone();
    let name = format!("{label}{}", namespace.tld());
    Task::perform(
        async move {
            let signer = match take_live_signer(&inner, &desc).await {
                Ok(s) => s,
                Err(e) => return Err::<(String, TxHash), String>(e),
            };
            let result = async {
                let hash = crate::names::manage::submit_set_recipient(
                    &*network, &signer, namespace, &label, recipient,
                )
                .await?;
                await_mined(&network, hash).await?;
                Ok::<_, String>((name, hash))
            }
            .await;
            if let Ok(mut g) = inner.lock() {
                *g = Some(signer);
            }
            result
        },
        move |result| Message::NameRecipientSet {
            result,
            signer: handoff,
        },
    )
}

/// Fetch a quote (the first network call — only ever from an explicit click).
fn spawn_cow_quote(host: CowHost, draft: SwapDraft, user: Address) -> Task<Message> {
    let chain = draft.chain;
    let req = cow_quote_request(&draft, user);
    Task::perform(
        async move { crate::cow::api::get_quote(chain, &req).await },
        move |result| Message::CowQuote { host, result },
    )
}

/// Discover a chain's pools from the 0xbow API and verify each via Helios. Fast
/// (one HTTP GET + a few verified `eth_call`s per pool) — the per-pool account
/// scan is decoupled into [`spawn_pool_account_sync`] so pools show immediately.
fn spawn_pool_discover(
    network: Arc<dyn BalanceFetcher>,
    base_url: String,
    chain: crate::chain::Chain,
) -> Task<Message> {
    Task::perform(
        async move {
            debug!(%chain, "privacy pools: discovering pools from the 0xbow API");
            let pools = crate::pool::discover::discover_pools(network.as_ref(), &base_url, chain)
                .await
                .map_err(|e| e.to_string())?;
            info!(%chain, count = pools.len(), "privacy pools: discovered + verified pools");
            Ok::<_, String>(pools)
        },
        move |result| Message::PoolsDiscovered { chain, result },
    )
}

/// Sync one pool's state (chunked `getLogs` scan + note recovery + Helios root
/// check) for the active account. Slow (historical scan) — runs in the
/// background after discovery so the pool list isn't blocked on it.
fn spawn_pool_account_sync(
    network: Arc<dyn BalanceFetcher>,
    account: privacy_pools::Account,
    info: crate::pool::PoolInfo,
    cached: Option<crate::pool::sync::CachedNotes>,
) -> Task<Message> {
    let pool = info.pool;
    let chain = info.chain;
    Task::perform(
        async move {
            let provider = network
                .provider(info.chain)
                .await
                .ok_or_else(|| "no RPC configured for this chain".to_string())?;
            let (state, notes) =
                crate::pool::sync::sync_state(&provider, &info, &account, cached.as_ref())
                    .await
                    .map_err(|e| e.to_string())?;
            debug!(
                symbol = %info.symbol,
                accounts = state.accounts.len(),
                to_block = state.to_block,
                "privacy pools: synced pool"
            );
            Ok::<_, String>((state, notes))
        },
        move |result| Message::PoolSynced {
            pool,
            chain,
            result,
        },
    )
}

/// Fetch which of `labels` are in the pool's approved Association Set (opt-in
/// 0xbow feed), for the per-account approval badges. Uses the shared proxied
/// HTTP client (not the RPC provider), so it takes no `network`.
fn spawn_pool_approval(
    asp_url: String,
    chain_id: u64,
    scope: String,
    pool: Address,
    labels: Vec<privacy_pools::Field>,
) -> Task<Message> {
    Task::perform(
        async move {
            crate::pool::asp::fetch_approved_labels(&asp_url, chain_id, &scope, &labels)
                .await
                .map_err(|e| e.to_string())
        },
        move |result| Message::PoolApproval { pool, result },
    )
}

/// Fetch a relayer fee quote for a withdrawal.
fn spawn_pool_quote(
    network: Arc<dyn BalanceFetcher>,
    req: pool_app::WithdrawRequest,
) -> Task<Message> {
    let _ = &network; // relayer client uses the shared proxied HTTP client, not the provider
    Task::perform(
        async move {
            let relayer = req
                .relayer
                .clone()
                .ok_or_else(|| "self-relay needs no quote".to_string())?;
            crate::pool::relayer::fetch_quote(
                &relayer,
                req.info.chain.chain_id(),
                req.amount,
                req.info.asset,
                req.target,
            )
            .await
            .map_err(|e| e.to_string())
        },
        move |result| Message::PoolQuoted { result },
    )
}

/// Title / subtitle / note for a pool sign-review overlay.
fn pool_review_labels(sign: &sign_review::PoolSign) -> (String, Option<String>, Option<String>) {
    match sign {
        sign_review::PoolSign::Deposit {
            symbol, approve, ..
        } => (
            format!("Deposit into the {symbol} pool"),
            Some("Funds join the pool's anonymity set.".to_string()),
            Some(
                if approve.is_some() {
                    "Two transactions: an ERC-20 approval, then the deposit. You pay gas; the \
                     deposit is public, withdrawals are private."
                } else {
                    "You pay gas from this account. The deposit is public; withdrawals are private."
                }
                .to_string(),
            ),
        ),
        sign_review::PoolSign::Ragequit { symbol, .. } => (
            format!("Ragequit the {symbol} deposit"),
            Some("Original-depositor exit — no relayer, no ASP.".to_string()),
            Some(
                "Ragequit returns your funds directly to this account and reveals that you \
                 deposited — it is NOT private. Use it only to recover funds."
                    .to_string(),
            ),
        ),
    }
}

/// Decode a pool EOA transaction's legs through the same clear-sign pipeline the
/// Send screen uses, so the review shows exactly what will be signed.
fn spawn_pool_prepare(
    network: Arc<dyn BalanceFetcher>,
    seq: u64,
    from: Address,
    sign: sign_review::PoolSign,
    local_names: std::collections::HashMap<Address, String>,
) -> Task<Message> {
    Task::perform(
        async move {
            match sign {
                sign_review::PoolSign::Deposit {
                    chain,
                    symbol,
                    to,
                    value,
                    calldata,
                    approve,
                } => {
                    let mut legs = Vec::new();
                    if let Some((token, appr)) = approve {
                        let decoded = crate::decode::clear_sign::decode_transaction(
                            network.as_ref(),
                            chain,
                            from,
                            token,
                            appr,
                            U256::ZERO,
                            local_names.clone(),
                        )
                        .await;
                        legs.push(sign_review::ReviewLeg {
                            title: format!("Approve {symbol}"),
                            to: token,
                            value: U256::ZERO,
                            chain,
                            decoded: Box::new(decoded),
                        });
                    }
                    let decoded = crate::decode::clear_sign::decode_transaction(
                        network.as_ref(),
                        chain,
                        from,
                        to,
                        calldata,
                        value,
                        local_names,
                    )
                    .await;
                    legs.push(sign_review::ReviewLeg {
                        title: format!("Deposit {symbol}"),
                        to,
                        value,
                        chain,
                        decoded: Box::new(decoded),
                    });
                    Ok::<_, String>(legs)
                }
                sign_review::PoolSign::Ragequit {
                    chain,
                    symbol,
                    pool,
                    calldata,
                } => {
                    let decoded = crate::decode::clear_sign::decode_transaction(
                        network.as_ref(),
                        chain,
                        from,
                        pool,
                        calldata,
                        U256::ZERO,
                        local_names,
                    )
                    .await;
                    Ok::<_, String>(vec![sign_review::ReviewLeg {
                        title: format!("Ragequit {symbol}"),
                        to: pool,
                        value: U256::ZERO,
                        chain,
                        decoded: Box::new(decoded),
                    }])
                }
            }
        },
        move |legs| Message::SignReviewPrepared {
            seq,
            steps: legs.map(|v| v.into_iter().map(sign_review::SignStep::RawTx).collect()),
        },
    )
}

/// Broadcast a confirmed pool EOA tx: an ERC-20 deposit sends + mines its
/// approval first, then the Entrypoint deposit; native deposits and ragequits
/// are a single tx. The parked signer is handed back for reclaim regardless.
fn spawn_pool_send(
    network: Arc<dyn BalanceFetcher>,
    handoff: SignerHandoff,
    desc: AccountDescriptor,
    sign: sign_review::PoolSign,
) -> Task<Message> {
    let inner = handoff.clone();
    let kind = match &sign {
        sign_review::PoolSign::Deposit { .. } => pool_app::PoolTxKind::Deposit,
        sign_review::PoolSign::Ragequit { .. } => pool_app::PoolTxKind::Ragequit,
    };
    Task::perform(
        async move {
            let signer = match take_live_signer(&inner, &desc).await {
                Ok(s) => s,
                Err(e) => return Err::<Option<String>, String>(e),
            };
            let result = async {
                let (chain, to, value, calldata, approve) = match sign {
                    sign_review::PoolSign::Deposit {
                        chain,
                        to,
                        value,
                        calldata,
                        approve,
                        ..
                    } => (chain, to, value, calldata, approve),
                    sign_review::PoolSign::Ragequit {
                        chain,
                        pool,
                        calldata,
                        ..
                    } => (chain, pool, U256::ZERO, calldata, None),
                };
                let provider = network
                    .provider(chain)
                    .await
                    .ok_or_else(|| "no RPC configured for this chain".to_string())?;
                if let Some((token, appr)) = approve {
                    let h = crate::cow::onchain::send_contract_call(
                        &provider,
                        &signer,
                        chain,
                        token,
                        U256::ZERO,
                        appr,
                    )
                    .await?;
                    crate::cow::onchain::wait_for_receipt(&provider, h, 60).await?;
                }
                let hash = crate::cow::onchain::send_contract_call(
                    &provider, &signer, chain, to, value, calldata,
                )
                .await?;
                Ok::<Option<String>, String>(Some(hash.to_string()))
            }
            .await;
            if let Ok(mut g) = inner.lock() {
                *g = Some(signer);
            }
            result
        },
        move |result| Message::PoolSubmitted {
            result,
            signer: Some(handoff),
            kind,
        },
    )
}

/// Wait for a broadcast pool deposit to mine, then re-sync `chain`. The deposit
/// is one fire-and-forget leg, so the immediate re-sync `set_submitted` requests
/// scans a chain that doesn't include it yet; this second pass — gated on the
/// receipt — is what makes the new note + anonymity set appear automatically. A
/// revert or a poll timeout still re-syncs (harmless: it just re-reads the
/// unchanged state), so a slow/failed mine never strands the pane on stale data.
fn spawn_pool_wait_and_resync(
    network: Arc<dyn BalanceFetcher>,
    chain: crate::chain::Chain,
    hash: TxHash,
    pool: Option<Address>,
) -> Task<Message> {
    Task::perform(
        async move {
            if let Some(provider) = network.provider(chain).await {
                let _ = crate::cow::onchain::wait_for_receipt(&provider, hash, 60).await;
            }
            (chain, pool)
        },
        |(chain, pool)| Message::PoolResync { chain, pool },
    )
}

/// Re-sync the pool, fetch the ASP set, assemble + prove the withdrawal, and POST
/// it to the relayer (which submits on-chain and pays gas). The user signs
/// nothing on-chain, so no signer is parked.
fn spawn_pool_relayed_withdraw(
    network: Arc<dyn BalanceFetcher>,
    account: privacy_pools::Account,
    req: pool_app::WithdrawRequest,
    quote: crate::pool::relayer::QuoteResponse,
    asp_url: Option<String>,
    cached: Option<crate::pool::sync::CachedNotes>,
) -> Task<Message> {
    Task::perform(
        async move {
            let info = req.info.clone();
            let relayer = req
                .relayer
                .clone()
                .ok_or_else(|| "no relayer selected".to_string())?;
            let asp_url = asp_url.ok_or_else(|| {
                "enable the 0xbow association-set feed in Settings to withdraw privately"
                    .to_string()
            })?;
            let provider = network
                .provider(info.chain)
                .await
                .ok_or_else(|| "no RPC configured for this chain".to_string())?;

            // Recover this account's notes incrementally (cache + tail scan) —
            // not a from-deploy-block rescan.
            let (state, _notes) =
                crate::pool::sync::sync_state(&provider, &info, &account, cached.as_ref())
                    .await
                    .map_err(|e| e.to_string())?;
            let pa = state
                .accounts
                .get(req.account)
                .ok_or_else(|| "pool account not found — re-sync and retry".to_string())?;

            // Association set (compliance) + the state-tree leaves, both from the
            // single ASP fetch. The scope selects this pool (X-Pool-Scope header).
            let asp = crate::pool::asp::fetch_mt_leaves(
                &asp_url,
                info.chain.chain_id(),
                &info.scope_decimal(),
            )
            .await
            .map_err(|e| e.to_string())?;
            // State tree from the API, Helios-verified against the on-chain root.
            // If it's stale or unverifiable, fall back to a fresh full leaf scan.
            let (state_leaves, state_tree) = match crate::pool::sync::verified_state_tree(
                network.as_ref(),
                &info,
                &asp.state_leaves,
            )
            .await
            {
                Ok(tree) => (asp.state_leaves.clone(), tree),
                Err(e) => {
                    warn!(error = %e, "privacy pools: API state tree unusable — scanning leaves");
                    let logs = crate::pool::sync::scan(
                        &provider,
                        &info,
                        crate::pool::scan_from_block(info.chain),
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                    // Verify the *scanned* tree too — the raw-RPC log set isn't
                    // Helios-verified, so anchor it in `currentRoot()` just like
                    // the API path rather than trusting it blindly (fail closed;
                    // a bad/stale tree errors here instead of reverting on-chain).
                    let leaves = logs.state_leaves();
                    let tree =
                        crate::pool::sync::verified_state_tree(network.as_ref(), &info, &leaves)
                            .await
                            .map_err(|e| e.to_string())?;
                    (leaves, tree)
                }
            };
            let dest = crate::pool::flow::destination_from_quote(&info, &quote, req.target)
                .map_err(|e| e.to_string())?;
            let plan = crate::pool::flow::plan_withdrawal(
                &account,
                &info,
                pa,
                &state_leaves,
                &state_tree,
                &asp.asp_leaves,
                req.amount,
                &dest,
            )
            .map_err(|e| e.to_string())?;
            crate::pool::flow::matches_quote(&plan, &quote).map_err(|e| e.to_string())?;

            // Prove off the async runtime (CPU-bound, seconds).
            let inputs = plan.inputs.clone();
            let proof =
                tokio::task::spawn_blocking(move || crate::pool::prover::prove_withdraw(&inputs))
                    .await
                    .map_err(|e| format!("prove task: {e}"))?
                    .map_err(|e| e.to_string())?;

            // Hand the proof to the relayer to submit + pay gas.
            let res = crate::pool::relayer::submit(
                &relayer,
                info.chain.chain_id(),
                &info.scope_decimal(),
                plan.withdrawal.processooor,
                &plan.withdrawal.data,
                crate::pool::flow::snarkjs_proof(&proof),
                crate::pool::flow::public_signals(&proof),
                quote.fee_commitment.clone(),
            )
            .await
            .map_err(|e| e.to_string())?;
            Ok::<Option<String>, String>(res.tx_hash)
        },
        move |result| Message::PoolSubmitted {
            result,
            signer: None,
            kind: pool_app::PoolTxKind::Withdrawal,
        },
    )
}

/// Re-sync, prove the ragequit (commitment) off-thread, and build the
/// `Pool.ragequit` calldata; the result opens the clear-sign review.
fn spawn_pool_ragequit_prove(
    network: Arc<dyn BalanceFetcher>,
    account: privacy_pools::Account,
    info: crate::pool::PoolInfo,
    account_index: usize,
) -> Task<Message> {
    Task::perform(
        async move {
            let provider = network
                .provider(info.chain)
                .await
                .ok_or_else(|| "no RPC configured for this chain".to_string())?;
            let logs =
                crate::pool::sync::scan(&provider, &info, crate::pool::scan_from_block(info.chain))
                    .await
                    .map_err(|e| e.to_string())?;
            let accounts = privacy_pools::recover_accounts(&account, info.scope, &logs, 10)
                .map_err(|e| e.to_string())?;
            let pa = accounts
                .get(account_index)
                .ok_or_else(|| "pool account not found — re-sync and retry".to_string())?;
            let note = pa
                .spendable()
                .ok_or_else(|| "nothing to ragequit in this pool account".to_string())?;
            let inputs = crate::pool::flow::ragequit_plan(note);
            let proof =
                tokio::task::spawn_blocking(move || crate::pool::prover::prove_ragequit(&inputs))
                    .await
                    .map_err(|e| format!("prove task: {e}"))?
                    .map_err(|e| e.to_string())?;
            let calldata =
                crate::pool::flow::ragequit_calldata(&proof).map_err(|e| e.to_string())?;
            Ok::<sign_review::PoolSign, String>(sign_review::PoolSign::Ragequit {
                chain: info.chain,
                symbol: info.symbol.clone(),
                pool: info.pool,
                calldata,
            })
        },
        move |result| Message::PoolRagequitReady { result },
    )
}

/// Place an order: ERC-20 (allowance → approve → sign → POST) or native ETH
/// (EthFlow `createOrder`). Runs the whole sequence in one task; the modal shows
/// a "Placing…" phase meanwhile. The signer rides in via `handoff` and back out
/// in the result message.
fn spawn_cow_place(
    network: Arc<dyn BalanceFetcher>,
    host: CowHost,
    handoff: SignerHandoff,
    desc: AccountDescriptor,
    draft: SwapDraft,
    quote: crate::cow::api::QuoteResponse,
    user: Address,
) -> Task<Message> {
    let inner = handoff.clone();
    let chain = draft.chain;
    Task::perform(
        async move {
            let provider =
                match provider_for(&network, crate::chain::NetworkId::Builtin(chain)).await {
                    Some(p) => p,
                    None => {
                        return Err::<TrackedOrder, String>("no execution RPC configured".into());
                    }
                };
            let signer = match take_live_signer(&inner, &desc).await {
                Ok(s) => s,
                Err(e) => return Err::<TrackedOrder, String>(e),
            };
            let result = cow_place_order(&network, &provider, &signer, &draft, &quote, user).await;
            if let Ok(mut g) = inner.lock() {
                *g = Some(signer);
            }
            result
        },
        move |result| Message::CowPlaced {
            host,
            result,
            signer: handoff,
        },
    )
}

/// revm preflight of a CoW on-chain leg (ERC-20 `approve` or EthFlow
/// `createOrder`) against Helios-verified state. Returns `Err` with the decoded
/// revert reason if the tx would revert/halt — so we never spend gas on a doomed
/// transaction (critical for the native path, where the gas is real ETH). A sim
/// that can't run (state unavailable, custom network) is advisory and passes.
/// The swap itself settles off-chain via solvers, so this covers only the
/// on-chain legs — there's nothing else for revm to simulate.
async fn cow_preflight_sim(
    network: &Arc<dyn BalanceFetcher>,
    chain: crate::chain::Chain,
    from: Address,
    to: Address,
    value: U256,
    input: Bytes,
) -> Result<(), String> {
    use crate::wallet::sim::{CallSpec, SimOutcome, simulate_call};
    let spec = CallSpec {
        chain,
        from,
        to,
        value,
        input,
        nonce: 0,
    };
    match simulate_call(network.clone(), &spec).await {
        Ok(r) => match r.outcome {
            SimOutcome::Revert { reason, .. } => Err(format!("preflight: would revert — {reason}")),
            SimOutcome::Halt { reason } => Err(format!("preflight: would fail — {reason}")),
            // Success or Unavailable → don't block.
            _ => Ok(()),
        },
        Err(e) => {
            warn!(error = %e, "cow: preflight simulation unavailable (proceeding)");
            Ok(())
        }
    }
}

/// The order-placement sequence shared by both surfaces.
async fn cow_place_order(
    network: &Arc<dyn BalanceFetcher>,
    provider: &alloy::providers::RootProvider<alloy::network::Ethereum>,
    signer: &KaoSigner,
    draft: &SwapDraft,
    quote: &crate::cow::api::QuoteResponse,
    user: Address,
) -> Result<TrackedOrder, String> {
    let chain = draft.chain;
    let q = &quote.quote;
    // Modern CoW orders carry feeAmount = 0; the user parts with the full input
    // (quote sellAmount + feeAmount) and solvers take their fee from the price.
    let full_sell = q.sell_amount.saturating_add(q.fee_amount);
    // Market-order appData: `orderClass = market` is what makes solvers fill the
    // order at the quoted price. Without it the orderbook books a *limit* order,
    // which only fills if the price gap covers the fee — so a near-market swap
    // sits OPEN forever. We sign the hash and provide the matching pre-image.
    let (full_app_data, app_data_hash) = cow::market_app_data(draft.slippage_bps);
    if draft.is_native {
        // Native ETH → EthFlow on-chain createOrder (msg.value = the full sell).
        let data = cow::ethflow::build_ethflow_data(
            draft.buy_token,
            user,
            full_sell,
            q.buy_amount,
            q.valid_to,
            quote.id.unwrap_or_default(),
            draft.slippage_bps,
            app_data_hash,
        );
        // The native path never POSTs an order body, so upload the appData
        // pre-image first — otherwise the orderbook only sees the bare hash and
        // books a limit order. Best-effort: a transient PUT failure shouldn't
        // burn the user's ETH, though the order then risks limit classification.
        if let Err(e) =
            cow::api::upload_app_data(chain, &format!("{app_data_hash:#x}"), &full_app_data).await
        {
            warn!(error = %e, "cow: appData upload failed (native order may book as limit)");
        }
        let calldata = cow::ethflow::create_order_calldata(&data);
        let value = cow::ethflow::msg_value(&data);
        // revm preflight before spending gas: catch a reverting createOrder
        // (wrong params, contract guards) without losing the up-front ETH.
        cow_preflight_sim(network, chain, user, cow::ETHFLOW, value, calldata.clone()).await?;
        let hash = cow::onchain::send_contract_call(
            provider,
            signer,
            chain,
            cow::ETHFLOW,
            value,
            calldata,
        )
        .await?;
        cow::onchain::wait_for_receipt(provider, hash, 40).await?;
        let uid = cow::ethflow::ethflow_uid(&data, chain)?;
        Ok(TrackedOrder {
            uid: cow::order::uid_hex(&uid),
            chain,
            owner: user,
            kind: cow::order::OrderKind::Sell,
            sell_token: draft.sell_token,
            buy_token: draft.buy_token,
            sell_symbol: draft.sell_symbol.clone(),
            buy_symbol: draft.buy_symbol.clone(),
            sell_amount: draft.sell_amount,
            buy_amount: cow::order::apply_slippage(q.buy_amount, draft.slippage_bps),
            sell_decimals: draft.sell_decimals,
            buy_decimals: draft.buy_decimals,
            valid_to: q.valid_to,
            status: OrderStatus::Open,
            executed: None,
            is_ethflow: true,
        })
    } else {
        // ERC-20 → ensure the vault relayer is approved, then sign + POST.
        let allowance = cow::onchain::read_allowance(provider, draft.sell_token, user).await?;
        info!(
            chain_id = chain.chain_id(),
            owner = %user,
            token = %draft.sell_token,
            allowance = %allowance,
            full_sell = %full_sell,
            needs_approve = allowance < full_sell,
            "cow: erc20 allowance check",
        );
        let needs_approve = allowance < full_sell;
        if needs_approve {
            // revm preflight the approve — catches e.g. USDT, which reverts on a
            // non-zero→non-zero approve, before we spend gas on it.
            cow_preflight_sim(
                network,
                chain,
                user,
                draft.sell_token,
                U256::ZERO,
                cow::onchain::approve_calldata(U256::MAX),
            )
            .await?;
            let hash =
                cow::onchain::approve_relayer(provider, signer, chain, draft.sell_token, U256::MAX)
                    .await?;
            cow::onchain::wait_for_receipt(provider, hash, 40).await?;
        }
        let order = cow::order::build_sell_order(
            draft.sell_token,
            draft.buy_token,
            user,
            full_sell,
            q.buy_amount,
            q.valid_to,
            draft.slippage_bps,
            app_data_hash,
        );
        let domain = cow::order::cow_domain(chain);
        let sig = cow::order::sign_order(signer, &order, &domain).await?;
        // Register the appData doc first, mirroring the cow-sdk (which uploads
        // before posting). The order body also carries the full pre-image, so a
        // transient failure here isn't fatal — log and proceed.
        let app_data_hex = format!("{app_data_hash:#x}");
        if let Err(e) = cow::api::upload_app_data(chain, &app_data_hex, &full_app_data).await {
            warn!(error = %e, "cow: appData upload failed (proceeding; order carries the pre-image)");
        }
        let body = cow::api::OrderCreation {
            sell_token: order.sellToken,
            buy_token: order.buyToken,
            receiver: order.receiver,
            sell_amount: order.sellAmount,
            buy_amount: order.buyAmount,
            valid_to: order.validTo,
            // POST the exact pre-image of the signed appData hash (and the hash
            // itself) so the orderbook reproduces it and reads orderClass=market.
            app_data: full_app_data,
            app_data_hash: app_data_hex,
            fee_amount: order.feeAmount,
            kind: "sell".to_string(),
            partially_fillable: false,
            sell_token_balance: "erc20".to_string(),
            buy_token_balance: "erc20".to_string(),
            signing_scheme: "eip712".to_string(),
            signature: format!("0x{}", alloy::hex::encode(sig.as_bytes())),
            from: user,
            quote_id: quote.id,
        };
        // POST with a short retry when we *just* approved: on Base a tx is
        // visible to us via a ~200ms flashblock preconfirmation, but CoW's
        // orderbook only sees the allowance once it indexes the canonical block
        // — a few seconds later. POSTing in that window 400s with "must give
        // allowance to VaultRelayer" even though the approval is on-chain. Retry
        // a few times so the orderbook can catch up. (No race when allowance was
        // already present — `needs_approve` is false and we post once.)
        let mut uid_result = cow::api::post_order(chain, &body).await;
        if needs_approve {
            let mut attempt = 0u32;
            while let Err(e) = &uid_result {
                if attempt >= 5 || !e.to_lowercase().contains("allowance") {
                    break;
                }
                attempt += 1;
                warn!(
                    attempt,
                    error = %e,
                    "cow: orderbook hasn't indexed the fresh approval yet; retrying POST",
                );
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                uid_result = cow::api::post_order(chain, &body).await;
            }
        }
        let uid = uid_result?;
        Ok(TrackedOrder {
            uid,
            chain,
            owner: user,
            kind: cow::order::OrderKind::Sell,
            sell_token: draft.sell_token,
            buy_token: draft.buy_token,
            sell_symbol: draft.sell_symbol.clone(),
            buy_symbol: draft.buy_symbol.clone(),
            sell_amount: draft.sell_amount,
            buy_amount: order.buyAmount,
            sell_decimals: draft.sell_decimals,
            buy_decimals: draft.buy_decimals,
            valid_to: q.valid_to,
            status: OrderStatus::Open,
            executed: None,
            is_ethflow: false,
        })
    }
}

/// Everything the Safe-swap place task needs that isn't in the draft/quote:
/// the Safe identity + chain, the version/trust gate inputs, the owner
/// descriptors to sign with (built into live signers inside the task), and a
/// preferred Local gas-payer (else the first owner self-pays the approval).
/// Assembled on the UI thread by [`WalletScreen::build_safe_swap_ctx`].
struct SafeSwapCtx {
    safe: Address,
    chain: crate::chain::Chain,
    version: String,
    trust: crate::wallet::SafeTrust,
    signer_owners: Vec<AccountDescriptor>,
    local_executor_key: Option<B256>,
}

/// What a Safe name-write task needs: the Safe address, the owner descriptors to
/// sign with (built into live signers inside the task), and a preferred Local
/// gas-payer (else the first owner self-pays). Mainnet is implied — the name
/// registries are Mainnet-pinned, and [`WalletScreen::build_safe_name_ctx`]
/// only yields a context for a Mainnet Safe.
#[derive(Clone)]
struct SafeNameCtx {
    safe: Address,
    owners: Vec<AccountDescriptor>,
    executor_key: Option<B256>,
}

/// Build, sign (with the Safe's owners), and broadcast `(to, value, calldata)`
/// as a Safe `execTransaction` on `chain`; returns the execTransaction hash.
/// The generic Safe-call executor behind the name-write tasks — same shape as
/// the swap approval / EthFlow legs (build at the live nonce, cross-check the
/// hash, sign every owner, execute via the gas-paying executor).
#[allow(clippy::too_many_arguments)]
async fn execute_call_as_safe_tx(
    network: &Arc<dyn BalanceFetcher>,
    provider: &alloy::providers::RootProvider<alloy::network::Ethereum>,
    owners: &[KaoSigner],
    executor: &KaoSigner,
    safe: Address,
    chain: crate::chain::Chain,
    to: Address,
    value: U256,
    calldata: Bytes,
) -> Result<TxHash, String> {
    use crate::safe::tx::{
        Operation, SafeTxInput, assemble_signatures, build_safe_tx_with_nonce, current_safe_nonce,
        execute_safe_tx, safe_domain, safe_tx_hash, sign_owner, verify_safe_tx_before_signing,
    };
    let nonce = current_safe_nonce(network.as_ref(), safe, chain).await?;
    let tx = build_safe_tx_with_nonce(
        SafeTxInput {
            to,
            value,
            data: calldata,
            operation: Operation::Call,
        },
        nonce,
    );
    let domain = safe_domain(safe, chain);
    let local_hash = safe_tx_hash(&tx, &domain);
    verify_safe_tx_before_signing(network.as_ref(), &tx, safe, chain, local_hash).await?;
    let mut sigs = Vec::with_capacity(owners.len());
    for owner in owners {
        sigs.push(sign_owner(owner, &tx, &domain, local_hash).await?);
    }
    let packed = assemble_signatures(sigs)?;
    execute_safe_tx(provider, executor, safe, chain, tx, packed).await
}

/// Build the Safe's owner signers + executor and run a single Mainnet name
/// `execTransaction` carrying `call` = `(to, value, calldata)`, waiting for it
/// to mine. Shared by every `spawn_name_*_safe`.
async fn run_name_write_as_safe(
    network: &Arc<dyn BalanceFetcher>,
    ctx: &SafeNameCtx,
    call: (Address, U256, Bytes),
) -> Result<TxHash, String> {
    let chain = crate::chain::Chain::Mainnet;
    let provider = network
        .provider(chain)
        .await
        .ok_or_else(|| "no Ethereum mainnet RPC configured".to_string())?;
    let mut owners = Vec::with_capacity(ctx.owners.len());
    for desc in &ctx.owners {
        owners.push(crate::wallet::build_owner_signer(desc).await?);
    }
    if owners.is_empty() {
        return Err("no signable owners for this Safe".into());
    }
    let local_exec;
    let executor: &KaoSigner = match ctx.executor_key {
        Some(key) => {
            let s = crate::wallet::signer_from_bytes(&key).map_err(|e| e.to_string())?;
            local_exec = KaoSigner::Local(s);
            &local_exec
        }
        None => &owners[0],
    };
    let (to, value, cd) = call;
    let hash = execute_call_as_safe_tx(
        network, &provider, &owners, executor, ctx.safe, chain, to, value, cd,
    )
    .await?;
    await_mined(network, hash).await?;
    Ok(hash)
}

/// Commit-reveal step 1 from a Safe (the commitment bakes `plan.owner` = the
/// Safe). Mirrors [`spawn_name_commit`] but executes as a Safe tx; the parked
/// active signer rides back via the `handoff` untouched.
fn spawn_name_commit_safe(
    network: Arc<dyn BalanceFetcher>,
    handoff: SignerHandoff,
    ctx: SafeNameCtx,
    plan: RegisterPlan,
) -> Task<Message> {
    Task::perform(
        async move {
            let call = crate::names::manage::commit_call_for(&*network, &plan).await?;
            let hash = run_name_write_as_safe(&network, &ctx, call).await?;
            Ok::<_, String>((plan.clone(), hash))
        },
        move |result| Message::NameCommitted {
            result,
            signer: handoff,
        },
    )
}

/// Commit-reveal step 2 (reveal/register) from a Safe.
fn spawn_name_register_safe(
    network: Arc<dyn BalanceFetcher>,
    handoff: SignerHandoff,
    ctx: SafeNameCtx,
    plan: RegisterPlan,
) -> Task<Message> {
    let name = format!("{}{}", plan.label, plan.namespace.tld());
    Task::perform(
        async move {
            let call = crate::names::manage::register_call_for(&*network, &plan).await?;
            let hash = run_name_write_as_safe(&network, &ctx, call).await?;
            Ok::<_, String>((name, hash))
        },
        move |result| Message::NameRegistered {
            result,
            signer: handoff,
        },
    )
}

/// XNS one-shot registration from a Safe — the Safe becomes the permanent owner
/// (XNS binds to the inner `msg.sender`).
fn spawn_name_register_xns_safe(
    network: Arc<dyn BalanceFetcher>,
    handoff: SignerHandoff,
    ctx: SafeNameCtx,
    namespace: String,
    label: String,
) -> Task<Message> {
    let name = format!("{label}.{namespace}");
    Task::perform(
        async move {
            let call =
                crate::names::manage::register_xns_call_for(&*network, &namespace, &label).await?;
            let hash = run_name_write_as_safe(&network, &ctx, call).await?;
            Ok::<_, String>((name, hash))
        },
        move |result| Message::NameRegistered {
            result,
            signer: handoff,
        },
    )
}

/// Renew an owned name from a Safe.
fn spawn_name_renew_safe(
    network: Arc<dyn BalanceFetcher>,
    handoff: SignerHandoff,
    ctx: SafeNameCtx,
    namespace: Namespace,
    label: String,
    years: u32,
) -> Task<Message> {
    let name = format!("{label}{}", namespace.tld());
    Task::perform(
        async move {
            let duration = crate::names::registrar::ens_duration_secs(years);
            let call = crate::names::manage::renew_call_for(&*network, namespace, &label, duration)
                .await?;
            let hash = run_name_write_as_safe(&network, &ctx, call).await?;
            Ok::<_, String>((name, hash))
        },
        move |result| Message::NameRenewed {
            result,
            signer: handoff,
        },
    )
}

/// Repoint an owned name from a Safe (the resolver authorizes the Safe owner).
fn spawn_name_set_recipient_safe(
    network: Arc<dyn BalanceFetcher>,
    handoff: SignerHandoff,
    ctx: SafeNameCtx,
    namespace: Namespace,
    label: String,
    recipient: Address,
) -> Task<Message> {
    let name = format!("{label}{}", namespace.tld());
    Task::perform(
        async move {
            let call = crate::names::manage::set_recipient_call_for(namespace, &label, recipient);
            let hash = run_name_write_as_safe(&network, &ctx, call).await?;
            Ok::<_, String>((name, hash))
        },
        move |result| Message::NameRecipientSet {
            result,
            signer: handoff,
        },
    )
}

/// Place a CoW order *from a Safe* via EIP-1271. Builds live signers for the
/// Safe's owners (software or hardware), then runs [`cow_place_order_safe`].
/// Reuses the `CowPlaced` result message — the `handoff` carries the parked
/// active signer straight back through untouched (the Safe path signs with
/// freshly-built owner signers, not the active one).
fn spawn_cow_place_safe(
    network: Arc<dyn BalanceFetcher>,
    host: CowHost,
    handoff: SignerHandoff,
    draft: SwapDraft,
    quote: crate::cow::api::QuoteResponse,
    ctx: SafeSwapCtx,
) -> Task<Message> {
    Task::perform(
        async move {
            let provider = match provider_for(&network, crate::chain::NetworkId::Builtin(ctx.chain))
                .await
            {
                Some(p) => p,
                None => return Err::<TrackedOrder, String>("no execution RPC configured".into()),
            };
            // Build one signer per owner up front (hardware opens a transport
            // once), reused for both the approval SafeTx and the EIP-1271 order.
            let mut owners = Vec::with_capacity(ctx.signer_owners.len());
            for desc in &ctx.signer_owners {
                match crate::wallet::build_owner_signer(desc).await {
                    Ok(s) => owners.push(s),
                    Err(e) => return Err(e), // already friendly (see build_owner_signer)
                }
            }
            if owners.is_empty() {
                return Err("no signable owners for this Safe".into());
            }
            // Executor: prefer a Local gas-payer; else the first owner self-pays.
            let local_exec;
            let executor: &KaoSigner = match ctx.local_executor_key {
                Some(key) => {
                    let s = crate::wallet::signer_from_bytes(&key)
                        .map_err(|e| format!("derive executor: {e}"))?;
                    local_exec = KaoSigner::Local(s);
                    &local_exec
                }
                None => &owners[0],
            };
            cow_place_order_safe(&network, &provider, &owners, executor, &draft, &quote, &ctx).await
        },
        move |result| Message::CowPlaced {
            host,
            result,
            signer: handoff,
        },
    )
}

/// The Safe variant of [`cow_place_order`] — ERC-20 sells only. Every signature
/// is a Safe owner action: the vault-relayer approval (when the Safe's
/// allowance is short) is an on-chain `execTransaction`, and the order itself
/// carries an EIP-1271 signature the orderbook validates against the Safe's
/// `isValidSignature`. We verify that signature against the live contract
/// before POSTing, so a bad derivation fails closed. Native-ETH (EthFlow) sells
/// aren't supported from a Safe yet — EthFlow's `createOrder` is a separate
/// on-chain Safe-tx mechanism — so they're rejected up front.
#[allow(clippy::too_many_arguments)]
/// Build the Safe transaction that places a native-ETH EthFlow order: a
/// value-bearing `Call` to `ETHFLOW.createOrder`, the ETH (`msg_value` = the
/// sell amount) forwarded from the Safe's balance by `execTransaction`. Pure —
/// no network/signer — so the `(to, value, selector)` wrapping is unit-testable.
fn ethflow_safe_tx(data: &cow::ethflow::EthFlowData, nonce: u64) -> crate::safe::SafeTx {
    use crate::safe::tx::{Operation, SafeTxInput, build_safe_tx_with_nonce};
    build_safe_tx_with_nonce(
        SafeTxInput {
            to: cow::ETHFLOW,
            value: cow::ethflow::msg_value(data),
            data: cow::ethflow::create_order_calldata(data),
            operation: Operation::Call,
        },
        nonce,
    )
}

async fn cow_place_order_safe(
    network: &Arc<dyn BalanceFetcher>,
    provider: &alloy::providers::RootProvider<alloy::network::Ethereum>,
    owners: &[KaoSigner],
    executor: &KaoSigner,
    draft: &SwapDraft,
    quote: &crate::cow::api::QuoteResponse,
    ctx: &SafeSwapCtx,
) -> Result<TrackedOrder, String> {
    use crate::safe::tx::{
        Operation, SafeTxInput, assemble_signatures, build_safe_tx_with_nonce, current_safe_nonce,
        ensure_signable_version, execute_safe_tx, safe_domain as safe_tx_domain, safe_tx_hash,
        sign_owner, verify_safe_tx_before_signing,
    };
    if let Some(reason) = ctx.trust.signing_block_reason() {
        return Err(reason.to_string());
    }
    ensure_signable_version(&ctx.version)?;

    let chain = ctx.chain;
    let safe = ctx.safe;
    let q = &quote.quote;
    let full_sell = q.sell_amount.saturating_add(q.fee_amount);
    let (full_app_data, app_data_hash) = cow::market_app_data(draft.slippage_bps);

    if draft.is_native {
        // Native ETH → the Safe calls `ETHFLOW.createOrder` as a value-bearing
        // `execTransaction`. The EthFlow contract becomes the GPv2 order owner
        // and signs the WETH order via its own EIP-1271, so — unlike the ERC-20
        // path — there's no order signature to build and no relayer approval:
        // the Safe's ETH rides along as the inner-call value. The Safe is the
        // `createOrder` caller, so an expiry refund returns to the Safe, and
        // `receiver = safe` sends the bought tokens to the Safe.
        let data = cow::ethflow::build_ethflow_data(
            draft.buy_token,
            safe,
            full_sell,
            q.buy_amount,
            q.valid_to,
            quote.id.unwrap_or_default(),
            draft.slippage_bps,
            app_data_hash,
        );
        // The native path never POSTs an order body, so the orderbook learns the
        // appData (and thus `orderClass = market`) only from this upload.
        let app_data_hex = format!("{app_data_hash:#x}");
        if let Err(e) = cow::api::upload_app_data(chain, &app_data_hex, &full_app_data).await {
            warn!(error = %e, "cow(safe): appData upload failed (native order may book as limit)");
        }
        let nonce = current_safe_nonce(network.as_ref(), safe, chain).await?;
        let tx = ethflow_safe_tx(&data, nonce);
        // revm-preflight the inner `createOrder` the Safe will make — native gas
        // is real ETH, so catch a revert (wrong params, underfunded) before
        // spending it. Advisory: an unrunnable sim doesn't block.
        cow_preflight_sim(network, chain, safe, tx.to, tx.value, tx.data.clone()).await?;
        let domain = safe_tx_domain(safe, chain);
        let local_hash = safe_tx_hash(&tx, &domain);
        verify_safe_tx_before_signing(network.as_ref(), &tx, safe, chain, local_hash).await?;
        let mut sigs = Vec::with_capacity(owners.len());
        for owner in owners {
            sigs.push(sign_owner(owner, &tx, &domain, local_hash).await?);
        }
        let packed = assemble_signatures(sigs)?;
        let hash = execute_safe_tx(provider, executor, safe, chain, tx, packed).await?;
        cow::onchain::wait_for_receipt(provider, hash, 40).await?;
        let uid = cow::ethflow::ethflow_uid(&data, chain)?;
        return Ok(TrackedOrder {
            uid: cow::order::uid_hex(&uid),
            chain,
            owner: safe,
            kind: cow::order::OrderKind::Sell,
            sell_token: draft.sell_token,
            buy_token: draft.buy_token,
            sell_symbol: draft.sell_symbol.clone(),
            buy_symbol: draft.buy_symbol.clone(),
            sell_amount: draft.sell_amount,
            buy_amount: cow::order::apply_slippage(q.buy_amount, draft.slippage_bps),
            sell_decimals: draft.sell_decimals,
            buy_decimals: draft.buy_decimals,
            valid_to: q.valid_to,
            status: OrderStatus::Open,
            executed: None,
            is_ethflow: true,
        });
    }

    // ── ERC-20 path: approve the vault relayer (if short), then place an
    //    EIP-1271-signed order. ──
    // 1. Approve the vault relayer if the Safe's allowance is short — as a Safe
    //    `execTransaction` signed by the owners, mined before we sign the order.
    let allowance = cow::onchain::read_allowance(provider, draft.sell_token, safe).await?;
    let needs_approve = allowance < full_sell;
    info!(
        chain_id = chain.chain_id(),
        safe = %safe,
        token = %draft.sell_token,
        allowance = %allowance,
        full_sell = %full_sell,
        needs_approve,
        "cow(safe): erc20 allowance check",
    );
    if needs_approve {
        let nonce = current_safe_nonce(network.as_ref(), safe, chain).await?;
        let approve_tx = build_safe_tx_with_nonce(
            SafeTxInput {
                to: draft.sell_token,
                value: U256::ZERO,
                data: cow::onchain::approve_calldata(U256::MAX),
                operation: Operation::Call,
            },
            nonce,
        );
        let domain = safe_tx_domain(safe, chain);
        let local_hash = safe_tx_hash(&approve_tx, &domain);
        verify_safe_tx_before_signing(network.as_ref(), &approve_tx, safe, chain, local_hash)
            .await?;
        let mut sigs = Vec::with_capacity(owners.len());
        for owner in owners {
            sigs.push(sign_owner(owner, &approve_tx, &domain, local_hash).await?);
        }
        let packed = assemble_signatures(sigs)?;
        let hash = execute_safe_tx(provider, executor, safe, chain, approve_tx, packed).await?;
        cow::onchain::wait_for_receipt(provider, hash, 40).await?;
    }

    // 2. Build the order (receiver = the Safe), sign EIP-1271, and verify the
    //    blob against the live Safe before it leaves the wallet.
    let order = cow::order::build_sell_order(
        draft.sell_token,
        draft.buy_token,
        safe,
        full_sell,
        q.buy_amount,
        q.valid_to,
        draft.slippage_bps,
        app_data_hash,
    );
    let order_domain = cow::order::cow_domain(chain);
    let order_digest = cow::order::order_digest(&order, &order_domain);
    let signature = cow::safe_sig::sign_eip1271_digest(owners, order_digest, safe, chain).await?;
    cow::safe_sig::verify_eip1271_on_chain(network.as_ref(), safe, chain, order_digest, &signature)
        .await?;

    // 3. Upload the appData pre-image, then POST the eip1271 order.
    let app_data_hex = format!("{app_data_hash:#x}");
    if let Err(e) = cow::api::upload_app_data(chain, &app_data_hex, &full_app_data).await {
        warn!(error = %e, "cow(safe): appData upload failed (proceeding; order carries the pre-image)");
    }
    let body = cow::api::OrderCreation {
        sell_token: order.sellToken,
        buy_token: order.buyToken,
        receiver: order.receiver,
        sell_amount: order.sellAmount,
        buy_amount: order.buyAmount,
        valid_to: order.validTo,
        app_data: full_app_data,
        app_data_hash: app_data_hex,
        fee_amount: order.feeAmount,
        kind: "sell".to_string(),
        partially_fillable: false,
        sell_token_balance: "erc20".to_string(),
        buy_token_balance: "erc20".to_string(),
        signing_scheme: "eip1271".to_string(),
        signature: format!("0x{}", alloy::hex::encode(&signature)),
        from: safe,
        quote_id: quote.id,
    };
    // Same fresh-approval indexing race as the EOA path: after our approval
    // mines, the orderbook may not see the Safe's allowance for a few seconds.
    let mut uid_result = cow::api::post_order(chain, &body).await;
    if needs_approve {
        let mut attempt = 0u32;
        while let Err(e) = &uid_result {
            if attempt >= 5 || !e.to_lowercase().contains("allowance") {
                break;
            }
            attempt += 1;
            warn!(attempt, error = %e, "cow(safe): orderbook hasn't indexed the fresh approval yet; retrying POST");
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            uid_result = cow::api::post_order(chain, &body).await;
        }
    }
    let uid = uid_result?;
    Ok(TrackedOrder {
        uid,
        chain,
        owner: safe,
        kind: cow::order::OrderKind::Sell,
        sell_token: draft.sell_token,
        buy_token: draft.buy_token,
        sell_symbol: draft.sell_symbol.clone(),
        buy_symbol: draft.buy_symbol.clone(),
        sell_amount: draft.sell_amount,
        buy_amount: order.buyAmount,
        sell_decimals: draft.sell_decimals,
        buy_decimals: draft.buy_decimals,
        valid_to: q.valid_to,
        status: OrderStatus::Open,
        executed: None,
        is_ethflow: false,
    })
}

/// Off-chain cancel an ERC-20 order (signed `DELETE /orders`). EthFlow orders
/// cancel on-chain (deferred) and never reach here — the Apps pane hides their
/// cancel affordance.
fn spawn_cow_cancel(
    handoff: SignerHandoff,
    desc: AccountDescriptor,
    host: CowHost,
    chain: crate::chain::Chain,
    uid: String,
) -> Task<Message> {
    let inner = handoff.clone();
    let uid_for_msg = uid.clone();
    Task::perform(
        async move {
            let signer = match take_live_signer(&inner, &desc).await {
                Ok(s) => s,
                Err(e) => return Err::<(), String>(e),
            };
            let res = cow_cancel(&signer, chain, &uid).await;
            if let Ok(mut g) = inner.lock() {
                *g = Some(signer);
            }
            res
        },
        move |result| Message::CowCancel {
            host,
            uid: uid_for_msg.clone(),
            result,
            signer: handoff,
        },
    )
}

async fn cow_cancel(
    signer: &KaoSigner,
    chain: crate::chain::Chain,
    uid: &str,
) -> Result<(), String> {
    let bytes = parse_order_uid(uid)?;
    let domain = cow::order::cow_domain(chain);
    let sig = cow::order::sign_cancellations(signer, &[bytes], &domain).await?;
    let body = cow::api::CancellationBody {
        order_uids: vec![uid.to_string()],
        signature: format!("0x{}", alloy::hex::encode(sig.as_bytes())),
        signing_scheme: "eip712".to_string(),
    };
    cow::api::delete_orders(chain, &body).await
}

/// EIP-1271 off-chain cancel of a Safe-owned order. No gas / executor — the
/// cancellation is a signed `DELETE /orders`; CoW derives the order's owner
/// (the Safe) from the UID and validates the signature via the Safe's
/// `isValidSignature`. Builds the Safe's owner signers (software or hardware)
/// and reuses the same `CowCancel` result handler (the `handoff` carries the
/// parked active signer straight back, untouched).
fn spawn_cow_cancel_safe(
    network: Arc<dyn BalanceFetcher>,
    handoff: SignerHandoff,
    host: CowHost,
    chain: crate::chain::Chain,
    uid: String,
    ctx: SafeSwapCtx,
) -> Task<Message> {
    let uid_for_msg = uid.clone();
    Task::perform(
        async move {
            let mut owners = Vec::with_capacity(ctx.signer_owners.len());
            for desc in &ctx.signer_owners {
                match crate::wallet::build_owner_signer(desc).await {
                    Ok(s) => owners.push(s),
                    Err(e) => return Err::<(), String>(e), // already friendly (see build_owner_signer)
                }
            }
            if owners.is_empty() {
                return Err("no signable owners for this Safe".into());
            }
            cow_cancel_safe(&network, &owners, ctx.safe, chain, &uid).await
        },
        move |result| Message::CowCancel {
            host,
            uid: uid_for_msg.clone(),
            result,
            signer: handoff,
        },
    )
}

/// The Safe variant of [`cow_cancel`]: sign the `OrderCancellations` digest as
/// an EIP-1271 Safe message (owner signatures over the Safe-wrapped digest),
/// verify it against the live Safe, then `DELETE /orders` with
/// `signingScheme: eip1271`.
async fn cow_cancel_safe(
    network: &Arc<dyn BalanceFetcher>,
    owners: &[KaoSigner],
    safe: Address,
    chain: crate::chain::Chain,
    uid: &str,
) -> Result<(), String> {
    let bytes = parse_order_uid(uid)?;
    let domain = cow::order::cow_domain(chain);
    let digest = cow::order::cancellations_digest(&[bytes], &domain);
    let signature = cow::safe_sig::sign_eip1271_digest(owners, digest, safe, chain).await?;
    cow::safe_sig::verify_eip1271_on_chain(network.as_ref(), safe, chain, digest, &signature)
        .await?;
    let body = cow::api::CancellationBody {
        order_uids: vec![uid.to_string()],
        signature: format!("0x{}", alloy::hex::encode(&signature)),
        signing_scheme: "eip1271".to_string(),
    };
    cow::api::delete_orders(chain, &body).await
}

fn parse_order_uid(uid: &str) -> Result<[u8; 56], String> {
    let hex = uid.strip_prefix("0x").unwrap_or(uid);
    let raw = alloy::hex::decode(hex).map_err(|e| format!("bad order uid: {e}"))?;
    raw.try_into()
        .map_err(|_| "order uid must be 56 bytes".to_string())
}

/// Poll one order's status.
fn spawn_cow_status(chain: crate::chain::Chain, uid: String) -> Task<Message> {
    let uid_for_msg = uid.clone();
    Task::perform(
        async move { crate::cow::api::get_order(chain, &uid).await },
        move |result| Message::CowStatus {
            uid: uid_for_msg.clone(),
            result,
        },
    )
}

/// The two legs of a just-filled swap order, captured for the targeted
/// post-swap balance refresh. `slots` are the portfolio rows to replace
/// (native ETH as `None`); `fetch` are the ERC-20 contracts to re-read
/// on-chain (native ETH rides the walk's always-included native read).
struct SwapFillRefresh {
    chain: crate::chain::Chain,
    owner: Address,
    slots: Vec<Option<Address>>,
    fetch: Vec<DiscoveredToken>,
}

/// Fetch the address's CoW order history for `chain` and map it to
/// `TrackedOrder`s for the Apps list. Backs the "Fetch" action — surfaces all
/// of the address's orders (incl. past sessions), not just this session's.
fn spawn_cow_account_orders(chain: crate::chain::Chain, owner: Address) -> Task<Message> {
    Task::perform(
        async move {
            let result = crate::cow::api::get_account_orders(chain, owner, ACCOUNT_ORDERS_LIMIT)
                .await
                .map(|orders| account_orders_to_tracked(chain, owner, orders));
            (owner, chain, result)
        },
        |(owner, chain, result)| Message::CowAccountOrders {
            address: owner,
            chain,
            result,
        },
    )
}

/// Map a page of CoW account orders into `TrackedOrder`s, resolving token
/// symbols/decimals from the chain's curated list (long-tail tokens fall back
/// to a short address + 18 decimals). `owner` is the queried address, used as
/// the tracked owner so the Apps filter shows them even for EthFlow orders
/// (whose on-chain `owner` is the EthFlow contract). EthFlow sells are shown as
/// native ETH to match the in-session rows.
fn account_orders_to_tracked(
    chain: crate::chain::Chain,
    owner: Address,
    orders: Vec<crate::cow::api::AccountOrder>,
) -> Vec<TrackedOrder> {
    use std::collections::HashMap;
    let lookup: HashMap<Address, (String, u8)> = crate::portfolio::curated_tokens(chain)
        .into_iter()
        .map(|(sym, addr, dec)| (addr, (sym, dec)))
        .collect();
    let resolve = |addr: Address| -> (String, u8) {
        lookup
            .get(&addr)
            .cloned()
            .unwrap_or_else(|| (short_address(addr), 18))
    };
    orders
        .into_iter()
        .map(|o| {
            let is_ethflow = o.ethflow_data.is_some();
            let (sell_symbol, sell_decimals) = if is_ethflow {
                ("ETH".to_string(), 18)
            } else {
                resolve(o.sell_token)
            };
            let (buy_symbol, buy_decimals) = resolve(o.buy_token);
            // EthFlow's on-chain validTo is uint256::MAX; the signed one lives
            // in userValidTo. Prefer it so the sort key stays sane.
            let valid_to = o
                .ethflow_data
                .as_ref()
                .and_then(|e| e.user_valid_to)
                .unwrap_or(o.valid_to);
            let executed = o.executed();
            TrackedOrder {
                uid: o.uid,
                chain,
                owner,
                kind: if o.kind == "buy" {
                    cow::order::OrderKind::Buy
                } else {
                    cow::order::OrderKind::Sell
                },
                sell_token: o.sell_token,
                buy_token: o.buy_token,
                sell_symbol,
                buy_symbol,
                sell_amount: o.sell_amount,
                buy_amount: o.buy_amount,
                sell_decimals,
                buy_decimals,
                valid_to,
                status: o.status,
                executed,
                is_ethflow,
            }
        })
        .collect()
}

/// Targeted balance refresh after a swap fills: re-read just the sell + buy
/// assets (the "actives" the order touched) on `chain` instead of walking the
/// whole multi-chain portfolio. `fetch` is the ERC-20 legs to read on-chain;
/// `slots` (carried through to the handler) are the portfolio rows to replace
/// — native ETH included as `None` for an EthFlow sell. CoW only runs on
/// built-in chains, so the provider resolves through `NetworkId::Builtin`.
fn spawn_swap_token_refresh(
    network: Arc<dyn BalanceFetcher>,
    address: Address,
    chain: crate::chain::Chain,
    slots: Vec<Option<Address>>,
    fetch: Vec<DiscoveredToken>,
) -> Task<Message> {
    Task::perform(
        async move {
            let result = match provider_for(&network, crate::chain::NetworkId::Builtin(chain)).await
            {
                Some(p) => crate::portfolio::fetch_token_balances(address, chain, &p, &fetch).await,
                None => Err(format!("no execution RPC configured for {}", chain.label())),
            };
            (address, chain, slots, result)
        },
        |(address, chain, slots, result)| Message::SwapTokensRefetched {
            address,
            network: crate::chain::NetworkId::Builtin(chain),
            slots,
            result,
        },
    )
}

/// ETH-first, then by USD value descending — the stable portfolio row order
/// both the full fetch and the targeted post-swap refresh re-apply after
/// merging fresh rows in.
fn sort_portfolio_rows(rows: &mut [LiveToken]) {
    rows.sort_by(|a, b| {
        // Native ETH bubbles up first per chain.
        let a_native = a.contract.is_none();
        let b_native = b.contract.is_none();
        match b_native.cmp(&a_native) {
            std::cmp::Ordering::Equal => b
                .usd_value
                .partial_cmp(&a.usd_value)
                .unwrap_or(std::cmp::Ordering::Equal),
            other => other,
        }
    });
}

#[cfg(test)]
#[allow(unused_must_use)]
mod tests {
    //! Race-condition coverage for the three address-tagged fetch
    //! messages: an in-flight fetch must never apply to the wrong
    //! account when the user switches between accounts (or invalidates
    //! the network/indexer client) before the response lands.
    use super::*;
    use crate::chain::Chain;
    use crate::net::MockFetcher;
    use crate::portfolio::{LiveToken, new_cache};
    use crate::wallet::{KaoSigner, view_only_account};
    use alloy::primitives::{Address, U256};

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    fn screen_for(addr: Address, cache: PortfolioCache) -> WalletScreen {
        WalletScreen::new(
            KaoSigner::ViewOnly(addr),
            vec![view_only_account(addr)],
            Vec::new(),
            0,
            Arc::new(MockFetcher::new()),
            cache,
            Arc::new(RwLock::new(ContactsBook::new())),
            None,
        )
    }

    fn token(symbol: &str, chain: Chain) -> LiveToken {
        LiveToken {
            symbol: symbol.into(),
            name: symbol.into(),
            balance: "1".into(),
            balance_f64: 1.0,
            balance_raw: U256::from(1u64),
            decimals: 18,
            contract: None,
            usd_price: 1.0,
            usd_value: 1.0,
            chain: chain.into(),
        }
    }

    /// An ERC-20 row with a specific contract + USD value, so the targeted
    /// post-swap refresh tests can tell rows apart by slot and assert the
    /// merge replaced the right one.
    fn erc20(symbol: &str, chain: Chain, contract: Address, usd: f64) -> LiveToken {
        LiveToken {
            symbol: symbol.into(),
            name: symbol.into(),
            balance: "1".into(),
            balance_f64: 1.0,
            balance_raw: U256::from(1u64),
            decimals: 18,
            contract: Some(contract),
            usd_price: usd,
            usd_value: usd,
            chain: chain.into(),
        }
    }

    #[test]
    fn swap_refetch_replaces_targeted_slots_and_leaves_the_rest() {
        let active = addr(0xAA);
        let usdc = addr(0x01);
        let weth = addr(0x02);
        let mut s = screen_for(active, new_cache());
        // ETH (untouched), USDC (about to be fully sold), WETH (bought into).
        s.portfolio = vec![
            token("ETH", Chain::Mainnet),
            erc20("USDC", Chain::Mainnet, usdc, 100.0),
            erc20("WETH", Chain::Mainnet, weth, 5.0),
        ];
        // Sold all USDC for more WETH: the drained sell token isn't in the
        // result (zero balances drop out of the walk); the buy token grows.
        s.update(Message::SwapTokensRefetched {
            address: active,
            network: Chain::Mainnet.into(),
            slots: vec![Some(weth), Some(usdc)],
            result: Ok(vec![erc20("WETH", Chain::Mainnet, weth, 105.0)]),
        });
        assert!(
            s.portfolio.iter().all(|t| t.contract != Some(usdc)),
            "drained sell token must disappear",
        );
        let w = s
            .portfolio
            .iter()
            .find(|t| t.contract == Some(weth))
            .expect("buy token present");
        assert_eq!(w.usd_value, 105.0, "buy token must be refreshed");
        assert!(
            s.portfolio.iter().any(|t| t.contract.is_none()),
            "the untouched native ETH row must survive",
        );
        assert_eq!(s.portfolio.len(), 2);
    }

    #[test]
    fn swap_refetch_ignores_result_rows_outside_the_slots() {
        let active = addr(0xAA);
        let usdc = addr(0x01);
        let weth = addr(0x02);
        let mut s = screen_for(active, new_cache());
        s.portfolio = vec![
            token("ETH", Chain::Mainnet),
            erc20("USDC", Chain::Mainnet, usdc, 100.0),
            erc20("WETH", Chain::Mainnet, weth, 5.0),
        ];
        // An ERC-20 → ERC-20 fill: the walk still reads native ETH, but it's
        // not a swap slot here, so the stray ETH row must be ignored — not
        // merged in as a duplicate.
        s.update(Message::SwapTokensRefetched {
            address: active,
            network: Chain::Mainnet.into(),
            slots: vec![Some(weth), Some(usdc)],
            result: Ok(vec![
                erc20("WETH", Chain::Mainnet, weth, 105.0),
                erc20("USDC", Chain::Mainnet, usdc, 0.5),
                token("ETH", Chain::Mainnet),
            ]),
        });
        assert_eq!(
            s.portfolio.iter().filter(|t| t.contract.is_none()).count(),
            1,
            "the out-of-slot native ETH row must not be duplicated",
        );
    }

    #[test]
    fn swap_refetch_for_other_address_updates_cache_not_live_view() {
        let active = addr(0xAA);
        let other = addr(0xBB);
        let weth = addr(0x02);
        let cache = new_cache();
        let mut s = screen_for(active, cache.clone());
        // Seed `other`'s cache slot and the active live view with a stale row.
        cache.lock().unwrap().insert(
            (other, Chain::Mainnet.into()),
            vec![erc20("WETH", Chain::Mainnet, weth, 5.0)],
        );
        s.portfolio = vec![erc20("WETH", Chain::Mainnet, weth, 5.0)];
        s.update(Message::SwapTokensRefetched {
            address: other,
            network: Chain::Mainnet.into(),
            slots: vec![Some(weth)],
            result: Ok(vec![erc20("WETH", Chain::Mainnet, weth, 50.0)]),
        });
        // Live view belongs to `active` — a fill for `other` must not touch it.
        assert_eq!(
            s.portfolio[0].usd_value, 5.0,
            "another account's fill must not pollute the live view",
        );
        // But `other`'s cache slot is still the right place for that data.
        assert_eq!(
            cache.lock().unwrap()[&(other, Chain::Mainnet.into())][0].usd_value,
            50.0,
            "the fetched address's cache slot must be refreshed",
        );
    }

    fn tracked_order(
        uid: &str,
        owner: Address,
        status: OrderStatus,
        valid_to: u32,
    ) -> TrackedOrder {
        TrackedOrder {
            uid: uid.into(),
            chain: Chain::Base,
            owner,
            kind: cow::order::OrderKind::Sell,
            sell_token: addr(0x01),
            buy_token: addr(0x02),
            sell_symbol: "USDC".into(),
            buy_symbol: "DAI".into(),
            sell_amount: U256::from(1_000_000u64),
            buy_amount: U256::from(990_000u64),
            sell_decimals: 6,
            buy_decimals: 18,
            valid_to,
            status,
            executed: None,
            is_ethflow: false,
        }
    }

    #[test]
    fn fetch_account_orders_upserts_history_and_refreshes_known() {
        let active = addr(0xAA);
        let mut s = screen_for(active, new_cache());
        // One order from this session, still open.
        s.tracked_orders
            .push(tracked_order("0xsession", active, OrderStatus::Open, 100));

        // A fetch returns the same order (now filled) plus a past-session one.
        s.update(Message::CowAccountOrders {
            address: active,
            chain: Chain::Base,
            result: Ok(vec![
                tracked_order("0xsession", active, OrderStatus::Fulfilled, 100),
                tracked_order("0xhistory", active, OrderStatus::Expired, 50),
            ]),
        });
        assert_eq!(
            s.tracked_orders.len(),
            2,
            "history order added; the known one is updated in place, not duplicated",
        );
        let session = s
            .tracked_orders
            .iter()
            .find(|o| o.uid == "0xsession")
            .unwrap();
        assert_eq!(
            session.status,
            OrderStatus::Fulfilled,
            "a known order picks up its fresh status from the fetch",
        );
        assert!(s.tracked_orders.iter().any(|o| o.uid == "0xhistory"));
    }

    #[test]
    fn fetch_account_orders_for_other_address_is_dropped() {
        let active = addr(0xAA);
        let other = addr(0xBB);
        let mut s = screen_for(active, new_cache());
        s.update(Message::CowAccountOrders {
            address: other,
            chain: Chain::Base,
            result: Ok(vec![tracked_order(
                "0xhistory",
                other,
                OrderStatus::Open,
                50,
            )]),
        });
        assert!(
            s.tracked_orders.is_empty(),
            "a fetch for another account must not populate this one",
        );
    }

    #[test]
    fn placing_an_order_keeps_apps_available_until_it_resolves() {
        use crate::wallet::local_account;
        use alloy::signers::local::PrivateKeySigner;

        // A Local EOA — inherently swap-capable.
        let pk = PrivateKeySigner::random();
        let desc = local_account(&pk);
        let mut s = WalletScreen::new(
            KaoSigner::Local(pk),
            vec![desc],
            Vec::new(),
            0,
            Arc::new(MockFetcher::new()),
            new_cache(),
            Arc::new(RwLock::new(ContactsBook::new())),
            None,
        );
        assert!(s.can_swap());
        assert!(s.apps_available());

        // Parking the signer (what RequestPlace/RequestCancel do) makes the
        // live signer unable to sign — but the Apps surface must NOT vanish.
        let handoff = s.park_signer_for_order();
        assert!(!s.can_swap(), "parked signer can't sign right now");
        assert!(
            s.apps_available(),
            "Apps tab must stay available while an order is in flight",
        );

        // Resolving the op (here an errored placement) reclaims the signer and
        // clears the in-flight reprieve — back to the normal capability check.
        s.update(Message::CowPlaced {
            host: CowHost::Apps,
            result: Err("placement failed (test)".into()),
            signer: handoff,
        });
        assert!(
            !s.order_op_in_flight,
            "in-flight flag must clear on resolve"
        );
        assert!(s.can_swap(), "signer reclaimed after the op resolves");
        assert!(s.apps_available());
    }

    #[test]
    fn pool_sign_keeps_overlay_open_until_the_signature_resolves() {
        use crate::wallet::handoff_with;

        let active = addr(0xAA);
        let mut s = screen_for(active, new_cache());

        // A prepared pool deposit, sitting in the clear-sign review overlay.
        let sign = sign_review::PoolSign::Deposit {
            chain: Chain::Mainnet,
            symbol: "ETH".into(),
            to: addr(0x10),
            value: U256::from(1u64),
            calldata: alloy::primitives::Bytes::new(),
            approve: None,
        };
        s.sign_review = Some(sign_review::SignReview::pending(
            "Deposit".into(),
            None,
            Vec::new(),
            None,
            1,
            sign_review::SignAction::PrivacyPool { sign },
        ));

        // Confirm enters the "waiting for a signature" state: unlike the CoW /
        // Names paths (which tear the overlay down and drive their own busy
        // phase), the pool overlay stays open and the signer parks.
        let _task = s.confirm_sign_review();
        let review = s
            .sign_review
            .as_ref()
            .expect("pool overlay stays open across the signature");
        assert!(
            review.signing_since.is_some(),
            "confirm flips the overlay into its waiting state",
        );
        assert!(
            s.order_op_in_flight,
            "the signer is parked for the in-flight tx",
        );

        // A signature in flight can't be dismissed (Cancel / Esc / backdrop).
        s.cancel_sign_review();
        assert!(
            s.sign_review.is_some(),
            "a signature in flight can't be cancelled from the overlay",
        );

        // The signing task resolving (here a rejected tx) clears the overlay and
        // the in-flight flag; the pane surfaces the error underneath.
        s.update(Message::PoolSubmitted {
            result: Err("user rejected on device".into()),
            signer: Some(handoff_with(KaoSigner::ViewOnly(active))),
            kind: pool_app::PoolTxKind::Deposit,
        });
        assert!(
            s.sign_review.is_none(),
            "PoolSubmitted clears the waiting overlay",
        );
        assert!(!s.order_op_in_flight, "in-flight flag clears on resolve");
    }

    #[test]
    fn pool_deposit_and_ragequit_are_refused_in_safe_mode() {
        // Regression: Privacy Pools has no Safe path — a pool tx is signed and
        // paid by the active EOA (`send_contract_call` signs from
        // `signer.address()`). In Safe mode the review used to show the Safe as
        // `from` (via `order_owner`) while the EOA silently signed and funded it.
        // Both signing entry points must refuse rather than open the gate.
        let mut s = hardware_safe_screen(); // active_safe = Some(0), on a CoW chain
        assert!(s.active_safe.is_some(), "precondition: in Safe mode");

        let info = crate::pool::PoolInfo {
            chain: Chain::Mainnet,
            entrypoint: addr(0x11),
            asset: addr(0x12),
            pool: addr(0x13),
            scope: privacy_pools::Field::from(1u64),
            symbol: "ETH".into(),
            decimals: 18,
            is_native: true,
            min_deposit: U256::ZERO,
            vetting_fee_bps: U256::ZERO,
            max_relay_fee_bps: U256::ZERO,
            anonymity_set: 0,
            verified: true,
        };

        let _ = s.open_pool_deposit_review(info.clone(), U256::from(1u64));
        assert!(
            s.sign_review.is_none(),
            "a Safe-mode deposit must not open the clear-sign gate",
        );
        assert_eq!(
            s.apps.pool_pane().error(),
            Some(
                "Privacy Pools deposits are signed by your account, not a Safe — \
                 switch to an account to deposit."
            ),
            "the deposit refusal is surfaced on the pool pane",
        );

        // Same guard for the original-depositor exit.
        let _ = s.pool_ragequit(info, 0);
        assert_eq!(
            s.apps.pool_pane().error(),
            Some(
                "Privacy Pools exits are signed by your account, not a Safe — \
                 switch to an account to continue."
            ),
            "the ragequit refusal is surfaced on the pool pane",
        );
    }

    #[test]
    fn concurrent_signer_park_never_strands_the_wallet() {
        use crate::wallet::local_account;
        use alloy::signers::local::PrivateKeySigner;

        let pk = PrivateKeySigner::random();
        let desc = local_account(&pk);
        let mut s = WalletScreen::new(
            KaoSigner::Local(pk),
            vec![desc],
            Vec::new(),
            0,
            Arc::new(MockFetcher::new()),
            new_cache(),
            Arc::new(RwLock::new(ContactsBook::new())),
            None,
        );
        assert!(s.can_swap());
        assert!(!s.is_signing_busy());

        // Two overlapping signing ops park the signer (e.g. a CoW order started
        // while a name write is still in flight). The second park only captures
        // the ViewOnly placeholder the first one left behind.
        let h1 = s.park_signer_for_order();
        let h2 = s.park_signer_for_order();
        assert!(s.is_signing_busy());

        // The first op (holding the REAL signer) resolves first — restoring it.
        s.update(Message::CowPlaced {
            host: CowHost::Apps,
            result: Err("first op (test)".into()),
            signer: h1,
        });
        assert!(s.can_swap(), "real signer restored by the first reclaim");

        // The second op resolves later holding only the ViewOnly placeholder.
        // The hardened reclaim must NOT overwrite the live signer with it — that
        // is exactly the bug that would strand the wallet as view-only.
        s.update(Message::CowPlaced {
            host: CowHost::Apps,
            result: Err("second op (test)".into()),
            signer: h2,
        });
        assert!(
            s.can_swap(),
            "a stale ViewOnly placeholder must never strand the live signer",
        );
    }

    #[test]
    fn portfolio_fetched_for_other_address_does_not_pollute_live_view() {
        let active = addr(0xAA);
        let other = addr(0xBB);
        let cache = new_cache();
        let mut s = screen_for(active, cache.clone());
        assert!(s.portfolio.is_empty());
        s.update(Message::PortfolioFetched {
            address: other,
            network: Chain::Mainnet.into(),
            result: Ok(vec![token("USDC", Chain::Mainnet)]),
        });
        // Active account's live portfolio must stay empty — the
        // response was for a different account.
        assert!(s.portfolio.is_empty());
    }

    #[test]
    fn portfolio_fetched_for_other_address_still_fills_that_address_cache_slot() {
        let active = addr(0xAA);
        let other = addr(0xBB);
        let cache = new_cache();
        let mut s = screen_for(active, cache.clone());
        s.update(Message::PortfolioFetched {
            address: other,
            network: Chain::Mainnet.into(),
            result: Ok(vec![token("USDC", Chain::Mainnet)]),
        });
        // The data is correct for `other`'s slot — we only suppressed
        // the live merge into the active screen. The active address's
        // slot must remain untouched.
        let g = cache.lock().expect("cache");
        assert_eq!(
            g.get(&(other, Chain::Mainnet.into())).map(|v| v.len()),
            Some(1),
            "other's cache slot should be populated",
        );
        assert!(
            g.get(&(active, Chain::Mainnet.into())).is_none(),
            "active's cache slot must not be touched by another address's fetch",
        );
    }

    #[test]
    fn portfolio_fetched_for_active_address_merges_and_caches() {
        let active = addr(0xAA);
        let cache = new_cache();
        let mut s = screen_for(active, cache.clone());
        s.update(Message::PortfolioFetched {
            address: active,
            network: Chain::Mainnet.into(),
            result: Ok(vec![token("USDC", Chain::Mainnet)]),
        });
        assert_eq!(s.portfolio.len(), 1);
        assert_eq!(s.portfolio[0].symbol, "USDC");
        assert!(!s.portfolio_loading);
        let g = cache.lock().expect("cache");
        assert_eq!(
            g.get(&(active, Chain::Mainnet.into())).map(|v| v.len()),
            Some(1)
        );
    }

    #[test]
    fn history_fetched_for_other_address_is_dropped() {
        let active = addr(0xAA);
        let other = addr(0xBB);
        let mut s = screen_for(active, new_cache());
        // Pre-seed history so we can detect any clobber. The Mainnet
        // response empties the pending set, so loading flips to false.
        s.history_pending = vec![Chain::Mainnet];
        s.history_loading = true;
        s.update(Message::HistoryFetched {
            address: active,
            chain: Chain::Mainnet,
            result: Ok(Vec::new()),
        });
        let baseline_loading = s.history_loading;
        // Simulate a fresh fetch in flight for both chains.
        s.history_pending = vec![Chain::Mainnet, Chain::Base];
        s.history_loading = true;
        s.update(Message::HistoryFetched {
            address: other,
            chain: Chain::Mainnet,
            result: Ok(Vec::new()),
        });
        // The dropped response must not shrink the pending set or flip
        // `history_loading` off — otherwise the spinner would disappear
        // before the *real* fetch for `active` lands.
        assert!(
            s.history_loading,
            "history_loading must stay true when a foreign-address response is dropped",
        );
        assert_eq!(
            s.history_pending.len(),
            2,
            "pending set must be untouched by a foreign-address response",
        );
        // Sanity: the initial active-address response did clear loading.
        assert!(!baseline_loading);
    }

    fn safe_descriptor(byte: u8, chain_id: u64) -> SafeDescriptor {
        SafeDescriptor {
            name: None,
            chain_id,
            address: [byte; 20],
            version: "1.4.1".into(),
            trust: crate::wallet::SafeTrust::Canonical,
            threshold: 1,
            owners: Vec::new(),
            modules: Vec::new(),
            guard: None,
            fallback_handler: None,
            linked_signer_indices: vec![0],
            sibling_chains: Vec::new(),
            cached_at: 0,
            tx_service_url: None,
        }
    }

    fn screen_with_safes(addr: Address, safes: Vec<SafeDescriptor>) -> WalletScreen {
        WalletScreen::new(
            KaoSigner::ViewOnly(addr),
            vec![view_only_account(addr)],
            safes,
            0,
            Arc::new(MockFetcher::new()),
            crate::portfolio::new_cache(),
            Arc::new(RwLock::new(ContactsBook::new())),
            None,
        )
    }

    #[test]
    fn display_address_returns_safe_addr_when_active_safe_set() {
        let mut screen = screen_with_safes(addr(1), vec![safe_descriptor(0x55, 1)]);
        assert_eq!(screen.display_address(), addr(1));
        screen.active_safe = Some(0);
        assert_eq!(screen.display_address(), Address::from([0x55u8; 20]));
    }

    #[test]
    fn select_safe_outcome_enters_safe_mode_and_resets_history() {
        let mut screen = screen_with_safes(addr(1), vec![safe_descriptor(0x77, 1)]);
        screen.history.push(IndexedTx {
            hash: alloy::primitives::B256::ZERO,
            block_number: 1,
            timestamp: 0,
            from: Address::ZERO,
            to: None,
            value: U256::ZERO,
            gas_used: None,
            gas_price: None,
            status: crate::indexer::TxStatus::Success,
            direction: crate::indexer::TxDirection::SelfTransfer,
            method: None,
            token: None,
            chain: Chain::Mainnet,
        });
        screen.history_loaded = true;
        // The handler bails unless the AccountDropdown modal is
        // open; mirror what happens after the user clicks the
        // address pill.
        screen.modal = Modal::AccountDropdown(AccountDropdown::new());
        let _ = screen.update(Message::AccountDropdown(
            account_dropdown::Message::SelectSafe(0),
        ));
        assert_eq!(screen.active_safe, Some(0));
        assert!(
            screen.history.is_empty(),
            "history should clear on Safe entry"
        );
        assert!(!screen.history_loaded);
    }

    #[test]
    fn can_send_in_safe_mode_true_when_linked_local_exists() {
        // Wallet: active = ViewOnly. Account 1 = Local (linked to Safe).
        // EOA mode would gate Send off (active is view-only), but in
        // Safe mode the linked Local owner serves as both signer and
        // gas-paying executor, so Send must stay clickable.
        let accounts = vec![
            view_only_account(addr(1)),
            crate::wallet::AccountDescriptor::Local {
                name: None,
                key_bytes: crate::wallet::SecretKeyBytes::new([0x7e; 32]),
            },
        ];
        let mut safe = safe_descriptor(0x99, 1);
        safe.linked_signer_indices = vec![1];
        let mut screen = WalletScreen::new(
            KaoSigner::ViewOnly(addr(1)),
            accounts,
            vec![safe],
            0,
            Arc::new(MockFetcher::new()),
            crate::portfolio::new_cache(),
            Arc::new(RwLock::new(ContactsBook::new())),
            None,
        );
        // EOA mode: ViewOnly active → can't send.
        assert!(!screen.can_send());
        // Safe mode: linked Local owner unlocks Send.
        screen.active_safe = Some(0);
        assert!(screen.can_send());
    }

    #[test]
    fn can_send_in_safe_mode_false_for_unrecognized_impl() {
        let accounts = vec![
            view_only_account(addr(1)),
            crate::wallet::AccountDescriptor::Local {
                name: None,
                key_bytes: crate::wallet::SecretKeyBytes::new([0x7e; 32]),
            },
        ];
        let mut safe = safe_descriptor(0x99, 1);
        safe.trust = crate::wallet::SafeTrust::UnrecognizedImpl;
        safe.linked_signer_indices = vec![1];
        let mut screen = WalletScreen::new(
            KaoSigner::ViewOnly(addr(1)),
            accounts,
            vec![safe],
            0,
            Arc::new(MockFetcher::new()),
            crate::portfolio::new_cache(),
            Arc::new(RwLock::new(ContactsBook::new())),
            None,
        );

        screen.active_safe = Some(0);
        assert!(
            !screen.can_send(),
            "unrecognized Safe implementations must not expose Send"
        );
    }

    #[test]
    fn can_send_in_safe_mode_true_for_hardware_owner() {
        // 1/1 Safe whose only linked owner is a Ledger, and the wallet
        // holds no Local key at all. The old gate required a Local owner;
        // now the hardware owner signs on-device and broadcasts its own
        // execTransaction, so Send must be live.
        let accounts = vec![view_only_account(addr(1)), ledger_acct(addr(0xab))];
        let mut safe = safe_descriptor(0x99, 1);
        safe.linked_signer_indices = vec![1];
        let mut screen = WalletScreen::new(
            KaoSigner::ViewOnly(addr(1)),
            accounts,
            vec![safe],
            0,
            Arc::new(MockFetcher::new()),
            crate::portfolio::new_cache(),
            Arc::new(RwLock::new(ContactsBook::new())),
            None,
        );
        screen.active_safe = Some(0);
        assert!(
            screen.can_send(),
            "a 1/1 hardware-owned Safe must expose Send"
        );
    }

    #[test]
    fn can_send_in_safe_mode_false_for_view_only_owner() {
        // The only linked owner is view-only — no key material anywhere,
        // so Send must stay blocked even though trust is Canonical.
        let accounts = vec![view_only_account(addr(1)), view_only_account(addr(2))];
        let mut safe = safe_descriptor(0x99, 1);
        safe.linked_signer_indices = vec![1];
        let mut screen = WalletScreen::new(
            KaoSigner::ViewOnly(addr(1)),
            accounts,
            vec![safe],
            0,
            Arc::new(MockFetcher::new()),
            crate::portfolio::new_cache(),
            Arc::new(RwLock::new(ContactsBook::new())),
            None,
        );
        screen.active_safe = Some(0);
        assert!(
            !screen.can_send(),
            "a Safe with only a view-only owner cannot send"
        );
    }

    #[test]
    fn send_hidden_for_view_only_and_disconnected_hardware_eoa() {
        // EOA mode: Send shows only when the active signer can sign right now.
        let local_signer =
            KaoSigner::Local(crate::wallet::signer_from_bytes(&B256::repeat_byte(0x11)).unwrap());
        let mut screen = WalletScreen::new(
            local_signer,
            vec![local_with_key(0x11)],
            Vec::new(),
            0,
            Arc::new(MockFetcher::new()),
            new_cache(),
            Arc::new(RwLock::new(ContactsBook::new())),
            None,
        );
        assert!(screen.can_send(), "a live Local signer shows Send");

        // Both a view-only account and a hardware account with a disconnected
        // device present as a view-only placeholder signer (no live signer), so
        // Send is hidden in either case.
        screen.signer = KaoSigner::ViewOnly(addr(0xCC));
        assert!(
            !screen.can_send(),
            "view-only / disconnected hardware (no live signer) hides Send"
        );
    }

    /// The canonical hardware-multisig these features target: a 1/1 Safe on
    /// Mainnet (CoW-supported) whose only owner is a Ledger, and the wallet
    /// holds no Local key. Active in Safe mode.
    fn hardware_safe_screen() -> WalletScreen {
        let accounts = vec![view_only_account(addr(1)), ledger_acct(addr(0xab))];
        let mut safe = safe_descriptor(0x99, 1); // chain_id 1 = Mainnet
        safe.linked_signer_indices = vec![1];
        let mut screen = WalletScreen::new(
            KaoSigner::ViewOnly(addr(1)),
            accounts,
            vec![safe],
            0,
            Arc::new(MockFetcher::new()),
            new_cache(),
            Arc::new(RwLock::new(ContactsBook::new())),
            None,
        );
        screen.active_safe = Some(0);
        screen
    }

    #[test]
    fn order_owner_tracks_active_identity() {
        let mut screen = hardware_safe_screen();
        let safe_addr = screen.safes[0].address();
        assert_eq!(
            screen.order_owner(),
            safe_addr,
            "Safe mode → CoW orders owned by the Safe"
        );
        screen.active_safe = None;
        assert_eq!(
            screen.order_owner(),
            screen.address,
            "EOA mode → CoW orders owned by the EOA"
        );
    }

    #[test]
    fn can_swap_true_for_hardware_safe() {
        assert!(
            hardware_safe_screen().can_swap(),
            "a hardware-owned Safe on a CoW chain can swap via EIP-1271"
        );
    }

    #[test]
    fn can_swap_false_for_view_only_safe() {
        let accounts = vec![view_only_account(addr(1)), view_only_account(addr(2))];
        let mut safe = safe_descriptor(0x99, 1);
        safe.linked_signer_indices = vec![1];
        let mut screen = WalletScreen::new(
            KaoSigner::ViewOnly(addr(1)),
            accounts,
            vec![safe],
            0,
            Arc::new(MockFetcher::new()),
            new_cache(),
            Arc::new(RwLock::new(ContactsBook::new())),
            None,
        );
        screen.active_safe = Some(0);
        assert!(
            !screen.can_swap(),
            "a view-only Safe has no signer for an EIP-1271 order"
        );
    }

    #[test]
    fn can_swap_false_for_unrecognized_safe() {
        let mut screen = hardware_safe_screen();
        screen.safes[0].trust = crate::wallet::SafeTrust::UnrecognizedImpl;
        assert!(
            !screen.can_swap(),
            "an unrecognized Safe implementation blocks signing"
        );
    }

    #[test]
    fn can_swap_false_for_safe_on_unsupported_chain() {
        let mut screen = hardware_safe_screen();
        screen.safes[0].chain_id = 10; // Optimism — CoW serves only Mainnet/Base
        assert!(
            !screen.can_swap(),
            "CoW doesn't serve this Safe's chain, so no swap"
        );
    }

    #[test]
    fn build_safe_swap_ctx_uses_hardware_owner_and_no_local_executor() {
        let screen = hardware_safe_screen();
        let ctx = screen
            .build_safe_swap_ctx()
            .expect("a valid hardware Safe must yield a swap context");
        assert_eq!(ctx.safe, screen.safes[0].address());
        assert_eq!(ctx.chain, Chain::Mainnet);
        assert_eq!(ctx.signer_owners.len(), 1, "one signable (hardware) owner");
        assert!(matches!(
            ctx.signer_owners[0],
            AccountDescriptor::Ledger { .. }
        ));
        assert!(
            ctx.local_executor_key.is_none(),
            "no Local key in wallet → the hardware owner self-pays gas"
        );
    }

    #[test]
    fn ethflow_safe_tx_targets_ethflow_with_eth_value() {
        // The native-ETH Safe swap is a value-bearing Call to ETHFLOW.createOrder
        // — the Safe forwards its own ETH as the inner-call value, no approval,
        // no EIP-1271 order signature (the EthFlow contract signs the order).
        let sell = U256::from(2_000_000_000_000_000_000u64); // 2 ETH
        let data = cow::ethflow::build_ethflow_data(
            addr(0xB0), // buy token
            addr(0x99), // receiver = the Safe
            sell,
            U256::from(5_000_000_000u64),
            1_900_000_000,
            7,
            50,
            cow::market_app_data(50).1,
        );
        let tx = ethflow_safe_tx(&data, 11);
        assert_eq!(tx.to, cow::ETHFLOW, "calls the EthFlow contract");
        assert_eq!(
            tx.value, sell,
            "forwards the full ETH sell as the inner value"
        );
        assert_eq!(
            &tx.data.as_ref()[0..4],
            &[0x32, 0x2b, 0xba, 0x21],
            "createOrder selector"
        );
        assert_eq!(tx.operation, 0, "Call, never DelegateCall");
        assert_eq!(tx.nonce, U256::from(11u64), "pinned nonce");
        assert_eq!(tx.gasPrice, U256::ZERO, "gas-refund fields zeroed");
    }

    #[test]
    fn active_cow_orders_scope_to_active_identity() {
        let mut screen = hardware_safe_screen();
        let safe_addr = screen.safes[0].address();
        let eoa = screen.address;
        screen.tracked_orders = vec![
            tracked_order("0xsafe_new", safe_addr, OrderStatus::Open, 200),
            tracked_order("0xsafe_old", safe_addr, OrderStatus::Open, 100),
            tracked_order("0xeoa", eoa, OrderStatus::Open, 300),
        ];
        // Safe mode: only the Safe's orders, newest-first by valid_to.
        let got: Vec<&str> = screen
            .active_cow_orders()
            .iter()
            .map(|o| o.uid.as_str())
            .collect();
        assert_eq!(
            got,
            vec!["0xsafe_new", "0xsafe_old"],
            "Safe mode shows the Safe's EIP-1271 orders, not the EOA's"
        );
        // EOA mode: only the EOA's order.
        screen.active_safe = None;
        let got: Vec<&str> = screen
            .active_cow_orders()
            .iter()
            .map(|o| o.uid.as_str())
            .collect();
        assert_eq!(got, vec!["0xeoa"]);
    }

    /// Like `hardware_safe_screen` but the Safe is on a non-Mainnet chain —
    /// where the Mainnet-pinned name registries can't reach it.
    fn hardware_safe_screen_on_chain(chain_id: u64) -> WalletScreen {
        let accounts = vec![view_only_account(addr(1)), ledger_acct(addr(0xab))];
        let mut safe = safe_descriptor(0x99, chain_id);
        safe.linked_signer_indices = vec![1];
        let mut screen = WalletScreen::new(
            KaoSigner::ViewOnly(addr(1)),
            accounts,
            vec![safe],
            0,
            Arc::new(MockFetcher::new()),
            new_cache(),
            Arc::new(RwLock::new(ContactsBook::new())),
            None,
        );
        screen.active_safe = Some(0);
        screen
    }

    #[test]
    fn build_safe_name_ctx_uses_hardware_owner_and_no_local_executor() {
        let screen = hardware_safe_screen(); // Mainnet
        let ctx = screen
            .build_safe_name_ctx()
            .expect("a Mainnet hardware Safe yields a name context");
        assert_eq!(ctx.safe, screen.safes[0].address());
        assert_eq!(ctx.owners.len(), 1);
        assert!(matches!(ctx.owners[0], AccountDescriptor::Ledger { .. }));
        assert!(ctx.executor_key.is_none(), "hardware owner self-pays gas");
    }

    #[test]
    fn names_available_and_routed_for_mainnet_safe() {
        // A Mainnet hardware Safe offers Names. A write now opens the
        // clear-signing review *first* (no signer parked yet); confirming it is
        // what routes through the Safe and parks the signer for the async
        // execTransaction.
        let mut screen = hardware_safe_screen();
        assert!(
            screen.names_available_for_active(),
            "a Mainnet Safe offers Names"
        );
        assert!(!screen.order_op_in_flight);
        let _ = screen.handle_name_outcome(super::names_app::Outcome::RegisterXns {
            namespace: "xns".to_string(),
            label: "alice".to_string(),
        });
        assert!(
            screen.sign_review.is_some(),
            "a name write opens the clear-signing review gate"
        );
        assert!(
            !screen.order_op_in_flight,
            "the signer is parked only when the review is confirmed"
        );
        let _ = screen.confirm_sign_review();
        assert!(
            screen.order_op_in_flight,
            "confirming routes through the Safe (signer parked)"
        );
        assert!(screen.sign_review.is_none(), "confirm closes the review");
    }

    #[test]
    fn names_refused_for_non_mainnet_safe() {
        // Names are Mainnet-pinned: a Safe on Base can't register, so Names is
        // hidden and a write is refused without parking the signer.
        let mut screen = hardware_safe_screen_on_chain(8453); // Base
        assert!(
            !screen.names_available_for_active(),
            "a non-Mainnet Safe hides Names"
        );
        assert!(screen.build_safe_name_ctx().is_none());
        assert!(!screen.order_op_in_flight);
        let _ = screen.handle_name_outcome(super::names_app::Outcome::RegisterXns {
            namespace: "xns".to_string(),
            label: "alice".to_string(),
        });
        assert!(
            !screen.order_op_in_flight,
            "a name write from a non-Mainnet Safe is refused (not parked)"
        );
    }

    #[test]
    fn names_available_for_eoa() {
        let mut screen = hardware_safe_screen();
        screen.active_safe = None; // EOA mode
        assert!(
            screen.names_available_for_active(),
            "EOA mode always offers Names"
        );
    }

    fn sample_swap_draft() -> SwapDraft {
        SwapDraft {
            chain: Chain::Mainnet,
            is_native: false,
            sell_token: addr(0x11),
            buy_token: addr(0x22),
            sell_amount: U256::from(1_000_000u64),
            slippage_bps: 50,
            sell_symbol: "USDC".into(),
            buy_symbol: "DAI".into(),
            sell_decimals: 6,
            buy_decimals: 18,
        }
    }

    fn sample_quote() -> crate::cow::api::QuoteResponse {
        crate::cow::api::QuoteResponse {
            quote: crate::cow::api::QuoteParams {
                sell_token: addr(0x11),
                buy_token: addr(0x22),
                receiver: None,
                sell_amount: U256::from(1_000_000u64),
                buy_amount: U256::from(990_000_000_000_000_000u64),
                valid_to: 1_900_000_000,
                app_data: "{}".into(),
                fee_amount: U256::ZERO,
                kind: "sell".into(),
                partially_fillable: false,
            },
            from: None,
            expiration: None,
            id: Some(1),
            verified: Some(true),
        }
    }

    #[test]
    fn cow_native_safe_exec_hash_pins_the_signed_hash() {
        // The safeTxHash shown in a native Safe-swap review is computed with the
        // exact expression `cow_place_order_safe` signs:
        // safe_tx_hash(ethflow_safe_tx(data, nonce), safe_domain(safe, chain)).
        use crate::safe::tx::{safe_domain, safe_tx_hash};
        let safe = addr(0x5A);
        let chain = Chain::Mainnet;
        let draft = sample_swap_draft();
        let quote = sample_quote();
        let q = &quote.quote;
        let full_sell = q.sell_amount.saturating_add(q.fee_amount);
        let (_, app_data_hash) = cow::market_app_data(draft.slippage_bps);
        let data = cow::ethflow::build_ethflow_data(
            draft.buy_token,
            safe,
            full_sell,
            q.buy_amount,
            q.valid_to,
            quote.id.unwrap_or_default(),
            draft.slippage_bps,
            app_data_hash,
        );
        let hash = safe_tx_hash(&ethflow_safe_tx(&data, 7), &safe_domain(safe, chain));
        assert_ne!(hash, alloy::primitives::B256::ZERO);
        // Nonce-bound: the pin matters — a different nonce yields a different hash.
        assert_ne!(
            hash,
            safe_tx_hash(&ethflow_safe_tx(&data, 8), &safe_domain(safe, chain))
        );
    }

    #[test]
    fn cow_safe_message_hash_is_what_owners_sign() {
        // The EIP-1271 message hash shown in a Safe ERC-20 review equals what
        // `sign_eip1271_digest` signs: safe_message_hash over the order digest of
        // an order whose receiver is the Safe.
        let safe = addr(0x5A);
        let chain = Chain::Mainnet;
        let draft = sample_swap_draft();
        let quote = sample_quote();
        let q = &quote.quote;
        let full_sell = q.sell_amount.saturating_add(q.fee_amount);
        let (_, app_data_hash) = cow::market_app_data(draft.slippage_bps);
        let order = cow::order::build_sell_order(
            draft.sell_token,
            draft.buy_token,
            safe,
            full_sell,
            q.buy_amount,
            q.valid_to,
            draft.slippage_bps,
            app_data_hash,
        );
        let digest = cow::order::order_digest(&order, &cow::order::cow_domain(chain));
        let message_hash = cow::safe_sig::safe_message_hash(digest, safe, chain);
        assert_ne!(message_hash, alloy::primitives::B256::ZERO);
        // Binds to the Safe: a different Safe → a different message hash.
        assert_ne!(
            message_hash,
            cow::safe_sig::safe_message_hash(digest, addr(0x5B), chain)
        );
        // The displayed order's receiver is the Safe (matches the signed order).
        assert_eq!(build_order_review(&draft, &quote, safe).receiver, safe);
    }

    #[test]
    fn cow_place_opens_review_then_confirm_parks_signer() {
        use crate::wallet::local_account;
        use alloy::signers::local::PrivateKeySigner;
        // Placing a swap must open the clear-signing review (showing the EIP-712
        // order panel) *before* any signing. The signer parks only on confirm.
        // A swap review now requires a signable context, so use a Local account.
        let pk = PrivateKeySigner::random();
        let me = pk.address();
        let desc = local_account(&pk);
        let mut screen = WalletScreen::new(
            KaoSigner::Local(pk),
            vec![desc],
            Vec::new(),
            0,
            Arc::new(MockFetcher::new()),
            new_cache(),
            Arc::new(RwLock::new(ContactsBook::new())),
            None,
        );
        assert!(screen.sign_review.is_none());
        assert!(!screen.order_op_in_flight);

        let _ = screen.open_cow_review(CowHost::Apps, sample_swap_draft(), sample_quote());
        let review = screen.sign_review.as_ref().expect("place opens a review");
        let order = review
            .steps
            .iter()
            .find_map(|s| match s {
                sign_review::SignStep::Typed(o) => Some(o),
                sign_review::SignStep::RawTx(_)
                | sign_review::SignStep::SafeExec(_)
                | sign_review::SignStep::SafeMessage(_) => None,
            })
            .expect("swap review shows the order panel");
        assert_eq!(order.receiver, me, "receiver is the active account");
        assert_eq!(order.sell_symbol, "USDC");
        assert_eq!(order.buy_symbol, "DAI");
        assert!(
            !screen.order_op_in_flight,
            "the signer is not parked until the user confirms"
        );

        // Cancelling drops the review and parks nothing.
        screen.cancel_sign_review();
        assert!(screen.sign_review.is_none());
        assert!(!screen.order_op_in_flight);

        // Re-open and confirm → places the order, parking the signer.
        let _ = screen.open_cow_review(CowHost::Apps, sample_swap_draft(), sample_quote());
        let _ = screen.confirm_sign_review();
        assert!(
            screen.order_op_in_flight,
            "confirming places the order (signer parked)"
        );
        assert!(screen.sign_review.is_none(), "confirm closes the review");
    }

    #[test]
    fn signer_context_is_eoa_for_a_signable_account() {
        use crate::wallet::local_account;
        use alloy::signers::local::PrivateKeySigner;
        let pk = PrivateKeySigner::random();
        let me = pk.address();
        let desc = local_account(&pk);
        let screen = WalletScreen::new(
            KaoSigner::Local(pk),
            vec![desc],
            Vec::new(),
            0,
            Arc::new(MockFetcher::new()),
            new_cache(),
            Arc::new(RwLock::new(ContactsBook::new())),
            None,
        );
        let ctx = screen
            .build_eoa_context()
            .expect("a signable EOA has a context");
        assert!(matches!(ctx, SignerContext::Eoa { .. }));
        assert_eq!(ctx.display_from(), me, "from == the active EOA");
        // Outside Safe mode both flows resolve to the same EOA context.
        for need in [SafeNeed::Swap, SafeNeed::Name] {
            assert_eq!(screen.build_signer_context(need).unwrap().display_from(), me);
        }
    }

    #[test]
    fn signer_context_refuses_watch_only() {
        // A watch-only account is unrepresentable as a signer context — a review is
        // never built for a signer that can't sign.
        let screen = screen_for(addr(0xAB), new_cache());
        assert!(screen.build_eoa_context().is_err(), "watch-only can't sign");
        assert!(screen.build_signer_context(SafeNeed::Swap).is_err());
    }

    #[test]
    fn signer_context_is_safe_in_safe_mode() {
        let screen = hardware_safe_screen(); // Mainnet hardware Safe
        let safe = screen.safes[0].address();
        for need in [SafeNeed::Swap, SafeNeed::Name] {
            let ctx = screen
                .build_signer_context(need)
                .expect("a Mainnet hardware Safe signs both swaps and names");
            assert!(matches!(ctx, SignerContext::Safe { .. }));
            assert_eq!(ctx.display_from(), safe, "from == the Safe");
        }
    }

    #[test]
    fn cow_cancel_opens_gasless_review() {
        // Cancelling an order opens a confirm gate (an off-chain EIP-712 message),
        // with no legs to decode and no order panel.
        let me = addr(0xAB);
        let mut screen = screen_for(me, new_cache());
        screen.tracked_orders.push(TrackedOrder {
            uid: "0xdeadbeef".repeat(7),
            chain: Chain::Mainnet,
            owner: me,
            kind: crate::cow::order::OrderKind::Sell,
            sell_token: addr(0x11),
            buy_token: addr(0x22),
            sell_symbol: "USDC".into(),
            buy_symbol: "DAI".into(),
            sell_amount: U256::from(1_000_000u64),
            buy_amount: U256::from(990_000_000_000_000_000u64),
            sell_decimals: 6,
            buy_decimals: 18,
            valid_to: 1_900_000_000,
            status: OrderStatus::Open,
            executed: None,
            is_ethflow: false,
        });
        let uid = screen.tracked_orders[0].uid.clone();
        let _ = screen.open_cow_cancel_review(CowHost::Modal, uid);
        let review = screen.sign_review.as_ref().expect("cancel opens a review");
        assert!(
            review.steps.is_empty(),
            "a cancellation has no order panel and nothing to decode"
        );
        assert!(
            !review.legs_loading,
            "a cancellation has nothing to decode — Confirm is enabled immediately"
        );
    }

    #[test]
    fn active_safe_signing_block_catches_demotion_and_swap() {
        let mut screen = screen_with_safes(addr(1), vec![safe_descriptor(0x99, 1)]);
        screen.active_safe = Some(0);
        let safe = screen.safes[0].address();
        let chain = Chain::Mainnet;

        // Canonical + matching descriptor → signing allowed.
        assert!(screen.active_safe_signing_block(safe, chain).is_none());

        // A refresh-on-open demotes the live descriptor while the modal's
        // snapshot is still Canonical → the re-check must block.
        screen.safes[0].trust = crate::wallet::SafeTrust::UnrecognizedImpl;
        assert!(screen.active_safe_signing_block(safe, chain).is_some());

        // Trust restored, but a wholesale SafesUpdated replace reordered the
        // active slot onto a different Safe → block on address mismatch.
        screen.safes[0] = safe_descriptor(0xAB, 1);
        assert!(screen.active_safe_signing_block(safe, chain).is_some());

        // No active descriptor at all (deleted / switched to EOA) → block.
        screen.active_safe = None;
        assert!(screen.active_safe_signing_block(safe, chain).is_some());
    }

    #[test]
    fn allowed_chains_in_eoa_mode_returns_all_chains() {
        let screen = screen_with_safes(addr(1), vec![safe_descriptor(0x55, 1)]);
        assert_eq!(screen.allowed_chains(), Chain::ALL.to_vec());
    }

    #[test]
    fn allowed_chains_in_safe_mode_returns_only_safe_chain() {
        // Mainnet Safe — only Mainnet shows.
        let mut screen = screen_with_safes(
            addr(1),
            vec![safe_descriptor(0x55, Chain::Mainnet.chain_id())],
        );
        screen.active_safe = Some(0);
        assert_eq!(screen.allowed_chains(), vec![Chain::Mainnet]);

        // Base Safe — only Base shows.
        let mut screen =
            screen_with_safes(addr(1), vec![safe_descriptor(0x66, Chain::Base.chain_id())]);
        screen.active_safe = Some(0);
        assert_eq!(screen.allowed_chains(), vec![Chain::Base]);

        // Optimism Safe — only Optimism shows.
        let mut screen = screen_with_safes(
            addr(1),
            vec![safe_descriptor(0x77, Chain::Optimism.chain_id())],
        );
        screen.active_safe = Some(0);
        assert_eq!(screen.allowed_chains(), vec![Chain::Optimism]);
    }

    #[test]
    fn portfolio_fetched_on_disallowed_chain_in_safe_mode_drops() {
        // Mainnet Safe receives a late Base portfolio fetch — must
        // not pollute the live view. The cache still gets written
        // (it's keyed by (addr, chain) and might be useful when the
        // user navigates back to that EOA), but `self.portfolio`
        // stays Safe-chain-only.
        let mut screen = screen_with_safes(
            addr(1),
            vec![safe_descriptor(0x55, Chain::Mainnet.chain_id())],
        );
        screen.active_safe = Some(0);
        let safe_addr = Address::from([0x55u8; 20]);
        // Stray Base fetch addressed to the Safe address.
        let stray = vec![LiveToken {
            chain: Chain::Base.into(),
            contract: None,
            name: "Ether".into(),
            symbol: "ETH".into(),
            decimals: 18,
            balance: "0.1".into(),
            balance_f64: 0.1,
            balance_raw: U256::ZERO,
            usd_price: 1000.0,
            usd_value: 100.0,
        }];
        let _ = screen.update(Message::PortfolioFetched {
            address: safe_addr,
            network: Chain::Base.into(),
            result: Ok(stray),
        });
        assert!(
            screen.portfolio.is_empty(),
            "Base fetch must not surface on a Mainnet Safe",
        );
    }

    #[test]
    fn history_fetched_on_disallowed_chain_in_safe_mode_drops() {
        let mut screen = screen_with_safes(
            addr(1),
            vec![safe_descriptor(0x55, Chain::Mainnet.chain_id())],
        );
        screen.active_safe = Some(0);
        let safe_addr = Address::from([0x55u8; 20]);
        let stray = vec![IndexedTx {
            hash: alloy::primitives::B256::ZERO,
            block_number: 1,
            timestamp: 0,
            from: Address::ZERO,
            to: None,
            value: U256::ZERO,
            gas_used: None,
            gas_price: None,
            status: crate::indexer::TxStatus::Success,
            direction: crate::indexer::TxDirection::SelfTransfer,
            method: None,
            token: None,
            chain: Chain::Optimism,
        }];
        let _ = screen.update(Message::HistoryFetched {
            address: safe_addr,
            chain: Chain::Optimism,
            result: Ok(stray),
        });
        assert!(
            screen.history.is_empty(),
            "Optimism history must not surface on a Mainnet Safe",
        );
    }

    #[test]
    fn switch_account_outcome_exits_safe_mode_and_resets_history() {
        let mut screen = screen_with_safes(addr(1), vec![safe_descriptor(0x77, 1)]);
        screen.active_safe = Some(0);
        screen.history_loaded = true;
        screen.modal = Modal::AccountDropdown(AccountDropdown::new());
        // Outcome::Switch(0) — same account, but exit Safe mode.
        let (_, outcome) = screen.update(Message::AccountDropdown(
            account_dropdown::Message::Select(0),
        ));
        // Outcome only bubbles when idx != active_index, so for the
        // same account we get None back. The state flip is what we
        // assert.
        assert!(outcome.is_none());
        assert!(screen.active_safe.is_none());
        assert!(!screen.history_loaded);
    }

    fn local_with_key(seed: u8) -> AccountDescriptor {
        AccountDescriptor::Local {
            name: None,
            key_bytes: crate::wallet::SecretKeyBytes::new([seed; 32]),
        }
    }

    fn ledger_acct(a: Address) -> AccountDescriptor {
        AccountDescriptor::Ledger {
            name: None,
            path: crate::wallet::LedgerHdPath::LedgerLive(0),
            address: a.into_array(),
        }
    }

    #[test]
    fn signable_owners_excludes_view_only_and_dangling_indices() {
        let accounts = vec![
            local_with_key(0xaa),          // 0: signable
            view_only_account(addr(0xbb)), // 1: excluded
            ledger_acct(addr(0xcc)),       // 2: signable (hardware)
        ];
        let mut safe = safe_descriptor(0x11, 1);
        safe.linked_signer_indices = vec![0, 1, 2, 9]; // 9 is dangling
        let got = signable_owners_of(&safe, &accounts);
        assert_eq!(got.len(), 2, "view-only + dangling dropped");
        assert!(matches!(got[0].1, AccountDescriptor::Local { .. }));
        assert!(matches!(got[1].1, AccountDescriptor::Ledger { .. }));
        // Hardware owner's address is carried through from the descriptor.
        assert_eq!(got[1].0, addr(0xcc));
    }

    #[test]
    fn first_local_key_finds_first_local_only() {
        let accounts = vec![
            view_only_account(addr(0xbb)),
            local_with_key(0x07),
            local_with_key(0x09),
        ];
        assert_eq!(first_local_key_of(&accounts), Some(B256::repeat_byte(0x07)));
        // Hardware/view-only-only wallet → no local executor.
        let hw_only = vec![view_only_account(addr(0xbb)), ledger_acct(addr(0xcc))];
        assert!(first_local_key_of(&hw_only).is_none());
    }

    #[test]
    fn owner_desc_by_address_matches_or_none() {
        let l = local_with_key(0x05);
        let la = account_address(&l).expect("local has address");
        let accounts = vec![view_only_account(addr(0xbb)), l];
        assert!(matches!(
            owner_desc_by_address(la, &accounts),
            Some(AccountDescriptor::Local { .. })
        ));
        assert!(owner_desc_by_address(addr(0xff), &accounts).is_none());
    }

    #[test]
    fn trim_trailing_decimal_zeros_strips_padding() {
        // `format_units` pads to `decimals`; "1 ETH" comes back with 18
        // trailing zeros. The amount-input must show "1", not the wall.
        assert_eq!(trim_trailing_decimal_zeros("1.000000000000000000"), "1");
        assert_eq!(trim_trailing_decimal_zeros("0.500000000000000000"), "0.5");
        assert_eq!(trim_trailing_decimal_zeros("0.000000000000000000"), "0");
        // Non-trailing zeros and integer-only inputs are preserved.
        assert_eq!(
            trim_trailing_decimal_zeros("0.123456789012"),
            "0.123456789012"
        );
        assert_eq!(trim_trailing_decimal_zeros("42"), "42");
    }

    // ── Safe pending queue: task gating + staleness ──────────────────

    fn safe_desc(chain_id: u64, address: Address) -> crate::wallet::SafeDescriptor {
        crate::wallet::SafeDescriptor {
            name: None,
            chain_id,
            address: address.into(),
            version: "1.4.1".into(),
            trust: crate::wallet::SafeTrust::Canonical,
            threshold: 2,
            owners: vec![addr(0x11).into(), addr(0x22).into()],
            modules: Vec::new(),
            guard: None,
            fallback_handler: None,
            linked_signer_indices: Vec::new(),
            sibling_chains: Vec::new(),
            cached_at: 0,
            tx_service_url: None,
        }
    }

    fn safe_screen(chain_id: u64, safe_addr: Address) -> WalletScreen {
        let mut s = WalletScreen::new(
            KaoSigner::ViewOnly(addr(0xAA)),
            vec![view_only_account(addr(0xAA))],
            vec![safe_desc(chain_id, safe_addr)],
            0,
            Arc::new(MockFetcher::new()),
            new_cache(),
            Arc::new(RwLock::new(ContactsBook::new())),
            None,
        );
        s.active_safe = Some(0);
        s
    }

    fn pending_tx(nonce: u64) -> crate::safe::service::PendingSafeTx {
        crate::safe::service::PendingSafeTx {
            safe_tx_hash: B256::repeat_byte(0xab),
            to: addr(0xdd),
            value: U256::ZERO,
            data: alloy::primitives::Bytes::new(),
            operation: 0,
            nonce,
            state: crate::safe::service::SafeTxState::AwaitingConfirmations {
                have: 1,
                required: 2,
            },
            submission_ts: 0,
        }
    }

    #[test]
    fn fetch_safe_pending_task_is_none_in_eoa_mode() {
        let s = screen_for(addr(0xAA), new_cache());
        assert!(s.fetch_safe_pending_task().is_none());
    }

    #[test]
    fn fetch_safe_pending_task_launches_for_mainnet_safe() {
        // Mainnet always has the seeded default RPC, so an active
        // Mainnet Safe must produce a real task.
        let s = safe_screen(1, addr(0xCC));
        assert!(s.fetch_safe_pending_task().is_some());
    }

    #[test]
    fn fetch_safe_pending_task_is_none_for_unsupported_chain() {
        // chain_id 42161 (Arbitrum) isn't in Chain::ALL — the fetch
        // can't run, so no task may launch (and therefore no loading
        // flag may be set by callers).
        let s = safe_screen(42161, addr(0xCC));
        assert!(s.fetch_safe_pending_task().is_none());
    }

    #[test]
    fn refresh_portfolio_does_not_strand_pending_loading_when_fetch_cannot_launch() {
        // Regression: RefreshPortfolio used to set `safe_pending_loading`
        // for *any* active Safe, even when `fetch_safe_pending_task`
        // couldn't launch — no SafePendingFetched ever arrived and the
        // queue spinner hung forever.
        let mut s = safe_screen(42161, addr(0xCC));
        s.update(Message::RefreshPortfolio);
        assert!(!s.safe_pending_loading);
    }

    #[test]
    fn refresh_portfolio_marks_pending_loading_when_fetch_launches() {
        let mut s = safe_screen(1, addr(0xCC));
        s.update(Message::RefreshPortfolio);
        assert!(s.safe_pending_loading);
    }

    #[test]
    fn safe_pending_fetched_for_active_safe_applies_and_clears_loading() {
        let safe = addr(0xCC);
        let mut s = safe_screen(1, safe);
        s.safe_pending_loading = true;
        s.update(Message::SafePendingFetched {
            safe,
            chain: Chain::Mainnet,
            result: Ok(vec![pending_tx(5)]),
        });
        assert_eq!(s.safe_pending.len(), 1);
        assert_eq!(s.safe_pending[0].nonce, 5);
        assert!(s.safe_pending_error.is_none());
        assert!(!s.safe_pending_loading);
    }

    #[test]
    fn safe_pending_fetched_for_other_safe_is_dropped() {
        // A fetch issued before the user switched Safes must not land in
        // the new identity's queue — same staleness rule as
        // PortfolioFetched/HistoryFetched.
        let mut s = safe_screen(1, addr(0xCC));
        s.update(Message::SafePendingFetched {
            safe: addr(0xEE), // not the active Safe
            chain: Chain::Mainnet,
            result: Ok(vec![pending_tx(5)]),
        });
        assert!(s.safe_pending.is_empty());
    }

    #[test]
    fn safe_pending_fetched_for_wrong_chain_is_dropped() {
        // Same address, different chain — a different Safe. The cached
        // descriptor pins (address, chain_id); a stale fetch tagged with
        // another chain must not apply.
        let safe = addr(0xCC);
        let mut s = safe_screen(1, safe);
        s.update(Message::SafePendingFetched {
            safe,
            chain: Chain::Base,
            result: Ok(vec![pending_tx(5)]),
        });
        assert!(s.safe_pending.is_empty());
    }

    #[test]
    fn safe_pending_fetched_error_is_surfaced_not_swallowed() {
        let safe = addr(0xCC);
        let mut s = safe_screen(1, safe);
        s.safe_pending_loading = true;
        s.update(Message::SafePendingFetched {
            safe,
            chain: Chain::Mainnet,
            result: Err("safe-service queue: HTTP 503".into()),
        });
        assert!(!s.safe_pending_loading);
        assert_eq!(
            s.safe_pending_error.as_deref(),
            Some("safe-service queue: HTTP 503"),
        );
        // A later successful refresh clears the error.
        s.update(Message::SafePendingFetched {
            safe,
            chain: Chain::Mainnet,
            result: Ok(Vec::new()),
        });
        assert!(s.safe_pending_error.is_none());
    }

    // ── rebuild_reviewed_safe_tx (the review-pin enforcement core) ────
    //
    // Every signature in the SafeSend flow goes through this fn. The
    // invariant under test: a signature can only ever cover the exact
    // `(nonce, safeTxHash)` the user verified on the review screen —
    // any drift (missing pin, advanced nonce, hash divergence, wrong
    // version) must abort BEFORE a signer is touched.

    use crate::net::CallMock;
    use crate::wallet::tx::SendToken;
    use alloy::sol_types::{SolCall, SolValue};

    fn reviewed_req(prepared: Option<send::PreparedSafeTx>) -> send::SafeSendRequest {
        send::SafeSendRequest {
            safe_address: addr(0x5A),
            chain: Chain::Mainnet,
            version: "1.4.1".into(),
            trust: crate::wallet::SafeTrust::Canonical,
            service_base: crate::safe::service::DEFAULT_TX_SERVICE_BASE.into(),
            recipient: addr(0xDD),
            amount_units: U256::from(1_000u64),
            token: SendToken::Native,
            threshold: 1,
            signable_indices: vec![0],
            prepared,
        }
    }

    /// The SafeTx `rebuild_reviewed_safe_tx` derives from `reviewed_req`
    /// at `nonce`, plus its local EIP-712 hash.
    fn expected_tx_and_hash(nonce: u64) -> (crate::safe::SafeTx, B256) {
        use crate::safe::tx::{build_safe_tx_with_nonce, safe_domain, safe_tx_hash};
        let req = reviewed_req(None);
        let tx = build_safe_tx_with_nonce(req.safe_tx_input(), nonce);
        let hash = safe_tx_hash(&tx, &safe_domain(req.safe_address, req.chain));
        (tx, hash)
    }

    fn plant_safe_nonce(mock: &CallMock, safe: Address, nonce: u64) {
        mock.set_call(
            safe,
            alloy::primitives::Bytes::from(crate::safe::nonceCall {}.abi_encode()),
            alloy::primitives::Bytes::from(U256::from(nonce).abi_encode()),
            true,
        );
    }

    #[tokio::test]
    async fn rebuild_refuses_without_a_review_pin() {
        let mock = CallMock::new();
        let err = rebuild_reviewed_safe_tx(&mock, &reviewed_req(None))
            .await
            .unwrap_err();
        assert!(err.contains("reviewed hash"), "{err}");
    }

    #[tokio::test]
    async fn rebuild_refuses_unsignable_version_before_any_chain_read() {
        // Nothing planted on the mock: if the version guard didn't fire
        // first, the nonce read would fail with a different error.
        let mock = CallMock::new();
        let mut req = reviewed_req(Some(send::PreparedSafeTx {
            nonce: 7,
            safe_tx_hash: B256::repeat_byte(0xaa),
        }));
        req.version = "1.1.1".into();
        let err = rebuild_reviewed_safe_tx(&mock, &req).await.unwrap_err();
        assert!(err.contains("outside the signable range"), "{err}");
    }

    #[tokio::test]
    async fn rebuild_refuses_unrecognized_safe_before_any_chain_read() {
        // Nothing planted on the mock: if the trust guard didn't fire
        // first, the nonce read would fail with a different error.
        let mock = CallMock::new();
        let mut req = reviewed_req(Some(send::PreparedSafeTx {
            nonce: 7,
            safe_tx_hash: B256::repeat_byte(0xaa),
        }));
        req.trust = crate::wallet::SafeTrust::UnrecognizedImpl;
        let err = rebuild_reviewed_safe_tx(&mock, &req).await.unwrap_err();
        assert!(err.contains("not recognized as canonical"), "{err}");
    }

    #[tokio::test]
    async fn rebuild_refuses_when_nonce_advanced_since_review() {
        // A co-signer executed something between review and click — the
        // live nonce is past the pin. Clear error, no signature.
        let mock = CallMock::new();
        let req = reviewed_req(Some(send::PreparedSafeTx {
            nonce: 7,
            safe_tx_hash: B256::repeat_byte(0xaa),
        }));
        plant_safe_nonce(&mock, req.safe_address, 8);
        let err = rebuild_reviewed_safe_tx(&mock, &req).await.unwrap_err();
        assert!(err.contains("advanced since review"), "{err}");
        assert!(err.contains("7 → 8"), "{err}");
    }

    #[tokio::test]
    async fn rebuild_refuses_when_pin_hash_diverges_from_rebuilt_tx() {
        // Pin carries the right nonce but a hash that doesn't match the
        // rebuilt tx (form/pin desync — a bug, but the invariant holds).
        let mock = CallMock::new();
        let req = reviewed_req(Some(send::PreparedSafeTx {
            nonce: 7,
            safe_tx_hash: B256::repeat_byte(0xaa), // not the real hash
        }));
        plant_safe_nonce(&mock, req.safe_address, 7);
        let err = rebuild_reviewed_safe_tx(&mock, &req).await.unwrap_err();
        assert!(err.contains("differs from the reviewed hash"), "{err}");
    }

    #[tokio::test]
    async fn rebuild_passes_when_pin_matches_and_contract_agrees() {
        use crate::safe::tx::safe_domain;
        let mock = CallMock::new();
        let (tx, local_hash) = expected_tx_and_hash(7);
        let req = reviewed_req(Some(send::PreparedSafeTx {
            nonce: 7,
            safe_tx_hash: local_hash,
        }));
        let safe = req.safe_address;
        plant_safe_nonce(&mock, safe, 7);
        // Contract agrees on both pre-sign checks.
        mock.set_call(
            safe,
            alloy::primitives::Bytes::from(crate::safe::domainSeparatorCall {}.abi_encode()),
            alloy::primitives::Bytes::from(
                safe_domain(safe, Chain::Mainnet).separator().abi_encode(),
            ),
            true,
        );
        mock.set_call(
            safe,
            alloy::primitives::Bytes::from(
                crate::safe::getTransactionHashCall {
                    to: tx.to,
                    value: tx.value,
                    data: tx.data.clone(),
                    operation: tx.operation,
                    safeTxGas: tx.safeTxGas,
                    baseGas: tx.baseGas,
                    gasPrice: tx.gasPrice,
                    gasToken: tx.gasToken,
                    refundReceiver: tx.refundReceiver,
                    _nonce: tx.nonce,
                }
                .abi_encode(),
            ),
            alloy::primitives::Bytes::from(local_hash.abi_encode()),
            true,
        );
        let (got_tx, _domain, got_hash) = rebuild_reviewed_safe_tx(&mock, &req).await.unwrap();
        assert_eq!(got_hash, local_hash);
        assert_eq!(got_tx.to, tx.to);
        assert_eq!(got_tx.value, tx.value);
        assert_eq!(got_tx.nonce, tx.nonce);
        assert_eq!(got_tx.operation, tx.operation);
    }

    #[tokio::test]
    async fn rebuild_refuses_when_contract_disputes_the_hash() {
        // Pin and local rebuild agree, but the contract's
        // getTransactionHash differs (wrong contract / encoding drift).
        // The on-chain cross-check must still veto.
        let mock = CallMock::new();
        let (tx, local_hash) = expected_tx_and_hash(7);
        let req = reviewed_req(Some(send::PreparedSafeTx {
            nonce: 7,
            safe_tx_hash: local_hash,
        }));
        let safe = req.safe_address;
        plant_safe_nonce(&mock, safe, 7);
        mock.set_call(
            safe,
            alloy::primitives::Bytes::from(crate::safe::domainSeparatorCall {}.abi_encode()),
            alloy::primitives::Bytes::from(
                crate::safe::tx::safe_domain(safe, Chain::Mainnet)
                    .separator()
                    .abi_encode(),
            ),
            true,
        );
        mock.set_call(
            safe,
            alloy::primitives::Bytes::from(
                crate::safe::getTransactionHashCall {
                    to: tx.to,
                    value: tx.value,
                    data: tx.data.clone(),
                    operation: tx.operation,
                    safeTxGas: tx.safeTxGas,
                    baseGas: tx.baseGas,
                    gasPrice: tx.gasPrice,
                    gasToken: tx.gasToken,
                    refundReceiver: tx.refundReceiver,
                    _nonce: tx.nonce,
                }
                .abi_encode(),
            ),
            alloy::primitives::Bytes::from(B256::repeat_byte(0x66).abi_encode()),
            true,
        );
        let err = rebuild_reviewed_safe_tx(&mock, &req).await.unwrap_err();
        assert!(err.contains("safe hash mismatch"), "{err}");
    }
}
