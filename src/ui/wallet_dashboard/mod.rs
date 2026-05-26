//! Kao Wallet dashboard — the main screen shown after unlock.
//!
//! Layout mirrors the HTML mock in `kao/project/Kao Wallet.html`:
//! a thin sidebar (wordmark · Home/Activity/Settings · theme dots), a header
//! with a mood kaomoji, and one of three content panes. Send and Receive are
//! modal overlays rendered via `stack`.

use std::mem;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use alloy::primitives::{Address, TxHash};
use iced::border::Radius;
use iced::widget::operation::focus as focus_widget;
use iced::widget::{Space, column, container, row, stack, text};
use iced::{Alignment, Background, Border, Element, Length, Padding, Subscription, Task};
use tracing::{debug, info, warn};

mod account_dropdown;
mod activity;
mod appearance;
mod contacts_settings;
mod function_panel;
mod header;
mod home;
mod modal_chrome;
mod nav;
mod networks;
mod receive;
mod send;
mod settings_root;
mod sidebar;
mod swap;
mod tx_details;
mod wc_panes;

use account_dropdown::AccountDropdown;
use contacts_settings::ContactsPane;
use networks::NetworksPane;
use receive::ReceivePane;
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

/// How long after a copy we wait before nuking the clipboard. Doubles as
/// the lifetime of the bottom-right "autoclear in N…" chip — the chip's
/// progress bar fills this whole duration.
const CLIPBOARD_CLEAR_SECS: u64 = 10;

use modal_chrome::ModalChrome;
pub use nav::Nav;

use crate::chain::PerChain;
use crate::indexer::IndexedTx;
use crate::net::{BalanceFetcher, VerificationStatus};
use crate::portfolio::{LiveToken, PortfolioCache};
use crate::settings::{self, IndexerProvider};
use crate::ui::kao_theme::with_alpha;
use crate::ui::kao_theme::{KaoTheme, ThemeKind};
use crate::ui::kao_widgets::{fill_style, mono};
use crate::wallet::tx::SendPlan;
use crate::wallet::{
    AccountDescriptor, Contact, ContactsBook, KaoSigner, SignerHandoff, handoff_with, short_address,
};

// ── Messages ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Message {
    /// Side-effect ack from the Mainnet Helios verification refresh.
    /// The handler just samples `network.last_status(Mainnet)` to drive
    /// the header badge — no per-address state changes here, so a stale
    /// fetch landing after an account switch is harmless.
    VerificationRefreshed,
    /// Per-chain portfolio result. The dashboard issues one fetch per
    /// configured chain in parallel and merges by `chain` as each lands,
    /// so a slow Optimism RPC never blocks the Mainnet rows from
    /// rendering. `address` is checked on arrival so a late response
    /// can't pollute the wrong account's portfolio (or its cache slot).
    PortfolioFetched {
        address: Address,
        chain: crate::chain::Chain,
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
    SelectNav(Nav),
    SelectTheme(ThemeKind),
    OpenSend,
    OpenReceive,
    OpenSwap,
    OpenAccountDropdown,
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
    Networks(networks::Message),
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
        actual: Option<String>,
    },
    // ── WalletConnect ──────────────────────────────────────────────────
    /// App tells the dashboard the WC state changed (proposal arrived,
    /// session settled, etc) and the modal slot may need to open. The
    /// dashboard reads `wc_state` and reconciles.
    WcStateChanged,
    /// Each keystroke into the Home pane's "Paste wc: URI" input.
    WcPasteInput(String),
    /// User pressed Enter / Connect on the wc URI input. Dispatches
    /// `WcCommand::PairWithUri` to the engine via the global handle.
    WcSubmitUri,
    /// User clicked Approve on the current proposal modal. Carries the
    /// `proposal_id` so a stale modal redraw can't approve the wrong one.
    WcApproveProposal(u64),
    /// User clicked Reject on the current proposal modal.
    WcRejectProposal(u64),
    /// User clicked Approve on the current request modal. The dashboard
    /// runs the per-method signer code, then dispatches `ApproveRequest`
    /// with the result or `RejectRequest` on signer error.
    WcApproveRequest(u64),
    /// User clicked Reject on the current request modal.
    WcRejectRequest(u64),
    /// Result of an async signer task spawned from `WcApproveRequest`.
    /// `request_id` lets the engine match this back to the original
    /// request even if the user has since dismissed the modal.
    WcRequestSigned {
        request_id: u64,
        result: Result<serde_json::Value, crate::walletconnect::protocol::JsonRpcError>,
    },
    /// User clicked Disconnect on a row in the Sessions settings pane.
    WcDisconnectSession(crate::walletconnect::crypto::Topic),
    /// User clicked "Sessions" in Settings → Root.
    OpenWcSessionsSettings,
    /// User clicked the ✕ on the WC error banner.
    WcDismissError,
    /// User clicked "Show details" / "Hide details" on the proposal modal.
    /// Toggles the raw-namespace expander so the wall-of-eip155-IDs is
    /// hidden by default but reachable for power users.
    WcToggleProposalDetails,
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
}

// ── State ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum Modal {
    None,
    Send(SendPane),
    Receive(ReceivePane),
    Swap(SwapPane),
    AccountDropdown(AccountDropdown),
    TxDetails(TxDetailsPane),
    /// WalletConnect modal slot. The actual proposal-vs-request shape lives
    /// in `wc_state.current_modal` so the engine subscription can mutate
    /// the queue in place without rebuilding the dashboard. This variant
    /// is just "a WC modal is on screen" — view() reads `wc_state` for the
    /// contents. Kept as its own variant rather than reusing Modal::None so
    /// the chrome animation runs and other modals can't open underneath.
    Wc,
}

/// Which settings pane is currently rendered. The Settings nav slot can show
/// either the root list of categories or one of the deeper category screens.
#[derive(Debug)]
enum SettingsPane {
    Root,
    Networks(NetworksPane),
    Appearance,
    Contacts(ContactsPane),
    /// WalletConnect sessions list. Read-only view of `wc_state.sessions`
    /// with a per-row Disconnect button. No screen-local state — the list
    /// is rebuilt from `wc_state` on every render so a settle event lands
    /// without re-entering the pane.
    WcSessions,
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
    /// Active clipboard auto-clear, set when the user copies anything
    /// from a child modal (Send, TxDetails). Drives the bottom-right
    /// countdown chip and the deferred ownership-checked clear.
    clipboard_clear: Option<ClipboardClearState>,
    /// Monotonic counter bumped on every fresh copy so a stale
    /// `ClipboardClearArmed` / `ClipboardClearProbe` from an older arm
    /// can't clobber the chip or the clipboard.
    clipboard_clear_gen: u64,
    /// Shared WalletConnect UI state. Written by App as engine events
    /// land (via `Message::Wc`), read by the dashboard's view + the
    /// Sessions settings pane. Mirrors the contacts `Arc<RwLock<…>>`
    /// pattern so a settle event repaints without rebuilding the dashboard.
    wc_state: Arc<RwLock<crate::walletconnect::state::WcState>>,
    /// Live "Paste wc: URI" input on the Home pane. Lives on the
    /// dashboard rather than `WcState` so the iced `text_input` can
    /// borrow from a stable self-lifetime location instead of a
    /// short-lived RwLock guard.
    wc_paste_input: String,
    /// Whether the proposal modal's raw-namespace expander is open. Reset
    /// on each new proposal (see the `WcStateChanged` handler).
    wc_proposal_details_expanded: bool,
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
    #[allow(clippy::too_many_arguments)] // App-level wiring; refactoring this to a struct would just move the same fields with no readability win.
    pub fn new(
        signer: KaoSigner,
        accounts: Vec<AccountDescriptor>,
        active_index: usize,
        network: Arc<dyn BalanceFetcher>,
        portfolio_cache: PortfolioCache,
        contacts: Arc<RwLock<ContactsBook>>,
        wc_state: Arc<RwLock<crate::walletconnect::state::WcState>>,
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
                .filter_map(|chain| c.get(&(address, *chain)).cloned())
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
            portfolio_cache,
            rename_draft: None,
            history: Vec::new(),
            history_loading: false,
            history_loaded: false,
            history_errors: PerChain::default(),
            history_pending: Vec::new(),
            contacts,
            clipboard_clear: None,
            clipboard_clear_gen: 0,
            wc_state,
            wc_paste_input: String::new(),
            wc_proposal_details_expanded: false,
        }
    }

    /// Move the live signer out of the dashboard. Used by the App when it
    /// transitions away from the dashboard (e.g. into the add-account flow)
    /// and wants to park the signer to return cheaply later.
    pub fn into_signer(self) -> KaoSigner {
        self.signer
    }

    /// Write `text` to the system clipboard and arm the deferred clear.
    /// Bumps the generation counter so any older arm fires stale and
    /// no-ops. The returned task batches the write itself with a
    /// `tokio::time::sleep` that emits `ClipboardClearArmed` once the
    /// deadline passes — the ownership check happens at that point, not
    /// here.
    fn arm_clipboard_clear(&mut self, text: String) -> Task<Message> {
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
            _ => false,
        }
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

    /// Issue a Mainnet `network.balance` call purely to refresh the
    /// Helios verification badge — the result is discarded; only the
    /// side-effect on `last_status(Mainnet)` matters. Without this the
    /// badge would never leave "Connecting…": `get_code`,
    /// `get_storage_at`, and `call` deliberately don't touch
    /// `last_status` so the proxy walker can't flicker the badge on
    /// every clear-signing probe, and the portfolio fetch goes through
    /// the raw fallback provider rather than helios.
    pub fn refresh_verification_task(&self) -> Task<Message> {
        let address = self.address;
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
        let address = self.address;
        let provider_kind = settings::indexer_provider();
        let mut tasks: Vec<Task<Message>> = Vec::new();
        for chain in crate::chain::Chain::ALL {
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
        let address = self.address;
        let provider_kind = settings::indexer_provider();
        let mut tasks: Vec<Task<Message>> = Vec::new();
        for chain in crate::chain::Chain::ALL {
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
                    chain,
                    result,
                },
            ));
        }
        Task::batch(tasks)
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
                debug!(addr = %short_address(address), "ens reverse lookup");
                let started = std::time::Instant::now();
                let result = match network.provider(crate::chain::Chain::Mainnet).await {
                    Some(provider) => crate::ens::lookup_address(&provider, address).await,
                    None => Err("no execution RPCs configured".to_string()),
                };
                debug!(
                    elapsed = ?started.elapsed(),
                    found = matches!(&result, Ok(Some(_))),
                    "ens reverse lookup completed",
                );
                (address, result)
            },
            |(address, result)| Message::EnsAutoNameResolved { address, result },
        )
    }

    pub fn update(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        match message {
            Message::VerificationRefreshed => {
                self.verification = self.network.last_status(crate::chain::Chain::Mainnet);
            }
            Message::PortfolioFetched {
                address,
                chain,
                result,
            } => {
                // Always write the (address, chain) we issued the fetch
                // for into the cache — it's still the correct slot for
                // that account's data even if the user has since
                // switched away. Only the live portfolio merge is gated
                // on `address == self.address`.
                if let Ok(tokens) = &result
                    && let Ok(mut cache) = self.portfolio_cache.lock()
                {
                    cache.insert((address, chain), tokens.clone());
                }
                if address != self.address {
                    return (Task::none(), None);
                }
                // Loading flag clears once *any* chain lands; the user
                // sees results stream in rather than wait for the
                // slowest chain.
                self.portfolio_loading = false;
                match result {
                    Ok(tokens) => {
                        // Merge by chain: replace the rows belonging to
                        // `chain` with the new ones, leave other chains'
                        // rows untouched. Re-sort ETH-first then by USD
                        // value descending so a late-landing chain
                        // doesn't shuffle a stable row order — the
                        // original portfolio sort already maintained this.
                        self.portfolio.retain(|t| t.chain != chain);
                        self.portfolio.extend(tokens);
                        self.portfolio.sort_by(|a, b| {
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
                    Err(e) => warn!(
                        chain = %chain.label(),
                        error = %e,
                        "portfolio fetch failed",
                    ),
                }
            }
            Message::HistoryFetched {
                address,
                chain,
                result,
            } => {
                if address != self.address {
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
                self.history_pending = crate::chain::Chain::ALL
                    .iter()
                    .copied()
                    .filter(|c| !settings::rpcs(*c).is_empty())
                    .collect();
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
                    self.history_pending = crate::chain::Chain::ALL
                        .iter()
                        .copied()
                        .filter(|c| !settings::rpcs(*c).is_empty())
                        .collect();
                    return (self.fetch_history_task(), None);
                }
            }
            Message::SelectTheme(k) => {
                self.theme_kind = k;
                settings::set_theme(k);
            }
            Message::OpenSend => {
                if !self.signer.can_sign() {
                    // View-only accounts can't broadcast. Open the modal in
                    // a "this is read-only" state would be nicer; for now,
                    // refuse to open it at all.
                    info!("send disabled: active account is view-only");
                    return (Task::none(), None);
                }
                self.modal = Modal::Send(SendPane::new(self.address));
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
                // Hold the contacts read guard for the duration of the
                // pane's update. iced is single-threaded so there is no
                // contention; the guard exists only because the pane's
                // `update` signature takes `&ContactsBook`.
                let contacts_guard = match self.contacts.read() {
                    Ok(g) => g,
                    Err(_) => {
                        warn!("contacts lock poisoned; treating as empty for send update");
                        // Fall through with a fresh empty book so the
                        // pane still functions (no contacts shown).
                        return (Task::none(), None);
                    }
                };
                let book: &ContactsBook = &contacts_guard;
                // ── Coordinator-side intercepts ────────────────────────
                //
                // Some pane messages need data the pane doesn't carry
                // (portfolio entries, the live signer, the network
                // provider). Handle those here, then either short-circuit
                // or forward to the pane.

                // Max: compute the largest sendable amount for the active
                // token. For native ETH, subtract the (loaded) gas cost so
                // the user isn't left dust-stuck at broadcast time.
                if let send::Message::Max = &child_msg {
                    if let Some(tk) = self.portfolio.get(p.token_idx()) {
                        let max_str = compute_max_amount(tk, p);
                        p.apply_max(max_str);
                    }
                    return (Task::none(), None);
                }

                // Step(2): user clicked "Review →". Spawn a quote task
                // (gas + 1559 fees + nonce) AND a clear-signing decode
                // task — both against the same plan the pane will
                // eventually broadcast.
                if let send::Message::Step(2) = &child_msg {
                    let plan = p.build_plan(&self.portfolio);
                    let pre_task = match plan {
                        Some(pl) => {
                            p.quote_started();
                            let decode_seq = p.decode_started();
                            let quote_task = spawn_quote_task(self.network.clone(), pl.clone());
                            let decode_task =
                                spawn_decode_task(self.network.clone(), decode_seq, pl);
                            Task::batch([quote_task, decode_task])
                        }
                        None => Task::none(),
                    };
                    let (task, _outcome) = p.update(child_msg, book);
                    let task = task.map(Message::Send);
                    return (Task::batch([pre_task, task]), None);
                }

                // Confirm: user clicked "Confirm Send ✓". Need to move
                // the signer out of the dashboard, run sign+broadcast in
                // a task, and route the signer back via `SignerHandoff`.
                if let send::Message::Confirm = &child_msg {
                    let plan = p.build_plan(&self.portfolio);
                    // Clone the quote — TxQuote stopped being Copy when it
                    // grew the SimulationResult field; spawn_broadcast_task
                    // still takes ownership.
                    let quote = p.quote().cloned();
                    info!(
                        has_plan = plan.is_some(),
                        has_quote = quote.is_some(),
                        "send: confirm clicked",
                    );
                    if let (Some(plan), Some(quote)) = (plan, quote) {
                        info!(
                            chain = %plan.chain.label(),
                            chain_id = plan.chain.chain_id(),
                            from = %plan.from,
                            recipient = %plan.recipient,
                            amount_units = %plan.amount_units,
                            erc20 = matches!(plan.token, crate::wallet::tx::SendToken::Erc20 { .. }),
                            gas_limit = quote.gas_limit,
                            nonce = quote.nonce,
                            "send: spawning broadcast task",
                        );
                        // Move the signer out — only ViewOnly stays
                        // behind so the dashboard view doesn't crash if
                        // it dereferences the signer's address while the
                        // task is running. self.address stays correct.
                        let signer =
                            mem::replace(&mut self.signer, KaoSigner::ViewOnly(self.address));
                        let handoff = handoff_with(signer);
                        let pre_task =
                            spawn_broadcast_task(self.network.clone(), handoff, plan, quote);
                        let (task, _outcome) = p.update(child_msg, book);
                        let task = task.map(Message::Send);
                        return (Task::batch([pre_task, task]), None);
                    }
                    // Missing plan or quote — let the pane no-op the
                    // confirm. Surface this loudly: it's the most common
                    // "send button does nothing" cause (button enabled,
                    // user clicks, no broadcast spawned).
                    warn!("send: confirm dropped — no plan or no quote");
                    let (task, _outcome) = p.update(child_msg, book);
                    return (task.map(Message::Send), None);
                }

                let (task, outcome) = p.update(child_msg, book);
                // After pumping the pane, check whether the recipient
                // input now points at an ENS-shaped value that hasn't been
                // dispatched yet. The pane bumps a sequence on each
                // change; `take_pending_ens` returns Some exactly once
                // per sequence so a no-op repaint won't refire the lookup.
                let ens_task = match p.take_pending_ens() {
                    Some((seq, name)) => spawn_ens_resolve_task(self.network.clone(), seq, name),
                    None => Task::none(),
                };
                let task = task.map(Message::Send);
                // Drop the read guard before mutating self below (which
                // happens in the SaveAsContact branch via OpenContactsPaneWith).
                drop(contacts_guard);
                match outcome {
                    Some(send::Outcome::Closed) => {
                        self.chrome.start_close();
                        return (Task::batch([task, ens_task]), None);
                    }
                    Some(send::Outcome::CopyText(s)) => {
                        let copy_task = self.arm_clipboard_clear(s);
                        return (Task::batch([task, copy_task, ens_task]), None);
                    }
                    Some(send::Outcome::SaveAsContact { address, ens }) => {
                        // Reuse the existing OpenContactsPaneWith path —
                        // switches nav, opens contacts pane in Add mode
                        // pre-filled, and starts the modal close
                        // animation. We synthesize the same Message
                        // here and forward it to ourselves on the next
                        // tick rather than inlining the body to keep
                        // the two entry points behaviourally identical.
                        let open_task = Task::done(Message::OpenContactsPaneWith { address, ens });
                        return (Task::batch([task, ens_task, open_task]), None);
                    }
                    None => return (Task::batch([task, ens_task]), None),
                }
            }
            Message::SendBroadcastReturn { result, signer } => {
                // Reclaim the signer regardless of pane state — the
                // dashboard must always end up holding it again.
                if let Ok(mut g) = signer.lock() {
                    if let Some(s) = g.take() {
                        self.signer = s;
                    } else {
                        warn!("broadcast return: signer cell was empty");
                    }
                }
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
                    let contacts_guard = match self.contacts.read() {
                        Ok(g) => g,
                        Err(_) => {
                            warn!("contacts lock poisoned in broadcast return");
                            return (Task::none(), None);
                        }
                    };
                    let (task, _outcome) =
                        p.update(send::Message::BroadcastDone(result), &contacts_guard);
                    drop(contacts_guard);
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
                            self.history_pending = crate::chain::Chain::ALL
                                .iter()
                                .copied()
                                .filter(|c| !settings::rpcs(*c).is_empty())
                                .collect();
                            tasks.push(self.fetch_history_task());
                        }
                        Task::batch(tasks)
                    } else {
                        Task::none()
                    };
                    return (Task::batch([task.map(Message::Send), refresh]), None);
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
                        warn!(error = %e, "ens auto-name lookup failed");
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
                let task = iced::clipboard::read()
                    .map(move |actual| Message::ClipboardClearProbe { generation, actual });
                return (task, None);
            }
            Message::ClipboardClearProbe { generation, actual } => {
                let Some(state) = &self.clipboard_clear else {
                    return (Task::none(), None);
                };
                if state.generation != generation {
                    return (Task::none(), None);
                }
                let still_ours = actual.as_deref() == Some(state.expected.as_str());
                self.clipboard_clear = None;
                if still_ours {
                    let clear = iced::clipboard::write(String::new())
                        .map(|_: ()| Message::ClipboardWritten);
                    return (clear, None);
                }
                return (Task::none(), None);
            }
            Message::OpenReceive => {
                self.modal = Modal::Receive(ReceivePane::new(self.address));
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
                    None => return (task, None),
                }
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
                        if idx != self.active_index && idx < self.accounts.len() {
                            return (task, Some(Outcome::Switch(idx)));
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
            Message::Tick => {
                if self.chrome.tick_settled() {
                    self.modal = Modal::None;
                }
            }
            Message::OpenNetworksSettings => {
                self.settings_pane =
                    SettingsPane::Networks(NetworksPane::new(self.network.clone()));
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
            Message::Networks(child_msg) => {
                let SettingsPane::Networks(p) = &mut self.settings_pane else {
                    return (Task::none(), None);
                };
                let (task, outcome) = p.update(child_msg);
                let task = task.map(Message::Networks);
                match outcome {
                    Some(networks::Outcome::Closed) => {
                        self.settings_pane = SettingsPane::Root;
                        return (task, None);
                    }
                    None => return (task, None),
                }
            }
            // ── WalletConnect ──────────────────────────────────────────
            Message::WcStateChanged => {
                let has_modal = self
                    .wc_state
                    .read()
                    .map(|g| g.current_modal.is_some())
                    .unwrap_or(false);
                match (&self.modal, has_modal) {
                    (Modal::None, true) => {
                        self.modal = Modal::Wc;
                        self.chrome.open();
                        // Fresh modal — collapse the proposal details
                        // expander so each new proposal starts in the
                        // "summary" view, never inheriting a stale toggle
                        // from the previous one.
                        self.wc_proposal_details_expanded = false;
                    }
                    (Modal::Wc, false) => {
                        // Modal queue drained while the chrome was still
                        // open (e.g. dApp deleted the session before the
                        // user approved). Tear down the slot.
                        self.chrome.start_close();
                    }
                    _ => {
                        // Either a non-WC modal is open (we don't preempt
                        // a Send-in-flight to show a WC modal — the
                        // event sits in `wc_state.queue` until the user
                        // closes the active modal) or there is no
                        // change to the slot.
                    }
                }
            }
            Message::WcPasteInput(s) => {
                self.wc_paste_input = s;
                if let Ok(mut g) = self.wc_state.write() {
                    g.last_error = None;
                }
            }
            Message::WcSubmitUri => {
                let uri = self.wc_paste_input.trim().to_string();
                if uri.is_empty() {
                    return (Task::none(), None);
                }
                use crate::walletconnect::engine::WcCommand;
                use crate::walletconnect::runtime::dispatch;
                match dispatch(WcCommand::PairWithUri { uri: uri.clone() }) {
                    Ok(()) => {
                        self.wc_paste_input.clear();
                        if let Ok(mut g) = self.wc_state.write() {
                            g.last_error = None;
                        }
                    }
                    Err(()) => {
                        if let Ok(mut g) = self.wc_state.write() {
                            g.last_error = Some(
                                "WalletConnect is offline — try again in a moment".to_string(),
                            );
                        }
                    }
                }
            }
            Message::WcApproveProposal(proposal_id) => {
                // Build the settled namespaces from the proposal's
                // required + optional, restricted to Kao's supported
                // chains and methods. Methods missing from
                // `walletconnect::methods::handle_method` are dropped so a
                // dApp asking for legacy `eth_sign` doesn't end up with an
                // unenforceable scope. Accounts are stamped with the
                // active address per CAIP-10.
                let snap = match self.wc_state.read() {
                    Ok(g) => g.clone(),
                    Err(_) => return (Task::none(), None),
                };
                let proposal = match snap.current_modal {
                    Some(crate::walletconnect::state::WcModal::Proposal(p))
                        if p.proposal_id == proposal_id =>
                    {
                        p
                    }
                    _ => return (Task::none(), None),
                };
                let namespaces = build_approved_namespaces(self.address, &proposal);
                let wallet_metadata = kao_wallet_metadata();
                use crate::walletconnect::engine::WcCommand;
                use crate::walletconnect::runtime::dispatch;
                let _ = dispatch(WcCommand::ApproveProposal {
                    proposal_id,
                    namespaces,
                    wallet_metadata,
                });
                // Close the modal now — the SessionSettled event will
                // refresh the sessions list. The chrome animation drives
                // the visual close; the Tick handler clears Modal::Wc.
                if let Ok(mut g) = self.wc_state.write() {
                    let _ = g.pop_current();
                }
                if matches!(self.modal, Modal::Wc)
                    && let Ok(g) = self.wc_state.read()
                    && g.current_modal.is_none()
                {
                    self.chrome.start_close();
                }
            }
            Message::WcRejectProposal(proposal_id) => {
                use crate::walletconnect::engine::WcCommand;
                use crate::walletconnect::runtime::dispatch;
                let _ = dispatch(WcCommand::RejectProposal {
                    proposal_id,
                    reason: "User rejected".to_string(),
                });
                if let Ok(mut g) = self.wc_state.write() {
                    // Only pop if the active modal is this proposal; a
                    // stale message after the user already moved on
                    // should not eject the next modal off the queue.
                    let stale = !matches!(
                        &g.current_modal,
                        Some(crate::walletconnect::state::WcModal::Proposal(p))
                            if p.proposal_id == proposal_id
                    );
                    if !stale {
                        let _ = g.pop_current();
                    }
                }
                if matches!(self.modal, Modal::Wc)
                    && let Ok(g) = self.wc_state.read()
                    && g.current_modal.is_none()
                {
                    self.chrome.start_close();
                }
            }
            Message::WcApproveRequest(request_id) => {
                let snap = match self.wc_state.read() {
                    Ok(g) => g.clone(),
                    Err(_) => return (Task::none(), None),
                };
                let req = match snap.current_modal {
                    Some(crate::walletconnect::state::WcModal::Request(r))
                        if r.request_id == request_id =>
                    {
                        r
                    }
                    _ => return (Task::none(), None),
                };
                let task = spawn_wc_method_task(&self.signer, req);
                return (task, None);
            }
            Message::WcRequestSigned { request_id, result } => {
                use crate::walletconnect::engine::WcCommand;
                use crate::walletconnect::runtime::dispatch;
                let cmd = match result {
                    Ok(v) => WcCommand::ApproveRequest {
                        request_id,
                        result: v,
                    },
                    Err(e) => WcCommand::RejectRequest {
                        request_id,
                        error: Some(e),
                    },
                };
                let _ = dispatch(cmd);
                if let Ok(mut g) = self.wc_state.write() {
                    let stale = !matches!(
                        &g.current_modal,
                        Some(crate::walletconnect::state::WcModal::Request(r))
                            if r.request_id == request_id
                    );
                    if !stale {
                        let _ = g.pop_current();
                    }
                }
                if matches!(self.modal, Modal::Wc)
                    && let Ok(g) = self.wc_state.read()
                    && g.current_modal.is_none()
                {
                    self.chrome.start_close();
                }
            }
            Message::WcRejectRequest(request_id) => {
                use crate::walletconnect::engine::WcCommand;
                use crate::walletconnect::runtime::dispatch;
                let _ = dispatch(WcCommand::RejectRequest {
                    request_id,
                    error: None,
                });
                if let Ok(mut g) = self.wc_state.write() {
                    let stale = !matches!(
                        &g.current_modal,
                        Some(crate::walletconnect::state::WcModal::Request(r))
                            if r.request_id == request_id
                    );
                    if !stale {
                        let _ = g.pop_current();
                    }
                }
                if matches!(self.modal, Modal::Wc)
                    && let Ok(g) = self.wc_state.read()
                    && g.current_modal.is_none()
                {
                    self.chrome.start_close();
                }
            }
            Message::WcDisconnectSession(topic) => {
                use crate::walletconnect::engine::WcCommand;
                use crate::walletconnect::runtime::dispatch;
                let _ = dispatch(WcCommand::Disconnect {
                    topic,
                    reason: "User disconnected".to_string(),
                });
                // The engine will emit SessionDeleted; App will update
                // `wc_state.sessions`. No optimistic local removal — a
                // failed disconnect would otherwise leave the UI lying.
            }
            Message::OpenWcSessionsSettings => {
                self.settings_pane = SettingsPane::WcSessions;
            }
            Message::WcDismissError => {
                if let Ok(mut g) = self.wc_state.write() {
                    g.last_error = None;
                }
            }
            Message::WcToggleProposalDetails => {
                self.wc_proposal_details_expanded = !self.wc_proposal_details_expanded;
            }
        }
        (Task::none(), None)
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let mut subs: Vec<Subscription<Message>> = Vec::new();
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
            Modal::Wc | Modal::None => {}
        }
        match &self.settings_pane {
            SettingsPane::Networks(p) => subs.push(p.subscription().map(Message::Networks)),
            SettingsPane::Contacts(p) => subs.push(p.subscription().map(Message::Contacts)),
            _ => {}
        }
        if self.chrome.is_animating() || self.clipboard_clear.is_some() {
            // `time::every` actively drives ticks (and therefore redraws)
            // on a timer; `window::frames()` only observes redraws the
            // runtime already decided to do, which left the animation idle
            // between unrelated events. 16 ms (~60 Hz) is plenty for the
            // 220 ms ease — going faster just burns CPU during the modal
            // open/close transition. The clipboard countdown chip rides
            // the same subscription so its progress bar animates smoothly
            // for the 10-second auto-clear window.
            subs.push(iced::time::every(Duration::from_millis(16)).map(|_| Message::Tick));
        }
        Subscription::batch(subs)
    }

    fn theme(&self) -> KaoTheme {
        KaoTheme::for_kind(self.theme_kind)
    }

    // ── View ────────────────────────────────────────────────────────────────

    pub fn view(&self) -> Element<'_, Message> {
        let t = self.theme();

        // Hold the wc_state read guard for the full view tick. Falls back
        // to an owned default snapshot on poisoning. The guard outlives
        // every iced widget that borrows from `wc` because both `main_pane`
        // and the modal layer drop their references before view() returns.
        let wc_guard = self.wc_state.read().ok();
        let wc_fallback = crate::walletconnect::state::WcState::default();
        let wc: &crate::walletconnect::state::WcState = match &wc_guard {
            Some(g) => g,
            None => &wc_fallback,
        };

        let app = row![sidebar::view(t, self.nav), self.main_pane(t, wc)]
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
        // the widget tree.
        let contacts_view: send::ContactsView = match self.contacts.read() {
            Ok(g) => send::ContactsView::from_book(&g),
            Err(_) => send::ContactsView::default(),
        };

        // Always render the same `stack![background, modal_layer]` tree
        // shape so iced doesn't reset child widget state when a modal
        // opens or closes. Without this, opening a modal changes the
        // tree from `Container` to `Stack(Container, Modal)`, and the
        // activity feed's scroll position (and any other internal
        // widget state below) snaps back to its default.
        let modal_layer: Element<'_, Message> = match &self.modal {
            Modal::None => Space::new().width(0).height(0).into(),
            Modal::Send(p) => p
                .view(t, &self.portfolio, contacts_view, self.chrome.progress())
                .map(Message::Send),
            Modal::Receive(p) => p.view(t, self.chrome.progress()).map(Message::Receive),
            Modal::Swap(p) => p.view(t, self.chrome.progress()).map(Message::Swap),
            Modal::AccountDropdown(d) => d
                .view(t, &self.accounts, self.active_index)
                .map(Message::AccountDropdown),
            Modal::TxDetails(p) => {
                let tx_book = match self.contacts.read() {
                    Ok(g) => g.clone(),
                    Err(_) => ContactsBook::new(),
                };
                p.view(t, self.chrome.progress(), &tx_book)
                    .map(Message::TxDetails)
            }
            Modal::Wc => {
                // Reuse the already-held `wc` guard from above. If the
                // active modal slot has been cleared while the chrome was
                // still open (close-animation race), render an empty box
                // — the next Tick clears Modal::Wc.
                wc_panes::view(
                    t,
                    wc,
                    self.chrome.progress(),
                    self.wc_proposal_details_expanded,
                )
            }
        };
        let composed: Element<'_, Message> = stack![background, modal_layer].into();

        // Bottom-right clipboard auto-clear chip rides on top of
        // whatever modal layer is currently visible. The chip is a
        // pointer-event sink only over its own card area; the rest of
        // the overlay is `Space`, so clicks on the screen below pass
        // through to the active modal/dashboard.
        match &self.clipboard_clear {
            None => composed,
            Some(state) => stack![composed, clipboard_clear_chip(t, state)].into(),
        }
    }

    // ── Send-flow helpers used by the broadcast Tasks ──────────────────────

    // ── Main pane (header + body) ──────────────────────────────────────────

    fn main_pane<'a>(
        &'a self,
        t: KaoTheme,
        wc: &crate::walletconnect::state::WcState,
    ) -> Element<'a, Message> {
        // Hold the read guard for the duration of `main_pane`. iced
        // views are synchronous and the lock is uncontested, so the
        // guard's lifetime safely outlives the returned Element.
        let contacts_guard = self.contacts.read().ok();
        let empty_book = ContactsBook::new();
        let contacts: &ContactsBook = match &contacts_guard {
            Some(g) => g,
            None => &empty_book,
        };
        let body: Element<'_, Message> = match self.nav {
            Nav::Home => home::view(
                t,
                &self.signer,
                &self.portfolio,
                self.portfolio_loading,
                wc,
                &self.wc_paste_input,
            ),
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
                    self.address,
                    &self.history,
                    self.history_loading,
                    merged_error,
                    contacts,
                )
            }
            Nav::Settings => match &self.settings_pane {
                SettingsPane::Root => settings_root::view(t),
                SettingsPane::Networks(p) => p.view(t).map(Message::Networks),
                SettingsPane::Appearance => appearance::view(t, self.theme_kind),
                SettingsPane::Contacts(p) => p.view(t).map(Message::Contacts),
                SettingsPane::WcSessions => wc_panes::sessions_view(t, wc),
            },
        };

        let display_name = self
            .accounts
            .get(self.active_index)
            .map(|a| a.display_name(self.active_index))
            .unwrap_or_else(|| format!("Account {}", self.active_index + 1));

        column![
            header::view(
                t,
                self.address,
                self.verification,
                display_name,
                self.rename_draft.as_deref(),
            ),
            body
        ]
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }
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
            let result = match network.provider(crate::chain::Chain::Mainnet).await {
                Some(provider) => crate::ens::resolve_name(&provider, &name).await,
                None => Err("no execution RPCs configured".to_string()),
            };
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
            let result = match network.provider(crate::chain::Chain::Mainnet).await {
                Some(provider) => crate::ens::resolve_name(&provider, &name).await,
                None => Err("no execution RPCs configured".to_string()),
            };
            (seq, name, result)
        },
        |(seq, name, result)| {
            Message::Contacts(contacts_settings::Message::EnsResolved { seq, name, result })
        },
    )
}

/// Spawn a clear-signing decode task. Walks the proxy chain rooted at
/// the plan's target, fetches verified bytecode, runs evmole + 4byte +
/// matcher, and humanizes the resulting args. Result message carries
/// `seq` so the SendPane can drop stale completions if the user backed
/// out of review and built a different plan.
fn spawn_decode_task(network: Arc<dyn BalanceFetcher>, seq: u64, plan: SendPlan) -> Task<Message> {
    let (to, _value, calldata) = plan.tx_target();
    let chain = plan.chain;
    Task::perform(
        async move {
            let decoded =
                crate::decode::render::decode_call(network.as_ref(), chain, to, calldata).await;
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

/// Spawn a quote task using the network's shared provider. Returns a
/// `Task` that resolves to a `Send::QuoteFetched(...)` message. The
/// provider is selected by `plan.chain` so an L2 send hits the L2 RPC,
/// not mainnet.
fn spawn_quote_task(network: Arc<dyn BalanceFetcher>, plan: SendPlan) -> Task<Message> {
    let chain = plan.chain;
    Task::perform(
        async move {
            match network.provider(chain).await {
                Some(provider) => {
                    crate::wallet::tx::build_quote(&provider, network.clone(), &plan).await
                }
                None => {
                    warn!(chain = %chain.label(), "quote: no execution RPC configured");
                    Err("no execution RPCs configured".into())
                }
            }
        },
        |result| Message::Send(send::Message::QuoteFetched(result)),
    )
}

/// Spawn the sign-and-broadcast task. The `handoff` cell carries the
/// signer in (the dashboard moved it out via `mem::replace`); the task
/// puts it back when finished. The result message round-trips both the
/// broadcast result and the handoff so the dashboard reclaims the signer.
fn spawn_broadcast_task(
    network: Arc<dyn BalanceFetcher>,
    handoff: SignerHandoff,
    plan: SendPlan,
    quote: crate::wallet::tx::TxQuote,
) -> Task<Message> {
    let inner = handoff.clone();
    let chain = plan.chain;
    Task::perform(
        async move {
            let provider = match network.provider(chain).await {
                Some(p) => p,
                None => {
                    warn!(chain = %chain.label(), "broadcast: no execution RPC configured");
                    return Err::<TxHash, String>("no execution RPCs configured".into());
                }
            };
            let signer_taken = {
                let mut g = match inner.lock() {
                    Ok(g) => g,
                    Err(e) => {
                        warn!(error = %e, "broadcast: signer cell poisoned");
                        return Err(format!("signer cell poisoned: {e}"));
                    }
                };
                g.take()
            };
            let signer = match signer_taken {
                Some(s) => s,
                None => {
                    warn!("broadcast: signer cell empty at task entry");
                    return Err("signer not available".into());
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

// ── WalletConnect helpers ────────────────────────────────────────────────

/// Build the settled-namespaces map for a sessionPropose approval.
///
/// Restricts the proposal's requested chains to Kao's supported set
/// (`Chain::from_chain_id`) and methods to those `walletconnect::methods`
/// can actually dispatch. Accounts are stamped with the active address per
/// CAIP-10. Non-EIP-155 namespaces (cosmos, solana, …) are dropped — Kao
/// only speaks EVM.
fn build_approved_namespaces(
    active: Address,
    proposal: &crate::walletconnect::state::UiProposal,
) -> std::collections::BTreeMap<String, crate::walletconnect::protocol::NamespaceSettled> {
    use crate::chain::Chain;
    use crate::walletconnect::methods::SUPPORTED_METHODS;
    use crate::walletconnect::protocol::NamespaceSettled;
    use std::collections::BTreeMap;

    let mut out: BTreeMap<String, NamespaceSettled> = BTreeMap::new();
    // Merge required + optional in proposal order. The dApp gets back the
    // intersection of what they asked for and what we support.
    for (key, ns) in proposal.required.iter().chain(proposal.optional.iter()) {
        if key != "eip155" {
            continue;
        }
        let mut chains: Vec<String> = Vec::new();
        for c in &ns.chains {
            if let Some(num) = c
                .strip_prefix("eip155:")
                .and_then(|s| s.parse::<u64>().ok())
                && Chain::from_chain_id(num).is_some()
            {
                let id = format!("eip155:{num}");
                if !chains.contains(&id) {
                    chains.push(id);
                }
            }
        }
        if chains.is_empty() {
            // Fall back to Mainnet so the dApp always has at least one
            // chain to operate against — refusing the proposal is the
            // user's job, not ours.
            chains.push("eip155:1".to_string());
        }
        let methods: Vec<String> = ns
            .methods
            .iter()
            .filter(|m| SUPPORTED_METHODS.iter().any(|sm| sm == m))
            .cloned()
            .collect();
        let events = ns.events.clone();
        let accounts: Vec<String> = chains.iter().map(|c| format!("{c}:{active:#x}")).collect();
        // Merge with any existing entry (required + optional both hit this
        // path) — extend without duplicates.
        let entry = out.entry(key.clone()).or_insert(NamespaceSettled {
            chains: Vec::new(),
            accounts: Vec::new(),
            methods: Vec::new(),
            events: Vec::new(),
        });
        for c in chains {
            if !entry.chains.contains(&c) {
                entry.chains.push(c);
            }
        }
        for m in methods {
            if !entry.methods.contains(&m) {
                entry.methods.push(m);
            }
        }
        for e in events {
            if !entry.events.contains(&e) {
                entry.events.push(e);
            }
        }
        for a in accounts {
            if !entry.accounts.contains(&a) {
                entry.accounts.push(a);
            }
        }
    }
    out
}

/// Static `PeerMetadata` for Kao, sent on every sessionSettle. The dApp
/// shows this to the user as "you're connected to Kao". Kept minimal:
/// real wallets serve their icon over HTTPS, but Kao is desktop-only and
/// has no canonical icon URL yet.
fn kao_wallet_metadata() -> crate::walletconnect::protocol::PeerMetadata {
    crate::walletconnect::protocol::PeerMetadata {
        name: "Kao".to_string(),
        description: "Kaomoji-centered desktop wallet".to_string(),
        url: "https://github.com/Wehi/kao".to_string(),
        icons: vec![],
        redirect: None,
    }
}

/// Spawn an async task that runs the per-method signer code for a
/// `wc_sessionRequest`. The signer is borrowed from the dashboard; only
/// non-clonable signers (Trezor/Ledger) need the same care as the Send
/// pane, but `personal_sign` / `eth_signTypedData_v4` don't take
/// ownership of the underlying device transport — they call into
/// alloy's signer APIs which clone the inner signer state. For raw-tx
/// methods we currently reject at the dispatch site, so no signer move
/// is needed.
fn spawn_wc_method_task(
    signer: &KaoSigner,
    req: crate::walletconnect::state::UiRequest,
) -> Task<Message> {
    let request_id = req.request_id;
    let signer_clone = match signer.share_for_wc() {
        Some(s) => s,
        None => {
            // Hardware / view-only — surface as a JSON-RPC error so the
            // dApp sees a clear "user's wallet doesn't support this from
            // this account" instead of timing out.
            use crate::walletconnect::protocol::{ERROR_UNAUTHORIZED_METHOD, JsonRpcError};
            let err = JsonRpcError {
                code: ERROR_UNAUTHORIZED_METHOD,
                message: "Hardware and view-only accounts can't sign for dApps yet".to_string(),
                data: None,
            };
            return Task::done(Message::WcRequestSigned {
                request_id,
                result: Err(err),
            });
        }
    };
    Task::perform(
        async move {
            let result = crate::walletconnect::methods::handle_method(
                &signer_clone,
                &req.method,
                &req.params,
                &req.chain_id,
            )
            .await;
            (request_id, result)
        },
        |(request_id, result)| Message::WcRequestSigned { request_id, result },
    )
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
            0,
            Arc::new(MockFetcher::new()),
            cache,
            Arc::new(RwLock::new(ContactsBook::new())),
            Arc::new(RwLock::new(crate::walletconnect::state::WcState::default())),
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
            chain,
        }
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
            chain: Chain::Mainnet,
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
            chain: Chain::Mainnet,
            result: Ok(vec![token("USDC", Chain::Mainnet)]),
        });
        // The data is correct for `other`'s slot — we only suppressed
        // the live merge into the active screen. The active address's
        // slot must remain untouched.
        let g = cache.lock().expect("cache");
        assert_eq!(
            g.get(&(other, Chain::Mainnet)).map(|v| v.len()),
            Some(1),
            "other's cache slot should be populated",
        );
        assert!(
            g.get(&(active, Chain::Mainnet)).is_none(),
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
            chain: Chain::Mainnet,
            result: Ok(vec![token("USDC", Chain::Mainnet)]),
        });
        assert_eq!(s.portfolio.len(), 1);
        assert_eq!(s.portfolio[0].symbol, "USDC");
        assert!(!s.portfolio_loading);
        let g = cache.lock().expect("cache");
        assert_eq!(g.get(&(active, Chain::Mainnet)).map(|v| v.len()), Some(1));
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
}
