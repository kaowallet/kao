//! Four-step network setup wizard for the Kao wallet.
//!
//! Guides the user through choosing an RPC provider, API/indexer provider,
//! Safe Transaction Service endpoint, and optional SOCKS proxy. Each step
//! presents option cards with privacy badges; a left-rail sidebar tracks
//! progress and shows a live privacy meter.
//!
//! Used both during onboarding (after CreatePassword) and from the wallet
//! settings pane. The `WizardMode` enum controls which back/close behaviour
//! applies and whether the draft is pre-filled from the current settings.

use iced::border::Radius;
use iced::keyboard;
use iced::widget::scrollable;
use iced::widget::{Column, Space, column, container, mouse_area, row, text, text_input};
use iced::{Alignment, Background, Border, Color, Element, Length, Padding, Subscription, Task};

use std::str::FromStr;

use alloy::primitives::B256;

use crate::chain::{Chain, PerChain};
use crate::settings::{self, ApiProvider, ProxyType, RpcProvider, SafeTxService};
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::{
    BadgeKind, auth_background, black, bold, error_text, kao_scrollable_style, kao_text,
    kao_toggle, link_button, mono, mono_bold, primary_button, privacy_badge, progress_bar,
    small_secondary_button, text_input_style, vspace,
};

// ── Input IDs for focus management ──────────────────────────────────────────

const RPC_KEY_INPUT_ID: &str = "nw_rpc_key_input";
const CUSTOM_RPC_URL_INPUT_ID: &str = "nw_custom_rpc_url_input";
const API_KEY_INPUT_ID: &str = "nw_api_key_input";
const SAFE_TX_URL_INPUT_ID: &str = "nw_safe_tx_url_input";
const KAO_SERVER_INPUT_ID: &str = "nw_kao_server_input";
const BLOCKSCOUT_URL_INPUT_ID: &str = "nw_blockscout_url_input";
const BLOCKSCOUT_KEY_INPUT_ID: &str = "nw_blockscout_key_input";
const PROXY_ADDR_INPUT_ID: &str = "nw_proxy_addr_input";
const CHECKPOINT_INPUT_ID: &str = "nw_checkpoint_input";

// ── Data structures ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardStep {
    Rpc,
    Api,
    SafeTx,
    Proxy,
    Consensus,
    CustomNetworks,
    Review,
}

impl WizardStep {
    const ALL: [WizardStep; 6] = [
        WizardStep::Rpc,
        WizardStep::Api,
        WizardStep::SafeTx,
        WizardStep::Proxy,
        WizardStep::Consensus,
        WizardStep::CustomNetworks,
    ];

    fn index(self) -> usize {
        match self {
            Self::Rpc => 0,
            Self::Api => 1,
            Self::SafeTx => 2,
            Self::Proxy => 3,
            Self::Consensus => 4,
            Self::CustomNetworks => 5,
            Self::Review => 6,
        }
    }

    /// Variant name for the GUI state trace.
    fn name(self) -> &'static str {
        match self {
            Self::Rpc => "Rpc",
            Self::Api => "Api",
            Self::SafeTx => "SafeTx",
            Self::Proxy => "Proxy",
            Self::Consensus => "Consensus",
            Self::CustomNetworks => "CustomNetworks",
            Self::Review => "Review",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::Rpc => "RPC Provider",
            Self::Api => "API / Indexer",
            Self::SafeTx => "Safe TX Service",
            Self::Proxy => "Proxy",
            Self::Consensus => "Consensus",
            Self::CustomNetworks => "Custom Networks",
            Self::Review => "Review",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Rpc => {
                "Choose how Kao connects to the Ethereum network. This determines who sees your on-chain queries."
            }
            Self::Api => {
                "Pick an indexer for transaction history and token balances. Disabling it means slower lookups but no third-party data sharing."
            }
            Self::SafeTx => {
                "The Safe Transaction Service coordinates multisig proposals. You can use the default or host your own."
            }
            Self::Proxy => {
                "Route all network traffic through a SOCKS5 proxy to hide your IP address from RPC and API providers."
            }
            Self::Consensus => {
                "Helios verifies every RPC response against the beacon chain consensus layer. Override the endpoints per chain or paste a checkpoint hash."
            }
            Self::CustomNetworks => {
                "Add your own EVM networks (Sepolia, a local Anvil node, …). These are optional and can be added or changed later from Settings."
            }
            Self::Review => "Review your network configuration before connecting.",
        }
    }

    fn kaomoji(self) -> &'static str {
        match self {
            Self::Rpc => "(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧",
            Self::Api => "(◕‿◕✿)",
            Self::SafeTx => "(ᵔᴥᵔ)",
            Self::Proxy => "(⌐■_■)",
            Self::Consensus => "( ˘▽˘)っ",
            Self::CustomNetworks => "ﾍ(⌐■_■)ﾉ♪",
            Self::Review => "ヽ(・∀・)ﾉ",
        }
    }

    fn next(self) -> WizardStep {
        match self {
            Self::Rpc => Self::Api,
            Self::Api => Self::SafeTx,
            Self::SafeTx => Self::Proxy,
            Self::Proxy => Self::Consensus,
            Self::Consensus => Self::CustomNetworks,
            Self::CustomNetworks => Self::Review,
            Self::Review => Self::Review,
        }
    }

    fn prev(self) -> Option<WizardStep> {
        match self {
            Self::Rpc => None,
            Self::Api => Some(Self::Rpc),
            Self::SafeTx => Some(Self::Api),
            Self::Proxy => Some(Self::SafeTx),
            Self::Consensus => Some(Self::Proxy),
            Self::CustomNetworks => Some(Self::Consensus),
            Self::Review => Some(Self::CustomNetworks),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardMode {
    Onboarding,
    Settings,
}

/// A user-typed secret (an API key, or an RPC URL that commonly embeds one
/// in its path) held in the wizard draft and in the key-carrying `Message`
/// variants. Behaves like a `String` for the wizard's
/// purposes, but its `Debug` is redacted so a stray `{:?}` on a `Message` or
/// `WizardDraft` — or a panic backtrace that formats one — never prints the
/// key. (The key is still persisted to `settings.toml` in plaintext; that file
/// is owner-only by design. This guards only against in-memory disclosure
/// through formatting/logging.)
#[derive(Clone, Default)]
pub(crate) struct SecretInput(String);

impl SecretInput {
    fn as_str(&self) -> &str {
        &self.0
    }

    fn clear(&mut self) {
        self.0.clear();
    }

    /// Unwrap into the inner `String` — only for draft fields that store
    /// the value unwrapped (values that persist plaintext in settings.toml).
    fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for SecretInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretInput(redacted)")
    }
}

impl From<String> for SecretInput {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Keyboard-event wrapper whose `Debug` hides what was typed. A raw
/// `keyboard::Event` carries the produced text and character keys (releases
/// reach `keyboard::listen` even while a text_input is focused), so a `{:?}`
/// of a containing message — in this screen's trace or a parent
/// dispatcher's — would otherwise echo API keys typed into the wizard
/// keystroke by keystroke. Named keys (Enter, Escape, …) stay visible since
/// they drive wizard navigation.
#[derive(Clone)]
pub(crate) struct KeyEvent(keyboard::Event);

impl std::fmt::Debug for KeyEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            keyboard::Event::KeyPressed {
                key: keyboard::Key::Named(named),
                ..
            } => write!(f, "KeyEvent(KeyPressed({named:?}))"),
            keyboard::Event::KeyPressed { .. } => f.write_str("KeyEvent(KeyPressed(<redacted>))"),
            keyboard::Event::KeyReleased {
                key: keyboard::Key::Named(named),
                ..
            } => write!(f, "KeyEvent(KeyReleased({named:?}))"),
            keyboard::Event::KeyReleased { .. } => f.write_str("KeyEvent(KeyReleased(<redacted>))"),
            keyboard::Event::ModifiersChanged(m) => write!(f, "KeyEvent(ModifiersChanged({m:?}))"),
        }
    }
}

/// One editable custom-network row in the wizard. All fields are strings so
/// the form can hold partially-typed input (e.g. a chain id mid-edit); they're
/// parsed/validated on `Continue` and converted to [`settings::CustomNetwork`]
/// on Finish.
#[derive(Debug, Clone, Default)]
struct CustomNetworkDraft {
    name: String,
    chain_id: String,
    // Redacted: custom RPC URLs commonly embed a provider key in the path.
    rpc_url: SecretInput,
    symbol: String,
    enabled: bool,
}

impl CustomNetworkDraft {
    /// A row the user hasn't started filling in — ignored on validate/commit
    /// so a stray empty card never blocks the wizard or persists junk.
    fn is_blank(&self) -> bool {
        self.name.trim().is_empty()
            && self.chain_id.trim().is_empty()
            && self.rpc_url.as_str().trim().is_empty()
            && self.symbol.trim().is_empty()
    }

    /// Parse the chain id field as a positive EIP-155 id that isn't one of the
    /// built-in chains (those already route to the verified path).
    fn parsed_chain_id(&self) -> Option<u64> {
        let id = self.chain_id.trim().parse::<u64>().ok()?;
        if id == 0 || settings::BUILTIN_CHAIN_IDS.contains(&id) {
            return None;
        }
        Some(id)
    }
}

#[derive(Debug, Clone)]
struct WizardDraft {
    rpc_provider: RpcProvider,
    rpc_key: SecretInput,
    // Redacted: custom RPC URLs commonly embed a provider key in the path.
    custom_rpc_url: SecretInput,
    kao_server_url: String,
    api_provider: ApiProvider,
    api_key: SecretInput,
    blockscout_url: String,
    blockscout_api_key: SecretInput,
    safe_tx_service: SafeTxService,
    safe_tx_service_url: String,
    proxy_enabled: bool,
    proxy_type: ProxyType,
    proxy_address: String,
    consensus_rpcs: PerChain<String>,
    checkpoint_override: String,
    custom_networks: Vec<CustomNetworkDraft>,
}

impl Default for WizardDraft {
    fn default() -> Self {
        // Seed consensus RPCs from per-chain defaults so the inputs aren't
        // empty on first run.
        let mut consensus_rpcs = PerChain::<String>::default();
        for chain in Chain::ALL {
            consensus_rpcs.set(chain, chain.default_consensus_url().to_string());
        }
        Self {
            rpc_provider: RpcProvider::default(),
            rpc_key: SecretInput::default(),
            custom_rpc_url: SecretInput::default(),
            kao_server_url: settings::DEFAULT_KAO_SERVER_URL.to_string(),
            api_provider: ApiProvider::default(),
            api_key: SecretInput::default(),
            blockscout_url: String::new(),
            blockscout_api_key: SecretInput::default(),
            safe_tx_service: SafeTxService::default(),
            safe_tx_service_url: String::new(),
            proxy_enabled: false,
            proxy_type: ProxyType::default(),
            proxy_address: "127.0.0.1:9050".to_string(),
            consensus_rpcs,
            checkpoint_override: String::new(),
            custom_networks: Vec::new(),
        }
    }
}

/// Map persisted custom networks into editable wizard rows.
fn custom_networks_to_drafts(nets: Vec<settings::CustomNetwork>) -> Vec<CustomNetworkDraft> {
    nets.into_iter()
        .map(|n| CustomNetworkDraft {
            name: n.name,
            chain_id: n.chain_id.to_string(),
            rpc_url: n.rpc_url.into(),
            symbol: n.currency_symbol,
            enabled: n.enabled,
        })
        .collect()
}

// ── Message / Outcome ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Message {
    GoToStep(WizardStep),
    SetRpcProvider(RpcProvider),
    RpcKeyInput(SecretInput),
    // Redacted: custom RPC URLs commonly embed a provider key in the path.
    CustomRpcUrlInput(SecretInput),
    KaoServerUrlInput(String),
    SetApiProvider(ApiProvider),
    ApiKeyInput(SecretInput),
    BlockscoutUrlInput(String),
    BlockscoutApiKeyInput(SecretInput),
    SetSafeTxService(SafeTxService),
    SafeTxServiceUrlInput(String),
    ToggleProxy,
    SetProxyType(ProxyType),
    ProxyAddressInput(String),
    // Redacted: hosted beacon endpoints commonly embed a key in the path.
    ConsensusRpcInput(Chain, SecretInput),
    CheckpointInput(String),
    // ── Custom networks (step 6) ─────────────────────────────────────────
    /// Append a fresh blank custom-network row.
    CustomNetAdd,
    /// Remove the row at the given index.
    CustomNetRemove(usize),
    CustomNetNameInput(usize, String),
    CustomNetChainIdInput(usize, String),
    // Redacted: custom RPC URLs commonly embed a provider key in the path.
    CustomNetRpcInput(usize, SecretInput),
    CustomNetSymbolInput(usize, String),
    /// Toggle the enabled flag on the row at the given index.
    CustomNetToggle(usize),
    /// Fetch a fresh mainnet checkpoint through the draft's proxy.
    RefreshCheckpoint,
    /// Result of an in-flight checkpoint refresh.
    CheckpointFetched(Result<B256, String>),
    MostPrivatePreset,
    Continue,
    Back,
    Finish,
    /// Settings mode only: persist the whole draft and close, from any step, so
    /// changing one setting doesn't require walking every section. Gated on the
    /// entire draft being valid (the same check as Review).
    Save,
    // Redacted via `KeyEvent`: raw key events echo typed characters.
    KeyboardEvent(KeyEvent),
}

#[derive(Debug, Clone)]
pub enum Outcome {
    Completed,
    Back,
    Closed,
}

impl Outcome {
    /// Variant name for the GUI state trace.
    fn name(&self) -> &'static str {
        match self {
            Outcome::Completed => "Completed",
            Outcome::Back => "Back",
            Outcome::Closed => "Closed",
        }
    }
}

// ── Screen state ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct NetworkSetupScreen {
    mode: WizardMode,
    step: WizardStep,
    draft: WizardDraft,
    error: Option<String>,
    /// True while a checkpoint refresh is in flight (Consensus step).
    checkpoint_fetching: bool,
}

impl NetworkSetupScreen {
    pub fn new(mode: WizardMode) -> Self {
        let draft = match mode {
            WizardMode::Onboarding => WizardDraft::default(),
            WizardMode::Settings => {
                let mut consensus_rpcs = PerChain::<String>::default();
                for chain in Chain::ALL {
                    let saved = settings::consensus_rpcs(chain);
                    let url = saved
                        .into_iter()
                        .next()
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| chain.default_consensus_url().to_string());
                    consensus_rpcs.set(chain, url);
                }
                WizardDraft {
                    rpc_provider: settings::rpc_provider(),
                    rpc_key: settings::rpc_key().unwrap_or_default().into(),
                    custom_rpc_url: settings::custom_rpc_url().unwrap_or_default().into(),
                    kao_server_url: settings::kao_server_url(),
                    api_provider: settings::api_provider(),
                    api_key: settings::api_key().unwrap_or_default().into(),
                    blockscout_url: settings::blockscout_base_url().unwrap_or_default(),
                    blockscout_api_key: settings::blockscout_api_key().unwrap_or_default().into(),
                    safe_tx_service: settings::safe_tx_service(),
                    safe_tx_service_url: settings::safe_tx_service_url().unwrap_or_default(),
                    proxy_enabled: settings::proxy_enabled(),
                    proxy_type: settings::proxy_type(),
                    proxy_address: settings::proxy_address(),
                    consensus_rpcs,
                    checkpoint_override: settings::checkpoint_override()
                        .map(|b| format!("0x{}", alloy::hex::encode(b.as_slice())))
                        .unwrap_or_default(),
                    custom_networks: custom_networks_to_drafts(settings::custom_networks()),
                }
            }
        };
        Self {
            mode,
            step: WizardStep::Rpc,
            draft,
            error: None,
            checkpoint_fetching: false,
        }
    }

    // ── Update ──────────────────────────────────────────────────────────

    pub fn update(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        crate::trace_msg!("network_setup", &message);
        let step_before = self.step.name();
        let fetching_before = self.checkpoint_fetching;
        let error_before = self.error.is_some();

        let (task, outcome) = self.update_inner(message);

        let step_after = self.step.name();
        if step_before != step_after {
            crate::trace::state("network_setup", "step", step_before, step_after);
        }
        if fetching_before != self.checkpoint_fetching {
            crate::trace::state(
                "network_setup",
                "checkpoint_fetching",
                fetching_before,
                self.checkpoint_fetching,
            );
        }
        if error_before != self.error.is_some() {
            let s = |shown: bool| if shown { "shown" } else { "none" };
            crate::trace::state(
                "network_setup",
                "error",
                s(error_before),
                s(self.error.is_some()),
            );
        }
        if let Some(o) = &outcome {
            crate::trace::outcome("network_setup", o.name());
        }
        (task, outcome)
    }

    fn update_inner(&mut self, message: Message) -> (Task<Message>, Option<Outcome>) {
        match message {
            Message::GoToStep(step) => {
                self.step = step;
                self.error = None;
                (Task::none(), None)
            }
            Message::SetRpcProvider(p) => {
                self.draft.rpc_provider = p;
                self.error = None;
                (Task::none(), None)
            }
            Message::RpcKeyInput(s) => {
                self.draft.rpc_key = s;
                (Task::none(), None)
            }
            Message::CustomRpcUrlInput(s) => {
                self.draft.custom_rpc_url = s;
                (Task::none(), None)
            }
            Message::KaoServerUrlInput(s) => {
                self.draft.kao_server_url = s;
                (Task::none(), None)
            }
            Message::SetApiProvider(p) => {
                self.draft.api_provider = p;
                self.error = None;
                (Task::none(), None)
            }
            Message::ApiKeyInput(s) => {
                self.draft.api_key = s;
                (Task::none(), None)
            }
            Message::BlockscoutUrlInput(s) => {
                self.draft.blockscout_url = s;
                (Task::none(), None)
            }
            Message::BlockscoutApiKeyInput(s) => {
                self.draft.blockscout_api_key = s;
                (Task::none(), None)
            }
            Message::SetSafeTxService(s) => {
                self.draft.safe_tx_service = s;
                self.error = None;
                (Task::none(), None)
            }
            Message::SafeTxServiceUrlInput(s) => {
                self.draft.safe_tx_service_url = s;
                (Task::none(), None)
            }
            Message::ToggleProxy => {
                self.draft.proxy_enabled = !self.draft.proxy_enabled;
                self.error = None;
                (Task::none(), None)
            }
            Message::SetProxyType(p) => {
                self.draft.proxy_type = p;
                if matches!(p, ProxyType::Tor) {
                    self.draft.proxy_address = "127.0.0.1:9050".to_string();
                }
                (Task::none(), None)
            }
            Message::ProxyAddressInput(s) => {
                self.draft.proxy_address = s;
                (Task::none(), None)
            }
            Message::ConsensusRpcInput(chain, s) => {
                self.draft.consensus_rpcs.set(chain, s.into_inner());
                (Task::none(), None)
            }
            Message::CheckpointInput(s) => {
                self.draft.checkpoint_override = s;
                (Task::none(), None)
            }
            Message::CustomNetAdd => {
                self.draft.custom_networks.push(CustomNetworkDraft {
                    enabled: true,
                    symbol: settings::DEFAULT_CUSTOM_SYMBOL.to_string(),
                    ..CustomNetworkDraft::default()
                });
                self.error = None;
                (Task::none(), None)
            }
            Message::CustomNetRemove(i) => {
                if i < self.draft.custom_networks.len() {
                    self.draft.custom_networks.remove(i);
                }
                self.error = None;
                (Task::none(), None)
            }
            Message::CustomNetNameInput(i, s) => {
                if let Some(n) = self.draft.custom_networks.get_mut(i) {
                    n.name = s;
                }
                (Task::none(), None)
            }
            Message::CustomNetChainIdInput(i, s) => {
                // Digits only — chain ids are decimal u64. Silently drop other
                // characters so the field can't hold an unparseable value.
                if let Some(n) = self.draft.custom_networks.get_mut(i) {
                    n.chain_id = s.chars().filter(|c| c.is_ascii_digit()).collect();
                }
                (Task::none(), None)
            }
            Message::CustomNetRpcInput(i, s) => {
                if let Some(n) = self.draft.custom_networks.get_mut(i) {
                    n.rpc_url = s;
                }
                (Task::none(), None)
            }
            Message::CustomNetSymbolInput(i, s) => {
                if let Some(n) = self.draft.custom_networks.get_mut(i) {
                    n.symbol = s;
                }
                (Task::none(), None)
            }
            Message::CustomNetToggle(i) => {
                if let Some(n) = self.draft.custom_networks.get_mut(i) {
                    n.enabled = !n.enabled;
                }
                (Task::none(), None)
            }
            Message::RefreshCheckpoint => {
                if self.checkpoint_fetching {
                    return (Task::none(), None);
                }
                self.checkpoint_fetching = true;
                self.error = None;
                (
                    Task::perform(
                        crate::net::fetch_latest_checkpoint(self.draft_proxy()),
                        Message::CheckpointFetched,
                    ),
                    None,
                )
            }
            Message::CheckpointFetched(result) => {
                self.checkpoint_fetching = false;
                match result {
                    Ok(cp) => {
                        self.draft.checkpoint_override =
                            format!("0x{}", alloy::hex::encode(cp.as_slice()));
                        self.error = None;
                    }
                    Err(e) => self.error = Some(format!("Checkpoint refresh failed: {e}")),
                }
                (Task::none(), None)
            }
            Message::MostPrivatePreset => {
                self.draft.rpc_provider = RpcProvider::Kao;
                self.draft.rpc_key.clear();
                self.draft.custom_rpc_url.clear();
                self.draft.api_provider = ApiProvider::Kao;
                self.draft.api_key.clear();
                self.draft.safe_tx_service = SafeTxService::Default;
                self.draft.safe_tx_service_url.clear();
                self.draft.proxy_enabled = true;
                self.draft.proxy_type = ProxyType::Tor;
                self.draft.proxy_address = "127.0.0.1:9050".to_string();
                self.error = None;
                (Task::none(), None)
            }
            Message::Continue => {
                if !self.can_advance() {
                    return (Task::none(), None);
                }
                self.error = None;
                self.step = self.step.next();
                (Task::none(), None)
            }
            Message::Back => {
                self.error = None;
                if let Some(prev) = self.step.prev() {
                    self.step = prev;
                    (Task::none(), None)
                } else {
                    match self.mode {
                        WizardMode::Onboarding => (Task::none(), Some(Outcome::Back)),
                        WizardMode::Settings => (Task::none(), Some(Outcome::Closed)),
                    }
                }
            }
            Message::Finish => {
                self.apply_draft();
                (Task::none(), Some(Outcome::Completed))
            }
            Message::Save => {
                // Persist the whole draft from wherever the user is. Requires
                // the entire draft to be valid (same gate as Review) because
                // `apply_draft` writes every section, not just the current step.
                if !self.step_valid(WizardStep::Review) {
                    return (Task::none(), None);
                }
                self.error = None;
                self.apply_draft();
                (Task::none(), Some(Outcome::Completed))
            }
            Message::KeyboardEvent(KeyEvent(keyboard::Event::KeyPressed { key, .. })) => {
                self.handle_key(key)
            }
            Message::KeyboardEvent(_) => (Task::none(), None),
        }
    }

    fn handle_key(&mut self, key: keyboard::Key) -> (Task<Message>, Option<Outcome>) {
        match key {
            keyboard::Key::Named(keyboard::key::Named::Enter) => {
                // Settings mode: Enter mirrors the "Save" footer button — persist
                // the whole (valid) draft and close from wherever the user is.
                if matches!(self.mode, WizardMode::Settings) {
                    if self.step_valid(WizardStep::Review) {
                        self.error = None;
                        self.apply_draft();
                        return (Task::none(), Some(Outcome::Completed));
                    }
                    return (Task::none(), None);
                }
                if self.step == WizardStep::Review {
                    if self.can_advance() {
                        self.apply_draft();
                        return (Task::none(), Some(Outcome::Completed));
                    }
                    return (Task::none(), None);
                }
                if self.can_advance() {
                    self.error = None;
                    self.step = self.step.next();
                }
                (Task::none(), None)
            }
            keyboard::Key::Named(keyboard::key::Named::Escape) => {
                self.error = None;
                if let Some(prev) = self.step.prev() {
                    self.step = prev;
                    (Task::none(), None)
                } else {
                    match self.mode {
                        WizardMode::Onboarding => (Task::none(), Some(Outcome::Back)),
                        WizardMode::Settings => (Task::none(), Some(Outcome::Closed)),
                    }
                }
            }
            _ => (Task::none(), None),
        }
    }

    /// The SOCKS5 proxy address to route a checkpoint refresh through, taken
    /// from the wizard's **draft** rather than persisted settings — during
    /// onboarding the proxy isn't applied until Finish, so reading settings
    /// would ignore the proxy the user is configuring right now. `None` means
    /// connect directly.
    fn draft_proxy(&self) -> Option<String> {
        self.draft
            .proxy_enabled
            .then(|| self.draft.proxy_address.trim().to_string())
    }

    // ── Validation ──────────────────────────────────────────────────────

    fn can_advance(&self) -> bool {
        self.step_valid(self.step)
    }

    /// Validate a single step's draft. The rail lets the user jump to any
    /// step (including Review) via `GoToStep`, bypassing the linear
    /// `Continue` gate — so Review re-checks every step rather than trusting
    /// that prior steps were passed in order.
    fn step_valid(&self, step: WizardStep) -> bool {
        match step {
            WizardStep::Rpc => match self.draft.rpc_provider {
                RpcProvider::Kao => {
                    settings::parse_kao_server_input(self.draft.kao_server_url.trim()).is_some()
                }
                RpcProvider::Alchemy => !self.draft.rpc_key.as_str().trim().is_empty(),
                RpcProvider::Drpc => !self.draft.rpc_key.as_str().trim().is_empty(),
                RpcProvider::Custom => {
                    settings::parse_rpc_input(self.draft.custom_rpc_url.as_str().trim()).is_some()
                }
                _ => true,
            },
            WizardStep::Api => match self.draft.api_provider {
                ApiProvider::Blockscout => {
                    // URL is optional — but if provided it must be valid HTTPS.
                    let url = self.draft.blockscout_url.trim();
                    url.is_empty()
                        || url::Url::parse(url)
                            .map(|u| u.scheme() == "https")
                            .unwrap_or(false)
                }
                ApiProvider::Drpc => !self.draft.api_key.as_str().trim().is_empty(),
                _ => true,
            },
            WizardStep::SafeTx => match self.draft.safe_tx_service {
                SafeTxService::Custom => {
                    let s = self.draft.safe_tx_service_url.trim();
                    url::Url::parse(s)
                        .map(|u| u.scheme() == "https")
                        .unwrap_or(false)
                }
                _ => true,
            },
            WizardStep::Proxy => {
                // A malformed address would make reqwest silently ignore the
                // proxy and connect directly, leaking the real IP — so block
                // advancing until it's a valid `host:port`.
                !self.draft.proxy_enabled
                    || settings::valid_proxy_address(self.draft.proxy_address.trim())
            }
            WizardStep::Consensus => {
                for chain in Chain::ALL {
                    let url = self.draft.consensus_rpcs.get(chain).trim();
                    let mandatory = matches!(chain, Chain::Mainnet);
                    if (mandatory || !url.is_empty()) && !settings::is_https_url(url) {
                        return false;
                    }
                }
                let cp = self.draft.checkpoint_override.trim();
                cp.is_empty() || B256::from_str(cp).is_ok()
            }
            WizardStep::CustomNetworks => {
                // Blank rows are ignored. Every filled row must have a name, a
                // valid non-built-in chain id, and an http(s) RPC URL, and the
                // chain ids across rows must be unique.
                let mut seen = std::collections::HashSet::new();
                for n in &self.draft.custom_networks {
                    if n.is_blank() {
                        continue;
                    }
                    let Some(id) = n.parsed_chain_id() else {
                        return false;
                    };
                    if n.name.trim().is_empty()
                        || !settings::is_http_or_https_url(n.rpc_url.as_str().trim())
                        || !seen.insert(id)
                    {
                        return false;
                    }
                }
                true
            }
            WizardStep::Review => WizardStep::ALL.iter().all(|s| self.step_valid(*s)),
        }
    }

    // ── Privacy scoring ─────────────────────────────────────────────────

    fn privacy_score(&self) -> u8 {
        let rpc = match self.draft.rpc_provider {
            RpcProvider::Kao => 3,
            RpcProvider::OneRpc => 2,
            RpcProvider::Custom => 2,
            RpcProvider::Drpc => 1,
            RpcProvider::Alchemy => 0,
        };
        let api = match self.draft.api_provider {
            ApiProvider::Kao => 2,
            ApiProvider::None => 2,
            ApiProvider::Blockscout => 1,
            ApiProvider::Drpc => 0,
        };
        let safe = match self.draft.safe_tx_service {
            SafeTxService::Custom => 1,
            SafeTxService::Default => 0,
        };
        let proxy = if self.draft.proxy_enabled { 2 } else { 0 };
        rpc + api + safe + proxy
    }

    fn privacy_label(&self) -> (&'static str, &'static str) {
        let pct = (self.privacy_score() as f32 / 8.0 * 100.0).round() as u8;
        if pct >= 82 {
            (
                "Fully shielded",
                "\u{30fd}(\u{30fb}\u{2200}\u{30fb})\u{ff89}",
            )
        } else if pct >= 55 {
            ("Well protected", "( \u{02d9}\u{25bf}\u{02d9} )")
        } else if pct >= 30 {
            ("Standard", "( \u{30fb}\u{03c9}\u{30fb})")
        } else {
            ("Exposed", "(\u{25de}\u{2038}\u{25df} )")
        }
    }

    fn privacy_fill_color(&self, t: KaoTheme) -> Color {
        let pct = (self.privacy_score() as f32 / 8.0 * 100.0).round() as u8;
        if pct >= 82 {
            t.up
        } else if pct >= 55 {
            t.a1
        } else if pct >= 30 {
            Color::from_rgb(0.85, 0.65, 0.0)
        } else {
            t.down
        }
    }

    // ── Apply draft to settings ─────────────────────────────────────────

    fn apply_draft(&self) {
        // Set the Kao server URL before applying providers so they can read it.
        settings::set_kao_server_url(self.draft.kao_server_url.clone());
        settings::apply_rpc_provider(
            self.draft.rpc_provider,
            self.draft.rpc_key.as_str().trim(),
            self.draft.custom_rpc_url.as_str().trim(),
        );
        settings::apply_api_provider(self.draft.api_provider, self.draft.api_key.as_str().trim());
        if self.draft.api_provider == ApiProvider::Blockscout {
            let url = self.draft.blockscout_url.trim();
            settings::set_blockscout_base_url(if url.is_empty() {
                None
            } else {
                Some(url.to_string())
            });
            let key = self.draft.blockscout_api_key.as_str().trim();
            settings::set_blockscout_api_key(if key.is_empty() {
                None
            } else {
                Some(key.to_string())
            });
        }
        settings::set_safe_tx_service(self.draft.safe_tx_service);
        if self.draft.safe_tx_service == SafeTxService::Custom {
            settings::set_safe_tx_service_url(Some(
                self.draft.safe_tx_service_url.trim().to_string(),
            ));
        } else {
            settings::set_safe_tx_service_url(None);
        }
        settings::set_proxy_enabled(self.draft.proxy_enabled);
        if self.draft.proxy_enabled {
            settings::set_proxy_type(self.draft.proxy_type);
            settings::set_proxy_address(self.draft.proxy_address.trim().to_string());
        }
        // Consensus RPCs — blank L2 clears the explicit override.
        for chain in Chain::ALL {
            let url = self.draft.consensus_rpcs.get(chain).trim().to_string();
            settings::set_consensus_rpcs(chain, if url.is_empty() { vec![] } else { vec![url] });
        }
        let cp = self.draft.checkpoint_override.trim();
        settings::set_checkpoint_override(if cp.is_empty() {
            None
        } else {
            B256::from_str(cp).ok()
        });

        // Custom networks: convert the filled rows into persisted networks.
        // `set_custom_networks` re-normalizes (drops blanks/invalid/duplicate
        // /built-in ids), so passing parsed rows is safe even if a row slipped
        // past the step's validity gate.
        let custom: Vec<settings::CustomNetwork> = self
            .draft
            .custom_networks
            .iter()
            .filter(|n| !n.is_blank())
            .filter_map(|n| {
                let chain_id = n.parsed_chain_id()?;
                let symbol = {
                    let s = n.symbol.trim();
                    if s.is_empty() {
                        settings::DEFAULT_CUSTOM_SYMBOL.to_string()
                    } else {
                        s.to_string()
                    }
                };
                Some(settings::CustomNetwork {
                    chain_id,
                    name: n.name.trim().to_string(),
                    rpc_url: n.rpc_url.as_str().trim().to_string(),
                    currency_symbol: symbol,
                    enabled: n.enabled,
                })
            })
            .collect();
        settings::set_custom_networks(custom);
    }

    // ── View ────────────────────────────────────────────────────────────

    pub fn view(&self) -> Element<'_, Message> {
        let t = KaoTheme::for_kind(settings::theme());

        let rail = self.view_rail(t);
        let main = self.view_main(t);

        let body = row![
            container(rail).width(Length::Fixed(316.0)),
            container(main).width(Length::Fill),
        ]
        .width(Length::Fill)
        .height(Length::Fill);

        match self.mode {
            WizardMode::Onboarding => {
                // Full-screen: rail + main fill the entire window.
                let panel = container(body)
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .style(move |_| container::Style {
                        background: Some(Background::Color(t.card)),
                        ..container::Style::default()
                    });
                auth_background(t, panel.into())
            }
            WizardMode::Settings => {
                // Embedded in the dashboard content area — no auth_background,
                // just fill the available space.
                container(body)
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .style(move |_| container::Style {
                        background: Some(Background::Color(t.card)),
                        ..container::Style::default()
                    })
                    .into()
            }
        }
    }

    // ── Left rail ───────────────────────────────────────────────────────

    fn view_rail(&self, t: KaoTheme) -> Element<'_, Message> {
        let brand = column![
            container(kao_text(t, "\u{30c4}", 28.0))
                .width(Length::Fixed(48.0))
                .height(Length::Fixed(48.0))
                .center_x(Length::Fixed(48.0))
                .center_y(Length::Fixed(48.0))
                .style(move |_| container::Style {
                    background: Some(Background::Color(t.ab1)),
                    border: Border {
                        color: with_alpha(t.a1, 0.3),
                        width: 1.0,
                        radius: Radius::from(24.0),
                    },
                    ..container::Style::default()
                }),
            vspace(8),
            text("Kao").size(18).color(t.text).font(black()),
            text("connect to the network").size(12).color(t.sub),
        ]
        .align_x(Alignment::Center)
        .spacing(0);

        let divider = container(Space::new().width(Length::Fill).height(1))
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(t.border)),
                ..container::Style::default()
            });

        let mut steps_col: Column<'_, Message> = column![].spacing(4);
        for (i, step) in WizardStep::ALL.iter().enumerate() {
            let is_active = self.step == *step || self.step == WizardStep::Review;
            let is_current = self.step == *step;
            let num = format!("{:02}", i + 1);
            let summary = self.step_summary(*step);

            let badge_bg = if is_current { t.a1 } else { t.card_alt };
            let badge_fg = if is_current { Color::WHITE } else { t.sub };

            let badge = container(text(num).size(11).color(badge_fg).font(bold()))
                .width(Length::Fixed(26.0))
                .height(Length::Fixed(26.0))
                .center_x(Length::Fixed(26.0))
                .center_y(Length::Fixed(26.0))
                .style(move |_| container::Style {
                    background: Some(Background::Color(badge_bg)),
                    border: Border {
                        color: if is_current { t.a1 } else { t.border },
                        width: 1.0,
                        radius: Radius::from(8.0),
                    },
                    ..container::Style::default()
                });

            let label_color = if is_active { t.text } else { t.sub };
            let step_row = row![
                badge,
                Space::new().width(10),
                column![
                    text(step.title()).size(13).color(label_color).font(bold()),
                    text(summary).size(11).color(t.sub),
                ]
                .spacing(1)
                .width(Length::Fill),
            ]
            .align_y(Alignment::Center)
            .width(Length::Fill);

            let bg = if is_current {
                with_alpha(t.a1, 0.10)
            } else {
                Color::TRANSPARENT
            };
            let step_card = container(step_row)
                .padding(Padding::from([8, 10]))
                .width(Length::Fill)
                .style(move |_| container::Style {
                    background: Some(Background::Color(bg)),
                    border: Border {
                        color: if is_current {
                            with_alpha(t.a1, 0.25)
                        } else {
                            Color::TRANSPARENT
                        },
                        width: 1.0,
                        radius: Radius::from(10),
                    },
                    ..container::Style::default()
                });

            let clickable = mouse_area(step_card)
                .on_press(Message::GoToStep(*step))
                .interaction(iced::mouse::Interaction::Pointer);

            steps_col = steps_col.push(clickable);
        }

        // Review "step" in the rail
        {
            let is_current = self.step == WizardStep::Review;
            let badge_bg = if is_current { t.a1 } else { t.card_alt };
            let badge_fg = if is_current { Color::WHITE } else { t.sub };
            let badge = container(text("\u{2713}").size(12).color(badge_fg).font(bold()))
                .width(Length::Fixed(26.0))
                .height(Length::Fixed(26.0))
                .center_x(Length::Fixed(26.0))
                .center_y(Length::Fixed(26.0))
                .style(move |_| container::Style {
                    background: Some(Background::Color(badge_bg)),
                    border: Border {
                        color: if is_current { t.a1 } else { t.border },
                        width: 1.0,
                        radius: Radius::from(8.0),
                    },
                    ..container::Style::default()
                });

            let label_color = if is_current { t.text } else { t.sub };
            let step_row = row![
                badge,
                Space::new().width(10),
                text("Review & Connect")
                    .size(13)
                    .color(label_color)
                    .font(bold()),
            ]
            .align_y(Alignment::Center)
            .width(Length::Fill);

            let bg = if is_current {
                with_alpha(t.a1, 0.10)
            } else {
                Color::TRANSPARENT
            };
            let step_card = container(step_row)
                .padding(Padding::from([8, 10]))
                .width(Length::Fill)
                .style(move |_| container::Style {
                    background: Some(Background::Color(bg)),
                    border: Border {
                        color: if is_current {
                            with_alpha(t.a1, 0.25)
                        } else {
                            Color::TRANSPARENT
                        },
                        width: 1.0,
                        radius: Radius::from(10),
                    },
                    ..container::Style::default()
                });

            let clickable = mouse_area(step_card)
                .on_press(Message::GoToStep(WizardStep::Review))
                .interaction(iced::mouse::Interaction::Pointer);

            steps_col = steps_col.push(clickable);
        }

        // Privacy meter card at bottom
        let score_frac = self.privacy_score() as f32 / 8.0;
        let (label, kao) = self.privacy_label();
        let fill_color = self.privacy_fill_color(t);

        let meter_card = container(
            column![
                text("Privacy Meter")
                    .size(11)
                    .color(t.sub)
                    .font(mono_bold()),
                vspace(8),
                progress_bar(t, score_frac, fill_color),
                vspace(6),
                row![
                    kao_text(t, kao, 13.0),
                    Space::new().width(8),
                    text(label).size(11).color(t.sub),
                ]
                .align_y(Alignment::Center),
            ]
            .width(Length::Fill),
        )
        .padding(Padding::from([12, 14]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card_alt)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(12),
            },
            ..container::Style::default()
        });

        let rail_content = column![
            vspace(16),
            brand,
            vspace(14),
            divider,
            vspace(14),
            steps_col,
            Space::new().height(Length::Fill),
            meter_card,
            vspace(16),
        ]
        .padding(Padding::from([0, 16]))
        .width(Length::Fill)
        .height(Length::Fill)
        .align_x(Alignment::Center);

        container(rail_content)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(t.card_alt)),
                border: Border {
                    color: t.border,
                    width: 0.0,
                    radius: Radius::from(0),
                },
                ..container::Style::default()
            })
            .into()
    }

    fn step_summary(&self, step: WizardStep) -> String {
        match step {
            WizardStep::Rpc => match self.draft.rpc_provider {
                RpcProvider::Kao => "Kao Proxy".to_string(),
                RpcProvider::OneRpc => "1RPC Relay".to_string(),
                RpcProvider::Drpc => "dRPC".to_string(),
                RpcProvider::Alchemy => "Alchemy".to_string(),
                RpcProvider::Custom => "Custom URL".to_string(),
            },
            WizardStep::Api => match self.draft.api_provider {
                ApiProvider::Kao => "Kao Proxy".to_string(),
                ApiProvider::Blockscout => "Blockscout".to_string(),
                ApiProvider::Drpc => "dRPC".to_string(),
                ApiProvider::None => "Disabled".to_string(),
            },
            WizardStep::SafeTx => match self.draft.safe_tx_service {
                SafeTxService::Default => "Default".to_string(),
                SafeTxService::Custom => "Custom URL".to_string(),
            },
            WizardStep::Proxy => {
                if self.draft.proxy_enabled {
                    match self.draft.proxy_type {
                        ProxyType::Tor => "Tor".to_string(),
                        ProxyType::Socks => "SOCKS5".to_string(),
                    }
                } else {
                    "Disabled".to_string()
                }
            }
            WizardStep::Consensus => {
                if self.draft.checkpoint_override.trim().is_empty() {
                    "Defaults".to_string()
                } else {
                    "Custom checkpoint".to_string()
                }
            }
            WizardStep::CustomNetworks => {
                let n = self
                    .draft
                    .custom_networks
                    .iter()
                    .filter(|c| !c.is_blank())
                    .count();
                match n {
                    0 => "None".to_string(),
                    1 => "1 network".to_string(),
                    n => format!("{n} networks"),
                }
            }
            WizardStep::Review => String::new(),
        }
    }

    // ── Main area ───────────────────────────────────────────────────────

    fn view_main(&self, t: KaoTheme) -> Element<'_, Message> {
        let step_num = self.step.index() + 1;
        let total = if self.step == WizardStep::Review {
            7
        } else {
            6
        };
        let step_counter = text(format!("Step {step_num} of {total}"))
            .size(11)
            .color(t.sub)
            .font(mono_bold());

        let title = text(self.step.title()).size(22).color(t.text).font(black());

        let description = text(self.step.description()).size(13).color(t.sub);

        let header = column![
            step_counter,
            vspace(6),
            row![
                title,
                Space::new().width(12),
                kao_text(t, self.step.kaomoji(), 22.0),
            ]
            .align_y(Alignment::Center),
            vspace(4),
            description,
            vspace(16),
        ]
        .width(Length::Fill);

        let body: Element<'_, Message> = match self.step {
            WizardStep::Rpc => self.view_rpc(t),
            WizardStep::Api => self.view_api(t),
            WizardStep::SafeTx => self.view_safe_tx(t),
            WizardStep::Proxy => self.view_proxy(t),
            WizardStep::Consensus => self.view_consensus(t),
            WizardStep::CustomNetworks => self.view_custom_networks(t),
            WizardStep::Review => self.view_review(t),
        };

        let scrollable_body = scrollable(container(body).width(Length::Fill).padding(Padding {
            top: 0.0,
            right: 4.0,
            bottom: 0.0,
            left: 0.0,
        }))
        .width(Length::Fill)
        .height(Length::Fill)
        .style(move |_theme, status| kao_scrollable_style(t, status));

        // Footer
        let back_label = if self.step == WizardStep::Rpc {
            match self.mode {
                WizardMode::Onboarding => "\u{2190} Back",
                WizardMode::Settings => "\u{2190} Close",
            }
        } else {
            "\u{2190} Back"
        };
        let back_btn = link_button(t, back_label).on_press(Message::Back);

        let center_widget: Element<'_, Message> = if self.step == WizardStep::Rpc {
            link_button(t, "\u{2728} Most private preset")
                .on_press(Message::MostPrivatePreset)
                .into()
        } else {
            Space::new().into()
        };

        // Settings mode: a single "Save" persists the whole draft from any step
        // (navigation between sections is via the left rail), so fixing one
        // setting doesn't mean clicking through every section. Onboarding keeps
        // the linear Continue → … → Connect & Finish flow.
        let (right_label, right_msg, can_go): (&str, Message, bool) = match self.mode {
            WizardMode::Settings => ("Save", Message::Save, self.step_valid(WizardStep::Review)),
            WizardMode::Onboarding if self.step == WizardStep::Review => {
                ("Connect & Finish", Message::Finish, self.can_advance())
            }
            WizardMode::Onboarding => ("Continue \u{2192}", Message::Continue, self.can_advance()),
        };
        let mut right_btn = primary_button(t, right_label, can_go).width(Length::Fixed(180.0));
        if can_go {
            right_btn = right_btn.on_press(right_msg);
        }

        let footer = container(
            row![
                container(back_btn).width(Length::FillPortion(1)),
                container(center_widget)
                    .width(Length::FillPortion(1))
                    .center_x(Length::FillPortion(1)),
                container(right_btn)
                    .width(Length::FillPortion(1))
                    .align_x(Alignment::End),
            ]
            .align_y(Alignment::Center)
            .width(Length::Fill),
        )
        .padding(Padding {
            top: 12.0,
            right: 0.0,
            bottom: 4.0,
            left: 0.0,
        })
        .width(Length::Fill);

        let mut main_col = column![header, scrollable_body, footer,]
            .padding(Padding::from([20, 24]))
            .width(Length::Fill)
            .height(Length::Fill);

        if let Some(e) = &self.error {
            main_col = main_col.push(error_text(t, e));
        }

        main_col.into()
    }

    // ── Step 1: RPC ─────────────────────────────────────────────────────

    fn view_rpc(&self, t: KaoTheme) -> Element<'_, Message> {
        let selected = self.draft.rpc_provider;

        let kao_body: Option<Element<'_, Message>> = if selected == RpcProvider::Kao {
            let input = text_input(settings::DEFAULT_KAO_SERVER_URL, &self.draft.kao_server_url)
                .id(KAO_SERVER_INPUT_ID)
                .on_input(Message::KaoServerUrlInput)
                .padding(Padding::from([10, 12]))
                .size(13)
                .font(mono())
                .style(move |_theme, status| text_input_style(t, status));
            Some(
                column![
                    text("Server URL").size(11).color(t.sub).font(mono()),
                    vspace(4),
                    input,
                    vspace(4),
                    text("HTTPS, or http:// for a localhost server.")
                        .size(10)
                        .color(t.sub),
                ]
                .width(Length::Fill)
                .into(),
            )
        } else {
            None
        };

        let kao_card = self.option_card(
            t,
            selected == RpcProvider::Kao,
            "Kao Privacy Proxy",
            Some("(recommended)"),
            "Routes queries through Kao's relay. Your IP and wallet address stay hidden from the upstream RPC.",
            &[(BadgeKind::Good, "IP hidden"), (BadgeKind::Good, "No logs")],
            kao_body,
            Message::SetRpcProvider(RpcProvider::Kao),
        );

        let onerpc_card = self.option_card(
            t,
            selected == RpcProvider::OneRpc,
            "1RPC Relay",
            None,
            "Privacy-preserving relay that strips metadata before forwarding. No API key required.",
            &[
                (BadgeKind::Good, "Metadata stripped"),
                (BadgeKind::Caution, "Third-party relay"),
            ],
            None,
            Message::SetRpcProvider(RpcProvider::OneRpc),
        );

        let drpc_body: Option<Element<'_, Message>> = if selected == RpcProvider::Drpc {
            let input = text_input("Your dRPC API key", self.draft.rpc_key.as_str())
                .id(RPC_KEY_INPUT_ID)
                .on_input(|s| Message::RpcKeyInput(s.into()))
                .padding(Padding::from([10, 12]))
                .size(13)
                .font(mono())
                .style(move |_theme, status| text_input_style(t, status));
            Some(input.into())
        } else {
            None
        };

        let drpc_card = self.option_card(
            t,
            selected == RpcProvider::Drpc,
            "dRPC",
            None,
            "Decentralized RPC load-balancer. Requires an API key from drpc.org.",
            &[
                (BadgeKind::Caution, "API key"),
                (BadgeKind::Warning, "Logs queries"),
            ],
            drpc_body,
            Message::SetRpcProvider(RpcProvider::Drpc),
        );

        let alchemy_body: Option<Element<'_, Message>> = if selected == RpcProvider::Alchemy {
            let input = text_input("Your Alchemy API key", self.draft.rpc_key.as_str())
                .id(RPC_KEY_INPUT_ID)
                .on_input(|s| Message::RpcKeyInput(s.into()))
                .padding(Padding::from([10, 12]))
                .size(13)
                .font(mono())
                .style(move |_theme, status| text_input_style(t, status));
            Some(input.into())
        } else {
            None
        };

        let alchemy_card = self.option_card(
            t,
            selected == RpcProvider::Alchemy,
            "Alchemy",
            None,
            "Fast and reliable. Requires an API key from alchemy.com.",
            &[
                (BadgeKind::Warning, "Logs IP + wallet"),
                (BadgeKind::Warning, "Centralized"),
            ],
            alchemy_body,
            Message::SetRpcProvider(RpcProvider::Alchemy),
        );

        let custom_body: Option<Element<'_, Message>> = if selected == RpcProvider::Custom {
            let input = text_input(
                "https://my-node.example:8545",
                self.draft.custom_rpc_url.as_str(),
            )
            .id(CUSTOM_RPC_URL_INPUT_ID)
            .on_input(|s| Message::CustomRpcUrlInput(s.into()))
            .padding(Padding::from([10, 12]))
            .size(13)
            .font(mono())
            .style(move |_theme, status| text_input_style(t, status));
            Some(input.into())
        } else {
            None
        };

        let custom_card = self.option_card(
            t,
            selected == RpcProvider::Custom,
            "Custom RPC",
            None,
            "Bring your own endpoint. Use your own node or any HTTPS RPC URL.",
            &[(BadgeKind::Info, "Self-hosted")],
            custom_body,
            Message::SetRpcProvider(RpcProvider::Custom),
        );

        column![
            kao_card,
            vspace(8),
            onerpc_card,
            vspace(8),
            drpc_card,
            vspace(8),
            alchemy_card,
            vspace(8),
            custom_card,
        ]
        .width(Length::Fill)
        .into()
    }

    // ── Step 2: API / Indexer ───────────────────────────────────────────

    fn view_api(&self, t: KaoTheme) -> Element<'_, Message> {
        let selected = self.draft.api_provider;

        let kao_card = self.option_card(
            t,
            selected == ApiProvider::Kao,
            "Kao Proxy",
            Some("(recommended)"),
            "Queries go through Kao's relay to dRPC. Uses the server URL configured in the RPC step.",
            &[(BadgeKind::Good, "IP hidden"), (BadgeKind::Good, "No logs")],
            None,
            Message::SetApiProvider(ApiProvider::Kao),
        );

        let blockscout_body: Option<Element<'_, Message>> = if selected == ApiProvider::Blockscout {
            let url_input = text_input(
                "https://eth.blockscout.com (default)",
                &self.draft.blockscout_url,
            )
            .id(BLOCKSCOUT_URL_INPUT_ID)
            .on_input(Message::BlockscoutUrlInput)
            .padding(Padding::from([10, 12]))
            .size(13)
            .font(mono())
            .style(move |_theme, status| text_input_style(t, status));
            let key_input =
                text_input("API key (optional)", self.draft.blockscout_api_key.as_str())
                    .id(BLOCKSCOUT_KEY_INPUT_ID)
                    .on_input(|s| Message::BlockscoutApiKeyInput(s.into()))
                    .padding(Padding::from([10, 12]))
                    .size(13)
                    .font(mono())
                    .style(move |_theme, status| text_input_style(t, status));
            Some(
                column![
                    text("Custom URL (optional)")
                        .size(11)
                        .color(t.sub)
                        .font(mono()),
                    vspace(4),
                    url_input,
                    vspace(8),
                    text("API key (optional)")
                        .size(11)
                        .color(t.sub)
                        .font(mono()),
                    vspace(4),
                    key_input,
                ]
                .width(Length::Fill)
                .into(),
            )
        } else {
            None
        };

        let blockscout_card = self.option_card(
            t,
            selected == ApiProvider::Blockscout,
            "Blockscout",
            None,
            "Open-source block explorer API. Uses the public instance by default, or point to your own.",
            &[
                (BadgeKind::Good, "Open source"),
                (BadgeKind::Caution, "Third-party default"),
            ],
            blockscout_body,
            Message::SetApiProvider(ApiProvider::Blockscout),
        );

        let drpc_body: Option<Element<'_, Message>> = if selected == ApiProvider::Drpc {
            let input = text_input("Your dRPC API key", self.draft.api_key.as_str())
                .id(API_KEY_INPUT_ID)
                .on_input(|s| Message::ApiKeyInput(s.into()))
                .padding(Padding::from([10, 12]))
                .size(13)
                .font(mono())
                .style(move |_theme, status| text_input_style(t, status));
            Some(input.into())
        } else {
            None
        };

        let drpc_card = self.option_card(
            t,
            selected == ApiProvider::Drpc,
            "dRPC Wallet API",
            None,
            "Uses dRPC's indexer API. Requires a paid API key.",
            &[
                (BadgeKind::Warning, "Logs queries"),
                (BadgeKind::Caution, "Paid key"),
            ],
            drpc_body,
            Message::SetApiProvider(ApiProvider::Drpc),
        );

        let none_card = self.option_card(
            t,
            selected == ApiProvider::None,
            "No Indexer",
            None,
            "Disable third-party indexing. Balances are fetched on-chain (slower). No transaction history.",
            &[(BadgeKind::Good, "No data shared"), (BadgeKind::Caution, "Slower")],
            None,
            Message::SetApiProvider(ApiProvider::None),
        );

        column![
            kao_card,
            vspace(8),
            blockscout_card,
            vspace(8),
            drpc_card,
            vspace(8),
            none_card,
        ]
        .width(Length::Fill)
        .into()
    }

    // ── Step 3: Safe TX Service ─────────────────────────────────────────

    fn view_safe_tx(&self, t: KaoTheme) -> Element<'_, Message> {
        let selected = self.draft.safe_tx_service;

        let default_card = self.option_card(
            t,
            selected == SafeTxService::Default,
            "Default Safe Service",
            Some("(recommended)"),
            "Uses the official Safe Transaction Service endpoints operated by Safe Global.",
            &[
                (BadgeKind::Info, "Official endpoints"),
                (BadgeKind::Caution, "Third-party"),
            ],
            None,
            Message::SetSafeTxService(SafeTxService::Default),
        );

        let custom_body: Option<Element<'_, Message>> = if selected == SafeTxService::Custom {
            let input = text_input(
                "https://safe-tx.example.com",
                &self.draft.safe_tx_service_url,
            )
            .id(SAFE_TX_URL_INPUT_ID)
            .on_input(Message::SafeTxServiceUrlInput)
            .padding(Padding::from([10, 12]))
            .size(13)
            .font(mono())
            .style(move |_theme, status| text_input_style(t, status));
            Some(input.into())
        } else {
            None
        };

        let custom_card = self.option_card(
            t,
            selected == SafeTxService::Custom,
            "Custom URL",
            None,
            "Self-host or use an alternative Safe TX Service. Must be HTTPS.",
            &[
                (BadgeKind::Good, "Self-hosted"),
                (BadgeKind::Good, "Full control"),
            ],
            custom_body,
            Message::SetSafeTxService(SafeTxService::Custom),
        );

        let info_note = container(
            row![
                text("ദ്ദി◝ ⩊ ◜.ᐟ").size(13).color(t.sub),
                Space::new().width(8),
                text("The Safe TX Service is only used for multisig (Safe) wallets. If you only use EOA wallets, this setting has no effect.")
                    .size(12)
                    .color(t.sub),
            ]
            .align_y(Alignment::Start)
            .width(Length::Fill),
        )
        .padding(Padding::from([10, 14]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(t.a2, 0.08))),
            border: Border {
                color: with_alpha(t.a2, 0.20),
                width: 1.0,
                radius: Radius::from(10),
            },
            ..container::Style::default()
        });

        column![default_card, vspace(8), custom_card, vspace(12), info_note,]
            .width(Length::Fill)
            .into()
    }

    // ── Step 4: Proxy ───────────────────────────────────────────────────

    fn view_proxy(&self, t: KaoTheme) -> Element<'_, Message> {
        let toggle_row = row![
            column![
                text("Enable SOCKS5 Proxy")
                    .size(15)
                    .color(t.text)
                    .font(bold()),
                vspace(2),
                text("Route all wallet traffic through a proxy to hide your IP from providers.")
                    .size(12)
                    .color(t.sub),
            ]
            .width(Length::Fill),
            Space::new().width(12),
            kao_toggle(t, self.draft.proxy_enabled, Message::ToggleProxy),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill);

        let toggle_card = container(toggle_row)
            .padding(Padding::from([16, 18]))
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(t.card_alt)),
                border: Border {
                    color: if self.draft.proxy_enabled {
                        with_alpha(t.a1, 0.35)
                    } else {
                        t.border
                    },
                    width: 1.0,
                    radius: Radius::from(14),
                },
                ..container::Style::default()
            });

        let mut content: Column<'_, Message> = column![toggle_card].width(Length::Fill);

        if self.draft.proxy_enabled {
            let is_tor = self.draft.proxy_type == ProxyType::Tor;
            let is_socks = self.draft.proxy_type == ProxyType::Socks;

            let tor_card = self.option_card(
                t,
                is_tor,
                "Tor",
                Some("(recommended)"),
                "Route through the Tor network via a local SOCKS5 proxy at 127.0.0.1:9050.",
                &[
                    (BadgeKind::Good, "Anonymous"),
                    (BadgeKind::Caution, "Slower"),
                ],
                None,
                Message::SetProxyType(ProxyType::Tor),
            );

            let socks_body: Option<Element<'_, Message>> = if is_socks {
                let input = text_input("127.0.0.1:1080", &self.draft.proxy_address)
                    .id(PROXY_ADDR_INPUT_ID)
                    .on_input(Message::ProxyAddressInput)
                    .padding(Padding::from([10, 12]))
                    .size(13)
                    .font(mono())
                    .style(move |_theme, status| text_input_style(t, status));
                let mut body = column![input].spacing(6);
                // Surface the fail-open risk as a visible error: an
                // authority-illegal address would otherwise be silently
                // ignored by reqwest and connect directly.
                let addr = self.draft.proxy_address.trim();
                if !addr.is_empty() && !settings::valid_proxy_address(addr) {
                    body = body.push(error_text(
                        t,
                        "Enter a valid host:port (e.g. 127.0.0.1:1080) — no spaces or special characters.",
                    ));
                }
                Some(body.into())
            } else {
                None
            };

            let socks_card = self.option_card(
                t,
                is_socks,
                "Custom SOCKS5",
                None,
                "Provide your own SOCKS5 proxy address.",
                &[(BadgeKind::Info, "Custom proxy")],
                socks_body,
                Message::SetProxyType(ProxyType::Socks),
            );

            content = content
                .push(vspace(12))
                .push(tor_card)
                .push(vspace(8))
                .push(socks_card);
        }

        // Honest restart notice. A proxy can only be installed once, at startup
        // (`proxy_env::set_all_proxy`), so any change to whether traffic is
        // actually routed takes effect on the next launch — not when saved. We
        // compare the draft's intent against what is really installed THIS
        // session (`proxy_env::installed()`) and tell the user plainly whether
        // a relaunch is needed and what their exposure is until then.
        let notice = |accent: Color, title: &str, body: String| -> Element<'_, Message> {
            container(
                column![
                    text(title.to_string()).size(12).color(accent).font(bold()),
                    vspace(3),
                    text(body).size(11).color(t.sub),
                ]
                .width(Length::Fill),
            )
            .padding(Padding::from([10, 12]))
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(with_alpha(accent, 0.08))),
                border: Border {
                    color: with_alpha(accent, 0.30),
                    width: 1.0,
                    radius: Radius::from(10),
                },
                ..container::Style::default()
            })
            .into()
        };
        let installed = proxy_env::installed();
        let restart_note: Option<Element<'_, Message>> = match (self.draft.proxy_enabled, installed)
        {
            (true, false) => Some(notice(
                t.down,
                "\u{27f3} Restart required to apply",
                "The proxy is installed once, at launch. Save this, then relaunch Kao — your IP \
                 stays exposed until you do."
                    .to_string(),
            )),
            (false, true) => Some(notice(
                t.down,
                "\u{27f3} Restart required to apply",
                "A proxy is still routing this session's traffic. Save this, then relaunch Kao — \
                 it won't turn off until you do."
                    .to_string(),
            )),
            (true, true) => Some(notice(
                t.sub,
                "Applies on next launch",
                "The proxy is active this session. Changes to the address or type take effect \
                 after you relaunch Kao."
                    .to_string(),
            )),
            (false, false) => None,
        };
        if let Some(note) = restart_note {
            content = content.push(vspace(10)).push(note);
        }

        content.into()
    }

    // ── Step 5: Consensus ───────────────────────────────────────────────

    fn view_consensus(&self, t: KaoTheme) -> Element<'_, Message> {
        let mut rows = column![].spacing(10).width(Length::Fill);
        for chain in Chain::ALL {
            let placeholder = chain.default_consensus_url();
            let input = text_input(placeholder, self.draft.consensus_rpcs.get(chain))
                .on_input(move |s| Message::ConsensusRpcInput(chain, s.into()))
                .padding(Padding::from([10, 12]))
                .size(13)
                .font(mono())
                .style(move |_theme, status| text_input_style(t, status));
            let label = container(text(chain.label()).size(12).color(t.text).font(bold()))
                .width(Length::Fixed(90.0));
            rows = rows.push(
                row![label, input]
                    .spacing(8)
                    .align_y(Alignment::Center)
                    .width(Length::Fill),
            );
        }

        let rpc_section = container(
            column![
                text("Consensus RPC Endpoints")
                    .size(14)
                    .color(t.text)
                    .font(bold()),
                vspace(4),
                text("Beacon-chain light-client API endpoints Helios bootstraps from. Leave an L2 blank to use the chain's default.")
                    .size(12)
                    .color(t.sub),
                vspace(12),
                rows,
            ]
            .width(Length::Fill),
        )
        .padding(Padding::from([16, 18]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card_alt)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(14),
            },
            ..container::Style::default()
        });

        let cp_placeholder = format!(
            "auto: 0x{}",
            alloy::hex::encode(settings::auto_checkpoint().as_slice())
        );
        let checkpoint_input = text_input(&cp_placeholder, &self.draft.checkpoint_override)
            .id(CHECKPOINT_INPUT_ID)
            .on_input(Message::CheckpointInput)
            .padding(Padding::from([10, 12]))
            .size(13)
            .font(mono())
            .style(move |_theme, status| text_input_style(t, status));

        let refresh_label = if self.checkpoint_fetching {
            "Fetching…"
        } else {
            "Refresh"
        };
        let mut refresh_btn = small_secondary_button(t, refresh_label);
        if !self.checkpoint_fetching {
            refresh_btn = refresh_btn.on_press(Message::RefreshCheckpoint);
        }

        let input_row = row![
            container(checkpoint_input).width(Length::Fill),
            Space::new().width(8),
            refresh_btn,
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill);

        let refresh_hint = if self.draft.proxy_enabled {
            "Refresh fetches the latest community checkpoint through your proxy."
        } else {
            "Refresh fetches the latest community checkpoint over a direct connection."
        };

        let checkpoint_section = container(
            column![
                text("Checkpoint Override")
                    .size(14)
                    .color(t.text)
                    .font(bold()),
                vspace(4),
                text("Leave blank to use the bundled checkpoint (or a freshly fetched one if stale). Paste a 32-byte hex hash to override.")
                    .size(12)
                    .color(t.sub),
                vspace(12),
                input_row,
                vspace(6),
                text(refresh_hint).size(11).color(t.sub),
            ]
            .width(Length::Fill),
        )
        .padding(Padding::from([16, 18]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card_alt)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(14),
            },
            ..container::Style::default()
        });

        column![rpc_section, vspace(12), checkpoint_section,]
            .width(Length::Fill)
            .into()
    }

    // ── Step 6: Custom networks ─────────────────────────────────────────

    fn view_custom_networks(&self, t: KaoTheme) -> Element<'_, Message> {
        // Unverified-trust warning — restated here (not just in the step
        // description) because this is the one screen where the user commits
        // to trusting an RPC directly.
        let warning = container(
            column![
                text("\u{26a0} Not verified by Helios")
                    .size(13)
                    .color(t.down)
                    .font(bold()),
                vspace(4),
                text(
                    "Helios can't verify custom networks. Balances and transactions on them trust the RPC you enter directly — only add networks you trust. http:// is allowed for local nodes (e.g. Anvil)."
                )
                .size(12)
                .color(t.sub),
            ]
            .width(Length::Fill),
        )
        .padding(Padding::from([12, 14]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(Color { a: 0.10, ..t.down })),
            border: Border {
                color: with_alpha(t.down, 0.4),
                width: 1.0,
                radius: Radius::from(12),
            },
            ..container::Style::default()
        });

        let mut cards = column![].spacing(12).width(Length::Fill);
        for (i, n) in self.draft.custom_networks.iter().enumerate() {
            let name_input = text_input("Sepolia", &n.name)
                .on_input(move |s| Message::CustomNetNameInput(i, s))
                .padding(Padding::from([10, 12]))
                .size(13)
                .style(move |_theme, status| text_input_style(t, status));
            let chain_input = text_input("11155111", &n.chain_id)
                .on_input(move |s| Message::CustomNetChainIdInput(i, s))
                .padding(Padding::from([10, 12]))
                .size(13)
                .font(mono())
                .style(move |_theme, status| text_input_style(t, status));
            let symbol_input = text_input("ETH", &n.symbol)
                .on_input(move |s| Message::CustomNetSymbolInput(i, s))
                .padding(Padding::from([10, 12]))
                .size(13)
                .font(mono())
                .style(move |_theme, status| text_input_style(t, status));
            let rpc_input = text_input("https://… or http://127.0.0.1:8545", n.rpc_url.as_str())
                .on_input(move |s| Message::CustomNetRpcInput(i, s.into()))
                .padding(Padding::from([10, 12]))
                .size(13)
                .font(mono())
                .style(move |_theme, status| text_input_style(t, status));

            let on_off = if n.enabled { "On" } else { "Off" };
            let header = row![
                text(format!("Network {}", i + 1))
                    .size(12)
                    .color(t.text)
                    .font(bold()),
                Space::new().width(Length::Fill),
                text(on_off).size(11).color(t.sub).font(mono()),
                Space::new().width(8),
                kao_toggle(t, n.enabled, Message::CustomNetToggle(i)),
                Space::new().width(12),
                link_button(t, "Delete").on_press(Message::CustomNetRemove(i)),
            ]
            .align_y(Alignment::Center)
            .width(Length::Fill);

            let id_symbol_row = row![
                column![
                    text("Chain ID").size(11).color(t.sub).font(mono()),
                    vspace(4),
                    chain_input,
                ]
                .width(Length::FillPortion(1)),
                Space::new().width(10),
                column![
                    text("Coin symbol").size(11).color(t.sub).font(mono()),
                    vspace(4),
                    symbol_input,
                ]
                .width(Length::FillPortion(1)),
            ]
            .width(Length::Fill);

            // Per-row hint when a started-but-invalid row would block Continue.
            let invalid = !n.is_blank()
                && (n.parsed_chain_id().is_none()
                    || n.name.trim().is_empty()
                    || !settings::is_http_or_https_url(n.rpc_url.as_str().trim()));
            let hint: Element<'_, Message> = if invalid {
                column![
                    vspace(6),
                    text("Needs a name, a unique chain id (not 1, 10 or 8453), and a valid http(s) RPC URL.")
                        .size(11)
                        .color(t.down),
                ]
                .into()
            } else {
                Space::new().height(0).into()
            };

            let card = container(
                column![
                    header,
                    vspace(10),
                    text("Name").size(11).color(t.sub).font(mono()),
                    vspace(4),
                    name_input,
                    vspace(8),
                    id_symbol_row,
                    vspace(8),
                    text("RPC URL").size(11).color(t.sub).font(mono()),
                    vspace(4),
                    rpc_input,
                    hint,
                ]
                .width(Length::Fill),
            )
            .padding(Padding::from([14, 16]))
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(t.card_alt)),
                border: Border {
                    color: t.border,
                    width: 1.0,
                    radius: Radius::from(14),
                },
                ..container::Style::default()
            });
            cards = cards.push(card);
        }

        if self.draft.custom_networks.is_empty() {
            cards = cards.push(
                container(
                    text("No custom networks yet. Add one to track its balance in your portfolio.")
                        .size(12)
                        .color(t.sub),
                )
                .padding(Padding::from([16, 4]))
                .width(Length::Fill)
                .center_x(Length::Fill),
            );
        }

        let add_btn = small_secondary_button(t, "\u{ff0b} Add custom network")
            .on_press(Message::CustomNetAdd);

        column![
            warning,
            vspace(14),
            cards,
            vspace(12),
            row![Space::new().width(Length::Fill), add_btn].width(Length::Fill),
        ]
        .width(Length::Fill)
        .into()
    }

    // ── Review step ─────────────────────────────────────────────────────

    fn view_review(&self, t: KaoTheme) -> Element<'_, Message> {
        let summary = self.view_review_summary(t);

        let score_frac = self.privacy_score() as f32 / 8.0;
        let (label, kao) = self.privacy_label();
        let fill_color = self.privacy_fill_color(t);

        let meter = container(
            column![
                text("Privacy Score")
                    .size(11)
                    .color(t.sub)
                    .font(mono_bold()),
                vspace(8),
                progress_bar(t, score_frac, fill_color),
                vspace(6),
                container(
                    row![
                        kao_text(t, kao, 16.0),
                        Space::new().width(8),
                        text(label).size(13).color(t.text).font(bold()),
                    ]
                    .align_y(Alignment::Center),
                )
                .width(Length::Fill)
                .center_x(Length::Fill),
            ]
            .width(Length::Fill),
        )
        .padding(Padding::from([14, 18]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card_alt)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(14),
            },
            ..container::Style::default()
        });

        column![summary, vspace(16), meter,]
            .width(Length::Fill)
            .into()
    }

    fn view_review_summary(&self, t: KaoTheme) -> Element<'_, Message> {
        let row_style = move |_: &_| container::Style {
            background: Some(Background::Color(t.card_alt)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(10),
            },
            ..container::Style::default()
        };

        let rpc_label = self.step_summary(WizardStep::Rpc);
        let rpc_badges = self.rpc_badges();
        let rpc_row = self.review_row(t, "RPC Provider", &rpc_label, &rpc_badges, row_style);

        let api_label = self.step_summary(WizardStep::Api);
        let api_badges = self.api_badges();
        let api_row = self.review_row(t, "API / Indexer", &api_label, &api_badges, row_style);

        let safe_label = self.step_summary(WizardStep::SafeTx);
        let safe_badges = self.safe_tx_badges();
        let safe_row = self.review_row(t, "Safe TX Service", &safe_label, &safe_badges, row_style);

        let proxy_label = self.step_summary(WizardStep::Proxy);
        let proxy_badges = self.proxy_badges();
        let proxy_row = self.review_row(t, "Proxy", &proxy_label, &proxy_badges, row_style);

        let consensus_label = self.step_summary(WizardStep::Consensus);
        let consensus_badges: Vec<(BadgeKind, &str)> =
            vec![(BadgeKind::Info, "Helios light-client")];
        let consensus_row = self.review_row(
            t,
            "Consensus",
            &consensus_label,
            &consensus_badges,
            row_style,
        );

        let custom_label = self.step_summary(WizardStep::CustomNetworks);
        let has_custom = self.draft.custom_networks.iter().any(|c| !c.is_blank());
        let custom_badges: Vec<(BadgeKind, &str)> = if has_custom {
            vec![(BadgeKind::Caution, "Unverified")]
        } else {
            Vec::new()
        };
        let custom_row = self.review_row(
            t,
            "Custom Networks",
            &custom_label,
            &custom_badges,
            row_style,
        );

        column![
            rpc_row,
            vspace(6),
            api_row,
            vspace(6),
            safe_row,
            vspace(6),
            proxy_row,
            vspace(6),
            consensus_row,
            vspace(6),
            custom_row,
        ]
        .width(Length::Fill)
        .into()
    }

    #[allow(clippy::too_many_arguments)]
    fn review_row<'a, F: Fn(&iced::Theme) -> container::Style + 'a>(
        &self,
        t: KaoTheme,
        title: &'a str,
        value: &str,
        badges: &[(BadgeKind, &str)],
        style_fn: F,
    ) -> Element<'a, Message> {
        let value_owned = value.to_string();
        let mut badge_row = row![].spacing(4);
        for (kind, label) in badges {
            badge_row = badge_row.push(privacy_badge(t, *kind, label));
        }

        container(
            row![
                column![
                    text(title).size(11).color(t.sub).font(mono_bold()),
                    vspace(2),
                    text(value_owned).size(14).color(t.text).font(bold()),
                    vspace(4),
                    badge_row,
                ]
                .width(Length::Fill),
            ]
            .width(Length::Fill),
        )
        .padding(Padding::from([10, 14]))
        .width(Length::Fill)
        .style(style_fn)
        .into()
    }

    fn rpc_badges(&self) -> Vec<(BadgeKind, &'static str)> {
        match self.draft.rpc_provider {
            RpcProvider::Kao => vec![(BadgeKind::Good, "IP hidden"), (BadgeKind::Good, "No logs")],
            RpcProvider::OneRpc => vec![
                (BadgeKind::Good, "Metadata stripped"),
                (BadgeKind::Caution, "Third-party"),
            ],
            RpcProvider::Drpc => vec![
                (BadgeKind::Caution, "API key"),
                (BadgeKind::Warning, "Logs queries"),
            ],
            RpcProvider::Alchemy => vec![
                (BadgeKind::Warning, "Logs IP + wallet"),
                (BadgeKind::Warning, "Centralized"),
            ],
            RpcProvider::Custom => vec![(BadgeKind::Info, "Self-hosted")],
        }
    }

    fn api_badges(&self) -> Vec<(BadgeKind, &'static str)> {
        match self.draft.api_provider {
            ApiProvider::Kao => vec![(BadgeKind::Good, "IP hidden"), (BadgeKind::Good, "No logs")],
            ApiProvider::Blockscout => vec![
                (BadgeKind::Good, "Open source"),
                (BadgeKind::Caution, "Third-party default"),
            ],
            ApiProvider::Drpc => vec![
                (BadgeKind::Warning, "Logs queries"),
                (BadgeKind::Caution, "Paid key"),
            ],
            ApiProvider::None => vec![
                (BadgeKind::Good, "No data shared"),
                (BadgeKind::Caution, "Slower"),
            ],
        }
    }

    fn safe_tx_badges(&self) -> Vec<(BadgeKind, &'static str)> {
        match self.draft.safe_tx_service {
            SafeTxService::Default => vec![
                (BadgeKind::Info, "Official"),
                (BadgeKind::Caution, "Third-party"),
            ],
            SafeTxService::Custom => vec![
                (BadgeKind::Good, "Self-hosted"),
                (BadgeKind::Good, "Full control"),
            ],
        }
    }

    fn proxy_badges(&self) -> Vec<(BadgeKind, &'static str)> {
        if self.draft.proxy_enabled {
            match self.draft.proxy_type {
                ProxyType::Tor => vec![
                    (BadgeKind::Good, "Anonymous"),
                    (BadgeKind::Good, "IP hidden"),
                ],
                ProxyType::Socks => vec![(BadgeKind::Good, "IP hidden")],
            }
        } else {
            vec![(BadgeKind::Warning, "IP exposed")]
        }
    }

    // ── Reusable option card ────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn option_card<'a>(
        &self,
        t: KaoTheme,
        selected: bool,
        title: &'a str,
        recommended: Option<&'a str>,
        description: &'a str,
        badges: &[(BadgeKind, &str)],
        expanded_body: Option<Element<'a, Message>>,
        on_select: Message,
    ) -> Element<'a, Message> {
        let radio_size: f32 = 18.0;
        let radio_inner: Element<'a, Message> = if selected {
            container(Space::new())
                .width(Length::Fixed(10.0))
                .height(Length::Fixed(10.0))
                .style(move |_| container::Style {
                    background: Some(Background::Color(t.a1)),
                    border: Border {
                        radius: Radius::from(5.0),
                        ..Default::default()
                    },
                    ..container::Style::default()
                })
                .into()
        } else {
            Space::new().width(10).height(10).into()
        };
        let radio = container(radio_inner)
            .width(Length::Fixed(radio_size))
            .height(Length::Fixed(radio_size))
            .center_x(Length::Fixed(radio_size))
            .center_y(Length::Fixed(radio_size))
            .style(move |_| container::Style {
                border: Border {
                    color: if selected { t.a1 } else { t.border },
                    width: 2.0,
                    radius: Radius::from(radio_size / 2.0),
                },
                ..container::Style::default()
            });

        let mut title_row = row![text(title).size(14).color(t.text).font(bold()),]
            .spacing(6)
            .align_y(Alignment::Center);

        if let Some(rec) = recommended {
            title_row = title_row.push(text(rec).size(11).color(t.a1).font(mono()));
        }

        let mut badge_row = row![].spacing(4);
        for (kind, label) in badges {
            badge_row = badge_row.push(privacy_badge(t, *kind, label));
        }

        let mut info_col = column![
            title_row,
            vspace(2),
            text(description).size(12).color(t.sub),
            vspace(4),
            badge_row,
        ]
        .spacing(0)
        .width(Length::Fill);

        if let Some(body) = expanded_body {
            info_col = info_col.push(vspace(10)).push(body);
        }

        let card_row = row![radio, Space::new().width(12), info_col,]
            .align_y(Alignment::Start)
            .width(Length::Fill);

        let border_color = if selected {
            with_alpha(t.a1, 0.45)
        } else {
            t.border
        };
        let bg = if selected {
            with_alpha(t.a1, 0.06)
        } else {
            t.card_alt
        };

        let card = container(card_row)
            .padding(Padding::from([14, 16]))
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(bg)),
                border: Border {
                    color: border_color,
                    width: if selected { 1.5 } else { 1.0 },
                    radius: Radius::from(14),
                },
                ..container::Style::default()
            });

        mouse_area(card)
            .on_press(on_select)
            .interaction(iced::mouse::Interaction::Pointer)
            .into()
    }

    // ── Subscription ────────────────────────────────────────────────────

    pub fn subscription(&self) -> Subscription<Message> {
        keyboard::listen().map(|e| Message::KeyboardEvent(KeyEvent(e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Selecting the custom Safe TX Service with an empty URL must not let
    /// the wizard finish, even when the user jumps straight to Review via the
    /// rail (which bypasses the linear `Continue` gate).
    #[test]
    fn empty_custom_safe_tx_url_blocks_review() {
        let mut s = NetworkSetupScreen::new(WizardMode::Onboarding);
        let _ = s.update(Message::SetSafeTxService(SafeTxService::Custom));

        // Jump past the SafeTx step's own gate straight to Review.
        let _ = s.update(Message::GoToStep(WizardStep::Review));
        assert!(
            !s.can_advance(),
            "empty custom URL should leave Review un-finishable"
        );

        // A whitespace-only URL is just as empty.
        let _ = s.update(Message::SafeTxServiceUrlInput("   ".to_string()));
        assert!(!s.can_advance());

        // A non-HTTPS URL is rejected too.
        let _ = s.update(Message::SafeTxServiceUrlInput(
            "http://safe.example".to_string(),
        ));
        assert!(!s.can_advance());

        // A valid HTTPS URL unblocks finishing.
        let _ = s.update(Message::SafeTxServiceUrlInput(
            "https://safe-tx.example.com".to_string(),
        ));
        assert!(s.can_advance());
    }

    /// A successful refresh overwrites whatever was in the override field
    /// with the fetched root, as `0x…` hex that round-trips back to the same
    /// `B256`, clears the in-flight flag, and leaves the Consensus step valid.
    #[test]
    fn checkpoint_refresh_success_populates_override() {
        let mut s = NetworkSetupScreen::new(WizardMode::Onboarding);
        // A stale value already sitting in the field — refresh must replace it.
        let _ = s.update(Message::CheckpointInput("0xdeadbeef".to_string()));

        let _ = s.update(Message::RefreshCheckpoint);
        assert!(s.checkpoint_fetching, "refresh should mark fetch in flight");

        let root = B256::repeat_byte(0xab);
        let _ = s.update(Message::CheckpointFetched(Ok(root)));
        assert!(!s.checkpoint_fetching);
        assert!(s.error.is_none());
        // The override is the fetched root, and it parses back to that root.
        assert_eq!(
            B256::from_str(s.draft.checkpoint_override.trim_start_matches("0x")).unwrap(),
            root,
        );
        // A fetched root is a valid 32-byte hash, so the step stays valid.
        let _ = s.update(Message::GoToStep(WizardStep::Consensus));
        assert!(s.can_advance());
    }

    /// A failed refresh clears the in-flight flag and surfaces an error
    /// without touching the override field.
    #[test]
    fn checkpoint_refresh_failure_surfaces_error() {
        let mut s = NetworkSetupScreen::new(WizardMode::Onboarding);
        let _ = s.update(Message::RefreshCheckpoint);
        let _ = s.update(Message::CheckpointFetched(Err("tor down".to_string())));
        assert!(!s.checkpoint_fetching);
        assert!(s.draft.checkpoint_override.is_empty());
        assert!(s.error.as_deref().unwrap_or_default().contains("tor down"));
    }

    /// Settings-mode "Save" persists the whole draft from any step, so it is
    /// gated on the entire draft being valid (the same check as Review) — a
    /// half-typed section elsewhere can't be silently written by saving from a
    /// different step. When invalid, Save is a no-op (no `Completed`, and it
    /// must not apply). Uses an invalid custom Safe TX URL to force the gate.
    #[test]
    fn save_refuses_invalid_draft() {
        let mut s = NetworkSetupScreen::new(WizardMode::Onboarding);
        let _ = s.update(Message::SetSafeTxService(SafeTxService::Custom));
        assert!(
            !s.step_valid(WizardStep::Review),
            "an empty custom Safe TX URL must leave the draft invalid",
        );
        let (_, outcome) = s.update(Message::Save);
        assert!(
            outcome.is_none(),
            "Save must not complete while any section is invalid",
        );
    }

    /// The checkpoint fetch routes through the *draft* proxy (what the user is
    /// configuring), not persisted settings, and only when the proxy is
    /// enabled. The address is trimmed.
    #[test]
    fn draft_proxy_reflects_draft_not_settings() {
        let mut s = NetworkSetupScreen::new(WizardMode::Onboarding);

        // Disabled by default → connect directly.
        assert_eq!(s.draft_proxy(), None);

        // Enable + a padded custom address → Some(trimmed).
        let _ = s.update(Message::ToggleProxy);
        let _ = s.update(Message::SetProxyType(ProxyType::Socks));
        let _ = s.update(Message::ProxyAddressInput("  1.2.3.4:1080  ".to_string()));
        assert_eq!(s.draft_proxy().as_deref(), Some("1.2.3.4:1080"));
    }
}
