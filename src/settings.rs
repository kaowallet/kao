//! User-tunable runtime settings, persisted to disk.

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};

use alloy::primitives::B256;
use serde::{Deserialize, Serialize};

use crate::chain::{Chain, PerChain};
use crate::ui::kao_theme::ThemeKind;

/// Default execution RPC for Mainnet. LlamaRPC's public mainnet endpoint
/// serves `eth_getProof`, which Helios needs to verify state (plain
/// `eth_getBalance` isn't enough). Users can swap to their own provider via
/// the Custom RPC option in setup.
const DEFAULT_RPCS: &[&str] = &["https://eth.llamarpc.com"];
/// Default beacon-chain LC API endpoint for Mainnet. PublicNode's beacon API
/// serves the `/eth/v1/beacon/light_client/{bootstrap,finality_update}`
/// calls Helios needs to verify consensus.
///
/// HTTPS only. Plain-HTTP endpoints would let a network attacker tamper with
/// the light-client bootstrap before any consensus signatures get verified.
const DEFAULT_CONSENSUS_RPCS: &[&str] = &["https://ethereum-beacon-api.publicnode.com"];

/// Default Kao privacy-proxy server. All Kao-proxied RPC and indexer
/// queries are relayed through this endpoint.
pub const DEFAULT_KAO_SERVER_URL: &str = "https://api.kaowallet.com";

/// Hex hash of the built-in mainnet checkpoint shipped with the binary, used
/// to bootstrap Mainnet helios sync when the user has set no override.
///
/// IMPORTANT: this must be a finalized beacon block root from a sync-committee
/// period that public LC servers still index — they prune older periods (~27h
/// rotation), so a checkpoint that's more than a day or two stale will fail
/// every bootstrap call. There is no automatic refresh: if it goes stale the
/// user resolves a fresh one via the network setup wizard's manual refresh
/// button (stored as `checkpoint_override`). Bump this at release time.
///
/// Last updated: 2026-06-23.
pub const BUILTIN_CHECKPOINT: &str =
    "0xb932756e3e27c272b4a39f90355e6ba829f485be230cf5b39abf325619fd92f0";

/// Third-party indexer used for transaction history and unverified balance
/// fan-outs. Helios verification of native ETH stays in `crate::net`; this
/// picks who answers `Indexer::transactions` / `Indexer::balances`. `None`
/// disables the indexer entirely — balances fall back to the on-chain
/// `portfolio::fetch_portfolio` walk and tx history is empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IndexerProvider {
    #[default]
    Blockscout,
    Etherscan,
    Alchemy,
    Drpc,
    /// Kao privacy proxy — fronts dRPC's Wallet API and holds the key, so
    /// the wallet sends no API key and no client identity upstream.
    Kao,
    None,
}

impl IndexerProvider {
    fn key(self) -> &'static str {
        match self {
            Self::Blockscout => "blockscout",
            Self::Etherscan => "etherscan",
            Self::Alchemy => "alchemy",
            Self::Drpc => "drpc",
            Self::Kao => "kao",
            Self::None => "none",
        }
    }

    fn from_key(s: &str) -> Option<Self> {
        match s {
            "blockscout" => Some(Self::Blockscout),
            "etherscan" => Some(Self::Etherscan),
            "alchemy" => Some(Self::Alchemy),
            "drpc" => Some(Self::Drpc),
            "kao" => Some(Self::Kao),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// Wizard-level RPC provider choice. Maps to per-chain URL generation
/// and drives the privacy posture score. Persisted in `settings.toml`
/// as a simple string key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RpcProvider {
    /// Kao privacy proxy (placeholder until the proxy backend ships).
    #[default]
    Kao,
    /// 1RPC relay — strips metadata before forwarding to the upstream.
    OneRpc,
    /// dRPC decentralized load-balancer — requires an API key.
    Drpc,
    /// Alchemy — fast, requires an API key.
    Alchemy,
    /// User-supplied URL(s).
    Custom,
}

impl RpcProvider {
    pub fn key(self) -> &'static str {
        match self {
            Self::Kao => "kao",
            Self::OneRpc => "1rpc",
            Self::Drpc => "drpc",
            Self::Alchemy => "alchemy",
            Self::Custom => "custom",
        }
    }

    pub fn from_key(s: &str) -> Option<Self> {
        match s {
            "kao" => Some(Self::Kao),
            "1rpc" => Some(Self::OneRpc),
            "drpc" => Some(Self::Drpc),
            "alchemy" => Some(Self::Alchemy),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }
}

/// Wizard-level API/indexer provider choice (simplified from
/// `IndexerProvider` — the wizard exposes fewer options).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApiProvider {
    /// Kao privacy proxy for indexer queries.
    #[default]
    Kao,
    /// Blockscout open-source explorer — optional custom URL + API key.
    Blockscout,
    /// dRPC Wallet API — requires a (paid) API key.
    Drpc,
    /// No indexer — slower, history limited to txs sent from Kao.
    None,
}

impl ApiProvider {
    pub fn key(self) -> &'static str {
        match self {
            Self::Kao => "kao",
            Self::Blockscout => "blockscout",
            Self::Drpc => "drpc",
            Self::None => "none",
        }
    }

    pub fn from_key(s: &str) -> Option<Self> {
        match s {
            "kao" => Some(Self::Kao),
            "blockscout" => Some(Self::Blockscout),
            "drpc" => Some(Self::Drpc),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// Safe Transaction Service endpoint choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SafeTxService {
    /// Use the default Safe Transaction Service endpoints.
    #[default]
    Default,
    /// User-supplied custom URL.
    Custom,
}

impl SafeTxService {
    pub fn key(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Custom => "custom",
        }
    }

    pub fn from_key(s: &str) -> Option<Self> {
        match s {
            "default" => Some(Self::Default),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }
}

/// SOCKS proxy type for network tunneling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyType {
    /// Tor/Whonix SOCKS5 proxy (typically 127.0.0.1:9050).
    #[default]
    Tor,
    /// Custom SOCKS5 proxy address.
    Socks,
}

impl ProxyType {
    pub fn key(self) -> &'static str {
        match self {
            Self::Tor => "tor",
            Self::Socks => "socks",
        }
    }

    pub fn from_key(s: &str) -> Option<Self> {
        match s {
            "tor" => Some(Self::Tor),
            "socks" => Some(Self::Socks),
            _ => None,
        }
    }
}

/// A user-defined custom network (e.g. Sepolia, a local Anvil node).
///
/// Custom networks are NOT verified by Helios — Helios's light-client only
/// ships configs for a fixed set of chains, so balances and broadcasts on a
/// custom network trust the configured RPC directly. The wallet surfaces this
/// with an "Unverified" treatment everywhere a custom network is shown.
///
/// Identity is the EIP-155 `chain_id`: it's baked into the signing hash, used
/// as the map key for the portfolio/provider routing, and must be unique
/// across both custom networks and the three built-in chains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomNetwork {
    /// EIP-155 chain id. Unique; never collides with a built-in (1/10/8453).
    pub chain_id: u64,
    /// Human label shown in the portfolio and send screens (e.g. "Sepolia").
    pub name: String,
    /// Execution JSON-RPC endpoint. `http://` is allowed (local Anvil nodes
    /// live on `http://127.0.0.1:8545`); built-in chains require HTTPS, but a
    /// custom network the user typed themselves is their own trust decision.
    pub rpc_url: String,
    /// Native-coin ticker shown next to balances (e.g. "ETH"). Defaults to
    /// "ETH" when the user leaves it blank.
    pub currency_symbol: String,
    /// Whether the network is active. Disabled networks are remembered but
    /// skipped by the portfolio fan-out and hidden from the send token list.
    pub enabled: bool,
}

/// Default native-coin ticker for a custom network when the user leaves the
/// symbol field blank.
pub const DEFAULT_CUSTOM_SYMBOL: &str = "ETH";

/// EIP-155 chain ids of the three Helios-verified built-in chains. A custom
/// network may not reuse one of these — that id already routes to the
/// verified path, and a "custom mainnet" would be a confusing footgun.
pub const BUILTIN_CHAIN_IDS: [u64; 3] = [1, 10, 8453];

/// EIP-155 chain id of the Sepolia testnet.
pub const SEPOLIA_CHAIN_ID: u64 = 11_155_111;
/// EIP-155 chain id Anvil/Hardhat use for their default local devnet.
pub const ANVIL_CHAIN_ID: u64 = 31_337;

/// Networks Kao ships pre-configured but **off by default**: the Sepolia
/// testnet and a local Anvil node. Seeding these saves the user from typing a
/// chain id and RPC by hand to reach the two most common non-mainnet targets —
/// they just flip the toggle in the Networks wizard. Once seeded they are
/// ordinary [`CustomNetwork`]s: editable and removable like any the user adds.
///
/// Both stay unverified (no Helios light client) and carry only the native
/// coin, exactly like a hand-added custom network.
fn seeded_custom_networks() -> Vec<CustomNetwork> {
    vec![
        CustomNetwork {
            chain_id: SEPOLIA_CHAIN_ID,
            name: "Sepolia".to_string(),
            rpc_url: "https://ethereum-sepolia-rpc.publicnode.com".to_string(),
            currency_symbol: DEFAULT_CUSTOM_SYMBOL.to_string(),
            enabled: false,
        },
        CustomNetwork {
            // Anvil binds to localhost; the NO_PROXY rule keeps this request off
            // the privacy proxy so a local devnet stays reachable.
            chain_id: ANVIL_CHAIN_ID,
            name: "Anvil".to_string(),
            rpc_url: "http://127.0.0.1:8545".to_string(),
            currency_symbol: DEFAULT_CUSTOM_SYMBOL.to_string(),
            enabled: false,
        },
    ]
}

/// True iff `s` parses as an `http`/`https` URL. Looser than [`is_https_url`]
/// because custom networks legitimately point at plain-HTTP local nodes
/// (Anvil, Hardhat). Used to filter custom-network RPCs on load.
pub fn is_http_or_https_url(s: &str) -> bool {
    url::Url::parse(s)
        .map(|u| matches!(u.scheme(), "http" | "https"))
        .unwrap_or(false)
}

#[derive(Clone)]
struct State {
    theme: ThemeKind,
    /// Per-chain execution RPC lists. Mainnet seeds from `DEFAULT_RPCS`; L2
    /// slots start empty so a user who never opens the Networks pane stays
    /// mainnet-only and we don't silently route their requests through any
    /// third-party L2 endpoint they didn't pick.
    rpcs: PerChain<Vec<String>>,
    /// Per-chain consensus (beacon-chain LC) RPC lists. Same defaulting rule
    /// as `rpcs` — Mainnet seeded, L2 empty until the user opts in.
    consensus_rpcs: PerChain<Vec<String>>,
    /// Mainnet-only checkpoint override pasted by the user. OP-Stack chains
    /// don't carry their own checkpoint — Helios bootstraps L2 off the L1
    /// SystemConfig contract via the mainnet exec RPC.
    checkpoint_override: Option<B256>,
    /// Resolved checkpoint used when the user hasn't pasted an override.
    /// Starts as the built-in constant; the network layer may swap in a
    /// fresher community-fallback hash on app startup.
    auto_checkpoint: B256,
    indexer_provider: IndexerProvider,
    etherscan_api_key: Option<String>,
    alchemy_api_key: Option<String>,
    drpc_api_key: Option<String>,
    /// Custom Blockscout instance base URL (e.g. for L2s). `None` falls back
    /// to the public mainnet endpoint baked into the indexer.
    blockscout_base_url: Option<String>,
    blockscout_api_key: Option<String>,
    // ── Wizard-level network config ──────────────────────────────────
    /// Kao privacy-proxy base URL. Defaults to `DEFAULT_KAO_SERVER_URL`.
    kao_server_url: String,
    rpc_provider: RpcProvider,
    rpc_key: Option<String>,
    custom_rpc_url: Option<String>,
    api_provider: ApiProvider,
    api_key: Option<String>,
    safe_tx_service: SafeTxService,
    safe_tx_service_url: Option<String>,
    proxy_enabled: bool,
    proxy_type: ProxyType,
    proxy_address: String,
    /// Custom networks. Seeded with Sepolia and Anvil (both disabled) on a
    /// fresh config via [`seeded_custom_networks`]; the user can toggle, edit,
    /// or remove them and add their own. Persisted as a TOML array of tables;
    /// remembered across restarts.
    custom_networks: Vec<CustomNetwork>,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // API keys are deliberately redacted: they live behind owner-only file
        // perms on disk, but a stray `{:?}` / log line / panic backtrace
        // shouldn't spill them. Presence (`Some`/`None`) is preserved so the
        // dump still tells you whether a key is configured.
        let redact = |o: &Option<String>| o.as_ref().map(|_| "<redacted>");
        f.debug_struct("State")
            .field("theme", &self.theme)
            .field("rpcs", &self.rpcs)
            .field("consensus_rpcs", &self.consensus_rpcs)
            .field("checkpoint_override", &self.checkpoint_override)
            .field("auto_checkpoint", &self.auto_checkpoint)
            .field("indexer_provider", &self.indexer_provider)
            .field("etherscan_api_key", &redact(&self.etherscan_api_key))
            .field("alchemy_api_key", &redact(&self.alchemy_api_key))
            .field("drpc_api_key", &redact(&self.drpc_api_key))
            .field("blockscout_base_url", &self.blockscout_base_url)
            .field("blockscout_api_key", &redact(&self.blockscout_api_key))
            .field("kao_server_url", &self.kao_server_url)
            .field("rpc_provider", &self.rpc_provider)
            .field("rpc_key", &redact(&self.rpc_key))
            .field("custom_rpc_url", &self.custom_rpc_url)
            .field("api_provider", &self.api_provider)
            .field("api_key", &redact(&self.api_key))
            .field("safe_tx_service", &self.safe_tx_service)
            .field("safe_tx_service_url", &self.safe_tx_service_url)
            .field("proxy_enabled", &self.proxy_enabled)
            .field("proxy_type", &self.proxy_type)
            .field("proxy_address", &self.proxy_address)
            .field("custom_networks", &self.custom_networks)
            .finish()
    }
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();

fn ensure() -> &'static Mutex<State> {
    STATE.get_or_init(|| Mutex::new(default_state()))
}

fn default_state() -> State {
    let mut rpcs = PerChain::<Vec<String>>::default();
    rpcs.set(
        Chain::Mainnet,
        DEFAULT_RPCS.iter().map(|s| s.to_string()).collect(),
    );
    let mut consensus_rpcs = PerChain::<Vec<String>>::default();
    consensus_rpcs.set(
        Chain::Mainnet,
        DEFAULT_CONSENSUS_RPCS
            .iter()
            .map(|s| s.to_string())
            .collect(),
    );
    State {
        theme: ThemeKind::Mint,
        rpcs,
        consensus_rpcs,
        checkpoint_override: None,
        auto_checkpoint: B256::from_str(BUILTIN_CHECKPOINT)
            .expect("built-in checkpoint constant must be valid hex"),
        indexer_provider: IndexerProvider::default(),
        etherscan_api_key: None,
        alchemy_api_key: None,
        drpc_api_key: None,
        blockscout_base_url: None,
        blockscout_api_key: None,
        kao_server_url: DEFAULT_KAO_SERVER_URL.to_string(),
        rpc_provider: RpcProvider::default(),
        rpc_key: None,
        custom_rpc_url: None,
        api_provider: ApiProvider::default(),
        api_key: None,
        safe_tx_service: SafeTxService::default(),
        safe_tx_service_url: None,
        proxy_enabled: false,
        proxy_type: ProxyType::default(),
        proxy_address: "127.0.0.1:9050".to_string(),
        custom_networks: seeded_custom_networks(),
    }
}

fn settings_path() -> PathBuf {
    crate::paths::config_dir().join("settings.toml")
}

/// Load settings from disk into the in-memory cache. Silently falls back to
/// defaults if the file is missing or unreadable.
pub fn load() {
    let Ok(contents) = std::fs::read_to_string(settings_path()) else {
        // Force initialization so subsequent reads see the defaults.
        let _ = ensure();
        return;
    };
    let state = parse(&contents);
    let mutex = ensure();
    *mutex.lock().expect("settings mutex poisoned") = state;
}

/// On-disk TOML schema. All fields are optional so a partial or older config
/// file falls back to defaults per-key rather than failing the whole load.
/// `auto_checkpoint` is intentionally absent — it's the binary's built-in
/// `BUILTIN_CHECKPOINT` and never persisted; a user-resolved checkpoint is
/// stored under `checkpoint_override` instead.
///
/// Per-chain RPC keys: `rpcs` / `consensus_rpcs` carry Mainnet (kept under
/// these names so an upgrade from the pre-L2 schema is a no-op). L2 lists
/// live in dedicated keys; we serialize each L2 list only when non-empty so
/// a stock config doesn't litter the file with empty arrays.
#[derive(Debug, Default, Serialize, Deserialize)]
struct OnDisk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    theme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rpcs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rpcs_base: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rpcs_optimism: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consensus_rpcs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consensus_rpcs_base: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consensus_rpcs_optimism: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checkpoint_override: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    indexer_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    etherscan_api_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alchemy_api_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    drpc_api_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blockscout_base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blockscout_api_key: Option<String>,
    // ── Wizard-level network config ──────────────────────────────────
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kao_server_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rpc_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rpc_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    custom_rpc_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    api_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    api_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    safe_tx_service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    safe_tx_service_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proxy_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proxy_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proxy_address: Option<String>,
    /// User-defined custom networks. Serialized as `[[custom_networks]]`
    /// tables; absent in pre-custom-network configs so the load defaults to
    /// an empty list (backward compatible).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    custom_networks: Option<Vec<CustomNetworkOnDisk>>,
}

/// On-disk form of a [`CustomNetwork`]. Separate from the runtime type so the
/// loader can validate/normalize (drop bad URLs, default the symbol) before a
/// row reaches `State`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CustomNetworkOnDisk {
    chain_id: u64,
    name: String,
    rpc_url: String,
    #[serde(default)]
    currency_symbol: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}

/// serde default for `CustomNetworkOnDisk::enabled` — a row written without an
/// explicit `enabled` is treated as on.
fn default_true() -> bool {
    true
}

/// True iff `s` parses as an HTTPS URL. Non-HTTPS endpoints are dropped on
/// load so a hand-edited `settings.toml` can't bypass the UI's HTTPS check
/// and steer the wallet onto a MITM-able transport.
pub fn is_https_url(s: &str) -> bool {
    url::Url::parse(s)
        .map(|u| u.scheme() == "https")
        .unwrap_or(false)
}

/// Apply a parsed RPC list to one chain. Empty lists and lists where every
/// entry fails the HTTPS check leave the chain at its current value (so a
/// hand-edited `rpcs = []` doesn't collapse the mainnet default).
fn apply_rpc_list(target: &mut PerChain<Vec<String>>, chain: Chain, list: Option<Vec<String>>) {
    let Some(list) = list else { return };
    let filtered: Vec<String> = list.into_iter().filter(|s| is_https_url(s)).collect();
    if !filtered.is_empty() {
        target.set(chain, filtered);
    }
}

/// Pure parser: produce a `State` from settings-file TOML. A malformed TOML
/// document, missing keys, and unparseable values all silently fall back to
/// defaults so a hand-edited config can never brick startup.
fn parse(text: &str) -> State {
    let mut state = default_state();
    let Ok(on_disk): Result<OnDisk, _> = toml::from_str(text) else {
        return state;
    };
    if let Some(t) = on_disk.theme.as_deref()
        && let Some(k) = ThemeKind::from_key(t)
    {
        state.theme = k;
    }
    apply_rpc_list(&mut state.rpcs, Chain::Mainnet, on_disk.rpcs);
    apply_rpc_list(&mut state.rpcs, Chain::Base, on_disk.rpcs_base);
    apply_rpc_list(&mut state.rpcs, Chain::Optimism, on_disk.rpcs_optimism);
    apply_rpc_list(
        &mut state.consensus_rpcs,
        Chain::Mainnet,
        on_disk.consensus_rpcs,
    );
    apply_rpc_list(
        &mut state.consensus_rpcs,
        Chain::Base,
        on_disk.consensus_rpcs_base,
    );
    apply_rpc_list(
        &mut state.consensus_rpcs,
        Chain::Optimism,
        on_disk.consensus_rpcs_optimism,
    );
    if let Some(s) = on_disk.checkpoint_override.as_deref() {
        state.checkpoint_override = if s.is_empty() {
            None
        } else {
            B256::from_str(s).ok()
        };
    }
    if let Some(p) = on_disk.indexer_provider.as_deref()
        && let Some(parsed) = IndexerProvider::from_key(p)
    {
        state.indexer_provider = parsed;
    }
    state.etherscan_api_key = on_disk.etherscan_api_key.filter(|s| !s.is_empty());
    state.alchemy_api_key = on_disk.alchemy_api_key.filter(|s| !s.is_empty());
    state.drpc_api_key = on_disk.drpc_api_key.filter(|s| !s.is_empty());
    state.blockscout_base_url = on_disk
        .blockscout_base_url
        .filter(|s| !s.is_empty() && is_https_url(s));
    state.blockscout_api_key = on_disk.blockscout_api_key.filter(|s| !s.is_empty());

    // ── Wizard-level network config ──────────────────────────────────
    if let Some(url) = on_disk.kao_server_url.as_deref()
        && let Some(normalized) = parse_kao_server_input(url)
    {
        state.kao_server_url = normalized;
    }
    if let Some(p) = on_disk.rpc_provider.as_deref()
        && let Some(parsed) = RpcProvider::from_key(p)
    {
        state.rpc_provider = parsed;
    } else {
        // Backwards compat: infer provider from existing config.
        if state.alchemy_api_key.is_some() {
            state.rpc_provider = RpcProvider::Alchemy;
        } else if state.drpc_api_key.is_some() {
            state.rpc_provider = RpcProvider::Drpc;
        }
    }
    state.rpc_key = on_disk.rpc_key.filter(|s| !s.is_empty());
    // Backwards compat: if rpc_key is unset, populate from the legacy
    // provider-specific key so the wizard shows the key the user already
    // entered.
    if state.rpc_key.is_none() {
        match state.rpc_provider {
            RpcProvider::Drpc => state.rpc_key = state.drpc_api_key.clone(),
            RpcProvider::Alchemy => state.rpc_key = state.alchemy_api_key.clone(),
            _ => {}
        }
    }
    state.custom_rpc_url = on_disk.custom_rpc_url.filter(|s| !s.is_empty());

    if let Some(p) = on_disk.api_provider.as_deref()
        && let Some(parsed) = ApiProvider::from_key(p)
    {
        state.api_provider = parsed;
    } else {
        // Backwards compat: infer API provider from existing indexer config.
        match state.indexer_provider {
            IndexerProvider::Blockscout => state.api_provider = ApiProvider::Blockscout,
            IndexerProvider::Drpc => state.api_provider = ApiProvider::Drpc,
            IndexerProvider::Kao => state.api_provider = ApiProvider::Kao,
            IndexerProvider::None => state.api_provider = ApiProvider::None,
            _ => {}
        }
    }
    state.api_key = on_disk.api_key.filter(|s| !s.is_empty());
    // Backwards compat: if api_key is unset, populate from the legacy
    // drpc_api_key so the wizard shows the key the user already entered.
    if state.api_key.is_none() && state.api_provider == ApiProvider::Drpc {
        state.api_key = state.drpc_api_key.clone();
    }

    if let Some(p) = on_disk.safe_tx_service.as_deref()
        && let Some(parsed) = SafeTxService::from_key(p)
    {
        state.safe_tx_service = parsed;
    }
    state.safe_tx_service_url = on_disk
        .safe_tx_service_url
        .filter(|s| !s.is_empty() && is_https_url(s));

    if let Some(enabled) = on_disk.proxy_enabled {
        state.proxy_enabled = enabled;
    }
    if let Some(p) = on_disk.proxy_type.as_deref()
        && let Some(parsed) = ProxyType::from_key(p)
    {
        state.proxy_type = parsed;
    }
    if let Some(addr) = on_disk.proxy_address.as_deref()
        && !addr.is_empty()
    {
        state.proxy_address = addr.to_string();
    }

    if let Some(rows) = on_disk.custom_networks {
        let parsed = rows.into_iter().map(|r| CustomNetwork {
            chain_id: r.chain_id,
            name: r.name,
            rpc_url: r.rpc_url,
            currency_symbol: r
                .currency_symbol
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_CUSTOM_SYMBOL.to_string()),
            enabled: r.enabled,
        });
        state.custom_networks = normalize_custom_networks(parsed);
    }

    state
}

/// Drop invalid/duplicate custom-network rows and trim fields. A row is kept
/// only when it has a non-empty name, an `http(s)` RPC URL, a chain id that
/// doesn't collide with a built-in chain, and a chain id not already seen
/// (first occurrence wins). Centralizes the rules so both the loader and the
/// setter enforce the same invariants.
fn normalize_custom_networks(rows: impl IntoIterator<Item = CustomNetwork>) -> Vec<CustomNetwork> {
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut out = Vec::new();
    for mut n in rows {
        n.name = n.name.trim().to_string();
        n.rpc_url = n.rpc_url.trim().to_string();
        n.currency_symbol = n.currency_symbol.trim().to_string();
        if n.currency_symbol.is_empty() {
            n.currency_symbol = DEFAULT_CUSTOM_SYMBOL.to_string();
        }
        if n.name.is_empty()
            || !is_http_or_https_url(&n.rpc_url)
            || BUILTIN_CHAIN_IDS.contains(&n.chain_id)
            || !seen.insert(n.chain_id)
        {
            continue;
        }
        out.push(n);
    }
    out
}

/// L2 lists go through `Some(...)` only when non-empty so a stock config
/// (which leaves L2 unconfigured) doesn't write `rpcs_base = []` lines that
/// hint at functionality the user hasn't opted into.
fn nonempty(v: &[String]) -> Option<Vec<String>> {
    if v.is_empty() { None } else { Some(v.to_vec()) }
}

/// Pure serializer: emit TOML for a `State`. Mirrors `parse` — `auto_checkpoint`
/// is intentionally omitted, and `checkpoint_override` is dropped from the
/// output when unset rather than being written as an empty string.
fn serialize(state: &State) -> String {
    let on_disk = OnDisk {
        theme: Some(state.theme.key().to_string()),
        rpcs: Some(state.rpcs.get(Chain::Mainnet).clone()),
        rpcs_base: nonempty(state.rpcs.get(Chain::Base)),
        rpcs_optimism: nonempty(state.rpcs.get(Chain::Optimism)),
        consensus_rpcs: Some(state.consensus_rpcs.get(Chain::Mainnet).clone()),
        consensus_rpcs_base: nonempty(state.consensus_rpcs.get(Chain::Base)),
        consensus_rpcs_optimism: nonempty(state.consensus_rpcs.get(Chain::Optimism)),
        checkpoint_override: state
            .checkpoint_override
            .map(|b| format!("0x{}", alloy::hex::encode(b.as_slice()))),
        indexer_provider: Some(state.indexer_provider.key().to_string()),
        etherscan_api_key: state.etherscan_api_key.clone(),
        alchemy_api_key: state.alchemy_api_key.clone(),
        drpc_api_key: state.drpc_api_key.clone(),
        blockscout_base_url: state.blockscout_base_url.clone(),
        blockscout_api_key: state.blockscout_api_key.clone(),
        kao_server_url: if state.kao_server_url != DEFAULT_KAO_SERVER_URL {
            Some(state.kao_server_url.clone())
        } else {
            None
        },
        rpc_provider: Some(state.rpc_provider.key().to_string()),
        rpc_key: state.rpc_key.clone(),
        custom_rpc_url: state.custom_rpc_url.clone(),
        api_provider: Some(state.api_provider.key().to_string()),
        api_key: state.api_key.clone(),
        safe_tx_service: Some(state.safe_tx_service.key().to_string()),
        safe_tx_service_url: state.safe_tx_service_url.clone(),
        proxy_enabled: if state.proxy_enabled {
            Some(true)
        } else {
            None
        },
        proxy_type: if state.proxy_enabled {
            Some(state.proxy_type.key().to_string())
        } else {
            None
        },
        proxy_address: if state.proxy_enabled && state.proxy_address != "127.0.0.1:9050" {
            Some(state.proxy_address.clone())
        } else {
            None
        },
        custom_networks: if state.custom_networks.is_empty() {
            None
        } else {
            Some(
                state
                    .custom_networks
                    .iter()
                    .map(|n| CustomNetworkOnDisk {
                        chain_id: n.chain_id,
                        name: n.name.clone(),
                        rpc_url: n.rpc_url.clone(),
                        currency_symbol: Some(n.currency_symbol.clone()),
                        enabled: n.enabled,
                    })
                    .collect(),
            )
        },
    };
    toml::to_string(&on_disk).expect("serializing settings cannot fail")
}

pub fn theme() -> ThemeKind {
    ensure().lock().expect("settings mutex poisoned").theme
}

pub fn set_theme(kind: ThemeKind) {
    let old = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        std::mem::replace(&mut state.theme, kind)
    };
    crate::trace::state("settings", "theme", old.key(), kind.key());
    write_all();
}

/// The built-in execution-RPC list for Mainnet.
#[cfg(test)]
fn default_rpcs() -> &'static [&'static str] {
    DEFAULT_RPCS
}

/// The built-in consensus (beacon-chain LC) RPC list for Mainnet.
#[cfg(test)]
fn default_consensus_rpcs() -> &'static [&'static str] {
    DEFAULT_CONSENSUS_RPCS
}

/// Per-chain execution-RPC list. When the user hasn't set one for `chain`,
/// fall back to a synthesized URL derived from whatever indexer key they
/// already entered: dRPC and Alchemy both expose Mainnet/Base/Optimism
/// under one key, so a user with just a dRPC key gets working Helios
/// builds on all three chains without revisiting the setup flow. Without
/// this fallback the dashboard's per-chain portfolio fan-out skipped L2s
/// silently and Base/OP balances never appeared.
pub fn rpcs(chain: Chain) -> Vec<String> {
    let explicit = ensure()
        .lock()
        .expect("settings mutex poisoned")
        .rpcs
        .get(chain)
        .clone();
    if !explicit.is_empty() {
        return explicit;
    }
    if let Some(url) = synthesize_exec_url(chain) {
        return vec![url];
    }
    Vec::new()
}

/// Build a single per-chain execution-RPC URL from the keys the user
/// already configured. Tried in dRPC-then-Alchemy order: matches the
/// preference users imply by setting one key vs. the other, and
/// keeps the synthesis stable across `indexer_provider` toggles (so the
/// Helios client doesn't get rebuilt mid-session by a UI dropdown
/// change).
fn synthesize_exec_url(chain: Chain) -> Option<String> {
    if let Some(key) = drpc_api_key() {
        let slug = match chain {
            Chain::Mainnet => "ethereum",
            Chain::Base => "base",
            Chain::Optimism => "optimism",
        };
        return Some(format!("https://lb.drpc.live/{slug}/{key}"));
    }
    if let Some(key) = alchemy_api_key() {
        let slug = match chain {
            Chain::Mainnet => "eth-mainnet",
            Chain::Base => "base-mainnet",
            Chain::Optimism => "opt-mainnet",
        };
        return Some(format!("https://{slug}.g.alchemy.com/v2/{key}"));
    }
    None
}

pub fn set_rpcs(chain: Chain, list: Vec<String>) {
    let to_len = list.len();
    let from_len = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        let from = state.rpcs.get(chain).len();
        state.rpcs.set(chain, list);
        from
    };
    // URLs can embed API keys — log list lengths only.
    crate::trace::state(
        "settings",
        &format!("rpcs_{}", chain.label()),
        from_len,
        to_len,
    );
    write_all();
}

/// Per-chain consensus-RPC list. Empty falls back to the chain's
/// hardcoded default (`Chain::default_consensus_url`) — public beacon
/// endpoint for Mainnet, operationsolarstorm.org's L2 light-client
/// proxies for Base/Optimism. These don't take an API key, so a user
/// with only a dRPC exec URL still ends up with a buildable Helios
/// client on every chain.
pub fn consensus_rpcs(chain: Chain) -> Vec<String> {
    let explicit = ensure()
        .lock()
        .expect("settings mutex poisoned")
        .consensus_rpcs
        .get(chain)
        .clone();
    if !explicit.is_empty() {
        return explicit;
    }
    vec![chain.default_consensus_url().to_string()]
}

pub fn set_consensus_rpcs(chain: Chain, list: Vec<String>) {
    let to_len = list.len();
    let from_len = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        let from = state.consensus_rpcs.get(chain).len();
        state.consensus_rpcs.set(chain, list);
        from
    };
    // URLs can embed API keys — log list lengths only.
    crate::trace::state(
        "settings",
        &format!("consensus_rpcs_{}", chain.label()),
        from_len,
        to_len,
    );
    write_all();
}

/// All remembered custom networks, enabled or not. Order is the order the
/// user added them (preserved by the setter).
pub fn custom_networks() -> Vec<CustomNetwork> {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .custom_networks
        .clone()
}

/// Custom networks the user has switched on — the set the portfolio fan-out
/// and send token list consider.
pub fn enabled_custom_networks() -> Vec<CustomNetwork> {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .custom_networks
        .iter()
        .filter(|n| n.enabled)
        .cloned()
        .collect()
}

/// Look up a single custom network by chain id. `None` if no custom network
/// with that id is configured (including when it's a built-in id).
pub fn custom_network(chain_id: u64) -> Option<CustomNetwork> {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .custom_networks
        .iter()
        .find(|n| n.chain_id == chain_id)
        .cloned()
}

/// Replace the whole custom-network list (the wizard edits all rows together
/// and commits once). Rows are normalized — invalid/duplicate/built-in-id
/// entries are dropped — before persisting, so callers can pass partially-
/// validated UI state without corrupting the file.
pub fn set_custom_networks(networks: Vec<CustomNetwork>) {
    let normalized = normalize_custom_networks(networks);
    let to_len = normalized.len();
    let from_len = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        let from = state.custom_networks.len();
        state.custom_networks = normalized;
        from
    };
    crate::trace::state("settings", "custom_networks", from_len, to_len);
    write_all();
}

pub fn checkpoint_override() -> Option<B256> {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .checkpoint_override
}

pub fn set_checkpoint_override(value: Option<B256>) {
    let old = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        std::mem::replace(&mut state.checkpoint_override, value)
    };
    let display = |v: Option<B256>| {
        v.map(|b| b.to_string())
            .unwrap_or_else(|| "none".to_string())
    };
    crate::trace::state(
        "settings",
        "checkpoint_override",
        display(old),
        display(value),
    );
    write_all();
}

pub fn indexer_provider() -> IndexerProvider {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .indexer_provider
}

pub fn set_indexer_provider(value: IndexerProvider) {
    let old = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        std::mem::replace(&mut state.indexer_provider, value)
    };
    crate::trace::state("settings", "indexer_provider", old.key(), value.key());
    write_all();
}

/// Presence label for logging credential-bearing settings (API keys, RPC
/// keys, URLs that can embed keys): neither content nor length may reach
/// the log stream.
fn presence(is_set: bool) -> &'static str {
    if is_set { "set" } else { "cleared" }
}

pub fn etherscan_api_key() -> Option<String> {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .etherscan_api_key
        .clone()
}

#[allow(dead_code)]
pub fn set_etherscan_api_key(value: Option<String>) {
    let value = value.filter(|s| !s.is_empty());
    let to = presence(value.is_some());
    let from = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        let from = presence(state.etherscan_api_key.is_some());
        state.etherscan_api_key = value;
        from
    };
    // Credential — presence only.
    crate::trace::state("settings", "etherscan_api_key", from, to);
    write_all();
}

pub fn alchemy_api_key() -> Option<String> {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .alchemy_api_key
        .clone()
}

pub fn set_alchemy_api_key(value: Option<String>) {
    let value = value.filter(|s| !s.is_empty());
    let to = presence(value.is_some());
    let from = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        let from = presence(state.alchemy_api_key.is_some());
        state.alchemy_api_key = value;
        from
    };
    // Credential — presence only.
    crate::trace::state("settings", "alchemy_api_key", from, to);
    write_all();
}

pub fn drpc_api_key() -> Option<String> {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .drpc_api_key
        .clone()
}

pub fn set_drpc_api_key(value: Option<String>) {
    let value = value.filter(|s| !s.is_empty());
    let to = presence(value.is_some());
    let from = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        let from = presence(state.drpc_api_key.is_some());
        state.drpc_api_key = value;
        from
    };
    // Credential — presence only.
    crate::trace::state("settings", "drpc_api_key", from, to);
    write_all();
}

pub fn blockscout_base_url() -> Option<String> {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .blockscout_base_url
        .clone()
}

pub fn set_blockscout_base_url(value: Option<String>) {
    let cleaned = value.filter(|s| !s.is_empty() && is_https_url(s));
    let to = presence(cleaned.is_some());
    let from = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        let from = presence(state.blockscout_base_url.is_some());
        state.blockscout_base_url = cleaned;
        from
    };
    // URL can embed credentials — presence only.
    crate::trace::state("settings", "blockscout_base_url", from, to);
    write_all();
}

pub fn blockscout_api_key() -> Option<String> {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .blockscout_api_key
        .clone()
}

pub fn set_blockscout_api_key(value: Option<String>) {
    let value = value.filter(|s| !s.is_empty());
    let to = presence(value.is_some());
    let from = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        let from = presence(state.blockscout_api_key.is_some());
        state.blockscout_api_key = value;
        from
    };
    // Credential — presence only.
    crate::trace::state("settings", "blockscout_api_key", from, to);
    write_all();
}

pub fn kao_server_url() -> String {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .kao_server_url
        .clone()
}

pub fn set_kao_server_url(value: String) {
    let url = parse_kao_server_input(&value).unwrap_or_else(|| DEFAULT_KAO_SERVER_URL.to_string());
    // URL can embed credentials — log default/custom only, never the value.
    let label = |u: &str| {
        if u == DEFAULT_KAO_SERVER_URL {
            "default"
        } else {
            "custom"
        }
    };
    let to = label(&url);
    let from = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        let from = label(&state.kao_server_url);
        state.kao_server_url = url;
        from
    };
    crate::trace::state("settings", "kao_server_url", from, to);
    write_all();
}

/// Built-in checkpoint used to bootstrap Mainnet sync when no user override is
/// set. Always the binary's `BUILTIN_CHECKPOINT`; a fresh value is obtained
/// only through the network setup wizard's manual refresh, which is stored as
/// `checkpoint_override` rather than mutating this.
pub fn auto_checkpoint() -> B256 {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .auto_checkpoint
}

// ── Wizard-level getters/setters ─────────────────────────────────────────

pub fn rpc_provider() -> RpcProvider {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .rpc_provider
}

pub fn set_rpc_provider(value: RpcProvider) {
    let old = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        std::mem::replace(&mut state.rpc_provider, value)
    };
    crate::trace::state("settings", "rpc_provider", old.key(), value.key());
    write_all();
}

pub fn rpc_key() -> Option<String> {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .rpc_key
        .clone()
}

pub fn set_rpc_key(value: Option<String>) {
    let value = value.filter(|s| !s.is_empty());
    let to = presence(value.is_some());
    let from = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        let from = presence(state.rpc_key.is_some());
        state.rpc_key = value;
        from
    };
    // Credential — presence only.
    crate::trace::state("settings", "rpc_key", from, to);
    write_all();
}

pub fn custom_rpc_url() -> Option<String> {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .custom_rpc_url
        .clone()
}

pub fn set_custom_rpc_url(value: Option<String>) {
    let value = value.filter(|s| !s.is_empty());
    let to = presence(value.is_some());
    let from = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        let from = presence(state.custom_rpc_url.is_some());
        state.custom_rpc_url = value;
        from
    };
    // URL can embed credentials — presence only.
    crate::trace::state("settings", "custom_rpc_url", from, to);
    write_all();
}

pub fn api_provider() -> ApiProvider {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .api_provider
}

pub fn set_api_provider(value: ApiProvider) {
    let old = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        std::mem::replace(&mut state.api_provider, value)
    };
    crate::trace::state("settings", "api_provider", old.key(), value.key());
    write_all();
}

pub fn api_key() -> Option<String> {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .api_key
        .clone()
}

pub fn set_api_key(value: Option<String>) {
    let value = value.filter(|s| !s.is_empty());
    let to = presence(value.is_some());
    let from = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        let from = presence(state.api_key.is_some());
        state.api_key = value;
        from
    };
    // Credential — presence only.
    crate::trace::state("settings", "api_key", from, to);
    write_all();
}

pub fn safe_tx_service() -> SafeTxService {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .safe_tx_service
}

pub fn set_safe_tx_service(value: SafeTxService) {
    let old = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        std::mem::replace(&mut state.safe_tx_service, value)
    };
    crate::trace::state("settings", "safe_tx_service", old.key(), value.key());
    write_all();
}

pub fn safe_tx_service_url() -> Option<String> {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .safe_tx_service_url
        .clone()
}

pub fn set_safe_tx_service_url(value: Option<String>) {
    let cleaned = value.filter(|s| !s.is_empty() && is_https_url(s));
    let to = presence(cleaned.is_some());
    let from = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        let from = presence(state.safe_tx_service_url.is_some());
        state.safe_tx_service_url = cleaned;
        from
    };
    // URL can embed credentials — presence only.
    crate::trace::state("settings", "safe_tx_service_url", from, to);
    write_all();
}

pub fn proxy_enabled() -> bool {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .proxy_enabled
}

pub fn set_proxy_enabled(value: bool) {
    let old = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        std::mem::replace(&mut state.proxy_enabled, value)
    };
    crate::trace::state("settings", "proxy_enabled", old, value);
    write_all();
}

pub fn proxy_type() -> ProxyType {
    ensure().lock().expect("settings mutex poisoned").proxy_type
}

pub fn set_proxy_type(value: ProxyType) {
    let old = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        std::mem::replace(&mut state.proxy_type, value)
    };
    crate::trace::state("settings", "proxy_type", old.key(), value.key());
    write_all();
}

pub fn proxy_address() -> String {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .proxy_address
        .clone()
}

pub fn set_proxy_address(value: String) {
    // Fall back to the Tor default for an empty or malformed address. The
    // wallet installs the proxy as `socks5h://{addr}` in `ALL_PROXY`, and
    // reqwest *silently ignores* a value it can't parse — connecting directly
    // and leaking the user's real IP. So a value that wouldn't yield a valid
    // proxy URI must never be persisted; the Tor default fails closed if Tor
    // isn't running, rather than fail open.
    let trimmed = value.trim();
    let v = if valid_proxy_address(trimmed) {
        trimmed.to_string()
    } else {
        "127.0.0.1:9050".to_string()
    };
    // Privacy: never log the address itself — only whether it's the Tor
    // default or a custom endpoint (revealing a bespoke host:port could
    // deanonymize the user's proxy setup).
    const TOR_DEFAULT: &str = "127.0.0.1:9050";
    let kind = |a: &str| {
        if a == TOR_DEFAULT {
            "default"
        } else {
            "custom"
        }
    };
    let to = kind(&v);
    let from = {
        let mut state = ensure().lock().expect("settings mutex poisoned");
        let from = kind(&state.proxy_address).to_string();
        state.proxy_address = v.clone();
        from
    };
    crate::trace::state("settings", "proxy_address", from, to);
    write_all();
}

/// True when `addr` is a well-formed `host:port` that reqwest will accept as a
/// proxy. The wallet installs the proxy as `socks5h://{addr}`, and reqwest /
/// hyper-util parse that value via [`http::Uri`], silently ignoring it (and
/// connecting *directly*) if it doesn't parse. We mirror that exact parser so
/// an authority-illegal value (spaces, non-ASCII, missing host, missing or
/// out-of-range port, trailing path) is rejected at input time instead of
/// turning into a silent direct connection that deanonymizes the user.
pub fn valid_proxy_address(addr: &str) -> bool {
    let addr = addr.trim();
    let Ok(uri) = format!("socks5h://{addr}").parse::<http::Uri>() else {
        return false;
    };
    match uri.authority() {
        // The whole input must be exactly the authority — `host:port` with an
        // explicit, in-range port and no path/query/trailing junk.
        Some(auth) => auth.as_str() == addr && auth.port_u16().is_some(),
        None => false,
    }
}

// ── URL generation helpers ──────────────────────────────────────────────

/// Build a per-chain map of Alchemy exec URLs from a single API key.
pub fn alchemy_exec_urls(key: &str) -> PerChain<String> {
    let mut out = PerChain::<String>::default();
    out.set(
        Chain::Mainnet,
        format!("https://eth-mainnet.g.alchemy.com/v2/{key}"),
    );
    out.set(
        Chain::Base,
        format!("https://base-mainnet.g.alchemy.com/v2/{key}"),
    );
    out.set(
        Chain::Optimism,
        format!("https://opt-mainnet.g.alchemy.com/v2/{key}"),
    );
    out
}

/// Build a per-chain map of dRPC exec URLs from a single API key.
pub fn drpc_exec_urls(key: &str) -> PerChain<String> {
    let mut out = PerChain::<String>::default();
    for chain in Chain::ALL {
        let slug = match chain {
            Chain::Mainnet => "ethereum",
            Chain::Base => "base",
            Chain::Optimism => "optimism",
        };
        out.set(chain, format!("https://lb.drpc.live/{slug}/{key}"));
    }
    out
}

/// Build per-chain Kao proxy RPC URLs from the server base URL.
pub fn kao_exec_urls(base: &str) -> PerChain<String> {
    let base = base.trim_end_matches('/');
    let mut out = PerChain::<String>::default();
    for chain in Chain::ALL {
        let slug = match chain {
            Chain::Mainnet => "ethereum",
            Chain::Base => "base",
            Chain::Optimism => "optimism",
        };
        out.set(chain, format!("{base}/rpc/{slug}"));
    }
    out
}

/// Per-chain consensus URL defaults.
pub fn default_consensus_url_map() -> PerChain<String> {
    let mut out = PerChain::<String>::default();
    for chain in Chain::ALL {
        out.set(chain, chain.default_consensus_url().to_string());
    }
    out
}

/// 1RPC relay endpoints — privacy-preserving relay that strips metadata
/// before forwarding to an upstream provider. No API key required.
fn one_rpc_exec_urls() -> PerChain<String> {
    let mut out = PerChain::<String>::default();
    out.set(Chain::Mainnet, "https://1rpc.io/eth".to_string());
    out.set(Chain::Base, "https://1rpc.io/base".to_string());
    out.set(Chain::Optimism, "https://1rpc.io/op".to_string());
    out
}

/// Expand the wizard's RPC provider + key + custom URL into the low-level
/// per-chain settings. Called at wizard finish to persist the provider
/// choice into the existing `rpcs` / `consensus_rpcs` / API-key slots.
pub fn apply_rpc_provider(provider: RpcProvider, key: &str, custom_url: &str) {
    // Persist the wizard-level choice.
    set_rpc_provider(provider);
    set_rpc_key(if key.is_empty() {
        None
    } else {
        Some(key.to_string())
    });
    set_custom_rpc_url(if custom_url.is_empty() {
        None
    } else {
        Some(custom_url.to_string())
    });

    // Generate per-chain URL lists.
    let consensus = default_consensus_url_map();
    match provider {
        RpcProvider::Kao => {
            let exec = kao_exec_urls(&kao_server_url());
            for chain in Chain::ALL {
                set_rpcs(chain, vec![exec.get(chain).clone()]);
                set_consensus_rpcs(chain, vec![consensus.get(chain).clone()]);
            }
        }
        RpcProvider::OneRpc => {
            let exec = one_rpc_exec_urls();
            for chain in Chain::ALL {
                set_rpcs(chain, vec![exec.get(chain).clone()]);
                set_consensus_rpcs(chain, vec![consensus.get(chain).clone()]);
            }
        }
        RpcProvider::Drpc => {
            let exec = drpc_exec_urls(key);
            set_drpc_api_key(Some(key.to_string()));
            for chain in Chain::ALL {
                set_rpcs(chain, vec![exec.get(chain).clone()]);
                set_consensus_rpcs(chain, vec![consensus.get(chain).clone()]);
            }
        }
        RpcProvider::Alchemy => {
            let exec = alchemy_exec_urls(key);
            set_alchemy_api_key(Some(key.to_string()));
            for chain in Chain::ALL {
                set_rpcs(chain, vec![exec.get(chain).clone()]);
                set_consensus_rpcs(chain, vec![consensus.get(chain).clone()]);
            }
        }
        RpcProvider::Custom => {
            if !custom_url.is_empty() {
                set_rpcs(Chain::Mainnet, vec![custom_url.to_string()]);
            }
            // Seed L2 with defaults for consensus.
            for chain in Chain::ALL {
                set_consensus_rpcs(chain, vec![consensus.get(chain).clone()]);
            }
            // L2 exec URLs default to each chain's built-in.
            for chain in [Chain::Base, Chain::Optimism] {
                set_rpcs(chain, vec![chain.default_exec_url().to_string()]);
            }
        }
    }
}

/// Expand the wizard's API provider + key into the low-level indexer
/// settings.
pub fn apply_api_provider(provider: ApiProvider, key: &str) {
    set_api_provider(provider);
    set_api_key(if key.is_empty() {
        None
    } else {
        Some(key.to_string())
    });

    match provider {
        ApiProvider::Kao => {
            // Route indexer queries through the Kao proxy. The proxy holds the
            // dRPC key, so — unlike `ApiProvider::Drpc` — no key is stored here
            // and none is sent upstream from the wallet.
            set_indexer_provider(IndexerProvider::Kao);
        }
        ApiProvider::Blockscout => {
            set_indexer_provider(IndexerProvider::Blockscout);
        }
        ApiProvider::Drpc => {
            set_drpc_api_key(Some(key.to_string()));
            set_indexer_provider(IndexerProvider::Drpc);
        }
        ApiProvider::None => {
            set_indexer_provider(IndexerProvider::None);
        }
    }
}

/// Validate and normalize a custom RPC input. Accepts:
/// - an explicit `https://` URL (kept as-is),
/// - a bare hostname with optional `:port` and `/path` (wrapped as `https://`),
/// - a bare IP address with optional `:port` and `/path` (wrapped as `http://`,
///   since local nodes typically do not have TLS).
///
/// Explicit non-https schemes (`http://`, `ws://`, …) are rejected so users
/// cannot downgrade themselves; if they want plain http they must type the
/// host without a scheme and we will pick the right scheme automatically.
pub fn parse_rpc_input(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if s.contains("://") {
        let url = url::Url::parse(s).ok()?;
        if url.scheme() != "https" {
            return None;
        }
        let host = url.host_str()?;
        if !is_plausible_host(host) {
            return None;
        }
        return Some(s.to_string());
    }
    let (host_port, _) = s.find('/').map_or((s, ""), |i| (&s[..i], &s[i..]));
    let host = match host_port.rsplit_once(':') {
        Some((host, port)) => {
            if port.parse::<u16>().is_err() {
                return None;
            }
            host
        }
        None => host_port,
    };
    if host.parse::<std::net::IpAddr>().is_ok() || host.eq_ignore_ascii_case("localhost") {
        return Some(format!("http://{s}"));
    }
    if !is_plausible_host(host) {
        return None;
    }
    Some(format!("https://{s}"))
}

/// Validate and normalize a user-supplied Kao privacy-proxy base URL.
///
/// Like [`parse_rpc_input`] but tailored to the Kao server field: it accepts
/// an explicit `https://` URL (any host) or — for the common self-hosted dev
/// setup — a plain `http://` URL pointed at loopback (`localhost`,
/// `127.0.0.1`, `[::1]`, …). A bare `host[:port][/path]` is wrapped: only
/// loopback hosts get `http://`; every public host — hostname *or* IP — gets
/// `https://`. Plain http to a *public* host is refused so Kao traffic can't be
/// silently downgraded onto a MITM-able transport, whether or not the user
/// typed the scheme. Returns the normalized URL, or `None` when the input can't
/// be made safe.
///
/// Unlike [`parse_rpc_input`], an explicit `http://localhost` is kept rather
/// than rejected — that's what we store after wrapping bare loopback input, so
/// the stored value must survive a re-parse on the next load.
pub fn parse_kao_server_input(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if s.contains("://") {
        let url = url::Url::parse(s).ok()?;
        let host = url.host_str()?;
        let host_ok = is_loopback_host(host) || is_plausible_host(host);
        let scheme_ok = match url.scheme() {
            "https" => true,
            "http" => is_loopback_host(host),
            _ => false,
        };
        return (host_ok && scheme_ok).then(|| s.to_string());
    }
    let (host_port, _) = s.find('/').map_or((s, ""), |i| (&s[..i], &s[i..]));
    let host = match host_port.rsplit_once(':') {
        Some((host, port)) => {
            if port.parse::<u16>().is_err() {
                return None;
            }
            host
        }
        None => host_port,
    };
    // Only loopback (localhost / 127.0.0.0/8 / ::1) may be wrapped as plain
    // http — that traffic never leaves the machine. A bare *public* IP must NOT
    // be silently downgraded to plaintext: the explicit-scheme branch above
    // already rejects `http://<public-ip>` for the byte-identical URL, so
    // accepting the same address here just because the user omitted the scheme
    // is an inconsistent downgrade. Fall through so a public IP is forced to
    // https like any other public host.
    if is_loopback_host(host) {
        return Some(format!("http://{s}"));
    }
    if !is_plausible_host(host) {
        return None;
    }
    Some(format!("https://{s}"))
}

/// True for hosts where plain http is safe because the traffic never leaves
/// the machine: `localhost` and any loopback IP (`127.0.0.0/8`, `::1`).
/// Accepts the bracketed IPv6 form (`[::1]`) that `Url::host_str` returns.
fn is_loopback_host(host: &str) -> bool {
    let h = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    h.eq_ignore_ascii_case("localhost")
        || h.parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// A host is plausible if it's an IP, `localhost`, or a multi-label hostname.
fn is_plausible_host(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if s.eq_ignore_ascii_case("localhost") || s.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if !s.contains('.') {
        return false;
    }
    is_valid_hostname(s)
}

fn is_valid_hostname(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Pull an Alchemy API key out of an RPC URL like
/// `https://eth-mainnet.g.alchemy.com/v2/{key}`.
#[cfg(test)]
fn extract_alchemy_key(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    if !host.ends_with(".g.alchemy.com") {
        return None;
    }
    let mut segs = parsed.path_segments()?;
    if segs.next()? != "v2" {
        return None;
    }
    let key = segs.next()?;
    if key.is_empty() {
        return None;
    }
    Some(key.to_string())
}

/// Pull a dRPC API key out of an RPC URL like
/// `https://lb.drpc.live/{chain}/{key}`.
#[cfg(test)]
fn extract_drpc_key(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    if host != "lb.drpc.live" {
        return None;
    }
    let mut segs = parsed.path_segments()?;
    let _chain = segs.next()?;
    let key = segs.next()?;
    if key.is_empty() {
        return None;
    }
    Some(key.to_string())
}

fn write_all() {
    let path = settings_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
        let _ = restrict_to_owner(parent, 0o700);
    }
    let snapshot = ensure().lock().expect("settings mutex poisoned").clone();
    let body = serialize(&snapshot);
    // Best-effort, but deliberately no world-readable fallback: if the atomic
    // write fails we leave the previous settings.toml intact rather than risk a
    // create+chmod that briefly exposes the plaintext API keys. The sibling
    // temp shares the target's filesystem, so the realistic failure modes are
    // genuine I/O errors a second insecure attempt wouldn't fix anyway.
    let _ = atomic_write_owner_only(&path, body.as_bytes());
}

/// Write `bytes` to `path` atomically with owner-only (0o600) permissions.
///
/// `settings.toml` holds API keys in plaintext, so three hazards matter on the
/// write path:
/// - a torn write (a crash mid-`write` leaving a truncated, garbage file),
/// - a permissions race (`fs::write` creates the file at the umask-default mode
///   — typically world-readable 0o644 — and only a *follow-up* chmod tightens
///   it, leaving a window where another local user can read the keys), and
/// - a pre-image at a predictable temp path (a symlink planted as the temp file
///   would be followed, redirecting the secret write and the chmod).
///
/// All three are closed by creating a sibling temp file with `create_new`
/// (never following an existing path/symlink) at mode 0o600 up front, writing
/// and `fsync`ing it, then renaming it over `path` — atomic on the same
/// filesystem, so the secret is never briefly world-readable and `path` is
/// either fully old or fully new.
fn atomic_write_owner_only(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("settings.toml");
    let tmp = dir.join(format!(".{file_name}.tmp"));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    // `create_new` refuses to open an existing path, so a hostile or stale temp
    // (a symlink pre-image, or a leftover from a crash) is never followed or
    // written through. A genuine leftover is unlinked and retried once so a past
    // crash can't wedge every future save; unlinking a symlink drops the link,
    // not its target.
    let mut f = match opts.open(&tmp) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(&tmp)?;
            opts.open(&tmp)?
        }
        Err(e) => return Err(e),
    };
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);

    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Restrict a path to owner-only access on Unix; no-op elsewhere.
fn restrict_to_owner(path: &std::path::Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_returns_defaults() {
        let s = parse("");
        let d = default_state();
        assert_eq!(s.rpcs.get(Chain::Mainnet), d.rpcs.get(Chain::Mainnet));
        assert_eq!(
            s.consensus_rpcs.get(Chain::Mainnet),
            d.consensus_rpcs.get(Chain::Mainnet)
        );
        assert_eq!(s.checkpoint_override, d.checkpoint_override);
        assert_eq!(s.theme, d.theme);
    }

    #[test]
    fn parse_ignores_comments_and_blank_lines() {
        let s = parse(
            "\
            # comment\n\
            \n\
            # indented comment\n\
            consensus_rpcs = [\"https://cl.example/\"]\n",
        );
        assert_eq!(
            s.consensus_rpcs.get(Chain::Mainnet),
            &vec!["https://cl.example/".to_string()]
        );
    }

    #[test]
    fn parse_ignores_unknown_keys() {
        let s = parse("totally_unknown = \"foo\"\nconsensus_rpcs = [\"https://cl.example/\"]\n");
        assert_eq!(
            s.consensus_rpcs.get(Chain::Mainnet),
            &vec!["https://cl.example/".to_string()]
        );
    }

    #[test]
    fn parse_malformed_toml_returns_defaults() {
        let s = parse("this is = = not valid toml\n");
        let d = default_state();
        assert_eq!(s.rpcs.get(Chain::Mainnet), d.rpcs.get(Chain::Mainnet));
        assert_eq!(
            s.consensus_rpcs.get(Chain::Mainnet),
            d.consensus_rpcs.get(Chain::Mainnet)
        );
    }

    #[test]
    fn parse_preserves_rpc_array_order() {
        let s =
            parse("rpcs = [\"https://a.example\", \"https://b.example\", \"https://c.example\"]\n");
        assert_eq!(
            s.rpcs.get(Chain::Mainnet),
            &vec![
                "https://a.example".to_string(),
                "https://b.example".to_string(),
                "https://c.example".to_string(),
            ],
        );
    }

    #[test]
    fn parse_empty_rpc_array_does_not_replace_default() {
        // An explicit empty list must NOT collapse the default RPC list, since
        // the user almost certainly didn't mean to disable all upstreams.
        let s = parse("rpcs = []\n");
        assert_eq!(
            s.rpcs.get(Chain::Mainnet),
            default_state().rpcs.get(Chain::Mainnet)
        );
    }

    #[test]
    fn parse_empty_consensus_rpc_array_does_not_replace_default() {
        let s = parse("consensus_rpcs = []\n");
        assert_eq!(
            s.consensus_rpcs.get(Chain::Mainnet),
            default_state().consensus_rpcs.get(Chain::Mainnet)
        );
    }

    #[test]
    fn parse_custom_networks_round_trips_via_serialize() {
        let toml = "\
[[custom_networks]]
chain_id = 11155111
name = \"Sepolia\"
rpc_url = \"https://sepolia.example\"
currency_symbol = \"ETH\"
enabled = true

[[custom_networks]]
chain_id = 31337
name = \"Anvil\"
rpc_url = \"http://127.0.0.1:8545\"
enabled = false
";
        let s = parse(toml);
        assert_eq!(s.custom_networks.len(), 2);
        assert_eq!(s.custom_networks[0].chain_id, 11155111);
        assert_eq!(s.custom_networks[0].name, "Sepolia");
        assert!(s.custom_networks[0].enabled);
        // `enabled` omitted on the second row defaults to true via serde, but
        // here it's explicitly false.
        assert_eq!(s.custom_networks[1].chain_id, 31337);
        assert!(!s.custom_networks[1].enabled);
        // http:// is allowed for custom networks (local Anvil).
        assert_eq!(s.custom_networks[1].rpc_url, "http://127.0.0.1:8545");

        // Serialize → parse must preserve the list.
        let reparsed = parse(&serialize(&s));
        assert_eq!(reparsed.custom_networks, s.custom_networks);
    }

    #[test]
    fn parse_custom_networks_drops_invalid_and_collisions() {
        let toml = "\
[[custom_networks]]
chain_id = 1
name = \"Fake Mainnet\"
rpc_url = \"https://evil.example\"

[[custom_networks]]
chain_id = 5
name = \"\"
rpc_url = \"https://no-name.example\"

[[custom_networks]]
chain_id = 6
name = \"Bad URL\"
rpc_url = \"not a url\"

[[custom_networks]]
chain_id = 11155111
name = \"Sepolia\"
rpc_url = \"https://sepolia.example\"

[[custom_networks]]
chain_id = 11155111
name = \"Sepolia Dup\"
rpc_url = \"https://dup.example\"
";
        let s = parse(toml);
        // Built-in id (1), blank name (5), bad URL (6), and the duplicate
        // 11155111 are all dropped — only the first valid Sepolia survives.
        assert_eq!(s.custom_networks.len(), 1);
        assert_eq!(s.custom_networks[0].chain_id, 11155111);
        assert_eq!(s.custom_networks[0].name, "Sepolia");
    }

    #[test]
    fn custom_networks_default_symbol_when_blank() {
        let toml = "\
[[custom_networks]]
chain_id = 31337
name = \"Anvil\"
rpc_url = \"http://127.0.0.1:8545\"
";
        let s = parse(toml);
        assert_eq!(s.custom_networks.len(), 1);
        assert_eq!(s.custom_networks[0].currency_symbol, DEFAULT_CUSTOM_SYMBOL);
    }

    #[test]
    fn empty_custom_networks_omits_section_from_output() {
        // An empty list must not litter the file with a `[[custom_networks]]`
        // section. (A stock config is seeded with Sepolia/Anvil, so clear them
        // first to exercise the empty case.)
        let mut s = default_state();
        s.custom_networks.clear();
        let out = serialize(&s);
        assert!(!out.contains("custom_networks"));
    }

    #[test]
    fn default_state_seeds_sepolia_and_anvil_disabled() {
        let s = default_state();
        let sepolia = s
            .custom_networks
            .iter()
            .find(|n| n.chain_id == SEPOLIA_CHAIN_ID)
            .expect("Sepolia seeded");
        let anvil = s
            .custom_networks
            .iter()
            .find(|n| n.chain_id == ANVIL_CHAIN_ID)
            .expect("Anvil seeded");
        // Off by default — they must not widen the portfolio fan-out unasked.
        assert!(!sepolia.enabled);
        assert!(!anvil.enabled);
        // Seeds are valid rows that survive normalization (Anvil's http:// is
        // intentionally allowed for the local node).
        assert_eq!(
            s.custom_networks,
            normalize_custom_networks(s.custom_networks.clone())
        );
        assert!(is_http_or_https_url(&anvil.rpc_url));
        assert!(anvil.rpc_url.starts_with("http://"));
    }

    #[test]
    fn fresh_config_keeps_seeds_section_present_is_authoritative() {
        // A config with no `[[custom_networks]]` section keeps the seeds…
        let fresh = parse("");
        assert_eq!(fresh.custom_networks, seeded_custom_networks());

        // …but once a section is present it fully replaces them, so a user who
        // deletes Anvil and keeps only Sepolia doesn't get Anvil re-added.
        let only_sepolia = parse(
            "\
[[custom_networks]]
chain_id = 11155111
name = \"Sepolia\"
rpc_url = \"https://sepolia.example\"
enabled = true
",
        );
        assert_eq!(only_sepolia.custom_networks.len(), 1);
        assert_eq!(only_sepolia.custom_networks[0].chain_id, SEPOLIA_CHAIN_ID);
        assert!(only_sepolia.custom_networks[0].enabled);
    }

    #[test]
    fn parse_legacy_flat_rpcs_seeds_only_mainnet_slot() {
        // Pre-L2 configs only carry `rpcs` / `consensus_rpcs` — those keys
        // must continue to populate Mainnet and leave L2 slots empty.
        let s =
            parse("rpcs = [\"https://eth.example\"]\nconsensus_rpcs = [\"https://cl.example\"]\n");
        assert_eq!(
            s.rpcs.get(Chain::Mainnet),
            &vec!["https://eth.example".to_string()]
        );
        assert!(s.rpcs.get(Chain::Base).is_empty());
        assert!(s.rpcs.get(Chain::Optimism).is_empty());
        assert!(s.consensus_rpcs.get(Chain::Base).is_empty());
        assert!(s.consensus_rpcs.get(Chain::Optimism).is_empty());
    }

    #[test]
    fn parse_per_chain_keys_populate_l2_slots() {
        let s = parse(
            "rpcs_base = [\"https://base.example\"]\n\
             rpcs_optimism = [\"https://op.example\"]\n\
             consensus_rpcs_base = [\"https://cl-base.example\"]\n\
             consensus_rpcs_optimism = [\"https://cl-op.example\"]\n",
        );
        assert_eq!(
            s.rpcs.get(Chain::Base),
            &vec!["https://base.example".to_string()]
        );
        assert_eq!(
            s.rpcs.get(Chain::Optimism),
            &vec!["https://op.example".to_string()]
        );
        assert_eq!(
            s.consensus_rpcs.get(Chain::Base),
            &vec!["https://cl-base.example".to_string()]
        );
        assert_eq!(
            s.consensus_rpcs.get(Chain::Optimism),
            &vec!["https://cl-op.example".to_string()]
        );
        // Mainnet should still hold the built-in default since the file had
        // no `rpcs` / `consensus_rpcs` flat keys.
        assert_eq!(
            s.rpcs.get(Chain::Mainnet),
            default_state().rpcs.get(Chain::Mainnet)
        );
    }

    #[test]
    fn parse_drops_non_https_l2_rpcs() {
        // Same MITM-protection rule applies on L2: a hand-edited http URL
        // gets filtered out, leaving the slot empty.
        let s = parse("rpcs_base = [\"http://insecure.example\"]\n");
        assert!(s.rpcs.get(Chain::Base).is_empty());
    }

    #[test]
    fn parse_checkpoint_override_empty_clears_value() {
        let s = parse("checkpoint_override = \"\"\n");
        assert_eq!(s.checkpoint_override, None);
    }

    #[test]
    fn parse_checkpoint_override_invalid_hex_clears_value() {
        let s = parse("checkpoint_override = \"not_a_hex\"\n");
        assert_eq!(s.checkpoint_override, None);
    }

    #[test]
    fn parse_then_serialize_roundtrip() {
        let mut rpcs = PerChain::<Vec<String>>::default();
        rpcs.set(
            Chain::Mainnet,
            vec!["https://r1.example".into(), "https://r2.example".into()],
        );
        rpcs.set(Chain::Base, vec!["https://base.example".into()]);
        rpcs.set(Chain::Optimism, vec!["https://op.example".into()]);
        let mut consensus_rpcs = PerChain::<Vec<String>>::default();
        consensus_rpcs.set(
            Chain::Mainnet,
            vec!["https://cl1.example".into(), "https://cl2.example".into()],
        );
        consensus_rpcs.set(Chain::Base, vec!["https://cl-base.example".into()]);
        consensus_rpcs.set(Chain::Optimism, vec!["https://cl-op.example".into()]);
        let original = State {
            theme: ThemeKind::Mint,
            rpcs,
            consensus_rpcs,
            checkpoint_override: Some(B256::from_str(BUILTIN_CHECKPOINT).unwrap()),
            auto_checkpoint: B256::from_str(BUILTIN_CHECKPOINT).unwrap(),
            indexer_provider: IndexerProvider::Alchemy,
            etherscan_api_key: Some("ETHERSCAN_TEST_KEY".into()),
            alchemy_api_key: Some("ALCHEMY_TEST_KEY".into()),
            drpc_api_key: Some("DRPC_TEST_KEY".into()),
            blockscout_base_url: Some("https://base.blockscout.com".into()),
            blockscout_api_key: Some("BLOCKSCOUT_TEST_KEY".into()),
            ..default_state()
        };
        let serialized = serialize(&original);
        let parsed = parse(&serialized);
        assert_eq!(parsed.theme, original.theme);
        for chain in Chain::ALL {
            assert_eq!(parsed.rpcs.get(chain), original.rpcs.get(chain));
            assert_eq!(
                parsed.consensus_rpcs.get(chain),
                original.consensus_rpcs.get(chain)
            );
        }
        assert_eq!(parsed.checkpoint_override, original.checkpoint_override);
        assert_eq!(parsed.indexer_provider, original.indexer_provider);
        assert_eq!(parsed.etherscan_api_key, original.etherscan_api_key);
        assert_eq!(parsed.alchemy_api_key, original.alchemy_api_key);
        assert_eq!(parsed.drpc_api_key, original.drpc_api_key);
        assert_eq!(parsed.blockscout_base_url, original.blockscout_base_url);
        assert_eq!(parsed.blockscout_api_key, original.blockscout_api_key);
        // auto_checkpoint isn't persisted; parsed value reverts to the default.
        assert_eq!(parsed.auto_checkpoint, default_state().auto_checkpoint);
    }

    #[test]
    fn serialize_omits_empty_l2_lists() {
        // A stock state (no L2 configured) must not emit `rpcs_base = []` /
        // `rpcs_optimism = []` lines into the file — those keys imply the
        // user opted into L2 when they didn't.
        let state = default_state();
        let text = serialize(&state);
        assert!(!text.contains("rpcs_base"));
        assert!(!text.contains("rpcs_optimism"));
        assert!(!text.contains("consensus_rpcs_base"));
        assert!(!text.contains("consensus_rpcs_optimism"));
    }

    #[test]
    fn is_https_url_accepts_https_only() {
        assert!(is_https_url("https://example.com"));
        assert!(is_https_url("https://eth.llamarpc.com"));
        assert!(!is_https_url("http://example.com"));
        assert!(!is_https_url("ftp://example.com"));
        assert!(!is_https_url(""));
        assert!(!is_https_url("not a url"));
    }

    #[test]
    fn valid_proxy_address_accepts_host_port_forms() {
        assert!(valid_proxy_address("127.0.0.1:9050")); // Tor default
        assert!(valid_proxy_address("127.0.0.1:1080"));
        assert!(valid_proxy_address("proxy.example.com:1080")); // hostname
        assert!(valid_proxy_address("[::1]:9050")); // bracketed IPv6
        assert!(valid_proxy_address("  127.0.0.1:9050  ")); // trimmed
    }

    #[test]
    fn valid_proxy_address_rejects_fail_open_inputs() {
        // The security-critical cases: authority-illegal values that reqwest
        // would silently ignore (→ direct connection / IP leak) rather than
        // proxy. These MUST be rejected at input time.
        assert!(!valid_proxy_address("127.0.0.1:90 50")); // inner space
        assert!(!valid_proxy_address("тор:9050")); // non-ASCII host
        assert!(!valid_proxy_address("proxy host:1080")); // inner space in host
    }

    #[test]
    fn valid_proxy_address_rejects_malformed_host_port() {
        assert!(!valid_proxy_address("")); // empty
        assert!(!valid_proxy_address("127.0.0.1")); // no port
        assert!(!valid_proxy_address("127.0.0.1:")); // empty port
        assert!(!valid_proxy_address("127.0.0.1:abc")); // non-numeric port
        assert!(!valid_proxy_address("127.0.0.1:99999")); // out-of-range port
        assert!(!valid_proxy_address("127.0.0.1:9050/path")); // trailing path
        assert!(!valid_proxy_address("socks5://127.0.0.1:9050")); // includes scheme
    }

    #[test]
    fn nonempty_passes_through_or_returns_none() {
        assert!(nonempty(&[]).is_none());
        assert_eq!(nonempty(&["a".to_string()]), Some(vec!["a".to_string()]));
    }

    #[test]
    fn indexer_provider_key_round_trip() {
        for p in [
            IndexerProvider::Blockscout,
            IndexerProvider::Etherscan,
            IndexerProvider::Alchemy,
            IndexerProvider::Drpc,
            IndexerProvider::Kao,
            IndexerProvider::None,
        ] {
            assert_eq!(IndexerProvider::from_key(p.key()), Some(p));
        }
        assert!(IndexerProvider::from_key("bogus").is_none());
        assert!(IndexerProvider::from_key("").is_none());
    }

    #[test]
    fn parse_indexer_provider_round_trip_through_serialize() {
        for p in [
            IndexerProvider::Blockscout,
            IndexerProvider::Etherscan,
            IndexerProvider::Alchemy,
            IndexerProvider::Drpc,
            IndexerProvider::Kao,
            IndexerProvider::None,
        ] {
            let mut s = default_state();
            s.indexer_provider = p;
            let parsed = parse(&serialize(&s));
            assert_eq!(parsed.indexer_provider, p);
        }
    }

    #[test]
    fn parse_drops_non_https_blockscout_base_url() {
        let s = parse("blockscout_base_url = \"http://insecure.example/\"\n");
        assert!(s.blockscout_base_url.is_none());
    }

    #[test]
    fn parse_accepts_https_blockscout_base_url() {
        let s = parse("blockscout_base_url = \"https://eth.blockscout.com\"\n");
        assert_eq!(
            s.blockscout_base_url.as_deref(),
            Some("https://eth.blockscout.com")
        );
    }

    #[test]
    fn parse_drops_empty_api_keys() {
        let s = parse(
            "etherscan_api_key = \"\"\n\
             alchemy_api_key = \"\"\n\
             drpc_api_key = \"\"\n\
             blockscout_api_key = \"\"\n",
        );
        assert!(s.etherscan_api_key.is_none());
        assert!(s.alchemy_api_key.is_none());
        assert!(s.drpc_api_key.is_none());
        assert!(s.blockscout_api_key.is_none());
    }

    #[test]
    fn parse_keeps_non_empty_api_keys() {
        let s = parse(
            "etherscan_api_key = \"key1\"\n\
             alchemy_api_key = \"key2\"\n\
             drpc_api_key = \"key3\"\n\
             blockscout_api_key = \"key4\"\n",
        );
        assert_eq!(s.etherscan_api_key.as_deref(), Some("key1"));
        assert_eq!(s.alchemy_api_key.as_deref(), Some("key2"));
        assert_eq!(s.drpc_api_key.as_deref(), Some("key3"));
        assert_eq!(s.blockscout_api_key.as_deref(), Some("key4"));
    }

    #[test]
    fn parse_unknown_indexer_provider_keeps_default() {
        let s = parse("indexer_provider = \"unknown_provider\"\n");
        assert_eq!(s.indexer_provider, default_state().indexer_provider);
    }

    #[test]
    fn parse_then_serialize_preserves_checkpoint_override() {
        let cp = B256::from_str(BUILTIN_CHECKPOINT).unwrap();
        let mut s = default_state();
        s.checkpoint_override = Some(cp);
        let parsed = parse(&serialize(&s));
        assert_eq!(parsed.checkpoint_override, Some(cp));
    }

    #[test]
    fn apply_rpc_list_filters_non_https() {
        let mut target = PerChain::<Vec<String>>::default();
        target.set(Chain::Mainnet, vec!["https://existing".into()]);
        apply_rpc_list(
            &mut target,
            Chain::Mainnet,
            Some(vec![
                "http://insecure".into(),
                "https://kept".into(),
                "ftp://nope".into(),
            ]),
        );
        // Only the https URL survives; existing list is replaced because the
        // filtered new list is non-empty.
        assert_eq!(
            target.get(Chain::Mainnet),
            &vec!["https://kept".to_string()]
        );
    }

    #[test]
    fn apply_rpc_list_leaves_target_when_all_filtered_out() {
        let mut target = PerChain::<Vec<String>>::default();
        target.set(Chain::Mainnet, vec!["https://existing".into()]);
        apply_rpc_list(
            &mut target,
            Chain::Mainnet,
            Some(vec!["http://nope".into()]),
        );
        // Existing entry preserved.
        assert_eq!(
            target.get(Chain::Mainnet),
            &vec!["https://existing".to_string()]
        );
    }

    #[test]
    fn apply_rpc_list_none_is_noop() {
        let mut target = PerChain::<Vec<String>>::default();
        target.set(Chain::Mainnet, vec!["https://existing".into()]);
        apply_rpc_list(&mut target, Chain::Mainnet, None);
        assert_eq!(
            target.get(Chain::Mainnet),
            &vec!["https://existing".to_string()]
        );
    }

    #[cfg(unix)]
    #[test]
    fn restrict_to_owner_sets_mode() {
        use std::os::unix::fs::PermissionsExt;
        let f = tempfile::NamedTempFile::new().unwrap();
        restrict_to_owner(f.path(), 0o600).unwrap();
        let meta = std::fs::metadata(f.path()).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_creates_owner_only_file_with_contents() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.toml");

        atomic_write_owner_only(&path, b"key = \"secret\"\n").unwrap();

        // The secret landed...
        assert_eq!(std::fs::read(&path).unwrap(), b"key = \"secret\"\n");
        // ...with owner-only perms from the moment it existed (no 0o644 window),
        // and the temp file was renamed away, not left behind.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got 0o{mode:o}");
        assert!(!dir.path().join(".settings.toml.tmp").exists());

        // A second write atomically replaces the file and keeps the perms.
        atomic_write_owner_only(&path, b"key = \"rotated\"\n").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"key = \"rotated\"\n");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_recovers_from_a_leftover_temp_file() {
        // A crash between create and rename can strand the temp file. `create_new`
        // would otherwise refuse to reopen it; the unlink-and-retry path must
        // recover so a single past crash doesn't wedge every future save.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.toml");
        let tmp = dir.path().join(".settings.toml.tmp");
        std::fs::write(&tmp, b"stale garbage").unwrap();

        atomic_write_owner_only(&path, b"key = \"fresh\"\n").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"key = \"fresh\"\n");
        assert!(
            !tmp.exists(),
            "leftover temp should be cleared, not left behind"
        );
    }

    #[test]
    fn default_rpc_lists_are_non_empty_https() {
        let rpcs = default_rpcs();
        assert!(!rpcs.is_empty());
        for u in rpcs {
            assert!(u.starts_with("https://"), "default rpc must be https: {u}");
        }
        let cl = default_consensus_rpcs();
        assert!(!cl.is_empty());
        for u in cl {
            assert!(
                u.starts_with("https://"),
                "default consensus rpc must be https: {u}"
            );
        }
    }

    /// Read-only getters: each just reflects `default_state` when no
    /// setter has run. Exercising them bumps coverage for the
    /// `ensure().lock().clone()` plumbing and confirms the defaults
    /// haven't drifted from what `default_state` builds. None of these
    /// call `write_all`, so they don't touch the user's real config.
    #[test]
    fn read_only_getters_reflect_default_state() {
        // These tests share global state with other tests; only assert
        // properties that are invariant under any prior setter (since
        // tests don't call setters, defaults always hold).
        let _ = theme();
        assert_eq!(indexer_provider(), default_state().indexer_provider);
        // Per-chain rpcs default to the Mainnet list.
        assert_eq!(
            rpcs(Chain::Mainnet),
            default_state().rpcs.get(Chain::Mainnet).clone()
        );
        // Consensus rpcs for Mainnet match the seeded default.
        assert_eq!(
            consensus_rpcs(Chain::Mainnet),
            default_state().consensus_rpcs.get(Chain::Mainnet).clone(),
        );
        // L2 consensus falls back to the chain's hardcoded default url.
        assert_eq!(
            consensus_rpcs(Chain::Base),
            vec![Chain::Base.default_consensus_url().to_string()],
        );
        assert_eq!(
            consensus_rpcs(Chain::Optimism),
            vec![Chain::Optimism.default_consensus_url().to_string()],
        );
        // auto_checkpoint starts at the built-in constant.
        assert_eq!(
            auto_checkpoint(),
            B256::from_str(BUILTIN_CHECKPOINT).unwrap()
        );
        // checkpoint_override starts as None.
        assert!(checkpoint_override().is_none());
    }

    #[test]
    fn rpcs_l2_falls_back_to_synthesize_when_no_explicit() {
        // No explicit L2 rpc, no drpc/alchemy key, → empty.
        // (synthesize_exec_url returns None when both keys are unset.)
        let bas = rpcs(Chain::Base);
        // Either empty (no key) OR a synthesized url — both branches
        // valid; assert the shape.
        if !bas.is_empty() {
            for url in &bas {
                assert!(url.starts_with("https://"), "got: {url}");
            }
        }
    }

    #[test]
    fn serialize_emits_valid_toml_arrays() {
        let mut rpcs = PerChain::<Vec<String>>::default();
        rpcs.set(Chain::Mainnet, vec!["https://a".into(), "https://b".into()]);
        let mut consensus_rpcs = PerChain::<Vec<String>>::default();
        consensus_rpcs.set(
            Chain::Mainnet,
            vec!["https://c".into(), "https://d".into(), "https://e".into()],
        );
        let state = State {
            rpcs,
            consensus_rpcs,
            checkpoint_override: None,
            indexer_provider: IndexerProvider::Blockscout,
            ..default_state()
        };
        let text = serialize(&state);
        let reparsed: OnDisk = toml::from_str(&text).expect("output must be valid toml");
        assert_eq!(
            reparsed.rpcs.as_deref(),
            Some(["https://a".to_string(), "https://b".to_string()].as_slice())
        );
        assert_eq!(
            reparsed.consensus_rpcs.as_deref(),
            Some(
                [
                    "https://c".to_string(),
                    "https://d".to_string(),
                    "https://e".to_string()
                ]
                .as_slice()
            ),
        );
        // Unset overrides are dropped from the output rather than emitted as "".
        assert!(reparsed.checkpoint_override.is_none());
    }

    // ── New wizard-level enum round-trip tests ──────────────────────

    #[test]
    fn rpc_provider_key_round_trip() {
        for p in [
            RpcProvider::Kao,
            RpcProvider::OneRpc,
            RpcProvider::Drpc,
            RpcProvider::Alchemy,
            RpcProvider::Custom,
        ] {
            assert_eq!(RpcProvider::from_key(p.key()), Some(p));
        }
        assert!(RpcProvider::from_key("bogus").is_none());
    }

    #[test]
    fn api_provider_key_round_trip() {
        for p in [
            ApiProvider::Kao,
            ApiProvider::Blockscout,
            ApiProvider::Drpc,
            ApiProvider::None,
        ] {
            assert_eq!(ApiProvider::from_key(p.key()), Some(p));
        }
        assert!(ApiProvider::from_key("bogus").is_none());
    }

    #[test]
    fn safe_tx_service_key_round_trip() {
        for p in [SafeTxService::Default, SafeTxService::Custom] {
            assert_eq!(SafeTxService::from_key(p.key()), Some(p));
        }
        assert!(SafeTxService::from_key("bogus").is_none());
    }

    #[test]
    fn proxy_type_key_round_trip() {
        for p in [ProxyType::Tor, ProxyType::Socks] {
            assert_eq!(ProxyType::from_key(p.key()), Some(p));
        }
        assert!(ProxyType::from_key("bogus").is_none());
    }

    #[test]
    fn parse_rpc_input_accepts_bare_ip() {
        assert_eq!(
            parse_rpc_input("192.168.1.5"),
            Some("http://192.168.1.5".into())
        );
    }

    #[test]
    fn parse_rpc_input_accepts_ip_with_port_and_path() {
        assert_eq!(
            parse_rpc_input("192.168.1.5:8545/rpc"),
            Some("http://192.168.1.5:8545/rpc".into())
        );
    }

    #[test]
    fn parse_rpc_input_accepts_bare_hostname() {
        assert_eq!(
            parse_rpc_input("my-node.example"),
            Some("https://my-node.example".into())
        );
    }

    #[test]
    fn parse_rpc_input_rejects_empty_and_invalid() {
        assert_eq!(parse_rpc_input(""), None);
        assert_eq!(parse_rpc_input("   "), None);
        assert_eq!(parse_rpc_input("my-node.example:abc"), None);
        assert_eq!(parse_rpc_input("--bad-label.example"), None);
    }

    #[test]
    fn parse_rpc_input_rejects_single_label_hosts() {
        assert_eq!(parse_rpc_input("https://d"), None);
        assert_eq!(parse_rpc_input("d"), None);
        assert_eq!(parse_rpc_input("asdf"), None);
    }

    #[test]
    fn parse_rpc_input_accepts_localhost_as_http() {
        assert_eq!(
            parse_rpc_input("localhost"),
            Some("http://localhost".into())
        );
        assert_eq!(
            parse_rpc_input("localhost:8545"),
            Some("http://localhost:8545".into())
        );
    }

    #[test]
    fn parse_rpc_input_rejects_http_url() {
        assert_eq!(parse_rpc_input("http://my-node.example"), None);
    }

    #[test]
    fn parse_kao_server_input_wraps_bare_localhost_as_http() {
        // The reported case: a self-hosted server typed without a scheme.
        assert_eq!(
            parse_kao_server_input("localhost:8080"),
            Some("http://localhost:8080".into())
        );
        assert_eq!(
            parse_kao_server_input("127.0.0.1:8080"),
            Some("http://127.0.0.1:8080".into())
        );
    }

    #[test]
    fn parse_kao_server_input_keeps_explicit_loopback_http() {
        // Must round-trip: this is what we store after wrapping bare input, so
        // it has to survive re-parsing on the next load.
        for url in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            assert_eq!(parse_kao_server_input(url), Some(url.into()), "{url}");
        }
    }

    #[test]
    fn parse_kao_server_input_keeps_https_anywhere() {
        assert_eq!(
            parse_kao_server_input(DEFAULT_KAO_SERVER_URL),
            Some(DEFAULT_KAO_SERVER_URL.into())
        );
        assert_eq!(
            parse_kao_server_input("my-node.example"),
            Some("https://my-node.example".into())
        );
    }

    #[test]
    fn parse_kao_server_input_rejects_public_http_and_junk() {
        // Plain http to a public host would let traffic be MITM'd.
        assert_eq!(parse_kao_server_input("http://my-node.example"), None);
        assert_eq!(parse_kao_server_input("http://1.2.3.4:8080"), None);
        // Single-label / malformed hosts and non-web schemes.
        assert_eq!(parse_kao_server_input("ws://localhost:8080"), None);
        assert_eq!(parse_kao_server_input("asdf"), None);
        assert_eq!(parse_kao_server_input(""), None);
        assert_eq!(parse_kao_server_input("   "), None);
    }

    /// A bare public IP (no scheme) must NOT be wrapped as plaintext http — the
    /// explicit-scheme path already rejects the byte-identical
    /// `http://1.2.3.4:8080`, so the scheme-omitted form must be forced to
    /// https rather than silently downgraded (finding #17). Loopback IPs still
    /// wrap as http since that traffic never leaves the machine.
    #[test]
    fn parse_kao_server_input_forces_bare_public_ip_to_https() {
        assert_eq!(
            parse_kao_server_input("1.2.3.4:8080"),
            Some("https://1.2.3.4:8080".into()),
            "bare public IP must be forced to https, not plaintext http",
        );
        assert_eq!(
            parse_kao_server_input("203.0.113.7"),
            Some("https://203.0.113.7".into()),
        );
        // Loopback IPs remain plain http — that hop never leaves the machine.
        assert_eq!(
            parse_kao_server_input("127.0.0.1:8080"),
            Some("http://127.0.0.1:8080".into()),
        );
        assert_eq!(
            parse_kao_server_input("[::1]:8080"),
            Some("http://[::1]:8080".into()),
        );
    }

    #[test]
    fn extract_alchemy_key_from_v2_url() {
        assert_eq!(
            extract_alchemy_key("https://eth-mainnet.g.alchemy.com/v2/abc123"),
            Some("abc123".to_string()),
        );
    }

    #[test]
    fn extract_alchemy_key_rejects_other_hosts() {
        assert_eq!(extract_alchemy_key("https://eth.llamarpc.com"), None);
        assert_eq!(extract_alchemy_key("not-a-url"), None);
    }

    #[test]
    fn extract_drpc_key_from_rpc_url() {
        assert_eq!(
            extract_drpc_key("https://lb.drpc.live/ethereum/abc123"),
            Some("abc123".to_string()),
        );
    }

    #[test]
    fn extract_drpc_key_rejects_other_hosts() {
        assert_eq!(extract_drpc_key("https://eth.drpc.org/"), None);
        assert_eq!(extract_drpc_key("not-a-url"), None);
    }

    #[test]
    fn alchemy_exec_urls_generates_all_chains() {
        let urls = alchemy_exec_urls("testkey");
        assert!(urls.get(Chain::Mainnet).contains("eth-mainnet"));
        assert!(urls.get(Chain::Base).contains("base-mainnet"));
        assert!(urls.get(Chain::Optimism).contains("opt-mainnet"));
    }

    #[test]
    fn drpc_exec_urls_generates_all_chains() {
        let urls = drpc_exec_urls("testkey");
        assert!(urls.get(Chain::Mainnet).contains("ethereum"));
        assert!(urls.get(Chain::Base).contains("base"));
        assert!(urls.get(Chain::Optimism).contains("optimism"));
    }

    #[test]
    fn backwards_compat_infers_alchemy_provider() {
        let s = parse("alchemy_api_key = \"testkey\"\n");
        assert_eq!(s.rpc_provider, RpcProvider::Alchemy);
    }

    #[test]
    fn backwards_compat_infers_drpc_provider() {
        let s = parse("drpc_api_key = \"testkey\"\n");
        assert_eq!(s.rpc_provider, RpcProvider::Drpc);
    }

    #[test]
    fn backwards_compat_defaults_to_kao_provider() {
        let s = parse("");
        assert_eq!(s.rpc_provider, RpcProvider::Kao);
    }

    #[test]
    fn explicit_rpc_provider_overrides_inference() {
        let s = parse("rpc_provider = \"1rpc\"\nalchemy_api_key = \"testkey\"\n");
        assert_eq!(s.rpc_provider, RpcProvider::OneRpc);
    }

    #[test]
    fn backwards_compat_infers_blockscout_api_provider() {
        let s = parse("indexer_provider = \"blockscout\"\n");
        assert_eq!(s.api_provider, ApiProvider::Blockscout);
    }

    #[test]
    fn backwards_compat_infers_drpc_api_provider() {
        let s = parse("indexer_provider = \"drpc\"\ndrpc_api_key = \"testkey\"\n");
        assert_eq!(s.api_provider, ApiProvider::Drpc);
        assert_eq!(s.api_key.as_deref(), Some("testkey"));
    }
}
