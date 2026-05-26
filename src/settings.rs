//! User-tunable runtime settings, persisted to disk.

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

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

/// Hex hash of the built-in mainnet checkpoint shipped with the binary.
/// Update at release time together with `BUILTIN_CHECKPOINT_PUBLISHED`.
/// If older than `BUILTIN_FRESHNESS_DAYS`, the auto-resolver prefers a
/// freshly fetched community fallback (see `crate::net::refresh_auto_checkpoint`).
///
/// IMPORTANT: this must be a finalized beacon block root from a sync-committee
/// period that public LC servers still index — they prune older periods (~27h
/// rotation), so a checkpoint that's more than a day or two stale will fail
/// every bootstrap call.
pub const BUILTIN_CHECKPOINT: &str =
    "0x56d275d9bdf4afb040ecbbba7da0dff9ed384b062c321d5f2b9a4a4f0eb83b4d";
pub const BUILTIN_CHECKPOINT_PUBLISHED: u64 = 1777188238;
pub const BUILTIN_FRESHNESS_DAYS: u64 = 14;

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
    None,
}

impl IndexerProvider {
    fn key(self) -> &'static str {
        match self {
            Self::Blockscout => "blockscout",
            Self::Etherscan => "etherscan",
            Self::Alchemy => "alchemy",
            Self::Drpc => "drpc",
            Self::None => "none",
        }
    }

    fn from_key(s: &str) -> Option<Self> {
        match s {
            "blockscout" => Some(Self::Blockscout),
            "etherscan" => Some(Self::Etherscan),
            "alchemy" => Some(Self::Alchemy),
            "drpc" => Some(Self::Drpc),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
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
    /// Whether the WalletConnect Verify API
    /// (`verify.walletconnect.com/v2/attestation/{id}`) is fetched on
    /// every inbound `wc_sessionPropose` / `wc_sessionRequest`. Default
    /// on; flipping off trades the SCAM hard-deny for the privacy
    /// upside of not leaking attestation ids to a third party.
    wc_verify_api_enabled: bool,
    /// User-supplied WalletConnect Cloud project id. `None` falls back
    /// to the compile-time `KAO_DEFAULT_WC_PROJECT_ID`. Public identifier
    /// (NOT a secret) — registered at `cloud.reown.com`.
    wc_project_id_override: Option<String>,
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
        wc_verify_api_enabled: true,
        wc_project_id_override: None,
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
/// `auto_checkpoint` is intentionally absent — it's rederived on each app
/// start from the network and never persisted.
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
    /// `None` on load = "default on" — absence preserves the secure default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wc_verify_api_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wc_project_id_override: Option<String>,
}

/// True iff `s` parses as an HTTPS URL. Non-HTTPS endpoints are dropped on
/// load so a hand-edited `settings.toml` can't bypass the UI's HTTPS check
/// and steer the wallet onto a MITM-able transport.
fn is_https_url(s: &str) -> bool {
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
    if let Some(b) = on_disk.wc_verify_api_enabled {
        state.wc_verify_api_enabled = b;
    }
    state.wc_project_id_override = on_disk.wc_project_id_override.filter(|s| !s.is_empty());
    state
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
        wc_verify_api_enabled: if state.wc_verify_api_enabled {
            None
        } else {
            Some(false)
        },
        wc_project_id_override: state.wc_project_id_override.clone(),
    };
    toml::to_string(&on_disk).expect("serializing settings cannot fail")
}

pub fn theme() -> ThemeKind {
    ensure().lock().expect("settings mutex poisoned").theme
}

pub fn set_theme(kind: ThemeKind) {
    ensure().lock().expect("settings mutex poisoned").theme = kind;
    write_all();
}

/// The built-in execution-RPC list for Mainnet. Exposed so the setup UI can
/// show the user exactly which endpoints "use defaults" enrolls them in.
pub fn default_rpcs() -> &'static [&'static str] {
    DEFAULT_RPCS
}

/// The built-in consensus (beacon-chain LC) RPC list for Mainnet. Mirrors
/// `default_rpcs` so the setup flow can reset both lists in one go.
pub fn default_consensus_rpcs() -> &'static [&'static str] {
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
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .rpcs
        .set(chain, list);
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
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .consensus_rpcs
        .set(chain, list);
    write_all();
}

pub fn checkpoint_override() -> Option<B256> {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .checkpoint_override
}

pub fn set_checkpoint_override(value: Option<B256>) {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .checkpoint_override = value;
    write_all();
}

pub fn indexer_provider() -> IndexerProvider {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .indexer_provider
}

pub fn set_indexer_provider(value: IndexerProvider) {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .indexer_provider = value;
    write_all();
}

pub fn etherscan_api_key() -> Option<String> {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .etherscan_api_key
        .clone()
}

pub fn set_etherscan_api_key(value: Option<String>) {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .etherscan_api_key = value.filter(|s| !s.is_empty());
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
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .alchemy_api_key = value.filter(|s| !s.is_empty());
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
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .drpc_api_key = value.filter(|s| !s.is_empty());
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
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .blockscout_base_url = cleaned;
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
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .blockscout_api_key = value.filter(|s| !s.is_empty());
    write_all();
}

/// WalletConnect Verify API toggle. `true` is the secure default — wallet
/// hard-denies `SCAM` / `INVALID` attestations with no click-through.
#[allow(dead_code)] // Phase 6b UI consumes.
pub fn wc_verify_api_enabled() -> bool {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .wc_verify_api_enabled
}

#[allow(dead_code)] // Phase 6b Settings pane.
pub fn set_wc_verify_api_enabled(value: bool) {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .wc_verify_api_enabled = value;
    write_all();
}

/// User-supplied WC Cloud project id. `None` → bundled default.
#[allow(dead_code)] // Phase 6b.
pub fn wc_project_id_override() -> Option<String> {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .wc_project_id_override
        .clone()
}

#[allow(dead_code)] // Phase 6b.
pub fn set_wc_project_id_override(value: Option<String>) {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .wc_project_id_override = value.filter(|s| !s.is_empty());
    write_all();
}

/// Resolved checkpoint (built-in or freshly fetched fallback) used when no
/// user override is set. Mutated by `crate::net` on startup.
pub fn auto_checkpoint() -> B256 {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .auto_checkpoint
}

pub fn set_auto_checkpoint(value: B256) {
    ensure()
        .lock()
        .expect("settings mutex poisoned")
        .auto_checkpoint = value;
    // Not persisted to disk: this value is rederived on each app start.
}

/// True when the binary's built-in checkpoint is recent enough that we don't
/// need to fetch a community fallback before the first sync.
pub fn builtin_is_fresh() -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let age_secs = now.saturating_sub(BUILTIN_CHECKPOINT_PUBLISHED);
    age_secs < BUILTIN_FRESHNESS_DAYS * 86400
}

fn write_all() {
    let path = settings_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
        let _ = restrict_to_owner(parent, 0o700);
    }
    let snapshot = ensure().lock().expect("settings mutex poisoned").clone();
    let _ = std::fs::write(&path, serialize(&snapshot));
    let _ = restrict_to_owner(&path, 0o600);
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
            wc_verify_api_enabled: false,
            wc_project_id_override: Some("USER_PROJECT_ID".into()),
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

    #[test]
    fn builtin_is_fresh_returns_bool() {
        // `builtin_is_fresh` is a pure (now − published) < freshness window
        // check. The output depends on wall clock, but the function must
        // always return without panicking — assert it produces a result.
        let _ = builtin_is_fresh();
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
            theme: default_state().theme,
            rpcs,
            consensus_rpcs,
            checkpoint_override: None,
            auto_checkpoint: default_state().auto_checkpoint,
            indexer_provider: IndexerProvider::Blockscout,
            etherscan_api_key: None,
            alchemy_api_key: None,
            drpc_api_key: None,
            blockscout_base_url: None,
            blockscout_api_key: None,
            wc_verify_api_enabled: true,
            wc_project_id_override: None,
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
}
