//! Read-only inspection of Gnosis Safe contracts via the `BalanceFetcher`
//! abstraction in [`crate::net`].
//!
//! ## Trust hierarchy
//!
//! For every onboarded Safe we make a binary trust call on the contract
//! behind the proxy:
//!
//! 1. **Canonical** — proxy storage slot 0 holds the address of a Safe
//!    singleton we've audited (entries in `KNOWN_SINGLETONS`). The future
//!    Safe-TX flow will enable signing only on this branch.
//! 2. **UnrecognizedImpl** — singleton is unknown to us but `VERSION()`
//!    returns a string matching the recognized-shape allowlist
//!    (`1.[0-4].\d+`) and the core view methods (`getOwners`,
//!    `getThreshold`) succeed. Surfaced with a visible warning badge;
//!    no signing in v1.
//! 3. **NotASafe / NotDeployed** — rejected outright.
//!
//! The `VERSION()` string is spoofable — anyone can deploy a contract
//! that returns `"1.4.1"` — so the singleton check is the actual trust
//! anchor. The version allowlist is only a secondary gate for the
//! UnrecognizedImpl branch (to filter out contracts that pretend to be
//! Safes but expose totally unrelated ABI shapes).
//!
//! ## Layout
//!
//! - `inspect_on_chain` does the full read sequence on one chain
//!   (`get_code` → bail if empty; then in parallel:
//!   proxy-slot-0 + VERSION + owners + threshold + nonce + modules +
//!   guard-slot + fallback-handler-slot).
//! - `scan_across_chains` fans `inspect_on_chain` across `Chain::ALL`
//!   in parallel so the onboarding chain chooser can show previews.
//! - `refresh_one` re-reads the cached fields of an existing
//!   `SafeDescriptor` and reports a structured diff. The dashboard
//!   calls this on app-open; the future Safe-TX flow calls it
//!   synchronously before quoting a transaction.
//!
//! Every Safe read in this module funnels through `&dyn BalanceFetcher`
//! so tests can drive the whole path against `CallMock` instead of
//! standing up Helios.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, B256, Bytes, U256, address, b256};
use alloy::sol;
use alloy::sol_types::SolCall;

use crate::chain::Chain;
use crate::net::BalanceFetcher;
use crate::wallet::{SafeDescriptor, SafeTrust, short_address};

pub mod service;
pub mod sim;
pub mod tx;

// ── Safe ABI (read + EIP-712/exec surface) ──────────────────────────────────

sol! {
    // Read-only inspection (onboarding + refresh).
    function VERSION() external view returns (string memory);
    function getOwners() external view returns (address[] memory);
    function getThreshold() external view returns (uint256);
    function nonce() external view returns (uint256);
    function getModulesPaginated(address start, uint256 pageSize)
        external view returns (address[] memory array, address next);

    // EIP-712 / exec surface used by the Safe-TX flow (`safe::tx`).
    function domainSeparator() external view returns (bytes32);
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) external view returns (bytes32);
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures
    ) external payable returns (bool success);

    // Field order must EXACTLY match the Safe 1.3+ canonical typehash
    // — alloy derives the EIP-712 typehash from declaration order, so
    // any permutation silently produces a different signing hash.
    // Pinned by `safe::tx::tests::safe_tx_typehash_matches_spec`.
    #[derive(Debug)]
    struct SafeTx {
        address to;
        uint256 value;
        bytes data;
        uint8 operation;
        uint256 safeTxGas;
        uint256 baseGas;
        uint256 gasPrice;
        address gasToken;
        address refundReceiver;
        uint256 nonce;
    }
}

// ── Storage slot anchors ────────────────────────────────────────────────────

/// `keccak256("guard_manager.guard.address")` — the well-known storage
/// slot where Safe ≥ 1.3.0 stores the optional transaction guard. Read
/// raw via `get_storage_at` because there's no public getter on the
/// contract. The `verifies_guard_storage_slot_matches_keccak` test
/// re-derives this at test time so a typo turns into a test failure
/// rather than a silently wrong read.
const GUARD_STORAGE_SLOT: B256 =
    b256!("0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8");

/// `keccak256("fallback_manager.handler.address")` — slot for the
/// fallback handler. Same shape as `GUARD_STORAGE_SLOT`: no getter,
/// keccak-derived, verified by a test.
const FALLBACK_HANDLER_STORAGE_SLOT: B256 =
    b256!("0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5");

/// Safe's proxy stores the singleton (implementation) address at the
/// very first storage slot — not EIP-1967. This is a Safe-specific
/// quirk worth calling out, since anyone reading this expecting an
/// EIP-1967 walk will look in the wrong place.
const IMPLEMENTATION_SLOT: U256 = U256::ZERO;

/// Sentinel address that bookends Safe's module linked list. Used as
/// the `start` value when calling `getModulesPaginated` to walk from
/// the head, and as the terminator: when the function returns this as
/// `next`, the list is exhausted.
const MODULE_SENTINEL: Address = address!("0x0000000000000000000000000000000000000001");

/// Page size for the modules walk. Safes with >100 enabled modules are
/// vanishingly rare in the wild (gas alone makes them impractical), so
/// one page covers essentially every real Safe and the walk loop is a
/// safety net rather than a hot path.
const MODULES_PAGE_SIZE: u64 = 100;

/// Maximum number of `getModulesPaginated` pages we'll walk before
/// giving up. Defensive: a malicious or buggy contract could in
/// principle return a `next` that loops forever; this caps the work.
const MODULES_MAX_PAGES: usize = 16;

// ── Known canonical singletons ──────────────────────────────────────────────

/// A canonical Safe singleton entry. Sourced from
/// <https://github.com/safe-global/safe-deployments>. The same Safe
/// version typically has two singleton addresses — one "L1" variant
/// (`Safe`) and one "L2" variant (`SafeL2`) that emits extra events for
/// indexer-friendliness. Both count as canonical for the same version
/// number, so we list each one.
///
/// Lookup is by address alone (not `(chain, address)`): if a deployment
/// of canonical 1.4.1 ever showed up on a chain we don't expect, the
/// implementation address still uniquely identifies the version, and
/// the trust call is the same.
#[derive(Debug, Clone, Copy)]
struct KnownSingleton {
    address: Address,
    version: &'static str,
}

const KNOWN_SINGLETONS: &[KnownSingleton] = &[
    // ── 1.5.0 ────────────────────────────────────────────────────────
    // 1.5.0 only has a `canonical` variant per safe-deployments (no
    // EIP-155 split). Deployed on Mainnet and Base; notably NOT yet
    // deployed on Optimism at the time of writing — a Safe a user
    // pastes on OP cannot legitimately use this implementation, but
    // our classifier matches by address alone so we just label it and
    // let the per-chain `get_code` check do the deployment gating.
    KnownSingleton {
        // Safe 1.5.0 (Safe.sol) — canonical L1 singleton.
        address: address!("0xFf51A5898e281Db6DfC7855790607438dF2ca44b"),
        version: "1.5.0",
    },
    KnownSingleton {
        // SafeL2 1.5.0 (SafeL2.sol) — canonical L2 singleton.
        address: address!("0xEdd160fEBBD92E350D4D398fb636302fccd67C7e"),
        version: "1.5.0",
    },
    // ── 1.4.1 ────────────────────────────────────────────────────────
    // 1.4.1 has only `canonical` + `zksync` variants in
    // safe-deployments; no EIP-155 split. We skip zksync (out of scope
    // for the v1 chain set: Mainnet/OP/Base).
    KnownSingleton {
        // Safe 1.4.1 (Safe.sol) — `canonical`, the L1-style singleton.
        // Used on Mainnet and as the recommended L1 deployment.
        address: address!("0x41675C099F32341bf84BFc5382aF534df5C7461a"),
        version: "1.4.1",
    },
    KnownSingleton {
        // SafeL2 1.4.1 (SafeL2.sol) — `canonical`, used on every L2 we
        // support (OP and Base both reference this in networkAddresses).
        address: address!("0x29fcB43b46531BcA003ddC8FCB67FFE91900C762"),
        version: "1.4.1",
    },
    // ── 1.3.0 ────────────────────────────────────────────────────────
    // 1.3.0 has THREE deployment variants per safe-deployments:
    // `canonical`, `eip155`, and `zksync`. Both `canonical` and
    // `eip155` are listed as active on Mainnet, OP, and Base — they
    // share the same code, the difference is the chain-id-aware
    // encoding used during the deployment transaction. We must
    // recognize both, or Safes deployed via the EIP-155 path on our
    // chains will fall through to UnrecognizedImpl.
    KnownSingleton {
        // GnosisSafe 1.3.0 — `canonical` L1 singleton.
        address: address!("0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552"),
        version: "1.3.0",
    },
    KnownSingleton {
        // GnosisSafe 1.3.0 — `eip155` L1 singleton variant.
        address: address!("0x69f4D1788e39c87893C980c06EdF4b7f686e2938"),
        version: "1.3.0",
    },
    KnownSingleton {
        // GnosisSafeL2 1.3.0 — `canonical` L2 singleton.
        address: address!("0x3E5c63644E683549055b9Be8653de26E0B4CD36E"),
        version: "1.3.0",
    },
    KnownSingleton {
        // GnosisSafeL2 1.3.0 — `eip155` L2 singleton variant.
        address: address!("0xfb1bffC9d739B8D520DaF37dF666da4C687191EA"),
        version: "1.3.0",
    },
];

fn classify_implementation(impl_addr: Address) -> Option<&'static str> {
    KNOWN_SINGLETONS
        .iter()
        .find(|s| s.address == impl_addr)
        .map(|s| s.version)
}

// ── Known modules / handlers ────────────────────────────────────────────────

/// Modules and handlers Kao has explicit knowledge of. The onboarding
/// UI uses this registry to render a label next to a known address
/// instead of just a raw hex string — so a user pasting a Safe with the
/// Allowance Module enabled sees "Safe Allowance Module" rather than a
/// scary unknown hex blob.
///
/// Anything not in this list is rendered with a warning style. The
/// table starts deliberately small — only entries Kao has verified
/// against the canonical Safe deployments registry — and grows as
/// users report Safes in the wild.
const KNOWN_MODULES: &[(Address, &str)] = &[
    // Safe Allowance Module v0.1.0 — deployed on Mainnet and Base (per
    // safe-modules-deployments). Notably NOT deployed on Optimism, so
    // a Safe on OP that lists this address as a module is suspect.
    // https://github.com/safe-global/safe-modules-deployments
    (
        address!("0xCFbFaC74C26F8647cBDb8c5caf80BB5b32E43134"),
        "Safe Allowance Module 0.1.0",
    ),
    // CompatibilityFallbackHandler is the standard fallback handler
    // shipped with each Safe release. Listed here so the classifier
    // returns a label uniformly for guard / fallback-handler reads
    // alongside module reads. 1.5.0 and 1.4.1 ship one variant each;
    // 1.3.0 shipped `canonical` and `eip155` like the singleton.
    (
        address!("0x3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4"),
        "Safe CompatibilityFallbackHandler 1.5.0",
    ),
    (
        address!("0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99"),
        "Safe CompatibilityFallbackHandler 1.4.1",
    ),
    (
        address!("0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4"),
        "Safe CompatibilityFallbackHandler 1.3.0",
    ),
    (
        address!("0x017062a1dE2FE6b99BE3d9d37841FeD19F573804"),
        "Safe CompatibilityFallbackHandler 1.3.0 (EIP-155)",
    ),
];

/// Human-readable label for a known module / guard / handler address,
/// or `None` if Kao doesn't recognize it. UI surfaces `None` with the
/// warning style — modules can move funds with no owner signatures,
/// so unknown ones deserve loud treatment.
#[allow(dead_code)]
pub fn classify_module(addr: Address) -> Option<&'static str> {
    KNOWN_MODULES
        .iter()
        .find(|(a, _)| *a == addr)
        .map(|(_, label)| *label)
}

// ── Version allowlist ───────────────────────────────────────────────────────

/// Whether the given `VERSION()` string falls inside the Safe-shape
/// allowlist we accept for the UnrecognizedImpl branch.
///
/// Rule: exactly `1.[0-5].N` where N is one or more decimal digits.
/// The 1.5 cap tracks Safe's most recent shipping major as of the
/// allowlist's last review — see
/// <https://docs.safe.global/advanced/smart-account-supported-networks>.
/// When Safe publishes 1.6.x, bump the cap here AND add the new
/// singletons to `KNOWN_SINGLETONS`; the two must move together or a
/// future Safe release sneaks into UnrecognizedImpl without the
/// maintainer ever seeing the implementation address.
///
/// Pre-release suffixes (`1.6.0-beta`) and non-Safe strings the
/// contract might decide to return (`"hi there"` from a non-Safe
/// VERSION) are rejected by the digits-only patch and the exact
/// `parts.next().is_none()` tail check.
fn is_recognized_safe_version(v: &str) -> bool {
    let mut parts = v.split('.');
    let Some("1") = parts.next() else {
        return false;
    };
    let Some(minor) = parts.next() else {
        return false;
    };
    if !matches!(minor, "0" | "1" | "2" | "3" | "4" | "5") {
        return false;
    }
    let Some(patch) = parts.next() else {
        return false;
    };
    if patch.is_empty() || !patch.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    parts.next().is_none()
}

// ── Public types ────────────────────────────────────────────────────────────

/// Outcome of inspecting a single (address, chain) pair.
///
/// The four variants map 1:1 to the user-facing reasons the onboarding
/// UI shows per chain in the scan-results screen, so adding a variant
/// here means adding an explicit UI string. This is deliberate — we
/// don't want a catch-all `Other(String)` that lets failures slip into
/// the UI as ad-hoc error text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanResult {
    /// No code at this address on this chain. Could mean an EOA, the
    /// wrong chain, or an undeployed counterfactual Safe — the UI
    /// surfaces all three possibilities since we can't distinguish.
    NotDeployed,
    /// Code is present but doesn't look like a Safe — either the core
    /// view methods reverted, or `VERSION()` returned a string outside
    /// the recognized-shape allowlist and the implementation address
    /// isn't in our singleton registry either. `reason` is a short
    /// diagnostic for the UI; consumers should treat the variant as the
    /// signal, not parse the reason string.
    NotASafe { reason: String },
    /// Implementation matches a known canonical Safe singleton. Safe to
    /// signal full capability in the future Safe-TX flow.
    Canonical(SafeMetadata),
    /// Implementation isn't in the registry, but the contract behaves
    /// like a Safe (VERSION in the allowlist, owners + threshold
    /// readable). Display-only in v1; not eligible for signing until
    /// the implementation address gets audited and added to
    /// `KNOWN_SINGLETONS`.
    UnrecognizedImpl(SafeMetadata),
}

/// Everything we learn about a Safe in one inspection pass. This is the
/// raw on-chain snapshot; the onboarding UI converts it into a
/// `SafeDescriptor` with the user-supplied `name`, the chosen
/// `linked_signer_indices`, and the `sibling_chains` it detected from
/// the parallel scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeMetadata {
    pub chain_id: u64,
    pub address: Address,
    /// Address held in proxy storage slot 0 — the singleton this proxy
    /// delegates calls to. Kept separate from `version` because the
    /// trust decision keys on this address, not on the version string.
    pub implementation: Address,
    /// Raw `VERSION()` return — e.g. `"1.4.1"`. Stored unparsed so a
    /// future Safe release that returns something we don't preempt
    /// doesn't trip a parse step.
    pub version: String,
    pub threshold: u32,
    pub owners: Vec<Address>,
    pub modules: Vec<Address>,
    pub guard: Option<Address>,
    pub fallback_handler: Option<Address>,
    /// Current Safe `nonce()`. Snapshot only — immediately stale after
    /// inspection. The Safe-TX flow re-reads before quoting. Useful in
    /// the onboarding UI as a "this Safe has executed N transactions"
    /// hint to confirm the user pasted the right address.
    pub nonce: U256,
}

/// One discrete change detected by `refresh_one`. The UI iterates over
/// the diff's `changes` to decide which banners to surface (e.g. an
/// `OwnerRemoved` for an owner that's one of the user's linked signers
/// gets a loud red banner; a `ModuleAdded` for an unknown module gets a
/// security warning).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafeChange {
    OwnerAdded(Address),
    OwnerRemoved(Address),
    ThresholdChanged {
        from: u32,
        to: u32,
    },
    ModuleAdded(Address),
    ModuleRemoved(Address),
    GuardChanged {
        from: Option<Address>,
        to: Option<Address>,
    },
    FallbackHandlerChanged {
        from: Option<Address>,
        to: Option<Address>,
    },
    /// Implementation address changed buckets — e.g. an UnrecognizedImpl
    /// proxy was upgraded to a canonical singleton, or vice versa. A
    /// canonical→canonical version bump (1.3.0 → 1.4.1) also shows up
    /// here because the trust string changes implicitly via version.
    TrustChanged {
        from: SafeTrust,
        to: SafeTrust,
    },
    VersionChanged {
        from: String,
        to: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RefreshDiff {
    pub changes: Vec<SafeChange>,
}

#[allow(dead_code)]
impl RefreshDiff {
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

/// Result of `refresh_all_safes`. One entry per Safe in `wallet.safes`
/// (in the same positional order), tagged with the source index so the
/// App handler can splice each new descriptor back into its slot. The
/// per-safe `Result` lets a single unreachable RPC degrade gracefully
/// without sinking the rest of the batch.
///
/// Aliased to keep `Message::SafesRefreshed` (in `app/mod.rs`) from
/// becoming the visually-complex tuple type clippy's `type_complexity`
/// lint refuses.
#[allow(dead_code)]
pub type RefreshBatch = Vec<(usize, Result<(SafeDescriptor, RefreshDiff), String>)>;

// ── Public functions ────────────────────────────────────────────────────────

/// Inspect a single address on a single chain. Returns one of the four
/// `ScanResult` variants — never panics, never bubbles a network error
/// as anything other than `NotDeployed` or `NotASafe`, because the
/// caller's branching is the same regardless of the underlying RPC
/// reason. Diagnostic detail lives in `NotASafe::reason` for surfacing
/// in the UI.
#[allow(dead_code)]
pub async fn inspect_on_chain(net: &dyn BalanceFetcher, chain: Chain, addr: Address) -> ScanResult {
    // 1. Bail early on undeployed addresses. The rest of the reads
    //    would just return empty bytes / revert, and the
    //    NotDeployed/NotASafe distinction matters to the UI.
    //
    //    Uses `_raw` reads throughout (here and in the parallel block
    //    below) so the scan never triggers a helios-opstack build —
    //    that crate spawns a background consensus task per build that
    //    polls the L2 beacon proxy every second forever, even after
    //    its `OpStackClient` is dropped. Probing every chain at
    //    onboarding would leave a permanent log-spamming task per L2.
    //    The verified path takes over once the user broadcasts.
    let code = match net.get_code_raw(addr, chain).await {
        Ok(v) => v.value,
        Err(e) => {
            return ScanResult::NotASafe {
                reason: format!("get_code failed: {e}"),
            };
        }
    };
    if code.is_empty() {
        return ScanResult::NotDeployed;
    }

    // 2. Fan out every other read in parallel. A revert in `VERSION` or
    //    `getOwners` is the signal that this is "not a Safe" — but we
    //    need ALL the parallel reads' results regardless, because the
    //    UnrecognizedImpl branch wants `modules`/`guard`/`fallback`
    //    populated too.
    let (
        impl_addr_res,
        version_res,
        owners_res,
        threshold_res,
        nonce_res,
        modules_res,
        guard_res,
        fallback_res,
    ) = tokio::join!(
        read_implementation(net, chain, addr),
        read_version(net, chain, addr),
        read_owners(net, chain, addr),
        read_threshold(net, chain, addr),
        read_nonce(net, chain, addr),
        read_modules(net, chain, addr),
        read_guard(net, chain, addr),
        read_fallback_handler(net, chain, addr),
    );

    // 3. Owners + threshold are the load-bearing Safe-shape signals. If
    //    either reverts the address is not a Safe regardless of what
    //    VERSION returned — a fake Safe could return a plausible
    //    VERSION string but won't get owners/threshold right.
    let (owners, threshold) = match (owners_res, threshold_res) {
        (Ok(o), Ok(t)) => (o, t),
        (Err(e), _) => {
            return ScanResult::NotASafe {
                reason: format!("getOwners reverted: {e}"),
            };
        }
        (_, Err(e)) => {
            return ScanResult::NotASafe {
                reason: format!("getThreshold reverted: {e}"),
            };
        }
    };

    let version = match version_res {
        Ok(v) => v,
        Err(e) => {
            return ScanResult::NotASafe {
                reason: format!("VERSION reverted: {e}"),
            };
        }
    };

    let implementation = impl_addr_res.unwrap_or(Address::ZERO);
    let nonce = nonce_res.unwrap_or(U256::ZERO);
    let modules = modules_res.unwrap_or_default();
    let guard = guard_res.ok().flatten();
    let fallback_handler = fallback_res.ok().flatten();

    let metadata = SafeMetadata {
        chain_id: chain.chain_id(),
        address: addr,
        implementation,
        version: version.clone(),
        threshold,
        owners,
        modules,
        guard,
        fallback_handler,
        nonce,
    };

    if let Some(canonical_version) = classify_implementation(implementation) {
        // Trust anchor matches a known singleton. Use the registry's
        // version string rather than the on-chain VERSION return —
        // they should agree, but if they disagree the registry is
        // authoritative (a malicious contract could lie about VERSION
        // even if its implementation pointer is canonical… though that
        // would require having deployed an entire fake proxy with a
        // legitimate singleton pointer, which is so weird that the
        // disagreement deserves a future audit hook).
        let mut md = metadata;
        md.version = canonical_version.to_string();
        ScanResult::Canonical(md)
    } else if is_recognized_safe_version(&version) {
        ScanResult::UnrecognizedImpl(metadata)
    } else {
        ScanResult::NotASafe {
            reason: format!(
                "unrecognized singleton {implementation:?} and VERSION {version:?} outside allowlist",
            ),
        }
    }
}

/// Inspect `addr` on every chain in `Chain::ALL` in parallel. Order of
/// results matches `Chain::ALL` so callers can do positional indexing.
#[allow(dead_code)]
pub async fn scan_across_chains(
    net: &dyn BalanceFetcher,
    addr: Address,
) -> Vec<(Chain, ScanResult)> {
    // Spawn each chain's inspect concurrently. `tokio::join!` would
    // require a fixed N-arity macro call; `join_all` lets us drive
    // `Chain::ALL` generically and stays correct if `Chain::ALL` ever
    // grows.
    let futures = Chain::ALL.iter().map(|chain| {
        let chain = *chain;
        async move { (chain, inspect_on_chain(net, chain, addr).await) }
    });
    futures::future::join_all(futures).await
}

/// Re-inspect an existing Safe and return the updated descriptor plus
/// a diff of what changed.
///
/// On Ok the caller should overwrite their cached descriptor with the
/// returned one and use the diff to decide which UI banners to raise.
/// On Err the cached descriptor is unchanged — the address was
/// unreadable, undeployed, or no longer looks like a Safe at all
/// (e.g. self-destructed). The dashboard surfaces this as a
/// "Safe unreachable" banner rather than silently dropping the entry.
#[allow(dead_code)]
pub async fn refresh_one(
    net: &dyn BalanceFetcher,
    existing: &SafeDescriptor,
) -> Result<(SafeDescriptor, RefreshDiff), String> {
    let chain = chain_from_id(existing.chain_id)
        .ok_or_else(|| format!("unsupported chain_id {}", existing.chain_id))?;
    let result = inspect_on_chain(net, chain, existing.address()).await;
    let (metadata, new_trust) = match result {
        ScanResult::Canonical(md) => (md, SafeTrust::Canonical),
        ScanResult::UnrecognizedImpl(md) => (md, SafeTrust::UnrecognizedImpl),
        ScanResult::NotDeployed => {
            return Err(format!(
                "Safe at {:?} on {} is no longer deployed",
                existing.address(),
                chain.label(),
            ));
        }
        ScanResult::NotASafe { reason } => {
            return Err(format!(
                "Safe at {:?} on {} no longer looks like a Safe: {reason}",
                existing.address(),
                chain.label(),
            ));
        }
    };

    let diff = compute_diff(existing, &metadata, new_trust.clone());
    let now = unix_seconds();
    let new_desc = SafeDescriptor {
        name: existing.name.clone(),
        chain_id: existing.chain_id,
        address: existing.address,
        version: metadata.version,
        trust: new_trust,
        threshold: metadata.threshold,
        owners: metadata.owners.iter().map(|a| (*a).into()).collect(),
        modules: metadata.modules.iter().map(|a| (*a).into()).collect(),
        guard: metadata.guard.map(|a| a.into()),
        fallback_handler: metadata.fallback_handler.map(|a| a.into()),
        linked_signer_indices: existing.linked_signer_indices.clone(),
        sibling_chains: existing.sibling_chains.clone(),
        cached_at: now,
        // User configuration, not on-chain state — survives refresh.
        tx_service_url: existing.tx_service_url.clone(),
    };
    Ok((new_desc, diff))
}

/// Fan `refresh_one` across every Safe in `safes` in parallel. Returns
/// one entry per input safe, paired with its position so the caller can
/// splice the result back into `wallet.safes[idx]` without losing
/// ordering. Errors are per-safe — a single unreachable RPC for one
/// Safe doesn't sink the whole batch.
///
/// Spawned by the App after unlock so the dashboard renders against
/// freshly-verified owner sets / modules / guards. Wallet is saved
/// once at the App layer after the batch completes (if any diff was
/// non-empty), which keeps the save path off the per-Safe hot loop.
#[allow(dead_code)]
pub async fn refresh_all_safes(
    net: Arc<dyn BalanceFetcher>,
    safes: Vec<SafeDescriptor>,
) -> RefreshBatch {
    let futures = safes.into_iter().enumerate().map(|(idx, desc)| {
        let net = net.clone();
        async move { (idx, refresh_one(net.as_ref(), &desc).await) }
    });
    futures::future::join_all(futures).await
}

/// Summarize a `RefreshDiff` into the short human-readable messages
/// the UI should surface as a banner / toast. Returns an empty vec
/// when nothing in the diff is worth interrupting the user with.
///
/// What counts as "worth interrupting":
/// - **Owner removed that is one of the user's linked signers** — the
///   user just learned their key no longer counts toward a quorum.
///   Owners removed that the user *doesn't* hold are silent (someone
///   else's governance, not their problem to react to).
/// - **Threshold changed** — security parameter of the multisig
///   moved; deserves explicit confirmation.
/// - **Unknown module added** — modules can move funds without owner
///   signatures, so an unrecognized one is a standing backdoor. Modules
///   matching `classify_module` are silent (recognized = safe enough
///   not to interrupt — the user has accepted them by prior on-chain
///   action).
/// - **Trust demoted Canonical → UnrecognizedImpl** — implies the
///   proxy was upgraded to an unaudited singleton, which pulls the
///   trust anchor out from under the user.
///
/// Silent diffs (still persisted but no banner): owner added that
/// isn't ours, recognized module added, module removed, guard /
/// fallback changes, version bumps within Canonical, threshold drop
/// that's also a Trust transition (already covered by the trust line),
/// trust *promotion* UnrecognizedImpl → Canonical (good news, no
/// interruption needed).
///
/// `linked_signer_addresses` is the set of addresses corresponding to
/// `SafeDescriptor.linked_signer_indices` — resolved by the caller
/// because the safe module has no view of the wallet's `accounts`.
#[allow(dead_code)]
pub fn summarize_user_facing_changes(
    diff: &RefreshDiff,
    linked_signer_addresses: &[Address],
) -> Vec<String> {
    let mut alerts = Vec::new();
    for change in &diff.changes {
        match change {
            SafeChange::OwnerRemoved(addr) if linked_signer_addresses.contains(addr) => {
                alerts.push(format!(
                    "Your signer {} is no longer an owner",
                    short_address(*addr),
                ));
            }
            SafeChange::ThresholdChanged { from, to } => {
                alerts.push(format!("Threshold changed: {from} → {to}"));
            }
            SafeChange::ModuleAdded(addr) if classify_module(*addr).is_none() => {
                alerts.push(format!("Unknown module added: {}", short_address(*addr)));
            }
            SafeChange::TrustChanged {
                from: SafeTrust::Canonical,
                to: SafeTrust::UnrecognizedImpl,
            } => {
                alerts.push("Implementation upgraded to an unknown contract".into());
            }
            _ => {}
        }
    }
    alerts
}

// ── Internal helpers: single ABI reads ──────────────────────────────────────

async fn read_implementation(
    net: &dyn BalanceFetcher,
    chain: Chain,
    addr: Address,
) -> Result<Address, String> {
    let slot = net
        .get_storage_at_raw(addr, IMPLEMENTATION_SLOT, chain)
        .await?;
    Ok(b256_to_address(slot.value))
}

async fn read_version(
    net: &dyn BalanceFetcher,
    chain: Chain,
    addr: Address,
) -> Result<String, String> {
    let calldata = VERSIONCall {}.abi_encode();
    let ret = net.call_raw(addr, Bytes::from(calldata), chain).await?;
    // Single-return sol! decode returns the bare value, not a tuple struct.
    decode_ret::<VERSIONCall>(&ret.value)
}

/// Read just the owner set and threshold, live. A targeted two-call read for
/// the pre-signing gate: [`refresh_one`] answers the same question but pays
/// for a full `inspect_on_chain` (implementation, version, modules, guard,
/// fallback handler) to do it, which is far too much to run in front of a
/// hardware prompt.
///
/// The cached [`SafeDescriptor`] is refreshed once, at unlock. A co-owner can
/// rotate keys or raise the threshold at any point in a long session, and
/// neither the pinned nonce nor the pinned `safeTxHash` commits to the owner
/// set — so without this read, the drift is invisible until `execTransaction`
/// reverts GS020/GS026 with every device already prompted and the gas spent.
pub async fn read_owner_set(
    net: &dyn BalanceFetcher,
    chain: Chain,
    addr: Address,
) -> Result<(Vec<Address>, u32), String> {
    let owners = read_owners(net, chain, addr).await?;
    let threshold = read_threshold(net, chain, addr).await?;
    Ok((owners, threshold))
}

/// Read the installed transaction guard, live. Same rationale as
/// [`read_owner_set`]: the cached [`SafeDescriptor`] learns about guards once,
/// at unlock, and a guard installed since then is precisely the one a user
/// doesn't know to expect — while being the one that can reject the
/// transaction they are about to collect signatures for.
pub async fn read_guard_live(
    net: &dyn BalanceFetcher,
    chain: Chain,
    addr: Address,
) -> Result<Option<Address>, String> {
    read_guard(net, chain, addr).await
}

/// The storage slot [`read_guard_live`] reads, so tests elsewhere can plant a
/// guard without reaching into this module's private const.
#[cfg(test)]
pub(crate) fn guard_storage_slot() -> B256 {
    GUARD_STORAGE_SLOT
}

async fn read_owners(
    net: &dyn BalanceFetcher,
    chain: Chain,
    addr: Address,
) -> Result<Vec<Address>, String> {
    let calldata = getOwnersCall {}.abi_encode();
    let ret = net.call_raw(addr, Bytes::from(calldata), chain).await?;
    decode_ret::<getOwnersCall>(&ret.value)
}

async fn read_threshold(
    net: &dyn BalanceFetcher,
    chain: Chain,
    addr: Address,
) -> Result<u32, String> {
    let calldata = getThresholdCall {}.abi_encode();
    let ret = net.call_raw(addr, Bytes::from(calldata), chain).await?;
    let v = decode_ret::<getThresholdCall>(&ret.value)?;
    // Clamp to u32. Realistic Safes have thresholds ≤ owner count
    // which itself is ≤ a few dozen; the cast can't lose meaningful
    // information. A pathological return of u256::MAX clamps to
    // u32::MAX, which the UI renders as "threshold absurd" — still
    // better than truncating silently.
    Ok(u32::try_from(v).unwrap_or(u32::MAX))
}

async fn read_nonce(net: &dyn BalanceFetcher, chain: Chain, addr: Address) -> Result<U256, String> {
    let calldata = nonceCall {}.abi_encode();
    let ret = net.call_raw(addr, Bytes::from(calldata), chain).await?;
    decode_ret::<nonceCall>(&ret.value)
}

async fn read_guard(
    net: &dyn BalanceFetcher,
    chain: Chain,
    addr: Address,
) -> Result<Option<Address>, String> {
    let slot = net
        .get_storage_at_raw(addr, B256_to_u256(GUARD_STORAGE_SLOT), chain)
        .await?;
    Ok(non_zero_address(b256_to_address(slot.value)))
}

async fn read_fallback_handler(
    net: &dyn BalanceFetcher,
    chain: Chain,
    addr: Address,
) -> Result<Option<Address>, String> {
    let slot = net
        .get_storage_at_raw(addr, B256_to_u256(FALLBACK_HANDLER_STORAGE_SLOT), chain)
        .await?;
    Ok(non_zero_address(b256_to_address(slot.value)))
}

/// Walk `getModulesPaginated` until exhaustion. Bounded by
/// `MODULES_MAX_PAGES` so a malicious contract can't trap us in an
/// infinite loop.
async fn read_modules(
    net: &dyn BalanceFetcher,
    chain: Chain,
    addr: Address,
) -> Result<Vec<Address>, String> {
    let mut all = Vec::new();
    let mut start = MODULE_SENTINEL;
    for _ in 0..MODULES_MAX_PAGES {
        let calldata = getModulesPaginatedCall {
            start,
            pageSize: U256::from(MODULES_PAGE_SIZE),
        }
        .abi_encode();
        let ret = net.call_raw(addr, Bytes::from(calldata), chain).await?;
        let decoded = decode_ret::<getModulesPaginatedCall>(&ret.value)?;
        all.extend(decoded.array.iter().copied());
        if decoded.next == MODULE_SENTINEL || decoded.next == Address::ZERO {
            return Ok(all);
        }
        start = decoded.next;
    }
    // Hit the page cap without seeing SENTINEL — surface as a soft
    // truncation. The user still gets the first N modules; the UI can
    // add a "truncated" hint. An onboarding flow that wants to be
    // strict can treat this as an error, but the failure mode here
    // (Safe with >100 modules) is not a real Safe in practice.
    Ok(all)
}

// ── Internal helpers: small primitives ──────────────────────────────────────

fn decode_ret<C: SolCall>(bytes: &[u8]) -> Result<C::Return, String> {
    C::abi_decode_returns(bytes).map_err(|e| format!("decode: {e}"))
}

fn b256_to_address(b: B256) -> Address {
    // The low 20 bytes of a 32-byte storage word are the address; the
    // top 12 bytes should be zero for a well-formed slot. We don't
    // assert on the top bytes — a malicious contract could write
    // garbage there and we'd silently mask it, but the alternative
    // (rejecting non-zero top bytes) would make us more brittle than
    // Solidity itself, which does the same masking.
    Address::from_slice(&b.as_slice()[12..32])
}

#[allow(non_snake_case)]
fn B256_to_u256(b: B256) -> U256 {
    U256::from_be_bytes(b.0)
}

fn non_zero_address(a: Address) -> Option<Address> {
    if a == Address::ZERO { None } else { Some(a) }
}

fn chain_from_id(id: u64) -> Option<Chain> {
    Chain::ALL.iter().copied().find(|c| c.chain_id() == id)
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Diff computation ────────────────────────────────────────────────────────

fn compute_diff(prev: &SafeDescriptor, fresh: &SafeMetadata, new_trust: SafeTrust) -> RefreshDiff {
    let mut changes = Vec::new();
    let prev_owners: std::collections::BTreeSet<Address> =
        prev.owners.iter().map(|a| Address::from(*a)).collect();
    let fresh_owners: std::collections::BTreeSet<Address> = fresh.owners.iter().copied().collect();
    for added in fresh_owners.difference(&prev_owners) {
        changes.push(SafeChange::OwnerAdded(*added));
    }
    for removed in prev_owners.difference(&fresh_owners) {
        changes.push(SafeChange::OwnerRemoved(*removed));
    }

    if prev.threshold != fresh.threshold {
        changes.push(SafeChange::ThresholdChanged {
            from: prev.threshold,
            to: fresh.threshold,
        });
    }

    let prev_modules: std::collections::BTreeSet<Address> =
        prev.modules.iter().map(|a| Address::from(*a)).collect();
    let fresh_modules: std::collections::BTreeSet<Address> =
        fresh.modules.iter().copied().collect();
    for added in fresh_modules.difference(&prev_modules) {
        changes.push(SafeChange::ModuleAdded(*added));
    }
    for removed in prev_modules.difference(&fresh_modules) {
        changes.push(SafeChange::ModuleRemoved(*removed));
    }

    let prev_guard = prev.guard.map(Address::from);
    if prev_guard != fresh.guard {
        changes.push(SafeChange::GuardChanged {
            from: prev_guard,
            to: fresh.guard,
        });
    }
    let prev_fb = prev.fallback_handler.map(Address::from);
    if prev_fb != fresh.fallback_handler {
        changes.push(SafeChange::FallbackHandlerChanged {
            from: prev_fb,
            to: fresh.fallback_handler,
        });
    }

    if prev.trust != new_trust {
        changes.push(SafeChange::TrustChanged {
            from: prev.trust.clone(),
            to: new_trust,
        });
    }
    if prev.version != fresh.version {
        changes.push(SafeChange::VersionChanged {
            from: prev.version.clone(),
            to: fresh.version.clone(),
        });
    }

    RefreshDiff { changes }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CallMock;
    use alloy::primitives::keccak256;
    use alloy::sol_types::SolValue;

    // ── Storage-slot derivation: the constants must equal the keccak ──

    #[test]
    fn verifies_guard_storage_slot_matches_keccak() {
        let derived = keccak256(b"guard_manager.guard.address");
        assert_eq!(
            GUARD_STORAGE_SLOT, derived,
            "GUARD_STORAGE_SLOT constant disagrees with keccak256 of the canonical string — \
             update the constant or the string, do NOT just adjust the test",
        );
    }

    #[test]
    fn verifies_fallback_handler_storage_slot_matches_keccak() {
        let derived = keccak256(b"fallback_manager.handler.address");
        assert_eq!(
            FALLBACK_HANDLER_STORAGE_SLOT, derived,
            "FALLBACK_HANDLER_STORAGE_SLOT constant disagrees with keccak256 of the canonical string",
        );
    }

    // ── Version allowlist ────────────────────────────────────────────

    #[test]
    fn version_allowlist_accepts_known_safe_releases() {
        // Every Safe minor currently shipping (1.0–1.5 per
        // docs.safe.global) with any patch.
        for v in [
            "1.0.0", "1.1.1", "1.2.0", "1.3.0", "1.4.1", "1.5.0", "1.0.99",
        ] {
            assert!(is_recognized_safe_version(v), "{v} should be recognized");
        }
    }

    #[test]
    fn version_allowlist_rejects_unaudited_and_malformed_versions() {
        // 1.6+ minors haven't shipped yet; the allowlist is
        // intentionally narrow so a hypothetical future release doesn't
        // auto-onboard before the maintainer adds the singleton to the
        // registry AND bumps the allowlist cap together.
        assert!(!is_recognized_safe_version("1.6.0"));
        // 2.x falls outside.
        assert!(!is_recognized_safe_version("2.0.0"));
        // Pre-release suffixes are rejected — beta Safes haven't been
        // audited and the patch field stops accepting non-digits.
        assert!(!is_recognized_safe_version("1.4.0-beta"));
        // Truncated forms.
        assert!(!is_recognized_safe_version("1.4"));
        assert!(!is_recognized_safe_version("1."));
        assert!(!is_recognized_safe_version("1"));
        assert!(!is_recognized_safe_version(""));
        // Extra component.
        assert!(!is_recognized_safe_version("1.4.1.0"));
        // Whitespace shouldn't be tolerated — VERSION() returns
        // exact-form strings on real Safes.
        assert!(!is_recognized_safe_version(" 1.4.1"));
        // Random non-Safe strings that VERSION() could plausibly return.
        assert!(!is_recognized_safe_version("hello"));
        assert!(!is_recognized_safe_version("v1.4.1"));
    }

    // ── Singleton classification ─────────────────────────────────────

    #[test]
    fn classifies_known_canonical_singletons() {
        // Every (variant, layer) combination we ship must classify with
        // the right version string. Sourced from safe-deployments —
        // a divergence here means we either dropped a legitimate
        // variant from the registry or added one with a wrong address.

        // 1.5.0 — canonical L1 + canonical L2 (no eip155 split).
        // Deployed on Mainnet and Base; not on Optimism at registry time.
        assert_eq!(
            classify_implementation(address!("0xFf51A5898e281Db6DfC7855790607438dF2ca44b")),
            Some("1.5.0"),
        );
        assert_eq!(
            classify_implementation(address!("0xEdd160fEBBD92E350D4D398fb636302fccd67C7e")),
            Some("1.5.0"),
        );

        // 1.4.1 — canonical L1 + canonical L2 (no eip155 variants).
        assert_eq!(
            classify_implementation(address!("0x41675C099F32341bf84BFc5382aF534df5C7461a")),
            Some("1.4.1"),
        );
        assert_eq!(
            classify_implementation(address!("0x29fcB43b46531BcA003ddC8FCB67FFE91900C762")),
            Some("1.4.1"),
        );

        // 1.3.0 — canonical L1.
        assert_eq!(
            classify_implementation(address!("0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552")),
            Some("1.3.0"),
        );
        // 1.3.0 — EIP-155 L1. Legitimate per safe-deployments; was
        // silently missing in the first cut of the registry.
        assert_eq!(
            classify_implementation(address!("0x69f4D1788e39c87893C980c06EdF4b7f686e2938")),
            Some("1.3.0"),
        );
        // 1.3.0 — canonical L2. This was MISSING from the original
        // registry (an earlier draft had only the EIP-155 L2 variant
        // labelled as "L2"); without this entry, every Safe on OP/Base
        // deployed via the canonical path falls through to
        // UnrecognizedImpl.
        assert_eq!(
            classify_implementation(address!("0x3E5c63644E683549055b9Be8653de26E0B4CD36E")),
            Some("1.3.0"),
        );
        // 1.3.0 — EIP-155 L2.
        assert_eq!(
            classify_implementation(address!("0xfb1bffC9d739B8D520DaF37dF666da4C687191EA")),
            Some("1.3.0"),
        );
    }

    #[test]
    fn unknown_implementation_returns_none() {
        assert_eq!(classify_implementation(Address::ZERO), None);
        assert_eq!(
            classify_implementation(address!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")),
            None,
        );
    }

    // ── Module classification ────────────────────────────────────────

    #[test]
    fn classifies_known_allowance_module_and_fallback_handlers() {
        assert_eq!(
            classify_module(address!("0xCFbFaC74C26F8647cBDb8c5caf80BB5b32E43134")),
            Some("Safe Allowance Module 0.1.0"),
        );
        // CompatibilityFallbackHandler — every variant we ship.
        assert_eq!(
            classify_module(address!("0x3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4")),
            Some("Safe CompatibilityFallbackHandler 1.5.0"),
        );
        assert_eq!(
            classify_module(address!("0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99")),
            Some("Safe CompatibilityFallbackHandler 1.4.1"),
        );
        assert_eq!(
            classify_module(address!("0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4")),
            Some("Safe CompatibilityFallbackHandler 1.3.0"),
        );
        // The 1.3.0 EIP-155 variant of the handler was missing in the
        // first cut. Without this entry the UI would render a real
        // Safe-supplied handler with the unknown/warning style.
        assert_eq!(
            classify_module(address!("0x017062a1dE2FE6b99BE3d9d37841FeD19F573804")),
            Some("Safe CompatibilityFallbackHandler 1.3.0 (EIP-155)"),
        );
    }

    #[test]
    fn unknown_module_returns_none_so_ui_can_warn() {
        // An unknown address must classify as None so the UI renders
        // it with the warning style. Returning Some("Unknown") here
        // would silently hide the warning behind a benign-looking
        // label.
        assert_eq!(classify_module(Address::ZERO), None);
        assert_eq!(
            classify_module(address!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")),
            None,
        );
    }

    // ── ABI decode round-trip ────────────────────────────────────────
    //
    // Each `sol!`-generated *Call type has matching abi_encode / abi_decode_returns
    // helpers; here we round-trip a synthetic return through abi_decode_returns
    // to make sure the type names + field shapes our reader code uses haven't
    // drifted from what the macro generates.

    #[test]
    fn version_call_decodes_string_return() {
        let return_bytes = "1.4.1".to_string().abi_encode();
        let decoded = VERSIONCall::abi_decode_returns(&return_bytes).unwrap();
        assert_eq!(decoded, "1.4.1");
    }

    #[test]
    fn get_owners_call_decodes_address_array_return() {
        let owners = vec![
            address!("0x000000000000000000000000000000000000bEEf"),
            address!("0x000000000000000000000000000000000000dEaD"),
        ];
        let return_bytes = owners.abi_encode();
        let decoded = getOwnersCall::abi_decode_returns(&return_bytes).unwrap();
        assert_eq!(decoded, owners);
    }

    #[test]
    fn get_threshold_call_decodes_uint256_return() {
        let return_bytes = U256::from(3u64).abi_encode();
        let decoded = getThresholdCall::abi_decode_returns(&return_bytes).unwrap();
        assert_eq!(decoded, U256::from(3u64));
    }

    #[test]
    fn get_modules_paginated_call_decodes_tuple_return() {
        let modules = vec![address!("0x000000000000000000000000000000000000beEF")];
        let next = MODULE_SENTINEL;
        // Function-return decoders expect param-sequence encoding —
        // `abi_encode()` on a dynamic tuple adds an outer offset
        // wrapper that `abi_decode_returns` then over-runs trying to
        // follow. `abi_encode_params` skips that wrapper.
        let return_bytes = (modules.clone(), next).abi_encode_params();
        let decoded = getModulesPaginatedCall::abi_decode_returns(&return_bytes).unwrap();
        assert_eq!(decoded.array, modules);
        assert_eq!(decoded.next, next);
    }

    // ── End-to-end inspect_on_chain against CallMock ─────────────────

    fn safe_addr() -> Address {
        address!("0x1111111111111111111111111111111111111111")
    }

    /// Plant a fully populated, fully canonical Safe in the mock.
    /// Returns the addr for convenience.
    fn plant_canonical_safe(
        mock: &CallMock,
        owners: &[Address],
        threshold: u64,
        modules: &[Address],
        guard: Option<Address>,
        fallback: Option<Address>,
    ) -> Address {
        let addr = safe_addr();
        // Code present so get_code returns non-empty.
        mock.set_code(addr, Bytes::from_static(&[0x60, 0x60, 0x60, 0x60]), true);
        // Proxy slot 0 holds a known-canonical 1.4.1 L2 singleton.
        let impl_word = {
            let impl_addr = address!("0x29fcB43b46531BcA003ddC8FCB67FFE91900C762");
            let mut buf = [0u8; 32];
            buf[12..].copy_from_slice(impl_addr.as_slice());
            B256::from(buf)
        };
        mock.set_storage(addr, B256::ZERO, impl_word, true);
        // Guard / fallback slots: zero by default; populate if Some.
        if let Some(g) = guard {
            let mut buf = [0u8; 32];
            buf[12..].copy_from_slice(g.as_slice());
            mock.set_storage(addr, GUARD_STORAGE_SLOT, B256::from(buf), true);
        }
        if let Some(f) = fallback {
            let mut buf = [0u8; 32];
            buf[12..].copy_from_slice(f.as_slice());
            mock.set_storage(addr, FALLBACK_HANDLER_STORAGE_SLOT, B256::from(buf), true);
        }
        // VERSION returns "1.4.1".
        mock.set_call(
            addr,
            Bytes::from(VERSIONCall {}.abi_encode()),
            Bytes::from("1.4.1".to_string().abi_encode()),
            true,
        );
        // getOwners returns the list.
        mock.set_call(
            addr,
            Bytes::from(getOwnersCall {}.abi_encode()),
            Bytes::from(owners.to_vec().abi_encode()),
            true,
        );
        // getThreshold returns the value.
        mock.set_call(
            addr,
            Bytes::from(getThresholdCall {}.abi_encode()),
            Bytes::from(U256::from(threshold).abi_encode()),
            true,
        );
        // nonce returns 42 (arbitrary).
        mock.set_call(
            addr,
            Bytes::from(nonceCall {}.abi_encode()),
            Bytes::from(U256::from(42u64).abi_encode()),
            true,
        );
        // getModulesPaginated returns the list with SENTINEL terminator.
        mock.set_call(
            addr,
            Bytes::from(
                getModulesPaginatedCall {
                    start: MODULE_SENTINEL,
                    pageSize: U256::from(MODULES_PAGE_SIZE),
                }
                .abi_encode(),
            ),
            Bytes::from((modules.to_vec(), MODULE_SENTINEL).abi_encode_params()),
            true,
        );
        addr
    }

    #[tokio::test]
    async fn inspect_returns_not_deployed_when_no_code_present() {
        let mock = CallMock::new();
        // No set_code call — default is empty bytes.
        let result = inspect_on_chain(&mock, Chain::Mainnet, safe_addr()).await;
        assert!(
            matches!(result, ScanResult::NotDeployed),
            "expected NotDeployed, got {result:?}",
        );
    }

    #[tokio::test]
    async fn inspect_returns_canonical_for_known_singleton_safe() {
        let mock = CallMock::new();
        let owners = vec![
            address!("0x000000000000000000000000000000000000beef"),
            address!("0x000000000000000000000000000000000000dead"),
        ];
        let addr = plant_canonical_safe(&mock, &owners, 2, &[], None, None);
        let result = inspect_on_chain(&mock, Chain::Optimism, addr).await;
        match result {
            ScanResult::Canonical(md) => {
                assert_eq!(md.chain_id, Chain::Optimism.chain_id());
                assert_eq!(md.address, addr);
                assert_eq!(md.version, "1.4.1");
                assert_eq!(md.threshold, 2);
                assert_eq!(md.owners, owners);
                assert!(md.modules.is_empty());
                assert_eq!(md.guard, None);
                assert_eq!(md.fallback_handler, None);
                assert_eq!(md.nonce, U256::from(42u64));
            }
            other => panic!("expected Canonical, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inspect_surfaces_modules_guard_and_fallback_when_present() {
        let mock = CallMock::new();
        let owners = vec![address!("0x000000000000000000000000000000000000beef")];
        let modules = vec![
            address!("0xCFbFaC74C26F8647cBDb8c5caf80BB5b32E43134"), // Allowance Module (known)
            address!("0x000000000000000000000000000000000000abcd"), // unknown
        ];
        let guard = Some(address!("0x000000000000000000000000000000000000aaaa"));
        let fallback = Some(address!("0x000000000000000000000000000000000000bbbb"));
        let addr = plant_canonical_safe(&mock, &owners, 1, &modules, guard, fallback);
        let result = inspect_on_chain(&mock, Chain::Mainnet, addr).await;
        let md = match result {
            ScanResult::Canonical(md) => md,
            other => panic!("expected Canonical, got {other:?}"),
        };
        assert_eq!(md.modules, modules);
        assert_eq!(md.guard, guard);
        assert_eq!(md.fallback_handler, fallback);
        // Sanity: the known module classifies via the registry; the
        // unknown one doesn't. UI surfacing depends on this split.
        assert_eq!(
            classify_module(md.modules[0]),
            Some("Safe Allowance Module 0.1.0"),
        );
        assert_eq!(classify_module(md.modules[1]), None);
    }

    #[tokio::test]
    async fn inspect_returns_unrecognized_when_implementation_unknown_but_version_in_allowlist() {
        let mock = CallMock::new();
        let addr = safe_addr();
        // Code present.
        mock.set_code(addr, Bytes::from_static(&[0x60]), true);
        // Implementation address is NOT in our registry, but VERSION
        // returns "1.4.1" (allowlist) and getOwners/getThreshold succeed.
        let unknown_impl = address!("0x000000000000000000000000000000000000c0de");
        let mut impl_word = [0u8; 32];
        impl_word[12..].copy_from_slice(unknown_impl.as_slice());
        mock.set_storage(addr, B256::ZERO, B256::from(impl_word), true);

        mock.set_call(
            addr,
            Bytes::from(VERSIONCall {}.abi_encode()),
            Bytes::from("1.4.1".to_string().abi_encode()),
            true,
        );
        mock.set_call(
            addr,
            Bytes::from(getOwnersCall {}.abi_encode()),
            Bytes::from(vec![address!("0x000000000000000000000000000000000000beef")].abi_encode()),
            true,
        );
        mock.set_call(
            addr,
            Bytes::from(getThresholdCall {}.abi_encode()),
            Bytes::from(U256::from(1u64).abi_encode()),
            true,
        );
        mock.set_call(
            addr,
            Bytes::from(nonceCall {}.abi_encode()),
            Bytes::from(U256::ZERO.abi_encode()),
            true,
        );
        mock.set_call(
            addr,
            Bytes::from(
                getModulesPaginatedCall {
                    start: MODULE_SENTINEL,
                    pageSize: U256::from(MODULES_PAGE_SIZE),
                }
                .abi_encode(),
            ),
            Bytes::from((Vec::<Address>::new(), MODULE_SENTINEL).abi_encode_params()),
            true,
        );

        let result = inspect_on_chain(&mock, Chain::Mainnet, addr).await;
        match result {
            ScanResult::UnrecognizedImpl(md) => {
                // VERSION return is preserved on this branch (not
                // overridden by the registry — we have no registry hit).
                assert_eq!(md.version, "1.4.1");
                assert_eq!(md.implementation, unknown_impl);
            }
            other => panic!("expected UnrecognizedImpl, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inspect_rejects_when_version_outside_allowlist_and_implementation_unknown() {
        let mock = CallMock::new();
        let addr = safe_addr();
        mock.set_code(addr, Bytes::from_static(&[0x60]), true);
        // Unknown impl + version "5.0.0" — not a Safe.
        mock.set_storage(addr, B256::ZERO, B256::ZERO, true);
        mock.set_call(
            addr,
            Bytes::from(VERSIONCall {}.abi_encode()),
            Bytes::from("5.0.0".to_string().abi_encode()),
            true,
        );
        mock.set_call(
            addr,
            Bytes::from(getOwnersCall {}.abi_encode()),
            Bytes::from(vec![address!("0x000000000000000000000000000000000000beef")].abi_encode()),
            true,
        );
        mock.set_call(
            addr,
            Bytes::from(getThresholdCall {}.abi_encode()),
            Bytes::from(U256::from(1u64).abi_encode()),
            true,
        );
        mock.set_call(
            addr,
            Bytes::from(nonceCall {}.abi_encode()),
            Bytes::from(U256::ZERO.abi_encode()),
            true,
        );
        mock.set_call(
            addr,
            Bytes::from(
                getModulesPaginatedCall {
                    start: MODULE_SENTINEL,
                    pageSize: U256::from(MODULES_PAGE_SIZE),
                }
                .abi_encode(),
            ),
            Bytes::from((Vec::<Address>::new(), MODULE_SENTINEL).abi_encode_params()),
            true,
        );

        let result = inspect_on_chain(&mock, Chain::Mainnet, addr).await;
        assert!(
            matches!(result, ScanResult::NotASafe { .. }),
            "expected NotASafe, got {result:?}",
        );
    }

    #[tokio::test]
    async fn scan_across_chains_returns_one_result_per_chain_in_order() {
        // Mock answers identically for every chain (CallMock ignores
        // the chain argument), so all three chains see the same Safe.
        // The assertion is that the result order matches Chain::ALL.
        let mock = CallMock::new();
        plant_canonical_safe(
            &mock,
            &[address!("0x000000000000000000000000000000000000beef")],
            1,
            &[],
            None,
            None,
        );
        let results = scan_across_chains(&mock, safe_addr()).await;
        assert_eq!(results.len(), Chain::ALL.len());
        for (i, chain) in Chain::ALL.iter().enumerate() {
            assert_eq!(results[i].0, *chain);
            assert!(matches!(results[i].1, ScanResult::Canonical(_)));
        }
    }

    // ── Diff computation ─────────────────────────────────────────────

    fn descriptor_from_metadata(md: &SafeMetadata, trust: SafeTrust) -> SafeDescriptor {
        SafeDescriptor {
            name: None,
            chain_id: md.chain_id,
            address: md.address.into(),
            version: md.version.clone(),
            trust,
            threshold: md.threshold,
            owners: md.owners.iter().map(|a| (*a).into()).collect(),
            modules: md.modules.iter().map(|a| (*a).into()).collect(),
            guard: md.guard.map(|a| a.into()),
            fallback_handler: md.fallback_handler.map(|a| a.into()),
            linked_signer_indices: Vec::new(),
            sibling_chains: Vec::new(),
            cached_at: 0,
            tx_service_url: None,
        }
    }

    fn fake_metadata() -> SafeMetadata {
        SafeMetadata {
            chain_id: Chain::Mainnet.chain_id(),
            address: safe_addr(),
            implementation: address!("0x41675C099F32341bf84BFc5382aF534df5C7461a"),
            version: "1.4.1".into(),
            threshold: 2,
            owners: vec![
                address!("0x000000000000000000000000000000000000beef"),
                address!("0x000000000000000000000000000000000000dead"),
            ],
            modules: vec![address!("0xCFbFaC74C26F8647cBDb8c5caf80BB5b32E43134")],
            guard: None,
            fallback_handler: None,
            nonce: U256::from(10u64),
        }
    }

    #[test]
    fn diff_is_empty_when_nothing_changed() {
        let md = fake_metadata();
        let prev = descriptor_from_metadata(&md, SafeTrust::Canonical);
        let diff = compute_diff(&prev, &md, SafeTrust::Canonical);
        assert!(diff.is_empty(), "no change → empty diff, got {diff:?}");
    }

    #[test]
    fn diff_detects_owner_added_and_removed_independently() {
        let mut md = fake_metadata();
        let prev = descriptor_from_metadata(&md, SafeTrust::Canonical);
        // Swap one owner for a different one — that's one removal + one addition.
        let new_owner = address!("0x000000000000000000000000000000000000face");
        md.owners[0] = new_owner;
        let diff = compute_diff(&prev, &md, SafeTrust::Canonical);
        assert!(diff.changes.contains(&SafeChange::OwnerAdded(new_owner)));
        assert!(diff.changes.contains(&SafeChange::OwnerRemoved(address!(
            "0x000000000000000000000000000000000000beef"
        ),)));
    }

    #[test]
    fn diff_records_threshold_change_with_before_and_after() {
        let mut md = fake_metadata();
        let prev = descriptor_from_metadata(&md, SafeTrust::Canonical);
        md.threshold = 1;
        let diff = compute_diff(&prev, &md, SafeTrust::Canonical);
        assert_eq!(
            diff.changes,
            vec![SafeChange::ThresholdChanged { from: 2, to: 1 }],
        );
    }

    #[test]
    fn diff_records_module_added_and_removed() {
        let mut md = fake_metadata();
        let prev = descriptor_from_metadata(&md, SafeTrust::Canonical);
        let new_module = address!("0x000000000000000000000000000000000000aaaa");
        md.modules = vec![new_module]; // removed the Allowance Module, added a new one
        let diff = compute_diff(&prev, &md, SafeTrust::Canonical);
        assert!(diff.changes.contains(&SafeChange::ModuleAdded(new_module)));
        assert!(diff.changes.contains(&SafeChange::ModuleRemoved(address!(
            "0xCFbFaC74C26F8647cBDb8c5caf80BB5b32E43134"
        ),)));
    }

    #[test]
    fn diff_records_guard_transitions_between_none_and_some() {
        let mut md = fake_metadata();
        let prev = descriptor_from_metadata(&md, SafeTrust::Canonical);
        let g = address!("0x000000000000000000000000000000000000abab");
        md.guard = Some(g);
        let diff = compute_diff(&prev, &md, SafeTrust::Canonical);
        assert_eq!(
            diff.changes,
            vec![SafeChange::GuardChanged {
                from: None,
                to: Some(g),
            }],
        );
    }

    #[test]
    fn diff_records_trust_demotion_from_canonical_to_unrecognized() {
        // Models a proxy upgrade to an unaudited implementation —
        // arguably the loudest change a Safe can undergo, since it
        // pulls the trust anchor out from under the user.
        let md = fake_metadata();
        let prev = descriptor_from_metadata(&md, SafeTrust::Canonical);
        let diff = compute_diff(&prev, &md, SafeTrust::UnrecognizedImpl);
        assert_eq!(
            diff.changes,
            vec![SafeChange::TrustChanged {
                from: SafeTrust::Canonical,
                to: SafeTrust::UnrecognizedImpl,
            }],
        );
    }

    // ── summarize_user_facing_changes ────────────────────────────────

    fn diff_with(changes: Vec<SafeChange>) -> RefreshDiff {
        RefreshDiff { changes }
    }

    #[test]
    fn summarize_empty_diff_yields_no_alerts() {
        // Nothing in the diff → nothing to interrupt the user with.
        // Pins the contract that an empty refresh result is silent.
        let alerts = summarize_user_facing_changes(&diff_with(vec![]), &[]);
        assert!(alerts.is_empty());
    }

    #[test]
    fn summarize_owner_removed_alerts_only_when_owner_is_a_linked_signer() {
        let my_signer = address!("0x000000000000000000000000000000000000beef");
        let stranger = address!("0x000000000000000000000000000000000000dead");

        // Removing someone else's key — silent. Other people's
        // governance isn't ours to react to.
        let alerts = summarize_user_facing_changes(
            &diff_with(vec![SafeChange::OwnerRemoved(stranger)]),
            &[my_signer],
        );
        assert!(alerts.is_empty(), "stranger removal should be silent");

        // Removing our own key — loud. The user just lost signing
        // capability on this Safe and needs to know immediately.
        let alerts = summarize_user_facing_changes(
            &diff_with(vec![SafeChange::OwnerRemoved(my_signer)]),
            &[my_signer],
        );
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].contains("no longer an owner"));
    }

    #[test]
    fn summarize_threshold_change_always_alerts() {
        // Threshold is a security parameter — any change deserves an
        // explicit acknowledgment regardless of whether the user holds
        // a key.
        let alerts = summarize_user_facing_changes(
            &diff_with(vec![SafeChange::ThresholdChanged { from: 3, to: 1 }]),
            &[],
        );
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].contains("Threshold"));
        assert!(alerts[0].contains("3"));
        assert!(alerts[0].contains("1"));
    }

    #[test]
    fn summarize_module_added_alerts_only_for_unknown_modules() {
        // Recognized module addition → silent (the user accepted this
        // module class by prior on-chain action; refreshing doesn't
        // require re-confirming).
        let known = address!("0xCFbFaC74C26F8647cBDb8c5caf80BB5b32E43134"); // Allowance Module
        assert!(classify_module(known).is_some(), "test invariant");
        let alerts =
            summarize_user_facing_changes(&diff_with(vec![SafeChange::ModuleAdded(known)]), &[]);
        assert!(alerts.is_empty(), "known module should be silent");

        // Unknown module → loud. Modules can move funds without owner
        // signatures, so an unaudited one is a standing backdoor.
        let unknown = address!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        assert!(classify_module(unknown).is_none(), "test invariant");
        let alerts =
            summarize_user_facing_changes(&diff_with(vec![SafeChange::ModuleAdded(unknown)]), &[]);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].contains("Unknown module"));
    }

    #[test]
    fn summarize_trust_demotion_alerts_but_promotion_is_silent() {
        // Canonical → UnrecognizedImpl: the trust anchor moved AWAY
        // from an audited singleton. Alert.
        let alerts = summarize_user_facing_changes(
            &diff_with(vec![SafeChange::TrustChanged {
                from: SafeTrust::Canonical,
                to: SafeTrust::UnrecognizedImpl,
            }]),
            &[],
        );
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].contains("unknown"));

        // UnrecognizedImpl → Canonical: good news. The proxy upgraded
        // to a known singleton. Silent — no reason to interrupt.
        let alerts = summarize_user_facing_changes(
            &diff_with(vec![SafeChange::TrustChanged {
                from: SafeTrust::UnrecognizedImpl,
                to: SafeTrust::Canonical,
            }]),
            &[],
        );
        assert!(alerts.is_empty(), "promotion should be silent");
    }

    #[test]
    fn summarize_silent_changes_dont_produce_alerts() {
        // Everything that's deliberately silent: owner added (someone
        // else joining governance), module removed (security surface
        // shrank — good news), guard / fallback transitions, version
        // bumps within Canonical trust. Bundling them in one diff and
        // asserting empty alerts pins the silent-by-default policy.
        let known_module = address!("0xCFbFaC74C26F8647cBDb8c5caf80BB5b32E43134");
        let alerts = summarize_user_facing_changes(
            &diff_with(vec![
                SafeChange::OwnerAdded(address!("0x000000000000000000000000000000000000aaaa")),
                SafeChange::ModuleRemoved(known_module),
                SafeChange::GuardChanged {
                    from: None,
                    to: Some(address!("0x000000000000000000000000000000000000bbbb")),
                },
                SafeChange::FallbackHandlerChanged {
                    from: Some(address!("0x000000000000000000000000000000000000cccc")),
                    to: None,
                },
                SafeChange::VersionChanged {
                    from: "1.3.0".into(),
                    to: "1.4.1".into(),
                },
            ]),
            &[],
        );
        assert!(
            alerts.is_empty(),
            "silent changes should produce no alerts, got {alerts:?}"
        );
    }

    #[test]
    fn summarize_aggregates_multiple_alerts_in_order() {
        // When a single Safe has multiple noisy changes in one
        // refresh, the alerts come back in the same order they appear
        // in the diff. The caller concatenates them into one toast —
        // depending on order means the toast reads sensibly rather
        // than as a random shuffle.
        let my_signer = address!("0x000000000000000000000000000000000000beef");
        let alerts = summarize_user_facing_changes(
            &diff_with(vec![
                SafeChange::ThresholdChanged { from: 2, to: 1 },
                SafeChange::OwnerRemoved(my_signer),
            ]),
            &[my_signer],
        );
        assert_eq!(alerts.len(), 2);
        assert!(alerts[0].contains("Threshold"));
        assert!(alerts[1].contains("no longer an owner"));
    }

    // ── End-to-end refresh_one ────────────────────────────────────────

    #[tokio::test]
    async fn refresh_one_returns_empty_diff_when_chain_state_unchanged() {
        let mock = CallMock::new();
        let owners = vec![address!("0x000000000000000000000000000000000000beef")];
        let _ = plant_canonical_safe(&mock, &owners, 1, &[], None, None);
        // Build a descriptor that matches what plant_canonical_safe writes.
        let prev = SafeDescriptor {
            name: Some("treasury".into()),
            chain_id: Chain::Mainnet.chain_id(),
            address: safe_addr().into(),
            version: "1.4.1".into(),
            trust: SafeTrust::Canonical,
            threshold: 1,
            owners: vec![owners[0].into()],
            modules: Vec::new(),
            guard: None,
            fallback_handler: None,
            linked_signer_indices: vec![3],
            sibling_chains: vec![10],
            cached_at: 100,
            tx_service_url: None,
        };

        let (new_desc, diff) = refresh_one(&mock, &prev).await.unwrap();
        assert!(
            diff.is_empty(),
            "no on-chain change → empty diff, got {diff:?}"
        );
        // Name + linked signers + siblings carry through unchanged —
        // refresh_one MUST NOT clobber user-controlled fields.
        assert_eq!(new_desc.name, prev.name);
        assert_eq!(new_desc.linked_signer_indices, prev.linked_signer_indices);
        assert_eq!(new_desc.sibling_chains, prev.sibling_chains);
        // cached_at advances (clamp to ≥ prev).
        assert!(new_desc.cached_at >= prev.cached_at);
    }

    #[tokio::test]
    async fn refresh_one_preserves_custom_tx_service_url() {
        // The service mirror is user configuration, not on-chain state —
        // a background refresh must carry it through verbatim, exactly
        // like name / linked signers / siblings.
        let mock = CallMock::new();
        let owners = vec![address!("0x000000000000000000000000000000000000beef")];
        let _ = plant_canonical_safe(&mock, &owners, 1, &[], None, None);
        let prev = SafeDescriptor {
            name: Some("treasury".into()),
            chain_id: Chain::Mainnet.chain_id(),
            address: safe_addr().into(),
            version: "1.4.1".into(),
            trust: SafeTrust::Canonical,
            threshold: 1,
            owners: vec![owners[0].into()],
            modules: Vec::new(),
            guard: None,
            fallback_handler: None,
            linked_signer_indices: Vec::new(),
            sibling_chains: Vec::new(),
            cached_at: 100,
            tx_service_url: Some("https://txs.example-dao.org".into()),
        };
        let (new_desc, _diff) = refresh_one(&mock, &prev).await.unwrap();
        assert_eq!(
            new_desc.tx_service_url.as_deref(),
            Some("https://txs.example-dao.org"),
        );
    }

    #[tokio::test]
    async fn refresh_one_returns_err_when_address_no_longer_deployed() {
        let mock = CallMock::new();
        // Deliberately don't plant anything — get_code returns empty.
        let prev = SafeDescriptor {
            name: None,
            chain_id: Chain::Mainnet.chain_id(),
            address: safe_addr().into(),
            version: "1.4.1".into(),
            trust: SafeTrust::Canonical,
            threshold: 1,
            owners: vec![address!("0x000000000000000000000000000000000000beef").into()],
            modules: Vec::new(),
            guard: None,
            fallback_handler: None,
            linked_signer_indices: Vec::new(),
            sibling_chains: Vec::new(),
            cached_at: 0,
            tx_service_url: None,
        };
        let err = refresh_one(&mock, &prev).await.unwrap_err();
        assert!(
            err.contains("no longer deployed"),
            "expected 'no longer deployed' in err, got {err}",
        );
    }

    #[tokio::test]
    async fn refresh_one_detects_owner_removal_in_diff() {
        let mock = CallMock::new();
        // Plant a Safe whose CURRENT owner set has only one address.
        let kept = address!("0x000000000000000000000000000000000000beef");
        let _ = plant_canonical_safe(&mock, &[kept], 1, &[], None, None);
        // Prev descriptor cached TWO owners — the second one ("removed")
        // is gone from chain. Diff should record the removal.
        let removed = address!("0x000000000000000000000000000000000000dead");
        let prev = SafeDescriptor {
            name: None,
            chain_id: Chain::Mainnet.chain_id(),
            address: safe_addr().into(),
            version: "1.4.1".into(),
            trust: SafeTrust::Canonical,
            threshold: 1,
            owners: vec![kept.into(), removed.into()],
            modules: Vec::new(),
            guard: None,
            fallback_handler: None,
            linked_signer_indices: Vec::new(),
            sibling_chains: Vec::new(),
            cached_at: 0,
            tx_service_url: None,
        };

        let (_new, diff) = refresh_one(&mock, &prev).await.unwrap();
        assert!(diff.changes.contains(&SafeChange::OwnerRemoved(removed)));
        // No spurious "owner added" — the kept owner was already in prev.
        assert!(
            !diff
                .changes
                .iter()
                .any(|c| matches!(c, SafeChange::OwnerAdded(_)))
        );
    }
}
