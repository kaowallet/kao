use alloy::consensus::SignableTransaction;
use alloy::eips::eip7702::{Authorization, SignedAuthorization};
use alloy::network::TxSigner;
use alloy::primitives::{Address, B256, Signature};
use alloy::signers::Signer;
use alloy::signers::ledger::{HDPath as AlloyLedgerHDPath, LedgerSigner};
use alloy::signers::local::{
    MnemonicBuilder, MnemonicKey, PrivateKeySigner, coins_bip39, coins_bip39::English,
};
use alloy::signers::trezor::{HDPath as AlloyTrezorHDPath, TrezorSigner};
use alloy::sol_types::{Eip712Domain, SolStruct};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

pub mod contacts;
pub mod sim;
mod store;
pub mod tx;

pub use contacts::{Contact, ContactEns, ContactsBook};
pub use store::db_exists as wallet_exists;
pub use store::{
    clear_pp_notes, load_all_pp_notes, load_contacts, load_descriptor, load_pp_seed, save_contacts,
    save_descriptor, save_pp_notes, save_pp_seed,
};

/// Errors that can occur during wallet operations.
#[derive(Debug)]
pub enum WalletError {
    /// Error generating or using a mnemonic.
    Mnemonic(String),
    /// Error encrypting/decrypting the private key.
    Encryption(String),
    /// Error reading/writing the wallet file.
    Io(std::io::Error),
    /// No wallet found on disk.
    NotFound,
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletError::Mnemonic(e) => write!(f, "mnemonic error: {e}"),
            WalletError::Encryption(e) => write!(f, "encryption error: {e}"),
            WalletError::Io(e) => write!(f, "io error: {e}"),
            WalletError::NotFound => write!(f, "no wallet found"),
        }
    }
}

impl std::error::Error for WalletError {}

impl From<std::io::Error> for WalletError {
    fn from(e: std::io::Error) -> Self {
        WalletError::Io(e)
    }
}

// ── Descriptor ─────────────────────────────────────────────────────────────

/// A 32-byte secp256k1 private key, stored so it never lingers as bare,
/// long-lived key material inside an `AccountDescriptor`.
///
/// Unlike the plain `[u8; 32]` it replaces:
///   * the buffer is zeroized on drop — and because the inner type is not
///     `Copy`, every `clone()` is a deliberate, independently-zeroized copy
///     rather than a silent bitwise duplication that outlives its use;
///   * `Debug` is redacted, so an accidental `{:?}` on an `AccountDescriptor`
///     (or a panic backtrace that formats one) can never print the key.
///
/// It (de)serializes byte-for-byte identically to the `[u8; 32]` it replaced,
/// so the on-disk wallet format is unchanged and existing wallets load as-is.
#[derive(Clone)]
pub struct SecretKeyBytes(Zeroizing<[u8; 32]>);

impl SecretKeyBytes {
    /// Wrap raw private-key bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the raw bytes. Keep the borrow short-lived and never copy it
    /// into an un-zeroized owner.
    pub fn as_array(&self) -> &[u8; 32] {
        &self.0
    }

    /// The key as a `B256` — the form alloy's signer constructors expect.
    /// The returned value is a plain (non-zeroizing) copy, so build the signer
    /// from it immediately and let it drop.
    pub fn to_b256(&self) -> B256 {
        B256::from_slice(self.as_array())
    }
}

impl From<[u8; 32]> for SecretKeyBytes {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

impl From<Zeroizing<[u8; 32]>> for SecretKeyBytes {
    fn from(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for SecretKeyBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKeyBytes(redacted)")
    }
}

impl Serialize for SecretKeyBytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Serialize as the bare `[u8; 32]` so the on-disk format is identical
        // to the field this type replaced — existing wallets load unchanged.
        let bytes: &[u8; 32] = &self.0;
        bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretKeyBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::new(<[u8; 32]>::deserialize(deserializer)?))
    }
}

/// What kind of signer one account uses, plus enough metadata to reconstruct
/// it on the next launch. Multiple of these live inside a `WalletDescriptor`.
///
/// `ViewOnly` is the read-only watch variant: it carries an address but no
/// signing material, so it can show balance/activity but can't sign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccountDescriptor {
    Local {
        name: Option<String>,
        key_bytes: SecretKeyBytes,
    },
    Ledger {
        name: Option<String>,
        path: LedgerHdPath,
        address: [u8; 20],
    },
    Trezor {
        name: Option<String>,
        path: TrezorHdPath,
        address: [u8; 20],
    },
    ViewOnly {
        name: Option<String>,
        address: [u8; 20],
    },
}

impl AccountDescriptor {
    /// User-assigned label for this account, if any. `None` means "no
    /// custom name set" — call `display_name(idx)` to get a string suitable
    /// for rendering ("Account 1" / "Account 2" / …).
    pub fn name(&self) -> Option<&str> {
        match self {
            AccountDescriptor::Local { name, .. }
            | AccountDescriptor::Ledger { name, .. }
            | AccountDescriptor::Trezor { name, .. }
            | AccountDescriptor::ViewOnly { name, .. } => name.as_deref(),
        }
    }

    /// Replace the account's user-assigned name. Trims whitespace and
    /// collapses an empty result to `None` so blank inputs revert to the
    /// "Account N" default.
    pub fn set_name(&mut self, name: Option<String>) {
        let cleaned = name.and_then(|s| {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        });
        let slot = match self {
            AccountDescriptor::Local { name, .. }
            | AccountDescriptor::Ledger { name, .. }
            | AccountDescriptor::Trezor { name, .. }
            | AccountDescriptor::ViewOnly { name, .. } => name,
        };
        *slot = cleaned;
    }

    /// Name to render. Falls back to `Account {idx + 1}` when no custom
    /// name has been set.
    pub fn display_name(&self, idx: usize) -> String {
        match self.name() {
            Some(n) => n.to_string(),
            None => format!("Account {}", idx + 1),
        }
    }

    /// Whether this account holds (or reaches, via a device) a key that can
    /// sign: `Local`, `Ledger` and `Trezor` do, `ViewOnly` never does. Only
    /// these may be linked as a Safe signer.
    pub fn can_sign(&self) -> bool {
        !matches!(self, AccountDescriptor::ViewOnly { .. })
    }
}

/// Top-level wallet payload. Encrypted at rest inside `wallet.enc`. Holds the
/// list of accounts the user has set up plus the index of the one currently
/// in focus on the dashboard, plus any Safes the user has onboarded.
///
/// `active_index` only refers to `accounts` — Safes are surfaced in the
/// account list UI but do not claim the active-selection slot in v1. The
/// future Safe-dashboard plan will introduce a unified `WalletSelection`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletDescriptor {
    pub accounts: Vec<AccountDescriptor>,
    pub safes: Vec<SafeDescriptor>,
    pub active_index: usize,
    /// Whether `repair_sibling_signer_links` has had its one run on this
    /// wallet (see `repair_sibling_signer_links_once`). `false` only for a
    /// wallet last saved before the repair shipped — the store reads a
    /// missing marker that way — so the repair runs on the first unlock
    /// after the upgrade and never again. Every new wallet starts `true`:
    /// nothing in it was written by the old onboarding.
    #[serde(default)]
    pub sibling_links_repaired: bool,
}

impl WalletDescriptor {
    pub fn single(account: AccountDescriptor) -> Self {
        Self {
            accounts: vec![account],
            safes: Vec::new(),
            active_index: 0,
            sibling_links_repaired: true,
        }
    }

    pub fn active(&self) -> &AccountDescriptor {
        &self.accounts[self.active_index.min(self.accounts.len().saturating_sub(1))]
    }

    /// Addresses currently held by the wallet. Used to skip duplicates when
    /// adding accounts via the HD picker, hardware probe, or import flows.
    pub fn addresses(&self) -> Vec<Address> {
        self.accounts.iter().filter_map(account_address).collect()
    }

    pub fn contains_address(&self, target: Address) -> bool {
        self.addresses().contains(&target)
    }

    /// True if any `(address, chain_id)` Safe descriptor matches.
    ///
    /// Tests exercise it directly; the add flows now go through
    /// `upsert_safe`, which needs the position (`safe_index`) rather than
    /// a yes/no.
    #[allow(dead_code)]
    pub fn contains_safe(&self, target: Address, chain_id: u64) -> bool {
        self.safe_index(target.into(), chain_id).is_some()
    }

    /// Position of the Safe keyed `(address, chain_id)` in `safes`, if the
    /// wallet holds it. Safes are identified by that pair, never by
    /// position: a position read before an await or a list edit can point
    /// at a different Safe after it.
    pub fn safe_index(&self, address: [u8; 20], chain_id: u64) -> Option<usize> {
        self.safes
            .iter()
            .position(|s| s.address == address && s.chain_id == chain_id)
    }

    /// Remove the account at `idx`, keeping every index-based reference to
    /// the account list consistent in the same edit:
    ///
    /// * unnamed accounts after `idx` get their current "Account N" frozen
    ///   in as a real name, so nothing the user sees is silently renamed
    ///   ("Account 3" must not turn into "Account 2");
    /// * every Safe's `linked_signer_indices` drops `idx` and shifts the
    ///   indices above it down by one. A missed shift fails quietly — the
    ///   link would point at a *different* key;
    /// * `active_index` follows its account down, or, when the active
    ///   account itself goes, lands on the one that slid into its slot
    ///   (the new last account when it was last).
    ///
    /// Refuses an out-of-range index and the wallet's only account (the
    /// store won't load a wallet without accounts, and `active()` assumes
    /// one); a refusal changes nothing. The caller persists the result.
    ///
    /// Settings → Accounts' Remove (via `App::remove_account`) consumes this.
    pub fn remove_account(&mut self, idx: usize) -> Result<RemovedAccount, RemoveAccountError> {
        let len = self.accounts.len();
        if idx >= len {
            return Err(RemoveAccountError::OutOfRange { index: idx, len });
        }
        if len == 1 {
            return Err(RemoveAccountError::LastAccount);
        }
        // Resolve the active slot the way `active()` does before shifting,
        // so an out-of-range stored index can't survive the edit.
        let active = self.active_index.min(len - 1);

        for (i, acc) in self.accounts.iter_mut().enumerate().skip(idx + 1) {
            if acc.name().is_none() {
                let frozen = acc.display_name(i);
                acc.set_name(Some(frozen));
            }
        }
        // The descriptor drops at the end of this block; a `Local` key
        // zeroizes with it.
        let (name, address) = {
            let account = self.accounts.remove(idx);
            (account.display_name(idx), account_address(&account))
        };

        let gone = idx as u32;
        let mut unlinked_safes = Vec::new();
        let mut left_without_signing_key = Vec::new();
        for safe in &mut self.safes {
            let before = safe.linked_signer_indices.len();
            safe.linked_signer_indices.retain(|&i| i != gone);
            for i in &mut safe.linked_signer_indices {
                if *i > gone {
                    *i -= 1;
                }
            }
            if safe.linked_signer_indices.len() != before {
                unlinked_safes.push(safe.key());
                // Remaining links don't count unless they can sign: a
                // view-only account or an ex-owner left linked is still
                // no way to sign for it.
                if !safe.has_signing_link(&self.accounts) {
                    left_without_signing_key.push(safe.key());
                }
            }
        }

        self.active_index = match active.cmp(&idx) {
            std::cmp::Ordering::Less => active,
            std::cmp::Ordering::Equal => idx.min(self.accounts.len() - 1),
            std::cmp::Ordering::Greater => active - 1,
        };

        Ok(RemovedAccount {
            name,
            address,
            unlinked_safes,
            left_without_signing_key,
        })
    }

    /// Remove the Safe keyed `(address, chain_id)`: that one deployment
    /// only, the same address on other chains stays. Unnamed Safes after it
    /// get their current "Safe N" frozen in as a real name (same reason as
    /// `remove_account`), and same-address peers stop listing `chain_id` in
    /// their informational `sibling_chains`.
    ///
    /// Returns the removed descriptor, or `None` when the wallet doesn't
    /// hold that Safe (nothing changed). The caller persists the result.
    ///
    /// Settings → Safes' Remove (via `App::remove_safe`) consumes this.
    pub fn remove_safe(&mut self, address: [u8; 20], chain_id: u64) -> Option<SafeDescriptor> {
        let idx = self.safe_index(address, chain_id)?;
        for (i, safe) in self.safes.iter_mut().enumerate().skip(idx + 1) {
            if safe.name().is_none() {
                let frozen = safe.display_name(i);
                safe.set_name(Some(frozen));
            }
        }
        let removed = self.safes.remove(idx);
        for peer in self.safes.iter_mut().filter(|s| s.address == address) {
            peer.sibling_chains.retain(|&c| c != chain_id);
        }
        Some(removed)
    }

    /// Rename the Safe at `address` on EVERY chain it is saved on. Siblings
    /// are one Safe to the user, and the address-keyed lookups (sign-review
    /// local names, the contacts merge) would otherwise disagree about which
    /// name it has. Goes through `SafeDescriptor::set_name`, so blank input
    /// reverts to the "Safe N" default.
    ///
    /// Returns how many descriptors were renamed — `0` means the wallet
    /// doesn't hold that address. The caller persists the result.
    ///
    /// The header pencil in Safe mode and Settings → Safes' Name field
    /// (via `App::rename_safe`) consume this.
    pub fn rename_safe(&mut self, address: [u8; 20], name: Option<String>) -> usize {
        let mut renamed = 0;
        for safe in self.safes.iter_mut().filter(|s| s.address == address) {
            safe.set_name(name.clone());
            renamed += 1;
        }
        renamed
    }

    /// Add a freshly onboarded Safe, or fold it into the entry already
    /// saved under its `(address, chain_id)`.
    ///
    /// Absent → appended. When the address is already saved on another
    /// chain, a new chain arriving without a name or service URL takes the
    /// saved one's, so one Safe keeps one name on every chain (address-keyed
    /// lookups like the sign-review local names depend on it). An explicit
    /// incoming name is kept here; `App::upsert_safes` then applies it to
    /// every chain.
    ///
    /// Present → the incoming signer links are unioned into the saved ones
    /// (sorted, deduped; nothing is ever unlinked), and the cached on-chain
    /// fields are taken from the incoming scan when it is at least as
    /// fresh. The saved name, service URL and `sibling_chains` stay as they
    /// are — `sibling_chains` deliberately isn't unioned, so
    /// `repair_sibling_signer_links`' mutual-listing test stays as tight as
    /// the bug that wrote it.
    ///
    /// This is what makes "add it again to link your key" work: re-adding a
    /// Safe that was saved watch-only used to be skipped silently.
    pub fn upsert_safe(&mut self, mut incoming: SafeDescriptor) -> SafeUpsert {
        let Some(index) = self.safe_index(incoming.address, incoming.chain_id) else {
            let address = incoming.address;
            let peers = || self.safes.iter().filter(|s| s.address == address);
            if incoming.name().is_none()
                && let Some(name) = peers().find_map(SafeDescriptor::name)
            {
                incoming.set_name(Some(name.to_owned()));
            }
            if incoming.tx_service_url.is_none()
                && let Some(url) = peers().find_map(|s| s.tx_service_url.as_ref())
            {
                incoming.tx_service_url = Some(url.clone());
            }
            self.safes.push(incoming);
            return SafeUpsert::Added;
        };
        let slot = &mut self.safes[index];
        slot.refresh_onchain_from(&incoming);
        let mut links: BTreeSet<u32> = slot.linked_signer_indices.iter().copied().collect();
        let before = links.len();
        links.extend(incoming.linked_signer_indices.iter().copied());
        let newly_linked = links.len() - before;
        slot.linked_signer_indices = links.into_iter().collect();
        if newly_linked == 0 {
            SafeUpsert::Unchanged(index)
        } else {
            SafeUpsert::Merged {
                index,
                newly_linked,
            }
        }
    }

    /// Repair Safes saved before sibling chains inherited signer links.
    ///
    /// Onboarding used to save every chain but the primary with no links,
    /// so a Safe added on Mainnet + Base came back watch-only on Base even
    /// when the user's key owned it there. That shape is recognisable: a
    /// watch-only target with a linked "donor" at the same address on
    /// another chain, the two listing each other in `sibling_chains` (the
    /// buggy confirm wrote both directions). The target gets every donor
    /// link whose account can sign (never a view-only one — the old flow
    /// linked those too, onboarding no longer does) and whose address is
    /// one of the target's own cached owners — owner sets can differ per
    /// chain. Dangling indices drop out.
    ///
    /// Returns the positions repaired (empty when nothing matched). Only
    /// ever adds links to a Safe that has none, so it is idempotent. It is
    /// NOT safe to run on every unlock, though: re-adding one chain of a
    /// saved pair links that chain while keeping its `sibling_chains`, which
    /// recreates the bug's shape when the user left the other chain
    /// watch-only on purpose. Unlock goes through
    /// `repair_sibling_signer_links_once`.
    pub fn repair_sibling_signer_links(&mut self) -> Vec<usize> {
        // `None` for an account that can't sign: it is never copied.
        let account_addrs: Vec<Option<[u8; 20]>> = self
            .accounts
            .iter()
            .map(|a| {
                a.can_sign()
                    .then(|| account_address(a))
                    .flatten()
                    .map(Address::into_array)
            })
            .collect();
        let donors: Vec<(SafeKey, Vec<u32>, Vec<u64>)> = self
            .safes
            .iter()
            .filter(|s| s.is_signer())
            .map(|s| {
                (
                    s.key(),
                    s.linked_signer_indices.clone(),
                    s.sibling_chains.clone(),
                )
            })
            .collect();

        let mut repaired = Vec::new();
        for (i, target) in self.safes.iter_mut().enumerate() {
            if target.is_signer() {
                continue;
            }
            let links: BTreeSet<u32> = donors
                .iter()
                .filter(|((address, chain_id), _, donor_siblings)| {
                    *address == target.address
                        && *chain_id != target.chain_id
                        && donor_siblings.contains(&target.chain_id)
                        && target.sibling_chains.contains(chain_id)
                })
                .flat_map(|(_, links, _)| links.iter().copied())
                .filter(|&idx| {
                    account_addrs
                        .get(idx as usize)
                        .copied()
                        .flatten()
                        .is_some_and(|a| target.owners.contains(&a))
                })
                .collect();
            if !links.is_empty() {
                target.linked_signer_indices = links.into_iter().collect();
                repaired.push(i);
            }
        }
        repaired
    }

    /// Run `repair_sibling_signer_links` once per wallet: only while
    /// `sibling_links_repaired` is unset, i.e. on a wallet last saved before
    /// the repair shipped, whose data is all the old onboarding's. Sets the
    /// marker either way.
    ///
    /// `None` when the repair already ran (nothing changed). Otherwise the
    /// positions repaired — possibly none, but the marker changed, so the
    /// caller must persist the wallet. The store writes the marker in the
    /// same transaction as the links, so if that save never lands the
    /// repair simply runs again next unlock against the same legacy data.
    pub fn repair_sibling_signer_links_once(&mut self) -> Option<Vec<usize>> {
        if self.sibling_links_repaired {
            return None;
        }
        let repaired = self.repair_sibling_signer_links();
        self.sibling_links_repaired = true;
        Some(repaired)
    }
}

/// Why `WalletDescriptor::remove_account` refused. Nothing was changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveAccountError {
    /// No account at `index`; the wallet has `len`.
    OutOfRange { index: usize, len: usize },
    /// It is the wallet's only account.
    LastAccount,
}

impl std::fmt::Display for RemoveAccountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfRange { index, len } => {
                write!(f, "no account at position {index} (the wallet has {len})")
            }
            Self::LastAccount => f.write_str("Your wallet needs at least one account."),
        }
    }
}

/// What `WalletDescriptor::remove_account` removed and what it touched —
/// enough for the confirmation toast and any follow-up copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedAccount {
    /// The name it was shown under right before removal.
    pub name: String,
    /// Its address, when one could be derived.
    pub address: Option<Address>,
    /// Every Safe that listed it as a linked signer.
    pub unlinked_safes: Vec<SafeKey>,
    /// The subset of `unlinked_safes` that no remaining linked account can
    /// sign for (`SafeDescriptor::has_signing_link`) — those are watch-only
    /// now, even when a view-only or ex-owner link is left behind.
    pub left_without_signing_key: Vec<SafeKey>,
}

/// Result of `WalletDescriptor::upsert_safe`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeUpsert {
    /// Not in the wallet yet — appended.
    Added,
    /// Already saved at `index`; `newly_linked` (≥ 1) signer links were
    /// added to it.
    Merged { index: usize, newly_linked: usize },
    /// Already saved at `index` with every incoming link. Nothing the user
    /// configured changed (the cached on-chain fields may have refreshed).
    Unchanged(usize),
}

// ── SafeDescriptor ─────────────────────────────────────────────────────────

/// A Safe's identity: `(address, chain_id)`. The same address on another
/// chain is a different Safe with its own owners.
pub type SafeKey = ([u8; 20], u64);

/// Whether Kao recognizes the on-chain implementation behind this Safe
/// proxy. Determined at onboarding by reading proxy storage slot 0 and
/// looking the address up in the per-chain canonical-singleton registry.
///
/// `Canonical` is the only state that will enable signing in the future
/// Safe-TX flow; `UnrecognizedImpl` is a deliberate "show but don't
/// trust" mode so a user pasting an exotic Safe deployment isn't locked
/// out, but also isn't silently led into signing against a contract Kao
/// has never seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafeTrust {
    Canonical,
    UnrecognizedImpl,
}

impl SafeTrust {
    pub fn permits_signing(&self) -> bool {
        self.signing_block_reason().is_none()
    }

    pub fn signing_block_reason(&self) -> Option<&'static str> {
        match self {
            Self::Canonical => None,
            Self::UnrecognizedImpl => {
                Some("Safe implementation is not recognized as canonical; signing is disabled.")
            }
        }
    }
}

/// Persisted record of a Safe the user has onboarded. Lives in its own
/// `safes` redb table — Safes have no private key material of their own
/// (signing happens via linked owner accounts), so commingling with
/// `AccountDescriptor` would conflate "thing that holds a secret" with
/// "thing that delegates signing to other accounts".
///
/// The cached on-chain fields (`owners`, `threshold`, `modules`, `guard`,
/// `fallback_handler`) are snapshots from `cached_at`. The dashboard
/// refreshes them on app open and the Safe-TX flow refreshes synchronously
/// before quoting transaction parameters, so stale data should never reach
/// a signing decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeDescriptor {
    /// User-assigned label. `None` means "no custom name" — call
    /// `display_name(idx)` for the rendered fallback.
    pub name: Option<String>,
    /// EVM chain ID this deployment lives on. Stored explicitly so the
    /// `(address, chain_id)` pair uniquely identifies a Safe — the same
    /// address on a different chain is a different Safe with potentially
    /// different owners.
    pub chain_id: u64,
    /// The Safe proxy's address.
    pub address: [u8; 20],
    /// `VERSION()` string returned by the proxy, e.g. "1.4.1". Kept as
    /// the raw string rather than a parsed semver so a future Safe release
    /// that adds e.g. "1.5.0-beta" doesn't trip deserialization.
    pub version: String,
    pub trust: SafeTrust,
    /// Signature threshold. Safe returns `uint256`; in practice this is
    /// ≤ owner count which is ≤ a few dozen, but we store as `u32`
    /// defensively so a pathological value doesn't truncate.
    pub threshold: u32,
    pub owners: Vec<[u8; 20]>,
    /// Enabled modules. Each one can move funds without any owner
    /// signature — surfaced loudly in the onboarding UI and treated as
    /// a standing security surface.
    pub modules: Vec<[u8; 20]>,
    /// Transaction guard, if set. A guard can block any transaction
    /// the owners try to execute, so a malicious guard is a brick of
    /// the entire Safe.
    pub guard: Option<[u8; 20]>,
    /// Fallback handler, if set. Safe delegates unknown function
    /// selectors to this contract — a malicious one can implement
    /// arbitrary behavior under the Safe's identity.
    pub fallback_handler: Option<[u8; 20]>,
    /// Indices into `WalletDescriptor.accounts` for keys the user has
    /// chosen to link as signers. Empty = observer/watch-only.
    pub linked_signer_indices: Vec<u32>,
    /// Other chain IDs where this same address is also a deployed Safe,
    /// detected during onboarding's parallel scan. Informational only —
    /// each sibling, if added, gets its own `SafeDescriptor` because
    /// owner sets can diverge across chains.
    pub sibling_chains: Vec<u64>,
    /// Unix seconds at which the cached on-chain fields above were last
    /// refreshed. UI uses this to show a staleness indicator.
    pub cached_at: u64,
    /// Custom Safe Transaction Service base URL for THIS Safe — `None`
    /// means the public `api.safe.global`. Per-Safe rather than global
    /// so a DAO treasury can point at its self-hosted mirror while a
    /// personal Safe stays on the default. Set via the onboarding
    /// Advanced section or Settings → Safes; always normalized through
    /// `safe::service::normalize_service_base` before it lands here.
    ///
    /// NOTE: appended last for postcard compatibility — the store's
    /// loader falls back to the pre-field layout for older wallets
    /// (`store::decode_safe`). New fields must keep appending.
    pub tx_service_url: Option<String>,
}

impl SafeDescriptor {
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// This Safe's identity, `(address, chain_id)`.
    pub fn key(&self) -> SafeKey {
        (self.address, self.chain_id)
    }

    /// Take the cached on-chain state — version, trust, threshold, owners,
    /// modules, guard, fallback handler and `cached_at` — from `fresh`, a
    /// newer read of the same Safe, leaving everything the user configured
    /// (name, linked signers, `sibling_chains`, service URL) as it is.
    ///
    /// Skipped when `fresh` is older than what's cached, so a slow read can
    /// never roll the cache back. Returns whether it adopted.
    pub fn refresh_onchain_from(&mut self, fresh: &SafeDescriptor) -> bool {
        if fresh.cached_at < self.cached_at {
            return false;
        }
        self.version = fresh.version.clone();
        self.trust = fresh.trust.clone();
        self.threshold = fresh.threshold;
        self.owners = fresh.owners.clone();
        self.modules = fresh.modules.clone();
        self.guard = fresh.guard;
        self.fallback_handler = fresh.fallback_handler;
        self.cached_at = fresh.cached_at;
        true
    }

    /// Replace the user-assigned name. Mirrors `AccountDescriptor::set_name`:
    /// trims whitespace and collapses an empty result to `None` so blank
    /// inputs revert to the "Safe N" default.
    pub fn set_name(&mut self, name: Option<String>) {
        let cleaned = name.and_then(|s| {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        });
        self.name = cleaned;
    }

    /// Rendered name. Falls back to `Safe {idx + 1}` when unnamed.
    pub fn display_name(&self, idx: usize) -> String {
        match self.name() {
            Some(n) => n.to_string(),
            None => format!("Safe {}", idx + 1),
        }
    }

    /// True when the user has linked at least one of their own accounts
    /// as a signer of this Safe. Watch-only Safes return false and are
    /// rendered in a visibly non-signing state.
    pub fn is_signer(&self) -> bool {
        !self.linked_signer_indices.is_empty()
    }

    /// Whether `account` can sign for this Safe: its kind holds or reaches
    /// a key (`AccountDescriptor::can_sign`) and its address is one of the
    /// cached owners. A link is the user's choice, not an ownership fact —
    /// it can name a view-only account (the old onboarding linked those)
    /// or outlive the owner's on-chain removal, and neither signs.
    pub fn is_signing_owner(&self, account: &AccountDescriptor) -> bool {
        account.can_sign()
            && account_address(account).is_some_and(|a| self.owners.contains(&a.into_array()))
    }

    /// The linked indices whose account in `accounts` can sign for this
    /// Safe (`is_signing_owner`). Dangling indices drop out.
    pub fn signing_links<'a>(
        &'a self,
        accounts: &'a [AccountDescriptor],
    ) -> impl Iterator<Item = u32> + 'a {
        self.linked_signer_indices.iter().copied().filter(|&idx| {
            accounts
                .get(idx as usize)
                .is_some_and(|a| self.is_signing_owner(a))
        })
    }

    /// Whether at least one linked account can sign for this Safe — what
    /// separates a Safe Kao can act as from a watch-only one. Stricter than
    /// `is_signer`, which only sees that something is linked. Decides
    /// whether the dashboard's Safe mode survives an update, which Safes
    /// the account dropdown offers, and what removing an account warns
    /// about.
    pub fn has_signing_link(&self, accounts: &[AccountDescriptor]) -> bool {
        self.signing_links(accounts).next().is_some()
    }

    pub fn address(&self) -> Address {
        Address::from(self.address)
    }

    /// Transaction-service base URL this Safe actually talks to — the
    /// custom mirror when set, the public default otherwise.
    pub fn tx_service_base(&self) -> &str {
        self.tx_service_url
            .as_deref()
            .unwrap_or(crate::safe::service::DEFAULT_TX_SERVICE_BASE)
    }
}

/// True if `account_idx` is listed as a linked signer of any Safe in
/// `safes`. Drives the dashboard's "Safe signer" cross-badge on
/// account rows so users can see at a glance which keys are
/// load-bearing for a multisig.
///
/// Free function (not a `WalletDescriptor` method) so the dashboard's
/// account-list view can call it with just the `&[SafeDescriptor]`
/// slice it already has — the view doesn't see the whole wallet.
pub fn account_is_safe_signer(account_idx: u32, safes: &[SafeDescriptor]) -> bool {
    safes
        .iter()
        .any(|s| s.linked_signer_indices.contains(&account_idx))
}

/// Compute the Ethereum address for an account descriptor. Returns None if a
/// `Local` variant carries unrecoverable key bytes (shouldn't happen for any
/// account that survived persistence, but the call is fallible upstream).
pub fn account_address(account: &AccountDescriptor) -> Option<Address> {
    match account {
        AccountDescriptor::Local { key_bytes, .. } => {
            let b = key_bytes.to_b256();
            signer_from_bytes(&b).ok().map(|s| s.address())
        }
        AccountDescriptor::Ledger { address, .. }
        | AccountDescriptor::Trezor { address, .. }
        | AccountDescriptor::ViewOnly { address, .. } => Some(Address::from(*address)),
    }
}

/// Serializable mirror of `alloy::signers::ledger::HDPath`. Kept separate so
/// we don't depend on alloy's serde derives (the upstream type doesn't have
/// them) and so we can reason about persistence stability ourselves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LedgerHdPath {
    LedgerLive(u32),
    Legacy(u32),
    Other(String),
}

impl LedgerHdPath {
    pub fn to_alloy(&self) -> AlloyLedgerHDPath {
        match self {
            LedgerHdPath::LedgerLive(i) => AlloyLedgerHDPath::LedgerLive(*i as usize),
            LedgerHdPath::Legacy(i) => AlloyLedgerHDPath::Legacy(*i as usize),
            LedgerHdPath::Other(s) => AlloyLedgerHDPath::Other(s.clone()),
        }
    }
}

/// Serializable mirror of `alloy::signers::trezor::HDPath`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrezorHdPath {
    TrezorLive(u32),
    Other(String),
}

impl TrezorHdPath {
    pub fn to_alloy(&self) -> AlloyTrezorHDPath {
        match self {
            TrezorHdPath::TrezorLive(i) => AlloyTrezorHDPath::TrezorLive(*i as usize),
            TrezorHdPath::Other(s) => AlloyTrezorHDPath::Other(s.clone()),
        }
    }
}

// ── KaoSigner ──────────────────────────────────────────────────────────────

/// Live, runtime form of the user's signer. Held by the wallet dashboard
/// for as long as the app is unlocked. Hardware variants own a USB transport
/// so the device must remain plugged in for the session.
///
/// `ViewOnly` is a placeholder that carries just the watched address — it
/// can answer `address()` but can't sign. The dashboard treats it as a
/// read-only account.
pub enum KaoSigner {
    Local(PrivateKeySigner),
    Ledger(LedgerSigner),
    Trezor(TrezorSigner),
    ViewOnly(Address),
}

impl std::fmt::Debug for KaoSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KaoSigner::Local(_) => f.write_str("KaoSigner::Local(..)"),
            KaoSigner::Ledger(_) => f.write_str("KaoSigner::Ledger(..)"),
            KaoSigner::Trezor(_) => f.write_str("KaoSigner::Trezor(..)"),
            KaoSigner::ViewOnly(addr) => write!(f, "KaoSigner::ViewOnly({addr})"),
        }
    }
}

impl KaoSigner {
    pub fn address(&self) -> Address {
        match self {
            KaoSigner::Local(s) => s.address(),
            KaoSigner::Ledger(s) => Signer::address(s),
            KaoSigner::Trezor(s) => Signer::address(s),
            KaoSigner::ViewOnly(addr) => *addr,
        }
    }

    /// Whether this signer can produce signatures. `false` for `ViewOnly`.
    pub fn can_sign(&self) -> bool {
        !matches!(self, KaoSigner::ViewOnly(_))
    }

    /// Sign a SignableTransaction. Dispatches to `TxSigner::sign_transaction`
    /// on the inner signer — the only path that works for both software and
    /// hardware. (Ledger and Trezor's `Signer::sign_hash` returns
    /// `UnsupportedOperation`; the device signs over the RLP-encoded tx, not
    /// a precomputed hash, so we have to hand it the structured tx.)
    ///
    /// Hardware variants are constructed with `chain_id = None`, so the
    /// chain id baked into the tx envelope is the one that gets signed —
    /// no per-chain reconstruction of the signer needed.
    ///
    /// `ViewOnly` returns `UnsupportedOperation(SignTransaction)`.
    pub async fn sign_tx(
        &self,
        tx: &mut dyn SignableTransaction<Signature>,
    ) -> Result<Signature, alloy::signers::Error> {
        match self {
            KaoSigner::Local(s) => TxSigner::sign_transaction(s, tx).await,
            KaoSigner::Ledger(s) => TxSigner::sign_transaction(s, tx).await,
            KaoSigner::Trezor(s) => TxSigner::sign_transaction(s, tx).await,
            KaoSigner::ViewOnly(_) => Err(alloy::signers::Error::UnsupportedOperation(
                alloy::signers::UnsupportedSignerOperation::SignTransaction,
            )),
        }
    }

    /// Sign a precomputed 32-byte hash as bare `r ‖ s ‖ v` with
    /// `v ∈ {27, 28}`. The Safe flow no longer calls this directly — it
    /// drives every owner through [`Self::sign_eip712`] so software and
    /// hardware share one path — but it's retained as the reference the
    /// `local_eip712_matches_sign_hash` test pins that path against.
    ///
    /// Hardware variants return `UnsupportedOperation` on purpose:
    /// Ledger's Ethereum app refuses bare-hash signing under its
    /// blind-signing policy, and Trezor likewise. Device EIP-712
    /// signing goes through [`Self::sign_eip712`] /
    /// [`Self::sign_typed_json`] instead (Ledger only — see there).
    /// `ViewOnly` has no key.
    #[allow(dead_code)]
    pub async fn sign_hash(&self, hash: B256) -> Result<Signature, alloy::signers::Error> {
        match self {
            KaoSigner::Local(s) => s.sign_hash(&hash).await,
            KaoSigner::Ledger(_) | KaoSigner::Trezor(_) | KaoSigner::ViewOnly(_) => {
                Err(alloy::signers::Error::UnsupportedOperation(
                    alloy::signers::UnsupportedSignerOperation::SignHash,
                ))
            }
        }
    }

    /// Sign an EIP-7702 authorization tuple (`chain_id`, delegate `address`,
    /// `nonce`) so the account can delegate its code to a batch-executor.
    ///
    /// Unlike `sign_hash`, hardware **is** supported here: the authorization
    /// is a first-class signing object the device recognises, not a bare
    /// blind hash. `Local` hashes the tuple locally (`signature_hash`);
    /// `Ledger` streams it over the `SIGN_EIP7702_AUTHORIZATION` APDU
    /// (`sign_auth`), which clear-signs the delegate address on-device.
    ///
    /// `Trezor` has no 7702 APDU in `alloy-signer-trezor` yet, and
    /// `ViewOnly` has no key → both `UnsupportedOperation`.
    ///
    /// The recovered authority is checked against this signer's own address
    /// before the signature is returned. An authorization whose signature
    /// doesn't recover to the account it delegates is not a loud failure on
    /// chain — the authorization list entry is simply *skipped*, the account
    /// keeps no code, and the batch that follows becomes a call into a
    /// code-less address, which **succeeds while doing nothing**. Every caller
    /// inherits the check from here rather than re-deriving it.
    pub async fn sign_authorization(
        &self,
        auth: &Authorization,
    ) -> Result<SignedAuthorization, alloy::signers::Error> {
        let signed = match self {
            KaoSigner::Local(s) => {
                let sig = s.sign_hash(&auth.signature_hash()).await?;
                auth.clone().into_signed(sig)
            }
            KaoSigner::Ledger(s) => {
                let sig = s
                    .sign_auth(auth)
                    .await
                    .map_err(alloy::signers::Error::other)?;
                auth.clone().into_signed(sig)
            }
            KaoSigner::Trezor(_) | KaoSigner::ViewOnly(_) => {
                return Err(alloy::signers::Error::UnsupportedOperation(
                    alloy::signers::UnsupportedSignerOperation::SignHash,
                ));
            }
        };
        let expected = self.address();
        match signed.recover_authority() {
            Ok(got) if got == expected => Ok(signed),
            Ok(got) => {
                tracing::warn!(%expected, recovered = %got, "7702: authorization recovers to the wrong authority");
                Err(alloy::signers::Error::other(format!(
                    "authorization signature recovers to {got}, not {expected} — refusing to \
                     delegate"
                )))
            }
            Err(e) => Err(alloy::signers::Error::other(format!(
                "could not recover the authority from the authorization signature: {e}"
            ))),
        }
    }

    /// Whether this signer can produce an EIP-7702 authorization — the gate
    /// for offering atomic EOA batching. Local (software) and Ledger only;
    /// Trezor/view-only fall back to single-call sends.
    pub fn supports_7702(&self) -> bool {
        matches!(self, KaoSigner::Local(_) | KaoSigner::Ledger(_))
    }

    /// Sign an EIP-712 typed-data payload (e.g. a `SafeTx`) — the path
    /// that makes **Ledger** Safe signing work where `sign_hash` does
    /// not. Each inner signer's `sign_typed_data` drives its native
    /// EIP-712 flow: software hashes locally; Ledger sends the domain
    /// separator + struct hash to the device (APDU `0x0C`, the
    /// hashed-message EIP-712 mode its firmware permits under blind
    /// signing; Ethereum app ≥ 1.6).
    ///
    /// **Trezor has no EIP-712 path here.** `alloy-signer-trezor` 2.4.2
    /// implements neither `sign_typed_data` nor an `eip712` feature, so the
    /// call falls through the trait default to `sign_hash`, which Trezor
    /// refuses — every Trezor call fails with
    /// `UnsupportedOperation(SignHash)`. Trezor Safe owners still sign
    /// because both owner flows catch that and fall back to an `eth_sign`
    /// personal message over the hash (`v + 4`): `safe::tx::sign_owner` and
    /// `cow::safe_sig::sign_eip1271_digest`. Callers without such a
    /// fallback (CoW orders from a Trezor EOA) fail.
    ///
    /// For `Local` this is byte-identical to `sign_hash` over
    /// `payload.eip712_signing_hash(domain)` — verified by
    /// `local_eip712_matches_sign_hash`. The produced `v` is `{27,28}`,
    /// exactly what `pack_owner_signatures` expects.
    ///
    /// `ViewOnly` has no key → `UnsupportedOperation`.
    pub async fn sign_eip712<T: SolStruct + Send + Sync>(
        &self,
        payload: &T,
        domain: &Eip712Domain,
    ) -> Result<Signature, alloy::signers::Error> {
        match self {
            KaoSigner::Local(s) => s.sign_typed_data(payload, domain).await,
            KaoSigner::Ledger(s) => s.sign_typed_data(payload, domain).await,
            KaoSigner::Trezor(s) => s.sign_typed_data(payload, domain).await,
            KaoSigner::ViewOnly(_) => Err(alloy::signers::Error::UnsupportedOperation(
                alloy::signers::UnsupportedSignerOperation::SignTypedData,
            )),
        }
    }

    /// EIP-712 over dapp JSON. Local: hash locally. Ledger:
    /// `sign_dynamic_typed_data` (APDU 0x0C "v0": the device shows only the
    /// domain hash and message hash; app ≥ 1.6). Trezor / ViewOnly: explicit
    /// `UnsupportedOperation(SignTypedData)` — alloy-signer-trezor 2.4.2 has no
    /// EIP-712.
    ///
    /// Both signing paths commit to `keccak256(0x1901 ‖ domain.separator() ‖
    /// hashStruct(message))` — the ERC-8213 triple the review shows — with one
    /// exception this refuses outright: `primaryType == "EIP712Domain"`, where
    /// alloy hashes locally over the 34-byte `0x1901 ‖ separator` (the
    /// eth-sig-util convention) but a Ledger is still sent a struct hash, so the
    /// two devices would sign different digests for the same review. Trezor is
    /// refused explicitly rather than left to the trait default, whose
    /// `UnsupportedOperation(SignHash)` would misname what is missing.
    ///
    /// The caller still owns the `from == signer` check: recover the result
    /// over the reviewed digest (`sign::recover::assert_prehash_signer`).
    pub async fn sign_typed_json(
        &self,
        td: &alloy::dyn_abi::TypedData,
    ) -> Result<Signature, alloy::signers::Error> {
        if td.primary_type == "EIP712Domain" {
            return Err(alloy::signers::Error::other(
                "refusing to sign typed data whose primary type is EIP712Domain",
            ));
        }
        match self {
            KaoSigner::Local(s) => s.sign_dynamic_typed_data(td).await,
            KaoSigner::Ledger(s) => s.sign_dynamic_typed_data(td).await,
            KaoSigner::Trezor(_) | KaoSigner::ViewOnly(_) => {
                Err(alloy::signers::Error::UnsupportedOperation(
                    alloy::signers::UnsupportedSignerOperation::SignTypedData,
                ))
            }
        }
    }

    /// Produce an EIP-191 `personal_sign` signature over `message`. The
    /// Safe `eth_sign` fallback (`v ∈ {31,32}`) builds on this for
    /// devices/app-versions that reject EIP-712; the Safe-specific `+4`
    /// `v` adjustment is applied at packing time in `safe::tx`, since
    /// the EIP-191 prefix Safe expects (`"\x19Ethereum Signed
    /// Message:\n32"` over the 32-byte safeTxHash) is exactly what
    /// `Signer::sign_message` emits.
    ///
    /// `ViewOnly` has no key → `UnsupportedOperation`.
    pub async fn sign_eth_message(
        &self,
        message: &[u8],
    ) -> Result<Signature, alloy::signers::Error> {
        match self {
            KaoSigner::Local(s) => s.sign_message(message).await,
            KaoSigner::Ledger(s) => s.sign_message(message).await,
            KaoSigner::Trezor(s) => s.sign_message(message).await,
            KaoSigner::ViewOnly(_) => Err(alloy::signers::Error::UnsupportedOperation(
                alloy::signers::UnsupportedSignerOperation::SignMessage,
            )),
        }
    }
}

/// Turn a raw signer error into a line a human can act on.
///
/// Hardware wallets surface the bare APDU status word from the device, which is
/// opaque ("APDU Response error `Code 6985 …`"). The two cases users actually
/// hit on a contract call both come back as `6985 CONDITIONS_NOT_SATISFIED`:
/// declining the on-device prompt, and having **Blind signing** disabled in the
/// Ledger Ethereum app (it refuses calldata it can't decode). Since our name /
/// swap / Safe calls can't be clear-signed, those collapse into one actionable
/// message instead of leaking the status word. A locked device (`6804`) or a
/// wrong / closed app (`6e00`, `6d00`) gets a reach-the-device hint, as does a
/// locked Trezor (whose PIN request the client mis-surfaces as a "network not
/// supported" error); everything else falls back to the raw text so we never
/// hide a genuinely novel failure.
pub fn friendly_signer_error(e: &alloy::signers::Error) -> String {
    friendly_signer_error_text(&e.to_string())
}

/// What an EIP-712 signing failure says about signing the same 32-byte hash as
/// a personal message (`eth_sign`) instead — the fallback Safe owner signing
/// has for signers without EIP-712.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eip712Failure {
    /// The signer has no EIP-712 path and nothing was shown on a device: a
    /// Trezor or a view-only key (`UnsupportedOperation`), or a Ledger Ethereum
    /// app too old for EIP-712 (refused by the version check that runs before
    /// any signing prompt).
    Unavailable,
    /// The Ledger was sent the EIP-712 hashes and answered with a refusal: the
    /// user declined the prompt, or Blind signing is off (both `6985`), or the
    /// app rejected the request. The user has seen — and may have declined — a
    /// prompt for this very hash.
    DeviceRefused,
    /// Anything else: a locked or unreachable device, the wrong app open, a
    /// transport error. A personal-message prompt would fail the same way.
    Other,
}

/// Classify an EIP-712 signing failure (see [`Eip712Failure`]). Ledger errors
/// are read from the typed APDU status, never from their text.
pub fn classify_eip712_failure(e: &alloy::signers::Error) -> Eip712Failure {
    use alloy::signers::ledger::{LedgerError, coins_ledger};
    use coins_ledger::common::APDUResponseCodes as Sw;
    match e {
        alloy::signers::Error::UnsupportedOperation(_) => Eip712Failure::Unavailable,
        alloy::signers::Error::Other(inner) => match inner.downcast_ref::<LedgerError>() {
            Some(LedgerError::UnsupportedAppVersion(_)) => Eip712Failure::Unavailable,
            Some(LedgerError::LedgerError(coins_ledger::LedgerError::BadRetcode(code))) => {
                match code {
                    // Locked, or not the Ethereum app: nothing was shown.
                    Sw::UnlockDeviceError | Sw::InsNotSupported | Sw::ClaNotSupported => {
                        Eip712Failure::Other
                    }
                    _ => Eip712Failure::DeviceRefused,
                }
            }
            _ => Eip712Failure::Other,
        },
        _ => Eip712Failure::Other,
    }
}

/// Inner string-matcher for [`friendly_signer_error`], split out so the APDU
/// classification is unit-testable without fabricating an `alloy` error.
fn friendly_signer_error_text(raw: &str) -> String {
    let low = raw.to_lowercase();
    let has = |needle: &str| low.contains(needle);
    if has("6985")
        || has("conditions_not_satisfied")
        || has("conditions of use")
        || has("denied")
        || has("rejected")
        || has("cancel")
    {
        "rejected on your hardware wallet — approve the transaction on the device, and make sure \
         \"Blind signing\" is enabled in its Ethereum app"
            .to_string()
    } else if has("given network is not supported") // Trezor mis-maps a PIN request to this
        || has("pinexpected")
        || has("pinmatrix")
    {
        "couldn't reach your Trezor — unlock it by entering your PIN, then try again".to_string()
    } else if has("6804") // device locked (coins-ledger UnlockDeviceError)
        || has("device is locked")
        || has("unlock_device")
        || has("6e00") // wrong / no app open (CLA / INS not supported)
        || has("6d00")
        || has("no device")
        || has("not found")
    {
        "couldn't reach your hardware wallet — unlock it and open the Ethereum app, then try again"
            .to_string()
    } else {
        format!("sign failed: {raw}")
    }
}

/// Construct a *live* signer for an arbitrary linked owner — used when a
/// Safe owner this wallet controls is **not** the currently-active
/// account (confirm/execute/propose from the queue). Software owners
/// rebuild from key bytes; hardware owners reconnect by their stored HD
/// path and the derived address is checked against the descriptor so a
/// wrong-device / wrong-derivation mismatch fails loudly instead of
/// signing under the wrong key.
///
/// Async because the hardware variants block on the device. `ViewOnly`
/// has no key and errors.
pub async fn build_owner_signer(desc: &AccountDescriptor) -> Result<KaoSigner, String> {
    match desc {
        AccountDescriptor::Local { key_bytes, .. } => {
            let s = signer_from_bytes(&key_bytes.to_b256()).map_err(|e| e.to_string())?;
            Ok(KaoSigner::Local(s))
        }
        AccountDescriptor::Ledger { path, address, .. } => {
            let s = LedgerSigner::new(path.to_alloy(), None)
                .await
                .map_err(|e| friendly_signer_error_text(&e.to_string()))?;
            let got = Signer::address(&s);
            let want = Address::from(*address);
            if got != want {
                // short_address: this string ends up in logs (warn! at
                // the call sites), and log lines never carry full user
                // addresses. Eight hex chars per side is plenty to tell
                // a wrong-device / wrong-path mix-up apart.
                return Err(format!(
                    "ledger address mismatch: device {} vs expected {}",
                    short_address(got),
                    short_address(want),
                ));
            }
            Ok(KaoSigner::Ledger(s))
        }
        AccountDescriptor::Trezor { path, address, .. } => {
            let s = TrezorSigner::new(path.to_alloy(), None)
                .await
                .map_err(|e| friendly_signer_error_text(&e.to_string()))?;
            let got = Signer::address(&s);
            let want = Address::from(*address);
            if got != want {
                return Err(format!(
                    "trezor address mismatch: device {} vs expected {}",
                    short_address(got),
                    short_address(want),
                ));
            }
            Ok(KaoSigner::Trezor(s))
        }
        AccountDescriptor::ViewOnly { .. } => {
            Err("view-only account has no signing key".to_string())
        }
    }
}

/// Make sure a hardware signer's device is still reachable right before we ask it
/// to sign, reconnecting it if the live transport has gone away (the device was
/// unplugged, auto-locked, or its Ethereum app closed since it was connected).
///
/// A `LedgerSigner` holds a *persistent* USB transport, so a dropped device
/// leaves a stale signer that still reports `can_sign()` — we catch that with a
/// **silent** `get_address` probe (Ledger's `NON_CONFIRM` APDU; no on-device
/// prompt) and, if it fails, rebuild the signer from its descriptor via
/// [`build_owner_signer`] (which also re-verifies the derived address). A
/// `TrezorSigner` re-finds the device on every call already, so it self-heals and
/// is passed through untouched (probing it could trigger an on-device prompt).
/// Software / view-only signers have nothing to check.
///
/// On reconnect failure the **original** signer is handed back alongside the
/// error, so the caller restores it to its handoff rather than stranding the
/// wallet as view-only — exactly the pre-existing behaviour, just after one
/// automatic reconnect attempt.
pub async fn ensure_connected(
    signer: KaoSigner,
    desc: &AccountDescriptor,
) -> Result<KaoSigner, (KaoSigner, String)> {
    // Only a Ledger can hold a stale transport; everything else either
    // self-reconnects (Trezor) or has no device (Local / ViewOnly).
    let KaoSigner::Ledger(ref s) = signer else {
        return Ok(signer);
    };
    let want = signer.address();
    match s.get_address().await {
        Ok(got) if got == want => Ok(signer), // device present, unlocked, app open
        probe => {
            match &probe {
                Ok(got) => {
                    tracing::warn!(%got, expected = %want, "ledger probe: wrong address, reconnecting")
                }
                Err(e) => tracing::debug!(error = %e, "ledger probe failed, reconnecting"),
            }
            // The held transport is (almost certainly) dead — rebuild from the
            // descriptor. `build_owner_signer` re-derives + checks the address, so
            // a wrong-device swap fails loudly rather than signing under it.
            match build_owner_signer(desc).await {
                Ok(fresh) => Ok(fresh),
                Err(e) => {
                    // `e` is already a friendly, human-readable line — build_owner_signer
                    // routes hardware-connect failures through friendly_signer_error_text
                    // (a locked device becomes "couldn't reach your hardware wallet …") —
                    // so surface it directly rather than nesting raw crate text in parens.
                    tracing::debug!(error = %e, "ledger reconnect failed");
                    Err((signer, e))
                }
            }
        }
    }
}

/// Cell used to hand a non-Clone live signer through Clone iced messages.
/// The producer fills the cell; the consumer `take()`s it out exactly once.
pub type SignerHandoff = std::sync::Arc<std::sync::Mutex<Option<KaoSigner>>>;

pub fn handoff_with(signer: KaoSigner) -> SignerHandoff {
    std::sync::Arc::new(std::sync::Mutex::new(Some(signer)))
}

// ── Software-wallet helpers (unchanged behaviour) ──────────────────────────

/// Generate a new random 12-word BIP39 mnemonic and return the phrase and the derived signer.
///
/// The phrase is wrapped in `SecretString` so its heap allocation is zeroed on
/// drop. Callers must keep it inside `SecretString` (or `Zeroizing`) for the
/// rest of its lifetime — converting to a plain `String` defeats the wrapper.
pub fn generate_mnemonic() -> Result<(SecretString, PrivateKeySigner), WalletError> {
    let mut rng = rand::thread_rng();
    let mnemonic = coins_bip39::Mnemonic::<English>::new_with_count(&mut rng, 12)
        .map_err(|e: coins_bip39::MnemonicError| WalletError::Mnemonic(e.to_string()))?;
    let phrase = mnemonic.to_phrase();
    let signer = MnemonicBuilder::<English>::default()
        .phrase(&phrase)
        .build()
        .map_err(|e| WalletError::Mnemonic(e.to_string()))?;
    Ok((SecretString::new(phrase.into_boxed_str()), signer))
}

/// Generate a fresh random **24-word** BIP39 mnemonic for Privacy Pools.
///
/// This is a *dedicated* pool seed, independent of the wallet's own seed (which
/// Kao never persists). One phrase derives every pool account, so it is a
/// keyring root, not a per-account key. Returned wrapped in `SecretString`; keep
/// it inside `SecretString`/`Zeroizing` for its whole lifetime.
pub fn generate_pp_mnemonic() -> Result<SecretString, WalletError> {
    let mut rng = rand::thread_rng();
    let mnemonic = coins_bip39::Mnemonic::<English>::new_with_count(&mut rng, 24)
        .map_err(|e: coins_bip39::MnemonicError| WalletError::Mnemonic(e.to_string()))?;
    Ok(SecretString::new(mnemonic.to_phrase().into_boxed_str()))
}

/// Validate that a string is a well-formed BIP39 mnemonic (12 or 24 words).
pub fn validate_mnemonic(phrase: &str) -> Result<(), WalletError> {
    MnemonicBuilder::<English>::default()
        .phrase(phrase)
        .build()
        .map(|_| ())
        .map_err(|e| WalletError::Mnemonic(e.to_string()))
}

/// Derive the BIP32 parent key (m/44'/60'/0'/0) from a mnemonic phrase.
///
/// This is the expensive step — PBKDF2-HMAC-SHA512 with 2048 rounds — so callers
/// should run it off the UI thread and reuse the returned key when paging through
/// child accounts.
pub type HdParentKey = MnemonicKey;

pub fn derive_parent_key(phrase: &str) -> Result<HdParentKey, WalletError> {
    MnemonicBuilder::<English>::default()
        .phrase(phrase)
        .build_parent_key()
        .map_err(|e| WalletError::Mnemonic(e.to_string()))
}

/// Derive `count` child signers from an already-built parent key.
/// Returns (hd_index, signer) pairs starting at m/44'/60'/0'/0/{start}.
pub fn derive_accounts_from(
    parent: &HdParentKey,
    start: u32,
    count: u32,
) -> Result<Vec<(u32, PrivateKeySigner)>, WalletError> {
    parent
        .children_from(start)
        .take(count as usize)
        .enumerate()
        .map(|(i, result)| {
            result
                .map(|signer| (start + i as u32, signer))
                .map_err(|e| WalletError::Mnemonic(e.to_string()))
        })
        .collect()
}

/// Build a signer directly from raw private key bytes.
pub fn signer_from_bytes(key_bytes: &B256) -> Result<PrivateKeySigner, WalletError> {
    PrivateKeySigner::from_bytes(key_bytes).map_err(|e| WalletError::Mnemonic(e.to_string()))
}

/// Get the Ethereum address from a signer.
pub fn signer_address(signer: &PrivateKeySigner) -> Address {
    signer.address()
}

/// Convenience: build a `Local` account descriptor from a software signer.
pub fn local_account(signer: &PrivateKeySigner) -> AccountDescriptor {
    let bytes: [u8; 32] = signer.to_bytes().0;
    AccountDescriptor::Local {
        name: None,
        key_bytes: SecretKeyBytes::new(bytes),
    }
}

/// Convenience: build a `ViewOnly` account descriptor from an address.
pub fn view_only_account(address: Address) -> AccountDescriptor {
    AccountDescriptor::ViewOnly {
        name: None,
        address: address.into_array(),
    }
}

/// Render an Ethereum address as `0xabcd…ef01`. Used for log lines so
/// debug/trace output doesn't print full user addresses, and for compact
/// display in the UI.
pub fn short_address(a: Address) -> String {
    let full = format!("{a}");
    if full.len() >= 12 {
        format!("{}…{}", &full[..6], &full[full.len() - 4..])
    } else {
        full
    }
}

/// Render the address an `AccountDescriptor` resolves to in short form. For
/// `Local` accounts this derives the address from the key bytes (cheap —
/// secp256k1 pubkey + keccak). Returns `0x????…????` if the key bytes are
/// somehow unrecoverable, which shouldn't happen for any account that
/// survived persistence.
pub fn account_short_address(account: &AccountDescriptor) -> String {
    match account_address(account) {
        Some(addr) => short_address(addr),
        None => "0x????…????".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;

    /// Which EIP-712 failures leave a personal-message signature of the same hash as a silent
    /// fallback (nothing was shown), which mean the device showed the prompt and refused it, and
    /// which are neither — read from the typed errors the signers return.
    #[test]
    fn eip712_failures_are_classified_from_the_typed_error() {
        use alloy::signers::ledger::{LedgerError, coins_ledger};
        use coins_ledger::common::APDUResponseCodes as Sw;
        let ledger = |e: LedgerError| alloy::signers::Error::other(e);
        let status = |sw: Sw| ledger(LedgerError::LedgerError(sw.into()));
        assert_eq!(
            classify_eip712_failure(&alloy::signers::Error::UnsupportedOperation(
                alloy::signers::UnsupportedSignerOperation::SignHash
            )),
            Eip712Failure::Unavailable,
            "a Trezor or view-only key"
        );
        assert_eq!(
            classify_eip712_failure(&ledger(LedgerError::UnsupportedAppVersion(">=1.6.0"))),
            Eip712Failure::Unavailable,
            "an old Ledger app, refused before any prompt"
        );
        for sw in [
            Sw::ConditionsNotSatisfied,
            Sw::InvalidData,
            Sw::CommandNotAllowed,
        ] {
            assert_eq!(
                classify_eip712_failure(&status(sw)),
                Eip712Failure::DeviceRefused,
                "{sw:?}"
            );
        }
        for sw in [
            Sw::UnlockDeviceError,
            Sw::InsNotSupported,
            Sw::ClaNotSupported,
        ] {
            assert_eq!(
                classify_eip712_failure(&status(sw)),
                Eip712Failure::Other,
                "{sw:?}"
            );
        }
        assert_eq!(
            classify_eip712_failure(&ledger(LedgerError::UnexpectedNullResponse)),
            Eip712Failure::Other
        );
        // A message that merely reads like a refusal is not a device status.
        assert_eq!(
            classify_eip712_failure(&alloy::signers::Error::message("Code 6985")),
            Eip712Failure::Other
        );
    }

    #[test]
    fn friendly_signer_error_maps_ledger_apdu_codes() {
        // The exact string a declining / blind-signing-disabled Ledger surfaces.
        let rejected = friendly_signer_error_text(
            "Ledger device: APDU Response error `Code 6985 \
             ([APDU_CODE_CONDITIONS_NOT_SATISFIED] Conditions of use not satisfied)`",
        );
        assert!(rejected.contains("Blind signing"), "got: {rejected}");
        assert!(
            !rejected.contains("6985"),
            "raw APDU code leaked: {rejected}"
        );

        // Locked device → the reach-the-device hint. 0x6804 is the *real*
        // "device is locked" status word (coins-ledger `UnlockDeviceError`); the
        // fictitious 6511 this used to assert on never reaches the device.
        let locked = friendly_signer_error_text(
            "Ledger device: APDU Response error `Code 6804 \
             ([APDU_CODE_UNLOCK_DEVICE_ERROR] Device is locked)`",
        );
        assert!(locked.contains("open the Ethereum app"), "got: {locked}");
        assert!(!locked.contains("6804"), "raw APDU code leaked: {locked}");

        // Wrong / closed app (CLA-not-supported) → same reach-the-device hint.
        let wrong_app = friendly_signer_error_text("Ledger device: APDU error `Code 6e00`");
        assert!(
            wrong_app.contains("open the Ethereum app"),
            "got: {wrong_app}"
        );

        // A locked Trezor's PIN request surfaces (mis-mapped) as a network error;
        // it collapses into a PIN hint rather than leaking the jargon.
        let trezor_locked = friendly_signer_error_text("given network is not supported");
        assert!(trezor_locked.contains("PIN"), "got: {trezor_locked}");
        assert!(
            !trezor_locked.contains("network is not supported"),
            "raw Trezor jargon leaked: {trezor_locked}"
        );

        // Anything we don't recognise is passed through verbatim (prefixed),
        // so a novel failure is never hidden behind a canned message.
        let other = friendly_signer_error_text("nonce too low");
        assert_eq!(other, "sign failed: nonce too low");
    }

    #[test]
    fn account_postcard_roundtrip_local() {
        let acc = AccountDescriptor::Local {
            name: Some("Treasury".into()),
            key_bytes: crate::wallet::SecretKeyBytes::new([0xab; 32]),
        };
        let encoded = postcard::to_stdvec(&acc).unwrap();
        let decoded: AccountDescriptor = postcard::from_bytes(&encoded).unwrap();
        match decoded {
            AccountDescriptor::Local { name, key_bytes } => {
                assert_eq!(name.as_deref(), Some("Treasury"));
                assert_eq!(key_bytes.as_array(), &[0xab; 32]);
            }
            _ => panic!("expected Local"),
        }
    }

    /// On-disk format guard: a wallet file written by the *old* code, where
    /// `Local::key_bytes` was a bare `[u8; 32]`, must still load now that the
    /// field is `SecretKeyBytes`. We reproduce the exact old wire shape with a
    /// mirror enum (same variant order, bare array) and confirm it decodes
    /// into the real type byte-for-byte. If this ever breaks, existing wallets
    /// would fail to open — treat a failure here as a hard backwards-compat
    /// regression, not a test to "fix".
    #[test]
    fn account_local_decodes_legacy_bare_key_bytes_layout() {
        #[derive(Serialize)]
        enum LegacyAccountDescriptor {
            Local {
                name: Option<String>,
                key_bytes: [u8; 32],
            },
            #[allow(dead_code)]
            Ledger {
                name: Option<String>,
                path: LedgerHdPath,
                address: [u8; 20],
            },
        }

        let legacy = LegacyAccountDescriptor::Local {
            name: Some("Treasury".into()),
            key_bytes: [0xab; 32],
        };
        let legacy_bytes = postcard::to_stdvec(&legacy).unwrap();

        // Same bytes the current type produces — proves the wire format is
        // unchanged in both directions.
        let current = AccountDescriptor::Local {
            name: Some("Treasury".into()),
            key_bytes: SecretKeyBytes::new([0xab; 32]),
        };
        assert_eq!(legacy_bytes, postcard::to_stdvec(&current).unwrap());

        let decoded: AccountDescriptor = postcard::from_bytes(&legacy_bytes).unwrap();
        match decoded {
            AccountDescriptor::Local { name, key_bytes } => {
                assert_eq!(name.as_deref(), Some("Treasury"));
                assert_eq!(key_bytes.as_array(), &[0xab; 32]);
            }
            _ => panic!("expected Local"),
        }
    }

    /// `SecretKeyBytes` must never leak its contents through `Debug` — an
    /// accidental `{:?}` on an `AccountDescriptor` (or a panic backtrace
    /// formatting one) must not print the private key.
    #[test]
    fn secret_key_bytes_debug_is_redacted() {
        let acc = AccountDescriptor::Local {
            name: Some("Treasury".into()),
            key_bytes: SecretKeyBytes::new([0xab; 32]),
        };
        let rendered = format!("{acc:?}");
        assert!(rendered.contains("redacted"), "got: {rendered}");
        assert!(
            !rendered.contains("ab"),
            "key bytes leaked into Debug: {rendered}"
        );
    }

    #[test]
    fn account_postcard_roundtrip_ledger() {
        let acc = AccountDescriptor::Ledger {
            name: None,
            path: LedgerHdPath::LedgerLive(3),
            address: [0x11; 20],
        };
        let encoded = postcard::to_stdvec(&acc).unwrap();
        let decoded: AccountDescriptor = postcard::from_bytes(&encoded).unwrap();
        match decoded {
            AccountDescriptor::Ledger {
                name,
                path,
                address,
            } => {
                assert!(name.is_none());
                assert!(matches!(path, LedgerHdPath::LedgerLive(3)));
                assert_eq!(address, [0x11; 20]);
            }
            _ => panic!("expected Ledger"),
        }
    }

    #[test]
    fn account_postcard_roundtrip_trezor() {
        let acc = AccountDescriptor::Trezor {
            name: None,
            path: TrezorHdPath::TrezorLive(2),
            address: [0x22; 20],
        };
        let encoded = postcard::to_stdvec(&acc).unwrap();
        let decoded: AccountDescriptor = postcard::from_bytes(&encoded).unwrap();
        match decoded {
            AccountDescriptor::Trezor {
                name,
                path,
                address,
            } => {
                assert!(name.is_none());
                assert!(matches!(path, TrezorHdPath::TrezorLive(2)));
                assert_eq!(address, [0x22; 20]);
            }
            _ => panic!("expected Trezor"),
        }
    }

    #[test]
    fn wallet_descriptor_postcard_roundtrip() {
        let desc = WalletDescriptor {
            accounts: vec![
                AccountDescriptor::Local {
                    name: None,
                    key_bytes: crate::wallet::SecretKeyBytes::new([0x11; 32]),
                },
                AccountDescriptor::Ledger {
                    name: None,
                    path: LedgerHdPath::LedgerLive(2),
                    address: [0x22; 20],
                },
            ],
            safes: Vec::new(),
            active_index: 1,
            sibling_links_repaired: true,
        };
        let encoded = postcard::to_stdvec(&desc).unwrap();
        let decoded: WalletDescriptor = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.accounts.len(), 2);
        assert_eq!(decoded.active_index, 1);
        assert!(matches!(
            decoded.accounts[0],
            AccountDescriptor::Local { .. }
        ));
        assert!(matches!(
            decoded.accounts[1],
            AccountDescriptor::Ledger { .. }
        ));
    }

    /// Hardhat / Anvil's default mnemonic. Anyone with a JS or Solidity
    /// background already knows the first three derived addresses by heart, so
    /// any divergence from these vectors is an obvious red flag.
    const HARDHAT_PHRASE: &str = "test test test test test test test test test test test junk";

    #[test]
    fn validate_mnemonic_accepts_valid_phrase() {
        assert!(validate_mnemonic(HARDHAT_PHRASE).is_ok());
    }

    #[test]
    fn validate_mnemonic_rejects_bad_checksum() {
        // Replace the final word so the checksum no longer matches.
        let bad = "test test test test test test test test test test test test";
        assert!(matches!(
            validate_mnemonic(bad),
            Err(WalletError::Mnemonic(_)),
        ));
    }

    #[test]
    fn validate_mnemonic_rejects_wrong_word_count() {
        let too_short = "test test test test test";
        assert!(matches!(
            validate_mnemonic(too_short),
            Err(WalletError::Mnemonic(_)),
        ));
    }

    #[test]
    fn validate_mnemonic_rejects_non_bip39_words() {
        let bad = "zzzzz zzzzz zzzzz zzzzz zzzzz zzzzz \
                   zzzzz zzzzz zzzzz zzzzz zzzzz zzzzz";
        assert!(matches!(
            validate_mnemonic(bad),
            Err(WalletError::Mnemonic(_)),
        ));
    }

    #[test]
    fn derive_accounts_matches_hardhat_vectors() {
        let parent = derive_parent_key(HARDHAT_PHRASE).expect("parent key");
        let accounts = derive_accounts_from(&parent, 0, 3).expect("derive 3");
        let expected: [Address; 3] = [
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
                .parse()
                .unwrap(),
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
                .parse()
                .unwrap(),
            "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
                .parse()
                .unwrap(),
        ];
        for (i, want) in expected.iter().enumerate() {
            assert_eq!(accounts[i].0, i as u32, "hd_index for account {i}");
            assert_eq!(accounts[i].1.address(), *want, "address for account {i}");
        }
    }

    #[test]
    fn derive_accounts_with_offset_skips_earlier() {
        let parent = derive_parent_key(HARDHAT_PHRASE).unwrap();
        let from_zero = derive_accounts_from(&parent, 0, 5).unwrap();
        let from_two = derive_accounts_from(&parent, 2, 3).unwrap();
        // The slice starting at 2 must equal the corresponding tail of [0..5].
        for (offset, (idx, signer)) in from_two.iter().enumerate() {
            assert_eq!(*idx, (offset as u32) + 2);
            assert_eq!(signer.address(), from_zero[offset + 2].1.address());
        }
    }

    #[test]
    fn signer_from_bytes_rejects_zero_key() {
        assert!(signer_from_bytes(&B256::ZERO).is_err());
    }

    #[test]
    fn account_address_view_only_returns_input() {
        let addr: Address = "0x000000000000000000000000000000000000dEaD"
            .parse()
            .unwrap();
        let view = AccountDescriptor::ViewOnly {
            name: None,
            address: addr.into_array(),
        };
        assert_eq!(account_address(&view), Some(addr));
    }

    #[test]
    fn account_address_local_matches_signer_address() {
        let parent = derive_parent_key(HARDHAT_PHRASE).unwrap();
        let (_, signer) = &derive_accounts_from(&parent, 0, 1).unwrap()[0];
        let key_bytes = SecretKeyBytes::new(signer.to_bytes().0);
        let acc = AccountDescriptor::Local {
            name: None,
            key_bytes,
        };
        assert_eq!(account_address(&acc), Some(signer.address()));
    }

    #[test]
    fn wallet_descriptor_active_clamps_when_index_too_large() {
        let desc = WalletDescriptor {
            accounts: vec![AccountDescriptor::Local {
                name: None,
                key_bytes: crate::wallet::SecretKeyBytes::new([0xab; 32]),
            }],
            safes: Vec::new(),
            // Bogus index larger than accounts.len(); active() must clamp.
            active_index: 99,
            sibling_links_repaired: true,
        };
        match desc.active() {
            AccountDescriptor::Local { key_bytes, .. } => {
                assert_eq!(key_bytes.as_array(), &[0xab; 32])
            }
            _ => panic!("expected Local"),
        }
    }

    #[test]
    fn display_name_falls_back_to_indexed_default() {
        let unnamed = AccountDescriptor::Local {
            name: None,
            key_bytes: crate::wallet::SecretKeyBytes::new([0x42; 32]),
        };
        assert_eq!(unnamed.display_name(0), "Account 1");
        assert_eq!(unnamed.display_name(4), "Account 5");

        let named = AccountDescriptor::Local {
            name: Some("Cold Storage".into()),
            key_bytes: crate::wallet::SecretKeyBytes::new([0x42; 32]),
        };
        assert_eq!(named.display_name(0), "Cold Storage");
    }

    #[test]
    fn set_name_trims_and_collapses_blank_to_none() {
        let mut acc = AccountDescriptor::ViewOnly {
            name: Some("old".into()),
            address: [0; 20],
        };
        acc.set_name(Some("  Treasury  ".into()));
        assert_eq!(acc.name(), Some("Treasury"));

        acc.set_name(Some("   ".into()));
        assert_eq!(acc.name(), None);

        acc.set_name(Some("Anvil".into()));
        acc.set_name(None);
        assert_eq!(acc.name(), None);
    }

    #[test]
    fn wallet_descriptor_contains_address_after_local_add() {
        let parent = derive_parent_key(HARDHAT_PHRASE).unwrap();
        let (_, signer) = &derive_accounts_from(&parent, 0, 1).unwrap()[0];
        let addr = signer.address();
        let desc = WalletDescriptor::single(local_account(signer));
        assert!(desc.contains_address(addr));
        let other: Address = "0x000000000000000000000000000000000000dEaD"
            .parse()
            .unwrap();
        assert!(!desc.contains_address(other));
    }

    #[test]
    fn convenience_constructors_default_to_no_name() {
        let parent = derive_parent_key(HARDHAT_PHRASE).unwrap();
        let (_, signer) = &derive_accounts_from(&parent, 0, 1).unwrap()[0];
        assert!(local_account(signer).name().is_none());
        let addr: Address = "0x000000000000000000000000000000000000dEaD"
            .parse()
            .unwrap();
        assert!(view_only_account(addr).name().is_none());
    }

    #[test]
    fn account_address_ledger_returns_stored_address() {
        let bytes = [0xab; 20];
        let acc = AccountDescriptor::Ledger {
            name: None,
            path: LedgerHdPath::LedgerLive(0),
            address: bytes,
        };
        assert_eq!(account_address(&acc), Some(Address::from(bytes)));
    }

    #[test]
    fn account_address_trezor_returns_stored_address() {
        let bytes = [0xcd; 20];
        let acc = AccountDescriptor::Trezor {
            name: None,
            path: TrezorHdPath::TrezorLive(0),
            address: bytes,
        };
        assert_eq!(account_address(&acc), Some(Address::from(bytes)));
    }

    #[test]
    fn ledger_hd_path_to_alloy_round_trips_variants() {
        // Pin each variant's enum-discriminator translation so a future
        // `AlloyLedgerHDPath` enum reorder can't silently swap LedgerLive
        // and Legacy paths.
        let live = LedgerHdPath::LedgerLive(3).to_alloy();
        assert!(matches!(live, AlloyLedgerHDPath::LedgerLive(3)));
        let legacy = LedgerHdPath::Legacy(2).to_alloy();
        assert!(matches!(legacy, AlloyLedgerHDPath::Legacy(2)));
        let other = LedgerHdPath::Other("m/44'/60'/1'/0/0".into()).to_alloy();
        match other {
            AlloyLedgerHDPath::Other(s) => assert_eq!(s, "m/44'/60'/1'/0/0"),
            _ => panic!("expected Other"),
        }
    }

    #[test]
    fn trezor_hd_path_to_alloy_round_trips_variants() {
        let live = TrezorHdPath::TrezorLive(7).to_alloy();
        assert!(matches!(live, AlloyTrezorHDPath::TrezorLive(7)));
        let other = TrezorHdPath::Other("m/44'/60'/2'/0/0".into()).to_alloy();
        match other {
            AlloyTrezorHDPath::Other(s) => assert_eq!(s, "m/44'/60'/2'/0/0"),
            _ => panic!("expected Other"),
        }
    }

    #[test]
    fn kao_signer_view_only_cannot_sign() {
        let addr: Address = "0x000000000000000000000000000000000000dEaD"
            .parse()
            .unwrap();
        let signer = KaoSigner::ViewOnly(addr);
        assert!(!signer.can_sign());
        assert_eq!(signer.address(), addr);
        // Debug shouldn't leak — ViewOnly intentionally includes the
        // address (it's not secret).
        let s = format!("{signer:?}");
        assert!(s.contains("ViewOnly"));
    }

    #[test]
    fn kao_signer_local_signs_and_recovers() {
        let parent = derive_parent_key(HARDHAT_PHRASE).unwrap();
        let (_, signer) = &derive_accounts_from(&parent, 0, 1).unwrap()[0];
        let ks = KaoSigner::Local(signer.clone());
        assert!(ks.can_sign());
        assert_eq!(ks.address(), signer.address());
        let s = format!("{ks:?}");
        assert!(s.contains("Local"));
    }

    #[tokio::test]
    async fn ensure_connected_passes_software_signer_through() {
        // A software signer has no device to probe — `ensure_connected` returns
        // it untouched (no network/device interaction), regardless of descriptor.
        let parent = derive_parent_key(HARDHAT_PHRASE).unwrap();
        let (_, signer) = &derive_accounts_from(&parent, 0, 1).unwrap()[0];
        let addr = signer.address();
        let ks = KaoSigner::Local(signer.clone());
        let desc = local_account(signer);
        let out = ensure_connected(ks, &desc)
            .await
            .expect("software passes through");
        assert!(matches!(out, KaoSigner::Local(_)));
        assert_eq!(out.address(), addr);
    }

    #[tokio::test]
    async fn ensure_connected_passes_view_only_through() {
        // View-only can't sign and has no device; it's returned as-is (the sign
        // call itself still errors UnsupportedOperation downstream).
        let addr: Address = "0x000000000000000000000000000000000000dEaD"
            .parse()
            .unwrap();
        let desc = AccountDescriptor::ViewOnly {
            name: None,
            address: addr.into_array(),
        };
        let out = ensure_connected(KaoSigner::ViewOnly(addr), &desc)
            .await
            .expect("view-only passes through");
        assert!(matches!(out, KaoSigner::ViewOnly(a) if a == addr));
    }

    #[tokio::test]
    async fn kao_signer_view_only_sign_tx_returns_unsupported() {
        use alloy::consensus::{SignableTransaction, TxEip1559};
        use alloy::primitives::{TxKind, U256};
        let addr: Address = "0x000000000000000000000000000000000000dEaD"
            .parse()
            .unwrap();
        let signer = KaoSigner::ViewOnly(addr);
        let mut tx = TxEip1559 {
            chain_id: 1,
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Call(addr),
            value: U256::ZERO,
            access_list: Default::default(),
            input: Default::default(),
        };
        let dyn_tx: &mut dyn SignableTransaction<_> = &mut tx;
        let err = signer.sign_tx(dyn_tx).await.unwrap_err();
        assert!(matches!(
            err,
            alloy::signers::Error::UnsupportedOperation(_)
        ));
    }

    #[tokio::test]
    async fn kao_signer_local_sign_hash_recovers_to_address() {
        let parent = derive_parent_key(HARDHAT_PHRASE).unwrap();
        let (_, signer) = &derive_accounts_from(&parent, 0, 1).unwrap()[0];
        let ks = KaoSigner::Local(signer.clone());
        let hash = B256::repeat_byte(0xab);
        let sig = ks.sign_hash(hash).await.unwrap();
        let recovered = sig.recover_address_from_prehash(&hash).unwrap();
        assert_eq!(recovered, ks.address());
    }

    #[tokio::test]
    async fn kao_signer_view_only_sign_hash_returns_unsupported() {
        let addr: Address = "0x000000000000000000000000000000000000dEaD"
            .parse()
            .unwrap();
        let ks = KaoSigner::ViewOnly(addr);
        let err = ks.sign_hash(B256::ZERO).await.unwrap_err();
        assert!(matches!(
            err,
            alloy::signers::Error::UnsupportedOperation(
                alloy::signers::UnsupportedSignerOperation::SignHash
            )
        ));
    }

    alloy::sol! {
        struct Demo712 {
            uint256 x;
            address y;
        }
    }

    /// An EIP-7702 authorization whose signature recovers to anything other
    /// than the delegating account is not a loud failure on chain — the entry
    /// is skipped, the account keeps no code, and the batch that follows
    /// becomes a call into a code-less address, which succeeds while doing
    /// nothing. `sign_authorization` checks the recovery so every caller
    /// inherits it; this pins the happy path so the check can't silently start
    /// rejecting good signatures.
    #[tokio::test]
    async fn sign_authorization_recovers_to_the_signing_account() {
        let parent = derive_parent_key(HARDHAT_PHRASE).unwrap();
        let (_, signer) = &derive_accounts_from(&parent, 0, 1).unwrap()[0];
        let ks = KaoSigner::Local(signer.clone());
        let auth = Authorization {
            chain_id: U256::from(1u64),
            address: Address::repeat_byte(0x4c),
            nonce: 7,
        };
        let signed = ks.sign_authorization(&auth).await.expect("local signs");
        assert_eq!(
            signed.recover_authority().expect("recoverable"),
            ks.address(),
            "the authority must be the account being delegated"
        );
        assert_eq!(signed.address, auth.address, "the delegate is unchanged");
        assert_eq!(signed.nonce, auth.nonce);
    }

    /// View-only and Trezor have no 7702 path, and must fail before producing
    /// anything that looks like an authorization.
    #[tokio::test]
    async fn sign_authorization_refuses_a_signer_without_a_7702_path() {
        let ks = KaoSigner::ViewOnly(Address::repeat_byte(0x11));
        let auth = Authorization {
            chain_id: U256::from(1u64),
            address: Address::repeat_byte(0x4c),
            nonce: 0,
        };
        assert!(ks.sign_authorization(&auth).await.is_err());
        assert!(!ks.supports_7702());
    }

    #[tokio::test]
    async fn local_eip712_matches_sign_hash() {
        // The software path through `sign_eip712` must be byte-identical
        // to hashing locally and `sign_hash`-ing the EIP-712 signing
        // hash — that equivalence is what lets the Safe flow swap to
        // `sign_eip712` (so hardware works) without changing the bytes a
        // software owner produces.
        use alloy::sol_types::SolStruct;
        let parent = derive_parent_key(HARDHAT_PHRASE).unwrap();
        let (_, signer) = &derive_accounts_from(&parent, 0, 1).unwrap()[0];
        let ks = KaoSigner::Local(signer.clone());
        let domain = Eip712Domain {
            name: None,
            version: None,
            chain_id: Some(U256::from(1u64)),
            verifying_contract: Some(Address::repeat_byte(0x11)),
            salt: None,
        };
        let payload = Demo712 {
            x: U256::from(42u64),
            y: Address::repeat_byte(0xab),
        };
        let via_712 = ks.sign_eip712(&payload, &domain).await.unwrap();
        let hash = payload.eip712_signing_hash(&domain);
        let via_hash = ks.sign_hash(hash).await.unwrap();
        assert_eq!(via_712.as_bytes(), via_hash.as_bytes());
        // And it recovers to the owner over the prehash.
        assert_eq!(
            via_712.recover_address_from_prehash(&hash).unwrap(),
            ks.address()
        );
    }

    #[tokio::test]
    async fn local_eth_message_recovers_over_eip191_prefix() {
        // `sign_eth_message` is EIP-191 personal_sign; recovery uses the
        // prefixed digest. This underpins the Safe `eth_sign` fallback.
        let parent = derive_parent_key(HARDHAT_PHRASE).unwrap();
        let (_, signer) = &derive_accounts_from(&parent, 0, 1).unwrap()[0];
        let ks = KaoSigner::Local(signer.clone());
        let hash = B256::repeat_byte(0xcd);
        let sig = ks.sign_eth_message(hash.as_slice()).await.unwrap();
        let recovered = sig.recover_address_from_msg(hash.as_slice()).unwrap();
        assert_eq!(recovered, ks.address());
    }

    #[tokio::test]
    async fn view_only_eip712_and_eth_message_unsupported() {
        let ks = KaoSigner::ViewOnly(Address::repeat_byte(0x01));
        let domain = Eip712Domain {
            name: None,
            version: None,
            chain_id: Some(U256::from(1u64)),
            verifying_contract: Some(Address::ZERO),
            salt: None,
        };
        let payload = Demo712 {
            x: U256::ZERO,
            y: Address::ZERO,
        };
        assert!(ks.sign_eip712(&payload, &domain).await.is_err());
        assert!(ks.sign_eth_message(&[0u8; 32]).await.is_err());
    }

    /// The EIP-712 "Mail" example, as a dapp would send it over
    /// `eth_signTypedData_v4` (a JSON object, `chainId` as a number).
    fn mail_typed_data() -> alloy::dyn_abi::TypedData {
        serde_json::from_value(serde_json::json!({
            "types": {
                "EIP712Domain": [
                    { "name": "name", "type": "string" },
                    { "name": "version", "type": "string" },
                    { "name": "chainId", "type": "uint256" },
                    { "name": "verifyingContract", "type": "address" }
                ],
                "Person": [
                    { "name": "name", "type": "string" },
                    { "name": "wallet", "type": "address" }
                ],
                "Mail": [
                    { "name": "from", "type": "Person" },
                    { "name": "to", "type": "Person" },
                    { "name": "contents", "type": "string" }
                ]
            },
            "primaryType": "Mail",
            "domain": {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "from": { "name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826" },
                "to": { "name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB" },
                "contents": "Hello, Bob!"
            }
        }))
        .expect("the EIP-712 Mail example parses")
    }

    /// A software key signs dapp typed data over exactly the ERC-8213 digest the
    /// review shows (`0x1901 ‖ domain hash ‖ message hash`), and the signature
    /// recovers to the account — the property `from == signer` rests on.
    #[tokio::test]
    async fn local_sign_typed_json_recovers_to_address() {
        use crate::sign::digest::Eip712Digests;
        let parent = derive_parent_key(HARDHAT_PHRASE).unwrap();
        let (_, signer) = &derive_accounts_from(&parent, 0, 1).unwrap()[0];
        let ks = KaoSigner::Local(signer.clone());
        let td = mail_typed_data();
        let digests = Eip712Digests::from_parts(td.domain.separator(), td.hash_struct().unwrap());
        // The EIP-712 reference vector for Mail.
        assert_eq!(
            digests.digest,
            alloy::primitives::b256!(
                "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
            ),
        );
        let sig = ks
            .sign_typed_json(&td)
            .await
            .expect("local signs typed data");
        assert_eq!(
            sig.recover_address_from_prehash(&digests.digest).unwrap(),
            ks.address(),
        );
        assert!(
            crate::sign::recover::assert_prehash_signer(&sig, digests.digest, ks.address()).is_ok()
        );
        // Byte-identical to signing the digest directly: nothing but the
        // reviewed 32 bytes reaches the key.
        let direct = ks.sign_hash(digests.digest).await.unwrap();
        assert_eq!(sig.as_bytes(), direct.as_bytes());
    }

    /// `primaryType == "EIP712Domain"` is the one shape where a software key and
    /// a Ledger would sign different digests for the same review; the signer
    /// refuses it whatever the caller checked.
    #[tokio::test]
    async fn sign_typed_json_refuses_domain_primary_type() {
        let parent = derive_parent_key(HARDHAT_PHRASE).unwrap();
        let (_, signer) = &derive_accounts_from(&parent, 0, 1).unwrap()[0];
        let ks = KaoSigner::Local(signer.clone());
        let mut td = mail_typed_data();
        td.primary_type = "EIP712Domain".to_string();
        assert!(ks.sign_typed_json(&td).await.is_err());
    }

    /// Neither a view-only placeholder nor a Trezor can sign dapp typed data,
    /// and both say so as `UnsupportedOperation(SignTypedData)` — not the
    /// trait default's misleading `SignHash`.
    ///
    /// A `KaoSigner::Trezor` can't be constructed without a device, so the
    /// Trezor arm is covered by the exhaustive `match` in `sign_typed_json`
    /// sharing this exact arm with `ViewOnly` (review checklist), and the
    /// WalletConnect sign task refuses a Trezor descriptor before any signer is
    /// touched (`wc_sign::tests::typed_refused_for_trezor_without_touching_the_device`).
    #[tokio::test]
    async fn trezor_and_viewonly_sign_typed_json_unsupported() {
        let ks = KaoSigner::ViewOnly(Address::repeat_byte(0x01));
        let err = ks.sign_typed_json(&mail_typed_data()).await.unwrap_err();
        assert!(
            matches!(
                err,
                alloy::signers::Error::UnsupportedOperation(
                    alloy::signers::UnsupportedSignerOperation::SignTypedData
                )
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn build_owner_signer_local_round_trips() {
        let parent = derive_parent_key(HARDHAT_PHRASE).unwrap();
        let (_, signer) = derive_accounts_from(&parent, 0, 1).unwrap()[0].clone();
        let addr = signer.address();
        let desc = local_account(&signer);
        let built = build_owner_signer(&desc).await.unwrap();
        assert_eq!(built.address(), addr);
        assert!(built.can_sign());
    }

    #[tokio::test]
    async fn build_owner_signer_view_only_errors() {
        let desc = AccountDescriptor::ViewOnly {
            name: None,
            address: [0x22; 20],
        };
        assert!(build_owner_signer(&desc).await.is_err());
    }

    #[test]
    fn handoff_with_take_returns_signer_once() {
        let addr: Address = "0x000000000000000000000000000000000000dEaD"
            .parse()
            .unwrap();
        let cell = handoff_with(KaoSigner::ViewOnly(addr));
        let taken = cell.lock().unwrap().take();
        assert!(taken.is_some());
        // Second take returns None.
        let again = cell.lock().unwrap().take();
        assert!(again.is_none());
    }

    #[test]
    fn generate_mnemonic_yields_distinct_words_each_call() {
        let (p1, _) = generate_mnemonic().unwrap();
        let (p2, _) = generate_mnemonic().unwrap();
        use secrecy::ExposeSecret;
        // Vanishingly small probability of collision (2^128); functional check
        // that the RNG actually advances.
        assert_ne!(p1.expose_secret(), p2.expose_secret());
    }

    #[test]
    fn short_address_full_form_truncates() {
        let addr: Address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
            .parse()
            .unwrap();
        let s = short_address(addr);
        // `format!("{addr}")` uses EIP-55 mixed-case; just check the
        // shape (head + ellipsis + tail) rather than the exact case.
        assert!(s.starts_with("0xd8dA"), "got: {s}");
        assert!(s.ends_with("6045"), "got: {s}");
        assert!(s.contains('…'));
    }

    #[test]
    fn account_short_address_fallback_when_key_invalid() {
        // Zero-bytes private key — signer_from_bytes rejects it, so
        // account_address returns None and the fallback string is used.
        let acc = AccountDescriptor::Local {
            name: None,
            key_bytes: crate::wallet::SecretKeyBytes::new([0u8; 32]),
        };
        assert_eq!(account_short_address(&acc), "0x????…????");
    }

    #[test]
    fn account_short_address_for_view_only_uses_short_form() {
        let addr: Address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
            .parse()
            .unwrap();
        let acc = view_only_account(addr);
        let s = account_short_address(&acc);
        assert!(s.starts_with("0xd8dA"), "got: {s}");
        assert!(s.ends_with("6045"));
    }

    #[test]
    fn signer_address_helper_matches_signer() {
        let parent = derive_parent_key(HARDHAT_PHRASE).unwrap();
        let (_, signer) = &derive_accounts_from(&parent, 0, 1).unwrap()[0];
        assert_eq!(signer_address(signer), signer.address());
    }

    #[test]
    fn wallet_descriptor_addresses_lists_all_accounts() {
        let addr_a: Address = "0x000000000000000000000000000000000000bEEf"
            .parse()
            .unwrap();
        let addr_b: Address = "0x000000000000000000000000000000000000dEaD"
            .parse()
            .unwrap();
        let desc = WalletDescriptor {
            accounts: vec![view_only_account(addr_a), view_only_account(addr_b)],
            safes: Vec::new(),
            active_index: 0,
            sibling_links_repaired: true,
        };
        let addrs = desc.addresses();
        assert_eq!(addrs, vec![addr_a, addr_b]);
    }

    // ── account_is_safe_signer (badge-classification helper) ────────────

    /// Build a `SafeDescriptor` carrying just the link list — the
    /// other fields are irrelevant to `account_is_safe_signer`, so we
    /// keep the test data minimal.
    fn safe_linking(linked: Vec<u32>) -> SafeDescriptor {
        SafeDescriptor {
            name: None,
            chain_id: 1,
            address: [0; 20],
            version: "1.4.1".into(),
            trust: SafeTrust::Canonical,
            threshold: 1,
            owners: Vec::new(),
            modules: Vec::new(),
            guard: None,
            fallback_handler: None,
            linked_signer_indices: linked,
            sibling_chains: Vec::new(),
            cached_at: 0,
            tx_service_url: None,
        }
    }

    #[test]
    fn account_is_safe_signer_false_when_safes_list_is_empty() {
        // No safes registered → no account can be a signer. Ensures the
        // dashboard's badge logic doesn't false-positive on a wallet
        // that has never onboarded a Safe.
        assert!(!account_is_safe_signer(0, &[]));
        assert!(!account_is_safe_signer(99, &[]));
    }

    #[test]
    fn account_is_safe_signer_true_when_any_safe_links_the_index() {
        // Multiple safes; only the second one links account 2.
        // The lookup must find it without caring about the first
        // safe's empty link list.
        let safes = [safe_linking(vec![]), safe_linking(vec![0, 2])];
        assert!(account_is_safe_signer(0, &safes));
        assert!(account_is_safe_signer(2, &safes));
    }

    #[test]
    fn account_is_safe_signer_false_for_unlinked_indices() {
        // Account 3 is not linked by any safe — the cross-badge must
        // NOT render for it. This is the negative case for the same
        // setup as above.
        let safes = [safe_linking(vec![0, 2]), safe_linking(vec![5])];
        assert!(!account_is_safe_signer(1, &safes));
        assert!(!account_is_safe_signer(3, &safes));
        assert!(!account_is_safe_signer(4, &safes));
    }

    #[test]
    fn account_is_safe_signer_false_for_watch_only_safes() {
        // A watch-only Safe has an empty `linked_signer_indices` — no
        // account it might list is "linked". Pins the convention that
        // watch-only = empty list (not a `None` somewhere).
        let safes = [safe_linking(vec![]), safe_linking(vec![])];
        assert!(!account_is_safe_signer(0, &safes));
        assert!(!account_is_safe_signer(7, &safes));
    }

    // ── WalletDescriptor edit helpers ───────────────────────────────────

    /// View-only account whose address is `[byte; 20]` — lets a test line
    /// an account up with a Safe owner of the same byte.
    fn watch(byte: u8) -> AccountDescriptor {
        view_only_account(Address::repeat_byte(byte))
    }

    /// Ledger account whose address is `[byte; 20]` — the signing-capable
    /// counterpart of `watch`.
    fn ledger(byte: u8) -> AccountDescriptor {
        AccountDescriptor::Ledger {
            name: None,
            path: LedgerHdPath::LedgerLive(0),
            address: [byte; 20],
        }
    }

    fn named_watch(byte: u8, name: &str) -> AccountDescriptor {
        let mut acc = watch(byte);
        acc.set_name(Some(name.into()));
        acc
    }

    /// Safe at `[addr; 20]` on `chain_id` with owners `[o; 20]` for each
    /// `o`, the given links and sibling list.
    fn safe_on(
        addr: u8,
        chain_id: u64,
        owners: &[u8],
        linked: Vec<u32>,
        sibling_chains: Vec<u64>,
    ) -> SafeDescriptor {
        SafeDescriptor {
            chain_id,
            address: [addr; 20],
            owners: owners.iter().map(|o| [*o; 20]).collect(),
            linked_signer_indices: linked,
            sibling_chains,
            ..safe_linking(Vec::new())
        }
    }

    fn wallet(accounts: Vec<AccountDescriptor>, safes: Vec<SafeDescriptor>) -> WalletDescriptor {
        WalletDescriptor {
            accounts,
            safes,
            active_index: 0,
            sibling_links_repaired: true,
        }
    }

    fn display_names(w: &WalletDescriptor) -> Vec<String> {
        w.accounts
            .iter()
            .enumerate()
            .map(|(i, a)| a.display_name(i))
            .collect()
    }

    fn safe_display_names(w: &WalletDescriptor) -> Vec<String> {
        w.safes
            .iter()
            .enumerate()
            .map(|(i, s)| s.display_name(i))
            .collect()
    }

    #[test]
    fn safe_index_matches_address_and_chain_together() {
        let w = wallet(
            vec![watch(1)],
            vec![
                safe_on(0x55, 1, &[], vec![], vec![]),
                safe_on(0x55, 8453, &[], vec![], vec![]),
            ],
        );
        assert_eq!(w.safe_index([0x55; 20], 1), Some(0));
        assert_eq!(w.safe_index([0x55; 20], 8453), Some(1));
        assert_eq!(w.safe_index([0x55; 20], 10), None);
        assert_eq!(w.safe_index([0x66; 20], 1), None);
        assert_eq!(w.safes[1].key(), ([0x55; 20], 8453));
    }

    #[test]
    fn remove_account_refuses_out_of_range_and_the_last_account() {
        let mut w = wallet(vec![watch(1), watch(2)], vec![]);
        assert_eq!(
            w.remove_account(2),
            Err(RemoveAccountError::OutOfRange { index: 2, len: 2 })
        );
        assert_eq!(w.accounts.len(), 2, "a refusal changes nothing");

        let mut solo = wallet(
            vec![watch(1)],
            vec![safe_on(0x55, 1, &[1], vec![0], vec![])],
        );
        assert_eq!(solo.remove_account(0), Err(RemoveAccountError::LastAccount));
        assert_eq!(solo.accounts.len(), 1);
        assert_eq!(solo.safes[0].linked_signer_indices, vec![0]);
        assert_eq!(
            RemoveAccountError::LastAccount.to_string(),
            "Your wallet needs at least one account."
        );
    }

    #[test]
    fn remove_account_remaps_links_and_reports_affected_safes() {
        let owners = [0xa0, 0xa1, 0xa2, 0xa3];
        let mut w = wallet(
            vec![ledger(0xa0), ledger(0xa1), ledger(0xa2), ledger(0xa3)],
            vec![
                safe_on(0x51, 1, &owners, vec![0, 1, 3], vec![]),
                safe_on(0x52, 1, &owners, vec![1], vec![]),
                safe_on(0x53, 10, &owners, vec![2, 3], vec![]),
                safe_on(0x54, 8453, &owners, vec![], vec![]),
            ],
        );
        let removed = w.remove_account(1).expect("removable");

        assert_eq!(w.accounts.len(), 3);
        // Index 1 dropped; everything above it shifted down by one so each
        // link still names the same key.
        assert_eq!(w.safes[0].linked_signer_indices, vec![0, 2]);
        assert!(w.safes[1].linked_signer_indices.is_empty());
        assert_eq!(w.safes[2].linked_signer_indices, vec![1, 2]);
        assert!(w.safes[3].linked_signer_indices.is_empty());
        for (safe, expected) in
            w.safes
                .iter()
                .zip([vec![0xa0, 0xa3], vec![], vec![0xa2, 0xa3], vec![]])
        {
            let linked: Vec<u8> = safe
                .linked_signer_indices
                .iter()
                .map(|&i| account_address(&w.accounts[i as usize]).unwrap()[0])
                .collect();
            assert_eq!(linked, expected, "links must keep naming the same keys");
        }

        assert_eq!(removed.name, "Account 2");
        assert_eq!(removed.address, Some(Address::repeat_byte(0xa1)));
        assert_eq!(
            removed.unlinked_safes,
            vec![([0x51; 20], 1), ([0x52; 20], 1)]
        );
        assert_eq!(removed.left_without_signing_key, vec![([0x52; 20], 1)]);
    }

    #[test]
    fn remove_account_counts_only_links_that_can_still_sign() {
        // Account 0 = the Safe owner's key; 1 = a view-only watch of a
        // co-owner (the old onboarding linked those); 2 = a Ledger the
        // owners have since removed on-chain. After account 0 goes, both
        // Safes keep a link — but no key in Kao can sign for either.
        let mut w = wallet(
            vec![ledger(0xa0), watch(0xa1), ledger(0xa2), ledger(0xa3)],
            vec![
                safe_on(0x51, 1, &[0xa0, 0xa1], vec![0, 1], vec![]),
                safe_on(0x52, 1, &[0xa0], vec![0, 2], vec![]),
                safe_on(0x53, 1, &[0xa0, 0xa3], vec![0, 3], vec![]),
            ],
        );
        let removed = w.remove_account(0).expect("removable");
        assert_eq!(
            w.safes[0].linked_signer_indices,
            vec![0],
            "kept, not signing"
        );
        assert_eq!(
            w.safes[1].linked_signer_indices,
            vec![1],
            "kept, not signing"
        );
        assert_eq!(
            removed.left_without_signing_key,
            vec![([0x51; 20], 1), ([0x52; 20], 1)],
            "0x53's other owner still signs"
        );
    }

    #[test]
    fn has_signing_link_needs_a_signing_kind_that_is_still_an_owner() {
        let accounts = [ledger(0xa0), watch(0xa1), ledger(0xa2)];
        let signs = |owners: &[u8], linked: Vec<u32>| {
            safe_on(0x55, 1, owners, linked, vec![]).has_signing_link(&accounts)
        };
        assert!(signs(&[0xa0], vec![0]));
        assert!(!signs(&[0xa0], vec![]), "nothing linked");
        assert!(!signs(&[0xa1], vec![1]), "view-only never signs");
        assert!(!signs(&[0xa0], vec![2]), "no longer an owner");
        assert!(!signs(&[0xa0], vec![7]), "dangling index");
        assert!(
            signs(&[0xa0, 0xa1], vec![1, 0]),
            "one signing link is enough"
        );

        let safe = safe_on(0x55, 1, &[0xa0, 0xa1, 0xa2], vec![0, 1, 2, 9], vec![]);
        assert_eq!(
            safe.signing_links(&accounts).collect::<Vec<_>>(),
            vec![0, 2]
        );
    }

    #[test]
    fn remove_account_freezes_default_names_after_the_removed_one() {
        let mut w = wallet(
            vec![watch(1), watch(2), named_watch(3, "Cold"), watch(4)],
            vec![],
        );
        w.remove_account(1).unwrap();
        // What the user saw for each surviving account is unchanged —
        // "Account 4" did not become "Account 3".
        assert_eq!(display_names(&w), vec!["Account 1", "Cold", "Account 4"]);
        // Accounts before the removed one keep their positional default.
        assert_eq!(w.accounts[0].name(), None);
        assert_eq!(w.accounts[2].name(), Some("Account 4"));
    }

    #[test]
    fn remove_account_keeps_the_active_account_or_takes_its_slot() {
        let four = || vec![watch(1), watch(2), watch(3), watch(4)];

        // Active below the removed one: untouched.
        let mut w = wallet(four(), vec![]);
        w.active_index = 0;
        w.remove_account(2).unwrap();
        assert_eq!(w.active_index, 0);

        // Active above: follows its account down.
        let mut w = wallet(four(), vec![]);
        w.active_index = 3;
        w.remove_account(1).unwrap();
        assert_eq!(w.active_index, 2);
        assert_eq!(account_address(w.active()), Some(Address::repeat_byte(4)));

        // Active removed from the middle: the next account slid into it.
        let mut w = wallet(four(), vec![]);
        w.active_index = 1;
        w.remove_account(1).unwrap();
        assert_eq!(w.active_index, 1);
        assert_eq!(account_address(w.active()), Some(Address::repeat_byte(3)));

        // Active removed from the end: the new last account.
        let mut w = wallet(four(), vec![]);
        w.active_index = 3;
        w.remove_account(3).unwrap();
        assert_eq!(w.active_index, 2);

        // An out-of-range stored index resolves like `active()` does (the
        // last account) and comes out in range.
        let mut w = wallet(four(), vec![]);
        w.active_index = 99;
        w.remove_account(0).unwrap();
        assert_eq!(w.active_index, 2);
        assert_eq!(account_address(w.active()), Some(Address::repeat_byte(4)));
    }

    #[test]
    fn remove_safe_removes_one_chain_and_prunes_peer_sibling_lists() {
        let mut w = wallet(
            vec![watch(1)],
            vec![
                safe_on(0x55, 1, &[], vec![0], vec![8453, 10]),
                safe_on(0x55, 8453, &[], vec![0], vec![1, 10]),
                safe_on(0x55, 10, &[], vec![], vec![1, 8453]),
                safe_on(0x66, 1, &[], vec![], vec![8453]),
            ],
        );
        let removed = w.remove_safe([0x55; 20], 8453).expect("held");
        assert_eq!(removed.key(), ([0x55; 20], 8453));
        let keys: Vec<SafeKey> = w.safes.iter().map(SafeDescriptor::key).collect();
        assert_eq!(
            keys,
            vec![([0x55; 20], 1), ([0x55; 20], 10), ([0x66; 20], 1)],
            "only that deployment goes; the same address elsewhere stays",
        );
        assert_eq!(w.safes[0].sibling_chains, vec![10]);
        assert_eq!(w.safes[1].sibling_chains, vec![1]);
        // A different Safe's list is not ours to edit.
        assert_eq!(w.safes[2].sibling_chains, vec![8453]);
    }

    #[test]
    fn remove_safe_returns_none_for_a_safe_not_held() {
        let mut w = wallet(vec![watch(1)], vec![safe_on(0x55, 1, &[], vec![], vec![])]);
        let before = w.safes.clone();
        assert!(w.remove_safe([0x55; 20], 8453).is_none());
        assert!(w.remove_safe([0x66; 20], 1).is_none());
        assert_eq!(w.safes, before);
    }

    #[test]
    fn remove_safe_freezes_default_names_after_the_removed_one() {
        let mut vault = safe_on(0x53, 1, &[], vec![], vec![]);
        vault.set_name(Some("Vault".into()));
        let mut w = wallet(
            vec![watch(1)],
            vec![
                safe_on(0x51, 1, &[], vec![], vec![]),
                safe_on(0x52, 1, &[], vec![], vec![]),
                vault,
                safe_on(0x54, 1, &[], vec![], vec![]),
            ],
        );
        w.remove_safe([0x51; 20], 1).unwrap();
        assert_eq!(safe_display_names(&w), vec!["Safe 2", "Vault", "Safe 4"]);
    }

    #[test]
    fn rename_safe_renames_every_chain_of_that_address() {
        let mut w = wallet(
            vec![watch(1)],
            vec![
                safe_on(0x55, 1, &[], vec![], vec![]),
                safe_on(0x66, 1, &[], vec![], vec![]),
                safe_on(0x55, 8453, &[], vec![], vec![]),
            ],
        );
        assert_eq!(w.rename_safe([0x55; 20], Some("  Treasury ".into())), 2);
        assert_eq!(w.safes[0].name(), Some("Treasury"));
        assert_eq!(w.safes[2].name(), Some("Treasury"));
        assert_eq!(w.safes[1].name(), None, "a different Safe is untouched");

        // Blank reverts to the positional default, on every chain.
        assert_eq!(w.rename_safe([0x55; 20], Some("   ".into())), 2);
        assert_eq!(w.safes[0].name(), None);
        assert_eq!(w.safes[2].name(), None);

        assert_eq!(w.rename_safe([0x77; 20], Some("Nope".into())), 0);
    }

    #[test]
    fn upsert_safe_appends_a_safe_not_held() {
        let mut w = wallet(
            vec![watch(1)],
            vec![safe_on(0x55, 1, &[1], vec![0], vec![])],
        );
        let base = safe_on(0x55, 8453, &[1], vec![0], vec![1]);
        assert_eq!(w.upsert_safe(base.clone()), SafeUpsert::Added);
        assert_eq!(w.safes.len(), 2);
        assert_eq!(w.safes[1], base);
    }

    #[test]
    fn upsert_safe_links_a_signer_into_a_watch_only_entry() {
        // The multi-chain bug left Base watch-only; adding it again with
        // the key that owns it must link it, not skip it.
        let mut w = wallet(
            vec![watch(1)],
            vec![
                safe_on(0x55, 1, &[1], vec![0], vec![8453]),
                safe_on(0x55, 8453, &[1], vec![], vec![1]),
            ],
        );
        let again = safe_on(0x55, 8453, &[1], vec![0], vec![1]);
        assert_eq!(
            w.upsert_safe(again),
            SafeUpsert::Merged {
                index: 1,
                newly_linked: 1
            }
        );
        assert_eq!(w.safes.len(), 2, "merged in place, no duplicate");
        assert_eq!(w.safes[1].linked_signer_indices, vec![0]);
    }

    #[test]
    fn upsert_safe_unions_links_and_keeps_user_configuration() {
        let mut saved = safe_on(0x55, 1, &[1, 2, 3], vec![2, 0, 2], vec![8453]);
        saved.set_name(Some("Vault".into()));
        saved.tx_service_url = Some("https://txs.example.org".into());
        let mut w = wallet(vec![watch(1), watch(2), watch(3)], vec![saved]);

        let mut incoming = safe_on(0x55, 1, &[1, 2, 3], vec![1, 2], vec![8453, 10]);
        incoming.set_name(Some("Other".into()));
        incoming.tx_service_url = None;
        assert_eq!(
            w.upsert_safe(incoming),
            SafeUpsert::Merged {
                index: 0,
                newly_linked: 1
            }
        );
        let s = &w.safes[0];
        assert_eq!(
            s.linked_signer_indices,
            vec![0, 1, 2],
            "sorted, deduped union"
        );
        assert_eq!(s.name(), Some("Vault"));
        assert_eq!(s.tx_service_url.as_deref(), Some("https://txs.example.org"));
        assert_eq!(
            s.sibling_chains,
            vec![8453],
            "sibling_chains is not unioned"
        );
    }

    #[test]
    fn upsert_safe_reports_unchanged_when_every_link_is_already_there() {
        let mut w = wallet(
            vec![watch(1), watch(2)],
            vec![
                safe_on(0x66, 1, &[], vec![], vec![]),
                safe_on(0x55, 1, &[1, 2], vec![0, 1], vec![]),
            ],
        );
        assert_eq!(
            w.upsert_safe(safe_on(0x55, 1, &[1, 2], vec![1], vec![])),
            SafeUpsert::Unchanged(1)
        );
        assert_eq!(
            w.upsert_safe(safe_on(0x66, 1, &[], vec![], vec![])),
            SafeUpsert::Unchanged(0),
            "watch-only again is unchanged too"
        );
        assert_eq!(w.safes[1].linked_signer_indices, vec![0, 1]);
    }

    #[test]
    fn upsert_safe_takes_onchain_fields_only_from_a_fresher_read() {
        let mut saved = safe_on(0x55, 1, &[1], vec![], vec![]);
        saved.cached_at = 100;
        let mut w = wallet(vec![watch(1)], vec![saved]);

        let mut stale = safe_on(0x55, 1, &[9], vec![], vec![]);
        stale.cached_at = 50;
        stale.threshold = 5;
        w.upsert_safe(stale);
        assert_eq!(
            w.safes[0].owners,
            vec![[1; 20]],
            "an older read never rolls back"
        );
        assert_eq!(w.safes[0].cached_at, 100);

        let mut fresh = safe_on(0x55, 1, &[1, 2], vec![], vec![]);
        fresh.cached_at = 200;
        fresh.threshold = 2;
        fresh.trust = SafeTrust::UnrecognizedImpl;
        w.upsert_safe(fresh);
        assert_eq!(w.safes[0].owners, vec![[1; 20], [2; 20]]);
        assert_eq!(w.safes[0].threshold, 2);
        assert_eq!(w.safes[0].trust, SafeTrust::UnrecognizedImpl);
        assert_eq!(w.safes[0].cached_at, 200);
    }

    #[test]
    fn refresh_onchain_from_keeps_everything_the_user_configured() {
        let mut live = safe_on(0x55, 1, &[1], vec![0], vec![8453]);
        live.set_name(Some("Renamed meanwhile".into()));
        live.tx_service_url = Some("https://txs.example.org".into());
        live.cached_at = 10;
        // A refresh built from an older snapshot: old name, no links, no URL.
        let mut fresh = safe_on(0x55, 1, &[1, 2], vec![], vec![]);
        fresh.cached_at = 20;
        fresh.version = "1.4.1+L2".into();
        fresh.modules = vec![[0xee; 20]];
        fresh.guard = Some([0xd0; 20]);
        fresh.fallback_handler = Some([0xfb; 20]);

        assert!(live.refresh_onchain_from(&fresh));
        assert_eq!(live.owners, fresh.owners);
        assert_eq!(live.version, "1.4.1+L2");
        assert_eq!(live.modules, vec![[0xee; 20]]);
        assert_eq!(live.guard, Some([0xd0; 20]));
        assert_eq!(live.fallback_handler, Some([0xfb; 20]));
        assert_eq!(live.cached_at, 20);
        assert_eq!(live.name(), Some("Renamed meanwhile"));
        assert_eq!(live.linked_signer_indices, vec![0]);
        assert_eq!(live.sibling_chains, vec![8453]);
        assert_eq!(
            live.tx_service_url.as_deref(),
            Some("https://txs.example.org")
        );
    }

    // ── repair_sibling_signer_links ─────────────────────────────────────

    #[test]
    fn repair_links_a_watch_only_sibling_from_its_linked_peer() {
        let mut w = wallet(
            vec![ledger(0xa)],
            vec![
                safe_on(0x55, 1, &[0xa], vec![0], vec![8453]),
                safe_on(0x55, 8453, &[0xa], vec![], vec![1]),
            ],
        );
        assert_eq!(w.repair_sibling_signer_links(), vec![1]);
        assert_eq!(w.safes[1].linked_signer_indices, vec![0]);
        assert_eq!(w.safes[0].linked_signer_indices, vec![0], "donor untouched");
    }

    #[test]
    fn repair_only_copies_accounts_that_own_the_target_chain() {
        // Accounts 0 (a) and 1 (b) are linked on Mainnet; Base is owned by
        // b and c only — a must not be linked where it isn't an owner.
        let mut w = wallet(
            vec![ledger(0xa), ledger(0xb)],
            vec![
                safe_on(0x55, 1, &[0xa, 0xb], vec![0, 1], vec![8453]),
                safe_on(0x55, 8453, &[0xb, 0xc], vec![], vec![1]),
            ],
        );
        assert_eq!(w.repair_sibling_signer_links(), vec![1]);
        assert_eq!(w.safes[1].linked_signer_indices, vec![1]);
    }

    #[test]
    fn repair_skips_when_no_linked_account_owns_the_target() {
        let mut w = wallet(
            vec![ledger(0xa)],
            vec![
                safe_on(0x55, 1, &[0xa], vec![0], vec![8453]),
                safe_on(0x55, 8453, &[0xb], vec![], vec![1]),
            ],
        );
        assert!(w.repair_sibling_signer_links().is_empty());
        assert!(w.safes[1].linked_signer_indices.is_empty());
    }

    #[test]
    fn repair_requires_both_entries_to_list_each_other() {
        // Donor doesn't list the target's chain.
        let mut one_way = wallet(
            vec![ledger(0xa)],
            vec![
                safe_on(0x55, 1, &[0xa], vec![0], vec![]),
                safe_on(0x55, 8453, &[0xa], vec![], vec![1]),
            ],
        );
        assert!(one_way.repair_sibling_signer_links().is_empty());
        // Target doesn't list the donor's chain — the "onboarded Base
        // first, watch-only, Mainnet unticked" shape stays deliberate.
        let mut other_way = wallet(
            vec![ledger(0xa)],
            vec![
                safe_on(0x55, 1, &[0xa], vec![0], vec![8453]),
                safe_on(0x55, 8453, &[0xa], vec![], vec![]),
            ],
        );
        assert!(other_way.repair_sibling_signer_links().is_empty());
        assert!(other_way.safes[1].linked_signer_indices.is_empty());
    }

    #[test]
    fn repair_ignores_other_addresses_and_same_chain_entries() {
        let mut w = wallet(
            vec![ledger(0xa)],
            vec![
                // Linked Safe at a different address listing chain 8453.
                safe_on(0x66, 1, &[0xa], vec![0], vec![8453]),
                safe_on(0x55, 8453, &[0xa], vec![], vec![1]),
            ],
        );
        assert!(w.repair_sibling_signer_links().is_empty());
    }

    #[test]
    fn repair_noop_when_everything_is_watch_only() {
        let mut w = wallet(
            vec![ledger(0xa)],
            vec![
                safe_on(0x55, 1, &[0xa], vec![], vec![8453]),
                safe_on(0x55, 8453, &[0xa], vec![], vec![1]),
            ],
        );
        assert!(w.repair_sibling_signer_links().is_empty());
        assert!(w.safes.iter().all(|s| s.linked_signer_indices.is_empty()));
    }

    #[test]
    fn repair_never_touches_an_already_linked_safe() {
        let mut w = wallet(
            vec![ledger(0xa), ledger(0xb), ledger(0xc)],
            vec![
                safe_on(0x55, 1, &[0xa, 0xc], vec![0], vec![8453]),
                safe_on(0x55, 8453, &[0xa, 0xc], vec![2], vec![1]),
            ],
        );
        assert!(w.repair_sibling_signer_links().is_empty());
        assert_eq!(w.safes[1].linked_signer_indices, vec![2]);
    }

    #[test]
    fn repair_drops_dangling_donor_indices_and_unions_donors() {
        let mut w = wallet(
            vec![ledger(0xa), ledger(0xb)],
            vec![
                safe_on(0x55, 1, &[0xa], vec![0, 9], vec![8453, 10]),
                safe_on(0x55, 10, &[0xb], vec![1], vec![1, 8453]),
                safe_on(0x55, 8453, &[0xa, 0xb], vec![], vec![1, 10]),
            ],
        );
        assert_eq!(w.repair_sibling_signer_links(), vec![2]);
        assert_eq!(
            w.safes[2].linked_signer_indices,
            vec![0, 1],
            "both donors contribute their owning accounts; index 9 dangles"
        );
    }

    #[test]
    fn repair_is_idempotent() {
        let mut w = wallet(
            vec![ledger(0xa)],
            vec![
                safe_on(0x55, 1, &[0xa], vec![0], vec![8453, 10]),
                safe_on(0x55, 8453, &[0xa], vec![], vec![1, 10]),
                safe_on(0x55, 10, &[0xa], vec![], vec![1, 8453]),
            ],
        );
        assert_eq!(w.repair_sibling_signer_links(), vec![1, 2]);
        let after = w.safes.clone();
        assert!(w.repair_sibling_signer_links().is_empty());
        assert_eq!(w.safes, after);
    }

    #[test]
    fn repair_never_copies_a_view_only_link() {
        // The old onboarding linked view-only owners too. Account 0 is one,
        // account 1 can sign; both own Base and are linked on Mainnet.
        let mut w = wallet(
            vec![watch(0xa), ledger(0xb)],
            vec![
                safe_on(0x55, 1, &[0xa, 0xb], vec![0, 1], vec![8453]),
                safe_on(0x55, 8453, &[0xa, 0xb], vec![], vec![1]),
            ],
        );
        assert_eq!(w.repair_sibling_signer_links(), vec![1]);
        assert_eq!(w.safes[1].linked_signer_indices, vec![1], "only the key");

        // A donor linked to nothing but a view-only account has nothing to
        // give: Base stays watch-only rather than "signer" with no key.
        let mut w = wallet(
            vec![watch(0xa)],
            vec![
                safe_on(0x55, 1, &[0xa], vec![0], vec![8453]),
                safe_on(0x55, 8453, &[0xa], vec![], vec![1]),
            ],
        );
        assert!(w.repair_sibling_signer_links().is_empty());
        assert!(w.safes[1].linked_signer_indices.is_empty());
    }

    #[test]
    fn repair_once_runs_only_on_a_wallet_not_yet_repaired() {
        let legacy_pair = || {
            vec![
                safe_on(0x55, 1, &[0xa], vec![0], vec![8453]),
                safe_on(0x55, 8453, &[0xa], vec![], vec![1]),
            ]
        };
        // A wallet saved before the marker: repaired, and marked.
        let mut legacy = wallet(vec![ledger(0xa)], legacy_pair());
        legacy.sibling_links_repaired = false;
        assert_eq!(legacy.repair_sibling_signer_links_once(), Some(vec![1]));
        assert!(legacy.sibling_links_repaired);
        assert_eq!(legacy.safes[1].linked_signer_indices, vec![0]);
        assert_eq!(legacy.repair_sibling_signer_links_once(), None);

        // Nothing to repair still flips the marker — it must be persisted.
        let mut clean = wallet(vec![ledger(0xa)], Vec::new());
        clean.sibling_links_repaired = false;
        assert_eq!(clean.repair_sibling_signer_links_once(), Some(Vec::new()));
        assert!(clean.sibling_links_repaired);

        // Already marked: the same shape is the user's choice, left alone.
        let mut current = wallet(vec![ledger(0xa)], legacy_pair());
        assert_eq!(current.repair_sibling_signer_links_once(), None);
        assert!(current.safes[1].linked_signer_indices.is_empty());
        assert!(WalletDescriptor::single(ledger(0xa)).sibling_links_repaired);
    }

    #[test]
    fn upsert_safe_gives_a_new_chain_the_saved_name_and_service_url() {
        let mut mainnet = safe_on(0x55, 1, &[1], vec![0], vec![]);
        mainnet.set_name(Some("Treasury".into()));
        mainnet.tx_service_url = Some("https://txs.example.org".into());
        let mut w = wallet(
            vec![ledger(1)],
            vec![safe_on(0x66, 8453, &[], vec![], vec![]), mainnet],
        );

        // Blank Review name, no Advanced URL: the saved ones carry over.
        assert_eq!(
            w.upsert_safe(safe_on(0x55, 8453, &[1], vec![0], vec![1])),
            SafeUpsert::Added
        );
        assert_eq!(w.safes[2].name(), Some("Treasury"));
        assert_eq!(
            w.safes[2].tx_service_url.as_deref(),
            Some("https://txs.example.org")
        );

        // Explicit values win here (the App then renames every chain).
        let mut typed = safe_on(0x55, 10, &[1], vec![0], vec![1]);
        typed.set_name(Some("Vault".into()));
        typed.tx_service_url = Some("https://mirror.example.org".into());
        assert_eq!(w.upsert_safe(typed), SafeUpsert::Added);
        assert_eq!(w.safes[3].name(), Some("Vault"));
        assert_eq!(
            w.safes[3].tx_service_url.as_deref(),
            Some("https://mirror.example.org")
        );

        // A different address adopts nothing.
        assert_eq!(
            w.upsert_safe(safe_on(0x77, 1, &[], vec![], vec![])),
            SafeUpsert::Added
        );
        assert_eq!(w.safes[4].name(), None);
        assert_eq!(w.safes[4].tx_service_url, None);
    }
}
