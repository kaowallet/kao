use alloy::primitives::{Address, B256, Signature};
use alloy::signers::Signer;
use alloy::signers::ledger::{HDPath as AlloyLedgerHDPath, LedgerSigner};
use alloy::signers::local::{
    MnemonicBuilder, MnemonicKey, PrivateKeySigner, coins_bip39, coins_bip39::English,
};
use alloy::signers::trezor::{HDPath as AlloyTrezorHDPath, TrezorSigner};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

mod store;
pub mod tx;

pub use store::db_exists as wallet_exists;
pub use store::{load_descriptor, save_descriptor};

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

/// Mainnet for now; both LedgerSigner::new and TrezorSigner::new take this.
pub const CHAIN_ID: u64 = 1;

// ── Descriptor ─────────────────────────────────────────────────────────────

/// What kind of signer one account uses, plus enough metadata to reconstruct
/// it on the next launch. Multiple of these live inside a `WalletDescriptor`.
///
/// `ViewOnly` is the read-only watch variant: it carries an address but no
/// signing material, so it can show balance/activity but can't sign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccountDescriptor {
    Local {
        name: Option<String>,
        key_bytes: [u8; 32],
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
}

/// Top-level wallet payload. Encrypted at rest inside `wallet.enc`. Holds the
/// list of accounts the user has set up plus the index of the one currently
/// in focus on the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletDescriptor {
    pub accounts: Vec<AccountDescriptor>,
    pub active_index: usize,
}

impl WalletDescriptor {
    pub fn single(account: AccountDescriptor) -> Self {
        Self {
            accounts: vec![account],
            active_index: 0,
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
}

/// Compute the Ethereum address for an account descriptor. Returns None if a
/// `Local` variant carries unrecoverable key bytes (shouldn't happen for any
/// account that survived persistence, but the call is fallible upstream).
pub fn account_address(account: &AccountDescriptor) -> Option<Address> {
    match account {
        AccountDescriptor::Local { key_bytes, .. } => {
            let b = B256::from_slice(key_bytes);
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

    /// Sign a 32-byte hash. Delegates to the inner signer's
    /// `Signer::sign_hash`. `ViewOnly` returns
    /// `UnsupportedOperation(SignHash)`.
    pub async fn sign_hash(&self, hash: &B256) -> Result<Signature, alloy::signers::Error> {
        match self {
            KaoSigner::Local(s) => s.sign_hash(hash).await,
            KaoSigner::Ledger(s) => s.sign_hash(hash).await,
            KaoSigner::Trezor(s) => s.sign_hash(hash).await,
            KaoSigner::ViewOnly(_) => Err(alloy::signers::Error::UnsupportedOperation(
                alloy::signers::UnsupportedSignerOperation::SignHash,
            )),
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
        key_bytes: bytes,
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

    #[test]
    fn account_bincode_roundtrip_local() {
        let acc = AccountDescriptor::Local {
            name: Some("Treasury".into()),
            key_bytes: [0xab; 32],
        };
        let encoded = bincode::serialize(&acc).unwrap();
        let decoded: AccountDescriptor = bincode::deserialize(&encoded).unwrap();
        match decoded {
            AccountDescriptor::Local { name, key_bytes } => {
                assert_eq!(name.as_deref(), Some("Treasury"));
                assert_eq!(key_bytes, [0xab; 32]);
            }
            _ => panic!("expected Local"),
        }
    }

    #[test]
    fn account_bincode_roundtrip_ledger() {
        let acc = AccountDescriptor::Ledger {
            name: None,
            path: LedgerHdPath::LedgerLive(3),
            address: [0x11; 20],
        };
        let encoded = bincode::serialize(&acc).unwrap();
        let decoded: AccountDescriptor = bincode::deserialize(&encoded).unwrap();
        match decoded {
            AccountDescriptor::Ledger { name, path, address } => {
                assert!(name.is_none());
                assert!(matches!(path, LedgerHdPath::LedgerLive(3)));
                assert_eq!(address, [0x11; 20]);
            }
            _ => panic!("expected Ledger"),
        }
    }

    #[test]
    fn account_bincode_roundtrip_trezor() {
        let acc = AccountDescriptor::Trezor {
            name: None,
            path: TrezorHdPath::TrezorLive(2),
            address: [0x22; 20],
        };
        let encoded = bincode::serialize(&acc).unwrap();
        let decoded: AccountDescriptor = bincode::deserialize(&encoded).unwrap();
        match decoded {
            AccountDescriptor::Trezor { name, path, address } => {
                assert!(name.is_none());
                assert!(matches!(path, TrezorHdPath::TrezorLive(2)));
                assert_eq!(address, [0x22; 20]);
            }
            _ => panic!("expected Trezor"),
        }
    }

    #[test]
    fn wallet_descriptor_bincode_roundtrip() {
        let desc = WalletDescriptor {
            accounts: vec![
                AccountDescriptor::Local {
                    name: None,
                    key_bytes: [0x11; 32],
                },
                AccountDescriptor::Ledger {
                    name: None,
                    path: LedgerHdPath::LedgerLive(2),
                    address: [0x22; 20],
                },
            ],
            active_index: 1,
        };
        let encoded = bincode::serialize(&desc).unwrap();
        let decoded: WalletDescriptor = bincode::deserialize(&encoded).unwrap();
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
        let key_bytes: [u8; 32] = signer.to_bytes().0;
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
                key_bytes: [0xab; 32],
            }],
            // Bogus index larger than accounts.len(); active() must clamp.
            active_index: 99,
        };
        match desc.active() {
            AccountDescriptor::Local { key_bytes, .. } => assert_eq!(*key_bytes, [0xab; 32]),
            _ => panic!("expected Local"),
        }
    }

    #[test]
    fn display_name_falls_back_to_indexed_default() {
        let unnamed = AccountDescriptor::Local {
            name: None,
            key_bytes: [0x42; 32],
        };
        assert_eq!(unnamed.display_name(0), "Account 1");
        assert_eq!(unnamed.display_name(4), "Account 5");

        let named = AccountDescriptor::Local {
            name: Some("Cold Storage".into()),
            key_bytes: [0x42; 32],
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
}
