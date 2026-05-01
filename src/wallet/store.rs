//! Persistent wallet store backed by redb + XChaCha20-Poly1305 + Argon2id.
//!
//! Layout
//! ------
//! - `meta` table (`&str -> &[u8]`):
//!   - `header`: bincode of `Header` (version, salt, Argon2 params,
//!     authenticated check blob).
//!   - `active_index`: `u32` LE bytes; plaintext, since the index leaks
//!     nothing useful and we want `redb` range scans over
//!     account keys to remain cheap.
//! - `accounts` table (`u32 -> &[u8]`):
//!   - value = `nonce(24) || ciphertext || tag(16)`. AAD binds the record to
//!     its `redb` key (`b"accounts:" || key.to_le_bytes()`) so values can't
//!     be silently moved between rows.
//!
//! XChaCha20-Poly1305 is preferred over plain ChaCha20-Poly1305 / AES-GCM:
//! the 192-bit nonce makes random nonces safe indefinitely, removing the
//! reuse footgun that comes with 96-bit AEADs.
//!
//! The master key is derived from the user's passphrase via Argon2id and the
//! random salt stored in `header`. The header also contains a small
//! authenticated blob whose successful decryption doubles as the "is this the
//! right password?" check.

use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::{RngCore, rngs::OsRng};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{AccountDescriptor, WalletDescriptor, WalletError};

const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const ACCOUNTS_TABLE: TableDefinition<u32, &[u8]> = TableDefinition::new("accounts");

const STORE_VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const SALT_LEN: usize = 16;

const HEADER_KEY: &str = "header";
const ACTIVE_INDEX_KEY: &str = "active_index";
const HEADER_AAD: &[u8] = b"header:auth_check";
const ACCOUNT_AAD_PREFIX: &[u8] = b"accounts:";

const AUTH_CONSTANT: &[u8] = b"KAO_AUTH_v1";

// Argon2id parameters. Targeting ~250–500ms on a modern desktop CPU; tune
// these on the actual target hardware before shipping. The chosen values are
// persisted in the header on first save, so future tuning will not invalidate
// existing wallets.
#[cfg(not(test))]
const DEFAULT_ARGON2_M_COST_KIB: u32 = 48 * 1024;
#[cfg(not(test))]
const DEFAULT_ARGON2_T_COST: u32 = 3;
#[cfg(not(test))]
const DEFAULT_ARGON2_P_COST: u32 = 1;

// Tests use the smallest legal Argon2id parameters so the suite finishes in
// well under a second total. Production wallets are unaffected.
#[cfg(test)]
const DEFAULT_ARGON2_M_COST_KIB: u32 = 8;
#[cfg(test)]
const DEFAULT_ARGON2_T_COST: u32 = 1;
#[cfg(test)]
const DEFAULT_ARGON2_P_COST: u32 = 1;

#[derive(Serialize, Deserialize)]
struct Header {
    version: u8,
    salt: [u8; SALT_LEN],
    argon2_m_cost_kib: u32,
    argon2_t_cost: u32,
    argon2_p_cost: u32,
    auth_check: Vec<u8>,
}

pub fn db_path() -> PathBuf {
    crate::paths::data_dir().join("wallet.redb")
}

pub fn db_exists() -> bool {
    db_path().exists()
}

pub fn save_descriptor(
    desc: &WalletDescriptor,
    passphrase: &SecretString,
) -> Result<(), WalletError> {
    let path = db_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        restrict_to_owner(parent, 0o700)?;
    }
    save_to(&path, desc, passphrase)
}

pub fn load_descriptor(passphrase: &SecretString) -> Result<WalletDescriptor, WalletError> {
    let path = db_path();
    if !path.exists() {
        return Err(WalletError::NotFound);
    }
    load_from(&path, passphrase)
}

fn save_to(path: &Path, desc: &WalletDescriptor, pw: &SecretString) -> Result<(), WalletError> {
    let db = Database::create(path).map_err(redb_err)?;
    // Tighten the on-disk permissions so other local users can't read the
    // (encrypted) wallet blob. Redb's open fd is unaffected; this only
    // restricts who can open the file in the future.
    restrict_to_owner(path, 0o600)?;
    let txn = db.begin_write().map_err(redb_err)?;

    let existing = {
        let meta = txn.open_table(META_TABLE).map_err(redb_err)?;
        match meta.get(HEADER_KEY).map_err(redb_err)? {
            Some(v) => Some(deserialize_header(v.value())?),
            None => None,
        }
    };

    let header = match existing {
        Some(h) => {
            // Existing wallet — verify the password matches the stored params
            // before we overwrite anything.
            let key = derive_master_key(
                pw,
                &h.salt,
                h.argon2_m_cost_kib,
                h.argon2_t_cost,
                h.argon2_p_cost,
            )?;
            decrypt_blob(key.as_slice(), HEADER_AAD, &h.auth_check)
                .map_err(|_| WalletError::Encryption("incorrect password".into()))?;
            h
        }
        None => {
            // Fresh wallet — mint a salt and seal a fresh auth-check blob.
            let mut salt = [0u8; SALT_LEN];
            OsRng.fill_bytes(&mut salt);
            let key = derive_master_key(
                pw,
                &salt,
                DEFAULT_ARGON2_M_COST_KIB,
                DEFAULT_ARGON2_T_COST,
                DEFAULT_ARGON2_P_COST,
            )?;
            let auth_check = encrypt_blob(key.as_slice(), HEADER_AAD, AUTH_CONSTANT)?;
            Header {
                version: STORE_VERSION,
                salt,
                argon2_m_cost_kib: DEFAULT_ARGON2_M_COST_KIB,
                argon2_t_cost: DEFAULT_ARGON2_T_COST,
                argon2_p_cost: DEFAULT_ARGON2_P_COST,
                auth_check,
            }
        }
    };

    let master_key = derive_master_key(
        pw,
        &header.salt,
        header.argon2_m_cost_kib,
        header.argon2_t_cost,
        header.argon2_p_cost,
    )?;

    let header_bytes = bincode::serialize(&header)
        .map_err(|e| WalletError::Encryption(format!("serialize header: {e}")))?;

    {
        let mut meta = txn.open_table(META_TABLE).map_err(redb_err)?;
        meta.insert(HEADER_KEY, header_bytes.as_slice())
            .map_err(redb_err)?;
        let active = (desc.active_index as u32).to_le_bytes();
        meta.insert(ACTIVE_INDEX_KEY, active.as_slice())
            .map_err(redb_err)?;
    }

    {
        let mut accounts = txn.open_table(ACCOUNTS_TABLE).map_err(redb_err)?;
        let existing_keys: Vec<u32> = {
            let mut acc = Vec::new();
            for entry in accounts.iter().map_err(redb_err)? {
                let (k, _) = entry.map_err(redb_err)?;
                acc.push(k.value());
            }
            acc
        };
        for k in existing_keys {
            accounts.remove(k).map_err(redb_err)?;
        }

        for (i, account) in desc.accounts.iter().enumerate() {
            let idx = i as u32;
            let plaintext = bincode::serialize(account)
                .map_err(|e| WalletError::Encryption(format!("serialize account {i}: {e}")))?;
            let aad = account_aad(idx);
            let blob = encrypt_blob(master_key.as_slice(), &aad, &plaintext)?;
            accounts.insert(idx, blob.as_slice()).map_err(redb_err)?;
        }
    }

    txn.commit().map_err(redb_err)?;
    Ok(())
}

fn load_from(path: &Path, pw: &SecretString) -> Result<WalletDescriptor, WalletError> {
    let db = match Database::open(path) {
        Ok(db) => db,
        Err(redb::DatabaseError::Storage(redb::StorageError::Io(e)))
            if e.kind() == std::io::ErrorKind::NotFound =>
        {
            return Err(WalletError::NotFound);
        }
        Err(e) => return Err(redb_err(e)),
    };
    let txn = db.begin_read().map_err(redb_err)?;

    let meta = txn.open_table(META_TABLE).map_err(redb_err)?;
    let header_guard = meta
        .get(HEADER_KEY)
        .map_err(redb_err)?
        .ok_or_else(|| WalletError::Encryption("missing header in store".into()))?;
    let header = deserialize_header(header_guard.value())?;

    let master_key = derive_master_key(
        pw,
        &header.salt,
        header.argon2_m_cost_kib,
        header.argon2_t_cost,
        header.argon2_p_cost,
    )?;

    decrypt_blob(master_key.as_slice(), HEADER_AAD, &header.auth_check)
        .map_err(|_| WalletError::Encryption("incorrect password".into()))?;

    let active_index = match meta.get(ACTIVE_INDEX_KEY).map_err(redb_err)? {
        Some(v) => {
            let bytes = v.value();
            if bytes.len() == 4 {
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize
            } else {
                0
            }
        }
        None => 0,
    };

    let accounts_tbl = txn.open_table(ACCOUNTS_TABLE).map_err(redb_err)?;
    let mut accounts: Vec<(u32, AccountDescriptor)> = Vec::new();
    for entry in accounts_tbl.iter().map_err(redb_err)? {
        let (k, v) = entry.map_err(redb_err)?;
        let idx = k.value();
        let aad = account_aad(idx);
        let plaintext = decrypt_blob(master_key.as_slice(), &aad, v.value())?;
        let account: AccountDescriptor = bincode::deserialize(&plaintext)
            .map_err(|e| WalletError::Encryption(format!("deserialize account {idx}: {e}")))?;
        accounts.push((idx, account));
    }
    accounts.sort_by_key(|(i, _)| *i);
    let accounts: Vec<AccountDescriptor> = accounts.into_iter().map(|(_, a)| a).collect();

    if accounts.is_empty() {
        return Err(WalletError::Encryption("no accounts in store".into()));
    }

    let active_index = active_index.min(accounts.len() - 1);
    Ok(WalletDescriptor {
        accounts,
        active_index,
    })
}

fn deserialize_header(bytes: &[u8]) -> Result<Header, WalletError> {
    bincode::deserialize::<Header>(bytes)
        .map_err(|e| WalletError::Encryption(format!("deserialize header: {e}")))
}

fn derive_master_key(
    pw: &SecretString,
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(32))
        .map_err(|e| WalletError::Encryption(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(pw.expose_secret().as_bytes(), salt, out.as_mut())
        .map_err(|e| WalletError::Encryption(format!("argon2 hash: {e}")))?;
    Ok(out)
}

fn encrypt_blob(key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, WalletError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| WalletError::Encryption(format!("encrypt: {e}")))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_blob(key: &[u8], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, WalletError> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(WalletError::Encryption("ciphertext too short".into()));
    }
    let nonce = XNonce::from_slice(&blob[..NONCE_LEN]);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &blob[NONCE_LEN..],
                aad,
            },
        )
        .map_err(|e| WalletError::Encryption(format!("decrypt: {e}")))
}

fn account_aad(idx: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(ACCOUNT_AAD_PREFIX.len() + 4);
    out.extend_from_slice(ACCOUNT_AAD_PREFIX);
    out.extend_from_slice(&idx.to_le_bytes());
    out
}

fn redb_err<E: std::fmt::Display>(e: E) -> WalletError {
    WalletError::Encryption(format!("store: {e}"))
}

/// Restrict a path to owner-only access. Unix-only — Windows lacks POSIX
/// modes and a proper ACL story is out of scope for this fix.
fn restrict_to_owner(path: &Path, mode: u32) -> std::io::Result<()> {
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
    use crate::wallet::{AccountDescriptor, LedgerHdPath, WalletDescriptor};
    use tempfile::tempdir;

    fn pw(s: &str) -> SecretString {
        SecretString::new(s.to_string().into_boxed_str())
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = WalletDescriptor {
            accounts: vec![
                AccountDescriptor::Local {
                    name: Some("Treasury".into()),
                    key_bytes: [0xab; 32],
                },
                AccountDescriptor::Ledger {
                    name: None,
                    path: LedgerHdPath::LedgerLive(2),
                    address: [0x33; 20],
                },
                AccountDescriptor::Local {
                    name: None,
                    key_bytes: [0xcd; 32],
                },
            ],
            active_index: 2,
        };
        save_to(&path, &desc, &pw("hunter2")).unwrap();
        let loaded = load_from(&path, &pw("hunter2")).unwrap();
        assert_eq!(loaded.accounts.len(), 3);
        assert_eq!(loaded.active_index, 2);
        match &loaded.accounts[0] {
            AccountDescriptor::Local { name, key_bytes } => {
                assert_eq!(name.as_deref(), Some("Treasury"));
                assert_eq!(*key_bytes, [0xab; 32]);
            }
            _ => panic!("expected Local"),
        }
        match &loaded.accounts[1] {
            AccountDescriptor::Ledger { name, path, address } => {
                assert!(name.is_none());
                assert!(matches!(path, LedgerHdPath::LedgerLive(2)));
                assert_eq!(*address, [0x33; 20]);
            }
            _ => panic!("expected Ledger"),
        }
        match &loaded.accounts[2] {
            AccountDescriptor::Local { key_bytes, .. } => assert_eq!(*key_bytes, [0xcd; 32]),
            _ => panic!("expected Local"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_wallet_file_with_owner_only_perms() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = WalletDescriptor::single(AccountDescriptor::Local {
            name: None,
            key_bytes: [0x42; 32],
        });
        save_to(&path, &desc, &pw("pw")).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got 0o{mode:o}");
    }

    #[test]
    fn load_returns_not_found_for_missing_file() {
        // Loading a nonexistent wallet file must surface `WalletError::NotFound`
        // — not a generic "missing header" error after silently creating an
        // empty redb. This is the contract the unlock screen relies on to
        // distinguish "no wallet yet, send to setup" from "real corruption".
        let dir = tempdir().unwrap();
        let path = dir.path().join("does_not_exist.redb");
        let err = load_from(&path, &pw("anything")).unwrap_err();
        assert!(
            matches!(err, WalletError::NotFound),
            "expected NotFound, got {err:?}",
        );
        assert!(
            !path.exists(),
            "load_from must not create the file as a side effect",
        );
    }

    #[test]
    fn wrong_password_fails_to_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = WalletDescriptor::single(AccountDescriptor::Local {
            name: None,
            key_bytes: [0x42; 32],
        });
        save_to(&path, &desc, &pw("correct")).unwrap();
        let err = load_from(&path, &pw("wrong")).unwrap_err();
        match err {
            WalletError::Encryption(msg) => assert!(msg.contains("incorrect password")),
            other => panic!("expected Encryption error, got {other:?}"),
        }
    }

    #[test]
    fn wrong_password_refused_on_save_over_existing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = WalletDescriptor::single(AccountDescriptor::Local {
            name: None,
            key_bytes: [0x11; 32],
        });
        save_to(&path, &desc, &pw("right")).unwrap();
        let err = save_to(&path, &desc, &pw("wrong")).unwrap_err();
        match err {
            WalletError::Encryption(msg) => assert!(msg.contains("incorrect password")),
            other => panic!("expected Encryption error, got {other:?}"),
        }
    }

    #[test]
    fn argon2_params_survive_header_roundtrip() {
        // Header is the only place the Argon2 work factors are stored. Tuning
        // the defaults later must not invalidate existing wallets, so confirm
        // a saved header round-trips through bincode with the values intact.
        let original = Header {
            version: STORE_VERSION,
            salt: [0x7e; SALT_LEN],
            argon2_m_cost_kib: 12_345,
            argon2_t_cost: 4,
            argon2_p_cost: 2,
            auth_check: vec![0xaa; 64],
        };
        let bytes = bincode::serialize(&original).unwrap();
        let parsed = deserialize_header(&bytes).unwrap();
        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.salt, original.salt);
        assert_eq!(parsed.argon2_m_cost_kib, original.argon2_m_cost_kib);
        assert_eq!(parsed.argon2_t_cost, original.argon2_t_cost);
        assert_eq!(parsed.argon2_p_cost, original.argon2_p_cost);
        assert_eq!(parsed.auth_check, original.auth_check);
    }

    #[test]
    fn tampered_account_ciphertext_fails_to_decrypt() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = WalletDescriptor::single(AccountDescriptor::Local {
            name: None,
            key_bytes: [0x55; 32],
        });
        save_to(&path, &desc, &pw("pw")).unwrap();

        // Flip a single byte inside the ciphertext (skipping the nonce prefix).
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut accounts = txn.open_table(ACCOUNTS_TABLE).unwrap();
                let mut blob = accounts.get(0u32).unwrap().unwrap().value().to_vec();
                let target = NONCE_LEN + 1;
                blob[target] ^= 0x01;
                accounts.insert(0u32, blob.as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }

        let err = load_from(&path, &pw("pw")).unwrap_err();
        match err {
            WalletError::Encryption(msg) => assert!(msg.contains("decrypt"), "got: {msg}"),
            other => panic!("expected Encryption error, got {other:?}"),
        }
    }

    #[test]
    fn save_overwrite_replaces_account_set() {
        // Saving a smaller account set must drop rows from the previous save —
        // not silently leave them as ghost accounts that re-appear on load.
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");

        let big = WalletDescriptor {
            accounts: vec![
                AccountDescriptor::Local {
                    name: None,
                    key_bytes: [0x01; 32],
                },
                AccountDescriptor::Local {
                    name: None,
                    key_bytes: [0x02; 32],
                },
                AccountDescriptor::Local {
                    name: None,
                    key_bytes: [0x03; 32],
                },
            ],
            active_index: 2,
        };
        save_to(&path, &big, &pw("pw")).unwrap();

        let small = WalletDescriptor::single(AccountDescriptor::Local {
            name: None,
            key_bytes: [0x09; 32],
        });
        save_to(&path, &small, &pw("pw")).unwrap();

        let loaded = load_from(&path, &pw("pw")).unwrap();
        assert_eq!(loaded.accounts.len(), 1);
        assert_eq!(loaded.active_index, 0);
        match &loaded.accounts[0] {
            AccountDescriptor::Local { key_bytes, .. } => assert_eq!(*key_bytes, [0x09; 32]),
            _ => panic!("expected Local"),
        }
    }

    /// Bind-AAD test: take the ciphertext for account 0 and stuff it under
    /// key 1. Loading must reject — the AAD on decrypt won't match.
    #[test]
    fn aad_binding_rejects_swapped_account_record() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = WalletDescriptor {
            accounts: vec![
                AccountDescriptor::Local {
                    name: None,
                    key_bytes: [0x01; 32],
                },
                AccountDescriptor::Local {
                    name: None,
                    key_bytes: [0x02; 32],
                },
            ],
            active_index: 0,
        };
        save_to(&path, &desc, &pw("pw")).unwrap();

        // Swap rows 0 and 1 in the accounts table.
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut accounts = txn.open_table(ACCOUNTS_TABLE).unwrap();
                let a = accounts.get(0u32).unwrap().unwrap().value().to_vec();
                let b = accounts.get(1u32).unwrap().unwrap().value().to_vec();
                accounts.insert(0u32, b.as_slice()).unwrap();
                accounts.insert(1u32, a.as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }

        let err = load_from(&path, &pw("pw")).unwrap_err();
        match err {
            WalletError::Encryption(msg) => assert!(msg.contains("decrypt")),
            other => panic!("expected Encryption error, got {other:?}"),
        }
    }
}
