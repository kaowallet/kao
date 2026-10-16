//! Persistent wallet store backed by redb + XChaCha20-Poly1305 + Argon2id.
//!
//! Layout
//! ------
//! - `meta` table (`&str -> &[u8]`):
//!   - `header`: postcard of `Header` (salt, Argon2 params, authenticated
//!     check blob).
//!   - `active_index`: `u32` LE bytes; plaintext, since the index leaks
//!     nothing useful and we want `redb` range scans over
//!     account keys to remain cheap.
//! - `accounts` table (`u32 -> &[u8]`):
//!   - value = `nonce(24) || ciphertext || tag(16)`. AAD binds the record to
//!     its `redb` key (`b"accounts:" || key.to_le_bytes()`) so values can't
//!     be silently moved between rows.
//! - `keys` table (`&str -> &[u8]`): one row, `data` — the wallet's data key
//!   ([`DataKey`]), sealed under the master key (AAD `b"keys:data"`).
//! - `wc_state`, `wc_connections`, `signed_messages` (`u64 -> &[u8]`): the
//!   sealed tables ([`SealedTable`]), encrypted under the data key — not the
//!   master key — so the vault writes them without an Argon2 pass per write.
//!   AAD `b"<table>:" || id.to_le_bytes()`.
//!
//! Every open of a store file first takes a process-wide per-path lock (see
//! "Store lock" below): redb refuses a second open in one process instead of
//! waiting, and the file is opened from several threads. A second Kao process
//! is kept off the wallet by the instance lock (`kao.lock`, see "Instance lock").
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
use std::sync::{Arc, Condvar, LazyLock, Mutex, PoisonError};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::{RngCore, rngs::OsRng};
use redb::{
    Database, ReadTransaction, ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{AccountDescriptor, Contact, SafeDescriptor, WalletDescriptor, WalletError};

use std::collections::HashMap;
use std::str::FromStr;

use alloy::primitives::Address;

use crate::pool::sync::CachedNotes;

const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const ACCOUNTS_TABLE: TableDefinition<u32, &[u8]> = TableDefinition::new("accounts");
const CONTACTS_TABLE: TableDefinition<u32, &[u8]> = TableDefinition::new("contacts");
const SAFES_TABLE: TableDefinition<u32, &[u8]> = TableDefinition::new("safes");
// Single-row table holding the dedicated Privacy Pools 24-word mnemonic. It is
// a keyring root shared by every pool account (not a per-account entry), so it
// lives in its own table rather than in `accounts`. The wallet's own BIP39 seed
// is never persisted (only derived keys), so this is an independent secret.
const PP_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("pp");
// Per-pool Privacy Pools note cache (the recovered-note logs + a `to_block`
// cursor), one row per `(chain, pool)` keyed `"{chain_id}:{pool:#x}"`. A cache,
// not a source of truth — cleared on identity change and self-healed on any
// inconsistency, so it never has to be migrated.
const PP_NOTES_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("pp_notes");
// Single-row table holding the data key (`DATA_KEY_ROW`), wrapped under the master key.
const KEYS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("keys");
// The sealed tables (see `SealedTable`), under the data key.
const WC_STATE_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("wc_state");
const WC_CONNECTIONS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("wc_connections");
const SIGNED_MESSAGES_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("signed_messages");

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const SALT_LEN: usize = 16;

const HEADER_KEY: &str = "header";
const ACTIVE_INDEX_KEY: &str = "active_index";
// `WalletDescriptor::sibling_links_repaired`, as one byte (0/1). Plaintext
// like `active_index`: it only says whether the one-time legacy repair still
// has to run. A wallet saved before the repair shipped has no such key, which
// reads as "not yet".
const SIBLING_LINKS_REPAIRED_KEY: &str = "sibling_links_repaired";
const PP_SEED_KEY: &str = "seed";
const HEADER_AAD: &[u8] = b"header:auth_check";
const ACCOUNT_AAD_PREFIX: &[u8] = b"accounts:";
const CONTACT_AAD_PREFIX: &[u8] = b"contacts:";
const SAFE_AAD_PREFIX: &[u8] = b"safes:";
// Single fixed AAD (the table has exactly one row), namespacing the Privacy
// Pools seed against accounts/contacts/safes so its ciphertext can't be swapped
// into another table.
const PP_SEED_AAD: &[u8] = b"pp:seed";
// Per-row AAD prefix for the note cache; the row key is appended so a blob is
// bound to its exact `(chain, pool)` slot and can't be swapped across rows/tables.
const PP_NOTES_AAD_PREFIX: &[u8] = b"pp_notes:";
const DATA_KEY_ROW: &str = "data";
// Fixed AAD for the one data-key row: its blob can't be swapped into (or out
// of) any other master-key table.
const KEYS_AAD: &[u8] = b"keys:data";

const AUTH_CONSTANT: &[u8] = b"KAO_AUTH";

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
    salt: [u8; SALT_LEN],
    argon2_m_cost_kib: u32,
    argon2_t_cost: u32,
    argon2_p_cost: u32,
    auth_check: Vec<u8>,
}

/// The persisted Privacy Pools secret. A struct (not a bare string) so future
/// fields — e.g. a deposit "birthday" block to bound the sync scan — can be
/// appended without a format break (postcard is not self-describing; new fields
/// MUST append and get a legacy fallback, exactly like `SafeDescriptor`).
#[derive(Serialize, Deserialize)]
struct PpSeedRecord {
    phrase: String,
}

pub fn db_path() -> PathBuf {
    crate::paths::data_dir().join("wallet.redb")
}

pub fn db_exists() -> bool {
    db_path().exists()
}

// ── Instance lock ───────────────────────────────────────────────────────────
//
// The store lock below is per process, and every store call opens and closes the file, so redb
// only refuses two processes' *overlapping* opens. Two Kao processes on one wallet would each
// count row ids from what they read at unlock and overwrite each other's history rows and saved
// WalletConnect state. So a process takes an advisory lock on `kao.lock` next to `wallet.redb`
// before it reads or creates the wallet and keeps it until it exits (the OS releases it then,
// crash included).

/// The instance lock file once taken; never released while the process runs.
static INSTANCE_LOCK: Mutex<Option<std::fs::File>> = Mutex::new(None);

fn instance_lock_path() -> PathBuf {
    crate::paths::data_dir().join("kao.lock")
}

/// Take the process-wide instance lock: an exclusive advisory lock ([`std::fs::File::try_lock`])
/// on `kao.lock` in the data directory, kept until the process exits. `Ok` at once when this
/// process already holds it; [`WalletError::InUse`] while another process (another Kao window)
/// does. Call it before the unlock reads the wallet and before a new wallet is created.
///
/// When the lock can't be taken for any other reason (a filesystem without locks, a directory
/// that can't be written) it warns and returns `Ok`: the lock is a safety net, never a reason to
/// keep the user out of their wallet. The next call tries again.
///
/// Tests don't call it: the lock it takes outlives the test, and its file the test run. They take
/// a lock file of their own (`acquire_instance_lock_at`) or stand in for it.
pub fn acquire_instance_lock() -> Result<(), WalletError> {
    acquire_instance_lock_at(&instance_lock_path(), &INSTANCE_LOCK)
}

fn acquire_instance_lock_at(
    path: &Path,
    slot: &Mutex<Option<std::fs::File>>,
) -> Result<(), WalletError> {
    let mut held = slot.lock().unwrap_or_else(PoisonError::into_inner);
    if held.is_some() {
        return Ok(());
    }
    let file = match open_lock_file(path) {
        Ok(file) => file,
        Err(e) => {
            warn!(error = %e, "couldn't open the instance lock file; carrying on without it");
            return Ok(());
        }
    };
    match file.try_lock() {
        Ok(()) => {
            *held = Some(file);
            Ok(())
        }
        Err(std::fs::TryLockError::WouldBlock) => Err(WalletError::InUse),
        Err(std::fs::TryLockError::Error(e)) => {
            warn!(error = %e, "couldn't take the instance lock; carrying on without it");
            Ok(())
        }
    }
}

/// `kao.lock`, created owner-only (in a data directory created owner-only, as a wallet save would).
fn open_lock_file(path: &Path) -> std::io::Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        restrict_to_owner(parent, 0o700)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

// ── Store lock ──────────────────────────────────────────────────────────────
//
// redb refuses a second open of a file inside one process (`DatabaseAlreadyOpen`, at once — it
// never waits), and Kao opens `wallet.redb` per call from several threads: the App's blocking
// tasks, the UI thread and the vault's writer. So every open in this file first takes a
// process-wide lock for its path and holds it for as long as the `Database` lives ([`Opened`]):
// those calls queue instead of failing. Across processes redb still fails fast (and the instance
// lock above keeps a second Kao process off the wallet altogether).
//
// Not re-entrant: no store fn may call another while it holds an `Opened`.

/// How an open waits for its path's lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wait {
    /// Wait for the holder to finish (every open whose failure the user would see).
    Block,
    /// Fail at once with "store: busy" — only the advisory pool-notes cache, where a busy file
    /// costs a re-scan.
    Try,
}

#[derive(Default)]
struct PathLock {
    held: Mutex<bool>,
    freed: Condvar,
}

/// One lock per path ever opened (a handful in production; the entries are never removed).
static LOCKS: LazyLock<Mutex<HashMap<PathBuf, Arc<PathLock>>>> = LazyLock::new(Default::default);

/// Holds a path's lock until dropped — also on unwind, so a panicking holder can't wedge the file.
struct PathGuard(Arc<PathLock>);

impl Drop for PathGuard {
    fn drop(&mut self) {
        *self.0.held.lock().unwrap_or_else(PoisonError::into_inner) = false;
        self.0.freed.notify_one();
    }
}

fn lock_path(path: &Path, wait: Wait) -> Result<PathGuard, WalletError> {
    let lock = LOCKS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(path.to_path_buf())
        .or_default()
        .clone();
    let mut held = lock.held.lock().unwrap_or_else(PoisonError::into_inner);
    while *held {
        if wait == Wait::Try {
            return Err(WalletError::Encryption("store: busy".into()));
        }
        held = lock
            .freed
            .wait(held)
            .unwrap_or_else(PoisonError::into_inner);
    }
    *held = true;
    drop(held);
    Ok(PathGuard(lock))
}

/// An open store and its path lock. `db` is declared first so the file is closed before the lock
/// is released (fields drop in declaration order).
struct Opened {
    db: Database,
    _guard: PathGuard,
}

/// Open an existing store file — a missing one is `NotFound`, never created.
fn open_existing(path: &Path, wait: Wait) -> Result<Opened, WalletError> {
    let guard = lock_path(path, wait)?;
    match Database::open(path) {
        Ok(db) => Ok(Opened { db, _guard: guard }),
        Err(redb::DatabaseError::Storage(redb::StorageError::Io(e)))
            if e.kind() == std::io::ErrorKind::NotFound =>
        {
            Err(WalletError::NotFound)
        }
        Err(e) => Err(redb_err(e)),
    }
}

/// Open the store file, creating it when missing.
fn open_or_create(path: &Path, wait: Wait) -> Result<Opened, WalletError> {
    let guard = lock_path(path, wait)?;
    let db = Database::create(path).map_err(redb_err)?;
    Ok(Opened { db, _guard: guard })
}

/// Persist `desc` under `passphrase`. On `Err` the file was NOT modified.
///
/// The descriptor commits first, on its own; the wallet's data key (see [`DataKey`]) is settled
/// afterwards, in transactions of its own, so a fault confined to the `keys` table or the sealed
/// tables never costs the user a wallet edit. `Some` carries the key and where it came from: the
/// stored one ([`KeyOrigin::Existing`]), or one minted after the descriptor
/// ([`KeyOrigin::Minted`]: a new wallet, a wallet saved before data keys existed, or one whose key
/// row was unreadable — the mint cleared the sealed tables). `None`: the descriptor is saved, but
/// the key couldn't be read or minted (warned; the next save tries again) — a session without a
/// key stays without one.
pub fn save_descriptor(
    desc: &WalletDescriptor,
    passphrase: &SecretString,
) -> Result<Option<(DataKey, KeyOrigin)>, WalletError> {
    let path = db_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        restrict_to_owner(parent, 0o700)?;
    }
    save_to(&path, desc, passphrase)
}

/// [`save_descriptor`] against `path` — for tests elsewhere in the crate that need a real wallet
/// file (and its data key) without touching `db_path()`. A key that couldn't be settled is an
/// `Err` here: those tests need one.
#[cfg(test)]
pub(crate) fn save_descriptor_at(
    path: &Path,
    desc: &WalletDescriptor,
    passphrase: &SecretString,
) -> Result<DataKey, WalletError> {
    save_to(path, desc, passphrase)?
        .map(|(key, _)| key)
        .ok_or_else(|| WalletError::Encryption("store: the data key wasn't settled".into()))
}

/// Unlock: one Argon2 pass reads the descriptor, the data key and the sealed tables. An `Err` is a
/// wrong password / missing or unreadable wallet — never anything key- or sealed-related (the
/// unlock screen shows every `Err` as "Incorrect password").
pub fn load_wallet(passphrase: &SecretString) -> Result<Unlocked, WalletError> {
    load_wallet_at(&db_path(), passphrase)
}

/// [`load_wallet`] against `path`.
///
/// The data key: present → unwrapped and the sealed tables read under it (a row that fails to
/// decrypt is skipped and counted); missing → minted ([`replace_data_key`]), so a wallet saved
/// before data keys existed gets persistence on its first unlock (a failed mint → `data_key: None`
/// with [`KeyStatus::Ok`]); a row that doesn't decrypt or decode → [`KeyStatus::Lost`]; a storage
/// error reading the key row or any sealed table → [`KeyStatus::Unavailable`]. Never a partial
/// read: whenever `data_key` is `None` the sealed load is empty, and whenever it is `Some` every
/// sealed row that exists was seen (the vault's ids continue from them).
pub(crate) fn load_wallet_at(path: &Path, pw: &SecretString) -> Result<Unlocked, WalletError> {
    if !path.exists() {
        return Err(WalletError::NotFound);
    }
    let opened = open_existing(path, Wait::Block)?;
    let (descriptor, master_key, key_row, sealed) = {
        let txn = opened.db.begin_read().map_err(redb_err)?;
        let master_key = unlock_master_key(&txn, pw)?;
        let descriptor = read_descriptor(&txn, &master_key)?;
        let key_row = read_key(&txn, &master_key);
        // A broken scan fails the key with it: rows the vault never saw would be overwritten by
        // ids restarting below them.
        let (key_row, sealed) = match key_row {
            Ok(KeyRow::Present(key)) => match read_sealed(&txn, &key) {
                Ok(sealed) => (Ok(KeyRow::Present(key)), sealed),
                Err(e) => (Err(e), SealedLoad::default()),
            },
            other => (other, SealedLoad::default()),
        };
        (descriptor, master_key, key_row, sealed)
    };
    let (data_key, key_status) = match key_row {
        Ok(KeyRow::Present(key)) => (Some(key), KeyStatus::Ok),
        Ok(KeyRow::Missing) => match replace_data_key(&opened.db, &master_key) {
            Ok((key, _)) => (Some(key), KeyStatus::Ok),
            Err(e) => {
                warn!(
                    error = %e,
                    "couldn't store a data key; WalletConnect sessions and history stay in memory this session"
                );
                (None, KeyStatus::Ok)
            }
        },
        Ok(KeyRow::Unreadable) => {
            warn!(
                "the wallet's data key is unreadable; saved WalletConnect sessions and history can't be read (the next wallet save mints a new key)"
            );
            (None, KeyStatus::Lost)
        }
        Err(e) => {
            warn!(
                error = %e,
                "couldn't read the wallet's data key or its saved records; WalletConnect sessions and history stay in memory this session"
            );
            (None, KeyStatus::Unavailable)
        }
    };
    Ok(Unlocked {
        descriptor,
        data_key,
        key_status,
        sealed,
    })
}

// ── Data key and sealed tables ──────────────────────────────────────────────

/// The wallet's data key (DEK): a random 32-byte key, stored wrapped under the master key, that
/// seals the WalletConnect state and the history tables without an Argon2 pass per write.
#[derive(Clone)]
pub struct DataKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey(..)")
    }
}

impl DataKey {
    fn generate() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut_slice());
        Self(key)
    }

    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn for_test(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// The `keys` row's plaintext. A struct (not bare bytes) so fields can be appended later under the
/// postcard append-only rule; scrubbed on drop.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct DataKeyRecord {
    key: [u8; 32],
}

/// What the `keys` table holds.
enum KeyRow {
    Missing,
    Present(DataKey),
    /// A row exists but doesn't decrypt or decode under this master key.
    Unreadable,
}

/// Read the data-key row. `Err` only for a storage error (the row may or may not exist).
fn read_key_row(
    tbl: &impl ReadableTable<&'static str, &'static [u8]>,
    master_key: &[u8; 32],
) -> Result<KeyRow, WalletError> {
    let Some(v) = tbl.get(DATA_KEY_ROW).map_err(redb_err)? else {
        return Ok(KeyRow::Missing);
    };
    let Ok(plaintext) = decrypt_blob(master_key, KEYS_AAD, v.value()) else {
        return Ok(KeyRow::Unreadable);
    };
    Ok(match postcard::from_bytes::<DataKeyRecord>(&plaintext) {
        Ok(rec) => KeyRow::Present(DataKey(Zeroizing::new(rec.key))),
        Err(_) => KeyRow::Unreadable,
    })
}

/// [`read_key_row`] from `txn`, a missing `keys` table being a missing row.
fn read_key(txn: &ReadTransaction, master_key: &[u8; 32]) -> Result<KeyRow, WalletError> {
    match txn.open_table(KEYS_TABLE) {
        Ok(tbl) => read_key_row(&tbl, master_key),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(KeyRow::Missing),
        Err(e) => Err(redb_err(e)),
    }
}

fn wrap_data_key(master_key: &[u8; 32], key: &DataKey) -> Result<Vec<u8>, WalletError> {
    let rec = DataKeyRecord { key: *key.expose() };
    let plaintext = Zeroizing::new(
        postcard::to_stdvec(&rec)
            .map_err(|e| WalletError::Encryption(format!("serialize data key: {e}")))?,
    );
    encrypt_blob(master_key, KEYS_AAD, &plaintext)
}

/// Mint a fresh data key, clear the sealed tables and store the key — rows sealed under any
/// earlier key can never be read again, and every row id is free — in write transactions of its
/// own (never bundled with a descriptor save).
///
/// A table whose delete fails (redb walks a table's pages to free them, and a broken page fails
/// the walk and poisons the transaction) is moved aside instead, in a fresh transaction: renamed
/// to `<name>.unreadable.<random>`, which nothing reads, so its own name reads as an empty table.
/// Its pages stay allocated; the rows in it were sealed under the key this replaces. The `keys`
/// table gets the same treatment when the new key can't be written into it.
///
/// `true` alongside the key when a table was moved aside: no compaction should follow then
/// (compaction rewrites every reachable page, the broken ones included). `Err`, with nothing
/// changed, when a table can't even be moved aside.
fn replace_data_key(db: &Database, master_key: &[u8; 32]) -> Result<(DataKey, bool), WalletError> {
    let key = DataKey::generate();
    let wrapped = wrap_data_key(master_key, &key)?;
    // Tables to move aside rather than delete or write: each failed attempt adds the table that
    // failed it, so this ends after at most one attempt per table.
    let mut aside: Vec<ResetTable> = Vec::new();
    loop {
        let txn = db.begin_write().map_err(redb_err)?;
        match reset_in(&txn, &wrapped, &aside) {
            Ok(()) => {
                txn.commit().map_err(redb_err)?;
                return Ok((key, !aside.is_empty()));
            }
            Err((table, e)) => {
                // A poisoned transaction can only be aborted; a failed abort changes nothing on
                // disk either.
                let _ = txn.abort();
                if aside.contains(&table) {
                    warn!(table = table.name(), error = %e, "store: couldn't replace the data key");
                    return Err(e);
                }
                warn!(
                    table = table.name(),
                    error = %e,
                    "store: couldn't clear a table for a new data key; moving it aside"
                );
                aside.push(table);
            }
        }
    }
}

/// The data key for a descriptor `save_to` has just committed (the password is verified by now),
/// in transactions of its own: a new header always mints (a headerless file's leftover rows can
/// never be unwrapped); an existing wallet keeps its key, minting when the row is missing, and
/// re-minting (with a warning) when the row is there but unreadable. Every mint clears the
/// sealed tables, moving aside one that won't delete ([`replace_data_key`]).
///
/// `None`, with a warning, when the key can't be settled: a storage error reading the key row
/// (the key and the rows may well be fine — nothing is minted over them; the session's unlock
/// was [`KeyStatus::Unavailable`] and "Reset saved history and connections…" is the cure), or a
/// mint that failed. The next save tries again.
fn settle_data_key(
    db: &Database,
    master_key: &[u8; 32],
    new_header: bool,
) -> Option<(DataKey, KeyOrigin)> {
    if !new_header {
        let row = db
            .begin_read()
            .map_err(redb_err)
            .and_then(|txn| read_key(&txn, master_key));
        match row {
            Ok(KeyRow::Present(key)) => return Some((key, KeyOrigin::Existing)),
            Ok(KeyRow::Missing) => {}
            Ok(KeyRow::Unreadable) => warn!(
                "the wallet's data key was unreadable; minting a new one and clearing the sealed tables"
            ),
            Err(e) => {
                warn!(
                    error = %e,
                    "wallet saved, but its data key couldn't be read; this save hands no key over (the next one tries again)"
                );
                return None;
            }
        }
    }
    match replace_data_key(db, master_key) {
        Ok((key, _)) => Some((key, KeyOrigin::Minted)),
        Err(e) => {
            warn!(
                error = %e,
                "wallet saved, but no data key could be minted; this save hands no key over (the next one tries again)"
            );
            None
        }
    }
}

/// How the unlock fared with the data key — what decides whether a key handed over later (by a
/// wallet save) may be adopted by the session's vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyStatus {
    /// Read (and the sealed tables with it), minted, or — with `data_key: None` — a mint that
    /// failed to write (the next save mints).
    #[default]
    Ok,
    /// A key row exists but doesn't decrypt or decode: what it sealed is gone, and the next save
    /// re-mints (clearing the sealed tables).
    Lost,
    /// A storage error reading the key row or a sealed table. The key and the rows may well be
    /// fine — nothing was loaded, so the session can't know which row ids are taken and mustn't
    /// adopt the existing key (only a freshly minted one, whose mint cleared the tables).
    Unavailable,
}

/// Where the data key [`save_descriptor`] returns came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOrigin {
    /// The key already stored; the sealed tables are untouched.
    Existing,
    /// Minted by this save, which cleared the sealed tables (every row id is free).
    Minted,
}

/// What a successful unlock read. `data_key` is `None` when the key couldn't be read or stored
/// (`key_status` says why); the wallet still unlocks.
#[derive(Clone)]
pub struct Unlocked {
    pub descriptor: WalletDescriptor,
    pub data_key: Option<DataKey>,
    pub key_status: KeyStatus,
    pub sealed: SealedLoad,
}

/// Counts only: the descriptor holds keys, the sealed rows plaintext.
impl std::fmt::Debug for Unlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unlocked")
            .field("accounts", &self.descriptor.accounts.len())
            .field("safes", &self.descriptor.safes.len())
            .field("data_key", &self.data_key.is_some())
            .field("key_status", &self.key_status)
            .field("sealed", &self.sealed)
            .finish()
    }
}

/// The sealed tables as read at unlock (decrypted, not yet decoded).
#[derive(Clone, Default)]
pub struct SealedLoad {
    pub wc_state: Option<Zeroizing<Vec<u8>>>,
    pub connections: SealedRows,
    pub signed: SealedRows,
}

impl std::fmt::Debug for SealedLoad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedLoad")
            .field("wc_state_bytes", &self.wc_state.as_ref().map(|b| b.len()))
            .field("connections", &self.connections)
            .field("signed", &self.signed)
            .finish()
    }
}

/// One sealed table's rows, `(id, plaintext)`, plus how many failed to decrypt and were skipped.
#[derive(Clone, Default)]
pub struct SealedRows {
    pub rows: Vec<(u64, Zeroizing<Vec<u8>>)>,
    pub dropped: usize,
}

impl std::fmt::Debug for SealedRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedRows")
            .field("rows", &self.rows.len())
            .field("dropped", &self.dropped)
            .finish()
    }
}

/// The tables sealed under the data key (`u64 -> &[u8]`, AAD `b"<name>:" || id.to_le_bytes()`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealedTable {
    /// "wc_state": the single WalletConnect state row, id [`WC_STATE_ID`].
    WcState,
    /// "wc_connections"
    WcConnections,
    /// "signed_messages"
    SignedMessages,
}

/// The one row of the `wc_state` table; unlock reads only this id.
pub(crate) const WC_STATE_ID: u64 = 0;

impl SealedTable {
    const ALL: [Self; 3] = [Self::WcState, Self::WcConnections, Self::SignedMessages];

    fn name(self) -> &'static str {
        match self {
            Self::WcState => "wc_state",
            Self::WcConnections => "wc_connections",
            Self::SignedMessages => "signed_messages",
        }
    }

    fn def(self) -> TableDefinition<'static, u64, &'static [u8]> {
        match self {
            Self::WcState => WC_STATE_TABLE,
            Self::WcConnections => WC_CONNECTIONS_TABLE,
            Self::SignedMessages => SIGNED_MESSAGES_TABLE,
        }
    }

    /// `b"<name>:" || id.to_le_bytes()`: a row is bound to its table and its id.
    fn aad(self, id: u64) -> Vec<u8> {
        let name = self.name().as_bytes();
        let mut out = Vec::with_capacity(name.len() + 1 + 8);
        out.extend_from_slice(name);
        out.push(b':');
        out.extend_from_slice(&id.to_le_bytes());
        out
    }
}

/// One op of a [`write_sealed_at`] batch (one write transaction per batch).
pub enum SealedWrite {
    Put {
        table: SealedTable,
        id: u64,
        plaintext: Zeroizing<Vec<u8>>,
    },
    Delete {
        table: SealedTable,
        id: u64,
    },
    Clear(SealedTable),
}

/// Variant, table, id and length only — never the plaintext.
impl std::fmt::Debug for SealedWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Put {
                table,
                id,
                plaintext,
            } => f
                .debug_struct("Put")
                .field("table", table)
                .field("id", id)
                .field("len", &plaintext.len())
                .finish(),
            Self::Delete { table, id } => f
                .debug_struct("Delete")
                .field("table", table)
                .field("id", id)
                .finish(),
            Self::Clear(table) => f.debug_tuple("Clear").field(table).finish(),
        }
    }
}

/// Apply `batch` to the sealed tables under `key` in the wallet file at `path`, in one write
/// transaction. Never creates the wallet file.
///
/// Refuses a missing file and a file without a header (a sealed write must never be what creates
/// `wallet.redb`: a headerless file reads as "Incorrect password" forever). Ops apply in order, so
/// a `Clear` followed by `Put`s leaves just those rows. After a batch whose `Clear` removed a
/// table, a best-effort `compact()` so the cleared ciphertext isn't left in freed pages longer
/// than necessary (redb reuses freed pages, but a file backup could still carry them).
pub(crate) fn write_sealed_at(
    path: &Path,
    batch: Vec<SealedWrite>,
    key: &DataKey,
) -> Result<(), WalletError> {
    if batch.is_empty() {
        return Ok(());
    }
    let mut opened = match open_existing(path, Wait::Block) {
        Err(WalletError::NotFound) => {
            return Err(WalletError::Encryption(
                "write_sealed called before wallet exists".into(),
            ));
        }
        other => other?,
    };
    let txn = opened.db.begin_write().map_err(redb_err)?;
    {
        let meta = txn.open_table(META_TABLE).map_err(redb_err)?;
        if meta.get(HEADER_KEY).map_err(redb_err)?.is_none() {
            return Err(WalletError::Encryption(
                "write_sealed called before wallet exists".into(),
            ));
        }
    }
    let mut cleared = false;
    for op in batch {
        match op {
            SealedWrite::Put {
                table,
                id,
                plaintext,
            } => {
                let blob = encrypt_blob(key.expose(), &table.aad(id), &plaintext)?;
                let mut tbl = txn.open_table(table.def()).map_err(redb_err)?;
                tbl.insert(id, blob.as_slice()).map_err(redb_err)?;
            }
            SealedWrite::Delete { table, id } => {
                let mut tbl = txn.open_table(table.def()).map_err(redb_err)?;
                tbl.remove(id).map_err(redb_err)?;
            }
            SealedWrite::Clear(table) => cleared |= delete_table(&txn, table)?,
        }
    }
    txn.commit().map_err(redb_err)?;
    if cleared && let Err(e) = opened.db.compact() {
        debug!(error = %e, "store: compact after a clear failed (ignored)");
    }
    Ok(())
}

/// Delete one sealed table, tolerating its absence. `true` when it existed.
fn delete_table(txn: &WriteTransaction, table: SealedTable) -> Result<bool, WalletError> {
    #[cfg(test)]
    test_faults::reset_step(test_faults::ResetFault::Delete(table)).map_err(redb_err)?;
    match txn.delete_table(table.def()) {
        Ok(existed) => Ok(existed),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(false),
        Err(e) => Err(redb_err(e)),
    }
}

// ── Reset of the sealed tables ──────────────────────────────────────────────

/// Explicit recovery for a wallet whose sealed tables can't be read ([`KeyStatus::Unavailable`]):
/// verifies the passphrase, mints a fresh data key, deletes the three sealed tables and stores
/// the key ([`replace_data_key`]: a table that won't delete, or a `keys` table that won't take
/// the key, is moved aside) — in write transactions of its own, never bundled with a descriptor
/// save. The origin is always [`KeyOrigin::Minted`] (every row id is free), which the session's
/// vault adopts. Compacts afterwards unless a table was moved aside.
///
/// `Err`, with nothing changed, for a wrong passphrase, a missing or headerless file, or a table
/// that can't even be moved aside.
pub fn reset_sealed(passphrase: &SecretString) -> Result<(DataKey, KeyOrigin), WalletError> {
    reset_sealed_at(&db_path(), passphrase)
}

/// [`reset_sealed`] against `path`.
pub(crate) fn reset_sealed_at(
    path: &Path,
    pw: &SecretString,
) -> Result<(DataKey, KeyOrigin), WalletError> {
    let mut opened = open_existing(path, Wait::Block)?;
    // Verified before any write; the path lock keeps the header from changing meanwhile.
    let master_key = {
        let txn = opened.db.begin_read().map_err(redb_err)?;
        unlock_master_key(&txn, pw)?
    };
    let (key, moved_aside) = replace_data_key(&opened.db, &master_key)?;
    if !moved_aside && let Err(e) = opened.db.compact() {
        debug!(error = %e, "store: compact after a reset failed (ignored)");
    }
    Ok((key, KeyOrigin::Minted))
}

/// A table [`replace_data_key`] clears or rewrites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResetTable {
    Sealed(SealedTable),
    Keys,
}

impl ResetTable {
    fn name(self) -> &'static str {
        match self {
            Self::Sealed(table) => table.name(),
            Self::Keys => "keys",
        }
    }
}

/// One attempt of [`replace_data_key`] inside `txn`: each sealed table deleted (or moved aside),
/// then the wrapped key written (into a fresh `keys` table when the old one is moved aside). The
/// error names the table that failed.
fn reset_in(
    txn: &WriteTransaction,
    wrapped_key: &[u8],
    aside: &[ResetTable],
) -> Result<(), (ResetTable, WalletError)> {
    for table in SealedTable::ALL {
        let target = ResetTable::Sealed(table);
        let done = if aside.contains(&target) {
            move_aside(txn, target)
        } else {
            delete_table(txn, table).map(|_| ())
        };
        done.map_err(|e| (target, e))?;
    }
    let keys = ResetTable::Keys;
    let keys_aside = aside.contains(&keys);
    let stored = if keys_aside {
        move_aside(txn, keys).and_then(|()| store_wrapped_key(txn, wrapped_key))
    } else {
        #[cfg(test)]
        test_faults::reset_step(test_faults::ResetFault::StoreKey)
            .map_err(|e| (keys, redb_err(e)))?;
        store_wrapped_key(txn, wrapped_key)
    };
    stored.map_err(|e| (keys, e))
}

fn store_wrapped_key(txn: &WriteTransaction, wrapped_key: &[u8]) -> Result<(), WalletError> {
    let mut keys = txn.open_table(KEYS_TABLE).map_err(redb_err)?;
    keys.insert(DATA_KEY_ROW, wrapped_key).map_err(redb_err)?;
    Ok(())
}

/// Rename `table` out of the way (a catalog change only — its pages aren't read), tolerating its
/// absence.
fn move_aside(txn: &WriteTransaction, table: ResetTable) -> Result<(), WalletError> {
    let name = format!("{}.unreadable.{:016x}", table.name(), OsRng.next_u64());
    let renamed = match table {
        ResetTable::Sealed(t) => {
            txn.rename_table(t.def(), TableDefinition::<u64, &[u8]>::new(&name))
        }
        ResetTable::Keys => {
            txn.rename_table(KEYS_TABLE, TableDefinition::<&str, &[u8]>::new(&name))
        }
    };
    match renamed {
        Ok(()) | Err(redb::TableError::TableDoesNotExist(_)) => Ok(()),
        Err(e) => Err(redb_err(e)),
    }
}

/// Every sealed table under `key`. `Err` on any storage error — a table that won't open, a row
/// that won't read, a scan that breaks off — never a partial load (see [`load_wallet_at`]). A row
/// that doesn't decrypt (a crypto failure, not a storage one) is skipped and counted.
fn read_sealed(txn: &ReadTransaction, key: &DataKey) -> Result<SealedLoad, WalletError> {
    Ok(SealedLoad {
        wc_state: read_wc_state(txn, key)?,
        connections: read_sealed_rows(txn, SealedTable::WcConnections, key)?,
        signed: read_sealed_rows(txn, SealedTable::SignedMessages, key)?,
    })
}

/// Open a sealed table for reading; `None` when it doesn't exist (nothing saved yet).
fn open_sealed(
    txn: &ReadTransaction,
    table: SealedTable,
) -> Result<Option<redb::ReadOnlyTable<u64, &'static [u8]>>, WalletError> {
    match txn.open_table(table.def()) {
        Ok(t) => Ok(Some(t)),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
        Err(e) => Err(redb_err(e)),
    }
}

fn read_wc_state(
    txn: &ReadTransaction,
    key: &DataKey,
) -> Result<Option<Zeroizing<Vec<u8>>>, WalletError> {
    let table = SealedTable::WcState;
    let Some(tbl) = open_sealed(txn, table)? else {
        return Ok(None);
    };
    let Some(row) = tbl.get(WC_STATE_ID).map_err(redb_err)? else {
        return Ok(None);
    };
    match decrypt_blob(key.expose(), &table.aad(WC_STATE_ID), row.value()) {
        Ok(plaintext) => Ok(Some(plaintext)),
        Err(_) => {
            warn!("store: the saved WalletConnect state doesn't decrypt; ignored");
            Ok(None)
        }
    }
}

fn read_sealed_rows(
    txn: &ReadTransaction,
    table: SealedTable,
    key: &DataKey,
) -> Result<SealedRows, WalletError> {
    let mut out = SealedRows::default();
    let Some(tbl) = open_sealed(txn, table)? else {
        return Ok(out);
    };
    for entry in tbl.iter().map_err(redb_err)? {
        let (k, v) = entry.map_err(redb_err)?;
        let id = k.value();
        #[cfg(test)]
        test_faults::scan_row(table, id).map_err(redb_err)?;
        match decrypt_blob(key.expose(), &table.aad(id), v.value()) {
            Ok(plaintext) => out.rows.push((id, plaintext)),
            Err(_) => out.dropped += 1,
        }
    }
    if out.dropped > 0 {
        warn!(
            table = table.name(),
            dropped = out.dropped,
            "store: sealed rows that failed to decrypt were skipped"
        );
    }
    Ok(out)
}

/// Test hook: a storage error injected into the sealed-table scan, on the calling thread only
/// (`load_wallet_at` reads on its caller's thread), so parallel tests never see it.
#[cfg(test)]
mod test_faults {
    use std::cell::Cell;

    use super::SealedTable;

    thread_local! {
        static SCAN: Cell<Option<(SealedTable, u64)>> = const { Cell::new(None) };
        static RESET: Cell<Option<ResetFault>> = const { Cell::new(None) };
    }

    /// A store step that fails on this thread until [`clear`]: as a broken page would, every
    /// time — deleting that sealed table (any delete: a reset's, a mint's, a `Clear`'s), or a key
    /// replacement writing the key into the `keys` table it found (a fresh one, after moving the
    /// old aside, takes it).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum ResetFault {
        Delete(SealedTable),
        StoreKey,
    }

    /// Scans of `table` on this thread break off at row `id` until [`clear`].
    pub(super) fn fail_scan(table: SealedTable, id: u64) {
        SCAN.set(Some((table, id)));
    }

    pub(super) fn fail_reset(step: ResetFault) {
        RESET.set(Some(step));
    }

    pub(super) fn clear() {
        SCAN.set(None);
        RESET.set(None);
    }

    /// The reset reached `step`.
    pub(super) fn reset_step(step: ResetFault) -> Result<(), redb::StorageError> {
        if RESET.get() == Some(step) {
            return Err(redb::StorageError::Io(std::io::Error::other(
                "injected reset fault",
            )));
        }
        Ok(())
    }

    /// The scan reached row `id` of `table`.
    pub(super) fn scan_row(table: SealedTable, id: u64) -> Result<(), redb::StorageError> {
        match SCAN.get() {
            Some((t, at)) if t == table && at == id => Err(redb::StorageError::Io(
                std::io::Error::other("injected scan fault"),
            )),
            _ => Ok(()),
        }
    }
}

/// [`save_descriptor`] against `path`: the descriptor in one write transaction, then the data key
/// ([`settle_data_key`]) once that has committed.
fn save_to(
    path: &Path,
    desc: &WalletDescriptor,
    pw: &SecretString,
) -> Result<Option<(DataKey, KeyOrigin)>, WalletError> {
    let opened = open_or_create(path, Wait::Block)?;
    // Tighten the on-disk permissions so other local users can't read the
    // (encrypted) wallet blob. Redb's open fd is unaffected; this only
    // restricts who can open the file in the future.
    restrict_to_owner(path, 0o600)?;
    let txn = opened.db.begin_write().map_err(redb_err)?;

    let existing = {
        let meta = txn.open_table(META_TABLE).map_err(redb_err)?;
        match meta.get(HEADER_KEY).map_err(redb_err)? {
            Some(v) => Some(deserialize_header(v.value())?),
            None => None,
        }
    };
    let new_header = existing.is_none();

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

    let header_bytes = postcard::to_stdvec(&header)
        .map_err(|e| WalletError::Encryption(format!("serialize header: {e}")))?;

    {
        let mut meta = txn.open_table(META_TABLE).map_err(redb_err)?;
        meta.insert(HEADER_KEY, header_bytes.as_slice())
            .map_err(redb_err)?;
        let active = (desc.active_index as u32).to_le_bytes();
        meta.insert(ACTIVE_INDEX_KEY, active.as_slice())
            .map_err(redb_err)?;
        // Same txn as the Safes below, so a repaired wallet is never saved
        // without its marker (or the marker without the repaired links).
        let repaired = [u8::from(desc.sibling_links_repaired)];
        meta.insert(SIBLING_LINKS_REPAIRED_KEY, repaired.as_slice())
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
            // Holds the account's private-key bytes — scrub it on drop rather
            // than leaving the serialized key in a freed allocation.
            let plaintext = Zeroizing::new(
                postcard::to_stdvec(account)
                    .map_err(|e| WalletError::Encryption(format!("serialize account {i}: {e}")))?,
            );
            let aad = account_aad(idx);
            let blob = encrypt_blob(master_key.as_slice(), &aad, &plaintext)?;
            accounts.insert(idx, blob.as_slice()).map_err(redb_err)?;
        }
    }

    // Safes table: same shape as accounts — wipe and re-insert from
    // `desc.safes` so a removed Safe drops its row. The `safes:` AAD
    // prefix prevents a Safe ciphertext from being silently swapped into
    // the accounts table or vice versa. Bundled into the same write txn
    // so the file is internally consistent on every commit.
    {
        let mut safes = txn.open_table(SAFES_TABLE).map_err(redb_err)?;
        let existing_keys: Vec<u32> = {
            let mut acc = Vec::new();
            for entry in safes.iter().map_err(redb_err)? {
                let (k, _) = entry.map_err(redb_err)?;
                acc.push(k.value());
            }
            acc
        };
        for k in existing_keys {
            safes.remove(k).map_err(redb_err)?;
        }

        for (i, safe) in desc.safes.iter().enumerate() {
            let idx = i as u32;
            let plaintext = Zeroizing::new(
                postcard::to_stdvec(safe)
                    .map_err(|e| WalletError::Encryption(format!("serialize safe {i}: {e}")))?,
            );
            let aad = safe_aad(idx);
            let blob = encrypt_blob(master_key.as_slice(), &aad, &plaintext)?;
            safes.insert(idx, blob.as_slice()).map_err(redb_err)?;
        }
    }

    txn.commit().map_err(redb_err)?;
    // The data key only after the descriptor is safely on disk: a broken `keys` table (or a
    // sealed table a mint can't clear) costs the session its key, never the user's edit.
    Ok(settle_data_key(&opened.db, &master_key, new_header))
}

/// The descriptor alone, as the store tests have always read it.
#[cfg(test)]
fn load_from(path: &Path, pw: &SecretString) -> Result<WalletDescriptor, WalletError> {
    load_wallet_at(path, pw).map(|u| u.descriptor)
}

/// Read the header, derive the master key (the one Argon2 pass) and check the password.
fn unlock_master_key(
    txn: &ReadTransaction,
    pw: &SecretString,
) -> Result<Zeroizing<[u8; 32]>, WalletError> {
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

    // A failed decrypt of the auth-check blob surfaces as "incorrect
    // password" — the same surface as a real wrong password.
    decrypt_blob(master_key.as_slice(), HEADER_AAD, &header.auth_check)
        .map_err(|_| WalletError::Encryption("incorrect password".into()))?;
    Ok(master_key)
}

fn read_descriptor(
    txn: &ReadTransaction,
    master_key: &[u8; 32],
) -> Result<WalletDescriptor, WalletError> {
    let meta = txn.open_table(META_TABLE).map_err(redb_err)?;
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
    let sibling_links_repaired = meta
        .get(SIBLING_LINKS_REPAIRED_KEY)
        .map_err(redb_err)?
        .is_some_and(|v| v.value() == [1]);

    let accounts_tbl = txn.open_table(ACCOUNTS_TABLE).map_err(redb_err)?;
    let mut accounts: Vec<(u32, AccountDescriptor)> = Vec::new();
    for entry in accounts_tbl.iter().map_err(redb_err)? {
        let (k, v) = entry.map_err(redb_err)?;
        let idx = k.value();
        let aad = account_aad(idx);
        let plaintext = decrypt_blob(master_key.as_slice(), &aad, v.value())?;
        let account: AccountDescriptor = postcard::from_bytes(&plaintext)
            .map_err(|e| WalletError::Encryption(format!("deserialize account {idx}: {e}")))?;
        accounts.push((idx, account));
    }
    accounts.sort_by_key(|(i, _)| *i);
    let accounts: Vec<AccountDescriptor> = accounts.into_iter().map(|(_, a)| a).collect();

    if accounts.is_empty() {
        return Err(WalletError::Encryption("no accounts in store".into()));
    }

    // Safes table: same shape as contacts loader — a wallet written
    // before the safes feature shipped has no `safes` table at all, and
    // `open_table` on a read txn returns `TableDoesNotExist` in that
    // case. Collapse to an empty vec so old wallets load cleanly; the
    // next save lazily creates the table.
    let safes = match txn.open_table(SAFES_TABLE) {
        Ok(safes_tbl) => {
            let mut entries: Vec<(u32, SafeDescriptor)> = Vec::new();
            for entry in safes_tbl.iter().map_err(redb_err)? {
                let (k, v) = entry.map_err(redb_err)?;
                let idx = k.value();
                let aad = safe_aad(idx);
                let plaintext = decrypt_blob(master_key.as_slice(), &aad, v.value())?;
                let safe = decode_safe(&plaintext, idx)?;
                entries.push((idx, safe));
            }
            entries.sort_by_key(|(i, _)| *i);
            entries.into_iter().map(|(_, s)| s).collect()
        }
        Err(redb::TableError::TableDoesNotExist(_)) => Vec::new(),
        Err(e) => return Err(redb_err(e)),
    };

    let active_index = active_index.min(accounts.len() - 1);
    Ok(WalletDescriptor {
        accounts,
        safes,
        active_index,
        sibling_links_repaired,
    })
}

/// Decode one decrypted Safe row, tolerating every layout ever persisted.
///
/// Postcard isn't self-describing: appending a field to `SafeDescriptor` makes
/// blobs written before the field one or more bytes short, and a plain
/// `from_bytes` would hard-fail the whole wallet load. So the shapes are tried
/// **newest first**, and the first that decodes wins.
///
/// # Adding a field — read this before you do
///
/// The order is not a preference, it is the only correct one, and the reason is
/// that `postcard::from_bytes` **ignores trailing bytes** (it has no
/// "consumed the whole input" check; `take_from_bytes` is the one that reports
/// a remainder). Two consequences, and they are asymmetric:
///
/// - A *longer* shape read from a *shorter* blob reliably errors: every
///   appendable type — `Option`, `bool`, any integer varint, `String`, `Vec`,
///   an enum discriminant — begins by popping at least one byte, and there is
///   none left. That is what makes the fallback fire.
/// - A *shorter* shape read from a *longer* blob **always succeeds**, silently
///   discarding the trailing field.
///
/// So the procedure is: **snapshot the current shape as a new `LegacySafeVn`
/// struct *before* appending the field, and add it to the chain below in
/// newest-to-oldest order.** Never edit an existing rung, and never skip one.
///
/// Extending the newest rung in place instead — which the previous wording of
/// this comment could be read as suggesting — is the failure this note exists
/// to prevent: a row written with the field populated would fall past the
/// current shape, decode through a rung that predates the field, and lose it
/// with no error. That failure is also **value-dependent**: a row whose new
/// field is `None`/default decodes "correctly" through the wrong rung, so a
/// test fixture that leaves it empty will not catch it. Test the fallback with
/// the field *populated* (see `decode_safe_never_loses_a_populated_field`).
fn decode_safe(plaintext: &[u8], idx: u32) -> Result<SafeDescriptor, WalletError> {
    /// `SafeDescriptor` exactly as persisted before `tx_service_url`
    /// shipped. Field order/types must never change.
    #[derive(serde::Deserialize)]
    struct LegacySafeV1 {
        name: Option<String>,
        chain_id: u64,
        address: [u8; 20],
        version: String,
        trust: crate::wallet::SafeTrust,
        threshold: u32,
        owners: Vec<[u8; 20]>,
        modules: Vec<[u8; 20]>,
        guard: Option<[u8; 20]>,
        fallback_handler: Option<[u8; 20]>,
        linked_signer_indices: Vec<u32>,
        sibling_chains: Vec<u64>,
        cached_at: u64,
    }

    if let Ok(safe) = postcard::from_bytes::<SafeDescriptor>(plaintext) {
        return Ok(safe);
    }
    let legacy: LegacySafeV1 = postcard::from_bytes(plaintext)
        .map_err(|e| WalletError::Encryption(format!("deserialize safe {idx}: {e}")))?;
    Ok(SafeDescriptor {
        name: legacy.name,
        chain_id: legacy.chain_id,
        address: legacy.address,
        version: legacy.version,
        trust: legacy.trust,
        threshold: legacy.threshold,
        owners: legacy.owners,
        modules: legacy.modules,
        guard: legacy.guard,
        fallback_handler: legacy.fallback_handler,
        linked_signer_indices: legacy.linked_signer_indices,
        sibling_chains: legacy.sibling_chains,
        cached_at: legacy.cached_at,
        tx_service_url: None,
    })
}

fn deserialize_header(bytes: &[u8]) -> Result<Header, WalletError> {
    postcard::from_bytes::<Header>(bytes)
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

/// Decrypt one record. The returned plaintext may contain private-key
/// material (account rows), so it is wrapped in `Zeroizing` to scrub the
/// buffer when the caller drops it rather than leaving it in freed memory.
fn decrypt_blob(key: &[u8], aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, WalletError> {
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
        .map(Zeroizing::new)
        .map_err(|e| WalletError::Encryption(format!("decrypt: {e}")))
}

fn account_aad(idx: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(ACCOUNT_AAD_PREFIX.len() + 4);
    out.extend_from_slice(ACCOUNT_AAD_PREFIX);
    out.extend_from_slice(&idx.to_le_bytes());
    out
}

fn contact_aad(idx: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(CONTACT_AAD_PREFIX.len() + 4);
    out.extend_from_slice(CONTACT_AAD_PREFIX);
    out.extend_from_slice(&idx.to_le_bytes());
    out
}

fn safe_aad(idx: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(SAFE_AAD_PREFIX.len() + 4);
    out.extend_from_slice(SAFE_AAD_PREFIX);
    out.extend_from_slice(&idx.to_le_bytes());
    out
}

/// Persist the contacts list under the existing wallet's master key.
///
/// Reuses the same per-row AEAD pattern as accounts but lives in its own
/// `contacts` table — a contact edit doesn't re-encrypt every account row
/// (and an account edit doesn't re-encrypt every contact). The `contacts:`
/// AAD prefix prevents a contact ciphertext from being silently swapped
/// into the accounts table or vice versa.
pub fn save_contacts(contacts: &[Contact], passphrase: &SecretString) -> Result<(), WalletError> {
    save_contacts_to(&db_path(), contacts, passphrase)
}

pub fn load_contacts(passphrase: &SecretString) -> Result<Vec<Contact>, WalletError> {
    load_contacts_from(&db_path(), passphrase)
}

fn save_contacts_to(
    path: &Path,
    contacts: &[Contact],
    pw: &SecretString,
) -> Result<(), WalletError> {
    let opened = open_or_create(path, Wait::Block)?;
    restrict_to_owner(path, 0o600)?;
    let txn = opened.db.begin_write().map_err(redb_err)?;

    // Verify password against the existing header. Contacts are only
    // stored alongside an existing wallet — a contacts save without a
    // header is a logic error elsewhere (the App should never dispatch
    // this before a successful unlock).
    let header = {
        let meta = txn.open_table(META_TABLE).map_err(redb_err)?;
        match meta.get(HEADER_KEY).map_err(redb_err)? {
            Some(v) => deserialize_header(v.value())?,
            None => {
                return Err(WalletError::Encryption(
                    "save_contacts called before wallet exists".into(),
                ));
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
    decrypt_blob(master_key.as_slice(), HEADER_AAD, &header.auth_check)
        .map_err(|_| WalletError::Encryption("incorrect password".into()))?;

    {
        let mut tbl = txn.open_table(CONTACTS_TABLE).map_err(redb_err)?;
        // Wipe the table, then re-insert. Same shape as the accounts save
        // path so a smaller list correctly drops removed rows.
        let existing_keys: Vec<u32> = {
            let mut acc = Vec::new();
            for entry in tbl.iter().map_err(redb_err)? {
                let (k, _) = entry.map_err(redb_err)?;
                acc.push(k.value());
            }
            acc
        };
        for k in existing_keys {
            tbl.remove(k).map_err(redb_err)?;
        }
        for (i, contact) in contacts.iter().enumerate() {
            let idx = i as u32;
            let plaintext = Zeroizing::new(
                postcard::to_stdvec(contact)
                    .map_err(|e| WalletError::Encryption(format!("serialize contact {i}: {e}")))?,
            );
            let aad = contact_aad(idx);
            let blob = encrypt_blob(master_key.as_slice(), &aad, &plaintext)?;
            tbl.insert(idx, blob.as_slice()).map_err(redb_err)?;
        }
    }

    txn.commit().map_err(redb_err)?;
    Ok(())
}

fn load_contacts_from(path: &Path, pw: &SecretString) -> Result<Vec<Contact>, WalletError> {
    let opened = open_existing(path, Wait::Block)?;
    let txn = opened.db.begin_read().map_err(redb_err)?;

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

    // Treat a missing contacts table as empty — fresh-since-feature
    // wallets have never saved contacts, and the table is created lazily
    // on first save. `open_table` on a read txn returns
    // `TableError::TableDoesNotExist` for missing tables; collapse to []
    // rather than bubbling that up as an error.
    let contacts_tbl = match txn.open_table(CONTACTS_TABLE) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(e) => return Err(redb_err(e)),
    };
    let mut entries: Vec<(u32, Contact)> = Vec::new();
    for entry in contacts_tbl.iter().map_err(redb_err)? {
        let (k, v) = entry.map_err(redb_err)?;
        let idx = k.value();
        let aad = contact_aad(idx);
        let plaintext = decrypt_blob(master_key.as_slice(), &aad, v.value())?;
        entries.push((idx, decode_contact(&plaintext, idx)?));
    }
    entries.sort_by_key(|(i, _)| *i);
    Ok(entries.into_iter().map(|(_, c)| c).collect())
}

/// Decode one decrypted contact row, tolerating every layout ever persisted.
///
/// The counterpart of [`decode_safe`], and its doc comment is the one to read
/// before adding a field — the rule, the reason, and the failure mode are
/// identical. In short: **snapshot the current shape as a new rung before
/// appending, try rungs newest-first, never edit or skip one.**
///
/// One thing here is *worse* than the Safe case and worth stating on its own.
/// `Contact` nests `Option<ContactEns>`, so a field appended to `ContactEns`
/// changes the bytes only for contacts that actually carry a name — a row with
/// `ens: None` is byte-identical across the versions. A migration test built on
/// a nameless fixture therefore passes without executing this fallback at all.
/// Any test of a rung below has to use a contact whose `ens` is `Some`.
///
/// Postcard offers no way to resume mid-stream, so a rung must mirror the whole
/// outer record even when only the nested type changed; there is no byte offset
/// at which to restart at the `ens` boundary.
fn decode_contact(plaintext: &[u8], idx: u32) -> Result<Contact, WalletError> {
    if let Ok(contact) = postcard::from_bytes::<Contact>(plaintext) {
        return Ok(contact);
    }
    // No rung below the current shape yet — `Contact` has not changed since it
    // shipped. The indirection exists so the *first* field addition is a
    // localized edit here rather than a change to the load loop, and so the
    // rule above is stated somewhere the next person will look.
    Err(WalletError::Encryption(format!(
        "deserialize contact {idx}: no known layout matches this row"
    )))
}

/// Persist the Privacy Pools mnemonic under the existing wallet's master key.
///
/// Same per-row AEAD + password-recheck pattern as `save_contacts`, in its own
/// `pp` table with a `pp:seed` AAD so the record can't be swapped into
/// accounts/contacts/safes. Only ever called on an unlocked wallet.
pub fn save_pp_seed(phrase: &SecretString, passphrase: &SecretString) -> Result<(), WalletError> {
    save_pp_seed_to(&db_path(), phrase, passphrase)
}

pub fn load_pp_seed(passphrase: &SecretString) -> Result<Option<SecretString>, WalletError> {
    load_pp_seed_from(&db_path(), passphrase)
}

/// Create the pool identity: like [`save_pp_seed`], but only when no seed row exists yet (an
/// existing one is never overwritten — `Err` "a pool identity already exists"). `save_pp_seed`
/// stays the upsert, for an explicit restore.
pub fn create_pp_seed(phrase: &SecretString, passphrase: &SecretString) -> Result<(), WalletError> {
    write_pp_seed(&db_path(), phrase, passphrase, SeedWrite::CreateOnly)
}

// ── Privacy Pools note cache ────────────────────────────────────────────────
//
// Encrypted under a **32-byte key the caller derives from the pool account**
// (see `pool::sync::notes_cipher_key`), NOT the wallet passphrase — the coordinator
// holds the account but not the passphrase, and per-pool-sync saves must not pay
// Argon2. The key is as strong as the mnemonic (which is itself stored under the
// passphrase), so cracking the passphrase is still the only path in. A row from a
// different identity simply won't decrypt and is skipped.

/// Persist one pool's note cache, encrypted under an account-derived `key`. The
/// cache is advisory — losing or clearing it just forces a full re-scan — so
/// there's no migration story to maintain.
pub fn save_pp_notes(
    chain_id: u64,
    pool: Address,
    notes: &CachedNotes,
    key: &[u8; 32],
) -> Result<(), WalletError> {
    save_pp_notes_to(&db_path(), chain_id, pool, notes, key)
}

/// Load every note cache decryptable with `key`, keyed by `(chain_id, pool)`.
/// Rows from other identities (or a missing table) collapse to nothing.
pub fn load_all_pp_notes(
    key: &[u8; 32],
) -> Result<HashMap<(u64, Address), CachedNotes>, WalletError> {
    load_all_pp_notes_from(&db_path(), key)
}

/// Drop every persisted note cache — a different mnemonic derives a different
/// note set, so the cache is invalidated wholesale on identity change.
pub fn clear_pp_notes() -> Result<(), WalletError> {
    clear_pp_notes_at(&db_path())
}

fn pp_notes_key(chain_id: u64, pool: Address) -> String {
    format!("{chain_id}:{pool:#x}")
}

fn parse_pp_notes_key(key: &str) -> Option<(u64, Address)> {
    let (cid, addr) = key.split_once(':')?;
    Some((cid.parse().ok()?, Address::from_str(addr).ok()?))
}

fn pp_notes_aad(key: &str) -> Vec<u8> {
    [PP_NOTES_AAD_PREFIX, key.as_bytes()].concat()
}

fn save_pp_notes_to(
    path: &Path,
    chain_id: u64,
    pool: Address,
    notes: &CachedNotes,
    key: &[u8; 32],
) -> Result<(), WalletError> {
    let opened = open_or_create(path, Wait::Try)?;
    restrict_to_owner(path, 0o600)?;
    let txn = opened.db.begin_write().map_err(redb_err)?;
    {
        let row_key = pp_notes_key(chain_id, pool);
        let plaintext = Zeroizing::new(
            postcard::to_stdvec(notes)
                .map_err(|e| WalletError::Encryption(format!("serialize pp notes: {e}")))?,
        );
        let aad = pp_notes_aad(&row_key);
        let blob = encrypt_blob(key, &aad, &plaintext)?;
        let mut tbl = txn.open_table(PP_NOTES_TABLE).map_err(redb_err)?;
        tbl.insert(row_key.as_str(), blob.as_slice())
            .map_err(redb_err)?;
    }
    txn.commit().map_err(redb_err)?;
    Ok(())
}

fn load_all_pp_notes_from(
    path: &Path,
    key: &[u8; 32],
) -> Result<HashMap<(u64, Address), CachedNotes>, WalletError> {
    let opened = match open_existing(path, Wait::Try) {
        Err(WalletError::NotFound) => return Ok(HashMap::new()),
        other => other?,
    };
    let txn = opened.db.begin_read().map_err(redb_err)?;

    let tbl = match txn.open_table(PP_NOTES_TABLE) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(HashMap::new()),
        Err(e) => return Err(redb_err(e)),
    };
    let mut out = HashMap::new();
    for entry in tbl.iter().map_err(redb_err)? {
        let (k, v) = entry.map_err(redb_err)?;
        let row_key = k.value();
        let Some(id) = parse_pp_notes_key(row_key) else {
            continue; // unrecognized key shape — skip rather than fail the load
        };
        let aad = pp_notes_aad(row_key);
        // A row written by a *different* identity won't decrypt under this key —
        // skip it (and any undecodable payload) rather than failing the load.
        let Ok(plaintext) = decrypt_blob(key, &aad, v.value()) else {
            continue;
        };
        if let Ok(notes) = postcard::from_bytes::<CachedNotes>(&plaintext) {
            out.insert(id, notes);
        }
    }
    Ok(out)
}

fn clear_pp_notes_at(path: &Path) -> Result<(), WalletError> {
    let opened = match open_existing(path, Wait::Try) {
        Err(WalletError::NotFound) => return Ok(()),
        other => other?,
    };
    let txn = opened.db.begin_write().map_err(redb_err)?;
    match txn.delete_table(PP_NOTES_TABLE) {
        Ok(_) => {}
        Err(redb::TableError::TableDoesNotExist(_)) => {}
        Err(e) => return Err(redb_err(e)),
    }
    txn.commit().map_err(redb_err)?;
    Ok(())
}

/// How [`write_pp_seed`] treats an existing seed row.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SeedWrite {
    /// Replace it (an explicit restore).
    Upsert,
    /// Refuse: creating an identity must never overwrite the one the user may have funds under.
    CreateOnly,
}

fn save_pp_seed_to(
    path: &Path,
    phrase: &SecretString,
    pw: &SecretString,
) -> Result<(), WalletError> {
    write_pp_seed(path, phrase, pw, SeedWrite::Upsert)
}

fn write_pp_seed(
    path: &Path,
    phrase: &SecretString,
    pw: &SecretString,
    mode: SeedWrite,
) -> Result<(), WalletError> {
    let opened = open_or_create(path, Wait::Block)?;
    restrict_to_owner(path, 0o600)?;
    let txn = opened.db.begin_write().map_err(redb_err)?;

    // The PP seed only lives alongside an existing wallet — a save without a
    // header is a logic error (the App must never dispatch this before unlock).
    let header = {
        let meta = txn.open_table(META_TABLE).map_err(redb_err)?;
        match meta.get(HEADER_KEY).map_err(redb_err)? {
            Some(v) => deserialize_header(v.value())?,
            None => {
                return Err(WalletError::Encryption(
                    "save_pp_seed called before wallet exists".into(),
                ));
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
    decrypt_blob(master_key.as_slice(), HEADER_AAD, &header.auth_check)
        .map_err(|_| WalletError::Encryption("incorrect password".into()))?;

    {
        let record = PpSeedRecord {
            phrase: phrase.expose_secret().to_string(),
        };
        let plaintext = Zeroizing::new(
            postcard::to_stdvec(&record)
                .map_err(|e| WalletError::Encryption(format!("serialize pp seed: {e}")))?,
        );
        let blob = encrypt_blob(master_key.as_slice(), PP_SEED_AAD, &plaintext)?;
        let mut tbl = txn.open_table(PP_TABLE).map_err(redb_err)?;
        // Checked in the same transaction as the insert, under the store lock: nothing can slip
        // a seed in between.
        if mode == SeedWrite::CreateOnly && tbl.get(PP_SEED_KEY).map_err(redb_err)?.is_some() {
            return Err(WalletError::Encryption(
                "a pool identity already exists".into(),
            ));
        }
        tbl.insert(PP_SEED_KEY, blob.as_slice()).map_err(redb_err)?;
    }

    txn.commit().map_err(redb_err)?;
    Ok(())
}

// `Wait::Block`, not `Try`: a busy file must never read as "no pool identity" — the pool app would
// then offer "Create identity", and the user could replace a seed they have funds under.
fn load_pp_seed_from(path: &Path, pw: &SecretString) -> Result<Option<SecretString>, WalletError> {
    let opened = open_existing(path, Wait::Block)?;
    let txn = opened.db.begin_read().map_err(redb_err)?;

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

    // A wallet created before Privacy Pools shipped has no `pp` table; a wallet
    // that has one but no row hasn't set up pools yet. Both collapse to `None`.
    let tbl = match txn.open_table(PP_TABLE) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(redb_err(e)),
    };
    let Some(v) = tbl.get(PP_SEED_KEY).map_err(redb_err)? else {
        return Ok(None);
    };
    let plaintext = decrypt_blob(master_key.as_slice(), PP_SEED_AAD, v.value())?;
    let record: PpSeedRecord = postcard::from_bytes(&plaintext)
        .map_err(|e| WalletError::Encryption(format!("deserialize pp seed: {e}")))?;
    Ok(Some(SecretString::new(record.phrase.into_boxed_str())))
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
                    key_bytes: crate::wallet::SecretKeyBytes::new([0xab; 32]),
                },
                AccountDescriptor::Ledger {
                    name: None,
                    path: LedgerHdPath::LedgerLive(2),
                    address: [0x33; 20],
                },
                AccountDescriptor::Local {
                    name: None,
                    key_bytes: crate::wallet::SecretKeyBytes::new([0xcd; 32]),
                },
            ],
            safes: Vec::new(),
            active_index: 2,
            sibling_links_repaired: true,
        };
        save_to(&path, &desc, &pw("hunter2")).unwrap();
        let loaded = load_from(&path, &pw("hunter2")).unwrap();
        assert_eq!(loaded.accounts.len(), 3);
        assert_eq!(loaded.active_index, 2);
        match &loaded.accounts[0] {
            AccountDescriptor::Local { name, key_bytes } => {
                assert_eq!(name.as_deref(), Some("Treasury"));
                assert_eq!(key_bytes.as_array(), &[0xab; 32]);
            }
            _ => panic!("expected Local"),
        }
        match &loaded.accounts[1] {
            AccountDescriptor::Ledger {
                name,
                path,
                address,
            } => {
                assert!(name.is_none());
                assert!(matches!(path, LedgerHdPath::LedgerLive(2)));
                assert_eq!(*address, [0x33; 20]);
            }
            _ => panic!("expected Ledger"),
        }
        match &loaded.accounts[2] {
            AccountDescriptor::Local { key_bytes, .. } => {
                assert_eq!(key_bytes.as_array(), &[0xcd; 32])
            }
            _ => panic!("expected Local"),
        }
    }

    #[test]
    fn sibling_links_repaired_marker_round_trips_both_ways() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let mut desc = wallet_with_safes(Vec::new());
        assert!(desc.sibling_links_repaired);

        save_to(&path, &desc, &pw("pw")).unwrap();
        assert!(load_from(&path, &pw("pw")).unwrap().sibling_links_repaired);

        // A later save carries whatever the wallet says now — the same
        // write as the accounts and Safes.
        desc.sibling_links_repaired = false;
        save_to(&path, &desc, &pw("pw")).unwrap();
        assert!(!load_from(&path, &pw("pw")).unwrap().sibling_links_repaired);
    }

    #[test]
    fn a_wallet_saved_before_the_marker_loads_as_not_yet_repaired() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        save_to(&path, &wallet_with_safes(Vec::new()), &pw("pw")).unwrap();
        // What a pre-marker build wrote: no such key in `meta`.
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut meta = txn.open_table(META_TABLE).unwrap();
                assert!(meta.remove(SIBLING_LINKS_REPAIRED_KEY).unwrap().is_some());
            }
            txn.commit().unwrap();
        }
        let loaded = load_from(&path, &pw("pw")).unwrap();
        assert!(
            !loaded.sibling_links_repaired,
            "a legacy wallet gets its one repair on the next unlock"
        );
        assert_eq!(loaded.accounts.len(), 1, "and otherwise loads as before");
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_wallet_file_with_owner_only_perms() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = WalletDescriptor::single(AccountDescriptor::Local {
            name: None,
            key_bytes: crate::wallet::SecretKeyBytes::new([0x42; 32]),
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
            key_bytes: crate::wallet::SecretKeyBytes::new([0x42; 32]),
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
            key_bytes: crate::wallet::SecretKeyBytes::new([0x11; 32]),
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
        // a saved header round-trips through postcard with the values intact.
        let original = Header {
            salt: [0x7e; SALT_LEN],
            argon2_m_cost_kib: 12_345,
            argon2_t_cost: 4,
            argon2_p_cost: 2,
            auth_check: vec![0xaa; 64],
        };
        let bytes = postcard::to_stdvec(&original).unwrap();
        let parsed = deserialize_header(&bytes).unwrap();
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
            key_bytes: crate::wallet::SecretKeyBytes::new([0x55; 32]),
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
                    key_bytes: crate::wallet::SecretKeyBytes::new([0x01; 32]),
                },
                AccountDescriptor::Local {
                    name: None,
                    key_bytes: crate::wallet::SecretKeyBytes::new([0x02; 32]),
                },
                AccountDescriptor::Local {
                    name: None,
                    key_bytes: crate::wallet::SecretKeyBytes::new([0x03; 32]),
                },
            ],
            safes: Vec::new(),
            active_index: 2,
            sibling_links_repaired: true,
        };
        save_to(&path, &big, &pw("pw")).unwrap();

        let small = WalletDescriptor::single(AccountDescriptor::Local {
            name: None,
            key_bytes: crate::wallet::SecretKeyBytes::new([0x09; 32]),
        });
        save_to(&path, &small, &pw("pw")).unwrap();

        let loaded = load_from(&path, &pw("pw")).unwrap();
        assert_eq!(loaded.accounts.len(), 1);
        assert_eq!(loaded.active_index, 0);
        match &loaded.accounts[0] {
            AccountDescriptor::Local { key_bytes, .. } => {
                assert_eq!(key_bytes.as_array(), &[0x09; 32])
            }
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
                    key_bytes: crate::wallet::SecretKeyBytes::new([0x01; 32]),
                },
                AccountDescriptor::Local {
                    name: None,
                    key_bytes: crate::wallet::SecretKeyBytes::new([0x02; 32]),
                },
            ],
            safes: Vec::new(),
            active_index: 0,
            sibling_links_repaired: true,
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

    // ── Contacts tests ───────────────────────────────────────────────────

    use crate::wallet::{Contact, ContactEns};

    fn sample_contact(seed: u8, name: &str) -> Contact {
        Contact {
            name: name.into(),
            address: [seed; 20],
            kaomoji: "(◕‿◕)".into(),
            notes: format!("seed {seed}"),
            ens: None,
        }
    }

    #[test]
    fn contacts_save_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = WalletDescriptor::single(AccountDescriptor::Local {
            name: None,
            key_bytes: crate::wallet::SecretKeyBytes::new([0x42; 32]),
        });
        save_to(&path, &desc, &pw("pw")).unwrap();

        let contacts = vec![
            sample_contact(0x01, "A"),
            Contact {
                name: "vitalik.eth".into(),
                address: [0xab; 20],
                kaomoji: "(◕‿◕✿)".into(),
                notes: String::new(),
                ens: Some(ContactEns {
                    name: "vitalik.eth".into(),
                    last_resolved_addr: [0xab; 20],
                }),
            },
        ];
        save_contacts_to(&path, &contacts, &pw("pw")).unwrap();
        let loaded = load_contacts_from(&path, &pw("pw")).unwrap();
        assert_eq!(loaded, contacts);
    }

    #[test]
    fn contacts_load_returns_empty_when_table_missing() {
        // A wallet saved before the contacts feature has no contacts
        // table at all. `load_contacts` must collapse that to an empty
        // vec rather than erroring — otherwise unlock would fail
        // post-feature on every pre-feature wallet.
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = WalletDescriptor::single(AccountDescriptor::Local {
            name: None,
            key_bytes: crate::wallet::SecretKeyBytes::new([0x42; 32]),
        });
        save_to(&path, &desc, &pw("pw")).unwrap();
        let loaded = load_contacts_from(&path, &pw("pw")).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn contacts_save_overwrite_replaces_set() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = WalletDescriptor::single(AccountDescriptor::Local {
            name: None,
            key_bytes: crate::wallet::SecretKeyBytes::new([0x42; 32]),
        });
        save_to(&path, &desc, &pw("pw")).unwrap();

        let big = vec![
            sample_contact(0x01, "A"),
            sample_contact(0x02, "B"),
            sample_contact(0x03, "C"),
        ];
        save_contacts_to(&path, &big, &pw("pw")).unwrap();
        let small = vec![sample_contact(0x09, "Solo")];
        save_contacts_to(&path, &small, &pw("pw")).unwrap();
        let loaded = load_contacts_from(&path, &pw("pw")).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "Solo");
    }

    #[test]
    fn contacts_save_refuses_wrong_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = WalletDescriptor::single(AccountDescriptor::Local {
            name: None,
            key_bytes: crate::wallet::SecretKeyBytes::new([0x42; 32]),
        });
        save_to(&path, &desc, &pw("right")).unwrap();
        let err = save_contacts_to(&path, &[sample_contact(0x01, "A")], &pw("wrong")).unwrap_err();
        match err {
            WalletError::Encryption(msg) => assert!(msg.contains("incorrect password")),
            other => panic!("expected wrong-password error, got {other:?}"),
        }
    }

    #[test]
    fn contact_aad_namespaces_against_account_aad() {
        // A blob encrypted under the contacts AAD must not decrypt under
        // the accounts AAD (and vice versa). This is the mechanism that
        // stops a copy-paste attack across tables — the AEAD tag binds
        // the row to its table.
        let key = [0x77u8; 32];
        let plaintext = b"hello";
        let blob_c = encrypt_blob(&key, &contact_aad(0), plaintext).unwrap();
        let blob_a = encrypt_blob(&key, &account_aad(0), plaintext).unwrap();
        assert!(decrypt_blob(&key, &account_aad(0), &blob_c).is_err());
        assert!(decrypt_blob(&key, &contact_aad(0), &blob_a).is_err());
        // Sanity: same AAD on both sides round-trips.
        assert_eq!(
            decrypt_blob(&key, &contact_aad(0), &blob_c)
                .unwrap()
                .as_slice(),
            plaintext,
        );
        assert_eq!(
            decrypt_blob(&key, &account_aad(0), &blob_a)
                .unwrap()
                .as_slice(),
            plaintext,
        );
    }

    // ── Safes tests ──────────────────────────────────────────────────────

    use crate::wallet::{SafeDescriptor, SafeTrust};

    /// Minimal Canonical Safe — owner-of-one threshold-one. Tests that
    /// don't care about the contents use this and override fields as
    /// needed.
    fn minimal_safe(seed: u8, chain_id: u64) -> SafeDescriptor {
        SafeDescriptor {
            name: Some(format!("Safe seed {seed:02x}")),
            chain_id,
            address: [seed; 20],
            version: "1.4.1".into(),
            trust: SafeTrust::Canonical,
            threshold: 1,
            owners: vec![[seed.wrapping_add(1); 20]],
            modules: Vec::new(),
            guard: None,
            fallback_handler: None,
            linked_signer_indices: vec![0],
            sibling_chains: Vec::new(),
            cached_at: 1_700_000_000,
            tx_service_url: None,
        }
    }

    /// Safe with every optional field populated — exercises the
    /// "loud surfaces" (modules, guard, fallback handler), the
    /// unrecognized-implementation branch, multiple owners and signer
    /// links, and the sibling-chains list. The deserialized round-trip
    /// of this must equal the input bit-for-bit.
    fn rich_safe(seed: u8) -> SafeDescriptor {
        SafeDescriptor {
            name: None,   // exercise the unnamed path
            chain_id: 10, // Optimism
            address: [seed; 20],
            version: "1.3.0".into(),
            trust: SafeTrust::UnrecognizedImpl,
            threshold: 3,
            owners: vec![[0xa1; 20], [0xa2; 20], [0xa3; 20], [0xa4; 20]],
            modules: vec![[0xb1; 20], [0xb2; 20]],
            guard: Some([0xc1; 20]),
            fallback_handler: Some([0xd1; 20]),
            linked_signer_indices: vec![0, 2],
            sibling_chains: vec![1, 8453], // mainnet, base
            cached_at: 1_700_000_042,
            tx_service_url: Some("https://txs.example-dao.org".into()),
        }
    }

    #[test]
    fn decode_safe_falls_back_to_pre_service_url_layout() {
        // Serialize the legacy 13-field shape verbatim (everything up to
        // `cached_at`) and decode through the loader's fallback — older
        // wallets must load with `tx_service_url: None`, not error.
        let current = minimal_safe(0x07, 1);
        let legacy_bytes = postcard::to_stdvec(&(
            &current.name,
            current.chain_id,
            current.address,
            &current.version,
            &current.trust,
            current.threshold,
            &current.owners,
            &current.modules,
            current.guard,
            current.fallback_handler,
            &current.linked_signer_indices,
            &current.sibling_chains,
            current.cached_at,
        ))
        .unwrap();
        let decoded = decode_safe(&legacy_bytes, 0).unwrap();
        assert_eq!(decoded, current);
        assert!(decoded.tx_service_url.is_none());

        // And the current shape still round-trips, custom URL intact.
        let rich = rich_safe(0x42);
        let bytes = postcard::to_stdvec(&rich).unwrap();
        assert_eq!(decode_safe(&bytes, 1).unwrap(), rich);
    }

    /// The guard on the *next* field addition, and the one the fallback test
    /// above cannot provide.
    ///
    /// `postcard::from_bytes` ignores trailing bytes, so a shape shorter than
    /// the blob always decodes — silently dropping whatever it didn't read. A
    /// future field appended without first snapshotting the current shape as a
    /// new rung would therefore make every populated `tx_service_url` fall
    /// through to `LegacySafeV1` and come back `None`, with no error anywhere.
    ///
    /// It is deliberately asserted on a **populated** URL: the existing
    /// fallback test uses `minimal_safe`, whose `tx_service_url` is `None`, and
    /// `None` decodes identically through the right rung and the wrong one. A
    /// fixture that leaves the newest field empty cannot distinguish them.
    #[test]
    fn decode_safe_never_loses_a_populated_field() {
        let rich = rich_safe(0x42);
        assert!(
            rich.tx_service_url.is_some(),
            "the whole point is a populated newest field",
        );
        let bytes = postcard::to_stdvec(&rich).unwrap();
        assert_eq!(
            decode_safe(&bytes, 0).unwrap().tx_service_url,
            rich.tx_service_url,
            "the newest shape has to win over any legacy rung that also parses",
        );

        // And the mechanism behind that requirement, stated as a fact about the
        // codec rather than about this struct: the legacy shape *does* accept
        // the longer blob, so rung order is the only thing keeping it out.
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct ShorterThanCurrent {
            name: Option<String>,
            chain_id: u64,
            address: [u8; 20],
            version: String,
            trust: crate::wallet::SafeTrust,
            threshold: u32,
            owners: Vec<[u8; 20]>,
            modules: Vec<[u8; 20]>,
            guard: Option<[u8; 20]>,
            fallback_handler: Option<[u8; 20]>,
            linked_signer_indices: Vec<u32>,
            sibling_chains: Vec<u64>,
            cached_at: u64,
        }
        assert!(
            postcard::from_bytes::<ShorterThanCurrent>(&bytes).is_ok(),
            "postcard ignores trailing bytes — a shorter rung will happily \
             swallow a longer row, which is why rungs are tried newest first",
        );
    }

    fn wallet_with_safes(safes: Vec<SafeDescriptor>) -> WalletDescriptor {
        WalletDescriptor {
            accounts: vec![AccountDescriptor::Local {
                name: None,
                key_bytes: crate::wallet::SecretKeyBytes::new([0x42; 32]),
            }],
            safes,
            active_index: 0,
            sibling_links_repaired: true,
        }
    }

    #[test]
    fn safes_save_and_load_roundtrip_preserves_every_field() {
        // The rich variant exercises both SafeTrust branches, optional
        // guard/fallback (Some), multi-element owners/modules/linked-
        // signers/siblings, and the unnamed display-name fallback path.
        // Anything that gets lost between save and load shows up here.
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = wallet_with_safes(vec![minimal_safe(0x01, 1), rich_safe(0x55)]);
        save_to(&path, &desc, &pw("hunter2")).unwrap();
        let loaded = load_from(&path, &pw("hunter2")).unwrap();
        assert_eq!(loaded.safes, desc.safes);
        // Sanity: accounts didn't get scrambled by the new safes loop.
        assert_eq!(loaded.accounts.len(), 1);
    }

    #[test]
    fn safes_load_returns_empty_when_table_missing() {
        // A wallet saved before the safes feature has no `safes` table at
        // all — the redb file only contains `meta`, `accounts`, and
        // possibly `contacts`. `load_from` must collapse the missing
        // table to an empty vec rather than erroring, otherwise unlock
        // breaks for every pre-feature wallet on upgrade.
        //
        // We can't easily construct a "pre-feature" file in-test (the
        // current `save_to` always opens the safes table). So we save
        // normally, then drop the safes table out-of-band and reload.
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = wallet_with_safes(Vec::new());
        save_to(&path, &desc, &pw("pw")).unwrap();
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            txn.delete_table(SAFES_TABLE).unwrap();
            txn.commit().unwrap();
        }

        let loaded = load_from(&path, &pw("pw")).unwrap();
        assert!(loaded.safes.is_empty());
        assert_eq!(loaded.accounts.len(), 1);
    }

    #[test]
    fn safes_save_overwrite_drops_removed_rows() {
        // A second save with fewer safes must actually shrink the table —
        // not silently leave the deleted rows as ghosts that re-appear on
        // load. Same shape as `save_overwrite_replaces_account_set`.
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let big = wallet_with_safes(vec![
            minimal_safe(0x01, 1),
            minimal_safe(0x02, 10),
            minimal_safe(0x03, 8453),
        ]);
        save_to(&path, &big, &pw("pw")).unwrap();
        let small = wallet_with_safes(vec![minimal_safe(0x09, 1)]);
        save_to(&path, &small, &pw("pw")).unwrap();

        let loaded = load_from(&path, &pw("pw")).unwrap();
        assert_eq!(loaded.safes.len(), 1);
        assert_eq!(loaded.safes[0].address, [0x09; 20]);
    }

    #[test]
    fn safes_save_with_empty_vec_clears_existing_table() {
        // Onboarding flow inverse: a wallet that had safes, all removed.
        // The table must end up empty, not retain old entries.
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let with_safes = wallet_with_safes(vec![minimal_safe(0x01, 1), minimal_safe(0x02, 10)]);
        save_to(&path, &with_safes, &pw("pw")).unwrap();
        let without = wallet_with_safes(Vec::new());
        save_to(&path, &without, &pw("pw")).unwrap();

        let loaded = load_from(&path, &pw("pw")).unwrap();
        assert!(loaded.safes.is_empty());
    }

    #[test]
    fn safes_preserve_insertion_order_via_index() {
        // Iteration order from `load_from` must match the order in the
        // input vec, because the UI surfaces Safes in the user's
        // chronological add order (matches accounts behavior). The
        // explicit sort-by-key in load_from is what guarantees this.
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = wallet_with_safes(vec![
            minimal_safe(0xaa, 8453), // base
            minimal_safe(0xbb, 1),    // mainnet
            minimal_safe(0xcc, 10),   // optimism
        ]);
        save_to(&path, &desc, &pw("pw")).unwrap();
        let loaded = load_from(&path, &pw("pw")).unwrap();
        let chain_ids: Vec<u64> = loaded.safes.iter().map(|s| s.chain_id).collect();
        assert_eq!(chain_ids, vec![8453, 1, 10]);
    }

    #[test]
    fn safes_and_accounts_save_atomically_under_one_commit() {
        // The whole point of bundling safes into `save_to` (rather than
        // a contacts-style sidecar) is that a wallet snapshot is always
        // internally consistent: you cannot observe "new safe added but
        // accounts still old" or vice versa. This test does a save that
        // changes BOTH and asserts both are visible after a single
        // reload. (A regression that committed safes after accounts in
        // a separate txn would leave a window where this fails.)
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let initial = wallet_with_safes(Vec::new());
        save_to(&path, &initial, &pw("pw")).unwrap();

        let updated = WalletDescriptor {
            accounts: vec![
                AccountDescriptor::Local {
                    name: Some("primary".into()),
                    key_bytes: crate::wallet::SecretKeyBytes::new([0x42; 32]),
                },
                AccountDescriptor::Local {
                    name: Some("hardware-backup".into()),
                    key_bytes: crate::wallet::SecretKeyBytes::new([0x43; 32]),
                },
            ],
            safes: vec![minimal_safe(0x77, 1)],
            active_index: 1,
            sibling_links_repaired: true,
        };
        save_to(&path, &updated, &pw("pw")).unwrap();

        let loaded = load_from(&path, &pw("pw")).unwrap();
        assert_eq!(loaded.accounts.len(), 2);
        assert_eq!(loaded.safes.len(), 1);
        assert_eq!(loaded.active_index, 1);
    }

    #[test]
    fn safe_aad_namespaces_against_account_and_contact_aads() {
        // Three-way AAD isolation: a safe ciphertext must not decrypt
        // under the accounts or contacts AAD (and vice versa). Without
        // this, an attacker with file-write access could copy an
        // encrypted safe row into the accounts table and have it
        // silently load as an account, or copy an account row into the
        // safes table to forge owner sets.
        let key = [0x77u8; 32];
        let plaintext = b"hello-safe";
        let blob_s = encrypt_blob(&key, &safe_aad(0), plaintext).unwrap();
        let blob_a = encrypt_blob(&key, &account_aad(0), plaintext).unwrap();
        let blob_c = encrypt_blob(&key, &contact_aad(0), plaintext).unwrap();

        // safe blob must not open under account or contact AAD.
        assert!(decrypt_blob(&key, &account_aad(0), &blob_s).is_err());
        assert!(decrypt_blob(&key, &contact_aad(0), &blob_s).is_err());
        // account / contact blobs must not open under safe AAD.
        assert!(decrypt_blob(&key, &safe_aad(0), &blob_a).is_err());
        assert!(decrypt_blob(&key, &safe_aad(0), &blob_c).is_err());

        // Sanity: the safe AAD round-trip works on its own blob.
        assert_eq!(
            decrypt_blob(&key, &safe_aad(0), &blob_s)
                .unwrap()
                .as_slice(),
            plaintext,
        );
    }

    #[test]
    fn aad_binding_rejects_swapped_safe_record() {
        // Mirror of `aad_binding_rejects_swapped_account_record` for the
        // safes table. Per-row AAD includes the row index, so swapping
        // the bytes between row 0 and row 1 must produce a decrypt
        // failure on load — otherwise an attacker with file-write
        // access could reorder safes (e.g. promote a watch-only Safe
        // into a signer slot by swapping it with one that has linked
        // signers, if the UI ever derived role from position).
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = wallet_with_safes(vec![minimal_safe(0x01, 1), minimal_safe(0x02, 10)]);
        save_to(&path, &desc, &pw("pw")).unwrap();

        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut safes = txn.open_table(SAFES_TABLE).unwrap();
                let a = safes.get(0u32).unwrap().unwrap().value().to_vec();
                let b = safes.get(1u32).unwrap().unwrap().value().to_vec();
                safes.insert(0u32, b.as_slice()).unwrap();
                safes.insert(1u32, a.as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }

        let err = load_from(&path, &pw("pw")).unwrap_err();
        match err {
            WalletError::Encryption(msg) => {
                assert!(msg.contains("decrypt"), "got: {msg}");
            }
            other => panic!("expected Encryption error, got {other:?}"),
        }
    }

    #[test]
    fn load_accepts_legacy_safe_row_written_before_tx_service_url() {
        // End-to-end guarantee for wallets saved before `tx_service_url`
        // shipped: a safes row whose plaintext uses the OLD 13-field
        // postcard layout — encrypted under the real per-row AAD — must
        // load as `tx_service_url: None`, not fail the whole wallet
        // open. Exercises the full path (decrypt → `decode_safe`
        // fallback), unlike the codec-only unit test.
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let expected = minimal_safe(0x07, 1);
        let desc = wallet_with_safes(vec![expected.clone()]);
        save_to(&path, &desc, &pw("pw")).unwrap();

        // Overwrite row 0 with a legacy-encoded, properly-encrypted blob.
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let header = {
                    let meta = txn.open_table(META_TABLE).unwrap();
                    let raw = meta.get(HEADER_KEY).unwrap().unwrap().value().to_vec();
                    deserialize_header(&raw).unwrap()
                };
                let key = derive_master_key(
                    &pw("pw"),
                    &header.salt,
                    header.argon2_m_cost_kib,
                    header.argon2_t_cost,
                    header.argon2_p_cost,
                )
                .unwrap();
                let legacy_plaintext = postcard::to_stdvec(&(
                    &expected.name,
                    expected.chain_id,
                    expected.address,
                    &expected.version,
                    &expected.trust,
                    expected.threshold,
                    &expected.owners,
                    &expected.modules,
                    expected.guard,
                    expected.fallback_handler,
                    &expected.linked_signer_indices,
                    &expected.sibling_chains,
                    expected.cached_at,
                ))
                .unwrap();
                let blob = encrypt_blob(key.as_slice(), &safe_aad(0), &legacy_plaintext).unwrap();
                let mut safes = txn.open_table(SAFES_TABLE).unwrap();
                safes.insert(0u32, blob.as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }

        let loaded = load_from(&path, &pw("pw")).unwrap();
        assert_eq!(loaded.safes, vec![expected]);
        assert!(loaded.safes[0].tx_service_url.is_none());
    }

    #[test]
    fn safe_descriptor_display_name_falls_back_to_indexed_default() {
        // Mirror of the account `display_name` behavior — unnamed safes
        // render as "Safe N" so the account list never has a blank row.
        let unnamed = SafeDescriptor {
            name: None,
            ..minimal_safe(0x01, 1)
        };
        assert_eq!(unnamed.display_name(0), "Safe 1");
        assert_eq!(unnamed.display_name(4), "Safe 5");

        let mut named = minimal_safe(0x01, 1);
        named.set_name(Some("  Treasury  ".into()));
        // set_name must trim whitespace; the rendered name is the trim.
        assert_eq!(named.display_name(0), "Treasury");

        // Empty-after-trim collapses to unnamed default.
        named.set_name(Some("   ".into()));
        assert_eq!(named.display_name(2), "Safe 3");
    }

    #[test]
    fn safe_descriptor_is_signer_reflects_linked_indices() {
        // The watch-only Safe path produces `linked_signer_indices: []`.
        // Anything non-empty marks the user as a signer. This is what
        // the UI checks to decide between the muted watch-only style
        // and the actuatable signer style.
        let mut s = minimal_safe(0x01, 1);
        assert!(s.is_signer(), "minimal_safe links signer 0");
        s.linked_signer_indices.clear();
        assert!(!s.is_signer());
        s.linked_signer_indices.push(7);
        assert!(s.is_signer());
    }

    #[test]
    fn contains_safe_distinguishes_address_and_chain() {
        // Dedup at onboarding is (address, chain_id) — the same address
        // on a different chain is a different Safe (separate owner set,
        // separate everything). This guard belongs in WalletDescriptor
        // rather than UI so every add path uses the same definition of
        // "already added".
        use alloy::primitives::Address;
        let desc = wallet_with_safes(vec![minimal_safe(0x42, 1)]);
        let same = Address::from([0x42; 20]);
        let other = Address::from([0x43; 20]);
        assert!(desc.contains_safe(same, 1));
        // Same address, different chain → not a duplicate.
        assert!(!desc.contains_safe(same, 10));
        // Different address, same chain → not a duplicate.
        assert!(!desc.contains_safe(other, 1));
    }

    /// Removing an account from the middle re-indexes everything after it.
    /// The save re-encrypts each surviving row under its NEW index (AAD is
    /// bound to the position), so a reload must decrypt every row, keep the
    /// remapped links and active index, and drop the removed account's row.
    #[test]
    fn remove_account_then_save_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let key = |b: u8| crate::wallet::SecretKeyBytes::new([b; 32]);
        let mut desc = WalletDescriptor {
            accounts: vec![
                AccountDescriptor::Local {
                    name: None,
                    key_bytes: key(0x01),
                },
                AccountDescriptor::Local {
                    name: Some("Doomed".into()),
                    key_bytes: key(0x02),
                },
                AccountDescriptor::Ledger {
                    name: None,
                    path: LedgerHdPath::LedgerLive(4),
                    address: [0x33; 20],
                },
                AccountDescriptor::Local {
                    name: None,
                    key_bytes: key(0x04),
                },
            ],
            safes: vec![
                SafeDescriptor {
                    linked_signer_indices: vec![0, 1, 3],
                    ..minimal_safe(0x51, 1)
                },
                SafeDescriptor {
                    linked_signer_indices: vec![1],
                    ..minimal_safe(0x52, 8453)
                },
            ],
            active_index: 3,
            sibling_links_repaired: true,
        };
        save_to(&path, &desc, &pw("pw")).unwrap();

        let removed = desc.remove_account(1).unwrap();
        assert_eq!(removed.name, "Doomed");
        save_to(&path, &desc, &pw("pw")).unwrap();

        let loaded = load_from(&path, &pw("pw")).unwrap();
        assert_eq!(loaded.accounts.len(), 3, "the removed row is gone");
        assert_eq!(loaded.active_index, 2, "active followed its account");
        match &loaded.accounts[0] {
            AccountDescriptor::Local { name, key_bytes } => {
                assert!(
                    name.is_none(),
                    "accounts before the removed one keep defaults"
                );
                assert_eq!(key_bytes.as_array(), &[0x01; 32]);
            }
            other => panic!("expected Local, got {other:?}"),
        }
        match &loaded.accounts[1] {
            AccountDescriptor::Ledger {
                name,
                path,
                address,
            } => {
                assert_eq!(name.as_deref(), Some("Account 3"), "default name frozen");
                assert!(matches!(path, LedgerHdPath::LedgerLive(4)));
                assert_eq!(*address, [0x33; 20]);
            }
            other => panic!("expected Ledger, got {other:?}"),
        }
        match &loaded.accounts[2] {
            AccountDescriptor::Local { name, key_bytes } => {
                assert_eq!(name.as_deref(), Some("Account 4"));
                assert_eq!(key_bytes.as_array(), &[0x04; 32]);
            }
            other => panic!("expected Local, got {other:?}"),
        }
        assert_eq!(loaded.safes[0].linked_signer_indices, vec![0, 2]);
        assert!(
            loaded.safes[1].linked_signer_indices.is_empty(),
            "lost its only signer → watch-only, and that persisted"
        );
        assert_eq!(loaded.safes, desc.safes);
    }

    /// A removed Safe stays removed across a reload, its surviving
    /// same-address sibling keeps its row (re-indexed) with the pruned
    /// sibling list, and a later unnamed Safe keeps the name it was shown
    /// under.
    #[test]
    fn remove_safe_then_save_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let mut desc = wallet_with_safes(vec![
            SafeDescriptor {
                sibling_chains: vec![8453],
                ..minimal_safe(0x55, 1)
            },
            SafeDescriptor {
                name: None,
                sibling_chains: vec![1],
                ..minimal_safe(0x55, 8453)
            },
            SafeDescriptor {
                name: None,
                ..minimal_safe(0x66, 10)
            },
        ]);
        save_to(&path, &desc, &pw("pw")).unwrap();

        desc.remove_safe([0x55; 20], 1).expect("held");
        save_to(&path, &desc, &pw("pw")).unwrap();

        let loaded = load_from(&path, &pw("pw")).unwrap();
        assert_eq!(loaded.safes, desc.safes);
        let keys: Vec<_> = loaded.safes.iter().map(SafeDescriptor::key).collect();
        assert_eq!(keys, vec![([0x55; 20], 8453), ([0x66; 20], 10)]);
        assert!(loaded.safes[0].sibling_chains.is_empty());
        assert_eq!(loaded.safes[0].name(), Some("Safe 2"));
        assert_eq!(loaded.safes[1].name(), Some("Safe 3"));
    }

    // ── Privacy Pools seed tests ─────────────────────────────────────────

    const SAMPLE_PP_PHRASE: &str = "test test test test test test test test test test test test \
         test test test test test test test test test test test junk";

    #[test]
    fn pp_seed_save_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = WalletDescriptor::single(AccountDescriptor::Local {
            name: None,
            key_bytes: crate::wallet::SecretKeyBytes::new([0x42; 32]),
        });
        save_to(&path, &desc, &pw("pw")).unwrap();

        let phrase = SecretString::new(SAMPLE_PP_PHRASE.to_string().into_boxed_str());
        save_pp_seed_to(&path, &phrase, &pw("pw")).unwrap();
        let loaded = load_pp_seed_from(&path, &pw("pw")).unwrap();
        assert_eq!(loaded.unwrap().expose_secret(), SAMPLE_PP_PHRASE);

        // Overwrite replaces (single row): saving a new phrase wins.
        let phrase2 = SecretString::new(
            "abandon "
                .repeat(23)
                .trim_end()
                .to_string()
                .into_boxed_str(),
        );
        save_pp_seed_to(&path, &phrase2, &pw("pw")).unwrap();
        let loaded2 = load_pp_seed_from(&path, &pw("pw")).unwrap();
        assert_eq!(loaded2.unwrap().expose_secret(), phrase2.expose_secret());
    }

    #[test]
    fn pp_seed_missing_table_loads_none() {
        // A wallet created before Privacy Pools shipped has no `pp` table; load
        // must collapse that to `None`, not error, or unlock breaks on upgrade.
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = WalletDescriptor::single(AccountDescriptor::Local {
            name: None,
            key_bytes: crate::wallet::SecretKeyBytes::new([0x42; 32]),
        });
        save_to(&path, &desc, &pw("pw")).unwrap();
        assert!(load_pp_seed_from(&path, &pw("pw")).unwrap().is_none());
    }

    #[test]
    fn pp_seed_save_refuses_wrong_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = WalletDescriptor::single(AccountDescriptor::Local {
            name: None,
            key_bytes: crate::wallet::SecretKeyBytes::new([0x42; 32]),
        });
        save_to(&path, &desc, &pw("right")).unwrap();
        let phrase = SecretString::new(SAMPLE_PP_PHRASE.to_string().into_boxed_str());
        let err = save_pp_seed_to(&path, &phrase, &pw("wrong")).unwrap_err();
        match err {
            WalletError::Encryption(msg) => assert!(msg.contains("incorrect password")),
            other => panic!("expected wrong-password error, got {other:?}"),
        }
    }

    #[test]
    fn pp_seed_aad_namespaces_against_other_tables() {
        // Four-way AAD isolation: a pp-seed ciphertext must not decrypt under
        // the account/contact/safe AAD (and vice versa), so a file-write
        // attacker can't move the seed record into another table.
        let key = [0x77u8; 32];
        let plaintext = b"seed-bytes";
        let blob_pp = encrypt_blob(&key, PP_SEED_AAD, plaintext).unwrap();
        let blob_a = encrypt_blob(&key, &account_aad(0), plaintext).unwrap();
        let blob_c = encrypt_blob(&key, &contact_aad(0), plaintext).unwrap();
        let blob_s = encrypt_blob(&key, &safe_aad(0), plaintext).unwrap();

        assert!(decrypt_blob(&key, &account_aad(0), &blob_pp).is_err());
        assert!(decrypt_blob(&key, &contact_aad(0), &blob_pp).is_err());
        assert!(decrypt_blob(&key, &safe_aad(0), &blob_pp).is_err());
        assert!(decrypt_blob(&key, PP_SEED_AAD, &blob_a).is_err());
        assert!(decrypt_blob(&key, PP_SEED_AAD, &blob_c).is_err());
        assert!(decrypt_blob(&key, PP_SEED_AAD, &blob_s).is_err());

        // Sanity: the pp AAD round-trips on its own blob.
        assert_eq!(
            decrypt_blob(&key, PP_SEED_AAD, &blob_pp)
                .unwrap()
                .as_slice(),
            plaintext,
        );
    }

    // ── Privacy Pools note cache tests ───────────────────────────────────

    #[test]
    fn pp_notes_save_load_clear_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let key = [0x33u8; 32];
        let pool = Address::from([0xab; 20]);
        let notes = CachedNotes {
            to_block: 4242,
            ..Default::default()
        };
        save_pp_notes_to(&path, 1, pool, &notes, &key).unwrap();

        // Round-trips under the right key, keyed by (chain_id, pool).
        let loaded = load_all_pp_notes_from(&path, &key).unwrap();
        assert_eq!(loaded.get(&(1, pool)).map(|n| n.to_block), Some(4242));

        // A different identity's key can't read the row — skipped, not an error.
        assert!(
            load_all_pp_notes_from(&path, &[0x99u8; 32])
                .unwrap()
                .is_empty()
        );

        // Clearing wipes the table.
        clear_pp_notes_at(&path).unwrap();
        assert!(load_all_pp_notes_from(&path, &key).unwrap().is_empty());
    }

    #[test]
    fn pp_notes_missing_db_and_table_are_empty() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope.redb");
        assert!(
            load_all_pp_notes_from(&missing, &[0u8; 32])
                .unwrap()
                .is_empty()
        );
        // Clear on a missing DB is a no-op, not an error.
        clear_pp_notes_at(&missing).unwrap();
    }

    // ── Data key, sealed tables, store lock ───────────────────────────────

    fn one_account() -> WalletDescriptor {
        wallet_with_safes(Vec::new())
    }

    /// A save that settles the data key, as every healthy wallet's does.
    fn saved_key(path: &Path, desc: &WalletDescriptor, pw: &SecretString) -> (DataKey, KeyOrigin) {
        save_to(path, desc, pw)
            .unwrap()
            .expect("the save settled a data key")
    }

    fn put(table: SealedTable, id: u64, bytes: &[u8]) -> SealedWrite {
        SealedWrite::Put {
            table,
            id,
            plaintext: Zeroizing::new(bytes.to_vec()),
        }
    }

    fn rows(r: &SealedRows) -> Vec<(u64, Vec<u8>)> {
        r.rows.iter().map(|(id, b)| (*id, b.to_vec())).collect()
    }

    fn master_key_of(path: &Path, pw: &SecretString) -> Zeroizing<[u8; 32]> {
        let db = Database::open(path).unwrap();
        let txn = db.begin_read().unwrap();
        unlock_master_key(&txn, pw).unwrap()
    }

    fn set_key_row(path: &Path, blob: &[u8]) {
        let db = Database::create(path).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut keys = txn.open_table(KEYS_TABLE).unwrap();
            keys.insert(DATA_KEY_ROW, blob).unwrap();
        }
        txn.commit().unwrap();
    }

    fn key_row(path: &Path) -> Vec<u8> {
        let db = Database::open(path).unwrap();
        let txn = db.begin_read().unwrap();
        let keys = txn.open_table(KEYS_TABLE).unwrap();
        keys.get(DATA_KEY_ROW).unwrap().unwrap().value().to_vec()
    }

    #[test]
    fn save_returns_the_stored_data_key_and_unlock_reads_the_same_one() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let (minted, origin) = saved_key(&path, &one_account(), &pw("pw"));
        assert_eq!(origin, KeyOrigin::Minted, "a new wallet's key");
        let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
        assert_eq!(unlocked.key_status, KeyStatus::Ok);
        assert_eq!(unlocked.data_key.unwrap().expose(), minted.expose());
        let (again, origin) = saved_key(&path, &one_account(), &pw("pw"));
        assert_eq!(
            again.expose(),
            minted.expose(),
            "a later save keeps the key"
        );
        assert_eq!(origin, KeyOrigin::Existing);
    }

    #[test]
    fn a_legacy_wallet_gets_a_data_key_on_its_first_unlock_and_keeps_it() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        save_to(&path, &one_account(), &pw("pw")).unwrap();
        // What a build before data keys wrote: no `keys` table at all.
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            assert!(txn.delete_table(KEYS_TABLE).unwrap());
            txn.commit().unwrap();
        }
        let first = load_wallet_at(&path, &pw("pw")).unwrap();
        assert_eq!(first.key_status, KeyStatus::Ok);
        let key = first.data_key.expect("minted at the first unlock");
        let second = load_wallet_at(&path, &pw("pw")).unwrap();
        assert_eq!(
            second.data_key.unwrap().expose(),
            key.expose(),
            "stable across loads"
        );
        let (saved, origin) = saved_key(&path, &one_account(), &pw("pw"));
        assert_eq!(saved.expose(), key.expose(), "and across saves");
        assert_eq!(origin, KeyOrigin::Existing);
        assert_eq!(
            load_wallet_at(&path, &pw("pw"))
                .unwrap()
                .data_key
                .unwrap()
                .expose(),
            key.expose()
        );
    }

    #[test]
    fn a_new_header_mints_a_fresh_key_and_clears_the_sealed_tables() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        // A headerless file carrying leftovers no new master key could ever unwrap.
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut keys = txn.open_table(KEYS_TABLE).unwrap();
                keys.insert(DATA_KEY_ROW, [9u8; 80].as_slice()).unwrap();
                let mut conns = txn.open_table(WC_CONNECTIONS_TABLE).unwrap();
                conns.insert(1u64, [1u8; 64].as_slice()).unwrap();
                let mut state = txn.open_table(WC_STATE_TABLE).unwrap();
                state.insert(WC_STATE_ID, [2u8; 64].as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }
        let (key, origin) = saved_key(&path, &one_account(), &pw("pw"));
        assert_eq!(origin, KeyOrigin::Minted);
        let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
        assert_eq!(unlocked.key_status, KeyStatus::Ok);
        assert_eq!(unlocked.data_key.unwrap().expose(), key.expose());
        assert!(unlocked.sealed.wc_state.is_none());
        assert!(unlocked.sealed.connections.rows.is_empty());
        assert_eq!(
            unlocked.sealed.connections.dropped, 0,
            "the leftovers are gone, not skipped"
        );
    }

    #[test]
    fn a_corrupt_key_row_unlocks_with_key_lost_and_the_next_save_re_mints() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let (old, _) = saved_key(&path, &one_account(), &pw("pw"));
        write_sealed_at(&path, vec![put(SealedTable::WcConnections, 1, b"{}")], &old).unwrap();
        let mut blob = key_row(&path);
        blob[NONCE_LEN + 1] ^= 0x01;
        set_key_row(&path, &blob);

        // Never an `Err`: the unlock screen would say "Incorrect password" forever.
        let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
        assert!(unlocked.data_key.is_none() && unlocked.key_status == KeyStatus::Lost);
        assert_eq!(
            unlocked.descriptor.accounts.len(),
            1,
            "the wallet itself loads"
        );
        assert!(unlocked.sealed.connections.rows.is_empty());
        // Still a wrong password when it is one.
        assert!(load_wallet_at(&path, &pw("nope")).is_err());

        let (fresh, origin) = saved_key(&path, &one_account(), &pw("pw"));
        assert_ne!(fresh.expose(), old.expose());
        assert_eq!(origin, KeyOrigin::Minted, "the re-mint cleared the tables");
        let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
        assert_eq!(unlocked.key_status, KeyStatus::Ok);
        assert_eq!(unlocked.data_key.unwrap().expose(), fresh.expose());
        assert_eq!(
            unlocked.sealed.connections.rows.len() + unlocked.sealed.connections.dropped,
            0,
            "rows sealed under the lost key were cleared with the re-mint"
        );
    }

    #[test]
    fn a_key_row_of_an_unknown_layout_is_lost_not_a_wrong_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        save_to(&path, &one_account(), &pw("pw")).unwrap();
        // Decrypts fine, but doesn't decode as this build's record.
        let master = master_key_of(&path, &pw("pw"));
        set_key_row(
            &path,
            &encrypt_blob(master.as_slice(), KEYS_AAD, &[1]).unwrap(),
        );
        let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
        assert!(unlocked.data_key.is_none() && unlocked.key_status == KeyStatus::Lost);
        let untouched = key_row(&path);
        assert_eq!(
            decrypt_blob(master.as_slice(), KEYS_AAD, &untouched)
                .unwrap()
                .as_slice(),
            &[1],
            "unlock leaves an unreadable row alone (only a save re-mints)"
        );
    }

    /// Replace the table `name` with one of another type, so the store's open of it fails with a
    /// storage error (`TableTypeMismatch`) rather than reading — a stand-in for a broken page.
    fn mistype_table(path: &Path, name: &str) {
        let db = Database::create(path).unwrap();
        let txn = db.begin_write().unwrap();
        let odd: TableDefinition<u128, u128> = TableDefinition::new(name);
        txn.delete_table(odd).unwrap();
        txn.open_table(odd).unwrap().insert(1, 1).unwrap();
        txn.commit().unwrap();
    }

    /// Clears the scan fault however the test ends.
    struct ScanFault;

    impl ScanFault {
        fn at(table: SealedTable, id: u64) -> Self {
            test_faults::fail_scan(table, id);
            Self
        }
    }

    impl Drop for ScanFault {
        fn drop(&mut self) {
            test_faults::clear();
        }
    }

    fn assert_nothing_loaded(sealed: &SealedLoad, why: &str) {
        assert!(
            sealed.wc_state.is_none()
                && sealed.connections.rows.is_empty()
                && sealed.signed.rows.is_empty()
                && sealed.connections.dropped + sealed.signed.dropped == 0,
            "{why}: {sealed:?}"
        );
    }

    #[test]
    fn a_storage_error_reading_the_key_row_is_unavailable_not_lost() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        save_to(&path, &one_account(), &pw("pw")).unwrap();
        mistype_table(&path, "keys");
        // Never an `Err` (that reads as "Incorrect password"), and not `Lost`: the row may be fine.
        let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
        assert_eq!(unlocked.key_status, KeyStatus::Unavailable);
        assert!(unlocked.data_key.is_none());
        assert_nothing_loaded(&unlocked.sealed, "no key");
        assert_eq!(unlocked.descriptor.accounts.len(), 1, "the wallet loads");
    }

    #[test]
    fn a_sealed_table_that_wont_open_withholds_the_key_and_every_row() {
        use SealedTable::*;
        for broken in SealedTable::ALL {
            let dir = tempdir().unwrap();
            let path = dir.path().join("wallet.redb");
            let (key, _) = saved_key(&path, &one_account(), &pw("pw"));
            let rows = vec![
                put(WcState, WC_STATE_ID, b"state"),
                put(WcConnections, 1, b"c1"),
                put(SignedMessages, 1, b"s1"),
            ];
            write_sealed_at(&path, rows, &key).unwrap();
            mistype_table(&path, broken.name());

            let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
            assert_eq!(unlocked.key_status, KeyStatus::Unavailable, "{broken:?}");
            assert!(unlocked.data_key.is_none(), "{broken:?}");
            assert_nothing_loaded(&unlocked.sealed, &format!("{broken:?} broken"));
            // The key itself is fine: a save keeps it and says so — what the vault of a session
            // that loaded nothing must not adopt.
            let (saved, origin) = saved_key(&path, &one_account(), &pw("pw"));
            assert_eq!(
                (saved.expose(), origin),
                (key.expose(), KeyOrigin::Existing)
            );
        }
    }

    #[test]
    fn a_scan_that_breaks_off_is_never_a_partial_load() {
        use SealedTable::*;
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let (key, _) = saved_key(&path, &one_account(), &pw("pw"));
        let rows = vec![
            put(WcConnections, 1, b"c1"),
            put(SignedMessages, 1, b"s1"),
            put(SignedMessages, 2, b"s2"),
            put(SignedMessages, 3, b"s3"),
        ];
        write_sealed_at(&path, rows, &key).unwrap();

        let broken = {
            let _fault = ScanFault::at(SignedMessages, 2);
            load_wallet_at(&path, &pw("pw")).unwrap()
        };
        assert_eq!(broken.key_status, KeyStatus::Unavailable);
        assert!(broken.data_key.is_none());
        assert_nothing_loaded(&broken.sealed, "a broken scan");

        let whole = load_wallet_at(&path, &pw("pw")).unwrap();
        assert_eq!(whole.key_status, KeyStatus::Ok);
        assert_eq!(whole.data_key.unwrap().expose(), key.expose());
        assert_eq!(rows_of(&whole.sealed.signed), vec![1, 2, 3]);
        assert_eq!(rows_of(&whole.sealed.connections), vec![1]);
    }

    fn rows_of(r: &SealedRows) -> Vec<u64> {
        r.rows.iter().map(|(id, _)| *id).collect()
    }

    // ── Reset of the sealed tables (fixregress-2) ─────────────────────────

    fn sealed_rows_everywhere(path: &Path, key: &DataKey) {
        use SealedTable::*;
        let rows = vec![
            put(WcState, WC_STATE_ID, b"state"),
            put(WcConnections, 1, b"c1"),
            put(SignedMessages, 1, b"s1"),
            put(SignedMessages, 2, b"s2"),
            put(SignedMessages, 3, b"s3"),
        ];
        write_sealed_at(path, rows, key).unwrap();
    }

    /// The tables a reset moved aside (`<name>.unreadable.<random>`), by original name.
    fn moved_aside(path: &Path) -> Vec<String> {
        use redb::TableHandle;
        let db = Database::open(path).unwrap();
        let txn = db.begin_read().unwrap();
        let mut out: Vec<String> = txn
            .list_tables()
            .unwrap()
            .filter_map(|t| {
                t.name()
                    .split_once(".unreadable.")
                    .map(|(n, _)| n.to_string())
            })
            .collect();
        out.sort();
        out
    }

    fn descriptor_bytes(d: &WalletDescriptor) -> Vec<u8> {
        postcard::to_stdvec(d).unwrap()
    }

    /// Clears the reset fault however the test ends.
    struct ResetFaultGuard;

    impl ResetFaultGuard {
        fn at(step: test_faults::ResetFault) -> Self {
            test_faults::fail_reset(step);
            Self
        }
    }

    impl Drop for ResetFaultGuard {
        fn drop(&mut self) {
            test_faults::clear();
        }
    }

    #[test]
    fn a_reset_brings_back_a_wallet_whose_sealed_tables_cant_be_read() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = wallet_with_safes(vec![rich_safe(7)]);
        let (old, _) = saved_key(&path, &desc, &pw("pw"));
        sealed_rows_everywhere(&path, &old);
        let contacts = vec![sample_contact(1, "alice"), sample_contact(2, "bob")];
        save_contacts_to(&path, &contacts, &pw("pw")).unwrap();
        let phrase = SecretString::new(SAMPLE_PP_PHRASE.to_string().into_boxed_str());
        save_pp_seed_to(&path, &phrase, &pw("pw")).unwrap();

        // A broken page in signed_messages: every unlock is Unavailable, and a save keeps the
        // stored key — which the session mustn't adopt. Nothing short of a reset gets out.
        let _fault = ScanFault::at(SealedTable::SignedMessages, 2);
        for _ in 0..2 {
            let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
            assert_eq!(unlocked.key_status, KeyStatus::Unavailable);
            assert!(unlocked.data_key.is_none());
        }
        let (kept, origin) = saved_key(&path, &desc, &pw("pw"));
        assert_eq!((kept.expose(), origin), (old.expose(), KeyOrigin::Existing));

        let (key, origin) = reset_sealed_at(&path, &pw("pw")).unwrap();
        assert_eq!(origin, KeyOrigin::Minted);
        assert_ne!(key.expose(), old.expose(), "a fresh key");

        // The fault is still armed, but the rows it sat on are gone: the next unlock is Ok, with
        // the new key, an empty history and the same wallet.
        let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
        assert_eq!(unlocked.key_status, KeyStatus::Ok);
        assert_eq!(unlocked.data_key.unwrap().expose(), key.expose());
        assert_nothing_loaded(&unlocked.sealed, "after the reset");
        assert_eq!(
            descriptor_bytes(&unlocked.descriptor),
            descriptor_bytes(&desc)
        );
        assert_eq!(load_contacts_from(&path, &pw("pw")).unwrap(), contacts);
        let seed = load_pp_seed_from(&path, &pw("pw")).unwrap().unwrap();
        assert_eq!(seed.expose_secret(), SAMPLE_PP_PHRASE);
        assert!(moved_aside(&path).is_empty(), "every table deleted cleanly");

        // Saves keep the new key; new rows persist under it.
        let (saved, origin) = saved_key(&path, &desc, &pw("pw"));
        assert_eq!(
            (saved.expose(), origin),
            (key.expose(), KeyOrigin::Existing)
        );
        write_sealed_at(
            &path,
            vec![put(SealedTable::SignedMessages, 1, b"new")],
            &key,
        )
        .unwrap();
        let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
        assert_eq!(rows(&unlocked.sealed.signed), vec![(1, b"new".to_vec())]);
    }

    #[test]
    fn a_reset_refuses_a_wrong_passphrase_and_never_creates_a_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let (old, _) = saved_key(&path, &one_account(), &pw("pw"));
        sealed_rows_everywhere(&path, &old);
        let key_before = key_row(&path);

        let err = reset_sealed_at(&path, &pw("nope")).unwrap_err();
        assert!(
            matches!(err, WalletError::Encryption(ref m) if m == "incorrect password"),
            "{err:?}"
        );
        assert_eq!(key_row(&path), key_before, "the key row is untouched");
        let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
        assert_eq!(unlocked.data_key.unwrap().expose(), old.expose());
        assert_eq!(rows_of(&unlocked.sealed.signed), vec![1, 2, 3]);
        assert!(unlocked.sealed.wc_state.is_some());

        let missing = dir.path().join("missing.redb");
        assert!(matches!(
            reset_sealed_at(&missing, &pw("pw")),
            Err(WalletError::NotFound)
        ));
        assert!(!missing.exists(), "a reset never creates the wallet file");
        let headerless = dir.path().join("headerless.redb");
        {
            let db = Database::create(&headerless).unwrap();
            let txn = db.begin_write().unwrap();
            txn.open_table(PP_NOTES_TABLE).unwrap();
            txn.commit().unwrap();
        }
        assert!(reset_sealed_at(&headerless, &pw("pw")).is_err());
        let db = Database::open(&headerless).unwrap();
        let txn = db.begin_read().unwrap();
        assert!(matches!(
            txn.open_table(KEYS_TABLE),
            Err(redb::TableError::TableDoesNotExist(_))
        ));
    }

    #[test]
    fn a_table_that_wont_delete_is_moved_aside_and_reads_as_empty() {
        for broken in SealedTable::ALL {
            let dir = tempdir().unwrap();
            let path = dir.path().join("wallet.redb");
            let (old, _) = saved_key(&path, &one_account(), &pw("pw"));
            sealed_rows_everywhere(&path, &old);
            let _fault = ResetFaultGuard::at(test_faults::ResetFault::Delete(broken));

            let (key, origin) = reset_sealed_at(&path, &pw("pw")).unwrap();
            assert_eq!(origin, KeyOrigin::Minted, "{broken:?}");
            assert_eq!(moved_aside(&path), vec![broken.name().to_string()]);
            let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
            assert_eq!(unlocked.key_status, KeyStatus::Ok, "{broken:?}");
            assert_eq!(unlocked.data_key.unwrap().expose(), key.expose());
            assert_nothing_loaded(&unlocked.sealed, &format!("{broken:?} moved aside"));
            // Its name takes new rows again.
            write_sealed_at(&path, vec![put(broken, WC_STATE_ID, b"again")], &key).unwrap();
        }
    }

    #[test]
    fn a_keys_table_that_wont_take_the_key_is_moved_aside() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let (old, _) = saved_key(&path, &one_account(), &pw("pw"));
        sealed_rows_everywhere(&path, &old);
        {
            let _fault = ResetFaultGuard::at(test_faults::ResetFault::StoreKey);
            let (key, _) = reset_sealed_at(&path, &pw("pw")).unwrap();
            assert_eq!(moved_aside(&path), vec!["keys".to_string()]);
            let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
            assert_eq!(unlocked.key_status, KeyStatus::Ok);
            assert_eq!(unlocked.data_key.unwrap().expose(), key.expose());
            assert_nothing_loaded(&unlocked.sealed, "after the reset");
        }

        // The real thing: a `keys` table redb won't open as this build's type. The unlock is
        // Unavailable and no descriptor save can settle the key (the wallet itself still saves,
        // see `a_keys_table_that_wont_open_never_fails_a_wallet_save`) — until a reset.
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        save_to(&path, &one_account(), &pw("pw")).unwrap();
        mistype_table(&path, "keys");
        assert_eq!(
            load_wallet_at(&path, &pw("pw")).unwrap().key_status,
            KeyStatus::Unavailable
        );
        assert!(save_to(&path, &one_account(), &pw("pw")).unwrap().is_none());
        let (key, _) = reset_sealed_at(&path, &pw("pw")).unwrap();
        let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
        assert_eq!(unlocked.key_status, KeyStatus::Ok);
        assert_eq!(unlocked.data_key.unwrap().expose(), key.expose());
        let (saved, origin) = saved_key(&path, &one_account(), &pw("pw"));
        assert_eq!(
            (saved.expose(), origin),
            (key.expose(), KeyOrigin::Existing)
        );
    }

    #[test]
    fn a_reset_that_cant_clear_a_table_changes_nothing_and_saves_still_work() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let (old, _) = saved_key(&path, &one_account(), &pw("pw"));
        sealed_rows_everywhere(&path, &old);
        // A table of another kind under a sealed table's name: redb refuses to delete it and to
        // rename it (as the wrong kind), so it can't even be moved aside.
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            assert!(txn.delete_table(SIGNED_MESSAGES_TABLE).unwrap());
            let odd: redb::MultimapTableDefinition<u64, u64> =
                redb::MultimapTableDefinition::new("signed_messages");
            txn.open_multimap_table(odd).unwrap().insert(1, 1).unwrap();
            txn.commit().unwrap();
        }
        assert_eq!(
            load_wallet_at(&path, &pw("pw")).unwrap().key_status,
            KeyStatus::Unavailable
        );
        let key_before = key_row(&path);

        assert!(reset_sealed_at(&path, &pw("pw")).is_err());
        assert_eq!(key_row(&path), key_before, "nothing committed");
        assert!(moved_aside(&path).is_empty());
        {
            // The tables before the broken one weren't deleted either.
            let db = Database::open(&path).unwrap();
            let txn = db.begin_read().unwrap();
            let conns = txn.open_table(WC_CONNECTIONS_TABLE).unwrap();
            assert!(conns.get(1u64).unwrap().is_some());
        }
        // The reset ran on its own: wallet saves don't depend on the sealed tables.
        let (saved, origin) = saved_key(&path, &one_account(), &pw("pw"));
        assert_eq!(
            (saved.expose(), origin),
            (old.expose(), KeyOrigin::Existing)
        );
        assert_eq!(load_from(&path, &pw("pw")).unwrap().accounts.len(), 1);
    }

    // ── Descriptor saves never wait on the data key (reset-2) ─────────────

    /// The ids in `table`, read raw (no key needed): what a save must leave alone.
    fn raw_ids(path: &Path, table: SealedTable) -> Vec<u64> {
        let db = Database::open(path).unwrap();
        let txn = db.begin_read().unwrap();
        let tbl = txn.open_table(table.def()).unwrap();
        tbl.iter().unwrap().map(|e| e.unwrap().0.value()).collect()
    }

    /// Garble the key row so it no longer decrypts: the next unlock is [`KeyStatus::Lost`].
    fn garble_key_row(path: &Path) {
        let mut blob = key_row(path);
        blob[NONCE_LEN + 1] ^= 0x01;
        set_key_row(path, &blob);
    }

    #[test]
    fn a_keys_table_that_wont_open_never_fails_a_wallet_save() {
        use SealedTable::*;
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let (old, _) = saved_key(&path, &one_account(), &pw("pw"));
        sealed_rows_everywhere(&path, &old);
        mistype_table(&path, "keys");
        assert_eq!(
            load_wallet_at(&path, &pw("pw")).unwrap().key_status,
            KeyStatus::Unavailable
        );

        // An edit made in that session (a Safe added): saved, with no key to hand over.
        let edited = wallet_with_safes(vec![rich_safe(7)]);
        assert!(save_to(&path, &edited, &pw("pw")).unwrap().is_none());
        let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
        assert_eq!(
            descriptor_bytes(&unlocked.descriptor),
            descriptor_bytes(&edited),
            "the edit survives a restart"
        );
        assert_eq!(unlocked.key_status, KeyStatus::Unavailable);
        // Nothing was minted over a key and rows that may well be fine.
        assert_eq!(raw_ids(&path, WcState), vec![WC_STATE_ID]);
        assert_eq!(raw_ids(&path, WcConnections), vec![1]);
        assert_eq!(raw_ids(&path, SignedMessages), vec![1, 2, 3]);
        assert!(moved_aside(&path).is_empty());
        // Still a wrong password when it is one — and that changes nothing.
        assert!(save_to(&path, &one_account(), &pw("nope")).is_err());
        assert_eq!(
            load_from(&path, &pw("pw")).unwrap().safes.len(),
            1,
            "a refused save writes nothing"
        );

        // The reset still cures it, and saves settle the key again.
        let (key, _) = reset_sealed_at(&path, &pw("pw")).unwrap();
        let (saved, origin) = saved_key(&path, &edited, &pw("pw"));
        assert_eq!(
            (saved.expose(), origin),
            (key.expose(), KeyOrigin::Existing)
        );
    }

    #[test]
    fn a_lost_key_re_mints_past_a_sealed_table_that_wont_delete() {
        for broken in SealedTable::ALL {
            let dir = tempdir().unwrap();
            let path = dir.path().join("wallet.redb");
            let (old, _) = saved_key(&path, &one_account(), &pw("pw"));
            sealed_rows_everywhere(&path, &old);
            garble_key_row(&path);
            assert_eq!(
                load_wallet_at(&path, &pw("pw")).unwrap().key_status,
                KeyStatus::Lost
            );

            // A broken page under that table: its delete fails every time, so the re-mint
            // moves it aside instead of failing the save.
            let _fault = ResetFaultGuard::at(test_faults::ResetFault::Delete(broken));
            let edited = wallet_with_safes(vec![rich_safe(7)]);
            let (key, origin) = save_to(&path, &edited, &pw("pw"))
                .unwrap()
                .unwrap_or_else(|| panic!("{broken:?}: the re-mint got past the table"));
            assert_eq!(origin, KeyOrigin::Minted, "{broken:?}");
            assert_ne!(key.expose(), old.expose(), "{broken:?}");
            assert_eq!(moved_aside(&path), vec![broken.name().to_string()]);
            let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
            assert_eq!(unlocked.key_status, KeyStatus::Ok, "{broken:?}");
            assert_eq!(unlocked.data_key.unwrap().expose(), key.expose());
            assert_nothing_loaded(&unlocked.sealed, &format!("{broken:?} moved aside"));
            assert_eq!(
                descriptor_bytes(&unlocked.descriptor),
                descriptor_bytes(&edited)
            );
        }
    }

    #[test]
    fn a_key_that_cant_be_minted_never_fails_a_wallet_save() {
        /// A multimap table under `signed_messages`' name: redb refuses to delete it and to
        /// rename it, so not even the move-aside fallback gets past it.
        fn unclearable_signed_messages(path: &Path) {
            let db = Database::create(path).unwrap();
            let txn = db.begin_write().unwrap();
            txn.delete_table(SIGNED_MESSAGES_TABLE).unwrap();
            let odd: redb::MultimapTableDefinition<u64, u64> =
                redb::MultimapTableDefinition::new("signed_messages");
            txn.open_multimap_table(odd).unwrap().insert(1, 1).unwrap();
            txn.commit().unwrap();
        }

        // A lost key: the re-mint fails, the edit is saved all the same.
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let (old, _) = saved_key(&path, &one_account(), &pw("pw"));
        sealed_rows_everywhere(&path, &old);
        garble_key_row(&path);
        unclearable_signed_messages(&path);
        let garbled = key_row(&path);
        let edited = wallet_with_safes(vec![rich_safe(7)]);
        for _ in 0..2 {
            assert!(save_to(&path, &edited, &pw("pw")).unwrap().is_none());
        }
        let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
        assert_eq!(
            descriptor_bytes(&unlocked.descriptor),
            descriptor_bytes(&edited)
        );
        assert_eq!(
            unlocked.key_status,
            KeyStatus::Lost,
            "the key row as it was"
        );
        assert_eq!(
            key_row(&path),
            garbled,
            "the failed mints committed nothing"
        );
        assert_eq!(raw_ids(&path, SealedTable::WcConnections), vec![1]);

        // A new wallet over a headerless file holding such a table: created, keyless.
        let path = dir.path().join("fresh.redb");
        unclearable_signed_messages(&path);
        assert!(save_to(&path, &edited, &pw("pw")).unwrap().is_none());
        let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
        assert_eq!(
            descriptor_bytes(&unlocked.descriptor),
            descriptor_bytes(&edited)
        );
        assert!(unlocked.data_key.is_none());
    }

    #[test]
    fn a_legacy_wallets_first_unlock_mints_past_a_table_that_wont_delete() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let (old, _) = saved_key(&path, &one_account(), &pw("pw"));
        sealed_rows_everywhere(&path, &old);
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            assert!(txn.delete_table(KEYS_TABLE).unwrap());
            txn.commit().unwrap();
        }
        let _fault =
            ResetFaultGuard::at(test_faults::ResetFault::Delete(SealedTable::WcConnections));
        let unlocked = load_wallet_at(&path, &pw("pw")).unwrap();
        assert_eq!(unlocked.key_status, KeyStatus::Ok);
        let key = unlocked.data_key.expect("minted past the broken table");
        assert_eq!(moved_aside(&path), vec!["wc_connections".to_string()]);
        let (saved, origin) = saved_key(&path, &one_account(), &pw("pw"));
        assert_eq!(
            (saved.expose(), origin),
            (key.expose(), KeyOrigin::Existing)
        );
    }

    #[test]
    fn sealed_rows_round_trip_under_the_data_key() {
        use SealedTable::*;
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let (key, _) = saved_key(&path, &one_account(), &pw("pw"));
        write_sealed_at(
            &path,
            vec![
                put(WcState, WC_STATE_ID, b"state"),
                put(WcConnections, 1, b"c1"),
                put(WcConnections, 2, b"c2"),
                put(SignedMessages, 7, b"s7"),
            ],
            &key,
        )
        .unwrap();
        let sealed = load_wallet_at(&path, &pw("pw")).unwrap().sealed;
        assert_eq!(
            sealed.wc_state.as_deref().map(Vec::as_slice),
            Some(&b"state"[..])
        );
        assert_eq!(
            rows(&sealed.connections),
            vec![(1, b"c1".to_vec()), (2, b"c2".to_vec())]
        );
        assert_eq!(rows(&sealed.signed), vec![(7, b"s7".to_vec())]);

        // In order: a delete, a clear, then a put into the cleared table.
        write_sealed_at(
            &path,
            vec![
                SealedWrite::Delete {
                    table: WcConnections,
                    id: 1,
                },
                SealedWrite::Clear(SignedMessages),
                put(SignedMessages, 8, b"s8"),
                SealedWrite::Clear(WcState),
            ],
            &key,
        )
        .unwrap();
        let sealed = load_wallet_at(&path, &pw("pw")).unwrap().sealed;
        assert!(sealed.wc_state.is_none());
        assert_eq!(rows(&sealed.connections), vec![(2, b"c2".to_vec())]);
        assert_eq!(rows(&sealed.signed), vec![(8, b"s8".to_vec())]);
        // The wallet is untouched by sealed writes (and the compaction after the clears).
        assert_eq!(load_from(&path, &pw("pw")).unwrap().accounts.len(), 1);
    }

    #[test]
    fn sealed_aad_binds_rows_to_their_table_and_id() {
        use SealedTable::*;
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let (key, _) = saved_key(&path, &one_account(), &pw("pw"));
        write_sealed_at(
            &path,
            vec![
                put(WcConnections, 1, b"one"),
                put(WcConnections, 2, b"two"),
                put(SignedMessages, 1, b"signed"),
            ],
            &key,
        )
        .unwrap();
        // A file-write attacker moves ciphertexts: id 1's blob into id 2, the signed row into
        // the connections table.
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut conns = txn.open_table(WC_CONNECTIONS_TABLE).unwrap();
                let signed = txn.open_table(SIGNED_MESSAGES_TABLE).unwrap();
                let one = conns.get(1u64).unwrap().unwrap().value().to_vec();
                let s1 = signed.get(1u64).unwrap().unwrap().value().to_vec();
                conns.insert(2u64, one.as_slice()).unwrap();
                conns.insert(3u64, s1.as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }
        let sealed = load_wallet_at(&path, &pw("pw")).unwrap().sealed;
        assert_eq!(rows(&sealed.connections), vec![(1, b"one".to_vec())]);
        assert_eq!(
            sealed.connections.dropped, 2,
            "swapped rows are skipped and counted"
        );

        // The AADs themselves: table and id both bind; the data key isn't the master key; the
        // wrapped data key can't pose as another master-key row (or vice versa).
        let dek = [1u8; 32];
        let master = [2u8; 32];
        let blob = encrypt_blob(&dek, &WcConnections.aad(1), b"x").unwrap();
        assert!(decrypt_blob(&dek, &WcConnections.aad(1), &blob).is_ok());
        for aad in [WcConnections.aad(2), WcState.aad(1), SignedMessages.aad(1)] {
            assert!(decrypt_blob(&dek, &aad, &blob).is_err());
        }
        assert!(decrypt_blob(&master, &WcConnections.aad(1), &blob).is_err());
        let wrapped = encrypt_blob(&master, KEYS_AAD, b"k").unwrap();
        for aad in [
            PP_SEED_AAD.to_vec(),
            account_aad(0),
            contact_aad(0),
            safe_aad(0),
            HEADER_AAD.to_vec(),
        ] {
            assert!(decrypt_blob(&master, &aad, &wrapped).is_err());
            let other = encrypt_blob(&master, &aad, b"k").unwrap();
            assert!(decrypt_blob(&master, KEYS_AAD, &other).is_err());
        }
    }

    #[test]
    fn write_sealed_refuses_a_missing_file_and_a_headerless_one() {
        let dir = tempdir().unwrap();
        let key = DataKey::for_test([3; 32]);
        let batch = || vec![put(SealedTable::WcConnections, 1, b"x")];

        let missing = dir.path().join("missing.redb");
        let err = write_sealed_at(&missing, batch(), &key).unwrap_err();
        assert!(
            matches!(err, WalletError::Encryption(ref m) if m.contains("before wallet exists"))
        );
        assert!(
            !missing.exists(),
            "a sealed write never creates the wallet file"
        );

        // A file without a header (what a stray cache write could leave behind).
        let headerless = dir.path().join("headerless.redb");
        {
            let db = Database::create(&headerless).unwrap();
            let txn = db.begin_write().unwrap();
            txn.open_table(PP_NOTES_TABLE).unwrap();
            txn.commit().unwrap();
        }
        let err = write_sealed_at(&headerless, batch(), &key).unwrap_err();
        assert!(
            matches!(err, WalletError::Encryption(ref m) if m.contains("before wallet exists"))
        );
        let db = Database::open(&headerless).unwrap();
        let txn = db.begin_read().unwrap();
        assert!(matches!(
            txn.open_table(WC_CONNECTIONS_TABLE),
            Err(redb::TableError::TableDoesNotExist(_))
        ));
    }

    #[test]
    fn concurrent_block_ops_on_one_path_both_succeed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let (key, _) = saved_key(&path, &one_account(), &pw("pw"));
        // Without the path lock one of each pair fails with redb's `DatabaseAlreadyOpen`.
        for round in 0..12u64 {
            let (p1, p2, k) = (path.clone(), path.clone(), key.clone());
            let save = std::thread::spawn(move || save_to(&p1, &one_account(), &pw("pw")));
            let seal = std::thread::spawn(move || {
                write_sealed_at(&p2, vec![put(SealedTable::WcConnections, round, b"r")], &k)
            });
            let (saved, _) = save.join().unwrap().unwrap().expect("the key is settled");
            assert_eq!(saved.expose(), key.expose());
            seal.join().unwrap().unwrap();
        }
        let sealed = load_wallet_at(&path, &pw("pw")).unwrap().sealed;
        assert_eq!(sealed.connections.rows.len(), 12);
    }

    #[test]
    fn block_ops_wait_for_the_holder_and_try_ops_fail_fast() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        save_to(&path, &one_account(), &pw("pw")).unwrap();
        let phrase = SecretString::new(SAMPLE_PP_PHRASE.to_string().into_boxed_str());
        save_pp_seed_to(&path, &phrase, &pw("pw")).unwrap();

        let held = lock_path(&path, Wait::Block).unwrap();
        // The advisory note cache gives up at once.
        let started = std::time::Instant::now();
        let busy = |r: Result<(), WalletError>| {
            assert!(matches!(r, Err(WalletError::Encryption(ref m)) if m == "store: busy"))
        };
        busy(load_all_pp_notes_from(&path, &[0u8; 32]).map(|_| ()));
        busy(save_pp_notes_to(
            &path,
            1,
            Address::ZERO,
            &CachedNotes::default(),
            &[0u8; 32],
        ));
        busy(clear_pp_notes_at(&path));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));

        // The pool seed waits: a busy file must never read as "no pool identity".
        let p = path.clone();
        let waiter = std::thread::spawn(move || load_pp_seed_from(&p, &pw("pw")));
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!waiter.is_finished(), "a Block open waits for the holder");
        drop(held);
        let seed = waiter.join().unwrap().unwrap().expect("the seed, not None");
        assert_eq!(seed.expose_secret(), SAMPLE_PP_PHRASE);
    }

    #[test]
    fn the_instance_lock_keeps_a_second_holder_out_and_is_idempotent() {
        use std::fs::{File, TryLockError};
        let dir = tempdir().unwrap();
        let path = dir.path().join("kao.lock");
        // Another process's hold: an independent open of the file, holding the lock.
        let other = File::create(&path).unwrap();
        other.try_lock().unwrap();
        let slot = Mutex::new(None);
        let err = acquire_instance_lock_at(&path, &slot).unwrap_err();
        assert!(matches!(err, WalletError::InUse), "{err:?}");
        assert_eq!(err.to_string(), "Kao is already open in another window.");
        assert!(slot.lock().unwrap().is_none(), "a refusal keeps nothing");

        drop(other); // that window closed
        acquire_instance_lock_at(&path, &slot).unwrap();
        acquire_instance_lock_at(&path, &slot).unwrap(); // already held: Ok at once
        // Held now: no other open of the file can take it.
        let probe = File::open(&path).unwrap();
        assert!(matches!(probe.try_lock(), Err(TryLockError::WouldBlock)));
    }

    #[test]
    fn the_instance_lock_file_is_created_owner_only() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fresh").join("kao.lock");
        acquire_instance_lock_at(&path, &Mutex::new(None)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(path.parent().unwrap()), 0o700);
        }
        #[cfg(not(unix))]
        assert!(path.exists());
    }

    /// The process-wide lock file sits next to the wallet in the data directory — in a test
    /// build, the per-process sandbox. Checked without taking it: a taken lock is kept until the
    /// process exits, so taking it here would leave `kao-test-<pid>/data/kao/kao.lock` behind
    /// after every test run. Taking it is tested on a lock file of the test's own.
    #[test]
    fn the_instance_lock_lives_next_to_the_wallet_in_the_sandbox() {
        use std::fs::{File, TryLockError};
        let path = instance_lock_path();
        assert_eq!(path, crate::paths::data_dir().join("kao.lock"));
        assert_eq!(path.parent(), db_path().parent(), "next to wallet.redb");
        assert!(
            path.starts_with(std::env::temp_dir()),
            "never the real data directory: {path:?}"
        );

        // What `acquire_instance_lock` does with it, on this test's own file and slot: once
        // taken it stays taken, and taking it again is `Ok` at once.
        let dir = tempdir().unwrap();
        let own = dir.path().join("data").join("kao.lock");
        let slot = Mutex::new(None);
        acquire_instance_lock_at(&own, &slot).unwrap();
        acquire_instance_lock_at(&own, &slot).unwrap();
        assert!(slot.lock().unwrap().is_some(), "kept for the process");
        let probe = File::open(&own).unwrap();
        assert!(matches!(probe.try_lock(), Err(TryLockError::WouldBlock)));
    }

    #[test]
    fn create_pp_seed_refuses_to_overwrite_an_existing_identity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        save_to(&path, &one_account(), &pw("pw")).unwrap();
        let first = SecretString::new(SAMPLE_PP_PHRASE.to_string().into_boxed_str());
        let second = SecretString::new(
            "abandon "
                .repeat(23)
                .trim_end()
                .to_string()
                .into_boxed_str(),
        );

        write_pp_seed(&path, &first, &pw("pw"), SeedWrite::CreateOnly).unwrap();
        let err = write_pp_seed(&path, &second, &pw("pw"), SeedWrite::CreateOnly).unwrap_err();
        assert!(
            matches!(err, WalletError::Encryption(ref m) if m == "a pool identity already exists")
        );
        let kept = load_pp_seed_from(&path, &pw("pw")).unwrap().unwrap();
        assert_eq!(
            kept.expose_secret(),
            SAMPLE_PP_PHRASE,
            "the first identity survives"
        );
        // An explicit restore still replaces it.
        save_pp_seed_to(&path, &second, &pw("pw")).unwrap();
        let restored = load_pp_seed_from(&path, &pw("pw")).unwrap().unwrap();
        assert_eq!(restored.expose_secret(), second.expose_secret());
    }

    #[test]
    fn debug_of_unlocked_sealed_load_and_sealed_write_prints_no_plaintext() {
        let secret = b"SECRET-PLAINTEXT".to_vec();
        let sealed = SealedLoad {
            wc_state: Some(Zeroizing::new(secret.clone())),
            connections: SealedRows {
                rows: vec![(1, Zeroizing::new(secret.clone()))],
                dropped: 2,
            },
            signed: SealedRows::default(),
        };
        let unlocked = Unlocked {
            descriptor: one_account(),
            data_key: Some(DataKey::for_test([0xab; 32])),
            key_status: KeyStatus::Ok,
            sealed: sealed.clone(),
        };
        let writes = [
            put(SealedTable::SignedMessages, 3, &secret),
            SealedWrite::Delete {
                table: SealedTable::WcConnections,
                id: 4,
            },
            SealedWrite::Clear(SealedTable::WcState),
        ];
        let dbg = format!("{unlocked:?} {sealed:?} {writes:?}");
        // The plaintext as text or as Debug's decimal byte list; the data key (0xab = 171); the
        // account key (0x42 = 66).
        for needle in ["SECRET", "83, 69, 67", "171", "66, 66"] {
            assert!(!dbg.contains(needle), "{needle} leaked: {dbg}");
        }
        assert!(
            dbg.contains("rows: 1") && dbg.contains("dropped: 2") && dbg.contains("len: 16"),
            "{dbg}"
        );
    }
}
