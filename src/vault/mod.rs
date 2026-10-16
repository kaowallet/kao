//! The vault: Kao's encrypted, App-owned store of WalletConnect state, connection history and
//! signed-message history, sealed under the wallet's data key (`wallet::DataKey`).
//!
//! [`Vault`] is a cheap clonable handle over shared state. It holds the data key, the decrypted
//! history in memory and — per unlocked session, an **epoch** — one writer thread ([`writer`]).
//! Every method is synchronous and cheap: no disk I/O and no encoding on the caller's thread.
//!
//! - [`Vault::unlock`] starts an epoch from what `wallet::load_wallet` read; [`Vault::lock`] ends it
//!   at once (records and key leave memory) and hands back a [`VaultFlush`] for the writer's drain.
//! - A runtime captures a [`VaultSession`] when it starts or restores. Its ops apply only while its
//!   epoch is current — a runtime from an earlier unlock can never touch a later session, in
//!   memory or on disk.
//! - A keyed epoch writes through its writer; a keyless one (create-password before the first
//!   wallet save, or a key that couldn't be read or stored) buffers its ops in memory until
//!   [`Vault::set_key`] replays them — or [`Vault::lock`] discards them. An epoch whose unlock
//!   couldn't read the key or the rows ([`KeyStatus`] `Lost` / `Unavailable`) loaded nothing, so
//!   its ids restart at 1: it adopts only a key the save just minted (the mint cleared the
//!   tables), never the existing one, whose rows it would overwrite.
//!
//! Every change is written as rows of the sealed tables: a record is re-written whole when it
//! changes; pruning (connections: newest 500, never an open one; signed messages: newest 500 and
//! at most 16 MiB of payload) is written as `Delete`s in the same batch; a user's "Clear history"
//! is a table `Clear` (the store compacts after it). A signed record's raw signature reaches disk
//! only once the dapp has it (`Delivery::Delivered`); before that the row carries only
//! `signature_hash` and `signature_len` — a signature that never reached the dapp must not sit in
//! the file as a usable bearer token.
//!
//! The one exception is deliberate: the raw signature of an answer the dapp hasn't received yet
//! is kept inside the saved WalletConnect state (the encrypted `wc_state` row's outbox), so that
//! Kao can send it again after a lock or restart; it leaves disk with that outbox entry (delivered,
//! refused or gone). When a re-sent answer is delivered, [`VaultSession::message_delivery`] gets
//! the signature back from it and the history row carries it from then on — history rows hold a
//! raw signature only once it is `Delivered`.
//!
//! Layering: `walletconnect` → `vault` (the vault never names WalletConnect types).
//!
//! Plaintext format: `serde_json`, with every record `#[serde(default)]`-tolerant ([`records`]) so
//! fields can be added without the postcard legacy rungs the wallet's own tables need — a
//! deliberate deviation from `wallet::store`'s postcard rows. Encoded in two passes into a
//! zeroizing buffer (`writer::encode`).
//!
//! What this does not erase: a cleared or pruned row's old ciphertext can stay in redb's freed
//! pages (and in file backups) until reused, and the data key doesn't rotate. At-rest encryption is
//! the protection.

pub mod records;
mod writer;

use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use alloy::primitives::{Bytes, keccak256};
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::wallet::{
    DataKey, KeyOrigin, KeyStatus, SealedLoad, SealedRows, SealedTable, WC_STATE_ID,
};

use writer::{Msg, Op, Payload, Pending, WriterHandle};

pub use records::*;

/// Connection records kept (newest first); an open one is never pruned.
const MAX_CONNECTIONS: usize = 500;
/// Signed-message records kept (newest first)…
const MAX_SIGNED: usize = 500;
/// …and at most this many payload bytes across them (the newest record always stays).
const MAX_SIGNED_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Records the last unlock couldn't read: rows that failed to decrypt (counted by the store) or to
/// decode, whether the data key itself was lost ([`KeyStatus::Lost`]: its rows are gone for good)
/// and whether a storage error kept the key and the rows from being read at all
/// ([`KeyStatus::Unavailable`]: they may still be there next time — until a reset deletes them,
/// which clears all of this; see [`Vault::set_key`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Unreadable {
    pub connections: usize,
    pub signed: usize,
    pub key_lost: bool,
    pub key_unavailable: bool,
}

/// App-owned handle to the vault. Clones share one state.
#[derive(Clone)]
pub struct Vault(Arc<Mutex<VaultInner>>);

struct VaultInner {
    store_path: PathBuf,
    /// The current epoch's number (0 = none yet). Bumped by every `unlock`; a [`VaultSession`] is
    /// current iff `unlocked` and its number matches.
    epoch: u64,
    unlocked: bool,
    key: Option<DataKey>,
    /// How the epoch's unlock fared with the key: anything but `Ok` means no rows were loaded, so
    /// only a freshly minted key may be adopted (`set_key`).
    key_status: KeyStatus,
    /// The epoch's writer: `Some` iff unlocked with a key (and its thread started).
    writer: Option<WriterHandle>,
    /// A keyless epoch's ops, merged, until `set_key` replays them (`lock` discards them).
    buffer: Pending,
    /// The wc_state blob loaded at unlock, until its one take.
    loaded_wc_state: Option<Zeroizing<Vec<u8>>>,
    /// Oldest first (ascending id).
    connections: Vec<ConnectionRecord>,
    signed: Vec<SignedRecord>,
    unreadable: Unreadable,
    next_connection_id: u64,
    next_signed_id: u64,
    revision: u64,
    /// The last wc_state save or clear this process (see `Vault::last_saved_wc_state`).
    #[cfg(test)]
    last_saved: Option<Option<Zeroizing<Vec<u8>>>>,
}

impl VaultInner {
    fn new(store_path: PathBuf) -> Self {
        Self {
            store_path,
            epoch: 0,
            unlocked: false,
            key: None,
            key_status: KeyStatus::Ok,
            writer: None,
            buffer: Pending::default(),
            loaded_wc_state: None,
            connections: Vec::new(),
            signed: Vec::new(),
            unreadable: Unreadable::default(),
            next_connection_id: 1,
            next_signed_id: 1,
            revision: 0,
            #[cfg(test)]
            last_saved: None,
        }
    }

    fn bump(&mut self) {
        self.revision = self.revision.wrapping_add(1);
    }

    /// Drop everything the epoch held from memory. A writer still attached is detached: its
    /// channel closes, so it drains what it has and exits on its own.
    fn forget_epoch(&mut self) {
        self.unlocked = false;
        self.key = None;
        self.key_status = KeyStatus::Ok;
        self.writer = None;
        self.buffer = Pending::default();
        self.loaded_wc_state = None;
        self.connections.clear();
        self.signed.clear();
        self.unreadable = Unreadable::default();
        self.next_connection_id = 1;
        self.next_signed_id = 1;
    }

    fn is_current(&self, epoch: u64) -> bool {
        self.unlocked && epoch != 0 && epoch == self.epoch
    }

    /// Start the epoch's writer for `self.key`. If the thread can't start, the epoch carries on
    /// keyless (ops buffer; nothing persists) rather than pretending it can persist.
    fn start_writer(&mut self) {
        let Some(key) = self.key.clone() else {
            return;
        };
        match writer::spawn(self.store_path.clone(), key, self.epoch) {
            Ok(w) => self.writer = Some(w),
            Err(e) => {
                warn!(error = %e, "vault: couldn't start the writer; this session's records stay in memory");
                self.key = None;
            }
        }
    }

    /// Queue `ops` (one message, so they land in one batch): to the writer, else to the keyless
    /// buffer.
    fn emit(&mut self, ops: Vec<Op>) {
        if ops.is_empty() {
            return;
        }
        let Some(w) = &self.writer else {
            for op in ops {
                self.buffer.apply(op);
            }
            return;
        };
        let Err(msg) = w.send(Msg::Ops(ops)) else {
            return;
        };
        // The thread is gone (a panic): start another for this epoch and hand it the ops.
        warn!(
            epoch = self.epoch,
            "vault: the writer stopped; restarting it"
        );
        self.writer = None;
        self.start_writer();
        match (&self.writer, msg) {
            (Some(w), msg) => {
                let _ = w.send(msg);
            }
            (None, Msg::Ops(ops)) => {
                for op in ops {
                    self.buffer.apply(op);
                }
            }
            (None, _) => {}
        }
    }

    /// The newest OPEN connection record with `topic`.
    fn newest_open(&mut self, topic: &str) -> Option<&mut ConnectionRecord> {
        self.connections
            .iter_mut()
            .rev()
            .find(|r| r.is_open() && r.topic == topic)
    }

    /// Record a new (open) connection, written with any prune it causes.
    fn open_connection(&mut self, rec: NewConnection) {
        let id = self.next_connection_id;
        self.next_connection_id = id.saturating_add(1);
        let rec = ConnectionRecord {
            id,
            topic: rec.topic,
            dapp: rec.dapp,
            account: rec.account,
            chains: rec.chains,
            connected_at: rec.connected_at,
            ack: rec.ack,
            ended_at: None,
            end: None,
        };
        let mut ops = vec![put_connection(&rec)];
        self.connections.push(rec);
        ops.extend(self.prune_connections());
        self.emit(ops);
        self.bump();
    }

    /// Over the cap: drop the oldest ENDED records (an open one is never pruned).
    fn prune_connections(&mut self) -> Vec<Op> {
        let mut excess = self.connections.len().saturating_sub(MAX_CONNECTIONS);
        let mut ops = Vec::new();
        if excess == 0 {
            return ops;
        }
        self.connections.retain(|r| {
            if excess > 0 && !r.is_open() {
                excess -= 1;
                ops.push(Op::Delete {
                    table: SealedTable::WcConnections,
                    id: r.id,
                });
                false
            } else {
                true
            }
        });
        ops
    }

    /// Over the count or payload cap: drop the oldest records, always keeping the newest one.
    fn prune_signed(&mut self) -> Vec<Op> {
        let mut bytes: usize = self.signed.iter().map(|r| r.payload.len()).sum();
        let mut drop_n = 0;
        while self.signed.len() - drop_n > 1
            && (self.signed.len() - drop_n > MAX_SIGNED || bytes > MAX_SIGNED_PAYLOAD_BYTES)
        {
            bytes -= self.signed[drop_n].payload.len();
            drop_n += 1;
        }
        self.signed
            .drain(..drop_n)
            .map(|r| Op::Delete {
                table: SealedTable::SignedMessages,
                id: r.id,
            })
            .collect()
    }

    #[cfg(test)]
    fn note_saved(&mut self, blob: Option<&Zeroizing<Vec<u8>>>) {
        self.last_saved = Some(blob.cloned());
    }
}

fn put_connection(r: &ConnectionRecord) -> Op {
    Op::Put {
        table: SealedTable::WcConnections,
        id: r.id,
        payload: Payload::Connection(Box::new(r.clone())),
    }
}

fn put_signed(r: &SignedRecord) -> Op {
    Op::Put {
        table: SealedTable::SignedMessages,
        id: r.id,
        payload: Payload::Signed(Box::new(disk_form(r))),
    }
}

/// A signed record as it may be written: the raw signature only once it was delivered.
fn disk_form(r: &SignedRecord) -> SignedRecord {
    let mut d = r.clone();
    if d.delivery != Delivery::Delivered {
        d.signature = None;
    }
    d
}

fn put_wc_state(blob: Zeroizing<Vec<u8>>) -> Op {
    Op::Put {
        table: SealedTable::WcState,
        id: WC_STATE_ID,
        payload: Payload::Bytes(blob),
    }
}

/// Decode one sealed table: `(row id, record)`, oldest first, the row id overriding the record's
/// own `id`; returns the records, how many failed to decode, and `max(row id) + 1`.
fn decode_rows<T: serde::de::DeserializeOwned>(
    rows: &SealedRows,
    what: &'static str,
    set_id: impl Fn(&mut T, u64),
) -> (Vec<(u64, T)>, usize, u64) {
    let mut out = Vec::with_capacity(rows.rows.len());
    let mut failed = 0usize;
    let mut next = 1u64;
    for (id, bytes) in &rows.rows {
        next = next.max(id.saturating_add(1));
        match serde_json::from_slice::<T>(bytes) {
            Ok(mut rec) => {
                set_id(&mut rec, *id);
                out.push((*id, rec));
            }
            // Never the error text: serde_json quotes the input it choked on.
            Err(_) => failed += 1,
        }
    }
    if failed > 0 {
        warn!(
            table = what,
            failed, "vault: records that failed to decode were skipped"
        );
    }
    out.sort_by_key(|(id, _)| *id);
    (out, failed, next)
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never blocks: a Debug while the vault is locked by another thread prints the name only.
        match self.0.try_lock() {
            Ok(v) => f
                .debug_struct("Vault")
                .field("epoch", &v.epoch)
                .field("unlocked", &v.unlocked)
                .field("key", &v.key.is_some())
                .field("writer", &v.writer.is_some())
                .field("buffered", &v.buffer.len())
                .field("connections", &v.connections.len())
                .field("signed", &v.signed.len())
                .field("revision", &v.revision)
                .finish(),
            Err(_) => f.write_str("Vault"),
        }
    }
}

impl Vault {
    /// Locked; store path = `wallet::db_path()` (computed only — nothing is opened).
    pub fn new() -> Self {
        Self::with_store_path(crate::wallet::db_path())
    }

    /// Against another store file (tests).
    pub(crate) fn with_store_path(path: PathBuf) -> Self {
        Self(Arc::new(Mutex::new(VaultInner::new(path))))
    }

    fn lock_inner(&self) -> MutexGuard<'_, VaultInner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Start a new epoch: decode the loaded records (serde_json; failures counted), keep the
    /// wc_state blob for one take, start the writer if `key` is Some, else buffer ops until
    /// [`Self::set_key`]. An unlock while already unlocked ends the previous epoch first (its
    /// writer drains and exits on its own).
    ///
    /// Ids continue from the loaded rows (`max + 1`, undecodable rows included): the App waits for
    /// the previous epoch's drain before it loads, so they can't collide with a late write. With
    /// any `status` but [`KeyStatus::Ok`] nothing was loaded (the store never pairs a key with a
    /// failed read; a `key` passed with one anyway is dropped) and ids start at 1 — see
    /// [`Self::set_key`].
    pub fn unlock(&self, key: Option<DataKey>, status: KeyStatus, loaded: SealedLoad) {
        let key = match (key, status) {
            (Some(_), KeyStatus::Lost | KeyStatus::Unavailable) => {
                warn!(
                    ?status,
                    "vault: a data key with a failed read; this session stays keyless"
                );
                None
            }
            (key, _) => key,
        };
        let (connections, bad_connections, next_connection_id) =
            decode_rows::<ConnectionRecord>(&loaded.connections, "wc_connections", |r, id| {
                r.id = id
            });
        let (signed, bad_signed, next_signed_id) =
            decode_rows::<SignedRecord>(&loaded.signed, "signed_messages", |r, id| r.id = id);
        let mut v = self.lock_inner();
        if v.unlocked {
            debug!(
                epoch = v.epoch,
                "vault: unlock while unlocked ends the previous epoch"
            );
        }
        v.forget_epoch();
        v.epoch = v.epoch.wrapping_add(1).max(1);
        v.unlocked = true;
        v.key = key;
        v.key_status = status;
        v.loaded_wc_state = loaded.wc_state;
        v.connections = connections.into_iter().map(|(_, r)| r).collect();
        v.signed = signed.into_iter().map(|(_, r)| r).collect();
        v.unreadable = Unreadable {
            connections: loaded.connections.dropped + bad_connections,
            signed: loaded.signed.dropped + bad_signed,
            key_lost: status == KeyStatus::Lost,
            key_unavailable: status == KeyStatus::Unavailable,
        };
        v.next_connection_id = next_connection_id;
        v.next_signed_id = next_signed_id;
        v.start_writer();
        // Rows beyond today's caps (an older build kept more) go now.
        let mut prune = v.prune_connections();
        prune.extend(v.prune_signed());
        v.emit(prune);
        v.bump();
        debug!(
            epoch = v.epoch,
            key = v.key.is_some(),
            connections = v.connections.len(),
            signed = v.signed.len(),
            "vault unlocked"
        );
    }

    /// A keyless epoch gets its key from a wallet save — the first after create-password, or one
    /// after an unlock that couldn't read or store the key: starts the writer and replays the
    /// buffered ops. Ignored when locked or already keyed. (A save that couldn't settle the key
    /// hands over none — the wallet is saved all the same — and the epoch stays keyless.)
    ///
    /// A [`KeyOrigin::Minted`] key is always adopted: its mint cleared the sealed tables, so this
    /// epoch's ids are free. A [`KeyOrigin::Existing`] one only when the unlock read the key's rows
    /// ([`KeyStatus::Ok`]: ids continue from them, or there were none); after a `Lost` or
    /// `Unavailable` unlock nothing was loaded and ids restart at 1, so its writes would overwrite
    /// the rows (and the saved WalletConnect state) already sealed under that key — it is ignored
    /// with a warning and the epoch stays keyless (its records stay in memory).
    ///
    /// A `Minted` key adopted by an `Unavailable` epoch clears [`Self::unreadable`] altogether: the
    /// mint deleted the rows the unlock couldn't read, and the panes have nothing left to warn
    /// about. Such a key almost always comes from the user's explicit reset
    /// (`wallet::reset_sealed`, whose confirm said those records are deleted) — the rows were
    /// fine, just out of reach, so "the key was lost" would be wrong. (The one other way, a save
    /// that found the key row gone or garbled after the unlock's read of it failed, is rare enough
    /// not to get a note of its own.) After a `Lost` unlock the note stays: those rows were
    /// unreadable for good. Ids need no reset either way: the epoch loaded nothing, so they count
    /// from this session's own records, which the buffer replays into the cleared tables.
    pub fn set_key(&self, key: DataKey, origin: KeyOrigin) {
        let mut v = self.lock_inner();
        if !v.unlocked || v.key.is_some() {
            return;
        }
        if origin == KeyOrigin::Existing && v.key_status != KeyStatus::Ok {
            warn!(
                epoch = v.epoch,
                status = ?v.key_status,
                "vault: not adopting the stored data key — this session couldn't read the records sealed under it, so its writes would overwrite them; its records stay in memory"
            );
            return;
        }
        if origin == KeyOrigin::Minted && v.key_status == KeyStatus::Unavailable {
            // The mint deleted what the unlock couldn't read (see above): nothing is unreadable
            // any more.
            v.unreadable = Unreadable::default();
        }
        // This epoch's ids are right for the stored key from here on.
        v.key_status = KeyStatus::Ok;
        v.key = Some(key);
        v.start_writer();
        let buffered = std::mem::take(&mut v.buffer);
        if let Some(w) = &v.writer
            && !buffered.is_empty()
        {
            debug!(
                epoch = v.epoch,
                ops = buffered.len(),
                "vault: replaying the keyless buffer"
            );
            let _ = w.send(Msg::Merge(buffered));
        }
        v.bump();
    }

    /// End the epoch NOW: records, key and any keyless buffer leave memory; the writer is detached
    /// (it drains, then exits) behind the returned flush.
    pub fn lock(&self) -> VaultFlush {
        let mut v = self.lock_inner();
        let writer = v.writer.take();
        let was = v.unlocked;
        v.forget_epoch();
        if was {
            v.bump();
            debug!(epoch = v.epoch, "vault locked");
        }
        VaultFlush {
            writer,
            #[cfg(test)]
            vault: Some(self.clone()),
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.lock_inner().unlocked
    }

    /// Unlocked with a data key (and its writer): what this epoch records reaches disk.
    pub fn can_persist(&self) -> bool {
        let v = self.lock_inner();
        v.unlocked && v.writer.is_some()
    }

    /// A writer handle bound to the current epoch (a dead one, never current, while locked).
    pub fn session(&self) -> VaultSession {
        let v = self.lock_inner();
        VaultSession {
            vault: self.clone(),
            epoch: if v.unlocked { v.epoch } else { 0 },
        }
    }

    /// The WalletConnect state loaded at unlock — once per epoch.
    pub fn take_wc_state(&self) -> Option<Zeroizing<Vec<u8>>> {
        let mut v = self.lock_inner();
        if !v.unlocked {
            return None;
        }
        v.loaded_wc_state.take()
    }

    /// Bumps on every in-memory change (records, lock / unlock, key).
    pub fn revision(&self) -> u64 {
        self.lock_inner().revision
    }

    /// Newest first.
    pub fn connections(&self) -> Vec<ConnectionRecord> {
        self.lock_inner()
            .connections
            .iter()
            .rev()
            .cloned()
            .collect()
    }

    /// Newest first.
    pub fn signed(&self) -> Vec<SignedRecord> {
        self.lock_inner().signed.iter().rev().cloned().collect()
    }

    pub fn unreadable(&self) -> Unreadable {
        self.lock_inner().unreadable
    }

    /// Remove every ended connection record — and any unreadable row; OPEN ones stay. Written as a
    /// table clear (so the store compacts the cleared rows away) plus the open records again.
    pub fn clear_ended_connections(&self) {
        let mut v = self.lock_inner();
        if !v.unlocked {
            return;
        }
        let before = v.connections.len();
        v.connections.retain(ConnectionRecord::is_open);
        if v.connections.len() == before && v.unreadable.connections == 0 {
            return;
        }
        v.unreadable.connections = 0;
        let mut ops = vec![Op::Clear(SealedTable::WcConnections)];
        ops.extend(v.connections.iter().map(put_connection));
        v.emit(ops);
        v.bump();
    }

    /// Remove every signed-message record (and any unreadable row).
    pub fn clear_signed(&self) {
        let mut v = self.lock_inner();
        if !v.unlocked || (v.signed.is_empty() && v.unreadable.signed == 0) {
            return;
        }
        v.signed.clear();
        v.unreadable.signed = 0;
        v.emit(vec![Op::Clear(SealedTable::SignedMessages)]);
        v.bump();
    }

    /// The last WalletConnect state saved or cleared in this process, through a current
    /// [`VaultSession`] or a [`VaultFlush`] of this vault: `None` = neither yet; `Some(None)` = the
    /// last op was a clear; `Some(Some(blob))` = the last blob saved.
    #[cfg(test)]
    pub(crate) fn last_saved_wc_state(&self) -> Option<Option<Zeroizing<Vec<u8>>>> {
        self.lock_inner().last_saved.clone()
    }

    /// Resolves once the current epoch's writer has written everything queued so far — or tried:
    /// a failed attempt also resolves it (the ops stay queued for the retry), so a test can't hang
    /// on a store that refuses writes. A no-op when keyless or locked.
    #[cfg(test)]
    pub(crate) fn wait_writer_idle(&self) -> impl std::future::Future<Output = ()> + Send {
        let rx = {
            let v = self.lock_inner();
            v.writer.as_ref().and_then(|w| {
                let (tx, rx) = tokio::sync::oneshot::channel();
                w.send(Msg::Barrier(tx)).ok().map(|()| rx)
            })
        };
        async move {
            if let Some(rx) = rx {
                let _ = rx.await;
            }
        }
    }
}

/// Epoch-bound writer handle captured by a runtime at start / restore. Every op is dropped (debug
/// log) unless its epoch is still the current one.
#[derive(Clone)]
pub struct VaultSession {
    vault: Vault,
    /// 0 = made while locked: never current.
    epoch: u64,
}

impl fmt::Debug for VaultSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VaultSession(epoch {})", self.epoch)
    }
}

impl VaultSession {
    /// Run `f` on the vault iff this session's epoch is current; else drop the op (debug log).
    fn with_current(&self, op: &'static str, f: impl FnOnce(&mut VaultInner)) {
        let mut v = self.vault.lock_inner();
        if !v.is_current(self.epoch) {
            debug!(
                op,
                epoch = self.epoch,
                "vault: op from an ended epoch dropped"
            );
            return;
        }
        f(&mut v);
    }

    pub fn is_current(&self) -> bool {
        self.vault.lock_inner().is_current(self.epoch)
    }

    pub fn can_persist(&self) -> bool {
        let v = self.vault.lock_inner();
        v.is_current(self.epoch) && v.writer.is_some()
    }

    /// Save the WalletConnect state (latest wins).
    pub fn save_wc_state(&self, blob: Zeroizing<Vec<u8>>) {
        self.with_current("save_wc_state", |v| {
            #[cfg(test)]
            v.note_saved(Some(&blob));
            v.emit(vec![put_wc_state(blob)]);
        });
    }

    /// Clear the saved WalletConnect state — on disk, and the blob loaded at unlock if nothing has
    /// taken it yet.
    pub fn clear_wc_state(&self) {
        self.with_current("clear_wc_state", |v| {
            v.loaded_wc_state = None;
            #[cfg(test)]
            v.note_saved(None);
            v.emit(vec![Op::Clear(SealedTable::WcState)]);
        });
    }

    pub fn connection_opened(&self, rec: NewConnection) {
        self.with_current("connection_opened", |v| v.open_connection(rec));
    }

    /// [`Self::connection_opened`] unless an OPEN record with `rec.topic` already exists — for a
    /// live session whose opening was never recorded (it settled while the epoch was ending, so
    /// that log was dropped); a no-op for one that has its record.
    pub fn ensure_open_connection(&self, rec: NewConnection) {
        self.with_current("ensure_open_connection", |v| {
            if v.newest_open(&rec.topic).is_none() {
                v.open_connection(rec);
            }
        });
    }

    /// The newest OPEN record with `topic` gets `ack`.
    pub fn connection_acked(&self, topic: &str, ack: AckRecord) {
        self.with_current("connection_acked", |v| {
            if let Some(r) = v.newest_open(topic) {
                r.ack = ack;
                let op = put_connection(r);
                v.emit(vec![op]);
                v.bump();
            }
        });
    }

    /// The newest OPEN record with `topic` ends at `at` for `reason`.
    pub fn connection_ended(&self, topic: &str, at: u64, reason: EndReason) {
        self.with_current("connection_ended", |v| {
            if let Some(r) = v.newest_open(topic) {
                r.ended_at = Some(at);
                r.end = Some(reason);
                let op = put_connection(r);
                v.emit(vec![op]);
                v.bump();
            }
        });
    }

    /// End every OPEN record whose topic isn't in `live`.
    pub fn end_open_connections_except(&self, live: &[String], at: u64, reason: EndReason) {
        self.with_current("end_open_connections_except", |v| {
            let mut ops = Vec::new();
            for r in v
                .connections
                .iter_mut()
                .filter(|r| r.is_open() && !live.contains(&r.topic))
            {
                r.ended_at = Some(at);
                r.end = Some(reason);
                ops.push(put_connection(r));
            }
            if !ops.is_empty() {
                v.emit(ops);
                v.bump();
            }
        });
    }

    /// Record a signature. The vault derives `signature_hash` (keccak256) and `signature_len`; the
    /// raw signature stays in memory and reaches this record's row only once delivered (until
    /// then, only the saved WalletConnect state's outbox holds it — see the module doc).
    pub fn message_signed(&self, rec: NewSigned) {
        self.with_current("message_signed", |v| {
            let id = v.next_signed_id;
            v.next_signed_id = id.saturating_add(1);
            let signature_hash = keccak256(&rec.signature);
            let signature_len = u32::try_from(rec.signature.len()).unwrap_or(u32::MAX);
            let rec = SignedRecord {
                id,
                at: rec.at,
                origin: rec.origin,
                account: rec.account,
                chain_id: rec.chain_id,
                kind: rec.kind,
                primary_type: rec.primary_type,
                payload: rec.payload,
                digests: rec.digests,
                signature: Some(rec.signature),
                signature_hash,
                signature_len,
                delivery: rec.delivery,
            };
            let mut ops = vec![put_signed(&rec)];
            v.signed.push(rec);
            ops.extend(v.prune_signed());
            v.emit(ops);
            v.bump();
        });
    }

    /// The newest signed record for WalletConnect request `(topic, request_id)` gets `d` (and, once
    /// `Delivered`, its signature is written).
    ///
    /// `signature` is the answer as it went out, when the caller has it: a record reloaded from
    /// disk before its delivery holds no signature (only its hash), and a `Delivered` one takes it
    /// back from here — only if it is the very signature recorded (`keccak256` equals
    /// `signature_hash`); a record that still holds one keeps it.
    pub fn message_delivery(
        &self,
        topic: &str,
        request_id: u64,
        d: Delivery,
        signature: Option<Bytes>,
    ) {
        self.with_current("message_delivery", |v| {
            let found = v.signed.iter_mut().rev().find(|r| match &r.origin {
                SignOrigin::WalletConnect {
                    topic: t,
                    request_id: id,
                    ..
                } => t == topic && *id == request_id,
            });
            if let Some(r) = found {
                r.delivery = d;
                if d == Delivery::Delivered
                    && r.signature.is_none()
                    && let Some(sig) = signature
                {
                    if keccak256(&sig) == r.signature_hash {
                        r.signature = Some(sig);
                    } else {
                        debug!(
                            id = r.id,
                            "vault: a delivered answer that isn't the recorded signature; not kept"
                        );
                    }
                }
                let op = put_signed(r);
                v.emit(vec![op]);
                v.bump();
            }
        });
    }
}

/// The ended epoch's writer, detached by [`Vault::lock`]: what the suspend's final save goes
/// through and what a quit waits for. Dropping it without `finish*` still lets the writer drain
/// and exit — nobody waits for it then.
pub struct VaultFlush {
    writer: Option<WriterHandle>,
    /// For `Vault::last_saved_wc_state`.
    #[cfg(test)]
    vault: Option<Vault>,
}

impl fmt::Debug for VaultFlush {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultFlush")
            .field("can_persist", &self.can_persist())
            .field("idle", &self.is_idle())
            .finish()
    }
}

impl VaultFlush {
    /// Nothing to drain.
    #[cfg(test)]
    pub fn none() -> Self {
        Self {
            writer: None,
            #[cfg(test)]
            vault: None,
        }
    }

    /// The ended epoch had a data key: a save through this flush reaches disk.
    pub fn can_persist(&self) -> bool {
        self.writer.is_some()
    }

    /// No writer thread to wait for.
    pub fn is_idle(&self) -> bool {
        self.writer.is_none()
    }

    /// The suspend's final WalletConnect state save (dropped when there's no writer).
    pub fn save_wc_state(&self, blob: Zeroizing<Vec<u8>>) {
        let Some(w) = &self.writer else {
            return;
        };
        #[cfg(test)]
        if let Some(vault) = &self.vault {
            vault.lock_inner().note_saved(Some(&blob));
        }
        if w.send(Msg::Ops(vec![put_wc_state(blob)])).is_err() {
            warn!("vault: the writer stopped; the final WalletConnect state save is lost");
        }
    }

    /// Close the channel; the writer drains, exits (DEK zeroized) and THEN drops `guard` (the WC
    /// slot counts the drain in its teardown registry so a quit waits for it). With no writer the
    /// guard drops now.
    pub fn finish_with(self, guard: Box<dyn Send>) {
        match self.writer {
            // A writer that's already gone hands the message (and the guard) back: dropped here.
            Some(w) => drop(w.send(Msg::Close(guard))),
            None => drop(guard),
        }
    }

    /// Resolves once the writer has drained and exited (at once when there's none).
    #[cfg(test)]
    pub fn finish(self) -> impl Future<Output = ()> + Send + 'static {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        self.finish_with(Box::new(tx));
        async move {
            let _ = rx.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::{
        AccountDescriptor, SecretKeyBytes, WalletDescriptor, load_wallet_at, reset_sealed_at,
        save_descriptor_at,
    };
    use alloy::primitives::Bytes;
    use secrecy::SecretString;
    use std::path::Path;
    use std::time::Duration;
    use tempfile::{TempDir, tempdir};

    fn vault() -> Vault {
        Vault::with_store_path(PathBuf::from("/nonexistent/kao-vault-test.redb"))
    }

    fn pw() -> SecretString {
        SecretString::new("pw".to_string().into_boxed_str())
    }

    /// A real wallet file in a temp dir, and its data key.
    fn wallet_file() -> (TempDir, PathBuf, DataKey) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let desc = WalletDescriptor::single(AccountDescriptor::Local {
            name: None,
            key_bytes: SecretKeyBytes::new([0x42; 32]),
        });
        let key = save_descriptor_at(&path, &desc, &pw()).unwrap();
        (dir, path, key)
    }

    /// What the next unlock would read.
    fn reload(path: &Path) -> SealedLoad {
        load_wallet_at(path, &pw()).unwrap().sealed
    }

    /// The rows that decode as `T` (a row that doesn't is left out).
    fn decoded<T: serde::de::DeserializeOwned>(rows: &SealedRows) -> Vec<(u64, T)> {
        rows.rows
            .iter()
            .filter_map(|(id, b)| Some((*id, serde_json::from_slice(b).ok()?)))
            .collect()
    }

    fn topics_on_disk(path: &Path) -> Vec<(u64, String)> {
        decoded::<ConnectionRecord>(&reload(path).connections)
            .into_iter()
            .map(|(id, r)| (id, r.topic))
            .collect()
    }

    /// A keyed vault over `path`, unlocked from what is on disk.
    fn unlocked_on(path: &Path, key: &DataKey) -> Vault {
        let v = Vault::with_store_path(path.to_path_buf());
        v.unlock(Some(key.clone()), KeyStatus::Ok, reload(path));
        v
    }

    async fn within<F: std::future::Future>(f: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(20), f)
            .await
            .expect("timed out")
    }

    fn blob(b: &[u8]) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(b.to_vec())
    }

    fn signed_for(topic: &str, request_id: u64, signature: &[u8]) -> NewSigned {
        NewSigned {
            origin: SignOrigin::WalletConnect {
                topic: topic.into(),
                request_id,
                session_ordinal: 1,
                dapp: DappRecord::default(),
            },
            payload: SignedPayload::Message {
                bytes: b"hello".to_vec(),
            },
            signature: Bytes::copy_from_slice(signature),
            ..Default::default()
        }
    }

    fn conn(topic: &str) -> NewConnection {
        NewConnection {
            topic: topic.into(),
            connected_at: 10,
            ..Default::default()
        }
    }

    fn rows<T: serde::Serialize>(recs: &[(u64, T)]) -> SealedRows {
        SealedRows {
            rows: recs
                .iter()
                .map(|(id, r)| (*id, Zeroizing::new(serde_json::to_vec(r).unwrap())))
                .collect(),
            dropped: 0,
        }
    }

    #[test]
    fn stale_sessions_are_dropped() {
        let v = vault();
        let dead = v.session();
        assert!(!dead.is_current());
        v.unlock(None, KeyStatus::Ok, SealedLoad::default());
        dead.connection_opened(conn("a"));
        assert!(v.connections().is_empty(), "a locked-time session is dead");
        let s1 = v.session();
        assert!(s1.is_current() && !s1.can_persist());
        s1.connection_opened(conn("a"));
        assert_eq!(v.connections().len(), 1);
        let _ = v.lock();
        v.unlock(None, KeyStatus::Ok, SealedLoad::default());
        s1.connection_opened(conn("b"));
        assert!(v.connections().is_empty(), "an earlier epoch can't write");
    }

    #[test]
    fn ids_continue_from_loaded_rows_and_getters_are_newest_first() {
        let v = vault();
        let loaded = SealedLoad {
            connections: rows(&[(
                4,
                ConnectionRecord {
                    topic: "old".into(),
                    ..Default::default()
                },
            )]),
            signed: SealedRows {
                rows: vec![(9, Zeroizing::new(b"not json".to_vec()))],
                dropped: 2,
            },
            ..Default::default()
        };
        v.unlock(Some(DataKey::for_test([7; 32])), KeyStatus::Ok, loaded);
        assert!(v.can_persist());
        let s = v.session();
        s.connection_opened(conn("new"));
        let c = v.connections();
        assert_eq!(
            c.iter()
                .map(|r| (r.id, r.topic.as_str()))
                .collect::<Vec<_>>(),
            vec![(5, "new"), (4, "old")]
        );
        assert_eq!(v.unreadable().signed, 3);
        s.message_signed(NewSigned {
            signature: Bytes::from_static(&[1, 2]),
            ..Default::default()
        });
        let signed = v.signed();
        assert_eq!(
            signed[0].id, 10,
            "max row id + 1, undecodable rows included"
        );
        assert_eq!(signed[0].signature_len, 2);
        assert_eq!(signed[0].signature_hash, keccak256([1u8, 2]));
    }

    #[test]
    fn ending_and_clearing() {
        let v = vault();
        v.unlock(None, KeyStatus::Ok, SealedLoad::default());
        let s = v.session();
        s.connection_opened(conn("a"));
        s.connection_opened(conn("b"));
        s.connection_opened(conn("c"));
        s.connection_ended("a", 20, EndReason::YouDisconnected);
        s.end_open_connections_except(&["c".to_string()], 30, EndReason::Lost);
        let c = v.connections();
        assert_eq!(c[0].end, None);
        assert_eq!(c[1].end, Some(EndReason::Lost));
        assert_eq!(c[2].end, Some(EndReason::YouDisconnected));
        let rev = v.revision();
        v.clear_ended_connections();
        assert!(v.revision() > rev);
        assert_eq!(v.connections().len(), 1, "the open record stays");
        s.message_signed(NewSigned {
            origin: SignOrigin::WalletConnect {
                topic: "c".into(),
                request_id: 5,
                session_ordinal: 1,
                dapp: DappRecord::default(),
            },
            ..Default::default()
        });
        s.message_delivery("c", 5, Delivery::Delivered, None);
        assert_eq!(v.signed()[0].delivery, Delivery::Delivered);
        v.clear_signed();
        assert!(v.signed().is_empty());
    }

    #[test]
    fn wc_state_is_taken_once_per_epoch_and_lock_forgets() {
        let v = vault();
        let loaded = || SealedLoad {
            wc_state: Some(Zeroizing::new(b"{}".to_vec())),
            ..Default::default()
        };
        v.unlock(None, KeyStatus::Ok, loaded());
        assert!(v.take_wc_state().is_some());
        assert!(v.take_wc_state().is_none());
        v.unlock(None, KeyStatus::Ok, loaded());
        v.session().clear_wc_state();
        assert!(
            v.take_wc_state().is_none(),
            "a clear drops the untaken blob"
        );
        v.unlock(Some(DataKey::for_test([1; 32])), KeyStatus::Ok, loaded());
        let flush = v.lock();
        assert!(
            flush.can_persist() && !flush.is_idle(),
            "a keyed epoch's flush carries its writer"
        );
        assert!(!v.is_unlocked() && v.take_wc_state().is_none());
        assert!(!VaultFlush::none().can_persist());
    }

    #[test]
    fn debug_is_counts_only() {
        let v = vault();
        v.unlock(
            Some(DataKey::for_test([0xab; 32])),
            KeyStatus::Ok,
            SealedLoad::default(),
        );
        v.session().save_wc_state(blob(b"SECRET-STATE"));
        v.session().message_signed(signed_for("t", 1, &[0xab; 65]));
        let dbg = format!("{v:?} {:?} {:?}", v.session(), v.lock());
        assert!(!dbg.contains("171") && !dbg.contains("ab"), "{dbg}");
        // And a keyless epoch's buffer.
        v.unlock(None, KeyStatus::Ok, SealedLoad::default());
        v.session().save_wc_state(blob(b"SECRET-STATE"));
        let dbg = format!("{v:?}");
        assert!(
            dbg.contains("buffered: 1") && !dbg.contains("SECRET"),
            "{dbg}"
        );
    }

    #[tokio::test]
    async fn an_ended_epoch_reaches_neither_memory_nor_disk() {
        let (_dir, path, key) = wallet_file();
        let v = unlocked_on(&path, &key);
        let s1 = v.session();
        s1.connection_opened(conn("a"));
        within(v.lock().finish()).await;

        v.unlock(Some(key.clone()), KeyStatus::Ok, reload(&path));
        s1.connection_opened(conn("stale"));
        s1.save_wc_state(blob(b"stale"));
        s1.message_signed(signed_for("stale", 1, &[1; 65]));
        assert!(!s1.is_current() && !s1.can_persist());
        let s2 = v.session();
        assert!(s2.can_persist());
        s2.connection_opened(conn("b"));
        assert_eq!(v.connections().len(), 2, "a + b, not the stale one");
        within(v.lock().finish()).await;

        let disk = reload(&path);
        assert_eq!(
            topics_on_disk(&path),
            vec![(1, "a".to_string()), (2, "b".to_string())]
        );
        assert!(disk.wc_state.is_none() && disk.signed.rows.is_empty());
    }

    #[tokio::test]
    async fn a_keyless_buffer_lands_once_the_key_arrives() {
        let (_dir, path, key) = wallet_file();
        let v = Vault::with_store_path(path.clone());
        v.unlock(None, KeyStatus::Ok, SealedLoad::default());
        let s = v.session();
        assert!(s.is_current() && !s.can_persist() && !v.can_persist());
        s.connection_opened(conn("a"));
        s.save_wc_state(blob(b"first"));
        s.message_signed(signed_for("a", 3, &[7; 65]));
        s.save_wc_state(blob(b"second"));
        within(v.wait_writer_idle()).await; // no writer: resolves at once
        assert!(
            reload(&path).connections.rows.is_empty(),
            "nothing written keyless"
        );

        v.set_key(key.clone(), KeyOrigin::Minted);
        assert!(
            v.can_persist() && s.can_persist(),
            "the same session now persists"
        );
        within(v.wait_writer_idle()).await;
        let disk = reload(&path);
        assert_eq!(
            disk.wc_state.as_deref().map(Vec::as_slice),
            Some(&b"second"[..])
        );
        assert_eq!(topics_on_disk(&path), vec![(1, "a".to_string())]);
        assert_eq!(disk.signed.rows.len(), 1);

        // Later ops go straight to the writer.
        s.connection_opened(conn("b"));
        within(v.wait_writer_idle()).await;
        assert_eq!(topics_on_disk(&path).len(), 2);
        // A second key is ignored.
        v.set_key(DataKey::for_test([9; 32]), KeyOrigin::Minted);
        s.connection_opened(conn("c"));
        within(v.lock().finish()).await;
        assert_eq!(
            topics_on_disk(&path).len(),
            3,
            "still sealed under the wallet's key"
        );
    }

    #[tokio::test]
    async fn lock_discards_a_keyless_buffer() {
        let (_dir, path, key) = wallet_file();
        let v = Vault::with_store_path(path.clone());
        v.unlock(None, KeyStatus::Ok, SealedLoad::default());
        let s = v.session();
        s.connection_opened(conn("a"));
        s.save_wc_state(blob(b"state"));
        let flush = v.lock();
        assert!(!flush.can_persist() && flush.is_idle());
        within(flush.finish()).await;
        v.set_key(key.clone(), KeyOrigin::Minted); // locked: ignored
        assert!(!v.is_unlocked() && !v.can_persist());

        v.unlock(Some(key.clone()), KeyStatus::Ok, reload(&path));
        within(v.lock().finish()).await;
        let disk = reload(&path);
        assert!(disk.connections.rows.is_empty() && disk.wc_state.is_none());
    }

    #[tokio::test]
    async fn ids_keep_climbing_across_re_unlocks() {
        let (_dir, path, key) = wallet_file();
        let v = unlocked_on(&path, &key);
        let s = v.session();
        s.connection_opened(conn("a"));
        s.connection_opened(conn("b"));
        s.message_signed(signed_for("a", 1, &[1; 65]));
        within(v.lock().finish()).await;

        let v = unlocked_on(&path, &key);
        let s = v.session();
        s.connection_opened(conn("c"));
        s.message_signed(signed_for("c", 2, &[2; 65]));
        assert_eq!(v.connections()[0].id, 3);
        assert_eq!(v.signed()[0].id, 2);
        within(v.lock().finish()).await;

        let disk = reload(&path);
        assert_eq!(
            topics_on_disk(&path)
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        let signed_ids: Vec<u64> = disk.signed.rows.iter().map(|(id, _)| *id).collect();
        assert_eq!(signed_ids, vec![1, 2]);
    }

    #[tokio::test]
    async fn pruning_keeps_the_newest_500_connections_and_never_an_open_one() {
        let (_dir, path, key) = wallet_file();
        let v = unlocked_on(&path, &key);
        let s = v.session();
        s.connection_opened(conn("still-open"));
        for i in 0..510 {
            let t = format!("t{i}");
            s.connection_opened(conn(&t));
            s.connection_ended(&t, 20, EndReason::Expired);
        }
        let mem = v.connections();
        assert_eq!(mem.len(), MAX_CONNECTIONS);
        assert!(mem.iter().any(|r| r.topic == "still-open" && r.is_open()));
        assert!(
            !mem.iter().any(|r| r.topic == "t10"),
            "the oldest ended ones went"
        );
        assert!(mem.iter().any(|r| r.topic == "t11"));
        within(v.lock().finish()).await;
        let mut disk_ids: Vec<u64> = topics_on_disk(&path).iter().map(|(id, _)| *id).collect();
        let mut mem_ids: Vec<u64> = mem.iter().map(|r| r.id).collect();
        disk_ids.sort_unstable();
        mem_ids.sort_unstable();
        assert_eq!(disk_ids, mem_ids, "the prune reached disk as deletes");

        // Open records are never pruned, even over the cap…
        let v = vault();
        v.unlock(None, KeyStatus::Ok, SealedLoad::default());
        let s = v.session();
        for i in 0..=MAX_CONNECTIONS {
            s.connection_opened(conn(&format!("o{i}")));
        }
        assert_eq!(v.connections().len(), MAX_CONNECTIONS + 1);
        // …and rows over the cap at unlock (an older build kept more) are pruned then.
        let loaded: Vec<(u64, ConnectionRecord)> = (1..=MAX_CONNECTIONS as u64 + 3)
            .map(|id| {
                let rec = ConnectionRecord {
                    topic: format!("l{id}"),
                    ended_at: Some(5),
                    ..Default::default()
                };
                (id, rec)
            })
            .collect();
        v.unlock(
            None,
            KeyStatus::Ok,
            SealedLoad {
                connections: rows(&loaded),
                ..Default::default()
            },
        );
        let c = v.connections();
        assert_eq!(c.len(), MAX_CONNECTIONS);
        assert_eq!(c.last().unwrap().topic, "l4", "the three oldest went");
    }

    #[test]
    fn pruning_signed_keeps_the_newest_500_and_at_most_16_mib() {
        let v = vault();
        v.unlock(None, KeyStatus::Ok, SealedLoad::default());
        let s = v.session();
        let mib = 1024 * 1024;
        for at in 0..17 {
            s.message_signed(NewSigned {
                at,
                payload: SignedPayload::TypedData {
                    json: "x".repeat(mib),
                },
                ..Default::default()
            });
        }
        let signed = v.signed();
        assert_eq!(signed.len(), 16, "17 MiB is over the cap");
        assert_eq!(signed.last().unwrap().at, 1, "the oldest went");
        assert_eq!(signed[0].at, 16);

        v.unlock(None, KeyStatus::Ok, SealedLoad::default());
        let s = v.session();
        for at in 0..=MAX_SIGNED as u64 {
            s.message_signed(NewSigned {
                at,
                ..Default::default()
            });
        }
        let signed = v.signed();
        assert_eq!(signed.len(), MAX_SIGNED);
        assert_eq!(signed.last().unwrap().at, 1);

        // A single record over the byte cap still stays: the newest is never pruned.
        v.unlock(None, KeyStatus::Ok, SealedLoad::default());
        v.session().message_signed(NewSigned {
            payload: SignedPayload::TypedData {
                json: "y".repeat(MAX_SIGNED_PAYLOAD_BYTES + 1),
            },
            ..Default::default()
        });
        assert_eq!(v.signed().len(), 1);
    }

    #[tokio::test]
    async fn clearing_ended_connections_keeps_open_ones_on_disk_and_drops_unreadable_rows() {
        let (_dir, path, key) = wallet_file();
        // One row that decrypts but isn't a record.
        crate::wallet::write_sealed_at(
            &path,
            vec![crate::wallet::SealedWrite::Put {
                table: SealedTable::WcConnections,
                id: 1,
                plaintext: blob(b"not json"),
            }],
            &key,
        )
        .unwrap();
        let v = unlocked_on(&path, &key);
        assert_eq!(v.unreadable().connections, 1);
        let s = v.session();
        s.connection_opened(conn("a"));
        s.connection_opened(conn("b"));
        s.connection_opened(conn("c"));
        s.connection_ended("a", 20, EndReason::YouDisconnected);
        s.end_open_connections_except(&["c".to_string()], 30, EndReason::Lost);
        within(v.wait_writer_idle()).await;
        let ends: Vec<(String, Option<EndReason>)> =
            decoded::<ConnectionRecord>(&reload(&path).connections)
                .into_iter()
                .map(|(_, r)| (r.topic, r.end))
                .collect();
        assert_eq!(
            ends,
            vec![
                ("a".to_string(), Some(EndReason::YouDisconnected)),
                ("b".to_string(), Some(EndReason::Lost)),
                ("c".to_string(), None),
            ]
        );
        assert_eq!(
            reload(&path).connections.rows.len(),
            4,
            "a, b, c and the unreadable row"
        );

        v.clear_ended_connections();
        assert_eq!(v.unreadable().connections, 0);
        within(v.lock().finish()).await;
        let disk = reload(&path);
        assert_eq!(
            disk.connections.rows.len(),
            1,
            "the unreadable row went with the clear"
        );
        assert_eq!(topics_on_disk(&path), vec![(4, "c".to_string())]);
    }

    #[tokio::test]
    async fn a_failed_batch_is_kept_and_retried_so_a_clear_is_never_lost() {
        let (_dir, path, key) = wallet_file();
        let v = unlocked_on(&path, &key);
        v.session().message_signed(signed_for("t", 1, &[1; 65]));
        within(v.lock().finish()).await;
        assert_eq!(reload(&path).signed.rows.len(), 1);

        let v = unlocked_on(&path, &key);
        // Another holder of the file (as a second Kao process would be): the writer's open fails.
        let other = redb::Database::open(&path).unwrap();
        v.clear_signed();
        v.session().connection_opened(conn("a"));
        within(v.wait_writer_idle()).await; // that attempt failed; the batch is kept
        drop(other);
        within(v.wait_writer_idle()).await; // the retry lands
        let disk = reload(&path);
        assert!(
            disk.signed.rows.is_empty(),
            "the clear survived the failure"
        );
        assert_eq!(topics_on_disk(&path), vec![(1, "a".to_string())]);
    }

    #[tokio::test]
    async fn a_signature_reaches_disk_only_once_delivered() {
        let (_dir, path, key) = wallet_file();
        let v = unlocked_on(&path, &key);
        let s = v.session();
        let sig = [0xaa; 65];
        s.message_signed(signed_for("t", 9, &sig));
        within(v.wait_writer_idle()).await;
        let on_disk = |path: &Path| {
            let disk = reload(path);
            let plain = String::from_utf8_lossy(&disk.signed.rows[0].1).into_owned();
            let rec = decoded::<SignedRecord>(&disk.signed).remove(0).1;
            (plain, rec)
        };
        let (plain, rec) = on_disk(&path);
        assert!(
            rec.signature.is_none() && !plain.contains("aaaaaaaa"),
            "{plain}"
        );
        assert_eq!(rec.signature_hash, keccak256(sig));
        assert_eq!(rec.signature_len, 65);
        assert!(v.signed()[0].signature.is_some(), "memory keeps it");

        s.message_delivery("t", 9, Delivery::NotDelivered, None);
        within(v.wait_writer_idle()).await;
        let (_, rec) = on_disk(&path);
        assert!(rec.signature.is_none() && rec.delivery == Delivery::NotDelivered);

        s.message_delivery("t", 9, Delivery::Delivered, None);
        within(v.wait_writer_idle()).await;
        let (_, rec) = on_disk(&path);
        assert_eq!(rec.signature.as_ref().map(|b| b.as_ref()), Some(&sig[..]));
        assert_eq!(rec.delivery, Delivery::Delivered);
        within(v.lock().finish()).await;
    }

    /// The record for WalletConnect request `(topic, _)`.
    fn signed_record(v: &Vault, topic: &str) -> SignedRecord {
        v.signed()
            .into_iter()
            .find(|r| matches!(&r.origin, SignOrigin::WalletConnect { topic: t, .. } if t == topic))
            .unwrap()
    }

    #[tokio::test]
    async fn a_delivery_brings_back_the_signature_a_reload_dropped() {
        let (_dir, path, key) = wallet_file();
        let v = unlocked_on(&path, &key);
        let sig = [0xaa; 65];
        v.session().message_signed(signed_for("t", 9, &sig));
        v.session().message_signed(signed_for("u", 4, &[0xcc; 65]));
        within(v.lock().finish()).await;

        // What the next unlock reads: Sending, without the raw signature.
        let v = unlocked_on(&path, &key);
        assert!(signed_record(&v, "t").signature.is_none());
        let s = v.session();
        let bytes = |b: &[u8]| Some(Bytes::copy_from_slice(b));
        // Not delivered: nothing is kept, even with the signature at hand.
        s.message_delivery("t", 9, Delivery::NotDelivered, bytes(&sig));
        assert!(signed_record(&v, "t").signature.is_none());
        // Delivered, but not the signature recorded: not kept.
        s.message_delivery("t", 9, Delivery::Delivered, bytes(&[0xbb; 65]));
        let r = signed_record(&v, "t");
        assert!(r.delivery == Delivery::Delivered && r.signature.is_none());
        // The very signature recorded: kept, in memory and on disk.
        s.message_delivery("t", 9, Delivery::Delivered, bytes(&sig));
        assert_eq!(signed_record(&v, "t").signature, bytes(&sig));
        // A delivery that comes without it stays signature-less.
        s.message_delivery("u", 4, Delivery::Delivered, None);
        within(v.lock().finish()).await;

        let disk: Vec<(Option<Bytes>, Delivery)> = decoded::<SignedRecord>(&reload(&path).signed)
            .into_iter()
            .map(|(_, r)| (r.signature, r.delivery))
            .collect();
        assert_eq!(
            disk,
            vec![
                (bytes(&sig), Delivery::Delivered),
                (None, Delivery::Delivered),
            ]
        );
    }

    #[tokio::test]
    async fn ensure_open_connection_opens_only_a_missing_record() {
        let (_dir, path, key) = wallet_file();
        let v = unlocked_on(&path, &key);
        let s = v.session();
        s.connection_opened(conn("a"));
        // An open record exists: left as it is.
        s.ensure_open_connection(NewConnection {
            connected_at: 99,
            ..conn("a")
        });
        // None: opened.
        s.ensure_open_connection(conn("b"));
        // Only an ended one: a new open record.
        s.connection_ended("b", 20, EndReason::DappDisconnected);
        s.ensure_open_connection(conn("b"));
        let summary = |v: &Vault| -> Vec<(u64, String, bool, u64)> {
            v.connections()
                .into_iter()
                .map(|r| (r.id, r.topic.clone(), r.is_open(), r.connected_at))
                .collect()
        };
        let expected = vec![
            (3, "b".to_string(), true, 10),
            (2, "b".to_string(), false, 10),
            (1, "a".to_string(), true, 10),
        ];
        assert_eq!(summary(&v), expected);
        within(v.lock().finish()).await;
        assert_eq!(
            topics_on_disk(&path),
            vec![
                (1, "a".to_string()),
                (2, "b".to_string()),
                (3, "b".to_string())
            ]
        );
        // An ended epoch's session can't add one.
        let v2 = unlocked_on(&path, &key);
        s.ensure_open_connection(conn("c"));
        assert_eq!(summary(&v2), expected);
        within(v2.lock().finish()).await;
    }

    #[test]
    fn an_existing_key_is_adopted_only_by_an_epoch_that_read_its_rows() {
        for status in [KeyStatus::Ok, KeyStatus::Lost, KeyStatus::Unavailable] {
            let v = vault();
            v.unlock(None, status, SealedLoad::default());
            v.set_key(DataKey::for_test([1; 32]), KeyOrigin::Existing);
            assert_eq!(
                v.can_persist(),
                status == KeyStatus::Ok,
                "{status:?} + an existing key"
            );
            v.unlock(None, status, SealedLoad::default());
            v.set_key(DataKey::for_test([1; 32]), KeyOrigin::Minted);
            assert!(
                v.can_persist(),
                "{status:?} + a minted key: every id is free"
            );
            let _ = v.lock();
        }
        // The store never pairs a key with a failed read; a caller that does gets a keyless epoch.
        let v = vault();
        v.unlock(
            Some(DataKey::for_test([1; 32])),
            KeyStatus::Unavailable,
            SealedLoad::default(),
        );
        assert!(!v.can_persist());
    }

    #[test]
    fn unreadable_reports_a_lost_and_an_unavailable_key_apart() {
        let v = vault();
        v.unlock(None, KeyStatus::Lost, SealedLoad::default());
        let lost = Unreadable {
            key_lost: true,
            ..Default::default()
        };
        assert_eq!(v.unreadable(), lost);
        v.unlock(None, KeyStatus::Unavailable, SealedLoad::default());
        assert_eq!(
            v.unreadable(),
            Unreadable {
                key_unavailable: true,
                ..Default::default()
            }
        );
        v.set_key(DataKey::for_test([1; 32]), KeyOrigin::Existing);
        assert!(
            v.unreadable().key_unavailable,
            "an ignored key changes nothing"
        );
        // A mint (the user's reset) deleted what the unlock couldn't read: no note is left —
        // not "unavailable", and not "lost" either (those rows were fine, just out of reach).
        v.set_key(DataKey::for_test([1; 32]), KeyOrigin::Minted);
        assert_eq!(v.unreadable(), Unreadable::default());
        // A lost key's note outlives the save's re-mint: those rows were unreadable for good.
        v.unlock(None, KeyStatus::Lost, SealedLoad::default());
        v.set_key(DataKey::for_test([1; 32]), KeyOrigin::Minted);
        assert!(v.can_persist());
        assert_eq!(v.unreadable(), lost);
        let _ = v.lock();
        assert_eq!(v.unreadable(), Unreadable::default());
    }

    /// fixregress-2: a session whose unlock couldn't read the sealed tables gets them back through
    /// `wallet::reset_sealed` — its key is adopted, the unreadable note goes, what it recorded
    /// meanwhile lands, and the next unlock reads it with the key the reset minted.
    #[tokio::test]
    async fn a_reset_key_ends_an_unavailable_epoch_and_its_records_persist() {
        let (_dir, path, old_key) = wallet_file();
        let v = unlocked_on(&path, &old_key);
        let s = v.session();
        for topic in ["before-1", "before-2", "before-3"] {
            s.connection_opened(conn(topic));
        }
        s.message_signed(signed_for("before", 1, &[1; 65]));
        s.message_signed(signed_for("before", 2, &[1; 65]));
        s.save_wc_state(blob(b"before"));
        within(v.lock().finish()).await;

        // The next unlock couldn't read the tables (a broken page, say): keyless, nothing loaded.
        v.unlock(None, KeyStatus::Unavailable, SealedLoad::default());
        let s = v.session();
        s.connection_opened(conn("meanwhile"));
        s.message_signed(signed_for("meanwhile", 2, &[2; 65]));
        s.save_wc_state(blob(b"meanwhile"));
        assert!(!v.can_persist() && v.unreadable().key_unavailable);
        // A wallet save in the meantime hands over the old key: not adoptable.
        v.set_key(old_key.clone(), KeyOrigin::Existing);
        assert!(!v.can_persist());

        let (key, origin) = reset_sealed_at(&path, &pw()).unwrap();
        assert_eq!(origin, KeyOrigin::Minted);
        let rev = v.revision();
        v.set_key(key.clone(), origin);
        assert!(
            v.can_persist() && s.can_persist(),
            "the same session persists"
        );
        assert_eq!(v.unreadable(), Unreadable::default(), "no unreadable note");
        assert!(v.revision() > rev, "the panes are told");
        assert_eq!(
            v.connections()
                .iter()
                .map(|r| (r.id, r.topic.as_str()))
                .collect::<Vec<_>>(),
            vec![(1, "meanwhile")],
            "ids count from this session's own records"
        );
        s.connection_opened(conn("after"));
        within(v.lock().finish()).await;

        let unlocked = load_wallet_at(&path, &pw()).unwrap();
        assert_eq!(unlocked.key_status, KeyStatus::Ok);
        assert_eq!(unlocked.data_key.unwrap().expose(), key.expose());
        assert_eq!(
            unlocked.sealed.connections.dropped + unlocked.sealed.signed.dropped,
            0,
            "nothing sealed under the old key is left"
        );
        assert_eq!(
            topics_on_disk(&path),
            vec![(1, "meanwhile".to_string()), (2, "after".to_string())]
        );
        let disk = reload(&path);
        let signed = decoded::<SignedRecord>(&disk.signed);
        assert_eq!(signed.len(), 1);
        assert!(
            matches!(&signed[0].1.origin, SignOrigin::WalletConnect { topic, .. } if topic == "meanwhile")
        );
        assert_eq!(
            disk.wc_state.as_deref().map(Vec::as_slice),
            Some(&b"meanwhile"[..])
        );
    }

    /// secrets-1: after an unlock that read nothing (here a storage error), the key a wallet save
    /// hands over is the stored one — adopting it would restart ids at 1 over the rows and the
    /// saved WalletConnect state already sealed under it.
    #[tokio::test]
    async fn an_epoch_that_couldnt_read_its_rows_never_overwrites_them() {
        let (_dir, path, key) = wallet_file();
        let v = unlocked_on(&path, &key);
        let s = v.session();
        s.connection_opened(conn("a"));
        s.connection_opened(conn("b"));
        s.message_signed(signed_for("a", 1, &[1; 65]));
        s.save_wc_state(blob(b"saved sessions"));
        within(v.lock().finish()).await;

        v.unlock(None, KeyStatus::Unavailable, SealedLoad::default());
        let s = v.session();
        s.connection_opened(conn("new"));
        s.message_signed(signed_for("new", 2, &[2; 65]));
        s.save_wc_state(blob(b"fresh"));
        assert_eq!(v.connections()[0].id, 1, "ids restart: nothing was loaded");
        v.set_key(key.clone(), KeyOrigin::Existing);
        assert!(!v.can_persist() && !s.can_persist(), "not adopted");
        within(v.lock().finish()).await;

        let disk = reload(&path);
        assert_eq!(
            topics_on_disk(&path),
            vec![(1, "a".to_string()), (2, "b".to_string())]
        );
        let signed = decoded::<SignedRecord>(&disk.signed);
        assert_eq!(signed.len(), 1);
        assert!(
            matches!(&signed[0].1.origin, SignOrigin::WalletConnect { topic, .. } if topic == "a")
        );
        assert_eq!(
            disk.wc_state.as_deref().map(Vec::as_slice),
            Some(&b"saved sessions"[..])
        );
    }

    #[tokio::test]
    async fn the_newest_wc_state_wins_and_a_clear_reaches_disk() {
        let (_dir, path, key) = wallet_file();
        let v = unlocked_on(&path, &key);
        let s = v.session();
        s.save_wc_state(blob(b"one"));
        s.clear_wc_state();
        s.save_wc_state(blob(b"two"));
        within(v.wait_writer_idle()).await;
        assert_eq!(
            reload(&path).wc_state.as_deref().map(Vec::as_slice),
            Some(&b"two"[..])
        );
        s.clear_wc_state();
        within(v.lock().finish()).await;
        assert!(reload(&path).wc_state.is_none());
    }

    #[test]
    fn records_decode_tolerantly() {
        let v = vault();
        let loaded = SealedLoad {
            connections: SealedRows {
                rows: vec![
                    // A field from a later build, and most fields missing.
                    (2, blob(br#"{"topic":"x","later":{"a":[1,2]}}"#)),
                    (3, blob(b"[1,2,3]")),
                ],
                dropped: 0,
            },
            signed: SealedRows {
                rows: vec![(1, blob(br#"{"kind":"TypedData","delivery":"Delivered"}"#))],
                dropped: 0,
            },
            ..Default::default()
        };
        v.unlock(None, KeyStatus::Ok, loaded);
        let c = v.connections();
        assert_eq!((c.len(), c[0].id, c[0].topic.as_str()), (1, 2, "x"));
        assert_eq!(v.unreadable().connections, 1);
        let s = v.signed();
        assert_eq!(
            (s[0].kind, s[0].delivery),
            (SignedKind::TypedData, Delivery::Delivered)
        );
        assert!(s[0].signature.is_none());
    }

    #[tokio::test]
    async fn finish_and_finish_with_resolve_only_after_the_drain() {
        struct Probe(std::sync::mpsc::Sender<()>);
        impl Drop for Probe {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }

        let (_dir, path, key) = wallet_file();
        let v = unlocked_on(&path, &key);
        v.session().connection_opened(conn("a"));
        let flush = v.lock();
        flush.save_wc_state(blob(b"final"));
        let (tx, rx) = std::sync::mpsc::channel();
        flush.finish_with(Box::new(Probe(tx)));
        rx.recv_timeout(Duration::from_secs(20)).unwrap();
        // The guard dropped only after the writer committed and exited.
        let disk = reload(&path);
        assert_eq!(
            disk.wc_state.as_deref().map(Vec::as_slice),
            Some(&b"final"[..])
        );
        assert_eq!(topics_on_disk(&path), vec![(1, "a".to_string())]);

        let v = unlocked_on(&path, &key);
        v.session().connection_opened(conn("b"));
        within(v.lock().finish()).await;
        assert_eq!(
            topics_on_disk(&path).len(),
            2,
            "finish resolved after the write"
        );

        // Nothing to drain: both resolve at once.
        let (tx, rx) = std::sync::mpsc::channel();
        VaultFlush::none().finish_with(Box::new(Probe(tx)));
        rx.try_recv().unwrap();
        within(VaultFlush::none().finish()).await;
    }

    #[test]
    fn last_saved_wc_state_tracks_saves_clears_and_the_flush() {
        let v = vault();
        assert!(v.last_saved_wc_state().is_none());
        v.unlock(None, KeyStatus::Ok, SealedLoad::default());
        let s = v.session();
        s.save_wc_state(blob(b"a"));
        assert_eq!(v.last_saved_wc_state(), Some(Some(blob(b"a"))));
        s.clear_wc_state();
        assert_eq!(v.last_saved_wc_state(), Some(None));
        // A keyless lock's flush can't save; a stale session's save is dropped.
        let flush = v.lock();
        flush.save_wc_state(blob(b"lost"));
        s.save_wc_state(blob(b"stale"));
        assert_eq!(v.last_saved_wc_state(), Some(None));

        v.unlock(
            Some(DataKey::for_test([1; 32])),
            KeyStatus::Ok,
            SealedLoad::default(),
        );
        v.session().save_wc_state(blob(b"b"));
        assert_eq!(v.last_saved_wc_state(), Some(Some(blob(b"b"))));
        let flush = v.lock();
        flush.save_wc_state(blob(b"c"));
        assert_eq!(
            v.last_saved_wc_state(),
            Some(Some(blob(b"c"))),
            "the suspend's final save"
        );
    }

    #[tokio::test]
    async fn wait_writer_idle_is_a_no_op_without_a_writer() {
        let v = vault();
        within(v.wait_writer_idle()).await; // locked
        v.unlock(None, KeyStatus::Ok, SealedLoad::default());
        within(v.wait_writer_idle()).await; // keyless
        // A writer whose store refuses every write still lets the wait end.
        v.unlock(
            Some(DataKey::for_test([1; 32])),
            KeyStatus::Ok,
            SealedLoad::default(),
        );
        v.session().connection_opened(conn("a"));
        within(v.wait_writer_idle()).await;
    }
}
