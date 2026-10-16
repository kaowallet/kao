//! The per-epoch writer thread: drains the vault's ops into `store::write_sealed_at` batches.
//!
//! One `std::thread` per keyed epoch owns a clone of the data key and the store path. Each round
//! it takes every op already queued and writes them as ONE batch (one write transaction). Ops
//! merge as they arrive ([`Pending`]): a later put or delete of a row replaces an earlier one and a
//! clear drops everything queued for its table before it — so only the newest WalletConnect state
//! put / clear survives a batch.
//!
//! A batch that fails is **kept** and retried with backoff (0.5 s doubling to 30 s), merged with
//! whatever arrives meanwhile: a `Clear` or `Delete` the user asked for is never silently lost to
//! a busy disk or a second Kao process holding the file. When the channel closes — the epoch's
//! `VaultFlush` finished or was dropped, or a new unlock detached the writer — it drains with a
//! few bounded attempts, then exits: the key is dropped (zeroized) first, and only then any guard
//! `VaultFlush::finish_with` handed in, so whoever counts the guard waits for the drain.
//!
//! Never logs plaintext — only the store's error text (`store: …`), counts and the epoch.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError, TryRecvError};
use std::time::{Duration, Instant};

use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::wallet::{self, DataKey, SealedTable, SealedWrite};

use super::records::{ConnectionRecord, SignedRecord};

const FIRST_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Attempts once the channel has closed (the first at once, then `CLOSE_BACKOFF` doubling):
/// bounded so a quit — which waits at most `QUIT_TEARDOWN_BUDGET`, after a suspend — and the
/// unlock that waits for the previous epoch stay short.
const CLOSE_ATTEMPTS: u32 = 3;
const CLOSE_BACKOFF: Duration = Duration::from_millis(250);

/// A row's content as queued. Encoded (see [`encode`]) only when a batch is built, on the writer
/// thread, so the vault's callers never pay for it.
pub(super) enum Payload {
    /// Already encoded by its owner (the WalletConnect state blob).
    Bytes(Zeroizing<Vec<u8>>),
    Connection(Box<ConnectionRecord>),
    /// Already in its on-disk form (the vault's signature rule applied).
    Signed(Box<SignedRecord>),
}

pub(super) enum Op {
    Put {
        table: SealedTable,
        id: u64,
        payload: Payload,
    },
    Delete {
        table: SealedTable,
        id: u64,
    },
    Clear(SealedTable),
}

const TABLES: [SealedTable; 3] = [
    SealedTable::WcState,
    SealedTable::WcConnections,
    SealedTable::SignedMessages,
];

fn slot(table: SealedTable) -> usize {
    match table {
        SealedTable::WcState => 0,
        SealedTable::WcConnections => 1,
        SealedTable::SignedMessages => 2,
    }
}

/// Queued ops, merged: per table an optional clear, then the latest put (`Some`) or delete (`None`)
/// of each row. Applying it as "clear, then rows by id" equals applying the ops one by one.
#[derive(Default)]
pub(super) struct Pending {
    tables: [TableOps; 3],
}

#[derive(Default)]
struct TableOps {
    clear: bool,
    rows: BTreeMap<u64, Option<Payload>>,
}

impl Pending {
    pub(super) fn apply(&mut self, op: Op) {
        match op {
            Op::Put { table, id, payload } => {
                self.tables[slot(table)].rows.insert(id, Some(payload));
            }
            Op::Delete { table, id } => {
                self.tables[slot(table)].rows.insert(id, None);
            }
            Op::Clear(table) => {
                let t = &mut self.tables[slot(table)];
                t.clear = true;
                t.rows.clear();
            }
        }
    }

    /// `later`'s ops after these.
    pub(super) fn merge(&mut self, later: Pending) {
        for (t, l) in self.tables.iter_mut().zip(later.tables) {
            if l.clear {
                t.clear = true;
                t.rows.clear();
            }
            t.rows.extend(l.rows);
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.tables.iter().all(|t| !t.clear && t.rows.is_empty())
    }

    /// Ops held (a clear counts as one).
    pub(super) fn len(&self) -> usize {
        self.tables
            .iter()
            .map(|t| usize::from(t.clear) + t.rows.len())
            .sum()
    }

    /// The batch for one attempt; `self` is kept until it commits. A row that can't be encoded
    /// (never expected for these types) is left out with a warning.
    fn batch(&self) -> Vec<SealedWrite> {
        let mut out = Vec::with_capacity(self.len());
        for (table, ops) in TABLES.into_iter().zip(&self.tables) {
            if ops.clear {
                out.push(SealedWrite::Clear(table));
            }
            for (&id, row) in &ops.rows {
                let Some(payload) = row else {
                    out.push(SealedWrite::Delete { table, id });
                    continue;
                };
                let plaintext = match payload {
                    Payload::Bytes(b) => Some(b.clone()),
                    Payload::Connection(r) => encode(&**r),
                    Payload::Signed(r) => encode(&**r),
                };
                match plaintext {
                    Some(plaintext) => out.push(SealedWrite::Put {
                        table,
                        id,
                        plaintext,
                    }),
                    None => warn!(?table, id, "vault: a record could not be encoded; skipped"),
                }
            }
        }
        out
    }
}

/// `serde_json` straight into a zeroizing buffer sized by a first counting pass, so the plaintext
/// leaves no copies behind in a growing `Vec`.
pub(super) fn encode<T: serde::Serialize>(value: &T) -> Option<Zeroizing<Vec<u8>>> {
    let mut counter = ByteCounter(0);
    serde_json::to_writer(&mut counter, value).ok()?;
    let mut out = Zeroizing::new(Vec::with_capacity(counter.0));
    serde_json::to_writer(&mut *out, value).ok()?;
    Some(out)
}

struct ByteCounter(usize);

impl std::io::Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) enum Msg {
    Ops(Vec<Op>),
    /// A keyless epoch's buffer, replayed by `set_key`.
    Merge(Pending),
    /// Released after the next write attempt (at once when nothing is queued) — tests only; it
    /// makes a pending retry due now, so a test never waits out a backoff.
    #[cfg(test)]
    Barrier(tokio::sync::oneshot::Sender<()>),
    /// No more ops: drain, exit, then drop the guard.
    Close(Box<dyn Send>),
}

/// The sending side of an epoch's writer. Dropping the last one closes the channel: the thread
/// drains and exits.
pub(super) struct WriterHandle {
    tx: mpsc::Sender<Msg>,
}

impl WriterHandle {
    /// `Err(msg)` when the thread is gone (it panicked).
    pub(super) fn send(&self, msg: Msg) -> Result<(), Msg> {
        self.tx.send(msg).map_err(|e| e.0)
    }
}

/// Start an epoch's writer over `path` with `key`.
pub(super) fn spawn(path: PathBuf, key: DataKey, epoch: u64) -> std::io::Result<WriterHandle> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name(format!("kao-vault-{epoch}"))
        .spawn(move || run(path, key, epoch, &rx))?;
    Ok(WriterHandle { tx })
}

struct Writer {
    path: PathBuf,
    key: DataKey,
    epoch: u64,
    pending: Pending,
    guards: Vec<Box<dyn Send>>,
    #[cfg(test)]
    barriers: Vec<tokio::sync::oneshot::Sender<()>>,
    closing: bool,
    backoff: Duration,
    /// When the kept batch may be retried (`None`: now).
    retry_at: Option<Instant>,
    failures_since_close: u32,
}

fn run(path: PathBuf, key: DataKey, epoch: u64, rx: &mpsc::Receiver<Msg>) {
    let mut w = Writer {
        path,
        key,
        epoch,
        pending: Pending::default(),
        guards: Vec::new(),
        #[cfg(test)]
        barriers: Vec::new(),
        closing: false,
        backoff: FIRST_BACKOFF,
        retry_at: None,
        failures_since_close: 0,
    };
    loop {
        w.receive(rx);
        if w.pending.is_empty() {
            w.release_barriers();
        } else if w.due() {
            w.attempt();
            w.release_barriers();
        }
        if w.closing {
            if w.pending.is_empty() {
                break;
            }
            if w.failures_since_close >= CLOSE_ATTEMPTS {
                warn!(
                    epoch,
                    ops = w.pending.len(),
                    "vault: unwritten ops dropped at close after retries"
                );
                break;
            }
            if let Some(at) = w.retry_at {
                std::thread::sleep(at.saturating_duration_since(Instant::now()));
            }
        }
    }
    debug!(epoch, "vault writer exits");
    // The key (and any plaintext still queued) goes first; the guards — what a quit or an unlock
    // is waiting on — only after.
    let Writer {
        key,
        pending,
        guards,
        ..
    } = w;
    drop(pending);
    drop(key);
    drop(guards);
}

impl Writer {
    fn handle(&mut self, msg: Msg) {
        match msg {
            Msg::Ops(ops) => {
                for op in ops {
                    self.pending.apply(op);
                }
            }
            Msg::Merge(buffer) => self.pending.merge(buffer),
            #[cfg(test)]
            Msg::Barrier(tx) => {
                self.barriers.push(tx);
                self.retry_at = None;
            }
            Msg::Close(guard) => {
                self.guards.push(guard);
                self.begin_close();
            }
        }
    }

    fn begin_close(&mut self) {
        if !self.closing {
            self.closing = true;
            self.retry_at = None;
            self.backoff = CLOSE_BACKOFF;
        }
    }

    /// Wait for the next message (or until a kept batch is due), then take everything queued.
    fn receive(&mut self, rx: &mpsc::Receiver<Msg>) {
        if !self.closing {
            let got = if self.pending.is_empty() {
                rx.recv().map_err(|_| RecvTimeoutError::Disconnected)
            } else if let Some(at) = self.retry_at {
                rx.recv_timeout(at.saturating_duration_since(Instant::now()))
            } else {
                // Due now: don't wait.
                Err(RecvTimeoutError::Timeout)
            };
            match got {
                Ok(msg) => self.handle(msg),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => self.begin_close(),
            }
        }
        loop {
            match rx.try_recv() {
                Ok(msg) => self.handle(msg),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.begin_close();
                    break;
                }
            }
        }
    }

    fn due(&self) -> bool {
        self.retry_at.is_none_or(|at| Instant::now() >= at)
    }

    /// One attempt at everything kept.
    fn attempt(&mut self) {
        let batch = self.pending.batch();
        let ops = batch.len();
        match wallet::write_sealed_at(&self.path, batch, &self.key) {
            Ok(()) => {
                debug!(epoch = self.epoch, ops, "vault: batch written");
                self.pending = Pending::default();
                self.retry_at = None;
                if !self.closing {
                    self.backoff = FIRST_BACKOFF;
                }
            }
            Err(e) => {
                warn!(
                    epoch = self.epoch,
                    ops,
                    error = %e,
                    retry_in_ms = self.backoff.as_millis() as u64,
                    "vault: write failed; kept for retry"
                );
                self.retry_at = Some(Instant::now() + self.backoff);
                self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
                if self.closing {
                    self.failures_since_close += 1;
                }
            }
        }
    }

    #[cfg(test)]
    fn release_barriers(&mut self) {
        for tx in self.barriers.drain(..) {
            let _ = tx.send(());
        }
    }

    #[cfg(not(test))]
    fn release_barriers(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(table: SealedTable, id: u64, byte: u8) -> Op {
        Op::Put {
            table,
            id,
            payload: Payload::Bytes(Zeroizing::new(vec![byte])),
        }
    }

    /// What a batch does, as `(variant, table, id, first plaintext byte)`.
    fn shape(p: &Pending) -> Vec<(char, SealedTable, u64, u8)> {
        p.batch()
            .into_iter()
            .map(|w| match w {
                SealedWrite::Put {
                    table,
                    id,
                    plaintext,
                } => ('P', table, id, plaintext[0]),
                SealedWrite::Delete { table, id } => ('D', table, id, 0),
                SealedWrite::Clear(table) => ('C', table, 0, 0),
            })
            .collect()
    }

    #[test]
    fn newest_wc_state_wins_and_a_clear_drops_what_came_before() {
        use SealedTable::*;
        let mut p = Pending::default();
        p.apply(put(WcState, 0, 1));
        p.apply(put(WcConnections, 3, 9));
        p.apply(put(WcState, 0, 2));
        assert_eq!(
            shape(&p),
            vec![('P', WcState, 0, 2), ('P', WcConnections, 3, 9)]
        );
        p.apply(Op::Clear(WcState));
        p.apply(Op::Delete {
            table: WcConnections,
            id: 3,
        });
        assert_eq!(
            shape(&p),
            vec![('C', WcState, 0, 0), ('D', WcConnections, 3, 0)]
        );
        // A clear then a put: the batch clears first, then writes the row.
        p.apply(put(WcState, 0, 5));
        assert_eq!(shape(&p)[..2], [('C', WcState, 0, 0), ('P', WcState, 0, 5)]);
        assert_eq!(p.len(), 3);
    }

    #[test]
    fn merge_applies_the_later_ops_after() {
        use SealedTable::*;
        let mut earlier = Pending::default();
        earlier.apply(put(SignedMessages, 1, 1));
        earlier.apply(put(SignedMessages, 2, 2));
        let mut later = Pending::default();
        later.apply(Op::Clear(SignedMessages));
        later.apply(put(SignedMessages, 3, 3));
        later.apply(put(WcConnections, 1, 7));
        earlier.merge(later);
        assert_eq!(
            shape(&earlier),
            vec![
                ('P', WcConnections, 1, 7),
                ('C', SignedMessages, 0, 0),
                ('P', SignedMessages, 3, 3),
            ]
        );
        assert!(!earlier.is_empty());
        assert!(Pending::default().is_empty());
    }

    #[test]
    fn encode_is_exactly_sized_json() {
        let rec = ConnectionRecord {
            id: 4,
            topic: "ab".into(),
            ..Default::default()
        };
        let bytes = encode(&rec).unwrap();
        assert_eq!(
            bytes.len(),
            bytes.capacity(),
            "no growth: sized by the counting pass"
        );
        assert_eq!(
            bytes.as_slice(),
            serde_json::to_vec(&rec).unwrap().as_slice()
        );
    }
}
