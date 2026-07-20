//! Saved Transaction-Builder templates: named, reusable batches persisted to a
//! dedicated redb store so a composed batch can be recalled in a later session.
//!
//! Unlike the wallet store, this file is **plaintext** — a template is a list
//! of public contract calls (addresses + calldata), carries no key material,
//! and is deliberately shareable across the machine's wallets. Keeping it out
//! of `wallet.redb` means saving a template never needs the wallet passphrase
//! (the coordinator holds the batch, not the passphrase) and never re-encrypts
//! the account rows.
//!
//! A template's calls are stored as a Safe-compatible [`bundle`] JSON string —
//! the same shape the Save/Load JSON modal already round-trips — so the
//! reconstruction path is shared and battle-tested. The stored `chainId` is
//! cosmetic: loading a template only reads the `to`/`value`/`data` triples and
//! renumbers ids into the live batch, exactly like the JSON import.

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::chain::Chain;

use super::{QueuedCall, TxBuilderError, bundle};

/// Single table keyed by insertion index (`u32 -> postcard(Template)`). A
/// smaller save wipes-and-reinserts, so removed rows drop, mirroring the
/// accounts/contacts pattern in `wallet::store`.
const TEMPLATES_TABLE: TableDefinition<u32, &[u8]> = TableDefinition::new("templates");

/// A named, persisted batch the user can reload into the composer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Template {
    /// User-facing title. Defaults to `Untitled batch`; renameable inline.
    pub name: String,
    /// Brand kaomoji shown beside the title.
    pub kaomoji: String,
    /// One-line subtitle tag (currently always `saved`). Reserved for future
    /// provenance labels; retained in the on-disk format.
    pub note: String,
    /// Cached call count so the picker renders `N calls` without re-parsing the
    /// bundle. Authoritative source is always `bundle_json`.
    pub call_count: usize,
    /// The batch serialized as a Safe-compatible bundle (see [`bundle::export`]).
    pub bundle_json: String,
}

impl Template {
    /// Snapshot the current batch as a template. `name`/`note` are user/UI
    /// supplied; the calls are frozen into a bundle JSON.
    pub fn from_batch(
        name: impl Into<String>,
        kaomoji: impl Into<String>,
        calls: &[QueuedCall],
    ) -> Self {
        Self {
            name: name.into(),
            kaomoji: kaomoji.into(),
            note: "saved".into(),
            call_count: calls.len(),
            // Chain is cosmetic in the stored bundle; the reload path ignores it.
            bundle_json: bundle::export(Chain::Mainnet, None, calls),
        }
    }

    /// Reconstruct the template's calls, renumbering ids from `start_id`.
    pub fn calls(&self, start_id: u64) -> Result<Vec<QueuedCall>, TxBuilderError> {
        bundle::import(&self.bundle_json, start_id)
    }
}

/// Location of the templates store, alongside `wallet.redb` in the data dir.
pub fn db_path() -> PathBuf {
    crate::paths::data_dir().join("templates.redb")
}

/// Load every saved template, in insertion order. Tolerant: a missing file,
/// missing table, or an undecodable row collapses to an empty/partial list
/// rather than an error — templates are a convenience, never load-blocking.
pub fn load() -> Vec<Template> {
    load_from(&db_path())
}

fn load_from(path: &PathBuf) -> Vec<Template> {
    let db = match Database::open(path) {
        Ok(db) => db,
        Err(_) => return Vec::new(), // no file yet, or unreadable — start empty
    };
    let Ok(txn) = db.begin_read() else {
        return Vec::new();
    };
    let tbl = match txn.open_table(TEMPLATES_TABLE) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let Ok(iter) = tbl.iter() else {
        return Vec::new();
    };
    let mut rows: Vec<(u32, Template)> = Vec::new();
    for entry in iter.flatten() {
        let (k, v) = entry;
        if let Ok(t) = postcard::from_bytes::<Template>(v.value()) {
            rows.push((k.value(), t));
        }
    }
    rows.sort_by_key(|(i, _)| *i);
    rows.into_iter().map(|(_, t)| t).collect()
}

/// Persist the full template list, replacing whatever was there. Wipe + insert
/// so a removed template drops its row.
pub fn save(templates: &[Template]) -> Result<(), String> {
    save_to(&db_path(), templates)
}

fn save_to(path: &PathBuf, templates: &[Template]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("templates: mkdir: {e}"))?;
    }
    let db = Database::create(path).map_err(|e| format!("templates: open: {e}"))?;
    let txn = db
        .begin_write()
        .map_err(|e| format!("templates: begin: {e}"))?;
    {
        let mut tbl = txn
            .open_table(TEMPLATES_TABLE)
            .map_err(|e| format!("templates: table: {e}"))?;
        let existing: Vec<u32> = tbl
            .iter()
            .map_err(|e| format!("templates: iter: {e}"))?
            .flatten()
            .map(|(k, _)| k.value())
            .collect();
        for k in existing {
            tbl.remove(k)
                .map_err(|e| format!("templates: remove: {e}"))?;
        }
        for (i, t) in templates.iter().enumerate() {
            let bytes = postcard::to_stdvec(t).map_err(|e| format!("templates: serialize: {e}"))?;
            tbl.insert(i as u32, bytes.as_slice())
                .map_err(|e| format!("templates: insert: {e}"))?;
        }
    }
    txn.commit()
        .map_err(|e| format!("templates: commit: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::txbuilder::abi;
    use crate::txbuilder::encode::build_contract_call;
    use alloy::primitives::address;
    use tempfile::tempdir;

    /// A single-call sample batch (USDC transfer), used to build templates in
    /// the tests without relying on any built-in starters.
    fn sample_calls() -> Vec<QueuedCall> {
        let usdc = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
        let c = abi::known_by_address(Chain::Mainnet, usdc).unwrap();
        let transfer = c.methods.iter().find(|m| m.name == "transfer").unwrap();
        let to = address!("0x000000000000000000000000000000000000dEaD");
        vec![
            build_contract_call(
                1,
                usdc,
                "USDC",
                transfer,
                &[to.to_string(), "1000000".into()],
                "0",
            )
            .unwrap(),
        ]
    }

    fn sample_template(name: &str) -> Template {
        Template::from_batch(name, "(°ᴗ°)", &sample_calls())
    }

    #[test]
    fn save_load_round_trip_and_overwrite() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("templates.redb");

        let a = vec![sample_template("one"), sample_template("two")];
        save_to(&path, &a).unwrap();
        let back = load_from(&path);
        assert_eq!(back, a);

        // A smaller list drops removed rows.
        let small = vec![a[0].clone()];
        save_to(&path, &small).unwrap();
        assert_eq!(load_from(&path), small);
    }

    #[test]
    fn load_missing_file_is_empty() {
        let dir = tempdir().unwrap();
        assert!(load_from(&dir.path().join("nope.redb")).is_empty());
    }

    #[test]
    fn from_batch_captures_calls() {
        let calls = sample_calls();
        let t = Template::from_batch("My batch", "(°ᴗ°)", &calls);
        assert_eq!(t.name, "My batch");
        assert_eq!(t.note, "saved");
        assert_eq!(t.call_count, calls.len());
        assert_eq!(t.calls(10).unwrap().len(), calls.len());
    }
}
