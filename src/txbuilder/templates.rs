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
//! reconstruction path is shared and battle-tested. The chain a template was
//! composed on is **binding**, not cosmetic: a [`QueuedCall`] carries only
//! `to`, and the same contract sits at a different address on every chain, so
//! an Optimism batch reloaded while composing on Mainnet would queue calls
//! aimed at whatever occupies those addresses there. The JSON import has
//! refused that since it was written; templates were the one path around it.
//!
//! Templates saved before the chain was recorded are chain-**unknown**, not
//! Mainnet. Their bundles carry `"chainId":"1"` because the old `from_batch`
//! stamped it unconditionally, so trusting that field would let a Base-composed
//! template load cleanly on Mainnet — the exact retargeting this exists to
//! prevent, in the one direction a naive check misses. The chain is therefore
//! read from `meta.kaoChainId`, a key only [`bundle::export`] writes; absent, it
//! is `None`, the row says so, and loading is refused on every chain until the
//! user re-saves the batch on the network they meant.

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use alloy::primitives::Address;

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
    /// The chain the batch was composed on, parsed out of `bundle_json` once
    /// so the picker row can show it without re-parsing every frame.
    ///
    /// `#[serde(skip)]` deliberately: the on-disk rows are non-self-describing
    /// postcard, so an added field would make every previously-saved template
    /// undecodable — and `load_from` drops undecodable rows, which would read
    /// as silent data loss. The authoritative copy stays inside the bundle
    /// JSON, where it always was; this is a cache, repopulated on load.
    #[serde(skip)]
    pub chain_id: Option<u64>,
    /// The account the batch was composed as, cached out of `bundle_json` the
    /// same way — and `#[serde(skip)]` for the same reason.
    ///
    /// A template is the shape this matters most in: saving a batch and running
    /// it later, under whatever identity happens to be active, is the whole
    /// point of the feature. `None` for a row saved before this was recorded,
    /// which reads as "unknown" and makes no claim either way.
    #[serde(skip)]
    pub from: Option<Address>,
}

impl Template {
    /// Snapshot the current batch as a template. `name`/`note` are user/UI
    /// supplied; the calls are frozen into a bundle JSON stamped with the chain
    /// they were composed on, which [`Self::calls`] then enforces.
    pub fn from_batch(
        name: impl Into<String>,
        kaomoji: impl Into<String>,
        chain: Chain,
        from: Address,
        calls: &[QueuedCall],
    ) -> Self {
        Self {
            name: name.into(),
            kaomoji: kaomoji.into(),
            note: "saved".into(),
            call_count: calls.len(),
            bundle_json: bundle::export(chain, None, from, calls),
            chain_id: Some(chain.chain_id()),
            from: Some(from),
        }
    }

    /// Reconstruct the template's calls, renumbering ids from `start_id`.
    ///
    /// `on` is the chain the composer is currently pointed at; a template
    /// stamped for a different one is refused rather than silently retargeting
    /// its addresses. A template with **no** recorded chain is refused on every
    /// chain — see the module note on why its `chainId` can't stand in.
    pub fn calls(&self, start_id: u64, on: Chain) -> Result<Vec<QueuedCall>, TxBuilderError> {
        let Some(chain) = self.chain() else {
            return Err(TxBuilderError::Assembly(format!(
                "\"{}\" was saved before Kao recorded which network a template was composed for, \
                 so its addresses can't be trusted on any chain — rebuild and re-save it",
                self.name,
            )));
        };
        if chain != on {
            return Err(TxBuilderError::Assembly(format!(
                "\"{}\" was composed on {} but you're composing on {} — the same contract has a \
                 different address on each chain",
                self.name,
                chain.label(),
                on.label(),
            )));
        }
        bundle::import(&self.bundle_json, start_id, Some(on))
    }

    /// The chain this template was composed on, or `None` for one saved before
    /// the chain was recorded — which is *not* the same as Mainnet, and is why
    /// this reads `meta.kaoChainId` rather than the bundle's own `chainId`.
    pub fn chain(&self) -> Option<Chain> {
        self.chain_id.and_then(Chain::from_chain_id)
    }

    /// Re-read the cached `chain_id` out of the stored bundle JSON. Called on
    /// load, where the field always arrives `None` (it is never serialized).
    fn hydrate_chain(&mut self) {
        let meta = serde_json::from_str::<bundle::Bundle>(&self.bundle_json)
            .ok()
            .map(|b| b.meta);
        self.chain_id = meta.as_ref().and_then(|m| m.kao_chain_id);
        self.from = meta.as_ref().and_then(bundle::Meta::composed_as);
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
        if let Ok(mut t) = postcard::from_bytes::<Template>(v.value()) {
            // `chain_id` is not on disk (see the field's note) — recover it
            // from the bundle the row does carry.
            t.hydrate_chain();
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
        restrict_to_owner(parent, 0o700).map_err(|e| format!("templates: chmod dir: {e}"))?;
    }
    let db = Database::create(path).map_err(|e| format!("templates: open: {e}"))?;
    // Every other store in the app is owner-only on disk; this one holds
    // unauthenticated postcard rows whose `name`/`note` are rendered verbatim,
    // so a locally-writable file is a rendering surface for another local user.
    restrict_to_owner(path, 0o600).map_err(|e| format!("templates: chmod: {e}"))?;
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

/// Restrict a path to owner-only access. Unix-only — Windows lacks POSIX
/// modes and a proper ACL story is out of scope here, same as `wallet::store`.
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
        Template::from_batch(
            name,
            "(°ᴗ°)",
            Chain::Mainnet,
            Address::repeat_byte(0xAA),
            &sample_calls(),
        )
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
        let t = Template::from_batch(
            "My batch",
            "(°ᴗ°)",
            Chain::Mainnet,
            Address::repeat_byte(0xAA),
            &calls,
        );
        assert_eq!(t.name, "My batch");
        assert_eq!(t.note, "saved");
        assert_eq!(t.call_count, calls.len());
        assert_eq!(t.calls(10, Chain::Mainnet).unwrap().len(), calls.len());
    }

    /// The hole templates were: the JSON import has always refused a
    /// cross-chain bundle, and `from_batch` used to throw the chain away, so
    /// loading a template on another network retargeted its addresses.
    #[test]
    fn a_template_refuses_to_load_on_another_chain() {
        let t = Template::from_batch(
            "opt batch",
            "(°ᴗ°)",
            Chain::Optimism,
            Address::repeat_byte(0xAA),
            &sample_calls(),
        );
        assert_eq!(t.chain(), Some(Chain::Optimism));
        let err = t
            .calls(1, Chain::Mainnet)
            .expect_err("an Optimism template must not load on Mainnet");
        assert!(
            err.to_string().contains("different address on each chain"),
            "got {err}"
        );
        assert!(t.calls(1, Chain::Optimism).is_ok(), "its own chain loads");
    }

    /// A template written before the chain was recorded carries `chainId: "1"`
    /// from the old unconditional stamp. Trusting that would let a
    /// Base-composed template load cleanly on Mainnet — the retargeting this
    /// whole mechanism exists to stop, in the one direction a naive
    /// chainId-vs-chainId check misses. It must be refused everywhere.
    #[test]
    fn a_template_with_no_recorded_chain_is_refused_on_every_chain() {
        let mut legacy = sample_template("legacy");
        // Strip the marker the way a pre-fix save would have left it: the
        // bundle still says chainId 1, but nothing says Kao recorded it.
        legacy.bundle_json = legacy.bundle_json.replace("\"kaoChainId\": 1,", "");
        legacy.bundle_json = legacy.bundle_json.replace("\"kaoChainId\": 1", "");
        legacy.hydrate_chain();
        assert!(
            legacy.bundle_json.contains("\"chainId\": \"1\""),
            "still stamped Mainnet"
        );
        assert_eq!(
            legacy.chain(),
            None,
            "an unmarked template is chain-unknown"
        );

        for on in [Chain::Mainnet, Chain::Base, Chain::Optimism] {
            let err = legacy
                .calls(1, on)
                .expect_err("a chain-unknown template must not load anywhere");
            assert!(
                err.to_string()
                    .contains("before Kao recorded which network"),
                "on {on:?}: {err}"
            );
        }
    }

    /// `chain_id` is `#[serde(skip)]`, so it has to come back off the bundle.
    #[test]
    fn chain_survives_a_save_load_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("templates.redb");
        let t = Template::from_batch(
            "base batch",
            "(°ᴗ°)",
            Chain::Base,
            Address::repeat_byte(0xAA),
            &sample_calls(),
        );
        save_to(&path, std::slice::from_ref(&t)).unwrap();
        let back = load_from(&path);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].chain(), Some(Chain::Base));
        assert_eq!(back[0], t, "hydration restores the skipped field exactly");
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_the_template_store_with_owner_only_perms() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("nested").join("templates.redb");
        save_to(&path, &[sample_template("t")]).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got 0o{mode:o}");
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "expected 0o700, got 0o{dir_mode:o}");
    }
}
