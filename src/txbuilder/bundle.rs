//! Safe{Wallet} Transaction-Builder–compatible JSON import/export.
//!
//! The batch serializes to the same shape the official Safe Transaction
//! Builder produces, so a Kao batch can be loaded into Safe{Wallet} (and
//! vice-versa). We always write the concrete `data` (the exact calldata),
//! plus the `contractMethod` / `contractInputsValues` metadata for human
//! readability and round-tripping the decoded view.
//!
//! On import we prefer the literal `data` when present; if a bundle from
//! another tool omits it (relying on the method + input values), we
//! re-encode from those.

use alloy::dyn_abi::DynSolType;
use alloy::primitives::{Address, Bytes, U256};
use serde::{Deserialize, Serialize};

use crate::chain::Chain;

use super::abi::{AbiMethod, AbiParam, MethodProvenance};
use super::encode::{decode_args, encode_call};
use super::{QueuedCall, TxBuilderError};

/// The bundle-format major version this wallet reads and writes.
///
/// `version` used to be written as `"1.0"` and never read back, which made the
/// field decoration rather than a contract: a future `2.x` bundle — whatever it
/// changed about how `data`, an operation byte, or the meta block are meant to
/// be interpreted — would have been parsed under v1 rules and queued as
/// something other than what it describes. A differing *minor* is fine (added
/// fields deserialize away); an unknown major is refused.
const FORMAT_MAJOR: u32 = 1;

/// The largest bundle this wallet will parse, in bytes.
///
/// [`import`] is fed by a paste box, so its input is untrusted in size as well
/// as in content, and everything downstream of it is linear in the batch. The
/// only place to stop a pathological one cheaply is before serde walks it. A
/// mebibyte is well above any batch whose calldata could fit in a block.
pub const MAX_BUNDLE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct Bundle {
    #[serde(default)]
    pub version: String,
    #[serde(rename = "chainId")]
    pub chain_id: String,
    #[serde(default, rename = "createdAt", skip_serializing_if = "is_zero_u64")]
    pub created_at: u64,
    /// Provenance. Optional on import: it carries no part of what executes, so
    /// a bundle from a tool that doesn't write one is still a perfectly good
    /// batch — it used to be rejected outright with serde's "missing field
    /// `meta`", which reads as a malformed file rather than an absent label.
    #[serde(default)]
    pub meta: Meta,
    pub transactions: Vec<BundleTx>,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// Seconds since the Unix epoch, for [`Bundle::created_at`]. Saturates to 0
/// (i.e. "not stamped") if the host clock is before 1970.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Refuse a bundle whose format major version this wallet doesn't implement.
fn check_version(raw: &str) -> Result<(), TxBuilderError> {
    let v = raw.trim();
    match v.split('.').next().unwrap_or("").trim().parse::<u32>() {
        Ok(FORMAT_MAJOR) => Ok(()),
        Ok(other) => Err(TxBuilderError::Assembly(format!(
            "bundle is format version {v}, and this wallet reads {FORMAT_MAJOR}.x — a version \
             {other} batch may encode its calls differently, so importing it under {FORMAT_MAJOR}.x \
             rules could queue something other than what it describes",
        ))),
        Err(_) => Err(TxBuilderError::Assembly(format!(
            "bundle doesn't say which format version it is ({}) — refusing to guess",
            if v.is_empty() {
                "no `version` field".to_string()
            } else {
                format!("`version` is {v:?}")
            },
        ))),
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Meta {
    pub name: String,
    #[serde(rename = "txBuilderVersion")]
    pub tx_builder_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe: Option<String>,
    /// The chain id, restated under a key only this wallet writes.
    ///
    /// The standard `chainId` field can't distinguish "composed on Mainnet"
    /// from "written by a version that stamped Mainnet unconditionally", and
    /// [`super::templates`] did exactly that before the chain became binding.
    /// A stored template lacking this key is chain-*unknown*, not Mainnet, and
    /// refuses to load anywhere rather than loading wrongly on one chain.
    /// Ignored on import — the standard `chainId` remains authoritative there.
    #[serde(
        default,
        rename = "kaoChainId",
        skip_serializing_if = "Option::is_none"
    )]
    pub kao_chain_id: Option<u64>,
    /// The account the batch was composed *as* — the Safe in Safe mode, the
    /// EOA otherwise.
    ///
    /// A batch's calls are written against one account: its allowances, its
    /// balances, its position. Reloading it under a different identity re-aims
    /// every one of them, and the natural workflow is exactly the dangerous one
    /// (compose and test as your EOA, save, switch to the Safe to run it).
    /// `meta.safe` recorded half of this and only for a Safe; nothing read it.
    ///
    /// **A disclosure, not a gate.** An imported bundle's `meta` is authored by
    /// whoever wrote the file, so a mismatch here can't be trusted as a
    /// *refusal* — it is worth saying out loud, and worth nothing as a wall.
    /// The value is real for a batch this wallet exported and reloads itself.
    #[serde(default, rename = "kaoFrom", skip_serializing_if = "Option::is_none")]
    pub kao_from: Option<String>,
}

impl Meta {
    /// The composing identity, when one was recorded and parses.
    pub fn composed_as(&self) -> Option<Address> {
        self.kao_from.as_ref()?.parse().ok()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BundleTx {
    pub to: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(
        default,
        rename = "contractMethod",
        skip_serializing_if = "Option::is_none"
    )]
    pub contract_method: Option<ContractMethod>,
    #[serde(
        default,
        rename = "contractInputsValues",
        skip_serializing_if = "Option::is_none"
    )]
    pub contract_inputs_values: Option<indexmap_lite::Map>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContractMethod {
    pub name: String,
    #[serde(default)]
    pub payable: bool,
    pub inputs: Vec<MethodInput>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MethodInput {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
}

/// A minimal insertion-ordered string map, so `contractInputsValues`
/// serializes in declared-argument order (a plain `HashMap` would scramble
/// it, and `BTreeMap` would alpha-sort). Values are always strings in the
/// Safe format.
pub mod indexmap_lite {
    use serde::de::{MapAccess, Visitor};
    use serde::ser::SerializeMap;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Debug, Clone, Default)]
    pub struct Map(pub Vec<(String, String)>);

    impl Map {
        pub fn get(&self, key: &str) -> Option<&str> {
            self.0
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        }
    }

    impl Serialize for Map {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut m = s.serialize_map(Some(self.0.len()))?;
            for (k, v) in &self.0 {
                m.serialize_entry(k, v)?;
            }
            m.end()
        }
    }

    impl<'de> Deserialize<'de> for Map {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Map;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("a map of string→string")
                }
                fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Map, A::Error> {
                    let mut out = Vec::new();
                    // Values may be numbers or strings in the wild; coerce
                    // via serde_json::Value then stringify.
                    while let Some((k, v)) = a.next_entry::<String, serde_json::Value>()? {
                        let s = match v {
                            serde_json::Value::String(s) => s,
                            other => other.to_string(),
                        };
                        out.push((k, s));
                    }
                    Ok(Map(out))
                }
            }
            d.deserialize_map(V)
        }
    }
}

/// Serialize a batch to a pretty Safe-compatible JSON string.
///
/// `from` is the account the batch was composed as, recorded so reloading it
/// under a different identity can say so — see [`Meta::kao_from`]. `safe` stays
/// the Safe-app-compatible field and is `None` for an EOA batch.
pub fn export(chain: Chain, safe: Option<Address>, from: Address, calls: &[QueuedCall]) -> String {
    let transactions = calls.iter().map(tx_from_call).collect();
    let bundle = Bundle {
        version: format!("{FORMAT_MAJOR}.0"),
        chain_id: chain.chain_id().to_string(),
        created_at: now_secs(),
        meta: Meta {
            name: "Kao batch".into(),
            tx_builder_version: concat!("kao-", env!("CARGO_PKG_VERSION")).into(),
            safe: safe.map(|s| s.to_string()),
            kao_chain_id: Some(chain.chain_id()),
            kao_from: Some(from.to_string()),
        },
        transactions,
    };
    serde_json::to_string_pretty(&bundle).unwrap_or_else(|_| "{}".into())
}

fn tx_from_call(c: &QueuedCall) -> BundleTx {
    let (contract_method, contract_inputs_values) = if let Some(sig) = &c.signature {
        let name = sig.split('(').next().unwrap_or(sig).to_string();
        let inputs = c
            .decoded_args
            .iter()
            .map(|a| MethodInput {
                name: a.name.clone(),
                ty: a.ty.clone(),
            })
            .collect();
        let values = indexmap_lite::Map(
            c.decoded_args
                .iter()
                .map(|a| (a.name.clone(), a.value.clone()))
                .collect(),
        );
        (
            Some(ContractMethod {
                name,
                payable: !c.value.is_zero(),
                inputs,
            }),
            Some(values),
        )
    } else {
        (None, None)
    };
    BundleTx {
        to: c.to.to_string(),
        value: c.value.to_string(),
        data: Some(format!("0x{}", alloy::hex::encode(&c.data))),
        contract_method,
        contract_inputs_values,
    }
}

/// Parse a bundle into queued calls, assigning ids `start_id, start_id+1,…`.
///
/// `expect_chain` rejects a bundle stamped for a different chain. A
/// [`QueuedCall`] carries only `to`, and the same contract lives at a different
/// address on every chain, so importing a Mainnet bundle while composing on
/// Base would queue calls aimed at whatever occupies those addresses there.
/// [`super::templates`] always passes a chain. The JSON modal passes
/// `net.builtin()`, which is `None` on a custom network — there is no `Chain`
/// to compare against there, and the check is skipped. That is reachable only
/// if a custom network ever gets the batch pane the modal lives in (it is
/// composer-only today, so there is no batch to export or import); if that
/// changes, this is the wall that has to be re-hung on the chain id itself.
pub fn import(
    json: &str,
    start_id: u64,
    expect_chain: Option<Chain>,
) -> Result<Vec<QueuedCall>, TxBuilderError> {
    let json = json.trim();
    // Ahead of serde: the cost of a hostile bundle is paid once in the parse
    // and then again in every frame that lays out its cards.
    if json.len() > MAX_BUNDLE_BYTES {
        return Err(TxBuilderError::Assembly(format!(
            "that bundle is {} bytes, and this wallet reads batches up to {MAX_BUNDLE_BYTES} — \
             no batch whose calls fit in a block comes anywhere near it",
            json.len(),
        )));
    }
    let bundle: Bundle = serde_json::from_str(json)
        .map_err(|e| TxBuilderError::Assembly(format!("not a batch bundle — {e}")))?;
    check_version(&bundle.version)?;
    if bundle.transactions.is_empty() {
        return Err(TxBuilderError::Assembly(
            "bundle has no transactions".into(),
        ));
    }
    // Before a single QueuedCall is built, so a 50k-transaction bundle never
    // becomes 50k cards.
    if bundle.transactions.len() > super::MAX_BATCH_CALLS {
        return Err(TxBuilderError::Assembly(format!(
            "that bundle has {} transactions, and this wallet queues at most {} — a batch that \
             long is more gas than a block will take and more cards than anyone reviews",
            bundle.transactions.len(),
            super::MAX_BATCH_CALLS,
        )));
    }
    if let Some(want) = expect_chain {
        // An unparseable or absent chain id is not treated as a match: the
        // point of the check is that the addresses were composed for the chain
        // we're about to aim them at.
        let got = bundle.chain_id.trim().parse::<u64>().ok();
        if got != Some(want.chain_id()) {
            return Err(TxBuilderError::Assembly(format!(
                "bundle is for chain {} but you're composing on {} (chain {}) — the same \
                 contract has a different address on each chain",
                bundle.chain_id.trim(),
                want.display_name(),
                want.chain_id(),
            )));
        }
    }
    bundle
        .transactions
        .iter()
        .enumerate()
        .map(|(i, tx)| call_from_tx(tx, start_id + i as u64))
        .collect()
}

fn call_from_tx(tx: &BundleTx, id: u64) -> Result<QueuedCall, TxBuilderError> {
    // Through the composer's own parser, so a bundle can't smuggle a corrupted
    // target past the checksum wall that guards every hand-typed address.
    // `export` writes the checksummed form, so anything this wallet emits
    // round-trips; only genuine mixed-case corruption is refused.
    let to = super::encode::parse_address(&tx.to)
        .map_err(|e| TxBuilderError::Assembly(format!("bad `to` address: {} — {e}", tx.to)))?;
    let value = parse_value(&tx.value)?;

    // Prefer the literal calldata; fall back to re-encoding from the method.
    let literal = tx
        .data
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty() && *d != "0x")
        .map(parse_hex)
        .transpose()?;

    match (&tx.contract_method, literal) {
        // Contract call with metadata.
        //
        // The calldata is the only thing that executes, so it is the only
        // thing trusted. `contractMethod` / `contractInputsValues` are
        // untrusted labels on top of it: a bundle can name `approve` over
        // `transfer` bytes, or claim `amount: 1` over a word holding MAX, and
        // the queue card is exactly where a user vets a batch before signing
        // it. So the metadata is *checked* against the bytes, never displayed
        // over them.
        (Some(cm), literal) => {
            let method = method_from_meta(cm)?;
            let data = match literal {
                Some(d) => {
                    // The claimed method must be the encoded one. Comparing
                    // selectors compares name *and* parameter types, since the
                    // selector is derived from both.
                    let got = d.get(..4).ok_or_else(|| {
                        TxBuilderError::Assembly(format!(
                            "transaction claims `{}` but carries {} bytes of calldata — \
                             too short to hold a selector",
                            method.signature,
                            d.len()
                        ))
                    })?;
                    if got != method.selector {
                        return Err(TxBuilderError::Assembly(format!(
                            "transaction claims `{}` (selector 0x{}) but its calldata starts \
                             with 0x{} — refusing to import a batch whose description doesn't \
                             match its bytes",
                            method.signature,
                            alloy::hex::encode(method.selector),
                            alloy::hex::encode(got),
                        )));
                    }
                    d
                }
                // No calldata supplied: encode it from the declared values, so
                // the bytes are derived from the metadata and agree with it by
                // construction.
                None => {
                    // `contractInputsValues` is keyed by the bundle's own
                    // parameter names, so the lookup has to use them — but it
                    // reads them straight off `cm.inputs` rather than off
                    // `method`, which deliberately no longer carries them (see
                    // `method_from_meta`). Metadata keyed by metadata: a name
                    // used here only ever chooses which value gets encoded, and
                    // the resulting bytes are decoded back and re-checked
                    // below, so a wrong name surfaces as a wrong *value* on the
                    // card rather than as a plausible label over other bytes.
                    let values: Vec<String> = (0..method.inputs.len())
                        .map(|i| {
                            let key = cm.inputs.get(i).map(|p| p.name.as_str()).unwrap_or("");
                            tx.contract_inputs_values
                                .as_ref()
                                .and_then(|m| m.get(key).or_else(|| m.get(&format!("arg{i}"))))
                                .unwrap_or("")
                                .to_string()
                        })
                        .collect();
                    encode_call(&method, &values)?
                }
            };
            // Either way, the displayed arguments are decoded back out of the
            // final bytes — never read off `contractInputsValues`. Calldata
            // that won't decode against the signature it claims is a hard
            // error: a batch can't be shown as something it isn't.
            let decoded_args = decode_args(&method, &data).ok_or_else(|| {
                TxBuilderError::Assembly(format!(
                    "calldata doesn't decode as `{}` — refusing to import a batch it can't \
                     account for",
                    method.signature
                ))
            })?;
            Ok(QueuedCall {
                id,
                to,
                value,
                data,
                title: format!("{}.{}", crate::wallet::short_address(to), cm.name),
                detail: decoded_args
                    .first()
                    .map(|a| format!("{}: {}", a.name, a.value))
                    .unwrap_or_else(|| "no arguments".into()),
                signature: Some(method.signature),
                decoded_args,
            })
        }
        // Raw call (no method metadata): the literal data is the calldata.
        (None, literal) => {
            let data = literal.unwrap_or_default();
            let detail = if data.is_empty() {
                "plain ETH transfer".into()
            } else {
                format!("{} bytes calldata", data.len())
            };
            Ok(QueuedCall {
                id,
                to,
                value,
                data,
                title: "Raw call".into(),
                detail,
                signature: None,
                decoded_args: Vec::new(),
            })
        }
    }
}

/// Rebuild the [`AbiMethod`] a bundle's `contractMethod` block claims.
///
/// The function *name* and the parameter *types* survive the trip because the
/// selector is derived from them and cross-checked against the calldata's own
/// first four bytes by the caller — claim `approve(address,uint256)` over
/// `transfer` bytes and the import is refused.
///
/// Parameter **names** get no such binding: they are not in the selector
/// preimage, so nothing in the bundle constrains them and nothing in the
/// calldata can contradict them. A hostile bundle could label an honest
/// `approve(spender, MAX)` as `revokedSpender` / `newLimit` and the queue card
/// — the screen where a user actually vets a batch — would render it. So they
/// are dropped here and [`AbiParam::display_name`] falls back to positional
/// `arg0` / `arg1`. Less pretty, but every label on that card is then derived
/// from something the bytes commit to.
fn method_from_meta(cm: &ContractMethod) -> Result<AbiMethod, TxBuilderError> {
    let inputs = cm
        .inputs
        .iter()
        .map(|inp| {
            let ty: DynSolType = inp.ty.parse().map_err(|e| {
                TxBuilderError::Assembly(format!("bad param type {:?}: {e}", inp.ty))
            })?;
            Ok(AbiParam {
                name: String::new(),
                ty_str: ty.sol_type_name().into_owned(),
                ty,
            })
        })
        .collect::<Result<Vec<_>, TxBuilderError>>()?;
    // Reuse the canonical signature/selector derivation.
    let mut sig = String::from(cm.name.as_str());
    sig.push('(');
    for (i, p) in inputs.iter().enumerate() {
        if i > 0 {
            sig.push(',');
        }
        sig.push_str(&p.ty_str);
    }
    sig.push(')');
    let hash = alloy::primitives::keccak256(sig.as_bytes());
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&hash[..4]);
    Ok(AbiMethod {
        name: cm.name.clone(),
        inputs,
        outputs: Vec::new(),
        payable: cm.payable,
        selector,
        signature: sig,
        // The name came from the bundle's own metadata, and `import` only
        // accepts it when the derived selector matches the calldata being
        // imported — the same standard a declared ABI is held to.
        provenance: MethodProvenance::Declared,
        inferred_mutability: None,
    })
}

fn parse_value(s: &str) -> Result<U256, TxBuilderError> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(U256::ZERO);
    }
    if let Some(hex) = t.strip_prefix("0x") {
        U256::from_str_radix(hex, 16)
            .map_err(|_| TxBuilderError::Assembly(format!("bad value: {s}")))
    } else {
        t.parse::<U256>()
            .map_err(|_| TxBuilderError::Assembly(format!("bad value: {s}")))
    }
}

fn parse_hex(s: &str) -> Result<Bytes, TxBuilderError> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    alloy::hex::decode(hex)
        .map(Bytes::from)
        .map_err(|_| TxBuilderError::Assembly(format!("bad hex data: {s}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::txbuilder::abi;
    use crate::txbuilder::encode::build_contract_call;
    use alloy::primitives::address;

    fn sample_batch() -> Vec<QueuedCall> {
        let usdc = abi::known_by_address(
            Chain::Mainnet,
            address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
        )
        .unwrap();
        let approve = usdc.methods.iter().find(|m| m.name == "approve").unwrap();
        let aave = address!("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2");
        vec![
            build_contract_call(
                101,
                usdc.address,
                "USDC",
                approve,
                &[aave.to_string(), "5000000000".into()],
                "0",
            )
            .unwrap(),
        ]
    }

    #[test]
    fn export_then_import_round_trips_calldata() {
        let batch = sample_batch();
        let json = export(
            Chain::Mainnet,
            Some(Address::repeat_byte(0x5a)),
            Address::repeat_byte(0x5a),
            &batch,
        );
        let back = import(&json, 1, None).unwrap();
        assert_eq!(back.len(), 1);
        // The exact calldata survives the round-trip.
        assert_eq!(back[0].data, batch[0].data);
        assert_eq!(back[0].to, batch[0].to);
        assert_eq!(back[0].value, batch[0].value);
        assert_eq!(back[0].signature, batch[0].signature);
        assert_eq!(back[0].id, 1);
    }

    #[test]
    fn a_composed_call_reads_the_same_after_a_round_trip() {
        // The audit's regression: the composer echoed keystrokes and the import
        // path decoded bytes, so export-then-reimport changed what the card
        // said about identical calldata. Both derive from the bytes now.
        let usdc = abi::known_by_address(
            Chain::Mainnet,
            address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
        )
        .unwrap();
        let approve = usdc.methods.iter().find(|m| m.name == "approve").unwrap();
        let batch = vec![
            build_contract_call(
                1,
                usdc.address,
                "USDC",
                approve,
                &[
                    "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2".into(),
                    // Typed with a unit suffix, which is where the two paths
                    // used to disagree.
                    "1 ether".into(),
                ],
                "0",
            )
            .unwrap(),
        ];
        let json = export(Chain::Mainnet, None, Address::repeat_byte(0xAA), &batch);
        let back = import(&json, 1, None).unwrap();
        assert_eq!(back[0].data, batch[0].data);

        // Values and types round-trip exactly, because both ends now read them
        // out of the calldata.
        let values = |c: &QueuedCall| -> Vec<(String, String)> {
            c.decoded_args
                .iter()
                .map(|a| (a.ty.clone(), a.value.clone()))
                .collect()
        };
        assert_eq!(values(&back[0]), values(&batch[0]));
        assert_eq!(back[0].decoded_args[1].value, "1000000000000000000");

        // Argument *names* deliberately do not survive: an imported name is
        // unvalidated metadata bound to nothing in the bytes, so import
        // replaces it with a positional label rather than render it over
        // calldata it doesn't describe.
        assert_eq!(batch[0].decoded_args[0].name, "spender");
        assert_eq!(back[0].decoded_args[0].name, "arg0");
    }

    #[test]
    fn export_shape_is_safe_compatible() {
        let batch = sample_batch();
        let json = export(Chain::Mainnet, None, Address::repeat_byte(0xAA), &batch);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["version"], "1.0");
        assert_eq!(v["chainId"], "1");
        assert!(v["transactions"][0]["to"].is_string());
        assert!(
            v["transactions"][0]["data"]
                .as_str()
                .unwrap()
                .starts_with("0x")
        );
        assert_eq!(v["transactions"][0]["contractMethod"]["name"], "approve");
    }

    /// Parameter names are not in the selector preimage, so nothing in a
    /// bundle binds them to the calldata. A hostile bundle could label an
    /// honest `approve(spender, MAX)` as `revokedSpender` / `newLimit` and the
    /// queue card — the screen where a batch is actually vetted — rendered it.
    #[test]
    fn import_ignores_attacker_supplied_parameter_names() {
        // Real `approve(0xdEaD, 2^256-1)` calldata, honestly encoded.
        let data = format!(
            "0x095ea7b3{}{}",
            "000000000000000000000000000000000000000000000000000000000000dead",
            "f".repeat(64),
        );
        let json = format!(
            r#"{{
            "version":"1.0","chainId":"1",
            "meta":{{"name":"x","txBuilderVersion":"other"}},
            "transactions":[{{
                "to":"0x000000000000000000000000000000000000dEaD","value":"0",
                "data":"{data}",
                "contractMethod":{{"name":"approve","payable":false,"inputs":[
                    {{"name":"revokedSpender","type":"address"}},
                    {{"name":"newLimit","type":"uint256"}}]}}
            }}]
        }}"#
        );
        let calls = import(&json, 1, None).unwrap();
        let names: Vec<&str> = calls[0]
            .decoded_args
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["arg0", "arg1"],
            "unbindable labels must not be rendered over trusted bytes"
        );
        // The function name and types *are* bound — the selector commits to
        // both — so they survive, and so do the values decoded from calldata.
        assert_eq!(
            calls[0].signature.as_deref(),
            Some("approve(address,uint256)")
        );
        assert_eq!(calls[0].decoded_args[1].value, U256::MAX.to_string());
    }

    #[test]
    fn import_raw_transaction_without_method() {
        let json = r#"{
            "version":"1.0","chainId":"1",
            "meta":{"name":"x","txBuilderVersion":"other"},
            "transactions":[{"to":"0x000000000000000000000000000000000000dEaD","value":"1000","data":"0xdeadbeef"}]
        }"#;
        let calls = import(json, 5, None).unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].is_raw());
        assert_eq!(calls[0].data.as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(calls[0].value, U256::from(1000u64));
        assert_eq!(calls[0].id, 5);
    }

    #[test]
    fn import_reencodes_when_data_missing() {
        // A Safe-UI bundle that omits `data` and relies on the method.
        let json = r#"{
            "version":"1.0","chainId":"1",
            "meta":{"name":"x","txBuilderVersion":"safe"},
            "transactions":[{
                "to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                "value":"0",
                "contractMethod":{"name":"approve","payable":false,
                    "inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}]},
                "contractInputsValues":{"spender":"0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2","amount":"5000000000"}
            }]
        }"#;
        let calls = import(json, 1, None).unwrap();
        assert_eq!(
            calls[0].signature.as_deref(),
            Some("approve(address,uint256)")
        );
        // selector present + amount word encoded
        assert_eq!(&calls[0].data[..4], &[0x09, 0x5e, 0xa7, 0xb3]);
        assert_eq!(
            U256::from_be_slice(&calls[0].data[4 + 32..4 + 64]),
            U256::from(5_000_000_000u64)
        );
    }

    /// `approve(address,uint256)` calldata, built by hand so a test can pair it
    /// with metadata that describes something else.
    fn approve_calldata(spender: Address, amount: U256) -> String {
        let mut d = vec![0x09u8, 0x5e, 0xa7, 0xb3];
        d.extend_from_slice(&spender.into_word().0);
        d.extend_from_slice(&amount.to_be_bytes::<32>());
        format!("0x{}", alloy::hex::encode(d))
    }

    fn bundle_with(tx_json: &str) -> String {
        format!(
            r#"{{"version":"1.0","chainId":"1",
                "meta":{{"name":"x","txBuilderVersion":"other"}},
                "transactions":[{tx_json}]}}"#
        )
    }

    #[test]
    fn import_refuses_a_bundle_larger_than_the_read_limit() {
        // Refused on length, before serde walks it — the point is that the
        // parse never runs, so the shape of the payload is irrelevant.
        let json = format!(
            r#"{{"version":"1.0","pad":"{}"}}"#,
            "a".repeat(MAX_BUNDLE_BYTES)
        );
        let err = import(&json, 1, None).unwrap_err().to_string();
        assert!(err.contains(&MAX_BUNDLE_BYTES.to_string()), "{err}");
    }

    #[test]
    fn import_refuses_more_transactions_than_the_queue_can_hold() {
        let tx = r#"{"to":"0x000000000000000000000000000000000000dEaD","value":"0","data":"0x"}"#;
        let bundle_of = |n: usize| {
            format!(
                r#"{{"version":"1.0","chainId":"1","transactions":[{}]}}"#,
                vec![tx; n].join(",")
            )
        };
        let err = import(&bundle_of(crate::txbuilder::MAX_BATCH_CALLS + 1), 1, None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&(crate::txbuilder::MAX_BATCH_CALLS + 1).to_string()),
            "{err}"
        );
        assert!(
            err.contains(&crate::txbuilder::MAX_BATCH_CALLS.to_string()),
            "{err}"
        );
        // Exactly at the ceiling still imports.
        assert_eq!(
            import(&bundle_of(crate::txbuilder::MAX_BATCH_CALLS), 1, None)
                .unwrap()
                .len(),
            crate::txbuilder::MAX_BATCH_CALLS
        );
    }

    #[test]
    fn import_refuses_a_bundle_whose_target_fails_its_checksum() {
        // A corrupted `to` still parses as a perfectly valid address, so the
        // only thing standing between it and the queue is the checksum. What
        // this wallet exports is checksummed, so nothing it wrote is refused.
        let corrupted = "0xa0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        let json = bundle_with(&format!(
            r#"{{"to":"{corrupted}","value":"0","data":"0xdeadbeef"}}"#
        ));
        let err = import(&json, 1, None).unwrap_err().to_string();
        assert!(err.contains("EIP-55"), "{err}");

        let good = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        let json = bundle_with(&format!(
            r#"{{"to":"{good}","value":"0","data":"0xdeadbeef"}}"#
        ));
        assert!(import(&json, 1, None).is_ok());
    }

    #[test]
    fn import_rejects_metadata_that_names_a_different_method_than_the_calldata() {
        // The attack: a bundle that reads as a harmless 1-unit approve in the
        // queue card while the bytes are something else entirely. The card is
        // where a batch is vetted, so this has to be refused outright.
        let json = bundle_with(&format!(
            r#"{{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","value":"0",
                 "data":"0xa9059cbb{}{}",
                 "contractMethod":{{"name":"approve","payable":false,
                   "inputs":[{{"name":"spender","type":"address"}},{{"name":"amount","type":"uint256"}}]}},
                 "contractInputsValues":{{"spender":"0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2","amount":"1"}}}}"#,
            alloy::hex::encode(Address::repeat_byte(0xDE).into_word().0),
            alloy::hex::encode(U256::MAX.to_be_bytes::<32>()),
        ));
        let err = import(&json, 1, None).unwrap_err().to_string();
        assert!(err.contains("approve(address,uint256)"), "{err}");
        assert!(err.contains("0xa9059cbb"), "names the real selector: {err}");
    }

    #[test]
    fn imported_arguments_come_from_the_calldata_not_the_metadata() {
        // Same selector, lying values: the metadata says 1, the word holds MAX.
        // The decoded view must report what will actually execute.
        let spender = address!("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2");
        let json = bundle_with(&format!(
            r#"{{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","value":"0",
                 "data":"{}",
                 "contractMethod":{{"name":"approve","payable":false,
                   "inputs":[{{"name":"spender","type":"address"}},{{"name":"amount","type":"uint256"}}]}},
                 "contractInputsValues":{{"spender":"0x0000000000000000000000000000000000000001","amount":"1"}}}}"#,
            approve_calldata(spender, U256::MAX),
        ));
        let calls = import(&json, 1, None).unwrap();
        let args = &calls[0].decoded_args;
        assert_eq!(
            args[0].value,
            spender.to_checksum(None),
            "spender from bytes"
        );
        assert_eq!(args[1].value, U256::MAX.to_string(), "amount from bytes");
        // The one-line summary is built from the same decoded view.
        assert!(calls[0].detail.contains(&spender.to_checksum(None)));
    }

    #[test]
    fn import_rejects_calldata_that_does_not_decode_as_the_claimed_method() {
        // Right selector, truncated body — nothing to display honestly.
        let json = bundle_with(
            r#"{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","value":"0",
                "data":"0x095ea7b300",
                "contractMethod":{"name":"approve","payable":false,
                  "inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}]}}"#,
        );
        let err = import(&json, 1, None).unwrap_err().to_string();
        assert!(err.contains("doesn't decode"), "{err}");
    }

    #[test]
    fn import_rejects_calldata_too_short_to_carry_a_selector() {
        let json = bundle_with(
            r#"{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","value":"0",
                "data":"0x0102",
                "contractMethod":{"name":"pause","payable":false,"inputs":[]}}"#,
        );
        let err = import(&json, 1, None).unwrap_err().to_string();
        assert!(err.contains("too short"), "{err}");
    }

    #[test]
    fn import_rejects_trailing_bytes_after_a_no_argument_selector() {
        // `pause()` takes nothing, so anything past the selector is calldata
        // the decoded view would silently omit.
        let sig = alloy::primitives::keccak256(b"pause()");
        let json = bundle_with(&format!(
            r#"{{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","value":"0",
                 "data":"0x{}deadbeef",
                 "contractMethod":{{"name":"pause","payable":false,"inputs":[]}}}}"#,
            alloy::hex::encode(&sig[..4]),
        ));
        let err = import(&json, 1, None).unwrap_err().to_string();
        assert!(err.contains("doesn't decode"), "{err}");
    }

    #[test]
    fn import_rejects_a_bundle_stamped_for_another_chain() {
        let batch = sample_batch();
        let json = export(Chain::Mainnet, None, Address::repeat_byte(0xAA), &batch);
        let err = import(&json, 1, Some(Chain::Base)).unwrap_err().to_string();
        assert!(err.contains("different address on each chain"), "{err}");
        // …and accepts it on the chain it was composed for.
        assert!(import(&json, 1, Some(Chain::Mainnet)).is_ok());
    }

    #[test]
    fn import_rejects_garbage() {
        assert!(import("not json", 1, None).is_err());
        assert!(import(r#"{"version":"1.0","chainId":"1","meta":{"name":"x","txBuilderVersion":"y"},"transactions":[]}"#, 1, None).is_err());
    }

    /// One well-formed v1 transaction, as JSON, with `version` left open so the
    /// version gate can be driven directly.
    fn one_tx_bundle(version: &str) -> String {
        format!(
            r#"{{"version":"{version}","chainId":"1",
                "meta":{{"name":"x","txBuilderVersion":"y"}},
                "transactions":[{{"to":"0x000000000000000000000000000000000000dEaD",
                                  "value":"0","data":"0x"}}]}}"#
        )
    }

    /// `version` was written and never read, so a future major would have been
    /// parsed under v1 rules — whatever it changed about how the calls are
    /// encoded — and queued as something other than what it describes.
    #[test]
    fn import_refuses_an_unknown_format_major() {
        let err = import(&one_tx_bundle("2.0"), 1, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("format version 2.0"), "{err}");
        assert!(err.contains("reads 1.x"), "{err}");
    }

    #[test]
    fn import_accepts_a_newer_minor() {
        // Additive fields deserialize away, so a differing minor is readable.
        assert!(import(&one_tx_bundle("1.7"), 1, None).is_ok());
    }

    #[test]
    fn import_refuses_a_bundle_that_names_no_version() {
        for v in ["", "banana"] {
            let err = import(&one_tx_bundle(v), 1, None).unwrap_err().to_string();
            assert!(err.contains("refusing to guess"), "for {v:?}: {err}");
        }
    }

    /// `meta` is provenance, not part of what executes. Requiring it turned
    /// every bundle from a tool that writes none into serde's "missing field
    /// `meta`", which reads as a corrupt file rather than an absent label.
    #[test]
    fn import_accepts_a_bundle_with_no_meta_block() {
        let json = r#"{"version":"1.0","chainId":"1",
            "transactions":[{"to":"0x000000000000000000000000000000000000dEaD",
                             "value":"0","data":"0x"}]}"#;
        let calls = import(json, 1, None).expect("provenance is optional");
        assert_eq!(calls.len(), 1);
    }

    /// A chain-unknown bundle stays chain-unknown when `meta` defaults, so the
    /// template wall keeps failing closed rather than assuming Mainnet.
    #[test]
    fn a_defaulted_meta_carries_no_kao_chain_id() {
        let json = r#"{"version":"1.0","chainId":"1",
            "transactions":[{"to":"0x000000000000000000000000000000000000dEaD",
                             "value":"0","data":"0x"}]}"#;
        let b: Bundle = serde_json::from_str(json).unwrap();
        assert_eq!(b.meta.kao_chain_id, None);
    }

    #[test]
    fn export_stamps_a_creation_time_and_the_format_version() {
        let json = export(Chain::Mainnet, None, Address::repeat_byte(0xAA), &[]);
        let b: Bundle = serde_json::from_str(&json).unwrap();
        assert_eq!(b.version, "1.0");
        assert!(b.created_at > 1_700_000_000, "got {}", b.created_at);
    }
}
