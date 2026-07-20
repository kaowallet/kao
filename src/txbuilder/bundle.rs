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

use super::abi::{AbiMethod, AbiParam};
use super::encode::encode_call;
use super::{DecodedArg, QueuedCall, TxBuilderError};

#[derive(Debug, Serialize, Deserialize)]
pub struct Bundle {
    pub version: String,
    #[serde(rename = "chainId")]
    pub chain_id: String,
    #[serde(default, rename = "createdAt", skip_serializing_if = "is_zero_u64")]
    pub created_at: u64,
    pub meta: Meta,
    pub transactions: Vec<BundleTx>,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Meta {
    pub name: String,
    #[serde(rename = "txBuilderVersion")]
    pub tx_builder_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe: Option<String>,
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
pub fn export(chain: Chain, safe: Option<Address>, calls: &[QueuedCall]) -> String {
    let transactions = calls.iter().map(tx_from_call).collect();
    let bundle = Bundle {
        version: "1.0".into(),
        chain_id: chain.chain_id().to_string(),
        created_at: 0,
        meta: Meta {
            name: "Kao batch".into(),
            tx_builder_version: concat!("kao-", env!("CARGO_PKG_VERSION")).into(),
            safe: safe.map(|s| s.to_string()),
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
pub fn import(json: &str, start_id: u64) -> Result<Vec<QueuedCall>, TxBuilderError> {
    let bundle: Bundle = serde_json::from_str(json.trim())
        .map_err(|e| TxBuilderError::Assembly(format!("not a batch bundle — {e}")))?;
    if bundle.transactions.is_empty() {
        return Err(TxBuilderError::Assembly(
            "bundle has no transactions".into(),
        ));
    }
    bundle
        .transactions
        .iter()
        .enumerate()
        .map(|(i, tx)| call_from_tx(tx, start_id + i as u64))
        .collect()
}

fn call_from_tx(tx: &BundleTx, id: u64) -> Result<QueuedCall, TxBuilderError> {
    let to = tx
        .to
        .trim()
        .parse::<Address>()
        .map_err(|_| TxBuilderError::Assembly(format!("bad `to` address: {}", tx.to)))?;
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
        // Contract call with metadata: rebuild the decoded view + encode
        // (or trust the literal data if it was supplied).
        (Some(cm), literal) => {
            let method = method_from_meta(cm)?;
            let values: Vec<String> = method
                .inputs
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    tx.contract_inputs_values
                        .as_ref()
                        .and_then(|m| m.get(&p.display_name(i)).or_else(|| m.get(&p.name)))
                        .unwrap_or("")
                        .to_string()
                })
                .collect();
            let data = match literal {
                Some(d) => d,
                None => encode_call(&method, &values)?,
            };
            let decoded_args = method
                .inputs
                .iter()
                .enumerate()
                .map(|(i, p)| DecodedArg {
                    name: p.display_name(i),
                    ty: p.ty_str.clone(),
                    value: values[i].clone(),
                })
                .collect();
            Ok(QueuedCall {
                id,
                to,
                value,
                data,
                title: format!("{}.{}", crate::wallet::short_address(to), cm.name),
                detail: cm
                    .inputs
                    .first()
                    .map(|inp| {
                        format!(
                            "{}: {}",
                            inp.name,
                            values.first().cloned().unwrap_or_default()
                        )
                    })
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

fn method_from_meta(cm: &ContractMethod) -> Result<AbiMethod, TxBuilderError> {
    let inputs = cm
        .inputs
        .iter()
        .map(|inp| {
            let ty: DynSolType = inp.ty.parse().map_err(|e| {
                TxBuilderError::Assembly(format!("bad param type {:?}: {e}", inp.ty))
            })?;
            Ok(AbiParam {
                name: inp.name.clone(),
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
        let json = export(Chain::Mainnet, Some(Address::repeat_byte(0x5a)), &batch);
        let back = import(&json, 1).unwrap();
        assert_eq!(back.len(), 1);
        // The exact calldata survives the round-trip.
        assert_eq!(back[0].data, batch[0].data);
        assert_eq!(back[0].to, batch[0].to);
        assert_eq!(back[0].value, batch[0].value);
        assert_eq!(back[0].signature, batch[0].signature);
        assert_eq!(back[0].id, 1);
    }

    #[test]
    fn export_shape_is_safe_compatible() {
        let batch = sample_batch();
        let json = export(Chain::Mainnet, None, &batch);
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

    #[test]
    fn import_raw_transaction_without_method() {
        let json = r#"{
            "version":"1.0","chainId":"1",
            "meta":{"name":"x","txBuilderVersion":"other"},
            "transactions":[{"to":"0x000000000000000000000000000000000000dEaD","value":"1000","data":"0xdeadbeef"}]
        }"#;
        let calls = import(json, 5).unwrap();
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
        let calls = import(json, 1).unwrap();
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

    #[test]
    fn import_rejects_garbage() {
        assert!(import("not json", 1).is_err());
        assert!(import(r#"{"version":"1.0","chainId":"1","meta":{"name":"x","txBuilderVersion":"y"},"transactions":[]}"#, 1).is_err());
    }
}
