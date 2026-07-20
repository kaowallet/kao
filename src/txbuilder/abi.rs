//! ABI model for the Transaction Builder's composer: what "write methods"
//! a contract exposes, and how each was discovered.
//!
//! Three loading tiers, in descending fidelity (v1 — no block-explorer
//! fetch):
//!
//! 1. **Known contracts** — a small curated registry of common Mainnet
//!    contracts with hand-verified method signatures and (importantly)
//!    parameter *names*. Selected via the quick-picker.
//! 2. **Pasted JSON ABI** — the user pastes a standard Solidity ABI array;
//!    we keep the state-mutating functions and parse each param type.
//!    Full param names, no network dependency.
//! 3. **Bytecode heuristic** — for any other address, `evmole` recovers
//!    the public selectors and argument *types* from the on-chain runtime
//!    code, and the embedded 4byte database supplies human names where it
//!    can. Never yields parameter names (positional `arg0…`), and can't
//!    tell payable from non-payable — but always available.
//!
//! All three converge on [`LoadedContract`] → `Vec<AbiMethod>`, which the
//! composer renders identically.

use std::sync::OnceLock;

use alloy::dyn_abi::DynSolType;
use alloy::primitives::{Address, address, keccak256};
use serde::Deserialize;

use crate::chain::Chain;
use crate::decode::{bytecode, fourbyte, matcher};

use super::TxBuilderError;

/// One argument of a write method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbiParam {
    /// Solidity parameter name. Empty (`arg0`-style handled by callers)
    /// when the source couldn't recover a name (bytecode heuristic).
    pub name: String,
    /// The parsed dynamic type — used to validate + coerce user input.
    pub ty: DynSolType,
    /// Canonical Solidity type string (`uint256`, `(address,uint256)[]`),
    /// used both for display and for computing the function selector.
    pub ty_str: String,
}

impl AbiParam {
    /// Best display name: the ABI name, or a positional fallback.
    pub fn display_name(&self, index: usize) -> String {
        if self.name.is_empty() {
            format!("arg{index}")
        } else {
            self.name.clone()
        }
    }
}

/// A contract function the user can compose a call to. Covers both
/// state-mutating (write) and `view`/`pure` (read) functions — the composer
/// keeps the two in separate lists on [`LoadedContract`], but the shape is
/// identical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbiMethod {
    pub name: String,
    pub inputs: Vec<AbiParam>,
    /// Return values, in declared order. Populated for read (`view`/`pure`)
    /// methods so an `eth_call` result can be ABI-decoded and shown typed;
    /// empty for write methods (their return, if any, is never surfaced) and
    /// for bytecode-recovered methods (evmole doesn't recover outputs).
    pub outputs: Vec<AbiParam>,
    /// True iff the method accepts ETH (`payable`). The composer shows a
    /// wei value field only for these. Always `false` for bytecode-derived
    /// methods (evmole doesn't recover mutability) — use raw-hex mode for
    /// a payable call on an unverified contract.
    pub payable: bool,
    /// `keccak256(signature)[..4]`.
    pub selector: [u8; 4],
    /// Canonical signature, e.g. `approve(address,uint256)`.
    pub signature: String,
}

impl AbiMethod {
    /// The return type to ABI-decode an `eth_call` result against: a tuple of
    /// the declared outputs (a bare tuple decodes identically to head-tail ABI
    /// return data). `None` when the method declares no outputs.
    pub fn output_tuple(&self) -> Option<DynSolType> {
        if self.outputs.is_empty() {
            None
        } else {
            Some(DynSolType::Tuple(
                self.outputs.iter().map(|o| o.ty.clone()).collect(),
            ))
        }
    }
}

/// How a contract's ABI was obtained — drives the verification badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiSource {
    /// Curated, hand-verified registry entry.
    Known,
    /// User-pasted standard JSON ABI.
    Pasted,
    /// Recovered from on-chain bytecode + the 4byte database. Argument
    /// names are unknown; mutability is assumed non-payable.
    Bytecode,
}

/// A contract whose functions are available to compose against. `methods`
/// holds the state-changing (write) functions; `read_methods` holds the
/// `view`/`pure` functions the Read tab queries via `eth_call`.
#[derive(Debug, Clone)]
pub struct LoadedContract {
    pub address: Address,
    /// Short name (`USDC`, or `0xA0b8…eB48` for a bytecode load).
    pub name: String,
    /// Longer descriptor (`USD Coin · proxy`), may be empty.
    pub label: String,
    pub methods: Vec<AbiMethod>,
    /// Read-only (`view`/`pure`) functions, with decodable `outputs`. Empty for
    /// a bytecode load (evmole can't recover outputs); the Read tab then prompts
    /// for a pasted ABI.
    pub read_methods: Vec<AbiMethod>,
    pub source: AbiSource,
    /// Brand kaomoji for known contracts; `None` otherwise.
    pub kaomoji: Option<&'static str>,
}

// ============================================================================
// Selector / signature helpers
// ============================================================================

/// Build the canonical signature `name(t1,t2,…)` and its 4-byte selector
/// from a name and parameter types.
fn signature_and_selector(name: &str, inputs: &[AbiParam]) -> (String, [u8; 4]) {
    let mut sig = String::with_capacity(name.len() + 2);
    sig.push_str(name);
    sig.push('(');
    for (i, p) in inputs.iter().enumerate() {
        if i > 0 {
            sig.push(',');
        }
        sig.push_str(&p.ty_str);
    }
    sig.push(')');
    let hash = keccak256(sig.as_bytes());
    let mut sel = [0u8; 4];
    sel.copy_from_slice(&hash[..4]);
    (sig, sel)
}

/// Construct an [`AbiMethod`] from a name, `payable` flag, and a list of
/// `(param_name, type_string)` pairs. Panics on an unparseable type — used
/// only for the compile-time known-contract table, where a bad type is a
/// programming error caught by [`tests::known_contracts_all_build`].
fn method(name: &str, payable: bool, params: &[(&str, &str)]) -> AbiMethod {
    let inputs: Vec<AbiParam> = params
        .iter()
        .map(|(pname, ty)| {
            let parsed: DynSolType = ty
                .parse()
                .unwrap_or_else(|e| panic!("known-contract type {ty:?} must parse: {e}"));
            AbiParam {
                name: (*pname).to_string(),
                ty_str: parsed.sol_type_name().into_owned(),
                ty: parsed,
                // (ty_str is derived from the parsed type, not the input
                // string, so it's always canonical — matches the selector.)
            }
        })
        .collect();
    let (signature, selector) = signature_and_selector(name, &inputs);
    AbiMethod {
        name: name.to_string(),
        inputs,
        outputs: Vec::new(),
        payable,
        selector,
        signature,
    }
}

/// Construct a read-only [`AbiMethod`] (`view`/`pure`) from a name, a list of
/// `(param_name, type_string)` inputs, and a list of `(name, type_string)`
/// outputs. Output names are cosmetic (shown beside the decoded value) and may
/// be empty. Panics on an unparseable type — compile-time registry only.
fn read_method(name: &str, params: &[(&str, &str)], outputs: &[(&str, &str)]) -> AbiMethod {
    let parse = |ty: &str| -> DynSolType {
        ty.parse()
            .unwrap_or_else(|e| panic!("known-contract type {ty:?} must parse: {e}"))
    };
    let inputs: Vec<AbiParam> = params
        .iter()
        .map(|(pname, ty)| {
            let parsed = parse(ty);
            AbiParam {
                name: (*pname).to_string(),
                ty_str: parsed.sol_type_name().into_owned(),
                ty: parsed,
            }
        })
        .collect();
    let outputs: Vec<AbiParam> = outputs
        .iter()
        .map(|(oname, ty)| {
            let parsed = parse(ty);
            AbiParam {
                name: (*oname).to_string(),
                ty_str: parsed.sol_type_name().into_owned(),
                ty: parsed,
            }
        })
        .collect();
    // Read methods are always non-payable; the selector hashes over inputs only.
    let (signature, selector) = signature_and_selector(name, &inputs);
    AbiMethod {
        name: name.to_string(),
        inputs,
        outputs,
        payable: false,
        selector,
        signature,
    }
}

// ============================================================================
// Known-contract registry (Mainnet)
// ============================================================================

/// A curated known contract. Mainnet-only for v1 — the quick-picker
/// filters by the active chain, so these never surface on an L2 where the
/// address may be a different (or absent) contract.
#[derive(Debug, Clone)]
pub struct KnownContract {
    pub chain: Chain,
    pub address: Address,
    pub name: &'static str,
    pub label: &'static str,
    pub kaomoji: &'static str,
    pub methods: Vec<AbiMethod>,
    /// Curated read-only functions surfaced in the Read tab. May be empty.
    pub read_methods: Vec<AbiMethod>,
}

impl KnownContract {
    fn to_loaded(&self) -> LoadedContract {
        LoadedContract {
            address: self.address,
            name: self.name.to_string(),
            label: self.label.to_string(),
            methods: self.methods.clone(),
            read_methods: self.read_methods.clone(),
            source: AbiSource::Known,
            kaomoji: Some(self.kaomoji),
        }
    }
}

/// The standard ERC-20 read surface, shared by every token in the registry.
/// Selectors are derived from the canonical signatures, so these match any
/// compliant token (`balanceOf`, `allowance`, `totalSupply`, metadata).
fn erc20_reads() -> Vec<AbiMethod> {
    vec![
        read_method(
            "balanceOf",
            &[("account", "address")],
            &[("balance", "uint256")],
        ),
        read_method(
            "allowance",
            &[("owner", "address"), ("spender", "address")],
            &[("remaining", "uint256")],
        ),
        read_method("totalSupply", &[], &[("supply", "uint256")]),
        read_method("decimals", &[], &[("decimals", "uint8")]),
        read_method("symbol", &[], &[("symbol", "string")]),
        read_method("name", &[], &[("name", "string")]),
    ]
}

fn build_known() -> Vec<KnownContract> {
    vec![
        KnownContract {
            chain: Chain::Mainnet,
            address: address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
            name: "USDC",
            label: "USD Coin · proxy",
            kaomoji: "(ᵔᴥᵔ)",
            methods: vec![
                method(
                    "transfer",
                    false,
                    &[("to", "address"), ("amount", "uint256")],
                ),
                method(
                    "approve",
                    false,
                    &[("spender", "address"), ("amount", "uint256")],
                ),
                method(
                    "transferFrom",
                    false,
                    &[
                        ("from", "address"),
                        ("to", "address"),
                        ("amount", "uint256"),
                    ],
                ),
            ],
            read_methods: erc20_reads(),
        },
        KnownContract {
            chain: Chain::Mainnet,
            address: address!("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"),
            name: "Aave v3 Pool",
            label: "Lending pool",
            kaomoji: "(๑˃ᴗ˂)ﻭ",
            methods: vec![
                method(
                    "supply",
                    false,
                    &[
                        ("asset", "address"),
                        ("amount", "uint256"),
                        ("onBehalfOf", "address"),
                        ("referralCode", "uint16"),
                    ],
                ),
                method(
                    "withdraw",
                    false,
                    &[
                        ("asset", "address"),
                        ("amount", "uint256"),
                        ("to", "address"),
                    ],
                ),
                method(
                    "borrow",
                    false,
                    &[
                        ("asset", "address"),
                        ("amount", "uint256"),
                        ("interestRateMode", "uint256"),
                        ("referralCode", "uint16"),
                        ("onBehalfOf", "address"),
                    ],
                ),
                method(
                    "repay",
                    false,
                    &[
                        ("asset", "address"),
                        ("amount", "uint256"),
                        ("interestRateMode", "uint256"),
                        ("onBehalfOf", "address"),
                    ],
                ),
            ],
            read_methods: vec![
                read_method(
                    "getReserveNormalizedIncome",
                    &[("asset", "address")],
                    &[("normalizedIncome", "uint256")],
                ),
                read_method(
                    "getReserveNormalizedVariableDebt",
                    &[("asset", "address")],
                    &[("normalizedDebt", "uint256")],
                ),
            ],
        },
        KnownContract {
            chain: Chain::Mainnet,
            address: address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
            name: "WETH9",
            label: "Wrapped Ether",
            kaomoji: "ヽ(・∀・)ﾉ",
            methods: vec![
                method("deposit", true, &[]),
                method("withdraw", false, &[("wad", "uint256")]),
                method(
                    "transfer",
                    false,
                    &[("to", "address"), ("amount", "uint256")],
                ),
                method(
                    "approve",
                    false,
                    &[("spender", "address"), ("amount", "uint256")],
                ),
            ],
            read_methods: erc20_reads(),
        },
        KnownContract {
            chain: Chain::Mainnet,
            address: address!("0x6B175474E89094C44Da98b954EedeAC495271d0F"),
            name: "DAI",
            label: "Dai Stablecoin",
            kaomoji: "(・ω・)",
            methods: vec![
                method(
                    "transfer",
                    false,
                    &[("to", "address"), ("amount", "uint256")],
                ),
                method(
                    "approve",
                    false,
                    &[("spender", "address"), ("amount", "uint256")],
                ),
            ],
            read_methods: erc20_reads(),
        },
    ]
}

/// The curated registry, built once.
pub fn known_contracts() -> &'static [KnownContract] {
    static KNOWN: OnceLock<Vec<KnownContract>> = OnceLock::new();
    KNOWN.get_or_init(build_known)
}

/// The known contracts available on `chain`, in registry order. Test-only:
/// the composer resolves known contracts by address (`known_by_address`) now
/// that the quick-pick chips are gone, so this only backs the registry tests.
#[cfg(test)]
pub fn known_for_chain(chain: Chain) -> Vec<&'static KnownContract> {
    known_contracts()
        .iter()
        .filter(|k| k.chain == chain)
        .collect()
}

/// Look up a curated contract by address (case-insensitive) on `chain`.
pub fn known_by_address(chain: Chain, addr: Address) -> Option<LoadedContract> {
    known_contracts()
        .iter()
        .find(|k| k.chain == chain && k.address == addr)
        .map(KnownContract::to_loaded)
}

// ============================================================================
// Pasted JSON ABI
// ============================================================================

#[derive(Debug, Deserialize)]
struct AbiEntry {
    #[serde(rename = "type")]
    kind: Option<String>,
    name: Option<String>,
    #[serde(default)]
    inputs: Vec<AbiJsonParam>,
    #[serde(default)]
    outputs: Vec<AbiJsonParam>,
    #[serde(rename = "stateMutability")]
    state_mutability: Option<String>,
    /// Legacy (pre-`stateMutability`) ABIs carried a bare `payable` bool.
    #[serde(default)]
    payable: Option<bool>,
    /// Legacy (pre-`stateMutability`) read-only marker. `constant: true` ⇒ a
    /// `view`-equivalent function.
    #[serde(default)]
    constant: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct AbiJsonParam {
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "type")]
    ty: String,
    #[serde(default)]
    components: Vec<AbiJsonParam>,
}

/// Assemble a param's canonical Solidity type string, expanding `tuple`
/// (and `tuple[]`/`tuple[N]`) from its `components` so `DynSolType` can
/// parse it.
fn canonical_ty(p: &AbiJsonParam) -> String {
    if let Some(suffix) = p.ty.strip_prefix("tuple") {
        let inner: Vec<String> = p.components.iter().map(canonical_ty).collect();
        format!("({}){suffix}", inner.join(","))
    } else {
        p.ty.clone()
    }
}

/// True for the two writable state mutabilities. `view`/`pure` are hidden —
/// the builder only sends state-changing calls. A missing mutability (very
/// old ABIs) falls back to the legacy `payable` bool via the caller.
fn is_writable(state_mutability: Option<&str>, payable: Option<bool>) -> Option<bool> {
    match state_mutability {
        Some("nonpayable") => Some(false),
        Some("payable") => Some(true),
        Some("view") | Some("pure") => None,
        Some(_) => None,
        // Legacy ABI without stateMutability: `constant` functions are
        // read-only; we only see `payable` here. A function with neither
        // is treated as writable-nonpayable.
        None => Some(payable.unwrap_or(false)),
    }
}

/// Parse a list of JSON ABI params into typed [`AbiParam`]s, expanding tuples.
fn params_from_json(list: &[AbiJsonParam]) -> Result<Vec<AbiParam>, TxBuilderError> {
    let mut out = Vec::with_capacity(list.len());
    for p in list {
        let ty_str = canonical_ty(p);
        let ty: DynSolType = ty_str
            .parse()
            .map_err(|e| TxBuilderError::Abi(format!("unsupported type {ty_str:?}: {e}")))?;
        out.push(AbiParam {
            name: p.name.clone().unwrap_or_default(),
            ty_str: ty.sol_type_name().into_owned(),
            ty,
        });
    }
    Ok(out)
}

/// Parse a standard Solidity JSON ABI array into a [`LoadedContract`],
/// splitting state-mutating functions (`methods`) from `view`/`pure` reads
/// (`read_methods`, which carry decodable `outputs`).
pub fn parse_abi_json(json: &str, address: Address) -> Result<LoadedContract, TxBuilderError> {
    let entries: Vec<AbiEntry> = serde_json::from_str(json.trim())
        .map_err(|e| TxBuilderError::Abi(format!("not a JSON ABI array — {e}")))?;

    let mut methods = Vec::new();
    let mut read_methods = Vec::new();
    for entry in &entries {
        if entry.kind.as_deref() != Some("function") {
            continue;
        }
        let Some(name) = entry.name.clone() else {
            continue;
        };
        let inputs = params_from_json(&entry.inputs)?;
        let (signature, selector) = signature_and_selector(&name, &inputs);
        let is_read = matches!(
            entry.state_mutability.as_deref(),
            Some("view") | Some("pure")
        ) || (entry.state_mutability.is_none() && entry.constant == Some(true));
        if is_read {
            let outputs = params_from_json(&entry.outputs)?;
            read_methods.push(AbiMethod {
                name,
                inputs,
                outputs,
                payable: false,
                selector,
                signature,
            });
        } else if let Some(payable) = is_writable(entry.state_mutability.as_deref(), entry.payable)
        {
            methods.push(AbiMethod {
                name,
                inputs,
                outputs: Vec::new(),
                payable,
                selector,
                signature,
            });
        }
    }

    if methods.is_empty() && read_methods.is_empty() {
        return Err(TxBuilderError::Abi("no functions in this ABI".into()));
    }

    Ok(LoadedContract {
        address,
        name: crate::wallet::short_address(address),
        label: "pasted ABI".into(),
        methods,
        read_methods,
        source: AbiSource::Pasted,
        kaomoji: None,
    })
}

// ============================================================================
// Bytecode heuristic
// ============================================================================

/// Recover a contract's write methods from its runtime `code` using
/// `evmole` (arg types) reconciled with the embedded 4byte database
/// (function names). Never yields parameter names or `payable` info, and
/// includes read-only functions the 4byte DB can't distinguish — but works
/// on any deployed contract without a pasted ABI. Returns `None` if the
/// code exposes no recoverable functions (EOA, empty account, minimal
/// proxy).
pub fn from_bytecode(code: &[u8], address: Address) -> Option<LoadedContract> {
    let extracted = bytecode::extract(code);
    if extracted.is_empty() {
        return None;
    }
    let mut methods = Vec::new();
    for f in &extracted {
        // Prefer a 4byte name whose arg shape matches the bytecode; fall
        // back to a synthetic name so the selector is still composable.
        let candidates = fourbyte::lookup(f.selector);
        let (name, arg_types) = match matcher::resolve(&candidates, Some(&f.arg_types)) {
            matcher::Resolved::Unique { name, arg_types } => (name, arg_types),
            matcher::Resolved::Ambiguous(mut v) | matcher::Resolved::BytecodeMismatch(mut v)
                if !v.is_empty() =>
            {
                let (name, arg_types) = v.remove(0);
                (name, arg_types)
            }
            _ => (
                format!("0x{}", alloy::hex::encode(f.selector)),
                f.arg_types.clone(),
            ),
        };
        let inputs: Vec<AbiParam> = arg_types
            .iter()
            .map(|ty| AbiParam {
                name: String::new(),
                ty_str: ty.sol_type_name().into_owned(),
                ty: ty.clone(),
            })
            .collect();
        // Recompute the selector from the resolved name+types and keep the
        // method only when it matches the on-chain selector — a 4byte name
        // whose canonical form doesn't hash back to this selector would be
        // a mislabel, so we fall back to the raw selector name instead.
        let (signature, selector) = signature_and_selector(&name, &inputs);
        let (signature, selector, name) = if selector == f.selector {
            (signature, selector, name)
        } else {
            let synth = format!("0x{}", alloy::hex::encode(f.selector));
            let (sig, _) = signature_and_selector(&synth, &inputs);
            (sig, f.selector, synth)
        };
        methods.push(AbiMethod {
            name,
            inputs,
            outputs: Vec::new(),
            payable: false,
            selector,
            signature,
        });
    }
    methods.sort_by(|a, b| a.name.cmp(&b.name));
    Some(LoadedContract {
        address,
        name: crate::wallet::short_address(address),
        label: "recovered from bytecode".into(),
        methods,
        // evmole recovers selectors + arg types but not return types, so a
        // bytecode load exposes no decodable reads — the Read tab prompts for
        // a pasted ABI instead.
        read_methods: Vec::new(),
        source: AbiSource::Bytecode,
        kaomoji: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_contracts_all_build() {
        // Exercises `method()`'s type parsing for every curated entry —
        // a bad type string panics here rather than at runtime.
        let known = known_contracts();
        assert_eq!(known.len(), 4);
        for k in known {
            assert!(!k.methods.is_empty(), "{} has no methods", k.name);
            for m in &k.methods {
                // signature/selector are self-consistent
                let (sig, sel) = signature_and_selector(&m.name, &m.inputs);
                assert_eq!(sig, m.signature);
                assert_eq!(sel, m.selector);
            }
        }
    }

    #[test]
    fn usdc_transfer_selector_is_canonical() {
        let usdc = known_by_address(
            Chain::Mainnet,
            address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
        )
        .expect("USDC known");
        let transfer = usdc.methods.iter().find(|m| m.name == "transfer").unwrap();
        // keccak256("transfer(address,uint256)")[..4] == 0xa9059cbb
        assert_eq!(transfer.selector, [0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(transfer.signature, "transfer(address,uint256)");
    }

    #[test]
    fn approve_selector_matches_erc20() {
        let dai = known_by_address(
            Chain::Mainnet,
            address!("0x6B175474E89094C44Da98b954EedeAC495271d0F"),
        )
        .unwrap();
        let approve = dai.methods.iter().find(|m| m.name == "approve").unwrap();
        // keccak256("approve(address,uint256)")[..4] == 0x095ea7b3
        assert_eq!(approve.selector, [0x09, 0x5e, 0xa7, 0xb3]);
    }

    #[test]
    fn weth_deposit_is_payable_no_args() {
        let weth = known_by_address(
            Chain::Mainnet,
            address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
        )
        .unwrap();
        let deposit = weth.methods.iter().find(|m| m.name == "deposit").unwrap();
        assert!(deposit.payable);
        assert!(deposit.inputs.is_empty());
        assert_eq!(deposit.selector, [0xd0, 0xe3, 0x0d, 0xb0]);
    }

    #[test]
    fn known_filtered_by_chain() {
        assert_eq!(known_for_chain(Chain::Mainnet).len(), 4);
        assert!(known_for_chain(Chain::Base).is_empty());
        assert!(known_for_chain(Chain::Optimism).is_empty());
    }

    #[test]
    fn parse_json_abi_keeps_only_writable_functions() {
        let json = r#"[
            {"type":"function","name":"transfer","stateMutability":"nonpayable",
             "inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],
             "outputs":[{"type":"bool"}]},
            {"type":"function","name":"balanceOf","stateMutability":"view",
             "inputs":[{"name":"who","type":"address"}],"outputs":[{"type":"uint256"}]},
            {"type":"function","name":"deposit","stateMutability":"payable","inputs":[]},
            {"type":"event","name":"Transfer","inputs":[]}
        ]"#;
        let c = parse_abi_json(json, Address::ZERO).unwrap();
        let names: Vec<_> = c.methods.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"transfer"));
        assert!(names.contains(&"deposit"));
        assert!(!names.contains(&"balanceOf"), "view fn must be dropped");
        let transfer = c.methods.iter().find(|m| m.name == "transfer").unwrap();
        assert_eq!(transfer.selector, [0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(transfer.inputs[0].name, "to");
        assert!(matches!(c.source, AbiSource::Pasted));
    }

    #[test]
    fn parse_json_abi_handles_tuple_components() {
        // A function taking a struct: exactInputSingle((address,address,uint24))
        let json = r#"[
            {"type":"function","name":"exactInputSingle","stateMutability":"payable",
             "inputs":[{"name":"params","type":"tuple","components":[
                {"name":"tokenIn","type":"address"},
                {"name":"tokenOut","type":"address"},
                {"name":"fee","type":"uint24"}
             ]}]}
        ]"#;
        let c = parse_abi_json(json, Address::ZERO).unwrap();
        let m = &c.methods[0];
        assert_eq!(m.signature, "exactInputSingle((address,address,uint24))");
        assert!(m.payable);
    }

    #[test]
    fn parse_json_abi_view_loads_as_read_method() {
        // A view-only ABI is now valid — it loads with a read method (no writes),
        // and the return type is parsed for decoding.
        let only_view = r#"[{"type":"function","name":"balanceOf","stateMutability":"view",
            "inputs":[{"name":"who","type":"address"}],"outputs":[{"name":"bal","type":"uint256"}]}]"#;
        let c = parse_abi_json(only_view, Address::ZERO).unwrap();
        assert!(c.methods.is_empty());
        assert_eq!(c.read_methods.len(), 1);
        let m = &c.read_methods[0];
        assert_eq!(m.name, "balanceOf");
        assert_eq!(m.selector, [0x70, 0xa0, 0x82, 0x31]);
        assert_eq!(m.outputs.len(), 1);
        assert_eq!(m.outputs[0].ty_str, "uint256");
    }

    #[test]
    fn parse_json_abi_empty_or_garbage_errors() {
        let no_fns = r#"[{"type":"event","name":"Transfer","inputs":[]}]"#;
        assert!(parse_abi_json(no_fns, Address::ZERO).is_err());
        assert!(parse_abi_json("not json", Address::ZERO).is_err());
    }

    #[test]
    fn known_erc20_reads_have_canonical_selectors() {
        let usdc = known_by_address(
            Chain::Mainnet,
            address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
        )
        .unwrap();
        let bal = usdc
            .read_methods
            .iter()
            .find(|m| m.name == "balanceOf")
            .unwrap();
        // keccak256("balanceOf(address)")[..4] == 0x70a08231
        assert_eq!(bal.selector, [0x70, 0xa0, 0x82, 0x31]);
        assert!(bal.output_tuple().is_some());
    }

    #[test]
    fn from_bytecode_empty_code_is_none() {
        assert!(from_bytecode(&[], Address::ZERO).is_none());
    }
}
