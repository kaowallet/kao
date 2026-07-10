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

/// A state-mutating function the user can compose a call to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbiMethod {
    pub name: String,
    pub inputs: Vec<AbiParam>,
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

/// A contract whose write methods are available to compose against.
#[derive(Debug, Clone)]
pub struct LoadedContract {
    pub address: Address,
    /// Short name (`USDC`, or `0xA0b8…eB48` for a bytecode load).
    pub name: String,
    /// Longer descriptor (`USD Coin · proxy`), may be empty.
    pub label: String,
    pub methods: Vec<AbiMethod>,
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
        payable,
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
}

impl KnownContract {
    fn to_loaded(&self) -> LoadedContract {
        LoadedContract {
            address: self.address,
            name: self.name.to_string(),
            label: self.label.to_string(),
            methods: self.methods.clone(),
            source: AbiSource::Known,
            kaomoji: Some(self.kaomoji),
        }
    }
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
    #[serde(rename = "stateMutability")]
    state_mutability: Option<String>,
    /// Legacy (pre-`stateMutability`) ABIs carried a bare `payable` bool.
    #[serde(default)]
    payable: Option<bool>,
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

/// Parse a standard Solidity JSON ABI array into a [`LoadedContract`],
/// keeping only the state-mutating functions.
pub fn parse_abi_json(json: &str, address: Address) -> Result<LoadedContract, TxBuilderError> {
    let entries: Vec<AbiEntry> = serde_json::from_str(json.trim())
        .map_err(|e| TxBuilderError::Abi(format!("not a JSON ABI array — {e}")))?;

    let mut methods = Vec::new();
    for entry in &entries {
        if entry.kind.as_deref() != Some("function") {
            continue;
        }
        let Some(payable) = is_writable(entry.state_mutability.as_deref(), entry.payable) else {
            continue; // view / pure — skip
        };
        let Some(name) = entry.name.clone() else {
            continue;
        };
        let mut inputs = Vec::with_capacity(entry.inputs.len());
        for p in &entry.inputs {
            let ty_str = canonical_ty(p);
            let ty: DynSolType = ty_str
                .parse()
                .map_err(|e| TxBuilderError::Abi(format!("unsupported type {ty_str:?}: {e}")))?;
            inputs.push(AbiParam {
                name: p.name.clone().unwrap_or_default(),
                ty_str: ty.sol_type_name().into_owned(),
                ty,
            });
        }
        let (signature, selector) = signature_and_selector(&name, &inputs);
        methods.push(AbiMethod {
            name,
            inputs,
            payable,
            selector,
            signature,
        });
    }

    if methods.is_empty() {
        return Err(TxBuilderError::Abi(
            "no state-changing functions in this ABI".into(),
        ));
    }

    Ok(LoadedContract {
        address,
        name: crate::wallet::short_address(address),
        label: "pasted ABI".into(),
        methods,
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
    fn parse_json_abi_empty_or_readonly_errors() {
        let only_view = r#"[{"type":"function","name":"x","stateMutability":"view","inputs":[]}]"#;
        assert!(parse_abi_json(only_view, Address::ZERO).is_err());
        assert!(parse_abi_json("not json", Address::ZERO).is_err());
    }

    #[test]
    fn from_bytecode_empty_code_is_none() {
        assert!(from_bytecode(&[], Address::ZERO).is_none());
    }
}
