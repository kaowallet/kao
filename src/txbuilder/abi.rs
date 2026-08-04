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
//!    the public selectors, argument *types* and state mutability from the
//!    on-chain runtime code, and the embedded 4byte database supplies human
//!    names where it can. Never yields parameter names (positional `arg0…`),
//!    and its mutability is inferred rather than declared — but always
//!    available. When the address
//!    is an EIP-1967 / ZeppelinOS proxy, the introspected code is the
//!    implementation's (see [`from_bytecode_behind_proxy`]); a proxy stub's
//!    own code exposes almost no selectors.
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

/// How a method's *name* was established.
///
/// [`AbiSource`] says where a contract's ABI came from; this says what a single
/// method's label inside that ABI is worth. It only varies for a bytecode load,
/// where the name (4byte) and the argument types (the contract's own
/// dispatcher) come from two different places and can disagree — and where that
/// disagreement is the phishing signal [`matcher::Resolved::BytecodeMismatch`]
/// exists to raise. The review overlay already says so at signing time; this
/// carries the same fact back to the menu the method is chosen from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum MethodProvenance {
    /// The ABI declared this name: a curated entry, or a pasted JSON ABI.
    #[default]
    Declared,
    /// One 4byte signature, consistent with the bytecode — name and code agree.
    Matched,
    /// Several 4byte names remain consistent with the bytecode. The one shown
    /// is the first; the others are equally possible.
    Ambiguous { alternatives: Vec<String> },
    /// 4byte offered names and the contract's own argument types contradict
    /// every one of them. Registering a friendly signature over code that does
    /// something else is what a phishing contract looks like.
    Mismatched { claimed: Vec<String> },
    /// 4byte had nothing to offer; the name shown is the raw selector.
    SelectorOnly,
}

impl MethodProvenance {
    /// Whether an empty parameter list means "this method takes no arguments"
    /// or "nobody recovered what it takes".
    ///
    /// Only a declaration settles it. `Declared` is an ABI saying so, and
    /// `Matched`/`Ambiguous` carry 4byte's argument types for a signature that
    /// agrees with the code. The other two get their types from evmole, which
    /// returns `vec![]` both for a genuine zero-argument method and for a
    /// function whose body it could not reach — see `decode::matcher`, which
    /// documents the same conflation and refuses to treat the empty list as a
    /// spoof signal for exactly this reason.
    pub fn declares_argument_list(&self) -> bool {
        matches!(
            self,
            Self::Declared | Self::Matched | Self::Ambiguous { .. }
        )
    }

    /// A one-line caution for the composer, or `None` when there is nothing to
    /// say. Deliberately worded like `function_panel::warning_strip`, which
    /// reports the same conditions on the review — one fact, one phrasing.
    pub fn caution(&self) -> Option<String> {
        match self {
            // Recovered from the dispatcher with no 4byte name to corroborate
            // it: the parameter list is evmole's inference, and evmole gives up
            // by returning a short list rather than an error — so a plausible,
            // fillable, wrong set of fields is a reachable outcome.
            Self::SelectorOnly => Some(
                "⚠ name and parameters recovered from bytecode — the argument list may be \
                 incomplete"
                    .to_string(),
            ),
            Self::Declared | Self::Matched => None,
            Self::Ambiguous { alternatives } => {
                Some(format!("⚠ ambiguous: {}", alternatives.join(", ")))
            }
            Self::Mismatched { claimed } => Some(format!(
                "⚠ possible spoof — on-chain code matches no known signature (claimed: {})",
                claimed.join(", ")
            )),
        }
    }

    /// True for the spoof signal specifically, which the composer colours as a
    /// warning rather than a note.
    pub fn is_spoof_signal(&self) -> bool {
        matches!(self, Self::Mismatched { .. })
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
    /// wei value field only for these. For a bytecode-derived method this is
    /// evmole's inference from the dispatcher rather than a declaration, so it
    /// can be wrong in either direction — raw-hex mode remains the escape
    /// hatch when a payable call won't take a value.
    pub payable: bool,
    /// `keccak256(signature)[..4]`.
    pub selector: [u8; 4],
    /// Canonical signature, e.g. `approve(address,uint256)`.
    pub signature: String,
    /// What `name` is worth. `Declared` for every source but bytecode.
    pub provenance: MethodProvenance,
    /// What the bytecode heuristic concluded about mutability, for a method
    /// recovered from bytecode. `None` for a declared ABI — whose own
    /// `stateMutability` already decided which list it is in — and for a
    /// selector evmole declined to classify. Cosmetic: it decides how a method
    /// is sorted and labelled, never whether it can be composed.
    pub inferred_mutability: Option<bytecode::StateMutability>,
}

impl AbiMethod {
    /// The return type to ABI-decode an `eth_call` result against: a tuple of
    /// the declared outputs (a bare tuple decodes identically to head-tail ABI
    /// return data). `None` when the method declares no outputs.
    /// The parameter tuple this method's calldata body encodes, for decoding
    /// arguments back out of calldata. `None` for a no-argument method.
    pub fn input_tuple(&self) -> Option<DynSolType> {
        if self.inputs.is_empty() {
            None
        } else {
            Some(DynSolType::Tuple(
                self.inputs.iter().map(|i| i.ty.clone()).collect(),
            ))
        }
    }

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
    /// Recovered from on-chain bytecode + the 4byte database. Argument names
    /// are unknown and mutability is inferred; per-method name confidence is
    /// carried separately, on [`MethodProvenance`].
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
    /// Read-only (`view`/`pure`) functions. `outputs` is populated for a known
    /// or pasted ABI and empty for a bytecode load (evmole recovers mutability
    /// but not return types), so a bytecode read renders as raw hex and the
    /// Read tab still points at a pasted ABI for typed rows.
    pub read_methods: Vec<AbiMethod>,
    pub source: AbiSource,
    /// Brand kaomoji for known contracts; `None` otherwise.
    pub kaomoji: Option<&'static str>,
    /// Set when `address` is a proxy and these methods were recovered from the
    /// implementation behind it. Calls are still composed to `address` — the
    /// proxy is what the user transacts with; this is only the contract whose
    /// bytecode supplied the selectors.
    pub proxy_impl: Option<Address>,
    /// False when this ABI rests on a code read that fell through to unverified
    /// RPC — during a light-client cooldown, the whole method list can be
    /// authored by an untrusted endpoint. Always true for a curated or pasted
    /// ABI, neither of which reads code at all.
    pub code_verified: bool,
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
        provenance: MethodProvenance::Declared,
        inferred_mutability: None,
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
        provenance: MethodProvenance::Declared,
        inferred_mutability: None,
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
            // A curated entry carries a hand-verified ABI for the address the
            // user calls, whether or not that address happens to be a proxy
            // (USDC is) — no implementation walk was involved.
            proxy_impl: None,
            code_verified: true,
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

/// Fold bytecode-recovered methods into a curated (or pasted) ABI.
///
/// The curated registry is a hand-written subset — two to four methods per
/// entry — and a curated hit used to short-circuit the bytecode fetch entirely,
/// so the four addresses most likely to be typed into a transaction builder
/// were the four with the shortest menus. `DAI.transferFrom` exists, is
/// composable from bytecode, and was unreachable because DAI is *curated*.
///
/// `base` wins every collision: its names and parameter names are declarations,
/// while the recovered entries are inference (see
/// [`MethodProvenance::declares_argument_list`]). Recovered methods are matched
/// by **selector**, not by name — an overload the registry lists under one
/// signature must not suppress the other.
///
/// Reads merge the same way. `source` stays the base's: the contract is still
/// the curated one, now with more of its surface reachable.
pub fn merge_recovered(base: LoadedContract, recovered: LoadedContract) -> LoadedContract {
    fn fold(mut kept: Vec<AbiMethod>, extra: Vec<AbiMethod>) -> Vec<AbiMethod> {
        let known: std::collections::HashSet<[u8; 4]> = kept.iter().map(|m| m.selector).collect();
        kept.extend(extra.into_iter().filter(|m| !known.contains(&m.selector)));
        kept
    }
    LoadedContract {
        methods: fold(base.methods, recovered.methods),
        read_methods: fold(base.read_methods, recovered.read_methods),
        ..base
    }
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
                provenance: MethodProvenance::Declared,
                inferred_mutability: None,
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
                provenance: MethodProvenance::Declared,
                inferred_mutability: None,
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
        proxy_impl: None,
        // A pasted ABI is the user's own claim, not a code read.
        code_verified: true,
    })
}

// ============================================================================
// Bytecode heuristic
// ============================================================================

/// Recover a contract's methods from its runtime `code` using `evmole` (arg
/// types and state mutability) reconciled with the embedded 4byte database
/// (function names). Never yields parameter names, and its `view`/`pure` split
/// is inferred from the dispatcher rather than declared — but works on any
/// deployed contract without a pasted ABI. Returns `None` if the code exposes
/// no recoverable functions (EOA, empty account, minimal proxy).
/// A selector evmole believes only reads state.
///
/// Kept composable — the inference bails silently on a big dispatcher and
/// reports the remainder as `Pure`, so removing it from the menu would remove
/// real write methods from the one screen that exists to compose arbitrary
/// calls. It only sinks in the ordering and earns a `view` pill.
fn reads_only(m: &AbiMethod) -> bool {
    matches!(
        m.inferred_mutability,
        Some(bytecode::StateMutability::View | bytecode::StateMutability::Pure)
    )
}

pub fn from_bytecode(code: &[u8], address: Address, code_verified: bool) -> Option<LoadedContract> {
    let extracted = bytecode::extract(code);
    if extracted.is_empty() {
        return None;
    }
    let mut methods = Vec::new();
    for f in &extracted {
        // Prefer a 4byte name whose arg shape matches the bytecode; fall
        // back to a synthetic name so the selector is still composable.
        let candidates = fourbyte::lookup(f.selector);
        // The matcher separates "one name, and the code agrees" from "several
        // names" from "names the code contradicts". Taking the head of the list
        // in all three cases was the same first choice made on three different
        // strengths of evidence, with the difference discarded — so the strength
        // rides along as `provenance` and reaches the menu.
        let names = |v: &[(String, Vec<DynSolType>)]| -> Vec<String> {
            v.iter().map(|(n, _)| n.clone()).collect()
        };
        let (name, arg_types, provenance) = match matcher::resolve(&candidates, Some(&f.arg_types))
        {
            matcher::Resolved::Unique { name, arg_types } => {
                (name, arg_types, MethodProvenance::Matched)
            }
            matcher::Resolved::Ambiguous(mut v) if !v.is_empty() => {
                let alternatives = names(&v);
                let (name, arg_types) = v.remove(0);
                (
                    name,
                    arg_types,
                    MethodProvenance::Ambiguous { alternatives },
                )
            }
            matcher::Resolved::BytecodeMismatch(v) if !v.is_empty() => {
                // Every name 4byte offered is contradicted by the contract's
                // own argument types. Showing the friendliest of them as *the*
                // method name is precisely what a phishing registration buys,
                // so the menu names the selector and the claims stay inside the
                // caution — which is the choice `decode::render` already makes
                // for the review. The two used to disagree about the same bytes.
                (
                    format!("0x{}", alloy::hex::encode(f.selector)),
                    f.arg_types.clone(),
                    MethodProvenance::Mismatched { claimed: names(&v) },
                )
            }
            _ => (
                format!("0x{}", alloy::hex::encode(f.selector)),
                f.arg_types.clone(),
                MethodProvenance::SelectorOnly,
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
        let (signature, selector, name, provenance) = if selector == f.selector {
            (signature, selector, name, provenance)
        } else {
            let synth = format!("0x{}", alloy::hex::encode(f.selector));
            let (sig, _) = signature_and_selector(&synth, &inputs);
            // A discarded 4byte name takes its confidence with it — unless it
            // was discarded on purpose above, in which case the *reason* is the
            // thing worth keeping and must not be downgraded to a shrug.
            let p = match provenance {
                MethodProvenance::Mismatched { .. } => provenance,
                _ => MethodProvenance::SelectorOnly,
            };
            (sig, f.selector, synth, p)
        };
        let method = AbiMethod {
            name,
            inputs,
            outputs: Vec::new(),
            payable: matches!(f.mutability, Some(bytecode::StateMutability::Payable)),
            selector,
            signature,
            provenance,
            inferred_mutability: f.mutability,
        };
        methods.push(method);
    }
    // Writes first, then the read-only ones, each block alphabetical: the Write
    // menu opens on what can actually change state instead of interleaving a
    // contract's whole read surface through it.
    //
    // Sorted rather than *removed*, deliberately. evmole's view/pure analysis
    // starts optimistic (`view: true, pure: true`) and breaks out of its walk on
    // a VM error or an exhausted gas budget without ever clearing them — so a
    // large contract whose dispatcher it couldn't finish reports `Pure` for
    // methods that write. Dropping those from the menu would quietly make them
    // uncomposable, which is the one thing this pane exists to do.
    methods.sort_by(|a, b| reads_only(a).cmp(&reads_only(b)).then(a.name.cmp(&b.name)));
    // The same view/pure selectors, mirrored into the Read tab — which was dead
    // for a bytecode load. evmole recovers no return types, so these query and
    // render as raw hex; `read_result_panel` already says so.
    let read_methods: Vec<AbiMethod> = methods.iter().filter(|m| reads_only(m)).cloned().collect();
    Some(LoadedContract {
        address,
        name: crate::wallet::short_address(address),
        label: "recovered from bytecode".into(),
        methods,
        // evmole recovers selectors, arg types and mutability, but not return
        // types — so these reads query fine and render as raw hex rather than
        // typed rows. The Read tab still points at a pasted ABI for those.
        read_methods,
        source: AbiSource::Bytecode,
        kaomoji: None,
        proxy_impl: None,
        code_verified,
    })
}

/// Recover write methods for a proxy: the selectors come from
/// `implementation`'s runtime code, but the loaded contract stays addressed at
/// the proxy, because that's where the call has to land for the delegatecall to
/// happen. `implementation == address` (no proxy detected, or a proxy whose
/// pointer we refused to follow) degrades to plain [`from_bytecode`].
pub fn from_bytecode_behind_proxy(
    code: &[u8],
    address: Address,
    implementation: Address,
    code_verified: bool,
) -> Option<LoadedContract> {
    let mut loaded = from_bytecode(code, address, code_verified)?;
    if implementation != address {
        loaded.label = "recovered from implementation bytecode".into();
        loaded.proxy_impl = Some(implementation);
    }
    Some(loaded)
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
        assert!(from_bytecode(&[], Address::ZERO, true).is_none());
    }

    #[test]
    fn proxy_load_addresses_the_proxy_not_the_implementation() {
        let proxy = Address::from([0x11; 20]);
        let impl_addr = Address::from([0x22; 20]);
        let code = crate::decode::bytecode::tiny_transfer_runtime();
        let c =
            from_bytecode_behind_proxy(&code, proxy, impl_addr, true).expect("selectors recovered");
        // The call must land on the proxy for the delegatecall to happen —
        // composing to the implementation would bypass the proxy's storage.
        assert_eq!(c.address, proxy);
        assert_eq!(c.name, crate::wallet::short_address(proxy));
        assert_eq!(c.proxy_impl, Some(impl_addr));
        assert_eq!(c.label, "recovered from implementation bytecode");
        assert!(c.methods.iter().any(|m| m.name == "transfer"));
    }

    #[test]
    fn a_declared_abi_carries_declared_provenance() {
        let usdc = known_by_address(
            Chain::Mainnet,
            address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
        )
        .unwrap();
        for m in usdc.methods.iter().chain(&usdc.read_methods) {
            assert_eq!(m.provenance, MethodProvenance::Declared);
            assert!(m.provenance.caution().is_none());
        }
        let pasted = parse_abi_json(
            r#"[{"type":"function","name":"transfer","stateMutability":"nonpayable",
                 "inputs":[{"name":"to","type":"address"}]}]"#,
            Address::ZERO,
        )
        .unwrap();
        assert_eq!(pasted.methods[0].provenance, MethodProvenance::Declared);
    }

    #[test]
    fn a_bytecode_selector_the_4byte_db_cannot_name_is_marked_selector_only() {
        let code = crate::decode::bytecode::tiny_transfer_runtime();
        let c = from_bytecode(&code, Address::ZERO, true).unwrap();
        let m = c
            .methods
            .iter()
            .chain(&c.read_methods)
            .find(|m| m.name == "transfer")
            .unwrap();
        // 4byte knows `transfer(address,uint256)` and the bytecode agrees.
        assert_eq!(m.provenance, MethodProvenance::Matched);
        assert!(m.provenance.caution().is_none());
        assert!(!m.provenance.is_spoof_signal());
    }

    #[test]
    fn the_spoof_signal_reaches_the_composer_instead_of_being_dropped() {
        // The matcher raises `BytecodeMismatch` when 4byte's names are all
        // contradicted by the contract's own argument types. That verdict used
        // to be collapsed to `v.remove(0)`, so the menu showed the friendly
        // name with nothing to say about it.
        let spoof = MethodProvenance::Mismatched {
            claimed: vec!["transfer".into(), "approve".into()],
        };
        assert!(spoof.is_spoof_signal());
        let caution = spoof.caution().expect("a spoof must be voiced");
        assert!(caution.contains("possible spoof"), "{caution}");
        assert!(caution.contains("transfer, approve"), "{caution}");

        let ambiguous = MethodProvenance::Ambiguous {
            alternatives: vec!["transfer".into(), "doppel".into()],
        };
        assert!(
            !ambiguous.is_spoof_signal(),
            "ambiguity is not an accusation"
        );
        let caution = ambiguous.caution().unwrap();
        assert!(caution.contains("ambiguous"), "{caution}");
    }

    #[test]
    fn a_read_only_selector_is_mirrored_into_the_read_tab_but_stays_composable() {
        // The fixture is `function transfer(address,uint256) external {}` — an
        // empty body, so evmole infers `pure`.
        //
        // It must still appear in the Write menu. evmole's view/pure walk
        // starts at `view: true, pure: true` and breaks out on a VM error or an
        // exhausted gas budget WITHOUT clearing them, so "Pure" is also what a
        // dispatcher it couldn't finish reports — and dropping those would make
        // real write methods on large contracts uncomposable.
        let code = crate::decode::bytecode::tiny_transfer_runtime();
        let c = from_bytecode(&code, Address::ZERO, true).expect("selectors recovered");

        let write = c
            .methods
            .iter()
            .find(|m| m.name == "transfer")
            .expect("an inferred-pure selector stays composable");
        assert_eq!(write.selector, [0xa9, 0x05, 0x9c, 0xbb]);
        assert!(!write.payable);
        assert!(reads_only(write), "but it is known to be read-only");

        // And the Read tab, which used to be empty for every bytecode load,
        // now offers it. evmole recovers no return types, so it renders raw.
        let read = c
            .read_methods
            .iter()
            .find(|m| m.name == "transfer")
            .expect("mirrored into the read menu");
        assert!(read.output_tuple().is_none());
    }

    #[test]
    fn the_write_menu_sinks_read_only_selectors_below_the_writes() {
        // Sorting, not filtering: the composable set is unchanged, but the menu
        // opens on what can actually change state.
        let mut methods = [
            AbiMethod {
                name: "zzWrite".into(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                payable: false,
                selector: [1, 2, 3, 4],
                signature: "zzWrite()".into(),
                provenance: MethodProvenance::Matched,
                inferred_mutability: Some(bytecode::StateMutability::NonPayable),
            },
            AbiMethod {
                name: "aaRead".into(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                payable: false,
                selector: [5, 6, 7, 8],
                signature: "aaRead()".into(),
                provenance: MethodProvenance::Matched,
                inferred_mutability: Some(bytecode::StateMutability::View),
            },
        ];
        methods.sort_by(|a, b| reads_only(a).cmp(&reads_only(b)).then(a.name.cmp(&b.name)));
        assert_eq!(methods[0].name, "zzWrite", "writes first, alphabet second");
        assert_eq!(methods[1].name, "aaRead");
    }

    #[test]
    fn non_proxy_load_leaves_proxy_impl_unset() {
        let addr = Address::from([0x11; 20]);
        let code = crate::decode::bytecode::tiny_transfer_runtime();
        // implementation == address ⇒ nothing was walked; must be
        // indistinguishable from a plain `from_bytecode` load.
        let via = from_bytecode_behind_proxy(&code, addr, addr, true).unwrap();
        let plain = from_bytecode(&code, addr, true).unwrap();
        assert!(via.proxy_impl.is_none());
        assert_eq!(via.label, plain.label);
        assert_eq!(via.methods.len(), plain.methods.len());
        assert_eq!(via.read_methods.len(), plain.read_methods.len());
    }

    #[test]
    fn curated_entry_never_claims_a_proxy_walk() {
        // USDC *is* a proxy, but its curated ABI is hand-verified for the
        // address the user calls — no implementation introspection involved.
        let usdc = known_by_address(
            Chain::Mainnet,
            address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
        )
        .unwrap();
        assert!(usdc.proxy_impl.is_none());
    }
}
