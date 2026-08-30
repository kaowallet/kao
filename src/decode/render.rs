//! Argument decoding + humanization. End-to-end pipeline:
//!
//! ```text
//! (chain, to, calldata)
//!     │
//!     ├─ proxy::resolve_implementation  → impl address (verified)
//!     ├─ net.get_code(impl)             → bytecode (verified)
//!     ├─ bytecode::extract              → selector → arg-type list
//!     ├─ fourbyte::lookup(selector)     → human signatures (snapshot)
//!     ├─ matcher::resolve               → Resolved::{Unique|Ambiguous|TypesOnly|Unknown}
//!     ├─ alloy::dyn_abi::abi_decode     → DynSolValue per arg
//!     └─ humanize:
//!          • addresses    → reverse ENS (Mainnet only)
//!          • amount + ERC-20 target → "1.234 USDC"
//!          • approve(_, MAX) → InfiniteApproval warning
//! ```
//!
//! Sync `decode_args` is the pure abi-decode step (callable from
//! tests with no RPC). Async `decode_call` is the full pipeline; the
//! Phase 7 dashboard kicks it off via `Task::perform`.

use alloy::dyn_abi::{DynSolType, DynSolValue};
use alloy::primitives::utils::format_units;
use alloy::primitives::{Address, B256, Bytes, I256, U256};

use crate::chain::Chain;
use crate::decode::{bytecode, fourbyte, matcher, proxy};
use crate::net::BalanceFetcher;
use crate::sanitize;

/// `symbol()` selector — first 4 bytes of `keccak256("symbol()")`.
const SYMBOL_SELECTOR: [u8; 4] = [0x95, 0xd8, 0x9b, 0x41];
/// `decimals()` selector.
const DECIMALS_SELECTOR: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];

/// Top-level decode result. Contains everything the FunctionPanel needs
/// to render a review row, plus a few fields (the call target, raw
/// arg ints) the v1 panel doesn't display but downstream consumers
/// (a WalletConnect request modal, future analyzers) will.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DecodedCall {
    pub to: Address,
    pub selector: [u8; 4],
    pub raw_calldata: Bytes,
    /// Function name when 4byte resolved; `None` for `TypesOnly` /
    /// `Unknown` / `Empty`.
    pub function_name: Option<String>,
    pub args: Vec<DecodedArg>,
    pub state: ResolutionState,
    pub warnings: Vec<Warning>,
    /// Chain of intermediate proxy addresses, in order. Empty when the
    /// call lands on a non-proxy contract.
    pub proxy_hops: Vec<Address>,
    /// All on-chain reads in this decode (storage slots + bytecode)
    /// went through Helios's verified path. False if any fell back —
    /// downstream UI should warn.
    pub all_verified: bool,
    /// Symbol/decimals of `to`, if it answers the standard probes.
    /// Drives "1.234 USDC" amount formatting.
    pub target_token: Option<TokenInfo>,
    /// Whether `target_token` came from a *verified* read. False when the
    /// symbol/decimals probe fell back to unverified RPC — the label is
    /// then attacker-influenceable, so amount formatting marks it.
    pub target_token_verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionState {
    /// Decoded with name + types from 4byte. Function name and per-arg
    /// types are accurate; values are valid abi-decoded.
    Resolved,
    /// Decoded with types-only — bytecode said "selector takes (X, Y)"
    /// but 4byte has no name registered. `function_name` is `None`.
    TypesOnly,
    /// Multiple 4byte signatures match this selector and bytecode
    /// couldn't narrow it down. We pick the first; UI surfaces the
    /// `AmbiguousSignature` warning so the user can review the raw
    /// calldata before signing.
    Ambiguous,
    /// No bytecode and no 4byte. Show selector + raw calldata.
    Unknown,
    /// Native ETH transfer — no calldata to decode.
    Empty,
}

#[derive(Debug, Clone)]
pub struct DecodedArg {
    /// The 4byte signature is just `transfer(address,uint256)`, no
    /// argument names; populated only when bytecode introspection
    /// names them (rare today; placeholder for future evmole versions).
    pub name: Option<String>,
    pub ty: DynSolType,
    pub display: ArgDisplay,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ArgDisplay {
    /// Address; `ens` populated when the chain is Mainnet and reverse
    /// resolution succeeded (forward-verified by `crate::names::lookup_address`,
    /// across ENS / GNS / WNS).
    Address {
        addr: Address,
        ens: Option<String>,
    },
    /// Unsigned integer. `formatted` is the decimal-aware display
    /// string when the call target is an ERC-20 and this arg is
    /// reasonably an "amount"; otherwise the raw decimal U256.
    Uint {
        raw: U256,
        formatted: String,
    },
    Int {
        raw: I256,
        formatted: String,
    },
    Bool(bool),
    String(String),
    /// Hex-encoded; truncated for display in the UI layer.
    Bytes(Bytes),
    /// Catch-all canonical-string render for tuple / array / fixed-bytes /
    /// other types we don't yet have a specialized renderer for.
    Raw(String),
}

#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub symbol: String,
    pub decimals: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// `approve(spender, type(uint256).max)` — unbounded allowance.
    InfiniteApproval { spender: Address, token: Address },
    /// At least one storage / bytecode read fell back to raw RPC.
    UnverifiedBytecode,
    /// 4byte returned multiple candidates and bytecode types couldn't
    /// narrow. UI lists candidates; signing this is "trust me bro".
    AmbiguousSignature { candidates: Vec<String> },
    /// 4byte offered candidate name(s) but the on-chain bytecode's arg
    /// types match none of them — the suggested name is contradicted by
    /// what the contract actually implements. A possible spoof; the UI
    /// flags it louder than plain ambiguity. Carries the rejected names.
    BytecodeMismatch { candidates: Vec<String> },
    /// The arguments on screen do not account for every byte of the calldata.
    ///
    /// Alloy's decoder is non-consuming: it reads the arguments it was asked
    /// for and ignores whatever follows. So a call can render a clean, complete
    /// argument list and still carry bytes that reach the contract — an
    /// ERC-2771 forwarder takes the spoofed sender from exactly this tail. The
    /// decoded view is the whole basis on which a call is vetted, so bytes it
    /// cannot explain have to be said out loud rather than dropped.
    ///
    /// Carries the length the decoded arguments account for and the total
    /// calldata body (both excluding the 4-byte selector).
    UnaccountedCalldata { decoded: usize, total: usize },
}

// ---------------------------------------------------------------------------
// Top-level pipeline

pub async fn decode_call(
    net: &dyn BalanceFetcher,
    chain: Chain,
    to: Address,
    calldata: Bytes,
) -> DecodedCall {
    let mut out = DecodedCall {
        to,
        selector: [0; 4],
        raw_calldata: calldata.clone(),
        function_name: None,
        args: Vec::new(),
        state: ResolutionState::Empty,
        warnings: Vec::new(),
        proxy_hops: Vec::new(),
        all_verified: true,
        target_token: None,
        target_token_verified: true,
    };

    if calldata.is_empty() {
        return out;
    }
    if calldata.len() < 4 {
        out.state = ResolutionState::Unknown;
        return out;
    }
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&calldata[..4]);
    out.selector = selector;
    out.state = ResolutionState::Unknown;

    // Phase 3: walk the proxy chain rooted at `to`.
    let resolved = proxy::resolve_implementation(net, chain, to).await;
    out.proxy_hops = resolved.hops.clone();
    if !resolved.all_verified {
        out.all_verified = false;
    }

    // Phase 1+4: fetch verified bytecode for the implementation, run evmole.
    let code = match net.get_code(resolved.implementation, chain).await {
        Ok(read) => {
            if !read.verified {
                out.all_verified = false;
            }
            read.value
        }
        Err(_) => Bytes::new(),
    };
    let bytecode_types = if code.is_empty() {
        None
    } else {
        bytecode::lookup(&code, selector)
    };

    // Phase 2+5: 4byte lookup (compile-time snapshot), signature matcher.
    let candidates = fourbyte::lookup(selector);
    let resolved_sig = matcher::resolve(&candidates, bytecode_types.as_deref());

    // Decide arg-type list and function name from the matcher result.
    let (function_name, arg_types, state) = match resolved_sig {
        matcher::Resolved::Unique { name, arg_types } => {
            (Some(name), arg_types, ResolutionState::Resolved)
        }
        matcher::Resolved::TypesOnly(types) => (None, types, ResolutionState::TypesOnly),
        matcher::Resolved::Ambiguous(list) => {
            // Pick the first parsed candidate as our best guess; flag
            // the rest in the warning so the UI can show alternatives.
            let mut iter = list.into_iter();
            let chosen = iter.next();
            let rest: Vec<String> = iter.map(|(n, _)| n).collect();
            let mut all_names: Vec<String> = chosen.iter().map(|(n, _)| n.clone()).collect();
            all_names.extend(rest);
            out.warnings.push(Warning::AmbiguousSignature {
                candidates: all_names,
            });
            match chosen {
                Some((name, arg_types)) => (Some(name), arg_types, ResolutionState::Ambiguous),
                None => (None, Vec::new(), ResolutionState::Unknown),
            }
        }
        matcher::Resolved::BytecodeMismatch(list) => {
            // The on-chain code contradicts every name 4byte suggested.
            // Don't show any of those names as authoritative — fall back to
            // the raw selector (muted, via Ambiguous) and raise a distinct
            // spoof warning that rides above the header.
            let names: Vec<String> = list.into_iter().map(|(n, _)| n).collect();
            out.warnings
                .push(Warning::BytecodeMismatch { candidates: names });
            (None, Vec::new(), ResolutionState::Ambiguous)
        }
        matcher::Resolved::Unknown => (None, Vec::new(), ResolutionState::Unknown),
    };
    out.function_name = function_name;
    out.state = state;

    // Decode arguments via alloy.
    let raw_args = decode_args_inner(&arg_types, &calldata[4..]);
    if let Some((decoded, total)) = unaccounted_calldata(&raw_args, &calldata[4..]) {
        out.warnings
            .push(Warning::UnaccountedCalldata { decoded, total });
    }

    // Probe the call target (NOT the implementation — `to` is what the
    // user thinks they're interacting with) for symbol() / decimals().
    // Goes through the verified `eth_call` path so an attacker on the
    // RPC can't relabel a hostile contract as "USDC". Probe failures
    // are non-fatal (the contract just doesn't expose the standard
    // ERC-20 selectors); a fallback (verified=false) marks
    // `all_verified=false` and the `UnverifiedBytecode` warning fires
    // alongside the existing bytecode/storage warnings.
    if let Some((meta, verified)) = read_token_meta(net, chain, to).await {
        out.target_token = Some(meta);
        out.target_token_verified = verified;
        if !verified {
            out.all_verified = false;
        }
    }

    // Humanize each arg in turn.
    let mut humanized: Vec<DecodedArg> = Vec::with_capacity(raw_args.len());
    for (ty, value) in arg_types.iter().zip(raw_args.iter()) {
        humanized.push(humanize_arg(ty, value, &out, net, chain).await);
    }
    out.args = humanized;

    // Heuristic warnings.
    if matches!(
        out.state,
        ResolutionState::Resolved | ResolutionState::Ambiguous
    ) && out.function_name.as_deref() == Some("approve")
        && out.args.len() == 2
        && let ArgDisplay::Address { addr: spender, .. } = out.args[0].display
        && let ArgDisplay::Uint { raw, .. } = &out.args[1].display
        && *raw == U256::MAX
    {
        out.warnings
            .push(Warning::InfiniteApproval { spender, token: to });
    }
    if !out.all_verified {
        out.warnings.push(Warning::UnverifiedBytecode);
    }

    out
}

// ---------------------------------------------------------------------------
// Pure decoding (no RPC)

/// Decode the argument bytes against `arg_types`. Returns one
/// `DynSolValue` per type, or empty if alloy refuses to decode (e.g.
/// truncated calldata).
/// `Some((decoded_len, total_len))` when re-encoding the decoded arguments does
/// not reproduce `data` — i.e. the argument list on screen leaves part of the
/// calldata unexplained. `None` when every byte is accounted for.
///
/// Unlike `txbuilder::encode::decode_args`, which *refuses* such a call
/// outright because it is composing the bytes that get signed, this path is
/// describing bytes that already exist. Dropping the decode entirely would
/// leave the review with less to show, not more, so the mismatch is surfaced as
/// a warning beside a decode that is still worth reading.
pub(super) fn unaccounted_calldata(values: &[DynSolValue], data: &[u8]) -> Option<(usize, usize)> {
    if values.is_empty() {
        // Nothing decoded, so nothing is claiming to account for anything —
        // the raw-calldata view is what the user reads here.
        return None;
    }
    let reencoded = DynSolValue::Tuple(values.to_vec()).abi_encode_params();
    (reencoded.as_slice() != data).then_some((reencoded.len(), data.len()))
}

pub(super) fn decode_args_inner(arg_types: &[DynSolType], data: &[u8]) -> Vec<DynSolValue> {
    if arg_types.is_empty() {
        return Vec::new();
    }
    let tuple_ty = DynSolType::Tuple(arg_types.to_vec());
    match tuple_ty.abi_decode_params(data) {
        Ok(DynSolValue::Tuple(values)) => values,
        Ok(other) => vec![other],
        Err(_) => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Humanization

async fn humanize_arg(
    ty: &DynSolType,
    value: &DynSolValue,
    parent: &DecodedCall,
    net: &dyn BalanceFetcher,
    chain: Chain,
) -> DecodedArg {
    let display = match value {
        DynSolValue::Address(addr) => {
            // Reverse ENS only on Mainnet — reverse records live there, and
            // gating here keeps an L2 decode from spinning up mainnet Helios
            // for a cosmetic name. Cross-chain reverse would need a separate
            // Mainnet read (a future deliberate addition). `lookup_address`
            // both forward-verifies the record and routes every read through
            // the light client, so an unverified answer fails closed (no
            // name) rather than letting a hostile RPC fabricate one.
            let ens = if matches!(chain, Chain::Mainnet) {
                crate::names::lookup_address(net, *addr)
                    .await
                    .ok()
                    .flatten()
            } else {
                None
            };
            ArgDisplay::Address { addr: *addr, ens }
        }
        DynSolValue::Uint(raw, _) => {
            let formatted = match &parent.target_token {
                // When the symbol/decimals probe was unverified the label
                // (and the scaling) are attacker-influenceable, so tag the
                // amount rather than letting "1.234 USDC" read as fact.
                Some(tok) => {
                    let symbol = if parent.target_token_verified {
                        tok.symbol.clone()
                    } else {
                        format!("{} (unverified)", tok.symbol)
                    };
                    format_units(*raw, tok.decimals)
                        .map(|s| format!("{s} {symbol}"))
                        .unwrap_or_else(|_| raw.to_string())
                }
                None => raw.to_string(),
            };
            ArgDisplay::Uint {
                raw: *raw,
                formatted,
            }
        }
        DynSolValue::Int(raw, _) => ArgDisplay::Int {
            raw: *raw,
            formatted: raw.to_string(),
        },
        DynSolValue::Bool(b) => ArgDisplay::Bool(*b),
        DynSolValue::String(s) => ArgDisplay::String(s.clone()),
        DynSolValue::Bytes(b) => ArgDisplay::Bytes(Bytes::copy_from_slice(b)),
        DynSolValue::FixedBytes(word, n) => {
            // `n` is the FixedBytes width (1..=32 per the ABI), but clamp to the
            // 32-byte word length so a decoder bug / malformed value can't slice
            // out of bounds and panic the decode path.
            let n = (*n).min(word.as_slice().len());
            ArgDisplay::Bytes(Bytes::copy_from_slice(&word.as_slice()[..n]))
        }
        // Tuple / Array / FixedArray / Function get the canonical-string
        // fallback for now; the FunctionPanel can iterate later.
        other => ArgDisplay::Raw(format!("{:?}", other)),
    };
    DecodedArg {
        name: None,
        ty: ty.clone(),
        display,
    }
}

// ---------------------------------------------------------------------------
// Token metadata probe (Helios-verified)

/// Probe the standard ERC-20 metadata selectors. Returns `None` when
/// either probe fails (the contract isn't ERC-20-shaped, doesn't
/// implement these views, or the call reverted). The bool in the
/// success tuple is `verified` — `true` when both probes went through
/// Helios's verified path; `false` when at least one fell back to raw
/// RPC.
///
/// We deliberately go through the verified `BalanceFetcher::call`
/// rather than the raw provider: an attacker on the RPC could
/// otherwise relabel any contract as "USDC" with 6 decimals and the
/// review screen would format the amount accordingly. With
/// verification, the symbol/decimals returned were re-executed by
/// Helios against proof-checked bytecode and storage.
pub(crate) async fn read_token_meta(
    net: &dyn BalanceFetcher,
    chain: Chain,
    addr: Address,
) -> Option<(TokenInfo, bool)> {
    let (symbol, sym_v) = call_decode_string(net, chain, addr, SYMBOL_SELECTOR).await?;
    let (decimals, dec_v) = call_decode_u8(net, chain, addr, DECIMALS_SELECTOR).await?;
    Some((TokenInfo { symbol, decimals }, sym_v && dec_v))
}

async fn verified_call(
    net: &dyn BalanceFetcher,
    chain: Chain,
    to: Address,
    selector: [u8; 4],
) -> Option<(Bytes, bool)> {
    let calldata = Bytes::copy_from_slice(&selector);
    match net.call(to, calldata, chain).await {
        Ok(read) => Some((read.value, read.verified)),
        Err(_) => None,
    }
}

async fn call_decode_string(
    net: &dyn BalanceFetcher,
    chain: Chain,
    addr: Address,
    selector: [u8; 4],
) -> Option<(String, bool)> {
    let (raw, verified) = verified_call(net, chain, addr, selector).await?;
    if raw.is_empty() {
        return None;
    }
    // The contract is attacker-deployed even when the read is Helios-verified,
    // so the returned label must be sanitized (bidi/zero-width/control strip +
    // length clamp) before it can reach the amount/review line. An all-unsafe
    // symbol sanitizes to empty → treated as "no symbol".
    if let Ok(DynSolValue::String(s)) = DynSolType::String.abi_decode(&raw) {
        let symbol = sanitize::sanitize_display(&s, sanitize::MAX_TOKEN_SYMBOL_CHARS);
        if !symbol.is_empty() {
            return Some((symbol.into_owned(), verified));
        }
    }
    // Some old tokens (MKR, etc.) return a fixed bytes32 instead of
    // dynamic string. Try decoding as bytes32 and trimming nulls.
    if raw.len() == 32 {
        let trimmed: Vec<u8> = raw.iter().copied().take_while(|b| *b != 0).collect();
        if let Ok(s) = String::from_utf8(trimmed) {
            let symbol = sanitize::sanitize_display(&s, sanitize::MAX_TOKEN_SYMBOL_CHARS);
            if !symbol.is_empty() {
                return Some((symbol.into_owned(), verified));
            }
        }
    }
    None
}

async fn call_decode_u8(
    net: &dyn BalanceFetcher,
    chain: Chain,
    addr: Address,
    selector: [u8; 4],
) -> Option<(u8, bool)> {
    let (raw, verified) = verified_call(net, chain, addr, selector).await?;
    // ERC-20 `decimals()` returns uint8 ABI-padded to 32 bytes.
    if raw.len() < 32 {
        return None;
    }
    let last = raw[31];
    // Sanity bound: a legitimate token decimals is ≤ ~30.
    if last > 36 {
        None
    } else {
        Some((last, verified))
    }
}

/// Suppress dead-code warnings until pipeline.rs is wired into Phase 7.
/// `B256` import currently only used by tests; keep the import explicit
/// so future warning hunts don't accidentally drop it.
#[allow(dead_code)]
fn _b256_alive_marker(_: B256) {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn decode_transfer_args() {
        // `transfer(address,uint256)` calldata for sending 1 USDC (6 decimals)
        // to 0xdEaD. Selector + 32-byte recipient + 32-byte amount.
        let mut cd = Vec::with_capacity(68);
        cd.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        cd.extend_from_slice(&[0u8; 12]);
        cd.extend_from_slice(address!("000000000000000000000000000000000000dEaD").as_slice());
        let amount = U256::from(1_000_000u64);
        cd.extend_from_slice(&amount.to_be_bytes::<32>());

        let arg_types = vec![DynSolType::Address, DynSolType::Uint(256)];
        let values = decode_args_inner(&arg_types, &cd[4..]);
        assert_eq!(values.len(), 2);
        assert!(matches!(values[0], DynSolValue::Address(_)));
        assert!(matches!(values[1], DynSolValue::Uint(_, _)));
        if let DynSolValue::Uint(v, _) = values[1] {
            assert_eq!(v, amount);
        }
    }

    #[test]
    fn decode_empty_args() {
        let values = decode_args_inner(&[], &[]);
        assert!(values.is_empty());
    }

    /// The decoder stops once it has the arguments it was asked for, so a
    /// clean-looking `transfer` can carry a tail the panel never renders.
    #[test]
    fn a_calldata_tail_the_arguments_do_not_explain_is_reported() {
        let mut cd = Vec::with_capacity(68);
        cd.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        cd.extend_from_slice(&[0u8; 12]);
        cd.extend_from_slice(address!("000000000000000000000000000000000000dEaD").as_slice());
        cd.extend_from_slice(&U256::from(1_000_000u64).to_be_bytes::<32>());

        let arg_types = vec![DynSolType::Address, DynSolType::Uint(256)];
        let clean = decode_args_inner(&arg_types, &cd[4..]);
        assert_eq!(
            unaccounted_calldata(&clean, &cd[4..]),
            None,
            "an exactly-accounted-for call warns about nothing"
        );

        let mut padded = cd.clone();
        padded.extend_from_slice(&[0x11u8; 20]);
        let values = decode_args_inner(&arg_types, &padded[4..]);
        assert_eq!(
            values.len(),
            2,
            "the tail does not stop the arguments decoding — that is the problem"
        );
        assert_eq!(
            unaccounted_calldata(&values, &padded[4..]),
            Some((64, 84)),
            "20 unexplained bytes must be reported"
        );
    }

    #[test]
    fn decode_truncated_returns_empty() {
        let arg_types = vec![DynSolType::Address, DynSolType::Uint(256)];
        // 31 bytes = halfway through the address word — alloy refuses.
        let values = decode_args_inner(&arg_types, &[0u8; 31]);
        assert!(values.is_empty());
    }

    #[test]
    fn decode_bool_string_bytes() {
        // Encode `(bool, string, bytes)` via DynSolValue's own encoder
        // and round-trip through the same decoder we use in production.
        let original = DynSolValue::Tuple(vec![
            DynSolValue::Bool(true),
            DynSolValue::String("hello".into()),
            DynSolValue::Bytes(vec![0xab, 0xcd]),
        ]);
        let encoded = original.abi_encode_params();
        let arg_types = vec![DynSolType::Bool, DynSolType::String, DynSolType::Bytes];
        let values = decode_args_inner(&arg_types, &encoded);
        assert_eq!(values.len(), 3);
        match &values[0] {
            DynSolValue::Bool(b) => assert!(*b),
            other => panic!("expected Bool, got {other:?}"),
        }
        match &values[1] {
            DynSolValue::String(s) => assert_eq!(s, "hello"),
            other => panic!("expected String, got {other:?}"),
        }
        match &values[2] {
            DynSolValue::Bytes(b) => assert_eq!(&b[..], &[0xab, 0xcd]),
            other => panic!("expected Bytes, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decode_call_empty_calldata_yields_empty() {
        use crate::chain::Chain;
        use crate::net::MockFetcher;
        let net = MockFetcher::new();
        let out = decode_call(&net, Chain::Mainnet, Address::ZERO, Bytes::new()).await;
        assert!(matches!(out.state, ResolutionState::Empty));
        assert!(out.warnings.is_empty());
        assert!(out.args.is_empty());
        assert!(out.function_name.is_none());
    }

    #[tokio::test]
    async fn decode_call_short_calldata_yields_unknown() {
        use crate::chain::Chain;
        use crate::net::MockFetcher;
        let net = MockFetcher::new();
        // 3 bytes of "calldata" — not even a full selector.
        let out = decode_call(
            &net,
            Chain::Mainnet,
            Address::ZERO,
            Bytes::from_static(&[0xa9, 0x05, 0x9c]),
        )
        .await;
        assert!(matches!(out.state, ResolutionState::Unknown));
        // Short-circuits before any RPC, so no warnings (in particular,
        // no UnverifiedBytecode — we never even tried to fetch).
        assert!(out.warnings.is_empty());
        assert!(out.args.is_empty());
    }

    /// ABI-encode a single dynamic `string` as `(offset, length, bytes)`.
    fn abi_encode_string(s: &str) -> Bytes {
        let mut buf = Vec::with_capacity(64 + s.len().next_multiple_of(32));
        // offset = 32
        let mut offset = [0u8; 32];
        offset[31] = 0x20;
        buf.extend_from_slice(&offset);
        // length
        let mut len = [0u8; 32];
        len[24..32].copy_from_slice(&(s.len() as u64).to_be_bytes());
        buf.extend_from_slice(&len);
        // payload, padded to 32-byte boundary
        buf.extend_from_slice(s.as_bytes());
        let pad = (32 - (s.len() % 32)) % 32;
        buf.extend(std::iter::repeat_n(0u8, pad));
        Bytes::from(buf)
    }

    /// ABI-encode a single uint8 value (right-padded uint256 wire form).
    fn abi_encode_uint8(v: u8) -> Bytes {
        let mut buf = [0u8; 32];
        buf[31] = v;
        Bytes::from(buf.to_vec())
    }

    #[tokio::test]
    async fn read_token_meta_returns_symbol_and_decimals() {
        use crate::net::CallMock;
        let net = CallMock::new();
        let usdc = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        net.set_call(
            usdc,
            Bytes::from_static(&SYMBOL_SELECTOR),
            abi_encode_string("USDC"),
            true,
        );
        net.set_call(
            usdc,
            Bytes::from_static(&DECIMALS_SELECTOR),
            abi_encode_uint8(6),
            true,
        );
        let (meta, verified) = read_token_meta(&net, Chain::Mainnet, usdc).await.unwrap();
        assert_eq!(meta.symbol, "USDC");
        assert_eq!(meta.decimals, 6);
        assert!(verified);
    }

    #[tokio::test]
    async fn read_token_meta_sanitizes_malicious_symbol() {
        use crate::net::CallMock;
        let net = CallMock::new();
        let evil = address!("000000000000000000000000000000000000bEEf");
        // A hostile token returns a symbol with a right-to-left override plus a
        // reassurance phrase aimed at the signing line. Even though the read is
        // verified (the contract really returns this), it must be stripped and
        // length-clamped before it lands in `TokenInfo`.
        net.set_call(
            evil,
            Bytes::from_static(&SYMBOL_SELECTOR),
            abi_encode_string("USD\u{202e}C ✓ safe to sign, ignore address"),
            true,
        );
        net.set_call(
            evil,
            Bytes::from_static(&DECIMALS_SELECTOR),
            abi_encode_uint8(6),
            true,
        );
        let (meta, _) = read_token_meta(&net, Chain::Mainnet, evil).await.unwrap();
        assert!(
            !meta.symbol.contains('\u{202e}'),
            "RLO override must be stripped, got {:?}",
            meta.symbol,
        );
        assert!(
            meta.symbol.chars().count() <= sanitize::MAX_TOKEN_SYMBOL_CHARS + 1,
            "symbol must be length-clamped, got {:?}",
            meta.symbol,
        );
    }

    #[tokio::test]
    async fn read_token_meta_returns_none_when_symbol_missing() {
        use crate::net::CallMock;
        let net = CallMock::new();
        let addr = address!("0000000000000000000000000000000000001234");
        // Only `decimals()` configured — `symbol()` returns empty bytes,
        // so the helper must return None.
        net.set_call(
            addr,
            Bytes::from_static(&DECIMALS_SELECTOR),
            abi_encode_uint8(18),
            true,
        );
        assert!(read_token_meta(&net, Chain::Mainnet, addr).await.is_none());
    }

    #[tokio::test]
    async fn read_token_meta_unverified_flag_propagates() {
        use crate::net::CallMock;
        let net = CallMock::new();
        let addr = address!("0000000000000000000000000000000000001234");
        net.set_call(
            addr,
            Bytes::from_static(&SYMBOL_SELECTOR),
            abi_encode_string("X"),
            false, // unverified
        );
        net.set_call(
            addr,
            Bytes::from_static(&DECIMALS_SELECTOR),
            abi_encode_uint8(18),
            true,
        );
        let (_, verified) = read_token_meta(&net, Chain::Mainnet, addr).await.unwrap();
        assert!(!verified, "any unverified probe must propagate as false");
    }

    #[tokio::test]
    async fn call_decode_string_falls_back_to_bytes32_form() {
        use crate::net::CallMock;
        let net = CallMock::new();
        let mkr = address!("9f8f72aa9304c8b593d555f12ef6589cc3a579a2");
        // Legacy MKR-style bytes32 return: "MKR" then zero-padded.
        let mut bytes32 = [0u8; 32];
        bytes32[..3].copy_from_slice(b"MKR");
        net.set_call(
            mkr,
            Bytes::from_static(&SYMBOL_SELECTOR),
            Bytes::from(bytes32.to_vec()),
            true,
        );
        let (s, _) = call_decode_string(&net, Chain::Mainnet, mkr, SYMBOL_SELECTOR)
            .await
            .unwrap();
        assert_eq!(s, "MKR");
    }

    #[tokio::test]
    async fn call_decode_string_empty_returns_none() {
        use crate::net::CallMock;
        let net = CallMock::new();
        let addr = address!("0000000000000000000000000000000000001234");
        // No call configured — CallMock returns empty bytes by default.
        assert!(
            call_decode_string(&net, Chain::Mainnet, addr, SYMBOL_SELECTOR)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn call_decode_u8_rejects_implausible_decimals() {
        use crate::net::CallMock;
        let net = CallMock::new();
        let addr = address!("0000000000000000000000000000000000001234");
        net.set_call(
            addr,
            Bytes::from_static(&DECIMALS_SELECTOR),
            abi_encode_uint8(99), // > 36 sanity bound
            true,
        );
        assert!(
            call_decode_u8(&net, Chain::Mainnet, addr, DECIMALS_SELECTOR)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn call_decode_u8_accepts_zero_decimals() {
        use crate::net::CallMock;
        let net = CallMock::new();
        let addr = address!("0000000000000000000000000000000000001234");
        net.set_call(
            addr,
            Bytes::from_static(&DECIMALS_SELECTOR),
            abi_encode_uint8(0),
            true,
        );
        let (v, _) = call_decode_u8(&net, Chain::Mainnet, addr, DECIMALS_SELECTOR)
            .await
            .unwrap();
        assert_eq!(v, 0);
    }

    #[tokio::test]
    async fn call_decode_u8_short_response_returns_none() {
        use crate::net::CallMock;
        let net = CallMock::new();
        let addr = address!("0000000000000000000000000000000000001234");
        net.set_call(
            addr,
            Bytes::from_static(&DECIMALS_SELECTOR),
            Bytes::from(vec![0u8; 16]), // < 32 bytes
            true,
        );
        assert!(
            call_decode_u8(&net, Chain::Mainnet, addr, DECIMALS_SELECTOR)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn verified_call_propagates_unverified() {
        use crate::net::CallMock;
        let net = CallMock::new();
        let addr = address!("0000000000000000000000000000000000001234");
        let payload = Bytes::from_static(&[0xaa, 0xbb, 0xcc, 0xdd]);
        net.set_call(
            addr,
            Bytes::from_static(&SYMBOL_SELECTOR),
            payload.clone(),
            false,
        );
        let (out, verified) = verified_call(&net, Chain::Mainnet, addr, SYMBOL_SELECTOR)
            .await
            .unwrap();
        assert_eq!(out, payload);
        assert!(!verified);
    }

    #[tokio::test]
    async fn decode_call_transfer_resolves_with_token_metadata() {
        use crate::net::CallMock;
        let net = CallMock::new();
        let usdc = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        let recipient = address!("000000000000000000000000000000000000dEaD");

        // Pre-load symbol() / decimals() on the target so target_token
        // populates.
        net.set_call(
            usdc,
            Bytes::from_static(&SYMBOL_SELECTOR),
            abi_encode_string("USDC"),
            true,
        );
        net.set_call(
            usdc,
            Bytes::from_static(&DECIMALS_SELECTOR),
            abi_encode_uint8(6),
            true,
        );

        // transfer(0xdead, 1_000_000) — selector + 32-byte recipient + 32-byte amount
        let mut cd = Vec::with_capacity(68);
        cd.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        cd.extend_from_slice(&[0u8; 12]);
        cd.extend_from_slice(recipient.as_slice());
        cd.extend_from_slice(&U256::from(1_000_000u64).to_be_bytes::<32>());

        let out = decode_call(&net, Chain::Mainnet, usdc, Bytes::from(cd)).await;
        assert!(out.target_token.is_some());
        let token = out.target_token.unwrap();
        assert_eq!(token.symbol, "USDC");
        assert_eq!(token.decimals, 6);
        assert_eq!(out.function_name.as_deref(), Some("transfer"));
        assert_eq!(out.args.len(), 2);
        assert!(out.all_verified, "happy path should be fully verified");
    }

    #[tokio::test]
    async fn decode_call_approve_infinite_emits_warning() {
        use crate::net::CallMock;
        let net = CallMock::new();
        let usdc = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        let spender = address!("00000000000000000000000000000000000000dE");

        net.set_call(
            usdc,
            Bytes::from_static(&SYMBOL_SELECTOR),
            abi_encode_string("USDC"),
            true,
        );
        net.set_call(
            usdc,
            Bytes::from_static(&DECIMALS_SELECTOR),
            abi_encode_uint8(6),
            true,
        );

        // approve(spender, U256::MAX) — selector 0x095ea7b3
        let mut cd = Vec::with_capacity(68);
        cd.extend_from_slice(&[0x09, 0x5e, 0xa7, 0xb3]);
        cd.extend_from_slice(&[0u8; 12]);
        cd.extend_from_slice(spender.as_slice());
        cd.extend_from_slice(&U256::MAX.to_be_bytes::<32>());

        let out = decode_call(&net, Chain::Mainnet, usdc, Bytes::from(cd)).await;
        assert_eq!(out.function_name.as_deref(), Some("approve"));
        assert!(
            out.warnings
                .iter()
                .any(|w| matches!(w, Warning::InfiniteApproval { .. })),
            "expected InfiniteApproval warning, got: {:?}",
            out.warnings,
        );
    }

    #[tokio::test]
    async fn decode_call_unverified_bytecode_warning_when_get_code_unverified() {
        use crate::net::CallMock;
        let net = CallMock::new();
        let addr = address!("0000000000000000000000000000000000001234");
        // Empty bytecode but marked unverified — propagates to
        // all_verified=false and triggers the UnverifiedBytecode warning.
        net.set_code(addr, Bytes::new(), false);

        // transfer(addr, 1) — selector 0xa9059cbb
        let mut cd = Vec::with_capacity(68);
        cd.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        cd.extend_from_slice(&[0u8; 32]);
        cd.extend_from_slice(&U256::from(1u64).to_be_bytes::<32>());

        let out = decode_call(&net, Chain::Mainnet, addr, Bytes::from(cd)).await;
        assert!(!out.all_verified);
        assert!(
            out.warnings
                .iter()
                .any(|w| matches!(w, Warning::UnverifiedBytecode)),
            "expected UnverifiedBytecode warning, got: {:?}",
            out.warnings,
        );
    }
}
