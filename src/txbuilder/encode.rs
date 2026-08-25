//! Forward ABI encoding: user-typed parameter strings → validated
//! `DynSolValue`s → calldata `Bytes`. The decode pipeline (`decode::`)
//! only goes the other way, so this is net-new.
//!
//! The security-relevant property: the bytes produced here are the exact
//! bytes queued, simulated, reviewed, and signed. We validate each param
//! by *coercing* it through its `DynSolType` (`coerce_str`), which is the
//! same parser alloy uses everywhere else — a value that coerces cleanly
//! is a value that ABI-encodes to what the user sees.

use alloy::dyn_abi::{DynSolType, DynSolValue};
use alloy::primitives::{Address, Bytes, U256};

use super::abi::AbiMethod;
use super::{DecodedArg, QueuedCall, TxBuilderError};

/// Why a mixed-case address string was refused. Short: parameter errors are
/// rendered prefixed with the parameter's name.
const EIP55_REASON: &str = "fails its EIP-55 checksum — one character is off, re-copy it";

/// True when `s` is a 20-byte hex address whose *mixed* case fails EIP-55.
///
/// All-lowercase and all-uppercase hex carry no checksum information — EIP-55
/// defines them as unchecksummed, and both explorers and JSON-RPC still emit
/// the lowercase form — so neither is ever a violation. Mixed case *is* a
/// checksum claim, and a claim that doesn't hold is exactly the transposed or
/// mistyped character the checksum exists to catch: one of the few corruptions
/// that still parses as a perfectly valid address and sends the funds nowhere.
fn fails_eip55(s: &str) -> bool {
    // The prefix is optional on the way in — alloy's coercer takes a bare
    // 40-hex address — so a check keyed on `0x` would wave that spelling past.
    let body = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if body.len() != 40 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    let mut lower = false;
    let mut upper = false;
    for c in body.chars().filter(|c| c.is_ascii_alphabetic()) {
        lower |= c.is_ascii_lowercase();
        upper |= c.is_ascii_uppercase();
    }
    // Re-prefix rather than pass `s` through: alloy's checksummer only accepts
    // a lowercase `0x`, so a `0X`-prefixed address would fail as a formatting
    // quirk rather than as the checksum mismatch we are testing for.
    lower && upper && Address::parse_checksummed(format!("0x{body}"), None).is_err()
}

/// Whether a token-level scan of a value string can be sure every 40-hex hit
/// it finds is an address.
///
/// True iff the type tree has an `address` leaf and no leaf written as free
/// hex. A `bytes20` is spelled exactly like an address and is *not* a checksum
/// claim, so a type carrying both — `(address,bytes20)` — is left alone rather
/// than risk refusing a legitimate value. That is a known hole in the gate, and
/// the right direction to leave one in: the cost is a missed check on an
/// unusual signature, against wrongly rejecting input the user typed correctly.
///
/// `string` is deliberately **not** free hex. It was when this predicate was
/// written, and that single word disarmed the gate for every `(address,string)`
/// signature in the wild — the token scan can't tell the address from the memo
/// beside it, so the whole tree was declared unscannable and a corrupted
/// mixed-case address coerced exactly as freely inside `(address,string)` as
/// `bytes20`'s. But a `string` leaf never *produces* a 40-hex token a reader
/// could mistake for an address: what the scan does with a string is consume
/// alphanumeric runs that are the string's own content, and refusing a
/// string whose content happens to be 40 mixed-case hex characters is the
/// same trade `bytes20` makes — except here the token scan only *acts* on
/// runs that fail EIP-55, and a string-authored 40-hex run with mixed case
/// has no checksum claim either. The distinction that matters: for `bytes`/
/// `bytesN`/`function`, a 40-hex run is *canonical spelling* the user may have
/// copied deliberately; for `string` it is incidental content, and the
/// corruption being caught is one the address leaf's own spelling rules
/// already reject everywhere else. So `string` no longer disarms the scan.
fn addresses_are_unambiguous(ty: &DynSolType) -> bool {
    fn walk(ty: &DynSolType, addr: &mut bool, hexish: &mut bool) {
        match ty {
            DynSolType::Address => *addr = true,
            // Free-hex leaves: a 40-hex run can be their canonical spelling,
            // so a token scan cannot attribute such a run to the address leaf.
            DynSolType::Bytes
            | DynSolType::FixedBytes(_)
            | DynSolType::Function => *hexish = true,
            DynSolType::Array(inner) => walk(inner, addr, hexish),
            DynSolType::FixedArray(inner, _) => walk(inner, addr, hexish),
            DynSolType::Tuple(items) => items.iter().for_each(|t| walk(t, addr, hexish)),
            DynSolType::CustomStruct { tuple, .. } => {
                tuple.iter().for_each(|t| walk(t, addr, hexish))
            }
            _ => {}
        }
    }
    let (mut addr, mut hexish) = (false, false);
    walk(ty, &mut addr, &mut hexish);
    addr && !hexish
}

/// Whether every integer leaf of `v` fits the width its own type declares.
///
/// The coercer enforces a narrow signed integer's *upper* bound and not its
/// lower one: `int8` refuses `128` and accepts `-129`, `-200`, `-255` alike
/// (`-256` is where the word finally wraps). Nothing downstream looks again —
/// the round-trip in [`build_contract_call`] passes, because the value
/// round-trips through alloy perfectly well, and [`encoded_preview`] returns
/// `None` because the string reads as what it encodes. So the field says
/// `✓ valid`, the call queues, and the revert arrives on chain, after the whole
/// ceremony and with the atomic batch failing as a unit.
///
/// Checking the width here rather than trusting the coercer also keeps the
/// guarantee off a dependency's patch version, where it is invisible.
fn ints_fit_their_width(v: &DynSolValue) -> bool {
    match v {
        DynSolValue::Int(i, bits) => i.bits() as usize <= *bits,
        DynSolValue::Uint(u, bits) => u.bit_len() <= *bits,
        DynSolValue::Array(items) | DynSolValue::FixedArray(items) | DynSolValue::Tuple(items) => {
            items.iter().all(ints_fit_their_width)
        }
        DynSolValue::CustomStruct { tuple, .. } => tuple.iter().all(ints_fit_their_width),
        _ => true,
    }
}

/// Validate a single parameter value against its type by coercing it. Ok
/// carries the encodable value; Err is a short, user-facing reason.
pub fn coerce_param(ty: &DynSolType, raw: &str) -> Result<DynSolValue, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("required".into());
    }
    // Alloy's `address` coercer is pure hex, so the checksum has to be checked
    // before it. Scanning the whole string rather than the scalar covers the
    // addresses nested in a tuple or array argument, which coerce_str would
    // otherwise wave through one level down.
    if addresses_are_unambiguous(ty)
        && s.split(|c: char| !c.is_ascii_alphanumeric())
            .any(fails_eip55)
    {
        return Err(EIP55_REASON.into());
    }
    let v = ty
        .coerce_str(s)
        // Solidity's spelling, so this names the same type as the field's own
        // pill and the signature on the review — `sol_type_name` would say
        // `(uint256,)` where every other surface says `(uint256)`.
        .map_err(|_| format!("expected {}", super::abi::canonical_sol_type(ty)))?;
    if !ints_fit_their_width(&v) {
        return Err(format!(
            "is out of range for {}",
            super::abi::canonical_sol_type(ty)
        ));
    }
    Ok(v)
}

/// Cheap validity check for live UI feedback (the `✓ valid` / `needs T`
/// annotation). Same coercion path as [`coerce_param`].
pub fn is_valid(ty: &DynSolType, raw: &str) -> bool {
    coerce_param(ty, raw).is_ok()
}

/// The number a parameter string will actually encode to, when that differs
/// from what was typed: `1 ether` → `1000000000000000000`, `1e6` → `1000000`,
/// a lowercase address → its checksummed form. `None` when the input doesn't
/// coerce, or when it already reads as what it encodes — the common case, where
/// a second line would only be noise.
///
/// Rendered under the field, so the value being agreed to is on screen at the
/// keystroke rather than only after the call is queued.
pub fn encoded_preview(ty: &DynSolType, raw: &str) -> Option<String> {
    let v = coerce_param(ty, raw).ok()?;
    let shown = format_sol_value(&v);
    (shown != raw.trim()).then_some(shown)
}

/// A short type hint shown as the field placeholder.
///
/// The integer hint names the grammar rather than a rule the parser doesn't
/// enforce. Alloy's uint coercer takes `1 ether`, `2.5 gwei`, `1e18` and `0x10`
/// as readily as a plain decimal, and `1 ether` into a 6-decimal token's
/// `uint256` is 10¹² of it — so "base units, no decimals" was the worst of both,
/// wrong about the units and wrong about the decimals (a bare `1.5` *is*
/// refused; `2.5 gwei` is not). The field annotates the number that actually
/// gets encoded — see [`encoded_preview`].
/// Arrays and tuples are tested **first**, and that ordering is the point. The
/// scalar arms below are prefix tests, so `uint256[]` used to match the integer
/// arm and `bytes32[]` the bytes arm — each field then advertised the grammar of
/// its *element* as if it were the grammar of the whole value, with nothing on
/// screen anywhere saying a list is written `[a, b]`. The encoder has always
/// accepted the composite syntax (`coerce_str` parses it); only the hint was
/// missing, so the whole type surface was unreachable in practice.
pub fn type_hint(ty_str: &str) -> String {
    if let Some(elem) = array_element(ty_str) {
        return format!("[{elem}, {elem}] — comma-separated in brackets, [] for none");
    }
    if ty_str.starts_with('(') {
        return "(a, b) — comma-separated in parens, in declaration order".into();
    }
    match ty_str {
        "address" => "0x… (20-byte address)".into(),
        "bool" => "true / false".into(),
        "string" => "text — \"\" for empty".into(),
        "bytes" => "0x… hex — 0x for empty".into(),
        _ if ty_str.starts_with("uint") || ty_str.starts_with("int") => {
            "base units — 1e18 / 1 gwei / 1 ether / 0x10 also parse".into()
        }
        _ if ty_str.starts_with("bytes") => "0x… hex".into(),
        _ => ty_str.into(),
    }
}

/// The element type of an array type string: `uint256[]` and `uint256[3]` both
/// yield `uint256`, `(address,uint256)[]` yields the tuple. `None` when the
/// type isn't an array. Strips one level, so a nested `uint256[][]` describes
/// itself as a list of `uint256[]` — which is what the outer field takes.
fn array_element(ty: &str) -> Option<&str> {
    let open = ty.strip_suffix(']')?.rfind('[')?;
    Some(&ty[..open])
}

/// Parse a wei value string — decimal or `0x`-prefixed hex.
pub fn parse_wei(raw: &str) -> Result<U256, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Ok(U256::ZERO);
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        // A bare prefix is a truncated paste, not a value. ruint parses the
        // empty hex string as a clean zero (the whole from_str_radix family
        // starts from `ZERO` and only ever accumulates digits), so without
        // this the composer's value gate read "0x" as valid — the CTA lit
        // up, and the call queued carrying 0 wei. An intentional zero is
        // typed `0` (the field's own placeholder) and still parses.
        if hex.is_empty() {
            return Err("hex value is missing its digits".into());
        }
        U256::from_str_radix(hex, 16).map_err(|_| "invalid hex wei value".into())
    } else {
        s.parse::<U256>().map_err(|_| "invalid wei value".into())
    }
}

/// Parse and validate a target/recipient address, checksum included.
pub fn parse_address(raw: &str) -> Result<Address, String> {
    let s = raw.trim();
    if fails_eip55(s) {
        return Err(format!("this address {EIP55_REASON}"));
    }
    s.parse::<Address>()
        .map_err(|_| "not a 20-byte 0x… address".into())
}

/// Parse the raw composer's calldata field. Empty or a bare `0x` is a plain
/// value transfer, not an error. Odd-length or non-hex is refused — the same
/// answer the composer's CTA is gated on, so the two can't disagree.
pub fn parse_data(raw: &str) -> Result<Bytes, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "0x" {
        return Ok(Bytes::new());
    }
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    alloy::hex::decode(hex)
        .map(Bytes::from)
        .map_err(|_| "data is not valid hex".into())
}

/// ABI-encode a method call: `selector ‖ abi_encode_params(args)`.
/// `values[i]` is the user's string for `method.inputs[i]`.
pub fn encode_call(method: &AbiMethod, values: &[String]) -> Result<Bytes, TxBuilderError> {
    if values.len() != method.inputs.len() {
        return Err(TxBuilderError::Input(format!(
            "{} expects {} argument(s), got {}",
            method.name,
            method.inputs.len(),
            values.len()
        )));
    }
    let mut coerced = Vec::with_capacity(method.inputs.len());
    for (i, input) in method.inputs.iter().enumerate() {
        let v = coerce_param(&input.ty, &values[i])
            .map_err(|e| TxBuilderError::Input(format!("{}: {e}", input.display_name(i))))?;
        coerced.push(v);
    }
    let mut out = Vec::with_capacity(4 + coerced.len() * 32);
    out.extend_from_slice(&method.selector);
    // A tuple of the args encodes identically to head-tail ABI params.
    out.extend_from_slice(&DynSolValue::Tuple(coerced).abi_encode_params());
    Ok(Bytes::from(out))
}

/// Recover the decoded-argument view from calldata, against the method whose
/// selector the calldata carries. The inverse of [`encode_call`], and the
/// reason a queue card can be trusted: what it shows is derived from the bytes
/// that will execute — never from the strings they were typed from, nor from
/// the metadata a bundle claims for them.
///
/// `None` when the body doesn't decode against the signature — truncated,
/// padded, or simply not that method's arguments.
pub fn decode_args(m: &AbiMethod, data: &[u8]) -> Option<Vec<DecodedArg>> {
    let Some(tuple) = m.input_tuple() else {
        // A no-argument method: the calldata is the bare selector, and
        // anything past it is unaccounted for.
        return (data.len() == 4).then(Vec::new);
    };
    let body = data.get(4..)?;
    let DynSolValue::Tuple(vals) = tuple.abi_decode_params(body).ok()? else {
        return None;
    };
    if vals.len() != m.inputs.len() {
        return None;
    }
    // Alloy's decoder is non-consuming: it reads the arguments it was asked for
    // and ignores whatever follows, so a body carrying a suffix past the last
    // argument decodes exactly as cleanly as one that doesn't. That suffix is
    // still calldata. A target reading `msg.data` past the argument region — an
    // ERC-2771 forwarder taking the spoofed sender from the tail, say — acts on
    // it, and nothing downstream would ever have shown it: the queue card, the
    // review, and every per-leg decode are all built from these `DecodedArg`s,
    // so an imported bundle could name `transfer(address,uint256)`, display two
    // clean arguments, and carry live bytes nobody signed for.
    //
    // Re-encoding the values and demanding the body back is what makes
    // "decodes" mean "every byte is accounted for". It also rejects a
    // *non-canonical* encoding of the same values — dirty high bits above an
    // address, a non-minimal offset — which is the same problem wearing a
    // different hat: bytes that survive into execution without appearing on
    // screen.
    if DynSolValue::Tuple(vals.clone())
        .abi_encode_params()
        .as_slice()
        != body
    {
        return None;
    }
    Some(
        m.inputs
            .iter()
            .zip(vals)
            .enumerate()
            .map(|(i, (p, v))| DecodedArg {
                name: p.display_name(i),
                ty: p.ty_str.clone(),
                value: format_sol_value(&v),
            })
            .collect(),
    )
}

/// Build a fully-formed queued contract call from composer input.
///
/// `contract_name` is the display prefix (`USDC`, `0x1234…`). `value_wei`
/// is only honoured for a payable method (ignored otherwise, so a stray
/// value can never ride along on a non-payable call).
#[allow(clippy::too_many_arguments)]
pub fn build_contract_call(
    id: u64,
    to: Address,
    contract_name: &str,
    method: &AbiMethod,
    values: &[String],
    value_wei: &str,
) -> Result<QueuedCall, TxBuilderError> {
    let data = encode_call(method, values)?;
    let value = if method.payable {
        parse_wei(value_wei).map_err(TxBuilderError::Input)?
    } else {
        U256::ZERO
    };

    // The card is where a batch is vetted, one screen ahead of the review, so
    // it answers to the same rule: every value on it is decoded back out of the
    // calldata rather than echoed from the box it was typed in. Echoing hid a
    // real difference — alloy's uint grammar takes `1 ether`, so that string
    // read back as itself over a word holding 10^18 — and made the composer
    // disagree with the import path, which has always decoded.
    let decoded_args = decode_args(method, &data).ok_or_else(|| {
        TxBuilderError::Assembly(format!(
            "the encoded call doesn't decode as `{}` — refusing to queue a call the card \
             can't account for",
            method.signature,
        ))
    })?;

    let title = format!("{contract_name}.{}", method.name);
    let detail = summarize_detail(method, &decoded_args, value);

    Ok(QueuedCall {
        id,
        to,
        value,
        data,
        title,
        detail,
        signature: Some(method.signature.clone()),
        decoded_args,
    })
}

/// Build a queued raw-hex call. `data_hex` may be empty / `0x` for a plain
/// value transfer.
pub fn build_raw_call(
    id: u64,
    to: Address,
    value_wei: &str,
    data_hex: &str,
) -> Result<QueuedCall, TxBuilderError> {
    let value = parse_wei(value_wei).map_err(TxBuilderError::Input)?;
    let data = parse_data(data_hex).map_err(TxBuilderError::Input)?;
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

/// A friendly one-line detail for the queue card, built from the *decoded*
/// arguments so it can't quote a value the calldata doesn't hold. Falls back to
/// the first argument for methods we don't special-case.
fn summarize_detail(method: &AbiMethod, args: &[DecodedArg], value: U256) -> String {
    let arg = |i: usize| args.get(i).map(|a| a.value.as_str()).unwrap_or("");
    let short = |s: &str| {
        s.parse::<Address>()
            .map(crate::wallet::short_address)
            .unwrap_or_else(|_| s.to_string())
    };
    match method.name.as_str() {
        "transfer" | "approve" if args.len() >= 2 => {
            format!("{} → {}", arg(1), short(arg(0)))
        }
        "deposit" if method.payable => format!("wrap {value} wei"),
        _ if args.is_empty() => "no arguments".into(),
        _ => format!("{}: {}", args[0].name, short(arg(0))),
    }
}

/// Humanise a decoded [`DynSolValue`]: checksummed address, decimal integer,
/// `0x…` hex, or a bracketed list for compounds.
///
/// Used wherever a value recovered *from calldata* is shown — the read-result
/// panel, and the decoded-argument view an imported bundle is rebuilt with.
pub fn format_sol_value(v: &DynSolValue) -> String {
    match v {
        DynSolValue::Address(a) => a.to_checksum(None),
        DynSolValue::Bool(b) => b.to_string(),
        DynSolValue::Int(i, _) => i.to_string(),
        DynSolValue::Uint(u, _) => u.to_string(),
        DynSolValue::FixedBytes(b, sz) => format!("0x{}", alloy::hex::encode(&b[..(*sz).min(32)])),
        DynSolValue::Bytes(b) => format!("0x{}", alloy::hex::encode(b)),
        DynSolValue::String(s) => s.clone(),
        DynSolValue::Array(items) | DynSolValue::FixedArray(items) => {
            let inner: Vec<String> = items.iter().map(format_sol_value).collect();
            format!("[{}]", inner.join(", "))
        }
        DynSolValue::Tuple(items) => {
            let inner: Vec<String> = items.iter().map(format_sol_value).collect();
            format!("({})", inner.join(", "))
        }
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::txbuilder::abi;
    use alloy::primitives::address;

    fn usdc() -> abi::LoadedContract {
        abi::known_by_address(
            crate::chain::Chain::Mainnet,
            address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
        )
        .unwrap()
    }

    #[test]
    fn encode_transfer_matches_manual_layout() {
        let c = usdc();
        let transfer = c.methods.iter().find(|m| m.name == "transfer").unwrap();
        let to = address!("0x000000000000000000000000000000000000dEaD");
        let data = encode_call(transfer, &[to.to_string(), "1000000".to_string()]).unwrap();
        // selector + 2 words
        assert_eq!(data.len(), 4 + 64);
        assert_eq!(&data[..4], &[0xa9, 0x05, 0x9c, 0xbb]);
        // address is right-aligned in the first word
        assert_eq!(&data[4 + 12..4 + 32], to.as_slice());
        // amount 1_000_000 = 0xF4240 in the last bytes of word 2
        assert_eq!(
            U256::from_be_slice(&data[4 + 32..4 + 64]),
            U256::from(1_000_000u64)
        );
    }

    #[test]
    fn encode_rejects_bad_address() {
        let c = usdc();
        let transfer = c.methods.iter().find(|m| m.name == "transfer").unwrap();
        let err = encode_call(transfer, &["not-an-address".into(), "1".into()]).unwrap_err();
        assert!(matches!(err, TxBuilderError::Input(_)));
    }

    #[test]
    fn encode_rejects_bad_uint() {
        let c = usdc();
        let approve = c.methods.iter().find(|m| m.name == "approve").unwrap();
        let spender = address!("0x000000000000000000000000000000000000bEEF");
        assert!(encode_call(approve, &[spender.to_string(), "-5".into()]).is_err());
        assert!(encode_call(approve, &[spender.to_string(), "".into()]).is_err());
    }

    #[test]
    fn build_contract_call_zeroes_value_for_nonpayable() {
        let c = usdc();
        let transfer = c.methods.iter().find(|m| m.name == "transfer").unwrap();
        let to = address!("0x000000000000000000000000000000000000dEaD");
        // Even with a stray value string, a non-payable call carries zero.
        let call = build_contract_call(
            1,
            c.address,
            "USDC",
            transfer,
            &[to.to_string(), "5".into()],
            "999",
        )
        .unwrap();
        assert_eq!(call.value, U256::ZERO);
        assert_eq!(call.signature.as_deref(), Some("transfer(address,uint256)"));
        assert_eq!(call.decoded_args.len(), 2);
    }

    #[test]
    fn build_payable_call_honours_value() {
        let c = abi::known_by_address(
            crate::chain::Chain::Mainnet,
            address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
        )
        .unwrap();
        let deposit = c.methods.iter().find(|m| m.name == "deposit").unwrap();
        let call = build_contract_call(2, c.address, "WETH9", deposit, &[], "1000000000000000000")
            .unwrap();
        assert_eq!(call.value, U256::from(1_000_000_000_000_000_000u64));
        assert!(call.data.len() == 4); // selector only, no args
    }

    #[test]
    fn raw_call_parses_hex_and_plain_transfer() {
        let to = address!("0x000000000000000000000000000000000000dEaD");
        let plain = build_raw_call(1, to, "1000", "0x").unwrap();
        assert!(plain.data.is_empty());
        assert_eq!(plain.value, U256::from(1000u64));
        assert!(plain.is_raw());

        let with_data = build_raw_call(2, to, "0", "0xdeadbeef").unwrap();
        assert_eq!(with_data.data.as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
        assert!(build_raw_call(3, to, "0", "0xzz").is_err());
    }

    /// USDC, in its canonical EIP-55 form.
    const CHECKSUMMED: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    /// The same 20 bytes with the leading `A` lowercased: still mixed case, so
    /// still a checksum claim, and now a false one.
    const CORRUPTED: &str = "0xa0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

    #[test]
    fn parse_address_accepts_both_unchecksummed_forms() {
        // EIP-55 defines all-one-case as carrying no checksum. Explorers and
        // JSON-RPC both still emit the lowercase form, so refusing it would
        // reject correct input.
        for s in [
            CHECKSUMMED,
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "0xA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48",
        ] {
            assert!(parse_address(s).is_ok(), "{s} should parse");
        }
    }

    #[test]
    fn parse_address_rejects_a_mixed_case_address_failing_its_checksum() {
        let err = parse_address(CORRUPTED).unwrap_err();
        assert!(err.contains("EIP-55"), "unexpected reason: {err}");
        // The corruption is invisible to the plain hex parser — which is the
        // whole reason the checksum has to be checked separately.
        assert!(CORRUPTED.parse::<Address>().is_ok());
    }


    /// `(address,string)` was the shape the gate went dark on: a `string`
    /// leaf used to disarm the whole tree-level scan, so a corrupted
    /// mixed-case address coerced as freely beside a memo as a `bytes20`
    /// beside an address — and `(address,string)` signatures are everywhere.
    #[test]
    fn the_checksum_gate_survives_a_string_beside_the_address() {
        let ty: DynSolType = "(address,string)".parse().unwrap();
        assert!(coerce_param(&ty, &format!("({CHECKSUMMED},\"memo\")")).is_ok());
        assert!(
            coerce_param(&ty, &format!("({CORRUPTED},\"memo\")")).is_err(),
            "a corrupted address must be refused even when the tuple also \
             carries a string"
        );
        // The gate still ignores the string's own content: a 40-hex-looking
        // string with no mixed case makes no checksum claim.
        let hexish_memo = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
        assert!(coerce_param(&ty, &format!("({CHECKSUMMED},\"{hexish_memo}\")")).is_ok());
    }

    #[test]
    fn address_params_carry_the_checksum_gate_into_coercion() {
        let c = usdc();
        let transfer = c.methods.iter().find(|m| m.name == "transfer").unwrap();
        let err = encode_call(transfer, &[CORRUPTED.into(), "1".into()]).unwrap_err();
        let TxBuilderError::Input(msg) = &err else {
            panic!("expected Input, got {err:?}");
        };
        assert!(msg.contains("EIP-55"), "unexpected reason: {msg}");
        assert!(encode_call(transfer, &[CHECKSUMMED.into(), "1".into()]).is_ok());
    }

    #[test]
    fn the_checksum_gate_reaches_an_address_nested_in_a_tuple() {
        let ty: DynSolType = "(address,uint256)".parse().unwrap();
        assert!(coerce_param(&ty, &format!("({CHECKSUMMED},5)")).is_ok());
        assert!(coerce_param(&ty, &format!("({CORRUPTED},5)")).is_err());
    }

    #[test]
    fn the_checksum_gate_leaves_a_type_it_cannot_read_alone() {
        // A bytes20 may hold any mixed-case hex it likes; it is not a claim.
        let ty: DynSolType = "bytes20".parse().unwrap();
        assert!(coerce_param(&ty, CORRUPTED).is_ok());
        let ty: DynSolType = "string".parse().unwrap();
        assert!(coerce_param(&ty, CORRUPTED).is_ok());
        // And a tuple mixing the two is left alone entirely: a token scan
        // can't tell which 40-hex string was meant to be which, and refusing
        // input the user typed correctly is the worse error.
        let ty: DynSolType = "(address,bytes20)".parse().unwrap();
        assert!(coerce_param(&ty, &format!("({CORRUPTED},{CORRUPTED})")).is_ok());
    }

    #[test]
    fn parse_address_gates_a_bare_unprefixed_address_too() {
        // alloy accepts 40 hex digits with no `0x`, so a predicate keyed on
        // the prefix would wave that spelling straight past the checksum.
        let bare = CORRUPTED.strip_prefix("0x").unwrap();
        assert!(parse_address(bare).is_err());
        assert!(parse_address(CHECKSUMMED.strip_prefix("0x").unwrap()).is_ok());
    }

    #[test]
    fn queued_arguments_are_decoded_from_the_calldata_not_the_typed_text() {
        // `1 ether` coerces cleanly into a uint256 and encodes 10^18. The card
        // used to echo the keystrokes, so it read "1 ether" over a word that
        // means a million million times a USDC unit.
        let c = usdc();
        let transfer = c.methods.iter().find(|m| m.name == "transfer").unwrap();
        let call = build_contract_call(
            1,
            c.address,
            "USDC",
            transfer,
            &[
                "0x000000000000000000000000000000000000dead".into(),
                "1 ether".into(),
            ],
            "0",
        )
        .unwrap();
        assert_eq!(call.decoded_args[1].value, "1000000000000000000");
        assert_eq!(
            call.decoded_args[0].value, "0x000000000000000000000000000000000000dEaD",
            "an address reads back checksummed, however it was typed"
        );
    }

    #[test]
    fn the_queue_detail_line_quotes_the_decoded_amount() {
        let c = usdc();
        let transfer = c.methods.iter().find(|m| m.name == "transfer").unwrap();
        let call = build_contract_call(
            1,
            c.address,
            "USDC",
            transfer,
            &[CHECKSUMMED.into(), "1 ether".into()],
            "0",
        )
        .unwrap();
        assert!(
            call.detail.contains("1000000000000000000"),
            "{}",
            call.detail
        );
        assert!(!call.detail.contains("ether"), "{}", call.detail);
    }

    #[test]
    fn the_integer_hint_names_the_units_the_parser_accepts() {
        let hint = type_hint("uint256");
        assert!(hint.contains("base units"), "{hint}");
        assert!(hint.contains("ether"), "{hint}");
        // `2.5 gwei` coerces, so the old "no decimals" was simply untrue.
        assert!(!hint.contains("no decimals"), "{hint}");
        let ty: DynSolType = "uint256".parse().unwrap();
        assert!(is_valid(&ty, "2.5 gwei"));
        assert!(!is_valid(&ty, "1.5"), "a bare fraction really is refused");
    }

    /// The bug this replaced: the scalar arms are prefix tests, so an array
    /// took its *element's* hint. `uint256[]` advertised "base units — 1e18 …"
    /// and `bytes32[]` advertised "0x… hex", each describing one item of a list
    /// the field actually wants written `[a, b]`.
    #[test]
    fn a_list_is_not_hinted_as_one_of_its_items() {
        for ty in ["uint256[]", "bytes32[]", "address[]", "uint8[3]"] {
            let hint = type_hint(ty);
            assert!(hint.starts_with('['), "{ty} → {hint}");
            assert!(hint.contains("[] for none"), "{ty} → {hint}");
        }
        // Specifically not the scalar hints they used to inherit.
        assert!(!type_hint("uint256[]").contains("base units"));
        assert!(!type_hint("bytes32[]").starts_with("0x…"));
        // Tuples get the syntax they need too.
        let tup = type_hint("(address,uint256)");
        assert!(tup.starts_with('('), "{tup}");
    }

    /// The hints have to describe a grammar the encoder actually accepts —
    /// otherwise they're a new way to be wrong. Each composite hint is checked
    /// against a value written the way it says.
    #[test]
    fn every_hinted_shape_actually_coerces() {
        let addr = CHECKSUMMED;
        for (ty_str, value) in [
            ("uint256[]", "[1, 2]"),
            ("uint256[]", "[]"),
            ("address[]", &format!("[{addr}, {addr}]")[..]),
            ("uint8[3]", "[1, 2, 3]"),
            ("(address,uint256)", &format!("({addr}, 5)")[..]),
            ("bytes", "0x"),
            ("string", ""),
        ] {
            let ty: DynSolType = ty_str.parse().unwrap();
            // `string`'s empty case is the one exception: an empty field reads
            // as "not filled in" everywhere else, so `coerce_param` refuses it
            // and the hint says `""` rather than nothing at all.
            if value.is_empty() {
                assert!(type_hint(ty_str).contains("\"\""), "{ty_str}");
                continue;
            }
            assert!(is_valid(&ty, value), "{ty_str} should accept {value}");
        }
    }

    #[test]
    fn encoded_preview_shows_only_what_the_typing_hides() {
        let uint: DynSolType = "uint256".parse().unwrap();
        assert_eq!(
            encoded_preview(&uint, "1 ether").as_deref(),
            Some("1000000000000000000")
        );
        assert_eq!(encoded_preview(&uint, "1e6").as_deref(), Some("1000000"));
        assert!(
            encoded_preview(&uint, "1000000").is_none(),
            "a value that reads as what it encodes needs no second line"
        );
        let addr: DynSolType = "address".parse().unwrap();
        assert_eq!(
            encoded_preview(&addr, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").as_deref(),
            Some(CHECKSUMMED)
        );
    }

    #[test]
    fn parse_data_accepts_the_empty_transfer_and_refuses_bad_hex() {
        for empty in ["", "   ", "0x"] {
            assert!(parse_data(empty).unwrap().is_empty(), "{empty:?}");
        }
        assert_eq!(
            parse_data("0xdeadbeef").unwrap().as_ref(),
            &[0xde, 0xad, 0xbe, 0xef]
        );
        assert!(parse_data("0xzz").is_err());
        assert!(parse_data("0xabc").is_err(), "odd-length hex is not bytes");
    }

    #[test]
    fn parse_wei_decimal_and_hex() {
        assert_eq!(parse_wei("  ").unwrap(), U256::ZERO);
        assert_eq!(parse_wei("1000").unwrap(), U256::from(1000u64));
        assert_eq!(parse_wei("0x10").unwrap(), U256::from(16u64));
        assert!(parse_wei("12.5").is_err());
        // A bare prefix is a truncated paste. ruint parses "" as a clean
        // zero, so this used to light the value gate green and queue a call
        // carrying 0 wei.
        assert!(parse_wei("0x").is_err());
        assert!(parse_wei("0X").is_err());
        // An intentional zero is typed `0` and still parses.
        assert_eq!(parse_wei("0").unwrap(), U256::ZERO);
    }

    /// A bundle can name a method, carry arguments that decode against it, and
    /// append whatever it likes — the decoder reads the arguments it was asked
    /// for and stops. Every surface that vets a batch is built from the decoded
    /// arguments, so those extra bytes would ride to the chain unshown.
    #[test]
    fn calldata_with_a_suffix_past_the_last_argument_does_not_decode() {
        let c = usdc();
        let transfer = c.methods.iter().find(|m| m.name == "transfer").unwrap();
        let to = address!("0x000000000000000000000000000000000000dEaD");
        let clean = encode_call(transfer, &[to.to_string(), "1000000".to_string()]).unwrap();
        assert!(
            decode_args(transfer, &clean).is_some(),
            "the exactly-accounted-for encoding still decodes"
        );

        // One byte is enough: this is about accounting, not about size.
        for suffix in [
            vec![0u8; 32],
            vec![0xffu8; 7],
            vec![0x11u8; 20],
            vec![0xabu8],
        ] {
            let mut padded = clean.to_vec();
            padded.extend_from_slice(&suffix);
            assert!(
                decode_args(transfer, &padded).is_none(),
                "{} trailing byte(s) must not decode as a clean call",
                suffix.len(),
            );
        }
    }

    /// The high bits above a narrow argument are just as unaccounted-for as
    /// bytes past the end of one.
    #[test]
    fn a_non_canonical_encoding_of_the_same_arguments_does_not_decode() {
        let c = usdc();
        let transfer = c.methods.iter().find(|m| m.name == "transfer").unwrap();
        let to = address!("0x000000000000000000000000000000000000dEaD");
        let mut data = encode_call(transfer, &[to.to_string(), "1000000".to_string()])
            .unwrap()
            .to_vec();
        // Dirty the padding above the address — it still decodes to the same
        // address, and it is still a byte nobody agreed to.
        data[4] = 0xff;
        assert!(decode_args(transfer, &data).is_none());
    }

    /// The coercer enforces a narrow signed integer's ceiling but not its
    /// floor, so this has to be checked here or not at all.
    #[test]
    fn a_signed_integer_below_its_types_floor_is_refused() {
        let i8_ty: DynSolType = "int8".parse().unwrap();
        for ok in ["-128", "-1", "0", "127"] {
            assert!(is_valid(&i8_ty, ok), "int8 must accept {ok}");
        }
        for bad in ["-129", "-200", "-255", "-256", "128"] {
            assert!(!is_valid(&i8_ty, bad), "int8 must refuse {bad}");
        }

        let i24: DynSolType = "int24".parse().unwrap();
        assert!(is_valid(&i24, "-8388608"));
        assert!(!is_valid(&i24, "-8388609"));

        // The full width has no narrowing to do.
        let i256: DynSolType = "int256".parse().unwrap();
        assert!(is_valid(&i256, "-1"));

        // And the check reaches leaves nested inside compounds.
        let arr: DynSolType = "int8[]".parse().unwrap();
        assert!(is_valid(&arr, "[-128, 127]"));
        assert!(!is_valid(&arr, "[1, -129]"));
    }
}
