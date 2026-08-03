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

/// Validate a single parameter value against its type by coercing it. Ok
/// carries the encodable value; Err is a short, user-facing reason.
pub fn coerce_param(ty: &DynSolType, raw: &str) -> Result<DynSolValue, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("required".into());
    }
    ty.coerce_str(s)
        .map_err(|_| format!("expected {}", ty.sol_type_name()))
}

/// Cheap validity check for live UI feedback (the `✓ valid` / `needs T`
/// annotation). Same coercion path as [`coerce_param`].
pub fn is_valid(ty: &DynSolType, raw: &str) -> bool {
    coerce_param(ty, raw).is_ok()
}

/// A short type hint shown as the field placeholder.
pub fn type_hint(ty_str: &str) -> String {
    if ty_str == "address" {
        "0x… (20-byte address)".into()
    } else if ty_str == "bool" {
        "true / false".into()
    } else if ty_str.starts_with("uint") || ty_str.starts_with("int") {
        "integer (base units, no decimals)".into()
    } else if ty_str.starts_with("bytes") {
        "0x… hex".into()
    } else if ty_str == "string" {
        "text".into()
    } else {
        ty_str.into()
    }
}

/// Parse a wei value string — decimal or `0x`-prefixed hex.
pub fn parse_wei(raw: &str) -> Result<U256, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Ok(U256::ZERO);
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        U256::from_str_radix(hex, 16).map_err(|_| "invalid hex wei value".into())
    } else {
        s.parse::<U256>().map_err(|_| "invalid wei value".into())
    }
}

/// Parse and validate a target/recipient address.
pub fn parse_address(raw: &str) -> Result<Address, String> {
    raw.trim()
        .parse::<Address>()
        .map_err(|_| "not a 20-byte 0x… address".into())
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

    let decoded_args: Vec<DecodedArg> = method
        .inputs
        .iter()
        .enumerate()
        .map(|(i, p)| DecodedArg {
            name: p.display_name(i),
            ty: p.ty_str.clone(),
            value: values[i].trim().to_string(),
        })
        .collect();

    let title = format!("{contract_name}.{}", method.name);
    let detail = summarize_detail(method, values, value);

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
    let trimmed = data_hex.trim();
    let data = if trimmed.is_empty() || trimmed == "0x" {
        Bytes::new()
    } else {
        let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        let raw = alloy::hex::decode(hex)
            .map_err(|_| TxBuilderError::Input("data is not valid hex".into()))?;
        Bytes::from(raw)
    };
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

/// A friendly one-line detail for the queue card. Falls back to the first
/// argument for methods we don't special-case.
fn summarize_detail(method: &AbiMethod, values: &[String], value: U256) -> String {
    let arg = |i: usize| values.get(i).map(|s| s.trim()).unwrap_or("");
    let short = |s: &str| {
        s.parse::<Address>()
            .map(crate::wallet::short_address)
            .unwrap_or_else(|_| s.to_string())
    };
    match method.name.as_str() {
        "transfer" | "approve" if method.inputs.len() >= 2 => {
            format!("{} → {}", arg(1), short(arg(0)))
        }
        "deposit" if method.payable => format!("wrap {value} wei"),
        _ if method.inputs.is_empty() => "no arguments".into(),
        _ => {
            let first = &method.inputs[0];
            format!("{}: {}", first.display_name(0), short(arg(0)))
        }
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

    #[test]
    fn parse_wei_decimal_and_hex() {
        assert_eq!(parse_wei("  ").unwrap(), U256::ZERO);
        assert_eq!(parse_wei("1000").unwrap(), U256::from(1000u64));
        assert_eq!(parse_wei("0x10").unwrap(), U256::from(16u64));
        assert!(parse_wei("12.5").is_err());
    }
}
