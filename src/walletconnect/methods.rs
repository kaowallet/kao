// Phase 3 scaffolding — the UI's approve-handler at Phase 6 calls into here
// once a `WcEvent::RequestReceived` modal is accepted.
#![allow(dead_code)]

//! Wallet-side method dispatch for `wc_sessionRequest`.
//!
//! When the engine emits a [`WcEvent::RequestReceived`] for a method like
//! `personal_sign` or `eth_signTypedData_v4`, the UI shows a per-method
//! modal and — on user approval — calls into here with the live signer.
//! Each handler returns a `serde_json::Value` ready for
//! `WcCommand::ApproveRequest`, or a [`JsonRpcError`] ready for
//! `WcCommand::RejectRequest`.
//!
//! Methods covered in Phase 3:
//! - `personal_sign` — EIP-191 message signing.
//! - `eth_signTypedData_v4` — EIP-712 v4 structured-data signing.
//! - `eth_sign` — legacy raw-data signing. Rejected: no preview, easy to
//!   abuse for blind transaction signing.
//! - `wallet_addEthereumChain` — politely declined. Kao's supported chains
//!   are fixed at compile time (Mainnet/Base/Optimism); we won't accept
//!   dApp-supplied RPC URLs.
//!
//! Methods deferred to later phases:
//! - `eth_sendTransaction` / `eth_signTransaction` — Phase 4 (needs the
//!   simulate→quote→sign pipeline).
//! - `wallet_switchEthereumChain` — Phase 6 (UI for chain selection).

use alloy::dyn_abi::TypedData;
use alloy::primitives::{Address, Bytes, U256};
use alloy::signers::{Error as SignerError, UnsupportedSignerOperation};
use serde_json::{Value, json};
use tracing::warn;

use crate::chain::Chain;
use crate::wallet::KaoSigner;
use crate::wallet::tx::RawTxRequest;
use crate::walletconnect::protocol::{
    ERROR_INTERNAL, ERROR_INVALID_PARAMS, ERROR_METHOD_NOT_FOUND, ERROR_UNAUTHORIZED_CHAIN,
    ERROR_UNAUTHORIZED_METHOD, JsonRpcError,
};

/// Method names Kao is willing to grant a dApp during `wc_sessionPropose`.
/// Single source of truth — the proposal-modal grant preview and
/// `build_approved_namespaces` both consume this list. Anything outside it
/// is dropped from the granted namespace (proposal time) and rejected with
/// `-32601` (request time).
///
/// Kept in the same module as the dispatcher so a contributor adding a new
/// method handler updates one list, not two.
pub const SUPPORTED_METHODS: &[&str] = &[
    "personal_sign",
    "eth_signTypedData",
    "eth_signTypedData_v4",
    "eth_sendTransaction",
    "eth_signTransaction",
    "wallet_switchEthereumChain",
];

/// Short human-readable verb for a supported method id. Returns `None` for
/// methods outside Kao's allowlist — those should never reach the UI (the
/// proposal modal filters them upstream), so the rendering code can treat
/// `None` as a "skip" signal rather than rendering raw method names.
///
/// `eth_signTypedData` and `eth_signTypedData_v4` collapse to the same label
/// because the user-visible action ("Sign typed data") is identical; the
/// version difference is a wire-format detail.
pub fn method_label(method: &str) -> Option<&'static str> {
    match method {
        "personal_sign" => Some("Sign messages"),
        "eth_signTypedData" | "eth_signTypedData_v4" => Some("Sign typed data"),
        "eth_sendTransaction" => Some("Send transactions"),
        "eth_signTransaction" => Some("Sign transactions"),
        "wallet_switchEthereumChain" => Some("Switch chain"),
        _ => None,
    }
}

// ── Public dispatcher ────────────────────────────────────────────────────

/// Top-level dispatch. The UI's approve handler calls this with the method
/// name from `WcEvent::RequestReceived` and the params verbatim. Per-method
/// handlers do their own param parsing and validation.
///
/// `chain_id` (CAIP-2 form, e.g. `"eip155:1"`) is passed through for
/// methods that need it (`eth_signTypedData_v4` cross-checks the EIP-712
/// domain's `chainId`; `eth_sendTransaction` in Phase 4 will use it to
/// pick the provider).
pub async fn handle_method(
    signer: &KaoSigner,
    method: &str,
    params: &Value,
    chain_id: &str,
) -> Result<Value, JsonRpcError> {
    match method {
        "personal_sign" => handle_personal_sign(signer, params).await,
        "eth_signTypedData_v4" | "eth_signTypedData" => {
            handle_eth_sign_typed_data_v4(signer, params, chain_id).await
        }
        "eth_sign" => Err(JsonRpcError {
            code: ERROR_UNAUTHORIZED_METHOD,
            // `eth_sign` lets the dApp ask the wallet to sign an arbitrary
            // 32-byte hash with no preview. That's the building block of
            // every blind-sign attack: the hash can be the keccak of any
            // transaction. MetaMask deprecated it in 2023 for the same
            // reason. Refuse outright instead of trying to render it.
            message: "eth_sign is disabled — use personal_sign instead".to_string(),
            data: None,
        }),
        "eth_sendTransaction" | "eth_signTransaction" => Err(JsonRpcError {
            code: ERROR_INTERNAL,
            message: "transaction signing not yet implemented (Phase 4)".to_string(),
            data: None,
        }),
        "wallet_switchEthereumChain" => Err(JsonRpcError {
            code: ERROR_INTERNAL,
            message: "wallet_switchEthereumChain not yet implemented (Phase 6)".to_string(),
            data: None,
        }),
        "wallet_addEthereumChain" => Err(JsonRpcError {
            code: ERROR_UNAUTHORIZED_METHOD,
            message: "Kao's supported chains are fixed; cannot add dApp-supplied chains"
                .to_string(),
            data: None,
        }),
        other => Err(JsonRpcError {
            code: ERROR_METHOD_NOT_FOUND,
            message: format!("method not supported: {other}"),
            data: None,
        }),
    }
}

// ── personal_sign ────────────────────────────────────────────────────────

/// EIP-191 message signing.
///
/// Spec params: `[message: hex|utf8, address: hex]`. **However** a non-trivial
/// minority of dApps still emit them in the legacy MetaMask order
/// `[address, message]`. We accept either by trying both interpretations
/// and picking the one where the second element parses as an `Address`.
///
/// Returns: `"0x<r||s||v>"` (65-byte hex string).
pub async fn handle_personal_sign(
    signer: &KaoSigner,
    params: &Value,
) -> Result<Value, JsonRpcError> {
    let arr = params
        .as_array()
        .ok_or_else(|| invalid_params("expected array"))?;
    if arr.len() < 2 {
        return Err(invalid_params(
            "personal_sign requires [message, address] or [address, message]",
        ));
    }
    let (message_str, address) = personal_sign_decode_order(&arr[0], &arr[1])?;
    ensure_request_matches_signer(signer, address)?;
    let message_bytes = decode_personal_sign_message(&message_str)?;

    let sig = signer
        .sign_personal(&message_bytes)
        .await
        .map_err(map_signer_error)?;
    Ok(json!(format!("0x{}", hex::encode(sig.as_bytes()))))
}

/// Refuse to sign if the request's `from` doesn't match the wallet's active
/// signer. The dApp picks the address in `personal_sign` / `eth_signTypedData_v4`
/// params; the engine's scope check covers chain+method but not the per-request
/// account, so the dApp could otherwise extract a signature from whichever
/// account happens to be active at the moment of approval — a confused deputy
/// that's especially dangerous after the user account-switches mid-session.
///
/// `ERROR_UNAUTHORIZED_METHOD` (3001) is the closest WC error: the request is
/// well-formed but the wallet isn't authorised to satisfy it under the current
/// signer.
fn ensure_request_matches_signer(
    signer: &KaoSigner,
    requested: Address,
) -> Result<(), JsonRpcError> {
    let active = signer.address();
    if active != requested {
        return Err(JsonRpcError {
            code: ERROR_UNAUTHORIZED_METHOD,
            message: format!(
                "request's from {requested:#x} does not match the active wallet address {active:#x}",
            ),
            data: None,
        });
    }
    Ok(())
}

/// Decode the two-string params into `(message, address)` regardless of the
/// dApp's chosen order. Returns the message as-passed-in (still in its hex
/// or utf-8 wire form) and the parsed address.
fn personal_sign_decode_order(a: &Value, b: &Value) -> Result<(String, Address), JsonRpcError> {
    let a_str = a
        .as_str()
        .ok_or_else(|| invalid_params("non-string param"))?;
    let b_str = b
        .as_str()
        .ok_or_else(|| invalid_params("non-string param"))?;

    // Address is unambiguous: exactly 42 chars (0x + 40 hex). Whichever side
    // matches is the address; the other is the message. If both match the
    // address shape (unlikely but possible — a `0xAA...AA`-style message),
    // prefer the spec order [message, address].
    let a_is_addr = parse_address(a_str).is_ok();
    let b_is_addr = parse_address(b_str).is_ok();
    match (a_is_addr, b_is_addr) {
        (true, false) => Ok((b_str.to_string(), parse_address(a_str)?)),
        (false, true) => Ok((a_str.to_string(), parse_address(b_str)?)),
        (true, true) => Ok((a_str.to_string(), parse_address(b_str)?)),
        (false, false) => Err(invalid_params(
            "personal_sign params must include exactly one Ethereum address",
        )),
    }
}

fn parse_address(s: &str) -> Result<Address, JsonRpcError> {
    s.parse::<Address>()
        .map_err(|_| invalid_params("invalid Ethereum address"))
}

/// Per the spec, `personal_sign` accepts either:
/// - a `0x`-prefixed hex string (most dApps), or
/// - a raw UTF-8 string (older dApps, e.g. SIWE before standardisation).
///
/// We decode permissively: if the string starts with `0x` and is valid hex,
/// treat it as raw bytes; otherwise treat it as UTF-8.
fn decode_personal_sign_message(s: &str) -> Result<Vec<u8>, JsonRpcError> {
    if let Some(hexstr) = s.strip_prefix("0x")
        && let Ok(bytes) = hex::decode(hexstr)
    {
        return Ok(bytes);
    }
    Ok(s.as_bytes().to_vec())
}

// ── eth_signTypedData_v4 ─────────────────────────────────────────────────

/// EIP-712 v4 structured-data signing.
///
/// Spec params: `[address: hex, typed_data: object|string]`. The typed-data
/// payload is sometimes already a JSON object (newer dApps) and sometimes
/// a JSON-encoded string (older). We accept both.
///
/// Returns: `"0x<r||s||v>"`.
pub async fn handle_eth_sign_typed_data_v4(
    signer: &KaoSigner,
    params: &Value,
    chain_id: &str,
) -> Result<Value, JsonRpcError> {
    let arr = params
        .as_array()
        .ok_or_else(|| invalid_params("expected array"))?;
    if arr.len() < 2 {
        return Err(invalid_params(
            "eth_signTypedData_v4 requires [address, typed_data]",
        ));
    }

    // First element is always the address (no order ambiguity here — the
    // typed-data side is a structured object/string, never an address).
    let address = arr[0]
        .as_str()
        .ok_or_else(|| invalid_params("address must be a string"))?
        .parse::<Address>()
        .map_err(|_| invalid_params("invalid address"))?;
    ensure_request_matches_signer(signer, address)?;

    // Second element: object OR JSON-encoded string.
    let typed_data: TypedData = match &arr[1] {
        Value::String(s) => serde_json::from_str(s)
            .map_err(|e| invalid_params(format!("typed_data JSON parse: {e}")))?,
        v @ Value::Object(_) => serde_json::from_value(v.clone())
            .map_err(|e| invalid_params(format!("typed_data object parse: {e}")))?,
        _ => {
            return Err(invalid_params(
                "typed_data must be an object or JSON string",
            ));
        }
    };

    // Defence-in-depth chain check: the EIP-712 domain's `chainId` (when
    // present) must match the WC namespace's chainId. The dApp can otherwise
    // ask the wallet to sign a typed payload bound to a different chain than
    // the session approved — opening the door to replay attacks on the chain
    // the user thought they had selected.
    if let Some(expected) = parse_eip155_chain(chain_id)
        && let Some(domain_chain) = typed_data.domain().chain_id
        && expected != domain_chain.to::<u64>()
    {
        return Err(invalid_params(format!(
            "typed_data domain.chainId {} doesn't match session chain {}",
            domain_chain, expected
        )));
    }

    let sig = signer
        .sign_typed_data(&typed_data)
        .await
        .map_err(map_signer_error)?;
    Ok(json!(format!("0x{}", hex::encode(sig.as_bytes()))))
}

/// Strip the `eip155:` CAIP-2 prefix and parse the chain id. Returns `None`
/// for non-EIP-155 chain ids — we only EIP-712-sign on EVM chains.
fn parse_eip155_chain(caip2: &str) -> Option<u64> {
    caip2.strip_prefix("eip155:").and_then(|n| n.parse().ok())
}

// ── eth_sendTransaction / eth_signTransaction param parsing ──────────────
//
// These two methods share a parser — the only difference is what the caller
// does with the result (broadcast vs. return the envelope to the dApp). The
// dispatcher in `handle_method` deliberately doesn't call them: producing a
// `RawTxRequest` is only step 1 of a flow that also needs a provider, a
// network handle, a UI approval modal, and a quote+sign pipeline. Phase 6
// wires those together at the App level. Until then the public surface is
// the parser alone, callable by the UI's per-method handler when
// `WcEvent::RequestReceived { method: "eth_sendTransaction", .. }` arrives.

/// Parse the WalletConnect `eth_sendTransaction` params block into a
/// [`RawTxRequest`]. Both `eth_sendTransaction` and `eth_signTransaction`
/// share this shape — the wire format is identical, only the wallet-side
/// post-processing diverges (broadcast vs. return envelope).
///
/// Params: `[{from, to?, value?, data?, gas?, nonce?, maxFeePerGas?,
/// maxPriorityFeePerGas?, gasPrice?}]` — single-element array carrying a
/// tx-object. All hex strings are EIP-1474-style (`0x`-prefixed
/// big-endian).
///
/// CAIP-2 chain id is validated against Kao's supported set; unsupported
/// chains return `ERROR_UNAUTHORIZED_CHAIN`.
///
/// Hints (`gas`, `nonce`, fees) are propagated into [`RawTxRequest`]
/// where the quote layer decides how to use them — under-estimates are
/// floored to our local estimate, nonce mismatches are hard errors. See
/// [`crate::wallet::tx::build_quote_raw`] for the policy.
pub fn parse_eth_send_transaction_params(
    params: &Value,
    chain_id: &str,
) -> Result<RawTxRequest, JsonRpcError> {
    let chain = caip2_to_chain(chain_id)?;

    let arr = params.as_array().ok_or_else(|| {
        invalid_params("eth_sendTransaction params must be a single-element array")
    })?;
    let tx = arr
        .first()
        .ok_or_else(|| invalid_params("eth_sendTransaction params array is empty"))?;
    let obj = tx
        .as_object()
        .ok_or_else(|| invalid_params("tx must be a JSON object"))?;

    let from_raw = obj
        .get("from")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params("tx.from is required"))?;
    let from: Address = from_raw
        .parse()
        .map_err(|_| invalid_params(format!("tx.from not a valid address: {from_raw}")))?;

    // `to` is optional — `None` means contract creation. dApps occasionally
    // send `to: ""` or `to: null`; normalize both to the Create form.
    let to: Option<Address> = match obj.get("to") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::String(s)) => Some(
            s.parse()
                .map_err(|_| invalid_params(format!("tx.to not a valid address: {s}")))?,
        ),
        _ => return Err(invalid_params("tx.to must be a hex string or null")),
    };

    let value = parse_hex_u256_opt(obj.get("value"), "tx.value")?.unwrap_or(U256::ZERO);
    let input = parse_hex_bytes_opt(obj.get("data"))?
        .or_else(|| parse_hex_bytes_opt(obj.get("input")).ok().flatten())
        .unwrap_or_default();

    let gas_limit_hint = parse_hex_u64_opt(obj.get("gas"), "tx.gas")?;
    let nonce_hint = parse_hex_u64_opt(obj.get("nonce"), "tx.nonce")?;

    // Reject `gasPrice` outright — Kao broadcasts EIP-1559 envelopes only,
    // and a dApp asking for legacy pricing is either ancient or trying to
    // skip the basefee/tip review the user sees on 1559 txs. The (handful
    // of) legacy-only dApps would already fail at our broadcast layer; the
    // explicit error is just a clearer surface.
    if let Some(v) = obj.get("gasPrice")
        && !v.is_null()
    {
        return Err(invalid_params(
            "legacy gasPrice not supported; use EIP-1559 maxFeePerGas/maxPriorityFeePerGas",
        ));
    }

    Ok(RawTxRequest {
        from,
        to,
        value,
        input,
        chain,
        gas_limit_hint,
        nonce_hint,
    })
}

/// `eth_signTransaction` shares the parser with `eth_sendTransaction` —
/// alias for caller-readability at the dispatch site.
pub fn parse_eth_sign_transaction_params(
    params: &Value,
    chain_id: &str,
) -> Result<RawTxRequest, JsonRpcError> {
    parse_eth_send_transaction_params(params, chain_id)
}

/// CAIP-2 → `Chain`. Errors with `ERROR_UNAUTHORIZED_CHAIN` (3005) on
/// chains outside Kao's supported set — the dApp asked us to transact on
/// a chain we never approved in the session, even if it accidentally was
/// in the session's chain list (defence in depth in case `sessionSettle`'s
/// namespace check ever drifts).
fn caip2_to_chain(caip2: &str) -> Result<Chain, JsonRpcError> {
    let id = parse_eip155_chain(caip2).ok_or_else(|| JsonRpcError {
        code: ERROR_UNAUTHORIZED_CHAIN,
        message: format!("non-EIP-155 chain ids unsupported: {caip2}"),
        data: None,
    })?;
    Chain::from_chain_id(id).ok_or_else(|| JsonRpcError {
        code: ERROR_UNAUTHORIZED_CHAIN,
        message: format!("chain eip155:{id} not supported by this wallet"),
        data: None,
    })
}

fn parse_hex_u256_opt(v: Option<&Value>, label: &str) -> Result<Option<U256>, JsonRpcError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let hex = s.strip_prefix("0x").unwrap_or(s);
            if hex.is_empty() {
                return Ok(None);
            }
            U256::from_str_radix(hex, 16)
                .map(Some)
                .map_err(|_| invalid_params(format!("{label} not a valid hex U256: {s}")))
        }
        _ => Err(invalid_params(format!("{label} must be a hex string"))),
    }
}

fn parse_hex_u64_opt(v: Option<&Value>, label: &str) -> Result<Option<u64>, JsonRpcError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let hex = s.strip_prefix("0x").unwrap_or(s);
            if hex.is_empty() {
                return Ok(None);
            }
            u64::from_str_radix(hex, 16)
                .map(Some)
                .map_err(|_| invalid_params(format!("{label} not a valid hex u64: {s}")))
        }
        _ => Err(invalid_params(format!("{label} must be a hex string"))),
    }
}

fn parse_hex_bytes_opt(v: Option<&Value>) -> Result<Option<Bytes>, JsonRpcError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            if s.is_empty() || s == "0x" {
                return Ok(Some(Bytes::new()));
            }
            let hex = s.strip_prefix("0x").unwrap_or(s);
            hex::decode(hex)
                .map(|b| Some(Bytes::from(b)))
                .map_err(|_| invalid_params(format!("tx.data not valid hex: {s}")))
        }
        _ => Err(invalid_params("tx.data must be a hex string")),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn invalid_params(msg: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: ERROR_INVALID_PARAMS,
        message: msg.into(),
        data: None,
    }
}

/// Map an `alloy::signers::Error` onto a JSON-RPC error. Surfaces the
/// Trezor-typed-data gap with a clear user-facing message so the UI banner
/// can quote it verbatim.
fn map_signer_error(e: SignerError) -> JsonRpcError {
    match e {
        SignerError::UnsupportedOperation(UnsupportedSignerOperation::SignTypedData) => {
            JsonRpcError {
                code: ERROR_UNAUTHORIZED_METHOD,
                // The only signer that hits this path for typed-data is
                // Trezor (alloy-signer-trezor 2.0.1 doesn't wire the
                // device's protobuf typed-data flow) or ViewOnly. The UI
                // can read `data` to decide whether to offer a fallback
                // ("blind-sign the hash anyway?") for Trezor specifically
                // — that opt-in is Phase 7 hardening.
                message: "this signer cannot display EIP-712 typed data".to_string(),
                data: Some(json!({ "reason": "typed_data_unsupported" })),
            }
        }
        SignerError::UnsupportedOperation(UnsupportedSignerOperation::SignMessage) => {
            JsonRpcError {
                code: ERROR_UNAUTHORIZED_METHOD,
                message: "this signer cannot sign messages (view-only account)".to_string(),
                data: None,
            }
        }
        SignerError::UnsupportedOperation(op) => JsonRpcError {
            code: ERROR_UNAUTHORIZED_METHOD,
            message: format!("signer unsupported operation: {op}"),
            data: None,
        },
        other => {
            // User-cancelled-on-device, USB disconnected, etc. Log the
            // detail but don't leak the raw stringly-typed error to the
            // dApp — surface a generic "signing failed" so the dApp can
            // back off without inferring wallet internals.
            warn!(error = ?other, "signer failure during WC method dispatch");
            JsonRpcError {
                code: ERROR_INTERNAL,
                message: "signing failed".to_string(),
                data: None,
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;
    use alloy::signers::local::PrivateKeySigner;

    fn local_signer() -> (KaoSigner, Address) {
        let key = PrivateKeySigner::random();
        let addr = key.address();
        (KaoSigner::Local(key), addr)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn personal_sign_round_trip_hex_message() {
        let (signer, addr) = local_signer();
        // "Hello Kao" as 0x-hex.
        let result = handle_personal_sign(
            &signer,
            &json!(["0x48656c6c6f204b616f", format!("{addr:#x}")]),
        )
        .await
        .unwrap();
        let hex_sig = result.as_str().unwrap();
        assert!(hex_sig.starts_with("0x"));
        let sig_bytes = hex::decode(&hex_sig[2..]).unwrap();
        assert_eq!(sig_bytes.len(), 65);

        // Verify recovery: the produced signature must recover the
        // signer's address against the EIP-191 personal_sign hash of the
        // original message.
        let sig: alloy::primitives::Signature =
            alloy::primitives::Signature::from_raw(&sig_bytes).unwrap();
        let recovered = sig.recover_address_from_msg(b"Hello Kao".as_ref()).unwrap();
        assert_eq!(recovered, addr);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn personal_sign_round_trip_utf8_message() {
        let (signer, addr) = local_signer();
        // dApp sent a raw UTF-8 string (no 0x prefix).
        let result = handle_personal_sign(&signer, &json!(["Hello Kao", format!("{addr:#x}")]))
            .await
            .unwrap();
        let sig_bytes = hex::decode(&result.as_str().unwrap()[2..]).unwrap();
        let sig: alloy::primitives::Signature =
            alloy::primitives::Signature::from_raw(&sig_bytes).unwrap();
        let recovered = sig.recover_address_from_msg(b"Hello Kao".as_ref()).unwrap();
        assert_eq!(recovered, addr);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn personal_sign_accepts_swapped_param_order() {
        // Legacy dApps put [address, message] — handler should still work.
        let (signer, addr) = local_signer();
        let result = handle_personal_sign(
            &signer,
            &json!([format!("{addr:#x}"), "0x48656c6c6f204b616f"]),
        )
        .await
        .unwrap();
        let sig_bytes = hex::decode(&result.as_str().unwrap()[2..]).unwrap();
        let sig: alloy::primitives::Signature =
            alloy::primitives::Signature::from_raw(&sig_bytes).unwrap();
        let recovered = sig.recover_address_from_msg(b"Hello Kao".as_ref()).unwrap();
        assert_eq!(recovered, addr);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn personal_sign_view_only_returns_unauthorized() {
        let signer = KaoSigner::ViewOnly(Address::ZERO);
        let err = handle_personal_sign(
            &signer,
            &json!(["0xdead", "0x0000000000000000000000000000000000000000"]),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ERROR_UNAUTHORIZED_METHOD);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn personal_sign_rejects_from_other_than_signer() {
        // dApp asked for a signature `from` address X, but the wallet's
        // active signer is Y. Must refuse — otherwise an attacker can
        // extract a signature from whichever account happens to be
        // active when the user clicks Approve.
        let (signer, _signer_addr) = local_signer();
        let other = Address::from([0x11; 20]);
        let err = handle_personal_sign(
            &signer,
            &json!(["0x48656c6c6f", format!("{other:#x}")]),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ERROR_UNAUTHORIZED_METHOD);
        assert!(err.message.contains("does not match"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn typed_data_v4_rejects_from_other_than_signer() {
        let (signer, _signer_addr) = local_signer();
        let other = Address::from([0x22; 20]);
        let typed_data = json!({
            "types": {"EIP712Domain":[{"name":"chainId","type":"uint256"}],"X":[{"name":"a","type":"uint256"}]},
            "primaryType": "X",
            "domain": {"chainId": 1},
            "message": {"a": "1"}
        });
        let err = handle_eth_sign_typed_data_v4(
            &signer,
            &json!([format!("{other:#x}"), typed_data]),
            "eip155:1",
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ERROR_UNAUTHORIZED_METHOD);
        assert!(err.message.contains("does not match"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn personal_sign_rejects_missing_address() {
        let (signer, _) = local_signer();
        let err = handle_personal_sign(&signer, &json!(["just-a-message", "also-not-address"]))
            .await
            .unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_PARAMS);
    }

    /// EIP-712 round trip with a minimal Permit-style typed data.
    /// Verifies the signature recovers the signer's address against the
    /// canonical EIP-712 hash.
    #[tokio::test(flavor = "current_thread")]
    async fn typed_data_v4_round_trip() {
        let (signer, addr) = local_signer();

        // Minimal EIP-2612 Permit typed data on Mainnet (chainId=1).
        let typed_data = json!({
            "types": {
                "EIP712Domain": [
                    {"name":"name","type":"string"},
                    {"name":"version","type":"string"},
                    {"name":"chainId","type":"uint256"},
                    {"name":"verifyingContract","type":"address"}
                ],
                "Permit": [
                    {"name":"owner","type":"address"},
                    {"name":"spender","type":"address"},
                    {"name":"value","type":"uint256"},
                    {"name":"nonce","type":"uint256"},
                    {"name":"deadline","type":"uint256"}
                ]
            },
            "primaryType": "Permit",
            "domain": {
                "name": "USD Coin",
                "version": "2",
                "chainId": 1,
                "verifyingContract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
            },
            "message": {
                "owner": format!("{addr:#x}"),
                "spender": "0x1111111111111111111111111111111111111111",
                "value": "1000000",
                "nonce": "0",
                "deadline": "9999999999"
            }
        });

        let result = handle_eth_sign_typed_data_v4(
            &signer,
            &json!([format!("{addr:#x}"), typed_data.clone()]),
            "eip155:1",
        )
        .await
        .unwrap();
        let sig_bytes = hex::decode(&result.as_str().unwrap()[2..]).unwrap();
        assert_eq!(sig_bytes.len(), 65);

        // Verify recovery against the EIP-712 hash.
        let td: TypedData = serde_json::from_value(typed_data).unwrap();
        let prehash = td.eip712_signing_hash().unwrap();
        let sig: alloy::primitives::Signature =
            alloy::primitives::Signature::from_raw(&sig_bytes).unwrap();
        let recovered = sig.recover_address_from_prehash(&prehash).unwrap();
        assert_eq!(recovered, addr);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn typed_data_v4_accepts_json_string_form() {
        // Some dApps pass the typed_data as a JSON-encoded string rather
        // than as an object — handler accepts both.
        let (signer, addr) = local_signer();
        let td_string = serde_json::to_string(&json!({
            "types": {
                "EIP712Domain": [
                    {"name":"chainId","type":"uint256"}
                ],
                "Hello": [
                    {"name":"greeting","type":"string"}
                ]
            },
            "primaryType": "Hello",
            "domain": {"chainId": 1},
            "message": {"greeting": "kao"}
        }))
        .unwrap();
        let result = handle_eth_sign_typed_data_v4(
            &signer,
            &json!([format!("{addr:#x}"), td_string]),
            "eip155:1",
        )
        .await
        .unwrap();
        assert!(result.as_str().unwrap().starts_with("0x"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn typed_data_v4_rejects_chain_mismatch() {
        // dApp says session is on Mainnet, but typed_data.domain.chainId = 10.
        let (signer, addr) = local_signer();
        let typed_data = json!({
            "types": {"EIP712Domain":[{"name":"chainId","type":"uint256"}],"X":[{"name":"a","type":"uint256"}]},
            "primaryType": "X",
            "domain": {"chainId": 10},
            "message": {"a": "1"}
        });
        let err = handle_eth_sign_typed_data_v4(
            &signer,
            &json!([format!("{addr:#x}"), typed_data]),
            "eip155:1",
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_PARAMS);
        assert!(err.message.contains("chainId"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn typed_data_v4_view_only_returns_unauthorized() {
        let signer = KaoSigner::ViewOnly(Address::ZERO);
        let typed_data = json!({
            "types": {"EIP712Domain":[],"X":[{"name":"a","type":"uint256"}]},
            "primaryType": "X",
            "domain": {},
            "message": {"a":"1"}
        });
        let err = handle_eth_sign_typed_data_v4(
            &signer,
            &json!(["0x0000000000000000000000000000000000000000", typed_data]),
            "eip155:1",
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ERROR_UNAUTHORIZED_METHOD);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn eth_sign_is_disabled() {
        let (signer, _) = local_signer();
        let err = handle_method(&signer, "eth_sign", &json!([]), "eip155:1")
            .await
            .unwrap_err();
        assert_eq!(err.code, ERROR_UNAUTHORIZED_METHOD);
        assert!(err.message.contains("disabled"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unknown_method_returns_minus_32601() {
        let (signer, _) = local_signer();
        let err = handle_method(&signer, "eth_subscribe", &json!([]), "eip155:1")
            .await
            .unwrap_err();
        assert_eq!(err.code, ERROR_METHOD_NOT_FOUND);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wallet_add_chain_is_declined() {
        let (signer, _) = local_signer();
        let err = handle_method(&signer, "wallet_addEthereumChain", &json!([]), "eip155:1")
            .await
            .unwrap_err();
        assert_eq!(err.code, ERROR_UNAUTHORIZED_METHOD);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dispatch_routes_personal_sign() {
        let (signer, addr) = local_signer();
        let result = handle_method(
            &signer,
            "personal_sign",
            &json!(["0x48", format!("{addr:#x}")]),
            "eip155:1",
        )
        .await
        .unwrap();
        assert!(result.as_str().unwrap().starts_with("0x"));
    }

    // Defence-in-depth: a JsonRpcError carrying `data.reason` lets the UI
    // distinguish "Trezor can't display typed data" from other unsupported
    // cases. Verify the marker is present for the typed-data unsupported
    // path so a future UI refactor doesn't silently lose it.
    #[test]
    fn map_signer_error_marks_typed_data_unsupported() {
        let err = map_signer_error(SignerError::UnsupportedOperation(
            UnsupportedSignerOperation::SignTypedData,
        ));
        assert_eq!(err.code, ERROR_UNAUTHORIZED_METHOD);
        assert_eq!(
            err.data.as_ref().and_then(|d| d.get("reason")),
            Some(&json!("typed_data_unsupported"))
        );
    }

    // Sanity-check that the dispatcher signature compiles against U256
    // payloads in the rare case where a dApp serialises a numeric chainId
    // — currently unused but locks in the API shape.
    #[test]
    fn chain_id_parser_strips_eip155_prefix() {
        assert_eq!(parse_eip155_chain("eip155:1"), Some(1));
        assert_eq!(parse_eip155_chain("eip155:8453"), Some(8453));
        assert_eq!(parse_eip155_chain("solana:101"), None);
        assert_eq!(parse_eip155_chain("eip155:notanumber"), None);
    }

    #[test]
    fn u256_is_in_scope_for_typed_data_tests() {
        // Sanity-check that U256 is still in scope; used by typed_data
        // assertions in future tests. Locks the alloy version in.
        let _ = U256::from(1u64);
    }

    // ── eth_sendTransaction parser tests ─────────────────────────────

    fn typical_send_tx() -> Value {
        // A swap-style payload: real `from`, `to`, value=0, hex calldata.
        json!([{
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x4200000000000000000000000000000000000010",
            "value": "0x0",
            "data": "0xa9059cbb000000000000000000000000222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000000000000003e8",
            "gas": "0x186a0",
            "nonce": "0x5"
        }])
    }

    #[test]
    fn parse_send_tx_happy_path() {
        let raw = parse_eth_send_transaction_params(&typical_send_tx(), "eip155:1").unwrap();
        assert_eq!(raw.chain, Chain::Mainnet);
        assert_eq!(
            raw.from,
            "0x1111111111111111111111111111111111111111"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(
            raw.to,
            Some(
                "0x4200000000000000000000000000000000000010"
                    .parse::<Address>()
                    .unwrap()
            )
        );
        assert_eq!(raw.value, U256::ZERO);
        assert_eq!(raw.input.len(), 68); // ERC-20 transfer calldata length.
        assert_eq!(raw.gas_limit_hint, Some(100_000));
        assert_eq!(raw.nonce_hint, Some(5));
    }

    #[test]
    fn parse_send_tx_accepts_omitted_optional_fields() {
        // Minimal viable: only `from` and `to`. Everything else defaults.
        let params = json!([{
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222"
        }]);
        let raw = parse_eth_send_transaction_params(&params, "eip155:1").unwrap();
        assert_eq!(raw.value, U256::ZERO);
        assert!(raw.input.is_empty());
        assert_eq!(raw.gas_limit_hint, None);
        assert_eq!(raw.nonce_hint, None);
    }

    #[test]
    fn parse_send_tx_accepts_contract_creation() {
        // `to: null` (or omitted) means create — bytecode lives in `data`.
        let params = json!([{
            "from": "0x1111111111111111111111111111111111111111",
            "to": null,
            "data": "0x6080604052"
        }]);
        let raw = parse_eth_send_transaction_params(&params, "eip155:1").unwrap();
        assert_eq!(raw.to, None);
        assert_eq!(raw.input.len(), 5);

        // And `to` field outright omitted.
        let params2 = json!([{
            "from": "0x1111111111111111111111111111111111111111",
            "data": "0x6080604052"
        }]);
        let raw2 = parse_eth_send_transaction_params(&params2, "eip155:1").unwrap();
        assert_eq!(raw2.to, None);
    }

    #[test]
    fn parse_send_tx_accepts_input_alias() {
        // Spec calls the calldata field `data`; some dApps still emit `input`.
        // Accept both — `data` wins if both present.
        let params = json!([{
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "input": "0xdeadbeef"
        }]);
        let raw = parse_eth_send_transaction_params(&params, "eip155:1").unwrap();
        assert_eq!(raw.input.as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_send_tx_missing_from_is_invalid_params() {
        let params = json!([{
            "to": "0x2222222222222222222222222222222222222222"
        }]);
        let err = parse_eth_send_transaction_params(&params, "eip155:1").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_PARAMS);
        assert!(err.message.contains("from"));
    }

    #[test]
    fn parse_send_tx_rejects_bad_address() {
        let params = json!([{
            "from": "0xnotanaddress",
            "to": "0x2222222222222222222222222222222222222222"
        }]);
        let err = parse_eth_send_transaction_params(&params, "eip155:1").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_PARAMS);
    }

    #[test]
    fn parse_send_tx_rejects_unsupported_chain() {
        let params = json!([{
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222"
        }]);
        // Arbitrum (42161) — not in Kao's enum.
        let err = parse_eth_send_transaction_params(&params, "eip155:42161").unwrap_err();
        assert_eq!(err.code, ERROR_UNAUTHORIZED_CHAIN);

        // Non-EIP-155 CAIP-2 namespace.
        let err2 = parse_eth_send_transaction_params(&params, "solana:101").unwrap_err();
        assert_eq!(err2.code, ERROR_UNAUTHORIZED_CHAIN);
    }

    #[test]
    fn parse_send_tx_rejects_legacy_gas_price() {
        let params = json!([{
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "gasPrice": "0x3b9aca00"
        }]);
        let err = parse_eth_send_transaction_params(&params, "eip155:1").unwrap_err();
        assert_eq!(err.code, ERROR_INVALID_PARAMS);
        assert!(err.message.contains("gasPrice"));
    }

    #[test]
    fn parse_send_tx_accepts_value_in_hex() {
        let params = json!([{
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "value": "0xde0b6b3a7640000"  // 1 ETH in wei.
        }]);
        let raw = parse_eth_send_transaction_params(&params, "eip155:1").unwrap();
        assert_eq!(raw.value, U256::from(1_000_000_000_000_000_000u128));
    }

    #[test]
    fn parse_send_tx_normalizes_empty_to_field_to_create() {
        let params = json!([{
            "from": "0x1111111111111111111111111111111111111111",
            "to": "",
            "data": "0x60"
        }]);
        let raw = parse_eth_send_transaction_params(&params, "eip155:1").unwrap();
        assert_eq!(raw.to, None);
    }

    #[test]
    fn parse_sign_tx_alias_matches_send_tx() {
        let parsed_a =
            parse_eth_send_transaction_params(&typical_send_tx(), "eip155:8453").unwrap();
        let parsed_b =
            parse_eth_sign_transaction_params(&typical_send_tx(), "eip155:8453").unwrap();
        assert_eq!(parsed_a.chain, parsed_b.chain);
        assert_eq!(parsed_a.from, parsed_b.from);
        assert_eq!(parsed_a.to, parsed_b.to);
        assert_eq!(parsed_a.value, parsed_b.value);
        assert_eq!(parsed_a.input, parsed_b.input);
    }

    // ── sign_raw envelope tests ─────────────────────────────────────

    /// `sign_raw` (in `wallet::tx`) produces an envelope whose recovered
    /// signer matches the wallet's address. Confirms the cross-module wire
    /// — `RawTxRequest` from methods.rs flows into `sign_raw` correctly,
    /// the chain id is baked in, and the resulting envelope decodes.
    #[tokio::test(flavor = "current_thread")]
    async fn sign_raw_envelope_recovers_signer_address() {
        use crate::wallet::sim::SimulationResult;
        use crate::wallet::tx::{RawTxRequest, TxQuote, sign_raw};
        use alloy::consensus::transaction::SignerRecoverable;
        use alloy::consensus::{Transaction, TxEnvelope};
        use alloy::eips::eip2718::Decodable2718;
        use alloy::primitives::TxKind;
        use alloy::signers::local::PrivateKeySigner;

        let key = PrivateKeySigner::random();
        let addr = key.address();
        let signer = KaoSigner::Local(key);

        let raw = RawTxRequest {
            from: addr,
            to: Some(
                "0x4200000000000000000000000000000000000010"
                    .parse()
                    .unwrap(),
            ),
            value: U256::from(42u64),
            input: Bytes::from(&[0x01, 0x02, 0x03][..]),
            chain: Chain::Mainnet,
            gas_limit_hint: None,
            nonce_hint: None,
        };
        let quote = TxQuote {
            gas_limit: 21_000,
            max_fee_per_gas: 30_000_000_000,
            max_priority_fee_per_gas: 1_500_000_000,
            nonce: 7,
            eth_cost_wei: U256::ZERO,
            sim: SimulationResult::unavailable(),
        };
        let (hash, envelope_bytes) = sign_raw(&signer, &raw, &quote).await.unwrap();

        // Round-trip the envelope to confirm wire-format correctness, then
        // check the recovered sender matches the wallet address.
        let envelope: TxEnvelope = TxEnvelope::decode_2718(&mut envelope_bytes.as_ref()).unwrap();
        assert_eq!(*envelope.tx_hash(), hash);
        let recovered = envelope.recover_signer().unwrap();
        assert_eq!(recovered, addr);
        // Chain id baked into the signed envelope must match the request.
        assert_eq!(envelope.chain_id(), Some(1));
        // `to` and `value` survived.
        match envelope.kind() {
            TxKind::Call(to) => assert_eq!(
                to,
                "0x4200000000000000000000000000000000000010"
                    .parse::<Address>()
                    .unwrap()
            ),
            TxKind::Create => panic!("expected Call"),
        }
    }
}
