//! Session-request validation: [`validate`] is THE parameter choke point — every dapp request
//! becomes an [`Admitted`] call or a [`Refusal`] here, before anything is queued or shown. Pure;
//! never panics on any input.
//!
//! The crate has already checked that the session exists, the request's chain is one of the
//! session's chains and the method was granted. It never looks inside `params`; everything about
//! them — who the request claims to sign as, which chain it binds to, what a transaction carries —
//! is decided here, and every dapp-visible answer is a static string (`Refusal::message`).

use std::sync::Arc;

use alloy::primitives::{Address, B256, TxKind, U256, hex};
use alloy::rpc::types::TransactionRequest;
use alloy::sol_types::SolCall;
use wallet_connect::sign::PendingRequest;
use wallet_connect::uri::PairingUri;

use super::types::*;
use super::{MAX_SUMMARY_CHARS, MAX_TX_DATA_BYTES, message, parse_eip155, typed};
use crate::sanitize::sanitize_display;
use crate::wallet::short_address;

const GAS_LIMIT_CEILING: u64 = 30_000_000;

/// EIP-7825's per-transaction gas cap (2^24), enforced at the txpool on mainnet since Fusaka: a
/// node refuses a transaction whose limit is above it.
pub const MAX_TX_GAS: u64 = 1 << 24;

/// A pasted link is a couple of hundred chars; anything this long isn't one.
const MAX_PAIRING_URI_CHARS: usize = 4096;
/// Bound on a dapp-supplied method name quoted in a user-facing detail.
const MAX_METHOD_CHARS: usize = 48;

const INVALID_LINK: &str = "That isn't a valid WalletConnect link — copy it again from the dapp.";
const EXPIRED_LINK: &str = "This link has expired — get a fresh one from the dapp.";
/// A pairing or an approve that reached a runtime already closing (Turn off, a retire, a lock).
/// The next attempt starts a fresh one.
pub(crate) const RUNTIME_CLOSED: &str = "WalletConnect is shutting down — try again in a moment.";

alloy::sol! {
    /// Safe's on-chain owner confirmation: marks `hashToApprove` as signed by `msg.sender`.
    function approveHash(bytes32 hashToApprove) external;
}

/// Raw transaction keys that only blob (EIP-4844) transactions carry; the
/// flattened sidecar in `TransactionRequest` would swallow a malformed one.
const BLOB_KEYS: &[&str] = &[
    "blobVersionedHashes",
    "maxFeePerBlobGas",
    "blobs",
    "commitments",
    "proofs",
    "sidecar",
];

/// THE parameter-validation choke point. Pure; never panics on any input.
///
/// Order: the session/identity/chain/method envelope, then the identity's
/// capability for the method (so a Trezor never has its typed data parsed),
/// then the params — whose claimed signer must be the session's identity.
pub fn validate(
    req: &PendingRequest,
    session: &BoundSession,
    caps: &IdentityCaps,
) -> Result<Admitted, Refusal> {
    if caps.identity != session.identity {
        return Err(Refusal::unauthorized(
            "the account's capabilities don't belong to this session's account",
        ));
    }
    let Some(chain_id) = parse_eip155(&req.chain_id) else {
        return Err(Refusal::invalid_params(
            "Unsupported chain id.",
            "the request names a chain that isn't a valid eip155 chain id",
        ));
    };
    if !session.chains.contains(&chain_id) {
        return Err(Refusal::chain_not_served(format!(
            "chain {chain_id} isn't part of this session"
        )));
    }
    if let WcIdentity::Safe {
        chain_id: safe_chain,
        ..
    } = session.identity
        && safe_chain != chain_id
    {
        return Err(Refusal::chain_not_served(format!(
            "this Safe lives on chain {safe_chain}, not chain {chain_id}"
        )));
    }
    if !caps.serves_chain(chain_id) {
        return Err(Refusal::chain_not_served(format!(
            "{} isn't available in Kao any more",
            super::chain_label(chain_id)
        )));
    }
    let method = req.request.method.as_str();
    if !session.methods.iter().any(|m| m == method) {
        return Err(Refusal::unsupported(
            "This method wasn't granted to the session.",
            format!(
                "the dapp called {}, which this session doesn't allow",
                sanitize_display(method, MAX_METHOD_CHARS)
            ),
        ));
    }

    let params = &req.request.params;
    let call = match method {
        "personal_sign" => {
            caps.messages()?;
            WcCall::PersonalSign(personal_sign(params, session, caps, chain_id)?)
        }
        "eth_signTypedData_v4" | "eth_signTypedData" => {
            caps.typed_data()?;
            WcCall::SignTypedData(sign_typed_data(params, session, chain_id)?)
        }
        "eth_sendTransaction" => {
            caps.transactions()?;
            WcCall::SendTransaction(send_transaction(params, session, chain_id)?)
        }
        "wallet_switchEthereumChain" => {
            let target = switch_target(params)?;
            if session.chains.contains(&target) && !caps.serves_chain(target) {
                return Err(Refusal::chain_not_served(format!(
                    "{} isn't available in Kao any more",
                    super::chain_label(target)
                )));
            }
            WcCall::SwitchChain { chain_id: target }
        }
        "eth_accounts" | "eth_requestAccounts" => WcCall::Accounts,
        "eth_chainId" => WcCall::ChainId,
        other => return Err(refused_method(other)),
    };
    let summary = summarize_call(&call);
    Ok(Admitted {
        chain_id,
        call,
        summary,
    })
}

/// Granted-but-refused (granted only because the dapp required it) and anything else: 4200 with
/// a method-specific static string.
fn refused_method(method: &str) -> Refusal {
    let message = match method {
        "eth_sign" => "eth_sign is disabled in Kao.",
        "eth_signTransaction" => {
            "Kao doesn't sign transactions for a dapp to broadcast; use eth_sendTransaction."
        }
        "eth_signTypedData_v3" => "Kao signs typed data only as eth_signTypedData_v4.",
        "wallet_addEthereumChain" => "Add networks in Kao Settings.",
        _ => "Kao doesn't support this method.",
    };
    Refusal::unsupported(
        message,
        format!(
            "Kao refuses {} requests",
            sanitize_display(method, MAX_METHOD_CHARS)
        ),
    )
}

fn params_array<'a>(
    params: &'a serde_json::Value,
    len: usize,
    shape: &'static str,
) -> Result<&'a [serde_json::Value], Refusal> {
    match params.as_array() {
        Some(a) if a.len() == len => Ok(a),
        _ => Err(Refusal::invalid_params(
            shape,
            "the request's params have the wrong shape",
        )),
    }
}

/// A `0x`-prefixed 20-byte address; mixed case must pass EIP-55 (a mixed-case
/// string that fails its checksum is a corrupted address, not a spelling).
fn param_address(v: &serde_json::Value) -> Result<Address, Refusal> {
    let invalid = |detail: String| Refusal::invalid_params("Invalid address.", detail);
    let s = v
        .as_str()
        .ok_or_else(|| invalid("the address parameter isn't a string".into()))?;
    if s.len() != 42 || !s.starts_with("0x") {
        return Err(invalid("the address parameter isn't a 0x… address".into()));
    }
    crate::txbuilder::encode::parse_address(s).map_err(invalid)
}

/// Shaped like an address (`0x` + 40 hex digits), checksum or not — what a
/// mis-typed address would still look like, as opposed to a message.
fn looks_like_address(v: &serde_json::Value) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == 42 && s.starts_with("0x") && s.bytes().skip(2).all(|b| b.is_ascii_hexdigit())
    })
}

fn same_as_session(claimed: Address, session: &BoundSession) -> Result<(), Refusal> {
    let bound = session.identity.address();
    if claimed != bound {
        return Err(Refusal::unauthorized(format!(
            "the dapp asked for {}, but this session is bound to {}",
            short_address(claimed),
            short_address(bound)
        )));
    }
    Ok(())
}

/// `personal_sign` is `[message, address]`, optionally followed by a third
/// element that is ignored entirely: web3.js's `personal.sign(data, address,
/// password)` always sends one (MetaMask treats it as optional extra params).
/// It is never decoded, shown or logged — nothing downstream carries it, so it
/// can't change what is reviewed or signed.
///
/// The legacy `[address, message]` order is swapped back only when it is
/// unambiguous: the second element doesn't even look like an address and the
/// first one parses as one. Swapping can't produce a raw-hash signature —
/// `personal_sign` always signs under the EIP-191 prefix — and the claimed
/// address must still be the session's.
fn personal_sign(
    params: &serde_json::Value,
    session: &BoundSession,
    caps: &IdentityCaps,
    chain_id: u64,
) -> Result<PersonalSign, Refusal> {
    const SHAPE: &str = "personal_sign params must be [message, address].";
    let (data, address) = match params.as_array().map(Vec::as_slice) {
        Some([data, address] | [data, address, _]) => (data, address),
        _ => {
            return Err(Refusal::invalid_params(
                SHAPE,
                "the request's params have the wrong shape",
            ));
        }
    };
    let (data, from) = match param_address(address) {
        Ok(a) => (data, a),
        Err(_) if !looks_like_address(address) && param_address(data).is_ok() => {
            (address, param_address(data)?)
        }
        Err(e) => return Err(e),
    };
    same_as_session(from, session)?;
    let message = message::decode_personal_param(data)?;
    let shape = message::classify(&message);
    // With v+4 an opaque 32-byte signature from a Safe owner IS an owner
    // confirmation of a safeTxHash equal to these bytes. The same rule runs
    // again when the review opens and at Confirm.
    caps.personal(&shape)?;
    let siwe = match &shape {
        MessageShape::Text { .. } => std::str::from_utf8(&message)
            .ok()
            .and_then(message::parse_siwe)
            .map(|s| message::check_siwe(s, session.dapp.host.as_deref(), from, chain_id)),
        MessageShape::Binary { .. } => None,
    };
    Ok(PersonalSign {
        from,
        message,
        shape,
        siwe,
    })
}

/// `eth_signTypedData_v4` / `eth_signTypedData`: `[address, typedData]`.
fn sign_typed_data(
    params: &serde_json::Value,
    session: &BoundSession,
    chain_id: u64,
) -> Result<TypedRequest, Refusal> {
    const SHAPE: &str = "eth_signTypedData_v4 params must be [address, typedData].";
    let p = params_array(params, 2, SHAPE)?;
    let (address, data) = match p {
        [address, data] => (address, data),
        _ => {
            return Err(Refusal::invalid_params(
                SHAPE,
                "typed data needs two params",
            ));
        }
    };
    let from = match param_address(address) {
        Ok(a) => a,
        Err(_) if param_address(data).is_ok() => {
            return Err(Refusal::invalid_params(
                SHAPE,
                "the dapp sent the typed data before the address",
            ));
        }
        Err(e) => return Err(e),
    };
    same_as_session(from, session)?;
    let (td, raw) = typed::parse_typed_param(data)?;
    let checked = typed::check_typed_data(&raw, &td, chain_id, from)?;
    Ok(TypedRequest {
        from,
        typed: Arc::new(td),
        checked,
    })
}

/// `eth_sendTransaction`: `[tx]`. Kao estimates gas and fees and reads the
/// nonce itself (a dapp tip is a real loss, a dapp nonce could replace a pending
/// transaction); what the dapp sent for those is recorded and shown,
/// never used. Anything Kao can't represent faithfully — contract creation,
/// 7702 authorizations, blobs, access lists, conflicting input/data — is refused.
fn send_transaction(
    params: &serde_json::Value,
    session: &BoundSession,
    chain_id: u64,
) -> Result<TxIntent, Refusal> {
    const SHAPE: &str = "eth_sendTransaction params must be [transaction].";
    let p = params_array(params, 1, SHAPE)?;
    let Some(obj) = p.first().and_then(serde_json::Value::as_object) else {
        return Err(Refusal::invalid_params(
            SHAPE,
            "the transaction isn't an object",
        ));
    };
    let present = |k: &str| obj.get(k).is_some_and(|v| !v.is_null());

    if present("authorizationList") {
        return Err(Refusal::invalid_params(
            "EIP-7702 authorizations aren't supported.",
            "the dapp's transaction carries an authorization list",
        ));
    }
    if BLOB_KEYS.iter().any(|k| present(k)) {
        return Err(Refusal::invalid_params(
            "Blob transactions aren't supported.",
            "the dapp's transaction carries blob fields",
        ));
    }
    if let Some(op) = obj.get("operation")
        && !op.is_null()
        && !is_zero_quantity(op)
    {
        return Err(Refusal::invalid_params(
            "Only plain calls are supported (operation must be 0).",
            "the dapp asked for a delegatecall",
        ));
    }
    // Mixed-case addresses must pass EIP-55 (serde's Address parse doesn't check).
    for key in ["from", "to"] {
        if let Some(s) = obj.get(key).and_then(serde_json::Value::as_str)
            && crate::txbuilder::encode::parse_address(s).is_err()
        {
            return Err(Refusal::invalid_params(
                "Invalid address.",
                format!("the transaction's `{key}` isn't a valid address"),
            ));
        }
    }

    let obj = with_gas_limit_as_gas(obj)?;
    let tx: TransactionRequest =
        serde_json::from_value(serde_json::Value::Object(obj)).map_err(|_| {
            Refusal::invalid_params(
                "The transaction is malformed.",
                "the dapp's transaction doesn't parse",
            )
        })?;
    if tx.authorization_list.is_some() {
        return Err(Refusal::invalid_params(
            "EIP-7702 authorizations aren't supported.",
            "the dapp's transaction carries an authorization list",
        ));
    }
    if tx.blob_versioned_hashes.is_some()
        || tx.max_fee_per_blob_gas.is_some()
        || tx.sidecar.is_some()
    {
        return Err(Refusal::invalid_params(
            "Blob transactions aren't supported.",
            "the dapp's transaction carries blob fields",
        ));
    }
    if tx.access_list.as_ref().is_some_and(|l| !l.0.is_empty()) {
        return Err(Refusal::invalid_params(
            "Access lists aren't supported.",
            "the dapp's transaction carries a non-empty access list",
        ));
    }
    let tx_type = match tx.transaction_type {
        None => None,
        Some(t @ 0..=2) => Some(t),
        Some(t) => {
            return Err(Refusal::invalid_params(
                "This transaction type isn't supported.",
                format!("the dapp asked for a type {t} transaction"),
            ));
        }
    };

    let Some(from) = tx.from else {
        return Err(Refusal::invalid_params(
            "The transaction has no from address.",
            "the dapp's transaction doesn't say which account sends it",
        ));
    };
    same_as_session(from, session)?;
    let to = match tx.to {
        Some(TxKind::Call(to)) => to,
        None | Some(TxKind::Create) => {
            return Err(Refusal::invalid_params(
                "Contract deployment isn't supported.",
                "the dapp's transaction has no recipient (a contract deployment)",
            ));
        }
    };
    if to == Address::ZERO {
        return Err(Refusal::invalid_params(
            "Kao won't send to the zero address.",
            "the dapp's transaction is addressed to 0x0000…0000",
        ));
    }
    if let Some(c) = tx.chain_id
        && c != chain_id
    {
        return Err(Refusal::invalid_params(
            "The transaction's chainId doesn't match the request's chain.",
            format!("the transaction names chain {c}; the request is on chain {chain_id}"),
        ));
    }
    let data = tx.input.try_into_unique_input().map_err(|_| {
        Refusal::invalid_params(
            "The transaction's input and data fields disagree.",
            "the dapp sent two different calldata values",
        )
    })?;
    let data = data.unwrap_or_default();
    if data.len() > MAX_TX_DATA_BYTES {
        return Err(Refusal::invalid_params(
            "The transaction data is too large.",
            format!(
                "{} bytes of calldata; Kao accepts up to {} KiB",
                data.len(),
                MAX_TX_DATA_BYTES / 1024
            ),
        ));
    }

    // A Safe's relay fields are always zero, so even the dapp's gas is only a note.
    let safe = session.identity.is_safe();
    Ok(TxIntent {
        from,
        to,
        value: tx.value.unwrap_or_default(),
        data,
        chain_id,
        dapp_gas: if safe { None } else { tx.gas },
        ignored: IgnoredTxFields {
            nonce: tx.nonce,
            gas_price: tx.gas_price,
            max_fee_per_gas: tx.max_fee_per_gas,
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
            tx_type,
            safe_gas: if safe { tx.gas } else { None },
        },
    })
}

/// The transaction object with a `gasLimit` key folded into `gas`. Hand-built requests use
/// ethers' field name; the RPC spelling `gas` is the only one `TransactionRequest` reads, so the
/// dapp's limit would otherwise vanish without a trace — from the gas policy, and from the
/// disclosure of what the dapp asked for. Both present must agree.
fn with_gas_limit_as_gas(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Map<String, serde_json::Value>, Refusal> {
    let mut obj = obj.clone();
    let Some(limit) = obj.remove("gasLimit").filter(|v| !v.is_null()) else {
        return Ok(obj);
    };
    // Parsed exactly as `gas` itself is (hex or decimal quantity, u64).
    let quantity = |v: &serde_json::Value| {
        serde_json::from_value::<TransactionRequest>(serde_json::json!({ "gas": v }))
            .ok()
            .and_then(|t| t.gas)
    };
    let Some(wanted) = quantity(&limit) else {
        return Err(Refusal::invalid_params(
            "The transaction is malformed.",
            "the dapp's gasLimit isn't a quantity",
        ));
    };
    match obj.get("gas").filter(|v| !v.is_null()) {
        None => {
            obj.insert("gas".to_string(), limit);
        }
        Some(gas) if quantity(gas) == Some(wanted) => {}
        Some(_) => {
            return Err(Refusal::invalid_params(
                "The transaction's gas and gasLimit fields disagree.",
                "the dapp sent two different gas limits",
            ));
        }
    }
    Ok(obj)
}

/// `0`, `"0"`, `"0x0"`, `"0x00"`, `"0x"` — every spelling of zero a dapp library emits.
fn is_zero_quantity(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Number(n) => n.as_u64() == Some(0),
        serde_json::Value::String(s) => {
            s == "0"
                || s.strip_prefix("0x")
                    .is_some_and(|h| h.bytes().all(|b| b == b'0'))
        }
        _ => false,
    }
}

/// `wallet_switchEthereumChain` (EIP-3326): `[{ chainId: "0x…" }]`.
fn switch_target(params: &serde_json::Value) -> Result<u64, Refusal> {
    let invalid = || {
        Refusal::invalid_params(
            "wallet_switchEthereumChain params must be [{ chainId: \"0x…\" }].",
            "the dapp's network switch request is malformed",
        )
    };
    let p = params_array(
        params,
        1,
        "wallet_switchEthereumChain params must be [{ chainId: \"0x…\" }].",
    )?;
    let hex_id = p
        .first()
        .and_then(|o| o.get("chainId"))
        .and_then(serde_json::Value::as_str)
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or_else(invalid)?;
    if hex_id.is_empty() || hex_id.len() > 16 || !hex_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    match u64::from_str_radix(hex_id, 16) {
        Ok(id) if id != 0 => Ok(id),
        _ => Err(invalid()),
    }
}

/// Accounts → [EIP-55]; ChainId → "0x<hex>"; SwitchChain → null | Err(4902). `None` for review calls.
///
/// A switch is answered `null` only to a chain already in the session (the
/// `chainChanged` emit that follows is the book's, and only when granted);
/// anything else is EIP-3326's 4902 so the dapp knows to stay put.
pub fn immediate_answer(
    call: &WcCall,
    session: &BoundSession,
    request_chain: u64,
) -> Option<Result<serde_json::Value, Refusal>> {
    match call {
        WcCall::Accounts => Some(Ok(serde_json::json!([session
            .identity
            .address()
            .to_checksum(None)]))),
        WcCall::ChainId => Some(Ok(serde_json::Value::String(format!(
            "0x{request_chain:x}"
        )))),
        WcCall::SwitchChain { chain_id } => Some(if session.chains.contains(chain_id) {
            Ok(serde_json::Value::Null)
        } else {
            Err(Refusal::unrecognized_chain())
        }),
        WcCall::PersonalSign(_) | WcCall::SignTypedData(_) | WcCall::SendTransaction(_) => None,
    }
}

/// Crate parser + 64-hex topic + relay-protocol "irn" + not expired. Never echoes the input.
pub fn parse_pairing_uri(uri: &str, now: u64) -> Result<ParsedPairing, &'static str> {
    if uri.len() > MAX_PAIRING_URI_CHARS {
        return Err(INVALID_LINK);
    }
    let parsed: PairingUri = uri.parse().map_err(|e| pairing_uri_error(&e))?;
    let topic = parsed.topic.as_str();
    // The crate accepts any topic string; a real one is sha256(symKey) in lowercase hex.
    if topic.len() != 64
        || !topic
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(INVALID_LINK);
    }
    if parsed.relay_protocol != "irn" {
        return Err("This WalletConnect link uses a relay Kao doesn't support.");
    }
    if parsed.expiry_timestamp.is_some_and(|e| e <= now) {
        return Err(EXPIRED_LINK);
    }
    Ok(ParsedPairing {
        topic: parsed.topic.clone(),
        expiry: parsed.expiry_timestamp,
    })
}

/// Crate errors echo the URI (it contains the symKey) — map to fixed copy.
pub fn pairing_uri_error(e: &wallet_connect::Error) -> &'static str {
    use wallet_connect::Error as E;
    match e {
        E::InvalidUri(_) | E::InvalidKey(_) | E::InvalidCaip(_) | E::Json(_) => INVALID_LINK,
        E::Expired(_) => EXPIRED_LINK,
        // `pair` reports an already-active pairing as a protocol error.
        E::Protocol(_) => "This link was already used — ask the dapp for a new one.",
        E::Disconnected | E::Timeout | E::Transport(_) | E::Relay(_) => {
            "Couldn't reach the WalletConnect relay — check your connection and try again."
        }
        E::Closed => RUNTIME_CLOSED,
        _ => "Couldn't pair with that link — get a fresh one from the dapp.",
    }
}

/// base = est (empty data) | est + est/5; dapp > base ⇒ min(dapp, max(2·est, est+100_000)); a
/// result over the ceiling ⇒ Err. Dapps legitimately pad for paths `estimate_gas` can't see; the
/// cap bounds the worst-case fee the user approves (unused gas is refunded).
///
/// Neither the headroom nor the dapp's pad ever lifts a limit past [`MAX_TX_GAS`] when the
/// estimate itself fits under it: a node enforcing EIP-7825 would refuse the signed transaction
/// at broadcast. Holding the limit at the cap only removes headroom, so it is harmless on a chain
/// without the cap, and needs no per-chain table.
pub fn choose_gas_limit(
    estimate: u64,
    dapp: Option<u64>,
    has_data: bool,
) -> Result<(u64, GasNote), Refusal> {
    let (base, base_note) = if has_data {
        (
            estimate.saturating_add(estimate / 5),
            GasNote::Buffered { estimate },
        )
    } else {
        (estimate, GasNote::Estimated)
    };
    let (limit, note) = match dapp {
        Some(d) if d > base => {
            let cap = estimate
                .saturating_mul(2)
                .max(estimate.saturating_add(100_000));
            if d <= cap {
                (d, GasNote::DappHonoured { estimate, dapp: d })
            } else {
                (cap, GasNote::DappCapped { estimate, dapp: d })
            }
        }
        _ => (base, base_note),
    };
    let (limit, note) = if limit > MAX_TX_GAS && estimate <= MAX_TX_GAS {
        (MAX_TX_GAS, GasNote::NetworkCapped { estimate, dapp })
    } else {
        (limit, note)
    };
    if limit > GAS_LIMIT_CEILING {
        return Err(Refusal::invalid_params(
            "The transaction needs more gas than Kao allows.",
            format!("it needs {limit} gas; Kao caps a transaction at {GAS_LIMIT_CEILING}"),
        ));
    }
    Ok((limit, note))
}

/// A call into a Kao-known Safe's approveHash(bytes32) / execTransaction(..) → red banner text.
pub fn owner_action_banner(
    to: Address,
    data: &[u8],
    known_safes: &[(Address, String)],
) -> Option<String> {
    let (safe, label) = known_safes.iter().find(|(a, _)| *a == to)?;
    let selector = data.get(..4)?;
    let name = sanitize_display(label, 40);
    let where_ = format!("your Safe “{name}” ({})", short_address(*safe));
    if selector == approveHashCall::SELECTOR.as_slice() {
        let hash = data
            .get(4..36)
            .and_then(|h| B256::try_from(h).ok())
            .map(|h| format!(" for {h}"))
            .unwrap_or_default();
        Some(format!(
            "This calls approveHash on {where_}{hash}: an on-chain owner confirmation of a Safe \
             transaction, exactly as binding as your signature. Only continue if you meant to \
             approve that Safe transaction."
        ))
    } else if selector == crate::safe::execTransactionCall::SELECTOR.as_slice() {
        Some(format!(
            "This executes a transaction from {where_} with signatures the dapp supplied. Kao \
             can't show what that Safe transaction does — only continue if you checked it in \
             the Safe itself."
        ))
    } else {
        None
    }
}

/// Sanitized one-liner, ≤ MAX_SUMMARY_CHARS ("Send 0.1 ETH to 0xAb…9f", "Sign in to app.example").
pub fn summarize_call(call: &WcCall) -> String {
    let line = match call {
        WcCall::PersonalSign(p) => match (&p.siwe, &p.shape) {
            (Some(c), _) => format!("Sign in to {}", c.siwe.domain),
            (None, MessageShape::Text { lines }) => {
                let first = lines
                    .iter()
                    .map(|l| l.trim())
                    .find(|l| !l.is_empty())
                    .unwrap_or_default();
                format!("Sign message “{first}”")
            }
            (
                None,
                MessageShape::Binary {
                    reason: BinaryReason::OpaqueHash32,
                    ..
                },
            ) => "Sign an opaque 32-byte hash".to_string(),
            (None, MessageShape::Binary { len, .. }) => format!("Sign {len} bytes of binary data"),
        },
        WcCall::SignTypedData(t) => match &t.checked.kind {
            TypedKind::Allowance(g) => {
                format!("{}: let {} spend tokens", g.kind, short_address(g.spender))
            }
            TypedKind::SafeTx { nonce, .. } => {
                format!("Confirm a Safe transaction (nonce {nonce})")
            }
            TypedKind::SafeMessage { .. } => "Confirm a Safe message".to_string(),
            TypedKind::Generic => match &t.checked.domain.name {
                Some(name) => format!("Sign {} for {name}", t.checked.primary_type),
                None => format!("Sign {}", t.checked.primary_type),
            },
        },
        WcCall::SendTransaction(tx) => {
            let to = short_address(tx.to);
            let amount = format!(
                "{} {}",
                format_native(tx.value),
                super::native_symbol(tx.chain_id)
            );
            match (tx.data.is_empty(), tx.value.is_zero()) {
                (true, _) => format!("Send {amount} to {to}"),
                (false, true) => format!("Call {to}"),
                (false, false) => format!("Call {to} with {amount}"),
            }
        }
        WcCall::SwitchChain { chain_id } => {
            format!("Switch to {}", super::chain_label(*chain_id))
        }
        WcCall::Accounts => "Read accounts".to_string(),
        WcCall::ChainId => "Read network".to_string(),
    };
    sanitize_display(&line, MAX_SUMMARY_CHARS).into_owned()
}

/// Exact decimal (18 decimals, trailing zeros trimmed) — a summary never rounds a value.
fn format_native(wei: U256) -> String {
    let s = alloy::primitives::utils::format_units(wei, 18).unwrap_or_else(|_| wei.to_string());
    match s.split_once('.') {
        Some((whole, frac)) => {
            let frac = frac.trim_end_matches('0');
            if frac.is_empty() {
                whole.to_string()
            } else {
                format!("{whole}.{frac}")
            }
        }
        None => s,
    }
}

/// "0x" + lowercase hex as a JSON string.
pub fn hex_value(bytes: &[u8]) -> serde_json::Value {
    serde_json::Value::String(format!("0x{}", hex::encode(bytes)))
}

/// Classify a crate respond/disconnect result for the outbox by what the crate still holds
/// (`still_held`: the request is still pending, or the session still exists).
///
/// A failed send leaves the request (or session) with the crate whatever the error — a dropped
/// socket, a timeout, a relay JSON-RPC error such as a rate limit — so it is still owed and is
/// re-sent. One the crate no longer holds (answered, expired, its session deleted) can never be
/// delivered, and neither can anything once the client shut down. The text is for the user's
/// notices — sanitized, and never the outgoing payload.
pub fn respond_result(r: &Result<(), wallet_connect::Error>, still_held: bool) -> RespondResult {
    match r {
        Ok(()) => RespondResult::Delivered,
        Err(e) => {
            let why = sanitize_display(&e.to_string(), 160).into_owned();
            if still_held && !matches!(e, wallet_connect::Error::Closed) {
                RespondResult::Retry(why)
            } else {
                RespondResult::Gone(why)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sanitize::exact_display_lines;
    use crate::walletconnect::namespaces::{EVENTS, REFUSED_METHODS, SERVED_METHODS};
    use crate::walletconnect::testkit;
    use crate::walletconnect::{MAX_MESSAGE_BYTES, MAX_TYPED_DATA_BYTES, MAX_TYPED_ROWS};
    use alloy::primitives::{address, b256};
    use serde_json::{Value, json};
    use wallet_connect::crypto::Topic;
    use wallet_connect::rpc::ErrorObject;
    use wallet_connect::sign::{Metadata, SessionRequest};

    const ADDR: Address = address!("ab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb");
    const OTHER: Address = address!("4444444444444444444444444444444444444444");
    const SAFE: Address = address!("1111111111111111111111111111111111111111");
    const TO: Address = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");

    const TOPIC_HEX: &str = "7f6e504bfad60b485450578e05678ed3e8e8c4751d3c6160be17160d63ec90f9";
    const SYM_KEY: &str = "587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303";

    fn eoa_caps(kind: EoaKind, safe_owner: bool, chains: &[u64]) -> IdentityCaps {
        testkit::eoa_caps(ADDR, kind, safe_owner, chains)
    }

    fn local() -> IdentityCaps {
        eoa_caps(EoaKind::Local, false, &[1, 8453])
    }

    fn safe_caps(threshold: u32, local_signers: u32) -> IdentityCaps {
        testkit::safe_identity_caps(SAFE, 1, threshold, 3, local_signers)
    }

    /// A session for `caps`' identity on `chains`, granted every method Kao knows.
    fn session_on(caps: &IdentityCaps, chains: &[u64]) -> BoundSession {
        let mut methods: Vec<String> = SERVED_METHODS
            .iter()
            .chain(REFUSED_METHODS)
            .map(|m| m.to_string())
            .collect();
        methods.push("foo_bar".into());
        BoundSession {
            topic: Topic::new("cc".repeat(32)),
            pairing_topic: Topic::new("dd".repeat(32)),
            ordinal: 1,
            identity: caps.identity,
            identity_label: caps.label.clone(),
            chains: chains.to_vec(),
            methods,
            events: EVENTS.iter().map(|e| e.to_string()).collect(),
            dapp: DappLabel::from_metadata(&Metadata::new("Dapp", "", "https://app.example")),
            expiry: u64::MAX,
            ack: AckState::Confirmed,
            paused: false,
            reject_streak: 0,
        }
    }

    fn session(caps: &IdentityCaps) -> BoundSession {
        session_on(caps, &caps.chains.clone())
    }

    fn req(method: &str, params: Value, chain: u64) -> PendingRequest {
        PendingRequest {
            id: 1,
            topic: Topic::new("cc".repeat(32)),
            chain_id: format!("eip155:{chain}"),
            request: SessionRequest::new(method, params),
        }
    }

    fn run(
        caps: &IdentityCaps,
        method: &str,
        params: Value,
        chain: u64,
    ) -> Result<Admitted, Refusal> {
        validate(&req(method, params, chain), &session(caps), caps)
    }

    fn ok(r: Result<Admitted, Refusal>) -> Admitted {
        r.unwrap_or_else(|e| panic!("expected admission, got {e:?}"))
    }

    fn err(r: Result<Admitted, Refusal>) -> Refusal {
        match r {
            Ok(a) => panic!("expected a refusal, got {:?}", a.call),
            Err(e) => e,
        }
    }

    fn tx(r: Result<Admitted, Refusal>) -> TxIntent {
        match ok(r).call {
            WcCall::SendTransaction(t) => t,
            other => panic!("expected a transaction, got {other:?}"),
        }
    }

    fn base_tx(from: Address) -> Value {
        json!({
            "from": from.to_checksum(None),
            "to": TO.to_checksum(None),
            "value": "0x16345785d8a0000",
            "data": "0xa9059cbb"
        })
    }

    fn send(caps: &IdentityCaps, t: Value, chain: u64) -> Result<Admitted, Refusal> {
        run(caps, "eth_sendTransaction", json!([t]), chain)
    }

    fn mail(chain: u64) -> Value {
        testkit::fixtures::mail(chain)
    }

    fn uri(expiry: u64) -> String {
        format!("wc:{TOPIC_HEX}@2?expiryTimestamp={expiry}&relay-protocol=irn&symKey={SYM_KEY}")
    }

    // ── the session envelope ──────────────────────────────────────────────────

    #[test]
    fn from_mismatch_is_4100() {
        let caps = local();
        let e = err(run(
            &caps,
            "personal_sign",
            json!(["0x48656c6c6f", OTHER.to_checksum(None)]),
            1,
        ));
        assert_eq!(e.code, codes::UNAUTHORIZED);
        assert_eq!(
            e.message,
            "The requested account is not authorized for this session."
        );
        let e = err(run(
            &caps,
            "eth_signTypedData_v4",
            json!([OTHER.to_checksum(None), mail(1)]),
            1,
        ));
        assert_eq!(e.code, codes::UNAUTHORIZED);
        let e = err(send(&caps, base_tx(OTHER), 1));
        assert_eq!(e.code, codes::UNAUTHORIZED);
        // A Safe session's `from` is the Safe, not an owner.
        let s = safe_caps(1, 1);
        assert_eq!(err(send(&s, base_tx(ADDR), 1)).code, codes::UNAUTHORIZED);
        // Caps for a different identity than the session is bound to.
        let wrong = validate(&req("eth_accounts", json!([]), 1), &session(&s), &caps);
        assert_eq!(err(wrong).code, codes::UNAUTHORIZED);
    }

    #[test]
    fn personal_sign_param_order_strict() {
        let caps = local();
        let addr = ADDR.to_checksum(None);
        let a = ok(run(
            &caps,
            "personal_sign",
            json!(["0x48656c6c6f", addr]),
            1,
        ));
        let WcCall::PersonalSign(p) = a.call else {
            panic!()
        };
        assert_eq!(p.from, ADDR);
        assert_eq!(p.message.as_ref(), b"Hello");
        for bad in [
            json!([]),
            json!(["0x48656c6c6f"]),
            json!(["0x48", addr, "pw", "extra"]),
            json!({"m": 1}),
            Value::Null,
        ] {
            let e = err(run(&caps, "personal_sign", bad.clone(), 1));
            assert_eq!(e.code, codes::INVALID_PARAMS, "{bad}");
            assert_eq!(
                e.message, "personal_sign params must be [message, address].",
                "{bad}"
            );
        }
        // Same strictness for typed data: [address, typedData].
        let e = err(run(
            &caps,
            "eth_signTypedData_v4",
            json!([mail(1), addr]),
            1,
        ));
        assert_eq!(
            e.message,
            "eth_signTypedData_v4 params must be [address, typedData]."
        );
    }

    /// web3.js's `personal.sign(data, address, password)` sends a third element. It is admitted
    /// and ignored whatever it holds: the call carries only the message and the signer, exactly
    /// as for the two-element form.
    #[test]
    fn personal_sign_third_param_is_ignored() {
        let caps = local();
        let lower = format!("{ADDR:#x}").to_lowercase();
        for third in [json!(""), Value::Null, json!("pw"), json!({"k": [1, 2]})] {
            let a = ok(run(
                &caps,
                "personal_sign",
                json!(["0x48656c6c6f", lower, third]),
                1,
            ));
            let WcCall::PersonalSign(p) = a.call else {
                panic!("{third}")
            };
            assert_eq!(
                (p.from, p.message.as_ref()),
                (ADDR, &b"Hello"[..]),
                "{third}"
            );
        }
        // The rest of the rules still apply: the address must be the session's.
        let e = err(run(
            &caps,
            "personal_sign",
            json!(["0x48", OTHER.to_checksum(None), "pw"]),
            1,
        ));
        assert_eq!(e.code, codes::UNAUTHORIZED);
    }

    /// The legacy `[address, message]` order is swapped back only when unambiguous: the message
    /// doesn't look like an address and the address parses. Everything after the swap — the
    /// session check, the opaque-hash rule — runs on the swapped values.
    #[test]
    fn personal_sign_legacy_order_swapped_only_when_unambiguous() {
        let caps = local();
        let lower = format!("{ADDR:#x}").to_lowercase();
        for from in [lower.clone(), ADDR.to_checksum(None)] {
            for params in [
                json!([from, "0x48656c6c6f"]),
                json!([from, "0x48656c6c6f", "pw"]),
            ] {
                let WcCall::PersonalSign(p) = ok(run(&caps, "personal_sign", params, 1)).call
                else {
                    panic!()
                };
                assert_eq!((p.from, p.message.as_ref()), (ADDR, &b"Hello"[..]));
            }
        }
        // Swapped, the address is still checked against the session.
        let e = err(run(
            &caps,
            "personal_sign",
            json!([OTHER.to_checksum(None), "0x48656c6c6f"]),
            1,
        ));
        assert_eq!(e.code, codes::UNAUTHORIZED);
        // Both look like addresses: the standard order stands (signs the first's 20 bytes as
        // `[message, address]`), never a guess.
        let WcCall::PersonalSign(p) = ok(run(
            &caps,
            "personal_sign",
            json!([OTHER.to_checksum(None), lower]),
            1,
        ))
        .call
        else {
            panic!()
        };
        assert_eq!(p.message.as_ref(), OTHER.as_slice());
        // A corrupted (bad-checksum) address in second place is an invalid address, not a
        // reason to swap.
        let bad = "0xAb16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb";
        let e = err(run(&caps, "personal_sign", json!([lower, bad]), 1));
        assert_eq!(e.message, "Invalid address.");
        // Neither is an address.
        let e = err(run(&caps, "personal_sign", json!(["0x48", "0x49"]), 1));
        assert_eq!(e.message, "Invalid address.");
        // An opaque 32-byte hash sent in legacy order to a Safe owner is still refused.
        let owner = eoa_caps(EoaKind::Local, true, &[1]);
        let hash32 = format!("0x{}", "ab".repeat(32));
        let e = err(run(&owner, "personal_sign", json!([lower, hash32]), 1));
        assert_eq!(e.code, codes::UNSUPPORTED_METHOD);
    }

    #[test]
    fn mixed_case_bad_checksum_refused() {
        let caps = local();
        // One letter's case flipped: a corrupted address, not a spelling.
        let bad = "0xAb16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb";
        let e = err(run(&caps, "personal_sign", json!(["0x48", bad]), 1));
        assert_eq!(e.code, codes::INVALID_PARAMS);
        assert_eq!(e.message, "Invalid address.");
        // All-lowercase (no checksum claim) is fine.
        let lower = format!("{ADDR:#x}").to_lowercase();
        assert!(run(&caps, "personal_sign", json!(["0x48", lower]), 1).is_ok());
        // Transaction addresses too.
        let mut t = base_tx(ADDR);
        t["to"] = json!("0x70997970c51812dc3A010C7d01b50e0d17dc79C8");
        assert_eq!(err(send(&caps, t, 1)).message, "Invalid address.");
        let mut t = base_tx(ADDR);
        t["from"] = json!(bad);
        assert_eq!(err(send(&caps, t, 1)).message, "Invalid address.");
        // Not an address at all.
        assert_eq!(
            err(run(&caps, "personal_sign", json!(["0x48", "0x1234"]), 1)).message,
            "Invalid address."
        );
    }

    #[test]
    fn chain_not_served_is_4901() {
        // The session has Base, but Kao no longer serves it (RPC removed / network disabled).
        let caps = eoa_caps(EoaKind::Local, false, &[1]);
        let s = session_on(&caps, &[1, 8453]);
        let e = err(validate(
            &req(
                "personal_sign",
                json!(["0x48", ADDR.to_checksum(None)]),
                8453,
            ),
            &s,
            &caps,
        ));
        assert_eq!(e.code, codes::CHAIN_DISCONNECTED);
        assert_eq!(e.message, "Kao no longer serves this chain.");
        // A chain the session never had.
        let e = err(validate(&req("eth_chainId", json!([]), 10), &s, &caps));
        assert_eq!(e.code, codes::CHAIN_DISCONNECTED);
        // Switching to a session chain Kao no longer serves.
        let e = err(validate(
            &req(
                "wallet_switchEthereumChain",
                json!([{"chainId": "0x2105"}]),
                1,
            ),
            &s,
            &caps,
        ));
        assert_eq!(e.code, codes::CHAIN_DISCONNECTED);
        // A Safe answers only on its own chain, even if the session lists more.
        let sc = safe_caps(1, 1);
        let s = session_on(&sc, &[1, 8453]);
        let e = err(validate(&req("eth_accounts", json!([]), 8453), &s, &sc));
        assert_eq!(e.code, codes::CHAIN_DISCONNECTED);
        // A malformed CAIP-2 id.
        let mut r = req("eth_chainId", json!([]), 1);
        r.chain_id = "eip155:01".into();
        assert_eq!(
            err(validate(&r, &session(&caps), &caps)).code,
            codes::INVALID_PARAMS
        );
    }

    #[test]
    fn eth_sign_is_refused_4200() {
        let caps = local();
        let hash = format!("0x{}", "ab".repeat(32));
        let e = err(run(
            &caps,
            "eth_sign",
            json!([ADDR.to_checksum(None), hash]),
            1,
        ));
        assert_eq!(e.code, codes::UNSUPPORTED_METHOD);
        assert_eq!(e.message, "eth_sign is disabled in Kao.");
        for (m, msg) in [
            (
                "eth_signTransaction",
                "Kao doesn't sign transactions for a dapp to broadcast; use eth_sendTransaction.",
            ),
            (
                "eth_signTypedData_v3",
                "Kao signs typed data only as eth_signTypedData_v4.",
            ),
            ("wallet_addEthereumChain", "Add networks in Kao Settings."),
            ("wallet_sendCalls", "Kao doesn't support this method."),
            ("foo_bar", "Kao doesn't support this method."),
        ] {
            let e = err(run(&caps, m, json!([]), 1));
            assert_eq!((e.code, e.message), (codes::UNSUPPORTED_METHOD, msg), "{m}");
        }
        // A method the session wasn't granted (the crate stops these first).
        let mut s = session(&caps);
        s.methods.retain(|m| m != "eth_sign");
        let e = err(validate(&req("eth_sign", json!([]), 1), &s, &caps));
        assert_eq!(e.message, "This method wasn't granted to the session.");
    }

    // ── personal_sign ─────────────────────────────────────────────────────────

    const OPAQUE: &str = "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2";

    #[test]
    fn personal_sign_opaque_32_refused_for_safe_owner() {
        let owner = eoa_caps(EoaKind::Ledger, true, &[1]);
        let e = err(run(
            &owner,
            "personal_sign",
            json!([OPAQUE, ADDR.to_checksum(None)]),
            1,
        ));
        assert_eq!(e.code, codes::UNSUPPORTED_METHOD);
        assert_eq!(
            e.message,
            "Kao won't sign an opaque 32-byte hash with a Safe owner key."
        );
    }

    #[test]
    fn personal_sign_opaque_32_allowed_with_banner_for_plain_eoa() {
        let a = ok(run(
            &local(),
            "personal_sign",
            json!([OPAQUE, ADDR.to_checksum(None)]),
            1,
        ));
        let WcCall::PersonalSign(p) = &a.call else {
            panic!()
        };
        assert!(matches!(
            p.shape,
            MessageShape::Binary {
                len: 32,
                reason: BinaryReason::OpaqueHash32,
                ..
            }
        ));
        assert!(p.siwe.is_none());
        assert_eq!(a.summary, "Sign an opaque 32-byte hash");
        // A Safe identity signs a SafeMessage, never the raw hash — no 32-byte rule.
        let sa = ok(run(
            &safe_caps(1, 1),
            "personal_sign",
            json!([OPAQUE, SAFE.to_checksum(None)]),
            1,
        ));
        assert!(matches!(sa.call, WcCall::PersonalSign(_)));
    }

    #[test]
    fn personal_sign_32_byte_text_allowed() {
        let owner = eoa_caps(EoaKind::Local, true, &[1]);
        let text = "Sign in to Example nonce 4242424";
        assert_eq!(text.len(), 32);
        let a = ok(run(
            &owner,
            "personal_sign",
            json!([text, ADDR.to_checksum(None)]),
            1,
        ));
        let WcCall::PersonalSign(p) = a.call else {
            panic!()
        };
        assert_eq!(
            p.shape,
            MessageShape::Text {
                lines: vec![text.into()]
            }
        );
        // The same 32 bytes as hex decode to the same text.
        let hex_text = format!("0x{}", hex::encode(text));
        assert!(
            run(
                &owner,
                "personal_sign",
                json!([hex_text, ADDR.to_checksum(None)]),
                1
            )
            .is_ok()
        );
    }

    #[test]
    fn personal_sign_siwe_checked_against_the_session() {
        let caps = local();
        let msg = format!(
            "evil.example wants you to sign in with your Ethereum account:\n{}\n\nURI: https://evil.example\nVersion: 1\nChain ID: 8453\nNonce: 1",
            ADDR.to_checksum(None)
        );
        let a = ok(run(
            &caps,
            "personal_sign",
            json!([msg, ADDR.to_checksum(None)]),
            1,
        ));
        let WcCall::PersonalSign(p) = &a.call else {
            panic!()
        };
        let c = p.siwe.as_ref().expect("SIWE parsed");
        assert!(c.domain_mismatch, "the session's dapp is app.example");
        assert!(c.chain_mismatch && !c.address_mismatch);
        assert_eq!(a.summary, "Sign in to evil.example");
    }

    #[test]
    fn safe_messages_need_capability() {
        let short = safe_caps(2, 1);
        let e = err(run(
            &short,
            "personal_sign",
            json!(["0x48", SAFE.to_checksum(None)]),
            1,
        ));
        assert_eq!(e.code, codes::UNSUPPORTED_METHOD);
        assert_eq!(e.message, "This Safe can't sign messages from Kao.");
        let e = err(run(
            &short,
            "eth_signTypedData_v4",
            json!([SAFE.to_checksum(None), mail(1)]),
            1,
        ));
        assert_eq!(e.code, codes::UNSUPPORTED_METHOD);
        // Transactions only need one owner (propose).
        assert!(send(&short, base_tx(SAFE), 1).is_ok());
        assert_eq!(
            err(send(&safe_caps(1, 0), base_tx(SAFE), 1)).code,
            codes::UNSUPPORTED_METHOD
        );
    }

    // ── typed data ────────────────────────────────────────────────────────────

    #[test]
    fn typed_data_v4_admitted_object_string_and_alias() {
        let caps = local();
        let addr = ADDR.to_checksum(None);
        for (method, data) in [
            ("eth_signTypedData_v4", mail(1)),
            ("eth_signTypedData_v4", Value::String(mail(1).to_string())),
            ("eth_signTypedData", mail(1)),
        ] {
            let a = ok(run(&caps, method, json!([addr, data]), 1));
            let WcCall::SignTypedData(t) = &a.call else {
                panic!()
            };
            assert_eq!(t.from, ADDR);
            assert_eq!(
                t.checked.digests.digest,
                b256!("be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2")
            );
            assert_eq!(
                t.typed.eip712_signing_hash().unwrap(),
                t.checked.digests.digest
            );
            assert_eq!(a.summary, "Sign Mail for Ether Mail");
        }
        // Legacy v1 (an array of {type, name, value}) doesn't parse as v4.
        let v1 = json!([{"type": "string", "name": "m", "value": "hi"}]);
        assert_eq!(
            err(run(&caps, "eth_signTypedData", json!([addr, v1]), 1)).code,
            codes::INVALID_PARAMS
        );
        // Domain chain must be the request's.
        assert_eq!(
            err(run(
                &caps,
                "eth_signTypedData_v4",
                json!([addr, mail(8453)]),
                1
            ))
            .message,
            "Typed data is for a different chain than the request."
        );
    }

    #[test]
    fn trezor_typed_refused_4200() {
        let trezor = eoa_caps(EoaKind::Trezor, false, &[1]);
        let e = err(run(
            &trezor,
            "eth_signTypedData_v4",
            json!([ADDR.to_checksum(None), mail(1)]),
            1,
        ));
        assert_eq!(e.code, codes::UNSUPPORTED_METHOD);
        assert_eq!(e.message, "Trezor can't sign EIP-712 typed data.");
        // personal_sign still works on Trezor.
        assert!(
            run(
                &trezor,
                "personal_sign",
                json!(["0x48", ADDR.to_checksum(None)]),
                1
            )
            .is_ok()
        );
    }

    // ── eth_sendTransaction ───────────────────────────────────────────────────

    #[test]
    fn tx_admitted_with_defaults() {
        let caps = local();
        let mut t = base_tx(ADDR);
        t.as_object_mut().unwrap().remove("value");
        t.as_object_mut().unwrap().remove("data");
        let i = tx(send(&caps, t, 8453));
        assert_eq!(i.from, ADDR);
        assert_eq!(i.to, TO);
        assert_eq!(i.value, U256::ZERO);
        assert!(i.data.is_empty());
        assert_eq!(i.chain_id, 8453);
        assert_eq!(i.dapp_gas, None);
        assert!(i.ignored.describe().is_empty());
        // `input` is accepted as the calldata field too.
        let mut t = base_tx(ADDR);
        t.as_object_mut().unwrap().remove("data");
        t["input"] = json!("0xdeadbeef");
        assert_eq!(
            tx(send(&caps, t, 1)).data.as_ref(),
            &[0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn tx_chain_id_mismatch_refused() {
        let caps = local();
        let mut t = base_tx(ADDR);
        t["chainId"] = json!("0x2105");
        let e = err(send(&caps, t.clone(), 1));
        assert_eq!(e.code, codes::INVALID_PARAMS);
        assert_eq!(
            e.message,
            "The transaction's chainId doesn't match the request's chain."
        );
        assert!(send(&caps, t, 8453).is_ok());
    }

    #[test]
    fn tx_without_to_refused() {
        let caps = local();
        let mut t = base_tx(ADDR);
        t.as_object_mut().unwrap().remove("to");
        assert_eq!(
            err(send(&caps, t, 1)).message,
            "Contract deployment isn't supported."
        );
        let mut t = base_tx(ADDR);
        t["to"] = Value::Null;
        assert_eq!(
            err(send(&caps, t, 1)).message,
            "Contract deployment isn't supported."
        );
        // And no `from` at all.
        let mut t = base_tx(ADDR);
        t.as_object_mut().unwrap().remove("from");
        assert_eq!(
            err(send(&caps, t, 1)).message,
            "The transaction has no from address."
        );
    }

    #[test]
    fn tx_to_zero_refused() {
        let mut t = base_tx(ADDR);
        t["to"] = json!("0x0000000000000000000000000000000000000000");
        let e = err(send(&local(), t, 1));
        assert_eq!(e.code, codes::INVALID_PARAMS);
        assert_eq!(e.message, "Kao won't send to the zero address.");
    }

    #[test]
    fn tx_input_data_conflict_refused() {
        let caps = local();
        let mut t = base_tx(ADDR);
        t["input"] = json!("0x095ea7b3");
        assert_eq!(
            err(send(&caps, t, 1)).message,
            "The transaction's input and data fields disagree."
        );
        let mut t = base_tx(ADDR);
        t["input"] = json!("0xa9059cbb");
        assert_eq!(
            tx(send(&caps, t, 1)).data.as_ref(),
            &[0xa9, 0x05, 0x9c, 0xbb]
        );
    }

    #[test]
    fn tx_type_3_4_and_auth_list_refused() {
        let caps = local();
        for ty in ["0x3", "0x4", "0x7e"] {
            let mut t = base_tx(ADDR);
            t["type"] = json!(ty);
            let e = err(send(&caps, t, 1));
            assert_eq!(e.code, codes::INVALID_PARAMS, "{ty}");
        }
        for (key, value, msg) in [
            (
                "authorizationList",
                json!([]),
                "EIP-7702 authorizations aren't supported.",
            ),
            (
                "blobVersionedHashes",
                json!([format!("0x01{}", "00".repeat(31))]),
                "Blob transactions aren't supported.",
            ),
            (
                "maxFeePerBlobGas",
                json!("0x1"),
                "Blob transactions aren't supported.",
            ),
            (
                "blobs",
                json!(["0x00"]),
                "Blob transactions aren't supported.",
            ),
        ] {
            let mut t = base_tx(ADDR);
            t[key] = value;
            assert_eq!(err(send(&caps, t, 1)).message, msg, "{key}");
        }
        // Explicit nulls are absent fields.
        let mut t = base_tx(ADDR);
        t["authorizationList"] = Value::Null;
        t["blobVersionedHashes"] = Value::Null;
        assert!(send(&caps, t, 1).is_ok());
        // Types 0/1/2 are fine (and only recorded).
        for ty in ["0x0", "0x1", "0x2"] {
            let mut t = base_tx(ADDR);
            t["type"] = json!(ty);
            assert!(send(&caps, t, 1).is_ok(), "{ty}");
        }
    }

    #[test]
    fn tx_nonempty_access_list_refused() {
        let caps = local();
        let mut t = base_tx(ADDR);
        t["accessList"] = json!([{"address": TO.to_checksum(None), "storageKeys": []}]);
        assert_eq!(
            err(send(&caps, t, 1)).message,
            "Access lists aren't supported."
        );
        let mut t = base_tx(ADDR);
        t["accessList"] = json!([]);
        assert!(send(&caps, t, 1).is_ok());
    }

    #[test]
    fn tx_fee_and_nonce_fields_ignored_and_recorded() {
        let mut t = base_tx(ADDR);
        t["nonce"] = json!("0x7");
        t["gasPrice"] = json!("0x4a817c800");
        t["maxFeePerGas"] = json!("0x7558bdb00");
        t["maxPriorityFeePerGas"] = json!("0x3b9aca00");
        t["type"] = json!("0x2");
        t["gas"] = json!("0x5208");
        let i = tx(send(&local(), t, 1));
        assert_eq!(i.dapp_gas, Some(21_000));
        assert_eq!(
            i.ignored,
            IgnoredTxFields {
                nonce: Some(7),
                gas_price: Some(20_000_000_000),
                max_fee_per_gas: Some(31_500_000_000),
                max_priority_fee_per_gas: Some(1_000_000_000),
                tx_type: Some(2),
                safe_gas: None,
            }
        );
        assert_eq!(i.value, U256::from(100_000_000_000_000_000u64));
        assert_eq!(i.data.as_ref(), &[0xa9, 0x05, 0x9c, 0xbb]);
    }

    /// A hand-built request's `gasLimit` is the dapp's gas: it reaches the gas policy for an EOA
    /// and the disclosure for a Safe, instead of being dropped. With `gas` too, both must agree.
    #[test]
    fn tx_gas_limit_key_is_the_dapps_gas() {
        let with = |pairs: &[(&str, Value)]| {
            let mut t = base_tx(ADDR);
            for (k, v) in pairs {
                t[*k] = v.clone();
            }
            t
        };
        for limit in [json!("0x30d40"), json!(200_000), json!("200000")] {
            let i = tx(send(&local(), with(&[("gasLimit", limit.clone())]), 1));
            assert_eq!(i.dapp_gas, Some(200_000), "{limit}");
        }
        let i = tx(send(
            &local(),
            with(&[("gasLimit", json!("0x30d40")), ("gas", json!("0x30d40"))]),
            1,
        ));
        assert_eq!(i.dapp_gas, Some(200_000));
        // `null` is no value, either way round.
        let i = tx(send(
            &local(),
            with(&[("gasLimit", Value::Null), ("gas", json!("0x5208"))]),
            1,
        ));
        assert_eq!(i.dapp_gas, Some(21_000));
        let i = tx(send(
            &local(),
            with(&[("gasLimit", json!("0x5208")), ("gas", Value::Null)]),
            1,
        ));
        assert_eq!(i.dapp_gas, Some(21_000));
        let e = err(send(
            &local(),
            with(&[("gasLimit", json!("0x30d40")), ("gas", json!("0x5208"))]),
            1,
        ));
        assert_eq!(e.code, codes::INVALID_PARAMS);
        assert_eq!(
            e.message,
            "The transaction's gas and gasLimit fields disagree."
        );
        for bad in [json!("lots"), json!("0xzz"), json!(-1), json!({"x": 1})] {
            let e = err(send(&local(), with(&[("gasLimit", bad.clone())]), 1));
            assert_eq!(e.message, "The transaction is malformed.", "{bad}");
        }
        // A Safe's relay gas is only ever disclosed.
        let s = safe_caps(1, 1);
        let i = tx(send(
            &s,
            with(&[
                ("from", json!(SAFE.to_checksum(None))),
                ("gasLimit", json!("0x30d40")),
            ]),
            1,
        ));
        assert_eq!((i.dapp_gas, i.ignored.safe_gas), (None, Some(200_000)));
    }

    #[test]
    fn safe_tx_operation_field_refused() {
        let caps = safe_caps(1, 1);
        for op in [json!(1), json!("0x1"), json!("1"), json!(true)] {
            let mut t = base_tx(SAFE);
            t["operation"] = op.clone();
            let e = err(send(&caps, t, 1));
            assert_eq!(e.code, codes::INVALID_PARAMS, "{op}");
            assert_eq!(
                e.message,
                "Only plain calls are supported (operation must be 0)."
            );
        }
        for op in [
            json!(0),
            json!("0x0"),
            json!("0x00"),
            json!("0"),
            Value::Null,
        ] {
            let mut t = base_tx(SAFE);
            t["operation"] = op.clone();
            assert!(send(&caps, t, 1).is_ok(), "{op}");
        }
    }

    #[test]
    fn safe_intent_is_always_call() {
        let caps = safe_caps(2, 1);
        let mut t = base_tx(SAFE);
        t["gas"] = json!("0x30d40");
        t["maxFeePerGas"] = json!("0x1");
        t["nonce"] = json!(3);
        let i = tx(send(&caps, t, 1));
        // TxIntent carries no operation: the Safe path builds `Operation::Call`
        // from it, and a dapp that asked for anything else was refused above.
        assert_eq!((i.from, i.to), (SAFE, TO));
        assert_eq!(i.dapp_gas, None, "a Safe's relay gas fields are always 0");
        assert_eq!(i.ignored.safe_gas, Some(200_000));
        assert_eq!(i.ignored.max_fee_per_gas, Some(1));
        assert_eq!(i.ignored.nonce, Some(3));
    }

    #[test]
    fn oversized_payloads_refused() {
        let caps = local();
        let addr = ADDR.to_checksum(None);
        let big_msg = format!("0x{}", "ab".repeat(MAX_MESSAGE_BYTES + 1));
        let e = err(run(&caps, "personal_sign", json!([big_msg, addr]), 1));
        assert_eq!(e.message, "The message to sign is too large.");
        let mut t = base_tx(ADDR);
        t["data"] = json!(format!("0x{}", "00".repeat(MAX_TX_DATA_BYTES + 1)));
        assert_eq!(
            err(send(&caps, t, 1)).message,
            "The transaction data is too large."
        );
        let mut m = mail(1);
        m["message"]["contents"] = json!("x".repeat(MAX_TYPED_DATA_BYTES));
        assert_eq!(
            err(run(&caps, "eth_signTypedData_v4", json!([addr, m]), 1)).message,
            "Typed data is too large."
        );
        let mut m = mail(1);
        m["types"]["Mail"][2]["type"] = json!("string[]");
        m["message"]["contents"] = json!(vec!["x"; MAX_TYPED_ROWS]);
        assert_eq!(
            err(run(&caps, "eth_signTypedData_v4", json!([addr, m]), 1)).message,
            "Typed data is too large to review."
        );
    }

    // ── no-UI calls ───────────────────────────────────────────────────────────

    #[test]
    fn switch_chain_params() {
        let caps = local();
        let a = ok(run(
            &caps,
            "wallet_switchEthereumChain",
            json!([{"chainId": "0x2105"}]),
            1,
        ));
        assert!(matches!(a.call, WcCall::SwitchChain { chain_id: 8453 }));
        assert_eq!(a.summary, "Switch to Base");
        for bad in [
            json!([]),
            json!([{"chainId": 8453}]),
            json!([{"chainId": "2105"}]),
            json!([{"chainId": "0x"}]),
            json!([{"chainId": "0xzz"}]),
            json!([{"chainId": "0x0"}]),
            json!([{"chainId": format!("0x{}", "f".repeat(17))}]),
            json!([{"chainId": "0x1"}, {"chainId": "0x2"}]),
            json!({"chainId": "0x1"}),
        ] {
            let e = err(run(&caps, "wallet_switchEthereumChain", bad.clone(), 1));
            assert_eq!(e.code, codes::INVALID_PARAMS, "{bad}");
        }
        // A chain outside the session is admitted; the answer (4902) is immediate_answer's.
        let a = ok(run(
            &caps,
            "wallet_switchEthereumChain",
            json!([{"chainId": "0xa4b1"}]),
            1,
        ));
        assert!(matches!(a.call, WcCall::SwitchChain { chain_id: 42161 }));
    }

    #[test]
    fn immediate_answers_shapes() {
        let caps = local();
        let s = session(&caps);
        // Accounts: the EIP-55 session address, whatever case it was bound with.
        assert_eq!(
            immediate_answer(&WcCall::Accounts, &s, 1),
            Some(Ok(json!(["0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"])))
        );
        let safe_s = session(&safe_caps(1, 1));
        assert_eq!(
            immediate_answer(&WcCall::Accounts, &safe_s, 1),
            Some(Ok(json!([SAFE.to_checksum(None)])))
        );
        // ChainId: lowercase hex of the request's chain.
        assert_eq!(
            immediate_answer(&WcCall::ChainId, &s, 8453),
            Some(Ok(json!("0x2105")))
        );
        assert_eq!(
            immediate_answer(&WcCall::ChainId, &s, 1),
            Some(Ok(json!("0x1")))
        );
        // Switch: null to a session chain, 4902 otherwise.
        assert_eq!(
            immediate_answer(&WcCall::SwitchChain { chain_id: 8453 }, &s, 1),
            Some(Ok(Value::Null))
        );
        let e = immediate_answer(&WcCall::SwitchChain { chain_id: 42161 }, &s, 1)
            .unwrap()
            .unwrap_err();
        assert_eq!(e.code, codes::UNRECOGNIZED_CHAIN);
        // Review calls have no immediate answer.
        let a = ok(run(
            &caps,
            "personal_sign",
            json!(["0x48", ADDR.to_checksum(None)]),
            1,
        ));
        assert_eq!(immediate_answer(&a.call, &s, 1), None);
        // eth_accounts / eth_requestAccounts / eth_chainId admit with any params.
        for m in ["eth_accounts", "eth_requestAccounts"] {
            assert!(matches!(
                ok(run(&caps, m, Value::Null, 1)).call,
                WcCall::Accounts
            ));
        }
        assert!(matches!(
            ok(run(&caps, "eth_chainId", json!([]), 1)).call,
            WcCall::ChainId
        ));
    }

    // ── pairing URI ───────────────────────────────────────────────────────────

    #[test]
    fn parse_pairing_uri_rejects_bad_topic_and_expired() {
        let now = 1_700_000_000;
        let p = parse_pairing_uri(&uri(now + 300), now).unwrap();
        assert_eq!(p.topic, Topic::new(TOPIC_HEX));
        assert_eq!(p.expiry, Some(now + 300));
        // Deep-link spelling and surrounding whitespace, as the crate accepts.
        assert!(
            parse_pairing_uri(
                &format!("  {}  ", uri(now + 300).replacen("wc:", "wc://", 1)),
                now
            )
            .is_ok()
        );
        // No expiry is allowed (the book applies a default window).
        let no_exp = format!("wc:{TOPIC_HEX}@2?relay-protocol=irn&symKey={SYM_KEY}");
        assert_eq!(parse_pairing_uri(&no_exp, now).unwrap().expiry, None);

        assert_eq!(parse_pairing_uri(&uri(now), now), Err(EXPIRED_LINK));
        assert_eq!(parse_pairing_uri(&uri(now - 1), now), Err(EXPIRED_LINK));
        for topic in [
            "abc",
            &TOPIC_HEX.to_uppercase(),
            &format!("{TOPIC_HEX}00"),
            &"g".repeat(64),
        ] {
            let u = format!("wc:{topic}@2?relay-protocol=irn&symKey={SYM_KEY}");
            assert_eq!(parse_pairing_uri(&u, now), Err(INVALID_LINK), "{topic}");
        }
        let waku = format!("wc:{TOPIC_HEX}@2?relay-protocol=waku&symKey={SYM_KEY}");
        assert_eq!(
            parse_pairing_uri(&waku, now),
            Err("This WalletConnect link uses a relay Kao doesn't support.")
        );
        assert_eq!(parse_pairing_uri(&"x".repeat(5000), now), Err(INVALID_LINK));
    }

    #[test]
    fn pairing_uri_errors_never_echo_input() {
        let now = 1_700_000_000;
        let secret_uri = uri(now + 300);
        let leaks = |s: &str| {
            s.contains(SYM_KEY)
                || s.contains(TOPIC_HEX)
                || s.contains("wc:")
                || s.contains("symKey")
        };
        for bad in [
            secret_uri.replace("wc:", "xx:"), // missing scheme (crate echoes the input)
            secret_uri.replace("@2", "@1"),   // unsupported version
            secret_uri.replace(SYM_KEY, &SYM_KEY[..60]), // short key
            secret_uri.replace(SYM_KEY, &"z".repeat(64)), // non-hex key
            secret_uri.replace("&relay-protocol=irn", ""), // missing relay protocol
            secret_uri.replace(&format!("{}", now + 300), "soon"), // bad expiry
            uri(now - 10),                    // expired
            secret_uri.replace(TOPIC_HEX, "abc"), // bad topic
        ] {
            let e = parse_pairing_uri(&bad, now).unwrap_err();
            assert!(!leaks(e), "{e}");
        }
        // Every crate error, even when its payload is the URI, maps to fixed copy.
        let errors = [
            wallet_connect::Error::InvalidUri(secret_uri.clone()),
            wallet_connect::Error::InvalidKey(secret_uri.clone()),
            wallet_connect::Error::Transport(secret_uri.clone()),
            wallet_connect::Error::Relay(ErrorObject::new(1, secret_uri.clone())),
            wallet_connect::Error::Protocol(ErrorObject::new(5, secret_uri.clone())),
            wallet_connect::Error::Peer(ErrorObject::new(5, secret_uri.clone())),
            wallet_connect::Error::NoPairing(secret_uri.clone()),
            wallet_connect::Error::InvalidEnvelope(secret_uri.clone()),
            wallet_connect::Error::Expired("pairing uri"),
            wallet_connect::Error::Disconnected,
            wallet_connect::Error::Timeout,
            wallet_connect::Error::Closed,
        ];
        for e in &errors {
            let s = pairing_uri_error(e);
            assert!(!leaks(s), "{s}");
            assert!(!s.is_empty());
        }
        assert_eq!(pairing_uri_error(&errors[0]), INVALID_LINK);
        assert_eq!(pairing_uri_error(&errors[8]), EXPIRED_LINK);
        assert_eq!(
            pairing_uri_error(&errors[4]),
            "This link was already used — ask the dapp for a new one."
        );
    }

    // ── gas policy, banners, summaries, plumbing ──────────────────────────────

    #[test]
    fn choose_gas_limit_table() {
        // Empty calldata: the estimate.
        assert_eq!(
            choose_gas_limit(21_000, None, false).unwrap(),
            (21_000, GasNote::Estimated)
        );
        // Calldata: +20 %.
        assert_eq!(
            choose_gas_limit(100_000, None, true).unwrap(),
            (120_000, GasNote::Buffered { estimate: 100_000 })
        );
        // Dapp below the base: the base.
        assert_eq!(
            choose_gas_limit(100_000, Some(90_000), true).unwrap(),
            (120_000, GasNote::Buffered { estimate: 100_000 })
        );
        assert_eq!(
            choose_gas_limit(21_000, Some(21_000), false).unwrap(),
            (21_000, GasNote::Estimated)
        );
        // Dapp in range: honoured.
        assert_eq!(
            choose_gas_limit(100_000, Some(150_000), true).unwrap(),
            (
                150_000,
                GasNote::DappHonoured {
                    estimate: 100_000,
                    dapp: 150_000
                }
            )
        );
        // Dapp above max(2·est, est + 100k): capped there.
        assert_eq!(
            choose_gas_limit(100_000, Some(1_000_000), true).unwrap(),
            (
                200_000,
                GasNote::DappCapped {
                    estimate: 100_000,
                    dapp: 1_000_000
                }
            )
        );
        assert_eq!(
            choose_gas_limit(50_000, Some(1_000_000), true).unwrap(),
            (
                150_000,
                GasNote::DappCapped {
                    estimate: 50_000,
                    dapp: 1_000_000
                }
            )
        );
        // Over the 30 M ceiling: refused.
        assert!(choose_gas_limit(26_000_000, None, true).is_err());
        assert!(choose_gas_limit(20_000_000, Some(40_000_000), true).is_err());
        assert!(choose_gas_limit(GAS_LIMIT_CEILING, None, false).is_ok());
        assert!(
            choose_gas_limit(u64::MAX, Some(u64::MAX), true).is_err(),
            "saturates, never overflows"
        );
    }

    /// EIP-7825: headroom or a dapp's pad never takes a limit whose estimate fits under 2^24 past
    /// it (a node would refuse the signed transaction); an estimate already past it is left to
    /// the 30 M ceiling, unchanged.
    #[test]
    fn choose_gas_limit_never_crosses_the_eip7825_cap() {
        assert_eq!(MAX_TX_GAS, 16_777_216);
        // est 14 M + 20 % = 16.8 M.
        assert_eq!(
            choose_gas_limit(14_000_000, None, true).unwrap(),
            (
                MAX_TX_GAS,
                GasNote::NetworkCapped {
                    estimate: 14_000_000,
                    dapp: None
                }
            )
        );
        // est 9 M, the dapp pads to 18 M (within 2·est).
        assert_eq!(
            choose_gas_limit(9_000_000, Some(18_000_000), true).unwrap(),
            (
                MAX_TX_GAS,
                GasNote::NetworkCapped {
                    estimate: 9_000_000,
                    dapp: Some(18_000_000)
                }
            )
        );
        // est 16 M: the dapp's 16.7 M is below the 19.2 M base, which is capped.
        assert_eq!(
            choose_gas_limit(16_000_000, Some(16_700_000), true).unwrap(),
            (
                MAX_TX_GAS,
                GasNote::NetworkCapped {
                    estimate: 16_000_000,
                    dapp: Some(16_700_000)
                }
            )
        );
        // Exactly at the cap, and a native send at the cap: untouched.
        assert_eq!(
            choose_gas_limit(MAX_TX_GAS, None, false).unwrap(),
            (MAX_TX_GAS, GasNote::Estimated)
        );
        assert_eq!(
            choose_gas_limit(13_000_000, Some(MAX_TX_GAS), true).unwrap(),
            (
                MAX_TX_GAS,
                GasNote::DappHonoured {
                    estimate: 13_000_000,
                    dapp: MAX_TX_GAS
                }
            )
        );
        // Below the cap, nothing changes.
        assert_eq!(
            choose_gas_limit(1_000_000, Some(1_500_000), true)
                .unwrap()
                .0,
            1_500_000
        );
        // An estimate that is itself over the cap isn't rewritten below it.
        assert_eq!(
            choose_gas_limit(20_000_000, None, false).unwrap(),
            (20_000_000, GasNote::Estimated)
        );
    }

    #[test]
    fn owner_action_banner_matches_approve_hash_and_exec() {
        let known = vec![(SAFE, "Treasury".to_string())];
        let hash = b256!("be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");
        let approve = approveHashCall {
            hashToApprove: hash,
        }
        .abi_encode();
        assert_eq!(
            &approve[..4],
            &[0xd4, 0xd9, 0xbd, 0xcd],
            "approveHash(bytes32)"
        );
        let b = owner_action_banner(SAFE, &approve, &known).expect("approveHash on a known Safe");
        assert!(b.contains("approveHash") && b.contains("Treasury"), "{b}");
        assert!(
            b.contains(&hash.to_string()),
            "the approved hash is shown in full: {b}"
        );

        let exec = crate::safe::execTransactionCall {
            to: TO,
            value: U256::ZERO,
            data: Default::default(),
            operation: 0,
            safeTxGas: U256::ZERO,
            baseGas: U256::ZERO,
            gasPrice: U256::ZERO,
            gasToken: Address::ZERO,
            refundReceiver: Address::ZERO,
            signatures: Default::default(),
        }
        .abi_encode();
        assert_eq!(&exec[..4], &[0x6a, 0x76, 0x12, 0x02], "execTransaction(..)");
        let b = owner_action_banner(SAFE, &exec, &known).expect("execTransaction on a known Safe");
        assert!(b.contains("executes a transaction"), "{b}");

        // Not a known Safe, another selector, or too short: no banner.
        assert_eq!(owner_action_banner(TO, &approve, &known), None);
        assert_eq!(
            owner_action_banner(SAFE, &[0xa9, 0x05, 0x9c, 0xbb], &known),
            None
        );
        assert_eq!(owner_action_banner(SAFE, &[0xd4, 0xd9], &known), None);
        assert!(
            owner_action_banner(SAFE, &[0xd4, 0xd9, 0xbd, 0xcd], &known).is_some(),
            "truncated args still flagged"
        );
    }

    #[test]
    fn summarize_call_is_sanitized() {
        let caps = local();
        let a = ok(send(&caps, base_tx(ADDR), 1));
        assert_eq!(
            a.summary,
            format!("Call {} with 0.1 ETH", short_address(TO))
        );
        let mut t = base_tx(ADDR);
        t["data"] = json!("0x");
        assert_eq!(
            ok(send(&caps, t, 1)).summary,
            format!("Send 0.1 ETH to {}", short_address(TO))
        );
        let mut t = base_tx(ADDR);
        t["value"] = json!("0x0");
        assert_eq!(
            ok(send(&caps, t, 1)).summary,
            format!("Call {}", short_address(TO))
        );

        // Dapp text never carries hidden characters into a summary, and stays short.
        let mut m = mail(1);
        m["domain"]["name"] = json!(format!("Ether\u{202E}Mail{}", "!".repeat(200)));
        let a = ok(run(
            &caps,
            "eth_signTypedData_v4",
            json!([ADDR.to_checksum(None), m]),
            1,
        ));
        assert!(
            a.summary.chars().count() <= MAX_SUMMARY_CHARS + 1,
            "{}",
            a.summary
        );
        assert!(!a.summary.contains('\u{202E}'));
        assert!(
            a.summary.starts_with("Sign Mail for Ether\\u{202E}Mail"),
            "{}",
            a.summary
        );
        let long = "y".repeat(500);
        let a = ok(run(
            &caps,
            "personal_sign",
            json!([long, ADDR.to_checksum(None)]),
            1,
        ));
        assert!(a.summary.chars().count() <= MAX_SUMMARY_CHARS + 1);
        assert!(a.summary.starts_with("Sign message “yyy"));
    }

    #[test]
    fn hex_value_is_lowercase_0x() {
        assert_eq!(hex_value(&[0xAB, 0x01]), json!("0xab01"));
        assert_eq!(hex_value(&[]), json!("0x"));
    }

    #[test]
    fn respond_result_classes() {
        use wallet_connect::Error as E;
        assert_eq!(respond_result(&Ok(()), true), RespondResult::Delivered);
        assert_eq!(respond_result(&Ok(()), false), RespondResult::Delivered);
        // Still held by the crate: owed, whatever the failure — a relay JSON-RPC error included.
        for e in [
            E::Disconnected,
            E::Timeout,
            E::Relay(ErrorObject::new(-32603, "internal error")),
            E::Transport("tls\u{202E} reset".into()),
        ] {
            match respond_result(&Err(e), true) {
                RespondResult::Retry(s) => assert!(!s.contains('\u{202E}'), "{s}"),
                other => panic!("expected Retry, got {other:?}"),
            }
        }
        // No longer held (answered, expired, session deleted), or the client shut down.
        assert!(matches!(
            respond_result(&Err(E::Closed), true),
            RespondResult::Gone(_)
        ));
        for e in [
            E::NoRequest(7),
            E::NoSession("t".into()),
            E::Disconnected,
            E::Protocol(ErrorObject::new(8, "Mismatched topic.")),
            E::Transport("tls\u{202E} reset".into()),
        ] {
            match respond_result(&Err(e), false) {
                RespondResult::Gone(s) => assert!(!s.contains('\u{202E}'), "{s}"),
                other => panic!("expected Gone, got {other:?}"),
            }
        }
    }

    // ── the never-panics property ────────────────────────────────────────────

    /// xorshift64* — deterministic, so a failure reproduces.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n.max(1) as u64) as usize
        }
    }

    fn nested(depth: usize) -> Value {
        let mut v = json!(1);
        for _ in 0..depth {
            v = json!([v]);
        }
        v
    }

    fn random_value(rng: &mut Rng) -> Value {
        match rng.below(22) {
            0 => Value::Null,
            1 => json!(rng.below(2) == 0),
            2 => json!(0),
            3 => json!(-1),
            4 => json!(u64::MAX),
            5 => json!(1.5e300),
            6 => json!(""),
            7 => json!("0x"),
            8 => json!("0x0"),
            9 => {
                let n = rng.below(80);
                let bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                json!(format!("0x{}", hex::encode(bytes)))
            }
            10 => json!("\u{202E}evil\u{200B}\n\r\u{E0041}"),
            11 => json!("x".repeat(rng.below(3) * 45_000)),
            12 => json!("0xAb16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"),
            13 => json!(ADDR.to_checksum(None)),
            14 => json!(SAFE.to_checksum(None)),
            15 => json!("-5"),
            16 => json!(format!("0x{}", "ff".repeat(33))),
            17 => json!([]),
            18 => json!({}),
            19 => nested(if rng.below(2) == 0 { 40 } else { 120 }),
            20 => json!({"chainId": "0x1", "name": "x", "type": "(uint256,address)"}),
            _ => json!(OPAQUE),
        }
    }

    const KEYS: &[&str] = &[
        "chainId",
        "operation",
        "accessList",
        "authorizationList",
        "blobs",
        "extra",
        "salt",
        "input",
        "data",
        "type",
        "nonce",
        "gas",
        "maxFeePerBlobGas",
        "EIP712Domain",
        "primaryType",
        "verifyingContract",
        "to",
        "from",
        "value",
        "message",
    ];

    fn pointers(v: &Value) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![(v, String::new())];
        while let Some((v, p)) = stack.pop() {
            if out.len() > 4000 || p.len() > 400 {
                continue;
            }
            match v {
                Value::Array(a) => {
                    for (i, c) in a.iter().enumerate() {
                        stack.push((c, format!("{p}/{i}")));
                    }
                }
                Value::Object(o) => {
                    for (k, c) in o {
                        let k = k.replace('~', "~0").replace('/', "~1");
                        stack.push((c, format!("{p}/{k}")));
                    }
                }
                _ => {}
            }
            out.push(p);
        }
        out
    }

    fn mutate(rng: &mut Rng, root: &mut Value) {
        let ptrs = pointers(root);
        let ptr = ptrs[rng.below(ptrs.len())].clone();
        let op = rng.below(9);
        if op == 2 && !ptr.is_empty() {
            // Delete from the parent.
            let (parent, last) = ptr.rsplit_once('/').unwrap();
            let last = last.replace("~1", "/").replace("~0", "~");
            match root.pointer_mut(parent) {
                Some(Value::Object(o)) => {
                    o.remove(&last);
                }
                Some(Value::Array(a)) => {
                    if let Ok(i) = last.parse::<usize>()
                        && i < a.len()
                    {
                        a.remove(i);
                    }
                }
                _ => {}
            }
            return;
        }
        let fresh = random_value(rng);
        let key = KEYS[rng.below(KEYS.len())];
        let Some(node) = root.pointer_mut(&ptr) else {
            return;
        };
        match op {
            3 => {
                if let Value::Object(o) = node {
                    o.insert(key.to_string(), fresh);
                }
            }
            4 => *node = Value::String(node.to_string()),
            5 => {
                if let Value::Array(a) = node
                    && a.len() >= 2
                {
                    let last = a.len() - 1;
                    a.swap(0, last);
                }
            }
            6 => {
                if let Value::Array(a) = node {
                    a.push(fresh);
                }
            }
            7 => {
                if let Value::String(s) = node {
                    let cut = s
                        .char_indices()
                        .map(|(i, _)| i)
                        .nth(rng.below(s.len() + 1))
                        .unwrap_or(s.len());
                    s.truncate(cut);
                    s.push_str(["\u{202E}", "A", "0", "", "zz"][rng.below(5)]);
                }
            }
            _ => *node = fresh,
        }
    }

    fn fixtures(from: Address) -> Vec<(&'static str, Value)> {
        let a = from.to_checksum(None);
        let siwe = format!(
            "app.example wants you to sign in with your Ethereum account:\n{a}\n\nURI: https://app.example\nVersion: 1\nChain ID: 1\nNonce: 42"
        );
        let mut permit = mail(1);
        permit["types"]["Mail"] = json!([{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"},
            {"name": "value", "type": "uint256"}, {"name": "nonce", "type": "uint256"}, {"name": "deadline", "type": "uint256"}]);
        permit["types"].as_object_mut().unwrap().remove("Person");
        permit["primaryType"] = json!("Mail");
        permit["message"] = json!({"owner": a, "spender": TO.to_checksum(None), "value": U256::MAX.to_string(), "nonce": 0, "deadline": 1});
        let mut full_tx = base_tx(from);
        full_tx["nonce"] = json!("0x7");
        full_tx["gas"] = json!("0x5208");
        full_tx["maxFeePerGas"] = json!("0x1");
        full_tx["type"] = json!("0x2");
        full_tx["chainId"] = json!("0x1");
        full_tx["accessList"] = json!([]);
        vec![
            ("personal_sign", json!(["0x48656c6c6f", a])),
            ("personal_sign", json!([siwe, a])),
            ("personal_sign", json!([OPAQUE, a])),
            ("eth_signTypedData_v4", json!([a, mail(1)])),
            ("eth_signTypedData_v4", json!([a, mail(1).to_string()])),
            ("eth_signTypedData", json!([a, permit])),
            ("eth_sendTransaction", json!([base_tx(from)])),
            ("eth_sendTransaction", json!([full_tx])),
            ("wallet_switchEthereumChain", json!([{"chainId": "0x2105"}])),
            ("eth_accounts", json!([])),
            ("eth_chainId", json!([])),
            ("eth_sign", json!([a, OPAQUE])),
        ]
    }

    const METHODS: &[&str] = &[
        "personal_sign",
        "eth_signTypedData_v4",
        "eth_signTypedData",
        "eth_sendTransaction",
        "wallet_switchEthereumChain",
        "eth_accounts",
        "eth_chainId",
        "eth_sign",
        "eth_signTypedData_v3",
        "foo_bar",
        "",
        "personal_sign\u{202E}",
    ];
    const CHAINS: &[&str] = &[
        "eip155:1",
        "eip155:8453",
        "eip155:10",
        "eip155:01",
        "eip155:",
        "",
        "solana:1",
        "eip155:99999999999999999999999",
    ];

    fn assert_admission_invariants(
        a: &Admitted,
        s: &BoundSession,
        caps: &IdentityCaps,
        method: &str,
    ) {
        assert!(s.chains.contains(&a.chain_id) && caps.serves_chain(a.chain_id));
        assert!(
            a.summary.chars().count() <= MAX_SUMMARY_CHARS + 1,
            "{}",
            a.summary
        );
        assert!(
            exact_display_lines(&a.summary, 1, 200).is_some(),
            "{:?}",
            a.summary
        );
        let me = s.identity.address();
        match &a.call {
            WcCall::PersonalSign(p) => {
                assert_eq!(method, "personal_sign");
                assert_eq!(p.from, me);
                assert!(!p.message.is_empty() && p.message.len() <= MAX_MESSAGE_BYTES);
                if matches!(
                    p.shape,
                    MessageShape::Binary {
                        reason: BinaryReason::OpaqueHash32,
                        ..
                    }
                ) {
                    assert!(!caps.safe_owner());
                }
                assert!(caps.messages().is_ok());
            }
            WcCall::SignTypedData(t) => {
                assert!(method.starts_with("eth_signTypedData"));
                assert_eq!(t.from, me);
                assert!(caps.typed_data().is_ok());
                assert_ne!(t.typed.primary_type, "EIP712Domain");
                assert_eq!(
                    t.checked.digests.digest,
                    t.typed.eip712_signing_hash().unwrap()
                );
                assert!(t.checked.domain.chain_id.is_none_or(|c| c == a.chain_id));
                assert!(t.checked.model.rows.len() <= MAX_TYPED_ROWS);
            }
            WcCall::SendTransaction(t) => {
                assert_eq!(method, "eth_sendTransaction");
                assert_eq!(t.from, me);
                assert_ne!(t.to, Address::ZERO);
                assert!(t.data.len() <= MAX_TX_DATA_BYTES);
                assert_eq!(t.chain_id, a.chain_id);
                assert!(caps.transactions().is_ok());
                if s.identity.is_safe() {
                    assert_eq!(t.dapp_gas, None);
                }
            }
            WcCall::SwitchChain { chain_id } => {
                assert_eq!(method, "wallet_switchEthereumChain");
                assert_ne!(*chain_id, 0);
            }
            WcCall::Accounts => {
                assert!(method == "eth_accounts" || method == "eth_requestAccounts")
            }
            WcCall::ChainId => assert_eq!(method, "eth_chainId"),
        }
    }

    #[test]
    fn validate_never_panics_on_mutated_fixtures() {
        let identities = [
            local(),
            eoa_caps(EoaKind::Trezor, true, &[1, 8453]),
            safe_caps(1, 1),
        ];
        let allowed_codes = [
            codes::UNAUTHORIZED,
            codes::UNSUPPORTED_METHOD,
            codes::CHAIN_DISCONNECTED,
            codes::INVALID_PARAMS,
            codes::INTERNAL,
        ];
        let mut rng = Rng(0x5eed_cafe_f00d_d00d);
        let mut admitted = 0usize;
        const ROUNDS: usize = 1500;
        for round in 0..ROUNDS {
            let caps = &identities[round % identities.len()];
            let s = session(caps);
            let fx = fixtures(caps.identity.address());
            let (base_method, base_params) = fx[rng.below(fx.len())].clone();
            let mut params = base_params;
            for _ in 0..1 + rng.below(4) {
                mutate(&mut rng, &mut params);
            }
            let method = if rng.below(8) == 0 {
                METHODS[rng.below(METHODS.len())]
            } else {
                base_method
            };
            let mut r = req(method, params, 1);
            if rng.below(8) == 0 {
                r.chain_id = CHAINS[rng.below(CHAINS.len())].to_string();
            }
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| validate(&r, &s, caps)));
            let Ok(result) = outcome else {
                let shown: String = r.request.params.to_string().chars().take(2000).collect();
                panic!(
                    "validate panicked (round {round}, {method} on {}): {shown}",
                    r.chain_id
                );
            };
            match result {
                Ok(a) => {
                    admitted += 1;
                    assert_admission_invariants(&a, &s, caps, method);
                    let _ = immediate_answer(&a.call, &s, a.chain_id);
                }
                Err(e) => {
                    assert!(!e.message.is_empty());
                    assert!(allowed_codes.contains(&e.code), "{e:?}");
                }
            }
        }
        // The fuzz must exercise both outcomes, not just bounce off the envelope.
        assert!(
            admitted > ROUNDS / 20,
            "only {admitted} admissions in {ROUNDS} rounds"
        );
        assert!(admitted < ROUNDS, "every mutation admitted");
    }
}
