// Phase 1 scaffolding — see `walletconnect/mod.rs`.
#![allow(dead_code)]

//! WalletConnect Sign v2 protocol envelopes and constants.
//!
//! These are the JSON-RPC payloads that live *inside* an encrypted relay
//! envelope (Type 0 or Type 1). The relay never sees these structures —
//! it only sees opaque base64 strings — but every dApp and wallet on the
//! network must agree on the shape.
//!
//! Spec references:
//! - <https://specs.walletconnect.com/2.0/specs/clients/sign/session-proposal>
//! - <https://specs.walletconnect.com/2.0/specs/clients/sign/session-settlement>
//! - <https://specs.walletconnect.com/2.0/specs/clients/sign/session-requests>
//! - <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods>
//!
//! Method tags and TTLs are spec-defined constants — changing them silently
//! breaks interop with every dApp on the network. The relay uses the tag
//! number to route message-buffering policy (push notifications, archival)
//! so getting it wrong means messages get dropped instead of queued.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// ── Method tags ─────────────────────────────────────────────────────────
//
// Tags are spec-mandated `u32` constants the relay uses to classify
// messages. Request and response carry distinct tags so the relay can apply
// different TTL/retention policies to each. Source:
// https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods

pub const TAG_SESSION_PROPOSE_REQ: u32 = 1100;
pub const TAG_SESSION_PROPOSE_RES: u32 = 1101;
pub const TAG_SESSION_SETTLE_REQ: u32 = 1102;
pub const TAG_SESSION_SETTLE_RES: u32 = 1103;
pub const TAG_SESSION_UPDATE_REQ: u32 = 1104;
pub const TAG_SESSION_UPDATE_RES: u32 = 1105;
pub const TAG_SESSION_EXTEND_REQ: u32 = 1106;
pub const TAG_SESSION_EXTEND_RES: u32 = 1107;
pub const TAG_SESSION_REQUEST_REQ: u32 = 1108;
pub const TAG_SESSION_REQUEST_RES: u32 = 1109;
pub const TAG_SESSION_EVENT_REQ: u32 = 1110;
pub const TAG_SESSION_EVENT_RES: u32 = 1111;
pub const TAG_SESSION_DELETE_REQ: u32 = 1112;
pub const TAG_SESSION_DELETE_RES: u32 = 1113;
pub const TAG_SESSION_PING_REQ: u32 = 1114;
pub const TAG_SESSION_PING_RES: u32 = 1115;

// ── TTLs ────────────────────────────────────────────────────────────────
//
// Relay-side buffering windows. A wallet that's offline longer than the TTL
// for an inbound request will silently miss that request — picking up only
// the next one within window. 5 minutes for `sessionRequest` is the
// load-bearing constraint: it caps how long a user can leave the wallet
// closed between dApp interactions before requests get dropped.

use std::time::Duration;

pub const TTL_SESSION_PROPOSE: Duration = Duration::from_secs(5 * 60);
pub const TTL_SESSION_SETTLE: Duration = Duration::from_secs(5 * 60);
pub const TTL_SESSION_UPDATE: Duration = Duration::from_secs(24 * 60 * 60);
pub const TTL_SESSION_EXTEND: Duration = Duration::from_secs(24 * 60 * 60);
pub const TTL_SESSION_REQUEST: Duration = Duration::from_secs(5 * 60);
pub const TTL_SESSION_EVENT: Duration = Duration::from_secs(5 * 60);
pub const TTL_SESSION_DELETE: Duration = Duration::from_secs(24 * 60 * 60);
pub const TTL_SESSION_PING: Duration = Duration::from_secs(30);

/// Default session lifetime when the dApp doesn't specify one. 7 days, per
/// spec. Sessions can be extended with `wc_sessionExtend`.
pub const DEFAULT_SESSION_LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);

// ── JSON-RPC envelopes ───────────────────────────────────────────────────
//
// All Sign-protocol messages are JSON-RPC 2.0 inside the encrypted relay
// envelope. We split request and response into separate types rather than
// one untagged enum because the engine routes them down distinct paths:
// requests fan out to handlers (`methods` module), responses fulfil pending
// awaiters keyed by `id`.

/// A request from the peer (dApp → wallet for inbound, wallet → dApp for
/// outbound). The `method` discriminator tells the dispatcher which handler
/// to invoke; `params` is left as a `serde_json::Value` so the handler can
/// pick the right concrete type for its specific method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub id: u64,
    pub jsonrpc: JsonRpcVersion,
    pub method: String,
    pub params: serde_json::Value,
}

/// A success or error response keyed by the request `id` it answers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub id: u64,
    pub jsonrpc: JsonRpcVersion,
    #[serde(flatten)]
    pub payload: JsonRpcResult,
}

/// Untagged so it deserialises either shape — JSON-RPC responses carry
/// exactly one of `result` or `error`, never both.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcResult {
    Success { result: serde_json::Value },
    Error { error: JsonRpcError },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Zero-sized newtype that serialises to/from the literal string `"2.0"`.
/// Wrapping it makes the version unforgettable at construction sites —
/// `JsonRpcRequest { jsonrpc: JsonRpcVersion, ... }` doesn't compile if you
/// fat-finger the wire constant.
///
/// Custom `Serialize`/`Deserialize` impls — not derived — because the type
/// has to round-trip through `serde_json::from_value` (the engine reads
/// an inbound payload as `Value` to peek at `method`/`result` before
/// committing to request vs. response shape). The derive-friendly
/// `try_from = "&str"` shortcut fails on `from_value` because the
/// borrowed-string path isn't supplied by `serde_json::Value`'s
/// deserializer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonRpcVersion;

impl JsonRpcVersion {
    pub const STR: &'static str = "2.0";
}

impl serde::Serialize for JsonRpcVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(Self::STR)
    }
}

impl<'de> serde::Deserialize<'de> for JsonRpcVersion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == Self::STR {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected jsonrpc \"2.0\", got {s:?}"
            )))
        }
    }
}

// ── Standard error codes ─────────────────────────────────────────────────
//
// Subset of the codes defined in WC's spec (see Sign error registry). We
// surface the ones the wallet emits; others (relay-side, push-side) are
// never produced by us.

/// JSON-RPC standard: method does not exist or is not available.
pub const ERROR_METHOD_NOT_FOUND: i32 = -32601;
/// JSON-RPC standard: invalid params.
pub const ERROR_INVALID_PARAMS: i32 = -32602;
/// JSON-RPC standard: internal error.
pub const ERROR_INTERNAL: i32 = -32603;
/// Wallet rejected the request (user clicked "Reject"). Mirrors EIP-1193's
/// 4001 user-rejected code; some dApps treat this specifically.
pub const ERROR_USER_REJECTED: i32 = 5000;
/// Requested method is outside the approved session scope.
pub const ERROR_UNAUTHORIZED_METHOD: i32 = 3001;
/// Requested chain is outside the approved session scope.
pub const ERROR_UNAUTHORIZED_CHAIN: i32 = 3005;
/// Session not found or already deleted.
pub const ERROR_NO_SESSION: i32 = 7001;

// ── Sign-protocol payload types ──────────────────────────────────────────
//
// One pair (`<Method>Params` / `<Method>Result`) per spec'd method. Kept
// minimal in Phase 1 — Phase 2/3 will fill in remaining optional fields as
// the engine grows.

/// Peer metadata (`Metadata` in the spec). Both sides exchange one of these
/// during proposal/settle. Used by the wallet to render the dApp's name,
/// icon, and origin URL in the approval modal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerMetadata {
    pub name: String,
    pub description: String,
    pub url: String,
    pub icons: Vec<String>,
    /// Optional, only present when the wallet emits it (links into deep
    /// links / push notification dispatch). Wallets receiving from a dApp
    /// usually find this absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<Redirect>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Redirect {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub universal: Option<String>,
}

/// A single namespace scope: which chains, methods, and events a session
/// covers. `eip155` is the EVM namespace; non-EVM namespaces (cosmos,
/// solana, …) follow the same shape under different keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamespaceProposal {
    #[serde(default)]
    pub chains: Vec<String>,
    pub methods: Vec<String>,
    pub events: Vec<String>,
}

/// Settled (approved) form of a namespace: includes the concrete `accounts`
/// the wallet exposes, in CAIP-10 form (`eip155:1:0xabc…`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamespaceSettled {
    #[serde(default)]
    pub chains: Vec<String>,
    pub accounts: Vec<String>,
    pub methods: Vec<String>,
    pub events: Vec<String>,
}

/// Relay routing block included in every proposal/settle. The wallet must
/// echo `protocol` back on settle so the dApp sees a matching pairing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayInfo {
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// `wc_sessionPropose` request from dApp → wallet. Carries the dApp's
/// ephemeral x25519 public key inside `proposer.publicKey` (lowercase hex);
/// the wallet ECDHs against it to derive the session symKey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionProposeParams {
    pub relays: Vec<RelayInfo>,
    pub proposer: Proposer,
    #[serde(rename = "requiredNamespaces", default)]
    pub required_namespaces: BTreeMap<String, NamespaceProposal>,
    #[serde(rename = "optionalNamespaces", default)]
    pub optional_namespaces: BTreeMap<String, NamespaceProposal>,
    #[serde(
        rename = "sessionProperties",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_properties: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proposer {
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub metadata: PeerMetadata,
}

/// Response to `wc_sessionPropose`. Wallet returns its own ephemeral pubkey
/// and the agreed relay. The dApp uses `responderPublicKey` to derive the
/// same session symKey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionProposeResult {
    pub relay: RelayInfo,
    #[serde(rename = "responderPublicKey")]
    pub responder_public_key: String,
}

/// `wc_sessionSettle` request from wallet → dApp on the new session topic.
/// Carries the concrete namespace mapping (accounts the wallet exposes) and
/// the agreed session expiry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSettleParams {
    pub relay: RelayInfo,
    pub controller: Controller,
    pub namespaces: BTreeMap<String, NamespaceSettled>,
    #[serde(
        rename = "sessionProperties",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_properties: Option<BTreeMap<String, String>>,
    pub expiry: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Controller {
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub metadata: PeerMetadata,
}

/// `wc_sessionRequest` from dApp → wallet — the main runtime carrier for
/// `personal_sign`, `eth_sendTransaction`, etc. The wallet inspects
/// `request.method` and dispatches to the matching handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRequestParams {
    /// Which chain the call should run against, e.g. `"eip155:1"`. Must be
    /// in the session's approved chains list.
    #[serde(rename = "chainId")]
    pub chain_id: String,
    pub request: InnerRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InnerRequest {
    pub method: String,
    pub params: serde_json::Value,
    /// Optional `expiryTimestamp` (Unix seconds) — requests past expiry
    /// MUST be ignored. Only some dApps set it; absence means "use the
    /// session-default 5-minute window".
    #[serde(
        rename = "expiryTimestamp",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expiry: Option<u64>,
}

/// `wc_sessionUpdate` request — controller (wallet) updates the approved
/// namespaces mid-session. dApp must accept or terminate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUpdateParams {
    pub namespaces: BTreeMap<String, NamespaceSettled>,
}

/// `wc_sessionExtend` request — extend session expiry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionExtendParams {
    pub expiry: u64,
}

/// `wc_sessionEvent` request — wallet emits an event (e.g.
/// `accountsChanged`, `chainChanged`) to the dApp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEventParams {
    #[serde(rename = "chainId")]
    pub chain_id: String,
    pub event: InnerEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InnerEvent {
    pub name: String,
    pub data: serde_json::Value,
}

/// `wc_sessionDelete` request — terminate the session. Either side may
/// emit; the receiver must clean up local state and not reply with another
/// `sessionDelete`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDeleteParams {
    pub code: i32,
    pub message: String,
}

/// `wc_sessionPing` request body. Spec sends an empty object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionPingParams {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jsonrpc_version_serializes_as_string() {
        let v = JsonRpcVersion;
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, "\"2.0\"");
    }

    #[test]
    fn jsonrpc_version_rejects_wrong_string() {
        // `serde_json::from_str` should fail on any version other than 2.0.
        let res: Result<JsonRpcVersion, _> = serde_json::from_str("\"1.0\"");
        assert!(res.is_err());
    }

    #[test]
    fn jsonrpc_request_round_trip() {
        let req = JsonRpcRequest {
            id: 1234567890,
            jsonrpc: JsonRpcVersion,
            method: "wc_sessionPing".to_string(),
            params: json!({}),
        };
        let s = serde_json::to_string(&req).unwrap();
        let back: JsonRpcRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, req.id);
        assert_eq!(back.method, req.method);
    }

    #[test]
    fn jsonrpc_success_response_round_trip() {
        let res = JsonRpcResponse {
            id: 7,
            jsonrpc: JsonRpcVersion,
            payload: JsonRpcResult::Success {
                result: json!("0xdeadbeef"),
            },
        };
        let s = serde_json::to_string(&res).unwrap();
        // success responses must have `result`, never `error`.
        assert!(s.contains("\"result\""));
        assert!(!s.contains("\"error\""));
        let back: JsonRpcResponse = serde_json::from_str(&s).unwrap();
        match back.payload {
            JsonRpcResult::Success { result } => assert_eq!(result, json!("0xdeadbeef")),
            JsonRpcResult::Error { .. } => panic!("expected Success"),
        }
    }

    #[test]
    fn jsonrpc_error_response_round_trip() {
        let res = JsonRpcResponse {
            id: 8,
            jsonrpc: JsonRpcVersion,
            payload: JsonRpcResult::Error {
                error: JsonRpcError {
                    code: ERROR_USER_REJECTED,
                    message: "user rejected".to_string(),
                    data: None,
                },
            },
        };
        let s = serde_json::to_string(&res).unwrap();
        assert!(s.contains("\"error\""));
        assert!(!s.contains("\"result\""));
        let back: JsonRpcResponse = serde_json::from_str(&s).unwrap();
        match back.payload {
            JsonRpcResult::Error { error } => {
                assert_eq!(error.code, ERROR_USER_REJECTED);
                assert_eq!(error.message, "user rejected");
            }
            JsonRpcResult::Success { .. } => panic!("expected Error"),
        }
    }

    #[test]
    fn session_propose_params_round_trip() {
        // Mirror the shape of a real-world `wc_sessionPropose` payload from
        // the reference dApp, minus the noise. If the field-naming drifts
        // (camelCase, requiredNamespaces, etc.) we want to catch it here
        // rather than at first contact with a live dApp.
        let raw = json!({
            "relays": [{"protocol": "irn"}],
            "proposer": {
                "publicKey": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
                "metadata": {
                    "name": "TestDapp",
                    "description": "A test dApp",
                    "url": "https://test.example",
                    "icons": ["https://test.example/icon.png"]
                }
            },
            "requiredNamespaces": {
                "eip155": {
                    "chains": ["eip155:1"],
                    "methods": ["eth_sendTransaction", "personal_sign"],
                    "events": ["chainChanged", "accountsChanged"]
                }
            }
        });
        let parsed: SessionProposeParams = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(parsed.relays.len(), 1);
        assert_eq!(parsed.relays[0].protocol, "irn");
        assert_eq!(parsed.proposer.metadata.name, "TestDapp");
        let eip155 = parsed.required_namespaces.get("eip155").unwrap();
        assert_eq!(eip155.chains, vec!["eip155:1"]);
        assert_eq!(eip155.methods.len(), 2);

        // Re-serialise and check field names survived (catches accidental
        // serde renames).
        let re = serde_json::to_value(&parsed).unwrap();
        assert!(re.get("requiredNamespaces").is_some());
        assert!(re["proposer"].get("publicKey").is_some());
    }

    #[test]
    fn session_settle_params_round_trip() {
        let raw = json!({
            "relay": {"protocol": "irn"},
            "controller": {
                "publicKey": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                "metadata": {
                    "name": "Kao",
                    "description": "Kao Wallet",
                    "url": "https://kao.example",
                    "icons": []
                }
            },
            "namespaces": {
                "eip155": {
                    "chains": ["eip155:1", "eip155:8453"],
                    "accounts": [
                        "eip155:1:0x1111111111111111111111111111111111111111",
                        "eip155:8453:0x1111111111111111111111111111111111111111"
                    ],
                    "methods": ["personal_sign", "eth_sendTransaction"],
                    "events": ["chainChanged", "accountsChanged"]
                }
            },
            "expiry": 1700000000
        });
        let parsed: SessionSettleParams = serde_json::from_value(raw).unwrap();
        assert_eq!(parsed.expiry, 1700000000);
        let ns = parsed.namespaces.get("eip155").unwrap();
        assert_eq!(ns.accounts.len(), 2);
        assert_eq!(ns.chains, vec!["eip155:1", "eip155:8453"]);
    }

    #[test]
    fn session_request_params_round_trip() {
        let raw = json!({
            "chainId": "eip155:1",
            "request": {
                "method": "personal_sign",
                "params": [
                    "0x48656c6c6f",
                    "0x1111111111111111111111111111111111111111"
                ]
            }
        });
        let parsed: SessionRequestParams = serde_json::from_value(raw).unwrap();
        assert_eq!(parsed.chain_id, "eip155:1");
        assert_eq!(parsed.request.method, "personal_sign");
        assert_eq!(parsed.request.params.as_array().unwrap().len(), 2);
        assert_eq!(parsed.request.expiry, None);
    }

    #[test]
    fn session_request_with_inner_expiry() {
        let raw = json!({
            "chainId": "eip155:10",
            "request": {
                "method": "eth_sendTransaction",
                "params": [{}],
                "expiryTimestamp": 1700000000u64
            }
        });
        let parsed: SessionRequestParams = serde_json::from_value(raw).unwrap();
        assert_eq!(parsed.request.expiry, Some(1700000000));
    }

    #[test]
    fn session_delete_params_round_trip() {
        let raw = json!({"code": 6000, "message": "User disconnected"});
        let parsed: SessionDeleteParams = serde_json::from_value(raw).unwrap();
        assert_eq!(parsed.code, 6000);
        assert_eq!(parsed.message, "User disconnected");
    }

    #[test]
    fn tags_are_distinct() {
        // Defensive — accidentally duplicating a tag would route messages
        // to the wrong handler silently.
        let tags = [
            TAG_SESSION_PROPOSE_REQ,
            TAG_SESSION_PROPOSE_RES,
            TAG_SESSION_SETTLE_REQ,
            TAG_SESSION_SETTLE_RES,
            TAG_SESSION_UPDATE_REQ,
            TAG_SESSION_UPDATE_RES,
            TAG_SESSION_EXTEND_REQ,
            TAG_SESSION_EXTEND_RES,
            TAG_SESSION_REQUEST_REQ,
            TAG_SESSION_REQUEST_RES,
            TAG_SESSION_EVENT_REQ,
            TAG_SESSION_EVENT_RES,
            TAG_SESSION_DELETE_REQ,
            TAG_SESSION_DELETE_RES,
            TAG_SESSION_PING_REQ,
            TAG_SESSION_PING_RES,
        ];
        for (i, a) in tags.iter().enumerate() {
            for b in &tags[i + 1..] {
                assert_ne!(a, b, "duplicate tag value {a}");
            }
        }
    }
}
