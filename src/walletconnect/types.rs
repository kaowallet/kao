//! Cross-module WalletConnect types: what the runtime, the book, the policy core and the dashboard
//! hand each other.
//!
//! Plain data. Dapp-supplied strings appear here only after sanitization (`DappLabel`, `MessageShape`,
//! typed rows, `summary`); raw payloads stay inside `WcCall` / `ProposalCard::proposal` and are never
//! rendered directly.

use std::fmt;
use std::sync::Arc;

use alloy::primitives::{Address, B256, Bytes, U256};
use wallet_connect::crypto::{PublicKey, Topic};
use wallet_connect::rpc::ErrorObject;
use wallet_connect::sign::{Metadata, PendingRequest, Proposal, SessionNamespaces};

use crate::chain::Chain;
use crate::sign::digest::Eip712Digests;
use crate::sign::typed::TypedDataModel;

// ───────────────────────────── codes & refusals ─────────────────────────────

pub mod codes {
    pub const USER_REJECTED: i64 = 4001; // EIP-1193 user rejection; every client library maps it
    pub const UNAUTHORIZED: i64 = 4100;
    pub const UNSUPPORTED_METHOD: i64 = 4200;
    pub const DISCONNECTED: i64 = 4900;
    pub const CHAIN_DISCONNECTED: i64 = 4901;
    pub const UNRECOGNIZED_CHAIN: i64 = 4902; // EIP-3326
    pub const INVALID_REQUEST: i64 = -32600;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL: i64 = -32603;
    pub const LIMIT_EXCEEDED: i64 = -32005;
}

/// Why Kao won't (or can't) answer a request with a result. `message` is the only text a dapp ever
/// sees and is `&'static str` BY TYPE; `detail` is for the user (pane notice / review error), never sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: i64,
    pub message: &'static str,
    pub detail: String,
}

impl Refusal {
    pub fn new(code: i64, message: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            message,
            detail: detail.into(),
        }
    }
    pub fn user_rejected() -> Self {
        Self::new(
            codes::USER_REJECTED,
            "User rejected the request.",
            "you rejected the request",
        )
    }
    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(
            codes::UNAUTHORIZED,
            "The requested account is not authorized for this session.",
            detail,
        )
    }
    pub fn unsupported(message: &'static str, detail: impl Into<String>) -> Self {
        Self::new(codes::UNSUPPORTED_METHOD, message, detail)
    }
    pub fn invalid_params(message: &'static str, detail: impl Into<String>) -> Self {
        Self::new(codes::INVALID_PARAMS, message, detail)
    }
    pub fn chain_not_served(detail: impl Into<String>) -> Self {
        Self::new(
            codes::CHAIN_DISCONNECTED,
            "Kao no longer serves this chain.",
            detail,
        )
    }
    pub fn unrecognized_chain() -> Self {
        Self::new(
            codes::UNRECOGNIZED_CHAIN,
            "Unrecognized chain.",
            "the dapp asked to switch to a chain this session doesn't include",
        )
    }
    pub fn expired() -> Self {
        Self::new(
            codes::INTERNAL,
            "Request expired before it was reviewed.",
            "the request expired before you reviewed it",
        )
    }
    pub fn closing() -> Self {
        Self::new(
            codes::DISCONNECTED,
            "Kao is closing; request cancelled.",
            "Kao locked or quit",
        )
    }
    /// A request still pending in a restored session that Kao never reviewed (it arrived before
    /// Kao locked or quit and no answer was owed).
    pub fn restarted() -> Self {
        Self::new(
            codes::DISCONNECTED,
            "Kao restarted before this request was reviewed.",
            "Kao restarted",
        )
    }
    /// A request Kao was signing (or sending) when it locked or quit, its outcome unknown: never
    /// "not reviewed" or "cancelled" — a transaction may have left the wallet.
    pub fn interrupted() -> Self {
        Self::new(
            codes::INTERNAL,
            "Kao closed while this request was being signed — it may have gone through; check \
             your activity before trying again.",
            "Kao closed while signing",
        )
    }
    pub fn limit() -> Self {
        Self::new(
            codes::LIMIT_EXCEEDED,
            "Too many pending requests.",
            "the dapp sent too many requests at once",
        )
    }
    pub fn duplicate() -> Self {
        Self::new(
            codes::INVALID_REQUEST,
            "Duplicate request id.",
            "the dapp re-sent a request Kao already answered",
        )
    }
    pub fn failed(detail: impl Into<String>) -> Self {
        Self::new(
            codes::INTERNAL,
            "The wallet could not complete the request.",
            detail,
        )
    }
    /// A request given up on while its transaction, `hash`, may be on its way: never "rejected",
    /// "expired" or "cancelled" — the user approved it, and it may yet be mined.
    pub fn unconfirmed(hash: B256) -> Self {
        Self::failed(format!(
            "transaction {hash:#x} may still be mined — Kao couldn't confirm the network received it"
        ))
    }
    /// The JSON-RPC error a dapp receives — code + the static message, never `detail`.
    pub fn error_object(&self) -> ErrorObject {
        ErrorObject::new(self.code, self.message)
    }
}

// ───────────────────────────── identity ─────────────────────────────

/// One dapp request. JSON-RPC ids are only unique per peer; Kao keys everything by (topic, id).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WcKey {
    pub topic: Topic,
    pub id: u64,
}

/// What a session is bound to — fixed at approval, never re-bound. A Safe is (address, chain):
/// same-address sibling Safes on other chains are different identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WcIdentity {
    Eoa { address: Address },
    Safe { address: Address, chain_id: u64 },
}

impl WcIdentity {
    pub fn address(&self) -> Address {
        match self {
            Self::Eoa { address } | Self::Safe { address, .. } => *address,
        }
    }
    pub fn is_safe(&self) -> bool {
        matches!(self, Self::Safe { .. })
    }
    /// `eip155:<chain>:<EIP-55>` — `to_checksum(None)` (EIP-55, not EIP-1191).
    pub fn caip10(&self, chain_id: u64) -> String {
        format!("eip155:{chain_id}:{}", self.address().to_checksum(None))
    }
}

/// Signer kind, from the `AccountDescriptor` — never the live `KaoSigner` (it may be a ViewOnly
/// placeholder or parked).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EoaKind {
    Local,
    Ledger,
    Trezor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EoaCaps {
    pub kind: EoaKind,
    /// The address is an owner of some Safe in Kao's wallet (cached owner sets) — gates the opaque
    /// 32-byte personal_sign refusal (signed, it would be a valid Safe owner confirmation).
    pub safe_owner: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeCaps {
    pub chain: Chain,
    pub version: String,
    pub threshold: u32,
    pub owner_count: u32,
    /// Strict: linked ∧ Local/Ledger/Trezor ∧ address ∈ cached owners (`strict_signable_indices`).
    pub local_signers: u32,
    /// The fallback handler validates EIP-1271 signatures for this Safe's
    /// version (one of Safe's own handlers, `safe::validates_eip1271`).
    /// Without it a message signature can never be checked by the Safe.
    pub fallback_handler: bool,
    /// `trust.signing_block_reason()` / `ensure_signable_version` failure, if any.
    pub signing_block: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityKind {
    Eoa(EoaCaps),
    Safe(SafeCaps),
}

/// What an identity can do right now. Built by the coordinator from descriptors (`wc_caps`), consumed
/// by pure policy (namespaces / request).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityCaps {
    pub identity: WcIdentity,
    /// Sanitized local name ("Account 2", "Treasury").
    pub label: String,
    pub kind: IdentityKind,
    /// EOA: `served_chain_ids()`. Safe: `[chain_id]` if served, else empty.
    pub chains: Vec<u64>,
}

impl IdentityCaps {
    pub fn serves_chain(&self, chain_id: u64) -> bool {
        self.chains.contains(&chain_id)
    }
    pub fn messages(&self) -> Result<(), Refusal> {
        match &self.kind {
            IdentityKind::Eoa(_) => Ok(()),
            IdentityKind::Safe(s) => {
                if let Some(why) = &s.signing_block {
                    return Err(Refusal::unsupported(
                        "This Safe can't sign from Kao.",
                        why.clone(),
                    ));
                }
                if !s.fallback_handler {
                    return Err(Refusal::unsupported(
                        "This Safe can't sign messages.",
                        "this Safe's fallback handler can't validate EIP-1271 signatures",
                    ));
                }
                if s.local_signers < s.threshold {
                    return Err(Refusal::unsupported(
                        "This Safe can't sign messages from Kao.",
                        format!(
                            "message signatures need {} owner keys in Kao; Kao holds {}",
                            s.threshold, s.local_signers
                        ),
                    ));
                }
                Ok(())
            }
        }
    }
    pub fn typed_data(&self) -> Result<(), Refusal> {
        match &self.kind {
            IdentityKind::Eoa(EoaCaps {
                kind: EoaKind::Trezor,
                ..
            }) => Err(Refusal::unsupported(
                "Trezor can't sign EIP-712 typed data.",
                "Kao's Trezor support has no EIP-712 signing path",
            )),
            IdentityKind::Eoa(_) => Ok(()),
            IdentityKind::Safe(_) => self.messages(),
        }
    }
    pub fn transactions(&self) -> Result<(), Refusal> {
        match &self.kind {
            IdentityKind::Eoa(_) => Ok(()),
            IdentityKind::Safe(s) => {
                if let Some(why) = &s.signing_block {
                    return Err(Refusal::unsupported(
                        "This Safe can't sign from Kao.",
                        why.clone(),
                    ));
                }
                if s.local_signers == 0 {
                    return Err(Refusal::unsupported(
                        "No owner key for this Safe in Kao.",
                        "Kao holds none of this Safe's owner keys",
                    ));
                }
                Ok(())
            }
        }
    }
    /// Ledger EOA: the device shows only the Domain Hash and Message Hash for typed data.
    pub fn typed_hash_mode(&self) -> bool {
        matches!(
            &self.kind,
            IdentityKind::Eoa(EoaCaps {
                kind: EoaKind::Ledger,
                ..
            })
        )
    }
    pub fn hardware(&self) -> bool {
        matches!(
            &self.kind,
            IdentityKind::Eoa(EoaCaps {
                kind: EoaKind::Ledger | EoaKind::Trezor,
                ..
            })
        )
    }
    pub fn safe_owner(&self) -> bool {
        matches!(
            &self.kind,
            IdentityKind::Eoa(EoaCaps {
                safe_owner: true,
                ..
            })
        )
    }
    /// `personal_sign` of a message shaped `shape`: [`Self::messages`], then the opaque-hash rule — an opaque 32-byte
    /// value is refused for a Safe owner, because with v+4 its signature IS an owner confirmation of
    /// a safeTxHash equal to those bytes. Checked at admission, again when the review opens and again
    /// at Confirm: Kao can learn the account owns a Safe while the request waits.
    pub fn personal(&self, shape: &MessageShape) -> Result<(), Refusal> {
        self.messages()?;
        if self.safe_owner()
            && matches!(
                shape,
                MessageShape::Binary {
                    reason: BinaryReason::OpaqueHash32,
                    ..
                }
            )
        {
            return Err(Refusal::unsupported(
                "Kao won't sign an opaque 32-byte hash with a Safe owner key.",
                "this account owns a Safe, and signing an opaque 32-byte hash with it could \
                 confirm a Safe transaction",
            ));
        }
        Ok(())
    }
}

// ───────────────────────────── dapp label ─────────────────────────────

/// Dapp-claimed metadata, sanitized ONCE at ingress. Deliberately has no icon / redirect / verify_url
/// fields: nothing is ever fetched or opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DappLabel {
    /// `sanitize_display(.., MAX_DAPP_NAME_CHARS)`; "Unnamed dapp" if empty.
    pub name: String,
    /// `url::Url` host (IDN → punycode by the url crate, lowercased), http(s) only.
    pub host: Option<String>,
    /// Sanitized + clamped, display only, never opened.
    pub url: String,
    pub description: String,
    pub insecure_scheme: bool,
}

impl DappLabel {
    pub fn from_metadata(m: &Metadata) -> Self {
        use crate::sanitize::sanitize_display;
        use crate::walletconnect::{
            MAX_DAPP_DESCRIPTION_CHARS, MAX_DAPP_HOST_CHARS, MAX_DAPP_NAME_CHARS,
            MAX_DAPP_URL_CHARS,
        };
        let name = sanitize_display(m.name.trim(), MAX_DAPP_NAME_CHARS).into_owned();
        let parsed = url::Url::parse(m.url.trim())
            .ok()
            .filter(|u| matches!(u.scheme(), "https" | "http"));
        let host = parsed
            .as_ref()
            .and_then(|u| u.host_str())
            .map(|h| sanitize_display(&h.to_ascii_lowercase(), MAX_DAPP_HOST_CHARS).into_owned());
        Self {
            name: if name.is_empty() {
                "Unnamed dapp".to_string()
            } else {
                name
            },
            host,
            url: sanitize_display(m.url.trim(), MAX_DAPP_URL_CHARS).into_owned(),
            description: sanitize_display(m.description.trim(), MAX_DAPP_DESCRIPTION_CHARS)
                .into_owned(),
            insecure_scheme: parsed.as_ref().is_some_and(|u| u.scheme() == "http"),
        }
    }
    /// Primary label: the host, never the self-declared name.
    pub fn headline(&self) -> &str {
        self.host.as_deref().unwrap_or("unknown site")
    }
}

// ───────────────────────────── validated calls ─────────────────────────────

/// Wei per gas in gwei, trimmed to three significant fractional digits, so a sub-gwei fee (usual
/// on L2s) keeps its digits instead of reading "0 gwei". Every fee Kao shows in gwei uses this.
pub fn format_gwei(wei: u128) -> String {
    let Ok(s) = alloy::primitives::utils::format_units(U256::from(wei), 9) else {
        return wei.to_string();
    };
    let Some((int_part, frac)) = s.split_once('.') else {
        return s;
    };
    let leading = frac.bytes().take_while(|b| *b == b'0').count();
    let kept: String = frac.chars().take(leading + 3).collect();
    let kept = kept.trim_end_matches('0');
    if kept.is_empty() {
        int_part.to_string()
    } else {
        format!("{int_part}.{kept}")
    }
}

/// Dapp tx fields Kao records but never uses — shown as review notes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IgnoredTxFields {
    pub nonce: Option<u64>,
    pub gas_price: Option<u128>,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub tx_type: Option<u8>,
    /// Safe identity: the dapp's `gas` (Safe relay fields are always 0).
    pub safe_gas: Option<u64>,
}

impl IgnoredTxFields {
    /// Human notes, e.g. ["nonce 7", "max fee 31.5 gwei"].
    pub fn describe(&self) -> Vec<String> {
        let gwei = format_gwei;
        let mut v = Vec::new();
        if let Some(n) = self.nonce {
            v.push(format!("nonce {n}"));
        }
        if let Some(p) = self.gas_price {
            v.push(format!("gas price {} gwei", gwei(p)));
        }
        if let Some(p) = self.max_fee_per_gas {
            v.push(format!("max fee {} gwei", gwei(p)));
        }
        if let Some(p) = self.max_priority_fee_per_gas {
            v.push(format!("priority fee {} gwei", gwei(p)));
        }
        if let Some(t) = self.tx_type {
            v.push(format!("transaction type {t}"));
        }
        if let Some(g) = self.safe_gas {
            v.push(format!("gas limit {g}"));
        }
        v
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIntent {
    pub from: Address,
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
    pub chain_id: u64,
    pub dapp_gas: Option<u64>,
    pub ignored: IgnoredTxFields,
}

/// How the pinned gas limit was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GasNote {
    Estimated,
    Buffered {
        estimate: u64,
    },
    DappHonoured {
        estimate: u64,
        dapp: u64,
    },
    DappCapped {
        estimate: u64,
        dapp: u64,
    },
    /// Headroom or the dapp's limit would have crossed the per-transaction gas cap
    /// (`request::MAX_TX_GAS`), which nodes refuse at the txpool; held at the cap instead.
    NetworkCapped {
        estimate: u64,
        dapp: Option<u64>,
    },
    /// Kao's node couldn't estimate the call (it expects a revert); the dapp's own limit is
    /// used as sent.
    DappUnestimated {
        dapp: u64,
    },
    /// Reopened after a broadcast whose acknowledgement never came: the limit already signed into
    /// the transaction.
    AsSigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryReason {
    NotUtf8,
    HiddenCharacters,
    TooLong,
    /// Exactly 32 bytes, not printable text — could be a hash of anything.
    OpaqueHash32,
}

/// personal_sign display: text only when every char displays exactly as signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageShape {
    Text {
        lines: Vec<String>,
    },
    Binary {
        len: usize,
        hex: String,
        reason: BinaryReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Siwe {
    pub domain: String,
    pub address: Option<Address>,
    pub uri: Option<String>,
    pub chain_id: Option<u64>,
    pub nonce: Option<String>,
    pub issued_at: Option<String>,
    pub expiration: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiweCheck {
    pub siwe: Siwe,
    pub domain_mismatch: bool,
    pub address_mismatch: bool,
    pub chain_mismatch: bool,
}

#[derive(Debug, Clone)]
pub struct PersonalSign {
    pub from: Address,
    /// Exact signed bytes.
    pub message: Bytes,
    pub shape: MessageShape,
    pub siwe: Option<SiweCheck>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DomainSummary {
    pub name: Option<String>,
    pub version: Option<String>,
    pub chain_id: Option<u64>,
    pub verifying_contract: Option<Address>,
    pub salt: Option<B256>,
    /// `name` / `version` in full (escaped) when the summary shortened them — signed like every
    /// other field, so reviewable in full behind "Show exact values".
    pub exact_name: Option<String>,
    pub exact_version: Option<String>,
}

impl DomainSummary {
    /// The summary shortened a domain string.
    pub fn shortened(&self) -> bool {
        self.exact_name.is_some() || self.exact_version.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedWarning {
    NoChainBinding,
    PermitOwnerNotSigner,
    LongValuesSummarized,
}

/// When a granted allowance (or, for Permit2 SignatureTransfer, the one-shot permit) stops working.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowanceExpiry {
    /// Valid until spent or revoked.
    Never,
    /// Unix seconds.
    At(u64),
    /// Permit2 AllowanceTransfer `expiration == 0`: Permit2 stores `block.timestamp` in its place,
    /// so the allowance is live in exactly the block the permit lands in — all a drainer needs to
    /// `permit` and `transferFrom` in one transaction. Not "expired in 1970".
    SubmittingBlock,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowanceGrant {
    /// "EIP-2612 Permit" | "Permit2 PermitSingle" | "Permit2 PermitBatch" | "Permit2 PermitTransferFrom" | …
    pub kind: &'static str,
    pub spender: Address,
    pub tokens: Vec<(Address, U256)>,
    /// The earliest expiry across the granted tokens.
    pub expires: AllowanceExpiry,
    /// Until when the signature itself can be submitted (EIP-2612 `deadline`, Permit2
    /// AllowanceTransfer `sigDeadline`), where that differs from `expires`.
    pub signature_deadline: Option<u64>,
    pub unlimited: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypedKind {
    Generic,
    Allowance(AllowanceGrant),
    /// Primary encodeType == SafeTx (1.3+ or legacy `dataGas`): signing this IS an owner confirmation.
    /// Every field of the signed struct but the domain, so the review can decode the call the Safe
    /// would make (`data`) and flag a refund (`gas_price` / `gas_token` / `refund_receiver`).
    SafeTx {
        safe: Option<Address>,
        to: Address,
        value: U256,
        data: Bytes,
        operation: u8,
        safe_tx_gas: U256,
        /// `baseGas` (1.3+) or the legacy `dataGas`.
        base_gas: U256,
        gas_price: U256,
        gas_token: Address,
        refund_receiver: Address,
        nonce: U256,
    },
    /// Primary encodeType == SafeMessage(bytes message).
    SafeMessage {
        safe: Option<Address>,
    },
}

/// The full value behind a typed-data row the review model shortened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactValue {
    /// A `bytes` value over 32 bytes, exactly as hashed.
    Bytes(Bytes),
    /// A string over the row's length limit, escaped as the row is (`escape_unsafe_display`).
    Text(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct CheckedTyped {
    pub primary_type: String,
    /// `from_parts(domain.separator(), hash_struct())`, asserted == `eip712_signing_hash()`.
    pub digests: Eip712Digests,
    pub domain: DomainSummary,
    /// Dotted-path rows walked from `td.coerce()`; strings via `escape_unsafe_display`.
    pub model: TypedDataModel,
    /// `(row index, full value)` for every row of `model` shown shortened, ascending by index — so
    /// everything signed stays reviewable in full ("Show exact values").
    pub exact: Vec<(usize, ExactValue)>,
    pub kind: TypedKind,
    pub warnings: Vec<TypedWarning>,
}

#[derive(Debug, Clone)]
pub struct TypedRequest {
    pub from: Address,
    /// The ONLY object that is hashed and signed.
    pub typed: Arc<alloy::dyn_abi::TypedData>,
    pub checked: CheckedTyped,
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // one per queued request; not stored in bulk
pub enum WcCall {
    PersonalSign(PersonalSign),
    SignTypedData(TypedRequest),
    SendTransaction(TxIntent),
    SwitchChain { chain_id: u64 },
    Accounts,
    ChainId,
}

impl WcCall {
    pub fn needs_review(&self) -> bool {
        matches!(
            self,
            Self::PersonalSign(_) | Self::SignTypedData(_) | Self::SendTransaction(_)
        )
    }
    pub fn label(&self) -> &'static str {
        match self {
            Self::PersonalSign(_) => "Sign message",
            Self::SignTypedData(_) => "Sign typed data",
            Self::SendTransaction(_) => "Send transaction",
            Self::SwitchChain { .. } => "Switch network",
            Self::Accounts => "Read accounts",
            Self::ChainId => "Read network",
        }
    }
}

/// `request::validate`'s success value.
#[derive(Debug, Clone)]
pub struct Admitted {
    pub chain_id: u64,
    pub call: WcCall,
    /// Sanitized one-liner for queue rows / toasts (`request::summarize_call`).
    pub summary: String,
}

/// Locally parsed pairing URI — deliberately WITHOUT the symKey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPairing {
    pub topic: Topic,
    pub expiry: Option<u64>,
}

// ───────────────────────────── proposals ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodSupport {
    Served,
    /// Served, but this identity refuses it per request (Trezor typed, Safe messages short).
    CapabilityRefused,
    /// In REFUSED_METHODS — granted only when required, refused per request (4200).
    Refused,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainLine {
    pub chain_id: u64,
    /// `chain_label`, or sanitized "eip155:N (not available)".
    pub label: String,
    pub required: bool,
    pub granted: bool,
    pub unverified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodLine {
    /// Sanitized.
    pub name: String,
    pub required: bool,
    pub support: MethodSupport,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Grant {
    pub namespaces: SessionNamespaces,
    pub chains: Vec<u64>,
    pub methods: Vec<String>,
    pub events: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalBlock {
    /// 5100 / 5101 / 5102 / 5103 / 5104 — never the crate's 9.
    pub code: i64,
    pub message: &'static str,
    /// User-facing detail ("requires Arbitrum — add it under Settings › Networks").
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProposalPlan {
    pub identity: WcIdentity,
    pub identity_label: String,
    pub chains: Vec<ChainLine>,
    pub methods: Vec<MethodLine>,
    /// "Your Ledger shows only hashes for typed data", "Message signatures need 2 owner keys; Kao holds 1", …
    pub caveats: Vec<String>,
    pub verdict: Result<Grant, ProposalBlock>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApproveTicket {
    pub proposal_id: u64,
    pub pairing_topic: Topic,
    pub proposer_key: PublicKey,
    pub grant: Grant,
    pub identity: WcIdentity,
    pub identity_label: String,
    pub dapp: DappLabel,
}

impl ApproveTicket {
    /// The proposal the user saw is still the one in the client: the crate keys proposals by id
    /// alone, so a colliding id from another pairing would replace it silently.
    pub fn matches(&self, p: &Proposal) -> bool {
        p.id == self.proposal_id
            && p.pairing_topic == self.pairing_topic
            && p.proposer.public_key == self.proposer_key
    }
}

// ───────────────────────────── book state ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckState {
    Pending,
    Confirmed,
    Unconfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckFailure {
    Refused,
    Timeout,
    Closed,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BoundSession {
    pub topic: Topic,
    pub pairing_topic: Topic,
    /// Local "Session N" — stable, never dapp-controlled.
    pub ordinal: u32,
    pub identity: WcIdentity,
    pub identity_label: String,
    pub chains: Vec<u64>,
    pub methods: Vec<String>,
    pub events: Vec<String>,
    pub dapp: DappLabel,
    pub expiry: u64,
    pub ack: AckState,
    pub paused: bool,
    pub reject_streak: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueState {
    Waiting,
    InReview { seq: u64 },
    Signing { seq: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Confirm stays live (device declined, RPC hiccup).
    Retryable,
    /// Pin / nonce / owner set moved — re-quote (EOA tx) or Cancel.
    Stale,
    /// The dapp stopped waiting — nothing to answer.
    Gone,
    /// A Safe owner's device showed the EIP-712 prompt for the Safe hash and
    /// refused it, and nothing else was asked of it. Confirm comes back offering
    /// the same hash as a personal message (`eth_sign`) — the user's call.
    Eip712Refused,
    /// A Safe transaction's execute-time dry run reverts: executing is
    /// withdrawn (the execute path refuses it every time), proposing stays.
    ExecuteRefused,
    /// A signed transaction was handed to the node and no acknowledgement came back
    /// ([`QueuedRequest::unconfirmed`]): it may be on its way. The request is never signed again;
    /// only those exact bytes may be sent again.
    Unconfirmed,
}

/// A dapp transaction Kao signed and handed to the node without getting its hash back. The reply
/// may have been lost after the node accepted it, so the transaction may be on its way: its
/// request must never be signed again (that would be a second, distinct transaction), and only
/// these exact bytes may be sent again — which is idempotent.
#[derive(Clone, PartialEq, Eq)]
pub struct UnconfirmedTx {
    /// keccak256 of `raw`.
    pub hash: B256,
    /// The exact signed envelope (EIP-2718).
    pub raw: Bytes,
    pub nonce: u64,
}

/// Shape only: the signed bytes are not secret, but they are long.
impl fmt::Debug for UnconfirmedTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnconfirmedTx")
            .field("hash", &self.hash)
            .field("nonce", &self.nonce)
            .field("raw_len", &self.raw.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoneReason {
    Expired,
    DappDisconnected,
    SessionExpired,
    UserDisconnected,
    IdentityRemoved,
    Teardown,
}

impl GoneReason {
    pub fn sentence(self) -> &'static str {
        match self {
            Self::Expired => "The dapp's request expired — nothing was sent.",
            Self::DappDisconnected => "The dapp disconnected — nothing was sent.",
            Self::SessionExpired => "The session expired — nothing was sent.",
            Self::UserDisconnected => "You disconnected this dapp — nothing was sent.",
            Self::IdentityRemoved => "The account this dapp used was removed — nothing was sent.",
            Self::Teardown => "Kao turned WalletConnect off — nothing was sent.",
        }
    }
}

#[derive(Debug, Clone)]
pub struct QueuedRequest {
    pub key: WcKey,
    pub chain_id: u64,
    pub call: WcCall,
    pub summary: String,
    pub identity: WcIdentity,
    pub received_at: u64,
    /// The dapp's own expiryTimestamp, uncapped: past it the dapp stopped waiting (no answer
    /// reaches it). Kao's TTL is `kao_deadline`, which never applies once Signing (a slow hardware or Safe ceremony is never cut short).
    pub dapp_deadline: Option<u64>,
    pub kao_deadline: u64,
    pub state: QueueState,
    pub notified: bool,
    pub failure: Option<FailureClass>,
    /// Set only on Signing entries whose session/request died; `is_live` is false from then on.
    pub gone: Option<GoneReason>,
    /// A transaction signed for this request left the wallet unacknowledged. Never cleared: the
    /// request is never signed again, whatever happens to its review.
    pub unconfirmed: Option<UnconfirmedTx>,
    /// The user asked to review this Safe transaction while Kao's unmined execution of an earlier
    /// one held its Safe ([`super::book::WcBook::review_past_hold`]): it no longer waits for it.
    pub past_hold: bool,
}

#[derive(Debug, Clone)]
pub struct ProposalCard {
    /// Raw — never rendered; read only by `plan_proposal` and the approve task.
    pub proposal: Proposal,
    pub dapp: DappLabel,
    pub busy: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayStatus {
    Connecting,
    Connected,
    Reconnecting { since: u64 },
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingState {
    Idle,
    Pairing {
        topic: Topic,
        since: u64,
    },
    Waiting {
        topic: Topic,
        since: u64,
        until: u64,
    },
    Failed(String),
}

/// What the book should send for a request. `Result` is accepted only in `Signing`;
/// `Refuse` from Waiting/InReview/Signing; `Abandon` removes without answering (Gone).
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    Result(serde_json::Value),
    Refuse(Refusal),
    Abandon,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespondResult {
    Delivered,
    /// Not sent, but the crate still holds the request / session (dropped socket, timeout, relay
    /// error): keep in the outbox, re-send (quickly, then with a backoff, and on RelayConnected).
    Retry(String),
    /// The crate no longer holds the request / session, or the client shut down (Closed): drop,
    /// with a notice when the dropped answer was a result (the dapp never got what it asked for).
    Gone(String),
}

/// Executed by the runtime (spawned on its tokio handle) — never by iced.
#[derive(Debug, Clone, PartialEq)]
pub enum NetEffect {
    Respond {
        key: WcKey,
        answer: Result<serde_json::Value, ErrorObject>,
    },
    RejectProposal {
        id: u64,
        error: ErrorObject,
    },
    Disconnect {
        topic: Topic,
    },
    DeletePairing {
        topic: Topic,
    },
    Emit {
        topic: Topic,
        chain_id: u64,
        name: &'static str,
        data: serde_json::Value,
    },
    /// Idle grace passed / flapping with nothing at stake: take from the slot and tear down.
    Retire {
        reason: String,
    },
}

/// Handled by the dashboard (returned from sync runtime ops, or delivered as `WcStreamItem::Ui`).
#[derive(Debug, Clone, PartialEq)]
pub enum UiEffect {
    RequestGone {
        key: WcKey,
        reason: GoneReason,
    },
    /// A toast. The book has already recorded the line in its activity ring (with its error
    /// flag), so the dashboard only shows it and never records it again.
    Notice {
        text: String,
    },
    Attention,
}

impl UiEffect {
    pub fn name(&self) -> &'static str {
        match self {
            Self::RequestGone { .. } => "RequestGone",
            Self::Notice { .. } => "Notice",
            Self::Attention => "Attention",
        }
    }
}

#[derive(Debug, Default)]
pub struct Effects {
    pub net: Vec<NetEffect>,
    pub ui: Vec<UiEffect>,
    /// Something render-visible changed (the stream emits `Changed`).
    pub changed: bool,
    /// History to record in the vault (through the runtime's epoch-checked `VaultSession`).
    pub log: Vec<LogEffect>,
    /// Whether (and how soon) the runtime should save its state to the vault.
    pub persist: Persist,
}

impl Effects {
    pub fn merge(&mut self, other: Effects) {
        self.net.extend(other.net);
        self.ui.extend(other.ui);
        self.changed |= other.changed;
        self.log.extend(other.log);
        self.persist = self.persist.max(other.persist);
    }
}

/// When the runtime saves its WalletConnect state. Ordered, so merging two is `max`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Persist {
    #[default]
    None,
    /// Dirty: housekeeping saves it within a couple of seconds.
    Soon,
    /// Save now (coalesced, off the UI thread): something a restore must not lose.
    Now,
}

/// One history event for the vault.
#[derive(Clone, PartialEq)]
pub enum LogEffect {
    ConnectionOpened(crate::vault::NewConnection),
    ConnectionAcked {
        topic: String,
        ack: crate::vault::AckRecord,
    },
    ConnectionEnded {
        topic: String,
        at: u64,
        reason: crate::vault::EndReason,
    },
    MessageSigned(crate::vault::NewSigned),
    MessageDelivery {
        topic: String,
        request_id: u64,
        delivery: crate::vault::Delivery,
        /// The raw signature, for a `Delivered` one (the vault keeps it from then on).
        signature: Option<Bytes>,
    },
}

impl LogEffect {
    fn topic(&self) -> &str {
        match self {
            Self::ConnectionOpened(c) => &c.topic,
            Self::MessageSigned(s) => match &s.origin {
                crate::vault::SignOrigin::WalletConnect { topic, .. } => topic,
                // Never a WalletConnect log: Kao's own CoW signatures are recorded by their task.
                crate::vault::SignOrigin::CowOrder { .. }
                | crate::vault::SignOrigin::CowCancel { .. } => "",
            },
            Self::ConnectionAcked { topic, .. }
            | Self::ConnectionEnded { topic, .. }
            | Self::MessageDelivery { topic, .. } => topic,
        }
    }
}

/// Variant + the topic's first 8 chars only — never a payload, signature or dapp string.
impl fmt::Debug for LogEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::ConnectionOpened(_) => "ConnectionOpened",
            Self::ConnectionAcked { .. } => "ConnectionAcked",
            Self::ConnectionEnded { .. } => "ConnectionEnded",
            Self::MessageSigned(_) => "MessageSigned",
            Self::MessageDelivery { .. } => "MessageDelivery",
        };
        let topic: String = self.topic().chars().take(8).collect();
        write!(f, "{name}({topic}…)")
    }
}

// ───────────────────────────── restore (slot → dashboard) ─────────────────────────────

/// What the WalletConnect pane shows while saved sessions are being restored (`WcSlot::restore_view`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreView {
    /// Saved dapps being restored whose session is still alive.
    pub sessions: usize,
    /// Disconnects the restore still owes whose session is still alive: sessions the dapps hold
    /// that no binding covers (a disconnect that hadn't reached the dapp). `sessions == 0` with
    /// some of these is a restore left only a disconnect to deliver; both 0, everything it held
    /// expired while it waited (the slot then ends it — see `WcSlot::restore_watch`).
    pub pending_disconnects: usize,
    pub phase: RestorePhase,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestorePhase {
    Connecting,
    /// A retryable failure; the next attempt is at `at` (unix seconds). `error` is Kao's own copy.
    RetryingAt {
        at: u64,
        error: String,
    },
    /// Waits for the user: Retry / Reconnect anyway (`direct_override`: the route got less private
    /// than the one the sessions were saved under) / Forget.
    NeedsYou {
        error: String,
        direct_override: bool,
    },
}

/// How a restore future ended (`WcMsg::Restored` — a UI nudge; the slot holds the real state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// Installed: `generation` is the restored runtime's.
    Restored { sessions: usize, generation: u64 },
    /// Nothing to restore (no saved state, or none of it still alive).
    Nothing,
    /// Waiting on the user (`RestorePhase::NeedsYou`).
    Waiting,
    /// The slot closed, or the user forgot the saved sessions, while it ran.
    Stopped,
}

// ───────────────────────────── snapshot (render-only) ─────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct WcSnapshot {
    pub generation: u64,
    pub relay: RelayStatus,
    pub route: RouteKind,
    pub pairing: PairingState,
    pub proposal: Option<ProposalView>,
    pub sessions: Vec<SessionView>,
    pub queue: Vec<RequestView>,
    pub notices: Vec<NoticeView>,
    pub refused_count: u32,
    pub undelivered: usize,
    /// The relay the live runtime uses (its origin, as its saved state keeps it): compare with the
    /// configured one through [`super::runtime::same_relay`] — a restore against another relay
    /// forgets these sessions.
    pub relay_url: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProposalView {
    pub id: u64,
    pub dapp: DappLabel,
    pub secs_left: u64,
    pub busy: bool,
    pub error: Option<String>,
    /// Filled by the coordinator for the ACTIVE identity (`None` = no exposable active identity).
    pub plan: Option<ProposalPlan>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionView {
    pub topic: Topic,
    pub ordinal: u32,
    pub dapp: DappLabel,
    pub identity: WcIdentity,
    pub identity_label: String,
    pub chains: Vec<u64>,
    pub pending: usize,
    pub ack: AckState,
    pub paused: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RequestView {
    pub key: WcKey,
    pub ordinal: u32,
    pub dapp_host: String,
    pub label: &'static str,
    pub summary: String,
    pub identity: WcIdentity,
    pub identity_label: String,
    pub chain_id: u64,
    pub state: QueueState,
    pub age_secs: u64,
    pub secs_left: Option<u64>,
    pub paused: bool,
    pub undelivered: bool,
    /// A Safe transaction waiting for Kao's unmined execution of an earlier one on its Safe
    /// ([`super::book::WcBook::held_behind_execution`]).
    pub held: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoticeView {
    pub at: u64,
    pub text: String,
    pub error: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProjectIdSource {
    Override,
    BuiltIn,
    #[default]
    Missing,
}

/// Kao's proxy setting is on, but the relay can only use it from the next launch.
pub const RESTART_FOR_PROXY: &str = "Restart Kao to route WalletConnect through your proxy.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyView {
    /// The relay goes through a proxy: Kao's own, installed this launch, or one the environment
    /// Kao was launched from exported.
    Proxied,
    /// Kao's proxy setting is on but not installed yet (it applies on restart).
    RestartPending,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WcConfigView {
    pub project_source: ProjectIdSource,
    pub relay_custom: Option<String>,
    pub default_relay: &'static str,
    pub proxy: ProxyView,
}

// ───────────────────────────── transport & runtime ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Direct,
    /// Proxy authority as installed: "127.0.0.1:9050", "[::1]:9050", "host:1080".
    Socks5h {
        proxy: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    Proxied,
    Direct,
    Loopback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteError {
    NoHost,
    WsNotLoopback,
    ProxyUnparseable,
    ProxyScheme,
    RestartPending,
    /// The proxy came from the user's environment (Kao's own setting is off) and can't carry the
    /// relay. `var` is the variable's name — never its value, which may embed credentials.
    ExportedProxyUnusable {
        var: &'static str,
    },
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fixed = match self {
            Self::NoHost => "The WalletConnect relay URL has no host.",
            Self::WsNotLoopback => "Plain ws:// is only allowed for a relay on this computer.",
            Self::ProxyUnparseable | Self::ProxyScheme => {
                "Kao's proxy setting can't be used for WalletConnect — check Settings › Network."
            }
            Self::RestartPending => RESTART_FOR_PROXY,
            Self::ExportedProxyUnusable { var } => {
                return write!(
                    f,
                    "Your environment exports {var}, a proxy WalletConnect can't tunnel through \
                     (only socks5h://host:port works) — export a socks5h:// proxy or unset {var}, \
                     then restart Kao."
                );
            }
        };
        f.write_str(fixed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    NeedsProjectId,
    BadRelayUrl,
    Route(RouteError),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NeedsProjectId => {
                f.write_str("WalletConnect needs a project ID — add one in WalletConnect settings.")
            }
            Self::BadRelayUrl => f.write_str("The WalletConnect relay URL in settings is invalid."),
            Self::Route(e) => fmt::Display::fmt(e, f),
        }
    }
}

/// What the runtime's event stream yields. Debug is shape-only BY TYPE (both App and dashboard trace
/// whole messages): never params, metadata or message bodies.
#[derive(Clone)]
pub enum WcStreamItem {
    /// A session request awaiting admission (needs the wallet's descriptors → dashboard).
    Request {
        req: PendingRequest,
        received_at: u64,
    },
    Ui(UiEffect),
    /// Book changed in the background — re-mirror the pane.
    Changed,
}

impl fmt::Debug for WcStreamItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request { req, received_at } => write!(
                f,
                "Request {{ id: {}, method: {}, chain: {}, at: {received_at} }}",
                req.id,
                crate::sanitize::sanitize_display(&req.request.method, 48),
                crate::sanitize::sanitize_display(&req.chain_id, 32),
            ),
            Self::Ui(e) => write!(f, "Ui({})", e.name()),
            Self::Changed => f.write_str("Changed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use std::collections::BTreeMap;
    use wallet_connect::sign::{Participant, Relay, SessionRequest};

    const ADDR: Address = address!("ab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb");

    fn safe_caps(threshold: u32, local_signers: u32) -> SafeCaps {
        super::super::testkit::safe_kind_caps(Chain::Mainnet, threshold, 3, local_signers)
    }

    fn caps(kind: IdentityKind) -> IdentityCaps {
        let identity = match &kind {
            IdentityKind::Eoa(_) => WcIdentity::Eoa { address: ADDR },
            IdentityKind::Safe(s) => WcIdentity::Safe {
                address: ADDR,
                chain_id: s.chain.chain_id(),
            },
        };
        IdentityCaps {
            identity,
            label: "Account 1".into(),
            kind,
            chains: vec![1],
        }
    }

    fn eoa(kind: EoaKind, safe_owner: bool) -> IdentityCaps {
        caps(IdentityKind::Eoa(EoaCaps { kind, safe_owner }))
    }

    fn metadata(name: &str, url: &str) -> Metadata {
        Metadata::new(name, "", url)
    }

    fn proposal(key: PublicKey) -> Proposal {
        Proposal {
            id: 42,
            pairing_topic: Topic::new("aa".repeat(32)),
            expiry_timestamp: 1_000,
            relays: vec![Relay::default()],
            proposer: Participant {
                public_key: key,
                metadata: metadata("dapp", "https://dapp.example"),
            },
            required_namespaces: BTreeMap::new(),
            optional_namespaces: BTreeMap::new(),
            session_properties: None,
            scoped_properties: None,
        }
    }

    #[test]
    fn caip10_is_eip55() {
        let lower = address!("ab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb");
        let id = WcIdentity::Eoa { address: lower };
        assert_eq!(
            id.caip10(1),
            "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"
        );
        // EIP-55, not EIP-1191: the chain id never changes the casing.
        let safe = WcIdentity::Safe {
            address: lower,
            chain_id: 30,
        };
        assert_eq!(
            safe.caip10(30),
            "eip155:30:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"
        );
        assert!(safe.is_safe() && !id.is_safe());
        assert_eq!(safe.address(), id.address());
        // A sibling Safe (same address, other chain) is a different identity.
        assert_ne!(
            safe,
            WcIdentity::Safe {
                address: lower,
                chain_id: 1
            }
        );
    }

    #[test]
    fn gwei_keeps_sub_gwei_digits() {
        assert_eq!(format_gwei(12_400_000_000), "12.4");
        assert_eq!(format_gwei(1_000_000_000), "1");
        assert_eq!(format_gwei(1_234_567), "0.00123");
        assert_eq!(format_gwei(0), "0");
    }

    #[test]
    fn ignored_fields_describe() {
        assert!(IgnoredTxFields::default().describe().is_empty());
        let f = IgnoredTxFields {
            nonce: Some(7),
            gas_price: Some(20_000_000_000),
            max_fee_per_gas: Some(31_500_000_000),
            max_priority_fee_per_gas: Some(1_234_567_890),
            tx_type: Some(2),
            safe_gas: Some(100_000),
        };
        assert_eq!(
            f.describe(),
            vec![
                "nonce 7",
                "gas price 20 gwei",
                "max fee 31.5 gwei",
                "priority fee 1.234 gwei",
                "transaction type 2",
                "gas limit 100000",
            ]
        );
        let only_nonce = IgnoredTxFields {
            nonce: Some(0),
            ..Default::default()
        };
        assert_eq!(only_nonce.describe(), vec!["nonce 0"]);
        // Sub-gwei fees, usual on L2s, keep their digits instead of reading "0 gwei".
        let l2 = IgnoredTxFields {
            max_fee_per_gas: Some(1_500_000),
            max_priority_fee_per_gas: Some(1_000_000),
            ..Default::default()
        };
        assert_eq!(
            l2.describe(),
            vec!["max fee 0.0015 gwei", "priority fee 0.001 gwei"]
        );
    }

    #[test]
    fn gone_reason_sentences_static() {
        let all = [
            GoneReason::Expired,
            GoneReason::DappDisconnected,
            GoneReason::SessionExpired,
            GoneReason::UserDisconnected,
            GoneReason::IdentityRemoved,
            GoneReason::Teardown,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for r in all {
            let s: &'static str = r.sentence();
            assert!(s.ends_with("nothing was sent."), "{r:?}: {s}");
            assert!(seen.insert(s), "{r:?} repeats another reason's sentence");
        }
    }

    /// EOA kinds × Safe capability gaps, against all three capability checks.
    #[test]
    fn identity_caps_matrix() {
        for (kind, typed_ok, hash_mode, hardware) in [
            (EoaKind::Local, true, false, false),
            (EoaKind::Ledger, true, true, true),
            (EoaKind::Trezor, false, false, true),
        ] {
            let c = eoa(kind, false);
            assert!(c.messages().is_ok(), "{kind:?}");
            assert_eq!(c.typed_data().is_ok(), typed_ok, "{kind:?}");
            assert!(c.transactions().is_ok(), "{kind:?}");
            assert_eq!(c.typed_hash_mode(), hash_mode, "{kind:?}");
            assert_eq!(c.hardware(), hardware, "{kind:?}");
            assert!(!c.safe_owner());
            assert!(eoa(kind, true).safe_owner());
        }

        // Safe, threshold 2: messages need 2 local owners; txs need 1.
        let full = caps(IdentityKind::Safe(safe_caps(2, 2)));
        assert!(full.messages().is_ok() && full.typed_data().is_ok());
        assert!(full.transactions().is_ok());
        assert!(!full.typed_hash_mode() && !full.hardware() && !full.safe_owner());

        let short = caps(IdentityKind::Safe(safe_caps(2, 1)));
        assert!(short.messages().is_err() && short.typed_data().is_err());
        assert!(
            short.transactions().is_ok(),
            "propose-only still serves txs"
        );

        let none = caps(IdentityKind::Safe(safe_caps(1, 0)));
        let e = none.transactions().unwrap_err();
        assert_eq!(e.code, codes::UNSUPPORTED_METHOD);
        assert_eq!(e.message, "No owner key for this Safe in Kao.");

        let blocked = caps(IdentityKind::Safe(SafeCaps {
            signing_block: Some("Safe version 0.1.0 isn't supported".into()),
            ..safe_caps(1, 1)
        }));
        for r in [
            blocked.messages(),
            blocked.typed_data(),
            blocked.transactions(),
        ] {
            let e = r.unwrap_err();
            assert_eq!(e.message, "This Safe can't sign from Kao.");
            assert_eq!(e.detail, "Safe version 0.1.0 isn't supported");
        }

        assert!(full.serves_chain(1) && !full.serves_chain(8453));
    }

    #[test]
    fn safe_messages_refused_below_threshold() {
        let c = caps(IdentityKind::Safe(safe_caps(2, 1)));
        let e = c.messages().unwrap_err();
        assert_eq!(e.code, codes::UNSUPPORTED_METHOD);
        assert_eq!(e.message, "This Safe can't sign messages from Kao.");
        assert!(e.detail.contains("need 2 owner keys"), "{}", e.detail);
        assert!(e.detail.contains("Kao holds 1"), "{}", e.detail);
        assert_eq!(c.typed_data().unwrap_err(), e);
    }

    #[test]
    fn safe_messages_refused_without_fallback_handler() {
        let c = caps(IdentityKind::Safe(SafeCaps {
            fallback_handler: false,
            ..safe_caps(1, 1)
        }));
        let e = c.messages().unwrap_err();
        assert_eq!(e.code, codes::UNSUPPORTED_METHOD);
        assert_eq!(e.message, "This Safe can't sign messages.");
        assert!(c.typed_data().is_err());
        // Transactions don't go through EIP-1271, so they're unaffected.
        assert!(c.transactions().is_ok());
    }

    #[test]
    fn trezor_typed_data_refused() {
        let e = eoa(EoaKind::Trezor, false).typed_data().unwrap_err();
        assert_eq!(e.code, codes::UNSUPPORTED_METHOD);
        assert_eq!(e.message, "Trezor can't sign EIP-712 typed data.");
        // personal_sign still works on Trezor.
        assert!(eoa(EoaKind::Trezor, false).messages().is_ok());
    }

    /// The dapp only ever sees the static message — never `detail`.
    #[test]
    fn refusal_error_object_uses_static_message() {
        let r = Refusal::failed("rpc https://eth.example/v2/SECRETKEY timed out");
        let o = r.error_object();
        assert_eq!(o.code, codes::INTERNAL);
        assert_eq!(o.message, "The wallet could not complete the request.");
        assert!(o.data.is_none());
        let json = serde_json::to_string(&o).unwrap();
        assert!(!json.contains("SECRETKEY"), "{json}");

        for (r, code) in [
            (Refusal::user_rejected(), codes::USER_REJECTED),
            (Refusal::unauthorized("x"), codes::UNAUTHORIZED),
            (
                Refusal::unsupported("Nope.", "x"),
                codes::UNSUPPORTED_METHOD,
            ),
            (Refusal::invalid_params("Bad.", "x"), codes::INVALID_PARAMS),
            (Refusal::chain_not_served("x"), codes::CHAIN_DISCONNECTED),
            (Refusal::unrecognized_chain(), codes::UNRECOGNIZED_CHAIN),
            (Refusal::expired(), codes::INTERNAL),
            (Refusal::closing(), codes::DISCONNECTED),
            (Refusal::limit(), codes::LIMIT_EXCEEDED),
            (Refusal::duplicate(), codes::INVALID_REQUEST),
        ] {
            let o = r.error_object();
            assert_eq!(o.code, code);
            assert_eq!(o.message, r.message);
            assert_ne!(o.message, r.detail, "detail must never be the dapp text");
        }
        assert_eq!(codes::USER_REJECTED, 4001);
    }

    #[test]
    fn ticket_rejects_swapped_proposer() {
        let key = PublicKey::from_bytes([1; 32]);
        let p = proposal(key);
        let ticket = ApproveTicket {
            proposal_id: p.id,
            pairing_topic: p.pairing_topic.clone(),
            proposer_key: key,
            grant: Grant {
                namespaces: BTreeMap::new(),
                chains: vec![1],
                methods: vec![],
                events: vec![],
            },
            identity: WcIdentity::Eoa { address: ADDR },
            identity_label: "Account 1".into(),
            dapp: DappLabel::from_metadata(&p.proposer.metadata),
        };
        assert!(ticket.matches(&p));

        let swapped = proposal(PublicKey::from_bytes([2; 32]));
        assert!(!ticket.matches(&swapped), "same id + topic, other proposer");
        let other_id = Proposal {
            id: 43,
            ..p.clone()
        };
        assert!(!ticket.matches(&other_id));
        let other_topic = Proposal {
            pairing_topic: Topic::new("bb".repeat(32)),
            ..p
        };
        assert!(!ticket.matches(&other_topic));
    }

    #[test]
    fn dapp_label_strips_bidi_and_controls() {
        let m = Metadata {
            description: "Swap\n\u{200B}tokens\u{2028}now".into(),
            ..metadata(
                "Uni\u{202E}swap\u{0007}",
                "https://app.\u{200B}uniswap.org\u{202E}",
            )
        };
        let d = DappLabel::from_metadata(&m);
        assert_eq!(d.name, "Uniswap");
        assert_eq!(d.description, "Swaptokensnow");
        assert!(
            !d.url.chars().any(|c| matches!(c, '\u{200B}' | '\u{202E}')),
            "{:?}",
            d.url
        );
        assert!(!d.insecure_scheme);

        // A name that is nothing but invisible chars falls back.
        let blank = DappLabel::from_metadata(&metadata("\u{202E}\u{200B} ", "https://a.example"));
        assert_eq!(blank.name, "Unnamed dapp");

        // Clamped to the display caps.
        let long = DappLabel::from_metadata(&Metadata {
            description: "d".repeat(500),
            ..metadata(&"n".repeat(500), "https://a.example")
        });
        assert!(long.name.chars().count() <= crate::walletconnect::MAX_DAPP_NAME_CHARS + 1);
        assert!(
            long.description.chars().count()
                <= crate::walletconnect::MAX_DAPP_DESCRIPTION_CHARS + 1
        );
    }

    #[test]
    fn dapp_label_host_is_punycode() {
        let d = DappLabel::from_metadata(&metadata("Books", "https://BÜCHER.example/shop"));
        assert_eq!(d.host.as_deref(), Some("xn--bcher-kva.example"));
        assert_eq!(d.headline(), "xn--bcher-kva.example");

        let http = DappLabel::from_metadata(&metadata("Plain", "http://app.example"));
        assert_eq!(http.host.as_deref(), Some("app.example"));
        assert!(http.insecure_scheme);
    }

    #[test]
    fn dapp_label_rejects_non_http_url_host() {
        for url in [
            "javascript:alert(1)",
            "ftp://files.example",
            "file:///etc/passwd",
            "wc:abc@2",
            "not a url",
            "",
        ] {
            let d = DappLabel::from_metadata(&metadata("x", url));
            assert_eq!(d.host, None, "{url:?}");
            assert_eq!(d.headline(), "unknown site");
            assert!(!d.insecure_scheme, "{url:?}");
        }
        // The self-declared name never becomes the headline.
        let d = DappLabel::from_metadata(&metadata("app.uniswap.org", "https://evil.example"));
        assert_eq!(d.headline(), "evil.example");
    }

    /// Both App and the dashboard trace whole messages, so a stream item's
    /// Debug must carry the shape only — never params or the message body.
    #[test]
    fn wc_stream_item_debug_is_shape_only() {
        let req = PendingRequest {
            id: 7,
            topic: Topic::new("cc".repeat(32)),
            chain_id: "eip155:1".into(),
            request: SessionRequest::new(
                "personal_sign\u{202E}",
                serde_json::json!(["0x5345435245545f424f4459", "SECRET-PARAM"]),
            ),
        };
        let item = WcStreamItem::Request {
            req,
            received_at: 99,
        };
        let s = format!("{item:?}");
        assert_eq!(
            s,
            "Request { id: 7, method: personal_sign, chain: eip155:1, at: 99 }"
        );
        assert!(!s.contains("SECRET") && !s.contains("cccc") && !s.contains("0x5345"));

        let gone = WcStreamItem::Ui(UiEffect::Notice {
            text: "secret notice text".into(),
        });
        assert_eq!(format!("{gone:?}"), "Ui(Notice)");
        assert_eq!(format!("{:?}", WcStreamItem::Changed), "Changed");
    }

    #[test]
    fn effects_merge_unions() {
        let mut a = Effects {
            net: vec![NetEffect::Retire {
                reason: "idle".into(),
            }],
            ui: vec![],
            changed: false,
            persist: Persist::Now,
            ..Default::default()
        };
        a.merge(Effects {
            net: vec![],
            ui: vec![UiEffect::Attention],
            changed: true,
            log: vec![LogEffect::ConnectionAcked {
                topic: "0123456789abcdef".into(),
                ack: crate::vault::AckRecord::Confirmed,
            }],
            persist: Persist::Soon,
        });
        assert_eq!(a.net.len(), 1);
        assert_eq!(a.ui, vec![UiEffect::Attention]);
        assert!(a.changed);
        assert_eq!(a.log.len(), 1);
        assert_eq!(
            a.persist,
            Persist::Now,
            "merge keeps the more urgent persist"
        );
        assert_eq!(format!("{:?}", a.log[0]), "ConnectionAcked(01234567…)");
    }

    #[test]
    fn wc_call_review_and_labels() {
        assert!(!WcCall::Accounts.needs_review());
        assert!(!WcCall::ChainId.needs_review());
        assert!(!WcCall::SwitchChain { chain_id: 1 }.needs_review());
        assert_eq!(
            WcCall::SwitchChain { chain_id: 1 }.label(),
            "Switch network"
        );
        let tx = WcCall::SendTransaction(TxIntent {
            from: ADDR,
            to: ADDR,
            value: U256::ZERO,
            data: Bytes::new(),
            chain_id: 1,
            dapp_gas: None,
            ignored: IgnoredTxFields::default(),
        });
        assert!(tx.needs_review());
        assert_eq!(tx.label(), "Send transaction");
    }

    #[test]
    fn start_and_route_errors_are_fixed_copy() {
        assert_eq!(
            StartError::Route(RouteError::RestartPending).to_string(),
            RouteError::RestartPending.to_string()
        );
        assert_eq!(
            RouteError::ProxyScheme.to_string(),
            RouteError::ProxyUnparseable.to_string()
        );
        assert!(
            StartError::NeedsProjectId
                .to_string()
                .contains("project ID")
        );
    }
}
