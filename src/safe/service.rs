//! Integration with the **Safe Transaction Service** (`api.safe.global`)
//! — the off-chain aggregator that holds a Safe's proposed multisig
//! transactions and the owner signatures collected so far.
//!
//! Reads: the Safe's pending queue (with a derived lifecycle
//! [`SafeTxState`] per entry) and per-tx detail. Writes: [`propose`] and
//! [`confirm`], which only ever carry a signature the caller produced
//! after on-chain hash verification. The service is hit **keyless** —
//! the public endpoint allows ~2 RPS without an `Authorization` header,
//! which is plenty for a single user's wallet. Execution never goes
//! through the service; Kao broadcasts `execTransaction` directly via
//! [`super::tx::execute_safe_tx`].
//!
//! ### Trust posture
//!
//! The service is an **untrusted convenience index**, exactly like the
//! transaction indexers in [`crate::indexer`]. Nothing here is signed or
//! executed off the back of its reply — it only decides what rows the
//! Safe portfolio *shows*. The lifecycle FSM cross-references the Safe's
//! **authoritative on-chain nonce** (read through `BalanceFetcher`, the
//! same path the rest of the Safe inspection uses) so a lying service
//! can't, e.g., make a long-executed tx look executable: a record whose
//! nonce is below the live nonce is rendered `Replaced` regardless of
//! what the service claims.
//!
//! Reuses the indexer's shared HTTP client and — crucially — its
//! URL-redacting error formatter: the Safe address sits in the request
//! path, so a raw `reqwest::Error` would leak it into logs. See
//! `feedback_reqwest_url_leak.md`.

use alloy::primitives::{Address, B256, Bytes, U256};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::chain::Chain;
use crate::net::BalanceFetcher;

use super::SafeTx;
use super::tx::{current_safe_nonce, safe_domain, safe_tx_hash as compute_safe_tx_hash};

/// The public Safe Transaction Service gateway. Every service call
/// takes an explicit `base` so a Safe can point at a self-hosted
/// mirror instead (per-Safe `SafeDescriptor::tx_service_url`); this is
/// the default when none is configured. A custom base must serve the
/// same multi-chain layout: `{base}/tx-service/{chain}/api/v1/…`.
pub const DEFAULT_TX_SERVICE_BASE: &str = "https://api.safe.global";

/// Validate and normalize a user-supplied service base URL.
///
/// Returns `Ok(None)` for blank input or the default gateway (both
/// mean "store nothing, use the default"), `Ok(Some(base))` with
/// trailing slashes stripped otherwise. Rejects anything that isn't
/// `https` — the Safe address rides in every request path, so a
/// plaintext mirror would broadcast the user's holdings to the network
/// — except plain-http loopback, the common self-hosted dev setup.
pub fn normalize_service_base(input: &str) -> Result<Option<String>, String> {
    let trimmed = input.trim().trim_end_matches('/');
    if trimmed.is_empty() || trimmed == DEFAULT_TX_SERVICE_BASE {
        return Ok(None);
    }
    let url = reqwest::Url::parse(trimmed).map_err(|e| format!("invalid URL: {e}"))?;
    match url.scheme() {
        "https" => {}
        "http" if matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")) => {}
        "http" => {
            return Err(
                "plain http would leak your Safe address to the network — use https \
                 (http is allowed only for localhost)"
                    .to_string(),
            );
        }
        other => return Err(format!("unsupported scheme \"{other}\" — use https")),
    }
    if url.host_str().is_none() {
        return Err("URL needs a host".to_string());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("base URL must not carry a ?query or #fragment".to_string());
    }
    Ok(Some(trimmed.to_string()))
}

// ── Lifecycle FSM ────────────────────────────────────────────────────────────

/// Lifecycle state of a Safe multisig transaction, **derived** from a
/// Transaction-Service record plus the Safe's current on-chain nonce.
/// Not persisted — recomputed on every fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeTxState {
    /// Fewer confirmations than the threshold — needs more owner
    /// signatures before it can execute.
    AwaitingConfirmations { have: u64, required: u64 },
    /// Threshold met, not yet executed. `is_next` is true when this tx's
    /// nonce equals the Safe's current nonce (executable right now);
    /// false means an earlier-nonce tx must be executed or replaced
    /// first.
    AwaitingExecution { required: u64, is_next: bool },
    /// A different transaction already consumed this nonce on-chain
    /// (record nonce < the Safe's live nonce) — this one can never
    /// execute and should be read as cancelled/superseded.
    Replaced,
    /// Mined. `success` mirrors the service's `isSuccessful`.
    Executed { success: bool },
}

/// Derive the [`SafeTxState`] from the scalar fields that matter. Pure
/// and total so the truth table is unit-testable without any network or
/// JSON. Priority order matters: executed wins over everything, then the
/// replaced-by-nonce check, then threshold.
fn derive_state(
    have: u64,
    required: u64,
    nonce: u64,
    is_executed: bool,
    is_successful: Option<bool>,
    current_nonce: u64,
) -> SafeTxState {
    if is_executed {
        return SafeTxState::Executed {
            success: is_successful.unwrap_or(false),
        };
    }
    if nonce < current_nonce {
        return SafeTxState::Replaced;
    }
    if have >= required {
        return SafeTxState::AwaitingExecution {
            required,
            is_next: nonce == current_nonce,
        };
    }
    SafeTxState::AwaitingConfirmations { have, required }
}

// ── UI-facing model ──────────────────────────────────────────────────────────

/// One entry in a Safe's pending queue, parsed and state-tagged for the
/// portfolio view. Carries enough to render a row and, later, to open a
/// detail/verify modal.
#[derive(Debug, Clone)]
pub struct PendingSafeTx {
    /// Carried for the follow-up detail/verify modal (it keys the
    /// service's confirmation endpoint and is what owners sign); not read
    /// by the current row renderer.
    #[allow(dead_code)]
    pub safe_tx_hash: B256,
    pub to: Address,
    pub value: U256,
    /// Inner calldata. Reserved for clear-signing / the detail modal; the
    /// row shows only the native value today.
    #[allow(dead_code)]
    pub data: Bytes,
    /// Safe operation byte: `0` = call, `1` = delegatecall. Surfaced so
    /// the queue row and detail modal can flag delegatecalls loudly — a
    /// queued delegatecall proposed by another owner runs arbitrary code
    /// under the Safe's identity and must never look like a plain send.
    pub operation: u8,
    pub nonce: u64,
    pub state: SafeTxState,
    /// Unix seconds the proposal was submitted (0 if unparsable).
    pub submission_ts: u64,
}

// ── Wire models (Safe Transaction Service v1) ────────────────────────────────

/// A field the service may serialize as a JSON string *or* a bare
/// number, normalized to its string form (the downstream `parse::<U256>`
/// handles both decimal renderings identically).
#[derive(Deserialize)]
#[serde(untagged)]
enum StrOrNum {
    Str(String),
    Num(serde_json::Number),
}

impl StrOrNum {
    fn into_string(self) -> String {
        match self {
            StrOrNum::Str(s) => s,
            StrOrNum::Num(n) => n.to_string(),
        }
    }
}

fn de_num_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    StrOrNum::deserialize(d).map(StrOrNum::into_string)
}

fn de_opt_num_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(Option::<StrOrNum>::deserialize(d)?.map(StrOrNum::into_string))
}

#[derive(Debug, Clone, Deserialize)]
struct MultisigPage {
    #[serde(default)]
    results: Vec<RawMultisigTx>,
    /// Set when the service holds more rows than this page carried. Only its
    /// presence is used: the next page's URL is built here, never followed from
    /// the response, so a page can't point the next request at another host.
    #[serde(default)]
    next: Option<String>,
}

/// The live service (v6.x) returns `nonce`/`safeTxGas`/`baseGas` as JSON
/// **numbers** but `value`/`gasPrice` as strings; older self-hosted
/// mirrors stringify everything. Every numeric-ish field therefore goes
/// through [`de_num_string`] so either wire shape decodes — a strict
/// `String` here made the derived `Vec` decoder reject the whole page on
/// the first integer (`invalid type: integer `0`, expected a string`).
/// `to`/`safeTxHash` are hex strings; `data` nullable hex. Values are
/// then parsed defensively in [`map_raw`] so a single malformed row
/// drops out instead of failing the whole page.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMultisigTx {
    safe_tx_hash: String,
    to: String,
    #[serde(deserialize_with = "de_num_string")]
    value: String,
    #[serde(default)]
    data: Option<String>,
    #[serde(deserialize_with = "de_num_string")]
    nonce: String,
    // Relay/gas fields — zero for Kao-proposed txs but a tx authored by
    // another client may set them, so they must be read back verbatim to
    // reconstruct an executable `SafeTx` (the safeTxHash depends on them).
    #[serde(default)]
    operation: u8,
    #[serde(default, deserialize_with = "de_opt_num_string")]
    safe_tx_gas: Option<String>,
    #[serde(default, deserialize_with = "de_opt_num_string")]
    base_gas: Option<String>,
    #[serde(default, deserialize_with = "de_opt_num_string")]
    gas_price: Option<String>,
    #[serde(default)]
    gas_token: Option<String>,
    #[serde(default)]
    refund_receiver: Option<String>,
    #[serde(default)]
    is_executed: bool,
    #[serde(default)]
    is_successful: Option<bool>,
    #[serde(default)]
    confirmations_required: Option<u64>,
    #[serde(default)]
    confirmations: Vec<RawConfirmation>,
    #[serde(default)]
    submission_date: Option<String>,
}

/// A single owner confirmation: `owner` + the `signature` bytes the
/// service stored. The signature is captured (not just counted) so the
/// execute-from-queue path can reassemble the `execTransaction`
/// signature blob without every owner re-signing locally.
#[derive(Debug, Clone, Deserialize)]
struct RawConfirmation {
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    signature: Option<String>,
}

/// Number of confirmation rows with a parsable owner address. The
/// queue's `have` badge and the detail pane's checklist must agree, and
/// both can only act on rows the execute path can actually assemble.
fn parsable_confirmations(confirmations: &[RawConfirmation]) -> u64 {
    confirmations
        .iter()
        .filter(|c| {
            c.owner
                .as_deref()
                .is_some_and(|o| o.parse::<Address>().is_ok())
        })
        .count() as u64
}

/// Decode the service's raw confirmations into `(owner, signature)` pairs,
/// keeping only the ones we can actually use to execute. A confirmation whose
/// owner OR signature is absent/unparseable, or whose signature is empty, is
/// dropped: an empty/garbage signature would break the 65-byte-per-sig packing
/// in `execTransaction` (on-chain GS020/GS026) and inflate `confirmations.len()`
/// above the count of usable signatures that `derive_state` relies on.
fn parse_confirmations(confirmations: &[RawConfirmation]) -> Vec<ServiceConfirmation> {
    confirmations
        .iter()
        .filter_map(|c| {
            let owner = c.owner.as_deref()?.parse::<Address>().ok()?;
            let signature = c.signature.as_deref()?.parse::<Bytes>().ok()?;
            if signature.is_empty() {
                return None;
            }
            Some(ServiceConfirmation { owner, signature })
        })
        .collect()
}

/// Parse a decimal/0x numeric string field to `U256`, treating
/// absent/empty/garbage as zero (relay fields legitimately arrive null).
fn parse_u256_field(s: &Option<String>) -> U256 {
    s.as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<U256>().ok())
        .unwrap_or(U256::ZERO)
}

/// Parse an address field, treating absent/empty/garbage as the zero
/// address (matches Safe's "no gas token / no refund receiver" encoding).
fn parse_addr_field(s: &Option<String>) -> Address {
    s.as_deref()
        .and_then(|s| s.parse::<Address>().ok())
        .unwrap_or(Address::ZERO)
}

/// Reconstruct the full, executable `SafeTx` from a wire record —
/// including the relay fields, since the safeTxHash is computed over all
/// of them. Returns `None` if a structurally-required field is
/// unparsable.
fn raw_to_safe_tx(raw: &RawMultisigTx) -> Option<SafeTx> {
    let to = raw.to.parse::<Address>().ok()?;
    let nonce = raw.nonce.parse::<u64>().ok()?;
    // `value` is the amount being moved — drop the row on a parse failure
    // (matching `to`/`nonce`) rather than silently rendering a 0-value send,
    // which would hide a real transfer in the pending queue.
    let value = match raw.value.parse::<U256>() {
        Ok(v) => v,
        Err(e) => {
            debug!(value = %raw.value, error = %e, "dropping Safe tx: unparseable value");
            return None;
        }
    };
    let data = raw
        .data
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<Bytes>().ok())
        .unwrap_or_default();
    Some(SafeTx {
        to,
        value,
        data,
        operation: raw.operation,
        safeTxGas: parse_u256_field(&raw.safe_tx_gas),
        baseGas: parse_u256_field(&raw.base_gas),
        gasPrice: parse_u256_field(&raw.gas_price),
        gasToken: parse_addr_field(&raw.gas_token),
        refundReceiver: parse_addr_field(&raw.refund_receiver),
        nonce: U256::from(nonce),
    })
}

/// Build a `PendingSafeTx` from a wire record. Returns `None` when a
/// structurally-required field (hash, recipient, nonce) is unparsable —
/// that row is dropped rather than poisoning the queue. `required` falls
/// back to the Safe's threshold when the service omits
/// `confirmationsRequired`, and is floored at 1 (a 0-threshold Safe is
/// impossible, but guards a degenerate "0/0 signatures" badge).
fn map_raw(raw: RawMultisigTx, threshold: u32, current_nonce: u64) -> Option<PendingSafeTx> {
    let safe_tx_hash = raw.safe_tx_hash.parse::<B256>().ok()?;
    let to = raw.to.parse::<Address>().ok()?;
    let nonce = raw.nonce.parse::<u64>().ok()?;
    // Drop the row on an unparseable value rather than showing 0 — same
    // reasoning as `raw_to_safe_tx`: a 0-value pending tx would mask a real
    // transfer awaiting co-signers.
    let value = match raw.value.parse::<U256>() {
        Ok(v) => v,
        Err(e) => {
            debug!(value = %raw.value, error = %e, "dropping pending Safe tx: unparseable value");
            return None;
        }
    };
    let data = raw
        .data
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<Bytes>().ok())
        .unwrap_or_default();
    let required = raw
        .confirmations_required
        .unwrap_or(threshold as u64)
        .max(1);
    // Count only confirmations whose owner parses — `fetch_detail` and
    // the execute-from-queue signature assembly can only use parsed
    // rows, so a raw count would make the queue badge claim "2/2" while
    // the detail modal (and the executable blob) holds 1.
    let have = parsable_confirmations(&raw.confirmations);
    let state = derive_state(
        have,
        required,
        nonce,
        raw.is_executed,
        raw.is_successful,
        current_nonce,
    );
    let submission_ts = raw
        .submission_date
        .as_deref()
        .map(crate::indexer::parse_iso8601)
        .unwrap_or(0);
    Some(PendingSafeTx {
        safe_tx_hash,
        to,
        value,
        data,
        operation: raw.operation,
        nonce,
        state,
        submission_ts,
    })
}

/// Resolve a Safe-service response: pass 2xx through, otherwise fold the
/// response **body** into the error string. The service returns its real
/// diagnostic as JSON in the body (field-level validation errors on
/// propose/confirm, e.g. `{"signature": ["Signature does not match
/// sender"]}`); `reqwest`'s `error_for_status()` would discard it and
/// leave an opaque `HTTP 422`. The body is service-authored text about
/// our own request — no URL, no key — so it's safe to surface, truncated
/// so a misbehaving upstream can't flood the log.
async fn check_status(context: &str, resp: reqwest::Response) -> Result<reqwest::Response, String> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().await.unwrap_or_default();
    let body = body.trim();
    if body.is_empty() {
        Err(format!("{context}: HTTP {status}"))
    } else {
        const MAX_BODY: usize = 300;
        let detail: String = body.chars().take(MAX_BODY).collect();
        let ellipsis = if body.chars().count() > MAX_BODY {
            "…"
        } else {
            ""
        };
        Err(format!("{context}: HTTP {status} — {detail}{ellipsis}"))
    }
}

/// Rows per queue page — the Transaction Service's maximum `limit`.
const QUEUE_PAGE_ROWS: usize = 200;
/// Pages [`fetch_pending`] reads before it gives up on knowing the whole queue.
const QUEUE_MAX_PAGES: usize = 5;

/// One page of the Safe Transaction Service queue for `safe` on `chain`:
/// `executed=false` rows at nonces from `min_nonce` up (a row below the Safe's
/// live nonce can never execute — replaced or rejected proposals stay
/// `executed=false` forever, and enough of them would otherwise fill the first
/// page and hide the live queue), `ordering=nonce` so they arrive
/// lowest-nonce-first, `offset` rows in. The Safe address is checksummed in
/// the path — the API 422s on a lowercase address.
fn queue_url(base: &str, safe: Address, chain: Chain, min_nonce: u64, offset: usize) -> String {
    format!(
        "{base}/tx-service/{}/api/v1/safes/{}/multisig-transactions/?executed=false&ordering=nonce\
         &nonce__gte={min_nonce}&limit={QUEUE_PAGE_ROWS}&offset={offset}",
        chain.safe_tx_service_shortname(),
        safe.to_checksum(None),
    )
}

/// Fetch the Safe's pending multisig queue and tag each entry with its
/// lifecycle state.
///
/// Reads the Safe's authoritative on-chain nonce first (via
/// `BalanceFetcher`), then GETs the queue keyless from that nonce up — every
/// page of it, up to [`QUEUE_MAX_PAGES`] — and maps each record through
/// [`derive_state`]. `threshold` is the cached `SafeDescriptor.threshold`,
/// used only as a fallback when the service omits `confirmationsRequired`.
/// Returns rows sorted by nonce ascending; an empty queue yields `Ok(vec![])`.
///
/// A queue longer than the pages read is an `Err`, never a partial `Ok`:
/// callers take an `Ok` as the whole queue, and pin new transactions past it.
pub async fn fetch_pending(
    net: &dyn BalanceFetcher,
    base: &str,
    safe: Address,
    chain: Chain,
    threshold: u32,
) -> Result<Vec<PendingSafeTx>, String> {
    let current_nonce = current_safe_nonce(net, safe, chain).await?;
    let client = crate::indexer::http_client_or_err()?;
    let mut out: Vec<PendingSafeTx> = Vec::new();
    let mut offset = 0usize;
    for _ in 0..QUEUE_MAX_PAGES {
        let url = queue_url(base, safe, chain, current_nonce, offset);
        let resp =
            client.get(&url).send().await.map_err(|e| {
                format!("safe-service GET: {}", crate::indexer::redact_url_in_err(e))
            })?;
        let page: MultisigPage = check_status("safe-service queue", resp)
            .await?
            .json()
            .await
            .map_err(|e| {
                format!(
                    "safe-service decode: {}",
                    crate::indexer::redact_url_in_err(e)
                )
            })?;
        let rows = page.results.len();
        out.extend(
            page.results
                .into_iter()
                .filter_map(|raw| map_raw(raw, threshold, current_nonce)),
        );
        if page.next.is_none() {
            // Offsets shift if the queue changes between pages, which can
            // deliver a row twice; it is still one transaction.
            let mut seen = std::collections::HashSet::new();
            out.retain(|t| seen.insert(t.safe_tx_hash));
            out.sort_by_key(|t| t.nonce);
            return Ok(out);
        }
        if rows == 0 {
            // More is claimed but none was sent: asking again at the same
            // offset would get the same nothing.
            return Err(
                "the Safe Transaction Service returned an incomplete queue, so Kao can't tell \
                 which nonce is free"
                    .to_string(),
            );
        }
        offset = offset.saturating_add(rows);
    }
    Err(format!(
        "this Safe's pending queue is longer than Kao reads ({} transactions or more), so Kao \
         can't tell which nonce is free",
        QUEUE_MAX_PAGES * QUEUE_PAGE_ROWS
    ))
}

// ── Detail (full tx + per-owner signatures) ──────────────────────────────────

/// One owner's stored confirmation: who signed and the signature bytes
/// (Safe wire format) the service holds for them.
#[derive(Debug, Clone)]
pub struct ServiceConfirmation {
    pub owner: Address,
    pub signature: Bytes,
}

/// Full detail of a single queued tx: the reconstructed, executable
/// `SafeTx`, its derived lifecycle state, and the confirmations gathered
/// so far. Backs the detail modal (owner signed/pending list) and the
/// execute-from-queue path (reassembling the signature blob).
#[derive(Debug, Clone)]
pub struct SafeTxDetail {
    pub safe_tx_hash: B256,
    pub tx: SafeTx,
    pub state: SafeTxState,
    pub confirmations: Vec<ServiceConfirmation>,
    pub confirmations_required: u64,
}

impl SafeTxDetail {
    /// Owners who have signed, in service order.
    pub fn owners_signed(&self) -> Vec<Address> {
        self.confirmations.iter().map(|c| c.owner).collect()
    }
}

fn detail_url(base: &str, safe_tx_hash: B256, chain: Chain) -> String {
    format!(
        "{base}/tx-service/{}/api/v1/multisig-transactions/{:#x}/",
        chain.safe_tx_service_shortname(),
        safe_tx_hash,
    )
}

fn confirmations_url(base: &str, safe_tx_hash: B256, chain: Chain) -> String {
    format!(
        "{base}/tx-service/{}/api/v1/multisig-transactions/{:#x}/confirmations/",
        chain.safe_tx_service_shortname(),
        safe_tx_hash,
    )
}

fn propose_url(base: &str, safe: Address, chain: Chain) -> String {
    format!(
        "{base}/tx-service/{}/api/v1/safes/{}/multisig-transactions/",
        chain.safe_tx_service_shortname(),
        safe.to_checksum(None),
    )
}

fn build_detail_from_raw(
    raw: &RawMultisigTx,
    safe: Address,
    chain: Chain,
    requested_hash: B256,
    threshold: u32,
    current_nonce: u64,
) -> Result<SafeTxDetail, String> {
    let tx = raw_to_safe_tx(raw).ok_or("safe-service: unparsable tx detail")?;
    let body_hash = compute_safe_tx_hash(&tx, &safe_domain(safe, chain));
    if body_hash != requested_hash {
        return Err(format!(
            "safe-service detail hash mismatch: requested {requested_hash:#x} but body hashes to {body_hash:#x}"
        ));
    }
    let nonce = u64::try_from(tx.nonce).unwrap_or(u64::MAX);
    let required = raw
        .confirmations_required
        .unwrap_or(threshold as u64)
        .max(1);
    let confirmations = parse_confirmations(&raw.confirmations);
    let state = derive_state(
        confirmations.len() as u64,
        required,
        nonce,
        raw.is_executed,
        raw.is_successful,
        current_nonce,
    );
    Ok(SafeTxDetail {
        safe_tx_hash: body_hash,
        tx,
        state,
        confirmations,
        confirmations_required: required,
    })
}

/// Fetch full detail for one queued tx, including each owner's signature.
/// Reads the Safe's live nonce to derive the lifecycle state (same as
/// the list path). `threshold` is the fallback when the service omits
/// `confirmationsRequired`.
pub async fn fetch_detail(
    net: &dyn BalanceFetcher,
    base: &str,
    safe: Address,
    chain: Chain,
    safe_tx_hash: B256,
    threshold: u32,
) -> Result<SafeTxDetail, String> {
    let current_nonce = current_safe_nonce(net, safe, chain).await?;
    let url = detail_url(base, safe_tx_hash, chain);
    let resp = crate::indexer::http_client_or_err()?
        .get(&url)
        .send()
        .await
        .map_err(|e| {
            format!(
                "safe-service GET detail: {}",
                crate::indexer::redact_url_in_err(e)
            )
        })?;
    let raw: RawMultisigTx = check_status("safe-service detail", resp)
        .await?
        .json()
        .await
        .map_err(|e| {
            format!(
                "safe-service detail decode: {}",
                crate::indexer::redact_url_in_err(e)
            )
        })?;

    build_detail_from_raw(&raw, safe, chain, safe_tx_hash, threshold, current_nonce)
}

// ── Write path (propose / confirm) ───────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposeBody {
    to: String,
    value: String,
    data: String,
    operation: u8,
    safe_tx_gas: String,
    base_gas: String,
    gas_price: String,
    gas_token: String,
    refund_receiver: String,
    nonce: String,
    contract_transaction_hash: String,
    sender: String,
    signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<String>,
}

#[derive(Debug, Serialize)]
struct ConfirmBody {
    signature: String,
}

/// Propose a new (or rejection) multisig tx to the service so co-owners
/// can see and sign it. `owner_sig` is the `(owner, signature)` pair from
/// `tx::sign_owner` — the owner must be one of the Safe's, and the blob
/// their EIP-712 (or eth_sign) signature over `safe_tx_hash`, so the
/// hardware path is covered. Pure HTTP: the caller is responsible for
/// having verified the hash on-chain before signing.
pub async fn propose(
    base: &str,
    safe: Address,
    chain: Chain,
    tx: &SafeTx,
    safe_tx_hash: B256,
    owner_sig: &(Address, Bytes),
    origin: Option<&str>,
) -> Result<(), String> {
    let (sender, signature) = owner_sig;
    let body = ProposeBody {
        to: tx.to.to_checksum(None),
        value: tx.value.to_string(),
        data: tx.data.to_string(),
        operation: tx.operation,
        safe_tx_gas: tx.safeTxGas.to_string(),
        base_gas: tx.baseGas.to_string(),
        gas_price: tx.gasPrice.to_string(),
        gas_token: tx.gasToken.to_checksum(None),
        refund_receiver: tx.refundReceiver.to_checksum(None),
        nonce: tx.nonce.to_string(),
        contract_transaction_hash: format!("{safe_tx_hash:#x}"),
        sender: sender.to_checksum(None),
        signature: signature.to_string(),
        origin: origin.map(str::to_string),
    };
    let resp = crate::indexer::http_client_or_err()?
        .post(propose_url(base, safe, chain))
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            format!(
                "safe-service propose: {}",
                crate::indexer::redact_url_in_err(e)
            )
        })?;
    check_status("safe-service propose", resp).await?;
    Ok(())
}

/// Add a confirming owner's `signature` (over `safe_tx_hash`) to an
/// existing queued tx. Pure HTTP.
pub async fn confirm(
    base: &str,
    safe_tx_hash: B256,
    chain: Chain,
    signature: &Bytes,
) -> Result<(), String> {
    let body = ConfirmBody {
        signature: signature.to_string(),
    };
    let resp = crate::indexer::http_client_or_err()?
        .post(confirmations_url(base, safe_tx_hash, chain))
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            format!(
                "safe-service confirm: {}",
                crate::indexer::redact_url_in_err(e)
            )
        })?;
    check_status("safe-service confirm", resp).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fsm_awaiting_confirmations_below_threshold() {
        // 1 of 2 sigs, nonce is the live one → still needs signatures.
        let s = derive_state(1, 2, 5, false, None, 5);
        assert_eq!(
            s,
            SafeTxState::AwaitingConfirmations {
                have: 1,
                required: 2
            }
        );
    }

    #[test]
    fn parse_confirmations_drops_empty_or_unparsable_signatures() {
        let owner_a = "0x1111111111111111111111111111111111111111";
        let owner_b = "0x2222222222222222222222222222222222222222";
        let sig = format!("0x{}", "11".repeat(65)); // a 65-byte signature
        let raw = vec![
            // Fully valid → kept.
            RawConfirmation {
                owner: Some(owner_a.into()),
                signature: Some(sig.clone()),
            },
            // Valid owner but empty signature ("0x") → dropped; an empty blob
            // would break `execTransaction` signature packing.
            RawConfirmation {
                owner: Some(owner_b.into()),
                signature: Some("0x".into()),
            },
            // Valid owner, missing signature → dropped.
            RawConfirmation {
                owner: Some(owner_b.into()),
                signature: None,
            },
            // Unparsable owner → dropped.
            RawConfirmation {
                owner: Some("not-an-address".into()),
                signature: Some(sig.clone()),
            },
        ];
        let parsed = parse_confirmations(&raw);
        assert_eq!(
            parsed.len(),
            1,
            "only the fully-valid confirmation survives"
        );
        assert_eq!(parsed[0].owner, owner_a.parse::<Address>().unwrap());
        assert!(!parsed[0].signature.is_empty());
    }

    #[test]
    fn fsm_awaiting_execution_is_next_when_nonce_current() {
        // Threshold met and nonce == current → executable now.
        let s = derive_state(2, 2, 5, false, None, 5);
        assert_eq!(
            s,
            SafeTxState::AwaitingExecution {
                required: 2,
                is_next: true
            }
        );
    }

    #[test]
    fn fsm_awaiting_execution_blocked_behind_earlier_nonce() {
        // Threshold met but an earlier nonce hasn't gone yet.
        let s = derive_state(3, 2, 7, false, None, 5);
        assert_eq!(
            s,
            SafeTxState::AwaitingExecution {
                required: 2,
                is_next: false
            }
        );
    }

    #[test]
    fn fsm_replaced_when_nonce_below_current() {
        // Even fully signed, a sub-current nonce can never execute.
        let s = derive_state(2, 2, 4, false, None, 5);
        assert_eq!(s, SafeTxState::Replaced);
    }

    #[test]
    fn fsm_executed_wins_over_everything() {
        // is_executed short-circuits the nonce/threshold checks.
        let ok = derive_state(2, 2, 4, true, Some(true), 5);
        assert_eq!(ok, SafeTxState::Executed { success: true });
        let failed = derive_state(2, 2, 4, true, Some(false), 5);
        assert_eq!(failed, SafeTxState::Executed { success: false });
        // Null isSuccessful is treated as not-yet-confirmed-success.
        let unknown = derive_state(2, 2, 4, true, None, 5);
        assert_eq!(unknown, SafeTxState::Executed { success: false });
    }

    #[test]
    fn map_raw_falls_back_to_threshold_when_required_absent() {
        let raw = RawMultisigTx {
            safe_tx_hash: "0x".to_string() + &"ab".repeat(32),
            to: "0x000000000000000000000000000000000000dEaD".to_string(),
            value: "0".to_string(),
            data: None,
            nonce: "5".to_string(),
            operation: 0,
            safe_tx_gas: None,
            base_gas: None,
            gas_price: None,
            gas_token: None,
            refund_receiver: None,
            is_executed: false,
            is_successful: None,
            confirmations_required: None, // service omitted it
            confirmations: vec![
                RawConfirmation {
                    owner: Some("0x2222222222222222222222222222222222222222".to_string()),
                    signature: None,
                },
                // Unparsable owner: must NOT count toward `have` — the
                // detail/execute path can't use this row either.
                RawConfirmation {
                    owner: None,
                    signature: None,
                },
            ],
            submission_date: None,
        };
        let tx = map_raw(raw, 3, 5).unwrap();
        // 1 parsable confirmation against the fallback threshold of 3.
        assert_eq!(
            tx.state,
            SafeTxState::AwaitingConfirmations {
                have: 1,
                required: 3
            }
        );
    }

    #[test]
    fn deserialize_and_map_live_integer_shape() {
        // Captured from api.safe.global (service v6.4.0, 2026-06):
        // `nonce`/`safeTxGas`/`baseGas` arrive as bare JSON numbers while
        // `value`/`gasPrice` stay strings. A strict String wire model
        // rejected this whole page with "invalid type: integer `0`,
        // expected a string".
        let json = r#"{
            "count": 1,
            "results": [
                {
                    "safe": "0x1111111111111111111111111111111111111111",
                    "to": "0x000000000000000000000000000000000000dEaD",
                    "value": "0",
                    "data": null,
                    "operation": 1,
                    "gasToken": "0x0000000000000000000000000000000000000000",
                    "safeTxGas": 0,
                    "baseGas": 0,
                    "gasPrice": "0",
                    "refundReceiver": "0x0000000000000000000000000000000000000000",
                    "nonce": 2820,
                    "safeTxHash": "0xe0a663a4fcc44de5a28b1db4d858b82b2f79221d47fb6b48392a66343eb04924",
                    "isExecuted": false,
                    "isSuccessful": null,
                    "confirmationsRequired": 2,
                    "confirmations": []
                }
            ]
        }"#;
        let page: MultisigPage = serde_json::from_str(json).unwrap();
        let raw = page.results.into_iter().next().unwrap();
        let tx = raw_to_safe_tx(&raw).unwrap();
        assert_eq!(tx.nonce, U256::from(2820u64));
        assert_eq!(tx.safeTxGas, U256::ZERO);
        let pending = map_raw(raw, 2, 2820).unwrap();
        assert_eq!(pending.nonce, 2820);
        assert_eq!(
            pending.state,
            SafeTxState::AwaitingConfirmations {
                have: 0,
                required: 2
            }
        );
    }

    #[test]
    fn deserialize_and_map_sample_page() {
        // String-shaped Safe v1 payload (older self-hosted mirrors
        // stringify the numeric fields): string `value`/`nonce`, null
        // `isSuccessful`, nested confirmations, extra fields we ignore.
        let json = r#"{
            "count": 1,
            "results": [
                {
                    "safe": "0x1111111111111111111111111111111111111111",
                    "to": "0x000000000000000000000000000000000000dEaD",
                    "value": "1000000000000000000",
                    "data": null,
                    "operation": 0,
                    "nonce": "9",
                    "safeTxHash": "0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8",
                    "isExecuted": false,
                    "isSuccessful": null,
                    "confirmationsRequired": 2,
                    "submissionDate": "2026-01-15T10:30:00Z",
                    "confirmations": [
                        {"owner": "0x2222222222222222222222222222222222222222", "signature": "0xdead"}
                    ]
                }
            ]
        }"#;
        let page: MultisigPage = serde_json::from_str(json).unwrap();
        assert_eq!(page.results.len(), 1);
        // current_nonce = 9 → this is the next executable tx, but it
        // only has 1 of 2 sigs, so it's still awaiting confirmations.
        let tx = map_raw(page.results.into_iter().next().unwrap(), 2, 9).unwrap();
        assert_eq!(tx.nonce, 9);
        assert_eq!(tx.value, U256::from(1_000_000_000_000_000_000u128));
        assert!(tx.data.is_empty());
        assert_eq!(
            tx.submission_ts,
            crate::indexer::parse_iso8601("2026-01-15T10:30:00Z")
        );
        assert_eq!(
            tx.state,
            SafeTxState::AwaitingConfirmations {
                have: 1,
                required: 2
            }
        );
    }

    // ── check_status ─────────────────────────────────────────────────

    /// Build a `reqwest::Response` without a network round-trip.
    /// reqwest implements `From<http::Response<T>>` exactly for this.
    fn response(status: u16, body: &str) -> reqwest::Response {
        reqwest::Response::from(
            http::Response::builder()
                .status(status)
                .body(body.to_string())
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn check_status_passes_success_through_with_body_intact() {
        let resp = check_status("ctx", response(200, r#"{"results": []}"#))
            .await
            .unwrap();
        // The body must still be readable downstream — check_status only
        // consumes it on the error path.
        assert_eq!(resp.text().await.unwrap(), r#"{"results": []}"#);
    }

    #[tokio::test]
    async fn check_status_folds_service_body_into_error() {
        // The whole point of check_status over `error_for_status()`: the
        // service's field-level diagnostic must survive into the error
        // string the UI and logs surface.
        let body = r#"{"signature": ["Signature does not match sender"]}"#;
        let err = check_status("safe-service propose", response(422, body))
            .await
            .unwrap_err();
        assert!(err.starts_with("safe-service propose: HTTP 422"), "{err}");
        assert!(err.contains("Signature does not match sender"), "{err}");
    }

    #[tokio::test]
    async fn check_status_empty_body_is_status_only() {
        let err = check_status("ctx", response(503, "")).await.unwrap_err();
        assert_eq!(err, "ctx: HTTP 503 Service Unavailable");
        // Whitespace-only bodies collapse to the same shape.
        let err = check_status("ctx", response(503, "  \n"))
            .await
            .unwrap_err();
        assert_eq!(err, "ctx: HTTP 503 Service Unavailable");
    }

    #[tokio::test]
    async fn check_status_truncates_runaway_bodies() {
        // 'z' rather than 'x': the context and status text must not
        // collide with the char we count.
        let body = "z".repeat(5_000);
        let err = check_status("ctx", response(500, &body)).await.unwrap_err();
        assert!(err.ends_with('…'), "{err}");
        assert_eq!(err.chars().filter(|c| *c == 'z').count(), 300);
    }

    // ── parsable_confirmations ───────────────────────────────────────

    #[test]
    fn parsable_confirmations_counts_only_rows_with_valid_owner() {
        let rows = vec![
            RawConfirmation {
                owner: Some("0x2222222222222222222222222222222222222222".into()),
                signature: Some("0xdead".into()),
            },
            // No owner at all.
            RawConfirmation {
                owner: None,
                signature: Some("0xdead".into()),
            },
            // Garbage owner.
            RawConfirmation {
                owner: Some("not-an-address".into()),
                signature: None,
            },
        ];
        assert_eq!(parsable_confirmations(&rows), 1);
        assert_eq!(parsable_confirmations(&[]), 0);
    }

    #[test]
    fn map_raw_floors_required_at_one_when_service_reports_zero() {
        // A 0-threshold Safe is impossible, but a lying/buggy service
        // must not produce a "1/0 signatures" badge — the floor turns
        // one valid signature into an executable state instead.
        let raw = RawMultisigTx {
            safe_tx_hash: "0x".to_string() + &"ab".repeat(32),
            to: "0x000000000000000000000000000000000000dEaD".to_string(),
            value: "0".to_string(),
            data: None,
            nonce: "5".to_string(),
            operation: 0,
            safe_tx_gas: None,
            base_gas: None,
            gas_price: None,
            gas_token: None,
            refund_receiver: None,
            is_executed: false,
            is_successful: None,
            confirmations_required: Some(0),
            confirmations: vec![RawConfirmation {
                owner: Some("0x2222222222222222222222222222222222222222".into()),
                signature: None,
            }],
            submission_date: None,
        };
        let tx = map_raw(raw, 3, 5).unwrap();
        assert_eq!(
            tx.state,
            SafeTxState::AwaitingExecution {
                required: 1,
                is_next: true
            }
        );
    }

    #[test]
    fn raw_to_safe_tx_rejects_nonce_overflowing_u64() {
        // 2^64 — parses as U256 but not as the u64 the wire field uses;
        // the row must drop rather than wrap silently.
        let json = r#"{
            "to": "0x000000000000000000000000000000000000dEaD",
            "value": "0",
            "operation": 0,
            "nonce": "18446744073709551616",
            "safeTxHash": "0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8",
            "isExecuted": false,
            "confirmations": []
        }"#;
        let raw: RawMultisigTx = serde_json::from_str(json).unwrap();
        assert!(raw_to_safe_tx(&raw).is_none());
    }

    #[test]
    fn propose_url_uses_checksum_and_shortname() {
        let safe = "0x000000000000000000000000000000000000dead"
            .parse::<Address>()
            .unwrap();
        let url = propose_url(DEFAULT_TX_SERVICE_BASE, safe, Chain::Mainnet);
        assert!(url.starts_with("https://api.safe.global/"));
        assert!(url.contains("/tx-service/eth/"));
        assert!(url.contains(&safe.to_checksum(None)));
        assert!(url.ends_with("/multisig-transactions/"));
    }

    #[test]
    fn url_builders_respect_custom_base() {
        let safe = Address::repeat_byte(0x11);
        let hash = B256::repeat_byte(0x22);
        let base = "https://txs.example-dao.org";
        for url in [
            queue_url(base, safe, Chain::Base, 0, 0),
            detail_url(base, hash, Chain::Base),
            confirmations_url(base, hash, Chain::Base),
            propose_url(base, safe, Chain::Base),
        ] {
            assert!(
                url.starts_with("https://txs.example-dao.org/tx-service/base/"),
                "{url}"
            );
            assert!(!url.contains("api.safe.global"), "{url}");
        }
    }

    #[test]
    fn normalize_service_base_accepts_https_and_strips_slashes() {
        assert_eq!(
            normalize_service_base("https://txs.example-dao.org//").unwrap(),
            Some("https://txs.example-dao.org".to_string()),
        );
        // Loopback http is the self-hosted dev setup — allowed.
        assert_eq!(
            normalize_service_base("http://localhost:8000/").unwrap(),
            Some("http://localhost:8000".to_string()),
        );
        assert_eq!(
            normalize_service_base("http://127.0.0.1:8000").unwrap(),
            Some("http://127.0.0.1:8000".to_string()),
        );
    }

    #[test]
    fn normalize_service_base_blank_or_default_means_none() {
        assert_eq!(normalize_service_base("").unwrap(), None);
        assert_eq!(normalize_service_base("   ").unwrap(), None);
        // Typing the default collapses to "no override" so the store
        // never pins the public gateway as if it were a custom mirror.
        assert_eq!(
            normalize_service_base(DEFAULT_TX_SERVICE_BASE).unwrap(),
            None
        );
        assert_eq!(
            normalize_service_base("https://api.safe.global/").unwrap(),
            None,
        );
    }

    #[test]
    fn normalize_service_base_handles_ipv6_loopback() {
        // The loopback allowance must cover IPv6 too — `Url::host_str`
        // keeps the brackets, which is what the allowlist matches on.
        assert_eq!(
            normalize_service_base("http://[::1]:8000").unwrap(),
            Some("http://[::1]:8000".to_string()),
        );
        // A NON-loopback IPv6 host over plain http stays rejected.
        assert!(normalize_service_base("http://[2001:db8::1]:8000").is_err());
    }

    #[test]
    fn normalize_service_base_rejects_leaky_or_malformed() {
        // Non-loopback plain http leaks the Safe address en route.
        assert!(normalize_service_base("http://txs.example-dao.org").is_err());
        assert!(normalize_service_base("ftp://example.org").is_err());
        assert!(normalize_service_base("not a url").is_err());
        assert!(normalize_service_base("https://example.org?key=1").is_err());
        assert!(normalize_service_base("https://example.org#frag").is_err());
    }

    #[test]
    fn multisig_page_tolerates_missing_results_key() {
        // Defensive deserialization: a degenerate (or error-shaped)
        // body without `results` must parse to an empty page, not fail.
        let page: MultisigPage = serde_json::from_str("{}").unwrap();
        assert!(page.results.is_empty());
        let page: MultisigPage = serde_json::from_str(r#"{"count": 0}"#).unwrap();
        assert!(page.results.is_empty());
    }

    // ── fetch_pending against a loopback Transaction Service ──────────

    /// A loopback stand-in for the Transaction Service: answers each GET with the JSON body
    /// `page` returns for its request line, up to `max` requests, and hands back every request
    /// line it saw.
    async fn queue_service(
        page: impl Fn(&str) -> serde_json::Value + Send + 'static,
        max: usize,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let served = tokio::spawn(async move {
            let mut lines = Vec::new();
            for _ in 0..max {
                let accepted =
                    tokio::time::timeout(std::time::Duration::from_millis(500), listener.accept())
                        .await;
                let Ok(Ok((mut sock, _))) = accepted else {
                    break;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let line = String::from_utf8_lossy(&buf)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                let body = page(&line).to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
                lines.push(line);
            }
            lines
        });
        (base, served)
    }

    fn queue_row(nonce: u64) -> serde_json::Value {
        serde_json::json!({
            "safeTxHash": format!("0x{:064x}", nonce + 1),
            "to": "0x000000000000000000000000000000000000dEaD",
            "value": "0",
            "data": null,
            "nonce": nonce,
            "operation": 0,
            "isExecuted": false,
            "confirmationsRequired": 2,
            "confirmations": []
        })
    }

    fn nonce_mock(safe: Address, nonce: u64) -> crate::net::CallMock {
        use alloy::sol_types::{SolCall, SolValue};
        let mock = crate::net::CallMock::new();
        mock.set_call(
            safe,
            Bytes::from(crate::safe::nonceCall {}.abi_encode()),
            Bytes::from(U256::from(nonce).abi_encode()),
            true,
        );
        mock
    }

    /// 100 or more never-executed proposals below the live nonce (replaced or rejected ones stay
    /// `executed=false` forever) must not fill the first page and hide the live queue: a page of
    /// stale rows read as the whole queue makes it look known and empty, and a dapp transaction
    /// would then pin the nonce a co-signer's proposal already holds.
    #[tokio::test]
    async fn fetch_pending_reads_the_live_queue_past_stale_rows() {
        let safe = Address::repeat_byte(0x5a);
        let (base, served) = queue_service(
            |line| {
                if line.contains("nonce__gte=120") {
                    serde_json::json!({"count": 1, "next": null, "results": [queue_row(120)]})
                } else if line.contains("offset=100") {
                    serde_json::json!({"count": 101, "next": null, "results": [queue_row(120)]})
                } else {
                    let rows: Vec<_> = (0..100).map(queue_row).collect();
                    serde_json::json!({
                        "count": 101,
                        "next": "http://elsewhere.example/page2?limit=100&offset=100",
                        "results": rows
                    })
                }
            },
            4,
        )
        .await;
        let got = fetch_pending(&nonce_mock(safe, 120), &base, safe, Chain::Mainnet, 2).await;
        let lines = served.await.unwrap();
        let live: Result<Vec<u64>, String> = got
            .as_ref()
            .map(|v| v.iter().map(|p| p.nonce).filter(|n| *n >= 120).collect())
            .map_err(Clone::clone);
        assert_eq!(
            live,
            Ok(vec![120]),
            "the co-signer's proposal at the live nonce is missing: {lines:?}"
        );
    }

    /// A queue spanning pages is read to its end — through offsets Kao builds itself against the
    /// service it was configured with, never through the `next` URL a response names.
    #[tokio::test]
    async fn fetch_pending_reads_every_page_from_its_own_offsets() {
        let safe = Address::repeat_byte(0x5a);
        let (base, served) = queue_service(
            |line| {
                if line.contains("offset=0") {
                    let rows: Vec<_> = (10..10 + QUEUE_PAGE_ROWS as u64).map(queue_row).collect();
                    serde_json::json!({
                        "count": QUEUE_PAGE_ROWS + 1,
                        "next": "http://elsewhere.example/?offset=200",
                        "results": rows
                    })
                } else {
                    serde_json::json!({"count": 201, "next": null, "results": [queue_row(500)]})
                }
            },
            4,
        )
        .await;
        let got = fetch_pending(&nonce_mock(safe, 10), &base, safe, Chain::Mainnet, 2)
            .await
            .expect("the whole queue");
        let lines = served.await.unwrap();
        assert_eq!(got.len(), QUEUE_PAGE_ROWS + 1);
        assert_eq!(got.last().map(|p| p.nonce), Some(500));
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines[1].contains(&format!("offset={QUEUE_PAGE_ROWS}"))
                && lines[1].contains("/tx-service/eth/"),
            "{lines:?}"
        );
    }

    /// A page that claims more rows but sends none, or a row delivered on two pages (offsets
    /// shift when the queue changes mid-read): neither is mistaken for the queue as it stands.
    #[tokio::test]
    async fn fetch_pending_refuses_an_empty_page_that_claims_more_and_dedups_rows() {
        let safe = Address::repeat_byte(0x5a);
        let (base, _served) = queue_service(
            |_| serde_json::json!({"count": 5, "next": "more", "results": []}),
            2,
        )
        .await;
        let got = fetch_pending(&nonce_mock(safe, 7), &base, safe, Chain::Mainnet, 2).await;
        assert!(
            got.as_ref().is_err_and(|e| e.contains("incomplete")),
            "{got:?}"
        );

        let (base, _served) = queue_service(
            |line| {
                if line.contains("offset=0") {
                    serde_json::json!({"count": 3, "next": "more", "results": [queue_row(7), queue_row(8)]})
                } else {
                    serde_json::json!({"count": 3, "next": null, "results": [queue_row(8), queue_row(9)]})
                }
            },
            3,
        )
        .await;
        let got = fetch_pending(&nonce_mock(safe, 7), &base, safe, Chain::Mainnet, 2)
            .await
            .expect("the queue");
        assert_eq!(
            got.iter().map(|p| p.nonce).collect::<Vec<_>>(),
            vec![7, 8, 9]
        );
    }

    /// A queue longer than Kao reads is not "the queue": an error, so the caller knows it doesn't
    /// know which nonce is free.
    #[tokio::test]
    async fn fetch_pending_refuses_a_queue_longer_than_it_reads() {
        let safe = Address::repeat_byte(0x5a);
        let (base, served) = queue_service(
            |_| serde_json::json!({"count": 100_000, "next": "more", "results": [queue_row(7)]}),
            QUEUE_MAX_PAGES + 2,
        )
        .await;
        let got = fetch_pending(&nonce_mock(safe, 7), &base, safe, Chain::Mainnet, 2).await;
        assert!(got.as_ref().is_err_and(|e| e.contains("longer")), "{got:?}");
        assert_eq!(served.await.unwrap().len(), QUEUE_MAX_PAGES);
    }

    #[test]
    fn queue_url_uses_checksum_and_shortname() {
        let safe = "0x000000000000000000000000000000000000dead"
            .parse::<Address>()
            .unwrap();
        let url = queue_url(DEFAULT_TX_SERVICE_BASE, safe, Chain::Optimism, 7, 200);
        assert!(url.contains("/tx-service/oeth/"));
        assert!(url.contains("executed=false"));
        assert!(url.contains("nonce__gte=7"), "{url}");
        assert!(url.contains("limit=200&offset=200"), "{url}");
        // Checksummed address in the path (mixed case), not the lowercase input.
        assert!(url.contains(&safe.to_checksum(None)));
    }

    #[test]
    fn map_raw_drops_unparsable_rows() {
        let raw = RawMultisigTx {
            safe_tx_hash: "not-a-hash".to_string(),
            to: "0x000000000000000000000000000000000000dEaD".to_string(),
            value: "0".to_string(),
            data: None,
            nonce: "1".to_string(),
            operation: 0,
            safe_tx_gas: None,
            base_gas: None,
            gas_price: None,
            gas_token: None,
            refund_receiver: None,
            is_executed: false,
            is_successful: None,
            confirmations_required: Some(1),
            confirmations: vec![],
            submission_date: None,
        };
        assert!(map_raw(raw, 1, 0).is_none());
    }

    #[test]
    fn map_raw_carries_operation_byte() {
        // A delegatecall proposed by another client must reach the UI
        // model — the queue row / detail modal flag it as dangerous.
        let raw = RawMultisigTx {
            safe_tx_hash: "0x".to_string() + &"ef".repeat(32),
            to: "0x000000000000000000000000000000000000dEaD".to_string(),
            value: "0".to_string(),
            data: None,
            nonce: "5".to_string(),
            operation: 1,
            safe_tx_gas: None,
            base_gas: None,
            gas_price: None,
            gas_token: None,
            refund_receiver: None,
            is_executed: false,
            is_successful: None,
            confirmations_required: Some(2),
            confirmations: vec![],
            submission_date: None,
        };
        let tx = map_raw(raw, 2, 5).unwrap();
        assert_eq!(tx.operation, 1);
    }

    #[test]
    fn detail_reconstructs_full_tx_and_confirmations() {
        // Detail endpoint returns a single object (not paged) with the
        // relay fields populated and per-owner signatures.
        let sig_hex = "0x".to_string() + &"11".repeat(65);
        let json = format!(
            r#"{{
                "to": "0x000000000000000000000000000000000000dEaD",
                "value": "1000000000000000000",
                "data": "0xabcd",
                "operation": 0,
                "nonce": "3",
                "safeTxGas": "21000",
                "baseGas": "0",
                "gasPrice": "0",
                "gasToken": "0x0000000000000000000000000000000000000000",
                "refundReceiver": null,
                "safeTxHash": "0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8",
                "isExecuted": false,
                "isSuccessful": null,
                "confirmationsRequired": 2,
                "confirmations": [
                    {{"owner": "0x2222222222222222222222222222222222222222", "signature": "{sig_hex}"}}
                ]
            }}"#
        );
        let raw: RawMultisigTx = serde_json::from_str(&json).unwrap();
        let tx = raw_to_safe_tx(&raw).unwrap();
        assert_eq!(tx.value, U256::from(1_000_000_000_000_000_000u128));
        assert_eq!(tx.nonce, U256::from(3u64));
        assert_eq!(tx.safeTxGas, U256::from(21000u64));
        assert_eq!(tx.data, "0xabcd".parse::<Bytes>().unwrap());
        assert_eq!(tx.gasToken, Address::ZERO);
        assert_eq!(tx.refundReceiver, Address::ZERO);
        // Confirmation owner + signature parse.
        assert_eq!(raw.confirmations.len(), 1);
        let owner = raw.confirmations[0]
            .owner
            .as_deref()
            .unwrap()
            .parse::<Address>()
            .unwrap();
        assert_eq!(owner, Address::repeat_byte(0x22));
        let sig = raw.confirmations[0]
            .signature
            .as_deref()
            .unwrap()
            .parse::<Bytes>()
            .unwrap();
        assert_eq!(sig.len(), 65);
    }

    fn detail_raw_for_hash_tests() -> RawMultisigTx {
        RawMultisigTx {
            safe_tx_hash: "0x".to_string() + &"bb".repeat(32),
            to: "0x000000000000000000000000000000000000dEaD".to_string(),
            value: "5".to_string(),
            data: Some("0xabcd".to_string()),
            nonce: "3".to_string(),
            operation: 0,
            safe_tx_gas: Some("21000".to_string()),
            base_gas: Some("0".to_string()),
            gas_price: Some("0".to_string()),
            gas_token: Some("0x0000000000000000000000000000000000000000".to_string()),
            refund_receiver: None,
            is_executed: false,
            is_successful: None,
            confirmations_required: Some(2),
            confirmations: vec![RawConfirmation {
                owner: Some("0x2222222222222222222222222222222222222222".to_string()),
                signature: Some("0x".to_string() + &"11".repeat(65)),
            }],
            submission_date: None,
        }
    }

    #[test]
    fn detail_builder_binds_body_to_requested_hash() {
        let safe = Address::repeat_byte(0x11);
        let chain = Chain::Mainnet;
        let raw = detail_raw_for_hash_tests();
        let tx = raw_to_safe_tx(&raw).unwrap();
        let requested_hash = compute_safe_tx_hash(&tx, &safe_domain(safe, chain));

        let detail = build_detail_from_raw(&raw, safe, chain, requested_hash, 2, 3).unwrap();

        assert_eq!(detail.safe_tx_hash, requested_hash);
        assert_eq!(detail.tx.to, tx.to);
        assert_eq!(detail.tx.value, tx.value);
        assert_eq!(detail.tx.data, tx.data);
        assert_eq!(detail.tx.operation, tx.operation);
        assert_eq!(detail.tx.safeTxGas, tx.safeTxGas);
        assert_eq!(detail.tx.baseGas, tx.baseGas);
        assert_eq!(detail.tx.gasPrice, tx.gasPrice);
        assert_eq!(detail.tx.gasToken, tx.gasToken);
        assert_eq!(detail.tx.refundReceiver, tx.refundReceiver);
        assert_eq!(detail.tx.nonce, tx.nonce);
        assert_eq!(
            detail.state,
            SafeTxState::AwaitingConfirmations {
                have: 1,
                required: 2
            }
        );
        assert_eq!(detail.confirmations.len(), 1);
    }

    #[test]
    fn detail_builder_rejects_mismatched_body_hash() {
        let safe = Address::repeat_byte(0x11);
        let chain = Chain::Mainnet;
        let raw = detail_raw_for_hash_tests();
        let wrong_requested_hash = B256::repeat_byte(0x42);

        let err = build_detail_from_raw(&raw, safe, chain, wrong_requested_hash, 2, 3)
            .expect_err("service detail whose body hashes differently must be rejected");

        assert!(err.contains("detail hash mismatch"), "{err}");
        assert!(err.contains(&format!("{wrong_requested_hash:#x}")), "{err}");
    }

    #[test]
    fn propose_body_has_camelcase_decimal_and_hex_fields() {
        let tx = SafeTx {
            to: "0x000000000000000000000000000000000000dEaD"
                .parse()
                .unwrap(),
            value: U256::from(1_000_000_000_000_000_000u128),
            data: Bytes::new(),
            operation: 0,
            safeTxGas: U256::ZERO,
            baseGas: U256::ZERO,
            gasPrice: U256::ZERO,
            gasToken: Address::ZERO,
            refundReceiver: Address::ZERO,
            nonce: U256::from(7u64),
        };
        let safe_tx_hash = "0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8"
            .parse::<B256>()
            .unwrap();
        let sender = Address::repeat_byte(0x22);
        let sig = Bytes::from(vec![0xAAu8; 65]);
        let body = ProposeBody {
            to: tx.to.to_checksum(None),
            value: tx.value.to_string(),
            data: tx.data.to_string(),
            operation: tx.operation,
            safe_tx_gas: tx.safeTxGas.to_string(),
            base_gas: tx.baseGas.to_string(),
            gas_price: tx.gasPrice.to_string(),
            gas_token: tx.gasToken.to_checksum(None),
            refund_receiver: tx.refundReceiver.to_checksum(None),
            nonce: tx.nonce.to_string(),
            contract_transaction_hash: format!("{safe_tx_hash:#x}"),
            sender: sender.to_checksum(None),
            signature: sig.to_string(),
            origin: Some("Kao".to_string()),
        };
        let v: serde_json::Value = serde_json::to_value(&body).unwrap();
        assert_eq!(v["value"], "1000000000000000000");
        assert_eq!(v["nonce"], "7");
        assert_eq!(v["data"], "0x");
        assert_eq!(
            v["contractTransactionHash"],
            "0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8"
        );
        assert_eq!(v["operation"], 0);
        assert_eq!(v["origin"], "Kao");
        // camelCase relay keys present.
        assert!(v.get("safeTxGas").is_some());
        assert!(v.get("refundReceiver").is_some());
    }

    #[test]
    fn raw_to_safe_tx_reads_all_relay_fields() {
        // A tx authored by another client may populate every relay field;
        // they must round-trip verbatim because the safeTxHash is computed
        // over them — dropping any to zero would make our execute revert.
        let json = r#"{
            "to": "0x000000000000000000000000000000000000dEaD",
            "value": "5",
            "data": "0x",
            "operation": 1,
            "nonce": "2",
            "safeTxGas": "100",
            "baseGas": "50",
            "gasPrice": "7",
            "gasToken": "0x2222222222222222222222222222222222222222",
            "refundReceiver": "0x3333333333333333333333333333333333333333",
            "safeTxHash": "0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8",
            "isExecuted": false,
            "confirmations": []
        }"#;
        let raw: RawMultisigTx = serde_json::from_str(json).unwrap();
        let tx = raw_to_safe_tx(&raw).unwrap();
        assert_eq!(tx.operation, 1);
        assert_eq!(tx.safeTxGas, U256::from(100u64));
        assert_eq!(tx.baseGas, U256::from(50u64));
        assert_eq!(tx.gasPrice, U256::from(7u64));
        assert_eq!(tx.gasToken, Address::repeat_byte(0x22));
        assert_eq!(tx.refundReceiver, Address::repeat_byte(0x33));
        assert_eq!(tx.nonce, U256::from(2u64));
    }

    #[test]
    fn parse_u256_field_handles_null_empty_garbage() {
        assert_eq!(parse_u256_field(&None), U256::ZERO);
        assert_eq!(parse_u256_field(&Some(String::new())), U256::ZERO);
        assert_eq!(
            parse_u256_field(&Some("not-a-number".to_string())),
            U256::ZERO
        );
        assert_eq!(parse_u256_field(&Some("42".to_string())), U256::from(42u64));
    }

    #[test]
    fn parse_addr_field_handles_null_and_valid() {
        assert_eq!(parse_addr_field(&None), Address::ZERO);
        assert_eq!(
            parse_addr_field(&Some("garbage".to_string())),
            Address::ZERO
        );
        let a = parse_addr_field(&Some(
            "0x000000000000000000000000000000000000dEaD".to_string(),
        ));
        assert_eq!(
            a,
            "0x000000000000000000000000000000000000dEaD"
                .parse::<Address>()
                .unwrap()
        );
    }

    #[test]
    fn map_raw_marks_executed_tx() {
        let raw = RawMultisigTx {
            safe_tx_hash: "0x".to_string() + &"cd".repeat(32),
            to: "0x000000000000000000000000000000000000dEaD".to_string(),
            value: "0".to_string(),
            data: None,
            nonce: "1".to_string(),
            operation: 0,
            safe_tx_gas: None,
            base_gas: None,
            gas_price: None,
            gas_token: None,
            refund_receiver: None,
            is_executed: true,
            is_successful: Some(true),
            confirmations_required: Some(2),
            confirmations: vec![],
            submission_date: None,
        };
        // current_nonce ahead of this tx; executed wins regardless.
        let tx = map_raw(raw, 2, 9).unwrap();
        assert_eq!(tx.state, SafeTxState::Executed { success: true });
    }

    #[test]
    fn propose_body_omits_origin_when_none() {
        let body = ProposeBody {
            to: Address::ZERO.to_checksum(None),
            value: "0".to_string(),
            data: "0x".to_string(),
            operation: 0,
            safe_tx_gas: "0".to_string(),
            base_gas: "0".to_string(),
            gas_price: "0".to_string(),
            gas_token: Address::ZERO.to_checksum(None),
            refund_receiver: Address::ZERO.to_checksum(None),
            nonce: "0".to_string(),
            contract_transaction_hash: format!("{:#x}", B256::ZERO),
            sender: Address::ZERO.to_checksum(None),
            signature: "0x".to_string(),
            origin: None,
        };
        let v: serde_json::Value = serde_json::to_value(&body).unwrap();
        assert!(v.get("origin").is_none());
    }

    #[test]
    fn confirm_body_serializes_signature() {
        let v = serde_json::to_value(ConfirmBody {
            signature: "0xabcd".to_string(),
        })
        .unwrap();
        assert_eq!(v["signature"], "0xabcd");
    }

    #[test]
    fn owners_signed_lists_confirmation_owners() {
        let detail = SafeTxDetail {
            safe_tx_hash: B256::ZERO,
            tx: SafeTx {
                to: Address::ZERO,
                value: U256::ZERO,
                data: Bytes::new(),
                operation: 0,
                safeTxGas: U256::ZERO,
                baseGas: U256::ZERO,
                gasPrice: U256::ZERO,
                gasToken: Address::ZERO,
                refundReceiver: Address::ZERO,
                nonce: U256::ZERO,
            },
            state: SafeTxState::AwaitingConfirmations {
                have: 2,
                required: 3,
            },
            confirmations: vec![
                ServiceConfirmation {
                    owner: Address::repeat_byte(0x11),
                    signature: Bytes::new(),
                },
                ServiceConfirmation {
                    owner: Address::repeat_byte(0x22),
                    signature: Bytes::new(),
                },
            ],
            confirmations_required: 3,
        };
        assert_eq!(
            detail.owners_signed(),
            vec![Address::repeat_byte(0x11), Address::repeat_byte(0x22)]
        );
    }

    #[test]
    fn detail_and_confirmation_urls_use_shortname_and_hash() {
        let hash = "0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8"
            .parse::<B256>()
            .unwrap();
        let d = detail_url(DEFAULT_TX_SERVICE_BASE, hash, Chain::Base);
        assert!(d.contains("/tx-service/base/"));
        assert!(d.contains(&format!("{hash:#x}")));
        let c = confirmations_url(DEFAULT_TX_SERVICE_BASE, hash, Chain::Mainnet);
        assert!(c.contains("/tx-service/eth/"));
        assert!(c.ends_with("/confirmations/"));
    }
}
