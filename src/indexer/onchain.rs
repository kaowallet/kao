//! On-chain transaction history reconstruction via `eth_getLogs`.
//!
//! Fallback for when the user has either disabled the indexer
//! (`IndexerProvider::None`) or every configured indexer fails. Walks
//! the most recent ~50k blocks for `Transfer(address,address,...)` logs
//! whose indexed `from`/`to` topics match the owner, enriches each
//! unique tx with a receipt + block timestamp, batches per-contract
//! `symbol()`/`decimals()` reads via Multicall3, and (when the RPC
//! exposes `trace_filter`) folds in native ETH transfers too. Returns
//! `IndexedTx` rows shaped identically to the indexer impls so the
//! activity feed renders without any per-source branching.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use std::time::Duration;

use alloy::eips::BlockId;
use alloy::network::Ethereum;
use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::providers::{Provider, RootProvider};
use alloy::rpc::types::{BlockNumberOrTag, Filter, Log};
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::chain::Chain;
use crate::portfolio::{multicall_pairs, with_rate_limit_retry};

use super::{IndexedTx, TokenTransfer, TxStatus, classify_direction};

/// `keccak256("Transfer(address,address,uint256)")` — shared by ERC-20
/// and ERC-721 (the latter just adds a 4th indexed `tokenId` topic).
const TRANSFER_TOPIC: B256 = B256::new([
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b,
    0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16,
    0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
]);

/// How many blocks back to scan from `latest`. ~7 days on Mainnet at
/// 12 s/block; faster L2s (when we extend coverage) cover proportionally
/// less wall-clock but still surface recent activity.
const WINDOW_BLOCKS: u64 = 50_000;

/// Cap recursion when range-splitting around RPC limits. 50k → 781
/// blocks worst case, which all known public RPCs accept.
const MAX_SPLIT_DEPTH: u32 = 6;

/// Stop splitting once the sub-range is this small — at this point
/// the error isn't a range cap, and we'd rather propagate it than
/// fan out into a 64-call storm.
const MIN_RANGE: u64 = 256;

/// Per-call concurrency for receipt / block-timestamp enrichment.
/// Public RPCs throttle aggressively above ~10 inflight reads; 8 is
/// the sweet spot we use elsewhere.
const ENRICH_BATCH: usize = 8;

/// Public entry point. Issues two `eth_getLogs` calls (sent + received)
/// covering ERC-20 and ERC-721 in one shot, optionally probes
/// `trace_filter` for native ETH, then enriches with per-tx receipts +
/// per-block timestamps + per-contract symbol/decimals. Returns up to
/// `limit` rows newest-first.
pub async fn fetch_onchain_history(
    provider: &RootProvider<Ethereum>,
    owner: Address,
    chain: Chain,
    limit: usize,
) -> Result<Vec<IndexedTx>, String> {
    let latest = provider
        .get_block_number()
        .await
        .map_err(|e| format!("get_block_number: {e}"))?;
    let from_block = latest.saturating_sub(WINDOW_BLOCKS);
    debug!(
        owner = %owner,
        chain = ?chain,
        from_block,
        to_block = latest,
        "onchain history fetch starting",
    );

    let owner_topic = address_to_topic(owner);
    let sent_filter = Filter::new()
        .event_signature(TRANSFER_TOPIC)
        .topic1(owner_topic);
    let recv_filter = Filter::new()
        .event_signature(TRANSFER_TOPIC)
        .topic2(owner_topic);

    // Two parallel chunked fetches. tokio::join lets each fan out
    // independently when the underlying RPC trips a range cap.
    let (sent, recv) = tokio::join!(
        get_logs_chunked(provider, &sent_filter, from_block, latest, 0, "sent"),
        get_logs_chunked(provider, &recv_filter, from_block, latest, 0, "recv"),
    );
    let mut all_logs: Vec<Log> = Vec::new();
    match sent {
        Ok(v) => all_logs.extend(v),
        Err(e) => warn!(error = %e, "onchain sent-logs fetch failed; continuing with received only"),
    }
    match recv {
        Ok(v) => all_logs.extend(v),
        Err(e) => warn!(error = %e, "onchain received-logs fetch failed; continuing with sent only"),
    }

    let mut rows: Vec<IndexedTx> = parse_log_rows(&all_logs, owner, chain);

    // Native ETH via trace_filter — best-effort, cached unsupported per chain.
    if trace_filter_supported(provider, chain, latest).await {
        match fetch_native_traces(provider, owner, chain, from_block, latest).await {
            Ok(traces) => rows.extend(traces),
            Err(e) => {
                // Common case is a stingy trace cap (dRPC: 100 blocks)
                // that even chunked splitting can't satisfy. Mark the
                // chain unsupported so future fetches don't re-probe,
                // and demote the noise to debug.
                debug!(
                    chain = ?chain,
                    error = %e,
                    "trace_filter native-eth disabled for this chain",
                );
                disable_trace_filter(chain).await;
            }
        }
    }

    // Dedupe by (block, tx_hash, log_index) for log rows; trace rows already
    // carry distinct synthetic keys.
    rows.sort_by(|a, b| {
        b.block_number
            .cmp(&a.block_number)
            .then_with(|| b.hash.cmp(&a.hash))
    });
    rows.dedup_by(|a, b| {
        a.block_number == b.block_number && a.hash == b.hash && a.token.is_some() == b.token.is_some() && {
            // Distinguish multiple token transfers within one tx by their contract+token_id.
            let ka = a.token.as_ref().map(|t| (t.contract, t.token_id));
            let kb = b.token.as_ref().map(|t| (t.contract, t.token_id));
            ka == kb
        }
    });
    rows.truncate(limit.max(1));

    enrich_receipts_and_timestamps(provider, &mut rows, owner).await;
    enrich_token_metadata(provider, &mut rows).await;

    rows.sort_by(|a, b| b.block_number.cmp(&a.block_number));
    debug!(rows = rows.len(), "onchain history fetch complete");
    Ok(rows)
}

// ── Logs (ERC-20 + ERC-721) ─────────────────────────────────────────────────

/// Recursively `eth_getLogs` over `[from, to]`, halving the range when
/// the RPC reports a cap error (block-range or result-count limit).
/// Wrapped in `with_rate_limit_retry` so 429s back off.
async fn get_logs_chunked(
    provider: &RootProvider<Ethereum>,
    filter: &Filter,
    from: u64,
    to: u64,
    depth: u32,
    label: &str,
) -> Result<Vec<Log>, String> {
    let scoped = filter
        .clone()
        .from_block(BlockNumberOrTag::Number(from))
        .to_block(BlockNumberOrTag::Number(to));

    let result = with_rate_limit_retry(label, || async {
        provider
            .get_logs(&scoped)
            .await
            .map_err(|e| format!("eth_getLogs: {e}"))
    })
    .await;

    match result {
        Ok(v) => Ok(v),
        Err(e) if depth < MAX_SPLIT_DEPTH && to.saturating_sub(from) >= MIN_RANGE && is_range_cap(&e) => {
            let mid = from + (to - from) / 2;
            debug!(
                label,
                from, to, mid, depth,
                error = %e,
                "range cap hit; splitting",
            );
            // Sequential — bursting parallel sub-ranges to a public RPC
            // tends to multiply 429s rather than land faster.
            let lhs = Box::pin(get_logs_chunked(provider, filter, from, mid, depth + 1, label)).await?;
            let rhs = Box::pin(get_logs_chunked(provider, filter, mid + 1, to, depth + 1, label)).await?;
            let mut out = lhs;
            out.extend(rhs);
            Ok(out)
        }
        Err(e) => Err(e),
    }
}

/// Common error substrings returned by RPC providers when an
/// `eth_getLogs` call exceeds either the block-range or result-count
/// cap. Conservative match — a non-cap error must propagate to avoid
/// fanning out a 64-call storm.
fn is_range_cap(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("query returned more")
        || m.contains("response size")
        || m.contains("more than")
        || m.contains("too many")
        || m.contains("range")
        || m.contains("limit")
        || m.contains("-32005")
        || m.contains("-32602")
}

/// Convert raw logs to `IndexedTx` rows. The receipt enrichment pass
/// fills in `status`, `gas_used`, `gas_price`, and the timestamp later.
fn parse_log_rows(logs: &[Log], owner: Address, chain: Chain) -> Vec<IndexedTx> {
    let mut out = Vec::with_capacity(logs.len());
    for log in logs {
        let topics = log.topics();
        if topics.first() != Some(&TRANSFER_TOPIC) || topics.len() < 3 {
            continue;
        }
        let from = address_from_topic(&topics[1]);
        let to = address_from_topic(&topics[2]);
        let block_number = log.block_number.unwrap_or(0);
        let Some(hash) = log.transaction_hash else { continue };

        let (is_nft, token_id, amount_raw) = if topics.len() >= 4 {
            // ERC-721: tokenId is indexed (topic[3]); data is empty.
            let id = U256::from_be_bytes(topics[3].0);
            (true, Some(id), U256::from(1u8))
        } else if log.data().data.len() >= 32 {
            // ERC-20: amount is the first 32 bytes of the log data.
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&log.data().data[..32]);
            (false, None, U256::from_be_bytes(buf))
        } else {
            continue;
        };

        out.push(IndexedTx {
            hash,
            block_number,
            timestamp: 0, // filled by enrichment
            from,
            to: Some(to),
            value: U256::ZERO,
            gas_used: None,
            gas_price: None,
            // `Transfer` only fires on success; failed txs don't emit it.
            // The receipt pass overwrites this if the receipt disagrees.
            status: TxStatus::Success,
            direction: classify_direction(from, Some(to), owner),
            method: None,
            token: Some(TokenTransfer {
                contract: log.address(),
                symbol: String::new(), // filled by metadata enrichment
                decimals: 18,
                amount_raw,
                is_nft,
                token_id,
            }),
            chain,
        });
    }
    out
}

fn address_to_topic(addr: Address) -> B256 {
    let mut buf = [0u8; 32];
    buf[12..].copy_from_slice(addr.as_slice());
    B256::from(buf)
}

fn address_from_topic(topic: &B256) -> Address {
    let mut buf = [0u8; 20];
    buf.copy_from_slice(&topic.0[12..]);
    Address::from(buf)
}

// ── Receipt + block enrichment ──────────────────────────────────────────────

async fn enrich_receipts_and_timestamps(
    provider: &RootProvider<Ethereum>,
    rows: &mut [IndexedTx],
    owner: Address,
) {
    // Group by tx hash for receipts (status / gas) and by block for
    // timestamps. Receipts also carry the outer-tx `from`/`to`, but
    // `Transfer` log endpoints are already correct for token rows.
    let unique_hashes: Vec<B256> = {
        let mut seen: HashSet<B256> = HashSet::new();
        rows.iter()
            .filter(|r| r.token.is_some()) // trace rows already have status/gas
            .map(|r| r.hash)
            .filter(|h| seen.insert(*h))
            .collect()
    };
    let unique_blocks: Vec<u64> = {
        let mut seen: HashSet<u64> = HashSet::new();
        rows.iter()
            .map(|r| r.block_number)
            .filter(|b| *b > 0 && seen.insert(*b))
            .collect()
    };

    let receipts = fetch_receipts(provider, &unique_hashes).await;
    let timestamps = fetch_timestamps(provider, &unique_blocks).await;

    for r in rows.iter_mut() {
        if let Some(ts) = timestamps.get(&r.block_number).copied() {
            r.timestamp = ts;
        }
        if r.token.is_none() {
            // Native trace row — skip receipt overwrite.
            continue;
        }
        if let Some(rc) = receipts.get(&r.hash) {
            r.status = rc.status;
            r.gas_used = rc.gas_used;
            r.gas_price = rc.gas_price;
            // Outer-tx from/to (the wallet that originated the call) is
            // useful for the details modal's "Method" field; the log
            // endpoints stay authoritative for direction classification.
            if let Some(outer_from) = rc.from {
                // Re-classify: a Transfer log to `owner` from a router call
                // the owner originated should still read "Out" via the
                // outer tx. Only flip when the log endpoints don't already
                // indicate involvement — i.e. when the existing endpoints
                // both equal owner-related addresses, leave them alone.
                let already = r.from == owner || r.to == Some(owner);
                if !already && (outer_from == owner || rc.to == Some(owner)) {
                    r.direction = classify_direction(outer_from, rc.to, owner);
                }
            }
        }
    }
}

struct ReceiptInfo {
    status: TxStatus,
    gas_used: Option<u64>,
    gas_price: Option<u128>,
    from: Option<Address>,
    to: Option<Address>,
}

async fn fetch_receipts(
    provider: &RootProvider<Ethereum>,
    hashes: &[B256],
) -> HashMap<B256, ReceiptInfo> {
    let mut out: HashMap<B256, ReceiptInfo> = HashMap::with_capacity(hashes.len());
    for chunk in hashes.chunks(ENRICH_BATCH) {
        let futs = chunk.iter().map(|h| {
            let h = *h;
            async move {
                let r = provider.get_transaction_receipt(h).await;
                (h, r)
            }
        });
        let results = futures::future::join_all(futs).await;
        for (hash, res) in results {
            match res {
                Ok(Some(rc)) => {
                    let status = if rc.status() {
                        TxStatus::Success
                    } else {
                        TxStatus::Failure
                    };
                    out.insert(
                        hash,
                        ReceiptInfo {
                            status,
                            gas_used: Some(rc.gas_used),
                            gas_price: Some(rc.effective_gas_price),
                            from: Some(rc.from),
                            to: rc.to,
                        },
                    );
                }
                Ok(None) => {
                    // Pending / dropped — leave defaults.
                }
                Err(e) => {
                    warn!(hash = %hash, error = %e, "get_transaction_receipt failed");
                }
            }
        }
        // Tiny inter-batch pause smooths over public-RPC burst limits.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    out
}

async fn fetch_timestamps(
    provider: &RootProvider<Ethereum>,
    blocks: &[u64],
) -> HashMap<u64, u64> {
    let mut out: HashMap<u64, u64> = HashMap::with_capacity(blocks.len());
    for chunk in blocks.chunks(ENRICH_BATCH) {
        let futs = chunk.iter().map(|b| {
            let b = *b;
            async move {
                let r = provider
                    .get_block(BlockId::Number(BlockNumberOrTag::Number(b)))
                    .await;
                (b, r)
            }
        });
        let results = futures::future::join_all(futs).await;
        for (block, res) in results {
            match res {
                Ok(Some(blk)) => {
                    out.insert(block, blk.header.timestamp);
                }
                Ok(None) => {}
                Err(e) => warn!(block, error = %e, "get_block failed"),
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    out
}

// ── Token metadata via Multicall3 ───────────────────────────────────────────

const SYMBOL_SELECTOR: [u8; 4] = [0x95, 0xd8, 0x9b, 0x41];
const DECIMALS_SELECTOR: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];

async fn enrich_token_metadata(
    provider: &RootProvider<Ethereum>,
    rows: &mut [IndexedTx],
) {
    let unique_contracts: Vec<Address> = {
        let mut seen: HashSet<Address> = HashSet::new();
        rows.iter()
            .filter_map(|r| r.token.as_ref().map(|t| t.contract))
            .filter(|c| seen.insert(*c))
            .collect()
    };
    if unique_contracts.is_empty() {
        return;
    }

    // Two subcalls per contract: symbol() then decimals(). Issued in one
    // Multicall3 round trip via the portfolio module's helper.
    let mut calls: Vec<(Address, Bytes)> = Vec::with_capacity(unique_contracts.len() * 2);
    for c in &unique_contracts {
        calls.push((*c, Bytes::from_static(&SYMBOL_SELECTOR)));
        calls.push((*c, Bytes::from_static(&DECIMALS_SELECTOR)));
    }

    let results = match multicall_pairs(provider, BlockId::latest(), "onchain history metadata", calls).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "token metadata multicall failed; rendering with truncated contracts");
            return;
        }
    };

    let mut meta: HashMap<Address, (String, u8)> = HashMap::with_capacity(unique_contracts.len());
    for (i, contract) in unique_contracts.iter().enumerate() {
        let sym_idx = i * 2;
        let dec_idx = i * 2 + 1;
        let symbol = results
            .get(sym_idx)
            .map(|(ok, data)| if *ok { decode_symbol(data) } else { String::new() })
            .unwrap_or_default();
        let decimals = results
            .get(dec_idx)
            .and_then(|(ok, data)| if *ok { decode_decimals(data) } else { None })
            .unwrap_or(18);
        meta.insert(*contract, (symbol, decimals));
    }

    for r in rows.iter_mut() {
        let Some(tok) = r.token.as_mut() else { continue };
        if let Some((sym, dec)) = meta.get(&tok.contract) {
            if !sym.is_empty() {
                tok.symbol = sym.clone();
            }
            // ERC-721 doesn't really use decimals; leave the default 18 → 0
            // would mis-render any future ERC-20 with 0 decimals. Trust the
            // contract's reported value either way.
            tok.decimals = *dec;
        }
    }
}

/// Decode a `string` ABI return. ERC-20s like MKR return `bytes32`
/// instead — fall back to a UTF-8-trimmed bytes32 read for those.
fn decode_symbol(data: &Bytes) -> String {
    if data.len() < 32 {
        return String::new();
    }
    // ABI string: offset (32 bytes) + length (32 bytes) + payload.
    if data.len() >= 64 {
        let offset = U256::from_be_slice(&data[..32]);
        if offset == U256::from(32u8) && data.len() >= 96 {
            let len = U256::from_be_slice(&data[32..64]).saturating_to::<usize>();
            let end = 64usize.saturating_add(len);
            if len > 0 && len <= 256 && end <= data.len()
                && let Ok(s) = std::str::from_utf8(&data[64..end])
            {
                let s = s.trim_end_matches('\0').trim();
                if !s.is_empty() {
                    return s.to_string();
                }
            }
        }
    }
    // bytes32 fallback (MKR et al.): trim trailing nulls.
    let end = data[..32].iter().position(|&b| b == 0).unwrap_or(32);
    if let Ok(s) = std::str::from_utf8(&data[..end]) {
        let s = s.trim();
        if s.chars().all(|c| !c.is_control()) && !s.is_empty() {
            return s.to_string();
        }
    }
    String::new()
}

fn decode_decimals(data: &Bytes) -> Option<u8> {
    if data.len() < 32 {
        return None;
    }
    // uint8 right-aligned in a 32-byte word.
    Some(data[31])
}

// ── trace_filter (native ETH) ───────────────────────────────────────────────

/// Per-chain `trace_filter` availability cache. `false` means the RPC
/// reported no such method (or any other error) — we never re-probe for
/// the process lifetime, so the indexer-free path stays cheap.
static TRACE_AVAILABLE: OnceLock<RwLock<HashMap<Chain, bool>>> = OnceLock::new();

async fn trace_filter_supported(
    provider: &RootProvider<Ethereum>,
    chain: Chain,
    latest: u64,
) -> bool {
    let cache = TRACE_AVAILABLE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Some(v) = cache.read().await.get(&chain).copied() {
        return v;
    }
    // Issue a trivial probe: latest..latest, no addresses. A supported
    // node returns `[]`; an unsupported one returns -32601.
    let params = json!([{
        "fromBlock": format!("0x{:x}", latest),
        "toBlock": format!("0x{:x}", latest),
    }]);
    let result: Result<Value, _> = provider
        .client()
        .request("trace_filter", params)
        .await;
    let supported = match result {
        Ok(_) => true,
        Err(e) => {
            debug!(chain = ?chain, error = %e, "trace_filter probe: unsupported");
            false
        }
    };
    cache.write().await.insert(chain, supported);
    supported
}

/// Set the per-chain trace_filter verdict to "unsupported" for the
/// remainder of the process. Called when a fetch errors with a range
/// cap so tight that even chunked splitting can't satisfy it (e.g.
/// dRPC's 100-block trace cap), so the next history refresh skips
/// trace_filter outright instead of warning every time.
async fn disable_trace_filter(chain: Chain) {
    let cache = TRACE_AVAILABLE.get_or_init(|| RwLock::new(HashMap::new()));
    cache.write().await.insert(chain, false);
}

async fn fetch_native_traces(
    provider: &RootProvider<Ethereum>,
    owner: Address,
    chain: Chain,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<IndexedTx>, String> {
    let from_str = format!("{owner:#x}");
    let (sent, recv) = tokio::join!(
        trace_filter_chunked(provider, &from_str, true, from_block, to_block, 0),
        trace_filter_chunked(provider, &from_str, false, from_block, to_block, 0),
    );
    let mut out: Vec<IndexedTx> = Vec::new();
    // Either side erroring is fatal — caller disables trace_filter on
    // this chain so we don't keep retrying. The Vec we'd return without
    // both sides isn't worth having (asymmetric coverage).
    let sent_v = sent?;
    let recv_v = recv?;
    for v in [sent_v, recv_v] {
        for t in v {
            if let Some(row) = trace_to_indexed(&t, owner, chain) {
                out.push(row);
            }
        }
    }
    // Dedupe on (tx_hash, value, from, to) — a single trace from the
    // sent-side call may also appear in the recv-side fetch.
    let mut seen: HashSet<(B256, U256, Address, Option<Address>)> = HashSet::new();
    out.retain(|r| seen.insert((r.hash, r.value, r.from, r.to)));
    Ok(out)
}

/// Recursive `trace_filter` over `[from, to]`, halving the range when
/// the RPC reports a cap error. Mirrors `get_logs_chunked`. The initial
/// 50k window won't survive providers with very tight caps (dRPC: 100
/// blocks), and that's the signal `fetch_native_traces`'s caller uses
/// to disable trace_filter for the chain — see `disable_trace_filter`.
async fn trace_filter_chunked(
    provider: &RootProvider<Ethereum>,
    addr_hex: &str,
    is_sender_side: bool,
    from: u64,
    to: u64,
    depth: u32,
) -> Result<Vec<Value>, String> {
    let key = if is_sender_side { "fromAddress" } else { "toAddress" };
    let params = json!([{
        "fromBlock": format!("0x{:x}", from),
        "toBlock": format!("0x{:x}", to),
        key: [addr_hex],
    }]);
    let result: Result<Vec<Value>, _> = provider
        .client()
        .request("trace_filter", params)
        .await;
    match result {
        Ok(v) => Ok(v),
        Err(e) => {
            let msg = e.to_string();
            if depth < MAX_SPLIT_DEPTH
                && to.saturating_sub(from) >= MIN_RANGE
                && is_range_cap(&msg)
            {
                let mid = from + (to - from) / 2;
                debug!(
                    side = if is_sender_side { "sent" } else { "recv" },
                    from, to, mid, depth,
                    "trace_filter range cap; splitting",
                );
                let lhs = Box::pin(trace_filter_chunked(
                    provider, addr_hex, is_sender_side, from, mid, depth + 1,
                ))
                .await?;
                let rhs = Box::pin(trace_filter_chunked(
                    provider, addr_hex, is_sender_side, mid + 1, to, depth + 1,
                ))
                .await?;
                let mut out = lhs;
                out.extend(rhs);
                Ok(out)
            } else {
                Err(format!("trace_filter: {msg}"))
            }
        }
    }
}

fn trace_to_indexed(t: &Value, owner: Address, chain: Chain) -> Option<IndexedTx> {
    let action = t.get("action")?;
    // Only call traces with non-zero value count as native ETH transfers.
    let call_type = action.get("callType").and_then(|v| v.as_str()).unwrap_or("");
    if call_type.is_empty() {
        return None; // skip create/suicide for now
    }
    let from = parse_addr(action.get("from")?)?;
    let to = parse_addr(action.get("to")?)?;
    let value = parse_u256(action.get("value")?)?;
    if value.is_zero() {
        return None;
    }
    // Skip failed traces — `error` field is present on revert.
    if t.get("error").and_then(|v| v.as_str()).is_some() {
        return None;
    }
    let hash = t
        .get("transactionHash")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<B256>().ok())?;
    let block_number = t
        .get("blockNumber")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    Some(IndexedTx {
        hash,
        block_number,
        timestamp: 0, // enrichment fills
        from,
        to: Some(to),
        value,
        gas_used: None,
        gas_price: None,
        status: TxStatus::Success,
        direction: classify_direction(from, Some(to), owner),
        method: Some(call_type.to_string()),
        token: None,
        chain,
    })
}

fn parse_addr(v: &Value) -> Option<Address> {
    v.as_str().and_then(|s| s.parse::<Address>().ok())
}

fn parse_u256(v: &Value) -> Option<U256> {
    let s = v.as_str()?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    U256::from_str_radix(s, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{LogData, b256};

    fn mk_log(
        contract: Address,
        topics: Vec<B256>,
        data: Vec<u8>,
        block: u64,
        tx: B256,
        log_index: u64,
    ) -> Log {
        Log {
            inner: alloy::primitives::Log {
                address: contract,
                data: LogData::new_unchecked(topics, data.into()),
            },
            block_hash: None,
            block_number: Some(block),
            block_timestamp: None,
            transaction_hash: Some(tx),
            transaction_index: None,
            log_index: Some(log_index),
            removed: false,
        }
    }

    fn owner() -> Address {
        "0xd8da6bf26964af9d7eed9e03e53415d37aa96045".parse().unwrap()
    }

    fn other() -> Address {
        "0x000000000000000000000000000000000000beef".parse().unwrap()
    }

    #[test]
    fn address_topic_round_trip() {
        let a = owner();
        let t = address_to_topic(a);
        assert_eq!(&t.0[..12], &[0u8; 12]);
        assert_eq!(address_from_topic(&t), a);
    }

    #[test]
    fn parse_log_rows_classifies_erc20_and_erc721() {
        let usdc: Address = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
            .parse()
            .unwrap();
        let nft: Address = "0x0000000000000000000000000000000000001234"
            .parse()
            .unwrap();
        let amount: U256 = U256::from(5_000_000u64);
        let mut amount_bytes = [0u8; 32];
        amount_bytes[24..].copy_from_slice(&amount.to::<u64>().to_be_bytes());

        let erc20 = mk_log(
            usdc,
            vec![
                TRANSFER_TOPIC,
                address_to_topic(other()),
                address_to_topic(owner()),
            ],
            amount_bytes.to_vec(),
            18_000_000,
            b256!("0x1111111111111111111111111111111111111111111111111111111111111111"),
            0,
        );
        let token_id = U256::from(42u64);
        let erc721 = mk_log(
            nft,
            vec![
                TRANSFER_TOPIC,
                address_to_topic(owner()),
                address_to_topic(other()),
                B256::from(token_id.to_be_bytes::<32>()),
            ],
            Vec::new(),
            18_000_001,
            b256!("0x2222222222222222222222222222222222222222222222222222222222222222"),
            1,
        );

        let rows = parse_log_rows(&[erc20, erc721], owner(), Chain::Mainnet);
        assert_eq!(rows.len(), 2);

        let erc20_row = rows.iter().find(|r| r.block_number == 18_000_000).unwrap();
        let tok = erc20_row.token.as_ref().unwrap();
        assert!(!tok.is_nft);
        assert!(tok.token_id.is_none());
        assert_eq!(tok.amount_raw, amount);

        let nft_row = rows.iter().find(|r| r.block_number == 18_000_001).unwrap();
        let tok = nft_row.token.as_ref().unwrap();
        assert!(tok.is_nft);
        assert_eq!(tok.token_id, Some(token_id));
        assert_eq!(tok.amount_raw, U256::from(1u8));
    }

    #[test]
    fn is_range_cap_matches_known_provider_strings() {
        assert!(is_range_cap("query returned more than 10000 results"));
        assert!(is_range_cap("Log response size exceeded"));
        assert!(is_range_cap("requested too many blocks"));
        assert!(is_range_cap("range too large"));
        assert!(is_range_cap("eth_getLogs is limited to a 2k block range"));
        assert!(is_range_cap("-32005 limit exceeded"));
        assert!(!is_range_cap("connection refused"));
        assert!(!is_range_cap("invalid params"));
    }

    #[test]
    fn decode_symbol_handles_string_and_bytes32() {
        // ABI `string` returning "USDC".
        let mut data = vec![0u8; 96];
        // offset = 32
        data[31] = 32;
        // length = 4
        data[63] = 4;
        // payload "USDC" (left-aligned)
        data[64..68].copy_from_slice(b"USDC");
        assert_eq!(decode_symbol(&Bytes::from(data)), "USDC");

        // bytes32 form ("MKR\0...") used by some legacy ERC-20s.
        let mut bytes32 = [0u8; 32];
        bytes32[..3].copy_from_slice(b"MKR");
        assert_eq!(decode_symbol(&Bytes::from(bytes32.to_vec())), "MKR");

        // Empty / short
        assert_eq!(decode_symbol(&Bytes::new()), "");
    }

    #[test]
    fn decode_decimals_reads_last_byte() {
        let mut data = vec![0u8; 32];
        data[31] = 6;
        assert_eq!(decode_decimals(&Bytes::from(data)), Some(6));
        assert_eq!(decode_decimals(&Bytes::new()), None);
    }
}
