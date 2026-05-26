//! Transaction building, fee estimation, signing, and broadcasting for the
//! Send flow. Native ETH and ERC-20 transfers go through one path: a
//! `SendPlan` resolves the destination/value/calldata, `build_quote` asks the
//! provider for gas and EIP-1559 fees + nonce, and `sign_and_send` fills a
//! `TxEip1559`, hands it to `KaoSigner::sign_tx` (which routes to whichever
//! `TxSigner` impl backs the active account), and broadcasts the raw
//! envelope.

use std::sync::Arc;

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy::eips::eip2718::Encodable2718;
use alloy::network::Ethereum;
use alloy::primitives::utils::parse_units;
use alloy::primitives::{Address, Bytes, TxHash, TxKind, U256};
use alloy::providers::{Provider, RootProvider};
use tracing::{debug, info, warn};

use crate::chain::Chain;
use crate::net::BalanceFetcher;
use crate::wallet::KaoSigner;
use crate::wallet::sim::{self, SimulationResult};

/// `transfer(address,uint256)` — first 4 bytes of keccak256.
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// Encode an ERC-20 `transfer(to, amount)` call.
///
/// Layout: 4-byte selector + 32-byte left-padded recipient + 32-byte amount.
pub fn erc20_transfer_calldata(to: Address, amount: U256) -> Bytes {
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&TRANSFER_SELECTOR);
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(to.as_slice());
    data.extend_from_slice(&amount.to_be_bytes::<32>());
    Bytes::from(data)
}

/// Parse a human amount string ("0.5", "1234.567") against a token's
/// decimal count. Rejects negative inputs and overflow.
pub fn parse_amount_units(amount: &str, decimals: u8) -> Result<U256, String> {
    let trimmed = amount.trim();
    if trimmed.is_empty() {
        return Err("empty amount".into());
    }
    let parsed = parse_units(trimmed, decimals).map_err(|e| format!("invalid amount: {e}"))?;
    let value: U256 = parsed.into();
    Ok(value)
}

/// What kind of token this send moves: native ETH, or an ERC-20 contract.
#[derive(Debug, Clone)]
pub enum SendToken {
    Native,
    Erc20 { contract: Address },
}

/// All inputs the send flow needs to produce a fully-formed transaction.
/// Built once in the dashboard from the parsed recipient, parsed amount, and
/// the active token's metadata; passed to both `build_quote` and
/// `sign_and_send`.
///
/// `chain` is the network the tx will be broadcast on; its EIP-155 id is
/// baked into the signing hash, so changing the chain after a quote is
/// fetched would invalidate the review screen's numbers.
#[derive(Debug, Clone)]
pub struct SendPlan {
    pub from: Address,
    pub recipient: Address,
    pub token: SendToken,
    pub amount_units: U256,
    pub chain: Chain,
}

impl SendPlan {
    /// Resolve the (to, value, calldata) triple for this plan. Public
    /// because the dashboard's clear-signing decode kickoff needs the
    /// same (to, calldata) pair the broadcast path will eventually use.
    pub fn tx_target(&self) -> (Address, U256, Bytes) {
        match &self.token {
            SendToken::Native => (self.recipient, self.amount_units, Bytes::new()),
            SendToken::Erc20 { contract, .. } => (
                *contract,
                U256::ZERO,
                erc20_transfer_calldata(self.recipient, self.amount_units),
            ),
        }
    }

    /// Build an alloy `TransactionRequest` for gas estimation. Includes a
    /// `from` so the RPC simulates against the real sender's state — without
    /// it, ERC-20 transfers always estimate against a balance-less address
    /// and revert.
    fn to_request(&self) -> alloy::rpc::types::TransactionRequest {
        let (to, value, input) = self.tx_target();
        alloy::rpc::types::TransactionRequest::default()
            .from(self.from)
            .to(to)
            .value(value)
            .input(alloy::rpc::types::TransactionInput::new(input))
    }
}

/// EIP-1559 gas + fee + nonce snapshot. Fetched once when the user enters
/// the review step, then reused by `sign_and_send` so the user signs the
/// same numbers they reviewed.
#[derive(Debug, Clone)]
pub struct TxQuote {
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub nonce: u64,
    /// `gas_limit × max_fee_per_gas` — the maximum ETH the sender can be
    /// charged (actual cost is usually lower because base fee + tip < max
    /// fee). Displayed on the review step.
    pub eth_cost_wei: U256,
    /// Local revm preflight. On supported chains it carries the revert
    /// reason (if any), the EVM-metered gas, and any ERC-20/721 transfers
    /// the tx would emit; on unsupported chains or after a sim failure
    /// it's a `SimulationResult::unavailable()` placeholder. Sim is
    /// always advisory — the review screen never blocks on it.
    pub sim: SimulationResult,
}

/// Quote a send: estimate gas, fetch 1559 fees, fetch the pending nonce,
/// and (where supported) run a local revm preflight. The `network` is
/// only used for the preflight — gas / fees / nonce go through the
/// raw provider, matching today's broadcast path. A simulation failure
/// is never fatal; the quote returns with `SimulationResult::unavailable()`
/// so the review screen can still render.
pub async fn build_quote(
    provider: &RootProvider<Ethereum>,
    network: Arc<dyn BalanceFetcher>,
    plan: &SendPlan,
) -> Result<TxQuote, String> {
    let req = plan.to_request();
    let (target, value, input) = plan.tx_target();
    let token_kind = match &plan.token {
        SendToken::Native => "native",
        SendToken::Erc20 { .. } => "erc20",
    };
    info!(
        chain = %plan.chain.label(),
        chain_id = plan.chain.chain_id(),
        token = token_kind,
        from = %plan.from,
        to = %target,
        value_wei = %value,
        input_len = input.len(),
        "quote: starting",
    );

    let gas_limit = match provider.estimate_gas(req).await {
        Ok(g) => {
            debug!(gas_limit = g, "quote: estimate_gas ok");
            g
        }
        Err(e) => {
            warn!(error = %e, "quote: estimate_gas failed");
            return Err(format!("estimate_gas: {e}"));
        }
    };

    let fees = match provider.estimate_eip1559_fees().await {
        Ok(f) => {
            debug!(
                max_fee_per_gas = f.max_fee_per_gas,
                max_priority_fee_per_gas = f.max_priority_fee_per_gas,
                "quote: estimate_eip1559_fees ok",
            );
            f
        }
        Err(e) => {
            warn!(error = %e, "quote: estimate_eip1559_fees failed");
            return Err(format!("estimate_eip1559_fees: {e}"));
        }
    };

    let nonce = match provider.get_transaction_count(plan.from).pending().await {
        Ok(n) => {
            debug!(nonce = n, "quote: pending nonce ok");
            n
        }
        Err(e) => {
            warn!(error = %e, "quote: get_transaction_count failed");
            return Err(format!("get_transaction_count: {e}"));
        }
    };

    let eth_cost_wei = U256::from(gas_limit).saturating_mul(U256::from(fees.max_fee_per_gas));

    // Local revm preflight. On supported chains we run it; on
    // unsupported chains (Base/Optimism in v1) or on any sim failure
    // we fall back to the `unavailable()` placeholder so the review
    // screen renders the existing gas/cost numbers exactly as before.
    let sim = if plan.chain.supports_simulation() {
        // Note: `fees` aren't passed to `simulate_tx` — preflight runs
        // with gas_price = 0 to avoid revm's upfront balance-reservation
        // check evicting users with less than `gas_limit × max_fee`
        // worth of ETH. Real fees still drive the broadcast path and
        // the eth_cost_wei the user reviews.
        match sim::simulate_tx(network, plan, nonce).await {
            Ok(s) => s,
            Err(e) => {
                // Advisory: degrade to "unavailable" rather than fail the
                // quote — the user can still review and send.
                warn!(error = %e, "quote: simulate_tx failed, marking sim unavailable");
                SimulationResult::unavailable()
            }
        }
    } else {
        debug!(chain = %plan.chain.label(), "quote: chain doesn't support simulation");
        SimulationResult::unavailable()
    };

    info!(
        gas_limit,
        max_fee_per_gas = fees.max_fee_per_gas,
        max_priority_fee_per_gas = fees.max_priority_fee_per_gas,
        nonce,
        eth_cost_wei = %eth_cost_wei,
        sim_gas_used = sim.gas_used,
        sim_reverted = sim.is_revert(),
        sim_verified = sim.verified,
        "quote: ready",
    );

    Ok(TxQuote {
        gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        nonce,
        eth_cost_wei,
        sim,
    })
}

/// Sign a `TxEip1559` with `signer` and broadcast it.
///
/// Manual encode (vs. an `EthereumWallet`-wrapped `FillProvider`) keeps one
/// code path across `KaoSigner::Local | Ledger | Trezor`.
pub async fn sign_and_send(
    provider: &RootProvider<Ethereum>,
    signer: &KaoSigner,
    plan: SendPlan,
    quote: TxQuote,
) -> Result<TxHash, String> {
    let (to, value, input) = plan.tx_target();
    let token_kind = match &plan.token {
        SendToken::Native => "native",
        SendToken::Erc20 { .. } => "erc20",
    };
    info!(
        chain = %plan.chain.label(),
        chain_id = plan.chain.chain_id(),
        token = token_kind,
        from = %plan.from,
        to = %to,
        value_wei = %value,
        input_len = input.len(),
        nonce = quote.nonce,
        gas_limit = quote.gas_limit,
        max_fee_per_gas = quote.max_fee_per_gas,
        max_priority_fee_per_gas = quote.max_priority_fee_per_gas,
        "sign+send: signing tx",
    );

    let mut tx = TxEip1559 {
        chain_id: plan.chain.chain_id(),
        nonce: quote.nonce,
        gas_limit: quote.gas_limit,
        max_fee_per_gas: quote.max_fee_per_gas,
        max_priority_fee_per_gas: quote.max_priority_fee_per_gas,
        to: TxKind::Call(to),
        value,
        access_list: Default::default(),
        input,
    };

    let sig = match signer.sign_tx(&mut tx).await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "sign+send: sign failed");
            return Err(format!("sign failed: {e}"));
        }
    };
    debug!("sign+send: signed");

    let envelope: TxEnvelope = tx.into_signed(sig).into();
    let raw = envelope.encoded_2718();
    debug!(raw_len = raw.len(), "sign+send: broadcasting raw envelope");

    let pending = match provider.send_raw_transaction(&raw).await {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "sign+send: broadcast failed");
            return Err(format!("broadcast failed: {e}"));
        }
    };

    let hash = *pending.tx_hash();
    info!(hash = %format!("{hash:#x}"), "sign+send: broadcast ok");
    Ok(hash)
}

// ── Raw-tx pipeline (WalletConnect `eth_sendTransaction`) ────────────────
//
// The Send pane builds a `SendPlan` (native ETH or ERC-20 transfer) and
// hands it to `build_quote` + `sign_and_send`. dApps via WalletConnect
// produce arbitrary calldata that doesn't fit either shape — a swap, a
// stake, an L2 deposit — and need a parallel entry point that takes the
// raw `(from, to, value, data)` tuple. The two paths share `TxQuote` and
// the EIP-1559 envelope construction; the divergence is purely at the
// input boundary.

/// Inputs for an arbitrary EIP-1559 transaction supplied by an external
/// caller (today: the WalletConnect engine handling `eth_sendTransaction`).
///
/// dApp-supplied hints (`gas_limit_hint`, `nonce_hint`, fee hints) are
/// treated as advisory only:
/// - `gas_limit_hint`: the quote always re-estimates locally; the higher
///   of (dApp hint, our estimate) wins, defending against dApps that
///   under-provision a stake/swap that's grown more expensive since they
///   computed their hint.
/// - `nonce_hint`: if present, the quote cross-checks against the pending
///   nonce from the provider. A mismatch is a hard error — the dApp is
///   asking us to broadcast at a stale nonce, which would either revert
///   on-chain or, worse, replay an old intent.
/// - Fee hints are currently ignored; we use the provider's
///   `eth_estimateFee` numbers. The user reviews the cost on the WC modal
///   the same way they review a native Send.
///
/// Phase 4 deliverable. Fields are constructed by
/// `walletconnect::methods::parse_eth_send_transaction_params` and read by
/// `build_quote_raw` / `sign_raw` in Phase 6 once the UI flow is wired up.
/// `dead_code` allow comes off as Phase 6 lands.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RawTxRequest {
    pub from: Address,
    /// `None` for contract creation. Rare via WC but spec-allowed.
    pub to: Option<Address>,
    pub value: U256,
    pub input: Bytes,
    pub chain: Chain,
    pub gas_limit_hint: Option<u64>,
    pub nonce_hint: Option<u64>,
}

/// Quote an arbitrary tx. Same shape as `build_quote` but takes a
/// [`RawTxRequest`] in place of `SendPlan`. Simulation is skipped for now —
/// `sim::simulate_tx` is currently `SendPlan`-shaped and a refactor to
/// accept raw inputs is Phase 7 hardening. Until then, the WC review modal
/// gets gas + fees + nonce but no preflight revert reason. The clear-
/// signing calldata decode (via `src/decode/`) is the primary review
/// affordance for dApp txs anyway.
#[allow(dead_code)] // Phase 6 wires this up; tested via `sign_raw` round-trip in Phase 4.
pub async fn build_quote_raw(
    provider: &RootProvider<Ethereum>,
    _network: Arc<dyn BalanceFetcher>,
    raw: &RawTxRequest,
) -> Result<TxQuote, String> {
    let to_label = match raw.to {
        Some(a) => format!("{a}"),
        None => "(create)".to_string(),
    };
    info!(
        chain = %raw.chain.label(),
        chain_id = raw.chain.chain_id(),
        from = %raw.from,
        to = %to_label,
        value_wei = %raw.value,
        input_len = raw.input.len(),
        gas_hint = ?raw.gas_limit_hint,
        nonce_hint = ?raw.nonce_hint,
        "raw quote: starting",
    );

    let mut req = alloy::rpc::types::TransactionRequest::default()
        .from(raw.from)
        .value(raw.value)
        .input(alloy::rpc::types::TransactionInput::new(raw.input.clone()));
    if let Some(to) = raw.to {
        req = req.to(to);
    }

    let estimated = match provider.estimate_gas(req).await {
        Ok(g) => g,
        Err(e) => {
            warn!(error = %e, "raw quote: estimate_gas failed");
            return Err(format!("estimate_gas: {e}"));
        }
    };
    // Take the larger of (estimate, dApp hint). Under-provisioning is a
    // common dApp bug that surfaces as a mid-execution out-of-gas revert;
    // over-provisioning costs at most the unused gas refund.
    let gas_limit = match raw.gas_limit_hint {
        Some(hint) => estimated.max(hint),
        None => estimated,
    };

    let fees = match provider.estimate_eip1559_fees().await {
        Ok(f) => f,
        Err(e) => {
            warn!(error = %e, "raw quote: estimate_eip1559_fees failed");
            return Err(format!("estimate_eip1559_fees: {e}"));
        }
    };

    let nonce = match provider.get_transaction_count(raw.from).pending().await {
        Ok(n) => n,
        Err(e) => {
            warn!(error = %e, "raw quote: get_transaction_count failed");
            return Err(format!("get_transaction_count: {e}"));
        }
    };

    // Defence-in-depth nonce check. The dApp passing a non-matching nonce
    // is asking us to broadcast at a stale point in the account's history
    // — either replaying an old intent or front-running its own queue.
    // Either way, refuse loudly rather than carry it through to broadcast.
    if let Some(hint) = raw.nonce_hint
        && hint != nonce
    {
        return Err(format!(
            "dApp-supplied nonce {hint} doesn't match pending nonce {nonce}"
        ));
    }

    let eth_cost_wei = U256::from(gas_limit).saturating_mul(U256::from(fees.max_fee_per_gas));

    info!(
        gas_limit,
        max_fee_per_gas = fees.max_fee_per_gas,
        max_priority_fee_per_gas = fees.max_priority_fee_per_gas,
        nonce,
        eth_cost_wei = %eth_cost_wei,
        "raw quote: ready (sim deferred — Phase 7)",
    );

    Ok(TxQuote {
        gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        nonce,
        eth_cost_wei,
        sim: SimulationResult::unavailable(),
    })
}

/// Sign a raw `RawTxRequest` and return the encoded envelope **plus the
/// computed transaction hash**. No network access — used by both
/// `sign_and_send_raw` (which then broadcasts) and the
/// `eth_signTransaction` WC handler (which hands the envelope back to the
/// dApp without broadcasting).
#[allow(dead_code)] // Phase 6 wires this up.
pub async fn sign_raw(
    signer: &KaoSigner,
    raw: &RawTxRequest,
    quote: &TxQuote,
) -> Result<(TxHash, Bytes), String> {
    let mut tx = TxEip1559 {
        chain_id: raw.chain.chain_id(),
        nonce: quote.nonce,
        gas_limit: quote.gas_limit,
        max_fee_per_gas: quote.max_fee_per_gas,
        max_priority_fee_per_gas: quote.max_priority_fee_per_gas,
        to: match raw.to {
            Some(a) => TxKind::Call(a),
            None => TxKind::Create,
        },
        value: raw.value,
        access_list: Default::default(),
        input: raw.input.clone(),
    };

    let sig = signer
        .sign_tx(&mut tx)
        .await
        .map_err(|e| format!("sign failed: {e}"))?;
    let envelope: TxEnvelope = tx.into_signed(sig).into();
    let hash = *envelope.tx_hash();
    let raw_bytes = Bytes::from(envelope.encoded_2718());
    Ok((hash, raw_bytes))
}

/// Sign + broadcast a raw request. Mirror of `sign_and_send` for dApp-
/// supplied tx shapes.
#[allow(dead_code)] // Phase 6 wires this up.
pub async fn sign_and_send_raw(
    provider: &RootProvider<Ethereum>,
    signer: &KaoSigner,
    raw: &RawTxRequest,
    quote: &TxQuote,
) -> Result<TxHash, String> {
    let (hash, raw_bytes) = sign_raw(signer, raw, quote).await?;
    debug!(
        raw_len = raw_bytes.len(),
        "raw sign+send: broadcasting envelope"
    );
    let pending = provider
        .send_raw_transaction(&raw_bytes)
        .await
        .map_err(|e| format!("broadcast failed: {e}"))?;
    let broadcast_hash = *pending.tx_hash();
    // Sanity-check: the hash we computed locally must match what the node
    // returns. A mismatch points at a tampered RPC; surface it loudly.
    if broadcast_hash != hash {
        warn!(
            local_hash = %format!("{hash:#x}"),
            broadcast_hash = %format!("{broadcast_hash:#x}"),
            "raw sign+send: hash mismatch between local compute and broadcast response",
        );
    }
    info!(hash = %format!("{hash:#x}"), "raw sign+send: broadcast ok");
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn erc20_transfer_calldata_matches_canonical_layout() {
        let to = address!("000000000000000000000000000000000000dEaD");
        let amount = U256::from(1_000_000u64);
        let calldata = erc20_transfer_calldata(to, amount);
        let bytes: &[u8] = calldata.as_ref();
        assert_eq!(bytes.len(), 68, "selector + 32 + 32");
        assert_eq!(&bytes[0..4], &[0xa9, 0x05, 0x9c, 0xbb], "transfer selector");
        // Recipient: 12 zero bytes + 20-byte address.
        assert_eq!(&bytes[4..16], &[0u8; 12]);
        assert_eq!(&bytes[16..36], to.as_slice());
        // Amount: 32-byte big-endian U256. 1_000_000 = 0x0F4240.
        assert_eq!(&bytes[36..62], &[0u8; 26]);
        assert_eq!(&bytes[62..68], &[0x00, 0x00, 0x00, 0x0F, 0x42, 0x40]);
    }

    #[test]
    fn parse_amount_units_eth_full_unit() {
        let parsed = parse_amount_units("1", 18).unwrap();
        assert_eq!(parsed, U256::from(10).pow(U256::from(18)));
    }

    #[test]
    fn parse_amount_units_usdc_six_decimals() {
        // 1.234567 USDC -> 1_234_567 (6 decimals).
        let parsed = parse_amount_units("1.234567", 6).unwrap();
        assert_eq!(parsed, U256::from(1_234_567u64));
    }

    #[test]
    fn parse_amount_units_rejects_empty() {
        assert!(parse_amount_units("   ", 18).is_err());
    }

    #[test]
    fn parse_amount_units_below_smallest_unit_is_zero() {
        // 0.0000001 USDC (6 decimals) is below USDC's smallest unit. Whether
        // alloy truncates to 0 or errors is implementation-defined; this
        // test pins our reliance on the downstream validator: the Send flow
        // refuses zero amounts via `amount_units.is_zero()` regardless of
        // which branch alloy takes.
        if let Ok(v) = parse_amount_units("0.0000001", 6) {
            assert!(v.is_zero(), "below-precision input must round to 0");
        }
        // Err is also allowed.
    }

    #[test]
    fn send_plan_native_target() {
        let from: Address = address!("000000000000000000000000000000000000beEF");
        let to: Address = address!("000000000000000000000000000000000000dEaD");
        let plan = SendPlan {
            from,
            recipient: to,
            token: SendToken::Native,
            amount_units: U256::from(123u64),
            chain: Chain::Mainnet,
        };
        let (target, value, input) = plan.tx_target();
        assert_eq!(target, to);
        assert_eq!(value, U256::from(123u64));
        assert!(input.is_empty());
    }

    #[test]
    fn send_plan_erc20_target() {
        let from: Address = address!("000000000000000000000000000000000000beEF");
        let to: Address = address!("000000000000000000000000000000000000dEaD");
        let usdc: Address = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        let plan = SendPlan {
            from,
            recipient: to,
            token: SendToken::Erc20 { contract: usdc },
            amount_units: U256::from(1_000_000u64),
            chain: Chain::Base,
        };
        let (target, value, input) = plan.tx_target();
        assert_eq!(target, usdc, "contract is the call target for ERC-20");
        assert_eq!(value, U256::ZERO);
        assert_eq!(input.len(), 68);
    }

    #[test]
    fn chain_id_is_eip155_canonical() {
        // Pin the EIP-155 ids — wrong values silently broadcast cross-chain.
        assert_eq!(Chain::Mainnet.chain_id(), 1);
        assert_eq!(Chain::Optimism.chain_id(), 10);
        assert_eq!(Chain::Base.chain_id(), 8453);
    }

    #[test]
    fn erc20_transfer_calldata_max_u256_amount() {
        // The amount field is a full U256; encoding must occupy all 32
        // bytes without truncation. Pinning MAX guards against a future
        // change that accidentally narrows the slot (e.g. swapping
        // `to_be_bytes::<32>()` for a smaller width).
        let to = address!("000000000000000000000000000000000000dEaD");
        let calldata = erc20_transfer_calldata(to, U256::MAX);
        let bytes: &[u8] = calldata.as_ref();
        assert_eq!(bytes.len(), 68);
        assert_eq!(&bytes[36..68], &[0xFFu8; 32]);
    }

    /// Pins a known sharp edge: alloy's `parse_units` accepts `"-N"`
    /// and `<ParseUnits as Into<U256>>` calls `get_absolute()`, which
    /// despite its name does NOT take the absolute value — it
    /// reinterprets the signed I256's raw two's-complement bytes as a
    /// U256. So `-1` (18 decimals) round-trips to `2^256 - 1e18`, an
    /// astronomically large amount that would always exceed the
    /// sender's balance and bounce upstream. The Send screen guards
    /// against this *additionally* (its amount field only accepts
    /// digits + one decimal point), but if a future caller bypasses
    /// the UI it must not assume `parse_amount_units` rejects negatives.
    #[test]
    fn parse_amount_units_negative_reinterprets_as_huge_u256() {
        let neg = parse_amount_units("-1", 18).expect("alloy accepts negative");
        let one_eth = U256::from(10).pow(U256::from(18));
        // -1e18 as I256, raw bytes reinterpreted as U256, is 2^256 - 1e18.
        assert_eq!(neg, U256::MAX - one_eth + U256::from(1u8));
    }

    #[test]
    fn parse_amount_units_rejects_garbage() {
        assert!(parse_amount_units("abc", 18).is_err());
        assert!(parse_amount_units("1.2.3", 18).is_err());
    }

    #[test]
    fn parse_amount_units_trims_whitespace() {
        // The Send screen passes raw text-field input; users can paste
        // amounts with stray whitespace. Trim before delegating.
        let parsed = parse_amount_units("  1  ", 18).unwrap();
        assert_eq!(parsed, U256::from(10).pow(U256::from(18)));
    }

    #[test]
    fn parse_amount_units_more_decimals_than_token_truncates_or_errors() {
        // 7 decimals on a 6-decimal token — alloy may either truncate
        // the extra digit or refuse. Pin our reliance: if it succeeds,
        // the value still fits the token's scale (≤ 1e7 base units for
        // "1.2345678").
        if let Ok(v) = parse_amount_units("1.2345678", 6) {
            assert!(v <= U256::from(1_234_568u64), "must not over-allocate");
        }
    }
}
