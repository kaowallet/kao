//! Transaction building, fee estimation, signing, and broadcasting for the
//! Send flow. Native ETH and ERC-20 transfers go through one path: a
//! `SendPlan` resolves the destination/value/calldata, `build_quote` asks the
//! provider for gas and EIP-1559 fees + nonce, and `sign_and_send` fills a
//! `TxEip1559`, hands it to `KaoSigner::sign_tx` (which routes to whichever
//! `TxSigner` impl backs the active account), and broadcasts the raw
//! envelope.

use std::sync::Arc;

use alloy::network::Ethereum;
use alloy::primitives::utils::parse_units;
use alloy::primitives::{Address, Bytes, TxHash, U256};
use alloy::providers::{Provider, RootProvider};
use tracing::{debug, info, warn};

use crate::chain::NetworkId;
use crate::net::BalanceFetcher;
use crate::sign::broadcast::{BroadcastCall, Fees, Guards, LiveSigners, broadcast};
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
    // alloy's `parse_units` accepts a leading '-' and `<ParseUnits as
    // Into<U256>>` reinterprets the signed value's two's-complement bytes as a
    // huge U256 (e.g. "-1" → 2^256 - 1e18). The Send screen's `parsed_amount`
    // also rejects negatives, but enforce it in this public helper too so the
    // API matches its "rejects negative inputs" contract and a non-UI caller
    // can't sign an astronomically large transfer. (See the rejects-negative
    // test.)
    if trimmed.starts_with('-') {
        return Err("amount must not be negative".into());
    }
    let parsed = parse_units(trimmed, decimals).map_err(|e| format!("invalid amount: {e}"))?;
    let value: U256 = parsed.into();
    Ok(value)
}

/// What kind of token this send moves: native ETH, or an ERC-20 contract.
#[derive(Debug, Clone, PartialEq, Eq)]
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
/// fetched would invalidate the review screen's numbers. It's a
/// [`NetworkId`] so the send flow works on a user-defined custom network
/// (which carries `NetworkId::Custom(chain_id)`) exactly as it does on a
/// built-in — only the provider the caller hands in differs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendPlan {
    pub from: Address,
    pub recipient: Address,
    pub token: SendToken,
    pub amount_units: U256,
    pub chain: NetworkId,
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
    /// Exact plan this quote/simulation was produced for. The signer re-checks
    /// it so a stale review quote cannot be paired with a newly-built plan.
    pub plan: SendPlan,
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

impl TxQuote {
    pub fn matches_plan(&self, plan: &SendPlan) -> bool {
        &self.plan == plan
    }
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
        chain_id = plan.chain.chain_id(),
        custom = plan.chain.is_custom(),
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
            // Alloy transport errors `Display` the full request URL, which for
            // the execution RPC embeds the API key (Alchemy, dRPC). This string
            // reaches both the warn log and the sign-review overlay error, so
            // scrub URLs to the host first (see `net::redact_urls`).
            let e = crate::net::redact_urls(&e.to_string());
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
            let e = crate::net::redact_urls(&e.to_string());
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
            let e = crate::net::redact_urls(&e.to_string());
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
                warn!(error = %crate::net::redact_urls(&e.to_string()), "quote: simulate_tx failed, marking sim unavailable");
                SimulationResult::unavailable()
            }
        }
    } else {
        debug!(
            chain_id = plan.chain.chain_id(),
            "quote: chain doesn't support simulation"
        );
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
        plan: plan.clone(),
        gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        nonce,
        eth_cost_wei,
        sim,
    })
}

/// Sign the reviewed `SendPlan`/`TxQuote` and broadcast it.
///
/// A thin shim over the unified [`crate::sign::broadcast::broadcast`] primitive:
/// it keeps the Send-specific stale-quote guard (a full structural `SendPlan`
/// comparison), then delegates the fill/sign/assert/broadcast tail. The quote's
/// nonce/gas/fees are passed as [`Fees::Quoted`] so the user signs exactly the
/// numbers they reviewed — no re-estimation. The zero-address recipient guard
/// (which must inspect `plan.recipient`, not the tx `to`, because an ERC-20's
/// recipient lives in the calldata) and the `from == signer` wall both live in
/// the primitive.
pub async fn sign_and_send(
    provider: &RootProvider<Ethereum>,
    signer: &KaoSigner,
    plan: SendPlan,
    quote: TxQuote,
) -> Result<TxHash, String> {
    // Send-specific stale-quote guard: the reviewed quote must still describe
    // the exact plan being signed. Kept here (rather than the primitive's
    // hash-based `stale_terms`) so the message and full-struct equality are
    // preserved byte-for-byte during the migration.
    if !quote.matches_plan(&plan) {
        warn!(
            from = %plan.from,
            current_recipient = %plan.recipient,
            quoted_recipient = %quote.plan.recipient,
            current_amount_units = %plan.amount_units,
            quoted_amount_units = %quote.plan.amount_units,
            "sign+send: refusing stale quote",
        );
        return Err("quote no longer matches the reviewed send — review again".to_string());
    }
    let (to, value, input) = plan.tx_target();
    info!(
        chain_id = plan.chain.chain_id(),
        custom = plan.chain.is_custom(),
        token = match &plan.token {
            SendToken::Native => "native",
            SendToken::Erc20 { .. } => "erc20",
        },
        from = %plan.from,
        to = %to,
        "sign+send: dispatching via unified broadcast",
    );

    broadcast(
        provider,
        LiveSigners::One(signer),
        plan.from,
        Fees::Quoted {
            nonce: quote.nonce,
            gas_limit: quote.gas_limit,
            max_fee_per_gas: quote.max_fee_per_gas,
            max_priority_fee_per_gas: quote.max_priority_fee_per_gas,
        },
        BroadcastCall {
            to,
            value,
            calldata: input,
            chain_id: plan.chain.chain_id(),
        },
        Guards {
            zero_recipient: Some(plan.recipient),
            ..Default::default()
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::Chain;
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
            chain: NetworkId::Builtin(Chain::Mainnet),
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
            chain: NetworkId::Builtin(Chain::Base),
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

    /// Guards a known sharp edge: alloy's `parse_units` accepts `"-N"` and
    /// `<ParseUnits as Into<U256>>` reinterprets the signed I256's raw
    /// two's-complement bytes as a U256 (so `-1` would become `2^256 - 1e18`,
    /// an astronomically large amount). `parse_amount_units` must reject
    /// negatives itself so a non-UI caller can't bypass the Send screen's
    /// digit-only field and sign a huge transfer.
    #[test]
    fn parse_amount_units_rejects_negative() {
        assert!(parse_amount_units("-1", 18).is_err());
        assert!(parse_amount_units("  -0.5  ", 18).is_err());
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

    fn dummy_quote(plan: &SendPlan) -> TxQuote {
        TxQuote {
            plan: plan.clone(),
            gas_limit: 21_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            nonce: 0,
            eth_cost_wei: U256::ZERO,
            sim: SimulationResult::unavailable(),
        }
    }

    #[tokio::test]
    async fn sign_and_send_refuses_zero_recipient_native() {
        use alloy::signers::local::PrivateKeySigner;
        let signer = KaoSigner::Local(PrivateKeySigner::random());
        // The guard returns before signing/broadcast, so the provider is
        // never contacted — a non-routable URL is fine.
        let provider = RootProvider::<Ethereum>::new_http("http://127.0.0.1:1".parse().unwrap());
        let plan = SendPlan {
            from: signer.address(),
            recipient: Address::ZERO,
            token: SendToken::Native,
            amount_units: U256::from(1u64),
            chain: NetworkId::Builtin(Chain::Mainnet),
        };
        let quote = dummy_quote(&plan);
        let res = sign_and_send(&provider, &signer, plan, quote).await;
        assert!(
            res.is_err(),
            "native send to the zero address must be refused"
        );
    }

    #[tokio::test]
    async fn sign_and_send_refuses_zero_recipient_erc20() {
        use alloy::signers::local::PrivateKeySigner;
        let signer = KaoSigner::Local(PrivateKeySigner::random());
        let provider = RootProvider::<Ethereum>::new_http("http://127.0.0.1:1".parse().unwrap());
        // ERC-20: the tx `to` is the (non-zero) contract, but the recipient
        // buried in the transfer calldata is zero — exactly the case a
        // `to`-only check would wave through. The guard inspects
        // `plan.recipient`, so it catches it.
        let usdc = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        let plan = SendPlan {
            from: signer.address(),
            recipient: Address::ZERO,
            token: SendToken::Erc20 { contract: usdc },
            amount_units: U256::from(1_000_000u64),
            chain: NetworkId::Builtin(Chain::Base),
        };
        let quote = dummy_quote(&plan);
        let res = sign_and_send(&provider, &signer, plan, quote).await;
        assert!(
            res.is_err(),
            "erc20 transfer to the zero address must be refused"
        );
    }

    #[tokio::test]
    async fn sign_and_send_refuses_quote_for_different_plan() {
        use alloy::signers::local::PrivateKeySigner;

        let signer = KaoSigner::Local(PrivateKeySigner::random());
        let provider = RootProvider::<Ethereum>::new_http("http://127.0.0.1:1".parse().unwrap());
        let reviewed = SendPlan {
            from: signer.address(),
            recipient: address!("000000000000000000000000000000000000dEaD"),
            token: SendToken::Native,
            amount_units: U256::from(1u64),
            chain: NetworkId::Builtin(Chain::Mainnet),
        };
        let current = SendPlan {
            amount_units: U256::from(2u64),
            ..reviewed.clone()
        };

        let err = sign_and_send(&provider, &signer, current, dummy_quote(&reviewed))
            .await
            .unwrap_err();
        assert!(
            err.contains("quote no longer matches"),
            "stale quote must be refused before signing, got {err}",
        );
    }
}
