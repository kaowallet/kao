//! Transaction building, fee estimation, signing, and broadcasting for the
//! Send flow. Native ETH and ERC-20 transfers go through one path: a
//! `SendPlan` resolves the destination/value/calldata, `build_quote` asks the
//! provider for gas and EIP-1559 fees + nonce, and `sign_and_send` fills a
//! `TxEip1559`, signs the EIP-2718 hash via `KaoSigner::sign_hash`, and
//! broadcasts the raw envelope.

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy::eips::eip2718::Encodable2718;
use alloy::network::Ethereum;
use alloy::primitives::utils::parse_units;
use alloy::primitives::{Address, Bytes, TxHash, TxKind, U256};
use alloy::providers::{Provider, RootProvider};

use crate::wallet::{CHAIN_ID, KaoSigner};

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
    let parsed = parse_units(trimmed, decimals)
        .map_err(|e| format!("invalid amount: {e}"))?;
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
#[derive(Debug, Clone)]
pub struct SendPlan {
    pub from: Address,
    pub recipient: Address,
    pub token: SendToken,
    pub amount_units: U256,
}

impl SendPlan {
    /// Resolve the (to, value, calldata) triple for this plan.
    fn tx_target(&self) -> (Address, U256, Bytes) {
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
#[derive(Debug, Clone, Copy)]
pub struct TxQuote {
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub nonce: u64,
    /// `gas_limit × max_fee_per_gas` — the maximum ETH the sender can be
    /// charged (actual cost is usually lower because base fee + tip < max
    /// fee). Displayed on the review step.
    pub eth_cost_wei: U256,
}

/// Quote a send: estimate gas, fetch 1559 fees, fetch the pending nonce.
pub async fn build_quote(
    provider: &RootProvider<Ethereum>,
    plan: &SendPlan,
) -> Result<TxQuote, String> {
    let req = plan.to_request();

    let gas_limit = provider
        .estimate_gas(req)
        .await
        .map_err(|e| format!("estimate_gas: {e}"))?;

    let fees = provider
        .estimate_eip1559_fees()
        .await
        .map_err(|e| format!("estimate_eip1559_fees: {e}"))?;

    let nonce = provider
        .get_transaction_count(plan.from)
        .pending()
        .await
        .map_err(|e| format!("get_transaction_count: {e}"))?;

    let eth_cost_wei = U256::from(gas_limit).saturating_mul(U256::from(fees.max_fee_per_gas));

    Ok(TxQuote {
        gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        nonce,
        eth_cost_wei,
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

    let tx = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce: quote.nonce,
        gas_limit: quote.gas_limit,
        max_fee_per_gas: quote.max_fee_per_gas,
        max_priority_fee_per_gas: quote.max_priority_fee_per_gas,
        to: TxKind::Call(to),
        value,
        access_list: Default::default(),
        input,
    };

    let signing_hash = tx.signature_hash();
    let sig = signer
        .sign_hash(&signing_hash)
        .await
        .map_err(|e| format!("sign failed: {e}"))?;

    let envelope: TxEnvelope = tx.into_signed(sig).into();
    let raw = envelope.encoded_2718();

    let pending = provider
        .send_raw_transaction(&raw)
        .await
        .map_err(|e| format!("broadcast failed: {e}"))?;

    Ok(*pending.tx_hash())
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
        };
        let (target, value, input) = plan.tx_target();
        assert_eq!(target, usdc, "contract is the call target for ERC-20");
        assert_eq!(value, U256::ZERO);
        assert_eq!(input.len(), 68);
    }
}
