//! The GPv2 order — the EIP-712 message a seller signs — plus order-UID
//! derivation and the off-chain cancellation struct.
//!
//! Correctness here is load-bearing: the order the user signs is the exact
//! intent solvers execute, so a wrong field order or domain silently produces
//! a signature the orderbook rejects (best case) or one that authorizes a
//! different trade (worst case). The `sol!` field order is pinned against the
//! canonical GPv2Order typehash by [`tests::order_typehash_matches_spec`], and
//! the domain against the GPv2 domain separator by
//! [`tests::cow_domain_separator_matches_manual`].

use alloy::primitives::{Address, B256, Bytes, Signature, U256};
use alloy::sol;
use alloy::sol_types::{Eip712Domain, SolStruct};
use serde::{Deserialize, Serialize};

use crate::chain::Chain;
use crate::wallet::KaoSigner;

use super::SETTLEMENT;

sol! {
    /// GPv2 order. Field order is canonical and MUST NOT be reordered — alloy
    /// derives the EIP-712 typehash from declaration order. `kind`,
    /// `sellTokenBalance` and `buyTokenBalance` are declared `string` (the
    /// on-chain struct stores them as `bytes32`, but the EIP-712 *type string*
    /// declares them as `string`, so the encoded value is `keccak256(<the
    /// literal>)` — exactly what alloy does for a `string` member). We pass the
    /// literals `"sell"`/`"buy"` and `"erc20"`. `Serialize` is for the EIP-712
    /// JSON the signed-message history keeps (`cow::history`).
    #[derive(Debug, Serialize)]
    struct Order {
        address sellToken;
        address buyToken;
        address receiver;
        uint256 sellAmount;
        uint256 buyAmount;
        uint32 validTo;
        bytes32 appData;
        uint256 feeAmount;
        string kind;
        bool partiallyFillable;
        string sellTokenBalance;
        string buyTokenBalance;
    }

    /// Off-chain order cancellation (the non-deprecated bulk form behind
    /// `DELETE /orders`). The signed message is over an array of 56-byte order
    /// UIDs as *dynamic* `bytes` (NOT `bytes32`) — EIP-712 type
    /// `OrderCancellations(bytes[] orderUids)`.
    #[derive(Debug, Serialize)]
    struct OrderCancellations {
        bytes[] orderUids;
    }
}

/// Which side the order fixes. v1 only ever places `Sell` orders (including the
/// EthFlow native path, which is sell-only), but the wire enum carries both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderKind {
    Sell,
    Buy,
}

impl OrderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            OrderKind::Sell => "sell",
            OrderKind::Buy => "buy",
        }
    }
}

/// The GPv2 EIP-712 domain for `chain`: `name = "Gnosis Protocol"`,
/// `version = "v2"`, the chain id, and the settlement contract as
/// `verifyingContract`. Shape mirrors [`crate::safe::tx::safe_domain`] but with
/// name+version set (Safe's domain omits them).
pub fn cow_domain(chain: Chain) -> Eip712Domain {
    Eip712Domain {
        name: Some("Gnosis Protocol".into()),
        version: Some("v2".into()),
        chain_id: Some(U256::from(chain.chain_id())),
        verifying_contract: Some(SETTLEMENT),
        salt: None,
    }
}

/// Local EIP-712 signing hash (`keccak256(0x1901 ‖ domainSeparator ‖
/// hashStruct(order))`) — the digest solvers and the orderbook recover
/// signatures against.
pub fn order_digest(order: &Order, domain: &Eip712Domain) -> B256 {
    order.eip712_signing_hash(domain)
}

/// Reduce slippage-protect a quoted buy amount: `amount * (1 - bps/10000)`,
/// floored. `slippage_bps` is clamped to 100% so a bad caller can't underflow.
pub fn apply_slippage(amount: U256, slippage_bps: u16) -> U256 {
    let bps = slippage_bps.min(10_000) as u64;
    amount.saturating_mul(U256::from(10_000 - bps)) / U256::from(10_000u64)
}

/// Build a fill-or-kill **sell** order from the values a quote returned.
///
/// `sell_amount` must be the FULL input the user parts with (the quote's
/// `sellAmount + feeAmount`): the modern CoW orderbook requires the signed
/// `feeAmount` to be **0** — solvers take their gas/network fee dynamically out
/// of the executed price rather than from a signed fee field. `quoted_buy_amount`
/// is the solver's quoted output; the signed `buyAmount` is that minus
/// `slippage_bps`. `app_data` is the keccak256 of the order's appData document
/// (see [`super::market_app_data`]); the same pre-image must be POSTed so the
/// orderbook can reproduce the hash and read its `orderClass`.
#[allow(clippy::too_many_arguments)]
pub fn build_sell_order(
    sell_token: Address,
    buy_token: Address,
    receiver: Address,
    sell_amount: U256,
    quoted_buy_amount: U256,
    valid_to: u32,
    slippage_bps: u16,
    app_data: B256,
) -> Order {
    Order {
        sellToken: sell_token,
        buyToken: buy_token,
        receiver,
        sellAmount: sell_amount,
        buyAmount: apply_slippage(quoted_buy_amount, slippage_bps),
        validTo: valid_to,
        appData: app_data,
        feeAmount: U256::ZERO,
        kind: OrderKind::Sell.as_str().to_string(),
        partiallyFillable: false,
        sellTokenBalance: "erc20".to_string(),
        buyTokenBalance: "erc20".to_string(),
    }
}

/// CoW order UID = `orderDigest(32) ‖ owner(20) ‖ validTo(4, big-endian)` = 56
/// bytes. For a normal EOA order `owner` is the signer and `valid_to` is the
/// order's own `validTo`; for an EthFlow order the contract overrides them to
/// `owner = ETHFLOW` and `valid_to = u32::MAX` (see [`super::ethflow`]).
pub fn order_uid(digest: B256, owner: Address, valid_to: u32) -> [u8; 56] {
    let mut uid = [0u8; 56];
    uid[..32].copy_from_slice(digest.as_slice());
    uid[32..52].copy_from_slice(owner.as_slice());
    uid[52..56].copy_from_slice(&valid_to.to_be_bytes());
    uid
}

/// `0x`-prefixed hex of a 56-byte UID — the form the orderbook uses in URLs
/// and JSON.
pub fn uid_hex(uid: &[u8; 56]) -> String {
    format!("0x{}", alloy::hex::encode(uid))
}

/// EIP-712-sign an order with the active account's signer. Works across
/// software and hardware via [`KaoSigner::sign_eip712`].
pub async fn sign_order(
    signer: &KaoSigner,
    order: &Order,
    domain: &Eip712Domain,
) -> Result<Signature, String> {
    signer
        .sign_eip712(order, domain)
        .await
        .map_err(|e| format!("sign order: {e}"))
}

/// The `OrderCancellations` EIP-712 message for a set of 56-byte order UIDs.
pub fn build_cancellations(uids: &[[u8; 56]]) -> OrderCancellations {
    OrderCancellations {
        orderUids: uids.iter().map(|u| Bytes::copy_from_slice(u)).collect(),
    }
}

/// Local EIP-712 signing hash of an off-chain bulk cancellation: the digest an
/// EOA recovers against directly, and — for a Safe — the digest wrapped in a
/// `SafeMessage` for an EIP-1271 cancellation (see [`crate::cow::safe_sig`]).
pub fn cancellations_digest(uids: &[[u8; 56]], domain: &Eip712Domain) -> B256 {
    build_cancellations(uids).eip712_signing_hash(domain)
}

/// EIP-712-sign an off-chain cancellation of one or more orders with an EOA key
/// (eip712 / ethsign). Safe-owned orders cancel via EIP-1271 instead (see
/// [`crate::cow::safe_sig`]); EthFlow orders cancel on-chain.
pub async fn sign_cancellations(
    signer: &KaoSigner,
    uids: &[[u8; 56]],
    domain: &Eip712Domain,
) -> Result<Signature, String> {
    signer
        .sign_eip712(&build_cancellations(uids), domain)
        .await
        .map_err(|e| format!("sign cancellation: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, keccak256};
    use alloy::sol_types::SolValue;

    fn sample_order() -> Order {
        Order {
            sellToken: address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
            buyToken: address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
            receiver: address!("0x1111111111111111111111111111111111111111"),
            sellAmount: U256::from(1_000_000_000_000_000_000u64),
            buyAmount: U256::from(2_500_000_000u64),
            validTo: 1_900_000_000,
            appData: super::super::market_app_data(50).1,
            feeAmount: U256::ZERO,
            kind: "sell".to_string(),
            partiallyFillable: false,
            sellTokenBalance: "erc20".to_string(),
            buyTokenBalance: "erc20".to_string(),
        }
    }

    #[test]
    fn order_typehash_matches_spec() {
        // Re-derive the canonical GPv2Order typehash from the type string. If
        // the `sol!` field order ever drifts, `eip712_encode_type` diverges
        // and this fails before any wrong-hash signing can happen.
        let canonical = b"Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)";
        let encoded = <Order as SolStruct>::eip712_encode_type();
        assert_eq!(encoded.as_bytes(), &canonical[..]);
        assert_eq!(sample_order().eip712_type_hash(), keccak256(&canonical[..]));
    }

    #[test]
    fn order_cancellations_typehash_uses_bytes_array() {
        // The UIDs are dynamic `bytes`, NOT `bytes32`; a wrong width here
        // yields a hash the orderbook won't accept.
        let canonical = b"OrderCancellations(bytes[] orderUids)";
        assert_eq!(
            <OrderCancellations as SolStruct>::eip712_encode_type().as_bytes(),
            &canonical[..]
        );
    }

    #[test]
    fn cow_domain_separator_matches_manual() {
        // Manual GPv2 domain separator:
        //   keccak256(abi.encode(
        //     keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        //     keccak256("Gnosis Protocol"), keccak256("v2"), chainId, settlement))
        let domain_typehash = keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        let manual = keccak256(
            (
                domain_typehash,
                keccak256(b"Gnosis Protocol"),
                keccak256(b"v2"),
                U256::from(Chain::Mainnet.chain_id()),
                SETTLEMENT,
            )
                .abi_encode(),
        );
        assert_eq!(cow_domain(Chain::Mainnet).separator(), manual);
    }

    #[test]
    fn digest_differs_across_chains() {
        let order = sample_order();
        let m = order_digest(&order, &cow_domain(Chain::Mainnet));
        let b = order_digest(&order, &cow_domain(Chain::Base));
        assert_ne!(m, b, "same order must hash differently per chain id");
    }

    #[test]
    fn uid_layout_is_digest_owner_validto() {
        let digest = B256::repeat_byte(0xAB);
        let owner = address!("0x2222222222222222222222222222222222222222");
        let uid = order_uid(digest, owner, 0x1234_5678);
        assert_eq!(uid.len(), 56);
        assert_eq!(&uid[..32], digest.as_slice());
        assert_eq!(&uid[32..52], owner.as_slice());
        assert_eq!(&uid[52..56], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(uid_hex(&uid).len(), 2 + 112);
        assert!(uid_hex(&uid).starts_with("0x"));
    }

    #[test]
    fn cancellations_digest_is_stable_and_chain_specific() {
        // The digest a Safe wraps in a SafeMessage for an EIP-1271 cancellation.
        // It must be deterministic for a given (uids, chain) and bind the chain.
        let uid = order_uid(
            B256::repeat_byte(0x11),
            address!("0x2222222222222222222222222222222222222222"),
            123,
        );
        let m = cancellations_digest(&[uid], &cow_domain(Chain::Mainnet));
        let b = cancellations_digest(&[uid], &cow_domain(Chain::Base));
        assert_ne!(m, b, "cancellation digest must bind the chain id");
        assert_eq!(
            m,
            cancellations_digest(&[uid], &cow_domain(Chain::Mainnet)),
            "digest must be deterministic"
        );
    }

    #[test]
    fn slippage_reduces_buy_amount() {
        // 0.5% off 1000 = 995.
        assert_eq!(apply_slippage(U256::from(1000u64), 50), U256::from(995u64));
        // 0 bps is a no-op.
        assert_eq!(apply_slippage(U256::from(1000u64), 0), U256::from(1000u64));
        // Clamped at 100%.
        assert_eq!(apply_slippage(U256::from(1000u64), 20_000), U256::ZERO);
    }

    #[test]
    fn build_sell_order_applies_slippage_and_zeroes_fee() {
        let app_data = super::super::market_app_data(100).1;
        let o = build_sell_order(
            address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
            address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
            address!("0x1111111111111111111111111111111111111111"),
            U256::from(1_000_000_000_000_000_000u64),
            U256::from(2_000_000_000u64),
            1_900_000_000,
            100, // 1%
            app_data,
        );
        assert_eq!(o.buyAmount, U256::from(1_980_000_000u64));
        // The orderbook requires a zero signed fee — solvers take it dynamically.
        assert_eq!(o.feeAmount, U256::ZERO);
        // The signed appData is the passed-through market-order hash.
        assert_eq!(o.appData, app_data);
        assert_eq!(o.kind, "sell");
        assert_eq!(o.sellTokenBalance, "erc20");
        assert!(!o.partiallyFillable);
    }
}
