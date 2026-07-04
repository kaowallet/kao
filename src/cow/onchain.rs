//! On-chain pieces of a CoW swap: the ERC-20 allowance read + approval to the
//! vault relayer, and a generic "sign and broadcast a contract call" helper
//! shared by the approval and the EthFlow `createOrder` / `invalidateOrder`
//! paths.
//!
//! [`send_contract_call`] is the only genuinely new broadcast code the
//! integration needs; it mirrors [`crate::wallet::tx::sign_and_send`] (fill a
//! `TxEip1559`, route it through `KaoSigner::sign_tx`, broadcast the raw
//! envelope) but for an arbitrary `(to, value, calldata)` rather than a
//! `SendPlan`.

use std::time::Duration;

use alloy::network::Ethereum;
use alloy::primitives::{Address, Bytes, TxHash, U256};
use alloy::providers::{Provider, RootProvider};
use alloy::rpc::types::{TransactionInput, TransactionRequest};
use alloy::sol;
use alloy::sol_types::SolCall;
use tracing::warn;

use crate::chain::Chain;
use crate::sign::broadcast::{BroadcastCall, Fees, Guards, LiveSigners, broadcast};
use crate::wallet::KaoSigner;

use super::VAULT_RELAYER;

sol! {
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

/// Read the ERC-20 allowance the seller has granted the vault relayer on
/// `token`. A sell order can only settle once this covers the sell amount.
pub async fn read_allowance(
    provider: &RootProvider<Ethereum>,
    token: Address,
    owner: Address,
) -> Result<U256, String> {
    let input = allowanceCall {
        owner,
        spender: VAULT_RELAYER,
    }
    .abi_encode();
    let req = TransactionRequest::default()
        .to(token)
        .input(TransactionInput::new(Bytes::from(input)));
    let out = provider
        .call(req)
        .await
        .map_err(|e| format!("allowance call: {e}"))?;
    allowanceCall::abi_decode_returns(&out).map_err(|e| format!("allowance decode: {e}"))
}

/// `approve(vaultRelayer, amount)` calldata for an ERC-20.
pub fn approve_calldata(amount: U256) -> Bytes {
    Bytes::from(
        approveCall {
            spender: VAULT_RELAYER,
            amount,
        }
        .abi_encode(),
    )
}

/// Sign and broadcast `approve(vaultRelayer, amount)` on `token`. Callers
/// typically pass `U256::MAX` for a one-time unlimited approval so repeat swaps
/// of the same token skip this step.
pub async fn approve_relayer(
    provider: &RootProvider<Ethereum>,
    signer: &KaoSigner,
    chain: Chain,
    token: Address,
    amount: U256,
) -> Result<TxHash, String> {
    send_contract_call(
        provider,
        signer,
        chain,
        token,
        U256::ZERO,
        approve_calldata(amount),
    )
    .await
}

/// Build, sign, and broadcast an arbitrary contract call from the active
/// account. A thin shim over the unified [`crate::sign::broadcast::broadcast`]
/// primitive: it estimates gas/fees/nonce fresh ([`Fees::Estimate`]), pre-flights
/// the balance, and remaps an "insufficient funds" broadcast error. `from` is the
/// signer's own address, so the `from == signer` wall is trivially satisfied.
/// Returns the tx hash; it does NOT wait for inclusion — the caller polls the
/// receipt.
pub async fn send_contract_call(
    provider: &RootProvider<Ethereum>,
    signer: &KaoSigner,
    chain: Chain,
    to: Address,
    value: U256,
    calldata: Bytes,
) -> Result<TxHash, String> {
    broadcast(
        provider,
        LiveSigners::One(signer),
        signer.address(),
        Fees::Estimate,
        BroadcastCall {
            to,
            value,
            calldata,
            chain_id: chain.chain_id(),
        },
        Guards {
            balance_preflight: true,
            insufficient_funds_massage: true,
            ..Default::default()
        },
    )
    .await
}

/// Poll for `hash`'s receipt, returning once it's mined. Errors if the tx
/// reverted, or if it hasn't confirmed within `max_polls` × 3s. Used to gate an
/// order submission on its approval (or an EthFlow `createOrder`) landing first.
pub async fn wait_for_receipt(
    provider: &RootProvider<Ethereum>,
    hash: TxHash,
    max_polls: u32,
) -> Result<(), String> {
    for _ in 0..max_polls {
        match provider.get_transaction_receipt(hash).await {
            Ok(Some(r)) => {
                return if r.status() {
                    Ok(())
                } else {
                    Err("transaction reverted".into())
                };
            }
            Ok(None) => {}
            Err(e) => {
                // Transient RPC hiccup — keep polling rather than failing the
                // whole placement.
                warn!(error = %e, "cow: receipt poll error (retrying)");
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    Err("transaction not confirmed in time".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approve_calldata_targets_vault_relayer() {
        let cd = approve_calldata(U256::MAX);
        let b: &[u8] = cd.as_ref();
        assert_eq!(b.len(), 68, "selector + spender + amount");
        // `approve(address,uint256)` selector.
        assert_eq!(&b[0..4], &[0x09, 0x5e, 0xa7, 0xb3]);
        assert_eq!(&b[4..16], &[0u8; 12]);
        assert_eq!(
            &b[16..36],
            VAULT_RELAYER.as_slice(),
            "spender is the relayer"
        );
        assert_eq!(&b[36..68], &[0xFFu8; 32], "max approval");
    }

    #[test]
    fn allowance_calldata_uses_canonical_selector() {
        let input = allowanceCall {
            owner: Address::repeat_byte(0x11),
            spender: VAULT_RELAYER,
        }
        .abi_encode();
        // `allowance(address,address)` selector.
        assert_eq!(&input[0..4], &[0xdd, 0x62, 0xed, 0x3e]);
        assert_eq!(&input[16..36], Address::repeat_byte(0x11).as_slice());
        assert_eq!(&input[48..68], VAULT_RELAYER.as_slice());
    }
}
