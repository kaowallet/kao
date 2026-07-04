//! The one EOA broadcast primitive.
//!
//! [`broadcast`] fills a `TxEip1559`, signs it with a [`KaoSigner`], **asserts
//! the produced signature recovers to the address the review showed as `from`**,
//! and broadcasts the raw envelope. It is the shared tail that
//! `wallet::tx::sign_and_send` and `cow::onchain::send_contract_call` used to
//! hand-roll independently (with divergent pre-flight guards); those are now
//! thin shims over this.
//!
//! The `from == signer` assertion is the wall neither helper had: a
//! "review shows A, signer is B" mismatch (the PP-Safe bug class) becomes a
//! refusal before the transaction leaves the wallet, rather than a silent
//! spend from the wrong account.
//!
//! This primitive models the single-EOA broadcast only. The Safe owner
//! ceremony (many owner signatures packed into one `execTransaction`, then an
//! executor envelope) is broadcast by its own primitive,
//! [`crate::safe::tx::execute_safe_tx`], not through here.

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy::eips::eip2718::Encodable2718;
use alloy::network::Ethereum;
use alloy::primitives::{Address, B256, Bytes, Signature, TxHash, TxKind, U256};
use alloy::providers::{Provider, RootProvider};
use alloy::rpc::types::{TransactionInput, TransactionRequest};
use tracing::{debug, info, warn};

use crate::wallet::KaoSigner;

/// The live signer authorizing a broadcast — a single EOA. There is no
/// multi-owner variant: the Safe owner ceremony broadcasts through
/// [`crate::safe::tx::execute_safe_tx`] instead, so it never reaches here.
pub enum LiveSigners<'a> {
    One(&'a KaoSigner),
}

/// Where the fee / nonce parameters come from.
pub enum Fees {
    /// Use these values **verbatim** — the send flow reviews a `TxQuote` and
    /// must sign exactly the numbers it showed the user, so it never
    /// re-estimates. No RPC calls are made to resolve fees on this path.
    Quoted {
        nonce: u64,
        gas_limit: u64,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    },
    /// Estimate gas + EIP-1559 fees + the pending nonce fresh from the provider
    /// (the on-chain-contract-call path).
    Estimate,
}

/// The exact bytes to broadcast.
pub struct BroadcastCall {
    pub to: Address,
    pub value: U256,
    pub calldata: Bytes,
    pub chain_id: u64,
}

/// Opt-in pre/post-flight guards, unioned from the two legacy EOA helpers. Each
/// caller enables exactly the checks it used before; new callers get them for
/// free.
#[derive(Default)]
pub struct Guards {
    /// `Some(recipient)` ⇒ refuse if the **actual** recipient is the zero
    /// address. For an ERC-20 transfer the recipient lives in the calldata, not
    /// the tx `to`, so the caller passes it explicitly. (Send.)
    pub zero_recipient: Option<Address>,
    /// `Some((frozen, current))` ⇒ refuse if the two differ — a generic
    /// stale-terms guard (a hash of the terms frozen at review vs. re-derived at
    /// dispatch) generalizing `TxQuote::matches_plan` for future callers.
    pub stale_terms: Option<(B256, B256)>,
    /// Refuse before signing if `value + worst-case gas > balance`. A native
    /// EthFlow order sends the amount as `value`, so the user needs
    /// amount + fee + gas all in ETH. (CoW.)
    pub balance_preflight: bool,
    /// Remap an RPC "insufficient funds" broadcast error to a friendly message
    /// instead of surfacing the raw text. (CoW.)
    pub insufficient_funds_massage: bool,
}

/// Fill a `TxEip1559`, sign it with the signer, assert the signature recovers
/// to `expected_from`, and broadcast the raw envelope. Returns the tx hash
/// without waiting for inclusion — the caller polls the receipt.
pub async fn broadcast(
    provider: &RootProvider<Ethereum>,
    signers: LiveSigners<'_>,
    expected_from: Address,
    fees: Fees,
    call: BroadcastCall,
    guards: Guards,
) -> Result<TxHash, String> {
    let LiveSigners::One(signer) = signers;

    // ── pre-sign guards ──
    if let Some(recipient) = guards.zero_recipient
        && recipient.is_zero()
    {
        warn!(from = %expected_from, "broadcast: refusing zero-address recipient");
        return Err("refusing to send to the zero address".to_string());
    }
    if let Some((frozen, current)) = guards.stale_terms
        && frozen != current
    {
        warn!(from = %expected_from, "broadcast: refusing stale terms");
        return Err("quote no longer matches the reviewed transaction — review again".to_string());
    }

    // ── fees / nonce ──
    let (nonce, gas_limit, max_fee_per_gas, max_priority_fee_per_gas) = match fees {
        Fees::Quoted {
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => (nonce, gas_limit, max_fee_per_gas, max_priority_fee_per_gas),
        Fees::Estimate => {
            let req = TransactionRequest::default()
                .from(expected_from)
                .to(call.to)
                .value(call.value)
                .input(TransactionInput::new(call.calldata.clone()));
            // Alloy transport errors `Display` the full request URL, which for
            // the execution RPC embeds the API key (Alchemy, dRPC). These
            // strings reach warn! logs and the sign-review overlay, so scrub
            // URLs to the host first (see `net::redact_urls`).
            let gas_limit = provider
                .estimate_gas(req)
                .await
                .map_err(|e| format!("estimate_gas: {}", crate::net::redact_urls(&e.to_string())))?;
            let f = provider.estimate_eip1559_fees().await.map_err(|e| {
                format!(
                    "estimate_eip1559_fees: {}",
                    crate::net::redact_urls(&e.to_string())
                )
            })?;
            let nonce = provider
                .get_transaction_count(expected_from)
                .pending()
                .await
                .map_err(|e| {
                    format!(
                        "get_transaction_count: {}",
                        crate::net::redact_urls(&e.to_string())
                    )
                })?;
            (
                nonce,
                gas_limit,
                f.max_fee_per_gas,
                f.max_priority_fee_per_gas,
            )
        }
    };

    // ── balance pre-flight ──
    if guards.balance_preflight {
        let balance = provider
            .get_balance(expected_from)
            .await
            .map_err(|e| format!("get_balance: {}", crate::net::redact_urls(&e.to_string())))?;
        let max_gas_cost = U256::from(gas_limit).saturating_mul(U256::from(max_fee_per_gas));
        let required = call.value.saturating_add(max_gas_cost);
        if balance < required {
            let what = if call.value > U256::ZERO {
                "the swap amount + fee + network gas"
            } else {
                "network gas"
            };
            return Err(format!(
                "not enough ETH for {what}: need ~{} ETH, have {} ETH",
                fmt_eth(required),
                fmt_eth(balance),
            ));
        }
    }

    info!(
        chain_id = call.chain_id,
        from = %expected_from,
        to = %call.to,
        value_wei = %call.value,
        input_len = call.calldata.len(),
        gas_limit,
        nonce,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        "broadcast: signing tx",
    );

    let mut tx = TxEip1559 {
        chain_id: call.chain_id,
        nonce,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        to: TxKind::Call(call.to),
        value: call.value,
        access_list: Default::default(),
        input: call.calldata,
    };

    // Capture the exact 32 bytes the signer commits to *before* signing, so the
    // recovery below checks the same preimage.
    let sighash = tx.signature_hash();

    let sig = match signer.sign_tx(&mut tx).await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "broadcast: sign failed");
            return Err(crate::wallet::friendly_signer_error(&e));
        }
    };

    assert_from_equals_signer(&sig, sighash, expected_from)?;
    debug!("broadcast: signed; from == signer verified");

    let envelope: TxEnvelope = tx.into_signed(sig).into();
    let raw = envelope.encoded_2718();
    debug!(raw_len = raw.len(), "broadcast: broadcasting raw envelope");

    let pending = provider.send_raw_transaction(&raw).await.map_err(|e| {
        // Scrub the key-bearing RPC URL before this hits the warn log or the
        // returned (UI-visible) error; the "insufficient funds" massage below
        // still matches because redaction only removes URLs.
        let msg = crate::net::redact_urls(&e.to_string());
        warn!(error = %msg, "broadcast: broadcast failed");
        if guards.insufficient_funds_massage && msg.to_lowercase().contains("insufficient funds") {
            // Belt-and-suspenders: the balance pre-flight should catch this, but a
            // gas-price spike between estimate and broadcast can still trip it.
            "not enough ETH to cover the swap amount + network gas".to_string()
        } else {
            format!("broadcast failed: {msg}")
        }
    })?;

    let hash = *pending.tx_hash();
    info!(hash = %format!("{hash:#x}"), "broadcast: ok");
    Ok(hash)
}

/// The wall: the address that actually signed must equal the one the review
/// showed as `from`. Recovers the signer from the tx's signature hash and
/// refuses on any mismatch. This catches a mis-handed live signer (e.g. a Safe
/// context wrongly routed through the EOA path) before the tx is broadcast.
fn assert_from_equals_signer(
    sig: &Signature,
    sighash: B256,
    expected_from: Address,
) -> Result<(), String> {
    let recovered = sig
        .recover_address_from_prehash(&sighash)
        .map_err(|e| format!("could not recover signer from signature: {e}"))?;
    if recovered != expected_from {
        warn!(
            expected = %expected_from,
            recovered = %recovered,
            "broadcast: signer does not match the reviewed from-address",
        );
        return Err(
            "signer does not match the reviewed sender — refusing to broadcast".to_string(),
        );
    }
    Ok(())
}

/// Format wei as a short ETH string (6 dp) for user-facing error messages.
fn fmt_eth(wei: U256) -> String {
    let s = alloy::primitives::utils::format_ether(wei);
    match s.parse::<f64>() {
        Ok(v) => format!("{v:.6}"),
        Err(_) => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use alloy::signers::local::PrivateKeySigner;

    /// A provider whose endpoint is not routable. Any actual RPC call errors,
    /// so a test that returns a *logical* error (guard / assert) rather than a
    /// connection error proves that path made no network call.
    fn dead_provider() -> RootProvider<Ethereum> {
        RootProvider::<Ethereum>::new_http("http://127.0.0.1:1".parse().unwrap())
    }

    fn quoted() -> Fees {
        Fees::Quoted {
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
        }
    }

    fn call_to(to: Address) -> BroadcastCall {
        BroadcastCall {
            to,
            value: U256::ZERO,
            calldata: Bytes::new(),
            chain_id: 1,
        }
    }

    /// The core invariant: signing with a key that isn't the reviewed `from`
    /// is refused — and, because the `Quoted` path makes no fee/nonce RPC, the
    /// refusal surfaces as the signer-mismatch message (not a connection error),
    /// which simultaneously proves `Quoted` does not re-estimate.
    #[tokio::test]
    async fn refuses_from_not_equal_signer_on_quoted_path() {
        let signer = KaoSigner::Local(PrivateKeySigner::random());
        let expected_from = address!("00000000000000000000000000000000000000aa"); // not the signer
        assert_ne!(expected_from, signer.address());

        let err = broadcast(
            &dead_provider(),
            LiveSigners::One(&signer),
            expected_from,
            quoted(),
            call_to(address!("000000000000000000000000000000000000dEaD")),
            Guards::default(),
        )
        .await
        .unwrap_err();

        assert!(
            err.contains("signer does not match"),
            "expected a signer-mismatch refusal (reached offline, proving no re-estimate), got: {err}",
        );
    }

    #[tokio::test]
    async fn refuses_stale_terms_before_signing() {
        let signer = KaoSigner::Local(PrivateKeySigner::random());
        let err = broadcast(
            &dead_provider(),
            LiveSigners::One(&signer),
            signer.address(),
            quoted(),
            call_to(address!("000000000000000000000000000000000000dEaD")),
            Guards {
                stale_terms: Some((B256::repeat_byte(1), B256::repeat_byte(2))),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(
            err.contains("quote no longer matches"),
            "stale terms must be refused before signing, got: {err}",
        );
    }

    #[tokio::test]
    async fn refuses_zero_recipient_before_signing() {
        let signer = KaoSigner::Local(PrivateKeySigner::random());
        let err = broadcast(
            &dead_provider(),
            LiveSigners::One(&signer),
            signer.address(),
            quoted(),
            call_to(address!("000000000000000000000000000000000000dEaD")),
            Guards {
                zero_recipient: Some(Address::ZERO),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(
            err.contains("zero address"),
            "zero recipient must be refused, got: {err}",
        );
    }

    /// Matching signer passes the `from == signer` wall and reaches broadcast;
    /// against the dead provider that surfaces as a broadcast/connection error,
    /// NOT a signer-mismatch — confirming a legitimate send is not falsely
    /// rejected and still never re-estimates on the `Quoted` path.
    #[tokio::test]
    async fn matching_signer_passes_wall_and_reaches_broadcast() {
        let signer = KaoSigner::Local(PrivateKeySigner::random());
        let err = broadcast(
            &dead_provider(),
            LiveSigners::One(&signer),
            signer.address(),
            quoted(),
            call_to(address!("000000000000000000000000000000000000dEaD")),
            Guards::default(),
        )
        .await
        .unwrap_err();
        assert!(
            !err.contains("signer does not match"),
            "a matching signer must clear the wall, got: {err}",
        );
        assert!(
            err.contains("broadcast failed"),
            "should fail at broadcast against the dead provider, got: {err}",
        );
    }
}
