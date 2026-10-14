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

/// Liveness hook run after the signature exists and immediately before the
/// broadcast. WalletConnect passes one per request so a transaction the dapp
/// stopped waiting for (disconnect, expiry, lock) is never sent: `Err` aborts
/// with that text and nothing leaves the wallet.
pub type BeforeSend = std::sync::Arc<dyn Fn() -> Result<(), String> + Send + Sync>;

/// How every failure of `eth_sendRawTransaction` reads — the signed
/// transaction was handed to the node — ahead of the node's or the transport's
/// own words.
pub const BROADCAST_FAILED: &str = "broadcast failed";

/// What a [`BeforeSend`] hook returns when the request it guards is no longer
/// live. User-facing (review error / pane notice), never sent to a dapp.
pub const STILL_WANTED_REFUSAL: &str =
    "the dapp stopped waiting before broadcast — nothing was sent";

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
    /// `Some` ⇒ called after `assert_from_equals_signer`, before
    /// `send_raw_transaction`; `Err` aborts the broadcast. (WalletConnect.)
    pub before_send: Option<BeforeSend>,
}

/// Run the guards' [`BeforeSend`] hook, if any. Shared with the Safe executor
/// broadcast ([`crate::safe::tx::execute_safe_tx_guarded`]) so both walls run
/// the hook at the same point: signature in hand, nothing broadcast yet.
pub(crate) fn run_before_send(guards: &Guards) -> Result<(), String> {
    match &guards.before_send {
        Some(check) => check(),
        None => Ok(()),
    }
}

/// Why a broadcast stopped: before the signed transaction left the wallet, or
/// after it was handed to the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastError {
    /// Nothing left the wallet — a guard or the liveness hook refused, a read
    /// failed, the signer declined. Trying again is a fresh attempt.
    NotSent(String),
    /// `eth_sendRawTransaction` was attempted and no hash came back. A reply
    /// lost on its way back (a dropped Tor circuit, a timeout) looks exactly
    /// like this, so the node may well have accepted the transaction: it may be
    /// on its way. `raw` is the exact signed envelope and `hash` its hash.
    /// Sending `raw` again is idempotent — a node keys it by `hash`, and its
    /// nonce can be used only once. Signing the same intent again is not: that
    /// is a second, distinct transaction.
    Unconfirmed {
        hash: TxHash,
        raw: Bytes,
        msg: String,
    },
    /// `eth_sendRawTransaction` was answered with a refusal that judges the
    /// signed bytes themselves invalid — under any node's rules, whatever the
    /// chain's state ([`invalid_everywhere`]). No node can hold them, so nothing
    /// is on its way; the same bytes would only be refused again.
    Refused(String),
}

impl BroadcastError {
    /// The user-facing text — exactly what [`broadcast`] returns for it.
    pub fn into_text(self) -> String {
        match self {
            Self::NotSent(msg) | Self::Unconfirmed { msg, .. } | Self::Refused(msg) => msg,
        }
    }
}

/// The node's own words for a transaction that is invalid as signed: too little
/// gas for its calldata, a gas limit over the protocol's per-transaction cap, a
/// signature or chain id that doesn't check out, a type or fee shape the chain
/// rejects. Each is a verdict on the bytes alone, so every node refuses them
/// alike. Refusals that hang on one node's configuration (its fee cap, its size
/// limit) or on the chain's state (a nonce already used, the balance, the
/// block's gas limit) are not here: another node may still have taken the
/// transaction.
const INVALID_EVERYWHERE: &[&str] = &[
    "intrinsic gas too low",
    "floor data gas",
    "transaction gas limit too high",
    "invalid sender",
    "invalid chain id",
    "transaction type not supported",
    "tx type not supported",
    "max priority fee per gas higher than max fee per gas",
];

/// Whether `e` is the node answering `eth_sendRawTransaction` with a refusal
/// that judges the transaction invalid on any node ([`INVALID_EVERYWHERE`]).
/// Anything else — a transport failure, a timeout, an error in other words —
/// leaves the transaction's fate unknown.
fn invalid_everywhere(
    e: &alloy::transports::RpcError<alloy::transports::TransportErrorKind>,
) -> bool {
    e.as_error_resp().is_some_and(|payload| {
        let message = payload.message.to_lowercase();
        INVALID_EVERYWHERE.iter().any(|m| message.contains(m))
    })
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
    broadcast_detailed(provider, signers, expected_from, fees, call, guards)
        .await
        .map_err(BroadcastError::into_text)
}

/// [`broadcast`], telling a failure before anything left the wallet apart from
/// one after the transaction was handed to the node ([`BroadcastError`]). The
/// texts are identical.
pub async fn broadcast_detailed(
    provider: &RootProvider<Ethereum>,
    signers: LiveSigners<'_>,
    expected_from: Address,
    fees: Fees,
    call: BroadcastCall,
    guards: Guards,
) -> Result<TxHash, BroadcastError> {
    use BroadcastError::NotSent;
    let LiveSigners::One(signer) = signers;

    // ── pre-sign guards ──
    if let Some(recipient) = guards.zero_recipient
        && recipient.is_zero()
    {
        warn!(from = %expected_from, "broadcast: refusing zero-address recipient");
        return Err(NotSent("refusing to send to the zero address".to_string()));
    }
    if let Some((frozen, current)) = guards.stale_terms
        && frozen != current
    {
        warn!(from = %expected_from, "broadcast: refusing stale terms");
        return Err(NotSent(
            "quote no longer matches the reviewed transaction — review again".to_string(),
        ));
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
            let gas_limit = provider.estimate_gas(req).await.map_err(|e| {
                NotSent(format!(
                    "estimate_gas: {}",
                    crate::net::redact_urls(&e.to_string())
                ))
            })?;
            let f = provider.estimate_eip1559_fees().await.map_err(|e| {
                NotSent(format!(
                    "estimate_eip1559_fees: {}",
                    crate::net::redact_urls(&e.to_string())
                ))
            })?;
            let nonce = provider
                .get_transaction_count(expected_from)
                .pending()
                .await
                .map_err(|e| {
                    NotSent(format!(
                        "get_transaction_count: {}",
                        crate::net::redact_urls(&e.to_string())
                    ))
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
        let balance = provider.get_balance(expected_from).await.map_err(|e| {
            NotSent(format!(
                "get_balance: {}",
                crate::net::redact_urls(&e.to_string())
            ))
        })?;
        let max_gas_cost = U256::from(gas_limit).saturating_mul(U256::from(max_fee_per_gas));
        let required = call.value.saturating_add(max_gas_cost);
        if balance < required {
            let what = if call.value > U256::ZERO {
                "the swap amount + fee + network gas"
            } else {
                "network gas"
            };
            return Err(NotSent(format!(
                "not enough ETH for {what}: need ~{} ETH, have {} ETH",
                fmt_eth(required),
                fmt_eth(balance),
            )));
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
            return Err(NotSent(crate::wallet::friendly_signer_error(&e)));
        }
    };

    assert_from_equals_signer(&sig, sighash, expected_from).map_err(NotSent)?;
    debug!("broadcast: signed; from == signer verified");

    // Last chance to abort: the signature exists but nothing has left the
    // wallet. A refusal here discards the signed envelope.
    if let Err(e) = run_before_send(&guards) {
        warn!(error = %e, "broadcast: before-send hook refused; nothing broadcast");
        return Err(NotSent(e));
    }

    let envelope: TxEnvelope = tx.into_signed(sig).into();
    let signed_hash = *envelope.tx_hash();
    let raw = envelope.encoded_2718();
    debug!(raw_len = raw.len(), "broadcast: broadcasting raw envelope");

    let pending = provider.send_raw_transaction(&raw).await.map_err(|e| {
        // Scrub the key-bearing RPC URL before this hits the warn log or the
        // returned (UI-visible) error; the "insufficient funds" massage below
        // still matches because redaction only removes URLs.
        let msg = crate::net::redact_urls(&e.to_string());
        let refused = invalid_everywhere(&e);
        if refused {
            warn!(
                error = %msg,
                hash = %format!("{signed_hash:#x}"),
                "broadcast: the node refused the transaction as invalid",
            );
        } else {
            warn!(
                error = %msg,
                hash = %format!("{signed_hash:#x}"),
                "broadcast: broadcast failed; the node may still have the transaction",
            );
        }
        let msg = if guards.insufficient_funds_massage
            && msg.to_lowercase().contains("insufficient funds")
        {
            // Belt-and-suspenders: the balance pre-flight should catch this, but a
            // gas-price spike between estimate and broadcast can still trip it.
            "not enough ETH to cover the swap amount + network gas".to_string()
        } else {
            format!("{BROADCAST_FAILED}: {msg}")
        };
        // The request was on the wire: unless the node's answer rules the bytes
        // out on every node, the transaction's fate is unknown, never "not sent".
        if refused {
            BroadcastError::Refused(msg)
        } else {
            BroadcastError::Unconfirmed {
                hash: signed_hash,
                raw: Bytes::from(raw.clone()),
                msg,
            }
        }
    })?;

    let hash = *pending.tx_hash();
    info!(hash = %format!("{hash:#x}"), "broadcast: ok");
    Ok(hash)
}

/// Hand the node an already-signed transaction again, byte for byte — never a
/// re-signed one. Idempotent: the node keys it by its hash, and its nonce can be
/// used once. `hash` must be `raw`'s own hash, so only the transaction the user
/// signed can go out under it ([`BroadcastError::NotSent`] otherwise).
///
/// A failure is classed as [`broadcast_detailed`]'s are: [`BroadcastError::Refused`]
/// when the node judges these bytes invalid on any node — so no node could have
/// taken them, on this send or an earlier one — and
/// [`BroadcastError::Unconfirmed`] for anything else.
pub async fn resend_signed(
    provider: &RootProvider<Ethereum>,
    hash: TxHash,
    raw: &Bytes,
) -> Result<TxHash, BroadcastError> {
    if alloy::primitives::keccak256(raw) != hash {
        warn!("broadcast: refusing to re-send bytes that aren't the signed transaction");
        return Err(BroadcastError::NotSent(
            "internal: the signed transaction doesn't match its hash".to_string(),
        ));
    }
    info!(hash = %format!("{hash:#x}"), "broadcast: re-sending the signed transaction");
    provider
        .send_raw_transaction(raw)
        .await
        .map(|pending| *pending.tx_hash())
        .map_err(|e| {
            let msg = crate::net::redact_urls(&e.to_string());
            let text = format!("{BROADCAST_FAILED}: {msg}");
            if invalid_everywhere(&e) {
                warn!(
                    error = %msg,
                    hash = %format!("{hash:#x}"),
                    "broadcast: the node refused the re-sent transaction as invalid",
                );
                BroadcastError::Refused(text)
            } else {
                warn!(error = %msg, "broadcast: re-send failed");
                BroadcastError::Unconfirmed {
                    hash,
                    raw: raw.clone(),
                    msg: text,
                }
            }
        })
}

/// Whether the node knows transaction `hash` — in its pool or mined. `Err` when
/// it couldn't say (the text is URL-redacted).
pub async fn node_knows_transaction(
    provider: &RootProvider<Ethereum>,
    hash: TxHash,
) -> Result<bool, String> {
    let redact = |what: &str, e: &dyn std::fmt::Display| {
        format!("{what}: {}", crate::net::redact_urls(&e.to_string()))
    };
    let pooled = provider
        .get_transaction_by_hash(hash)
        .await
        .map_err(|e| redact("get_transaction_by_hash", &e))?;
    if pooled.is_some() {
        return Ok(true);
    }
    let mined = provider
        .get_transaction_receipt(hash)
        .await
        .map_err(|e| redact("get_transaction_receipt", &e))?;
    Ok(mined.is_some())
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

    #[test]
    fn guards_default_has_no_before_send() {
        let g = Guards::default();
        assert!(g.before_send.is_none());
        assert_eq!(run_before_send(&g), Ok(()));
    }

    /// The liveness hook runs after the signature exists and before the
    /// broadcast: a refusal surfaces verbatim (not "broadcast failed"), proving
    /// `send_raw_transaction` was never reached — and the hook was called once.
    #[tokio::test]
    async fn run_before_send_aborts_on_err() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let hook: BeforeSend = Arc::new(move || {
            seen.fetch_add(1, Ordering::SeqCst);
            Err(STILL_WANTED_REFUSAL.to_string())
        });
        assert_eq!(
            run_before_send(&Guards {
                before_send: Some(hook.clone()),
                ..Default::default()
            }),
            Err(STILL_WANTED_REFUSAL.to_string())
        );

        let signer = KaoSigner::Local(PrivateKeySigner::random());
        let err = broadcast(
            &dead_provider(),
            LiveSigners::One(&signer),
            signer.address(),
            quoted(),
            call_to(address!("000000000000000000000000000000000000dEaD")),
            Guards {
                before_send: Some(hook),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err, STILL_WANTED_REFUSAL);
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        // A hook that says "still wanted" lets the send through to the
        // (dead) provider.
        let ok: BeforeSend = Arc::new(|| Ok(()));
        let err = broadcast(
            &dead_provider(),
            LiveSigners::One(&signer),
            signer.address(),
            quoted(),
            call_to(address!("000000000000000000000000000000000000dEaD")),
            Guards {
                before_send: Some(ok),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(err.contains("broadcast failed"), "got: {err}");
    }

    /// Once `eth_sendRawTransaction` was attempted, a failure is never "not sent": it carries
    /// the exact signed envelope and its hash, so a caller can only ever send those bytes again.
    /// The text is what `broadcast` has always returned.
    #[tokio::test]
    async fn failure_after_the_send_attempt_is_unconfirmed_with_the_signed_bytes() {
        use alloy::eips::eip2718::Decodable2718;
        let signer = KaoSigner::Local(PrivateKeySigner::random());
        let to = address!("000000000000000000000000000000000000dEaD");
        let err = broadcast_detailed(
            &dead_provider(),
            LiveSigners::One(&signer),
            signer.address(),
            quoted(),
            call_to(to),
            Guards::default(),
        )
        .await
        .unwrap_err();
        let BroadcastError::Unconfirmed { hash, raw, msg } = err.clone() else {
            panic!("expected an unconfirmed broadcast, got {err:?}");
        };
        assert!(msg.starts_with("broadcast failed"), "{msg}");
        assert_eq!(alloy::primitives::keccak256(&raw), hash);
        let TxEnvelope::Eip1559(signed) = TxEnvelope::decode_2718(&mut raw.as_ref()).unwrap()
        else {
            panic!("an EIP-1559 envelope");
        };
        assert_eq!(*signed.hash(), hash);
        assert_eq!(signed.tx().to, TxKind::Call(to));
        assert_eq!(
            signed
                .signature()
                .recover_address_from_prehash(&signed.tx().signature_hash())
                .unwrap(),
            signer.address()
        );
        assert_eq!(err.into_text(), msg);
    }

    /// Every refusal before the send attempt is `NotSent`, with `broadcast`'s text.
    #[tokio::test]
    async fn refusals_before_the_send_attempt_are_not_sent() {
        let signer = KaoSigner::Local(PrivateKeySigner::random());
        let refuse: BeforeSend = std::sync::Arc::new(|| Err(STILL_WANTED_REFUSAL.to_string()));
        for (from, guards) in [
            (
                signer.address(),
                Guards {
                    zero_recipient: Some(Address::ZERO),
                    ..Default::default()
                },
            ),
            (
                signer.address(),
                Guards {
                    before_send: Some(refuse),
                    ..Default::default()
                },
            ),
            (
                address!("00000000000000000000000000000000000000aa"),
                Guards::default(),
            ),
        ] {
            let err = broadcast_detailed(
                &dead_provider(),
                LiveSigners::One(&signer),
                from,
                quoted(),
                call_to(address!("000000000000000000000000000000000000dEaD")),
                guards,
            )
            .await
            .unwrap_err();
            assert!(matches!(err, BroadcastError::NotSent(_)), "{err:?}");
        }
    }

    /// Only the bytes whose hash is given can go out under it: anything else is refused before
    /// the provider is touched.
    #[tokio::test]
    async fn resend_refuses_bytes_that_arent_the_hashed_transaction() {
        let raw = Bytes::from_static(&[0x02, 0xc0, 0x01]);
        let err = resend_signed(&dead_provider(), B256::repeat_byte(7), &raw)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, BroadcastError::NotSent(t) if t.starts_with("internal")),
            "{err:?}"
        );
        // The right hash reaches the (dead) provider: no answer, so its fate is unknown.
        let hash = alloy::primitives::keccak256(&raw);
        let err = resend_signed(&dead_provider(), hash, &raw)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, BroadcastError::Unconfirmed { hash: h, raw: r, msg }
                if *h == hash && *r == raw && msg.starts_with("broadcast failed")),
            "{err:?}"
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
