//! Dapp signing: synchronous step builders (open time), async prepare tasks for transactions, and the
//! sign tasks. Every task re-derives its pin, checks `signer == from` before any device prompt, recovers
//! the signature after, consults `WcRuntime::is_live` (directly or via `before_send`) before anything
//! irreversible, and puts a parked signer back on every path. A child of `wallet_dashboard`, so it uses
//! the coordinator's private helpers through `super::`.
//!
//! Each `spawn_*` is a thin shell: it turns the runtime into the request's liveness guard
//! ([`WcRuntime::before_send_guard`]), runs a body that takes only that guard, and notes a stale pin
//! on the runtime before handing the result to `Message::Signed`. The bodies never see the runtime,
//! so the ordering they enforce — pin, liveness, signer, sign, recover, liveness — is testable
//! against a scripted guard.

use std::collections::HashMap;

use alloy::primitives::Signature;

use super::sign_review::{
    MessageReview, SignStep, SigningOwner, TypedDataReview, WcOriginCard, WcSafeMessageInner,
    WcSafeMessageReview, WcTxFeesReview,
};
use super::*;
use crate::chain::NetworkId;
use crate::safe::tx::Operation;
use crate::sign::broadcast::{BeforeSend, BroadcastError};
use crate::sign::digest::Eip712Digests;
use crate::wallet::tx::{SendPlan, SendToken, TxQuote};
use crate::walletconnect::{self as wc, FailureClass, WcKey, runtime::WcRuntime};

pub(super) enum WcSafeMessageSource<'a> {
    Personal(&'a wc::PersonalSign),
    Typed(&'a wc::TypedRequest),
}

// ── step builders (open time, synchronous) ────────────────────────────────────

/// [WcOrigin, WcMessage]; pin = eip191_hash(message).
pub(super) fn personal_steps(
    origin: WcOriginCard,
    from: Address,
    net: crate::chain::NetworkId,
    call: &wc::PersonalSign,
    hardware: bool,
) -> (Vec<SignStep>, B256) {
    let eip191_hash = wc::message::eip191_hash(&call.message);
    let review = MessageReview {
        from,
        net,
        raw: call.message.clone(),
        shape: call.shape.clone(),
        eip191_hash,
        siwe: call.siwe.clone(),
        hardware,
    };
    (
        vec![SignStep::WcOrigin(origin), SignStep::WcMessage(review)],
        eip191_hash,
    )
}

/// [WcOrigin, WcTyped]; pin = call.checked.digests.
pub(super) fn typed_steps(
    origin: WcOriginCard,
    from: Address,
    net: crate::chain::NetworkId,
    req: &wc::TypedRequest,
    hash_mode: bool,
    safe_label: Option<String>,
) -> (Vec<SignStep>, crate::sign::digest::Eip712Digests) {
    let pin = req.checked.digests;
    let review = TypedDataReview {
        from,
        net,
        checked: req.checked.clone(),
        hash_mode_device: hash_mode,
        safe_label,
        // A SafeTx's call is decoded by the prepare (`prepare_safe_tx_call`).
        inner_leg: None,
    };
    (
        vec![SignStep::WcOrigin(origin), SignStep::WcTyped(review)],
        pin,
    )
}

/// [WcOrigin, WcSafeMessage]; returns (steps, data_hash, message_hash pin).
///
/// `data_hash` is what the dapp will hand to `isValidSignature`: the EIP-191 digest of a
/// `personal_sign`, or the dapp's own EIP-712 digest. The owners never sign it directly — they sign
/// `SafeMessage(bytes message = data_hash)` under the Safe's domain, whose hash is the pin. The inner
/// review is display-only (`hardware` / `hash_mode_device` stay false: no device ever shows the dapp's
/// message here, only the SafeMessage hashes).
pub(super) fn safe_message_steps(
    origin: WcOriginCard,
    safe: Address,
    chain: Chain,
    threshold: u32,
    owner_count: u32,
    signers: Vec<SigningOwner>,
    inner: WcSafeMessageSource<'_>,
) -> (Vec<SignStep>, B256, B256) {
    let net = NetworkId::Builtin(chain);
    let (inner, data_hash) = match inner {
        WcSafeMessageSource::Personal(p) => {
            let digest = wc::message::eip191_hash(&p.message);
            let review = MessageReview {
                from: safe,
                net,
                raw: p.message.clone(),
                shape: p.shape.clone(),
                eip191_hash: digest,
                siwe: p.siwe.clone(),
                hardware: false,
            };
            (WcSafeMessageInner::Personal(review), digest)
        }
        WcSafeMessageSource::Typed(t) => {
            let review = TypedDataReview {
                from: safe,
                net,
                checked: t.checked.clone(),
                hash_mode_device: false,
                safe_label: None,
                inner_leg: None,
            };
            // `checked.digests.digest` was asserted equal to `eip712_signing_hash()` at admission.
            (WcSafeMessageInner::Typed(review), t.checked.digests.digest)
        }
    };
    let message_hash = crate::cow::safe_sig::safe_message_hash(data_hash, safe, chain);
    let review = WcSafeMessageReview {
        inner,
        safe,
        chain,
        threshold: u8::try_from(threshold).unwrap_or(u8::MAX),
        owner_count: u8::try_from(owner_count).unwrap_or(u8::MAX),
        signers,
        data_hash,
        message_hash,
        eip712: crate::cow::safe_sig::safe_message_digests(data_hash, safe, chain),
    };
    (
        vec![SignStep::WcOrigin(origin), SignStep::WcSafeMessage(review)],
        data_hash,
        message_hash,
    )
}

// ── prepare (transactions) ────────────────────────────────────────────────────

/// The least gas any transaction can carry (the intrinsic cost of a plain transfer).
const MIN_TX_GAS: u64 = 21_000;
/// Bound on the node's estimate error quoted in the review.
const MAX_ESTIMATE_ERROR_CHARS: usize = 240;

/// The least gas a call carrying `data` can be included with: the intrinsic cost (21 000, plus 16
/// per non-zero and 4 per zero calldata byte) or, when higher, the EIP-7623 calldata floor (21 000
/// plus 10 per token, a non-zero byte counting 4 tokens and a zero byte 1). A limit under it can't
/// be included wherever the floor is live; on a chain without it this errs on the safe side, as it
/// only decides whether the dapp's own limit may stand in for a failed estimate.
fn intrinsic_gas(data: &[u8]) -> u64 {
    let zero = data.iter().filter(|b| **b == 0).count() as u64;
    let non_zero = (data.len() as u64).saturating_sub(zero);
    let standard = MIN_TX_GAS
        .saturating_add(non_zero.saturating_mul(16))
        .saturating_add(zero.saturating_mul(4));
    let tokens = non_zero.saturating_mul(4).saturating_add(zero);
    let floor = MIN_TX_GAS.saturating_add(tokens.saturating_mul(10));
    standard.max(floor)
}

/// provider_for → build_quote_with(SendToken::Call, dapp gas as the fallback) → choose_gas_limit
/// (rewrite gas_limit + eth_cost_wei) → decode_leg → 7702 disclosure → owner_action_banner →
/// [Delegation?, RawTx, WcTxFees].
///
/// The quote is the one the review pins and the broadcast signs verbatim (`Fees::Quoted`): estimated
/// gas under Kao's gas-limit policy (`request::choose_gas_limit`), the node's EIP-1559 fees and the
/// pending nonce. Whatever fee, nonce or type the dapp sent never reaches this task: the coordinator
/// discloses it in the review's note.
///
/// An estimate that fails (the call reverts, the account can't pay) takes the dapp's own gas limit
/// when it sent a usable one: Kao's node may lag the dapp's by a block (just after an approve), or
/// mis-model the path. The review then carries the node's reason in red and Confirm reads
/// "Sign anyway ⚠". Without the dapp's limit there is nothing to sign with, so the failure is a
/// prepare error: the overlay keeps it and Confirm stays disabled.
pub(super) async fn prepare_eoa_tx(
    network: Arc<dyn BalanceFetcher>,
    plan: SendPlan,
    dapp_gas: Option<u64>,
    known_safes: Vec<(Address, String)>,
    local_names: HashMap<Address, String>,
    balance_wei: Option<U256>,
) -> Result<Vec<SignStep>, String> {
    if !matches!(plan.token, SendToken::Call { .. }) {
        return Err("internal: a dapp transaction must be quoted as a call".to_string());
    }
    let (_, _, data) = plan.tx_target();
    let provider = provider_for(&network, plan.chain)
        .await
        .ok_or_else(|| "no execution RPCs configured".to_string())?;
    // Only a limit a node could include: at least what the calldata costs to carry, at most the
    // per-transaction cap (itself under Kao's own ceiling).
    let fallback =
        dapp_gas.filter(|g| (intrinsic_gas(&data)..=wc::request::MAX_TX_GAS).contains(g));
    // A failed estimate's error can quote the contract's own revert string — dapp-controlled text,
    // shown as the prepare error: escaped, so a newline or a bidi override is seen, not acted on.
    let (mut quote, estimate_failed) =
        crate::wallet::tx::build_quote_with(&provider, network.clone(), &plan, fallback)
            .await
            .map_err(|e| crate::sanitize::escape_and_clamp(&e, MAX_ESTIMATE_ERROR_CHARS))?;
    let (gas_limit, gas_note) = match &estimate_failed {
        None => wc::request::choose_gas_limit(quote.gas_limit, dapp_gas, !data.is_empty())
            .map_err(|refusal| refusal.detail)?,
        Some(_) => (
            quote.gas_limit,
            wc::GasNote::DappUnestimated {
                dapp: quote.gas_limit,
            },
        ),
    };
    // Ethereum nodes refuse any transaction above the per-transaction cap (EIP-7825, since
    // Fusaka). Headroom never crosses it (`choose_gas_limit`), so only an estimate that is itself
    // above it gets here — a transaction that can never be included, so it isn't offered.
    if plan.chain == NetworkId::Builtin(Chain::Mainnet) && gas_limit > wc::request::MAX_TX_GAS {
        return Err(format!(
            "this transaction needs {gas_limit} gas; Ethereum refuses any transaction above {} \
             (EIP-7825)",
            wc::request::MAX_TX_GAS
        ));
    }
    quote.gas_limit = gas_limit;
    quote.eth_cost_wei = U256::from(gas_limit).saturating_mul(U256::from(quote.max_fee_per_gas));
    debug!(
        chain_id = plan.chain.chain_id(),
        gas_limit,
        note = ?gas_note,
        nonce = quote.nonce,
        "wc: eoa tx quoted",
    );
    // The reason can quote the contract's own revert string: dapp-controlled text, escaped for the
    // red banner like the prepare error above.
    let estimate_failed =
        estimate_failed.map(|e| crate::sanitize::escape_and_clamp(&e, MAX_ESTIMATE_ERROR_CHARS));
    let priced = PricedTx {
        plan,
        quote,
        gas_note,
        estimate_failed,
    };
    eoa_tx_steps(
        &network,
        &provider,
        priced,
        &known_safes,
        &local_names,
        balance_wei,
    )
    .await
}

/// A dapp transaction priced for review — what [`eoa_tx_steps`] lays out.
struct PricedTx {
    plan: SendPlan,
    quote: TxQuote,
    gas_note: wc::GasNote,
    estimate_failed: Option<String>,
}

/// The review of a priced dapp transaction: [Delegation?, RawTx, WcTxFees].
async fn eoa_tx_steps(
    network: &Arc<dyn BalanceFetcher>,
    provider: &alloy::providers::RootProvider<alloy::network::Ethereum>,
    priced: PricedTx,
    known_safes: &[(Address, String)],
    local_names: &HashMap<Address, String>,
    balance_wei: Option<U256>,
) -> Result<Vec<SignStep>, String> {
    use alloy::providers::Provider;
    let PricedTx {
        plan,
        quote,
        gas_note,
        estimate_failed,
    } = priced;
    let (to, value, data) = plan.tx_target();

    // Clear-sign the call exactly as the Transaction Builder's single-call leg does: ERC-7730 first,
    // heuristic fallback; custom networks stay undecoded (no verified chain to resolve against).
    let decoded = decode_leg(
        network.as_ref(),
        plan.chain,
        plan.from,
        to,
        data.clone(),
        value,
        local_names,
    )
    .await;
    let leg = sign_review::ReviewLeg {
        title: if data.is_empty() {
            format!("Send to {}", short_address(to))
        } else {
            format!("Call to {}", short_address(to))
        },
        to,
        value,
        net: plan.chain,
        // A call into one of the user's own Safes that confirms or executes a Safe transaction
        // (`approveHash` / `execTransaction`) is an owner action dressed as a dapp call.
        self_admin: wc::request::owner_action_banner(to, &data, known_safes),
        calldata: data,
        decoded: Box::new(decoded),
        sub_legs: Vec::new(),
    };

    let mut steps = Vec::with_capacity(3);
    // An account carrying an EIP-7702 designator runs contract code as `from` for the duration of
    // this call. Nothing here installs or changes it, so this is a disclosure, read live (the
    // Transaction Builder single-call pattern). Built-in chains only: there is no verified code read
    // on a custom network.
    if let Some(chain) = plan.chain.builtin() {
        let code = network.get_code(plan.from, chain).await?.value;
        if let Some(current) = crate::txbuilder::eip7702::delegated_to(&code) {
            steps.push(SignStep::Delegation(sign_review::DelegationReview {
                delegate: current,
                delegate_label: delegate_label(current, chain),
                authority: plan.from,
                chain_id: chain.chain_id(),
                net: plan.chain,
                already_active: true,
                incumbent: Some(current),
                auth_nonce: None,
                auth_digest: None,
            }));
        }
    }
    steps.push(SignStep::RawTx(leg));

    // The caller's balance when it has one; otherwise a live read (best-effort — an unknown balance
    // only means the review can't warn about it).
    let balance_wei = match balance_wei {
        Some(b) => Some(b),
        None => provider.get_balance(plan.from).await.ok(),
    };
    let max_total_wei = value.saturating_add(quote.eth_cost_wei);
    let sim_reverted = quote.sim.is_revert();
    steps.push(SignStep::WcTxFees(WcTxFeesReview {
        quote,
        gas_note,
        max_total_wei,
        balance_wei,
        unverified_network: plan.chain.is_custom(),
        sim_reverted,
        estimate_failed,
    }));
    Ok(steps)
}

/// The review of a request whose transaction already left the wallet unacknowledged, opened again
/// (its first overlay was lost). Nothing is priced: the steps describe the signed envelope itself,
/// decoded from its bytes — exactly what may be on its way, and exactly what a re-send sends.
/// Refused unless those bytes are an EIP-1559 transaction of this very call, signed by `plan.from`.
async fn prepare_unconfirmed_eoa_tx(
    network: Arc<dyn BalanceFetcher>,
    plan: SendPlan,
    tx: wc::UnconfirmedTx,
    known_safes: Vec<(Address, String)>,
    local_names: HashMap<Address, String>,
    balance_wei: Option<U256>,
) -> Result<Vec<SignStep>, String> {
    let quote = signed_quote(&plan, &tx)?;
    let provider = provider_for(&network, plan.chain)
        .await
        .ok_or_else(|| "no execution RPCs configured".to_string())?;
    let priced = PricedTx {
        plan,
        quote,
        gas_note: wc::GasNote::AsSigned,
        estimate_failed: None,
    };
    eoa_tx_steps(
        &network,
        &provider,
        priced,
        &known_safes,
        &local_names,
        balance_wei,
    )
    .await
}

/// The numbers a signed envelope carries, as the quote the review pins — if it is exactly `plan`'s
/// call, at `tx.nonce`, signed by `plan.from`.
fn signed_quote(plan: &SendPlan, tx: &wc::UnconfirmedTx) -> Result<TxQuote, String> {
    use alloy::consensus::{SignableTransaction, TxEnvelope};
    use alloy::eips::eip2718::Decodable2718;
    let mismatch = || {
        error!("wc: the transaction kept for this request doesn't describe it");
        "internal: the transaction already sent for this request doesn't match it".to_string()
    };
    let Ok(TxEnvelope::Eip1559(signed)) = TxEnvelope::decode_2718(&mut tx.raw.as_ref()) else {
        return Err(mismatch());
    };
    let t = signed.tx();
    let (to, value, data) = plan.tx_target();
    let signer = signed
        .signature()
        .recover_address_from_prehash(&t.signature_hash())
        .ok();
    if *signed.hash() != tx.hash
        || t.chain_id != plan.chain.chain_id()
        || t.nonce != tx.nonce
        || t.to != alloy::primitives::TxKind::Call(to)
        || t.value != value
        || t.input != data
        || !t.access_list.is_empty()
        || signer != Some(plan.from)
    {
        return Err(mismatch());
    }
    Ok(TxQuote {
        plan: plan.clone(),
        gas_limit: t.gas_limit,
        max_fee_per_gas: t.max_fee_per_gas,
        max_priority_fee_per_gas: t.max_priority_fee_per_gas,
        nonce: t.nonce,
        eth_cost_wei: U256::from(t.gas_limit).saturating_mul(U256::from(t.max_fee_per_gas)),
        sim: crate::wallet::sim::SimulationResult::unavailable(),
    })
}

/// The review of a dapp's Safe transaction whose execution already left the wallet unacknowledged,
/// opened again (its first overlay was lost). Nothing is pinned or signed: the steps describe the
/// executor's signed transaction itself, decoded from its bytes — exactly what may be on its way,
/// and exactly what a re-send sends. Refused unless those bytes are an EIP-1559 `execTransaction`
/// of this very call, on this Safe and chain.
pub(super) async fn prepare_unconfirmed_safe_exec(
    network: Arc<dyn BalanceFetcher>,
    sreq: tx_builder::SafeBatchRequest,
    tx: wc::UnconfirmedTx,
    known_safes: Vec<(Address, String)>,
    local_names: HashMap<Address, String>,
) -> Result<Vec<SignStep>, String> {
    let plan = executor_plan(&sreq, &tx)?;
    let quote = signed_quote(&plan, &tx)?;
    let provider = provider_for(&network, plan.chain)
        .await
        .ok_or_else(|| "no execution RPCs configured".to_string())?;
    let priced = PricedTx {
        plan,
        quote,
        gas_note: wc::GasNote::AsSigned,
        estimate_failed: None,
    };
    eoa_tx_steps(
        &network,
        &provider,
        priced,
        &known_safes,
        &local_names,
        None,
    )
    .await
}

/// The executor's transaction kept for a Safe request, as the plain call it is — from its signer to
/// the Safe, `execTransaction` of exactly the request's call — or why it isn't. [`signed_quote`]
/// then holds the rest of the envelope (hash, chain, nonce, signer) against it.
fn executor_plan(
    sreq: &tx_builder::SafeBatchRequest,
    tx: &wc::UnconfirmedTx,
) -> Result<SendPlan, String> {
    use alloy::consensus::{SignableTransaction, TxEnvelope};
    use alloy::eips::eip2718::Decodable2718;
    use alloy::sol_types::SolCall;
    let mismatch = || {
        error!("wc: the execution kept for this Safe request doesn't describe it");
        "internal: the transaction already sent for this request doesn't match it".to_string()
    };
    let Ok(TxEnvelope::Eip1559(signed)) = TxEnvelope::decode_2718(&mut tx.raw.as_ref()) else {
        return Err(mismatch());
    };
    let t = signed.tx();
    let call = crate::safe::execTransactionCall::abi_decode(&t.input).map_err(|_| mismatch())?;
    let from = signed
        .signature()
        .recover_address_from_prehash(&t.signature_hash())
        .map_err(|_| mismatch())?;
    if t.to != alloy::primitives::TxKind::Call(sreq.safe)
        || call.to != sreq.input.to
        || call.value != sreq.input.value
        || call.data != sreq.input.data
        || call.operation != Operation::Call as u8
    {
        return Err(mismatch());
    }
    Ok(SendPlan {
        from,
        recipient: sreq.safe,
        token: SendToken::Call {
            data: t.input.clone(),
        },
        amount_units: U256::ZERO,
        chain: NetworkId::Builtin(sreq.chain),
    })
}

/// → Message::SignReviewPrepared { seq, steps }.
pub(super) fn spawn_prepare_unconfirmed_safe_exec(
    network: Arc<dyn BalanceFetcher>,
    seq: u64,
    sreq: tx_builder::SafeBatchRequest,
    tx: wc::UnconfirmedTx,
    known_safes: Vec<(Address, String)>,
    local_names: HashMap<Address, String>,
) -> Task<Message> {
    Task::perform(
        prepare_unconfirmed_safe_exec(network, sreq, tx, known_safes, local_names),
        move |steps| Message::SignReviewPrepared { seq, steps },
    )
}

/// → Message::SignReviewPrepared { seq, steps }.
pub(super) fn spawn_prepare_unconfirmed_eoa_tx(
    network: Arc<dyn BalanceFetcher>,
    seq: u64,
    plan: SendPlan,
    tx: wc::UnconfirmedTx,
    known_safes: Vec<(Address, String)>,
    local_names: HashMap<Address, String>,
    balance_wei: Option<U256>,
) -> Task<Message> {
    Task::perform(
        prepare_unconfirmed_eoa_tx(network, plan, tx, known_safes, local_names, balance_wei),
        move |steps| Message::SignReviewPrepared { seq, steps },
    )
}

/// → Message::SignReviewPrepared { seq, steps }.
pub(super) fn spawn_prepare_eoa_tx(
    network: Arc<dyn BalanceFetcher>,
    seq: u64,
    plan: SendPlan,
    dapp_gas: Option<u64>,
    known_safes: Vec<(Address, String)>,
    local_names: HashMap<Address, String>,
    balance_wei: Option<U256>,
) -> Task<Message> {
    Task::perform(
        prepare_eoa_tx(
            network,
            plan,
            dapp_gas,
            known_safes,
            local_names,
            balance_wei,
        ),
        move |steps| Message::SignReviewPrepared { seq, steps },
    )
}

/// build_txbuilder_steps(BatchSignRequest::Safe(sreq /* operation == Call */), local_names, None) → SignReviewPrepared.
pub(super) fn spawn_prepare_safe_tx(
    network: Arc<dyn BalanceFetcher>,
    seq: u64,
    sreq: tx_builder::SafeBatchRequest,
    local_names: HashMap<Address, String>,
    known_safes: Vec<(Address, String)>,
) -> Task<Message> {
    Task::perform(
        prepare_safe_tx(network, sreq, local_names, known_safes),
        move |steps| Message::SignReviewPrepared { seq, steps },
    )
}

/// The body of [`spawn_prepare_safe_tx`]: the Transaction Builder's Safe prepare (trust, version,
/// queue-aware nonce, on-chain hash cross-check, live guard) over a single `Operation::Call`, then
/// what that Builder prepare leaves to its composer:
/// - a call into another of the user's Safes that confirms or executes a Safe transaction there
///   (`approveHash` / `execTransaction`) gets the owner-action banner the EOA path gives it — a
///   self-call keeps the Builder's own self-admin banner;
/// - a dry run of the call, as the Safe, against the chain as it stands. No composer simulated a
///   dapp's call before the review; this is the verdict the review shows and labels by. A
///   simulator that can't run leaves `preflight` without a verdict, never a refusal.
async fn prepare_safe_tx(
    network: Arc<dyn BalanceFetcher>,
    sreq: tx_builder::SafeBatchRequest,
    local_names: HashMap<Address, String>,
    known_safes: Vec<(Address, String)>,
) -> Result<Vec<SignStep>, String> {
    only_call(&sreq).map_err(|f| f.text)?;
    let mut steps = build_txbuilder_steps(
        network.as_ref(),
        tx_builder::BatchSignRequest::Safe(sreq.clone()),
        local_names,
        None,
    )
    .await?;
    let calls = safe_batch_inner_calls(&sreq)?;
    let preflight = match crate::txbuilder::sim::simulate_batch(
        network.clone(),
        sreq.chain,
        sreq.safe,
        crate::txbuilder::sim::to_steps(&calls),
    )
    .await
    {
        Ok(sim) => Some(sim),
        Err(e) => {
            warn!(error = %e, "wc: the Safe call's review-time simulation couldn't run");
            None
        }
    };
    for step in &mut steps {
        if let SignStep::SafeExec(x) = step {
            if x.inner.self_admin.is_none() {
                x.inner.self_admin =
                    wc::request::owner_action_banner(x.inner.to, &x.inner.calldata, &known_safes);
            }
            x.preflight = preflight.clone();
        }
    }
    Ok(steps)
}

/// → Message::SignReviewPrepared { seq, steps: [RawTx(the SafeTx's call)] }.
pub(super) fn spawn_prepare_safe_tx_call(
    network: Arc<dyn BalanceFetcher>,
    seq: u64,
    net: NetworkId,
    kind: wc::TypedKind,
    known_safes: Vec<(Address, String)>,
    local_names: HashMap<Address, String>,
) -> Task<Message> {
    Task::perform(
        prepare_safe_tx_call(network, net, kind, known_safes, local_names),
        move |steps| Message::SignReviewPrepared { seq, steps },
    )
}

/// The call a `SafeTx` owner confirmation would have its Safe make, decoded the way a Safe
/// transaction step decodes its inner call — clear-signed as the Safe, a call to the Safe itself
/// flagged as the multisig reconfiguring itself, an `approveHash` / `execTransaction` into another
/// of the user's Safes flagged as the owner action it is. A delegatecall to a canonical
/// `MultiSendCallOnly` library is a Safe{Wallet} batch: its sub-calls are unpacked from the signed
/// `data` and decoded one by one.
///
/// Lands as `[RawTx(leg)]`; `wc_on_prepared` moves the leg into the typed step it explains (it is
/// not a transaction this review signs), checking it against the typed data's own fields.
async fn prepare_safe_tx_call(
    network: Arc<dyn BalanceFetcher>,
    net: NetworkId,
    kind: wc::TypedKind,
    known_safes: Vec<(Address, String)>,
    local_names: HashMap<Address, String>,
) -> Result<Vec<SignStep>, String> {
    use crate::txbuilder::multisend::canonical_multisend_call_only;
    let wc::TypedKind::SafeTx {
        safe,
        to,
        value,
        data,
        operation,
        ..
    } = kind
    else {
        return Err("internal: only a SafeTx has a call to decode".to_string());
    };
    // Whose call it is: the Safe the domain names. A SafeTx naming none executes on no Safe
    // anyone can identify, so its call is decoded as nobody's.
    let sender = safe.unwrap_or(Address::ZERO);
    let delegatecall = operation == 1;
    let batch = if delegatecall && canonical_multisend_call_only(to).is_some() {
        decode_batch_sub_legs(network.as_ref(), net, sender, true, &data, &local_names)
            .await
            .inspect_err(|e| warn!(error = %e, "wc: a SafeTx MultiSend batch didn't unpack"))
            .ok()
            .filter(|legs| !legs.is_empty())
    } else {
        None
    };
    let (decoded, sub_legs) = match batch {
        Some(legs) => (crate::decode::clear_sign::DecodeResult::Empty, legs),
        None => (
            decode_leg(
                network.as_ref(),
                net,
                sender,
                to,
                data.clone(),
                value,
                &local_names,
            )
            .await,
            Vec::new(),
        ),
    };
    let self_admin = safe
        .and_then(|s| self_admin_warning(s, true, to, &data))
        .or_else(|| wc::request::owner_action_banner(to, &data, &known_safes));
    let leg = sign_review::ReviewLeg {
        title: match (delegatecall, sub_legs.len()) {
            (true, 0) => format!("Delegatecall to {}", short_address(to)),
            (true, n) => format!("MultiSend · {n} call{}", if n == 1 { "" } else { "s" }),
            (false, _) if data.is_empty() => format!("Send to {}", short_address(to)),
            (false, _) => format!("Call to {}", short_address(to)),
        },
        to,
        value,
        net,
        calldata: data,
        decoded: Box::new(decoded),
        sub_legs,
        self_admin,
    };
    Ok(vec![SignStep::RawTx(leg)])
}

// ── sign tasks ────────────────────────────────────────────────────────────────
// Each → Message::Signed { tag: SignTag::WalletConnect { key, kind }, signer, result }.

pub(super) fn spawn_sign_personal(
    rt: WcRuntime,
    key: WcKey,
    handoff: SignerHandoff,
    desc: AccountDescriptor,
    from: Address,
    message: Bytes,
    pin: B256,
) -> Task<Message> {
    let live = rt.before_send_guard(key.clone());
    let tag = SignTag::WalletConnect {
        key: key.clone(),
        kind: WcSignKind::Personal,
    };
    let inner = handoff.clone();
    Task::perform(
        async move {
            let result = sign_personal(&inner, &desc, from, &message, pin, &live).await;
            settle(&rt, &key, result)
        },
        move |result| Message::Signed {
            tag,
            signer: Some(handoff),
            result,
        },
    )
}

pub(super) fn spawn_sign_typed(
    rt: WcRuntime,
    key: WcKey,
    handoff: SignerHandoff,
    desc: AccountDescriptor,
    from: Address,
    typed: Arc<alloy::dyn_abi::TypedData>,
    pin: crate::sign::digest::Eip712Digests,
) -> Task<Message> {
    let live = rt.before_send_guard(key.clone());
    let tag = SignTag::WalletConnect {
        key: key.clone(),
        kind: WcSignKind::Typed,
    };
    let inner = handoff.clone();
    Task::perform(
        async move {
            let result = sign_typed(&inner, &desc, from, &typed, pin, &live).await;
            settle(&rt, &key, result)
        },
        move |result| Message::Signed {
            tag,
            signer: Some(handoff),
            result,
        },
    )
}

/// provider → pending nonce == quote.nonce (else note Stale) → take_or_build_live_signer → signer == from →
/// sign_and_send_detailed(.., Some(rt.before_send_guard(key))) → signer back.
///
/// A request that already had a transaction leave the wallet unacknowledged is never signed again,
/// whatever the coordinator asks: the task answers with that transaction instead, so the review
/// latches onto it.
pub(super) fn spawn_send_eoa_tx(
    network: Arc<dyn BalanceFetcher>,
    rt: WcRuntime,
    key: WcKey,
    handoff: SignerHandoff,
    desc: AccountDescriptor,
    plan: SendPlan,
    quote: TxQuote,
) -> Task<Message> {
    let live = rt.before_send_guard(key.clone());
    let tag = SignTag::WalletConnect {
        key: key.clone(),
        kind: WcSignKind::EoaTx,
    };
    let inner = handoff.clone();
    let already_sent = rt.with_book(|b| b.unconfirmed(&key));
    Task::perform(
        async move {
            let result = match never_signed_twice(already_sent) {
                Ok(()) => send_eoa_tx(&network, &inner, &desc, plan, quote, live).await,
                Err(f) => Err(f),
            };
            settle(&rt, &key, result)
        },
        move |result| Message::Signed {
            tag,
            signer: Some(handoff),
            result,
        },
    )
}

/// The wall in front of every EOA signature for a dapp request: once a transaction signed for it
/// left the wallet unacknowledged (`already_sent`, the runtime's record), nothing is signed for it
/// again — the failure carries that transaction instead, so the review latches onto it.
fn never_signed_twice(already_sent: Option<wc::UnconfirmedTx>) -> Result<(), Failure> {
    match already_sent {
        None => Ok(()),
        Some(tx) => {
            error!("wc: refusing to sign a request whose transaction already left");
            Err(Failure::unconfirmed(
                "a transaction for this request already left the wallet",
                tx,
            ))
        }
    }
}

/// resend_eoa_tx → `SignOutcome::Tx(hash)` of the transaction already signed for this request. No
/// signer is parked: nothing is signed.
pub(super) fn spawn_resend_eoa_tx(
    network: Arc<dyn BalanceFetcher>,
    rt: WcRuntime,
    key: WcKey,
    chain: NetworkId,
    tx: wc::UnconfirmedTx,
) -> Task<Message> {
    let live = rt.before_send_guard(key.clone());
    let tag = SignTag::WalletConnect {
        key: key.clone(),
        kind: WcSignKind::EoaTx,
    };
    Task::perform(
        async move {
            let hash = tx.hash;
            let result = resend_eoa_tx(&network, chain, tx, &live).await;
            settle_resend(&rt, &key, hash, result)
        },
        move |result| Message::Signed {
            tag,
            signer: None,
            result,
        },
    )
}

/// execute_safe_batch(.., Some(guard), opts) → SignOutcome::Tx(executor hash). `opts.parked` — the
/// active account's signer when it is one of the owners, or an active Ledger that isn't one,
/// let go while a Ledger owner signs — goes back through `Message::Signed`.
///
/// A request whose execution already left the wallet unacknowledged is never executed again: the
/// task answers with that transaction instead, so the review latches onto it. An execution that
/// left — answered, or sent without an acknowledgement — holds its Safe nonce on the slot
/// ([`wc::book::SafeExecHolds`]) until mined ([`hold_safe_exec`]), wherever its result lands.
pub(super) fn spawn_execute_safe_tx(
    network: Arc<dyn BalanceFetcher>,
    rt: WcRuntime,
    key: WcKey,
    sreq: tx_builder::SafeBatchRequest,
    signer_owners: Vec<AccountDescriptor>,
    executor_key: Option<B256>,
    opts: OwnerSignOpts,
) -> Task<Message> {
    let live = rt.before_send_guard(key.clone());
    let tag = SignTag::WalletConnect {
        key: key.clone(),
        kind: WcSignKind::SafeExecute,
    };
    let handoff = opts.parked.clone();
    let already_sent = rt.with_book(|b| b.unconfirmed(&key));
    let pin = SafeExecInFlight::of(&sreq);
    Task::perform(
        async move {
            let result = match never_signed_twice(already_sent) {
                Ok(()) => {
                    let owners = signer_owners;
                    execute_safe_tx(network.clone(), sreq, owners, executor_key, live, opts).await
                }
                Err(f) => Err(f),
            };
            let executed = match &result {
                Ok(executor) => Some(*executor),
                Err(f) => f.unconfirmed.as_ref().map(ExecutorTx::of),
            };
            hold_if_executed(&rt, &network, pin, executed);
            settle(
                &rt,
                &key,
                result.map(|executor| SignOutcome::Tx(executor.hash)),
            )
        },
        move |result| Message::Signed {
            tag,
            signer: handoff,
            result,
        },
    )
}

/// resend_eoa_tx of the executor's transaction already signed for `safe`'s request →
/// `SignOutcome::Tx(its hash)`, tagged as the execution it is. Nothing is signed: no owner, no
/// executor, no device. Once it went, the Safe nonce it executes at is held on the slot
/// ([`wc::book::SafeExecHolds`]): `pin` when the review pinned one; otherwise (a review reopened
/// on it) the Safe's nonce as it reads now, which an execution still to be mined hasn't moved.
/// Refused as invalid on any node instead, those bytes lift the hold they made
/// ([`settle_resend`]).
pub(super) fn spawn_resend_safe_exec(
    network: Arc<dyn BalanceFetcher>,
    rt: WcRuntime,
    key: WcKey,
    safe: Address,
    chain: Chain,
    tx: wc::UnconfirmedTx,
    pin: Option<SafeExecInFlight>,
) -> Task<Message> {
    let live = rt.before_send_guard(key.clone());
    let tag = SignTag::WalletConnect {
        key: key.clone(),
        kind: WcSignKind::SafeExecute,
    };
    Task::perform(
        async move {
            let hash = tx.hash;
            let executor = ExecutorTx::of(&tx);
            let result = resend_eoa_tx(&network, NetworkId::Builtin(chain), tx, &live).await;
            let pin = match pin {
                Some(pin) => Some(pin),
                None => crate::safe::tx::current_safe_nonce(network.as_ref(), safe, chain)
                    .await
                    .inspect_err(|e| {
                        warn!(error = %crate::net::redact_urls(e), "wc: couldn't read the Safe's nonce to hold it");
                    })
                    .ok()
                    .map(|nonce| SafeExecInFlight { safe, chain, nonce }),
            };
            // Sent again, or still unacknowledged: those bytes may yet take the nonce.
            let executed = match &result {
                Ok(_) => Some(executor),
                Err(f) => f.unconfirmed.as_ref().map(ExecutorTx::of),
            };
            hold_if_executed(&rt, &network, pin, executed);
            settle_resend(&rt, &key, hash, result)
        },
        move |result| Message::Signed {
            tag,
            signer: None,
            result,
        },
    )
}

/// How a hold's watch keeps time ([`watch_safe_exec`]).
#[derive(Debug, Clone, Copy)]
struct SafeExecPace {
    /// Between looks at first: until the execution is mined, the Safe's next dapp transaction
    /// can't be pinned (it would take the same nonce).
    poll: Duration,
    /// Between looks once the hold has lasted `slow_after`: by then the execution waits on its
    /// fee or a relay, not on the next block, and the watch runs on through lock and Turn off.
    slow_poll: Duration,
    slow_after: Duration,
    /// How long the node may go without showing the execution's transaction as pending before Kao
    /// takes it as dropped. A node not knowing it says little — a private relay may still be
    /// routing it, or the node evicted it — so this only bounds a hold that nothing else settles:
    /// far longer than a relay keeps trying a transaction.
    gone_after: Duration,
    /// The longest any hold lasts, its transaction pending or not: about as long as a node's pool
    /// keeps a transaction it can't mine.
    max_hold: Duration,
    /// How long one read may take before the look counts it as failed: a node that never answers
    /// is one that can't be read.
    read_timeout: Duration,
}

const SAFE_EXEC_PACE: SafeExecPace = SafeExecPace {
    poll: Duration::from_secs(3),
    slow_poll: Duration::from_secs(30),
    slow_after: Duration::from_secs(5 * 60),
    gone_after: Duration::from_secs(30 * 60),
    max_hold: Duration::from_secs(3 * 60 * 60),
    read_timeout: Duration::from_secs(25),
};

impl SafeExecPace {
    /// The wait before the next look, `held` into the hold.
    fn next_look(&self, held: Duration) -> Duration {
        if held < self.slow_after {
            self.poll
        } else {
            self.slow_poll
        }
    }
}

/// A dapp's Safe transaction Kao executed, by the Safe nonce it took. Until the Safe's on-chain
/// nonce moves past it, the chain and the Transaction Service both still offer that nonce as free
/// — the execution was never proposed — so a second dapp transaction for the Safe must wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SafeExecInFlight {
    pub(super) safe: Address,
    pub(super) chain: Chain,
    pub(super) nonce: u64,
}

impl SafeExecInFlight {
    /// The nonce an execution of `sreq` takes, once the review pinned one.
    pub(super) fn of(sreq: &tx_builder::SafeBatchRequest) -> Option<Self> {
        sreq.prepared.map(|(nonce, _)| Self {
            safe: sreq.safe,
            chain: sreq.chain,
            nonce,
        })
    }
}

/// The transaction executing a held Safe nonce: its hash and, when Kao knows them, the account
/// that sent it and the nonce it took there. Once that account's nonce is past it, the transaction
/// went into a block or another one took its place — it can't take the Safe's nonce any more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ExecutorTx {
    pub(super) hash: TxHash,
    pub(super) sent: Option<(Address, u64)>,
}

impl ExecutorTx {
    /// Known by its hash alone: the watch learns the rest from the node, once it shows it.
    pub(super) fn by_hash(hash: TxHash) -> Self {
        Self { hash, sent: None }
    }

    /// The executor's signed transaction kept for a request, its sender recovered from the bytes.
    pub(super) fn of(tx: &wc::UnconfirmedTx) -> Self {
        use alloy::consensus::TxEnvelope;
        use alloy::consensus::transaction::SignerRecoverable;
        use alloy::eips::eip2718::Decodable2718;
        let from = TxEnvelope::decode_2718(&mut tx.raw.as_ref())
            .ok()
            .and_then(|envelope| envelope.recover_signer().ok());
        Self {
            hash: tx.hash,
            sent: from.map(|from| (from, tx.nonce)),
        }
    }
}

/// Hold `pin`'s Safe — [`wc::WcBook::next_reviewable`] defers its next dapp transaction — while
/// `executor`, the transaction executing it, may still be mined ([`watch_safe_exec`]). The hold
/// is the runtime's slot's, so it outlives any dashboard (a rebuild, an account switch) and the
/// runtime itself (Turn off, a lock), and covers every Safe at once. It is `executor`'s: the node
/// refusing those bytes as invalid on any node lifts it ([`settle_resend`]). A watch that gives up
/// on `executor` lifts it too, but as possibly still pending ([`SafeExecEnd::hold_end`]).
pub(super) fn hold_safe_exec(
    rt: &WcRuntime,
    network: Arc<dyn BalanceFetcher>,
    pin: SafeExecInFlight,
    executor: ExecutorTx,
) {
    let settled = async move {
        let end = watch_safe_exec(network.as_ref(), pin, executor, SAFE_EXEC_PACE).await;
        let hash = format!("{:#x}", executor.hash);
        match end {
            SafeExecEnd::Mined => debug!(
                nonce = pin.nonce,
                "wc: the executed Safe transaction is mined"
            ),
            SafeExecEnd::Spent => info!(
                nonce = pin.nonce,
                hash = %hash,
                "wc: the executor's nonce moved past the executed Safe transaction — mined or \
                 replaced; it no longer holds the Safe's nonce"
            ),
            SafeExecEnd::Dropped => warn!(
                nonce = pin.nonce,
                hash = %hash,
                "wc: the node hasn't shown the executed Safe transaction as pending for long — \
                 the Safe's next transaction no longer waits for it, though it may still be mined"
            ),
            SafeExecEnd::Overdue => warn!(
                nonce = pin.nonce,
                hash = %hash,
                "wc: the executed Safe transaction still isn't mined after the longest hold — \
                 the Safe's next transaction no longer waits for it, though it may still be mined"
            ),
        }
        end.hold_end()
    };
    rt.hold_safe_exec(
        (pin.safe.into_array(), pin.chain.chain_id()),
        pin.nonce,
        executor.hash,
        settled,
    );
}

/// How a watched Safe execution stopped holding its nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SafeExecEnd {
    /// The Safe's nonce moved past it, or its transaction is in a block.
    Mined,
    /// The executor's own nonce moved past its transaction: it went into a block, or another
    /// transaction took its place.
    Spent,
    /// The node went [`SafeExecPace::gone_after`] without showing its transaction as pending, and
    /// nothing else settled it: taken as dropped.
    Dropped,
    /// The hold lasted [`SafeExecPace::max_hold`] with nothing settling it.
    Overdue,
}

impl SafeExecEnd {
    /// How the hold lifts: only a mined or replaced execution can no longer take the nonce.
    fn hold_end(self) -> wc::book::HoldEnd {
        match self {
            Self::Mined | Self::Spent => wc::book::HoldEnd::Settled,
            Self::Dropped | Self::Overdue => wc::book::HoldEnd::GaveUp,
        }
    }
}

/// Look at `pin`'s execution (every [`SafeExecPace::next_look`]) until it can no longer take the
/// Safe's nonce: mined — the Safe's nonce is past `pin.nonce`, or `executor` is in a block — or
/// spent: the executor's account nonce is past the one `executor` took (known from its signed
/// bytes, or from the node once it shows it). The node not knowing `executor` settles nothing by
/// itself, since a private relay may still be routing it; a read that fails, or doesn't answer
/// within [`SafeExecPace::read_timeout`], says nothing at all. A transaction the node shows as
/// pending, or can't be asked about, keeps the hold up to `pace.max_hold`; one the node answers it
/// doesn't know, look after look, for `pace.gone_after` is taken as dropped. So every hold ends.
async fn watch_safe_exec(
    network: &dyn BalanceFetcher,
    pin: SafeExecInFlight,
    executor: ExecutorTx,
    pace: SafeExecPace,
) -> SafeExecEnd {
    tokio::time::timeout(
        pace.max_hold,
        look_until_settled(network, pin, executor, pace),
    )
    .await
    .unwrap_or(SafeExecEnd::Overdue)
}

/// [`watch_safe_exec`]'s looks, until one settles the execution or the node has gone long enough
/// without it.
async fn look_until_settled(
    network: &dyn BalanceFetcher,
    pin: SafeExecInFlight,
    executor: ExecutorTx,
    pace: SafeExecPace,
) -> SafeExecEnd {
    use alloy::providers::Provider as _;
    let mut sent = executor.sent;
    let began = tokio::time::Instant::now();
    let mut looked = began;
    // How long the node has answered that it doesn't know `executor`, since it last showed it as
    // pending (or the watch began).
    let mut unseen = Duration::ZERO;
    loop {
        tokio::time::sleep(pace.next_look(began.elapsed())).await;
        let safe_nonce = crate::safe::tx::current_safe_nonce(network, pin.safe, pin.chain);
        match bounded_read(pace.read_timeout, safe_nonce).await {
            Ok(live) if live > pin.nonce => return SafeExecEnd::Mined,
            Ok(_) => {}
            Err(e) => {
                debug!(error = %crate::net::redact_urls(&e), "wc: Safe nonce read failed while watching an execution");
            }
        }
        if let Some(provider) = network.provider(pin.chain).await {
            match bounded_read(pace.read_timeout, executor_state(&provider, executor.hash)).await {
                Ok(ExecutorState::Mined) => return SafeExecEnd::Mined,
                Ok(ExecutorState::Pending { from, nonce }) => {
                    sent = Some((from, nonce));
                    unseen = Duration::ZERO;
                }
                Ok(ExecutorState::Unknown) => unseen += looked.elapsed(),
                Err(e) => {
                    debug!(error = %e, "wc: couldn't look the executed Safe transaction up");
                }
            }
            if let Some((from, nonce)) = sent {
                let count = async {
                    provider
                        .get_transaction_count(from)
                        .latest()
                        .await
                        .map_err(|e| crate::net::redact_urls(&e.to_string()))
                };
                match bounded_read(pace.read_timeout, count).await {
                    Ok(next) if next > nonce => return SafeExecEnd::Spent,
                    Ok(_) => {}
                    Err(e) => {
                        debug!(error = %e, "wc: executor nonce read failed while watching an execution");
                    }
                }
            }
        }
        looked = tokio::time::Instant::now();
        if unseen >= pace.gone_after {
            return SafeExecEnd::Dropped;
        }
        if began.elapsed() >= pace.max_hold {
            return SafeExecEnd::Overdue;
        }
    }
}

/// `read`, failed once it has gone `limit` without an answer.
async fn bounded_read<T>(
    limit: Duration,
    read: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    tokio::time::timeout(limit, read)
        .await
        .unwrap_or_else(|_| Err(format!("no answer within {limit:?}")))
}

/// Where the node has transaction `hash` — while pending, with its sender and nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutorState {
    Pending { from: Address, nonce: u64 },
    Mined,
    Unknown,
}

async fn executor_state(
    provider: &alloy::providers::RootProvider<alloy::network::Ethereum>,
    hash: TxHash,
) -> Result<ExecutorState, String> {
    use alloy::consensus::Transaction as _;
    use alloy::providers::Provider as _;
    let redact = |what: &str, e: &dyn std::fmt::Display| {
        format!("{what}: {}", crate::net::redact_urls(&e.to_string()))
    };
    let held = provider
        .get_transaction_by_hash(hash)
        .await
        .map_err(|e| redact("get_transaction_by_hash", &e))?;
    if let Some(tx) = held {
        return Ok(if tx.block_number.is_some() {
            ExecutorState::Mined
        } else {
            ExecutorState::Pending {
                from: tx.inner.signer(),
                nonce: tx.nonce(),
            }
        });
    }
    let receipt = provider
        .get_transaction_receipt(hash)
        .await
        .map_err(|e| redact("get_transaction_receipt", &e))?;
    Ok(if receipt.is_some() {
        ExecutorState::Mined
    } else {
        ExecutorState::Unknown
    })
}

/// An execution that left the wallet — answered with its hash, or sent without an
/// acknowledgement (the wall's refusal carries that same transaction) — holds its Safe nonce.
fn hold_if_executed(
    rt: &WcRuntime,
    network: &Arc<dyn BalanceFetcher>,
    pin: Option<SafeExecInFlight>,
    executed: Option<ExecutorTx>,
) {
    if let (Some(pin), Some(executor)) = (pin, executed) {
        hold_safe_exec(rt, network.clone(), pin, executor);
    }
}

/// propose_safe_batch(.., wc::SAFE_PROPOSE_ORIGIN, Some(guard), opts) → SignOutcome::SafeProposed(hash).
///
/// Never for a request whose execution already left the wallet unacknowledged: a proposal at the
/// same nonce would be a second, different transaction for it.
pub(super) fn spawn_propose_safe_tx(
    network: Arc<dyn BalanceFetcher>,
    rt: WcRuntime,
    key: WcKey,
    owner_desc: AccountDescriptor,
    sreq: tx_builder::SafeBatchRequest,
    opts: OwnerSignOpts,
) -> Task<Message> {
    let live = rt.before_send_guard(key.clone());
    let tag = SignTag::WalletConnect {
        key: key.clone(),
        kind: WcSignKind::SafePropose,
    };
    let handoff = opts.parked.clone();
    let already_sent = rt.with_book(|b| b.unconfirmed(&key));
    Task::perform(
        async move {
            let result = match never_signed_twice(already_sent) {
                Ok(()) => propose_safe_tx(network, owner_desc, sreq, live, opts).await,
                Err(f) => Err(f),
            };
            settle(&rt, &key, result)
        },
        move |result| Message::Signed {
            tag,
            signer: handoff,
            result,
        },
    )
}

/// pin check → check_safe_owner_drift → EIP-1271 fallback handler → each owner (parked or built)
/// signs and lets go → verify on chain (MUST pass) → is_live → SignOutcome::Signature(blob).
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_sign_safe_message(
    network: Arc<dyn BalanceFetcher>,
    rt: WcRuntime,
    key: WcKey,
    owners: Vec<AccountDescriptor>,
    safe: Address,
    chain: Chain,
    threshold: u32,
    data_hash: B256,
    pin: B256,
    opts: OwnerSignOpts,
) -> Task<Message> {
    let live = rt.before_send_guard(key.clone());
    let tag = SignTag::WalletConnect {
        key: key.clone(),
        kind: WcSignKind::SafeMessage,
    };
    let handoff = opts.parked.clone();
    Task::perform(
        async move {
            let msg = SafeMessageJob {
                safe,
                chain,
                threshold,
                data_hash,
                pin,
            };
            let result = sign_safe_message(network.as_ref(), &owners, msg, &live, &opts)
                .await
                .map(SignOutcome::Signature);
            settle(&rt, &key, result)
        },
        move |result| Message::Signed {
            tag,
            signer: handoff,
            result,
        },
    )
}

/// take_live_signer; if `needs_on_demand_connect`, build_owner_signer(desc) (verifies the derived address);
/// on failure the original placeholder goes back into the handoff.
async fn take_or_build_live_signer(
    handoff: &SignerHandoff,
    desc: &AccountDescriptor,
) -> Result<KaoSigner, String> {
    // `take_live_signer` already re-probes a connected Ledger, and on failure puts the original
    // back itself.
    let signer = take_live_signer(handoff, desc).await?;
    if !needs_on_demand_connect(&signer, desc) {
        return Ok(signer);
    }
    // A hardware account this session never connected: its live signer is still the unlock-time
    // `ViewOnly` placeholder, which `ensure_connected` passes straight through. Connect it here
    // instead of bouncing the user to the reconnect screen, which rebuilds the dashboard (and drops
    // the open review). `build_owner_signer` re-derives the address and refuses a different device;
    // once back in the handoff, the result handler installs the now-live signer for the session.
    info!("wc: connecting the hardware wallet on demand");
    match crate::wallet::build_owner_signer(desc).await {
        Ok(live) => Ok(live),
        Err(e) => {
            restore_signer(handoff, signer);
            Err(e)
        }
    }
}

/// `!signer.can_sign() && desc ∈ {Ledger, Trezor}`.
fn needs_on_demand_connect(signer: &KaoSigner, desc: &AccountDescriptor) -> bool {
    !signer.can_sign()
        && matches!(
            desc,
            AccountDescriptor::Ledger { .. } | AccountDescriptor::Trezor { .. }
        )
}

// ── bodies ────────────────────────────────────────────────────────────────────

/// Why a sign task stopped, as the coordinator will classify it ([`FailureClass`]).
///
/// `stale`: a reviewed pin no longer holds — the message, typed data, quote or nonce, the Safe's
/// pinned `(nonce, safeTxHash)` or owner set, or the signer itself moved. Retrying would only fail the
/// same way (or sign something nobody reviewed), so the coordinator disables Confirm or re-quotes an
/// EOA transaction. Everything else — a declined device prompt, an RPC hiccup — stays retryable. A
/// request that stopped being wanted is classed `Gone` by the runtime itself (`is_live`), whatever
/// is noted here.
///
/// `class`: a narrower verdict for the coordinator, noted instead of `stale` — an owner's device
/// refused the EIP-712 prompt ([`FailureClass::Eip712Refused`]), or a Safe transaction can't be
/// executed but can still be proposed ([`FailureClass::ExecuteRefused`]).
///
/// `unconfirmed`: a signed transaction was handed to the node and no acknowledgement came back —
/// it may be on its way. Neither class fits: re-quoting would sign a second, distinct transaction,
/// and a plain retry would too. The request keeps the signed bytes (noted on the runtime) and is
/// never signed again; only those bytes can be sent again.
///
/// `voided`: the transaction a request latched onto, sent again, turned out invalid on any node —
/// no node can ever take those bytes, so nothing is on its way after all. The runtime lets go of
/// its record of exactly that transaction ([`settle_resend`]), and the failure is `stale`.
#[derive(Debug)]
struct Failure {
    text: String,
    stale: bool,
    voided: bool,
    class: Option<FailureClass>,
    unconfirmed: Option<wc::UnconfirmedTx>,
}

impl Failure {
    fn new(text: impl Into<String>, stale: bool) -> Self {
        Self {
            text: text.into(),
            stale,
            voided: false,
            class: None,
            unconfirmed: None,
        }
    }

    fn retry(text: impl Into<String>) -> Self {
        Self::new(text, false)
    }

    fn stale(text: impl Into<String>) -> Self {
        Self::new(text, true)
    }

    fn classed(text: impl Into<String>, class: FailureClass) -> Self {
        Self {
            class: Some(class),
            ..Self::retry(text)
        }
    }

    fn unconfirmed(text: impl Into<String>, tx: wc::UnconfirmedTx) -> Self {
        Self {
            unconfirmed: Some(tx),
            ..Self::retry(text)
        }
    }

    /// The transaction the request latched onto can never be mined: a fresh look.
    fn voided(text: impl Into<String>) -> Self {
        Self {
            voided: true,
            ..Self::stale(text)
        }
    }

    /// An owner's signature wasn't produced. A device that refused the EIP-712 prompt is told
    /// apart, so the review can offer the `eth_sign` prompt as a choice.
    fn owner_sig(e: crate::safe::tx::OwnerSigError) -> Self {
        if e.eip712_refused {
            Self::classed(eip712_refused_text(&e.text), FailureClass::Eip712Refused)
        } else {
            Self::retry(e.text)
        }
    }
}

/// What the review says after an owner's device refused the EIP-712 prompt, ahead of offering the
/// same Safe hash as a personal message.
fn eip712_refused_text(device: &str) -> String {
    format!(
        "{device}. Nothing was signed. If the device can't sign it as EIP-712 data, Confirm again \
         to sign the same Safe hash as a personal message instead."
    )
}

/// Hand a body's result to `Message::Signed`, noting a stale pin — or a transaction that left
/// unacknowledged, with its bytes — on the runtime first so `wc_on_signed`'s `failure_class`
/// reads it.
fn settle(
    rt: &WcRuntime,
    key: &WcKey,
    result: Result<SignOutcome, Failure>,
) -> Result<SignOutcome, String> {
    result.map_err(|f| {
        // The text can quote an RPC error, and RPC URLs routinely carry an API key.
        warn!(
            id = key.id,
            stale = f.stale,
            unconfirmed = f.unconfirmed.as_ref().map(|u| format!("{:#x}", u.hash)),
            error = %crate::net::redact_urls(&f.text),
            "wc: sign task failed"
        );
        if let Some(tx) = f.unconfirmed {
            rt.note_unconfirmed(key, tx);
        } else if let Some(class) = f.class {
            rt.note_failure(key, class);
        } else if f.stale {
            rt.note_failure(key, FailureClass::Stale);
        }
        f.text
    })
}

/// [`settle`] for a re-send of `hash`, the transaction the request latched onto: when the node
/// refused those bytes as invalid on any node ([`Failure::voided`]), the runtime lets go of its
/// record of them first — and, for a Safe's execution, of the hold they put on its nonce
/// ([`wc::WcBook::void_unconfirmed`]), whose watch stops.
fn settle_resend(
    rt: &WcRuntime,
    key: &WcKey,
    hash: TxHash,
    result: Result<SignOutcome, Failure>,
) -> Result<SignOutcome, String> {
    if result.as_ref().is_err_and(|f| f.voided) {
        rt.void_unconfirmed(key, hash);
    }
    settle(rt, key, result)
}

/// The request is still wanted (`WcRuntime::is_live`, through its guard). Never noted stale — the
/// runtime classes a dead request `Gone` on its own.
fn still_live(live: &BeforeSend) -> Result<(), Failure> {
    live().map_err(Failure::retry)
}

/// Put a taken signer back into the handoff, so the result handler's reclaim finds it — poisoned
/// lock or not: losing the active signer would strand the wallet as view-only.
fn restore_signer(handoff: &SignerHandoff, signer: KaoSigner) {
    match handoff.lock() {
        Ok(mut cell) => *cell = Some(signer),
        Err(poisoned) => *poisoned.into_inner() = Some(signer),
    }
}

/// The live signer for `from`, or why there isn't one. On every refusal the signer is already back
/// in `handoff`; on success the caller owes it back after signing.
async fn live_signer_for(
    handoff: &SignerHandoff,
    desc: &AccountDescriptor,
    from: Address,
) -> Result<KaoSigner, Failure> {
    // The descriptor a device would be connected from must be the reviewed account's, or there is
    // no point waking anything.
    if account_address(desc) != Some(from) {
        warn!(expected = %short_address(from), "wc: signer descriptor is not the reviewed account");
        return Err(Failure::stale(
            "the active account is not the one you reviewed — refusing to sign",
        ));
    }
    let signer = take_or_build_live_signer(handoff, desc)
        .await
        .map_err(Failure::retry)?;
    if !signer.can_sign() {
        restore_signer(handoff, signer);
        return Err(Failure::retry(
            "this account has no signing key connected — reconnect its hardware wallet and try again",
        ));
    }
    let got = signer.address();
    if got != from {
        // The from == signer wall, before any device prompt: the review showed `from`.
        warn!(
            expected = %short_address(from),
            signer = %short_address(got),
            "wc: live signer is not the reviewed account",
        );
        restore_signer(handoff, signer);
        return Err(Failure::stale(format!(
            "the signing key is {}, not the reviewed {} — refusing to sign",
            short_address(got),
            short_address(from),
        )));
    }
    Ok(signer)
}

async fn sign_personal(
    handoff: &SignerHandoff,
    desc: &AccountDescriptor,
    from: Address,
    message: &[u8],
    pin: B256,
    live: &BeforeSend,
) -> Result<SignOutcome, Failure> {
    // Reviewed == signed: these exact bytes hash to the digest the review showed. Checked before
    // any device is woken.
    if wc::message::eip191_hash(message) != pin {
        warn!("wc: personal_sign bytes differ from the reviewed digest");
        return Err(Failure::stale(
            "the message differs from the one you reviewed — refusing to sign",
        ));
    }
    // A request that already died must not prompt a device.
    still_live(live)?;
    let signer = live_signer_for(handoff, desc, from).await?;
    let signed = signer.sign_eth_message(message).await;
    restore_signer(handoff, signer);
    let sig = signed.map_err(|e| Failure::retry(crate::wallet::friendly_signer_error(&e)))?;
    crate::sign::recover::assert_message_signer(&sig, message, from).map_err(Failure::stale)?;
    // Answering is the irreversible step: a signature for a request that stopped being wanted is
    // discarded here, never sent.
    still_live(live)?;
    Ok(SignOutcome::Signature(
        crate::sign::recover::signature_bytes(&sig),
    ))
}

async fn sign_typed(
    handoff: &SignerHandoff,
    desc: &AccountDescriptor,
    from: Address,
    typed: &alloy::dyn_abi::TypedData,
    pin: Eip712Digests,
    live: &BeforeSend,
) -> Result<SignOutcome, Failure> {
    // Refused before any signer is touched: Kao's Trezor support has no EIP-712 path
    // (`KaoSigner::sign_typed_json` would refuse too, after waking the device for nothing).
    if matches!(desc, AccountDescriptor::Trezor { .. }) {
        return Err(Failure::stale(
            "Trezor can't sign EIP-712 typed data — nothing was signed",
        ));
    }
    // Reviewed == signed: re-derive the ERC-8213 triple from the one object that will be hashed
    // and signed, and hold it against the pin.
    let digests = wc::typed::digests_of(typed).map_err(|refusal| Failure::stale(refusal.detail))?;
    if digests != pin {
        warn!("wc: typed data differs from the reviewed digests");
        return Err(Failure::stale(
            "the typed data differs from what you reviewed — refusing to sign",
        ));
    }
    still_live(live)?;
    let signer = live_signer_for(handoff, desc, from).await?;
    let signed = signer.sign_typed_json(typed).await;
    restore_signer(handoff, signer);
    let sig = signed.map_err(|e| Failure::retry(crate::wallet::friendly_signer_error(&e)))?;
    crate::sign::recover::assert_prehash_signer(&sig, pin.digest, from).map_err(Failure::stale)?;
    still_live(live)?;
    Ok(SignOutcome::Signature(
        crate::sign::recover::signature_bytes(&sig),
    ))
}

async fn send_eoa_tx(
    network: &Arc<dyn BalanceFetcher>,
    handoff: &SignerHandoff,
    desc: &AccountDescriptor,
    plan: SendPlan,
    quote: TxQuote,
    live: BeforeSend,
) -> Result<SignOutcome, Failure> {
    use alloy::providers::Provider;
    // Reviewed == signed: the pinned quote must describe this exact call (`sign_and_send_with`
    // re-checks it; checking here classes it before any RPC or device).
    if !quote.matches_plan(&plan) {
        return Err(Failure::stale(
            "the transaction differs from the one you reviewed — review it again",
        ));
    }
    still_live(&live)?;
    let provider = provider_for(network, plan.chain)
        .await
        .ok_or_else(|| Failure::retry("no execution RPCs configured"))?;
    // The pinned nonce must still be this account's next one. Anything sent from it since the review
    // (in Kao or elsewhere) would make the pinned transaction a replacement or a dud — re-quote.
    let pending = provider
        .get_transaction_count(plan.from)
        .pending()
        .await
        .map_err(|e| {
            Failure::retry(format!(
                "couldn't read the account's nonce: {}",
                crate::net::redact_urls(&e.to_string())
            ))
        })?;
    if pending != quote.nonce {
        warn!(
            quoted = quote.nonce,
            pending, "wc: account nonce moved since the review"
        );
        return Err(Failure::stale(format!(
            "this account's next nonce moved since you reviewed ({} → {pending}) — the transaction \
             needs a fresh look",
            quote.nonce,
        )));
    }
    let signer = live_signer_for(handoff, desc, plan.from).await?;
    let nonce = quote.nonce;
    // `Fees::Quoted` (exactly the reviewed numbers), the from == signer wall, the zero-recipient
    // guard, and `live` between the signature and the broadcast.
    let sent =
        crate::wallet::tx::sign_and_send_detailed(&provider, &signer, plan, quote, Some(live))
            .await;
    restore_signer(handoff, signer);
    match sent {
        Ok(hash) => Ok(SignOutcome::Tx(hash)),
        // Nothing left the wallet: a plain retry is a fresh attempt.
        Err(BroadcastError::NotSent(text)) => Err(Failure::retry(text)),
        // The node judged the signed bytes invalid on any node: nothing is on its way, and the
        // same bytes would only be refused again — a fresh quote is the way on.
        Err(BroadcastError::Refused(text)) => Err(Failure::stale(text)),
        // The request reached the node; its reply didn't come back. Never a retry.
        Err(BroadcastError::Unconfirmed { hash, raw, msg }) => {
            let tx = wc::UnconfirmedTx { hash, raw, nonce };
            settle_unacknowledged(&provider, tx, msg).await
        }
    }
}

/// `tx` was handed to the node without an acknowledgement. If the node knows its hash — pooled or
/// mined — it did get there, and that hash is the dapp's answer. Otherwise the failure carries the
/// signed bytes: the request is never signed again, and only these bytes may be sent again.
async fn settle_unacknowledged(
    provider: &alloy::providers::RootProvider<alloy::network::Ethereum>,
    tx: wc::UnconfirmedTx,
    msg: String,
) -> Result<SignOutcome, Failure> {
    match crate::sign::broadcast::node_knows_transaction(provider, tx.hash).await {
        Ok(true) => {
            info!(
                hash = %format!("{:#x}", tx.hash),
                "wc: the node has the transaction its lost reply was about"
            );
            Ok(SignOutcome::Tx(tx.hash))
        }
        Ok(false) => Err(Failure::unconfirmed(msg, tx)),
        Err(lookup) => {
            warn!(error = %lookup, "wc: couldn't look the unacknowledged transaction up");
            Err(Failure::unconfirmed(msg, tx))
        }
    }
}

/// Send `tx` — a transaction already signed for this request, whose first broadcast went
/// unacknowledged — again, byte for byte. Nothing is signed: no signer, no device. Idempotent, so
/// it can't make the dapp's call run twice. A request that stopped being wanted gets nothing more
/// sent (the runtime classes it Gone). The node refusing these bytes as invalid on any node means
/// no node ever took them, the first send included: the request lets go of them ([`Failure::voided`]).
/// Every other failure keeps the request latched on these bytes.
async fn resend_eoa_tx(
    network: &Arc<dyn BalanceFetcher>,
    chain: NetworkId,
    tx: wc::UnconfirmedTx,
    live: &BeforeSend,
) -> Result<SignOutcome, Failure> {
    still_live(live)?;
    let Some(provider) = provider_for(network, chain).await else {
        return Err(Failure::unconfirmed("no execution RPCs configured", tx));
    };
    match crate::sign::broadcast::resend_signed(&provider, tx.hash, &tx.raw).await {
        // The node keys it by this hash; the dapp's answer is the signed transaction's own.
        Ok(_) => Ok(SignOutcome::Tx(tx.hash)),
        Err(BroadcastError::Refused(text)) => Err(Failure::voided(text)),
        // "already known", "nonce too low" (mined meanwhile), or a lost reply again: ask.
        Err(BroadcastError::NotSent(msg) | BroadcastError::Unconfirmed { msg, .. }) => {
            settle_unacknowledged(&provider, tx, msg).await
        }
    }
}

/// The dapp's Safe call executed: the executor's transaction, answered by its hash.
async fn execute_safe_tx(
    network: Arc<dyn BalanceFetcher>,
    sreq: tx_builder::SafeBatchRequest,
    signer_owners: Vec<AccountDescriptor>,
    executor_key: Option<B256>,
    live: BeforeSend,
    opts: OwnerSignOpts,
) -> Result<ExecutorTx, Failure> {
    only_call(&sreq)?;
    // The extraction rebuilds the pin, checks owner drift, preflights the call, checks the
    // executor's funding, runs `live` before the first owner prompt and again after the executor
    // signs, immediately before the broadcast.
    let executed = execute_safe_batch(
        network.clone(),
        sreq.clone(),
        signer_owners.clone(),
        executor_key,
        Some(live.clone()),
        opts,
    )
    .await;
    let text = match executed {
        Ok(sent) => {
            return Ok(ExecutorTx {
                hash: sent.hash,
                sent: Some((sent.from, sent.nonce)),
            });
        }
        // The dapp's call reverts against the chain as it stands. Nothing was signed, and executing
        // would only re-run the same dry run — but a proposal doesn't run it, and may be exactly
        // what the dapp's flow needs (a call that depends on another still queued). Said in the
        // dapp's terms: there is no batch here for the user to go back and re-simulate.
        Err(SafeExecError::Preflight(p @ PreflightError::Reverts { .. })) => {
            return Err(Failure::classed(
                preflight_text(&p),
                FailureClass::ExecuteRefused,
            ));
        }
        // Can never be mined, proposed or not.
        Err(SafeExecError::Preflight(p)) => return Err(Failure::stale(preflight_text(&p))),
        Err(SafeExecError::Eip712Refused(text)) => {
            return Err(Failure::owner_sig(crate::safe::tx::OwnerSigError {
                text,
                eip712_refused: true,
            }));
        }
        // The executor's transaction reached the node; its reply didn't come back. Never a retry,
        // and never classed by the Safe's nonce: while it sits unmined the nonce hasn't moved, and
        // once mined a "stale" verdict would tell the dapp it failed when it ran.
        Err(SafeExecError::Unconfirmed(tx, msg)) => {
            let executor = ExecutorTx::of(&tx);
            return match network.provider(sreq.chain).await {
                Some(provider) => settle_unacknowledged(&provider, tx, msg)
                    .await
                    .map(|_| executor),
                None => Err(Failure::unconfirmed(msg, tx)),
            };
        }
        Err(SafeExecError::Other(text)) => text,
    };
    let owners = signer_owners.as_slice();
    Err(classify_safe_failure(network.as_ref(), &sreq, owners, false, &live, text).await)
}

async fn propose_safe_tx(
    network: Arc<dyn BalanceFetcher>,
    owner_desc: AccountDescriptor,
    sreq: tx_builder::SafeBatchRequest,
    live: BeforeSend,
    opts: OwnerSignOpts,
) -> Result<SignOutcome, Failure> {
    only_call(&sreq)?;
    // A nonce pinned without knowing the Safe's queue may collide with a co-signer's proposal; the
    // dispatch refuses it, and so does the task.
    if sreq.queued_nonces.is_none() {
        return Err(Failure::stale(
            "Kao couldn't read this Safe's pending queue, so it can't tell which nonce is free — \
             nothing was proposed",
        ));
    }
    // The origin co-signers see is a constant, never a dapp string. `live` runs before the owner is
    // prompted and again, signature in hand, immediately before the proposal is filed.
    let proposed = propose_safe_batch(
        network.clone(),
        owner_desc.clone(),
        sreq.clone(),
        wc::SAFE_PROPOSE_ORIGIN,
        Some(live.clone()),
        opts,
    )
    .await;
    let text = match proposed {
        Ok(safe_tx_hash) => return Ok(SignOutcome::SafeProposed(safe_tx_hash)),
        Err(SafeExecError::Eip712Refused(text)) => {
            return Err(Failure::owner_sig(crate::safe::tx::OwnerSigError {
                text,
                eip712_refused: true,
            }));
        }
        Err(SafeExecError::Preflight(p)) => preflight_text(&p),
        // A proposal broadcasts nothing, so this never arises; kept as the text it carries.
        Err(SafeExecError::Unconfirmed(_, text) | SafeExecError::Other(text)) => text,
    };
    let owners = std::slice::from_ref(&owner_desc);
    Err(classify_safe_failure(network.as_ref(), &sreq, owners, true, &live, text).await)
}

/// The pinned Safe message a [`sign_safe_message`] call works on.
#[derive(Debug, Clone, Copy)]
struct SafeMessageJob {
    safe: Address,
    chain: Chain,
    threshold: u32,
    /// What the dapp will pass to `isValidSignature`.
    data_hash: B256,
    /// The reviewed `SafeMessage` hash the owners sign.
    pin: B256,
}

async fn sign_safe_message(
    network: &dyn BalanceFetcher,
    owners: &[AccountDescriptor],
    job: SafeMessageJob,
    live: &BeforeSend,
    opts: &OwnerSignOpts,
) -> Result<Bytes, Failure> {
    use crate::cow::safe_sig::{
        Eip1271Check, check_eip1271_on_chain, safe_message_hash, sign_eip1271_owner,
    };
    let SafeMessageJob {
        safe,
        chain,
        threshold,
        data_hash,
        pin,
    } = job;
    // Reviewed == signed: the owners sign exactly the SafeMessage hash the review showed.
    let message_hash = safe_message_hash(data_hash, safe, chain);
    if message_hash != pin {
        warn!("wc: safe message differs from the reviewed SafeMessage hash");
        return Err(Failure::stale(
            "the message differs from the SafeMessage you reviewed — refusing to sign",
        ));
    }
    // Every one of the threshold signatures is produced here: there is no off-chain collection path
    // for Safe messages.
    let needed = usize::try_from(threshold).unwrap_or(usize::MAX);
    let all_owners = owners;
    let Some(owners) = owners.get(..needed).filter(|o| !o.is_empty()) else {
        return Err(Failure::stale(format!(
            "this Safe needs {threshold} owner signatures and Kao holds {} of its keys — nothing \
             was signed",
            owners.len(),
        )));
    };
    // The threshold the review promised and every key about to sign are still what the Safe says.
    if let Err(text) = check_safe_owner_drift(network, chain, safe, threshold, owners).await {
        let moved = owner_set_moved(network, chain, safe, threshold, owners).await;
        return Err(Failure::new(text, moved));
    }
    // Only a handler that implements EIP-1271 can ever accept the signature: with any other, every
    // owner would be prompted for a blob the Safe can't validate, on every retry.
    match crate::safe::read_fallback_handler(network, chain, safe).await {
        Ok(Some(handler)) if crate::safe::is_eip1271_handler(handler) => {}
        Ok(_) => {
            return Err(Failure::stale(
                "this Safe's fallback handler can't validate EIP-1271 signatures, so the Safe \
                 could never accept a message signature — nothing was signed",
            ));
        }
        Err(e) => {
            return Err(Failure::retry(format!(
                "couldn't read the Safe's fallback handler: {}",
                crate::net::redact_urls(&e)
            )));
        }
    }
    // Last moment before any device is prompted.
    still_live(live)?;
    // One owner at a time: each device is let go once it has signed, so two owners on one Ledger
    // never hold it at once — and the active account signs through the instance the dashboard
    // already holds (parked for this ceremony), not a second connection. When another owner is a
    // Ledger too, that held connection is closed for the ceremony and reopened after it.
    let parked = opts.parked.as_ref();
    let opened: Vec<&AccountDescriptor> = owners.iter().collect();
    let let_go = let_go_of_parked_ledger(opts, all_owners, &opened);
    let signed: Result<Vec<_>, Failure> = async {
        let mut sigs = Vec::with_capacity(owners.len());
        for desc in owners {
            let (signer, from_parked) = owner_signer(opts, desc).await.map_err(Failure::retry)?;
            let signer = if from_parked {
                signer
            } else {
                crate::wallet::ensure_connected(signer, desc)
                    .await
                    .map_err(|(_, e)| Failure::retry(e))?
            };
            let signed = sign_eip1271_owner(&signer, data_hash, safe, chain, opts.mode).await;
            release_owner_signer(parked, signer, from_parked);
            sigs.push(signed.map_err(Failure::owner_sig)?);
        }
        Ok(sigs)
    }
    .await;
    if let Some(desc) = &let_go {
        reconnect_parked(opts, desc).await;
    }
    let sigs = signed?;
    let expected: Vec<Address> = sigs.iter().map(|(owner, _)| *owner).collect();
    let blob = crate::safe::tx::assemble_signatures(sigs).map_err(Failure::retry)?;
    // from == signer for a Safe: every signature in the blob recovers to exactly the owner it is
    // filed under, over the reviewed SafeMessage hash.
    assert_owner_blob(&blob, message_hash, &expected).map_err(Failure::stale)?;
    // The Safe itself must accept it before a dapp ever sees it — this catches a threshold or owner
    // change, or a derivation bug. An answer that isn't the magic value would be the same on a
    // retry; a call that couldn't be made says nothing.
    check_eip1271_on_chain(network, safe, chain, data_hash, &blob)
        .await
        .map_err(|e| {
            let text = eip1271_failure_text(&e);
            match e {
                Eip1271Check::Rejected(_) => Failure::stale(text),
                Eip1271Check::Unreachable(_) => Failure::retry(text),
            }
        })?;
    still_live(live)?;
    Ok(blob)
}

/// Every 65-byte owner signature in an assembled Safe blob recovers to its owner, in Safe order
/// (ascending owner address): `v ∈ {27,28}` over the SafeMessage hash itself (EIP-712), `v ∈ {31,32}`
/// over its EIP-191 personal-message hash (the `eth_sign` fallback).
fn assert_owner_blob(blob: &[u8], message_hash: B256, owners: &[Address]) -> Result<(), String> {
    use crate::sign::recover::{assert_message_signer, assert_prehash_signer};
    let mut expected = owners.to_vec();
    expected.sort();
    if blob.len() != expected.len().saturating_mul(65) {
        return Err(format!(
            "the assembled Safe signature is {} bytes, not {} owner signatures",
            blob.len(),
            expected.len(),
        ));
    }
    for (chunk, owner) in blob.chunks_exact(65).zip(&expected) {
        let (rs, v) = chunk.split_at(64);
        match v.first().copied() {
            Some(v @ (27 | 28)) => assert_prehash_signer(
                &Signature::from_bytes_and_parity(rs, v == 28),
                message_hash,
                *owner,
            )?,
            Some(v @ (31 | 32)) => assert_message_signer(
                &Signature::from_bytes_and_parity(rs, v == 32),
                message_hash.as_slice(),
                *owner,
            )?,
            other => {
                return Err(format!(
                    "unexpected owner signature type in the Safe signature (v = {other:?})"
                ));
            }
        }
    }
    Ok(())
}

/// User-facing text for a failed `isValidSignature` check. `verify_eip1271_on_chain` words its own
/// error for CoW orders; here it is a dapp message, and either the Safe answered "no" or it couldn't
/// be asked — chosen by the verdict, never by the detail's wording.
fn eip1271_failure_text(e: &crate::cow::safe_sig::Eip1271Check) -> String {
    use crate::cow::safe_sig::Eip1271Check;
    match e {
        Eip1271Check::Rejected(detail) => {
            warn!(error = %crate::net::redact_urls(detail), "wc: the Safe rejected a safe message signature (EIP-1271)");
            "the Safe didn't accept these owner signatures (isValidSignature check failed), so \
             nothing was sent to the dapp — the Safe's fallback handler may not support EIP-1271 \
             messages"
                .to_string()
        }
        Eip1271Check::Unreachable(detail) => {
            let detail = crate::net::redact_urls(detail);
            warn!(error = %detail, "wc: couldn't run the on-chain EIP-1271 check for a safe message");
            format!(
                "couldn't check the signature against the Safe, so nothing was sent to the dapp: \
                 {detail}"
            )
        }
    }
}

/// The execute-time preflight's verdict on a dapp's Safe transaction, for the review and (through
/// Cancel) the dapp.
fn preflight_text(p: &PreflightError) -> String {
    match p {
        PreflightError::Reverts { reason, .. } => format!(
            "This transaction would revert right now: {}. Nothing was signed — the dapp may need \
             to build it again.",
            sign_review::display_revert_reason(reason)
        ),
        PreflightError::Unmineable { floor, limit } => format!(
            "This transaction needs at least {floor} gas, more than a block on this chain holds \
             ({limit}), so it can never be mined. Nothing was signed."
        ),
    }
}

/// A dapp's Safe transaction is a plain CALL. A DELEGATECALL would run foreign code as the Safe —
/// owners, modules, guard and all — so it never reaches an owner, whatever the request says.
fn only_call(sreq: &tx_builder::SafeBatchRequest) -> Result<(), Failure> {
    if sreq.input.operation == Operation::Call {
        Ok(())
    } else {
        error!("wc: a Safe request reached signing with operation != CALL");
        Err(Failure::stale(
            "refusing a delegatecall from a dapp — only plain calls can be signed",
        ))
    }
}

/// After a Safe ceremony failed: was it the reviewed pin that moved (stale) rather than a device,
/// relay or RPC hiccup (retryable)? Only asked on failure, so the happy path costs nothing extra;
/// a read that fails proves nothing and leaves the failure retryable.
async fn classify_safe_failure(
    network: &dyn BalanceFetcher,
    sreq: &tx_builder::SafeBatchRequest,
    owners: &[AccountDescriptor],
    queue_ahead: bool,
    live: &BeforeSend,
    text: String,
) -> Failure {
    // A request that died is the runtime's to class (Gone); don't spend reads on it.
    if live().is_err() {
        return Failure::retry(text);
    }
    let moved = safe_pin_moved(network, sreq, queue_ahead).await
        || owner_set_moved(network, sreq.chain, sreq.safe, sreq.threshold, owners).await;
    Failure::new(text, moved)
}

/// The `(nonce, safeTxHash)` the review pinned can no longer be signed on this path: there is no
/// pin, the hash no longer rebuilds from the request, or the live nonce left the range the path
/// accepts (execute: equal; propose: not passed).
async fn safe_pin_moved(
    network: &dyn BalanceFetcher,
    sreq: &tx_builder::SafeBatchRequest,
    queue_ahead: bool,
) -> bool {
    use crate::safe::tx::{
        build_safe_tx_with_nonce, current_safe_nonce, safe_domain, safe_tx_hash,
    };
    let Some((nonce, hash)) = sreq.prepared else {
        return true;
    };
    let tx = build_safe_tx_with_nonce(sreq.input.clone(), nonce);
    if safe_tx_hash(&tx, &safe_domain(sreq.safe, sreq.chain)) != hash {
        return true;
    }
    match current_safe_nonce(network, sreq.safe, sreq.chain).await {
        Ok(live) if queue_ahead => check_queued_nonce(live, nonce).is_err(),
        Ok(live) => check_pinned_nonce(live, nonce).is_err(),
        Err(_) => false,
    }
}

/// The Safe's live threshold differs from the reviewed one, or one of `owners` is no longer an
/// owner. `false` when the owner set can't be read.
async fn owner_set_moved(
    network: &dyn BalanceFetcher,
    chain: Chain,
    safe: Address,
    threshold: u32,
    owners: &[AccountDescriptor],
) -> bool {
    match crate::safe::read_owner_set(network, chain, safe).await {
        Ok((live_owners, live_threshold)) => {
            live_threshold != threshold
                || owners
                    .iter()
                    .filter_map(account_address)
                    .any(|a| !live_owners.contains(&a))
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{CallMock, LatestBlock, VerificationStatus, VerifiedRead};
    use crate::sign::broadcast::STILL_WANTED_REFUSAL;
    use crate::wallet::handoff_with;
    use alloy::network::Ethereum;
    use alloy::primitives::{eip191_hash_message, keccak256};
    use alloy::providers::RootProvider;
    use alloy::sol_types::{SolCall, SolValue};
    use serde_json::{Value, json};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    // ── fixtures ──────────────────────────────────────────────────────────────

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    fn local_desc(seed: u8) -> AccountDescriptor {
        AccountDescriptor::Local {
            name: None,
            key_bytes: crate::wallet::SecretKeyBytes::new([seed; 32]),
        }
    }

    fn local_signer(seed: u8) -> KaoSigner {
        KaoSigner::Local(crate::wallet::signer_from_bytes(&B256::repeat_byte(seed)).unwrap())
    }

    fn local_addr(seed: u8) -> Address {
        local_signer(seed).address()
    }

    fn ledger_desc(a: Address) -> AccountDescriptor {
        AccountDescriptor::Ledger {
            name: None,
            path: crate::wallet::LedgerHdPath::LedgerLive(0),
            address: a.into_array(),
        }
    }

    fn trezor_desc(a: Address) -> AccountDescriptor {
        AccountDescriptor::Trezor {
            name: None,
            path: crate::wallet::TrezorHdPath::TrezorLive(0),
            address: a.into_array(),
        }
    }

    /// Who's in the handoff right now (`None` = nothing parked).
    fn parked(handoff: &SignerHandoff) -> Option<(Address, bool)> {
        handoff
            .lock()
            .unwrap()
            .as_ref()
            .map(|s| (s.address(), s.can_sign()))
    }

    /// A liveness guard that answers "still wanted" for its first `allow` calls and refuses every
    /// call after — and counts them, so a test can tell which steps ran.
    fn guard(allow: usize) -> (BeforeSend, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let check: BeforeSend = Arc::new(move || {
            if seen.fetch_add(1, Ordering::SeqCst) < allow {
                Ok(())
            } else {
                Err(STILL_WANTED_REFUSAL.to_string())
            }
        });
        (check, calls)
    }

    fn alive() -> BeforeSend {
        guard(usize::MAX).0
    }

    /// How WalletConnect's Safe ceremonies sign: EIP-712 with no `eth_sign` after a refused
    /// prompt, nothing parked.
    fn wc_opts() -> OwnerSignOpts {
        OwnerSignOpts {
            mode: crate::safe::tx::OwnerSigMode::Eip712,
            ..OwnerSignOpts::default()
        }
    }

    /// The EIP-712 "Mail" example as a dapp sends it.
    fn mail() -> alloy::dyn_abi::TypedData {
        serde_json::from_value(crate::walletconnect::testkit::fixtures::mail(1)).unwrap()
    }

    fn mail_digests() -> Eip712Digests {
        let td = mail();
        Eip712Digests::from_parts(td.domain.separator(), td.hash_struct().unwrap())
    }

    fn typed_request(from: Address) -> wc::TypedRequest {
        let td = mail();
        wc::TypedRequest {
            from,
            checked: wc::CheckedTyped {
                primary_type: td.primary_type.clone(),
                digests: mail_digests(),
                domain: wc::DomainSummary {
                    name: Some("Ether Mail".into()),
                    version: Some("1".into()),
                    chain_id: Some(1),
                    verifying_contract: Some(addr(0xCC)),
                    salt: None,
                    exact_name: None,
                    exact_version: None,
                },
                model: crate::sign::typed::TypedDataModel {
                    type_name: "Mail".into(),
                    headline: None,
                    rows: Vec::new(),
                },
                exact: Vec::new(),
                kind: wc::TypedKind::Generic,
                warnings: Vec::new(),
            },
            typed: Arc::new(td),
        }
    }

    fn origin(identity: wc::WcIdentity, method: &'static str) -> WcOriginCard {
        WcOriginCard {
            dapp: wc::DappLabel {
                name: "Example".into(),
                host: Some("app.example".into()),
                url: "https://app.example".into(),
                description: String::new(),
                insecure_scheme: false,
            },
            session_ordinal: 1,
            identity,
            identity_label: "Account 1".into(),
            identity_badge: "Local",
            method,
            net: NetworkId::Builtin(Chain::Mainnet),
            unverified_network: false,
            received_at: 0,
            dapp_deadline: None,
            kao_deadline: 3_600,
            waiting_behind: 0,
        }
    }

    // ── Safe fixtures ─────────────────────────────────────────────────────────

    const SAFE: u8 = 0x5A;

    /// A WalletConnect Safe request: one plain CALL, the queue known and empty.
    fn safe_call_req(to: Address, threshold: u32) -> tx_builder::SafeBatchRequest {
        tx_builder::SafeBatchRequest {
            queue_map: tx_builder::QueueMap {
                prepends: 0,
                queued: 1,
            },
            safe: addr(SAFE),
            chain: Chain::Mainnet,
            version: "1.4.1".into(),
            trust: crate::wallet::SafeTrust::Canonical,
            threshold,
            owner_count: 3,
            signable_indices: vec![0],
            input: crate::safe::tx::SafeTxInput {
                to,
                value: U256::ZERO,
                data: Bytes::from(vec![0x01]),
                operation: Operation::Call,
            },
            call_count: 1,
            prepared: None,
            queued_nonces: Some(Vec::new()),
            service_base: crate::safe::service::DEFAULT_TX_SERVICE_BASE.to_string(),
        }
    }

    /// Pin `req` at `nonce`, as the prepared review would.
    fn pin_at(req: &mut tx_builder::SafeBatchRequest, nonce: u64) -> (crate::safe::SafeTx, B256) {
        use crate::safe::tx::{build_safe_tx_with_nonce, safe_domain, safe_tx_hash};
        let tx = build_safe_tx_with_nonce(req.input.clone(), nonce);
        let hash = safe_tx_hash(&tx, &safe_domain(req.safe, req.chain));
        req.prepared = Some((nonce, hash));
        (tx, hash)
    }

    fn plant_owner_set(mock: &CallMock, safe: Address, owners: &[Address], threshold: u32) {
        mock.set_call(
            safe,
            Bytes::from(crate::safe::getOwnersCall {}.abi_encode()),
            Bytes::from(owners.to_vec().abi_encode()),
            true,
        );
        mock.set_call(
            safe,
            Bytes::from(crate::safe::getThresholdCall {}.abi_encode()),
            Bytes::from(U256::from(threshold).abi_encode()),
            true,
        );
    }

    fn plant_nonce(mock: &CallMock, safe: Address, nonce: u64) {
        mock.set_call(
            safe,
            Bytes::from(crate::safe::nonceCall {}.abi_encode()),
            Bytes::from(U256::from(nonce).abi_encode()),
            true,
        );
    }

    /// The on-chain `domainSeparator()` / `getTransactionHash(..)` agree with the local build.
    fn plant_tx_agreement(mock: &CallMock, safe: Address, tx: &crate::safe::SafeTx, hash: B256) {
        mock.set_call(
            safe,
            Bytes::from(crate::safe::domainSeparatorCall {}.abi_encode()),
            Bytes::from(
                crate::safe::tx::safe_domain(safe, Chain::Mainnet)
                    .separator()
                    .abi_encode(),
            ),
            true,
        );
        mock.set_call(
            safe,
            Bytes::from(
                crate::safe::getTransactionHashCall {
                    to: tx.to,
                    value: tx.value,
                    data: tx.data.clone(),
                    operation: tx.operation,
                    safeTxGas: tx.safeTxGas,
                    baseGas: tx.baseGas,
                    gasPrice: tx.gasPrice,
                    gasToken: tx.gasToken,
                    refundReceiver: tx.refundReceiver,
                    _nonce: tx.nonce,
                }
                .abi_encode(),
            ),
            Bytes::from(hash.abi_encode()),
            true,
        );
    }

    /// The Safe's fallback handler is `handler` (its storage slot, as `read_fallback_handler` reads it).
    fn plant_handler(mock: &CallMock, safe: Address, handler: Address) {
        mock.set_storage(
            safe,
            crate::safe::FALLBACK_HANDLER_STORAGE_SLOT,
            handler.into_word(),
            true,
        );
    }

    /// Safe's CompatibilityFallbackHandler 1.4.1, which implements EIP-1271.
    fn compat_handler() -> Address {
        "0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99"
            .parse()
            .unwrap()
    }

    /// `isValidSignature(data_hash, blob)` answers `magic`.
    fn plant_is_valid_signature(
        mock: &CallMock,
        safe: Address,
        data_hash: B256,
        blob: &Bytes,
        magic: [u8; 4],
    ) {
        mock.set_call(
            safe,
            Bytes::from(
                crate::cow::safe_sig::isValidSignatureCall {
                    _dataHash: data_hash,
                    _signature: blob.clone(),
                }
                .abi_encode(),
            ),
            Bytes::from(alloy::primitives::FixedBytes::<4>(magic).abi_encode()),
            true,
        );
    }

    /// The blob the given local owners produce for `data_hash` — deterministic (RFC 6979).
    async fn expected_blob(seeds: &[u8], data_hash: B256) -> Bytes {
        let owners: Vec<KaoSigner> = seeds.iter().map(|s| local_signer(*s)).collect();
        crate::cow::safe_sig::sign_eip1271_digest(
            &owners,
            data_hash,
            addr(SAFE),
            Chain::Mainnet,
            crate::safe::tx::OwnerSigMode::Auto,
        )
        .await
        .unwrap()
    }

    fn message_job(threshold: u32, data_hash: B256) -> SafeMessageJob {
        SafeMessageJob {
            safe: addr(SAFE),
            chain: Chain::Mainnet,
            threshold,
            data_hash,
            pin: crate::cow::safe_sig::safe_message_hash(data_hash, addr(SAFE), Chain::Mainnet),
        }
    }

    /// A loopback stand-in for the Safe Transaction Service that serves at most one request
    /// (answering `201 Created`) and hands back the raw text — or `None` if nothing ever arrived.
    async fn one_shot_service() -> (String, tokio::task::JoinHandle<Option<String>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let served = tokio::spawn(async move {
            let accepted =
                tokio::time::timeout(std::time::Duration::from_millis(500), listener.accept())
                    .await;
            let Ok(Ok((mut sock, _))) = accepted else {
                return None;
            };
            let request = read_http_request(&mut sock).await;
            let _ = sock
                .write_all(
                    b"HTTP/1.1 201 Created\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await;
            let _ = sock.shutdown().await;
            let mut rest = Vec::new();
            let _ = sock.read_to_end(&mut rest).await;
            Some(String::from_utf8_lossy(&request).into_owned())
        });
        (base, served)
    }

    /// Read one HTTP/1.1 request (headers + `content-length` body) off `sock`.
    async fn read_http_request(sock: &mut tokio::net::TcpStream) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = sock.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                return buf;
            }
            buf.extend_from_slice(&chunk[..n]);
            let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let len = head
                .lines()
                .find_map(|l| {
                    l.strip_prefix("content-length:")
                        .and_then(|v| v.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                return buf;
            }
        }
    }

    // ── a loopback JSON-RPC node ──────────────────────────────────────────────

    type RpcAnswer = Arc<dyn Fn(&str, &Value) -> Result<Value, String> + Send + Sync>;
    type RpcLog = Arc<Mutex<Vec<(String, Value)>>>;

    /// An execution RPC on loopback: answers each JSON-RPC call through `answer` (an `Err` becomes a
    /// JSON-RPC error) and records `(method, params)` in arrival order.
    async fn rpc_node(answer: RpcAnswer) -> (String, RpcLog) {
        rpc_node_stalling(answer, |_| false).await
    }

    /// [`rpc_node`], except that a call whose method `stalls` is taken and never answered: the
    /// connection stays open, silent.
    async fn rpc_node_stalling(answer: RpcAnswer, stalls: fn(&str) -> bool) -> (String, RpcLog) {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let log: RpcLog = Arc::new(Mutex::new(Vec::new()));
        let seen = log.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let answer = answer.clone();
                let seen = seen.clone();
                tokio::spawn(async move {
                    let raw = read_http_request(&mut sock).await;
                    let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                        return;
                    };
                    let req: Value = serde_json::from_slice(&raw[end + 4..]).unwrap_or_default();
                    let method = req["method"].as_str().unwrap_or_default().to_string();
                    let params = req["params"].clone();
                    seen.lock().unwrap().push((method.clone(), params.clone()));
                    if stalls(&method) {
                        std::future::pending::<()>().await;
                    }
                    let reply = match answer(&method, &params) {
                        Ok(result) => {
                            json!({ "jsonrpc": "2.0", "id": req["id"], "result": result })
                        }
                        Err(message) => json!({
                            "jsonrpc": "2.0",
                            "id": req["id"],
                            "error": { "code": -32000, "message": message }
                        }),
                    };
                    let body = reply.to_string();
                    let _ = sock
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                                 content-length: {}\r\nconnection: close\r\n\r\n{body}",
                                body.len()
                            )
                            .as_bytes(),
                        )
                        .await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (url, log)
    }

    fn methods(log: &RpcLog) -> Vec<String> {
        log.lock().unwrap().iter().map(|(m, _)| m.clone()).collect()
    }

    /// `CallMock` state plus a real (loopback) execution provider — what `provider_for` hands the
    /// quote and the broadcast.
    #[derive(Debug)]
    struct RpcFetcher {
        state: CallMock,
        url: String,
    }

    #[async_trait::async_trait]
    impl BalanceFetcher for RpcFetcher {
        async fn balance(&self, a: Address, c: Chain) -> Result<String, String> {
            self.state.balance(a, c).await
        }
        async fn invalidate(&self) {}
        fn last_status(&self, c: Chain) -> VerificationStatus {
            self.state.last_status(c)
        }
        async fn provider(&self, _: Chain) -> Option<RootProvider<Ethereum>> {
            Some(RootProvider::<Ethereum>::new_http(self.url.parse().ok()?))
        }
        async fn get_code(&self, a: Address, c: Chain) -> Result<VerifiedRead<Bytes>, String> {
            self.state.get_code(a, c).await
        }
        async fn get_storage_at(
            &self,
            a: Address,
            slot: U256,
            c: Chain,
        ) -> Result<VerifiedRead<B256>, String> {
            self.state.get_storage_at(a, slot, c).await
        }
        async fn call(
            &self,
            to: Address,
            d: Bytes,
            c: Chain,
        ) -> Result<VerifiedRead<Bytes>, String> {
            self.state.call(to, d, c).await
        }
        async fn get_balance_raw(
            &self,
            a: Address,
            c: Chain,
        ) -> Result<VerifiedRead<U256>, String> {
            self.state.get_balance_raw(a, c).await
        }
        async fn get_transaction_count(
            &self,
            a: Address,
            c: Chain,
        ) -> Result<VerifiedRead<u64>, String> {
            self.state.get_transaction_count(a, c).await
        }
        async fn latest_block(&self, c: Chain) -> Result<VerifiedRead<LatestBlock>, String> {
            self.state.latest_block(c).await
        }
        async fn get_code_raw(&self, a: Address, c: Chain) -> Result<VerifiedRead<Bytes>, String> {
            self.state.get_code_raw(a, c).await
        }
        async fn get_storage_at_raw(
            &self,
            a: Address,
            slot: U256,
            c: Chain,
        ) -> Result<VerifiedRead<B256>, String> {
            self.state.get_storage_at_raw(a, slot, c).await
        }
        async fn call_raw(
            &self,
            to: Address,
            d: Bytes,
            c: Chain,
        ) -> Result<VerifiedRead<Bytes>, String> {
            self.state.call_raw(to, d, c).await
        }
    }

    fn quantity(n: u64) -> Value {
        Value::String(format!("{n:#x}"))
    }

    /// A node that quotes: `estimate` gas, a 1 gwei base fee with a 1 gwei tip, pending nonce
    /// `nonce`, and 1 ETH of balance.
    fn quoting_node(estimate: u64, nonce: u64) -> RpcAnswer {
        Arc::new(move |method, _| match method {
            "eth_estimateGas" => Ok(quantity(estimate)),
            "eth_feeHistory" => Ok(json!({
                "oldestBlock": "0x1",
                "baseFeePerGas": ["0x3b9aca00", "0x3b9aca00"],
                "gasUsedRatio": [0.5],
                "reward": [["0x3b9aca00"]]
            })),
            "eth_getTransactionCount" => Ok(quantity(nonce)),
            "eth_getBalance" => Ok(json!("0xde0b6b3a7640000")),
            "eth_chainId" => Ok(json!("0x1")),
            other => Err(format!("unexpected {other}")),
        })
    }

    /// A node for the send path: pending nonce `nonce`; a raw transaction is accepted and answered
    /// with its own hash.
    fn sending_node(nonce: u64) -> RpcAnswer {
        Arc::new(move |method, params| match method {
            "eth_getTransactionCount" => Ok(quantity(nonce)),
            "eth_sendRawTransaction" => {
                let raw = params[0].as_str().unwrap_or_default();
                let bytes = alloy::hex::decode(raw).map_err(|e| e.to_string())?;
                Ok(json!(format!("{:#x}", keccak256(bytes))))
            }
            "eth_chainId" => Ok(json!("0x1")),
            other => Err(format!("unexpected {other}")),
        })
    }

    fn call_plan(from: Address, data: Vec<u8>, value: u64) -> SendPlan {
        SendPlan {
            from,
            recipient: addr(0xC1),
            token: SendToken::Call {
                data: Bytes::from(data),
            },
            amount_units: U256::from(value),
            chain: NetworkId::Builtin(Chain::Mainnet),
        }
    }

    fn pinned_quote(plan: &SendPlan, nonce: u64) -> TxQuote {
        TxQuote {
            plan: plan.clone(),
            gas_limit: 77_777,
            max_fee_per_gas: 3_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            nonce,
            eth_cost_wei: U256::from(77_777u64) * U256::from(3_000_000_000u64),
            sim: crate::wallet::sim::SimulationResult::unavailable(),
        }
    }

    // ── hardware on demand ────────────────────────────────────────────────────

    /// The on-demand connect fires exactly for a hardware account whose live signer is still the
    /// unlock-time placeholder — never for a live signer, a software account or a watch-only one.
    #[test]
    fn needs_on_demand_connect_matrix() {
        let a = local_addr(0x11);
        let placeholder = KaoSigner::ViewOnly(a);
        let live = local_signer(0x11);
        assert!(needs_on_demand_connect(&placeholder, &ledger_desc(a)));
        assert!(needs_on_demand_connect(&placeholder, &trezor_desc(a)));
        assert!(!needs_on_demand_connect(&placeholder, &local_desc(0x11)));
        assert!(!needs_on_demand_connect(
            &placeholder,
            &crate::wallet::view_only_account(a)
        ));
        assert!(!needs_on_demand_connect(&live, &ledger_desc(a)));
        assert!(!needs_on_demand_connect(&live, &trezor_desc(a)));
        assert!(!needs_on_demand_connect(&live, &local_desc(0x11)));
    }

    #[tokio::test]
    async fn take_or_build_hands_out_a_live_signer() {
        let handoff = handoff_with(local_signer(0x11));
        let signer = take_or_build_live_signer(&handoff, &local_desc(0x11))
            .await
            .expect("a live software signer passes straight through");
        assert_eq!(signer.address(), local_addr(0x11));
        assert!(parked(&handoff).is_none(), "taken exactly once");
        assert!(
            take_or_build_live_signer(&handoff, &local_desc(0x11))
                .await
                .is_err(),
            "nothing left to take"
        );
    }

    /// A placeholder that can't sign is refused before any signing — and stays parked, so the
    /// dashboard's reclaim finds what it handed over.
    #[tokio::test]
    async fn placeholder_signer_is_refused_and_put_back() {
        let a = local_addr(0x11);
        let handoff = handoff_with(KaoSigner::ViewOnly(a));
        let err = live_signer_for(&handoff, &local_desc(0x11), a)
            .await
            .unwrap_err();
        assert!(!err.stale, "reconnecting can fix it: {err:?}");
        assert_eq!(parked(&handoff), Some((a, false)));
    }

    // ── personal_sign ─────────────────────────────────────────────────────────

    #[test]
    fn personal_steps_pin_the_eip191_digest() {
        let from = local_addr(0x11);
        let message = Bytes::from_static(b"Sign in to app.example");
        let call = wc::PersonalSign {
            from,
            message: message.clone(),
            shape: wc::MessageShape::Text {
                lines: vec!["Sign in to app.example".into()],
            },
            siwe: None,
        };
        let identity = wc::WcIdentity::Eoa { address: from };
        let (steps, pin) = personal_steps(
            origin(identity, "Sign message"),
            from,
            NetworkId::Builtin(Chain::Mainnet),
            &call,
            false,
        );
        assert_eq!(pin, eip191_hash_message(&message));
        assert!(matches!(steps.first(), Some(SignStep::WcOrigin(_))));
        match steps.get(1) {
            Some(SignStep::WcMessage(m)) => {
                assert_eq!(m.raw, message);
                assert_eq!(m.eip191_hash, pin);
                assert_eq!(m.from, from);
            }
            other => panic!("expected the message step, got {other:?}"),
        }
        assert_eq!(steps.len(), 2);
    }

    #[tokio::test]
    async fn personal_sign_recovers_answers_and_puts_the_signer_back() {
        let from = local_addr(0x11);
        let handoff = handoff_with(local_signer(0x11));
        let message = b"Sign in to app.example";
        let (live, checks) = guard(usize::MAX);
        let out = sign_personal(
            &handoff,
            &local_desc(0x11),
            from,
            message,
            eip191_hash_message(message),
            &live,
        )
        .await
        .expect("signed");
        let SignOutcome::Signature(sig) = out else {
            panic!("expected a signature");
        };
        assert_eq!(sig.len(), 65);
        assert!(matches!(sig[64], 27 | 28));
        let sig = Signature::from_raw(&sig).unwrap();
        assert_eq!(sig.recover_address_from_msg(message).unwrap(), from);
        assert_eq!(
            parked(&handoff),
            Some((from, true)),
            "signer back in the handoff"
        );
        assert_eq!(
            checks.load(Ordering::SeqCst),
            2,
            "liveness before the prompt and before the answer"
        );
    }

    #[tokio::test]
    async fn personal_pin_mismatch_refuses() {
        let from = local_addr(0x11);
        let handoff = handoff_with(local_signer(0x11));
        let (live, checks) = guard(usize::MAX);
        let err = sign_personal(
            &handoff,
            &local_desc(0x11),
            from,
            b"what the dapp sent",
            eip191_hash_message(b"what the review showed"),
            &live,
        )
        .await
        .unwrap_err();
        assert!(err.stale, "{err:?}");
        assert!(err.text.contains("reviewed"), "{}", err.text);
        assert_eq!(
            parked(&handoff),
            Some((from, true)),
            "never taken: no device woken"
        );
        assert_eq!(checks.load(Ordering::SeqCst), 0);
    }

    /// The key about to sign isn't the account the review showed — a mis-handed signer, or a
    /// mid-flight account switch: refused before signing, and the signer goes back untouched.
    #[tokio::test]
    async fn wc_sign_personal_refuses_wrong_signer() {
        let reviewed = local_addr(0x22);
        let message = b"Sign in to app.example";
        // The parked signer belongs to another account than the reviewed one.
        let handoff = handoff_with(local_signer(0x11));
        let err = sign_personal(
            &handoff,
            &local_desc(0x22),
            reviewed,
            message,
            eip191_hash_message(message),
            &alive(),
        )
        .await
        .unwrap_err();
        assert!(err.stale, "{err:?}");
        assert!(err.text.contains("signing key"), "{}", err.text);
        assert_eq!(parked(&handoff), Some((local_addr(0x11), true)));
        // The active account (its descriptor) is another one: refused before anything is taken.
        let err = sign_personal(
            &handoff,
            &local_desc(0x11),
            reviewed,
            message,
            eip191_hash_message(message),
            &alive(),
        )
        .await
        .unwrap_err();
        assert!(err.stale && err.text.contains("refusing"), "{err:?}");
        assert_eq!(parked(&handoff), Some((local_addr(0x11), true)));
    }

    /// The dapp stopped waiting while the signature was being made: it is discarded, not answered.
    #[tokio::test]
    async fn personal_signature_discarded_when_the_request_dies() {
        let from = local_addr(0x11);
        let handoff = handoff_with(local_signer(0x11));
        let message = b"Sign in to app.example";
        let (live, checks) = guard(1);
        let err = sign_personal(
            &handoff,
            &local_desc(0x11),
            from,
            message,
            eip191_hash_message(message),
            &live,
        )
        .await
        .unwrap_err();
        assert_eq!(err.text, STILL_WANTED_REFUSAL);
        assert!(!err.stale, "the runtime classes a dead request Gone");
        assert_eq!(checks.load(Ordering::SeqCst), 2);
        assert_eq!(parked(&handoff), Some((from, true)));
    }

    // ── typed data ────────────────────────────────────────────────────────────

    #[test]
    fn typed_steps_lead_with_origin_and_pin_the_checked_digests() {
        let from = local_addr(0x11);
        let req = typed_request(from);
        let identity = wc::WcIdentity::Eoa { address: from };
        let (steps, pin) = typed_steps(
            origin(identity, "Sign typed data"),
            from,
            NetworkId::Builtin(Chain::Mainnet),
            &req,
            true,
            None,
        );
        assert_eq!(pin, mail_digests());
        assert_eq!(steps.len(), 2);
        assert!(matches!(steps.first(), Some(SignStep::WcOrigin(_))));
        match steps.get(1) {
            Some(SignStep::WcTyped(t)) => {
                assert!(t.hash_mode_device, "a Ledger review discloses hash mode");
                assert_eq!(t.checked.digests, pin);
                assert_eq!(t.from, from);
            }
            other => panic!("expected the typed step, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn typed_signs_the_pinned_digest_and_puts_the_signer_back() {
        let from = local_addr(0x11);
        let handoff = handoff_with(local_signer(0x11));
        let pin = mail_digests();
        let out = sign_typed(&handoff, &local_desc(0x11), from, &mail(), pin, &alive())
            .await
            .expect("signed");
        let SignOutcome::Signature(sig) = out else {
            panic!("expected a signature");
        };
        let sig = Signature::from_raw(&sig).unwrap();
        assert_eq!(sig.recover_address_from_prehash(&pin.digest).unwrap(), from);
        assert_eq!(parked(&handoff), Some((from, true)));
    }

    #[tokio::test]
    async fn typed_pin_mismatch_refuses() {
        let from = local_addr(0x11);
        let handoff = handoff_with(local_signer(0x11));
        let mut pin = mail_digests();
        pin.message_hash = B256::repeat_byte(0x77);
        let (live, checks) = guard(usize::MAX);
        let err = sign_typed(&handoff, &local_desc(0x11), from, &mail(), pin, &live)
            .await
            .unwrap_err();
        assert!(err.stale, "{err:?}");
        assert_eq!(parked(&handoff), Some((from, true)), "never taken");
        assert_eq!(checks.load(Ordering::SeqCst), 0);
    }

    /// A Trezor has no EIP-712 path: refused before the placeholder is even taken, so no device
    /// is ever opened for it.
    #[tokio::test]
    async fn typed_refused_for_trezor_without_touching_the_device() {
        let a = addr(0x7E);
        let handoff = handoff_with(KaoSigner::ViewOnly(a));
        let err = sign_typed(
            &handoff,
            &trezor_desc(a),
            a,
            &mail(),
            mail_digests(),
            &alive(),
        )
        .await
        .unwrap_err();
        assert!(err.text.contains("Trezor"), "{}", err.text);
        assert!(err.stale);
        assert_eq!(
            parked(&handoff),
            Some((a, false)),
            "the placeholder never moved"
        );
    }

    // ── EOA transactions ──────────────────────────────────────────────────────

    /// Kao's gas-limit policy applied to the quote the review pins: the gas limit is rewritten and
    /// the fee ceiling recomputed with it; the fees and nonce are the node's.
    #[tokio::test]
    async fn prepare_eoa_tx_applies_gas_policy() {
        let (url, _log) = rpc_node(quoting_node(100_000, 7)).await;
        let network: Arc<dyn BalanceFetcher> = Arc::new(RpcFetcher {
            state: CallMock::new(),
            url,
        });
        let from = local_addr(0x11);
        // (calldata, dapp gas) → (pinned gas limit, how it was chosen)
        let cases = [
            (vec![], None, 100_000, wc::GasNote::Estimated),
            (
                vec![0x12, 0x34, 0x56, 0x78],
                None,
                120_000,
                wc::GasNote::Buffered { estimate: 100_000 },
            ),
            (
                vec![0x12, 0x34, 0x56, 0x78],
                Some(150_000),
                150_000,
                wc::GasNote::DappHonoured {
                    estimate: 100_000,
                    dapp: 150_000,
                },
            ),
            (
                vec![0x12, 0x34, 0x56, 0x78],
                Some(5_000_000),
                200_000,
                wc::GasNote::DappCapped {
                    estimate: 100_000,
                    dapp: 5_000_000,
                },
            ),
        ];
        for (data, dapp_gas, want_gas, want_note) in cases {
            let plan = call_plan(from, data, 5);
            let steps = prepare_eoa_tx(
                network.clone(),
                plan.clone(),
                dapp_gas,
                Vec::new(),
                HashMap::new(),
                None,
            )
            .await
            .expect("prepared");
            assert_eq!(steps.len(), 2, "no delegation on this account");
            assert!(matches!(steps.first(), Some(SignStep::RawTx(leg)) if leg.to == addr(0xC1)));
            let Some(SignStep::WcTxFees(fees)) = steps.get(1) else {
                panic!("expected the fees step");
            };
            assert_eq!(fees.quote.gas_limit, want_gas);
            assert_eq!(fees.gas_note, want_note);
            assert_eq!(
                fees.quote.eth_cost_wei,
                U256::from(want_gas) * U256::from(fees.quote.max_fee_per_gas),
                "the fee ceiling follows the pinned gas limit"
            );
            assert_eq!(
                fees.max_total_wei,
                U256::from(5u64) + fees.quote.eth_cost_wei
            );
            assert_eq!(
                fees.quote.nonce, 7,
                "the node's pending nonce, not the dapp's"
            );
            assert!(fees.quote.matches_plan(&plan));
            assert_eq!(
                fees.balance_wei,
                Some(U256::from(10u64).pow(U256::from(18u64)))
            );
            assert!(!fees.unverified_network);
        }
    }

    /// An account already running EIP-7702 code says so ahead of the call — a disclosure with no
    /// authorization to sign — and the fee step still closes the review.
    #[tokio::test]
    async fn prepare_eoa_tx_discloses_a_live_delegation() {
        let (url, _log) = rpc_node(quoting_node(60_000, 2)).await;
        let from = local_addr(0x11);
        let delegate = addr(0xDE);
        let state = CallMock::new();
        let mut designator = vec![0xef, 0x01, 0x00];
        designator.extend_from_slice(delegate.as_slice());
        state.set_code(from, Bytes::from(designator), true);
        let network: Arc<dyn BalanceFetcher> = Arc::new(RpcFetcher { state, url });
        let steps = prepare_eoa_tx(
            network,
            call_plan(from, vec![0x12, 0x34, 0x56, 0x78], 0),
            None,
            Vec::new(),
            HashMap::new(),
            Some(U256::from(1u64)),
        )
        .await
        .expect("prepared");
        assert_eq!(steps.len(), 3);
        match steps.first() {
            Some(SignStep::Delegation(d)) => {
                assert_eq!(d.delegate, delegate);
                assert_eq!(d.authority, from);
                assert!(d.already_active, "nothing new is installed");
                assert_eq!(
                    (d.auth_nonce, d.auth_digest),
                    (None, None),
                    "nothing to sign"
                );
            }
            other => panic!("expected the delegation disclosure, got {other:?}"),
        }
        assert!(matches!(steps.get(1), Some(SignStep::RawTx(_))));
        match steps.get(2) {
            Some(SignStep::WcTxFees(fees)) => {
                assert_eq!(
                    fees.balance_wei,
                    Some(U256::from(1u64)),
                    "the caller's balance wins"
                )
            }
            other => panic!("expected the fees step, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn prepare_eoa_tx_estimate_failure_is_a_prepare_error() {
        let failing: RpcAnswer = Arc::new(|method, _| match method {
            "eth_estimateGas" => Err("execution reverted".into()),
            other => Err(format!("unexpected {other}")),
        });
        let (url, log) = rpc_node(failing).await;
        let network: Arc<dyn BalanceFetcher> = Arc::new(RpcFetcher {
            state: CallMock::new(),
            url,
        });
        let err = prepare_eoa_tx(
            network,
            call_plan(local_addr(0x11), vec![0x12, 0x34], 0),
            None,
            Vec::new(),
            HashMap::new(),
            None,
        )
        .await
        .unwrap_err();
        assert!(err.contains("estimate_gas"), "{err}");
        assert_eq!(methods(&log), vec!["eth_estimateGas"]);
    }

    /// Mainnet refuses a transaction above EIP-7825's cap at the txpool, so one whose own estimate
    /// is above it is a prepare error there; elsewhere it is left to Kao's 30 M ceiling.
    #[tokio::test]
    async fn prepare_eoa_tx_refuses_an_estimate_over_the_eip7825_cap_on_mainnet() {
        let (url, _log) = rpc_node(quoting_node(20_000_000, 1)).await;
        let network: Arc<dyn BalanceFetcher> = Arc::new(RpcFetcher {
            state: CallMock::new(),
            url,
        });
        let prepare = |chain: Chain| {
            let plan = SendPlan {
                chain: NetworkId::Builtin(chain),
                ..call_plan(local_addr(0x11), Vec::new(), 1)
            };
            prepare_eoa_tx(
                network.clone(),
                plan,
                None,
                Vec::new(),
                HashMap::new(),
                Some(U256::MAX),
            )
        };
        let err = prepare(Chain::Mainnet).await.unwrap_err();
        assert!(err.contains("EIP-7825"), "{err}");
        let steps = prepare(Chain::Base)
            .await
            .expect("no such cap assumed off mainnet");
        assert_eq!(quote_of(&steps).gas_limit, 20_000_000);
    }

    /// A node whose estimate fails but that otherwise quotes: fees, nonce 3, 1 ETH of balance.
    fn non_estimating_node(reason: &'static str) -> RpcAnswer {
        Arc::new(move |method, _| match method {
            "eth_estimateGas" => Err(reason.into()),
            "eth_feeHistory" => Ok(json!({
                "oldestBlock": "0x1",
                "baseFeePerGas": ["0x3b9aca00", "0x3b9aca00"],
                "gasUsedRatio": [0.5],
                "reward": [["0x3b9aca00"]]
            })),
            "eth_getTransactionCount" => Ok(quantity(3)),
            "eth_getBalance" => Ok(json!("0xde0b6b3a7640000")),
            "eth_chainId" => Ok(json!("0x1")),
            other => Err(format!("unexpected {other}")),
        })
    }

    /// Kao's node can't estimate the call but the dapp sent a usable gas limit: the review is
    /// priced at exactly that limit (no buffer, no policy — there is no estimate to apply it to),
    /// with the node's reason carried, sanitized, for the red banner.
    #[tokio::test]
    async fn prepare_eoa_tx_estimate_failure_takes_the_dapps_gas() {
        let (url, log) = rpc_node(non_estimating_node(
            "execution reverted: insufficient allowance\u{202e}gnissap",
        ))
        .await;
        let network: Arc<dyn BalanceFetcher> = Arc::new(RpcFetcher {
            state: CallMock::new(),
            url,
        });
        let plan = call_plan(local_addr(0x11), vec![0x12, 0x34, 0x56, 0x78], 0);
        let steps = prepare_eoa_tx(
            network,
            plan.clone(),
            Some(300_000),
            Vec::new(),
            HashMap::new(),
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("{e}; rpc calls = {:?}", methods(&log)));
        let Some(SignStep::WcTxFees(fees)) = steps.last() else {
            panic!("expected the fees step");
        };
        assert_eq!(fees.quote.gas_limit, 300_000);
        assert_eq!(
            fees.gas_note,
            wc::GasNote::DappUnestimated { dapp: 300_000 }
        );
        assert_eq!(
            fees.quote.eth_cost_wei,
            U256::from(300_000u64) * U256::from(fees.quote.max_fee_per_gas)
        );
        assert_eq!(fees.quote.nonce, 3);
        assert!(fees.quote.matches_plan(&plan));
        let why = fees
            .estimate_failed
            .as_deref()
            .expect("the reason is carried");
        assert!(why.contains("insufficient allowance"), "{why}");
        assert!(!why.contains('\u{202e}'), "sanitized: {why:?}");
    }

    /// Without a dapp limit a node could include — none at all, under the intrinsic 21 000, or
    /// over the per-transaction cap — a failed estimate stays a prepare error.
    #[tokio::test]
    async fn prepare_eoa_tx_estimate_failure_without_a_usable_dapp_gas_is_an_error() {
        let (url, _log) = rpc_node(non_estimating_node("execution reverted")).await;
        let network: Arc<dyn BalanceFetcher> = Arc::new(RpcFetcher {
            state: CallMock::new(),
            url,
        });
        for dapp_gas in [None, Some(20_999), Some(wc::request::MAX_TX_GAS + 1)] {
            let err = prepare_eoa_tx(
                network.clone(),
                call_plan(local_addr(0x11), vec![0x12, 0x34], 0),
                dapp_gas,
                Vec::new(),
                HashMap::new(),
                None,
            )
            .await
            .unwrap_err();
            assert!(err.contains("estimate_gas"), "{dapp_gas:?}: {err}");
        }
    }

    /// A dapp gas limit under what its own calldata costs to carry — the intrinsic gas, or the
    /// EIP-7623 floor — can't be included either, so it is no fallback for a failed estimate.
    #[tokio::test]
    async fn prepare_eoa_tx_estimate_failure_refuses_a_dapp_gas_under_the_calldata_cost() {
        let (url, _log) = rpc_node(non_estimating_node("execution reverted")).await;
        let network: Arc<dyn BalanceFetcher> = Arc::new(RpcFetcher {
            state: CallMock::new(),
            url,
        });
        // Two non-zero bytes and one zero byte: 21 000 + 2·16 + 4 = 21 036 by the standard
        // schedule, 21 000 + 10·(2·4 + 1) = 21 090 by the EIP-7623 floor.
        let data = vec![0x12, 0x00, 0x34];
        assert_eq!(intrinsic_gas(&data), 21_090);
        let prepare = |dapp_gas: u64| {
            prepare_eoa_tx(
                network.clone(),
                call_plan(local_addr(0x11), data.clone(), 0),
                Some(dapp_gas),
                Vec::new(),
                HashMap::new(),
                None,
            )
        };
        for under in [21_000, 21_036, 21_089] {
            let err = prepare(under).await.unwrap_err();
            assert!(err.contains("estimate_gas"), "{under}: {err}");
        }
        let steps = prepare(21_090)
            .await
            .expect("the floor itself is includable");
        assert_eq!(quote_of(&steps).gas_limit, 21_090);
    }

    /// The node's reason for a failed estimate can quote the contract's revert string — text the
    /// dapp chooses. Wherever it is shown or logged it is escaped, so a newline or a U+202E is seen
    /// rather than acted on (no forged review line, no reordered copy, no forged log line), and
    /// it is bounded in length.
    #[tokio::test]
    async fn prepare_eoa_tx_estimate_reason_is_escaped_and_bounded_everywhere() {
        let reason: &'static str = Box::leak(
            format!(
                "execution reverted: \u{202e}\nKao verified this call: safe to sign {}",
                "x".repeat(4_000)
            )
            .into_boxed_str(),
        );
        let (url, _log) = rpc_node(non_estimating_node(reason)).await;
        let network: Arc<dyn BalanceFetcher> = Arc::new(RpcFetcher {
            state: CallMock::new(),
            url,
        });
        let (_guard, log) = wc::testkit::capture_logs("kao=warn");
        let prepare = |dapp_gas: Option<u64>| {
            prepare_eoa_tx(
                network.clone(),
                call_plan(local_addr(0x11), vec![0x12, 0x34], 0),
                dapp_gas,
                Vec::new(),
                HashMap::new(),
                None,
            )
        };
        let shown_safely = |text: &str| {
            assert!(
                !text.contains('\u{202e}') && !text.contains('\n'),
                "unescaped: {text:?}"
            );
            assert!(text.contains("\\u{202E}"), "escaped, not dropped: {text:?}");
            assert!(
                text.chars().count() <= MAX_ESTIMATE_ERROR_CHARS + 1,
                "bounded: {} chars",
                text.chars().count()
            );
        };
        // No usable dapp gas: the reason is the prepare error the review shows.
        let err = prepare(None).await.unwrap_err();
        shown_safely(&err);
        // The dapp's gas carries the review: the reason is its red banner.
        let steps = prepare(Some(300_000))
            .await
            .expect("priced at the dapp's gas");
        let Some(SignStep::WcTxFees(fees)) = steps.last() else {
            panic!("expected the fees step");
        };
        shown_safely(
            fees.estimate_failed
                .as_deref()
                .expect("the reason is carried"),
        );
        let log = log.text();
        assert!(log.contains("estimate_gas failed"), "{log}");
        assert!(
            !log.contains("\nKao verified") && !log.contains('\u{202e}'),
            "a revert string forged a log line: {log}"
        );
        assert!(
            log.len() < 4_000,
            "the logged reason is bounded: {} bytes",
            log.len()
        );
    }

    #[tokio::test]
    async fn prepare_eoa_tx_refuses_a_non_call_plan() {
        let network: Arc<dyn BalanceFetcher> = Arc::new(CallMock::new());
        let plan = SendPlan {
            token: SendToken::Native,
            ..call_plan(local_addr(0x11), Vec::new(), 1)
        };
        let err = prepare_eoa_tx(network, plan, None, Vec::new(), HashMap::new(), None)
            .await
            .unwrap_err();
        assert!(err.contains("call"), "{err}");
    }

    /// Exactly the reviewed numbers reach the chain: the raw transaction carries the pinned nonce,
    /// gas limit and fees and the dapp's call verbatim, signed by the reviewed account.
    #[tokio::test]
    async fn eoa_tx_signs_pinned_quote() {
        use alloy::consensus::{SignableTransaction, TxEnvelope};
        use alloy::eips::eip2718::Decodable2718;
        let (url, log) = rpc_node(sending_node(5)).await;
        let network: Arc<dyn BalanceFetcher> = Arc::new(RpcFetcher {
            state: CallMock::new(),
            url,
        });
        let from = local_addr(0x11);
        let handoff = handoff_with(local_signer(0x11));
        let plan = call_plan(from, vec![0xde, 0xad, 0xbe, 0xef], 3);
        let quote = pinned_quote(&plan, 5);
        let (live, checks) = guard(usize::MAX);
        let out = send_eoa_tx(&network, &handoff, &local_desc(0x11), plan, quote, live)
            .await
            .expect("broadcast");
        let SignOutcome::Tx(hash) = out else {
            panic!("expected a transaction hash");
        };

        let calls = log.lock().unwrap().clone();
        let (nonce_call, sent) = (&calls[0], &calls[1]);
        assert_eq!(nonce_call.0, "eth_getTransactionCount");
        assert_eq!(
            nonce_call.1[1],
            json!("pending"),
            "the pending nonce, mempool included"
        );
        assert_eq!(sent.0, "eth_sendRawTransaction");
        assert_eq!(
            calls.len(),
            2,
            "no re-estimate: the quote is signed verbatim"
        );
        let raw = alloy::hex::decode(sent.1[0].as_str().unwrap()).unwrap();
        let TxEnvelope::Eip1559(signed) = TxEnvelope::decode_2718(&mut raw.as_slice()).unwrap()
        else {
            panic!("expected an EIP-1559 envelope");
        };
        let tx = signed.tx();
        assert_eq!(tx.chain_id, 1);
        assert_eq!(tx.nonce, 5);
        assert_eq!(tx.gas_limit, 77_777);
        assert_eq!(tx.max_fee_per_gas, 3_000_000_000);
        assert_eq!(tx.max_priority_fee_per_gas, 1_000_000_000);
        assert_eq!(tx.to, alloy::primitives::TxKind::Call(addr(0xC1)));
        assert_eq!(tx.value, U256::from(3u64));
        assert_eq!(tx.input, Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(
            signed
                .signature()
                .recover_address_from_prehash(&tx.signature_hash())
                .unwrap(),
            from
        );
        assert_eq!(hash, *signed.hash());
        assert_eq!(
            parked(&handoff),
            Some((from, true)),
            "signer back in the handoff"
        );
        assert_eq!(
            checks.load(Ordering::SeqCst),
            2,
            "liveness before the prompt and between signature and broadcast"
        );
    }

    /// Something was sent from the account since the review: nothing is signed, the parked signer
    /// is never taken, and the failure is stale so the coordinator re-quotes.
    #[tokio::test]
    async fn moved_nonce_is_stale() {
        let (url, log) = rpc_node(sending_node(6)).await;
        let network: Arc<dyn BalanceFetcher> = Arc::new(RpcFetcher {
            state: CallMock::new(),
            url,
        });
        let from = local_addr(0x11);
        let handoff = handoff_with(local_signer(0x11));
        let plan = call_plan(from, vec![0xde, 0xad, 0xbe, 0xef], 0);
        let quote = pinned_quote(&plan, 5);
        let err = send_eoa_tx(&network, &handoff, &local_desc(0x11), plan, quote, alive())
            .await
            .unwrap_err();
        assert!(err.stale, "{err:?}");
        assert!(err.text.contains("5 → 6"), "{}", err.text);
        assert_eq!(methods(&log), vec!["eth_getTransactionCount"]);
        assert_eq!(parked(&handoff), Some((from, true)));
    }

    #[tokio::test]
    async fn eoa_tx_refuses_a_quote_for_another_call() {
        let network: Arc<dyn BalanceFetcher> = Arc::new(CallMock::new());
        let from = local_addr(0x11);
        let handoff = handoff_with(local_signer(0x11));
        let reviewed = call_plan(from, vec![0xaa], 0);
        let quote = pinned_quote(&reviewed, 5);
        let other = call_plan(from, vec![0xab], 0);
        let err = send_eoa_tx(&network, &handoff, &local_desc(0x11), other, quote, alive())
            .await
            .unwrap_err();
        assert!(err.stale, "{err:?}");
        assert_eq!(parked(&handoff), Some((from, true)));
    }

    /// The dapp stopped waiting after the signature was made: the signed envelope is discarded and
    /// nothing is broadcast.
    #[tokio::test]
    async fn eoa_tx_not_broadcast_once_the_request_dies() {
        let (url, log) = rpc_node(sending_node(5)).await;
        let network: Arc<dyn BalanceFetcher> = Arc::new(RpcFetcher {
            state: CallMock::new(),
            url,
        });
        let from = local_addr(0x11);
        let handoff = handoff_with(local_signer(0x11));
        let plan = call_plan(from, vec![0x01], 0);
        let quote = pinned_quote(&plan, 5);
        let (live, checks) = guard(1);
        let err = send_eoa_tx(&network, &handoff, &local_desc(0x11), plan, quote, live)
            .await
            .unwrap_err();
        assert_eq!(err.text, STILL_WANTED_REFUSAL);
        assert_eq!(checks.load(Ordering::SeqCst), 2);
        assert_eq!(
            methods(&log),
            vec!["eth_getTransactionCount"],
            "nothing sent"
        );
        assert_eq!(parked(&handoff), Some((from, true)));
    }

    /// A node that accepts the first raw transaction but drops the reply, bumping the pending
    /// nonce; later raw transactions are accepted and answered. With `lookups`, it also answers
    /// `eth_getTransactionByHash` for what it holds (and `null` for anything else, receipts
    /// included); without, it doesn't support lookups at all.
    async fn lossy_node(start_nonce: u64, lookups: bool) -> (String, Arc<Mutex<Vec<Vec<u8>>>>) {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let nonce = Arc::new(AtomicU64::new(start_nonce));
        let sent: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let mempool = sent.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let nonce = nonce.clone();
                let mempool = mempool.clone();
                tokio::spawn(async move {
                    let raw = read_http_request(&mut sock).await;
                    let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                        return;
                    };
                    let req: Value = serde_json::from_slice(&raw[end + 4..]).unwrap_or_default();
                    let result: Result<Value, String> = match req["method"]
                        .as_str()
                        .unwrap_or_default()
                    {
                        "eth_estimateGas" => Ok(quantity(100_000)),
                        "eth_feeHistory" => Ok(
                            json!({"oldestBlock":"0x1","baseFeePerGas":["0x3b9aca00","0x3b9aca00"],"gasUsedRatio":[0.5],"reward":[["0x3b9aca00"]]}),
                        ),
                        "eth_getTransactionCount" => Ok(quantity(nonce.load(Ordering::SeqCst))),
                        "eth_getBalance" => Ok(json!("0xde0b6b3a7640000")),
                        "eth_chainId" => Ok(json!("0x1")),
                        "eth_getTransactionByHash" if lookups => {
                            let want = req["params"][0].as_str().unwrap_or_default();
                            let held = mempool
                                .lock()
                                .unwrap()
                                .iter()
                                .find(|raw| format!("{:#x}", keccak256(raw)) == want)
                                .cloned();
                            Ok(held.map_or(Value::Null, |raw| pooled_tx_json(&raw)))
                        }
                        "eth_getTransactionReceipt" if lookups => Ok(Value::Null),
                        "eth_sendRawTransaction" => {
                            let bytes =
                                alloy::hex::decode(req["params"][0].as_str().unwrap()).unwrap();
                            let first = {
                                let mut p = mempool.lock().unwrap();
                                p.push(bytes.clone());
                                p.len() == 1
                            };
                            nonce.fetch_add(1, Ordering::SeqCst);
                            if first {
                                let _ = sock.shutdown().await;
                                return;
                            }
                            Ok(json!(format!("{:#x}", keccak256(bytes))))
                        }
                        other => Err(format!("unexpected {other}")),
                    };
                    let reply = match result {
                        Ok(r) => json!({"jsonrpc":"2.0","id":req["id"],"result":r}),
                        Err(m) => {
                            json!({"jsonrpc":"2.0","id":req["id"],"error":{"code":-32000,"message":m}})
                        }
                    };
                    let body = reply.to_string();
                    let _ = sock
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                                 content-length: {}\r\nconnection: close\r\n\r\n{body}",
                                body.len()
                            )
                            .as_bytes(),
                        )
                        .await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (url, sent)
    }

    /// A pending transaction as `eth_getTransactionByHash` returns it.
    fn pooled_tx_json(raw: &[u8]) -> Value {
        use alloy::consensus::TxEnvelope;
        use alloy::consensus::transaction::{Recovered, SignerRecoverable};
        use alloy::eips::eip2718::Decodable2718;
        let envelope = TxEnvelope::decode_2718(&mut &raw[..]).unwrap();
        let from = envelope.recover_signer().unwrap();
        serde_json::to_value(alloy::rpc::types::Transaction {
            inner: Recovered::new_unchecked(envelope, from),
            block_hash: None,
            block_number: None,
            transaction_index: None,
            effective_gas_price: None,
            block_timestamp: None,
        })
        .unwrap()
    }

    /// `plan`'s call signed by the local key `seed` at `nonce`, as a broadcast would have sent it.
    async fn signed_tx(seed: u8, plan: &SendPlan, nonce: u64) -> wc::UnconfirmedTx {
        use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
        use alloy::eips::eip2718::Encodable2718;
        let (to, value, input) = plan.tx_target();
        let mut tx = TxEip1559 {
            chain_id: plan.chain.chain_id(),
            nonce,
            gas_limit: 77_777,
            max_fee_per_gas: 3_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: alloy::primitives::TxKind::Call(to),
            value,
            access_list: Default::default(),
            input,
        };
        let sig = local_signer(seed).sign_tx(&mut tx).await.unwrap();
        let envelope: TxEnvelope = tx.into_signed(sig).into();
        wc::UnconfirmedTx {
            hash: *envelope.tx_hash(),
            raw: Bytes::from(envelope.encoded_2718()),
            nonce,
        }
    }

    fn quote_of(steps: &[SignStep]) -> TxQuote {
        steps
            .iter()
            .find_map(|s| match s {
                SignStep::WcTxFees(f) => Some(f.quote.clone()),
                _ => None,
            })
            .unwrap()
    }

    /// The node takes the transaction but the reply is lost, and it can't be looked up either.
    /// The failure is neither a retry nor stale — either would lead to a second signature at a
    /// fresh nonce — but carries the exact signed bytes. Sending those again is the only way on,
    /// and it never makes a second, distinct transaction.
    #[tokio::test]
    async fn lost_broadcast_reply_keeps_the_signed_bytes_and_resends_only_them() {
        let (url, mempool) = lossy_node(5, false).await;
        let network: Arc<dyn BalanceFetcher> = Arc::new(RpcFetcher {
            state: CallMock::new(),
            url,
        });
        let (from, desc, handoff) = (
            local_addr(0x11),
            local_desc(0x11),
            handoff_with(local_signer(0x11)),
        );
        let plan = call_plan(from, vec![0xde, 0xad, 0xbe, 0xef], 3);
        let steps = prepare_eoa_tx(
            network.clone(),
            plan.clone(),
            None,
            Vec::new(),
            HashMap::new(),
            None,
        )
        .await
        .unwrap();
        let quote = quote_of(&steps);
        assert_eq!(quote.nonce, 5);
        let err = send_eoa_tx(&network, &handoff, &desc, plan.clone(), quote, alive())
            .await
            .unwrap_err();
        assert!(!err.stale, "never re-quoted: {err:?}");
        assert!(err.text.starts_with("broadcast failed"), "{}", err.text);
        let tx = err.unconfirmed.clone().expect("the signed bytes come back");
        assert_eq!(tx.nonce, 5);
        assert_eq!(keccak256(&tx.raw), tx.hash);
        assert_eq!(
            mempool.lock().unwrap().as_slice(),
            std::slice::from_ref(&tx.raw.to_vec()),
            "exactly these bytes reached the node"
        );
        assert_eq!(parked(&handoff), Some((from, true)));

        // Sending again: the same bytes, answered with their own hash. No signer is involved.
        let out = resend_eoa_tx(&network, plan.chain, tx.clone(), &alive())
            .await
            .expect("re-sent");
        assert!(matches!(out, SignOutcome::Tx(h) if h == tx.hash), "{out:?}");
        let pool = mempool.lock().unwrap().clone();
        assert_eq!(pool.len(), 2);
        assert!(
            pool.iter().all(|raw| raw.as_slice() == tx.raw.as_ref()),
            "never a second, distinct transaction"
        );
    }

    /// The reply was lost, but the node has the transaction: its hash is the dapp's answer, with
    /// no second send at all.
    #[tokio::test]
    async fn lost_broadcast_reply_found_by_hash_is_the_answer() {
        let (url, mempool) = lossy_node(5, true).await;
        let network: Arc<dyn BalanceFetcher> = Arc::new(RpcFetcher {
            state: CallMock::new(),
            url,
        });
        let from = local_addr(0x11);
        let handoff = handoff_with(local_signer(0x11));
        let plan = call_plan(from, vec![0xde, 0xad, 0xbe, 0xef], 3);
        let quote = pinned_quote(&plan, 5);
        let out = send_eoa_tx(&network, &handoff, &local_desc(0x11), plan, quote, alive())
            .await
            .expect("the node has it");
        let pool = mempool.lock().unwrap().clone();
        assert_eq!(pool.len(), 1, "sent once");
        assert!(
            matches!(out, SignOutcome::Tx(h) if h == keccak256(&pool[0])),
            "{out:?}"
        );
    }

    /// The node answered and refused the transaction as invalid — a verdict on its own bytes that
    /// every node gives alike, so it can't be on its way. Nothing latches: the failure re-quotes,
    /// and nothing is looked up or sent again. A refusal that hangs on the node or the chain's
    /// state (a fee cap, a nonce already used), or an error that isn't the node's answer, stays
    /// unconfirmed: the transaction may still be somewhere.
    #[tokio::test]
    async fn a_nodes_refusal_of_an_invalid_transaction_does_not_latch() {
        let refusing = |reason: &'static str| -> RpcAnswer {
            Arc::new(move |method, _| match method {
                "eth_getTransactionCount" => Ok(quantity(5)),
                "eth_sendRawTransaction" => Err(reason.to_string()),
                "eth_getTransactionByHash" | "eth_getTransactionReceipt" => Ok(Value::Null),
                "eth_chainId" => Ok(json!("0x1")),
                other => Err(format!("unexpected {other}")),
            })
        };
        for (reason, invalid) in [
            ("intrinsic gas too low: have 21000, want 21064", true),
            (
                "insufficient gas for floor data gas cost: have 21000, want 21160",
                true,
            ),
            (
                "transaction gas limit too high (cap: 16777216, tx: 30000000)",
                true,
            ),
            ("transaction type not supported", true),
            ("invalid sender", true),
            ("invalid chain id for signer", true),
            ("max priority fee per gas higher than max fee per gas", true),
            (
                "tx fee (1.20 ether) exceeds the configured cap (1.00 ether)",
                false,
            ),
            ("nonce too low: next nonce 6, tx nonce 5", false),
            ("already known", false),
            ("insufficient funds for gas * price + value", false),
            ("upstream request timed out", false),
        ] {
            let (url, log) = rpc_node(refusing(reason)).await;
            let network: Arc<dyn BalanceFetcher> = Arc::new(RpcFetcher {
                state: CallMock::new(),
                url,
            });
            let (from, desc, handoff) = (
                local_addr(0x11),
                local_desc(0x11),
                handoff_with(local_signer(0x11)),
            );
            let plan = call_plan(from, vec![0xde, 0xad, 0xbe, 0xef], 3);
            let quote = pinned_quote(&plan, 5);
            let err = send_eoa_tx(&network, &handoff, &desc, plan, quote, alive())
                .await
                .unwrap_err();
            assert!(err.text.contains(reason), "{reason}: {}", err.text);
            assert_eq!(parked(&handoff), Some((from, true)));
            if invalid {
                assert!(
                    err.unconfirmed.is_none(),
                    "{reason}: a refused transaction latched the request: {err:?}"
                );
                assert!(
                    err.stale,
                    "{reason}: re-quoted, never the same bytes: {err:?}"
                );
                assert_eq!(
                    methods(&log),
                    vec!["eth_getTransactionCount", "eth_sendRawTransaction"],
                    "{reason}: sent once, nothing looked up"
                );
            } else {
                let tx = err.unconfirmed.as_ref().unwrap_or_else(|| {
                    panic!("{reason}: may be elsewhere, so it latches: {err:?}")
                });
                assert_eq!(tx.nonce, 5);
                assert!(!err.stale, "{reason}: never re-quoted: {err:?}");
            }
        }
    }

    /// A first send whose fate is unknown, then a re-send of the same bytes that the node refuses
    /// as invalid on any node: those bytes could never have been taken anywhere, the first time
    /// included. The request lets go of them (re-quoted, never sent again) and nothing is looked
    /// up. A refusal that hangs on the node or the chain's state keeps the request latched.
    #[tokio::test]
    async fn a_resend_refused_as_invalid_lets_go_of_the_transaction() {
        let refusing = |reason: &'static str| -> RpcAnswer {
            Arc::new(move |method, _| match method {
                "eth_sendRawTransaction" => Err(reason.to_string()),
                "eth_getTransactionByHash" | "eth_getTransactionReceipt" => Ok(Value::Null),
                "eth_chainId" => Ok(json!("0x1")),
                other => Err(format!("unexpected {other}")),
            })
        };
        let plan = call_plan(local_addr(0x11), vec![0xde, 0xad, 0xbe, 0xef], 3);
        let tx = signed_tx(0x11, &plan, 5).await;
        for (reason, invalid) in [
            ("intrinsic gas too low: have 21000, want 21064", true),
            ("transaction type not supported", true),
            ("nonce too low: next nonce 6, tx nonce 5", false),
            (
                "tx fee (1.20 ether) exceeds the configured cap (1.00 ether)",
                false,
            ),
            ("upstream request timed out", false),
        ] {
            let (url, log) = rpc_node(refusing(reason)).await;
            let network: Arc<dyn BalanceFetcher> = Arc::new(RpcFetcher {
                state: CallMock::new(),
                url,
            });
            let err = resend_eoa_tx(&network, plan.chain, tx.clone(), &alive())
                .await
                .unwrap_err();
            assert!(err.text.contains(reason), "{reason}: {}", err.text);
            if invalid {
                assert!(
                    err.unconfirmed.is_none(),
                    "{reason}: bytes no node can take latched the request: {err:?}"
                );
                assert!(err.voided, "{reason}: {err:?}");
                assert!(err.stale, "{reason}: a fresh look: {err:?}");
                assert_eq!(
                    methods(&log),
                    vec!["eth_sendRawTransaction"],
                    "{reason}: nothing looked up"
                );
            } else {
                assert_eq!(err.unconfirmed.as_ref(), Some(&tx), "{reason}: {err:?}");
                assert!(!err.voided, "{reason}: {err:?}");
                assert!(!err.stale, "{reason}: {err:?}");
            }
        }
    }

    /// A re-send for a request the dapp stopped waiting for sends nothing.
    #[tokio::test]
    async fn resend_sends_nothing_once_the_request_dies() {
        let (url, mempool) = lossy_node(5, false).await;
        let network: Arc<dyn BalanceFetcher> = Arc::new(RpcFetcher {
            state: CallMock::new(),
            url,
        });
        let plan = call_plan(local_addr(0x11), vec![0x01], 0);
        let tx = signed_tx(0x11, &plan, 5).await;
        let (live, _) = guard(0);
        let err = resend_eoa_tx(&network, plan.chain, tx, &live)
            .await
            .unwrap_err();
        assert_eq!(err.text, STILL_WANTED_REFUSAL);
        assert!(mempool.lock().unwrap().is_empty());
    }

    /// Once a transaction left for a request, nothing more is signed for it: the wall answers
    /// with that transaction, so the review latches onto it.
    #[test]
    fn never_signed_twice_wall() {
        assert!(never_signed_twice(None).is_ok());
        let tx = wc::UnconfirmedTx {
            hash: B256::repeat_byte(0xaa),
            raw: Bytes::from_static(&[1, 2, 3]),
            nonce: 9,
        };
        let f = never_signed_twice(Some(tx.clone())).unwrap_err();
        assert!(!f.stale);
        assert_eq!(f.unconfirmed, Some(tx));
    }

    /// The review reopened on a transaction already sent describes its own bytes — and refuses
    /// bytes that aren't exactly this call, at this nonce, from this account.
    #[tokio::test]
    async fn signed_quote_reads_the_envelope_and_refuses_anything_else() {
        let from = local_addr(0x11);
        let plan = call_plan(from, vec![0xde, 0xad, 0xbe, 0xef], 3);
        let tx = signed_tx(0x11, &plan, 5).await;
        let q = signed_quote(&plan, &tx).expect("its own bytes");
        assert_eq!(
            (
                q.nonce,
                q.gas_limit,
                q.max_fee_per_gas,
                q.max_priority_fee_per_gas
            ),
            (5, 77_777, 3_000_000_000, 1_000_000_000)
        );
        assert_eq!(q.eth_cost_wei, U256::from(77_777u64 * 3_000_000_000));
        assert!(q.matches_plan(&plan));
        // Another call, another nonce, another signer, another hash: refused.
        let other = call_plan(from, vec![0xde, 0xad], 3);
        assert!(signed_quote(&other, &tx).is_err());
        assert!(
            signed_quote(
                &plan,
                &wc::UnconfirmedTx {
                    nonce: 6,
                    ..tx.clone()
                }
            )
            .is_err()
        );
        let wrong_key = signed_tx(0x22, &plan, 5).await;
        assert!(signed_quote(&plan, &wrong_key).is_err());
        let wrong_hash = wc::UnconfirmedTx {
            hash: B256::repeat_byte(1),
            ..tx.clone()
        };
        assert!(signed_quote(&plan, &wrong_hash).is_err());
        let garbage = wc::UnconfirmedTx {
            raw: Bytes::from_static(&[0x02, 0xc0]),
            ..tx
        };
        assert!(signed_quote(&plan, &garbage).is_err());
    }

    /// Reopened, a request whose transaction already left is shown as signed — nothing is
    /// estimated, priced or read for a nonce.
    #[tokio::test]
    async fn prepare_unconfirmed_eoa_tx_prices_nothing() {
        let (url, log) = rpc_node(quoting_node(100_000, 9)).await;
        let network: Arc<dyn BalanceFetcher> = Arc::new(RpcFetcher {
            state: CallMock::new(),
            url,
        });
        let plan = call_plan(local_addr(0x11), vec![0xde, 0xad, 0xbe, 0xef], 3);
        let tx = signed_tx(0x11, &plan, 5).await;
        let steps =
            prepare_unconfirmed_eoa_tx(network, plan.clone(), tx, Vec::new(), HashMap::new(), None)
                .await
                .expect("prepared");
        let Some(SignStep::WcTxFees(fees)) = steps.last() else {
            panic!("expected the fees step");
        };
        assert_eq!((fees.quote.nonce, fees.quote.gas_limit), (5, 77_777));
        assert_eq!(fees.gas_note, wc::GasNote::AsSigned);
        assert!(matches!(steps.first(), Some(SignStep::RawTx(leg)) if leg.to == addr(0xC1)));
        assert_eq!(methods(&log), vec!["eth_getBalance"]);
    }

    // ── Safe transactions ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn safe_tx_refuses_a_delegatecall() {
        let network: Arc<dyn BalanceFetcher> = Arc::new(CallMock::new());
        let mut req = safe_call_req(addr(0xC1), 1);
        req.input.operation = Operation::DelegateCall;
        pin_at(&mut req, 4);
        let err = prepare_safe_tx(network.clone(), req.clone(), HashMap::new(), Vec::new())
            .await
            .unwrap_err();
        assert!(err.contains("delegatecall"), "{err}");
        let err = execute_safe_tx(
            network.clone(),
            req.clone(),
            vec![local_desc(0x31)],
            None,
            alive(),
            wc_opts(),
        )
        .await
        .unwrap_err();
        assert!(err.stale && err.text.contains("delegatecall"), "{err:?}");
        let err = propose_safe_tx(network, local_desc(0x31), req, alive(), wc_opts())
            .await
            .unwrap_err();
        assert!(err.stale && err.text.contains("delegatecall"), "{err:?}");
    }

    /// A co-signer executed something since the review: the pinned nonce is gone, so the failure
    /// is stale (Confirm disabled), not a retry that can only fail again.
    #[tokio::test]
    async fn execute_moved_safe_nonce_is_stale() {
        let mock = CallMock::new();
        plant_nonce(&mock, addr(SAFE), 5);
        let mut req = safe_call_req(addr(0xC1), 1);
        pin_at(&mut req, 4);
        let err = execute_safe_tx(
            Arc::new(mock),
            req,
            vec![local_desc(0x31)],
            None,
            alive(),
            wc_opts(),
        )
        .await
        .unwrap_err();
        assert!(err.stale, "{err:?}");
        assert!(err.text.contains("4 → 5"), "{}", err.text);
    }

    /// A Safe whose live nonce is 4, threshold 1, owned by the local key 0x31, with the executor's
    /// transactions going to `url`; and the dapp's call pinned at nonce 4.
    fn executable_safe_call(
        url: String,
    ) -> (Arc<dyn BalanceFetcher>, tx_builder::SafeBatchRequest) {
        let mut req = safe_call_req(addr(0xC1), 1);
        let (tx, hash) = pin_at(&mut req, 4);
        let state = CallMock::new();
        plant_tx_agreement(&state, addr(SAFE), &tx, hash);
        plant_nonce(&state, addr(SAFE), 4);
        plant_owner_set(&state, addr(SAFE), &[local_addr(0x31)], 1);
        (Arc::new(RpcFetcher { state, url }), req)
    }

    /// The executor's `execTransaction` reached the node but its reply was lost, and it can't be
    /// looked up. While it sits unmined the Safe still reads the pinned nonce, so the failure must
    /// not be a plain retry — the next Confirm would walk the owners again and sign a second,
    /// distinct executor transaction at the next nonce, which can only revert. It carries the
    /// executor's exact signed bytes instead: nothing is signed for the request again, and only
    /// those bytes are ever sent again.
    #[tokio::test]
    async fn safe_exec_lost_reply_keeps_the_executor_bytes_and_never_signs_again() {
        let (url, mempool) = lossy_node(9, false).await;
        let (network, req) = executable_safe_call(url);
        let err = execute_safe_tx(
            network.clone(),
            req,
            vec![local_desc(0x31)],
            None,
            alive(),
            wc_opts(),
        )
        .await
        .unwrap_err();
        assert!(!err.stale && err.class.is_none(), "{err:?}");
        assert!(err.text.starts_with("broadcast failed"), "{}", err.text);
        let sent = err
            .unconfirmed
            .clone()
            .expect("a lost executor reply latches onto the executor's bytes");
        assert_eq!(sent.nonce, 9, "the executor's own nonce");
        assert_eq!(keccak256(&sent.raw), sent.hash);
        assert_eq!(
            mempool.lock().unwrap().as_slice(),
            std::slice::from_ref(&sent.raw.to_vec()),
            "exactly these bytes reached the node"
        );
        // The spawn's wall: nothing more is signed for this request.
        let wall = never_signed_twice(err.unconfirmed).unwrap_err();
        assert_eq!(wall.unconfirmed.as_ref(), Some(&sent));
        // Sending again is those bytes, answered with their own hash.
        let out = resend_eoa_tx(
            &network,
            NetworkId::Builtin(Chain::Mainnet),
            sent.clone(),
            &alive(),
        )
        .await
        .expect("re-sent");
        assert!(
            matches!(out, SignOutcome::Tx(h) if h == sent.hash),
            "{out:?}"
        );
        let pool = mempool.lock().unwrap().clone();
        assert_eq!(pool.len(), 2);
        assert!(
            pool.iter().all(|raw| raw.as_slice() == sent.raw.as_ref()),
            "never a second, distinct executor transaction"
        );
    }

    /// The executor's reply was lost, but the node has its transaction: that hash is the dapp's
    /// answer, with nothing signed or sent a second time.
    #[tokio::test]
    async fn safe_exec_lost_reply_found_by_hash_is_the_answer() {
        let (url, mempool) = lossy_node(9, true).await;
        let (network, req) = executable_safe_call(url);
        let out = execute_safe_tx(
            network,
            req,
            vec![local_desc(0x31)],
            None,
            alive(),
            wc_opts(),
        )
        .await
        .expect("the node has the executor's transaction");
        let pool = mempool.lock().unwrap().clone();
        assert_eq!(pool.len(), 1, "sent once");
        assert_eq!(out.hash, keccak256(&pool[0]));
        assert_eq!(
            out.sent,
            Some((local_addr(0x31), 9)),
            "the executor and the nonce it took, for the hold's watch"
        );
    }

    // ── the hold on an executed Safe transaction's nonce ─────────────────────

    /// An executor transaction (from the local key 0x31) as the node would hold it.
    async fn executor_tx() -> (TxHash, Vec<u8>) {
        use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
        use alloy::eips::eip2718::Encodable2718;
        let mut tx = TxEip1559 {
            chain_id: 1,
            nonce: 9,
            gas_limit: 100_000,
            max_fee_per_gas: 3_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: alloy::primitives::TxKind::Call(addr(SAFE)),
            value: U256::ZERO,
            access_list: Default::default(),
            input: Bytes::from(vec![0x6a, 0x76, 0x12, 0x02]),
        };
        let sig = local_signer(0x31).sign_tx(&mut tx).await.unwrap();
        let envelope: TxEnvelope = tx.into_signed(sig).into();
        (*envelope.tx_hash(), envelope.encoded_2718())
    }

    /// What the node says of the executor's transaction at each look.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum NodeSays {
        Pending,
        Mined,
        Unknown,
    }

    /// A Safe at nonce 4 whose node answers each look at the executor's transaction with the next
    /// of `says` (the last one repeating), and the executor's account nonce with the returned
    /// counter (9: its transaction not yet in a block). The Safe's nonce can be moved through the
    /// fetcher.
    async fn watched_node(says: Vec<NodeSays>) -> (Arc<RpcFetcher>, TxHash, Arc<AtomicU64>) {
        let (hash, raw) = executor_tx().await;
        let looks = Arc::new(AtomicUsize::new(0));
        let executor_nonce = Arc::new(AtomicU64::new(9));
        let account = executor_nonce.clone();
        let answer: RpcAnswer = Arc::new(move |method, _| {
            let say = |n: usize| says[n.min(says.len() - 1)];
            match method {
                "eth_getTransactionByHash" => {
                    let n = looks.fetch_add(1, Ordering::SeqCst);
                    Ok(match say(n) {
                        NodeSays::Pending => pooled_tx_json(&raw),
                        NodeSays::Mined => {
                            let mut tx = pooled_tx_json(&raw);
                            tx["blockHash"] = json!(format!("{:#x}", B256::repeat_byte(0xb1)));
                            tx["blockNumber"] = json!("0x10");
                            tx["transactionIndex"] = json!("0x0");
                            tx
                        }
                        NodeSays::Unknown => Value::Null,
                    })
                }
                "eth_getTransactionReceipt" => Ok(Value::Null),
                "eth_getTransactionCount" => {
                    Ok(json!(format!("{:#x}", account.load(Ordering::SeqCst))))
                }
                other => Err(format!("unexpected {other}")),
            }
        });
        let (url, _) = rpc_node(answer).await;
        let state = CallMock::new();
        plant_nonce(&state, addr(SAFE), 4);
        (Arc::new(RpcFetcher { state, url }), hash, executor_nonce)
    }

    fn held_at_4() -> SafeExecInFlight {
        SafeExecInFlight {
            safe: addr(SAFE),
            chain: Chain::Mainnet,
            nonce: 4,
        }
    }

    const LOOK: Duration = Duration::from_millis(5);
    const GONE: Duration = Duration::from_millis(150);

    /// Looks every [`LOOK`], taking a transaction the node doesn't show for `gone_after` as
    /// dropped; no hold is too long.
    fn pace(gone_after: Duration) -> SafeExecPace {
        SafeExecPace {
            poll: LOOK,
            slow_poll: LOOK,
            slow_after: Duration::MAX,
            gone_after,
            max_hold: Duration::MAX,
            read_timeout: Duration::MAX,
        }
    }

    /// An execution the node holds as pending keeps its nonce however long it waits — a moment
    /// the node didn't know it, between looks that it did, included. Short of the longest hold
    /// ([`SafeExecPace::max_hold`]), no clock lets it go.
    #[tokio::test]
    async fn an_execution_hold_lasts_while_its_transaction_is_pending() {
        use NodeSays::*;
        let mut says = vec![Unknown, Pending, Unknown, Pending];
        says.extend(
            std::iter::repeat_n(Pending, 4)
                .chain([Unknown])
                .cycle()
                .take(200),
        );
        says.push(Pending);
        let (fetcher, hash, _) = watched_node(says).await;
        let executor = ExecutorTx::by_hash(hash);
        let watch = watch_safe_exec(fetcher.as_ref(), held_at_4(), executor, pace(GONE));
        assert!(
            tokio::time::timeout(GONE * 4, watch).await.is_err(),
            "the hold ended while the execution was pending"
        );
    }

    /// The execution is mined: the Safe's nonce moved past it, or its transaction is in a block
    /// (even while the Safe's nonce still reads the old one).
    #[tokio::test]
    async fn an_execution_hold_ends_once_mined() {
        let (fetcher, hash, _) = watched_node(vec![NodeSays::Pending]).await;
        let moved = fetcher.clone();
        tokio::spawn(async move {
            tokio::time::sleep(LOOK * 10).await;
            plant_nonce(&moved.state, addr(SAFE), 5);
        });
        let executor = ExecutorTx::by_hash(hash);
        let end = tokio::time::timeout(
            GONE * 4,
            watch_safe_exec(fetcher.as_ref(), held_at_4(), executor, pace(GONE)),
        )
        .await
        .expect("ended");
        assert_eq!(end, SafeExecEnd::Mined);

        let (fetcher, hash, _) =
            watched_node(vec![NodeSays::Pending, NodeSays::Pending, NodeSays::Mined]).await;
        let executor = ExecutorTx::by_hash(hash);
        let end = tokio::time::timeout(
            GONE * 4,
            watch_safe_exec(fetcher.as_ref(), held_at_4(), executor, pace(GONE)),
        )
        .await
        .expect("ended");
        assert_eq!(end, SafeExecEnd::Mined);
    }

    /// A transaction the node stops knowing, with nothing else settling it, is taken as dropped
    /// only once the node has gone the whole grace period without it. Not sooner.
    #[tokio::test]
    async fn an_execution_hold_ends_once_its_transaction_is_gone() {
        let (fetcher, hash, _) = watched_node(vec![NodeSays::Pending, NodeSays::Unknown]).await;
        let started = tokio::time::Instant::now();
        let executor = ExecutorTx::by_hash(hash);
        let end = tokio::time::timeout(
            GONE * 10,
            watch_safe_exec(fetcher.as_ref(), held_at_4(), executor, pace(GONE)),
        )
        .await
        .expect("ended");
        assert_eq!(end, SafeExecEnd::Dropped);
        assert!(started.elapsed() >= GONE, "{:?}", started.elapsed());
    }

    /// The executor's own nonce moving past its transaction settles it whatever the node shows:
    /// that went into a block, or another transaction took its place. Known from the signed bytes
    /// for a node that never shows the transaction; learned from the node when it does.
    #[tokio::test]
    async fn an_execution_hold_ends_once_the_executor_nonce_moves_past_it() {
        let (_, raw) = executor_tx().await;
        let kept = wc::UnconfirmedTx {
            hash: keccak256(&raw),
            raw: Bytes::from(raw),
            nonce: 9,
        };
        let known = ExecutorTx::of(&kept);
        assert_eq!(known.sent, Some((local_addr(0x31), 9)));
        for (says, executor) in [
            (vec![NodeSays::Unknown], known),
            (
                vec![NodeSays::Pending, NodeSays::Unknown],
                ExecutorTx::by_hash(kept.hash),
            ),
        ] {
            let (fetcher, _, executor_nonce) = watched_node(says).await;
            let mut watch = std::pin::pin!(watch_safe_exec(
                fetcher.as_ref(),
                held_at_4(),
                executor,
                pace(GONE * 100),
            ));
            assert!(
                tokio::time::timeout(GONE * 2, &mut watch).await.is_err(),
                "the hold ended while the executor's nonce was still open"
            );
            executor_nonce.store(10, Ordering::SeqCst);
            let end = tokio::time::timeout(GONE * 4, watch).await.expect("ended");
            assert_eq!(end, SafeExecEnd::Spent);
        }
    }

    /// A node that doesn't show the executor's transaction — a private relay routed it, or the
    /// node evicted it — says nothing about whether it can still be mined. Alone, that lifts the
    /// hold only far later than a relay keeps trying a transaction: the bound on a hold that no
    /// node and no nonce ever settles.
    #[test]
    fn an_unseen_execution_is_held_far_longer_than_a_relay_retries_it() {
        let gone_after = SAFE_EXEC_PACE.gone_after;
        assert!(gone_after >= Duration::from_secs(30 * 60), "{gone_after:?}");
    }

    /// Every hold ends: one whose transaction the node keeps showing as pending — underpriced,
    /// say — lifts once it has lasted the longest a hold may, with nothing else settling it.
    #[tokio::test]
    async fn an_execution_hold_ends_at_its_longest_even_while_pending() {
        let (fetcher, hash, _) = watched_node(vec![NodeSays::Pending]).await;
        let started = tokio::time::Instant::now();
        let executor = ExecutorTx::by_hash(hash);
        let pace = SafeExecPace {
            max_hold: GONE,
            ..pace(GONE * 100)
        };
        let end = tokio::time::timeout(
            GONE * 10,
            watch_safe_exec(fetcher.as_ref(), held_at_4(), executor, pace),
        )
        .await
        .expect("ended");
        assert_eq!(end, SafeExecEnd::Overdue);
        assert!(started.elapsed() >= GONE, "{:?}", started.elapsed());
    }

    /// A node that takes every call and never answers can't keep a hold up past the longest hold:
    /// the watch ends however its reads hang.
    #[tokio::test]
    async fn a_node_that_never_answers_cant_hold_past_the_longest_hold() {
        let (url, _) = rpc_node_stalling(Arc::new(|_, _| Ok(Value::Null)), |_| true).await;
        let state = CallMock::new();
        plant_nonce(&state, addr(SAFE), 4);
        let fetcher = RpcFetcher { state, url };
        let (hash, _) = executor_tx().await;
        let pace = SafeExecPace {
            max_hold: GONE,
            ..pace(GONE * 100)
        };
        let end = tokio::time::timeout(
            Duration::from_secs(5),
            watch_safe_exec(&fetcher, held_at_4(), ExecutorTx::by_hash(hash), pace),
        )
        .await
        .expect("a hung read kept the hold up past its longest");
        assert_eq!(end, SafeExecEnd::Overdue);
    }

    /// A read that never answers is given up on, so the look goes on to the reads that do: here
    /// the executor's own nonce, past the one its transaction took, settles the hold.
    #[tokio::test]
    async fn a_read_that_never_answers_doesnt_stall_the_watch() {
        let answer: RpcAnswer = Arc::new(|method, _| match method {
            "eth_getTransactionCount" => Ok(json!("0xa")),
            other => Err(format!("unexpected {other}")),
        });
        let (url, _) = rpc_node_stalling(answer, |m| m == "eth_getTransactionByHash").await;
        let state = CallMock::new();
        plant_nonce(&state, addr(SAFE), 4);
        let fetcher = RpcFetcher { state, url };
        let (_, raw) = executor_tx().await;
        let kept = wc::UnconfirmedTx {
            hash: keccak256(&raw),
            raw: Bytes::from(raw),
            nonce: 9,
        };
        let pace = SafeExecPace {
            read_timeout: LOOK * 4,
            ..pace(GONE * 100)
        };
        let end = tokio::time::timeout(
            Duration::from_secs(5),
            watch_safe_exec(&fetcher, held_at_4(), ExecutorTx::of(&kept), pace),
        )
        .await
        .expect("the hung lookup stalled the watch");
        assert_eq!(end, SafeExecEnd::Spent);
    }

    /// A node Kao can't read at all says nothing about the execution: unlike one that answers it
    /// doesn't know the transaction, it doesn't count toward taking it as dropped. Such a hold
    /// lasts until the longest hold.
    #[tokio::test]
    async fn an_unreadable_node_doesnt_drop_a_hold() {
        let (url, _) = rpc_node(Arc::new(|_, _| Err("unavailable".into()))).await;
        let fetcher = RpcFetcher {
            state: CallMock::new(),
            url,
        };
        let (hash, _) = executor_tx().await;
        let executor = ExecutorTx::by_hash(hash);
        assert!(
            tokio::time::timeout(
                GONE * 4,
                watch_safe_exec(&fetcher, held_at_4(), executor, pace(GONE))
            )
            .await
            .is_err(),
            "taken as dropped while nothing could be read"
        );
        let pace = SafeExecPace {
            max_hold: GONE * 2,
            ..pace(GONE)
        };
        let end = tokio::time::timeout(
            GONE * 10,
            watch_safe_exec(&fetcher, held_at_4(), executor, pace),
        )
        .await
        .expect("ended");
        assert_eq!(end, SafeExecEnd::Overdue);
    }

    /// Only an execution known to be past taking the nonce resets what its hold kept back; one
    /// the watch gave up on may still be mined.
    #[test]
    fn only_a_settled_execution_lifts_its_hold_as_settled() {
        use wc::book::HoldEnd;
        assert_eq!(SafeExecEnd::Mined.hold_end(), HoldEnd::Settled);
        assert_eq!(SafeExecEnd::Spent.hold_end(), HoldEnd::Settled);
        assert_eq!(SafeExecEnd::Dropped.hold_end(), HoldEnd::GaveUp);
        assert_eq!(SafeExecEnd::Overdue.hold_end(), HoldEnd::GaveUp);
    }

    /// A hold looks often while its execution may land in the next block, then backs off: it runs
    /// on through lock and Turn off. The longest hold is as long as a node's pool keeps a
    /// transaction it can't mine — far past the grace for one the node doesn't show at all.
    #[test]
    fn a_long_hold_looks_less_often_and_still_ends() {
        let p = SAFE_EXEC_PACE;
        assert_eq!(p.next_look(Duration::ZERO), Duration::from_secs(3));
        assert_eq!(p.next_look(p.slow_after - Duration::from_secs(1)), p.poll);
        assert_eq!(p.next_look(p.slow_after), Duration::from_secs(30));
        assert_eq!(p.next_look(Duration::from_secs(60 * 60)), p.slow_poll);
        assert!(
            p.slow_after <= Duration::from_secs(5 * 60),
            "{:?}",
            p.slow_after
        );
        assert!(p.max_hold > p.gone_after, "{p:?}");
        assert!(p.max_hold <= Duration::from_secs(3 * 60 * 60), "{p:?}");
        assert!(p.read_timeout <= Duration::from_secs(30), "{p:?}");
    }

    /// Co-signers see Kao's constant origin, never a dapp-controlled string, and the dapp is
    /// answered with the reviewed safeTxHash.
    #[tokio::test]
    async fn propose_origin_is_constant() {
        let owner = local_desc(0x31);
        let mut req = safe_call_req(addr(0xC1), 2);
        let (tx, hash) = pin_at(&mut req, 4);
        let (base, served) = one_shot_service().await;
        req.service_base = base;
        let mock = CallMock::new();
        plant_tx_agreement(&mock, addr(SAFE), &tx, hash);
        plant_nonce(&mock, addr(SAFE), 4);
        plant_owner_set(&mock, addr(SAFE), &[local_addr(0x31), addr(0x99)], 2);
        let out = propose_safe_tx(Arc::new(mock), owner, req, alive(), wc_opts())
            .await
            .expect("proposed");
        assert!(matches!(out, SignOutcome::SafeProposed(h) if h == hash));
        let request = served.await.unwrap().expect("the proposal was filed");
        assert!(
            request.contains(&format!(r#""origin":"{}""#, wc::SAFE_PROPOSE_ORIGIN)),
            "{request}"
        );
        assert_eq!(wc::SAFE_PROPOSE_ORIGIN, "Kao:walletconnect");
        assert!(request.contains(&format!("{hash:#x}")), "{request}");
        assert!(request.contains(r#""operation":0"#), "{request}");
    }

    /// The proposing owner is the active account: it signs with the dashboard's own live signer,
    /// parked for the task — never a second connection to its device — and that signer is back in
    /// the handoff afterwards. (The owner here is a Ledger account whose parked signer is a stand-in
    /// with its address: building a new one would have to reach a device.)
    #[tokio::test]
    async fn propose_signs_with_the_parked_active_signer_and_puts_it_back() {
        let owner = ledger_desc(local_addr(0x31));
        let mut req = safe_call_req(addr(0xC1), 2);
        let (tx, hash) = pin_at(&mut req, 4);
        let (base, served) = one_shot_service().await;
        req.service_base = base;
        let mock = CallMock::new();
        plant_tx_agreement(&mock, addr(SAFE), &tx, hash);
        plant_nonce(&mock, addr(SAFE), 4);
        plant_owner_set(&mock, addr(SAFE), &[local_addr(0x31), addr(0x99)], 2);
        let handoff = handoff_with(local_signer(0x31));
        let opts = OwnerSignOpts {
            parked: Some(handoff.clone()),
            ..wc_opts()
        };
        let out = propose_safe_tx(Arc::new(mock), owner, req, alive(), opts)
            .await
            .expect("proposed with the parked signer");
        assert!(matches!(out, SignOutcome::SafeProposed(h) if h == hash));
        assert!(served.await.unwrap().is_some(), "the proposal was filed");
        assert_eq!(parked(&handoff), Some((local_addr(0x31), true)));
    }

    /// A request that died is never filed for co-signers — not before the owner signs, and not
    /// with the signature already in hand.
    #[tokio::test]
    async fn propose_not_filed_when_dead() {
        for allow in [0, 1] {
            let owner = local_desc(0x31);
            let mut req = safe_call_req(addr(0xC1), 2);
            let (tx, hash) = pin_at(&mut req, 4);
            let (base, served) = one_shot_service().await;
            req.service_base = base;
            let mock = CallMock::new();
            plant_tx_agreement(&mock, addr(SAFE), &tx, hash);
            plant_nonce(&mock, addr(SAFE), 4);
            plant_owner_set(&mock, addr(SAFE), &[local_addr(0x31), addr(0x99)], 2);
            let (live, checks) = guard(allow);
            let err = propose_safe_tx(Arc::new(mock), owner, req, live, wc_opts())
                .await
                .unwrap_err();
            assert_eq!(err.text, STILL_WANTED_REFUSAL, "allow {allow}");
            assert!(!err.stale);
            // The refusing hook, then the failure classifier asking once more (and, seeing a dead
            // request, reading nothing).
            assert_eq!(checks.load(Ordering::SeqCst), allow + 2);
            assert!(
                served.await.unwrap().is_none(),
                "nothing filed (allow {allow})"
            );
        }
    }

    /// A Safe-identity dapp call that confirms (`approveHash`) a transaction on ANOTHER of the
    /// user's Safes is an owner action, flagged as the EOA path flags it — and the flag is what
    /// turns the labels into explicit overrides.
    #[tokio::test]
    async fn safe_identity_approve_hash_into_another_known_safe_is_flagged() {
        let other = addr(0xB5);
        let mut data = keccak256(b"approveHash(bytes32)")[..4].to_vec();
        data.extend_from_slice(B256::repeat_byte(0x77).as_slice());
        let mut req = safe_call_req(other, 1);
        req.input.data = Bytes::from(data);
        let (tx, hash) = pin_at(&mut req.clone(), 5);
        let mock = CallMock::new();
        plant_nonce(&mock, addr(SAFE), 5);
        plant_tx_agreement(&mock, addr(SAFE), &tx, hash);
        let known = vec![(other, "B".to_string())];
        let steps = prepare_safe_tx(Arc::new(mock), req, HashMap::new(), known)
            .await
            .expect("prepares");
        let [SignStep::SafeExec(x)] = steps.as_slice() else {
            panic!("{steps:?}")
        };
        let banner = x.inner.self_admin.as_deref().unwrap_or_default();
        assert!(
            banner.contains("approveHash") && banner.contains("“B”"),
            "a Safe-identity approveHash into another Kao Safe gets no owner-action banner: \
             {banner:?}"
        );
    }

    /// A SafeTx's kind as admission builds it: CALL `data` to `to`, no gas or refund.
    fn safe_tx_kind(to: Address, data: Vec<u8>, operation: u8) -> wc::TypedKind {
        wc::TypedKind::SafeTx {
            safe: Some(addr(SAFE)),
            to,
            value: U256::ZERO,
            data: Bytes::from(data),
            operation,
            safe_tx_gas: U256::ZERO,
            base_gas: U256::ZERO,
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce: U256::from(7),
        }
    }

    async fn safe_tx_call(
        kind: wc::TypedKind,
        known: Vec<(Address, String)>,
    ) -> sign_review::ReviewLeg {
        let steps = prepare_safe_tx_call(
            Arc::new(CallMock::new()),
            NetworkId::Builtin(Chain::Mainnet),
            kind,
            known,
            HashMap::new(),
        )
        .await
        .expect("decodes");
        let [SignStep::RawTx(leg)] = <[SignStep; 1]>::try_from(steps).expect("one leg") else {
            panic!("not a leg")
        };
        leg
    }

    /// The call a SafeTx owner confirmation would have the Safe make, flagged as a Safe
    /// transaction step flags its inner call: a call to the Safe itself reconfigures it, an
    /// `approveHash` into another of the user's Safes is an owner action there.
    #[tokio::test]
    async fn safe_tx_call_is_decoded_and_flagged_like_a_safe_inner_call() {
        let mut add_owner = keccak256(b"addOwnerWithThreshold(address,uint256)")[..4].to_vec();
        add_owner.extend_from_slice(B256::left_padding_from(&[0xba, 0xdb, 0xad]).as_slice());
        add_owner.extend_from_slice(&U256::from(1).to_be_bytes::<32>());
        let leg = safe_tx_call(safe_tx_kind(addr(SAFE), add_owner.clone(), 0), Vec::new()).await;
        assert_eq!(
            (leg.to, leg.calldata.to_vec()),
            (addr(SAFE), add_owner),
            "exactly the SafeTx's call"
        );
        assert!(
            leg.self_admin
                .as_deref()
                .is_some_and(|w| w.contains("reconfigures")),
            "{:?}",
            leg.self_admin
        );

        let other = addr(0xB5);
        let mut approve = keccak256(b"approveHash(bytes32)")[..4].to_vec();
        approve.extend_from_slice(B256::repeat_byte(0x77).as_slice());
        let leg = safe_tx_call(
            safe_tx_kind(other, approve, 0),
            vec![(other, "B".to_string())],
        )
        .await;
        assert!(
            leg.self_admin
                .as_deref()
                .is_some_and(|w| w.contains("approveHash") && w.contains("“B”")),
            "{:?}",
            leg.self_admin
        );

        assert!(
            prepare_safe_tx_call(
                Arc::new(CallMock::new()),
                NetworkId::Builtin(Chain::Mainnet),
                wc::TypedKind::Generic,
                Vec::new(),
                HashMap::new(),
            )
            .await
            .is_err()
        );
    }

    /// A Safe{Wallet} batch — a delegatecall to the canonical MultiSendCallOnly — is unpacked from
    /// the signed `data` into its sub-calls, each decoded and flagged on its own.
    #[tokio::test]
    async fn safe_tx_multisend_batch_is_unpacked() {
        use crate::txbuilder::multisend::{
            MULTISEND_CALL_ONLY_1_4_1, encode_multisend_calldata, encode_packed,
        };
        let call = |to: Address, data: Vec<u8>| crate::txbuilder::QueuedCall {
            id: 0,
            to,
            value: U256::ZERO,
            data: Bytes::from(data),
            title: String::new(),
            detail: String::new(),
            signature: None,
            decoded_args: Vec::new(),
        };
        let mut change_threshold = keccak256(b"changeThreshold(uint256)")[..4].to_vec();
        change_threshold.extend_from_slice(&U256::from(1).to_be_bytes::<32>());
        let data = encode_multisend_calldata(&encode_packed(&[
            call(addr(0xC1), vec![0x01, 0x02, 0x03, 0x04]),
            call(addr(SAFE), change_threshold),
        ]));
        let leg = safe_tx_call(
            safe_tx_kind(MULTISEND_CALL_ONLY_1_4_1, data.to_vec(), 1),
            Vec::new(),
        )
        .await;
        assert_eq!(leg.calldata, data, "the outer call is the signed bytes");
        assert_eq!(leg.sub_legs.len(), 2);
        assert!(leg.sub_legs[0].self_admin.is_none());
        assert!(
            leg.sub_legs[1].self_admin.is_some(),
            "a sub-call to the Safe itself is flagged"
        );
        // Not the canonical library: no unpacking on the dapp's word — decoded as a plain call,
        // under the operation banner's warning.
        let leg = safe_tx_call(safe_tx_kind(addr(0xD1), data.to_vec(), 1), Vec::new()).await;
        assert!(leg.sub_legs.is_empty());
        assert!(leg.title.starts_with("Delegatecall"), "{}", leg.title);
    }

    /// Safe{Wallet} batches through the official MultiSendCallOnly deployments other than the
    /// 1.3.0 canonical and 1.4.1 ones — 1.5.0, and the 1.3.0 EIP-155 variant that OP and Base
    /// list first — are unpacked like any canonical batch, not shown as one opaque delegatecall
    /// to an unknown library.
    #[tokio::test]
    async fn safe_tx_batches_through_every_official_multisend_are_unpacked() {
        use crate::txbuilder::multisend::{encode_multisend_calldata, encode_packed};
        let call = |to: Address, data: Vec<u8>| crate::txbuilder::QueuedCall {
            id: 0,
            to,
            value: U256::ZERO,
            data: Bytes::from(data),
            title: String::new(),
            detail: String::new(),
            signature: None,
            decoded_args: Vec::new(),
        };
        let mut change_threshold = keccak256(b"changeThreshold(uint256)")[..4].to_vec();
        change_threshold.extend_from_slice(&U256::from(1).to_be_bytes::<32>());
        let data = encode_multisend_calldata(&encode_packed(&[
            call(addr(0xC1), vec![0x01, 0x02, 0x03, 0x04]),
            call(addr(SAFE), change_threshold),
        ]));
        for lib in [
            "0x40A2aCCbd92BCA938b02010E17A5b8929b49130D",
            "0xA1dabEF33b3B82c7814B6D82A79e50F4AC44102B",
            "0x9641d764fc13c8B624c04430C7356C1C7C8102e2",
            "0xA83c336B20401Af773B6219BA5027174338D1836",
        ] {
            let lib: Address = lib.parse().unwrap();
            let leg = safe_tx_call(safe_tx_kind(lib, data.to_vec(), 1), Vec::new()).await;
            assert_eq!(leg.sub_legs.len(), 2, "{lib}: {}", leg.title);
            assert!(leg.title.starts_with("MultiSend"), "{lib}: {}", leg.title);
        }
    }

    /// No composer simulated a dapp's Safe call, so the prepare does: a call that reverts now is
    /// said so on the review, before any owner signs.
    #[tokio::test]
    async fn prepare_safe_tx_dry_runs_the_dapp_call() {
        let mut req = safe_call_req(addr(0xC1), 1);
        let (tx, hash) = pin_at(&mut req.clone(), 5);
        let mock = CallMock::new();
        plant_nonce(&mock, addr(SAFE), 5);
        plant_tx_agreement(&mock, addr(SAFE), &tx, hash);
        // `PUSH1 0x00 PUSH1 0x00 REVERT`.
        mock.set_code(
            addr(0xC1),
            Bytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xfd]),
            true,
        );
        req.prepared = None;
        let steps = prepare_safe_tx(Arc::new(mock), req, HashMap::new(), Vec::new())
            .await
            .expect("a reverting call still prepares — the review says why");
        let [SignStep::SafeExec(x)] = steps.as_slice() else {
            panic!("{steps:?}")
        };
        assert!(
            x.preflight.as_ref().is_some_and(|p| p.is_revert()),
            "{:?}",
            x.preflight
        );
        assert!(x.inner.self_admin.is_none(), "an ordinary call");
    }

    /// A dapp call that reverts at execute time is refused in the dapp's terms — not the
    /// Transaction Builder's "re-simulate the batch" — and classed as an execute refusal: Execute
    /// would only re-run the same failing preflight, while Propose doesn't run it.
    #[tokio::test]
    async fn reverting_dapp_safe_tx_is_refused_in_dapp_terms_and_stale() {
        let owner = local_desc(0x31);
        let mut req = safe_call_req(addr(0xC1), 1);
        let (tx, hash) = pin_at(&mut req, 4);
        let mock = CallMock::new();
        plant_tx_agreement(&mock, addr(SAFE), &tx, hash);
        plant_nonce(&mock, addr(SAFE), 4);
        plant_owner_set(&mock, addr(SAFE), &[local_addr(0x31)], 1);
        // `PUSH1 0x00 PUSH1 0x00 REVERT`.
        mock.set_code(
            addr(0xC1),
            Bytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xfd]),
            true,
        );
        let err = execute_safe_tx(Arc::new(mock), req, vec![owner], None, alive(), wc_opts())
            .await
            .unwrap_err();
        assert!(
            !err.text.contains("re-simulate") && !err.text.contains("This batch"),
            "Transaction Builder copy shown to a dapp user: {}",
            err.text
        );
        assert!(err.text.contains("would revert"), "{}", err.text);
        assert!(err.text.contains("Nothing was signed"), "{}", err.text);
        // Executing would only re-run the same preflight; proposing doesn't run it, so the review
        // keeps that and withdraws only Execute.
        assert_eq!(
            err.class,
            Some(FailureClass::ExecuteRefused),
            "execute refused, propose still on offer: {err:?}"
        );
    }

    #[tokio::test]
    async fn propose_refuses_an_unknown_queue() {
        let mut req = safe_call_req(addr(0xC1), 2);
        pin_at(&mut req, 4);
        req.queued_nonces = None;
        let err = propose_safe_tx(
            Arc::new(CallMock::new()),
            local_desc(0x31),
            req,
            alive(),
            wc_opts(),
        )
        .await
        .unwrap_err();
        assert!(err.stale && err.text.contains("queue"), "{err:?}");
    }

    // ── Safe messages (EIP-1271) ──────────────────────────────────────────────

    /// The copy follows the verdict, not the detail's wording: a rejection reads as one whatever
    /// the Safe answered, and only an unreachable check reads as "couldn't check".
    #[test]
    fn eip1271_copy_follows_the_verdict() {
        use crate::cow::safe_sig::Eip1271Check;
        let rejected = eip1271_failure_text(&Eip1271Check::Rejected(
            "the Safe answered 0xffffffff".into(),
        ));
        assert!(
            rejected.starts_with("the Safe didn't accept these owner signatures"),
            "{rejected}"
        );
        let unreachable = eip1271_failure_text(&Eip1271Check::Unreachable(
            "isValidSignature returned nothing: connection reset".into(),
        ));
        assert!(
            unreachable.starts_with("couldn't check the signature against the Safe"),
            "{unreachable}"
        );
    }

    #[test]
    fn safe_message_steps_pin_the_safe_message_hash() {
        let safe = addr(SAFE);
        let req = typed_request(safe);
        let signers = vec![signing_owner_of(0, &local_desc(0x31))];
        let identity = wc::WcIdentity::Safe {
            address: safe,
            chain_id: 1,
        };
        let (steps, data_hash, pin) = safe_message_steps(
            origin(identity, "Sign typed data"),
            safe,
            Chain::Mainnet,
            2,
            3,
            signers,
            WcSafeMessageSource::Typed(&req),
        );
        assert_eq!(
            data_hash,
            mail_digests().digest,
            "the dapp's own EIP-712 digest"
        );
        assert_eq!(
            pin,
            crate::cow::safe_sig::safe_message_hash(data_hash, safe, Chain::Mainnet)
        );
        assert!(matches!(steps.first(), Some(SignStep::WcOrigin(_))));
        match steps.get(1) {
            Some(SignStep::WcSafeMessage(m)) => {
                assert_eq!(m.message_hash, pin);
                assert_eq!(
                    m.eip712.digest, pin,
                    "the triple the owners' devices commit to"
                );
                assert_eq!((m.threshold, m.owner_count), (2, 3));
                assert_eq!(m.signers.len(), 1);
                assert!(matches!(m.inner, WcSafeMessageInner::Typed(_)));
            }
            other => panic!("expected the Safe message step, got {other:?}"),
        }
    }

    /// A `personal_sign` to a Safe: the dapp will ask `isValidSignature` about the EIP-191 digest
    /// of its message, so that is the data hash the owners' SafeMessage wraps.
    #[test]
    fn safe_message_steps_wrap_the_personal_eip191_digest() {
        let safe = addr(SAFE);
        let message = Bytes::from_static(b"Sign in to app.example");
        let call = wc::PersonalSign {
            from: safe,
            message: message.clone(),
            shape: wc::MessageShape::Text {
                lines: vec!["Sign in to app.example".into()],
            },
            siwe: None,
        };
        let identity = wc::WcIdentity::Safe {
            address: safe,
            chain_id: 1,
        };
        let (steps, data_hash, pin) = safe_message_steps(
            origin(identity, "Sign message"),
            safe,
            Chain::Mainnet,
            1,
            1,
            Vec::new(),
            WcSafeMessageSource::Personal(&call),
        );
        assert_eq!(data_hash, eip191_hash_message(&message));
        assert_eq!(
            pin,
            crate::cow::safe_sig::safe_message_hash(data_hash, safe, Chain::Mainnet)
        );
        match steps.get(1) {
            Some(SignStep::WcSafeMessage(m)) => match &m.inner {
                WcSafeMessageInner::Personal(p) => {
                    assert_eq!(p.raw, message);
                    assert_eq!(p.eip191_hash, data_hash);
                    assert!(!p.hardware, "no device shows the dapp's message here");
                }
                other => panic!("expected the personal inner, got {other:?}"),
            },
            other => panic!("expected the Safe message step, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn safe_message_signs_verifies_and_answers_the_owner_blob() {
        let data_hash = eip191_hash_message(b"Sign in to app.example");
        let blob = expected_blob(&[0x31, 0x32], data_hash).await;
        let mock = CallMock::new();
        plant_owner_set(
            &mock,
            addr(SAFE),
            &[local_addr(0x31), local_addr(0x32), addr(0x99)],
            2,
        );
        plant_handler(&mock, addr(SAFE), compat_handler());
        plant_is_valid_signature(
            &mock,
            addr(SAFE),
            data_hash,
            &blob,
            [0x16, 0x26, 0xba, 0x7e],
        );
        let (live, checks) = guard(usize::MAX);
        let got = sign_safe_message(
            &mock,
            &[local_desc(0x31), local_desc(0x32)],
            message_job(2, data_hash),
            &live,
            &wc_opts(),
        )
        .await
        .expect("signed and verified");
        assert_eq!(got, blob);
        assert_eq!(got.len(), 2 * 65, "threshold × 65 bytes, owner-sorted");
        assert_eq!(checks.load(Ordering::SeqCst), 2);
    }

    /// The Safe says no (a derivation bug, a stale owner set): the blob is never answered, and the
    /// refusal is stale — the Safe would say no again.
    #[tokio::test]
    async fn safe_message_answer_requires_onchain_verify() {
        let data_hash = eip191_hash_message(b"Sign in to app.example");
        let blob = expected_blob(&[0x31], data_hash).await;
        let mock = CallMock::new();
        plant_owner_set(&mock, addr(SAFE), &[local_addr(0x31)], 1);
        plant_handler(&mock, addr(SAFE), compat_handler());
        plant_is_valid_signature(
            &mock,
            addr(SAFE),
            data_hash,
            &blob,
            [0xff, 0xff, 0xff, 0xff],
        );
        let (live, checks) = guard(usize::MAX);
        let err = sign_safe_message(
            &mock,
            &[local_desc(0x31)],
            message_job(1, data_hash),
            &live,
            &wc_opts(),
        )
        .await
        .unwrap_err();
        assert!(err.text.contains("didn't accept"), "{}", err.text);
        assert!(!err.text.contains("order"), "no CoW wording: {}", err.text);
        assert!(err.stale, "{err:?}");
        assert_eq!(
            checks.load(Ordering::SeqCst),
            1,
            "refused before the answer's liveness check"
        );
        // An unanswered `isValidSignature` is no better than a "no".
        let silent = CallMock::new();
        plant_owner_set(&silent, addr(SAFE), &[local_addr(0x31)], 1);
        plant_handler(&silent, addr(SAFE), compat_handler());
        assert!(
            sign_safe_message(
                &silent,
                &[local_desc(0x31)],
                message_job(1, data_hash),
                &alive(),
                &wc_opts()
            )
            .await
            .is_err()
        );
    }

    /// Owners sign one at a time, the active account through its parked signer (back in the
    /// handoff afterwards); and once the user chose it after a refused EIP-712 prompt, each signs
    /// the Safe message hash as a personal message (`v` 31/32) — which the Safe accepts too.
    #[tokio::test]
    async fn safe_message_owners_sign_through_the_parked_signer_and_in_the_chosen_mode() {
        let data_hash = eip191_hash_message(b"Sign in to app.example");
        let message_hash =
            crate::cow::safe_sig::safe_message_hash(data_hash, addr(SAFE), Chain::Mainnet);
        for mode in [
            crate::safe::tx::OwnerSigMode::Eip712,
            crate::safe::tx::OwnerSigMode::EthSign,
        ] {
            let mut owners = vec![
                crate::cow::safe_sig::sign_eip1271_owner(
                    &local_signer(0x31),
                    data_hash,
                    addr(SAFE),
                    Chain::Mainnet,
                    mode,
                )
                .await
                .unwrap(),
                crate::cow::safe_sig::sign_eip1271_owner(
                    &local_signer(0x32),
                    data_hash,
                    addr(SAFE),
                    Chain::Mainnet,
                    mode,
                )
                .await
                .unwrap(),
            ];
            owners.sort_by_key(|(a, _)| *a);
            let blob = crate::safe::tx::assemble_signatures(owners).unwrap();
            let mock = CallMock::new();
            plant_owner_set(&mock, addr(SAFE), &[local_addr(0x31), local_addr(0x32)], 2);
            plant_handler(&mock, addr(SAFE), compat_handler());
            plant_is_valid_signature(
                &mock,
                addr(SAFE),
                data_hash,
                &blob,
                [0x16, 0x26, 0xba, 0x7e],
            );
            let handoff = handoff_with(local_signer(0x31));
            let opts = OwnerSignOpts {
                mode,
                parked: Some(handoff.clone()),
                ..OwnerSignOpts::default()
            };
            let got = sign_safe_message(
                &mock,
                // The active owner is a Ledger account: only its parked signer can sign for it here.
                &[ledger_desc(local_addr(0x31)), local_desc(0x32)],
                message_job(2, data_hash),
                &alive(),
                &opts,
            )
            .await
            .expect("signed and verified");
            assert_eq!(got, blob, "{mode:?}");
            let want_v = match mode {
                crate::safe::tx::OwnerSigMode::EthSign => [31u8, 32],
                _ => [27, 28],
            };
            assert!(
                got.chunks_exact(65).all(|c| want_v.contains(&c[64])),
                "{mode:?}"
            );
            assert_eq!(
                assert_owner_blob(&got, message_hash, &[local_addr(0x31), local_addr(0x32)]),
                Ok(())
            );
            assert_eq!(parked(&handoff), Some((local_addr(0x31), true)));
        }
    }

    /// Every device opening [`stand_in_device`] saw: (address, a Ledger owner, the parked handoff
    /// still held a live signer).
    type Openings = Vec<(Address, bool, bool)>;

    thread_local! {
        /// For [`stand_in_device`]: the parked handoff each opening is checked against, and every
        /// opening.
        static OPENED: std::cell::RefCell<(Option<SignerHandoff>, Openings)> = Default::default();
    }

    /// An owner's device, stood in for by the local key with the address its descriptor names
    /// (seeds 0x31..=0x3f), recording each opening in [`OPENED`].
    fn stand_in_device(
        desc: &AccountDescriptor,
    ) -> futures::future::BoxFuture<'_, Result<KaoSigner, String>> {
        let want = account_address(desc);
        let ledger = matches!(desc, AccountDescriptor::Ledger { .. });
        OPENED.with(|o| {
            let mut o = o.borrow_mut();
            let parked_live =
                o.0.as_ref()
                    .is_some_and(|h| h.lock().unwrap().as_ref().is_some_and(KaoSigner::can_sign));
            o.1.push((want.unwrap_or_default(), ledger, parked_live));
        });
        let signer = (0x31..=0x3f)
            .map(local_signer)
            .find(|s| Some(s.address()) == want);
        Box::pin(async move { signer.ok_or_else(|| "no device for this owner".to_string()) })
    }

    /// Ceremony options with `handoff` parked and owners' devices stood in for, recording into a
    /// fresh [`OPENED`].
    fn stand_in_opts(handoff: &SignerHandoff) -> OwnerSignOpts {
        OPENED.with(|o| *o.borrow_mut() = (Some(handoff.clone()), Vec::new()));
        OwnerSignOpts {
            parked: Some(handoff.clone()),
            connect: stand_in_device,
            ..wc_opts()
        }
    }

    /// Every device the ceremony opened, as recorded by [`stand_in_device`].
    fn opened() -> Openings {
        OPENED.with(|o| o.borrow().1.clone())
    }

    /// The active account is a Ledger owner, parked for the ceremony, and another owner is a
    /// Ledger too — possibly the same device. No Ledger is opened while the parked one still holds
    /// its connection (a second handle to one device locks it once either closes), and the active
    /// account has a live signer back in the handoff afterwards.
    #[tokio::test]
    async fn safe_message_never_opens_a_ledger_while_the_parked_one_is_held() {
        let data_hash = eip191_hash_message(b"Sign in to app.example");
        let mut sigs = Vec::new();
        for seed in [0x31, 0x32] {
            sigs.push(
                crate::cow::safe_sig::sign_eip1271_owner(
                    &local_signer(seed),
                    data_hash,
                    addr(SAFE),
                    Chain::Mainnet,
                    crate::safe::tx::OwnerSigMode::Eip712,
                )
                .await
                .unwrap(),
            );
        }
        sigs.sort_by_key(|(a, _)| *a);
        let blob = crate::safe::tx::assemble_signatures(sigs).unwrap();
        let mock = CallMock::new();
        plant_owner_set(&mock, addr(SAFE), &[local_addr(0x31), local_addr(0x32)], 2);
        plant_handler(&mock, addr(SAFE), compat_handler());
        plant_is_valid_signature(
            &mock,
            addr(SAFE),
            data_hash,
            &blob,
            [0x16, 0x26, 0xba, 0x7e],
        );
        for owners in [
            [ledger_desc(local_addr(0x31)), ledger_desc(local_addr(0x32))],
            [ledger_desc(local_addr(0x32)), ledger_desc(local_addr(0x31))],
        ] {
            let handoff = handoff_with(local_signer(0x31));
            let opts = stand_in_opts(&handoff);
            let got = sign_safe_message(&mock, &owners, message_job(2, data_hash), &alive(), &opts)
                .await
                .expect("signed and verified");
            assert_eq!(got, blob);
            let opened = opened();
            assert!(
                opened.iter().any(|&(a, ..)| a == local_addr(0x32)),
                "{opened:?}"
            );
            assert!(
                !opened.iter().any(|&(_, ledger, live)| ledger && live),
                "a Ledger was opened while the parked one was still held: {opened:?}"
            );
            assert_eq!(parked(&handoff), Some((local_addr(0x31), true)));
        }
    }

    /// The active account is a Ledger the dashboard holds open, parked for the ceremony though it
    /// isn't the owner that signs — a Ledger too, possibly on the same device. A proposal and a Safe
    /// message let go of it while that owner's device is open, and it is live in the handoff again
    /// afterwards.
    #[tokio::test]
    async fn a_parked_ledger_that_isnt_an_owner_is_let_go_while_a_ledger_owner_signs() {
        let parked_ledger = |handoff: &SignerHandoff| OwnerSignOpts {
            active: Some(ledger_desc(local_addr(0x31))),
            ..stand_in_opts(handoff)
        };
        let let_go_while_open = |opened: Openings| {
            assert!(
                opened.iter().any(|&(a, ..)| a == local_addr(0x32)),
                "{opened:?}"
            );
            assert!(
                !opened.iter().any(|&(_, ledger, live)| ledger && live),
                "a Ledger was opened while the parked one was still held: {opened:?}"
            );
        };

        let mut req = safe_call_req(addr(0xC1), 2);
        let (tx, hash) = pin_at(&mut req, 4);
        let (base, served) = one_shot_service().await;
        req.service_base = base;
        let mock = CallMock::new();
        plant_tx_agreement(&mock, addr(SAFE), &tx, hash);
        plant_nonce(&mock, addr(SAFE), 4);
        plant_owner_set(&mock, addr(SAFE), &[local_addr(0x32), addr(0x99)], 2);
        let handoff = handoff_with(local_signer(0x31));
        let owner = ledger_desc(local_addr(0x32));
        let out = propose_safe_tx(Arc::new(mock), owner, req, alive(), parked_ledger(&handoff))
            .await
            .expect("proposed");
        assert!(matches!(out, SignOutcome::SafeProposed(h) if h == hash));
        assert!(served.await.unwrap().is_some(), "the proposal was filed");
        let_go_while_open(opened());
        assert_eq!(parked(&handoff), Some((local_addr(0x31), true)));

        let data_hash = eip191_hash_message(b"Sign in to app.example");
        let (owner, sig) = crate::cow::safe_sig::sign_eip1271_owner(
            &local_signer(0x32),
            data_hash,
            addr(SAFE),
            Chain::Mainnet,
            crate::safe::tx::OwnerSigMode::Eip712,
        )
        .await
        .unwrap();
        let blob = crate::safe::tx::assemble_signatures(vec![(owner, sig)]).unwrap();
        let mock = CallMock::new();
        plant_owner_set(&mock, addr(SAFE), &[local_addr(0x32)], 1);
        plant_handler(&mock, addr(SAFE), compat_handler());
        plant_is_valid_signature(
            &mock,
            addr(SAFE),
            data_hash,
            &blob,
            [0x16, 0x26, 0xba, 0x7e],
        );
        let handoff = handoff_with(local_signer(0x31));
        let got = sign_safe_message(
            &mock,
            &[ledger_desc(local_addr(0x32))],
            message_job(1, data_hash),
            &alive(),
            &parked_ledger(&handoff),
        )
        .await
        .expect("signed and verified");
        assert_eq!(got, blob);
        let_go_while_open(opened());
        assert_eq!(parked(&handoff), Some((local_addr(0x31), true)));
    }

    /// The same for an execution: the owners and the executor (the parked account) never hold a
    /// Ledger while another is opened, and the active account is live in the handoff afterwards.
    #[tokio::test]
    async fn safe_exec_never_opens_a_ledger_while_the_parked_one_is_held() {
        let (url, mempool) = lossy_node(9, true).await;
        let mut req = safe_call_req(addr(0xC1), 2);
        let (tx, hash) = pin_at(&mut req, 4);
        let state = CallMock::new();
        plant_tx_agreement(&state, addr(SAFE), &tx, hash);
        plant_nonce(&state, addr(SAFE), 4);
        plant_owner_set(&state, addr(SAFE), &[local_addr(0x31), local_addr(0x32)], 2);
        let network: Arc<dyn BalanceFetcher> = Arc::new(RpcFetcher { state, url });
        let handoff = handoff_with(local_signer(0x31));
        let out = execute_safe_tx(
            network,
            req,
            vec![ledger_desc(local_addr(0x31)), ledger_desc(local_addr(0x32))],
            None,
            alive(),
            stand_in_opts(&handoff),
        )
        .await
        .expect("executed");
        let pool = mempool.lock().unwrap().clone();
        assert!(
            pool.len() == 1 && out.hash == keccak256(&pool[0]),
            "{out:?}"
        );
        let opened = opened();
        assert!(
            !opened.iter().any(|&(_, ledger, live)| ledger && live),
            "a Ledger was opened while the parked one was still held: {opened:?}"
        );
        assert_eq!(parked(&handoff), Some((local_addr(0x31), true)));
    }

    /// A Safe whose fallback handler can't validate EIP-1271 signatures is refused before any
    /// owner is prompted, and classed stale: every retry would walk the owners through their
    /// devices for a signature the Safe can never accept.
    #[tokio::test]
    async fn safe_message_refused_before_prompting_when_the_handler_cant_validate() {
        let data_hash = eip191_hash_message(b"Sign in to app.example");
        let mock = CallMock::new();
        plant_owner_set(&mock, addr(SAFE), &[local_addr(0x31)], 1);
        // isValidSignature unplanted: the handler answers nothing.
        let (live, checks) = guard(usize::MAX);
        let err = sign_safe_message(
            &mock,
            &[local_desc(0x31)],
            message_job(1, data_hash),
            &live,
            &wc_opts(),
        )
        .await
        .unwrap_err();
        assert!(err.stale, "classed retryable: {}", err.text);
        assert_eq!(
            checks.load(Ordering::SeqCst),
            0,
            "an owner was prompted: {}",
            err.text
        );
    }

    #[tokio::test]
    async fn safe_message_hash_pin_mismatch_refuses() {
        let data_hash = eip191_hash_message(b"what the dapp sent");
        let mut job = message_job(1, data_hash);
        job.pin = crate::cow::safe_sig::safe_message_hash(
            eip191_hash_message(b"what the review showed"),
            addr(SAFE),
            Chain::Mainnet,
        );
        let (live, checks) = guard(usize::MAX);
        let err = sign_safe_message(
            &CallMock::new(),
            &[local_desc(0x31)],
            job,
            &live,
            &wc_opts(),
        )
        .await
        .unwrap_err();
        assert!(err.stale, "{err:?}");
        assert!(err.text.contains("reviewed"), "{}", err.text);
        assert_eq!(checks.load(Ordering::SeqCst), 0);
    }

    /// The threshold or an owner changed since the review: refused before any owner is asked to
    /// sign (the liveness check that precedes the first prompt never runs), and classed stale.
    #[tokio::test]
    async fn owner_drift_aborts_before_signing() {
        let data_hash = eip191_hash_message(b"Sign in to app.example");
        // The threshold went 1 → 2.
        let raised = CallMock::new();
        plant_owner_set(&raised, addr(SAFE), &[local_addr(0x31)], 2);
        let (live, checks) = guard(usize::MAX);
        let err = sign_safe_message(
            &raised,
            &[local_desc(0x31)],
            message_job(1, data_hash),
            &live,
            &wc_opts(),
        )
        .await
        .unwrap_err();
        assert!(err.stale && err.text.contains("threshold"), "{err:?}");
        assert_eq!(checks.load(Ordering::SeqCst), 0, "no owner prompted");
        // The signing key was removed as an owner.
        let removed = CallMock::new();
        plant_owner_set(&removed, addr(SAFE), &[addr(0x99)], 1);
        let (live, checks) = guard(usize::MAX);
        let err = sign_safe_message(
            &removed,
            &[local_desc(0x31)],
            message_job(1, data_hash),
            &live,
            &wc_opts(),
        )
        .await
        .unwrap_err();
        assert!(
            err.stale && err.text.contains("no longer an owner"),
            "{err:?}"
        );
        assert_eq!(checks.load(Ordering::SeqCst), 0, "no owner prompted");
    }

    #[tokio::test]
    async fn safe_message_refuses_fewer_owners_than_threshold() {
        let data_hash = eip191_hash_message(b"Sign in to app.example");
        let err = sign_safe_message(
            &CallMock::new(),
            &[local_desc(0x31)],
            message_job(2, data_hash),
            &alive(),
            &wc_opts(),
        )
        .await
        .unwrap_err();
        assert!(err.stale && err.text.contains("needs 2"), "{err:?}");
    }

    /// The local wall over the assembled blob: each 65-byte signature must recover to the owner it
    /// is filed under — EIP-712 (`v` 27/28) or the `eth_sign` fallback (`v` 31/32).
    #[tokio::test]
    async fn owner_blob_must_recover_to_the_owners() {
        let safe = addr(SAFE);
        let data_hash = eip191_hash_message(b"Sign in to app.example");
        let message_hash = crate::cow::safe_sig::safe_message_hash(data_hash, safe, Chain::Mainnet);
        let blob = expected_blob(&[0x31, 0x32], data_hash).await;
        let owners = [local_addr(0x32), local_addr(0x31)];
        assert_eq!(assert_owner_blob(&blob, message_hash, &owners), Ok(()));
        assert!(assert_owner_blob(&blob, message_hash, &[local_addr(0x31), addr(0x99)]).is_err());
        assert!(assert_owner_blob(&blob, B256::repeat_byte(1), &owners).is_err());
        assert!(assert_owner_blob(&blob[..65], message_hash, &owners).is_err());

        // An eth_sign fallback signature: EIP-191 over the SafeMessage hash, v + 4.
        let sig = local_signer(0x31)
            .sign_eth_message(message_hash.as_slice())
            .await
            .unwrap();
        let mut eth_sign = sig.as_bytes().to_vec();
        eth_sign[64] += 4;
        assert_eq!(
            assert_owner_blob(&eth_sign, message_hash, &[local_addr(0x31)]),
            Ok(())
        );
        eth_sign[64] = 0;
        assert!(assert_owner_blob(&eth_sign, message_hash, &[local_addr(0x31)]).is_err());
    }
}
