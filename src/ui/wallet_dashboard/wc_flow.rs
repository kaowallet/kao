//! WalletConnect coordinator — the dashboard half. Admits requests (validation needs the wallet's
//! descriptors), opens one review at a time through `pump_wc_queue` (the only opener), signs through
//! `dispatch_wc`, and answers through `WcRuntime::answer` (the book's exactly-once choke point).
//! Sessions are bound to their approval-time identity; a request is reviewed only while that identity
//! is the active one (`wc_signer_context`, the from == signer gate).
//!
//! Nothing here sends anything to a dapp or the relay by itself: every answer, rejection and
//! disconnect is a call into the App-owned runtime, which spawns the network effect on its own
//! tokio handle. So an answer survives the dashboard being rebuilt under it, and the only
//! iced `Task`s this module returns are review prepares, signing tasks, the runtime start, window
//! attention, toasts, and the balance / Safe-queue refreshes after a dapp transaction was sent.

use super::sign_review::{
    OwnerEthSign, SignAction, SignReview, SignStep, SigningKind, SigningOwner, WcOriginCard,
    WcSafeMessageInner, WcSignPlan,
};
use super::tx_details::short_hash;
use super::*;
use crate::trace::SecretInput;
use crate::wallet::account_address;
use crate::wallet::tx::{SendToken, TxQuote};
use crate::walletconnect::{
    self as wc,
    runtime::{WcRuntime, WcSlot},
};

/// The deferred-host toast: a request for the active identity that can't open over a modal
/// or a settings pane the user is in the middle of.
const DEFERRED_TOAST: &str = "A dapp is waiting for your signature — it opens when you close this.";
/// The same, while a Privacy Pools proof is running: there is nothing to close, only to wait for.
const PROOF_DEFERRED_TOAST: &str =
    "A dapp is waiting for your signature — it opens when the Privacy Pools proof finishes.";
/// Confirm while another signature is in flight. Confirm stays live: the user retries once it ends.
const BUSY_TEXT: &str = "another signing operation is in progress — try again in a moment";
/// Approve refused because what the card displayed no longer holds.
const CHANGED_TEXT: &str = "Your active account or networks changed — check the request again.";
/// A request that died between review and signature.
const GONE_TEXT: &str = "The dapp stopped waiting — nothing was sent.";
/// The refusal detail when a session's identity left the wallet, whichever step notices it.
const IDENTITY_GONE_DETAIL: &str = "the account this dapp is connected as is no longer in Kao";
/// An EOA quote re-taken in place because it aged out or its nonce moved.
const REQUOTE_NOTE: &str = "Fees refreshed — check again.";
/// A link that reaches Connect while a relay start is still in flight.
const STILL_STARTING: &str =
    "Kao is still connecting to the relay — paste the link again in a moment.";
/// Confirm on a review whose transaction already left the wallet without an acknowledgement.
const RESEND_LABEL: &str = "Re-send the same transaction";
/// The secondary action on a dapp transaction whose prepare failed: run it again, in place.
const RECHECK_LABEL: &str = "Re-check";
/// The note on a review prepared again from "Re-check".
const RECHECK_NOTE: &str = "Prepared again — check it before you sign.";
/// Why a dapp's Safe transaction isn't proposed while Kao couldn't read the Safe's queue: the
/// nonce a proposal would pin may already be a co-signer's.
const QUEUE_UNREAD_TEXT: &str = "Kao couldn't read this Safe's pending queue, so it can't propose \
     this safely — cancel, refresh the Safe's queue, and ask the dapp again.";
/// [Review] on a dapp Safe transaction that waits for Kao's unmined execution of an earlier one.
const HELD_NOTICE: &str = "This transaction waits until Kao's previous execution for this Safe \
     is mined or given up on — or use Review anyway.";
/// What a Safe `eth_sendTransaction` answers the dapp with, either way it goes: executing answers
/// the executor's on-chain hash (which a dapp that isn't Safe-aware can wait on), proposing
/// answers the safeTxHash (which only resolves through the Transaction Service).
const SAFE_EXECUTE_NOTE: &str = "If executed now, the dapp receives the on-chain hash of the \
     transaction that executes it; a Safe-aware dapp expecting a Safe transaction hash may keep \
     showing \"pending\".";
const SAFE_PROPOSE_NOTE: &str = "If proposed, the dapp receives the Safe transaction hash \
     (safeTxHash), not an on-chain hash; it may show \"pending\" until co-signers execute.";
/// In place of [`SAFE_PROPOSE_NOTE`] on a review that can execute but not propose: the Safe's
/// queue couldn't be read ([`QUEUE_UNREAD_TEXT`]).
const PROPOSE_WITHHELD_NOTE: &str = "Proposing isn't offered: Kao couldn't read this Safe's \
     pending queue — to propose instead, cancel, refresh the Safe's queue, and ask the dapp again.";
/// Local names are the user's own, but they reach a dapp-facing card; clamp them like dapp names.
const IDENTITY_LABEL_CHARS: usize = wc::MAX_DAPP_NAME_CHARS;

#[derive(Clone)]
pub enum WcMsg {
    Stream {
        generation: u64,
        item: wc::WcStreamItem,
    },
    /// The start task installed the runtime (Ok(generation)) or failed (user-facing text).
    Started { result: Result<u64, String> },
}

impl std::fmt::Debug for WcMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stream { generation, item } => {
                write!(f, "Stream {{ gen: {generation}, item: {item:?} }}")
            }
            Self::Started { result } => write!(f, "Started {{ ok: {} }}", result.is_ok()),
        }
    }
}

/// The dashboard's own WalletConnect bookkeeping. Deliberately thin: sessions, the queue, the
/// proposal card and every answer live in the runtime's book and survive a rebuild of this
/// screen; what's here is only what a single dashboard needs to drive its overlay and pane.
#[derive(Debug, Default)]
pub struct WcDashState {
    /// The App-owned slot, handed over by `set_wc_slot` after every (re)build. `None` before that.
    slot: Option<WcSlot>,
    /// The request the user asked to review from the pane ([Review]): eligible regardless of age
    /// or pause, but still only on a Free host and only for the active identity.
    manual: Option<wc::WcKey>,
    /// When the window last asked for the user's attention (≥ `ATTENTION_MIN_INTERVAL` apart).
    last_attention: Option<Instant>,
    /// The open review's request died (`RequestGone`, or a Gone sign failure): Cancel closes the
    /// overlay without answering, because there is no one left to answer.
    gone: Option<wc::WcKey>,
    /// The proposal card already announced with a toast, so it is announced once.
    announced_proposal: Option<u64>,
    /// The book's coarse shape at the last mirror, diffed into `kao::gui` state traces.
    traced: Option<TraceShape>,
    /// (`gone`, `manual`) presence after the last update, for [`WalletScreen::wc_trace_latches`].
    traced_latches: (bool, bool),
}

/// What `wc_mirror` traces: `trace::state("wc", "relay"|"sessions"|"queue"|"proposal", ..)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TraceShape {
    relay: &'static str,
    sessions: usize,
    queue: usize,
    proposal: bool,
}

impl TraceShape {
    const OFF: Self = Self {
        relay: "off",
        sessions: 0,
        queue: 0,
        proposal: false,
    };

    fn of(snap: Option<&wc::WcSnapshot>) -> Self {
        let Some(s) = snap else {
            return Self::OFF;
        };
        Self {
            relay: match s.relay {
                wc::RelayStatus::Connecting => "connecting",
                wc::RelayStatus::Connected => "connected",
                wc::RelayStatus::Reconnecting { .. } => "reconnecting",
                wc::RelayStatus::Closed => "closed",
            },
            sessions: s.sessions.len(),
            queue: s.queue.len(),
            proposal: s.proposal.is_some(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WcHost {
    Free,
    Deferred,
    Busy,
}

/// The only signing context a WC review/dispatch may use. No key material.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // short-lived, one per open/dispatch
enum WcSignerCtx {
    Eoa {
        address: Address,
        desc: AccountDescriptor,
        kind: wc::EoaKind,
    },
    Safe {
        descriptor: crate::wallet::SafeDescriptor,
        chain: Chain,
        signable_indices: Vec<u32>,
    },
}

/// What a confirmed review runs, decided — and every refusal raised — before the request is
/// claimed for signing, so a refusal leaves it InReview with the overlay intact.
enum Ceremony {
    Personal {
        desc: AccountDescriptor,
        from: Address,
        message: Bytes,
        pin: B256,
        owner: SigningOwner,
    },
    Typed {
        desc: AccountDescriptor,
        from: Address,
        typed: Arc<alloy::dyn_abi::TypedData>,
        pin: crate::sign::digest::Eip712Digests,
        owner: SigningOwner,
        hash_mode: bool,
    },
    EoaTx {
        desc: AccountDescriptor,
        plan: crate::wallet::tx::SendPlan,
        quote: TxQuote,
    },
    /// The transaction already signed for this request, sent again byte for byte.
    EoaResend {
        chain: crate::chain::NetworkId,
        tx: wc::UnconfirmedTx,
    },
    /// The executor's transaction already signed for this Safe request, sent again byte for byte.
    /// `pin`: the Safe nonce it executes at, when this review pinned one.
    SafeResend {
        safe: Address,
        chain: Chain,
        tx: wc::UnconfirmedTx,
        pin: Option<wc_sign::SafeExecInFlight>,
    },
    SafeExecute {
        sreq: tx_builder::SafeBatchRequest,
        signer_owners: Vec<AccountDescriptor>,
        executor_key: Option<B256>,
        kind: SigningKind,
    },
    SafePropose {
        sreq: tx_builder::SafeBatchRequest,
        owner_desc: AccountDescriptor,
        kind: SigningKind,
    },
    SafeMessage {
        owners: Vec<AccountDescriptor>,
        signers: Vec<SigningOwner>,
        safe: Address,
        chain: Chain,
        threshold: u32,
        data_hash: B256,
        pin: B256,
    },
}

/// What `dispatch_wc`'s checks hand to the ceremony: the request, its pinned plan and the signer
/// context, all re-validated at Confirm.
struct DispatchReady {
    rt: WcRuntime,
    key: wc::WcKey,
    plan: WcSignPlan,
    ctx: WcSignerCtx,
    seq: u64,
    /// The account the review named as a Safe execution's sender.
    shown_executor: Option<Address>,
    /// Owners sign EIP-712, or the hash as a message after a device refused the EIP-712 prompt.
    mode: crate::safe::tx::OwnerSigMode,
}

/// zero-sized fn item for `Subscription::map`.
fn wc_stream_msg(item: (u64, wc::WcStreamItem)) -> Message {
    Message::Wc(WcMsg::Stream {
        generation: item.0,
        item: item.1,
    })
}

/// App's off-screen path: a `Message::Signed { tag: WalletConnect, .. }` that landed while the screen
/// isn't the wallet. Ok → `rt.answer(Result)`; Err → Gone → Abandon (with an Activity line if a
/// transaction may be on its way); a transaction sent but unacknowledged → requeued, unanswered;
/// else −32603. Every other message is ignored. The parked signer (if any) is dropped.
pub fn handle_orphan_message(msg: Message, slot: &WcSlot) {
    let Message::Signed {
        tag: SignTag::WalletConnect { key, kind },
        signer,
        result,
    } = msg
    else {
        return;
    };
    // No dashboard to put it back into; the next one is built from the descriptors, exactly as
    // for every other flow whose result lands off-screen.
    drop(signer);
    let Some(rt) = slot.get() else {
        debug!(
            ?kind,
            "wc: off-screen signing result with no runtime — nothing to answer"
        );
        return;
    };
    let Some(answer) = answer_without_overlay(&rt, &key, kind, result) else {
        return;
    };
    for effect in rt.answer(&key, answer) {
        // The pane re-mirrors from the book when a dashboard returns; a toast has nowhere to go.
        debug!(effect = effect.name(), "wc: off-screen UI effect not shown");
    }
}

/// Tx/SafeProposed → "0x<hash>"; Signature → "0x<bytes>"; mismatched kind/outcome → Err.
fn answer_value(kind: WcSignKind, outcome: &SignOutcome) -> Result<serde_json::Value, String> {
    use WcSignKind as K;
    let hex = wc::request::hex_value;
    match (kind, outcome) {
        // Execute: the executor's `execTransaction` hash — real and minable, so a dapp that
        // isn't Safe-aware can still wait for its receipt. Propose: the safeTxHash (the
        // Safe{Wallet} convention), which Safe-aware dapps resolve via the Transaction Service.
        (K::EoaTx | K::SafeExecute, SignOutcome::Tx(hash)) => Ok(hex(hash.as_slice())),
        (K::SafePropose, SignOutcome::SafeProposed(hash)) => Ok(hex(hash.as_slice())),
        // An EOA signature is exactly r‖s‖v; a Safe's EIP-1271 blob is one 65-byte owner
        // signature per signer. Anything else is a wiring bug, never something to send.
        (K::Personal | K::Typed, SignOutcome::Signature(sig)) if sig.len() == 65 => Ok(hex(sig)),
        (K::SafeMessage, SignOutcome::Signature(blob))
            if !blob.is_empty() && blob.len() % 65 == 0 =>
        {
            Ok(hex(blob))
        }
        _ => Err(format!(
            "internal: the {kind:?} signing task produced a result of the wrong shape"
        )),
    }
}

/// What to answer when no overlay remains to retry in: the result, `−32603` (a failure nobody
/// can retry), or `Abandon` when the dapp already stopped waiting.
///
/// `None`: nothing is answered yet. A transaction signed for the request left the wallet without
/// an acknowledgement — it may be on its way — and answering "failed" would invite the dapp to ask
/// again, for a second transaction. The request goes back to the queue instead (an Activity line
/// says why); its next review offers only re-sending the same signed bytes.
fn answer_without_overlay(
    rt: &WcRuntime,
    key: &wc::WcKey,
    kind: WcSignKind,
    result: Result<SignOutcome, String>,
) -> Option<wc::Answer> {
    let e = match result {
        Ok(outcome) => {
            return Some(match answer_value(kind, &outcome) {
                Ok(value) => wc::Answer::Result(value),
                Err(e) => {
                    error!(error = %e, "wc: signing result doesn't match its request");
                    wc::Answer::Refuse(wc::Refusal::failed(e))
                }
            });
        }
        Err(e) => e,
    };
    let class = rt.failure_class(key);
    let unconfirmed = rt.with_book(|b| b.unconfirmed(key));
    match (class, unconfirmed) {
        (wc::FailureClass::Gone, Some(tx)) => {
            record_notice(rt, &unconfirmed_gone_text(&tx), true);
            Some(wc::Answer::Abandon)
        }
        (wc::FailureClass::Gone, None) => Some(wc::Answer::Abandon),
        (_, Some(tx)) => {
            rt.with_book(|b| b.back_to_review(key) && b.release(key));
            warn!(
                hash = %format!("{:#x}", tx.hash),
                "wc: an unacknowledged transaction's request goes back to the queue"
            );
            record_notice(
                rt,
                &format!(
                    "Transaction {:#x} for a dapp may already be on its way — Kao couldn't \
                     confirm the network received it. Review the request again to re-send the \
                     same transaction.",
                    tx.hash
                ),
                true,
            );
            None
        }
        (_, None) => Some(wc::Answer::Refuse(wc::Refusal::failed(e))),
    }
}

/// What a review latched onto an unacknowledged transaction says: what happened, why "Re-send"
/// is safe, and what Cancel means for it.
fn unconfirmed_review_text(tx: &wc::UnconfirmedTx, why: Option<&str>) -> String {
    let why = why.map(|w| format!(" ({w})")).unwrap_or_default();
    format!(
        "Kao sent transaction {:#x} (nonce {}) to the network, but couldn't confirm the network \
         received it{why} — it may already be on its way. \"{RESEND_LABEL}\" hands the network \
         the exact transaction you signed again; it can't run twice, and nothing new is signed. \
         If you cancel, the dapp is told the request failed, but this transaction may still be \
         mined — look its hash up before asking the dapp again.",
        tx.hash, tx.nonce
    )
}

/// [`unconfirmed_review_text`] for a Safe transaction, whose sent transaction is the executor's
/// `execTransaction`: re-sending can't execute it twice, and no owner signs anything again. If the
/// user gives up, the Safe may still execute it — asking the dapp again could run the call twice.
fn unconfirmed_safe_review_text(tx: &wc::UnconfirmedTx, why: Option<&str>) -> String {
    let why = why.map(|w| format!(" ({w})")).unwrap_or_default();
    format!(
        "Kao sent transaction {:#x} (the executor's nonce {}), which executes this Safe \
         transaction, but couldn't confirm the network received it{why} — it may already be on \
         its way. \"{RESEND_LABEL}\" hands the network that exact transaction again; it can't \
         execute twice, and no owner signs anything new. If you cancel, the dapp is told the \
         request failed, but the Safe may still execute it — look its hash up before asking the \
         dapp again, or the call may run twice.",
        tx.hash, tx.nonce
    )
}

/// A request whose transaction may be on its way ended — the dapp stopped waiting, or Kao let it
/// go: "nothing was sent" would be false.
fn unconfirmed_gone_text(tx: &wc::UnconfirmedTx) -> String {
    format!(
        "This request is over, but transaction {:#x} may still be on its way — Kao couldn't \
         confirm the network received it, so look its hash up before trying again.",
        tx.hash
    )
}

/// The Activity line when a review latches onto a transaction that may be on its way: the hash
/// outlives the overlay, whatever becomes of the request.
fn unconfirmed_latched_text(tx: &wc::UnconfirmedTx) -> String {
    format!(
        "Transaction {:#x} for a dapp may already be on its way — Kao couldn't confirm the \
         network received it. Look its hash up before asking the dapp again.",
        tx.hash
    )
}

/// The Activity line when the user gives up on a request whose transaction may be on its way.
fn unconfirmed_cancelled_text(tx: &wc::UnconfirmedTx) -> String {
    format!(
        "Transaction {:#x} may still be on its way — Kao couldn't confirm the network received \
         it, and told the dapp the request failed. Look its hash up before asking the dapp again.",
        tx.hash
    )
}

/// The refusal a request whose transaction may be on its way gets when the user gives up on it.
/// Not "rejected": the user approved it, and it may yet be mined.
fn unconfirmed_refusal(tx: &wc::UnconfirmedTx) -> wc::Refusal {
    wc::Refusal::unconfirmed(tx.hash)
}

/// Task::perform([`start_and_pair`]) → WcMsg::Started.
fn spawn_start(
    slot: WcSlot,
    cfg: wc::runtime::WcConfig,
    uri: zeroize::Zeroizing<String>,
) -> Task<Message> {
    Task::perform(start_and_pair(slot, cfg, uri), |result| {
        Message::Wc(WcMsg::Started { result })
    })
}

/// start(cfg) → slot.install (Err ⇒ mark_closed + teardown) → rt.pair(uri, now): the started
/// runtime's generation, or what the user is shown.
async fn start_and_pair(
    slot: WcSlot,
    cfg: wc::runtime::WcConfig,
    uri: zeroize::Zeroizing<String>,
) -> Result<u64, String> {
    let generation = cfg.generation;
    let rt = match WcRuntime::start(cfg).await {
        Ok(rt) => rt,
        Err(e) => {
            slot.start_failed();
            // Already the user's sentence ("Couldn't reach the relay: …").
            return Err(e);
        }
    };
    // The task installs the runtime itself, so a `Started` message lost to a rebuild or a screen
    // change loses nothing. A slot a lock closed meanwhile refuses it, and the socket must not
    // outlive that refusal.
    if let Err(refused) = slot.install(rt.clone()) {
        slot.start_failed();
        drop(rt);
        refused.mark_closed();
        refused.teardown(wc::TEARDOWN_PER_PHASE).await;
        return Err("WalletConnect was closed while it was connecting.".to_string());
    }
    rt.pair(uri, wc::now_secs())
        .map(|()| generation)
        .map_err(str::to_string)
}

/// Re-deliver a toast to the next update as a synthetic stream item of `generation`, for the
/// paths that return only a `Task` (pump, completion, cancel): `wc_apply_ui` bubbles it then.
/// The line itself must already be in the Activity list; the toast doesn't record it.
fn toast_task(generation: u64, text: String) -> Task<Message> {
    Task::done(Message::Wc(WcMsg::Stream {
        generation,
        item: wc::WcStreamItem::Ui(wc::UiEffect::Notice { text }),
    }))
}

/// Record one of the coordinator's own activity lines in the book (what the pane's Activity list
/// mirrors). Never a line the book raised: the book records its own notices.
fn record_notice(rt: &WcRuntime, text: &str, error: bool) {
    let now = wc::now_secs();
    rt.with_book(|b| b.push_notice(text.to_string(), error, now));
}

/// The badge the review and pane show for an identity.
fn identity_badge(caps: &wc::IdentityCaps) -> &'static str {
    match &caps.kind {
        wc::IdentityKind::Eoa(e) => match e.kind {
            wc::EoaKind::Local => "Local",
            wc::EoaKind::Ledger => "Ledger",
            wc::EoaKind::Trezor => "Trezor",
        },
        wc::IdentityKind::Safe(_) => "Safe",
    }
}

/// The signer kind behind an account, `None` for one that can't sign (view-only).
fn eoa_kind(desc: &AccountDescriptor) -> Option<wc::EoaKind> {
    match desc {
        AccountDescriptor::Local { .. } => Some(wc::EoaKind::Local),
        AccountDescriptor::Ledger { .. } => Some(wc::EoaKind::Ledger),
        AccountDescriptor::Trezor { .. } => Some(wc::EoaKind::Trezor),
        AccountDescriptor::ViewOnly { .. } => None,
    }
}

fn identity_label(name: &str) -> String {
    crate::sanitize::sanitize_display(name, IDENTITY_LABEL_CHARS).into_owned()
}

/// "The dapp's suggested nonce 7, max fee 31.5 gwei were ignored; Kao set its own.", if any.
fn ignored_note(ignored: &wc::IgnoredTxFields) -> Option<String> {
    let parts = ignored.describe();
    (!parts.is_empty()).then(|| {
        format!(
            "The dapp's suggested {} {} ignored; Kao set its own.",
            parts.join(", "),
            if parts.len() == 1 { "was" } else { "were" }
        )
    })
}

fn join_notes(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) => Some(format!("{a} {b}")),
        (a, b) => a.or(b),
    }
}

/// How a WalletConnect economics card's "≈ fee" line is wrong, for a dapp call that `sim` dry-ran:
/// the OP stack's L1 data fee always; for a Safe, also the tip and the `execTransaction` wrapper
/// its executor pays (the Transaction Builder's Safe caveats). None when the run left no fee
/// figure — they qualify that line, and the card would otherwise appear just to hold them.
fn wc_fee_caveats(
    sim: &crate::txbuilder::sim::BatchSimResult,
    net: crate::chain::NetworkId,
    safe: bool,
) -> Vec<String> {
    if super::sim_view::format_gas_fee_eth(sim.gas_used, sim.base_fee_per_gas).is_none() {
        return Vec::new();
    }
    let mut out = Vec::new();
    if safe {
        out.push("excludes the priority tip, which every transaction also pays".to_string());
        out.push(
            "excludes the execTransaction wrapper and its per-owner signature checks".to_string(),
        );
    }
    out.extend(tx_builder::l1_data_fee_caveat(net).map(str::to_string));
    out
}

/// [`WalletScreen::wc_on_prepared`] for a dapp transaction from an EOA: pin the quote the steps
/// priced (reviewed == signed), or — for a transaction already sent — check the steps describe it;
/// then the Confirm label and gate, the economics, and arm.
fn prepared_eoa_tx(review: &mut SignReview, portfolio: &[LiveToken]) {
    let SignAction::WalletConnect {
        plan:
            WcSignPlan::EoaTx {
                plan: send_plan,
                quote,
                quoted_at,
                unconfirmed,
                ..
            },
        ..
    } = &mut review.action
    else {
        return;
    };
    let fees = review.steps.iter().find_map(|s| match s {
        SignStep::WcTxFees(f) => Some(f.clone()),
        _ => None,
    });
    let Some(fees) = fees.filter(|f| f.quote.matches_plan(send_plan)) else {
        // A prepare that didn't price exactly this call must not be signable.
        error!("wc: prepared transaction steps carry no matching quote");
        review.error = Some(
            "Kao couldn't price this transaction — cancel and ask the dapp again.".to_string(),
        );
        review.confirm_disabled = true;
        return;
    };
    // A review of a transaction that already left must describe that very one.
    if let Some(tx) = unconfirmed
        .as_ref()
        .filter(|tx| tx.nonce != fees.quote.nonce)
    {
        error!("wc: prepared steps don't describe the transaction already sent");
        review.error = Some(format!(
            "Kao couldn't show transaction {:#x}, already sent for this request — \
             look its hash up before doing anything else.",
            tx.hash
        ));
        review.confirm_disabled = true;
        return;
    }
    // Reviewed == signed: the send task signs exactly this quote.
    *quote = Some(fees.quote.clone());
    *quoted_at = Some(Instant::now());
    let net = send_plan.chain;
    let from = send_plan.from;
    let (to, value, data) = send_plan.tx_target();
    if let Some(tx) = unconfirmed.as_ref() {
        // A transaction that already left: the steps describe its own bytes, and
        // Confirm only sends those again — nothing here is signed, so no balance or
        // simulation verdict gates it.
        review.confirm_label = Some(RESEND_LABEL.to_string());
        review.error = Some(unconfirmed_review_text(tx, None));
    } else if fees.balance_wei.is_some_and(|b| b < fees.max_total_wei) {
        review.confirm_label = Some("Not enough ETH for gas".to_string());
        review.confirm_disabled = true;
    } else if fees.sim_reverted
        || fees.estimate_failed.is_some()
        || (fees.unverified_network && !data.is_empty())
    {
        // A reverting preflight, a node that couldn't estimate the call (the quote
        // took the dapp's gas), or calldata Kao can neither decode nor simulate on an
        // unverified network.
        review.confirm_label = Some("Sign anyway ⚠".to_string());
    } else {
        review.confirm_label = Some("Sign & send".to_string());
    }
    if net.builtin().is_some() {
        let call = crate::txbuilder::QueuedCall {
            id: 0,
            to,
            value,
            data,
            title: "Dapp call".to_string(),
            detail: String::new(),
            signature: None,
            decoded_args: Vec::new(),
        };
        let sim = crate::txbuilder::sim::BatchSimResult::from_single(&fees.quote.sim);
        review.economics = Some(build_batch_economics(
            &[call],
            Some(&sim),
            false,
            from,
            net,
            portfolio,
            wc_fee_caveats(&sim, net, false),
        ));
    }
    review.armed_at = Some(Instant::now());
}

/// [`WalletScreen::wc_on_prepared`] for a Safe transaction reopened on an execution that already
/// left: the steps must describe that very transaction, and Confirm only sends it again.
fn prepared_safe_resend(review: &mut SignReview) {
    let SignAction::WalletConnect {
        plan:
            WcSignPlan::SafeTx {
                req,
                unconfirmed: Some(tx),
                ..
            },
        ..
    } = &mut review.action
    else {
        return;
    };
    // Reopened on an execution that already left: the steps must describe that very
    // transaction (the executor's call into this Safe, at its own nonce), and Confirm
    // only sends it again — nothing here is signed, so no verdict gates it.
    let describes = review.steps.iter().any(|s| {
        matches!(s, SignStep::WcTxFees(f)
            if f.quote.nonce == tx.nonce && f.quote.plan.recipient == req.safe)
    });
    if !describes {
        error!("wc: prepared steps don't describe the execution already sent");
        review.error = Some(format!(
            "Kao couldn't show transaction {:#x}, already sent for this request — \
             look its hash up before doing anything else.",
            tx.hash
        ));
        review.confirm_disabled = true;
        return;
    }
    review.confirm_label = Some(RESEND_LABEL.to_string());
    review.secondary_label = None;
    review.error = Some(unconfirmed_safe_review_text(tx, None));
    review.armed_at = Some(Instant::now());
}

/// [`WalletScreen::wc_on_prepared`] for a dapp's Safe transaction: pin (nonce, safeTxHash) from the
/// prepared `SafeExec` step, decide execute vs propose, the labels, the economics, and arm. A nonce
/// an execution Kao sent may still take ([`wc::book::SafeExecHolds::unmined_at`]) is named.
fn prepared_safe_tx(
    review: &mut SignReview,
    portfolio: &[LiveToken],
    holds: Option<&wc::book::SafeExecHolds>,
) {
    let SignAction::WalletConnect {
        plan:
            WcSignPlan::SafeTx {
                req,
                can_execute,
                unconfirmed: None,
            },
        ..
    } = &mut review.action
    else {
        return;
    };
    let exec = review.steps.iter().find_map(|s| match s {
        SignStep::SafeExec(x) => Some((
            x.safe,
            x.nonce,
            x.safe_tx_hash,
            x.queued_ahead(),
            x.operation,
            x.inner.self_admin.is_some(),
            x.preflight.clone(),
        )),
        _ => None,
    });
    let Some((safe, nonce, hash, queued_ahead, operation, self_admin, preflight)) =
        exec.filter(|&(safe, _, _, _, operation, _, _)| safe == req.safe && operation == 0)
    else {
        // A dapp's call is only ever an `Operation::Call` from this Safe.
        error!("wc: prepared Safe steps don't match the request");
        review.error = Some(
            "Kao couldn't prepare this Safe transaction — cancel and ask the dapp \
             again."
                .to_string(),
        );
        review.confirm_disabled = true;
        return;
    };
    debug!(%safe, operation, "wc: Safe transaction pinned");
    req.prepared = Some((nonce, hash));
    let identity = wc::WcIdentity::Safe {
        address: req.safe,
        chain_id: req.chain.chain_id(),
    };
    if let Some(unmined) = holds.and_then(|h| h.unmined_at(&identity, nonce)) {
        warn!(
            nonce,
            "wc: Safe transaction pinned at a nonce Kao's unmined execution may take"
        );
        review.error = join_notes(
            review.error.take(),
            Some(unmined_execution_caution(unmined, nonce)),
        );
    }
    // A dapp asking a Safe to reconfigure itself, or to act as an owner of another
    // Safe, or a call Kao's dry run saw revert, reads as a deliberate override.
    let sim_reverted = preflight.as_ref().is_some_and(|p| p.is_revert());
    // Behind queued proposals the Safe accepts only its current nonce, so this is
    // not executable now however many owner keys are linked. Nor is a call the dry
    // run saw revert: the execute path re-runs that dry run and refuses it, so an
    // execute button could only fail — proposing it is the one action that can run.
    *can_execute =
        queued_ahead == 0 && req.signable_indices.len() >= req.threshold as usize && !sim_reverted;
    let (confirm, secondary, disabled) = safe_exec_labels(
        *can_execute,
        req.signable_indices.is_empty(),
        self_admin || sim_reverted,
    );
    review.confirm_label = Some(confirm);
    review.secondary_label = secondary;
    if disabled {
        review.confirm_disabled = true;
    }
    // What the call moves, from a dry run that went through (the Safe is the account
    // it moves from). A reverted run is the banner on the step; one that couldn't run
    // says nothing.
    if let Some(sim) = preflight.as_ref().filter(|p| p.is_success())
        && let Ok(calls) = safe_batch_inner_calls(req)
    {
        let net = crate::chain::NetworkId::Builtin(req.chain);
        review.economics = Some(build_batch_economics(
            &calls,
            Some(sim),
            false,
            req.safe,
            net,
            portfolio,
            wc_fee_caveats(sim, net, true),
        ));
    }
    withhold_blind_propose(review);
    review.armed_at = Some(Instant::now());
}

/// [`WalletScreen::wc_on_prepared`] for typed data that confirms a `SafeTx`: attach the prepared
/// call to the panel it explains, then arm.
fn prepared_typed(review: &mut SignReview) {
    if let Err(why) = attach_safe_tx_call(&mut review.steps) {
        error!(
            why,
            "wc: the decoded SafeTx call doesn't match the typed data"
        );
        review.error = Some(
            "Kao couldn't show the Safe transaction this confirms — cancel and ask the \
             dapp again."
                .to_string(),
        );
        review.confirm_disabled = true;
        return;
    }
    review.armed_at = Some(Instant::now());
}

/// Move a prepared `SafeTx` call (`wc_sign::prepare_safe_tx_call`, appended as the last step) into
/// the typed review it explains — on its own it would read as a transaction this review signs.
/// Reviewed == signed: it must be exactly the `to` / `value` / `data` of the typed data being
/// signed, or nothing is attached and the review can't be confirmed.
fn attach_safe_tx_call(steps: &mut Vec<SignStep>) -> Result<(), &'static str> {
    let Some(SignStep::RawTx(leg)) = steps.pop() else {
        return Err("the prepare landed no decoded call");
    };
    let typed = steps.iter_mut().find_map(|s| match s {
        SignStep::WcTyped(r) => Some(r),
        SignStep::WcSafeMessage(m) => match &mut m.inner {
            WcSafeMessageInner::Typed(r) => Some(r),
            WcSafeMessageInner::Personal(_) => None,
        },
        _ => None,
    });
    let Some(r) = typed else {
        return Err("no typed data to attach the call to");
    };
    match &r.checked.kind {
        wc::TypedKind::SafeTx {
            to, value, data, ..
        } if *to == leg.to && *value == leg.value && *data == leg.calldata => {
            r.inner_leg = Some(Box::new(leg));
            Ok(())
        }
        _ => Err("the decoded call isn't the SafeTx's"),
    }
}

/// How a WalletConnect Safe ceremony's owners sign: EIP-712 with no automatic `eth_sign` after a
/// device refused the prompt — unless the user is confirming the review that offered exactly that.
fn wc_owner_sig_mode(review: &SignReview) -> crate::safe::tx::OwnerSigMode {
    if review.owner_eth_sign.is_some() {
        crate::safe::tx::OwnerSigMode::EthSign
    } else {
        crate::safe::tx::OwnerSigMode::Eip712
    }
}

/// Confirm / secondary labels once an owner's refused EIP-712 prompt turned the review into an
/// `eth_sign` one: the same actions, each saying how it now signs.
fn eth_sign_labels(action: &SignAction) -> (String, Option<String>) {
    const EXECUTE: &str = "Execute — sign as a message ⚠";
    const PROPOSE: &str = "Propose — sign as a message ⚠";
    match action {
        SignAction::WalletConnect {
            plan: WcSignPlan::SafeTx {
                can_execute: true, ..
            },
            ..
        } => (EXECUTE.to_string(), Some(PROPOSE.to_string())),
        SignAction::WalletConnect {
            plan: WcSignPlan::SafeTx { .. },
            ..
        } => (PROPOSE.to_string(), None),
        _ => ("Sign as a message ⚠".to_string(), None),
    }
}

/// Proposing pins a nonce against the Safe's queue; one Kao couldn't read leaves executing (which
/// takes the live nonce) as the only action on a dapp's Safe transaction, its note saying why — or
/// none, saying why, when executing is off the table too. Run after every relabel of the
/// execute-or-propose fork.
fn withhold_blind_propose(review: &mut SignReview) {
    let SignAction::WalletConnect {
        plan: WcSignPlan::SafeTx {
            req, can_execute, ..
        },
        ..
    } = &review.action
    else {
        return;
    };
    if req.queued_nonces.is_some() {
        return;
    }
    if *can_execute {
        review.secondary_label = None;
        review.note = withheld_propose_note(review.note.take());
    } else if !review.confirm_disabled {
        review.confirm_disabled = true;
        review.error = Some(match review.error.take() {
            Some(e) => format!("{e} {QUEUE_UNREAD_TEXT}"),
            None => QUEUE_UNREAD_TEXT.to_string(),
        });
    }
}

/// A dapp's Safe transaction pinned at `nonce`, which `executor` — Kao's earlier execution for the
/// Safe, not seen mined — may still take: only one of them can.
fn unmined_execution_caution(executor: TxHash, nonce: u64) -> String {
    format!(
        "Kao's previous execution for this Safe, transaction {executor:#x}, may still be pending \
         at Safe nonce {nonce} — the nonce this transaction takes. If that one is mined first, \
         this one can't go through: look its hash up before you sign."
    )
}

/// `note` saying why Propose is missing in place of what a proposal would answer the dapp — once,
/// however often the fork is relabelled.
fn withheld_propose_note(note: Option<String>) -> Option<String> {
    match note {
        Some(n) if n.contains(PROPOSE_WITHHELD_NOTE) => Some(n),
        Some(n) if n.contains(SAFE_PROPOSE_NOTE) => {
            Some(n.replacen(SAFE_PROPOSE_NOTE, PROPOSE_WITHHELD_NOTE, 1))
        }
        n => join_notes(n, Some(PROPOSE_WITHHELD_NOTE.to_string())),
    }
}

/// The transaction a review latched onto: one already signed for its request that left without
/// an acknowledgement (an EOA transaction, or a Safe execution's executor transaction).
fn latched_tx(plan: &WcSignPlan) -> Option<&wc::UnconfirmedTx> {
    match plan {
        WcSignPlan::EoaTx { unconfirmed, .. } | WcSignPlan::SafeTx { unconfirmed, .. } => {
            unconfirmed.as_ref()
        }
        _ => None,
    }
}

impl WalletScreen {
    /// Called by App after every (re)build: store; release every review; reconcile; flush; take
    /// the pick; mirror; pump.
    pub fn set_wc_slot(&mut self, slot: WcSlot) -> Task<Message> {
        self.wc.slot = Some(slot);
        self.wc.manual = None;
        let mut tasks = Vec::new();
        if let Some(rt) = self.wc_runtime() {
            // Every InReview entry belonged to an overlay that died with the previous dashboard.
            // A review this very dashboard still shows (the slot handed over twice) goes with
            // them rather than sit over a request the book no longer has under review.
            if self
                .sign_review
                .as_ref()
                .is_some_and(|r| r.is_walletconnect() && r.signing_since.is_none())
            {
                self.sign_review = None;
                self.wc.gone = None;
            }
            rt.with_book(|b| b.release_reviews_except(None));
            let fx = rt.reconcile(&self.wc_available_identities());
            tasks.push(self.wc_effects_task(&rt, fx));
            // The recovery path for any answer stranded while no dashboard existed.
            rt.flush_outbox();
            // The request a [Switch to ⟨account⟩] that built this dashboard was clicked on opens
            // here as [Review] would — if it is this account's. The user lands back on the pane.
            let active = self.wc_active_identity();
            self.wc.manual = rt.with_book(|b| {
                b.take_pick().filter(|k| {
                    active.is_some_and(|a| b.request(k).is_some_and(|r| r.identity == a))
                })
            });
            if self.wc.manual.is_some() {
                self.apps.open_wc();
            }
        }
        self.wc_mirror();
        tasks.push(self.pump_wc_queue());
        Task::batch(tasks)
    }

    pub(super) fn wc_runtime(&self) -> Option<WcRuntime> {
        self.wc
            .slot
            .as_ref()
            .and_then(WcSlot::get)
            .filter(|rt| !rt.is_closed())
    }

    /// `[Subscription::run_with(rt.events(), wc::runtime::event_stream).map(wc_stream_msg)]` or empty.
    pub(super) fn wc_subscriptions(&self) -> Vec<Subscription<Message>> {
        // Keyed by the runtime's generation alone, so the stream keeps running across every
        // review, modal and nav change, and a new runtime is a new stream.
        self.wc_runtime()
            .map(|rt| {
                Subscription::run_with(rt.events(), wc::runtime::event_stream).map(wc_stream_msg)
            })
            .into_iter()
            .collect()
    }

    /// Safe mode → Safe{address, chain_id} of the active Safe; EOA → Eoa{address} if its descriptor can sign.
    ///
    /// A Safe with no strict signing owner (none of this wallet's keys is still an owner) is not
    /// exposable, and in Safe mode that is `None` — never a fallback to the EOA behind it, which
    /// is not what the user is looking at.
    pub(super) fn wc_active_identity(&self) -> Option<wc::WcIdentity> {
        if self.active_safe.is_some() {
            let d = self.active_safe_descriptor()?;
            if strict_signable_indices(d, &self.accounts).is_empty() {
                return None;
            }
            return Some(wc::WcIdentity::Safe {
                address: d.address(),
                chain_id: d.chain_id,
            });
        }
        // The descriptor, never the live signer: a hardware account's signer is a view-only
        // placeholder until the device connects, and a parked one is mid-signature.
        self.build_eoa_context().ok()?;
        Some(wc::WcIdentity::Eoa {
            address: self.address,
        })
    }

    fn wc_caps(&self, identity: &wc::WcIdentity) -> Option<wc::IdentityCaps> {
        match *identity {
            wc::WcIdentity::Eoa { address } => {
                let (idx, desc) = self
                    .accounts
                    .iter()
                    .enumerate()
                    .find(|(_, a)| account_address(a) == Some(address))?;
                let kind = eoa_kind(desc)?;
                // An owner of any Safe Kao knows (cached owner sets) — an opaque 32-byte
                // `personal_sign` from it is a valid Safe owner confirmation.
                let safe_owner = self
                    .safes
                    .iter()
                    .any(|s| s.owners.contains(&address.into_array()));
                Some(wc::IdentityCaps {
                    identity: *identity,
                    label: identity_label(&desc.display_name(idx)),
                    kind: wc::IdentityKind::Eoa(wc::EoaCaps { kind, safe_owner }),
                    chains: wc::served_chain_ids(),
                })
            }
            wc::WcIdentity::Safe { address, chain_id } => {
                let (idx, d) = self
                    .safes
                    .iter()
                    .enumerate()
                    .find(|(_, s)| s.address() == address && s.chain_id == chain_id)?;
                // Never the Builder's `unwrap_or(Mainnet)`: a Safe on a chain Kao doesn't know
                // isn't served at all.
                let chain = Chain::from_chain_id(chain_id)?;
                let signing_block = d
                    .trust
                    .signing_block_reason()
                    .map(str::to_string)
                    .or_else(|| crate::safe::tx::ensure_signable_version(&d.version).err());
                Some(wc::IdentityCaps {
                    identity: *identity,
                    label: identity_label(&d.display_name(idx)),
                    kind: wc::IdentityKind::Safe(wc::SafeCaps {
                        chain,
                        version: d.version.clone(),
                        threshold: d.threshold,
                        owner_count: u32::try_from(d.owners.len()).unwrap_or(u32::MAX),
                        local_signers: u32::try_from(
                            strict_signable_indices(d, &self.accounts).len(),
                        )
                        .unwrap_or(u32::MAX),
                        // Only a handler that implements EIP-1271 lets the Safe validate a
                        // message signature; with any other, every owner would sign for nothing.
                        fallback_handler: d
                            .fallback_handler
                            .is_some_and(|h| crate::safe::is_eip1271_handler(Address::from(h))),
                        signing_block,
                    }),
                    // A Safe is single-chain, and never on a custom network.
                    chains: if wc::served_chain_ids().contains(&chain_id) {
                        vec![chain_id]
                    } else {
                        Vec::new()
                    },
                })
            }
        }
    }

    /// What the wallet calls `identity` now — the name a session or request shows, which can
    /// move after approval (a rename, or an unnamed account's position after a removal).
    fn wc_identity_label(&self, identity: &wc::WcIdentity) -> Option<String> {
        let name = match *identity {
            wc::WcIdentity::Eoa { address } => self
                .accounts
                .iter()
                .enumerate()
                .find(|(_, a)| account_address(a) == Some(address))
                .map(|(i, a)| a.display_name(i)),
            wc::WcIdentity::Safe { address, chain_id } => self
                .safes
                .iter()
                .enumerate()
                .find(|(_, s)| s.address() == address && s.chain_id == chain_id)
                .map(|(i, s)| s.display_name(i)),
        }?;
        Some(identity_label(&name))
    }

    /// Every signing EOA + every Safe with a strict signing owner (by (address, chain_id)).
    fn wc_available_identities(&self) -> Vec<wc::WcIdentity> {
        let mut out: Vec<wc::WcIdentity> = self
            .accounts
            .iter()
            .filter(|a| eoa_kind(a).is_some())
            .filter_map(account_address)
            .map(|address| wc::WcIdentity::Eoa { address })
            .collect();
        out.extend(
            self.safes
                .iter()
                .filter(|d| !strict_signable_indices(d, &self.accounts).is_empty())
                .map(|d| wc::WcIdentity::Safe {
                    address: d.address(),
                    chain_id: d.chain_id,
                }),
        );
        out
    }

    /// THE from == signer gate: identity must equal the active identity (full equality incl. chain_id)
    /// and be able to sign (build_eoa_context / Safe trust+version+strict owners).
    fn wc_signer_context(&self, identity: &wc::WcIdentity) -> Result<WcSignerCtx, wc::Refusal> {
        // Full equality: a same-address sibling Safe on another chain is a different identity,
        // and so is a watch-only account (which has no active identity at all).
        if self.wc_active_identity() != Some(*identity) {
            return Err(wc::Refusal::unauthorized(
                "this request is for an account that isn't the active one in Kao",
            ));
        }
        match *identity {
            wc::WcIdentity::Eoa { address } => {
                self.build_eoa_context()
                    .map_err(wc::Refusal::unauthorized)?;
                let desc = self.active_signer_descriptor();
                if self.address != address || account_address(&desc) != Some(address) {
                    return Err(wc::Refusal::unauthorized(
                        "the active account no longer matches this request",
                    ));
                }
                let kind = eoa_kind(&desc).ok_or_else(|| {
                    wc::Refusal::unauthorized("this account is watch-only and can't sign")
                })?;
                Ok(WcSignerCtx::Eoa {
                    address,
                    desc,
                    kind,
                })
            }
            wc::WcIdentity::Safe { address, chain_id } => {
                let d = self
                    .active_safe_descriptor()
                    .filter(|d| d.address() == address && d.chain_id == chain_id)
                    .ok_or_else(|| {
                        wc::Refusal::unauthorized("this Safe isn't the active one in Kao")
                    })?;
                let chain = Chain::from_chain_id(chain_id).ok_or_else(|| {
                    wc::Refusal::chain_not_served("the Safe is on a chain Kao doesn't support")
                })?;
                if let Some(why) = d.trust.signing_block_reason() {
                    return Err(wc::Refusal::unsupported(
                        "This Safe can't sign from Kao.",
                        why,
                    ));
                }
                crate::safe::tx::ensure_signable_version(&d.version)
                    .map_err(|e| wc::Refusal::unsupported("This Safe can't sign from Kao.", e))?;
                let signable_indices = strict_signable_indices(d, &self.accounts);
                if signable_indices.is_empty() {
                    return Err(wc::Refusal::unsupported(
                        "No owner key for this Safe in Kao.",
                        "none of this wallet's keys is an owner of this Safe any more",
                    ));
                }
                // The Safe's pending queue isn't part of the context: a transaction's request
                // reads it itself (`active_safe_batch_request`), from the same dashboard state.
                Ok(WcSignerCtx::Safe {
                    descriptor: d.clone(),
                    chain,
                    signable_indices,
                })
            }
        }
    }

    fn wc_host_state(&self) -> WcHost {
        let book_signing = self
            .wc_runtime()
            .is_some_and(|rt| rt.with_book(|b| b.has_signing()));
        if self.sign_review.is_some() || self.is_signing_busy() || book_signing {
            return WcHost::Busy;
        }
        // Never hijack a modal or a settings pane the user is in the middle of, nor a Privacy
        // Pools proof: the request waits (badge + toast) and opens when the host frees.
        if self.pool_proof_in_flight
            || !matches!(self.modal, Modal::None)
            || matches!(
                self.settings_pane,
                SettingsPane::NetworkWizard(_) | SettingsPane::Contacts(_)
            )
        {
            return WcHost::Deferred;
        }
        WcHost::Free
    }

    /// Requests waiting for the user plus an open connection request, for the Apps nav badge.
    pub(super) fn wc_badge(&self) -> usize {
        self.wc_runtime().map_or(0, |rt| {
            rt.with_book(|b| b.waiting_count() + usize::from(b.proposal().is_some()))
        })
    }

    pub(super) fn handle_wc_msg(&mut self, m: WcMsg) -> (Task<Message>, Option<Outcome>) {
        match m {
            WcMsg::Started { result } => {
                match result {
                    Ok(generation) => {
                        if self.wc_runtime().map(|rt| rt.generation()) == Some(generation) {
                            // From here the book's pairing state drives the status line.
                            self.apps.wc_pane().set_pairing(wc_app::PairingUi::Idle);
                        } else {
                            debug!(
                                generation,
                                "wc: start result for a runtime no longer in the slot"
                            );
                        }
                    }
                    Err(e) => {
                        warn!("wc: relay start or pairing failed");
                        self.apps
                            .wc_pane()
                            .set_pairing(wc_app::PairingUi::Failed(e));
                    }
                }
                self.wc_mirror();
                (Task::none(), None)
            }
            WcMsg::Stream { generation, item } => {
                let Some(rt) = self.wc_runtime() else {
                    // The runtime left the slot (retired, turned off) with items still buffered.
                    // None of them may touch anything now (a stopped runtime is never resurrected), but the pane must stop showing
                    // that runtime, and a retire's reason must reach the user.
                    debug!(generation, "wc: stream item with no runtime — dropped");
                    self.wc_mirror();
                    return (Task::none(), self.wc_take_retired());
                };
                // An item from a retired runtime never touches the current one.
                if rt.generation() != generation {
                    debug!(
                        generation,
                        current = rt.generation(),
                        "wc: dropping an item from an older runtime"
                    );
                    return (Task::none(), None);
                }
                let (task, outcome) = match item {
                    wc::WcStreamItem::Request { req, received_at } => {
                        self.wc_admit(&rt, req, received_at)
                    }
                    wc::WcStreamItem::Ui(effect) => {
                        let (task, toast) = self.wc_apply_ui(vec![effect]);
                        (task, toast.map(Outcome::Notice))
                    }
                    wc::WcStreamItem::Changed => (Task::none(), None),
                };
                self.wc_mirror();
                let announce = self.wc_announce_proposal(&rt);
                (task, outcome.or(announce.map(Outcome::Notice)))
            }
        }
    }

    pub(super) fn handle_wc_outcome(
        &mut self,
        o: wc_app::Outcome,
    ) -> (Task<Message>, Option<Outcome>) {
        use wc_app::Outcome as O;
        match o {
            O::Pair { uri } => self.wc_pair(uri, crate::settings::proxy_enabled()),
            O::Approve {
                proposal_id,
                identity,
                chains,
            } => self.wc_approve(
                proposal_id,
                identity,
                chains,
                crate::settings::proxy_enabled(),
            ),
            O::RejectProposal { proposal_id } => self.wc_reject_proposal(proposal_id),
            O::ReviewNow { key } => {
                let held = self
                    .wc_runtime()
                    .is_some_and(|rt| rt.with_book(|b| b.held_behind_execution(&key)));
                // Picked either way: the pick outlasts the hold (while the request waits), so it
                // opens once the hold lifts.
                self.wc.manual = Some(key);
                if held {
                    // Nothing would open now: say why rather than do nothing.
                    return (Task::none(), Some(Outcome::Notice(HELD_NOTICE.to_string())));
                }
                (self.pump_wc_queue(), None)
            }
            O::ReviewPastHold { key } => {
                // That request alone stops waiting; its review names the execution it may collide
                // with. Opened as [Review] would: a hold that lifted meanwhile changes nothing.
                if let Some(rt) = self.wc_runtime() {
                    rt.with_book(|b| b.review_past_hold(&key));
                }
                self.wc.manual = Some(key);
                (self.pump_wc_queue(), None)
            }
            O::RejectRequest { key } => self.wc_reject_request(key),
            O::SwitchTo { identity, key } => self.wc_switch_to(identity, key),
            O::Disconnect { topic } => {
                let Some(rt) = self.wc_runtime() else {
                    return (Task::none(), None);
                };
                let fx = rt.disconnect(&topic);
                let (task, toast) = self.wc_apply_ui(fx);
                self.wc_mirror();
                (task, toast.map(Outcome::Notice))
            }
            O::RejectAllFrom { topic } => {
                let Some(rt) = self.wc_runtime() else {
                    return (Task::none(), None);
                };
                // The book answers Waiting requests only; a stranded review counts as one.
                self.wc_release_stranded(&rt);
                let fx = rt.reject_all_from(&topic);
                let (task, toast) = self.wc_apply_ui(fx);
                self.wc_mirror();
                (task, toast.map(Outcome::Notice))
            }
            O::Resume { topic } => {
                if let Some(rt) = self.wc_runtime() {
                    rt.resume(&topic);
                }
                self.wc_mirror();
                (self.pump_wc_queue(), None)
            }
            O::Stop => self.wc_turn_off(),
            O::SaveSettings {
                project_id,
                relay_url,
            } => self.wc_save_settings(project_id, relay_url),
            // Handled inside the Apps pane (back to the launcher); nothing to coordinate.
            O::Close => (Task::none(), None),
        }
    }

    /// The reason a runtime retired itself (idle, a flapping relay, Turn off), once. It is read
    /// from the slot, not the runtime's stream: iced cancels that subscription on the first update
    /// after the runtime left the slot, possibly before it polled the notice. The pane stops
    /// mirroring the dead runtime and says why the relay is off; a flapping relay — the bad
    /// project id / relay URL case — is also a toast and fails the paste that was waiting.
    pub(super) fn wc_take_retired(&mut self) -> Option<Outcome> {
        let notice = self.wc.slot.as_ref()?.take_retire_notice()?;
        info!(error = notice.error, "wc: the runtime retired itself");
        self.wc_mirror();
        let pane = self.apps.wc_pane();
        if notice.error {
            pane.set_pairing(wc_app::PairingUi::Failed(notice.text.clone()));
            Some(Outcome::Notice(notice.text))
        } else {
            pane.set_off_reason(Some(notice.text));
            None
        }
    }

    /// RequestGone → disable the matching open review; Notice → the toast to raise (its line is
    /// already in the Activity list); Attention → window::request_user_attention
    /// (≥ ATTENTION_MIN_INTERVAL apart).
    fn wc_apply_ui(&mut self, fx: Vec<wc::UiEffect>) -> (Task<Message>, Option<String>) {
        let mut tasks = Vec::new();
        let mut toast: Option<String> = None;
        for effect in fx {
            match effect {
                wc::UiEffect::RequestGone { key, reason } => self.wc_request_gone(key, reason),
                // One toast per update; the rest stay in the Activity list only.
                wc::UiEffect::Notice { text } => {
                    toast.get_or_insert(text);
                }
                wc::UiEffect::Attention => tasks.push(self.wc_attention()),
            }
        }
        (Task::batch(tasks), toast)
    }

    /// THE only opener of WC reviews.
    pub(super) fn pump_wc_queue(&mut self) -> Task<Message> {
        let Some(rt) = self.wc_runtime() else {
            return Task::none();
        };
        self.wc_release_stranded(&rt);
        // A key the user picked from the pane that has since left Waiting (answered, opened,
        // dropped) stops being special.
        if let Some(m) = &self.wc.manual
            && rt.with_book(|b| b.state_of(m)) != Some(wc::QueueState::Waiting)
        {
            self.wc.manual = None;
        }
        let mut tasks = Vec::new();
        // Each pass either opens a review (done) or answers the head request at open time and
        // tries the next; bounded by the global queue cap so a request that neither opens nor
        // leaves the queue can't spin.
        for _ in 0..=wc::MAX_QUEUE_TOTAL {
            if self.wc_host_state() != WcHost::Free {
                break;
            }
            let Some(active) = self.wc_active_identity() else {
                break;
            };
            let now = wc::now_secs();
            // A Safe transaction pinned against a queue still loading could pick a nonce
            // a co-signer already holds. (One pinned while Kao's own execution of the previous
            // one is unmined would take that execution's nonce: the book holds those back
            // itself, per Safe.) Messages aren't affected.
            let defer_safe_tx = self.active_safe.is_some() && self.safe_pending_loading;
            let manual = self.wc.manual.clone();
            let Some(key) = rt.with_book(|b| {
                b.next_reviewable(Some(&active), now, manual.as_ref(), defer_safe_tx)
            }) else {
                break;
            };
            if self.wc.manual.as_ref() == Some(&key) {
                self.wc.manual = None;
            }
            tasks.push(self.open_wc_review(key.clone()));
            if self.sign_review.is_some() {
                break;
            }
            if rt.with_book(|b| b.state_of(&key)) == Some(wc::QueueState::Waiting) {
                debug!("wc: head request neither opened nor answered — pump stops");
                break;
            }
        }
        Task::batch(tasks)
    }

    /// Pin quote / (nonce, safeTxHash) from the prepared steps into WcSignPlan; labels; economics; armed_at.
    pub(super) fn wc_on_prepared(&mut self) {
        let holds = self.wc_runtime().map(|rt| rt.with_book(|b| b.safe_execs()));
        let Some(review) = self.sign_review.as_mut() else {
            return;
        };
        let SignAction::WalletConnect { plan, .. } = &review.action else {
            return;
        };
        match plan {
            WcSignPlan::EoaTx { .. } => prepared_eoa_tx(review, &self.portfolio),
            WcSignPlan::SafeTx {
                unconfirmed: Some(_),
                ..
            } => prepared_safe_resend(review),
            WcSignPlan::SafeTx {
                unconfirmed: None, ..
            } => prepared_safe_tx(review, &self.portfolio, holds.as_ref()),
            // Typed data that is a `SafeTx` (from an EOA, or signed as a Safe's message) prepares
            // the call it confirms: move it into the panel, then arm — Confirm only now went live.
            WcSignPlan::Typed { .. } | WcSignPlan::SafeMessage { .. } => prepared_typed(review),
            // Pinned and armed at open; nothing is prepared for it.
            WcSignPlan::Personal { .. } => {}
        }
    }

    /// A dapp transaction's prepare failed (the overlay already shows why, with Confirm blocked):
    /// offer "Re-check", which runs it again in place. Kao's node may simply lag the dapp's, and
    /// the request is still answerable — Cancel stays the way to give up. A Safe review reopened
    /// on an execution already sent describes that transaction from the node too.
    pub(super) fn wc_on_prepare_failed(&mut self) {
        if let Some(review) = self.sign_review.as_mut()
            && matches!(
                review.action,
                SignAction::WalletConnect {
                    plan: WcSignPlan::EoaTx { .. }
                        | WcSignPlan::SafeTx {
                            unconfirmed: Some(_),
                            ..
                        },
                    ..
                }
            )
        {
            review.secondary_label = Some(RECHECK_LABEL.to_string());
            // It signs nothing, so it stays live while Confirm is blocked.
            review.secondary_unblocked = true;
        }
    }

    /// "Re-check": re-run a failed dapp-transaction prepare in place (`wc_requote`: a fresh seq,
    /// the request InReview under it; `wc_reprepare_safe_resend` for a Safe execution already
    /// sent). Signs nothing.
    pub(super) fn wc_recheck(&mut self) -> Task<Message> {
        let Some(review) = self.sign_review.as_ref() else {
            return Task::none();
        };
        let (key, safe_resend) = match &review.action {
            SignAction::WalletConnect {
                key,
                plan: WcSignPlan::EoaTx { .. },
            } => (key.clone(), false),
            SignAction::WalletConnect {
                key,
                plan:
                    WcSignPlan::SafeTx {
                        unconfirmed: Some(_),
                        ..
                    },
            } => (key.clone(), true),
            _ => return Task::none(),
        };
        if !review.secondary_unblocked || review.legs_loading || review.signing_since.is_some() {
            return Task::none();
        }
        let Some(rt) = self.wc_runtime() else {
            self.wc_review_dead(&key, wc::GoneReason::Teardown.sentence());
            return Task::none();
        };
        info!("wc: re-checking a dapp transaction whose prepare failed");
        if safe_resend {
            self.wc_reprepare_safe_resend(&rt, &key)
        } else {
            self.wc_requote(&rt, &key, RECHECK_NOTE.to_string())
        }
    }

    pub(super) fn dispatch_wc(&mut self, execute: bool) -> Task<Message> {
        let DispatchReady {
            rt,
            key,
            plan,
            ctx,
            seq,
            shown_executor,
            mode,
        } = match self.wc_dispatch_checks(execute) {
            Ok(ready) => ready,
            Err(task) => return task,
        };
        let ceremony = match self.wc_ceremony(plan, ctx, execute) {
            Ok(c) => c,
            Err(e) => {
                self.wc_review_error(e, true);
                return Task::none();
            }
        };
        // The executing account is the sender the chain and the dapp see: it must be the one the
        // review named.
        if let Ceremony::SafeExecute {
            signer_owners,
            executor_key,
            ..
        } = &ceremony
        {
            let executor = match executor_key {
                Some(k) => crate::wallet::signer_from_bytes(k)
                    .ok()
                    .map(|s| s.address()),
                None => signer_owners.first().and_then(account_address),
            };
            if executor.is_none() || executor != shown_executor {
                warn!("wc: the Safe executor differs from the one the review named");
                self.wc_review_error(
                    "The account that would send and pay for this execution changed since the \
                     review opened — cancel and ask the dapp again."
                        .to_string(),
                    true,
                );
                return Task::none();
            }
        }
        // Claim the request last: from here on every path ends in `wc_on_signed`.
        if !rt.with_book(|b| b.mark_signing(&key, seq)) {
            self.wc_review_dead(&key, GONE_TEXT);
            return Task::none();
        }
        self.wc_spawn_ceremony(rt, key, ceremony, mode)
    }

    /// Everything `dispatch_wc` re-checks before a ceremony is built: the review is confirmable,
    /// nothing else is signing, the request is still this review's, the from == signer gate and
    /// the method capability still hold, and the plan's own preconditions (a fresh quote, a
    /// pinned Safe transaction, nothing already sent). `Err` carries the task to return instead —
    /// usually none, or the re-quote of an aged quote.
    fn wc_dispatch_checks(&mut self, execute: bool) -> Result<DispatchReady, Task<Message>> {
        let Some(review) = self.sign_review.as_ref() else {
            return Err(Task::none());
        };
        let SignAction::WalletConnect { key, plan } = &review.action else {
            return Err(Task::none());
        };
        // A second click, the arming window, a review still preparing or blocked: the view
        // renders Confirm dead for all of these, and this is the boundary behind it.
        if review.signing_since.is_some()
            || review.broadcast.is_some()
            || review.legs_loading
            || review.confirm_disabled
            || !review.confirm_ready(Instant::now())
        {
            debug!("wc: dispatch ignored — the review isn't confirmable");
            return Err(Task::none());
        }
        // The secondary action exists only for the Safe execute-or-propose fork.
        if !execute && !matches!(plan, WcSignPlan::SafeTx { .. }) {
            return Err(Task::none());
        }
        let key = key.clone();
        let plan = plan.clone();
        let seq = review.seq;
        // The account the review named as the Safe execution's sender, and whether the user is
        // past an owner's refused EIP-712 prompt (Confirm then signs the hash as a message).
        let shown_executor = review.steps.iter().find_map(|s| match s {
            SignStep::SafeExec(x) => x.executor.as_ref().map(|e| e.address),
            _ => None,
        });
        let mode = wc_owner_sig_mode(review);
        // One signature at a time, across every flow and every WC request.
        let book_signing = self
            .wc_runtime()
            .is_some_and(|rt| rt.with_book(|b| b.has_signing()));
        if self.is_signing_busy() || book_signing {
            self.wc_review_error(BUSY_TEXT.to_string(), false);
            return Err(Task::none());
        }
        let Some(rt) = self.wc_runtime() else {
            self.wc_review_dead(&key, wc::GoneReason::Teardown.sentence());
            return Err(Task::none());
        };
        // Still ours to sign: InReview under this very review.
        let identity = match rt.with_book(|b| b.request(&key).map(|r| (r.identity, r.state))) {
            Some((identity, wc::QueueState::InReview { seq: s })) if s == seq => identity,
            _ => {
                self.wc_review_dead(&key, GONE_TEXT);
                return Err(Task::none());
            }
        };
        // Re-check the from == signer gate and the method capability now — the identity
        // or its caps may have moved while the review was open.
        let ctx = match self.wc_signer_context(&identity) {
            Ok(ctx) => ctx,
            Err(r) => {
                self.wc_review_error(r.detail, true);
                return Err(Task::none());
            }
        };
        let capable = match self.wc_caps(&identity) {
            Some(caps) => match &plan {
                // The opaque-hash rule once more: the classification is a pure function of the pinned bytes.
                WcSignPlan::Personal { message, .. } => {
                    caps.personal(&wc::message::classify(message))
                }
                // Owners sign a SafeMessage under the Safe's own domain, never the raw bytes.
                WcSignPlan::SafeMessage { .. } => caps.messages(),
                WcSignPlan::Typed { .. } => caps.typed_data(),
                WcSignPlan::EoaTx { .. } | WcSignPlan::SafeTx { .. } => caps.transactions(),
            },
            None => Err(wc::Refusal::unauthorized(IDENTITY_GONE_DETAIL)),
        };
        if let Err(r) = capable {
            self.wc_review_error(r.detail, true);
            return Err(Task::none());
        }
        match &plan {
            // A transaction already left for this request (`unconfirmed: Some`): Confirm can only
            // send those bytes again, never quote or sign anew — the ceremony below.
            WcSignPlan::EoaTx {
                quote,
                quoted_at,
                unconfirmed: None,
                ..
            } => {
                // The runtime's record decides, should this overlay have missed it.
                if let Some(tx) = rt.with_book(|b| b.unconfirmed(&key)) {
                    self.wc_latch_unconfirmed(tx, None);
                    return Err(Task::none());
                }
                if quote.is_none() {
                    return Err(Task::none());
                }
                // An aged quote is re-taken in place rather than signed.
                if quoted_at.is_none_or(|t| t.elapsed() >= wc::QUOTE_MAX_AGE) {
                    info!("wc: quote older than the limit — re-quoting before signing");
                    return Err(self.wc_requote(&rt, &key, REQUOTE_NOTE.to_string()));
                }
            }
            // An execution already left for this request (`unconfirmed: Some`): Confirm can only
            // send those bytes again, and nothing may be proposed for it either — a proposal at
            // the same nonce would be a second, different transaction.
            WcSignPlan::SafeTx {
                unconfirmed: Some(_),
                ..
            } if !execute => return Err(Task::none()),
            WcSignPlan::SafeTx {
                req,
                can_execute,
                unconfirmed: None,
            } => {
                // The runtime's record decides, should this overlay have missed it.
                if let Some(tx) = rt.with_book(|b| b.unconfirmed(&key)) {
                    self.wc_latch_unconfirmed(tx, None);
                    return Err(Task::none());
                }
                if req.prepared.is_none() {
                    return Err(Task::none());
                }
                // A proposal against a queue Kao couldn't read (the review offers none): refused
                // here, leaving an execution the review offers live.
                if !(execute && *can_execute) && req.queued_nonces.is_none() {
                    self.wc_review_error(QUEUE_UNREAD_TEXT.to_string(), !*can_execute);
                    return Err(Task::none());
                }
            }
            _ => {}
        }
        Ok(DispatchReady {
            rt,
            key,
            plan,
            ctx,
            seq,
            shown_executor,
            mode,
        })
    }

    /// Run the ceremony for a request already marked Signing: park the signer (or hold the busy
    /// flag for a re-send), show the waiting card, and spawn the signing task.
    fn wc_spawn_ceremony(
        &mut self,
        rt: WcRuntime,
        key: wc::WcKey,
        ceremony: Ceremony,
        mode: crate::safe::tx::OwnerSigMode,
    ) -> Task<Message> {
        let network = self.network.clone();
        match ceremony {
            Ceremony::Personal {
                desc,
                from,
                message,
                pin,
                owner,
            } => {
                info!("wc: signing a personal_sign request");
                let handoff = self.park_signer_for_order();
                self.wc_begin_signing(Some(SigningKind::WcMessage {
                    owners: vec![owner],
                    hash_mode: false,
                }));
                wc_sign::spawn_sign_personal(rt, key, handoff, desc, from, message, pin)
            }
            Ceremony::Typed {
                desc,
                from,
                typed,
                pin,
                owner,
                hash_mode,
            } => {
                info!(hash_mode, "wc: signing a typed-data request");
                let handoff = self.park_signer_for_order();
                self.wc_begin_signing(Some(SigningKind::WcMessage {
                    owners: vec![owner],
                    hash_mode,
                }));
                wc_sign::spawn_sign_typed(rt, key, handoff, desc, from, typed, pin)
            }
            Ceremony::EoaTx { desc, plan, quote } => {
                info!(
                    nonce = quote.nonce,
                    "wc: signing and sending a dapp transaction"
                );
                let handoff = self.park_signer_for_order();
                self.wc_begin_signing(None);
                wc_sign::spawn_send_eoa_tx(network, rt, key, handoff, desc, plan, quote)
            }
            Ceremony::EoaResend { chain, tx } => {
                info!(
                    hash = %format!("{:#x}", tx.hash),
                    "wc: sending a dapp transaction already signed again"
                );
                // Nothing is signed or parked; the busy flag keeps every other signature out
                // until it lands (cleared in the shared `Message::Signed` tail).
                self.order_op_in_flight = true;
                self.wc_begin_signing(None);
                wc_sign::spawn_resend_eoa_tx(network, rt, key, chain, tx)
            }
            Ceremony::SafeResend {
                safe,
                chain,
                tx,
                pin,
            } => {
                info!(
                    hash = %format!("{:#x}", tx.hash),
                    "wc: sending a dapp Safe transaction's execution already signed again"
                );
                // As for an EOA re-send: no owner, no executor, nothing parked.
                self.order_op_in_flight = true;
                self.wc_begin_signing(None);
                wc_sign::spawn_resend_safe_exec(network, rt, key, safe, chain, tx, pin)
            }
            Ceremony::SafeExecute {
                sreq,
                signer_owners,
                executor_key,
                kind,
            } => {
                info!(safe = %sreq.safe, "wc: executing a dapp Safe transaction");
                let opts = self.wc_owner_sign_opts(&signer_owners, mode);
                self.wc_begin_signing(Some(kind));
                wc_sign::spawn_execute_safe_tx(
                    network,
                    rt,
                    key,
                    sreq,
                    signer_owners,
                    executor_key,
                    opts,
                )
            }
            Ceremony::SafePropose {
                sreq,
                owner_desc,
                kind,
            } => {
                info!(safe = %sreq.safe, "wc: proposing a dapp Safe transaction");
                let opts = self.wc_owner_sign_opts(std::slice::from_ref(&owner_desc), mode);
                self.wc_begin_signing(Some(kind));
                wc_sign::spawn_propose_safe_tx(network, rt, key, owner_desc, sreq, opts)
            }
            Ceremony::SafeMessage {
                owners,
                signers,
                safe,
                chain,
                threshold,
                data_hash,
                pin,
            } => {
                info!(%safe, threshold, "wc: signing a Safe message");
                let opts = self.wc_owner_sign_opts(&owners, mode);
                self.wc_begin_signing(Some(SigningKind::WcMessage {
                    owners: signers,
                    hash_mode: false,
                }));
                wc_sign::spawn_sign_safe_message(
                    network, rt, key, owners, safe, chain, threshold, data_hash, pin, opts,
                )
            }
        }
    }

    pub(super) fn wc_on_signed(
        &mut self,
        key: wc::WcKey,
        kind: WcSignKind,
        result: Result<SignOutcome, String>,
    ) -> Task<Message> {
        let overlay = self.wc_review_is(&key);
        let Some(rt) = self.wc_runtime() else {
            // Locked or turned off mid-signature: the runtime refused to broadcast or answer —
            // unless it closed during the broadcast itself, when something did go out, or may have.
            warn!(?kind, "wc: signing finished after WalletConnect closed");
            let why = match &result {
                Ok(SignOutcome::Tx(hash)) => format!(
                    "Kao turned WalletConnect off before the dapp heard back. Transaction \
                     {hash:#x} was sent — look it up before asking the dapp again."
                ),
                Ok(SignOutcome::SafeProposed(hash)) => format!(
                    "Kao turned WalletConnect off before the dapp heard back. Safe transaction \
                     {hash:#x} was proposed — look it up before asking the dapp again."
                ),
                Err(e) if e.starts_with(crate::sign::broadcast::BROADCAST_FAILED) => {
                    "Kao turned WalletConnect off before the dapp heard back. A transaction for \
                     it may be on its way — Kao couldn't confirm the network received it, so \
                     check this account's activity before asking the dapp again."
                        .to_string()
                }
                _ => wc::GoneReason::Teardown.sentence().to_string(),
            };
            self.wc_review_dead(&key, &why);
            return Task::none();
        };
        if !overlay {
            // The overlay died with a rebuild (or was replaced): answer from here, there is no
            // review left to retry in — unless a transaction may be on its way, which goes back
            // to the queue for a review that can re-send it.
            let ok = result.is_ok();
            let mut tasks = Vec::new();
            match answer_without_overlay(&rt, &key, kind, result) {
                Some(answer) => {
                    let fx = rt.answer(&key, answer);
                    tasks.push(self.wc_effects_task(&rt, fx));
                }
                None => self.wc_mirror(),
            }
            if ok {
                tasks.push(self.wc_refresh_after(kind));
            }
            tasks.push(self.pump_wc_queue());
            return Task::batch(tasks);
        }
        match result {
            Ok(outcome) => match answer_value(kind, &outcome) {
                Ok(value) => self.wc_signed_ok(&rt, key, kind, &outcome, value),
                Err(e) => {
                    // Something was signed but not in a shape we may send. Tell the dapp the
                    // wallet failed, and show the reason; the request is answered, so Close
                    // answers nothing more.
                    error!(error = %e, "wc: signing result doesn't match its request");
                    let fx = rt.answer(&key, wc::Answer::Refuse(wc::Refusal::failed(e.clone())));
                    self.wc_review_dead(&key, &e);
                    self.wc_effects_task(&rt, fx)
                }
            },
            Err(e) => self.wc_signed_err(&rt, key, e),
        }
    }

    /// Takes the WC review: no-op while signing. A request the book no longer holds answers
    /// nothing; one that died under the review (`gone`) answers Abandon; one whose transaction left
    /// unacknowledged answers −32603 with an Activity line (it may still be mined); otherwise 4001,
    /// or −32603 when (error ∧ confirm_disabled). Then pump.
    pub(super) fn wc_on_cancel(&mut self) -> Task<Message> {
        let Some(review) = self.sign_review.as_ref() else {
            return Task::none();
        };
        let SignAction::WalletConnect { key, .. } = &review.action else {
            return Task::none();
        };
        // Once signing, the overlay can't be dismissed: the task can't be aborted from here.
        if review.signing_since.is_some() {
            return Task::none();
        }
        let key = key.clone();
        // A review that can't be confirmed and says why failed on Kao's side, not the user's.
        let failed = review.error.clone().filter(|_| review.confirm_disabled);
        let unconfirmed = match &review.action {
            SignAction::WalletConnect { plan, .. } => latched_tx(plan).cloned(),
            _ => None,
        };
        self.sign_review = None;
        let gone = self.wc.gone.take_if(|g| *g == key).is_some();
        if self.wc.manual.as_ref() == Some(&key) {
            self.wc.manual = None;
        }
        let Some(rt) = self.wc_runtime() else {
            return Task::none();
        };
        let mut tasks = Vec::new();
        match rt.with_book(|b| b.state_of(&key)) {
            None => debug!("wc: cancelled a review whose request is already gone"),
            Some(_) if gone => {
                let fx = rt.answer(&key, wc::Answer::Abandon);
                tasks.push(self.wc_effects_task(&rt, fx));
            }
            Some(_) => {
                // The runtime's record decides, should this overlay have missed it.
                let unconfirmed = unconfirmed.or_else(|| rt.with_book(|b| b.unconfirmed(&key)));
                let refusal = match (unconfirmed, failed) {
                    (Some(tx), _) => {
                        record_notice(&rt, &unconfirmed_cancelled_text(&tx), true);
                        unconfirmed_refusal(&tx)
                    }
                    (None, Some(detail)) => wc::Refusal::failed(detail),
                    (None, None) => wc::Refusal::user_rejected(),
                };
                info!(
                    code = refusal.code,
                    "wc: review cancelled — answering the dapp"
                );
                let fx = rt.answer(&key, wc::Answer::Refuse(refusal));
                tasks.push(self.wc_effects_task(&rt, fx));
            }
        }
        self.wc_mirror();
        tasks.push(self.pump_wc_queue());
        Task::batch(tasks)
    }

    /// The active identity moved in place (Safe ⇄ EOA, or a Safe/account update). An open review
    /// for an identity that is no longer active goes back to Waiting — not rejected: the dapp
    /// is still waiting and the user may switch back.
    pub(super) fn wc_on_identity_changed(&mut self) -> Task<Message> {
        let active = self.wc_active_identity();
        if let Some(rt) = self.wc_runtime()
            && let Some(review) = self.sign_review.as_ref()
            && let SignAction::WalletConnect { key, .. } = &review.action
            && review.signing_since.is_none()
        {
            let key = key.clone();
            let identity = rt.with_book(|b| b.request(&key).map(|r| r.identity));
            if identity.is_some_and(|id| Some(id) != active) {
                debug!("wc: active identity changed under an open review — released");
                self.sign_review = None;
                if self.wc.gone.as_ref() == Some(&key) {
                    self.wc.gone = None;
                }
                rt.with_book(|b| b.release(&key));
            }
        }
        // The proposal plan follows the active identity.
        self.wc_mirror();
        Task::none()
    }

    /// An account or Safe was renamed, or moved: the pane names identities as the wallet now does.
    pub(super) fn wc_names_changed(&mut self) {
        self.wc_mirror();
    }

    pub(super) fn wc_reconcile(&mut self) -> Task<Message> {
        let Some(rt) = self.wc_runtime() else {
            return Task::none();
        };
        // A session whose identity is no longer in this wallet (or can no longer sign)
        // is disconnected — the dapp hears 6000 rather than waiting on an account that's gone.
        let fx = rt.reconcile(&self.wc_available_identities());
        let task = self.wc_effects_task(&rt, fx);
        self.wc_mirror();
        task
    }

    /// rt.snapshot + plan for the active identity + config_view → apps.wc_pane().sync(..).
    fn wc_mirror(&mut self) {
        let rt = self.wc_runtime();
        let active_caps = self.wc_active_identity().and_then(|id| self.wc_caps(&id));
        let now = wc::now_secs();
        let snap = rt.as_ref().map(|rt| {
            let mut snap = rt.snapshot(now);
            // The book keeps the name each session was approved under; show today's.
            for s in &mut snap.sessions {
                if let Some(label) = self.wc_identity_label(&s.identity) {
                    s.identity_label = label;
                }
            }
            for r in &mut snap.queue {
                if let Some(label) = self.wc_identity_label(&r.identity) {
                    r.identity_label = label;
                }
            }
            if let Some(view) = snap.proposal.as_mut() {
                // The card always describes what Connect would grant the ACTIVE identity.
                view.plan = match (&active_caps, rt.card_proposal()) {
                    (Some(caps), Some(p)) if p.id == view.id => {
                        Some(wc::namespaces::plan_proposal(&p, caps, &wc::chain_label))
                    }
                    _ => None,
                };
            }
            snap
        });
        // "+N more requests waiting" on an open review keeps up with the queue.
        if let Some(rt) = &rt
            && let Some(review) = self.sign_review.as_mut()
            && review.is_walletconnect()
        {
            let behind = rt.with_book(|b| b.waiting_count());
            for step in &mut review.steps {
                if let SignStep::WcOrigin(o) = step {
                    o.waiting_behind = behind;
                }
            }
        }
        self.wc_trace(snap.as_ref());
        let active = active_caps.map(|caps| wc_app::ActiveIdentityView {
            identity: caps.identity,
            badge: identity_badge(&caps),
            label: caps.label,
        });
        self.apps
            .wc_pane()
            .sync(snap, active, wc::runtime::config_view());
        let starting = self.wc.slot.as_ref().is_some_and(WcSlot::is_starting);
        self.apps.wc_pane().sync_start(starting);
    }

    fn open_wc_review(&mut self, key: wc::WcKey) -> Task<Message> {
        let Some(rt) = self.wc_runtime() else {
            return Task::none();
        };
        // The pump opens only on a Free host; this is the boundary behind it.
        if self.sign_review.is_some() || self.is_signing_busy() {
            return Task::none();
        }
        let found = rt.with_book(|b| {
            let req = b.request(&key)?.clone();
            let session = b.session(&key.topic)?.clone();
            Some((req, session))
        });
        let Some((req, session)) = found else {
            return Task::none();
        };
        if req.state != wc::QueueState::Waiting {
            return Task::none();
        }
        // Only the active identity, compared in full (a Safe's chain included). The pump
        // already filtered on this; a mismatch leaves the request waiting, unanswered.
        if self.wc_active_identity() != Some(req.identity) {
            return Task::none();
        }
        let host = session.dapp.headline().to_string();
        let method = req.call.label();
        let ctx = match self.wc_signer_context(&req.identity) {
            Ok(ctx) => ctx,
            Err(r) => return self.wc_refuse_at_open(&rt, &key, &host, method, r),
        };
        let Some(caps) = self.wc_caps(&req.identity) else {
            let r = wc::Refusal::unauthorized(IDENTITY_GONE_DETAIL);
            return self.wc_refuse_at_open(&rt, &key, &host, method, r);
        };
        // The method capability, again: caps may have changed since admission — the opaque-hash
        // rule included, since Kao may have learned meanwhile that this account owns a Safe.
        let capable = match &req.call {
            wc::WcCall::PersonalSign(p) => caps.personal(&p.shape),
            wc::WcCall::SignTypedData(_) => caps.typed_data(),
            wc::WcCall::SendTransaction(_) => caps.transactions(),
            // Answered without a review at admission; never queued.
            wc::WcCall::SwitchChain { .. } | wc::WcCall::Accounts | wc::WcCall::ChainId => {
                Err(wc::Refusal::failed("this request needs no review"))
            }
        };
        if let Err(r) = capable {
            return self.wc_refuse_at_open(&rt, &key, &host, method, r);
        }
        let Some(net) =
            wc::network_id_for(req.chain_id).filter(|_| caps.serves_chain(req.chain_id))
        else {
            let r = wc::Refusal::chain_not_served(format!(
                "{} is no longer set up in Kao",
                wc::chain_label(req.chain_id)
            ));
            return self.wc_refuse_at_open(&rt, &key, &host, method, r);
        };
        let seq = next_task_seq();
        if !rt.with_book(|b| b.mark_in_review(&key, seq)) {
            return Task::none();
        }
        let origin = WcOriginCard {
            dapp: session.dapp.clone(),
            session_ordinal: session.ordinal,
            identity: req.identity,
            identity_label: caps.label.clone(),
            identity_badge: identity_badge(&caps),
            method,
            net,
            unverified_network: net.is_custom(),
            received_at: req.received_at,
            dapp_deadline: req.dapp_deadline,
            kao_deadline: req.kao_deadline,
            waiting_behind: rt.with_book(|b| b.waiting_count()),
        };
        let head = ReviewHead {
            origin,
            title: method.to_string(),
            subtitle: Some(format!("{host} · Session {}", session.ordinal)),
            seq,
            key: key.clone(),
            net,
        };
        let built = match (&req.call, &ctx) {
            (wc::WcCall::PersonalSign(p), WcSignerCtx::Eoa { address, .. }) => {
                self.wc_personal_review(head, p, *address, &caps)
            }
            (wc::WcCall::SignTypedData(t), WcSignerCtx::Eoa { address, .. }) => {
                self.wc_typed_review(head, t, *address, &caps, req.chain_id)
            }
            (wc::WcCall::SendTransaction(tx), WcSignerCtx::Eoa { address, .. }) => {
                self.wc_eoa_tx_review(head, tx, *address)
            }
            (
                wc::WcCall::PersonalSign(_) | wc::WcCall::SignTypedData(_),
                WcSignerCtx::Safe {
                    descriptor,
                    chain,
                    signable_indices,
                    ..
                },
            ) => self.wc_safe_message_review(head, &req, descriptor, *chain, signable_indices),
            (wc::WcCall::SendTransaction(tx), WcSignerCtx::Safe { descriptor, .. }) => {
                self.wc_safe_tx_review(head, &req, tx, descriptor)
            }
            // Excluded by the capability check above.
            (wc::WcCall::SwitchChain { .. } | wc::WcCall::Accounts | wc::WcCall::ChainId, _) => {
                Err(wc::Refusal::failed("this request needs no review"))
            }
        };
        match built {
            Ok((review, task)) => {
                info!(method, "wc: opening a dapp request for review");
                self.sign_review = Some(review);
                task
            }
            Err(r) => self.wc_refuse_at_open(&rt, &key, &host, method, r),
        }
    }
}

/// What every WC review opens with, whatever it signs.
struct ReviewHead {
    origin: WcOriginCard,
    title: String,
    subtitle: Option<String>,
    seq: u64,
    key: wc::WcKey,
    net: crate::chain::NetworkId,
}

// ── private helpers ─────────────────────────────────────────────────────────

impl WalletScreen {
    /// `wc_apply_ui` where no `Outcome` can be returned: a toast is re-delivered to the next update
    /// (see [`toast_task`]), everything else is applied now.
    fn wc_effects_task(&mut self, rt: &WcRuntime, fx: Vec<wc::UiEffect>) -> Task<Message> {
        if fx.is_empty() {
            return Task::none();
        }
        match self.wc_apply_ui(fx) {
            (task, Some(text)) => Task::batch([task, toast_task(rt.generation(), text)]),
            (task, None) => task,
        }
    }

    /// Record an Activity line now and, when `toast`, raise it as a toast on the next update.
    fn wc_notice_task(
        &mut self,
        rt: &WcRuntime,
        text: String,
        error: bool,
        toast: bool,
    ) -> Task<Message> {
        record_notice(rt, &text, error);
        if toast {
            toast_task(rt.generation(), text)
        } else {
            Task::none()
        }
    }

    fn wc_attention(&mut self) -> Task<Message> {
        let now = Instant::now();
        if self
            .wc
            .last_attention
            .is_some_and(|t| now.saturating_duration_since(t) < wc::ATTENTION_MIN_INTERVAL)
        {
            return Task::none();
        }
        self.wc.last_attention = Some(now);
        iced::window::latest().and_then(|id| {
            iced::window::request_user_attention(
                id,
                Some(iced::window::UserAttention::Informational),
            )
        })
    }

    /// The open review is for `key`.
    fn wc_review_is(&self, key: &wc::WcKey) -> bool {
        self.sign_review.as_ref().is_some_and(
            |r| matches!(&r.action, SignAction::WalletConnect { key: k, .. } if k == key),
        )
    }

    /// Backstop: a request InReview that the open overlay isn't showing lost its overlay without
    /// being released or answered (another flow cleared or replaced `sign_review`). Nothing would
    /// ever reopen it — the pump picks Waiting requests only — so it goes back to Waiting, where
    /// the pump and the pane's Review / Reject can reach it. Returns how many were released.
    fn wc_release_stranded(&mut self, rt: &WcRuntime) -> usize {
        let shown = self.sign_review.as_ref().and_then(|r| match &r.action {
            SignAction::WalletConnect { key, .. } => Some(key.clone()),
            _ => None,
        });
        let released = rt.with_book(|b| b.release_reviews_except(shown.as_ref()));
        if released > 0 {
            warn!(released, "wc: a review lost its overlay — back to waiting");
            self.wc_mirror();
        }
        released
    }

    /// The request under the open review died (expired, session gone, identity removed): the
    /// review says why and can only be closed. A signing review keeps its waiting card — the task
    /// finds the request dead before anything irreversible and reports Gone.
    fn wc_request_gone(&mut self, key: wc::WcKey, reason: wc::GoneReason) {
        if !self.wc_review_is(&key) {
            return;
        }
        let sentence = self.wc_gone_sentence(&key, reason.sentence());
        if let Some(review) = self.sign_review.as_mut()
            && review.signing_since.is_none()
        {
            review.error = Some(sentence);
            review.confirm_disabled = true;
            // Nothing is left to re-check either.
            review.secondary_unblocked = false;
        }
        self.wc.gone = Some(key);
    }

    /// Why the open review's request died: `why` — unless a transaction already left for it
    /// without an acknowledgement, when "nothing was sent" would be false.
    fn wc_gone_sentence(&self, key: &wc::WcKey, why: &str) -> String {
        let latched = self.sign_review.as_ref().and_then(|r| match &r.action {
            SignAction::WalletConnect { key: k, plan } if k == key => latched_tx(plan).cloned(),
            _ => None,
        });
        latched
            .or_else(|| {
                self.wc_runtime()
                    .and_then(|rt| rt.with_book(|b| b.unconfirmed(key)))
            })
            .map_or_else(|| why.to_string(), |tx| unconfirmed_gone_text(&tx))
    }

    /// Surface a refusal on the open WC review. `disable`: nothing the user does in this review
    /// can fix it (Cancel then answers −32603); otherwise Confirm stays live for a retry.
    fn wc_review_error(&mut self, error: String, disable: bool) {
        if let Some(r) = self.sign_review.as_mut()
            && r.is_walletconnect()
        {
            r.error = Some(error);
            if disable {
                r.confirm_disabled = true;
            }
        }
    }

    /// The open review's request can no longer be answered (it died, or the runtime closed): stop
    /// any waiting card, say why, and leave only Close — which answers nothing.
    fn wc_review_dead(&mut self, key: &wc::WcKey, why: &str) {
        if !self.wc_review_is(key) {
            return;
        }
        let why = self.wc_gone_sentence(key, why);
        if let Some(r) = self.sign_review.as_mut() {
            r.back_to_review(why, false);
            r.confirm_disabled = true;
            r.secondary_unblocked = false;
        }
        self.wc.gone = Some(key.clone());
    }

    /// How a Safe ceremony's owners sign: in `mode`, and — when one of `owners` is the active
    /// account and the dashboard holds its live signer — through that very instance, parked for
    /// the task and handed back through `Message::Signed`, rather than a second connection to the
    /// same device. A held active Ledger that isn't an owner is parked too when an owner is
    /// another Ledger (possibly the same device): the ceremony lets go of it while that one signs.
    /// Raises the busy flag either way (the shared `Message::Signed` tail clears it).
    fn wc_owner_sign_opts(
        &mut self,
        owners: &[AccountDescriptor],
        mode: crate::safe::tx::OwnerSigMode,
    ) -> OwnerSignOpts {
        let is_ledger = |d: &AccountDescriptor| matches!(d, AccountDescriptor::Ledger { .. });
        let live = self.signer.can_sign() && self.signer.address() == self.address;
        let active = self
            .accounts
            .get(self.active_index)
            .filter(|d| account_address(d) == Some(self.address))
            .cloned();
        let active_owner = owners
            .iter()
            .any(|d| account_address(d) == Some(self.address));
        let beside_a_ledger = active.as_ref().is_some_and(is_ledger)
            && owners
                .iter()
                .any(|d| is_ledger(d) && account_address(d) != Some(self.address));
        let parked = if live && (active_owner || beside_a_ledger) {
            Some(self.park_signer_for_order())
        } else {
            self.order_op_in_flight = true;
            None
        };
        OwnerSignOpts {
            mode,
            active: active.filter(|_| parked.is_some()),
            parked,
            ..OwnerSignOpts::default()
        }
    }

    fn wc_begin_signing(&mut self, progress: Option<SigningKind>) {
        if let Some(r) = self.sign_review.as_mut() {
            r.signing_since = Some(Instant::now());
            r.signing_progress = progress;
            r.error = None;
        }
    }

    /// Answer a queued request Kao can't open after all (state drifted since admission) and say so.
    fn wc_refuse_at_open(
        &mut self,
        rt: &WcRuntime,
        key: &wc::WcKey,
        host: &str,
        method: &str,
        refusal: wc::Refusal,
    ) -> Task<Message> {
        warn!(
            code = refusal.code,
            method, "wc: refusing a queued request at open"
        );
        // Worded like the book's own refusal lines. A queued request keeps its parsed call, not
        // the dapp's method name, so the line names the call's kind.
        let text = wc::book::refusal_line(host, method, &refusal.detail);
        let fx = rt.answer(key, wc::Answer::Refuse(refusal));
        let effects = self.wc_effects_task(rt, fx);
        let notice = self.wc_notice_task(rt, text, true, true);
        Task::batch([effects, notice])
    }

    /// Kao's name for a SafeTx / SafeMessage `verifyingContract` that is one of the user's own
    /// Safes (on the request's chain when there is one there, else any chain).
    fn wc_safe_label(&self, kind: &wc::TypedKind, chain_id: u64) -> Option<String> {
        let safe = match kind {
            wc::TypedKind::SafeTx { safe, .. } | wc::TypedKind::SafeMessage { safe } => (*safe)?,
            wc::TypedKind::Generic | wc::TypedKind::Allowance(_) => return None,
        };
        let on_chain = self
            .safes
            .iter()
            .enumerate()
            .find(|(_, s)| s.address() == safe && s.chain_id == chain_id);
        let any = || {
            self.safes
                .iter()
                .enumerate()
                .find(|(_, s)| s.address() == safe)
        };
        on_chain
            .or_else(any)
            .map(|(i, s)| identity_label(&s.display_name(i)))
    }

    fn wc_personal_review(
        &self,
        head: ReviewHead,
        call: &wc::PersonalSign,
        address: Address,
        caps: &wc::IdentityCaps,
    ) -> Result<(SignReview, Task<Message>), wc::Refusal> {
        if call.from != address {
            return Err(wc::Refusal::unauthorized(
                "the message names a different account than the session's",
            ));
        }
        let hardware = caps.hardware();
        let (steps, pin) =
            wc_sign::personal_steps(head.origin, call.from, head.net, call, hardware);
        let action = SignAction::WalletConnect {
            key: head.key,
            plan: WcSignPlan::Personal {
                from: call.from,
                message: call.message.clone(),
                pin,
            },
        };
        let mut review =
            SignReview::pending(head.title, head.subtitle, steps, None, head.seq, action);
        review.legs_loading = false;
        // 32 bytes that aren't text could be a hash of anything.
        if matches!(
            call.shape,
            wc::MessageShape::Binary {
                reason: wc::BinaryReason::OpaqueHash32,
                ..
            }
        ) {
            review.confirm_label = Some("Sign anyway ⚠".to_string());
        }
        review.armed_at = Some(Instant::now());
        Ok((review, Task::none()))
    }

    fn wc_typed_review(
        &self,
        head: ReviewHead,
        req: &wc::TypedRequest,
        address: Address,
        caps: &wc::IdentityCaps,
        chain_id: u64,
    ) -> Result<(SignReview, Task<Message>), wc::Refusal> {
        if req.from != address {
            return Err(wc::Refusal::unauthorized(
                "the typed data names a different account than the session's",
            ));
        }
        let hash_mode = caps.typed_hash_mode();
        let safe_label = self.wc_safe_label(&req.checked.kind, chain_id);
        let task = self.wc_safe_tx_call_task(head.seq, head.net, &req.checked.kind);
        let (steps, pin) =
            wc_sign::typed_steps(head.origin, req.from, head.net, req, hash_mode, safe_label);
        let action = SignAction::WalletConnect {
            key: head.key,
            plan: WcSignPlan::Typed {
                from: req.from,
                typed: req.typed.clone(),
                pin,
            },
        };
        let mut review =
            SignReview::pending(head.title, head.subtitle, steps, None, head.seq, action);
        review.legs_loading = task.is_some();
        if hash_mode {
            // The device shows only the Domain Hash and Message Hash: have them on screen
            // before the user looks at the device.
            review.show_fingerprints = true;
            review.confirm_label = Some("Sign on Ledger".to_string());
        }
        // Signing a SafeTx / SafeMessage IS an owner confirmation.
        if matches!(
            req.checked.kind,
            wc::TypedKind::SafeTx { .. } | wc::TypedKind::SafeMessage { .. }
        ) {
            review.confirm_label = Some("Sign as Safe owner ⚠".to_string());
        }
        review.armed_at = Some(Instant::now());
        Ok((review, task.unwrap_or_else(Task::none)))
    }

    fn wc_eoa_tx_review(
        &self,
        head: ReviewHead,
        tx: &wc::TxIntent,
        address: Address,
    ) -> Result<(SignReview, Task<Message>), wc::Refusal> {
        if tx.from != address {
            return Err(wc::Refusal::unauthorized(
                "the transaction names a different sender than the session's",
            ));
        }
        if tx.chain_id != head.net.chain_id() {
            return Err(wc::Refusal::invalid_params(
                "The transaction's chain doesn't match the request.",
                "the transaction's chain id doesn't match the request's chain",
            ));
        }
        let plan = crate::wallet::tx::SendPlan {
            from: tx.from,
            recipient: tx.to,
            token: SendToken::Call {
                data: tx.data.clone(),
            },
            amount_units: tx.value,
            chain: head.net,
        };
        // A transaction already left for this request (its first review was lost): this review
        // shows that transaction and can only send it again — never a fresh quote.
        let unconfirmed = self
            .wc_runtime()
            .and_then(|rt| rt.with_book(|b| b.unconfirmed(&head.key)));
        let action = SignAction::WalletConnect {
            key: head.key,
            plan: WcSignPlan::EoaTx {
                plan: plan.clone(),
                dapp_gas: tx.dapp_gas,
                ignored: tx.ignored.clone(),
                quote: None,
                quoted_at: None,
                unconfirmed: unconfirmed.clone(),
            },
        };
        let review = SignReview::pending(
            head.title,
            head.subtitle,
            vec![SignStep::WcOrigin(head.origin)],
            ignored_note(&tx.ignored),
            head.seq,
            action,
        );
        let task = self.wc_spawn_eoa_prepare(head.seq, plan, tx.dapp_gas, unconfirmed);
        Ok((review, task))
    }

    fn wc_safe_message_review(
        &self,
        head: ReviewHead,
        req: &wc::QueuedRequest,
        descriptor: &crate::wallet::SafeDescriptor,
        chain: Chain,
        signable_indices: &[u32],
    ) -> Result<(SignReview, Task<Message>), wc::Refusal> {
        let safe = descriptor.address();
        let (from, source) = match &req.call {
            wc::WcCall::PersonalSign(p) => (p.from, wc_sign::WcSafeMessageSource::Personal(p)),
            wc::WcCall::SignTypedData(t) => (t.from, wc_sign::WcSafeMessageSource::Typed(t)),
            _ => return Err(wc::Refusal::failed("not a message request")),
        };
        if from != safe {
            return Err(wc::Refusal::unauthorized(
                "the message names a different account than the session's Safe",
            ));
        }
        if req.chain_id != descriptor.chain_id {
            return Err(wc::Refusal::invalid_params(
                "The request's chain doesn't match the Safe.",
                "the request is for a different chain than the Safe's",
            ));
        }
        let threshold = descriptor.threshold;
        // Exactly the owners that will sign: the ceremony derives them the same way and refuses
        // unless it gets this list.
        let owners = self
            .wc_message_owners(signable_indices, threshold)
            .map_err(|held| {
                wc::Refusal::unsupported(
                    "This Safe can't sign messages from Kao.",
                    format!(
                        "message signatures need {threshold} owner keys in Kao; Kao holds {held}"
                    ),
                )
            })?;
        let any_hardware = owners.iter().any(|(_, d)| {
            matches!(
                d,
                AccountDescriptor::Ledger { .. } | AccountDescriptor::Trezor { .. }
            )
        });
        let signers: Vec<SigningOwner> = owners
            .iter()
            .map(|(i, d)| signing_owner_of(*i, d))
            .collect();
        let owner_count = u32::try_from(descriptor.owners.len()).unwrap_or(u32::MAX);
        // Signing SafeTx / SafeMessage typed data IS an owner confirmation — for another Safe,
        // through this one's EIP-1271 — exactly as it is from an EOA.
        let owner_confirmation = matches!(
            &source,
            wc_sign::WcSafeMessageSource::Typed(t)
                if matches!(
                    t.checked.kind,
                    wc::TypedKind::SafeTx { .. } | wc::TypedKind::SafeMessage { .. }
                )
        );
        // A SafeTx signed as this Safe's message (an owner confirmation for another Safe, through
        // EIP-1271) shows the call it confirms too.
        let task = match &source {
            wc_sign::WcSafeMessageSource::Typed(t) => self.wc_safe_tx_call_task(
                head.seq,
                crate::chain::NetworkId::Builtin(chain),
                &t.checked.kind,
            ),
            wc_sign::WcSafeMessageSource::Personal(_) => None,
        };
        let (steps, data_hash, pin) = wc_sign::safe_message_steps(
            head.origin,
            safe,
            chain,
            threshold,
            owner_count,
            signers,
            source,
        );
        let action = SignAction::WalletConnect {
            key: head.key,
            plan: WcSignPlan::SafeMessage {
                safe,
                chain,
                threshold,
                signable_indices: signable_indices.to_vec(),
                owners: owners
                    .iter()
                    .map(|(_, d)| account_address(d).unwrap_or_default())
                    .collect(),
                data_hash,
                pin,
            },
        };
        let mut review =
            SignReview::pending(head.title, head.subtitle, steps, None, head.seq, action);
        review.legs_loading = task.is_some();
        // A hardware owner shows the SafeMessage hashes on its screen; have them ready.
        review.show_fingerprints = any_hardware;
        if owner_confirmation {
            review.confirm_label = Some("Sign as Safe owner ⚠".to_string());
        }
        review.armed_at = Some(Instant::now());
        Ok((review, task.unwrap_or_else(Task::none)))
    }

    fn wc_safe_tx_review(
        &self,
        head: ReviewHead,
        req: &wc::QueuedRequest,
        tx: &wc::TxIntent,
        descriptor: &crate::wallet::SafeDescriptor,
    ) -> Result<(SignReview, Task<Message>), wc::Refusal> {
        if tx.from != descriptor.address() {
            return Err(wc::Refusal::unauthorized(
                "the transaction names a different sender than the session's Safe",
            ));
        }
        if req.chain_id != descriptor.chain_id || tx.chain_id != descriptor.chain_id {
            return Err(wc::Refusal::invalid_params(
                "The request's chain doesn't match the Safe.",
                "the transaction is for a different chain than the Safe's",
            ));
        }
        // The dapp's call, as a plain CALL from the Safe — never a delegatecall.
        let input = crate::safe::tx::SafeTxInput {
            to: tx.to,
            value: tx.value,
            data: tx.data.clone(),
            operation: crate::safe::tx::Operation::Call,
        };
        let sreq = self
            .active_safe_batch_request(
                input,
                1,
                tx_builder::QueueMap {
                    prepends: 0,
                    queued: 1,
                },
            )
            .map_err(wc::Refusal::failed)?;
        // An execution already left for this request (its first review was lost): this review
        // shows that transaction and can only send it again — nothing is pinned, signed or
        // proposed anew.
        let unconfirmed = self
            .wc_runtime()
            .and_then(|rt| rt.with_book(|b| b.unconfirmed(&head.key)));
        let action = SignAction::WalletConnect {
            key: head.key,
            plan: WcSignPlan::SafeTx {
                req: sreq.clone(),
                // Decided once the prepare pins the nonce (`wc_on_prepared`).
                can_execute: false,
                unconfirmed: unconfirmed.clone(),
            },
        };
        let note = if unconfirmed.is_some() {
            ignored_note(&tx.ignored)
        } else {
            join_notes(
                Some(format!("{SAFE_EXECUTE_NOTE} {SAFE_PROPOSE_NOTE}")),
                ignored_note(&tx.ignored),
            )
        };
        let review = SignReview::pending(
            head.title,
            head.subtitle,
            vec![SignStep::WcOrigin(head.origin)],
            note,
            head.seq,
            action,
        );
        let local_names = build_local_names(&self.accounts, &self.safes, &self.contacts);
        if let Some(sent) = unconfirmed {
            // The executor's call into this Safe is exactly what is shown: the owner-action
            // banner names it.
            let task = wc_sign::spawn_prepare_unconfirmed_safe_exec(
                self.network.clone(),
                head.seq,
                sreq,
                sent,
                self.wc_known_safes(),
                local_names,
            );
            return Ok((review, task));
        }
        // Every other Safe of the user's: a call confirming or executing a transaction on one of
        // them is an owner action (a call to this Safe itself is flagged as a self-call instead).
        let safe = descriptor.address();
        let known_safes = self
            .wc_known_safes()
            .into_iter()
            .filter(|(a, _)| *a != safe)
            .collect();
        let task = wc_sign::spawn_prepare_safe_tx(
            self.network.clone(),
            head.seq,
            sreq,
            local_names,
            known_safes,
        );
        Ok((review, task))
    }

    /// For typed data that is a `SafeTx`: the prepare that decodes the call the Safe would make
    /// (`wc_sign::prepare_safe_tx_call`), so the owner confirmation shows what it confirms. Confirm
    /// stays dead until it lands. `None` for every other kind — nothing to prepare.
    fn wc_safe_tx_call_task(
        &self,
        seq: u64,
        net: crate::chain::NetworkId,
        kind: &wc::TypedKind,
    ) -> Option<Task<Message>> {
        matches!(kind, wc::TypedKind::SafeTx { .. }).then(|| {
            wc_sign::spawn_prepare_safe_tx_call(
                self.network.clone(),
                seq,
                net,
                kind.clone(),
                self.wc_known_safes(),
                build_local_names(&self.accounts, &self.safes, &self.contacts),
            )
        })
    }

    /// The user's Safes by address and name, for the `approveHash` / `execTransaction` banner.
    fn wc_known_safes(&self) -> Vec<(Address, String)> {
        self.safes
            .iter()
            .enumerate()
            .map(|(i, s)| (s.address(), identity_label(&s.display_name(i))))
            .collect()
    }

    /// The active EOA's native balance on `net`, from the portfolio already on screen.
    fn wc_native_balance(&self, net: crate::chain::NetworkId) -> Option<U256> {
        if self.active_safe.is_some() {
            return None;
        }
        self.portfolio
            .iter()
            .find(|t| t.chain == net && t.contract.is_none())
            .map(|t| t.balance_raw)
    }

    /// Decide what a confirmed review runs. `Err` is the user-facing reason it can't run.
    fn wc_ceremony(
        &self,
        plan: WcSignPlan,
        ctx: WcSignerCtx,
        execute: bool,
    ) -> Result<Ceremony, String> {
        const MISMATCH: &str = "The account under review no longer matches the request — \
                                cancel and ask the dapp again.";
        const OWNERS_MOVED: &str = "This Safe's owner keys in Kao changed since the review \
                                    opened — cancel and ask the dapp again.";
        match (plan, ctx) {
            (
                WcSignPlan::Personal { from, message, pin },
                WcSignerCtx::Eoa { address, desc, .. },
            ) if from == address => {
                let owner = signing_owner_of(self.active_index, &desc);
                Ok(Ceremony::Personal {
                    desc,
                    from,
                    message,
                    pin,
                    owner,
                })
            }
            (
                WcSignPlan::Typed { from, typed, pin },
                WcSignerCtx::Eoa {
                    address,
                    desc,
                    kind,
                },
            ) if from == address => {
                let owner = signing_owner_of(self.active_index, &desc);
                Ok(Ceremony::Typed {
                    desc,
                    from,
                    typed,
                    pin,
                    owner,
                    hash_mode: kind == wc::EoaKind::Ledger,
                })
            }
            (
                WcSignPlan::EoaTx {
                    plan,
                    unconfirmed: Some(tx),
                    ..
                },
                WcSignerCtx::Eoa { address, .. },
            ) if plan.from == address => Ok(Ceremony::EoaResend {
                chain: plan.chain,
                tx,
            }),
            (
                WcSignPlan::EoaTx {
                    plan,
                    quote: Some(quote),
                    unconfirmed: None,
                    ..
                },
                WcSignerCtx::Eoa { address, desc, .. },
            ) if plan.from == address && quote.matches_plan(&plan) => {
                Ok(Ceremony::EoaTx { desc, plan, quote })
            }
            (
                WcSignPlan::SafeTx {
                    req,
                    unconfirmed: Some(tx),
                    ..
                },
                WcSignerCtx::Safe {
                    descriptor, chain, ..
                },
            ) if descriptor.address() == req.safe && chain == req.chain => {
                Ok(Ceremony::SafeResend {
                    safe: req.safe,
                    chain,
                    pin: wc_sign::SafeExecInFlight::of(&req),
                    tx,
                })
            }
            (
                WcSignPlan::SafeTx {
                    req,
                    can_execute,
                    unconfirmed: None,
                },
                WcSignerCtx::Safe {
                    descriptor,
                    chain,
                    signable_indices,
                    ..
                },
            ) if descriptor.address() == req.safe && chain == req.chain => {
                if signable_indices != req.signable_indices {
                    return Err(OWNERS_MOVED.to_string());
                }
                // Confirm executes only when the review offered execution; otherwise (and for
                // the secondary action) the transaction is proposed to co-signers.
                // The executor's hash is what the dapp receives: an account already tied to
                // the Safe pays for it when the wallet has one.
                match self.plan_safe_batch_dispatch_with(
                    &req,
                    execute && can_execute,
                    ExecutorPolicy::SafeLinkedFirst,
                )? {
                    SafeBatchPlan::Execute {
                        signer_owners,
                        executor_key,
                        kind,
                    } => Ok(Ceremony::SafeExecute {
                        sreq: req,
                        signer_owners,
                        executor_key,
                        kind,
                    }),
                    SafeBatchPlan::Propose { owner_desc, kind } => Ok(Ceremony::SafePropose {
                        sreq: req,
                        owner_desc,
                        kind,
                    }),
                }
            }
            (
                WcSignPlan::SafeMessage {
                    safe,
                    chain,
                    threshold,
                    signable_indices,
                    owners: reviewed,
                    data_hash,
                    pin,
                },
                WcSignerCtx::Safe {
                    descriptor,
                    chain: ctx_chain,
                    signable_indices: now_signable,
                    ..
                },
            ) if descriptor.address() == safe && ctx_chain == chain => {
                if now_signable != signable_indices || descriptor.threshold != threshold {
                    return Err(OWNERS_MOVED.to_string());
                }
                // The owners the review listed are the owners that sign — or nobody does.
                let pairs = self
                    .wc_message_owners(&signable_indices, threshold)
                    .map_err(|_| OWNERS_MOVED.to_string())?;
                let signing: Vec<Address> = pairs
                    .iter()
                    .map(|(_, d)| account_address(d).unwrap_or_default())
                    .collect();
                if signing != reviewed {
                    return Err(OWNERS_MOVED.to_string());
                }
                let signers = pairs.iter().map(|(i, d)| signing_owner_of(*i, d)).collect();
                let owners = pairs.into_iter().map(|(_, d)| d).collect();
                Ok(Ceremony::SafeMessage {
                    owners,
                    signers,
                    safe,
                    chain,
                    threshold,
                    data_hash,
                    pin,
                })
            }
            _ => Err(MISMATCH.to_string()),
        }
    }

    /// Re-take the EOA quote in place: a fresh seq, the prepared steps dropped (the origin
    /// card stays), the request back to InReview under the new seq, and the prepare re-run.
    fn wc_requote(&mut self, rt: &WcRuntime, key: &wc::WcKey, note: String) -> Task<Message> {
        if self.wc.gone.as_ref() == Some(key) {
            self.wc_review_dead(key, GONE_TEXT);
            return Task::none();
        }
        let current = self.sign_review.as_ref().and_then(|r| match &r.action {
            SignAction::WalletConnect {
                key: k,
                plan:
                    WcSignPlan::EoaTx {
                        plan,
                        dapp_gas,
                        ignored,
                        ..
                    },
            } if k == key => Some((plan.clone(), *dapp_gas, ignored.clone())),
            _ => None,
        });
        let Some((plan, dapp_gas, ignored)) = current else {
            return Task::none();
        };
        // Never a fresh quote once a transaction left for this request: "prepare again" then
        // means showing that transaction again.
        let sent = rt.with_book(|b| b.unconfirmed(key));
        let seq = next_task_seq();
        if !rt.with_book(|b| b.mark_in_review(key, seq)) {
            self.wc_review_dead(key, GONE_TEXT);
            return Task::none();
        }
        if let Some(review) = self.sign_review.as_mut() {
            if let SignAction::WalletConnect {
                plan:
                    WcSignPlan::EoaTx {
                        quote,
                        quoted_at,
                        unconfirmed,
                        ..
                    },
                ..
            } = &mut review.action
            {
                *quote = None;
                *quoted_at = None;
                *unconfirmed = sent.clone();
            }
            review.seq = seq;
            review.legs_loading = true;
            review.steps.retain(|s| matches!(s, SignStep::WcOrigin(_)));
            review.signing_since = None;
            review.signing_progress = None;
            review.error = None;
            review.confirm_label = None;
            review.confirm_disabled = false;
            review.secondary_label = None;
            review.secondary_unblocked = false;
            review.economics = None;
            review.armed_at = None;
            review.note = join_notes(Some(note), ignored_note(&ignored));
        }
        self.wc_spawn_eoa_prepare(seq, plan, dapp_gas, sent)
    }

    /// Describe the execution already sent for a reopened Safe review again, in place: a fresh seq,
    /// the request InReview under it, the prepared steps dropped (the origin card stays). It is
    /// the runtime's record that is shown — bytes since refused as invalid are let go, never shown
    /// again — and Confirm stays the re-send of exactly those bytes.
    fn wc_reprepare_safe_resend(&mut self, rt: &WcRuntime, key: &wc::WcKey) -> Task<Message> {
        if self.wc.gone.as_ref() == Some(key) {
            self.wc_review_dead(key, GONE_TEXT);
            return Task::none();
        }
        let current = self.sign_review.as_ref().and_then(|r| match &r.action {
            SignAction::WalletConnect {
                key: k,
                plan:
                    WcSignPlan::SafeTx {
                        req,
                        unconfirmed: Some(_),
                        ..
                    },
            } if k == key => Some(req.clone()),
            _ => None,
        });
        let Some(req) = current else {
            return Task::none();
        };
        let Some(sent) = rt.with_book(|b| b.unconfirmed(key)) else {
            self.wc_unlatch_voided(rt, key);
            return Task::none();
        };
        let seq = next_task_seq();
        if !rt.with_book(|b| b.mark_in_review(key, seq)) {
            self.wc_review_dead(key, GONE_TEXT);
            return Task::none();
        }
        if let Some(review) = self.sign_review.as_mut() {
            if let SignAction::WalletConnect {
                plan: WcSignPlan::SafeTx { unconfirmed, .. },
                ..
            } = &mut review.action
            {
                *unconfirmed = Some(sent.clone());
            }
            review.seq = seq;
            review.legs_loading = true;
            review.steps.retain(|s| matches!(s, SignStep::WcOrigin(_)));
            review.signing_since = None;
            review.signing_progress = None;
            review.error = None;
            review.confirm_label = None;
            review.confirm_disabled = false;
            review.secondary_label = None;
            review.secondary_unblocked = false;
            review.economics = None;
            review.armed_at = None;
        }
        wc_sign::spawn_prepare_unconfirmed_safe_exec(
            self.network.clone(),
            seq,
            req,
            sent,
            self.wc_known_safes(),
            build_local_names(&self.accounts, &self.safes, &self.contacts),
        )
    }

    /// The prepare for a dapp transaction from an EOA under `seq`. A transaction already sent for
    /// the request (`sent`) is shown and can only be sent again as signed; otherwise a fresh quote.
    fn wc_spawn_eoa_prepare(
        &self,
        seq: u64,
        plan: crate::wallet::tx::SendPlan,
        dapp_gas: Option<u64>,
        sent: Option<wc::UnconfirmedTx>,
    ) -> Task<Message> {
        let known_safes = self.wc_known_safes();
        let local_names = build_local_names(&self.accounts, &self.safes, &self.contacts);
        let balance = self.wc_native_balance(plan.chain);
        match sent {
            Some(tx) => wc_sign::spawn_prepare_unconfirmed_eoa_tx(
                self.network.clone(),
                seq,
                plan,
                tx,
                known_safes,
                local_names,
                balance,
            ),
            None => wc_sign::spawn_prepare_eoa_tx(
                self.network.clone(),
                seq,
                plan,
                dapp_gas,
                known_safes,
                local_names,
                balance,
            ),
        }
    }

    /// The owners a Safe message is signed with: the first `threshold` of the signable owners
    /// Kao holds, with their account indices. The review lists exactly these and the ceremony
    /// signs with exactly these, so both take them from here. `Err(held)` when Kao holds fewer
    /// than `threshold`.
    fn wc_message_owners(
        &self,
        signable_indices: &[u32],
        threshold: u32,
    ) -> Result<Vec<(usize, AccountDescriptor)>, usize> {
        let owners: Vec<(usize, AccountDescriptor)> = signable_indices
            .iter()
            .filter_map(|&i| {
                self.accounts
                    .get(i as usize)
                    .cloned()
                    .map(|d| (i as usize, d))
            })
            .take(threshold as usize)
            .collect();
        if (owners.len() as u64) < u64::from(threshold) {
            Err(owners.len())
        } else {
            Ok(owners)
        }
    }

    /// A signing task succeeded with the review still up for it: answer the dapp, close the
    /// overlay (Kao doesn't track the receipt; the dapp tracks inclusion), leave an Activity line
    /// and a toast, refresh what the transaction changed.
    fn wc_signed_ok(
        &mut self,
        rt: &WcRuntime,
        key: wc::WcKey,
        kind: WcSignKind,
        outcome: &SignOutcome,
        value: serde_json::Value,
    ) -> Task<Message> {
        let host = rt
            .with_book(|b| b.session(&key.topic).map(|s| s.dapp.headline().to_string()))
            .unwrap_or_else(|| "the dapp".to_string());
        // What an executed Safe transaction pinned, read before the review goes: its nonce stays
        // taken until the execution is mined, and its safeTxHash is how Safe{Wallet} finds it.
        let executed = match self.sign_review.as_ref().map(|r| &r.action) {
            Some(SignAction::WalletConnect {
                plan: WcSignPlan::SafeTx { req, .. },
                ..
            }) if kind == WcSignKind::SafeExecute => wc_sign::SafeExecInFlight::of(req)
                .zip(req.prepared.map(|(_, safe_tx_hash)| safe_tx_hash)),
            _ => None,
        };
        let fx = rt.answer(&key, wc::Answer::Result(value));
        self.sign_review = None;
        if self.wc.gone.as_ref() == Some(&key) {
            self.wc.gone = None;
        }
        let text = match (outcome, executed) {
            (SignOutcome::Tx(hash), Some((f, safe_tx_hash))) => {
                info!(
                    hash = %format!("{hash:#x}"),
                    safe_tx_hash = %format!("{safe_tx_hash:#x}"),
                    nonce = f.nonce,
                    "wc: dapp Safe transaction executed"
                );
                // Until it is mined the Safe still reads this nonce, and the Transaction Service
                // never heard of it: the next dapp Safe transaction waits rather than take it too.
                // (The task holds it too; holding twice is one hold.)
                let executor = wc_sign::ExecutorTx::by_hash(*hash);
                wc_sign::hold_safe_exec(rt, self.network.clone(), f, executor);
                format!(
                    "Executed {} for {host} — Safe transaction hash {}",
                    short_hash(hash),
                    short_hash(&safe_tx_hash)
                )
            }
            (SignOutcome::Tx(hash), None) => {
                info!(hash = %format!("{hash:#x}"), "wc: dapp transaction broadcast");
                format!("Sent {} for {host}", short_hash(hash))
            }
            (SignOutcome::SafeProposed(hash), _) => {
                info!(hash = %format!("{hash:#x}"), "wc: dapp Safe transaction proposed");
                format!(
                    "Proposed to co-signers for {host} — it received the Safe transaction hash {}",
                    short_hash(hash)
                )
            }
            _ => {
                info!(?kind, "wc: dapp message signed");
                format!("Signed a message for {host}")
            }
        };
        let effects = self.wc_effects_task(rt, fx);
        let notice = self.wc_notice_task(rt, text, false, true);
        let refresh = self.wc_refresh_after(kind);
        let next = self.pump_wc_queue();
        Task::batch([effects, notice, refresh, next])
    }

    /// A signing task failed with the review still up for it: retry, re-quote / disable,
    /// or report that the dapp stopped waiting.
    fn wc_signed_err(&mut self, rt: &WcRuntime, key: wc::WcKey, e: String) -> Task<Message> {
        let class = rt.failure_class(&key);
        let unconfirmed = rt.with_book(|b| b.unconfirmed(&key));
        warn!(
            ?class,
            unconfirmed = unconfirmed.as_ref().map(|tx| format!("{:#x}", tx.hash)),
            error = %e,
            "wc: signing failed"
        );
        // A transaction left for this request without an acknowledgement: it may be on its way.
        // Whatever this attempt reported, the request is never re-quoted or signed again — the
        // review latches onto the bytes already signed, and Confirm can only send those again.
        if let Some(tx) = unconfirmed {
            if class == wc::FailureClass::Gone {
                let fx = rt.answer(&key, wc::Answer::Abandon);
                self.wc_review_dead(&key, &unconfirmed_gone_text(&tx));
                return self.wc_effects_task(rt, fx);
            }
            rt.with_book(|b| b.back_to_review(&key));
            self.wc_latch_unconfirmed(tx, Some(&e));
            return Task::none();
        }
        if class != wc::FailureClass::Gone {
            self.wc_unlatch_voided(rt, &key);
        }
        match class {
            wc::FailureClass::Retryable => {
                rt.with_book(|b| b.back_to_review(&key));
                if let Some(r) = self.sign_review.as_mut() {
                    // Confirm comes back live; re-arm so it isn't hit by a click in flight.
                    r.back_to_review(e, true);
                }
                Task::none()
            }
            wc::FailureClass::Stale => {
                rt.with_book(|b| b.back_to_review(&key));
                let eoa_tx = self.sign_review.as_ref().is_some_and(|r| {
                    matches!(
                        r.action,
                        SignAction::WalletConnect {
                            plan: WcSignPlan::EoaTx { .. },
                            ..
                        }
                    )
                });
                if eoa_tx {
                    return self.wc_requote(rt, &key, format!("{e} {REQUOTE_NOTE}"));
                }
                if let Some(r) = self.sign_review.as_mut() {
                    r.back_to_review(e, false);
                    r.confirm_disabled = true;
                }
                Task::none()
            }
            wc::FailureClass::Gone => {
                // Nothing was broadcast, proposed or answered; drop the request quietly.
                let fx = rt.answer(&key, wc::Answer::Abandon);
                self.wc_review_dead(&key, GONE_TEXT);
                self.wc_effects_task(rt, fx)
            }
            wc::FailureClass::Eip712Refused => {
                // An owner's device showed the EIP-712 prompt for the Safe hash and refused it —
                // declined, or Blind signing is off; the device can't say which. Nothing else was
                // asked of it. The same hash can be signed as a personal message instead, which a
                // Ledger without Blind signing allows: offer that as the next Confirm, with what
                // the device will show, rather than prompting for it unasked.
                rt.with_book(|b| b.back_to_review(&key));
                if let Some(r) = self.sign_review.as_mut() {
                    let hash = match &r.action {
                        SignAction::WalletConnect {
                            plan: WcSignPlan::SafeMessage { pin, .. },
                            ..
                        } => Some(*pin),
                        SignAction::WalletConnect {
                            plan: WcSignPlan::SafeTx { req, .. },
                            ..
                        } => req.prepared.map(|(_, hash)| hash),
                        _ => None,
                    };
                    r.back_to_review(e, true);
                    match hash {
                        Some(hash) => {
                            r.owner_eth_sign = Some(OwnerEthSign::of(hash));
                            let (confirm, secondary) = eth_sign_labels(&r.action);
                            r.confirm_label = Some(confirm);
                            r.secondary_label = secondary;
                            withhold_blind_propose(r);
                        }
                        None => r.confirm_disabled = true,
                    }
                }
                Task::none()
            }
            wc::FailureClass::ExecuteRefused => {
                // The call reverts against the chain as it stands, so executing it is refused —
                // every time. Proposing doesn't run it now: that stays on offer, as an explicit
                // override, with the reason on screen.
                rt.with_book(|b| b.back_to_review(&key));
                if let Some(r) = self.sign_review.as_mut() {
                    let no_owner_key = match &mut r.action {
                        SignAction::WalletConnect {
                            plan:
                                WcSignPlan::SafeTx {
                                    req, can_execute, ..
                                },
                            ..
                        } => {
                            *can_execute = false;
                            req.signable_indices.is_empty()
                        }
                        _ => true,
                    };
                    let (confirm, secondary, disabled) =
                        safe_exec_labels(false, no_owner_key, true);
                    r.confirm_label = Some(confirm);
                    r.secondary_label = secondary;
                    r.confirm_disabled = disabled;
                    r.back_to_review(e, true);
                    withhold_blind_propose(r);
                    for step in &mut r.steps {
                        if let SignStep::SafeExec(x) = step {
                            x.executor = None;
                        }
                    }
                }
                Task::none()
            }
            // Always noted with its record (handled above); without one there are no bytes to
            // send again, and nothing may be signed anew.
            wc::FailureClass::Unconfirmed => {
                rt.with_book(|b| b.back_to_review(&key));
                if let Some(r) = self.sign_review.as_mut() {
                    r.back_to_review(e, false);
                    r.confirm_disabled = true;
                }
                Task::none()
            }
        }
    }

    /// Latch the open review onto `tx`, a transaction signed for its request that left without an
    /// acknowledgement: say so, and turn Confirm into sending those exact bytes again. Nothing in
    /// this review can quote or sign anything anew from here on.
    ///
    /// For a Safe transaction `tx` is the executor's `execTransaction`: the owners are never asked
    /// again, proposing is withdrawn (it would file a second transaction at the same nonce), and
    /// the Safe's nonce stays held until it is mined.
    fn wc_latch_unconfirmed(&mut self, tx: wc::UnconfirmedTx, why: Option<&str>) {
        let Some(r) = self.sign_review.as_mut() else {
            return;
        };
        let (text, pin, newly) = match &mut r.action {
            SignAction::WalletConnect {
                plan: WcSignPlan::EoaTx { unconfirmed, .. },
                ..
            } => {
                let newly = unconfirmed.replace(tx.clone()).is_none();
                (unconfirmed_review_text(&tx, why), None, newly)
            }
            SignAction::WalletConnect {
                plan:
                    WcSignPlan::SafeTx {
                        req, unconfirmed, ..
                    },
                ..
            } => {
                let newly = unconfirmed.replace(tx.clone()).is_none();
                (
                    unconfirmed_safe_review_text(&tx, why),
                    wc_sign::SafeExecInFlight::of(req),
                    newly,
                )
            }
            _ => return,
        };
        // Confirm comes back live; re-arm so it isn't hit by a click in flight.
        r.back_to_review(text, true);
        r.confirm_label = Some(RESEND_LABEL.to_string());
        r.confirm_disabled = false;
        r.secondary_label = None;
        r.secondary_unblocked = false;
        // Nothing is signed from here on, as a message or otherwise.
        r.owner_eth_sign = None;
        let Some(rt) = self.wc_runtime() else {
            return;
        };
        if newly {
            record_notice(&rt, &unconfirmed_latched_text(&tx), true);
        }
        if let Some(pin) = pin {
            let executor = wc_sign::ExecutorTx::of(&tx);
            wc_sign::hold_safe_exec(&rt, self.network.clone(), pin, executor);
        }
    }

    /// The runtime let go of the transaction the open review for `key` latched onto, while still
    /// holding the request — the node refused those very bytes as invalid on any node, so they can
    /// never be mined ([`wc::WcBook::void_unconfirmed`]). The review stops offering to send them
    /// again; whatever the failure's class does next starts from a review with nothing on its way.
    /// A request the runtime no longer holds keeps its latch: then nothing says the bytes are dead.
    fn wc_unlatch_voided(&mut self, rt: &WcRuntime, key: &wc::WcKey) {
        if rt.with_book(|b| b.request(key).is_none() || b.unconfirmed(key).is_some()) {
            return;
        }
        let Some(r) = self.sign_review.as_mut() else {
            return;
        };
        let SignAction::WalletConnect {
            key: k,
            plan: WcSignPlan::EoaTx { unconfirmed, .. } | WcSignPlan::SafeTx { unconfirmed, .. },
        } = &mut r.action
        else {
            return;
        };
        if k != key {
            return;
        }
        let Some(tx) = unconfirmed.take() else {
            return;
        };
        info!(
            hash = %format!("{:#x}", tx.hash),
            "wc: the latched transaction was refused as invalid; the review lets go of it"
        );
        r.confirm_label = None;
    }

    /// Refresh what a completed signature changed.
    fn wc_refresh_after(&mut self, kind: WcSignKind) -> Task<Message> {
        match kind {
            WcSignKind::EoaTx => Task::batch([
                self.refresh_verification_task(),
                self.fetch_portfolio_task(),
            ]),
            WcSignKind::SafeExecute | WcSignKind::SafePropose => {
                // Mark the queue loading until a read launched after this one lands: the pump
                // then defers the next Safe transaction instead of pinning a nonce this one
                // just took.
                let pending = self.reload_safe_pending(true);
                let portfolio = if kind == WcSignKind::SafeExecute {
                    self.fetch_portfolio_task()
                } else {
                    Task::none()
                };
                Task::batch([pending, portfolio])
            }
            WcSignKind::Personal | WcSignKind::Typed | WcSignKind::SafeMessage => Task::none(),
        }
    }

    /// Admission: validate against the session's identity, hand the verdict to the book, and
    /// toast once when the request can't open now.
    fn wc_admit(
        &mut self,
        rt: &WcRuntime,
        req: wallet_connect::sign::PendingRequest,
        received_at: u64,
    ) -> (Task<Message>, Option<Outcome>) {
        let key = wc::WcKey {
            topic: req.topic.clone(),
            id: req.id,
        };
        let Some(session) = rt.with_book(|b| b.session(&req.topic).cloned()) else {
            // A session Kao never bound, or one already deleted: nothing to answer on.
            debug!(id = req.id, "wc: request for an unknown session dropped");
            return (Task::none(), None);
        };
        let admitted = match self.wc_caps(&session.identity) {
            Some(caps) => wc::request::validate(&req, &session, &caps),
            None => Err(wc::Refusal::unauthorized(IDENTITY_GONE_DETAIL)),
        };
        let refused = admitted.is_err();
        let fx = rt.admit(&req, received_at, admitted);
        let (task, toast) = self.wc_apply_ui(fx);
        if toast.is_some() || refused {
            // A refusal's toast is the book's alone (it names a refused method, throttled per
            // session and within the per-session answer budget): never a second one here, or a refusing flood
            // would keep the toast slot to itself.
            return (task, toast.map(Outcome::Notice));
        }
        let toast = self.wc_waiting_toast(rt, &key, &session);
        (task, toast.map(Outcome::Notice))
    }

    /// The once-per-request toast for a request that can't open now.
    fn wc_waiting_toast(
        &mut self,
        rt: &WcRuntime,
        key: &wc::WcKey,
        session: &wc::BoundSession,
    ) -> Option<String> {
        let identity = rt.with_book(|b| {
            b.request(key)
                .filter(|r| r.state == wc::QueueState::Waiting && !r.notified)
                .map(|r| r.identity)
        })?;
        let host = session.dapp.headline();
        let text = if self.wc_active_identity() != Some(identity) {
            let label = self
                .wc_identity_label(&identity)
                .unwrap_or_else(|| session.identity_label.clone());
            format!("{host} is waiting for {label} — open Apps › WalletConnect")
        } else if session.paused {
            format!(
                "{host} is waiting — pop-ups are paused for this dapp; open Apps › WalletConnect"
            )
        } else if rt.with_book(|b| b.held_behind_execution(key)) {
            format!(
                "{host} is waiting — its transaction waits until Kao's previous execution for \
                 this Safe is mined or given up on"
            )
        } else if self.wc_host_state() == WcHost::Deferred {
            if self.pool_proof_in_flight {
                PROOF_DEFERRED_TOAST.to_string()
            } else {
                DEFERRED_TOAST.to_string()
            }
        } else {
            // Free: the pump opens it now. Busy: it waits silently behind the open review.
            return None;
        };
        rt.with_book(|b| b.mark_notified(key));
        Some(text)
    }

    /// Toast a newly shown proposal card when the user isn't looking at the WalletConnect pane.
    fn wc_announce_proposal(&mut self, rt: &WcRuntime) -> Option<String> {
        let card = rt.with_book(|b| {
            b.proposal()
                .map(|c| (c.proposal.id, c.dapp.headline().to_string()))
        });
        let Some((id, host)) = card else {
            self.wc.announced_proposal = None;
            return None;
        };
        if self.wc.announced_proposal == Some(id) {
            return None;
        }
        self.wc.announced_proposal = Some(id);
        let visible = matches!(self.nav, Nav::Apps)
            && matches!(self.modal, Modal::None)
            && self.apps.wc_visible();
        (!visible).then(|| format!("{host} wants to connect — open Apps › WalletConnect"))
    }

    fn wc_trace(&mut self, snap: Option<&wc::WcSnapshot>) {
        let now = TraceShape::of(snap);
        let before = self.wc.traced.replace(now).unwrap_or(TraceShape::OFF);
        if before.relay != now.relay {
            crate::trace::state("wc", "relay", before.relay, now.relay);
        }
        if before.sessions != now.sessions {
            crate::trace::state("wc", "sessions", before.sessions, now.sessions);
        }
        if before.queue != now.queue {
            crate::trace::state("wc", "queue", before.queue, now.queue);
        }
        if before.proposal != now.proposal {
            let s = |open: bool| if open { "open" } else { "none" };
            crate::trace::state("wc", "proposal", s(before.proposal), s(now.proposal));
        }
    }

    /// Trace the dashboard's own latches — the open review's request died (`gone`), a request
    /// picked from the pane (`manual`) — when they flip, as presence. Runs after every update:
    /// they change on paths that never mirror the book.
    pub(super) fn wc_trace_latches(&mut self) {
        let now = (self.wc.gone.is_some(), self.wc.manual.is_some());
        let before = std::mem::replace(&mut self.wc.traced_latches, now);
        if before.0 != now.0 {
            crate::trace::state("wc", "review_gone", before.0, now.0);
        }
        if before.1 != now.1 {
            crate::trace::state("wc", "manual_pick", before.1, now.1);
        }
    }

    /// Launcher / pane Connect. Local checks first — the URI, then the configuration and
    /// route — and only then the network: a runtime exists from here on, never before.
    /// `proxy_intent` is Kao's proxy setting (`settings::proxy_enabled`).
    fn wc_pair(
        &mut self,
        uri: SecretInput,
        proxy_intent: bool,
    ) -> (Task<Message>, Option<Outcome>) {
        let mut uri = uri.take();
        if uri.trim().len() != uri.len() {
            uri = zeroize::Zeroizing::new(uri.trim().to_string());
        }
        let now = wc::now_secs();
        if let Err(msg) = wc::request::parse_pairing_uri(&uri, now) {
            // Fixed copy: the URI carries the pairing key and is never echoed.
            self.apps
                .wc_pane()
                .set_pairing(wc_app::PairingUi::Failed(msg.to_string()));
            return (Task::none(), None);
        }
        if let Some(rt) = self.wc_runtime() {
            // The route is checked here too: a runtime dialled directly before the proxy was
            // turned on pairs no new dapp, as a start now wouldn't.
            if let Some(e) = rt.route_refusal(proxy_intent) {
                self.apps
                    .wc_pane()
                    .set_pairing(wc_app::PairingUi::Failed(e.to_string()));
                return (Task::none(), None);
            }
            // `pair` refuses while a connection request is open, with its own copy.
            let pairing = match rt.pair(uri, now) {
                Ok(()) => wc_app::PairingUi::Idle,
                Err(msg) => wc_app::PairingUi::Failed(msg.to_string()),
            };
            self.apps.wc_pane().set_pairing(pairing);
            self.wc_mirror();
            return (Task::none(), None);
        }
        let Some(slot) = self.wc.slot.clone() else {
            self.apps.wc_pane().set_pairing(wc_app::PairingUi::Failed(
                "WalletConnect isn't available right now.".to_string(),
            ));
            return (Task::none(), None);
        };
        if slot.is_closed() {
            self.apps.wc_pane().set_pairing(wc_app::PairingUi::Failed(
                "WalletConnect is closed — unlock Kao again to connect.".to_string(),
            ));
            return (Task::none(), None);
        }
        if slot.is_starting() {
            // The pane disables Connect while starting; a second start is never spawned, and a
            // link that gets here anyway is turned away out loud.
            debug!("wc: connect while the relay is still starting — refused");
            self.apps.wc_pane().set_pairing(wc_app::PairingUi::Starting);
            return (
                Task::none(),
                Some(Outcome::Notice(STILL_STARTING.to_string())),
            );
        }
        let cfg = match wc::runtime::config_from_settings(wc::runtime::next_generation()) {
            Ok(cfg) => cfg,
            Err(wc::StartError::NeedsProjectId) => {
                // Park the link with the settings form; Save resumes the connect.
                let parked = SecretInput::from(std::mem::take(&mut *uri));
                self.apps.open_wc();
                self.apps.wc_pane().open_settings_with_pending(
                    parked,
                    "WalletConnect needs a project ID for the default relay — add one, then \
                     Kao connects.",
                );
                return (Task::none(), None);
            }
            Err(e) => {
                // A route error fails closed: never a direct dial around the user's proxy.
                self.apps
                    .wc_pane()
                    .set_pairing(wc_app::PairingUi::Failed(e.to_string()));
                return (Task::none(), None);
            }
        };
        if !slot.begin_start() {
            debug!("wc: the slot refused a start");
            return (Task::none(), None);
        }
        info!("wc: starting the relay connection");
        self.apps.wc_pane().set_pairing(wc_app::PairingUi::Starting);
        (spawn_start(slot, cfg, uri), None)
    }

    /// Set the card's error (and clear its busy flag) through the book.
    fn wc_card_error(
        &mut self,
        rt: &WcRuntime,
        proposal_id: u64,
        error: String,
    ) -> (Task<Message>, Option<Outcome>) {
        let fx = rt.with_book(|b| b.approve_failed(proposal_id, error));
        let ui = rt.apply(fx);
        let (task, toast) = self.wc_apply_ui(ui);
        self.wc_mirror();
        (task, toast.map(Outcome::Notice))
    }

    /// The approval binds exactly what the card displayed — re-planned now against the
    /// active identity, refused if either the identity or the granted chains moved, or if the
    /// relay's route is one Kao's proxy setting (`proxy_intent`) now refuses.
    fn wc_approve(
        &mut self,
        proposal_id: u64,
        identity: wc::WcIdentity,
        chains: Vec<u64>,
        proxy_intent: bool,
    ) -> (Task<Message>, Option<Outcome>) {
        let Some(rt) = self.wc_runtime() else {
            return (Task::none(), None);
        };
        match rt.with_book(|b| b.proposal().map(|c| (c.proposal.id, c.busy))) {
            Some((id, busy)) if id == proposal_id => {
                if busy {
                    debug!("wc: approve while the card is busy — ignored");
                    return (Task::none(), None);
                }
            }
            _ => {
                debug!("wc: approve for a card that is gone — ignored");
                self.wc_mirror();
                return (Task::none(), None);
            }
        }
        if let Some(e) = rt.route_refusal(proxy_intent) {
            return self.wc_card_error(&rt, proposal_id, e.to_string());
        }
        if self.wc_active_identity() != Some(identity) {
            return self.wc_card_error(&rt, proposal_id, CHANGED_TEXT.to_string());
        }
        let Some(caps) = self.wc_caps(&identity) else {
            return self.wc_card_error(&rt, proposal_id, CHANGED_TEXT.to_string());
        };
        let Some(proposal) = rt.card_proposal().filter(|p| p.id == proposal_id) else {
            self.wc_mirror();
            return (Task::none(), None);
        };
        let plan = wc::namespaces::plan_proposal(&proposal, &caps, &wc::chain_label);
        let grant = match plan.verdict {
            Ok(grant) => grant,
            Err(block) => return self.wc_card_error(&rt, proposal_id, block.reason),
        };
        if grant.chains != chains {
            return self.wc_card_error(&rt, proposal_id, CHANGED_TEXT.to_string());
        }
        let ticket = wc::ApproveTicket {
            proposal_id,
            pairing_topic: proposal.pairing_topic.clone(),
            proposer_key: proposal.proposer.public_key,
            grant,
            identity,
            identity_label: caps.label.clone(),
            dapp: wc::DappLabel::from_metadata(&proposal.proposer.metadata),
        };
        match rt.approve(ticket) {
            Ok(()) => {
                info!(chains = chains.len(), "wc: approving a connection request");
                self.wc_mirror();
                (Task::none(), None)
            }
            Err(e) => self.wc_card_error(&rt, proposal_id, e.to_string()),
        }
    }

    /// Reject the card: the plan's own code when it blocks, else 5000.
    fn wc_reject_proposal(&mut self, proposal_id: u64) -> (Task<Message>, Option<Outcome>) {
        let Some(rt) = self.wc_runtime() else {
            return (Task::none(), None);
        };
        let Some(proposal) = rt.card_proposal().filter(|p| p.id == proposal_id) else {
            self.wc_mirror();
            return (Task::none(), None);
        };
        let blocked = self
            .wc_active_identity()
            .and_then(|id| self.wc_caps(&id))
            .and_then(|caps| {
                wc::namespaces::plan_proposal(&proposal, &caps, &wc::chain_label)
                    .verdict
                    .err()
            });
        let error = match &blocked {
            Some(block) => wc::namespaces::proposal_reject_error(block),
            None => wallet_connect::sign::SdkError::UserRejected.error(),
        };
        info!(code = error.code, "wc: rejecting a connection request");
        rt.reject_proposal(proposal_id, error);
        self.wc_mirror();
        (Task::none(), None)
    }

    /// [Reject] on a queue row: 4001 to a request that is waiting, or under review with no overlay
    /// showing it. Never to one an overlay shows or one signing — those have their own controls.
    fn wc_reject_request(&mut self, key: wc::WcKey) -> (Task<Message>, Option<Outcome>) {
        let Some(rt) = self.wc_runtime() else {
            return (Task::none(), None);
        };
        let rejectable = match rt.with_book(|b| b.state_of(&key)) {
            Some(wc::QueueState::Waiting) => true,
            // Under review with no overlay showing it: stranded, so the row is its only control.
            Some(wc::QueueState::InReview { .. }) => !self.wc_review_is(&key),
            Some(wc::QueueState::Signing { .. }) | None => false,
        };
        if !rejectable {
            return (Task::none(), None);
        }
        if self.wc.manual.as_ref() == Some(&key) {
            self.wc.manual = None;
        }
        let refusal = match rt.with_book(|b| b.unconfirmed(&key)) {
            // Not "rejected": the user approved it, and its transaction may yet be mined.
            Some(tx) => {
                record_notice(&rt, &unconfirmed_cancelled_text(&tx), true);
                unconfirmed_refusal(&tx)
            }
            None => wc::Refusal::user_rejected(),
        };
        let fx = rt.answer(&key, wc::Answer::Refuse(refusal));
        let (task, toast) = self.wc_apply_ui(fx);
        self.wc_mirror();
        (task, toast.map(Outcome::Notice))
    }

    /// [Switch to ⟨identity⟩] on the waiting request `key`: the same switches the account dropdown
    /// performs, then `key` opens as [Review] would open it. An EOA other than the active one
    /// rebuilds the dashboard through App, and the pick goes to the new one through the book.
    fn wc_switch_to(
        &mut self,
        identity: wc::WcIdentity,
        key: wc::WcKey,
    ) -> (Task<Message>, Option<Outcome>) {
        // A rebuild under a parked signer would strand it; an open review owns the screen.
        if self.is_signing_busy() || self.sign_review.is_some() {
            return (
                Task::none(),
                Some(Outcome::Notice(
                    "Finish the signature in progress before switching accounts.".to_string(),
                )),
            );
        }
        match identity {
            wc::WcIdentity::Eoa { address } => {
                let Some(idx) = self
                    .accounts
                    .iter()
                    .position(|a| account_address(a) == Some(address))
                else {
                    return (
                        Task::none(),
                        Some(Outcome::Notice(
                            "That account is no longer in Kao.".to_string(),
                        )),
                    );
                };
                self.rename_draft = None;
                if idx != self.active_index {
                    // As the dropdown does: drop the Safe identity here; App rebuilds for the
                    // new account (and the new dashboard pumps through `set_wc_slot`).
                    let was_safe = self.active_safe.take().is_some();
                    self.refresh_txbuilder_context();
                    let probe = self.drain_txbuilder_delegation_probe();
                    if was_safe {
                        self.clear_safe_feeds();
                    }
                    if let Some(rt) = self.wc_runtime() {
                        rt.with_book(|b| b.set_pick(key));
                    }
                    return (probe, Some(Outcome::Switch(idx)));
                }
                self.wc.manual = Some(key);
                (self.exit_safe_mode(), None)
            }
            wc::WcIdentity::Safe { address, chain_id } => {
                let Some(idx) = self
                    .safes
                    .iter()
                    .position(|s| s.address() == address && s.chain_id == chain_id)
                    .filter(|&i| {
                        self.safes
                            .get(i)
                            .is_some_and(|s| s.has_signing_link(&self.accounts))
                    })
                else {
                    return (
                        Task::none(),
                        Some(Outcome::Notice(
                            "Kao can't sign for that Safe any more.".to_string(),
                        )),
                    );
                };
                self.wc.manual = Some(key);
                if self.active_safe == Some(idx) {
                    return (Task::none(), None);
                }
                (self.activate_safe(idx), None)
            }
        }
    }

    /// [Turn off WalletConnect]: every dapp is disconnected and the relay closed. A review
    /// that isn't signing yet closes with it (the teardown answers its request 4900); one that is
    /// signing finds the runtime closed before anything irreversible.
    fn wc_turn_off(&mut self) -> (Task<Message>, Option<Outcome>) {
        let Some(rt) = self.wc_runtime() else {
            self.wc_mirror();
            return (Task::none(), None);
        };
        if self
            .sign_review
            .as_ref()
            .is_some_and(|r| r.is_walletconnect() && r.signing_since.is_none())
        {
            self.sign_review = None;
        }
        info!("wc: turned off by the user");
        rt.retire("You turned WalletConnect off.");
        // Shown right here (the toast below says the rest), not on a later update.
        let _ = self.wc_take_retired();
        self.wc.manual = None;
        self.wc.gone = None;
        self.wc.announced_proposal = None;
        self.wc_mirror();
        (
            Task::none(),
            Some(Outcome::Notice(
                "WalletConnect is off — every dapp was disconnected.".to_string(),
            )),
        )
    }

    /// Settings Save. Both values are validated before either is stored, so a half-applied
    /// save can't leave the relay pointing somewhere the user didn't choose. Never called from
    /// tests: it writes the user's config.
    fn wc_save_settings(
        &mut self,
        project_id: wc_app::SettingEdit<SecretInput>,
        relay_url: wc_app::SettingEdit<String>,
    ) -> (Task<Message>, Option<Outcome>) {
        use wc_app::SettingEdit;
        // Both are checked before either is stored, so a refusal stores nothing. The pane's Save
        // already refuses an invalid draft; this is the same rule, worded in the same place.
        let project = match &project_id {
            SettingEdit::Keep => Ok(None),
            SettingEdit::Clear => Ok(Some(None)),
            SettingEdit::Set(s) => {
                settings::check_walletconnect_project_id(s.expose()).map(|v| Some(Some(v)))
            }
        };
        let relay = match &relay_url {
            SettingEdit::Keep => Ok(None),
            SettingEdit::Clear => Ok(Some(None)),
            SettingEdit::Set(s) => {
                settings::check_walletconnect_relay_url(s).map(|v| Some(Some(v)))
            }
        };
        let (project, relay): (Option<Option<String>>, Option<Option<String>>) =
            match (project, relay) {
                (Ok(p), Ok(r)) => (p, r),
                (Err(e), _) | (_, Err(e)) => {
                    self.apps.wc_pane().set_settings_error(Some(e.to_string()));
                    return (Task::none(), None);
                }
            };
        let stored = project
            .map_or(Ok(()), |p| {
                settings::set_walletconnect_project_id(p.as_deref())
            })
            .and_then(|()| {
                relay.map_or(Ok(()), |r| {
                    settings::set_walletconnect_relay_url(r.as_deref())
                })
            });
        if let Err(e) = stored {
            self.apps.wc_pane().set_settings_error(Some(e.to_string()));
            return (Task::none(), None);
        }
        self.apps.wc_pane().set_settings_error(None);
        self.wc_mirror();
        // A link parked by the missing-project-id prompt resumes now.
        match self.apps.wc_pane().take_pending_pair() {
            Some(uri) => self.wc_pair(uri, crate::settings::proxy_enabled()),
            None => (Task::none(), None),
        }
    }
}

#[cfg(test)]
#[allow(unused_must_use)]
mod tests {
    //! Coordinator tests. The pure decisions — the from == signer gate, the host state,
    //! answer shapes, prepare pins — run on a bare `WalletScreen`. The flows run against an
    //! in-process relay (`testkit::harness`): a dapp `SignClient` and Kao's runtime on one
    //! `RelayServer`, with the test playing the dashboard's subscription by feeding runtime items
    //! into `handle_wc_msg` and running the pump where the `update` wrapper would. No iced `Task`
    //! is ever executed; signing results are delivered to `wc_on_signed` by hand. Keys are random,
    //! nothing touches settings or the wallet on disk.
    use std::collections::BTreeMap;
    use std::time::Duration;

    use alloy::signers::local::PrivateKeySigner;
    use serde_json::json;
    use wallet_connect::crypto::Topic;
    use wallet_connect::relay::RelayServer;
    use wallet_connect::sign::{
        ConnectParams, ProposalNamespace, Session, SessionRequest, SignClient, SignEvent,
        SignEvents,
    };

    use super::*;
    use crate::chain::NetworkId;
    use crate::decode::clear_sign::DecodeResult;
    use crate::net::MockFetcher;
    use crate::sign::digest::Eip712Digests;
    use crate::wallet::sim::SimulationResult;
    use crate::wallet::tx::SendPlan;
    use crate::wallet::{LedgerHdPath, SafeTrust, TrezorHdPath, view_only_account};
    use crate::walletconnect::testkit;
    use sign_review::{ReviewLeg, SafeExecReview, WcTxFeesReview};

    const ANSWER_WAIT: Duration = Duration::from_secs(2);
    const SILENCE: Duration = Duration::from_millis(300);
    const METHODS: [&str; 4] = [
        "personal_sign",
        "eth_signTypedData_v4",
        "eth_sendTransaction",
        "eth_chainId",
    ];

    // ── fixtures ──────────────────────────────────────────────────────────

    fn local_account(key: &PrivateKeySigner) -> AccountDescriptor {
        AccountDescriptor::Local {
            name: None,
            key_bytes: crate::wallet::SecretKeyBytes::new(key.to_bytes().0),
        }
    }

    fn ledger_account(a: Address) -> AccountDescriptor {
        AccountDescriptor::Ledger {
            name: None,
            path: LedgerHdPath::LedgerLive(0),
            address: a.into_array(),
        }
    }

    fn trezor_account(a: Address) -> AccountDescriptor {
        AccountDescriptor::Trezor {
            name: None,
            path: TrezorHdPath::TrezorLive(0),
            address: a.into_array(),
        }
    }

    /// A dashboard over `accounts` signing as `accounts[active]`: a Local account gets its live
    /// signer, hardware and watch-only ones the view-only placeholder they have before a device
    /// connects.
    fn screen(
        accounts: Vec<AccountDescriptor>,
        active: usize,
        safes: Vec<SafeDescriptor>,
    ) -> WalletScreen {
        let desc = accounts.get(active).expect("active account").clone();
        let address = account_address(&desc).expect("account address");
        let signer = match &desc {
            AccountDescriptor::Local { key_bytes, .. } => KaoSigner::Local(
                crate::wallet::signer_from_bytes(&key_bytes.to_b256()).expect("test key"),
            ),
            _ => KaoSigner::ViewOnly(address),
        };
        WalletScreen::new(
            signer,
            accounts,
            safes,
            active,
            Arc::new(MockFetcher::new()),
            crate::portfolio::new_cache(),
            Arc::new(RwLock::new(ContactsBook::new())),
            None,
        )
    }

    /// Safe's CompatibilityFallbackHandler 1.4.1 — a fallback handler that validates EIP-1271.
    const COMPAT_HANDLER: [u8; 20] =
        alloy::primitives::address!("0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99").into_array();

    /// A canonical 1.4.1 Safe on `chain_id` with its CompatibilityFallbackHandler.
    fn safe(
        byte: u8,
        chain_id: u64,
        owners: &[Address],
        linked: Vec<u32>,
        threshold: u32,
    ) -> SafeDescriptor {
        SafeDescriptor {
            name: None,
            chain_id,
            address: [byte; 20],
            version: "1.4.1".into(),
            trust: SafeTrust::Canonical,
            threshold,
            owners: owners.iter().map(|a| a.into_array()).collect(),
            modules: Vec::new(),
            guard: None,
            fallback_handler: Some(COMPAT_HANDLER),
            linked_signer_indices: linked,
            sibling_chains: Vec::new(),
            cached_at: 0,
            tx_service_url: None,
        }
    }

    fn safe_req(safe: Address, threshold: u32, signable: Vec<u32>) -> tx_builder::SafeBatchRequest {
        tx_builder::SafeBatchRequest {
            queue_map: tx_builder::QueueMap {
                prepends: 0,
                queued: 1,
            },
            safe,
            chain: Chain::Mainnet,
            version: "1.4.1".into(),
            trust: SafeTrust::Canonical,
            threshold,
            owner_count: 3,
            signable_indices: signable,
            input: crate::safe::tx::SafeTxInput {
                to: Address::repeat_byte(0x40),
                value: U256::ZERO,
                data: Bytes::new(),
                operation: crate::safe::tx::Operation::Call,
            },
            call_count: 1,
            prepared: None,
            queued_nonces: Some(Vec::new()),
            service_base: "http://127.0.0.1:9".into(),
        }
    }

    fn wc_review(key: wc::WcKey, plan: WcSignPlan) -> SignReview {
        SignReview::pending(
            "WalletConnect".into(),
            None,
            Vec::new(),
            None,
            42,
            SignAction::WalletConnect { key, plan },
        )
    }

    fn safe_exec_step(safe: Address, nonce: u64, onchain_nonce: u64, operation: u8) -> SignStep {
        SignStep::SafeExec(SafeExecReview {
            safe,
            nonce,
            threshold: 1,
            owner_count: 3,
            safe_tx_hash: B256::repeat_byte(0x5e),
            eip712: Eip712Digests::from_parts(B256::repeat_byte(1), B256::repeat_byte(2)),
            inner: Box::new(ReviewLeg {
                title: "Call".into(),
                to: Address::repeat_byte(0x40),
                value: U256::ZERO,
                net: NetworkId::Builtin(Chain::Mainnet),
                calldata: Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
                decoded: Box::new(DecodeResult::Empty),
                sub_legs: Vec::new(),
                self_admin: None,
            }),
            operation,
            guard: None,
            onchain_nonce,
            preflight: None,
            executor: None,
        })
    }

    /// The steps `wc_sign::prepare_eoa_tx` lands for `plan`: the call and its pinned fees.
    fn eoa_tx_steps(plan: &SendPlan, balance_wei: Option<U256>, unverified: bool) -> Vec<SignStep> {
        let quote = TxQuote {
            plan: plan.clone(),
            gas_limit: 50_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000,
            nonce: 3,
            eth_cost_wei: U256::from(100_000_000_000_000u64),
            sim: SimulationResult::unavailable(),
        };
        let (to, value, data) = plan.tx_target();
        vec![
            SignStep::RawTx(ReviewLeg {
                title: "Dapp call".into(),
                to,
                value,
                net: plan.chain,
                calldata: data,
                decoded: Box::new(DecodeResult::Empty),
                sub_legs: Vec::new(),
                self_admin: None,
            }),
            SignStep::WcTxFees(WcTxFeesReview {
                quote,
                gas_note: wc::GasNote::Estimated,
                max_total_wei: value.saturating_add(U256::from(100_000_000_000_000u64)),
                balance_wei,
                unverified_network: unverified,
                sim_reverted: false,
                estimate_failed: None,
            }),
        ]
    }

    /// Land a prepare result on the open review through the dashboard's `SignReviewPrepared`
    /// arm, which appends the steps and, for a WalletConnect review, pins them (`wc_on_prepared`).
    fn deliver_prepared(s: &mut WalletScreen, steps: Vec<SignStep>) {
        let seq = s.sign_review.as_ref().expect("an open review").seq;
        s.update(Message::SignReviewPrepared {
            seq,
            steps: Ok(steps),
        });
    }

    /// Skip the 1 s anti-clickjack window (tests confirm immediately).
    fn disarm(s: &mut WalletScreen) {
        if let Some(r) = s.sign_review.as_mut() {
            r.armed_at = None;
        }
    }

    fn review(s: &WalletScreen) -> &SignReview {
        s.sign_review.as_ref().expect("an open review")
    }

    fn review_key(s: &WalletScreen) -> wc::WcKey {
        match &review(s).action {
            SignAction::WalletConnect { key, .. } => key.clone(),
            _ => panic!("not a WalletConnect review"),
        }
    }

    // ── the in-process relay rig ─────────────────────────────────────────

    struct Rig {
        _relay: RelayServer,
        dapp: SignClient,
        dapp_events: SignEvents,
        rt: WcRuntime,
        slot: WcSlot,
    }

    async fn start_rig() -> Rig {
        start_rig_on(wc::RouteKind::Loopback).await
    }

    /// A rig whose runtime says it reaches its relay by `route`.
    async fn start_rig_on(route: wc::RouteKind) -> Rig {
        let (relay, dapp, dapp_events, rt, slot) = testkit::harness_on(route).await;
        Rig {
            _relay: relay,
            dapp,
            dapp_events,
            rt,
            slot,
        }
    }

    /// Feed runtime items to the dashboard, as its subscription would, until `done` holds.
    /// Returns every outcome (toast) the dashboard raised on the way.
    async fn feed_until(
        s: &mut WalletScreen,
        rt: &WcRuntime,
        done: impl Fn(&WalletScreen) -> bool,
    ) -> Vec<Outcome> {
        let src = rt.events();
        let mut outcomes = Vec::new();
        for _ in 0..256 {
            if done(s) {
                return outcomes;
            }
            let (generation, item) = testkit::next_item(&src).await;
            let (_, outcome) = s.handle_wc_msg(WcMsg::Stream { generation, item });
            outcomes.extend(outcome);
        }
        panic!("the condition never held");
    }

    /// Feed items until the next `Request` arrives, and return it un-fed.
    async fn next_request(s: &mut WalletScreen, rt: &WcRuntime) -> (u64, wc::WcStreamItem) {
        let src = rt.events();
        loop {
            let (generation, item) = testkit::next_item(&src).await;
            if matches!(item, wc::WcStreamItem::Request { .. }) {
                return (generation, item);
            }
            s.handle_wc_msg(WcMsg::Stream { generation, item });
        }
    }

    fn waiting(rt: &WcRuntime) -> usize {
        rt.with_book(|b| b.waiting_count())
    }

    fn queued_keys(rt: &WcRuntime) -> Vec<wc::WcKey> {
        rt.snapshot(wc::now_secs())
            .queue
            .into_iter()
            .map(|r| r.key)
            .collect()
    }

    fn state(rt: &WcRuntime, key: &wc::WcKey) -> Option<wc::QueueState> {
        rt.with_book(|b| b.state_of(key))
    }

    /// Pair the dapp with the dashboard's active identity: paste its URI, take the card, approve
    /// exactly what the card shows.
    async fn connect(s: &mut WalletScreen, rig: &Rig) -> Session {
        let ns = ProposalNamespace::new(["eip155:1"], METHODS, ["chainChanged", "accountsChanged"]);
        let resp = rig
            .dapp
            .connect(ConnectParams {
                optional_namespaces: BTreeMap::from([("eip155".to_string(), ns)]),
                ..Default::default()
            })
            .await
            .expect("dapp connect");
        let uri = resp.uri.as_ref().expect("a fresh pairing").to_string();
        s.handle_wc_outcome(wc_app::Outcome::Pair {
            uri: SecretInput::from(uri),
        });
        feed_until(s, &rig.rt, |_| rig.rt.card_proposal().is_some()).await;
        let proposal = rig.rt.card_proposal().expect("the card");
        let identity = s.wc_active_identity().expect("an exposable identity");
        let caps = s.wc_caps(&identity).expect("caps");
        let chains = wc::namespaces::plan_proposal(&proposal, &caps, &wc::chain_label)
            .verdict
            .expect("a grantable proposal")
            .chains;
        s.handle_wc_outcome(wc_app::Outcome::Approve {
            proposal_id: proposal.id,
            identity,
            chains,
        });
        let session = tokio::time::timeout(ANSWER_WAIT, resp.approval)
            .await
            .expect("approved in time")
            .expect("approved");
        testkit::settle(|| rig.rt.with_book(|b| b.session(&session.topic).is_some())).await;
        session
    }

    type DappCall = tokio::task::JoinHandle<wallet_connect::Result<serde_json::Value>>;

    fn dapp_request(rig: &Rig, topic: &Topic, method: &str, params: serde_json::Value) -> DappCall {
        let dapp = rig.dapp.clone();
        let topic = topic.clone();
        let req = SessionRequest::new(method, params);
        tokio::spawn(async move { dapp.request(&topic, "eip155:1", req).await })
    }

    fn personal_params(from: Address) -> serde_json::Value {
        json!([
            format!("0x{}", alloy::hex::encode(b"hello from the dapp")),
            from.to_checksum(None)
        ])
    }

    fn tx_params(from: Address) -> serde_json::Value {
        json!([{
            "from": from.to_checksum(None),
            "to": Address::repeat_byte(0x40).to_checksum(None),
            "value": "0x0",
            "data": "0xdeadbeef",
        }])
    }

    fn typed_params(from: Address) -> serde_json::Value {
        json!([from.to_checksum(None), testkit::fixtures::mail(1)])
    }

    async fn answered(call: &mut DappCall) -> wallet_connect::Result<serde_json::Value> {
        tokio::time::timeout(ANSWER_WAIT, call)
            .await
            .expect("the dapp got an answer in time")
            .expect("the dapp task")
    }

    async fn assert_unanswered(call: &mut DappCall) {
        assert!(
            tokio::time::timeout(SILENCE, call).await.is_err(),
            "the dapp must not have been answered"
        );
    }

    fn peer_code(r: &wallet_connect::Result<serde_json::Value>) -> Option<i64> {
        match r {
            Err(wallet_connect::Error::Peer(e)) => Some(e.code),
            _ => None,
        }
    }

    async fn dapp_event(events: &mut SignEvents, want: impl Fn(&SignEvent) -> bool) -> SignEvent {
        tokio::time::timeout(ANSWER_WAIT, async {
            loop {
                match events.recv().await {
                    Some(e) if want(&e) => return e,
                    Some(_) => continue,
                    None => panic!("the dapp's event stream closed"),
                }
            }
        })
        .await
        .expect("the dapp saw the event in time")
    }

    // ── the from == signer gate (pure) ───────────────────────────────────

    #[test]
    fn signer_context_refuses_inactive_identity() {
        let (a, b) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let s = screen(vec![local_account(&a), local_account(&b)], 0, Vec::new());
        let other = wc::WcIdentity::Eoa {
            address: b.address(),
        };
        let err = s
            .wc_signer_context(&other)
            .expect_err("another account in the wallet is not the signer");
        assert_eq!(err.code, wc::codes::UNAUTHORIZED);
        let active = wc::WcIdentity::Eoa {
            address: a.address(),
        };
        assert!(matches!(
            s.wc_signer_context(&active),
            Ok(WcSignerCtx::Eoa { address, kind: wc::EoaKind::Local, .. }) if address == a.address()
        ));
    }

    #[test]
    fn signer_context_refuses_sibling_safe_on_other_chain() {
        let owner = PrivateKeySigner::random();
        let mainnet = safe(0x5a, 1, &[owner.address()], vec![0], 1);
        let base = safe(0x5a, 8453, &[owner.address()], vec![0], 1);
        let mut s = screen(vec![local_account(&owner)], 0, vec![mainnet, base]);
        s.test_enter_safe_mode(1);
        let address = Address::from([0x5a; 20]);
        let sibling = wc::WcIdentity::Safe {
            address,
            chain_id: 1,
        };
        assert!(
            s.wc_signer_context(&sibling).is_err(),
            "same address, other chain: a different Safe with possibly different owners"
        );
        let active = wc::WcIdentity::Safe {
            address,
            chain_id: 8453,
        };
        assert_eq!(s.wc_active_identity(), Some(active));
        assert!(matches!(
            s.wc_signer_context(&active),
            Ok(WcSignerCtx::Safe { chain: Chain::Base, ref signable_indices, .. })
                if signable_indices == &vec![0]
        ));
    }

    #[test]
    fn signer_context_refuses_watch_only() {
        let watch = Address::repeat_byte(0x11);
        let s = screen(vec![view_only_account(watch)], 0, Vec::new());
        assert_eq!(s.wc_active_identity(), None, "nothing to expose");
        let identity = wc::WcIdentity::Eoa { address: watch };
        assert!(s.wc_signer_context(&identity).is_err());
        assert!(
            s.wc_caps(&identity).is_none(),
            "a watch-only account has no capabilities"
        );
    }

    #[test]
    fn signer_context_refuses_a_safe_kao_cant_sign_for() {
        let owner = PrivateKeySigner::random();
        let mut unrecognized = safe(0x5b, 1, &[owner.address()], vec![0], 1);
        unrecognized.trust = SafeTrust::UnrecognizedImpl;
        let mut old = safe(0x5c, 1, &[owner.address()], vec![0], 1);
        old.version = "1.1.1".into();
        let mut s = screen(vec![local_account(&owner)], 0, vec![unrecognized, old]);
        for idx in 0..2 {
            s.test_enter_safe_mode(idx);
            let identity = s.wc_active_identity().expect("a strict owner is linked");
            let err = s
                .wc_signer_context(&identity)
                .expect_err("signing is blocked");
            assert_eq!(err.code, wc::codes::UNSUPPORTED_METHOD);
        }
    }

    #[test]
    fn active_identity_follows_safe_mode_and_needs_a_strict_owner() {
        let owner = PrivateKeySigner::random();
        let stranger = Address::repeat_byte(0x77);
        let owned = safe(0x5a, 1, &[owner.address()], vec![0], 1);
        // Linked, but the account is no longer one of the owners.
        let ex_owner = safe(0x5b, 1, &[stranger], vec![0], 1);
        let mut s = screen(vec![local_account(&owner)], 0, vec![owned, ex_owner]);
        assert_eq!(
            s.wc_active_identity(),
            Some(wc::WcIdentity::Eoa {
                address: owner.address()
            })
        );
        s.test_enter_safe_mode(0);
        assert_eq!(
            s.wc_active_identity(),
            Some(wc::WcIdentity::Safe {
                address: Address::from([0x5a; 20]),
                chain_id: 1
            })
        );
        s.test_enter_safe_mode(1);
        assert_eq!(
            s.wc_active_identity(),
            None,
            "a Safe nobody here can sign for is not exposable — and not the EOA behind it"
        );
    }

    #[test]
    fn available_identities_are_signing_eoas_and_strictly_owned_safes() {
        let a = PrivateKeySigner::random();
        let watch = Address::repeat_byte(0x22);
        let ledger = Address::repeat_byte(0x33);
        let accounts = vec![
            local_account(&a),
            view_only_account(watch),
            ledger_account(ledger),
        ];
        let safes = vec![
            safe(0x51, 1, &[a.address()], vec![0], 1),
            // Its only linked account is watch-only.
            safe(0x52, 1, &[watch], vec![1], 1),
            // Linked to an account that isn't an owner.
            safe(0x53, 1, &[Address::repeat_byte(0x99)], vec![0], 1),
        ];
        let s = screen(accounts, 0, safes);
        assert_eq!(
            s.wc_available_identities(),
            vec![
                wc::WcIdentity::Eoa {
                    address: a.address()
                },
                wc::WcIdentity::Eoa { address: ledger },
                wc::WcIdentity::Safe {
                    address: Address::from([0x51; 20]),
                    chain_id: 1
                },
            ]
        );
    }

    #[test]
    fn caps_come_from_descriptors() {
        let a = PrivateKeySigner::random();
        let ledger = Address::repeat_byte(0x33);
        let trezor = Address::repeat_byte(0x44);
        let mut two_of_three = safe(0x51, 1, &[a.address(), ledger, trezor], vec![0], 2);
        two_of_three.fallback_handler = None;
        let s = screen(
            vec![
                local_account(&a),
                ledger_account(ledger),
                trezor_account(trezor),
            ],
            0,
            vec![two_of_three],
        );
        let eoa = s
            .wc_caps(&wc::WcIdentity::Eoa {
                address: a.address(),
            })
            .expect("caps");
        assert!(eoa.safe_owner(), "an owner of a Safe Kao knows");
        assert!(eoa.chains.contains(&1), "Mainnet is always served");
        let ledger_caps = s
            .wc_caps(&wc::WcIdentity::Eoa { address: ledger })
            .expect("caps");
        assert!(ledger_caps.typed_hash_mode());
        let trezor_caps = s
            .wc_caps(&wc::WcIdentity::Eoa { address: trezor })
            .expect("caps");
        assert!(trezor_caps.typed_data().is_err());
        let safe_caps = s
            .wc_caps(&wc::WcIdentity::Safe {
                address: Address::from([0x51; 20]),
                chain_id: 1,
            })
            .expect("caps");
        let wc::IdentityKind::Safe(sc) = &safe_caps.kind else {
            panic!("a Safe identity has Safe caps");
        };
        assert_eq!((sc.threshold, sc.owner_count, sc.local_signers), (2, 3, 1));
        assert!(!sc.fallback_handler);
        assert_eq!(sc.signing_block, None);
        assert_eq!(safe_caps.chains, vec![1]);
        assert!(
            safe_caps.messages().is_err(),
            "no fallback handler, 1 of 2 keys"
        );
        assert!(
            safe_caps.transactions().is_ok(),
            "one owner key can propose"
        );
        assert!(
            s.wc_caps(&wc::WcIdentity::Safe {
                address: Address::from([0x51; 20]),
                chain_id: 10
            })
            .is_none(),
            "no such Safe on that chain"
        );
    }

    /// Only a fallback handler that implements EIP-1271 (Safe's CompatibilityFallbackHandler)
    /// lets a Safe sign messages: with any other handler, `isValidSignature` can't answer, so
    /// every owner would be prompted for a signature the Safe can never validate.
    #[test]
    fn a_safe_whose_handler_cant_validate_eip1271_cant_sign_messages() {
        let a = PrivateKeySigner::random();
        let caps_with = |handler: Option<[u8; 20]>| {
            let mut d = safe(0x51, 1, &[a.address()], vec![0], 1);
            d.fallback_handler = handler;
            let s = screen(vec![local_account(&a)], 0, vec![d]);
            s.wc_caps(&wc::WcIdentity::Safe {
                address: Address::from([0x51; 20]),
                chain_id: 1,
            })
            .expect("caps")
        };
        // An unknown contract (or an EOA) as the handler.
        let unknown = caps_with(Some([0xfa; 20]));
        let err = unknown
            .messages()
            .expect_err("an unknown handler can't sign messages");
        assert!(err.detail.contains("EIP-1271"), "{}", err.detail);
        assert!(unknown.transactions().is_ok(), "transactions don't need it");
        // Every CompatibilityFallbackHandler Kao knows.
        for handler in [
            "0x3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4",
            "0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99",
            "0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4",
            "0x017062a1dE2FE6b99BE3d9d37841FeD19F573804",
        ] {
            let h: Address = handler.parse().unwrap();
            assert!(
                caps_with(Some(h.into_array())).messages().is_ok(),
                "{handler}"
            );
        }
    }

    // ── host state, answers, small helpers (pure) ────────────────────────

    #[test]
    fn host_state_matrix() {
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        assert_eq!(s.wc_host_state(), WcHost::Free);
        s.modal = Modal::Receive(ReceivePane::new(a.address()));
        assert_eq!(s.wc_host_state(), WcHost::Deferred);
        s.modal = Modal::None;
        s.settings_pane = SettingsPane::Contacts(ContactsPane::new(s.contacts.clone()));
        assert_eq!(s.wc_host_state(), WcHost::Deferred);
        s.settings_pane = SettingsPane::Root;
        s.order_op_in_flight = true;
        assert_eq!(s.wc_host_state(), WcHost::Busy);
        s.order_op_in_flight = false;
        s.sign_review = Some(wc_review(
            wc::WcKey {
                topic: Topic::generate(),
                id: 1,
            },
            WcSignPlan::Personal {
                from: a.address(),
                message: Bytes::from_static(b"hi"),
                pin: B256::ZERO,
            },
        ));
        assert_eq!(s.wc_host_state(), WcHost::Busy);
    }

    #[test]
    fn answer_value_maps_each_kind() {
        let h = B256::repeat_byte(0xab);
        let hex = |b: &[u8]| json!(format!("0x{}", alloy::hex::encode(b)));
        assert_eq!(
            answer_value(WcSignKind::EoaTx, &SignOutcome::Tx(h)),
            Ok(hex(h.as_slice()))
        );
        assert_eq!(
            answer_value(WcSignKind::SafeExecute, &SignOutcome::Tx(h)),
            Ok(hex(h.as_slice()))
        );
        assert_eq!(
            answer_value(WcSignKind::SafePropose, &SignOutcome::SafeProposed(h)),
            Ok(hex(h.as_slice()))
        );
        let sig = Bytes::from(vec![0x11; 65]);
        for kind in [
            WcSignKind::Personal,
            WcSignKind::Typed,
            WcSignKind::SafeMessage,
        ] {
            assert_eq!(
                answer_value(kind, &SignOutcome::Signature(sig.clone())),
                Ok(hex(&sig))
            );
        }
        let blob = Bytes::from(vec![0x22; 130]);
        assert_eq!(
            answer_value(
                WcSignKind::SafeMessage,
                &SignOutcome::Signature(blob.clone())
            ),
            Ok(hex(&blob))
        );
    }

    #[test]
    fn answer_value_refuses_mismatched_shapes() {
        let h = B256::repeat_byte(0xab);
        // A proposal's safeTxHash must never be answered as an executed transaction, nor an
        // executor hash as a proposal.
        assert!(answer_value(WcSignKind::SafeExecute, &SignOutcome::SafeProposed(h)).is_err());
        assert!(answer_value(WcSignKind::SafePropose, &SignOutcome::Tx(h)).is_err());
        assert!(answer_value(WcSignKind::EoaTx, &SignOutcome::Unit).is_err());
        assert!(
            answer_value(
                WcSignKind::Personal,
                &SignOutcome::Signature(Bytes::from(vec![1; 64]))
            )
            .is_err()
        );
        assert!(
            answer_value(
                WcSignKind::Typed,
                &SignOutcome::Signature(Bytes::from(vec![1; 130]))
            )
            .is_err()
        );
        assert!(
            answer_value(
                WcSignKind::SafeMessage,
                &SignOutcome::Signature(Bytes::new())
            )
            .is_err()
        );
        assert!(answer_value(WcSignKind::Personal, &SignOutcome::Tx(h)).is_err());
    }

    #[test]
    fn wc_msg_debug_is_shape_only() {
        let secret = "wc:abcd@2?relay-protocol=irn&symKey=deadbeefdeadbeef";
        let m = WcMsg::Started {
            result: Err(secret.to_string()),
        };
        assert_eq!(format!("{m:?}"), "Started { ok: false }");
    }

    #[test]
    fn stream_items_without_a_runtime_are_dropped() {
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        let (task, outcome) = s.handle_wc_msg(WcMsg::Stream {
            generation: 7,
            item: wc::WcStreamItem::Ui(wc::UiEffect::Notice { text: "x".into() }),
        });
        assert_eq!(task.units(), 0);
        assert!(outcome.is_none());
        assert!(s.wc_subscriptions().is_empty());
        assert_eq!(s.wc_badge(), 0);
        assert_eq!(s.pump_wc_queue().units(), 0);
    }

    #[test]
    fn notes_and_short_hashes() {
        assert_eq!(ignored_note(&wc::IgnoredTxFields::default()), None);
        let one = wc::IgnoredTxFields {
            nonce: Some(7),
            ..Default::default()
        };
        assert_eq!(
            ignored_note(&one).as_deref(),
            Some("The dapp's suggested nonce 7 was ignored; Kao set its own.")
        );
        let two = wc::IgnoredTxFields {
            nonce: Some(7),
            max_fee_per_gas: Some(31_500_000_000),
            ..Default::default()
        };
        assert_eq!(
            ignored_note(&two).as_deref(),
            Some("The dapp's suggested nonce 7, max fee 31.5 gwei were ignored; Kao set its own.")
        );
        assert_eq!(short_hash(&B256::repeat_byte(0xab)), "0xabab…abab");
    }

    // ── dispatch is serialized ───────────────────────────────────────────

    #[test]
    fn dispatch_wc_refuses_when_busy() {
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        let mut r = wc_review(
            wc::WcKey {
                topic: Topic::generate(),
                id: 9,
            },
            WcSignPlan::Personal {
                from: a.address(),
                message: Bytes::from_static(b"hi"),
                pin: B256::ZERO,
            },
        );
        r.legs_loading = false;
        s.sign_review = Some(r);
        // Another flow holds the signer.
        s.order_op_in_flight = true;
        let task = s.dispatch_wc(true);
        assert_eq!(task.units(), 0, "nothing is spawned");
        let r = review(&s);
        assert!(r.signing_since.is_none());
        assert_eq!(r.error.as_deref(), Some(BUSY_TEXT));
        assert!(
            !r.confirm_disabled,
            "busy is retryable — Confirm stays live"
        );
        assert!(s.signer.can_sign(), "the live signer was not parked");
    }

    #[test]
    fn dispatch_wc_ignored_inside_arming_window() {
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        let mut r = wc_review(
            wc::WcKey {
                topic: Topic::generate(),
                id: 9,
            },
            WcSignPlan::Personal {
                from: a.address(),
                message: Bytes::from_static(b"hi"),
                pin: B256::ZERO,
            },
        );
        r.legs_loading = false;
        r.armed_at = Some(Instant::now());
        s.sign_review = Some(r);
        assert_eq!(s.dispatch_wc(true).units(), 0);
        let r = review(&s);
        assert!(r.signing_since.is_none() && r.error.is_none());
        assert!(!s.order_op_in_flight);
    }

    // ── prepare pins and labels (pure) ───────────────────────────────────

    fn screen_with_safe_tx_review(threshold: u32, signable: Vec<u32>) -> (WalletScreen, Address) {
        let a = PrivateKeySigner::random();
        let safe_addr = Address::from([0x5a; 20]);
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.sign_review = Some(wc_review(
            wc::WcKey {
                topic: Topic::generate(),
                id: 3,
            },
            WcSignPlan::SafeTx {
                req: safe_req(safe_addr, threshold, signable),
                can_execute: false,
                unconfirmed: None,
            },
        ));
        (s, safe_addr)
    }

    fn safe_plan(s: &WalletScreen) -> (tx_builder::SafeBatchRequest, bool) {
        match &review(s).action {
            SignAction::WalletConnect {
                plan:
                    WcSignPlan::SafeTx {
                        req, can_execute, ..
                    },
                ..
            } => (req.clone(), *can_execute),
            _ => panic!("not a Safe transaction review"),
        }
    }

    #[test]
    fn prepared_safe_tx_with_local_threshold_offers_execute() {
        let (mut s, safe_addr) = screen_with_safe_tx_review(1, vec![0]);
        deliver_prepared(&mut s, vec![safe_exec_step(safe_addr, 5, 5, 0)]);
        let (req, can_execute) = safe_plan(&s);
        assert_eq!(req.prepared, Some((5, B256::repeat_byte(0x5e))), "pinned");
        assert!(can_execute);
        let r = review(&s);
        assert_eq!(r.confirm_label.as_deref(), Some("Sign & execute now"));
        assert_eq!(r.secondary_label.as_deref(), Some("Propose to co-signers"));
        assert!(!r.confirm_disabled);
        assert!(r.armed_at.is_some(), "armed once confirmable");
    }

    #[test]
    fn prepared_safe_tx_below_threshold_or_behind_the_queue_proposes() {
        let (mut s, safe_addr) = screen_with_safe_tx_review(2, vec![0]);
        deliver_prepared(&mut s, vec![safe_exec_step(safe_addr, 5, 5, 0)]);
        assert!(!safe_plan(&s).1);
        assert_eq!(
            review(&s).confirm_label.as_deref(),
            Some("Propose to co-signers")
        );
        assert_eq!(review(&s).secondary_label, None);

        let (mut s, safe_addr) = screen_with_safe_tx_review(1, vec![0]);
        // Two proposals already queued ahead: only the current nonce executes.
        deliver_prepared(&mut s, vec![safe_exec_step(safe_addr, 7, 5, 0)]);
        assert!(!safe_plan(&s).1, "not executable behind the queue");
        assert_eq!(
            review(&s).confirm_label.as_deref(),
            Some("Propose to co-signers")
        );
    }

    #[test]
    fn prepared_safe_tx_refuses_a_delegatecall_or_another_safe() {
        let (mut s, safe_addr) = screen_with_safe_tx_review(1, vec![0]);
        deliver_prepared(&mut s, vec![safe_exec_step(safe_addr, 5, 5, 1)]);
        assert_eq!(safe_plan(&s).0.prepared, None, "nothing pinned");
        assert!(review(&s).confirm_disabled);
        assert!(review(&s).error.is_some());

        let (mut s, _) = screen_with_safe_tx_review(1, vec![0]);
        deliver_prepared(
            &mut s,
            vec![safe_exec_step(Address::repeat_byte(0x01), 5, 5, 0)],
        );
        assert_eq!(safe_plan(&s).0.prepared, None);
        assert!(review(&s).confirm_disabled);
    }

    /// A dapp Safe call Kao's dry run saw revert is offered only as an explicit proposal: the
    /// execute path refuses any call its own dry run sees revert, so an "Execute anyway" button
    /// could only fail. One the dry run passed keeps the routine labels and gets the economics
    /// card from that same run.
    #[test]
    fn prepared_safe_tx_that_reverts_is_propose_only() {
        let (mut s, safe_addr) = screen_with_safe_tx_review(1, vec![0]);
        let mut step = safe_exec_step(safe_addr, 5, 5, 0);
        if let SignStep::SafeExec(x) = &mut step {
            let mut sim = crate::txbuilder::sim::BatchSimResult::unavailable();
            sim.outcome = crate::txbuilder::sim::BatchOutcome::Revert {
                step: 0,
                reason: "ERC20: transfer amount exceeds balance".into(),
            };
            x.preflight = Some(sim);
        }
        deliver_prepared(&mut s, vec![step]);
        assert!(
            !safe_plan(&s).1,
            "execute is not offered for a reverting call"
        );
        let r = review(&s);
        assert_eq!(r.confirm_label.as_deref(), Some("Propose anyway ⚠"));
        assert_eq!(r.secondary_label, None);
        assert!(!r.confirm_disabled, "an override, not a refusal");
        assert!(
            r.economics.is_none(),
            "a reverted run moves nothing: {:?}",
            r.economics
        );

        // A passing dry run keeps the routine labels, and says what the call moves and costs —
        // with the OP-stack caveat on Base.
        let (mut s, safe_addr) = screen_with_safe_tx_review(1, vec![0]);
        if let Some(SignAction::WalletConnect {
            plan: WcSignPlan::SafeTx { req, .. },
            ..
        }) = s.sign_review.as_mut().map(|r| &mut r.action)
        {
            req.chain = Chain::Base;
        }
        let mut step = safe_exec_step(safe_addr, 5, 5, 0);
        if let SignStep::SafeExec(x) = &mut step {
            let mut sim = crate::txbuilder::sim::BatchSimResult::unavailable();
            sim.outcome = crate::txbuilder::sim::BatchOutcome::Success;
            sim.gas_used = 60_000;
            sim.base_fee_per_gas = 1_000_000_000;
            x.preflight = Some(sim);
        }
        deliver_prepared(&mut s, vec![step]);
        let r = review(&s);
        assert_eq!(r.confirm_label.as_deref(), Some("Sign & execute now"));
        let e = r.economics.as_ref().expect("the dry run's economics");
        assert!(e.simulated && e.fee_eth().is_some(), "{e:?}");
        assert!(
            e.fee_caveats.iter().any(|c| c.contains("L1 data fee")),
            "{:?}",
            e.fee_caveats
        );
    }

    const SAFE_TX_TO: Address = Address::repeat_byte(0xA0);

    /// `transfer(0x…badbad, 1e12)`, the call a dapp's SafeTx confirms.
    fn safe_tx_call_data() -> Bytes {
        let mut data = alloy::primitives::keccak256(b"transfer(address,uint256)")[..4].to_vec();
        data.extend_from_slice(B256::left_padding_from(&[0xba, 0xdb, 0xad]).as_slice());
        data.extend_from_slice(&U256::from(1_000_000_000_000u64).to_be_bytes::<32>());
        Bytes::from(data)
    }

    /// `eth_signTypedData_v4` params for a SafeTx on Mainnet that an owner `from` confirms.
    fn safe_tx_typed_params(from: Address) -> serde_json::Value {
        let data = format!("0x{}", alloy::hex::encode(safe_tx_call_data()));
        let safe_tx = testkit::fixtures::safe_tx(Address::repeat_byte(0x5a), SAFE_TX_TO, &data);
        json!([from.to_checksum(None), safe_tx])
    }

    fn safe_tx_call_leg(to: Address, calldata: Bytes) -> ReviewLeg {
        ReviewLeg {
            title: "Call".into(),
            to,
            value: U256::ZERO,
            net: NetworkId::Builtin(Chain::Mainnet),
            calldata,
            decoded: Box::new(DecodeResult::Empty),
            sub_legs: Vec::new(),
            self_admin: None,
        }
    }

    /// Typed data that is a SafeTx opens with Confirm dead until the call it confirms is
    /// decoded; the decoded call then lives in the owner-confirmation panel (not as a transaction
    /// of its own), and only then does the review arm.
    #[tokio::test]
    async fn safetx_typed_review_waits_for_and_attaches_its_call() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let mut call = dapp_request(
            &rig,
            &session.topic,
            "eth_signTypedData_v4",
            safe_tx_typed_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        let r = review(&s);
        assert!(r.legs_loading, "Confirm waits for the decoded call");
        assert_eq!(r.confirm_label.as_deref(), Some("Sign as Safe owner ⚠"));
        deliver_prepared(
            &mut s,
            vec![SignStep::RawTx(safe_tx_call_leg(
                SAFE_TX_TO,
                safe_tx_call_data(),
            ))],
        );
        let r = review(&s);
        assert!(!r.legs_loading && !r.confirm_disabled, "{:?}", r.error);
        assert!(r.armed_at.is_some(), "armed when Confirm went live");
        let [SignStep::WcOrigin(_), SignStep::WcTyped(t)] = r.steps.as_slice() else {
            panic!("the call is part of the typed step: {:?}", r.steps)
        };
        assert_eq!(
            t.inner_leg.as_ref().map(|l| l.calldata.clone()),
            Some(safe_tx_call_data())
        );
        assert_unanswered(&mut call).await;
    }

    /// A Safe identity signing SafeTx typed data (a nested owner confirmation for another Safe,
    /// through EIP-1271) is an owner confirmation exactly as it is from an EOA, and is labelled
    /// as one — before and after the call it confirms is attached, delegatecall or not.
    #[tokio::test]
    async fn safe_identity_signing_safetx_typed_data_is_labelled_an_owner_confirmation() {
        let rig = start_rig().await;
        let owner = PrivateKeySigner::random();
        let mut s = screen(
            vec![local_account(&owner)],
            0,
            vec![safe(0x5c, 1, &[owner.address()], vec![0], 1)],
        );
        s.test_enter_safe_mode(0);
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let mut params = safe_tx_typed_params(Address::repeat_byte(0x5c));
        params[1]["message"]["operation"] = json!(1);
        let mut call = dapp_request(&rig, &session.topic, "eth_signTypedData_v4", params);
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        assert!(matches!(
            &review(&s).action,
            SignAction::WalletConnect {
                plan: WcSignPlan::SafeMessage { .. },
                ..
            }
        ));
        assert_eq!(
            review(&s).confirm_label.as_deref(),
            Some("Sign as Safe owner ⚠")
        );
        deliver_prepared(
            &mut s,
            vec![SignStep::RawTx(safe_tx_call_leg(
                SAFE_TX_TO,
                safe_tx_call_data(),
            ))],
        );
        let r = review(&s);
        assert!(!r.confirm_disabled, "{:?}", r.error);
        assert_eq!(r.confirm_label.as_deref(), Some("Sign as Safe owner ⚠"));
        assert_unanswered(&mut call).await;
    }

    /// Reviewed == signed: a decoded call that isn't exactly the SafeTx's is never shown as what
    /// it confirms — the review can't be confirmed.
    #[test]
    fn a_call_that_isnt_the_safetxs_is_not_attached() {
        let (td, raw) = crate::walletconnect::typed::parse_typed_param(
            &safe_tx_typed_params(Address::repeat_byte(0x11))[1],
        )
        .unwrap();
        let checked =
            crate::walletconnect::typed::check_typed_data(&raw, &td, 1, Address::repeat_byte(0x11))
                .unwrap();
        let typed = || {
            SignStep::WcTyped(sign_review::TypedDataReview {
                from: Address::repeat_byte(0x11),
                net: NetworkId::Builtin(Chain::Mainnet),
                checked: checked.clone(),
                hash_mode_device: false,
                safe_label: None,
                inner_leg: None,
            })
        };
        for leg in [
            safe_tx_call_leg(Address::repeat_byte(0x01), safe_tx_call_data()),
            safe_tx_call_leg(SAFE_TX_TO, Bytes::from(vec![0xde, 0xad, 0xbe, 0xef])),
        ] {
            let mut steps = vec![typed(), SignStep::RawTx(leg)];
            assert!(attach_safe_tx_call(&mut steps).is_err());
            let SignStep::WcTyped(t) = &steps[0] else {
                unreachable!()
            };
            assert!(t.inner_leg.is_none());
        }
        let mut steps = vec![
            typed(),
            SignStep::RawTx(safe_tx_call_leg(SAFE_TX_TO, safe_tx_call_data())),
        ];
        assert_eq!(attach_safe_tx_call(&mut steps), Ok(()));
        assert_eq!(steps.len(), 1);
    }

    #[test]
    fn prepared_eoa_tx_pins_the_quote_and_labels_it() {
        let a = PrivateKeySigner::random();
        // A custom network: unverified, no simulation, no economics card.
        let plan = SendPlan {
            from: a.address(),
            recipient: Address::repeat_byte(0x40),
            token: SendToken::Call {
                data: Bytes::from(vec![0xde, 0xad]),
            },
            amount_units: U256::ZERO,
            chain: NetworkId::Custom(31_337),
        };
        let open = |balance: Option<U256>| {
            let mut s = screen(vec![local_account(&a)], 0, Vec::new());
            s.sign_review = Some(wc_review(
                wc::WcKey {
                    topic: Topic::generate(),
                    id: 4,
                },
                WcSignPlan::EoaTx {
                    plan: plan.clone(),
                    dapp_gas: None,
                    ignored: wc::IgnoredTxFields::default(),
                    quote: None,
                    quoted_at: None,
                    unconfirmed: None,
                },
            ));
            deliver_prepared(&mut s, eoa_tx_steps(&plan, balance, true));
            s
        };
        let s = open(None);
        let SignAction::WalletConnect {
            plan: WcSignPlan::EoaTx {
                quote, quoted_at, ..
            },
            ..
        } = &review(&s).action
        else {
            panic!("an EOA transaction review");
        };
        assert!(
            quote
                .as_ref()
                .is_some_and(|q| q.matches_plan(&plan) && q.nonce == 3)
        );
        assert!(quoted_at.is_some());
        assert_eq!(
            review(&s).confirm_label.as_deref(),
            Some("Sign anyway ⚠"),
            "calldata on an unverified network"
        );
        assert!(review(&s).economics.is_none());

        let poor = open(Some(U256::from(1u64)));
        assert_eq!(
            review(&poor).confirm_label.as_deref(),
            Some("Not enough ETH for gas")
        );
        assert!(review(&poor).confirm_disabled);
    }

    /// On the OP stack the economics card's fee figure says it leaves out the L1 data fee, as the
    /// Transaction Builder's does; on L1 it carries no such caveat.
    #[test]
    fn prepared_eoa_tx_economics_name_the_l1_data_fee_on_the_op_stack() {
        let a = PrivateKeySigner::random();
        let caveats = |chain: Chain| {
            let plan = SendPlan {
                from: a.address(),
                recipient: Address::repeat_byte(0x40),
                token: SendToken::Call {
                    data: Bytes::from(vec![0xde, 0xad]),
                },
                amount_units: U256::ZERO,
                chain: NetworkId::Builtin(chain),
            };
            let mut s = screen(vec![local_account(&a)], 0, Vec::new());
            s.sign_review = Some(wc_review(
                wc::WcKey {
                    topic: Topic::generate(),
                    id: 4,
                },
                WcSignPlan::EoaTx {
                    plan: plan.clone(),
                    dapp_gas: None,
                    ignored: wc::IgnoredTxFields::default(),
                    quote: None,
                    quoted_at: None,
                    unconfirmed: None,
                },
            ));
            let mut steps = eoa_tx_steps(&plan, None, false);
            if let Some(SignStep::WcTxFees(f)) = steps.last_mut() {
                f.quote.sim = SimulationResult {
                    outcome: crate::wallet::sim::SimOutcome::Success {
                        output: Bytes::new(),
                    },
                    gas_used: 45_000,
                    transfers: Vec::new(),
                    verified: true,
                    base_fee_per_gas: 1_000_000_000,
                };
            }
            deliver_prepared(&mut s, steps);
            review(&s)
                .economics
                .as_ref()
                .expect("economics on a built-in chain")
                .fee_caveats
                .clone()
        };
        for chain in [Chain::Base, Chain::Optimism] {
            assert!(
                caveats(chain).iter().any(|c| c.contains("L1 data fee")),
                "{chain:?}"
            );
        }
        assert!(caveats(Chain::Mainnet).is_empty());
    }

    #[test]
    fn prepared_eoa_tx_with_a_foreign_quote_is_not_signable() {
        let a = PrivateKeySigner::random();
        let plan = SendPlan {
            from: a.address(),
            recipient: Address::repeat_byte(0x40),
            token: SendToken::Call {
                data: Bytes::from(vec![0xde, 0xad]),
            },
            amount_units: U256::ZERO,
            chain: NetworkId::Custom(31_337),
        };
        let mut other = plan.clone();
        other.amount_units = U256::from(1u64);
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.sign_review = Some(wc_review(
            wc::WcKey {
                topic: Topic::generate(),
                id: 4,
            },
            WcSignPlan::EoaTx {
                plan,
                dapp_gas: None,
                ignored: wc::IgnoredTxFields::default(),
                quote: None,
                quoted_at: None,
                unconfirmed: None,
            },
        ));
        deliver_prepared(&mut s, eoa_tx_steps(&other, None, false));
        assert!(review(&s).confirm_disabled);
        assert!(matches!(
            &review(&s).action,
            SignAction::WalletConnect {
                plan: WcSignPlan::EoaTx { quote: None, .. },
                ..
            }
        ));
    }

    #[test]
    fn cancel_without_a_wc_review_is_a_noop() {
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        assert_eq!(s.wc_on_cancel().units(), 0);
        assert!(s.sign_review.is_none());
    }

    // ── opaque 32-byte personal_sign from a Safe owner ───────────────────

    fn opaque32_params(from: Address) -> serde_json::Value {
        json!([
            format!("0x{}", alloy::hex::encode(B256::repeat_byte(0x5e))),
            from.to_checksum(None)
        ])
    }

    /// At admission: an opaque 32-byte `personal_sign` from a Safe owner is refused (4200).
    #[tokio::test]
    async fn opaque32_from_a_safe_owner_refused_at_admission() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(
            vec![local_account(&a)],
            0,
            vec![safe(0x5a, 1, &[a.address()], vec![0], 1)],
        );
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let mut call = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            opaque32_params(a.address()),
        );
        let (generation, item) = next_request(&mut s, &rig.rt).await;
        s.handle_wc_msg(WcMsg::Stream { generation, item });
        assert_eq!(
            peer_code(&answered(&mut call).await),
            Some(wc::codes::UNSUPPORTED_METHOD)
        );
    }

    /// The opaque-hash rule is not admission-only: a request admitted before Kao knew the account owns a
    /// Safe is refused when it opens, not offered with "Sign anyway ⚠".
    #[tokio::test]
    async fn opaque32_rechecked_when_the_signer_became_a_safe_owner() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let mut call = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            opaque32_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        // Kao learns `a` owns a Safe while the request waits.
        s.safes.push(safe(0x5a, 1, &[a.address()], vec![0], 1));
        let identity = s.wc_active_identity().expect("still the EOA");
        assert!(s.wc_caps(&identity).expect("caps").safe_owner());
        s.pump_wc_queue();
        assert!(
            s.sign_review.is_none(),
            "an opaque 32-byte personal_sign from a Safe owner must be refused, not opened \
             (label {:?})",
            s.sign_review.as_ref().and_then(|r| r.confirm_label.clone())
        );
        assert_eq!(
            peer_code(&answered(&mut call).await),
            Some(wc::codes::UNSUPPORTED_METHOD)
        );
    }

    /// …and again at Confirm: Kao can learn of the Safe while the review is open.
    #[tokio::test]
    async fn opaque32_rechecked_at_confirm() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let mut call = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            opaque32_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        assert_eq!(
            review(&s).confirm_label.as_deref(),
            Some("Sign anyway ⚠"),
            "a plain EOA may sign it, with the banner"
        );
        s.safes.push(safe(0x5a, 1, &[a.address()], vec![0], 1));
        disarm(&mut s);
        s.dispatch_wc(true);
        let r = review(&s);
        assert!(r.signing_since.is_none(), "nothing may be signed");
        assert!(r.confirm_disabled, "and Confirm can't try again");
        assert!(
            r.error.as_deref().is_some_and(|e| e.contains("Safe")),
            "{:?}",
            r.error
        );
        assert_unanswered(&mut call).await;
    }

    // ── nothing dials before Connect ─────────────────────────────────────

    #[test]
    fn no_runtime_until_connect() {
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        let slot = WcSlot::new();
        let task = s.set_wc_slot(slot.clone());
        assert_eq!(task.units(), 0, "handing over the slot starts nothing");
        assert!(slot.get().is_none() && !slot.is_starting());
        assert!(s.wc_subscriptions().is_empty());
        let key = wc::WcKey {
            topic: Topic::generate(),
            id: 1,
        };
        let topic = Topic::generate();
        let me = wc::WcIdentity::Eoa {
            address: a.address(),
        };
        for o in [
            wc_app::Outcome::ReviewNow { key: key.clone() },
            wc_app::Outcome::RejectRequest { key: key.clone() },
            wc_app::Outcome::Approve {
                proposal_id: 1,
                identity: me,
                chains: vec![1],
            },
            wc_app::Outcome::RejectProposal { proposal_id: 1 },
            wc_app::Outcome::Disconnect {
                topic: topic.clone(),
            },
            wc_app::Outcome::RejectAllFrom {
                topic: topic.clone(),
            },
            wc_app::Outcome::Resume { topic },
            wc_app::Outcome::Stop,
            wc_app::Outcome::SwitchTo { identity: me, key },
            wc_app::Outcome::Close,
        ] {
            s.handle_wc_outcome(o);
        }
        s.handle_wc_msg(WcMsg::Stream {
            generation: 1,
            item: wc::WcStreamItem::Changed,
        });
        s.pump_wc_queue();
        s.wc_reconcile();
        s.wc_on_identity_changed();
        s.wc_on_cancel();
        assert!(slot.get().is_none() && !slot.is_starting());
        assert!(s.wc_subscriptions().is_empty());
    }

    #[test]
    fn invalid_uri_starts_nothing() {
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        let slot = WcSlot::new();
        s.set_wc_slot(slot.clone());
        let expired = format!(
            "wc:{}@2?relay-protocol=irn&symKey={}&expiryTimestamp=1",
            "ab".repeat(32),
            "cd".repeat(32)
        );
        for bad in [
            "",
            "not a link",
            "wc:",
            "wc:abcd@2?relay-protocol=irn&symKey=00",
            "https://example.com/?uri=wc:x",
            expired.as_str(),
        ] {
            let (task, outcome) = s.handle_wc_outcome(wc_app::Outcome::Pair {
                uri: SecretInput::from(bad),
            });
            assert_eq!(task.units(), 0, "no start task for {bad:?}");
            assert!(outcome.is_none());
            assert!(slot.get().is_none() && !slot.is_starting());
        }
    }

    // ── approve binds what was displayed ─────────────────────────────────

    #[tokio::test]
    async fn approve_refuses_when_identity_changed() {
        let rig = start_rig().await;
        let owner = PrivateKeySigner::random();
        let mut s = screen(
            vec![local_account(&owner)],
            0,
            vec![safe(0x5a, 1, &[owner.address()], vec![0], 1)],
        );
        s.set_wc_slot(rig.slot.clone());
        let resp = rig
            .dapp
            .connect(ConnectParams {
                optional_namespaces: BTreeMap::from([(
                    "eip155".to_string(),
                    ProposalNamespace::new(["eip155:1"], METHODS, ["chainChanged"]),
                )]),
                ..Default::default()
            })
            .await
            .expect("connect");
        s.handle_wc_outcome(wc_app::Outcome::Pair {
            uri: SecretInput::from(resp.uri.as_ref().expect("uri").to_string()),
        });
        feed_until(&mut s, &rig.rt, |_| rig.rt.card_proposal().is_some()).await;
        let proposal = rig.rt.card_proposal().expect("card");
        // The card showed the EOA…
        let shown = s.wc_active_identity().expect("EOA");
        let caps = s.wc_caps(&shown).expect("caps");
        let chains = wc::namespaces::plan_proposal(&proposal, &caps, &wc::chain_label)
            .verdict
            .expect("grant")
            .chains;
        // …then the user stepped into the Safe before pressing Connect.
        s.test_enter_safe_mode(0);
        s.handle_wc_outcome(wc_app::Outcome::Approve {
            proposal_id: proposal.id,
            identity: shown,
            chains: chains.clone(),
        });
        assert_eq!(
            rig.rt
                .with_book(|b| b.proposal().and_then(|c| c.error.clone()))
                .as_deref(),
            Some(CHANGED_TEXT)
        );
        assert!(
            rig.rt.with_book(|b| b.sessions().is_empty()),
            "nothing bound"
        );
        // Approving what is active now works, and binds the Safe.
        let safe_id = s.wc_active_identity().expect("the Safe");
        let safe_chains = wc::namespaces::plan_proposal(
            &proposal,
            &s.wc_caps(&safe_id).expect("caps"),
            &wc::chain_label,
        )
        .verdict
        .expect("grant")
        .chains;
        s.handle_wc_outcome(wc_app::Outcome::Approve {
            proposal_id: proposal.id,
            identity: safe_id,
            chains: safe_chains,
        });
        let session = tokio::time::timeout(ANSWER_WAIT, resp.approval)
            .await
            .expect("in time")
            .expect("approved");
        testkit::settle(|| rig.rt.with_book(|b| b.session(&session.topic).is_some())).await;
        assert_eq!(
            rig.rt
                .with_book(|b| b.session(&session.topic).map(|x| x.identity)),
            Some(safe_id)
        );
    }

    #[tokio::test]
    async fn approve_refuses_when_granted_chains_changed() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let resp = rig
            .dapp
            .connect(ConnectParams {
                optional_namespaces: BTreeMap::from([(
                    "eip155".to_string(),
                    ProposalNamespace::new(["eip155:1"], METHODS, ["chainChanged"]),
                )]),
                ..Default::default()
            })
            .await
            .expect("connect");
        s.handle_wc_outcome(wc_app::Outcome::Pair {
            uri: SecretInput::from(resp.uri.as_ref().expect("uri").to_string()),
        });
        feed_until(&mut s, &rig.rt, |_| rig.rt.card_proposal().is_some()).await;
        let proposal = rig.rt.card_proposal().expect("card");
        let identity = s.wc_active_identity().expect("EOA");
        let chains = wc::namespaces::plan_proposal(
            &proposal,
            &s.wc_caps(&identity).expect("caps"),
            &wc::chain_label,
        )
        .verdict
        .expect("grant")
        .chains;
        // The card displayed a different set of networks than Connect would now grant.
        let mut displayed = chains.clone();
        displayed.push(31_337);
        s.handle_wc_outcome(wc_app::Outcome::Approve {
            proposal_id: proposal.id,
            identity,
            chains: displayed,
        });
        assert_eq!(
            rig.rt
                .with_book(|b| b.proposal().and_then(|c| c.error.clone()))
                .as_deref(),
            Some(CHANGED_TEXT)
        );
        assert!(rig.rt.with_book(|b| b.sessions().is_empty()));
        s.handle_wc_outcome(wc_app::Outcome::Approve {
            proposal_id: proposal.id,
            identity,
            chains,
        });
        tokio::time::timeout(ANSWER_WAIT, resp.approval)
            .await
            .expect("in time")
            .expect("approved");
    }

    // ── the pump is the only opener ──────────────────────────────────────

    #[tokio::test]
    async fn pump_does_not_open_over_existing_review() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        // Another flow's review is open.
        s.sign_review = Some(SignReview::pending(
            "Send".into(),
            None,
            Vec::new(),
            None,
            1,
            SignAction::CowCancel {
                host: CowHost::Apps,
                uid: "0x01".into(),
            },
        ));
        let mut call = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        assert!(
            !review(&s).is_walletconnect(),
            "the open review is untouched"
        );
        assert_eq!(waiting(&rig.rt), 1);
        assert_unanswered(&mut call).await;
        // Once it closes, the request opens.
        s.sign_review = None;
        s.pump_wc_queue();
        assert!(review(&s).is_walletconnect());
        assert_eq!(waiting(&rig.rt), 0);
    }

    // ── other flows never strand a dapp review ───────────────────────────

    fn pool_info() -> crate::pool::PoolInfo {
        crate::pool::PoolInfo {
            chain: Chain::Mainnet,
            entrypoint: Address::repeat_byte(0x11),
            asset: Address::ZERO,
            pool: Address::repeat_byte(0x77),
            scope: privacy_pools::Field::from(1u64),
            symbol: "ETH".into(),
            decimals: 18,
            is_native: true,
            min_deposit: U256::ZERO,
            vetting_fee_bps: U256::ZERO,
            max_relay_fee_bps: U256::ZERO,
            anonymity_set: 0,
            verified: true,
        }
    }

    fn pool_account() -> privacy_pools::Account {
        privacy_pools::Account::from_master_keys(privacy_pools::MasterKeys {
            nullifier: privacy_pools::Field::from(1u64),
            secret: privacy_pools::Field::from(2u64),
        })
    }

    fn proved_ragequit() -> sign_review::PoolSign {
        sign_review::PoolSign::Ragequit {
            chain: Chain::Mainnet,
            symbol: "ETH".into(),
            pool: Address::repeat_byte(0x77),
            calldata: Bytes::from_static(&[1, 2, 3]),
        }
    }

    fn cow_cancel_review() -> SignReview {
        SignReview::pending(
            "Cancel order".into(),
            None,
            Vec::new(),
            None,
            1,
            SignAction::CowCancel {
                host: CowHost::Apps,
                uid: "0x01".into(),
            },
        )
    }

    /// A connected local EOA with one dapp `personal_sign` open in its review — opened the way
    /// production opens it, by the `update` wrapper's pump.
    async fn dapp_review_open(rig: &Rig) -> (WalletScreen, Session, DappCall, wc::WcKey) {
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, rig).await;
        let call = dapp_request(
            rig,
            &session.topic,
            "personal_sign",
            personal_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.update(Message::Tick);
        let key = review_key(&s);
        assert!(matches!(
            state(&rig.rt, &key),
            Some(wc::QueueState::InReview { .. })
        ));
        (s, session, call, key)
    }

    #[tokio::test]
    async fn relayed_withdrawal_result_leaves_an_open_dapp_review_alone() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, key) = dapp_review_open(&rig).await;
        let seq = review(&s).seq;
        // A relayed withdrawal opens no overlay, so its result has none to close.
        s.update(Message::PoolSubmitted {
            result: Ok(Some("0xabc".into())),
            signer: None,
            kind: pool_app::PoolTxKind::Withdrawal,
        });
        assert!(s.wc_review_is(&key), "the dapp's review is still up");
        assert_eq!(review(&s).seq, seq, "the very same review, not a reopen");
        assert!(matches!(
            state(&rig.rt, &key),
            Some(wc::QueueState::InReview { seq: q }) if q == seq
        ));
        assert_unanswered(&mut call).await;
    }

    #[tokio::test]
    async fn ragequit_proof_in_flight_defers_dapp_reviews() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        s.pp_account = Some(pool_account());
        let _ = s.pool_ragequit(pool_info(), 0);
        assert_eq!(
            s.wc_host_state(),
            WcHost::Deferred,
            "the proof owns the screen"
        );
        let mut call = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(a.address()),
        );
        let toasts = feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.update(Message::Tick);
        assert!(s.sign_review.is_none(), "nothing opens over the proof");
        assert!(
            toasts
                .iter()
                .any(|o| matches!(o, Outcome::Notice(t) if t == PROOF_DEFERRED_TOAST)),
            "{toasts:?}"
        );
        // The proof lands: its own review opens, and the dapp keeps waiting behind it.
        s.update(Message::PoolRagequitReady {
            result: Ok(proved_ragequit()),
        });
        assert!(matches!(review(&s).action, SignAction::PrivacyPool { .. }));
        assert_eq!(waiting(&rig.rt), 1);
        assert_unanswered(&mut call).await;
        // Once that review closes, the dapp's request opens.
        s.update(Message::SignReview(sign_review::Message::Cancel));
        assert!(review(&s).is_walletconnect());
        assert_eq!(waiting(&rig.rt), 0);
    }

    #[tokio::test]
    async fn relayed_withdrawal_proof_in_flight_defers_dapp_reviews() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        s.pp_account = Some(pool_account());
        let req = pool_app::WithdrawRequest {
            info: pool_info(),
            account: 0,
            target: Address::repeat_byte(0x42),
            amount: U256::from(1u64),
            relayer: Some("http://127.0.0.1:9".into()),
        };
        let quote = crate::pool::relayer::QuoteResponse {
            base_fee_bps: "10".into(),
            fee_bps: "10".into(),
            fee_commitment: serde_json::Value::Null,
        };
        let _ = s.pool_submit(req, quote);
        assert_eq!(s.wc_host_state(), WcHost::Deferred);
        let mut call = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.update(Message::Tick);
        assert!(s.sign_review.is_none(), "nothing opens over the proof");
        assert_unanswered(&mut call).await;
        // The withdrawal fails; the update wrapper's pump then opens the waiting request.
        s.update(Message::PoolSubmitted {
            result: Err("relayer unreachable".into()),
            signer: None,
            kind: pool_app::PoolTxKind::Withdrawal,
        });
        assert!(review(&s).is_walletconnect());
        assert_eq!(waiting(&rig.rt), 0);
    }

    #[tokio::test]
    async fn ragequit_proof_landing_under_an_open_review_says_so() {
        let rig = start_rig().await;
        // A review opened while the proof ran (here a dapp's; it could be any flow's).
        let (mut s, _session, mut call, key) = dapp_review_open(&rig).await;
        s.update(Message::PoolRagequitReady {
            result: Ok(proved_ragequit()),
        });
        assert!(s.wc_review_is(&key), "the open review is untouched");
        assert!(
            s.apps.pool_pane().error().is_some(),
            "the proved exit can't open now, and the pool pane says so"
        );
        assert_unanswered(&mut call).await;
    }

    #[tokio::test]
    async fn a_review_that_loses_its_overlay_goes_back_to_the_queue() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, key) = dapp_review_open(&rig).await;
        let seq = review(&s).seq;
        // Another flow's overlay replaces the review without releasing or answering it.
        s.sign_review = Some(cow_cancel_review());
        s.update(Message::Tick);
        assert_eq!(
            state(&rig.rt, &key),
            Some(wc::QueueState::Waiting),
            "released, so the pane offers Review and Reject again"
        );
        assert_eq!(s.wc_badge(), 1);
        // Once that overlay closes, the pump reopens the request.
        s.update(Message::SignReview(sign_review::Message::Cancel));
        assert!(s.wc_review_is(&key));
        assert_ne!(review(&s).seq, seq, "a fresh review");
        assert_unanswered(&mut call).await;
    }

    #[tokio::test]
    async fn stranded_request_can_be_rejected_from_the_pane() {
        let rig = start_rig().await;
        let (mut s, session, mut call, key) = dapp_review_open(&rig).await;
        // While its overlay shows it, the row can't answer it.
        s.handle_wc_outcome(wc_app::Outcome::RejectRequest { key: key.clone() });
        assert!(s.wc_review_is(&key));
        assert_unanswered(&mut call).await;
        // Strand it: the overlay goes, the request stays under review (no update, so no pump).
        s.sign_review = None;
        s.wc_mirror();
        let row = s
            .apps
            .wc_pane()
            .update(wc_app::Message::RejectRequest { key: key.clone() })
            .expect("the row's Reject reaches the coordinator");
        s.handle_wc_outcome(row);
        assert_eq!(
            peer_code(&answered(&mut call).await),
            Some(wc::codes::USER_REJECTED)
        );
        // "Reject all" answers a stranded request too.
        let mut second = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(s.address),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.update(Message::Tick);
        assert!(review(&s).is_walletconnect());
        s.sign_review = None;
        s.wc_mirror();
        let all = s
            .apps
            .wc_pane()
            .update(wc_app::Message::RejectAllFrom {
                topic: session.topic.clone(),
            })
            .expect("Reject all reaches the coordinator");
        s.handle_wc_outcome(all);
        assert_eq!(
            peer_code(&answered(&mut second).await),
            Some(wc::codes::USER_REJECTED)
        );
    }

    #[tokio::test]
    async fn swap_results_never_touch_a_dapp_review() {
        let rig = start_rig().await;
        // A swap result landing on a dashboard whose overlay is a dapp's (one rebuilt under the
        // swap): neither outcome is the dapp review's to take.
        let (mut s, _session, mut call, key) = dapp_review_open(&rig).await;
        let seq = review(&s).seq;
        s.update(Message::Signed {
            tag: SignTag::Cow {
                host: CowHost::Apps,
            },
            signer: None,
            result: Err("placement failed".into()),
        });
        assert!(s.wc_review_is(&key));
        assert!(
            review(&s).error.is_none(),
            "the swap's error isn't pinned on the dapp's review"
        );
        let order = TrackedOrder {
            uid: "0x01".into(),
            chain: Chain::Base,
            owner: s.address,
            kind: crate::cow::order::OrderKind::Sell,
            sell_token: Address::repeat_byte(0x01),
            buy_token: Address::repeat_byte(0x02),
            sell_symbol: "USDC".into(),
            buy_symbol: "DAI".into(),
            sell_amount: U256::from(1_000_000u64),
            buy_amount: U256::from(990_000u64),
            sell_decimals: 6,
            buy_decimals: 18,
            valid_to: u32::MAX,
            status: OrderStatus::Open,
            executed: None,
            is_ethflow: false,
        };
        s.update(Message::Signed {
            tag: SignTag::Cow {
                host: CowHost::Apps,
            },
            signer: None,
            result: Ok(SignOutcome::Order(Box::new(order))),
        });
        assert!(s.wc_review_is(&key));
        assert_eq!(review(&s).seq, seq, "the very same review, not a reopen");
        assert_unanswered(&mut call).await;
    }

    #[tokio::test]
    async fn pump_skips_inactive_identity() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(
            vec![local_account(&a)],
            0,
            vec![safe(0x5a, 1, &[a.address()], vec![0], 1)],
        );
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        // The user is looking at the Safe now; the session stays bound to the EOA.
        s.activate_safe(0);
        s.wc_on_identity_changed();
        let mut call = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(a.address()),
        );
        let toasts = feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        assert!(
            toasts
                .iter()
                .any(|o| matches!(o, Outcome::Notice(t) if t.contains("is waiting for"))),
            "the user is told which identity the dapp waits for: {toasts:?}"
        );
        s.pump_wc_queue();
        assert!(
            s.sign_review.is_none(),
            "never opened for an inactive identity"
        );
        assert_unanswered(&mut call).await;
        s.exit_safe_mode();
        s.wc_on_identity_changed();
        s.pump_wc_queue();
        assert!(review(&s).is_walletconnect());
    }

    #[tokio::test]
    async fn pump_defers_while_modal_open() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        s.modal = Modal::Receive(ReceivePane::new(a.address()));
        let _call = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(a.address()),
        );
        let toasts = feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        assert!(
            toasts
                .iter()
                .any(|o| matches!(o, Outcome::Notice(t) if t == DEFERRED_TOAST)),
            "{toasts:?}"
        );
        s.pump_wc_queue();
        assert!(s.sign_review.is_none(), "a modal is never hijacked");
        s.modal = Modal::None;
        s.pump_wc_queue();
        assert!(review(&s).is_walletconnect(), "opens once the host frees");
    }

    #[tokio::test]
    async fn pump_respects_paused_session() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let mut calls: Vec<DappCall> = (0..wc::REJECT_STREAK_PAUSE)
            .map(|_| {
                dapp_request(
                    &rig,
                    &session.topic,
                    "personal_sign",
                    personal_params(a.address()),
                )
            })
            .collect();
        let n = calls.len();
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == n).await;
        for key in queued_keys(&rig.rt) {
            s.handle_wc_outcome(wc_app::Outcome::RejectRequest { key });
        }
        for call in &mut calls {
            assert_eq!(
                peer_code(&answered(call).await),
                Some(wc::codes::USER_REJECTED)
            );
        }
        let _next = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        assert!(
            s.sign_review.is_none(),
            "auto-open is paused after the streak"
        );
        s.handle_wc_outcome(wc_app::Outcome::Resume {
            topic: session.topic.clone(),
        });
        assert!(review(&s).is_walletconnect(), "Resume reopens the queue");
    }

    #[tokio::test]
    async fn pump_skips_old_requests_unless_manual() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let _call = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(a.address()),
        );
        let (generation, item) = next_request(&mut s, &rig.rt).await;
        let wc::WcStreamItem::Request { req, .. } = item else {
            unreachable!("next_request returns a request");
        };
        // Received eleven minutes ago (the dapp still waits: its own expiry is later).
        let old = wc::now_secs().saturating_sub(wc::AUTO_OPEN_MAX_AGE_SECS + 60);
        s.handle_wc_msg(WcMsg::Stream {
            generation,
            item: wc::WcStreamItem::Request {
                req,
                received_at: old,
            },
        });
        assert_eq!(waiting(&rig.rt), 1);
        s.pump_wc_queue();
        assert!(s.sign_review.is_none(), "no stale pop-up");
        let key = queued_keys(&rig.rt).pop().expect("queued");
        s.handle_wc_outcome(wc_app::Outcome::ReviewNow { key: key.clone() });
        assert_eq!(review_key(&s), key, "[Review] opens it on demand");
    }

    /// Feed the next `count` requests as received `age_secs` ago (the dapp still waits: its own
    /// expiry is later).
    async fn feed_aged(s: &mut WalletScreen, rt: &WcRuntime, count: usize, age_secs: u64) {
        for _ in 0..count {
            let (generation, item) = next_request(s, rt).await;
            let wc::WcStreamItem::Request { req, .. } = item else {
                unreachable!("next_request returns a request");
            };
            s.handle_wc_msg(WcMsg::Stream {
                generation,
                item: wc::WcStreamItem::Request {
                    req,
                    received_at: wc::now_secs().saturating_sub(age_secs),
                },
            });
        }
    }

    /// [Switch to ⟨account⟩] on a request too old to open by itself: the click picked that
    /// request, so the dashboard rebuilt for the account opens it — that one only, and once.
    #[tokio::test]
    async fn switch_to_another_account_opens_the_request_it_was_clicked_on() {
        let rig = start_rig().await;
        let (a, b) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let accounts = vec![local_account(&a), local_account(&b)];
        let mut on_b = screen(accounts.clone(), 1, Vec::new());
        on_b.set_wc_slot(rig.slot.clone());
        let session = connect(&mut on_b, &rig).await;
        drop(on_b);
        let mut s = screen(accounts.clone(), 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let _calls: Vec<DappCall> = (0..2)
            .map(|_| {
                dapp_request(
                    &rig,
                    &session.topic,
                    "personal_sign",
                    personal_params(b.address()),
                )
            })
            .collect();
        feed_aged(&mut s, &rig.rt, 2, wc::AUTO_OPEN_MAX_AGE_SECS + 60).await;
        let keys = queued_keys(&rig.rt);
        assert_eq!(keys.len(), 2);
        // The later one, so the queue's own order can't pass for the pick.
        let picked = keys[1].clone();
        s.apps.open_wc();
        let (_, outcome) = s.handle_wc_outcome(wc_app::Outcome::SwitchTo {
            identity: wc::WcIdentity::Eoa {
                address: b.address(),
            },
            key: picked.clone(),
        });
        assert!(matches!(outcome, Some(Outcome::Switch(1))), "{outcome:?}");
        drop(s);
        // App rebuilds the dashboard for B.
        let mut s = screen(accounts.clone(), 1, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        assert_eq!(review_key(&s), picked, "the clicked request opens");
        s.wc_on_cancel();
        assert!(
            s.sign_review.is_none(),
            "the other old request waits for [Review]"
        );
        drop(s);
        let mut s = screen(accounts, 1, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        assert!(s.sign_review.is_none(), "the pick was spent");
    }

    /// The same in place — out of a Safe, back to the account the request is for.
    #[tokio::test]
    async fn switch_to_in_place_opens_the_request_it_was_clicked_on() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(
            vec![local_account(&a)],
            0,
            vec![safe(0x5a, 1, &[a.address()], vec![0], 1)],
        );
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        s.activate_safe(0);
        s.wc_on_identity_changed();
        let _call = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(a.address()),
        );
        feed_aged(&mut s, &rig.rt, 1, wc::AUTO_OPEN_MAX_AGE_SECS + 60).await;
        let key = queued_keys(&rig.rt).pop().expect("queued");
        s.handle_wc_outcome(wc_app::Outcome::SwitchTo {
            identity: wc::WcIdentity::Eoa {
                address: a.address(),
            },
            key: key.clone(),
        });
        assert!(s.active_safe.is_none());
        s.wc_on_identity_changed();
        s.pump_wc_queue();
        assert_eq!(review_key(&s), key);
    }

    /// A session names its identity as the wallet names it now, not as it did at approval: once
    /// an account before it is removed (and another added), the toast and the pane follow.
    #[tokio::test]
    async fn a_sessions_identity_is_named_as_the_wallet_names_it_now() {
        let rig = start_rig().await;
        let keys: Vec<PrivateKeySigner> = (0..4).map(|_| PrivateKeySigner::random()).collect();
        let (a, b, c, d) = (&keys[0], &keys[1], &keys[2], &keys[3]);
        let mut on_c = screen(
            vec![local_account(a), local_account(b), local_account(c)],
            2,
            Vec::new(),
        );
        on_c.set_wc_slot(rig.slot.clone());
        let session = connect(&mut on_c, &rig).await;
        drop(on_c);
        // B removed, D added: C is "Account 2" now, and "Account 3" is D.
        let mut s = screen(
            vec![local_account(a), local_account(c), local_account(d)],
            0,
            Vec::new(),
        );
        s.set_wc_slot(rig.slot.clone());
        let _call = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(c.address()),
        );
        let toasts: Vec<String> = feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1)
            .await
            .into_iter()
            .filter_map(|o| match o {
                Outcome::Notice(t) => Some(t),
                _ => None,
            })
            .collect();
        assert!(
            toasts.iter().any(|t| t.contains("waiting for Account 2")),
            "{toasts:?}"
        );
        assert!(
            !toasts.iter().any(|t| t.contains("Account 3")),
            "{toasts:?}"
        );
        let texts = pane_texts(&mut s);
        for now in [
            "Switch to Account 2".to_string(),
            format!("for Account 2 · {}", wc::chain_label(1)),
        ] {
            assert!(texts.contains(&now), "{now}: {texts:?}");
        }
        assert!(
            texts.iter().any(|t| t.starts_with("as Account 2 · ")),
            "{texts:?}"
        );
        assert!(
            !texts.iter().any(|t| t == "Switch to Account 3"
                || t.starts_with("for Account 3")
                || t.starts_with("as Account 3")),
            "{texts:?}"
        );
        // A rename shows at once.
        s.accounts[1].set_name(Some("Savings".into()));
        s.reseed_accounts_pane();
        let texts = pane_texts(&mut s);
        assert!(texts.iter().any(|t| t == "Switch to Savings"), "{texts:?}");
    }

    #[tokio::test]
    async fn pump_defers_safe_tx_while_queue_loading() {
        let rig = start_rig().await;
        let owner = PrivateKeySigner::random();
        let safe_addr = Address::from([0x5a; 20]);
        let mut s = screen(
            vec![local_account(&owner)],
            0,
            vec![safe(0x5a, 1, &[owner.address()], vec![0], 1)],
        );
        s.test_enter_safe_mode(0);
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        s.safe_pending_loading = true;
        let _tx = dapp_request(
            &rig,
            &session.topic,
            "eth_sendTransaction",
            tx_params(safe_addr),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        assert!(s.sign_review.is_none(), "a Safe tx waits for the queue");
        // Messages aren't deferred.
        let _msg = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(safe_addr),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 2).await;
        s.pump_wc_queue();
        assert!(matches!(
            &review(&s).action,
            SignAction::WalletConnect {
                plan: WcSignPlan::SafeMessage { .. },
                ..
            }
        ));
        s.wc_on_cancel();
        assert!(s.sign_review.is_none(), "still deferred after the message");
        s.safe_pending_loading = false;
        s.pump_wc_queue();
        assert!(matches!(
            &review(&s).action,
            SignAction::WalletConnect {
                plan: WcSignPlan::SafeTx { .. },
                ..
            }
        ));
    }

    /// The `update` wrapper pumps after every message — unless the outcome is about to replace
    /// the dashboard (App drops its tasks, and the review would die with the screen).
    #[tokio::test]
    async fn pump_not_run_on_leaving_outcome() {
        let rig = start_rig().await;
        let (a, b) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let mut s = screen(vec![local_account(&a), local_account(&b)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        s.modal = Modal::AccountDropdown(AccountDropdown::new());
        let _call = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        // Picking another account frees the host — and replaces the dashboard.
        let (_, outcome) = s.update(Message::AccountDropdown(account_dropdown::Message::Select(
            1,
        )));
        assert!(matches!(outcome, Some(Outcome::Switch(1))));
        assert!(
            s.sign_review.is_none(),
            "no review opens on a dashboard about to go"
        );
        assert_eq!(waiting(&rig.rt), 1);
        // The same click on the same account stays on this dashboard: the wrapper pumps.
        s.modal = Modal::AccountDropdown(AccountDropdown::new());
        let (_, outcome) = s.update(Message::AccountDropdown(account_dropdown::Message::Select(
            0,
        )));
        assert!(outcome.is_none());
        assert!(review(&s).is_walletconnect());
    }

    // ── Cancel answers the dapp ──────────────────────────────────────────

    #[tokio::test]
    async fn cancel_wc_review_answers_4001() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let mut call = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        let key = review_key(&s);
        s.wc_on_cancel();
        assert!(s.sign_review.is_none());
        assert_eq!(
            peer_code(&answered(&mut call).await),
            Some(wc::codes::USER_REJECTED)
        );
        assert_eq!(state(&rig.rt, &key), None, "answered exactly once and gone");
    }

    #[tokio::test]
    async fn cancel_after_prepare_failure_answers_32603() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let mut call = dapp_request(
            &rig,
            &session.topic,
            "eth_sendTransaction",
            tx_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        // The prepare fails: the overlay stays up, showing why, with Confirm disabled.
        let detail = "gas estimation failed: execution reverted (http://rpc.example/key)";
        let seq = review(&s).seq;
        s.update(Message::SignReviewPrepared {
            seq,
            steps: Err(detail.into()),
        });
        let r = review(&s);
        assert_eq!(r.error.as_deref(), Some(detail));
        assert!(r.confirm_disabled && !r.legs_loading);
        s.wc_on_cancel();
        let Err(wallet_connect::Error::Peer(e)) = answered(&mut call).await else {
            panic!("the dapp gets an error");
        };
        assert_eq!(e.code, wc::codes::INTERNAL);
        assert_eq!(e.message, "The wallet could not complete the request.");
        assert!(
            !e.message.contains("rpc.example"),
            "the detail never reaches a dapp"
        );
    }

    /// A dapp transaction whose prepare failed isn't a dead end: "Re-check" (live although
    /// Confirm is blocked — it signs nothing) runs the prepare again in place, under a new seq,
    /// with the request still InReview and unanswered.
    #[tokio::test]
    async fn failed_tx_prepare_offers_a_recheck_that_prepares_again() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let mut call = dapp_request(
            &rig,
            &session.topic,
            "eth_sendTransaction",
            tx_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        let key = review_key(&s);
        let seq = review(&s).seq;
        s.update(Message::SignReviewPrepared {
            seq,
            steps: Err("estimate_gas: execution reverted".into()),
        });
        let r = review(&s);
        assert!(r.confirm_disabled && !r.legs_loading);
        assert_eq!(r.secondary_label.as_deref(), Some(RECHECK_LABEL));
        assert!(r.secondary_unblocked);
        assert_eq!(s.dispatch_wc(true).units(), 0, "Confirm stays blocked");
        s.update(Message::SignReview(sign_review::Message::Secondary));
        let r = review(&s);
        assert_ne!(r.seq, seq, "a new seq retires the failed prepare");
        assert!(r.legs_loading && !r.confirm_disabled && r.error.is_none());
        assert!(r.secondary_label.is_none() && !r.secondary_unblocked);
        assert!(r.note.as_deref().is_some_and(|n| n.contains(RECHECK_NOTE)));
        assert_eq!(
            state(&rig.rt, &key),
            Some(wc::QueueState::InReview { seq: r.seq })
        );
        // The second prepare lands: the review is signable again.
        let plan = match &r.action {
            SignAction::WalletConnect {
                plan: WcSignPlan::EoaTx { plan, .. },
                ..
            } => plan.clone(),
            _ => panic!("an EOA transaction review"),
        };
        deliver_prepared(&mut s, eoa_tx_steps(&plan, None, false));
        disarm(&mut s);
        assert_eq!(review(&s).confirm_label.as_deref(), Some("Sign & send"));
        assert_unanswered(&mut call).await;
    }

    /// Once the request is gone, "Re-check" has nothing left to prepare: it goes dead with
    /// Confirm.
    #[tokio::test]
    async fn recheck_goes_dead_with_the_request() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let _call = dapp_request(
            &rig,
            &session.topic,
            "eth_sendTransaction",
            tx_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        let key = review_key(&s);
        let seq = review(&s).seq;
        s.update(Message::SignReviewPrepared {
            seq,
            steps: Err("estimate_gas: execution reverted".into()),
        });
        assert!(review(&s).secondary_unblocked);
        s.wc_request_gone(key, wc::GoneReason::DappDisconnected);
        let r = review(&s);
        assert!(r.confirm_disabled && !r.secondary_unblocked);
        assert_eq!(s.wc_recheck().units(), 0);
    }

    /// A quote that took the dapp's gas because Kao's node couldn't estimate the call reads as a
    /// deliberate override.
    #[tokio::test]
    async fn prepared_tx_with_a_failed_estimate_reads_sign_anyway() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let _call = dapp_request(
            &rig,
            &session.topic,
            "eth_sendTransaction",
            tx_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        let plan = match &review(&s).action {
            SignAction::WalletConnect {
                plan: WcSignPlan::EoaTx { plan, .. },
                ..
            } => plan.clone(),
            _ => panic!("an EOA transaction review"),
        };
        let mut steps = eoa_tx_steps(&plan, None, false);
        if let Some(SignStep::WcTxFees(f)) = steps.last_mut() {
            f.estimate_failed = Some("execution reverted".into());
            f.gas_note = wc::GasNote::DappUnestimated { dapp: 50_000 };
        }
        deliver_prepared(&mut s, steps);
        let r = review(&s);
        assert_eq!(r.confirm_label.as_deref(), Some("Sign anyway ⚠"));
        assert!(!r.confirm_disabled);
    }

    /// The origin card carries Kao's own deadline for the request alongside the dapp's (which may
    /// be hours later), so it can count down the one that actually ends the review.
    #[tokio::test]
    async fn origin_card_carries_kaos_deadline_beside_a_later_dapp_expiry() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let now = wc::now_secs();
        let (dapp, topic) = (rig.dapp.clone(), session.topic.clone());
        let mut req = SessionRequest::new("personal_sign", personal_params(a.address()));
        req.expiry_timestamp = Some(now + 7_200);
        let _call = tokio::spawn(async move { dapp.request(&topic, "eip155:1", req).await });
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        let key = review_key(&s);
        let card = review(&s)
            .steps
            .iter()
            .find_map(|st| match st {
                SignStep::WcOrigin(o) => Some(o.clone()),
                _ => None,
            })
            .expect("origin card");
        let (dapp_deadline, kao_deadline) = rig
            .rt
            .with_book(|b| b.request(&key).map(|q| (q.dapp_deadline, q.kao_deadline)))
            .expect("queued");
        assert_eq!(card.kao_deadline, kao_deadline);
        assert_eq!(card.dapp_deadline, dapp_deadline);
        assert!(
            card.kao_deadline < card.dapp_deadline.expect("the dapp's expiry"),
            "Kao's deadline is the earlier one here"
        );
    }

    #[tokio::test]
    async fn cancel_after_request_gone_answers_nothing() {
        let mut rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let mut call = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        let key = review_key(&s);
        rig.dapp
            .disconnect(&session.topic)
            .await
            .expect("dapp disconnects");
        feed_until(&mut s, &rig.rt, |s| {
            s.sign_review.as_ref().is_some_and(|r| r.confirm_disabled)
        })
        .await;
        assert_eq!(
            review(&s).error.as_deref(),
            Some(wc::GoneReason::DappDisconnected.sentence())
        );
        s.wc_on_cancel();
        assert!(s.sign_review.is_none(), "Close just closes");
        assert_eq!(state(&rig.rt, &key), None);
        if let Ok(joined) = tokio::time::timeout(SILENCE, &mut call).await {
            let r = joined.expect("dapp task");
            assert!(
                !matches!(peer_code(&r), Some(c) if c == wc::codes::USER_REJECTED || c == wc::codes::INTERNAL),
                "no answer is sent for a request that is gone: {r:?}"
            );
        }
        // The dapp saw its own disconnect, nothing else.
        let _ = &mut rig.dapp_events;
    }

    // ── a removed identity's sessions end ────────────────────────────────

    #[tokio::test]
    async fn removing_a_safe_disconnects_its_sessions() {
        let mut rig = start_rig().await;
        let owner = PrivateKeySigner::random();
        let mut s = screen(
            vec![local_account(&owner)],
            0,
            vec![safe(0x5a, 1, &[owner.address()], vec![0], 1)],
        );
        s.test_enter_safe_mode(0);
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        // Settings › Safes › Remove: App pushes the list without it; the arm reconciles.
        s.update(Message::SafesUpdated(Vec::new()));
        let topic = session.topic.clone();
        dapp_event(
            &mut rig.dapp_events,
            |e| matches!(e, SignEvent::SessionDelete { topic: t, .. } if *t == topic),
        )
        .await;
        assert!(rig.rt.with_book(|b| b.session(&topic).is_none()));
    }

    // ── Safe answers ─────────────────────────────────────────────────────

    /// The active Safe's queue read in flight lands with `result`.
    fn queue_read_lands(
        s: &mut WalletScreen,
        safe: Address,
        result: Result<Vec<crate::safe::service::PendingSafeTx>, String>,
    ) {
        let (_, seq) = s.safe_pending_reading.expect("a queue read in flight");
        s.update(Message::SafePendingFetched {
            safe,
            chain: Chain::Mainnet,
            seq,
            result,
        });
    }

    async fn safe_tx_review(
        rig: &Rig,
        threshold: u32,
    ) -> (WalletScreen, Session, DappCall, Address) {
        safe_tx_review_over(rig, threshold, None).await
    }

    /// [`safe_tx_review`], opened after the Safe's queue read failed with `queue_error` (when
    /// given): Kao doesn't know which nonces co-signers already hold.
    async fn safe_tx_review_over(
        rig: &Rig,
        threshold: u32,
        queue_error: Option<&str>,
    ) -> (WalletScreen, Session, DappCall, Address) {
        let owner = PrivateKeySigner::random();
        let safe_addr = Address::from([0x5a; 20]);
        let mut owners = vec![owner.address()];
        owners.extend((1..threshold).map(|i| Address::repeat_byte(0x70 + i as u8)));
        let mut s = screen(
            vec![local_account(&owner)],
            0,
            vec![safe(0x5a, 1, &owners, vec![0], threshold)],
        );
        s.test_enter_safe_mode(0);
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, rig).await;
        if let Some(e) = queue_error {
            s.safe_pending_loading = false;
            s.safe_pending_error = Some(e.to_string());
        }
        let call = dapp_request(
            rig,
            &session.topic,
            "eth_sendTransaction",
            tx_params(safe_addr),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        assert_eq!(
            safe_plan(&s).0.queued_nonces.is_none(),
            queue_error.is_some(),
            "the review knows whether the queue was read"
        );
        deliver_prepared(&mut s, vec![safe_exec_step(safe_addr, 5, 5, 0)]);
        disarm(&mut s);
        (s, session, call, safe_addr)
    }

    /// The Safe's queue couldn't be read when the review opened. Proposing would pin a nonce a
    /// co-signer may already hold, so it isn't offered — the note says why, and no longer
    /// describes proposing; executing takes the live nonce and stays. A propose that reaches the
    /// dispatch anyway is refused without taking Execute down with it.
    #[tokio::test]
    async fn an_unread_safe_queue_withholds_propose_but_keeps_execute() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, _) =
            safe_tx_review_over(&rig, 1, Some("HTTP 429 Too Many Requests")).await;
        let r = review(&s);
        assert_eq!(r.confirm_label.as_deref(), Some("Sign & execute now"));
        assert_eq!(
            r.secondary_label, None,
            "no propose against an unread queue"
        );
        assert!(!r.confirm_disabled && r.error.is_none(), "{:?}", r.error);
        assert_withheld_propose_note(r);

        assert_eq!(s.dispatch_wc(false).units(), 0, "nothing is proposed");
        let r = review(&s);
        assert!(r.signing_since.is_none());
        assert!(
            r.error
                .as_deref()
                .is_some_and(|e| e.contains("pending queue")),
            "{:?}",
            r.error
        );
        assert!(!r.confirm_disabled, "Execute survives the refused propose");

        disarm(&mut s);
        assert!(s.dispatch_wc(true).units() > 0, "executing still runs");
        assert!(matches!(
            review(&s).signing_progress,
            Some(SigningKind::SafeExecute { .. })
        ));
        assert_unanswered(&mut call).await;
    }

    /// The note on an executable review whose Propose was withheld: why, and nothing on what a
    /// proposal would answer the dapp — said once, however often the fork was relabelled.
    fn assert_withheld_propose_note(r: &SignReview) {
        let note = r.note.as_deref().unwrap_or_default();
        assert!(note.contains("pending queue"), "{note}");
        assert!(!note.contains("If proposed"), "{note}");
        assert!(note.contains("If executed now"), "{note}");
        assert_eq!(note.matches("pending queue").count(), 1, "{note}");
    }

    /// The same below the threshold, where proposing is the only action: it can't be taken
    /// safely, so Confirm is off and says why, and Cancel tells the dapp Kao failed.
    #[tokio::test]
    async fn an_unread_safe_queue_blocks_a_propose_only_review() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, _) =
            safe_tx_review_over(&rig, 2, Some("HTTP 429 Too Many Requests")).await;
        let r = review(&s);
        assert!(r.confirm_disabled, "{:?}", r.confirm_label);
        assert_eq!(r.secondary_label, None);
        assert!(
            r.error
                .as_deref()
                .is_some_and(|e| e.contains("pending queue")),
            "{:?}",
            r.error
        );
        assert_eq!(s.dispatch_wc(true).units(), 0);
        assert!(review(&s).signing_since.is_none());
        assert_unanswered(&mut call).await;
        s.wc_on_cancel();
        assert_eq!(
            peer_code(&answered(&mut call).await),
            Some(wc::codes::INTERNAL)
        );
    }

    /// An owner's refused EIP-712 prompt relabels the fork for `eth_sign`; against an unread
    /// queue that still offers no propose.
    #[tokio::test]
    async fn an_unread_safe_queue_withholds_propose_after_an_eth_sign_fallback() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, _) =
            safe_tx_review_over(&rig, 1, Some("HTTP 429 Too Many Requests")).await;
        let key = review_key(&s);
        assert!(s.dispatch_wc(true).units() > 0);
        rig.rt.note_failure(&key, wc::FailureClass::Eip712Refused);
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key.clone(),
                kind: WcSignKind::SafeExecute,
            },
            signer: None,
            result: Err("rejected on your hardware wallet".into()),
        });
        let r = review(&s);
        assert_eq!(
            r.confirm_label.as_deref(),
            Some("Execute — sign as a message ⚠")
        );
        assert_eq!(r.secondary_label, None);
        assert!(!r.confirm_disabled);
        assert_withheld_propose_note(r);
        assert_unanswered(&mut call).await;
    }

    /// Execution refused by its dry run leaves proposing as the only action — which an unread
    /// queue rules out too: Confirm is off, and the review says both why.
    #[tokio::test]
    async fn an_unread_safe_queue_blocks_propose_after_execute_is_refused() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, _) =
            safe_tx_review_over(&rig, 1, Some("HTTP 429 Too Many Requests")).await;
        let key = review_key(&s);
        assert!(s.dispatch_wc(true).units() > 0);
        rig.rt.note_failure(&key, wc::FailureClass::ExecuteRefused);
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key.clone(),
                kind: WcSignKind::SafeExecute,
            },
            signer: None,
            result: Err(
                "This transaction would revert right now: ERC20: insufficient allowance.".into(),
            ),
        });
        let r = review(&s);
        assert!(r.confirm_disabled && r.signing_since.is_none());
        let e = r.error.as_deref().unwrap_or_default();
        assert!(e.contains("revert") && e.contains("pending queue"), "{e}");
        disarm(&mut s);
        assert_eq!(s.dispatch_wc(true).units(), 0, "nothing is proposed");
        assert_unanswered(&mut call).await;
    }

    #[tokio::test]
    async fn safe_propose_answers_safe_tx_hash() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, _) = safe_tx_review(&rig, 1).await;
        let key = review_key(&s);
        // The secondary action: propose to co-signers.
        s.dispatch_wc(false);
        assert!(matches!(
            review(&s).signing_progress,
            Some(SigningKind::SafePropose { .. })
        ));
        let safe_tx_hash = B256::repeat_byte(0x5e);
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key.clone(),
                kind: WcSignKind::SafePropose,
            },
            signer: None,
            result: Ok(SignOutcome::SafeProposed(safe_tx_hash)),
        });
        s.wc_on_signed(
            key.clone(),
            WcSignKind::SafePropose,
            Ok(SignOutcome::SafeProposed(safe_tx_hash)),
        );
        assert_eq!(
            answered(&mut call).await.expect("a result"),
            json!(format!("{safe_tx_hash:#x}"))
        );
        assert!(s.sign_review.is_none(), "the overlay closes");
        assert!(
            !s.order_op_in_flight,
            "the busy flag cleared in the shared tail"
        );
    }

    #[tokio::test]
    async fn safe_execute_answers_executor_hash() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, _) = safe_tx_review(&rig, 1).await;
        let key = review_key(&s);
        s.dispatch_wc(true);
        assert!(matches!(
            review(&s).signing_progress,
            Some(SigningKind::SafeExecute { .. })
        ));
        let executor_hash = TxHash::repeat_byte(0xe1);
        s.wc_on_signed(
            key,
            WcSignKind::SafeExecute,
            Ok(SignOutcome::Tx(executor_hash)),
        );
        assert_eq!(
            answered(&mut call).await.expect("a result"),
            json!(format!("{executor_hash:#x}"))
        );
        assert!(s.sign_review.is_none());
    }

    /// The dapp's Safe execution is sent and paid for by an account the review names before
    /// Confirm; if that account is no longer the one the dispatch would use, nothing is signed.
    #[tokio::test]
    async fn safe_execute_names_its_sender_and_refuses_another() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, _) = safe_tx_review(&rig, 1).await;
        let owner = s.address;
        let named = review(&s).steps.iter().find_map(|st| match st {
            SignStep::SafeExec(x) => x.executor.clone(),
            _ => None,
        });
        assert_eq!(
            named.map(|e| e.address),
            Some(owner),
            "the Local signing owner sends it"
        );
        // The review's sender drifts from the dispatch's.
        if let Some(r) = s.sign_review.as_mut() {
            for st in &mut r.steps {
                if let SignStep::SafeExec(x) = st
                    && let Some(e) = x.executor.as_mut()
                {
                    e.address = Address::repeat_byte(0x99);
                }
            }
        }
        assert_eq!(s.dispatch_wc(true).units(), 0, "nothing is signed");
        let r = review(&s);
        assert!(r.confirm_disabled && r.error.is_some(), "{:?}", r.error);
        assert!(r.signing_since.is_none());
        assert_unanswered(&mut call).await;
    }

    /// An owner's Ledger refused the EIP-712 prompt for a Safe message (declined, or Blind signing
    /// off). Nothing else is asked of it: the review comes back offering the same Safe hash as a
    /// personal message, shows the digest the device will display, and only the next Confirm —
    /// the user's choice — signs that way.
    #[tokio::test]
    async fn a_refused_eip712_owner_prompt_offers_eth_sign_as_an_explicit_choice() {
        let rig = start_rig().await;
        let owner = PrivateKeySigner::random();
        let safe_addr = Address::from([0x5a; 20]);
        let mut s = screen(
            vec![local_account(&owner)],
            0,
            vec![safe(0x5a, 1, &[owner.address()], vec![0], 1)],
        );
        s.test_enter_safe_mode(0);
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let mut call = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(safe_addr),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        disarm(&mut s);
        let key = review_key(&s);
        let pin = match &review(&s).action {
            SignAction::WalletConnect {
                plan: WcSignPlan::SafeMessage { pin, .. },
                ..
            } => *pin,
            _ => panic!("a Safe message review"),
        };
        assert_eq!(
            wc_owner_sig_mode(review(&s)),
            crate::safe::tx::OwnerSigMode::Eip712,
            "no automatic eth_sign"
        );
        assert!(s.dispatch_wc(true).units() > 0);
        rig.rt.note_failure(&key, wc::FailureClass::Eip712Refused);
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key.clone(),
                kind: WcSignKind::SafeMessage,
            },
            signer: None,
            result: Err("rejected on your hardware wallet".into()),
        });
        let r = review(&s);
        assert_eq!(r.owner_eth_sign, Some(OwnerEthSign::of(pin)));
        assert_eq!(
            r.owner_eth_sign.map(|f| f.eip191),
            Some(alloy::primitives::eip191_hash_message(pin)),
            "the digest the device shows for a 32-byte personal message"
        );
        assert_eq!(r.confirm_label.as_deref(), Some("Sign as a message ⚠"));
        assert!(!r.confirm_disabled && r.signing_since.is_none());
        assert!(r.error.is_some() && r.armed_at.is_some());
        assert_eq!(
            state(&rig.rt, &key),
            Some(wc::QueueState::InReview { seq: r.seq })
        );
        assert_eq!(wc_owner_sig_mode(r), crate::safe::tx::OwnerSigMode::EthSign);
        disarm(&mut s);
        assert!(
            s.dispatch_wc(true).units() > 0,
            "the user's second Confirm signs"
        );
        assert_unanswered(&mut call).await;
    }

    /// The same for a dapp's Safe transaction: both actions stay, each saying how it now signs.
    #[test]
    fn eth_sign_labels_keep_the_execute_or_propose_fork() {
        let (s, _) = screen_with_safe_tx_review(1, vec![0]);
        let mut action = review(&s).action.clone();
        assert_eq!(
            eth_sign_labels(&action),
            ("Propose — sign as a message ⚠".to_string(), None)
        );
        if let SignAction::WalletConnect {
            plan: WcSignPlan::SafeTx { can_execute, .. },
            ..
        } = &mut action
        {
            *can_execute = true;
        }
        assert_eq!(
            eth_sign_labels(&action),
            (
                "Execute — sign as a message ⚠".to_string(),
                Some("Propose — sign as a message ⚠".to_string())
            )
        );
    }

    /// Execute was on offer, but the execute-time dry run reverts (the chain moved since the
    /// review). Executing is withdrawn — it would only re-run that dry run — and proposing, which
    /// doesn't, stays live with the reason on screen.
    #[tokio::test]
    async fn an_execute_refused_by_its_dry_run_leaves_propose_live() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, _) = safe_tx_review(&rig, 1).await;
        let key = review_key(&s);
        assert!(review(&s).secondary_label.is_some(), "Propose is offered");
        assert!(
            s.dispatch_wc(true).units() > 0,
            "the execute task is spawned"
        );
        rig.rt.note_failure(&key, wc::FailureClass::ExecuteRefused);
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key.clone(),
                kind: WcSignKind::SafeExecute,
            },
            signer: None,
            result: Err(
                "This transaction would revert right now: ERC20: insufficient allowance. \
                 Nothing was signed — the dapp may need to build it again."
                    .into(),
            ),
        });
        let r = review(&s);
        assert!(r.signing_since.is_none() && !r.confirm_disabled);
        assert_eq!(r.confirm_label.as_deref(), Some("Propose anyway ⚠"));
        assert_eq!(r.secondary_label, None);
        assert!(r.error.as_deref().is_some_and(|e| e.contains("revert")));
        assert!(
            r.steps
                .iter()
                .all(|st| !matches!(st, SignStep::SafeExec(x) if x.executor.is_some())),
            "no sender is named for an execution that's off the table"
        );
        assert!(!safe_plan(&s).1);
        assert_eq!(
            state(&rig.rt, &key),
            Some(wc::QueueState::InReview { seq: r.seq })
        );
        disarm(&mut s);
        assert!(s.dispatch_wc(true).units() > 0, "Confirm now proposes");
        assert!(matches!(
            review(&s).signing_progress,
            Some(SigningKind::SafePropose { .. })
        ));
        assert_unanswered(&mut call).await;
    }

    /// An executed Safe transaction answers the dapp with the executor's on-chain hash; the
    /// review says so before Confirm, and the Activity entry carries both that hash and the
    /// Safe transaction hash, so the user can find it in Safe{Wallet} too.
    #[tokio::test]
    async fn safe_execute_discloses_and_records_both_hashes() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, _) = safe_tx_review(&rig, 1).await;
        let note = review(&s).note.clone().unwrap_or_default();
        assert!(
            note.contains("If executed now") && note.contains("If proposed"),
            "{note}"
        );
        let key = review_key(&s);
        s.dispatch_wc(true);
        let executor_hash = TxHash::repeat_byte(0xe1);
        s.wc_on_signed(
            key,
            WcSignKind::SafeExecute,
            Ok(SignOutcome::Tx(executor_hash)),
        );
        assert_eq!(
            answered(&mut call).await.expect("a result"),
            json!(format!("{executor_hash:#x}"))
        );
        let notices = rig.rt.with_book(|b| b.snapshot(wc::now_secs()).notices);
        let safe_tx_hash = B256::repeat_byte(0x5e);
        assert!(
            notices
                .iter()
                .any(|n| n.text.contains(&short_hash(&executor_hash))
                    && n.text.contains(&short_hash(&safe_tx_hash))),
            "{:?}",
            notices.iter().map(|n| &n.text).collect::<Vec<_>>()
        );
    }

    /// Kao executed dapp transaction A at the Safe's nonce 5 and answered with the executor hash;
    /// A is still in the mempool, so the chain still reads nonce 5 and the Transaction Service
    /// (A was never proposed) reads an empty queue. A second dapp transaction must not open
    /// until A is mined: it would pin nonce 5 again and offer "Sign & execute now" for a
    /// transaction that can only revert or go stale.
    #[tokio::test]
    async fn a_second_safe_tx_waits_while_the_first_execution_is_unmined() {
        let rig = start_rig().await;
        let (mut s, session, mut call_a, safe_addr) = safe_tx_review(&rig, 1).await;
        let key_a = review_key(&s);
        let _call_b = dapp_request(
            &rig,
            &session.topic,
            "eth_sendTransaction",
            tx_params(safe_addr),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        assert!(s.dispatch_wc(true).units() > 0, "A executes");
        let exec_hash = TxHash::repeat_byte(0xe1);
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key_a.clone(),
                kind: WcSignKind::SafeExecute,
            },
            signer: None,
            result: Ok(SignOutcome::Tx(exec_hash)),
        });
        assert_eq!(
            answered(&mut call_a).await.expect("A answered"),
            json!(format!("{exec_hash:#x}"))
        );
        // The queue refetch lands empty: A was executed directly, never proposed.
        queue_read_lands(&mut s, safe_addr, Ok(Vec::new()));
        assert!(!s.safe_pending_loading);
        assert!(
            s.sign_review.is_none(),
            "B opened while A's execution at nonce 5 is still unmined"
        );
        let identity = wc::WcIdentity::Safe {
            address: safe_addr,
            chain_id: Chain::Mainnet.chain_id(),
        };
        let held = (safe_addr.into_array(), Chain::Mainnet.chain_id());
        assert_eq!(
            rig.rt.with_book(|b| b.safe_exec_held(&identity)),
            Some(5),
            "A's nonce is held"
        );
        // Another nonce settling is not A's.
        assert!(!rig.rt.with_book(|b| b.release_safe_exec(held, 4)));
        let _ = s.pump_wc_queue();
        assert!(s.sign_review.is_none());
        // A is mined (as the runtime's watch reports it): B opens, to be pinned against the moved
        // nonce.
        assert!(rig.rt.with_book(|b| b.release_safe_exec(held, 5)));
        let _ = s.pump_wc_queue();
        assert_eq!(rig.rt.with_book(|b| b.safe_exec_held(&identity)), None);
        assert!(matches!(
            &review(&s).action,
            SignAction::WalletConnect {
                plan: WcSignPlan::SafeTx { .. },
                ..
            }
        ));
        assert_ne!(review_key(&s), key_a);
    }

    /// The hold on an unmined execution's nonce outlives the dashboard that made it: rebuilt (an
    /// account switch and back), the next dapp transaction for that Safe still waits rather than
    /// pin the same nonce with "Sign & execute now".
    #[tokio::test]
    async fn the_execution_hold_survives_a_dashboard_rebuild() {
        let rig = start_rig().await;
        let (mut s, session, mut call_a, safe_addr) = safe_tx_review(&rig, 1).await;
        let key_a = review_key(&s);
        let _call_b = dapp_request(
            &rig,
            &session.topic,
            "eth_sendTransaction",
            tx_params(safe_addr),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        assert!(s.dispatch_wc(true).units() > 0);
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key_a.clone(),
                kind: WcSignKind::SafeExecute,
            },
            signer: None,
            result: Ok(SignOutcome::Tx(TxHash::repeat_byte(0xe1))),
        });
        answered(&mut call_a).await.expect("A answered");
        let (accounts, safes) = (s.accounts.clone(), s.safes.clone());
        drop(s);
        let mut s = screen(accounts, 0, safes);
        s.test_enter_safe_mode(0);
        s.set_wc_slot(rig.slot.clone());
        let _ = s.reload_safe_pending(true);
        queue_read_lands(&mut s, safe_addr, Ok(Vec::new()));
        assert!(!s.safe_pending_loading);
        assert!(
            s.sign_review.is_none(),
            "B opened on a rebuilt dashboard while A's execution at nonce 5 is unmined"
        );
        assert_eq!(waiting(&rig.rt), 1);
    }

    /// A queue read launched before dapp transaction A was proposed lands after it: it predates
    /// A, so it neither releases the hold on the next Safe transaction nor becomes the queue B is
    /// pinned against. B opens on the read launched after the proposal, which holds A's nonce.
    #[tokio::test]
    async fn a_queue_read_older_than_a_proposal_never_releases_the_next_transaction() {
        let rig = start_rig().await;
        let (mut s, session, mut call_a, safe_addr) = safe_tx_review(&rig, 1).await;
        let key_a = review_key(&s);
        let _call_b = dapp_request(
            &rig,
            &session.topic,
            "eth_sendTransaction",
            tx_params(safe_addr),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        let safes = s.safes.clone();
        s.update(Message::SafesUpdated(safes));
        assert!(s.safe_pending_loading, "read #1 in flight");
        let (_, first) = s.safe_pending_reading.expect("read #1 in flight");
        assert!(s.dispatch_wc(false).units() > 0, "A is proposed at nonce 5");
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key_a.clone(),
                kind: WcSignKind::SafePropose,
            },
            signer: None,
            result: Ok(SignOutcome::SafeProposed(B256::repeat_byte(0x5e))),
        });
        answered(&mut call_a).await.expect("A answered");
        assert!(s.safe_pending_loading && s.sign_review.is_none());
        // Read #1, from before the proposal, lands first.
        s.update(Message::SafePendingFetched {
            safe: safe_addr,
            chain: Chain::Mainnet,
            seq: first,
            result: Ok(Vec::new()),
        });
        assert!(
            s.sign_review.is_none(),
            "B opened against a queue read from before A was proposed"
        );
        assert!(
            s.safe_pending_loading,
            "the hold stays until the later read lands"
        );
    }

    /// The Safe's owner is the active account, whose live signer the dashboard holds: the Safe
    /// ceremony signs with that same instance (parked for the task and handed back through
    /// `Message::Signed`), never a second connection to the same device — a Ledger refuses a second
    /// open while the first is held.
    #[tokio::test]
    async fn safe_ceremony_reuses_the_active_owner_signer() {
        let rig = start_rig().await;
        let owner = PrivateKeySigner::random();
        let safe_addr = Address::from([0x5a; 20]);
        let mut s = screen(
            vec![local_account(&owner)],
            0,
            vec![safe(0x5a, 1, &[owner.address()], vec![0], 1)],
        );
        s.test_enter_safe_mode(0);
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let _msg = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(safe_addr),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        disarm(&mut s);
        assert!(s.dispatch_wc(true).units() > 0, "the ceremony is spawned");
        assert!(
            !s.signer.can_sign(),
            "the active owner's signer is parked for the ceremony, not left open beside a second one"
        );
        assert!(s.order_op_in_flight);
    }

    /// A Safe whose owners don't include the active account parks nothing: the dashboard keeps
    /// its signer, and only the busy flag goes up.
    #[test]
    fn safe_ceremony_parks_nothing_when_the_active_account_isnt_an_owner() {
        let active = PrivateKeySigner::random();
        let owner = PrivateKeySigner::random();
        let mut s = screen(
            vec![local_account(&active), local_account(&owner)],
            0,
            vec![safe(0x5a, 1, &[owner.address()], vec![1], 1)],
        );
        s.test_enter_safe_mode(0);
        let opts = s.wc_owner_sign_opts(
            &[local_account(&owner)],
            crate::safe::tx::OwnerSigMode::Eip712,
        );
        assert!(opts.parked.is_none());
        assert!(s.signer.can_sign() && s.order_op_in_flight);
        // The owner that IS the active account: its live signer goes into the handoff.
        let mut s = screen(
            vec![local_account(&owner)],
            0,
            vec![safe(0x5a, 1, &[owner.address()], vec![0], 1)],
        );
        let opts = s.wc_owner_sign_opts(
            &[local_account(&owner)],
            crate::safe::tx::OwnerSigMode::Eip712,
        );
        let parked = opts.parked.expect("parked");
        assert_eq!(
            parked.lock().unwrap().as_ref().map(|k| k.address()),
            Some(owner.address())
        );
        assert!(!s.signer.can_sign() && s.order_op_in_flight);
        // Handed back through `Message::Signed`, it is the dashboard's again.
        s.update(Message::Signed {
            tag: SignTag::TxBuilderPropose,
            signer: Some(parked),
            result: Err("declined".into()),
        });
        assert!(s.signer.can_sign() && !s.order_op_in_flight);
    }

    /// Who pays for and sends a dapp's Safe execution: an account already tied to the Safe —
    /// a Local signing owner first (it signs anyway), else a Local account linked to the Safe —
    /// ahead of whichever Local account happens to come first in the wallet.
    #[test]
    fn wc_safe_executor_prefers_an_owner_then_a_linked_local_account() {
        let personal = PrivateKeySigner::random();
        let owner = PrivateKeySigner::random();
        let linked = PrivateKeySigner::random();
        let ledger_owner = Address::repeat_byte(0x77);
        let executor_of = |s: &WalletScreen| {
            let identity = s.wc_active_identity().expect("the Safe is the identity");
            let ctx = s.wc_signer_context(&identity).expect("a signing context");
            let mut req = s
                .active_safe_batch_request(
                    crate::safe::tx::SafeTxInput {
                        to: Address::repeat_byte(0x40),
                        value: U256::ZERO,
                        data: Bytes::new(),
                        operation: crate::safe::tx::Operation::Call,
                    },
                    1,
                    tx_builder::QueueMap {
                        prepends: 0,
                        queued: 1,
                    },
                )
                .expect("a request");
            req.prepared = Some((5, B256::repeat_byte(0x5e)));
            let plan = WcSignPlan::SafeTx {
                req,
                can_execute: true,
                unconfirmed: None,
            };
            match s.wc_ceremony(plan, ctx, true) {
                Ok(Ceremony::SafeExecute { executor_key, .. }) => {
                    executor_key.map(|k| crate::wallet::signer_from_bytes(&k).unwrap().address())
                }
                Ok(_) => panic!("not an execute"),
                Err(e) => panic!("{e}"),
            }
        };
        // A Local owner signs anyway: it executes, not the unrelated first account.
        let mut s = screen(
            vec![local_account(&personal), local_account(&owner)],
            1,
            vec![safe(0x5a, 1, &[owner.address()], vec![1], 1)],
        );
        s.test_enter_safe_mode(0);
        assert_eq!(executor_of(&s), Some(owner.address()));
        // A hardware owner, and a Local account linked to the Safe (not an owner): the linked
        // account pays, not the unrelated first one.
        let mut s = screen(
            vec![
                local_account(&personal),
                ledger_account(ledger_owner),
                local_account(&linked),
            ],
            0,
            vec![safe(0x5a, 1, &[ledger_owner], vec![1, 2], 1)],
        );
        s.test_enter_safe_mode(0);
        assert_eq!(executor_of(&s), Some(linked.address()));
    }

    #[tokio::test]
    async fn safe_dispatch_raises_busy_flag() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, _) = safe_tx_review(&rig, 1).await;
        let key = review_key(&s);
        let seq = review(&s).seq;
        assert!(!s.is_signing_busy());
        let task = s.dispatch_wc(true);
        assert!(task.units() > 0, "the execute task is spawned");
        assert!(
            s.order_op_in_flight && s.is_signing_busy(),
            "one signature at a time"
        );
        assert!(review(&s).signing_since.is_some());
        assert_eq!(state(&rig.rt, &key), Some(wc::QueueState::Signing { seq }));
        // A second confirm while it runs does nothing.
        assert_eq!(s.dispatch_wc(true).units(), 0);
        assert_unanswered(&mut call).await;
    }

    #[tokio::test]
    async fn dispatch_wc_refuses_while_another_wc_request_signs() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let _first = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(a.address()),
        );
        let _second = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 2).await;
        s.pump_wc_queue();
        disarm(&mut s);
        let open = review_key(&s);
        // The other request is signing (a dashboard rebuilt away left it running).
        let other = queued_keys(&rig.rt)
            .into_iter()
            .find(|k| *k != open)
            .expect("second request");
        rig.rt.with_book(|b| {
            assert!(b.mark_in_review(&other, 999_001));
            assert!(b.mark_signing(&other, 999_001));
        });
        assert_eq!(s.dispatch_wc(true).units(), 0);
        assert_eq!(review(&s).error.as_deref(), Some(BUSY_TEXT));
        assert!(matches!(
            state(&rig.rt, &open),
            Some(wc::QueueState::InReview { .. })
        ));
    }

    // ── a stale quote is re-taken, not signed ───────────────────────────

    #[tokio::test]
    async fn stale_quote_requotes_in_place() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let mut call = dapp_request(
            &rig,
            &session.topic,
            "eth_sendTransaction",
            tx_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        let key = review_key(&s);
        let plan = match &review(&s).action {
            SignAction::WalletConnect {
                plan: WcSignPlan::EoaTx { plan, .. },
                ..
            } => plan.clone(),
            _ => panic!("an EOA transaction review"),
        };
        deliver_prepared(&mut s, eoa_tx_steps(&plan, None, false));
        disarm(&mut s);
        let seq_before = review(&s).seq;
        // The review sat open past the quote's lifetime.
        let aged = Instant::now()
            .checked_sub(wc::QUOTE_MAX_AGE + Duration::from_secs(1))
            .expect("monotonic clock past boot");
        if let Some(SignAction::WalletConnect {
            plan: WcSignPlan::EoaTx { quoted_at, .. },
            ..
        }) = s.sign_review.as_mut().map(|r| &mut r.action)
        {
            *quoted_at = Some(aged);
        }
        let task = s.dispatch_wc(true);
        assert!(task.units() > 0, "a fresh prepare is spawned");
        let r = review(&s);
        assert_ne!(r.seq, seq_before, "a new seq retires the old prepare");
        assert!(r.legs_loading && r.signing_since.is_none());
        assert!(matches!(r.steps.as_slice(), [SignStep::WcOrigin(_)]));
        assert!(r.note.as_deref().is_some_and(|n| n.contains(REQUOTE_NOTE)));
        assert!(matches!(
            &r.action,
            SignAction::WalletConnect {
                plan: WcSignPlan::EoaTx { quote: None, .. },
                ..
            }
        ));
        assert_eq!(
            state(&rig.rt, &key),
            Some(wc::QueueState::InReview { seq: r.seq })
        );
        assert!(
            !s.order_op_in_flight && s.signer.can_sign(),
            "nothing was signed"
        );
        assert_unanswered(&mut call).await;
    }

    // ── a broadcast whose reply was lost is never signed again ──────────

    /// An EOA transaction review, prepared (nonce 3) and confirmed: the send task is in flight.
    async fn eoa_tx_signing(
        rig: &Rig,
    ) -> (
        WalletScreen,
        DappCall,
        wc::WcKey,
        SendPlan,
        PrivateKeySigner,
    ) {
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, rig).await;
        let call = dapp_request(
            rig,
            &session.topic,
            "eth_sendTransaction",
            tx_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        let key = review_key(&s);
        let plan = match &review(&s).action {
            SignAction::WalletConnect {
                plan: WcSignPlan::EoaTx { plan, .. },
                ..
            } => plan.clone(),
            _ => panic!("an EOA transaction review"),
        };
        deliver_prepared(&mut s, eoa_tx_steps(&plan, None, false));
        disarm(&mut s);
        assert!(s.dispatch_wc(true).units() > 0);
        assert!(matches!(
            state(&rig.rt, &key),
            Some(wc::QueueState::Signing { .. })
        ));
        (s, call, key, plan, a)
    }

    fn unconfirmed_tx(nonce: u64) -> wc::UnconfirmedTx {
        let raw = Bytes::from(vec![0x02, 0xc0, nonce as u8]);
        wc::UnconfirmedTx {
            hash: alloy::primitives::keccak256(&raw),
            raw,
            nonce,
        }
    }

    /// What the send task reports when its broadcast's reply never came back: the bytes it
    /// signed noted on the runtime (as `settle` does), the node's text as the error, and the
    /// parked signer handed back.
    fn lose_the_reply(
        s: &mut WalletScreen,
        rig: &Rig,
        key: &wc::WcKey,
        a: &PrivateKeySigner,
        tx: &wc::UnconfirmedTx,
    ) {
        rig.rt.note_unconfirmed(key, tx.clone());
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key.clone(),
                kind: WcSignKind::EoaTx,
            },
            signer: Some(crate::wallet::handoff_with(KaoSigner::Local(a.clone()))),
            result: Err("broadcast failed: error sending request for url (http://rpc/…)".into()),
        });
    }

    fn latched(r: &SignReview) -> Option<wc::UnconfirmedTx> {
        match &r.action {
            SignAction::WalletConnect {
                plan: WcSignPlan::EoaTx { unconfirmed, .. },
                ..
            } => unconfirmed.clone(),
            _ => None,
        }
    }

    /// A broadcast whose reply was lost latches the review onto the transaction already signed:
    /// Confirm becomes "send the same bytes again". An aged quote doesn't re-quote, a nonce that
    /// moved (the node did take it) doesn't either — nothing is ever signed anew — and the re-send
    /// answers the dapp with that transaction's hash.
    #[tokio::test]
    async fn lost_broadcast_reply_latches_and_never_requotes() {
        let rig = start_rig().await;
        let (mut s, mut call, key, _plan, a) = eoa_tx_signing(&rig).await;
        let tx = unconfirmed_tx(3);
        lose_the_reply(&mut s, &rig, &key, &a, &tx);
        assert!(s.signer.can_sign() && !s.order_op_in_flight);
        let r = review(&s);
        let seq = r.seq;
        assert_eq!(latched(r), Some(tx.clone()));
        assert!(r.signing_since.is_none() && !r.confirm_disabled && !r.legs_loading);
        assert_eq!(r.confirm_label.as_deref(), Some(RESEND_LABEL));
        let error = r.error.clone().unwrap_or_default();
        assert!(error.contains(&format!("{:#x}", tx.hash)), "{error}");
        assert!(error.contains("broadcast failed"), "{error}");
        assert!(!error.contains("  "), "one clean sentence: {error}");
        assert!(matches!(
            &r.action,
            SignAction::WalletConnect {
                plan: WcSignPlan::EoaTx { quote: Some(_), .. },
                ..
            }
        ));
        assert_eq!(state(&rig.rt, &key), Some(wc::QueueState::InReview { seq }));

        // The quote ages past its limit: Confirm still only re-sends — no re-quote, no signer.
        if let Some(SignAction::WalletConnect {
            plan: WcSignPlan::EoaTx { quoted_at, .. },
            ..
        }) = s.sign_review.as_mut().map(|r| &mut r.action)
        {
            *quoted_at = Instant::now().checked_sub(wc::QUOTE_MAX_AGE + Duration::from_secs(1));
        }
        disarm(&mut s);
        assert!(s.dispatch_wc(true).units() > 0, "the re-send is spawned");
        let r = review(&s);
        assert_eq!(r.seq, seq, "not re-quoted");
        assert!(!r.legs_loading && r.signing_since.is_some());
        assert_eq!(state(&rig.rt, &key), Some(wc::QueueState::Signing { seq }));
        assert!(
            s.order_op_in_flight && s.signer.can_sign(),
            "busy, but no signer was parked: nothing is signed"
        );

        // Even a stale verdict (the nonce moved: the node did take it) never re-quotes.
        rig.rt.note_failure(&key, wc::FailureClass::Stale);
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key.clone(),
                kind: WcSignKind::EoaTx,
            },
            signer: None,
            result: Err("this account's next nonce moved since you reviewed (3 → 4)".into()),
        });
        let r = review(&s);
        assert!(!r.legs_loading && r.seq == seq, "still not re-quoted");
        assert_eq!(latched(r), Some(tx.clone()));
        assert_eq!(r.confirm_label.as_deref(), Some(RESEND_LABEL));
        assert_unanswered(&mut call).await;

        // The re-send lands: the dapp gets the signed transaction's own hash.
        disarm(&mut s);
        assert!(s.dispatch_wc(true).units() > 0);
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key.clone(),
                kind: WcSignKind::EoaTx,
            },
            signer: None,
            result: Ok(SignOutcome::Tx(tx.hash)),
        });
        assert_eq!(
            answered(&mut call).await.expect("a result"),
            json!(format!("{:#x}", tx.hash))
        );
        assert!(s.sign_review.is_none());
    }

    /// The runtime's record decides even if the overlay never latched: Confirm latches instead of
    /// signing.
    #[tokio::test]
    async fn dispatch_latches_on_the_runtimes_record() {
        let rig = start_rig().await;
        let (mut s, _call, key, _plan, a) = eoa_tx_signing(&rig).await;
        // An ordinary retryable failure brings Confirm back...
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key.clone(),
                kind: WcSignKind::EoaTx,
            },
            signer: Some(crate::wallet::handoff_with(KaoSigner::Local(a.clone()))),
            result: Err("the device declined".into()),
        });
        assert_eq!(latched(review(&s)), None);
        // ...but the runtime holds a transaction already sent for this request.
        let tx = unconfirmed_tx(3);
        rig.rt.with_book(|b| b.note_unconfirmed(&key, tx.clone()));
        disarm(&mut s);
        assert_eq!(s.dispatch_wc(true).units(), 0, "nothing signed");
        let r = review(&s);
        assert_eq!(latched(r), Some(tx));
        assert_eq!(r.confirm_label.as_deref(), Some(RESEND_LABEL));
        assert!(matches!(
            state(&rig.rt, &key),
            Some(wc::QueueState::InReview { .. })
        ));
    }

    /// Giving up on a latched review isn't "rejected": the user approved it and it may yet be
    /// mined, so the dapp hears −32603 and the Activity log keeps the hash.
    #[tokio::test]
    async fn cancelling_a_latched_review_answers_failed() {
        let rig = start_rig().await;
        let (mut s, mut call, key, _plan, a) = eoa_tx_signing(&rig).await;
        let tx = unconfirmed_tx(3);
        lose_the_reply(&mut s, &rig, &key, &a, &tx);
        s.wc_on_cancel();
        assert_eq!(
            peer_code(&answered(&mut call).await),
            Some(wc::codes::INTERNAL)
        );
        let hash = format!("{:#x}", tx.hash);
        assert!(
            rig.rt
                .snapshot(wc::now_secs())
                .notices
                .iter()
                .any(|n| n.error && n.text.contains(&hash) && !n.text.contains("  ")),
            "the hash is kept in Activity"
        );
    }

    /// Latching puts the transaction's hash in the Activity list, once, so it outlives the
    /// overlay. When the request then ends under the review (here the dapp's deadline passes),
    /// the review still names the hash, and closing it — nothing left to answer — leaves the line
    /// in place.
    #[tokio::test]
    async fn a_latched_transactions_hash_outlives_the_review() {
        let rig = start_rig().await;
        let (mut s, mut call, key, _plan, a) = eoa_tx_signing(&rig).await;
        let tx = unconfirmed_tx(3);
        let hash = format!("{:#x}", tx.hash);
        let lines = |rt: &WcRuntime| {
            rt.snapshot(wc::now_secs())
                .notices
                .iter()
                .filter(|n| n.error && n.text.contains(&hash))
                .count()
        };
        lose_the_reply(&mut s, &rig, &key, &a, &tx);
        assert_eq!(lines(&rig.rt), 1, "the latch keeps the hash in Activity");

        // A re-send that goes unacknowledged too latches again, without a second line.
        disarm(&mut s);
        assert!(s.dispatch_wc(true).units() > 0);
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key.clone(),
                kind: WcSignKind::EoaTx,
            },
            signer: None,
            result: Err("broadcast failed: request timed out".into()),
        });
        assert_eq!(latched(review(&s)), Some(tx.clone()));
        assert_eq!(lines(&rig.rt), 1, "one line per transaction");

        // The dapp's deadline passes under the latched review.
        let deadline = rig
            .rt
            .with_book(|b| {
                b.request(&key).map(|q| {
                    q.dapp_deadline
                        .map_or(q.kao_deadline, |d| d.min(q.kao_deadline))
                })
            })
            .expect("queued");
        let ui = rig.rt.apply(rig.rt.with_book(|b| b.tick(deadline)));
        s.wc_apply_ui(ui);
        assert_eq!(state(&rig.rt, &key), None, "the request ended");
        let error = review(&s).error.clone().unwrap_or_default();
        assert!(
            error.contains(&hash) && !error.contains("nothing was sent"),
            "{error}"
        );
        s.wc_on_cancel();
        assert!(s.sign_review.is_none());
        assert_unanswered(&mut call).await;
        assert!(lines(&rig.rt) >= 1, "the hash is still in Activity");
    }

    /// A result that lands after WalletConnect closed never claims "nothing was sent" when a
    /// transaction went out, or may have.
    #[tokio::test]
    async fn a_result_after_walletconnect_closed_names_what_was_sent() {
        let rig = start_rig().await;
        let (mut s, _call, key, _plan, a) = eoa_tx_signing(&rig).await;
        rig.rt.mark_closed();
        let hash = B256::repeat_byte(0x5e);
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key.clone(),
                kind: WcSignKind::EoaTx,
            },
            signer: Some(crate::wallet::handoff_with(KaoSigner::Local(a.clone()))),
            result: Ok(SignOutcome::Tx(hash)),
        });
        let error = review(&s).error.clone().unwrap_or_default();
        assert!(
            error.contains(&format!("{hash:#x}")) && !error.contains("nothing was sent"),
            "{error}"
        );

        let rig = start_rig().await;
        let (mut s, _call, key, _plan, a) = eoa_tx_signing(&rig).await;
        rig.rt.mark_closed();
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key.clone(),
                kind: WcSignKind::EoaTx,
            },
            signer: Some(crate::wallet::handoff_with(KaoSigner::Local(a.clone()))),
            result: Err("broadcast failed: request timed out".into()),
        });
        let error = review(&s).error.clone().unwrap_or_default();
        assert!(
            error.contains("on its way") && !error.contains("nothing was sent"),
            "{error}"
        );
    }

    /// The review lost its overlay while latched: the request goes back to the queue, and its
    /// next review is latched too — on the very same bytes, never a fresh quote.
    #[tokio::test]
    async fn a_latched_request_reopens_latched() {
        let rig = start_rig().await;
        let (mut s, mut call, key, plan, a) = eoa_tx_signing(&rig).await;
        let tx = unconfirmed_tx(3);
        lose_the_reply(&mut s, &rig, &key, &a, &tx);
        // Another flow takes the overlay; the backstop releases the stranded request.
        s.sign_review = None;
        assert_eq!(s.wc_release_stranded(&rig.rt), 1);
        assert_eq!(state(&rig.rt, &key), Some(wc::QueueState::Waiting));
        s.pump_wc_queue();
        assert_eq!(review_key(&s), key);
        assert_eq!(latched(review(&s)), Some(tx.clone()), "reopened latched");
        // Its prepare shows the signed transaction (nonce 3, as `eoa_tx_steps` prices it).
        deliver_prepared(&mut s, eoa_tx_steps(&plan, None, false));
        disarm(&mut s);
        assert_eq!(review(&s).confirm_label.as_deref(), Some(RESEND_LABEL));
        assert!(s.dispatch_wc(true).units() > 0);
        assert!(
            s.signer.can_sign(),
            "nothing parked: a re-send signs nothing"
        );
        assert_unanswered(&mut call).await;
    }

    /// The overlay died while the send was in flight and its reply was lost: the dapp isn't told
    /// "failed" (that invites a second transaction); the request goes back to the queue and
    /// reopens latched.
    #[tokio::test]
    async fn lost_reply_without_an_overlay_requeues_instead_of_failing() {
        let rig = start_rig().await;
        let (mut s, mut call, key, _plan, a) = eoa_tx_signing(&rig).await;
        s.sign_review = None;
        let tx = unconfirmed_tx(3);
        lose_the_reply(&mut s, &rig, &key, &a, &tx);
        assert_unanswered(&mut call).await;
        assert_eq!(review_key(&s), key, "the pump reopened it");
        assert_eq!(latched(review(&s)), Some(tx));
    }

    /// The dapp stops waiting while a transaction may be on its way: the review says so instead
    /// of "nothing was sent".
    #[tokio::test]
    async fn a_dead_request_with_a_transaction_on_its_way_says_so() {
        let rig = start_rig().await;
        let (mut s, _call, key, _plan, a) = eoa_tx_signing(&rig).await;
        let tx = unconfirmed_tx(3);
        lose_the_reply(&mut s, &rig, &key, &a, &tx);
        rig.rt.with_book(|b| b.release_reviews_except(None));
        let other = review(&s).seq.wrapping_add(1);
        rig.rt.with_book(|b| assert!(b.mark_in_review(&key, other)));
        disarm(&mut s);
        // The review is no longer the request's: Confirm finds it gone.
        assert_eq!(s.dispatch_wc(true).units(), 0);
        let error = review(&s).error.clone().unwrap_or_default();
        assert!(error.contains(&format!("{:#x}", tx.hash)), "{error}");
        assert!(!error.contains("nothing was sent"), "{error}");
    }

    /// What the Safe execute task reports when the executor's broadcast lost its reply: the
    /// executor's signed bytes noted on the runtime (as `settle` does), the node's text, and the
    /// active owner's signer, parked for the ceremony, handed back as on every outcome.
    fn lose_the_exec_reply(
        s: &mut WalletScreen,
        rig: &Rig,
        key: &wc::WcKey,
        tx: &wc::UnconfirmedTx,
    ) {
        rig.rt.note_unconfirmed(key, tx.clone());
        let parked = match s.accounts.first() {
            Some(AccountDescriptor::Local { key_bytes, .. }) => {
                let bytes = B256::from(*key_bytes.as_array());
                let owner = crate::wallet::signer_from_bytes(&bytes).expect("a local key");
                Some(crate::wallet::handoff_with(KaoSigner::Local(owner)))
            }
            _ => None,
        };
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key.clone(),
                kind: WcSignKind::SafeExecute,
            },
            signer: parked,
            result: Err("broadcast failed: error sending request for url (http://rpc/…)".into()),
        });
    }

    /// The executor's `execTransaction` left without an acknowledgement: the Safe review latches
    /// onto it. Confirm only sends those exact bytes again — no owner is asked to sign anything —
    /// and proposing is withdrawn (it would file a second transaction at the same nonce). The
    /// re-send answers the dapp with the executor's own hash.
    #[tokio::test]
    async fn lost_safe_exec_reply_latches_and_resends_only_those_bytes() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, _) = safe_tx_review(&rig, 1).await;
        let key = review_key(&s);
        assert!(s.dispatch_wc(true).units() > 0, "the execution is spawned");
        let tx = unconfirmed_tx(9);
        lose_the_exec_reply(&mut s, &rig, &key, &tx);
        let r = review(&s);
        let seq = r.seq;
        assert!(
            r.signing_since.is_none() && r.signing_progress.is_none(),
            "the waiting card is gone"
        );
        assert!(!r.confirm_disabled);
        assert_eq!(r.confirm_label.as_deref(), Some(RESEND_LABEL));
        assert_eq!(r.secondary_label, None, "proposing is withdrawn");
        let error = r.error.clone().unwrap_or_default();
        assert!(error.contains(&format!("{:#x}", tx.hash)), "{error}");
        assert!(error.contains("broadcast failed"), "{error}");
        assert_eq!(state(&rig.rt, &key), Some(wc::QueueState::InReview { seq }));
        assert_unanswered(&mut call).await;

        disarm(&mut s);
        assert_eq!(s.dispatch_wc(false).units(), 0, "nothing is proposed");
        assert!(s.dispatch_wc(true).units() > 0, "the re-send is spawned");
        let r = review(&s);
        assert!(r.signing_since.is_some());
        assert!(
            !matches!(r.signing_progress, Some(SigningKind::SafeExecute { .. })),
            "no owner ceremony: {:?}",
            r.signing_progress
        );
        assert!(
            s.signer.can_sign(),
            "nothing parked: a re-send signs nothing"
        );
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key.clone(),
                kind: WcSignKind::SafeExecute,
            },
            signer: None,
            result: Ok(SignOutcome::Tx(tx.hash)),
        });
        assert_eq!(
            answered(&mut call).await.expect("a result"),
            json!(format!("{:#x}", tx.hash))
        );
        assert!(s.sign_review.is_none());
    }

    /// A Safe review that missed the latch still never signs or proposes for a request whose
    /// execution already left: the runtime's record decides at Confirm, for either action.
    #[tokio::test]
    async fn safe_dispatch_latches_on_the_runtimes_record() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, _) = safe_tx_review(&rig, 1).await;
        let key = review_key(&s);
        let tx = unconfirmed_tx(9);
        rig.rt.with_book(|b| b.note_unconfirmed(&key, tx.clone()));
        assert_eq!(s.dispatch_wc(false).units(), 0, "nothing proposed");
        assert_eq!(review(&s).confirm_label.as_deref(), Some(RESEND_LABEL));
        assert_eq!(review(&s).secondary_label, None);
        disarm(&mut s);
        // The latched Confirm is the re-send — never the owner ceremony.
        assert!(s.dispatch_wc(true).units() > 0);
        assert!(!matches!(
            review(&s).signing_progress,
            Some(SigningKind::SafeExecute { .. })
        ));
        assert!(matches!(
            state(&rig.rt, &key),
            Some(wc::QueueState::Signing { .. })
        ));
        assert_unanswered(&mut call).await;
    }

    /// Giving up on a latched Safe review answers −32603 (the Safe may yet execute it) and keeps
    /// the executor's hash in Activity; the dapp stopping meanwhile is said the same way.
    #[tokio::test]
    async fn a_latched_safe_review_cancels_as_failed_and_dies_honestly() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, _) = safe_tx_review(&rig, 1).await;
        let key = review_key(&s);
        assert!(s.dispatch_wc(true).units() > 0);
        let tx = unconfirmed_tx(9);
        lose_the_exec_reply(&mut s, &rig, &key, &tx);
        let hash = format!("{:#x}", tx.hash);
        // The dapp's request dies under the latched review: not "nothing was sent".
        s.wc_review_dead(&key, GONE_TEXT);
        let error = review(&s).error.clone().unwrap_or_default();
        assert!(
            error.contains(&hash) && !error.contains("nothing was sent"),
            "{error}"
        );
        s.wc.gone = None;
        s.wc_on_cancel();
        assert_eq!(
            peer_code(&answered(&mut call).await),
            Some(wc::codes::INTERNAL)
        );
        assert!(
            rig.rt
                .snapshot(wc::now_secs())
                .notices
                .iter()
                .any(|n| n.error && n.text.contains(&hash)),
            "the hash is kept in Activity"
        );
    }

    /// What a re-send task reports when the node refused the latched bytes as invalid on any node:
    /// the runtime lets go of them (as `settle` does) and the node's text is the error.
    fn refuse_the_resend(
        s: &mut WalletScreen,
        rig: &Rig,
        key: &wc::WcKey,
        kind: WcSignKind,
        tx: &wc::UnconfirmedTx,
    ) {
        rig.rt.void_unconfirmed(key, tx.hash);
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key.clone(),
                kind,
            },
            signer: None,
            result: Err(
                "broadcast failed: server returned an error response: error code \
                         -32000: intrinsic gas too low: have 21000, want 21064"
                    .into(),
            ),
        });
    }

    /// The latched transaction, re-sent, is refused as invalid on any node: it never went
    /// anywhere, so the review lets go of it and takes a fresh quote — never the same bytes again,
    /// and never "may still be mined".
    #[tokio::test]
    async fn a_latched_eoa_review_whose_resend_is_refused_as_invalid_requotes() {
        let rig = start_rig().await;
        let (mut s, mut call, key, _plan, a) = eoa_tx_signing(&rig).await;
        let tx = unconfirmed_tx(3);
        lose_the_reply(&mut s, &rig, &key, &a, &tx);
        let seq = review(&s).seq;
        disarm(&mut s);
        assert!(s.dispatch_wc(true).units() > 0, "the re-send is spawned");
        refuse_the_resend(&mut s, &rig, &key, WcSignKind::EoaTx, &tx);
        let r = review(&s);
        assert_eq!(latched(r), None);
        assert!(r.legs_loading && r.seq != seq, "re-quoted");
        assert_eq!(r.confirm_label, None);
        assert!(
            r.note
                .as_deref()
                .is_some_and(|n| n.contains("intrinsic gas too low")),
            "{:?}",
            r.note
        );
        assert_eq!(rig.rt.with_book(|b| b.unconfirmed(&key)), None);
        assert_eq!(
            state(&rig.rt, &key),
            Some(wc::QueueState::InReview { seq: r.seq })
        );
        assert_unanswered(&mut call).await;
    }

    /// The same for a Safe execution: the executor's bytes can never be mined, so the review lets
    /// go of them. Nothing more is sent or signed from it; Cancel says the request failed, not
    /// that it may still execute.
    #[tokio::test]
    async fn a_latched_safe_review_whose_resend_is_refused_as_invalid_lets_go() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, _) = safe_tx_review(&rig, 1).await;
        let key = review_key(&s);
        assert!(s.dispatch_wc(true).units() > 0);
        let tx = unconfirmed_tx(9);
        lose_the_exec_reply(&mut s, &rig, &key, &tx);
        disarm(&mut s);
        assert!(s.dispatch_wc(true).units() > 0, "the re-send is spawned");
        refuse_the_resend(&mut s, &rig, &key, WcSignKind::SafeExecute, &tx);
        let r = review(&s);
        let SignAction::WalletConnect { plan, .. } = &r.action else {
            panic!("a WalletConnect review");
        };
        assert_eq!(latched_tx(plan), None);
        assert!(r.confirm_disabled && r.signing_since.is_none());
        assert_ne!(r.confirm_label.as_deref(), Some(RESEND_LABEL));
        let error = r.error.clone().unwrap_or_default();
        assert!(error.contains("intrinsic gas too low"), "{error}");
        disarm(&mut s);
        assert_eq!(s.dispatch_wc(true).units(), 0, "nothing more is sent");
        s.wc_on_cancel();
        assert_eq!(
            peer_code(&answered(&mut call).await),
            Some(wc::codes::INTERNAL)
        );
        let notices = rig.rt.snapshot(wc::now_secs()).notices;
        assert!(
            !notices
                .iter()
                .any(|n| n.text.contains("told the dapp the request failed")),
            "{notices:?}"
        );
        assert!(
            notices
                .iter()
                .any(|n| n.text.contains(&format!("{:#x}", tx.hash))
                    && n.text.contains("never be mined")),
            "{notices:?}"
        );
    }

    /// Bytes no node can ever take can't take the Safe's nonce either: the hold their execution
    /// put on the Safe lifts with them, so the dapp's next Safe transaction opens rather than wait
    /// behind them.
    #[tokio::test]
    async fn a_voided_execution_lifts_its_safes_hold() {
        let rig = start_rig().await;
        let (mut s, session, _call, safe_addr) = safe_tx_review(&rig, 1).await;
        let key = review_key(&s);
        assert!(s.dispatch_wc(true).units() > 0);
        let tx = unconfirmed_tx(9);
        lose_the_exec_reply(&mut s, &rig, &key, &tx);
        let identity = wc::WcIdentity::Safe {
            address: safe_addr,
            chain_id: Chain::Mainnet.chain_id(),
        };
        assert_eq!(rig.rt.with_book(|b| b.safe_exec_held(&identity)), Some(5));
        disarm(&mut s);
        assert!(s.dispatch_wc(true).units() > 0, "the re-send is spawned");
        refuse_the_resend(&mut s, &rig, &key, WcSignKind::SafeExecute, &tx);
        assert_eq!(rig.rt.with_book(|b| b.unconfirmed(&key)), None);
        assert_eq!(
            rig.rt.with_book(|b| b.safe_exec_held(&identity)),
            None,
            "the voided execution still holds the Safe"
        );
        s.wc_on_cancel();
        if s.safe_pending_reading.is_some() {
            queue_read_lands(&mut s, safe_addr, Ok(Vec::new()));
        }
        let _call_b = dapp_request(
            &rig,
            &session.topic,
            "eth_sendTransaction",
            tx_params(safe_addr),
        );
        let outcomes = feed_until(&mut s, &rig.rt, |s| {
            s.sign_review.is_some() || waiting(&rig.rt) >= 1
        })
        .await;
        let _ = s.pump_wc_queue();
        assert!(
            !outcomes
                .iter()
                .any(|o| matches!(o, Outcome::Notice(t) if t.contains("previous execution"))),
            "{outcomes:?}"
        );
        assert!(
            matches!(
                &review(&s).action,
                SignAction::WalletConnect {
                    plan: WcSignPlan::SafeTx { .. },
                    ..
                }
            ),
            "the next Safe transaction opens"
        );
        assert_ne!(review_key(&s), key);
    }

    /// A latched Safe review loses its overlay (the identity flips away and back) and the
    /// request opens again on the execution already sent.
    fn reopen_latched(s: &mut WalletScreen) {
        s.exit_safe_mode();
        s.wc_on_identity_changed();
        assert!(s.sign_review.is_none());
        s.test_enter_safe_mode(0);
        s.wc_on_identity_changed();
        s.pump_wc_queue();
    }

    /// The reopened review of an execution already sent describes it from Kao's node, which can
    /// fail as any read does. "Re-check" describes the same transaction again — nothing is signed,
    /// Confirm stays the re-send of those bytes, and the dapp hears nothing meanwhile.
    #[tokio::test]
    async fn a_reopened_latched_safe_review_whose_prepare_fails_offers_recheck() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, safe_addr) = safe_tx_review(&rig, 1).await;
        let key = review_key(&s);
        assert!(s.dispatch_wc(true).units() > 0);
        let tx = unconfirmed_tx(9);
        lose_the_exec_reply(&mut s, &rig, &key, &tx);
        rig.rt
            .with_book(|b| b.release_safe_exec((safe_addr.into_array(), 1), 5));
        reopen_latched(&mut s);
        assert_eq!(review_key(&s), key);
        let seq = review(&s).seq;
        s.update(Message::SignReviewPrepared {
            seq,
            steps: Err("error sending request for url (http://rpc/…)".into()),
        });
        let r = review(&s);
        assert!(r.confirm_disabled && !r.legs_loading);
        assert_eq!(r.secondary_label.as_deref(), Some(RECHECK_LABEL));
        assert!(r.secondary_unblocked);
        s.update(Message::SignReview(sign_review::Message::Secondary));
        let r = review(&s);
        assert_ne!(r.seq, seq, "a new seq retires the failed prepare");
        assert!(r.legs_loading && !r.confirm_disabled && r.error.is_none());
        assert!(r.secondary_label.is_none() && !r.secondary_unblocked);
        let SignAction::WalletConnect { plan, .. } = &r.action else {
            panic!("a WalletConnect review");
        };
        assert_eq!(latched_tx(plan), Some(&tx), "still that transaction");
        assert_eq!(
            state(&rig.rt, &key),
            Some(wc::QueueState::InReview { seq: r.seq })
        );
        assert!(!s.order_op_in_flight, "nothing signs");
        assert_unanswered(&mut call).await;
    }

    /// The request whose execution left unacknowledged is the one its own hold waits on: its
    /// review only sends those bytes again and pins nothing, so it reopens while the hold stands.
    #[tokio::test]
    async fn a_latched_request_reopens_under_its_own_execution_hold() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, safe_addr) = safe_tx_review(&rig, 1).await;
        let key = review_key(&s);
        assert!(s.dispatch_wc(true).units() > 0);
        let tx = unconfirmed_tx(9);
        lose_the_exec_reply(&mut s, &rig, &key, &tx);
        let identity = wc::WcIdentity::Safe {
            address: safe_addr,
            chain_id: Chain::Mainnet.chain_id(),
        };
        assert_eq!(rig.rt.with_book(|b| b.safe_exec_held(&identity)), Some(5));
        reopen_latched(&mut s);
        assert_eq!(review_key(&s), key, "the latched request reopened");
        let SignAction::WalletConnect { plan, .. } = &review(&s).action else {
            panic!("a WalletConnect review");
        };
        assert_eq!(latched_tx(plan), Some(&tx));
        assert_eq!(rig.rt.with_book(|b| b.safe_exec_held(&identity)), Some(5));
        assert_unanswered(&mut call).await;
    }

    /// A dapp Safe transaction waiting on Kao's unmined execution of the previous one says so: a
    /// toast when it arrives, the pane's row in place of [Review], and a [Review] that arrives
    /// anyway is answered with why. It opens by itself once the execution is mined.
    #[tokio::test]
    async fn a_safe_tx_held_behind_an_unmined_execution_says_why() {
        let rig = start_rig().await;
        let (mut s, session, mut call_a, safe_addr) = safe_tx_review(&rig, 1).await;
        let key_a = review_key(&s);
        assert!(s.dispatch_wc(true).units() > 0);
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key_a.clone(),
                kind: WcSignKind::SafeExecute,
            },
            signer: None,
            result: Ok(SignOutcome::Tx(TxHash::repeat_byte(0xe1))),
        });
        answered(&mut call_a).await.expect("A answered");
        queue_read_lands(&mut s, safe_addr, Ok(Vec::new()));
        let _call_b = dapp_request(
            &rig,
            &session.topic,
            "eth_sendTransaction",
            tx_params(safe_addr),
        );
        let outcomes = feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        let _ = s.pump_wc_queue();
        assert!(s.sign_review.is_none());
        let says_why = |t: &str| t.contains("previous execution");
        assert!(
            outcomes
                .iter()
                .any(|o| matches!(o, Outcome::Notice(t) if says_why(t))),
            "{outcomes:?}"
        );
        let key_b = queued_keys(&rig.rt).pop().expect("B is queued");
        s.wc_mirror();
        let texts = pane_texts(&mut s);
        assert!(texts.iter().any(|t| says_why(t)), "{texts:?}");
        assert!(!texts.iter().any(|t| t == "Review"), "{texts:?}");
        assert!(texts.iter().any(|t| t == "Reject"), "{texts:?}");
        let (_, outcome) = s.handle_wc_outcome(wc_app::Outcome::ReviewNow { key: key_b.clone() });
        assert!(
            matches!(&outcome, Some(Outcome::Notice(t)) if says_why(t)),
            "{outcome:?}"
        );
        assert!(s.sign_review.is_none());
        assert!(
            rig.rt
                .with_book(|b| b.release_safe_exec((safe_addr.into_array(), 1), 5))
        );
        let _ = s.pump_wc_queue();
        assert_eq!(review_key(&s), key_b);
    }

    /// A request held back however long — past the age at which a waiting request stops opening
    /// by itself — still opens once the hold lifts with its execution mined, as its toast and the
    /// pane promised: the wait behind the execution doesn't age it, and a [Review] clicked
    /// meanwhile isn't forgotten.
    #[tokio::test]
    async fn a_held_request_opens_once_the_hold_lifts_however_long_it_waited() {
        for click in [false, true] {
            let rig = start_rig().await;
            let executor = TxHash::repeat_byte(0xe1);
            let (mut s, session, safe_addr) = executed_a(&rig, 1, executor).await;
            // The hold began long before B arrived: it held B all along.
            let holds = rig.rt.with_book(|b| b.safe_execs());
            let this = (safe_addr.into_array(), 1);
            assert!(holds.release(
                this,
                5,
                executor,
                wc::book::HoldEnd::Settled,
                wc::now_secs()
            ));
            let began = wc::now_secs() - (wc::AUTO_OPEN_MAX_AGE_SECS + 120);
            assert!(holds.hold(this, 5, executor, began).is_some());
            let _call_b = dapp_request(
                &rig,
                &session.topic,
                "eth_sendTransaction",
                tx_params(safe_addr),
            );
            feed_aged(&mut s, &rig.rt, 1, wc::AUTO_OPEN_MAX_AGE_SECS + 60).await;
            let key_b = queued_keys(&rig.rt).pop().expect("B is queued");
            assert!(rig.rt.with_book(|b| b.held_behind_execution(&key_b)));
            if click {
                let (_, outcome) =
                    s.handle_wc_outcome(wc_app::Outcome::ReviewNow { key: key_b.clone() });
                assert!(
                    matches!(&outcome, Some(Outcome::Notice(t)) if t == HELD_NOTICE),
                    "{outcome:?}"
                );
                assert!(s.sign_review.is_none());
            }
            assert!(
                rig.rt
                    .with_book(|b| b.release_safe_exec((safe_addr.into_array(), 1), 5))
            );
            let _ = s.pump_wc_queue();
            assert_eq!(
                s.sign_review.as_ref().map(|_| review_key(&s)),
                Some(key_b),
                "clicked: {click}"
            );
        }
    }

    /// A dapp Safe transaction A that Kao executed with `executor` and the dapp heard about, its
    /// Safe now held at nonce 5; the Safe's queue read it started has landed.
    async fn executed_a(
        rig: &Rig,
        threshold: u32,
        executor: TxHash,
    ) -> (WalletScreen, Session, Address) {
        let (mut s, session, mut call_a, safe_addr) = safe_tx_review(rig, threshold).await;
        let key_a = review_key(&s);
        assert!(s.dispatch_wc(true).units() > 0);
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key_a,
                kind: WcSignKind::SafeExecute,
            },
            signer: None,
            result: Ok(SignOutcome::Tx(executor)),
        });
        answered(&mut call_a).await.expect("A answered");
        queue_read_lands(&mut s, safe_addr, Ok(Vec::new()));
        (s, session, safe_addr)
    }

    /// The review's caution names `executor` and the Safe nonce it may still take.
    fn assert_names_the_unmined_execution(s: &WalletScreen, executor: TxHash) {
        let error = review(s).error.clone().unwrap_or_default();
        assert!(
            error.contains(&format!("{executor:#x}")) && error.contains("nonce 5"),
            "{error}"
        );
    }

    /// A hold whose watch gave up on its execution lifts, but that execution may still be mined:
    /// the request it kept back opens by itself only while young enough to open anyway — one held
    /// past that waits for [Review] — and its review, pinning the same nonce, names the execution
    /// that may still take it.
    #[tokio::test]
    async fn a_hold_given_up_on_lifts_without_promising_the_nonce() {
        for aged in [false, true] {
            let rig = start_rig().await;
            let executor = TxHash::repeat_byte(0xe1);
            let (mut s, session, safe_addr) = executed_a(&rig, 1, executor).await;
            let _call_b = dapp_request(
                &rig,
                &session.topic,
                "eth_sendTransaction",
                tx_params(safe_addr),
            );
            let age = if aged {
                wc::AUTO_OPEN_MAX_AGE_SECS + 60
            } else {
                0
            };
            feed_aged(&mut s, &rig.rt, 1, age).await;
            let key_b = queued_keys(&rig.rt).pop().expect("B is queued");
            assert!(rig.rt.with_book(|b| b.held_behind_execution(&key_b)));
            let holds = rig.rt.with_book(|b| b.safe_execs());
            assert!(holds.release(
                (safe_addr.into_array(), 1),
                5,
                executor,
                wc::book::HoldEnd::GaveUp,
                wc::now_secs(),
            ));
            let _ = s.pump_wc_queue();
            if aged {
                assert!(
                    s.sign_review.is_none(),
                    "a request held past the auto-open age opened by itself"
                );
                let _ = s.handle_wc_outcome(wc_app::Outcome::ReviewNow { key: key_b.clone() });
            }
            assert_eq!(review_key(&s), key_b, "aged: {aged}");
            deliver_prepared(&mut s, vec![safe_exec_step(safe_addr, 5, 5, 0)]);
            assert_names_the_unmined_execution(&s, executor);
        }
    }

    /// The Safe's nonce moved past the execution given up on: a review pinning the next nonce
    /// can't collide with it, and says nothing of it.
    #[tokio::test]
    async fn a_review_past_the_given_up_nonce_has_no_caution() {
        let rig = start_rig().await;
        let executor = TxHash::repeat_byte(0xe1);
        let (mut s, session, safe_addr) = executed_a(&rig, 1, executor).await;
        let holds = rig.rt.with_book(|b| b.safe_execs());
        assert!(holds.release(
            (safe_addr.into_array(), 1),
            5,
            executor,
            wc::book::HoldEnd::GaveUp,
            wc::now_secs(),
        ));
        let _call_b = dapp_request(
            &rig,
            &session.topic,
            "eth_sendTransaction",
            tx_params(safe_addr),
        );
        feed_until(&mut s, &rig.rt, |s| {
            s.sign_review.is_some() || waiting(&rig.rt) >= 1
        })
        .await;
        let _ = s.pump_wc_queue();
        assert!(s.sign_review.is_some(), "B opens: nothing holds it");
        deliver_prepared(&mut s, vec![safe_exec_step(safe_addr, 6, 6, 0)]);
        assert_eq!(review(&s).error, None);
    }

    /// [Review anyway] on a request a hold keeps back opens that request — only that one — now,
    /// its review naming the unmined execution it may collide with. The hold stands for the rest.
    #[tokio::test]
    async fn review_anyway_opens_a_held_request_with_a_caution() {
        let rig = start_rig().await;
        let executor = TxHash::repeat_byte(0xe1);
        let (mut s, session, safe_addr) = executed_a(&rig, 1, executor).await;
        let _call_b = dapp_request(
            &rig,
            &session.topic,
            "eth_sendTransaction",
            tx_params(safe_addr),
        );
        let _call_c = dapp_request(
            &rig,
            &session.topic,
            "eth_sendTransaction",
            tx_params(safe_addr),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 2).await;
        let _ = s.pump_wc_queue();
        assert!(s.sign_review.is_none());
        let keys = queued_keys(&rig.rt);
        let (key_b, key_c) = (keys[0].clone(), keys[1].clone());
        s.wc_mirror();
        let texts = pane_texts(&mut s);
        assert!(texts.iter().any(|t| t == "Review anyway"), "{texts:?}");
        let (_, outcome) =
            s.handle_wc_outcome(wc_app::Outcome::ReviewPastHold { key: key_b.clone() });
        assert!(outcome.is_none(), "{outcome:?}");
        assert_eq!(review_key(&s), key_b);
        deliver_prepared(&mut s, vec![safe_exec_step(safe_addr, 5, 5, 0)]);
        assert_names_the_unmined_execution(&s, executor);
        assert!(rig.rt.with_book(|b| b.held_behind_execution(&key_c)));
        let identity = wc::WcIdentity::Safe {
            address: safe_addr,
            chain_id: Chain::Mainnet.chain_id(),
        };
        assert_eq!(rig.rt.with_book(|b| b.safe_exec_held(&identity)), Some(5));
    }

    /// A fresh runtime on the rig's relay, installed in `slot`: what pairing again after Turn off
    /// (or an idle retire) starts, or the first pairing after an unlock.
    async fn restarted(rig: &Rig, slot: &WcSlot) -> WcRuntime {
        let generation = wc::runtime::next_generation();
        let rt = WcRuntime::start_with_connector(
            rig._relay.connector(format!("kao-{generation}")),
            generation,
            wc::RouteKind::Loopback,
        )
        .await
        .expect("Kao's runtime starts on the in-process relay");
        assert!(slot.install(rt.clone()).is_ok(), "the slot takes it");
        rt
    }

    /// The hold on an unmined execution's nonce outlives the runtime that made it: turned off and
    /// paired again, the dapp's next Safe transaction still waits rather than pin the same nonce
    /// with "Sign & execute now" — and so it does after a lock.
    #[tokio::test]
    async fn the_execution_hold_outlives_the_runtime() {
        let mut rig = start_rig().await;
        let (mut s, _session, mut call_a, safe_addr) = safe_tx_review(&rig, 1).await;
        let key_a = review_key(&s);
        assert!(s.dispatch_wc(true).units() > 0);
        s.update(Message::Signed {
            tag: SignTag::WalletConnect {
                key: key_a.clone(),
                kind: WcSignKind::SafeExecute,
            },
            signer: None,
            result: Ok(SignOutcome::Tx(TxHash::repeat_byte(0xe1))),
        });
        answered(&mut call_a).await.expect("A answered");
        queue_read_lands(&mut s, safe_addr, Ok(Vec::new()));
        let identity = wc::WcIdentity::Safe {
            address: safe_addr,
            chain_id: Chain::Mainnet.chain_id(),
        };
        assert_eq!(rig.rt.with_book(|b| b.safe_exec_held(&identity)), Some(5));
        let _ = s.handle_wc_outcome(wc_app::Outcome::Stop);
        assert!(rig.rt.is_closed());
        rig.rt = restarted(&rig, &rig.slot).await;
        let session = connect(&mut s, &rig).await;
        let _call_b = dapp_request(
            &rig,
            &session.topic,
            "eth_sendTransaction",
            tx_params(safe_addr),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        let _ = s.pump_wc_queue();
        assert!(
            s.sign_review.is_none(),
            "B opened on a fresh runtime while A's execution at nonce 5 is unmined"
        );
        assert_eq!(rig.rt.with_book(|b| b.safe_exec_held(&identity)), Some(5));
        // A lock hands the next unlock a fresh slot: the hold is still there.
        let next = rig.slot.successor();
        if let Some(rt) = rig.slot.close() {
            rig.slot.spawn_teardown(rt);
        }
        let after_unlock = restarted(&rig, &next).await;
        assert_eq!(
            after_unlock.with_book(|b| b.safe_exec_held(&identity)),
            Some(5)
        );
    }

    /// The active account is a Ledger the dashboard holds open, and it isn't among the owners the
    /// ceremony opens — one of which is a Ledger, possibly the same device. Its connection is let
    /// go for the ceremony (and back afterwards), never held beside the owner's.
    #[test]
    fn a_live_active_ledger_that_isnt_an_owner_is_let_go_for_a_ledger_owner() {
        let active = PrivateKeySigner::random();
        let owner = Address::repeat_byte(0x77);
        let mut s = screen(
            vec![ledger_account(active.address()), ledger_account(owner)],
            0,
            vec![safe(0x5a, 1, &[owner], vec![1], 1)],
        );
        // It connected earlier: the dashboard holds its live signer (a local key stands in).
        s.signer = KaoSigner::Local(active.clone());
        s.test_enter_safe_mode(0);
        assert!(s.signer.can_sign() && s.signer.address() == s.address);
        let owners = [ledger_account(owner)];
        let opts = s.wc_owner_sign_opts(&owners, crate::safe::tx::OwnerSigMode::Eip712);
        assert!(
            !s.signer.can_sign(),
            "the dashboard still holds the active Ledger"
        );
        let opened: Vec<&AccountDescriptor> = owners.iter().collect();
        let let_go = crate::ui::wallet_dashboard::let_go_of_parked_ledger(&opts, &owners, &opened);
        assert_eq!(
            let_go.as_ref().and_then(account_address),
            Some(active.address())
        );
    }

    // ── items from an older runtime are dropped ──────────────────────────

    #[tokio::test]
    async fn stale_generation_items_are_dropped() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let _call = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(a.address()),
        );
        let (generation, item) = next_request(&mut s, &rig.rt).await;
        let (task, outcome) = s.handle_wc_msg(WcMsg::Stream {
            generation: generation.wrapping_add(1),
            item: item.clone(),
        });
        assert_eq!(task.units(), 0);
        assert!(outcome.is_none());
        assert_eq!(waiting(&rig.rt), 0, "an old runtime's item touches nothing");
        s.handle_wc_msg(WcMsg::Stream { generation, item });
        assert_eq!(
            waiting(&rig.rt),
            1,
            "the current runtime's item is admitted"
        );
    }

    // ── answers survive rebuilds and off-screen completion ──────────────

    /// A personal_sign the dapp is waiting on, claimed for signing on `s` (as a confirmed
    /// dispatch would, without running the device).
    async fn signing_request(
        s: &mut WalletScreen,
        rig: &Rig,
        from: Address,
    ) -> (wc::WcKey, DappCall) {
        let session = connect(s, rig).await;
        let call = dapp_request(rig, &session.topic, "personal_sign", personal_params(from));
        feed_until(s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        let key = review_key(s);
        let seq = review(s).seq;
        assert!(rig.rt.with_book(|b| b.mark_signing(&key, seq)));
        (key, call)
    }

    #[tokio::test]
    async fn respond_survives_switch_outcome() {
        let rig = start_rig().await;
        let (a, b) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let accounts = vec![local_account(&a), local_account(&b)];
        let mut s = screen(accounts.clone(), 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let (key, mut call) = signing_request(&mut s, &rig, a.address()).await;
        // The user switched account: App drops this dashboard (and its task) and builds a new one.
        drop(s);
        let mut s2 = screen(accounts, 1, Vec::new());
        s2.set_wc_slot(rig.slot.clone());
        assert_eq!(
            state(&rig.rt, &key),
            Some(wc::QueueState::Signing {
                seq: match state(&rig.rt, &key) {
                    Some(wc::QueueState::Signing { seq }) => seq,
                    other => panic!("still signing, got {other:?}"),
                }
            }),
            "a rebuild never interrupts a signature in flight"
        );
        let sig = Bytes::from(vec![0x1b; 65]);
        let task = s2.wc_on_signed(
            key,
            WcSignKind::Personal,
            Ok(SignOutcome::Signature(sig.clone())),
        );
        drop(task); // the answer does not ride an iced Task
        assert_eq!(
            answered(&mut call).await.expect("a result"),
            json!(format!("0x{}", alloy::hex::encode(&sig)))
        );
    }

    #[tokio::test]
    async fn orphan_signed_is_answered() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let (key, mut call) = signing_request(&mut s, &rig, a.address()).await;
        // The screen changed (hardware reconnect, add-account) before the result landed.
        drop(s);
        let sig = Bytes::from(vec![0x1c; 65]);
        handle_orphan_message(
            Message::Signed {
                tag: SignTag::WalletConnect {
                    key: key.clone(),
                    kind: WcSignKind::Personal,
                },
                signer: None,
                result: Ok(SignOutcome::Signature(sig.clone())),
            },
            &rig.slot,
        );
        assert_eq!(
            answered(&mut call).await.expect("a result"),
            json!(format!("0x{}", alloy::hex::encode(&sig)))
        );
        assert_eq!(state(&rig.rt, &key), None);
        // Anything else that lands off-screen is ignored.
        handle_orphan_message(Message::Tick, &rig.slot);
    }

    #[tokio::test]
    async fn orphan_failure_answers_32603() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let (key, mut call) = signing_request(&mut s, &rig, a.address()).await;
        drop(s);
        handle_orphan_message(
            Message::Signed {
                tag: SignTag::WalletConnect {
                    key,
                    kind: WcSignKind::Personal,
                },
                signer: None,
                result: Err("the Ledger was unplugged".into()),
            },
            &rig.slot,
        );
        assert_eq!(
            peer_code(&answered(&mut call).await),
            Some(wc::codes::INTERNAL)
        );
    }

    #[tokio::test]
    async fn set_wc_slot_releases_stranded_reviews() {
        let rig = start_rig().await;
        let (a, b) = (PrivateKeySigner::random(), PrivateKeySigner::random());
        let accounts = vec![local_account(&a), local_account(&b)];
        let mut s = screen(accounts.clone(), 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let mut call = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        let key = review_key(&s);
        assert!(matches!(
            state(&rig.rt, &key),
            Some(wc::QueueState::InReview { .. })
        ));
        // Rebuilt for another account: the overlay is gone, the request waits again.
        drop(s);
        let mut s2 = screen(accounts, 1, Vec::new());
        s2.set_wc_slot(rig.slot.clone());
        assert_eq!(state(&rig.rt, &key), Some(wc::QueueState::Waiting));
        assert!(s2.sign_review.is_none(), "not this identity's request");
        assert_unanswered(&mut call).await;
    }

    // ── every signing review is fingerprinted ────────────────────────────

    fn has_fingerprints(r: &SignReview) -> bool {
        r.steps
            .iter()
            .any(|st| !sign_review::erc8213_rows(st).is_empty())
    }

    #[tokio::test]
    async fn every_signing_wc_review_has_a_fingerprinted_step() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        for (method, params) in [
            ("personal_sign", personal_params(a.address())),
            ("eth_signTypedData_v4", typed_params(a.address())),
            ("eth_sendTransaction", tx_params(a.address())),
        ] {
            let _call = dapp_request(&rig, &session.topic, method, params);
            feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
            s.pump_wc_queue();
            if let SignAction::WalletConnect {
                plan: WcSignPlan::EoaTx { plan, .. },
                ..
            } = &review(&s).action
            {
                let plan = plan.clone();
                deliver_prepared(&mut s, eoa_tx_steps(&plan, None, false));
            }
            assert!(
                has_fingerprints(review(&s)),
                "{method} review shows no fingerprint"
            );
            s.wc_on_cancel();
        }

        // And as a Safe: a message and a transaction.
        let rig = start_rig().await;
        let owner = PrivateKeySigner::random();
        let safe_addr = Address::from([0x5a; 20]);
        let mut s = screen(
            vec![local_account(&owner)],
            0,
            vec![safe(0x5a, 1, &[owner.address()], vec![0], 1)],
        );
        s.test_enter_safe_mode(0);
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let _msg = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(safe_addr),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        assert!(has_fingerprints(review(&s)), "Safe message");
        s.wc_on_cancel();
        let _tx = dapp_request(
            &rig,
            &session.topic,
            "eth_sendTransaction",
            tx_params(safe_addr),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        deliver_prepared(&mut s, vec![safe_exec_step(safe_addr, 5, 5, 0)]);
        assert!(has_fingerprints(review(&s)), "Safe transaction");
    }

    // ── a session's identity never silently changes ─────────────────────

    #[tokio::test]
    async fn account_switch_keeps_binding() {
        let mut rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(
            vec![local_account(&a)],
            0,
            vec![safe(0x5a, 1, &[a.address()], vec![0], 1)],
        );
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let bound = wc::WcIdentity::Eoa {
            address: a.address(),
        };
        let mut call = dapp_request(
            &rig,
            &session.topic,
            "personal_sign",
            personal_params(a.address()),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        let key = review_key(&s);
        // Into the Safe, in place: the open review goes back to waiting, unanswered.
        s.activate_safe(0);
        s.wc_on_identity_changed();
        assert!(s.sign_review.is_none());
        assert_eq!(state(&rig.rt, &key), Some(wc::QueueState::Waiting));
        s.pump_wc_queue();
        assert!(s.sign_review.is_none(), "not reviewable as the Safe");
        assert_eq!(
            rig.rt
                .with_book(|b| b.session(&session.topic).map(|x| x.identity)),
            Some(bound),
            "the session stays bound to the account it was approved for"
        );
        // Kao never tells the dapp about the switch.
        let silent = tokio::time::timeout(SILENCE, async {
            loop {
                match rig.dapp_events.recv().await {
                    Some(SignEvent::SessionEvent { .. } | SignEvent::SessionUpdate { .. }) => {
                        return;
                    }
                    Some(_) => continue,
                    None => std::future::pending::<()>().await,
                }
            }
        })
        .await;
        assert!(silent.is_err(), "no accountsChanged / session update");
        assert_unanswered(&mut call).await;
        // Back on the account: it opens again.
        s.exit_safe_mode();
        s.wc_on_identity_changed();
        s.pump_wc_queue();
        assert_eq!(review_key(&s), key);
    }

    // ── hardware disclosures, Safe below threshold ──────────────────────

    #[tokio::test]
    async fn trezor_typed_refused_and_toasted() {
        let rig = start_rig().await;
        let trezor = Address::repeat_byte(0x44);
        let mut s = screen(vec![trezor_account(trezor)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let mut call = dapp_request(
            &rig,
            &session.topic,
            "eth_signTypedData_v4",
            typed_params(trezor),
        );
        let (generation, item) = next_request(&mut s, &rig.rt).await;
        let (_, outcome) = s.handle_wc_msg(WcMsg::Stream { generation, item });
        assert!(
            matches!(&outcome, Some(Outcome::Notice(t)) if t.contains("Trezor")),
            "the user hears why: {outcome:?}"
        );
        assert_eq!(
            peer_code(&answered(&mut call).await),
            Some(wc::codes::UNSUPPORTED_METHOD)
        );
        assert_eq!(waiting(&rig.rt), 0, "nothing queued");
        s.pump_wc_queue();
        assert!(s.sign_review.is_none());
    }

    #[tokio::test]
    async fn ledger_typed_hash_mode_disclosed() {
        let rig = start_rig().await;
        let ledger = Address::repeat_byte(0x33);
        let mut s = screen(vec![ledger_account(ledger)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let _call = dapp_request(
            &rig,
            &session.topic,
            "eth_signTypedData_v4",
            typed_params(ledger),
        );
        feed_until(&mut s, &rig.rt, |_| waiting(&rig.rt) == 1).await;
        s.pump_wc_queue();
        let r = review(&s);
        assert!(
            r.show_fingerprints,
            "the hashes the device shows are on screen at open"
        );
        assert_eq!(r.confirm_label.as_deref(), Some("Sign on Ledger"));
        assert!(
            r.steps
                .iter()
                .any(|st| matches!(st, SignStep::WcTyped(t) if t.hash_mode_device))
        );
        assert!(matches!(
            &r.action,
            SignAction::WalletConnect {
                plan: WcSignPlan::Typed { .. },
                ..
            }
        ));
    }

    #[tokio::test]
    async fn safe_threshold2_local1_proposes_only() {
        let rig = start_rig().await;
        let (mut s, _session, mut call, _) = safe_tx_review(&rig, 2).await;
        let (req, can_execute) = safe_plan(&s);
        assert!(!can_execute, "one of two keys can't execute");
        assert_eq!(req.prepared, Some((5, B256::repeat_byte(0x5e))));
        let r = review(&s);
        assert_eq!(r.confirm_label.as_deref(), Some("Propose to co-signers"));
        assert_eq!(r.secondary_label, None);
        assert!(r.note.as_deref().is_some_and(|n| n.contains("safeTxHash")));
        // Confirm proposes.
        s.dispatch_wc(true);
        assert!(matches!(
            review(&s).signing_progress,
            Some(SigningKind::SafePropose { .. })
        ));
        assert_unanswered(&mut call).await;
    }

    // ── retire: the reason reaches the user ──────────────────────────────

    /// A `wc:` link whose dapp never answers (closed dialog, wrong project id).
    fn dead_link() -> String {
        format!(
            "wc:{}@2?relay-protocol=irn&symKey={}&expiryTimestamp={}",
            alloy::hex::encode(B256::random()),
            alloy::hex::encode(B256::random()),
            wc::now_secs() + 300
        )
    }

    fn fresh_link() -> String {
        format!(
            "wc:{}@2?relay-protocol=irn&symKey={}",
            alloy::hex::encode(B256::random()),
            alloy::hex::encode(B256::random())
        )
    }

    fn pane_texts(s: &mut WalletScreen) -> Vec<String> {
        let theme = crate::ui::kao_theme::KaoTheme::for_kind(crate::ui::kao_theme::ThemeKind::Mint);
        super::super::test_support::texts(s.apps.wc_pane().view(theme))
    }

    /// A relay start in flight shows on a dashboard rebuilt meanwhile, not only on the one that
    /// began it: Connect waits (and the pasted link stays in the field) rather than take a link
    /// the old start would never pair. A link that reaches the dashboard anyway is answered, not
    /// dropped silently. Once the start ends — its result went to the old dashboard — Connect is
    /// back.
    #[test]
    fn a_start_in_flight_shows_on_a_rebuilt_dashboard() {
        let a = PrivateKeySigner::random();
        let slot = WcSlot::new();
        assert!(slot.begin_start(), "the old dashboard's start");
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(slot.clone());
        s.apps
            .wc_pane()
            .update(wc_app::Message::UriChanged(SecretInput::from(dead_link())));
        assert!(
            pane_texts(&mut s)
                .iter()
                .any(|t| t.contains("Connecting to the relay")),
            "{:?}",
            pane_texts(&mut s)
        );
        assert!(
            s.apps.wc_pane().update(wc_app::Message::Connect).is_none(),
            "Connect waits for the start"
        );

        let (task, outcome) = s.handle_wc_outcome(wc_app::Outcome::Pair {
            uri: SecretInput::from(dead_link()),
        });
        assert_eq!(task.units(), 0);
        assert!(
            matches!(&outcome, Some(Outcome::Notice(t)) if t.contains("still connecting")),
            "{outcome:?}"
        );
        assert!(slot.is_starting());

        slot.start_failed();
        s.wc_mirror();
        assert!(
            s.apps.wc_pane().update(wc_app::Message::Connect).is_some(),
            "Connect is back once the start ended"
        );
    }

    /// A relay that can't be reached is said once: the runtime's own "Couldn't reach the relay: …"
    /// is what the user reads, not wrapped in a second copy of itself.
    #[tokio::test]
    async fn an_unreachable_relay_is_said_once() {
        let slot = WcSlot::new();
        assert!(slot.begin_start());
        let cfg = wc::runtime::WcConfig {
            relay_url: url::Url::parse("ws://127.0.0.1:1").expect("url"),
            project_id: None,
            route: wc::Route::Direct,
            generation: wc::runtime::next_generation(),
        };
        let shown = start_and_pair(slot.clone(), cfg, zeroize::Zeroizing::new(fresh_link()))
            .await
            .expect_err("nothing listens there");
        assert!(shown.starts_with("Couldn't reach the relay: "), "{shown}");
        assert_eq!(
            shown.matches("Couldn't reach the relay").count(),
            1,
            "{shown}"
        );
        assert!(!slot.is_starting() && slot.get().is_none());
    }

    /// The bad-project-id case: a paste waits, the relay keeps closing, the flap detector retires
    /// the runtime. Its reason is a toast, the pane stops showing the dead runtime, and Connect
    /// takes a fresh link — with every item the stream still delivers fed as the subscription would.
    #[tokio::test]
    async fn flap_retire_reason_reaches_the_user_and_frees_connect() {
        use futures::StreamExt;
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        s.handle_wc_outcome(wc_app::Outcome::Pair {
            uri: SecretInput::from(dead_link()),
        });
        feed_until(&mut s, &rig.rt, |_| {
            matches!(
                rig.rt.snapshot(wc::now_secs()).pairing,
                wc::PairingState::Waiting { .. }
            )
        })
        .await;
        s.wc_mirror();
        let src = rig.rt.events();
        rig.rt.retire(wc::book::FLAP_RETIRE_REASON);
        let mut toasts = Vec::new();
        let mut stream = std::pin::pin!(wc::runtime::event_stream(&src));
        while let Ok(Some((generation, item))) =
            tokio::time::timeout(Duration::from_millis(300), stream.next()).await
        {
            let (_, o) = s.handle_wc_msg(WcMsg::Stream { generation, item });
            toasts.extend(o);
        }
        let (_, o) = s.update(Message::Tick);
        toasts.extend(o);
        assert!(
            matches!(toasts.as_slice(), [Outcome::Notice(t)] if t == wc::book::FLAP_RETIRE_REASON),
            "the diagnostic is toasted once: {toasts:?}"
        );
        let texts = pane_texts(&mut s);
        assert!(
            !texts.iter().any(|t| t.contains("Waiting for the dapp")),
            "{texts:?}"
        );
        assert!(
            texts.iter().any(|t| t == wc::book::FLAP_RETIRE_REASON),
            "the pane says why: {texts:?}"
        );
        s.apps
            .wc_pane()
            .update(wc_app::Message::UriChanged(SecretInput::from(fresh_link())));
        assert!(
            s.apps.wc_pane().update(wc_app::Message::Connect).is_some(),
            "Connect takes a fresh link"
        );
    }

    /// iced drops the stream on the first update after the runtime left the slot — possibly
    /// before it polled the retire's items. The reason still reaches the user, once.
    #[tokio::test]
    async fn retire_reason_survives_a_cancelled_subscription() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        rig.rt.retire(wc::book::FLAP_RETIRE_REASON);
        assert!(s.wc_subscriptions().is_empty(), "the stream goes now");
        let (_, outcome) = s.update(Message::Tick);
        assert!(
            matches!(&outcome, Some(Outcome::Notice(t)) if t == wc::book::FLAP_RETIRE_REASON),
            "{outcome:?}"
        );
        let (_, again) = s.update(Message::Tick);
        assert!(again.is_none(), "once");
    }

    /// The idle retire is no error (no toast), but the pane says why the relay is off.
    #[tokio::test]
    async fn idle_retire_is_explained_on_the_pane() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        rig.rt.retire(wc::book::IDLE_RETIRE_REASON);
        let (_, outcome) = s.update(Message::Tick);
        assert!(outcome.is_none(), "{outcome:?}");
        let texts = pane_texts(&mut s);
        assert!(
            texts.iter().any(|t| t == wc::book::IDLE_RETIRE_REASON),
            "{texts:?}"
        );
        assert!(!texts.iter().any(|t| t == "Turn off WalletConnect"));
    }

    // ── the book alone decides refusal toasts ────────────────────────────

    #[tokio::test]
    async fn refused_method_toasts_respect_the_book_throttle() {
        let rig = start_rig().await;
        let trezor = Address::repeat_byte(0x44);
        let mut s = screen(vec![trezor_account(trezor)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let session = connect(&mut s, &rig).await;
        let mut toasts = Vec::new();
        let mut calls = Vec::new();
        for _ in 0..6 {
            calls.push(dapp_request(
                &rig,
                &session.topic,
                "eth_signTypedData_v4",
                typed_params(trezor),
            ));
            let (generation, item) = next_request(&mut s, &rig.rt).await;
            let (_, outcome) = s.handle_wc_msg(WcMsg::Stream { generation, item });
            if let Some(Outcome::Notice(t)) = outcome {
                toasts.push(t);
            }
        }
        for mut c in calls {
            assert_eq!(
                peer_code(&answered(&mut c).await),
                Some(wc::codes::UNSUPPORTED_METHOD)
            );
        }
        assert_eq!(toasts.len(), 1, "six refusals in 10 s: {toasts:?}");
        assert!(
            toasts[0].contains("eth_signTypedData_v4") && toasts[0].contains("Trezor"),
            "{toasts:?}"
        );
    }

    /// A toast the book raised is already in its Activity ring. Delivered late (buffered while
    /// another screen was up, well past any "same moment" window), it is shown and never
    /// recorded a second time.
    #[tokio::test]
    async fn a_late_book_toast_is_not_recorded_twice() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        let text = "app.example stopped waiting before Kao's answer reached it.".to_string();
        let raised_at = wc::now_secs().saturating_sub(30);
        rig.rt
            .with_book(|b| b.push_notice(text.clone(), true, raised_at));
        let (_, outcome) = s.handle_wc_msg(WcMsg::Stream {
            generation: rig.rt.generation(),
            item: wc::WcStreamItem::Ui(wc::UiEffect::Notice { text: text.clone() }),
        });
        assert!(
            matches!(&outcome, Some(Outcome::Notice(t)) if *t == text),
            "{outcome:?}"
        );
        let recorded = rig.rt.with_book(|b| {
            b.snapshot(wc::now_secs())
                .notices
                .iter()
                .filter(|n| n.text == text)
                .count()
        });
        assert_eq!(recorded, 1);
    }

    // ── a fresh link supersedes a paste still waiting ────────────────────

    #[tokio::test]
    async fn a_fresh_link_supersedes_a_waiting_paste() {
        let rig = start_rig().await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        s.handle_wc_outcome(wc_app::Outcome::Pair {
            uri: SecretInput::from(dead_link()),
        });
        feed_until(&mut s, &rig.rt, |_| {
            matches!(
                rig.rt.snapshot(wc::now_secs()).pairing,
                wc::PairingState::Waiting { .. }
            )
        })
        .await;
        s.wc_mirror();
        let ns = ProposalNamespace::new(["eip155:1"], METHODS, ["chainChanged", "accountsChanged"]);
        let resp = rig
            .dapp
            .connect(ConnectParams {
                optional_namespaces: BTreeMap::from([("eip155".to_string(), ns)]),
                ..Default::default()
            })
            .await
            .expect("dapp connect");
        let fresh = resp.uri.as_ref().expect("a fresh pairing").to_string();
        s.apps
            .wc_pane()
            .update(wc_app::Message::UriChanged(SecretInput::from(fresh)));
        let Some(pair) = s.apps.wc_pane().update(wc_app::Message::Connect) else {
            panic!("Connect is live for a fresh link while the old paste waits");
        };
        s.handle_wc_outcome(pair);
        assert!(
            !pane_texts(&mut s)
                .iter()
                .any(|t| t.contains("Finish the current connection request first.")),
            "the coordinator took it"
        );
        feed_until(&mut s, &rig.rt, |_| rig.rt.card_proposal().is_some()).await;
        assert_eq!(
            rig.rt.card_proposal().map(|p| p.pairing_topic),
            Some(resp.pairing_topic),
            "the fresh link's card"
        );
    }

    /// A link from the rig's dapp, and the dapp's side of the connection it proposes.
    async fn dapp_link(rig: &Rig) -> (String, wallet_connect::sign::ConnectResponse) {
        let ns = ProposalNamespace::new(["eip155:1"], METHODS, ["chainChanged", "accountsChanged"]);
        let resp = rig
            .dapp
            .connect(ConnectParams {
                optional_namespaces: BTreeMap::from([("eip155".to_string(), ns)]),
                ..Default::default()
            })
            .await
            .expect("dapp connect");
        let uri = resp.uri.as_ref().expect("a fresh pairing").to_string();
        (uri, resp)
    }

    /// WalletConnect already runs, dialled directly, when the user turns Kao's proxy on: that
    /// applies from the next launch, and a start now would be refused for it. No new dapp is
    /// connected over the running relay meanwhile — a paste fails closed before it reaches the
    /// relay, and so does approving a card shown before the switch.
    #[tokio::test]
    async fn a_pending_proxy_restart_connects_no_new_dapp_over_a_direct_relay() {
        let rig = start_rig_on(wc::RouteKind::Direct).await;
        let a = PrivateKeySigner::random();
        let mut s = screen(vec![local_account(&a)], 0, Vec::new());
        s.set_wc_slot(rig.slot.clone());
        // A card shown while the proxy was still off.
        let (uri, _first) = dapp_link(&rig).await;
        s.wc_pair(SecretInput::from(uri), false);
        feed_until(&mut s, &rig.rt, |_| rig.rt.card_proposal().is_some()).await;
        let proposal = rig.rt.card_proposal().expect("the card");
        let identity = s.wc_active_identity().expect("the account");
        let chains = wc::namespaces::plan_proposal(
            &proposal,
            &s.wc_caps(&identity).expect("caps"),
            &wc::chain_label,
        )
        .verdict
        .expect("a grantable proposal")
        .chains;
        // The proxy is on now: Connect on that card binds nothing.
        s.wc_approve(proposal.id, identity, chains, true);
        assert_eq!(
            rig.rt
                .with_book(|b| b.proposal().and_then(|c| c.error.clone()))
                .as_deref(),
            Some(wc::RESTART_FOR_PROXY)
        );
        assert!(
            rig.rt.with_book(|b| b.sessions().is_empty()),
            "nothing bound"
        );
        s.handle_wc_outcome(wc_app::Outcome::RejectProposal {
            proposal_id: proposal.id,
        });
        feed_until(&mut s, &rig.rt, |_| rig.rt.card_proposal().is_none()).await;
        // A new link isn't paired at all.
        let (uri, second) = dapp_link(&rig).await;
        s.wc_pair(SecretInput::from(uri), true);
        assert!(
            pane_texts(&mut s)
                .iter()
                .any(|t| t == wc::RESTART_FOR_PROXY),
            "the pane says why"
        );
        assert!(
            !matches!(
                rig.rt.snapshot(wc::now_secs()).pairing,
                wc::PairingState::Pairing { ref topic, .. }
                    | wc::PairingState::Waiting { ref topic, .. }
                    if *topic == second.pairing_topic
            ),
            "the link never reached the relay"
        );
        let carded = tokio::time::timeout(
            SILENCE,
            feed_until(&mut s, &rig.rt, |_| rig.rt.card_proposal().is_some()),
        )
        .await;
        assert!(carded.is_err(), "no card for the new dapp");
    }
}
