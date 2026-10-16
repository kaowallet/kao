//! Unified **sign-review gate** — the clear-signing confirmation surface every
//! app signature passes through before the key is ever touched.
//!
//! The Send flow already clear-signs its transactions (decode → `function_panel`).
//! The two in-app surfaces — CoW Swap and the Names registrar — used to sign with
//! no decoded review at all (CoW signed its EIP-712 order the moment the user hit
//! "Place order"; Names blind-signed every registrar call behind a thin "verify
//! the contract" card). This overlay closes that gap: the coordinator *prepares*
//! the exact bytes the user is about to authorize, decodes every raw transaction
//! through the same `decode_transaction` pipeline Send uses, and renders them here
//! with an explicit **Confirm & sign** / **Cancel** gate. Only on Confirm does the
//! coordinator run the (unchanged) signing task.
//!
//! It renders as the top-most `stack!` layer over whatever app is active, so it
//! works identically for the Swap modal, the Apps-pane composer, and the Names
//! pane without any of them losing their own state on Cancel.
//!
//! Two kinds of thing get reviewed:
//! - **Raw transactions** ([`ReviewLeg`]) — ERC-20 approvals, the EthFlow
//!   `createOrder` call, and every registrar call (commit/register/renew/setAddr).
//!   These carry a full [`DecodeResult`] rendered by [`function_panel`].
//! - **The CoW EIP-712 order** ([`OrderReview`]) — *not* calldata, so it can't go
//!   through `function_panel`; it gets a purpose-built panel spelling out every
//!   signed field (sell/buy/receiver/min-received/expiry/kind/fee/settlement).

use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::primitives::{Address, B256, Bytes, U256};
use iced::keyboard;
use iced::widget::{Space, button, column, container, row, scrollable, text};
use iced::{Alignment, Element, Length, Padding};

use crate::chain::Chain;
use crate::cow::api::QuoteResponse;
use crate::cow::composer::SwapDraft;
use crate::decode::clear_sign::DecodeResult;
use crate::names::registrar::{Namespace, RegisterPlan};
use crate::sign::digest::{
    self, CALLDATA_DIGEST_LABEL, COW_ORDER_DIGEST_LABEL, DOMAIN_HASH_LABEL, EIP712_DIGEST_LABEL,
    Eip712Digests, INNER_CALLDATA_DIGEST_LABEL, MESSAGE_HASH_LABEL,
};
use crate::sign::typed::{IntoTypedModel, TypedDataModel, TypedRow, TypedValue};
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    bold, bullet_wave, colored_address, colored_hash_copyable, kao_scrollable_style, modal_wrapper,
    mono, mono_bold, mono_box, primary_button, secondary_button,
};
use crate::wallet::tx::{SendPlan, TxQuote};
use crate::walletconnect::{
    CheckedTyped, DappLabel, GasNote, IgnoredTxFields, MessageShape, SiweCheck, UnconfirmedTx,
    WcIdentity, WcKey,
};

use super::CowHost;

/// WalletConnect review panels and their ERC-8213 rows. A child module so it
/// can use this module's private helpers (`kv`, `addr_kv`, `hash_row`,
/// `card`, `leg_card`, …) without widening them; its typed-data panel is its
/// own (`typed_panel_wc`).
mod wc;

const MODAL_WIDTH: f32 = 520.0;
const FORM_MAX_HEIGHT: f32 = 520.0;

/// Bytes per line of the hex dump raw signed bytes render as.
const HEX_DUMP_BYTES_PER_LINE: usize = 16;

/// A revert reason is whatever string the reverting contract chose — bounded for display.
const MAX_REVERT_REASON_CHARS: usize = 200;

/// Confirm is inert this long after a WalletConnect review becomes confirmable
/// (anti-clickjack): a dapp can make a review pop up under the user's cursor, so
/// a click already on its way must not land on Confirm.
pub const ARMING_DELAY: Duration = Duration::from_millis(1000);

#[derive(Debug, Clone)]
pub enum Message {
    Confirm,
    Cancel,
    BoxClickIgnored,
    Key(keyboard::Event),
    /// No-op published by a copyable address click so the dashboard's "Copied!"
    /// toast animation starts (a click changes no state otherwise). Ignored.
    AddressCopied,
    /// Expand/collapse the "for the paranoid" decoded-calldata block on a Send
    /// review step (the only interactive control inside a reviewed step).
    ToggleCalldata,
    /// Expand/collapse the "ERC-8213 fingerprints" section (Calldata Digest /
    /// EIP-712 Digest + Domain + Message hashes) shown on every reviewed step.
    ToggleFingerprints,
    /// Expand/collapse the breakdown under the "Network fee" and "Cost" cards
    /// (gas limit, fee caps, balance, how each figure is wrong). Warnings and
    /// the headline figures stay visible either way.
    ToggleFeeDetails,
    /// Expand/collapse an already-active delegation card for a known delegate
    /// (see [`DelegationReview::collapsible`]). Other delegation cards have no
    /// toggle.
    ToggleDelegation,
    /// The overlay's optional secondary action (Safe send: "Propose to
    /// co-signers", alongside the primary "Sign & execute"). Only emitted when a
    /// `secondary_label` is set.
    Secondary,
}

/// A single raw transaction the user will sign, decoded for review through the
/// same pipeline the Send screen uses.
#[derive(Debug, Clone)]
pub struct ReviewLeg {
    /// Human label for this leg, e.g. "Approve USDC for CoW" or "Register cow.eth".
    pub title: String,
    pub to: Address,
    pub value: U256,
    /// The network this leg broadcasts on. A [`NetworkId`] (not [`Chain`]) so a
    /// Transaction-Builder call on a user-defined custom network renders and
    /// signs on the right chain id; built-in flows pass `chain.into()`.
    pub net: crate::chain::NetworkId,
    /// The exact calldata this leg signs — retained (not just its decode) so the
    /// ERC-8213 Calldata Digest is computed over the real bytes. `DecodeResult`
    /// drops the raw input on its descriptor-matched (`ClearSigned`) path, so it
    /// can't be recovered from `decoded`. Empty for a pure value transfer.
    pub calldata: Bytes,
    pub decoded: Box<DecodeResult>,
    /// The calls a batch leg fans out into, each clear-signed on its own.
    ///
    /// A Transaction Builder batch signs one outer call — a Safe `multiSend(bytes)`
    /// delegatecall, or an EIP-7702 `executeBatch(Call[])` self-call — whose own
    /// decode says nothing a user can act on ("multiSend, 1 argument, 412 bytes").
    /// The sub-calls are recovered *from that outer calldata* (not from the queue
    /// it was built from) and decoded individually, so the panels the user reads
    /// are derived from the exact bytes being signed.
    ///
    /// Empty for an ordinary single-call leg.
    pub sub_legs: Vec<ReviewLeg>,
    /// Set when this leg calls the very account it executes as.
    ///
    /// For a Safe batch that is the multisig reconfiguring itself:
    /// `MultiSendCallOnly` is reached by `DELEGATECALL`, so every packed
    /// sub-call runs with the Safe as `msg.sender` — which is the one and only
    /// way to satisfy the `authorized` modifier on `addOwnerWithThreshold`,
    /// `changeThreshold`, `setGuard` and `enableModule`. A bundle pasted from
    /// a dapp can therefore carry a call that hands the Safe to someone else,
    /// and it renders as an ordinary leg addressed to a plain hex address.
    ///
    /// The string is what the call *changes*, in the user's terms. A self-call
    /// whose selector isn't one this wallet recognises still gets a value here
    /// — an unrecognised call to the account's own address is more alarming
    /// than a recognised one, not less.
    pub self_admin: Option<String>,
}

/// The EIP-7702 delegation an atomic EOA batch rides on.
///
/// A `SetCode` (type `0x04`) transaction carries a **second** signature the
/// transaction panel below it can't show: an authorization tuple over
/// `(chain_id, delegate, nonce)` that installs `delegate` as the account's
/// code. Two things make it worth its own card rather than a line on the tx:
/// it is signed separately (a Ledger prompts twice), and unlike the batch it
/// rides on, it **persists** — the account keeps running that code after this
/// transaction is mined.
///
/// The tuple's `nonce` is deliberately absent. It is bound at broadcast from
/// the account's live nonce (self-sponsored ⇒ outer nonce + 1) and is pure
/// replay protection; the fields a signer needs to check are the delegate and
/// the chain it's scoped to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationReview {
    /// The contract this account's code will point at.
    pub delegate: Address,
    /// Human label for the delegate, e.g. "EF Simple7702Account".
    pub delegate_label: String,
    /// The account being delegated.
    pub authority: Address,
    /// The chain the authorization is scoped to. Never 0 — a zero chain id in
    /// a 7702 authorization makes the delegation valid on *every* chain.
    pub chain_id: u64,
    pub net: crate::chain::NetworkId,
    /// True when the account already runs this delegate's code, so this
    /// transaction reuses the existing delegation and signs no new
    /// authorization at all.
    pub already_active: bool,
    /// The delegate the account runs *today*, whatever it is: `None` for an
    /// undelegated account, `Some(delegate)` for one already on the delegate
    /// this review installs, `Some(other)` for one running someone else's
    /// smart-account implementation.
    ///
    /// Unfiltered on purpose. This is the value the send path pins and
    /// re-checks against chain, and the three cases have to stay distinct to do
    /// that: collapsing "nothing installed" into "someone else's contract
    /// installed" is exactly the drift that used to slip through, because both
    /// answered `false` to the only question being asked. [`Self::replacing`]
    /// is the display-side reading of this field.
    pub incumbent: Option<Address>,
    /// The `nonce` the authorization commits to, resolved at prepare.
    ///
    /// Self-sponsored, so it is the outer transaction's nonce **+ 1**. Pinning
    /// it here is what gives this signature a digest at all: without a nonce
    /// there is no `signature_hash`, and the one signature in this wallet whose
    /// effect outlives its own transaction was also the only one the user could
    /// not check against their device. The send path re-reads the account's
    /// nonce and aborts if it moved, so the pin can't drift.
    ///
    /// `None` when `already_active` — nothing is signed, so nothing to commit.
    pub auth_nonce: Option<u64>,
    /// ERC-8213 digest of the authorization tuple, over `auth_nonce`.
    pub auth_digest: Option<B256>,
}

impl DelegationReview {
    /// The incumbent delegate *worth naming to the user* — some other wallet's
    /// smart-account implementation that signing here would displace.
    ///
    /// `None` for an undelegated account and for one already running
    /// [`Self::delegate`], because neither is being replaced by anything. A
    /// method rather than a second field: it is entirely determined by
    /// [`Self::incumbent`] and [`Self::delegate`], and two stored fields that
    /// must agree eventually don't.
    pub fn replacing(&self) -> Option<Address> {
        self.incumbent.filter(|d| *d != self.delegate)
    }

    /// True when this card is a revocation: the authorization targets the
    /// zero address, which EIP-7702 interprets as "clear the designator".
    pub fn is_revocation(&self) -> bool {
        self.delegate.is_zero()
    }

    /// The delegate's name when it is one this wallet recognises: its own
    /// [`EF_SIMPLE_7702_ACCOUNT`](crate::txbuilder::eip7702::EF_SIMPLE_7702_ACCOUNT)
    /// or a listed third-party implementation. `None` for anything else.
    pub fn known_delegate_name(&self) -> Option<&'static str> {
        use crate::txbuilder::eip7702;
        if self.delegate == eip7702::EF_SIMPLE_7702_ACCOUNT {
            Some("Ethereum Foundation Simple7702Account")
        } else {
            eip7702::third_party_delegate_name(self.delegate)
        }
    }

    /// True when the card may fold behind a toggle: the delegation is already
    /// in place (nothing is signed) and points at a delegate this wallet
    /// recognises. A fresh authorization, a replacement, a revocation, or an
    /// unrecognised delegate always renders in full.
    pub fn collapsible(&self) -> bool {
        self.already_active && !self.is_revocation() && self.known_delegate_name().is_some()
    }
}

/// The CoW GPv2 order the user signs as EIP-712 typed data. Every field here is a
/// field of the signed message (or derived from it) so the review matches the
/// signature byte-for-byte.
#[derive(Debug, Clone)]
pub struct OrderReview {
    pub chain: Chain,
    pub sell_amount: String,
    pub sell_symbol: String,
    pub buy_amount: String,
    pub buy_symbol: String,
    pub min_received: String,
    pub receiver: Address,
    /// Unix expiry (`validTo`).
    pub valid_to: u32,
    pub slippage_bps: u16,
    pub settlement: Address,
    /// Native-ETH (EthFlow) order — settles on-chain and costs gas, vs. a gasless
    /// off-chain ERC-20 order.
    pub native: bool,
    /// ERC-8213 digests of the CoW GPv2 order's own EIP-712 signature (domain =
    /// `cow_domain(chain)`, message = the `Order` struct). Computed from a
    /// byte-exact reconstruction of the signed order, so the EOA typed-data panel
    /// shows the Digest/Domain/Message the wallet actually signs.
    pub eip712: Eip712Digests,
}

impl IntoTypedModel for OrderReview {
    /// The exact rows the CoW order panel has always shown — now expressed as a
    /// generic [`TypedDataModel`] so `typed_panel` can render it (and any future
    /// EIP-712 message) uniformly. All unit/precision/relative-time formatting is
    /// done here, so the model stays render-only.
    fn to_typed_model(&self) -> TypedDataModel {
        TypedDataModel {
            type_name: "CoW order — EIP-712 signature".to_string(),
            headline: Some(format!(
                "Sell {} {} for at least {} {}",
                self.sell_amount, self.sell_symbol, self.min_received, self.buy_symbol
            )),
            rows: vec![
                TypedRow::text(
                    "You sell",
                    format!("{} {}", self.sell_amount, self.sell_symbol),
                ),
                TypedRow::text(
                    "Receive (est.)",
                    format!("{} {}", self.buy_amount, self.buy_symbol),
                ),
                TypedRow::text(
                    "Min received",
                    format!(
                        "{} {} · {} slippage",
                        self.min_received,
                        self.buy_symbol,
                        slippage_label(self.slippage_bps)
                    ),
                ),
                TypedRow::addr("Receiver", self.receiver),
                TypedRow::text("Order type", "Sell · fill-or-kill"),
                TypedRow::text("Solver fee", "taken from price (signed fee 0)"),
                TypedRow::text("Expires", format_expiry(self.valid_to)),
                TypedRow::addr("Settlement", self.settlement),
                TypedRow::text("Network", self.chain.display_name()),
                TypedRow::text(
                    "Settles",
                    if self.native {
                        "on-chain (native ETH) · costs gas"
                    } else {
                        "off-chain via solvers · gasless"
                    },
                ),
            ],
        }
    }
}

/// A Safe `execTransaction` the owners sign as EIP-712 (`SafeTx`). Wraps the
/// decoded **inner** call (EthFlow `createOrder` for a native swap, or the ERC-20
/// vault-relayer approve) plus the exact 32-byte `safeTxHash` each owner signs,
/// pinned at the nonce read when the review was prepared. Carries only public tx
/// fields + hashes — no key material.
#[derive(Debug, Clone)]
pub struct SafeExecReview {
    pub safe: Address,
    pub nonce: u64,
    pub threshold: u8,
    pub owner_count: u8,
    /// The exact 32 bytes each owner signs — identical to what `sign_owner` will
    /// consume at dispatch (nonce-pinned).
    pub safe_tx_hash: B256,
    /// ERC-8213 digests of the `SafeTx` EIP-712 signature. `eip712.digest` equals
    /// `safe_tx_hash` (both are `SafeTx::eip712_signing_hash`); the extra domain /
    /// message hashes let the fingerprints section show all three components.
    pub eip712: Eip712Digests,
    /// The decoded inner call the Safe will `execTransaction`. Always a raw tx, so
    /// it reuses [`ReviewLeg`] and its `leg_card` renderer verbatim.
    pub inner: Box<ReviewLeg>,
    /// The `SafeTx.operation` byte being signed: `0` = CALL, `1` = DELEGATECALL.
    ///
    /// The single field the Safe threat model turns on, and the overlay used
    /// to omit it — while `safe_tx_detail` has always shown co-signers a red
    /// banner for exactly this byte on exactly these transactions. A Ledger
    /// displays `operation: 1` on its screen; without this there was nothing
    /// on the host to compare it against.
    pub operation: u8,
    /// The Safe's transaction guard, when one is installed. A guard can reject
    /// any transaction at execution time and the revm preflight never runs it
    /// (see `txbuilder::sim::to_steps`), so a batch can read "preflight passed"
    /// and still revert after every owner has signed. Naming it is the honest
    /// minimum.
    pub guard: Option<Address>,
    /// The Safe's live nonce when this was prepared. Equal to `nonce` on an
    /// empty queue; lower when this transaction is being appended behind
    /// proposals co-signers have already filed.
    ///
    /// `execTransaction` accepts the current nonce and nothing else, so the gap
    /// is exactly the set of transactions that must execute before this one can
    /// — which makes it both a disclosure and the reason the execute button
    /// disappears while the queue is occupied.
    pub onchain_nonce: u64,
    /// The review-time dry run of the call(s) the Safe would make, when the prepare ran one — a
    /// WalletConnect dapp transaction, which no composer simulated first. `None` where the flow
    /// simulates elsewhere (the Transaction Builder's own preflight) or not at all.
    pub preflight: Option<crate::txbuilder::sim::BatchSimResult>,
    /// The account that sends `execTransaction` and pays its gas if this is executed now — the
    /// sender the chain shows, and for a dapp's transaction the account whose transaction hash
    /// the dapp receives. Set once the review knows execution is on offer; `None` while it isn't.
    pub executor: Option<SigningOwner>,
}

impl SafeExecReview {
    /// How many already-queued proposals this transaction sits behind.
    pub fn queued_ahead(&self) -> u64 {
        self.nonce.saturating_sub(self.onchain_nonce)
    }
}

/// A CoW ERC-20 order authorized via EIP-1271 (a Safe `SafeMessage`). The order
/// rows plus the exact `safe_message_hash(order_digest, safe, chain)` each owner
/// signs over the order digest. Nonce-free (a message hash, not a `SafeTx`).
#[derive(Debug, Clone)]
pub struct SafeMessageReview {
    pub order: OrderReview,
    pub safe: Address,
    pub threshold: u8,
    pub owner_count: u8,
    /// CoW EIP-712 order hash — what the orderbook validates the signature against.
    pub order_digest: B256,
    /// `safe_message_hash(order_digest, safe, chain)` — the 32 bytes each owner
    /// signs. A pure function of `(order_digest, safe, chain)`, so no pin needed.
    pub message_hash: B256,
    /// ERC-8213 digests of the `SafeMessage` EIP-712 signature the owners produce
    /// (domain = `safe_domain(safe, chain)`, message = the `SafeMessage` wrapping
    /// `order_digest`). `eip712.digest` equals `message_hash`.
    pub eip712: Eip712Digests,
}

/// Leads every WalletConnect review: who is asking (the dapp's host, never its
/// self-declared name), through which session, as which identity, on which
/// network. Informational — signs nothing, so it has no ERC-8213 rows.
#[derive(Debug, Clone)]
pub struct WcOriginCard {
    pub dapp: DappLabel,
    pub session_ordinal: u32,
    pub identity: WcIdentity,
    pub identity_label: String,
    /// "Local" | "Ledger" | "Trezor" | "Safe"
    pub identity_badge: &'static str,
    pub method: &'static str,
    pub net: crate::chain::NetworkId,
    pub unverified_network: bool,
    pub received_at: u64,
    /// The dapp's own expiry, uncapped.
    pub dapp_deadline: Option<u64>,
    /// Kao's own limit on an unsigned review: past it the request is answered "expired" and the
    /// review closes, however long the dapp would wait. It never applies once signing.
    pub kao_deadline: u64,
    pub waiting_behind: usize,
}

/// A dapp `personal_sign` (EIP-191) from an EOA: the exact bytes, how they
/// display, and the digest the key signs.
#[derive(Debug, Clone)]
pub struct MessageReview {
    pub from: Address,
    pub net: crate::chain::NetworkId,
    /// Exact signed bytes.
    pub raw: Bytes,
    pub shape: MessageShape,
    pub eip191_hash: B256,
    pub siwe: Option<SiweCheck>,
    pub hardware: bool,
}

/// Dapp EIP-712 typed data: the checked parse (domain, flat rows, kind, the
/// ERC-8213 triple) of the one object that is hashed and signed.
#[derive(Debug, Clone)]
pub struct TypedDataReview {
    pub from: Address,
    pub net: crate::chain::NetworkId,
    pub checked: CheckedTyped,
    /// Ledger EOA: the device shows only Domain Hash / Message Hash.
    pub hash_mode_device: bool,
    /// Kao's name for a SafeTx/SafeMessage `verifyingContract`, if it's one of the user's Safes.
    pub safe_label: Option<String>,
    /// A `SafeTx`'s call — the `to` / `value` / `data` this owner confirmation would have the Safe
    /// make — decoded the way a Safe transaction's inner call is (self-call and owner-action
    /// banners included). Attached once the prepare lands (`wc_on_prepared`), checked against the
    /// typed data's own fields; `None` for every other kind.
    pub inner_leg: Option<Box<ReviewLeg>>,
}

/// What a Safe is asked to sign as an EIP-1271 message.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // one per open review; not stored in bulk
pub enum WcSafeMessageInner {
    Personal(MessageReview),
    Typed(TypedDataReview),
}

/// A dapp message signed by a Safe (EIP-1271): the inner message, the
/// `SafeMessage` hash each local owner signs, and exactly which owners sign.
#[derive(Debug, Clone)]
pub struct WcSafeMessageReview {
    pub inner: WcSafeMessageInner,
    pub safe: Address,
    pub chain: Chain,
    pub threshold: u8,
    pub owner_count: u8,
    /// Exactly the local owners that will sign.
    pub signers: Vec<SigningOwner>,
    /// eip191(msg) or the dapp's EIP-712 digest.
    pub data_hash: B256,
    /// `cow::safe_sig::safe_message_hash(data_hash, safe, chain)` — what owners sign.
    pub message_hash: B256,
    /// `cow::safe_sig::safe_message_digests(data_hash, safe, chain)`.
    pub eip712: Eip712Digests,
}

/// The fee side of a dapp `eth_sendTransaction` from an EOA: the pinned quote and
/// how its gas limit was chosen. What the dapp asked for that Kao ignored is the review's note.
#[derive(Debug, Clone)]
pub struct WcTxFeesReview {
    /// Pinned by `wc_on_prepared` into `WcSignPlan::EoaTx.quote` (reviewed == signed).
    pub quote: crate::wallet::tx::TxQuote,
    pub gas_note: GasNote,
    /// value + gas_limit × max_fee_per_gas.
    pub max_total_wei: U256,
    pub balance_wei: Option<U256>,
    pub unverified_network: bool,
    pub sim_reverted: bool,
    /// Kao's node couldn't estimate the call — why, sanitized for display — so the quote took the
    /// dapp's own gas limit. The node expects this transaction to fail.
    pub estimate_failed: Option<String>,
}

/// One reviewable step in a signature. A review is an ordered list of these: an
/// EOA swap is `[Typed(order), RawTx(approve)…]`; a Safe swap is
/// `[SafeExec(approve)?, SafeMessage(order)]` or `[SafeExec(createOrder)]`; a
/// name/pool write is just raw-tx steps. Every step carries the exact artifact
/// (calldata or 32-byte hash) the user authorizes, so reviewed == signed.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum SignStep {
    /// A raw transaction the user signs (approval, EthFlow `createOrder`, a
    /// registrar call, a pool deposit), decoded for review.
    RawTx(ReviewLeg),
    /// The EIP-7702 authorization an atomic EOA batch installs, reviewed ahead
    /// of the transaction that carries it. Signed separately from the
    /// transaction, and outlives it.
    Delegation(DelegationReview),
    /// EIP-712 typed data the user signs (the CoW GPv2 order, EOA path).
    Typed(OrderReview),
    /// A Safe `execTransaction` (native `createOrder` / ERC-20 approve): the inner
    /// call plus the `safeTxHash` each owner signs.
    SafeExec(SafeExecReview),
    /// A CoW order authorized via EIP-1271 from a Safe: the order plus the
    /// `SafeMessage` hash each owner signs.
    SafeMessage(SafeMessageReview),
    /// An EOA send: the full inline review (intent, revm balance-change sim, gas,
    /// recipient, decoded call) snapshotted for the overlay. Carries the quote +
    /// plan that drive the broadcast, so reviewed == signed.
    Send(super::send::SendReview),
    /// A Safe send: the full Safe review (intent, revm balance-change sim,
    /// recipient, the exact `safeTxHash` each owner signs, the signing owner set)
    /// snapshotted for the overlay. The `SignAction::SafeSend` alongside it drives
    /// the execute/propose ceremony against the pinned hash.
    SafeSend(super::send::SafeSendReview),
    /// WalletConnect: who is asking. Leads every WC review; signs nothing.
    WcOrigin(WcOriginCard),
    /// WalletConnect `personal_sign` from an EOA.
    WcMessage(MessageReview),
    /// WalletConnect EIP-712 typed data from an EOA.
    WcTyped(TypedDataReview),
    /// WalletConnect message (personal or typed) signed by a Safe via EIP-1271.
    WcSafeMessage(WcSafeMessageReview),
    /// WalletConnect `eth_sendTransaction` fees (the call itself is a `RawTx`).
    WcTxFees(WcTxFeesReview),
}

/// Pins the reviewed Safe artifacts so `cow_place_order_safe` signs exactly what
/// the review displayed. `SafeTx` isn't `Clone`, so we pin the `nonce` (the tx
/// rebuild is pure + deterministic) plus the hashes for an equality assert. Copy
/// — plain scalars/hashes, no key material.
#[derive(Debug, Clone, Copy)]
pub struct CowSafePin {
    /// Nonce the reviewed `execTransaction` was built at (native `createOrder` or
    /// ERC-20 approve). Unused when `exec_hash` is `None`.
    pub exec_nonce: u64,
    /// safeTxHash shown for the `execTransaction`, if the review had one (native,
    /// or ERC-20 with a short allowance). `None` for an ERC-20 swap needing no
    /// approval.
    pub exec_hash: Option<B256>,
    /// `safe_message_hash` shown for the EIP-1271 order, if any (ERC-20 path).
    pub msg_hash: Option<B256>,
}

/// What a WalletConnect review signs, pinned so the sign task re-derives and
/// compares it (reviewed == signed). Message pins are fixed at open; the EOA
/// quote and the Safe `(nonce, safeTxHash)` are pinned once prepare lands.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum WcSignPlan {
    Personal {
        from: Address,
        message: Bytes,
        pin: B256,
    },
    Typed {
        from: Address,
        typed: Arc<alloy::dyn_abi::TypedData>,
        pin: Eip712Digests,
    },
    EoaTx {
        plan: crate::wallet::tx::SendPlan,
        dapp_gas: Option<u64>,
        ignored: IgnoredTxFields,
        /// None until prepared.
        quote: Option<crate::wallet::tx::TxQuote>,
        quoted_at: Option<Instant>,
        /// The transaction already signed for this request, which left the wallet without an
        /// acknowledgement (the runtime's record, copied when the review latches onto it). Once
        /// set, Confirm only ever sends these exact bytes again: nothing is quoted or signed anew.
        unconfirmed: Option<UnconfirmedTx>,
    },
    SafeTx {
        req: super::tx_builder::SafeBatchRequest,
        can_execute: bool,
        /// The executor's transaction already signed to execute this request, which left the
        /// wallet without an acknowledgement (the runtime's record, copied when the review latches
        /// onto it). Once set, Confirm only ever sends these exact bytes again: no owner signs
        /// anything anew, and nothing is proposed.
        unconfirmed: Option<UnconfirmedTx>,
    },
    SafeMessage {
        safe: Address,
        chain: Chain,
        threshold: u32,
        signable_indices: Vec<u32>,
        /// The owners the review listed as signing, in order. The ceremony signs with exactly
        /// these or refuses.
        owners: Vec<Address>,
        data_hash: B256,
        pin: B256,
    },
}

/// What the coordinator runs when the user confirms. Holds the fully-prepared
/// action (commit secret already minted, draft+quote captured) so the signed
/// transaction is exactly what was reviewed.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum SignAction {
    Cow {
        host: CowHost,
        draft: SwapDraft,
        quote: QuoteResponse,
        /// Filled once a Safe prepare task lands (scanned from the steps in the
        /// `SignReviewPrepared` handler). `None` for an EOA swap (nothing to pin).
        prepared: Option<CowSafePin>,
    },
    CowCancel {
        host: CowHost,
        uid: String,
    },
    Name {
        sign: NameSign,
    },
    PrivacyPool {
        sign: PoolSign,
    },
    /// An EOA send. `plan` is known when the review opens; `quote` is filled once
    /// the prepare task lands (gas / nonce / fees), and the two together drive the
    /// broadcast at confirm — the same numbers the `SignStep::Send` step displays.
    Send {
        plan: SendPlan,
        quote: Option<TxQuote>,
    },
    /// A Safe send. `req` describes the transfer; its `prepared` `(nonce,
    /// safeTxHash)` is filled once the prepare task lands, pinning what the owners
    /// sign. `can_execute` (the wallet holds a threshold of signable owners) picks
    /// whether the primary action is Execute-now (Confirm) with Propose as the
    /// secondary, or Propose-only.
    SafeSend {
        req: super::send::SafeSendRequest,
        can_execute: bool,
    },
    /// A Transaction Builder batch. The Safe variant signs one MultiSend
    /// `execTransaction` (its `prepared` `(nonce, safeTxHash)` pinned once the
    /// prepare task lands, `can_execute` picking sign-and-execute vs a blocked
    /// state); the EOA variant broadcasts a single call. Reuses the existing
    /// `SafeExec` / `RawTx` review steps for rendering.
    TxBuilder {
        req: super::tx_builder::BatchSignRequest,
        can_execute: bool,
        /// What the composer's revm preflight found. Advisory, but it decides
        /// whether the confirm button reads as a routine confirmation or as a
        /// deliberate override of a batch that is expected to revert.
        preflight: super::tx_builder::Preflight,
    },
    /// A WalletConnect dapp request, keyed `(topic, id)`; answered to the dapp
    /// exactly once by the coordinator, whatever the outcome.
    WalletConnect {
        key: WcKey,
        plan: WcSignPlan,
    },
}

/// A prepared Privacy Pools EOA transaction to sign. A deposit carries an
/// optional ERC-20 approve leg then the Entrypoint deposit; the calldata is
/// final (deposits need no proof), so the reviewed bytes == the signed bytes.
#[derive(Debug, Clone)]
pub enum PoolSign {
    Deposit {
        chain: Chain,
        symbol: String,
        /// The Entrypoint the deposit targets.
        to: Address,
        /// ETH sent for a native deposit, `0` for an ERC-20 deposit.
        value: U256,
        calldata: Bytes,
        /// `(token, approve calldata)` sent to the token before an ERC-20 deposit.
        approve: Option<(Address, Bytes)>,
    },
    /// Ragequit (original-depositor exit) — the commitment proof is already
    /// generated, so `calldata` is the final `Pool.ragequit(proof)`.
    Ragequit {
        chain: Chain,
        symbol: String,
        pool: Address,
        calldata: Bytes,
    },
}

/// A prepared name-registry write. Commit/Register carry the *minted* plan so the
/// reviewed commitment matches the later reveal.
#[derive(Debug, Clone)]
pub enum NameSign {
    Commit(RegisterPlan),
    Register(RegisterPlan),
    RegisterXns {
        namespace: String,
        label: String,
    },
    Renew {
        namespace: Namespace,
        label: String,
        years: u32,
    },
    SetRecipient {
        namespace: Namespace,
        label: String,
        recipient: Address,
    },
}

/// One owner the wallet will drive through a Safe signing ceremony. Display-only
/// — the label, address, and whether signing prompts a hardware device — so the
/// waiting card can tell the user how many device prompts to expect and on which
/// accounts, instead of a single generic "waiting for a signature".
#[derive(Debug, Clone)]
pub struct SigningOwner {
    pub label: String,
    pub address: Address,
    /// `true` for a Ledger/Trezor owner (the user must confirm on the device);
    /// `false` for a software owner (signs in-process, no prompt).
    pub hardware: bool,
}

/// The shape of the signing ceremony the overlay is waiting on. Snapshotted at
/// dispatch — the owner set is known then — so the waiting card can lay out a
/// multi-device Safe ceremony. The whole ceremony runs as one task that emits a
/// single result, so this is the *plan* the user is about to walk through, not a
/// live per-owner cursor. `None` on the review means "a single signature"
/// (EOA send, CoW, name/pool write): the plain waiting card.
#[derive(Debug, Clone)]
pub enum SigningKind {
    /// A Safe `execTransaction`: each `owners` entry signs the SafeTx on its own
    /// device in turn, then the transaction is broadcast — by `gas_payer`, a
    /// Local account that pays the gas, or without one by re-using the first
    /// owner (one extra prompt on that device).
    SafeExecute {
        owners: Vec<SigningOwner>,
        gas_payer: Option<SigningOwner>,
    },
    /// A Safe proposal: sign once as `owner` and POST to the Transaction Service
    /// for co-signers to finish from their own wallets.
    SafePropose { owner: SigningOwner },
    /// An atomic EOA batch via EIP-7702. Costs **two** device prompts when a
    /// fresh authorization is needed (the authorization, then the transaction
    /// carrying it) and one when the account is already delegated — a
    /// difference the waiting card used to paper over by saying "waiting for a
    /// signature" in both cases, so a second prompt appeared with nothing on
    /// the host having predicted it.
    Eip7702Batch { fresh_authorization: bool },
    /// An EIP-7702 revocation: one authorization to the zero address, then
    /// the empty type-`0x04` transaction that carries it. Always two
    /// signatures — there is no "already cleared" shortcut, because if the
    /// account were already a plain EOA the review would have refused.
    Eip7702Revoke,
    /// Signed and broadcast; waiting for the receipt that says whether it
    /// actually worked. The overlay stays up through this because a broadcast
    /// hash is not an outcome — a reverted transaction is broadcast exactly as
    /// successfully as one that succeeds.
    Broadcasting { hash: B256 },
    /// WalletConnect message signature(s): "Confirm the message on <device>"
    /// per owner; nothing extra for Local. `hash_mode`: a Ledger shows only the
    /// typed data's Domain Hash / Message Hash.
    WcMessage {
        owners: Vec<SigningOwner>,
        hash_mode: bool,
    },
}

/// Which way a netted balance change runs, relative to the signing account.
///
/// There is deliberately no third "moved between two other parties" variant.
/// Every row here is a change to *this* account's balance; a hop between third
/// parties nets out of the total, and is already visible on the leg that made
/// it. A card titled "this transaction moves" whose rows are a mix of the two
/// is one a user has to reconcile by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveDirection {
    /// Leaves the account that is signing.
    Out,
    /// Arrives at the account that is signing.
    In,
}

impl MoveDirection {
    fn prefix(self) -> &'static str {
        match self {
            Self::Out => "−",
            Self::In => "+",
        }
    }
}

/// One line of "what this transaction moves", already denominated for display.
///
/// Formatted at prepare time rather than at render time: resolving a token
/// contract to a symbol and decimals needs the live portfolio, which the
/// overlay's `view` does not have, and doing it once at prepare keeps the two
/// halves of `reviewed == signed` from drifting apart on a re-render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MovedAmount {
    /// Amount and symbol, e.g. `1,250.5 USDC`, `#4211 BAYC`, `0.4 ETH`.
    pub amount: String,
    pub direction: MoveDirection,
}

/// What a Transaction Builder batch is expected to move, and what it will cost.
///
/// The Builder was the one signing surface that showed neither: the batch
/// simulator has always computed the token transfers a batch performs and the
/// gas it meters, and both were dropped on the way to the overlay — so a user
/// signed a six-call DeFi batch on the strength of a green "Simulation passed"
/// strip and a call list, with no statement anywhere of what left their account
/// or what the transaction cost.
///
/// Every figure here is advisory and says so. The fee is a *base-fee* estimate
/// over *simulated* gas; [`Self::fee_excludes`] carries what it leaves out, and
/// the card renders it under a leading `≈`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchEconomics {
    /// Balance movements, signer-relative. Native value is derived from the
    /// calls themselves and is present even without a simulation; token rows
    /// come from the simulation's `Transfer` logs and are not.
    pub moves: Vec<MovedAmount>,
    /// Whether a successful simulation stands behind the token rows.
    ///
    /// Load-bearing, not decorative: when this is false an empty `moves` means
    /// "nothing is known about token movement", which must not be allowed to
    /// read as "this batch moves no tokens".
    pub simulated: bool,
    /// True when every read behind the simulation went through Helios's
    /// verified path.
    pub verified: bool,
    /// The simulation is old enough that it is no longer a statement about the
    /// state this batch will meet.
    ///
    /// Tracked here and not left to the note alone: verification and freshness
    /// are different properties, and a "✓ Verified by Helios" badge sitting
    /// over balance figures from twenty minutes ago vouches for the wrong one.
    pub stale: bool,
    /// Gas metered by the simulated sub-calls, and the base fee of the block
    /// they ran against. Zero for either means there is no fee to state.
    pub gas_used: u64,
    pub base_fee_per_gas: u64,
    /// How the fee figure is wrong, in the user's terms — in *both* directions,
    /// which is why these are caveats rather than a list of exclusions: the
    /// simulated gas under-counts the wrapper and the calldata, and over-counts
    /// the intrinsic 21 000 on every call past the first.
    ///
    /// Derived from the batch's shape and chain, so the list names only what
    /// actually applies — a list padded with inapplicable caveats is one users
    /// learn to skip.
    pub fee_caveats: Vec<String>,
}

impl BatchEconomics {
    /// The estimated fee in ETH, or `None` when no simulation produced a gas
    /// figure or the block carried no base fee — in which case the card omits
    /// the fee line rather than claiming a free transaction.
    pub fn fee_eth(&self) -> Option<String> {
        super::sim_view::format_gas_fee_eth(self.gas_used, self.base_fee_per_gas)
    }

    /// Nothing to say at all — no movements, no fee, and no caveats. The card
    /// is skipped entirely rather than rendering an empty box. A caveat-only
    /// card is still a card: an EIP-7702 revocation moves no tokens and has
    /// no simulated gas, but the caveat is the only place the review says
    /// the gas budget is a constant rather than an estimate.
    pub fn is_empty(&self) -> bool {
        self.moves.is_empty() && self.fee_eth().is_none() && self.fee_caveats.is_empty()
    }
}

/// Coordinator-held overlay state: what to show, and what to do on confirm.
#[derive(Debug, Clone)]
pub struct SignReview {
    pub title: String,
    pub subtitle: Option<String>,
    /// The reviewed steps, rendered top-to-bottom: an optional leading EIP-712
    /// typed-data step (a swap's order), then the decoded raw-tx legs. The order
    /// is known at open; the raw legs are appended when the prepare task lands.
    pub steps: Vec<SignStep>,
    /// True until the prepare task lands the decoded raw-tx legs.
    pub legs_loading: bool,
    /// A trailing context note (e.g. "gasless off-chain signature").
    pub note: Option<String>,
    /// Drops stale prepare results after the user has moved on.
    pub seq: u64,
    pub action: SignAction,
    /// Set once the user confirms and the signing task is in flight: the overlay
    /// stays open showing a "waiting for a signature" notice (so a hardware
    /// wallet prompt isn't left facing a blank screen) until the broadcast
    /// resolves. `None` before confirm; the elapsed time drives the animation.
    pub signing_since: Option<Instant>,
    /// A broadcast error surfaced back onto the still-open overlay (the Send flow
    /// keeps its review up so the user can read the failure and retry Confirm,
    /// rather than dropping them onto a blank host pane). `None` unless a dispatch
    /// resolved with an error.
    pub error: Option<String>,
    /// Overrides the "Confirm & sign" button label (e.g. the Send flow's
    /// "Sign & Send" / "Sign anyway ⚠" / "Need ETH for gas"). `None` → default.
    pub confirm_label: Option<String>,
    /// Blocks Confirm even once the steps are ready (e.g. a Send with too little
    /// ETH for gas). Independent of `legs_loading`.
    pub confirm_disabled: bool,
    /// When set, an optional second primary action rendered below Cancel/Confirm
    /// (the Safe send's "Propose to co-signers", alongside "Sign & execute").
    /// Emits [`Message::Secondary`]. Gated on `!legs_loading` like Confirm.
    pub secondary_label: Option<String>,
    /// The Secondary action stays live while `confirm_disabled` blocks Confirm. Set only for an
    /// action that signs nothing (WalletConnect's "Re-check", which re-runs a failed prepare).
    pub secondary_unblocked: bool,
    /// Expand state for the Send step's "for the paranoid" decoded-calldata block.
    pub show_calldata: bool,
    /// Expand state for the "ERC-8213 fingerprints" section on every reviewed
    /// step (the signature/calldata digests). One flag toggles them all together.
    pub show_fingerprints: bool,
    /// Expand state for the fee breakdown under the "Network fee" and "Cost"
    /// cards. One flag unfolds both: they sit together and answer one question.
    pub show_fee_details: bool,
    /// Expand state for a collapsible delegation card
    /// ([`DelegationReview::collapsible`]). Folded by default.
    pub show_delegation: bool,
    /// The ceremony the waiting card describes once signing is in flight. Set at
    /// dispatch for a multi-device Safe send (execute or propose) so the "waiting
    /// for a signature" card lays out the per-owner device prompts; `None` for a
    /// single-signature flow (the plain card). Cleared when a dispatch resolves.
    pub signing_progress: Option<SigningKind>,
    /// What this transaction moves and what it costs. Set by the Transaction
    /// Builder, which is the flow that had neither; `None` everywhere else,
    /// where the step's own renderer already carries it (the Send review's
    /// `TxQuote` + simulation block).
    pub economics: Option<BatchEconomics>,
    /// The hash of a transaction this review has already put on the wire.
    ///
    /// A **broadcast-once latch**: while it is set, Confirm is dead no matter
    /// what else happens to the overlay. A receipt that never arrived used to
    /// clear `signing_since`, drop the hash and hand the user back a live
    /// Confirm button under the words "not confirmed in time" — an invitation
    /// to sign and broadcast the same batch again while the first one sat in
    /// the mempool. Signing again is not a retry; it needs a fresh review
    /// against a fresh nonce, which is what closing this overlay gets you.
    pub broadcast: Option<B256>,
    /// `Some(t)` ⇒ Confirm / Secondary are inert until `t + ARMING_DELAY`. Set
    /// only by WalletConnect, when a review becomes confirmable (a review a dapp
    /// opened can appear under a click already on its way). `pending()` sets
    /// `None`, so every other flow is unaffected.
    pub armed_at: Option<Instant>,
    /// Set by WalletConnect after an owner's device refused the EIP-712 prompt
    /// for a Safe hash: Confirm then signs that hash as a personal message
    /// (`eth_sign`) instead, and the review shows what the device will. `None`
    /// everywhere else.
    pub owner_eth_sign: Option<OwnerEthSign>,
}

/// The `eth_sign` fallback a WalletConnect Safe review offers once an owner's
/// device refused the EIP-712 prompt: each owner signs the same 32-byte Safe
/// hash as an EIP-191 personal message (Safe accepts it, `v + 4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerEthSign {
    /// The Safe hash signed — the `SafeMessage` hash or the safeTxHash.
    pub hash: B256,
    /// Its EIP-191 personal-message digest, which a Ledger shows as the
    /// message hash: `keccak256("\x19Ethereum Signed Message:\n32" ‖ hash)`.
    pub eip191: B256,
}

impl OwnerEthSign {
    pub fn of(hash: B256) -> Self {
        Self {
            hash,
            eip191: alloy::primitives::eip191_hash_message(hash),
        }
    }
}

impl SignReview {
    /// Coarse phase name for the GUI state trace: "prepare" while the legs are
    /// still being built/decoded, "confirm" once they're shown and the gate is
    /// live, "signing" after the user confirmed and the signing task runs. The
    /// transitions themselves happen in the coordinator (`wallet_dashboard`),
    /// which diffs this name across its dispatch.
    pub fn phase(&self) -> &'static str {
        if self.signing_since.is_some() {
            "signing"
        } else if self.legs_loading {
            "prepare"
        } else {
            "confirm"
        }
    }

    /// Build a pending review whose legs are still being prepared.
    pub fn pending(
        title: String,
        subtitle: Option<String>,
        steps: Vec<SignStep>,
        note: Option<String>,
        seq: u64,
        action: SignAction,
    ) -> Self {
        let review = Self {
            title,
            subtitle,
            steps,
            legs_loading: true,
            note,
            seq,
            action,
            signing_since: None,
            error: None,
            confirm_label: None,
            confirm_disabled: false,
            secondary_label: None,
            secondary_unblocked: false,
            economics: None,
            broadcast: None,
            show_calldata: false,
            show_fingerprints: false,
            show_fee_details: false,
            show_delegation: false,
            signing_progress: None,
            armed_at: None,
            owner_eth_sign: None,
        };
        // Coordinator-driven open: every caller assigns this straight into the
        // overlay slot (guarded by an is-already-open early return), so the
        // open transition is traced at the one construction site.
        crate::trace::state("sign_review", "phase", "closed", review.phase());
        review
    }

    /// Whether Confirm / Secondary may act at `now`: always, unless the review
    /// is armed and [`ARMING_DELAY`] hasn't elapsed since.
    pub fn confirm_ready(&self, now: Instant) -> bool {
        self.armed_at
            .is_none_or(|t| now.saturating_duration_since(t) >= ARMING_DELAY)
    }

    /// Inside the arming window — the overlay keeps its animation tick running
    /// so Confirm visibly comes alive when it ends.
    pub fn arming(&self, now: Instant) -> bool {
        self.armed_at
            .is_some_and(|t| now.saturating_duration_since(t) < ARMING_DELAY)
    }

    /// Shows a WalletConnect origin card, whose "received … ago · the dapp waits …" line counts
    /// in whole seconds — the overlay keeps a clock tick running so it moves on its own.
    pub fn shows_countdown(&self) -> bool {
        self.steps
            .iter()
            .any(|s| matches!(s, SignStep::WcOrigin(_)))
    }

    /// A WalletConnect review: the dapp is answered by the coordinator, and the
    /// backdrop never rejects it.
    pub fn is_walletconnect(&self) -> bool {
        matches!(self.action, SignAction::WalletConnect { .. })
    }

    /// A signing attempt ended without a result and the review stays up: leave
    /// the signing state and say why. `rearm` when Confirm comes back live, so a
    /// click already on its way can't land on it.
    pub fn back_to_review(&mut self, error: String, rearm: bool) {
        self.signing_since = None;
        self.signing_progress = None;
        self.error = Some(error);
        if rearm {
            self.armed_at = Some(Instant::now());
        }
    }
}

/// What a click on the dimmed backdrop does. Before confirm it cancels — except
/// for a WalletConnect review, where a stray click must never refuse a dapp
/// (Cancel / Esc / Reject are the deliberate ways out). While a signature is in
/// flight nothing can be dismissed (a hardware signature can't be aborted from
/// here).
pub(super) fn backdrop_message(review: &SignReview) -> Message {
    if review.signing_since.is_some() || review.is_walletconnect() {
        Message::BoxClickIgnored
    } else {
        Message::Cancel
    }
}

/// Whether Confirm (and the Secondary action) are live at `now`. Disabled while
/// the legs are still decoding (the user can't approve bytes they haven't been
/// shown), while a step-level guard blocks it (a Send with too little ETH for
/// gas), once this review has broadcast, and inside a WalletConnect review's
/// arming window.
fn confirm_enabled(review: &SignReview, now: Instant) -> bool {
    !review.legs_loading
        && !review.confirm_disabled
        && review.broadcast.is_none()
        && review.confirm_ready(now)
}

/// Whether the Secondary action is live at `now`: as Confirm, except that one marked
/// `secondary_unblocked` (it signs nothing) stays live while `confirm_disabled` blocks Confirm.
fn secondary_enabled(review: &SignReview, now: Instant) -> bool {
    !review.legs_loading
        && (!review.confirm_disabled || review.secondary_unblocked)
        && review.broadcast.is_none()
        && review.confirm_ready(now)
}

/// Render the overlay. `progress` drives the shared modal open/close ease.
pub fn view<'a>(t: KaoTheme, review: &'a SignReview, progress: f32) -> Element<'a, Message> {
    let mut body = column![].spacing(0).width(Length::Fill);

    // ── Header ────────────────────────────────────────────────────────────
    body = body.push(
        text("Review & sign")
            .size(12)
            .color(t.sub)
            .font(mono_bold()),
    );
    body = body.push(Space::new().height(4));
    body = body.push(text(&review.title).size(19).color(t.text).font(bold()));
    if let Some(sub) = &review.subtitle {
        body = body.push(Space::new().height(4));
        body = body.push(text(sub).size(12).color(t.sub).font(mono()));
    }
    body = body.push(Space::new().height(16));

    // ── Reviewed steps: the EIP-712 order (if any) then the decoded raw-tx legs ──
    // Spacing preserves the original layout: 12px after a typed-data step, 10px
    // between raw-tx legs.
    for (i, step) in review.steps.iter().enumerate() {
        if i > 0 {
            let gap = if matches!(
                review.steps[i - 1],
                SignStep::Typed(_)
                    | SignStep::WcTyped(_)
                    | SignStep::WcMessage(_)
                    | SignStep::WcSafeMessage(_)
            ) {
                12
            } else {
                10
            };
            body = body.push(Space::new().height(gap));
        }
        body = body.push(step_card(
            t,
            step,
            review.show_calldata,
            review.show_fingerprints,
            review.show_fee_details,
            review.show_delegation,
            review.signing_since.is_some(),
        ));
    }

    if review.legs_loading {
        // A leading typed step (a swap's order) keeps its 12px gap before the
        // "preparing" card, matching the old order→legs spacing.
        if matches!(review.steps.last(), Some(SignStep::Typed(_))) {
            body = body.push(Space::new().height(12));
        }
        body = body.push(card(
            t,
            column![
                text("Preparing…").size(12).color(t.sub).font(bold()),
                Space::new().height(4),
                text("(・_・;) decoding the transaction you'll sign")
                    .size(12)
                    .color(t.sub)
                    .font(mono()),
            ]
            .into(),
        ));
    }

    // What the transaction moves and costs. Above the note (which carries the
    // batch-level caveats) and below the legs, so the reading order is: what it
    // does → what it costs you → what to watch out for.
    if let Some(e) = review.economics.as_ref().filter(|e| !e.is_empty()) {
        body = body.push(Space::new().height(12));
        body = body.push(economics_card(t, e, review.show_fee_details));
    }

    if let Some(note) = &review.note {
        body = body.push(Space::new().height(12));
        body = body.push(text(note).size(11).color(t.sub).font(mono()));
    }

    // Kept up while signing: each owner's device shows this digest as it prompts, and that is when
    // it has to be checked.
    if let Some(fallback) = &review.owner_eth_sign {
        body = body.push(Space::new().height(12));
        body = body.push(owner_eth_sign_card(
            t,
            fallback,
            review.signing_since.is_some(),
            review.signing_progress.as_ref(),
        ));
    }

    // A broadcast error surfaced back onto the still-open review (Send retry path).
    if let Some(err) = &review.error {
        body = body.push(Space::new().height(12));
        body = body.push(
            text(format!("(╥﹏╥) {err}"))
                .size(12)
                .color(t.down)
                .font(bold()),
        );
    }

    // ── Actions ───────────────────────────────────────────────────────────
    // Once confirmed, the overlay swaps its buttons for a live "waiting for a
    // signature" notice and stays open until the signing task resolves — so a
    // hardware-wallet prompt isn't left facing a blank screen, and the reviewed
    // bytes stay visible above it. Otherwise show the Confirm / Cancel gate.
    body = body.push(Space::new().height(20));
    if let Some(since) = review.signing_since {
        body = body.push(waiting_card(
            t,
            since.elapsed().as_secs_f32(),
            review.signing_progress.as_ref(),
        ));
    } else {
        // Confirm stays disabled while legs are still decoding so the user can't
        // approve bytes they haven't been shown yet, and while a step-level guard
        // blocks it (a Send with too little ETH for gas). The label can be
        // overridden per-flow (Send's "Sign & Send" / "Sign anyway ⚠").
        //
        // `broadcast` is the hard one: this review has already put a transaction
        // on the wire, so there is nothing left here to confirm. Signing again
        // is a new transaction at a new nonce and has to go through a new
        // review — not a second press of a button whose numbers are now stale.
        let broadcast = review.broadcast.is_some();
        let label = if broadcast {
            "Already broadcast"
        } else {
            review.confirm_label.as_deref().unwrap_or("Confirm & sign")
        };
        let enabled = confirm_enabled(review, Instant::now());
        let confirm = primary_button(t, label, enabled);
        let confirm = if enabled {
            confirm.on_press(Message::Confirm)
        } else {
            confirm
        };
        // "Cancel" would be a lie once the transaction is out — there is
        // nothing left to cancel, only a window to shut.
        let dismiss = if broadcast { "Close" } else { "Cancel" };
        let actions = row![
            container(secondary_button(t, dismiss).on_press(Message::Cancel))
                .width(Length::FillPortion(1)),
            Space::new().width(10),
            container(confirm).width(Length::FillPortion(1)),
        ]
        .width(Length::Fill);
        body = body.push(actions);
        // Optional second primary action (Safe send: "Propose to co-signers"),
        // full-width below the Cancel/Confirm row, gated the same as Confirm —
        // except one that signs nothing (`secondary_unblocked`).
        if let Some(sec) = &review.secondary_label {
            let enabled = secondary_enabled(review, Instant::now());
            let sec_btn = primary_button(t, sec, enabled);
            let sec_btn = if enabled {
                sec_btn.on_press(Message::Secondary)
            } else {
                sec_btn
            };
            body = body.push(Space::new().height(8));
            body = body.push(sec_btn);
        }
    }

    // Inset the content from the right so the scrollbar rides in its own gutter
    // instead of overlapping the cards (notably the full address rows).
    let scroll_body = scrollable(container(body).width(Length::Fill).padding(Padding {
        top: 0.0,
        right: 14.0,
        bottom: 0.0,
        left: 0.0,
    }))
    .height(Length::Shrink)
    .style(move |_, s| kao_scrollable_style(t, s));
    let bounded = container(scroll_body).max_height(FORM_MAX_HEIGHT);

    // While the signing task is in flight the review can't be dismissed (a
    // hardware signature can't be aborted from here), so a backdrop click is a
    // no-op; before confirm it cancels as usual — never for a WalletConnect
    // review (see `backdrop_message`).
    let on_backdrop = backdrop_message(review);
    modal_wrapper(
        t,
        MODAL_WIDTH,
        progress,
        on_backdrop,
        Message::BoxClickIgnored,
        bounded.into(),
    )
}

/// What Confirm signs once an owner's device refused the EIP-712 prompt: the
/// same Safe hash as a personal message, and the digest the device will show
/// for it — so the second, different prompt can be checked like the first.
/// `signing`: the devices are prompting now, so the instruction is for a prompt
/// already on screen.
fn owner_eth_sign_card<'a>(
    t: KaoTheme,
    fallback: &OwnerEthSign,
    signing: bool,
    progress: Option<&SigningKind>,
) -> Element<'a, Message> {
    // With no Local gas payer the first owner also signs the executor's transaction: on a
    // hardware device that is one more prompt, a transaction rather than the message.
    let executor_prompts = matches!(
        progress,
        Some(SigningKind::SafeExecute { owners, gas_payer: None })
            if owners.first().is_some_and(|o| o.hardware)
    );
    let instruction = if signing && executor_prompts {
        "Signing the Safe hash as a personal message (eth_sign). Each owner's device shows that \
         message or its message hash — approve those only if they match one below. Then owner \
         1's device shows the transaction to the Safe that executes it and pays the gas — check \
         it against the review above."
    } else if signing {
        "Signing the Safe hash as a personal message (eth_sign). Your device is asking now, \
         showing that message or its message hash — approve only if it shows one of these."
    } else {
        "An owner's hardware wallet refused the EIP-712 prompt — it was declined, or Blind \
         signing is off in its Ethereum app. Confirm now signs the same Safe hash as a \
         personal message (eth_sign), which the Safe accepts too. The device will ask again, \
         showing that message or its message hash: approve only if it matches one below."
    };
    let col = column![
        text("⚠ SIGN AS A PERSONAL MESSAGE INSTEAD")
            .size(12)
            .color(t.down)
            .font(bold()),
        Space::new().height(3),
        text(instruction).size(11).color(t.text),
        Space::new().height(8),
        hash_row(t, "Safe hash signed as a message", fallback.hash),
        hash_row(
            t,
            "Message hash the device shows (EIP-191)",
            fallback.eip191
        ),
    ]
    .spacing(0)
    .width(Length::Fill);
    card(t, col.into())
}

/// The post-confirm "waiting for a signature" panel: a font-safe bouncing-bullet
/// animator (shared with the ZK proving screen) over a short notice. Shown in
/// place of the Confirm / Cancel gate while the signing task runs.
///
/// `progress` lays out a multi-device Safe ceremony (execute or propose) as a
/// per-owner checklist, so the user knows how many device prompts to expect and
/// on which accounts — otherwise a single generic "confirm on your device" line.
/// The ceremony runs as one task, so the checklist is the plan, not a live
/// cursor: it can't highlight the owner currently signing.
fn waiting_card<'a>(
    t: KaoTheme,
    elapsed: f32,
    progress: Option<&'a SigningKind>,
) -> Element<'a, Message> {
    let plural = matches!(
        progress,
        Some(SigningKind::SafeExecute { owners, .. } | SigningKind::WcMessage { owners, .. })
            if owners.len() > 1
    );
    let title = if plural {
        "Waiting for signatures"
    } else {
        "Waiting for a signature"
    };

    let mut col = column![
        text(bullet_wave(elapsed))
            .size(15)
            .color(t.a3)
            .font(mono_bold()),
        Space::new().height(8),
        text(title).size(14).color(t.text).font(bold()),
    ]
    .align_x(Alignment::Center)
    .width(Length::Fill);

    match progress {
        Some(SigningKind::SafeExecute { owners, gas_payer }) => {
            col = col.push(Space::new().height(4));
            col = col.push(
                text("Approve the Safe transaction on each owner in turn:")
                    .size(12)
                    .color(t.sub)
                    .font(mono()),
            );
            col = col.push(Space::new().height(8));
            col = col.push(ceremony_owner_list(t, owners));
            col = col.push(Space::new().height(6));
            let broadcast = match gas_payer {
                Some(p) => format!(
                    "Then {} ({}) broadcasts it and pays the gas.",
                    p.label,
                    crate::wallet::short_address(p.address)
                ),
                None => "Then owner 1 re-signs to broadcast it and pay the gas.".to_string(),
            };
            col = col.push(text(broadcast).size(11).color(t.sub).font(mono()));
        }
        Some(SigningKind::SafePropose { owner }) => {
            col = col.push(Space::new().height(4));
            col = col.push(
                text(if owner.hardware {
                    "Approve the Safe transaction on your device to propose it."
                } else {
                    "Signing the Safe transaction to propose it to co-signers."
                })
                .size(12)
                .color(t.sub)
                .font(mono()),
            );
            col = col.push(Space::new().height(8));
            col = col.push(ceremony_owner_list(t, std::slice::from_ref(owner)));
            col = col.push(Space::new().height(6));
            col = col.push(
                text("Co-signers finish it from their own wallets.")
                    .size(11)
                    .color(t.sub)
                    .font(mono()),
            );
        }
        Some(SigningKind::Broadcasting { hash }) => {
            col = col.push(Space::new().height(4));
            col = col.push(
                text("Broadcast — waiting for it to be mined.")
                    .size(12)
                    .color(t.sub)
                    .font(mono()),
            );
            col = col.push(Space::new().height(8));
            col = col.push(hash_row(t, "Transaction", *hash));
        }
        Some(SigningKind::Eip7702Batch {
            fresh_authorization,
        }) => {
            col = col.push(Space::new().height(4));
            col = col.push(
                text(if *fresh_authorization {
                    "Two signatures: first the account delegation, then the batch that uses \
                     it. On a hardware wallet that is two separate prompts — the first names \
                     the delegate, the second the transaction."
                } else {
                    "One signature: your account already runs the batch executor's code, so \
                     no new delegation is authorized."
                })
                .size(12)
                .color(t.sub)
                .font(mono()),
            );
        }
        Some(SigningKind::Eip7702Revoke) => {
            col = col.push(Space::new().height(4));
            col = col.push(
                text(
                    "Two signatures: first the authorization that clears the delegation, then \
                     the empty transaction that carries it. On a hardware wallet that is two \
                     separate prompts.",
                )
                .size(12)
                .color(t.sub)
                .font(mono()),
            );
        }
        Some(SigningKind::WcMessage { owners, hash_mode }) => {
            col = col.push(wc::waiting_body(t, owners, *hash_mode));
        }
        None => {
            col = col.push(Space::new().height(4));
            col = col.push(
                text(
                    "Confirm the transaction on your device — this window stays open until it's signed.",
                )
                .size(12)
                .color(t.sub)
                .font(mono()),
            );
        }
    }

    card(t, col.into())
}

/// The per-owner rows for a Safe signing ceremony: an ordinal, the owner's
/// label + short address, and whether it prompts a hardware device or signs
/// in-process. Left-aligned inside the otherwise-centered waiting card.
fn ceremony_owner_list<'a>(t: KaoTheme, owners: &'a [SigningOwner]) -> Element<'a, Message> {
    let mut list = column![].spacing(4).width(Length::Fill);
    for (i, owner) in owners.iter().enumerate() {
        let how = if owner.hardware {
            "confirm on device"
        } else {
            "signs automatically"
        };
        let head = format!(
            "{}. {} · {}",
            i + 1,
            owner.label,
            crate::wallet::short_address(owner.address),
        );
        list = list.push(
            column![
                text(head).size(12).color(t.text).font(mono_bold()),
                text(how).size(11).color(t.sub).font(mono()),
            ]
            .spacing(1)
            .width(Length::Fill),
        );
    }
    container(list).width(Length::Fill).into()
}

/// Render one reviewed step: its type-specific panel, then the collapsible
/// ERC-8213 fingerprints section (the signature/calldata digests for this step).
/// `signing`: the signature is in flight (a WalletConnect origin card's deadline
/// depends on it).
fn step_card<'a>(
    t: KaoTheme,
    step: &'a SignStep,
    show_calldata: bool,
    show_fingerprints: bool,
    show_fee_details: bool,
    show_delegation: bool,
    signing: bool,
) -> Element<'a, Message> {
    let panel = match step {
        SignStep::RawTx(leg) => leg_card(t, leg, show_calldata),
        SignStep::Delegation(d) => delegation_panel(t, d, show_delegation),
        SignStep::Typed(order) => order_panel(t, order),
        SignStep::SafeExec(x) => safe_exec_panel(t, x, show_calldata),
        SignStep::SafeMessage(m) => safe_message_panel(t, m),
        SignStep::Send(r) => {
            super::send::render_send_review(t, r, show_calldata, Message::ToggleCalldata)
        }
        SignStep::SafeSend(r) => super::send::render_safe_send_review::<Message>(t, r),
        SignStep::WcOrigin(_)
        | SignStep::WcMessage(_)
        | SignStep::WcTyped(_)
        | SignStep::WcSafeMessage(_)
        | SignStep::WcTxFees(_) => wc::step_card(t, step, show_calldata, show_fee_details, signing),
    };
    let rows = erc8213_rows(step);
    if rows.is_empty() {
        return panel;
    }
    column![
        panel,
        Space::new().height(6),
        fingerprints_section(t, show_fingerprints, rows),
    ]
    .spacing(0)
    .width(Length::Fill)
    .into()
}

/// The ERC-8213 fingerprint rows for one reviewed step: `(exact-ERC-label, hash)`
/// pairs the fingerprints section renders — and the tests assert. This is the
/// single source of truth, so what is verified is exactly what is displayed.
///
/// A raw transaction contributes its **Calldata Digest**; an EIP-712 signature
/// contributes the **EIP-712 Digest** + **Domain Hash** + **Message Hash**; a Safe
/// step contributes both the wrapping `SafeTx`/`SafeMessage` signature *and* the
/// inner calldata. A native (calldata-less) transfer contributes nothing.
pub(crate) fn erc8213_rows(step: &SignStep) -> Vec<(String, B256)> {
    fn push_eip712(rows: &mut Vec<(String, B256)>, d: &Eip712Digests) {
        rows.push((EIP712_DIGEST_LABEL.to_string(), d.digest));
        rows.push((DOMAIN_HASH_LABEL.to_string(), d.domain_hash));
        rows.push((MESSAGE_HASH_LABEL.to_string(), d.message_hash));
    }
    fn push_calldata(rows: &mut Vec<(String, B256)>, label: &str, calldata: &[u8]) {
        if !calldata.is_empty() {
            rows.push((label.to_string(), digest::calldata_digest(calldata)));
        }
    }

    let mut rows = Vec::new();
    match step {
        SignStep::RawTx(leg) => push_calldata(&mut rows, CALLDATA_DIGEST_LABEL, &leg.calldata),
        // The authorization's signature hash commits to a nonce, so it only
        // exists once that nonce is pinned — which prepare now does. An
        // already-active delegation signs nothing and so has no digest.
        SignStep::Delegation(d) => {
            if let Some(h) = d.auth_digest {
                rows.push(("Authorization Digest (EIP-7702)".to_string(), h));
            }
        }
        SignStep::Typed(order) => push_eip712(&mut rows, &order.eip712),
        SignStep::SafeExec(x) => {
            push_eip712(&mut rows, &x.eip712);
            push_calldata(&mut rows, INNER_CALLDATA_DIGEST_LABEL, &x.inner.calldata);
        }
        SignStep::SafeMessage(m) => {
            push_eip712(&mut rows, &m.eip712);
            rows.push((COW_ORDER_DIGEST_LABEL.to_string(), m.order_digest));
        }
        SignStep::Send(r) => {
            if let Some(cd) = r.calldata_digest {
                rows.push((CALLDATA_DIGEST_LABEL.to_string(), cd));
            }
        }
        SignStep::SafeSend(r) => {
            push_eip712(&mut rows, &r.eip712);
            if let Some(cd) = r.inner_calldata_digest {
                rows.push((INNER_CALLDATA_DIGEST_LABEL.to_string(), cd));
            }
        }
        SignStep::WcOrigin(_)
        | SignStep::WcMessage(_)
        | SignStep::WcTyped(_)
        | SignStep::WcSafeMessage(_)
        | SignStep::WcTxFees(_) => rows = wc::erc8213_rows(step),
    }
    rows
}

/// The collapsible **ERC-8213 fingerprints** section: a click-to-toggle header
/// (mirroring the Send step's "for the paranoid" block) that, when expanded,
/// lists each labelled digest via [`hash_row`] — the full 32-byte, 0x-prefixed,
/// monospace, click-to-copy display ERC-8213 requires. Callers pass a non-empty
/// `rows`; an empty step renders no section at all (see [`step_card`]).
fn fingerprints_section<'a>(
    t: KaoTheme,
    show: bool,
    rows: Vec<(String, B256)>,
) -> Element<'a, Message> {
    let caret = if show { "▾" } else { "▸" };
    let header = row![
        text(caret).size(12).color(t.sub).font(mono()),
        Space::new().width(6),
        text("ERC-8213 fingerprints")
            .size(12)
            .color(t.text)
            .font(mono_bold()),
        Space::new().width(Length::Fill),
        text(if show { "hide" } else { "verify hashes" })
            .size(11)
            .color(t.sub)
            .font(mono()),
    ]
    .align_y(Alignment::Center)
    .spacing(0);
    let toggle: Element<'a, Message> = button(header.width(Length::Fill))
        .width(Length::Fill)
        .padding(Padding::from([10, 14]))
        .on_press(Message::ToggleFingerprints)
        .style(move |_theme, _status| button::Style {
            background: Some(iced::Background::Color(iced::Color::TRANSPARENT)),
            text_color: t.text,
            ..button::Style::default()
        })
        .into();

    let mut col = column![toggle].spacing(0).width(Length::Fill);
    if show {
        let mut body = column![].spacing(6).width(Length::Fill);
        for (label, hash) in rows {
            body = body.push(hash_row(t, label, hash));
        }
        col = col.push(
            container(body)
                .padding(Padding::from([0, 14]).bottom(12.0))
                .width(Length::Fill),
        );
    }
    container(col)
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(iced::Background::Color(t.card_alt)),
            border: iced::Border {
                color: t.border,
                width: 1.0,
                radius: iced::border::Radius::from(12),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
}

/// A Safe `execTransaction` step: the ceremony header (N-of-M owners, Safe
/// address, nonce), the decoded inner call (via the shared `leg_card`), and the
/// exact `safeTxHash` each owner signs on their device.
fn safe_exec_panel<'a>(
    t: KaoTheme,
    x: &'a SafeExecReview,
    show_detail: bool,
) -> Element<'a, Message> {
    let mut col = column![
        text("Safe transaction — execTransaction")
            .size(11)
            .color(t.sub)
            .font(bold()),
        Space::new().height(2),
        text(format!(
            "{}-of-{} owners must sign",
            x.threshold, x.owner_count
        ))
        .size(13)
        .color(t.text)
        .font(bold()),
        Space::new().height(8),
    ]
    .spacing(0)
    .width(Length::Fill);
    col = col.push(addr_kv(t, "Safe", x.safe));
    col = col.push(kv(
        t,
        "Nonce",
        match x.queued_ahead() {
            0 => x.nonce.to_string(),
            n => format!(
                "{} (Safe is at {}, {n} queued ahead)",
                x.nonce, x.onchain_nonce
            ),
        },
    ));
    // The operation byte, always — a row that only appeared for delegatecall
    // would teach the user nothing about what its absence means.
    col = col.push(kv(
        t,
        "Operation",
        match x.operation {
            0 => "0 (call)".to_string(),
            1 => "1 (delegatecall)".to_string(),
            other => format!("{other} (unknown)"),
        },
    ));
    // A guard is not part of the signed payload, so it cannot be read off the
    // hash — but it can veto this transaction at execution time and the
    // preflight never runs it. Say so where the batch is being approved.
    if let Some(g) = x.guard {
        col = col.push(addr_kv(t, "Transaction guard", g));
    }
    if let Some(e) = &x.executor {
        col = col.push(addr_kv(
            t,
            format!("If executed now, sent and paid for by {}", e.label),
            e.address,
        ));
    }
    col = col.push(Space::new().height(8));
    if x.operation != 0 {
        col = col.push(operation_banner(t, x.operation, x.inner.to));
        col = col.push(Space::new().height(8));
    }
    if x.guard.is_some() {
        col = col.push(
            text(
                "This Safe has a transaction guard installed. A guard can reject this \
                 transaction when it executes, and the preflight simulation does not run it — \
                 a passing preflight is not a promise that the guard will allow this.",
            )
            .size(11)
            .color(t.sub),
        );
        col = col.push(Space::new().height(8));
    }
    if let Some(reason) = x.preflight.as_ref().and_then(preflight_failure) {
        col = col.push(preflight_banner(t, reason));
        col = col.push(Space::new().height(8));
    }
    if x.queued_ahead() > 0 {
        col = col.push(
            text(format!(
                "This Safe already has {} transaction{} queued at nonce{} {}–{}. Signing at \
                 nonce {} puts this one behind them: it can only be queued, not executed now, \
                 and it becomes executable once those ahead of it have run. Filing it at the \
                 Safe's current nonce instead would compete with them — whichever executed \
                 first would void the other.",
                x.queued_ahead(),
                if x.queued_ahead() == 1 { "" } else { "s" },
                if x.queued_ahead() == 1 { "" } else { "s" },
                x.onchain_nonce,
                x.nonce - 1,
                x.nonce,
            ))
            .size(11)
            .color(t.sub),
        );
        col = col.push(Space::new().height(8));
    }
    col = col.push(text("Safe will execute").size(11).color(t.sub).font(bold()));
    col = col.push(Space::new().height(4));
    col = col.push(leg_card(t, x.inner.as_ref(), show_detail));
    col = col.push(Space::new().height(8));
    col = col.push(hash_row(
        t,
        "Each owner signs (SafeTx hash)",
        x.safe_tx_hash,
    ));
    card(t, col.into())
}

/// Why a review-time dry run says the call fails: the revert (or halt) reason, `None` when it
/// succeeded or couldn't run — a simulator gap is not a verdict.
fn preflight_failure(sim: &crate::txbuilder::sim::BatchSimResult) -> Option<&str> {
    use crate::txbuilder::sim::BatchOutcome;
    match &sim.outcome {
        BatchOutcome::Revert { reason, .. } | BatchOutcome::Halt { reason, .. } => Some(reason),
        BatchOutcome::Success | BatchOutcome::Error(_) | BatchOutcome::Unavailable => None,
    }
}

/// A simulated revert reason for display. The reverting contract wrote it, so hidden characters
/// are shown as escapes and its length is clamped.
pub(super) fn display_revert_reason(reason: &str) -> String {
    use crate::sanitize::{escape_unsafe_display, sanitize_display};
    sanitize_display(&escape_unsafe_display(reason), MAX_REVERT_REASON_CHARS).into_owned()
}

/// A Safe call Kao's dry run saw fail, said where the user decides — before anyone signs, not at
/// execute time after every owner has.
fn preflight_banner<'a>(t: KaoTheme, reason: &str) -> Element<'a, Message> {
    let reason = display_revert_reason(reason);
    let col = column![
        text("⚠ SIMULATION REVERTED")
            .size(12)
            .color(t.down)
            .font(bold()),
        Space::new().height(3),
        text(format!(
            "Kao ran this call as the Safe against the chain as it stands, and it reverted: \
             {reason}. Executed now it would fail; proposed, it asks your co-signers to sign a \
             call that fails."
        ))
        .size(11)
        .color(t.text)
        .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
    ]
    .spacing(0)
    .width(Length::Fill);
    container(col)
        .padding(10)
        .width(Length::Fill)
        .style(move |_: &iced::Theme| container::Style {
            background: Some(t.card_alt.into()),
            border: iced::Border {
                color: t.down,
                width: 1.0,
                radius: 8.0.into(),
            },
            ..Default::default()
        })
        .into()
}

/// The red banner for a non-CALL `SafeTx.operation`. Deliberately makes the
/// same claim `safe_tx_detail::operation_warning` makes to a co-signer
/// reviewing an incoming proposal — arbitrary code running as the Safe, able to
/// change owners, drain funds, or replace the implementation — so the same
/// transaction doesn't read as more dangerous when someone else built it than
/// when this wallet did. The wording differs because the situations do: there
/// the question is whether to trust a proposer, here it is whether the target
/// is the library this wallet meant to use.
///
/// `to` is named because a delegatecall's danger is entirely a function of
/// whose code runs — the canonical `MultiSendCallOnly` libraries are labelled
/// so the expected case is legible as the expected case.
fn operation_banner<'a>(t: KaoTheme, operation: u8, to: Address) -> Element<'a, Message> {
    use crate::txbuilder::multisend::canonical_multisend_call_only;
    let (title, msg) = if operation == 1 {
        let target = match canonical_multisend_call_only(to) {
            Some(version) => format!(
                "The target is the canonical Safe MultiSendCallOnly {version} library, which can \
                 only make plain calls — this is the expected shape for a batch."
            ),
            None => format!(
                "The target {} is NOT a canonical Safe MultiSend library. Do not sign unless \
                 you know exactly what code lives there.",
                crate::wallet::short_address(to)
            ),
        };
        (
            "⚠ DELEGATECALL",
            format!(
                "This transaction runs the target's code AS the Safe. Code reached this way can \
                 change owners, drain all funds, or replace the Safe's implementation. {target}"
            ),
        )
    } else {
        (
            "⚠ MALFORMED OPERATION",
            format!(
                "operation = {operation} is neither CALL (0) nor DELEGATECALL (1). Refuse this \
                 transaction."
            ),
        )
    };
    let col = column![
        text(title).size(12).color(t.down).font(bold()),
        Space::new().height(3),
        text(msg).size(11).color(t.text),
    ]
    .spacing(0)
    .width(Length::Fill);
    container(col)
        .padding(10)
        .width(Length::Fill)
        .style(move |_: &iced::Theme| container::Style {
            background: Some(t.card_alt.into()),
            border: iced::Border {
                color: t.down,
                width: 1.0,
                radius: 8.0.into(),
            },
            ..Default::default()
        })
        .into()
}

/// The banner for a sub-call addressed to the account executing the batch.
///
/// Styled like [`operation_banner`] on purpose. That banner is the one place
/// this surface already raises its voice, and this is the case it was leaving
/// out: it reassures the reader that `MultiSendCallOnly` "can only make plain
/// calls", which is true and, for a call addressed to the Safe itself, beside
/// the point — a plain call from the Safe to the Safe is precisely what the
/// `authorized` modifier accepts.
fn self_admin_banner<'a>(t: KaoTheme, warning: &'a str) -> Element<'a, Message> {
    let col = column![
        text("⚠ THIS CALL TARGETS THE SIGNING ACCOUNT")
            .size(12)
            .color(t.down)
            .font(bold()),
        Space::new().height(3),
        text(warning).size(11).color(t.text),
    ]
    .spacing(0)
    .width(Length::Fill);
    container(col)
        .padding(10)
        .width(Length::Fill)
        .style(move |_: &iced::Theme| container::Style {
            background: Some(t.card_alt.into()),
            border: iced::Border {
                color: t.down,
                width: 1.0,
                radius: 8.0.into(),
            },
            ..Default::default()
        })
        .into()
}

/// The EIP-7702 authorization card. Deliberately leads with what changes about
/// the *account* rather than with the transaction: this is the only signature
/// in the wallet whose effect survives the transaction that carried it.
///
/// A [collapsible](DelegationReview::collapsible) card — an existing
/// delegation to a known delegate, where nothing is signed — folds to a
/// one-line toggle naming the delegate; `show` unfolds it.
fn delegation_panel<'a>(t: KaoTheme, d: &'a DelegationReview, show: bool) -> Element<'a, Message> {
    let Some(name) = d.known_delegate_name().filter(|_| d.collapsible()) else {
        return card(t, delegation_body(t, d).into());
    };
    let caret = if show { "▾" } else { "▸" };
    let header = row![
        text(caret).size(12).color(t.sub).font(mono()),
        Space::new().width(6),
        text(format!("Account delegated to {name}"))
            .size(12)
            .color(t.text)
            .font(mono_bold()),
        Space::new().width(Length::Fill),
        text(if show { "hide" } else { "details" })
            .size(11)
            .color(t.sub)
            .font(mono()),
    ]
    .align_y(Alignment::Center)
    .spacing(0);
    let toggle: Element<'a, Message> = button(header.width(Length::Fill))
        .width(Length::Fill)
        .padding(0)
        .on_press(Message::ToggleDelegation)
        .style(move |_theme, _status| button::Style {
            background: Some(iced::Background::Color(iced::Color::TRANSPARENT)),
            text_color: t.text,
            ..button::Style::default()
        })
        .into();
    let mut col = column![toggle].spacing(0).width(Length::Fill);
    if show {
        col = col.push(Space::new().height(10));
        col = col.push(delegation_body(t, d));
    }
    card(t, col.into())
}

/// The full contents of a delegation card (everything [`delegation_panel`]
/// shows unfolded), without the surrounding card.
fn delegation_body<'a>(t: KaoTheme, d: &'a DelegationReview) -> iced::widget::Column<'a, Message> {
    let mut col = column![
        text("Account delegation — EIP-7702 authorization")
            .size(11)
            .color(t.sub)
            .font(bold()),
    ]
    .spacing(0)
    .width(Length::Fill);
    col = col.push(Space::new().height(2));
    col = col.push(
        text(if d.is_revocation() {
            "Your account will stop running contract code"
        } else {
            match (d.already_active, d.replacing().is_some()) {
                (true, _) => "Your account already runs this code",
                (false, true) => "Your account will be re-pointed to different code",
                (false, false) => "Your account will start running contract code",
            }
        })
        .size(13)
        .color(t.text)
        .font(bold()),
    );
    col = col.push(Space::new().height(8));
    col = col.push(addr_kv(t, "Your account", d.authority));
    if d.is_revocation() {
        if let Some(prev) = d.incumbent {
            col = col.push(addr_kv(t, "Currently delegated to", prev));
        }
        col = col.push(kv(t, "Delegates to", "none — restore a plain EOA"));
    } else {
        // Naming the incumbent first makes the swap legible as a swap: without it,
        // an account already delegated elsewhere reads identically to a fresh one.
        if let Some(prev) = d.replacing() {
            col = col.push(addr_kv(t, "Currently delegated to", prev));
        }
        col = col.push(addr_kv(t, "Delegates to", d.delegate));
        col = col.push(kv(t, "Delegate", d.delegate_label.clone()));
    }
    col = col.push(kv(
        t,
        "Scoped to",
        format!("{} · chain id {}", d.net.display_name(), d.chain_id),
    ));
    // The nonce is the third field of the signed tuple, alongside the chain id
    // and the delegate already shown. Naming it is what makes the fingerprint
    // below checkable: a digest over a nonce the user can't see is a digest
    // they can compare but not reason about.
    if let Some(n) = d.auth_nonce {
        col = col.push(kv(t, "Authorization nonce", n.to_string()));
    }
    col = col.push(Space::new().height(10));
    // The persistence is the part a user can't infer from the transaction
    // panel below, so it is stated rather than implied.
    col = col.push(
        text(if d.is_revocation() {
            "You sign this authorization separately from the empty transaction that carries \
             it (on a hardware wallet, that's two prompts). After it mines, this account is \
             a plain EOA again — it no longer runs any contract code."
        } else {
            match (d.already_active, d.replacing().is_some()) {
                (true, _) => {
                    "This delegation is already in place, so no new authorization is signed — \
                     the transaction below is an ordinary call into the code your account \
                     already runs."
                }
                (false, true) => {
                    "Your account is ALREADY delegated to the contract above, and signing this \
                     replaces it — anything reachable only through that contract stops being \
                     reachable. You sign this separately from the transaction below (on a \
                     hardware wallet, that's two prompts), and it does NOT expire with the \
                     transaction."
                }
                (false, false) => {
                    "You sign this authorization separately from the transaction below (on a \
                     hardware wallet, that's two prompts). It does NOT expire with the \
                     transaction — your account keeps running this code until you remove it."
                }
            }
        })
        .size(11)
        .color(if d.already_active { t.sub } else { t.down })
        .font(bold()),
    );
    col
}

/// A CoW order authorized via EIP-1271 from a Safe: the order rows (same as the
/// EOA `typed_panel`) plus the order digest and the `SafeMessage` hash each owner
/// signs.
fn safe_message_panel<'a>(t: KaoTheme, m: &'a SafeMessageReview) -> Element<'a, Message> {
    let model = m.order.to_typed_model();
    let mut col = column![text(model.type_name).size(11).color(t.sub).font(bold())]
        .spacing(0)
        .width(Length::Fill);
    if let Some(headline) = model.headline {
        col = col.push(Space::new().height(2));
        col = col.push(text(headline).size(13).color(t.text).font(bold()));
    }
    col = col.push(Space::new().height(8));
    for TypedRow { label, value } in model.rows {
        col = match value {
            TypedValue::Text(v) => col.push(kv(t, label, v)),
            TypedValue::Addr(a) => col.push(addr_kv(t, label, a)),
        };
    }
    col = col.push(Space::new().height(10));
    col = col.push(
        text(format!(
            "Authorized via EIP-1271 — {}-of-{} owners sign",
            m.threshold, m.owner_count
        ))
        .size(11)
        .color(t.sub)
        .font(bold()),
    );
    col = col.push(Space::new().height(4));
    col = col.push(addr_kv(t, "Authorizing Safe", m.safe));
    col = col.push(hash_row(t, "Order digest (CoW EIP-712)", m.order_digest));
    col = col.push(hash_row(
        t,
        "Each owner signs (SafeMessage hash)",
        m.message_hash,
    ));
    card(t, col.into())
}

/// A 32-byte hash field: label on top, the full `0x…` value in its own bordered
/// box below, rendered as click-to-copy coloured chunks (like [`addr_kv`]) so a
/// signer can verify it against their device and copy it to co-signers.
fn hash_row<'a>(t: KaoTheme, label: impl Into<String>, hash: B256) -> Element<'a, Message> {
    let inner = container(colored_hash_copyable::<Message>(t, hash))
        .width(Length::Fill)
        .padding(Padding::from([6, 8]))
        .style(move |_| container::Style {
            background: Some(iced::Background::Color(t.card)),
            border: iced::Border {
                color: t.border,
                width: 1.0,
                radius: iced::border::Radius::from(8),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        });
    column![
        text(label.into()).size(12).color(t.sub),
        Space::new().height(4),
        inner,
    ]
    .spacing(0)
    .padding(Padding::from([2, 0]))
    .width(Length::Fill)
    .into()
}

/// Exact signed bytes as an offset-led hex dump, 16 bytes per line in 4-byte groups, so a long
/// payload stays scannable and a byte can be found by position.
fn hex_dump(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 3 + 8);
    for (i, chunk) in bytes.chunks(HEX_DUMP_BYTES_PER_LINE).enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let _ = write!(out, "{:05x} ", i * HEX_DUMP_BYTES_PER_LINE);
        for group in chunk.chunks(4) {
            out.push(' ');
            out.push_str(&alloy::hex::encode(group));
        }
    }
    out
}

/// `bytes` as a [`hex_dump`] in a [`mono_box`].
fn hex_box<'a>(t: KaoTheme, bytes: &[u8]) -> Element<'a, Message> {
    mono_box(
        t,
        text(hex_dump(bytes))
            .size(11)
            .color(t.text)
            .font(mono())
            .into(),
    )
}

/// A show / hide control for raw bytes. Emits the overlay's shared [`Message::ToggleCalldata`] —
/// the same one-flag disclosure every raw-bytes block and "Show details" fold on the overlay uses.
fn bytes_toggle<'a>(
    t: KaoTheme,
    shown: bool,
    show: &'static str,
    hide: &'static str,
) -> Element<'a, Message> {
    button(
        row![
            text(if shown { "▾" } else { "▸" })
                .size(11)
                .color(t.sub)
                .font(mono()),
            Space::new().width(6),
            text(if shown { hide } else { show })
                .size(11)
                .color(t.sub)
                .font(bold()),
        ]
        .align_y(Alignment::Center),
    )
    .padding(Padding::from([4, 0]))
    .on_press(Message::ToggleCalldata)
    .style(move |_theme, _status| button::Style {
        background: None,
        text_color: t.sub,
        ..button::Style::default()
    })
    .into()
}

/// A call no decoder could read — on a custom network there is no verified chain to resolve a
/// descriptor or an ABI against — still shows what it signs: its selector always, and every byte
/// of it behind the shared toggle. A fingerprint alone is not a review.
fn raw_calldata_block<'a>(t: KaoTheme, calldata: &[u8], show: bool) -> Element<'a, Message> {
    let selector = match calldata.get(..4) {
        Some(sel) => format!("0x{}", alloy::hex::encode(sel)),
        None => "none (under 4 bytes)".to_string(),
    };
    let mut col = column![
        text("Not decoded — Kao can't read this call, so these are its exact bytes")
            .size(11)
            .color(t.sub)
            .font(bold()),
        Space::new().height(4),
        kv(t, "Function selector", selector),
        kv(t, "Calldata", format!("{} bytes", calldata.len())),
        bytes_toggle(
            t,
            show,
            "Show the exact calldata (hex)",
            "Hide the exact calldata"
        ),
    ]
    .spacing(0)
    .width(Length::Fill);
    if show {
        col = col.push(Space::new().height(4));
        col = col.push(hex_box(t, calldata));
    }
    col.into()
}

/// [`raw_calldata_block`] is for a leg whose bytes nothing else shows: undecoded, carrying
/// calldata, and not a batch whose sub-calls already decode it.
fn shows_raw_calldata(leg: &ReviewLeg) -> bool {
    matches!(*leg.decoded, DecodeResult::Empty)
        && !leg.calldata.is_empty()
        && leg.sub_legs.is_empty()
}

/// The CoW order review panel. Maps the [`OrderReview`] into a generic
/// [`TypedDataModel`] and hands it to [`typed_panel`] — so the order and any
/// future EIP-712 message share one renderer instead of a bespoke panel each.
fn order_panel<'a>(t: KaoTheme, o: &OrderReview) -> Element<'a, Message> {
    typed_panel(t, o.to_typed_model())
}

/// Render a [`TypedDataModel`] as a single card — header, optional headline, then
/// one row per field. The typed-data analogue of `function_panel`: no calldata to
/// decode, so it spells out the signed fields the orderbook/contract recovers the
/// signature against. Consumes the model so its owned strings move straight into
/// the widgets.
fn typed_panel<'a>(t: KaoTheme, model: TypedDataModel) -> Element<'a, Message> {
    let mut col = column![text(model.type_name).size(11).color(t.sub).font(bold())]
        .spacing(0)
        .width(Length::Fill);

    if let Some(headline) = model.headline {
        col = col.push(Space::new().height(2));
        col = col.push(text(headline).size(13).color(t.text).font(bold()));
    }
    col = col.push(Space::new().height(8));

    for TypedRow { label, value } in model.rows {
        col = match value {
            TypedValue::Text(v) => col.push(kv(t, label, v)),
            TypedValue::Addr(a) => col.push(addr_kv(t, label, a)),
        };
    }

    card(t, col.into())
}

/// A decoded raw-transaction leg: destination + value, then the shared
/// `function_panel` clear-signing render of its calldata. A batch leg
/// additionally renders each of its [`sub_legs`](ReviewLeg::sub_legs) — the
/// calls the outer transaction fans out into, decoded individually.
fn leg_card<'a>(t: KaoTheme, leg: &'a ReviewLeg, show_detail: bool) -> Element<'a, Message> {
    let mut col = column![
        text(&leg.title).size(13).color(t.text).font(bold()),
        Space::new().height(6),
    ]
    .spacing(0)
    .width(Length::Fill);

    // Ahead of everything, including the headline: a call to the signing
    // account is a fact about the call the decode cannot express.
    if let Some(warning) = &leg.self_admin {
        col = col.push(self_admin_banner(t, warning));
        col = col.push(Space::new().height(8));
    }

    // What it does, before who it touches: the headline leads the card, the
    // destination rows follow, the mechanical decode comes last.
    let headline = leg.decoded.headline();
    if let Some(h) = &headline {
        col = col.push(super::function_panel::headline_view::<Message>(t, h));
        col = col.push(Space::new().height(8));
    }

    // A clear-signed call has an authored sentence saying what it does, so the
    // destination/value rows and the decoded entries are corroboration, not the
    // primary read — fold them behind a toggle. Without a descriptor there is
    // no such sentence, so everything stays unfolded.
    let collapsible = headline.as_ref().is_some_and(|h| h.clear_signed);
    if collapsible {
        col = col.push(detail_toggle(t, show_detail));
    }
    if !collapsible || show_detail {
        if collapsible {
            col = col.push(Space::new().height(6));
        }
        col = col.push(addr_kv(t, "To", leg.to));
        col = col.push(kv(t, "Network", leg.net.display_name()));
        col = col.push(kv(t, "Value", format!("{} ETH", format_eth(leg.value))));

        if let Some(panel) =
            super::function_panel::view::<Message>(t, Some(leg.decoded.as_ref()), false)
        {
            col = col.push(Space::new().height(8));
            col = col.push(panel);
        }
        if shows_raw_calldata(leg) {
            col = col.push(Space::new().height(8));
            col = col.push(raw_calldata_block(t, &leg.calldata, show_detail));
        }
    }

    if !leg.sub_legs.is_empty() {
        col = col.push(Space::new().height(10));
        col = col.push(
            text(format!(
                "This transaction performs {} call{} — all-or-nothing",
                leg.sub_legs.len(),
                if leg.sub_legs.len() == 1 { "" } else { "s" }
            ))
            .size(11)
            .color(t.sub)
            .font(bold()),
        );
        for sub in &leg.sub_legs {
            col = col.push(Space::new().height(6));
            col = col.push(sub_leg_card(t, sub, show_detail));
        }
    }

    card(t, col.into())
}

/// The show/hide control for a clear-signed leg's mechanical detail. Emits the
/// shared [`Message::ToggleCalldata`], so one click unfolds every leg on the
/// overlay at once — the same "one flag toggles them all" rule the ERC-8213
/// fingerprints section follows.
fn detail_toggle<'a>(t: KaoTheme, shown: bool) -> Element<'a, Message> {
    button(
        row![
            text(if shown { "▾" } else { "▸" })
                .size(11)
                .color(t.sub)
                .font(mono()),
            Space::new().width(6),
            text(if shown {
                "Hide details"
            } else {
                "Show details"
            })
            .size(11)
            .color(t.sub)
            .font(bold()),
        ]
        .align_y(Alignment::Center),
    )
    .padding(Padding::from([4, 0]))
    .on_press(Message::ToggleCalldata)
    .style(move |_theme, _status| button::Style {
        background: None,
        text_color: t.sub,
        ..button::Style::default()
    })
    .into()
}

/// One call inside a batch: the same fields and clear-signing panel as a
/// top-level leg, in a tighter card so the nesting reads as "inside the
/// transaction above". `Network` is dropped — every sub-call runs on the outer
/// leg's chain, so repeating it per call is noise.
fn sub_leg_card<'a>(t: KaoTheme, leg: &'a ReviewLeg, show_detail: bool) -> Element<'a, Message> {
    let mut col = column![
        text(&leg.title).size(11).color(t.sub).font(bold()),
        Space::new().height(4),
    ]
    .spacing(0)
    .width(Length::Fill);

    // Above the decode, not below it: a call that reconfigures the multisig is
    // not a footnote on an otherwise ordinary leg, and the decode underneath it
    // renders `addOwnerWithThreshold` as calmly as it renders `approve`.
    if let Some(warning) = &leg.self_admin {
        col = col.push(self_admin_banner(t, warning));
        col = col.push(Space::new().height(6));
    }

    let headline = leg.decoded.headline();
    if let Some(h) = &headline {
        col = col.push(super::function_panel::headline_view::<Message>(t, h));
        col = col.push(Space::new().height(6));
    }

    // No toggle of its own — a sub-call follows the outer leg's disclosure
    // state, so one click unfolds the whole batch rather than N.
    if !headline.as_ref().is_some_and(|h| h.clear_signed) || show_detail {
        col = col.push(addr_kv(t, "To", leg.to));
        if !leg.value.is_zero() {
            col = col.push(kv(t, "Value", format!("{} ETH", format_eth(leg.value))));
        }

        if let Some(panel) =
            super::function_panel::view::<Message>(t, Some(leg.decoded.as_ref()), false)
        {
            col = col.push(Space::new().height(6));
            col = col.push(panel);
        }
        if shows_raw_calldata(leg) {
            col = col.push(Space::new().height(6));
            col = col.push(raw_calldata_block(t, &leg.calldata, show_detail));
        }
    }

    container(col)
        .padding(Padding::from([10, 12]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(iced::Background::Color(t.card)),
            border: iced::Border {
                color: t.border,
                width: 1.0,
                radius: iced::border::Radius::from(10),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
}

fn kv<'a>(t: KaoTheme, label: impl Into<String>, value: impl Into<String>) -> Element<'a, Message> {
    row![
        text(label.into()).size(12).color(t.sub),
        Space::new().width(Length::Fill),
        text(value.into()).size(12).color(t.text).font(mono_bold()),
    ]
    .align_y(Alignment::Center)
    .padding(Padding::from([2, 0]))
    .width(Length::Fill)
    .into()
}

/// An address field: label on top, then the *full* checksummed address in its own
/// full-width card below. Stacking (rather than right-aligning on the label row)
/// is what gives the 42-char address the room to render in full instead of being
/// clipped at the panel edge.
fn addr_kv<'a>(t: KaoTheme, label: impl Into<String>, addr: Address) -> Element<'a, Message> {
    let inner = container(colored_address(t, addr))
        .width(Length::Fill)
        .padding(Padding::from([6, 8]))
        .style(move |_| container::Style {
            background: Some(iced::Background::Color(t.card)),
            border: iced::Border {
                color: t.border,
                width: 1.0,
                radius: iced::border::Radius::from(8),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        });
    column![
        text(label.into()).size(12).color(t.sub),
        Space::new().height(4),
        inner,
    ]
    .spacing(0)
    .padding(Padding::from([2, 0]))
    .width(Length::Fill)
    .into()
}

/// "What this moves, and what it costs" — the Transaction Builder's economics
/// block.
///
/// Deliberately two claims in one card, because they answer the same question
/// and were both missing: the balance movements the reviewed simulation
/// observed, and a base-fee estimate over the gas it metered. Everything here
/// is hedged in the copy rather than in a footnote — the fee leads with `≈`,
/// and `fee_caveats` names how the number is wrong, because a fee figure with
/// no stated error bars is one users treat as a quote.
///
/// Folded (`show_details` false) it keeps the header, its simulation badge,
/// the movements and the `≈` fee; the gas basis, the caveats and the tracking
/// note unfold under the header's toggle.
fn economics_card<'a>(
    t: KaoTheme,
    e: &'a BatchEconomics,
    show_details: bool,
) -> Element<'a, Message> {
    let mut col = column![].spacing(4).width(Length::Fill);

    // Freshness is checked before verification: a Helios-verified read of a
    // balance that has since moved is precisely verified and no longer true,
    // so the badge must not lead with the tick.
    let badge = text(if !e.simulated {
        "not simulated"
    } else if e.stale {
        "⚠ Simulated a while ago"
    } else if e.verified {
        "✓ Verified by Helios"
    } else {
        "⚠ Unverified simulation"
    })
    .size(11)
    .color(if e.simulated && e.verified && !e.stale {
        t.up
    } else {
        t.sub
    })
    .font(bold());
    col = col.push(fee_details_toggle(
        t,
        if e.moves.is_empty() {
            "Cost"
        } else {
            "This transaction moves"
        },
        badge.into(),
        show_details,
    ));

    for m in &e.moves {
        col = col.push(
            text(format!("{} {}", m.direction.prefix(), m.amount))
                .size(13)
                .color(match m.direction {
                    MoveDirection::Out => t.down,
                    MoveDirection::In => t.up,
                })
                .font(mono()),
        );
    }

    if show_details {
        // Absence of token rows is only evidence of "moves no tokens" when a
        // simulation actually ran. Without one, say so where the rows would be
        // — the header's "not simulated" badge says it while this is folded.
        let note = if !e.simulated {
            "Token movement wasn't simulated for this batch, so this list covers only the native \
             value the calls carry — run the preflight to see ERC-20 and NFT movement."
        } else {
            // The one hole a successful simulation still leaves. Balance
            // changes are recovered from `Transfer` logs, and native ETH
            // *arriving* emits none — an unwrap or a refund lands in the
            // account with nothing here to show for it. The outgoing side is
            // exact (it is the calls' own `value`), so the gap is
            // one-directional and worth naming as such.
            "ETH arriving back in the account isn't tracked here — native transfers emit no \
             event. The ETH these calls send is exact."
        };
        col = col.push(text(note).size(11).color(t.sub).font(mono()));
    }

    if let Some(fee) = e.fee_eth() {
        let mut fee_row = row![
            text(format!("≈ {fee} ETH fee"))
                .size(13)
                .color(t.text)
                .font(bold()),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill);
        if show_details {
            use super::sim_view::{format_gas, format_gwei};
            let gas = format_gas(e.gas_used);
            let basis = match format_gwei(e.base_fee_per_gas) {
                Some(g) => format!("{gas} gas at {g} gwei base fee"),
                None => format!("{gas} gas"),
            };
            fee_row = fee_row
                .push(Space::new().width(8))
                .push(text(basis).size(11).color(t.sub).font(mono()));
        }
        col = col.push(Space::new().height(4));
        col = col.push(fee_row);
    }
    if show_details {
        for caveat in &e.fee_caveats {
            col = col.push(
                text(format!("· {caveat}"))
                    .size(11)
                    .color(t.sub)
                    .font(mono()),
            );
        }
    }

    card(t, col.into())
}

/// The click-to-toggle title row of a fee card ("Network fee", "Cost"): a
/// caret, the title, and a right-aligned summary that stays readable while the
/// card is folded. Emits [`Message::ToggleFeeDetails`].
fn fee_details_toggle<'a>(
    t: KaoTheme,
    title: &'a str,
    summary: Element<'a, Message>,
    show: bool,
) -> Element<'a, Message> {
    let header = row![
        text(if show { "▾" } else { "▸" })
            .size(12)
            .color(t.sub)
            .font(mono()),
        Space::new().width(6),
        text(title).size(12).color(t.sub).font(mono_bold()),
        Space::new().width(Length::Fill),
        summary,
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);
    button(header)
        .width(Length::Fill)
        .padding(0)
        .on_press(Message::ToggleFeeDetails)
        .style(move |_theme, _status| button::Style {
            background: Some(iced::Background::Color(iced::Color::TRANSPARENT)),
            text_color: t.text,
            ..button::Style::default()
        })
        .into()
}

fn card<'a>(t: KaoTheme, content: Element<'a, Message>) -> Element<'a, Message> {
    container(content)
        .padding(Padding::from([12, 14]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(iced::Background::Color(t.card_alt)),
            border: iced::Border {
                color: t.border,
                width: 1.0,
                radius: iced::border::Radius::from(12),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
}

fn slippage_label(bps: u16) -> String {
    // 50 bps → "0.5%", 200 → "2%".
    let pct = bps as f64 / 100.0;
    if (pct.fract()).abs() < f64::EPSILON {
        format!("{pct:.0}%")
    } else {
        format!("{pct}%")
    }
}

fn format_eth(v: U256) -> String {
    if v.is_zero() {
        return "0".to_string();
    }
    let raw = alloy::primitives::utils::format_ether(v);
    let f = raw.parse::<f64>().unwrap_or(0.0);
    if f >= 1.0 {
        format!("{f:.4}")
    } else {
        let s = format!("{f:.8}");
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

/// `validTo` rendered as an absolute UTC instant plus a relative "in N min" so a
/// user can sanity-check the order's lifetime before signing.
fn format_expiry(valid_to: u32) -> String {
    let now = crate::names::manage::now_secs();
    let abs = format_iso_utc(valid_to as u64);
    if now == 0 || (valid_to as u64) <= now {
        return abs;
    }
    let secs = (valid_to as u64).saturating_sub(now);
    let rel = if secs < 90 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{} min", secs / 60)
    } else {
        format!("{} hr", secs / 3600)
    };
    format!("{abs} (in {rel})")
}

/// `YYYY-MM-DD HH:MM UTC` from unix seconds (Howard Hinnant's civil-day algo —
/// the same one `tx_details` uses, kept inline to avoid a chrono dependency).
/// Also the history panes' absolute time (Settings → Signed messages /
/// Connection history).
pub(super) fn format_iso_utc(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = unix_secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02} UTC")
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slippage_label_formats_bps() {
        assert_eq!(slippage_label(50), "0.5%");
        assert_eq!(slippage_label(200), "2%");
        assert_eq!(slippage_label(10), "0.1%");
    }

    #[test]
    fn format_eth_trims_and_floors() {
        assert_eq!(format_eth(U256::ZERO), "0");
        // 1 ETH exactly.
        assert_eq!(
            format_eth(U256::from(1_000_000_000_000_000_000u128)),
            "1.0000"
        );
    }

    #[test]
    fn format_iso_utc_epoch() {
        assert_eq!(format_iso_utc(0), "1970-01-01 00:00 UTC");
    }

    /// Folded, the economics card keeps what moves, the `≈` fee and the
    /// simulation badge; the gas basis, the caveats and the tracking note wait
    /// for the toggle.
    #[test]
    fn economics_card_folds_the_basis_and_caveats() {
        let e = BatchEconomics {
            moves: vec![MovedAmount {
                amount: "1,250.5 USDC".into(),
                direction: MoveDirection::Out,
            }],
            simulated: true,
            verified: false,
            stale: false,
            gas_used: 55_785,
            base_fee_per_gas: 5_000_000,
            fee_caveats: vec!["excludes the L1 data fee".into()],
        };
        let t = KaoTheme::for_kind(crate::ui::kao_theme::ThemeKind::Mint);
        let render =
            |show| super::super::test_support::texts(economics_card(t, &e, show)).join("\n");
        let folded = render(false);
        assert!(folded.contains("1,250.5 USDC"), "{folded}");
        assert!(folded.contains("ETH fee"), "{folded}");
        assert!(folded.contains("Unverified simulation"), "{folded}");
        for detail in ["arriving back", "55,785 gas", "L1 data fee"] {
            assert!(!folded.contains(detail), "{detail} folded away: {folded}");
        }
        let open = render(true);
        for detail in ["arriving back", "55,785 gas", "L1 data fee"] {
            assert!(open.contains(detail), "{detail} unfolded: {open}");
        }
    }

    #[test]
    fn pending_review_starts_without_signing_progress() {
        // A freshly-opened review is in its prepare/confirm phase — no ceremony
        // plan until a Safe dispatch sets one, so the waiting card falls back to
        // the plain single-signature notice.
        let review = SignReview::pending(
            "Cancel order".into(),
            None,
            Vec::new(),
            None,
            0,
            SignAction::CowCancel {
                host: CowHost::Apps,
                uid: "0xabc".into(),
            },
        );
        assert!(review.signing_progress.is_none());
        assert_eq!(review.phase(), "prepare");
    }

    /// A review whose legs are ready, so only the arming window can hold
    /// Confirm back.
    fn ready(action: SignAction) -> SignReview {
        let mut r = SignReview::pending("Review".into(), None, Vec::new(), None, 0, action);
        r.legs_loading = false;
        r
    }

    fn wc_action() -> SignAction {
        SignAction::WalletConnect {
            key: WcKey {
                topic: crate::walletconnect::Topic::new("ab".repeat(32)),
                id: 7,
            },
            plan: WcSignPlan::Personal {
                from: Address::repeat_byte(0x11),
                message: Bytes::from_static(b"hello"),
                pin: B256::ZERO,
            },
        }
    }

    fn cow_cancel() -> SignAction {
        SignAction::CowCancel {
            host: CowHost::Apps,
            uid: "0xabc".into(),
        }
    }

    #[test]
    fn confirm_ignored_before_arming_delay() {
        let t0 = Instant::now();
        let mut r = ready(wc_action());
        r.armed_at = Some(t0);
        assert!(!r.confirm_ready(t0));
        assert!(r.arming(t0));
        assert!(!confirm_enabled(&r, t0), "Confirm is inert while arming");
        let just_before = t0 + ARMING_DELAY - Duration::from_millis(1);
        assert!(!r.confirm_ready(just_before) && r.arming(just_before));
        let armed = t0 + ARMING_DELAY;
        assert!(r.confirm_ready(armed));
        assert!(!r.arming(armed));
        assert!(confirm_enabled(&r, armed));
        // The other gates still apply once armed.
        r.confirm_disabled = true;
        assert!(!confirm_enabled(&r, armed));
    }

    #[test]
    fn non_wc_reviews_have_no_arming_delay() {
        let r = ready(cow_cancel());
        assert!(r.armed_at.is_none(), "`pending` never arms a review");
        let now = Instant::now();
        assert!(r.confirm_ready(now));
        assert!(!r.arming(now));
        assert!(confirm_enabled(&r, now));
        // A freshly opened WC review is not armed either until the
        // coordinator says so.
        assert!(ready(wc_action()).confirm_ready(now));
    }

    #[test]
    fn wc_backdrop_is_ignored() {
        let mut r = ready(wc_action());
        assert!(r.is_walletconnect());
        // Confirming, preparing, and signing: a stray click never refuses a dapp.
        assert!(matches!(backdrop_message(&r), Message::BoxClickIgnored));
        r.legs_loading = true;
        assert!(matches!(backdrop_message(&r), Message::BoxClickIgnored));
        r.armed_at = Some(Instant::now());
        assert!(matches!(backdrop_message(&r), Message::BoxClickIgnored));
        r.signing_since = Some(Instant::now());
        assert!(matches!(backdrop_message(&r), Message::BoxClickIgnored));
    }

    #[test]
    fn non_wc_backdrop_still_cancels() {
        let mut r = ready(cow_cancel());
        assert!(!r.is_walletconnect());
        assert!(matches!(backdrop_message(&r), Message::Cancel));
        r.legs_loading = true;
        assert!(matches!(backdrop_message(&r), Message::Cancel));
        // …but never mid-signature.
        r.signing_since = Some(Instant::now());
        assert!(matches!(backdrop_message(&r), Message::BoxClickIgnored));
    }

    #[test]
    fn safe_execute_ceremony_carries_every_owner() {
        // The execute ceremony lists one entry per signing owner (so the waiting
        // card can spell out each device prompt) and names the account that
        // pays the gas, when a separate one does.
        let kind = SigningKind::SafeExecute {
            owners: vec![
                SigningOwner {
                    label: "Ledger".into(),
                    address: Address::repeat_byte(0x11),
                    hardware: true,
                },
                SigningOwner {
                    label: "Hot key".into(),
                    address: Address::repeat_byte(0x22),
                    hardware: false,
                },
            ],
            gas_payer: Some(SigningOwner {
                label: "Gas payer".into(),
                address: Address::repeat_byte(0x33),
                hardware: false,
            }),
        };
        let SigningKind::SafeExecute { owners, gas_payer } = kind else {
            panic!("expected SafeExecute");
        };
        assert_eq!(owners.len(), 2);
        assert!(owners[0].hardware);
        assert!(!owners[1].hardware);
        assert_eq!(
            gas_payer.map(|p| p.address),
            Some(Address::repeat_byte(0x33))
        );
    }

    #[test]
    fn cow_order_maps_to_the_expected_typed_rows() {
        // Pins the CoW order review content: a dropped/renamed row fails here, and
        // this mapping is exactly what `typed_panel` renders — so it doubles as the
        // pixel-identical guard for the panel refactor.
        let o = OrderReview {
            chain: Chain::Mainnet,
            sell_amount: "1.5".into(),
            sell_symbol: "WETH".into(),
            buy_amount: "4200".into(),
            buy_symbol: "USDC".into(),
            min_received: "4158".into(),
            receiver: Address::repeat_byte(0xAA),
            valid_to: 1_600_000_000, // 2020 — always past, so `Expires` is deterministic
            slippage_bps: 50,
            settlement: Address::repeat_byte(0x55),
            native: false,
            eip712: Eip712Digests::from_parts(B256::ZERO, B256::ZERO),
        };
        let m = o.to_typed_model();

        assert_eq!(m.type_name, "CoW order — EIP-712 signature");
        assert_eq!(
            m.headline.as_deref(),
            Some("Sell 1.5 WETH for at least 4158 USDC")
        );
        let labels: Vec<&str> = m.rows.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "You sell",
                "Receive (est.)",
                "Min received",
                "Receiver",
                "Order type",
                "Solver fee",
                "Expires",
                "Settlement",
                "Network",
                "Settles",
            ],
        );
        assert_eq!(m.rows[0].value, TypedValue::Text("1.5 WETH".into()));
        assert_eq!(m.rows[1].value, TypedValue::Text("4200 USDC".into()));
        assert_eq!(
            m.rows[2].value,
            TypedValue::Text("4158 USDC · 0.5% slippage".into())
        );
        assert_eq!(m.rows[3].value, TypedValue::Addr(o.receiver));
        assert_eq!(m.rows[7].value, TypedValue::Addr(o.settlement));
        assert_eq!(
            m.rows[9].value,
            TypedValue::Text("off-chain via solvers · gasless".into())
        );
    }

    // ── ERC-8213 fingerprints ────────────────────────────────────────────────

    /// A minimal `ReviewLeg` carrying the given calldata (the only field the
    /// ERC-8213 mapping reads).
    fn leg_with(calldata: Bytes) -> ReviewLeg {
        ReviewLeg {
            title: "leg".into(),
            to: Address::repeat_byte(0x01),
            value: U256::ZERO,
            net: crate::chain::NetworkId::Builtin(Chain::Mainnet),
            calldata,
            decoded: Box::new(DecodeResult::Empty),
            sub_legs: Vec::new(),
            self_admin: None,
        }
    }

    /// A minimal `OrderReview` carrying `eip712` (the only field the mapping reads).
    fn order_with(eip712: Eip712Digests) -> OrderReview {
        OrderReview {
            chain: Chain::Mainnet,
            sell_amount: "1".into(),
            sell_symbol: "A".into(),
            buy_amount: "2".into(),
            buy_symbol: "B".into(),
            min_received: "2".into(),
            receiver: Address::repeat_byte(0x5A),
            valid_to: 1_900_000_000,
            slippage_bps: 50,
            settlement: Address::repeat_byte(0x03),
            native: false,
            eip712,
        }
    }

    #[test]
    fn erc8213_rows_raw_tx_is_the_calldata_digest() {
        let calldata = Bytes::from(vec![0x11, 0x22, 0x33]);
        let rows = erc8213_rows(&SignStep::RawTx(leg_with(calldata.clone())));
        assert_eq!(
            rows,
            vec![(
                CALLDATA_DIGEST_LABEL.to_string(),
                digest::calldata_digest(&calldata)
            )],
        );
    }

    #[test]
    fn erc8213_rows_empty_calldata_leg_has_no_fingerprints() {
        // A pure value transfer signs no calldata → the standard prescribes no
        // digest, and the section renders nothing (see `step_card`).
        assert!(erc8213_rows(&SignStep::RawTx(leg_with(Bytes::new()))).is_empty());
    }

    #[test]
    fn erc8213_rows_delegation_has_no_fingerprints() {
        // Deliberate, and worth pinning: an EIP-7702 authorization's signature
        // hash commits to a `nonce` that isn't known until broadcast
        // (self-sponsored ⇒ the outer transaction's nonce + 1). Any digest here
        // would be over a nonce we guessed — worse than none, because the user
        // An already-active delegation signs no authorization at all, so there
        // is no digest to show — and showing one would invite the user to check
        // their device for a prompt that never comes.
        let d = DelegationReview {
            delegate: Address::repeat_byte(0x4C),
            delegate_label: "EF · Simple7702Account".into(),
            authority: Address::repeat_byte(0xE0),
            chain_id: 1,
            net: crate::chain::NetworkId::Builtin(Chain::Mainnet),
            already_active: true,
            incumbent: None,
            auth_nonce: None,
            auth_digest: None,
        };
        assert!(erc8213_rows(&SignStep::Delegation(d)).is_empty());
    }

    /// The one signature whose effect outlives its transaction now has a
    /// digest to hold against the device, because prepare pins the nonce it
    /// commits to instead of leaving it to be discovered at broadcast.
    #[test]
    fn erc8213_rows_delegation_is_the_authorization_digest() {
        let h = B256::repeat_byte(0x7E);
        let d = DelegationReview {
            delegate: Address::repeat_byte(0x4C),
            delegate_label: "EF · Simple7702Account".into(),
            authority: Address::repeat_byte(0xE0),
            chain_id: 1,
            net: crate::chain::NetworkId::Builtin(Chain::Mainnet),
            already_active: false,
            incumbent: None,
            auth_nonce: Some(42),
            auth_digest: Some(h),
        };
        assert_eq!(
            erc8213_rows(&SignStep::Delegation(d)),
            vec![("Authorization Digest (EIP-7702)".to_string(), h)],
        );
    }

    #[test]
    fn erc8213_rows_typed_is_the_full_eip712_triple() {
        let d = Eip712Digests::from_parts(B256::repeat_byte(0xA1), B256::repeat_byte(0xA2));
        let rows = erc8213_rows(&SignStep::Typed(order_with(d)));
        assert_eq!(
            rows,
            vec![
                (EIP712_DIGEST_LABEL.to_string(), d.digest),
                (DOMAIN_HASH_LABEL.to_string(), d.domain_hash),
                (MESSAGE_HASH_LABEL.to_string(), d.message_hash),
            ],
        );
    }

    #[test]
    fn erc8213_rows_safe_exec_shows_the_signed_hash_and_inner_calldata() {
        let d = Eip712Digests::from_parts(B256::repeat_byte(0xB1), B256::repeat_byte(0xB2));
        let inner = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]);
        let x = SafeExecReview {
            safe: Address::repeat_byte(0x5A),
            nonce: 3,
            threshold: 2,
            owner_count: 3,
            // In production this always equals `eip712.digest`.
            safe_tx_hash: d.digest,
            eip712: d,
            inner: Box::new(leg_with(inner.clone())),
            operation: 1,
            guard: None,
            onchain_nonce: 3,
            preflight: None,
            executor: None,
        };
        let rows = erc8213_rows(&SignStep::SafeExec(x));
        assert_eq!(
            rows,
            vec![
                (EIP712_DIGEST_LABEL.to_string(), d.digest),
                (DOMAIN_HASH_LABEL.to_string(), d.domain_hash),
                (MESSAGE_HASH_LABEL.to_string(), d.message_hash),
                (
                    "Calldata Digest (inner call)".to_string(),
                    digest::calldata_digest(&inner)
                ),
            ],
        );
    }

    #[test]
    fn erc8213_rows_safe_message_shows_the_triple_and_the_order_digest() {
        let d = Eip712Digests::from_parts(B256::repeat_byte(0xC1), B256::repeat_byte(0xC2));
        let order_digest = B256::repeat_byte(0xBB);
        let m = SafeMessageReview {
            order: order_with(Eip712Digests::from_parts(B256::ZERO, B256::ZERO)),
            safe: Address::repeat_byte(0x5A),
            threshold: 2,
            owner_count: 3,
            order_digest,
            message_hash: d.digest,
            eip712: d,
        };
        let rows = erc8213_rows(&SignStep::SafeMessage(m));
        // The EIP-712 Digest the owners sign == the SafeMessage hash.
        assert_eq!(rows[0], (EIP712_DIGEST_LABEL.to_string(), d.digest));
        assert_eq!(rows[1].0, DOMAIN_HASH_LABEL);
        assert_eq!(rows[2].0, MESSAGE_HASH_LABEL);
        // …plus the wrapped CoW order digest, so a signer can cross-check the order.
        assert_eq!(
            rows[3],
            ("Order Digest (CoW EIP-712)".to_string(), order_digest),
        );
    }

    /// The CoW `SafeMessage` step keeps exactly its pre-WalletConnect rows: the
    /// SafeMessage triple plus the wrapped order digest — none of the dapp rows
    /// the `Wc*` arms delegate to `sign_review::wc`.
    #[test]
    fn cow_safe_message_rows_unchanged() {
        let d = Eip712Digests::from_parts(B256::repeat_byte(0xC1), B256::repeat_byte(0xC2));
        let order_digest = B256::repeat_byte(0xBB);
        let step = SignStep::SafeMessage(SafeMessageReview {
            order: order_with(Eip712Digests::from_parts(B256::ZERO, B256::ZERO)),
            safe: Address::repeat_byte(0x5A),
            threshold: 2,
            owner_count: 3,
            order_digest,
            message_hash: d.digest,
            eip712: d,
        });
        assert_eq!(
            erc8213_rows(&step),
            vec![
                (EIP712_DIGEST_LABEL.to_string(), d.digest),
                (DOMAIN_HASH_LABEL.to_string(), d.domain_hash),
                (MESSAGE_HASH_LABEL.to_string(), d.message_hash),
                ("Order Digest (CoW EIP-712)".to_string(), order_digest),
            ],
        );
    }

    #[test]
    fn fingerprints_section_defaults_collapsed() {
        let review = SignReview::pending(
            "Cancel order".into(),
            None,
            Vec::new(),
            None,
            0,
            SignAction::CowCancel {
                host: CowHost::Apps,
                uid: "0xabc".into(),
            },
        );
        assert!(!review.show_fingerprints);
    }

    fn delegation(delegate: Address, already_active: bool) -> DelegationReview {
        DelegationReview {
            delegate,
            delegate_label: String::new(),
            authority: Address::repeat_byte(0xE0),
            chain_id: 8453,
            net: crate::chain::NetworkId::Builtin(Chain::Base),
            already_active,
            incumbent: already_active.then_some(delegate),
            auth_nonce: None,
            auth_digest: None,
        }
    }

    #[test]
    fn an_existing_delegation_to_a_known_delegate_folds() {
        use crate::txbuilder::eip7702;
        for delegate in [
            eip7702::EF_SIMPLE_7702_ACCOUNT,
            eip7702::AMBIRE_7702_DELEGATE,
            eip7702::METAMASK_STATELESS_DELEGATOR,
        ] {
            assert!(delegation(delegate, true).collapsible(), "{delegate}");
        }
    }

    #[test]
    fn an_unknown_or_signed_delegation_never_folds() {
        use crate::txbuilder::eip7702;
        // Unrecognised: the warning is the point of the card.
        assert!(!delegation(Address::repeat_byte(0x77), true).collapsible());
        // A fresh authorization is a real signature, known delegate or not.
        assert!(!delegation(eip7702::EF_SIMPLE_7702_ACCOUNT, false).collapsible());
        // Revocation signs an authorization too.
        assert!(!delegation(Address::ZERO, false).collapsible());
    }

    #[test]
    fn folded_delegation_names_the_delegate_and_hides_the_details() {
        let t = KaoTheme::for_kind(crate::ui::kao_theme::ThemeKind::Mint);
        let step = SignStep::Delegation(delegation(
            crate::txbuilder::eip7702::AMBIRE_7702_DELEGATE,
            true,
        ));
        let render = |show| {
            super::super::test_support::texts(step_card(t, &step, false, false, false, show, false))
                .join("\n")
        };
        let folded = render(false);
        assert!(folded.contains("Account delegated to Ambire"), "{folded}");
        assert!(!folded.contains("Your account already runs this code"));
        let open = render(true);
        assert!(
            open.contains("Your account already runs this code"),
            "{open}"
        );
    }

    #[test]
    fn delegation_card_defaults_collapsed() {
        let review = SignReview::pending(
            "Cancel order".into(),
            None,
            Vec::new(),
            None,
            0,
            SignAction::CowCancel {
                host: CowHost::Apps,
                uid: "0xabc".into(),
            },
        );
        assert!(!review.show_delegation);
    }

    /// After an owner's device refused the EIP-712 prompt, Confirm signs the Safe hash as a
    /// personal message and every owner's device shows its EIP-191 digest. That digest stays on
    /// screen while the devices prompt — the moment it has to be checked — with the instruction
    /// said for a prompt that is already up.
    #[test]
    fn eth_sign_fallback_digest_stays_visible_while_signing() {
        let t = KaoTheme::for_kind(crate::ui::kao_theme::ThemeKind::Mint);
        let fallback = OwnerEthSign::of(B256::repeat_byte(0x5e));
        let mut review = SignReview::pending(
            "eth_sendTransaction".into(),
            None,
            Vec::new(),
            None,
            0,
            SignAction::CowCancel {
                host: CowHost::Apps,
                uid: "0xabc".into(),
            },
        );
        review.owner_eth_sign = Some(fallback);
        // The hash rows are copyable widgets, which lay out no text of their own: each is found by
        // its label.
        let shows = |review: &SignReview| {
            let texts = super::super::test_support::texts(view(t, review, 1.0));
            (
                texts
                    .iter()
                    .any(|s| s == "Message hash the device shows (EIP-191)"),
                texts.iter().any(|s| s.contains("asking now")),
            )
        };
        assert_eq!(shows(&review), (true, false), "before Confirm");
        review.signing_since = Some(Instant::now());
        assert_eq!(shows(&review), (true, true), "while the devices prompt");
    }

    /// With no Local gas payer, the first owner's device also signs the executor's transaction,
    /// right after the message prompts. The fallback card says that prompt is coming — told to
    /// approve only the message, the user would reject it and lose every owner's signature.
    #[test]
    fn eth_sign_card_names_the_executor_transaction_that_follows() {
        let t = KaoTheme::for_kind(crate::ui::kao_theme::ThemeKind::Mint);
        let mut review = SignReview::pending(
            "eth_sendTransaction".into(),
            None,
            Vec::new(),
            None,
            0,
            SignAction::CowCancel {
                host: CowHost::Apps,
                uid: "0xabc".into(),
            },
        );
        review.owner_eth_sign = Some(OwnerEthSign::of(B256::repeat_byte(0x5e)));
        review.signing_since = Some(Instant::now());
        let owner = |hardware| SigningOwner {
            label: "Account 1".into(),
            address: Address::repeat_byte(0x11),
            hardware,
        };
        let card = |review: &SignReview| {
            super::super::test_support::texts(view(t, review, 1.0))
                .into_iter()
                .find(|s| s.starts_with("Signing the Safe hash as a personal message"))
                .expect("the eth_sign card's instruction")
        };
        review.signing_progress = Some(SigningKind::SafeExecute {
            owners: vec![owner(true)],
            gas_payer: None,
        });
        let text = card(&review);
        assert!(text.contains("transaction"), "{text}");
        assert!(
            !text.contains("approve only if it shows one of these"),
            "{text}"
        );
        // A Local account pays, or the first owner is a Local key: no device shows a transaction.
        for (owners, gas_payer) in [
            (vec![owner(true)], Some(owner(false))),
            (vec![owner(false), owner(true)], None),
        ] {
            review.signing_progress = Some(SigningKind::SafeExecute { owners, gas_payer });
            assert!(card(&review).contains("approve only if it shows one of these"));
        }
    }

    fn rendered(step: &SignStep, show_calldata: bool) -> Vec<String> {
        let t = KaoTheme::for_kind(crate::ui::kao_theme::ThemeKind::Mint);
        super::super::test_support::texts(step_card(
            t,
            step,
            show_calldata,
            true,
            true,
            true,
            false,
        ))
    }

    /// A call Kao can't decode (a custom network has no verified chain to resolve it against)
    /// still shows its bytes: the selector always, the full calldata behind the toggle.
    #[tokio::test]
    async fn undecoded_calldata_is_shown_raw() {
        let network = crate::net::MockFetcher::new();
        let from = Address::repeat_byte(0x11);
        let to = Address::repeat_byte(0xC1);
        // `approve(0x…badbadbadbad, MAX)`.
        let mut data = vec![0x09, 0x5e, 0xa7, 0xb3];
        data.extend_from_slice(
            B256::left_padding_from(&[0xba, 0xdb, 0xad, 0xba, 0xdb, 0xad]).as_slice(),
        );
        data.extend_from_slice(&U256::MAX.to_be_bytes::<32>());
        let data = Bytes::from(data);
        let net = crate::chain::NetworkId::Custom(31337); // the seeded Anvil row, in memory
        let decoded = super::super::decode_leg(
            &network,
            net,
            from,
            to,
            data.clone(),
            U256::ZERO,
            &std::collections::HashMap::new(),
        )
        .await;
        assert!(matches!(decoded, DecodeResult::Empty));
        let leg = ReviewLeg {
            title: "Call to 0xC1C1…C1C1".into(),
            to,
            value: U256::ZERO,
            net,
            self_admin: None,
            calldata: data,
            decoded: Box::new(decoded),
            sub_legs: Vec::new(),
        };
        let step = SignStep::RawTx(leg);
        let folded = rendered(&step, false).join("\n").to_lowercase();
        assert!(
            folded.contains("095ea7b3"),
            "not even the selector is drawn for undecoded calldata: {folded}"
        );
        let open = rendered(&step, true).join("\n").to_lowercase();
        assert!(
            open.contains("badbad") && open.contains(&"f".repeat(8)),
            "the full calldata isn't reviewable: {open}"
        );
        // The same fallback inside a Safe batch's sub-call.
        let mut outer = leg_with(Bytes::from(vec![0x8d, 0x80, 0xff, 0x0a]));
        let SignStep::RawTx(sub) = step else {
            unreachable!()
        };
        outer.sub_legs = vec![sub];
        let all = rendered(&SignStep::RawTx(outer), true)
            .join("\n")
            .to_lowercase();
        assert!(all.contains("095ea7b3") && all.contains("badbad"), "{all}");
    }
}
