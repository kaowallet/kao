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

use std::time::Instant;

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
    self, CALLDATA_DIGEST_LABEL, DOMAIN_HASH_LABEL, EIP712_DIGEST_LABEL, Eip712Digests,
    MESSAGE_HASH_LABEL,
};
use crate::sign::typed::{IntoTypedModel, TypedDataModel, TypedRow, TypedValue};
use crate::ui::kao_theme::KaoTheme;
use crate::ui::kao_widgets::{
    bold, bullet_wave, colored_address, colored_hash_copyable, kao_scrollable_style, modal_wrapper,
    mono, mono_bold, primary_button, secondary_button,
};
use crate::wallet::tx::{SendPlan, TxQuote};

use super::CowHost;

const MODAL_WIDTH: f32 = 520.0;
const FORM_MAX_HEIGHT: f32 = 520.0;

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
    /// device in turn, then the transaction is broadcast — by a separate linked
    /// gas payer when `separate_gas_payer`, otherwise by re-using the first owner
    /// (one extra prompt on that device).
    SafeExecute {
        owners: Vec<SigningOwner>,
        separate_gas_payer: bool,
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
    /// Signed and broadcast; waiting for the receipt that says whether it
    /// actually worked. The overlay stays up through this because a broadcast
    /// hash is not an outcome — a reverted transaction is broadcast exactly as
    /// successfully as one that succeeds.
    Broadcasting { hash: B256 },
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

    /// Nothing to say at all — no movements and no fee. The card is skipped
    /// entirely rather than rendering an empty box.
    pub fn is_empty(&self) -> bool {
        self.moves.is_empty() && self.fee_eth().is_none()
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
    /// Expand state for the Send step's "for the paranoid" decoded-calldata block.
    pub show_calldata: bool,
    /// Expand state for the "ERC-8213 fingerprints" section on every reviewed
    /// step (the signature/calldata digests). One flag toggles them all together.
    pub show_fingerprints: bool,
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
            economics: None,
            broadcast: None,
            show_calldata: false,
            show_fingerprints: false,
            signing_progress: None,
        };
        // Coordinator-driven open: every caller assigns this straight into the
        // overlay slot (guarded by an is-already-open early return), so the
        // open transition is traced at the one construction site.
        crate::trace::state("sign_review", "phase", "closed", review.phase());
        review
    }
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
            let gap = if matches!(review.steps[i - 1], SignStep::Typed(_)) {
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
        body = body.push(economics_card(t, e));
    }

    if let Some(note) = &review.note {
        body = body.push(Space::new().height(12));
        body = body.push(text(note).size(11).color(t.sub).font(mono()));
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
        let enabled = !review.legs_loading && !review.confirm_disabled && !broadcast;
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
        // full-width below the Cancel/Confirm row, gated the same as Confirm.
        if let Some(sec) = &review.secondary_label {
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
    // no-op; before confirm it cancels as usual.
    let on_backdrop = if review.signing_since.is_some() {
        Message::BoxClickIgnored
    } else {
        Message::Cancel
    };
    modal_wrapper(
        t,
        MODAL_WIDTH,
        progress,
        on_backdrop,
        Message::BoxClickIgnored,
        bounded.into(),
    )
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
        Some(SigningKind::SafeExecute { owners, .. }) if owners.len() > 1
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
        Some(SigningKind::SafeExecute {
            owners,
            separate_gas_payer,
        }) => {
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
            let broadcast = if *separate_gas_payer {
                "Then a linked account broadcasts it and pays the gas."
            } else {
                "Then owner 1 re-signs to broadcast it and pay the gas."
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
fn step_card<'a>(
    t: KaoTheme,
    step: &'a SignStep,
    show_calldata: bool,
    show_fingerprints: bool,
) -> Element<'a, Message> {
    let panel = match step {
        SignStep::RawTx(leg) => leg_card(t, leg, show_calldata),
        SignStep::Delegation(d) => delegation_panel(t, d),
        SignStep::Typed(order) => order_panel(t, order),
        SignStep::SafeExec(x) => safe_exec_panel(t, x, show_calldata),
        SignStep::SafeMessage(m) => safe_message_panel(t, m),
        SignStep::Send(r) => {
            super::send::render_send_review(t, r, show_calldata, Message::ToggleCalldata)
        }
        SignStep::SafeSend(r) => super::send::render_safe_send_review::<Message>(t, r),
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
            push_calldata(&mut rows, "Calldata Digest (inner call)", &x.inner.calldata);
        }
        SignStep::SafeMessage(m) => {
            push_eip712(&mut rows, &m.eip712);
            rows.push(("Order Digest (CoW EIP-712)".to_string(), m.order_digest));
        }
        SignStep::Send(r) => {
            if let Some(cd) = r.calldata_digest {
                rows.push((CALLDATA_DIGEST_LABEL.to_string(), cd));
            }
        }
        SignStep::SafeSend(r) => {
            push_eip712(&mut rows, &r.eip712);
            if let Some(cd) = r.inner_calldata_digest {
                rows.push(("Calldata Digest (inner call)".to_string(), cd));
            }
        }
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
    use crate::txbuilder::multisend::{MULTISEND_CALL_ONLY_1_3_0, MULTISEND_CALL_ONLY_1_4_1};
    let (title, msg) = if operation == 1 {
        let target = match to {
            MULTISEND_CALL_ONLY_1_3_0 => {
                "The target is the canonical Safe MultiSendCallOnly 1.3.0 library, which can \
                 only make plain calls — this is the expected shape for a batch."
                    .to_string()
            }
            MULTISEND_CALL_ONLY_1_4_1 => {
                "The target is the canonical Safe MultiSendCallOnly 1.4.1 library, which can \
                 only make plain calls — this is the expected shape for a batch."
                    .to_string()
            }
            other => format!(
                "The target {} is NOT a canonical Safe MultiSend library. Do not sign unless \
                 you know exactly what code lives there.",
                crate::wallet::short_address(other)
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
fn delegation_panel<'a>(t: KaoTheme, d: &'a DelegationReview) -> Element<'a, Message> {
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
        text(match (d.already_active, d.replacing().is_some()) {
            (true, _) => "Your account already runs this code",
            (false, true) => "Your account will be re-pointed to different code",
            (false, false) => "Your account will start running contract code",
        })
        .size(13)
        .color(t.text)
        .font(bold()),
    );
    col = col.push(Space::new().height(8));
    col = col.push(addr_kv(t, "Your account", d.authority));
    // Naming the incumbent first makes the swap legible as a swap: without it,
    // an account already delegated elsewhere reads identically to a fresh one.
    if let Some(prev) = d.replacing() {
        col = col.push(addr_kv(t, "Currently delegated to", prev));
    }
    col = col.push(addr_kv(t, "Delegates to", d.delegate));
    col = col.push(kv(t, "Delegate", d.delegate_label.clone()));
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
        text(match (d.already_active, d.replacing().is_some()) {
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
                 transaction — your account keeps running this code until you replace it."
            }
        })
        .size(11)
        .color(if d.already_active { t.sub } else { t.down })
        .font(bold()),
    );
    card(t, col.into())
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
fn economics_card<'a>(t: KaoTheme, e: &'a BatchEconomics) -> Element<'a, Message> {
    let mut col = column![].spacing(4).width(Length::Fill);

    let header = row![
        text(if e.moves.is_empty() {
            "Cost"
        } else {
            "This transaction moves"
        })
        .size(12)
        .color(t.sub)
        .font(mono_bold()),
        Space::new().width(Length::Fill),
        // Freshness is checked before verification: a Helios-verified read of
        // a balance that has since moved is precisely verified and no longer
        // true, so the badge must not lead with the tick.
        text(if !e.simulated {
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
        .font(bold()),
    ]
    .align_y(Alignment::Center)
    .width(Length::Fill);
    col = col.push(header);

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

    // Absence of token rows is only evidence of "moves no tokens" when a
    // simulation actually ran. Without one, say so where the rows would be —
    // an empty list under a "this transaction moves" header otherwise reads as
    // a positive finding.
    if !e.simulated {
        col = col.push(
            text(
                "Token movement wasn't simulated for this batch, so this list covers only the \
                 native value the calls carry — run the preflight to see ERC-20 and NFT \
                 movement.",
            )
            .size(11)
            .color(t.sub)
            .font(mono()),
        );
    } else {
        // The one hole a successful simulation still leaves. Balance changes
        // are recovered from `Transfer` logs, and native ETH *arriving* emits
        // none — an unwrap or a refund lands in the account with nothing here
        // to show for it. The outgoing side is exact (it is the calls' own
        // `value`), so the gap is one-directional and worth naming as such.
        col = col.push(
            text(
                "ETH arriving back in the account isn't tracked here — native transfers emit no \
                 event. The ETH these calls send is exact.",
            )
            .size(11)
            .color(t.sub)
            .font(mono()),
        );
    }

    if let Some(fee) = e.fee_eth() {
        let basis = match crate::ui::wallet_dashboard::sim_view::format_gwei(e.base_fee_per_gas) {
            Some(g) => format!(
                "{} gas at {g} gwei base fee",
                crate::ui::wallet_dashboard::sim_view::format_gas(e.gas_used)
            ),
            None => format!(
                "{} gas",
                crate::ui::wallet_dashboard::sim_view::format_gas(e.gas_used)
            ),
        };
        col = col.push(Space::new().height(4));
        col = col.push(
            row![
                text(format!("≈ {fee} ETH fee"))
                    .size(13)
                    .color(t.text)
                    .font(bold()),
                Space::new().width(8),
                text(basis).size(11).color(t.sub).font(mono()),
            ]
            .align_y(Alignment::Center)
            .width(Length::Fill),
        );
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
fn format_iso_utc(unix_secs: u64) -> String {
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

    #[test]
    fn safe_execute_ceremony_carries_every_owner() {
        // The execute ceremony lists one entry per signing owner (so the waiting
        // card can spell out each device prompt) and records whether a separate
        // account pays the gas.
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
            separate_gas_payer: true,
        };
        let SigningKind::SafeExecute {
            owners,
            separate_gas_payer,
        } = kind
        else {
            panic!("expected SafeExecute");
        };
        assert_eq!(owners.len(), 2);
        assert!(owners[0].hardware);
        assert!(!owners[1].hardware);
        assert!(separate_gas_payer);
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
}
