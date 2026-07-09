//! Transaction Builder — compose arbitrary contract calls, queue them
//! into a batch, simulate, and execute.
//!
//! Two execution shapes, gated by whether a Safe is active:
//!
//! - **Safe** — the queue of N calls is packed into a single
//!   `MultiSendCallOnly` payload and wrapped in ONE `SafeTx`
//!   (`operation = DelegateCall` to the canonical MultiSend contract).
//!   The Safe executes all N sub-calls atomically: if any reverts, the
//!   whole batch reverts. Threshold owner signatures are collected
//!   through the shared `sign_review` overlay, then broadcast via
//!   `safe::tx::execute_safe_tx`.
//! - **Plain EOA** — atomic batching is achieved via EIP-7702: the account
//!   delegates its code to the EF `Simple7702Account` and self-calls
//!   `executeBatch(Call[])` in one `SetCode` (type `0x04`) transaction, so N
//!   calls run all-or-nothing (see `eip7702`). A single-call batch, or an
//!   account whose signer can't authorize a delegation (Trezor / view-only),
//!   still broadcasts as an ordinary EIP-1559 transaction through the same
//!   review/broadcast pipeline the Send flow uses.
//!
//! This module holds the *domain* logic (ABI loading, calldata encoding,
//! MultiSend packing, batch simulation glue, JSON import/export). The UI
//! state machine lives in `ui::wallet_dashboard::tx_builder`; it owns no
//! I/O and bubbles work to the dashboard coordinator via `Outcome`s, per
//! the same convention as the Names and Privacy Pools apps.

pub mod abi;
pub mod bundle;
pub mod eip7702;
pub mod encode;
pub mod multisend;
pub mod sim;

use alloy::primitives::{Address, Bytes, U256};

/// One decoded argument of a composed contract call, retained so the
/// review/queue UI can render the `name = value` block without a second
/// decode round-trip. `value` is already humanised for display (checksummed
/// address, decimal integer, `0x…` hex) — it is *not* re-parsed for
/// encoding; the authoritative bytes live in [`QueuedCall::data`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedArg {
    pub name: String,
    pub ty: String,
    pub value: String,
}

/// A single call queued in the batch. Self-contained: it carries the
/// already-ABI-encoded `data`, so simulation, MultiSend packing, and
/// broadcast never re-encode from user input (the reviewed bytes are the
/// signed bytes). `signature` is `None` for a raw-hex call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedCall {
    /// Stable per-session id for reorder/remove keying in the UI. Not
    /// serialized — a re-imported batch is renumbered.
    pub id: u64,
    /// Target contract / recipient.
    pub to: Address,
    /// ETH value in wei sent with the call (payable methods / raw sends).
    pub value: U256,
    /// The exact calldata that will be executed and signed over.
    pub data: Bytes,
    /// Short human title, e.g. `USDC.approve` or `Raw call`.
    pub title: String,
    /// One-line detail, e.g. `5,000 → 0x8787…4E2` or `68 bytes calldata`.
    pub detail: String,
    /// Canonical function signature (`approve(address,uint256)`) for a
    /// decoded contract call; `None` for raw hex.
    pub signature: Option<String>,
    /// Decoded arguments for the expandable decode panel; empty for raw.
    pub decoded_args: Vec<DecodedArg>,
}

impl QueuedCall {
    /// True for a raw-hex call (no ABI-decoded signature).
    pub fn is_raw(&self) -> bool {
        self.signature.is_none()
    }

    /// The 4-byte function selector, if the calldata is at least 4 bytes.
    pub fn selector(&self) -> Option<[u8; 4]> {
        (self.data.len() >= 4).then(|| {
            let mut s = [0u8; 4];
            s.copy_from_slice(&self.data[..4]);
            s
        })
    }
}

/// Errors surfaced by the builder's domain layer. String-carrying, per the
/// crate convention (`WalletError` / `PoolError`) — the UI renders the
/// `Display` message directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxBuilderError {
    /// A user-supplied contract address, ABI, or parameter didn't parse /
    /// validate.
    Input(String),
    /// A pasted ABI JSON blob was malformed.
    Abi(String),
    /// The batch or a call couldn't be assembled (e.g. empty batch, or a
    /// MultiSend total-value overflow).
    Assembly(String),
}

impl std::fmt::Display for TxBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input(s) => write!(f, "{s}"),
            Self::Abi(s) => write!(f, "invalid ABI: {s}"),
            Self::Assembly(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for TxBuilderError {}
