//! Unified signing pipeline.
//!
//! Phase 0 introduces [`broadcast`], the single EOA broadcast primitive that
//! the send / on-chain-call paths share — replacing the byte-identical
//! `build TxEip1559 → KaoSigner::sign_tx → encoded_2718 → send_raw_transaction`
//! tail that `wallet::tx::sign_and_send` and `cow::onchain::send_contract_call`
//! each hand-rolled. Later phases grow a signable-artifact model, a generic
//! EIP-712 renderer, and the Safe owner-ceremony arm on top of it.

pub mod broadcast;
pub mod context;
pub mod typed;
