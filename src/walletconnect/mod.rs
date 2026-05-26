//! WalletConnect Sign v2 (wallet-side) implementation.
//!
//! Layered on top of `reown-com/reown-rust`'s relay client, which only ships
//! the relay-server JSON-RPC transport. The Sign protocol on top of the
//! relay — pairing crypto, session envelopes, method routing — is what this
//! module implements.
//!
//! Layout
//! ------
//! - [`crypto`] — Type 0 / Type 1 envelope codec, HKDF-SHA256 session-key
//!   derivation, `sha256(symKey) → topic`, ephemeral x25519 keypair for the
//!   sessionSettle handshake.
//! - [`uri`]    — Parser for `wc:<topic>@2?relay-protocol=irn&symKey=<hex>…`
//!   pairing URIs.
//! - [`protocol`] — Sign v2 JSON-RPC envelope types + per-method tag/TTL
//!   constants from the spec.
//! - [`transport`] — `RelayTransport` trait abstracting the underlying
//!   WebSocket relay client. Concrete `reown-rust` adapter and the engine
//!   that drives it land in a later phase.
//!
//! This module is Phase 1 of the WalletConnect Sign v2 integration. The
//! engine, session state machine, method dispatch, persistence, Verify API,
//! and UI come in subsequent phases. See
//! `/home/agent/.claude/plans/yeah-lets-go-path-valiant-rain.md`.

// The submodules carry `#![allow(dead_code)]` because most items are
// designed for downstream phases (UI integration in Phase 5/6) to consume.
// `cargo xtask check` runs clippy with `-D warnings`; the allows come off
// as later phases import the relevant items.
pub mod crypto;
pub mod engine;
pub mod methods;
pub mod protocol;
pub mod runtime;
pub mod session;
pub mod state;
pub mod transport;
pub mod transport_reown;
pub mod uri;
pub mod verify;
