//! App-level glue between the engine and the iced runtime.
//!
//! The engine runs on a tokio task and speaks `mpsc::UnboundedReceiver<WcEvent>`
//! / `WcEngineHandle`. iced's subscription API wants a `Stream` produced by
//! a function pointer (`Subscription::run(fn() -> Stream)`), so bridging the
//! two needs a place to hand the engine's setup data to the worker without
//! capturing it in a closure.
//!
//! We use two short-lived process-global cells:
//!   * `WC_BOOTSTRAP` — populated by App before the subscription mounts;
//!     drained by the worker on first launch.
//!   * `WC_HANDLE` — populated by the worker after the engine spawns;
//!     read by App when the UI dispatches a command.
//!
//! Both are intentionally `Mutex<Option<...>>` rather than a oneshot channel:
//! the worker may reconnect after a relay drop, so the slot has to be
//! refillable. App resets the slots on lock so a re-unlock with a different
//! wallet doesn't reuse the previous session's identity.

use std::sync::{Mutex, OnceLock};

use iced::futures::SinkExt;
use iced::futures::Stream;
use rand::rngs::OsRng;
use relay_rpc::auth::ed25519_dalek::SigningKey;

use crate::walletconnect::engine::{WcCommand, WcEngineHandle, WcEvent};
use crate::walletconnect::session::PersistedSession;
use crate::walletconnect::transport_reown::ReownTransport;

/// Bundled compile-time WalletConnect Cloud project_id. Read from the
/// `KAO_WC_PROJECT_ID` env var at build time via [`option_env!`]; falls
/// back to the placeholder when the env var is unset (local `cargo build`
/// for unrelated work, or a forgotten CI secret).
///
/// The placeholder is intentionally non-routable so a forgotten swap
/// surfaces as a connect-time error rather than silent use. A
/// hand-rolled `wc_project_id_override` in `settings.toml` takes
/// precedence over this value at runtime — see the unlock handler in
/// `src/app/mod.rs`.
///
/// **Cache coherence**: `build.rs` emits
/// `cargo:rerun-if-env-changed=KAO_WC_PROJECT_ID`, so cargo rebuilds
/// when the env var changes. Without that directive, a cached binary
/// from a previous build would silently retain the old id.
///
/// Not a secret in the cryptographic sense — the project_id only
/// identifies Kao's Cloud account for relay-side rate limiting (akin to
/// a Stripe publishable key). It's still kept out of the repo for
/// operational hygiene: a leaked id can be used to burn through Kao's
/// relay quota under our name, and rotating it is awkward once it lives
/// in `git log`.
pub const KAO_DEFAULT_WC_PROJECT_ID: &str = match option_env!("KAO_WC_PROJECT_ID") {
    Some(v) => v,
    None => "kao_placeholder_project_id",
};

/// Bootstrap context handed off to the subscription worker on first mount.
///
/// `identity_key` is the relay-side ed25519 keypair used to sign the JWT
/// Kao presents to `wss://relay.walletconnect.com`. We mint a fresh one per
/// App launch — the relay JWT TTL is one hour and the key has no role
/// outside that handshake, so persistence buys nothing.
pub struct WcBootstrap {
    pub project_id: String,
    pub identity_key: SigningKey,
    pub initial_sessions: Vec<PersistedSession>,
}

fn bootstrap_cell() -> &'static Mutex<Option<WcBootstrap>> {
    static CELL: OnceLock<Mutex<Option<WcBootstrap>>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(None))
}

fn handle_cell() -> &'static Mutex<Option<WcEngineHandle>> {
    static CELL: OnceLock<Mutex<Option<WcEngineHandle>>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(None))
}

/// Load WC bootstrap data into the global cell so the next subscription
/// mount picks it up. Idempotent — replaces any prior bootstrap.
pub fn install_bootstrap(b: WcBootstrap) {
    *bootstrap_cell().lock().expect("wc bootstrap poisoned") = Some(b);
}

/// Drop both the pending bootstrap and the live engine handle. App calls
/// this on lock so a re-unlock with a different wallet doesn't accidentally
/// keep the previous wallet's sessions live in the worker.
///
/// Currently called only from the not-yet-implemented lock-screen flow;
/// the `#[allow(dead_code)]` comes off when that screen lands.
#[allow(dead_code)]
pub fn reset() {
    *bootstrap_cell().lock().expect("wc bootstrap poisoned") = None;
    *handle_cell().lock().expect("wc handle poisoned") = None;
}

/// Take the live engine handle, if any. Returns `None` while the relay
/// isn't connected — callers must surface that as "WalletConnect offline"
/// rather than queueing the command (the worker has no persistent queue).
pub fn engine_handle() -> Option<WcEngineHandle> {
    handle_cell().lock().expect("wc handle poisoned").clone()
}

/// Dispatch a command to the live engine. `Err(())` means "engine is
/// offline or the runner died" — the command is dropped. The dispatch site
/// is responsible for surfacing the offline state in the UI; if it wants to
/// retry, it must reconstruct the command (we can't return it because
/// `WcEngineHandle::send` consumes the command on failure too).
pub fn dispatch(cmd: WcCommand) -> Result<(), ()> {
    match engine_handle() {
        Some(h) => h.send(cmd).inspect_err(|_| {
            // Handle exists but the runner is gone — clear the slot so
            // subsequent dispatches surface as offline immediately.
            *handle_cell().lock().expect("wc handle poisoned") = None;
        }),
        None => Err(()),
    }
}

/// What the subscription worker emits.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // WcEvent is 264 bytes; boxing it would force a heap alloc per relay frame.
pub enum WcSubMsg {
    /// Worker started but the bootstrap cell was empty. The App should
    /// install bootstrap and the worker will pick it up on the next attempt.
    Idle,
    /// Worker is connecting to the relay. Surfaced so the UI can show a
    /// "connecting…" pip on the Home pane.
    Connecting,
    /// Engine is live and the global handle has been published.
    Connected,
    /// Connection failed before reaching the engine spawn. Worker exits;
    /// the subscription will re-mount on the next `App.subscription()` call
    /// (which iced does after the next user event).
    Failed(String),
    /// Forwarded engine event.
    Engine(WcEvent),
}

/// Fresh ed25519 keypair for the relay JWT. One per App launch.
pub fn generate_identity_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Subscription worker stream. iced calls this function pointer once per
/// mount; the returned stream is driven by iced's futures runtime until the
/// subscription is unmounted (e.g., the app exits).
///
/// Drains [`bootstrap_cell`] on every start. If the cell is empty (App
/// hasn't unlocked yet, or never plans to use WC), emits `Idle` and exits —
/// iced will re-mount the subscription on the next `subscription()` call,
/// at which point the cell may be populated.
pub fn wc_worker() -> impl Stream<Item = WcSubMsg> {
    iced::stream::channel(64, async |mut output| {
        // Drop the lock guard before the first await so the resulting
        // future is `Send` (iced's executor requires it).
        let maybe_boot = {
            let mut guard = bootstrap_cell().lock().expect("wc bootstrap poisoned");
            guard.take()
        };
        let boot = match maybe_boot {
            Some(b) => b,
            None => {
                let _ = output.send(WcSubMsg::Idle).await;
                return;
            }
        };
        let _ = output.send(WcSubMsg::Connecting).await;

        let (transport, inbound_rx, transport_events_rx) =
            match ReownTransport::connect(boot.project_id, boot.identity_key).await {
                Ok(triple) => triple,
                Err(e) => {
                    let _ = output
                        .send(WcSubMsg::Failed(format!("relay connect: {e}")))
                        .await;
                    return;
                }
            };

        let (handle, mut events) = crate::walletconnect::engine::spawn(
            Box::new(transport),
            inbound_rx,
            transport_events_rx,
            boot.initial_sessions,
        );

        {
            let mut hguard = handle_cell().lock().expect("wc handle poisoned");
            *hguard = Some(handle);
        }
        let _ = output.send(WcSubMsg::Connected).await;

        while let Some(ev) = events.recv().await {
            if output.send(WcSubMsg::Engine(ev)).await.is_err() {
                // Subscription dropped — iced unmounted us. Engine task
                // keeps running; on the next mount the worker will see an
                // empty bootstrap cell and emit Idle, which is the right
                // shutdown signal.
                break;
            }
        }

        // Engine ended (both channels closed). Clear the handle slot so
        // further dispatches surface as offline rather than silently
        // failing into a dead sender.
        {
            let mut hguard = handle_cell().lock().expect("wc handle poisoned");
            *hguard = None;
        }
    })
}
