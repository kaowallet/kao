#![forbid(unsafe_code)]

mod app;
mod chain;
mod decode;
mod ens;
mod indexer;
mod net;
mod paths;
mod portfolio;
mod settings;
mod ui;
mod wallet;
mod walletconnect;

use app::App;
use tracing_subscriber::EnvFilter;

pub fn main() -> iced::Result {
    // Default to our own crate at info; everything else (helios, alloy, hyper)
    // stays at warn so their per-request chatter doesn't spam stderr. Override
    // via RUST_LOG, e.g. `RUST_LOG=kao=debug` to see redacted addresses or
    // `RUST_LOG=kao=trace` to see raw addresses and per-token reads.
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("kao=info,warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();

    // Pick a rustls crypto provider before any TLS handshake runs. Both
    // `aws-lc-rs` and `ring` are linked in (reqwest's rustls-tls pulls
    // aws-lc-rs; relay_client's `rustls` feature pulls ring) — when both
    // providers are compiled in, rustls 0.23 refuses to auto-pick and
    // panics on first connect. `install_default()` is a one-shot; we
    // ignore `Err` so a second binary embedding (tests, future ffi) doesn't
    // panic.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    iced::application(App::new, App::update, App::view)
        .title("Kao Wallet")
        .subscription(App::subscription)
        .run()
}
