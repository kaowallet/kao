#![forbid(unsafe_code)]
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod app;
mod chain;
mod cow;
mod decode;
mod indexer;
mod names;
mod net;
mod paths;
mod pool;
mod portfolio;
mod safe;
mod sanitize;
mod settings;
mod trace;
mod ui;
mod wallet;

use app::App;
use tracing_subscriber::EnvFilter;

pub fn main() -> iced::Result {
    // Default to our own crate at info; everything else (helios, alloy, hyper)
    // stays at warn so their per-request chatter doesn't spam stderr. Override
    // via RUST_LOG, e.g. `RUST_LOG=kao=debug` to see redacted addresses or
    // `RUST_LOG=kao=trace` to see raw addresses and per-token reads.
    //
    // GUI state tracing (see `crate::trace`): `RUST_LOG=kao::gui=debug` logs
    // coarse state transitions (screen/pane/modal/stage changes, outcomes);
    // `RUST_LOG=kao::gui=trace` additionally logs every message entering
    // every update() — the full GUI state machine, secret inputs redacted.
    // This is the stream an AI agent should watch when debugging the GUI.
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("kao=info,warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();

    // Load persisted settings and, if the user enabled a proxy, install it
    // process-wide *before* iced spawns any thread or builds any HTTP client.
    // reqwest's `ALL_PROXY` is the only proxy hook helios's internally-built
    // clients honour, so this is what routes ALL outbound traffic (helios
    // consensus/execution, the alloy fallback provider, indexers, the Safe
    // service, ENS) through the proxy. It must run here, single-threaded, at
    // startup: installing it mutates the environment, which is only sound
    // before other threads exist. A proxy change therefore applies on the
    // next launch, not mid-session.
    settings::load();
    if settings::proxy_enabled() {
        let stored = settings::proxy_address();
        let stored = stored.trim();
        // Defence in depth: `load()` reads the address straight from disk
        // without going through `set_proxy_address`, so a hand-edited config
        // could carry a malformed value. Never install an invalid proxy URL —
        // reqwest would silently ignore it and connect directly, leaking the
        // real IP. Fall back to the Tor default, which fails closed if Tor
        // isn't running.
        let addr = if settings::valid_proxy_address(stored) {
            stored.to_string()
        } else {
            tracing::warn!(
                "configured proxy address is invalid; falling back to the default to avoid a direct connection"
            );
            "127.0.0.1:9050".to_string()
        };
        proxy_env::set_all_proxy(&format!("socks5h://{addr}"));
        tracing::info!("routing all outbound traffic through the configured SOCKS5 proxy");
    }

    iced::application(App::new, App::update, App::view)
        .title("Kao Wallet")
        .subscription(App::subscription)
        .run()
}
