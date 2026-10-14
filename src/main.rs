#![forbid(unsafe_code)]
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod app;
mod approvals;
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
mod sign;
mod trace;
mod txbuilder;
mod ui;
mod wallet;
mod walletconnect;

use app::App;
use tracing_subscriber::EnvFilter;

/// The log filter when `RUST_LOG` is unset (see `main`). The WalletConnect protocol crate logs
/// what a dapp sent — its error text, undecodable messages — verbatim in its warnings, so a dapp
/// could write lines into Kao's log (a newline, then a forged Kao line). Only its errors pass;
/// Kao logs WalletConnect itself, shape only.
const DEFAULT_LOG_FILTER: &str = "kao=info,wallet_connect=error,warn";

pub fn main() -> iced::Result {
    // Default to our own crate at info; everything else (helios, alloy, hyper)
    // stays at warn so their per-request chatter doesn't spam stderr — and the
    // WalletConnect crate at error, as it echoes dapp text. Override
    // via RUST_LOG, e.g. `RUST_LOG=kao=debug` to see redacted addresses or
    // `RUST_LOG=kao=trace` to see raw addresses and per-token reads.
    //
    // GUI state tracing (see `crate::trace`): `RUST_LOG=kao::gui=debug` logs
    // coarse state transitions (screen/pane/modal/stage changes, outcomes);
    // `RUST_LOG=kao::gui=trace` additionally logs every message entering
    // every update() — the full GUI state machine, secret inputs redacted.
    // This is the stream an AI agent should watch when debugging the GUI.
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_FILTER));
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

    let app = iced::application(App::new, App::update, App::view)
        .title("Kao Wallet")
        .subscription(App::subscription);
    // Wayland/X11 app id, matching flatpak/com.kaowallet.kao.desktop so the
    // session shell associates the window with that desktop entry.
    #[cfg(target_os = "linux")]
    let app = app.window(linux_window());
    // Closing the window must end WalletConnect sessions before the process
    // goes: `App` subscribes to close requests, tears the runtime down
    // (bounded) and exits itself. Set after `.window(..)`, which replaces the
    // whole window settings and would reset this.
    let app = app.exit_on_close_request(false);
    app.run()
}

/// Desktop id shared with the Flatpak manifest and the cargo-packager identifier.
#[cfg(target_os = "linux")]
const DESKTOP_APP_ID: &str = "com.kaowallet.kao";

#[cfg(target_os = "linux")]
fn linux_window() -> iced::window::Settings {
    iced::window::Settings {
        platform_specific: iced::window::settings::PlatformSpecific {
            application_id: DESKTOP_APP_ID.to_owned(),
            ..Default::default()
        },
        ..Default::default()
    }
}
