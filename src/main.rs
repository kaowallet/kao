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

    iced::application(App::new, App::update, App::view)
        .title("Kao Wallet")
        .subscription(App::subscription)
        .run()
}
