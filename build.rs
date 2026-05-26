//! Build script that bundles every `assets/<chain>/<address>/logo.svg`
//! into the binary via `include_bytes!`. The generated `logos.rs` is a
//! flat slice that `src/ui/token_logos.rs` reshapes into a
//! `(Chain, Address) -> Handle` map. Running `cargo xtask sync-tokens`
//! repopulates the directory; cargo re-runs this script automatically on
//! any change inside `assets/`.

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

const CHAINS: &[&str] = &["ethereum", "optimism", "base"];

fn main() {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let assets = manifest_dir.join("assets");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let dest = out_dir.join("logos.rs");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", assets.display());
    // WalletConnect Cloud project id, baked into the binary via
    // `option_env!` in `walletconnect::runtime`. Re-running on change
    // keeps `cargo build` cache-coherent: without this directive, cargo
    // wouldn't notice a new env value and would hand back a stale binary
    // with the previous (or empty) id compiled in.
    println!("cargo:rerun-if-env-changed=KAO_WC_PROJECT_ID");

    let mut entries: Vec<(&'static str, String, PathBuf)> = Vec::new();
    for chain in CHAINS {
        let chain_dir = assets.join(chain);
        if !chain_dir.is_dir() {
            continue;
        }
        println!("cargo:rerun-if-changed={}", chain_dir.display());
        let mut addr_dirs: Vec<PathBuf> = fs::read_dir(&chain_dir)
            .unwrap_or_else(|e| panic!("read {chain_dir:?}: {e}"))
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        addr_dirs.sort();
        for addr_dir in addr_dirs {
            let logo = addr_dir.join("logo.svg");
            if !logo.is_file() {
                continue;
            }
            println!("cargo:rerun-if-changed={}", logo.display());
            let addr = addr_dir
                .file_name()
                .and_then(|n| n.to_str())
                .expect("non-utf8 asset dir name")
                .to_owned();
            entries.push((chain, addr, logo));
        }
    }

    let mut f = fs::File::create(&dest).expect("create logos.rs");
    writeln!(f, "&[").unwrap();
    for (chain, addr, logo) in &entries {
        writeln!(
            f,
            "    (\"{chain}\", \"{addr}\", include_bytes!({:?})),",
            logo.to_string_lossy()
        )
        .unwrap();
    }
    writeln!(f, "]").unwrap();
}
