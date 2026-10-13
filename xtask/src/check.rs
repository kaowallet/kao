use std::path::Path;
use std::process::Command;

use anyhow::Result;

pub fn check(workspace_root: &Path) -> Result<()> {
    let steps: &[(&str, &[&str])] = &[
        ("fmt", &["fmt", "--all", "--", "--check"]),
        (
            "clippy",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--locked",
                "--",
                "-D",
                "warnings",
            ],
        ),
        ("test", &["test", "--workspace", "--locked"]),
        // cargo-deny takes yanked status from cargo's local index cache and
        // only fetches entries missing from it, so a stale cache hides yanks
        // that CI (cold cache) reports. A dry-run update re-resolves against
        // the live index, refreshing the cache without touching Cargo.lock.
        ("refresh-index", &["update", "--dry-run", "--quiet"]),
        (
            "cargo-deny",
            &["deny", "check", "advisories", "bans", "licenses", "sources"],
        ),
        ("cargo-vet", &["vet", "--locked"]),
    ];

    let mut failures: Vec<&str> = Vec::new();

    for (name, args) in steps {
        eprintln!("\n::: {name} :::");
        let status = Command::new("cargo")
            .args(*args)
            .current_dir(workspace_root)
            .status();
        match status {
            Ok(s) if s.success() => eprintln!("  ok"),
            Ok(s) => {
                eprintln!("  FAILED (exit {})", s.code().unwrap_or(-1));
                failures.push(name);
            }
            Err(e) => {
                eprintln!("  FAILED to spawn cargo: {e}");
                failures.push(name);
            }
        }
    }

    eprintln!();
    if failures.is_empty() {
        eprintln!("all checks passed");
        Ok(())
    } else {
        eprintln!("failed: {}", failures.join(", "));
        std::process::exit(1);
    }
}
