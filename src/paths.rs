//! Resolved on-disk locations for kao's config and data, with cross-platform
//! fallbacks via the `dirs` crate.
//!
//! - **config**: `$XDG_CONFIG_HOME/kao/` on Linux, `~/Library/Application Support/kao/`
//!   on macOS, `%APPDATA%\kao\` on Windows.
//! - **data**: `$XDG_DATA_HOME/kao/` on Linux, `~/Library/Application Support/kao/`
//!   on macOS, `%APPDATA%\kao\` on Windows.
//!
//! When the platform helper can't resolve a base dir (no HOME, no APPDATA),
//! both fall through to `./kao/` so the app still runs out of CWD.
//!
//! Test builds never resolve to those places. Every test that builds a
//! dashboard reaches the templates store (the Apps pane loads it on
//! construction), and the app shell reads `settings.toml`; with the real
//! directories a test run would read the user's config and let redb rewrite
//! the header of their `templates.redb`. Under `cfg(test)` both functions
//! answer a per-process directory under the system temp dir instead, which is
//! only created if a test actually writes through it.

use std::path::PathBuf;

const APP_DIR: &str = "kao";

#[cfg(not(test))]
pub fn config_dir() -> PathBuf {
    platform_config_dir()
}

#[cfg(not(test))]
pub fn data_dir() -> PathBuf {
    platform_data_dir()
}

#[cfg(test)]
pub fn config_dir() -> PathBuf {
    test_root().join("config").join(APP_DIR)
}

#[cfg(test)]
pub fn data_dir() -> PathBuf {
    test_root().join("data").join(APP_DIR)
}

fn platform_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(APP_DIR)
}

fn platform_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(APP_DIR)
}

/// The stand-in for both platform directories in a test build: one directory
/// per test process, so a run never shares files with the user's install or
/// with another concurrent run.
#[cfg(test)]
fn test_root() -> PathBuf {
    std::env::temp_dir().join(format!("kao-test-{}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_dir_ends_in_app_dir() {
        for p in [platform_config_dir(), config_dir()] {
            assert_eq!(p.file_name().and_then(|s| s.to_str()), Some(APP_DIR));
        }
    }

    #[test]
    fn data_dir_ends_in_app_dir() {
        for p in [platform_data_dir(), data_dir()] {
            assert_eq!(p.file_name().and_then(|s| s.to_str()), Some(APP_DIR));
        }
    }

    #[test]
    fn config_dir_parent_matches_dirs_or_cwd() {
        let parent = platform_config_dir().parent().unwrap().to_path_buf();
        let expected = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        assert_eq!(parent, expected);
    }

    #[test]
    fn data_dir_parent_matches_dirs_or_cwd() {
        let parent = platform_data_dir().parent().unwrap().to_path_buf();
        let expected = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
        assert_eq!(parent, expected);
    }

    /// A test build must never resolve to the user's real directories: the
    /// dashboard opens the templates store and the shell reads settings on
    /// construction, so anything else lets a test run touch the user's files.
    #[test]
    fn test_builds_never_resolve_to_the_real_directories() {
        let sandbox = test_root();
        for (got, real) in [
            (config_dir(), platform_config_dir()),
            (data_dir(), platform_data_dir()),
        ] {
            assert!(got.starts_with(&sandbox), "{got:?} is outside {sandbox:?}");
            assert!(!got.starts_with(&real), "{got:?} is the real {real:?}");
        }
        assert!(sandbox.starts_with(std::env::temp_dir()));
        // The store every dashboard-building test opens.
        let templates = crate::txbuilder::templates::db_path();
        assert!(
            templates.starts_with(&sandbox),
            "{templates:?} is outside {sandbox:?}"
        );
    }
}
