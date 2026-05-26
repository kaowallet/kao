//! Thin wrapper around the OS keyring (`keyring` crate).
//!
//! Acts as the external trust anchor for state that must not roll back
//! together with `wallet.redb` — the planned consumer is a monotonic epoch
//! that protects contacts and the clear-signing ABI registry from an
//! attacker who swaps the wallet file for an older snapshot. The wrapper
//! exposes a small synchronous bytes API; callers decide what to put in.
//!
//! # Backend
//!
//! - macOS: Apple Keychain
//! - Windows: Credential Manager
//! - Linux: Secret Service (GNOME Keyring / KWallet via D-Bus)
//!
//! All entries live under the service name `"com.kaowallet"` (reverse-DNS
//! of the project's domain, to avoid colliding with any other "kao" tool
//! on the same machine); `name` is the per-purpose key (currently
//! `wallet-epoch-<hex(salt[..8])>`, written by `wallet::store`).
//!
//! # Errors
//!
//! Three categories, deliberately coarse so callers can apply policy
//! without re-reading the underlying error chain:
//!
//! - [`KeyringError::Unavailable`]: the backend itself is unreachable
//!   (D-Bus down on Linux, Keychain locked, Credential Manager service
//!   stopped). Wallet policy is to refuse to open on this — never silently
//!   degrade — so this maps to a hard "can't proceed" upstream.
//! - [`KeyringError::Backend`]: anything else from the backend (encoding
//!   issues, oversize values, ambiguous matches). Bug-shaped, not
//!   environment-shaped.
//!
//! Note: "no entry exists yet" is **not** an error — `read_secret` returns
//! `Ok(None)` so callers can distinguish first-run from a real failure.

const SERVICE: &str = "com.kaowallet";

#[derive(Debug)]
pub enum KeyringError {
    /// The OS keyring backend is unreachable — Linux Secret Service / D-Bus
    /// not running, Keychain locked, Windows Credential Manager service
    /// stopped. Distinct from [`KeyringError::Backend`] so the wallet can
    /// surface a "fix your environment" message instead of a generic crash.
    Unavailable(String),
    /// Other backend-side failures: encoding, oversize, ambiguous match.
    /// Should be rare for our usage (small fixed-size byte values).
    Backend(String),
}

impl std::fmt::Display for KeyringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyringError::Unavailable(msg) => write!(f, "keyring unavailable: {msg}"),
            KeyringError::Backend(msg) => write!(f, "keyring backend error: {msg}"),
        }
    }
}

impl std::error::Error for KeyringError {}

/// Read a secret. `Ok(None)` means "no entry stored under this name" — a
/// normal first-run state, not an error. `Err` always indicates the backend
/// itself misbehaved.
pub fn read_secret(name: &str) -> Result<Option<Vec<u8>>, KeyringError> {
    let entry = keyring::Entry::new(SERVICE, name).map_err(map_err)?;
    match entry.get_secret() {
        Ok(bytes) => Ok(Some(bytes)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(map_err(e)),
    }
}

/// Write (or overwrite) a secret. Last write wins.
pub fn write_secret(name: &str, value: &[u8]) -> Result<(), KeyringError> {
    let entry = keyring::Entry::new(SERVICE, name).map_err(map_err)?;
    entry.set_secret(value).map_err(map_err)
}

// No production consumer yet — the wallet store reads and writes but
// never deletes. Tests need this to simulate the "user wiped their
// keyring" scenario, so it stays in the public API.
#[allow(dead_code)]
/// Remove a secret. Idempotent: deleting a non-existent entry is `Ok(())`,
/// since the post-condition ("no entry under this name") already holds.
pub fn delete_secret(name: &str) -> Result<(), KeyringError> {
    let entry = keyring::Entry::new(SERVICE, name).map_err(map_err)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(map_err(e)),
    }
}

fn map_err(e: keyring::Error) -> KeyringError {
    match e {
        // `read_secret` / `delete_secret` consume NoEntry before reaching here.
        // If we ever route NoEntry through this mapper we'd silently turn it
        // into a Backend error — louder failure modes are better than silent
        // misclassification.
        keyring::Error::NoEntry => {
            KeyringError::Backend("internal: NoEntry routed through map_err".into())
        }
        keyring::Error::PlatformFailure(src) => KeyringError::Unavailable(format!("{src}")),
        keyring::Error::NoStorageAccess(src) => KeyringError::Unavailable(format!("{src}")),
        other => KeyringError::Backend(format!("{other}")),
    }
}

/// In-process keyring backend for tests, keyed on (service, user) with a
/// shared map. Lives here (not under `mod tests`) so other modules in the
/// crate — notably `wallet::store` — can install it from their own tests.
///
/// Why not the stock `keyring::mock`: the stock backend creates a fresh,
/// isolated credential for every `Entry::new` call, so write-via-one-handle
/// / read-via-another (which is exactly what this wrapper does) never
/// shares state. Real OS backends key on service+user, so this fake
/// matches their semantics rather than the mock's.
#[cfg(test)]
pub(crate) mod test_support {
    use keyring::credential::{
        Credential, CredentialApi, CredentialBuilderApi, CredentialPersistence,
    };
    use std::any::Any;
    use std::collections::HashMap;
    use std::fmt::{self, Formatter};
    use std::sync::{Mutex, OnceLock};

    type StoreKey = (String, String);

    fn store() -> &'static Mutex<HashMap<StoreKey, Vec<u8>>> {
        static STORE: OnceLock<Mutex<HashMap<StoreKey, Vec<u8>>>> = OnceLock::new();
        STORE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    struct InMemoryCredential {
        service: String,
        user: String,
    }

    impl InMemoryCredential {
        fn key(&self) -> StoreKey {
            (self.service.clone(), self.user.clone())
        }
    }

    impl CredentialApi for InMemoryCredential {
        fn set_password(&self, password: &str) -> keyring::Result<()> {
            self.set_secret(password.as_bytes())
        }

        fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
            store().lock().unwrap().insert(self.key(), secret.to_vec());
            Ok(())
        }

        fn get_password(&self) -> keyring::Result<String> {
            let bytes = self.get_secret()?;
            String::from_utf8(bytes).map_err(|e| keyring::Error::BadEncoding(e.into_bytes()))
        }

        fn get_secret(&self) -> keyring::Result<Vec<u8>> {
            store()
                .lock()
                .unwrap()
                .get(&self.key())
                .cloned()
                .ok_or(keyring::Error::NoEntry)
        }

        fn get_attributes(&self) -> keyring::Result<HashMap<String, String>> {
            Ok(HashMap::new())
        }

        fn update_attributes(&self, _: &HashMap<&str, &str>) -> keyring::Result<()> {
            Ok(())
        }

        fn delete_credential(&self) -> keyring::Result<()> {
            match store().lock().unwrap().remove(&self.key()) {
                Some(_) => Ok(()),
                None => Err(keyring::Error::NoEntry),
            }
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn debug_fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "InMemoryCredential({}/{})", self.service, self.user)
        }
    }

    struct InMemoryBuilder;

    impl CredentialBuilderApi for InMemoryBuilder {
        fn build(
            &self,
            _target: Option<&str>,
            service: &str,
            user: &str,
        ) -> keyring::Result<Box<Credential>> {
            Ok(Box::new(InMemoryCredential {
                service: service.to_string(),
                user: user.to_string(),
            }))
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn persistence(&self) -> CredentialPersistence {
            CredentialPersistence::ProcessOnly
        }
    }

    /// Install the in-memory backend as the process-global keyring. Safe to
    /// call from many tests in parallel — the `OnceLock` guard ensures the
    /// underlying `set_default_credential_builder` runs exactly once and
    /// late callers block until install completes.
    pub fn install() {
        static INIT: OnceLock<()> = OnceLock::new();
        INIT.get_or_init(|| {
            keyring::set_default_credential_builder(Box::new(InMemoryBuilder));
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each test uses a unique entry name so parallel runs don't trample
    // each other through the process-global store.

    #[test]
    fn read_missing_returns_none() {
        test_support::install();
        let got = read_secret("test_read_missing").unwrap();
        assert!(
            got.is_none(),
            "expected None for unwritten entry, got {got:?}"
        );
    }

    #[test]
    fn round_trip_bytes() {
        test_support::install();
        let name = "test_round_trip";
        let value = b"hello, keyring";
        write_secret(name, value).unwrap();
        let got = read_secret(name).unwrap();
        assert_eq!(got.as_deref(), Some(&value[..]));
    }

    #[test]
    fn round_trip_bytes_with_nul_and_high_bytes() {
        // Ensures we're going through the bytes API, not a UTF-8 string
        // round-trip that would mangle these.
        test_support::install();
        let name = "test_round_trip_binary";
        let value: &[u8] = &[0x00, 0x01, 0xff, 0x00, 0x80, 0x7f];
        write_secret(name, value).unwrap();
        let got = read_secret(name).unwrap();
        assert_eq!(got.as_deref(), Some(value));
    }

    #[test]
    fn write_overwrites_previous_value() {
        test_support::install();
        let name = "test_overwrite";
        write_secret(name, b"first").unwrap();
        write_secret(name, b"second").unwrap();
        let got = read_secret(name).unwrap();
        assert_eq!(got.as_deref(), Some(&b"second"[..]));
    }

    #[test]
    fn delete_removes_entry() {
        test_support::install();
        let name = "test_delete";
        write_secret(name, b"to be deleted").unwrap();
        delete_secret(name).unwrap();
        let got = read_secret(name).unwrap();
        assert!(got.is_none(), "expected None after delete, got {got:?}");
    }

    #[test]
    fn delete_missing_is_ok() {
        // `delete_secret` is idempotent — the post-condition already holds.
        // Callers that retry / clean up shouldn't have to special-case the
        // first-run path.
        test_support::install();
        delete_secret("test_delete_missing").unwrap();
    }

    // ── map_err classification ───────────────────────────────────────────
    //
    // The Unavailable/Backend split drives wallet policy (refuse to open vs.
    // surface as a bug), so these mappings need direct coverage rather than
    // riding on whatever the in-memory backend happens to return.

    #[test]
    fn map_err_platform_failure_is_unavailable() {
        let src: Box<dyn std::error::Error + Send + Sync> = "dbus session bus down".into();
        let mapped = map_err(keyring::Error::PlatformFailure(src));
        assert!(
            matches!(mapped, KeyringError::Unavailable(_)),
            "expected Unavailable, got {mapped:?}",
        );
    }

    #[test]
    fn map_err_no_storage_access_is_unavailable() {
        let src: Box<dyn std::error::Error + Send + Sync> = "keychain locked".into();
        let mapped = map_err(keyring::Error::NoStorageAccess(src));
        assert!(
            matches!(mapped, KeyringError::Unavailable(_)),
            "expected Unavailable, got {mapped:?}",
        );
    }

    #[test]
    fn map_err_no_entry_routes_to_backend_defensively() {
        // `read_secret` / `delete_secret` consume `NoEntry` before it reaches
        // `map_err`. If a future refactor ever lets it leak through, the
        // defensive arm must classify as Backend — silently turning it into
        // Unavailable would make the wallet refuse to open on a normal
        // first-run state.
        let mapped = map_err(keyring::Error::NoEntry);
        match mapped {
            KeyringError::Backend(msg) => {
                assert!(
                    msg.contains("NoEntry"),
                    "expected NoEntry breadcrumb, got: {msg}"
                );
            }
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn map_err_other_variants_are_backend() {
        // BadEncoding is the canonical "weird value, not a broken
        // environment" case — must not be classified as Unavailable.
        let mapped = map_err(keyring::Error::BadEncoding(vec![0xff, 0xfe]));
        assert!(
            matches!(mapped, KeyringError::Backend(_)),
            "expected Backend, got {mapped:?}",
        );
    }

    #[test]
    fn display_includes_category_and_detail() {
        let unav = KeyringError::Unavailable("dbus down".into());
        let s = format!("{unav}");
        assert!(s.contains("unavailable"), "got: {s}");
        assert!(s.contains("dbus down"), "got: {s}");

        let backend = KeyringError::Backend("bad encoding".into());
        let s = format!("{backend}");
        assert!(s.contains("backend"), "got: {s}");
        assert!(s.contains("bad encoding"), "got: {s}");
    }

    #[test]
    fn error_trait_is_implemented() {
        // KeyringError must impl std::error::Error so callers can chain it
        // through anyhow / Box<dyn Error>. Compile-time guarantee + a quick
        // dyn round-trip.
        fn is_error<E: std::error::Error>() {}
        is_error::<KeyringError>();

        let boxed: Box<dyn std::error::Error> = Box::new(KeyringError::Backend("x".into()));
        assert!(format!("{boxed}").contains("backend"));
    }

    #[test]
    fn empty_value_round_trip() {
        // Edge case: storing an empty byte slice must round-trip. Some
        // backends silently reject empty values; the in-memory store here
        // accepts them. Pin behavior for callers who store length-prefixed
        // payloads that could be legitimately empty.
        test_support::install();
        let name = "test_empty_value";
        write_secret(name, &[]).unwrap();
        let got = read_secret(name).unwrap();
        assert_eq!(got.as_deref(), Some(&[][..]));
    }
}
