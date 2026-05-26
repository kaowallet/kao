// Phase 6 scaffolding — UI consumer in `wallet_dashboard` lands as part
// of the modal-queue wiring.
#![allow(dead_code)]

//! WalletConnect Verify API client.
//!
//! Endpoint: `https://verify.walletconnect.com/v2/attestation/{attestation_id}`
//!
//! When a dApp publishes `wc_sessionPropose` / `wc_sessionRequest` through
//! the relay, the relay attaches an `attestation` field — a short opaque
//! token identifying the origin the dApp claimed to be from. The wallet
//! looks that token up via this client; the verify service returns whether
//! the origin matches the dApp's registered metadata.
//!
//! Three states, from most-trusted to least:
//!
//! - [`AttestationStatus::Verified`] — origin matches the dApp's registered
//!   metadata. UI shows a green chip.
//! - [`AttestationStatus::Unverified`] — no attestation present, or the
//!   verify service didn't claim verification either way. UI shows a yellow
//!   "we couldn't verify this dApp" banner with click-through allowed.
//! - [`AttestationStatus::Scam`] — origin mismatch or the dApp is on the
//!   verify-service blocklist. UI shows a red banner with **action buttons
//!   disabled** — no override. The user clicking past a red Scam warning is
//!   exactly the social-engineering path Verify exists to block.
//!
//! UI ordering
//! -----------
//! The fetch is **lazy**: the modal renders immediately in `Unverified
//! (loading)` state and updates when the fetch lands (~100-300ms typical,
//! 2s timeout). A network outage at `verify.walletconnect.com` must not
//! hang the wallet modal.
//!
//! Privacy
//! -------
//! Every fetch leaks `(client_ip, attestation_id)` to a WalletConnect
//! Foundation server, in addition to the relay seeing the topic/IP pair
//! already. Users can disable Verify entirely in Settings
//! (`settings::wc_verify_api_enabled`) — at the cost of losing the
//! Scam/Invalid hard-deny.

use std::time::Duration;

use serde::Deserialize;
use tracing::warn;

/// Default base URL — overridable in tests via [`VerifyClient::new_with_base`].
const DEFAULT_BASE_URL: &str = "https://verify.walletconnect.com";

/// HTTP path under the base URL.
const ATTESTATION_PATH: &str = "/v2/attestation/";

/// Timeout floor. Modal renders before the fetch lands and updates when it
/// returns; 2s caps the user-visible "could not verify" pending state.
pub const VERIFY_TIMEOUT: Duration = Duration::from_secs(2);

/// Three-state classification, ordered low-to-high trust *and* matching
/// the UI's traffic-light colouring (red < yellow < green). Phase 7 may
/// add a fourth `Loading` placeholder for the lazy-fetch UX, but the
/// engine itself only deals with the resolved triplet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationStatus {
    /// Red. Hard-deny in the UI — no click-through.
    Scam,
    /// Yellow. Click-through allowed with a warning banner.
    Unverified,
    /// Green. Trust chip displayed.
    Verified,
}

#[derive(Debug, Clone)]
pub struct AttestationResult {
    pub status: AttestationStatus,
    /// Origin string from the verify service (e.g. `https://app.uniswap.org`).
    /// `None` when the response didn't include one.
    pub origin: Option<String>,
    /// Human-readable explanation if the response carried one. The UI may
    /// surface this verbatim under the trust chip.
    pub validation_label: Option<String>,
}

impl AttestationResult {
    pub fn unverified(reason: &str) -> Self {
        Self {
            status: AttestationStatus::Unverified,
            origin: None,
            validation_label: Some(reason.to_string()),
        }
    }

    pub fn is_blocking(&self) -> bool {
        matches!(self.status, AttestationStatus::Scam)
    }
}

#[derive(Debug)]
pub enum VerifyError {
    /// Network transport failure (DNS, TLS, refused, …). UI degrades to
    /// `Unverified` and the user makes the call without the registry's
    /// input.
    Transport(String),
    /// Verify service returned a non-2xx HTTP status. Treated the same as
    /// `Transport` by UI consumers — caller may choose to log differently.
    Http { status: u16 },
    /// Fetch took longer than `VERIFY_TIMEOUT`.
    Timeout,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(s) => write!(f, "verify transport: {s}"),
            Self::Http { status } => write!(f, "verify HTTP {status}"),
            Self::Timeout => write!(f, "verify timed out after {VERIFY_TIMEOUT:?}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verify API client. Holds one shared `reqwest::Client` so concurrent
/// modals don't pay the TLS-handshake tax per fetch.
#[derive(Debug, Clone)]
pub struct VerifyClient {
    http: reqwest::Client,
    base_url: String,
}

impl VerifyClient {
    pub fn new() -> Self {
        Self::new_with_base(DEFAULT_BASE_URL.to_string())
    }

    /// Construct against a custom base URL — used by tests against a
    /// local echo server and by privacy-conscious users who proxy through
    /// their own deployment.
    pub fn new_with_base(base_url: String) -> Self {
        let http = reqwest::Client::builder()
            // We never need redirects to leave verify.walletconnect.com.
            .redirect(reqwest::redirect::Policy::none())
            // The Verify API is plain JSON-over-HTTPS; no need for keep-
            // alive pools beyond what reqwest defaults to.
            .build()
            .expect("reqwest client must build with default settings");
        Self { http, base_url }
    }

    /// Look up an attestation. Returns an [`AttestationResult`] on success;
    /// callers degrade transport errors to `Unverified` at the UI layer
    /// (we surface them as `Err` here so they can be logged distinctly).
    ///
    /// The caller is responsible for checking
    /// [`crate::settings::wc_verify_api_enabled`] before invoking — when
    /// the toggle is off, the App layer skips the call entirely and
    /// treats every dApp as `Unverified`. Keeping that branch out of
    /// here means `VerifyClient` is a pure HTTP wrapper with no
    /// dependency on global state, which keeps tests isolated under
    /// `cargo test`'s default parallel runner.
    pub async fn fetch(&self, attestation_id: &str) -> Result<AttestationResult, VerifyError> {
        let url = format!("{}{}{}", self.base_url, ATTESTATION_PATH, attestation_id);
        let fut = self.http.get(&url).send();
        let resp = match tokio::time::timeout(VERIFY_TIMEOUT, fut).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                // Strip URL from reqwest errors — `Display` on
                // `reqwest::Error` embeds the URL, which for some
                // upstream services would carry an API key. Verify
                // doesn't, but the habit is correct and consistent.
                let stripped = e.without_url().to_string();
                return Err(VerifyError::Transport(stripped));
            }
            Err(_) => return Err(VerifyError::Timeout),
        };

        let status = resp.status();
        if !status.is_success() {
            return Err(VerifyError::Http {
                status: status.as_u16(),
            });
        }

        let body = match resp.text().await {
            Ok(t) => t,
            Err(e) => {
                let stripped = e.without_url().to_string();
                return Err(VerifyError::Transport(stripped));
            }
        };
        Ok(parse_response(&body))
    }
}

impl Default for VerifyClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Shape of the JSON body the verify service returns. Conservative: every
/// field is optional so a future API version that drops or renames things
/// degrades to `Unverified` instead of crashing the parser.
#[derive(Debug, Deserialize)]
struct VerifyResponse {
    #[serde(default)]
    origin: Option<String>,
    #[serde(default, rename = "isScam")]
    is_scam: Option<bool>,
    #[serde(default, rename = "isVerified")]
    is_verified: Option<bool>,
    /// Some API versions emit `validation: "VALID" | "INVALID" | "UNKNOWN"`.
    #[serde(default)]
    validation: Option<String>,
}

/// Pure parser: JSON body → [`AttestationResult`]. Exposed for testing —
/// integration tests against a real verify server would be flaky and
/// privacy-sensitive, so the API surface is split with `fetch` doing only
/// the HTTP and this doing the classification.
///
/// Precedence (high → low):
/// 1. `isScam: true` → Scam (always wins; explicit flag).
/// 2. `validation: "INVALID"` → Scam.
/// 3. `isVerified: true` or `validation: "VALID"` → Verified.
/// 4. Anything else (including malformed JSON) → Unverified.
fn parse_response(body: &str) -> AttestationResult {
    let parsed: VerifyResponse = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "verify response not JSON, treating as unverified");
            return AttestationResult::unverified("malformed response");
        }
    };
    let validation = parsed.validation.as_deref().map(|s| s.to_ascii_uppercase());
    let status = match (parsed.is_scam, validation.as_deref()) {
        (Some(true), _) | (_, Some("INVALID")) => AttestationStatus::Scam,
        _ => match (parsed.is_verified, validation.as_deref()) {
            (Some(true), _) | (_, Some("VALID")) => AttestationStatus::Verified,
            _ => AttestationStatus::Unverified,
        },
    };
    AttestationResult {
        status,
        origin: parsed.origin,
        validation_label: validation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_explicit_scam_wins_over_verified_flag() {
        // `isScam: true` MUST take precedence — a malicious response that
        // sets both flags shouldn't slip past as Verified.
        let body = r#"{"origin":"https://attacker.example","isScam":true,"isVerified":true}"#;
        let r = parse_response(body);
        assert_eq!(r.status, AttestationStatus::Scam);
        assert!(r.is_blocking());
        assert_eq!(r.origin.as_deref(), Some("https://attacker.example"));
    }

    #[test]
    fn parse_validation_invalid_is_scam() {
        let body = r#"{"validation":"INVALID","origin":"https://x.example"}"#;
        let r = parse_response(body);
        assert_eq!(r.status, AttestationStatus::Scam);
        assert_eq!(r.validation_label.as_deref(), Some("INVALID"));
    }

    #[test]
    fn parse_validation_invalid_lowercase_still_scam() {
        // Case-insensitive: `validation: "invalid"` is still INVALID.
        let body = r#"{"validation":"invalid"}"#;
        let r = parse_response(body);
        assert_eq!(r.status, AttestationStatus::Scam);
    }

    #[test]
    fn parse_verified_via_flag() {
        let body = r#"{"origin":"https://app.uniswap.org","isVerified":true}"#;
        let r = parse_response(body);
        assert_eq!(r.status, AttestationStatus::Verified);
        assert!(!r.is_blocking());
        assert_eq!(r.origin.as_deref(), Some("https://app.uniswap.org"));
    }

    #[test]
    fn parse_verified_via_validation_field() {
        let body = r#"{"validation":"VALID","origin":"https://x.example"}"#;
        let r = parse_response(body);
        assert_eq!(r.status, AttestationStatus::Verified);
    }

    #[test]
    fn parse_unknown_is_unverified() {
        let body = r#"{"validation":"UNKNOWN"}"#;
        let r = parse_response(body);
        assert_eq!(r.status, AttestationStatus::Unverified);
        assert!(!r.is_blocking());
    }

    #[test]
    fn parse_empty_object_is_unverified() {
        // Forward-compatibility: a future API revision that returns
        // fields we don't recognise mustn't crash the modal flow.
        let body = "{}";
        let r = parse_response(body);
        assert_eq!(r.status, AttestationStatus::Unverified);
    }

    #[test]
    fn parse_malformed_json_is_unverified() {
        let body = "not json at all";
        let r = parse_response(body);
        assert_eq!(r.status, AttestationStatus::Unverified);
        // Validation label carries the parser's hint for the UI.
        assert_eq!(r.validation_label.as_deref(), Some("malformed response"));
    }

    #[test]
    fn parse_handles_unknown_extra_fields() {
        // The verify service has shipped multiple revisions adding
        // fields; our parser ignores them all. Specifically check that
        // a known-good response with a `verifyContext` nested object
        // still classifies correctly.
        let body = r#"{
            "origin": "https://app.uniswap.org",
            "isVerified": true,
            "verifyContext": {
                "verified": {"validation": "VALID", "origin": "https://app.uniswap.org"}
            },
            "newFutureField": ["arbitrary", "values"]
        }"#;
        let r = parse_response(body);
        assert_eq!(r.status, AttestationStatus::Verified);
    }

    #[test]
    fn is_blocking_only_true_for_scam() {
        assert!(
            AttestationResult {
                status: AttestationStatus::Scam,
                origin: None,
                validation_label: None,
            }
            .is_blocking()
        );
        assert!(
            !AttestationResult {
                status: AttestationStatus::Unverified,
                origin: None,
                validation_label: None,
            }
            .is_blocking()
        );
        assert!(
            !AttestationResult {
                status: AttestationStatus::Verified,
                origin: None,
                validation_label: None,
            }
            .is_blocking()
        );
    }

    #[test]
    fn timeout_constant_is_documented_two_seconds() {
        // Lock in the 2-second cap so a future tweak to a 30-second
        // timeout that would hang the modal trips this test on review.
        assert_eq!(VERIFY_TIMEOUT, Duration::from_secs(2));
    }

    /// Smoke test against a localhost address that's guaranteed not to
    /// respond — verifies the timeout path fires rather than hanging
    /// the test runner. Uses 240.0.0.0/4 (TEST-NET reserved, no real
    /// host responds) so the TCP connection attempt either fails
    /// immediately or times out fast; either way the wrapped
    /// `tokio::time::timeout` is what bounds the wait.
    #[tokio::test(flavor = "current_thread")]
    async fn fetch_timeout_or_transport_returns_error_quickly() {
        let client = VerifyClient::new_with_base("http://240.0.0.1:1".to_string());
        let started = std::time::Instant::now();
        let result = client.fetch("abc").await;
        let elapsed = started.elapsed();
        // Whichever way it failed (transport refusal or timeout), we
        // must not have waited longer than ~3x the configured timeout.
        // Generous bound — the test runner just needs to not hang.
        assert!(
            elapsed < Duration::from_secs(6),
            "verify fetch took too long ({elapsed:?}) — timeout path broken?"
        );
        assert!(result.is_err());
    }
}
