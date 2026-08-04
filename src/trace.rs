//! GUI state-change tracing.
//!
//! Kao is an Elm-architecture app: every state mutation happens inside an
//! `update()` in response to a message. Logging (a) each message as it
//! enters an update function and (b) each coarse state transition (screen,
//! nav pane, modal, flow stage, busy flag) therefore makes the entire GUI
//! state machine observable from the log stream alone — enough for a human
//! or an AI agent to debug the GUI without a debugger attached.
//!
//! Everything logs under the single target `kao::gui` so it can be enabled
//! independently of the networking / wallet plumbing:
//!   * `RUST_LOG=kao::gui=debug` — coarse transitions and outcomes only
//!     (screen changes, pane switches, modal open/close, busy flips);
//!   * `RUST_LOG=kao::gui=trace` — additionally every message entering
//!     every update function, Debug-formatted and clamped.
//!
//! Conventions (applied uniformly across the codebase):
//!   * `crate::trace_msg!("scope", &message)` is the first statement of
//!     every `update()`; `scope` is a short stable name for the screen or
//!     pane ("app", "unlock", "dashboard", "send", …). Variants that are
//!     pure redraw kicks (per-frame animation ticks) may be skipped with a
//!     comment to keep the trace stream readable.
//!   * Coarse transitions are logged via [`state`] (or [`state_caused`],
//!     which also names the message responsible) by diffing a name
//!     before/after dispatch in a thin `update` wrapper around the
//!     original body (renamed `update_inner`) — this catches every
//!     assignment site without instrumenting each one.
//!   * Child→parent [`Outcome` signals](crate::ui) are logged via
//!     [`outcome`] by variant name only — outcome payloads can carry key
//!     material and must never be Debug-formatted into a log.
//!
//! Secrecy: a message payload that carries secret text the user typed
//! (password, seed phrase, private key, API key) must be wrapped in
//! [`SecretInput`] so its `Debug` output is redacted at the type level.
//! Logging is then safe by construction — here, in panic backtraces, and
//! in any future `{:?}`. This mirrors `wallet::SecretKeyBytes`.

use std::fmt;

use zeroize::Zeroizing;

/// Upper bound on a Debug-formatted message in the trace stream. Long
/// payloads (portfolio result vectors, Safe descriptor batches) get
/// clamped — the variant name and leading fields are what matter.
pub const MAX_MSG_CHARS: usize = 256;

/// Trace one message entering an update function. Expands to a guarded
/// `tracing::trace!` so the Debug formatting only runs when `kao::gui` is
/// enabled at TRACE (i.e. never costs a per-keystroke allocation in
/// normal operation).
#[macro_export]
macro_rules! trace_msg {
    ($scope:expr, $msg:expr) => {
        if ::tracing::enabled!(target: "kao::gui", ::tracing::Level::TRACE) {
            ::tracing::trace!(
                target: "kao::gui",
                scope = $scope,
                msg = %$crate::trace::clamp_debug($msg),
                "msg"
            );
        }
    };
}

/// Debug-format `value` and clamp it to [`MAX_MSG_CHARS`] characters
/// (appending `…` when truncated), so one oversized payload can't flood
/// the trace stream.
pub fn clamp_debug(value: &impl fmt::Debug) -> String {
    let s = format!("{value:?}");
    if s.chars().count() <= MAX_MSG_CHARS {
        return s;
    }
    let mut out: String = s.chars().take(MAX_MSG_CHARS).collect();
    out.push('…');
    out
}

/// Log a coarse state transition (`what` went `from` → `to`) at DEBUG.
/// Callers compare before/after themselves and only call this when the
/// value actually changed.
pub fn state(scope: &str, what: &str, from: impl fmt::Display, to: impl fmt::Display) {
    tracing::debug!(target: "kao::gui", scope, what, %from, %to, "state");
}

/// Log a coarse state transition together with the message that caused it.
///
/// Same as [`state`], plus a `cause` field naming the message variant. Use it
/// where the transition alone doesn't identify the path taken — a pane whose
/// queue can be cleared by an edit, a network switch, an identity switch, a
/// template load and a successful broadcast logs `batch: 3 -> 0` five ways,
/// and which one it was is the whole question.
///
/// `cause` must be a variant *name*, never a Debug format: message payloads
/// carry pasted ABIs, bundle JSON and user input, and one of them will
/// eventually carry a secret.
pub fn state_caused(
    scope: &str,
    cause: &str,
    what: &str,
    from: impl fmt::Display,
    to: impl fmt::Display,
) {
    tracing::debug!(target: "kao::gui", scope, cause, what, %from, %to, "state");
}

/// Log a child→parent outcome signal at DEBUG, by variant name only —
/// outcome payloads can carry secrets and must not be Debug-formatted.
pub fn outcome(scope: &str, outcome: &str) {
    tracing::debug!(target: "kao::gui", scope, outcome, "outcome");
}

/// Secret text the user typed into an input widget (password, seed
/// phrase, private key, API key), carried inside a GUI message.
///
/// Wrapping at the message layer means the derived `Debug` of every
/// containing `Message` enum is safe to log: this type formats as
/// `SecretInput(<redacted>)` — no contents, no length. The inner buffer is
/// zeroized on drop, so the per-keystroke copy iced hands us doesn't
/// linger on the heap after the handler moves it into screen state.
#[derive(Clone)]
pub struct SecretInput(Zeroizing<String>);

impl SecretInput {
    /// Borrow the secret. Keep the borrow short-lived and never copy it
    /// into an un-zeroized owner.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Take ownership of the zeroizing buffer (for handlers that store
    /// the input as screen state).
    pub fn take(self) -> Zeroizing<String> {
        self.0
    }
}

impl From<String> for SecretInput {
    fn from(s: String) -> Self {
        Self(Zeroizing::new(s))
    }
}

impl From<&str> for SecretInput {
    fn from(s: &str) -> Self {
        Self(Zeroizing::new(s.to_string()))
    }
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretInput(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_input_debug_is_redacted() {
        let s = SecretInput::from("hunter2".to_string());
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("hunter2"));
        assert_eq!(dbg, "SecretInput(<redacted>)");
    }

    #[test]
    fn secret_input_round_trips() {
        let s = SecretInput::from("correct horse".to_string());
        assert_eq!(s.expose(), "correct horse");
        assert_eq!(s.take().as_str(), "correct horse");
    }

    #[test]
    fn clamp_debug_passes_short_values() {
        assert_eq!(clamp_debug(&42u32), "42");
    }

    #[test]
    fn clamp_debug_clamps_long_values() {
        let long = "x".repeat(1000);
        let out = clamp_debug(&long);
        // +2 for the quotes Debug adds, +1 for the ellipsis.
        assert_eq!(out.chars().count(), MAX_MSG_CHARS + 1);
        assert!(out.ends_with('…'));
    }
}
