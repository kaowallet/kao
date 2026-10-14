//! The WalletConnect pane (Apps) and the launcher's `wc:` row. Purely UI: it mirrors a `WcSnapshot`
//! pushed by the coordinator and emits `Outcome`s; it never touches the runtime.
//!
//! - **Launcher row** — a `wc:` field + Connect, and one status line, at the top of the Apps
//!   launcher. Connect *moves* the pasted link (it carries the pairing symKey) into
//!   [`Outcome::Pair`] and clears the field; the coordinator does the real parse.
//! - **Home** — the relay line, the same `wc:` row, at most one connection request (the approval
//!   card for the *active* identity), the requests waiting for the user, the connected dapps, the
//!   recent activity, and a two-step "Turn off WalletConnect".
//! - **Settings** — the project id (typed fresh; the stored one is never shown back) and the relay
//!   URL, validated inline with the settings module's own validators.
//!
//! Dapp-controlled strings (all sanitized at ingress, `DappLabel` & co.) are only drawn inside
//! bordered mono boxes or labelled as the dapp's claim. Nothing here ever answers a dapp: Esc and
//! "← Apps" step back, they never reject (only the explicit Reject buttons do).
//!
//! Secrecy: the `wc:` link and the project id ride in [`SecretInput`] (redacted `Debug`), and the
//! pane's keyboard subscription is Esc-only, so typed keystrokes never become (traced) messages.

use std::time::Duration;

use iced::border::Radius;
use iced::keyboard;
use iced::widget::{Space, button, column, container, row, text, text_input};
use iced::{Alignment, Background, Border, Color, Element, Length, Padding, Subscription};
use zeroize::Zeroizing;

use crate::trace::SecretInput;
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::{
    BadgeKind, bold, caution_color, colored_address, ghost_button, hover_tint, mono, mono_bold,
    mono_box, primary_button, privacy_badge, screen_subtitle, screen_title, secondary_button,
    small_danger_button, small_secondary_button, span_label, text_input_style,
};
use crate::walletconnect::{
    AckState, ChainLine, MethodLine, MethodSupport, NoticeView, PAIRING_HINT_AFTER_SECS,
    PairingState, ProjectIdSource, ProposalView, ProxyView, QueueState, RESTART_FOR_PROXY,
    RelayStatus, RequestView, RouteKind, SessionView, Topic, WcConfigView, WcIdentity, WcKey,
    WcSnapshot,
};

/// The pane's mascot, also the launcher card's chip.
pub(super) const KAO_MASCOT: &str = "(⌁ω⌁)";

const URI_PLACEHOLDER: &str = "Paste a WalletConnect link (wc:…)";
const IDLE_HINT_LAUNCHER: &str =
    "Connect Kao to a dapp: copy its WalletConnect link and paste it here.";
const IDLE_HINT_PANE: &str =
    "Copy the WalletConnect link from a dapp's connect dialog and paste it here.";

#[derive(Debug, Clone)]
pub enum Message {
    UriChanged(SecretInput),
    Connect,
    Approve {
        proposal_id: u64,
    },
    RejectProposal {
        proposal_id: u64,
    },
    ReviewNow {
        key: WcKey,
    },
    /// [Review anyway] on a request Kao's unmined execution of an earlier one holds back.
    ReviewPastHold {
        key: WcKey,
    },
    RejectRequest {
        key: WcKey,
    },
    /// [Switch to ⟨identity⟩] on the waiting request `key`.
    SwitchTo {
        identity: WcIdentity,
        key: WcKey,
    },
    AskDisconnect {
        topic: Topic,
    },
    ConfirmDisconnect {
        topic: Topic,
    },
    CancelDisconnect,
    RejectAllFrom {
        topic: Topic,
    },
    Resume {
        topic: Topic,
    },
    AskStop,
    ConfirmStop,
    CancelStop,
    ToggleSettings,
    ProjectIdChanged(SecretInput),
    /// A relay draft can carry a `?projectId=…` pasted along with it: redacted like the id.
    RelayUrlChanged(SecretInput),
    SaveSettings,
    ResetSettings,
    Back,
    Escape,
    Tick,
    AddressCopied,
}

/// One settings field's requested change: leave it, remove the override, or store a new value.
#[derive(Debug, Clone)]
pub enum SettingEdit<T> {
    Keep,
    Clear,
    Set(T),
}

#[derive(Debug, Clone)]
pub enum Outcome {
    Pair {
        uri: SecretInput,
    },
    /// Carries what the card displayed; the coordinator refuses if either moved since, so an
    /// approval binds exactly what the user saw.
    Approve {
        proposal_id: u64,
        identity: WcIdentity,
        chains: Vec<u64>,
    },
    RejectProposal {
        proposal_id: u64,
    },
    ReviewNow {
        key: WcKey,
    },
    /// Open `key` now, though it waits for Kao's unmined execution of an earlier one.
    ReviewPastHold {
        key: WcKey,
    },
    RejectRequest {
        key: WcKey,
    },
    /// Switch to `identity`, then open `key` — the request the user clicked it on.
    SwitchTo {
        identity: WcIdentity,
        key: WcKey,
    },
    Disconnect {
        topic: Topic,
    },
    RejectAllFrom {
        topic: Topic,
    },
    Resume {
        topic: Topic,
    },
    Stop,
    SaveSettings {
        project_id: SettingEdit<SecretInput>,
        relay_url: SettingEdit<String>,
    },
    Close,
}

impl Outcome {
    /// Variant name for the GUI state trace — never the payload.
    pub fn name(&self) -> &'static str {
        match self {
            Outcome::Pair { .. } => "Pair",
            Outcome::Approve { .. } => "Approve",
            Outcome::RejectProposal { .. } => "RejectProposal",
            Outcome::ReviewNow { .. } => "ReviewNow",
            Outcome::ReviewPastHold { .. } => "ReviewPastHold",
            Outcome::RejectRequest { .. } => "RejectRequest",
            Outcome::SwitchTo { .. } => "SwitchTo",
            Outcome::Disconnect { .. } => "Disconnect",
            Outcome::RejectAllFrom { .. } => "RejectAllFrom",
            Outcome::Resume { .. } => "Resume",
            Outcome::Stop => "Stop",
            Outcome::SaveSettings { .. } => "SaveSettings",
            Outcome::Close => "Close",
        }
    }
}

/// Pane-local pairing progress the snapshot can't carry: the runtime start (no runtime yet, so no
/// book) and a failure the coordinator caught before the runtime saw the link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingUi {
    Idle,
    Starting,
    Failed(String),
}

impl PairingUi {
    fn name(&self) -> &'static str {
        match self {
            PairingUi::Idle => "idle",
            PairingUi::Starting => "starting",
            PairingUi::Failed(_) => "failed",
        }
    }
}

/// The identity a new connection would expose — always the active one: connecting another means
/// switching to it first, so nothing is exposed that the user isn't looking at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveIdentityView {
    pub identity: WcIdentity,
    pub label: String,
    pub badge: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaneView {
    Home,
    Settings,
}

impl PaneView {
    fn name(self) -> &'static str {
        match self {
            PaneView::Home => "Home",
            PaneView::Settings => "Settings",
        }
    }
}

/// The relay settings drafts. The project id is typed fresh — the stored one is never displayed
/// back — and the relay URL starts from the current override.
#[derive(Default)]
struct SettingsForm {
    project: Zeroizing<String>,
    relay: Zeroizing<String>,
    /// "Use Kao's defaults" was pressed: an empty project field now means *remove* the override.
    reset: bool,
}

/// What Save would do to one field, before the payload is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EditKind {
    Keep,
    Clear,
    Set,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tone {
    Info,
    Warn,
    Error,
}

/// The pane. Holds only UI drafts plus the last mirror from the coordinator; losing it on a
/// dashboard rebuild loses nothing that matters (the runtime owns every session and request).
pub struct WcApp {
    /// The pasted `wc:` link — it carries the pairing symKey, so it lives in a zeroizing buffer and
    /// is moved (never copied) into [`Outcome::Pair`].
    uri: Zeroizing<String>,
    pairing: PairingUi,
    snapshot: Option<WcSnapshot>,
    /// `now_secs()` when `snapshot` arrived; countdowns tick from it between mirrors.
    synced_at: u64,
    active: Option<ActiveIdentityView>,
    config: Option<WcConfigView>,
    view: PaneView,
    form: SettingsForm,
    /// A Connect that needs a project id first (`NeedsProjectId`), parked until Save.
    pending_pair: Option<SecretInput>,
    pending_why: Option<&'static str>,
    confirm_disconnect: Option<Topic>,
    confirm_stop: bool,
    /// A settings setter's refusal, shown inline; nothing was stored.
    settings_error: Option<String>,
    /// Why the relay is off, when the runtime retired itself (idle, Turn off) — shown on the relay
    /// card until a runtime is back. Kao's own copy.
    off_reason: Option<String>,
}

impl std::fmt::Debug for WcApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WcApp")
    }
}

impl Default for WcApp {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::ui::kao_widgets::CopyKick for Message {
    fn copy_kick() -> Option<Self> {
        Some(Message::AddressCopied)
    }
}

/// Coarse pane state captured before dispatch and diffed after, so every transition is logged
/// whichever arm (or coordinator callback) made it. Presence only — never the link or the id.
#[derive(PartialEq, Eq)]
struct TraceSnapshot {
    view: &'static str,
    pairing: &'static str,
    pending_pair: bool,
    confirm_disconnect: bool,
    confirm_stop: bool,
    settings_error: bool,
    connect_ready: bool,
    off_reason: bool,
}

/// Esc, and nothing else, becomes a message: keystrokes typed into the link or project-id field
/// (key releases reach `keyboard::listen` even while a field is focused) never enter `update`, so
/// they can never reach the trace. A zero-sized fn item, as `Subscription::filter_map` requires.
fn esc_only(e: keyboard::Event) -> Option<Message> {
    match e {
        keyboard::Event::KeyPressed {
            key: keyboard::Key::Named(keyboard::key::Named::Escape),
            ..
        } => Some(Message::Escape),
        _ => None,
    }
}

/// A cheap shape check gating Connect — the coordinator parses for real. `wc:` covers the
/// `wc://…` deep-link forms; a base64-wrapped link (the crate accepts those too) starts with
/// `d2M6`, the base64 of `wc:`.
fn looks_like_wc_uri(s: &str) -> bool {
    let s = s.trim();
    s.starts_with("wc:")
        || (s.starts_with("d2M6")
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')))
}

/// What a dapp can ask for, in the user's words. `None` for anything not served.
fn method_phrase(method: &str) -> Option<&'static str> {
    Some(match method {
        "eth_sendTransaction" => "send transactions",
        "personal_sign" => "sign messages",
        "eth_signTypedData_v4" | "eth_signTypedData" => "sign typed data",
        "wallet_switchEthereumChain" => "switch networks",
        "eth_accounts" | "eth_requestAccounts" | "eth_chainId" => "read your address and network",
        _ => return None,
    })
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn tone_color(t: KaoTheme, tone: Tone) -> Color {
    match tone {
        Tone::Info => t.sub,
        Tone::Warn => caution_color(),
        Tone::Error => t.down,
    }
}

impl WcApp {
    /// Every `AppsPane` builds one, so it must not panic.
    pub fn new() -> Self {
        Self {
            uri: Zeroizing::default(),
            pairing: PairingUi::Idle,
            snapshot: None,
            synced_at: 0,
            active: None,
            config: None,
            view: PaneView::Home,
            form: SettingsForm::default(),
            pending_pair: None,
            pending_why: None,
            confirm_disconnect: None,
            confirm_stop: false,
            settings_error: None,
            off_reason: None,
        }
    }

    fn trace_snapshot(&self) -> TraceSnapshot {
        TraceSnapshot {
            view: self.view.name(),
            pairing: self.pairing.name(),
            pending_pair: self.pending_pair.is_some(),
            confirm_disconnect: self.confirm_disconnect.is_some(),
            confirm_stop: self.confirm_stop,
            settings_error: self.settings_error.is_some(),
            connect_ready: self.connect_enabled(),
            off_reason: self.off_reason.is_some(),
        }
    }

    /// Log every coarse change against `before`. Shared by `update` and the coordinator-called
    /// entry points (`sync`, `set_*`, `open_settings_with_pending`, `take_pending_pair`), which
    /// mutate the pane outside `update`.
    fn trace_delta(&self, before: &TraceSnapshot) {
        let after = self.trace_snapshot();
        if *before == after {
            return;
        }
        if before.view != after.view {
            crate::trace::state("wc", "pane_view", before.view, after.view);
        }
        if before.pairing != after.pairing {
            crate::trace::state("wc", "pairing_ui", before.pairing, after.pairing);
        }
        let flags = [
            ("pending_pair", before.pending_pair, after.pending_pair),
            (
                "confirm_disconnect",
                before.confirm_disconnect,
                after.confirm_disconnect,
            ),
            ("confirm_stop", before.confirm_stop, after.confirm_stop),
            (
                "settings_error",
                before.settings_error,
                after.settings_error,
            ),
            ("connect_ready", before.connect_ready, after.connect_ready),
            ("off_reason", before.off_reason, after.off_reason),
        ];
        for (what, from, to) in flags {
            if from != to {
                crate::trace::state("wc", what, from, to);
            }
        }
    }

    /// `trace_msg!("wc", ..)` wrapper (Tick skipped) + update_inner.
    pub fn update(&mut self, m: Message) -> Option<Outcome> {
        // `Tick` only repaints the countdowns once a second — tracing it would drown the stream.
        if !matches!(m, Message::Tick) {
            crate::trace_msg!("wc", &m);
        }
        let before = self.trace_snapshot();
        let out = self.update_inner(m);
        self.trace_delta(&before);
        if let Some(o) = &out {
            crate::trace::outcome("wc", o.name());
        }
        out
    }

    fn update_inner(&mut self, m: Message) -> Option<Outcome> {
        match m {
            Message::UriChanged(s) => {
                // The old buffer drops (and zeroizes) here.
                self.uri = s.take();
                // Editing the link is the retry — the last failure no longer describes it.
                if matches!(self.pairing, PairingUi::Failed(_)) {
                    self.pairing = PairingUi::Idle;
                }
                None
            }
            Message::Connect => {
                if !self.connect_enabled() {
                    return None;
                }
                // Move the buffer out — no copy of the symKey stays behind in the field.
                let uri = std::mem::take(&mut *self.uri);
                self.pairing = PairingUi::Idle;
                Some(Outcome::Pair {
                    uri: SecretInput::from(uri),
                })
            }
            Message::Approve { proposal_id } => {
                let p = self.card()?;
                if p.id != proposal_id
                    || p.busy
                    || self.secs_left(p.secs_left) == 0
                    || !self.relay_connected()
                {
                    return None;
                }
                // Exactly what the card shows as the connection: its identity and the granted
                // chains (the networks list renders from the same grant). The coordinator refuses
                // if either moved since.
                let plan = p.plan.as_ref()?;
                let grant = plan.verdict.as_ref().ok()?;
                Some(Outcome::Approve {
                    proposal_id,
                    identity: plan.identity,
                    chains: grant.chains.clone(),
                })
            }
            Message::RejectProposal { proposal_id } => {
                let p = self.card()?;
                (p.id == proposal_id && !p.busy).then_some(Outcome::RejectProposal { proposal_id })
            }
            Message::ReviewNow { key } => {
                let r = self.request(&key)?;
                (r.state == QueueState::Waiting
                    && !r.undelivered
                    && !r.held
                    && self.is_active(&r.identity))
                .then_some(Outcome::ReviewNow { key })
            }
            Message::ReviewPastHold { key } => {
                let r = self.request(&key)?;
                (r.state == QueueState::Waiting
                    && !r.undelivered
                    && r.held
                    && self.is_active(&r.identity))
                .then_some(Outcome::ReviewPastHold { key })
            }
            Message::RejectRequest { key } => {
                let r = self.request(&key)?;
                // Never once signing. A request under review is normally answered from its
                // overlay (which covers this pane); the coordinator refuses while one shows it,
                // so the row's Reject only lands for a review that lost its overlay.
                (matches!(r.state, QueueState::Waiting | QueueState::InReview { .. })
                    && !r.undelivered)
                    .then_some(Outcome::RejectRequest { key })
            }
            Message::SwitchTo { identity, key } => {
                let r = self.request(&key)?;
                (r.identity == identity
                    && r.state == QueueState::Waiting
                    && !r.undelivered
                    && !self.is_active(&identity))
                .then_some(Outcome::SwitchTo { identity, key })
            }
            Message::AskDisconnect { topic } => {
                if self.session(&topic).is_some() {
                    self.confirm_disconnect = Some(topic);
                }
                None
            }
            Message::ConfirmDisconnect { topic } => {
                if self.confirm_disconnect.as_ref() != Some(&topic)
                    || self.session(&topic).is_none()
                {
                    return None;
                }
                self.confirm_disconnect = None;
                Some(Outcome::Disconnect { topic })
            }
            Message::CancelDisconnect => {
                self.confirm_disconnect = None;
                None
            }
            Message::RejectAllFrom { topic } => {
                let s = self.session(&topic)?;
                (s.pending > 0).then_some(Outcome::RejectAllFrom { topic })
            }
            Message::Resume { topic } => {
                let s = self.session(&topic)?;
                s.paused.then_some(Outcome::Resume { topic })
            }
            Message::AskStop => {
                self.confirm_stop = self.snapshot.is_some();
                None
            }
            Message::ConfirmStop => {
                if !std::mem::take(&mut self.confirm_stop) {
                    return None;
                }
                self.confirm_disconnect = None;
                Some(Outcome::Stop)
            }
            Message::CancelStop => {
                self.confirm_stop = false;
                None
            }
            Message::ToggleSettings => {
                match self.view {
                    PaneView::Settings => self.close_settings(),
                    PaneView::Home => self.open_settings(),
                }
                None
            }
            Message::ProjectIdChanged(s) => {
                self.form.project = s.take();
                self.settings_error = None;
                None
            }
            Message::RelayUrlChanged(s) => {
                self.form.relay = s.take();
                self.settings_error = None;
                None
            }
            Message::SaveSettings => self.save_settings(),
            Message::ResetSettings => {
                self.form.project = Zeroizing::default();
                self.form.relay = Zeroizing::default();
                self.form.reset = true;
                self.settings_error = None;
                None
            }
            Message::Back => match self.view {
                PaneView::Settings => {
                    self.close_settings();
                    None
                }
                PaneView::Home => self.close(),
            },
            // Esc unwinds the innermost thing first — a staged confirm, then the settings form —
            // and only then leaves the pane. It never rejects a request or a connection.
            Message::Escape => {
                if std::mem::take(&mut self.confirm_stop) {
                    return None;
                }
                if self.confirm_disconnect.take().is_some() {
                    return None;
                }
                match self.view {
                    PaneView::Settings => {
                        self.close_settings();
                        None
                    }
                    PaneView::Home => self.close(),
                }
            }
            Message::Tick | Message::AddressCopied => None,
        }
    }

    /// Leave the pane (to the launcher); a staged confirm doesn't survive leaving.
    fn close(&mut self) -> Option<Outcome> {
        self.confirm_stop = false;
        self.confirm_disconnect = None;
        Some(Outcome::Close)
    }

    fn open_settings(&mut self) {
        self.form = SettingsForm {
            project: Zeroizing::default(),
            relay: Zeroizing::new(
                self.config
                    .as_ref()
                    .and_then(|c| c.relay_custom.clone())
                    .unwrap_or_default(),
            ),
            reset: false,
        };
        self.settings_error = None;
        self.view = PaneView::Settings;
    }

    /// Close the form without saving. A link parked for a project id is abandoned with it (and
    /// zeroized on drop) — the user walked away from the step it was waiting on.
    fn close_settings(&mut self) {
        self.view = PaneView::Home;
        self.form = SettingsForm::default();
        self.pending_pair = None;
        self.pending_why = None;
        self.settings_error = None;
    }

    fn save_settings(&mut self) -> Option<Outcome> {
        if self.view != PaneView::Settings {
            return None;
        }
        let (Ok(p), Ok(r)) = (self.project_edit(), self.relay_edit()) else {
            return None;
        };
        if p == EditKind::Keep && r == EditKind::Keep && self.pending_pair.is_none() {
            return None;
        }
        let project_id = match p {
            EditKind::Keep => SettingEdit::Keep,
            EditKind::Clear => SettingEdit::Clear,
            EditKind::Set => SettingEdit::Set(SecretInput::from(self.form.project.trim())),
        };
        let relay_url = match r {
            EditKind::Keep => SettingEdit::Keep,
            EditKind::Clear => SettingEdit::Clear,
            EditKind::Set => SettingEdit::Set(self.form.relay.trim().to_string()),
        };
        self.settings_error = None;
        // Optimistic: the setters run synchronously in the coordinator, and a refusal reopens the
        // form with these drafts intact (`set_settings_error`).
        self.view = PaneView::Home;
        Some(Outcome::SaveSettings {
            project_id,
            relay_url,
        })
    }

    /// The project-id field's effect on Save. Empty keeps the stored id, unless "Use Kao's
    /// defaults" was pressed with an override in place.
    fn project_edit(&self) -> Result<EditKind, &'static str> {
        let p = self.form.project.trim();
        if !p.is_empty() {
            return crate::settings::check_walletconnect_project_id(p).map(|_| EditKind::Set);
        }
        let has_override = self
            .config
            .as_ref()
            .is_none_or(|c| c.project_source == ProjectIdSource::Override);
        Ok(if self.form.reset && has_override {
            EditKind::Clear
        } else {
            EditKind::Keep
        })
    }

    /// The relay field's effect on Save. Empty means Kao's default relay; the current override
    /// unchanged is a no-op; anything else must pass the settings validator — a typo can never
    /// fall back to the public relay silently.
    fn relay_edit(&self) -> Result<EditKind, &'static str> {
        let r = self.form.relay.trim();
        let current = self.config.as_ref().and_then(|c| c.relay_custom.as_deref());
        if r.is_empty() {
            let has_override = current.is_some() || (self.form.reset && self.config.is_none());
            return Ok(if has_override {
                EditKind::Clear
            } else {
                EditKind::Keep
            });
        }
        if current == Some(r) {
            return Ok(EditKind::Keep);
        }
        crate::settings::check_walletconnect_relay_url(r).map(|_| EditKind::Set)
    }

    /// Save is live only for a valid form that changes something — or that a parked link is
    /// waiting on.
    fn can_save(&self) -> bool {
        match (self.project_edit(), self.relay_edit()) {
            (Ok(p), Ok(r)) => {
                p != EditKind::Keep || r != EditKind::Keep || self.pending_pair.is_some()
            }
            _ => false,
        }
    }

    fn project_feedback(&self) -> Option<(String, Tone)> {
        match self.project_edit() {
            Err(e) => Some((e.to_string(), Tone::Error)),
            Ok(EditKind::Set) => {
                let p = self.form.project.trim();
                // Soft: Reown ids are 32 hex today, but the validator is deliberately looser
                // so a format change can't lock anyone out.
                let looks_standard = p.len() == 32 && p.bytes().all(|b| b.is_ascii_hexdigit());
                (!looks_standard).then(|| {
                    (
                        "Reown project IDs are usually 32 hex characters — check you copied the \
                         whole ID."
                            .to_string(),
                        Tone::Warn,
                    )
                })
            }
            Ok(EditKind::Clear) => {
                Some(("Saving removes your project ID.".to_string(), Tone::Info))
            }
            Ok(EditKind::Keep) => None,
        }
    }

    fn relay_feedback(&self) -> Option<(String, Tone)> {
        match self.relay_edit() {
            Err(e) => Some((e.to_string(), Tone::Error)),
            Ok(EditKind::Clear) => Some((
                "Saving switches back to Kao's default relay.".to_string(),
                Tone::Info,
            )),
            Ok(EditKind::Set | EditKind::Keep) => None,
        }
    }

    // ── coordinator entry points ─────────────────────────────────────────────

    /// Mirror the runtime: called by the coordinator after every book change, identity change and
    /// rebuild.
    pub fn sync(
        &mut self,
        snap: Option<WcSnapshot>,
        active: Option<ActiveIdentityView>,
        config: WcConfigView,
    ) {
        let before = self.trace_snapshot();
        // A staged confirm only stands while its target does.
        if let Some(topic) = &self.confirm_disconnect
            && !snap
                .as_ref()
                .is_some_and(|s| s.sessions.iter().any(|x| &x.topic == topic))
        {
            self.confirm_disconnect = None;
        }
        if snap.is_none() {
            self.confirm_stop = false;
        }
        // Once the runtime reports its own pairing progress, the local "starting" is superseded.
        if self.pairing == PairingUi::Starting
            && snap
                .as_ref()
                .is_some_and(|s| s.pairing != PairingState::Idle || s.proposal.is_some())
        {
            self.pairing = PairingUi::Idle;
        }
        if snap.is_some() {
            self.off_reason = None;
        }
        self.snapshot = snap;
        self.active = active;
        self.config = Some(config);
        self.synced_at = crate::walletconnect::now_secs();
        self.trace_delta(&before);
    }

    pub fn set_pairing(&mut self, p: PairingUi) {
        let before = self.trace_snapshot();
        if p == PairingUi::Starting {
            // A new runtime is on its way: why the last one went off is history.
            self.off_reason = None;
        }
        self.pairing = p;
        self.trace_delta(&before);
    }

    /// Whether the slot has a relay start in flight — begun here or by a dashboard since rebuilt,
    /// whose pane alone was told. Shown as "starting" (Connect waits) while it runs; once it ends,
    /// a "starting" no result came back to here gives way.
    pub fn sync_start(&mut self, starting: bool) {
        if starting && self.pairing != PairingUi::Starting {
            self.set_pairing(PairingUi::Starting);
        } else if !starting && self.pairing == PairingUi::Starting {
            self.set_pairing(PairingUi::Idle);
        }
    }

    /// Why the relay went off (a retired runtime's reason); cleared by the next live mirror.
    pub fn set_off_reason(&mut self, reason: Option<String>) {
        let before = self.trace_snapshot();
        self.off_reason = reason;
        self.trace_delta(&before);
    }

    /// A settings setter's verdict. `Some` reopens the form (drafts intact) with the reason —
    /// nothing was stored; `None` clears it, and drops the drafts of a save that went through.
    pub fn set_settings_error(&mut self, e: Option<String>) {
        let before = self.trace_snapshot();
        match e {
            Some(msg) => {
                self.settings_error = Some(msg);
                self.view = PaneView::Settings;
            }
            None => {
                self.settings_error = None;
                if self.view != PaneView::Settings {
                    self.form = SettingsForm::default();
                }
            }
        }
        self.trace_delta(&before);
    }

    /// NeedsProjectId: park the URI, open the settings form with `why`.
    pub fn open_settings_with_pending(&mut self, uri: SecretInput, why: &'static str) {
        let before = self.trace_snapshot();
        self.open_settings();
        self.pending_pair = Some(uri);
        self.pending_why = Some(why);
        self.pairing = PairingUi::Idle;
        self.trace_delta(&before);
    }

    /// The link parked by [`Self::open_settings_with_pending`], once — the coordinator resumes
    /// Connect with it after a successful save.
    pub fn take_pending_pair(&mut self) -> Option<SecretInput> {
        let before = self.trace_snapshot();
        let p = self.pending_pair.take();
        if p.is_some() {
            self.pending_why = None;
        }
        self.trace_delta(&before);
        p
    }

    // ── derived state ────────────────────────────────────────────────────────

    fn card(&self) -> Option<&ProposalView> {
        self.snapshot.as_ref()?.proposal.as_ref()
    }

    /// An approve needs the relay: while it reconnects, the approve's first network step fails.
    fn relay_connected(&self) -> bool {
        self.snapshot
            .as_ref()
            .is_some_and(|s| s.relay == RelayStatus::Connected)
    }

    fn request(&self, key: &WcKey) -> Option<&RequestView> {
        self.snapshot.as_ref()?.queue.iter().find(|r| &r.key == key)
    }

    fn session(&self, topic: &Topic) -> Option<&SessionView> {
        self.snapshot
            .as_ref()?
            .sessions
            .iter()
            .find(|s| &s.topic == topic)
    }

    fn is_active(&self, identity: &WcIdentity) -> bool {
        self.active
            .as_ref()
            .is_some_and(|a| &a.identity == identity)
    }

    /// Seconds since the last mirror — the snapshot's countdowns were computed then.
    fn elapsed(&self) -> u64 {
        crate::walletconnect::now_secs().saturating_sub(self.synced_at)
    }

    fn secs_left(&self, at_sync: u64) -> u64 {
        at_sync.saturating_sub(self.elapsed())
    }

    fn pairing_in_progress(&self) -> bool {
        self.pairing == PairingUi::Starting
            || self.snapshot.as_ref().is_some_and(|s| {
                matches!(
                    s.pairing,
                    PairingState::Pairing { .. } | PairingState::Waiting { .. }
                )
            })
    }

    /// Connect is live for a link-shaped value unless the relay is still starting or a connection
    /// request is open (each paste yields at most one card). A paste still waiting for its
    /// proposal doesn't block: a fresh link supersedes it (the dapp's dialog may have closed).
    fn connect_enabled(&self) -> bool {
        looks_like_wc_uri(&self.uri) && self.pairing != PairingUi::Starting && self.card().is_none()
    }

    /// Anything on screen counting down — the 1 s Tick runs only then.
    fn countdowns_visible(&self) -> bool {
        self.snapshot.as_ref().is_some_and(|s| {
            s.proposal.is_some()
                || !s.queue.is_empty()
                || matches!(
                    s.pairing,
                    PairingState::Pairing { .. } | PairingState::Waiting { .. }
                )
                || matches!(s.relay, RelayStatus::Reconnecting { .. })
        })
    }

    /// The one status line under the `wc:` field. `launcher`: the row sits on the Apps launcher
    /// (the pane's own sections aren't on screen, so the line summarises them).
    fn uri_status(&self, launcher: bool, now: u64) -> (String, Tone) {
        if let PairingUi::Failed(m) = &self.pairing {
            return (m.clone(), Tone::Error);
        }
        if self.pairing == PairingUi::Starting {
            return ("Connecting to the relay…".to_string(), Tone::Info);
        }
        if self.pending_pair.is_some() {
            return (
                if launcher {
                    "WalletConnect needs a project ID — open WalletConnect below to add one."
                } else {
                    "WalletConnect needs a project ID — add one in Connection settings."
                }
                .to_string(),
                Tone::Warn,
            );
        }
        let snap = self.snapshot.as_ref();
        match snap.map(|s| &s.pairing) {
            Some(PairingState::Pairing { since, .. } | PairingState::Waiting { since, .. }) => {
                let waited = now.saturating_sub(*since);
                return (
                    if waited >= PAIRING_HINT_AFTER_SECS {
                        "Still waiting — is the dapp's connect dialog still open?"
                    } else {
                        "Waiting for the dapp…"
                    }
                    .to_string(),
                    Tone::Info,
                );
            }
            // A new paste in the field supersedes the last attempt's failure.
            Some(PairingState::Failed(m)) if self.uri.is_empty() => {
                return (m.clone(), Tone::Error);
            }
            Some(PairingState::Failed(_)) => {}
            Some(PairingState::Idle) | None => {}
        }
        if snap.is_some_and(|s| s.proposal.is_some()) {
            return (
                if launcher {
                    "A dapp wants to connect — open WalletConnect below to review it."
                } else {
                    "A dapp wants to connect — review the request below."
                }
                .to_string(),
                Tone::Info,
            );
        }
        // The pane's relay card says it already; only the launcher has no other place to.
        if launcher
            && self
                .config
                .as_ref()
                .is_some_and(|c| c.proxy == ProxyView::RestartPending)
        {
            return (RESTART_FOR_PROXY.to_string(), Tone::Warn);
        }
        if launcher && let Some(summary) = self.activity_summary() {
            return (summary, Tone::Info);
        }
        (
            if launcher {
                IDLE_HINT_LAUNCHER
            } else {
                IDLE_HINT_PANE
            }
            .to_string(),
            Tone::Info,
        )
    }

    /// "2 dapps connected · 1 request waiting", or `None` when there's nothing to report.
    fn activity_summary(&self) -> Option<String> {
        let s = self.snapshot.as_ref()?;
        let waiting = s
            .queue
            .iter()
            .filter(|r| r.state == QueueState::Waiting && !r.undelivered)
            .count();
        let mut parts = Vec::new();
        if !s.sessions.is_empty() {
            parts.push(format!(
                "{} connected",
                plural(s.sessions.len(), "dapp", "dapps")
            ));
        }
        if waiting > 0 {
            parts.push(format!(
                "{} waiting",
                plural(waiting, "request", "requests")
            ));
        }
        if s.proposal.is_some() {
            parts.push("1 connection request".to_string());
        }
        (!parts.is_empty()).then(|| parts.join(" · "))
    }

    pub fn launcher_card_subtitle(&self) -> String {
        self.activity_summary()
            .unwrap_or_else(|| "Use Kao with dapps — paste a WalletConnect link".to_string())
    }

    /// Esc-only `keyboard::listen().filter_map(esc_only)` + 1 s Tick while countdowns are visible.
    pub fn subscription(&self) -> Subscription<Message> {
        let keys = keyboard::listen().filter_map(esc_only);
        if self.countdowns_visible() {
            Subscription::batch([
                keys,
                iced::time::every(Duration::from_secs(1)).map(|_| Message::Tick),
            ])
        } else {
            keys
        }
    }

    // ── views ────────────────────────────────────────────────────────────────

    pub fn view<'a>(&'a self, t: KaoTheme) -> Element<'a, Message> {
        match self.view {
            PaneView::Home => self.home_view(t),
            PaneView::Settings => self.settings_view(t),
        }
    }

    /// The `wc:` field, Connect, and the status line — on the launcher and atop the pane alike.
    pub fn launcher_row<'a>(&'a self, t: KaoTheme) -> Element<'a, Message> {
        self.uri_row(t, true)
    }

    fn uri_row<'a>(&'a self, t: KaoTheme, launcher: bool) -> Element<'a, Message> {
        let now = crate::walletconnect::now_secs();
        let enabled = self.connect_enabled();
        let label = if self.pairing_in_progress() && !enabled {
            "…"
        } else {
            "Connect"
        };
        let field = text_input(URI_PLACEHOLDER, &self.uri)
            .on_input(|s| Message::UriChanged(SecretInput::from(s)))
            .on_submit(Message::Connect)
            .padding(Padding::from([12, 14]))
            .size(14)
            .font(mono())
            .width(Length::Fill)
            .style(move |_, s| text_input_style(t, s));
        let (status, tone) = self.uri_status(launcher, now);
        column![
            row![
                field,
                Space::new().width(10),
                pill_button(t, label, enabled.then_some(Message::Connect)),
            ]
            .align_y(Alignment::Center)
            .width(Length::Fill),
            Space::new().height(6),
            text(status)
                .size(12)
                .color(tone_color(t, tone))
                .font(if tone == Tone::Info { mono() } else { bold() }),
        ]
        .spacing(0)
        .width(Length::Fill)
        .into()
    }

    fn home_view<'a>(&'a self, t: KaoTheme) -> Element<'a, Message> {
        let now = crate::walletconnect::now_secs();
        let mut body = column![
            row![
                ghost_button(t, text("← Apps").size(13).color(t.sub).font(bold()))
                    .on_press(Message::Back),
                Space::new().width(Length::Fill),
                text(KAO_MASCOT).size(20).color(t.a3).font(bold()),
            ]
            .align_y(Alignment::Center)
            .width(Length::Fill),
            Space::new().height(10),
            screen_title(t, "WalletConnect"),
            Space::new().height(6),
            screen_subtitle(
                t,
                "Use Kao with dapps — every request opens a review here first"
            ),
            Space::new().height(16),
            self.relay_card(t, now),
            Space::new().height(14),
            self.uri_row(t, false),
        ]
        .spacing(0)
        .width(Length::Fill)
        .max_width(560);

        if let Some(snap) = &self.snapshot {
            if let Some(p) = &snap.proposal {
                body = body.push(Space::new().height(20));
                body = body.push(section_label(t, "CONNECTION REQUEST"));
                body = body.push(Space::new().height(8));
                body = body.push(self.proposal_card(t, p));
            }
            if !snap.queue.is_empty() {
                body = body.push(Space::new().height(20));
                body = body.push(section_label(t, "WAITING FOR YOU"));
                body = body.push(Space::new().height(8));
                let mut list = column![].spacing(8).width(Length::Fill);
                for r in &snap.queue {
                    list = list.push(self.request_row(t, r));
                }
                body = body.push(list);
            }
            body = body.push(Space::new().height(20));
            body = body.push(section_label(t, "CONNECTED DAPPS"));
            body = body.push(Space::new().height(8));
            if snap.sessions.is_empty() {
                body = body.push(text("No dapps connected yet.").size(12).color(t.sub));
            } else {
                let mut list = column![].spacing(8).width(Length::Fill);
                for s in &snap.sessions {
                    list = list.push(self.session_row(t, s));
                }
                body = body.push(list);
            }
            if !snap.notices.is_empty() || snap.refused_count > 0 {
                body = body.push(Space::new().height(20));
                body = body.push(section_label(t, "ACTIVITY"));
                body = body.push(Space::new().height(8));
                if snap.refused_count > 0 {
                    body = body.push(
                        text(format!(
                            "Kao refused {} without asking you — malformed, unsupported or over \
                             the limits.",
                            plural(snap.refused_count as usize, "request", "requests")
                        ))
                        .size(11)
                        .color(t.sub),
                    );
                    body = body.push(Space::new().height(6));
                }
                if !snap.notices.is_empty() {
                    body = body.push(activity_box(t, &snap.notices, now));
                }
            }
        }

        body = body.push(Space::new().height(20));
        body = body.push(self.settings_link(t));
        if self.snapshot.is_some() {
            body = body.push(Space::new().height(16));
            body = body.push(self.stop_controls(t));
        }
        body.into()
    }

    /// The relay connection: a status chip plus what it means for the user's privacy.
    fn relay_card<'a>(&'a self, t: KaoTheme, now: u64) -> Element<'a, Message> {
        const OFF: &str = "Off — Kao connects to the relay only when you paste a link.";
        let (chip, kind, line) = match &self.snapshot {
            None => (
                "off",
                BadgeKind::Info,
                self.off_reason.clone().unwrap_or_else(|| OFF.to_string()),
            ),
            Some(s) => match s.relay {
                RelayStatus::Connected => (
                    "connected",
                    BadgeKind::Good,
                    match s.route {
                        RouteKind::Proxied => "Connected via your proxy.",
                        RouteKind::Direct => {
                            "Connected directly — the relay operator can see your IP."
                        }
                        RouteKind::Loopback => "Connected to a relay on this computer.",
                    }
                    .to_string(),
                ),
                RelayStatus::Connecting => (
                    "connecting",
                    BadgeKind::Info,
                    "Connecting to the relay…".to_string(),
                ),
                RelayStatus::Reconnecting { since } => (
                    "reconnecting",
                    BadgeKind::Caution,
                    format!(
                        "Reconnecting for {} — dapps can't reach Kao until the relay is back.",
                        span_label(now.saturating_sub(since))
                    ),
                ),
                RelayStatus::Closed => ("off", BadgeKind::Info, OFF.to_string()),
            },
        };
        let mut col = column![
            row![
                privacy_badge(t, kind, chip),
                Space::new().width(8),
                text(line).size(12).color(t.text),
            ]
            .align_y(Alignment::Center)
            .width(Length::Fill),
        ]
        .spacing(4)
        .width(Length::Fill);
        if let Some(s) = &self.snapshot
            && s.undelivered > 0
        {
            col = col.push(
                text(format!(
                    "{} waiting for the relay — Kao re-sends them when it reconnects.",
                    plural(s.undelivered, "answer", "answers")
                ))
                .size(11)
                .color(t.sub),
            );
        }
        if self
            .config
            .as_ref()
            .is_some_and(|c| c.proxy == ProxyView::RestartPending)
        {
            col = col.push(
                text(RESTART_FOR_PROXY)
                    .size(11)
                    .color(caution_color())
                    .font(bold()),
            );
        }
        tile(t, col.into())
    }

    /// The approval card: who is asking (host first, unverified), what connecting exposes
    /// (the active identity only), on which networks, what the dapp can ask for, and the caveats.
    fn proposal_card<'a>(&'a self, t: KaoTheme, p: &'a ProposalView) -> Element<'a, Message> {
        let left = self.secs_left(p.secs_left);
        let mut col = column![
            row![
                text("wants to connect").size(11).color(t.sub).font(bold()),
                Space::new().width(Length::Fill),
                privacy_badge(t, BadgeKind::Caution, "unverified"),
            ]
            .align_y(Alignment::Center)
            .width(Length::Fill),
            Space::new().height(6),
            mono_box(
                t,
                text(p.dapp.headline())
                    .size(17)
                    .color(t.text)
                    .font(mono_bold())
                    .into()
            ),
            Space::new().height(4),
            text(if p.dapp.description.is_empty() {
                format!("calls itself \"{}\"", p.dapp.name)
            } else {
                format!(
                    "calls itself \"{}\" · \"{}\"",
                    p.dapp.name, p.dapp.description
                )
            })
            .size(12)
            .color(t.sub),
        ]
        .spacing(0)
        .width(Length::Fill);
        if p.dapp.insecure_scheme {
            col = col.push(Space::new().height(4));
            col = col.push(
                text("⚠ http:// — not a secure connection")
                    .size(12)
                    .color(t.down)
                    .font(bold()),
            );
        }
        col = col.push(Space::new().height(6));
        col = col.push(
            text(format!(
                "⚠ Kao can't confirm this request came from {}. Only continue if you just copied \
                 this link from that site.",
                p.dapp.headline()
            ))
            .size(11)
            .color(caution_color())
            .font(bold()),
        );
        col = col.push(Space::new().height(12));

        let mut can_connect = false;
        match &p.plan {
            None => {
                col = col.push(
                    text(
                        "Switch to an account that can sign to connect — this one can't sign for \
                         a dapp.",
                    )
                    .size(12)
                    .color(t.text)
                    .font(bold()),
                );
            }
            Some(plan) => {
                let granted = plan.verdict.as_ref().ok().map(|g| g.chains.as_slice());
                can_connect = granted.is_some() && !p.busy && left > 0 && self.relay_connected();
                let badge = match (&self.active, plan.identity) {
                    (Some(a), id) if a.identity == id => a.badge,
                    (_, WcIdentity::Safe { .. }) => "Safe",
                    (_, WcIdentity::Eoa { .. }) => "Account",
                };
                col = col.push(label_line(t, "Connect as"));
                col = col.push(
                    text(format!("{} · {badge}", plan.identity_label))
                        .size(13)
                        .color(t.text)
                        .font(bold()),
                );
                col = col.push(Space::new().height(4));
                col = col.push(mono_box(t, colored_address(t, plan.identity.address())));
                col = col.push(Space::new().height(4));
                col = col.push(
                    text("The dapp will see this one address. Nothing else.")
                        .size(11)
                        .color(t.sub),
                );
                col = col.push(Space::new().height(10));
                // Chain labels can carry the dapp's own CAIP-2 strings ("eip155:N (not
                // available)"), so the list sits in a mono box like every dapp string.
                col = col.push(label_line(t, "Networks"));
                let mut nets = column![].spacing(2).width(Length::Fill);
                for (line, tone) in chain_lines(&plan.chains, granted) {
                    nets = nets.push(text(line).size(12).color(tone_color(t, tone)).font(mono()));
                }
                col = col.push(mono_box(t, nets.into()));
                let (asks, refused) = method_lines(&plan.methods);
                col = col.push(Space::new().height(10));
                col = col.push(label_line(t, "It can ask you to"));
                col = col.push(
                    text(if asks.is_empty() {
                        "nothing Kao serves".to_string()
                    } else {
                        asks
                    })
                    .size(12)
                    .color(t.text),
                );
                // Method names are the dapp's strings.
                if !refused.is_empty() {
                    col = col.push(Space::new().height(4));
                    let mut lines = column![].spacing(2).width(Length::Fill);
                    for r in refused {
                        lines = lines.push(text(r).size(11).color(t.sub).font(mono()));
                    }
                    col = col.push(mono_box(t, lines.into()));
                }
                if !plan.caveats.is_empty() {
                    col = col.push(Space::new().height(10));
                    col = col.push(label_line(t, "Caveats"));
                    for c in &plan.caveats {
                        col = col.push(text(format!("· {c}")).size(11).color(t.text));
                    }
                }
                if let Err(block) = &plan.verdict {
                    col = col.push(Space::new().height(10));
                    col = col.push(
                        text(format!("Kao can't connect: {}", block.reason))
                            .size(12)
                            .color(t.down)
                            .font(bold()),
                    );
                }
            }
        }
        if let Some(e) = &p.error {
            col = col.push(Space::new().height(8));
            col = col.push(text(e.as_str()).size(12).color(t.down).font(bold()));
        }
        if !p.busy && left > 0 && !self.relay_connected() {
            col = col.push(Space::new().height(8));
            col = col.push(
                text("Connect comes back once the relay is back.")
                    .size(12)
                    .color(t.sub),
            );
        }
        col = col.push(Space::new().height(10));
        col = col.push(
            text(if left > 0 {
                format!("Expires in {}", span_label(left))
            } else {
                "This request has expired.".to_string()
            })
            .size(11)
            .color(t.sub)
            .font(mono()),
        );
        col = col.push(Space::new().height(12));

        let reject = secondary_button(t, "Reject");
        let reject = if p.busy {
            reject
        } else {
            reject.on_press(Message::RejectProposal { proposal_id: p.id })
        };
        let connect = primary_button(
            t,
            if p.busy { "Connecting…" } else { "Connect" },
            can_connect,
        );
        let connect = if can_connect {
            connect.on_press(Message::Approve { proposal_id: p.id })
        } else {
            connect
        };
        col = col.push(
            row![
                container(reject).width(Length::FillPortion(1)),
                Space::new().width(10),
                container(connect).width(Length::FillPortion(1)),
            ]
            .width(Length::Fill),
        );
        container(col)
            .padding(Padding::from([14, 16]))
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(t.card_alt)),
                border: Border {
                    color: with_alpha(t.a1, 0.45),
                    width: 1.5,
                    radius: Radius::from(14),
                },
                text_color: Some(t.text),
                ..container::Style::default()
            })
            .into()
    }

    /// One request waiting for the user, with what they can do about it right now.
    fn request_row<'a>(&'a self, t: KaoTheme, r: &'a RequestView) -> Element<'a, Message> {
        let elapsed = self.elapsed();
        let when = match r.secs_left {
            Some(left) => match left.saturating_sub(elapsed) {
                0 => "expired".to_string(),
                l => format!("{} left", span_label(l)),
            },
            None => format!(
                "received {} ago",
                span_label(r.age_secs.saturating_add(elapsed))
            ),
        };
        let mut col = column![
            row![
                text(format!("Session {}", r.ordinal))
                    .size(11)
                    .color(t.sub)
                    .font(mono_bold()),
                Space::new().width(6),
                host_chip(t, &r.dapp_host),
                Space::new().width(Length::Fill),
                text(when).size(11).color(t.sub).font(mono()),
            ]
            .align_y(Alignment::Center)
            .width(Length::Fill),
            Space::new().height(4),
            text(r.label).size(13).color(t.text).font(bold()),
            Space::new().height(4),
            mono_box(
                t,
                text(r.summary.as_str())
                    .size(12)
                    .color(t.text)
                    .font(mono())
                    .into()
            ),
            Space::new().height(4),
            text(format!(
                "for {} · {}",
                r.identity_label,
                crate::walletconnect::chain_label(r.chain_id)
            ))
            .size(12)
            .color(t.sub),
            Space::new().height(8),
        ]
        .spacing(0)
        .width(Length::Fill);

        let reject = || {
            small_danger_button(t, "Reject").on_press(Message::RejectRequest { key: r.key.clone() })
        };
        let actions: Element<'a, Message> = if r.undelivered {
            note(
                t,
                "Answer waiting for the relay — Kao re-sends it automatically.",
            )
        } else {
            match r.state {
                // The overlay covers this row while it shows the review; Reject is for a review
                // that lost its overlay.
                QueueState::InReview { .. } => row![
                    note(t, "In review…"),
                    Space::new().width(Length::Fill),
                    reject(),
                ]
                .align_y(Alignment::Center)
                .spacing(6)
                .width(Length::Fill)
                .into(),
                QueueState::Signing { .. } => note(t, "Waiting for the signature…"),
                // A paused session's requests wait here instead of opening: after several
                // rejections in a row Kao stops popping them up until the user resumes.
                QueueState::Waiting if r.paused => row![
                    text("Paused — many rejections in a row")
                        .size(11)
                        .color(caution_color())
                        .font(bold()),
                    Space::new().width(Length::Fill),
                    small_secondary_button(t, "Resume").on_press(Message::Resume {
                        topic: r.key.topic.clone()
                    }),
                    small_danger_button(t, "Reject all").on_press(Message::RejectAllFrom {
                        topic: r.key.topic.clone()
                    }),
                ]
                .align_y(Alignment::Center)
                .spacing(6)
                .width(Length::Fill)
                .into(),
                // Kao's execution of an earlier transaction for this Safe isn't mined yet: this one
                // would take the same nonce, so it waits until that is mined or given up on.
                // [Review anyway] opens it now, its review naming the execution it may collide with.
                QueueState::Waiting if r.held && self.is_active(&r.identity) => row![
                    note(t, "Waits for Kao's previous execution"),
                    Space::new().width(Length::Fill),
                    small_secondary_button(t, "Review anyway")
                        .on_press(Message::ReviewPastHold { key: r.key.clone() }),
                    reject(),
                ]
                .align_y(Alignment::Center)
                .spacing(6)
                .width(Length::Fill)
                .into(),
                QueueState::Waiting if self.is_active(&r.identity) => row![
                    Space::new().width(Length::Fill),
                    small_secondary_button(t, "Review")
                        .on_press(Message::ReviewNow { key: r.key.clone() }),
                    reject(),
                ]
                .align_y(Alignment::Center)
                .spacing(6)
                .width(Length::Fill)
                .into(),
                QueueState::Waiting => row![
                    text("Kao is using a different account")
                        .size(11)
                        .color(t.sub),
                    Space::new().width(Length::Fill),
                    chip_button(
                        t,
                        format!("Switch to {}", r.identity_label),
                        Message::SwitchTo {
                            identity: r.identity,
                            key: r.key.clone(),
                        }
                    ),
                    reject(),
                ]
                .align_y(Alignment::Center)
                .spacing(6)
                .width(Length::Fill)
                .into(),
            }
        };
        col = col.push(actions);
        tile(t, col.into())
    }

    /// One connected dapp: host first (unverified), its claimed name, the identity and networks it
    /// was granted, and the two-step Disconnect.
    fn session_row<'a>(&'a self, t: KaoTheme, s: &'a SessionView) -> Element<'a, Message> {
        let chains = s
            .chains
            .iter()
            .map(|c| crate::walletconnect::chain_label(*c))
            .collect::<Vec<_>>()
            .join(", ");
        let mut col = column![
            row![
                text(format!("Session {}", s.ordinal))
                    .size(11)
                    .color(t.sub)
                    .font(mono_bold()),
                Space::new().width(Length::Fill),
                privacy_badge(t, BadgeKind::Caution, "unverified"),
            ]
            .align_y(Alignment::Center)
            .width(Length::Fill),
            Space::new().height(6),
            mono_box(
                t,
                text(s.dapp.headline())
                    .size(14)
                    .color(t.text)
                    .font(mono_bold())
                    .into()
            ),
            Space::new().height(4),
            text(format!("calls itself \"{}\"", s.dapp.name))
                .size(12)
                .color(t.sub),
            Space::new().height(4),
            text(format!(
                "as {} · {} · {chains}",
                s.identity_label,
                crate::wallet::short_address(s.identity.address())
            ))
            .size(12)
            .color(t.text),
        ]
        .spacing(0)
        .width(Length::Fill);
        match s.ack {
            AckState::Unconfirmed => {
                col = col.push(Space::new().height(4));
                col = col.push(
                    text("The dapp never confirmed this connection.")
                        .size(11)
                        .color(caution_color())
                        .font(bold()),
                );
            }
            AckState::Pending => {
                col = col.push(Space::new().height(4));
                col = col.push(
                    text("Waiting for the dapp to confirm…")
                        .size(11)
                        .color(t.sub),
                );
            }
            AckState::Confirmed => {}
        }
        if s.paused {
            col = col.push(Space::new().height(4));
            col = col.push(
                text(
                    "Paused — you rejected several requests in a row, so new ones wait here \
                     instead of opening.",
                )
                .size(11)
                .color(caution_color()),
            );
        }
        col = col.push(Space::new().height(8));

        let mut actions = row![]
            .spacing(6)
            .align_y(Alignment::Center)
            .width(Length::Fill);
        if self.confirm_disconnect.as_ref() == Some(&s.topic) {
            actions = actions.push(
                text("Disconnect this dapp?")
                    .size(12)
                    .color(t.down)
                    .font(bold()),
            );
            actions = actions.push(Space::new().width(Length::Fill));
            actions =
                actions.push(small_secondary_button(t, "Keep").on_press(Message::CancelDisconnect));
            actions = actions.push(small_danger_button(t, "Disconnect").on_press(
                Message::ConfirmDisconnect {
                    topic: s.topic.clone(),
                },
            ));
        } else {
            actions = actions.push(Space::new().width(Length::Fill));
            if s.paused {
                actions = actions.push(small_secondary_button(t, "Resume").on_press(
                    Message::Resume {
                        topic: s.topic.clone(),
                    },
                ));
            }
            if s.pending > 0 {
                actions = actions.push(chip_button(
                    t,
                    format!("Reject all ({})", s.pending),
                    Message::RejectAllFrom {
                        topic: s.topic.clone(),
                    },
                ));
            }
            actions = actions.push(small_danger_button(t, "Disconnect").on_press(
                Message::AskDisconnect {
                    topic: s.topic.clone(),
                },
            ));
        }
        col = col.push(actions);
        tile(t, col.into())
    }

    /// "Connection settings ›" plus a one-line summary of what's configured.
    fn settings_link<'a>(&'a self, t: KaoTheme) -> Element<'a, Message> {
        let summary = self.config.as_ref().map(|c| {
            let project = match c.project_source {
                ProjectIdSource::Override => "your project ID",
                ProjectIdSource::BuiltIn => "Kao's project ID",
                ProjectIdSource::Missing => "no project ID",
            };
            let relay = if c.relay_custom.is_some() {
                "custom relay"
            } else {
                "default relay"
            };
            format!("{project} · {relay}")
        });
        let mut inner = row![
            text("Connection settings ›")
                .size(13)
                .color(t.text)
                .font(bold()),
            Space::new().width(Length::Fill),
        ]
        .align_y(Alignment::Center)
        .width(Length::Fill);
        if let Some(s) = summary {
            inner = inner.push(text(s).size(11).color(t.sub).font(mono()));
        }
        ghost_button(t, container(inner).padding(Padding::from([8, 4])))
            .width(Length::Fill)
            .on_press(Message::ToggleSettings)
            .into()
    }

    /// The two-step "Turn off WalletConnect".
    fn stop_controls<'a>(&'a self, t: KaoTheme) -> Element<'a, Message> {
        if self.confirm_stop {
            column![
                text(
                    "This disconnects every dapp and closes the relay connection. Requests still \
                     waiting are cancelled."
                )
                .size(12)
                .color(t.down)
                .font(bold()),
                Space::new().height(8),
                row![
                    Space::new().width(Length::Fill),
                    small_secondary_button(t, "Keep it on").on_press(Message::CancelStop),
                    small_danger_button(t, "Turn off").on_press(Message::ConfirmStop),
                ]
                .spacing(6)
                .align_y(Alignment::Center)
                .width(Length::Fill),
            ]
            .spacing(0)
            .width(Length::Fill)
            .into()
        } else {
            row![
                small_danger_button(t, "Turn off WalletConnect").on_press(Message::AskStop),
                Space::new().width(Length::Fill),
            ]
            .width(Length::Fill)
            .into()
        }
    }

    fn settings_view<'a>(&'a self, t: KaoTheme) -> Element<'a, Message> {
        let mut body = column![
            ghost_button(
                t,
                text("← WalletConnect").size(13).color(t.sub).font(bold())
            )
            .on_press(Message::Back),
            Space::new().height(10),
            screen_title(t, "Connection settings"),
            Space::new().height(6),
            screen_subtitle(t, "How Kao reaches the WalletConnect relay"),
            Space::new().height(18),
        ]
        .spacing(0)
        .width(Length::Fill)
        .max_width(560);

        if let Some(why) = self.pending_why {
            body = body.push(tile(
                t,
                column![
                    text(why).size(12).color(caution_color()).font(bold()),
                    Space::new().height(4),
                    text("Your link is kept until you save — then Kao connects with it.")
                        .size(11)
                        .color(t.sub),
                ]
                .spacing(0)
                .width(Length::Fill)
                .into(),
            ));
            body = body.push(Space::new().height(14));
        }

        // ── project id ──
        let source = self.config.as_ref().map(|c| c.project_source);
        let (status, tone) = match source {
            Some(ProjectIdSource::Override) => ("Using your project ID.", Tone::Info),
            Some(ProjectIdSource::BuiltIn) => ("Using Kao's project ID.", Tone::Info),
            Some(ProjectIdSource::Missing) | None => (
                "No project ID — one is required for the default relay.",
                Tone::Warn,
            ),
        };
        let mut project = column![
            section_label(t, "PROJECT ID"),
            Space::new().height(6),
            text(status).size(12).color(tone_color(t, tone)),
            Space::new().height(6),
            text_input(
                "Paste a WalletConnect Cloud (Reown) project ID",
                &self.form.project
            )
            .on_input(|s| Message::ProjectIdChanged(SecretInput::from(s)))
            .on_submit(Message::SaveSettings)
            .padding(Padding::from([10, 12]))
            .size(13)
            .font(mono())
            .width(Length::Fill)
            .style(move |_, s| text_input_style(t, s)),
        ]
        .spacing(0)
        .width(Length::Fill);
        if let Some((msg, tone)) = self.project_feedback() {
            project = project.push(Space::new().height(4));
            project = project.push(text(msg).size(11).color(tone_color(t, tone)));
        }
        body = body.push(project);
        body = body.push(Space::new().height(16));

        // ── relay ──
        let default_relay = self
            .config
            .as_ref()
            .map_or(wallet_connect::relay::rpc::DEFAULT_RELAY_URL, |c| {
                c.default_relay
            });
        let mut relay = column![
            section_label(t, "RELAY"),
            Space::new().height(6),
            text_input(default_relay, &self.form.relay)
                .on_input(|s| Message::RelayUrlChanged(SecretInput::from(s)))
                .on_submit(Message::SaveSettings)
                .padding(Padding::from([10, 12]))
                .size(13)
                .font(mono())
                .width(Length::Fill)
                .style(move |_, s| text_input_style(t, s)),
            Space::new().height(4),
            text(format!("Leave empty for Kao's default ({default_relay})."))
                .size(11)
                .color(t.sub),
        ]
        .spacing(0)
        .width(Length::Fill);
        if let Some((msg, tone)) = self.relay_feedback() {
            relay = relay.push(Space::new().height(4));
            relay = relay.push(text(msg).size(11).color(tone_color(t, tone)));
        }
        body = body.push(relay);
        body = body.push(Space::new().height(12));
        body = body.push(
            row![
                small_secondary_button(t, "Use Kao's defaults").on_press(Message::ResetSettings),
                Space::new().width(Length::Fill),
            ]
            .width(Length::Fill),
        );
        body = body.push(Space::new().height(14));
        body = body.push(note(
            t,
            "Changes apply the next time WalletConnect starts — turn WalletConnect off and connect \
             again, or restart Kao. Kao never restarts it on its own — that would drop your \
             connected dapps.",
        ));
        body = body.push(Space::new().height(4));
        body = body.push(note(
            t,
            "The relay operator (Reown by default) sees when you're connected; through your proxy \
             it doesn't see your IP.",
        ));
        if let Some(e) = &self.settings_error {
            body = body.push(Space::new().height(10));
            body = body.push(text(e.as_str()).size(12).color(t.down).font(bold()));
        }
        body = body.push(Space::new().height(16));
        let enabled = self.can_save();
        let save = primary_button(
            t,
            if self.pending_pair.is_some() {
                "Save & connect"
            } else {
                "Save"
            },
            enabled,
        );
        body = body.push(if enabled {
            save.on_press(Message::SaveSettings)
        } else {
            save
        });
        body.into()
    }
}

/// The networks block of the approval card. With a grant, ✓ means "in the grant the Connect
/// button sends" — so the list can't show a chain the approval wouldn't include, or hide one it
/// would. A granted chain the plan didn't itemise is appended rather than dropped.
fn chain_lines(lines: &[ChainLine], granted: Option<&[u64]>) -> Vec<(String, Tone)> {
    let mut out: Vec<(String, Tone)> = lines
        .iter()
        .map(|l| {
            let on = granted.map_or(l.granted, |g| g.contains(&l.chain_id));
            if on {
                let mut s = format!("✓ {}", l.label);
                if l.required {
                    s.push_str(" (required)");
                }
                if l.unverified {
                    s.push_str(" (unverified network)");
                }
                (s, if l.unverified { Tone::Warn } else { Tone::Info })
            } else if l.required {
                (
                    format!("✕ {} — required, not available in Kao", l.label),
                    Tone::Error,
                )
            } else {
                (
                    format!("✕ {} — not set up in Kao (optional, skipped)", l.label),
                    Tone::Info,
                )
            }
        })
        .collect();
    for c in granted.unwrap_or_default() {
        if !lines.iter().any(|l| l.chain_id == *c) {
            out.push((
                format!("✓ {}", crate::walletconnect::chain_label(*c)),
                Tone::Info,
            ));
        }
    }
    out
}

/// "send transactions · sign messages …" for what the dapp may ask (and Kao serves), plus one
/// line per method Kao grants only because the dapp requires it and then refuses on every call.
fn method_lines(methods: &[MethodLine]) -> (String, Vec<String>) {
    let mut asks: Vec<&'static str> = Vec::new();
    let mut refused = Vec::new();
    for m in methods {
        match m.support {
            MethodSupport::Served => {
                if let Some(p) = method_phrase(&m.name)
                    && !asks.contains(&p)
                {
                    asks.push(p);
                }
            }
            MethodSupport::CapabilityRefused => {
                if let Some(p) = method_phrase(&m.name) {
                    refused.push(format!("Kao refuses to {p} for this account"));
                }
            }
            MethodSupport::Refused if m.required => refused.push(format!(
                "Kao refuses {} — the dapp requires it, so every call gets a refusal",
                m.name
            )),
            MethodSupport::Unknown if m.required => refused.push(format!(
                "✕ {} — not supported (required by the dapp)",
                m.name
            )),
            MethodSupport::Refused | MethodSupport::Unknown => {}
        }
    }
    refused.dedup();
    (asks.join(" · "), refused)
}

/// The recent notices, newest as the book keeps them, in one bordered mono box (they can name a
/// dapp's host).
fn activity_box<'a>(t: KaoTheme, notices: &'a [NoticeView], now: u64) -> Element<'a, Message> {
    let mut col = column![].spacing(4).width(Length::Fill);
    for n in notices {
        col = col.push(
            text(format!(
                "{} ago · {}",
                span_label(now.saturating_sub(n.at)),
                n.text
            ))
            .size(11)
            .color(if n.error { t.down } else { t.text })
            .font(mono()),
        );
    }
    mono_box(t, col.into())
}

fn section_label<'a>(t: KaoTheme, label: &'a str) -> Element<'a, Message> {
    text(label).size(11).color(t.sub).font(mono_bold()).into()
}

fn label_line<'a>(t: KaoTheme, label: &'a str) -> Element<'a, Message> {
    column![
        text(label).size(11).color(t.sub).font(bold()),
        Space::new().height(2)
    ]
    .spacing(0)
    .into()
}

fn note<'a>(t: KaoTheme, msg: &'a str) -> Element<'a, Message> {
    text(msg).size(11).color(t.sub).into()
}

/// A section tile — the card the pane's rows sit in.
fn tile<'a>(t: KaoTheme, content: Element<'a, Message>) -> Element<'a, Message> {
    container(content)
        .padding(Padding::from([12, 14]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card_alt)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(12),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
}

/// A dapp's host, small, in its own bordered mono chip — the row-header form of the host box.
fn host_chip<'a>(t: KaoTheme, host: &'a str) -> Element<'a, Message> {
    container(text(host).size(11).color(t.text).font(mono_bold()))
        .padding(Padding::from([2, 6]))
        .style(move |_| container::Style {
            background: Some(Background::Color(t.card)),
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(6),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
}

/// The compact accent action next to the `wc:` field (the Names search-bar pattern). `None`
/// renders it greyed and inert.
fn pill_button<'a>(t: KaoTheme, label: &'a str, msg: Option<Message>) -> Element<'a, Message> {
    let enabled = msg.is_some();
    let bg = if enabled { t.a1 } else { t.border };
    let b = button(text(label).size(13).color(Color::WHITE).font(bold()))
        .padding(Padding::from([11, 18]))
        .style(move |_, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed if enabled => {
                    with_alpha(t.a1, 0.82)
                }
                _ => bg,
            })),
            text_color: Color::WHITE,
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: Radius::from(10),
            },
            ..button::Style::default()
        });
    match msg {
        Some(m) => b.on_press(m).into(),
        None => b.into(),
    }
}

/// `small_secondary_button` with an owned label ("Switch to Account 2", "Reject all (3)").
fn chip_button<'a>(t: KaoTheme, label: String, msg: Message) -> Element<'a, Message> {
    button(text(label).size(11).color(t.text).font(bold()))
        .padding(Padding::from([4, 10]))
        .on_press(msg)
        .style(move |_theme, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => hover_tint(t.card_alt, t.text),
                _ => t.card_alt,
            })),
            text_color: t.text,
            border: Border {
                color: t.border,
                width: 1.0,
                radius: Radius::from(8),
            },
            ..button::Style::default()
        })
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::walletconnect::{DappLabel, Grant, ProposalBlock, ProposalPlan};
    use alloy::primitives::Address;

    const URI: &str = "wc:7f6e504bfad60b485450578e05678ed3e8e8c4751d3c6160be17160d63ec90f9@2?relay-protocol=irn&symKey=587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303";
    const SYM_KEY: &str = "587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303";
    const PROJECT_ID: &str = "0123456789abcdef0123456789abcdef";

    fn topic(c: char) -> Topic {
        Topic::new(c.to_string().repeat(64))
    }

    fn eoa() -> WcIdentity {
        WcIdentity::Eoa {
            address: Address::repeat_byte(0x11),
        }
    }

    fn safe() -> WcIdentity {
        WcIdentity::Safe {
            address: Address::repeat_byte(0x5A),
            chain_id: 8453,
        }
    }

    fn label(name: &str, host: &str) -> DappLabel {
        DappLabel {
            name: name.into(),
            host: Some(host.into()),
            url: format!("https://{host}"),
            description: String::new(),
            insecure_scheme: false,
        }
    }

    fn config() -> WcConfigView {
        WcConfigView {
            project_source: ProjectIdSource::Missing,
            relay_custom: None,
            default_relay: wallet_connect::relay::rpc::DEFAULT_RELAY_URL,
            proxy: ProxyView::None,
        }
    }

    fn active(identity: WcIdentity) -> ActiveIdentityView {
        ActiveIdentityView {
            identity,
            label: "Account 2".into(),
            badge: "Local",
        }
    }

    fn snapshot() -> WcSnapshot {
        WcSnapshot {
            generation: 1,
            relay: RelayStatus::Connected,
            route: RouteKind::Direct,
            pairing: PairingState::Idle,
            proposal: None,
            sessions: Vec::new(),
            queue: Vec::new(),
            notices: Vec::new(),
            refused_count: 0,
            undelivered: 0,
        }
    }

    fn plan(identity: WcIdentity, verdict: Result<Vec<u64>, ProposalBlock>) -> ProposalPlan {
        ProposalPlan {
            identity,
            identity_label: "Account 2".into(),
            chains: vec![
                ChainLine {
                    chain_id: 1,
                    label: "Ethereum".into(),
                    required: true,
                    granted: true,
                    unverified: false,
                },
                ChainLine {
                    chain_id: 8453,
                    label: "Base".into(),
                    required: false,
                    granted: true,
                    unverified: false,
                },
                ChainLine {
                    chain_id: 42161,
                    label: "eip155:42161 (not available)".into(),
                    required: false,
                    granted: false,
                    unverified: false,
                },
            ],
            methods: vec![MethodLine {
                name: "personal_sign".into(),
                required: true,
                support: MethodSupport::Served,
            }],
            caveats: Vec::new(),
            verdict: verdict.map(|chains| Grant {
                namespaces: Default::default(),
                chains,
                methods: vec!["personal_sign".into()],
                events: Vec::new(),
            }),
        }
    }

    fn with_proposal(plan: Option<ProposalPlan>) -> WcSnapshot {
        WcSnapshot {
            proposal: Some(ProposalView {
                id: 42,
                dapp: label("Uniswap Interface", "app.uniswap.org"),
                secs_left: 240,
                busy: false,
                error: None,
                plan,
            }),
            ..snapshot()
        }
    }

    fn session(t: Topic, identity: WcIdentity) -> SessionView {
        SessionView {
            topic: t,
            ordinal: 1,
            dapp: label("Uniswap Interface", "app.uniswap.org"),
            identity,
            identity_label: "Account 2".into(),
            chains: vec![1],
            pending: 1,
            ack: AckState::Confirmed,
            paused: false,
        }
    }

    fn request(t: Topic, id: u64, identity: WcIdentity) -> RequestView {
        RequestView {
            key: WcKey { topic: t, id },
            ordinal: 1,
            dapp_host: "app.uniswap.org".into(),
            label: "Sign message",
            summary: "Sign in to app.uniswap.org".into(),
            identity,
            identity_label: "Account 2".into(),
            chain_id: 1,
            state: QueueState::Waiting,
            age_secs: 5,
            secs_left: Some(300),
            paused: false,
            undelivered: false,
            held: false,
        }
    }

    fn pane_with(snap: WcSnapshot, who: WcIdentity) -> WcApp {
        let mut app = WcApp::new();
        app.sync(Some(snap), Some(active(who)), config());
        app
    }

    fn esc_event(key: keyboard::Key) -> keyboard::Event {
        keyboard::Event::KeyPressed {
            key: key.clone(),
            modified_key: key,
            physical_key: keyboard::key::Physical::Code(keyboard::key::Code::Escape),
            location: keyboard::Location::Standard,
            modifiers: keyboard::Modifiers::default(),
            text: None,
            repeat: false,
        }
    }

    #[test]
    fn connect_enabled_only_for_wc_uri() {
        let mut app = WcApp::new();
        for not_a_link in [
            "",
            "   ",
            "hello",
            "https://app.uniswap.org",
            "WC:abc@2",
            "ethereum:0x1234",
            // Base64-alphabet, but not the base64 of a `wc:` link.
            "aGVsbG8gd29ybGQ=",
            "d2M6 not base64",
        ] {
            app.update(Message::UriChanged(not_a_link.into()));
            assert!(!app.connect_enabled(), "{not_a_link:?}");
            assert!(app.update(Message::Connect).is_none(), "{not_a_link:?}");
        }
        for link in [
            URI.to_string(),
            format!("  {URI}\n"),
            URI.replacen("wc:", "wc://", 1),
            // `wc:` + topic@2… in base64 — what Telegram-style deep links carry.
            "d2M6N2Y2ZTUwNGJmYWQ2MGI0ODU0NTA1NzhlMDU2NzhlZDNlOGU4YzQ3NTFkM2M2MTYwYmUxNzE2MGQ2M2VjOTBmOUAyP3JlbGF5LXByb3RvY29sPWlybiZzeW1LZXk9NTg3ZDU0ODRjZTJhMmE2ZWUzYmExOTYyZmRkN2U4NTg4ZTA2MjAwYzQ2ODIzYmQxOGZiZDY3ZGVmOTZhZDMwMw=="
                .to_string(),
        ] {
            app.update(Message::UriChanged(link.as_str().into()));
            assert!(app.connect_enabled(), "{link:?}");
        }
    }

    #[test]
    fn connect_moves_and_clears_uri() {
        let mut app = WcApp::new();
        app.update(Message::UriChanged(URI.into()));
        let Some(Outcome::Pair { uri }) = app.update(Message::Connect) else {
            panic!("Connect on a wc: link pairs");
        };
        assert_eq!(uri.expose(), URI);
        // The field is empty now: nothing left to re-send, and no copy of the symKey stays put.
        assert!(app.uri.is_empty());
        assert!(!app.connect_enabled());
        assert!(app.update(Message::Connect).is_none());
        // Submitting the field (Enter) is the same Connect.
        app.update(Message::UriChanged(URI.into()));
        assert!(matches!(
            app.update(Message::Connect),
            Some(Outcome::Pair { .. })
        ));
    }

    #[test]
    fn connect_disabled_while_card_open() {
        // An open connection request: each paste yields at most one card.
        let mut app = pane_with(with_proposal(Some(plan(eoa(), Ok(vec![1])))), eoa());
        app.update(Message::UriChanged(URI.into()));
        assert!(!app.connect_enabled());
        assert!(app.update(Message::Connect).is_none());
        assert_eq!(app.uri.as_str(), URI, "a refused Connect keeps the link");

        // A paste still waiting for its proposal doesn't block a fresh link (it supersedes it).
        let waiting = WcSnapshot {
            pairing: PairingState::Waiting {
                topic: topic('a'),
                since: 0,
                until: u64::MAX,
            },
            ..snapshot()
        };
        app.sync(Some(waiting), Some(active(eoa())), config());
        assert!(app.connect_enabled());

        // The runtime starting (no book yet).
        app.sync(None, Some(active(eoa())), config());
        assert!(app.connect_enabled());
        app.set_pairing(PairingUi::Starting);
        assert!(!app.connect_enabled());
        app.set_pairing(PairingUi::Failed("Couldn't reach the relay".into()));
        assert!(app.connect_enabled(), "a failure lets the user try again");
    }

    #[test]
    fn esc_never_rejects() {
        let t = topic('b');
        let mut snap = with_proposal(Some(plan(eoa(), Ok(vec![1]))));
        snap.sessions = vec![session(t.clone(), eoa())];
        snap.queue = vec![request(t.clone(), 7, eoa())];
        let mut app = pane_with(snap, eoa());

        // A staged two-step confirm is unwound first, and nothing is sent.
        app.update(Message::AskDisconnect { topic: t.clone() });
        assert!(app.confirm_disconnect.is_some());
        assert!(app.update(Message::Escape).is_none());
        assert!(app.confirm_disconnect.is_none());
        app.update(Message::AskStop);
        assert!(app.update(Message::Escape).is_none());
        assert!(!app.confirm_stop);

        // Then the settings form.
        app.update(Message::ToggleSettings);
        assert_eq!(app.view, PaneView::Settings);
        assert!(app.update(Message::Escape).is_none());
        assert_eq!(app.view, PaneView::Home);

        // Then the pane itself — with a connection request AND a dapp request open, Esc leaves;
        // it never answers either of them.
        assert!(matches!(app.update(Message::Escape), Some(Outcome::Close)));
        assert!(matches!(app.update(Message::Back), Some(Outcome::Close)));
    }

    /// While the relay reconnects, the card's Connect is off (and says why): an approve would fail
    /// at its first network step. It comes back with the relay.
    #[test]
    fn connect_waits_for_the_relay() {
        let mut snap = with_proposal(Some(plan(eoa(), Ok(vec![1]))));
        snap.relay = RelayStatus::Reconnecting { since: 1 };
        let mut app = pane_with(snap.clone(), eoa());
        assert!(app.update(Message::Approve { proposal_id: 42 }).is_none());
        let theme = crate::ui::kao_theme::KaoTheme::for_kind(crate::ui::kao_theme::ThemeKind::Mint);
        let shown = super::super::test_support::texts(app.view(theme));
        assert!(
            shown.iter().any(|t| t.contains("relay is back")),
            "{shown:?}"
        );
        snap.relay = RelayStatus::Connected;
        let mut app = pane_with(snap, eoa());
        assert!(matches!(
            app.update(Message::Approve { proposal_id: 42 }),
            Some(Outcome::Approve { .. })
        ));
    }

    #[test]
    fn approve_carries_displayed_identity_and_chains() {
        let mut app = pane_with(with_proposal(Some(plan(eoa(), Ok(vec![1, 8453])))), eoa());
        let Some(Outcome::Approve {
            proposal_id,
            identity,
            chains,
        }) = app.update(Message::Approve { proposal_id: 42 })
        else {
            panic!("an approvable card approves");
        };
        assert_eq!(proposal_id, 42);
        assert_eq!(identity, eoa());
        assert_eq!(chains, vec![1, 8453]);

        // What the card lists as ✓ is exactly that grant — nothing more, nothing less.
        let p = plan(eoa(), Ok(vec![1, 8453]));
        let lines = chain_lines(&p.chains, Some(&[1, 8453]));
        let ticked: Vec<&str> = lines
            .iter()
            .filter(|(l, _)| l.starts_with('✓'))
            .map(|(l, _)| l.as_str())
            .collect();
        assert_eq!(ticked, vec!["✓ Ethereum (required)", "✓ Base"]);
        // A grant chain the plan didn't itemise still shows; a plan line outside the grant
        // doesn't get a tick.
        let lines = chain_lines(&p.chains[..1], Some(&[1, 10]));
        assert_eq!(lines.len(), 2);
        assert!(lines[1].0.starts_with("✓ "));
        let lines = chain_lines(&p.chains, Some(&[1]));
        assert!(lines[1].0.starts_with("✕ Base"));

        // A stale or foreign id does nothing.
        assert!(app.update(Message::Approve { proposal_id: 41 }).is_none());

        // A Safe identity carries the Safe (address AND chain).
        let mut app = pane_with(with_proposal(Some(plan(safe(), Ok(vec![8453])))), safe());
        assert!(matches!(
            app.update(Message::Approve { proposal_id: 42 }),
            Some(Outcome::Approve { identity, chains, .. }) if identity == safe() && chains == vec![8453]
        ));

        // A blocked plan can't be approved — but it can be rejected (with the block's code, by
        // the coordinator).
        let block = ProposalBlock {
            code: 5100,
            message: "Unsupported chains.",
            reason: "requires Arbitrum — add it under Settings › Networks".into(),
        };
        let mut app = pane_with(with_proposal(Some(plan(eoa(), Err(block)))), eoa());
        assert!(app.update(Message::Approve { proposal_id: 42 }).is_none());
        assert!(matches!(
            app.update(Message::RejectProposal { proposal_id: 42 }),
            Some(Outcome::RejectProposal { proposal_id: 42 })
        ));

        // No exposable active identity (watch-only): nothing to approve.
        let mut app = pane_with(with_proposal(None), eoa());
        assert!(app.update(Message::Approve { proposal_id: 42 }).is_none());

        // Busy (approve in flight): neither button acts.
        let mut snap = with_proposal(Some(plan(eoa(), Ok(vec![1]))));
        if let Some(p) = snap.proposal.as_mut() {
            p.busy = true;
        }
        let mut app = pane_with(snap, eoa());
        assert!(app.update(Message::Approve { proposal_id: 42 }).is_none());
        assert!(
            app.update(Message::RejectProposal { proposal_id: 42 })
                .is_none()
        );
    }

    #[test]
    fn settings_save_disabled_when_invalid() {
        let mut app = pane_with(snapshot(), eoa());
        app.update(Message::ToggleSettings);
        // Nothing typed, nothing parked: nothing to save.
        assert!(!app.can_save());
        assert!(app.update(Message::SaveSettings).is_none());

        app.update(Message::ProjectIdChanged("too-short".into()));
        assert!(!app.can_save());
        assert!(app.update(Message::SaveSettings).is_none());
        assert_eq!(
            app.view,
            PaneView::Settings,
            "an invalid save keeps the form"
        );

        app.update(Message::ProjectIdChanged(PROJECT_ID.into()));
        app.update(Message::RelayUrlChanged("http://relay.example.com".into()));
        assert!(!app.can_save(), "a bad relay blocks the whole save");
        assert!(app.update(Message::SaveSettings).is_none());
        app.update(Message::RelayUrlChanged("wss://relay.example.com".into()));
        assert!(app.can_save());
        let Some(Outcome::SaveSettings {
            project_id: SettingEdit::Set(id),
            relay_url: SettingEdit::Set(relay),
        }) = app.update(Message::SaveSettings)
        else {
            panic!("a valid form saves both fields");
        };
        assert_eq!(id.expose(), PROJECT_ID);
        assert_eq!(relay, "wss://relay.example.com");

        // A setter refusal reopens the form with the reason; nothing stored.
        app.set_settings_error(Some("That relay URL isn't allowed.".into()));
        assert_eq!(app.view, PaneView::Settings);
        assert!(app.settings_error.is_some());
    }

    #[test]
    fn missing_project_id_parks_uri_and_resumes() {
        let mut app = pane_with(snapshot(), eoa());
        app.open_settings_with_pending(
            SecretInput::from(URI),
            "WalletConnect needs a project ID to use the default relay.",
        );
        assert_eq!(app.view, PaneView::Settings);
        assert!(app.uri_status(true, 0).0.contains("project ID"));

        app.update(Message::ProjectIdChanged(PROJECT_ID.into()));
        let Some(Outcome::SaveSettings {
            project_id: SettingEdit::Set(_),
            relay_url: SettingEdit::Keep,
        }) = app.update(Message::SaveSettings)
        else {
            panic!("Save & connect saves the id");
        };
        // The coordinator stores it, then resumes Connect with the parked link — exactly once.
        let parked = app.take_pending_pair().expect("the link was parked");
        assert_eq!(parked.expose(), URI);
        assert!(app.take_pending_pair().is_none());
        assert!(app.pending_why.is_none());

        // Walking away from the form abandons a parked link.
        app.open_settings_with_pending(SecretInput::from(URI), "needs an id");
        app.update(Message::Escape);
        assert!(app.take_pending_pair().is_none());
    }

    #[test]
    fn parked_link_saves_without_edits() {
        // With a link parked, Save is the "connect now" button even when the form changes
        // nothing (e.g. the id was set elsewhere meanwhile) — no validator involved.
        let mut app = pane_with(snapshot(), eoa());
        app.open_settings_with_pending(SecretInput::from(URI), "needs an id");
        assert!(app.can_save());
        assert!(matches!(
            app.update(Message::SaveSettings),
            Some(Outcome::SaveSettings {
                project_id: SettingEdit::Keep,
                relay_url: SettingEdit::Keep
            })
        ));
        assert_eq!(app.view, PaneView::Home);
    }

    #[test]
    fn reset_clears_overrides() {
        let mut app = WcApp::new();
        app.sync(
            Some(snapshot()),
            None,
            WcConfigView {
                project_source: ProjectIdSource::Override,
                relay_custom: Some("wss://relay.example.com".into()),
                ..config()
            },
        );
        app.update(Message::ToggleSettings);
        assert_eq!(
            app.form.relay.as_str(),
            "wss://relay.example.com",
            "prefilled"
        );
        assert!(!app.can_save(), "unchanged");
        app.update(Message::ResetSettings);
        assert!(matches!(
            app.update(Message::SaveSettings),
            Some(Outcome::SaveSettings {
                project_id: SettingEdit::Clear,
                relay_url: SettingEdit::Clear
            })
        ));
    }

    #[test]
    fn uri_and_project_id_debug_redacted() {
        let msgs = [
            Message::UriChanged(URI.into()),
            Message::ProjectIdChanged(PROJECT_ID.into()),
        ];
        for m in &msgs {
            let dbg = format!("{m:?}");
            assert!(!dbg.contains(SYM_KEY) && !dbg.contains("symKey"), "{dbg}");
            assert!(!dbg.contains(PROJECT_ID), "{dbg}");
        }
        let outs = [
            Outcome::Pair {
                uri: SecretInput::from(URI),
            },
            Outcome::SaveSettings {
                project_id: SettingEdit::Set(SecretInput::from(PROJECT_ID)),
                relay_url: SettingEdit::Keep,
            },
        ];
        for o in &outs {
            let dbg = format!("{o:?}");
            assert!(!dbg.contains(SYM_KEY) && !dbg.contains(PROJECT_ID), "{dbg}");
        }
        // The pane itself, holding both.
        let mut app = WcApp::new();
        app.update(Message::UriChanged(URI.into()));
        app.update(Message::ToggleSettings);
        app.update(Message::ProjectIdChanged(PROJECT_ID.into()));
        let dbg = format!("{app:?}");
        assert!(!dbg.contains(SYM_KEY) && !dbg.contains(PROJECT_ID), "{dbg}");
        // And the trace path (what `trace_msg!` would log) — a relay draft too, which can carry
        // a project id pasted along with it.
        let traced = crate::trace::clamp_debug(&Message::UriChanged(URI.into()));
        assert!(!traced.contains(SYM_KEY));
        let relay = format!("wss://relay.walletconnect.com/?projectId={PROJECT_ID}");
        let traced = crate::trace::clamp_debug(&Message::RelayUrlChanged(relay.into()));
        assert!(!traced.contains(PROJECT_ID), "{traced}");
    }

    #[test]
    fn only_escape_becomes_a_message() {
        use keyboard::key::Named;
        assert!(matches!(
            esc_only(esc_event(keyboard::Key::Named(Named::Escape))),
            Some(Message::Escape)
        ));
        // Typing into the link / project-id fields — presses and releases alike — is never a
        // message, so it can never be traced.
        let released = keyboard::Event::KeyReleased {
            key: keyboard::Key::Named(Named::Escape),
            modified_key: keyboard::Key::Named(Named::Escape),
            physical_key: keyboard::key::Physical::Code(keyboard::key::Code::Escape),
            location: keyboard::Location::Standard,
            modifiers: keyboard::Modifiers::default(),
        };
        for e in [
            esc_event(keyboard::Key::Character("v".into())),
            esc_event(keyboard::Key::Character("7".into())),
            esc_event(keyboard::Key::Named(Named::Enter)),
            esc_event(keyboard::Key::Named(Named::Tab)),
            released,
            keyboard::Event::ModifiersChanged(keyboard::Modifiers::COMMAND),
        ] {
            assert!(esc_only(e).is_none());
        }
    }

    #[test]
    fn request_actions_follow_state_and_identity() {
        let t = topic('c');
        let mut snap = snapshot();
        let mut paused = session(t.clone(), eoa());
        paused.paused = true;
        snap.sessions = vec![paused];
        let mut reviewing = request(t.clone(), 2, eoa());
        reviewing.state = QueueState::InReview { seq: 9 };
        snap.queue = vec![
            request(t.clone(), 1, eoa()),
            reviewing,
            request(t.clone(), 3, safe()),
        ];
        let mut app = pane_with(snap, eoa());
        let key = |id| WcKey {
            topic: t.clone(),
            id,
        };

        // Waiting, identity active.
        assert!(matches!(
            app.update(Message::ReviewNow { key: key(1) }),
            Some(Outcome::ReviewNow { .. })
        ));
        assert!(matches!(
            app.update(Message::RejectRequest { key: key(1) }),
            Some(Outcome::RejectRequest { .. })
        ));
        // Under review: no Review; Reject reaches the coordinator, which refuses it while an
        // overlay shows that review and answers it when the review lost its overlay.
        assert!(app.update(Message::ReviewNow { key: key(2) }).is_none());
        assert!(matches!(
            app.update(Message::RejectRequest { key: key(2) }),
            Some(Outcome::RejectRequest { .. })
        ));
        // Another identity: switch, don't review.
        assert!(app.update(Message::ReviewNow { key: key(3) }).is_none());
        assert!(matches!(
            app.update(Message::SwitchTo { identity: safe(), key: key(3) }),
            Some(Outcome::SwitchTo { identity, key: k }) if identity == safe() && k == key(3)
        ));
        assert!(
            app.update(Message::SwitchTo {
                identity: eoa(),
                key: key(1)
            })
            .is_none()
        );
        // Only for the request it was clicked on.
        assert!(
            app.update(Message::SwitchTo {
                identity: safe(),
                key: key(1)
            })
            .is_none()
        );
        assert!(
            app.update(Message::SwitchTo {
                identity: safe(),
                key: key(99)
            })
            .is_none()
        );
        // Unknown key.
        assert!(app.update(Message::ReviewNow { key: key(99) }).is_none());

        // Session actions: paused ⇒ Resume; pending ⇒ Reject all; Disconnect is two-step.
        assert!(matches!(
            app.update(Message::Resume { topic: t.clone() }),
            Some(Outcome::Resume { .. })
        ));
        assert!(matches!(
            app.update(Message::RejectAllFrom { topic: t.clone() }),
            Some(Outcome::RejectAllFrom { .. })
        ));
        assert!(
            app.update(Message::ConfirmDisconnect { topic: t.clone() })
                .is_none(),
            "confirm without ask does nothing"
        );
        app.update(Message::AskDisconnect { topic: t.clone() });
        assert!(matches!(
            app.update(Message::ConfirmDisconnect { topic: t.clone() }),
            Some(Outcome::Disconnect { .. })
        ));

        // Turn off is two-step too.
        assert!(app.update(Message::ConfirmStop).is_none());
        app.update(Message::AskStop);
        assert!(matches!(
            app.update(Message::ConfirmStop),
            Some(Outcome::Stop)
        ));
    }

    #[test]
    fn sync_drops_stale_confirms_and_supersedes_starting() {
        let t = topic('d');
        let mut snap = snapshot();
        snap.sessions = vec![session(t.clone(), eoa())];
        let mut app = pane_with(snap, eoa());
        app.update(Message::AskDisconnect { topic: t.clone() });
        app.update(Message::AskStop);
        // The session went away (dapp disconnected) and then the runtime retired.
        app.sync(Some(snapshot()), Some(active(eoa())), config());
        assert!(app.confirm_disconnect.is_none());
        app.sync(None, Some(active(eoa())), config());
        assert!(!app.confirm_stop);

        app.set_pairing(PairingUi::Starting);
        app.sync(
            Some(WcSnapshot {
                pairing: PairingState::Pairing {
                    topic: topic('e'),
                    since: 0,
                },
                ..snapshot()
            }),
            Some(active(eoa())),
            config(),
        );
        assert_eq!(app.pairing, PairingUi::Idle);
        assert_eq!(app.uri_status(false, 1).0, "Waiting for the dapp…");
        assert!(
            app.uri_status(false, PAIRING_HINT_AFTER_SECS)
                .0
                .starts_with("Still waiting")
        );
    }

    #[test]
    fn card_subtitle_counts_what_waits() {
        let t = topic('f');
        let mut snap = with_proposal(None);
        snap.sessions = vec![session(t.clone(), eoa()), session(topic('g'), eoa())];
        let mut under_review = request(t.clone(), 2, eoa());
        under_review.state = QueueState::Signing { seq: 1 };
        snap.queue = vec![request(t.clone(), 1, eoa()), under_review];
        let app = pane_with(snap, eoa());
        // The request under signature isn't waiting on the user.
        assert_eq!(
            app.launcher_card_subtitle(),
            "2 dapps connected · 1 request waiting · 1 connection request"
        );
    }

    #[test]
    fn method_lines_phrase_what_the_dapp_can_ask() {
        let line = |name: &str, required, support| MethodLine {
            name: name.into(),
            required,
            support,
        };
        let (asks, refused) = method_lines(&[
            line("eth_sendTransaction", false, MethodSupport::Served),
            line("personal_sign", true, MethodSupport::Served),
            line(
                "eth_signTypedData_v4",
                false,
                MethodSupport::CapabilityRefused,
            ),
            line("eth_accounts", false, MethodSupport::Served),
            line("eth_chainId", false, MethodSupport::Served),
            line("eth_sign", true, MethodSupport::Refused),
            line("eth_signTransaction", false, MethodSupport::Refused),
        ]);
        assert_eq!(
            asks,
            "send transactions · sign messages · read your address and network"
        );
        assert_eq!(
            refused,
            vec![
                "Kao refuses to sign typed data for this account".to_string(),
                "Kao refuses eth_sign — the dapp requires it, so every call gets a refusal"
                    .to_string(),
            ]
        );
    }

    /// The pane renders every section without touching anything beyond the mirror, and draws the
    /// dapp's host ahead of its claimed name.
    #[test]
    fn home_view_renders_the_mirror() {
        let t = topic('h');
        let mut snap = with_proposal(Some(plan(eoa(), Ok(vec![1, 8453]))));
        snap.sessions = vec![session(t.clone(), eoa())];
        snap.queue = vec![request(t.clone(), 1, eoa()), request(t, 2, safe())];
        snap.notices = vec![NoticeView {
            at: 0,
            text: "Connected to app.uniswap.org".into(),
            error: false,
        }];
        let app = pane_with(snap, eoa());
        let theme = KaoTheme::for_kind(crate::ui::kao_theme::ThemeKind::Void);
        let texts = super::super::test_support::texts(app.view(theme));
        let host = texts.iter().position(|s| s == "app.uniswap.org");
        let claim = texts
            .iter()
            .position(|s| s == "calls itself \"Uniswap Interface\"");
        assert!(host.is_some() && claim.is_some(), "{texts:?}");
        assert!(host < claim, "{texts:?}");
        for expected in [
            "CONNECTION REQUEST",
            "WAITING FOR YOU",
            "CONNECTED DAPPS",
            "ACTIVITY",
            "✓ Ethereum (required)",
            "Switch to Account 2",
            "Turn off WalletConnect",
        ] {
            assert!(texts.iter().any(|s| s == expected), "{expected}: {texts:?}");
        }

        // The settings form renders too (empty drafts: no validator involved).
        let mut app = app;
        app.update(Message::ToggleSettings);
        let texts = super::super::test_support::texts(app.view(theme));
        assert!(texts.iter().any(|s| s == "PROJECT ID"), "{texts:?}");
    }

    /// The settings note names the restarts the user can actually make — turning WalletConnect off
    /// and connecting again, or restarting Kao — never a lock the dashboard doesn't offer.
    #[test]
    fn settings_note_names_restarts_the_user_can_make() {
        let mut app = pane_with(snapshot(), eoa());
        app.update(Message::ToggleSettings);
        let theme = KaoTheme::for_kind(crate::ui::kao_theme::ThemeKind::Void);
        let texts = super::super::test_support::texts(app.view(theme));
        let note = texts
            .iter()
            .find(|s| s.starts_with("Changes apply"))
            .unwrap_or_else(|| panic!("the note: {texts:?}"));
        assert!(!note.contains("lock"), "{note}");
        assert!(
            note.contains("turn WalletConnect off") && note.contains("restart Kao"),
            "{note}"
        );
    }

    /// A proxy that applies on restart is said once on the pane (its relay card), with or without
    /// a runtime; only the launcher, which has no relay card, puts it in the status line.
    #[test]
    fn restart_for_proxy_is_said_once() {
        let theme = KaoTheme::for_kind(crate::ui::kao_theme::ThemeKind::Void);
        for snap in [Some(snapshot()), None] {
            let mut app = WcApp::new();
            let mut cfg = config();
            cfg.proxy = ProxyView::RestartPending;
            app.sync(snap, Some(active(eoa())), cfg);
            let texts = super::super::test_support::texts(app.view(theme));
            assert_eq!(
                texts.iter().filter(|s| *s == RESTART_FOR_PROXY).count(),
                1,
                "{texts:?}"
            );
            assert_eq!(app.uri_status(true, 0).0, RESTART_FOR_PROXY);
        }
    }

    /// A Safe transaction waiting for Kao's unmined execution of an earlier one says so in place
    /// of [Review], which would open nothing; [Review anyway] opens it past the hold, and Reject
    /// still answers it.
    #[test]
    fn a_held_request_says_why_instead_of_offering_review() {
        let t = topic('w');
        let mut snap = snapshot();
        snap.sessions = vec![session(t.clone(), safe())];
        let mut held = request(t.clone(), 1, safe());
        held.held = true;
        snap.queue = vec![held];
        let mut app = pane_with(snap, safe());
        let theme = KaoTheme::for_kind(crate::ui::kao_theme::ThemeKind::Void);
        let texts = super::super::test_support::texts(app.view(theme));
        assert!(
            texts.iter().any(|s| s.contains("previous execution")),
            "{texts:?}"
        );
        assert!(!texts.iter().any(|s| s == "Review"), "{texts:?}");
        assert!(texts.iter().any(|s| s == "Review anyway"), "{texts:?}");
        let key = WcKey { topic: t, id: 1 };
        assert!(
            app.update(Message::ReviewNow { key: key.clone() })
                .is_none()
        );
        assert!(matches!(
            app.update(Message::ReviewPastHold { key: key.clone() }),
            Some(Outcome::ReviewPastHold { key: k }) if k == key
        ));
        assert!(matches!(
            app.update(Message::RejectRequest { key }),
            Some(Outcome::RejectRequest { .. })
        ));
    }

    /// [Review anyway] is only for a request a hold keeps back, of the account Kao is using.
    #[test]
    fn review_anyway_is_only_for_a_held_request() {
        let t = topic('w');
        let mut snap = snapshot();
        snap.sessions = vec![session(t.clone(), safe())];
        snap.queue = vec![request(t.clone(), 1, safe())];
        let mut app = pane_with(snap.clone(), safe());
        let key = WcKey { topic: t, id: 1 };
        assert!(
            app.update(Message::ReviewPastHold { key: key.clone() })
                .is_none(),
            "nothing holds it: [Review] is the way"
        );
        snap.queue[0].held = true;
        let mut elsewhere = pane_with(snap, eoa());
        assert!(
            elsewhere.update(Message::ReviewPastHold { key }).is_none(),
            "another account's request"
        );
    }
}
