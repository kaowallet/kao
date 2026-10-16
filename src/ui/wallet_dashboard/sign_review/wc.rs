//! WalletConnect review panels. A child of `sign_review` so it can use the parent's private helpers
//! (`kv`, `addr_kv`, `hash_row`, `card`, `ceremony_owner_list`, `format_eth`, …) without widening them.
//!
//! Every string a dapp controls reaches the screen in exactly one of two ways: inside a bordered
//! monospace box (the dapp's host, message text, typed-data fields, SIWE fields), or explicitly
//! labelled as the dapp's claim (`calls itself "…"`). The self-declared name never leads — the
//! origin card's headline is the host the dapp's metadata URL names, captioned as unconfirmed,
//! because Kao has no way to confirm either (the protocol crate has no Verify API).
//!
//! Every panel renders from the review structs the coordinator pinned at open / prepare time, so
//! what is drawn here is what the sign task re-derives and signs. The ERC-8213 rows for the new
//! steps live here too ([`erc8213_rows`]); the parent appends them under each panel.

use std::fmt::Write as _;

use super::*;

// Explicit: through the glob, iced's `column!` would be ambiguous with std's `column!`.
use iced::widget::column;
use iced::widget::text::Wrapping;

use crate::chain::NetworkId;
use crate::sanitize::{escape_unsafe_display, sanitize_display};
use crate::sign::digest::{
    DAPP_DOMAIN_HASH_LABEL, DAPP_EIP712_DIGEST_LABEL, DAPP_MESSAGE_HASH_LABEL, EIP191_DIGEST_LABEL,
};
use crate::ui::kao_widgets::{BadgeKind, caution_color, privacy_badge, span_label};
use crate::walletconnect::{
    AllowanceExpiry, AllowanceGrant, BinaryReason, DomainSummary, ExactValue, TypedKind,
    TypedWarning, format_gwei,
};

/// Display clamps for dapp strings drawn in the typed-data and SIWE boxes. Generous on purpose —
/// the fingerprints cover every byte, but a value the user can't read in full is one they can't
/// check — while still bounding a hostile multi-kilobyte field. A typed value longer than its row
/// shows is reviewable in full behind "Show exact values".
const MAX_FIELD_LABEL_CHARS: usize = 128;
const MAX_FIELD_VALUE_CHARS: usize = 512;
const MAX_SIWE_FIELD_CHARS: usize = 160;

/// Every text a dapp controls wraps mid-token when it has to. The default (`Word`) lays an
/// unbroken run out on one line far past the box, and the scrollable body clips it with no sign
/// anything is missing.
const DAPP_WRAP: Wrapping = Wrapping::WordOrGlyph;

/// Unix seconds past the year 9999 aren't a date anyone means — `type(uint256).max` is the usual
/// way to say "no deadline".
const MAX_SHOWN_TIMESTAMP: u64 = 253_402_300_799;

/// The panel for one WalletConnect step (`WcOrigin` / `WcMessage` / `WcTyped` / `WcSafeMessage` /
/// `WcTxFees`). The parent appends the ERC-8213 fingerprints section from [`erc8213_rows`].
pub(super) fn step_card<'a>(
    t: KaoTheme,
    step: &'a SignStep,
    show_calldata: bool,
    show_fee_details: bool,
    signing: bool,
) -> Element<'a, Message> {
    match step {
        SignStep::WcOrigin(o) => origin_card(t, o, signing),
        SignStep::WcMessage(m) => card(t, message_body(t, m, show_calldata).into()),
        SignStep::WcTyped(r) => typed_panel_wc(t, r, show_calldata),
        SignStep::WcSafeMessage(m) => safe_message_panel_wc(t, m, show_calldata),
        SignStep::WcTxFees(f) => fees_card(t, f, show_fee_details),
        // The parent routes only the `Wc*` arms here.
        SignStep::RawTx(_)
        | SignStep::Delegation(_)
        | SignStep::Typed(_)
        | SignStep::SafeExec(_)
        | SignStep::SafeMessage(_)
        | SignStep::Send(_)
        | SignStep::SafeSend(_) => Space::new().width(0).height(0).into(),
    }
}

/// The ERC-8213 `(label, hash)` rows for a WalletConnect step: none for `WcOrigin` / `WcTxFees`;
/// the EIP-191 digest for `WcMessage`; the EIP-712 triple for `WcTyped`; the SafeMessage triple
/// plus the inner message's digest(s) for `WcSafeMessage`. Typed data that is a `SafeTx` adds the
/// Calldata Digest of the call it confirms, exactly as a Safe transaction step does.
///
/// `WcTxFees` has none of its own: the transaction's calldata is a `RawTx` step of the same
/// review, which carries the Calldata Digest.
pub(super) fn erc8213_rows(step: &SignStep) -> Vec<(String, B256)> {
    const STANDARD: [&str; 3] = [EIP712_DIGEST_LABEL, DOMAIN_HASH_LABEL, MESSAGE_HASH_LABEL];
    const DAPP: [&str; 3] = [
        DAPP_EIP712_DIGEST_LABEL,
        DAPP_DOMAIN_HASH_LABEL,
        DAPP_MESSAGE_HASH_LABEL,
    ];
    fn triple(rows: &mut Vec<(String, B256)>, d: &Eip712Digests, labels: [&str; 3]) {
        rows.push((labels[0].to_string(), d.digest));
        rows.push((labels[1].to_string(), d.domain_hash));
        rows.push((labels[2].to_string(), d.message_hash));
    }
    fn typed(rows: &mut Vec<(String, B256)>, r: &TypedDataReview, labels: [&str; 3]) {
        triple(rows, &r.checked.digests, labels);
        if let TypedKind::SafeTx { data, .. } = &r.checked.kind
            && !data.is_empty()
        {
            rows.push((
                INNER_CALLDATA_DIGEST_LABEL.to_string(),
                crate::sign::digest::calldata_digest(data),
            ));
        }
    }

    let mut rows = Vec::new();
    match step {
        SignStep::WcMessage(m) => rows.push((EIP191_DIGEST_LABEL.to_string(), m.eip191_hash)),
        SignStep::WcTyped(r) => typed(&mut rows, r, STANDARD),
        SignStep::WcSafeMessage(m) => {
            // What the owners sign first, then what it wraps — the order a signer checks them in
            // (device prompt, then the dapp's own payload).
            triple(&mut rows, &m.eip712, STANDARD);
            match &m.inner {
                WcSafeMessageInner::Personal(_) => {
                    rows.push((EIP191_DIGEST_LABEL.to_string(), m.data_hash))
                }
                WcSafeMessageInner::Typed(r) => typed(&mut rows, r, DAPP),
            }
        }
        SignStep::WcOrigin(_) | SignStep::WcTxFees(_) => {}
        // Not routed here by the parent.
        SignStep::RawTx(_)
        | SignStep::Delegation(_)
        | SignStep::Typed(_)
        | SignStep::SafeExec(_)
        | SignStep::SafeMessage(_)
        | SignStep::Send(_)
        | SignStep::SafeSend(_) => {}
    }
    rows
}

/// The waiting card's body for `SigningKind::WcMessage`: per-owner device prompts, and the
/// Ledger hash-mode note. A single local key signs in-process with no prompt, so it adds nothing.
pub(super) fn waiting_body<'a>(
    t: KaoTheme,
    owners: &'a [SigningOwner],
    hash_mode: bool,
) -> Element<'a, Message> {
    let mut col = column![]
        .spacing(0)
        .width(Length::Fill)
        .align_x(Alignment::Center);
    match owners {
        [] => {}
        [one] if !one.hardware => {}
        [_] => {
            col = col.push(Space::new().height(4));
            col = col.push(
                text(
                    "Confirm the message on your device — this window stays open until it's \
                     signed.",
                )
                .size(12)
                .color(t.sub)
                .font(mono()),
            );
        }
        many => {
            col = col.push(Space::new().height(4));
            col = col.push(
                text("Each owner signs the Safe message in turn:")
                    .size(12)
                    .color(t.sub)
                    .font(mono()),
            );
            col = col.push(Space::new().height(8));
            col = col.push(ceremony_owner_list(t, many));
            col = col.push(Space::new().height(6));
            col = col.push(
                text(
                    "Kao checks the combined signature against the Safe before answering the \
                     dapp.",
                )
                .size(11)
                .color(t.sub)
                .font(mono()),
            );
        }
    }
    if hash_mode {
        col = col.push(Space::new().height(6));
        col = col.push(
            text(
                "Your Ledger shows only a Domain Hash and a Message Hash — they must match the \
                 fingerprints above.",
            )
            .size(11)
            .color(t.text)
            .font(bold()),
        );
    }
    col.into()
}

// ── origin ───────────────────────────────────────────────────────────────────

/// What the origin card says, as plain text — computed apart from the widgets so the
/// host-not-name rule is a unit test rather than a screenshot.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OriginText {
    /// The host from the dapp's metadata URL, or "unknown site" — never its self-declared name.
    headline: String,
    /// The self-declared name, labelled as a claim.
    claim: String,
    insecure: bool,
    session: String,
    /// "Account 2 · Ledger" / "Treasury · Safe on Base".
    identity: String,
    network: String,
    /// "received 0:42 ago · the dapp waits 4:18 more".
    timing: String,
    /// "+2 more requests waiting".
    behind: Option<String>,
}

/// `signing`: the signature is in flight, so Kao's own deadline no longer applies.
fn origin_text(o: &WcOriginCard, now: u64, signing: bool) -> OriginText {
    let identity = match o.identity {
        WcIdentity::Safe { chain_id, .. } => format!(
            "{} · {} on {}",
            o.identity_label,
            o.identity_badge,
            crate::walletconnect::chain_label(chain_id)
        ),
        WcIdentity::Eoa { .. } => format!("{} · {}", o.identity_label, o.identity_badge),
    };
    let mut timing = format!(
        "received {} ago",
        span_label(now.saturating_sub(o.received_at))
    );
    // An unsigned review ends at the earlier of the two deadlines: Kao answers "expired" at its
    // own even when the dapp would wait longer, so that is the one to count down. Once signing,
    // only the dapp's applies — Kao never cuts a signature short.
    let kao = (!signing).then_some(o.kao_deadline);
    match (o.dapp_deadline, kao) {
        (Some(d), Some(k)) if k < d => kao_closes(&mut timing, k, now),
        (None, Some(k)) => kao_closes(&mut timing, k, now),
        (Some(d), _) if d > now => {
            let _ = write!(timing, " · the dapp waits {} more", span_label(d - now));
        }
        (Some(_), _) => timing.push_str(" · the dapp has stopped waiting"),
        (None, None) => {}
    }
    OriginText {
        headline: o.dapp.headline().to_string(),
        claim: format!("calls itself \"{}\"", o.dapp.name),
        insecure: o.dapp.insecure_scheme,
        session: format!("Session {}", o.session_ordinal),
        identity,
        network: o.net.display_name(),
        timing,
        behind: (o.waiting_behind > 0).then(|| {
            format!(
                "+{} more request{} waiting",
                o.waiting_behind,
                if o.waiting_behind == 1 { "" } else { "s" }
            )
        }),
    }
}

fn kao_closes(timing: &mut String, deadline: u64, now: u64) {
    if deadline > now {
        let _ = write!(
            timing,
            " · Kao closes this review in {}",
            span_label(deadline - now)
        );
    } else {
        timing.push_str(" · Kao is closing this review");
    }
}

/// Leads every WalletConnect review: who is asking, through which session, as which identity, on
/// which network. Informational — it signs nothing and has no fingerprints.
fn origin_card<'a>(t: KaoTheme, o: &'a WcOriginCard, signing: bool) -> Element<'a, Message> {
    let txt = origin_text(o, crate::walletconnect::now_secs(), signing);
    let mut col = column![
        text("WalletConnect request")
            .size(11)
            .color(t.sub)
            .font(bold()),
        Space::new().height(6),
        mono_box(
            t,
            text(txt.headline)
                .size(17)
                .color(t.text)
                .font(mono_bold())
                .wrapping(DAPP_WRAP)
                .into()
        ),
        Space::new().height(4),
        text(txt.claim).size(12).color(t.sub).wrapping(DAPP_WRAP),
    ]
    .spacing(0)
    .width(Length::Fill);
    if txt.insecure {
        col = col.push(Space::new().height(4));
        col = col.push(
            text("⚠ http:// — the dapp's address is not a secure connection")
                .size(12)
                .color(t.down)
                .font(bold()),
        );
    }
    col = col.push(Space::new().height(4));
    col = col.push(
        text(
            "Kao can't verify which site this is — the address and name above are what the dapp \
             says about itself.",
        )
        .size(11)
        .color(t.sub),
    );
    col = col.push(Space::new().height(8));
    col = col.push(kv(t, "Request", o.method));
    col = col.push(kv(t, "Via", txt.session));
    let mut net_row = row![
        text("Network").size(12).color(t.sub),
        Space::new().width(Length::Fill),
    ]
    .align_y(Alignment::Center)
    .padding(Padding::from([2, 0]))
    .width(Length::Fill);
    if o.unverified_network {
        net_row = net_row.push(privacy_badge(t, BadgeKind::Warning, "unverified network"));
        net_row = net_row.push(Space::new().width(6));
    }
    net_row = net_row.push(text(txt.network).size(12).color(t.text).font(mono_bold()));
    col = col.push(net_row);
    col = col.push(addr_kv(
        t,
        format!("As {}", txt.identity),
        o.identity.address(),
    ));
    col = col.push(Space::new().height(4));
    col = col.push(text(txt.timing).size(11).color(t.sub).font(mono()));
    if let Some(behind) = txt.behind {
        col = col.push(Space::new().height(2));
        col = col.push(text(behind).size(11).color(t.sub).font(bold()));
    }
    card(t, col.into())
}

// ── personal_sign ────────────────────────────────────────────────────────────

/// A `personal_sign` message: shape banner, SIWE card, then the exact text (one row per line) or
/// the exact bytes. Returned uncarded so the Safe-message panel can nest it.
fn message_body<'a>(
    t: KaoTheme,
    m: &'a MessageReview,
    show_raw: bool,
) -> iced::widget::Column<'a, Message> {
    let len = m.raw.len();
    let mut col = column![
        text("Message — personal_sign (EIP-191)")
            .size(11)
            .color(t.sub)
            .font(bold()),
        Space::new().height(2),
        text(format!(
            "Sign this message · {len} byte{}",
            if len == 1 { "" } else { "s" }
        ))
        .size(13)
        .color(t.text)
        .font(bold()),
        Space::new().height(8),
    ]
    .spacing(0)
    .width(Length::Fill);

    if let Some(b) = shape_banner(t, &m.shape) {
        col = col.push(b);
        col = col.push(Space::new().height(8));
    }
    if let Some(s) = &m.siwe {
        col = col.push(siwe_card(t, s));
        col = col.push(Space::new().height(8));
    }
    // Same caution the typed-data panel gives: a signature made for a network the user
    // added can be used there, and Kao can't see what that does.
    if let Some(b) = unverified_network_banner(t, m.net) {
        col = col.push(b);
        col = col.push(Space::new().height(8));
    }

    match &m.shape {
        MessageShape::Text { lines } => {
            col = col.push(text_lines_box(t, lines));
            col = col.push(Space::new().height(6));
            col = col.push(bytes_toggle(
                t,
                show_raw,
                "Show the exact bytes (hex)",
                "Hide the exact bytes",
            ));
            if show_raw {
                col = col.push(Space::new().height(4));
                col = col.push(hex_box(t, &m.raw));
            }
        }
        MessageShape::Binary {
            reason: BinaryReason::OpaqueHash32,
            ..
        } => match <[u8; 32]>::try_from(m.raw.as_ref()) {
            // The bytes, as the 32-byte value they are — chunk-coloured like every other hash.
            Ok(bytes) => col = col.push(hash_row(t, "The 32-byte value", B256::from(bytes))),
            Err(_) => col = col.push(hex_box(t, &m.raw)),
        },
        MessageShape::Binary { .. } => col = col.push(hex_box(t, &m.raw)),
    }

    if m.hardware && device_may_show_hex(&m.shape) {
        col = col.push(Space::new().height(6));
        col = col.push(
            text(
                "Your hardware wallet may show this message as hex rather than text — compare \
                 the bytes, not the wording.",
            )
            .size(11)
            .color(t.sub),
        );
    }
    col = col.push(Space::new().height(8));
    col = col.push(addr_kv(t, "Signing account", m.from));
    col
}

/// Hardware apps render a message as text only when it's plain ASCII; anything else reaches the
/// device screen as hex.
fn device_may_show_hex(shape: &MessageShape) -> bool {
    match shape {
        MessageShape::Text { lines } => lines.iter().any(|l| !l.is_ascii()),
        MessageShape::Binary { .. } => true,
    }
}

/// Why a message is shown as bytes rather than text. `None` for displayable text.
fn shape_banner<'a>(t: KaoTheme, shape: &MessageShape) -> Option<Element<'a, Message>> {
    let MessageShape::Binary { reason, .. } = shape else {
        return None;
    };
    Some(match reason {
        BinaryReason::OpaqueHash32 => banner(
            t,
            Tone::Danger,
            "⚠ A 32-BYTE VALUE, NOT A MESSAGE",
            "This is exactly 32 bytes that aren't text — the shape of a hash. Signing it can \
             approve something Kao can't see: a transaction, an order, or a Safe confirmation. \
             Only sign if you know exactly what produced it.",
        ),
        BinaryReason::HiddenCharacters => banner(
            t,
            Tone::Danger,
            "⚠ HIDDEN CHARACTERS",
            "This text contains invisible or direction-changing characters, so what it reads as \
             could differ from what you sign. Kao shows its exact bytes instead.",
        ),
        BinaryReason::NotUtf8 => banner(
            t,
            Tone::Info,
            "Not text",
            "This message isn't readable text, so Kao shows its exact bytes.",
        ),
        BinaryReason::TooLong => banner(
            t,
            Tone::Info,
            "Too long to show as text",
            "This message is too long to show line by line, so Kao shows its exact bytes.",
        ),
    })
}

/// The message exactly as signed, one row per line. The lines come from
/// `sanitize::exact_display_lines`, which only yields text whose every character displays as
/// signed — so nothing here is rewritten for display.
fn text_lines_box<'a>(t: KaoTheme, lines: &'a [String]) -> Element<'a, Message> {
    let mut col = column![].spacing(2).width(Length::Fill);
    for line in lines {
        col = if line.is_empty() {
            // A blank line in the message stays a blank line on screen.
            col.push(Space::new().height(14))
        } else {
            col.push(
                text(line.as_str())
                    .size(12)
                    .color(t.text)
                    .font(mono())
                    .wrapping(DAPP_WRAP),
            )
        };
    }
    mono_box(t, col.into())
}

/// Sign-In with Ethereum (EIP-4361): the parsed fields in a bordered box, then a red line for every
/// way the message disagrees with the request it arrived in.
fn siwe_card<'a>(t: KaoTheme, s: &'a SiweCheck) -> Element<'a, Message> {
    // Escaped, not stripped: a hidden character in a sign-in field should be seen, not erased.
    let f = |v: &str| field_str(v, MAX_SIWE_FIELD_CHARS);
    let mut fields = column![].spacing(2).width(Length::Fill);
    fields = fields.push(field_row(t, "domain", f(&s.siwe.domain)));
    if let Some(a) = s.siwe.address {
        fields = fields.push(field_row(t, "address", a.to_checksum(None)));
    }
    if let Some(u) = &s.siwe.uri {
        fields = fields.push(field_row(t, "uri", f(u)));
    }
    if let Some(c) = s.siwe.chain_id {
        fields = fields.push(field_row(t, "chain id", c.to_string()));
    }
    if let Some(n) = &s.siwe.nonce {
        fields = fields.push(field_row(t, "nonce", f(n)));
    }
    if let Some(i) = &s.siwe.issued_at {
        fields = fields.push(field_row(t, "issued at", f(i)));
    }
    if let Some(e) = &s.siwe.expiration {
        fields = fields.push(field_row(t, "expires", f(e)));
    }

    let mut col = column![
        text("Sign-In with Ethereum (EIP-4361)")
            .size(11)
            .color(t.sub)
            .font(bold()),
        Space::new().height(4),
        mono_box(t, fields.into()),
    ]
    .spacing(0)
    .width(Length::Fill);
    let warnings = [
        (
            s.domain_mismatch,
            "⚠ This sign-in is for a different site than the dapp says it is — someone may be \
             trying to log in as you elsewhere.",
        ),
        (
            s.address_mismatch,
            "⚠ This sign-in names a different account than the one signing it.",
        ),
        (
            s.chain_mismatch,
            "⚠ This sign-in names a different network than this request.",
        ),
    ];
    for (hit, msg) in warnings {
        if hit {
            col = col.push(Space::new().height(4));
            col = col.push(text(msg).size(11).color(t.down).font(bold()));
        }
    }
    col.into()
}

// ── typed data ───────────────────────────────────────────────────────────────

/// Dapp EIP-712 typed data from an EOA. `show_exact` is the overlay's shared calldata toggle:
/// every shortened value in full, and the decoded Safe call's details.
fn typed_panel_wc<'a>(
    t: KaoTheme,
    r: &'a TypedDataReview,
    show_exact: bool,
) -> Element<'a, Message> {
    let mut col = typed_body(t, r, show_exact);
    col = col.push(Space::new().height(8));
    col = col.push(addr_kv(t, "Signing account", r.from));
    card(t, col.into())
}

/// The fingerprints a Ledger in hash mode puts on its screen — the only thing it shows for typed
/// data — rendered inside the panel (not just in the collapsible ERC-8213 section), so the values
/// the user must compare are on screen from the moment the review opens. Empty for every other
/// signer.
fn device_check_rows(r: &TypedDataReview) -> Vec<(String, B256)> {
    if !r.hash_mode_device {
        return Vec::new();
    }
    let d = &r.checked.digests;
    vec![
        (DOMAIN_HASH_LABEL.to_string(), d.domain_hash),
        (MESSAGE_HASH_LABEL.to_string(), d.message_hash),
    ]
}

/// Typed data uncarded: headline, banners (device, owner confirmation and the call it confirms,
/// allowance, warnings, network), the domain, then every field of the message — each shortened
/// value in full when `show_exact`.
fn typed_body<'a>(
    t: KaoTheme,
    r: &'a TypedDataReview,
    show_exact: bool,
) -> iced::widget::Column<'a, Message> {
    let c = &r.checked;
    let mut col = column![
        text("Typed data — EIP-712")
            .size(11)
            .color(t.sub)
            .font(bold()),
        Space::new().height(2),
        text("Sign this typed data")
            .size(13)
            .color(t.text)
            .font(bold()),
        Space::new().height(8),
    ]
    .spacing(0)
    .width(Length::Fill);

    let device = device_check_rows(r);
    if !device.is_empty() {
        col = col.push(hash_mode_banner(t, device));
        col = col.push(Space::new().height(8));
    }
    if let Some(b) = owner_confirmation_banner(t, &c.kind, r.safe_label.as_deref()) {
        col = col.push(b);
        col = col.push(Space::new().height(8));
    }
    if let TypedKind::SafeTx { to, operation, .. } = &c.kind {
        // The same claim a Safe transaction step makes about this byte, canonical MultiSend
        // libraries named — a delegatecall's danger is whose code runs.
        if *operation != 0 {
            col = col.push(operation_banner(t, *operation, *to));
            col = col.push(Space::new().height(8));
        }
        // The call this confirmation would have the Safe make, decoded from the signed `data`.
        if let Some(leg) = &r.inner_leg {
            col = col.push(
                text("The Safe would execute")
                    .size(11)
                    .color(t.sub)
                    .font(bold()),
            );
            col = col.push(Space::new().height(4));
            col = col.push(leg_card(t, leg, show_exact));
            col = col.push(Space::new().height(8));
        }
    }
    if let TypedKind::Allowance(g) = &c.kind {
        col = col.push(allowance_banner(t, g));
        col = col.push(Space::new().height(8));
    }
    for w in &c.warnings {
        col = col.push(warning_line(t, *w));
        col = col.push(Space::new().height(6));
    }
    if let Some(b) = unverified_network_banner(t, r.net) {
        col = col.push(b);
        col = col.push(Space::new().height(8));
    }

    col = col.push(text("Domain").size(11).color(t.sub).font(bold()));
    col = col.push(Space::new().height(4));
    col = col.push(domain_box(
        t,
        &c.domain,
        r.safe_label.as_deref(),
        show_exact,
    ));
    col = col.push(Space::new().height(8));
    col = col.push(text("Message").size(11).color(t.sub).font(bold()));
    col = col.push(Space::new().height(4));
    col = col.push(typed_rows_box(
        t,
        &c.primary_type,
        &c.model,
        &c.exact,
        show_exact,
    ));
    if !c.exact.is_empty() || c.domain.shortened() {
        col = col.push(Space::new().height(4));
        col = col.push(bytes_toggle(
            t,
            show_exact,
            "Show exact values",
            "Hide exact values",
        ));
    }
    col
}

/// Ledger hash mode: the device shows only these two hashes, so they lead the panel.
fn hash_mode_banner<'a>(t: KaoTheme, rows: Vec<(String, B256)>) -> Element<'a, Message> {
    let mut col = column![
        text(
            "Your Ledger shows only a Domain Hash and a Message Hash — compare them with the \
             fingerprints below."
        )
        .size(12)
        .color(t.text)
        .font(bold()),
        Space::new().height(6),
    ]
    .spacing(0)
    .width(Length::Fill);
    for (label, hash) in rows {
        col = col.push(hash_row(t, label, hash));
    }
    tinted_box(t, t.a1, col.into())
}

/// Signing `SafeTx` / `SafeMessage` typed data *is* a Safe owner confirmation — the dapp is asking
/// this key to approve something on a Safe's behalf. Red, and specific about what.
fn owner_confirmation_banner<'a>(
    t: KaoTheme,
    kind: &'a TypedKind,
    safe_label: Option<&'a str>,
) -> Option<Element<'a, Message>> {
    let safe_named = |safe: &Option<Address>| -> String {
        match (safe_label, safe) {
            (Some(l), _) => format!("your Safe “{l}”"),
            (None, Some(_)) => "the Safe below".to_string(),
            (None, None) => "a Safe (the domain names none)".to_string(),
        }
    };
    let col = match kind {
        TypedKind::SafeTx {
            safe,
            to,
            value,
            operation,
            nonce,
            safe_tx_gas,
            base_gas,
            gas_price,
            gas_token,
            refund_receiver,
            ..
        } => {
            let mut col = column![
                text("⚠ THIS APPROVES A SAFE TRANSACTION AS AN OWNER")
                    .size(12)
                    .color(t.down)
                    .font(bold()),
                Space::new().height(3),
                text(format!(
                    "Your signature is an owner confirmation for {}. Once enough owners sign, \
                     anyone can execute it.",
                    safe_named(safe)
                ))
                .size(11)
                .color(t.text),
                Space::new().height(6),
            ]
            .spacing(0)
            .width(Length::Fill);
            if let Some(s) = safe {
                col = col.push(addr_kv(t, "Safe", *s));
            }
            col = col.push(addr_kv(t, "Calls", *to));
            col = col.push(kv(t, "Value", format!("{} ETH", format_eth(*value))));
            col = col.push(kv(
                t,
                "Operation",
                match operation {
                    0 => "0 (call)".to_string(),
                    1 => "1 (DELEGATECALL)".to_string(),
                    other => format!("{other} (unknown)"),
                },
            ));
            col = col.push(kv(t, "Safe nonce", nonce.to_string()));
            let fees = SafeTxFees {
                safe_tx_gas: *safe_tx_gas,
                base_gas: *base_gas,
                gas_price: *gas_price,
                gas_token: *gas_token,
                refund_receiver: *refund_receiver,
            };
            if fees.any_set() {
                col = col.push(Space::new().height(4));
                col = col.push(safe_tx_fee_rows(t, fees));
            }
            col
        }
        TypedKind::SafeMessage { safe } => {
            let mut col = column![
                text("⚠ THIS SIGNS A SAFE MESSAGE AS AN OWNER")
                    .size(12)
                    .color(t.down)
                    .font(bold()),
                Space::new().height(3),
                text(format!(
                    "Your signature counts toward an EIP-1271 signature of {} — it can authorize \
                     anything the Safe can sign: logins, off-chain orders, permits.",
                    safe_named(safe)
                ))
                .size(11)
                .color(t.text),
            ]
            .spacing(0)
            .width(Length::Fill);
            if let Some(s) = safe {
                col = col.push(Space::new().height(6));
                col = col.push(addr_kv(t, "Safe", *s));
            }
            col
        }
        TypedKind::Generic | TypedKind::Allowance(_) => return None,
    };
    Some(tinted_box(t, t.down, col.into()))
}

/// A SafeTx's gas and refund fields. Kao's own Safe transactions leave every one at zero; a
/// dapp's needn't, and `gasPrice` > 0 makes the Safe pay its executor out of its own funds.
#[derive(Debug, Clone, Copy)]
struct SafeTxFees {
    safe_tx_gas: U256,
    base_gas: U256,
    gas_price: U256,
    gas_token: Address,
    refund_receiver: Address,
}

impl SafeTxFees {
    fn any_set(&self) -> bool {
        !self.safe_tx_gas.is_zero()
            || !self.base_gas.is_zero()
            || !self.gas_price.is_zero()
            || !self.gas_token.is_zero()
            || !self.refund_receiver.is_zero()
    }

    /// What the non-zero fields do, in the user's terms — one red line each.
    fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.gas_price.is_zero() {
            out.push(format!(
                "⚠ This pays a gas refund out of the Safe: when it executes, the Safe sends up to \
                 gasPrice × (gas used + baseGas) in {} to {}. A dapp can set these to drain the \
                 Safe.",
                if self.gas_token.is_zero() {
                    "ETH"
                } else {
                    "the gasToken above"
                },
                if self.refund_receiver.is_zero() {
                    "whoever executes it"
                } else {
                    "the refundReceiver above"
                },
            ));
        } else {
            out.push(
                "⚠ Gas or refund fields are set — Kao's own Safe transactions leave them at 0. \
                 With gasPrice 0 no refund is paid; only sign if you expected these values."
                    .to_string(),
            );
        }
        if !self.safe_tx_gas.is_zero() {
            out.push(
                "⚠ With safeTxGas set, this can be executed even if its call fails — the Safe's \
                 nonce is used up either way."
                    .to_string(),
            );
        }
        out
    }
}

/// The non-zero SafeTx gas / refund fields and what they do.
fn safe_tx_fee_rows<'a>(t: KaoTheme, f: SafeTxFees) -> Element<'a, Message> {
    let mut col = column![].spacing(0).width(Length::Fill);
    for (label, v) in [
        ("safeTxGas", f.safe_tx_gas),
        ("baseGas", f.base_gas),
        ("gasPrice", f.gas_price),
    ] {
        if !v.is_zero() {
            col = col.push(kv(t, label, v.to_string()));
        }
    }
    if !f.gas_token.is_zero() {
        col = col.push(addr_kv(t, "gasToken", f.gas_token));
    }
    if !f.refund_receiver.is_zero() {
        col = col.push(addr_kv(t, "refundReceiver", f.refund_receiver));
    }
    for w in f.warnings() {
        col = col.push(Space::new().height(4));
        col = col.push(text(w).size(11).color(t.down).font(bold()));
    }
    col.into()
}

/// A timestamp a dapp signed, as a date — or as what it means when it is no date at all.
fn time_label(unix_secs: u64) -> String {
    if unix_secs > MAX_SHOWN_TIMESTAMP {
        "no practical limit".to_string()
    } else {
        format_iso_utc(unix_secs)
    }
}

/// A permit (EIP-2612 / Permit2): who may move which tokens, how much, until when. An unlimited
/// amount is called out in red — it's the drainer pattern — and so is a Permit2 allowance usable
/// the moment it lands (`expiration` 0).
fn allowance_banner<'a>(t: KaoTheme, g: &'a AllowanceGrant) -> Element<'a, Message> {
    let tone = if g.unlimited { t.down } else { caution_color() };
    let mut col = column![
        text(format!("⚠ TOKEN ALLOWANCE — {}", g.kind))
            .size(12)
            .color(tone)
            .font(bold()),
        Space::new().height(3),
        text(
            "Signing this lets the spender below move your tokens without asking you again — no \
             transaction, no further prompt."
        )
        .size(11)
        .color(t.text),
        Space::new().height(6),
        addr_kv(t, "Spender", g.spender),
    ]
    .spacing(0)
    .width(Length::Fill);
    for (token, amount) in &g.tokens {
        col = col.push(addr_kv(t, "Token", *token));
        col = col.push(kv(
            t,
            "Amount",
            if g.unlimited || *amount == U256::MAX {
                "UNLIMITED".to_string()
            } else {
                format!("{amount} (raw units)")
            },
        ));
    }
    col = col.push(kv(
        t,
        "Expires",
        match g.expires {
            AllowanceExpiry::At(ts) => time_label(ts),
            AllowanceExpiry::Never => "never".to_string(),
            AllowanceExpiry::SubmittingBlock => "in the block it's submitted in".to_string(),
        },
    ));
    if let Some(d) = g.signature_deadline {
        col = col.push(kv(t, "Signature usable until", time_label(d)));
    }
    if g.expires == AllowanceExpiry::SubmittingBlock {
        col = col.push(Space::new().height(4));
        col = col.push(
            text(
                "Usable immediately: expiration 0 makes this allowance valid in the block the \
                 permit is submitted in — enough for the spender to take the tokens in that same \
                 transaction.",
            )
            .size(11)
            .color(t.down)
            .font(bold()),
        );
    }
    if g.unlimited {
        col = col.push(Space::new().height(4));
        col = col.push(
            text("An unlimited allowance stays valid until you revoke it.")
                .size(11)
                .color(t.down)
                .font(bold()),
        );
    }
    tinted_box(t, tone, col.into())
}

fn warning_line<'a>(t: KaoTheme, w: TypedWarning) -> Element<'a, Message> {
    let (msg, color) = match w {
        TypedWarning::NoChainBinding => (
            "⚠ This signature names no network (no chainId in its domain), so it could be \
             replayed on another chain.",
            caution_color(),
        ),
        TypedWarning::PermitOwnerNotSigner => (
            "⚠ The permit names a different owner than the account signing it.",
            t.down,
        ),
        TypedWarning::LongValuesSummarized => (
            "Long values are shortened below — “Show exact values” shows every one in full.",
            t.sub,
        ),
    };
    text(msg).size(11).color(color).font(bold()).into()
}

/// The EIP-712 domain: what the signature is scoped to. A `verifyingContract` that is one of the
/// user's own Safes is named.
fn domain_box<'a>(
    t: KaoTheme,
    d: &'a DomainSummary,
    safe_label: Option<&'a str>,
    show_exact: bool,
) -> Element<'a, Message> {
    let mut col = column![].spacing(4).width(Length::Fill);
    if let Some(n) = &d.name {
        col = col.push(field_row(t, "name", field_str(n, MAX_FIELD_VALUE_CHARS)));
        if show_exact && let Some(full) = &d.exact_name {
            col = col.push(exact_text(t, full));
        }
    }
    if let Some(v) = &d.version {
        col = col.push(field_row(t, "version", field_str(v, MAX_FIELD_VALUE_CHARS)));
        if show_exact && let Some(full) = &d.exact_version {
            col = col.push(exact_text(t, full));
        }
    }
    col = col.push(field_row(
        t,
        "chainId",
        match d.chain_id {
            Some(id) => format!("{id} ({})", crate::walletconnect::chain_label(id)),
            None => "none — not tied to a network".to_string(),
        },
    ));
    if let Some(vc) = d.verifying_contract {
        col = col.push(
            column![
                text("verifyingContract").size(11).color(t.sub).font(mono()),
                colored_address(t, vc),
            ]
            .spacing(1)
            .width(Length::Fill),
        );
        if let Some(l) = safe_label {
            col = col.push(
                text(format!("your Safe “{l}”"))
                    .size(11)
                    .color(t.text)
                    .font(bold())
                    .wrapping(DAPP_WRAP),
            );
        }
    }
    if let Some(s) = d.salt {
        col = col.push(field_row(t, "salt", format!("{s}")));
    }
    mono_box(t, col.into())
}

/// The primary type, then every field of the message flattened to dotted paths, in a bordered mono
/// box (type and field names are the dapp's too). The rows were walked from the same coerced value
/// that is hashed and signed (`typed::typed_model`). With `show_exact`, each shortened row is
/// followed by its full value from `exact`: bytes as a hex dump, a string whole.
fn typed_rows_box<'a>(
    t: KaoTheme,
    primary_type: &str,
    model: &'a TypedDataModel,
    exact: &'a [(usize, ExactValue)],
    show_exact: bool,
) -> Element<'a, Message> {
    let mut col = column![field_row(
        t,
        "primaryType",
        field_str(primary_type, MAX_FIELD_LABEL_CHARS)
    )]
    .spacing(4)
    .width(Length::Fill);
    if let Some(h) = &model.headline {
        col = col.push(
            text(field_str(h, MAX_FIELD_VALUE_CHARS))
                .size(12)
                .color(t.text)
                .font(mono_bold())
                .wrapping(DAPP_WRAP),
        );
    }
    if model.rows.is_empty() {
        col = col.push(text("(no fields)").size(11).color(t.sub).font(mono()));
    }
    for (i, TypedRow { label, value }) in model.rows.iter().enumerate() {
        let label = field_str(label, MAX_FIELD_LABEL_CHARS);
        col = match value {
            TypedValue::Text(v) => {
                col.push(field_row(t, label, field_str(v, MAX_FIELD_VALUE_CHARS)))
            }
            TypedValue::Addr(a) => col.push(
                column![
                    text(label)
                        .size(11)
                        .color(t.sub)
                        .font(mono())
                        .wrapping(DAPP_WRAP),
                    colored_address(t, *a),
                ]
                .spacing(1)
                .width(Length::Fill),
            ),
        };
        if show_exact && let Some((_, full)) = exact.iter().find(|(row, _)| *row == i) {
            col = col.push(exact_value(t, full));
        }
    }
    mono_box(t, col.into())
}

/// A shortened typed value in full, under its row: bytes as an offset hex dump, a string whole
/// (escaped as its row is — `escape_unsafe_display` already ran at admission).
fn exact_value<'a>(t: KaoTheme, v: &'a ExactValue) -> Element<'a, Message> {
    match v {
        ExactValue::Bytes(b) => exact_block(
            t,
            format!("exact value · {} bytes", b.len()),
            text(hex_dump(b)),
        ),
        ExactValue::Text(s) => exact_text(t, s),
    }
}

/// A shortened (already escaped) string in full, under its row.
fn exact_text<'a>(t: KaoTheme, s: &'a str) -> Element<'a, Message> {
    exact_block(
        t,
        format!("exact value · {} chars", s.chars().count()),
        text(s),
    )
}

fn exact_block<'a>(
    t: KaoTheme,
    what: String,
    body: iced::widget::Text<'a>,
) -> Element<'a, Message> {
    container(
        column![
            text(what).size(10).color(t.sub).font(mono()),
            body.size(11).color(t.text).font(mono()).wrapping(DAPP_WRAP),
        ]
        .spacing(2)
        .width(Length::Fill),
    )
    .padding(Padding::from([4, 0]).left(10.0))
    .width(Length::Fill)
    .into()
}

/// A dapp string for display in a box: unsafe characters become visible `\u{…}` escapes (so a
/// bidi override or zero-width space can't hide in plain sight), then clamped. Idempotent, so the
/// already-escaped typed rows pass through unchanged.
fn field_str(s: &str, max: usize) -> String {
    sanitize_display(&escape_unsafe_display(s), max).into_owned()
}

// ── Safe message ─────────────────────────────────────────────────────────────

/// A dapp message signed by a Safe (EIP-1271): the Safe and the owners that will sign, the inner
/// message exactly as the EOA panels show it, and the hash each owner signs.
fn safe_message_panel_wc<'a>(
    t: KaoTheme,
    m: &'a WcSafeMessageReview,
    show_raw: bool,
) -> Element<'a, Message> {
    let mut col = column![
        text("Safe message — EIP-1271")
            .size(11)
            .color(t.sub)
            .font(bold()),
        Space::new().height(2),
        text(format!(
            "{}-of-{} owners must sign · Kao signs with {}",
            m.threshold,
            m.owner_count,
            m.signers.len()
        ))
        .size(13)
        .color(t.text)
        .font(bold()),
        Space::new().height(8),
        addr_kv(t, "Safe", m.safe),
        kv(t, "Network", m.chain.display_name()),
        Space::new().height(6),
        text("Signed by").size(11).color(t.sub).font(bold()),
        Space::new().height(4),
        ceremony_owner_list(t, &m.signers),
        Space::new().height(10),
    ]
    .spacing(0)
    .width(Length::Fill);

    let (inner, inner_label) = match &m.inner {
        WcSafeMessageInner::Personal(mr) => (
            message_body(t, mr, show_raw),
            "The message's digest (EIP-191)",
        ),
        WcSafeMessageInner::Typed(tr) => (typed_body(t, tr, show_raw), "The dapp's EIP-712 digest"),
    };
    col = col.push(
        text("What the Safe signs")
            .size(11)
            .color(t.sub)
            .font(bold()),
    );
    col = col.push(Space::new().height(4));
    col = col.push(
        container(inner)
            .padding(Padding::from([10, 12]))
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(iced::Background::Color(t.card)),
                border: iced::Border {
                    color: t.border,
                    width: 1.0,
                    radius: iced::border::Radius::from(10),
                },
                text_color: Some(t.text),
                ..container::Style::default()
            }),
    );
    col = col.push(Space::new().height(8));
    col = col.push(hash_row(t, inner_label, m.data_hash));
    col = col.push(hash_row(
        t,
        "Each owner signs (SafeMessage hash)",
        m.message_hash,
    ));
    col = col.push(Space::new().height(6));
    col = col.push(
        text(
            "The dapp receives the owners' signatures packed together. Kao checks them against \
             the Safe on-chain before answering.",
        )
        .size(11)
        .color(t.sub),
    );
    card(t, col.into())
}

// ── transaction fees ─────────────────────────────────────────────────────────

/// The fee side of a dapp `eth_sendTransaction` from an EOA: the pinned quote (the numbers the
/// broadcast uses), how the gas limit was chosen, and the worst case against the balance. What the
/// dapp asked for that Kao ignored is the review's note, shown once above every step.
///
/// Folded (`show_details` false) it keeps the maximum fee in its header, every warning banner and
/// the shortfall line; the nonce, gas and fee-cap breakdown unfolds under the header's toggle.
fn fees_card<'a>(t: KaoTheme, f: &'a WcTxFeesReview, show_details: bool) -> Element<'a, Message> {
    use crate::ui::wallet_dashboard::sim_view::format_gas;
    let q = &f.quote;
    let sym = crate::walletconnect::native_symbol(q.plan.chain.chain_id());
    // On the OP stack the cap isn't the whole cost: the L1 data fee is charged on top (the
    // Transaction Builder's caveat, word for word). The folded summary says so in brief.
    let l1_caveat = super::super::tx_builder::l1_data_fee_caveat(q.plan.chain);
    let summary = format!(
        "max {} {sym}{}",
        format_eth(q.eth_cost_wei),
        if l1_caveat.is_some() { " + L1 fee" } else { "" }
    );
    let summary = text(summary).size(12).color(t.text).font(mono_bold());
    let header = super::fee_details_toggle(t, "Network fee", summary.into(), show_details);
    let mut col = column![header].spacing(0).width(Length::Fill);
    // The space before the next block, after whatever was pushed last. Each block pushes its own
    // leading gap, so a folded card with nothing under its header ends at the header.
    let mut gap = 6.0;
    if f.sim_reverted {
        col = col.push(Space::new().height(gap));
        col = col.push(banner(
            t,
            Tone::Danger,
            "⚠ SIMULATION REVERTED",
            "Kao's simulation of this transaction reverted. It will most likely fail on-chain and \
             still cost the gas it burns.",
        ));
        gap = 8.0;
    }
    if let Some(why) = &f.estimate_failed {
        col = col.push(Space::new().height(gap));
        col = col.push(banner(
            t,
            Tone::Danger,
            "⚠ KAO'S NODE EXPECTS THIS TO FAIL",
            format!(
                "Kao's node couldn't estimate this transaction's gas: {why}. The gas limit is the \
                 dapp's own. If the transaction fails on-chain it still costs the gas it burns."
            ),
        ));
        gap = 8.0;
    }
    // `unverified_network` is the coordinator's verdict; the quote's own chain is the fallback
    // proof, so neither alone can hide the banner.
    if f.unverified_network || q.plan.chain.is_custom() {
        col = col.push(Space::new().height(gap));
        col = col.push(network_caution(t, q.plan.chain));
        gap = 8.0;
    }
    if show_details {
        col = col.push(Space::new().height(gap));
        col = col.push(kv(t, "Nonce", q.nonce.to_string()));
        col = col.push(kv(t, "Gas limit", format_gas(q.gas_limit)));
        col = col.push(
            text(gas_note_text(f.gas_note))
                .size(11)
                .color(t.sub)
                .font(mono()),
        );
        col = col.push(kv(
            t,
            "Max fee per gas",
            format!("{} gwei", format_gwei(q.max_fee_per_gas)),
        ));
        col = col.push(kv(
            t,
            "Priority tip",
            format!("{} gwei", format_gwei(q.max_priority_fee_per_gas)),
        ));
        col = col.push(kv(
            t,
            "Max network fee",
            format!("{} {sym}", format_eth(q.eth_cost_wei)),
        ));
        col = col.push(kv(
            t,
            "Max total (value + fee)",
            format!("{} {sym}", format_eth(f.max_total_wei)),
        ));
        col = col.push(kv(
            t,
            "Your balance",
            match f.balance_wei {
                Some(b) => format!("{} {sym}", format_eth(b)),
                None => "unknown".to_string(),
            },
        ));
        gap = 4.0;
    }
    // A shortfall is a warning, not detail: it stays up while the breakdown is folded.
    if f.balance_wei.is_some_and(|b| b < f.max_total_wei) {
        col = col.push(Space::new().height(gap));
        col = col.push(
            text(format!(
                "Not enough {sym} to cover the value plus the maximum network fee."
            ))
            .size(11)
            .color(t.down)
            .font(bold()),
        );
    }
    if show_details {
        col = col.push(Space::new().height(6));
        let cost_note = match l1_caveat {
            Some(caveat) => format!(
                "Unused gas is refunded, but the maximum network fee {caveat} — it is charged on \
                 top of the figures above."
            ),
            None => "Unused gas is refunded — you pay at most the maximum network fee.".to_string(),
        };
        col = col.push(text(cost_note).size(11).color(t.sub));
    }
    card(t, col.into())
}

/// How the pinned gas limit was chosen, in the user's terms.
fn gas_note_text(n: GasNote) -> String {
    use crate::ui::wallet_dashboard::sim_view::format_gas;
    match n {
        GasNote::Estimated => "Kao's estimate".to_string(),
        GasNote::Buffered { estimate } => {
            format!("Kao's estimate ({}) + 20% headroom", format_gas(estimate))
        }
        GasNote::DappHonoured { estimate, dapp } => format!(
            "the dapp's limit ({}); Kao estimated {}",
            format_gas(dapp),
            format_gas(estimate)
        ),
        GasNote::DappCapped { estimate, dapp } => format!(
            "capped — the dapp asked for {}; Kao estimated {}",
            format_gas(dapp),
            format_gas(estimate)
        ),
        GasNote::NetworkCapped { estimate, dapp } => {
            let asked = match dapp {
                Some(d) if d > crate::walletconnect::request::MAX_TX_GAS => {
                    format!("the dapp asked for {}; ", format_gas(d))
                }
                _ => String::new(),
            };
            format!(
                "held at the network's per-transaction maximum — {asked}Kao estimated {}",
                format_gas(estimate)
            )
        }
        GasNote::DappUnestimated { dapp } => format!(
            "the dapp's limit ({}) — Kao's node couldn't estimate this call",
            format_gas(dapp)
        ),
        GasNote::AsSigned => "as signed into this transaction".to_string(),
    }
}

/// A custom network: reached through the user's own RPC with no light-client verification, no
/// clear-signing and no simulation. `None` on a built-in chain.
fn unverified_network_banner<'a>(t: KaoTheme, net: NetworkId) -> Option<Element<'a, Message>> {
    net.is_custom().then(|| network_caution(t, net))
}

fn network_caution<'a>(t: KaoTheme, net: NetworkId) -> Element<'a, Message> {
    banner(
        t,
        Tone::Caution,
        "⚠ UNVERIFIED NETWORK",
        format!(
            "{} (chain id {}) is a network you added. Kao reaches it through your own RPC \
             without verification, and can't decode or simulate what happens there.",
            net.display_name(),
            net.chain_id()
        ),
    )
}

// ── shared bits ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tone {
    Danger,
    Caution,
    Info,
}

/// A titled banner in the style of the parent's operation banner: a bordered box whose border and
/// title carry the tone.
fn banner<'a>(
    t: KaoTheme,
    tone: Tone,
    title: impl Into<String>,
    body: impl Into<String>,
) -> Element<'a, Message> {
    let color = match tone {
        Tone::Danger => t.down,
        Tone::Caution => caution_color(),
        Tone::Info => t.sub,
    };
    let col = column![
        text(title.into()).size(12).color(color).font(bold()),
        Space::new().height(3),
        text(body.into()).size(11).color(t.text),
    ]
    .spacing(0)
    .width(Length::Fill);
    tinted_box(t, color, col.into())
}

fn tinted_box<'a>(
    t: KaoTheme,
    color: iced::Color,
    content: Element<'a, Message>,
) -> Element<'a, Message> {
    container(content)
        .padding(10)
        .width(Length::Fill)
        .style(move |_: &iced::Theme| container::Style {
            background: Some(t.card_alt.into()),
            border: iced::Border {
                color,
                width: 1.0,
                radius: 8.0.into(),
            },
            ..Default::default()
        })
        .into()
}

/// One `label` / `value` pair inside a mono box — the label above, so a long value wraps under it
/// instead of being clipped at the panel edge.
fn field_row<'a>(
    t: KaoTheme,
    label: impl Into<String>,
    value: impl Into<String>,
) -> Element<'a, Message> {
    column![
        text(label.into())
            .size(11)
            .color(t.sub)
            .font(mono())
            .wrapping(DAPP_WRAP),
        text(value.into())
            .size(12)
            .color(t.text)
            .font(mono())
            .wrapping(DAPP_WRAP),
    ]
    .spacing(1)
    .width(Length::Fill)
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::walletconnect::{CheckedTyped, DappLabel};
    use alloy::primitives::address;

    fn digests(a: u8, b: u8) -> Eip712Digests {
        Eip712Digests::from_parts(B256::repeat_byte(a), B256::repeat_byte(b))
    }

    fn dapp(name: &str, host: Option<&str>) -> DappLabel {
        DappLabel {
            name: name.to_string(),
            host: host.map(str::to_string),
            url: host.map(|h| format!("https://{h}")).unwrap_or_default(),
            description: String::new(),
            insecure_scheme: false,
        }
    }

    fn origin(name: &str, host: Option<&str>) -> WcOriginCard {
        WcOriginCard {
            dapp: dapp(name, host),
            session_ordinal: 3,
            identity: WcIdentity::Eoa {
                address: Address::repeat_byte(0x11),
            },
            identity_label: "Account 2".into(),
            identity_badge: "Ledger",
            method: "Sign message",
            net: NetworkId::Builtin(Chain::Mainnet),
            unverified_network: false,
            received_at: 1_000,
            dapp_deadline: Some(1_300),
            kao_deadline: 1_000 + 3_600,
            waiting_behind: 2,
        }
    }

    fn typed_review(hash_mode: bool, d: Eip712Digests) -> TypedDataReview {
        TypedDataReview {
            from: Address::repeat_byte(0x11),
            net: NetworkId::Builtin(Chain::Mainnet),
            checked: CheckedTyped {
                primary_type: "Mail".into(),
                digests: d,
                domain: DomainSummary {
                    name: Some("Ether Mail".into()),
                    version: Some("1".into()),
                    chain_id: Some(1),
                    verifying_contract: Some(Address::repeat_byte(0xCC)),
                    salt: None,
                    exact_name: None,
                    exact_version: None,
                },
                model: TypedDataModel {
                    type_name: "Mail".into(),
                    headline: None,
                    rows: Vec::new(),
                },
                exact: Vec::new(),
                kind: TypedKind::Generic,
                warnings: Vec::new(),
            },
            hash_mode_device: hash_mode,
            safe_label: None,
            inner_leg: None,
        }
    }

    fn message_review(raw: &'static [u8], hash: B256) -> MessageReview {
        MessageReview {
            from: Address::repeat_byte(0x11),
            net: NetworkId::Builtin(Chain::Mainnet),
            raw: Bytes::from_static(raw),
            shape: MessageShape::Text {
                lines: vec!["hello".into()],
            },
            eip191_hash: hash,
            siwe: None,
            hardware: false,
        }
    }

    fn safe_message(inner: WcSafeMessageInner, data_hash: B256) -> WcSafeMessageReview {
        WcSafeMessageReview {
            inner,
            safe: Address::repeat_byte(0x5A),
            chain: Chain::Base,
            threshold: 1,
            owner_count: 2,
            signers: vec![SigningOwner {
                label: "Hot key".into(),
                address: Address::repeat_byte(0x22),
                hardware: false,
            }],
            data_hash,
            message_hash: B256::repeat_byte(0xD1),
            eip712: digests(0xD2, 0xD3),
        }
    }

    /// Every signing WC step carries exactly its fingerprints, under the exact labels the
    /// fingerprints section prints; the informational steps carry none.
    #[test]
    fn erc8213_rows_for_wc_steps() {
        // personal_sign: the EIP-191 digest, under a label that is NOT an ERC-8213 label.
        let h = B256::repeat_byte(0x91);
        assert_eq!(
            erc8213_rows(&SignStep::WcMessage(message_review(b"hello", h))),
            vec![("Message Digest (EIP-191)".to_string(), h)],
        );

        // Typed data: the standard triple, digest first.
        let d = digests(0xA1, 0xA2);
        assert_eq!(
            erc8213_rows(&SignStep::WcTyped(typed_review(false, d))),
            vec![
                ("EIP-712 Digest".to_string(), d.digest),
                ("Domain Hash".to_string(), d.domain_hash),
                ("Message Hash".to_string(), d.message_hash),
            ],
        );

        // Safe message wrapping personal_sign: SafeMessage triple, then the inner EIP-191 digest.
        let data_hash = B256::repeat_byte(0xE1);
        let m = safe_message(
            WcSafeMessageInner::Personal(message_review(b"hello", data_hash)),
            data_hash,
        );
        let outer = m.eip712;
        assert_eq!(
            erc8213_rows(&SignStep::WcSafeMessage(m)),
            vec![
                ("EIP-712 Digest".to_string(), outer.digest),
                ("Domain Hash".to_string(), outer.domain_hash),
                ("Message Hash".to_string(), outer.message_hash),
                ("Message Digest (EIP-191)".to_string(), data_hash),
            ],
        );

        // Safe message wrapping typed data: SafeMessage triple, then the dapp's own triple under
        // labels that can't be confused with the owners'.
        let inner = digests(0xB1, 0xB2);
        let m = safe_message(
            WcSafeMessageInner::Typed(typed_review(false, inner)),
            inner.digest,
        );
        let outer = m.eip712;
        assert_eq!(
            erc8213_rows(&SignStep::WcSafeMessage(m)),
            vec![
                ("EIP-712 Digest".to_string(), outer.digest),
                ("Domain Hash".to_string(), outer.domain_hash),
                ("Message Hash".to_string(), outer.message_hash),
                ("Dapp EIP-712 Digest".to_string(), inner.digest),
                ("Dapp Domain Hash".to_string(), inner.domain_hash),
                ("Dapp Message Hash".to_string(), inner.message_hash),
            ],
        );

        // The origin card signs nothing.
        assert!(erc8213_rows(&SignStep::WcOrigin(origin("x", Some("x.example")))).is_empty());

        // Through the parent's dispatcher too — what the overlay actually renders.
        assert_eq!(
            super::super::erc8213_rows(&SignStep::WcTyped(typed_review(false, d))),
            erc8213_rows(&SignStep::WcTyped(typed_review(false, d))),
        );
    }

    /// A Ledger in hash mode shows only the Domain Hash and Message Hash, so the typed panel
    /// carries exactly those two, always expanded — the same values (and labels) as the
    /// fingerprints section, which the coordinator also opens for this review.
    #[test]
    fn ledger_typed_review_expands_fingerprints() {
        let d = digests(0xA1, 0xA2);
        let ledger = typed_review(true, d);
        let shown = device_check_rows(&ledger);
        assert_eq!(
            shown,
            vec![
                (DOMAIN_HASH_LABEL.to_string(), d.domain_hash),
                (MESSAGE_HASH_LABEL.to_string(), d.message_hash),
            ],
        );
        let fingerprints = erc8213_rows(&SignStep::WcTyped(ledger));
        for row in &shown {
            assert!(
                fingerprints.contains(row),
                "the device check must match a fingerprint row exactly: {row:?}"
            );
        }
        // A key that signs the full digest needs no device comparison block.
        assert!(device_check_rows(&typed_review(false, d)).is_empty());
    }

    /// The origin card leads with the host the dapp's URL names; its self-declared name only
    /// ever appears labelled as a claim.
    #[test]
    fn origin_card_shows_host_not_name() {
        let o = origin("MetaMask Official", Some("evil.example"));
        let txt = origin_text(&o, 1_042, false);
        assert_eq!(txt.headline, "evil.example");
        assert!(!txt.headline.contains("MetaMask"));
        assert_eq!(txt.claim, "calls itself \"MetaMask Official\"");
        assert_eq!(txt.session, "Session 3");
        assert_eq!(txt.identity, "Account 2 · Ledger");
        assert_eq!(txt.timing, "received 0:42 ago · the dapp waits 4:18 more");
        assert_eq!(txt.behind.as_deref(), Some("+2 more requests waiting"));

        // No usable host: say so — never fall back to the name.
        let anon = origin_text(&origin("Uniswap", None), 1_000, false);
        assert_eq!(anon.headline, "unknown site");

        // What actually renders: the host comes before the claim, and the name never appears
        // outside it.
        let theme = KaoTheme::for_kind(crate::ui::kao_theme::ThemeKind::Mint);
        let texts = super::super::super::test_support::texts(origin_card(theme, &o, false));
        let host_at = texts.iter().position(|s| s == "evil.example");
        let claim_at = texts
            .iter()
            .position(|s| s == "calls itself \"MetaMask Official\"");
        assert!(host_at.is_some() && claim_at.is_some(), "{texts:?}");
        assert!(host_at < claim_at, "host must lead: {texts:?}");
        assert_eq!(
            texts.iter().filter(|s| s.contains("MetaMask")).count(),
            1,
            "the name appears only as the claim: {texts:?}"
        );
    }

    /// With no dapp expiry, an open review counts down Kao's own deadline — the one that closes
    /// it. Once signing, Kao's deadline no longer applies and nothing is counted.
    #[test]
    fn origin_timing_without_a_dapp_deadline() {
        let mut o = origin("x", Some("x.example"));
        o.dapp_deadline = None;
        o.waiting_behind = 1;
        let txt = origin_text(&o, 1_000 + 125, false);
        assert_eq!(
            txt.timing,
            "received 2:05 ago · Kao closes this review in 57:55"
        );
        assert_eq!(txt.behind.as_deref(), Some("+1 more request waiting"));
        assert_eq!(
            origin_text(&o, 1_000 + 3_725, false).timing,
            "received 1 h 02 min ago · Kao is closing this review"
        );
        assert_eq!(
            origin_text(&o, 1_000 + 3_725, true).timing,
            "received 1 h 02 min ago"
        );
        o.dapp_deadline = Some(1_100);
        assert!(
            origin_text(&o, 1_200, false)
                .timing
                .ends_with("the dapp has stopped waiting")
        );
    }

    /// A dapp expiry later than Kao's own deadline doesn't govern an open review: Kao closes it
    /// first, so that is what the card says. While signing, the dapp's deadline is the only one.
    #[test]
    fn origin_timing_counts_down_the_deadline_that_governs() {
        let mut o = origin("x", Some("x.example"));
        o.dapp_deadline = Some(1_000 + 7_200);
        assert_eq!(
            origin_text(&o, 1_000, false).timing,
            "received 0:00 ago · Kao closes this review in 1 h 00 min"
        );
        assert_eq!(
            origin_text(&o, 1_000, true).timing,
            "received 0:00 ago · the dapp waits 2 h 00 min more"
        );
        // An earlier dapp expiry governs either way.
        o.dapp_deadline = Some(1_000 + 600);
        for signing in [false, true] {
            assert_eq!(
                origin_text(&o, 1_000, signing).timing,
                "received 0:00 ago · the dapp waits 10:00 more"
            );
        }
    }

    #[test]
    fn safe_identity_names_its_chain() {
        let mut o = origin("x", Some("x.example"));
        o.identity = WcIdentity::Safe {
            address: Address::repeat_byte(0x5A),
            chain_id: 8453,
        };
        o.identity_label = "Treasury".into();
        o.identity_badge = "Safe";
        assert_eq!(
            origin_text(&o, 1_000, false).identity,
            "Treasury · Safe on Base"
        );
    }

    #[test]
    fn hex_dump_offsets_and_groups() {
        let bytes: Vec<u8> = (0u8..20).collect();
        assert_eq!(
            hex_dump(&bytes),
            "00000  00010203 04050607 08090a0b 0c0d0e0f\n00010  10111213",
        );
        assert_eq!(hex_dump(&[]), "");
    }

    #[test]
    fn hardware_hex_note_only_for_non_ascii() {
        let ascii = MessageShape::Text {
            lines: vec!["Sign in".into()],
        };
        let accented = MessageShape::Text {
            lines: vec!["Connexion à l'app".into()],
        };
        let binary = MessageShape::Binary {
            len: 3,
            hex: "0x010203".into(),
            reason: BinaryReason::NotUtf8,
        };
        assert!(!device_may_show_hex(&ascii));
        assert!(device_may_show_hex(&accented));
        assert!(device_may_show_hex(&binary));
    }

    #[test]
    fn gas_notes_say_where_the_limit_came_from() {
        assert_eq!(gas_note_text(GasNote::Estimated), "Kao's estimate");
        assert_eq!(
            gas_note_text(GasNote::Buffered { estimate: 100_000 }),
            "Kao's estimate (100,000) + 20% headroom"
        );
        assert_eq!(
            gas_note_text(GasNote::DappCapped {
                estimate: 50_000,
                dapp: 900_000
            }),
            "capped — the dapp asked for 900,000; Kao estimated 50,000"
        );
        assert_eq!(
            gas_note_text(GasNote::NetworkCapped {
                estimate: 9_000_000,
                dapp: Some(18_000_000)
            }),
            "held at the network's per-transaction maximum — the dapp asked for 18,000,000; Kao \
             estimated 9,000,000"
        );
        assert_eq!(
            gas_note_text(GasNote::NetworkCapped {
                estimate: 14_000_000,
                dapp: None
            }),
            "held at the network's per-transaction maximum — Kao estimated 14,000,000"
        );
        assert_eq!(
            gas_note_text(GasNote::DappUnestimated { dapp: 300_000 }),
            "the dapp's limit (300,000) — Kao's node couldn't estimate this call"
        );
    }

    #[test]
    fn span_label_precision() {
        assert_eq!(span_label(0), "0:00");
        assert_eq!(span_label(42), "0:42");
        assert_eq!(span_label(3_599), "59:59");
        assert_eq!(span_label(3_600), "1 h 00 min");
        assert_eq!(span_label(90_000), "1 d 1 h");
    }

    fn theme() -> KaoTheme {
        KaoTheme::for_kind(crate::ui::kao_theme::ThemeKind::Mint)
    }

    /// Every text the overlay draws for `step`, with the calldata/exact-values toggle and the
    /// fingerprints open — the most a user can make the review show.
    fn rendered(step: &SignStep) -> Vec<String> {
        super::super::super::test_support::texts(super::super::step_card(
            theme(),
            step,
            true,
            true,
            true,
            true,
            false,
        ))
    }

    const OWNER: Address = Address::repeat_byte(0x11);
    const TREASURY: Address = address!("5afe5afe5afe5afe5afe5afe5afe5afe5afe5afe");
    const USDC: Address = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
    /// `transfer(0xbadbad…, 1e12)`.
    const TRANSFER_TO_BADBAD: &str = "0xa9059cbb000000000000000000000000badbadbadbadbadbadbadbadbadbadbadbadbadb000000000000000000000000000000000000000000000000000000e8d4a51000";
    /// `addOwnerWithThreshold(0xbadbad…, 1)`.
    const ADD_OWNER_BADBAD: &str = "0x0d582f13000000000000000000000000badbadbadbadbadbadbadbadbadbadbadbadbadb0000000000000000000000000000000000000000000000000000000000000001";

    /// A `SafeTx` as Safe{Wallet} sends it over WalletConnect for an owner to confirm.
    fn safe_tx_json(safe: Address, to: Address, data: &str) -> serde_json::Value {
        crate::walletconnect::testkit::fixtures::safe_tx(safe, to, data)
    }

    /// The typed review the coordinator opens for `json`, checked exactly as admission checks it.
    fn checked_typed_review(json: serde_json::Value) -> TypedDataReview {
        let (td, raw) = crate::walletconnect::typed::parse_typed_param(&json).expect("parses");
        let checked =
            crate::walletconnect::typed::check_typed_data(&raw, &td, 1, OWNER).expect("admitted");
        TypedDataReview {
            from: OWNER,
            net: NetworkId::Builtin(Chain::Mainnet),
            checked,
            hash_mode_device: true,
            safe_label: Some("Treasury".into()),
            inner_leg: None,
        }
    }

    /// An owner confirmation is reviewable — the call the Safe would make is on screen, not
    /// two bytes of it and a promise that the fingerprints cover the rest.
    #[test]
    fn wc_safetx_owner_confirmation_shows_the_inner_calls_bytes() {
        let r = checked_typed_review(safe_tx_json(TREASURY, USDC, TRANSFER_TO_BADBAD));
        assert!(matches!(r.checked.kind, TypedKind::SafeTx { .. }));
        let all = rendered(&SignStep::WcTyped(r)).join("\n").to_lowercase();
        assert!(
            all.contains("badbad"),
            "the SafeTx's inner-call recipient never reaches the overlay: {all}"
        );
        assert!(all.contains("a9059cbb"), "the selector is shown: {all}");
    }

    /// A SafeTx that adds an owner to the Safe confirming it: the new owner's bytes are on screen.
    #[test]
    fn wc_safetx_self_call_add_owner_is_reviewable() {
        let r = checked_typed_review(safe_tx_json(TREASURY, TREASURY, ADD_OWNER_BADBAD));
        let all = rendered(&SignStep::WcTyped(r)).join("\n").to_lowercase();
        assert!(
            all.contains("badbad"),
            "the new owner is never shown for a SafeTx that adds one: {all}"
        );
    }

    /// A long domain name is signed in full, so it shows in full behind the same toggle.
    #[test]
    fn long_domain_name_is_shown_in_full() {
        let tail = "_hidden_tail_of_the_domain_name";
        let mut json = safe_tx_json(TREASURY, USDC, TRANSFER_TO_BADBAD);
        json["types"]["EIP712Domain"] = serde_json::json!([
            {"name": "name", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"}
        ]);
        json["domain"]["name"] = serde_json::json!(format!("Safe{}{tail}", "x".repeat(100)));
        let step = SignStep::WcTyped(checked_typed_review(json));
        assert!(rendered(&step).join("\n").contains(tail));
        let folded = super::super::super::test_support::texts(super::super::step_card(
            theme(),
            &step,
            false,
            false,
            false,
            false,
            false,
        ));
        assert!(!folded.join("\n").contains(tail), "shortened until asked");
        assert!(
            folded.iter().any(|t| t == "Show exact values"),
            "{folded:#?}"
        );
    }

    /// The decoded call lives inside the owner-confirmation panel, with its banners; the ERC-8213
    /// section adds the call's Calldata Digest, as a Safe transaction step does.
    #[test]
    fn wc_safetx_panel_carries_the_decoded_call_and_its_digest() {
        let mut r = checked_typed_review(safe_tx_json(TREASURY, TREASURY, ADD_OWNER_BADBAD));
        let TypedKind::SafeTx { data, .. } = r.checked.kind.clone() else {
            unreachable!()
        };
        r.inner_leg = Some(Box::new(ReviewLeg {
            title: "Call to 0x5afe…5afe".into(),
            to: TREASURY,
            value: U256::ZERO,
            net: NetworkId::Builtin(Chain::Mainnet),
            calldata: data.clone(),
            decoded: Box::new(crate::decode::clear_sign::DecodeResult::Empty),
            sub_legs: Vec::new(),
            self_admin: Some("This call reconfigures the Safe that is signing it.".into()),
        }));
        let step = SignStep::WcTyped(r);
        let texts = rendered(&step);
        let at = |needle: &str| texts.iter().position(|t| t.contains(needle));
        let banner = at("THIS APPROVES A SAFE TRANSACTION");
        let call = at("The Safe would execute");
        let admin = at("reconfigures the Safe");
        assert!(
            banner.is_some() && call.is_some() && admin.is_some(),
            "{texts:#?}"
        );
        assert!(
            banner < call && call < admin,
            "the call follows the banner: {texts:#?}"
        );
        let rows = erc8213_rows(&step);
        assert_eq!(
            rows.last(),
            Some(&(
                "Calldata Digest (inner call)".to_string(),
                crate::sign::digest::calldata_digest(&data)
            )),
            "{rows:?}"
        );
        assert_eq!(rows.len(), 4, "the EIP-712 triple, then the call's digest");
    }

    /// Gas and refund fields a dapp set are named, each with what it does; a delegatecall gets the
    /// Safe transaction step's operation banner.
    #[test]
    fn wc_safetx_refund_and_delegatecall_are_called_out() {
        let mut json = safe_tx_json(TREASURY, USDC, TRANSFER_TO_BADBAD);
        json["message"]["gasPrice"] = serde_json::json!("1000000000");
        json["message"]["baseGas"] = serde_json::json!("50000");
        json["message"]["safeTxGas"] = serde_json::json!("100000");
        json["message"]["refundReceiver"] =
            serde_json::json!("0x9999999999999999999999999999999999999999");
        json["message"]["operation"] = serde_json::json!(1);
        let all = rendered(&SignStep::WcTyped(checked_typed_review(json))).join("\n");
        for needle in [
            "gasPrice",
            "baseGas",
            "safeTxGas",
            "refundReceiver",
            "gas refund out of the Safe",
            "the refundReceiver above",
            "even if its call fails",
            "⚠ DELEGATECALL",
            "NOT a canonical Safe MultiSend library",
        ] {
            assert!(all.contains(needle), "missing {needle:?}: {all}");
        }
        // Kao's own shape — every gas field 0 — raises none of it (the message rows still list
        // the fields, as they list every field).
        let all = rendered(&SignStep::WcTyped(checked_typed_review(safe_tx_json(
            TREASURY,
            USDC,
            TRANSFER_TO_BADBAD,
        ))))
        .join("\n");
        for needle in [
            "gas refund",
            "Gas or refund fields",
            "even if its call fails",
            "DELEGATECALL",
        ] {
            assert!(!all.contains(needle), "{needle:?}: {all}");
        }
    }

    /// Permit2 `expiration` 0 is the block the permit lands in — shown as usable now, in red,
    /// with the signature's own deadline beside it. Never "1970-01-01".
    #[test]
    fn permit2_expiration_zero_is_shown_as_usable_now() {
        let json = serde_json::json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"}, {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "PermitDetails": [
                    {"name": "token", "type": "address"}, {"name": "amount", "type": "uint160"},
                    {"name": "expiration", "type": "uint48"}, {"name": "nonce", "type": "uint48"}
                ],
                "PermitSingle": [
                    {"name": "details", "type": "PermitDetails"},
                    {"name": "spender", "type": "address"},
                    {"name": "sigDeadline", "type": "uint256"}
                ]
            },
            "primaryType": "PermitSingle",
            "domain": {
                "name": "Permit2", "chainId": 1,
                "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            },
            "message": {
                "details": {"token": USDC.to_checksum(None), "amount": "5000000000",
                    "expiration": "0", "nonce": "0"},
                "spender": "0x4444444444444444444444444444444444444444",
                "sigDeadline": "1893456000"
            }
        });
        let all = rendered(&SignStep::WcTyped(checked_typed_review(json))).join("\n");
        assert!(!all.contains("1970-01-01"), "{all}");
        assert!(all.contains("Usable immediately"), "{all}");
        assert!(all.contains("Signature usable until"), "{all}");
        assert!(all.contains("2030-01-01 00:00 UTC"), "{all}");
    }

    /// The OP-stack L1 data fee is charged on top of the gas cap; the card must not promise the
    /// cap is all the user pays.
    #[test]
    fn wc_fee_card_on_base_discloses_the_l1_data_fee() {
        use crate::wallet::sim::SimulationResult;
        use crate::wallet::tx::{SendPlan, SendToken, TxQuote};
        let step = |chain: Chain| {
            let plan = SendPlan {
                from: OWNER,
                recipient: Address::repeat_byte(0x40),
                token: SendToken::Call {
                    data: Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
                },
                amount_units: U256::ZERO,
                chain: NetworkId::Builtin(chain),
            };
            let quote = TxQuote {
                plan,
                gas_limit: 50_000,
                max_fee_per_gas: 2_000_000_000,
                max_priority_fee_per_gas: 1_000_000,
                nonce: 3,
                eth_cost_wei: U256::from(100_000_000_000_000u64),
                sim: SimulationResult::unavailable(),
            };
            SignStep::WcTxFees(WcTxFeesReview {
                quote,
                gas_note: GasNote::Estimated,
                max_total_wei: U256::from(100_000_000_000_000u64),
                balance_wei: Some(U256::from(100_000_000_000_000u64)),
                unverified_network: false,
                sim_reverted: false,
                estimate_failed: None,
            })
        };
        for chain in [Chain::Base, Chain::Optimism] {
            let all = rendered(&step(chain)).join("\n");
            assert!(
                !all.contains("you pay at most the maximum network fee"),
                "{chain:?}: an upper bound that excludes the L1 data fee: {all}"
            );
            assert!(all.contains("L1 data fee"), "{chain:?}: {all}");
        }
        // On L1 the cap is the whole cost, and the card says so.
        let all = rendered(&step(Chain::Mainnet)).join("\n");
        assert!(
            all.contains("you pay at most the maximum network fee"),
            "{all}"
        );
        assert!(!all.contains("L1 data fee"), "{all}");
    }

    /// Folded, the fee card is its header and its warnings: the maximum fee (flagged when the L1
    /// data fee comes on top), the banners and the shortfall stay up; the breakdown waits for the
    /// toggle.
    #[test]
    fn wc_fee_card_folds_the_breakdown_but_not_the_warnings() {
        use crate::wallet::sim::SimulationResult;
        use crate::wallet::tx::{SendPlan, SendToken, TxQuote};
        let step = |chain: Chain| {
            SignStep::WcTxFees(WcTxFeesReview {
                quote: TxQuote {
                    plan: SendPlan {
                        from: OWNER,
                        recipient: Address::repeat_byte(0x40),
                        token: SendToken::Call {
                            data: Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
                        },
                        amount_units: U256::ZERO,
                        chain: NetworkId::Builtin(chain),
                    },
                    gas_limit: 50_000,
                    max_fee_per_gas: 2_000_000_000,
                    max_priority_fee_per_gas: 1_000_000,
                    nonce: 3,
                    eth_cost_wei: U256::from(100_000_000_000_000u64),
                    sim: SimulationResult::unavailable(),
                },
                gas_note: GasNote::Estimated,
                max_total_wei: U256::from(100_000_000_000_000u64),
                balance_wei: Some(U256::from(1u64)),
                unverified_network: false,
                sim_reverted: true,
                estimate_failed: None,
            })
        };
        let folded = |step: &SignStep| {
            super::super::super::test_support::texts(super::super::step_card(
                theme(),
                step,
                false,
                false,
                false,
                false,
                false,
            ))
            .join("\n")
        };
        const DETAILS: [&str; 5] = [
            "Nonce",
            "Gas limit",
            "Priority tip",
            "Your balance",
            "refunded",
        ];
        let all = folded(&step(Chain::Mainnet));
        assert!(all.contains("max 0.0001 ETH"), "{all}");
        assert!(!all.contains("L1 fee"), "{all}");
        assert!(all.contains("SIMULATION REVERTED"), "{all}");
        assert!(all.contains("Not enough ETH"), "{all}");
        for detail in DETAILS {
            assert!(!all.contains(detail), "{detail} folded away: {all}");
        }
        let all = folded(&step(Chain::Base));
        assert!(all.contains("max 0.0001 ETH + L1 fee"), "{all}");
        // Unfolded, the breakdown is back.
        let all = rendered(&step(Chain::Mainnet)).join("\n");
        for detail in DETAILS {
            assert!(all.contains(detail), "{detail} unfolded: {all}");
        }
    }

    /// A quote that took the dapp's gas because Kao's node couldn't estimate the call says so in
    /// red, with the node's reason, and the gas note names the dapp's limit.
    #[test]
    fn wc_fee_card_discloses_an_estimate_failure() {
        use crate::wallet::sim::SimulationResult;
        use crate::wallet::tx::{SendPlan, SendToken, TxQuote};
        let plan = SendPlan {
            from: OWNER,
            recipient: Address::repeat_byte(0x40),
            token: SendToken::Call {
                data: Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
            },
            amount_units: U256::ZERO,
            chain: NetworkId::Builtin(Chain::Mainnet),
        };
        let step = |estimate_failed: Option<String>| {
            SignStep::WcTxFees(WcTxFeesReview {
                quote: TxQuote {
                    plan: plan.clone(),
                    gas_limit: 300_000,
                    max_fee_per_gas: 2_000_000_000,
                    max_priority_fee_per_gas: 1_000_000,
                    nonce: 3,
                    eth_cost_wei: U256::from(600_000_000_000_000u64),
                    sim: SimulationResult::unavailable(),
                },
                gas_note: GasNote::DappUnestimated { dapp: 300_000 },
                max_total_wei: U256::from(600_000_000_000_000u64),
                balance_wei: None,
                unverified_network: false,
                sim_reverted: false,
                estimate_failed,
            })
        };
        let all = rendered(&step(Some(
            "execution reverted: insufficient allowance".into(),
        )))
        .join("\n");
        assert!(all.contains("KAO'S NODE EXPECTS THIS TO FAIL"), "{all}");
        assert!(all.contains("insufficient allowance"), "{all}");
        assert!(all.contains("the dapp's limit (300,000)"), "{all}");
        assert!(
            !rendered(&step(None))
                .join("\n")
                .contains("EXPECTS THIS TO FAIL")
        );
    }

    /// A dapp-signed token longer than the box wraps inside it instead of running past the edge,
    /// where the scrollable body clips it with no sign anything is missing.
    #[test]
    fn long_dapp_tokens_wrap_inside_their_box() {
        use super::super::super::test_support::text_bounds;
        let token = format!(
            "Approve:0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045_spend_all_USDC_for_{}",
            "f".repeat(150)
        );
        // 12 px text at the default 1.3 line height: one line is 15.6 px tall.
        let wrapped = |el: Element<'_, Message>| {
            let bounds = text_bounds(container(el).width(470).into());
            bounds
                .iter()
                .filter(|(s, _)| s.contains(&token))
                .map(|(_, b)| b.height)
                .collect::<Vec<_>>()
        };
        let lines = [token.clone()];
        for (what, heights) in [
            (
                "field value",
                wrapped(field_row(theme(), "label", token.clone())),
            ),
            (
                "field label",
                wrapped(field_row(theme(), token.clone(), "v")),
            ),
            ("message line", wrapped(text_lines_box(theme(), &lines))),
        ] {
            assert!(!heights.is_empty(), "{what}: not drawn");
            for h in heights {
                assert!(
                    h > 2.0 * 15.6,
                    "{what}: laid out on one line, clipped ({h} px tall)"
                );
            }
        }
    }
}
