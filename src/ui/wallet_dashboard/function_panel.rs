//! Decoded function call rendering — two pieces at two altitudes.
//!
//! [`headline_view`] is the **headline**: the one line saying what a call
//! does, from [`DecodeResult::headline`]. Every review renders it at the top
//! of the leg, above the destination rows. It used to live inside the panel
//! below, which buried the only line most users read under `To` / `Value` and
//! forced the Send flow to re-derive it for its collapsed pill.
//!
//! [`view`] is the **panel**: the mechanical half — labeled entries, per-arg
//! rows, warning strips — dispatched on `DecodeResult`:
//! - **ClearSigned** — ERC-7730 descriptor matched. Labeled entries from the
//!   `DisplayModel`.
//! - **Fallback** — partial descriptor match; entries plus the heuristic's
//!   spoof/ambiguity signals.
//! - **Heuristic** — no descriptor. Per-arg rows from evmole/4byte.
//! - **Empty** — native ETH transfer, no calldata. Returns `None`.
//!
//! The panel returns `None` whenever it would render nothing at all (a
//! no-argument call is fully described by its headline), so callers can skip
//! the surrounding divider.
//!
//! Warnings render as tinted strips. The one that undermines the headline
//! itself — an unverified read, a selector several signatures share — is
//! `Headline::caution` and renders beside the headline, never behind the
//! detail toggle. `AmbiguousSignature` / `BytecodeMismatch` lead the panel
//! with their candidate lists; `InfiniteApproval` / `UnverifiedBytecode`
//! qualify the call without contradicting the headline and stay in the strip
//! below the args.
//!
//! Loading state shows a small "decoding…" line; sized so the review
//! card doesn't pop when the result lands.

use alloy::primitives::Address;
use iced::border::Radius;
use iced::widget::text::Wrapping;
use iced::widget::{Space, column, container, row, text};
use iced::{Alignment, Background, Border, Element, Length, Padding};

use clear_signing::{
    DiagnosticSeverity, DisplayEntry, DisplayItem, DisplayModel, FormatDiagnostic,
};

use crate::decode::clear_sign::{DecodeResult, Headline};
use crate::decode::render::{ArgDisplay, DecodedArg, DecodedCall, ResolutionState, Warning};
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::{CopyKick, bold, colored_address, mono};

/// Build the panel: the *mechanical* half of a decode — labeled entries, arg
/// rows, and the warning strips that qualify them.
///
/// The headline ("what does this do") is deliberately **not** here: it is
/// [`DecodeResult::headline`], rendered by the caller above the destination
/// rows. Rendering it inside this panel put the one line that matters below
/// `To` / `Value` and inside the block users skim.
///
/// Returns `None` when nothing would render — a native transfer, or a decode
/// whose entries and warnings are both empty (e.g. a resolved no-argument call
/// like `pause()`, fully described by its headline). Callers should omit the
/// surrounding divider so the review card layout stays clean.
pub fn view<'a, M: CopyKick + 'a>(
    t: KaoTheme,
    decoded: Option<&'a DecodeResult>,
    loading: bool,
) -> Option<Element<'a, M>> {
    if loading {
        return Some(loading_view(t));
    }
    // What the headline already told the user, so the entries below don't
    // repeat it back.
    let said = decoded.and_then(DecodeResult::headline).map(|h| h.text);
    match decoded? {
        DecodeResult::ClearSigned {
            model,
            diagnostics,
            warnings,
            ..
        } => clear_signed_panel(t, model, diagnostics, warnings, said.as_deref()),
        DecodeResult::Fallback {
            model,
            diagnostics,
            heuristic,
            ..
        } => clear_signed_panel(
            t,
            model,
            diagnostics,
            // The heuristic ran alongside the partial descriptor; don't drop
            // its spoof/ambiguity signals just because we're showing the
            // descriptor's intent.
            &heuristic.warnings,
            said.as_deref(),
        ),
        DecodeResult::Heuristic(decoded) => {
            if matches!(decoded.state, ResolutionState::Empty) {
                None
            } else {
                heuristic_panel(t, decoded)
            }
        }
        DecodeResult::Empty => None,
    }
}

/// The review's headline card: what this call does, centered above the
/// destination rows. When the decode carries a
/// [`caution`](crate::decode::clear_sign::Headline::caution) the line is muted
/// and the strip renders directly beneath it — it must stay visible even when
/// the caller has folded the rest of the detail away.
pub fn headline_view<'a, M: CopyKick + 'a>(t: KaoTheme, h: &Headline) -> Element<'a, M> {
    // No "Intent" label and no contract name: the sentence says what it is, and
    // the contract is already the `To` row — a label and a repeat of the token
    // ticker were two lines of chrome around the one line that matters.
    let color = if h.caution.is_some() { t.sub } else { t.text };
    let mut col = column![]
        .spacing(2)
        .align_x(Alignment::Center)
        .width(Length::Fill);

    // An ERC-7730 intent interpolates recipients straight into its sentence
    // ("Transfer 800 DAI to 0x6B17…"). Lift those out so they render as the
    // coloured, click-to-copy address widget rather than 40 undifferentiated
    // hex characters — this is the one field in the sentence a user has to
    // check character by character.
    for part in split_addresses(&h.text) {
        col = match part {
            HeadlinePart::Text(s) => col.push(
                text(s)
                    .size(13)
                    .color(color)
                    .font(bold())
                    .align_x(Alignment::Center),
            ),
            HeadlinePart::Addr(addr) => col.push(colored_address::<M>(t, addr)),
        };
    }

    if let Some(note) = &h.note {
        col = col.push(text(note.clone()).size(11).color(t.sub).font(mono()));
    }
    if h.via_proxy {
        col = col.push(text("(via proxy)").size(10).color(t.sub).font(mono()));
    }

    let card = intent_card(t, col.into());
    // The caution never hides behind the detail toggle — it qualifies the
    // headline, which is the one thing always on screen.
    match &h.caution {
        Some(msg) => column![card, Space::new().height(6), caution_strip(t, msg.clone())]
            .width(Length::Fill)
            .into(),
        None => card,
    }
}

/// A run of a headline sentence: either prose, or an address lifted out of it
/// for the coloured widget.
#[derive(Debug, PartialEq, Eq)]
enum HeadlinePart {
    Text(String),
    Addr(Address),
}

/// Split a headline sentence on any addresses interpolated into it.
///
/// Matches `0x` followed by **exactly** 40 hex characters, so a 32-byte hash
/// (64 hex) or a bare `0x` prefix in prose is left as text. Surrounding
/// whitespace is trimmed off each prose run, since the parts render as their
/// own centered lines.
fn split_addresses(s: &str) -> Vec<HeadlinePart> {
    let mut parts = Vec::new();
    let mut prose = String::new();
    let mut rest = s;

    let flush = |prose: &mut String, parts: &mut Vec<HeadlinePart>| {
        let trimmed = prose.trim();
        if !trimmed.is_empty() {
            parts.push(HeadlinePart::Text(trimmed.to_string()));
        }
        prose.clear();
    };

    while let Some(i) = rest.find("0x") {
        let hex = rest[i + 2..]
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .count();
        // `i + 42` is a char boundary whenever `hex == 40`: those 40 bytes are
        // ASCII hex digits by construction.
        if hex == 40
            && let Ok(addr) = rest[i..i + 42].parse::<Address>()
        {
            prose.push_str(&rest[..i]);
            flush(&mut prose, &mut parts);
            parts.push(HeadlinePart::Addr(addr));
            rest = &rest[i + 42..];
            continue;
        }
        // Not an address — keep the `0x` as prose and scan on past it.
        prose.push_str(&rest[..i + 2]);
        rest = &rest[i + 2..];
    }
    prose.push_str(rest);
    flush(&mut prose, &mut parts);
    parts
}

fn loading_view<'a, M: 'a>(t: KaoTheme) -> Element<'a, M> {
    let mut col = column![].spacing(6);
    col = col.push(text("Intent").size(11).color(t.sub).font(bold()));
    col = col.push(Space::new().height(2));
    col = col.push(
        text("(・_・;) resolving…")
            .size(13)
            .color(t.sub)
            .font(mono()),
    );
    // Placeholder rows so the card doesn't jump when the result lands.
    for label in ["· ···", "· ···"] {
        col = col.push(
            row![
                text(label)
                    .size(11)
                    .color(with_alpha(t.sub, 0.4))
                    .font(mono()),
                Space::new().width(Length::Fill),
                text("···")
                    .size(12)
                    .color(with_alpha(t.sub, 0.4))
                    .font(mono()),
            ]
            .width(Length::Fill),
        );
    }
    col.width(Length::Fill).into()
}

// ---------------------------------------------------------------------------
// ERC-7730 clear-signed panel

fn clear_signed_panel<'a, M: CopyKick + 'a>(
    t: KaoTheme,
    model: &'a DisplayModel,
    diagnostics: &'a [FormatDiagnostic],
    heuristic_warnings: &'a [Warning],
    said: Option<&str>,
) -> Option<Element<'a, M>> {
    let mut col = column![].spacing(6);
    let mut rendered = false;

    // Signals from the mechanical cross-check lead the panel — they cast doubt
    // on the headline above, so the user must meet them before reading the
    // entries. Spoof/ambiguity come from the heuristic decode on the Fallback
    // path; unaccounted calldata is computed from the bytes on both descriptor
    // paths, and is the one finding an authored descriptor cannot make about
    // itself: it renders the fields it knows, and says nothing about a tail it
    // was never told to look for.
    for w in heuristic_warnings {
        if matches!(
            w,
            Warning::BytecodeMismatch { .. }
                | Warning::AmbiguousSignature { .. }
                | Warning::UnaccountedCalldata { .. }
        ) {
            col = col.push(warning_strip(t, w));
            rendered = true;
        }
    }

    // Neither the intent nor the unverified-reads caution is rendered here:
    // both belong to the headline (`DecodeResult::headline`), which stays on
    // screen even when this panel is collapsed away.

    // Entries — minus anything the headline already spelled out. An ERC-7730
    // intent interpolates the fields that matter ("Transfer 800 DAI to 0x…"),
    // so echoing them as rows underneath is the same value read twice; what's
    // left is what the sentence didn't say.
    for entry in &model.entries {
        if !entry_is_visible(entry, said) {
            continue;
        }
        col = push_display_entry(&mut col, t, entry, 0, said);
        rendered = true;
    }

    // Diagnostics (warning-severity only).
    let warnings: Vec<&FormatDiagnostic> = diagnostics
        .iter()
        .filter(|d| matches!(d.severity, DiagnosticSeverity::Warning))
        .collect();
    if !warnings.is_empty() {
        col = col.push(Space::new().height(4));
        for diag in warnings {
            col = col.push(diagnostic_strip(t, diag));
        }
        rendered = true;
    }

    rendered.then(|| col.width(Length::Fill).into())
}

/// Whether an entry still has anything to show once everything the headline
/// already said is dropped. Keeps the panel from claiming content it will then
/// render as nothing.
fn entry_is_visible(entry: &DisplayEntry, said: Option<&str>) -> bool {
    match entry {
        DisplayEntry::Item(item) => !already_said(said, &item.value),
        DisplayEntry::Group { items, .. } => items.iter().any(|i| !already_said(said, &i.value)),
        // A nested call renders its own label + intent header regardless.
        DisplayEntry::Nested { .. } => true,
    }
}

/// Recursively push a `DisplayEntry` into the column. `depth` controls
/// indentation for nested entries.
fn push_display_entry<'a, M: CopyKick + 'a>(
    col: &mut iced::widget::Column<'a, M>,
    t: KaoTheme,
    entry: &'a DisplayEntry,
    depth: u16,
    said: Option<&str>,
) -> iced::widget::Column<'a, M> {
    let indent = (depth as f32) * 12.0;
    let col_taken = std::mem::replace(col, column![]);
    let mut col = col_taken;
    match entry {
        DisplayEntry::Item(item) => {
            if !already_said(said, &item.value) {
                col = col.push(display_item_row(t, item, indent));
            }
        }
        DisplayEntry::Group { label, items, .. } => {
            let keep: Vec<&DisplayItem> = items
                .iter()
                .filter(|i| !already_said(said, &i.value))
                .collect();
            // A group whose every item was already in the headline takes its
            // label with it — an empty sub-header is worse than nothing.
            if !keep.is_empty() {
                col = col.push(row![
                    Space::new().width(Length::Fixed(indent)),
                    text(label).size(11).color(t.sub).font(bold()),
                ]);
                for item in keep {
                    col = col.push(display_item_row(t, item, indent + 8.0));
                }
            }
        }
        DisplayEntry::Nested {
            label,
            intent,
            entries,
            ..
        } => {
            // Nested card: label + intent as a sub-header, entries indented.
            let nested_header = row![
                Space::new().width(Length::Fixed(indent)),
                column![
                    text(label).size(11).color(t.sub).font(bold()),
                    text(intent).size(12).color(t.text).font(bold()),
                ]
                .spacing(2),
            ];
            col = col.push(nested_header);
            for sub_entry in entries {
                col = push_display_entry(&mut col, t, sub_entry, depth + 1, said);
            }
        }
    }
    col
}

/// Whether the headline sentence already carries this value verbatim, so the
/// entry row would be a second reading of the same field.
///
/// Matched on token boundaries and case-insensitively: `"1"` must not count as
/// said because the headline mentions `1000`, and an address interpolated by
/// the descriptor can differ from the entry only in checksum casing.
fn already_said(said: Option<&str>, value: &str) -> bool {
    let (Some(said), value) = (said, value.trim()) else {
        return false;
    };
    if value.is_empty() {
        return false;
    }
    // ASCII-lowercasing preserves byte length, so indices stay in step.
    let hay = said.to_ascii_lowercase();
    let needle = value.to_ascii_lowercase();
    let mut from = 0usize;
    while let Some(i) = hay[from..].find(&needle) {
        let start = from + i;
        let end = start + needle.len();
        let bounded_left = hay[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        let bounded_right = hay[end..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric());
        if bounded_left && bounded_right {
            return true;
        }
        from = start + hay[start..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

fn display_item_row<'a, M: CopyKick + 'a>(
    t: KaoTheme,
    item: &'a DisplayItem,
    indent: f32,
) -> Element<'a, M> {
    // ERC-7730 hands back every value as a plain string. Recover the ones that
    // are exactly an address so they render as the same coloured, click-to-copy
    // widget as the `To` row: an address is the field most worth checking
    // character by character, and undifferentiated monospace hex is the hardest
    // thing to check. Everything else (amounts, names, dates) stays text.
    if let Ok(addr) = item.value.trim().parse::<Address>() {
        return column![
            row![
                Space::new().width(Length::Fixed(indent)),
                text(format!("· {}", item.label))
                    .size(11)
                    .color(t.sub)
                    .font(mono()),
            ],
            row![
                Space::new().width(Length::Fixed(indent + 8.0)),
                colored_address::<M>(t, addr),
            ],
        ]
        .spacing(2)
        .width(Length::Fill)
        .into();
    }
    let value_display = truncate(&item.value, 48);
    labeled_value(
        t,
        indent,
        format!("· {}", item.label),
        value_display.into_owned(),
        t.text,
    )
}

/// The intent block's own card: the one line that says what this call actually
/// does, lifted out of the flush-left run of labeled rows below it.
///
/// `width(Fill)` + `align_x` centers the *content* inside a full-width card;
/// `center_x` would instead set the container's width to the content and
/// collapse the card around the text.
fn intent_card<'a, M: 'a>(t: KaoTheme, content: Element<'a, M>) -> Element<'a, M> {
    container(content)
        .padding(Padding::from([10, 12]))
        .width(Length::Fill)
        .align_x(Alignment::Center)
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(t.a1, 0.07))),
            border: Border {
                color: with_alpha(t.a1, 0.25),
                width: 1.0,
                radius: Radius::from(10),
            },
            text_color: Some(t.text),
            ..container::Style::default()
        })
        .into()
}

/// A tinted caution band — the shared styling for diagnostics, heuristic
/// warnings, and the unverified-reads notice.
fn caution_strip<'a, M: 'a>(t: KaoTheme, line: String) -> Element<'a, M> {
    container(text(line).size(11).color(t.down).font(bold()))
        .padding(Padding::from([6, 8]))
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(with_alpha(t.down, 0.12))),
            border: Border {
                color: with_alpha(t.down, 0.4),
                width: 1.0,
                radius: Radius::from(8),
            },
            text_color: Some(t.down),
            ..container::Style::default()
        })
        .into()
}

fn diagnostic_strip<'a, M: 'a>(t: KaoTheme, diag: &'a FormatDiagnostic) -> Element<'a, M> {
    caution_strip(t, format!("⚠ {}", diag.message))
}

// ---------------------------------------------------------------------------
// Heuristic panel (existing renderer, extracted from the old `panel`)

fn heuristic_panel<'a, M: CopyKick + 'a>(
    t: KaoTheme,
    d: &'a DecodedCall,
) -> Option<Element<'a, M>> {
    // AmbiguousSignature warnings lead — they cast doubt on the headline
    // above (which is muted to match), so the user must meet them before
    // reading the args. The other warning kinds qualify the call without
    // undermining the name and ride below the arg rows in the foot strip.
    let mut col = column![].spacing(6);
    let mut rendered = false;
    for w in &d.warnings {
        if matches!(
            w,
            Warning::AmbiguousSignature { .. } | Warning::BytecodeMismatch { .. }
        ) {
            col = col.push(warning_strip(t, w));
            rendered = true;
        }
    }

    for arg in &d.args {
        col = col.push(arg_row(t, arg));
        rendered = true;
    }

    if d.args.is_empty() && matches!(d.state, ResolutionState::Unknown) {
        // No types at all — tell the user we couldn't decode and show
        // the raw calldata footprint so they can at least eyeball it.
        col = col.push(unknown_call_body(t, d));
        rendered = true;
    }

    let mut foot_warnings = d
        .warnings
        .iter()
        .filter(|w| {
            !matches!(
                w,
                Warning::AmbiguousSignature { .. } | Warning::BytecodeMismatch { .. }
            )
        })
        .peekable();
    if foot_warnings.peek().is_some() {
        col = col.push(Space::new().height(4));
        for w in foot_warnings {
            col = col.push(warning_strip(t, w));
        }
        rendered = true;
    }

    // A resolved no-argument call (`pause()`) has nothing mechanical left to
    // show — its headline already says everything.
    rendered.then(|| col.width(Length::Fill).into())
}

fn arg_row<'a, M: 'a>(t: KaoTheme, arg: &'a DecodedArg) -> Element<'a, M> {
    let name = arg.name.as_deref().unwrap_or(""); // bytecode introspection rarely has names
    let ty_label = ty_short(&arg.ty);
    let label = if name.is_empty() {
        format!("· {ty_label}")
    } else {
        format!("· {name}: {ty_label}")
    };
    let value = match &arg.display {
        ArgDisplay::Address { addr, ens } => match ens {
            Some(name) => format!("{name}  {}", short(*addr)),
            None => short(*addr),
        },
        ArgDisplay::Uint { formatted, .. } => formatted.clone(),
        ArgDisplay::Int { formatted, .. } => formatted.clone(),
        ArgDisplay::Bool(b) => b.to_string(),
        ArgDisplay::String(s) => format!("\"{}\"", truncate(s, 48)),
        ArgDisplay::Bytes(b) => {
            let hex = alloy::hex::encode(b);
            format!("0x{}", truncate(&hex, 32))
        }
        ArgDisplay::Raw(s) => truncate(s, 48).into_owned(),
    };

    labeled_value(t, 0.0, label, value, t.text)
}

fn unknown_call_body<'a, M: 'a>(t: KaoTheme, d: &'a DecodedCall) -> Element<'a, M> {
    // Show truncated raw calldata so the user has _something_ to
    // eyeball when no decoder applied.
    let hex = alloy::hex::encode(&d.raw_calldata);
    let display = format!("0x{}", truncate(&hex, 64));
    labeled_value(t, 0.0, "· raw".to_string(), display, t.sub)
}

/// A `label … value` arg row. Short values sit on the same line as the label,
/// right-aligned; values too long for that (big `uint256`s, long hex) drop onto
/// their own full-width line and **wrap by glyph** so a 77-digit number breaks
/// across rows instead of overflowing the panel edge.
fn labeled_value<'a, M: 'a>(
    t: KaoTheme,
    indent: f32,
    label: String,
    value: String,
    value_color: iced::Color,
) -> Element<'a, M> {
    let label_el = text(label).size(11).color(t.sub).font(mono());
    if value.chars().count() <= VALUE_INLINE_MAX {
        row![
            Space::new().width(Length::Fixed(indent)),
            label_el,
            Space::new().width(Length::Fill),
            text(value).size(12).color(value_color).font(mono()),
        ]
        .width(Length::Fill)
        .into()
    } else {
        // Stacked: label, then the value wrapping across the full width. The
        // value row must be `Fill` (a Row defaults to Shrink) so the text has a
        // width bound to glyph-wrap within instead of overflowing.
        column![
            row![Space::new().width(Length::Fixed(indent)), label_el],
            row![
                Space::new().width(Length::Fixed(indent + 8.0)),
                text(value)
                    .size(12)
                    .color(value_color)
                    .font(mono())
                    .wrapping(Wrapping::Glyph)
                    .width(Length::Fill),
            ]
            .width(Length::Fill),
        ]
        .width(Length::Fill)
        .spacing(2)
        .into()
    }
}

/// Values longer than this won't fit on the shared label row (the panel is ~45
/// mono chars wide once the label and gap are subtracted), so they wrap onto
/// their own line instead.
const VALUE_INLINE_MAX: usize = 20;

fn warning_strip<'a, M: 'a>(t: KaoTheme, w: &'a Warning) -> Element<'a, M> {
    let line: String = match w {
        Warning::InfiniteApproval { spender, .. } => {
            format!("⚠ infinite approval to {}", short(*spender))
        }
        Warning::UnverifiedBytecode => "⚠ bytecode read fell back to unverified RPC".into(),
        Warning::AmbiguousSignature { candidates } => {
            let names: Vec<&str> = candidates.iter().map(String::as_str).collect();
            format!("⚠ ambiguous: {}", truncate(&names.join(", "), 60))
        }
        Warning::BytecodeMismatch { candidates } => {
            let names: Vec<&str> = candidates.iter().map(String::as_str).collect();
            format!(
                "⚠ possible spoof — on-chain code matches no known signature (claimed: {})",
                truncate(&names.join(", "), 48)
            )
        }
        Warning::UnaccountedCalldata { decoded, total } => format!(
            "⚠ {} byte(s) of calldata are not shown above — the arguments account for {decoded} \
             of {total}",
            total.saturating_sub(*decoded),
        ),
    };
    caution_strip(t, line)
}

// ---------------------------------------------------------------------------
// Formatting helpers

fn short(addr: Address) -> String {
    let s = format!("{addr:#x}");
    // Six leading + four trailing — enough to spot-check, narrow enough
    // to fit in the value column without crowding.
    let len = s.len();
    if len <= 12 {
        return s;
    }
    format!("{}…{}", &s[..6], &s[len - 4..])
}

/// Clamp `s` to `max` characters (appending `…`) **and** strip unsafe display
/// code points — bidi controls, zero-width / invisible characters, control
/// chars. Arg values and clear-signed labels can carry attacker-controlled
/// strings (decoded calldata, contract-supplied text); stripping here keeps a
/// hostile contract from reordering or hiding the review surface. See
/// [`crate::sanitize`].
fn truncate(s: &str, max: usize) -> std::borrow::Cow<'_, str> {
    crate::sanitize::sanitize_display(s, max)
}

/// Compact canonical-string label for an alloy `DynSolType` — used on
/// arg rows so the reader sees `address` / `uint256` / `(address,uint256)[]`
/// instead of evmole's debug repr.
fn ty_short(ty: &alloy::dyn_abi::DynSolType) -> String {
    use alloy::dyn_abi::DynSolType;
    match ty {
        DynSolType::Address => "address".into(),
        DynSolType::Bool => "bool".into(),
        DynSolType::String => "string".into(),
        DynSolType::Bytes => "bytes".into(),
        DynSolType::FixedBytes(n) => format!("bytes{n}"),
        DynSolType::Uint(n) => format!("uint{n}"),
        DynSolType::Int(n) => format!("int{n}"),
        DynSolType::Tuple(items) => {
            let inner: Vec<String> = items.iter().map(ty_short).collect();
            format!("({})", inner.join(","))
        }
        DynSolType::Array(inner) => format!("{}[]", ty_short(inner)),
        DynSolType::FixedArray(inner, n) => format!("{}[{}]", ty_short(inner), n),
        DynSolType::Function => "function".into(),
        // `CustomStruct` only materializes from EIP-712 typed-data
        // decoding, which the function panel (evmole-derived calldata
        // types) never produces — render its name rather than its fields.
        DynSolType::CustomStruct { name, .. } => name.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    fn dai() -> Address {
        address!("0x6B175474E89094C44Da98b954EedeAC495271d0F")
    }

    fn text_part(s: &str) -> HeadlinePart {
        HeadlinePart::Text(s.to_string())
    }

    #[test]
    fn splits_an_interpolated_recipient_out_of_the_sentence() {
        // The ERC-7730 shape that prompted this: the address is inside the
        // intent string, so it has to be lifted out to be coloured.
        assert_eq!(
            split_addresses("Transfer 800 DAI to 0x6B175474E89094C44Da98b954EedeAC495271d0F"),
            vec![text_part("Transfer 800 DAI to"), HeadlinePart::Addr(dai())],
        );
    }

    #[test]
    fn keeps_prose_on_both_sides_and_splits_several_addresses() {
        assert_eq!(
            split_addresses(
                "Approve 0x6B175474E89094C44Da98b954EedeAC495271d0F for \
                 0x6B175474E89094C44Da98b954EedeAC495271d0F now"
            ),
            vec![
                text_part("Approve"),
                HeadlinePart::Addr(dai()),
                text_part("for"),
                HeadlinePart::Addr(dai()),
                text_part("now"),
            ],
        );
    }

    #[test]
    fn a_sentence_without_an_address_is_one_run() {
        assert_eq!(
            split_addresses("Stake 1.5 ETH for 30 days"),
            vec![text_part("Stake 1.5 ETH for 30 days")],
        );
    }

    #[test]
    fn only_exactly_twenty_byte_hex_counts_as_an_address() {
        // A 32-byte hash is not a recipient — colouring it would imply the
        // wrong thing, so it stays prose. Same for a truncated address and a
        // bare `0x` in the middle of a word.
        let hash = format!("Commit 0x{}", "ab".repeat(32));
        assert_eq!(split_addresses(&hash), vec![text_part(&hash)]);
        assert_eq!(
            split_addresses("Send to 0x6B175474E8"),
            vec![text_part("Send to 0x6B175474E8")],
        );
        assert_eq!(
            split_addresses("costs 0x gas"),
            vec![text_part("costs 0x gas")]
        );
    }

    // ── already_said (headline / entry dedupe) ───────────────────────

    #[test]
    fn a_value_the_headline_spelled_out_is_not_repeated() {
        let said = Some("Transfer 800 DAI to 0x6B175474E89094C44Da98b954EedeAC495271d0F");
        assert!(already_said(said, "800 DAI"));
        // The descriptor interpolates a checksummed address; the entry may
        // carry a different casing of the same address.
        assert!(already_said(
            said,
            "0x6b175474e89094c44da98b954eedeac495271d0f"
        ));
        assert!(already_said(said, " 800 DAI "), "entries are trimmed first");
    }

    #[test]
    fn a_value_the_headline_did_not_say_survives() {
        let said = Some("Transfer 800 DAI to 0x6B175474E89094C44Da98b954EedeAC495271d0F");
        assert!(!already_said(
            said,
            "0x0000000000000000000000000000000000000001"
        ));
        assert!(!already_said(said, "2030-01-01"));
        assert!(!already_said(None, "800 DAI"), "no headline, nothing said");
        assert!(!already_said(said, ""));
    }

    #[test]
    fn substrings_of_larger_numbers_do_not_count_as_said() {
        // The bug this guards: "1" appearing inside "1000" would silently drop
        // a genuinely different amount from the review.
        let said = Some("Approve 1000 USDC for Aave");
        assert!(!already_said(said, "1"));
        assert!(!already_said(said, "100"));
        assert!(already_said(said, "1000"));
        // Bounded by punctuation, not just spaces.
        assert!(already_said(Some("Swap (1.5 ETH) now"), "1.5 ETH"));
    }

    #[test]
    fn an_address_alone_yields_no_empty_prose_runs() {
        assert_eq!(
            split_addresses("0x6B175474E89094C44Da98b954EedeAC495271d0F"),
            vec![HeadlinePart::Addr(dai())],
        );
        assert!(split_addresses("").is_empty());
        assert!(split_addresses("   ").is_empty());
    }
}
