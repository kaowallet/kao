//! Decoded function call panel — read-only view that slots into the
//! send review screen between the gas row and the warning band.
//!
//! Renders four outcomes from `decode::render::DecodedCall`:
//! - **Loading** — small "decoding…" line; sized so the review card
//!   doesn't pop when the result lands.
//! - **Resolved / Ambiguous** — function name + per-arg rows
//!   (name : type → display value). ENS-resolved addresses get the
//!   resolved name above the chunked checksum address.
//! - **TypesOnly** — same per-arg rows but the header is the raw
//!   selector hex; no function name.
//! - **Unknown** — selector + "Unverified call" hint and truncated
//!   raw calldata.
//!
//! Warnings render as tinted strips. `AmbiguousSignature` rides *above*
//! the header — when several signatures collide on the same selector,
//! the title we show is provisional, so the warning has to land before
//! the user reads the name (and the title gets muted to match).
//! `InfiniteApproval` / `UnverifiedBytecode` qualify the call without
//! contradicting the title and stay in the strip below the args.
//!
//! `Empty` (native ETH transfer, no calldata) returns `None` — the
//! caller skips the panel and the divider so the review card stays the
//! same shape it had before clear signing landed.

use alloy::primitives::Address;
use iced::border::Radius;
use iced::widget::{Space, column, container, row, text};
use iced::{Background, Border, Element, Length, Padding};

use crate::decode::render::{ArgDisplay, DecodedArg, DecodedCall, ResolutionState, Warning};
use crate::ui::kao_theme::{KaoTheme, with_alpha};
use crate::ui::kao_widgets::{bold, mono};

/// Build the panel. Returns `None` when there's nothing to render
/// (native ETH transfer); the caller should also omit the surrounding
/// divider so the review card layout stays clean.
pub fn view<'a, M: 'a>(
    t: KaoTheme,
    decoded: Option<&'a DecodedCall>,
    loading: bool,
) -> Option<Element<'a, M>> {
    if loading {
        return Some(loading_view(t));
    }
    let decoded = decoded?;
    if matches!(decoded.state, ResolutionState::Empty) {
        return None;
    }
    Some(panel(t, decoded))
}

fn loading_view<'a, M: 'a>(t: KaoTheme) -> Element<'a, M> {
    container(
        text("(・_・;) decoding call…")
            .size(11)
            .color(t.sub)
            .font(mono()),
    )
    .padding(Padding::from([6, 0]))
    .width(Length::Fill)
    .into()
}

fn panel<'a, M: 'a>(t: KaoTheme, d: &'a DecodedCall) -> Element<'a, M> {
    // AmbiguousSignature warnings precede the header — they cast doubt
    // on the title itself, so the user must see them first. The other
    // warning kinds qualify the call without undermining the name and
    // ride below the arg rows in the foot strip.
    let mut col = column![].spacing(6);
    for w in &d.warnings {
        if matches!(w, Warning::AmbiguousSignature { .. }) {
            col = col.push(warning_strip(t, w));
        }
    }
    col = col.push(header(t, d));

    for arg in &d.args {
        col = col.push(arg_row(t, arg));
    }

    if d.args.is_empty() && matches!(d.state, ResolutionState::Unknown) {
        // No types at all — tell the user we couldn't decode and show
        // the raw calldata footprint so they can at least eyeball it.
        col = col.push(unknown_call_body(t, d));
    }

    let mut foot_warnings = d
        .warnings
        .iter()
        .filter(|w| !matches!(w, Warning::AmbiguousSignature { .. }))
        .peekable();
    if foot_warnings.peek().is_some() {
        col = col.push(Space::new().height(4));
        for w in foot_warnings {
            col = col.push(warning_strip(t, w));
        }
    }

    col.width(Length::Fill).into()
}

fn header<'a, M: 'a>(t: KaoTheme, d: &'a DecodedCall) -> Element<'a, M> {
    let label = text("Function").size(11).color(t.sub).font(bold());
    let title = match &d.function_name {
        Some(name) => format!("{}(…)", name),
        None => format!("0x{:02x}{:02x}{:02x}{:02x}", d.selector[0], d.selector[1], d.selector[2], d.selector[3]),
    };
    // For Ambiguous the title is just one of several plausible names —
    // mute it so the chunk doesn't visually claim authority. The banner
    // above carries the full candidate list. Resolved/TypesOnly/Unknown
    // keep the strong text color.
    let title_color = if matches!(d.state, ResolutionState::Ambiguous) {
        t.sub
    } else {
        t.text
    };
    let subtitle: Option<String> = match d.state {
        ResolutionState::Resolved => None,
        // Banner above the header conveys this; a duplicate subtitle
        // would just split the user's attention.
        ResolutionState::Ambiguous => None,
        ResolutionState::TypesOnly => Some("decoded from bytecode · no name".into()),
        ResolutionState::Unknown => Some("unverified call".into()),
        ResolutionState::Empty => None,
    };

    let mut col = column![
        label,
        Space::new().height(2),
        text(title).size(13).color(title_color).font(bold()),
    ]
    .spacing(0);
    if let Some(s) = subtitle {
        col = col.push(text(s).size(11).color(t.sub).font(mono()));
    }
    if !d.proxy_hops.is_empty() {
        // Just the fact, no implementation address. The user can't act
        // on the impl address (it changes when the proxy upgrades),
        // and showing 0x4350…02dd reads as a technical leak rather
        // than reassurance. The fact that bytecode was Helios-verified
        // is implicit — `UnverifiedBytecode` would have fired
        // otherwise.
        col = col.push(
            text("(via proxy)")
                .size(10)
                .color(t.sub)
                .font(mono()),
        );
    }
    col.into()
}

fn arg_row<'a, M: 'a>(t: KaoTheme, arg: &'a DecodedArg) -> Element<'a, M> {
    let name = arg
        .name
        .as_deref()
        .unwrap_or(""); // bytecode introspection rarely has names
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

    row![
        text(label).size(11).color(t.sub).font(mono()),
        Space::new().width(Length::Fill),
        text(value).size(12).color(t.text).font(mono()),
    ]
    .width(Length::Fill)
    .into()
}

fn unknown_call_body<'a, M: 'a>(t: KaoTheme, d: &'a DecodedCall) -> Element<'a, M> {
    // Show truncated raw calldata so the user has _something_ to
    // eyeball when no decoder applied.
    let hex = alloy::hex::encode(&d.raw_calldata);
    let display = format!("0x{}", truncate(&hex, 64));
    row![
        text("· raw").size(11).color(t.sub).font(mono()),
        Space::new().width(Length::Fill),
        text(display).size(11).color(t.sub).font(mono()),
    ]
    .width(Length::Fill)
    .into()
}

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
    };
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

fn truncate(s: &str, max: usize) -> std::borrow::Cow<'_, str> {
    if s.chars().count() <= max {
        return std::borrow::Cow::Borrowed(s);
    }
    let head: String = s.chars().take(max).collect();
    std::borrow::Cow::Owned(format!("{head}…"))
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
    }
}
