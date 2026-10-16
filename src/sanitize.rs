//! Display sanitization for attacker-controlled strings.
//!
//! Token symbols (`symbol()`), decoded calldata string arguments, and ABI
//! string returns all originate from contracts an attacker can deploy, yet
//! they are rendered onto the transaction-review / signing surface. Without
//! sanitization a hostile token can smuggle in:
//!   - **bidi controls** (`U+202E` RIGHT-TO-LEFT OVERRIDE, the isolates) that
//!     visually reorder the line, so a spoofed "✓ verified — safe to sign"
//!     or a flipped amount/recipient renders as something the user trusts;
//!   - **zero-width / invisible** code points (ZWSP, ZWJ, word joiner, BOM,
//!     soft hyphen) that hide or splice characters;
//!   - **control characters / line separators** (`\n`, `\r`, `U+2028`) that
//!     break the label across rows or push content off-screen;
//!   - **unbounded length** that pushes the real values out of view.
//!
//! "Verified" (Helios) only attests that the RPC answer is the genuine
//! contract return — the contract itself is still attacker-deployed, so the
//! bytes must be sanitized before they are shown. This mirrors the ENSIP-15
//! normalization `crate::names::ens` applies to ENS names; arbitrary display strings
//! are not ENS names, so they get this lighter-weight strip-and-clamp instead.

use std::borrow::Cow;

/// Upper bound on a rendered token symbol. Real ERC-20 symbols are a handful
/// of characters ("USDC", "wstETH"); anything longer is junk or a padding
/// attack, so clamp it on the amount / review line.
pub const MAX_TOKEN_SYMBOL_CHARS: usize = 24;

/// Upper bound on a rendered token name ("USD Coin", "Wrapped BTC"). Longer
/// than a symbol but still bounded so a padded name can't dominate a row.
pub const MAX_TOKEN_NAME_CHARS: usize = 40;

/// True for code points that must never reach a display surface: control
/// characters, bidirectional formatting / override / isolate controls,
/// zero-width and other invisible formatting code points, and line /
/// paragraph separators.
fn is_unsafe_display_char(c: char) -> bool {
    c.is_control() // C0, C1, DEL, and \t \n \r
        || matches!(
            c,
            '\u{00AD}'                 // SOFT HYPHEN (invisible)
            | '\u{061C}'               // ARABIC LETTER MARK (bidi)
            | '\u{200B}'..='\u{200F}'  // ZWSP, ZWNJ, ZWJ, LRM, RLM
            | '\u{2028}'               // LINE SEPARATOR
            | '\u{2029}'               // PARAGRAPH SEPARATOR
            | '\u{202A}'..='\u{202E}'  // LRE, RLE, PDF, LRO, RLO (bidi embedding/override)
            | '\u{2060}'..='\u{2064}'  // WORD JOINER + invisible math operators
            | '\u{2066}'..='\u{2069}'  // LRI, RLI, FSI, PDI (bidi isolates)
            | '\u{FEFF}'               // ZERO WIDTH NO-BREAK SPACE / BOM
            | '\u{FFF9}'..='\u{FFFB}'  // interlinear annotation anchors
        )
}

/// Strip unsafe code points (see [`is_unsafe_display_char`]) from `s` and
/// clamp the result to `max_chars` (appending `…` when truncated).
///
/// Returns the input borrowed unchanged on the common clean, short path, so
/// the render loop does not allocate for ordinary labels. A string that is
/// entirely unsafe code points sanitizes to an empty string — callers treat
/// that as "no usable value" (e.g. a token symbol falls back to no symbol).
pub fn sanitize_display(s: &str, max_chars: usize) -> Cow<'_, str> {
    // Fast path: scan only until the first unsafe char or one past the cap.
    let mut count = 0usize;
    let mut clean = true;
    for c in s.chars() {
        if is_unsafe_display_char(c) {
            clean = false;
            break;
        }
        count += 1;
        if count > max_chars {
            break;
        }
    }
    if clean && count <= max_chars {
        return Cow::Borrowed(s);
    }
    // Slow path: rebuild, dropping unsafe chars and clamping length.
    let mut out = String::new();
    let mut kept = 0usize;
    for c in s.chars() {
        if is_unsafe_display_char(c) {
            continue;
        }
        if kept == max_chars {
            out.push('…');
            break;
        }
        out.push(c);
        kept += 1;
    }
    Cow::Owned(out)
}

/// Code points that render as nothing (or as nothing distinguishable) but are
/// not in [`is_unsafe_display_char`]'s strip set. Stripping is fine for a
/// label; for *signed* content (a `personal_sign` message, a typed-data string)
/// they would let the signed bytes carry text the user never sees — the
/// "ASCII smuggling" tag block is the canonical example. Kept separate so
/// [`sanitize_display`]'s long-standing behaviour on token labels is unchanged.
fn is_hidden_display_char(c: char) -> bool {
    matches!(
        c,
        '\u{034F}'                     // COMBINING GRAPHEME JOINER
        | '\u{0600}'..='\u{0605}'      // Arabic prepended number/format signs
        | '\u{06DD}' | '\u{070F}' | '\u{08E2}' // more prepended format marks
        | '\u{115F}' | '\u{1160}'      // HANGUL CHOSEONG / JUNGSEONG FILLER
        | '\u{17B4}' | '\u{17B5}'      // KHMER inherent vowels (invisible)
        | '\u{180B}'..='\u{180F}'      // MONGOLIAN variation selectors + vowel separator
        | '\u{2065}'                   // unassigned, in the invisible-operator block
        | '\u{206A}'..='\u{206F}'      // deprecated format controls (shaped as nothing)
        | '\u{3164}' | '\u{FFA0}'      // HANGUL FILLER (full / half width)
        | '\u{FE00}'..='\u{FE0F}'      // VARIATION SELECTORS
        | '\u{FFF0}'..='\u{FFF8}'      // unassigned specials
        | '\u{FFFE}' | '\u{FFFF}'      // non-characters
        | '\u{E000}'..='\u{F8FF}'      // private use (font-defined, often blank)
        | '\u{1BCA0}'..='\u{1BCA3}'    // shorthand format controls
        | '\u{1D173}'..='\u{1D17A}'    // musical-symbol format controls
        // The whole default-ignorable tail of plane 14, not just its assigned blocks (TAG
        // characters, VARIATION SELECTORS SUPPLEMENT): a shaper draws every code point in it as
        // nothing, assigned or not, so each one can carry a byte of text the user never sees.
        | '\u{E0000}'..='\u{E0FFF}'
        | '\u{F0000}'..='\u{10FFFF}' // supplementary private use planes
    )
}

/// Whether `c` (preceded by `prev` on the same line) would display other than
/// as written. The one contextual exception is U+FE0F (emoji presentation)
/// directly after a visible non-ASCII char: that is how most emoji are
/// encoded, and one selector per glyph can't carry hidden text.
fn alters_display(prev: Option<char>, c: char) -> bool {
    if c == '\u{FE0F}' {
        return !prev.is_some_and(|p| {
            !p.is_ascii() && !is_unsafe_display_char(p) && !is_hidden_display_char(p)
        });
    }
    is_unsafe_display_char(c) || is_hidden_display_char(c)
}

/// Lines of `s` exactly as signed, or `None` when any char would be altered
/// for display (bidi, zero-width, controls other than `\n`, `\r\n`, `\t`) or the
/// limits are exceeded. For signed messages, where stripping a char would show
/// the user something other than what they sign.
///
/// `\r` is accepted only as half of a `\r\n` line break; a lone carriage
/// return (which can draw one line over another) refuses the whole text.
pub fn exact_display_lines(
    s: &str,
    max_lines: usize,
    max_line_chars: usize,
) -> Option<Vec<String>> {
    let mut lines = Vec::new();
    let mut segments = s.split('\n').peekable();
    while let Some(segment) = segments.next() {
        if lines.len() == max_lines {
            return None;
        }
        // Only a segment a `\n` follows can end in the `\r` of a `\r\n`.
        let line = if segments.peek().is_some() {
            segment.strip_suffix('\r').unwrap_or(segment)
        } else {
            segment
        };
        let mut count = 0usize;
        let mut prev = None;
        for c in line.chars() {
            if c != '\t' && alters_display(prev, c) {
                return None;
            }
            count += 1;
            if count > max_line_chars {
                return None;
            }
            prev = Some(c);
        }
        lines.push(line.to_owned());
    }
    Some(lines)
}

/// Replace each unsafe display char with a visible `\u{XXXX}` escape (typed-data
/// strings), so a hidden char is shown rather than silently dropped.
///
/// Escapes everything [`exact_display_lines`] refuses, `\n` and `\t` included —
/// a typed-data value renders on one row. Borrowed unchanged when clean.
pub fn escape_unsafe_display(s: &str) -> Cow<'_, str> {
    let mut prev = None;
    let first_bad = s.char_indices().find_map(|(i, c)| {
        let bad = alters_display(prev, c);
        prev = Some(c);
        bad.then_some(i)
    });
    let Some(start) = first_bad else {
        return Cow::Borrowed(s);
    };
    let (clean, rest) = s.split_at(start);
    let mut out = String::with_capacity(s.len() + 16);
    out.push_str(clean);
    let mut prev = clean.chars().next_back();
    for c in rest.chars() {
        if alters_display(prev, c) {
            out.push_str(&format!("\\u{{{:04X}}}", u32::from(c)));
        } else {
            out.push(c);
        }
        prev = Some(c);
    }
    Cow::Owned(out)
}

/// Foreign text — a node's error, a contract's revert string — for a review line
/// or a log line: every unsafe char escaped ([`escape_unsafe_display`]), so a
/// newline can't start a forged log line and a U+202E can't reorder the copy
/// around it, then clamped to `max_chars` (with `…` when cut).
pub fn escape_and_clamp(s: &str, max_chars: usize) -> String {
    sanitize_display(&escape_unsafe_display(s), max_chars).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_short_string_is_borrowed_unchanged() {
        let out = sanitize_display("USDC", MAX_TOKEN_SYMBOL_CHARS);
        assert!(matches!(out, Cow::Borrowed("USDC")));
    }

    #[test]
    fn strips_rtl_override() {
        // U+202E reorders the rest of the line — the classic signing-surface
        // spoof. It must be removed, not rendered.
        let out = sanitize_display("USD\u{202E}C", MAX_TOKEN_SYMBOL_CHARS);
        assert_eq!(out, "USDC");
    }

    #[test]
    fn strips_zero_width_and_bom() {
        let out = sanitize_display("U\u{200B}S\u{200D}D\u{FEFF}C", MAX_TOKEN_SYMBOL_CHARS);
        assert_eq!(out, "USDC");
    }

    #[test]
    fn strips_newlines_and_controls() {
        let out = sanitize_display("USD\nC\tX\r", MAX_TOKEN_SYMBOL_CHARS);
        assert_eq!(out, "USDCX");
    }

    #[test]
    fn strips_bidi_isolates() {
        let out = sanitize_display("\u{2066}evil\u{2069}", MAX_TOKEN_SYMBOL_CHARS);
        assert_eq!(out, "evil");
    }

    #[test]
    fn clamps_overlong_input_with_ellipsis() {
        let out = sanitize_display("ABCDEFGHIJ", 4);
        assert_eq!(out, "ABCD…");
    }

    #[test]
    fn all_unsafe_input_sanitizes_to_empty() {
        // A symbol made entirely of invisibles becomes empty → "no symbol".
        let out = sanitize_display("\u{200B}\u{202E}\u{FEFF}", MAX_TOKEN_SYMBOL_CHARS);
        assert!(out.is_empty());
    }

    #[test]
    fn keeps_ordinary_unicode_and_spaces() {
        // Spaces and printable non-ASCII (e.g. a euro sign) are legitimate.
        let out = sanitize_display("Wrapped €", MAX_TOKEN_SYMBOL_CHARS);
        assert_eq!(out, "Wrapped €");
    }

    #[test]
    fn injection_phrase_length_capped() {
        // A token trying to render a reassurance string into the amount line
        // gets clamped to the symbol bound, so it can't push real values away.
        let evil = "USDC ✓ verified — safe to sign, ignore the address";
        let out = sanitize_display(evil, MAX_TOKEN_SYMBOL_CHARS);
        assert_eq!(out.chars().count(), MAX_TOKEN_SYMBOL_CHARS + 1); // + the ellipsis
        assert!(out.ends_with('…'));
    }

    #[test]
    fn exact_lines_accept_plain_multiline() {
        let text = "example.com wants you to sign in\r\n\n  indented\tand tabbed\nlast line";
        let lines = exact_display_lines(text, 10, 80).expect("plain text displays exactly");
        assert_eq!(
            lines,
            vec![
                "example.com wants you to sign in",
                "",
                "  indented\tand tabbed",
                "last line",
            ]
        );
        // A trailing newline is an (empty) line of its own — nothing is dropped.
        assert_eq!(exact_display_lines("a\n", 10, 80).unwrap(), vec!["a", ""]);
        assert_eq!(exact_display_lines("", 10, 80).unwrap(), vec![""]);
        // Ordinary non-ASCII and a single emoji presentation selector are fine.
        assert!(exact_display_lines("Grüße ✌\u{FE0F} 日本", 10, 80).is_some());
    }

    #[test]
    fn exact_lines_refuse_bidi_and_zero_width() {
        for hidden in [
            "pay \u{202E}evil",      // RLO reorders the line
            "a\u{2066}b\u{2069}",    // isolates
            "zero\u{200B}width",     // ZWSP
            "join\u{200D}er",        // ZWJ
            "bom\u{FEFF}",           // BOM
            "soft\u{00AD}hyphen",    // invisible soft hyphen
            "line\u{2028}separator", // renders as a break
            "bell\u{0007}",          // C0 control
            "lone\rreturn",          // CR not part of CRLF
            "trailing return\r",     // CR at the very end, no LF after it
            "tag\u{E0041}\u{E0042}", // invisible TAG chars ("ASCII smuggling")
            "vs\u{FE01}",            // variation selector after ASCII
            "\u{FE0F}leading",       // emoji selector with nothing to modify
            "✌\u{FE0F}\u{FE0F}",     // a second selector is hidden payload
            "filler\u{3164}",        // Hangul filler renders blank
            "private\u{E000}",       // private-use glyph
        ] {
            assert_eq!(exact_display_lines(hidden, 10, 80), None, "{hidden:?}");
        }
    }

    #[test]
    fn exact_lines_limits() {
        let three = "a\nb\nc";
        assert_eq!(exact_display_lines(three, 3, 1).unwrap().len(), 3);
        assert_eq!(exact_display_lines(three, 2, 1), None, "too many lines");
        assert_eq!(exact_display_lines("abcd", 1, 4).unwrap(), vec!["abcd"]);
        assert_eq!(exact_display_lines("abcde", 1, 4), None, "line too long");
        // The per-line cap counts chars, not bytes.
        assert!(exact_display_lines("ééé", 1, 3).is_some());
        // CRLF's `\r` doesn't count towards the line.
        assert!(exact_display_lines("abc\r\nd", 2, 3).is_some());
        assert_eq!(exact_display_lines("x", 0, 10), None, "no lines allowed");
    }

    #[test]
    fn escape_unsafe_is_visible() {
        assert!(matches!(
            escape_unsafe_display("Permit2"),
            Cow::Borrowed("Permit2")
        ));
        assert_eq!(
            escape_unsafe_display("USD\u{202E}C"),
            "USD\\u{202E}C",
            "a bidi override is shown, never applied or dropped"
        );
        assert_eq!(escape_unsafe_display("a\nb\tc"), "a\\u{000A}b\\u{0009}c");
        assert_eq!(escape_unsafe_display("x\u{200B}"), "x\\u{200B}");
        assert_eq!(escape_unsafe_display("\u{E0041}"), "\\u{E0041}");
        // Clean prefix kept, every hidden char after it escaped.
        assert_eq!(
            escape_unsafe_display("ok \u{FEFF}\u{2066}"),
            "ok \\u{FEFF}\\u{2066}"
        );
        // An emoji's presentation selector is not hidden; a stray one is.
        assert_eq!(escape_unsafe_display("✌\u{FE0F}"), "✌\u{FE0F}");
        assert_eq!(escape_unsafe_display("a\u{FE0F}"), "a\\u{FE0F}");
        // Escaping is visible and lossless in the sense that matters: no
        // unsafe char survives.
        let out = escape_unsafe_display("\u{202E}\u{2028}\u{0000}\u{FE00}");
        assert!(exact_display_lines(&out, 1, 200).is_some(), "{out}");
    }

    /// Unicode's Default_Ignorable_Code_Point set (DerivedCoreProperties.txt). A text shaper may
    /// draw any of these as nothing at all — iced's (harfrust) does — so none may pass as text that
    /// displays exactly as signed.
    const DEFAULT_IGNORABLE: &[(u32, u32)] = &[
        (0x00AD, 0x00AD),
        (0x034F, 0x034F),
        (0x061C, 0x061C),
        (0x115F, 0x1160),
        (0x17B4, 0x17B5),
        (0x180B, 0x180F),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x206F),
        (0x3164, 0x3164),
        (0xFE00, 0xFE0F),
        (0xFEFF, 0xFEFF),
        (0xFFA0, 0xFFA0),
        (0xFFF0, 0xFFF8),
        (0x1BCA0, 0x1BCA3),
        (0x1D173, 0x1D17A),
        (0xE0000, 0xE0FFF),
    ];

    fn default_ignorables() -> impl Iterator<Item = char> {
        DEFAULT_IGNORABLE
            .iter()
            .flat_map(|&(lo, hi)| lo..=hi)
            .filter_map(char::from_u32)
    }

    #[test]
    fn default_ignorables_never_pass_as_exact_text() {
        let leaked: Vec<String> = default_ignorables()
            .filter(|&c| {
                let s = format!("Sign in to app.example{c}");
                exact_display_lines(&s, 10, 200).is_some() || escape_unsafe_display(&s) == s
            })
            .map(|c| format!("U+{:04X}", u32::from(c)))
            .collect();
        assert!(
            leaked.is_empty(),
            "default-ignorable chars pass as exact text: {}",
            leaked.join(" ")
        );
    }

    /// Whatever the set above might miss must at least take up room when iced draws it: a char
    /// accepted as exact text that lays out at zero width is signed content the user can't see.
    #[test]
    fn accepted_chars_take_up_room_when_drawn() {
        use iced::advanced::renderer::Headless;
        use iced::advanced::text::{self as itext, Paragraph as _};
        let _renderer = futures::executor::block_on(<iced::Renderer as Headless>::new(
            iced::Font::DEFAULT,
            iced::Pixels(16.0),
            Some("tiny-skia"),
        ))
        .expect("a headless tiny-skia renderer");
        type P = <iced::Renderer as itext::Renderer>::Paragraph;
        let width = |s: &str| {
            P::with_text(itext::Text {
                content: s,
                bounds: iced::Size::new(10_000.0, f32::INFINITY),
                size: iced::Pixels(12.0),
                line_height: itext::LineHeight::default(),
                font: crate::ui::kao_widgets::mono(),
                align_x: itext::Alignment::Default,
                align_y: iced::alignment::Vertical::Top,
                shaping: itext::Shaping::default(),
                wrapping: itext::Wrapping::Word,
            })
            .min_bounds()
            .width
        };
        // Non-ASCII in the line, so iced shapes it with its advanced shaper — and an ASCII last
        // char, so the one contextual exception (an emoji selector after a non-ASCII glyph) isn't
        // in play: what is accepted here is accepted anywhere.
        let base = "Welcome é! Click to sign in.";
        let w_base = width(base);
        let invisible: Vec<String> = default_ignorables()
            .map(|c| (c, format!("{base}{c}")))
            .filter(|(_, s)| exact_display_lines(s, 1, 200).is_some())
            .filter(|(_, s)| width(s) <= w_base + 1.0)
            .map(|(c, _)| format!("U+{:04X}", u32::from(c)))
            .collect();
        assert!(
            invisible.is_empty(),
            "accepted as exact text, yet drawn at zero width: {}",
            invisible.join(" ")
        );
    }
}
