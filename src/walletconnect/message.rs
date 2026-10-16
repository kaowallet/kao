//! `personal_sign`: param decoding, the exact-display classification (text only when every char
//! displays exactly as signed), SIWE (EIP-4361) parsing and checks, and the EIP-191 digest.

use alloy::primitives::{Address, B256, Bytes, hex};

use super::MAX_MESSAGE_BYTES;
use super::types::*;
use crate::sanitize::{exact_display_lines, sanitize_display};

/// Shown as text at most this many lines …
const MAX_TEXT_LINES: usize = 200;
/// … of at most this many chars. Generous on purpose: common sign-in messages
/// (a terms-of-service sentence, a nonce paragraph) run one long line that the
/// review wraps; forcing those to hex would train users to sign blind. The byte
/// cap (`MAX_MESSAGE_BYTES`) is what bounds the payload.
const MAX_TEXT_LINE_CHARS: usize = 1024;
/// Display bound for SIWE fields (an authority is ≤ 253 chars + a port).
const MAX_SIWE_FIELD_CHARS: usize = 260;

const SIWE_HEADER_SUFFIX: &str = " wants you to sign in with your Ethereum account:";

/// "0x"+even valid hex → bytes; any other string → its UTF-8 bytes; non-string/empty/> cap → −32602.
///
/// The hex rule is MetaMask's (and every dapp library's): `0x`-prefixed hex is
/// the bytes, anything else is text. `0X…`, odd-length or non-hex after `0x`
/// is text, signed as its own UTF-8.
pub fn decode_personal_param(v: &serde_json::Value) -> Result<Bytes, Refusal> {
    let Some(s) = v.as_str() else {
        return Err(Refusal::invalid_params(
            "The message to sign must be a string.",
            "the dapp sent a message that isn't a string",
        ));
    };
    // Cheap upper bound before decoding: hex doubles the size, + "0x".
    if s.len() > 2 + 2 * MAX_MESSAGE_BYTES {
        return Err(too_large(s.len()));
    }
    let bytes = match s.strip_prefix("0x") {
        Some(h) if h.len() % 2 == 0 && h.bytes().all(|b| b.is_ascii_hexdigit()) => {
            hex::decode(h).unwrap_or_else(|_| s.as_bytes().to_vec())
        }
        _ => s.as_bytes().to_vec(),
    };
    if bytes.is_empty() {
        return Err(Refusal::invalid_params(
            "The message to sign is empty.",
            "the dapp asked to sign an empty message",
        ));
    }
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(too_large(bytes.len()));
    }
    Ok(Bytes::from(bytes))
}

fn too_large(len: usize) -> Refusal {
    Refusal::invalid_params(
        "The message to sign is too large.",
        format!(
            "the message is {len} bytes; Kao signs messages up to {} KiB",
            MAX_MESSAGE_BYTES / 1024
        ),
    )
}

/// Text only via `sanitize::exact_display_lines` (≤ 200 lines × 1024 chars); else Binary with reason.
///
/// Exactly 32 bytes is special: that is the shape of a Safe owner's
/// `eth_sign`-style confirmation of a safeTxHash, so it counts as text only
/// when it reads as plain words (see [`reads_as_words`]). Anything else that
/// is 32 bytes long is [`BinaryReason::OpaqueHash32`], whatever else is wrong
/// with it.
pub fn classify(bytes: &[u8]) -> MessageShape {
    let binary = |reason| MessageShape::Binary {
        len: bytes.len(),
        hex: format!("0x{}", hex::encode(bytes)),
        reason,
    };
    let text = std::str::from_utf8(bytes).ok();
    if bytes.len() == 32 && !text.is_some_and(reads_as_words) {
        return binary(BinaryReason::OpaqueHash32);
    }
    let Some(text) = text else {
        return binary(BinaryReason::NotUtf8);
    };
    match exact_display_lines(text, MAX_TEXT_LINES, MAX_TEXT_LINE_CHARS) {
        Some(lines) => MessageShape::Text { lines },
        // Still refused without limits ⇒ a char problem, not a size problem.
        None if exact_display_lines(text, usize::MAX, usize::MAX).is_none() => {
            binary(BinaryReason::HiddenCharacters)
        }
        None => binary(BinaryReason::TooLong),
    }
}

/// A 32-byte message that is plainly words: ASCII letters, digits and spaces
/// only, with at least one letter and one space. To turn a personal_sign into
/// an owner confirmation a dapp must grind its safeTxHash until the 32 bytes
/// look like this; 63 symbols plus a space costs ≈ 2^66 keccak evaluations,
/// where "any printable text" (95 symbols, ≈ 2^46) is a GPU-afternoon.
fn reads_as_words(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b' ')
        && text.bytes().any(|b| b == b' ')
        && text.bytes().any(|b| b.is_ascii_alphabetic())
}

/// EIP-4361 header + fields; tolerant; never panics.
///
/// Recognised only by the spec's header line (`[scheme://]domain wants you to
/// sign in with your Ethereum account:`); the next line is the address. Field
/// lines (`URI:`, `Chain ID:`, `Nonce:`, `Issued At:`, `Expiration Time:`) are
/// picked up wherever they appear — the first occurrence wins, even when it
/// doesn't parse. Values are clamped for display; an unparseable field is `None`.
pub fn parse_siwe(text: &str) -> Option<Siwe> {
    let mut lines = text.lines();
    let header = lines.next()?;
    let authority = header.strip_suffix(SIWE_HEADER_SUFFIX)?;
    // EIP-4361 allows an optional `scheme://` before the domain.
    let domain = authority
        .split_once("://")
        .map_or(authority, |(_, rest)| rest);
    if domain.is_empty() || domain.chars().any(char::is_whitespace) {
        return None;
    }
    let address = lines
        .next()
        .and_then(|l| crate::txbuilder::encode::parse_address(l).ok());

    let mut siwe = Siwe {
        domain: clamp(domain),
        address,
        uri: None,
        chain_id: None,
        nonce: None,
        issued_at: None,
        expiration: None,
    };
    let (mut uri, mut chain, mut nonce, mut issued, mut expiry) =
        (false, false, false, false, false);
    for line in lines {
        let Some((tag, value)) = line.split_once(": ") else {
            continue;
        };
        let value = value.trim();
        match tag {
            "URI" if !uri => {
                uri = true;
                siwe.uri = Some(clamp(value));
            }
            "Chain ID" if !chain => {
                chain = true;
                siwe.chain_id = value.parse().ok();
            }
            "Nonce" if !nonce => {
                nonce = true;
                siwe.nonce = Some(clamp(value));
            }
            "Issued At" if !issued => {
                issued = true;
                siwe.issued_at = Some(clamp(value));
            }
            "Expiration Time" if !expiry => {
                expiry = true;
                siwe.expiration = Some(clamp(value));
            }
            _ => {}
        }
    }
    Some(siwe)
}

fn clamp(s: &str) -> String {
    sanitize_display(s, MAX_SIWE_FIELD_CHARS).into_owned()
}

/// The SIWE message's claims against the request it arrived in. Every
/// "can't tell" counts as a mismatch: the banners err towards warning.
///
/// - `domain_mismatch`: the domain's host (IDN → punycode, port ignored) ≠ the
///   dapp's metadata host, or either is unknown, clamped or carries userinfo.
/// - `address_mismatch`: the address line is missing/unparseable or ≠ `from`.
/// - `chain_mismatch`: `Chain ID` is missing (it is mandatory) or ≠ the request chain.
pub fn check_siwe(siwe: Siwe, dapp_host: Option<&str>, from: Address, chain_id: u64) -> SiweCheck {
    let domain_mismatch = match (siwe_host(&siwe.domain).as_deref(), dapp_host) {
        (Some(s), Some(d)) => !s.eq_ignore_ascii_case(d),
        _ => true,
    };
    let address_mismatch = siwe.address != Some(from);
    let chain_mismatch = siwe.chain_id != Some(chain_id);
    SiweCheck {
        siwe,
        domain_mismatch,
        address_mismatch,
        chain_mismatch,
    }
}

/// Host of an RFC 3986 authority, normalised the way `DappLabel` normalises
/// the metadata URL (the `url` crate: lowercase, IDN → punycode). A clamped
/// domain (ends in "…") or one with userinfo (`good.example@evil.example`)
/// never matches.
fn siwe_host(domain: &str) -> Option<String> {
    if domain.ends_with('…') {
        return None;
    }
    let url = url::Url::parse(&format!("https://{domain}/")).ok()?;
    if !url.username().is_empty() || url.password().is_some() || url.path() != "/" {
        return None;
    }
    url.host_str().map(str::to_ascii_lowercase)
}

/// alloy `eip191_hash_message`.
pub fn eip191_hash(message: &[u8]) -> B256 {
    alloy::primitives::eip191_hash_message(message)
}

/// The ERC-8213 rows the signed-message history keeps for a signed `call` — the same rows, in the
/// same order and under the same labels, the review showed (`sign_review/wc.rs::erc8213_rows`):
/// personal → the EIP-191 digest; typed → the EIP-712 triple (+ the inner calldata digest for a
/// `SafeTx` that makes a call); a Safe identity → the SafeMessage triple its owners signed, then
/// the dapp's own payload — the EIP-191 digest, or the typed rows under the "Dapp …" labels.
/// Labels come from `crate::sign::digest`. A call that isn't a message has none.
///
/// The SafeMessage domain is the Safe's own chain — `chain_id`, the request's, is the same for
/// every request Kao admits for a Safe. A Safe on a chain Kao doesn't know has no domain to hash
/// (Kao never reviews such a request): only its inner rows are kept.
pub fn digest_rows(
    call: &WcCall,
    identity: &WcIdentity,
    chain_id: u64,
) -> Vec<crate::vault::DigestRow> {
    use crate::sign::digest::{
        DAPP_DOMAIN_HASH_LABEL, DAPP_EIP712_DIGEST_LABEL, DAPP_MESSAGE_HASH_LABEL,
        DOMAIN_HASH_LABEL, EIP191_DIGEST_LABEL, EIP712_DIGEST_LABEL, Eip712Digests,
        INNER_CALLDATA_DIGEST_LABEL, MESSAGE_HASH_LABEL, calldata_digest,
    };
    use crate::vault::DigestRow;

    const STANDARD: [&str; 3] = [EIP712_DIGEST_LABEL, DOMAIN_HASH_LABEL, MESSAGE_HASH_LABEL];
    const DAPP: [&str; 3] = [
        DAPP_EIP712_DIGEST_LABEL,
        DAPP_DOMAIN_HASH_LABEL,
        DAPP_MESSAGE_HASH_LABEL,
    ];
    fn push(rows: &mut Vec<DigestRow>, label: &str, hash: B256) {
        rows.push(DigestRow {
            label: label.to_string(),
            hash,
        });
    }
    fn triple(rows: &mut Vec<DigestRow>, d: &Eip712Digests, labels: [&str; 3]) {
        push(rows, labels[0], d.digest);
        push(rows, labels[1], d.domain_hash);
        push(rows, labels[2], d.message_hash);
    }
    fn typed(rows: &mut Vec<DigestRow>, t: &TypedRequest, labels: [&str; 3]) {
        triple(rows, &t.checked.digests, labels);
        if let TypedKind::SafeTx { data, .. } = &t.checked.kind
            && !data.is_empty()
        {
            push(rows, INNER_CALLDATA_DIGEST_LABEL, calldata_digest(data));
        }
    }

    // Every digest here commits to its chain already (EIP-712 domains), or to none (EIP-191).
    let _ = chain_id;
    // What a Safe's owners sign over: the EIP-191 digest, or the dapp's EIP-712 digest.
    let data_hash = match call {
        WcCall::PersonalSign(p) => eip191_hash(&p.message),
        WcCall::SignTypedData(t) => t.checked.digests.digest,
        WcCall::SendTransaction(_)
        | WcCall::SwitchChain { .. }
        | WcCall::Accounts
        | WcCall::ChainId => return Vec::new(),
    };
    let mut rows = Vec::new();
    let inner = match identity {
        WcIdentity::Eoa { .. } => STANDARD,
        WcIdentity::Safe {
            address,
            chain_id: safe_chain,
        } => {
            // What the owners sign first, then what it wraps — the order a signer checks them in.
            if let Some(chain) = crate::chain::Chain::from_chain_id(*safe_chain) {
                let signed = crate::cow::safe_sig::safe_message_digests(data_hash, *address, chain);
                triple(&mut rows, &signed, STANDARD);
            }
            DAPP
        }
    };
    match call {
        WcCall::SignTypedData(t) => typed(&mut rows, t, inner),
        _ => push(&mut rows, EIP191_DIGEST_LABEL, data_hash),
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, b256};
    use serde_json::json;

    const FROM: Address = address!("ab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb");

    fn siwe_text(domain: &str, addr: &str, chain: &str) -> String {
        format!(
            "{domain} wants you to sign in with your Ethereum account:\n{addr}\n\n\
             I accept the Terms of Service.\n\n\
             URI: https://{domain}/login\nVersion: 1\nChain ID: {chain}\n\
             Nonce: 32891756\nIssued At: 2021-09-30T16:25:24Z\n\
             Expiration Time: 2021-10-01T16:25:24Z"
        )
    }

    #[test]
    fn hex_vs_utf8_decoding() {
        // 0x + even hex ⇒ the bytes.
        assert_eq!(
            decode_personal_param(&json!("0x48656c6c6f")).unwrap(),
            Bytes::from_static(b"Hello")
        );
        assert_eq!(
            decode_personal_param(&json!("0xDEADbeef")).unwrap(),
            Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef])
        );
        // Anything else ⇒ the UTF-8 of the string itself.
        assert_eq!(
            decode_personal_param(&json!("Hello")).unwrap(),
            Bytes::from_static(b"Hello")
        );
        assert_eq!(
            decode_personal_param(&json!("0Xdead")).unwrap(),
            Bytes::from_static(b"0Xdead"),
            "only a lowercase 0x prefix marks hex"
        );
        assert_eq!(
            decode_personal_param(&json!("0xzz")).unwrap(),
            Bytes::from_static(b"0xzz")
        );
        assert_eq!(
            decode_personal_param(&json!("héllo")).unwrap().as_ref(),
            "héllo".as_bytes()
        );
        // Not a string.
        for v in [json!(42), json!(null), json!(["0x00"]), json!({"m": "x"})] {
            let e = decode_personal_param(&v).unwrap_err();
            assert_eq!(e.code, codes::INVALID_PARAMS, "{v}");
        }
        // The size cap applies to the decoded bytes.
        let max_hex = format!("0x{}", "ab".repeat(MAX_MESSAGE_BYTES));
        assert_eq!(
            decode_personal_param(&json!(max_hex)).unwrap().len(),
            MAX_MESSAGE_BYTES
        );
        let over = format!("0x{}", "ab".repeat(MAX_MESSAGE_BYTES + 1));
        assert_eq!(
            decode_personal_param(&json!(over)).unwrap_err().message,
            "The message to sign is too large."
        );
        let over_text = "a".repeat(MAX_MESSAGE_BYTES + 1);
        assert!(decode_personal_param(&json!(over_text)).is_err());
    }

    #[test]
    fn odd_hex_treated_as_text() {
        assert_eq!(
            decode_personal_param(&json!("0xabc")).unwrap(),
            Bytes::from_static(b"0xabc")
        );
    }

    #[test]
    fn empty_refused() {
        for v in [json!(""), json!("0x")] {
            let e = decode_personal_param(&v).unwrap_err();
            assert_eq!(e.code, codes::INVALID_PARAMS);
            assert_eq!(e.message, "The message to sign is empty.");
        }
    }

    #[test]
    fn binary_shape_for_non_utf8() {
        let bytes = [0xff, 0xfe, 0x00, 0x41];
        assert_eq!(
            classify(&bytes),
            MessageShape::Binary {
                len: 4,
                hex: "0xfffe0041".into(),
                reason: BinaryReason::NotUtf8,
            }
        );
    }

    #[test]
    fn hidden_chars_force_binary() {
        let msg = "Approve \u{202E}0001 USDC".as_bytes();
        match classify(msg) {
            MessageShape::Binary { reason, len, hex } => {
                assert_eq!(reason, BinaryReason::HiddenCharacters);
                assert_eq!(len, msg.len());
                assert_eq!(hex, format!("0x{}", alloy::primitives::hex::encode(msg)));
            }
            other => panic!("expected binary, got {other:?}"),
        }
        // Too long (but clean) is its own reason.
        let long = "x".repeat(MAX_TEXT_LINE_CHARS + 1);
        assert!(matches!(
            classify(long.as_bytes()),
            MessageShape::Binary {
                reason: BinaryReason::TooLong,
                ..
            }
        ));
        let many = "x\n".repeat(MAX_TEXT_LINES + 1);
        assert!(matches!(
            classify(many.as_bytes()),
            MessageShape::Binary {
                reason: BinaryReason::TooLong,
                ..
            }
        ));
    }

    #[test]
    fn opaque_32_detected() {
        // A safeTxHash-shaped payload.
        let hash = b256!("be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");
        assert!(matches!(
            classify(hash.as_slice()),
            MessageShape::Binary {
                len: 32,
                reason: BinaryReason::OpaqueHash32,
                ..
            }
        ));
        // 32 printable-but-not-plain bytes are still opaque: that is what a
        // ground hash would look like.
        let printable = b"aZ3$k9%Qx!r7&Lm2^Pw5*Tb8(Yc1)Ve4";
        assert_eq!(printable.len(), 32);
        assert!(matches!(
            classify(printable),
            MessageShape::Binary {
                reason: BinaryReason::OpaqueHash32,
                ..
            }
        ));
        // 31 random bytes are not the confirmation shape.
        assert!(matches!(
            classify(&hash.as_slice()[..31]),
            MessageShape::Binary {
                reason: BinaryReason::NotUtf8,
                ..
            }
        ));
        // 32 bytes of plain words are text.
        let words = b"Sign in to Example nonce 4242424";
        assert_eq!(words.len(), 32);
        assert_eq!(
            classify(words),
            MessageShape::Text {
                lines: vec!["Sign in to Example nonce 4242424".into()]
            }
        );
    }

    #[test]
    fn multiline_preserved_exactly() {
        let text = siwe_text("app.example", &FROM.to_checksum(None), "1");
        let MessageShape::Text { lines } = classify(text.as_bytes()) else {
            panic!("SIWE text should display as text");
        };
        assert_eq!(lines.join("\n"), text);
        assert_eq!(lines[2], "", "blank lines kept");
        let crlf = "line one\r\nline two";
        assert_eq!(
            classify(crlf.as_bytes()),
            MessageShape::Text {
                lines: vec!["line one".into(), "line two".into()]
            }
        );
    }

    #[test]
    fn siwe_parse_minimal() {
        let text = siwe_text("app.example", &FROM.to_checksum(None), "1");
        let s = parse_siwe(&text).expect("valid SIWE");
        assert_eq!(s.domain, "app.example");
        assert_eq!(s.address, Some(FROM));
        assert_eq!(s.uri.as_deref(), Some("https://app.example/login"));
        assert_eq!(s.chain_id, Some(1));
        assert_eq!(s.nonce.as_deref(), Some("32891756"));
        assert_eq!(s.issued_at.as_deref(), Some("2021-09-30T16:25:24Z"));
        assert_eq!(s.expiration.as_deref(), Some("2021-10-01T16:25:24Z"));

        // Header + address only, with a scheme and a port.
        let bare = format!(
            "https://app.example:8443 wants you to sign in with your Ethereum account:\n{}",
            FROM.to_checksum(None).to_lowercase()
        );
        let s = parse_siwe(&bare).expect("minimal SIWE");
        assert_eq!(s.domain, "app.example:8443");
        assert_eq!(s.address, Some(FROM));
        assert_eq!(s.chain_id, None);
        assert_eq!(s.uri, None);
    }

    #[test]
    fn siwe_parse_garbage_none() {
        for text in [
            "",
            "hello",
            "\n\n\n",
            " wants you to sign in with your Ethereum account:",
            "evil site wants you to sign in with your Ethereum account:\n0x00",
            "app.example wants you to sign in with your Ethereum account",
            "Please sign: app.example wants you to sign in with your Ethereum account:",
        ] {
            assert_eq!(parse_siwe(text), None, "{text:?}");
        }
        // A bad address or chain id is tolerated as missing, never a panic.
        let s = parse_siwe(
            "a.example wants you to sign in with your Ethereum account:\nnot-an-address\n\
             Chain ID: 0x1\nChain ID: 5",
        )
        .unwrap();
        assert_eq!(s.address, None);
        assert_eq!(
            s.chain_id, None,
            "the first Chain ID line wins, even if bad"
        );
        // A mixed-case address that fails EIP-55 is not trusted.
        let bad_sum = "a.example wants you to sign in with your Ethereum account:\n\
                       0xAB16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb";
        assert_eq!(parse_siwe(bad_sum).unwrap().address, None);
    }

    #[test]
    fn siwe_domain_mismatch_flagged() {
        let text = siwe_text("evil.example", &FROM.to_checksum(None), "1");
        let c = check_siwe(parse_siwe(&text).unwrap(), Some("app.example"), FROM, 1);
        assert!(c.domain_mismatch);
        assert!(!c.address_mismatch && !c.chain_mismatch);

        let ok = siwe_text("App.Example", &FROM.to_checksum(None), "1");
        let c = check_siwe(parse_siwe(&ok).unwrap(), Some("app.example"), FROM, 1);
        assert!(!c.domain_mismatch, "case-insensitive host match");

        // The port is ignored; an IDN compares as punycode, like DappLabel.
        let port = siwe_text("app.example:3000", &FROM.to_checksum(None), "1");
        let c = check_siwe(parse_siwe(&port).unwrap(), Some("app.example"), FROM, 1);
        assert!(!c.domain_mismatch);
        let idn = siwe_text("bücher.example", &FROM.to_checksum(None), "1");
        let c = check_siwe(
            parse_siwe(&idn).unwrap(),
            Some("xn--bcher-kva.example"),
            FROM,
            1,
        );
        assert!(!c.domain_mismatch);

        // An unknown dapp host, or userinfo tricks, never match.
        assert!(check_siwe(parse_siwe(&ok).unwrap(), None, FROM, 1).domain_mismatch);
        let userinfo = siwe_text("app.example@evil.example", &FROM.to_checksum(None), "1");
        let c = check_siwe(
            parse_siwe(&userinfo).unwrap(),
            Some("evil.example"),
            FROM,
            1,
        );
        assert!(c.domain_mismatch);

        // Address and chain.
        let other = address!("0000000000000000000000000000000000000001");
        let c = check_siwe(parse_siwe(&ok).unwrap(), Some("app.example"), other, 8453);
        assert!(c.address_mismatch && c.chain_mismatch);
        let no_chain = format!(
            "app.example wants you to sign in with your Ethereum account:\n{}",
            FROM.to_checksum(None)
        );
        let c = check_siwe(parse_siwe(&no_chain).unwrap(), Some("app.example"), FROM, 1);
        assert!(c.chain_mismatch, "Chain ID is mandatory in EIP-4361");
    }

    /// "ASCII smuggling" past the tag block: each byte of a second sentence rides in a
    /// default-ignorable char the shaper draws as nothing. It must not classify as text.
    #[test]
    fn smuggled_default_ignorables_are_not_text() {
        for offset in [0xE0080u32, 0xE0100] {
            let smuggled: String = "Welcome! Click to sign in."
                .chars()
                .chain(
                    "transfer all to 0xdead"
                        .bytes()
                        .filter_map(|b| char::from_u32(offset + u32::from(b))),
                )
                .collect();
            assert!(
                matches!(
                    classify(smuggled.as_bytes()),
                    MessageShape::Binary {
                        reason: BinaryReason::HiddenCharacters,
                        ..
                    }
                ),
                "U+{offset:X}…: smuggled text classified as displayable"
            );
        }
        assert!(matches!(
            classify("Sign in\u{206A}".as_bytes()),
            MessageShape::Binary {
                reason: BinaryReason::HiddenCharacters,
                ..
            }
        ));
    }

    #[test]
    fn eip191_hash_matches_the_prefixed_keccak() {
        assert_eq!(
            eip191_hash(b"Hello"),
            alloy::primitives::keccak256(b"\x19Ethereum Signed Message:\n5Hello")
        );
    }

    fn typed_call(raw: serde_json::Value, from: Address) -> WcCall {
        use crate::walletconnect::typed::{check_typed_data, parse_typed_param};
        let (td, raw) = parse_typed_param(&raw).expect("parses");
        let checked = check_typed_data(&raw, &td, 1, from).expect("checks");
        WcCall::SignTypedData(TypedRequest {
            from,
            typed: std::sync::Arc::new(td),
            checked,
        })
    }

    /// The history keeps the rows the review showed, in its order and under its labels: EIP-191
    /// for a message, the EIP-712 triple for typed data (+ the inner call of a SafeTx), and for a
    /// Safe the SafeMessage its owners signed first, then the dapp's own payload ("Dapp …").
    #[test]
    fn digest_rows_follow_the_review() {
        use crate::cow::safe_sig::safe_message_digests;
        use crate::sign::digest::*;
        use crate::vault::DigestRow;
        let labels = |rows: &[DigestRow]| rows.iter().map(|r| r.label.clone()).collect::<Vec<_>>();
        let eoa = WcIdentity::Eoa { address: FROM };
        let personal = WcCall::PersonalSign(PersonalSign {
            from: FROM,
            message: Bytes::from_static(b"hi"),
            shape: classify(b"hi"),
            siwe: None,
        });
        assert_eq!(
            digest_rows(&personal, &eoa, 1),
            vec![DigestRow {
                label: EIP191_DIGEST_LABEL.into(),
                hash: eip191_hash(b"hi"),
            }]
        );
        let mail = typed_call(crate::walletconnect::testkit::fixtures::mail(1), FROM);
        let WcCall::SignTypedData(t) = &mail else {
            unreachable!("built as typed data")
        };
        let dapp = t.checked.digests;
        let rows = digest_rows(&mail, &eoa, 1);
        assert_eq!(
            labels(&rows),
            [EIP712_DIGEST_LABEL, DOMAIN_HASH_LABEL, MESSAGE_HASH_LABEL]
        );
        assert_eq!(
            rows.iter().map(|r| r.hash).collect::<Vec<_>>(),
            [dapp.digest, dapp.domain_hash, dapp.message_hash]
        );

        let safe_address = Address::repeat_byte(0x5a);
        let safe = WcIdentity::Safe {
            address: safe_address,
            chain_id: 1,
        };
        let rows = digest_rows(&personal, &safe, 1);
        let signed = safe_message_digests(
            eip191_hash(b"hi"),
            safe_address,
            crate::chain::Chain::Mainnet,
        );
        assert_eq!(
            labels(&rows),
            [
                EIP712_DIGEST_LABEL,
                DOMAIN_HASH_LABEL,
                MESSAGE_HASH_LABEL,
                EIP191_DIGEST_LABEL
            ]
        );
        assert_eq!(
            rows.iter().map(|r| r.hash).collect::<Vec<_>>(),
            [
                signed.digest,
                signed.domain_hash,
                signed.message_hash,
                eip191_hash(b"hi")
            ]
        );
        let rows = digest_rows(&mail, &safe, 1);
        let signed = safe_message_digests(dapp.digest, safe_address, crate::chain::Chain::Mainnet);
        assert_eq!(
            labels(&rows),
            [
                EIP712_DIGEST_LABEL,
                DOMAIN_HASH_LABEL,
                MESSAGE_HASH_LABEL,
                DAPP_EIP712_DIGEST_LABEL,
                DAPP_DOMAIN_HASH_LABEL,
                DAPP_MESSAGE_HASH_LABEL
            ]
        );
        assert_eq!(rows[0].hash, signed.digest);
        assert_eq!(rows[3].hash, dapp.digest);

        // An owner confirming a SafeTx: the inner call's calldata digest too.
        let safe_tx = typed_call(
            crate::walletconnect::testkit::fixtures::safe_tx(
                safe_address,
                Address::repeat_byte(0x40),
                "0xdeadbeef",
            ),
            FROM,
        );
        let rows = digest_rows(&safe_tx, &eoa, 1);
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[3].label, INNER_CALLDATA_DIGEST_LABEL);
        assert_eq!(rows[3].hash, calldata_digest(&[0xde, 0xad, 0xbe, 0xef]));

        assert!(
            digest_rows(&WcCall::Accounts, &eoa, 1).is_empty(),
            "not a message"
        );
    }
}
