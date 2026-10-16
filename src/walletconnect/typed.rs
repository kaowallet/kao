//! EIP-712 from dapp JSON: parse caps, the domain/encodeType guards that keep render = hash = sign,
//! the ERC-8213 digests, the flat review model, and SafeTx / SafeMessage / Permit classification.
//!
//! The one object that is rendered, hashed and signed is alloy's [`TypedData`] parse. Everything
//! here exists to make that parse safe to trust: the declared `EIP712Domain` must be exactly the
//! domain alloy hashes (alloy ignores the declaration), the domain must carry no keys alloy drops,
//! and the type graph is bounded *before* alloy resolves it (its resolver is unmemoised, and it
//! parses tuple types EIP-712 doesn't have).

use std::collections::BTreeMap;

use alloy::dyn_abi::{DynSolValue, Eip712Types, TypedData};
use alloy::primitives::{Address, Bytes, U256, hex};

use super::types::*;
use super::{MAX_TYPED_DATA_BYTES, MAX_TYPED_JSON_DEPTH, MAX_TYPED_ROWS, MAX_TYPED_TYPES};
use crate::sanitize::{escape_unsafe_display, sanitize_display};
use crate::sign::digest::Eip712Digests;
use crate::sign::typed::{TypedDataModel, TypedRow, TypedValue};

const SAFE_TX_TYPE: &str = "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)";
const SAFE_TX_TYPE_LEGACY: &str = "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 dataGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)";
const SAFE_MESSAGE_TYPE: &str = "SafeMessage(bytes message)";

const PERMIT_EIP2612_TYPE: &str =
    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";
const PERMIT_DAI_TYPE: &str =
    "Permit(address holder,address spender,uint256 nonce,uint256 expiry,bool allowed)";
const PERMIT2_SINGLE_TYPE: &str = "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
const PERMIT2_BATCH_TYPE: &str = "PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
const PERMIT2_TRANSFER_TYPE: &str = "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)";
const PERMIT2_BATCH_TRANSFER_TYPE: &str = "PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)";
/// Witness variants append the dapp's own witness type, so only their fixed head is matched.
const PERMIT2_WITNESS_PREFIX: &str = "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,";
const PERMIT2_BATCH_WITNESS_PREFIX: &str = "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,";
const TOKEN_PERMISSIONS_TYPE: &str = "TokenPermissions(address token,uint256 amount)";

/// Seaport (1.4–1.6) order types: what OpenSea and seaport-js sign for a listing.
const SEAPORT_ORDER_TYPE: &str = "OrderComponents(address offerer,address zone,OfferItem[] offer,ConsiderationItem[] consideration,uint8 orderType,uint256 startTime,uint256 endTime,bytes32 zoneHash,uint256 salt,bytes32 conduitKey,uint256 counter)";
const SEAPORT_OFFER_ITEM_TYPE: &str = "OfferItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount)";
const SEAPORT_CONSIDERATION_ITEM_TYPE: &str = "ConsiderationItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount,address recipient)";
/// A bulk listing's primary type head: `tree` is `OrderComponents` under one `[2]` per tree level.
const SEAPORT_BULK_PREFIX: &str = "BulkOrder(OrderComponents";

/// The keys alloy's `Eip712Domain` reads. Anything else in the dapp's domain is
/// silently dropped by alloy — and silently *hashed* by a wallet that honours
/// the declaration — so it is refused.
const DOMAIN_KEYS: &[&str] = &["name", "version", "chainId", "verifyingContract", "salt"];

/// Nodes in the resolved type tree (structs, leaves, array wrappers). alloy's
/// `Resolver::resolve` re-expands a shared type at every use, so a 33-type
/// "binary tree" declaration would be 2^33 nodes before a single message byte
/// is read. Real payloads (Seaport, Permit2, CoW) are a few dozen.
const MAX_TYPE_NODES: usize = 1024;
/// Array dimensions on one property type (`uint256[][]` is 2). A fixed-size dimension adds no work
/// the byte cap doesn't already bound (every element is spelled out in the JSON), so the tree of a
/// Seaport bulk listing of 17 to 32 orders (`OrderComponents[2][2][2][2][2]`) passes; dynamic
/// dimensions stay tight.
const MAX_ARRAY_DIMS: usize = 10;
const MAX_DYNAMIC_ARRAY_DIMS: usize = 4;
/// Structs inside the all-zero runs the review folds into one row, over the whole message. They
/// are hashed like every other struct but cost no row, so this keeps bounded the hashing the row
/// cap alone used to bound. It covers the padding of the tallest Seaport tree the dimension cap
/// allows (2^10 slots).
const MAX_HIDDEN_STRUCTS: usize = 1024;
/// A type or field name. Real ones are identifiers of a few dozen chars.
const MAX_IDENT_CHARS: usize = 128;

/// Display bounds for the review model.
const MAX_LABEL_SEGMENT_CHARS: usize = 48;
const MAX_LABEL_CHARS: usize = 120;
const MAX_STRING_VALUE_CHARS: usize = 256;
const MAX_DOMAIN_TEXT_CHARS: usize = 80;
const MAX_TYPE_NAME_CHARS: usize = 64;
/// Amounts at or above 2^128 base units are "unlimited" in any meaningful
/// sense (`type(uint160).max` / `type(uint256).max` in practice).
const UNLIMITED_FROM_BITS: usize = 128;

fn malformed(detail: impl Into<String>) -> Refusal {
    Refusal::invalid_params("Typed data is malformed.", detail)
}

fn too_large(detail: impl Into<String>) -> Refusal {
    Refusal::invalid_params("Typed data is too large.", detail)
}

/// Object or JSON string; ≤ MAX_TYPED_DATA_BYTES; JSON depth ≤ 32; ≤ 64 types. Returns the parse and the
/// raw object (needed to detect unknown domain keys alloy drops).
pub fn parse_typed_param(
    raw: &serde_json::Value,
) -> Result<(TypedData, serde_json::Value), Refusal> {
    let obj = match raw {
        serde_json::Value::String(s) => {
            if s.len() > MAX_TYPED_DATA_BYTES {
                return Err(too_large(format!("{} bytes of typed data", s.len())));
            }
            // serde_json's own recursion limit (128) bounds the parse.
            serde_json::from_str::<serde_json::Value>(s)
                .map_err(|_| malformed("the typed data string isn't JSON"))?
        }
        serde_json::Value::Object(_) => {
            // Depth first: it bounds the serializer's recursion in the size check.
            if exceeds_depth(raw, MAX_TYPED_JSON_DEPTH) {
                return Err(too_large("the typed data is nested too deeply"));
            }
            if !fits_serialized(raw, MAX_TYPED_DATA_BYTES) {
                return Err(too_large("the typed data is over 256 KiB"));
            }
            raw.clone()
        }
        _ => return Err(malformed("typed data must be an object or a JSON string")),
    };
    if !obj.is_object() {
        return Err(malformed("typed data must be a JSON object"));
    }
    if exceeds_depth(&obj, MAX_TYPED_JSON_DEPTH) {
        return Err(too_large("the typed data is nested too deeply"));
    }
    let types = obj
        .get("types")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| malformed("typed data has no `types` object"))?;
    if types.len() > MAX_TYPED_TYPES {
        return Err(too_large(format!("{} declared types", types.len())));
    }
    let td: TypedData = serde_json::from_value(obj.clone())
        .map_err(|_| malformed("the typed data doesn't parse as EIP-712"))?;
    guard_types(&td)?;
    Ok((td, obj))
}

/// True when any array/object in `v` sits deeper than `max` (the root is depth 1).
/// Iterative, so a hostile nesting can't exhaust the stack here.
fn exceeds_depth(v: &serde_json::Value, max: usize) -> bool {
    let mut stack = vec![(v, 1usize)];
    while let Some((v, depth)) = stack.pop() {
        let is_container = matches!(
            v,
            serde_json::Value::Array(_) | serde_json::Value::Object(_)
        );
        if is_container && depth > max {
            return true;
        }
        match v {
            serde_json::Value::Array(a) => stack.extend(a.iter().map(|c| (c, depth + 1))),
            serde_json::Value::Object(o) => stack.extend(o.values().map(|c| (c, depth + 1))),
            _ => {}
        }
    }
    false
}

/// Whether `v` serializes to at most `limit` bytes, stopping as soon as it doesn't.
fn fits_serialized(v: &serde_json::Value, limit: usize) -> bool {
    struct Capped {
        left: usize,
    }
    impl std::io::Write for Capped {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if buf.len() > self.left {
                return Err(std::io::Error::other("over the cap"));
            }
            self.left -= buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Capped { left: limit }, v).is_ok()
}

/// Bounds the declared type graph before anything asks alloy to resolve,
/// coerce or hash it: type count, identifier lengths, array dimensions, no
/// tuple types (EIP-712 has none; alloy parses `(uint256,address)` into a
/// value its own encoder can't type), no cycles, and a resolved-tree size cap.
fn guard_types(td: &TypedData) -> Result<(), Refusal> {
    let types = Eip712Types::from(&td.resolver);
    if types.len() > MAX_TYPED_TYPES {
        return Err(too_large(format!("{} declared types", types.len())));
    }
    for (name, props) in types.iter() {
        if name.chars().count() > MAX_IDENT_CHARS {
            return Err(too_large("a type name is too long"));
        }
        for p in props {
            if p.name().chars().count() > MAX_IDENT_CHARS
                || p.type_name().chars().count() > MAX_IDENT_CHARS
            {
                return Err(too_large("a field name or type is too long"));
            }
            if p.type_name().contains('(') {
                return Err(Refusal::invalid_params(
                    "Typed data uses tuple types, which EIP-712 doesn't define.",
                    "the typed data declares a tuple-typed field",
                ));
            }
            let ty = p.type_name();
            if ty.matches('[').count() > MAX_ARRAY_DIMS
                || ty.matches("[]").count() > MAX_DYNAMIC_ARRAY_DIMS
            {
                return Err(too_large("a field has too many array dimensions"));
            }
        }
    }
    let mut memo = BTreeMap::new();
    let mut path = Vec::new();
    match type_nodes(&types, &td.primary_type, &mut memo, &mut path) {
        Some(n) if n <= MAX_TYPE_NODES => Ok(()),
        Some(n) => Err(too_large(format!("the type tree expands to {n}+ nodes"))),
        None => Err(malformed("the typed data's types are recursive")),
    }
}

/// Size of `name`'s resolved tree, saturating just past the cap. `None` on a
/// cycle (alloy's resolver refuses those too). Recursion depth ≤ type count.
fn type_nodes<'a>(
    types: &'a Eip712Types,
    name: &'a str,
    memo: &mut BTreeMap<&'a str, usize>,
    path: &mut Vec<&'a str>,
) -> Option<usize> {
    let Some(props) = types.get(name) else {
        return Some(1); // a basic type (or an undeclared one alloy will refuse)
    };
    if let Some(n) = memo.get(name) {
        return Some(*n);
    }
    if path.contains(&name) {
        return None;
    }
    path.push(name);
    let mut total = 1usize;
    for p in props {
        let dims = p.type_name().matches('[').count();
        let inner = type_nodes(types, p.root_type_name(), memo, path)?;
        total = total.saturating_add(dims).saturating_add(inner);
        if total > MAX_TYPE_NODES {
            break;
        }
    }
    path.pop();
    memo.insert(name, total);
    Some(total)
}

/// Every typed-data guard (incl. the REQUIRED declared EIP712Domain == domain.encode_type(), so
/// what is rendered is what is hashed and signed), then the model + kind.
pub fn check_typed_data(
    raw: &serde_json::Value,
    td: &TypedData,
    request_chain: u64,
    from: Address,
) -> Result<CheckedTyped, Refusal> {
    if td.primary_type == "EIP712Domain" {
        // alloy hashes a 34-byte preimage for this, a Ledger 66 — and it signs
        // nothing but the domain. Never a legitimate request.
        return Err(Refusal::invalid_params(
            "Typed data can't use EIP712Domain as its primary type.",
            "the dapp asked to sign a bare EIP-712 domain",
        ));
    }
    if !td.resolver.contains_type_name(&td.primary_type) {
        return Err(Refusal::invalid_params(
            "Typed data's primary type isn't declared.",
            "the typed data's primaryType has no definition in `types`",
        ));
    }
    if !td.resolver.contains_type_name("EIP712Domain") {
        return Err(Refusal::invalid_params(
            "Typed data must declare its EIP712Domain type.",
            "the typed data has no EIP712Domain type",
        ));
    }
    guard_types(td)?;
    // alloy hashes `domain` by its own canonical layout and ignores the
    // declaration; a wallet that honours the declaration hashes something
    // else. Only when the two are the same string are they the same hash.
    let declared = td
        .resolver
        .encode_type("EIP712Domain")
        .map_err(|_| malformed("the EIP712Domain type doesn't resolve"))?;
    if declared != td.domain.encode_type() {
        return Err(Refusal::invalid_params(
            "Typed data's EIP712Domain type doesn't match its domain.",
            "the declared EIP712Domain fields differ from the domain values",
        ));
    }
    match raw.get("domain") {
        Some(serde_json::Value::Object(m))
            if m.keys().any(|k| !DOMAIN_KEYS.contains(&k.as_str())) =>
        {
            return Err(Refusal::invalid_params(
                "Typed data's domain has unknown fields.",
                "the domain carries fields EIP-712 doesn't define",
            ));
        }
        None | Some(serde_json::Value::Object(_)) => {}
        Some(_) => return Err(malformed("the typed data's domain isn't an object")),
    }
    let mut warnings = Vec::new();
    match td.domain.chain_id {
        Some(c) if c != U256::from(request_chain) => {
            return Err(Refusal::invalid_params(
                "Typed data is for a different chain than the request.",
                format!("the typed data names chain {c}; the request is on chain {request_chain}"),
            ));
        }
        Some(_) => {}
        None => warnings.push(TypedWarning::NoChainBinding),
    }
    let value = td
        .coerce()
        .map_err(|_| malformed("the message doesn't match its declared types"))?;
    // Rows before hashing: the row cap and the all-zero-run budget bound how many structs get hashed.
    let (model, exact) = model_from_value(td, &value, MAX_TYPED_ROWS)?;
    let digests = digests_of(td)?;
    let (kind, kind_warnings) = kind_of(td, &value, from);
    warnings.extend(kind_warnings);
    let domain = domain_summary(td);
    if !exact.is_empty() || domain.shortened() {
        warnings.push(TypedWarning::LongValuesSummarized);
    }
    Ok(CheckedTyped {
        primary_type: display_type_name(&td.primary_type),
        digests,
        domain,
        model,
        exact,
        kind,
        warnings,
    })
}

fn domain_summary(td: &TypedData) -> DomainSummary {
    let text =
        |s: &str| sanitize_display(&escape_unsafe_display(s), MAX_DOMAIN_TEXT_CHARS).into_owned();
    // The whole escaped string, when the summary had to shorten it.
    let exact = |s: &str| {
        let full = escape_unsafe_display(s);
        (full.chars().count() > MAX_DOMAIN_TEXT_CHARS).then(|| full.into_owned())
    };
    DomainSummary {
        name: td.domain.name.as_deref().map(text),
        version: td.domain.version.as_deref().map(text),
        chain_id: td.domain.chain_id.and_then(|c| u64::try_from(c).ok()),
        verifying_contract: td.domain.verifying_contract,
        salt: td.domain.salt,
        exact_name: td.domain.name.as_deref().and_then(exact),
        exact_version: td.domain.version.as_deref().and_then(exact),
    }
}

fn display_type_name(name: &str) -> String {
    sanitize_display(&escape_unsafe_display(name), MAX_TYPE_NAME_CHARS).into_owned()
}

/// from_parts(domain.separator(), hash_struct()) and assert == eip712_signing_hash().
pub fn digests_of(td: &TypedData) -> Result<Eip712Digests, Refusal> {
    if td.primary_type == "EIP712Domain" {
        return Err(Refusal::invalid_params(
            "Typed data can't use EIP712Domain as its primary type.",
            "the dapp asked to sign a bare EIP-712 domain",
        ));
    }
    guard_types(td)?;
    let hash_err = |_| malformed("the typed data couldn't be hashed");
    let message_hash = td.hash_struct().map_err(hash_err)?;
    let digests = Eip712Digests::from_parts(td.domain.separator(), message_hash);
    let signing = td.eip712_signing_hash().map_err(hash_err)?;
    if digests.digest != signing {
        tracing::error!("typed: ERC-8213 digest disagrees with alloy's signing hash");
        return Err(Refusal::failed(
            "the EIP-712 digest Kao would show differs from the one it would sign",
        ));
    }
    Ok(digests)
}

/// Dotted-path rows from `td.coerce()`; addresses → TypedRow::addr; uints decimal; bytes hex (> 64 chars
/// summarized "0x12345678…abcd (N bytes)" — the head is a whole 4-byte selector); strings via
/// `sanitize::escape_unsafe_display`. > max_rows ⇒ Err.
///
/// `check_typed_data` builds the model (and the kind) from its own single `coerce`; this standalone
/// form is for tests.
#[cfg(test)]
pub fn typed_model(
    td: &TypedData,
    max_rows: usize,
) -> Result<(TypedDataModel, bool /*summarized*/), Refusal> {
    guard_types(td)?;
    let value = td
        .coerce()
        .map_err(|_| malformed("the message doesn't match its declared types"))?;
    let (model, exact) = model_from_value(td, &value, max_rows)?;
    Ok((model, !exact.is_empty()))
}

/// The review model, and the full value behind each row it shortened.
fn model_from_value(
    td: &TypedData,
    value: &DynSolValue,
    max_rows: usize,
) -> Result<(TypedDataModel, Vec<(usize, ExactValue)>), Refusal> {
    let layout = layout_of(td);
    let mut w = Walker {
        rows: Vec::new(),
        max_rows,
        exact: Vec::new(),
        seaport_items: layout != Layout::Generic,
        hidden_structs: 0,
    };
    w.walk(String::new(), value)?;
    let headline = match layout {
        Layout::SeaportBulk => bulk_headline(value),
        Layout::Generic | Layout::SeaportOrder => None,
    };
    Ok((
        TypedDataModel {
            type_name: format!(
                "{} — EIP-712 typed data",
                display_type_name(&td.primary_type)
            ),
            headline,
            rows: w.rows,
        },
        w.exact,
    ))
}

/// How the review lays out a message. Only an exact encodeType match picks a Seaport layout, and
/// every layout shows every signed value: they differ in how many rows that takes, never in what is
/// shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    Generic,
    /// One Seaport order (primary type `OrderComponents`).
    SeaportOrder,
    /// A Seaport bulk listing: `BulkOrder(OrderComponents[2]…[2] tree)`, one signature for every
    /// order in the tree.
    SeaportBulk,
}

fn layout_of(td: &TypedData) -> Layout {
    let Ok(enc) = td.encode_type() else {
        return Layout::Generic;
    };
    // encodeType appends the referenced types sorted by name.
    if enc
        == format!("{SEAPORT_ORDER_TYPE}{SEAPORT_CONSIDERATION_ITEM_TYPE}{SEAPORT_OFFER_ITEM_TYPE}")
    {
        return Layout::SeaportOrder;
    }
    let referenced =
        format!("{SEAPORT_CONSIDERATION_ITEM_TYPE}{SEAPORT_OFFER_ITEM_TYPE}{SEAPORT_ORDER_TYPE}");
    let dims = enc
        .strip_prefix(SEAPORT_BULK_PREFIX)
        .and_then(|rest| rest.strip_suffix(referenced.as_str()))
        .and_then(|rest| rest.strip_suffix(" tree)"));
    match dims {
        Some(d) if !d.is_empty() && d.as_bytes().chunks(3).all(|c| c == b"[2]") => {
            Layout::SeaportBulk
        }
        _ => Layout::Generic,
    }
}

/// "One signature for 12 orders · 4 empty padding slots": a bulk listing signs every order in its
/// tree at once. Counted from the coerced value, like the rows.
fn bulk_headline(value: &DynSolValue) -> Option<String> {
    let (mut orders, mut padding) = (0usize, 0usize);
    let mut stack = vec![field(value, "tree")?];
    while let Some(v) = stack.pop() {
        match v {
            DynSolValue::FixedArray(items) => stack.extend(items),
            DynSolValue::CustomStruct { .. } if is_zero_value(v) => padding += 1,
            DynSolValue::CustomStruct { .. } => orders += 1,
            _ => return None,
        }
    }
    let count = |n: usize, what: &str| {
        if n == 1 {
            format!("1 {what}")
        } else {
            format!("{n} {what}s")
        }
    };
    let mut line = format!("One signature for {}", count(orders, "order"));
    if padding > 0 {
        line.push_str(&format!(" · {}", count(padding, "empty padding slot")));
    }
    Some(line)
}

/// The value is its type's EIP-712 zero: 0, false, the zero address, an all-zero `bytesN`, empty
/// `bytes` / `string` / dynamic array, or a fixed array or struct of nothing but such values. Given
/// the type, that pins the value exactly — so a row saying so shows all of it.
fn is_zero_value(v: &DynSolValue) -> bool {
    match v {
        DynSolValue::Address(a) => a.is_zero(),
        DynSolValue::Bool(b) => !*b,
        DynSolValue::Int(i, _) => i.is_zero(),
        DynSolValue::Uint(u, _) => u.is_zero(),
        // The whole word: it is what gets hashed, padding included.
        DynSolValue::FixedBytes(word, _) => word.is_zero(),
        DynSolValue::Function(f) => f.is_zero(),
        DynSolValue::Bytes(b) => b.is_empty(),
        DynSolValue::String(s) => s.is_empty(),
        DynSolValue::Array(items) => items.is_empty(),
        DynSolValue::FixedArray(items) | DynSolValue::Tuple(items) => {
            items.iter().all(is_zero_value)
        }
        DynSolValue::CustomStruct { tuple, .. } => tuple.iter().all(is_zero_value),
    }
}

/// Structs in `v`, `v` included.
fn structs_in(v: &DynSolValue) -> usize {
    match v {
        DynSolValue::CustomStruct { tuple, .. } => 1 + tuple.iter().map(structs_in).sum::<usize>(),
        DynSolValue::Array(items) | DynSolValue::FixedArray(items) | DynSolValue::Tuple(items) => {
            items.iter().map(structs_in).sum()
        }
        _ => 0,
    }
}

/// Array elements at their zero value, shown together as one row.
struct ZeroRun<'a> {
    /// The struct type of every slot (an array's elements share one type).
    type_name: &'a str,
    /// Struct-typed elements in the run, counting through nested fixed-size arrays.
    slots: usize,
    /// Every struct in the run, nested ones included: what hashing it costs.
    structs: usize,
}

impl<'a> ZeroRun<'a> {
    /// `v` as part of a run: a struct whose every field is zero, or a non-empty fixed-size array of
    /// such structs (through any number of fixed-size levels). Anything else — a dynamic array
    /// included, whose length the row couldn't show — is walked field by field.
    fn of(v: &'a DynSolValue) -> Option<Self> {
        match v {
            DynSolValue::CustomStruct { name, tuple, .. } if tuple.iter().all(is_zero_value) => {
                Some(Self {
                    type_name: name,
                    slots: 1,
                    structs: structs_in(v),
                })
            }
            DynSolValue::FixedArray(items) => {
                let mut run: Option<Self> = None;
                for item in items {
                    let next = Self::of(item)?;
                    run = Some(match run {
                        None => next,
                        Some(r) => r.and(next),
                    });
                }
                run
            }
            _ => None,
        }
    }

    fn and(self, next: Self) -> Self {
        Self {
            type_name: self.type_name,
            slots: self.slots.saturating_add(next.slots),
            structs: self.structs.saturating_add(next.structs),
        }
    }
}

struct Walker {
    rows: Vec<TypedRow>,
    max_rows: usize,
    /// `(row index, full value)` for each row shown shortened.
    exact: Vec<(usize, ExactValue)>,
    /// Show each Seaport offer / consideration item as one row of its numbers, its addresses as
    /// rows of their own. Only for typed data whose encodeType is exactly Seaport's.
    seaport_items: bool,
    /// Structs folded into all-zero rows so far.
    hidden_structs: usize,
}

impl Walker {
    fn push(&mut self, path: &str, value: TypedValue) -> Result<(), Refusal> {
        if self.rows.len() >= self.max_rows {
            return Err(Refusal::invalid_params(
                "Typed data is too large to review.",
                format!("more than {} fields to show", self.max_rows),
            ));
        }
        let label = if path.is_empty() { "(value)" } else { path };
        self.rows.push(TypedRow {
            label: clamp_label(label),
            value,
        });
        Ok(())
    }

    fn text(&mut self, path: &str, s: String) -> Result<(), Refusal> {
        self.push(path, TypedValue::Text(s))
    }

    /// A text row whose display may be shortened; `exact` is the full value behind it when it is.
    fn text_or_exact(
        &mut self,
        path: &str,
        (shown, exact): (String, Option<ExactValue>),
    ) -> Result<(), Refusal> {
        let index = self.rows.len();
        self.text(path, shown)?;
        if let Some(e) = exact {
            self.exact.push((index, e));
        }
        Ok(())
    }

    /// Values exactly as they were coerced — the encoding `hash_struct` hashes
    /// — never the raw JSON (which may carry keys the hash ignores).
    fn walk(&mut self, path: String, v: &DynSolValue) -> Result<(), Refusal> {
        match v {
            DynSolValue::Address(a) => self.push(&path, TypedValue::Addr(*a)),
            DynSolValue::Bool(b) => self.text(&path, b.to_string()),
            DynSolValue::Int(i, _) => self.text(&path, i.to_string()),
            DynSolValue::Uint(u, _) => self.text(&path, u.to_string()),
            DynSolValue::FixedBytes(word, size) => {
                let bytes = word.get(..*size).unwrap_or(word.as_slice());
                self.text_or_exact(&path, Self::bytes(bytes))
            }
            DynSolValue::Bytes(b) => self.text_or_exact(&path, Self::bytes(b)),
            DynSolValue::Function(f) => self.text(&path, format!("0x{}", hex::encode(f))),
            DynSolValue::String(s) => self.text_or_exact(&path, Self::string(s)),
            DynSolValue::Array(items) | DynSolValue::FixedArray(items) => {
                if items.is_empty() {
                    return self.text(&path, "[] (empty)".into());
                }
                let mut i = 0;
                while let Some(item) = items.get(i) {
                    let Some(mut run) = ZeroRun::of(item) else {
                        self.walk(format!("{path}[{i}]"), item)?;
                        i += 1;
                        continue;
                    };
                    let first = i;
                    i += 1;
                    while let Some(next) = items.get(i).and_then(ZeroRun::of) {
                        run = run.and(next);
                        i += 1;
                    }
                    self.zero_run(&path, first, i - 1, &run)?;
                }
                Ok(())
            }
            DynSolValue::CustomStruct {
                name,
                prop_names,
                tuple,
            } => {
                if self.seaport_items
                    && (name == "OfferItem" || name == "ConsiderationItem")
                    && self.seaport_item(&path, v)?
                {
                    return Ok(());
                }
                if tuple.is_empty() {
                    return self.text(&path, "{} (empty)".into());
                }
                for (name, item) in prop_names.iter().zip(tuple) {
                    self.walk(join(&path, name), item)?;
                }
                Ok(())
            }
            // EIP-712 has no tuples and `guard_types` refuses them; walked by
            // position anyway rather than dropped.
            DynSolValue::Tuple(items) => {
                for (i, item) in items.iter().enumerate() {
                    self.walk(join(&path, &i.to_string()), item)?;
                }
                Ok(())
            }
        }
    }

    /// Elements `first..=last` of the array at `path`, every one at its zero value: one row that
    /// says so (Seaport pads a bulk listing's tree with such orders). The hash is untouched — the
    /// row describes the coerced value exactly — but the structs it stands for are budgeted, since
    /// they no longer cost a row each.
    fn zero_run(
        &mut self,
        path: &str,
        first: usize,
        last: usize,
        run: &ZeroRun<'_>,
    ) -> Result<(), Refusal> {
        self.hidden_structs = self.hidden_structs.saturating_add(run.structs);
        if self.hidden_structs > MAX_HIDDEN_STRUCTS {
            return Err(Refusal::invalid_params(
                "Typed data is too large to review.",
                format!("more than {MAX_HIDDEN_STRUCTS} empty structs"),
            ));
        }
        let label = if first == last {
            format!("{path}[{first}]")
        } else {
            format!("{path}[{first}–{last}]")
        };
        let name = display_type_name(run.type_name);
        let value = if run.slots == 1 {
            format!("{name} — every field zero / empty")
        } else {
            format!("{} × {name} — every field zero / empty", run.slots)
        };
        self.text(&label, value)
    }

    /// A Seaport offer or consideration item: its item type, ids and amounts on one row, its token
    /// (unless the zero address, which the row then names) and recipient as address rows. Every
    /// field is shown, in fewer rows, so a bulk listing's real orders fit the row cap. `false`, with
    /// nothing pushed, when the struct isn't shaped as Seaport's.
    fn seaport_item(&mut self, path: &str, item: &DynSolValue) -> Result<bool, Refusal> {
        let (Some(item_type), Some(token), Some(id), Some(start), Some(end)) = (
            uint(field(item, "itemType")),
            addr(field(item, "token")),
            uint(field(item, "identifierOrCriteria")),
            uint(field(item, "startAmount")),
            uint(field(item, "endAmount")),
        ) else {
            return Ok(false);
        };
        let recipient = match field(item, "recipient") {
            None => None,
            Some(DynSolValue::Address(a)) => Some(*a),
            Some(_) => return Ok(false),
        };
        let kind = match u8::try_from(item_type) {
            Ok(0) => "NATIVE",
            Ok(1) => "ERC20",
            Ok(2) => "ERC721",
            Ok(3) => "ERC1155",
            Ok(4) => "ERC721_WITH_CRITERIA",
            Ok(5) => "ERC1155_WITH_CRITERIA",
            _ => "unknown item type",
        };
        let mut line = format!("{kind} (itemType {item_type})");
        if token.is_zero() {
            line.push_str(" · token: the zero address");
        }
        line.push_str(&format!(" · identifierOrCriteria {id}"));
        if start == end {
            line.push_str(&format!(" · startAmount = endAmount = {start}"));
        } else {
            line.push_str(&format!(" · startAmount {start} · endAmount {end}"));
        }
        self.text(path, line)?;
        if !token.is_zero() {
            self.push(&join(path, "token"), TypedValue::Addr(token))?;
        }
        if let Some(r) = recipient {
            self.push(&join(path, "recipient"), TypedValue::Addr(r))?;
        }
        Ok(true)
    }

    /// Up to 32 bytes whole; longer values shortened to their head — a whole 4-byte selector, so
    /// calldata still names its function — and tail, with the full bytes kept beside the row.
    fn bytes(b: &[u8]) -> (String, Option<ExactValue>) {
        if b.len() <= 32 {
            return (format!("0x{}", hex::encode(b)), None);
        }
        let head = b.get(..4).unwrap_or_default();
        let tail = b.get(b.len().saturating_sub(2)..).unwrap_or_default();
        let shown = format!(
            "0x{}…{} ({} bytes)",
            hex::encode(head),
            hex::encode(tail),
            b.len()
        );
        (shown, Some(ExactValue::Bytes(Bytes::copy_from_slice(b))))
    }

    fn string(s: &str) -> (String, Option<ExactValue>) {
        let escaped = escape_unsafe_display(s);
        let chars = escaped.chars().count();
        if chars <= MAX_STRING_VALUE_CHARS {
            return (escaped.into_owned(), None);
        }
        let head: String = escaped.chars().take(MAX_STRING_VALUE_CHARS).collect();
        (
            format!("{head}… ({chars} chars)"),
            Some(ExactValue::Text(escaped.into_owned())),
        )
    }
}

fn join(path: &str, name: &str) -> String {
    let escaped = escape_unsafe_display(name);
    let segment = sanitize_display(&escaped, MAX_LABEL_SEGMENT_CHARS);
    if path.is_empty() {
        segment.into_owned()
    } else {
        format!("{path}.{segment}")
    }
}

/// Keep the end of an over-long path: the leaf name is the informative part.
fn clamp_label(label: &str) -> String {
    let n = label.chars().count();
    if n <= MAX_LABEL_CHARS {
        return label.to_owned();
    }
    let tail: String = label.chars().skip(n - (MAX_LABEL_CHARS - 1)).collect();
    format!("…{tail}")
}

/// SafeTx / SafeMessage by exact primary encodeType (signing one IS an owner
/// confirmation), then the allowance primitives (EIP-2612, DAI, Permit2).
///
/// Expects typed data that passed [`check_typed_data`] (coercible); anything
/// that can't be coerced is `Generic` — `check_typed_data` refuses it first.
#[cfg(test)]
fn classify_kind(td: &TypedData, from: Address) -> (TypedKind, Vec<TypedWarning>) {
    if guard_types(td).is_err() {
        return (TypedKind::Generic, Vec::new());
    }
    match td.coerce() {
        Ok(value) => kind_of(td, &value, from),
        Err(_) => (TypedKind::Generic, Vec::new()),
    }
}

fn kind_of(td: &TypedData, msg: &DynSolValue, from: Address) -> (TypedKind, Vec<TypedWarning>) {
    let Ok(enc) = td.encode_type() else {
        return (TypedKind::Generic, Vec::new());
    };
    let token = td.domain.verifying_contract.unwrap_or_default();
    let mut warnings = Vec::new();
    let kind = if enc == SAFE_TX_TYPE || enc == SAFE_TX_TYPE_LEGACY {
        safe_tx(td, msg)
    } else if enc == SAFE_MESSAGE_TYPE {
        Some(TypedKind::SafeMessage {
            safe: td.domain.verifying_contract,
        })
    } else if enc == PERMIT_EIP2612_TYPE {
        if addr(field(msg, "owner")) != Some(from) {
            warnings.push(TypedWarning::PermitOwnerNotSigner);
        }
        let value = uint(field(msg, "value"));
        grant(
            "EIP-2612 Permit",
            field(msg, "spender"),
            value.map(|v| vec![(token, v)]),
            // The allowance itself never expires; `deadline` bounds only the signature.
            AllowanceExpiry::Never,
            timestamp(field(msg, "deadline")),
        )
    } else if enc == PERMIT_DAI_TYPE {
        if addr(field(msg, "holder")) != Some(from) {
            warnings.push(TypedWarning::PermitOwnerNotSigner);
        }
        let allowed = match field(msg, "allowed") {
            Some(DynSolValue::Bool(b)) => Some(*b),
            _ => None,
        };
        grant(
            "DAI Permit",
            field(msg, "spender"),
            allowed.map(|a| vec![(token, if a { U256::MAX } else { U256::ZERO })]),
            AllowanceExpiry::Never,
            None,
        )
    } else if enc == PERMIT2_SINGLE_TYPE {
        let details = field(msg, "details");
        grant(
            "Permit2 PermitSingle",
            field(msg, "spender"),
            token_amount(details, "token", "amount").map(|t| vec![t]),
            permit2_expiry(details.into_iter()),
            timestamp(field(msg, "sigDeadline")),
        )
    } else if enc == PERMIT2_BATCH_TYPE {
        let details = array(field(msg, "details"));
        grant(
            "Permit2 PermitBatch",
            field(msg, "spender"),
            details.and_then(|d| {
                d.iter()
                    .map(|x| token_amount(Some(x), "token", "amount"))
                    .collect()
            }),
            permit2_expiry(details.unwrap_or_default().iter()),
            timestamp(field(msg, "sigDeadline")),
        )
    } else if enc == PERMIT2_TRANSFER_TYPE
        || (enc.starts_with(PERMIT2_WITNESS_PREFIX) && enc.contains(TOKEN_PERMISSIONS_TYPE))
    {
        let kind = if enc == PERMIT2_TRANSFER_TYPE {
            "Permit2 PermitTransferFrom"
        } else {
            "Permit2 PermitWitnessTransferFrom"
        };
        grant(
            kind,
            field(msg, "spender"),
            token_amount(field(msg, "permitted"), "token", "amount").map(|t| vec![t]),
            // One-shot: the permit is spent or dead by its `deadline`.
            timestamp(field(msg, "deadline")).map_or(AllowanceExpiry::Never, AllowanceExpiry::At),
            None,
        )
    } else if enc == PERMIT2_BATCH_TRANSFER_TYPE
        || (enc.starts_with(PERMIT2_BATCH_WITNESS_PREFIX) && enc.contains(TOKEN_PERMISSIONS_TYPE))
    {
        let kind = if enc == PERMIT2_BATCH_TRANSFER_TYPE {
            "Permit2 PermitBatchTransferFrom"
        } else {
            "Permit2 PermitBatchWitnessTransferFrom"
        };
        grant(
            kind,
            field(msg, "spender"),
            array(field(msg, "permitted")).and_then(|p| {
                p.iter()
                    .map(|x| token_amount(Some(x), "token", "amount"))
                    .collect()
            }),
            timestamp(field(msg, "deadline")).map_or(AllowanceExpiry::Never, AllowanceExpiry::At),
            None,
        )
    } else {
        None
    };
    (kind.unwrap_or(TypedKind::Generic), warnings)
}

fn safe_tx(td: &TypedData, msg: &DynSolValue) -> Option<TypedKind> {
    let operation = uint(field(msg, "operation"))?;
    let data = match field(msg, "data")? {
        DynSolValue::Bytes(b) => Bytes::copy_from_slice(b),
        _ => return None,
    };
    Some(TypedKind::SafeTx {
        safe: td.domain.verifying_contract,
        to: addr(field(msg, "to"))?,
        value: uint(field(msg, "value"))?,
        data,
        operation: u8::try_from(operation).ok()?,
        safe_tx_gas: uint(field(msg, "safeTxGas"))?,
        // The legacy (< 1.0) encodeType names it `dataGas`.
        base_gas: uint(field(msg, "baseGas")).or_else(|| uint(field(msg, "dataGas")))?,
        gas_price: uint(field(msg, "gasPrice"))?,
        gas_token: addr(field(msg, "gasToken"))?,
        refund_receiver: addr(field(msg, "refundReceiver"))?,
        nonce: uint(field(msg, "nonce"))?,
    })
}

fn grant(
    kind: &'static str,
    spender: Option<&DynSolValue>,
    tokens: Option<Vec<(Address, U256)>>,
    expires: AllowanceExpiry,
    signature_deadline: Option<u64>,
) -> Option<TypedKind> {
    let spender = addr(spender)?;
    let tokens = tokens?;
    let unlimited = tokens
        .iter()
        .any(|(_, a)| a.bit_len() > UNLIMITED_FROM_BITS);
    Some(TypedKind::Allowance(AllowanceGrant {
        kind,
        spender,
        tokens,
        expires,
        signature_deadline,
        unlimited,
    }))
}

/// The soonest expiry across Permit2 AllowanceTransfer `PermitDetails`. An `expiration` of 0 is
/// Permit2's "this block" (stored as `block.timestamp`): the soonest of all, yet live when the
/// permit lands — not a date in 1970. No readable expiration at all is `Never`, as before.
fn permit2_expiry<'a>(details: impl Iterator<Item = &'a DynSolValue>) -> AllowanceExpiry {
    let mut soonest = AllowanceExpiry::Never;
    for d in details {
        match u64_of(field(d, "expiration")) {
            Some(0) => return AllowanceExpiry::SubmittingBlock,
            Some(t) if !matches!(soonest, AllowanceExpiry::At(s) if s <= t) => {
                soonest = AllowanceExpiry::At(t);
            }
            Some(_) | None => {}
        }
    }
    soonest
}

/// A uint timestamp, saturated to `u64::MAX` (`type(uint256).max` is a common "no deadline").
fn timestamp(v: Option<&DynSolValue>) -> Option<u64> {
    uint(v).map(|u| u64::try_from(u).unwrap_or(u64::MAX))
}

fn field<'a>(v: &'a DynSolValue, name: &str) -> Option<&'a DynSolValue> {
    match v {
        DynSolValue::CustomStruct {
            prop_names, tuple, ..
        } => prop_names
            .iter()
            .position(|n| n == name)
            .and_then(|i| tuple.get(i)),
        _ => None,
    }
}

fn addr(v: Option<&DynSolValue>) -> Option<Address> {
    match v? {
        DynSolValue::Address(a) => Some(*a),
        _ => None,
    }
}

fn uint(v: Option<&DynSolValue>) -> Option<U256> {
    match v? {
        DynSolValue::Uint(u, _) => Some(*u),
        _ => None,
    }
}

fn u64_of(v: Option<&DynSolValue>) -> Option<u64> {
    uint(v).and_then(|u| u64::try_from(u).ok())
}

fn array(v: Option<&DynSolValue>) -> Option<&[DynSolValue]> {
    match v? {
        DynSolValue::Array(items) | DynSolValue::FixedArray(items) => Some(items),
        _ => None,
    }
}

fn token_amount(v: Option<&DynSolValue>, token: &str, amount: &str) -> Option<(Address, U256)> {
    let v = v?;
    Some((addr(field(v, token))?, uint(field(v, amount))?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approvals::PERMIT2;
    use alloy::primitives::{address, b256};
    use serde_json::{Value, json};

    const FROM: Address = address!("CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826");

    fn domain_type(fields: &[(&str, &str)]) -> Value {
        Value::Array(
            fields
                .iter()
                .map(|(name, ty)| json!({"name": name, "type": ty}))
                .collect(),
        )
    }

    /// The EIP-712 specification's own "Mail" example.
    fn mail() -> Value {
        json!({
            "types": {
                "EIP712Domain": domain_type(&[
                    ("name", "string"),
                    ("version", "string"),
                    ("chainId", "uint256"),
                    ("verifyingContract", "address"),
                ]),
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "wallet", "type": "address"}
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                    {"name": "to", "type": "Person"},
                    {"name": "contents", "type": "string"}
                ]
            },
            "primaryType": "Mail",
            "domain": {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
                "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
                "contents": "Hello, Bob!"
            }
        })
    }

    /// The ERC-8213 site's Permit2 `PermitTransferFrom` example, as dapp JSON
    /// (pinned digests in `sign::digest` tests).
    fn permit2_transfer() -> Value {
        json!({
            "types": {
                "EIP712Domain": domain_type(&[
                    ("name", "string"),
                    ("chainId", "uint256"),
                    ("verifyingContract", "address"),
                ]),
                "TokenPermissions": [
                    {"name": "token", "type": "address"},
                    {"name": "amount", "type": "uint256"}
                ],
                "PermitTransferFrom": [
                    {"name": "permitted", "type": "TokenPermissions"},
                    {"name": "spender", "type": "address"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint256"}
                ]
            },
            "primaryType": "PermitTransferFrom",
            "domain": {
                "name": "Permit2",
                "chainId": "0x1",
                "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            },
            "message": {
                "permitted": {
                    "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    "amount": "1000000000"
                },
                "spender": "0xE592427A0AEce92De3Edee1F18E0157C05861564",
                "nonce": "0",
                "deadline": "1893456000"
            }
        })
    }

    fn check(v: &Value, chain: u64) -> Result<CheckedTyped, Refusal> {
        let (td, raw) = parse_typed_param(v)?;
        check_typed_data(&raw, &td, chain, FROM)
    }

    fn refusal(v: &Value, chain: u64) -> Refusal {
        check(v, chain).expect_err("should be refused")
    }

    #[test]
    fn digests_match_eip712_mail_vector() {
        let c = check(&mail(), 1).unwrap();
        assert_eq!(
            c.digests.digest,
            b256!("be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2")
        );
        // The spec's domain separator and Mail struct hash.
        assert_eq!(
            c.digests.domain_hash,
            b256!("f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f")
        );
        assert_eq!(
            c.digests.message_hash,
            b256!("c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e")
        );
        assert_eq!(c.primary_type, "Mail");
        assert_eq!(c.kind, TypedKind::Generic);
        assert!(c.warnings.is_empty());
        // The same object passed as a JSON string parses identically.
        let as_string = Value::String(mail().to_string());
        assert_eq!(check(&as_string, 1).unwrap().digests, c.digests);
    }

    #[test]
    fn digests_match_permit2_vector() {
        let c = check(&permit2_transfer(), 1).unwrap();
        assert_eq!(
            c.digests.domain_hash,
            b256!("866a5aba21966af95d6c7ab78eb2b2fc913915c28be3b9aa07cc04ff903e3f28")
        );
        assert_eq!(
            c.digests.message_hash,
            b256!("7d1be9b8c7677c8cc6adba965260e35822632ef4eb35ddd5d6aafe26cb1ef882")
        );
        assert_eq!(
            c.digests.digest,
            b256!("01e5a64a608f03873d795fe77fe6bcd1a15692ee25bc02dd638b8fbc3753625c")
        );
        // digests_of is what the sign task re-derives: same answer, and equal
        // to alloy's signing hash.
        let (td, _) = parse_typed_param(&permit2_transfer()).unwrap();
        assert_eq!(digests_of(&td).unwrap(), c.digests);
        assert_eq!(td.eip712_signing_hash().unwrap(), c.digests.digest);
    }

    #[test]
    fn refuses_primary_type_eip712domain() {
        let mut v = mail();
        v["primaryType"] = json!("EIP712Domain");
        let e = refusal(&v, 1);
        assert_eq!(e.code, codes::INVALID_PARAMS);
        assert_eq!(
            e.message,
            "Typed data can't use EIP712Domain as its primary type."
        );
        let (td, _) = parse_typed_param(&v).unwrap();
        assert!(digests_of(&td).is_err(), "digests_of guards it too");
    }

    #[test]
    fn refuses_missing_domain_type() {
        let mut v = mail();
        v["types"].as_object_mut().unwrap().remove("EIP712Domain");
        assert_eq!(
            refusal(&v, 1).message,
            "Typed data must declare its EIP712Domain type."
        );
        // Undeclared primary type.
        let mut v = mail();
        v["primaryType"] = json!("Letter");
        assert_eq!(
            refusal(&v, 1).message,
            "Typed data's primary type isn't declared."
        );
    }

    #[test]
    fn refuses_domain_type_reordered() {
        let mut v = mail();
        v["types"]["EIP712Domain"] = domain_type(&[
            ("version", "string"),
            ("name", "string"),
            ("chainId", "uint256"),
            ("verifyingContract", "address"),
        ]);
        assert_eq!(
            refusal(&v, 1).message,
            "Typed data's EIP712Domain type doesn't match its domain."
        );
    }

    #[test]
    fn refuses_domain_type_extra_field() {
        // Declared but absent from the domain values.
        let mut v = mail();
        v["types"]["EIP712Domain"] = domain_type(&[
            ("name", "string"),
            ("version", "string"),
            ("chainId", "uint256"),
            ("verifyingContract", "address"),
            ("salt", "bytes32"),
        ]);
        assert_eq!(
            refusal(&v, 1).message,
            "Typed data's EIP712Domain type doesn't match its domain."
        );
        // A value present but not declared.
        let mut v = mail();
        v["domain"]["salt"] = json!(format!("0x{}", "11".repeat(32)));
        assert_eq!(
            refusal(&v, 1).message,
            "Typed data's EIP712Domain type doesn't match its domain."
        );
        // A wrongly-typed declaration (alloy hashes chainId as uint256).
        let mut v = mail();
        v["types"]["EIP712Domain"] = domain_type(&[
            ("name", "string"),
            ("version", "string"),
            ("chainId", "uint64"),
            ("verifyingContract", "address"),
        ]);
        assert!(check(&v, 1).is_err());
    }

    #[test]
    fn refuses_unknown_domain_key() {
        let mut v = mail();
        v["domain"]["extra"] = json!("ignored by alloy, hashed by others");
        let e = refusal(&v, 1);
        assert_eq!(e.message, "Typed data's domain has unknown fields.");
    }

    #[test]
    fn domain_chain_mismatch_refused() {
        let e = refusal(&mail(), 8453);
        assert_eq!(e.code, codes::INVALID_PARAMS);
        assert_eq!(
            e.message,
            "Typed data is for a different chain than the request."
        );
    }

    #[test]
    fn no_chain_binding_warns() {
        let mut v = mail();
        v["types"]["EIP712Domain"] = domain_type(&[
            ("name", "string"),
            ("version", "string"),
            ("verifyingContract", "address"),
        ]);
        v["domain"].as_object_mut().unwrap().remove("chainId");
        let c = check(&v, 8453).expect("no chainId is allowed, with a warning");
        assert_eq!(c.warnings, vec![TypedWarning::NoChainBinding]);
        assert_eq!(c.domain.chain_id, None);
    }

    /// A domain string the summary shortens is kept whole beside it — the domain is signed too.
    #[test]
    fn long_domain_strings_stay_reviewable() {
        let long = format!("Ether Mail {}", "x".repeat(MAX_DOMAIN_TEXT_CHARS));
        let mut v = mail();
        v["domain"]["name"] = json!(long);
        let c = check(&v, 1).unwrap();
        assert!(c.domain.name.as_deref().is_some_and(|n| n.ends_with('…')));
        assert_eq!(c.domain.exact_name.as_deref(), Some(long.as_str()));
        assert_eq!(
            c.domain.exact_version, None,
            "a short version needs no exact copy"
        );
        assert!(c.warnings.contains(&TypedWarning::LongValuesSummarized));
        assert!(!check(&mail(), 1).unwrap().domain.shortened());
    }

    #[test]
    fn chain_id_hex_and_number_both_parse() {
        for chain in [json!(8453), json!("0x2105"), json!("8453")] {
            let mut v = mail();
            v["domain"]["chainId"] = chain.clone();
            let c = check(&v, 8453).unwrap_or_else(|e| panic!("{chain}: {e:?}"));
            assert_eq!(c.domain.chain_id, Some(8453), "{chain}");
        }
    }

    #[test]
    fn model_rows_come_from_coerced_value() {
        let mut v = mail();
        // A key the types don't declare is ignored by the hash — and must not
        // be shown either.
        v["message"]["bcc"] = json!("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB");
        let c = check(&v, 1).unwrap();
        let labels: Vec<_> = c.model.rows.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "from.name",
                "from.wallet",
                "to.name",
                "to.wallet",
                "contents"
            ]
        );
        assert_eq!(c.model.rows[0].value, TypedValue::Text("Cow".into()));
        assert_eq!(
            c.model.rows[1].value,
            TypedValue::Addr(address!("CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"))
        );
        assert_eq!(c.model.type_name, "Mail — EIP-712 typed data");
        // Numbers are rendered as the coerced decimal, whatever the JSON spelling.
        let c = check(&permit2_transfer(), 1).unwrap();
        let amount = c
            .model
            .rows
            .iter()
            .find(|r| r.label == "permitted.amount")
            .unwrap();
        assert_eq!(amount.value, TypedValue::Text("1000000000".into()));
        // Arrays are indexed; empty ones get a row of their own.
        let (td, _) = parse_typed_param(&json!({
            "types": {
                "EIP712Domain": [],
                "Batch": [
                    {"name": "items", "type": "uint8[]"},
                    {"name": "none", "type": "address[]"},
                    {"name": "flag", "type": "bool"},
                    {"name": "delta", "type": "int256"}
                ]
            },
            "primaryType": "Batch",
            "domain": {},
            "message": {"items": [1, "2"], "none": [], "flag": true, "delta": "-5"}
        }))
        .unwrap();
        let (m, summarized) = typed_model(&td, MAX_TYPED_ROWS).unwrap();
        let rows: Vec<_> = m
            .rows
            .iter()
            .map(|r| (r.label.as_str(), r.value.clone()))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("items[0]", TypedValue::Text("1".into())),
                ("items[1]", TypedValue::Text("2".into())),
                ("none", TypedValue::Text("[] (empty)".into())),
                ("flag", TypedValue::Text("true".into())),
                ("delta", TypedValue::Text("-5".into())),
            ]
        );
        assert!(!summarized);
    }

    #[test]
    fn typed_strings_escaped_visibly() {
        let mut v = mail();
        v["message"]["contents"] = json!("Pay \u{202E}0001\nnow\u{200B}");
        v["domain"]["name"] = json!("Ether\u{202E}Mail");
        // Field names are dapp-chosen too.
        v["types"]["Mail"][2]["name"] = json!("con\u{2066}tents");
        v["message"]["con\u{2066}tents"] = v["message"]["contents"].clone();
        let c = check(&v, 1).unwrap();
        let row = c.model.rows.last().unwrap();
        assert_eq!(row.label, "con\\u{2066}tents");
        assert_eq!(
            row.value,
            TypedValue::Text("Pay \\u{202E}0001\\u{000A}now\\u{200B}".into())
        );
        assert_eq!(c.domain.name.as_deref(), Some("Ether\\u{202E}Mail"));
        for r in &c.model.rows {
            assert!(crate::sanitize::exact_display_lines(&r.label, 1, 1000).is_some());
            if let TypedValue::Text(t) = &r.value {
                assert!(
                    crate::sanitize::exact_display_lines(t, 1, 1000).is_some(),
                    "{t}"
                );
            }
        }
    }

    #[test]
    fn deep_or_huge_typed_data_refused() {
        // JSON depth.
        let mut deep = json!(1);
        for _ in 0..MAX_TYPED_JSON_DEPTH {
            deep = json!([deep]);
        }
        let mut v = mail();
        v["message"]["contents"] = deep;
        let e = parse_typed_param(&v).unwrap_err();
        assert_eq!(e.message, "Typed data is too large.");
        assert!(parse_typed_param(&Value::String(v.to_string())).is_err());

        // Byte size, object and string form.
        let mut v = mail();
        v["message"]["contents"] = json!("x".repeat(MAX_TYPED_DATA_BYTES));
        assert_eq!(
            parse_typed_param(&v).unwrap_err().message,
            "Typed data is too large."
        );
        assert_eq!(
            parse_typed_param(&Value::String(v.to_string()))
                .unwrap_err()
                .message,
            "Typed data is too large."
        );

        // Type count.
        let mut v = mail();
        let types = v["types"].as_object_mut().unwrap();
        for i in 0..MAX_TYPED_TYPES {
            types.insert(format!("Pad{i}"), json!([{"name": "x", "type": "uint256"}]));
        }
        assert_eq!(
            parse_typed_param(&v).unwrap_err().message,
            "Typed data is too large."
        );

        // An exponential type tree: T0 has two T1s, T1 two T2s, … — 2^40 nodes
        // if anyone resolved it.
        let mut types = serde_json::Map::new();
        types.insert("EIP712Domain".into(), json!([]));
        for i in 0..40 {
            types.insert(
                format!("T{i}"),
                json!([
                    {"name": "a", "type": format!("T{}", i + 1)},
                    {"name": "b", "type": format!("T{}", i + 1)}
                ]),
            );
        }
        types.insert("T40".into(), json!([{"name": "x", "type": "uint8"}]));
        let bomb = json!({"types": types, "primaryType": "T0", "domain": {}, "message": {}});
        assert_eq!(
            parse_typed_param(&bomb).unwrap_err().message,
            "Typed data is too large."
        );

        // Row cap.
        let mut v = mail();
        v["types"]["Mail"][2]["type"] = json!("string[]");
        v["message"]["contents"] = json!(vec!["x"; MAX_TYPED_ROWS]);
        assert_eq!(refusal(&v, 1).message, "Typed data is too large to review.");
    }

    #[test]
    fn rows_over_cap_refused() {
        let (td, _) = parse_typed_param(&mail()).unwrap();
        assert_eq!(typed_model(&td, 5).unwrap().0.rows.len(), 5);
        let e = typed_model(&td, 4).unwrap_err();
        assert_eq!(e.code, codes::INVALID_PARAMS);
        assert_eq!(e.message, "Typed data is too large to review.");
    }

    /// Seaport bulk listings as seaport-js / OpenSea sign them: one `BulkOrder` whose `tree` is
    /// `OrderComponents[2]…[2]`, padded to a power of two with empty orders. Neither the tree's
    /// depth (5 dimensions from 17 listings) nor its padding may refuse a listing of a size a user
    /// lists in practice — and what is shown changes nothing that is hashed.
    #[test]
    fn seaport_bulk_listings_admitted() {
        use crate::walletconnect::testkit::fixtures;
        for royalty in [false, true] {
            for n in [2usize, 3, 5, 8, 11, 12, 13, 15, 16, 17, 20] {
                let v = fixtures::seaport_bulk_order(FROM, n, royalty, 1);
                let c = check(&v, 1).unwrap_or_else(|e| panic!("n={n} royalty={royalty}: {e:?}"));
                let (td, _) = parse_typed_param(&v).unwrap();
                assert_eq!(
                    c.digests.digest,
                    td.eip712_signing_hash().unwrap(),
                    "n={n} royalty={royalty}: the review hashes what alloy signs"
                );
                assert_eq!(c.kind, TypedKind::Generic);
            }
        }
    }

    fn rows_of(c: &CheckedTyped) -> Vec<(&str, TypedValue)> {
        c.model
            .rows
            .iter()
            .map(|r| (r.label.as_str(), r.value.clone()))
            .collect()
    }

    /// Every field of one OpenSea listing with a creator royalty, as the Seaport layout shows it
    /// under `p`: the items' numbers one row each, every address its own row.
    fn listing_rows(p: &str, i: usize) -> Vec<(String, TypedValue)> {
        use crate::walletconnect::testkit::fixtures::*;
        let text = |label: &str, v: String| (format!("{p}.{label}"), TypedValue::Text(v));
        let addr = |label: &str, a: Address| (format!("{p}.{label}"), TypedValue::Addr(a));
        let native = |wei: u128| {
            format!(
                "NATIVE (itemType 0) · token: the zero address · identifierOrCriteria 0 · \
                 startAmount = endAmount = {wei}"
            )
        };
        let salt = U256::from_str_radix(
            "360c6ebe0000000000000000000000000000000000000000a0e9cd8c4b2f6e0c",
            16,
        )
        .unwrap()
            + U256::from(i);
        vec![
            addr("offerer", FROM),
            addr("zone", address!("000056F7000000EcE9003ca63978907a00FFD100")),
            text(
                "offer[0]",
                format!(
                    "ERC721 (itemType 2) · identifierOrCriteria {} · startAmount = endAmount = 1",
                    1000 + i
                ),
            ),
            addr("offer[0].token", BAYC),
            text(
                "consideration[0]",
                native(LIST_PRICE - OPENSEA_FEE_WEI - ROYALTY_WEI),
            ),
            addr("consideration[0].recipient", FROM),
            text("consideration[1]", native(OPENSEA_FEE_WEI)),
            addr("consideration[1].recipient", OPENSEA_FEE),
            text("consideration[2]", native(ROYALTY_WEI)),
            addr("consideration[2].recipient", CREATOR_ROYALTY),
            text("orderType", "0".into()),
            text("startTime", "1728000000".into()),
            text("endTime", "1730592000".into()),
            text("zoneHash", format!("0x{}", "00".repeat(32))),
            text("salt", salt.to_string()),
            text(
                "conduitKey",
                "0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000".into(),
            ),
            text("counter", "0".into()),
        ]
    }

    /// A bulk listing's review: a headline saying how many orders the one signature lists, every
    /// field of every real order (items compacted, addresses as address rows), and each run of
    /// padding as a single row — at whatever tree level the run starts.
    #[test]
    fn seaport_bulk_review_shows_every_order_and_folds_the_padding() {
        use crate::walletconnect::testkit::fixtures;
        let c = check(&fixtures::seaport_bulk_order(FROM, 3, true, 1), 1).unwrap();
        assert_eq!(c.primary_type, "BulkOrder");
        assert_eq!(
            c.model.headline.as_deref(),
            Some("One signature for 3 orders · 1 empty padding slot")
        );
        let mut expected = Vec::new();
        for (i, p) in ["tree[0][0]", "tree[0][1]", "tree[1][0]"]
            .iter()
            .enumerate()
        {
            expected.extend(listing_rows(p, i));
        }
        expected.push((
            "tree[1][1]".into(),
            TypedValue::Text("OrderComponents — every field zero / empty".into()),
        ));
        let rows = rows_of(&c);
        let expected: Vec<(&str, TypedValue)> = expected
            .iter()
            .map(|(l, v)| (l.as_str(), v.clone()))
            .collect();
        assert_eq!(rows, expected);
        assert!(c.exact.is_empty() && c.warnings.is_empty());

        // 20 listings: a 32-leaf tree whose 12 padding slots fold at two levels.
        let c = check(&fixtures::seaport_bulk_order(FROM, 20, true, 1), 1).unwrap();
        assert_eq!(
            c.model.headline.as_deref(),
            Some("One signature for 20 orders · 12 empty padding slots")
        );
        let folded: Vec<_> = rows_of(&c)
            .into_iter()
            .filter(|(_, v)| matches!(v, TypedValue::Text(t) if t.ends_with("every field zero / empty")))
            .collect();
        assert_eq!(
            folded,
            vec![
                (
                    "tree[1][0][1]",
                    TypedValue::Text("4 × OrderComponents — every field zero / empty".into())
                ),
                (
                    "tree[1][1]",
                    TypedValue::Text("8 × OrderComponents — every field zero / empty".into())
                ),
            ]
        );
        assert_eq!(c.model.rows.len(), 20 * 17 + 2);
        let last = &rows_of(&c)[19 * 17..20 * 17];
        let last_expected = listing_rows("tree[1][0][0][1][1]", 19);
        assert!(
            last.iter()
                .zip(&last_expected)
                .all(|((l, v), (el, ev))| l == el && v == ev),
            "the 20th order in full: {last:?}"
        );
        // Full trees have no padding to mention.
        let c = check(&fixtures::seaport_bulk_order(FROM, 16, true, 1), 1).unwrap();
        assert_eq!(
            c.model.headline.as_deref(),
            Some("One signature for 16 orders")
        );
    }

    /// A single Seaport order gets the compact items too, and no headline; a look-alike whose
    /// encodeType isn't exactly Seaport's (here 1.1's `nonce` for `counter`) is walked field by field.
    #[test]
    fn seaport_layout_only_for_the_exact_types() {
        use crate::walletconnect::testkit::fixtures;
        let c = check(&fixtures::seaport_order(FROM, true, 1), 1).unwrap();
        assert_eq!(c.model.headline, None);
        let expected = listing_rows("", 0);
        let rows = rows_of(&c);
        assert_eq!(rows.len(), expected.len());
        for ((l, v), (el, ev)) in rows.iter().zip(&expected) {
            assert_eq!((*l, v), (el.trim_start_matches('.'), ev));
        }

        let mut v = fixtures::seaport_order(FROM, true, 1);
        v["types"]["OrderComponents"][10]["name"] = json!("nonce");
        let counter = v["message"]["counter"].take();
        v["message"]["nonce"] = counter;
        let c = check(&v, 1).unwrap();
        let labels: Vec<_> = c.model.rows.iter().map(|r| r.label.as_str()).collect();
        assert!(labels.contains(&"offer[0].itemType"), "{labels:?}");
        assert!(labels.contains(&"consideration[2].recipient"));
        assert_eq!(c.model.rows.len(), 2 + 5 + 3 * 6 + 7);
    }

    /// Folding is generic and exact: only array elements at their zero value — consecutive ones
    /// share a row — and never a struct with a non-empty dynamic array, or one whose bool is set.
    #[test]
    fn zero_struct_runs_fold_into_one_row() {
        let v = json!({
            "types": {
                "EIP712Domain": [],
                "Leg": [
                    {"name": "to", "type": "address"},
                    {"name": "amount", "type": "uint256"},
                    {"name": "memo", "type": "string"},
                    {"name": "flag", "type": "bool"},
                    {"name": "tags", "type": "uint8[]"}
                ],
                "Batch": [{"name": "legs", "type": "Leg[]"}]
            },
            "primaryType": "Batch",
            "domain": {},
            "message": {"legs": [
                {"to": "0x0000000000000000000000000000000000000000", "amount": "0", "memo": "", "flag": false, "tags": [0]},
                {"to": "0x0000000000000000000000000000000000000000", "amount": 0, "memo": "", "flag": false, "tags": []},
                {"to": "0x0000000000000000000000000000000000000000", "amount": "0x0", "memo": "", "flag": false, "tags": []},
                {"to": "0x0000000000000000000000000000000000000000", "amount": "0", "memo": "", "flag": true, "tags": []},
                {"to": "0x0000000000000000000000000000000000000000", "amount": "0", "memo": "", "flag": false, "tags": []}
            ]}
        });
        let c = check(&v, 1).unwrap();
        let labels: Vec<_> = c.model.rows.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "legs[0].to",
                "legs[0].amount",
                "legs[0].memo",
                "legs[0].flag",
                "legs[0].tags[0]",
                "legs[1–2]",
                "legs[3].to",
                "legs[3].amount",
                "legs[3].memo",
                "legs[3].flag",
                "legs[3].tags",
                "legs[4]",
            ]
        );
        assert_eq!(
            c.model.rows[5].value,
            TypedValue::Text("2 × Leg — every field zero / empty".into())
        );
        assert_eq!(
            c.model.rows[11].value,
            TypedValue::Text("Leg — every field zero / empty".into())
        );
        // The digest is the unfolded message's.
        let (td, _) = parse_typed_param(&v).unwrap();
        assert_eq!(c.digests.digest, td.eip712_signing_hash().unwrap());
    }

    /// Folded structs cost no row, but they are still hashed: past the budget the request is
    /// refused before anything is hashed.
    #[test]
    fn folded_structs_are_budgeted() {
        let batch = |n: usize| {
            json!({
                "types": {
                    "EIP712Domain": [],
                    "E": [{"name": "a", "type": "uint8"}],
                    "Batch": [{"name": "xs", "type": format!("E[{n}]")}]
                },
                "primaryType": "Batch",
                "domain": {},
                "message": {"xs": vec![json!({"a": 0}); n]}
            })
        };
        let c = check(&batch(MAX_HIDDEN_STRUCTS), 1).unwrap();
        assert_eq!(c.model.rows.len(), 1);
        assert_eq!(
            c.model.rows[0].value,
            TypedValue::Text(format!(
                "{MAX_HIDDEN_STRUCTS} × E — every field zero / empty"
            ))
        );
        let e = refusal(&batch(MAX_HIDDEN_STRUCTS + 1), 1);
        assert_eq!(e.code, codes::INVALID_PARAMS);
        assert_eq!(e.message, "Typed data is too large to review.");
    }

    /// Fixed-size dimensions are allowed up to ten (a tall Seaport tree); dynamic ones up to four.
    #[test]
    fn array_dimension_caps() {
        let with = |ty: &str, value: Value| {
            json!({
                "types": {"EIP712Domain": [], "T": [{"name": "x", "type": ty}]},
                "primaryType": "T",
                "domain": {},
                "message": {"x": value}
            })
        };
        let nested = |dims: usize| {
            let mut v = json!(7);
            for _ in 0..dims {
                v = json!([v]);
            }
            v
        };
        let fixed = |dims: usize| format!("uint8{}", "[1]".repeat(dims));
        assert!(check(&with(&fixed(MAX_ARRAY_DIMS), nested(MAX_ARRAY_DIMS)), 1).is_ok());
        let e = parse_typed_param(&with(
            &fixed(MAX_ARRAY_DIMS + 1),
            nested(MAX_ARRAY_DIMS + 1),
        ))
        .unwrap_err();
        assert_eq!(e.message, "Typed data is too large.");
        let dynamic = |dims: usize| format!("uint8{}", "[]".repeat(dims));
        assert!(
            check(
                &with(
                    &dynamic(MAX_DYNAMIC_ARRAY_DIMS),
                    nested(MAX_DYNAMIC_ARRAY_DIMS)
                ),
                1
            )
            .is_ok()
        );
        assert!(
            parse_typed_param(&with(
                &dynamic(MAX_DYNAMIC_ARRAY_DIMS + 1),
                nested(MAX_DYNAMIC_ARRAY_DIMS + 1)
            ))
            .is_err()
        );
        // Mixed: four dynamic and six fixed is ten.
        let mixed = format!("uint8{}{}", "[]".repeat(4), "[1]".repeat(6));
        assert!(check(&with(&mixed, nested(10)), 1).is_ok());
    }

    #[test]
    fn tuple_types_refused_without_panic() {
        // alloy parses tuple field types for EIP-712 that no EIP-712
        // implementation can hash — refused up front, with a clear reason.
        let v = json!({
            "types": {
                "EIP712Domain": [],
                "T": [{"name": "pair", "type": "(uint256,address)"}]
            },
            "primaryType": "T",
            "domain": {},
            "message": {"pair": ["1", "0x0000000000000000000000000000000000000001"]}
        });
        let e = parse_typed_param(&v).unwrap_err();
        assert_eq!(
            e.message,
            "Typed data uses tuple types, which EIP-712 doesn't define."
        );
        // Self-referential (recursive) types are refused too, not resolved.
        let v = json!({
            "types": {
                "EIP712Domain": [],
                "Node": [{"name": "kids", "type": "Node[]"}]
            },
            "primaryType": "Node",
            "domain": {},
            "message": {"kids": []}
        });
        assert!(parse_typed_param(&v).is_err());
    }

    #[test]
    fn bytes_summarized_over_64_chars() {
        let v = json!({
            "types": {
                "EIP712Domain": [],
                "Blob": [
                    {"name": "short", "type": "bytes"},
                    {"name": "long", "type": "bytes"},
                    {"name": "word", "type": "bytes32"},
                    {"name": "text", "type": "string"}
                ]
            },
            "primaryType": "Blob",
            "domain": {},
            "message": {
                "short": format!("0x{}", "ab".repeat(32)),
                "long": format!("0x1234{}abcd", "00".repeat(29)),
                "word": format!("0x{}", "cd".repeat(32)),
                "text": "y".repeat(MAX_STRING_VALUE_CHARS + 1)
            }
        });
        let (td, raw) = parse_typed_param(&v).unwrap();
        let c = check_typed_data(&raw, &td, 1, FROM).unwrap();
        let text = |label: &str| match &c
            .model
            .rows
            .iter()
            .find(|r| r.label == label)
            .unwrap()
            .value
        {
            TypedValue::Text(t) => t.clone(),
            TypedValue::Addr(a) => panic!("unexpected address {a}"),
        };
        assert_eq!(
            text("short"),
            format!("0x{}", "ab".repeat(32)),
            "64 hex chars shown whole"
        );
        assert_eq!(
            text("long"),
            "0x12340000…abcd (33 bytes)",
            "a whole 4-byte head: a selector stays readable"
        );
        assert_eq!(text("word"), format!("0x{}", "cd".repeat(32)));
        assert!(text("text").ends_with(&format!("… ({} chars)", MAX_STRING_VALUE_CHARS + 1)));
        assert!(c.warnings.contains(&TypedWarning::LongValuesSummarized));
        // Every shortened row keeps its full value beside it, under its own row index.
        let index = |label: &str| c.model.rows.iter().position(|r| r.label == label).unwrap();
        let mut long = vec![0x12, 0x34];
        long.extend([0u8; 29]);
        long.extend([0xab, 0xcd]);
        assert_eq!(
            c.exact,
            vec![
                (index("long"), ExactValue::Bytes(long.into())),
                (
                    index("text"),
                    ExactValue::Text("y".repeat(MAX_STRING_VALUE_CHARS + 1))
                ),
            ]
        );
    }

    fn safe_tx_json(legacy: bool, operation: u8) -> Value {
        let gas_name = if legacy { "dataGas" } else { "baseGas" };
        json!({
            "types": {
                "EIP712Domain": domain_type(&[("chainId", "uint256"), ("verifyingContract", "address")]),
                "SafeTx": [
                    {"name": "to", "type": "address"},
                    {"name": "value", "type": "uint256"},
                    {"name": "data", "type": "bytes"},
                    {"name": "operation", "type": "uint8"},
                    {"name": "safeTxGas", "type": "uint256"},
                    {"name": gas_name, "type": "uint256"},
                    {"name": "gasPrice", "type": "uint256"},
                    {"name": "gasToken", "type": "address"},
                    {"name": "refundReceiver", "type": "address"},
                    {"name": "nonce", "type": "uint256"}
                ]
            },
            "primaryType": "SafeTx",
            "domain": {"chainId": 1, "verifyingContract": "0x1111111111111111111111111111111111111111"},
            "message": {
                "to": "0x2222222222222222222222222222222222222222",
                "value": "5",
                "data": "0x",
                "operation": operation,
                "safeTxGas": 0, gas_name: 0, "gasPrice": 0,
                "gasToken": "0x0000000000000000000000000000000000000000",
                "refundReceiver": "0x0000000000000000000000000000000000000000",
                "nonce": 7
            }
        })
    }

    #[test]
    fn typed_safetx_classified_owner_confirmation() {
        let c = check(&safe_tx_json(false, 1), 1).unwrap();
        assert_eq!(
            c.kind,
            TypedKind::SafeTx {
                safe: Some(address!("1111111111111111111111111111111111111111")),
                to: address!("2222222222222222222222222222222222222222"),
                value: U256::from(5),
                data: Bytes::new(),
                operation: 1,
                safe_tx_gas: U256::ZERO,
                base_gas: U256::ZERO,
                gas_price: U256::ZERO,
                gas_token: Address::ZERO,
                refund_receiver: Address::ZERO,
                nonce: U256::from(7),
            }
        );
        // The typehash is Safe's: the struct alloy hashes is the real SafeTx.
        let (td, _) = parse_typed_param(&safe_tx_json(false, 0)).unwrap();
        assert_eq!(td.encode_type().unwrap(), SAFE_TX_TYPE);
        assert_eq!(
            td.type_hash().unwrap(),
            b256!("bb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8")
        );
    }

    #[test]
    fn typed_safetx_legacy_classified() {
        let mut v = safe_tx_json(true, 0);
        v["message"]["dataGas"] = json!(21_000);
        let c = check(&v, 1).unwrap();
        assert!(
            matches!(c.kind, TypedKind::SafeTx { operation: 0, base_gas, .. } if base_gas == U256::from(21_000)),
            "the legacy dataGas is the base gas: {:?}",
            c.kind
        );
        // A look-alike under another name is not a Safe confirmation (and not flagged as one).
        let mut v = safe_tx_json(false, 0);
        let def = v["types"]["SafeTx"].clone();
        v["types"].as_object_mut().unwrap().remove("SafeTx");
        v["types"]["SafeTX"] = def;
        v["primaryType"] = json!("SafeTX");
        assert_eq!(check(&v, 1).unwrap().kind, TypedKind::Generic);
    }

    #[test]
    fn typed_safemessage_classified() {
        let v = json!({
            "types": {
                "EIP712Domain": domain_type(&[("chainId", "uint256"), ("verifyingContract", "address")]),
                "SafeMessage": [{"name": "message", "type": "bytes"}]
            },
            "primaryType": "SafeMessage",
            "domain": {"chainId": "0x1", "verifyingContract": "0x1111111111111111111111111111111111111111"},
            "message": {"message": format!("0x{}", "42".repeat(32))}
        });
        let c = check(&v, 1).unwrap();
        assert_eq!(
            c.kind,
            TypedKind::SafeMessage {
                safe: Some(address!("1111111111111111111111111111111111111111"))
            }
        );
    }

    fn permit_2612(owner: Address, value: &str) -> Value {
        json!({
            "types": {
                "EIP712Domain": domain_type(&[
                    ("name", "string"), ("version", "string"),
                    ("chainId", "uint256"), ("verifyingContract", "address"),
                ]),
                "Permit": [
                    {"name": "owner", "type": "address"},
                    {"name": "spender", "type": "address"},
                    {"name": "value", "type": "uint256"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint256"}
                ]
            },
            "primaryType": "Permit",
            "domain": {
                "name": "USD Coin", "version": "2", "chainId": 1,
                "verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            },
            "message": {
                "owner": owner.to_checksum(None),
                "spender": "0x3333333333333333333333333333333333333333",
                "value": value,
                "nonce": 0,
                "deadline": "1893456000"
            }
        })
    }

    #[test]
    fn permit_eip2612_banner_unlimited() {
        let max = U256::MAX.to_string();
        let c = check(&permit_2612(FROM, &max), 1).unwrap();
        let TypedKind::Allowance(g) = c.kind else {
            panic!("expected an allowance, got {:?}", c.kind);
        };
        assert_eq!(g.kind, "EIP-2612 Permit");
        assert_eq!(
            g.spender,
            address!("3333333333333333333333333333333333333333")
        );
        assert_eq!(
            g.tokens,
            vec![(
                address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
                U256::MAX
            )]
        );
        assert!(g.unlimited);
        assert_eq!(
            g.expires,
            AllowanceExpiry::Never,
            "an EIP-2612 allowance never expires"
        );
        assert_eq!(g.signature_deadline, Some(1_893_456_000), "its `deadline`");
        assert!(c.warnings.is_empty());

        let c = check(&permit_2612(FROM, "1000000"), 1).unwrap();
        let TypedKind::Allowance(g) = c.kind else {
            panic!()
        };
        assert!(!g.unlimited);
        assert_eq!(g.tokens[0].1, U256::from(1_000_000));
    }

    #[test]
    fn permit_owner_not_signer_warns() {
        let other = address!("4444444444444444444444444444444444444444");
        let c = check(&permit_2612(other, "1"), 1).unwrap();
        assert!(matches!(c.kind, TypedKind::Allowance(_)));
        assert_eq!(c.warnings, vec![TypedWarning::PermitOwnerNotSigner]);
    }

    fn details(token: &str, amount: &str, expiration: u64) -> Value {
        json!({"token": token, "amount": amount, "expiration": expiration, "nonce": 0})
    }

    fn permit2_allowance(batch: bool) -> Value {
        let details_ty = json!([
            {"name": "token", "type": "address"},
            {"name": "amount", "type": "uint160"},
            {"name": "expiration", "type": "uint48"},
            {"name": "nonce", "type": "uint48"}
        ]);
        let max160 = ((U256::from(1u8) << 160u32) - U256::from(1u8)).to_string();
        let (primary, field_ty, value) = if batch {
            (
                "PermitBatch",
                "PermitDetails[]",
                json!([
                    details(
                        "0x5555555555555555555555555555555555555555",
                        "10",
                        2_000_000_000
                    ),
                    details(
                        "0x6666666666666666666666666666666666666666",
                        &max160,
                        1_900_000_000
                    )
                ]),
            )
        } else {
            (
                "PermitSingle",
                "PermitDetails",
                details(
                    "0x5555555555555555555555555555555555555555",
                    &max160,
                    1_900_000_000,
                ),
            )
        };
        json!({
            "types": {
                "EIP712Domain": domain_type(&[
                    ("name", "string"), ("chainId", "uint256"), ("verifyingContract", "address"),
                ]),
                "PermitDetails": details_ty,
                primary: [
                    {"name": "details", "type": field_ty},
                    {"name": "spender", "type": "address"},
                    {"name": "sigDeadline", "type": "uint256"}
                ]
            },
            "primaryType": primary,
            "domain": {"name": "Permit2", "chainId": 1, "verifyingContract": PERMIT2.to_checksum(None)},
            "message": {
                "details": value,
                "spender": "0x3333333333333333333333333333333333333333",
                "sigDeadline": "1893456000"
            }
        })
    }

    #[test]
    fn permit2_single_and_batch_banners() {
        let max160 = (U256::from(1u8) << 160u32) - U256::from(1u8);
        let c = check(&permit2_allowance(false), 1).unwrap();
        let TypedKind::Allowance(g) = c.kind else {
            panic!("{:?}", c.kind)
        };
        assert_eq!(g.kind, "Permit2 PermitSingle");
        assert_eq!(
            g.spender,
            address!("3333333333333333333333333333333333333333")
        );
        assert_eq!(
            g.tokens,
            vec![(address!("5555555555555555555555555555555555555555"), max160)]
        );
        assert_eq!(g.expires, AllowanceExpiry::At(1_900_000_000));
        assert_eq!(g.signature_deadline, Some(1_893_456_000), "sigDeadline");
        assert!(g.unlimited);

        let c = check(&permit2_allowance(true), 1).unwrap();
        let TypedKind::Allowance(g) = c.kind else {
            panic!("{:?}", c.kind)
        };
        assert_eq!(g.kind, "Permit2 PermitBatch");
        assert_eq!(g.tokens.len(), 2);
        assert_eq!(g.tokens[0].1, U256::from(10));
        assert_eq!(
            g.expires,
            AllowanceExpiry::At(1_900_000_000),
            "the earliest expiry"
        );
        assert!(g.unlimited, "one unlimited token makes the grant unlimited");

        let c = check(&permit2_transfer(), 1).unwrap();
        let TypedKind::Allowance(g) = c.kind else {
            panic!("{:?}", c.kind)
        };
        assert_eq!(g.kind, "Permit2 PermitTransferFrom");
        assert_eq!(g.expires, AllowanceExpiry::At(1_893_456_000));
        assert_eq!(g.signature_deadline, None, "the deadline IS the expiry");
        assert!(!g.unlimited);
    }

    /// SafeTx data as an owner confirmation carries it: a transfer's selector and recipient.
    fn safe_tx_with_data(data: &str) -> Value {
        let mut v = safe_tx_json(false, 0);
        v["message"]["data"] = json!(data);
        v
    }

    /// `transfer(0x4444…, 1e12)` — 68 bytes, over the row's 32-byte display limit.
    fn transfer_data() -> String {
        let recipient = "4444444444444444444444444444444444444444";
        format!("0xa9059cbb{recipient:0>64}{:064x}", 1_000_000_000_000u64)
    }

    /// A shortened bytes row keeps a call's whole 4-byte selector, so an owner confirmation's row
    /// at least names the function its Safe would call.
    #[test]
    fn safe_tx_data_row_keeps_the_selector() {
        let c = check(&safe_tx_with_data(&transfer_data()), 1).unwrap();
        let row = c
            .model
            .rows
            .iter()
            .find(|r| r.label == "data")
            .expect("a data row");
        let TypedValue::Text(shown) = &row.value else {
            panic!("data is bytes: {row:?}")
        };
        assert!(
            shown.starts_with("0xa9059cbb"),
            "the 4-byte selector of the Safe's call is not shown: {shown}"
        );
    }

    /// Permit2 AllowanceTransfer `expiration == 0` is stored as `block.timestamp`: the allowance
    /// is live for the block the permit lands in — never "expired in 1970".
    #[test]
    fn permit2_expiration_zero_is_the_submitting_block() {
        for batch in [false, true] {
            let mut v = permit2_allowance(batch);
            if batch {
                v["message"]["details"][1]["expiration"] = json!(0);
            } else {
                v["message"]["details"]["expiration"] = json!("0");
            }
            let c = check(&v, 1).unwrap();
            let TypedKind::Allowance(g) = &c.kind else {
                panic!("{:?}", c.kind)
            };
            assert_ne!(
                format!("{:?}", g.expires),
                format!("{:?}", Some(0u64)),
                "batch={batch}: expiration 0 carried as the Unix epoch"
            );
            assert_eq!(
                g.expires,
                AllowanceExpiry::SubmittingBlock,
                "batch={batch}: the soonest expiry, live in the block it lands in"
            );
            assert_eq!(g.signature_deadline, Some(1_893_456_000), "batch={batch}");
        }
    }

    /// Everything a SafeTx signs reaches the review: the full `data` beside its shortened row, and
    /// every field of the struct (gas and refund included) in the kind.
    #[test]
    fn safe_tx_data_full_value_travels_with_the_review() {
        let data = transfer_data();
        let mut v = safe_tx_with_data(&data);
        v["message"]["gasPrice"] = json!("7");
        v["message"]["refundReceiver"] = json!("0x9999999999999999999999999999999999999999");
        let c = check(&v, 1).unwrap();
        let i = c.model.rows.iter().position(|r| r.label == "data").unwrap();
        let full = hex::decode(&data).unwrap();
        assert_eq!(
            c.exact,
            vec![(i, ExactValue::Bytes(full.clone().into()))],
            "the full data behind the shortened row"
        );
        let TypedKind::SafeTx {
            data: carried,
            gas_price,
            refund_receiver,
            ..
        } = &c.kind
        else {
            panic!("{:?}", c.kind)
        };
        assert_eq!(carried.as_ref(), full.as_slice());
        assert_eq!(*gas_price, U256::from(7));
        assert_eq!(*refund_receiver, Address::repeat_byte(0x99));
    }

    #[test]
    fn classify_kind_matches_check() {
        let (td, _) = parse_typed_param(&permit_2612(FROM, "1")).unwrap();
        let (kind, warnings) = classify_kind(&td, FROM);
        assert!(matches!(kind, TypedKind::Allowance(_)));
        assert!(warnings.is_empty());
        let (td, _) = parse_typed_param(&mail()).unwrap();
        assert_eq!(classify_kind(&td, FROM).0, TypedKind::Generic);
    }
}
