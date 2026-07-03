//! Generic EIP-712 typed-data review model.
//!
//! `function_panel` renders decoded *calldata*; typed data (a CoW GPv2 order, an
//! order cancellation, a future permit) has no calldata, so it is reviewed as a
//! flat list of label→value rows. [`IntoTypedModel`] turns a typed payload into
//! that [`TypedDataModel`]; the overlay renders any model the same way, so a new
//! signed message earns a panel by implementing the trait — no bespoke panel per
//! type (as the CoW order needed before this).

use alloy::primitives::Address;

/// A render-agnostic view of an EIP-712 message: a titled list of label→value
/// rows plus an optional one-line headline summarizing the action. The renderer
/// (`sign_review::typed_panel`) turns this into the same card layout for every
/// typed payload.
#[derive(Debug, Clone, PartialEq)]
pub struct TypedDataModel {
    /// Panel header, e.g. `"CoW order — EIP-712 signature"`.
    pub type_name: String,
    /// Optional bold one-liner under the header.
    pub headline: Option<String>,
    pub rows: Vec<TypedRow>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TypedRow {
    pub label: String,
    pub value: TypedValue,
}

/// A rendered field value. `Text` is a pre-composed string — the caller owns any
/// unit / precision / relative-time formatting, so the model stays render-only —
/// and `Addr` gets the full-width checksummed address card.
#[derive(Debug, Clone, PartialEq)]
pub enum TypedValue {
    Text(String),
    Addr(Address),
}

impl TypedRow {
    pub fn text(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: TypedValue::Text(value.into()),
        }
    }

    pub fn addr(label: impl Into<String>, addr: Address) -> Self {
        Self {
            label: label.into(),
            value: TypedValue::Addr(addr),
        }
    }
}

/// Anything reviewable as EIP-712 typed data.
pub trait IntoTypedModel {
    fn to_typed_model(&self) -> TypedDataModel;
}
