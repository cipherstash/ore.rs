#![deny(missing_docs)]
//! Canonical, order-preserving byte encodings for plaintext types.
//!
//! Each supported type implements [`OrderableBytes`], which maps a
//! value to bytes whose byte-wise lexicographic order agrees with the
//! type's natural total order, and whose byte equality agrees with the
//! type's value equality. The resulting bytes are scheme-agnostic —
//! they're intended for any comparison-as-bytes scheme that wants to
//! preserve plaintext order on ciphertexts (e.g. `ore-rs` BlockORE, an
//! OPE construction, an ordered hash).
//!
//! Every type also implements exactly one of two subtraits, which say
//! how its bytes may be handled:
//!
//! - [`FixedOrderableBytes`]: every value encodes to the same length,
//!   [`ENCODED_LEN`](FixedOrderableBytes::ENCODED_LEN). Numbers, `bool`,
//!   `char`, `Decimal` and the `chrono` types.
//! - [`VariableOrderableBytes`]: the length varies with the value.
//!   Strings and byte strings (see [`variable`]).
//!
//! Bound on the subtrait your code relies on. Padding to a block size,
//! for example, is only safe for [`FixedOrderableBytes`]; bound on
//! [`OrderableBytes`] only when you handle both kinds correctly.
//!
//! Encoders are gated behind per-type feature flags so callers only pay
//! for the dependencies they actually use.

#[cfg(feature = "chrono")]
pub mod chrono;
#[cfg(feature = "decimal")]
pub mod decimal;
pub mod primitive;
pub mod variable;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

// Runs the README's Rust examples as doctests, so the README cannot drift
// from the API. The examples use no optional feature, so they run under
// a plain `cargo test` as well as with `--all-features`.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

/// Maps a value to its canonical, order-preserving byte encoding.
///
/// Implementors guarantee, for any `a` and `b` of the implementing type:
///
/// - **Equality:** byte equality of the outputs agrees with the type's
///   value equality (`a.to_orderable_bytes() == b.to_orderable_bytes()`
///   iff `a == b`).
/// - **Order:** byte-wise lexicographic comparison of the outputs agrees
///   with the type's natural total order
///   (`a.to_orderable_bytes() <= b.to_orderable_bytes()` iff `a <= b`).
///
/// Every implementor also implements exactly one of
/// [`FixedOrderableBytes`] or [`VariableOrderableBytes`]. Code that
/// needs a fixed length, such as code that pads to a block size, must
/// bound on [`FixedOrderableBytes`], not on this trait.
///
/// In 0.1 this trait was called `ToOrderableBytes` and was fixed-length
/// only. It was renamed so that 0.1 code bounded on it fails to compile
/// rather than silently accepting variable-length types: migrate such
/// bounds to [`FixedOrderableBytes`].
pub trait OrderableBytes {
    /// The bytes returned by
    /// [`to_orderable_bytes`](Self::to_orderable_bytes): a
    /// `[u8; ENCODED_LEN]` array for fixed-length types, or a slice
    /// borrowed from `self` for variable-length ones, so encoding a
    /// string makes no copy of it.
    type Bytes<'a>: AsRef<[u8]>
    where
        Self: 'a;

    /// Build the canonical, order-preserving byte encoding of `self`.
    fn to_orderable_bytes(&self) -> Self::Bytes<'_>;
}

/// An [`OrderableBytes`] encoding whose length is the same for every
/// value of the type.
///
/// Implementors must make [`OrderableBytes::Bytes`] exactly
/// [`ENCODED_LEN`](Self::ENCODED_LEN) bytes long for every value, and by
/// convention it is `[u8; Self::ENCODED_LEN]`. Consumers size blocks and
/// buffers from `ENCODED_LEN`, so a mismatch truncates or mis-orders.
///
/// Fixed-length encodings may be zero-extended to a larger block, since
/// every value is extended the same way. Bounding on this trait is what
/// keeps variable-length types out of such code:
///
/// ```
/// use orderable_bytes::{FixedOrderableBytes, OrderableBytes};
///
/// fn pad_to_16<T: FixedOrderableBytes>(value: &T) -> [u8; 16] {
///     let mut block = [0u8; 16];
///     block[..T::ENCODED_LEN].copy_from_slice(value.to_orderable_bytes().as_ref());
///     block
/// }
///
/// assert!(pad_to_16(&1u32) < pad_to_16(&2u32));
/// ```
///
/// ```compile_fail
/// # use orderable_bytes::{FixedOrderableBytes, OrderableBytes};
/// # fn pad_to_16<T: FixedOrderableBytes>(value: &T) -> [u8; 16] {
/// #     let mut block = [0u8; 16];
/// #     block[..T::ENCODED_LEN].copy_from_slice(value.to_orderable_bytes().as_ref());
/// #     block
/// # }
/// // Strings are variable-length, so padding them is rejected.
/// pad_to_16(&String::from("a"));
/// ```
pub trait FixedOrderableBytes: OrderableBytes {
    /// Length, in bytes, of the canonical encoding produced by
    /// [`to_orderable_bytes`](OrderableBytes::to_orderable_bytes).
    const ENCODED_LEN: usize;
}

/// An [`OrderableBytes`] encoding whose length varies with the value.
///
/// A value sorts before any longer value it is a prefix of. The bytes do
/// not mark where they end, so they must never be padded or
/// concatenated: see [`variable`] for why, and for the implementations.
pub trait VariableOrderableBytes: OrderableBytes {}
