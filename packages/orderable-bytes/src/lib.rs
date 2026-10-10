#![deny(missing_docs)]
//! Canonical, order-preserving byte encodings for plaintext types.
//!
//! Each supported type implements [`ToOrderableBytes`], which maps a
//! value to bytes whose byte-wise lexicographic order agrees with the
//! type's natural total order, and whose byte equality agrees with the
//! type's value equality. The resulting bytes are scheme-agnostic —
//! they're intended for any comparison-as-bytes scheme that wants to
//! preserve plaintext order on ciphertexts (e.g. `ore-rs` BlockORE, an
//! OPE construction, an ordered hash).
//!
//! Most types encode to a fixed length, and also implement
//! [`FixedOrderableBytes`], which names that length. Strings and byte
//! strings encode to variable-length bytes (see [`variable`]).
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
/// Fixed-length encodings also implement [`FixedOrderableBytes`].
/// Variable-length encodings (strings and byte strings) do not; see
/// [`variable`] for the rules that come with them.
pub trait ToOrderableBytes {
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

/// A [`ToOrderableBytes`] encoding whose length is the same for every
/// value of the type.
///
/// The length is exposed as [`ENCODED_LEN`](Self::ENCODED_LEN), and by
/// convention [`ToOrderableBytes::Bytes`] is `[u8; Self::ENCODED_LEN]`.
/// Per-type modules also re-export the same value as a free `pub const`
/// for use in const contexts where naming the impl would be unwieldy.
pub trait FixedOrderableBytes: ToOrderableBytes {
    /// Length, in bytes, of the canonical encoding produced by
    /// [`to_orderable_bytes`](ToOrderableBytes::to_orderable_bytes).
    const ENCODED_LEN: usize;
}
