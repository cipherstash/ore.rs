#![deny(missing_docs)]
//! Canonical, order-preserving fixed-length byte encodings for plaintext
//! types.
//!
//! Each supported type implements [`ToOrderableBytes`], which maps a
//! value to a fixed-length byte array whose byte-wise lexicographic
//! order agrees with the type's natural total order, and whose byte
//! equality agrees with the type's value equality. The resulting bytes
//! are scheme-agnostic — they're intended for any comparison-as-bytes
//! scheme that wants to preserve plaintext order on ciphertexts (e.g.
//! `ore-rs` BlockORE, an OPE construction, an ordered hash).
//!
//! Encoders are gated behind per-type feature flags so callers only pay
//! for the dependencies they actually use.

#[cfg(feature = "chrono")]
pub mod chrono;
#[cfg(feature = "decimal")]
pub mod decimal;
pub mod primitive;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

/// Maps a value to its canonical, order-preserving fixed-length byte
/// encoding.
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
/// The encoded length is fixed per type and exposed via
/// [`ENCODED_LEN`](Self::ENCODED_LEN). Per-type modules also re-export
/// the same value as a free `pub const` for use in const contexts where
/// naming the impl would be unwieldy.
pub trait ToOrderableBytes {
    /// Length, in bytes, of the canonical encoding produced by
    /// [`to_orderable_bytes`](Self::to_orderable_bytes).
    const ENCODED_LEN: usize;

    /// The fixed-length byte array type returned by
    /// [`to_orderable_bytes`](Self::to_orderable_bytes). By convention
    /// every impl sets this to `[u8; Self::ENCODED_LEN]`; the
    /// indirection through an associated type is only needed because
    /// stable Rust does not yet allow naming `[u8; Self::ENCODED_LEN]`
    /// directly in a method signature (that requires
    /// `feature(generic_const_exprs)`).
    type Bytes: AsRef<[u8]>;

    /// Build the canonical, order-preserving fixed-length byte encoding
    /// of `self`.
    fn to_orderable_bytes(&self) -> Self::Bytes;
}
