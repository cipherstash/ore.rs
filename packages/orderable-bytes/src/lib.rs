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
//!   [`ENCODED_LEN`](FixedOrderableBytes::ENCODED_LEN), available as an
//!   owned array. Numbers, `bool`, `char`, byte arrays `[u8; N]`,
//!   `Decimal` and the `chrono` types.
//! - [`VariableOrderableBytes`]: the length varies with the value, and
//!   the bytes are borrowed from it. Strings and byte strings (see
//!   [`variable`]).
//!
//! A reference `&T` implements the same traits as `T`.
//!
//! | Need | Bound | Call |
//! |---|---|---|
//! | Pad, store or return fixed-length bytes | `T: FixedOrderableBytes` | [`to_fixed_orderable_bytes`](FixedOrderableBytes::to_fixed_orderable_bytes) (owned) |
//! | Bytes of either kind, used immediately | `T: OrderableBytes` | [`to_orderable_bytes`](OrderableBytes::to_orderable_bytes) (may borrow) |
//! | Strings or byte strings specifically | `T: VariableOrderableBytes` | [`to_orderable_bytes`](OrderableBytes::to_orderable_bytes) (borrowed) |
//!
//! Padding to a block size is only safe for [`FixedOrderableBytes`];
//! bound on [`OrderableBytes`] only when you handle both kinds correctly.
//!
//! The traits are sealed: only this crate implements them, so every
//! encoding is pinned by its golden vectors, and the rules above hold
//! for every type that implements them.
//!
//! Encoders are gated behind per-type feature flags so callers only pay
//! for the dependencies they actually use.

/// Implements [`OrderableBytes`] and [`FixedOrderableBytes`] for a type
/// whose encoding is always `$len` bytes, from one body that builds the
/// array. Writing both impls from one length keeps
/// [`FixedOrderableBytes::ENCODED_LEN`], [`FixedOrderableBytes::Array`]
/// and [`OrderableBytes::Bytes`] in agreement.
macro_rules! impl_fixed_orderable_bytes {
    ($(#[$attr:meta])* $ty:ty, $len:literal, |$value:ident| $body:block) => {
        impl $crate::private::Sealed for $ty {}

        impl $crate::OrderableBytes for $ty {
            type Bytes<'a> = [u8; $len];

            fn to_orderable_bytes(&self) -> [u8; $len] {
                $crate::FixedOrderableBytes::to_fixed_orderable_bytes(self)
            }
        }

        $(#[$attr])*
        impl $crate::FixedOrderableBytes for $ty {
            const ENCODED_LEN: usize = $len;

            type Array = [u8; $len];

            fn to_fixed_orderable_bytes(&self) -> [u8; $len] {
                let $value = self;
                $body
            }
        }
    };
}

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

mod private {
    /// Restricts the traits below to this crate's types. See the crate
    /// docs for why they are sealed.
    pub trait Sealed {}
}

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
/// The trait is sealed, so types outside this crate can't implement it:
///
/// ```compile_fail,E0277
/// use orderable_bytes::OrderableBytes;
///
/// struct Mine(u32);
///
/// impl OrderableBytes for Mine {
///     type Bytes<'a> = [u8; 4];
///     fn to_orderable_bytes(&self) -> [u8; 4] {
///         self.0.to_be_bytes()
///     }
/// }
/// ```
///
/// In 0.1 this trait was called `ToOrderableBytes` and was fixed-length
/// only. It was renamed so that 0.1 code bounded on it fails to compile
/// rather than silently accepting variable-length types: migrate such
/// bounds to [`FixedOrderableBytes`].
pub trait OrderableBytes: private::Sealed {
    /// The bytes returned by
    /// [`to_orderable_bytes`](Self::to_orderable_bytes): a
    /// `[u8; ENCODED_LEN]` array for fixed-length types, or a slice
    /// borrowed from `self` for variable-length ones, so encoding a
    /// string makes no copy of it.
    ///
    /// Because it may borrow from `self`, it can't outlive the value.
    /// To keep fixed-length bytes, use
    /// [`FixedOrderableBytes::to_fixed_orderable_bytes`].
    type Bytes<'a>: AsRef<[u8]>
    where
        Self: 'a;

    /// Build the canonical, order-preserving byte encoding of `self`.
    fn to_orderable_bytes(&self) -> Self::Bytes<'_>;
}

/// An [`OrderableBytes`] encoding whose length is the same for every
/// value of the type.
///
/// [`to_fixed_orderable_bytes`](Self::to_fixed_orderable_bytes) returns
/// the same bytes as
/// [`to_orderable_bytes`](OrderableBytes::to_orderable_bytes), as an
/// owned [`Array`](Self::Array) of exactly
/// [`ENCODED_LEN`](Self::ENCODED_LEN) bytes that doesn't borrow from the
/// value. Generic code can store or return it:
///
/// ```
/// use orderable_bytes::FixedOrderableBytes;
///
/// fn term<T: FixedOrderableBytes>(value: T) -> T::Array {
///     value.to_fixed_orderable_bytes()
/// }
///
/// assert_eq!(term(7u32), [0, 0, 0, 7]);
/// ```
///
/// Fixed-length encodings may be zero-extended to a larger block, since
/// every value is extended the same way. Bounding on this trait is what
/// keeps variable-length types out of such code:
///
/// ```
/// use orderable_bytes::FixedOrderableBytes;
///
/// fn pad_to_16<T: FixedOrderableBytes>(value: &T) -> [u8; 16] {
///     let mut block = [0u8; 16];
///     block[..T::ENCODED_LEN].copy_from_slice(value.to_fixed_orderable_bytes().as_ref());
///     block
/// }
///
/// assert!(pad_to_16(&1u32) < pad_to_16(&2u32));
/// ```
///
/// ```compile_fail,E0277
/// # use orderable_bytes::FixedOrderableBytes;
/// # fn pad_to_16<T: FixedOrderableBytes>(value: &T) -> [u8; 16] {
/// #     let mut block = [0u8; 16];
/// #     block[..T::ENCODED_LEN].copy_from_slice(value.to_fixed_orderable_bytes().as_ref());
/// #     block
/// # }
/// // Strings are variable-length, so padding them is rejected.
/// pad_to_16(&String::from("a"));
/// ```
pub trait FixedOrderableBytes: OrderableBytes {
    /// Length, in bytes, of the canonical encoding.
    const ENCODED_LEN: usize;

    /// The owned encoding: always `[u8; ENCODED_LEN]`.
    type Array: AsRef<[u8]> + Copy;

    /// Build the canonical, order-preserving byte encoding of `self` as
    /// an owned array. The bytes are the same as
    /// [`to_orderable_bytes`](OrderableBytes::to_orderable_bytes) returns.
    fn to_fixed_orderable_bytes(&self) -> Self::Array;
}

/// An [`OrderableBytes`] encoding whose length varies with the value.
///
/// A value sorts before any longer value it is a prefix of. The bytes do
/// not mark where they end, so they must never be padded or
/// concatenated: see [`variable`] for why, and for the implementations.
pub trait VariableOrderableBytes: OrderableBytes {}

impl<T: OrderableBytes + ?Sized> private::Sealed for &T {}

/// A reference encodes exactly as the value it points to.
impl<T: OrderableBytes + ?Sized> OrderableBytes for &T {
    type Bytes<'a> = T::Bytes<'a>
    where
        Self: 'a;

    fn to_orderable_bytes(&self) -> T::Bytes<'_> {
        (**self).to_orderable_bytes()
    }
}

impl<T: FixedOrderableBytes + ?Sized> FixedOrderableBytes for &T {
    const ENCODED_LEN: usize = T::ENCODED_LEN;

    type Array = T::Array;

    fn to_fixed_orderable_bytes(&self) -> T::Array {
        (**self).to_fixed_orderable_bytes()
    }
}

impl<T: VariableOrderableBytes + ?Sized> VariableOrderableBytes for &T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reference_encodes_as_its_value() {
        fn any<T: OrderableBytes>(value: T) -> Vec<u8> {
            value.to_orderable_bytes().as_ref().to_vec()
        }
        fn fixed<T: FixedOrderableBytes>(value: T) -> T::Array {
            value.to_fixed_orderable_bytes()
        }
        fn is_variable<T: VariableOrderableBytes>(_: T) {}

        // The references are the point here, so bind them to names
        // rather than borrowing inline.
        let n = 7u32;
        let s = String::from("abc");
        let (n_ref, s_ref, str_ref_ref): (&u32, &String, &&str) = (&n, &s, &"abc");

        assert_eq!(any("abc"), b"abc");
        assert_eq!(any(str_ref_ref), b"abc");
        assert_eq!(any(n_ref), [0, 0, 0, 7]);
        assert_eq!(fixed(n_ref), [0, 0, 0, 7]);
        assert_eq!(<&u32 as FixedOrderableBytes>::ENCODED_LEN, 4);
        is_variable("abc");
        is_variable(s_ref);
    }
}
