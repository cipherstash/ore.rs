//! Wrappers that mark bytes as a binary value: [`ByteArray`] for a
//! fixed-length value such as a hash or a UUID, and [`ByteString`] for a
//! variable-length one.
//!
//! A binary value encodes to its own bytes, borrowed, since byte-wise
//! order is already the order Rust defines for byte arrays and slices.
//! The bare types `[u8; N]`, `[u8]` and `Vec<u8>` don't implement the
//! traits. Bare bytes are just as often bytes that something has already
//! encoded, and an encoding done by hand is where order goes wrong:
//! little-endian integers, a signed integer without its sign bit flipped,
//! or `f64::to_bits` all encrypt fine and then sort wrong. Without these
//! impls, handing such bytes to code bounded on [`OrderableBytes`] is a
//! compile error:
//!
//! ```compile_fail,E0277
//! use orderable_bytes::FixedOrderableBytes;
//!
//! fn term<T: FixedOrderableBytes>(value: &T) -> T::Array {
//!     value.to_fixed_orderable_bytes()
//! }
//!
//! // Little-endian bytes sort wrong. Pass the `u64` itself instead.
//! term(&258u64.to_le_bytes());
//! ```
//!
//! Wrapping bytes is a claim that they are the value, ordered byte-wise.
//! Wrap bytes you received as a value, never bytes you encoded yourself.
//!
//! [`OrderableBytes`]: crate::OrderableBytes

use crate::{private::Sealed, FixedOrderableBytes, OrderableBytes, VariableOrderableBytes};

/// A fixed-length binary value, such as a hash or a UUID, ordered
/// byte-wise.
///
/// It borrows the array, so encoding makes no copy of it.
///
/// ```
/// use orderable_bytes::{ByteArray, FixedOrderableBytes, OrderableBytes};
///
/// let uuid = [0x12u8; 16];
/// let value = ByteArray(&uuid);
///
/// assert_eq!(value.to_orderable_bytes(), &uuid);
/// assert_eq!(<ByteArray<16> as FixedOrderableBytes>::ENCODED_LEN, 16);
/// ```
#[derive(Clone, Copy)]
pub struct ByteArray<'a, const N: usize>(pub &'a [u8; N]);

impl<const N: usize> Sealed for ByteArray<'_, N> {}

impl<const N: usize> OrderableBytes for ByteArray<'_, N> {
    // Required because the wrapper itself holds a borrow.
    type Bytes<'b>
        = &'b [u8]
    where
        Self: 'b;

    fn to_orderable_bytes(&self) -> &[u8] {
        self.0
    }
}

impl<const N: usize> FixedOrderableBytes for ByteArray<'_, N> {
    const ENCODED_LEN: usize = N;

    type Array = [u8; N];

    fn to_fixed_orderable_bytes(&self) -> [u8; N] {
        *self.0
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for ByteArray<'a, N> {
    fn from(bytes: &'a [u8; N]) -> Self {
        Self(bytes)
    }
}

/// A variable-length binary value, ordered byte-wise: a value sorts
/// before any longer value it is a prefix of.
///
/// It borrows the bytes, so encoding makes no copy of them. Like strings,
/// the encoding doesn't mark where it ends, so it must never be padded or
/// concatenated (see [`crate::variable`]).
///
/// ```
/// use orderable_bytes::{ByteString, OrderableBytes};
///
/// let short = ByteString(b"ab");
/// let long = ByteString(b"abc");
///
/// assert!(short.to_orderable_bytes() < long.to_orderable_bytes());
/// ```
#[derive(Clone, Copy)]
pub struct ByteString<'a>(pub &'a [u8]);

impl Sealed for ByteString<'_> {}
impl VariableOrderableBytes for ByteString<'_> {}

impl OrderableBytes for ByteString<'_> {
    // Required because the wrapper itself holds a borrow.
    type Bytes<'b>
        = &'b [u8]
    where
        Self: 'b;

    fn to_orderable_bytes(&self) -> &[u8] {
        self.0
    }
}

impl<'a> From<&'a [u8]> for ByteString<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
}

impl<'a> From<&'a Vec<u8>> for ByteString<'a> {
    fn from(bytes: &'a Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for ByteString<'a> {
    fn from(bytes: &'a [u8; N]) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_byte_array_encodes_to_itself_without_copying() {
        let a = [1u8, 2, 3];
        let value = ByteArray(&a);
        assert_eq!(value.to_orderable_bytes(), &a);
        assert_eq!(value.to_orderable_bytes().as_ptr(), a.as_ptr());
        assert_eq!(value.to_fixed_orderable_bytes(), a);
        assert_eq!(<ByteArray<3> as FixedOrderableBytes>::ENCODED_LEN, 3);
    }

    #[test]
    fn a_byte_string_encodes_to_itself_without_copying() {
        let v = vec![1u8, 2, 3];
        let value = ByteString::from(&v);
        assert_eq!(value.to_orderable_bytes(), v.as_slice());
        assert_eq!(value.to_orderable_bytes().as_ptr(), v.as_ptr());
    }

    #[test]
    fn every_spelling_of_a_byte_string_encodes_the_same() {
        let a = [9u8, 8, 7];
        let from_array = ByteString::from(&a);
        let from_slice = ByteString::from(&a[..]);
        let v = a.to_vec();
        let from_vec = ByteString::from(&v);
        assert_eq!(
            from_array.to_orderable_bytes(),
            from_slice.to_orderable_bytes()
        );
        assert_eq!(
            from_array.to_orderable_bytes(),
            from_vec.to_orderable_bytes()
        );
    }

    #[test]
    fn the_wrappers_implement_their_length_trait() {
        fn is_fixed<T: FixedOrderableBytes>() {}
        fn is_variable<T: VariableOrderableBytes>() {}
        is_fixed::<ByteArray<'static, 16>>();
        is_variable::<ByteString<'static>>();
    }

    #[test]
    fn a_prefix_sorts_before_the_longer_byte_string() {
        let ascending: [&[u8]; 5] = [b"", b"\0", b"\0\0", b"\x01", b"\xff"];
        for window in ascending.windows(2) {
            assert!(
                ByteString(window[0]).to_orderable_bytes()
                    < ByteString(window[1]).to_orderable_bytes(),
                "{:?} < {:?} failed",
                window[0],
                window[1]
            );
        }
    }

    quickcheck! {
        fn byte_array_order_matches_array_order(a: Vec<u8>, b: Vec<u8>) -> bool {
            let mut x = [0u8; 8];
            let mut y = [0u8; 8];
            for (dst, src) in x.iter_mut().zip(&a) { *dst = *src; }
            for (dst, src) in y.iter_mut().zip(&b) { *dst = *src; }
            ByteArray(&x).to_orderable_bytes().cmp(ByteArray(&y).to_orderable_bytes()) == x.cmp(&y)
        }

        fn byte_string_order_matches_bytes_order(a: Vec<u8>, b: Vec<u8>) -> bool {
            ByteString(&a).to_orderable_bytes().cmp(ByteString(&b).to_orderable_bytes()) == a.cmp(&b)
        }

        fn byte_string_equality_matches_bytes_equality(a: Vec<u8>, b: Vec<u8>) -> bool {
            (ByteString(&a).to_orderable_bytes() == ByteString(&b).to_orderable_bytes()) == (a == b)
        }
    }
}
