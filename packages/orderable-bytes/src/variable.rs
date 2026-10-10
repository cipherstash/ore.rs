//! Canonical, order-preserving variable-length byte encodings for
//! `str`, `String`, `[u8]` and `Vec<u8>`.
//!
//! The encoding is the value's own bytes, borrowed: a string encodes to
//! its UTF-8 bytes, and a byte string to itself. No copy is made, so no
//! second copy of the plaintext is left in memory.
//!
//! Byte-wise lexicographic order is already the order these types
//! define, with a value sorting before any longer value it is a prefix
//! of (`"ab"` < `"abc"`). For `str` this is Unicode code-point order,
//! because UTF-8 preserves it. Byte equality is value equality.
//!
//! # No normalisation
//!
//! A string is encoded exactly as given. Two strings that Unicode
//! considers the same text but that use different code points (`é` as
//! U+00E9, or as `e` followed by U+0301) encode differently, and sort
//! by code point rather than by any language's collation. Callers that
//! need canonical equivalence, case folding or accent folding must
//! normalise before encoding.
//!
//! # Never pad, never concatenate
//!
//! These encodings do not mark where they end. A consumer must keep
//! each value's length and compare by length when one value is a prefix
//! of the other, as a variable-length scheme does. Two misuses break
//! the guarantees:
//!
//! - **Zero-padding** to a fixed block size makes `"a"` and `"a\0"`
//!   encode identically.
//! - **Concatenating** two values loses the boundary between them, so
//!   `("ab", "c")` and `("a", "bc")` encode identically.
//!
//! Fixed-length encodings (see [`crate::FixedOrderableBytes`]) are safe
//! to zero-extend; these are not. That is why these types implement
//! [`crate::VariableOrderableBytes`] and not
//! [`crate::FixedOrderableBytes`]: code that pads must bound on the
//! latter, and then rejects these types at compile time.

use crate::{OrderableBytes, VariableOrderableBytes};

impl VariableOrderableBytes for str {}

impl OrderableBytes for str {
    type Bytes<'a> = &'a [u8];

    fn to_orderable_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl VariableOrderableBytes for String {}

impl OrderableBytes for String {
    type Bytes<'a> = &'a [u8];

    fn to_orderable_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl VariableOrderableBytes for [u8] {}

impl OrderableBytes for [u8] {
    type Bytes<'a> = &'a [u8];

    fn to_orderable_bytes(&self) -> &[u8] {
        self
    }
}

impl VariableOrderableBytes for Vec<u8> {}

impl OrderableBytes for Vec<u8> {
    type Bytes<'a> = &'a [u8];

    fn to_orderable_bytes(&self) -> &[u8] {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_length_types_implement_variable_orderable_bytes() {
        fn is_variable<T: VariableOrderableBytes + ?Sized>() {}
        is_variable::<str>();
        is_variable::<String>();
        is_variable::<[u8]>();
        is_variable::<Vec<u8>>();
    }

    #[test]
    fn str_encodes_to_its_utf8_bytes() {
        assert_eq!("".to_orderable_bytes(), b"");
        assert_eq!("a".to_orderable_bytes(), b"a");
        assert_eq!("\u{e9}".to_orderable_bytes(), [0xc3, 0xa9]);
        assert_eq!("e\u{301}".to_orderable_bytes(), [0x65, 0xcc, 0x81]);
    }

    #[test]
    fn encoding_borrows_rather_than_copies() {
        let s = String::from("borrowed");
        assert_eq!(s.to_orderable_bytes().as_ptr(), s.as_ptr());
        let v = vec![1u8, 2, 3];
        assert_eq!(v.to_orderable_bytes().as_ptr(), v.as_ptr());
    }

    #[test]
    fn a_prefix_sorts_before_the_longer_value() {
        let ascending = ["", "a", "a\0", "ab", "abc", "b", "\u{e9}", "\u{10ffff}"];
        for window in ascending.windows(2) {
            assert!(
                window[0].to_orderable_bytes() < window[1].to_orderable_bytes(),
                "{:?} < {:?} failed",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn no_normalisation_is_applied() {
        // Precomposed and decomposed é are the same text to Unicode but
        // different strings to Rust, and they encode differently.
        assert_ne!(
            "\u{e9}".to_orderable_bytes(),
            "e\u{301}".to_orderable_bytes()
        );
    }

    quickcheck! {
        fn string_byte_order_matches_string_order(a: String, b: String) -> bool {
            a.to_orderable_bytes().cmp(b.to_orderable_bytes()) == a.cmp(&b)
        }

        fn string_byte_equality_matches_string_equality(a: String, b: String) -> bool {
            (a.to_orderable_bytes() == b.to_orderable_bytes()) == (a == b)
        }

        fn bytes_byte_order_matches_bytes_order(a: Vec<u8>, b: Vec<u8>) -> bool {
            a.to_orderable_bytes().cmp(b.to_orderable_bytes()) == a.cmp(&b)
        }

        fn str_and_string_encode_identically(a: String) -> bool {
            a.as_str().to_orderable_bytes() == a.to_orderable_bytes()
        }
    }
}
