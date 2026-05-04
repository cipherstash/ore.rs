//! Canonical, order-preserving fixed-length byte encodings for the
//! primitives `bool`, `u8`, `i8`, `i16`, `i32`, `i64`, `u128`, `i128`,
//! and the IEEE 754 double `f64`.
//!
//! Encoded widths:
//!
//! - `bool`, `u8`, `i8`, `i16`, `i32`, `i64`, `f64` → `[u8; 8]`
//! - `u128`, `i128` → `[u8; 16]`
//!
//! Sub-`u64` integer types are widened to `u64` (sign-flipping for
//! signed integers, identity-cast for `bool`/`u8`) and serialised
//! big-endian, matching the `IntoOrePlaintext<u64>` widening used by
//! the cipherstash-suite ORE indexer (so e.g. an `i16` value lands in
//! the low two bytes of the output, with the upper six bytes zero).
//! 128-bit integers use their native width.
//!
//! Byte-wise lex compare on the output agrees with the type's natural
//! total order *within that type*. Cross-type comparison is not
//! meaningful — `i16(0)` and `i64(0)` both encode to non-equal byte
//! patterns, and the encodings of an `i16` value and the same value
//! held as `i64` differ.
//!
//! ## Unsigned integers (`u8`, `u128`)
//!
//! Already in lex order — no sign-flip needed. `u8` is zero-extended
//! to `u64` before BE serialisation; `u128` uses its native width.
//!
//! ## Signed integers (`i8`, `i16`, `i32`, `i64`, `i128`)
//!
//! Each two's-complement input is mapped to its unsigned equivalent by
//! flipping the sign bit at its native width (`x ^ (1 << (N-1))`),
//! widened to `u64` by zero-extension (or kept at native width for
//! `i128`), and serialised big-endian. Sign-flipping moves negatives
//! below positives (the sign bit `1` for negatives clears to `0`, vice
//! versa for positives) and preserves order within each sign class;
//! the zero-extension is a no-op on lex order because the high padding
//! bytes are constant.
//!
//! ## `f64`
//!
//! IEEE 754 doubles are mapped to a lex-orderable `u64` using the
//! standard monotonic encoding:
//!
//! - Negatives flip every bit (their bit pattern's lex order is the
//!   reverse of magnitude order, so flipping inverts it).
//! - Positives (and `+0.0`) flip only the sign bit (bringing them above
//!   negatives in lex order).
//!
//! `-0.0` is canonicalised to `+0.0` before encoding so the two compare
//! byte-equal — matching `-0.0 == 0.0` on `f64`.
//!
//! NaN handling is unspecified. `f64` is `PartialOrd` rather than `Ord`
//! (NaN compares unordered against every value, including itself), so
//! the trait's order/equality guarantees only apply to non-NaN inputs.
//! Different NaN bit patterns will produce different bytes; consumers
//! that need a canonical NaN must canonicalise upstream.

use crate::ToOrderableBytes;

impl ToOrderableBytes for bool {
    const ENCODED_LEN: usize = 8;
    type Bytes = [u8; Self::ENCODED_LEN];

    fn to_orderable_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        // `false as u64 == 0`, `true as u64 == 1`. Lex order on the
        // BE-encoded `u64` then puts `false` strictly below `true`.
        (*self as u64).to_be_bytes()
    }
}

impl ToOrderableBytes for u8 {
    const ENCODED_LEN: usize = 8;
    type Bytes = [u8; Self::ENCODED_LEN];

    fn to_orderable_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        u64::from(*self).to_be_bytes()
    }
}

impl ToOrderableBytes for i8 {
    const ENCODED_LEN: usize = 8;
    type Bytes = [u8; Self::ENCODED_LEN];

    fn to_orderable_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let sign_flipped = (*self as u8) ^ (1u8 << 7);
        u64::from(sign_flipped).to_be_bytes()
    }
}

impl ToOrderableBytes for i16 {
    const ENCODED_LEN: usize = 8;
    type Bytes = [u8; Self::ENCODED_LEN];

    fn to_orderable_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let sign_flipped = (*self as u16) ^ (1u16 << 15);
        u64::from(sign_flipped).to_be_bytes()
    }
}

impl ToOrderableBytes for i32 {
    const ENCODED_LEN: usize = 8;
    type Bytes = [u8; Self::ENCODED_LEN];

    fn to_orderable_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let sign_flipped = (*self as u32) ^ (1u32 << 31);
        u64::from(sign_flipped).to_be_bytes()
    }
}

impl ToOrderableBytes for i64 {
    const ENCODED_LEN: usize = 8;
    type Bytes = [u8; Self::ENCODED_LEN];

    fn to_orderable_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        ((*self as u64) ^ (1u64 << 63)).to_be_bytes()
    }
}

impl ToOrderableBytes for u128 {
    const ENCODED_LEN: usize = 16;
    type Bytes = [u8; Self::ENCODED_LEN];

    fn to_orderable_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        self.to_be_bytes()
    }
}

impl ToOrderableBytes for i128 {
    const ENCODED_LEN: usize = 16;
    type Bytes = [u8; Self::ENCODED_LEN];

    fn to_orderable_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        ((*self as u128) ^ (1u128 << 127)).to_be_bytes()
    }
}

impl ToOrderableBytes for f64 {
    const ENCODED_LEN: usize = 8;
    type Bytes = [u8; Self::ENCODED_LEN];

    fn to_orderable_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        // Canonicalise -0.0 → 0.0 so the two share one byte encoding
        // (their f64 equality demands byte equality under our contract).
        let value = if *self == -0.0 { 0.0 } else { *self };
        let bits = value.to_bits();
        // Branchless monotonic mapping. `sign_extension` is `u64::MAX`
        // when the input is negative (sign bit `1`) and `0` when
        // positive. ORing in `1 << 63` makes the mask `u64::MAX` for
        // negatives (XOR-flip every bit) and `1 << 63` for positives
        // (XOR-flip just the sign bit).
        let sign_extension = (bits as i64 >> 63) as u64;
        let mask = sign_extension | (1u64 << 63);
        (bits ^ mask).to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- bool ---

    #[test]
    fn bool_known_anchors() {
        assert_eq!(false.to_orderable_bytes(), [0; 8]);
        assert_eq!(true.to_orderable_bytes(), [0, 0, 0, 0, 0, 0, 0, 0x01]);
    }

    #[test]
    fn bool_byte_order_matches_natural_order() {
        assert!(false.to_orderable_bytes() < true.to_orderable_bytes());
    }

    // --- u8 ---

    #[test]
    fn u8_known_anchors() {
        // Zero-extend to u64 BE: the u8 value lands in the last byte.
        assert_eq!(u8::MIN.to_orderable_bytes(), [0; 8]);
        assert_eq!(0x42u8.to_orderable_bytes(), [0, 0, 0, 0, 0, 0, 0, 0x42]);
        assert_eq!(u8::MAX.to_orderable_bytes(), [0, 0, 0, 0, 0, 0, 0, 0xFF]);
    }

    #[test]
    fn u8_byte_order_matches_natural_order() {
        let ascending = [u8::MIN, 1, 100, 200, u8::MAX];
        for window in ascending.windows(2) {
            assert!(
                window[0].to_orderable_bytes() < window[1].to_orderable_bytes(),
                "{} < {} failed",
                window[0],
                window[1]
            );
        }
    }

    // --- i8 ---

    #[test]
    fn i8_known_anchors() {
        // Sign-flip at u8 (XOR 0x80), then zero-extend to u64 BE: the
        // i8 value lands in the last byte, upper seven bytes zero.
        assert_eq!(i8::MIN.to_orderable_bytes(), [0, 0, 0, 0, 0, 0, 0, 0x00]);
        assert_eq!(0i8.to_orderable_bytes(), [0, 0, 0, 0, 0, 0, 0, 0x80]);
        assert_eq!(i8::MAX.to_orderable_bytes(), [0, 0, 0, 0, 0, 0, 0, 0xFF]);
    }

    #[test]
    fn i8_byte_order_matches_natural_order() {
        let ascending = [i8::MIN, -100, -1, 0, 1, 100, i8::MAX];
        for window in ascending.windows(2) {
            assert!(
                window[0].to_orderable_bytes() < window[1].to_orderable_bytes(),
                "{} < {} failed",
                window[0],
                window[1]
            );
        }
    }

    // --- i16 ---

    #[test]
    fn i16_known_anchors() {
        // Sign-flip at u16, then zero-extend to u64 BE: the i16 value
        // lands in the low two bytes, with the upper six bytes zero.
        assert_eq!(
            i16::MIN.to_orderable_bytes(),
            [0, 0, 0, 0, 0, 0, 0x00, 0x00]
        );
        assert_eq!(0i16.to_orderable_bytes(), [0, 0, 0, 0, 0, 0, 0x80, 0x00]);
        assert_eq!(
            i16::MAX.to_orderable_bytes(),
            [0, 0, 0, 0, 0, 0, 0xFF, 0xFF]
        );
    }

    #[test]
    fn i16_byte_order_matches_natural_order() {
        let ascending = [i16::MIN, -10000, -1, 0, 1, 10000, i16::MAX];
        for window in ascending.windows(2) {
            assert!(
                window[0].to_orderable_bytes() < window[1].to_orderable_bytes(),
                "{} < {} failed",
                window[0],
                window[1]
            );
        }
    }

    // --- i32 ---

    #[test]
    fn i32_known_anchors() {
        // Sign-flip at u32, then zero-extend to u64 BE: the i32 value
        // lands in the low four bytes, with the upper four bytes zero.
        assert_eq!(
            i32::MIN.to_orderable_bytes(),
            [0, 0, 0, 0, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            0i32.to_orderable_bytes(),
            [0, 0, 0, 0, 0x80, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            i32::MAX.to_orderable_bytes(),
            [0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn i32_byte_order_matches_natural_order() {
        let ascending = [i32::MIN, -1_000_000_000, -1, 0, 1, 1_000_000_000, i32::MAX];
        for window in ascending.windows(2) {
            assert!(
                window[0].to_orderable_bytes() < window[1].to_orderable_bytes(),
                "{} < {} failed",
                window[0],
                window[1]
            );
        }
    }

    // --- i64 ---

    #[test]
    fn i64_known_anchors() {
        assert_eq!(i64::MIN.to_orderable_bytes(), [0x00; 8]);
        assert_eq!(
            0i64.to_orderable_bytes(),
            [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(i64::MAX.to_orderable_bytes(), [0xFF; 8]);
    }

    #[test]
    fn i64_byte_order_matches_natural_order() {
        let ascending = [
            i64::MIN,
            -1_000_000_000_000,
            -1,
            0,
            1,
            1_000_000_000_000,
            i64::MAX,
        ];
        for window in ascending.windows(2) {
            assert!(
                window[0].to_orderable_bytes() < window[1].to_orderable_bytes(),
                "{} < {} failed",
                window[0],
                window[1]
            );
        }
    }

    // --- u128 ---

    #[test]
    fn u128_known_anchors() {
        assert_eq!(u128::MIN.to_orderable_bytes(), [0; 16]);
        assert_eq!(u128::MAX.to_orderable_bytes(), [0xFF; 16]);
        let one = 1u128.to_orderable_bytes();
        let mut expected_one = [0u8; 16];
        expected_one[15] = 1;
        assert_eq!(one, expected_one);
    }

    #[test]
    fn u128_byte_order_matches_natural_order() {
        let ascending = [
            u128::MIN,
            1,
            (1u128 << 32),
            (1u128 << 64),
            (1u128 << 96),
            u128::MAX - 1,
            u128::MAX,
        ];
        for window in ascending.windows(2) {
            assert!(
                window[0].to_orderable_bytes() < window[1].to_orderable_bytes(),
                "{} < {} failed",
                window[0],
                window[1]
            );
        }
    }

    // --- i128 ---

    #[test]
    fn i128_known_anchors() {
        assert_eq!(i128::MIN.to_orderable_bytes(), [0; 16]);
        assert_eq!(i128::MAX.to_orderable_bytes(), [0xFF; 16]);
        let mut expected_zero = [0u8; 16];
        expected_zero[0] = 0x80;
        assert_eq!(0i128.to_orderable_bytes(), expected_zero);
    }

    #[test]
    fn i128_byte_order_matches_natural_order() {
        let ascending = [
            i128::MIN,
            -(1i128 << 96),
            -(1i128 << 64),
            -1,
            0,
            1,
            (1i128 << 64),
            (1i128 << 96),
            i128::MAX,
        ];
        for window in ascending.windows(2) {
            assert!(
                window[0].to_orderable_bytes() < window[1].to_orderable_bytes(),
                "{} < {} failed",
                window[0],
                window[1]
            );
        }
    }

    // --- f64 ---

    #[test]
    fn f64_zero_canonical_bytes() {
        // +0.0 → 0x8000_0000_0000_0000 (sign-bit-only flip on all-zero bits).
        assert_eq!(
            0.0f64.to_orderable_bytes(),
            [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn f64_negative_zero_canonicalises_with_zero() {
        assert_eq!((-0.0f64).to_orderable_bytes(), 0.0f64.to_orderable_bytes());
    }

    #[test]
    fn f64_byte_order_matches_natural_order() {
        let ascending = [
            f64::NEG_INFINITY,
            f64::MIN,
            -1e100,
            -1.0,
            -f64::MIN_POSITIVE,
            0.0,
            f64::MIN_POSITIVE,
            1.0,
            1e100,
            f64::MAX,
            f64::INFINITY,
        ];
        for window in ascending.windows(2) {
            let a = window[0].to_orderable_bytes();
            let b = window[1].to_orderable_bytes();
            assert!(a < b, "{} < {} failed", window[0], window[1]);
        }
    }

    #[test]
    fn f64_subnormals_sort_above_zero_below_normals() {
        // Smallest positive subnormal (`f64::from_bits(1)`) must land
        // strictly between 0.0 and the smallest positive normal.
        let subnormal = f64::from_bits(1);
        assert!(0.0f64.to_orderable_bytes() < subnormal.to_orderable_bytes());
        assert!(subnormal.to_orderable_bytes() < f64::MIN_POSITIVE.to_orderable_bytes());
    }
}
