//! Canonical, order-preserving fixed-length byte encodings for the
//! primitives `bool`, `u8`, `i8`, `i16`, `i32`, `i64`, `u128`, `i128`,
//! and the IEEE 754 double `f64`.
//!
//! Each impl emits the type's native byte width — no padding:
//!
//! - `bool`, `u8`, `i8` → `[u8; 1]`
//! - `i16` → `[u8; 2]`
//! - `i32` → `[u8; 4]`
//! - `i64`, `f64` → `[u8; 8]`
//! - `u128`, `i128` → `[u8; 16]`
//!
//! Consumers that need a fixed wider encoding (e.g. an ORE construction
//! whose plaintext block size is `[u8; 8]`) should zero-extend the
//! orderable bytes upstream of the encrypter; widening is monotonic on
//! lex order so it preserves the encoding's guarantees.
//!
//! ## Unsigned integers (`u8`, `u128`)
//!
//! Already in lex order — no sign-flip needed. Native big-endian.
//!
//! ## Signed integers (`i8`, `i16`, `i32`, `i64`, `i128`)
//!
//! Each two's-complement input is mapped to its unsigned equivalent by
//! flipping the sign bit at its native width (`x ^ (1 << (N-1))`),
//! then serialised big-endian. Sign-flipping moves negatives below
//! positives (the sign bit `1` for negatives clears to `0`, vice versa
//! for positives) and preserves order within each sign class.
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
    const ENCODED_LEN: usize = 1;
    type Bytes = [u8; Self::ENCODED_LEN];

    fn to_orderable_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        // `false as u8 == 0`, `true as u8 == 1`. `false` sorts strictly
        // below `true`.
        [*self as u8]
    }
}

impl ToOrderableBytes for u8 {
    const ENCODED_LEN: usize = 1;
    type Bytes = [u8; Self::ENCODED_LEN];

    fn to_orderable_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        [*self]
    }
}

impl ToOrderableBytes for i8 {
    const ENCODED_LEN: usize = 1;
    type Bytes = [u8; Self::ENCODED_LEN];

    fn to_orderable_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        [(*self as u8) ^ (1u8 << 7)]
    }
}

impl ToOrderableBytes for i16 {
    const ENCODED_LEN: usize = 2;
    type Bytes = [u8; Self::ENCODED_LEN];

    fn to_orderable_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        ((*self as u16) ^ (1u16 << 15)).to_be_bytes()
    }
}

impl ToOrderableBytes for i32 {
    const ENCODED_LEN: usize = 4;
    type Bytes = [u8; Self::ENCODED_LEN];

    fn to_orderable_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        ((*self as u32) ^ (1u32 << 31)).to_be_bytes()
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
        assert_eq!(false.to_orderable_bytes(), [0x00]);
        assert_eq!(true.to_orderable_bytes(), [0x01]);
    }

    #[test]
    fn bool_byte_order_matches_natural_order() {
        assert!(false.to_orderable_bytes() < true.to_orderable_bytes());
    }

    // --- u8 ---

    #[test]
    fn u8_known_anchors() {
        // Native: u8 is already in lex order, no transform.
        assert_eq!(u8::MIN.to_orderable_bytes(), [0x00]);
        assert_eq!(0x42u8.to_orderable_bytes(), [0x42]);
        assert_eq!(u8::MAX.to_orderable_bytes(), [0xFF]);
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
        // Sign-flip at u8 (XOR 0x80) so MIN→0x00, 0→0x80, MAX→0xFF.
        assert_eq!(i8::MIN.to_orderable_bytes(), [0x00]);
        assert_eq!(0i8.to_orderable_bytes(), [0x80]);
        assert_eq!(i8::MAX.to_orderable_bytes(), [0xFF]);
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
        // Sign-flip at u16 (XOR 0x8000), then BE.
        assert_eq!(i16::MIN.to_orderable_bytes(), [0x00, 0x00]);
        assert_eq!(0i16.to_orderable_bytes(), [0x80, 0x00]);
        assert_eq!(i16::MAX.to_orderable_bytes(), [0xFF, 0xFF]);
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
        // Sign-flip at u32 (XOR 0x8000_0000), then BE.
        assert_eq!(i32::MIN.to_orderable_bytes(), [0x00, 0x00, 0x00, 0x00]);
        assert_eq!(0i32.to_orderable_bytes(), [0x80, 0x00, 0x00, 0x00]);
        assert_eq!(i32::MAX.to_orderable_bytes(), [0xFF, 0xFF, 0xFF, 0xFF]);
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
