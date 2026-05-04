//! Canonical, order-preserving fixed-length byte encodings for the
//! signed-integer primitives `i16`, `i32`, `i64` and the IEEE 754
//! double `f64`.
//!
//! Each impl emits the type's native byte width (no widening). Byte-wise
//! lex compare on the output agrees with the type's natural total order
//! (or partial order, in the f64 case — see below).
//!
//! ## Signed integers (`i16`, `i32`, `i64`)
//!
//! Two's-complement signed integers are mapped to their unsigned
//! equivalent by flipping the sign bit (`x ^ (1 << (N-1))`), then
//! serialised big-endian. Sign-flipping moves negatives below positives
//! (sign bit `1` for negatives clears to `0`, vice versa for positives)
//! and preserves order within each sign class.
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

    // --- i16 ---

    #[test]
    fn i16_known_anchors() {
        // i16::MIN sign-flips to 0x0000, 0 to 0x8000, i16::MAX to 0xFFFF.
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
