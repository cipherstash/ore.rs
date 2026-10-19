//! Concrete BlockORE schemes. Use [`bit2_w6`] for fixed-length values up to
//! 10 bytes, or [`chained`] for wider values and strings. The legacy
//! [`bit2`] scheme remains available for compatibility with existing data.

/// Invokes `$impl!(type, BLOCKS_CONST, tests_module, lo, hi)` for each
/// fixed-width type that fits the Bit6 packed prefix. Both v2 schemes
/// implement `OreEncrypt` for every type listed here, so a type added here
/// reaches both of them (issue #124). The chained scheme adds wider types
/// itself. The legacy scheme's list is frozen and kept separately.
macro_rules! for_each_bit6_type {
    ($impl:ident) => {
        $impl!(bool, BOOL_BLOCKS, bool_tests, false, true);
        $impl!(u8, U8_BLOCKS, u8_tests, 0u8, u8::MAX);
        $impl!(i8, I8_BLOCKS, i8_tests, i8::MIN, i8::MAX);
        $impl!(u16, U16_BLOCKS, u16_tests, 0u16, u16::MAX);
        $impl!(i16, I16_BLOCKS, i16_tests, i16::MIN, i16::MAX);
        $impl!(u32, U32_BLOCKS, u32_tests, 0u32, u32::MAX);
        $impl!(i32, I32_BLOCKS, i32_tests, i32::MIN, i32::MAX);
        $impl!(u64, U64_BLOCKS, u64_tests, 0u64, u64::MAX);
        $impl!(i64, I64_BLOCKS, i64_tests, i64::MIN, i64::MAX);
        $impl!(char, CHAR_BLOCKS, char_tests, '\0', char::MAX);
        $impl!(f32, F32_BLOCKS, f32_tests, f32::MIN, f32::MAX);
        $impl!(f64, F64_BLOCKS, f64_tests, f64::MIN, f64::MAX);
        #[cfg(feature = "chrono")]
        $impl!(
            ::chrono::NaiveDate,
            NAIVE_DATE_BLOCKS,
            naive_date_tests,
            ::chrono::NaiveDate::MIN,
            ::chrono::NaiveDate::MAX
        );
    };
}

/// 2-bit-indicator BlockORE with AES-128 PRF and Knuth-shuffle PRP.
pub mod bit2;

/// 6-bit-block variant of [`bit2`]: 4x less AES work per block and 4x
/// smaller right blocks. Wire format v2 (headered), frozen as of 0.9.0.
pub mod bit2_w6;

/// Variable-length / chained-prefix scheme (6-bit blocks): lifts the packed
/// 14-block cap via an AES-CMAC accumulator, enabling string encryption. Wire
/// format v2 (scheme id 0x03). See
/// `docs/plans/2026-06-15-ore-v2-cmac-accumulator-spec.md`.
pub mod chained;

pub(crate) mod keys;

pub(crate) mod decompose;
pub(crate) mod width;
