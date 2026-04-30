//! ORE encryption for `rust_decimal::Decimal`, gated behind the `decimal`
//! feature.
//!
//! Each `Decimal` is mapped to a fixed 14-byte canonical plaintext whose
//! byte-wise lexicographic order agrees with `Decimal::cmp` and whose byte
//! equality agrees with `Decimal` value equality (so `1`, `1.0`, `1.00` and
//! `±0` collide). The plaintext is fed through the existing fixed-N ORE
//! machinery with `N = 14`, well under the 15-byte cap imposed by the
//! AES-as-PRF construction in `scheme/bit2.rs`.
//!
//! ## Encoding (scientific form, base 10)
//!
//! Each non-zero value is re-expressed in *signed scientific form*:
//!
//! ```text
//! value = ±significand × 10^(leading_exp − digits(significand) + 1)
//! ```
//!
//! where `significand` is the mantissa with trailing zeros stripped (after
//! `Decimal::normalize`) and `leading_exp` is the decimal exponent of the
//! leading significant digit. For `Decimal`, `leading_exp ∈ [-28, 28]`.
//!
//! The 14-byte plaintext is bit-packed as:
//!
//! ```text
//! byte 0       : [sign:1][biased_exp:7]
//! bytes 1..=13 : padded_significand (104 bits, big-endian)
//! ```
//!
//! - **Sign bit** (top bit of byte 0): `1` for positive and zero, `0` for
//!   negative. Negative ciphertexts sort lex-less than zero, which sorts
//!   lex-less than any positive.
//! - **Biased exponent** (low 7 bits of byte 0): `leading_exp + 64`. For
//!   non-zero inputs this lands in `[36, 92]`. Zero uses `0`, which is
//!   unreachable for any non-zero positive — so zero never collides with a
//!   positive plaintext.
//! - **Padded significand** (104-bit big-endian field, bytes 1..13):
//!   `significand × 10^(29 − digits(significand))`, i.e. the significand
//!   left-justified to a fixed 29-digit width by appending trailing zeros.
//!   This is exactly the integer reading of the value's normalised
//!   fractional significand (in `[0.1, 1.0)`) at 29 digits of decimal
//!   precision; byte-wise lex compare on this field matches numeric compare
//!   across different significand digit counts at the same exponent.
//!   `Decimal`'s u96 mantissa has at most 29 decimal digits, so the padded
//!   value is at most `~10^29`, which fits comfortably in 104 bits.
//!
//! For negatives, the low 7 bits of byte 0 (`biased_exp`) and the 104-bit
//! mantissa region are bitwise inverted so within the negative class a
//! larger magnitude maps to smaller bytes. Combined with the sign-bit class
//! ordering this gives a total order over the full `Decimal` range.
//!
//! ## Equivalence semantics
//!
//! - `1`, `1.0`, `1.00` reduce to the same `(significand, leading_exp)` and
//!   therefore to identical plaintext bytes.
//! - `+0` and `-0` reduce to the same canonical zero plaintext.
//!
//! These match `Decimal::cmp` / `Decimal::eq` exactly.

use crate::ciphertext::{CipherText, Left};
use crate::encrypt::OreEncrypt;
use crate::{OreCipher, OreError};
use rust_decimal::Decimal;

/// Number of bytes in the canonical plaintext.
pub(crate) const PRE_ENCODED_LEN: usize = 14;

/// Width of the padded-significand field in bytes (13 bytes = 104 bits).
const MANTISSA_BYTES: usize = 13;

/// Bias applied to `leading_exp` so it fits unsigned within the 7-bit
/// exponent field. With bias 64 and `leading_exp ∈ [-28, 28]`, the biased
/// value lands in `[36, 92]`, well inside `[0, 127]`.
const EXP_BIAS: i32 = 64;

/// Fixed digit count the significand is padded to. `Decimal`'s 96-bit
/// mantissa supports up to 29 decimal digits; padding to exactly 29 is
/// what makes same-exponent comparisons across different significand
/// lengths byte-wise correct.
const PADDED_DIGITS: u32 = 29;

/// Top bit of byte 0 — set for positives and zero, clear for negatives.
const SIGN_BIT: u8 = 0x80;

/// Mask for the 7-bit exponent field in byte 0.
const EXP_MASK: u8 = 0x7F;

/// Build the canonical, order-preserving fixed-length plaintext for a
/// `Decimal`. Two `Decimal`s that compare equal under `Decimal::cmp` produce
/// identical byte arrays.
pub(crate) fn pre_encode(d: &Decimal) -> [u8; PRE_ENCODED_LEN] {
    let mut out = [0u8; PRE_ENCODED_LEN];

    if d.is_zero() {
        // Canonical zero: positive sign-class, biased_exp = 0, mantissa = 0.
        // No non-zero positive uses biased_exp = 0 (range is [36, 92]), so
        // zero is unambiguously distinct from every non-zero plaintext.
        out[0] = SIGN_BIT;
        return out;
    }

    // We deliberately don't call `Decimal::normalize()` here. `normalize`
    // strips trailing zeros from the mantissa via a `while scale > 0` loop
    // whose iteration count depends on the secret value's trailing-zero
    // count — a timing side channel. Our own `strip_trailing_zeros` already
    // strips *all* trailing zeros (a strict superset of what `normalize`
    // would remove, since it doesn't stop at scale=0), so the leading-digit
    // exponent we compute below is identical whether the input has been
    // normalised first or not. Skipping the call removes the leak.
    let raw_mantissa = d.mantissa();
    let scale = d.scale() as i32;
    // Branchless absolute value via the standard two's-complement identity
    // `abs(x) = (x ^ s) - s` where `s` is the arithmetic right-shift of the
    // sign bit (`-1` if `x` is negative, `0` otherwise). For positives this
    // collapses to `x - 0 = x`; for negatives to `~x + 1 = -x`. Equivalent
    // in value to `i128::unsigned_abs`, which compiles to a CMOV on tier-1
    // ISAs but is not language-guaranteed constant-time. The explicit form
    // here removes the dependency on optimiser behaviour.
    let sign_extension = raw_mantissa >> 127;
    let abs_mantissa = ((raw_mantissa ^ sign_extension).wrapping_sub(sign_extension)) as u128;
    let (significand, trailing) = strip_trailing_zeros(abs_mantissa);
    let digits = digit_count(significand);

    // value = ±significand × 10^trailing × 10^(-scale)
    // leading_exp = decimal exponent of the leading significant digit.
    let leading_exp = digits as i32 - 1 + trailing - scale;
    debug_assert!(
        (-28..=28).contains(&leading_exp),
        "leading_exp {} out of bounds for Decimal — mantissa or scale corrupted",
        leading_exp,
    );
    let biased_exp = (leading_exp + EXP_BIAS) as u8;
    debug_assert!(biased_exp <= EXP_MASK, "biased_exp overflowed 7 bits");

    // Pad the significand out to 29 decimal digits so same-exponent compares
    // across different significand lengths are byte-wise correct.
    let padded_mantissa = significand * 10u128.pow(PADDED_DIGITS - digits);
    let mant_be = padded_mantissa.to_be_bytes();
    debug_assert!(
        mant_be[..16 - MANTISSA_BYTES].iter().all(|&b| b == 0),
        "padded mantissa overflowed 104 bits",
    );
    let mant_field = &mant_be[16 - MANTISSA_BYTES..];

    let is_negative = raw_mantissa < 0;
    if is_negative {
        // sign = 0; invert biased_exp (within 7 bits) and the mantissa field
        // so larger magnitude → smaller bytes.
        out[0] = (!biased_exp) & EXP_MASK;
        for (i, &b) in mant_field.iter().enumerate() {
            out[1 + i] = !b;
        }
    } else {
        // sign = 1; biased_exp and mantissa go through unchanged.
        out[0] = SIGN_BIT | biased_exp;
        out[1..].copy_from_slice(mant_field);
    }
    out
}

/// Repeatedly divide by ten while the trailing digit is zero. Returns the
/// stripped value and how many trailing zero digits were removed.
///
/// Runs in constant time with respect to the input. The loop count is fixed
/// at `PADDED_DIGITS` iterations (covering the maximum possible trailing-
/// zero count for a u96-bounded `Decimal` mantissa, which is 28), and each
/// iteration uses bitmask conditional selection rather than a data-
/// dependent branch — so the function's timing does not leak the trailing-
/// zero count of the secret mantissa.
fn strip_trailing_zeros(m: u128) -> (u128, i32) {
    let mut current = m;
    let mut count: i32 = 0;
    for _ in 0..PADDED_DIGITS {
        let div = current / 10;
        let rem = current - div * 10;
        // For a u128 `x`, `(x | x.wrapping_neg()) >> 127` is the 1-bit mask
        // `1` iff `x != 0`.
        let cur_nz = (current | current.wrapping_neg()) >> 127;
        let rem_nz = (rem | rem.wrapping_neg()) >> 127;
        // strip iff current != 0 AND rem == 0
        let do_strip = cur_nz & (rem_nz ^ 1);
        let mask = 0u128.wrapping_sub(do_strip);
        current = (div & mask) | (current & !mask);
        count = count.wrapping_add(do_strip as i32);
    }
    (current, count)
}

/// Number of decimal digits in `m`. `m` must be non-zero.
///
/// Runs in constant time with respect to the input: a fixed
/// `PADDED_DIGITS` iterations with branchless tally, so timing does not
/// leak the digit count of the secret mantissa.
fn digit_count(m: u128) -> u32 {
    debug_assert!(m > 0);
    let mut current = m;
    let mut n: u32 = 0;
    for _ in 0..PADDED_DIGITS {
        // Increment `n` iff `current != 0` — same nonzero-mask idiom as
        // `strip_trailing_zeros`. `current / 10` is run unconditionally;
        // once `current` reaches zero it stays zero and stops contributing.
        let cur_nz = (current | current.wrapping_neg()) >> 127;
        n = n.wrapping_add(cur_nz as u32);
        current /= 10;
    }
    n
}

impl<T: OreCipher> OreEncrypt<T> for Decimal {
    type LeftOutput = Left<T, PRE_ENCODED_LEN>;
    type FullOutput = CipherText<T, PRE_ENCODED_LEN>;

    fn encrypt_left(&self, cipher: &T) -> Result<Self::LeftOutput, OreError> {
        cipher.encrypt_left(&pre_encode(self))
    }

    fn encrypt(&self, cipher: &T) -> Result<Self::FullOutput, OreError> {
        cipher.encrypt(&pre_encode(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ciphertext::OreOutput;
    use crate::scheme::bit2::OreAes128ChaCha20;
    use hex_literal::hex;
    use quickcheck::{Arbitrary, Gen, TestResult};
    use rust_decimal_macros::dec;
    use std::cmp::Ordering;

    fn cipher() -> OreAes128ChaCha20 {
        let k1: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        let k2: [u8; 16] = hex!("0f0e0d0c 0b0a0908 07060504 03020100");
        OreCipher::init(&k1, &k2).unwrap()
    }

    fn encrypt(
        ore: &OreAes128ChaCha20,
        d: Decimal,
    ) -> CipherText<OreAes128ChaCha20, PRE_ENCODED_LEN> {
        d.encrypt(ore).unwrap()
    }

    // --- Canonical encoding: structure and equivalence ---

    #[test]
    fn zero_canonicalises_to_sign_bit_only() {
        let mut expected = [0u8; PRE_ENCODED_LEN];
        expected[0] = SIGN_BIT;
        assert_eq!(pre_encode(&dec!(0)), expected);
        assert_eq!(pre_encode(&dec!(0.0)), expected);
        assert_eq!(pre_encode(&dec!(0.000)), expected);
    }

    #[test]
    fn negative_zero_canonicalises_with_zero() {
        let neg_zero = -dec!(0);
        assert_eq!(pre_encode(&neg_zero), pre_encode(&dec!(0)));
    }

    #[test]
    fn equivalent_forms_canonicalise_identically() {
        let one = pre_encode(&dec!(1));
        assert_eq!(pre_encode(&dec!(1.0)), one);
        assert_eq!(pre_encode(&dec!(1.00)), one);
        assert_eq!(pre_encode(&dec!(1.000)), one);
    }

    #[test]
    fn integer_trailing_zeros_share_significand_bytes() {
        // 100 strips to (sig=1, leading_exp=2). Same significand as 1, so the
        // padded-mantissa region must match.
        let one = pre_encode(&dec!(1));
        let hundred = pre_encode(&dec!(100));
        assert_eq!(&one[1..], &hundred[1..]);
        // Top bit (sign) matches; low 7 bits differ by leading_exp.
        assert_eq!(one[0] & SIGN_BIT, SIGN_BIT);
        assert_eq!(hundred[0] & SIGN_BIT, SIGN_BIT);
        assert_eq!(one[0] & EXP_MASK, EXP_BIAS as u8);
        assert_eq!(hundred[0] & EXP_MASK, (2i32 + EXP_BIAS) as u8);
    }

    #[test]
    fn worked_positive_examples() {
        let one = pre_encode(&dec!(1));
        assert_eq!(one[0], SIGN_BIT | (EXP_BIAS as u8));

        let half = pre_encode(&dec!(0.5));
        assert_eq!(half[0], SIGN_BIT | ((-1i32 + EXP_BIAS) as u8));

        let ten = pre_encode(&dec!(10));
        assert_eq!(ten[0], SIGN_BIT | ((1i32 + EXP_BIAS) as u8));
    }

    #[test]
    fn worked_negative_examples() {
        let neg_one = pre_encode(&dec!(-1));
        let pos_one = pre_encode(&dec!(1));

        // Negative byte 0: sign bit clear, low 7 bits are inverted exp.
        assert_eq!(neg_one[0] & SIGN_BIT, 0);
        assert_eq!(neg_one[0] & EXP_MASK, !(EXP_BIAS as u8) & EXP_MASK);

        // Negative mantissa bytes are bitwise complements of the positive.
        for i in 1..PRE_ENCODED_LEN {
            assert_eq!(neg_one[i], !pos_one[i]);
        }
    }

    #[test]
    fn pre_encode_byte_order_matches_decimal_order() {
        // The canonical bytes themselves must sort consistently with
        // `Decimal::cmp` — this is the property the ORE comparator depends on.
        let values = [
            Decimal::MIN,
            dec!(-1000000000),
            dec!(-1.5),
            dec!(-1.05),
            dec!(-1),
            dec!(-0.001),
            dec!(0),
            dec!(0.001),
            dec!(1),
            dec!(1.05),
            dec!(1.5),
            dec!(1000000000),
            Decimal::MAX,
        ];
        for window in values.windows(2) {
            let a = pre_encode(&window[0]);
            let b = pre_encode(&window[1]);
            assert!(
                a < b,
                "pre_encode({}) < pre_encode({}) failed",
                window[0],
                window[1]
            );
        }
    }

    // --- Order pinning via ORE ciphertexts ---

    #[test]
    fn preserves_order_across_dramatic_magnitudes() {
        let ore = cipher();
        let ascending = [
            dec!(-1000000000000),
            dec!(-1000000),
            dec!(-1.001),
            dec!(-1),
            dec!(-0.001),
            dec!(0),
            dec!(0.001),
            dec!(1),
            dec!(1.001),
            dec!(1000000),
            dec!(1000000000000),
        ];
        let encrypted: Vec<_> = ascending.iter().map(|d| encrypt(&ore, *d)).collect();
        for window in encrypted.windows(2) {
            assert!(window[0] < window[1]);
        }
    }

    #[test]
    fn preserves_order_at_signed_extremes() {
        let ore = cipher();
        let min = encrypt(&ore, Decimal::MIN);
        let neg_one = encrypt(&ore, dec!(-1));
        let zero = encrypt(&ore, dec!(0));
        let one = encrypt(&ore, dec!(1));
        let max = encrypt(&ore, Decimal::MAX);
        assert!(min < neg_one);
        assert!(neg_one < zero);
        assert!(zero < one);
        assert!(one < max);
    }

    #[test]
    fn smallest_positive_above_zero() {
        let ore = cipher();
        let zero = encrypt(&ore, dec!(0));
        let smallest = encrypt(&ore, Decimal::new(1, 28)); // 1e-28
        assert!(zero < smallest);
    }

    #[test]
    fn signed_zero_collides_in_ciphertext() {
        let ore = cipher();
        let pos_zero = encrypt(&ore, dec!(0));
        let neg_zero = encrypt(&ore, -dec!(0));
        assert_eq!(pos_zero.cmp(&neg_zero), Ordering::Equal);
    }

    #[test]
    fn equivalent_forms_collide_in_ciphertext() {
        let ore = cipher();
        let a = encrypt(&ore, dec!(1));
        let b = encrypt(&ore, dec!(1.0));
        let c = encrypt(&ore, dec!(1.00));
        let d = encrypt(&ore, dec!(1.000));
        assert_eq!(a.cmp(&b), Ordering::Equal);
        assert_eq!(b.cmp(&c), Ordering::Equal);
        assert_eq!(c.cmp(&d), Ordering::Equal);
    }

    #[test]
    fn vec_sort_consistent_with_decimal_sort() {
        let ore = cipher();
        let values = vec![
            dec!(0),
            Decimal::MAX,
            dec!(-1.0),
            Decimal::MIN,
            dec!(0.001),
            dec!(-0.5),
            dec!(1000),
            dec!(1.001),
            dec!(-1000000),
            dec!(0.999999999),
        ];
        let mut sorted_plain = values.clone();
        sorted_plain.sort();

        let mut paired: Vec<_> = values
            .iter()
            .copied()
            .map(|v| (encrypt(&ore, v), v))
            .collect();
        paired.sort_by(|a, b| a.0.cmp(&b.0));
        let sorted_via_ct: Vec<_> = paired.into_iter().map(|(_, v)| v).collect();

        assert_eq!(sorted_via_ct, sorted_plain);
    }

    #[test]
    fn hex_round_trip_via_ore_output() {
        let ore = cipher();
        let ct = encrypt(&ore, dec!(123.456));
        let bytes = ct.to_bytes();
        let parsed = CipherText::<OreAes128ChaCha20, PRE_ENCODED_LEN>::from_slice(&bytes).unwrap();
        assert_eq!(ct.cmp(&parsed), Ordering::Equal);
    }

    // --- Quickcheck: arbitrary Decimal generation ---

    #[derive(Debug, Clone)]
    struct ArbDecimal(Decimal);

    impl Arbitrary for ArbDecimal {
        fn arbitrary(g: &mut Gen) -> Self {
            let lo = u32::arbitrary(g);
            let mid = u32::arbitrary(g);
            let hi = u32::arbitrary(g);
            let negative = bool::arbitrary(g);
            let scale = u32::arbitrary(g) % 29;
            ArbDecimal(Decimal::from_parts(lo, mid, hi, negative, scale))
        }
    }

    /// Pair of `Decimal`s that name the same value via different
    /// `(mantissa, scale)` representations.
    #[derive(Debug, Clone)]
    struct EquivalentForms(Decimal, Decimal);

    impl Arbitrary for EquivalentForms {
        fn arbitrary(g: &mut Gen) -> Self {
            let base = ArbDecimal::arbitrary(g).0;
            let headroom = 28u32.saturating_sub(base.scale());
            if headroom == 0 || base.is_zero() {
                return EquivalentForms(base, base);
            }
            let extra = (u32::arbitrary(g) % headroom) + 1;

            let mut new_mantissa = base.mantissa().unsigned_abs();
            for _ in 0..extra {
                match new_mantissa.checked_mul(10) {
                    Some(v) if v < (1u128 << 96) => new_mantissa = v,
                    _ => return EquivalentForms(base, base),
                }
            }
            let lo = new_mantissa as u32;
            let mid = (new_mantissa >> 32) as u32;
            let hi = (new_mantissa >> 64) as u32;
            let twin =
                Decimal::from_parts(lo, mid, hi, base.is_sign_negative(), base.scale() + extra);
            if twin != base {
                return EquivalentForms(base, base);
            }
            EquivalentForms(base, twin)
        }
    }

    quickcheck! {
        fn prop_decimal_cmp_consistent(x: ArbDecimal, y: ArbDecimal) -> bool {
            let ore = cipher();
            let a = encrypt(&ore, x.0);
            let b = encrypt(&ore, y.0);
            a.cmp(&b) == x.0.cmp(&y.0)
        }

        fn prop_decimal_cmp_antisymmetric(x: ArbDecimal, y: ArbDecimal) -> bool {
            let ore = cipher();
            let a = encrypt(&ore, x.0);
            let b = encrypt(&ore, y.0);
            a.cmp(&b) == b.cmp(&a).reverse()
        }

        fn prop_decimal_negation_symmetry(x: ArbDecimal, y: ArbDecimal) -> TestResult {
            if x.0.is_zero() || y.0.is_zero() {
                return TestResult::discard();
            }
            let ore = cipher();
            let neg_x = encrypt(&ore, -x.0);
            let neg_y = encrypt(&ore, -y.0);
            let pos_x = encrypt(&ore, x.0);
            let pos_y = encrypt(&ore, y.0);
            TestResult::from_bool(neg_x.cmp(&neg_y) == pos_y.cmp(&pos_x))
        }

        fn prop_decimal_sign_class(x: ArbDecimal) -> bool {
            let ore = cipher();
            let zero = encrypt(&ore, Decimal::ZERO);
            let ct = encrypt(&ore, x.0);
            match x.0.cmp(&Decimal::ZERO) {
                Ordering::Less => ct < zero,
                Ordering::Equal => ct.cmp(&zero) == Ordering::Equal,
                Ordering::Greater => ct > zero,
            }
        }

        fn prop_decimal_equivalent_forms_collide(forms: EquivalentForms) -> bool {
            let ore = cipher();
            let a = encrypt(&ore, forms.0);
            let b = encrypt(&ore, forms.1);
            a.cmp(&b) == Ordering::Equal
        }
    }
}
