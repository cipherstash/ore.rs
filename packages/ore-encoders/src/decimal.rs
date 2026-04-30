//! Canonical, order-preserving fixed-length pre-encoder for
//! `rust_decimal::Decimal`.
//!
//! Maps each `Decimal` to a fixed 14-byte canonical plaintext whose
//! byte-wise lexicographic order agrees with `Decimal::cmp` and whose byte
//! equality agrees with `Decimal` value equality (so `1`, `1.0`, `1.00` and
//! `±0` collide). Intended to be fed into the `ore-rs` fixed-N ORE machinery
//! with `N = 14`, well under the 15-byte cap imposed by its AES-as-PRF
//! construction; the resulting ciphertexts inherit the same order and
//! equality properties.
//!
//! ## Encoding (scientific form, base 10)
//!
//! Each non-zero value is re-expressed in *signed scientific form*:
//!
//! ```text
//! value = ±significand × 10^(leading_exp − digits(significand) + 1)
//! ```
//!
//! where `significand` is the mantissa with trailing zeros stripped and
//! `leading_exp` is the decimal exponent of the leading significant digit.
//! For `Decimal`, `leading_exp ∈ [-28, 28]`.
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
//!
//! ## Constant-time
//!
//! `pre_encode` is straight-line code with fixed-iteration loops and
//! branchless mask arithmetic. It does not call `Decimal::normalize`
//! (which loops while `scale > 0`) and does not branch on sign or
//! zero-ness. Timing does not distinguish the input's sign, zero-ness,
//! digit count, trailing-zero count, or scale.

use rust_decimal::Decimal;

/// Number of bytes in the canonical plaintext.
pub const PRE_ENCODED_LEN: usize = 14;

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
pub fn pre_encode(d: &Decimal) -> [u8; PRE_ENCODED_LEN] {
    let mut out = [0u8; PRE_ENCODED_LEN];

    // The pipeline runs unconditionally — no early return for zero inputs.
    // A `d.is_zero()` short-circuit at the top would distinguish zero from
    // non-zero plaintexts via timing. Instead we feed zero through the same
    // sequence of operations as every other value (the helpers tolerate
    // `m == 0` and produce `(significand=0, digits=0, trailing=0)`) and
    // canonicalise the resulting byte 0 to the zero plaintext at the end
    // via a branchless mask.
    //
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
    //
    // For non-zero `Decimal`s `leading_exp` lies in `[-28, 28]`. The
    // pipeline also runs for zero inputs (significand = 0, digits = 0,
    // trailing = 0), where the formula collapses to `-1 - scale` and
    // `leading_exp` lands in `[-29, -1]`; this produces a perfectly valid
    // — though arbitrary — non-zero positive plaintext that we'll
    // overwrite at the end with the canonical zero. The widened range
    // `[-29, 28]` covers both branches without leaking the zero/non-zero
    // distinction in debug builds either.
    let leading_exp = digits as i32 - 1 + trailing - scale;
    debug_assert!(
        (-29..=28).contains(&leading_exp),
        "leading_exp {} out of bounds — mantissa or scale corrupted",
        leading_exp,
    );
    let biased_exp = (leading_exp + EXP_BIAS) as u8;
    debug_assert!(biased_exp <= EXP_MASK, "biased_exp overflowed 7 bits");

    // Pad the significand out to 29 decimal digits so same-exponent compares
    // across different significand lengths are byte-wise correct.
    //
    // We can't write this as `significand * 10u128.pow(PADDED_DIGITS - digits)`
    // — `u128::pow` is square-and-multiply on the bits of its exponent, with
    // both the iteration count and the conditional `acc * base` step driven
    // by the exponent value. Since the exponent here is `PADDED_DIGITS −
    // digits` and `digits` is derived from the secret mantissa, that would
    // leak the digit count via timing.
    //
    // Instead, run a fixed `PADDED_DIGITS`-iteration loop that multiplies
    // `padded_mantissa` by 10 under a branchless mask. The mask is `1` while
    // we still have padding to apply (`digits + i < PADDED_DIGITS`) and `0`
    // afterwards; the multiplication itself is computed unconditionally each
    // iteration so the instruction sequence doesn't depend on `digits`.
    //
    // No overflow concern: in any iteration where the mask is `1` we have
    // `padded_mantissa < 10^(PADDED_DIGITS-1) ≤ 10^28`, so `× 10` stays
    // under `10^29`. In iterations where the mask is `0`, `padded_mantissa`
    // sits at its final value (≤ `10^29`) and the unstored `× 10` product
    // is at most `10^30 ≈ 2^99.7`, well inside `u128`.
    let mut padded_mantissa = significand;
    for i in 0..PADDED_DIGITS {
        let do_step = ((digits + i) < PADDED_DIGITS) as u128;
        let mask = 0u128.wrapping_sub(do_step);
        let stepped = padded_mantissa.wrapping_mul(10);
        padded_mantissa = (padded_mantissa & !mask) | (stepped & mask);
    }
    let mant_be = padded_mantissa.to_be_bytes();
    debug_assert!(
        mant_be[..16 - MANTISSA_BYTES].iter().all(|&b| b == 0),
        "padded mantissa overflowed 104 bits",
    );
    let mant_field = &mant_be[16 - MANTISSA_BYTES..];

    // Sign-class handling is folded into a single branchless mask so the
    // function executes the same instructions regardless of the input's
    // sign. `neg_mask` is `0xFF` for negatives and `0x00` for positives
    // (and zero, which lives in the positive sign-class), formed from the
    // arithmetic shift of the sign bit and a u8 truncation.
    //
    // - byte 0: positives want `SIGN_BIT | biased_exp`; negatives want
    //   `(!biased_exp) & EXP_MASK`. Expressed as one expression:
    //     (SIGN_BIT & !neg_mask)        — keep sign bit only when positive
    //   | (biased_exp ^ (neg_mask & EXP_MASK))
    //                                   — XOR the 7 exp bits with `neg_mask`,
    //                                     which is a no-op for positives and
    //                                     a 7-bit complement for negatives.
    //
    // - mantissa bytes: positives want the bytes unchanged; negatives want
    //   the bitwise complement. `b ^ neg_mask` does both: XOR with `0x00`
    //   is a no-op, XOR with `0xFF` is bitwise NOT.
    let neg_mask = (raw_mantissa >> 127) as u8;
    out[0] = (SIGN_BIT & !neg_mask) | (biased_exp ^ (neg_mask & EXP_MASK));
    for (i, &b) in mant_field.iter().enumerate() {
        out[1 + i] = b ^ neg_mask;
    }

    // Final canonicalisation for the zero plaintext, applied branchlessly
    // so the function's timing doesn't reveal whether the input was zero.
    //
    // The non-zero pipeline ran end-to-end on the zero input too. With
    // `significand = 0` the padded mantissa is also `0`, so `out[1..]` is
    // already the all-zero canonical zero tail; we only need to fix up
    // `out[0]`, which currently holds some valid-looking positive
    // `SIGN_BIT | biased_exp` byte.
    //
    // Build a full-byte mask `zero_mask` that is `0xFF` when `abs_mantissa
    // == 0` and `0x00` otherwise:
    //   - `(x | -x) >> 127` is `1` if `x != 0`, `0` if `x == 0` (standard
    //     u128 nonzero-detection idiom).
    //   - XOR with `1` flips it to "is zero".
    //   - Subtract from `0u8` to broadcast the bit across all 8 bits.
    // Then merge: keep `out[0]` for non-zero, replace with `SIGN_BIT` for
    // zero.
    let mant_nonzero_bit = ((abs_mantissa | abs_mantissa.wrapping_neg()) >> 127) as u8;
    let zero_mask = 0u8.wrapping_sub(mant_nonzero_bit ^ 1);
    out[0] = (out[0] & !zero_mask) | (SIGN_BIT & zero_mask);
    out
}

/// `5⁻¹ mod 2¹²⁸`. Verified: `5 * INV5 ≡ 1 (mod 2¹²⁸)`. Used to substitute
/// the hardware `udiv` instruction (which has data-dependent latency on
/// several real ISAs, including older ARM cores) with an unconditional
/// multiply.
const INV5: u128 = 0xCCCC_CCCC_CCCC_CCCC_CCCC_CCCC_CCCC_CCCD;

/// Largest `u128` divisible by 5, equivalently `floor((2¹²⁸ − 1) / 5)`.
/// Used as the threshold for the constant-time "is divisible by 5" test:
/// because multiplication by [`INV5`] is a bijection on `u128` that maps
/// `{0, 5, 10, …, 2¹²⁸ − 5}` onto `[0, MAX_DIV_5]`, `x.wrapping_mul(INV5) ≤
/// MAX_DIV_5` iff `5 | x`.
const MAX_DIV_5: u128 = u128::MAX / 5;

/// Repeatedly divide by ten while the trailing digit is zero. Returns the
/// stripped value and how many trailing zero digits were removed.
///
/// Runs in constant time with respect to the input. The loop count is fixed
/// at `PADDED_DIGITS` iterations (covering the maximum possible trailing-
/// zero count for a u96-bounded `Decimal` mantissa, which is 28), each
/// iteration uses bitmask conditional selection rather than a data-
/// dependent branch, and we explicitly avoid hardware integer division
/// because `udiv` latency is data-dependent on several real ISAs (notably
/// older ARM cores; modern x86 is constant-time but the next compiler
/// revision could regress lowering).
///
/// Two tricks make this division-free:
///
/// - **Inverse-multiply division.** When `10 | current`, `current / 10` can
///   be computed as `(current >> 1).wrapping_mul(INV5)`. Halving is exact
///   for even values, then the multiply-by-`5⁻¹ (mod 2¹²⁸)` recovers the
///   quotient. When `10 ∤ current` the result is garbage — discarded by
///   the masked select below.
///
/// - **Divisibility-by-10 test.** `10 | x ⟺ (2 | x) ∧ (5 | x)`. The
///   `2 | x` test is the LSB of `x`. The `5 | x` test exploits the same
///   inverse-multiply identity: multiplication by `INV5` is a bijection on
///   `u128`, and the multiples of 5 land precisely in `[0, MAX_DIV_5]`. So
///   `x.wrapping_mul(INV5) ≤ MAX_DIV_5 ⟺ 5 | x`. The comparison is
///   lowered to `overflowing_sub` (SBB + carry on x86, equivalent on ARM),
///   which is data-independent on every reasonable target.
fn strip_trailing_zeros(m: u128) -> (u128, i32) {
    let mut current = m;
    let mut count: i32 = 0;
    for _ in 0..PADDED_DIGITS {
        // Inverse-multiply division by 10. Valid only when 10 | current;
        // garbage otherwise, but masked out by `do_strip` below.
        let div = (current >> 1).wrapping_mul(INV5);

        // CT divisibility-by-10. `5 | current` iff `current * INV5 ≤
        // MAX_DIV_5`; the comparison is implemented via `overflowing_sub`
        // so it lowers to a borrow-out of a subtract instead of a branch.
        let q5 = current.wrapping_mul(INV5);
        let (_, borrow) = MAX_DIV_5.overflowing_sub(q5);
        let div_by_5 = (borrow as u128) ^ 1; // 1 iff 5 | current
        let div_by_2 = (current & 1) ^ 1; // 1 iff 2 | current
        let div_by_10 = div_by_5 & div_by_2;

        // Standard `(x | -x) >> 127` nonzero-mask: 1 iff current != 0.
        let cur_nz = (current | current.wrapping_neg()) >> 127;

        let do_strip = cur_nz & div_by_10;
        let mask = 0u128.wrapping_sub(do_strip);
        current = (div & mask) | (current & !mask);
        count = count.wrapping_add(do_strip as i32);
    }
    (current, count)
}

/// Number of decimal digits in `m`. Returns `0` for `m == 0`.
///
/// Runs in constant time with respect to the input. Like
/// [`strip_trailing_zeros`] this avoids hardware division entirely, but
/// the inverse-multiply trick doesn't transfer here — we'd need true
/// `floor(current / 10)` for arbitrary `current`, not just when divisible.
/// Instead the digit count is recast as the number of `i ∈ [0, PADDED_DIGITS)`
/// for which `m ≥ 10^i`. Each comparison is computed via `overflowing_sub`
/// (which lowers to SBB + carry on x86 and is data-independent on every
/// reasonable target), and the running power of ten is stepped via
/// `wrapping_mul(10)` — multiplication by a small constant is constant-
/// time on every target this code is likely to run on.
fn digit_count(m: u128) -> u32 {
    let mut n: u32 = 0;
    let mut pow: u128 = 1; // 10^i, walking 10^0 .. 10^(PADDED_DIGITS − 1)
    for _ in 0..PADDED_DIGITS {
        // borrow = 1 iff m < pow; we want n += (m >= pow) = !borrow.
        let (_, borrow) = m.overflowing_sub(pow);
        n = n.wrapping_add((borrow as u32) ^ 1);
        // Final iteration's value is computed but unused; wrapping is fine.
        pow = pow.wrapping_mul(10);
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

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
}
