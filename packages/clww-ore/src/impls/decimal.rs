//! OPE encryption for `rust_decimal::Decimal`, gated behind the `decimal`
//! feature.
//!
//! The encoder converts a `Decimal` into a canonical byte sequence whose
//! lexicographic order agrees with `Decimal::cmp` and whose byte equality
//! agrees with `Decimal` value equality. The bytes are then fed through the
//! shared variable-length OPE primitive ([`crate::impls::encrypt_ope_bits`]),
//! so the resulting ciphertext is an [`OpeCllw8VariableV1`] whose lex order
//! matches the plaintext order.
//!
//! ## Canonical encoding
//!
//! Every value is reduced to a *signed scientific form*: a sign indicator,
//! the decimal exponent of the leading significant digit, and the digits of
//! the normalised significand. Two `Decimal`s that compare equal under
//! `Decimal::cmp` map to identical bytes; this includes `1`, `1.0`, `1.00`
//! and signed zeros (`+0`, `-0`).
//!
//! Layout for a non-zero value:
//!
//! ```text
//! sign-byte | exp-byte | digit-bytes [ | terminator ]
//! ```
//!
//! - **Sign**: `0x00` for negative, `0x01` for zero, `0x02` for positive.
//!   Ensures any negative ciphertext is lex-less than the zero ciphertext,
//!   which is lex-less than any positive ciphertext.
//! - **Exp**: the decimal exponent of the leading significant digit, biased
//!   by `+128` so the result fits in an unsigned byte and lex order matches
//!   numeric order. `Decimal` constrains scale to `0..=28` and the mantissa
//!   to 96 bits, so the leading-digit exponent fits in `[-28, 28]`.
//! - **Digits**: the significant digits of the normalised mantissa, leading
//!   digit first, encoded as bytes `0x01..=0x0A` (digit `d` ↦ byte `d + 1`).
//!   Shifting digits out of `0x00`/`0xFF` keeps the negative terminator
//!   unambiguous.
//! - **Terminator**: only present for negatives. A trailing `0xFF` byte
//!   makes the prefix-rule lex compare resolve "more digits ⇒ more negative
//!   ⇒ smaller ciphertext" correctly.
//!
//! For negatives, the exp-byte and each digit-byte are bitwise-inverted so
//! that within a sign-and-exponent class a larger magnitude maps to a
//! smaller byte. The terminator (`0xFF`) is chosen larger than any inverted
//! digit byte (`0x01..=0x0A` ⇒ `0xF5..=0xFE` after inversion) so the prefix
//! rule never collides with a digit byte.
//!
//! Zero is a single `0x01` byte: `+0` and `-0` collide here, consistent with
//! `Decimal::cmp` treating them equal.

use crate::biterator::Biterator;
use crate::impls::encrypt_ope_bits;
use crate::impls::string::OpeCllw8VariableV1;
use crate::{CllwOpeEncrypt, Error, Key};
use rust_decimal::Decimal;

const SIGN_NEG: u8 = 0x00;
const SIGN_ZERO: u8 = 0x01;
const SIGN_POS: u8 = 0x02;
const NEG_TERMINATOR: u8 = 0xFF;
const EXP_BIAS: i32 = 128;

/// Build the canonical, order-preserving byte form of a `Decimal`.
///
/// See module docs for the layout. Two `Decimal`s that compare equal under
/// `Decimal::cmp` produce identical byte sequences.
pub(crate) fn canonical_bytes(d: &Decimal) -> Vec<u8> {
    if d.is_zero() {
        return vec![SIGN_ZERO];
    }

    let normalized = d.normalize();
    let raw_mantissa = normalized.mantissa();
    let scale = normalized.scale() as i32;
    let abs_mantissa = raw_mantissa.unsigned_abs();
    let (significand, trailing) = strip_trailing_zeros(abs_mantissa);
    let digits = digit_string(significand);

    // value = ±significand × 10^trailing × 10^(-scale)
    // Position of the leading digit relative to the ones place.
    let leading_exp = digits.len() as i32 - 1 + trailing - scale;
    debug_assert!(
        (-28..=28).contains(&leading_exp),
        "leading_exp {leading_exp} out of bounds for Decimal — mantissa or scale corrupted",
    );
    let biased_exp = (leading_exp + EXP_BIAS) as u8;

    let is_negative = raw_mantissa < 0;

    if is_negative {
        let mut out = Vec::with_capacity(2 + digits.len() + 1);
        out.push(SIGN_NEG);
        out.push(!biased_exp);
        for digit in digits {
            out.push(!(digit + 1));
        }
        out.push(NEG_TERMINATOR);
        out
    } else {
        let mut out = Vec::with_capacity(2 + digits.len());
        out.push(SIGN_POS);
        out.push(biased_exp);
        for digit in digits {
            out.push(digit + 1);
        }
        out
    }
}

/// Repeatedly divide by ten while the trailing digit is zero. Returns the
/// stripped value and how many trailing zero digits were removed.
fn strip_trailing_zeros(mut m: u128) -> (u128, i32) {
    if m == 0 {
        return (0, 0);
    }
    let mut t = 0;
    while m.is_multiple_of(10) {
        m /= 10;
        t += 1;
    }
    (m, t)
}

/// Decimal digits of `m`, leading digit first. `m` must be non-zero.
fn digit_string(m: u128) -> Vec<u8> {
    debug_assert!(m > 0);
    let mut digits = Vec::with_capacity(32);
    let mut v = m;
    while v > 0 {
        digits.push((v % 10) as u8);
        v /= 10;
    }
    digits.reverse();
    digits
}

impl CllwOpeEncrypt for Decimal {
    type Output = OpeCllw8VariableV1;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let canonical = canonical_bytes(&self);
        let n = canonical.len() * 8;
        let bits = canonical.into_iter().flat_map(Biterator::new);
        let bytes = encrypt_ope_bits(bits, n, key, salt);
        Ok(OpeCllw8VariableV1::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;
    use quickcheck::{quickcheck, Arbitrary, Gen, TestResult};
    use rust_decimal_macros::dec;
    use std::cmp::Ordering;

    fn key() -> Key {
        Key::from([7u8; 32])
    }

    fn encrypt(d: Decimal) -> OpeCllw8VariableV1 {
        key().encrypt_ope(d).unwrap()
    }

    // --- Canonical encoding: worked examples ---

    #[test]
    fn zero_canonicalises_to_single_byte() {
        assert_eq!(canonical_bytes(&dec!(0)), vec![SIGN_ZERO]);
        assert_eq!(canonical_bytes(&dec!(0.0)), vec![SIGN_ZERO]);
        assert_eq!(canonical_bytes(&dec!(0.000)), vec![SIGN_ZERO]);
    }

    #[test]
    fn negative_zero_canonicalises_with_zero() {
        // rust_decimal can store a sign-bit-set zero; Decimal::cmp treats it
        // equal to +0 and our encoder must too.
        let neg_zero = -dec!(0);
        assert_eq!(canonical_bytes(&neg_zero), canonical_bytes(&dec!(0)));
    }

    #[test]
    fn equivalent_forms_canonicalise_identically() {
        let one = canonical_bytes(&dec!(1));
        assert_eq!(canonical_bytes(&dec!(1.0)), one);
        assert_eq!(canonical_bytes(&dec!(1.00)), one);
        assert_eq!(canonical_bytes(&dec!(1.000)), one);
    }

    #[test]
    fn integer_trailing_zeros_canonicalise_to_scientific_form() {
        // 100 normalises to (mantissa=100, scale=0); the encoder strips the
        // remaining integer trailing zeros to recover scientific form.
        // sign-pos, biased_exp = 128 + 2 = 130, single significand digit 1 → 0x02
        assert_eq!(canonical_bytes(&dec!(100)), vec![SIGN_POS, 130, 2]);
    }

    #[test]
    fn worked_positive_examples() {
        assert_eq!(canonical_bytes(&dec!(1)), vec![SIGN_POS, 128, 2]);
        assert_eq!(canonical_bytes(&dec!(1.5)), vec![SIGN_POS, 128, 2, 6]);
        assert_eq!(canonical_bytes(&dec!(0.5)), vec![SIGN_POS, 127, 6]);
        assert_eq!(
            canonical_bytes(&dec!(9.99)),
            vec![SIGN_POS, 128, 10, 10, 10]
        );
    }

    #[test]
    fn worked_negative_examples() {
        assert_eq!(
            canonical_bytes(&dec!(-1)),
            vec![SIGN_NEG, !128u8, !2u8, NEG_TERMINATOR]
        );
        assert_eq!(
            canonical_bytes(&dec!(-1.5)),
            vec![SIGN_NEG, !128u8, !2u8, !6u8, NEG_TERMINATOR]
        );
    }

    // --- Order pinning ---

    #[test]
    fn preserves_order_across_dramatic_magnitudes() {
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
        let encrypted: Vec<_> = ascending.iter().copied().map(encrypt).collect();
        for window in encrypted.windows(2) {
            assert!(
                window[0] < window[1],
                "ciphertexts not strictly ordered across dramatic magnitudes"
            );
        }
    }

    #[test]
    fn preserves_order_at_signed_extremes() {
        let min = encrypt(Decimal::MIN);
        let neg_one = encrypt(dec!(-1));
        let zero = encrypt(dec!(0));
        let one = encrypt(dec!(1));
        let max = encrypt(Decimal::MAX);
        assert!(min < neg_one);
        assert!(neg_one < zero);
        assert!(zero < one);
        assert!(one < max);
    }

    #[test]
    fn smallest_positive_above_zero() {
        let zero = encrypt(dec!(0));
        let smallest = encrypt(Decimal::new(1, 28)); // 1e-28
        assert!(zero < smallest);
    }

    #[test]
    fn signed_zero_collides_in_ciphertext() {
        let pos_zero = encrypt(dec!(0));
        let neg_zero = encrypt(-dec!(0));
        assert_eq!(pos_zero, neg_zero);
    }

    #[test]
    fn equivalent_forms_collide_in_ciphertext() {
        let a = encrypt(dec!(1));
        let b = encrypt(dec!(1.0));
        let c = encrypt(dec!(1.00));
        let d = encrypt(dec!(1.000));
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(c, d);
    }

    #[test]
    fn vec_sort_consistent_with_decimal_sort() {
        // The headline invariant: sort a Vec of plaintexts and a Vec of
        // their ciphertexts and the orders must agree.
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

        let mut paired: Vec<_> = values.iter().copied().map(|v| (encrypt(v), v)).collect();
        paired.sort_by(|a, b| a.0.cmp(&b.0));
        let sorted_via_ct: Vec<_> = paired.into_iter().map(|(_, v)| v).collect();

        assert_eq!(sorted_via_ct, sorted_plain);
    }

    // --- Quickcheck: arbitrary Decimal generation ---

    #[derive(Debug, Clone)]
    struct ArbDecimal(Decimal);

    impl Arbitrary for ArbDecimal {
        fn arbitrary(g: &mut Gen) -> Self {
            // Decimal::from_parts gives full coverage of the 96-bit mantissa
            // and the [0, 28] scale range.
            let lo = u32::arbitrary(g);
            let mid = u32::arbitrary(g);
            let hi = u32::arbitrary(g);
            let negative = bool::arbitrary(g);
            let scale = u32::arbitrary(g) % 29;
            ArbDecimal(Decimal::from_parts(lo, mid, hi, negative, scale))
        }
    }

    /// Pair of `Decimal`s that name the same value via different
    /// `(mantissa, scale)` representations. Used to exercise canonicalisation
    /// — the property check requires both ciphertexts to be byte-equal.
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

            // Multiply mantissa by 10^extra; bail to identity if it would
            // exceed the 96-bit Decimal mantissa.
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
            // Sanity check: twin must equal base. If not (e.g. -0 reconstruction
            // quirk), fall back to identity rather than fabricate a false
            // "equivalent" pair.
            if twin != base {
                return EquivalentForms(base, base);
            }
            EquivalentForms(base, twin)
        }
    }

    quickcheck! {
        // Determinism: same input ⇒ same ciphertext.
        fn prop_decimal_determinism(x: ArbDecimal) -> bool {
            let key = key();
            let a = key.encrypt_ope(x.0).unwrap();
            let b = key.encrypt_ope(x.0).unwrap();
            a == b
        }

        // Headline invariant #1+#2: lex compare on ciphertexts agrees with
        // Decimal::cmp on plaintexts (covers ordering AND equality, since
        // cmp(x, y) == Equal iff x == y for total orders).
        fn prop_decimal_cmp_consistent(x: ArbDecimal, y: ArbDecimal) -> bool {
            let key = key();
            let a = key.encrypt_ope(x.0).unwrap();
            let b = key.encrypt_ope(y.0).unwrap();
            a.cmp(&b) == x.0.cmp(&y.0)
        }

        // Antisymmetry of the order homomorphism.
        fn prop_decimal_cmp_antisymmetric(x: ArbDecimal, y: ArbDecimal) -> bool {
            let key = key();
            let a = key.encrypt_ope(x.0).unwrap();
            let b = key.encrypt_ope(y.0).unwrap();
            a.cmp(&b) == b.cmp(&a).reverse()
        }

        // Negation flips order (excluding zero, which is its own negation).
        fn prop_decimal_negation_symmetry(x: ArbDecimal, y: ArbDecimal) -> TestResult {
            if x.0.is_zero() || y.0.is_zero() {
                return TestResult::discard();
            }
            let key = key();
            let neg_x = key.encrypt_ope(-x.0).unwrap();
            let neg_y = key.encrypt_ope(-y.0).unwrap();
            let pos_x = key.encrypt_ope(x.0).unwrap();
            let pos_y = key.encrypt_ope(y.0).unwrap();
            TestResult::from_bool(neg_x.cmp(&neg_y) == pos_y.cmp(&pos_x))
        }

        // Sign class: any negative < zero < any positive in ciphertext space.
        fn prop_decimal_sign_class(x: ArbDecimal) -> bool {
            let key = key();
            let zero = key.encrypt_ope(Decimal::ZERO).unwrap();
            let ct = key.encrypt_ope(x.0).unwrap();
            match x.0.cmp(&Decimal::ZERO) {
                Ordering::Less => ct < zero,
                Ordering::Equal => ct == zero,
                Ordering::Greater => ct > zero,
            }
        }

        // Length is a function of the canonical encoding only — independent
        // of key and salt.
        fn prop_decimal_length_independent_of_key(x: ArbDecimal, k1: Vec<u8>, k2: Vec<u8>) -> TestResult {
            if k1.len() != 32 || k2.len() != 32 {
                return TestResult::discard();
            }
            let mut a_key = [0u8; 32];
            a_key.copy_from_slice(&k1);
            let mut b_key = [0u8; 32];
            b_key.copy_from_slice(&k2);
            let a = Key::from(a_key).encrypt_ope(x.0).unwrap();
            let b = Key::from(b_key).encrypt_ope(x.0).unwrap();
            TestResult::from_bool(a.as_ref().len() == b.as_ref().len())
        }

        // Hex round-trip preserves bytes.
        fn prop_decimal_hex_round_trip(x: ArbDecimal) -> bool {
            let ct = key().encrypt_ope(x.0).unwrap();
            let hex_str = hex::encode(ct.as_ref());
            let ct2 = OpeCllw8VariableV1::from_hex(&hex_str).unwrap();
            ct == ct2
        }

        // Salt domain separation: distinct salts ⇒ distinct ciphertexts.
        fn prop_decimal_salt_differs(x: ArbDecimal) -> bool {
            let key = key();
            let a = x.0.encrypt_ope_with_salt(&key, Some(b"domain1")).unwrap();
            let b = x.0.encrypt_ope_with_salt(&key, Some(b"domain2")).unwrap();
            a != b
        }

        // Salt does not break order.
        fn prop_decimal_salt_preserves_order(x: ArbDecimal, y: ArbDecimal) -> bool {
            let key = key();
            let salt = b"some-domain";
            let a = x.0.encrypt_ope_with_salt(&key, Some(salt)).unwrap();
            let b = y.0.encrypt_ope_with_salt(&key, Some(salt)).unwrap();
            a.cmp(&b) == x.0.cmp(&y.0)
        }

        // Different `(mantissa, scale)` representations of the same value
        // produce identical ciphertexts.
        fn prop_decimal_equivalent_forms_collide(forms: EquivalentForms) -> bool {
            let key = key();
            let a = key.encrypt_ope(forms.0).unwrap();
            let b = key.encrypt_ope(forms.1).unwrap();
            a == b
        }
    }
}
