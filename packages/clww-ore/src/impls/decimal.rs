//! OPE encryption for `rust_decimal::Decimal`, gated behind the `decimal`
//! feature.
//!
//! Delegates to the shared `[u8; N]` impl in [`super::byte_array`] after
//! canonicalising via [`orderable_bytes::decimal::to_orderable_bytes`].
//! See that module for the encoding details, ordering guarantees, and
//! constant-time properties.

use crate::{ClwwOpeEncrypt, Error, Key, OpeClww8V1};
use orderable_bytes::ToOrderableBytes;
use rust_decimal::Decimal;

impl ClwwOpeEncrypt for Decimal {
    type Output = OpeClww8V1<{ <Self as ToOrderableBytes>::ENCODED_LEN * 8 + 1 }>;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        self.to_orderable_bytes().encrypt_ope_with_salt(key, salt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;
    use quickcheck::{quickcheck, Arbitrary, Gen, TestResult};
    use rust_decimal_macros::dec;
    use std::cmp::Ordering;

    const CT_LEN: usize = <Decimal as ToOrderableBytes>::ENCODED_LEN * 8 + 1;

    fn key() -> Key {
        Key::from([7u8; 32])
    }

    fn encrypt(d: Decimal) -> OpeClww8V1<{ CT_LEN }> {
        key().encrypt_ope(d).unwrap()
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
        paired.sort_by_key(|a| a.0);
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

        // Length is fixed by the canonical encoding — independent of input.
        fn prop_decimal_length_invariant(x: ArbDecimal) -> bool {
            let ct = key().encrypt_ope(x.0).unwrap();
            ct.as_ref().len() == CT_LEN
        }

        // Hex round-trip preserves bytes.
        fn prop_decimal_hex_round_trip(x: ArbDecimal) -> bool {
            let ct = key().encrypt_ope(x.0).unwrap();
            let hex_str = hex::encode(ct.as_ref());
            let ct2 = OpeClww8V1::<CT_LEN>::from_hex(&hex_str).unwrap();
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
