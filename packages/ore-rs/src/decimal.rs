//! ORE encryption for `rust_decimal::Decimal`, gated behind the `decimal`
//! feature.
//!
//! Wraps the canonical fixed-length byte encoding from
//! [`orderable_bytes::decimal`] in an [`OreEncrypt`] impl, feeding the
//! 14-byte plaintext through the existing fixed-N ORE machinery
//! (`N = 14`). See the `orderable_bytes::decimal` module docs for the
//! encoding details, ordering properties, and constant-time guarantees.

use crate::ciphertext::{CipherText, Left};
use crate::encrypt::OreEncrypt;
use crate::scheme::bit2::OreAes128;
use crate::{OreCipher, OreError};
use orderable_bytes::ToOrderableBytes;
use rand::{Rng, SeedableRng};
use rust_decimal::Decimal;

const ENCODED_LEN: usize = <Decimal as ToOrderableBytes>::ENCODED_LEN;

impl<T_: Rng + SeedableRng> OreEncrypt<OreAes128<T_>> for Decimal {
    type LeftOutput = Left<OreAes128<T_>, ENCODED_LEN>;
    type FullOutput = CipherText<OreAes128<T_>, ENCODED_LEN>;

    fn encrypt_left(&self, cipher: &OreAes128<T_>) -> Result<Self::LeftOutput, OreError> {
        cipher.encrypt_left(&self.to_orderable_bytes())
    }

    fn encrypt(&self, cipher: &OreAes128<T_>) -> Result<Self::FullOutput, OreError> {
        cipher.encrypt(&self.to_orderable_bytes())
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

    fn encrypt(ore: &OreAes128ChaCha20, d: Decimal) -> CipherText<OreAes128ChaCha20, ENCODED_LEN> {
        d.encrypt(ore).unwrap()
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
        let parsed = CipherText::<OreAes128ChaCha20, ENCODED_LEN>::from_slice(&bytes).unwrap();
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
