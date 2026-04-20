use crate::{
    biterator::Biterator, CllwOpeDecrypt, CllwOpeEncrypt, CllwOreDecrypt, CllwOreEncrypt, Error,
    Key,
};
use hex::FromHex;
#[cfg(feature = "postgres-types")]
use postgres_types::ToSql;
use std::cmp::Ordering;
use subtle::ConstantTimeEq;

/// Fixed-size CLLW ORE ciphertext for unsigned integer types.
///
/// This type represents an encrypted value using the CLLW Order-Revealing Encryption scheme.
/// The size `N` corresponds to the number of bits in the plaintext (one byte per bit).
///
/// - `OreCllw8V1<8>` encrypts `u8` (8 bytes)
/// - `OreCllw8V1<16>` encrypts `u16` (16 bytes)
/// - `OreCllw8V1<32>` encrypts `u32` (32 bytes)
/// - `OreCllw8V1<64>` encrypts `u64` (64 bytes)
/// - `OreCllw8V1<128>` encrypts `u128` (128 bytes)
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "postgres-types", derive(ToSql))]
#[cfg_attr(feature = "postgres-types", postgres(name = "ore_cllw_8_v1"))]
pub struct OreCllw8V1<const N: usize> {
    pub(super) bytes: [u8; N],
}

impl<const N: usize> AsRef<[u8]> for OreCllw8V1<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<const N: usize> FromHex for OreCllw8V1<N> {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, <Self as FromHex>::Error> {
        let mut out = [0u8; N];
        hex::decode_to_slice(hex, &mut out as &mut [u8]).map_err(|_| Error)?;
        Ok(Self { bytes: out })
    }
}

impl<const N: usize> TryFrom<&[u8]> for OreCllw8V1<N> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != N {
            return Err(Error);
        }

        let mut bytes: [u8; N] = [0; N];
        bytes.copy_from_slice(value);
        Ok(OreCllw8V1 { bytes })
    }
}

/// Macro to implement CllwOreEncrypt and CllwOreDecrypt for unsigned integer types
macro_rules! impl_cllw_ore_uint {
    ($uint_type:ty, $array_size:expr) => {
        impl CllwOreEncrypt for $uint_type {
            type Output = OreCllw8V1<$array_size>;

            fn encrypt_with_salt(
                self,
                key: &Key,
                salt: Option<&[u8]>,
            ) -> Result<Self::Output, Error> {
                let mut hasher = blake3::Hasher::new_keyed(&key.0);
                if let Some(salt) = salt {
                    let _ = hasher.update(salt);
                }

                let mut bytes: [u8; $array_size] = [0; $array_size];
                Biterator::new(self).enumerate().for_each(|(i, bit)| {
                    let mut buf: [u8; 16] = [0; 16];
                    hasher.finalize_xof().fill(&mut buf);
                    let byte = u128::from_be_bytes(buf).wrapping_add(bit as u128) & 0xFF;
                    let _ = hasher.update(&[bit]);
                    bytes[i] = byte as u8;
                });

                Ok(OreCllw8V1 { bytes })
            }
        }

        impl CllwOreDecrypt for OreCllw8V1<$array_size> {
            type Output = $uint_type;

            fn decrypt_with_salt(
                self,
                key: &Key,
                salt: Option<&[u8]>,
            ) -> Result<Self::Output, Error> {
                let mut hasher = blake3::Hasher::new_keyed(&key.0);
                if let Some(salt) = salt {
                    let _ = hasher.update(salt);
                }

                let mut result: $uint_type = 0;
                for (i, &ciphertext_byte) in self.bytes.iter().enumerate() {
                    let mut buf: [u8; 16] = [0; 16];
                    hasher.finalize_xof().fill(&mut buf);
                    let prf_block = u128::from_be_bytes(buf) & 0xFF;
                    // Recover the bit by subtracting ciphertext from PRF block
                    let bit = ciphertext_byte.wrapping_sub(prf_block as u8) & 0x01;
                    let _ = hasher.update(&[bit]);
                    // Set the bit in the result (MSB first)
                    // Use constant-time operation to avoid timing side-channel
                    result |= (bit as $uint_type) << ((<$uint_type>::BITS - 1) - i as u32);
                }

                Ok(result)
            }
        }
    };
}

// Generate encrypt/decrypt implementations for all unsigned integer types
impl_cllw_ore_uint!(u8, 8);
impl_cllw_ore_uint!(u16, 16);
impl_cllw_ore_uint!(u32, 32);
impl_cllw_ore_uint!(u64, 64);
impl_cllw_ore_uint!(u128, 128);

impl<const N: usize> Ord for OreCllw8V1<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        super::compare_slice(self.bytes.as_slice(), other.bytes.as_slice())
    }
}

impl<const N: usize> PartialOrd for OreCllw8V1<N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize> PartialEq for OreCllw8V1<N> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl<const N: usize> Eq for OreCllw8V1<N> {}

// --- Fixed-size numeric OPE ---

/// Fixed-size CLLW OPE ciphertext for unsigned integer types.
///
/// This is the Order-Preserving Encryption variant of [`OreCllw8V1`]. The underlying bytes
/// are identical to the ORE ciphertext, but comparison uses standard lexicographic byte
/// ordering instead of the ORE comparison function. This means ciphertexts can be compared
/// using normal numeric/byte comparison without a custom comparison function.
///
/// **Correctness**: OPE comparison is correct with probability `1 - 1/256 ~ 99.6%` per
/// comparison. The error occurs when the PRF output at the first differing bit position
/// wraps around modulo 256. See Section 3.2 of the CLWW paper for details.
///
/// The size `N` corresponds to the number of bits in the plaintext (one byte per bit).
///
/// - `OpeCllw8V1<8>` encrypts `u8` (8 bytes)
/// - `OpeCllw8V1<16>` encrypts `u16` (16 bytes)
/// - `OpeCllw8V1<32>` encrypts `u32` (32 bytes)
/// - `OpeCllw8V1<64>` encrypts `u64` (64 bytes)
/// - `OpeCllw8V1<128>` encrypts `u128` (128 bytes)
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "postgres-types", derive(ToSql))]
#[cfg_attr(feature = "postgres-types", postgres(name = "ore_cllw_8_ope_v1"))]
pub struct OpeCllw8V1<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> AsRef<[u8]> for OpeCllw8V1<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<const N: usize> FromHex for OpeCllw8V1<N> {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, <Self as FromHex>::Error> {
        let mut out = [0u8; N];
        hex::decode_to_slice(hex, &mut out as &mut [u8]).map_err(|_| Error)?;
        Ok(Self { bytes: out })
    }
}

impl<const N: usize> TryFrom<&[u8]> for OpeCllw8V1<N> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != N {
            return Err(Error);
        }

        let mut bytes: [u8; N] = [0; N];
        bytes.copy_from_slice(value);
        Ok(OpeCllw8V1 { bytes })
    }
}

impl<const N: usize> From<OreCllw8V1<N>> for OpeCllw8V1<N> {
    fn from(ore: OreCllw8V1<N>) -> Self {
        Self { bytes: ore.bytes }
    }
}

impl<const N: usize> From<OpeCllw8V1<N>> for OreCllw8V1<N> {
    fn from(ope: OpeCllw8V1<N>) -> Self {
        Self { bytes: ope.bytes }
    }
}

// OPE comparison: standard lexicographic byte comparison.
// This is the base-256 numeric interpretation from Section 3.2 of the CLWW paper.
impl<const N: usize> Ord for OpeCllw8V1<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl<const N: usize> PartialOrd for OpeCllw8V1<N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize> PartialEq for OpeCllw8V1<N> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<const N: usize> Eq for OpeCllw8V1<N> {}

/// Macro to implement CllwOpeEncrypt and CllwOpeDecrypt for unsigned integer types.
/// Delegates to the ORE encryption and converts the result.
macro_rules! impl_cllw_ope_uint {
    ($uint_type:ty, $array_size:expr) => {
        impl CllwOpeEncrypt for $uint_type {
            type Output = OpeCllw8V1<$array_size>;

            fn encrypt_ope_with_salt(
                self,
                key: &Key,
                salt: Option<&[u8]>,
            ) -> Result<Self::Output, Error> {
                let ore: OreCllw8V1<$array_size> = self.encrypt_with_salt(key, salt)?;
                Ok(OpeCllw8V1::from(ore))
            }
        }

        impl CllwOpeDecrypt for OpeCllw8V1<$array_size> {
            type Output = $uint_type;

            fn decrypt_ope_with_salt(
                self,
                key: &Key,
                salt: Option<&[u8]>,
            ) -> Result<Self::Output, Error> {
                let ore: OreCllw8V1<$array_size> = OreCllw8V1::from(self);
                ore.decrypt_with_salt(key, salt)
            }
        }
    };
}

impl_cllw_ope_uint!(u8, 8);
impl_cllw_ope_uint!(u16, 16);
impl_cllw_ope_uint!(u32, 32);
impl_cllw_ope_uint!(u64, 64);
impl_cllw_ope_uint!(u128, 128);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Key;
    use paste::paste;
    use quickcheck::{quickcheck, TestResult};

    macro_rules! quickcheck_type {
        ($ty:ident) => {
            paste! {
                quickcheck! {
                    /// Test that encrypting the same value twice produces equal ciphertexts
                    fn [<prop_eq_ $ty>](key: Key, x: $ty) -> bool {
                        let a = key.encrypt(x).unwrap();
                        let b = key.encrypt(x).unwrap();

                        a == b
                    }

                    /// Test that the encryption preserves the ordering relationship between any two values
                    fn [<prop_cmp_ $ty>](key: Key, x: $ty, y: $ty) -> bool {
                        let a = key.encrypt(x).unwrap();
                        let b = key.encrypt(y).unwrap();

                        a.cmp(&b) == x.cmp(&y)
                    }

                    /// Test that 1 encrypts to a value greater than 0 (tests low-order bit ordering)
                    fn [<prop_low_order_bit_greater_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt(1 as $ty).unwrap();
                        let x2 = key.encrypt(0 as $ty).unwrap();
                        x1.cmp(&x2) == Ordering::Greater
                    }

                    /// Test that the MSB value (2^(BITS-1)) encrypts to a value greater than 0
                    fn [<prop_high_order_bit_greater_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt::<$ty>(1 << ($ty::BITS - 1)).unwrap();
                        let x2 = key.encrypt::<$ty>(0).unwrap();
                        x1.cmp(&x2) == Ordering::Greater
                    }

                    /// Test that 0 encrypts to a value less than the MSB value (2^(BITS-1))
                    fn [<prop_high_order_bit_less_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt::<$ty>(0).unwrap();
                        let x2 = key.encrypt::<$ty>(1 << ($ty::BITS - 1)).unwrap();
                        x1.cmp(&x2) == Ordering::Less
                    }

                    /// Test that the MSB value encrypts to equal ciphertexts (determinism check)
                    fn [<prop_high_order_bit_eq_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt::<$ty>(1 << ($ty::BITS - 1)).unwrap();
                        let x2 = key.encrypt::<$ty>(1 << ($ty::BITS - 1)).unwrap();
                        x1.cmp(&x2) == Ordering::Equal
                    }

                    /// Test that 0 encrypts to a value less than 1 (tests low-order bit ordering)
                    fn [<prop_low_order_bit_less_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt::<$ty>(0).unwrap();
                        let x2 = key.encrypt::<$ty>(1).unwrap();
                        x1.cmp(&x2) == Ordering::Less
                    }

                    /// Test that 1 encrypts to equal ciphertexts (determinism check)
                    fn [<prop_low_order_bit_eq_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt::<$ty>(1).unwrap();
                        let x2 = key.encrypt::<$ty>(1).unwrap();
                        x1.cmp(&x2) == Ordering::Equal
                    }

                    /// Test that 0 encrypts to equal ciphertexts (determinism check for min value)
                    fn [<prop_zero_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt::<$ty>(0).unwrap();
                        let x2 = key.encrypt::<$ty>(0).unwrap();
                        x1.cmp(&x2) == Ordering::Equal
                    }

                    /// Test that MAX encrypts to equal ciphertexts (determinism check for max value)
                    fn [<prop_max_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt($ty::MAX).unwrap();
                        let x2 = key.encrypt($ty::MAX).unwrap();
                        x1.cmp(&x2) == Ordering::Equal
                    }

                    /// Test that any value less than MAX encrypts to a value less than MAX
                    fn [<prop_less_than_max_right_ $ty>](key: Key, x: $ty) -> TestResult {
                        if x == $ty::MAX {
                            return TestResult::discard();
                        }
                        let x1 = key.encrypt(x).unwrap();
                        let x2 = key.encrypt($ty::MAX).unwrap();
                        TestResult::from_bool(x1.cmp(&x2) == Ordering::Less)
                    }

                    /// Test that MAX encrypts to a value greater than 0
                    fn [<prop_more_than_max_left_ $ty>](key: Key, x: $ty) -> TestResult {
                        if x == $ty::MAX {
                            return TestResult::discard();
                        }
                        let x1 = key.encrypt($ty::MAX).unwrap();
                        let x2 = key.encrypt::<$ty>(0).unwrap();
                        TestResult::from_bool(x1.cmp(&x2) == Ordering::Greater)
                    }

                    /// Test that 0 encrypts to a value less than any non-zero value
                    fn [<prop_more_than_zero_left_ $ty>](key: Key, x: $ty) -> TestResult {
                        if x == 0 {
                            return TestResult::discard();
                        }
                        let x1 = key.encrypt::<$ty>(0).unwrap();
                        let x2 = key.encrypt(x).unwrap();
                        TestResult::from_bool(x1.cmp(&x2) == Ordering::Less)
                    }

                    /// Test that any non-zero value encrypts to a value greater than 0
                    fn [<prop_more_than_zero_right_ $ty>](key: Key, x: $ty) -> TestResult {
                        if x == 0 {
                            return TestResult::discard();
                        }
                        let x1 = key.encrypt(x).unwrap();
                        let x2 = key.encrypt::<$ty>(0).unwrap();
                        TestResult::from_bool(x1.cmp(&x2) == Ordering::Greater)
                    }

                    /// Test that (x-1) encrypts to a value less than x for all x > 1
                    fn [<prop_one_less_than_ $ty>](key: Key, x: $ty) -> TestResult {
                        if x <= 1 {
                            return TestResult::discard();
                        }
                        let x1 = key.encrypt(x - 1).unwrap();
                        let x2 = key.encrypt(x).unwrap();
                        TestResult::from_bool(x1.cmp(&x2) == Ordering::Less)
                    }

                    /// Test that decryption correctly recovers the original plaintext value
                    fn [<prop_decrypt_ $ty>](key: Key, x: $ty) -> bool {
                        let ciphertext = key.encrypt(x).unwrap();
                        let decrypted = key.decrypt(ciphertext).unwrap();
                        x == decrypted
                    }
                }
            }
        };
    }

    quickcheck_type!(u16);
    quickcheck_type!(u32);
    quickcheck_type!(u64);
    quickcheck_type!(u128);

    // Salt tests for numeric types

    #[test]
    fn test_u32_different_salts_produce_different_ciphertexts() {
        use crate::CllwOreEncrypt;

        let key = Key::from([0; 32]);
        let value: u32 = 42;
        let salt1 = b"domain1";
        let salt2 = b"domain2";

        let ct1 = value.encrypt_with_salt(&key, Some(salt1)).unwrap();
        let ct2 = value.encrypt_with_salt(&key, Some(salt2)).unwrap();

        // Different salts should produce different ciphertexts
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_u64_wrong_salt_produces_wrong_plaintext() {
        use crate::{CllwOreDecrypt, CllwOreEncrypt};

        let key = Key::from([0; 32]);
        let value: u64 = 12345;
        let salt1 = b"domain1";
        let salt2 = b"domain2";

        let ciphertext = value.encrypt_with_salt(&key, Some(salt1)).unwrap();
        let decrypted = ciphertext.decrypt_with_salt(&key, Some(salt2)).unwrap();

        // Using wrong salt should produce incorrect plaintext
        assert_ne!(value, decrypted);
    }

    #[test]
    fn test_u128_correct_salt_decrypts_correctly() {
        use crate::{CllwOreDecrypt, CllwOreEncrypt};

        let key = Key::from([0; 32]);
        let value: u128 = 999999;
        let salt = b"my-domain";

        let ciphertext = value.encrypt_with_salt(&key, Some(salt)).unwrap();
        let decrypted = ciphertext.decrypt_with_salt(&key, Some(salt)).unwrap();

        // Using correct salt should decrypt correctly
        assert_eq!(value, decrypted);
    }

    #[test]
    fn test_u16_no_salt_and_none_salt_are_equivalent() {
        use crate::CllwOreEncrypt;

        let key = Key::from([0; 32]);
        let value: u16 = 100;

        let ct1 = value.encrypt(&key).unwrap();
        let ct2 = value.encrypt_with_salt(&key, None).unwrap();

        // No salt and None salt should produce identical ciphertexts
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_u32_empty_salt_same_as_no_salt() {
        use crate::CllwOreEncrypt;

        let key = Key::from([0; 32]);
        let value: u32 = 42;

        let ct_no_salt = value.encrypt_with_salt(&key, None).unwrap();
        let ct_empty_salt = value.encrypt_with_salt(&key, Some(b"")).unwrap();

        // Empty salt produces same result as no salt (empty bytes don't change hash)
        assert_eq!(ct_no_salt, ct_empty_salt);
    }

    #[test]
    fn test_u64_salt_preserves_ordering() {
        use crate::CllwOreEncrypt;

        let key = Key::from([0; 32]);
        let salt = b"domain";

        let ct1 = 100u64.encrypt_with_salt(&key, Some(salt)).unwrap();
        let ct2 = 200u64.encrypt_with_salt(&key, Some(salt)).unwrap();

        // Ordering should be preserved even with salt
        assert!(ct1 < ct2);
    }

    #[test]
    fn test_u128_salt_ordering_with_max_values() {
        use crate::CllwOreEncrypt;

        let key = Key::from([0; 32]);
        let salt = b"test-domain";

        let ct_zero = 0u128.encrypt_with_salt(&key, Some(salt)).unwrap();
        let ct_max = u128::MAX.encrypt_with_salt(&key, Some(salt)).unwrap();

        // Ordering should be preserved: 0 < MAX
        assert!(ct_zero < ct_max);
    }

    // --- OPE (numeric) tests ---

    #[test]
    fn test_ope_u32_deterministic() {
        let key = Key::from([0u8; 32]);
        let a = key.encrypt_ope(42u32).unwrap();
        let b = key.encrypt_ope(42u32).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_ope_u64_deterministic() {
        let key = Key::from([1u8; 32]);
        let a = key.encrypt_ope(12345u64).unwrap();
        let b = key.encrypt_ope(12345u64).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_ore_to_ope_to_ore_round_trip_u32() {
        let key = Key::from([0u8; 32]);
        let ore = key.encrypt(42u32).unwrap();
        let ope = OpeCllw8V1::from(ore);
        let ore_back: OreCllw8V1<32> = OreCllw8V1::from(ope);
        assert_eq!(ore.as_ref(), ore_back.as_ref());
    }

    #[test]
    fn test_ope_decrypt_u8() {
        let key = Key::from([0u8; 32]);
        let value: u8 = 200;
        let ct = key.encrypt_ope(value).unwrap();
        let pt: u8 = key.decrypt_ope(ct).unwrap();
        assert_eq!(value, pt);
    }

    #[test]
    fn test_ope_decrypt_u16() {
        let key = Key::from([0u8; 32]);
        let value: u16 = 12345;
        let ct = key.encrypt_ope(value).unwrap();
        let pt: u16 = key.decrypt_ope(ct).unwrap();
        assert_eq!(value, pt);
    }

    #[test]
    fn test_ope_decrypt_u32() {
        let key = Key::from([0u8; 32]);
        let value: u32 = 999999;
        let ct = key.encrypt_ope(value).unwrap();
        let pt: u32 = key.decrypt_ope(ct).unwrap();
        assert_eq!(value, pt);
    }

    #[test]
    fn test_ope_decrypt_u64() {
        let key = Key::from([0u8; 32]);
        let value: u64 = 1_000_000_000;
        let ct = key.encrypt_ope(value).unwrap();
        let pt: u64 = key.decrypt_ope(ct).unwrap();
        assert_eq!(value, pt);
    }

    #[test]
    fn test_ope_decrypt_u128() {
        let key = Key::from([0u8; 32]);
        let value: u128 = u128::MAX / 2;
        let ct = key.encrypt_ope(value).unwrap();
        let pt: u128 = key.decrypt_ope(ct).unwrap();
        assert_eq!(value, pt);
    }

    #[test]
    fn test_ope_salt_decrypt_round_trip() {
        use crate::{CllwOpeDecrypt, CllwOpeEncrypt};
        let key = Key::from([0u8; 32]);
        let salt = b"my-domain";
        let ct = 42u32.encrypt_ope_with_salt(&key, Some(salt)).unwrap();
        let pt = ct.decrypt_ope_with_salt(&key, Some(salt)).unwrap();
        assert_eq!(42u32, pt);
    }

    #[test]
    fn test_ope_different_salts_different_ciphertexts() {
        use crate::CllwOpeEncrypt;
        let key = Key::from([0u8; 32]);
        let ct1 = 42u32.encrypt_ope_with_salt(&key, Some(b"domain1")).unwrap();
        let ct2 = 42u32.encrypt_ope_with_salt(&key, Some(b"domain2")).unwrap();
        assert_ne!(ct1, ct2);
    }

    // Statistical ordering: numeric OPE retains the paper's ~1/256 per-comparison
    // error. These tests sample many pairs and assert the success rate stays
    // near the expected 99.6%.

    #[test]
    fn test_ope_u32_ordering_statistical() {
        let key = Key::from([42u8; 32]);
        let n = 10_000;
        let mut correct = 0usize;
        for i in 0..n {
            let x = (i * 7 + 13) as u32;
            let y = (i * 11 + 29) as u32;
            if x == y {
                continue;
            }
            let ct_x = key.encrypt_ope(x).unwrap();
            let ct_y = key.encrypt_ope(y).unwrap();
            if ct_x.cmp(&ct_y) == x.cmp(&y) {
                correct += 1;
            }
        }
        let rate = correct as f64 / n as f64;
        assert!(
            rate >= 0.99,
            "OPE ordering correct rate {rate:.4} is below 99% threshold (expected ~99.6%)"
        );
    }

    #[test]
    fn test_ope_u64_ordering_statistical() {
        let key = Key::from([77u8; 32]);
        let n = 10_000;
        let mut correct = 0usize;
        for i in 0..n {
            let x = (i as u64) * 997 + 1;
            let y = (i as u64) * 991 + 3;
            if x == y {
                continue;
            }
            let ct_x = key.encrypt_ope(x).unwrap();
            let ct_y = key.encrypt_ope(y).unwrap();
            if ct_x.cmp(&ct_y) == x.cmp(&y) {
                correct += 1;
            }
        }
        let rate = correct as f64 / n as f64;
        assert!(
            rate >= 0.99,
            "OPE ordering correct rate {rate:.4} is below 99% threshold (expected ~99.6%)"
        );
    }

    #[test]
    fn test_ope_equal_values_always_equal() {
        let key = Key::from([0u8; 32]);
        for x in [0u32, 1, 42, 1000, u32::MAX / 2, u32::MAX] {
            let ct1 = key.encrypt_ope(x).unwrap();
            let ct2 = key.encrypt_ope(x).unwrap();
            assert_eq!(ct1.cmp(&ct2), Ordering::Equal, "failed for x={x}");
        }
    }

    #[test]
    fn test_ope_hex_round_trip_fixed() {
        let key = Key::from([0u8; 32]);
        let ct = key.encrypt_ope(42u32).unwrap();
        let hex_str = hex::encode(ct.as_ref());
        let ct2 = OpeCllw8V1::<32>::from_hex(&hex_str).unwrap();
        assert_eq!(ct, ct2);
    }

    #[test]
    fn test_ope_try_from_bytes_fixed() {
        let key = Key::from([0u8; 32]);
        let ct = key.encrypt_ope(42u32).unwrap();
        let bytes = ct.as_ref();
        let ct2 = OpeCllw8V1::<32>::try_from(bytes).unwrap();
        assert_eq!(ct, ct2);
    }

    #[test]
    fn test_ope_try_from_wrong_length_fails() {
        let bytes = [0u8; 16];
        let result = OpeCllw8V1::<32>::try_from(bytes.as_slice());
        assert!(result.is_err());
    }

    // --- Domain-specific error rate analysis ---
    //
    // Measures the numeric-OPE error rate for realistic plaintext domains with
    // many keys. The fixed-size numeric construction keeps the paper's
    // ~1/256 ≈ 0.39% per-comparison error.
    //
    // Run with: cargo test -p cllw-ore -- --ignored ope_error_rate --nocapture

    /// Days from 1940-01-01 to 2010-12-31, encoded as days-since-1940-01-01.
    /// Encrypt all dates, compare every pair with both ORE (ground truth) and OPE.
    #[test]
    #[ignore = "expensive analysis test — run with --ignored --nocapture"]
    fn ope_error_rate_birthdates_1940_2010() {
        fn days_in_month(year: u32, month: u32) -> u32 {
            match month {
                1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
                4 | 6 | 9 | 11 => 30,
                2 => {
                    if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                        29
                    } else {
                        28
                    }
                }
                _ => unreachable!(),
            }
        }

        // Generate all dates as days-since-1940-01-01
        let mut dates: Vec<u32> = Vec::new();
        let mut day_count: u32 = 0;
        for year in 1940..=2010 {
            for month in 1..=12 {
                for _day in 1..=days_in_month(year, month) {
                    dates.push(day_count);
                    day_count += 1;
                }
            }
        }

        let num_keys = 1000;
        println!("\n=== OPE Error Rate: Birthdates 1940-2010 ===");
        println!("Domain size: {} dates", dates.len());
        println!(
            "Total pairs: {}",
            dates.len() as u64 * (dates.len() as u64 - 1) / 2
        );

        // Sample to keep runtime reasonable: take every Nth date
        let sample_size = 2000;
        let step = dates.len() / sample_size;
        let sampled: Vec<u32> = dates.iter().step_by(step.max(1)).copied().collect();
        let total_pairs = sampled.len() as u64 * (sampled.len() as u64 - 1) / 2;
        println!("Sampled: {} dates ({} pairs)", sampled.len(), total_pairs);
        println!("Keys: {num_keys}\n");

        let mut all_error_rates: Vec<f64> = Vec::with_capacity(num_keys);
        let mut total_errors_all_keys = 0u64;
        let mut total_pairs_all_keys = 0u64;

        for key_seed in 0..num_keys {
            // Use a varied key — spread the seed across the key bytes
            let mut key_bytes = [0u8; 32];
            let seed_bytes = (key_seed as u64).to_le_bytes();
            key_bytes[..8].copy_from_slice(&seed_bytes);
            let key = Key::from(key_bytes);

            // Encrypt all sampled dates
            let ope_cts: Vec<OpeCllw8V1<32>> = sampled
                .iter()
                .map(|&d| key.encrypt_ope(d).unwrap())
                .collect();
            let ore_cts: Vec<OreCllw8V1<32>> =
                sampled.iter().map(|&d| key.encrypt(d).unwrap()).collect();

            let mut errors = 0u64;
            let mut total = 0u64;

            for i in 0..sampled.len() {
                for j in (i + 1)..sampled.len() {
                    let ore_ord = ore_cts[i].cmp(&ore_cts[j]);
                    let ope_ord = ope_cts[i].cmp(&ope_cts[j]);
                    total += 1;
                    if ore_ord != ope_ord {
                        errors += 1;
                    }
                }
            }

            let error_rate = errors as f64 / total as f64;
            all_error_rates.push(error_rate);
            total_errors_all_keys += errors;
            total_pairs_all_keys += total;
        }

        // Aggregate statistics
        let mean_rate = all_error_rates.iter().sum::<f64>() / all_error_rates.len() as f64;
        let global_rate = total_errors_all_keys as f64 / total_pairs_all_keys as f64;
        let max_rate = all_error_rates
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);
        let min_rate = all_error_rates
            .iter()
            .cloned()
            .fold(f64::INFINITY, f64::min);
        let keys_with_zero = all_error_rates.iter().filter(|&&r| r == 0.0).count();
        let variance = all_error_rates
            .iter()
            .map(|r| (r - mean_rate).powi(2))
            .sum::<f64>()
            / all_error_rates.len() as f64;
        let stddev = variance.sqrt();

        println!("--- Results across {num_keys} keys ---");
        println!(
            "Global error rate: {total_errors_all_keys}/{total_pairs_all_keys} ({:.4}%)",
            global_rate * 100.0
        );
        println!("Mean per-key rate: {:.4}%", mean_rate * 100.0);
        println!("Std dev:           {:.4}%", stddev * 100.0);
        println!("Min per-key rate:  {:.4}%", min_rate * 100.0);
        println!("Max per-key rate:  {:.4}%", max_rate * 100.0);
        println!(
            "Keys with 0 errors: {keys_with_zero}/{num_keys} ({:.1}%)",
            keys_with_zero as f64 / num_keys as f64 * 100.0
        );
        println!("\nExpected error rate: {:.4}% (1/256)", 100.0 / 256.0);
    }
}
