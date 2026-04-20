use crate::{biterator::Biterator, CllwOpeEncrypt, CllwOreDecrypt, CllwOreEncrypt, Error, Key};
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
    bytes: [u8; N],
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
/// Ciphertexts are compared with standard lexicographic byte ordering.
/// Encryption uses the CLLW keystream from Section 3.2 of the paper, but
/// propagates the `+1` addition as a right-to-left carry into a reserved
/// leading byte, which eliminates the ~1/256 ordering error the paper's
/// naive OPE construction exhibits.
///
/// **Correctness**: OPE comparison is exact (100%) — lex ordering of two
/// ciphertexts under the same key and salt always matches the plaintext
/// ordering.
///
/// **Encrypt-only**: this type intentionally does not support decryption.
/// OPE is used for ordered lookups; callers that need round-trip should
/// pair it with an ORE (`OreCllw8V1`) ciphertext.
///
/// The size `N` is the ciphertext byte length: one byte per plaintext bit
/// plus one reserved leading byte that absorbs the carry.
///
/// - `OpeCllw8V1<9>` encrypts `u8` (8 bits → 9 bytes)
/// - `OpeCllw8V1<17>` encrypts `u16` (16 bits → 17 bytes)
/// - `OpeCllw8V1<33>` encrypts `u32` (32 bits → 33 bytes)
/// - `OpeCllw8V1<65>` encrypts `u64` (64 bits → 65 bytes)
/// - `OpeCllw8V1<129>` encrypts `u128` (128 bits → 129 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

/// Implements [`CllwOpeEncrypt`] for unsigned integer types using the shared
/// backward-carry encoding. The output size is `<$ty>::BITS + 1`, covering
/// one byte per plaintext bit plus the reserved leading byte.
macro_rules! impl_cllw_ope_uint {
    ($uint_type:ty) => {
        impl CllwOpeEncrypt for $uint_type {
            type Output = OpeCllw8V1<{ <$uint_type>::BITS as usize + 1 }>;

            fn encrypt_ope_with_salt(
                self,
                key: &Key,
                salt: Option<&[u8]>,
            ) -> Result<Self::Output, Error> {
                let n = <$uint_type>::BITS as usize;
                let vec = super::encrypt_ope_bits(Biterator::new(self), n, key, salt);
                let mut bytes = [0u8; { <$uint_type>::BITS as usize + 1 }];
                bytes.copy_from_slice(&vec);
                Ok(OpeCllw8V1 { bytes })
            }
        }
    };
}

impl_cllw_ope_uint!(u8);
impl_cllw_ope_uint!(u16);
impl_cllw_ope_uint!(u32);
impl_cllw_ope_uint!(u64);
impl_cllw_ope_uint!(u128);

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
    //
    // OPE encryption is exact (100%) under the backward-carry encoding — every
    // assertion uses plain equality rather than a statistical tolerance.

    #[test]
    fn test_ope_different_salts_different_ciphertexts() {
        use crate::CllwOpeEncrypt;
        let key = Key::from([0u8; 32]);
        let ct1 = 42u32.encrypt_ope_with_salt(&key, Some(b"domain1")).unwrap();
        let ct2 = 42u32.encrypt_ope_with_salt(&key, Some(b"domain2")).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_ope_hex_round_trip_fixed() {
        let key = Key::from([0u8; 32]);
        let ct = key.encrypt_ope(42u32).unwrap();
        let hex_str = hex::encode(ct.as_ref());
        let ct2 = OpeCllw8V1::<33>::from_hex(&hex_str).unwrap();
        assert_eq!(ct, ct2);
    }

    #[test]
    fn test_ope_try_from_bytes_fixed() {
        let key = Key::from([0u8; 32]);
        let ct = key.encrypt_ope(42u32).unwrap();
        let bytes = ct.as_ref();
        let ct2 = OpeCllw8V1::<33>::try_from(bytes).unwrap();
        assert_eq!(ct, ct2);
    }

    #[test]
    fn test_ope_try_from_wrong_length_fails() {
        let bytes = [0u8; 16];
        let result = OpeCllw8V1::<33>::try_from(bytes.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn test_ope_numeric_boundary_ordering() {
        // Boundary pairs that used to trigger the 1/256 wrap-around bug, plus
        // MAX/MIN, and adjacent values. All must preserve order exactly.
        for seed in [0u8, 1, 17, 42, 99, 200, 255] {
            let key = Key::from([seed; 32]);
            let pairs_u32: &[(u32, u32)] = &[
                (0, 1),
                (0, u32::MAX),
                (u32::MAX - 1, u32::MAX),
                (1 << 31, (1 << 31) + 1),
                (0x7FFF_FFFF, 0x8000_0000),
            ];
            for &(x, y) in pairs_u32 {
                let cx = key.encrypt_ope(x).unwrap();
                let cy = key.encrypt_ope(y).unwrap();
                assert_eq!(cx.cmp(&cy), x.cmp(&y), "seed {seed}: u32 {x} vs {y}");
            }
        }
    }

    /// Per-type OPE property suite: determinism, exact ordering, length, and
    /// a regression check for the pre-fix 1/256 wrap-around bug.
    macro_rules! ope_quickcheck_type {
        ($ty:ident) => {
            paste! {
                quickcheck! {
                    fn [<prop_ope_eq_ $ty>](key: Key, x: $ty) -> bool {
                        let a = key.encrypt_ope(x).unwrap();
                        let b = key.encrypt_ope(x).unwrap();
                        a == b
                    }

                    fn [<prop_ope_cmp_ $ty>](key: Key, x: $ty, y: $ty) -> bool {
                        let a = key.encrypt_ope(x).unwrap();
                        let b = key.encrypt_ope(y).unwrap();
                        a.cmp(&b) == x.cmp(&y)
                    }

                    fn [<prop_ope_zero_less_than_one_ $ty>](key: Key) -> bool {
                        let c0 = key.encrypt_ope(0 as $ty).unwrap();
                        let c1 = key.encrypt_ope(1 as $ty).unwrap();
                        c0 < c1
                    }

                    fn [<prop_ope_length_ $ty>](key: Key, x: $ty) -> bool {
                        let ct = key.encrypt_ope(x).unwrap();
                        ct.as_ref().len() == <$ty>::BITS as usize + 1
                    }
                }
            }
        };
    }

    ope_quickcheck_type!(u16);
    ope_quickcheck_type!(u32);
    ope_quickcheck_type!(u64);
    ope_quickcheck_type!(u128);
}
