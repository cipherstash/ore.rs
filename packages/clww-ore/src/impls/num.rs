use crate::{biterator::Biterator, CllwOreDecrypt, CllwOreEncrypt, Error, Key};
use hex::FromHex;
use postgres_types::ToSql;
use std::cmp::Ordering;
use subtle::ConstantTimeEq;

/// Fixed-size CLLW ORE ciphertext for unsigned integer types.
///
/// This type represents an encrypted value using the CLLW Order-Revealing Encryption scheme.
/// The size `N` corresponds to the number of bits in the plaintext (one byte per bit).
///
/// - `OreCllw8V1<16>` encrypts `u16` (16 bytes)
/// - `OreCllw8V1<32>` encrypts `u32` (32 bytes)
/// - `OreCllw8V1<64>` encrypts `u64` (64 bytes)
/// - `OreCllw8V1<128>` encrypts `u128` (128 bytes)
#[derive(Debug, ToSql)]
#[postgres(name = "ore_cllw_8_v1")]
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
        let actual_len = hex.as_ref().len();
        hex::decode_to_slice(hex, &mut out as &mut [u8]).map_err(|_| Error::InvalidLength {
            expected: N,
            actual: actual_len,
        })?;
        Ok(Self { bytes: out })
    }
}

impl<const N: usize> TryFrom<&[u8]> for OreCllw8V1<N> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != N {
            return Err(Error::InvalidLength {
                expected: N,
                actual: value.len(),
            });
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
}
