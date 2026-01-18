use crate::{biterator::Biterator, CllwOreDecrypt, CllwOreEncrypt, Error, Key};
use hex::FromHex;
use postgres_types::ToSql;
use std::cmp::Ordering;

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

impl CllwOreEncrypt for u32 {
    type Output = OreCllw8V1<32>;

    fn encrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let mut hasher = blake3::Hasher::new_keyed(&key.0);
        if let Some(salt) = salt {
            hasher.update(salt);
        }

        let mut bytes: [u8; 32] = [0; 32];
        // TODO: Split this bit into a separate function
        Biterator::new(self).enumerate().for_each(|(i, bit)| {
            let mut buf: [u8; 16] = [0; 16];
            hasher.finalize_xof().fill(&mut buf);
            let byte = u128::from_be_bytes(buf).wrapping_add(bit as u128) & 0xFF;
            hasher.update(&[bit]);
            bytes[i] = byte as u8;
        });

        Ok(OreCllw8V1 { bytes })
    }
}

impl CllwOreDecrypt for OreCllw8V1<32> {
    type Output = u32;

    fn decrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let mut hasher = blake3::Hasher::new_keyed(&key.0);
        if let Some(salt) = salt {
            hasher.update(salt);
        }

        let mut result: u32 = 0;
        for (i, &ciphertext_byte) in self.bytes.iter().enumerate() {
            let mut buf: [u8; 16] = [0; 16];
            hasher.finalize_xof().fill(&mut buf);
            let prf_block = u128::from_be_bytes(buf) & 0xFF;
            // Recover the bit by subtracting ciphertext from PRF block
            let bit = ciphertext_byte.wrapping_sub(prf_block as u8) & 0x01;
            hasher.update(&[bit]);
            // Set the bit in the result (MSB first, so bit 31 is at index 0)
            if bit == 1 {
                result |= 1 << (31 - i);
            }
        }

        Ok(result)
    }
}

impl CllwOreEncrypt for u64 {
    type Output = OreCllw8V1<64>;

    fn encrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let mut hasher = blake3::Hasher::new_keyed(&key.0);
        if let Some(salt) = salt {
            hasher.update(salt);
        }

        let mut bytes: [u8; 64] = [0; 64];
        Biterator::new(self).enumerate().for_each(|(i, bit)| {
            let mut buf: [u8; 16] = [0; 16];
            hasher.finalize_xof().fill(&mut buf);
            let byte = u128::from_be_bytes(buf).wrapping_add(bit as u128) & 0xFF;
            hasher.update(&[bit]);
            bytes[i] = byte as u8;
        });

        Ok(OreCllw8V1 { bytes })
    }
}

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
        // TODO: Use constant time (Paranoid? or at least subtle)
        self.bytes == other.bytes
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
                    fn [<prop_eq_ $ty>](key: Key, x: $ty) -> bool {
                        let a = key.encrypt(x).unwrap();
                        let b = key.encrypt(x).unwrap();

                        a == b
                    }


                    fn [<prop_cmp_ $ty>](key: Key, x: $ty, y: $ty) -> bool {
                        let a = key.encrypt(x).unwrap();
                        let b = key.encrypt(y).unwrap();

                        a.cmp(&b) == x.cmp(&y)
                    }

                    fn [<prop_low_order_bit_greater_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt(1 as $ty).unwrap();
                        let x2 = key.encrypt(0 as $ty).unwrap();
                        x1.cmp(&x2) == Ordering::Greater
                    }

                    fn [<prop_high_order_bit_greater_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt::<$ty>(1 << ($ty::BITS - 1)).unwrap();
                        let x2 = key.encrypt::<$ty>(0).unwrap();
                        x1.cmp(&x2) == Ordering::Greater
                    }

                    fn [<prop_high_order_bit_less_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt::<$ty>(0).unwrap();
                        let x2 = key.encrypt::<$ty>(1 << ($ty::BITS - 1)).unwrap();
                        x1.cmp(&x2) == Ordering::Less
                    }

                    fn [<prop_high_order_bit_eq_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt::<$ty>(1 << ($ty::BITS - 1)).unwrap();
                        let x2 = key.encrypt::<$ty>(1 << ($ty::BITS - 1)).unwrap();
                        x1.cmp(&x2) == Ordering::Equal
                    }

                    fn [<prop_low_order_bit_less_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt::<$ty>(0).unwrap();
                        let x2 = key.encrypt::<$ty>(1).unwrap();
                        x1.cmp(&x2) == Ordering::Less
                    }

                    fn [<prop_low_order_bit_eq_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt::<$ty>(1).unwrap();
                        let x2 = key.encrypt::<$ty>(1).unwrap();
                        x1.cmp(&x2) == Ordering::Equal
                    }

                    fn [<prop_zero_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt::<$ty>(0).unwrap();
                        let x2 = key.encrypt::<$ty>(0).unwrap();
                        x1.cmp(&x2) == Ordering::Equal
                    }

                    fn [<prop_max_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt($ty::MAX).unwrap();
                        let x2 = key.encrypt($ty::MAX).unwrap();
                        x1.cmp(&x2) == Ordering::Equal
                    }

                    fn [<prop_less_than_max_right_ $ty>](key: Key, x: $ty) -> TestResult {
                        if x == $ty::MAX {
                            return TestResult::discard();
                        }
                        let x1 = key.encrypt(x).unwrap();
                        let x2 = key.encrypt($ty::MAX).unwrap();
                        TestResult::from_bool(x1.cmp(&x2) == Ordering::Less)
                    }

                    fn [<prop_more_than_max_left_ $ty>](key: Key, x: $ty) -> TestResult {
                        if x == $ty::MAX {
                            return TestResult::discard();
                        }
                        let x1 = key.encrypt($ty::MAX).unwrap();
                        let x2 = key.encrypt::<$ty>(0).unwrap();
                        TestResult::from_bool(x1.cmp(&x2) == Ordering::Greater)
                    }

                    fn [<prop_more_than_zero_left_ $ty>](key: Key, x: $ty) -> TestResult {
                        if x == 0 {
                            return TestResult::discard();
                        }
                        let x1 = key.encrypt::<$ty>(0).unwrap();
                        let x2 = key.encrypt(x).unwrap();
                        TestResult::from_bool(x1.cmp(&x2) == Ordering::Less)
                    }

                    fn [<prop_more_than_zero_right_ $ty>](key: Key, x: $ty) -> TestResult {
                        if x == 0 {
                            return TestResult::discard();
                        }
                        let x1 = key.encrypt(x).unwrap();
                        let x2 = key.encrypt::<$ty>(0).unwrap();
                        TestResult::from_bool(x1.cmp(&x2) == Ordering::Greater)
                    }

                    fn [<prop_one_less_than_ $ty>](key: Key, x: $ty) -> TestResult {
                        if x <= 1 {
                            return TestResult::discard();
                        }
                        let x1 = key.encrypt(x - 1).unwrap();
                        let x2 = key.encrypt(x).unwrap();
                        TestResult::from_bool(x1.cmp(&x2) == Ordering::Less)
                    }
                }
            }
        };
    }

    quickcheck_type!(u32);
    quickcheck_type!(u64);

    #[test]
    fn test_decrypt_u32() {
        let key = Key::from([0; 32]);
        let plaintext: u32 = 42;
        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    quickcheck! {
        fn prop_decrypt_u32(key: Key, x: u32) -> bool {
            let ciphertext = key.encrypt(x).unwrap();
            let decrypted = key.decrypt(ciphertext).unwrap();
            x == decrypted
        }
    }
}
