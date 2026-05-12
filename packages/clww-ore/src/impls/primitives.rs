use crate::{biterator::Biterator, CllwOpeEncrypt, CllwOreDecrypt, CllwOreEncrypt, Error, Key};
use hex::FromHex;
#[cfg(feature = "postgres-types")]
use postgres_types::ToSql;
use std::cmp::Ordering;
use subtle::ConstantTimeEq;

/// Fixed-size CLWW ORE ciphertext for unsigned integer types.
///
/// This type represents an encrypted value using the CLWW Order-Revealing Encryption scheme.
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

/// Macro to implement CllwOreEncrypt for signed integer types.
///
/// Sign-flips the plaintext to its unsigned equivalent (`x ^ (1 << (N-1))`)
/// so two's-complement order on `iN` matches unsigned order on `uN`, then
/// delegates to the matching unsigned ORE impl. The output ciphertext type
/// is shared with the unsigned variant (`OreCllw8V1<N>`) — the bytes are
/// identical and `compare_slice` is byte-level, so a separate type would
/// add no information.
///
/// **Decryption note**: there is no `CllwOreDecrypt` impl for the signed
/// case. To round-trip, decrypt to `uN` (using the existing unsigned impl)
/// and reverse the bias yourself: `(biased ^ (1 << (N-1))) as iN`.
macro_rules! impl_cllw_ore_iint {
    ($iint_type:ty, $uint_type:ty, $array_size:expr) => {
        impl CllwOreEncrypt for $iint_type {
            type Output = OreCllw8V1<$array_size>;

            fn encrypt_with_salt(
                self,
                key: &Key,
                salt: Option<&[u8]>,
            ) -> Result<Self::Output, Error> {
                let biased = (self as $uint_type) ^ (1 << (<$uint_type>::BITS - 1));
                biased.encrypt_with_salt(key, salt)
            }
        }
    };
}

// Generate encrypt implementations for all signed integer types.
impl_cllw_ore_iint!(i8, u8, 8);
impl_cllw_ore_iint!(i16, u16, 16);
impl_cllw_ore_iint!(i32, u32, 32);
impl_cllw_ore_iint!(i64, u64, 64);
impl_cllw_ore_iint!(i128, u128, 128);

/// CLWW ORE for `bool`. Maps `false → 0u8`, `true → 1u8` and delegates to the
/// `u8` impl. The output ciphertext type is shared with `u8` (`OreCllw8V1<8>`),
/// so `false` ciphertext is strictly less than `true`.
impl CllwOreEncrypt for bool {
    type Output = OreCllw8V1<8>;

    fn encrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        (self as u8).encrypt_with_salt(key, salt)
    }
}

/// Macro to implement [`CllwOreEncrypt`] for floating-point types.
///
/// Maps the IEEE-754 bit pattern to a sortable `uN` using the standard
/// monotonic float→int trick: flip the sign bit on non-negatives, flip all
/// bits on negatives. The resulting `uN` orders by IEEE-754 totalOrder
/// (matches `f{32,64}::total_cmp`), then delegates to the matching unsigned
/// ORE impl. The output ciphertext type is shared with the unsigned variant.
///
/// **`−0.0` vs `+0.0`**: distinguished — `−0.0` ciphertext is strictly less
/// than `+0.0`. IEEE-754 `==` considers them equal; the encoding does not.
///
/// **Decryption note**: there is no [`CllwOreDecrypt`] impl for floats. To
/// round-trip, decrypt to the matching `uN` and reverse the bias yourself:
/// `let mask = (bits >> (BITS-1)).wrapping_neg() | (1 << (BITS-1));`
/// `let f = fN::from_bits(bits ^ mask);`.
macro_rules! impl_cllw_ore_float {
    ($float_type:ty, $uint_type:ty, $array_size:expr) => {
        impl CllwOreEncrypt for $float_type {
            type Output = OreCllw8V1<$array_size>;

            fn encrypt_with_salt(
                self,
                key: &Key,
                salt: Option<&[u8]>,
            ) -> Result<Self::Output, Error> {
                let bits = self.to_bits();
                let mask = (bits >> (<$uint_type>::BITS - 1)).wrapping_neg()
                    | (1 << (<$uint_type>::BITS - 1));
                (bits ^ mask).encrypt_with_salt(key, salt)
            }
        }
    };
}

impl_cllw_ore_float!(f32, u32, 32);
impl_cllw_ore_float!(f64, u64, 64);

// --- Fixed-size numeric OPE ---

/// Fixed-size CLWW OPE ciphertext for integer types.
///
/// Ciphertexts are compared with standard lexicographic byte ordering.
/// Encryption uses the CLWW keystream from Section 3.2 of the paper; the
/// plaintext bit contribution is placed at the top bit of its byte (adding
/// `128` rather than `1`) and the resulting sum is propagated as a
/// right-to-left carry into a reserved leading byte.
///
/// **Correctness**: comparison is **exact** — lex compare always agrees
/// with the plaintext integer order. The `+128` signal at the first
/// differing byte exceeds any backward-carry noise (±1 per byte), so no
/// PRF choice can flip the comparison. See
/// `packages/cllw-ore/docs/backward-carry-ope.md` for the derivation.
///
/// **Encrypt-only**: this type intentionally does not support decryption.
/// OPE is used for ordered lookups; if round-trip is required, pair the OPE
/// ciphertext with an authenticated symmetric cipher (e.g. AES-GCM) over the
/// same plaintext.
///
/// The size `N` is the ciphertext byte length: one byte per plaintext bit
/// plus one reserved leading byte that absorbs the carry.
///
/// - `OpeCllw8V1<9>` encrypts `u8` or `i8` (8 bits → 9 bytes)
/// - `OpeCllw8V1<17>` encrypts `u16` or `i16` (16 bits → 17 bytes)
/// - `OpeCllw8V1<33>` encrypts `u32` or `i32` (32 bits → 33 bytes)
/// - `OpeCllw8V1<65>` encrypts `u64` or `i64` (64 bits → 65 bytes)
/// - `OpeCllw8V1<129>` encrypts `u128` or `i128` (128 bits → 129 bytes)
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

/// Implements [`CllwOpeEncrypt`] for signed integer types by sign-flipping to
/// the matching unsigned width and delegating to the unsigned OPE impl.
/// The output ciphertext type is shared with the unsigned variant — OPE has
/// no decrypt path, so there is no type ambiguity.
macro_rules! impl_cllw_ope_iint {
    ($iint_type:ty, $uint_type:ty) => {
        impl CllwOpeEncrypt for $iint_type {
            type Output = OpeCllw8V1<{ <$uint_type>::BITS as usize + 1 }>;

            fn encrypt_ope_with_salt(
                self,
                key: &Key,
                salt: Option<&[u8]>,
            ) -> Result<Self::Output, Error> {
                let biased = (self as $uint_type) ^ (1 << (<$uint_type>::BITS - 1));
                biased.encrypt_ope_with_salt(key, salt)
            }
        }
    };
}

impl_cllw_ope_iint!(i8, u8);
impl_cllw_ope_iint!(i16, u16);
impl_cllw_ope_iint!(i32, u32);
impl_cllw_ope_iint!(i64, u64);
impl_cllw_ope_iint!(i128, u128);

/// CLWW OPE for `bool`. Delegates to the `u8` OPE impl; see the ORE `bool`
/// impl for the encoding rationale.
impl CllwOpeEncrypt for bool {
    type Output = OpeCllw8V1<{ u8::BITS as usize + 1 }>;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        (self as u8).encrypt_ope_with_salt(key, salt)
    }
}

/// Macro to implement [`CllwOpeEncrypt`] for floating-point types using the
/// same monotonic float→int bias as the ORE float impl.
macro_rules! impl_cllw_ope_float {
    ($float_type:ty, $uint_type:ty) => {
        impl CllwOpeEncrypt for $float_type {
            type Output = OpeCllw8V1<{ <$uint_type>::BITS as usize + 1 }>;

            fn encrypt_ope_with_salt(
                self,
                key: &Key,
                salt: Option<&[u8]>,
            ) -> Result<Self::Output, Error> {
                let bits = self.to_bits();
                let mask = (bits >> (<$uint_type>::BITS - 1)).wrapping_neg()
                    | (1 << (<$uint_type>::BITS - 1));
                (bits ^ mask).encrypt_ope_with_salt(key, salt)
            }
        }
    };
}

impl_cllw_ope_float!(f32, u32);
impl_cllw_ope_float!(f64, u64);

impl<const N: usize> OpeCllw8V1<N> {
    /// Construct a ciphertext from raw bytes produced by
    /// [`super::encrypt_ope_bits`]. Crate-internal — used by feature
    /// modules (e.g. `chrono`, `decimal`) that build their own canonical
    /// byte form and need a fixed-width ciphertext sized to the plaintext.
    pub(crate) fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }
}

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
    // The MSB-bit backward-carry encoding gives exact ordering; property tests
    // below exercise that guarantee, and `ope_exactness_adjacent_u16` verifies
    // it exhaustively on every adjacent `u16` pair under a set of keys.

    #[test]
    fn test_ope_try_from_wrong_length_fails() {
        let bytes = [0u8; 16];
        let result = OpeCllw8V1::<33>::try_from(bytes.as_slice());
        assert!(result.is_err());
    }

    /// The fixed-width OPE ciphertext for a primitive is byte-for-byte
    /// identical to the variable-length OPE ciphertext of the canonical
    /// big-endian byte form that the fixed impl feeds through
    /// [`super::encrypt_ope_bits`]:
    ///
    /// - unsigned integers — `x.to_be_bytes()`
    /// - signed integers — the sign-flipped unsigned width's `to_be_bytes()`
    /// - floats — the monotonic-bias bits' `to_be_bytes()`
    /// - `bool` — the single `as u8` byte
    ///
    /// In every case both paths push the same MSB-first bit stream through the
    /// encoder, so a fixed-width OPE ciphertext can be read as a variable OPE
    /// ciphertext of the same byte width and vice versa.
    ///
    /// `$canonical_be` maps a value of `$ty` to that byte form.
    macro_rules! ope_fixed_matches_variable_be_bytes {
        ($anchor:ident, $prop:ident, $ty:ty, $values:expr, $canonical_be:expr) => {
            #[test]
            fn $anchor() {
                let key = Key::from([0u8; 32]);
                let canonical_be: fn($ty) -> Vec<u8> = $canonical_be;
                for x in $values {
                    let fixed = key.encrypt_ope(x).unwrap();
                    let variable = key.encrypt_ope(canonical_be(x).as_slice()).unwrap();
                    assert_eq!(
                        fixed.as_ref(),
                        variable.as_ref(),
                        "fixed vs variable OPE wire mismatch for {x:?}",
                    );
                }
            }

            quickcheck! {
                /// Property form of the matching anchor test: holds for every
                /// key and every value of the type.
                fn $prop(key: Key, x: $ty) -> bool {
                    let canonical_be: fn($ty) -> Vec<u8> = $canonical_be;
                    let fixed = key.encrypt_ope(x).unwrap();
                    let variable = key.encrypt_ope(canonical_be(x).as_slice()).unwrap();
                    fixed.as_ref() == variable.as_ref()
                }
            }
        };
    }

    ope_fixed_matches_variable_be_bytes!(
        ope_u8_fixed_matches_variable_be_bytes,
        prop_ope_u8_fixed_matches_variable_be_bytes,
        u8,
        [0u8, 1, 42, 0x7F, 0x80, u8::MAX],
        |x| x.to_be_bytes().to_vec()
    );

    ope_fixed_matches_variable_be_bytes!(
        ope_u16_fixed_matches_variable_be_bytes,
        prop_ope_u16_fixed_matches_variable_be_bytes,
        u16,
        [0u16, 1, 42, 0x0123, 0xDEAD, u16::MAX],
        |x| x.to_be_bytes().to_vec()
    );

    ope_fixed_matches_variable_be_bytes!(
        ope_u32_fixed_matches_variable_be_bytes,
        prop_ope_u32_fixed_matches_variable_be_bytes,
        u32,
        [0u32, 1, 42, 0x0123_4567, 0xDEAD_BEEF, u32::MAX],
        |x| x.to_be_bytes().to_vec()
    );

    ope_fixed_matches_variable_be_bytes!(
        ope_u64_fixed_matches_variable_be_bytes,
        prop_ope_u64_fixed_matches_variable_be_bytes,
        u64,
        [
            0u64,
            1,
            42,
            0x0123_4567_89AB_CDEF,
            0xDEAD_BEEF_DEAD_BEEF,
            u64::MAX
        ],
        |x| x.to_be_bytes().to_vec()
    );

    ope_fixed_matches_variable_be_bytes!(
        ope_u128_fixed_matches_variable_be_bytes,
        prop_ope_u128_fixed_matches_variable_be_bytes,
        u128,
        [
            0u128,
            1,
            42,
            0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEF,
            u128::MAX
        ],
        |x| x.to_be_bytes().to_vec()
    );

    ope_fixed_matches_variable_be_bytes!(
        ope_i8_fixed_matches_variable_be_bytes,
        prop_ope_i8_fixed_matches_variable_be_bytes,
        i8,
        [i8::MIN, -42, -1, 0, 1, 42, i8::MAX],
        |x| ((x as u8) ^ (1 << (u8::BITS - 1))).to_be_bytes().to_vec()
    );

    ope_fixed_matches_variable_be_bytes!(
        ope_i16_fixed_matches_variable_be_bytes,
        prop_ope_i16_fixed_matches_variable_be_bytes,
        i16,
        [i16::MIN, -42, -1, 0, 1, 42, i16::MAX],
        |x| ((x as u16) ^ (1 << (u16::BITS - 1))).to_be_bytes().to_vec()
    );

    ope_fixed_matches_variable_be_bytes!(
        ope_i32_fixed_matches_variable_be_bytes,
        prop_ope_i32_fixed_matches_variable_be_bytes,
        i32,
        [i32::MIN, -42, -1, 0, 1, 42, i32::MAX],
        |x| ((x as u32) ^ (1 << (u32::BITS - 1))).to_be_bytes().to_vec()
    );

    ope_fixed_matches_variable_be_bytes!(
        ope_i64_fixed_matches_variable_be_bytes,
        prop_ope_i64_fixed_matches_variable_be_bytes,
        i64,
        [i64::MIN, -42, -1, 0, 1, 42, i64::MAX],
        |x| ((x as u64) ^ (1 << (u64::BITS - 1))).to_be_bytes().to_vec()
    );

    ope_fixed_matches_variable_be_bytes!(
        ope_i128_fixed_matches_variable_be_bytes,
        prop_ope_i128_fixed_matches_variable_be_bytes,
        i128,
        [i128::MIN, -42, -1, 0, 1, 42, i128::MAX],
        |x| ((x as u128) ^ (1 << (u128::BITS - 1)))
            .to_be_bytes()
            .to_vec()
    );

    ope_fixed_matches_variable_be_bytes!(
        ope_bool_fixed_matches_variable_be_bytes,
        prop_ope_bool_fixed_matches_variable_be_bytes,
        bool,
        [false, true],
        |b| [b as u8].to_vec()
    );

    ope_fixed_matches_variable_be_bytes!(
        ope_f32_fixed_matches_variable_be_bytes,
        prop_ope_f32_fixed_matches_variable_be_bytes,
        f32,
        [
            0.0f32,
            -0.0,
            1.0,
            -1.0,
            f32::MIN,
            f32::MAX,
            f32::INFINITY,
            f32::NEG_INFINITY
        ],
        |x| {
            let bits = x.to_bits();
            let mask = (bits >> (u32::BITS - 1)).wrapping_neg() | (1 << (u32::BITS - 1));
            (bits ^ mask).to_be_bytes().to_vec()
        }
    );

    ope_fixed_matches_variable_be_bytes!(
        ope_f64_fixed_matches_variable_be_bytes,
        prop_ope_f64_fixed_matches_variable_be_bytes,
        f64,
        [
            0.0f64,
            -0.0,
            1.0,
            -1.0,
            f64::MIN,
            f64::MAX,
            f64::INFINITY,
            f64::NEG_INFINITY
        ],
        |x| {
            let bits = x.to_bits();
            let mask = (bits >> (u64::BITS - 1)).wrapping_neg() | (1 << (u64::BITS - 1));
            (bits ^ mask).to_be_bytes().to_vec()
        }
    );

    /// Per-type OPE property suite: determinism, ordering, length, serialisation
    /// round-trips, salt domain-separation, and a regression check for the
    /// pre-fix 1/256 wrap-around bug.
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

                    fn [<prop_ope_hex_round_trip_ $ty>](key: Key, x: $ty) -> bool {
                        let ct = key.encrypt_ope(x).unwrap();
                        let hex_str = hex::encode(ct.as_ref());
                        let ct2 = OpeCllw8V1::<{ <$ty>::BITS as usize + 1 }>::from_hex(&hex_str).unwrap();
                        ct == ct2
                    }

                    fn [<prop_ope_try_from_bytes_ $ty>](key: Key, x: $ty) -> bool {
                        let ct = key.encrypt_ope(x).unwrap();
                        let ct2 = OpeCllw8V1::<{ <$ty>::BITS as usize + 1 }>::try_from(ct.as_ref()).unwrap();
                        ct == ct2
                    }

                    fn [<prop_ope_different_salts_differ_ $ty>](key: Key, x: $ty) -> bool {
                        let ct1 = x.encrypt_ope_with_salt(&key, Some(b"domain1")).unwrap();
                        let ct2 = x.encrypt_ope_with_salt(&key, Some(b"domain2")).unwrap();
                        ct1 != ct2
                    }
                }
            }
        };
    }

    ope_quickcheck_type!(u16);
    ope_quickcheck_type!(u32);
    ope_quickcheck_type!(u64);
    ope_quickcheck_type!(u128);

    // --- Signed integer ORE/OPE property suites ---
    //
    // These mirror `quickcheck_type!`/`ope_quickcheck_type!` but use
    // signed-aware properties (no `1 << (BITS-1)`, anchors at MIN/-1/0/1/MAX).

    macro_rules! quickcheck_iint_type {
        ($ty:ident, $uty:ident) => {
            paste! {
                quickcheck! {
                    /// Determinism: same plaintext encrypts to equal ciphertexts.
                    fn [<prop_eq_ $ty>](key: Key, x: $ty) -> bool {
                        let a = key.encrypt(x).unwrap();
                        let b = key.encrypt(x).unwrap();
                        a == b
                    }

                    /// Order homomorphism: ciphertext order matches plaintext order.
                    fn [<prop_cmp_ $ty>](key: Key, x: $ty, y: $ty) -> bool {
                        let a = key.encrypt(x).unwrap();
                        let b = key.encrypt(y).unwrap();
                        a.cmp(&b) == x.cmp(&y)
                    }

                    /// Sign class: any negative encrypts below zero, zero below any positive.
                    fn [<prop_sign_class_ $ty>](key: Key, x: $ty) -> TestResult {
                        let zero_ct = key.encrypt::<$ty>(0).unwrap();
                        let ct = key.encrypt(x).unwrap();
                        TestResult::from_bool(match x.cmp(&0) {
                            Ordering::Less => ct < zero_ct,
                            Ordering::Equal => ct == zero_ct,
                            Ordering::Greater => ct > zero_ct,
                        })
                    }

                    /// MIN encrypts to a value strictly below 0.
                    fn [<prop_min_less_than_zero_ $ty>](key: Key) -> bool {
                        let min_ct = key.encrypt($ty::MIN).unwrap();
                        let zero_ct = key.encrypt::<$ty>(0).unwrap();
                        min_ct < zero_ct
                    }

                    /// MAX encrypts to a value strictly above 0.
                    fn [<prop_max_greater_than_zero_ $ty>](key: Key) -> bool {
                        let max_ct = key.encrypt($ty::MAX).unwrap();
                        let zero_ct = key.encrypt::<$ty>(0).unwrap();
                        max_ct > zero_ct
                    }

                    /// MIN encrypts deterministically (regression check on the
                    /// signed boundary, where bias maps it to 0u).
                    fn [<prop_min_ $ty>](key: Key) -> bool {
                        let a = key.encrypt($ty::MIN).unwrap();
                        let b = key.encrypt($ty::MIN).unwrap();
                        a == b
                    }

                    /// MAX encrypts deterministically.
                    fn [<prop_max_ $ty>](key: Key) -> bool {
                        let a = key.encrypt($ty::MAX).unwrap();
                        let b = key.encrypt($ty::MAX).unwrap();
                        a == b
                    }

                    /// (x-1) < x for all x > MIN.
                    fn [<prop_one_less_than_ $ty>](key: Key, x: $ty) -> TestResult {
                        if x == $ty::MIN {
                            return TestResult::discard();
                        }
                        let a = key.encrypt(x - 1).unwrap();
                        let b = key.encrypt(x).unwrap();
                        TestResult::from_bool(a.cmp(&b) == Ordering::Less)
                    }

                    /// Round-trip: decrypt to the unsigned bias and reverse the
                    /// XOR to recover the signed plaintext. Documents the
                    /// expected unbias pattern alongside verifying it.
                    fn [<prop_decrypt_ $ty>](key: Key, x: $ty) -> bool {
                        let ciphertext = key.encrypt(x).unwrap();
                        let biased: $uty = key.decrypt(ciphertext).unwrap();
                        let recovered = (biased ^ (1 << (<$uty>::BITS - 1))) as $ty;
                        x == recovered
                    }
                }
            }
        };
    }

    quickcheck_iint_type!(i16, u16);
    quickcheck_iint_type!(i32, u32);
    quickcheck_iint_type!(i64, u64);
    quickcheck_iint_type!(i128, u128);

    macro_rules! ope_quickcheck_iint_type {
        ($ty:ident, $bits:expr) => {
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

                    fn [<prop_ope_sign_class_ $ty>](key: Key, x: $ty) -> TestResult {
                        let zero_ct = key.encrypt_ope::<$ty>(0).unwrap();
                        let ct = key.encrypt_ope(x).unwrap();
                        TestResult::from_bool(match x.cmp(&0) {
                            Ordering::Less => ct < zero_ct,
                            Ordering::Equal => ct == zero_ct,
                            Ordering::Greater => ct > zero_ct,
                        })
                    }

                    fn [<prop_ope_length_ $ty>](key: Key, x: $ty) -> bool {
                        let ct = key.encrypt_ope(x).unwrap();
                        ct.as_ref().len() == $bits + 1
                    }

                    fn [<prop_ope_hex_round_trip_ $ty>](key: Key, x: $ty) -> bool {
                        let ct = key.encrypt_ope(x).unwrap();
                        let hex_str = hex::encode(ct.as_ref());
                        let ct2 = OpeCllw8V1::<{ $bits + 1 }>::from_hex(&hex_str).unwrap();
                        ct == ct2
                    }

                    fn [<prop_ope_different_salts_differ_ $ty>](key: Key, x: $ty) -> bool {
                        let ct1 = x.encrypt_ope_with_salt(&key, Some(b"domain1")).unwrap();
                        let ct2 = x.encrypt_ope_with_salt(&key, Some(b"domain2")).unwrap();
                        ct1 != ct2
                    }
                }
            }
        };
    }

    ope_quickcheck_iint_type!(i16, 16);
    ope_quickcheck_iint_type!(i32, 32);
    ope_quickcheck_iint_type!(i64, 64);
    ope_quickcheck_iint_type!(i128, 128);

    // Sanity anchors that pin the signed encoding at MIN/0/MAX and across
    // sign boundaries — easier to read than the property tests above.
    #[test]
    fn signed_ore_anchors_i32() {
        let key = Key::from([0u8; 32]);
        let min = key.encrypt(i32::MIN).unwrap();
        let neg_one = key.encrypt(-1i32).unwrap();
        let zero = key.encrypt(0i32).unwrap();
        let one = key.encrypt(1i32).unwrap();
        let max = key.encrypt(i32::MAX).unwrap();
        assert!(min < neg_one);
        assert!(neg_one < zero);
        assert!(zero < one);
        assert!(one < max);
    }

    #[test]
    fn signed_ore_decrypt_i64_anchors() {
        // Round-trip pattern for signed: decrypt to the unsigned bias, then
        // reverse the sign-flip XOR to recover the signed plaintext.
        let key = Key::from([7u8; 32]);
        for x in [i64::MIN, -1_000_000_000, -1, 0, 1, 1_000_000_000, i64::MAX] {
            let ct = key.encrypt(x).unwrap();
            let biased: u64 = key.decrypt(ct).unwrap();
            let recovered = (biased ^ (1u64 << 63)) as i64;
            assert_eq!(recovered, x);
        }
    }

    #[test]
    fn signed_ope_anchors_i32() {
        let key = Key::from([0u8; 32]);
        let min = key.encrypt_ope(i32::MIN).unwrap();
        let neg_one = key.encrypt_ope(-1i32).unwrap();
        let zero = key.encrypt_ope(0i32).unwrap();
        let one = key.encrypt_ope(1i32).unwrap();
        let max = key.encrypt_ope(i32::MAX).unwrap();
        assert!(min < neg_one);
        assert!(neg_one < zero);
        assert!(zero < one);
        assert!(one < max);
    }

    // --- Bool ---

    #[test]
    fn bool_ore_anchors() {
        let key = Key::from([0u8; 32]);
        let f = key.encrypt(false).unwrap();
        let t = key.encrypt(true).unwrap();
        assert!(f < t);
        assert_eq!(f, key.encrypt(false).unwrap());
        assert_eq!(t, key.encrypt(true).unwrap());
    }

    #[test]
    fn bool_ope_anchors() {
        let key = Key::from([0u8; 32]);
        let f = key.encrypt_ope(false).unwrap();
        let t = key.encrypt_ope(true).unwrap();
        assert!(f < t);
        assert_eq!(f, key.encrypt_ope(false).unwrap());
        assert_eq!(t, key.encrypt_ope(true).unwrap());
    }

    // --- Float property suites ---
    //
    // The encoding matches IEEE-754 totalOrder (same total order as
    // `f{32,64}::total_cmp`), including the `−0.0 < +0.0` split. NaN inputs
    // are discarded — the encoding is consistent on them too, but excluding
    // NaN keeps the assertion crisp and avoids depending on quickcheck's
    // NaN generation behaviour.

    macro_rules! quickcheck_float_type {
        ($ty:ident) => {
            paste! {
                quickcheck! {
                    fn [<prop_eq_ $ty>](key: Key, x: $ty) -> TestResult {
                        if x.is_nan() {
                            return TestResult::discard();
                        }
                        let a = key.encrypt(x).unwrap();
                        let b = key.encrypt(x).unwrap();
                        TestResult::from_bool(a == b)
                    }

                    fn [<prop_cmp_ $ty>](key: Key, x: $ty, y: $ty) -> TestResult {
                        if x.is_nan() || y.is_nan() {
                            return TestResult::discard();
                        }
                        let a = key.encrypt(x).unwrap();
                        let b = key.encrypt(y).unwrap();
                        TestResult::from_bool(a.cmp(&b) == x.total_cmp(&y))
                    }

                    fn [<prop_ope_eq_ $ty>](key: Key, x: $ty) -> TestResult {
                        if x.is_nan() {
                            return TestResult::discard();
                        }
                        let a = key.encrypt_ope(x).unwrap();
                        let b = key.encrypt_ope(x).unwrap();
                        TestResult::from_bool(a == b)
                    }

                    fn [<prop_ope_cmp_ $ty>](key: Key, x: $ty, y: $ty) -> TestResult {
                        if x.is_nan() || y.is_nan() {
                            return TestResult::discard();
                        }
                        let a = key.encrypt_ope(x).unwrap();
                        let b = key.encrypt_ope(y).unwrap();
                        TestResult::from_bool(a.cmp(&b) == x.total_cmp(&y))
                    }
                }
            }
        };
    }

    quickcheck_float_type!(f32);
    quickcheck_float_type!(f64);

    #[test]
    fn float_ore_anchors_f32() {
        let key = Key::from([0u8; 32]);
        let neg_inf = key.encrypt(f32::NEG_INFINITY).unwrap();
        let neg_one = key.encrypt(-1f32).unwrap();
        let neg_zero = key.encrypt(-0f32).unwrap();
        let pos_zero = key.encrypt(0f32).unwrap();
        let one = key.encrypt(1f32).unwrap();
        let inf = key.encrypt(f32::INFINITY).unwrap();
        assert!(neg_inf < neg_one);
        assert!(neg_one < neg_zero);
        assert!(neg_zero < pos_zero);
        assert!(pos_zero < one);
        assert!(one < inf);
    }

    #[test]
    fn float_ope_anchors_f64() {
        let key = Key::from([0u8; 32]);
        let neg_inf = key.encrypt_ope(f64::NEG_INFINITY).unwrap();
        let neg_one = key.encrypt_ope(-1f64).unwrap();
        let neg_zero = key.encrypt_ope(-0f64).unwrap();
        let pos_zero = key.encrypt_ope(0f64).unwrap();
        let one = key.encrypt_ope(1f64).unwrap();
        let inf = key.encrypt_ope(f64::INFINITY).unwrap();
        assert!(neg_inf < neg_one);
        assert!(neg_one < neg_zero);
        assert!(neg_zero < pos_zero);
        assert!(pos_zero < one);
        assert!(one < inf);
    }

    // --- Empirical exactness check ---
    //
    // The backward-carry encoding with MSB-bit placement (bit contributes
    // `+128` at its byte, not `+1`) gives exact OPE: lex comparison of the
    // ciphertext always agrees with the plaintext integer order. See
    // `packages/cllw-ore/docs/backward-carry-ope.md` for the derivation.
    //
    // This test exhaustively verifies the property on every adjacent u16 pair
    // under a set of keys — the worst case for the older `+1` variant, which
    // had a residual ~7.7e-6 per-pair error rate. It's `#[ignore]`-gated
    // because it's expensive (~2 min at 20 keys).

    #[test]
    #[ignore = "exhaustive exactness check — slow; run with `cargo test -- --ignored`"]
    fn ope_exactness_adjacent_u16() {
        let num_keys = 20usize;
        let mut total = 0u64;
        let mut errors = 0u64;

        for key_seed in 0..num_keys {
            let mut key_bytes = [0u8; 32];
            key_bytes[..8].copy_from_slice(&(key_seed as u64).to_le_bytes());
            let key = Key::from(key_bytes);

            for x in 0u16..u16::MAX {
                let ct_x = key.encrypt_ope(x).unwrap();
                let ct_y = key.encrypt_ope(x + 1).unwrap();
                total += 1;
                if ct_x.cmp(&ct_y) != Ordering::Less {
                    errors += 1;
                }
            }
        }

        assert_eq!(
            errors, 0,
            "exact OPE violated: {errors} ordering errors out of {total} adjacent pairs",
        );
    }
}
