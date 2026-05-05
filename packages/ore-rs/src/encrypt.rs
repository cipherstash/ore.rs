use crate::ciphertext::*;
use crate::PlainText;
use crate::{OreCipher, OreError};
use orderable_bytes::ToOrderableBytes;

/// Type-directed entry point for encrypting plaintext values with a given
/// [`OreCipher`].
///
/// Each implementation knows how to canonicalise its target type into the
/// fixed-size byte plaintext expected by the cipher. For primitives and
/// the `chrono` / `decimal` value types the canonicalisation is delegated
/// to [`orderable_bytes::ToOrderableBytes`], which guarantees the encoded
/// bytes preserve the type's natural total order under lexicographic
/// comparison. The associated output types pin the resulting ciphertext
/// shape, with `LeftOutput` the query-only half and `FullOutput` the full
/// ciphertext suitable for storage.
pub trait OreEncrypt<T: OreCipher> {
    /// Output type produced by [`encrypt_left`](Self::encrypt_left).
    type LeftOutput: OreOutput;
    /// Output type produced by [`encrypt`](Self::encrypt).
    type FullOutput: OreOutput;

    /// Encrypt `self` with `cipher`, producing the Left half only — useful
    /// for query plaintexts compared against stored ciphertexts.
    fn encrypt_left(&self, cipher: &T) -> Result<Self::LeftOutput, OreError>;
    /// Encrypt `self` with `input`, producing a full Left+Right ciphertext
    /// suitable for storage and subsequent comparison.
    fn encrypt(&self, input: &T) -> Result<Self::FullOutput, OreError>;
}

// `Left<T, N>` and `CipherText<T, N>` need a const-generic `N` known at
// the type level. Stable Rust can't accept `<Self as ToOrderableBytes>::ENCODED_LEN`
// directly in that position (it would require `generic_const_exprs`), so
// we lift each primitive's encoded length into a free `const` and name
// that const in the associated type. Same idiom as `chrono.rs` /
// `decimal.rs`.
const BOOL_LEN: usize = <bool as ToOrderableBytes>::ENCODED_LEN;
const U8_LEN: usize = <u8 as ToOrderableBytes>::ENCODED_LEN;
const I8_LEN: usize = <i8 as ToOrderableBytes>::ENCODED_LEN;
const U16_LEN: usize = <u16 as ToOrderableBytes>::ENCODED_LEN;
const I16_LEN: usize = <i16 as ToOrderableBytes>::ENCODED_LEN;
const U32_LEN: usize = <u32 as ToOrderableBytes>::ENCODED_LEN;
const I32_LEN: usize = <i32 as ToOrderableBytes>::ENCODED_LEN;
const U64_LEN: usize = <u64 as ToOrderableBytes>::ENCODED_LEN;
const I64_LEN: usize = <i64 as ToOrderableBytes>::ENCODED_LEN;
const U128_LEN: usize = <u128 as ToOrderableBytes>::ENCODED_LEN;
const I128_LEN: usize = <i128 as ToOrderableBytes>::ENCODED_LEN;
const CHAR_LEN: usize = <char as ToOrderableBytes>::ENCODED_LEN;
const F32_LEN: usize = <f32 as ToOrderableBytes>::ENCODED_LEN;
const F64_LEN: usize = <f64 as ToOrderableBytes>::ENCODED_LEN;

macro_rules! impl_ore_encrypt_via_orderable_bytes {
    ($type:ty, $len_const:ident) => {
        impl<T: OreCipher> OreEncrypt<T> for $type {
            type LeftOutput = Left<T, $len_const>;
            type FullOutput = CipherText<T, $len_const>;

            fn encrypt_left(&self, cipher: &T) -> Result<Self::LeftOutput, OreError> {
                cipher.encrypt_left(&self.to_orderable_bytes())
            }

            fn encrypt(&self, cipher: &T) -> Result<Self::FullOutput, OreError> {
                cipher.encrypt(&self.to_orderable_bytes())
            }
        }
    };
}

impl_ore_encrypt_via_orderable_bytes!(bool, BOOL_LEN);
impl_ore_encrypt_via_orderable_bytes!(u8, U8_LEN);
impl_ore_encrypt_via_orderable_bytes!(i8, I8_LEN);
impl_ore_encrypt_via_orderable_bytes!(u16, U16_LEN);
impl_ore_encrypt_via_orderable_bytes!(i16, I16_LEN);
impl_ore_encrypt_via_orderable_bytes!(u32, U32_LEN);
impl_ore_encrypt_via_orderable_bytes!(i32, I32_LEN);
impl_ore_encrypt_via_orderable_bytes!(u64, U64_LEN);
impl_ore_encrypt_via_orderable_bytes!(i64, I64_LEN);
impl_ore_encrypt_via_orderable_bytes!(u128, U128_LEN);
impl_ore_encrypt_via_orderable_bytes!(i128, I128_LEN);
impl_ore_encrypt_via_orderable_bytes!(char, CHAR_LEN);
impl_ore_encrypt_via_orderable_bytes!(f32, F32_LEN);
impl_ore_encrypt_via_orderable_bytes!(f64, F64_LEN);

impl<T: OreCipher, const N: usize> OreEncrypt<T> for PlainText<N> {
    type LeftOutput = Left<T, N>;
    type FullOutput = CipherText<T, N>;

    fn encrypt_left(&self, cipher: &T) -> Result<Self::LeftOutput, OreError> {
        cipher.encrypt_left(self)
    }

    fn encrypt(&self, cipher: &T) -> Result<Self::FullOutput, OreError> {
        cipher.encrypt(self)
    }
}
