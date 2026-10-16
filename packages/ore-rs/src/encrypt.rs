use crate::ciphertext::*;
use crate::scheme::bit2::{OreAes128, MAX_BLOCKS};
use crate::PlainText;
use crate::{OreCipher, OreError};
use orderable_bytes::{FixedOrderableBytes, OrderableBytes};
use rand::{Rng, SeedableRng};

/// Type-directed entry point for encrypting plaintext values with a given
/// cipher: an [`OreCipher`], or the chained scheme
/// [`crate::scheme::chained::OreAes128Bit6Chained`].
///
/// Each implementation knows how to canonicalise its target type into the
/// fixed-size byte plaintext expected by the cipher. For primitives and
/// the `chrono` / `decimal` value types the canonicalisation is delegated
/// to [`orderable_bytes::OrderableBytes`], which guarantees the encoded
/// bytes preserve the type's natural total order under lexicographic
/// comparison. The associated output types pin the resulting ciphertext
/// shape, with `LeftOutput` the query-only half and `FullOutput` the full
/// ciphertext suitable for storage.
pub trait OreEncrypt<T> {
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
// the type level. Stable Rust can't accept `<Self as FixedOrderableBytes>::ENCODED_LEN`
// directly in that position (it would require `generic_const_exprs`), so
// we lift each primitive's encoded length into a free `const` and name
// that const in the associated type. Same idiom as `chrono.rs` /
// `decimal.rs`.
const BOOL_LEN: usize = <bool as FixedOrderableBytes>::ENCODED_LEN;
const U8_LEN: usize = <u8 as FixedOrderableBytes>::ENCODED_LEN;
const I8_LEN: usize = <i8 as FixedOrderableBytes>::ENCODED_LEN;
const U16_LEN: usize = <u16 as FixedOrderableBytes>::ENCODED_LEN;
const I16_LEN: usize = <i16 as FixedOrderableBytes>::ENCODED_LEN;
const U32_LEN: usize = <u32 as FixedOrderableBytes>::ENCODED_LEN;
const I32_LEN: usize = <i32 as FixedOrderableBytes>::ENCODED_LEN;
const U64_LEN: usize = <u64 as FixedOrderableBytes>::ENCODED_LEN;
const I64_LEN: usize = <i64 as FixedOrderableBytes>::ENCODED_LEN;
const CHAR_LEN: usize = <char as FixedOrderableBytes>::ENCODED_LEN;
const F32_LEN: usize = <f32 as FixedOrderableBytes>::ENCODED_LEN;
const F64_LEN: usize = <f64 as FixedOrderableBytes>::ENCODED_LEN;

// These impls are specific to the legacy byte-per-block scheme (one
// plaintext byte = one ORE block, so the orderable-bytes encoding feeds
// the cipher directly). The 6-bit scheme provides its own impls in
// `scheme::bit2_w6`, which interpose the byte->block decomposition. They
// were previously blanket impls over `T: OreCipher`; scheme-specific
// impls keep coherence simple now that block count != byte count for
// some schemes.
//
// Each invocation also emits a test that the type round-trips, orders `$lo`
// below `$hi`, and compares equal across nonces, so a type cannot be listed
// as supported without being exercised (issue #105).
macro_rules! impl_ore_encrypt_via_orderable_bytes {
    ($type:ty, $len_const:ident, $tests:ident, $lo:expr, $hi:expr) => {
        // The legacy left-tag input puts the block index at byte `N` of one
        // AES block, so the scheme takes at most 15 bytes. `u128`/`i128`
        // (16 bytes) must not get these impls: see `scheme::chained`.
        const _: () = assert!($len_const <= MAX_BLOCKS);

        impl<R: Rng + SeedableRng> OreEncrypt<OreAes128<R>> for $type {
            type LeftOutput = Left<OreAes128<R>, $len_const>;
            type FullOutput = CipherText<OreAes128<R>, $len_const>;

            fn encrypt_left(&self, cipher: &OreAes128<R>) -> Result<Self::LeftOutput, OreError> {
                cipher.encrypt_left(&self.to_orderable_bytes())
            }

            fn encrypt(&self, cipher: &OreAes128<R>) -> Result<Self::FullOutput, OreError> {
                cipher.encrypt(&self.to_orderable_bytes())
            }
        }

        #[cfg(test)]
        mod $tests {
            use super::*;
            use crate::scheme::bit2::OreAes128ChaCha20;
            use std::cmp::Ordering;

            #[test]
            fn round_trip_order_and_equality() {
                let ore: OreAes128ChaCha20 = OreCipher::init(&[0x11; 16], &[0x22; 16]).unwrap();
                let (lo, hi): ($type, $type) = ($lo, $hi);
                assert!(lo < hi);

                let lo_ct = lo.encrypt(&ore).unwrap();
                let hi_ct = hi.encrypt(&ore).unwrap();
                let lo_left = lo.encrypt_left(&ore).unwrap();
                let lo_ct2 = lo.encrypt(&ore).unwrap();

                let lo_bytes = lo_ct.to_bytes();
                let hi_bytes = hi_ct.to_bytes();
                assert_eq!(
                    CipherText::<OreAes128ChaCha20, $len_const>::from_slice(&lo_bytes)
                        .unwrap()
                        .to_bytes(),
                    lo_bytes
                );
                assert_eq!(
                    Left::<OreAes128ChaCha20, $len_const>::from_slice(&lo_left.to_bytes())
                        .unwrap()
                        .to_bytes(),
                    lo_left.to_bytes()
                );

                let cmp = OreAes128ChaCha20::compare_raw_slices;
                assert_eq!(cmp(&lo_bytes, &hi_bytes), Some(Ordering::Less));
                assert_eq!(cmp(&hi_bytes, &lo_bytes), Some(Ordering::Greater));
                assert_ne!(lo_bytes, lo_ct2.to_bytes());
                assert_eq!(cmp(&lo_bytes, &lo_ct2.to_bytes()), Some(Ordering::Equal));
                // The typed comparator, where the scheme has one.
                assert_eq!(lo_ct.cmp(&hi_ct), Ordering::Less);
            }
        }
    };
}

impl_ore_encrypt_via_orderable_bytes!(bool, BOOL_LEN, bool_tests, false, true);
impl_ore_encrypt_via_orderable_bytes!(u8, U8_LEN, u8_tests, 0u8, u8::MAX);
impl_ore_encrypt_via_orderable_bytes!(i8, I8_LEN, i8_tests, i8::MIN, i8::MAX);
impl_ore_encrypt_via_orderable_bytes!(u16, U16_LEN, u16_tests, 0u16, u16::MAX);
impl_ore_encrypt_via_orderable_bytes!(i16, I16_LEN, i16_tests, i16::MIN, i16::MAX);
impl_ore_encrypt_via_orderable_bytes!(u32, U32_LEN, u32_tests, 0u32, u32::MAX);
impl_ore_encrypt_via_orderable_bytes!(i32, I32_LEN, i32_tests, i32::MIN, i32::MAX);
impl_ore_encrypt_via_orderable_bytes!(u64, U64_LEN, u64_tests, 0u64, u64::MAX);
impl_ore_encrypt_via_orderable_bytes!(i64, I64_LEN, i64_tests, i64::MIN, i64::MAX);
// `u128`/`i128` (16 bytes) exceed this scheme's 15-byte limit and are
// provided by `scheme::chained` instead (issue #105).
impl_ore_encrypt_via_orderable_bytes!(char, CHAR_LEN, char_tests, '\0', char::MAX);
impl_ore_encrypt_via_orderable_bytes!(f32, F32_LEN, f32_tests, f32::MIN, f32::MAX);
impl_ore_encrypt_via_orderable_bytes!(f64, F64_LEN, f64_tests, f64::MIN, f64::MAX);

impl<R: Rng + SeedableRng, const N: usize> OreEncrypt<OreAes128<R>> for PlainText<N> {
    type LeftOutput = Left<OreAes128<R>, N>;
    type FullOutput = CipherText<OreAes128<R>, N>;

    fn encrypt_left(&self, cipher: &OreAes128<R>) -> Result<Self::LeftOutput, OreError> {
        cipher.encrypt_left(self)
    }

    fn encrypt(&self, cipher: &OreAes128<R>) -> Result<Self::FullOutput, OreError> {
        cipher.encrypt(self)
    }
}
