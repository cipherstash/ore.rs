//! OPE for the fixed-size byte arrays the `chrono` and `decimal` encoders
//! produce with [`orderable_bytes`].
//!
//! Each `[u8; N]` is treated as an opaque canonical byte form whose lex
//! order is the property the caller wants to preserve under encryption.
//! The bytes are fed through the shared [`super::encrypt_ope_bits`]
//! primitive, producing a fixed-size [`OpeClww8V1<{N * 8 + 1}>`]
//! ciphertext. This is the building block used by the `decimal` and
//! `chrono` impls: the type-specific encoders convert their value to a
//! `[u8; N]` via [`orderable_bytes`] and delegate here.
//!
//! The trait is crate-private. A public `ClwwOpeEncrypt` for `[u8; N]`
//! would encrypt bytes a caller encoded by hand (little-endian integers,
//! an unflipped sign bit) without error, and they would then sort wrong.
//!
//! The set of supported widths is restricted to the sizes the bundled
//! type encoders need (4 for `NaiveDate`, 12 for `DateTime<Utc>`, 14 for
//! `Decimal`). Adding more is a one-line macro invocation if a new
//! type-specific encoder needs it.

use crate::biterator::Biterator;
use crate::impls::encrypt_ope_bits;
use crate::{Error, Key, OpeClww8V1};

/// OPE over an encoder's canonical bytes, for the `chrono` and `decimal`
/// impls only.
pub(crate) trait OpeByteArray {
    /// The fixed-size ciphertext, one byte per bit plus the carry byte.
    type Output;

    /// Encrypt the bytes as they are, under an optional salt.
    fn encrypt_ope_array(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error>;
}

/// Generates an `OpeByteArray` impl for `[u8; $n]` whose ciphertext is
/// `OpeClww8V1<{ $n * 8 + 1 }>`. The `$n` substitution must be a literal
/// (or other compile-time integer), since stable Rust does not yet
/// accept `OpeClww8V1<{ N * 8 + 1 }>` for a generic `const N: usize` —
/// that needs `feature(generic_const_exprs)`.
macro_rules! impl_clww_ope_byte_array {
    ($n:literal) => {
        impl OpeByteArray for [u8; $n] {
            type Output = OpeClww8V1<{ $n * 8 + 1 }>;

            fn encrypt_ope_array(
                self,
                key: &Key,
                salt: Option<&[u8]>,
            ) -> Result<Self::Output, Error> {
                let bits = self.into_iter().flat_map(Biterator::new);
                let vec = encrypt_ope_bits(bits, key, salt)?;
                let mut bytes = [0u8; { $n * 8 + 1 }];
                bytes.copy_from_slice(&vec);
                Ok(OpeClww8V1::from_bytes(bytes))
            }
        }
    };
}

// `chrono::NaiveDate` (orderable_bytes::chrono::naive_date::ENCODED_LEN).
impl_clww_ope_byte_array!(4);
// `chrono::DateTime<Utc>` (orderable_bytes::chrono::datetime_utc::ENCODED_LEN).
impl_clww_ope_byte_array!(12);
// `rust_decimal::Decimal` (orderable_bytes::decimal::ENCODED_LEN).
impl_clww_ope_byte_array!(14);

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;
    use quickcheck::{quickcheck, Arbitrary, Gen};

    fn key() -> Key {
        Key::from([7u8; 32])
    }

    /// Wrapper to give quickcheck an `Arbitrary` instance for `[u8; N]`.
    /// `quickcheck` ships impls for tuples and `Vec<u8>` but not arbitrary-N
    /// arrays.
    #[derive(Debug, Clone, Copy)]
    struct ArbBytes<const N: usize>([u8; N]);

    impl<const N: usize> Arbitrary for ArbBytes<N> {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut bytes = [0u8; N];
            for b in &mut bytes {
                *b = u8::arbitrary(g);
            }
            ArbBytes(bytes)
        }
    }

    // Encryption is deterministic for a given (key, salt, plaintext).
    quickcheck! {
        fn prop_byte_array_4_determinism(x: ArbBytes<4>) -> bool {
            let a = x.0.encrypt_ope_array(&key(), None).unwrap();
            let b = x.0.encrypt_ope_array(&key(), None).unwrap();
            a == b
        }

        fn prop_byte_array_12_determinism(x: ArbBytes<12>) -> bool {
            let a = x.0.encrypt_ope_array(&key(), None).unwrap();
            let b = x.0.encrypt_ope_array(&key(), None).unwrap();
            a == b
        }

        fn prop_byte_array_14_determinism(x: ArbBytes<14>) -> bool {
            let a = x.0.encrypt_ope_array(&key(), None).unwrap();
            let b = x.0.encrypt_ope_array(&key(), None).unwrap();
            a == b
        }

        // Headline invariant: lex order on ciphertexts matches lex order on
        // plaintext byte arrays. This is the property the type-specific
        // encoders rely on to inherit ordering from `orderable_bytes`.
        fn prop_byte_array_4_cmp(x: ArbBytes<4>, y: ArbBytes<4>) -> bool {
            let a = x.0.encrypt_ope_array(&key(), None).unwrap();
            let b = y.0.encrypt_ope_array(&key(), None).unwrap();
            a.cmp(&b) == x.0.cmp(&y.0)
        }

        fn prop_byte_array_12_cmp(x: ArbBytes<12>, y: ArbBytes<12>) -> bool {
            let a = x.0.encrypt_ope_array(&key(), None).unwrap();
            let b = y.0.encrypt_ope_array(&key(), None).unwrap();
            a.cmp(&b) == x.0.cmp(&y.0)
        }

        fn prop_byte_array_14_cmp(x: ArbBytes<14>, y: ArbBytes<14>) -> bool {
            let a = x.0.encrypt_ope_array(&key(), None).unwrap();
            let b = y.0.encrypt_ope_array(&key(), None).unwrap();
            a.cmp(&b) == x.0.cmp(&y.0)
        }
    }

    // Width pinning: ciphertext is exactly `N * 8 + 1` bytes.
    #[test]
    fn ciphertext_widths() {
        let k = key();
        assert_eq!(
            [0u8; 4].encrypt_ope_array(&k, None).unwrap().as_ref().len(),
            4 * 8 + 1
        );
        assert_eq!(
            [0u8; 12]
                .encrypt_ope_array(&k, None)
                .unwrap()
                .as_ref()
                .len(),
            12 * 8 + 1
        );
        assert_eq!(
            [0u8; 14]
                .encrypt_ope_array(&k, None)
                .unwrap()
                .as_ref()
                .len(),
            14 * 8 + 1
        );
    }

    // Hex round-trip: ensure ciphertext bytes serialise/parse losslessly.
    #[test]
    fn hex_round_trip_14() {
        let ct = [42u8; 14].encrypt_ope_array(&key(), None).unwrap();
        let parsed = OpeClww8V1::<{ 14 * 8 + 1 }>::from_hex(hex::encode(ct.as_ref())).unwrap();
        assert_eq!(ct, parsed);
    }

    // Salt domain separation propagates through the byte-array path.
    #[test]
    fn distinct_salts_produce_distinct_ciphertexts() {
        let k = key();
        let x = [9u8; 14];
        let a = x.encrypt_ope_array(&k, Some(b"domain-a")).unwrap();
        let b = x.encrypt_ope_array(&k, Some(b"domain-b")).unwrap();
        assert_ne!(a, b);
    }
}
