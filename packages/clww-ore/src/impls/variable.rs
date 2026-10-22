//! The terms of the two schemes:
//!
//! - [`OreClww8VariableV1`], the term of [`crate::ClwwOre`];
//! - [`OpeClww8VariableV1`], the term of [`crate::ClwwOpe`].
//!
//! Both are encrypt-only. This module defines the types, how stored bytes
//! become one, and how they compare; the encryption is in [`super`].

use crate::Error;
use hex::FromHex;
#[cfg(feature = "postgres-types")]
use postgres_types::ToSql;
use std::cmp::Ordering;
use subtle::ConstantTimeEq;

const BITS_PER_BYTE: usize = 8;

/// A CLWW ORE term: the term of [`crate::ClwwOre`], for every target.
///
/// One byte per plaintext bit, so 8 bytes per byte of the sealed plaintext.
/// `Ord` is the scheme's comparator, never byte order. The Postgres type is
/// `ore_cllw_8_variable_v1`, with the `postgres-types` feature.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres-types", derive(ToSql))]
#[cfg_attr(feature = "postgres-types", postgres(name = "ore_cllw_8_variable_v1"))]
pub struct OreClww8VariableV1 {
    bytes: Vec<u8>,
}

impl AsRef<[u8]> for OreClww8VariableV1 {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// The hex decoder (`#[serde(with = "hex::serde")]`), with the same length
/// check as [`from_bytes`](OreClww8VariableV1::from_bytes).
impl FromHex for OreClww8VariableV1 {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Self::from_bytes(hex::decode(hex).map_err(|_| Error)?)
    }
}

/// Slice-borrowing counterpart of [`OreClww8VariableV1::from_bytes`], with
/// the same length check.
impl TryFrom<&[u8]> for OreClww8VariableV1 {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value.to_vec())
    }
}

impl OreClww8VariableV1 {
    /// The one length rule, shared by [`from_bytes`](Self::from_bytes) and
    /// the `TryFrom` impl: encryption emits one byte per plaintext *bit*, so
    /// a ciphertext over whole-byte plaintext is a multiple of 8 bytes long,
    /// and never empty, since no plaintext vitaminc seals is.
    fn is_term_len(len: usize) -> bool {
        len > 0 && len.is_multiple_of(BITS_PER_BYTE)
    }

    /// Wrap bytes without the length check, for terms this crate just made
    /// (valid by construction) and tests.
    pub(crate) fn from_bytes_unchecked(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Rebuild a term from stored bytes, rejecting lengths no ORE term can
    /// have. Structural only: bytes that pass are not thereby proven to be a
    /// genuine term.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        if !Self::is_term_len(bytes.len()) {
            return Err(Error);
        }
        Ok(Self { bytes })
    }
}

impl Ord for OreClww8VariableV1 {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_lex(self, other)
    }
}

impl PartialOrd for OreClww8VariableV1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for OreClww8VariableV1 {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for OreClww8VariableV1 {}

/// Compare two outputs lexicographically in constant time.
/// Terms of values of different lengths have different lengths, and a
/// shorter term that is a prefix of a longer one sorts first.
fn compare_lex(a: &OreClww8VariableV1, b: &OreClww8VariableV1) -> Ordering {
    let a_len = a.bytes.len();
    let b_len = b.bytes.len();
    let slice_len = a_len.min(b_len);

    // Handle empty slices
    if slice_len == 0 {
        return a_len.cmp(&b_len);
    }

    // Compare the common prefix
    let prefix_ordering = super::compare_pairs(a.bytes.iter().zip(b.bytes.iter()));

    // If prefix is equal, compare by length; otherwise return prefix comparison
    match prefix_ordering {
        Ordering::Equal => a_len.cmp(&b_len),
        other => other,
    }
}

// --- Variable-length OPE ---

/// A CLWW OPE term: the term of [`crate::ClwwOpe`], for every target.
///
/// Terms compare in standard lexicographic byte order, so a database needs no
/// comparator of its own. The Postgres type is `ore_cllw_8_ope_variable_v1`,
/// with the `postgres-types` feature.
/// Encryption uses the CLWW keystream from Section 3.2 of the paper; the
/// plaintext bit contribution is placed at the top bit of its byte (adding
/// `128` rather than `1`) and the resulting sum is propagated as a
/// right-to-left carry into a reserved leading byte.
///
/// **Correctness**: comparison is **exact** — lex compare always agrees
/// with the plaintext byte-lex order. The `+128` signal at the first
/// differing byte exceeds any backward-carry noise (±1 per byte), so no
/// PRF choice can flip the comparison. See
/// `packages/clww-ore/docs/backward-carry-ope.md` for the derivation.
///
/// **Encrypt-only**, as every term in this crate is: if round-trip is
/// required, pair the term with an authenticated symmetric cipher (e.g.
/// AES-GCM) over the same plaintext.
///
/// The ciphertext length is `8 * plaintext_bytes + 1` (one reserved leading
/// byte plus one byte per plaintext bit).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "postgres-types", derive(ToSql))]
#[cfg_attr(
    feature = "postgres-types",
    postgres(name = "ore_cllw_8_ope_variable_v1")
)]
pub struct OpeClww8VariableV1 {
    bytes: Vec<u8>,
}

impl OpeClww8VariableV1 {
    /// The one length rule, shared by [`from_bytes`](Self::from_bytes) and
    /// the `TryFrom` impl: a ciphertext over whole-byte plaintext is
    /// `8 * plaintext_bytes + 1` long (one byte per plaintext bit plus the
    /// reserved leading carry byte), and no plaintext vitaminc seals is
    /// empty, so the carry byte alone is not a term.
    fn is_term_len(len: usize) -> bool {
        len > 1 && len % BITS_PER_BYTE == 1
    }

    /// Wrap bytes without the length check, for terms this crate just made
    /// (valid by construction) and tests.
    pub(crate) fn from_bytes_unchecked(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Rebuild a term from stored bytes, rejecting lengths no OPE term can
    /// have. Structural only: bytes that pass are not thereby proven to be a
    /// genuine term.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        if !Self::is_term_len(bytes.len()) {
            return Err(Error);
        }
        Ok(Self { bytes })
    }
}

/// Slice-borrowing counterpart of [`OpeClww8VariableV1::from_bytes`], with
/// the same length check.
impl TryFrom<&[u8]> for OpeClww8VariableV1 {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value.to_vec())
    }
}

impl AsRef<[u8]> for OpeClww8VariableV1 {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// The hex decoder, with the same length check as
/// [`from_bytes`](OpeClww8VariableV1::from_bytes).
impl FromHex for OpeClww8VariableV1 {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Self::from_bytes(hex::decode(hex).map_err(|_| Error)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // One length rule per type, shared by `from_bytes`, `TryFrom` and
    // `from_hex`: an ORE term is a non-empty multiple of 8 bytes and an OPE
    // term is `8 * n + 1` with `n > 0` (the reserved leading carry byte).

    #[test]
    fn ore_rejects_impossible_length_on_the_checked_entry_points() {
        for bad in [vec![], vec![0u8; 7]] {
            assert!(OreClww8VariableV1::from_bytes(bad.clone()).is_err());
            assert!(OreClww8VariableV1::try_from(bad.as_slice()).is_err());
            assert!(OreClww8VariableV1::from_hex(hex::encode(&bad)).is_err());
        }
    }

    #[test]
    fn ore_round_trips_a_valid_length_on_every_entry_point() {
        let valid = vec![0xABu8; 16];
        let hex_str = hex::encode(&valid);

        assert_eq!(
            OreClww8VariableV1::from_bytes(valid.clone())
                .expect("from_bytes")
                .as_ref(),
            valid.as_slice()
        );
        assert_eq!(
            OreClww8VariableV1::try_from(valid.as_slice())
                .expect("try_from")
                .as_ref(),
            valid.as_slice()
        );
        assert_eq!(
            OreClww8VariableV1::from_hex(&hex_str)
                .expect("from_hex")
                .as_ref(),
            valid.as_slice()
        );
    }

    #[test]
    fn ope_rejects_impossible_length_on_the_checked_entry_points() {
        // A multiple of 8 is exactly what an OPE ciphertext cannot be: the
        // carry byte makes every valid length `8 * n + 1`. The carry byte
        // alone is a term of the empty plaintext, which no space seals.
        for bad in [vec![0u8; 8], vec![0u8]] {
            assert!(OpeClww8VariableV1::from_bytes(bad.clone()).is_err());
            assert!(OpeClww8VariableV1::try_from(bad.as_slice()).is_err());
            assert!(OpeClww8VariableV1::from_hex(hex::encode(&bad)).is_err());
        }
    }

    #[test]
    fn malformed_hex_is_refused() {
        // A non-hex digit, and an odd number of digits.
        for bad in ["zz", "0", "0g00000000000000"] {
            assert!(OreClww8VariableV1::from_hex(bad).is_err(), "{bad}");
            assert!(OpeClww8VariableV1::from_hex(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ope_round_trips_a_valid_length_on_every_entry_point() {
        let valid = vec![0xCDu8; 17];
        let hex_str = hex::encode(&valid);

        assert_eq!(
            OpeClww8VariableV1::from_bytes(valid.clone())
                .expect("from_bytes")
                .as_ref(),
            valid.as_slice()
        );
        assert_eq!(
            OpeClww8VariableV1::try_from(valid.as_slice())
                .expect("try_from")
                .as_ref(),
            valid.as_slice()
        );
        assert_eq!(
            OpeClww8VariableV1::from_hex(&hex_str)
                .expect("from_hex")
                .as_ref(),
            valid.as_slice()
        );
    }
}
