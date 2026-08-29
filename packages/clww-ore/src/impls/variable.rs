//! Variable-length CLWW ciphertext types and their associated machinery.
//!
//! This module owns both:
//!
//! - [`OreCllw8VariableV1`] — Order-Revealing Encryption ciphertext for
//!   variable-length plaintexts (strings, byte slices). Supports decryption.
//! - [`OpeCllw8VariableV1`] — Order-Preserving Encryption ciphertext for
//!   variable-length plaintexts (strings, byte slices). Encrypt-only.
//!
//! The actual encryption logic for `&str` / `&[u8]` lives in
//! [`super::string`]; this module only defines the ciphertext types,
//! their construction helpers, comparison/equality semantics, and the
//! ORE → bytes/UTF-8 decryption path.

use crate::{CllwOreDecrypt, Error, Key};
use hex::{FromHex, FromHexError};
#[cfg(feature = "postgres-types")]
use postgres_types::ToSql;
use std::cmp::Ordering;
use subtle::ConstantTimeEq;

const BITS_PER_BYTE: usize = 8;

/// Variable-length CLWW ORE ciphertext for strings and byte slices.
///
/// This type represents an encrypted value using the CLWW Order-Revealing Encryption scheme
/// for variable-length data types like `&str` and `&[u8]`.
///
/// The ciphertext length is proportional to the input length (8 bytes per input byte).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres-types", derive(ToSql))]
#[cfg_attr(feature = "postgres-types", postgres(name = "ore_cllw_8_variable_v1"))]
pub struct OreCllw8VariableV1 {
    bytes: Vec<u8>,
}

impl AsRef<[u8]> for OreCllw8VariableV1 {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Deliberately **not** length-checked, unlike
/// [`from_bytes`](OreCllw8VariableV1::from_bytes) and the `TryFrom` impl: this
/// is the wire decoder (`#[serde(with = "hex::serde")]`) for consumers whose
/// plaintext is a *tagged bit stream* rather than whole bytes, whose
/// ciphertexts are legitimately not a multiple of 8 bytes long. Rejecting
/// them here would reject real stored terms. See
/// [`from_bytes_unchecked`](OreCllw8VariableV1::from_bytes_unchecked).
impl FromHex for OreCllw8VariableV1 {
    type Error = FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: hex::decode(hex)?,
        })
    }
}

/// Slice-borrowing counterpart of [`OreCllw8VariableV1::from_bytes`], with
/// the same length check.
impl TryFrom<&[u8]> for OreCllw8VariableV1 {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value.to_vec())
    }
}

impl OreCllw8VariableV1 {
    /// The one length rule, shared by [`from_bytes`](Self::from_bytes) and
    /// the `TryFrom` impl: encryption emits one byte per plaintext *bit*, so
    /// a ciphertext over whole-byte plaintext is a multiple of 8 bytes long
    /// (the same check [`decrypt_to_bytes`](Self::decrypt_to_bytes) applies
    /// before decrypting).
    fn is_byte_aligned_len(len: usize) -> bool {
        len.is_multiple_of(BITS_PER_BYTE)
    }

    /// Wrap bytes without the length check — for ciphertexts this crate just
    /// produced (valid by construction) and for consumers encrypting a
    /// *tagged bit stream* rather than whole bytes, whose ciphertexts are
    /// legitimately not a multiple of 8 bytes long and which
    /// [`from_bytes`](Self::from_bytes) would therefore reject.
    pub fn from_bytes_unchecked(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Rebuild a ciphertext from stored bytes, rejecting lengths no ORE
    /// ciphertext of *whole-byte* plaintext can have. Structural only —
    /// bytes that pass are not thereby proven to be a genuine ciphertext.
    /// Callers holding a tagged-bit-stream ciphertext want
    /// [`from_bytes_unchecked`](Self::from_bytes_unchecked) instead.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        if !Self::is_byte_aligned_len(bytes.len()) {
            return Err(Error);
        }
        Ok(Self { bytes })
    }

    /// Decrypt the ciphertext to raw bytes
    pub fn decrypt_to_bytes(&self, key: &Key, salt: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        // Validate that ciphertext length is a multiple of 8
        // Each plaintext byte requires exactly 8 ciphertext bytes (one per bit)
        // Use Unspecified error to avoid oracle attacks that could exploit specific error messages
        if !self.bytes.len().is_multiple_of(BITS_PER_BYTE) {
            return Err(Error);
        }

        let mut hasher = blake3::Hasher::new_keyed(&key.0);
        if let Some(salt) = salt {
            let _ = hasher.update(salt);
        }

        let mut result_bytes = Vec::with_capacity(self.bytes.len() / BITS_PER_BYTE);
        let mut current_byte: u8 = 0;

        for (i, &ciphertext_byte) in self.bytes.iter().enumerate() {
            let mut buf: [u8; 16] = [0; 16];
            hasher.finalize_xof().fill(&mut buf);
            let prf_block = u128::from_be_bytes(buf) & 0xFF;
            // Recover the bit by subtracting ciphertext from PRF block
            let bit = ciphertext_byte.wrapping_sub(prf_block as u8) & 0x01;
            let _ = hasher.update(&[bit]);

            // Build up the byte MSB-first (8 bits per byte)
            // Use constant-time operation to avoid timing side-channel
            let bit_position = i % BITS_PER_BYTE;
            current_byte |= bit << (7 - bit_position);

            // Push the byte when we've collected 8 bits (every 8th iteration)
            // Check using modulo which is constant-time for the bit position
            if bit_position == 7 {
                result_bytes.push(current_byte);
                current_byte = 0;
            }
        }

        Ok(result_bytes)
    }
}

impl CllwOreDecrypt for OreCllw8VariableV1 {
    type Output = String;

    fn decrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let result_bytes = self.decrypt_to_bytes(key, salt)?;
        // Convert bytes back to string
        // Use Unspecified error to avoid oracle attacks that could exploit specific error messages
        String::from_utf8(result_bytes).map_err(|_| Error)
    }
}

impl Ord for OreCllw8VariableV1 {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_lex(self, other)
    }
}

impl PartialOrd for OreCllw8VariableV1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for OreCllw8VariableV1 {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for OreCllw8VariableV1 {}

/// Compare two outputs lexicographically in constant time.
/// This is useful for strings where the length of the output is not necessarily the same.
/// A shorter string is considered less than a longer string if it is a prefix of the longer string.
fn compare_lex(a: &OreCllw8VariableV1, b: &OreCllw8VariableV1) -> Ordering {
    let a_len = a.bytes.len();
    let b_len = b.bytes.len();
    let slice_len = a_len.min(b_len);

    // Handle empty slices
    if slice_len == 0 {
        return a_len.cmp(&b_len);
    }

    // Compare the common prefix
    let prefix_ordering = super::compare_slice(&a.bytes[..slice_len], &b.bytes[..slice_len]);

    // If prefix is equal, compare by length; otherwise return prefix comparison
    match prefix_ordering {
        Ordering::Equal => a_len.cmp(&b_len),
        other => other,
    }
}

// --- Variable-length OPE ---

/// Variable-length CLWW OPE ciphertext for strings and byte slices.
///
/// Ciphertexts are compared with standard lexicographic byte ordering.
/// Encryption uses the CLWW keystream from Section 3.2 of the paper; the
/// plaintext bit contribution is placed at the top bit of its byte (adding
/// `128` rather than `1`) and the resulting sum is propagated as a
/// right-to-left carry into a reserved leading byte.
///
/// **Correctness**: comparison is **exact** — lex compare always agrees
/// with the plaintext byte-lex order. The `+128` signal at the first
/// differing byte exceeds any backward-carry noise (±1 per byte), so no
/// PRF choice can flip the comparison. See
/// `packages/cllw-ore/docs/backward-carry-ope.md` for the derivation.
///
/// **Encrypt-only**: this type intentionally does not support decryption.
/// OPE is used for ordered lookups; if round-trip is required, pair the OPE
/// ciphertext with an authenticated symmetric cipher (e.g. AES-GCM) over the
/// same plaintext.
///
/// The ciphertext length is `8 * plaintext_bytes + 1` (one reserved leading
/// byte plus one byte per plaintext bit).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "postgres-types", derive(ToSql))]
#[cfg_attr(
    feature = "postgres-types",
    postgres(name = "ore_cllw_8_ope_variable_v1")
)]
pub struct OpeCllw8VariableV1 {
    bytes: Vec<u8>,
}

impl OpeCllw8VariableV1 {
    /// The one length rule, shared by [`from_bytes`](Self::from_bytes) and
    /// the `TryFrom` impl: a ciphertext over whole-byte plaintext is
    /// `8 * plaintext_bytes + 1` long (one byte per plaintext bit plus the
    /// reserved leading carry byte).
    fn is_byte_aligned_len(len: usize) -> bool {
        len % BITS_PER_BYTE == 1
    }

    /// Wrap bytes produced by [`crate::encrypt_ope_bits`] without the length
    /// check — for ciphertexts this crate just produced (valid by
    /// construction) and for consumers encrypting a *tagged bit stream*
    /// rather than whole bytes (the `decimal`/`chrono` modules, external
    /// consumers wiring their own tagged plaintext bit streams), whose
    /// ciphertexts are legitimately not `8n + 1` long and which
    /// [`from_bytes`](Self::from_bytes) would therefore reject.
    pub fn from_bytes_unchecked(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Rebuild a ciphertext from stored bytes produced by
    /// [`crate::encrypt_ope_bits`], rejecting lengths no OPE ciphertext of
    /// *whole-byte* plaintext can have. Structural only — bytes that pass are
    /// not thereby proven to be a genuine ciphertext. Callers holding a
    /// tagged-bit-stream ciphertext want
    /// [`from_bytes_unchecked`](Self::from_bytes_unchecked) instead.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        if !Self::is_byte_aligned_len(bytes.len()) {
            return Err(Error);
        }
        Ok(Self { bytes })
    }
}

/// Slice-borrowing counterpart of [`OpeCllw8VariableV1::from_bytes`], with
/// the same length check.
impl TryFrom<&[u8]> for OpeCllw8VariableV1 {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value.to_vec())
    }
}

impl AsRef<[u8]> for OpeCllw8VariableV1 {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Deliberately **not** length-checked, for the same reason as the ORE impl
/// above: it is the wire decoder for tagged-bit-stream ciphertexts, whose
/// lengths the `8n + 1` rule does not describe.
impl FromHex for OpeCllw8VariableV1 {
    type Error = FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: hex::decode(hex)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // One length rule per type, shared by `from_bytes` and `TryFrom`: over
    // whole-byte plaintext an ORE ciphertext is a multiple of 8 bytes and an
    // OPE ciphertext is `8 * n + 1` (the reserved leading carry byte).
    // `from_hex` (the wire decoder) and `from_bytes_unchecked` stay permissive
    // for tagged-bit-stream ciphertexts, which the rule does not describe.

    #[test]
    fn ore_rejects_impossible_length_on_the_checked_entry_points() {
        let short = vec![0u8; 7];
        assert!(OreCllw8VariableV1::from_bytes(short.clone()).is_err());
        assert!(OreCllw8VariableV1::try_from(short.as_slice()).is_err());
        // `from_hex` and `from_bytes_unchecked` are the documented escape
        // hatches for tagged-bit-stream ciphertexts, so they accept it.
        assert!(OreCllw8VariableV1::from_hex(hex::encode(&short)).is_ok());
    }

    #[test]
    fn ore_round_trips_a_valid_length_on_every_entry_point() {
        let valid = vec![0xABu8; 16];
        let hex_str = hex::encode(&valid);

        assert_eq!(
            OreCllw8VariableV1::from_bytes(valid.clone())
                .expect("from_bytes")
                .as_ref(),
            valid.as_slice()
        );
        assert_eq!(
            OreCllw8VariableV1::try_from(valid.as_slice())
                .expect("try_from")
                .as_ref(),
            valid.as_slice()
        );
        assert_eq!(
            OreCllw8VariableV1::from_hex(&hex_str)
                .expect("from_hex")
                .as_ref(),
            valid.as_slice()
        );
    }

    #[test]
    fn ope_rejects_impossible_length_on_the_checked_entry_points() {
        // A multiple of 8 is exactly what an OPE ciphertext cannot be: the
        // carry byte makes every valid length `8 * n + 1`.
        let short = vec![0u8; 8];
        assert!(OpeCllw8VariableV1::from_bytes(short.clone()).is_err());
        assert!(OpeCllw8VariableV1::try_from(short.as_slice()).is_err());
        // As for ORE: the hex wire decoder stays permissive on purpose.
        assert!(OpeCllw8VariableV1::from_hex(hex::encode(&short)).is_ok());
    }

    #[test]
    fn ope_round_trips_a_valid_length_on_every_entry_point() {
        let valid = vec![0xCDu8; 17];
        let hex_str = hex::encode(&valid);

        assert_eq!(
            OpeCllw8VariableV1::from_bytes(valid.clone())
                .expect("from_bytes")
                .as_ref(),
            valid.as_slice()
        );
        assert_eq!(
            OpeCllw8VariableV1::try_from(valid.as_slice())
                .expect("try_from")
                .as_ref(),
            valid.as_slice()
        );
        assert_eq!(
            OpeCllw8VariableV1::from_hex(&hex_str)
                .expect("from_hex")
                .as_ref(),
            valid.as_slice()
        );
    }
}
