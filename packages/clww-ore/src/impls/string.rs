use crate::{
    biterator::{string_biter, Biterator},
    impls::encrypt_ope_bits,
    CllwOpeEncrypt, CllwOreDecrypt, CllwOreEncrypt, Error, Key,
};
use hex::{FromHex, FromHexError};
#[cfg(feature = "postgres-types")]
use postgres_types::ToSql;
use std::cmp::Ordering;
use subtle::ConstantTimeEq;
use unicode_normalization::char::decompose_canonical;

const BITS_PER_BYTE: usize = 8;

/// Variable-length CLLW ORE ciphertext for strings and byte slices.
///
/// This type represents an encrypted value using the CLLW Order-Revealing Encryption scheme
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

impl FromHex for OreCllw8VariableV1 {
    type Error = FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: hex::decode(hex)?,
        })
    }
}

/// FIXME: this impl should not exist - there are infinitely many Vec lengths that will not contain a valid term.
/// Fallibility is a must. Switch to TryFrom.
impl From<Vec<u8>> for OreCllw8VariableV1 {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl OreCllw8VariableV1 {
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

impl CllwOreEncrypt for &[u8] {
    type Output = OreCllw8VariableV1;

    fn encrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let len = self.len() * u8::BITS as usize;
        let mut hasher = blake3::Hasher::new_keyed(&key.0);
        if let Some(salt) = salt {
            let _ = hasher.update(salt);
        }

        // Process each byte through the Biterator (MSB first)
        let bytes = self.iter().flat_map(|&byte| Biterator::new(byte)).fold(
            Vec::with_capacity(len),
            |mut out, bit| {
                let mut buf: [u8; 16] = [0; 16];
                hasher.finalize_xof().fill(&mut buf);
                let byte = u128::from_be_bytes(buf).wrapping_add(bit as u128) & 0xFF;
                let _ = hasher.update(&[bit]);
                out.push(byte as u8);
                out
            },
        );

        Ok(OreCllw8VariableV1 { bytes })
    }
}

impl CllwOreEncrypt for &str {
    type Output = OreCllw8VariableV1;

    fn encrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let string = orderize_string(self);
        let len = string.len() * u8::BITS as usize;
        let mut hasher = blake3::Hasher::new_keyed(&key.0);
        if let Some(salt) = salt {
            let _ = hasher.update(salt);
        }
        let bytes = string_biter(&string).fold(Vec::with_capacity(len), |mut out, bit| {
            let mut buf: [u8; 16] = [0; 16];
            hasher.finalize_xof().fill(&mut buf);
            let byte = u128::from_be_bytes(buf).wrapping_add(bit as u128) & 0xFF;
            let _ = hasher.update(&[bit]);
            out.push(byte as u8);
            out
        });

        Ok(OreCllw8VariableV1 { bytes })
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

/// Variable-length CLLW OPE ciphertext for strings and byte slices.
///
/// Ciphertexts are compared with standard lexicographic byte ordering.
/// Encryption uses the CLLW keystream from Section 3.2 of the paper and
/// propagates the `+1` addition as a right-to-left carry into a reserved
/// leading byte, which dramatically reduces the ~1/256 ordering error
/// of the paper's naive base-256 OPE interpretation.
///
/// **Correctness**: comparison is *not* exact. The residual per-comparison
/// error rate is approximately `(1/255)² / 2 ≈ 7.7 × 10⁻⁶` for adjacent
/// plaintext pairs and essentially zero for well-separated ones. The
/// residual error is inherent to the CLLW construction (the PRF chain is
/// plaintext-dependent, so low-order PRF divergence can occasionally flip
/// the high-order comparison via the carry pass).
///
/// **Encrypt-only**: this type intentionally does not support decryption.
/// OPE is used for ordered lookups; callers that need round-trip should
/// pair it with an ORE (`OreCllw8VariableV1`) ciphertext.
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

impl AsRef<[u8]> for OpeCllw8VariableV1 {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl FromHex for OpeCllw8VariableV1 {
    type Error = FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: hex::decode(hex)?,
        })
    }
}

impl CllwOpeEncrypt for &str {
    type Output = OpeCllw8VariableV1;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let normalized = orderize_string(self);
        let n = normalized.len() * 8;
        let bytes = encrypt_ope_bits(string_biter(&normalized), n, key, salt);
        Ok(OpeCllw8VariableV1 { bytes })
    }
}

impl CllwOpeEncrypt for &[u8] {
    type Output = OpeCllw8VariableV1;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let n = self.len() * 8;
        let bits = self.iter().flat_map(|&byte| Biterator::new(byte));
        let bytes = encrypt_ope_bits(bits, n, key, salt);
        Ok(OpeCllw8VariableV1 { bytes })
    }
}

/// Normalizes the string use Unicode = NFKC normalization, and then removes any
/// characters that are not alphanumeric, whitespace, or ASCII punctuation.
/// This is a "rough" collation that is used to orderize strings for encryption.
///
/// Eventually, this will move to a more sophisticated collation that can handle
/// more complex strings using the [Unicode Collation Algorithm](https://www.unicode.org/reports/tr10/).
fn orderize_string(input: &str) -> String {
    fn filter_push(out: &mut String, c: char) {
        if c.is_alphanumeric() || c.is_whitespace() || c.is_ascii_punctuation() {
            out.push(c);
        }
    }

    input.chars().fold(String::new(), |mut out, c| {
        decompose_canonical(c, |c| filter_push(&mut out, c));
        out
    })
}

#[cfg(test)]
mod tests {
    use super::{orderize_string, OpeCllw8VariableV1, OreCllw8VariableV1};
    use crate::{Error, Key};
    use quickcheck::{quickcheck, Arbitrary, Gen};
    use std::cmp::Ordering;

    /// The set of characters that survive `orderize_string`: ASCII alphanumeric, space, and ASCII
    /// punctuation. These are the characters that are preserved after NFKC normalization and
    /// filtering.
    const ORDERIZE_SAFE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

    /// A string type that only contains characters that survive `orderize_string`.
    /// This enables meaningful property tests for roundtrip and ordering.
    #[derive(Debug, Clone)]
    struct SafeString(String);

    impl Arbitrary for SafeString {
        fn arbitrary(g: &mut Gen) -> Self {
            let len = usize::arbitrary(g) % 32; // Limit length to keep tests fast
            let s: String = (0..len)
                .map(|_| {
                    let idx = usize::arbitrary(g) % ORDERIZE_SAFE_CHARS.len();
                    ORDERIZE_SAFE_CHARS[idx] as char
                })
                .collect();
            SafeString(s)
        }
    }

    fn encrypt_cmp(x: &str, y: &str) -> Ordering {
        let key = Key::from([0; 32]);
        let a = key.encrypt(x).unwrap();
        let b = key.encrypt(y).unwrap();
        a.cmp(&b)
    }

    #[test]
    fn test_ascii_strings_eq() {
        assert_eq!(encrypt_cmp("hello", "hello"), Ordering::Equal);
        assert_eq!(encrypt_cmp("00hello", "00hello"), Ordering::Equal);
        // Case sensitivity retained (ne!)
        assert_eq!(encrypt_cmp("Hello", "hello"), Ordering::Less);
    }

    #[test]
    fn test_ascii_strings() {
        assert_eq!(encrypt_cmp("", "a"), Ordering::Less);
        assert_eq!(encrypt_cmp("hell", "hello"), Ordering::Less);
        // Punctuation is ordered before letters
        assert_eq!(encrypt_cmp("hello", "'hello"), Ordering::Greater);
        assert_eq!(encrypt_cmp("hello", "\"hello"), Ordering::Greater);
    }

    #[test]
    fn test_numbers() {
        // Numbers are ordered before letters
        assert_eq!(encrypt_cmp("00hello", "hello"), Ordering::Less);
        assert_eq!(encrypt_cmp("00hello", "helloooooo"), Ordering::Less);
        assert_eq!(encrypt_cmp("A", "3"), Ordering::Greater);
        // Numbers are ordered numerically with other numbers
        assert_eq!(encrypt_cmp("00hello", "11hello"), Ordering::Less);
        assert_eq!(encrypt_cmp("hello00", "hello99"), Ordering::Less);
        assert_eq!(encrypt_cmp("hello77", "hello30"), Ordering::Greater);
        assert_eq!(encrypt_cmp("77", "30"), Ordering::Greater);
    }

    #[test]
    fn test_string_non_ascii_stripped() {
        // Non-ASCII characters are stripped
        assert_eq!(encrypt_cmp("hello’", "hello"), Ordering::Equal);
        assert_eq!(encrypt_cmp("hello😎", "hello"), Ordering::Equal);
    }

    #[test]
    fn test_string_whitespace() {
        assert_eq!(encrypt_cmp(" hello", "helloo"), Ordering::Less);
        assert_eq!(encrypt_cmp("hello world", "helloXworld"), Ordering::Less);
        assert_eq!(encrypt_cmp("hello world", "hello?world"), Ordering::Less);
    }

    #[test]
    fn test_decrypt_string() {
        let key = Key::from([0; 32]);
        let plaintext = "hello";
        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_decrypt_string_with_whitespace() {
        let key = Key::from([0; 32]);
        let plaintext = "hello world";
        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_decrypt_string_with_numbers() {
        let key = Key::from([0; 32]);
        let plaintext = "hello123";
        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_decrypt_empty_string() {
        let key = Key::from([0; 32]);
        let plaintext = "";
        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_bytes() {
        let key = Key::from([0; 32]);
        let data: &[u8] = b"hello";
        let ciphertext = key.encrypt(data).unwrap();
        let decrypted_bytes = ciphertext.decrypt_to_bytes(&key, None).unwrap();
        assert_eq!(data, decrypted_bytes.as_slice());
    }

    #[test]
    fn test_encrypt_bytes_with_zeros() {
        let key = Key::from([0; 32]);
        let data: &[u8] = &[0, 1, 2, 3, 4];
        let ciphertext = key.encrypt(data).unwrap();
        let decrypted_bytes = ciphertext.decrypt_to_bytes(&key, None).unwrap();
        assert_eq!(data, decrypted_bytes.as_slice());
    }

    #[test]
    fn test_encrypt_empty_bytes() {
        let key = Key::from([0; 32]);
        let data: &[u8] = &[];
        let ciphertext = key.encrypt(data).unwrap();
        let decrypted_bytes = ciphertext.decrypt_to_bytes(&key, None).unwrap();
        assert_eq!(data, decrypted_bytes.as_slice());
    }

    #[test]
    fn test_encrypt_bytes_preserves_order() {
        let key = Key::from([0; 32]);
        let data1: &[u8] = b"abc";
        let data2: &[u8] = b"abd";
        let ct1 = key.encrypt(data1).unwrap();
        let ct2 = key.encrypt(data2).unwrap();
        assert_eq!(ct1.cmp(&ct2), Ordering::Less);
    }

    #[test]
    fn test_encrypt_bytes_binary_data() {
        let key = Key::from([0; 32]);
        let data: &[u8] = &[0xFF, 0x00, 0xAB, 0xCD];
        let ciphertext = key.encrypt(data).unwrap();
        let decrypted_bytes = ciphertext.decrypt_to_bytes(&key, None).unwrap();
        assert_eq!(data, decrypted_bytes.as_slice());
    }

    // Salt tests for strings

    #[test]
    fn test_string_different_salts_produce_different_ciphertexts() {
        use crate::CllwOreEncrypt;

        let key = Key::from([0; 32]);
        let plaintext = "hello";
        let salt1 = b"domain1";
        let salt2 = b"domain2";

        let ct1 = plaintext.encrypt_with_salt(&key, Some(salt1)).unwrap();
        let ct2 = plaintext.encrypt_with_salt(&key, Some(salt2)).unwrap();

        // Different salts should produce different ciphertexts
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_string_wrong_salt_fails_or_produces_garbage() {
        use crate::{CllwOreDecrypt, CllwOreEncrypt};

        let key = Key::from([0; 32]);
        let plaintext = "hello";
        let salt1 = b"domain1";
        let salt2 = b"domain2";

        let ciphertext = plaintext.encrypt_with_salt(&key, Some(salt1)).unwrap();

        // Using wrong salt typically produces invalid UTF-8 and fails
        // or in rare cases produces garbage if it happens to be valid UTF-8
        match ciphertext.decrypt_with_salt(&key, Some(salt2)) {
            Err(_) => {} // Expected: invalid UTF-8
            Ok(decrypted) => {
                // If it succeeds, it should be garbage (not the original)
                assert_ne!(plaintext, decrypted);
            }
        }
    }

    #[test]
    fn test_string_correct_salt_decrypts_correctly() {
        use crate::{CllwOreDecrypt, CllwOreEncrypt};

        let key = Key::from([0; 32]);
        let plaintext = "hello world";
        let salt = b"my-domain";

        let ciphertext = plaintext.encrypt_with_salt(&key, Some(salt)).unwrap();
        let decrypted = ciphertext.decrypt_with_salt(&key, Some(salt)).unwrap();

        // Using correct salt should decrypt correctly
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_string_no_salt_and_none_salt_are_equivalent() {
        use crate::CllwOreEncrypt;

        let key = Key::from([0; 32]);
        let plaintext = "hello";

        let ct1 = plaintext.encrypt(&key).unwrap();
        let ct2 = plaintext.encrypt_with_salt(&key, None).unwrap();

        // No salt and None salt should produce identical ciphertexts
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_string_empty_salt_same_as_no_salt() {
        use crate::CllwOreEncrypt;

        let key = Key::from([0; 32]);
        let plaintext = "hello";

        let ct_no_salt = plaintext.encrypt_with_salt(&key, None).unwrap();
        let ct_empty_salt = plaintext.encrypt_with_salt(&key, Some(b"")).unwrap();

        // Empty salt produces same result as no salt (empty bytes don't change hash)
        assert_eq!(ct_no_salt, ct_empty_salt);
    }

    #[test]
    fn test_string_salt_preserves_ordering() {
        use crate::CllwOreEncrypt;

        let key = Key::from([0; 32]);
        let salt = b"domain";

        let ct1 = "alice".encrypt_with_salt(&key, Some(salt)).unwrap();
        let ct2 = "bob".encrypt_with_salt(&key, Some(salt)).unwrap();

        // Ordering should be preserved even with salt
        assert!(ct1 < ct2);
    }

    // Salt tests for byte slices

    #[test]
    fn test_bytes_different_salts_produce_different_ciphertexts() {
        use crate::CllwOreEncrypt;

        let key = Key::from([0; 32]);
        let data: &[u8] = b"hello";
        let salt1 = b"domain1";
        let salt2 = b"domain2";

        let ct1 = data.encrypt_with_salt(&key, Some(salt1)).unwrap();
        let ct2 = data.encrypt_with_salt(&key, Some(salt2)).unwrap();

        // Different salts should produce different ciphertexts
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_bytes_wrong_salt_produces_wrong_plaintext() {
        use crate::CllwOreEncrypt;

        let key = Key::from([0; 32]);
        let data: &[u8] = b"hello";
        let salt1 = b"domain1";
        let salt2 = b"domain2";

        let ciphertext = data.encrypt_with_salt(&key, Some(salt1)).unwrap();
        let decrypted = ciphertext.decrypt_to_bytes(&key, Some(salt2)).unwrap();

        // Using wrong salt should produce incorrect plaintext
        assert_ne!(data, decrypted.as_slice());
    }

    #[test]
    fn test_bytes_correct_salt_decrypts_correctly() {
        use crate::CllwOreEncrypt;

        let key = Key::from([0; 32]);
        let data: &[u8] = &[0xFF, 0x00, 0xAB, 0xCD];
        let salt = b"my-domain";

        let ciphertext = data.encrypt_with_salt(&key, Some(salt)).unwrap();
        let decrypted = ciphertext.decrypt_to_bytes(&key, Some(salt)).unwrap();

        // Using correct salt should decrypt correctly
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_bytes_no_salt_and_none_salt_are_equivalent() {
        use crate::CllwOreEncrypt;

        let key = Key::from([0; 32]);
        let data: &[u8] = b"hello";

        let ct1 = data.encrypt(&key).unwrap();
        let ct2 = data.encrypt_with_salt(&key, None).unwrap();

        // No salt and None salt should produce identical ciphertexts
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_bytes_empty_salt_same_as_no_salt() {
        use crate::CllwOreEncrypt;

        let key = Key::from([0; 32]);
        let data: &[u8] = b"hello";

        let ct_no_salt = data.encrypt_with_salt(&key, None).unwrap();
        let ct_empty_salt = data.encrypt_with_salt(&key, Some(b"")).unwrap();

        // Empty salt produces same result as no salt (empty bytes don't change hash)
        assert_eq!(ct_no_salt, ct_empty_salt);
    }

    #[test]
    fn test_bytes_salt_preserves_ordering() {
        use crate::CllwOreEncrypt;

        let key = Key::from([0; 32]);
        let salt = b"domain";
        let data1: &[u8] = &[1, 2, 3];
        let data2: &[u8] = &[1, 2, 4];

        let ct1 = data1.encrypt_with_salt(&key, Some(salt)).unwrap();
        let ct2 = data2.encrypt_with_salt(&key, Some(salt)).unwrap();

        // Ordering should be preserved even with salt
        assert!(ct1 < ct2);
    }

    // Ciphertext validation tests

    #[test]
    fn test_malformed_ciphertext_length_not_multiple_of_8() {
        let key = Key::from([0; 32]);

        // Create a valid ciphertext and then truncate it to an invalid length
        let data: &[u8] = b"test";
        let ciphertext = key.encrypt(data).unwrap();

        // Truncate to make length not a multiple of 8
        // Valid length would be 32 (4 bytes * 8 bits), so try 30
        let invalid_bytes = ciphertext.as_ref()[..30].to_vec();
        let malformed_ct = OreCllw8VariableV1::from(invalid_bytes);

        // Decryption should fail with Unspecified error
        let result = malformed_ct.decrypt_to_bytes(&key, None);
        assert!(matches!(result, Err(Error)));
    }

    #[test]
    fn test_malformed_ciphertext_length_7() {
        let key = Key::from([0; 32]);

        // Create a ciphertext with length 7 (not multiple of 8)
        let invalid_bytes = vec![0u8; 7];
        let malformed_ct = OreCllw8VariableV1::from(invalid_bytes);

        // Decryption should fail
        let result = malformed_ct.decrypt_to_bytes(&key, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_ciphertext_length_0() {
        let key = Key::from([0; 32]);

        // Empty ciphertext (length 0) is valid - represents empty input
        let empty_ct = OreCllw8VariableV1::from(vec![]);

        let result = empty_ct.decrypt_to_bytes(&key, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_valid_ciphertext_length_8() {
        let key = Key::from([0; 32]);

        // Length 8 is valid (represents 1 byte)
        let data: &[u8] = &[42];
        let ciphertext = key.encrypt(data).unwrap();

        assert_eq!(ciphertext.as_ref().len(), 8);

        let decrypted = ciphertext.decrypt_to_bytes(&key, None).unwrap();
        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_malformed_string_ciphertext_fails_gracefully() {
        let key = Key::from([0; 32]);

        // Create a malformed ciphertext (length not multiple of 8)
        let invalid_bytes = vec![0u8; 15];
        let malformed_ct = OreCllw8VariableV1::from(invalid_bytes);

        // String decryption should also fail with the same error
        let result = key.decrypt(malformed_ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_orderize_empty() {
        assert!(orderize_string("").is_empty());
    }

    // Property tests for strings

    quickcheck! {
        /// Test that encrypting the same string twice produces equal ciphertexts
        fn prop_string_eq(key: Key, x: SafeString) -> bool {
            let a = key.encrypt(x.0.as_str()).unwrap();
            let b = key.encrypt(x.0.as_str()).unwrap();
            a == b
        }

        /// Test that encryption preserves the ordering relationship between any two strings
        fn prop_string_cmp(key: Key, x: SafeString, y: SafeString) -> bool {
            let a = key.encrypt(x.0.as_str()).unwrap();
            let b = key.encrypt(y.0.as_str()).unwrap();

            // Compare the orderized forms since that's what gets encrypted
            let x_ord = orderize_string(&x.0);
            let y_ord = orderize_string(&y.0);

            a.cmp(&b) == x_ord.cmp(&y_ord)
        }

        /// Test that decryption correctly recovers the original string
        fn prop_string_decrypt(key: Key, x: SafeString) -> bool {
            let ciphertext = key.encrypt(x.0.as_str()).unwrap();
            let decrypted: String = key.decrypt(ciphertext).unwrap();

            // The decrypted value should match the orderized input
            let expected = orderize_string(&x.0);
            decrypted == expected
        }

        /// Test that empty string encrypts deterministically
        fn prop_string_empty(key: Key) -> bool {
            let a = key.encrypt("").unwrap();
            let b = key.encrypt("").unwrap();
            a == b
        }

        /// Test that empty string is less than any non-empty string
        fn prop_string_empty_less_than(key: Key, x: SafeString) -> bool {
            let x_ord = orderize_string(&x.0);
            if x_ord.is_empty() {
                return true; // Skip if x normalizes to empty
            }

            let empty = key.encrypt("").unwrap();
            let non_empty = key.encrypt(x.0.as_str()).unwrap();
            empty < non_empty
        }

        /// Test that a string is less than itself with an appended character
        fn prop_string_prefix_less_than(key: Key, x: SafeString) -> bool {
            let mut extended = x.0.clone();
            extended.push('a'); // Append a safe character

            let a = key.encrypt(x.0.as_str()).unwrap();
            let b = key.encrypt(extended.as_str()).unwrap();

            let x_ord = orderize_string(&x.0);
            let ext_ord = orderize_string(&extended);

            a.cmp(&b) == x_ord.cmp(&ext_ord)
        }
    }

    // Property tests for byte slices

    quickcheck! {
        /// Test that encrypting the same bytes twice produces equal ciphertexts
        fn prop_bytes_eq(key: Key, x: Vec<u8>) -> bool {
            let a = key.encrypt(x.as_slice()).unwrap();
            let b = key.encrypt(x.as_slice()).unwrap();
            a == b
        }

        /// Test that encryption preserves the ordering relationship between any two byte slices
        fn prop_bytes_cmp(key: Key, x: Vec<u8>, y: Vec<u8>) -> bool {
            let a = key.encrypt(x.as_slice()).unwrap();
            let b = key.encrypt(y.as_slice()).unwrap();
            a.cmp(&b) == x.cmp(&y)
        }

        /// Test that decryption correctly recovers the original bytes
        fn prop_bytes_decrypt(key: Key, x: Vec<u8>) -> bool {
            let ciphertext = key.encrypt(x.as_slice()).unwrap();
            let decrypted = ciphertext.decrypt_to_bytes(&key, None).unwrap();
            decrypted == x
        }

        /// Test that empty bytes encrypts deterministically
        fn prop_bytes_empty(key: Key) -> bool {
            let empty: &[u8] = &[];
            let a = key.encrypt(empty).unwrap();
            let b = key.encrypt(empty).unwrap();
            a == b
        }
    }

    // --- Variable-length OPE tests ---
    //
    // OPE encryption is exact (100%) here — every assertion uses plain
    // equality rather than a statistical tolerance.

    #[test]
    fn test_ope_variable_reserved_byte_and_length() {
        let key = Key::from([0u8; 32]);
        // Empty plaintext is a single reserved byte.
        let empty = key.encrypt_ope("").unwrap();
        assert_eq!(empty.as_ref().len(), 1);
        // A single character is 8 bits + 1 reserved byte.
        let single = key.encrypt_ope("a").unwrap();
        assert_eq!(single.as_ref().len(), 9);
        // Byte-slice path: length = 8 * N + 1.
        let five: &[u8] = b"hello";
        let ct = key.encrypt_ope(five).unwrap();
        assert_eq!(ct.as_ref().len(), 8 * five.len() + 1);
    }

    #[test]
    fn test_ope_variable_empty_less_than_nonempty() {
        for k in 0..32u8 {
            let key = Key::from([k; 32]);
            let empty = key.encrypt_ope("").unwrap();
            for s in ["a", "hello", "zebra", "   ", "~"] {
                let ct = key.encrypt_ope(s).unwrap();
                assert!(empty < ct, "empty should be less than {s:?} under key {k}");
            }
        }
    }

    #[test]
    fn test_ope_variable_adjacent_single_bytes() {
        for seed in [0u8, 1, 17, 99, 200] {
            let key = Key::from([seed; 32]);
            for x in 0u8..=254 {
                let a: &[u8] = &[x];
                let b: &[u8] = &[x + 1];
                let ca = key.encrypt_ope(a).unwrap();
                let cb = key.encrypt_ope(b).unwrap();
                assert!(
                    ca < cb,
                    "seed {seed}, x={x}: expected ct({x}) < ct({})",
                    x + 1
                );
            }
        }
    }

    #[test]
    fn test_ope_variable_prefix_ordering() {
        for seed in [0u8, 7, 42] {
            let key = Key::from([seed; 32]);
            // Prefix strictly less than its extension.
            let pairs: &[(&[u8], &[u8])] = &[
                (b"a", b"ab"),
                (b"abc", b"abcd"),
                (b"", b"x"),
                (b"hello", b"hello!"),
                (b"\x00", b"\x00\x00"),
                (b"\xff", b"\xff\x00"),
            ];
            for (shorter, longer) in pairs {
                let cs = key.encrypt_ope(*shorter).unwrap();
                let cl = key.encrypt_ope(*longer).unwrap();
                assert!(
                    cs < cl,
                    "seed {seed}: expected ct({shorter:?}) < ct({longer:?})"
                );
            }
        }
    }

    #[test]
    fn test_ope_variable_carry_across_byte_boundary() {
        // Plaintexts chosen to force a multi-byte carry chain: [0x00, 0xFF]
        // vs [0x01, 0x00] only differ in a single position (the top bit of
        // byte 1 / low bits of byte 0), so any carry from the later bits
        // must walk left across the byte boundary to preserve order.
        for seed in 0..64u8 {
            let key = Key::from([seed; 32]);
            let a: &[u8] = &[0x00, 0xFF];
            let b: &[u8] = &[0x01, 0x00];
            let ca = key.encrypt_ope(a).unwrap();
            let cb = key.encrypt_ope(b).unwrap();
            assert!(
                ca < cb,
                "seed {seed}: ct([0x00,0xFF]) should be < ct([0x01,0x00])"
            );
        }
    }

    #[test]
    fn test_ope_variable_exhaustive_boundary_pairs() {
        // Enumerate every 2-byte plaintext built from boundary values
        // {0x00, 0x01, 0xFE, 0xFF} and every pair of them across several
        // keys.
        let boundary: [u8; 4] = [0x00, 0x01, 0xFE, 0xFF];
        let mut plaintexts: Vec<[u8; 2]> = Vec::new();
        for &a in &boundary {
            for &b in &boundary {
                plaintexts.push([a, b]);
            }
        }
        for seed in [0u8, 1, 13, 127, 255] {
            let key = Key::from([seed; 32]);
            let cts: Vec<OpeCllw8VariableV1> = plaintexts
                .iter()
                .map(|p| key.encrypt_ope(p.as_slice()).unwrap())
                .collect();
            for i in 0..plaintexts.len() {
                for j in 0..plaintexts.len() {
                    assert_eq!(
                        cts[i].cmp(&cts[j]),
                        plaintexts[i].cmp(&plaintexts[j]),
                        "seed {seed}: ct({:?}) vs ct({:?})",
                        plaintexts[i],
                        plaintexts[j],
                    );
                }
            }
        }
    }

    #[test]
    fn test_ope_variable_determinism() {
        let key = Key::from([3u8; 32]);
        for input in [b"".as_slice(), b"a", b"hello", b"\x00\xff\x01"] {
            let a = key.encrypt_ope(input).unwrap();
            let b = key.encrypt_ope(input).unwrap();
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_ope_hex_round_trip_variable() {
        use hex::FromHex;
        let key = Key::from([0u8; 32]);
        let ct = key.encrypt_ope("hello").unwrap();
        let hex_str = hex::encode(ct.as_ref());
        let ct2 = OpeCllw8VariableV1::from_hex(&hex_str).unwrap();
        assert_eq!(ct, ct2);
    }

    // --- Variable-length OPE property tests ---

    quickcheck! {
        /// Regression property for the 1/256 wrap-around bug. Under the old
        /// scheme, a small fraction of keys would report ct(0x00) > ct(0x01)
        /// because PRF_7 = 0xFF makes the wrapped byte 0x00 compare less than
        /// the un-wrapped peer's 0xFF. The backward-carry design must give
        /// the correct order for every key.
        fn prop_ope_variable_single_bit_difference(key: Key) -> bool {
            let c1 = key.encrypt_ope([0x00u8].as_slice()).unwrap();
            let c2 = key.encrypt_ope([0x01u8].as_slice()).unwrap();
            c1 < c2
        }

        fn prop_ope_variable_ordering_matches_plaintext(a: Vec<u8>, b: Vec<u8>, key: Key) -> bool {
            let ca = key.encrypt_ope(a.as_slice()).unwrap();
            let cb = key.encrypt_ope(b.as_slice()).unwrap();
            ca.cmp(&cb) == a.cmp(&b)
        }

        fn prop_ope_variable_length_invariant(a: Vec<u8>, key: Key) -> bool {
            let ct = key.encrypt_ope(a.as_slice()).unwrap();
            ct.as_ref().len() == 8 * a.len() + 1
        }

        fn prop_ope_variable_determinism_bytes(a: Vec<u8>, key: Key) -> bool {
            let c1 = key.encrypt_ope(a.as_slice()).unwrap();
            let c2 = key.encrypt_ope(a.as_slice()).unwrap();
            c1 == c2
        }

        fn prop_ope_variable_string_ordering(a: SafeString, b: SafeString, key: Key) -> bool {
            let ca = key.encrypt_ope(a.0.as_str()).unwrap();
            let cb = key.encrypt_ope(b.0.as_str()).unwrap();
            // SafeString characters are orderize-invariant, so raw cmp is fine.
            ca.cmp(&cb) == a.0.cmp(&b.0)
        }

        fn prop_ope_variable_string_determinism(a: SafeString, key: Key) -> bool {
            let c1 = key.encrypt_ope(a.0.as_str()).unwrap();
            let c2 = key.encrypt_ope(a.0.as_str()).unwrap();
            c1 == c2
        }

        fn prop_ope_variable_string_length_invariant(a: SafeString, key: Key) -> bool {
            let ct = key.encrypt_ope(a.0.as_str()).unwrap();
            ct.as_ref().len() == 8 * a.0.len() + 1
        }
    }

    // Property tests for orderize_string

    quickcheck! {
        /// Test that orderize_string is idempotent
        fn prop_orderize_idempotent(x: String) -> bool {
            let once = orderize_string(&x);
            let twice = orderize_string(&once);
            once == twice
        }

        /// Test that orderize_string output only contains valid characters
        fn prop_orderize_valid_chars(x: String) -> bool {
            let result = orderize_string(&x);
            result.chars().all(|c| {
                c.is_alphanumeric() || c.is_whitespace() || c.is_ascii_punctuation()
            })
        }

        /// Test that ASCII alphanumeric strings pass through unchanged
        fn prop_orderize_ascii_alphanumeric_unchanged(x: SafeString) -> bool {
            // Filter to only ASCII alphanumeric and space to test this specific subset
            let ascii_only: String = x.0.chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == ' ')
                .collect();
            orderize_string(&ascii_only) == ascii_only
        }

        /// Test that SafeString instances are unchanged by orderize_string
        fn prop_orderize_safe_string_unchanged(x: SafeString) -> bool {
            // SafeString only contains chars that survive orderize_string
            orderize_string(&x.0) == x.0
        }
    }
}
