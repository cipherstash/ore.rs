//! `CllwOreEncrypt` / `CllwOpeEncrypt` impls for `&str` and `&[u8]` plus
//! the `orderize_string` collation step.
//!
//! The variable-length ciphertext types ([`OreCllw8VariableV1`] /
//! [`OpeCllw8VariableV1`]) and their construction/decryption machinery
//! live in [`super::variable`].

use crate::biterator::{string_biter, Biterator};
use crate::impls::encrypt_ope_bits;
use crate::impls::variable::{OpeCllw8VariableV1, OreCllw8VariableV1};
use crate::{CllwOpeEncrypt, CllwOreEncrypt, Error, Key};
use unicode_normalization::char::decompose_canonical;

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

        Ok(OreCllw8VariableV1::from(bytes))
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

        Ok(OreCllw8VariableV1::from(bytes))
    }
}

impl CllwOpeEncrypt for &str {
    type Output = OpeCllw8VariableV1;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let normalized = orderize_string(self);
        let n = normalized.len() * 8;
        let bytes = encrypt_ope_bits(string_biter(&normalized), n, key, salt);
        Ok(OpeCllw8VariableV1::from_bytes(bytes))
    }
}

impl CllwOpeEncrypt for &[u8] {
    type Output = OpeCllw8VariableV1;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let n = self.len() * 8;
        let bits = self.iter().flat_map(|&byte| Biterator::new(byte));
        let bytes = encrypt_ope_bits(bits, n, key, salt);
        Ok(OpeCllw8VariableV1::from_bytes(bytes))
    }
}

/// Normalizes the string use Unicode = NFKC normalization, and then removes any
/// characters that are not alphanumeric, whitespace, or ASCII punctuation.
/// This is a "rough" collation that is used to orderize strings for encryption.
///
/// Eventually, this will move to a more sophisticated collation that can handle
/// more complex strings using the [Unicode Collation Algorithm](https://www.unicode.org/reports/tr10/).
pub(crate) fn orderize_string(input: &str) -> String {
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
    use super::orderize_string;
    use crate::impls::variable::{OpeCllw8VariableV1, OreCllw8VariableV1};
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

    // --- Variable-length OPE property tests ---
    //
    // The MSB-bit backward-carry encoding gives exact ordering (see
    // `OpeCllw8VariableV1` rustdoc and the numeric exactness test in
    // `impls/num.rs`); the property tests below exercise that guarantee on
    // random `Vec<u8>` and `SafeString` inputs.

    quickcheck! {
        /// Regression for the original naive-OPE wrap-around bug: under the
        /// paper's byte-compare reading of CLWW, ~1/256 of keys would report
        /// `ct([0x00]) > ct([0x01])` because `PRF_7 = 0xFF` made the wrapped
        /// byte `0x00` compare less than its peer's `0xFF`. With MSB-bit
        /// placement plus backward carry the scheme is exact for every key
        /// and every pair; this test just pins the single-bit case as the
        /// canonical sanity check.
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

        fn prop_ope_variable_hex_round_trip(a: Vec<u8>, key: Key) -> bool {
            use hex::FromHex;
            let ct = key.encrypt_ope(a.as_slice()).unwrap();
            let hex_str = hex::encode(ct.as_ref());
            let ct2 = OpeCllw8VariableV1::from_hex(&hex_str).unwrap();
            ct == ct2
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
