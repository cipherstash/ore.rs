use crate::{biterator::{string_biter, Biterator}, CllwOreDecrypt, CllwOreEncrypt, Error, Key};
use hex::{FromHex, FromHexError};
use postgres_types::ToSql;
use std::cmp::Ordering;
use subtle::ConstantTimeEq;
use unicode_normalization::char::decompose_canonical;

#[derive(Debug, ToSql)]
#[postgres(name = "ore_cllw_8_variable_v1")]
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
        let mut hasher = blake3::Hasher::new_keyed(&key.0);
        if let Some(salt) = salt {
            hasher.update(salt);
        }

        let mut result_bytes = Vec::with_capacity(self.bytes.len() / 8);
        let mut current_byte: u8 = 0;

        for (i, &ciphertext_byte) in self.bytes.iter().enumerate() {
            let mut buf: [u8; 16] = [0; 16];
            hasher.finalize_xof().fill(&mut buf);
            let prf_block = u128::from_be_bytes(buf) & 0xFF;
            // Recover the bit by subtracting ciphertext from PRF block
            let bit = ciphertext_byte.wrapping_sub(prf_block as u8) & 0x01;
            hasher.update(&[bit]);
            
            // Build up the byte MSB-first (8 bits per byte)
            // Use constant-time operation to avoid timing side-channel
            let bit_position = i % 8;
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
        String::from_utf8(result_bytes).map_err(|_| Error::InvalidLength {
            expected: 0,
            actual: 0,
        })
    }
}

impl CllwOreEncrypt for &[u8] {
    type Output = OreCllw8VariableV1;

    fn encrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let len = self.len() * u8::BITS as usize;
        let mut hasher = blake3::Hasher::new_keyed(&key.0);
        if let Some(salt) = salt {
            hasher.update(salt);
        }
        
        // Process each byte through the Biterator (MSB first)
        let bytes = self.iter()
            .flat_map(|&byte| Biterator::new(byte))
            .fold(Vec::with_capacity(len), |mut out, bit| {
                let mut buf: [u8; 16] = [0; 16];
                hasher.finalize_xof().fill(&mut buf);
                let byte = u128::from_be_bytes(buf).wrapping_add(bit as u128) & 0xFF;
                hasher.update(&[bit]);
                out.push(byte as u8);
                out
            });

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
            hasher.update(salt);
        }
        let bytes = string_biter(&string).fold(Vec::with_capacity(len), |mut out, bit| {
            let mut buf: [u8; 16] = [0; 16];
            hasher.finalize_xof().fill(&mut buf);
            let byte = u128::from_be_bytes(buf).wrapping_add(bit as u128) & 0xFF;
            hasher.update(&[bit]);
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
    use crate::Key;
    use std::cmp::Ordering;

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
}
