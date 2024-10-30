use crate::{biterator::string_biter, CllwOreEncrypt, Error, Key};
use postgres_types::ToSql;
use std::cmp::Ordering;
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

impl From<Vec<u8>> for OreCllw8VariableV1 {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
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
        // TODO: Use ct_eq
        self.bytes == other.bytes
    }
}

impl Eq for OreCllw8VariableV1 {}

/// Compare two outputs lexicographically.
/// This is useful for strings where the length of the output is not necessarily the same.
/// A shorter string is considered less than a longer string if it is a prefix of the longer string.
fn compare_lex(a: &OreCllw8VariableV1, b: &OreCllw8VariableV1) -> Ordering {
    if a.bytes.is_empty() && b.bytes.is_empty() {
        return Ordering::Equal;
    }
    if a.bytes.is_empty() {
        return Ordering::Less;
    }
    if b.bytes.is_empty() {
        return Ordering::Greater;
    }
    let slice_len = a.bytes.len().min(b.bytes.len());
    match super::compare_slice(&a.bytes[..slice_len], &b.bytes[..slice_len]) {
        Ordering::Less => Ordering::Less,
        Ordering::Greater => Ordering::Greater,
        // Shorter strings are less than longer strings (i.e. they sort first)
        Ordering::Equal => a.bytes.len().cmp(&b.bytes.len()),
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
}
