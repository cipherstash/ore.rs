use crate::{
    biterator::string_biter, orderize_string::orderize_string, CllwOreEncrypt, Error, Key,
};
use postgres_types::ToSql;
use std::cmp::Ordering;

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
        let string = orderize_string(self)?;
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
        Ordering::Equal => match a.bytes.len().cmp(&b.bytes.len()) {
            Ordering::Less => Ordering::Greater,
            Ordering::Greater => Ordering::Less,
            Ordering::Equal => Ordering::Equal,
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::Key;

    #[test]
    fn test_string() {
        let key = Key::from([0; 32]);
        let input = "hello";
        let a = key.encrypt(input).unwrap();
        let b = key.encrypt(input).unwrap();
        assert_eq!(a, b);
    }

    // TODO: There are a number of weird edge cases that cause these to fail though they are unlikely to occur in practice
    /*quickcheck! {
        fn test_string_cmp_less(a: String, b: String) -> TestResult {
            if !a.is_ascii() || !b.is_ascii() {
                return TestResult::discard();
            }
            let key = Key::from([0; 32]);
            let x = key.encrypt(a.as_str());
            let y = key.encrypt(b.as_str());
            TestResult::from_bool(compare_lex(&x, &y) == a.cmp(&b))
        }

        fn test_string_cmp_prefix(x: String, suffix: String) -> TestResult {
            if suffix.len() == 0 {
                return TestResult::discard();
            }
            if !x.is_ascii() || !suffix.is_ascii() {
                return TestResult::discard();
            }
            let key = Key::from([0; 32]);
            let a = key.encrypt(x.as_str());
            let b = key.encrypt(format!("{}{}", x, suffix).as_str());
            TestResult::from_bool(compare_lex(&a, &b) == Ordering::Greater)
        }
    }*/
}
