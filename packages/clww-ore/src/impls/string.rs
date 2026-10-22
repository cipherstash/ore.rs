//! `ClwwOreEncrypt` / `ClwwOpeEncrypt` impls for `&str` and `&[u8]` plus
//! the `orderize_string` collation step.
//!
//! The variable-length ciphertext types ([`OreClww8VariableV1`] /
//! [`OpeClww8VariableV1`]) and their construction machinery
//! live in [`super::variable`].

use crate::biterator::{string_biter, Biterator};
use crate::impls::encrypt_ope_bits;
use crate::impls::variable::{OpeClww8VariableV1, OreClww8VariableV1};
use crate::{ClwwOpeEncrypt, ClwwOreEncrypt, Error, Key};
use unicode_normalization::char::decompose_canonical;
use zeroize::Zeroizing;

/// Encrypts a bit stream into a CLWW ORE ciphertext.
///
/// `bits` is an iterator of one byte per plaintext bit, each `0` or `1`. The
/// CLWW keystream is derived from `key` (optionally domain-separated by `salt`)
/// and each ciphertext byte is `(PRF_i + bit_i) mod 256`. The output length is
/// the number of plaintext bits — one byte per bit — and bytes compare under
/// clww-ore's ORE comparison (first-differing-byte `y + 1 == x`), **not** plain
/// lex order. See [`OreClww8VariableV1`].
///
/// # Errors
///
/// [`Error`](struct@crate::Error) if any byte of `bits` is not `0` or `1`: the comparison reads a
/// difference of exactly one as the order, so any other byte gives terms that
/// sort wrong. The whole stream is read first, so the error does not tell
/// where the bad byte was.
pub fn encrypt_ore_bits<I>(bits: I, key: &Key, salt: Option<&[u8]>) -> Result<Vec<u8>, Error>
where
    I: IntoIterator<Item = u8>,
{
    let mut hasher = crate::impls::keyed_hasher(key, crate::impls::Scheme::Ore, salt);
    let mut invalid = 0u8;
    let out = bits.into_iter().fold(Vec::new(), |mut out, bit| {
        invalid |= bit >> 1;
        out.push(crate::impls::prf_byte(&hasher).wrapping_add(bit));
        let _ = hasher.update(&[bit]);
        out
    });
    if invalid != 0 {
        return Err(Error);
    }
    Ok(out)
}

impl ClwwOreEncrypt for &[u8] {
    type Output = OreClww8VariableV1;

    fn encrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let bits = self.iter().flat_map(|&byte| Biterator::new(byte));
        Ok(OreClww8VariableV1::from_bytes_unchecked(encrypt_ore_bits(
            bits, key, salt,
        )?))
    }
}

impl ClwwOreEncrypt for &str {
    type Output = OreClww8VariableV1;

    fn encrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let string = orderize_secret(self);
        Ok(OreClww8VariableV1::from_bytes_unchecked(encrypt_ore_bits(
            string_biter(&string),
            key,
            salt,
        )?))
    }
}

impl ClwwOpeEncrypt for &str {
    type Output = OpeClww8VariableV1;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let normalized = orderize_secret(self);
        let bytes = encrypt_ope_bits(string_biter(&normalized), key, salt)?;
        Ok(OpeClww8VariableV1::from_bytes_unchecked(bytes))
    }
}

impl ClwwOpeEncrypt for &[u8] {
    type Output = OpeClww8VariableV1;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let bits = self.iter().flat_map(|&byte| Biterator::new(byte));
        let bytes = encrypt_ope_bits(bits, key, salt)?;
        Ok(OpeClww8VariableV1::from_bytes_unchecked(bytes))
    }
}

/// Owned counterpart of the `&str` impl: an owned value can outlive the call
/// that hands it to an encryptor (e.g. a visitor that must be `'static`),
/// where a borrow cannot. Produces byte-identical ciphertext to `&str`.
///
/// The operand is taken into a [`Zeroizing`] for the duration of the call, so
/// an owned plaintext is wiped when this returns rather than handed back to
/// the allocator intact. A caller who owns the plaintext already should
/// prefer the `Zeroizing<String>` impl and keep it wrapped throughout.
impl ClwwOreEncrypt for String {
    type Output = OreClww8VariableV1;

    fn encrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        Zeroizing::new(self).encrypt_with_salt(key, salt)
    }
}

/// Owned counterpart of the `&[u8]` impl; byte-identical ciphertext. Wipes
/// its operand, as the `String` impl does.
impl ClwwOreEncrypt for Vec<u8> {
    type Output = OreClww8VariableV1;

    fn encrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        Zeroizing::new(self).encrypt_with_salt(key, salt)
    }
}

/// Owned counterpart of the `&str` impl; byte-identical ciphertext. Wipes its
/// operand, as the ORE `String` impl does.
impl ClwwOpeEncrypt for String {
    type Output = OpeClww8VariableV1;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        Zeroizing::new(self).encrypt_ope_with_salt(key, salt)
    }
}

/// Owned counterpart of the `&[u8]` impl; byte-identical ciphertext. Wipes
/// its operand, as the ORE `Vec<u8>` impl does.
impl ClwwOpeEncrypt for Vec<u8> {
    type Output = OpeClww8VariableV1;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        Zeroizing::new(self).encrypt_ope_with_salt(key, salt)
    }
}

/// The wrapped-owned impls, and the ones a caller holding a secret should
/// reach for: the operand keeps its wipe-on-drop the whole way through, so
/// nothing has to remember to wrap it at the boundary. `'static` and `Send`
/// like the bare owned impls, so they satisfy the same visitor bounds.
/// Byte-identical ciphertext to `&str` / `&[u8]`.
impl ClwwOreEncrypt for Zeroizing<String> {
    type Output = OreClww8VariableV1;

    fn encrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        self.as_str().encrypt_with_salt(key, salt)
    }
}

/// See the [`Zeroizing<String>`](ClwwOreEncrypt#impl-ClwwOreEncrypt-for-Zeroizing<String>) impl.
impl ClwwOreEncrypt for Zeroizing<Vec<u8>> {
    type Output = OreClww8VariableV1;

    fn encrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        self.as_slice().encrypt_with_salt(key, salt)
    }
}

/// See the [`Zeroizing<String>`](ClwwOreEncrypt#impl-ClwwOreEncrypt-for-Zeroizing<String>) impl.
impl ClwwOpeEncrypt for Zeroizing<String> {
    type Output = OpeClww8VariableV1;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        self.as_str().encrypt_ope_with_salt(key, salt)
    }
}

/// See the [`Zeroizing<String>`](ClwwOreEncrypt#impl-ClwwOreEncrypt-for-Zeroizing<String>) impl.
impl ClwwOpeEncrypt for Zeroizing<Vec<u8>> {
    type Output = OpeClww8VariableV1;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        self.as_slice().encrypt_ope_with_salt(key, salt)
    }
}

/// Normalizes the string use Unicode = NFKC normalization, and then removes any
/// characters that are not alphanumeric, whitespace, or ASCII punctuation.
/// This is a "rough" collation that is used to orderize strings for encryption.
///
/// Eventually, this will move to a more sophisticated collation that can handle
/// more complex strings using the [Unicode Collation Algorithm](https://www.unicode.org/reports/tr10/).
///
/// The collated form is derived from the input and is exactly as sensitive as
/// it, so a caller collating a secret should wrap the result — or call it
/// through [`Zeroizing`], as this crate's own encrypt paths do via
/// `orderize_secret`. The bare `String` return is kept for compatibility with
/// existing callers; wrapping it costs nothing (`Zeroizing::new` moves the
/// same allocation).
pub fn orderize_string(input: &str) -> String {
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

/// [`orderize_string`], with the collated form wiped when it drops.
///
/// The encrypt paths run over a plaintext operand, so the intermediate
/// collated copy must not go back to the allocator intact — in a wasm guest
/// that memory is linear memory the host can read. `Zeroizing::new` moves the
/// `String`, so this is the same allocation, not a second copy.
fn orderize_secret(input: &str) -> Zeroizing<String> {
    Zeroizing::new(orderize_string(input))
}

#[cfg(test)]
mod tests {
    use super::orderize_string;
    use crate::impls::variable::OpeClww8VariableV1;
    use crate::Key;
    use quickcheck::{quickcheck, Arbitrary, Gen};
    use std::cmp::Ordering;
    use zeroize::Zeroizing;

    /// The wrapped-owned impls exist so a caller holding a secret never has to
    /// unwrap it to encrypt. That is only true if they are interchangeable
    /// with the borrowed impls, so pin the ciphertext bytes across all three
    /// spellings — borrowed, bare owned, and `Zeroizing` — for ORE and OPE.
    #[test]
    fn every_owned_spelling_encrypts_identically_to_the_borrowed_one() {
        let key = Key::from([7; 32]);
        let text = "Ada Lovelace, 1815";
        let bytes = text.as_bytes();

        let ore_borrowed = key.encrypt(text).unwrap();
        assert_eq!(
            key.encrypt(text.to_string()).unwrap().as_ref(),
            ore_borrowed.as_ref()
        );
        assert_eq!(
            key.encrypt(Zeroizing::new(text.to_string()))
                .unwrap()
                .as_ref(),
            ore_borrowed.as_ref()
        );

        let ore_bytes_borrowed = key.encrypt(bytes).unwrap();
        assert_eq!(
            key.encrypt(bytes.to_vec()).unwrap().as_ref(),
            ore_bytes_borrowed.as_ref()
        );
        assert_eq!(
            key.encrypt(Zeroizing::new(bytes.to_vec()))
                .unwrap()
                .as_ref(),
            ore_bytes_borrowed.as_ref()
        );

        let ope_borrowed = key.encrypt_ope(text).unwrap();
        assert_eq!(
            key.encrypt_ope(text.to_string()).unwrap().as_ref(),
            ope_borrowed.as_ref()
        );
        assert_eq!(
            key.encrypt_ope(Zeroizing::new(text.to_string()))
                .unwrap()
                .as_ref(),
            ope_borrowed.as_ref()
        );

        let ope_bytes_borrowed = key.encrypt_ope(bytes).unwrap();
        assert_eq!(
            key.encrypt_ope(bytes.to_vec()).unwrap().as_ref(),
            ope_bytes_borrowed.as_ref()
        );
        assert_eq!(
            key.encrypt_ope(Zeroizing::new(bytes.to_vec()))
                .unwrap()
                .as_ref(),
            ope_bytes_borrowed.as_ref()
        );
    }

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
    fn test_encrypt_bytes_preserves_order() {
        let key = Key::from([0; 32]);
        let data1: &[u8] = b"abc";
        let data2: &[u8] = b"abd";
        let ct1 = key.encrypt(data1).unwrap();
        let ct2 = key.encrypt(data2).unwrap();
        assert_eq!(ct1.cmp(&ct2), Ordering::Less);
    }

    // Salt tests for strings

    #[test]
    fn test_string_different_salts_produce_different_ciphertexts() {
        use crate::ClwwOreEncrypt;

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
    fn test_string_no_salt_and_none_salt_are_equivalent() {
        use crate::ClwwOreEncrypt;

        let key = Key::from([0; 32]);
        let plaintext = "hello";

        let ct1 = plaintext.encrypt(&key).unwrap();
        let ct2 = plaintext.encrypt_with_salt(&key, None).unwrap();

        // No salt and None salt should produce identical ciphertexts
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_string_empty_salt_same_as_no_salt() {
        use crate::ClwwOreEncrypt;

        let key = Key::from([0; 32]);
        let plaintext = "hello";

        let ct_no_salt = plaintext.encrypt_with_salt(&key, None).unwrap();
        let ct_empty_salt = plaintext.encrypt_with_salt(&key, Some(b"")).unwrap();

        // Empty salt produces same result as no salt (empty bytes don't change hash)
        assert_eq!(ct_no_salt, ct_empty_salt);
    }

    #[test]
    fn test_string_salt_preserves_ordering() {
        use crate::ClwwOreEncrypt;

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
        use crate::ClwwOreEncrypt;

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
    fn test_bytes_no_salt_and_none_salt_are_equivalent() {
        use crate::ClwwOreEncrypt;

        let key = Key::from([0; 32]);
        let data: &[u8] = b"hello";

        let ct1 = data.encrypt(&key).unwrap();
        let ct2 = data.encrypt_with_salt(&key, None).unwrap();

        // No salt and None salt should produce identical ciphertexts
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_bytes_empty_salt_same_as_no_salt() {
        use crate::ClwwOreEncrypt;

        let key = Key::from([0; 32]);
        let data: &[u8] = b"hello";

        let ct_no_salt = data.encrypt_with_salt(&key, None).unwrap();
        let ct_empty_salt = data.encrypt_with_salt(&key, Some(b"")).unwrap();

        // Empty salt produces same result as no salt (empty bytes don't change hash)
        assert_eq!(ct_no_salt, ct_empty_salt);
    }

    #[test]
    fn test_bytes_salt_preserves_ordering() {
        use crate::ClwwOreEncrypt;

        let key = Key::from([0; 32]);
        let salt = b"domain";
        let data1: &[u8] = &[1, 2, 3];
        let data2: &[u8] = &[1, 2, 4];

        let ct1 = data1.encrypt_with_salt(&key, Some(salt)).unwrap();
        let ct2 = data2.encrypt_with_salt(&key, Some(salt)).unwrap();

        // Ordering should be preserved even with salt
        assert!(ct1 < ct2);
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

        /// Test that the ciphertext is one byte per plaintext bit
        fn prop_bytes_length(key: Key, x: Vec<u8>) -> bool {
            key.encrypt(x.as_slice()).unwrap().as_ref().len() == x.len() * 8
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
    // `OpeClww8VariableV1` rustdoc and the numeric exactness test in
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
            let ct2 = OpeClww8VariableV1::from_hex(&hex_str).unwrap();
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

    #[test]
    fn owned_string_matches_borrowed_str() {
        let key = Key::from([7; 32]);
        let borrowed = key.encrypt("hello world").unwrap();
        let owned = key.encrypt(String::from("hello world")).unwrap();
        assert_eq!(borrowed.as_ref(), owned.as_ref());

        let borrowed = key.encrypt_ope("hello world").unwrap();
        let owned = key.encrypt_ope(String::from("hello world")).unwrap();
        assert_eq!(borrowed.as_ref(), owned.as_ref());
    }

    #[test]
    fn owned_bytes_match_borrowed_slice() {
        let key = Key::from([7; 32]);
        let bytes: &[u8] = b"\x00\xff\x10";
        let borrowed = key.encrypt(bytes).unwrap();
        let owned = key.encrypt(bytes.to_vec()).unwrap();
        assert_eq!(borrowed.as_ref(), owned.as_ref());

        let borrowed = key.encrypt_ope(bytes).unwrap();
        let owned = key.encrypt_ope(bytes.to_vec()).unwrap();
        assert_eq!(borrowed.as_ref(), owned.as_ref());
    }
}
