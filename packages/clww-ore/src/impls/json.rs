//! OPE encryption for `serde_json::Value`, gated behind the `serde_json`
//! feature.
//!
//! A JSON value is canonicalised to a byte string carrying a one-byte
//! **variant tag** prefix — distinct per [`Value`] variant — followed by an
//! order-preserving encoding of the payload, then fed through the shared
//! [`super::encrypt_ope_bits`] primitive to produce a variable-length
//! [`OpeCllw8VariableV1`] ciphertext.
//!
//! The tag bytes are assigned in ascending order, so under lexicographic byte
//! comparison ciphertexts of different JSON types fall into disjoint, totally
//! ordered ranges:
//!
//! ```text
//! Null  <  Bool  <  Number  <  String
//! ```
//!
//! Within a variant the encoding preserves the natural order:
//!
//! - `Bool` — `false` before `true`
//! - `Number` — numeric order; every JSON number is projected to `f64` and
//!   encoded with [`orderable_bytes`]' canonical 8-byte `f64` encoding (the
//!   standard monotonic float→int mapping, with `-0.0` canonicalised to
//!   `+0.0`). The `f64` projection is lossy above 2⁵³ — distinct large
//!   integers, and integer vs float spellings of the same value, may collide
//!   — which is acceptable, and arguably desirable, for an OPE projection.
//! - `String` — the `orderize_string` collation used by the `&str` OPE impl,
//!   so JSON strings sort consistently with bare strings.
//!
//! **Objects and arrays are not supported.** Encrypting a `Value::Object` or
//! `Value::Array` returns [`Error`]; there is no single total order over
//! composite JSON values that a flat OPE ciphertext could express.
//!
//! **Encrypt-only**, like every OPE path — see [`OpeCllw8VariableV1`].

use crate::biterator::Biterator;
use crate::impls::encrypt_ope_bits;
use crate::impls::string::orderize_string;
use crate::impls::variable::OpeCllw8VariableV1;
use crate::{CllwOpeEncrypt, Error, Key};
use orderable_bytes::ToOrderableBytes;
use serde_json::Value;

/// One-byte variant tags prefixed onto the canonical byte form. Assigned in
/// ascending order so that, under lexicographic byte comparison, ciphertexts
/// group and sort by JSON type: `Null < Bool < Number < String`.
const TAG_NULL: u8 = 0x00;
const TAG_BOOL: u8 = 0x01;
const TAG_NUMBER: u8 = 0x02;
const TAG_STRING: u8 = 0x03;

/// Canonicalises a scalar JSON value to its tagged, order-preserving byte
/// form. Returns [`Error`] for `Value::Array` and `Value::Object`, which have
/// no supported encoding.
fn encode(value: &Value) -> Result<Vec<u8>, Error> {
    match value {
        Value::Null => Ok(vec![TAG_NULL]),
        Value::Bool(b) => Ok(vec![TAG_BOOL, *b as u8]),
        Value::Number(n) => {
            // `as_f64` only returns `None` under the `arbitrary_precision`
            // feature for values that don't fit a float; treat that as an
            // unsupported value rather than panicking. JSON numbers are
            // always finite, so the canonical `f64` encoding is well-behaved.
            let encoded = n.as_f64().ok_or(Error)?.to_orderable_bytes();
            let mut out = Vec::with_capacity(1 + <f64 as ToOrderableBytes>::ENCODED_LEN);
            out.push(TAG_NUMBER);
            out.extend_from_slice(encoded.as_ref());
            Ok(out)
        }
        Value::String(s) => {
            let normalized = orderize_string(s);
            let mut out = Vec::with_capacity(1 + normalized.len());
            out.push(TAG_STRING);
            out.extend_from_slice(normalized.as_bytes());
            Ok(out)
        }
        Value::Array(_) | Value::Object(_) => Err(Error),
    }
}

impl CllwOpeEncrypt for &Value {
    type Output = OpeCllw8VariableV1;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let encoded = encode(self)?;
        let n = encoded.len() * 8;
        let bits = encoded.into_iter().flat_map(Biterator::new);
        let bytes = encrypt_ope_bits(bits, n, key, salt);
        Ok(OpeCllw8VariableV1::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::impls::variable::OpeCllw8VariableV1;
    use hex::FromHex;
    use serde_json::{json, Value};

    fn key() -> Key {
        Key::from([7u8; 32])
    }

    fn encrypt(v: &Value) -> OpeCllw8VariableV1 {
        key().encrypt_ope(v).unwrap()
    }

    // --- Variant prefixes are unique and ordered ---

    #[test]
    fn variant_tags_are_distinct() {
        let tags = [TAG_NULL, TAG_BOOL, TAG_NUMBER, TAG_STRING];
        let unique: std::collections::BTreeSet<u8> = tags.iter().copied().collect();
        assert_eq!(unique.len(), tags.len(), "variant tags must be unique");
    }

    #[test]
    fn encoded_form_starts_with_variant_tag() {
        assert_eq!(encode(&json!(null)).unwrap()[0], TAG_NULL);
        assert_eq!(encode(&json!(true)).unwrap()[0], TAG_BOOL);
        assert_eq!(encode(&json!(42)).unwrap()[0], TAG_NUMBER);
        assert_eq!(encode(&json!("hi")).unwrap()[0], TAG_STRING);
    }

    #[test]
    fn variants_sort_into_disjoint_ranges() {
        // One representative per variant, picked so the *payload* ordering
        // can't accidentally rescue a missing/colliding tag.
        let null = encrypt(&json!(null));
        let bool_false = encrypt(&json!(false));
        let bool_true = encrypt(&json!(true));
        let number = encrypt(&json!(-999999));
        let string = encrypt(&json!(""));
        assert!(null < bool_false);
        assert!(bool_false < bool_true);
        assert!(bool_true < number);
        assert!(number < string);
    }

    // --- Objects and arrays are unsupported ---

    #[test]
    fn arrays_and_objects_are_rejected() {
        assert!(encode(&json!([1, 2, 3])).is_err());
        assert!(encode(&json!({ "a": 1 })).is_err());
        assert!(key().encrypt_ope(&json!([])).is_err());
        assert!(key().encrypt_ope(&json!({})).is_err());
        // Nested composites are rejected at the top level too.
        assert!(key().encrypt_ope(&json!({ "k": [1, { "n": 2 }] })).is_err());
    }

    // --- Within-variant ordering ---

    #[test]
    fn bool_false_below_true() {
        assert!(encrypt(&json!(false)) < encrypt(&json!(true)));
    }

    #[test]
    fn numbers_sort_numerically_across_representations() {
        // serde_json stores these as NegInt / PosInt / Float respectively;
        // the f64 projection must still order them numerically.
        let ascending = [
            json!(-1_000_000_000_000i64),
            json!(-1.5),
            json!(-1),
            json!(0),
            json!(0.5),
            json!(1),
            json!(1.5),
            json!(1_000_000u64),
            json!(1e12),
        ];
        let cts: Vec<_> = ascending.iter().map(encrypt).collect();
        for window in cts.windows(2) {
            assert!(window[0] < window[1], "JSON numbers not strictly ordered");
        }
    }

    #[test]
    fn zero_spellings_collide_in_ciphertext() {
        // Integer `0`, float `0.0`, and `-0.0` all project to the same
        // canonical `f64` encoding, so their ciphertexts are byte-equal.
        let zero_int = encrypt(&json!(0));
        let zero_float = encrypt(&json!(0.0));
        let neg_zero = encrypt(&json!(-0.0));
        assert_eq!(zero_int, zero_float);
        assert_eq!(zero_float, neg_zero);
    }

    #[test]
    fn integer_and_float_spellings_of_a_value_collide() {
        assert_eq!(encrypt(&json!(1)), encrypt(&json!(1.0)));
        assert_eq!(encrypt(&json!(-42)), encrypt(&json!(-42.0)));
    }

    #[test]
    fn strings_sort_lexicographically() {
        assert!(encrypt(&json!("alice")) < encrypt(&json!("bob")));
        assert!(encrypt(&json!("")) < encrypt(&json!("a")));
        assert!(encrypt(&json!("abc")) < encrypt(&json!("abcd")));
    }

    #[test]
    fn string_collation_matches_bare_str() {
        // A JSON string encrypts to the same ciphertext as the bare `&str`
        // with the `TAG_STRING` byte prepended, i.e. JSON strings and bare
        // strings share the `orderize_string` collation.
        let key = key();
        let json_ct = key.encrypt_ope(&json!("Héllo, World!")).unwrap();
        let mut tagged = vec![TAG_STRING];
        tagged.extend_from_slice(orderize_string("Héllo, World!").as_bytes());
        let bare_ct = key.encrypt_ope(tagged.as_slice()).unwrap();
        assert_eq!(json_ct.as_ref(), bare_ct.as_ref());
    }

    // --- Determinism, length, serialisation, salt ---

    #[test]
    fn determinism() {
        for v in [json!(null), json!(true), json!(12.5), json!("xyz")] {
            assert_eq!(encrypt(&v), encrypt(&v));
        }
    }

    #[test]
    fn ciphertext_length_tracks_encoded_form() {
        for v in [json!(null), json!(false), json!(123456789), json!("hello")] {
            let encoded_len = encode(&v).unwrap().len();
            assert_eq!(encrypt(&v).as_ref().len(), 8 * encoded_len + 1);
        }
    }

    #[test]
    fn hex_round_trip() {
        let ct = encrypt(&json!("round-trip me"));
        let parsed = OpeCllw8VariableV1::from_hex(hex::encode(ct.as_ref())).unwrap();
        assert_eq!(ct, parsed);
    }

    #[test]
    fn distinct_salts_produce_distinct_ciphertexts() {
        let key = key();
        let v = json!(42);
        let a = (&v).encrypt_ope_with_salt(&key, Some(b"domain-a")).unwrap();
        let b = (&v).encrypt_ope_with_salt(&key, Some(b"domain-b")).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn salt_preserves_ordering() {
        let key = key();
        let salt = b"some-domain";
        let a = (&json!(1)).encrypt_ope_with_salt(&key, Some(salt)).unwrap();
        let b = (&json!(2)).encrypt_ope_with_salt(&key, Some(salt)).unwrap();
        assert!(a < b);
    }

    #[test]
    fn no_salt_matches_none_salt() {
        let key = key();
        let v = json!("hello");
        assert_eq!(
            (&v).encrypt_ope(&key).unwrap(),
            (&v).encrypt_ope_with_salt(&key, None).unwrap()
        );
    }
}
