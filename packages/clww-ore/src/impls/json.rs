//! OPE encryption for `serde_json::Value`, gated behind the `serde_json`
//! feature.
//!
//! A JSON value — including nested arrays and objects — is canonicalised to a
//! *bit* string, then fed bit-by-bit through the shared
//! [`super::encrypt_ope_bits`] primitive to produce a variable-length
//! [`OpeCllw8VariableV1`] ciphertext. Standard lexicographic byte comparison
//! of the ciphertexts then reproduces a total order over all JSON values.
//!
//! # The encoding
//!
//! Every value begins with a 3-bit **type tag**, assigned in ascending order
//! so that ciphertexts of different JSON types fall into disjoint, totally
//! ordered ranges:
//!
//! ```text
//! Null  <  Bool  <  Number  <  String  <  Array  <  Object
//! ```
//!
//! Within a type the encoding preserves the natural order:
//!
//! - `Null` — nothing follows the tag.
//! - `Bool` — one bit: `false` (0) before `true` (1).
//! - `Number` — numeric order; every JSON number is projected to `f64` and
//!   encoded with [`orderable_bytes`]' canonical 8-byte `f64` encoding (the
//!   standard monotonic float→int mapping, with `-0.0` canonicalised to
//!   `+0.0`). The `f64` projection is lossy above 2⁵³ — distinct large
//!   integers, and integer vs float spellings of the same value, may collide
//!   — which is acceptable, and arguably desirable, for an OPE projection.
//! - `String` — the `orderize_string` collation (shared with the `&str` OPE
//!   impl, so JSON strings sort consistently with bare strings), followed by
//!   a single `0x00` terminator byte. The collation never emits `0x00`, so
//!   the byte unambiguously marks end-of-string, and because `0x00` sorts
//!   below every other byte it also keeps the prefix order correct
//!   (`"" < "a" < "ab"`).
//! - `Array` — each element is prefixed with a `1` bit and its own recursive
//!   encoding; a trailing `0` bit ends the list. Arrays therefore compare
//!   element-by-element, a shorter array that is a prefix of a longer one
//!   sorting first: `[] < [1] < [1, 1] < [1, 2] < [2]`.
//! - `Object` — entries are sorted by key; each entry is a `1` bit, the key
//!   (encoded as a `String`), then the value's recursive encoding; a trailing
//!   `0` bit ends the map. Input key order is irrelevant — `{"a":1,"b":2}`
//!   and `{"b":2,"a":1}` encode identically — and objects compare by their
//!   sorted `(key, value)` sequence.
//!
//! The framing (`0x00` string terminators, `1`/`0` element markers) makes the
//! encoding prefix-free, hence injective *up to collation*: distinct JSON
//! values map to distinct ciphertexts except where `orderize_string` folds
//! distinct strings — or distinct object keys — together, the same lossiness
//! the `String` case already documents. Without that framing, `[[1], 2]` and
//! `[[1, 2]]` would flatten to the same bit stream.
//!
//! Encryption fails only for a `Number` that does not fit an `f64`, which is
//! reachable solely under `serde_json`'s `arbitrary_precision` feature.
//!
//! **Encrypt-only**, like every OPE path — see [`OpeCllw8VariableV1`].

use crate::impls::encrypt_ope_bits;
use crate::impls::string::orderize_string;
use crate::impls::variable::OpeCllw8VariableV1;
use crate::{CllwOpeEncrypt, Error, Key};
use orderable_bytes::ToOrderableBytes;
use serde_json::Value;

/// Width, in bits, of the type tag prefixed onto every encoded value.
const TAG_BITS: u32 = 3;

/// Type tags, assigned in ascending order so that — once expanded into the
/// OPE bit stream and compared lexicographically — ciphertexts group and sort
/// by JSON type: `Null < Bool < Number < String < Array < Object`.
const TAG_NULL: u8 = 0b000;
const TAG_BOOL: u8 = 0b001;
const TAG_NUMBER: u8 = 0b010;
const TAG_STRING: u8 = 0b011;
const TAG_ARRAY: u8 = 0b100;
const TAG_OBJECT: u8 = 0b101;

/// Appends the low `width` bits of `value`, most-significant first, to `bits`
/// (one entry per bit, each `0` or `1`).
fn push_bits(bits: &mut Vec<u8>, value: u8, width: u32) {
    for shift in (0..width).rev() {
        bits.push((value >> shift) & 1);
    }
}

/// Appends the order-preserving encoding of a JSON string to `bits`: the
/// [`TAG_STRING`] tag, the `orderize_string` collation of `s`, then a `0x00`
/// terminator byte. `orderize_string` never emits `0x00`, so the terminator
/// is unambiguous, and — because `0x00` sorts below every content byte — it
/// also keeps the prefix order correct. Object keys reuse this, so they
/// collate exactly like JSON string values.
fn encode_string(s: &str, bits: &mut Vec<u8>) {
    push_bits(bits, TAG_STRING, TAG_BITS);
    for &byte in orderize_string(s).as_bytes() {
        push_bits(bits, byte, u8::BITS);
    }
    push_bits(bits, 0x00, u8::BITS);
}

/// Appends the tagged, order-preserving bit encoding of `value` to `bits`,
/// recursing into arrays and objects. Returns [`Error`] only for a `Number`
/// that does not fit an `f64` (reachable solely under `serde_json`'s
/// `arbitrary_precision` feature).
fn encode_into(value: &Value, bits: &mut Vec<u8>) -> Result<(), Error> {
    match value {
        Value::Null => push_bits(bits, TAG_NULL, TAG_BITS),
        Value::Bool(b) => {
            push_bits(bits, TAG_BOOL, TAG_BITS);
            // A bool is a single bit: `false` (0) sorts before `true` (1).
            bits.push(*b as u8);
        }
        Value::Number(n) => {
            push_bits(bits, TAG_NUMBER, TAG_BITS);
            // `as_f64` only returns `None` under the `arbitrary_precision`
            // feature for values that don't fit a float; treat that as an
            // unsupported value rather than panicking. JSON numbers are
            // always finite, so the canonical `f64` encoding is well-behaved.
            let encoded = n.as_f64().ok_or(Error)?.to_orderable_bytes();
            for &byte in encoded.as_ref() {
                push_bits(bits, byte, u8::BITS);
            }
        }
        Value::String(s) => encode_string(s, bits),
        Value::Array(elements) => {
            push_bits(bits, TAG_ARRAY, TAG_BITS);
            for element in elements {
                bits.push(1); // another element follows
                encode_into(element, bits)?;
            }
            bits.push(0); // end of array
        }
        Value::Object(map) => {
            push_bits(bits, TAG_OBJECT, TAG_BITS);
            // Sort by key so semantically equal objects — which may differ in
            // input key order, or in `serde_json::Map`'s iteration order
            // depending on the `preserve_order` feature — encode identically.
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
            for (key, val) in entries {
                bits.push(1); // another entry follows
                encode_string(key, bits);
                encode_into(val, bits)?;
            }
            bits.push(0); // end of object
        }
    }
    Ok(())
}

/// Canonicalises a JSON value to its tagged, order-preserving bit form, MSB
/// first, one entry per bit. See the module-level docs for the layout.
fn encode(value: &Value) -> Result<Vec<u8>, Error> {
    let mut bits = Vec::new();
    encode_into(value, &mut bits)?;
    Ok(bits)
}

impl CllwOpeEncrypt for &Value {
    type Output = OpeCllw8VariableV1;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let bits = encode(self)?;
        let n = bits.len();
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

    /// Reads the leading [`TAG_BITS`]-bit type tag off an encoded bit form.
    fn leading_tag(v: &Value) -> u8 {
        encode(v).unwrap()[..TAG_BITS as usize]
            .iter()
            .fold(0u8, |acc, &bit| (acc << 1) | bit)
    }

    /// Asserts every adjacent pair of values yields a strictly increasing
    /// pair of ciphertexts.
    fn assert_strictly_increasing(values: &[Value]) {
        let cts: Vec<_> = values.iter().map(encrypt).collect();
        for (i, (lo, hi)) in cts.iter().zip(cts.iter().skip(1)).enumerate() {
            assert!(
                lo < hi,
                "ciphertexts not strictly increasing at index {i}: {:?} vs {:?}",
                values[i],
                values[i + 1]
            );
        }
    }

    // --- Type tags ---

    #[test]
    fn type_tags_are_distinct() {
        let tags = [
            TAG_NULL, TAG_BOOL, TAG_NUMBER, TAG_STRING, TAG_ARRAY, TAG_OBJECT,
        ];
        let unique: std::collections::BTreeSet<u8> = tags.iter().copied().collect();
        assert_eq!(unique.len(), tags.len(), "type tags must be unique");
    }

    #[test]
    fn encoded_form_starts_with_type_tag() {
        assert_eq!(leading_tag(&json!(null)), TAG_NULL);
        assert_eq!(leading_tag(&json!(true)), TAG_BOOL);
        assert_eq!(leading_tag(&json!(42)), TAG_NUMBER);
        assert_eq!(leading_tag(&json!("hi")), TAG_STRING);
        assert_eq!(leading_tag(&json!([])), TAG_ARRAY);
        assert_eq!(leading_tag(&json!({})), TAG_OBJECT);
    }

    #[test]
    fn types_sort_into_disjoint_ranges() {
        // One representative per type; scalars are picked so payload ordering
        // can't accidentally rescue a missing/colliding tag, composites are
        // empty so they carry essentially no payload at all.
        assert_strictly_increasing(&[
            json!(null),
            json!(false),
            json!(true),
            json!(-999_999),
            json!(""),
            json!([]),
            json!({}),
        ]);
        // The type tag dominates regardless of how "heavy" the payloads are.
        assert!(encrypt(&json!(true)) < encrypt(&json!(-1e300)));
        assert!(encrypt(&json!(1e300)) < encrypt(&json!("")));
        assert!(encrypt(&json!("zzzzzzzz")) < encrypt(&json!([])));
        assert!(encrypt(&json!([null, null, null])) < encrypt(&json!({})));
    }

    // --- Bool / Number / String (within-type ordering) ---

    #[test]
    fn bool_false_below_true() {
        assert!(encrypt(&json!(false)) < encrypt(&json!(true)));
    }

    #[test]
    fn numbers_sort_numerically_across_representations() {
        // serde_json stores these as NegInt / PosInt / Float respectively;
        // the f64 projection must still order them numerically.
        assert_strictly_increasing(&[
            json!(-1_000_000_000_000i64),
            json!(-1.5),
            json!(-1),
            json!(0),
            json!(0.5),
            json!(1),
            json!(1.5),
            json!(1_000_000u64),
            json!(1e12),
        ]);
    }

    #[test]
    fn zero_spellings_collide_in_ciphertext() {
        // Integer `0`, float `0.0`, and `-0.0` all project to the same
        // canonical `f64` encoding, so their ciphertexts are byte-equal.
        assert_eq!(encrypt(&json!(0)), encrypt(&json!(0.0)));
        assert_eq!(encrypt(&json!(0.0)), encrypt(&json!(-0.0)));
    }

    #[test]
    fn integer_and_float_spellings_of_a_value_collide() {
        assert_eq!(encrypt(&json!(1)), encrypt(&json!(1.0)));
        assert_eq!(encrypt(&json!(-42)), encrypt(&json!(-42.0)));
    }

    #[test]
    fn strings_sort_lexicographically() {
        assert_strictly_increasing(&[
            json!(""),
            json!("a"),
            json!("abc"),
            json!("abcd"),
            json!("alice"),
            json!("bob"),
        ]);
    }

    #[test]
    fn json_strings_use_orderize_string_collation() {
        // JSON strings run the same `orderize_string` collation as the bare
        // `&str` OPE impl: here `é` canonically decomposes to `e` plus a
        // combining accent that the collation drops, so both spellings
        // collate to the same normalized form and encrypt to byte-equal
        // ciphertexts.
        assert_eq!(
            encrypt(&json!("Héllo, World!")),
            encrypt(&json!("Hello, World!"))
        );
    }

    // --- Arrays ---

    #[test]
    fn arrays_compare_element_by_element() {
        // Lexicographic over elements, with a prefix sorting before its
        // extensions; element type tags settle cross-type comparisons within
        // a slot.
        assert_strictly_increasing(&[
            json!([]),
            json!([null]),
            json!([false]),
            json!([1]),
            json!([1, 1]),
            json!([1, 2]),
            json!([2]),
            json!([2, 0]),
            json!(["a"]),
            json!(["a", 0]),
            json!(["b"]),
            json!([[1]]),
            json!([[1], 0]),
            json!([[2]]),
        ]);
    }

    #[test]
    fn nested_array_grouping_does_not_collide() {
        // `[[1], 2]` and `[[1, 2]]` would flatten to the same bit stream
        // without element framing; the `1`/`0` markers keep them distinct and
        // correctly ordered (`[1]` is a prefix of `[1, 2]`, so the first
        // element of `[[1], 2]` sorts below that of `[[1, 2]]`).
        let grouped_outer = encrypt(&json!([[1], 2]));
        let grouped_inner = encrypt(&json!([[1, 2]]));
        assert_ne!(grouped_outer, grouped_inner);
        assert!(grouped_outer < grouped_inner);
    }

    // --- Objects ---

    #[test]
    fn objects_ignore_input_key_order() {
        assert_eq!(
            encrypt(&json!({ "a": 1, "b": 2 })),
            encrypt(&json!({ "b": 2, "a": 1 }))
        );
        // ...recursively, too.
        assert_eq!(
            encrypt(&json!({ "outer": { "x": 1, "y": 2 }, "z": 3 })),
            encrypt(&json!({ "z": 3, "outer": { "y": 2, "x": 1 } }))
        );
    }

    #[test]
    fn objects_compare_by_sorted_entries() {
        // After key-sorting, objects compare entry-by-entry; a prefix sorts
        // before its extensions, and within an entry the key comparison
        // dominates the value.
        assert_strictly_increasing(&[
            json!({}),
            json!({ "a": 1 }),
            json!({ "a": 2 }),
            json!({ "a": 2, "b": 0 }),
            // Same as `{"a":9,"b":0}` after sorting — beats the previous row
            // on entry 0's value (`9 > 2`).
            json!({ "b": 0, "a": 9 }),
            // No "a" entry, so the first entry's key "b" wins.
            json!({ "b": 0 }),
        ]);
    }

    // --- Determinism, length, serialisation, salt ---

    #[test]
    fn determinism() {
        for v in [
            json!(null),
            json!(true),
            json!(12.5),
            json!("xyz"),
            json!([1, "two", null]),
            json!({ "k": [1, 2], "j": "v" }),
        ] {
            assert_eq!(encrypt(&v), encrypt(&v));
        }
    }

    #[test]
    fn ciphertext_length_tracks_encoded_form() {
        // One ciphertext byte per encoded bit, plus the reserved leading
        // carry byte.
        for v in [
            json!(null),
            json!(false),
            json!(123456789),
            json!("hello"),
            json!([]),
            json!({ "a": [1] }),
        ] {
            assert_eq!(encrypt(&v).as_ref().len(), encode(&v).unwrap().len() + 1);
        }
        // Concrete widths: 3-bit tag, 1 bit for `Bool`, 64 bits for `Number`,
        // 8 bits per content byte plus an 8-bit `0x00` terminator for
        // `String`, a 1-bit marker per element plus a final 0 bit for
        // composites.
        assert_eq!(encode(&json!(null)).unwrap().len(), 3);
        assert_eq!(encode(&json!(true)).unwrap().len(), 3 + 1);
        assert_eq!(encode(&json!(42)).unwrap().len(), 3 + 64);
        assert_eq!(encode(&json!("hi")).unwrap().len(), 3 + 2 * 8 + 8);
        assert_eq!(encode(&json!([])).unwrap().len(), 3 + 1);
        // `[null]`: ARRAY(3) + marker(1) + NULL(3) + end(1).
        assert_eq!(encode(&json!([null])).unwrap().len(), 3 + 1 + 3 + 1);
        // `{"a": null}`: OBJECT(3) + marker(1) + STRING-key("a")(3+8+8) +
        // value NULL(3) + end(1).
        assert_eq!(
            encode(&json!({ "a": null })).unwrap().len(),
            3 + 1 + (3 + 8 + 8) + 3 + 1
        );
    }

    #[test]
    fn hex_round_trip() {
        let ct = encrypt(&json!({ "a": [1, "x", null], "b": 2.5 }));
        let parsed = OpeCllw8VariableV1::from_hex(hex::encode(ct.as_ref())).unwrap();
        assert_eq!(ct, parsed);
    }

    #[test]
    fn distinct_salts_produce_distinct_ciphertexts() {
        let key = key();
        let v = json!([1, 2, 3]);
        let a = (&v).encrypt_ope_with_salt(&key, Some(b"domain-a")).unwrap();
        let b = (&v).encrypt_ope_with_salt(&key, Some(b"domain-b")).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn salt_preserves_ordering() {
        let key = key();
        let salt = b"some-domain";
        let a = (&json!([1]))
            .encrypt_ope_with_salt(&key, Some(salt))
            .unwrap();
        let b = (&json!([2]))
            .encrypt_ope_with_salt(&key, Some(salt))
            .unwrap();
        assert!(a < b);
    }

    #[test]
    fn no_salt_matches_none_salt() {
        let key = key();
        let v = json!({ "hello": "world" });
        assert_eq!(
            (&v).encrypt_ope(&key).unwrap(),
            (&v).encrypt_ope_with_salt(&key, None).unwrap()
        );
    }
}
