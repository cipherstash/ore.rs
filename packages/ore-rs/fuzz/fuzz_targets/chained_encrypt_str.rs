#![no_main]

use std::cmp::Ordering;

use libfuzzer_sys::fuzz_target;
use ore_rs::scheme::chained::{OreAes128Bit6Chained, Padding, DEFAULT_MAX_STR_BYTES};
use ore_rs::{OreError, OreScheme};
use vitaminc_ore::{order, OrderPlaintext, OrderTarget, Physical};
use vitaminc_protected::{Controlled, Protected};

type C = OreAes128Bit6Chained;

thread_local! {
    static ORE: C = C::init(Protected::new([0x42; 16])).expect("init");
}

/// The sealed text plaintext of `s`, or `None` where vitaminc refuses the
/// string (a code point Unicode 16 does not assign).
fn text(s: &str) -> Option<OrderPlaintext> {
    order(OrderTarget::Text, None, Physical::Text(s)).ok()
}

/// Encrypt `s` under the default options and check everything a single
/// string promises; `None` if the string is one the encryptors refuse,
/// after checking that they do. The bucket, then the ceiling, then the
/// trailing NUL, in the encryptors' order. The encoding is the marker
/// byte, then the folded text, so lengths are the encoding's.
fn encrypt(ore: &C, s: &str) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let plaintext = text(s)?;
    let encoded = plaintext.bytes().risky_ref().clone();
    let full = ore.encrypt_plaintext(&plaintext);
    let left = ore.encrypt_query_plaintext(&plaintext);
    let Ok(bucket) = Padding::default().padded_len(encoded.len()) else {
        assert!(matches!(full, Err(OreError::TooManyBlocks)), "{s:?}");
        assert!(matches!(left, Err(OreError::TooManyBlocks)), "{s:?}");
        return None;
    };
    if encoded.len() > DEFAULT_MAX_STR_BYTES {
        assert!(matches!(full, Err(OreError::TooLong)), "{s:?}");
        assert!(matches!(left, Err(OreError::TooLong)), "{s:?}");
        return None;
    }
    if encoded.last() == Some(&0) {
        assert!(matches!(full, Err(OreError::TrailingNul)), "{s:?}");
        assert!(matches!(left, Err(OreError::TrailingNul)), "{s:?}");
        return None;
    }
    let full = full.expect("encrypt_plaintext").into_bytes();
    let left = left.expect("encrypt_query_plaintext").into_bytes();

    // The sizes reveal the bucket and nothing more.
    let count = (bucket * 8).div_ceil(6);
    assert_eq!(full.len(), 7 + 25 * count + 16, "{s:?}");
    assert_eq!(left.len(), 7 + 17 * count, "{s:?}");
    // The full ciphertext begins with the left one.
    assert!(full.starts_with(&left), "{s:?}");
    // Equal to a fresh encryption (new nonce) and to its own left.
    let again = ore.encrypt_plaintext(&plaintext).expect("encrypt_plaintext");
    assert_eq!(
        C::compare_raw_slices(&full, again.as_bytes()),
        Some(Ordering::Equal),
        "{s:?}"
    );
    assert_eq!(
        C::compare_left_to_full(&left, &full),
        Some(Ordering::Equal),
        "{s:?}"
    );
    Some((encoded, full, left))
}

// Text is padded to a length bucket (the default policy: powers of two with
// a 16-byte floor). For any string: one whose encoding ends in NUL, would
// pad past the wire limit, or is over the default ceiling is refused, and
// every other one encrypts to a ciphertext of its bucket's size that
// compares Equal to a second encryption and to its own left ciphertext. For
// any pair, both comparators reproduce the order of the encodings, within a
// bucket and across them.
fuzz_target!(|pair: (&str, &str)| {
    let (a, b) = pair;
    ORE.with(|ore| {
        let (Some((enc_a, full_a, left_a)), Some((enc_b, full_b, left_b))) =
            (encrypt(ore, a), encrypt(ore, b))
        else {
            return;
        };
        let expected = Some(enc_a.cmp(&enc_b));
        assert_eq!(
            C::compare_raw_slices(&full_a, &full_b),
            expected,
            "{a:?} vs {b:?}"
        );
        assert_eq!(
            C::compare_raw_slices(&full_b, &full_a),
            expected.map(Ordering::reverse),
            "{b:?} vs {a:?}"
        );
        assert_eq!(
            C::compare_left_to_full(&left_a, &full_b),
            expected,
            "left {a:?} vs {b:?}"
        );
        assert_eq!(
            C::compare_left_to_full(&left_b, &full_a),
            expected.map(Ordering::reverse),
            "left {b:?} vs {a:?}"
        );
    });
});
