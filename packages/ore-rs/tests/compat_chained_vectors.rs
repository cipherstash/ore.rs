//! Wire-format vectors for the `OreAes128Bit6Chained` scheme — the v2
//! variable-length (chained-prefix) scheme with the v2 wire header, the CMAC
//! accumulator (review brief A2/A3) and the BHKR σ-MMO hash `H` (A1).
//!
//! These tests pin the exact serialised bytes produced for a fixed key and
//! fixed inputs, plus comparison results over those bytes. They freeze the v2
//! chained wire format introduced by this PR: once released, any change that
//! alters these bytes is a wire-format break for stored chained ciphertexts
//! and must fail here. (Mirror of `compat_w6_vectors.rs`, which does the same
//! for the fixed-width Bit6 scheme.)
//!
//! Strings are pinned under three padding policies: the default (powers of
//! two with a 16-byte floor), none, and a fixed length.
//!
//! Left ciphertexts are deterministic given the key. Full ciphertexts include
//! a random nonce drawn from the cipher's internal RNG, which `init` seeds via
//! `SeedableRng::from_entropy`; [`TestRng`] overrides `from_entropy` to a
//! fixed seed so full-ciphertext bytes are reproducible.
//!
//! To regenerate (only legitimate if the wire format is *deliberately* changed):
//!
//! ```text
//! cargo test --test compat_chained_vectors -- --ignored --nocapture generate
//! ```

use ore_rs::scheme::chained::{
    Options, OreAes128Bit6Chained, OreAes128Bit6ChainedChaCha20, Padding, VarCipherText,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::cmp::Ordering;

const K1: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

/// RNG whose `from_entropy` is deterministic, so that `init` (which calls
/// `from_entropy` internally) produces a reproducible nonce stream.
struct TestRng<const SEED: u8>(ChaCha20Rng);

impl<const SEED: u8> RngCore for TestRng<SEED> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl<const SEED: u8> SeedableRng for TestRng<SEED> {
    type Seed = [u8; 32];
    fn from_seed(seed: Self::Seed) -> Self {
        Self(ChaCha20Rng::from_seed(seed))
    }
    fn from_entropy() -> Self {
        Self::from_seed([SEED; 32])
    }
}

type OreA = OreAes128Bit6Chained<TestRng<0x2a>>;
type OreB = OreAes128Bit6Chained<TestRng<0x77>>;

fn cipher_a() -> OreA {
    OreAes128Bit6Chained::init(&K1).unwrap()
}

fn cipher_b() -> OreB {
    OreAes128Bit6Chained::init(&K1).unwrap()
}

fn cipher_left() -> OreAes128Bit6ChainedChaCha20 {
    OreAes128Bit6Chained::init(&K1).unwrap()
}

const FIXED: Padding = Padding::Fixed { max_bytes: 40 };

fn cipher_a_with(padding: Padding) -> OreA {
    OreAes128Bit6Chained::init_with(&K1, Options::default().with_padding(padding)).unwrap()
}

fn cipher_left_with(padding: Padding) -> OreAes128Bit6ChainedChaCha20 {
    OreAes128Bit6Chained::init_with(&K1, Options::default().with_padding(padding)).unwrap()
}

/// Pinned `(string, hex)` pairs.
type Pinned = &'static [(&'static str, &'static str)];

/// The pinned string sets other than the default: each policy's left and
/// full ciphertexts.
fn other_policies() -> [(Padding, Pinned, Pinned); 2] {
    [
        (Padding::None, LEFT_STR_UNPADDED, FULL_STR_UNPADDED),
        (FIXED, LEFT_STR_FIXED, FULL_STR_FIXED),
    ]
}

/// Strings pinned as full ciphertexts. Ordered so that adjacent pairs exercise
/// each comparator path: equal prefix then shorter-first (`""` < `"a"`,
/// `"alice"` < `"alice@example.com"`), a difference in the last, padded
/// block (`"alice"` vs `"alicf"`), and a difference in the first block. The
/// default policy pads the first three to 16 bytes, the 17- and 32-byte
/// strings to 32, and the 33-byte string to 64.
const STRINGS: &[&str] = &[
    "",
    "a",
    "alice",
    "alice@example.com",
    "alice@example.com/0123456789abcd",
    "alice@example.com/0123456789abcde",
    "alicf",
    "bob",
];

#[path = "compat_chained_vectors/vectors.rs"]
mod vectors;
use vectors::*;

// ---------------------------------------------------------------------------
// Left ciphertexts (fully deterministic)
// ---------------------------------------------------------------------------

#[test]
fn left_str_vectors() {
    let ore = cipher_left();
    for (s, expected) in LEFT_STR {
        let left = ore.encrypt_left_str(s).unwrap();
        assert_eq!(
            hex::encode(left.to_bytes()),
            *expected,
            "left ciphertext mismatch for {s:?}"
        );
    }
}

#[test]
fn left_str_vectors_other_policies() {
    for (padding, lefts, _) in other_policies() {
        let ore = cipher_left_with(padding);
        for (s, expected) in lefts {
            let left = ore.encrypt_left_str(s).unwrap();
            assert_eq!(
                hex::encode(left.to_bytes()),
                *expected,
                "left ciphertext mismatch for {s:?} under {padding:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Full ciphertexts (deterministic via TestRng nonce stream)
// ---------------------------------------------------------------------------

#[test]
fn full_str_vectors() {
    for (s, expected) in FULL_STR {
        let ct = cipher_a().encrypt_str(s).unwrap();
        assert_eq!(
            hex::encode(ct.to_bytes()),
            *expected,
            "full ciphertext mismatch for {s:?}"
        );
    }
}

#[test]
fn full_str_vectors_other_policies() {
    for (padding, _, fulls) in other_policies() {
        for (s, expected) in fulls {
            let ct = cipher_a_with(padding).encrypt_str(s).unwrap();
            assert_eq!(
                hex::encode(ct.to_bytes()),
                *expected,
                "full ciphertext mismatch for {s:?} under {padding:?}"
            );
        }
    }
}

#[test]
fn full_alice_alternate_nonce() {
    let ct = cipher_b().encrypt_str("alice").unwrap();
    assert_eq!(hex::encode(ct.to_bytes()), FULL_ALICE_SEED_B);
}

/// The left half of a full ciphertext is byte-identical to the left-only
/// artefact: `compare_left_to_full` relies on the shared layout.
#[test]
fn full_ciphertext_starts_with_the_left_ciphertext() {
    let mut sets = vec![(LEFT_STR, FULL_STR)];
    sets.extend(other_policies().iter().map(|&(_, l, f)| (l, f)));
    for (lefts, fulls) in sets {
        for ((s, left), (s2, full)) in lefts.iter().zip(fulls.iter()) {
            assert_eq!(s, s2);
            assert!(full.starts_with(left), "left prefix mismatch for {:?}", s);
        }
    }
}

// ---------------------------------------------------------------------------
// Comparison fixtures over pinned bytes (no RNG involved)
// ---------------------------------------------------------------------------

fn pinned(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).unwrap()
}

/// Every pair of pinned strings compares as the plaintexts do (byte-wise,
/// shorter prefix first), in both argument orders.
#[test]
fn compare_raw_slices_matches_plaintext_order() {
    for (sa, ha) in FULL_STR {
        for (sb, hb) in FULL_STR {
            let expected = sa.as_bytes().cmp(sb.as_bytes());
            assert_eq!(
                OreAes128Bit6ChainedChaCha20::compare_raw_slices(&pinned(ha), &pinned(hb)),
                Some(expected),
                "compare_raw_slices({sa:?}, {sb:?})"
            );
        }
    }
}

#[test]
fn compare_matches_plaintext_order_other_policies() {
    type C = OreAes128Bit6ChainedChaCha20;
    for (padding, lefts, fulls) in other_policies() {
        for ((sa, ha), (_, hl)) in fulls.iter().zip(lefts.iter()) {
            for (sb, hb) in fulls {
                let expected = sa.as_bytes().cmp(sb.as_bytes());
                assert_eq!(
                    C::compare_raw_slices(&pinned(ha), &pinned(hb)),
                    Some(expected),
                    "compare_raw_slices({sa:?}, {sb:?}) under {padding:?}"
                );
                assert_eq!(
                    C::compare_left_to_full(&pinned(hl), &pinned(hb)),
                    Some(expected),
                    "compare_left_to_full({sa:?}, {sb:?}) under {padding:?}"
                );
            }
        }
    }
}

/// Ciphertexts of one string under different policies do not compare.
#[test]
fn comparators_refuse_mixed_policies() {
    type C = OreAes128Bit6ChainedChaCha20;
    let alice =
        |set: &[(&str, &'static str)]| pinned(set.iter().find(|(s, _)| *s == "alice").unwrap().1);
    let fulls = [
        alice(FULL_STR),
        alice(FULL_STR_UNPADDED),
        alice(FULL_STR_FIXED),
    ];
    let lefts = [
        alice(LEFT_STR),
        alice(LEFT_STR_UNPADDED),
        alice(LEFT_STR_FIXED),
    ];
    for (i, (full_a, left_a)) in fulls.iter().zip(&lefts).enumerate() {
        for (j, full_b) in fulls.iter().enumerate() {
            let expected = (i == j).then_some(Ordering::Equal);
            assert_eq!(C::compare_raw_slices(full_a, full_b), expected);
            assert_eq!(C::compare_left_to_full(left_a, full_b), expected);
        }
    }
}

/// Padding changes only the header and adds blocks: each padded vector's
/// blocks begin with the unpadded vector's.
#[test]
fn padding_extends_the_unpadded_blocks() {
    // `xt` follows the 7-byte header.
    const H: usize = 7;
    for ((s, unpadded), (_, padded)) in LEFT_STR_UNPADDED.iter().zip(LEFT_STR) {
        let (u, p) = (pinned(unpadded), pinned(padded));
        let count = u16::from_be_bytes([u[2], u[3]]) as usize;
        assert_eq!(u[H..H + count], p[H..H + count], "xt prefix for {s:?}");
    }
}

/// The query path: a pinned left-only ciphertext against every pinned full
/// ciphertext.
#[test]
fn compare_left_to_full_matches_plaintext_order() {
    for (sa, hl) in LEFT_STR {
        for (sb, hf) in FULL_STR {
            let expected = sa.as_bytes().cmp(sb.as_bytes());
            assert_eq!(
                OreAes128Bit6ChainedChaCha20::compare_left_to_full(&pinned(hl), &pinned(hf)),
                Some(expected),
                "compare_left_to_full({sa:?}, {sb:?})"
            );
        }
    }
}

#[test]
fn compare_raw_slices_equality_across_nonces() {
    let alice_a = pinned(FULL_STR.iter().find(|(s, _)| *s == "alice").unwrap().1);
    let alice_b = pinned(FULL_ALICE_SEED_B);
    assert_ne!(
        alice_a, alice_b,
        "different nonces must give different bytes"
    );
    assert_eq!(
        OreAes128Bit6ChainedChaCha20::compare_raw_slices(&alice_a, &alice_b),
        Some(Ordering::Equal)
    );
    assert_eq!(
        OreAes128Bit6ChainedChaCha20::compare_raw_slices(&alice_b, &alice_a),
        Some(Ordering::Equal)
    );
}

#[test]
fn pinned_bytes_round_trip_the_parser() {
    let sets = other_policies();
    let others = sets.iter().flat_map(|(_, _, fulls)| fulls.iter());
    for (_, h) in FULL_STR.iter().chain(others) {
        let bytes = pinned(h);
        let ct = VarCipherText::from_slice(&bytes).unwrap();
        assert_eq!(ct.to_bytes(), bytes);
    }
}

// ---------------------------------------------------------------------------
// Malformed input over pinned bytes
// ---------------------------------------------------------------------------

/// Offset of the first `xt` byte: after the 4-byte common header and the
/// 3-byte padding policy.
const XT: usize = 7;

/// A pinned ciphertext with its first `xt` byte set to 64, one past the
/// Bit6 symbol domain.
fn with_out_of_domain_symbol(hex_str: &str) -> Vec<u8> {
    let mut bytes = pinned(hex_str);
    bytes[XT] = 64;
    bytes
}

fn full_alice() -> &'static str {
    FULL_STR.iter().find(|(s, _)| *s == "alice").unwrap().1
}

fn left_alice() -> &'static str {
    LEFT_STR.iter().find(|(s, _)| *s == "alice").unwrap().1
}

#[test]
fn parser_rejects_out_of_domain_symbols() {
    assert!(VarCipherText::from_slice(&with_out_of_domain_symbol(full_alice())).is_err());

    // The highest in-domain symbol still parses.
    let mut edge = pinned(full_alice());
    edge[XT] = 63;
    assert!(VarCipherText::from_slice(&edge).is_ok());
}

#[test]
fn comparators_reject_out_of_domain_symbols() {
    let good = pinned(full_alice());
    let bad = with_out_of_domain_symbol(full_alice());
    assert_eq!(
        OreAes128Bit6ChainedChaCha20::compare_raw_slices(&bad, &good),
        None
    );
    assert_eq!(
        OreAes128Bit6ChainedChaCha20::compare_raw_slices(&good, &bad),
        None
    );

    let bad_left = with_out_of_domain_symbol(left_alice());
    assert_eq!(
        OreAes128Bit6ChainedChaCha20::compare_left_to_full(&bad_left, &good),
        None
    );
    assert_eq!(
        OreAes128Bit6ChainedChaCha20::compare_left_to_full(&pinned(left_alice()), &bad),
        None
    );
}

#[test]
fn comparators_reject_wrong_lengths_and_headers() {
    let full = pinned(full_alice());
    let left = pinned(left_alice());

    // A left-only artefact is not a full ciphertext, and vice versa.
    assert_eq!(
        OreAes128Bit6ChainedChaCha20::compare_raw_slices(&left, &full),
        None
    );
    assert_eq!(
        OreAes128Bit6ChainedChaCha20::compare_left_to_full(&full, &full),
        None
    );
    assert!(VarCipherText::from_slice(&left).is_err());

    // Truncation and extension.
    assert!(VarCipherText::from_slice(&full[..full.len() - 1]).is_err());
    let mut longer = full.clone();
    longer.push(0);
    assert!(VarCipherText::from_slice(&longer).is_err());

    // Wrong version / scheme id.
    let mut v = full.clone();
    v[0] ^= 1;
    assert_eq!(
        OreAes128Bit6ChainedChaCha20::compare_raw_slices(&v, &full),
        None
    );
    let mut s = full.clone();
    s[1] ^= 1;
    assert_eq!(
        OreAes128Bit6ChainedChaCha20::compare_raw_slices(&s, &full),
        None
    );

    // Unknown padding kind.
    let mut p = full.clone();
    p[4] = 3;
    assert_eq!(
        OreAes128Bit6ChainedChaCha20::compare_raw_slices(&p, &p),
        None
    );
    assert!(VarCipherText::from_slice(&p).is_err());
}

#[test]
#[ignore = "generator: prints the contents of tests/compat_chained_vectors/vectors.rs"]
fn generate() {
    println!("// Contents of tests/compat_chained_vectors/vectors.rs");
    println!(
        "// Generated by `cargo test --test compat_chained_vectors -- --ignored --nocapture generate`"
    );
    println!("// DO NOT regenerate unless deliberately breaking the wire format (see plan doc).");
    println!();

    let ore = cipher_left();

    println!("pub const LEFT_STR: &[(&str, &str)] = &[");
    for s in STRINGS {
        let left = ore.encrypt_left_str(s).unwrap();
        println!("    ({s:?}, \"{}\"),", hex::encode(left.to_bytes()));
    }
    println!("];");
    println!();

    println!("pub const FULL_STR: &[(&str, &str)] = &[");
    for s in STRINGS {
        let ct = cipher_a().encrypt_str(s).unwrap();
        println!("    ({s:?}, \"{}\"),", hex::encode(ct.to_bytes()));
    }
    println!("];");
    println!();

    let ct = cipher_b().encrypt_str("alice").unwrap();
    println!(
        "pub const FULL_ALICE_SEED_B: &str = \"{}\";",
        hex::encode(ct.to_bytes())
    );

    for (padding, suffix) in [(Padding::None, "UNPADDED"), (FIXED, "FIXED")] {
        println!();
        let ore = cipher_left_with(padding);
        println!("pub const LEFT_STR_{suffix}: &[(&str, &str)] = &[");
        for s in STRINGS {
            let left = ore.encrypt_left_str(s).unwrap();
            println!("    ({s:?}, \"{}\"),", hex::encode(left.to_bytes()));
        }
        println!("];");
        println!();
        println!("pub const FULL_STR_{suffix}: &[(&str, &str)] = &[");
        for s in STRINGS {
            let ct = cipher_a_with(padding).encrypt_str(s).unwrap();
            println!("    ({s:?}, \"{}\"),", hex::encode(ct.to_bytes()));
        }
        println!("];");
    }
}
