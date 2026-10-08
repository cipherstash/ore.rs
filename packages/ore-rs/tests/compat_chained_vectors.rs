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

use ore_rs::scheme::chained::{OreAes128Bit6Chained, OreAes128Bit6ChainedChaCha20, VarCipherText};
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

/// Strings pinned as full ciphertexts. Ordered so that adjacent pairs exercise
/// each comparator path: equal prefix then shorter-first (`""` < `"a"`,
/// `"alice"` < `"alice@example.com"`), a difference in the last, padded
/// block (`"alice"` vs `"alicf"`), and a difference in the first block.
const STRINGS: &[&str] = &["", "a", "alice", "alice@example.com", "alicf", "bob"];

/// Raw 6-bit symbol sequences pinned as full ciphertexts: the two domain
/// edges, a repeated symbol (distinct permutations per position), and the
/// longest value of one byte.
const SYMBOLS: &[&[u8]] = &[&[0], &[63], &[0, 0, 0], &[63, 63], &[1, 2, 3, 4, 5]];

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
fn left_symbol_vectors() {
    let ore = cipher_left();
    for (syms, expected) in LEFT_SYMBOLS {
        let left = ore.encrypt_left_var(syms).unwrap();
        assert_eq!(
            hex::encode(left.to_bytes()),
            *expected,
            "left ciphertext mismatch for symbols {syms:?}"
        );
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
fn full_symbol_vectors() {
    for (syms, expected) in FULL_SYMBOLS {
        let ct = cipher_a().encrypt_var(syms).unwrap();
        assert_eq!(
            hex::encode(ct.to_bytes()),
            *expected,
            "full ciphertext mismatch for symbols {syms:?}"
        );
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
    for ((s, left), (s2, full)) in LEFT_STR.iter().zip(FULL_STR) {
        assert_eq!(s, s2);
        assert!(full.starts_with(left), "left prefix mismatch for {:?}", s);
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
fn compare_raw_slices_matches_symbol_order() {
    for (xa, ha) in FULL_SYMBOLS {
        for (xb, hb) in FULL_SYMBOLS {
            assert_eq!(
                OreAes128Bit6ChainedChaCha20::compare_raw_slices(&pinned(ha), &pinned(hb)),
                Some(xa.cmp(xb)),
                "compare_raw_slices({xa:?}, {xb:?})"
            );
        }
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
    let strs = FULL_STR.iter().map(|(_, h)| *h);
    let syms = FULL_SYMBOLS.iter().map(|(_, h)| *h);
    for h in strs.chain(syms) {
        let bytes = pinned(h);
        let ct = VarCipherText::from_slice(&bytes).unwrap();
        assert_eq!(ct.to_bytes(), bytes);
    }
}

// ---------------------------------------------------------------------------
// Malformed input over pinned bytes
// ---------------------------------------------------------------------------

/// A pinned ciphertext with its first `xt` byte (just after the 4-byte
/// header) set to 64, one past the Bit6 symbol domain.
fn with_out_of_domain_symbol(hex_str: &str) -> Vec<u8> {
    let mut bytes = pinned(hex_str);
    bytes[4] = 64;
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
    edge[4] = 63;
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

    println!("pub const LEFT_SYMBOLS: &[(&[u8], &str)] = &[");
    for syms in SYMBOLS {
        let left = ore.encrypt_left_var(syms).unwrap();
        println!("    (&{syms:?}, \"{}\"),", hex::encode(left.to_bytes()));
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

    println!("pub const FULL_SYMBOLS: &[(&[u8], &str)] = &[");
    for syms in SYMBOLS {
        let ct = cipher_a().encrypt_var(syms).unwrap();
        println!("    (&{syms:?}, \"{}\"),", hex::encode(ct.to_bytes()));
    }
    println!("];");
    println!();

    let ct = cipher_b().encrypt_str("alice").unwrap();
    println!(
        "pub const FULL_ALICE_SEED_B: &str = \"{}\";",
        hex::encode(ct.to_bytes())
    );
}
