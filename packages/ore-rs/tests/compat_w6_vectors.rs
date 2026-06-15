//! Wire-format vectors for the `OreAes128Bit6` (bit2_w6) scheme — the v2
//! 6-bit-block scheme with the v2 wire header and the BHKR σ-MMO hash `H`
//! (plan §6 / review brief A1, resolved 2026-06-15).
//!
//! These tests pin the exact serialised bytes produced for fixed keys and
//! plaintexts, plus comparison results over those bytes. They freeze the v2
//! Bit6 wire format introduced by this PR: once released, any change that
//! alters these bytes is a wire-format break for stored Bit6 ciphertexts and
//! must fail here. (Mirror of `compat_vectors.rs`, which does the same for the
//! legacy Bit8 `OreAes128` scheme.)
//!
//! Left ciphertexts are deterministic given the keys. Full ciphertexts include
//! a random nonce drawn from the cipher's internal RNG, which `OreCipher::init`
//! seeds via `SeedableRng::from_entropy`; [`TestRng`] overrides `from_entropy`
//! to a fixed seed so full-ciphertext bytes are reproducible.
//!
//! To regenerate (only legitimate if the wire format is *deliberately* changed):
//!
//! ```text
//! cargo test --test compat_w6_vectors -- --ignored --nocapture generate
//! ```

use ore_rs::{
    scheme::bit2_w6::{OreAes128Bit6, OreAes128Bit6ChaCha20},
    CipherText, OreCipher, OreEncrypt, OreOutput,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::cmp::Ordering;

const K1: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const K2: [u8; 16] = [
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
];

/// RNG whose `from_entropy` is deterministic, so that `OreCipher::init`
/// (which calls `from_entropy` internally) produces a reproducible nonce stream.
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

type OreA = OreAes128Bit6<TestRng<0x2a>>;
type OreB = OreAes128Bit6<TestRng<0x77>>;

fn cipher_a() -> OreA {
    OreCipher::init(&K1, &K2).unwrap()
}

fn cipher_b() -> OreB {
    OreCipher::init(&K1, &K2).unwrap()
}

fn cipher_left() -> OreAes128Bit6ChaCha20 {
    OreCipher::init(&K1, &K2).unwrap()
}

#[path = "compat_w6_vectors/vectors.rs"]
mod vectors;
use vectors::*;

// ---------------------------------------------------------------------------
// Left ciphertexts (fully deterministic)
// ---------------------------------------------------------------------------

#[test]
fn left_u64_456() {
    let ore = cipher_left();
    let left = 456u64.encrypt_left(&ore).unwrap();
    assert_eq!(hex::encode(left.to_bytes()), LEFT_U64_456);
}

#[test]
fn left_u64_zero() {
    let ore = cipher_left();
    let left = 0u64.encrypt_left(&ore).unwrap();
    assert_eq!(hex::encode(left.to_bytes()), LEFT_U64_0);
}

#[test]
fn left_u32_1000() {
    let ore = cipher_left();
    let left = 1000u32.encrypt_left(&ore).unwrap();
    assert_eq!(hex::encode(left.to_bytes()), LEFT_U32_1000);
}

// ---------------------------------------------------------------------------
// Full ciphertexts (deterministic via TestRng nonce stream)
// ---------------------------------------------------------------------------

#[test]
fn full_u64_vectors() {
    for (value, expected) in FULL_U64 {
        let ct = value.encrypt(&cipher_a()).unwrap();
        assert_eq!(
            hex::encode(ct.to_bytes()),
            *expected,
            "full ciphertext mismatch for u64 {value}"
        );
    }
}

#[test]
fn full_u32_vectors() {
    for (value, expected) in FULL_U32 {
        let ct = value.encrypt(&cipher_a()).unwrap();
        assert_eq!(
            hex::encode(ct.to_bytes()),
            *expected,
            "full ciphertext mismatch for u32 {value}"
        );
    }
}

#[test]
fn full_i64_vectors() {
    for (value, expected) in FULL_I64 {
        let ct = value.encrypt(&cipher_a()).unwrap();
        assert_eq!(
            hex::encode(ct.to_bytes()),
            *expected,
            "full ciphertext mismatch for i64 {value}"
        );
    }
}

#[test]
fn full_f64_vector() {
    let ct = 1.5f64.encrypt(&cipher_a()).unwrap();
    assert_eq!(hex::encode(ct.to_bytes()), FULL_F64_1_5);
}

#[test]
fn full_u64_456_alternate_nonce() {
    let ct = 456u64.encrypt(&cipher_b()).unwrap();
    assert_eq!(hex::encode(ct.to_bytes()), FULL_U64_456_SEED_B);
}

// ---------------------------------------------------------------------------
// Comparison fixtures over pinned bytes (no RNG involved)
// ---------------------------------------------------------------------------

fn pinned(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).unwrap()
}

#[test]
fn compare_raw_slices_total_order_u64() {
    // FULL_U64 is listed in ascending plaintext order.
    for (i, (_, a)) in FULL_U64.iter().enumerate() {
        for (j, (_, b)) in FULL_U64.iter().enumerate() {
            let expected = i.cmp(&j);
            assert_eq!(
                OreAes128Bit6ChaCha20::compare_raw_slices(&pinned(a), &pinned(b)),
                Some(expected),
                "u64 vector order mismatch at ({i}, {j})"
            );
        }
    }
}

#[test]
fn compare_raw_slices_total_order_i64() {
    // FULL_I64 is listed in ascending plaintext order (incl. negatives).
    for (i, (_, a)) in FULL_I64.iter().enumerate() {
        for (j, (_, b)) in FULL_I64.iter().enumerate() {
            let expected = i.cmp(&j);
            assert_eq!(
                OreAes128Bit6ChaCha20::compare_raw_slices(&pinned(a), &pinned(b)),
                Some(expected),
                "i64 vector order mismatch at ({i}, {j})"
            );
        }
    }
}

#[test]
fn compare_raw_slices_equality_across_nonces() {
    // Same plaintext (456u64) encrypted under two different nonce streams
    // must compare equal.
    let (_, seed_a) = FULL_U64[2];
    assert_eq!(
        OreAes128Bit6ChaCha20::compare_raw_slices(&pinned(seed_a), &pinned(FULL_U64_456_SEED_B)),
        Some(Ordering::Equal)
    );
}

#[test]
fn typed_comparison_of_pinned_bytes() {
    // u64 is 11 blocks at 6-bit width.
    let a = CipherText::<OreAes128Bit6ChaCha20, 11>::from_slice(&pinned(FULL_U64[1].1)).unwrap();
    let b = CipherText::<OreAes128Bit6ChaCha20, 11>::from_slice(&pinned(FULL_U64[3].1)).unwrap();
    assert!(a < b);
    assert!(b > a);
    assert_eq!(a.cmp(&a), Ordering::Equal);
}

// ---------------------------------------------------------------------------
// Generator (run manually; see module docs)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "generator: prints the contents of tests/compat_w6_vectors/vectors.rs"]
fn generate() {
    println!("// Contents of tests/compat_w6_vectors/vectors.rs");
    println!(
        "// Generated by `cargo test --test compat_w6_vectors -- --ignored --nocapture generate`"
    );
    println!("// DO NOT regenerate unless deliberately breaking the wire format (see plan doc).");
    println!();

    let ore = cipher_left();
    let print_left = |name: &str, bytes: Vec<u8>| {
        println!("pub const {}: &str = \"{}\";", name, hex::encode(bytes));
    };

    print_left(
        "LEFT_U64_456",
        456u64.encrypt_left(&ore).unwrap().to_bytes(),
    );
    print_left("LEFT_U64_0", 0u64.encrypt_left(&ore).unwrap().to_bytes());
    print_left(
        "LEFT_U32_1000",
        1000u32.encrypt_left(&ore).unwrap().to_bytes(),
    );
    println!();

    println!("pub const FULL_U64: &[(u64, &str)] = &[");
    for value in [0u64, 1, 456, 1 << 32, u64::MAX] {
        let ct = value.encrypt(&cipher_a()).unwrap();
        println!("    ({}, \"{}\"),", value, hex::encode(ct.to_bytes()));
    }
    println!("];");
    println!();

    println!("pub const FULL_U32: &[(u32, &str)] = &[");
    for value in [0u32, 1000, u32::MAX] {
        let ct = value.encrypt(&cipher_a()).unwrap();
        println!("    ({}, \"{}\"),", value, hex::encode(ct.to_bytes()));
    }
    println!("];");
    println!();

    println!("pub const FULL_I64: &[(i64, &str)] = &[");
    for value in [i64::MIN, -1i64, 0, 1, i64::MAX] {
        let ct = value.encrypt(&cipher_a()).unwrap();
        println!("    ({}, \"{}\"),", value, hex::encode(ct.to_bytes()));
    }
    println!("];");
    println!();

    let f = 1.5f64.encrypt(&cipher_a()).unwrap();
    println!(
        "pub const FULL_F64_1_5: &str = \"{}\";",
        hex::encode(f.to_bytes())
    );

    let alt = 456u64.encrypt(&cipher_b()).unwrap();
    println!(
        "pub const FULL_U64_456_SEED_B: &str = \"{}\";",
        hex::encode(alt.to_bytes())
    );
}
