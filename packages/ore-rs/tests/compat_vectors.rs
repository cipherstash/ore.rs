//! Compatibility vectors for the `OreAes128` (bit2) scheme.
//!
//! These tests pin the exact serialised bytes produced by the current
//! implementation for fixed keys and plaintexts, plus the comparison results
//! over those pinned bytes. They are the contract for the frozen legacy wire
//! format (see `docs/plans/2026-06-12-ore-v2-architecture.md`): any change
//! that alters these bytes is a wire-format break for data already stored by
//! downstream users, and must fail here.
//!
//! The plaintexts go in through the public path, sealed by vitaminc-ore, so
//! this also pins that vitaminc's encodings of a `u64`, a `u32` and an `f64`
//! are the bytes the legacy scheme always encrypted.
//!
//! Left ciphertexts are deterministic given the keys. Full ciphertexts
//! include a random nonce, drawn from the cipher's generator; `init_seeded`
//! (the `test-support` feature) seeds it, so full-ciphertext bytes are
//! reproducible. The comparison fixtures parse pinned bytes only, so they
//! exercise the comparator without any RNG involvement.
//!
//! To regenerate (only legitimate if the wire format is *deliberately*
//! changed, which the v2 plan forbids for this scheme):
//!
//! ```text
//! cargo test --test compat_vectors -- --ignored --nocapture generate
//! ```

use ore_rs::scheme::bit2::OreAes128;
use ore_rs::OreScheme;
use std::cmp::Ordering;
use vitaminc_ore::{order, Float, Int, OrderPlaintext, OrderTarget, Physical};
use vitaminc_protected::Protected;

const K1: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const K2: [u8; 16] = [
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
];

/// A cipher whose nonce stream is seeded with `seed`, so its full
/// ciphertexts are reproducible.
fn seeded(seed: u8) -> OreAes128 {
    OreAes128::init_seeded(Protected::new(K1), Protected::new(K2), [seed; 32]).unwrap()
}

fn cipher_a() -> OreAes128 {
    seeded(0x2a)
}

fn cipher_b() -> OreAes128 {
    seeded(0x77)
}

fn cipher_c() -> OreAes128 {
    seeded(0x5c)
}

/// For left ciphertexts, which draw no nonce.
fn cipher_left() -> OreAes128 {
    OreAes128::init(Protected::new(K1), Protected::new(K2)).unwrap()
}

fn u64_pt(x: u64) -> OrderPlaintext {
    order(OrderTarget::U64, None, Physical::Int(Int::U64(x))).unwrap()
}

fn u32_pt(x: u32) -> OrderPlaintext {
    order(OrderTarget::U32, None, Physical::Int(Int::U32(x))).unwrap()
}

fn f64_pt(x: f64) -> OrderPlaintext {
    order(OrderTarget::F64, None, Physical::Float(Float::F64(x))).unwrap()
}

fn left(ore: &OreAes128, plaintext: &OrderPlaintext) -> Vec<u8> {
    ore.encrypt_query_plaintext(plaintext).unwrap().into_bytes()
}

fn full(ore: &OreAes128, plaintext: &OrderPlaintext) -> Vec<u8> {
    ore.encrypt_plaintext(plaintext).unwrap().into_bytes()
}

/// Plaintexts for [`FULL_U64_ONE_CIPHER`], in ascending order. Blocks are the
/// big-endian bytes, so pairs first differ at the last block (`BASE` and
/// `BASE + 1`), a middle block (`+ (1 << 32)`, block 3) and block 0
/// (`+ (1 << 56)`).
const ONE_CIPHER_U64: [u64; 4] = [
    0x1020_3040_5060_7080,
    0x1020_3040_5060_7081,
    0x1020_3041_5060_7080,
    0x1120_3040_5060_7080,
];

#[path = "compat_vectors/vectors.rs"]
mod vectors;
use vectors::*;

// ---------------------------------------------------------------------------
// Left ciphertexts (fully deterministic)
// ---------------------------------------------------------------------------

#[test]
fn left_u64_456() {
    assert_eq!(
        hex::encode(left(&cipher_left(), &u64_pt(456))),
        LEFT_U64_456
    );
}

#[test]
fn left_u64_zero() {
    assert_eq!(hex::encode(left(&cipher_left(), &u64_pt(0))), LEFT_U64_0);
}

#[test]
fn left_u32_1000() {
    assert_eq!(
        hex::encode(left(&cipher_left(), &u32_pt(1000))),
        LEFT_U32_1000
    );
}

/// The vector was made from the plaintext bytes `[0, 1, 2, 3, 4, 5, 6, 7]`,
/// which are the `U64` encoding of `0x0001_0203_0405_0607`.
#[test]
fn left_plaintext_bytes() {
    let ore = cipher_left();
    assert_eq!(
        hex::encode(left(&ore, &u64_pt(0x0001_0203_0405_0607))),
        LEFT_PT8
    );
}

// ---------------------------------------------------------------------------
// Full ciphertexts (deterministic via the seeded nonce stream)
// ---------------------------------------------------------------------------

#[test]
fn full_u64_vectors() {
    for (value, expected) in FULL_U64 {
        assert_eq!(
            hex::encode(full(&cipher_a(), &u64_pt(*value))),
            *expected,
            "full ciphertext mismatch for u64 {value}"
        );
    }
}

#[test]
fn full_u32_vectors() {
    for (value, expected) in FULL_U32 {
        assert_eq!(
            hex::encode(full(&cipher_a(), &u32_pt(*value))),
            *expected,
            "full ciphertext mismatch for u32 {value}"
        );
    }
}

#[test]
fn full_f64_vector() {
    assert_eq!(hex::encode(full(&cipher_a(), &f64_pt(1.5))), FULL_F64_1_5);
}

#[test]
fn full_u64_one_cipher_vectors() {
    // One cipher for every value, so its nonce stream advances and each
    // ciphertext has a different nonce.
    let ore = cipher_c();
    for (value, (pinned_value, expected)) in ONE_CIPHER_U64.iter().zip(FULL_U64_ONE_CIPHER) {
        assert_eq!(value, pinned_value);
        assert_eq!(
            hex::encode(full(&ore, &u64_pt(*value))),
            *expected,
            "full ciphertext mismatch for u64 {value}"
        );
    }
}

#[test]
fn full_u64_456_alternate_nonce() {
    assert_eq!(
        hex::encode(full(&cipher_b(), &u64_pt(456))),
        FULL_U64_456_SEED_B
    );
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
                OreAes128::compare_raw_slices(&pinned(a), &pinned(b)),
                Some(expected),
                "u64 vector order mismatch at ({i}, {j})"
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
        OreAes128::compare_raw_slices(&pinned(seed_a), &pinned(FULL_U64_456_SEED_B)),
        Some(Ordering::Equal)
    );
}

#[test]
fn compare_raw_slices_across_nonces() {
    // Every unequal pair here has two different nonces, and the comparator
    // must hash under the nonce of its second argument. FULL_U64 cannot pin
    // this: its unequal pairs share one nonce.
    // The nonce opens the right half, after 8 left blocks of 17 bytes.
    let nonce = |ct: &str| pinned(ct)[8 * 17..8 * 17 + 16].to_vec();
    for (i, (_, a)) in FULL_U64_ONE_CIPHER.iter().enumerate() {
        for (j, (_, b)) in FULL_U64_ONE_CIPHER.iter().enumerate() {
            if i != j {
                assert_ne!(nonce(a), nonce(b), "pair ({i}, {j}) shares a nonce");
            }
            let expected = i.cmp(&j);
            assert_eq!(
                OreAes128::compare_raw_slices(&pinned(a), &pinned(b)),
                Some(expected),
                "raw order mismatch at ({i}, {j})"
            );
            // The left half of `a`, as a query, orders the same way.
            assert_eq!(
                OreAes128::compare_left_to_full(&pinned(a)[..8 * 17], &pinned(b)),
                Some(expected),
                "left-to-full order mismatch at ({i}, {j})"
            );
        }
    }
}

#[test]
fn left_against_pinned_full() {
    // A freshly produced left ciphertext for 456 must equal the left half of
    // the pinned full ciphertext for 456 (left bytes are deterministic).
    let left = left(&cipher_left(), &u64_pt(456));
    let (_, full_hex) = FULL_U64[2];
    let full = pinned(full_hex);
    assert_eq!(
        left,
        full[..left.len()],
        "left half of full ciphertext drifted"
    );
    assert_eq!(
        OreAes128::compare_left_to_full(&left, &full),
        Some(Ordering::Equal)
    );
}

/// The legacy scheme takes no text, bytes or 16-byte plaintext.
#[test]
fn variable_width_and_sixteen_byte_plaintexts_are_refused() {
    let ore = cipher_left();
    let text = order(OrderTarget::Text, None, Physical::Text("alice")).unwrap();
    assert!(matches!(
        ore.encrypt_plaintext(&text),
        Err(ore_rs::OreError::VariableLength)
    ));
    let wide = order(OrderTarget::U128, None, Physical::Int(Int::U128(1))).unwrap();
    assert!(matches!(
        ore.encrypt_plaintext(&wide),
        Err(ore_rs::OreError::TooManyBlocks)
    ));
}

// ---------------------------------------------------------------------------
// Generator (run manually; see module docs)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "generator: prints the contents of tests/compat_vectors/vectors.rs"]
fn generate() {
    println!("// Contents of tests/compat_vectors/vectors.rs");
    println!(
        "// Generated by `cargo test --test compat_vectors -- --ignored --nocapture generate`"
    );
    println!("// DO NOT regenerate unless deliberately breaking the wire format (see plan doc).");
    println!();

    let ore = cipher_left();
    let print_left = |name: &str, bytes: Vec<u8>| {
        println!("pub const {}: &str = \"{}\";", name, hex::encode(bytes));
    };

    print_left("LEFT_U64_456", left(&ore, &u64_pt(456)));
    print_left("LEFT_U64_0", left(&ore, &u64_pt(0)));
    print_left("LEFT_U32_1000", left(&ore, &u32_pt(1000)));
    print_left("LEFT_PT8", left(&ore, &u64_pt(0x0001_0203_0405_0607)));
    println!();

    println!("pub const FULL_U64: &[(u64, &str)] = &[");
    for value in [0u64, 1, 456, 1 << 32, u64::MAX] {
        println!(
            "    ({}, \"{}\"),",
            value,
            hex::encode(full(&cipher_a(), &u64_pt(value)))
        );
    }
    println!("];");
    println!();

    println!("pub const FULL_U32: &[(u32, &str)] = &[");
    for value in [0u32, 1000, u32::MAX] {
        println!(
            "    ({}, \"{}\"),",
            value,
            hex::encode(full(&cipher_a(), &u32_pt(value)))
        );
    }
    println!("];");
    println!();

    println!(
        "pub const FULL_F64_1_5: &str = \"{}\";",
        hex::encode(full(&cipher_a(), &f64_pt(1.5)))
    );
    println!(
        "pub const FULL_U64_456_SEED_B: &str = \"{}\";",
        hex::encode(full(&cipher_b(), &u64_pt(456)))
    );
    println!();

    let ore = cipher_c();
    println!("pub const FULL_U64_ONE_CIPHER: &[(u64, &str)] = &[");
    for value in ONE_CIPHER_U64 {
        println!(
            "    ({}, \"{}\"),",
            value,
            hex::encode(full(&ore, &u64_pt(value)))
        );
    }
    println!("];");
}
