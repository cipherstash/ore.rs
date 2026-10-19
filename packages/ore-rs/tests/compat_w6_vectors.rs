//! Wire-format vectors for the `OreAes128Bit6` (bit2_w6) scheme — the v2
//! 6-bit-block scheme with the v2 wire header and the BHKR σ-MMO hash `H`
//! (plan §6 / review brief A1, resolved 2026-06-15).
//!
//! These tests pin the exact serialised bytes produced for fixed keys and
//! plaintexts, plus comparison results over those bytes. They freeze the v2
//! Bit6 wire format, released in 0.9.0: any change that alters these bytes
//! is a wire-format break for stored Bit6 ciphertexts and must fail here.
//! (Mirror of `compat_vectors.rs`, which does the same for the legacy Bit8
//! `OreAes128` scheme.)
//!
//! The plaintexts go in through the public path, sealed by vitaminc-ore, so
//! this also pins that vitaminc's encodings are the bytes 0.9 encrypted.
//!
//! Left ciphertexts are deterministic given the keys. Full ciphertexts include
//! a random nonce, drawn from the cipher's generator; `init_seeded` (the
//! `test-support` feature) seeds it, so full-ciphertext bytes are
//! reproducible.
//!
//! To regenerate (only legitimate if the wire format is *deliberately* changed):
//!
//! ```text
//! cargo test --test compat_w6_vectors -- --ignored --nocapture generate
//! ```

use ore_rs::scheme::bit2_w6::OreAes128Bit6;
use ore_rs::OreScheme;
use std::cmp::Ordering;
use vitaminc_context::Context;
use vitaminc_ore::{order, Float, Int, OrderPlaintext, OrderTarget, Physical};
use vitaminc_protected::Protected;

const K1: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

/// A salt from raw bytes: the bytes are the context, verbatim, as a 0.9
/// caller's `init_with_salt(key, bytes)` had them.
fn salt(bytes: &[u8]) -> Context<'static> {
    Context::from_encoded(bytes.to_vec())
}

/// A cipher whose nonce stream is seeded with `seed`, under `salt`.
fn seeded(seed: u8, salt: &Context<'_>) -> OreAes128Bit6 {
    OreAes128Bit6::init_seeded(Protected::new(K1), salt, [seed; 32]).unwrap()
}

fn cipher_a() -> OreAes128Bit6 {
    seeded(0x2a, &Context::empty())
}

fn cipher_b() -> OreAes128Bit6 {
    seeded(0x77, &Context::empty())
}

fn cipher_c() -> OreAes128Bit6 {
    seeded(0x5c, &Context::empty())
}

/// For left ciphertexts, which draw no nonce.
fn cipher_left() -> OreAes128Bit6 {
    OreAes128Bit6::init(Protected::new(K1)).unwrap()
}

fn cipher_a_salted(s: &[u8]) -> OreAes128Bit6 {
    seeded(0x2a, &salt(s))
}

fn cipher_left_salted(s: &[u8]) -> OreAes128Bit6 {
    OreAes128Bit6::init_with_salt(Protected::new(K1), &salt(s)).unwrap()
}

fn u64_pt(x: u64) -> OrderPlaintext {
    order(OrderTarget::U64, None, Physical::Int(Int::U64(x))).unwrap()
}

fn i64_pt(x: i64) -> OrderPlaintext {
    order(OrderTarget::I64, None, Physical::Int(Int::I64(x))).unwrap()
}

fn u32_pt(x: u32) -> OrderPlaintext {
    order(OrderTarget::U32, None, Physical::Int(Int::U32(x))).unwrap()
}

fn f64_pt(x: f64) -> OrderPlaintext {
    order(OrderTarget::F64, None, Physical::Float(Float::F64(x))).unwrap()
}

fn left(ore: &OreAes128Bit6, plaintext: &OrderPlaintext) -> Vec<u8> {
    ore.encrypt_query_plaintext(plaintext).unwrap().into_bytes()
}

fn full(ore: &OreAes128Bit6, plaintext: &OrderPlaintext) -> Vec<u8> {
    ore.encrypt_plaintext(plaintext).unwrap().into_bytes()
}

/// Plaintexts for [`FULL_U64_ONE_CIPHER`], in ascending order. Blocks are the
/// 6-bit groups of the big-endian bits, so pairs first differ at the last
/// block (`BASE` and `BASE + 1`), a middle block (`+ (1 << 29)`, block 5) and
/// block 0 (`+ (1 << 58)`). None of the additions carries.
const ONE_CIPHER_U64: [u64; 4] = [
    0x1020_3040_5060_7080,
    0x1020_3040_5060_7081,
    0x1020_3040_7060_7080,
    0x1420_3040_5060_7080,
];

/// Salts pinned beside the empty one, so the salt encoding is frozen too.
/// The first CMAC block holds the 8-byte length and 8 salt bytes: these end
/// inside it, fill it exactly, and run into a third block.
const SALTS: &[&[u8]] = &[b"age", b"users.dt", b"public.users.date_of_birth"];

#[path = "compat_w6_vectors/vectors.rs"]
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
fn full_i64_vectors() {
    for (value, expected) in FULL_I64 {
        assert_eq!(
            hex::encode(full(&cipher_a(), &i64_pt(*value))),
            *expected,
            "full ciphertext mismatch for i64 {value}"
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

/// `456u64` under each of [`SALTS`], left and full.
#[test]
fn salted_u64_456_vectors() {
    assert_eq!(SALTED_U64_456.len(), SALTS.len());
    for (s, (pinned_salt, left_hex, full_hex)) in SALTS.iter().zip(SALTED_U64_456) {
        assert_eq!(s, pinned_salt);
        assert_eq!(
            hex::encode(left(&cipher_left_salted(s), &u64_pt(456))),
            *left_hex,
            "left ciphertext mismatch for salt {s:?}"
        );
        assert_eq!(
            hex::encode(full(&cipher_a_salted(s), &u64_pt(456))),
            *full_hex,
            "full ciphertext mismatch for salt {s:?}"
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
                OreAes128Bit6::compare_raw_slices(&pinned(a), &pinned(b)),
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
                OreAes128Bit6::compare_raw_slices(&pinned(a), &pinned(b)),
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
        OreAes128Bit6::compare_raw_slices(&pinned(seed_a), &pinned(FULL_U64_456_SEED_B)),
        Some(Ordering::Equal)
    );
}

#[test]
fn compare_raw_slices_across_nonces() {
    // Every unequal pair here has two different nonces, and the comparator
    // must hash under the nonce of its second argument. FULL_U64 cannot pin
    // this: its unequal pairs share one nonce.
    // The nonce opens the right half, after the 4-byte header and 11 left
    // blocks of 17 bytes.
    const LEFT_LEN: usize = 4 + 11 * 17;
    let nonce = |ct: &str| pinned(ct)[LEFT_LEN..LEFT_LEN + 16].to_vec();
    for (i, (_, a)) in FULL_U64_ONE_CIPHER.iter().enumerate() {
        for (j, (_, b)) in FULL_U64_ONE_CIPHER.iter().enumerate() {
            if i != j {
                assert_ne!(nonce(a), nonce(b), "pair ({i}, {j}) shares a nonce");
            }
            let expected = i.cmp(&j);
            assert_eq!(
                OreAes128Bit6::compare_raw_slices(&pinned(a), &pinned(b)),
                Some(expected),
                "raw order mismatch at ({i}, {j})"
            );
            // The left half of `a`, as a query, orders the same way.
            assert_eq!(
                OreAes128Bit6::compare_left_to_full(&pinned(a)[..LEFT_LEN], &pinned(b)),
                Some(expected),
                "left-to-full order mismatch at ({i}, {j})"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Malformed symbols: an `xt` byte outside the 64-element domain
// ---------------------------------------------------------------------------

/// A pinned ciphertext with its first `xt` byte (just after the 4-byte
/// header) set to 64, one past the Bit6 symbol domain.
fn with_out_of_domain_symbol(hex_str: &str) -> Vec<u8> {
    let mut bytes = pinned(hex_str);
    bytes[4] = 64;
    bytes
}

/// The pinned left ciphertext of 456 against every pinned full `u64` (#120).
#[test]
fn left_to_full_on_pinned_bytes() {
    let left = pinned(LEFT_U64_456);
    for (value, full) in FULL_U64 {
        let full = pinned(full);
        assert_eq!(
            OreAes128Bit6::compare_left_to_full(&left, &full),
            Some(456u64.cmp(value)),
            "against {value}"
        );
    }
}

#[test]
fn comparators_reject_out_of_domain_symbols() {
    let good = pinned(FULL_U64[0].1);
    let bad = with_out_of_domain_symbol(FULL_U64[0].1);
    assert_eq!(OreAes128Bit6::compare_raw_slices(&bad, &good), None);
    assert_eq!(OreAes128Bit6::compare_raw_slices(&good, &bad), None);
    let bad_left = with_out_of_domain_symbol(LEFT_U64_456);
    assert_eq!(OreAes128Bit6::compare_left_to_full(&bad_left, &good), None);
    assert_eq!(
        OreAes128Bit6::compare_left_to_full(&pinned(LEFT_U64_456), &bad),
        None
    );
    // The highest in-domain symbol is still a symbol.
    let mut edge = pinned(FULL_U64[0].1);
    edge[4] = 63;
    assert!(OreAes128Bit6::compare_raw_slices(&edge, &good).is_some());
}

/// The scheme takes a fixed width of up to ten bytes and nothing else.
#[test]
fn wide_and_variable_width_plaintexts_are_refused() {
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

    print_left("LEFT_U64_456", left(&ore, &u64_pt(456)));
    print_left("LEFT_U64_0", left(&ore, &u64_pt(0)));
    print_left("LEFT_U32_1000", left(&ore, &u32_pt(1000)));
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

    println!("pub const FULL_I64: &[(i64, &str)] = &[");
    for value in [i64::MIN, -1i64, 0, 1, i64::MAX] {
        println!(
            "    ({}, \"{}\"),",
            value,
            hex::encode(full(&cipher_a(), &i64_pt(value)))
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
    println!();

    println!("pub const SALTED_U64_456: &[(&[u8], &str, &str)] = &[");
    for s in SALTS {
        println!(
            "    (b{:?}, \"{}\", \"{}\"),",
            std::str::from_utf8(s).unwrap(),
            hex::encode(left(&cipher_left_salted(s), &u64_pt(456))),
            hex::encode(full(&cipher_a_salted(s), &u64_pt(456)))
        );
    }
    println!("];");
}
