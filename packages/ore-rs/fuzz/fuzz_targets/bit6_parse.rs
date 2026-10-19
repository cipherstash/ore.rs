#![no_main]

use libfuzzer_sys::fuzz_target;
use ore_rs::scheme::bit2_w6::OreAes128Bit6ChaCha20;
use ore_rs::{CipherText, Left, OreCipher, OreOutput, Right};

// The fixed-width v2 scheme at its two shipped widths (11 blocks for 64-bit
// values, 6 for 32-bit). Parsing untrusted bytes as a full, left-only or
// right-only ciphertext must never panic, anything accepted must re-encode
// to itself, and the raw comparators (full against full, and left against
// full) must answer arbitrary pairs without panicking and agree with their
// typed forms on pairs that parse.
fn check<const N: usize>(data: &[u8]) {
    if let Ok(ct) = CipherText::<OreAes128Bit6ChaCha20, N>::from_slice(data) {
        assert_eq!(
            ct.to_bytes(),
            data,
            "accepted full ciphertext did not round-trip"
        );
    }
    if let Ok(left) = Left::<OreAes128Bit6ChaCha20, N>::from_slice(data) {
        assert_eq!(
            left.to_bytes(),
            data,
            "accepted left ciphertext did not round-trip"
        );
    }
    if let Ok(right) = Right::<OreAes128Bit6ChaCha20, N>::from_slice(data) {
        assert_eq!(
            right.to_bytes(),
            data,
            "accepted right ciphertext did not round-trip"
        );
    }
}

/// When both inputs parse as full ciphertexts, the raw comparator and the
/// typed `Ord` must give the same order: a database index (raw bytes) and an
/// application (parsed values) must not order the same rows differently.
/// Antisymmetry is not asserted; it holds only for genuine ciphertexts.
fn agree<const N: usize>(a: &[u8], b: &[u8]) {
    let (Ok(ct_a), Ok(ct_b)) = (
        CipherText::<OreAes128Bit6ChaCha20, N>::from_slice(a),
        CipherText::<OreAes128Bit6ChaCha20, N>::from_slice(b),
    ) else {
        return;
    };
    assert_eq!(
        OreAes128Bit6ChaCha20::compare_raw_slices(a, b),
        Some(ct_a.cmp(&ct_b)),
        "raw and typed comparators disagree"
    );
}

/// When `b` parses as a full ciphertext, the raw and typed left-to-full
/// comparators must agree on every left that parses against it (#120): `a`
/// itself, and a left made of `b`'s header and left-length prefix with `a`
/// written over the body. A left never has a full ciphertext's length, so
/// the `overlay` pairs below cannot supply one; this does.
fn agree_left<const N: usize>(a: &[u8], b: &[u8]) {
    let Ok(full) = CipherText::<OreAes128Bit6ChaCha20, N>::from_slice(b) else {
        return;
    };
    let from_b = overlay(&b[..Left::<OreAes128Bit6ChaCha20, N>::size()], a, 4);
    for cand in [a, &from_b[..]] {
        let Ok(left) = Left::<OreAes128Bit6ChaCha20, N>::from_slice(cand) else {
            continue;
        };
        assert_eq!(
            OreAes128Bit6ChaCha20::compare_left_to_full(cand, b),
            Some(left.compare_to_full(&full)),
            "raw and typed left-to-full comparators disagree"
        );
    }
}

/// `a` with its first `header` bytes kept and `b` written over the rest.
/// Random pairs almost never both parse; this pair has `a`'s length and
/// header, so when `a` parses it usually does too.
fn overlay(a: &[u8], b: &[u8], header: usize) -> Vec<u8> {
    let mut out = a.to_vec();
    for (o, &x) in out.iter_mut().skip(header).zip(b) {
        *o = x;
    }
    out
}

fuzz_target!(|pair: (&[u8], &[u8])| {
    let (a, b) = pair;
    check::<11>(a);
    check::<6>(a);
    let b2 = overlay(a, b, 4);
    for (x, y) in [(a, b), (a, &b2[..]), (&b2[..], a)] {
        agree::<11>(x, y);
        agree::<6>(x, y);
        agree_left::<11>(x, y);
        agree_left::<6>(x, y);
    }
    let _ = OreAes128Bit6ChaCha20::compare_raw_slices(a, b);
    let _ = OreAes128Bit6ChaCha20::compare_raw_slices(b, a);
    let _ = OreAes128Bit6ChaCha20::compare_left_to_full(a, b);
    let _ = OreAes128Bit6ChaCha20::compare_left_to_full(b, a);
});
