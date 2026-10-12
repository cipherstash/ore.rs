#![no_main]

use libfuzzer_sys::fuzz_target;
use ore_rs::scheme::bit2::OreAes128ChaCha20;
use ore_rs::{CipherText, Left, OreCipher, OreOutput, Right};

// The legacy 8-bit-block scheme, whose wire format is frozen and whose rows
// already sit in customer databases. Same contract as the v2 targets, for
// the full, left-only and right-only parsers:
// never panic on untrusted bytes, accepted bytes round-trip, the raw
// comparator answers any pair and agrees with the typed `Ord`.
fn check<const N: usize>(data: &[u8]) {
    if let Ok(ct) = CipherText::<OreAes128ChaCha20, N>::from_slice(data) {
        assert_eq!(
            ct.to_bytes(),
            data,
            "accepted full ciphertext did not round-trip"
        );
    }
    if let Ok(left) = Left::<OreAes128ChaCha20, N>::from_slice(data) {
        assert_eq!(
            left.to_bytes(),
            data,
            "accepted left ciphertext did not round-trip"
        );
    }
    if let Ok(right) = Right::<OreAes128ChaCha20, N>::from_slice(data) {
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
        CipherText::<OreAes128ChaCha20, N>::from_slice(a),
        CipherText::<OreAes128ChaCha20, N>::from_slice(b),
    ) else {
        return;
    };
    assert_eq!(
        OreAes128ChaCha20::compare_raw_slices(a, b),
        Some(ct_a.cmp(&ct_b)),
        "raw and typed comparators disagree"
    );
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
    check::<8>(a);
    check::<4>(a);
    let b2 = overlay(a, b, 0);
    for (x, y) in [(a, b), (a, &b2[..]), (&b2[..], a)] {
        agree::<8>(x, y);
        agree::<4>(x, y);
    }
    let _ = OreAes128ChaCha20::compare_raw_slices(a, b);
    let _ = OreAes128ChaCha20::compare_raw_slices(b, a);
});
