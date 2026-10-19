#![no_main]

use libfuzzer_sys::fuzz_target;
use ore_rs::scheme::bit2::OreAes128;
use ore_rs::OreScheme;
use std::cmp::Ordering;

// The legacy 8-bit-block scheme, whose wire format is frozen and whose rows
// already sit in customer databases. Its comparators infer the block count
// from the length, so every length must be handled: never panic on
// untrusted bytes, a ciphertext is `Equal` to itself whenever it is
// accepted, and the left-to-full comparator agrees with the full-to-full
// one on a full ciphertext's left prefix.
fn consistent(a: &[u8], b: &[u8]) {
    let full = OreAes128::compare_raw_slices(a, b);
    let body = a.len().saturating_sub(16);
    if full.is_some() && body % 49 == 0 {
        let count = body / 49;
        let by_left = OreAes128::compare_left_to_full(&a[..count * 17], b);
        assert_eq!(full, by_left, "left-to-full disagrees with full-to-full");
    }
}

/// `a` with its first `header` bytes kept and `b` written over the rest.
fn overlay(a: &[u8], b: &[u8], header: usize) -> Vec<u8> {
    let mut out = a.to_vec();
    for (o, &x) in out.iter_mut().skip(header).zip(b) {
        *o = x;
    }
    out
}

fuzz_target!(|pair: (&[u8], &[u8])| {
    let (a, b) = pair;
    if let Some(order) = OreAes128::compare_raw_slices(a, a) {
        assert_eq!(order, Ordering::Equal, "a ciphertext is not equal to itself");
    }
    let b2 = overlay(a, b, 0);
    for (x, y) in [(a, b), (a, &b2[..]), (&b2[..], a)] {
        consistent(x, y);
    }
    let _ = OreAes128::compare_raw_slices(b, a);
    let _ = OreAes128::compare_left_to_full(a, b);
    let _ = OreAes128::compare_left_to_full(b, a);
});
