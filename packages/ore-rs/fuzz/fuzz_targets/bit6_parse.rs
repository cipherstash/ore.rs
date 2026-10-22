#![no_main]

use libfuzzer_sys::fuzz_target;
use ore_rs::scheme::bit2_w6::OreAes128Bit6;
use ore_rs::OreScheme;
use std::cmp::Ordering;

// The fixed-width v2 scheme's comparators take raw stored bytes and index
// into them by the block count the header declares. Arbitrary byte pairs
// must never panic: a malformed side is answered with `None`. A full
// ciphertext compared with itself is `Equal` whenever it is accepted, and a
// left ciphertext is its full's prefix, so the left-to-full comparator must
// agree with the full-to-full one on that prefix. Antisymmetry is not
// asserted; it holds only for genuine ciphertexts.
fn consistent(a: &[u8], b: &[u8]) {
    let full = OreAes128Bit6::compare_raw_slices(a, b);
    if let Some(count) = header_count(a) {
        let left_len = 4 + count * 17;
        if a.len() >= left_len {
            let by_left = OreAes128Bit6::compare_left_to_full(&a[..left_len], b);
            if full.is_some() {
                assert_eq!(full, by_left, "left-to-full disagrees with full-to-full");
            }
        }
    }
}

/// The block count a v2 header declares, if the bytes have one.
fn header_count(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 4 || bytes[0] != 0x02 || bytes[1] != 0x02 {
        return None;
    }
    Some(u16::from_be_bytes([bytes[2], bytes[3]]) as usize)
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
    if let Some(order) = OreAes128Bit6::compare_raw_slices(a, a) {
        assert_eq!(order, Ordering::Equal, "a ciphertext is not equal to itself");
    }
    let b2 = overlay(a, b, 4);
    for (x, y) in [(a, b), (a, &b2[..]), (&b2[..], a)] {
        consistent(x, y);
    }
    let _ = OreAes128Bit6::compare_raw_slices(b, a);
    let _ = OreAes128Bit6::compare_left_to_full(a, b);
    let _ = OreAes128Bit6::compare_left_to_full(b, a);
});
