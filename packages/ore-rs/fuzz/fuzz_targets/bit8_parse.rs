#![no_main]

use libfuzzer_sys::fuzz_target;
use ore_rs::scheme::bit2::OreAes128ChaCha20;
use ore_rs::{CipherText, Left, OreCipher, OreOutput, Right};

// The legacy 8-bit-block scheme, whose wire format is frozen and whose rows
// already sit in customer databases. Same contract as the v2 targets, for
// the full, left-only and right-only parsers:
// never panic on untrusted bytes, accepted bytes round-trip, the raw
// comparator answers any pair.
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

fuzz_target!(|pair: (&[u8], &[u8])| {
    let (a, b) = pair;
    check::<8>(a);
    check::<4>(a);
    let _ = OreAes128ChaCha20::compare_raw_slices(a, b);
    let _ = OreAes128ChaCha20::compare_raw_slices(b, a);
});
