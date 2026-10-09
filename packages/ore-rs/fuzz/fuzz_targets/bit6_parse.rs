#![no_main]

use libfuzzer_sys::fuzz_target;
use ore_rs::scheme::bit2_w6::OreAes128Bit6ChaCha20;
use ore_rs::{CipherText, Left, OreCipher, OreOutput, Right};

// The fixed-width v2 scheme at its two shipped widths (11 blocks for 64-bit
// values, 6 for 32-bit). Parsing untrusted bytes as a full, left-only or
// right-only ciphertext must never panic, anything accepted must re-encode
// to itself, and the raw comparator must answer arbitrary pairs without
// panicking.
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

fuzz_target!(|pair: (&[u8], &[u8])| {
    let (a, b) = pair;
    check::<11>(a);
    check::<6>(a);
    let _ = OreAes128Bit6ChaCha20::compare_raw_slices(a, b);
    let _ = OreAes128Bit6ChaCha20::compare_raw_slices(b, a);
});
