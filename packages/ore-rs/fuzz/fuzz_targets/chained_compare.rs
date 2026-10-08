#![no_main]

use libfuzzer_sys::fuzz_target;
use ore_rs::scheme::chained::OreAes128Bit6ChainedChaCha20;

// Both comparators take raw stored bytes and index into them by the block
// count each header declares. Arbitrary byte pairs must never panic: a
// malformed side is answered with `None`. No ordering property is asserted
// here, because antisymmetry only holds for genuine ciphertexts, not for
// arbitrary right halves.
fuzz_target!(|pair: (&[u8], &[u8])| {
    let (a, b) = pair;
    let _ = OreAes128Bit6ChainedChaCha20::compare_raw_slices(a, b);
    let _ = OreAes128Bit6ChainedChaCha20::compare_raw_slices(b, a);
    let _ = OreAes128Bit6ChainedChaCha20::compare_left_to_full(a, b);
    let _ = OreAes128Bit6ChainedChaCha20::compare_left_to_full(b, a);
});
