#![no_main]

use libfuzzer_sys::fuzz_target;
use ore_rs::scheme::chained::OreAes128Bit6Chained;
use ore_rs::OreScheme;
use std::cmp::Ordering;

// Ciphertexts are read back from storage, so the comparators parse untrusted
// bytes: they must never panic (the block count is read from the header and
// drives every slice index), and anything accepted as a full ciphertext is
// `Equal` to itself, and to its own left prefix through the query comparator.
fuzz_target!(|data: &[u8]| {
    let Some(order) = OreAes128Bit6Chained::compare_raw_slices(data, data) else {
        return;
    };
    assert_eq!(order, Ordering::Equal, "a ciphertext is not equal to itself");
    // `header(7) ‖ xt(count) ‖ f(16·count)` is the left prefix.
    let count = u16::from_be_bytes([data[2], data[3]]) as usize;
    let left = &data[..7 + count * 17];
    assert_eq!(
        OreAes128Bit6Chained::compare_left_to_full(left, data),
        Some(Ordering::Equal),
        "a ciphertext's left prefix is not equal to it"
    );
});
