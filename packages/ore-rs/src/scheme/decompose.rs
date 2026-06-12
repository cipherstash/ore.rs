//! Decomposition of canonical plaintext bytes into per-block values.
//!
//! Plaintext canonicalisation (making a value's natural order match
//! lexicographic byte order) lives in `orderable-bytes`. This module handles
//! the next step: splitting those bytes into block values `< DOMAIN` for a
//! given [`super::width::BlockWidth`].
//!
//! - 8-bit: identity — one byte per block.
//! - 6-bit: MSB-first bit-packing — `N` bytes become `ceil(8N / 6)` blocks,
//!   with the final block zero-padded in its low bits. MSB-first packing
//!   preserves lexicographic order, and for fixed-length inputs the trailing
//!   zero padding is order-neutral.
//!
//! The 6-bit packing ships ahead of the Bit6 scheme (v2 plan, PR 5) because
//! it is pure bit logic that can be pinned by property tests now.

// The 6-bit functions are consumed by the Bit6 scheme (v2 plan, PR 5); they
// land early so the packing is pinned by tests independent of that scheme.
#[allow(dead_code)]
/// Number of 6-bit blocks needed for `n` plaintext bytes.
pub(crate) const fn num_blocks_6bit(n: usize) -> usize {
    (8 * n).div_ceil(6)
}

#[allow(dead_code)]
/// Decompose `bytes` MSB-first into 6-bit block values, writing them to
/// `out`. `out.len()` must be exactly `num_blocks_6bit(bytes.len())`.
///
/// Block `i` holds plaintext bits `[6i, 6i + 6)` (bit 0 = MSB of byte 0),
/// so lexicographic order over block values equals lexicographic order over
/// the input bytes.
pub(crate) fn decompose_6bit(bytes: &[u8], out: &mut [u8]) {
    debug_assert_eq!(out.len(), num_blocks_6bit(bytes.len()));

    for (i, slot) in out.iter_mut().enumerate() {
        let bit = 6 * i;
        let byte = bit / 8;
        let offset = bit % 8;

        // Take 6 bits starting at `offset` within `bytes[byte]`, spilling
        // into the next byte (or zero padding past the end).
        let hi = bytes[byte] as u16;
        let lo = *bytes.get(byte + 1).unwrap_or(&0) as u16;
        let window = (hi << 8) | lo;

        *slot = ((window >> (10 - offset)) & 0x3f) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        /// MSB-first 6-bit packing preserves lexicographic order for
        /// equal-length inputs.
        fn order_preserved_u64(x: u64, y: u64) -> bool {
            let xb = x.to_be_bytes();
            let yb = y.to_be_bytes();
            let mut xq = [0u8; num_blocks_6bit(8)];
            let mut yq = [0u8; num_blocks_6bit(8)];
            decompose_6bit(&xb, &mut xq);
            decompose_6bit(&yb, &mut yq);

            xb.cmp(&yb) == xq.cmp(&yq)
        }

        /// Every block value is in the 6-bit domain.
        fn blocks_in_domain(bytes: Vec<u8>) -> bool {
            let mut out = vec![0u8; num_blocks_6bit(bytes.len())];
            decompose_6bit(&bytes, &mut out);
            out.iter().all(|&b| b < 64)
        }

        /// Decomposition is injective: it can be inverted by re-concatenating
        /// the 6-bit values and truncating to the original bit length.
        fn roundtrip(bytes: Vec<u8>) -> bool {
            let mut out = vec![0u8; num_blocks_6bit(bytes.len())];
            decompose_6bit(&bytes, &mut out);

            let mut rebuilt = vec![0u8; bytes.len()];
            for (i, &v) in out.iter().enumerate() {
                let bit = 6 * i;
                let byte = bit / 8;
                let offset = bit % 8;
                let window = (v as u16) << (10 - offset);
                rebuilt[byte] |= (window >> 8) as u8;
                if byte + 1 < rebuilt.len() {
                    rebuilt[byte + 1] |= (window & 0xff) as u8;
                }
            }
            rebuilt == bytes
        }
    }

    #[test]
    fn block_counts() {
        assert_eq!(num_blocks_6bit(4), 6); // u32: 32 bits -> 6 blocks
        assert_eq!(num_blocks_6bit(8), 11); // u64: 64 bits -> 11 blocks
        assert_eq!(num_blocks_6bit(14), 19); // Decimal
        assert_eq!(num_blocks_6bit(16), 22); // u128
        assert_eq!(num_blocks_6bit(0), 0);
    }

    #[test]
    fn known_packing() {
        // Bit stream 11111100 00001111 -> 111111 | 000000 | 1111 + 2 pad bits
        let mut out = [0u8; 3];
        decompose_6bit(&[0b1111_1100, 0b0000_1111], &mut out);
        assert_eq!(out, [0b111111, 0b000000, 0b111100]);
    }
}
