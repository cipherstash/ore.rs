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

use crate::primitives::{PrpError, Symbol};
use crate::OreError;

/// Number of 6-bit blocks needed for `n` plaintext bytes.
pub(crate) const fn num_blocks_6bit(n: usize) -> usize {
    (8 * n).div_ceil(6)
}

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

/// 6-bit block values, each `< 64` by construction, in any byte storage
/// (`[u8; N]` for Bit6, `Vec<u8>` for the chained scheme).
///
/// There are two ways to make one. [`Self::decompose`] masks every value to
/// six bits as it packs, so it never branches on the plaintext; the
/// `OreEncrypt` and string paths use it. [`Self::check`] validates blocks a
/// caller passes in directly and branches once on the result. The encryptors
/// take a `Blocks6`, so the PRP gets an in-domain [`Symbol`] without a
/// per-block range check on the secret.
pub(crate) struct Blocks6<B>(B);

impl<B: AsRef<[u8]>> Blocks6<B> {
    /// Accept `blocks` if every value is `< 64`, else
    /// [`OreError::PrpError`] (the error an out-of-domain symbol has always
    /// produced). The values are folded together branch-free and the one
    /// branch is on the folded result, so for well-formed input the branch
    /// always goes the same way.
    pub(crate) fn check(blocks: B) -> Result<Self, OreError> {
        let high = blocks.as_ref().iter().fold(0u8, |acc, &b| acc | (b >> 6));
        if high != 0 {
            return Err(OreError::PrpError(PrpError));
        }
        Ok(Self(blocks))
    }

    /// The block values as bytes.
    #[inline]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Block `i` as a PRP symbol. `from_low_bits` is the identity here (the
    /// value is `< 64`), and does not branch.
    #[inline]
    pub(crate) fn symbol(&self, i: usize) -> Symbol<64> {
        Symbol::from_low_bits(self.0.as_ref()[i])
    }

    /// The number of blocks.
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.0.as_ref().len()
    }

    /// The underlying storage.
    #[inline]
    pub(crate) fn inner(&self) -> &B {
        &self.0
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> Blocks6<B> {
    /// Decompose `bytes` into `out` (see [`decompose_6bit`]).
    /// `out.as_ref().len()` must be `num_blocks_6bit(bytes.len())`.
    pub(crate) fn decompose(bytes: &[u8], mut out: B) -> Self {
        decompose_6bit(bytes, out.as_mut());
        Self(out)
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
    fn blocks6_check_accepts_exactly_the_domain() {
        assert!(Blocks6::check([0u8, 63, 17]).is_ok());
        assert!(matches!(
            Blocks6::check([0u8, 64, 17]),
            Err(OreError::PrpError(_))
        ));
        assert!(Blocks6::check([255u8]).is_err());
        assert!(Blocks6::check(Vec::<u8>::new()).is_ok());
    }

    #[test]
    fn known_packing() {
        // Bit stream 11111100 00001111 -> 111111 | 000000 | 1111 + 2 pad bits
        let mut out = [0u8; 3];
        decompose_6bit(&[0b1111_1100, 0b0000_1111], &mut out);
        assert_eq!(out, [0b111111, 0b000000, 0b111100]);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Inputs up to this many bytes are covered by the bounded harnesses.
    const MAX_LEN: usize = 16;
    /// `num_blocks_6bit(MAX_LEN)`.
    const MAX_BLOCKS: usize = 22;

    /// Bit `k` (MSB-first) of `bytes`, or 0 past the end.
    fn input_bit(bytes: &[u8], k: usize) -> u8 {
        if k / 8 < bytes.len() {
            (bytes[k / 8] >> (7 - k % 8)) & 1
        } else {
            0
        }
    }

    /// `num_blocks_6bit(n)` is the least `b` with `6b >= 8n`, for every `n`
    /// with `8n` representable in `usize` (full domain of non-overflowing `n`).
    #[kani::proof]
    fn num_blocks_6bit_is_ceil_8n_over_6() {
        let n: usize = kani::any();
        kani::assume(n <= usize::MAX / 8);
        let b = num_blocks_6bit(n);
        assert!(6 * (b as u128) >= 8 * (n as u128));
        if b > 0 {
            assert!(6 * ((b - 1) as u128) < 8 * (n as u128));
        }
    }

    /// For every input of length `0..=16`: every output symbol is `< 64`, and
    /// bit `5 - t` of block `i` is plaintext bit `6i + t` (MSB-first, zero
    /// past the end) — the exact packing spec, which implies round-trip.
    #[kani::proof]
    #[kani::unwind(23)]
    fn decompose_6bit_matches_bit_spec() {
        let buf: [u8; MAX_LEN] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX_LEN);
        let bytes = &buf[..len];
        let nb = num_blocks_6bit(len);
        let mut out_buf = [0u8; MAX_BLOCKS];
        let out = &mut out_buf[..nb];
        decompose_6bit(bytes, out);

        let i: usize = kani::any();
        kani::assume(i < nb);
        assert!(out[i] < 64);
        let t: usize = kani::any();
        kani::assume(t < 6);
        assert_eq!((out[i] >> (5 - t)) & 1, input_bit(bytes, 6 * i + t));
    }

    /// For any two inputs of lengths `0..=16`, equal decompositions (same
    /// block count and same symbols) imply equal inputs: decomposition is
    /// injective on that domain.
    #[kani::proof]
    #[kani::unwind(23)]
    fn decompose_6bit_injective() {
        let a_buf: [u8; MAX_LEN] = kani::any();
        let b_buf: [u8; MAX_LEN] = kani::any();
        let a_len: usize = kani::any();
        let b_len: usize = kani::any();
        kani::assume(a_len <= MAX_LEN && b_len <= MAX_LEN);
        let a = &a_buf[..a_len];
        let b = &b_buf[..b_len];

        let mut a_out = [0u8; MAX_BLOCKS];
        let mut b_out = [0u8; MAX_BLOCKS];
        let a_nb = num_blocks_6bit(a_len);
        let b_nb = num_blocks_6bit(b_len);
        decompose_6bit(a, &mut a_out[..a_nb]);
        decompose_6bit(b, &mut b_out[..b_nb]);

        if a_out[..a_nb] == b_out[..b_nb] {
            assert!(a == b);
        }
    }

    /// For any two inputs of the same length `0..=16`, lexicographic order
    /// of the block values equals lexicographic order of the bytes.
    #[kani::proof]
    #[kani::unwind(23)]
    fn decompose_6bit_preserves_order() {
        let a_buf: [u8; MAX_LEN] = kani::any();
        let b_buf: [u8; MAX_LEN] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX_LEN);
        let a = &a_buf[..len];
        let b = &b_buf[..len];
        let nb = num_blocks_6bit(len);
        let mut a_out = [0u8; MAX_BLOCKS];
        let mut b_out = [0u8; MAX_BLOCKS];
        decompose_6bit(a, &mut a_out[..nb]);
        decompose_6bit(b, &mut b_out[..nb]);
        assert!(a.cmp(b) == a_out[..nb].cmp(&b_out[..nb]));
    }
}
