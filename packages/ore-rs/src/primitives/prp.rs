pub mod prng;
use crate::primitives::prp::prng::Aes128Prng;
use crate::primitives::{Prp, PrpError, PrpResult};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize)]
pub struct KnuthShufflePRP<T: Zeroize, const N: usize> {
    permutation: [T; N],
    inverse: [T; N],
}

// For some reason ZeroizeOnDrop doesn't work - so manually do it
impl<T: Zeroize, const N: usize> Drop for KnuthShufflePRP<T, N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Impl the ZeroizeOnDrop marker trait since we're zeroizing above
impl<T: Zeroize, const N: usize> ZeroizeOnDrop for KnuthShufflePRP<T, N> {}

/// Implements `Prp<u8>` for a Knuth-shuffle PRP over a `$domain`-element
/// space (`$domain ≤ 256`), with `$gt_mask` as the bulk indicator kernel.
/// The shuffle algorithm and PRNG byte consumption are identical across
/// domains; only the iteration bounds change. For the 256 domain this is
/// wire-frozen (the legacy bit2 scheme); other domains are used by new
/// schemes only.
macro_rules! impl_knuth_shuffle_prp {
    ($domain:literal, $gt_mask:path) => {
        impl Prp<u8> for KnuthShufflePRP<u8, $domain> {
            /*
             * Initialize a ($domain element) PRP using a KnuthShuffle
             * seeded from a 16-byte key
             */
            fn new(key: &[u8]) -> PrpResult<Self> {
                let mut rng = Aes128Prng::init(key); // TODO: Use Result type here, too

                let mut perm = Self {
                    permutation: [0u8; $domain],
                    inverse: [0u8; $domain],
                };

                // Initialize values
                for i in 0..$domain {
                    perm.permutation[i] = i as u8;
                }

                // Iterations stop at i = 1: the i = 0 step always
                // degenerates to `swap(0, 0)` after drawing
                // rejection-sampled bytes until one is zero (expected 256
                // draws — a full PRNG regeneration), and the RNG is dropped
                // right after this loop, so skipping it consumes no
                // observable state and yields a byte-identical permutation.
                (1..$domain).rev().for_each(|i| {
                    let j = rng.gen_range(i as u8);
                    perm.permutation.swap(i, j as usize);
                });

                for (index, val) in perm.permutation.iter().enumerate() {
                    perm.inverse[*val as usize] = index as u8;
                }

                Ok(perm)
            }

            /*
             * Permutes a number under the Pseudo-Random Permutation in constant time.
             *
             * Forward permutations are only used once in the ORE scheme so this is OK
             */
            fn permute(&self, input: u8) -> PrpResult<u8> {
                let index = usize::from(input);

                match self.inverse.get(index) {
                    Some(i) => Ok(*i),
                    None => Err(PrpError),
                }
            }

            /*
             * Performs the inverse permutation in constant time.
             */
            fn invert(&self, input: u8) -> PrpResult<u8> {
                let index = usize::from(input);

                // Forward an inverse permutations are reversed for historical reasons
                match self.permutation.get(index) {
                    Some(i) => Ok(*i),
                    None => Err(PrpError),
                }
            }

            fn indicator_mask_xor(&self, data: u8, out: &mut [u8]) {
                debug_assert_eq!(out.len() * 8, $domain);

                // `invert(j)` is `self.permutation[j]` (see `invert`
                // above), so the mask is one pass over the table: a
                // bytewise `> data` compare packed to bits — vectorised
                // where the target supports it.
                $gt_mask(&self.permutation, data, out);
            }
        }
    };
}

impl_knuth_shuffle_prp!(256, crate::primitives::simd::gt_mask_xor_256);
impl_knuth_shuffle_prp!(64, crate::primitives::simd::gt_mask_xor_64);

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn init_prp() -> PrpResult<KnuthShufflePRP<u8, 256>> {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0eaa");
        Prp::new(&key)
    }

    quickcheck! {
        /// The bulk indicator mask must agree with the naive per-bit
        /// reference: bit j = (invert(j) > x). This is the regression guard
        /// for `indicator_mask_xor` (and, later, its SIMD overrides).
        fn indicator_mask_matches_reference(key: Vec<u8>, x: u8) -> quickcheck::TestResult {
            if key.len() < 16 {
                return quickcheck::TestResult::discard();
            }
            let prp: KnuthShufflePRP<u8, 256> = Prp::new(&key[0..16]).unwrap();

            let mut mask = [0u8; 32];
            prp.indicator_mask_xor(x, &mut mask);

            let mut reference = [0u8; 32];
            for j in 0..=255u8 {
                let indicator = u8::from(prp.invert(j).unwrap() > x);
                reference[(j / 8) as usize] |= indicator << (j % 8);
            }

            quickcheck::TestResult::from_bool(mask == reference)
        }
    }

    #[test]
    fn test_invert() -> Result<(), PrpError> {
        let prp = init_prp()?;

        for i in 0..=255 {
            assert_eq!(
                i,
                prp.invert(prp.permute(i)?)?,
                "permutation round-trip failed"
            );
        }

        Ok(())
    }
}
