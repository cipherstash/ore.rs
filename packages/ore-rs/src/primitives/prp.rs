pub mod prng;
use crate::primitives::prp::prng::Aes128Prng;
use crate::primitives::{AesBlock, Prp, PrpError, PrpResult};
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
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

// The legacy bit2 scheme (256) is wire-frozen on the Knuth shuffle. New
// schemes use [`LemireFyPrp`] below; no other domain is instantiated here.
impl_knuth_shuffle_prp!(256, crate::primitives::simd::gt_mask_xor_256);

/// PRP over a small domain via a Fisher–Yates shuffle driven by a fixed
/// number of **wide draws** — full 64-bit values reduced to range by
/// Lemire's multiply-high (`(x * range) >> 64`) — with the randomness
/// produced by AES-CTR under the 16-byte seed. Same field/method
/// semantics as [`KnuthShufflePRP`] (`permute` ↦ `inverse`, `invert` and
/// the indicator mask ↦ `permutation`).
///
/// Contrast with [`KnuthShufflePRP`], which draws single bytes and uses
/// **rejection sampling** to avoid modulo bias: there the number of draws
/// (and PRNG buffer regenerations, and branches taken) depends on the
/// seed, and the seed is `PRF(plaintext prefix)`, so PRP construction time
/// is weakly plaintext-dependent — a timing side-channel. This construction
/// has a seed-independent, branch-free draw count, closing that channel,
/// and is ~9× faster (no rejection loop, no `%`, just multiply-high).
///
/// Uniformity: each Lemire reduction to range `m` deviates from uniform by
/// at most `m / 2^64`; over the `N-1` draws the output permutation is within
/// statistical distance `< 2^-55` (for `N = 64`) of a uniformly random
/// permutation — exactly the object Lewi-Wu's analysis assumes. That is a
/// pure statistical term on top of the scheme's existing PRF advantage: no
/// new assumption, no new idealised model.
///
/// New (non-wire-frozen) schemes only.
///
/// Layout note (constant-time): key generation performs two secret-indexed
/// writes — the Fisher–Yates `permutation.swap(i, j)` (secret `j`) and the
/// `inverse[val] = …` fill (secret `val`). The one-cache-line argument that
/// defends these (any access within a single 64-byte line leaks nothing
/// through the cache) requires each table to occupy exactly one line. At
/// `N = 64` each `[u8; N]` is 64 bytes, so `#[repr(C, align(64))]` places
/// `permutation` at offset 0 (line 0) and `inverse` at offset 64 (line 1):
/// `repr(C)` pins field order (default `repr(Rust)` may reorder), `align(64)`
/// puts the struct on a cache-line boundary. The argument only holds for
/// `N ≤ 64`; the sole instantiation is `LemireFyPrp<64>`.
///
/// **Under review** — see `docs/reviews/2026-06-14-ore-v2-crypto-review-brief.md`
/// (A4). If the cache-line argument is rejected, this is replaced by a strictly
/// constant-time (oblivious-swap) construction.
#[derive(Zeroize)]
#[repr(C, align(64))]
pub struct LemireFyPrp<const N: usize> {
    permutation: [u8; N],
    inverse: [u8; N],
}

impl<const N: usize> Drop for LemireFyPrp<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const N: usize> ZeroizeOnDrop for LemireFyPrp<N> {}

/// Implements `Prp<u8>` for [`LemireFyPrp`] over `$domain` elements, drawing
/// `$domain - 1` wide values from `$stream_blocks` AES-CTR blocks
/// (`$stream_blocks == ((($domain - 1) * 8) + 15) / 16`). `$gt_mask` is the
/// bulk indicator kernel for the domain.
macro_rules! impl_lemire_fy_prp {
    ($domain:literal, $stream_blocks:literal, $gt_mask:path) => {
        // The one-cache-line constant-time argument for the secret-indexed
        // key-generation writes (see the struct docs / review brief A4) holds
        // only when each `[u8; N]` table fits a single 64-byte cache line. A
        // larger domain silently spans multiple lines and loses the property,
        // so make it a compile error rather than a comment.
        const _: () = assert!(
            $domain <= 64,
            "LemireFyPrp: the one-cache-line constant-time argument requires domain <= 64"
        );

        impl LemireFyPrp<$domain> {
            /// Build the permutation directly from a precomputed draw stream
            /// (shape (ii)): `stream` must be at least `($domain - 1) * 8`
            /// bytes, consumed as `$domain - 1` little-endian u64 draws and
            /// Lemire-reduced. The chained scheme feeds the CMAC accumulator's
            /// `PRP_STREAM` branch here, avoiding a per-block AES key schedule.
            pub(crate) fn from_stream(stream: &[u8]) -> PrpResult<Self> {
                if stream.len() < ($domain - 1) * 8 {
                    return Err(PrpError);
                }

                let mut perm = Self {
                    permutation: [0u8; $domain],
                    inverse: [0u8; $domain],
                };
                for (i, p) in perm.permutation.iter_mut().enumerate() {
                    *p = i as u8;
                }

                // Fisher–Yates with Lemire-reduced wide draws: draw `d`
                // (8 bytes) drives step `i`. Fixed trip count, branch-free
                // index reduction (the swap address is secret — defended by
                // the single-cache-line argument; the table is `$domain`
                // bytes).
                for i in (1..$domain).rev() {
                    let d = $domain - 1 - i;
                    let mut draw = [0u8; 8];
                    draw.copy_from_slice(&stream[d * 8..d * 8 + 8]);
                    let x = u64::from_le_bytes(draw);
                    let j = ((x as u128 * (i as u128 + 1)) >> 64) as usize;
                    perm.permutation.swap(i, j);
                }

                for (index, val) in perm.permutation.iter().enumerate() {
                    perm.inverse[*val as usize] = index as u8;
                }

                Ok(perm)
            }
        }

        impl Prp<u8> for LemireFyPrp<$domain> {
            fn new(key: &[u8]) -> PrpResult<Self> {
                if key.len() < 16 {
                    return Err(PrpError);
                }

                // Fixed-count AES-CTR keystream from the seed: counter in
                // the first 4 bytes (big-endian), matching the existing
                // PRNG's counter convention. Shape (i): a fresh key schedule
                // per call. Shape (ii) skips this via `from_stream`.
                let cipher = Aes128::new(GenericArray::from_slice(&key[0..16]));
                let mut blocks = [AesBlock::default(); $stream_blocks];
                for (i, b) in blocks.iter_mut().enumerate() {
                    b[0..4].copy_from_slice(&(i as u32).to_be_bytes());
                }
                cipher.encrypt_blocks(&mut blocks);

                let mut stream = [0u8; $stream_blocks * 16];
                for (i, b) in blocks.iter().enumerate() {
                    stream[i * 16..(i + 1) * 16].copy_from_slice(b);
                }

                let perm = Self::from_stream(&stream)?;

                // The keystream determined the permutation — wipe it.
                stream.zeroize();
                for b in blocks.iter_mut() {
                    b.as_mut_slice().zeroize();
                }

                Ok(perm)
            }

            fn permute(&self, input: u8) -> PrpResult<u8> {
                match self.inverse.get(usize::from(input)) {
                    Some(i) => Ok(*i),
                    None => Err(PrpError),
                }
            }

            fn invert(&self, input: u8) -> PrpResult<u8> {
                match self.permutation.get(usize::from(input)) {
                    Some(i) => Ok(*i),
                    None => Err(PrpError),
                }
            }

            fn indicator_mask_xor(&self, data: u8, out: &mut [u8]) {
                debug_assert_eq!(out.len() * 8, $domain);
                $gt_mask(&self.permutation, data, out);
            }
        }
    };
}

impl_lemire_fy_prp!(64, 32, crate::primitives::simd::gt_mask_xor_64);

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

    // -----------------------------------------------------------------
    // LemireFyPrp (Bit6 PRP)
    // -----------------------------------------------------------------

    fn init_fy(seed_byte: u8) -> LemireFyPrp<64> {
        Prp::new(&[seed_byte; 16]).unwrap()
    }

    #[test]
    fn fy_is_a_permutation_and_round_trips() {
        for seed in 0u8..32 {
            let prp = init_fy(seed);
            // Every value 0..64 appears exactly once in `permutation`.
            let mut seen = [false; 64];
            for v in 0..64u8 {
                let mapped = prp.invert(v).unwrap();
                assert!(mapped < 64);
                assert!(
                    !seen[mapped as usize],
                    "value {} repeated (seed {})",
                    mapped, seed
                );
                seen[mapped as usize] = true;
            }
            // Forward/inverse round-trip both directions.
            for v in 0..64u8 {
                assert_eq!(v, prp.invert(prp.permute(v).unwrap()).unwrap());
                assert_eq!(v, prp.permute(prp.invert(v).unwrap()).unwrap());
            }
        }
    }

    #[test]
    fn fy_is_deterministic() {
        let a = init_fy(7);
        let b = init_fy(7);
        for v in 0..64u8 {
            assert_eq!(a.permute(v).unwrap(), b.permute(v).unwrap());
        }
        // A different seed gives a different permutation (overwhelmingly).
        let c = init_fy(8);
        assert!((0..64u8).any(|v| a.permute(v).unwrap() != c.permute(v).unwrap()));
    }

    #[test]
    fn fy_rejects_short_key() {
        assert!(<LemireFyPrp<64> as Prp<u8>>::new(&[0u8; 8]).is_err());
    }

    quickcheck! {
        /// The bulk indicator mask must agree with the per-bit reference for
        /// the Bit6 PRP too (guards the gt_mask_xor_64 kernel path).
        fn fy_indicator_mask_matches_reference(key: Vec<u8>, x: u8) -> quickcheck::TestResult {
            if key.len() < 16 {
                return quickcheck::TestResult::discard();
            }
            let prp: LemireFyPrp<64> = Prp::new(&key[0..16]).unwrap();

            let mut mask = [0u8; 8];
            prp.indicator_mask_xor(x, &mut mask);

            let mut reference = [0u8; 8];
            for j in 0..64u8 {
                let indicator = u8::from(prp.invert(j).unwrap() > x);
                reference[(j / 8) as usize] |= indicator << (j % 8);
            }

            quickcheck::TestResult::from_bool(mask == reference)
        }
    }
}
