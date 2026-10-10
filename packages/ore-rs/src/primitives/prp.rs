pub(crate) mod oblivious;
pub mod prng;
use crate::primitives::prp::prng::Aes128Prng;
use crate::primitives::{AesBlock, Prp, PrpError, PrpResult, Symbol};
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Read `table[index]` without a secret-dependent memory access: every
/// entry is read and the wanted one selected in constant time. `index` is
/// a plaintext symbol (`permute`) or a candidate (`invert`); an aligned
/// table only defends cache-line granularity, and sub-line timing would
/// otherwise reveal which part of the table was read.
///
/// `index` is in range by type, so there is no range check to branch on.
/// The tables are permutations of `0..D`, so every entry is itself a symbol;
/// `from_low_bits` is the identity on it.
#[inline]
fn oblivious_lookup<const D: usize>(table: &[u8; D], index: Symbol<D>) -> Symbol<D> {
    Symbol::from_low_bits(crate::scheme::width::ct_select_byte(
        table,
        usize::from(index.get()),
    ))
}

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
        impl Prp<Symbol<$domain>> for KnuthShufflePRP<u8, $domain> {
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
            fn permute(&self, input: Symbol<$domain>) -> Symbol<$domain> {
                oblivious_lookup(&self.inverse, input)
            }

            /*
             * Performs the inverse permutation in constant time.
             */
            fn invert(&self, input: Symbol<$domain>) -> Symbol<$domain> {
                // Forward and inverse permutations are reversed for historical reasons
                oblivious_lookup(&self.permutation, input)
            }

            fn indicator_mask_xor(&self, data: Symbol<$domain>, out: &mut [u8]) {
                debug_assert_eq!(out.len() * 8, $domain);

                // `invert(j)` is `self.permutation[j]` (see `invert`
                // above), so the mask is one pass over the table: a
                // bytewise `> data` compare packed to bits — vectorised
                // where the target supports it.
                $gt_mask(&self.permutation, data.get(), out);
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
/// Constant-time construction: key generation goes through the oblivious
/// builders in [`oblivious`] (NEON on aarch64, SSSE3 on x86_64 when the CPU
/// has it, portable SWAR elsewhere), which never use a secret value as a
/// memory address. Textbook Fisher–Yates swaps at the secret draw-derived
/// index and fills `inverse` at the secret permutation values; those
/// offsets stay within one cache line, but dudect measured a timing
/// dependence on the swap sequence on Apple M4, which the one-cache-line
/// argument does not cover (review brief A4). The oblivious builders apply
/// the same draws and swaps, so the tables, and every ciphertext, are
/// byte-identical to the textbook form's.
///
/// Layout: `#[repr(C, align(64))]` places `permutation` at offset 0 (line 0)
/// and `inverse` at offset 64 (line 1); `repr(C)` pins field order and
/// `align(64)` puts the struct on a cache-line boundary. The lookups
/// (`permute`, `invert`) read every entry either way.
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
        // The oblivious builders are written for exactly 64 entries (four
        // 16-byte registers, eight 64-bit words per table); make another
        // domain a compile error rather than a type mismatch deep inside.
        const _: () = assert!(
            $domain == oblivious::DOMAIN,
            "LemireFyPrp: the oblivious builders are written for a 64-entry domain"
        );

        impl LemireFyPrp<$domain> {
            /// Build the permutation directly from a precomputed draw stream
            /// (shape (ii)): `stream` must be at least `($domain - 1) * 8`
            /// bytes, consumed as `$domain - 1` little-endian u64 draws and
            /// Lemire-reduced. The chained scheme feeds the CMAC accumulator's
            /// `PRP_STREAM` branch here, avoiding a per-block AES key schedule;
            /// [`Prp::new`] feeds it an AES-CTR keystream. Either way the
            /// tables come from the oblivious builder ([`oblivious::build`]),
            /// so no address depends on the stream.
            pub(crate) fn from_stream(stream: &[u8]) -> PrpResult<Self> {
                // Fisher–Yates with Lemire-reduced wide draws: draw `d`
                // (8 bytes) drives step `$domain - 1 - d`. Fixed trip count,
                // branch-free index reduction, and no secret-dependent
                // address: the oblivious builder keeps both tables in
                // registers (or masked words) and maintains the inverse
                // alongside the swaps. It wipes its copies of each draw.
                Self::from_stream_with(stream, oblivious::build)
            }

            /// [`Self::from_stream`] through a given builder. The schemes
            /// only ever use [`oblivious::build`]; the `ct-bench` timing
            /// hooks pass the reference builder or a portable oblivious one,
            /// so they time this same function. `build` is a generic
            /// parameter, not a function pointer, so the scheme path is
            /// monomorphised and the builder still inlines.
            pub(crate) fn from_stream_with<F>(stream: &[u8], build: F) -> PrpResult<Self>
            where
                F: FnOnce(&[u8], &mut [u8; $domain], &mut [u8; $domain]),
            {
                if stream.len() < ($domain - 1) * 8 {
                    return Err(PrpError);
                }
                let mut perm = Self {
                    permutation: [0u8; $domain],
                    inverse: [0u8; $domain],
                };
                build(stream, &mut perm.permutation, &mut perm.inverse);
                Ok(perm)
            }
        }

        impl Prp<Symbol<$domain>> for LemireFyPrp<$domain> {
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

            fn permute(&self, input: Symbol<$domain>) -> Symbol<$domain> {
                oblivious_lookup(&self.inverse, input)
            }

            fn invert(&self, input: Symbol<$domain>) -> Symbol<$domain> {
                oblivious_lookup(&self.permutation, input)
            }

            fn indicator_mask_xor(&self, data: Symbol<$domain>, out: &mut [u8]) {
                debug_assert_eq!(out.len() * 8, $domain);
                $gt_mask(&self.permutation, data.get(), out);
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
            prp.indicator_mask_xor(Symbol::from(x), &mut mask);

            let mut reference = [0u8; 32];
            for j in 0..=255u8 {
                let indicator = u8::from(prp.invert(Symbol::from(j)).get() > x);
                reference[(j / 8) as usize] |= indicator << (j % 8);
            }

            quickcheck::TestResult::from_bool(mask == reference)
        }
    }

    #[test]
    fn test_invert() -> Result<(), PrpError> {
        let prp = init_prp()?;

        for i in 0..=255u8 {
            let i = Symbol::from(i);
            assert_eq!(
                i,
                prp.invert(prp.permute(i)),
                "permutation round-trip failed"
            );
        }

        Ok(())
    }

    // -----------------------------------------------------------------
    // LemireFyPrp (Bit6 PRP)
    // -----------------------------------------------------------------

    fn sym64(v: u8) -> Symbol<64> {
        assert!(v < 64, "test symbol in 0..64");
        Symbol::from_low_bits(v)
    }

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
                let mapped = prp.invert(sym64(v)).get();
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
                let v = sym64(v);
                assert_eq!(v, prp.invert(prp.permute(v)));
                assert_eq!(v, prp.permute(prp.invert(v)));
            }
        }
    }

    #[test]
    fn fy_is_deterministic() {
        let a = init_fy(7);
        let b = init_fy(7);
        for v in 0..64u8 {
            assert_eq!(a.permute(sym64(v)), b.permute(sym64(v)));
        }
        // A different seed gives a different permutation (overwhelmingly).
        let c = init_fy(8);
        assert!((0..64u8).any(|v| a.permute(sym64(v)) != c.permute(sym64(v))));
    }

    /// `from_stream` rejects every stream shorter than 63 * 8 bytes and
    /// accepts the first full length. Exhaustive over the 504 short lengths;
    /// this was a Kani harness, which took 335 s to prove the same thing.
    #[test]
    fn fy_from_stream_rejects_every_short_stream() {
        let buf = [0u8; 63 * 8];
        for len in 0..buf.len() {
            assert!(
                LemireFyPrp::<64>::from_stream(&buf[..len]).is_err(),
                "len {}",
                len
            );
        }
        assert!(LemireFyPrp::<64>::from_stream(&buf).is_ok());
    }

    #[test]
    fn fy_rejects_short_key() {
        assert!(<LemireFyPrp<64> as Prp<Symbol<64>>>::new(&[0u8; 8]).is_err());
    }

    quickcheck! {
        /// The bulk indicator mask must agree with the per-bit reference for
        /// the Bit6 PRP too (guards the gt_mask_xor_64 kernel path).
        fn fy_indicator_mask_matches_reference(key: Vec<u8>, x: u8) -> quickcheck::TestResult {
            if key.len() < 16 {
                return quickcheck::TestResult::discard();
            }
            let prp: LemireFyPrp<64> = Prp::new(&key[0..16]).unwrap();
            let x = Symbol::<64>::from_low_bits(x);

            let mut mask = [0u8; 8];
            prp.indicator_mask_xor(x, &mut mask);

            let mut reference = [0u8; 8];
            for j in 0..64u8 {
                let indicator = u8::from(prp.invert(sym64(j)).get() > x.get());
                reference[(j / 8) as usize] |= indicator << (j % 8);
            }

            quickcheck::TestResult::from_bool(mask == reference)
        }
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// `oblivious_lookup` over a 64-entry table returns `table[i]` for every
    /// symbol `i` (all tables whose entries are in the domain, as a
    /// permutation's are).
    #[kani::proof]
    #[kani::unwind(65)]
    fn oblivious_lookup_64_matches_index() {
        let table: [u8; 64] = kani::any();
        kani::assume(table.iter().all(|&v| v < 64));
        let index = Symbol::<64>::from_low_bits(kani::any());
        let got = oblivious_lookup(&table, index);
        assert_eq!(got.get(), table[usize::from(index.get())]);
    }

    /// `oblivious_lookup` over a 256-entry table returns `table[i]` for every
    /// symbol `i` (all tables).
    #[kani::proof]
    #[kani::unwind(257)]
    fn oblivious_lookup_256_matches_index() {
        let table: [u8; 256] = kani::any();
        let index = Symbol::<256>::from(kani::any::<u8>());
        let got = oblivious_lookup(&table, index);
        assert_eq!(got.get(), table[usize::from(index.get())]);
    }

    /// `Symbol::<64>::from_low_bits` always yields a value in `0..64`, and
    /// is the identity on `0..64` (all `u8`).
    #[kani::proof]
    fn symbol_64_from_low_bits_in_domain() {
        let b: u8 = kani::any();
        let s = Symbol::<64>::from_low_bits(b);
        assert!(s.get() < 64);
        if b < 64 {
            assert_eq!(s.get(), b);
        }
    }

    /// `oblivious::lemire_draw`, the draw every builder uses, reads step
    /// `i`'s draw from bytes `(63 - i) * 8 ..+ 8` as a little-endian `u64`
    /// and reduces it to `0..=i` by multiply-high: for every stream and every
    /// step `1..64` it is `(x * (i + 1)) >> 64` of that draw, and so never
    /// exceeds `i`. Proved on the function itself, not a restatement of its
    /// formula. The steps are a loop rather than a symbolic `i`, so every
    /// slice offset is concrete once unwound.
    #[kani::proof]
    #[kani::unwind(64)]
    fn lemire_draw_in_range() {
        let stream: [u8; 63 * 8] = kani::any();
        for i in 1..64 {
            let d = 63 - i;
            let mut draw = [0u8; 8];
            draw.copy_from_slice(&stream[d * 8..d * 8 + 8]);
            let x = u64::from_le_bytes(draw);

            let j = oblivious::lemire_draw(&stream, i);
            assert_eq!(u128::from(j), (u128::from(x) * (i as u128 + 1)) >> 64);
            assert!(usize::from(j) <= i);
        }
    }

    /// Asserts `perm` is a permutation of `0..64` with `inverse` its
    /// two-sided inverse. Checking `perm[i] < 64` and `inverse[perm[i]] == i`
    /// for every `i` suffices: it makes `perm` injective on a 64-element
    /// domain into `0..64`, hence a bijection, and `inverse` then agrees with
    /// `perm⁻¹` at every point of `0..64`.
    fn assert_is_permutation(perm: &[u8; 64], inverse: &[u8; 64]) {
        for (i, p) in perm.iter().enumerate() {
            assert!(*p < 64);
            assert_eq!(inverse[*p as usize] as usize, i);
        }
    }

    /// A fixed non-trivial keystream, used for the concrete draws of the
    /// bounded harness below.
    const FIXED_STREAM: [u8; 512] = {
        let mut s = [0u8; 512];
        let mut n = 0;
        while n < 512 {
            s[n] = (n as u8).wrapping_mul(167).wrapping_add(13);
            n += 1;
        }
        s
    };

    /// Number of leading symbolic draws in the bounded harness below.
    const SYMBOLIC_DRAWS: usize = 6;

    /// The reference builder (textbook Fisher–Yates, which the oblivious
    /// builders are proved equal to below) yields a permutation of `0..64`
    /// and its inverse for every stream whose first `SYMBOLIC_DRAWS` draws
    /// (driving steps 63 down to `64 - SYMBOLIC_DRAWS`) are arbitrary and
    /// whose remaining draws come from `FIXED_STREAM`. Proved on the
    /// reference rather than through `from_stream` (the SWAR builder under
    /// Kani) because that takes under half the time; the harness below
    /// carries the property over to the SWAR builder.
    /// With all 63 draws symbolic CBMC does not finish in 30 minutes; 8
    /// symbolic draws does not finish in 20.
    #[kani::proof]
    #[kani::unwind(65)]
    fn lemire_fy_reference_is_permutation_first_draws_symbolic() {
        let mut stream = FIXED_STREAM;
        let head: [u8; SYMBOLIC_DRAWS * 8] = kani::any();
        stream[..SYMBOLIC_DRAWS * 8].copy_from_slice(&head);
        let (mut perm, mut inverse) = ([0u8; 64], [0u8; 64]);
        oblivious::reference::build(&stream, &mut perm, &mut inverse);
        assert_is_permutation(&perm, &inverse);
    }

    /// The SWAR oblivious builder (what `from_stream` dispatches to under
    /// Kani, and on targets with neither NEON nor SSSE3) builds exactly the
    /// reference builder's `permutation` and `inverse` for every stream whose
    /// first `SYMBOLIC_DRAWS` draws are arbitrary and whose remaining draws
    /// come from `FIXED_STREAM`: same shape as the harness above.
    // 872 s on an M4, and on GitHub's ubuntu-latest runners it has been
    // cancelled 26 to 32 minutes in on every run but one, so it runs only
    // with `kani-full`. Every CI run still tests SWAR against the reference
    // on every swap (`oblivious::tests`).
    #[cfg(feature = "kani-full")]
    #[kani::proof]
    #[kani::unwind(65)]
    fn oblivious_swar_matches_reference_first_draws_symbolic() {
        let mut stream = FIXED_STREAM;
        let head: [u8; SYMBOLIC_DRAWS * 8] = kani::any();
        stream[..SYMBOLIC_DRAWS * 8].copy_from_slice(&head);
        let (mut perm, mut inverse) = ([0u8; 64], [0u8; 64]);
        oblivious::swar::build(&stream, &mut perm, &mut inverse);
        let (mut want_perm, mut want_inverse) = ([0u8; 64], [0u8; 64]);
        oblivious::reference::build(&stream, &mut want_perm, &mut want_inverse);
        assert!(perm == want_perm);
        assert!(inverse == want_inverse);
    }
}
