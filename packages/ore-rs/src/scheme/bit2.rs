//! BlockORE implementation using a 2-bit indicator function, AES-128 as
//! the per-block PRF, and Knuth-shuffle for the per-block PRP. Plaintexts
//! are arrays of bytes (`PlainText<N>`); the construction packs
//! `(prefix ‖ xt[i] ‖ block_index)` into a single 16-byte AES input, which
//! caps `N` at 15.

use crate::{
    ciphertext::*,
    primitives::{
        hash::Aes128Z2Hash, prf::Aes128Prf, AesBlock, Hash, HashKey, Prf, Prp, Symbol, NONCE_SIZE,
    },
    scheme::width::{AesBlockBuf, Bit8, BlockWidth, FirstDiff, RightBitVec},
    OreCipher, OreError, PlainText,
};

use aes::cipher::generic_array::GenericArray;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::cell::RefCell;
use std::cmp::Ordering;
use subtle_ng::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Per-block ciphertext component types ([`LeftBlock16`], [`RightBlock32`])
/// used by this scheme.
pub mod block_types;
pub use self::block_types::*;

/// AES-128 BlockORE cipher, generic over the RNG used to draw per-encryption
/// nonces. The two PRF instances are keyed at construction; the RNG is held
/// in a `RefCell` so encryption can take `&self` while still drawing fresh
/// randomness. Keys are zeroised on drop.
#[derive(ZeroizeOnDrop)]
pub struct OreAes128<R: Rng + SeedableRng> {
    prf1: Aes128Prf,
    prf2: Aes128Prf,
    #[zeroize(skip)]
    rng: RefCell<R>,
}

// Opaque Debug: never render key material. (`Aes128`'s own Debug is already
// opaque, but spell it out so the guarantee can't regress.)
impl<R: Rng + SeedableRng> std::fmt::Debug for OreAes128<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OreAes128").finish_non_exhaustive()
    }
}

/// Convenience alias for [`OreAes128`] backed by `ChaCha20Rng` — the RNG
/// most callers will want.
pub type OreAes128ChaCha20 = OreAes128<ChaCha20Rng>;

/* Define some convenience types */
type EncryptLeftResult<R, const N: usize> = Result<Left<OreAes128<R>, N>, OreError>;
type EncryptResult<R, const N: usize> = Result<CipherText<OreAes128<R>, N>, OreError>;

/// Derive the per-block PRP seeds for `x` under `prf2`: seed `n` is
/// `PRF₂(x[0..n] ‖ 0…)`. The seeds are **key-equivalent material** — anyone
/// holding seed `n` can rebuild that block's permutation and invert `xt[n]`
/// — so they live in their own buffer, never in the (serialisable) `Left`,
/// and the caller must consume them via [`SeedBuf`]'s zeroize-on-drop.
struct SeedBuf<const N: usize>([AesBlock; N]);

impl<const N: usize> Drop for SeedBuf<N> {
    fn drop(&mut self) {
        for seed in self.0.iter_mut() {
            seed.zeroize();
        }
    }
}

fn derive_prp_seeds<const N: usize>(prf2: &Aes128Prf, x: &PlainText<N>) -> SeedBuf<N> {
    let mut seeds = [AesBlock::default(); N];
    for (n, block) in seeds.iter_mut().enumerate() {
        block[0..n].clone_from_slice(&x[0..n]);
        // TODO (tracked in v2 plan, fixed for new schemes by the §5(b)
        // accumulator): the block index is not bound here, so a run of
        // identical prefix bytes yields identical seeds.
    }
    prf2.encrypt_all(&mut seeds);
    SeedBuf(seeds)
}

/// Build the right-ciphertext bitvector for one block: for every candidate
/// value `j`, bit `j` is `(π⁻¹(j) > x) ⊕ h[j]`.
///
/// Bulk form (v2 plan §2): the hash bits are packed straight into the
/// block's bitvector, then the PRP XORs its indicator mask over the top in
/// one linear pass of its inverse table — no per-bit `invert` lookups, no
/// heap allocation. `ro_blocks` holds the PRF₁-encrypted RO keys and is
/// trashed by the hash pass.
pub(crate) fn encode_right_block<W: BlockWidth, H: Hash>(
    block: &mut W::RightBlock,
    prp: &W::Prp,
    x: W::Symbol,
    hasher: &H,
    ro_blocks: &mut [AesBlock],
) {
    debug_assert_eq!(ro_blocks.len(), W::DOMAIN);
    let out = block.as_mut_bytes();
    hasher.hash_all_into(ro_blocks, out);
    prp.indicator_mask_xor(x, out);
}

impl<R: Rng + SeedableRng> OreAes128<R> {
    /// Fill `left` with the PRF₁ tag inputs and permuted values for `x`,
    /// using the given PRP seeds. After this returns, `left.f[n]` holds the
    /// *unencrypted* tag input `(x[0..n] ‖ xt[n] ‖ n)`; the caller runs the
    /// final PRF₁ pass once any other use of the inputs (the RO key
    /// template) is done.
    fn build_left<const N: usize>(
        &self,
        left: &mut Left<Self, N>,
        seeds: &SeedBuf<N>,
        x: &PlainText<N>,
    ) -> Result<(), OreError> {
        for n in 0..N {
            let prp: <Bit8 as BlockWidth>::Prp = Prp::new(&seeds.0[n])?;
            left.xt[n] = prp.permute(Symbol::from(x[n])).get();

            left.f[n][0..n].clone_from_slice(&x[0..n]);
            left.f[n][n] = left.xt[n];
            // Include the block number in the value passed to the Random Oracle
            left.f[n][N] = n as u8;
        }
        Ok(())
    }
}

impl<R: Rng + SeedableRng> OreCipher for OreAes128<R> {
    type LeftBlockType = LeftBlock16;
    type RightBlockType = RightBlock32;

    fn init(k1: &[u8; 16], k2: &[u8; 16]) -> Result<Self, OreError> {
        // TODO: k1 and k2 should be Key types and we should have a set of traits to abstract the
        // behaviour ro parsing/loading etc

        let rng: R = SeedableRng::from_entropy();

        Ok(OreAes128 {
            prf1: Prf::new(GenericArray::from_slice(k1)),
            prf2: Prf::new(GenericArray::from_slice(k2)),
            rng: RefCell::new(rng),
        })
    }

    fn encrypt_left<const N: usize>(&self, x: &PlainText<N>) -> EncryptLeftResult<R, N> {
        let mut output = Left::<Self, N>::init();

        let seeds = derive_prp_seeds(&self.prf2, x);
        self.build_left(&mut output, &seeds, x)?;
        self.prf1.encrypt_all(&mut output.f);

        Ok(output)
    }

    fn encrypt<const N: usize>(&self, x: &PlainText<N>) -> EncryptResult<R, N> {
        let mut left = Left::<Self, N>::init();
        let mut right = Right::<Self, N>::init();

        // Generate a 16-byte random nonce
        self.rng.borrow_mut().try_fill(&mut right.nonce)?;

        let seeds = derive_prp_seeds(&self.prf2, x);

        /* TODO: This seems to work but it is technically using the nonce as the key
         * (instead of using it as the plaintext). This appears to be how the original
         * ORE implementation does it but it feels a bit wonky to me.
         * Alternatives are catalogued in the v2 plan §6 and will be settled
         * there for new schemes; this scheme keeps the construction for
         * wire compatibility.
         */
        let hasher: Aes128Z2Hash = Hash::new(AesBlock::from_slice(&right.nonce));

        // RO key template: entry `j` of the template holds the *input*
        // `(x[0..n] ‖ j ‖ n)` for the current block. Between blocks only
        // three bytes per entry change (the prefix byte just fixed, the
        // candidate byte position, and the block index), so the template is
        // maintained incrementally; `work` receives a copy each block for
        // the in-place PRF/hash passes. Template and work hold secret
        // intermediate state and are zeroized at the end.
        let mut template = <Bit8 as BlockWidth>::RoKeyBuf::zeroed();
        for (j, entry) in template.iter_mut().enumerate() {
            entry[0] = j as u8;
        }
        let mut work = <Bit8 as BlockWidth>::RoKeyBuf::zeroed();

        for n in 0..N {
            let prp: <Bit8 as BlockWidth>::Prp = Prp::new(&seeds.0[n])?;
            left.xt[n] = prp.permute(Symbol::from(x[n])).get();

            left.f[n][0..n].clone_from_slice(&x[0..n]);
            left.f[n][n] = left.xt[n];
            // Include the block number in the value passed to the Random Oracle
            left.f[n][N] = n as u8;

            if n > 0 {
                // Extend the prefix over the previous candidate position and
                // move the candidate byte and block index along.
                for (j, entry) in template.iter_mut().enumerate() {
                    entry[n - 1] = x[n - 1];
                    entry[n] = j as u8;
                    entry[N] = n as u8;
                }
            }

            work.copy_from(&template);
            self.prf1.encrypt_all(work.as_mut_slice());

            encode_right_block::<Bit8, _>(
                &mut right.data[n],
                &prp,
                Symbol::from(x[n]),
                &hasher,
                &mut work,
            );
        }

        self.prf1.encrypt_all(&mut left.f);

        for entry in template.iter_mut() {
            entry.zeroize();
        }
        for entry in work.as_mut_slice() {
            entry.zeroize();
        }

        Ok(CipherText { left, right })
    }

    fn compare_raw_slices(a: &[u8], b: &[u8]) -> Option<Ordering> {
        if a.len() != b.len() {
            return None;
        };
        let left_size = Self::LeftBlockType::BLOCK_SIZE;
        let right_size = Self::RightBlockType::BLOCK_SIZE;

        // The legacy wire has no header: the block count is implied by the
        // length, `n·(1 + left + right) + nonce`. Anything that does not fit
        // that shape exactly (too short for a nonce, or a partial block) is
        // not a ciphertext of this scheme, and the slicing below would panic
        // on it. A nonce-only input is the valid `N = 0` ciphertext, which
        // `CipherText::<_, 0>::from_slice` also accepts; it compares Equal.
        let body = a.len().checked_sub(NONCE_SIZE)?;
        let per_block = left_size + right_size + 1;
        if body % per_block != 0 {
            return None;
        }
        let num_blocks = body / per_block;

        let mut is_equal = Choice::from(1);
        // What the resolution step needs from the first differing block `l`:
        // `a`'s permuted symbol and PRF tag, and `b`'s right bitvector. All
        // three are latched *inside* the scan, under the choice "this is the
        // first difference", so no load after the loop is indexed by `l`.
        // The right blocks are the one region the scan would otherwise never
        // touch, so a direct `right[l]` afterwards hits or misses the cache
        // according to `l`; measured as a timing signal, see `docs/reviews/`.
        // The wire format is unchanged.
        let mut diff = FirstDiff::<{ RightBlock32::BLOCK_SIZE }>::new();

        // Slices for the PRF ("f") blocks and the right half.
        let a_f = &a[num_blocks..];
        let b_f = &b[num_blocks..];
        let b_right = &b[num_blocks * (left_size + 1)..];
        let b_right_blocks = &b_right[NONCE_SIZE..];

        for n in 0..num_blocks {
            let prp_eq: Choice = !a[n].ct_eq(&b[n]);
            let left_block_comparison: Choice = !left_block(a_f, n).ct_eq(left_block(b_f, n));
            let condition: Choice = prp_eq | left_block_comparison;
            // Set for exactly one `n`: the first differing block.
            let first = is_equal & condition;

            diff.latch(
                a[n],
                left_block(a_f, n),
                right_block(b_right_blocks, n),
                first,
            );
            is_equal.conditional_assign(&Choice::from(0), first);
        }

        if bool::from(is_equal) {
            return Some(Ordering::Equal);
        }

        let hash_key = HashKey::from_slice(&b_right[0..NONCE_SIZE]);
        let hash: Aes128Z2Hash = Hash::new(hash_key);

        if diff.resolve(&hash) == 1 {
            return Some(Ordering::Greater);
        }

        Some(Ordering::Less)
    }
}

// TODO: Move these to block_types
#[inline]
fn left_block(input: &[u8], n: usize) -> &[u8] {
    let f_pos = n * LeftBlock16::BLOCK_SIZE;
    &input[f_pos..(f_pos + LeftBlock16::BLOCK_SIZE)]
}

#[inline]
fn right_block(input: &[u8], n: usize) -> &[u8] {
    let f_pos = n * RightBlock32::BLOCK_SIZE;
    &input[f_pos..(f_pos + RightBlock32::BLOCK_SIZE)]
}

impl<const N: usize> PartialEq for CipherText<OreAes128ChaCha20, N> {
    fn eq(&self, b: &Self) -> bool {
        matches!(self.cmp(b), Ordering::Equal)
    }
}

impl<const N: usize> Ord for CipherText<OreAes128ChaCha20, N> {
    fn cmp(&self, b: &Self) -> Ordering {
        let mut is_equal = Choice::from(1);
        // Latch the first differing block during the scan, as in
        // `compare_raw_slices`: no load after the loop is indexed by its
        // position.
        let mut diff = FirstDiff::<{ RightBlock32::BLOCK_SIZE }>::new();

        for n in 0..N {
            let condition: Choice =
                !(self.left.xt[n].ct_eq(&b.left.xt[n])) | !(self.left.f[n].ct_eq(&b.left.f[n]));
            // Set for exactly one `n`: the first differing block.
            let first = is_equal & condition;

            diff.latch(
                self.left.xt[n],
                &self.left.f[n],
                b.right.data[n].bytes(),
                first,
            );
            is_equal.conditional_assign(&Choice::from(0), first);
        }

        if bool::from(is_equal) {
            return Ordering::Equal;
        }

        let hash: Aes128Z2Hash = Hash::new(AesBlock::from_slice(&b.right.nonce));
        if diff.resolve(&hash) == 1 {
            return Ordering::Greater;
        }

        Ordering::Less
    }
}

impl<const N: usize> PartialOrd for CipherText<OreAes128ChaCha20, N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/*
 * (From the Rust docs)
 * This property cannot be checked by the compiler, and therefore Eq implies PartialEq, and has no extra methods.
 */
impl<const N: usize> Eq for CipherText<OreAes128ChaCha20, N> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::OreEncrypt;
    use quickcheck::TestResult;

    type Ore = OreAes128ChaCha20;

    fn init_ore() -> Ore {
        let mut k1: [u8; 16] = Default::default();
        let mut k2: [u8; 16] = Default::default();

        let mut rng = ChaCha20Rng::from_entropy();

        rng.fill(&mut k1);
        rng.fill(&mut k2);

        OreCipher::init(&k1, &k2).unwrap()
    }

    /// The legacy wire has no header, so the comparator infers the block
    /// count from the length. Lengths that do not fit `n·(1 + 16 + 32) + 16`
    /// must be refused, not indexed: two empty slices used to underflow the
    /// nonce subtraction, and a partial block to slice past the end.
    #[test]
    fn compare_raw_slices_refuses_malformed_lengths() {
        let ore = init_ore();
        let good = 42u64.encrypt(&ore).unwrap().to_bytes();
        assert!(Ore::compare_raw_slices(&good, &good).is_some());

        assert_eq!(Ore::compare_raw_slices(&[], &[]), None);
        let short = vec![0u8; NONCE_SIZE - 1];
        assert_eq!(Ore::compare_raw_slices(&short, &short), None);
        let partial = &good[..good.len() - 1];
        assert_eq!(Ore::compare_raw_slices(partial, partial), None);
        let mut longer = good.clone();
        longer.push(0);
        assert_eq!(Ore::compare_raw_slices(&longer, &longer), None);
    }

    /// A zero-block plaintext encrypts to a nonce-only ciphertext. The raw
    /// comparator must agree with the parsed one on it, not refuse it.
    #[test]
    fn compare_raw_slices_accepts_zero_blocks() {
        let ore = init_ore();
        let a = [0u8; 0].encrypt(&ore).unwrap();
        let b = [0u8; 0].encrypt(&ore).unwrap();
        let (a_bytes, b_bytes) = (a.to_bytes(), b.to_bytes());
        assert_eq!(a_bytes.len(), NONCE_SIZE);

        let parsed = CipherText::<Ore, 0>::from_slice(&a_bytes).unwrap();
        assert_eq!(parsed.cmp(&b), Ordering::Equal);
        assert_eq!(
            Ore::compare_raw_slices(&a_bytes, &b_bytes),
            Some(Ordering::Equal)
        );
    }

    quickcheck! {
        fn compare_u64(x: u64, y: u64) -> bool {
            let ore = init_ore();
            let a = x.encrypt(&ore).unwrap();
            let b = y.encrypt(&ore).unwrap();

            match x.cmp(&y) {
                Ordering::Greater => a > b,
                Ordering::Less    => a < b,
                Ordering::Equal   => a == b
            }
        }

        fn compare_u64_raw_slices(x: u64, y: u64) -> bool {
            let ore = init_ore();
            let a = x.encrypt(&ore).unwrap().to_bytes();
            let b = y.encrypt(&ore).unwrap().to_bytes();

            match Ore::compare_raw_slices(&a, &b) {
                Some(Ordering::Greater) => x > y,
                Some(Ordering::Less)    => x < y,
                Some(Ordering::Equal)   => x == y,
                None                    => false
            }
        }

        fn equality_u64(x: u64) -> bool {
            let ore = init_ore();
            let a = x.encrypt(&ore).unwrap();
            let b = x.encrypt(&ore).unwrap();

            a == b
        }

        fn equality_u64_raw_slices(x: u64) -> bool {
            let ore = init_ore();
            let a = x.encrypt(&ore).unwrap().to_bytes();
            let b = x.encrypt(&ore).unwrap().to_bytes();

            matches!(Ore::compare_raw_slices(&a, &b), Some(Ordering::Equal))
        }

        fn compare_u32(x: u32, y: u32) -> bool {
            let ore = init_ore();
            let a = x.encrypt(&ore).unwrap();
            let b = y.encrypt(&ore).unwrap();

            match x.cmp(&y) {
                Ordering::Greater => a > b,
                Ordering::Less    => a < b,
                Ordering::Equal   => a == b
            }
        }

        fn equality_u32(x: u64) -> bool {
            let ore = init_ore();
            let a = x.encrypt(&ore).unwrap();
            let b = x.encrypt(&ore).unwrap();

            a == b
        }

        fn compare_f64(x: f64, y: f64) -> TestResult {
            if x.is_nan() || x.is_infinite() || y.is_nan() || y.is_infinite() {
                return TestResult::discard();
            }

            let ore = init_ore();
            let a = x.encrypt(&ore).unwrap();
            let b = y.encrypt(&ore).unwrap();

            match x.partial_cmp(&y) {
                Some(Ordering::Greater) => TestResult::from_bool(a > b),
                Some(Ordering::Less)    => TestResult::from_bool(a < b),
                Some(Ordering::Equal)   => TestResult::from_bool(a == b),
                None                    => TestResult::failed()
            }
        }

        /*
         * Note that we don't discard any values for the equality check
         * because NaN == NaN works with the integer encoding
         * */
        fn equality_f64(x: f64) -> bool {
            let ore = init_ore();
            let a = x.encrypt(&ore).unwrap();
            let b = x.encrypt(&ore).unwrap();

            a == b
        }

        fn compare_plaintext(x: u64, y: u64) -> bool {
            let ore = init_ore();
            let a = x.to_be_bytes().encrypt(&ore).unwrap();
            let b = y.to_be_bytes().encrypt(&ore).unwrap();

            match x.cmp(&y) {
                Ordering::Greater => a > b,
                Ordering::Less    => a < b,
                Ordering::Equal   => a == b
            }
        }

        fn equality_plaintext(x: f64) -> bool {
            let ore = init_ore();
            let a = x.to_be_bytes().encrypt(&ore).unwrap();
            let b = x.to_be_bytes().encrypt(&ore).unwrap();

            a == b
        }
    }

    #[test]
    fn smallest_to_largest() {
        let ore = init_ore();
        let a = 0u64.encrypt(&ore).unwrap();
        let b = 18446744073709551615u64.encrypt(&ore).unwrap();

        assert!(a < b);
    }

    #[test]
    fn largest_to_smallest() {
        let ore = init_ore();
        let a = 18446744073709551615u64.encrypt(&ore).unwrap();
        let b = 0u64.encrypt(&ore).unwrap();

        assert!(a > b);
    }

    #[test]
    fn smallest_to_smallest() {
        let ore = init_ore();
        let a = 0u64.encrypt(&ore).unwrap();
        let b = 0u64.encrypt(&ore).unwrap();

        assert!(a == b);
    }

    #[test]
    fn largest_to_largest() {
        let ore = init_ore();
        let a = 18446744073709551615u64.encrypt(&ore).unwrap();
        let b = 18446744073709551615u64.encrypt(&ore).unwrap();

        assert!(a == b);
    }

    // Regression: IEEE-754 says -0.0 == +0.0, so their ciphertexts must
    // compare equal. Previously, sign-bit handling in
    // `ToOrderedInteger::map_to` produced different `u64` plaintexts for
    // the two zeros (0x7FFF... vs 0x8000...), so a quickcheck draw of
    // `(-0.0, 0.0)` would flake. Pin the contract deterministically.
    #[test]
    fn signed_zeros_compare_equal() {
        let ore = init_ore();
        let pos_zero = 0.0_f64.encrypt(&ore).unwrap();
        let neg_zero = (-0.0_f64).encrypt(&ore).unwrap();

        assert_eq!(0.0_f64.partial_cmp(&-0.0_f64), Some(Ordering::Equal));
        assert!(pos_zero == neg_zero);
    }

    #[test]
    fn comparisons_in_first_block() {
        let ore = init_ore();
        let a = 18446744073709551615u64.encrypt(&ore).unwrap();
        let b = 18446744073709551612u64.encrypt(&ore).unwrap();

        assert!(a > b);
        assert!(b < a);
    }

    #[test]
    fn comparisons_in_last_block() {
        let ore = init_ore();
        let a = 10u64.encrypt(&ore).unwrap();
        let b = 73u64.encrypt(&ore).unwrap();

        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn compare_raw_slices_mismatched_lengths() {
        let ore = init_ore();
        let a_64 = 10u64.encrypt(&ore).unwrap().to_bytes();
        let a_32 = 10u32.encrypt(&ore).unwrap().to_bytes();

        assert_eq!(Ore::compare_raw_slices(&a_64, &a_32), Option::None);
    }

    #[test]
    fn binary_encoding() {
        let ore = init_ore();
        let a = 10u64.encrypt(&ore).unwrap();
        let bin = a.to_bytes();
        assert_eq!(
            a,
            CipherText::<OreAes128ChaCha20, 8>::from_slice(&bin).unwrap()
        );
    }

    #[test]
    #[should_panic(expected = "ParseError")]
    fn binary_encoding_invalid_length() {
        let bin = vec![0, 1, 2, 3];
        CipherText::<OreAes128ChaCha20, 8>::from_slice(&bin).unwrap();
    }

    #[test]
    fn test_different_prf_keys() {
        let k1: [u8; 16] = [
            97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
        ];
        let k2: [u8; 16] = [
            129, 4, 114, 186, 102, 145, 225, 73, 166, 57, 244, 251, 56, 92, 188, 36,
        ];
        let k3: [u8; 16] = [
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 97, 98, 99, 100, 101, 102,
        ];

        let ore1: OreAes128ChaCha20 = OreCipher::init(&k1, &k2).unwrap();
        let ore2: OreAes128ChaCha20 = OreCipher::init(&k3, &k2).unwrap();

        let a = 1000u32.encrypt(&ore1).unwrap().to_bytes();
        let b = 1000u32.encrypt(&ore2).unwrap().to_bytes();

        assert_ne!(Some(Ordering::Equal), Ore::compare_raw_slices(&a, &b));
    }

    #[test]
    fn test_different_prp_keys() {
        let k1: [u8; 16] = [
            97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
        ];
        let k2: [u8; 16] = [
            129, 4, 114, 186, 102, 145, 225, 73, 166, 57, 244, 251, 56, 92, 188, 36,
        ];
        let k3: [u8; 16] = [
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 97, 98, 99, 100, 101, 102,
        ];

        let ore1: OreAes128ChaCha20 = OreCipher::init(&k1, &k2).unwrap();
        let ore2: OreAes128ChaCha20 = OreCipher::init(&k1, &k3).unwrap();

        let a = 1000u32.encrypt(&ore1).unwrap().to_bytes();
        let b = 1000u32.encrypt(&ore2).unwrap().to_bytes();

        assert_ne!(Some(Ordering::Equal), Ore::compare_raw_slices(&a, &b));
    }
}
