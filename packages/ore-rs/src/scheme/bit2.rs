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
        // Known leakage, kept because the wire format is frozen: the seed
        // input binds neither the block index nor the block count, so the
        // seeds for blocks n < m are equal when x[n..m] is all zero. Those
        // blocks share one permutation, so a zero run repeats π(0) in `xt`
        // and a single Left ciphertext shows it. See "Known leakage of the
        // legacy scheme" in the v2 plan. New schemes bind the block index
        // and count into the seed:
        // https://github.com/cipherstash/ore.rs/pull/82
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

#[cfg(test)]
mod golden_vectors {
    //! ORE wire-format stability tests for `OreAes128ChaCha20`.
    //!
    //! Encryption is non-deterministic by design: each call draws a
    //! random 16-byte nonce and folds it into the right-side ciphertext.
    //! So we cannot assert byte-for-byte equality on the full payload.
    //!
    //! What *is* stable across calls — and what consumers (database-side
    //! `compare_raw_slices`, on-disk ciphertexts, query terms) actually
    //! depend on — is the **deterministic prefix**: the indicator-function
    //! header plus the Left half. For an `N`-block plaintext, that's
    //! `N + 16N = 17N` bytes (header is `N`, each Left block is 16 bytes).
    //! Total ciphertext is `49N + 16` bytes (header + Left + nonce + Right).
    //!
    //! Each fixture below pins those `17N` bytes against a value captured
    //! from this same module on a fixed key (`k1 = k2 = [7u8; 16]`).
    //! Together with the explicit `total_len` assertions, these tests
    //! catch:
    //!
    //! - Cipher-level wire-format drift (any change in the indicator
    //!   function, PRF construction, or block layout).
    //! - Per-type `OreEncrypt` impls (e.g. an i64 sign-flip going wrong).
    //! - Plaintext-block-width changes (e.g. an int impl that suddenly
    //!   widens or narrows).
    //!
    //! These vectors are also used as a cross-crate compatibility anchor
    //! by downstream consumers (notably `cipherstash-suite`'s
    //! `OreIndexer`) — the `i64` and `f64` fixtures here match their
    //! counterparts there, since both feed the cipher the same plaintext
    //! bytes.
    //!
    //! When intentionally rolling the wire format, regenerate every
    //! fixture in lockstep and call out the change explicitly.
    use super::*;
    use crate::encrypt::OreEncrypt;
    #[cfg(feature = "chrono")]
    use ::chrono::NaiveDate;

    /// Fixed-key cipher used for all golden-vector tests in this module.
    fn cipher() -> OreAes128ChaCha20 {
        let k1 = [7u8; 16];
        let k2 = [7u8; 16];
        OreCipher::init(&k1, &k2).unwrap()
    }

    /// Asserts that `bytes` is exactly `49N + 16` long (the full ORE
    /// ciphertext shape for an `N`-byte plaintext block) and that its
    /// first `17N` bytes — the deterministic header + Left half — match
    /// `expected_prefix_hex`.
    #[track_caller]
    fn assert_deterministic_prefix<const N: usize>(bytes: &[u8], expected_prefix_hex: &str) {
        let prefix_len = 17 * N;
        let total_len = 49 * N + 16;
        assert_eq!(
            expected_prefix_hex.len(),
            prefix_len * 2,
            "fixture is the wrong length for an {N}-byte plaintext block",
        );
        assert_eq!(
            bytes.len(),
            total_len,
            "ciphertext shape changed: got {} bytes, expected {}",
            bytes.len(),
            total_len,
        );
        assert_eq!(
            hex::encode(&bytes[..prefix_len]),
            expected_prefix_hex,
            "ORE deterministic prefix changed",
        );
    }

    #[test]
    fn u64_wire_format_is_stable() {
        let c = cipher();
        assert_deterministic_prefix::<8>(
            &0u64.encrypt(&c).unwrap().to_bytes(),
            "cecececececececefc6a65709ae5689bd6be674717d0b1e65b2fad12385216ab\
             dd9fefc3390261fee1e223d4e971d7796d6edea734d9edb88eed524f40f5554b\
             2e4d35f355d231dc71281ff74c420c492853a6ef321662fb7c7a3ec3b8e36d10\
             8e069671a8e086d27f6b5fb9ca399b5f003190eab8031552cf4692d29f9451a0\
             caa6a8885a60348f",
        );
        assert_deterministic_prefix::<8>(
            &42u64.encrypt(&c).unwrap().to_bytes(),
            "cecececececece4ffc6a65709ae5689bd6be674717d0b1e65b2fad12385216ab\
             dd9fefc3390261fee1e223d4e971d7796d6edea734d9edb88eed524f40f5554b\
             2e4d35f355d231dc71281ff74c420c492853a6ef321662fb7c7a3ec3b8e36d10\
             8e069671a8e086d27f6b5fb9ca399b5f003190eab80315521b0b6c745c46fd15\
             791d9f75b665a4a2",
        );
        assert_deterministic_prefix::<8>(
            &u64::MAX.encrypt(&c).unwrap().to_bytes(),
            "e51cd055a35629704d773701cdbd62fd05175e913aa7c349deba38250f0c82b8\
             60b9782edab63bcbba7a1325a5e3435a36a927dc6292c29f6021e3744d11be6e\
             501b99ffcc309a397c9a0580cc2345540156953eb58b4c347ef5aabd19a6116b\
             f6c2ed449be770a7c29fe8c750f62a37806759832dcb80f02833467fb96b6a3c\
             d2ee34cbf4e7e102",
        );
    }

    #[test]
    fn i64_wire_format_is_stable() {
        let c = cipher();
        assert_deterministic_prefix::<8>(
            &0i64.encrypt(&c).unwrap().to_bytes(),
            "d00d0d0d0d0d0d0ddaf1cba91cf962e083775b5237c06c06747140c08f504744\
             71c10b31426c70f0405fc43b6ec3a1d65b77d5f6f4accab914a2da8ebdfba7f7\
             fd24456ae9dd3fab5b84aadb93a43b89033f2a9c3a33305fafbf28974022357a\
             1278dade28f538f20f2a218a1c145be0cc0d522b73ed052d39163d5fcbdb2227\
             cecd7cd460cdefd4",
        );
        assert_deterministic_prefix::<8>(
            &42i64.encrypt(&c).unwrap().to_bytes(),
            "d00d0d0d0d0d0d16daf1cba91cf962e083775b5237c06c06747140c08f504744\
             71c10b31426c70f0405fc43b6ec3a1d65b77d5f6f4accab914a2da8ebdfba7f7\
             fd24456ae9dd3fab5b84aadb93a43b89033f2a9c3a33305fafbf28974022357a\
             1278dade28f538f20f2a218a1c145be0cc0d522b73ed052d573c8f420a888937\
             01ebcde6f5bb6101",
        );
        assert_deterministic_prefix::<8>(
            &(-42i64).encrypt(&c).unwrap().to_bytes(),
            "d3228ef7485a3f789a88d0d95fd1c0b3f1790e02928fdd895c427411cb1288bf\
             c18575b8ab6d8b592d6875bf185afa1b242769643510b699adc553625ad5615a\
             f0cd34ad11f5e799f4e2607809d7db52c636cbe5837fd7c825642c485fdbc430\
             14112a08408c71beb50119d58d3b5a09ea400ca8c9c8b98fc8f9430da4e4f04e\
             19edc34f050376ce",
        );
        assert_deterministic_prefix::<8>(
            &i64::MIN.encrypt(&c).unwrap().to_bytes(),
            "cecececececececefc6a65709ae5689bd6be674717d0b1e65b2fad12385216ab\
             dd9fefc3390261fee1e223d4e971d7796d6edea734d9edb88eed524f40f5554b\
             2e4d35f355d231dc71281ff74c420c492853a6ef321662fb7c7a3ec3b8e36d10\
             8e069671a8e086d27f6b5fb9ca399b5f003190eab8031552cf4692d29f9451a0\
             caa6a8885a60348f",
        );
        assert_deterministic_prefix::<8>(
            &i64::MAX.encrypt(&c).unwrap().to_bytes(),
            "e51cd055a35629704d773701cdbd62fd05175e913aa7c349deba38250f0c82b8\
             60b9782edab63bcbba7a1325a5e3435a36a927dc6292c29f6021e3744d11be6e\
             501b99ffcc309a397c9a0580cc2345540156953eb58b4c347ef5aabd19a6116b\
             f6c2ed449be770a7c29fe8c750f62a37806759832dcb80f02833467fb96b6a3c\
             d2ee34cbf4e7e102",
        );
    }

    #[test]
    fn f64_wire_format_is_stable() {
        let c = cipher();
        // f64 0.0 and i64 0 share the same plaintext bytes
        // (`[0x80, 0, 0, 0, 0, 0, 0, 0]`) under their respective
        // `to_orderable_bytes` impls and therefore the same Left half.
        assert_deterministic_prefix::<8>(
            &0.0f64.encrypt(&c).unwrap().to_bytes(),
            "d00d0d0d0d0d0d0ddaf1cba91cf962e083775b5237c06c06747140c08f504744\
             71c10b31426c70f0405fc43b6ec3a1d65b77d5f6f4accab914a2da8ebdfba7f7\
             fd24456ae9dd3fab5b84aadb93a43b89033f2a9c3a33305fafbf28974022357a\
             1278dade28f538f20f2a218a1c145be0cc0d522b73ed052d39163d5fcbdb2227\
             cecd7cd460cdefd4",
        );
        assert_deterministic_prefix::<8>(
            &1.5f64.encrypt(&c).unwrap().to_bytes(),
            "0593dbdbdbdbdbdbbbd98421c5189a12fc5c39545de73168e3942466fd993ec4\
             8f554e421343631a5d9409a5a6ea0a78d5fc05a4e43a3eaabfba978c222edd38\
             43bb320aa9ab2e883b0e1865898a85cc93c74512068e26af6ae406cd61e81c7f\
             259c633bd621df1625312d5e0ad05672f19d79a3cfcdadf3a4904732daea75ce\
             1eca3363d5be73c6",
        );
        assert_deterministic_prefix::<8>(
            &(-1.5f64).encrypt(&c).unwrap().to_bytes(),
            "fb03c6e95da115fbb1ca1d4a741cf59b5eb87f38e59ac17cddb8dafbe0aa6b02\
             b134c60c41e450ff016e9efbf87862fc57a5e75b586c3ed04baf962e54e865e9\
             a3e9334e40042905462c2ea66e4e594d3d894db23927e27c615fef6ddd6e1ed6\
             2a976960d641eadfbe8e5d48dfe08656c4cc3a90d7dd5a3de2422b8b5d9b0784\
             13f450fb6d113815",
        );
    }

    #[test]
    fn i32_wire_format_is_stable() {
        let c = cipher();
        assert_deterministic_prefix::<4>(
            &0i32.encrypt(&c).unwrap().to_bytes(),
            "d00d0d0ddaf1cba91cf962e083775b5237c06c062a72cf35efab4653832ae18c\
             f692f93e084f3adb31b82b1770ef586d4e64f96df50ac5e7e1f5f659befa2a2a\
             19750b77",
        );
        assert_deterministic_prefix::<4>(
            &42i32.encrypt(&c).unwrap().to_bytes(),
            "d00d0d16daf1cba91cf962e083775b5237c06c062a72cf35efab4653832ae18c\
             f692f93e084f3adb31b82b1770ef586d4e64f96d6dfbb06b2d63eabc222a02d5\
             939a80f3",
        );
        assert_deterministic_prefix::<4>(
            &(-42i32).encrypt(&c).unwrap().to_bytes(),
            "d3228eee9a88d0d95fd1c0b3f1790e02928fdd89f24f431cb2ef7d7791b737da\
             ffa262449dfb565bc18bb77ef5f987fdd26824530dc94819b1c8ebca30309b8c\
             8636cfcf",
        );
        assert_deterministic_prefix::<4>(
            &i32::MIN.encrypt(&c).unwrap().to_bytes(),
            "cecececefc6a65709ae5689bd6be674717d0b1e68431fb1b9f87c803668c6e1b\
             3348e723d5a4768b7e39dc7fd22b85a1f51cbd85f74531b4cf312e5bfdb0c648\
             a2f50026",
        );
        assert_deterministic_prefix::<4>(
            &i32::MAX.encrypt(&c).unwrap().to_bytes(),
            "e51cd0554d773701cdbd62fd05175e913aa7c3498f5e9c5ef8bcae8fe7a03b86\
             f2ce17aa58d3a5c6de503efb09a456edfc0e16fb3b747143d28bef147d9aca04\
             83b7ff92",
        );
    }

    #[test]
    fn i16_wire_format_is_stable() {
        let c = cipher();
        assert_deterministic_prefix::<2>(
            &0i16.encrypt(&c).unwrap().to_bytes(),
            "d00ddaf1cba91cf962e083775b5237c06c064c40ec240af33273bb4832fe24ab254e",
        );
        assert_deterministic_prefix::<2>(
            &42i16.encrypt(&c).unwrap().to_bytes(),
            "d016daf1cba91cf962e083775b5237c06c069578b0052c8402e2ed18a00f7229ac80",
        );
        assert_deterministic_prefix::<2>(
            &(-42i16).encrypt(&c).unwrap().to_bytes(),
            "d3bb9a88d0d95fd1c0b3f1790e02928fdd89b083c07528f9051c525be47f0902c1bb",
        );
    }

    #[test]
    fn bool_wire_format_is_stable() {
        let c = cipher();
        assert_deterministic_prefix::<1>(
            &false.encrypt(&c).unwrap().to_bytes(),
            "cefc6a65709ae5689bd6be674717d0b1e6",
        );
        assert_deterministic_prefix::<1>(
            &true.encrypt(&c).unwrap().to_bytes(),
            "e10d717c3f0a874c683a02b8d27dcdaf64",
        );
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn naive_date_wire_format_is_stable() {
        let c = cipher();
        assert_deterministic_prefix::<4>(
            &NaiveDate::from_ymd_opt(2024, 1, 15)
                .unwrap()
                .encrypt(&c)
                .unwrap()
                .to_bytes(),
            "d038ee23daf1cba91cf962e083775b5237c06c06a7b068e660dee83d73c60c76\
             2845dd312350293f4022e1d34108c6c2c4bb0d5fb1ef22cad3dc65180ed9774c\
             0b041752",
        );
        assert_deterministic_prefix::<4>(
            &NaiveDate::from_ymd_opt(1970, 1, 1)
                .unwrap()
                .encrypt(&c)
                .unwrap()
                .to_bytes(),
            "d0400910daf1cba91cf962e083775b5237c06c0688d1ffba203844a0ead9ab56\
             0b0aeb43945dd80dec3929fe7e88fcbcc5b7e1cd4dacaec8cdadd4fd6cbb923b\
             b0a0d4ce",
        );
    }
}
