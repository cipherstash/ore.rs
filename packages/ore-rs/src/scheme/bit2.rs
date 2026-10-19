//! BlockORE implementation using a 2-bit indicator function, AES-128 as
//! the per-block PRF, and Knuth-shuffle for the per-block PRP. Plaintexts
//! are arrays of bytes (`PlainText<N>`); the construction packs
//! `(prefix ‖ xt[i] ‖ block_index)` into a single 16-byte AES input, which
//! caps `N` at 15.
//!
//! **Legacy.** The wire format is frozen and headerless, and the scheme is
//! kept so stored ciphertexts stay readable; use the v2 schemes for new
//! data (the crate README says why). It takes a sealed `OrderPlaintext`
//! through [`crate::OreScheme`], of any fixed width up to 15 bytes: every
//! vitaminc target but the 16-byte kinds, text and bytes.

use crate::{
    ciphertext::*,
    primitives::{
        hash::Aes128Z2Hash, prf::Aes128Prf, AesBlock, Hash, HashKey, Prf, Prp, Symbol, NONCE_SIZE,
    },
    scheme::width::{AesBlockBuf, Bit8, BlockWidth, FirstDiff, RightBitVec},
    OreCipher, OreError, OreScheme, PlainText, Query, Term,
};

use aes::cipher::generic_array::GenericArray;
use rand::TryRng;
use std::cmp::Ordering;
use std::convert::TryInto;
use std::sync::Mutex;
use subtle_ng::{Choice, ConditionallySelectable, ConstantTimeEq};
use vitaminc_ore::OrderPlaintext;
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::SafeRand;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Per-block ciphertext component types ([`LeftBlock16`], [`RightBlock32`])
/// used by this scheme.
pub(crate) mod block_types;
pub(crate) use self::block_types::*;

/// AES-128 BlockORE cipher. The two PRF instances are keyed at
/// construction; per-encryption nonces come from a [`SafeRand`] seeded
/// from the OS, behind a mutex, so the cipher is `Send + Sync`. Keys are
/// zeroised on drop.
#[derive(ZeroizeOnDrop)]
pub struct OreAes128 {
    prf1: Aes128Prf,
    prf2: Aes128Prf,
    #[zeroize(skip)]
    rng: Mutex<SafeRand>,
}

// Opaque Debug: never render key material. (`Aes128Prf`, which holds each
// key, already has an opaque Debug, but spell it out here too so the
// guarantee can't regress.)
impl std::fmt::Debug for OreAes128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OreAes128").finish_non_exhaustive()
    }
}

/* Define some convenience types */
type EncryptLeftResult<const N: usize> = Result<Left<OreAes128, N>, OreError>;
type EncryptResult<const N: usize> = Result<CipherText<OreAes128, N>, OreError>;

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
    ro_blocks: &mut W::RoKeyBuf,
) {
    let out = block.as_mut_bits();
    W::hash_into(hasher, ro_blocks, out);
    prp.indicator_mask_xor(x, out);
}

/// Maximum number of blocks (= plaintext bytes): the left-tag input packs
/// `prefix ‖ xt ‖ index@N` into one 16-byte AES block, so `N ≤ 15`. A
/// 16-byte plaintext (`u128`/`i128`) used to index past the block and panic
/// (issue #105); the scheme returns [`OreError::TooManyBlocks`] for it.
pub const MAX_BLOCKS: usize = 15;

impl OreAes128 {
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

impl OreAes128 {
    /// Initialise the cipher from two 16-byte keys: `k1` keys PRF₁ (the
    /// per-block tags) and `k2` keys PRF₂ (the per-block PRP seeds),
    /// directly. The wire format is frozen, so this stays two-key and
    /// unsalted; the v2 schemes take one key and a salt.
    ///
    /// Fails ([`OreError::Random`]) only if the OS random number generator
    /// could not seed the nonce generator.
    pub fn init(k1: Protected<[u8; 16]>, k2: Protected<[u8; 16]>) -> Result<Self, OreError> {
        Self::init_with_rng(k1, k2, SafeRand::from_entropy()?)
    }

    /// [`Self::init`] with every nonce drawn from `seed`, so a test can pin
    /// a full ciphertext's bytes. Never ship a seeded cipher: two values
    /// encrypted under one seed share their nonces.
    #[cfg(any(test, feature = "test-support"))]
    pub fn init_seeded(
        k1: Protected<[u8; 16]>,
        k2: Protected<[u8; 16]>,
        seed: [u8; 32],
    ) -> Result<Self, OreError> {
        use vitaminc_random::SeedableRng;
        Self::init_with_rng(k1, k2, SafeRand::from_seed(seed))
    }

    fn init_with_rng(
        k1: Protected<[u8; 16]>,
        k2: Protected<[u8; 16]>,
        rng: SafeRand,
    ) -> Result<Self, OreError> {
        Ok(OreAes128 {
            prf1: Prf::new(GenericArray::from_slice(k1.risky_ref())),
            prf2: Prf::new(GenericArray::from_slice(k2.risky_ref())),
            rng: Mutex::new(rng),
        })
    }

    /// Draw one nonce; see the Bit6 sibling.
    fn fill_nonce(&self, nonce: &mut [u8; NONCE_SIZE]) {
        let mut rng = self
            .rng
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match rng.try_fill_bytes(nonce) {
            Ok(()) => {}
            Err(never) => match never {},
        }
    }
}

/// Encrypt `bytes`, which are exactly `N` long, as `N` blocks, serialised.
fn fixed<const N: usize>(cipher: &OreAes128, bytes: &[u8]) -> Result<Vec<u8>, OreError> {
    let input: &[u8; N] = bytes
        .try_into()
        // The plaintext is sealed, so its length is its width; refused
        // rather than unwrapped all the same.
        .map_err(|_| OreError::InitFailed)?;
    OreCipher::encrypt(cipher, input).map(|ct| ct.to_bytes())
}

/// [`fixed`], for the left half.
fn fixed_left<const N: usize>(cipher: &OreAes128, bytes: &[u8]) -> Result<Vec<u8>, OreError> {
    let input: &[u8; N] = bytes.try_into().map_err(|_| OreError::InitFailed)?;
    OreCipher::encrypt_left(cipher, input).map(|left| left.to_bytes())
}

/// The bytes of a fixed-width plaintext this scheme takes: up to
/// [`MAX_BLOCKS`], one block per byte. Text and bytes are
/// [`OreError::VariableLength`]; a wider plaintext is
/// [`OreError::TooManyBlocks`].
fn fixed_width_bytes(plaintext: &OrderPlaintext) -> Result<&[u8], OreError> {
    match plaintext.width() {
        None => Err(OreError::VariableLength),
        Some(width) if width > MAX_BLOCKS => Err(OreError::TooManyBlocks),
        Some(_) => Ok(plaintext.bytes().risky_ref().as_slice()),
    }
}

/// Run `$f::<N>(cipher, bytes)` for the `N` that is `bytes.len()`, one
/// arm per width the scheme takes. Stable Rust cannot pick `N` from a
/// runtime value, so each is named.
macro_rules! by_width {
    ($f:ident, $cipher:expr, $bytes:expr) => {
        match $bytes.len() {
            0 => $f::<0>($cipher, $bytes),
            1 => $f::<1>($cipher, $bytes),
            2 => $f::<2>($cipher, $bytes),
            3 => $f::<3>($cipher, $bytes),
            4 => $f::<4>($cipher, $bytes),
            5 => $f::<5>($cipher, $bytes),
            6 => $f::<6>($cipher, $bytes),
            7 => $f::<7>($cipher, $bytes),
            8 => $f::<8>($cipher, $bytes),
            9 => $f::<9>($cipher, $bytes),
            10 => $f::<10>($cipher, $bytes),
            11 => $f::<11>($cipher, $bytes),
            12 => $f::<12>($cipher, $bytes),
            13 => $f::<13>($cipher, $bytes),
            14 => $f::<14>($cipher, $bytes),
            15 => $f::<15>($cipher, $bytes),
            _ => Err(OreError::TooManyBlocks),
        }
    };
}

impl crate::sealed::Sealed for OreAes128 {}

impl OreScheme for OreAes128 {
    fn encrypt_plaintext(&self, plaintext: &OrderPlaintext) -> Result<Term, OreError> {
        let bytes = fixed_width_bytes(plaintext)?;
        by_width!(fixed, self, bytes).map(Term::new)
    }

    fn encrypt_query_plaintext(&self, plaintext: &OrderPlaintext) -> Result<Query, OreError> {
        let bytes = fixed_width_bytes(plaintext)?;
        by_width!(fixed_left, self, bytes).map(Query::new)
    }

    fn compare_raw_slices(a: &[u8], b: &[u8]) -> Option<Ordering> {
        if a.len() != b.len() {
            return None;
        };
        let left_size = LeftBlock16::BLOCK_SIZE;
        let right_size = RightBlock32::BLOCK_SIZE;

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

    /// The legacy wire has no header, so the block count is the left
    /// ciphertext's length over a left block's. `None` for a length that
    /// is not a left ciphertext's, a full ciphertext of another count, or
    /// a malformed block.
    fn compare_left_to_full(left: &[u8], full: &[u8]) -> Option<Ordering> {
        let per_block = LeftBlock16::BLOCK_SIZE + 1;
        if left.len() % per_block != 0 {
            return None;
        }
        fn typed<const N: usize>(left: &[u8], full: &[u8]) -> Option<Ordering> {
            let left = Left::<OreAes128, N>::from_slice(left).ok()?;
            let full = CipherText::<OreAes128, N>::from_slice(full).ok()?;
            Some(compare_typed(&left, &full))
        }
        match left.len() / per_block {
            0 => typed::<0>(left, full),
            1 => typed::<1>(left, full),
            2 => typed::<2>(left, full),
            3 => typed::<3>(left, full),
            4 => typed::<4>(left, full),
            5 => typed::<5>(left, full),
            6 => typed::<6>(left, full),
            7 => typed::<7>(left, full),
            8 => typed::<8>(left, full),
            9 => typed::<9>(left, full),
            10 => typed::<10>(left, full),
            11 => typed::<11>(left, full),
            12 => typed::<12>(left, full),
            13 => typed::<13>(left, full),
            14 => typed::<14>(left, full),
            15 => typed::<15>(left, full),
            _ => None,
        }
    }
}

impl OreCipher for OreAes128 {
    type LeftBlockType = LeftBlock16;
    type RightBlockType = RightBlock32;

    fn encrypt_left<const N: usize>(&self, x: &PlainText<N>) -> EncryptLeftResult<N> {
        if N > MAX_BLOCKS {
            return Err(OreError::TooManyBlocks);
        }
        let mut output = Left::<Self, N>::init();

        let seeds = derive_prp_seeds(&self.prf2, x);
        self.build_left(&mut output, &seeds, x)?;
        self.prf1.encrypt_all(&mut output.f);

        Ok(output)
    }

    fn encrypt<const N: usize>(&self, x: &PlainText<N>) -> EncryptResult<N> {
        if N > MAX_BLOCKS {
            return Err(OreError::TooManyBlocks);
        }
        let mut left = Left::<Self, N>::init();
        let mut right = Right::<Self, N>::init();

        // Generate a 16-byte random nonce
        self.fill_nonce(&mut right.nonce);

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

impl<const N: usize> PartialEq for CipherText<OreAes128, N> {
    fn eq(&self, b: &Self) -> bool {
        matches!(self.cmp(b), Ordering::Equal)
    }
}

impl<const N: usize> Ord for CipherText<OreAes128, N> {
    fn cmp(&self, b: &Self) -> Ordering {
        compare_typed(&self.left, b)
    }
}

/// The typed comparator: `left`'s plaintext against `b`'s. Reads only
/// `left` and `b`, as the raw comparator reads only `a`'s left view.
fn compare_typed<const N: usize>(
    left: &Left<OreAes128, N>,
    b: &CipherText<OreAes128, N>,
) -> Ordering {
    let mut is_equal = Choice::from(1);
    // Latch the first differing block during the scan, as in
    // `compare_raw_slices`: no load after the loop is indexed by its
    // position.
    let mut diff = FirstDiff::<{ RightBlock32::BLOCK_SIZE }>::new();

    for n in 0..N {
        let condition: Choice =
            !(left.xt[n].ct_eq(&b.left.xt[n])) | !(left.f[n].ct_eq(&b.left.f[n]));
        // Set for exactly one `n`: the first differing block.
        let first = is_equal & condition;

        diff.latch(left.xt[n], &left.f[n], b.right.data[n].bytes(), first);
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

impl<const N: usize> PartialOrd for CipherText<OreAes128, N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/*
 * (From the Rust docs)
 * This property cannot be checked by the compiler, and therefore Eq implies PartialEq, and has no extra methods.
 */
impl<const N: usize> Eq for CipherText<OreAes128, N> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{bytes_pt, f64_pt, fixed_key, key, timestamp_pt, u128_pt, u32_pt, u64_pt};
    use quickcheck::TestResult;

    type Ore = OreAes128;

    fn init_ore() -> Ore {
        Ore::init(key(), key()).unwrap()
    }

    fn full<const N: usize>(ore: &Ore, plaintext: &OrderPlaintext) -> CipherText<Ore, N> {
        let term = ore.encrypt_plaintext(plaintext).unwrap();
        CipherText::from_slice(term.as_bytes()).unwrap()
    }

    fn full_u64(ore: &Ore, x: u64) -> CipherText<Ore, 8> {
        full(ore, &u64_pt(x))
    }

    fn term_bytes(ore: &Ore, plaintext: &OrderPlaintext) -> Vec<u8> {
        ore.encrypt_plaintext(plaintext).unwrap().into_bytes()
    }

    /// A 16-byte plaintext does not fit the left-tag input (issue #105): an
    /// error, not an out-of-bounds panic. 15 bytes is the most the scheme
    /// takes, so a `u128` is refused by width, a timestamp (12 bytes) is
    /// taken, and text has no width to take.
    #[test]
    fn sixteen_bytes_is_an_error_not_a_panic() {
        let ore = init_ore();
        assert!(matches!(
            OreCipher::encrypt(&ore, &[0u8; 16]),
            Err(OreError::TooManyBlocks)
        ));
        assert!(matches!(
            OreCipher::encrypt_left(&ore, &[0u8; 16]),
            Err(OreError::TooManyBlocks)
        ));
        assert!(OreCipher::encrypt(&ore, &[0u8; 15]).is_ok());
        assert!(OreCipher::encrypt_left(&ore, &[0u8; 15]).is_ok());

        assert!(matches!(
            ore.encrypt_plaintext(&u128_pt(1)),
            Err(OreError::TooManyBlocks)
        ));
        assert!(matches!(
            ore.encrypt_query_plaintext(&u128_pt(1)),
            Err(OreError::TooManyBlocks)
        ));
        assert!(ore.encrypt_plaintext(&timestamp_pt(1)).is_ok());
        assert!(matches!(
            ore.encrypt_plaintext(&bytes_pt(b"x")),
            Err(OreError::VariableLength)
        ));
    }

    /// The legacy wire has no header, so the comparator infers the block
    /// count from the length. Lengths that do not fit `n·(1 + 16 + 32) + 16`
    /// must be refused, not indexed: two empty slices used to underflow the
    /// nonce subtraction, and a partial block to slice past the end.
    #[test]
    fn compare_raw_slices_refuses_malformed_lengths() {
        let ore = init_ore();
        let good = term_bytes(&ore, &u64_pt(42));
        assert_eq!(Ore::compare_raw_slices(&[], &[]), None);
        assert_eq!(Ore::compare_raw_slices(&good[..15], &good[..15]), None);
        assert_eq!(Ore::compare_raw_slices(&good[..17], &good[..17]), None);
        assert_eq!(
            Ore::compare_raw_slices(&good[..good.len() - 1], &good[..good.len() - 1]),
            None
        );
        assert_eq!(Ore::compare_raw_slices(&good, &good), Some(Ordering::Equal));
    }

    /// A nonce-only input is the valid zero-block ciphertext: it parses, and
    /// two of them compare `Equal`.
    #[test]
    fn compare_raw_slices_accepts_zero_blocks() {
        let ore = init_ore();
        let a = OreCipher::encrypt(&ore, &[0u8; 0]).unwrap();
        let b = OreCipher::encrypt(&ore, &[0u8; 0]).unwrap();
        let (a_bytes, b_bytes) = (a.to_bytes(), b.to_bytes());
        assert_eq!(a_bytes.len(), NONCE_SIZE);
        assert_eq!(
            Ore::compare_raw_slices(&a_bytes, &b_bytes),
            Some(Ordering::Equal)
        );
        let parsed = CipherText::<Ore, 0>::from_slice(&a_bytes).unwrap();
        assert_eq!(parsed.cmp(&b), Ordering::Equal);
    }

    /// A left (query) ciphertext against a full one: the order of the
    /// plaintexts, and `None` for the pairs that are not a left and a full
    /// of one block count.
    #[test]
    fn left_to_full_orders_as_the_plaintexts_and_refuses_the_rest() {
        let ore = init_ore();
        let query = ore.encrypt_query_plaintext(&u64_pt(7)).unwrap();
        let (below, same, above) = (
            term_bytes(&ore, &u64_pt(6)),
            term_bytes(&ore, &u64_pt(7)),
            term_bytes(&ore, &u64_pt(8)),
        );
        let left = query.as_bytes();
        assert_eq!(left.len(), 8 * 17);
        assert_eq!(
            Ore::compare_left_to_full(left, &below),
            Some(Ordering::Greater)
        );
        assert_eq!(
            Ore::compare_left_to_full(left, &same),
            Some(Ordering::Equal)
        );
        assert_eq!(
            Ore::compare_left_to_full(left, &above),
            Some(Ordering::Less)
        );
        // A full as the left, a left as the full, another count, a partial block.
        assert_eq!(Ore::compare_left_to_full(&same, &same), None);
        assert_eq!(Ore::compare_left_to_full(left, left), None);
        assert_eq!(
            Ore::compare_left_to_full(left, &term_bytes(&ore, &u32_pt(7))),
            None
        );
        assert_eq!(Ore::compare_left_to_full(&left[1..], &same), None);
        // The query is the term's left half, so this is `Ord`'s answer too.
        let typed_left = Left::<Ore, 8>::from_slice(left).unwrap();
        assert_eq!(typed_left.to_bytes(), full_u64(&ore, 7).left.to_bytes());
    }

    quickcheck! {
        fn compare_u64(x: u64, y: u64) -> bool {
            let ore = init_ore();
            let a = full_u64(&ore, x);
            let b = full_u64(&ore, y);

            match x.cmp(&y) {
                Ordering::Greater => a > b,
                Ordering::Less    => a < b,
                Ordering::Equal   => a == b
            }
        }

        fn compare_u64_raw_slices(x: u64, y: u64) -> bool {
            let ore = init_ore();
            let a = term_bytes(&ore, &u64_pt(x));
            let b = term_bytes(&ore, &u64_pt(y));

            match Ore::compare_raw_slices(&a, &b) {
                Some(Ordering::Greater) => x > y,
                Some(Ordering::Less)    => x < y,
                Some(Ordering::Equal)   => x == y,
                None                    => false
            }
        }

        fn left_to_full_u64(x: u64, y: u64) -> bool {
            let ore = init_ore();
            let left = ore.encrypt_query_plaintext(&u64_pt(x)).unwrap();
            let full = term_bytes(&ore, &u64_pt(y));
            Ore::compare_left_to_full(left.as_bytes(), &full) == Some(x.cmp(&y))
        }

        fn equality_u64(x: u64) -> bool {
            let ore = init_ore();
            full_u64(&ore, x) == full_u64(&ore, x)
        }

        fn equality_u64_raw_slices(x: u64) -> bool {
            let ore = init_ore();
            let a = term_bytes(&ore, &u64_pt(x));
            let b = term_bytes(&ore, &u64_pt(x));
            Ore::compare_raw_slices(&a, &b) == Some(Ordering::Equal)
        }

        fn compare_u32(x: u32, y: u32) -> bool {
            let ore = init_ore();
            let a: CipherText<Ore, 4> = full(&ore, &u32_pt(x));
            let b: CipherText<Ore, 4> = full(&ore, &u32_pt(y));

            match x.cmp(&y) {
                Ordering::Greater => a > b,
                Ordering::Less    => a < b,
                Ordering::Equal   => a == b
            }
        }

        fn equality_u32(x: u32) -> bool {
            let ore = init_ore();
            let a: CipherText<Ore, 4> = full(&ore, &u32_pt(x));
            let b: CipherText<Ore, 4> = full(&ore, &u32_pt(x));
            a == b
        }

        fn compare_f64(x: f64, y: f64) -> TestResult {
            if x.is_nan() || x.is_infinite() || y.is_nan() || y.is_infinite() {
                return TestResult::discard();
            }

            let ore = init_ore();
            let a: CipherText<Ore, 8> = full(&ore, &f64_pt(x));
            let b: CipherText<Ore, 8> = full(&ore, &f64_pt(y));

            match x.partial_cmp(&y) {
                Some(Ordering::Greater) => TestResult::from_bool(a > b),
                Some(Ordering::Less)    => TestResult::from_bool(a < b),
                Some(Ordering::Equal)   => TestResult::from_bool(a == b),
                None                    => TestResult::failed()
            }
        }

        fn equality_f64(x: f64) -> bool {
            let ore = init_ore();
            let a: CipherText<Ore, 8> = full(&ore, &f64_pt(x));
            let b: CipherText<Ore, 8> = full(&ore, &f64_pt(x));
            a == b
        }

        /// The block-level path on big-endian bytes is the `U64` target's
        /// encoding, so it orders the same way, and matches the sealed path.
        fn compare_plaintext(x: u64, y: u64) -> bool {
            let ore = init_ore();
            let a = OreCipher::encrypt(&ore, &x.to_be_bytes()).unwrap();
            let b = OreCipher::encrypt(&ore, &y.to_be_bytes()).unwrap();

            match x.cmp(&y) {
                Ordering::Greater => a > b,
                Ordering::Less    => a < b,
                Ordering::Equal   => a == b
            }
        }

        fn equality_plaintext(x: u64) -> bool {
            let ore = init_ore();
            let a = OreCipher::encrypt(&ore, &x.to_be_bytes()).unwrap();
            let b = OreCipher::encrypt(&ore, &x.to_be_bytes()).unwrap();
            a == b && a == full_u64(&ore, x)
        }
    }

    #[test]
    fn smallest_to_largest() {
        let ore = init_ore();
        assert!(full_u64(&ore, 0) < full_u64(&ore, u64::MAX));
    }

    #[test]
    fn largest_to_smallest() {
        let ore = init_ore();
        assert!(full_u64(&ore, u64::MAX) > full_u64(&ore, 0));
    }

    #[test]
    fn smallest_to_smallest() {
        let ore = init_ore();
        assert!(full_u64(&ore, 0) == full_u64(&ore, 0));
    }

    #[test]
    fn largest_to_largest() {
        let ore = init_ore();
        assert!(full_u64(&ore, u64::MAX) == full_u64(&ore, u64::MAX));
    }

    // f64 encodes +0.0 and -0.0 to the same bytes, so their ciphertexts
    // compare equal, as the floats do.
    #[test]
    fn signed_zeros_compare_equal() {
        let ore = init_ore();
        let pos_zero: CipherText<Ore, 8> = full(&ore, &f64_pt(0.0));
        let neg_zero: CipherText<Ore, 8> = full(&ore, &f64_pt(-0.0));

        assert_eq!(0.0_f64.partial_cmp(&-0.0_f64), Some(Ordering::Equal));
        assert!(pos_zero == neg_zero);
    }

    #[test]
    fn comparisons_in_first_block() {
        let ore = init_ore();
        let a = full_u64(&ore, 18446744073709551615u64);
        let b = full_u64(&ore, 18446744073709551612u64);

        assert!(a > b);
        assert!(b < a);
    }

    #[test]
    fn comparisons_in_last_block() {
        let ore = init_ore();
        let a = full_u64(&ore, 10);
        let b = full_u64(&ore, 73);

        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn compare_raw_slices_mismatched_lengths() {
        let ore = init_ore();
        let a_64 = term_bytes(&ore, &u64_pt(10));
        let a_32 = term_bytes(&ore, &u32_pt(10));

        assert_eq!(Ore::compare_raw_slices(&a_64, &a_32), Option::None);
    }

    #[test]
    fn binary_encoding() {
        let ore = init_ore();
        let a = full_u64(&ore, 10);
        let bin = a.to_bytes();
        assert_eq!(a, CipherText::<Ore, 8>::from_slice(&bin).unwrap());
    }

    #[test]
    #[should_panic(expected = "ParseError")]
    fn binary_encoding_invalid_length() {
        let bin = vec![0, 1, 2, 3];
        CipherText::<Ore, 8>::from_slice(&bin).unwrap();
    }

    const K1: [u8; 16] = [
        97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
    ];
    const K2: [u8; 16] = [
        129, 4, 114, 186, 102, 145, 225, 73, 166, 57, 244, 251, 56, 92, 188, 36,
    ];
    const K3: [u8; 16] = [
        49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 97, 98, 99, 100, 101, 102,
    ];

    #[test]
    fn test_different_prf_keys() {
        let ore1 = Ore::init(Protected::new(K1), Protected::new(K2)).unwrap();
        let ore2 = Ore::init(Protected::new(K3), Protected::new(K2)).unwrap();

        let a = term_bytes(&ore1, &u32_pt(1000));
        let b = term_bytes(&ore2, &u32_pt(1000));

        assert_ne!(Some(Ordering::Equal), Ore::compare_raw_slices(&a, &b));
    }

    #[test]
    fn test_different_prp_keys() {
        let ore1 = Ore::init(Protected::new(K1), Protected::new(K2)).unwrap();
        let ore2 = Ore::init(Protected::new(K1), Protected::new(K3)).unwrap();

        let a = term_bytes(&ore1, &u32_pt(1000));
        let b = term_bytes(&ore2, &u32_pt(1000));

        assert_ne!(Some(Ordering::Equal), Ore::compare_raw_slices(&a, &b));
    }

    /// A seeded cipher draws the same nonces again; an entropy-seeded one
    /// does not.
    #[test]
    fn a_seeded_cipher_is_reproducible() {
        let a = Ore::init_seeded(fixed_key(1), fixed_key(2), [9; 32]).unwrap();
        let b = Ore::init_seeded(fixed_key(1), fixed_key(2), [9; 32]).unwrap();
        assert_eq!(term_bytes(&a, &u64_pt(5)), term_bytes(&b, &u64_pt(5)));
        let c = Ore::init(fixed_key(1), fixed_key(2)).unwrap();
        assert_ne!(term_bytes(&a, &u64_pt(5)), term_bytes(&c, &u64_pt(5)));
    }
}
