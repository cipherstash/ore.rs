//! BlockORE with **6-bit input blocks** (domain 64): the `(Bit6, packed
//! prefix, fixed-N)` scheme from the ORE v2 plan.
//!
//! Plaintext bytes are decomposed MSB-first into 6-bit block values (see
//! the crate-private `scheme::decompose`); `N` in the types below counts *blocks*,
//! not bytes (a `u64` is 11 blocks). Compared to the legacy 8-bit scheme,
//! each block costs 64 random-oracle evaluations instead of 256 and stores
//! an 8-byte right block instead of 32 — a `u64` ciphertext is 295 bytes
//! (vs 408) including the 4-byte v2 wire header.
//!
//! The packed prefix caps `N` at 14 (`prefix ≤ 13 ‖ value ‖ index` plus
//! the block count in byte 15 must fit one AES block; seeds also use byte
//! 14 for the block index), which covers all
//! primitives up to 64 bits. `Decimal` stays on the legacy scheme until the
//! chained-prefix construction lands (plan §5). `u128`/`i128` (22 blocks)
//! fit neither this scheme nor the legacy one (15 bytes at most); they are
//! encrypted with [`crate::scheme::chained`], which has no length cap.
//!
//! **Status: wire format NOT yet frozen.** The Z2 hash is the fixed-π MMO
//! construction proposed in plan §6 (option 3), pending crypto review;
//! flipping the private `Z2Hash` alias re-keys the right ciphertexts without any other
//! code change. Do not store ciphertexts produced by this scheme until
//! the review lands and vectors are pinned.
//!
//! **Keys:** one 16-byte key and an optional salt. PRF₁ and PRF₂ run under
//! keys derived through the crate-private `scheme::keys` stages (root
//! label, salt, per-PRF label), never the raw key, so sharing a key with
//! the legacy scheme does not let legacy ciphertexts reveal Bit6 masking
//! keys, and ciphertexts under different salts share no key material.

use crate::{
    ciphertext::*,
    primitives::{
        hash::FixedPiZ2Hash, prf::Aes128Prf, stack, AesBlock, Hash, HashKey, Prf, Prp, NONCE_SIZE,
    },
    scheme::decompose::Blocks6,
    scheme::keys,
    scheme::width::{AesBlockBuf, Bit6, BlockWidth, FirstDiff},
    OreCipher, OreError, PlainText,
};

use aes::cipher::generic_array::GenericArray;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::cell::RefCell;
use std::cmp::Ordering;
use subtle_ng::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Per-block ciphertext component types for this scheme.
pub mod block_types;
pub use self::block_types::*;

/// The Z2 random-oracle instantiation for this scheme (plan §6, option 3 —
/// pending review; option 2 fallback is `Aes128Z2Hash` with an extra
/// feedforward, and the legacy construction is `Aes128Z2Hash`).
type Z2Hash = FixedPiZ2Hash;

/// Maximum number of blocks: the packed prefix (`prefix ‖ value ‖ index`)
/// plus the block count at byte 15 must fit one 16-byte AES input.
pub const MAX_BLOCKS: usize = 14;

/// AES-128 BlockORE cipher over 6-bit blocks, generic over the RNG used
/// for per-encryption nonces. Keys are zeroised on drop.
#[derive(ZeroizeOnDrop)]
pub struct OreAes128Bit6<R: Rng + SeedableRng> {
    prf1: Aes128Prf,
    prf2: Aes128Prf,
    #[zeroize(skip)]
    rng: RefCell<R>,
}

// Opaque Debug: never render key material (OpaqueDebug discipline).
impl<R: Rng + SeedableRng> std::fmt::Debug for OreAes128Bit6<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OreAes128Bit6").finish_non_exhaustive()
    }
}

/// Convenience alias for [`OreAes128Bit6`] backed by `ChaCha20Rng`.
pub type OreAes128Bit6ChaCha20 = OreAes128Bit6<ChaCha20Rng>;

type EncryptLeftResult<R, const N: usize> = Result<Left<OreAes128Bit6<R>, N>, OreError>;
type EncryptResult<R, const N: usize> = Result<CipherText<OreAes128Bit6<R>, N>, OreError>;

/// v2 wire header for this scheme: version 2, scheme id 0x02
/// (= AES-128 suite, 6-bit blocks, packed prefix).
const WIRE: WireHeader = WireHeader {
    version: 0x02,
    scheme_id: 0x02,
};

/// PRP seeds are key-equivalent material; see the bit2 sibling for the
/// full rationale. Zeroized on drop.
struct SeedBuf<const N: usize>([AesBlock; N]);

impl<const N: usize> Drop for SeedBuf<N> {
    fn drop(&mut self) {
        for seed in self.0.iter_mut() {
            seed.zeroize();
        }
    }
}

/// The only input the caller's key is evaluated on: `k_root = AES_key(ROOT_LABEL)`.
///
/// Bit6 must not evaluate PRF₁/PRF₂ under the caller's raw key, because
/// the legacy scheme does, and its inputs cover Bit6's: a legacy `N = 15`
/// left ciphertext publishes exactly the PRF₁ outputs Bit6 uses as its
/// masking keys. Deriving separate keys separates the schemes.
///
/// The label itself must never be a legacy PRF input, or a legacy
/// ciphertext would publish the root key. Every legacy PRF₁ input has
/// byte 15 in `0..=14` (the block index at `N = 15`, else `0`) and every
/// legacy PRF₂ input has byte 15 `= 0`; this label ends in ASCII `'t'`
/// (`0x74`), so it is outside both. See `scheme::keys`.
const ROOT_LABEL: [u8; 16] = *b"ORE.v2.bit6.root";

/// Labels for the two PRF keys under the salted key:
/// `prf1 = AES_{k_salt}(PRF1_LABEL)`, `prf2 = AES_{k_salt}(PRF2_LABEL)`.
const PRF1_LABEL: [u8; 16] = *b"ORE.v2.bit6.prf1";
const PRF2_LABEL: [u8; 16] = *b"ORE.v2.bit6.prf2";

impl<R: Rng + SeedableRng> OreAes128Bit6<R> {
    /// Per-block PRP seeds: `PRF₂(x[0..n] ‖ 0… ‖ n@14 ‖ N@15)`. The block
    /// count in byte 15 separates plaintext shapes (plan §4); the block
    /// index in byte 14 separates positions, so a prefix padded with zero
    /// blocks no longer collides with a shorter prefix (which gave every
    /// position of an all-zero plaintext the same permutation). Prefixes
    /// equal up to block `n` still share `seed_n`, as the comparator needs.
    /// `N ≤ 14` puts the prefix in bytes `0..=12`, so byte 14 is free.
    fn derive_prp_seeds<const N: usize>(&self, x: &PlainText<N>) -> SeedBuf<N> {
        let mut seeds = [AesBlock::default(); N];
        for (n, block) in seeds.iter_mut().enumerate() {
            block[0..n].clone_from_slice(&x[0..n]);
            block[14] = n as u8;
            block[15] = N as u8;
        }
        self.prf2.encrypt_all(&mut seeds);
        SeedBuf(seeds)
    }

    /// [`OreCipher::encrypt_left`] over blocks already known to be in the
    /// 6-bit domain, without the stack scrub. Every caller runs it inside
    /// [`stack::scrubbed`]: building a block's PRP leaves its seed and tables
    /// in dead stack (see `primitives::stack`).
    pub(crate) fn encrypt_left_blocks<const N: usize>(
        &self,
        x: &Blocks6<PlainText<N>>,
    ) -> EncryptLeftResult<R, N> {
        if N > MAX_BLOCKS {
            return Err(OreError::TooManyBlocks);
        }

        let mut output = Left::<Self, N>::init();
        let seeds = self.derive_prp_seeds(x.inner());

        for n in 0..N {
            let prp: <Bit6 as BlockWidth>::Prp = Prp::new(&seeds.0[n])?;
            output.xt[n] = prp.permute(x.symbol(n)).get();

            output.f[n][0..n].clone_from_slice(&x.as_bytes()[0..n]);
            output.f[n][n] = output.xt[n];
            output.f[n][N] = n as u8;
            output.f[n][15] = N as u8;
        }
        self.prf1.encrypt_all(&mut output.f);

        Ok(output)
    }

    /// [`OreCipher::encrypt`] over blocks already known to be in the 6-bit
    /// domain, without the stack scrub; see [`Self::encrypt_left_blocks`].
    pub(crate) fn encrypt_blocks<const N: usize>(
        &self,
        x: &Blocks6<PlainText<N>>,
    ) -> EncryptResult<R, N> {
        if N > MAX_BLOCKS {
            return Err(OreError::TooManyBlocks);
        }

        let mut left = Left::<Self, N>::init();
        let mut right = Right::<Self, N>::init();

        self.rng.borrow_mut().try_fill(&mut right.nonce)?;

        let seeds = self.derive_prp_seeds(x.inner());
        let hasher: Z2Hash = Hash::new(HashKey::from_slice(&right.nonce));

        // RO key template, maintained incrementally (see the bit2 sibling).
        // Entry j for block n is (x[0..n] ‖ j ‖ 0… ‖ n@N ‖ N@15).
        let mut template = <Bit6 as BlockWidth>::RoKeyBuf::zeroed();
        for (j, entry) in template.iter_mut().enumerate() {
            entry[0] = j as u8;
            entry[15] = N as u8;
        }
        let mut work = <Bit6 as BlockWidth>::RoKeyBuf::zeroed();

        for n in 0..N {
            let prp: <Bit6 as BlockWidth>::Prp = Prp::new(&seeds.0[n])?;
            left.xt[n] = prp.permute(x.symbol(n)).get();

            left.f[n][0..n].clone_from_slice(&x.as_bytes()[0..n]);
            left.f[n][n] = left.xt[n];
            left.f[n][N] = n as u8;
            left.f[n][15] = N as u8;

            if n > 0 {
                for (j, entry) in template.iter_mut().enumerate() {
                    entry[n - 1] = x.as_bytes()[n - 1];
                    entry[n] = j as u8;
                    entry[N] = n as u8;
                }
            }

            work.copy_from(&template);
            self.prf1.encrypt_all(work.as_mut_slice());

            crate::scheme::bit2::encode_right_block::<Bit6, _>(
                &mut right.data[n],
                &prp,
                x.symbol(n),
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

// Right-block encoding is the width-/hash-generic helper shared with the
// legacy scheme: `crate::scheme::bit2::encode_right_block::<Bit6, Z2Hash>`.

impl<R: Rng + SeedableRng> OreAes128Bit6<R> {
    /// Initialise the cipher from one 16-byte key, with an empty salt:
    /// `init_with_salt(key, &[])`.
    pub fn init(key: &[u8; 16]) -> Result<Self, OreError> {
        Self::init_with_salt(key, &[])
    }

    /// Initialise the cipher from one 16-byte key and a salt naming what
    /// the key is for (a column, a tenant, a plaintext type). PRF₁ and
    /// PRF₂ are keyed by `AES_{k_salt}(label)` with
    /// `k_salt = CMAC_{AES_key(ROOT_LABEL)}(salt)`; see the crate-private
    /// `scheme::keys` for the stages and their argument.
    ///
    /// Ciphertexts under different salts share no key material, but
    /// nothing on the wire records the salt, so the comparators cannot
    /// refuse a mismatched pair: they return a confident, meaningless
    /// result, `Equal` included (a typed comparison of zero blocks is
    /// `Equal` under any salts), so no result confirms that two salts
    /// match. Keep the salt with the identity of the stored data, as you
    /// keep the key.
    pub fn init_with_salt(key: &[u8; 16], salt: &[u8]) -> Result<Self, OreError> {
        let k_salt = keys::salted(&keys::root(key, &ROOT_LABEL), salt);
        let prf1 = Prf::new(GenericArray::from_slice(&*keys::subkey(
            &k_salt,
            &PRF1_LABEL,
        )));
        let prf2 = Prf::new(GenericArray::from_slice(&*keys::subkey(
            &k_salt,
            &PRF2_LABEL,
        )));
        Ok(OreAes128Bit6 {
            prf1,
            prf2,
            rng: RefCell::new(SeedableRng::from_entropy()),
        })
    }
}

impl<R: Rng + SeedableRng> OreCipher for OreAes128Bit6<R> {
    type LeftBlockType = LeftBlock16;
    type RightBlockType = RightBlock8;

    const WIRE_HEADER: Option<WireHeader> = Some(WIRE);
    const SYMBOL_DOMAIN: usize = <Bit6 as BlockWidth>::DOMAIN;

    /// Encrypt `x`, whose entries are **6-bit block values** (`< 64`, as
    /// the crate-private `scheme::decompose` produces); `N` is the block count
    /// (≤ [`MAX_BLOCKS`]; more returns [`OreError::TooManyBlocks`]). The [`crate::OreEncrypt`] impls handle the
    /// byte→block decomposition for primitive types and skip the check
    /// below. A value `>= 64` returns [`OreError::PrpError`].
    fn encrypt_left<const N: usize>(&self, x: &PlainText<N>) -> EncryptLeftResult<R, N> {
        stack::scrubbed(|| self.encrypt_left_blocks(&Blocks6::check(*x)?))
    }

    /// As [`Self::encrypt_left`], for the full ciphertext.
    fn encrypt<const N: usize>(&self, x: &PlainText<N>) -> EncryptResult<R, N> {
        stack::scrubbed(|| self.encrypt_blocks(&Blocks6::check(*x)?))
    }

    fn compare_raw_slices(a: &[u8], b: &[u8]) -> Option<Ordering> {
        if a.len() != b.len() {
            return None;
        }
        let (header_a, a) = parse_header(a).ok()?;
        let (header_b, b) = parse_header(b).ok()?;
        if header_a != header_b || (header_a.0, header_a.1) != (WIRE.version, WIRE.scheme_id) {
            return None;
        }
        let num_blocks = header_a.2;
        // Reject a degenerate count=0 header: no OreEncrypt path produces zero
        // blocks, and an empty scan would otherwise return Equal for any pair
        // of crafted 0-block ciphertexts.
        if num_blocks == 0 || num_blocks > MAX_BLOCKS {
            return None;
        }

        let left_size = Self::LeftBlockType::BLOCK_SIZE;
        let right_size = Self::RightBlockType::BLOCK_SIZE;
        if a.len() != num_blocks * (left_size + 1 + right_size) + NONCE_SIZE {
            return None;
        }
        // Reject symbols outside the 64-element domain: the scan below reads
        // the right block at `a[l]`, which must index one of its 64 bits.
        // `xt` is public, so this may branch.
        if a[..num_blocks]
            .iter()
            .chain(&b[..num_blocks])
            .any(|&s| usize::from(s) >= <Bit6 as BlockWidth>::DOMAIN)
        {
            return None;
        }

        let mut is_equal = Choice::from(1);
        // What the resolution step needs from the first differing block `l`:
        // `a`'s permuted symbol and PRF tag, and `b`'s right bitvector. All
        // three are latched *inside* the scan, under the choice "this is the
        // first difference", so no load after the loop is indexed by `l`.
        // The right blocks are the one region the scan would otherwise never
        // touch, so a direct `right[l]` afterwards hits or misses the cache
        // according to `l`; measured as a timing signal, see `docs/reviews/`.
        let mut diff = FirstDiff::<{ RightBlock8::BLOCK_SIZE }>::new();

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

        let hash: Z2Hash = Hash::new(HashKey::from_slice(&b_right[0..NONCE_SIZE]));

        if diff.resolve(&hash) == 1 {
            return Some(Ordering::Greater);
        }

        Some(Ordering::Less)
    }
}

#[inline]
fn left_block(input: &[u8], n: usize) -> &[u8] {
    let f_pos = n * LeftBlock16::BLOCK_SIZE;
    &input[f_pos..(f_pos + LeftBlock16::BLOCK_SIZE)]
}

#[inline]
fn right_block(input: &[u8], n: usize) -> &[u8] {
    let f_pos = n * RightBlock8::BLOCK_SIZE;
    &input[f_pos..(f_pos + RightBlock8::BLOCK_SIZE)]
}

impl<const N: usize> PartialEq for CipherText<OreAes128Bit6ChaCha20, N> {
    fn eq(&self, b: &Self) -> bool {
        matches!(self.cmp(b), Ordering::Equal)
    }
}

impl<const N: usize> Ord for CipherText<OreAes128Bit6ChaCha20, N> {
    fn cmp(&self, b: &Self) -> Ordering {
        let mut is_equal = Choice::from(1);
        // Latch the first differing block during the scan, as in
        // `compare_raw_slices`: no load after the loop is indexed by its
        // position.
        let mut diff = FirstDiff::<{ RightBlock8::BLOCK_SIZE }>::new();

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

        let hash: Z2Hash = Hash::new(HashKey::from_slice(&b.right.nonce));
        if diff.resolve(&hash) == 1 {
            return Ordering::Greater;
        }

        Ordering::Less
    }
}

impl<const N: usize> PartialOrd for CipherText<OreAes128Bit6ChaCha20, N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize> Eq for CipherText<OreAes128Bit6ChaCha20, N> {}

// ---------------------------------------------------------------------------
// OreEncrypt impls: byte → 6-bit-block decomposition per primitive type.
// ---------------------------------------------------------------------------

mod encrypt_impls {
    use super::{OreAes128Bit6, MAX_BLOCKS};
    use crate::primitives::stack;
    use crate::scheme::decompose::{num_blocks_6bit, Blocks6};
    use crate::{CipherText, Left, OreEncrypt, OreError};
    use orderable_bytes::{FixedOrderableBytes, OrderableBytes};
    use rand::{Rng, SeedableRng};

    // Each invocation also emits a test that the type round-trips, orders
    // `$lo` below `$hi`, and compares equal across nonces, so a type cannot
    // be listed as supported without being exercised (issue #105).
    macro_rules! impl_ore_encrypt_bit6 {
        ($type:ty, $blocks_const:ident, $tests:ident, $lo:expr, $hi:expr) => {
            /// Block count for this type at 6-bit width.
            const $blocks_const: usize =
                num_blocks_6bit(<$type as FixedOrderableBytes>::ENCODED_LEN);
            // The packed prefix caps the block count; types beyond it
            // (u128, i128, Decimal) must not get these impls.
            const _: () = assert!($blocks_const <= MAX_BLOCKS);

            impl<R: Rng + SeedableRng> OreEncrypt<OreAes128Bit6<R>> for $type {
                type LeftOutput = Left<OreAes128Bit6<R>, $blocks_const>;
                type FullOutput = CipherText<OreAes128Bit6<R>, $blocks_const>;

                fn encrypt_left(
                    &self,
                    cipher: &OreAes128Bit6<R>,
                ) -> Result<Self::LeftOutput, OreError> {
                    // The plaintext's bytes and blocks are copies in this
                    // frame, so they go inside the scrub too.
                    stack::scrubbed(|| {
                        let bytes = self.to_orderable_bytes();
                        let blocks = Blocks6::decompose(&bytes, [0u8; $blocks_const]);
                        cipher.encrypt_left_blocks(&blocks)
                    })
                }

                fn encrypt(&self, cipher: &OreAes128Bit6<R>) -> Result<Self::FullOutput, OreError> {
                    stack::scrubbed(|| {
                        let bytes = self.to_orderable_bytes();
                        let blocks = Blocks6::decompose(&bytes, [0u8; $blocks_const]);
                        cipher.encrypt_blocks(&blocks)
                    })
                }
            }

            #[cfg(test)]
            mod $tests {
                use super::*;
                use crate::scheme::bit2_w6::OreAes128Bit6ChaCha20;
                use crate::{OreCipher, OreOutput};
                use std::cmp::Ordering;

                #[test]
                fn round_trip_order_and_equality() {
                    let ore = OreAes128Bit6ChaCha20::init(&[0x11; 16]).unwrap();
                    let (lo, hi): ($type, $type) = ($lo, $hi);
                    assert!(lo < hi);

                    let lo_ct = lo.encrypt(&ore).unwrap();
                    let hi_ct = hi.encrypt(&ore).unwrap();
                    let lo_left = lo.encrypt_left(&ore).unwrap();
                    let lo_ct2 = lo.encrypt(&ore).unwrap();

                    let lo_bytes = lo_ct.to_bytes();
                    let hi_bytes = hi_ct.to_bytes();
                    assert_eq!(
                        CipherText::<OreAes128Bit6ChaCha20, $blocks_const>::from_slice(&lo_bytes)
                            .unwrap()
                            .to_bytes(),
                        lo_bytes
                    );
                    assert_eq!(
                        Left::<OreAes128Bit6ChaCha20, $blocks_const>::from_slice(
                            &lo_left.to_bytes()
                        )
                        .unwrap()
                        .to_bytes(),
                        lo_left.to_bytes()
                    );

                    let cmp = OreAes128Bit6ChaCha20::compare_raw_slices;
                    assert_eq!(cmp(&lo_bytes, &hi_bytes), Some(Ordering::Less));
                    assert_eq!(cmp(&hi_bytes, &lo_bytes), Some(Ordering::Greater));
                    assert_ne!(lo_bytes, lo_ct2.to_bytes());
                    assert_eq!(cmp(&lo_bytes, &lo_ct2.to_bytes()), Some(Ordering::Equal));
                    assert_eq!(lo_ct.cmp(&hi_ct), Ordering::Less);
                }
            }
        };
    }

    impl_ore_encrypt_bit6!(bool, BOOL_BLOCKS, bool_tests, false, true);
    impl_ore_encrypt_bit6!(u8, U8_BLOCKS, u8_tests, 0u8, u8::MAX);
    impl_ore_encrypt_bit6!(i8, I8_BLOCKS, i8_tests, i8::MIN, i8::MAX);
    impl_ore_encrypt_bit6!(u16, U16_BLOCKS, u16_tests, 0u16, u16::MAX);
    impl_ore_encrypt_bit6!(i16, I16_BLOCKS, i16_tests, i16::MIN, i16::MAX);
    impl_ore_encrypt_bit6!(u32, U32_BLOCKS, u32_tests, 0u32, u32::MAX);
    impl_ore_encrypt_bit6!(i32, I32_BLOCKS, i32_tests, i32::MIN, i32::MAX);
    impl_ore_encrypt_bit6!(u64, U64_BLOCKS, u64_tests, 0u64, u64::MAX);
    impl_ore_encrypt_bit6!(i64, I64_BLOCKS, i64_tests, i64::MIN, i64::MAX);
    // `u128`/`i128` (22 blocks) exceed `MAX_BLOCKS` and are provided by
    // `scheme::chained` instead (issue #105).
    impl_ore_encrypt_bit6!(char, CHAR_BLOCKS, char_tests, '\0', char::MAX);
    impl_ore_encrypt_bit6!(f32, F32_BLOCKS, f32_tests, f32::MIN, f32::MAX);
    impl_ore_encrypt_bit6!(f64, F64_BLOCKS, f64_tests, f64::MIN, f64::MAX);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::OreEncrypt;
    use crate::OreOutput;
    use quickcheck::TestResult;

    type Ore = OreAes128Bit6ChaCha20;

    fn init_ore() -> Ore {
        let mut key: [u8; 16] = Default::default();
        ChaCha20Rng::from_entropy().fill(&mut key);
        Ore::init(&key).unwrap()
    }

    /// `init` is the empty salt; another salt gives unrelated ciphertexts,
    /// and the same salt reproduces them. The two column salts have equal
    /// lengths, so the length prefix alone cannot separate them.
    #[test]
    fn salt_separates_keys() {
        let key = [0x42u8; 16];
        let plain = Ore::init(&key).unwrap();
        let empty = Ore::init_with_salt(&key, &[]).unwrap();
        let col_a = Ore::init_with_salt(&key, b"users.age").unwrap();
        let col_a2 = Ore::init_with_salt(&key, b"users.age").unwrap();
        let col_b = Ore::init_with_salt(&key, b"users.dob").unwrap();

        let left = |c: &Ore| 456u64.encrypt_left(c).unwrap().to_bytes();
        assert_eq!(left(&plain), left(&empty));
        assert_eq!(left(&col_a), left(&col_a2));
        assert_ne!(left(&plain), left(&col_a));
        assert_ne!(left(&col_a), left(&col_b));

        let a = 456u64.encrypt(&col_a).unwrap().to_bytes();
        let b = 456u64.encrypt(&col_b).unwrap().to_bytes();
        assert_ne!(Ore::compare_raw_slices(&a, &b), Some(Ordering::Equal));
        assert_eq!(
            Ore::compare_raw_slices(&a, &456u64.encrypt(&col_a2).unwrap().to_bytes()),
            Some(Ordering::Equal)
        );
    }

    /// A block count past `MAX_BLOCKS` through the public `OreCipher` path
    /// is an error, as on the legacy scheme, not a panic (review of #113).
    #[test]
    fn too_many_blocks_is_an_error_not_a_panic() {
        let ore = init_ore();
        assert!(matches!(
            ore.encrypt(&[0u8; MAX_BLOCKS + 1]),
            Err(OreError::TooManyBlocks)
        ));
        assert!(matches!(
            ore.encrypt_left(&[0u8; MAX_BLOCKS + 1]),
            Err(OreError::TooManyBlocks)
        ));
        assert!(ore.encrypt(&[0u8; MAX_BLOCKS]).is_ok());
        assert!(ore.encrypt_left(&[0u8; MAX_BLOCKS]).is_ok());
    }

    /// Cross-scheme regression (review of #82): under keys shared with the
    /// legacy scheme, a legacy `N = 15` left ciphertext must never publish
    /// one of Bit6's PRF₁ tags. Bit6's `f[0]` for an 11-block value has PRF₁
    /// input `xt[0] ‖ 0×10 ‖ 0@11 ‖ 0×3 ‖ 11@15`; legacy block 11 of
    /// `(xt[0], 0×10, c, 0×3)` has input `xt[0] ‖ 0×10 ‖ xt'[11] ‖ 0×3 ‖
    /// 11@15`, which matches whenever `c` permutes to 0. Search every `c`.
    /// Blocks passed straight to `OreCipher` are checked: a value outside
    /// the 6-bit domain is refused, and an in-domain array encrypts exactly
    /// as the decomposing `OreEncrypt` path does.
    #[test]
    fn raw_blocks_are_checked() {
        let ore = init_ore();
        let mut blocks = [0u8; 11];
        blocks[3] = 64;
        assert!(matches!(
            OreCipher::encrypt(&ore, &blocks),
            Err(OreError::PrpError(_))
        ));
        assert!(matches!(
            OreCipher::encrypt_left(&ore, &blocks),
            Err(OreError::PrpError(_))
        ));

        let x = 0x0123_4567_89ab_cdefu64;
        let decomposed = crate::scheme::decompose::Blocks6::decompose(&x.to_be_bytes(), [0u8; 11]);
        let raw = OreCipher::encrypt_left(&ore, decomposed.inner()).unwrap();
        assert_eq!(raw.to_bytes(), x.encrypt_left(&ore).unwrap().to_bytes());
    }

    #[test]
    fn legacy_ciphertexts_never_publish_bit6_tags() {
        use crate::scheme::bit2::OreAes128ChaCha20;

        let mut k1 = [0u8; 16];
        let mut k2 = [0u8; 16];
        let mut rng = ChaCha20Rng::from_entropy();
        rng.fill(&mut k1);
        rng.fill(&mut k2);
        let bit6 = Ore::init(&k1).unwrap();
        let legacy = OreAes128ChaCha20::init(&k1, &k2).unwrap();

        let target = bit6.encrypt_left(&[0u8; 11]).unwrap();
        let tag = target.f[0];

        let mut probe = [0u8; 15];
        probe[0] = target.xt[0];
        for c in 0..=255u8 {
            probe[11] = c;
            let left = legacy.encrypt_left(&probe).unwrap();
            assert!(
                !bool::from(left.f[11].ct_eq(&tag)),
                "legacy block 11 reproduced a Bit6 tag (c = {})",
                c
            );
        }
    }

    /// Position-binding regression (review of #82): every position of an
    /// all-zero plaintext must get its own permutation, so its `xt` bytes
    /// are not all equal (they were, when seeds bound only the count).
    #[test]
    fn zero_blocks_use_distinct_permutations_per_position() {
        let ore = init_ore();
        let left = ore.encrypt_left(&[0u8; 11]).unwrap();
        let first = left.xt[0];
        assert!(
            left.xt.iter().any(|&s| s != first),
            "all 11 positions produced the same symbol"
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

        fn serialize_roundtrip_u64(x: u64) -> bool {
            let ore = init_ore();
            let a = x.encrypt(&ore).unwrap();
            let bytes = a.to_bytes();
            let b = CipherText::<Ore, 11>::from_slice(&bytes).unwrap();
            a == b
        }
    }

    #[test]
    fn ciphertext_sizes() {
        // u64: 11 blocks. header(4) + xt(11) + f(11*16) + nonce(16) + right(11*8)
        assert_eq!(CipherText::<Ore, 11>::size(), 4 + 11 + 176 + 16 + 88);
        let ore = init_ore();
        let ct = 456u64.encrypt(&ore).unwrap();
        assert_eq!(ct.to_bytes().len(), 295);
    }

    #[test]
    fn header_emitted_and_validated() {
        let ore = init_ore();
        let mut bytes = 456u64.encrypt(&ore).unwrap().to_bytes();
        assert_eq!(&bytes[0..4], &[0x02, 0x02, 0x00, 11]);

        // Corrupt each header field; parsing must fail.
        for i in 0..4 {
            let mut bad = bytes.clone();
            bad[i] ^= 0xff;
            assert!(CipherText::<Ore, 11>::from_slice(&bad).is_err());
        }

        // Truncation fails.
        bytes.pop();
        assert!(CipherText::<Ore, 11>::from_slice(&bytes).is_err());
    }

    #[test]
    fn cross_scheme_comparison_rejected() {
        use crate::scheme::bit2::OreAes128ChaCha20;

        let k1 = [1u8; 16];
        let k2 = [2u8; 16];
        let legacy = OreAes128ChaCha20::init(&k1, &k2).unwrap();
        let bit6 = Ore::init(&k1).unwrap();

        let a = 456u64.encrypt(&legacy).unwrap().to_bytes();
        let b = 456u64.encrypt(&bit6).unwrap().to_bytes();

        assert_eq!(Ore::compare_raw_slices(&a, &b), None);
        assert_eq!(Ore::compare_raw_slices(&b, &a), None);
        // The legacy comparator infers block count from length; a Bit6
        // u64 ciphertext (295 bytes) never matches a legacy length for
        // equal-length inputs, and unequal lengths return None up front.
        assert_eq!(OreAes128ChaCha20::compare_raw_slices(&a, &b), None);
    }

    #[test]
    fn cross_block_count_comparison_rejected() {
        let ore = init_ore();
        let a = 456u64.encrypt(&ore).unwrap().to_bytes();
        let b = 456u32.encrypt(&ore).unwrap().to_bytes();
        assert_eq!(Ore::compare_raw_slices(&a, &b), None);
    }

    #[test]
    fn smallest_to_largest() {
        let ore = init_ore();
        let a = 0u64.encrypt(&ore).unwrap();
        let b = u64::MAX.encrypt(&ore).unwrap();

        assert!(a < b);
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
    fn different_keys_not_equal() {
        let k1 = [1u8; 16];
        let k3 = [3u8; 16];

        let ore1 = Ore::init(&k1).unwrap();
        let ore2 = Ore::init(&k3).unwrap();

        let a = 1000u32.encrypt(&ore1).unwrap().to_bytes();
        let b = 1000u32.encrypt(&ore2).unwrap().to_bytes();

        assert_ne!(Some(Ordering::Equal), Ore::compare_raw_slices(&a, &b));
    }

    /// The PRP seeds and permutation tables of every block, which must not
    /// survive an encryption in dead stack (review of #82).
    fn block_secrets(ore: &Ore, blocks: &[u8; 11]) -> Vec<Vec<u8>> {
        let seeds = ore.derive_prp_seeds(blocks);
        let mut needles = Vec::new();
        for seed in seeds.0.iter() {
            let prp: <Bit6 as BlockWidth>::Prp = Prp::new(seed).unwrap();
            needles.push(seed.to_vec());
            let symbols = (0..64).map(crate::primitives::Symbol::<64>::from_low_bits);
            needles.push(symbols.clone().map(|i| prp.permute(i).get()).collect());
            needles.push(symbols.map(|i| prp.invert(i).get()).collect());
        }
        needles
    }

    fn assert_no_block_secrets(encrypt: fn(&Ore, u64), unscrubbed: fn(&Ore, u64)) {
        use crate::primitives::stack::{residue, SCRUB_BYTES};
        let k1 = [0x3cu8; 16];
        let x = 0x0123_4567_89ab_cdefu64;
        let needles = block_secrets(&Ore::init(&k1).unwrap(), u64_blocks(x).inner());

        // Positive control and depth: without the scrub the secrets are
        // there, and the scrub must reach deeper than the encryption did.
        let ore = Ore::init(&k1).unwrap();
        let dead = residue::after(move || unscrubbed(&ore, x));
        assert!(needles.iter().any(|n| residue::contains(&dead, n)));
        let depth = residue::depth(&dead);
        assert!(
            depth < SCRUB_BYTES,
            "encryption reached {} bytes of stack, past the {}-byte scrub",
            depth,
            SCRUB_BYTES
        );

        let ore = Ore::init(&k1).unwrap();
        let dead = residue::after(move || encrypt(&ore, x));
        for (i, needle) in needles.iter().enumerate() {
            assert!(
                !residue::contains(&dead, needle),
                "block {} {} left in dead stack",
                i / 3,
                ["seed", "permutation", "inverse"][i % 3]
            );
        }
    }

    fn u64_blocks(x: u64) -> Blocks6<[u8; 11]> {
        Blocks6::decompose(&x.to_be_bytes(), [0u8; 11])
    }

    #[test]
    fn encrypt_leaves_no_prp_secrets_on_the_stack() {
        assert_no_block_secrets(
            |ore, x| {
                core::hint::black_box(x.encrypt(ore).unwrap());
            },
            |ore, x| {
                core::hint::black_box(ore.encrypt_blocks(&u64_blocks(x)).unwrap());
            },
        );
    }

    #[test]
    fn encrypt_left_leaves_no_prp_secrets_on_the_stack() {
        assert_no_block_secrets(
            |ore, x| {
                core::hint::black_box(x.encrypt_left(ore).unwrap());
            },
            |ore, x| {
                core::hint::black_box(ore.encrypt_left_blocks(&u64_blocks(x)).unwrap());
            },
        );
    }
}
