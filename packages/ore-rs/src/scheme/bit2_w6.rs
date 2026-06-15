//! BlockORE with **6-bit input blocks** (domain 64): the `(Bit6, packed
//! prefix, fixed-N)` scheme from the ORE v2 plan.
//!
//! Plaintext bytes are decomposed MSB-first into 6-bit block values (see
//! [`crate::scheme::decompose`]); `N` in the types below counts *blocks*,
//! not bytes (a `u64` is 11 blocks). Compared to the legacy 8-bit scheme,
//! each block costs 64 random-oracle evaluations instead of 256 and stores
//! an 8-byte right block instead of 32 — a `u64` ciphertext is 295 bytes
//! (vs 408) including the 4-byte v2 wire header.
//!
//! The packed prefix caps `N` at 14 (`prefix ≤ 13 ‖ value ‖ index` plus
//! the block count in byte 15 must fit one AES block), which covers all
//! primitives up to 64 bits. `u128`/`i128`/`Decimal` stay on the legacy
//! scheme until the chained-prefix construction lands (plan §5).
//!
//! **Status: wire format NOT yet frozen.** The Z2 hash is the fixed-π MMO
//! construction proposed in plan §6 (option 3), pending crypto review;
//! flipping [`Z2Hash`] re-keys the right ciphertexts without any other
//! code change. Do not store ciphertexts produced by this scheme until
//! the review lands and vectors are pinned.

use crate::{
    ciphertext::*,
    primitives::{
        hash::FixedPiZ2Hash, prf::Aes128Prf, AesBlock, Hash, HashKey, Prf, Prp, NONCE_SIZE,
    },
    scheme::width::{AesBlockBuf, Bit6, BlockWidth, RightBitVec},
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
#[derive(Debug, ZeroizeOnDrop)]
pub struct OreAes128Bit6<R: Rng + SeedableRng> {
    prf1: Aes128Prf,
    prf2: Aes128Prf,
    #[zeroize(skip)]
    rng: RefCell<R>,
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

impl<R: Rng + SeedableRng> OreAes128Bit6<R> {
    /// Per-block PRP seeds: `PRF₂(x[0..n] ‖ 0… ‖ N)`. Unlike the legacy
    /// scheme, the block count is bound into byte 15 (domain separation
    /// across plaintext shapes under shared keys, plan §4) — though the
    /// per-block index is still absent by construction (prefix-equal
    /// plaintexts must share seeds only up to the first differing block;
    /// binding the *count* keeps cross-type prefixes apart).
    fn derive_prp_seeds<const N: usize>(&self, x: &PlainText<N>) -> SeedBuf<N> {
        let mut seeds = [AesBlock::default(); N];
        for (n, block) in seeds.iter_mut().enumerate() {
            block[0..n].clone_from_slice(&x[0..n]);
            block[15] = N as u8;
        }
        self.prf2.encrypt_all(&mut seeds);
        SeedBuf(seeds)
    }
}

fn encode_right_block(
    block: &mut <Bit6 as BlockWidth>::RightBlock,
    prp: &<Bit6 as BlockWidth>::Prp,
    x: u8,
    hasher: &Z2Hash,
    ro_blocks: &mut [AesBlock],
) {
    debug_assert_eq!(ro_blocks.len(), <Bit6 as BlockWidth>::DOMAIN);
    let out = block.as_mut_bytes();
    hasher.hash_all_into(ro_blocks, out);
    prp.indicator_mask_xor(x, out);
}

impl<R: Rng + SeedableRng> OreCipher for OreAes128Bit6<R> {
    type LeftBlockType = LeftBlock16;
    type RightBlockType = RightBlock8;

    const WIRE_HEADER: Option<WireHeader> = Some(WIRE);

    fn init(k1: &[u8; 16], k2: &[u8; 16]) -> Result<Self, OreError> {
        let rng: R = SeedableRng::from_entropy();

        Ok(OreAes128Bit6 {
            prf1: Prf::new(GenericArray::from_slice(k1)),
            prf2: Prf::new(GenericArray::from_slice(k2)),
            rng: RefCell::new(rng),
        })
    }

    /// Encrypt `x`, whose entries are **6-bit block values** (`< 64`,
    /// produced by [`crate::scheme::decompose`]); `N` is the block count
    /// (≤ [`MAX_BLOCKS`]). The [`crate::OreEncrypt`] impls handle the
    /// byte→block decomposition for primitive types.
    fn encrypt_left<const N: usize>(&self, x: &PlainText<N>) -> EncryptLeftResult<R, N> {
        assert!(N <= MAX_BLOCKS);
        debug_assert!(x
            .iter()
            .all(|&b| (b as usize) < <Bit6 as BlockWidth>::DOMAIN));

        let mut output = Left::<Self, N>::init();
        let seeds = self.derive_prp_seeds(x);

        for n in 0..N {
            let prp: <Bit6 as BlockWidth>::Prp = Prp::new(&seeds.0[n])?;
            output.xt[n] = prp.permute(x[n])?;

            output.f[n][0..n].clone_from_slice(&x[0..n]);
            output.f[n][n] = output.xt[n];
            output.f[n][N] = n as u8;
            output.f[n][15] = N as u8;
        }
        self.prf1.encrypt_all(&mut output.f);

        Ok(output)
    }

    fn encrypt<const N: usize>(&self, x: &PlainText<N>) -> EncryptResult<R, N> {
        assert!(N <= MAX_BLOCKS);
        debug_assert!(x
            .iter()
            .all(|&b| (b as usize) < <Bit6 as BlockWidth>::DOMAIN));

        let mut left = Left::<Self, N>::init();
        let mut right = Right::<Self, N>::init();

        self.rng.borrow_mut().try_fill(&mut right.nonce)?;

        let seeds = self.derive_prp_seeds(x);
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
            left.xt[n] = prp.permute(x[n])?;

            left.f[n][0..n].clone_from_slice(&x[0..n]);
            left.f[n][n] = left.xt[n];
            left.f[n][N] = n as u8;
            left.f[n][15] = N as u8;

            if n > 0 {
                for (j, entry) in template.iter_mut().enumerate() {
                    entry[n - 1] = x[n - 1];
                    entry[n] = j as u8;
                    entry[N] = n as u8;
                }
            }

            work.copy_from(&template);
            self.prf1.encrypt_all(work.as_mut_slice());

            encode_right_block(&mut right.data[n], &prp, x[n], &hasher, &mut work);
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
        }
        let (header_a, a) = parse_header(a).ok()?;
        let (header_b, b) = parse_header(b).ok()?;
        if header_a != header_b || (header_a.0, header_a.1) != (WIRE.version, WIRE.scheme_id) {
            return None;
        }
        let num_blocks = header_a.2;
        if num_blocks > MAX_BLOCKS {
            return None;
        }

        let left_size = Self::LeftBlockType::BLOCK_SIZE;
        let right_size = Self::RightBlockType::BLOCK_SIZE;
        if a.len() != num_blocks * (left_size + 1 + right_size) + NONCE_SIZE {
            return None;
        }

        let mut is_equal = Choice::from(1);
        let mut l: u64 = 0; // Unequal block

        // Slices for the PRF ("f") blocks
        let a_f = &a[num_blocks..];
        let b_f = &b[num_blocks..];

        for n in 0..num_blocks {
            let prp_eq: Choice = !a[n].ct_eq(&b[n]);
            let left_block_comparison: Choice = !left_block(a_f, n).ct_eq(left_block(b_f, n));
            let condition: Choice = prp_eq | left_block_comparison;

            l.conditional_assign(&(n as u64), is_equal & condition);
            is_equal.conditional_assign(&Choice::from(0), is_equal & condition);
        }

        let l: usize = l as usize;

        if bool::from(is_equal) {
            return Some(Ordering::Equal);
        }

        let b_right = &b[num_blocks * (left_size + 1)..];
        let hash: Z2Hash = Hash::new(HashKey::from_slice(&b_right[0..NONCE_SIZE]));
        let h = hash.hash(left_block(a_f, l));

        let target_block = right_block(&b_right[NONCE_SIZE..], l);
        let test = get_bit(target_block, a[l] as usize) ^ h;

        if test == 1 {
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

#[inline]
fn get_bit(block: &[u8], bit: usize) -> u8 {
    debug_assert!(block.len() == RightBlock8::BLOCK_SIZE);
    debug_assert!(bit < 64);
    // `bit` is the secret permuted symbol; read the byte obliviously so the
    // access address does not depend on it. See `width::ct_select_byte`.
    let byte = crate::scheme::width::ct_select_byte(block, bit / 8);
    (byte >> (bit % 8)) & 1
}

impl<const N: usize> PartialEq for CipherText<OreAes128Bit6ChaCha20, N> {
    fn eq(&self, b: &Self) -> bool {
        matches!(self.cmp(b), Ordering::Equal)
    }
}

impl<const N: usize> Ord for CipherText<OreAes128Bit6ChaCha20, N> {
    fn cmp(&self, b: &Self) -> Ordering {
        let mut is_equal = Choice::from(1);
        let mut l: u64 = 0; // Unequal block

        for n in 0..N {
            let condition: Choice =
                !(self.left.xt[n].ct_eq(&b.left.xt[n])) | !(self.left.f[n].ct_eq(&b.left.f[n]));

            l.conditional_assign(&(n as u64), is_equal & condition);
            is_equal.conditional_assign(&Choice::from(0), is_equal & condition);
        }

        let l: usize = l as usize;

        if bool::from(is_equal) {
            return Ordering::Equal;
        }

        let hash: Z2Hash = Hash::new(HashKey::from_slice(&b.right.nonce));
        let h = hash.hash(&self.left.f[l]);

        let test = b.right.data[l].get_bit(self.left.xt[l] as usize) ^ h;
        if test == 1 {
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
    use crate::scheme::decompose::{decompose_6bit, num_blocks_6bit};
    use crate::{CipherText, Left, OreCipher, OreEncrypt, OreError};
    use orderable_bytes::ToOrderableBytes;
    use rand::{Rng, SeedableRng};

    macro_rules! impl_ore_encrypt_bit6 {
        ($type:ty, $blocks_const:ident) => {
            /// Block count for this type at 6-bit width.
            const $blocks_const: usize = num_blocks_6bit(<$type as ToOrderableBytes>::ENCODED_LEN);
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
                    let bytes = self.to_orderable_bytes();
                    let mut blocks = [0u8; $blocks_const];
                    decompose_6bit(&bytes, &mut blocks);
                    cipher.encrypt_left(&blocks)
                }

                fn encrypt(&self, cipher: &OreAes128Bit6<R>) -> Result<Self::FullOutput, OreError> {
                    let bytes = self.to_orderable_bytes();
                    let mut blocks = [0u8; $blocks_const];
                    decompose_6bit(&bytes, &mut blocks);
                    cipher.encrypt(&blocks)
                }
            }
        };
    }

    impl_ore_encrypt_bit6!(bool, BOOL_BLOCKS);
    impl_ore_encrypt_bit6!(u8, U8_BLOCKS);
    impl_ore_encrypt_bit6!(i8, I8_BLOCKS);
    impl_ore_encrypt_bit6!(u16, U16_BLOCKS);
    impl_ore_encrypt_bit6!(i16, I16_BLOCKS);
    impl_ore_encrypt_bit6!(u32, U32_BLOCKS);
    impl_ore_encrypt_bit6!(i32, I32_BLOCKS);
    impl_ore_encrypt_bit6!(u64, U64_BLOCKS);
    impl_ore_encrypt_bit6!(i64, I64_BLOCKS);
    impl_ore_encrypt_bit6!(char, CHAR_BLOCKS);
    impl_ore_encrypt_bit6!(f32, F32_BLOCKS);
    impl_ore_encrypt_bit6!(f64, F64_BLOCKS);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::OreEncrypt;
    use crate::OreOutput;
    use quickcheck::TestResult;

    type Ore = OreAes128Bit6ChaCha20;

    fn init_ore() -> Ore {
        let mut k1: [u8; 16] = Default::default();
        let mut k2: [u8; 16] = Default::default();

        let mut rng = ChaCha20Rng::from_entropy();

        rng.fill(&mut k1);
        rng.fill(&mut k2);

        OreCipher::init(&k1, &k2).unwrap()
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
        let legacy: OreAes128ChaCha20 = OreCipher::init(&k1, &k2).unwrap();
        let bit6: Ore = OreCipher::init(&k1, &k2).unwrap();

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
        let k2 = [2u8; 16];
        let k3 = [3u8; 16];

        let ore1: Ore = OreCipher::init(&k1, &k2).unwrap();
        let ore2: Ore = OreCipher::init(&k3, &k2).unwrap();

        let a = 1000u32.encrypt(&ore1).unwrap().to_bytes();
        let b = 1000u32.encrypt(&ore2).unwrap().to_bytes();

        assert_ne!(Some(Ordering::Equal), Ore::compare_raw_slices(&a, &b));
    }
}
