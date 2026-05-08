//! BlockORE implementation using a 2-bit indicator function, AES-128 as
//! the per-block PRF, and Knuth-shuffle for the per-block PRP. Plaintexts
//! are arrays of bytes (`PlainText<N>`); the construction packs
//! `(prefix ‖ xt[i] ‖ block_index)` into a single 16-byte AES input, which
//! caps `N` at 15.

use crate::{
    ciphertext::*,
    primitives::{
        hash::Aes128Z2Hash, prf::Aes128Prf, prp::KnuthShufflePRP, AesBlock, Hash, HashKey, Prf,
        Prp, NONCE_SIZE,
    },
    OreCipher, OreError, PlainText,
};

use aes::cipher::generic_array::GenericArray;
use lazy_static::lazy_static;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::cell::RefCell;
use std::cmp::Ordering;
use subtle_ng::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::ZeroizeOnDrop;

/// Per-block ciphertext component types ([`LeftBlock16`], [`RightBlock32`])
/// used by this scheme.
pub mod block_types;
pub use self::block_types::*;

/// AES-128 BlockORE cipher, generic over the RNG used to draw per-encryption
/// nonces. The two PRF instances are keyed at construction; the RNG is held
/// in a `RefCell` so encryption can take `&self` while still drawing fresh
/// randomness. Keys are zeroised on drop.
#[derive(Debug, ZeroizeOnDrop)]
pub struct OreAes128<R: Rng + SeedableRng> {
    prf1: Aes128Prf,
    prf2: Aes128Prf,
    #[zeroize(skip)]
    rng: RefCell<R>,
}

/// Convenience alias for [`OreAes128`] backed by `ChaCha20Rng` — the RNG
/// most callers will want.
pub type OreAes128ChaCha20 = OreAes128<ChaCha20Rng>;

/* Define some convenience types */
type EncryptLeftResult<R, const N: usize> = Result<Left<OreAes128<R>, N>, OreError>;
type EncryptResult<R, const N: usize> = Result<CipherText<OreAes128<R>, N>, OreError>;

fn cmp(a: u8, b: u8) -> u8 {
    use subtle_ng::ConstantTimeGreater;
    a.ct_gt(&b).unwrap_u8()
}

/// Branchless-friendly conversion from a tristate i8 (`-1` = Less,
/// `0` = Equal, `1` = Greater) to `std::cmp::Ordering`. This is the
/// single observable branch in the comparison's externally visible
/// contract; everything before it is constant-time.
#[inline]
fn ordering_from_i8(t: i8) -> Ordering {
    match t {
        1 => Ordering::Greater,
        0 => Ordering::Equal,
        _ => Ordering::Less,
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

        // Build the prefixes
        // TODO: Don't modify struct values directly - use a function on a "Left" trait
        output.f.iter_mut().enumerate().for_each(|(n, block)| {
            block[0..n].clone_from_slice(&x[0..n]);
            // TODO: Include the block number in the prefix to avoid repeating values for common
            // blocks in a long prefix
            // e.g. when plaintext is 4700 (2-bytes/blocks)
            // xt = [17, 17, 17, 17, 17, 17, 223, 76]
        });

        self.prf2.encrypt_all(&mut output.f);

        for (n, xn) in x.iter().enumerate().take(N) {
            // Set prefix and create PRP for the block
            let prp: KnuthShufflePRP<u8, 256> = Prp::new(&output.f[n])?;

            output.xt[n] = prp.permute(*xn)?;
        }

        // Reset the f block
        // We don't actually need to clear sensitive data here, we
        // just need fast "zero set". Reassigning the value will drop the old one and allocate new
        // data to the stack
        output.f = [Default::default(); N];

        for n in 0..N {
            output.f[n][0..n].clone_from_slice(&x[0..n]);
            output.f[n][n] = output.xt[n];
            // Include the block number in the value passed to the Random Oracle
            output.f[n][N] = n as u8;
        }
        self.prf1.encrypt_all(&mut output.f);

        Ok(output)
    }

    fn encrypt<const N: usize>(&self, x: &PlainText<N>) -> EncryptResult<R, N> {
        let mut left = Left::<Self, N>::init();
        let mut right = Right::<Self, N>::init();

        // Generate a 16-byte random nonce
        self.rng.borrow_mut().try_fill(&mut right.nonce)?;

        // Build the prefixes
        // TODO: Don't modify struct values directly - use a function on a "Left"
        left.f.iter_mut().enumerate().for_each(|(n, block)| {
            block[0..n].clone_from_slice(&x[0..n]);
        });

        self.prf2.encrypt_all(&mut left.f);

        // To make zeroizing / resetting the RO keys
        // Since the AesBlock type is stack allocated this should get optimised to a single memcpy
        lazy_static! {
            static ref ZEROED_RO_KEYS: [AesBlock; 256] = [Default::default(); 256];
        }

        let mut ro_keys = *ZEROED_RO_KEYS;

        for n in 0..N {
            // Set prefix and create PRP for the block
            let prp: KnuthShufflePRP<u8, 256> = Prp::new(&left.f[n])?;

            left.xt[n] = prp.permute(x[n])?;

            // Reset the f block
            left.f[n].default_in_place();

            left.f[n][0..n].clone_from_slice(&x[0..n]);
            left.f[n][n] = left.xt[n];
            // Include the block number in the value passed to the Random Oracle
            left.f[n][N] = n as u8;

            for (j, ro_key) in ro_keys.iter_mut().enumerate() {
                /*
                 * The output of F in H(F(k1, y|i-1||j), r)
                 */
                ro_key[0..n].clone_from_slice(&x[0..n]);
                ro_key[n] = j as u8;
                ro_key[N] = n as u8;
            }

            self.prf1.encrypt_all(&mut ro_keys);

            /* TODO: This seems to work but it is technically using the nonce as the key
             * (instead of using it as the plaintext). This appears to be how the original
             * ORE implementation does it but it feels a bit wonky to me. Should check with David.
             * It is useful though because the AES crate makes it easy to encrypt groups of 8
             * plaintexts under the same key. We really want the ability to encrypt the same
             * plaintext (i.e. the nonce) under different keys but this may be an acceptable
             * approximation.
             *
             * If not, we will probably need to implement our own parallel encrypt using intrisics
             * like in the AES crate: https://github.com/RustCrypto/block-ciphers/blob/master/aes/src/ni/aes128.rs#L26
             */
            let hasher: Aes128Z2Hash = Hash::new(AesBlock::from_slice(&right.nonce));
            let hashes = hasher.hash_all(&mut ro_keys);

            // FIXME: force casting to u8 from usize could cause a panic
            for (j, h) in hashes.iter().enumerate() {
                let jstar = prp.invert(j as u8)?;
                let indicator = cmp(jstar, x[n]);
                right.data[n].set_bit(j, indicator ^ h);
            }

            // Zeroize / reset the RO keys before the next loop iteration
            ro_keys.clone_from_slice(&*ZEROED_RO_KEYS);
        }

        self.prf1.encrypt_all(&mut left.f);

        Ok(CipherText { left, right })
    }

    fn compare_raw_slices(a: &[u8], b: &[u8]) -> Option<Ordering> {
        if a.len() != b.len() {
            return None;
        };
        let left_size = Self::LeftBlockType::BLOCK_SIZE;
        let right_size = Self::RightBlockType::BLOCK_SIZE;
        let block_total = left_size + right_size + 1;

        // Reject malformed ciphertexts. The byte layout is
        // `num_blocks * block_total + NONCE_SIZE`, so a.len() must be at
        // least NONCE_SIZE and the remainder must divide evenly. Without
        // this check, `a.len() - NONCE_SIZE` would wrap on undersized
        // input and `num_blocks` would be silently wrong on non-canonical
        // sizes (the latter is what cargo-mutants used to find a coverage
        // gap on this function).
        if a.len() < NONCE_SIZE {
            return None;
        }
        let body_len = a.len() - NONCE_SIZE;
        if body_len % block_total != 0 {
            return None;
        }
        let num_blocks = body_len / block_total;

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

        let b_right = &b[num_blocks * (left_size + 1)..];
        let hash_key = HashKey::from_slice(&b_right[0..NONCE_SIZE]);
        let hash: Aes128Z2Hash = Hash::new(hash_key);
        let right_data = &b_right[NONCE_SIZE..];

        // Hash every block, use subtle_ng to pick the contribution at index l.
        // `test` ends up holding the masked bit from the unequal block; for all
        // other blocks it stays 0. Constant-time because the conditional_assign
        // is byte-wise CT and the loop runs unconditionally over num_blocks.
        let mut test: u8 = 0;
        for (n, &a_n) in a.iter().enumerate().take(num_blocks) {
            let is_target: Choice = (n as u64).ct_eq(&(l as u64));
            let h_n = hash.hash(left_block(a_f, n));
            let target_block_n = right_block(right_data, n);
            let bit_n = get_bit(target_block_n, a_n as usize);
            let candidate = bit_n ^ h_n;
            test.conditional_assign(&candidate, is_target);
        }

        // Encode as i8: 1 = Greater, -1 = Less, 0 = Equal.
        // `test` is 0 or 1, so (test as i8) * 2 - 1 is +1 or -1.
        let mut order: i8 = (test as i8) * 2 - 1;
        order.conditional_assign(&0i8, is_equal);

        Some(ordering_from_i8(order))
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

#[inline]
fn get_bit(block: &[u8], bit: usize) -> u8 {
    debug_assert!(block.len() == RightBlock32::BLOCK_SIZE);
    debug_assert!(bit < 256);
    let byte_index = bit >> 3;
    let position = bit & 0b111;
    (block[byte_index] >> position) & 1
}

impl<const N: usize> PartialEq for CipherText<OreAes128ChaCha20, N> {
    fn eq(&self, b: &Self) -> bool {
        matches!(self.cmp(b), Ordering::Equal)
    }
}

impl<const N: usize> Ord for CipherText<OreAes128ChaCha20, N> {
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

        let hash: Aes128Z2Hash = Hash::new(AesBlock::from_slice(&b.right.nonce));

        let mut test: u8 = 0;
        for n in 0..N {
            let is_target: Choice = (n as u64).ct_eq(&(l as u64));
            let h_n = hash.hash(&self.left.f[n]);
            let bit_n = b.right.data[n].get_bit(self.left.xt[n] as usize);
            let candidate = bit_n ^ h_n;
            test.conditional_assign(&candidate, is_target);
        }

        let mut order: i8 = (test as i8) * 2 - 1;
        order.conditional_assign(&0i8, is_equal);

        ordering_from_i8(order)
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
    fn compare_raw_slices_too_short() {
        // Both inputs equal length but shorter than NONCE_SIZE — malformed.
        // Without the precondition, a.len() - NONCE_SIZE would wrap.
        let short = vec![0u8; 8];
        assert_eq!(Ore::compare_raw_slices(&short, &short), None);
    }

    #[test]
    fn compare_raw_slices_non_divisible_body() {
        // a.len() = 17 -> body_len = 1, not divisible by 49. Malformed.
        let weird = vec![0u8; 17];
        assert_eq!(Ore::compare_raw_slices(&weird, &weird), None);
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
