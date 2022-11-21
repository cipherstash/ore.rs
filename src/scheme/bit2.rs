/*
 * Block ORE Implemenation using a 2-bit indicator function
 */

use crate::{
    ciphertext::*,
    primitives::{
        hash::{AES128Z2Hash, hash_all}, prf::AES128PRF, prp::{KnuthShufflePRP, block_shuffle}, AesBlock, Hash, HashKey, Prf,
        Prp, NONCE_SIZE,
    },
    ORECipher, OREError, PlainText,
};

use aes::cipher::generic_array::GenericArray;
use lazy_static::lazy_static;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{cell::RefCell, slice::Chunks};
use std::cmp::Ordering;
use subtle_ng::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{ZeroizeOnDrop, Zeroize};

pub mod block_types;
pub use self::block_types::*;

/* Define our scheme */
#[derive(Debug, ZeroizeOnDrop)]
pub struct OreAes128<R: Rng + SeedableRng> {
    prf1: AES128PRF,
    prf2: AES128PRF,
    #[zeroize(skip)]
    rng: RefCell<R>,
}

pub type OREAES128 = OreAes128<ChaCha20Rng>;

/* Define some convenience types */
type EncryptLeftResult<R, const N: usize> = Result<Left<OreAes128<R>, N>, OREError>;
type EncryptResult<R, const N: usize> = Result<CipherText<OreAes128<R>, N>, OREError>;

impl<R: Rng + SeedableRng> ORECipher for OreAes128<R> {
    type LeftBlockType = LeftBlock16;
    type RightBlockType = RightBlock32;

    fn init(k1: &[u8; 16], k2: &[u8; 16]) -> Result<Self, OREError> {
        // TODO: k1 and k2 should be Key types and we should have a set of traits to abstract the
        // behaviour ro parsing/loading etc

        let rng: R = SeedableRng::from_entropy();

        return Ok(OreAes128 {
            prf1: Prf::new(GenericArray::from_slice(k1)),
            prf2: Prf::new(GenericArray::from_slice(k2)),
            rng: RefCell::new(rng),
        });
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
            (output.xt[n], _) = block_shuffle(&output.f[n], *xn);
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
        self.rng
            .borrow_mut()
            .try_fill(&mut right.nonce)
            .map_err(|_| OREError)?;

        // Build the prefixes
        // TODO: Don't modify struct values directly - use a function on a "Left"
        left.f.iter_mut().enumerate().for_each(|(n, block)| {
            block[0..n].clone_from_slice(&x[0..n]);
            // TODO: Include the block number
        });

        self.prf2.encrypt_all(&mut left.f);
        let mut ro_keys = vec![AesBlock::default(); 256 * N];

        for (n, chunk) in ro_keys.chunks_mut(256).enumerate() {
            for (j, ro_key) in chunk.iter_mut().enumerate() {
                // The output of F in H(F(k1, y|i-1||j), r)
                ro_key[0..n].clone_from_slice(&x[0..n]);
                ro_key[n] = j as u8;
                ro_key[N] = n as u8;
            }
        }

        self.prf1.encrypt_all(&mut ro_keys);

        // The output of F in H(F(k1, y|i-1||j), r)
        let hashes = hash_all(AesBlock::from_slice(&right.nonce), &mut ro_keys);
        //ro_keys.zeroize(); TODO

        for (n, chunk) in hashes.chunks(32).enumerate() {
            // TODO: Make the left and right one big vector/array
            let shuffled = block_shuffle(&left.f[n], x[n]);
            left.xt[n] = shuffled.0;

            // Reset the f block
            left.f[n].default_in_place();
            left.f[n][0..n].clone_from_slice(&x[0..n]);
            left.f[n][n] = left.xt[n];
            // Include the block number in the value passed to the Random Oracle
            left.f[n][N] = n as u8;

            for (i, hash) in chunk.iter().enumerate() {
                right.data[n].data[i] = hash ^ shuffled.1[i];
            }
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

        // TODO: This calculation slows things down a bit - maybe store the number of blocks in the
        // first byte?
        let num_blocks = (a.len() - NONCE_SIZE) / (left_size + right_size + 1);

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
        let hash_key = HashKey::from_slice(&b_right[0..NONCE_SIZE]);
        let hash: AES128Z2Hash = Hash::new(hash_key);
        let h = hash.hash(left_block(a_f, l));

        let target_block = right_block(&b_right[NONCE_SIZE..], l);
        let test = get_bit(target_block, a[l] as usize) ^ h;

        if test == 1 {
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

#[inline]
fn get_bit(block: &[u8], bit: usize) -> u8 {
    debug_assert!(block.len() == RightBlock32::BLOCK_SIZE);
    debug_assert!(bit < 256);
    let byte_index = bit / 8;
    let position = bit % 8;
    let v = 1 << position;

    (block[byte_index] & v) >> position
}

impl<const N: usize> PartialEq for CipherText<OREAES128, N> {
    fn eq(&self, b: &Self) -> bool {
        matches!(self.cmp(b), Ordering::Equal)
    }
}

impl<const N: usize> Ord for CipherText<OREAES128, N> {
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

        let hash: AES128Z2Hash = Hash::new(AesBlock::from_slice(&b.right.nonce));
        let h = hash.hash(&self.left.f[l]);

        let test = b.right.data[l].get_bit(self.left.xt[l] as usize) ^ h;
        if test == 1 {
            return Ordering::Greater;
        }

        Ordering::Less
    }
}

impl<const N: usize> PartialOrd for CipherText<OREAES128, N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/*
 * (From the Rust docs)
 * This property cannot be checked by the compiler, and therefore Eq implies PartialEq, and has no extra methods.
 */
impl<const N: usize> Eq for CipherText<OREAES128, N> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::OREEncrypt;
    use quickcheck::TestResult;

    type ORE = OREAES128;

    fn init_ore() -> ORE {
        let mut k1: [u8; 16] = Default::default();
        let mut k2: [u8; 16] = Default::default();

        let mut rng = ChaCha20Rng::from_entropy();

        rng.fill(&mut k1);
        rng.fill(&mut k2);

        ORECipher::init(&k1, &k2).unwrap()
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

            match ORE::compare_raw_slices(&a, &b) {
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

            match ORE::compare_raw_slices(&a, &b) {
                Some(Ordering::Equal) => true,
                _ => false
            }
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

        assert_eq!(ORE::compare_raw_slices(&a_64, &a_32), Option::None);
    }

    #[test]
    fn binary_encoding() {
        let ore = init_ore();
        let a = 10u64.encrypt(&ore).unwrap();
        let bin = a.to_bytes();
        assert_eq!(a, CipherText::<OREAES128, 8>::from_bytes(&bin).unwrap());
    }

    #[test]
    #[should_panic(expected = "ParseError")]
    fn binary_encoding_invalid_length() {
        let bin = vec![0, 1, 2, 3];
        CipherText::<OREAES128, 8>::from_bytes(&bin).unwrap();
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

        let ore1: OREAES128 = ORECipher::init(&k1, &k2).unwrap();
        let ore2: OREAES128 = ORECipher::init(&k3, &k2).unwrap();

        let a = 1000u32.encrypt(&ore1).unwrap().to_bytes();
        let b = 1000u32.encrypt(&ore2).unwrap().to_bytes();

        assert_ne!(Some(Ordering::Equal), ORE::compare_raw_slices(&a, &b));
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

        let ore1: OREAES128 = ORECipher::init(&k1, &k2).unwrap();
        let ore2: OREAES128 = ORECipher::init(&k1, &k3).unwrap();

        let a = 1000u32.encrypt(&ore1).unwrap().to_bytes();
        let b = 1000u32.encrypt(&ore2).unwrap().to_bytes();

        assert_ne!(Some(Ordering::Equal), ORE::compare_raw_slices(&a, &b));
    }
}
