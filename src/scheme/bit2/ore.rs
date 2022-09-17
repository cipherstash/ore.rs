use crate::{
    ciphertext::*,
    primitives::{
        hash::AES128Z2Hash, AesBlock, Hash, HashKey,
        NONCE_SIZE, SEED64,
    },
    CRECipher, CRECipherInit, ORECipher, CREError, PlainText,
};

use super::{CreAes128, LeftBlock16, RightBlock32, left_block, right_block, get_bit};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::cmp::Ordering;

#[derive(Debug)]
pub struct OreAes128<R: Rng + SeedableRng>(CreAes128<R>);

pub type OREAES128 = OreAes128<ChaCha20Rng>;

fn gt(a: u8, b: u8) -> u8 {
    if a > b {
        1u8
    } else {
        0u8
    }
}

/* Define some convenience types */
type EncryptLeftResult<R, const N: usize> = Result<Left<OreAes128<R>, N>, CREError>;
type EncryptResult<R, const N: usize> = Result<CipherText<OreAes128<R>, N>, CREError>;

impl<R: Rng + SeedableRng> CRECipher for OreAes128<R> {
    type LeftBlockType = LeftBlock16;
    type RightBlockType = RightBlock32;

    fn encrypt_left<const N: usize>(&self, x: &PlainText<N>) -> EncryptLeftResult<R, N> {
        Left::<Self, N>::from_bytes(&self.0.encrypt_left(x)?.to_bytes()).map_err(|_| CREError)
    }

    fn encrypt<const N: usize>(&self, x: &PlainText<N>) -> EncryptResult<R, N> {
        CipherText::<Self, N>::from_bytes(&self.0.encrypt(x)?.to_bytes()).map_err(|_| CREError)
    }
}

impl<R: Rng + SeedableRng> ORECipher for OreAes128<R> {
    fn init(k1: [u8; 16], k2: [u8; 16], seed: &SEED64) -> Result<Self, CREError> {
        Ok(OreAes128::<R>(CRECipherInit::init(k1, k2, seed, gt)?))
    }

    fn encrypt_left<const N: usize>(&self, x: &PlainText<N>) -> EncryptLeftResult<R, N> {
        Left::<Self, N>::from_bytes(&self.0.encrypt_left(x)?.to_bytes()).map_err(|_| CREError)
    }

    fn encrypt<const N: usize>(&self, x: &PlainText<N>) -> EncryptResult<R, N> {
        CipherText::<Self, N>::from_bytes(&self.0.encrypt(x)?.to_bytes()).map_err(|_| CREError)
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

        let mut is_equal = true;
        let mut l = 0; // Unequal block

        // Slices for the PRF ("f") blocks
        let a_f = &a[num_blocks..];
        let b_f = &b[num_blocks..];

        for n in 0..num_blocks {
            if a[n] != b[n] || left_block::<Self::LeftBlockType>(a_f, n) != left_block::<Self::LeftBlockType>(b_f, n) {
                is_equal = false;
                l = n;
                break;
            }
        }

        if is_equal {
            return Some(Ordering::Equal);
        }

        let b_right = &b[num_blocks * (left_size + 1)..];
        let hash_key = HashKey::from_slice(&b_right[0..NONCE_SIZE]);
        let hash: AES128Z2Hash = Hash::new(hash_key);
        let h = hash.hash(left_block::<Self::LeftBlockType>(a_f, l));

        let target_block = right_block::<Self::RightBlockType>(&b_right[NONCE_SIZE..], l);
        let test = get_bit::<Self::RightBlockType>(target_block, a[l] as usize) ^ h;

        if test == 1 {
            return Some(Ordering::Greater);
        }

        Some(Ordering::Less)
    }
}

impl<const N: usize> PartialEq for CipherText<OREAES128, N> {
    fn eq(&self, b: &Self) -> bool {
        matches!(self.cmp(b), Ordering::Equal)
    }
}

impl<const N: usize> Ord for CipherText<OREAES128, N> {
    fn cmp(&self, b: &Self) -> Ordering {
        let mut is_equal = true;
        let mut l = 0; // Unequal block

        for n in 0..N {
            if self.left.xt[n] != b.left.xt[n] || self.left.f[n] != b.left.f[n] {
                is_equal = false;
                l = n;
                // TODO: Make sure that this is constant time (i.e. don't break)
                break;
            }
        }

        if is_equal {
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
        let mut seed: [u8; 8] = [0; 8];

        rng.fill(&mut seed);
        rng.fill(&mut k1);
        rng.fill(&mut k2);

        ORECipher::init(k1, k2, &seed).unwrap()
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
        let seed: [u8; 8] = [119, 104, 41, 110, 199, 157, 235, 169];

        let ore1: OREAES128 = ORECipher::init(k1, k2, &seed).unwrap();
        let ore2: OREAES128 = ORECipher::init(k3, k2, &seed).unwrap();

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
        let seed: [u8; 8] = [119, 104, 41, 110, 199, 157, 235, 169];

        let ore1: OREAES128 = ORECipher::init(k1, k2, &seed).unwrap();
        let ore2: OREAES128 = ORECipher::init(k1, k3, &seed).unwrap();

        let a = 1000u32.encrypt(&ore1).unwrap().to_bytes();
        let b = 1000u32.encrypt(&ore2).unwrap().to_bytes();

        assert_ne!(Some(Ordering::Equal), ORE::compare_raw_slices(&a, &b));
    }
}
