/*
 * Block ORE Implementation using a 2-bit indicator function
 */

use crate::{
    ciphertext::*,
    primitives::{
        hash::AES128Z2Hash, prf::AES128PRF, prp::KnuthShufflePRP, Hash, Prf, Prp, SEED64,
    },
    ORECipher, OREError, PlainText,
};

use aes::cipher::generic_array::GenericArray;
use rand::{os::OsRng, Rng};
use std::cmp::Ordering;

pub mod block_types;
pub use self::block_types::*;

/* Define our scheme */
#[derive(Debug)]
pub struct OREAES128 {
    prf1: AES128PRF,
    prf2: AES128PRF,
    // OsRng uses /dev/urandom but we may want to look at
    // ChaCha20 rng and HC128
    rng: OsRng,
    prp_seed: SEED64,
}

/* Define some convenience types */
type EncryptLeftResult = Result<OreAes128Left, OREError>;
type EncryptResult = Result<CipherText<OreAes128Left>, OREError>;

#[derive(Debug)]
pub struct OreAes128Left {
    num_blocks: usize,
    data: Vec<u8>,
}

impl LeftCipherText for OreAes128Left {
    const BLOCK_SIZE: usize = 17;

    fn init(blocks: usize) -> Self {
        Self {
            data: vec![0; blocks * Self::BLOCK_SIZE],
            num_blocks: blocks,
        }
    }

    fn num_blocks(&self) -> usize {
        self.num_blocks
    }

    #[inline]
    fn set_xn(&mut self, n: usize, value: u8) {
        debug_assert!(n < self.num_blocks);
        self.data[n] = value
    }

    #[inline]
    fn block(&self, index: usize) -> &[u8] {
        let offset = self.num_blocks + (index * 16); // TODO: LEFT_F_BLOCK_SIZE
        &self.data[offset..(offset + 16)]
    }

    #[inline]
    fn block_mut(&mut self, index: usize) -> &mut [u8] {
        let offset = self.num_blocks + (index * 16); // TODO: LEFT_F_BLOCK_SIZE
        &mut self.data[offset..(offset + 16)]
    }

    #[inline]
    fn f_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.num_blocks..]
    }
}

fn cmp(a: u8, b: u8) -> u8 {
    if a > b {
        1u8
    } else {
        0u8
    }
}

#[inline]
fn right_block_mut(data: &mut [u8], index: usize) -> &mut [u8] {
    let offset = index * 32; // TODO: RIGHT_BLOCK_SIZE
    &mut data[offset..(offset + 32)]
}

#[inline]
fn right_block(data: &[u8], index: usize) -> &[u8] {
    let offset = index * 32; // TODO: RIGHT_BLOCK_SIZE
    &data[offset..(offset + 32)]
}

#[inline]
fn right_set_bit(block: &mut [u8], bit: usize, value: u8) {
    debug_assert!(bit < 256);
    let byte_index = bit / 8;
    let mask = bit % 8;
    let v = value << mask;
    block[byte_index] |= v;
}

#[inline]
fn right_get_bit(block: &[u8], bit: usize) -> u8 {
    debug_assert!(bit < 256);
    let byte_index = bit / 8;
    let position = bit % 8;
    let v = 1 << position;

    (block[byte_index] & v) >> position
}

impl ORECipher for OREAES128 {
    type LeftType = OreAes128Left;

    fn init(k1: [u8; 16], k2: [u8; 16], seed: &SEED64) -> Result<Self, OREError> {
        // TODO: k1 and k2 should be Key types and we should have a set of traits to abstract the
        // behaviour ro parsing/loading etc

        return Ok(OREAES128 {
            prf1: Prf::new(GenericArray::from_slice(&k1)),
            prf2: Prf::new(GenericArray::from_slice(&k2)),
            rng: OsRng::new().map_err(|_| OREError)?,
            prp_seed: *seed,
        });
    }

    // TODO: Eventually, this will be the default implementation for ORECipher
    // and we'll provide associated types for the Left and Right CipherText impls
    fn encrypt_left<const N: usize>(&mut self, x: &PlainText<N>) -> EncryptLeftResult {
        // First N-bytes for the "x" values, the rest for the "f" blocks
        let mut output = Self::LeftType::init(N);

        // Build the prefixes
        // TODO: Include the block number in the prefix to avoid repeating values for common
        // blocks in a long prefix
        // e.g. when plaintext is 4700 (2-bytes/blocks)
        // xt = [17, 17, 17, 17, 17, 17, 223, 76]
        for (n, _) in x.iter().enumerate() {
            output.block_mut(n)[..n].clone_from_slice(&x[..n]);
        }

        self.prf2.encrypt_all(output.f_mut());

        for (n, xn) in x.iter().enumerate().take(N) {
            // Set prefix and create PRP for the block
            let prp: KnuthShufflePRP<u8, 256> =
                Prp::new(output.block(n), &self.prp_seed).map_err(|_| OREError)?;

            output.data[n] = prp.permute(*xn).map_err(|_| OREError)?;
        }

        // Reset the f block
        // TODO: Should we use Zeroize? We don't actually need to clear sensitive data here, we
        // just need fast "zero set". Reassigning the value will drop the old one and allocate new
        // data to the stack
        output.f_mut().fill(0);

        // TODO: This could iterate the plaintext for each input block
        for n in 0..N {
            // TODO: This code will probably need to be moved into the LeftCipherText trait
            // (say set_block_from_plaintext or something) as it might need to work differently for
            // different sized blocks
            let block_n = output.data[n];
            let block = output.block_mut(n);
            block[0..n].clone_from_slice(&x[0..n]);
            block[n] = block_n;
            // Include the block number in the value passed to the Random Oracle
            block[N] = n as u8;
        }
        // TODO: Maybe we invert this by passing the PRF to a function on the left type
        // and making the block size generic so we can handle PRFs of different sizes with compile
        // time checking
        self.prf1.encrypt_all(output.f_mut());

        Ok(output)
    }

    fn encrypt<const N: usize>(&mut self, x: &PlainText<N>) -> EncryptResult {
        // TODO: We can probably make Left generic in S (not N) so that we can use static compile
        // checks (and avoid things like comparison of different sized ciphertexts)
        // For example, we could have a PartialOrd implemented from Left<130> to a Right<280> but
        // nothing else (we may need to keep the scheme on the struct as well!)
        let mut left = Self::LeftType::init(N);
        let mut right = Right::init(N * 32); // TODO: N * RIGHT_BLOCK_SIZE
                                             // Generate a 16-byte random nonce
        self.rng.fill_bytes(&mut right.nonce);

        // TODO: This should be a function on Left
        for (n, _) in x.iter().enumerate() {
            left.block_mut(n)[..n].clone_from_slice(&x[..n]);
        }

        self.prf2.encrypt_all(left.f_mut());

        for (n, xn) in x.iter().enumerate().take(N) {
            // Set prefix and create PRP for the block
            let prp: KnuthShufflePRP<u8, 256> =
                Prp::new(left.block(n), &self.prp_seed).map_err(|_| OREError)?;

            left.data[n] = prp.permute(*xn).map_err(|_| OREError)?;

            let block_n = left.data[n];
            let block = left.block_mut(n);
            block.fill(0);
            block[0..n].clone_from_slice(&x[0..n]);
            block[n] = block_n;
            // Include the block number in the value passed to the Random Oracle
            block[N] = n as u8;

            let mut ro_keys: [u8; 256 * 16] = [0; 256 * 16];

            for (j, ro_key) in ro_keys.chunks_mut(16).enumerate() {
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
            let hasher: AES128Z2Hash = Hash::new(&right.nonce);
            let hashes = hasher.hash_all(&mut ro_keys);

            // FIXME: force casting to u8 from usize could cause a panic
            for (j, h) in hashes.iter().enumerate() {
                let jstar = prp.invert(j as u8).map_err(|_| OREError)?;
                let indicator = cmp(jstar, x[n]);

                // TODO: Perhaps these functions should be combined and take n as an arg
                // Then we could do right.set_bit(n, j, inidicator ^ h);
                let right_block = right_block_mut(&mut right.data, n);
                right_set_bit(right_block, j, indicator ^ h);
            }
        }
        self.prf1.encrypt_all(left.f_mut());

        // TODO: Do we need to do any zeroing? See https://lib.rs/crates/zeroize
        // Zeroize the RO Keys before re-assigning them

        Ok(CipherText(left, right))
    }

    fn compare_raw_slices(a: &[u8], b: &[u8]) -> Option<Ordering> {
        /*if a.len() != b.len() {
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
            if a[n] != b[n] || left_block(a_f, n) != left_block(b_f, n) {
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
        let h = hash.hash(left_block(a_f, l));

        let target_block = right_block(&b_right[NONCE_SIZE..], l);
        let test = get_bit(target_block, a[l] as usize) ^ h;

        if test == 1 {
            return Some(Ordering::Greater);
        }*/

        Some(Ordering::Less)
    }
}

// TODO: This could possibly be generic (same with Eq)
impl PartialEq for CipherText<OreAes128Left> {
    fn eq(&self, b: &Self) -> bool {
        matches!(self.cmp(b), Ordering::Equal)
    }
}

impl Ord for CipherText<OreAes128Left> {
    fn cmp(&self, b: &Self) -> Ordering {
        let mut is_equal = true;
        let mut l = 0; // Unequal block

        // FIXME: This probably means we can only implement PartialOrd
        // Unless we make the Left type generic on the number of input blocks, N!?
        // Some schemes may support comparing CTs of different lengths!
        assert_eq!(self.0.num_blocks(), b.0.num_blocks());

        for n in 0..self.0.num_blocks() {
            // TODO: Fix me!
            if self.0.data[n] != b.0.data[n] || &self.0.block(n) != &b.0.block(n) {
                is_equal = false;
                l = n;
                // TODO: Make sure that this is constant time (i.e. don't break)
                break;
            }
        }

        if is_equal {
            return Ordering::Equal;
        }

        let hash: AES128Z2Hash = Hash::new(&b.1.nonce);
        let h = hash.hash(&self.0.block(l));

        let block = right_block(&b.1.data, l);
        let test = right_get_bit(block, self.0.data[l] as usize) ^ h;
        if test == 1 {
            return Ordering::Greater;
        }

        Ordering::Less
    }
}

impl PartialOrd for CipherText<OreAes128Left> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/*
 * (From the Rust docs)
 * This property cannot be checked by the compiler, and therefore Eq implies PartialEq, and has no extra methods.
 */
impl Eq for CipherText<OreAes128Left> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::OREEncrypt;
    use quickcheck::TestResult;

    fn init_ore() -> OREAES128 {
        let mut k1: [u8; 16] = Default::default();
        let mut k2: [u8; 16] = Default::default();

        let mut rng = OsRng::new().unwrap();
        let mut seed: [u8; 8] = [0; 8];

        rng.fill_bytes(&mut seed);
        rng.fill_bytes(&mut k1);
        rng.fill_bytes(&mut k2);

        ORECipher::init(k1, k2, &seed).unwrap()
    }

    quickcheck! {
            fn compare_u64(x: u64, y: u64) -> bool {
                let mut ore = init_ore();
                let a = x.encrypt(&mut ore).unwrap();
                let b = y.encrypt(&mut ore).unwrap();

                match x.cmp(&y) {
                    Ordering::Greater => a > b,
                    Ordering::Less    => a < b,
                    Ordering::Equal   => a == b
                }
            }

    /*
            fn compare_u64_raw_slices(x: u64, y: u64) -> bool {
                let mut ore = init_ore();
                let a = x.encrypt(&mut ore).unwrap().to_bytes();
                let b = y.encrypt(&mut ore).unwrap().to_bytes();

                match OREAES128::compare_raw_slices(&a, &b) {
                    Some(Ordering::Greater) => x > y,
                    Some(Ordering::Less)    => x < y,
                    Some(Ordering::Equal)   => x == y,
                    None                    => false
                }
            }
            */

            fn equality_u64(x: u64) -> bool {
                let mut ore = init_ore();
                let a = x.encrypt(&mut ore).unwrap();
                let b = x.encrypt(&mut ore).unwrap();

                a == b
            }
    /*
            fn equality_u64_raw_slices(x: u64) -> bool {
                let mut ore = init_ore();
                let a = x.encrypt(&mut ore).unwrap().to_bytes();
                let b = x.encrypt(&mut ore).unwrap().to_bytes();

                match OREAES128::compare_raw_slices(&a, &b) {
                    Some(Ordering::Equal) => true,
                    _ => false
                }
            }
            */

            fn compare_u32(x: u32, y: u32) -> bool {
                let mut ore = init_ore();
                let a = x.encrypt(&mut ore).unwrap();
                let b = y.encrypt(&mut ore).unwrap();

                match x.cmp(&y) {
                    Ordering::Greater => a > b,
                    Ordering::Less    => a < b,
                    Ordering::Equal   => a == b
                }
            }

            fn equality_u32(x: u64) -> bool {
                let mut ore = init_ore();
                let a = x.encrypt(&mut ore).unwrap();
                let b = x.encrypt(&mut ore).unwrap();

                a == b
            }

            fn compare_f64(x: f64, y: f64) -> TestResult {
                if x.is_nan() || x.is_infinite() || y.is_nan() || y.is_infinite() {
                    return TestResult::discard();
                }

                let mut ore = init_ore();
                let a = x.encrypt(&mut ore).unwrap();
                let b = y.encrypt(&mut ore).unwrap();

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
                let mut ore = init_ore();
                let a = x.encrypt(&mut ore).unwrap();
                let b = x.encrypt(&mut ore).unwrap();

                a == b
            }

            fn compare_plaintext(x: u64, y: u64) -> bool {
                let mut ore = init_ore();
                let a = x.to_be_bytes().encrypt(&mut ore).unwrap();
                let b = y.to_be_bytes().encrypt(&mut ore).unwrap();

                match x.cmp(&y) {
                    Ordering::Greater => a > b,
                    Ordering::Less    => a < b,
                    Ordering::Equal   => a == b
                }
            }

            fn equality_plaintext(x: f64) -> bool {
                let mut ore = init_ore();
                let a = x.to_be_bytes().encrypt(&mut ore).unwrap();
                let b = x.to_be_bytes().encrypt(&mut ore).unwrap();

                a == b
            }
        }

    #[test]
    fn smallest_to_largest() {
        let mut ore = init_ore();
        let a = 0u64.encrypt(&mut ore).unwrap();
        let b = 18446744073709551615u64.encrypt(&mut ore).unwrap();

        assert!(a < b);
    }

    #[test]
    fn largest_to_smallest() {
        let mut ore = init_ore();
        let a = 18446744073709551615u64.encrypt(&mut ore).unwrap();
        let b = 0u64.encrypt(&mut ore).unwrap();

        assert!(a > b);
    }

    #[test]
    fn smallest_to_smallest() {
        let mut ore = init_ore();
        let a = 0u64.encrypt(&mut ore).unwrap();
        let b = 0u64.encrypt(&mut ore).unwrap();

        assert!(a == b);
    }

    #[test]
    fn largest_to_largest() {
        let mut ore = init_ore();
        let a = 18446744073709551615u64.encrypt(&mut ore).unwrap();
        let b = 18446744073709551615u64.encrypt(&mut ore).unwrap();

        assert!(a == b);
    }

    #[test]
    fn comparisons_in_first_block() {
        let mut ore = init_ore();
        let a = 18446744073709551615u64.encrypt(&mut ore).unwrap();
        let b = 18446744073709551612u64.encrypt(&mut ore).unwrap();

        assert!(a > b);
        assert!(b < a);
    }

    #[test]
    fn comparisons_in_last_block() {
        let mut ore = init_ore();
        let a = 10u64.encrypt(&mut ore).unwrap();
        let b = 73u64.encrypt(&mut ore).unwrap();

        assert!(a < b);
        assert!(b > a);
    }

    /*
    #[test]
    fn compare_raw_slices_mismatched_lengths() {
        let mut ore = init_ore();
        let a_64 = 10u64.encrypt(&mut ore).unwrap().to_bytes();
        let a_32 = 10u32.encrypt(&mut ore).unwrap().to_bytes();

        assert_eq!(OREAES128::compare_raw_slices(&a_64, &a_32), Option::None);
    }

    #[test]
    fn binary_encoding() {
        let mut ore = init_ore();
        let a = 10u64.encrypt(&mut ore).unwrap();
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

        let mut ore1: OREAES128 = ORECipher::init(k1, k2, &seed).unwrap();
        let mut ore2: OREAES128 = ORECipher::init(k3, k2, &seed).unwrap();

        let a = 1000u32.encrypt(&mut ore1).unwrap().to_bytes();
        let b = 1000u32.encrypt(&mut ore2).unwrap().to_bytes();

        assert_ne!(Some(Ordering::Equal), OREAES128::compare_raw_slices(&a, &b));
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

        let mut ore1: OREAES128 = ORECipher::init(k1, k2, &seed).unwrap();
        let mut ore2: OREAES128 = ORECipher::init(k1, k3, &seed).unwrap();

        let a = 1000u32.encrypt(&mut ore1).unwrap().to_bytes();
        let b = 1000u32.encrypt(&mut ore2).unwrap().to_bytes();

        assert_ne!(Some(Ordering::Equal), OREAES128::compare_raw_slices(&a, &b));
    }*/
}
