
/*
 * Block ORE Implemenation using a 2-bit indicator function
 */

use crate::{
    OREError,
    PlainText,
    ORECipher,
    ciphertext::*,
    primitives::{
        PRF,
        Hash,
        HashKey,
        PRP,
        SEED64,
        AesBlock,
        NONCE_SIZE,
        prf::AES128PRF,
        hash::AES128Z2Hash,
        prp::KnuthShufflePRP
    }
};

use std::cmp::Ordering;
use rand::{
    Rng,
    os::OsRng
};
use aes::cipher::generic_array::GenericArray;

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
    prp_seed: SEED64
}

/* Define some convenience types */
type EncryptLeftResult<const N: usize> = Result<Left<OREAES128, N>, OREError>;
type EncryptResult<const N: usize> = Result<CipherText<OREAES128, N>, OREError>;

fn cmp(a: u8, b: u8) -> u8 {
    if a > b {
        return 1u8;
    } else {
        return 0u8;
    }
}

impl ORECipher for OREAES128 {
    type LeftBlockType = LeftBlock16;
    type RightBlockType = RightBlock32;

    fn init(k1: [u8; 16], k2: [u8; 16], seed: &SEED64) -> Result<Self, OREError> {

        // TODO: k1 and k2 should be Key types and we should have a set of traits to abstract the
        // behaviour ro parsing/loading etc

        return Ok(OREAES128 {
            prf1: PRF::new(GenericArray::from_slice(&k1)),
            prf2: PRF::new(GenericArray::from_slice(&k2)),
            rng: OsRng::new().map_err(|_| OREError)?,
            prp_seed: *seed
        })
    }

    fn encrypt_left<const N: usize>(&mut self, x: &PlainText<N>) -> EncryptLeftResult<N> {
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

        for n in 0..N {
            // Set prefix and create PRP for the block
            let prp: KnuthShufflePRP<u8, 256> = PRP::new(&output.f[n], &self.prp_seed).map_err(|_| OREError)?;
            output.xt[n] = prp.permute(x[n]).map_err(|_| OREError)?;
        }

        // Reset the f block
        // TODO: Should we use Zeroize? We don't actually need to clear sensitive data here, we
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

        return Ok(output);
    }

    fn encrypt<const N: usize>(&mut self, x: &PlainText<N>) -> EncryptResult<N> {
        let mut left = Left::<Self, N>::init();
        let mut right = Right::<Self, N>::init();

        // Generate a 16-byte random nonce
        self.rng.fill_bytes(&mut right.nonce);

        // Build the prefixes
        // TODO: Don't modify struct values directly - use a function on a "Left"
        left.f.iter_mut().enumerate().for_each(|(n, block)| {
            block[0..n].clone_from_slice(&x[0..n]);
        });

        self.prf2.encrypt_all(&mut left.f);

        for n in 0..N {
            // Set prefix and create PRP for the block
            let prp: KnuthShufflePRP<u8, 256> = PRP::new(&left.f[n], &self.prp_seed).map_err(|_| OREError)?;
            left.xt[n] = prp.permute(x[n]).map_err(|_| OREError)?;

            // Reset the f block
            // TODO: Do we need to zeroize the old data before it is dropped due to de-assignment?
            left.f[n] = Default::default();


            left.f[n][0..n].clone_from_slice(&x[0..n]);
            left.f[n][n] = left.xt[n];
            // Include the block number in the value passed to the Random Oracle
            left.f[n][N] = n as u8;

            let mut ro_keys: [AesBlock; 256] = [Default::default(); 256];

            for j in 0..=255 {
                /*
                 * The output of F in H(F(k1, y|i-1||j), r)
                 */
                ro_keys[j][0..n].clone_from_slice(&x[0..n]);
                ro_keys[j][n] = j as u8;
                ro_keys[j][N] = n as u8;
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
                right.data[n].set_bit(j, indicator ^ h);
            }
        }
        self.prf1.encrypt_all(&mut left.f);

        // TODO: Do we need to do any zeroing? See https://lib.rs/crates/zeroize
        // Zeroize the RO Keys before re-assigning them

        return Ok(CipherText { left: left, right: right });
    }


    fn compare_raw_slices(a: &[u8], b: &[u8]) -> Option<Ordering> {
        if a.len() != b.len() { return None };
        let left_size = Self::LeftBlockType::BLOCK_SIZE;
        let right_size = Self::RightBlockType::BLOCK_SIZE;

        // TODO: This calculation slows things down a bit - maybe store the number of blocks in the
        // first byte?
        let num_blocks = (a.len() - NONCE_SIZE) / (left_size + right_size + 1);

        let mut is_equal = true;
        let mut l = 0; // Unequal block

        // Slices for the PRF ("f") blocks
        let a_f = &a[num_blocks..];
        let b_f = &a[num_blocks..];

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
        let hash: AES128Z2Hash = Hash::new(&hash_key);
        let h = hash.hash(left_block(a_f, l));

        let target_block = right_block(&b_right[NONCE_SIZE..], l);
        let test = get_bit(target_block, a[l] as usize) ^ h;

        if test == 1 {
            return Some(Ordering::Greater);
        }

        return Some(Ordering::Less);
    }
}

// TODO: Move these to block_types
#[inline]
fn left_block(input: &[u8], n: usize) -> &[u8] {
    let f_pos = n * LeftBlock16::BLOCK_SIZE;
    return &input[f_pos..(f_pos + LeftBlock16::BLOCK_SIZE)];
}

#[inline]
fn right_block(input: &[u8], n: usize) -> &[u8] {
    let f_pos = n * RightBlock32::BLOCK_SIZE;
    return &input[f_pos..(f_pos + RightBlock32::BLOCK_SIZE)];
}

#[inline]
fn get_bit(block: &[u8], bit: usize) -> u8 {
    debug_assert!(block.len() == RightBlock32::BLOCK_SIZE);
    debug_assert!(bit < 256);
    let byte_index = bit / 8;
    let position = bit % 8;
    let v = 1 << position;

    return (block[byte_index] & v) >> position;
}

impl<const N: usize> PartialEq for CipherText<OREAES128, N> {
    fn eq(&self, b: &Self) -> bool {
        return match self.cmp(b) {
            Ordering::Equal => true,
            _ => false
        }
    }
}

impl<const N: usize> Ord for CipherText<OREAES128, N> {
    fn cmp(&self, b: &Self) -> Ordering {
        let mut is_equal = true;
        let mut l = 0; // Unequal block

        for n in 0..N {
            if &self.left.xt[n] != &b.left.xt[n] || &self.left.f[n] != &b.left.f[n] {
                is_equal = false;
                l = n;
                // TODO: Make sure that this is constant time (i.e. don't break)
                break;
            }
        }

        if is_equal {
            return Ordering::Equal;
        }

        let hash: AES128Z2Hash = Hash::new(&b.right.nonce);
        let h = hash.hash(&self.left.f[l]);

        let test = b.right.data[l].get_bit(self.left.xt[l] as usize) ^ h;
        if test == 1 {
            return Ordering::Greater;
        }

        return Ordering::Less;
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

    fn init_ore() -> OREAES128 {
        let mut k1: [u8; 16] = Default::default();
        let mut k2: [u8; 16] = Default::default();

        let mut rng = OsRng::new().unwrap();
        let mut seed: [u8; 8] = [0; 8];

        rng.fill_bytes(&mut seed);
        rng.fill_bytes(&mut k1);
        rng.fill_bytes(&mut k2);

        return ORECipher::init(k1, k2, &seed).unwrap();
    }

    quickcheck! {
        fn compare_64(x: u64, y: u64) -> bool {
            let mut ore = init_ore();
            let a = x.encrypt(&mut ore).unwrap();
            let b = y.encrypt(&mut ore).unwrap();

            return match x.cmp(&y) {
                Ordering::Greater => a > b,
                Ordering::Less    => a < b,
                Ordering::Equal   => a == b
            };
        }

        fn compare_64_raw_slices(x: u64, y: u64) -> bool {
            let mut ore = init_ore();
            let a = x.encrypt(&mut ore).unwrap().to_bytes();
            let b = y.encrypt(&mut ore).unwrap().to_bytes();

            return match OREAES128::compare_raw_slices(&a, &b) {
                Some(Ordering::Greater) => x > y,
                Some(Ordering::Less)    => x < y,
                Some(Ordering::Equal)   => x == y,
                None                    => false
            };
        }

        fn equality_64(x: u64) -> bool {
            let mut ore = init_ore();
            let a = x.encrypt(&mut ore).unwrap();
            let b = x.encrypt(&mut ore).unwrap();

            return a == b;
        }

        fn equality_64_raw_slices(x: u64) -> bool {
            let mut ore = init_ore();
            let a = x.encrypt(&mut ore).unwrap().to_bytes();
            let b = x.encrypt(&mut ore).unwrap().to_bytes();

            return match OREAES128::compare_raw_slices(&a, &b) {
                Some(Ordering::Equal) => true,
                _ => false
            }
        }

        fn compare_32(x: u32, y: u32) -> bool {
            let mut ore = init_ore();
            let a = x.encrypt(&mut ore).unwrap();
            let b = y.encrypt(&mut ore).unwrap();

            return match x.cmp(&y) {
                Ordering::Greater => a > b,
                Ordering::Less    => a < b,
                Ordering::Equal   => a == b
            };
        }

        fn equality_32(x: u64) -> bool {
            let mut ore = init_ore();
            let a = x.encrypt(&mut ore).unwrap();
            let b = x.encrypt(&mut ore).unwrap();

            return a == b;
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
}
