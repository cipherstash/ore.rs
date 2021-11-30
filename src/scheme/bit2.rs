
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
        PRP,
        SEED64,
        AesBlock,
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
pub type OREAES128Left<const N: usize> = Left<LeftBlock16, N>;
pub type OREAES128Right<const N: usize> = Right<OreBlock8, N>;
pub type OREAES128CipherText<const N: usize> = CipherText<LeftBlock16, OreBlock8, N>;
pub type EncryptLeftResult<const N: usize> = Result<OREAES128Left<N>, OREError>;
pub type EncryptResult<const N: usize> = Result<OREAES128CipherText<N>, OREError>;

fn cmp(a: u8, b: u8) -> u8 {
    if a > b {
        return 1u8;
    } else {
        return 0u8;
    }
}

impl ORECipher for OREAES128 {
    type LeftBlockType = LeftBlock16;
    type RightBlockType = OreBlock8;

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
        let mut output = OREAES128Left::<N> {
            xt: [0; N],
            f: [Default::default(); N]
        };

        // Build the prefixes
        // TODO: Don't modify struct values directly - use a function on a "Left" trait
        output.f.iter_mut().enumerate().for_each(|(n, block)| {
            block[0..n].clone_from_slice(&x[0..n]);
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
        let mut right = OREAES128Right::<N> {
            nonce: Default::default(),
            data: [Default::default(); N]
        };

        let mut left = OREAES128Left::<N> {
            xt: [0; N],
            f: [Default::default(); N]
        };

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
                right.data[n].set_bit(j as u8, indicator ^ h);
            }
        }
        self.prf1.encrypt_all(&mut left.f);

        // TODO: Do we need to do any zeroing? See https://lib.rs/crates/zeroize
        // Zeroize the RO Keys before re-assigning them

        return Ok(CipherText { left: left, right: right });
    }
}

impl<const N: usize> PartialEq for OREAES128CipherText<N> {
    fn eq(&self, b: &Self) -> bool {
        return match self.partial_cmp(b) {
            Some(Ordering::Equal) => true,
            _ => false
        }
    }
}

impl<const N: usize> PartialOrd for OREAES128CipherText<N> {
    fn partial_cmp(&self, b: &Self) -> Option<Ordering> {
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
            return Some(Ordering::Equal);
        }

        let hash: AES128Z2Hash = Hash::new(&b.right.nonce);
        let h = hash.hash(&self.left.f[l]);

        // Test the set and get bit functions
        let test = b.right.data[l].get_bit(self.left.xt[l]) ^ h;
        if test == 1 {
            return Some(Ordering::Greater);
        }

        return Some(Ordering::Less);
    }
}

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

        fn equality_64(x: u64) -> bool {
            let mut ore = init_ore();
            let a = x.encrypt(&mut ore).unwrap();
            let b = x.encrypt(&mut ore).unwrap();

            return a == b;
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
    fn set_and_get_bit() {
        let mut block: OreBlock8 = Default::default();
        block.set_bit(17, 1);
        assert_eq!(block.get_bit(17), 1);

        block.set_bit(180, 1);
        assert_eq!(block.get_bit(180), 1);

        block.set_bit(255, 1);
        assert_eq!(block.get_bit(255), 1);
    }
}
