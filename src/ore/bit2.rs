
/*
 *
 * Block ORE Implemenation using a 2-bit indicator function
 */

pub use crate::ore::{
    ORE,
    OREError,
    Left,
    Right,
    CipherText,
    OreBlock8,
    ORECipher
};
use crate::primitives::{
    PRF,
    Hash,
    PRP,
    SEED64,
    prf::AES128PRF,
    hash::AES128Hash,
    prp::KnuthShufflePRP
};
use std::cmp::Ordering;

use rand;
use rand::Rng;
use rand::os::{OsRng};

// TODO: Move this and the impl to its own file
#[derive(Debug)]
pub struct OREAES128 { // TODO: OREAES128<8, 8> (k, d)
    prf1: AES128PRF,
    prf2: AES128PRF,
    // OsRng uses /dev/urandom but we may want to look at
    // ChaCha20 rng and HC128
    rng: OsRng,
    prp_seed: SEED64
}

const NUM_BLOCKS: usize = 8;

fn cmp(a: u8, b: u8) -> u8 {
    if a > b {
        return 1u8;
    } else {
        return 0u8;
    }
}

impl PartialOrd for CipherText {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        return self.cmp(other);
    }
}

impl PartialEq for CipherText {
    fn eq(&self, other: &CipherText) -> bool {
        return self.eq(other);
    }
}

// TODO: Next steps
// * Make the Left and Right generic
// * Use a block type for Left as well as right? (possibly more work)
// * Add marshall and unmarshall functions to get consistent binary formats
// * Move this first implementation to ore/AES128ORE (consistent naming)
//

impl ORECipher for OREAES128 {
    fn init(k1: [u8; 16], k2: [u8; 16], seed: &SEED64) -> Result<Self, OREError> {
        // TODO: Can the PRP be initialized in the init function, too?
        return Ok(OREAES128 {
            prf1: PRF::new(&k1), // TODO: Don't borrow - use the fixed length array
            prf2: PRF::new(&k2),
            rng: OsRng::new().map_err(|_| OREError)?,
            prp_seed: *seed
        })
    }

    fn encrypt_left(&mut self, x: &[u8]) -> Result<Left, OREError> {
        let mut output = Left {
            x: Default::default(),
            f: [0u8; 128]
        };
        //let x: [u8; NUM_BLOCKS] = input.to_be_bytes();

        // Build the prefixes
        // TODO: Don't modify struct values directly - use a function on a "Left" trait
        output.f.chunks_mut(16).enumerate().for_each(|(n, block)| {
            block[0..n].clone_from_slice(&x[0..n]);
        });

        self.prf2.encrypt_all(&mut output.f);

        // TODO: Use chunks?
        // TODO: Don't use the 16 magic number!
        for n in 0..NUM_BLOCKS {
            let position = n * 16;
            // Set prefix and create PRP for the block
            let prp: KnuthShufflePRP<u8, 256> = PRP::new(&output.f[position..(position + 16)], &self.prp_seed).map_err(|_| OREError)?;
            output.x[n] = prp.permute(x[n]).map_err(|_| OREError)?;
        }

        // Reset the f block
        // TODO: Should we use Zeroize? Might be OK because we are returning the value (do some
        // research)
        output.f.iter_mut().for_each(|x| *x = 0);

        // TODO: Use chunks?
        for n in 0..NUM_BLOCKS {
            let position = n * 16;
            output.f[position..(position + n)].clone_from_slice(&x[0..n]);
            output.f[position + n] = output.x[n];
            // Include the block number in the value passed to the Random Oracle
            output.f[position + NUM_BLOCKS] = n as u8;
        }
        self.prf1.encrypt_all(&mut output.f);

        return Ok(output);
    }

    fn encrypt(&mut self, x: &[u8]) -> Result<CipherText, OREError> {
        // TODO: Replace with generic form
        let mut right = Right {
            nonce: Default::default(),
            data: [Default::default(); 8]
        };

        let mut left = Left {
            x: Default::default(),
            f: [0u8; 128]
        };

        // Generate a 16-byte random nonce
        self.rng.fill_bytes(&mut right.nonce);

        //let x: [u8; NUM_BLOCKS] = input.to_be_bytes();

        // Build the prefixes
        left.f.chunks_mut(16).enumerate().for_each(|(n, block)| {
            block[0..n].clone_from_slice(&x[0..n]);
        });

        self.prf2.encrypt_all(&mut left.f);

        for n in 0..NUM_BLOCKS {
            // Set prefix and create PRP for the block
            let position = n * 16;
            // Set prefix and create PRP for the block
            let prp: KnuthShufflePRP<u8, 256> = PRP::new(&left.f[position..(position + 16)], &self.prp_seed).map_err(|_| OREError)?;
            left.x[n] = prp.permute(x[n]).map_err(|_| OREError)?;

            // Reset the f block
            // TODO: We don't actually need to reset the whole thing - just from n onwards
            left.f[position..(position + 16)].iter_mut().for_each(|x| *x = 0);
            left.f[position..(position + n)].clone_from_slice(&x[0..n]);
            left.f[position + n] = left.x[n];
            // Include the block number in the value passed to the Random Oracle
            left.f[position + NUM_BLOCKS] = n as u8;

            // TODO: The first block or RO keys will be the same for every encryption
            // because there is no plaintext prefix for the first block
            // This means we can generate the first 16 keys in a setup step

            let mut ro_keys = [0u8; 16 * 256];

            for j in 0..=255 {
                let offset = j * 16;
                // the output of F in H(F(k1, y|i-1||j), r)
                ro_keys[offset..(offset + n)].clone_from_slice(&x[0..n]);
                ro_keys[offset + n] = j as u8;
                ro_keys[offset + NUM_BLOCKS] = n as u8;
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
            let p: AES128PRF = PRF::new(&right.nonce);
            p.encrypt_all(&mut ro_keys);

            for j in 0..=255 {
                let jstar = prp.invert(j).map_err(|_| OREError)?;
                let indicator = cmp(jstar, x[n]);
                let offset: usize = (j as usize) * 16;
                let h = ro_keys[offset as usize] & 1u8;
                right.data[n].set_bit(j, indicator ^ h);
            }
        }
        //prf::encrypt_all(&self.k1, &mut left.f);
        self.prf1.encrypt_all(&mut left.f);

        // TODO: Do we need to do any zeroing? See https://lib.rs/crates/zeroize

        return Ok(CipherText { left: left, right: right });
    }
}

impl CipherText {
    fn eq(&self, b: &Self) -> bool {
        return match self.cmp(b) {
            Some(Ordering::Equal) => true,
            _ => false
        }
    }


    fn cmp(&self, b: &CipherText) -> Option<Ordering> {
        let mut is_equal = true;
        let mut l = 0; // Unequal block

        // TODO: Surely this could be done with iterators?
        for n in 0..NUM_BLOCKS {
            let position = n * 16;
            if &self.left.x[n] != &b.left.x[n] || &self.left.f[position..(position + 16)] != &b.left.f[position..(position + 16)] {
                is_equal = false;
                l = n;
                // TODO: Make sure that this is constant time (i.e. don't break)
                break;
            }
        }

        if is_equal {
            return Some(Ordering::Equal);
        }

        let hash: AES128Hash = Hash::new(&b.right.nonce);
        let h = hash.hash(&self.left.f[(l * 16)..((l * 16) + 16)]);

        // Test the set and get bit functions
        let test = b.right.data[l].get_bit(self.left.x[l]) ^ h;
        if test == 1 {
            return Some(Ordering::Greater);
        }

        return Some(Ordering::Less);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // TODO: We're only doing this to get the numerical traits - perhaps move those to their own
    // module
    use crate::ore::*;

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
        fn compare(x: u64, y: u64) -> bool {
            let mut ore = init_ore();
            let a = x.encrypt(&mut ore).unwrap();
            let b = y.encrypt(&mut ore).unwrap();

            return match(x.cmp(&y)) {
                Ordering::Greater => a > b,
                Ordering::Less    => a < b,
                Ordering::Equal   => a == b
            };
        }

        fn compare_equal(x: u64) -> bool {
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
