
/*
 *
 * Block ORE Implemenation
 */

mod primitives;
use crate::primitives::{
    PRF,
    prf::AES128PRF
};
pub mod prp; // FIXME: This probably shouldn't be public (it is now for the benchmark)
mod hash;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

use rand;
use rand::Rng;
use rand::os::{OsRng};
use byteorder::{ByteOrder, BigEndian};

use aes::cipher::{
    NewBlockCipher,
    generic_array::GenericArray,
};
use aes::Aes128;

// TODO: Move this and the impl to its own file
#[derive(Debug)]
pub struct OREAES128 { // TODO: OREAES128<8, 8> (k, d)
    prf1: AES128PRF,
    prf2: AES128PRF,
    // OsRng uses /dev/urandom but we may want to look at
    // ChaCha20 rng and HC128
    rng: OsRng
}

const NUM_BLOCKS: usize = 8;

// TODO: Don't need GenericArray in Rust 1.51.0
// See https://blog.rust-lang.org/2021/03/25/Rust-1.51.0.html

#[derive(Debug)]
pub struct Left {
    f: [u8; 128], // Blocksize * ORE blocks (16 * 8)
    x: [u8; 8]
}

// TODO: Replace Left and Right with the generic types
// the Left should be an array of OreLeftBlock like we did for Right
#[derive(Debug)]
pub struct RightNew<const BLOCKS: usize> {
    //nonce: [u8; 16],
    nonce: GenericArray<u8, <Aes128 as NewBlockCipher>::KeySize>,
    data: [OreBlock8; BLOCKS]
}

#[derive(Debug)]
pub struct Right {
    //nonce: [u8; 16],
    nonce: GenericArray<u8, <Aes128 as NewBlockCipher>::KeySize>,
    data: [OreBlock8; 8]
}

#[derive(Debug)]
pub struct CipherText {
    left: Left,
    right: Right
}

fn cmp(a: u8, b: u8) -> u8 {
    if a > b {
        return 1u8;
    } else {
        return 0u8;
    }
}

/* An ORE block for k=8
 * |N| = 2^k */
// TODO: We might be able to use an __m256 for this
#[derive(Debug)]
#[derive(Default)]
#[derive(Copy)]
#[derive(Clone)]
struct OreBlock8 {
    low: u128,
    high: u128
}

// TODO: Make this a trait
impl OreBlock8 {
    // TODO: This should really just take a bool or we define an unset_bit fn, too
    // TODO: Return a Result<type>
    #[inline]
    pub fn set_bit(&mut self, position: u8, value: u8) {
        if position < 128 {
          let bit: u128 = (value as u128) << position;
          self.low |= bit;
        } else {
          let bit: u128 = (value as u128) << (position - 128);
          self.high |= bit;
        }
    }

    #[inline]
    pub fn get_bit(&self, position: u8) -> u8 {
        if position < 128 {
            let mask: u128 = 1 << position;
            return ((self.low & mask) >> position) as u8;
        } else {
            let mask: u128 = 1 << (position - 128);
            return ((self.high & mask) >> (position - 128)) as u8;
        }
    }
}

impl OREAES128 {
    pub fn init(k1: &[u8], k2: &[u8]) -> OREAES128 {
        // TODO: Can the PRP be initialized in the init function, too?
        return OREAES128 {
            prf1: PRF::new(k1),
            prf2: PRF::new(k2),
            rng: OsRng::new().unwrap() // TODO: Don't use unwrap
        }
    }

    pub fn encrypt_left(&self, input: u64) -> Left {
        let mut output = Left {
            x: Default::default(),
            f: [0u8; 128]
        };
        let mut x: [u8; NUM_BLOCKS] = Default::default();
        BigEndian::write_uint(&mut x, input, NUM_BLOCKS);
        let x = x;

        // Build the prefixes
        output.f.chunks_mut(16).enumerate().for_each(|(n, block)| {
            block[0..n].clone_from_slice(&x[0..n]);
        });

        self.prf2.encrypt_all(&mut output.f);

        // TODO: Use chunks?
        // TODO: Don't use the 16 magic number!
        for n in 0..NUM_BLOCKS {
            let position = n * 16;
            // Set prefix and create PRP for the block
            let prp = prp::Prp::init(&output.f[position..(position + 16)]);
            output.x[n] = prp.permute(x[n]);
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

        return output;
    }

    pub fn encrypt(&mut self, input: u64) -> CipherText {
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

        let mut x: [u8; NUM_BLOCKS] = Default::default();
        BigEndian::write_uint(&mut x, input, NUM_BLOCKS);
        let x = x;

        // Build the prefixes
        left.f.chunks_mut(16).enumerate().for_each(|(n, block)| {
            block[0..n].clone_from_slice(&x[0..n]);
        });

        self.prf2.encrypt_all(&mut left.f);

        for n in 0..NUM_BLOCKS {
            // Set prefix and create PRP for the block
            let position = n * 16;
            // Set prefix and create PRP for the block
            let prp = prp::Prp::init(&left.f[position..(position + 16)]);
            left.x[n] = prp.permute(x[n]);

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
                let jstar = prp.inverse(j);
                let indicator = cmp(jstar, x[n]);
                let offset: usize = (j as usize) * 16;
                let h = ro_keys[offset as usize] & 1u8;
                right.data[n].set_bit(j, indicator ^ h);
            }
        }
        //prf::encrypt_all(&self.k1, &mut left.f);
        self.prf1.encrypt_all(&mut left.f);

        // TODO: Do we need to do any zeroing? See https://lib.rs/crates/zeroize

        return CipherText { left: left, right: right };
    }

    pub fn compare(a: &CipherText, b: &CipherText) -> i8 {
        // TODO: Make sure that this is constant time

        let mut is_equal = true;
        let mut l = 0; // Unequal block

        // TODO: Surely this could be done with iterators?
        for n in 0..NUM_BLOCKS {
            let position = n * 16;
            if &a.left.x[n] != &b.left.x[n] || &a.left.f[position..(position + 16)] != &b.left.f[position..(position + 16)] {
                is_equal = false;
                l = n;
                break;
            }
        }

        if is_equal {
            return 0;
        }

        let h = hash::hash(&b.right.nonce, &a.left.f[(l * 16)..((l * 16) + 16)]);
        // Test the set and get bit functions
        let test = b.right.data[l].get_bit(a.left.x[l]) ^ h;
        if test == 1 {
            return 1;
        }

        return -1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn init_ore() -> OREAES128 {
        let k1: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        let k2: [u8; 16] = hex!("d0d007a5 3f9a6848 83bc1f21 0f6595a3");

        return OREAES128::init(&k1, &k2);
    }

    quickcheck! {
        fn compare(x: u64, y: u64) -> bool {
            // TODO: This should possibly not be mutable (I think it is now because the PRP must
            // have mutable state
            let mut ore = init_ore();

            let ret =
                if x > y {
                    1
                } else if x < y {
                    -1
                } else {
                    0
                };

            let a = ore.encrypt(x);
            let b = ore.encrypt(y);

            return ret == OREAES128::compare(&a, &b);
        }

        fn compare_equal(x: u64) -> bool {
            let mut ore = init_ore();
            let a = ore.encrypt(x);
            let b = ore.encrypt(x);

            return 0 == OREAES128::compare(&a, &b);
        }
    }

    #[test]
    fn smallest_to_largest() {
        let mut ore = init_ore();
        let a = ore.encrypt(0);
        let b = ore.encrypt(18446744073709551615);

        assert_eq!(-1, OREAES128::compare(&a, &b));
    }

    #[test]
    fn largest_to_smallest() {
        let mut ore = init_ore();
        let a = ore.encrypt(18446744073709551615);
        let b = ore.encrypt(0);

        assert_eq!(1, OREAES128::compare(&a, &b));
    }

    #[test]
    fn smallest_to_smallest() {
        let mut ore = init_ore();
        let a = ore.encrypt(0);
        let b = ore.encrypt(0);

        assert_eq!(0, OREAES128::compare(&a, &b));
    }

    #[test]
    fn largest_to_largest() {
        let mut ore = init_ore();
        let a = ore.encrypt(18446744073709551615);
        let b = ore.encrypt(18446744073709551615);

        assert_eq!(0, OREAES128::compare(&a, &b));
    }

    #[test]
    fn comparisons_in_first_block() {
        let mut ore = init_ore();
        let a = ore.encrypt(18446744073709551615);
        let b = ore.encrypt(18446744073709551612);

        assert_eq!(1, OREAES128::compare(&a, &b));
        assert_eq!(-1, OREAES128::compare(&b, &a));
    }

    #[test]
    fn comparisons_in_last_block() {
        let mut ore = init_ore();
        let a = ore.encrypt(10);
        let b = ore.encrypt(73);

        assert_eq!(-1, OREAES128::compare(&a, &b));
        assert_eq!(1, OREAES128::compare(&b, &a));
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
