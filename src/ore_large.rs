
/*
 *
 * Block ORE Implemenation
 */

use crate::prp;
use crate::prf;
use crate::hash;

use rand;
use rand::Rng;
use rand::os::{OsRng};
use byteorder::{ByteOrder, BigEndian};

// This could probably be a re-export
//use aes::cipher::generic_array::arr;

use aes::cipher::{
    consts::{U16, U256},
    NewBlockCipher, BlockCipher,
    generic_array::GenericArray,
};
use aes::{Aes128};

pub struct OreLarge {
    k1: Key,
    k2: Key,
    // OsRng uses /dev/urandom but we may want to look at
    // ChaCha20 rng and HC128
    rng: OsRng
}

const NUM_BLOCKS: usize = 8;

// TODO: Don't need GenericArray in Rust 1.51.0
// See https://blog.rust-lang.org/2021/03/25/Rust-1.51.0.html
/*#[derive(Debug)]
pub struct LeftBlock {
    // The output of the PRF
    f: GenericArray<u8, U16>,
    // The output of the PRP
    x: u8
}

pub type Left = [LeftBlock; 8];*/

#[derive(Debug)]
pub struct Left {
    f: GenericArray<GenericArray<u8, <Aes128 as BlockCipher>::BlockSize>, <Aes128 as BlockCipher>::ParBlocks>,
    x: [u8; 8]
}

#[derive(Debug)]
pub struct Right {
    nonce: [u8; 16],
    data: [OreBlock8; 8]
}

#[derive(Debug)]
pub struct CipherText {
    left: Left,
    right: Right
}

pub type Key = GenericArray<u8, <Aes128 as NewBlockCipher>::KeySize>;

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

// TODO: This is just the Encryptor - use an "Encryption" trait
impl OreLarge {
    pub fn init(prf_key: Key, prp_key: Key) -> OreLarge {
      return Self {
          k1: prf_key,
          k2: prp_key,
          rng: OsRng::new().unwrap() // TODO: Don't use unwrap
      }
    }
    
    pub fn encrypt_left(&self, input: u64) -> Left {
        let mut output = Left {
            x: Default::default(),
            f: Default::default()
        };
        let mut x: [u8; NUM_BLOCKS] = Default::default();
        BigEndian::write_uint(&mut x, input, NUM_BLOCKS);
        let x = x;

        // Build the prefixes
        output.f.iter_mut().enumerate().for_each(|(n, block)| {
            block[0..n].clone_from_slice(&x[0..n]);
        });

        prf::encrypt8(&self.k2, &mut output.f);

        for n in 0..NUM_BLOCKS {
            // Set prefix and create PRP for the block
            let prp = prp::Prp::init(&output.f[n]);
            output.x[n] = prp.permute(x[n]);

            // Reset the f block (probably inefficient)
            output.f[n] = Default::default();
            output.f[n][0..n].clone_from_slice(&x[0..n]);
            output.f[n][n] = output.x[n];
            // Include the block number in the value passed to the Random Oracle
            output.f[n][NUM_BLOCKS] = n as u8;
        }
        prf::encrypt8(&self.k1, &mut output.f);

        return output;
    }

    pub fn encrypt(&mut self, input: u64) -> CipherText {
        let mut right = Right {
            nonce: Default::default(),
            data: [Default::default(); 8]
        };

        let mut left = Left {
            x: Default::default(),
            f: Default::default()
        };

        // Generate a 16-byte random nonce
        self.rng.fill_bytes(&mut right.nonce);

        let mut x: [u8; NUM_BLOCKS] = Default::default();
        BigEndian::write_uint(&mut x, input, NUM_BLOCKS);
        let x = x;

        // Build the prefixes
        left.f.iter_mut().enumerate().for_each(|(n, block)| {
            block[0..n].clone_from_slice(&x[0..n]);
        });

        prf::encrypt8(&self.k2, &mut left.f);

        for n in 0..NUM_BLOCKS {
            // Set prefix and create PRP for the block
            let prp = prp::Prp::init(&left.f[n]);
            left.x[n] = prp.permute(x[n]);

            // Reset the f block (probably inefficient)
            left.f[n] = Default::default();
            left.f[n][0..n].clone_from_slice(&x[0..n]);
            left.f[n][n] = left.x[n];
            // Include the block number in the value passed to the Random Oracle
            left.f[n][NUM_BLOCKS] = n as u8;

            //let mut ro_keys: [GenericArray<u8, U16>; 256] = [Default::default(); 256];

            let mut ro_keys: GenericArray<GenericArray<u8, <Aes128 as BlockCipher>::BlockSize>, U256> = Default::default();
            for j in 0..=255 {
                //let mut ro_key: GenericArray<u8, U16> = Default::default();
                // Intermediate Random-Oracle key
                // the output of F in H(F(k1, y|i-1||j), r)
                ro_keys[j][0..n].clone_from_slice(&x[0..n]);
                ro_keys[j][n] = j as u8;
                ro_keys[j][NUM_BLOCKS] = n as u8;
            }
            prf::encrypt8(&self.k1, &mut ro_keys);

            for j in 0..=255 {
                let jstar = prp.inverse(j);
                let indicator = cmp(jstar, x[n]);
                let h = hash::hash(&ro_keys[j as usize], &right.nonce);
                right.data[n].set_bit(j, indicator ^ h);
            }
        }
        prf::encrypt8(&self.k1, &mut left.f);

        return CipherText { left: left, right: right };
    }

    /*pub fn encrypt(&mut self, input: u64) -> CipherText {
        CipherText {
            left: self.encrypt_left(input),
            right: self.encrypt_right(input)
        }
    }*/

    pub fn compare(a: &CipherText, b: &CipherText) -> i8 {
        // TODO: Make sure that this is constant time

        let mut is_equal = true;
        let mut l = 0; // Unequal block

        // TODO: Surely this could be done with iterators?
        for n in 0..NUM_BLOCKS {
            if &a.left.x[n] != &b.left.x[n] || &a.left.f[n] != &b.left.f[n] {
                is_equal = false;
                l = n;
                break;
            }
        }

        if is_equal {
            return 0;
        }

        let h = hash::hash(&a.left.f[l], &b.right.nonce);
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
    use aes::cipher::generic_array::arr;

    fn init_ore() -> OreLarge {
        let prf_key: Key = arr![u8; 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let prp_key: Key = arr![u8; 0xd0, 0xd0, 0x07, 0xa5, 0x3f, 0x9a, 0x68, 0x48, 0x83, 0xbc, 0x1f, 0x21, 0x0f, 0x65, 0x95, 0xa3];
        return OreLarge::init(prf_key, prp_key);
    }

    quickcheck! {
        fn compare(x: u64, y: u64) -> bool {
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

            return ret == OreLarge::compare(&a, &b);
        }

        fn compare_equal(x: u64) -> bool {
            let mut ore = init_ore();
            let a = ore.encrypt(x);
            let b = ore.encrypt(x);

            return 0 == OreLarge::compare(&a, &b);
        }
    }

    #[test]
    fn smallest_to_largest() {
        let mut ore = init_ore();
        let a = ore.encrypt(0);
        let b = ore.encrypt(18446744073709551615);

        assert_eq!(-1, OreLarge::compare(&a, &b));
    }

    #[test]
    fn largest_to_smallest() {
        let mut ore = init_ore();
        let a = ore.encrypt(18446744073709551615);
        let b = ore.encrypt(0);

        assert_eq!(1, OreLarge::compare(&a, &b));
    }

    #[test]
    fn smallest_to_smallest() {
        let mut ore = init_ore();
        let a = ore.encrypt(0);
        let b = ore.encrypt(0);

        assert_eq!(0, OreLarge::compare(&a, &b));
    }

    #[test]
    fn largest_to_largest() {
        let mut ore = init_ore();
        let a = ore.encrypt(18446744073709551615);
        let b = ore.encrypt(18446744073709551615);

        assert_eq!(0, OreLarge::compare(&a, &b));
    }

    #[test]
    fn comparisons_in_first_block() {
        let mut ore = init_ore();
        let a = ore.encrypt(18446744073709551615);
        let b = ore.encrypt(18446744073709551612);

        assert_eq!(1, OreLarge::compare(&a, &b));
        assert_eq!(-1, OreLarge::compare(&b, &a));
    }

    #[test]
    fn comparisons_in_last_block() {
        let mut ore = init_ore();
        let a = ore.encrypt(10);
        let b = ore.encrypt(73);

        assert_eq!(-1, OreLarge::compare(&a, &b));
        assert_eq!(1, OreLarge::compare(&b, &a));
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
