
use crate::prp;
use crate::prf;
use crate::hash;

use rand;
use rand::Rng;
use rand::os::{OsRng};
use byteorder::{ByteOrder, BigEndian};

use std::fmt;

// This could probably be a re-export
//use aes::cipher::generic_array::arr;

use aes::cipher::{
    consts::{U8, U16, U32},
    NewBlockCipher,
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
const NONCE_SIZE: usize = 16;
const LEFT_CHUNK_SIZE: usize = 17;
// block size = 8, 256 bits (1-bit indicator)
const RIGHT_CHUNK_SIZE: usize = 32;

// TODO: Don't need GenericArray in Rust 1.51.0
// See https://blog.rust-lang.org/2021/03/25/Rust-1.51.0.html
#[derive(Debug)]
pub struct LeftBlock {
    // The output of the PRF
    f: GenericArray<u8, U16>,
    // The output of the PRP
    x: u8
}

pub type Left = [LeftBlock; 8];

#[derive(Debug)]
pub struct Right {
    nonce: [u8; 16],
    data: [OreBlock8; 8]
}

//type Left = [u8; LEFT_CHUNK_SIZE * 8]; // 1 small-domain block times the number of blocks
//type Right = [u8; NONCE_SIZE + (RIGHT_CHUNK_SIZE * 8)];

#[derive(Debug)]
pub struct CipherText {
    left: Left,
    right: Right
}

/*impl fmt::Display for CipherText {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Write strictly the first element into the supplied output
        // stream: `f`. Returns `fmt::Result` which indicates whether the
        // operation succeeded or failed. Note that `write!` uses syntax which
        // is very similar to `println!`.
        write!(f, "L<{:?}>, R<{:?}>", self.left, self.right)
    }
}*/

pub type Key = GenericArray<u8, <Aes128 as NewBlockCipher>::KeySize>;

trait Initialise {
    fn init() -> Self;
}

/*impl Initialise for Left {
    fn init() -> Self {
        [0u8; LEFT_CHUNK_SIZE * 8]
    }
}*/

/*impl Initialise for Right {
    fn init() -> Self {
        [0u8; NONCE_SIZE + (RIGHT_CHUNK_SIZE * 8)]
    }
}*/

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
            println!("mask = {}", mask);
            return ((self.low & mask) >> position) as u8;
        } else {
            let mask: u128 = 1 << (position - 128);
            return ((self.high & mask) >> (position - 128)) as u8;
        }
    }

    #[inline]
    pub fn from(input: &[u8]) -> Self {
        Self {
            low: BigEndian::read_u128(&input[0..16]),
            high: BigEndian::read_u128(&input[16..32])
        }
    }

    /*pub fn write_to(&self, &mut output: &[u8]) {
        // TODO: panic if slice is too small (or can we check at compile time?)
        BigEndian::write_u128(&mut output[0..16], block.low);
        BigEndian::write_u128(&mut output[16..32], block.low);
    }*/
}

fn left_eq(a: &LeftBlock, b: &LeftBlock) -> bool {
    a.x == b.x && a.f == b.f
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
    
    /* A potential problem. If there several blocks are identical we leak some information:
     *
     * LEFT prefix A: [53, 183, 207, 218, 185, 250, 90, 8, 245, 5, 161, 13, 57, 167, 194, 87], 0 => 105
       LEFT prefix A: [117, 119, 218, 93, 233, 78, 71, 194, 13, 107, 168, 213, 157, 80, 187, 32], 0 => 105
        LEFT prefix A: [166, 67, 156, 11, 162, 163, 89, 213, 192, 248, 91, 248, 151, 9, 190, 190], 0 => 105
        LEFT prefix A: [241, 21, 60, 59, 59, 17, 39, 105, 0, 115, 168, 129, 253, 80, 3, 221], 0 => 105
        LEFT prefix A: [21, 113, 57, 247, 39, 201, 129, 107, 19, 128, 129, 104, 71, 79, 185, 233], 0 => 105
        LEFT prefix A: [133, 106, 71, 146, 120, 225, 33, 219, 157, 2, 175, 250, 153, 107, 28, 121], 20 => 224
        LEFT prefix A: [252, 207, 10, 171, 40, 206, 232, 138, 249, 55, 143, 50, 40, 4, 223, 4], 125 => 77
        LEFT prefix A: [30, 56, 1, 20, 214, 174, 213, 63, 207, 6, 76, 178, 172, 246, 224, 232], 217 => 187

     Could we hash the block number as well as the block value?
    */


    /* TODO: A better approach here could be to define the left CT as an array
     * of LeftBlocks. We generate each one in sequence and then just join them
     * together at the end. This would make it easier to have different block sizes
     * and different numbers of blocks */
    pub fn encrypt_left(&self, input: u64) -> Left {
        let mut output: Left = [
            LeftBlock { f: Default::default(), x: Default::default() },
            LeftBlock { f: Default::default(), x: Default::default() },
            LeftBlock { f: Default::default(), x: Default::default() },
            LeftBlock { f: Default::default(), x: Default::default() },
            LeftBlock { f: Default::default(), x: Default::default() },
            LeftBlock { f: Default::default(), x: Default::default() },
            LeftBlock { f: Default::default(), x: Default::default() },
            LeftBlock { f: Default::default(), x: Default::default() },
        ];
        let mut x: [u8; NUM_BLOCKS] = Default::default();
        BigEndian::write_uint(&mut x, input, NUM_BLOCKS);
        let x = x;

        println!("x raw (left) = {:?}", x);

        // Use iter?
        for n in 0..NUM_BLOCKS {
            // Set prefix
            // Optimisation note: all blocks with the same prefix are going to have
            // the same PRP - no need to generate again (though checking may be just as expensive!)
            // Just see if the current prefix is the same as the last
            output[n].f[0..n].clone_from_slice(&x[0..n]);
            prf::encrypt(&self.k2, &mut output[n].f);
            let prp = prp::Prp::init(&output[n].f);
            output[n].x = prp.permute(x[n]);

            output[n].f = Default::default(); // Reset the f block (probably inefficient)
            output[n].f[0..n].clone_from_slice(&x[0..n]);
            output[n].f[n] = output[n].x;

            prf::encrypt(&self.k1, &mut output[n].f);
        }

        return output;
    }

    pub fn encrypt_right(&mut self, input: u64) -> Right {
        let mut output = Right {
            nonce: Default::default(),
            data: [Default::default(); 8]
        };
        // Generate a 16-byte random nonce
        self.rng.fill_bytes(&mut output.nonce);

        // Split the input into bytes
        let mut x: [u8; NUM_BLOCKS] = Default::default();
        BigEndian::write_uint(&mut x, input, NUM_BLOCKS);
        // Ensure x can't be mutated
        let x = x;


        let mut buf: GenericArray<u8, U16> = Default::default();

        for n in 0..NUM_BLOCKS {
            // Set prefix (same as the left side)
            buf = Default::default();
            buf[0..n].clone_from_slice(&x[0..n]);
            prf::encrypt(&self.k2, &mut buf);
            let prp = prp::Prp::init(&buf);

            for j in 0..=255 {
                let jstar = prp.inverse(j);
                let indicator = cmp(jstar, x[n]);
                let mut ro_key: GenericArray<u8, U16> = Default::default();
                // Intermediate Random-Oracle key
                // the output of F in H(F(k1, y|i-1||j), r)
                ro_key[0..n].clone_from_slice(&x[0..n]);
                ro_key[n] = j;

                prf::encrypt(&self.k1, &mut ro_key);

                let h = hash::hash(&ro_key, &output.nonce);
                output.data[n].set_bit(j, indicator ^ h);
            }

        }

        return output;
    }

    pub fn encrypt(&mut self, input: u64) -> CipherText {
        CipherText {
            left: self.encrypt_left(input),
            right: self.encrypt_right(input)
        }
    }

    pub fn compare(a: &CipherText, b: &CipherText) -> i8 {
        // TODO: Make sure that this is constant time

        let mut is_equal = true;
        let mut l = 0; // Unequal block

        // TODO: Surely this could be done with iterators?
        for n in 0..NUM_BLOCKS {
            if !left_eq(&a.left[n], &b.left[n]) {
                is_equal = false;
                l = n;
                break;
            }
        }

        if is_equal {
            return 0;
        }

        // FIXME: h is inconsistent across calls
        // This could be the right encryption that's broken or even the PRP
        // TODO: Check that the hash key is correct
        let h = hash::hash(&a.left[l].f, &b.right.nonce);
        // TODO: Try with a static nonce
        // Test the set and get bit functions
        //println!("a.left = {:?}", a.left);
        let test = b.right.data[l].get_bit(a.left[l].x) ^ h;
        //println!("block = {:?}, get_bit({}) = {}", b.right.data[l], a.left[l].x, b.right.data[l].get_bit(a.left[l].x));
        //println!("l = {}, test = {}, h = {}, a.left[l].x = {}", l, test, h, a.left[l].x);
        if test == 1 {
            return 1;
        }

        /*

        let ki: &[u8] = &a.left[position_left..(position_left + 16)];
        let hi: u8 = a.left[position_left + 16];
        let vi = OreBlock8::from(&b.right[position_right..(position_right + RIGHT_CHUNK_SIZE)]);
        let h = hash::hash(ki, nonce);

        if (vi.get_bit(hi) ^ h) == 1 {
            println!("DO WE GET HERE");
            return 1;
        }*/

        return -1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::generic_array::arr;
    use fake::{Fake};

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
