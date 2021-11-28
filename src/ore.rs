
pub mod bit2;
use crate::primitives::SEED64;
use aes::cipher::{
    NewBlockCipher,
    generic_array::GenericArray,
};
use aes::Aes128;

#[derive(Debug)]
pub struct Left {
    pub f: [u8; 128], // Blocksize * ORE blocks (16 * 8)
    pub x: [u8; 8] // FIXME: x is poorly named!
}

// TODO: Replace Left and Right with the generic types
// the Left should be an array of OreLeftBlock like we did for Right
#[derive(Debug)]
pub struct RightNew<const BLOCKS: usize> {
    // TODO: Can we make the Nonce type generic
    nonce: GenericArray<u8, <Aes128 as NewBlockCipher>::KeySize>,
    data: [OreBlock8; BLOCKS]
}

#[derive(Debug)]
pub struct Right {
    pub nonce: GenericArray<u8, <Aes128 as NewBlockCipher>::KeySize>,
    pub data: [OreBlock8; 8]
}

#[derive(Debug)]
pub struct CipherText {
    pub left: Left,
    pub right: Right
}

/* An ORE block for k=8
 * |N| = 2^k */
// TODO: We might be able to use an __m256 for this
#[derive(Debug, Default, Copy, Clone)]
pub struct OreBlock8 {
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


#[derive(Debug, Clone)]
pub struct OREError;

// Make cmp type generic
// Make num blocks and block size/type generic
/*
 * Trait for an ORE scheme that encrypts a type, T and
 * outputs a CipherText with N blocks of 8-bit small-domain ORE.
 */
pub trait ORE<T>: Sized {
    fn init(k1: &[u8], k2: &[u8], seed: &SEED64) -> Result<Self, OREError>;
    fn encrypt_left(&self, input: T) -> Result<Left, OREError>;
    fn encrypt(&mut self, input: T) -> Result<CipherText, OREError>;

    // TODO: This could probably do dynamic dispatch depending on the type
    fn compare(a: &CipherText, b: &CipherText) -> i8;
}

