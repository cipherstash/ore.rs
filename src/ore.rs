
pub mod bit2;
use crate::primitives::SEED64;
use aes::cipher::{
    NewBlockCipher,
    generic_array::GenericArray,
};
use aes::Aes128;
use std::cmp::Ordering;

// TODO: Replace Left with a generic types
#[derive(Debug)]
pub struct Left {
    pub f: [u8; 128], // Blocksize * ORE blocks (16 * 8)
    pub x: [u8; 8] // FIXME: x is poorly named!
}

#[derive(Debug)]
pub struct Right<const N: usize> {
    pub nonce: GenericArray<u8, <Aes128 as NewBlockCipher>::KeySize>,
    pub data: [OreBlock8; N]
}

#[derive(Debug)]
pub struct CipherText<const N: usize> {
    pub left: Left,
    pub right: Right<N>
}

pub type PlainText<const N: usize> = [u8; N];

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

pub trait ORECipher: Sized {
    fn init(k1: [u8; 16], k2: [u8; 16], seed: &SEED64) -> Result<Self, OREError>;
    fn encrypt_left(&mut self, input: &[u8]) -> Result<Left, OREError>;
    fn encrypt<const N: usize>(&mut self, input: &PlainText<N>) -> Result<CipherText<N>, OREError>;
}

pub trait OREEncrypt {
    type Output;

    fn encrypt_left(&self, cipher: &mut impl ORECipher) -> Result<Left, OREError>;
    fn encrypt<T: ORECipher>(&self, input: &mut T) -> Result<Self::Output, OREError>;
}

impl<const N: usize> PartialOrd for CipherText<N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        return self.cmp(other);
    }
}

impl<const N: usize> PartialEq for CipherText<N> {
    fn eq(&self, other: &Self) -> bool {
        return self.eq(other);
    }
}

// TODO:
// Make these the default implementations in the trait
// And add a trait called ToOREPlaintext or something
// Then we only need one function here
// FIXME: I don't like that the cipher is mutable - its private members are mutable
impl OREEncrypt for u64 {
    type Output = CipherText<8>;

    fn encrypt_left(&self, cipher: &mut impl ORECipher) -> Result<Left, OREError> {
        let bytes: [u8; 8] = self.to_be_bytes();
        return cipher.encrypt_left(&bytes);
    }

    fn encrypt<T: ORECipher>(&self, cipher: &mut T) -> Result<Self::Output, OREError> {
        let bytes: PlainText<8> = self.to_be_bytes();
        return cipher.encrypt(&bytes);
    }
}

/*
 * TODO: This won't work yet as we need to genericise `Left`
impl OREEncrypt for u32 {
    type Output = CipherText<4>;

    fn encrypt_left(&self, cipher: &mut impl ORECipher) -> Result<Left, OREError> {
        let bytes: [u8; 4] = self.to_be_bytes();
        return cipher.encrypt_left(&bytes);
    }

    fn encrypt<T: ORECipher>(&self, cipher: &mut T) -> Result<Self::Output, OREError> {
        let bytes: PlainText<4> = self.to_be_bytes();
        return cipher.encrypt(&bytes);
    }
}*/

