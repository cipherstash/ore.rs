
pub mod bit2;
use crate::primitives::{AesBlock, SEED64};
use std::cmp::Ordering;

pub type PlainText<const N: usize> = [u8; N];
pub type LeftBlock16 = AesBlock;

#[derive(Debug)]
pub struct Left<const N: usize> {
    pub f: [LeftBlock16; N],
    pub x: [u8; 8] // FIXME: x is poorly named!
}

#[derive(Debug)]
pub struct Right<const N: usize> {
    pub nonce: AesBlock,
    pub data: [OreBlock8; N]
}

#[derive(Debug)]
pub struct CipherText<const N: usize> {
    pub left: Left<N>,
    pub right: Right<N>
}

/* An ORE block for k=8
 * |N| = 2^k */
// TODO: We might be able to use an __m256 for this
// TODO: Poorly named - we should call it RightBlock32 (32 bytes)
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
    fn encrypt_left<const N: usize>(&mut self, input: &PlainText<N>) -> Result<Left<N>, OREError>;
    fn encrypt<const N: usize>(&mut self, input: &PlainText<N>) -> Result<CipherText<N>, OREError>;
}

pub trait OREEncrypt {
    type LeftOutput;
    type FullOutput;

    fn encrypt_left<T: ORECipher>(&self, cipher: &mut T) -> Result<Self::LeftOutput, OREError>;
    fn encrypt<T: ORECipher>(&self, input: &mut T) -> Result<Self::FullOutput, OREError>;
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

// FIXME: I don't like that the cipher is mutable - its private members are mutable
// TODO: Perhaps we could make the implementations default for the trait and control things
// with the types. Only need to override for things like floats.
impl OREEncrypt for u64 {
    type LeftOutput = Left<8>;
    type FullOutput = CipherText<8>;

    fn encrypt_left<T: ORECipher>(&self, cipher: &mut T) -> Result<Self::LeftOutput, OREError> {
        let bytes: PlainText<8> = self.to_be_bytes();
        return cipher.encrypt_left(&bytes);
    }

    fn encrypt<T: ORECipher>(&self, cipher: &mut T) -> Result<Self::FullOutput, OREError> {
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

