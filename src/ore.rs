
pub mod bit2;
use crate::primitives::{AesBlock, SEED64};
use std::cmp::Ordering;

pub type PlainText<const N: usize> = [u8; N];
pub type LeftBlock16 = AesBlock;

#[derive(Debug)]
pub struct Left<const N: usize> {
    /* Array of Left blocks of size N */
    pub f: [LeftBlock16; N],

    /* Transformed input array of size N (x̃ = π(F (k_2 , x|i−1 ), x_i )) */
    pub xt: [u8; N]
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

