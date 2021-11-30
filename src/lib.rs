
mod encrypt;
mod ciphertext;
mod primitives;
pub mod scheme;

//pub use crate::ore::ORECipher;
pub use crate::encrypt::OREEncrypt;
pub use crate::ciphertext::*;

use crate::primitives::SEED64;
pub type PlainText<const N: usize> = [u8; N];

#[derive(Debug, Clone)]
pub struct OREError;

pub trait ORECipher: Sized {
    type LeftBlockType;
    type RightBlockType;

    fn init(k1: [u8; 16], k2: [u8; 16], seed: &SEED64) -> Result<Self, OREError>;

    fn encrypt_left<const N: usize>(
        &mut self, input: &PlainText<N>
    ) -> Result<Left<Self::LeftBlockType, N>, OREError>;

    fn encrypt<const N: usize>(
        &mut self, input: &PlainText<N>
    ) -> Result<CipherText<Self::LeftBlockType, Self::RightBlockType, N>, OREError>;
}

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

