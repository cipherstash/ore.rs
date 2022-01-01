pub use crate::ORECipher;
use rand::Rng;
use serde::{Serialize, Deserialize, de::DeserializeOwned};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherText<S>
where
    S: ORECipher,
    <S as ORECipher>::LeftType: LeftCipherText,
    <S as ORECipher>::RightType: RightCipherText,
{
    pub left: S::LeftType,
    pub right: S::RightType,
}

// TODO: Is DeserializeOwned slower than Deserialize? Will we have lifetime problems if we don't
// use it?
impl <S> CipherText<S>
where
    S: ORECipher,
    <S as ORECipher>::LeftType: LeftCipherText + DeserializeOwned,
    <S as ORECipher>::RightType: RightCipherText + DeserializeOwned,
{
    // TODO: Deprecate these
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        let decoded: Self = bincode::deserialize(&data).or_else(|_| Err(ParseError))?;
        Ok(decoded)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Left<S: ORECipher>
where
    <S as ORECipher>::LeftType: LeftCipherText,
{
    pub left: S::LeftType,
}

// TODO: Remove this
#[derive(Debug)]
pub struct ParseError;

pub trait LeftCipherText: Serialize {
    const BLOCK_SIZE: usize;

    fn init(blocks: usize) -> Self;
    fn num_blocks(&self) -> usize;
    fn block(&self, index: usize) -> &[u8];
    fn block_mut(&mut self, index: usize) -> &mut [u8];

    /* Sets the value for the nth permuted x value in the output */
    fn set_xn(&mut self, n: usize, value: u8);

    /* Returns a mutable slice for the whole "F" block.
     * This must be suitable for passing to a PRF.
     * TODO: Perhaps we should consider a trait bound here? */
    fn f_mut(&mut self) -> &mut [u8];
}

pub trait RightCipherText: Serialize {
    const BLOCK_SIZE: usize;
    fn init<R: Rng>(blocks: usize, rng: &mut R) -> Self;
    fn num_blocks(&self) -> usize;
    fn block(&self, index: usize) -> &[u8];

    /* Set's the jth bit (or trit) of the nth block to value */
    fn set_n_bit(&mut self, index: usize, j: usize, value: u8);

    /* Get's the jth bit (or trit) of the nth block */
    fn get_n_bit(&self, index: usize, j: usize) -> u8;
}
