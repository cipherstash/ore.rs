use crate::primitives::AesBlock;
use rand::Rng;
pub use crate::ORECipher;

#[derive(Debug, Clone)]
pub struct Right {
    pub nonce: AesBlock,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CipherText<S: ORECipher>
where
    <S as ORECipher>::LeftType: LeftCipherText,
    <S as ORECipher>::RightType: RightCipherText
{
    pub left: S::LeftType,
    pub right: S::RightType
}

#[derive(Debug)]
pub struct ParseError;

// TODO: Create a Left wrapper type so we can do Left<OREAES128>
pub trait LeftCipherText {
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

pub trait RightCipherText {
    const BLOCK_SIZE: usize;
    fn init<R: Rng>(blocks: usize, rng: &mut R) -> Self;
    fn num_blocks(&self) -> usize;
    fn block(&self, index: usize) -> &[u8];
    fn block_mut(&mut self, index: usize) -> &mut [u8];

    /* Set's the jth bit (or trit) of the nth block to value */
    fn set_n_bit(&mut self, index: usize, j: usize, value: u8);

    /* Get's the jth bit (or trit) of the nth block */
    fn get_n_bit(&self, index: usize, j: usize) -> u8;
}

