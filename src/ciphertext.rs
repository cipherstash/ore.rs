pub use crate::ORECipher;
use rand::Rng;
use serde::{Serialize, Deserialize, de::DeserializeOwned};

#[derive(Debug, Clone, Serialize)]
pub struct CipherText<S, const N: usize>
where
    S: ORECipher<N>,
    <S as ORECipher<N>>::LeftType: LeftCipherText<N>,
    <S as ORECipher<N>>::RightType: RightCipherText,
{
    pub left: Left<S, N>,
    pub right: S::RightType, // TODO: Use a Right wrapper type
}

// TODO: Is DeserializeOwned slower than Deserialize? Will we have lifetime problems if we don't
// use it?
impl <S, const N: usize> CipherText<S, N>
where
    S: ORECipher<N>,
    <S as ORECipher<N>>::LeftType: LeftCipherText<N>,
    <S as ORECipher<N>>::RightType: RightCipherText + DeserializeOwned,
{
    // TODO: Deprecate these
    pub fn to_bytes(&self) -> Vec<u8> {
        //bincode::serialize(&self).unwrap()
        /*let slice = self.right.as_slice();
        let mut vec = vec![0; slice.len()];
        vec.copy_from_slice(slice);
        vec*/
        vec![0u8]
    }

    pub fn as_slice(&self) -> &[u8] {
        self.right.as_slice()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        //let decoded: Self = bincode::deserialize(&data).or_else(|_| Err(ParseError))?;
        //Ok(decoded)
        Err(ParseError)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Left<S, const N: usize>
where
    S: ORECipher<N>,
    <S as ORECipher<N>>::LeftType: LeftCipherText<N>
{
    pub data: Vec<u8>,
    inner: S::LeftType
}

// TODO: This is just meant to be a convenience type that wraps
// the underlying implementation
// It doesn't need the ORECipher but it does need the underlying type
//
impl <S, const N: usize> Left<S, N>
where
    S: ORECipher<N>,
    <S as ORECipher<N>>::LeftType: LeftCipherText<N>
{
    pub fn init() -> Self {
        Self {
            // TODO: Could this be an array? What is better?
            data: vec![0; S::LeftType::output_size()],
            // TODO: We can pass the slice to init
            inner: S::LeftType::init()
        }
    }

    pub fn block_mut(&mut self, index: usize) -> &mut [u8] {
        S::LeftType::block_mut(&mut self.data, index)
    }

    pub fn block(&self, index: usize) -> &[u8] {
        S::LeftType::block(&self.data, index)
    }

    pub fn f_mut(&mut self) -> &mut [u8] {
        S::LeftType::f_mut(&mut self.data)
    }

    pub fn xn(&self, n: usize) -> u8 {
        S::LeftType::xn(&self.data, n)
    }
}

// TODO: Remove this
#[derive(Debug)]
pub struct ParseError;

// TODO: Rename this to LeftInner or something? Or LeftData?
pub trait LeftCipherText<const N: usize>: Clone + Serialize + std::fmt::Debug {
    const BLOCK_SIZE: usize;

    fn init() -> Self;

    fn output_size() -> usize;
    fn block(data: &[u8], index: usize) -> &[u8];
    fn block_mut(data: &mut [u8], index: usize) -> &mut [u8];

    /* Sets the value for the nth permuted x value in the output */
    fn set_xn(data: &mut [u8], n: usize, value: u8);

    /* Gets the value for the nth permuted x value in the output */
    fn xn(data: &[u8], n: usize) -> u8;

    /* Returns a mutable slice for the whole "F" block.
     * This must be suitable for passing to a PRF.
     * TODO: Perhaps we should consider a trait bound here? */
    fn f_mut(data: &mut [u8]) -> &mut [u8];
}

pub trait RightCipherText: Serialize {
    const BLOCK_SIZE: usize;
    fn init<R: Rng>(blocks: usize, rng: &mut R) -> Self;
    fn num_blocks(&self) -> usize;
    fn block(&self, index: usize) -> &[u8];

    fn as_slice(&self) -> &[u8];

    /* Set's the jth bit (or trit) of the nth block to value */
    fn set_n_bit(&mut self, index: usize, j: usize, value: u8);

    /* Get's the jth bit (or trit) of the nth block */
    fn get_n_bit(&self, index: usize, j: usize) -> u8;
}
