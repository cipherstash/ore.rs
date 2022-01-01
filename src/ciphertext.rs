use crate::primitives::AesBlock;
pub use crate::ORECipher;

#[derive(Debug, Clone)]
pub struct Right {
    pub nonce: AesBlock,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CipherText<L: LeftCipherText>(pub L, pub Right);

#[derive(Debug)]
pub struct ParseError;

pub trait LeftCipherText {
    const BLOCK_SIZE: usize;

    fn init(blocks: usize) -> Self;
    fn num_blocks(&self) -> usize;

    /* Sets the value for the nth permuted x value in the output */
    fn set_xn(&mut self, n: usize, value: u8);

    fn block(&self, index: usize) -> &[u8];
    fn block_mut(&mut self, index: usize) -> &mut [u8];

    /* Returns a mutable slice for the whole "F" block.
     * This must be suitable for passing to a PRF.
     * TODO: Perhaps we should consider a trait bound here? */
    fn f_mut(&mut self) -> &mut [u8];
}

impl Right {
    // TODO: Pass a size value for the data
    pub(crate) fn init(len: usize) -> Self {
        Self {
            nonce: Default::default(),
            data: vec![0u8; len],
        }
    }

    pub fn size(self) -> usize {
        self.data.len()
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.data
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        // TODO
        Ok(Self::init(100))
    }
}

impl<L: LeftCipherText> CipherText<L> {
    pub fn to_bytes(&self) -> Vec<u8> {
        // TODO - or do we just use serde?
        //[self.0.to_bytes(), self.1.to_bytes()].concat()
        vec![0]
    }

    // TODO: Maybe we just use serde traits instead!?
    /*pub fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        // TODO: I'm not sure if this makes sense any more on it's own?
        // You'd have to know the size of the left CT at least
        // Maybe that value *could* be a generic parameter?
    }*/
}
