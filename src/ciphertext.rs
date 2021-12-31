use crate::primitives::{AesBlock, NONCE_SIZE};
pub use crate::ORECipher;

#[derive(Debug, Clone)]
pub struct Left {
    pub data: Vec<u8>
}

#[derive(Debug, Clone)]
pub struct Right {
    pub nonce: AesBlock,
    pub data: Vec<u8>
}

#[derive(Debug, Clone)]
pub struct CipherText(pub Left, pub Right);

#[derive(Debug)]
pub struct ParseError;

impl Left {
    pub(crate) fn init(len: usize) -> Self {
        Self {
            data: vec![0u8; len]
        }
    }

    pub fn size(self) -> usize {
        self.data.len()
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.data
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        Ok(Self { data: Vec::from(data) })
    }
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

impl CipherText {
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
