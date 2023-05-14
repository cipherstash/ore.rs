use std::{marker::PhantomData, slice::Iter};
use crate::{data_with_header::{DataWithHeader, CtType}, ParseError, header::Header};
use super::{CipherTextBlock, CipherText};

pub struct RightCiphertext<B: CipherTextBlock> {
    pub(crate) data: DataWithHeader,
    _phantom: PhantomData<B>,
}

impl<B: CipherTextBlock> RightCiphertext<B> {
    const NONCE_SIZE: usize = 16;

    pub fn new(num_blocks: usize, nonce: &[u8; 16]) -> Self {
        let hdr = Header::new(CtType::Left, num_blocks);
        let mut data = DataWithHeader::new(hdr, Self::NONCE_SIZE + (num_blocks * <Self as CipherText>::Block::byte_size()));
        data.extend_from_slice(nonce);
        Self { data, _phantom: PhantomData }
    }

    pub fn add_block(&mut self, block: u32) {
        self.data.extend(block.to_be_bytes().into_iter());
    }
}


impl<B: CipherTextBlock> CipherText for RightCiphertext<B> {
    type Block = B;

    fn header(&self) -> Header {
        self.data.header()
    }

    fn blocks(&self) -> Iter<Self::Block> {
        todo!()
    }
}

impl<B: CipherTextBlock> TryFrom<&[u8]> for RightCiphertext<B> {
    type Error = ParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let hdr = Header::from_slice(data);
        if matches!(hdr.ct_type, CtType::Right) {
            Ok(Self { data: data.into(), _phantom: PhantomData })
        } else {
            Err(ParseError {  })
        }
    }
}

impl<B: CipherTextBlock> AsRef<[u8]> for RightCiphertext<B> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}