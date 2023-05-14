use std::{marker::PhantomData, slice::Iter};
use crate::{data_with_header::{CtType, DataWithHeader}, header::Header, ParseError};
use super::{CipherTextBlock, CipherText};

pub struct LeftCiphertext<B: CipherTextBlock> {
    pub(crate) data: DataWithHeader,
    _phantom: PhantomData<B>,
}

impl<B: CipherTextBlock> LeftCiphertext<B> {
    pub fn new(num_blocks: usize) -> Self {
        let hdr = Header::new(CtType::Left, num_blocks);

        Self {
            data: DataWithHeader::new(hdr, num_blocks * <Self as CipherText>::Block::byte_size()),
            _phantom: PhantomData
        }
    }

    pub fn add_block(&mut self, block: &B) {
        block.extend_into(&mut self.data);
    }
}

impl<B: CipherTextBlock> CipherText for LeftCiphertext<B> {
    type Block = B;

    fn header(&self) -> Header {
        self.data.header()
    }

    fn blocks(&self) -> Iter<Self::Block> {
        todo!()
    }
}

impl<B: CipherTextBlock> TryFrom<&[u8]> for LeftCiphertext<B> {
    type Error = ParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let hdr = Header::from_slice(data);
        if matches!(hdr.ct_type, CtType::Left) {
            Ok(Self { data: data.into(), _phantom: PhantomData })
        } else {
            Err(ParseError {  })
        }
    }
}

impl<B: CipherTextBlock> AsRef<[u8]> for LeftCiphertext<B> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}
