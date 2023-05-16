use std::marker::PhantomData;
use crate::{data_with_header::{DataWithHeader, CtType}, ParseError, header::Header};
use super::{CipherTextBlock, CipherText, RightCipherTextBlock};

pub struct RightCiphertext<'a, B: RightCipherTextBlock<'a>> {
    pub(crate) data: DataWithHeader,
    _phantom: PhantomData<&'a B>,
}

impl<'a, B: RightCipherTextBlock<'a>> RightCiphertext<'a, B> {
    pub const NONCE_SIZE: usize = 16;

    pub fn new(num_blocks: usize, nonce: &[u8; 16]) -> Self {
        let hdr = Header::new(CtType::Right, num_blocks);
        let mut data = DataWithHeader::new(hdr, Self::NONCE_SIZE + (num_blocks * <Self as CipherText>::Block::byte_size()));
        data.extend_from_slice(nonce);
        Self { data, _phantom: PhantomData }
    }

    pub fn add_block(&mut self, block: B) {
        block.extend_into(&mut self.data);
    }
}

impl<'a, B: RightCipherTextBlock<'a>> CipherText<'a> for RightCiphertext<'a, B> {
    type Block = B;

    fn header(&self) -> Header {
        self.data.header()
    }

    fn blocks(&self) -> Box<dyn Iterator<Item=Self::Block>> {
        todo!()
    }
}

impl<'a, B: RightCipherTextBlock<'a>> TryFrom<&'a [u8]> for RightCiphertext<'a, B> {
    type Error = ParseError;

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        let hdr = Header::from_slice(data);
        if matches!(hdr.ct_type, CtType::Right) {
            Ok(Self { data: data.into(), _phantom: PhantomData })
        } else {
            Err(ParseError {  })
        }
    }
}

impl<'a, B: RightCipherTextBlock<'a>> AsRef<[u8]> for RightCiphertext<'a, B> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}