use std::{slice::Iter, marker::PhantomData};
use crate::{data_with_header::DataWithHeader, header::Header, ParseError, CtType};
use super::{CipherTextBlock, CipherText, left::LeftCiphertext, right::RightCiphertext};

pub struct CombinedBlock<L: CipherTextBlock, R: CipherTextBlock>(L, R);

impl<L: CipherTextBlock, R: CipherTextBlock> CipherTextBlock for CombinedBlock<L, R> {
    fn byte_size() -> usize {
        L::byte_size() + R::byte_size()
    }

    fn extend_into(&self, out: &mut Vec<u8>) {
        todo!()
    }
}

pub struct CombinedCiphertext<L: CipherTextBlock, R: CipherTextBlock> {
    data: DataWithHeader,
    _phantom: (PhantomData<L>, PhantomData<R>),
}


impl<L: CipherTextBlock, R: CipherTextBlock> CombinedCiphertext<L, R> {
    /// Creates a new CombinedCiphertext by merging (and consuming) the given left and right Ciphertexts.
    /// The headers must be comparable (See [Header]) and have the same block length.
    /// The resulting Ciphertext has a single header representing both ciphertexts.
    pub fn new(mut left: LeftCiphertext<L>, right: RightCiphertext<R>) -> Self {
        let mut l_hdr = left.header();
        let r_hdr = right.header();

        if !l_hdr.comparable(&r_hdr) || l_hdr.num_blocks != r_hdr.num_blocks {
            panic!("Cannot combine incompatible ciphertexts");
        }

        // Steal and reuse the left
        l_hdr.ct_type = CtType::Combined;
        left.data.set_header(&l_hdr);
        left.data.extend_from_slice(right.data.body());

        Self { data: left.data, _phantom: (PhantomData, PhantomData) }
    }
}

impl<L: CipherTextBlock, R: CipherTextBlock> CipherText for CombinedCiphertext<L, R> {
    type Block = CombinedBlock<L, R>;

    fn header(&self) -> Header {
        self.data.header()
    }

    fn blocks(&self) -> Iter<Self::Block> {
        todo!()
    }
}


impl<L: CipherTextBlock, R: CipherTextBlock> TryFrom<&[u8]> for CombinedCiphertext<L, R> {
    type Error = ParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let hdr = Header::from_slice(data);
        if matches!(hdr.ct_type, CtType::Combined) {
            Ok(Self { data: data.into(), _phantom: (PhantomData, PhantomData) })
        } else {
            Err(ParseError {  })
        }
    }
}

impl<L: CipherTextBlock, R: CipherTextBlock> AsRef<[u8]> for CombinedCiphertext<L, R> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}
