use std::{marker::PhantomData, cmp::Ordering};
use crate::{data_with_header::{CtType, DataWithHeader}, header::Header, ParseError, LeftBlockEq, LeftCipherTextBlock, OreBlockOrd};
use super::{CipherTextBlock, CipherText, left::LeftCiphertext, right::RightCiphertext, RightCipherTextBlock};

#[derive(Debug)]
pub struct CombinedBlock<'a, L: CipherTextBlock<'a>, R: CipherTextBlock<'a>> {
    pub left: L,
    pub right: R,
    _phantom: PhantomData<&'a L>
}

/// A combined ciphertext block also implements Right Block
impl<'a, L, R> RightCipherTextBlock<'a> for CombinedBlock<'a, L, R>
where L: LeftCipherTextBlock<'a>,
    R: RightCipherTextBlock<'a>
{}

impl <'a, L: CipherTextBlock<'a>, R: CipherTextBlock<'a>> From<&'a [u8]> for CombinedBlock<'a, L, R> {
    fn from(value: &'a [u8]) -> Self {
        let left = L::from(&value[..L::byte_size()]);
        let right = R::from(&value[L::byte_size()..]);
        Self { left, right, _phantom: PhantomData }
    }
}

impl<'a, L: CipherTextBlock<'a>, R: CipherTextBlock<'a>> CipherTextBlock<'a> for CombinedBlock<'a, L, R> {
    fn byte_size() -> usize {
        L::byte_size() + R::byte_size()
    }

    fn extend_into(&self, out: &mut DataWithHeader) {
        todo!()
    }
}

pub struct CombinedCiphertext<'a, L: LeftCipherTextBlock<'a>, R: RightCipherTextBlock<'a>> {
    data: DataWithHeader,
    _phantom: (PhantomData<&'a L>, PhantomData<&'a R>),
}


impl<'a, L, R> CombinedCiphertext<'a, L, R>
where
    L: LeftCipherTextBlock<'a>,
    R: RightCipherTextBlock<'a> 
{
    pub fn new(num_blocks: usize, nonce: &[u8; 16]) -> Self {
        let hdr = Header::new(CtType::Combined, num_blocks);
        let mut data = DataWithHeader::new(
            hdr,
            RightCiphertext::<'a, R>::NONCE_SIZE + (num_blocks * <Self as CipherText>::Block::byte_size())
        );
        data.extend_from_slice(nonce);
        Self { data, _phantom: (PhantomData, PhantomData) }
    }

    // TODO: We should probably pass the args as references (same for left and right impls)
    pub fn add_block(&mut self, left: L, right: R) {
        left.extend_into(&mut self.data);
        right.extend_into(&mut self.data);
    }

    pub fn nonce(&self) -> &[u8] {
        &self.data.body()[..RightCiphertext::<'a, R>::NONCE_SIZE]
    }
}

impl<'a, L, R> CipherText<'a> for CombinedCiphertext<'a, L, R>
where
    L: LeftCipherTextBlock<'a>,
    R: RightCipherTextBlock<'a> 
{
    type Block = CombinedBlock<'a, L, R>;

    fn len(&self) -> usize {
        self.data.len()
    }

    fn header(&self) -> Header {
        self.data.header()
    }

    // TODO: This can go into the trait if we add a body method
    // Right is different though because we have the nonce!
    fn blocks(&'a self) -> Box<dyn Iterator<Item=Self::Block> + 'a> {
        Box::new(
            self.data.body()[RightCiphertext::<'a, R>::NONCE_SIZE..]
            .chunks(Self::Block::byte_size())
            .map(|bytes| {
                println!("BYTES LEN: {}", bytes.len());
                Self::Block::from(bytes)
            })
        )
    }
}


impl<'a, L, R> TryFrom<&'a [u8]> for CombinedCiphertext<'a, L, R>
where
    L: LeftCipherTextBlock<'a>,
    R: RightCipherTextBlock<'a> 
{
    type Error = ParseError;

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        let hdr = Header::from_slice(data);
        if matches!(hdr.ct_type, CtType::Combined) {
            Ok(Self { data: data.into(), _phantom: (PhantomData, PhantomData) })
        } else {
            Err(ParseError {  })
        }
    }
}

impl<'a, L, R> AsRef<[u8]> for CombinedCiphertext<'a, L, R>
where
    L: LeftCipherTextBlock<'a>,
    R: RightCipherTextBlock<'a> 
{
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

/// Blanket implementation to compare a left block to the left of any combined block
impl<'a, L, R> LeftBlockEq<'a, CombinedBlock<'a, L, R>> for L
where
    L: LeftCipherTextBlock<'a>,
    R: RightCipherTextBlock<'a>
{
    fn constant_eq(&self, other: &CombinedBlock<'a, L, R>) -> subtle_ng::Choice {
        self.constant_eq(&other.left)
    }
}

/// Blanket implementation for a left block to Ore compare to the right block
/// of a combined block.
impl<'a, L, R> OreBlockOrd<'a, CombinedBlock<'a, L, R>> for L
where
    L: LeftCipherTextBlock<'a>,
    R: RightCipherTextBlock<'a>,
    L: OreBlockOrd<'a, R>
{
    fn ore_compare(&self, nonce: &[u8], other: &CombinedBlock<'a, L, R>) -> Ordering {
        self.ore_compare(nonce, &other.right)
    }
}

