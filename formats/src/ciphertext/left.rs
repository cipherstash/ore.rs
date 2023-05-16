use std::{marker::PhantomData, ops::BitOr, cmp::Ordering};
use subtle_ng::{Choice, CtOption};

use crate::{data_with_header::{CtType, DataWithHeader}, header::Header, ParseError, LeftCipherTextBlock, OreBlockOrd, RightCipherTextBlock};
use super::{CipherTextBlock, CipherText, LeftBlockEq};

pub struct LeftCiphertext<'a, B: LeftCipherTextBlock<'a>> {
    pub(crate) data: DataWithHeader,
    _phantom: PhantomData<&'a B>,
}

impl<'a, B: LeftCipherTextBlock<'a>> LeftCiphertext<'a, B> {
    pub fn new(num_blocks: usize) -> Self {
        let hdr = Header::new(CtType::Left, num_blocks);

        Self {
            data: DataWithHeader::new(hdr, num_blocks * <Self as CipherText>::Block::byte_size()),
            _phantom: PhantomData
        }
    }

    pub fn add_block(&mut self, block: B) {
        block.extend_into(&mut self.data);
    }

    // TODO: this should return an Option of the first block that differs
    /// Compare all the blocks of self with all the blocks in the given iterator, up to the `n`
    /// where `n` is the length of the shorter iterator.
    /// In the case that the two iterators are not equal length and all `n` blocks are equal,
    /// TODO??? What do we return? Perhaps we can do the ORE comparison in this step, too?
    /// The ordering mechanism is important here, too (i.e. Lexicographic or Numerical)
    /// If its numerical then the shorter value is always less than the other.
    pub fn compare_blocks<O>(&'a self, nonce: &[u8], other: Box<dyn Iterator<Item=O> + 'a>) -> Ordering
    where
        B: LeftBlockEq<'a, O> + OreBlockOrd<'a, O>,
        O: RightCipherTextBlock<'a>
    {
        // TODO: We should use CtOption and acc.conditionally_select
        let eq = self.blocks().zip(other).fold(None, { |acc: Option<(B, O)>, (a, b): (B, O)|
            // FIXME: This definitely isn't constant time
            if a.constant_eq(&b).into() {
                acc.or(None)
            } else {
                Some((a, b))
            }
        });

        // FIXME: This isn't constant time either
        if let Some((a, b)) = eq {
            a.ore_compare(nonce, &b)
        } else {
            // No blocks differ so say that the values are equal
            Ordering::Equal
        }
        
        // TODO: Handle different lengths
    }
}

impl<'a, B: LeftCipherTextBlock<'a>> CipherText<'a> for LeftCiphertext<'a, B> {
    type Block = B;

    fn len(&self) -> usize {
        self.data.len()
    }

    fn header(&self) -> Header {
        self.data.header()
    }

    fn blocks(&'a self) -> Box<dyn Iterator<Item=Self::Block> + 'a> {
        // TODO: Should we assert that length is a multiple of the block size?
        Box::new(self.data.body().chunks(Self::Block::byte_size()).map(|bytes| B::from(bytes)))
    }
}

impl<'a, B: LeftCipherTextBlock<'a>> TryFrom<&'a [u8]> for LeftCiphertext<'a, B> {
    type Error = ParseError;

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        let hdr = Header::from_slice(data);
        if matches!(hdr.ct_type, CtType::Left) {
            Ok(Self { data: data.into(), _phantom: PhantomData })
        } else {
            Err(ParseError {  })
        }
    }
}

impl<'a, B: LeftCipherTextBlock<'a>> AsRef<[u8]> for LeftCiphertext<'a, B> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}
