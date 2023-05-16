use subtle_ng::{ConstantTimeEq, Choice};
use crate::{header::Header, data_with_header::DataWithHeader};
pub(crate) mod left;
pub(crate) mod right;
pub(crate) mod combined;

// TODO: make the new and add_block functions a separate trait
pub trait CipherText<'a> {
    type Block: CipherTextBlock<'a>;

    // TODO: Remove this
    fn comparable(&self, to: &impl CipherText<'a>) -> bool {
        self.header().comparable(&to.header())
    }
    // TODO: Probs shouldn't expose the header
    fn header(&self) -> Header;

    fn blocks(&'a self) -> Box<dyn Iterator<Item=Self::Block> + 'a>;
}

pub trait CipherTextBlock<'a>: From<&'a [u8]> { // TODO: Zeroize
    fn byte_size() -> usize;
    fn extend_into(&self, out: &mut DataWithHeader);
}

pub trait LeftCipherTextBlock<'a>: LeftBlockEq<'a> + CipherTextBlock<'a> {}

pub trait RightCipherTextBlock<'a>: CipherTextBlock<'a> {}

pub trait LeftBlockEq<'a, Other = Self> {
    type Other: ?Sized + CipherTextBlock<'a>;

    // TODO: Maybe this is choice? Or a wrapper of choice at least
    fn constant_eq(&self, other: &Other) -> Choice;
}

pub trait OreBlockOrd<'a, Other> {
    type Other: ?Sized + RightCipherTextBlock<'a>;

    fn ore_compare(&self, right: &Other) -> u8; // TODO: Return a PartialOrd enum value
}
