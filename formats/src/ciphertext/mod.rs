use std::slice::Iter;
use crate::header::Header;
mod left;
mod right;
mod combined;

// TODO: make the new and add_block functions a separate trait
pub trait CipherText {
    type Block: CipherTextBlock;

    fn comparable(&self, to: &impl CipherText) -> bool {
        self.header().comparable(&to.header())
    }
    // TODO: Probs shouldn't expose the header
    fn header(&self) -> Header;

    fn blocks(&self) -> Iter<Self::Block>;
}

pub trait CipherTextBlock {
    fn byte_size() -> usize;
    fn extend_into(&self, out: &mut Vec<u8>);
}
