use std::ops::BitXorAssign;

use formats::{CipherTextBlock, DataWithHeader, RightCipherTextBlock};
use primitives::{NewPrp, prp::bitwise::BitwisePrp};


#[derive(Debug)]
pub struct RightBlock(pub(super) u32);

impl<'a> RightCipherTextBlock<'a> for RightBlock {}

impl RightBlock {
    pub(crate) fn init(plaintext: u8) -> Self {
        assert!(plaintext < 32, "Block cannot encode more than 32-bits");
        Self(0xFFFFFFFF << plaintext)
    }

    pub(crate) fn shuffle(&self, prp: &NewPrp<u8, 32>) -> Self {
        Self(self.0.bitwise_inverse_shuffle(prp))
    }

    pub(crate) fn get_bit(&self, bit: u8) -> u8 {
        ((self.0 >> bit) & 1).try_into().unwrap()
    }

    // TODO: Instead of get_bit, we could define get_indicator which also takes a "blind"
    // parameter (i.e. the hash function output)
}

impl BitXorAssign<u32> for RightBlock {
    fn bitxor_assign(&mut self, rhs: u32) {
        self.0 ^= rhs;
    }
}

// TODO: Can we derive macro any of this, too??
impl<'a> CipherTextBlock<'a> for RightBlock {
    fn byte_size() -> usize {
        4
    }

    fn extend_into(&self, out: &mut DataWithHeader) {
        out.extend(self.0.to_be_bytes());
    }
}

impl From<&[u8]> for RightBlock {
    fn from(value: &[u8]) -> Self {
        assert!(value.len() == Self::byte_size());
        let mut buf: [u8; 4] = Default::default();
        buf.copy_from_slice(&value[0..4]);
        RightBlock(u32::from_be_bytes(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_0() {
        let block = RightBlock::init(0);
        assert!(matches!(block, RightBlock(0b11111111111111111111111111111111)));
    }

    #[test]
    fn test_init_28() {
        let block = RightBlock::init(28);
        assert!(matches!(block, RightBlock(0b11110000000000000000000000000000)));
    }

    #[test]
    fn test_init_31() {
        let block = RightBlock::init(31);
        assert!(matches!(block, RightBlock(0b10000000000000000000000000000000)));
    }

    #[test]
    #[should_panic(expected="Block cannot encode more than 32-bits")]
    fn test_init_32() {
        RightBlock::init(32);
    }

    #[test]
    fn get_bit() {
        let block = RightBlock::init(28);
        assert_eq!(block.get_bit(0), 0);
        assert_eq!(block.get_bit(1), 0);
        assert_eq!(block.get_bit(2), 0);
        assert_eq!(block.get_bit(27), 0);
        assert_eq!(block.get_bit(28), 1);
        assert_eq!(block.get_bit(31), 1);
    }

    #[test]
    #[should_panic]
    fn get_bit_out_of_range() {
        let block = RightBlock::init(28);
        block.get_bit(32);
    }
}