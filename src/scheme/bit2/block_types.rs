use zeroize::Zeroize;

use crate::ciphertext::{CipherTextBlock, ParseError};
use crate::primitives::AesBlock;

pub type LeftBlock16 = AesBlock;

/*
 * Block type for a Right CipherText with 32-bytes per block
 * corresponding to a plaintext block-size of 8-bits and a 2-bit indicator function.
 */
#[derive(Debug, Copy, Clone, Default)]
pub struct RightBlock32 {
    // TODO: Make this a slice later when the entire right ciphertext is a big array
    data: [u8; 32],
}

impl RightBlock32 {
    #[inline]
    pub fn set_bit(&mut self, bit: usize, value: u8) {
        debug_assert!(bit < 256);
        let byte_index = bit / 8;
        let mask = bit % 8;
        let v = value << mask;
        self.data[byte_index] |= v;
    }

    #[inline]
    pub fn get_bit(&self, bit: usize) -> u8 {
        debug_assert!(bit < 256);
        let byte_index = bit / 8;
        let position = bit % 8;
        let v = 1 << position;

        (self.data[byte_index] & v) >> position
    }
}

impl CipherTextBlock for LeftBlock16 {
    const BLOCK_SIZE: usize = 16;

    fn to_bytes(self) -> Vec<u8> {
        self.to_vec()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() != Self::BLOCK_SIZE {
            Err(ParseError)
        } else {
            Ok(Self::clone_from_slice(data))
        }
    }

    fn default_in_place(&mut self) {
        self.zeroize()
    }
}

impl CipherTextBlock for RightBlock32 {
    const BLOCK_SIZE: usize = 32;

    // TODO: Just return a slice so we can just return data directly!
    fn to_bytes(self) -> Vec<u8> {
        self.data.to_vec()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() != Self::BLOCK_SIZE {
            Err(ParseError)
        } else {
            let mut arr = [0; 32];
            arr.clone_from_slice(data);

            Ok(Self { data: arr })
        }
    }

    fn default_in_place(&mut self) {
        self.data.zeroize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_get_bit() {
        let mut block: RightBlock32 = Default::default();
        block.set_bit(17, 1);
        assert_eq!(block.get_bit(17), 1);

        block.set_bit(180, 1);
        assert_eq!(block.get_bit(180), 1);

        block.set_bit(255, 1);
        assert_eq!(block.get_bit(255), 1);
    }

    #[test]
    fn right_default_in_place_without_new_data() {
        let mut right = RightBlock32::default();
        right.data.copy_from_slice(&[1; 32]);

        let ptr: *const [u8] = &right.data;

        assert_eq!(unsafe { &*ptr }, &[1; 32]);

        right.default_in_place();

        assert_eq!(unsafe { &*ptr }, &[0; 32]);
        assert_eq!(right.data, [0; 32]);
    }
}
