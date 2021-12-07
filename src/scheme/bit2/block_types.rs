use crate::primitives::AesBlock;
use crate::ciphertext::{
    CipherTextBlock,
    ParseError
};
use std::convert::TryInto;
use core::array::TryFromSliceError;

pub type LeftBlock16 = AesBlock;

/*
 * Block type for a Right CipherText with 32-bytes per block
 * corresponding to a plaintext block-size of 8-bits and a 2-bit indicator function.
 */
#[derive(Debug, Default, Copy, Clone)]
pub struct RightBlock32 {
    low: u128,
    high: u128
}

impl RightBlock32 {
    #[inline]
    pub fn set_bit(&mut self, position: u8, value: u8) {
        if position < 128 {
          let bit: u128 = (value as u128) << position;
          self.low |= bit;
        } else {
          let bit: u128 = (value as u128) << (position - 128);
          self.high |= bit;
        }
    }

    #[inline]
    pub fn get_bit(&self, position: u8) -> u8 {
        if position < 128 {
            let mask: u128 = 1 << position;
            return ((self.low & mask) >> position) as u8;
        } else {
            let mask: u128 = 1 << (position - 128);
            return ((self.high & mask) >> (position - 128)) as u8;
        }
    }
}

impl CipherTextBlock for LeftBlock16 {
    const BLOCK_SIZE: usize = 16;

    fn to_bytes(self) -> Vec<u8> {
        return self.to_vec();
    }

    fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() != Self::BLOCK_SIZE {
            return Err(ParseError);
        } else {
            return Ok(Self::clone_from_slice(data));
        }
    }
}

fn parse_words(input: &[u8]) -> Result<(u128, u128), TryFromSliceError> {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u128>());
    let x = u128::from_be_bytes(int_bytes.try_into()?);
    let (int2_bytes, _) = rest.split_at(std::mem::size_of::<u128>());
    let y = u128::from_be_bytes(int2_bytes.try_into()?);
    return Ok((x, y));
}

impl CipherTextBlock for RightBlock32 {
    const BLOCK_SIZE: usize = 32;

    fn to_bytes(self) -> Vec<u8> {
        [self.low.to_be_bytes().to_vec(), self.high.to_be_bytes().to_vec()].concat()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() != Self::BLOCK_SIZE {
            return Err(ParseError);
        } else {
            let (low, high) = parse_words(data).map_err(|_| ParseError)?;
            return Ok(Self {
                low: low,
                high: high
            });
        }
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
}
