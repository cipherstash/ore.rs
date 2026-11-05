use crate::ciphertext::{CipherTextBlock, ParseError};
use crate::scheme::width::RightBitVec;

pub use crate::scheme::bit2::block_types::LeftBlock16;

/// Per-block component of the Right half of a `bit2_w6` ciphertext: an
/// 8-byte (64-bit) bitvector encoding one masked truth-table row, one bit
/// per value in the 6-bit block domain.
#[derive(Debug, Copy, Clone, Default)]
pub struct RightBlock8 {
    data: [u8; 8],
}

impl RightBlock8 {
    /// The raw bitvector bytes, LSB-first within each byte.
    #[inline]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.data
    }
}

impl RightBitVec for RightBlock8 {
    type Bits = [u8; 8];

    fn as_mut_bits(&mut self) -> &mut [u8; 8] {
        &mut self.data
    }
}

impl CipherTextBlock for RightBlock8 {
    const BLOCK_SIZE: usize = 8;

    fn to_bytes(self) -> Vec<u8> {
        self.data.to_vec()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() != Self::BLOCK_SIZE {
            Err(ParseError)
        } else {
            let mut arr = [0; 8];
            arr.clone_from_slice(data);

            Ok(Self { data: arr })
        }
    }
}
