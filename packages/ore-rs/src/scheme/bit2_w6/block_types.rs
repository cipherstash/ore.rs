use zeroize::Zeroize;

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
    /// Read bit `bit` (in `0..64`); returns `0` or `1`.
    #[inline]
    pub fn get_bit(&self, bit: usize) -> u8 {
        debug_assert!(bit < 64);
        // `bit` is the secret permuted symbol; read the byte obliviously so the
        // access address does not depend on it. See `width::ct_select_byte`.
        let byte = crate::scheme::width::ct_select_byte(&self.data, bit / 8);
        crate::scheme::width::ct_bit(byte, (bit % 8) as u8)
    }
}

impl RightBitVec for RightBlock8 {
    fn set_bit(&mut self, bit: usize, value: u8) {
        debug_assert!(bit < 64);
        let byte_index = bit / 8;
        let mask = bit % 8;
        self.data[byte_index] |= value << mask;
    }
    fn get_bit(&self, bit: usize) -> u8 {
        RightBlock8::get_bit(self, bit)
    }
    fn as_mut_bytes(&mut self) -> &mut [u8] {
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

    fn default_in_place(&mut self) {
        self.data.zeroize()
    }
}
