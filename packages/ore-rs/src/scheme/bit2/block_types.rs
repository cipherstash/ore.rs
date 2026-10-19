use crate::ciphertext::{CipherTextBlock, ParseError};
use crate::primitives::AesBlock;

/// Per-block component of the Left half of a `bit2` ciphertext: a 16-byte
/// AES block holding the per-block PRF₁ tag.
pub type LeftBlock16 = AesBlock;

/// Per-block component of the Right half of a `bit2` ciphertext: a 32-byte
/// (256-bit) bitvector encoding one masked truth-table row, one bit per
/// possible byte value of the plaintext block.
#[derive(Debug, Copy, Clone, Default)]
pub struct RightBlock32 {
    // TODO: Make this a slice later when the entire right ciphertext is a big array
    data: [u8; 32],
}

impl RightBlock32 {
    /// Set bit `bit` to the low bit of `value`, overwriting whatever the
    /// bit held. A `u8` names every one of the 256 bits and no other.
    #[inline]
    pub fn set_bit(&mut self, bit: u8, value: u8) {
        let shift = bit % 8;
        let b = &mut self.data[usize::from(bit / 8)];
        *b = (*b & !(1 << shift)) | ((value & 1) << shift);
    }

    /// The raw bitvector bytes, LSB-first within each byte — the bit order
    /// used by [`Self::set_bit`] / [`Self::get_bit`].
    #[inline]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Mutable form of [`Self::bytes`].
    #[inline]
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8; 32] {
        &mut self.data
    }

    /// Read bit `bit` (in `0..256`); returns `0` or `1`. A `bit` past the
    /// block reads as `0`: the oblivious select finds no byte.
    #[inline]
    pub fn get_bit(&self, bit: usize) -> u8 {
        // `bit` is the secret permuted symbol; read the byte obliviously so the
        // access address does not depend on it. See `width::ct_select_byte`.
        let byte = crate::scheme::width::ct_select_byte(&self.data, bit / 8);
        crate::scheme::width::ct_bit(byte, (bit % 8) as u8)
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
    fn set_bit_overwrites_rather_than_ors() {
        let mut block = RightBlock32::default();
        block.set_bit(17, 1);
        block.set_bit(17, 0);
        assert_eq!(block.get_bit(17), 0);
        block.set_bit(18, 1);
        block.set_bit(16, 1);
        block.set_bit(17, 0);
        assert_eq!(
            (block.get_bit(16), block.get_bit(18)),
            (1, 1),
            "neighbours untouched"
        );
    }
}
