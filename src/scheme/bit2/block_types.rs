use crate::primitives::AesBlock;

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
