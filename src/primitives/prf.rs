use crate::primitives::{PRFKey, Prf};
use aes::Aes128;

use aes::cipher::{
    generic_array::{ArrayLength, GenericArray},
    BlockCipher, BlockEncrypt, NewBlockCipher,
};

type BlockSize = <Aes128 as BlockCipher>::BlockSize;

#[derive(Debug)]
pub struct AES128PRF {
    cipher: Aes128,
}

/*
 * This can be made a whole lot simpler
 * when the AES crate supports const generics and we don't have to deal with GenericArray.
*/
impl Prf for AES128PRF {
    fn new(key: &PRFKey) -> Self {
        let cipher = Aes128::new(key);
        Self { cipher }
    }

    fn encrypt_all(&self, data: &mut [u8]) {
        let blocks = to_blocks::<BlockSize>(&mut *data);
        self.cipher.encrypt_blocks(blocks);
    }
}

fn to_blocks<N>(data: &mut [u8]) -> &mut [GenericArray<u8, N>]
where
    N: ArrayLength<u8>,
{
    use core::slice;
    let n = N::to_usize();
    debug_assert!(data.len() % n == 0);

    #[allow(unsafe_code)]
    unsafe {
        slice::from_raw_parts_mut(data.as_ptr() as *mut GenericArray<u8, N>, data.len() / n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn init_prf() -> AES128PRF {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        let key_array = GenericArray::from_slice(&key);
        Prf::new(key_array)
    }

    #[test]
    fn prf_test_single_block() {
        let mut input: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 170];
        let prf = init_prf();

        prf.encrypt_all(&mut input);
        assert_eq!(
            input,
            [183, 103, 151, 211, 249, 253, 170, 135, 117, 243, 131, 50, 27, 15, 170, 59]
        );
    }

    #[test]
    fn prf_test_2_blocks() {
        let mut input = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 170, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            13, 14, 170, 255, 221, 97, 170,
        ];
        let prf = init_prf();

        prf.encrypt_all(&mut input);
        assert_eq!(
            input,
            [
                183, 103, 151, 211, 249, 253, 170, 135, 117, 243, 131, 50, 27, 15, 170, 59, 100,
                192, 41, 108, 208, 245, 146, 251, 188, 245, 156, 28, 33, 210, 70, 50
            ]
        );
    }
}
