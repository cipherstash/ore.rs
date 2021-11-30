
use crate::primitives::{AesBlock, PRF, PRFKey};
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, NewBlockCipher, BlockCipher,
};

type BlockSize = <Aes128 as BlockCipher>::BlockSize;

#[derive(Debug)]
pub struct AES128PRF {
    cipher: Aes128
}

/* 
 * This can be made a whole lot simpler
 * when the AES crate supports const generics and we don't have to deal with GenericArray.
*/
impl PRF for AES128PRF {
    fn new(key: &PRFKey) -> Self {
        //let key_array = GenericArray::from_slice(key);
        let cipher = Aes128::new(&key);
        return Self { cipher };
    }

    fn encrypt_all(&self, data: &mut [AesBlock]) {
        self.cipher.encrypt_blocks(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use aes::cipher::generic_array::{arr, ArrayLength, GenericArray};

    fn init_prf() -> AES128PRF {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        let key_array = GenericArray::from_slice(&key);
        return PRF::new(&key_array);
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

    #[test]
    fn prf_test_single_block() {
        let mut input = [arr![u8; 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 170]];
        let prf = init_prf();

        prf.encrypt_all(&mut input);
        assert_eq!(input, [arr![u8; 183, 103, 151, 211, 249, 253, 170, 135, 117, 243, 131, 50, 27, 15, 170, 59]]);
    }

    #[test]
    fn prf_test_2_blocks() {
        let mut input = [
            arr![u8; 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 170],
            arr![u8; 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 170, 255, 221, 97, 170]
        ];
        let prf = init_prf();

        prf.encrypt_all(&mut input);
        assert_eq!(input, [
            arr![u8; 183, 103, 151, 211, 249, 253, 170, 135, 117, 243, 131, 50, 27, 15, 170, 59],
            arr![u8; 100, 192, 41, 108, 208, 245, 146, 251, 188, 245, 156, 28, 33, 210, 70, 50]
        ]);
    }
}
 
