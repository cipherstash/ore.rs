use crate::{AesBlock, Prf, PrfKey};
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use zeroize::ZeroizeOnDrop;
use std::slice;

pub type PrfBlock = [u8; 16];

fn convert_slice<'a>(input: &'a mut [PrfBlock]) -> &'a mut [AesBlock] {
    let ptr = input.as_mut_ptr() as *mut AesBlock;
    unsafe { slice::from_raw_parts_mut(ptr, input.len()) }
}

#[derive(Debug, ZeroizeOnDrop)]
pub struct Aes128Prf {
    cipher: Aes128,
}

/*
 * This can be made a whole lot simpler
 * when the AES crate supports const generics and we don't have to deal with GenericArray.
*/
impl Prf for Aes128Prf {
    fn new(key: &PrfKey) -> Self {
        let cipher = Aes128::new(key);
        Self { cipher }
    }

    fn encrypt_all(&self, data: &mut [PrfBlock]) {
        let blocks = convert_slice(data);
        self.cipher.encrypt_blocks(blocks);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::generic_array::GenericArray;
    use hex_literal::hex;

    fn init_prf() -> Aes128Prf {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        let key_array = GenericArray::from_slice(&key);
        Prf::new(key_array)
    }

    #[test]
    fn prf_test_single_block() {
        let mut input = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 170]];
        
        let prf = init_prf();

        prf.encrypt_all(&mut input);
        assert_eq!(
            input,
            [[183, 103, 151, 211, 249, 253, 170, 135, 117, 243, 131, 50, 27, 15, 170, 59]]
        );
    }

    #[test]
    fn prf_test_2_blocks() {
        let mut input = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 170],
            [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 170, 255, 221, 97, 170],
        ];
        let prf = init_prf();

        prf.encrypt_all(&mut input);
        assert_eq!(
            input,
            [
                [183, 103, 151, 211, 249, 253, 170, 135, 117, 243, 131, 50, 27, 15, 170, 59],
                [100, 192, 41, 108, 208, 245, 146, 251, 188, 245, 156, 28, 33, 210, 70, 50]
            ]
        );
    }
}
