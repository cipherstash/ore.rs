use crate::primitives::{AesBlock, Prf, PrfKey};
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::Aes128;
use zeroize::ZeroizeOnDrop;

#[derive(Debug, ZeroizeOnDrop)]
pub struct Aes128Prf {
    cipher: Aes128,
}

impl Prf for Aes128Prf {
    fn new(key: &PrfKey) -> Self {
        let cipher = Aes128::new(key);
        Self { cipher }
    }

    fn encrypt_all(&self, data: &mut [AesBlock]) {
        self.cipher.encrypt_blocks(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::Array;
    use hex_literal::hex;

    fn init_prf() -> Aes128Prf {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        let key_array = &key.into();
        Prf::new(key_array)
    }

    #[test]
    fn prf_test_single_block() {
        let mut input = [Array([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 170,
        ])];
        let prf = init_prf();

        prf.encrypt_all(&mut input);
        assert_eq!(
            input,
            [Array([
                183, 103, 151, 211, 249, 253, 170, 135, 117, 243, 131, 50, 27, 15, 170, 59
            ])]
        );
    }

    #[test]
    fn prf_test_2_blocks() {
        let mut input = [
            Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 170]),
            Array([4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 170, 255, 221, 97, 170]),
        ];
        let prf = init_prf();

        prf.encrypt_all(&mut input);
        assert_eq!(
            input,
            [
                Array([183, 103, 151, 211, 249, 253, 170, 135, 117, 243, 131, 50, 27, 15, 170, 59]),
                Array([100, 192, 41, 108, 208, 245, 146, 251, 188, 245, 156, 28, 33, 210, 70, 50])
            ]
        );
    }
}
