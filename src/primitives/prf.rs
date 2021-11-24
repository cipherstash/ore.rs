
use crate::PRF;
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, NewBlockCipher, BlockCipher,
    generic_array::{GenericArray, ArrayLength},
};

type BlockSize = <Aes128 as BlockCipher>::BlockSize;

#[derive(Debug)]
pub struct AES128PRF {
    cipher: Aes128
}

impl PRF for AES128PRF {
    fn new(key: &[u8]) -> Self {
        let key_array = GenericArray::from_slice(key);
        let cipher = Aes128::new(&key_array);
        return Self { cipher };
    }

    fn encrypt_all(&self, data: &mut [u8]) {
        let mut blocks = to_blocks::<BlockSize>(&mut data[..]);
        self.cipher.encrypt_blocks(&mut blocks);
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
        return PRF::new(&key);
    }

    #[test]
    fn prf_test_single_block() {
        let mut input: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0eaa");
        let prf = init_prf();

        prf.encrypt_all(&mut input);
        assert_eq!(input, [183, 103, 151, 211, 249, 253, 170, 135, 117, 243, 131, 50, 27, 15, 170, 59]);
    }

    #[test]
    fn prf_test_2_blocks() {
        let mut input: [u8; 32] = hex!("00010203 04050607 08090a0b 0c0d0eaa 04050607 08090a0b 0c0d0eaa ffdd61aa");
        let prf = init_prf();

        prf.encrypt_all(&mut input);
        assert_eq!(input, [
                   183, 103, 151, 211, 249, 253, 170, 135, 117, 243, 131, 50, 27, 15, 170, 59,
                   100, 192, 41, 108, 208, 245, 146, 251, 188, 245, 156, 28, 33, 210, 70, 50
        ]);
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn prf_test_input_too_small() {
        let mut input: [u8; 12] = hex!("00010203 04050607 08090a0b");
        let prf = init_prf();

        prf.encrypt_all(&mut input);
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn prf_test_input_not_multiple_of_block_size() {
        let mut input: [u8; 17] = hex!("00010203 04050607 08090a0b ffaadd11 ff");
        let prf = init_prf();

        prf.encrypt_all(&mut input);
    }
}
 
