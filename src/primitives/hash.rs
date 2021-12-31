use crate::primitives::{AesBlock, Hash, HashKey};
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, NewBlockCipher, BlockCipher,
    generic_array::{GenericArray, ArrayLength},
};

type BlockSize = <Aes128 as BlockCipher>::BlockSize;

pub struct AES128Z2Hash {
    cipher: Aes128,
}

impl Hash for AES128Z2Hash {
    fn new(key: &HashKey) -> Self {
        let key_array = GenericArray::from_slice(key);
        let cipher = Aes128::new(key_array);
        Self { cipher }
    }

    fn hash(&self, data: &[u8]) -> u8 {
        /*
         * Slice size is not known at compile time so we assert here
         * We could do this with compile checks but this would require an additional
         * copy (and doesn't entirely avoid runtime checks anyway)
         * See https://stackoverflow.com/questions/38168956/take-slice-of-certain-length-known-at-compile-time
         */
        assert_eq!(data.len(), 16);
        // Can we clone into GenericArray directly? Are we doing an extra copy?
        let mut output = [0u8; 16];
        output.clone_from_slice(data);
        let block = GenericArray::from_mut_slice(&mut output);
        self.cipher.encrypt_block(block);
        output[0] & 1u8
    }

    fn hash_all(&self, data: &mut [u8]) -> Vec<u8> {
        let mut vec = Vec::with_capacity(data.len());
        let mut blocks = to_blocks::<BlockSize>(&mut data[..]);
        self.cipher.encrypt_blocks(blocks);

        // TODO: Use a mapping iterator?
        for &mut block in blocks {
            // Output is Z2 (1-bit)
            vec.push(block[0] & 1u8);
        }

        vec
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

    fn init_hash() -> AES128Z2Hash {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        let key_array = GenericArray::from_slice(&key);
        Hash::new(key_array)
    }

    #[test]
    fn hash_test_1() {
        let hash = init_hash();
        let input: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0eaa");

        assert_eq!(1u8, hash.hash(&input));
    }

    #[test]
    fn hash_test_2() {
        let hash = init_hash();
        let input: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");

        assert_eq!(0u8, hash.hash(&input));
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn hash_test_input_too_small() {
        let hash = init_hash();
        let input: [u8; 8] = hex!("00010203 04050607");

        assert_eq!(0u8, hash.hash(&input));
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn hash_test_input_too_large() {
        let hash = init_hash();
        let input: [u8; 24] = hex!("00010203 04050607 ffffffff bbbbbbbb cccccccc abababab");

        hash.hash(&input);
    }
}
