use crate::primitives::{AesBlock, Hash, HashKey};
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct Aes128Z2Hash {
    cipher: Aes128,
}

impl Hash for Aes128Z2Hash {
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

    // TODO: this mutates - see how much a copy effects performance (clone_from_slice)
    fn hash_all(&self, data: &mut [AesBlock]) -> Vec<u8> {
        self.cipher.encrypt_blocks(data);

        let mut vec = Vec::with_capacity(data.len());
        for &mut block in data {
            // Output is Z2 (1-bit)
            vec.push(block[0] & 1u8);
        }

        vec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn init_hash() -> Aes128Z2Hash {
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
