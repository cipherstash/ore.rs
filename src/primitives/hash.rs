
use crate::Hash;
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, NewBlockCipher,
    generic_array::GenericArray,
};

pub struct AES128Hash {
    cipher: Aes128
}

impl Hash for AES128Hash {
    fn new(key: &[u8]) -> Self {
        let key_array = GenericArray::from_slice(key);
        let cipher = Aes128::new(&key_array);
        return Self { cipher };
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
        let mut block = GenericArray::from_mut_slice(&mut output);
        self.cipher.encrypt_block(&mut block);
        return output[0] & 1u8;
    }

    fn hash_all(&self, input: &[u8], output: &mut [u8]) {
        // len(output) = Blocksize * len(input) - how to check this at compile time?
        // TODO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn init_hash() -> AES128Hash {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        return Hash::new(&key);
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
