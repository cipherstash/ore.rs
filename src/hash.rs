
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, NewBlockCipher,
    generic_array::GenericArray,
};

/* 
 * Generates a short hash of the input.
 * Does not modify the input.
 * (uses AES in the Random Oracle model).
 * Returns only the LSB (useful for 1-bit indicator function).
 */
// FIXME: The input should be exactly 16-bytes long (or technically the ORE block size)
pub fn hash(key: &[u8], input: &[u8]) -> u8 {
    let key_array = GenericArray::from_slice(key);
    let cipher = Aes128::new(&key_array);
    // Can we clone into GenericArray directly? Are we doing an extra copy?
    let mut output = [0u8; 16];
    output.clone_from_slice(input);
    let mut block = GenericArray::from_mut_slice(&mut output);
    cipher.encrypt_block(&mut block);
    return output[0] & 1u8;
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn hash_test_1() {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        let input: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0eaa");

        assert_eq!(1u8, hash(&key, &input));
    }

    #[test]
    fn hash_test_2() {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        let input: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");

        assert_eq!(0u8, hash(&key, &input));
    }
}
