
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
pub fn hash(key: &[u8], input: &[u8]) -> u8 {
    /*
     * Slice size is not known at compile time so we assert here
     * We could do this with compile checks but this would require an additional
     * copy (and doesn't entirely avoid runtime checks anyway)
     * See https://stackoverflow.com/questions/38168956/take-slice-of-certain-length-known-at-compile-time
    */
    assert_eq!(input.len(), 16);
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

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn hash_test_input_too_small() {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        let input: [u8; 8] = hex!("00010203 04050607");

        assert_eq!(0u8, hash(&key, &input));
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn hash_test_input_too_large() {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        let input: [u8; 24] = hex!("00010203 04050607 ffffffff bbbbbbbb cccccccc abababab");

        assert_eq!(0u8, hash(&key, &input));
    }
}
