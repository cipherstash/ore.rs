
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, NewBlockCipher,
    generic_array::GenericArray,
};

/* Generates a short hash of the input.
 * Does not modify the input.
 * (uses AES in the Random Oracle model) */
pub fn hash(key: &[u8], input: &[u8]) -> u8 { // TODO: can we use a U3 type?
    let key_array = GenericArray::from_slice(key);
    let cipher = Aes128::new(&key_array);
    // Can we clone into GenericArray directly? Are we doing an extra copy?
    let mut output = [0u8; 16];
    output.clone_from_slice(input);
    let mut block = GenericArray::from_mut_slice(&mut output);
    cipher.encrypt_block(&mut block);
    // Returns only the LSB (useful for 1-bit indicator function)
    //return u128::from(output[0]) & 1u128;
    return output[0] & 1u8;
}

// TODO: Test internal modules internally?
