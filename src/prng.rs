use aes::{Aes128};
use aes::cipher::{
    BlockEncrypt, NewBlockCipher,
    generic_array::{GenericArray},
};

pub struct Prng {
    cipher: Aes128,
    counter: u8
}

impl Prng {
    pub fn init(key: &[u8]) -> Prng {
        let key_array = GenericArray::from_slice(key);
        let cipher = Aes128::new(&key_array);
        return Prng { cipher, counter: 0 };
    }

    /*
     * Notes:
     *
     * use std::mem::transmute;
     let bytes: [u8; 4] = unsafe { transmute(123u32.to_be()) }; // or .to_le()

     or use https://docs.rs/byteorder/1.4.3/byteorder/
     */

    pub fn next_byte(&mut self) -> u8 {

        // FIXME: We can't handle if counter > 255
        let mut data: Vec<u8> = vec![self.counter, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut block = GenericArray::from_mut_slice(&mut data);
        self.cipher.encrypt_block(&mut block);
        self.counter += 1;
        return block[0];
    }
}
