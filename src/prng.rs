use aes::{Aes128};
use aes::cipher::{
    BlockEncrypt, NewBlockCipher,
    generic_array::{GenericArray},
};
use byteorder::{ByteOrder, BigEndian};

pub struct Prng {
    cipher: Aes128,
    counter: u128
}

impl Prng {
    pub fn init(key: &[u8]) -> Prng {
        let key_array = GenericArray::from_slice(key);
        let cipher = Aes128::new(&key_array);
        return Prng { cipher, counter: 0 };
    }

    /*
     * Generates the next byte of the random number sequence
     */
    pub fn next_byte(&mut self) -> u8 {
        let mut buf = [0u8; 16];
        BigEndian::write_u128(&mut buf, self.counter);

        // TODO: Keep the block so we don't have to do another AES encryption every time
        let mut block = GenericArray::from_mut_slice(&mut buf);
        self.cipher.encrypt_block(&mut block);
        self.counter += 1;
        return block[0];
    }
}
