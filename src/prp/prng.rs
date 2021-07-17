use aes::Aes128;
use aes::cipher::{
    consts::U16,
    BlockEncrypt, NewBlockCipher,
    generic_array::GenericArray,
};
use byteorder::{ByteOrder, BigEndian};

pub struct Prng {
    cipher: Aes128,
    counter: u128,
    data: GenericArray<u8, U16>,
    ptr: usize
}

impl Prng {
    pub fn init(key: &[u8]) -> Prng {
        let key_array = GenericArray::from_slice(key);
        let cipher = Aes128::new(&key_array);
        let mut prng = Prng {
            cipher,
            counter: 0,
            data: Default::default(),
            ptr: 0
        };
        prng.generate();
        return prng;
    }

    fn generate(&mut self) {
        self.ptr = 0;
        BigEndian::write_u128(&mut self.data, self.counter);
        self.cipher.encrypt_block(&mut self.data);
        self.counter += 1;
    }

    /*
     * Generates the next byte of the random number sequence
     */
    pub fn next_byte(&mut self) -> u8 {
        if self.ptr >= 16 { // Use the BlockSize from AES
            self.generate();
        }
        let value: u8 = self.data[self.ptr];
        self.ptr += 1;
        return value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn prg_next_byte() {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");

        let mut prg = Prng::init(&key);
        assert_eq!(198, prg.next_byte());
        assert_eq!(161, prg.next_byte());
        assert_eq!(1, prg.counter);
        assert_eq!(2, prg.ptr);

        for _i in 3..=17 {
          prg.next_byte();
        }
        assert_eq!(2, prg.counter);
        assert_eq!(1, prg.ptr);



    }
}
