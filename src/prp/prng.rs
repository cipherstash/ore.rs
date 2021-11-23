use aes::Aes128;
use aes::cipher::{
    consts::U16,
    BlockEncrypt, NewBlockCipher,
    generic_array::GenericArray,
};

pub struct Prng {
    cipher: Aes128,
    data: [GenericArray<u8, U16>; 16],
    ptr: (usize, usize)
}

/* 
 * To aid in performance this PRNG can only generate 256 random numbers
 * before it panics. Should _only_ be used inside the PRP.
 * FIXME: Roll this into the PRP implementation so it can't be abused!
 */
impl Prng {
    pub fn init(key: &[u8]) -> Prng {
        let key_array = GenericArray::from_slice(key);
        let cipher = Aes128::new(&key_array);
        let mut prng = Prng {
            cipher,
            data: Default::default(),
            ptr: (0, 0)
        };
        prng.generate();
        return prng;
    }

    /*
     * Generates the next byte of the random number sequence.
     */
    pub fn next_byte(&mut self) -> u8 {
        let value: u8 = self.data[self.ptr.0][self.ptr.1];
        self.inc_ptr();
        return value;
    }

    fn generate(&mut self) {
        self.ptr = (0, 0);
        for i in 0..16 {
            self.data[i][0] = i as u8;
        }
        self.cipher.encrypt_blocks(&mut self.data[0..8]);
        self.cipher.encrypt_blocks(&mut self.data[8..16]);
    }

    #[inline]
    fn inc_ptr(&mut self) {
        if self.ptr.1 < 15 {
            self.ptr.1 += 1;
        } else {
            self.ptr.1 = 0;
            self.ptr.0 += 1;
        }
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

        for _i in 3..=255 {
          prg.next_byte();
        }
        assert_eq!((15, 15), prg.ptr);
    }
}
