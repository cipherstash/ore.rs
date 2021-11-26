use aes::Aes128;
use aes::cipher::{
    consts::U16,
    BlockEncrypt, NewBlockCipher,
    generic_array::GenericArray,
};

pub struct Prng {
    cipher: Aes128,
    data: [GenericArray<u8, U16>; 16],
    ptr: (usize, usize),
    seed: [u8; 8]
}

/* 
 * To aid in performance this PRNG can only generate 256 random numbers
 * before it panics. Should _only_ be used inside the PRP.
 */
// TODO: Rename this
impl Prng {
    pub fn init(key: &[u8], seed: &[u8; 8]) -> Prng {
        let key_array = GenericArray::from_slice(key);
        let cipher = Aes128::new(&key_array);
        let mut prng = Prng {
            cipher,
            data: Default::default(),
            ptr: (0, 0),
            seed: *seed
        };
        prng.generate();
        return prng;
    }

    /*
     * Generates the next byte of the random number sequence.
     */
    pub fn next_byte(&mut self) -> u8 {
        debug_assert!(self.ptr.0 < 16 && self.ptr.1 < 16);
        let value: u8 = self.data[self.ptr.0][self.ptr.1];
        self.inc_ptr();
        return value;
    }

    fn generate(&mut self) {
        self.ptr = (0, 0);
        for i in 0..16 {
            self.data[i][0] = i as u8;

            // Random seed (we do it this way because GenericArray is a bit shit)
            self.data[i][8]  = self.seed[0];
            self.data[i][9]  = self.seed[1];
            self.data[i][10] = self.seed[2];
            self.data[i][11] = self.seed[3];
            self.data[i][12] = self.seed[4];
            self.data[i][13] = self.seed[5];
            self.data[i][14] = self.seed[6];
            self.data[i][15] = self.seed[7];
        }
        self.cipher.encrypt_blocks(&mut self.data);
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

    fn init_prng() -> Prng {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        let seed: [u8; 8] = hex!("00010203 04050607");

        return Prng::init(&key, &seed);
    }

    #[test]
    fn prg_next_byte() {
        let mut prg = init_prng();
        assert_eq!(244, prg.next_byte());
        assert_eq!(39, prg.next_byte());

        for _i in 3..=255 {
          prg.next_byte();
        }
        assert_eq!((15, 15), prg.ptr);
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn prg_entropy_exceeded() {
        let mut prg = init_prng();

        /* Ask for one more byte than is available */
        for _i in 0..=256 {
          prg.next_byte();
        }
    }
}
