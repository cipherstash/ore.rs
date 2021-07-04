
mod aes_prg {
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
}

use aes_prg::*;
use std::convert::TryFrom;

struct Prp {
    permutation: Vec<usize>
}

impl Prp {
    pub fn init(prg: &mut Prng) -> Prp {
        let mut permutation: Vec<usize> = vec![];

        // TODO: Size the vector on create based on domain size of the PRP
        for i in 0..=255 as usize {
            permutation.push(i);
        }

        for elem in 1..permutation.len() {
            let j = prg.next_byte();
            permutation.swap(elem, usize::try_from(j).unwrap());
        }

        Prp { permutation: permutation }
    }

    /* Permutes a number under the Pseudo-Random Permutation.
     * Permution is worst case a linear search in 2^d (where d is the block size)
     *
     * Forward permutations are only used once in the ORE scheme so this is OK
     * */
    pub fn permute(&self, input: usize) -> usize {
        self.permutation.iter().position(|&x| x == input).unwrap()
    }

    /* Performs the inverse permutation. This operation is constant time
     * and is designed that way because there are d (block size) inverse
     * permutations in the ORE scheme */
    pub fn inverse(&self, input: usize) -> usize {
        self.permutation[input]
    }
}

#[cfg(test)]
mod tests {

    use aes::cipher::{
        generic_array::arr,
    };
    use super::*;
    use super::aes_prg::*;

    #[test]
    fn prg_next_byte() {
        let key = arr![u8; 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut prg = Prng::init(&key);
        assert_eq!(219, prg.next_byte());
        assert_eq!(69, prg.next_byte());
    }

    #[test]
    fn init_prp() {
        let key = arr![u8; 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut prg = Prng::init(&key);
        let prp = Prp::init(&mut prg);

        // TODO: Test all numbers in the block
        println!("15 -> {}", prp.permute(15));
        println!("75 -> {}", prp.permute(75));
        assert_eq!(15, prp.inverse(prp.permute(15)));
    }
}

