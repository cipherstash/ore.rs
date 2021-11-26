
pub mod prng;
use crate::primitives::{PRP, SEED64};
use crate::primitives::prp::prng::AES128PRNG;
use std::convert::TryFrom;

pub struct KnuthShufflePRP<T, const N: usize> {
    permutation: Vec<T>
}

impl PRP<u8> for KnuthShufflePRP<u8, 256> {
    /*
     * Initialize an 8-bit (256 element) PRP using a KnuthShuffle
     * and a 64-bit random seed
     */
    fn new(key: &[u8], seed: &SEED64) -> Self {
        let mut prg = AES128PRNG::init(&key, &seed);
        let mut permutation: Vec<u8> = (0..=255).collect();

        for elem in 0..permutation.len() {
            let j = prg.next_byte();
            permutation.swap(elem, usize::try_from(j).unwrap());
        }

        return Self { permutation: permutation }
    }

    /*
     * Permutes a number under the Pseudo-Random Permutation.
     * Permution is worst case a linear search in 2^d (where d is the block size)
     *
     * Forward permutations are only used once in the ORE scheme so this is OK
     */
    fn permute(&self, input: u8) -> u8 {
        // TODO: Don't use unwrap
        let position: usize = self.permutation.iter().position(|&x| x == input).unwrap();
        // TODO: Use as
        return u8::try_from(position).unwrap();
    }

    /* Performs the inverse permutation. This operation is constant time
     * and is designed that way because there are d (block size) inverse
     * permutations in the ORE scheme */
    fn invert(&self, input: u8) -> u8 {
        // TODO use 'as'
        let index = usize::try_from(input).unwrap();
        return self.permutation[index];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn init_prp() -> KnuthShufflePRP<u8, 256> {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0eaa");
        let seed: [u8; 8] = hex!("00010203 04050607");
        return PRP::new(&key, &seed);
    }

    #[test]
    fn test_invert() {
        let prp = init_prp();

        for i in 0..255 {
          assert_eq!(i, prp.invert(prp.permute(i)));
        }
    }
}

