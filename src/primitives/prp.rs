pub mod prng;
use crate::primitives::prp::prng::AES128PRNG;
use crate::primitives::{PRPError, PRPResult, Prp, SEED64};
use std::convert::TryFrom;

pub struct KnuthShufflePRP<T, const N: usize> {
    permutation: Vec<T>,
}

fn const_position(input: &[u8], val: u8) -> Option<usize> {
    let mut position = None;

    for (index, elem) in input.iter().enumerate() {
        if *elem == val && position == None {
            position = Some(index);
        }
    }

    position
}

impl Prp<u8> for KnuthShufflePRP<u8, 256> {
    /*
     * Initialize an 8-bit (256 element) PRP using a KnuthShuffle
     * and a 64-bit random seed
     */
    fn new(key: &[u8], seed: &SEED64) -> PRPResult<Self> {
        let mut prg = AES128PRNG::init(key, seed); // TODO: Use Result type here, too
        let mut permutation: Vec<u8> = (0..=255).collect();

        for elem in 0..permutation.len() {
            let j = prg.next_byte();
            permutation.swap(elem, usize::try_from(j).map_err(|_| PRPError)?);
        }

        Ok(Self { permutation })
    }

    /*
     * Permutes a number under the Pseudo-Random Permutation.
     * Permution is worst case a linear search in 2^d (where d is the block size)
     *
     * Forward permutations are only used once in the ORE scheme so this is OK
     */
    fn permute(&self, input: u8) -> PRPResult<u8> {
        let u = const_position(&self.permutation, input).ok_or(PRPError)?;

        u8::try_from(u).map_err(|_| PRPError)
    }

    /* Performs the inverse permutation. This operation is constant time
     * and is designed that way because there are d (block size) inverse
     * permutations in the ORE scheme */
    fn invert(&self, input: u8) -> PRPResult<u8> {
        let index = usize::try_from(input).map_err(|_| PRPError)?;

        match self.permutation.get(index) {
            Some(i) => Ok(*i),
            None => Err(PRPError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn init_prp() -> PRPResult<KnuthShufflePRP<u8, 256>> {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0eaa");
        let seed: [u8; 8] = hex!("00010203 04050607");
        Prp::new(&key, &seed)
    }

    #[test]
    fn test_invert() -> Result<(), PRPError> {
        let prp = init_prp()?;

        for i in 0..255 {
            assert_eq!(i, prp.invert(prp.permute(i)?)?);
        }

        Ok(())
    }
}
