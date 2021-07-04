
pub mod prng;
use prng::Prng;
use std::convert::TryFrom;

pub struct Prp {
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

