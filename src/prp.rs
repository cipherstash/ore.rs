

pub mod prng;
use prng::Prng;
use std::convert::TryFrom;

// TODO: Use GenericArray so we can do
/*pub struct Prp2<S: ArrayLength<i32>> {
    permutation: GenericArray<u8, S>
}*/

pub struct Prp {
    permutation: Vec<u8>
}

impl Prp { // TODO: Rename to Prp8
    // TODO: Pass the block size as an argument
    // TODO: Add a guard for the block_size
    // Should probably use generics for the block size and make it a bit more robust
    pub fn init(key: &[u8]) -> Prp {
        // TODO: We could possibly use the rust rand library with a fixed seed (i.e. the prp key)
        // to do this instead of the Prng
        let mut prg = Prng::init(&key);
        let mut permutation: Vec<u8> = (0..=255).collect();

        for elem in 1..permutation.len() {
            let j = prg.next_byte();
            permutation.swap(elem, usize::try_from(j).unwrap());
        }

        return Prp { permutation: permutation }
    }

    /* Permutes a number under the Pseudo-Random Permutation.
     * Permution is worst case a linear search in 2^d (where d is the block size)
     *
     * Forward permutations are only used once in the ORE scheme so this is OK
     * */
    pub fn permute(&self, input: u8) -> u8 {
        let position: usize = self.permutation.iter().position(|&x| x == input).unwrap();
        return u8::try_from(position).unwrap();
    }

    /* Performs the inverse permutation. This operation is constant time
     * and is designed that way because there are d (block size) inverse
     * permutations in the ORE scheme */
    pub fn inverse(&self, input: u8) -> u8 {
        let index = usize::try_from(input).unwrap();
        return self.permutation[index];
    }
}

