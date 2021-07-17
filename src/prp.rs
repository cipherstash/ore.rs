

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

// TODO: Review https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
// We probably want to use Sattolo's Algorithm because if PRP(x) = x that could reveal information
// in the ORE scheme (e.g. if the first k bytes of the plaintext are the same).
impl Prp { // TODO: Rename to Prp8
    // TODO: Pass the block size as an argument
    // TODO: Add a guard for the block_size
    // Should probably use generics for the block size and make it a bit more robust
    pub fn init(key: &[u8]) -> Prp {
        // TODO: We could possibly use the rust rand library with a fixed seed (i.e. the prp key)
        // to do this instead of the Prng
        let mut prg = Prng::init(&key);
        let mut permutation: Vec<u8> = (0..=255).collect();

        for elem in 0..permutation.len() {
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
        // TODO: Use as
        return u8::try_from(position).unwrap();
    }

    /* Performs the inverse permutation. This operation is constant time
     * and is designed that way because there are d (block size) inverse
     * permutations in the ORE scheme */
    pub fn inverse(&self, input: u8) -> u8 {
        // TODO use 'as'
        let index = usize::try_from(input).unwrap();
        return self.permutation[index];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn init_prp() {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        let prp = Prp::init(&key);

        // TODO: Test all numbers in the block (prop tests?)
        println!("15 -> {}", prp.permute(15));
        println!("75 -> {}", prp.permute(75));
        assert_eq!(15, prp.inverse(prp.permute(15)));
        assert_ne!(0, prp.permute(0));
    }
}
