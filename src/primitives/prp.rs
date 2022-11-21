pub mod prng;
use crate::primitives::prp::prng::AES128PRNG;
use crate::primitives::{PRPError, PRPResult, Prp};
use std::convert::TryFrom;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize)]
pub struct KnuthShufflePRP<T: Zeroize, const N: usize> {
    permutation: [T; N],
    inverse: [T; N],
}

// For some reason ZeroizeOnDrop doesn't work - so manually do it
impl<T: Zeroize, const N: usize> Drop for KnuthShufflePRP<T, N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

fn cmp(a: u8, b: u8) -> u8 {
    if a > b {
        1u8
    } else {
        0u8
    }
}

// FIXME: To get this right, we need to change the "Left" type to be a Vec
pub(crate) fn block_shuffle(key: &[u8], forward_target: u8) -> (u8, Vec<u8>) {
    let mut input = [0u8; 256];
    for i in 0..=255 {
        input[i] = i as u8;
    }

    // 96 is the number of pre-generated AES blocks
    // Performance tuned to minimize the need for regeneration
    let mut rng: AES128PRNG<96> = AES128PRNG::init(key); // TODO: Use Result type here, too

    (0..=255usize).into_iter().rev().for_each(|i| {
        let j = rng.gen_range(i as u8);
        input.swap(i, j as usize);
    });

    let block: Vec<u8> = input.chunks(8).map(|chunk| {
        let mut out: u8 = 0;
        // Build a u8
        for &jstar in chunk[1..].iter().rev() {
            out |= cmp(jstar, forward_target);
            out <<= 1;
        }
        out | cmp(chunk[0], forward_target)
    }).collect();

    let mut forward_permuted = None;
    for (index, val) in input.iter().enumerate() {
        match forward_permuted {
            None => {
                if (*val as u8) == forward_target {
                    forward_permuted = Some(index as u8)
                }
            },
            _ => ()
        };
    }

    input.zeroize();
        
    (forward_permuted.unwrap(), block)
}

// Impl the ZeroizeOnDrop marker trait since we're zeroizing above
impl<T: Zeroize, const N: usize> ZeroizeOnDrop for KnuthShufflePRP<T, N> {}

impl Prp<u8> for KnuthShufflePRP<u8, 256> {
    /*
     * Initialize an 8-bit (256 element) PRP using a KnuthShuffle
     * and a 64-bit random seed
     */
    fn new(key: &[u8]) -> PRPResult<Self> {
        let mut rng: AES128PRNG<32> = AES128PRNG::init(key); // TODO: Use Result type here, too

        let mut perm = Self {
            permutation: [0u8; 256],
            inverse: [0u8; 256],
        };

        // Initialize values
        for i in 0..=255 {
            perm.permutation[i] = i as u8;
        }

        (0..=255usize).into_iter().rev().for_each(|i| {
            let j = rng.gen_range(i as u8);
            perm.permutation.swap(i, j as usize);
        });

        for (index, val) in perm.permutation.iter().enumerate() {
            perm.inverse[*val as usize] = index as u8;
        }

        Ok(perm)
    }

    /*
     * Permutes a number under the Pseudo-Random Permutation in constant time.
     *
     * Forward permutations are only used once in the ORE scheme so this is OK
     */
    fn permute(&self, input: u8) -> PRPResult<u8> {
        let index = usize::try_from(input).map_err(|_| PRPError)?;

        match self.inverse.get(index) {
            Some(i) => Ok(*i),
            None => Err(PRPError),
        }
    }

    /*
     * Performs the inverse permutation in constant time.
     */
    fn invert(&self, input: u8) -> PRPResult<u8> {
        let index = usize::try_from(input).map_err(|_| PRPError)?;

        // Forward an inverse permutations are reversed for historical reasons
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
        Prp::new(&key)
    }

    #[test]
    /*fn test_block_shuffle() -> Result<(), PRPError> {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0eaa");  

        // TODO: Test all values
        let (permuted, _) = block_shuffle(&key, 10);
        assert_eq!(10, input[permuted as usize]);

        Ok(())
    }*/

    #[test]
    fn test_invert() -> Result<(), PRPError> {
        let prp = init_prp()?;

        for i in 0..=255 {
            assert_eq!(
                i,
                prp.invert(prp.permute(i)?)?,
                "permutation round-trip failed"
            );
        }

        Ok(())
    }
}
