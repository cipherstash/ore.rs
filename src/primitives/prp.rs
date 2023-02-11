pub mod prng;
use crate::primitives::prp::prng::Aes128Prng;
use crate::primitives::{Prp, PrpError, PrpResult};
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

// Impl the ZeroizeOnDrop marker trait since we're zeroizing above
impl<T: Zeroize, const N: usize> ZeroizeOnDrop for KnuthShufflePRP<T, N> {}

impl Prp<u8> for KnuthShufflePRP<u8, 256> {
    /*
     * Initialize an 8-bit (256 element) PRP using a KnuthShuffle
     * and a 64-bit random seed
     */
    fn new(key: &[u8]) -> PrpResult<Self> {
        let mut rng = Aes128Prng::init(key); // TODO: Use Result type here, too

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
    fn permute(&self, input: u8) -> PrpResult<u8> {
        let index = usize::try_from(input).map_err(|_| PrpError)?;

        match self.inverse.get(index) {
            Some(i) => Ok(*i),
            None => Err(PrpError),
        }
    }

    /*
     * Performs the inverse permutation in constant time.
     */
    fn invert(&self, input: u8) -> PrpResult<u8> {
        let index = usize::try_from(input).map_err(|_| PrpError)?;

        // Forward an inverse permutations are reversed for historical reasons
        match self.permutation.get(index) {
            Some(i) => Ok(*i),
            None => Err(PrpError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn init_prp() -> PrpResult<KnuthShufflePRP<u8, 256>> {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0eaa");
        Prp::new(&key)
    }

    #[test]
    fn test_invert() -> Result<(), PrpError> {
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
