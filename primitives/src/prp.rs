pub mod prng;
pub mod bitwise;
use crate::prp::prng::Aes128Prng;
use crate::{Prp, PrpError, PrpResult};
use std::convert::TryFrom;
use std::iter::Enumerate;
use std::slice::Iter;
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

// TODO: This would make more sense if we defined PRP as a generator
impl <const N: usize> Prp<u8> for KnuthShufflePRP<u8, N> {
    /*
     * Initialize an 8-bit (N element) PRP using a KnuthShuffle
     */
    fn new(key: &[u8]) -> PrpResult<Self> {
        assert!(N <= 256);
        let mut rng = Aes128Prng::init(key); // TODO: Use Result type here, too

        let mut perm = Self {
            permutation: [0u8; N],
            inverse: [0u8; N],
        };

        // Initialize values
        for i in 0..N {
            perm.permutation[i] = i as u8;
        }

        (0..N).into_iter().rev().for_each(|i| {
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

    fn enumerate(&self) -> Enumerate<Iter<u8>> {
        self.permutation.iter().enumerate()
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