use std::{cell::RefCell, ops::{BitAnd, BitXor, BitXorAssign}, cmp::Ordering};
use formats::{LeftCiphertext, CipherTextBlock, DataWithHeader, RightCiphertext, CombinedCiphertext, CipherText, LeftCipherTextBlock, RightCipherTextBlock, OreBlockOrd, LeftBlockEq};
use left_block::LeftBlock;
use primitives::{prf::Aes128Prf, Prf, prp::bitwise::BitwisePrp, Prp, KnuthShuffleGenerator, PrpGenerator, NewPrp, hash::Aes128Z2Hash, Hash};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use right_block::RightBlock;
use subtle_ng::{ConstantTimeEq, Choice};
use zeroize::ZeroizeOnDrop;
use aes::cipher::generic_array::GenericArray;
use crate::packing::prefixes;
pub mod packing;
mod right_block;
mod left_block;

#[derive(Debug, ZeroizeOnDrop)]
pub struct Ore5Bit<R: Rng + SeedableRng> {
    // TODO: Temp
    k2: [u8; 16],

    prf1: Aes128Prf,
    prf2: Aes128Prf,
    #[zeroize(skip)]
    rng: RefCell<R>,
}

// TODO: use a trait type
/// This type is deliberately opaque as to avoid potential side-channel leakage.
#[derive(Debug)]
pub struct OreError;

pub type Ore5BitChaCha20 = Ore5Bit<ChaCha20Rng>;
pub type Ore5BitLeft<'a> = LeftCiphertext<'a, LeftBlock>;
pub type Ore5BitRight<'a> = RightCiphertext<'a, RightBlock>;
pub type Ore5BitCombined<'a> = CombinedCiphertext<'a, LeftBlock, RightBlock>;



// TODO: Make this use the ORE traits once we've cleaned these up
impl<R: Rng + SeedableRng> Ore5Bit<R> {
    // TODO: This should be an implementation of OreInit
    pub fn init(k1: &[u8; 16], k2: &[u8; 16]) -> Result<Self, OreError> {
        // TODO: k1 and k2 should be Key types and we should have a set of traits to abstract the
        // behaviour ro parsing/loading etc

        let rng: R = SeedableRng::from_entropy();

        return Ok(Self {
            k2: k2.clone(),
            prf1: Prf::new(GenericArray::from_slice(k1)),
            prf2: Prf::new(GenericArray::from_slice(k2)),
            rng: RefCell::new(rng),
        });
    }

    /// Takes a slice of 5-bit values (represented by a slice of `u8` but the
    /// most significant 3-bits of each value are ignored).
    /// TODO: Create a wrapper type
    /// TODO: This might be faster if we do it blocks of statically allocated chunks
    pub fn encrypt_left(&self, input: &[u8]) -> Ore5BitLeft {
        // We're limited to 16 input blocks for now because we're using AES as the PRF (1 block)
        debug_assert!(input.len() <= 16);
        let mut out = Ore5BitLeft::new(input.len());

        // Here we'll model a PRF using a single block of AES
        // This will be OK for up to 16-bytes of input (or 25 5-bit values)
        // For larger inputs we can chain the values by XORing the last output
        // with the next input (a little like CMAC).
        let mut prefixes = prefixes(input);

        self.prf2.encrypt_all(&mut prefixes);

        // This deviates from the paper slightly.
        // Instead of calling PRF1 with the plaintext prefix, we call it
        // with the output of the PRF2 of the prefix.
        // This avoids a copy and should have the same effect.
        // TODO: Change this to use functional callbacks rather than for
        let mut p_ns = vec![];

        for (n, in_blk) in input.iter().enumerate() {
            let prp: NewPrp<u8, 32> = KnuthShuffleGenerator::new(&prefixes[n]).generate();
            let p_n = prp.permute(*in_blk);
            p_ns.push(p_n);

            prefixes[n].iter_mut().for_each(|x| *x = 0);
            prefixes[n][0..n].clone_from_slice(&input[0..n]);
            prefixes[n][n] = p_n;
            prefixes[n][15] = n as u8;
        }

        self.prf1.encrypt_all(&mut prefixes);

        for (prf_block, permuted) in prefixes.iter().zip(p_ns.iter()) {
            out.add_block(LeftBlock(*prf_block, *permuted));
        }

        out
    }

    pub fn encrypt(&self, input: &[u8]) -> Ore5BitCombined {
        let mut nonce: [u8; 16] = Default::default();
        self.rng.borrow_mut().try_fill(&mut nonce).unwrap();

        // TODO: Can we pack the input bytes??
        debug_assert!(input.len() <= 16);
        let mut out = Ore5BitCombined::new(input.len(), &nonce);

        // Here we'll model a PRF using a single block of AES
        // This will be OK for up to 16-bytes of input (or 25 5-bit values)
        // For larger inputs we can chain the values by XORing the last output
        // with the next input (a little like CMAC).
        let mut prefixes = prefixes(input);
        let mut right_blocks: Vec<RightBlock> = Vec::with_capacity(input.len());
        self.prf2.encrypt_all(&mut prefixes);

        // This deviates from the paper slightly.
        // Instead of calling PRF1 with the plaintext prefix, we call it
        // with the output of the PRF2 of the prefix.
        // This avoids a copy and should have the same effect.
        // We also use a mask to set the comparison bits in one constant time
        // operation and then perform a bitwise shuffle using the PRP
        // instead of performing comparisons on each value (which would not be constant time).
        let mut p_ns: Vec<u8> = Vec::with_capacity(input.len());

        for (n, in_blk) in input.iter().enumerate() {
            let prp: NewPrp<u8, 32> = KnuthShuffleGenerator::new(&prefixes[n]).generate();
            let p_n = prp.permute(*in_blk);
            p_ns.push(p_n);

            prefixes[n].iter_mut().for_each(|x| *x = 0);
            prefixes[n][0..n].clone_from_slice(&input[0..n]);
            prefixes[n][n] = p_n;
            prefixes[n][15] = n as u8;


            // encrypt_left and encrypt functions are identical, except that we have this encrypt right block stuff in the middle
            let mut right_blk = RightBlock::init(*in_blk).shuffle(&prp);

            // TODO: Use the same approach here as we do in the original implementation
            let mut ro_keys: [[u8; 16]; 32] = Default::default();
            
            for (j, ro_key) in ro_keys.iter_mut().enumerate() {
                ro_key[0..n].copy_from_slice(&input[0..n]);
                ro_key[n] = j as u8;
            }

            self.prf1.encrypt_all(&mut ro_keys);

            // TODO: Hash all of these keys with the nonce
            // set the bits and and Xor with the right_block
            // Push bytes onto right output vec
            let hasher: Aes128Z2Hash = Hash::new(&nonce.into());
            // TODO: Hash all onto could be generic (right block)
            // A RightBlock is like an "indicator set"
            let mask = hasher.hash_all_onto_u32(&ro_keys);

            right_blk ^= mask;

            right_blocks.push(right_blk);

        }

        self.prf1.encrypt_all(&mut prefixes);

        for ((left, p_n), right) in prefixes.into_iter().zip(p_ns.into_iter()).zip(right_blocks.into_iter()) {
            out.add_block(LeftBlock(left, p_n), right);
        }

        out
    }

    // TODO: Do this as a PartialOrd impl (and handle versions)
    // TODO: Handle different length slices. Compare the first n-bytes and if they're equal then the
    // longer value will be more "more-than"
    pub fn compare_slices(a: impl AsRef<[u8]>, b: impl AsRef<[u8]>) -> i8 {
        let left: Ore5BitLeft = a.as_ref().try_into().unwrap();
        let combined: Ore5BitCombined = b.as_ref().try_into().unwrap();
        //assert!(left.comparable(&combined)); // TODO: Error

        // With most of the work now in the LeftCipherText and the block types, this
        // could be a default implementation in the main trait
        left.compare_blocks(combined.nonce(), combined.blocks())
    }

    // For the right encryption we could either use the approach that we do in the current version,
    // or instead of doing a comparison of every number, we set all bits >= the input to 1 and then do
    // a bitwise permutation.
    // Current approach:
    // - Permute
    // - Traverse permutation
    // - N comparisons (which may not be constant time!)
    // - N bit sets (left shift, or)
    // Proposed approach:
    // - Set all bits to one (>= the plaintext)
    // - Bitwise permute: N bit get, N bit set (we avoid the comparisons!)
}

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

#[cfg(test)]
mod tests {
    use quickcheck::{Arbitrary, QuickCheck};
    use super::*;

    type ORE = Ore5BitChaCha20;

    // TODO: Can we make these a macro so that we can reuse for every scheme?

    fn init_ore() -> Result<ORE, OreError> {
        let mut k1: [u8; 16] = Default::default();
        let mut k2: [u8; 16] = Default::default();

        let mut rng = ChaCha20Rng::from_entropy();

        rng.fill(&mut k1);
        rng.fill(&mut k2);

        // TODO: This will work when have the trait setup correctly
        //OreCipher::init(&k1, &k2).unwrap()
        Ore5BitChaCha20::init(&k1, &k2)
    }

    #[test]
    fn test_single_block_eq() -> Result<(), OreError> {
        let a = vec![10];
        let ore = init_ore()?;
        let left = ore.encrypt_left(&a);
        let combined = ore.encrypt(&a);

        assert_eq!(ORE::compare_slices(&left, &combined), 0);
        Ok(())
    }

    #[test]
    fn test_single_block_lt() -> Result<(), OreError> {
        let a = vec![10];
        let b = vec![29];
        let ore = init_ore()?;
        let left = ore.encrypt_left(&a);
        let combined = ore.encrypt(&b);

        assert_eq!(ORE::compare_slices(&left, &combined), -1);

        Ok(())
    }

    #[test]
    fn test_single_block_gt() -> Result<(), OreError> {
        let a = vec![11];
        let b = vec![0];
        let ore = init_ore()?;
        let left = ore.encrypt_left(&a);
        let combined = ore.encrypt(&b);

        assert_eq!(ORE::compare_slices(&left, &combined), 1);

        Ok(())
    }

    #[test]
    fn test_empty_lt() -> Result<(), OreError> {
        let a = vec![];
        let b = vec![0];
        let ore = init_ore()?;
        let left = ore.encrypt_left(&a);
        let combined = ore.encrypt(&b);

        assert_eq!(ORE::compare_slices(&left, &combined), -1);

        Ok(())
    }

    #[test]
    fn test_empty_gt() -> Result<(), OreError> {
        let a = vec![0];
        let b = vec![];
        let ore = init_ore()?;
        let left = ore.encrypt_left(&a);
        let combined = ore.encrypt(&b);

        assert_eq!(ORE::compare_slices(&left, &combined), 1);

        Ok(())
    }

    #[test]
    fn test_uneven_common_prefix_gt() -> Result<(), OreError> {
        let a = vec![10, 15];
        let b = vec![10];
        let ore = init_ore()?;
        let left = ore.encrypt_left(&a);
        let combined = ore.encrypt(&b);

        assert_eq!(ORE::compare_slices(&left, &combined), 1);

        Ok(())
    }

    #[test]
    fn test_uneven_gt() -> Result<(), OreError> {
        let a = vec![10];
        let b = vec![7, 20];
        let ore = init_ore()?;
        let left = ore.encrypt_left(&a);
        let combined = ore.encrypt(&b);

        assert_eq!(ORE::compare_slices(&left, &combined), 1);

        Ok(())
    }

    #[test]
    fn test_uneven_common_prefix_lt() -> Result<(), OreError> {
        let a = vec![10];
        let b = vec![10, 15];
        let ore = init_ore()?;
        let left = ore.encrypt_left(&a);
        let combined = ore.encrypt(&b);

        assert_eq!(ORE::compare_slices(&left, &combined), -1);

        Ok(())
    }

    #[test]
    fn test_uneven_lt() -> Result<(), OreError> {
        let a = vec![10, 20];
        let b = vec![27];
        let ore = init_ore()?;
        let left = ore.encrypt_left(&a);
        let combined = ore.encrypt(&b);

        assert_eq!(ORE::compare_slices(&left, &combined), -1);

        Ok(())
    }

    #[derive(Debug, Copy, Clone, PartialEq)]
    struct U5(u8);

    impl Arbitrary for U5 {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            loop {
                let v: u8 = Arbitrary::arbitrary(g);

                if v <= 31 {
                    return Self(v)
                }

            }
        }
    }

    impl PartialOrd for U5 {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            self.0.partial_cmp(&other.0)
        }
    }

    #[test]
    fn test_quick() {
        fn single_elem(a: U5, b: U5) -> bool {
            let ore = init_ore().unwrap();
            let ax = [a.0];
            let bx = [b.0];
            let left = ore.encrypt_left(&ax);
            let combined = ore.encrypt(&bx);

            match ORE::compare_slices(&left, &combined) {
                -1 => a < b,
                0 => a == b,
                1 => a > b,
                _ => panic!()
            }
        }

        QuickCheck::new().max_tests(1000).quickcheck(single_elem as fn(U5, U5) -> bool)
    }

    /*#[test]
    fn test_quick2() {
        fn multiple_elems(a: Vec<U5>, b: Vec<U5>) -> bool {
            let ax: Vec<u8> = a.into_iter().map(|U5(x)| x).collect();
            let bx: Vec<u8> = b.into_iter().map(|U5(x)| x).collect();
            let ore = init_ore().unwrap();
            let left = ore.encrypt_left(&ax);
            let combined = ore.encrypt(&bx);

            match ORE::compare_slices(&left, &combined) {
                Ordering::Less => ax < bx,
                Ordering::Equal => ax == bx,
                Ordering::Greater => ax > bx
            }
        }

        QuickCheck::new().max_tests(1).quickcheck(multiple_elems as fn(Vec<U5>, Vec<U5>) -> bool)
    }*/
}
