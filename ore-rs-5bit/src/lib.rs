use std::{cell::RefCell, ops::BitAnd};
use formats::{LeftCiphertext, CipherTextBlock, DataWithHeader, RightCiphertext, CombinedCiphertext, CipherText, LeftCipherTextBlock, RightCipherTextBlock, OreBlockOrd, LeftBlockEq};
use primitives::{prf::Aes128Prf, Prf, prp::bitwise::BitwisePrp, Prp, KnuthShuffleGenerator, PrpGenerator, NewPrp, hash::Aes128Z2Hash, Hash};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use subtle_ng::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;
use aes::cipher::generic_array::GenericArray;
use crate::packing::packed_prefixes;
pub mod packing;

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
#[derive(Debug)]
pub struct OreError;

pub type Ore5BitChaCha20 = Ore5Bit<ChaCha20Rng>;
pub type Ore5BitLeft<'a> = LeftCiphertext<'a, LeftBlock>;
pub type Ore5BitRight<'a> = RightCiphertext<'a, RightBlock>;
pub type Ore5BitCombined<'a> = CombinedCiphertext<'a, LeftBlock, RightBlock>;

#[derive(Debug)]
pub struct LeftBlock([u8; 16], u8);
#[derive(Debug)]
pub struct RightBlock(u32);

impl<'a> CipherTextBlock<'a> for LeftBlock {
    fn byte_size() -> usize {
        17
    }

    fn extend_into(&self, out: &mut DataWithHeader) {
        out.extend_from_slice(&self.0);
        out.extend([self.1]);
    }
}

impl ConstantTimeEq for LeftBlock {
    fn ct_eq(&self, other: &Self) -> subtle_ng::Choice {
        self.0.ct_eq(&other.0).bitand(self.1.ct_eq(&other.1))
    }
}

impl<'a> LeftBlockEq<'a, LeftBlock> for LeftBlock {
    type Other = LeftBlock;

    fn constant_eq(&self, other: &Self) -> subtle_ng::Choice {
        self.ct_eq(other)
    }
}

// TODO: Derive macro?
impl<'a> LeftCipherTextBlock<'a> for LeftBlock {}

impl<'a> OreBlockOrd<'a, RightBlock> for LeftBlock {
    type Other = RightBlock;

    fn ore_compare(&self, right: &RightBlock) -> u8 {
        0
    }
}

impl<'a> RightCipherTextBlock<'a> for RightBlock {}


// TODO: Can we derive macro any of this, too??
impl<'a> CipherTextBlock<'a> for RightBlock {
    fn byte_size() -> usize {
        4
    }

    fn extend_into(&self, out: &mut DataWithHeader) {
        out.extend(self.0.to_be_bytes());
    }
}

/*impl OreBlockOrd<RightBlock> for LeftBlock {
    fn ore_compare(&self, right: &RightBlock) -> bool {
        false
    }
}*/

impl From<&[u8]> for LeftBlock {
    fn from(value: &[u8]) -> Self {
        assert!(value.len() == Self::byte_size());
        let mut buf: [u8; 16] = Default::default();
        buf.copy_from_slice(&value[0..16]);
        LeftBlock(buf, value[16])
    }
}

impl From<&[u8]> for RightBlock {
    fn from(value: &[u8]) -> Self {
        assert!(value.len() == Self::byte_size());
        let mut buf: [u8; 4] = Default::default();
        buf.copy_from_slice(&value[0..4]);
        RightBlock(u32::from_be_bytes(buf))
    }
}

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
        let mut prefixes = packed_prefixes(input);
        self.prf2.encrypt_all(&mut prefixes);

        // This deviates from the paper slightly.
        // Instead of calling PRF1 with the plaintext prefix, we call it
        // with the output of the PRF2 of the prefix.
        // This avoids a copy and should have the same effect.
        // TODO: Change this to use functional callbacks rather than for
        let mut p_ns = vec![];
        for (enc_prefix, in_blk) in prefixes.iter_mut().zip(input.iter()) {
            let prp: NewPrp<u8, 32> = KnuthShuffleGenerator::new(enc_prefix).generate();
            let p_n = prp.permute(*in_blk);
            p_ns.push(p_n);
            enc_prefix[15] = p_n;
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
        let mut right = Ore5BitRight::new(input.len(), &nonce);

        // Here we'll model a PRF using a single block of AES
        // This will be OK for up to 16-bytes of input (or 25 5-bit values)
        // For larger inputs we can chain the values by XORing the last output
        // with the next input (a little like CMAC).
        let mut prefixes = packed_prefixes(input);
        let mut right_blocks: Vec<u32> = Vec::new(); // TODO: Len
        self.prf2.encrypt_all(&mut prefixes);

        // This deviates from the paper slightly.
        // Instead of calling PRF1 with the plaintext prefix, we call it
        // with the output of the PRF2 of the prefix.
        // This avoids a copy and should have the same effect.
        // We also use a mask to set the comparison bits in one constant time
        // operation and then perform a bitwise shuffle using the PRP
        // instead of performing comparisons on each value (which would not be constant time).
        let mut p_ns: Vec<u8> = Vec::with_capacity(input.len());

        for (enc_prefix, in_blk) in prefixes.iter_mut().zip(input.iter()) {
            let out_right_blk: u32 = 0xFFFFFFFF >> *in_blk;
            let prp: NewPrp<u8, 32> = KnuthShuffleGenerator::new(enc_prefix).generate();
            let p_n = prp.permute(*in_blk);
            p_ns.push(p_n);
            enc_prefix[15] = p_n;

            out_right_blk.inverse_shuffle(&prp);
            right_blocks.push(out_right_blk.inverse_shuffle(&prp));
        }

        self.prf1.encrypt_all(&mut prefixes);

        // TODO: This feels a bit janky
        for ((enc_prefix, right_blk), p_n) in prefixes.iter().zip(right_blocks.iter()).zip(p_ns.iter()) {
            //left.add_block(&LeftBlock(*enc_prefix, *p_n));
            let mut ro_keys: [[u8; 16]; 32] = Default::default();
            
            for (j, ro_key) in ro_keys.iter_mut().enumerate() {
                ro_key.copy_from_slice(enc_prefix);
                ro_key[15] = j as u8;
            }
            self.prf1.encrypt_all(&mut ro_keys);
            // TODO: Hash all of these keys with the nonce
            // set the bits and and Xor with the right_block
            // Push bytes onto right output vec
            let hasher: Aes128Z2Hash = Hash::new(&nonce.into());
            let final_right = right_blk ^ hasher.hash_all_onto_u32(&ro_keys);
            //right.add_block(RightBlock(final_right));

            out.add_block(LeftBlock(*enc_prefix, *p_n), RightBlock(final_right));
        }

        out
    }

    // TODO: Do this as a PartialOrd impl (and handle versions)
    // TODO: Handle different length slices. Compare the first n-bytes and if they're equal then the
    // longer value will be more "more-than"
    pub fn compare_slices(a: impl AsRef<[u8]>, b: impl AsRef<[u8]>) -> bool {
        let left: Ore5BitLeft = a.as_ref().try_into().unwrap();
        let combined: Ore5BitCombined = b.as_ref().try_into().unwrap();
        //assert!(left.comparable(&combined)); // TODO: Error
        // TODO: Should this iteration also be constant time?
        // We could make our own iterator type which works in constant time and zips another

        let x = left.compare_blocks(combined.blocks());
        dbg!(x);

        true
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
mod tests {
    use super::*;
}
