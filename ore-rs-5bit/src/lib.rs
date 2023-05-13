use std::cell::RefCell;
use primitives::{prf::{Aes128Prf, PrfBlock}, Prf, prp::{KnuthShufflePRP, bitwise::BitwisePrp}, Prp, AesBlock, KnuthShuffleGenerator, PrpGenerator, NewPrp, hash::Aes128Z2Hash, Hash, HashKey};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use zeroize::ZeroizeOnDrop;
use aes::{cipher::generic_array::GenericArray, Aes128};
use cmac::{Cmac, Mac, digest::FixedOutput};

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

#[derive(Debug)]
pub struct Out(Vec<u8>, u8);

// TODO: Include block prefixes
pub fn cmac(key: &[u8; 16], input: &[u8]) -> PrfBlock {
    let mut out: PrfBlock = Default::default();
    let mut buf = GenericArray::from_mut_slice(&mut out);
    // TODO: This might be really inefficient!
    let mut mac = Cmac::<Aes128>::new_from_slice(key).unwrap();
    mac.update(input);
    mac.finalize_into(&mut buf);
    //result.into_bytes().to_vec()
    out
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
    pub fn encrypt_left(&self, input: &[u8]) -> Vec<u8> {
        // TODO: Can we pack the input bytes??
        debug_assert!(input.len() <= 16);
        // TODO: We could possibly use the stack and just do a single extend on to a vec after each round
        // Format: [<u8:number of blocks>, <u8:prp-values>, <Prfblock:prf-values>]
        let mut out: Vec<u8> = Vec::new(); // TODO: What capacity?

        // Here we'll model a PRF using a single block of AES
        // This will be OK for up to 16-bytes of input (or 25 5-bit values)
        // For larger inputs we can chain the values by XORing the last output
        // with the next input (a little like CMAC).
        let mut output_blocks = packed_prefixes(input);
        self.prf2.encrypt_all(&mut output_blocks);
        out.push(output_blocks.len().try_into().unwrap()); // TODO: DOn't unwrap

        // This deviates from the paper slightly.
        // Instead of calling PRF1 with the plaintext prefix, we call it
        // with the output of the PRF2 of the prefix.
        // This avoids a copy and should have the same effect.
        for (output_block, input_block) in output_blocks.iter_mut().zip(input.iter()) {
            let prp: KnuthShufflePRP<u8, 32> = Prp::new(output_block).unwrap(); // TODO:
            let p_n = prp.permute(*input_block).unwrap();
            out.push(p_n);
            output_block[15] = p_n;
        }

        self.prf1.encrypt_all(&mut output_blocks);
        for output_block in output_blocks {
            out.extend_from_slice(&output_block);
        }

        out
    }

    pub fn encrypt(&self, input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut nonce: [u8; 16] = Default::default();
        self.rng.borrow_mut().try_fill(&mut nonce).unwrap();

        // TODO: Can we pack the input bytes??
        debug_assert!(input.len() <= 16);
        // TODO: We could possibly use the stack and just do a single extend on to a vec after each round
        // Format: [<u8:number of blocks>, <u8:prp-values>, <Prfblock:prf-values>]
        let mut left: Vec<u8> = Vec::new(); // TODO: What capacity?
        let mut right: Vec<u8> = Vec::new(); // TODO: What capacity?

        // Here we'll model a PRF using a single block of AES
        // This will be OK for up to 16-bytes of input (or 25 5-bit values)
        // For larger inputs we can chain the values by XORing the last output
        // with the next input (a little like CMAC).
        let mut left_blks = packed_prefixes(input);
        let mut right_blocks: Vec<u32> = Vec::new(); // TODO: Len
        self.prf2.encrypt_all(&mut left_blks);
        left.push(left_blks.len().try_into().unwrap()); // TODO: DOn't unwrap
        right.push(left_blks.len().try_into().unwrap()); // TODO: DOn't unwrap

        // This deviates from the paper slightly.
        // Instead of calling PRF1 with the plaintext prefix, we call it
        // with the output of the PRF2 of the prefix.
        // This avoids a copy and should have the same effect.
        // We also use a mask to set the comparison bits in one constant time
        // operation and then perform a bitwise shuffle using the PRP
        // instead of performing comparisons on each value (which would not be constant time).
        for (out_left_blk, in_blk) in left_blks.iter_mut().zip(input.iter()) {
            let out_right_blk: u32 = 0xFFFFFFFF >> *in_blk;
            let prp: NewPrp<u8, 32> = KnuthShuffleGenerator::new(out_left_blk).generate();
            let p_n = prp.permute(*in_blk);
            out_right_blk.inverse_shuffle(&prp);
            left.push(p_n);
            out_left_blk[15] = p_n;
            right_blocks.push(out_right_blk.inverse_shuffle(&prp));
        }

        self.prf1.encrypt_all(&mut left_blks);

        for output_block in left_blks {
            left.extend_from_slice(&output_block);
            let mut ro_keys: [[u8; 16]; 32] = Default::default();
            
            for (j, ro_key) in ro_keys.iter_mut().enumerate() {
                ro_key.copy_from_slice(&output_block);
                ro_key[15] = j as u8;
            }
            self.prf1.encrypt_all(&mut ro_keys);
            // TODO: Hash all of these keys with the nonce
            // set the bits and and Xor with the right_block
            // Push bytes onto right output vec
            let hasher: Aes128Z2Hash = Hash::new(&nonce.into());
            let blind_block = hasher.hash_all_onto_u32(&ro_keys);
        }




        // TODO: Final XORs

        (left, right)
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
