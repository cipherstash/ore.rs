pub mod hash;
pub mod prf;
pub mod prp;

use std::iter::Enumerate;
use std::slice::Iter;

use aes::cipher::{consts::U16, generic_array::GenericArray};
use aes::Block;
use hash::HashBlock;
use prf::PrfBlock;
use thiserror::Error;
use zeroize::Zeroize;

use crate::prp::prng::Aes128Prng;
pub type AesBlock = Block;
pub type PrfKey = GenericArray<u8, U16>;
pub type HashKey = GenericArray<u8, U16>;
pub const NONCE_SIZE: usize = 16;

pub trait Prf {
    fn new(key: &PrfKey) -> Self;
    fn encrypt_all(&self, data: &mut [PrfBlock]);
}

pub trait Hash {
    fn new(key: &HashKey) -> Self;
    fn hash(&self, data: &[u8]) -> u8;
    fn hash_all(&self, input: &mut [HashBlock]) -> Vec<u8>;
}

#[derive(Debug, Error)]
#[error("PRP Error")]
pub struct PrpError;
pub type PrpResult<T> = Result<T, PrpError>;

// TODO: There should be a single "permutation type"
// and a generator trait to use different approaches of generating it
pub trait Prp<T>: Sized {
    fn new(key: &[u8]) -> PrpResult<Self>;
    fn permute(&self, data: T) -> PrpResult<T>;
    fn invert(&self, data: T) -> PrpResult<T>;
    fn enumerate(&self) -> Enumerate<Iter<T>>;
}

pub struct NewPrp<T: Sized + Copy, const N: usize> {
    forward: [T; N],
    inverse: [T; N]
}

impl <T: Sized + Copy, const N: usize> NewPrp<T, N> {
    pub fn forward(&self) -> Enumerate<Iter<T>> {
        self.forward.iter().enumerate()
    }

    pub fn inverse(&self) -> Enumerate<Iter<T>> {
        self.inverse.iter().enumerate()
    }

    // TODO: Can we make this able to be called only once?
    pub fn permute(&self, input: impl Into<usize>) -> T {
        self.forward[input.into()]
    }
}

pub trait PrpGenerator<T: Sized + Copy, const N: usize> {
    fn generate(self) -> NewPrp<T, N>;
}

pub struct KnuthShuffleGenerator<'p> {
    prng_seed: &'p [u8]
}

impl<'p> KnuthShuffleGenerator<'p> {
    pub fn new(prng_seed: &'p [u8]) -> Self {
        Self { prng_seed }
    }
}

// TODO: We could avoid code repetition with macros
impl <'p> PrpGenerator<u8, 32> for KnuthShuffleGenerator<'p> {
    fn generate(self) -> NewPrp<u8, 32> {
        let mut rng = Aes128Prng::init(self.prng_seed); // TODO: Use Result type here, too

        let mut forward = [0u8; 32];
        let mut inverse = [0u8; 32];

        // Initialize values
        for i in 0..32 {
            forward[i] = i as u8;
        }

        (0..32).into_iter().rev().for_each(|i| {
            let j = rng.gen_range(i as u8);
            forward.swap(i, j as usize);
        });

        for (index, val) in forward.iter().enumerate() {
            inverse[*val as usize] = index as u8;
        }

        NewPrp { forward, inverse }
    }
}