pub mod hash;
pub mod prf;
pub mod prp;

use aes::cipher::{consts::U16, generic_array::GenericArray};

/*
 * Represents a 64-bit (8-byte) random seed.
 */
pub type SEED64 = [u8; 8];

use aes::Block;

pub type AesBlock = Block;
pub type PRFKey = GenericArray<u8, U16>;
pub type HashKey = GenericArray<u8, U16>;
pub const NONCE_SIZE: usize = 16;

pub trait PRF {
    fn new(key: &PRFKey) -> Self;
    fn encrypt_all(&self, data: &mut [AesBlock]);
}

pub trait Hash {
    fn new(key: &HashKey) -> Self;
    fn hash(&self, data: &[u8]) -> u8;
    fn hash_all(&self, input: &mut [AesBlock]) -> Vec<u8>;
}

#[derive(Debug, Clone)]
pub struct PRPError;
pub type PRPResult<T> = Result<T, PRPError>;

pub trait PRP<T>: Sized {
    fn new(key: &[u8], seed: &SEED64) -> PRPResult<Self>;
    fn permute(&self, data: T) -> PRPResult<T>;
    fn invert(&self, data: T) -> PRPResult<T>;
}
