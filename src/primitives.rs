
pub mod prf;
pub mod hash;
pub mod prp;

/*
 * Represents a 64-bit (8-byte) random seed.
 */
pub type SEED64 = [u8; 8];

use aes::Block;

pub type AesBlock = Block;

pub trait PRF {
    // TODO: Use a PRFKey trait as the argument here
    fn new(key: &[u8]) -> Self;
    // TODO: Use PRF Block trait as the data argument
    fn encrypt_all(&self, data: &mut [AesBlock]);
}

pub trait Hash {
    fn new(key: &[u8]) -> Self;
    fn hash(&self, data: &[u8]) -> u8;
    fn hash_all(&self, input: &[u8], output: &mut [u8]);
}

#[derive(Debug, Clone)]
pub struct PRPError;
pub type PRPResult<T> = Result<T, PRPError>;

pub trait PRP<T>: Sized {
    fn new(key: &[u8], seed: &SEED64) -> PRPResult<Self>;
    fn permute(&self, data: T) -> PRPResult<T>;
    fn invert(&self, data: T) -> PRPResult<T>;
}
