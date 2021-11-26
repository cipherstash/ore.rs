
pub mod prf;
pub mod hash;
pub mod prp;

/*
 * Represents a 64-bit (8-byte) random seed.
 */
pub type SEED64 = [u8; 8];

pub trait PRF {
    // TODO: Use a PRFKey trait as the argument here
    fn new(key: &[u8]) -> Self;
    // TODO: Use PRF Block trait as the data argument
    fn encrypt_all(&self, data: &mut [u8]);
}

pub trait Hash {
    fn new(key: &[u8]) -> Self;
    fn hash(&self, data: &[u8]) -> u8;
    fn hash_all(&self, input: &[u8], output: &mut [u8]);
}

pub trait PRP<T> {
    fn new(key: &[u8], seed: &SEED64) -> Self;
    fn permute(&self, data: T) -> T;
    fn invert(&self, data: T) -> T;
}