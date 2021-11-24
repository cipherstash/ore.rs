
pub mod prf;
pub mod hash;

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
