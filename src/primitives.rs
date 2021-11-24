
pub mod prf;

pub trait PRF {
    // TODO: Use a PRFKey trait as the argument here
    fn new(key: &[u8]) -> Self;
    // TODO: Use PRF Block trait as the data argument
    fn encrypt_all(&self, data: &mut [u8]);
}

