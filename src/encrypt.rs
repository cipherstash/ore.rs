use crate::ciphertext::*;
use crate::convert::ToOrderedInteger;
use crate::PlainText;
use crate::{ORECipher, OREError};

pub trait OREEncrypt<T: ORECipher> {
    fn encrypt_left(&self, cipher: &mut T) -> Result<Left, OREError>;
    fn encrypt(&self, input: &mut T) -> Result<CipherText, OREError>;
}

// FIXME: I don't like that the cipher is mutable - its private members are mutable
// TODO: Perhaps we could make the implementations default for the trait and control things
// with the types. Only need to override for things like floats.
impl<T: ORECipher> OREEncrypt<T> for u64 {
    fn encrypt_left(&self, cipher: &mut T) -> Result<Left, OREError> {
        let bytes = self.to_be_bytes();
        cipher.encrypt_left(&bytes)
    }

    fn encrypt(&self, cipher: &mut T) -> Result<CipherText, OREError> {
        let bytes = self.to_be_bytes();
        cipher.encrypt(&bytes)
    }
}

impl<T: ORECipher> OREEncrypt<T> for u32 {
    fn encrypt_left(&self, cipher: &mut T) -> Result<Left, OREError> {
        let bytes = self.to_be_bytes();
        cipher.encrypt_left(&bytes)
    }

    fn encrypt(&self, cipher: &mut T) -> Result<CipherText, OREError> {
        let bytes = self.to_be_bytes();
        cipher.encrypt(&bytes)
    }
}

impl<T: ORECipher> OREEncrypt<T> for f64 {
    fn encrypt_left(&self, cipher: &mut T) -> Result<Left, OREError> {
        let plaintext: u64 = self.map_to();
        plaintext.encrypt_left(cipher)
    }

    fn encrypt(&self, cipher: &mut T) -> Result<CipherText, OREError> {
        let plaintext: u64 = self.map_to();
        plaintext.encrypt(cipher)
    }
}

impl<T: ORECipher, const N: usize> OREEncrypt<T> for PlainText<N> {
    fn encrypt_left(&self, cipher: &mut T) -> Result<Left, OREError> {
        cipher.encrypt_left(self)
    }

    fn encrypt(&self, cipher: &mut T) -> Result<CipherText, OREError> {
        cipher.encrypt(self)
    }
}
