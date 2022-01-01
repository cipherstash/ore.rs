use crate::ciphertext::*;
use crate::convert::ToOrderedInteger;
use crate::PlainText;
use crate::{ORECipher, OREError};

pub trait OREEncrypt<T>
where
    T: ORECipher,
    <T as ORECipher>::LeftType: LeftCipherText,
    <T as ORECipher>::RightType: RightCipherText,
{
    fn encrypt_left(&self, cipher: &mut T) -> Result<T::LeftType, OREError>;
    fn encrypt(&self, input: &mut T) -> Result<CipherText<T>, OREError>;
}

// FIXME: I don't like that the cipher is mutable - its private members are mutable
// TODO: Perhaps we could make the implementations default for the trait and control things
// with the types. Only need to override for things like floats.
impl<T> OREEncrypt<T> for u64
where
    T: ORECipher,
    <T as ORECipher>::LeftType: LeftCipherText,
    <T as ORECipher>::RightType: RightCipherText,
{
    fn encrypt_left(&self, cipher: &mut T) -> Result<T::LeftType, OREError> {
        let bytes = self.to_be_bytes();
        cipher.encrypt_left(&bytes)
    }

    fn encrypt(&self, cipher: &mut T) -> Result<CipherText<T>, OREError> {
        let bytes = self.to_be_bytes();
        cipher.encrypt(&bytes)
    }
}

impl<T> OREEncrypt<T> for u32
where
    T: ORECipher,
    <T as ORECipher>::LeftType: LeftCipherText,
    <T as ORECipher>::RightType: RightCipherText,
{
    fn encrypt_left(&self, cipher: &mut T) -> Result<T::LeftType, OREError> {
        let bytes = self.to_be_bytes();
        cipher.encrypt_left(&bytes)
    }

    fn encrypt(&self, cipher: &mut T) -> Result<CipherText<T>, OREError> {
        let bytes = self.to_be_bytes();
        cipher.encrypt(&bytes)
    }
}

impl<T> OREEncrypt<T> for f64
where
    T: ORECipher,
    <T as ORECipher>::LeftType: LeftCipherText,
    <T as ORECipher>::RightType: RightCipherText,
{
    fn encrypt_left(&self, cipher: &mut T) -> Result<T::LeftType, OREError> {
        let plaintext: u64 = self.map_to();
        plaintext.encrypt_left(cipher)
    }

    fn encrypt(&self, cipher: &mut T) -> Result<CipherText<T>, OREError> {
        let plaintext: u64 = self.map_to();
        plaintext.encrypt(cipher)
    }
}

impl<T, const N: usize> OREEncrypt<T> for PlainText<N>
where
    T: ORECipher,
    <T as ORECipher>::LeftType: LeftCipherText,
    <T as ORECipher>::RightType: RightCipherText,
{
    fn encrypt_left(&self, cipher: &mut T) -> Result<T::LeftType, OREError> {
        cipher.encrypt_left(self)
    }

    fn encrypt(&self, cipher: &mut T) -> Result<CipherText<T>, OREError> {
        cipher.encrypt(self)
    }
}
