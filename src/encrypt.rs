use crate::ciphertext::*;
use crate::convert::ToOrderedInteger;
use crate::PlainText;
use crate::{EncryptLeftResult, EncryptResult, ORECipher};

pub trait OREEncrypt<T: ORECipher> {
    fn encrypt_left(&self, cipher: &mut T) -> EncryptLeftResult<T>
    where
        <T as ORECipher>::LeftType: LeftCipherText;

    fn encrypt(&self, input: &mut T) -> EncryptResult<T>
    where
        <T as ORECipher>::LeftType: LeftCipherText,
        <T as ORECipher>::RightType: RightCipherText;
}

// FIXME: I don't like that the cipher is mutable - its private members are mutable
// TODO: Perhaps we could make the implementations default for the trait and control things
// with the types. Only need to override for things like floats.
impl<T: ORECipher> OREEncrypt<T> for u64 {
    fn encrypt_left(&self, cipher: &mut T) -> EncryptLeftResult<T>
    where
        <T as ORECipher>::LeftType: LeftCipherText,
    {
        let bytes = self.to_be_bytes();
        cipher.encrypt_left(&bytes)
    }

    fn encrypt(&self, cipher: &mut T) -> EncryptResult<T>
    where
        <T as ORECipher>::LeftType: LeftCipherText,
        <T as ORECipher>::RightType: RightCipherText,
    {
        let bytes = self.to_be_bytes();
        cipher.encrypt(&bytes)
    }
}

impl<T: ORECipher> OREEncrypt<T> for u32 {
    fn encrypt_left(&self, cipher: &mut T) -> EncryptLeftResult<T>
    where
        <T as ORECipher>::LeftType: LeftCipherText,
    {
        let bytes = self.to_be_bytes();
        cipher.encrypt_left(&bytes)
    }

    fn encrypt(&self, cipher: &mut T) -> EncryptResult<T>
    where
        <T as ORECipher>::LeftType: LeftCipherText,
        <T as ORECipher>::RightType: RightCipherText,
    {
        let bytes = self.to_be_bytes();
        cipher.encrypt(&bytes)
    }
}

impl<T: ORECipher> OREEncrypt<T> for f64 {
    fn encrypt_left(&self, cipher: &mut T) -> EncryptLeftResult<T>
    where
        <T as ORECipher>::LeftType: LeftCipherText,
    {
        let plaintext: u64 = self.map_to();
        plaintext.encrypt_left(cipher)
    }

    fn encrypt(&self, cipher: &mut T) -> EncryptResult<T>
    where
        <T as ORECipher>::LeftType: LeftCipherText,
        <T as ORECipher>::RightType: RightCipherText,
    {
        let plaintext: u64 = self.map_to();
        plaintext.encrypt(cipher)
    }
}

impl<T: ORECipher, const N: usize> OREEncrypt<T> for PlainText<N> {
    fn encrypt_left(&self, cipher: &mut T) -> EncryptLeftResult<T>
    where
        <T as ORECipher>::LeftType: LeftCipherText,
    {
        cipher.encrypt_left(self)
    }

    fn encrypt(&self, cipher: &mut T) -> EncryptResult<T>
    where
        <T as ORECipher>::LeftType: LeftCipherText,
        <T as ORECipher>::RightType: RightCipherText,
    {
        cipher.encrypt(self)
    }
}
