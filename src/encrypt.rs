use crate::ciphertext::*;
use crate::convert::ToOrderedInteger;
use crate::PlainText;
use crate::{ORECipher, OREError};

pub trait OREEncrypt<T: ORECipher> {
    type LeftOutput;
    type FullOutput;

    fn encrypt_left(&self, cipher: &T) -> Result<Self::LeftOutput, OREError>;
    fn encrypt(&self, input: &T) -> Result<Self::FullOutput, OREError>;
}

// FIXME: I don't like that the cipher is mutable - its private members are mutable
// TODO: Perhaps we could make the implementations default for the trait and control things
// with the types. Only need to override for things like floats.
impl<T: ORECipher> OREEncrypt<T> for u64 {
    /* Note that Rust currently doesn't allow
     * generic associated types so this ia a bit verbose! */
    type LeftOutput = Left<T, 8>;
    type FullOutput = CipherText<T, 8>;

    fn encrypt_left(&self, cipher: &T) -> Result<Self::LeftOutput, OREError>
    where
        T::LeftBlockType: CipherTextBlock,
    {
        let bytes = self.to_be_bytes();
        ORECipher::encrypt_left(&cipher, &bytes)
    }

    fn encrypt(&self, cipher: &T) -> Result<Self::FullOutput, OREError>
    where
        T::LeftBlockType: CipherTextBlock,
        T::RightBlockType: CipherTextBlock,
    {
        let bytes = self.to_be_bytes();
        ORECipher::encrypt(&cipher, &bytes)
    }
}

impl<T: ORECipher> OREEncrypt<T> for u32 {
    type LeftOutput = Left<T, 4>;
    type FullOutput = CipherText<T, 4>;

    fn encrypt_left(&self, cipher: &T) -> Result<Self::LeftOutput, OREError> {
        let bytes = self.to_be_bytes();
        ORECipher::encrypt_left(&cipher, &bytes)
    }

    fn encrypt(&self, cipher: &T) -> Result<Self::FullOutput, OREError> {
        let bytes = self.to_be_bytes();
        ORECipher::encrypt(&cipher, &bytes)
    }
}

impl<T: ORECipher> OREEncrypt<T> for f64 {
    type LeftOutput = Left<T, 8>;
    type FullOutput = CipherText<T, 8>;

    fn encrypt_left(&self, cipher: &T) -> Result<Self::LeftOutput, OREError> {
        let plaintext: u64 = self.map_to();
        plaintext.encrypt_left(cipher)
    }

    fn encrypt(&self, cipher: &T) -> Result<Self::FullOutput, OREError> {
        let plaintext: u64 = self.map_to();
        plaintext.encrypt(cipher)
    }
}

impl<T: ORECipher, const N: usize> OREEncrypt<T> for PlainText<N> {
    type LeftOutput = Left<T, N>;
    type FullOutput = CipherText<T, N>;

    fn encrypt_left(&self, cipher: &T) -> Result<Self::LeftOutput, OREError> {
        ORECipher::encrypt_left(&cipher, self)
    }

    fn encrypt(&self, cipher: &T) -> Result<Self::FullOutput, OREError> {
        ORECipher::encrypt(&cipher, self)
    }
}
