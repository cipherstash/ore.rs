use crate::ciphertext::*;
use crate::convert::ToOrderedInteger;
use crate::PlainText;
use crate::{OreCipher, OreError};

pub trait OreEncrypt<T: OreCipher> {
    type LeftOutput: OreOutput;
    type FullOutput: OreOutput;

    fn encrypt_left(&self, cipher: &T) -> Result<Self::LeftOutput, OreError>;
    fn encrypt(&self, input: &T) -> Result<Self::FullOutput, OreError>;
}

impl<T: OreCipher> OreEncrypt<T> for u64 {
    /* Note that Rust currently doesn't allow
     * generic associated types so this ia a bit verbose! */
    type LeftOutput = Left<T, 8>;
    type FullOutput = CipherText<T, 8>;

    fn encrypt_left(&self, cipher: &T) -> Result<Self::LeftOutput, OreError>
    where
        T::LeftBlockType: CipherTextBlock,
    {
        let bytes = self.to_be_bytes();
        cipher.encrypt_left(&bytes)
    }

    fn encrypt(&self, cipher: &T) -> Result<Self::FullOutput, OreError>
    where
        T::LeftBlockType: CipherTextBlock,
        T::RightBlockType: CipherTextBlock,
    {
        let bytes = self.to_be_bytes();
        cipher.encrypt(&bytes)
    }
}

impl<T: OreCipher> OreEncrypt<T> for u32 {
    type LeftOutput = Left<T, 4>;
    type FullOutput = CipherText<T, 4>;

    fn encrypt_left(&self, cipher: &T) -> Result<Self::LeftOutput, OreError> {
        let bytes = self.to_be_bytes();
        cipher.encrypt_left(&bytes)
    }

    fn encrypt(&self, cipher: &T) -> Result<Self::FullOutput, OreError> {
        let bytes = self.to_be_bytes();
        cipher.encrypt(&bytes)
    }
}

impl<T: OreCipher> OreEncrypt<T> for f64 {
    type LeftOutput = Left<T, 8>;
    type FullOutput = CipherText<T, 8>;

    fn encrypt_left(&self, cipher: &T) -> Result<Self::LeftOutput, OreError> {
        let plaintext: u64 = self.map_to();
        plaintext.encrypt_left(cipher)
    }

    fn encrypt(&self, cipher: &T) -> Result<Self::FullOutput, OreError> {
        let plaintext: u64 = self.map_to();
        plaintext.encrypt(cipher)
    }
}

impl<T: OreCipher, const N: usize> OreEncrypt<T> for PlainText<N> {
    type LeftOutput = Left<T, N>;
    type FullOutput = CipherText<T, N>;

    fn encrypt_left(&self, cipher: &T) -> Result<Self::LeftOutput, OreError> {
        cipher.encrypt_left(self)
    }

    fn encrypt(&self, cipher: &T) -> Result<Self::FullOutput, OreError> {
        cipher.encrypt(self)
    }
}
