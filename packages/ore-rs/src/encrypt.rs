use crate::ciphertext::*;
use crate::convert::ToOrderedInteger;
use crate::PlainText;
use crate::{OreCipher, OreError};

/// Type-directed entry point for encrypting plaintext values with a given
/// [`OreCipher`].
///
/// Each implementation knows how to canonicalise its target type into the
/// fixed-size byte plaintext expected by the cipher (e.g. big-endian bytes
/// for `u64`, an order-preserving 8-byte mapping for `f64`, the 14-byte
/// scientific-form encoding for `Decimal`). The associated output types
/// pin the resulting ciphertext shape, with `LeftOutput` the query-only
/// half and `FullOutput` the full ciphertext suitable for storage.
pub trait OreEncrypt<T: OreCipher> {
    /// Output type produced by [`encrypt_left`](Self::encrypt_left).
    type LeftOutput: OreOutput;
    /// Output type produced by [`encrypt`](Self::encrypt).
    type FullOutput: OreOutput;

    /// Encrypt `self` with `cipher`, producing the Left half only — useful
    /// for query plaintexts compared against stored ciphertexts.
    fn encrypt_left(&self, cipher: &T) -> Result<Self::LeftOutput, OreError>;
    /// Encrypt `self` with `input`, producing a full Left+Right ciphertext
    /// suitable for storage and subsequent comparison.
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
