
use crate::{
    ORECipher,
    OREError
};
use crate::ciphertext::*;

pub trait OREEncrypt<T: ORECipher> {
    type LeftOutput;
    type FullOutput;

    fn encrypt_left(&self, cipher: &mut T) -> Result<Self::LeftOutput, OREError>;
    fn encrypt(&self, input: &mut T) -> Result<Self::FullOutput, OREError>;
}

// FIXME: I don't like that the cipher is mutable - its private members are mutable
// TODO: Perhaps we could make the implementations default for the trait and control things
// with the types. Only need to override for things like floats.
impl<T: ORECipher> OREEncrypt<T> for u64
where <T as ORECipher>::LeftBlockType: CipherTextBlock,
      <T as ORECipher>::RightBlockType: CipherTextBlock
{
    /* Note that Rust currently doesn't allow
     * generic associated types so this ia a bit verbose! */
    type LeftOutput = Left<T, 8>;
    type FullOutput = CipherText<T, 8>;

    fn encrypt_left(&self, cipher: &mut T) -> Result<Self::LeftOutput, OREError>
        where T::LeftBlockType: CipherTextBlock
    {
        let bytes = self.to_be_bytes();
        return cipher.encrypt_left(&bytes);
    }

    fn encrypt(&self, cipher: &mut T) -> Result<Self::FullOutput, OREError>
        where T::LeftBlockType: CipherTextBlock,
              T::RightBlockType: CipherTextBlock
    {
        let bytes = self.to_be_bytes();
        return cipher.encrypt(&bytes);
    }
}

impl<T: ORECipher> OREEncrypt<T> for u32
where <T as ORECipher>::LeftBlockType: CipherTextBlock,
      <T as ORECipher>::RightBlockType: CipherTextBlock
{
    type LeftOutput = Left<T, 4>;
    type FullOutput = CipherText<T, 4>;

    fn encrypt_left(&self, cipher: &mut T) -> Result<Self::LeftOutput, OREError> {
        let bytes = self.to_be_bytes();
        return cipher.encrypt_left(&bytes);
    }

    fn encrypt(&self, cipher: &mut T) -> Result<Self::FullOutput, OREError> {
        let bytes = self.to_be_bytes();
        return cipher.encrypt(&bytes);
    }
}

