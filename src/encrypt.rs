
use crate::ore::{
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
impl<T: ORECipher> OREEncrypt<T> for u64 {
    type LeftOutput = Left<T::LeftBlockType, 8>;
    type FullOutput = CipherText<T::LeftBlockType, T::RightBlockType, 8>;

    fn encrypt_left(&self, cipher: &mut T) -> Result<Self::LeftOutput, OREError> {
        let bytes = self.to_be_bytes();
        return cipher.encrypt_left(&bytes);
    }

    fn encrypt(&self, cipher: &mut T) -> Result<Self::FullOutput, OREError> {
        let bytes = self.to_be_bytes();
        return cipher.encrypt(&bytes);
    }
}

/*
impl OREEncrypt for u32 {
    type LeftOutput = Left<4>;
    type FullOutput = CipherText<4>;

    fn encrypt_left<T: ORECipher>(&self, cipher: &mut T) -> Result<Self::LeftOutput, OREError> {
        let bytes = self.to_be_bytes();
        return cipher.encrypt_left(&bytes);
    }

    fn encrypt<T: ORECipher>(&self, cipher: &mut T) -> Result<Self::FullOutput, OREError> {
        let bytes = self.to_be_bytes();
        return cipher.encrypt(&bytes);
    }
}*/

