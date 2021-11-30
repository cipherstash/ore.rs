
use crate::ore::{
    ORECipher,
    Left,
    CipherText,
    OREError
};

pub trait OREEncrypt {
    type LeftOutput;
    type FullOutput;

    fn encrypt_left<T: ORECipher>(&self, cipher: &mut T) -> Result<Self::LeftOutput, OREError>;
    fn encrypt<T: ORECipher>(&self, input: &mut T) -> Result<Self::FullOutput, OREError>;
}

// FIXME: I don't like that the cipher is mutable - its private members are mutable
// TODO: Perhaps we could make the implementations default for the trait and control things
// with the types. Only need to override for things like floats.
impl OREEncrypt for u64 {
    type LeftOutput = Left<8>;
    type FullOutput = CipherText<8>;

    fn encrypt_left<T: ORECipher>(&self, cipher: &mut T) -> Result<Self::LeftOutput, OREError> {
        let bytes = self.to_be_bytes();
        return cipher.encrypt_left(&bytes);
    }

    fn encrypt<T: ORECipher>(&self, cipher: &mut T) -> Result<Self::FullOutput, OREError> {
        let bytes = self.to_be_bytes();
        return cipher.encrypt(&bytes);
    }
}

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
}

