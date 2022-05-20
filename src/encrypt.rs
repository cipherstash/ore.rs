use crate::ciphertext::*;
use crate::convert::ToOrderedInteger;
use crate::PlainText;
use crate::{EncryptLeftResult, EncryptResult, ORECipher};

pub trait OREEncrypt<T: ORECipher<N>, const N: usize> {
    fn encrypt_left(&self, cipher: &mut T) -> EncryptLeftResult<T, N>
    where
        <T as ORECipher<N>>::LeftType: LeftCipherText<N>;

    fn encrypt(&self, input: &mut T) -> EncryptResult<T, N>
    where
        <T as ORECipher<N>>::LeftType: LeftCipherText<N>,
        <T as ORECipher<N>>::RightType: RightCipherText;
}

// TODO: This assumes that block-size is 8 - so these will have to be handled for different schemes
impl<T: ORECipher<8>> OREEncrypt<T, 8> for u64 {
    fn encrypt_left(&self, cipher: &mut T) -> EncryptLeftResult<T, 8>
    where
        <T as ORECipher<8>>::LeftType: LeftCipherText<8>,
    {
        let bytes = self.to_be_bytes();
        cipher.encrypt_left(&bytes)
    }

    fn encrypt(&self, cipher: &mut T) -> EncryptResult<T, 8>
    where
        <T as ORECipher<8>>::LeftType: LeftCipherText<8>,
        <T as ORECipher<8>>::RightType: RightCipherText,
    {
        let bytes = self.to_be_bytes();
        cipher.encrypt(&bytes)
    }
}

impl<T: ORECipher<4>> OREEncrypt<T, 4> for u32 {
    fn encrypt_left(&self, cipher: &mut T) -> EncryptLeftResult<T, 4>
    where
        <T as ORECipher<4>>::LeftType: LeftCipherText<4>,
    {
        let bytes = self.to_be_bytes();
        cipher.encrypt_left(&bytes)
    }

    fn encrypt(&self, cipher: &mut T) -> EncryptResult<T, 4>
    where
        <T as ORECipher<4>>::LeftType: LeftCipherText<4>,
        <T as ORECipher<4>>::RightType: RightCipherText,
    {
        let bytes = self.to_be_bytes();
        cipher.encrypt(&bytes)
    }
}

impl<T: ORECipher<8>> OREEncrypt<T, 8> for f64 {
    fn encrypt_left(&self, cipher: &mut T) -> EncryptLeftResult<T, 8>
    where
        <T as ORECipher<8>>::LeftType: LeftCipherText<8>,
    {
        let plaintext: u64 = self.map_to();
        plaintext.encrypt_left(cipher)
    }

    fn encrypt(&self, cipher: &mut T) -> EncryptResult<T, 8>
    where
        <T as ORECipher<8>>::LeftType: LeftCipherText<8>,
        <T as ORECipher<8>>::RightType: RightCipherText,
    {
        let plaintext: u64 = self.map_to();
        plaintext.encrypt(cipher)
    }
}

impl<T: ORECipher<N>, const N: usize> OREEncrypt<T, N> for PlainText<N> {
    fn encrypt_left(&self, cipher: &mut T) -> EncryptLeftResult<T, N>
    where
        <T as ORECipher<N>>::LeftType: LeftCipherText<N>,
    {
        cipher.encrypt_left(self)
    }

    fn encrypt(&self, cipher: &mut T) -> EncryptResult<T, N>
    where
        <T as ORECipher<N>>::LeftType: LeftCipherText<N>,
        <T as ORECipher<N>>::RightType: RightCipherText,
    {
        cipher.encrypt(self)
    }
}
