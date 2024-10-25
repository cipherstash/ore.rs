use thiserror::Error;
mod biterator;
mod impls;
mod nibble_iterator;
mod orderize_string;

pub use impls::num::OreCllw8V1;
pub use impls::string::OreCllw8VariableV1;

#[derive(Debug, Error)]
pub enum Error {
    #[error("String must be ASCII to encode for ORE")]
    NotAscii,
}

pub struct Key([u8; 32]);

impl Key {
    pub fn encrypt<T>(&self, input: T) -> Result<<T as CllwOreEncrypt>::Output, Error>
    where
        T: CllwOreEncrypt,
    {
        input.encrypt(self)
    }
}

impl From<[u8; 32]> for Key {
    fn from(key: [u8; 32]) -> Self {
        Self(key)
    }
}

pub trait CllwOreEncrypt: Sized {
    type Output;

    fn encrypt(self, key: &Key) -> Result<Self::Output, Error> {
        self.encrypt_with_salt(key, None)
    }

    fn encrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error>;
}

#[derive(Debug, Clone)]
pub struct Output<Elem> {
    bytes: Vec<u8>,
    _elem: std::marker::PhantomData<Elem>,
    num_elements: usize,
}

impl Output<u8> {
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    fn new(num_elements: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(num_elements),
            _elem: std::marker::PhantomData,
            num_elements,
        }
    }

    fn push_into(mut self, elem: u8) -> Self {
        self.bytes.push(elem);
        self
    }

    /// Returns the number of elements (which is not necessarily the number of bytes)
    fn len(&self) -> usize {
        self.num_elements
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl From<Vec<u8>> for Output<u8> {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            num_elements: bytes.len(),
            bytes,
            _elem: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen};
    use std::{
        array,
        fmt::{self, Debug, Formatter},
    };

    impl Clone for Key {
        fn clone(&self) -> Self {
            Key(self.0)
        }
    }

    impl Arbitrary for Key {
        fn arbitrary(g: &mut Gen) -> Self {
            Self(array::from_fn(|_| u8::arbitrary(g)))
        }
    }

    impl Debug for Key {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
}
