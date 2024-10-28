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

    #[error("Invalid length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
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
