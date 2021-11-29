
mod ore;
mod primitives;
pub use crate::ore::{
    CipherText,
    ORECipher,
    OREEncrypt,
    bit2
};


#[cfg(test)]
#[macro_use]
extern crate quickcheck;

