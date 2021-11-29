
mod ore;
mod primitives;
pub use crate::ore::{
    ORE,
    CipherText,
    bit2,
    ORECipher,
    OREEncrypt
};


#[cfg(test)]
#[macro_use]
extern crate quickcheck;

