
mod ore;
mod encrypt;
mod primitives;
pub use crate::ore::{
    CipherText,
    ORECipher,
    bit2
};
pub use crate::encrypt::OREEncrypt;


#[cfg(test)]
#[macro_use]
extern crate quickcheck;

