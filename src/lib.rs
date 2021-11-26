
mod ore;
mod primitives;
pub use crate::ore::{
    ORE,
    CipherText,
    bit2::OREAES128
};


#[cfg(test)]
#[macro_use]
extern crate quickcheck;

