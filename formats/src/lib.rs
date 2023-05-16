#![feature(iter_next_chunk)]
mod data_with_header;
mod header;
mod ciphertext;

pub use ciphertext::{
    CipherText,
    CipherTextBlock,
    LeftCipherTextBlock,
    RightCipherTextBlock,
    LeftBlockEq,
    OreBlockOrd,
    // TODO: Make the naming of these consistent
    left::LeftCiphertext,
    right::RightCiphertext,
    combined::CombinedCiphertext
};
pub use data_with_header::DataWithHeader;

#[derive(Debug)]
pub struct ParseError {}
