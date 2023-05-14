#![feature(iter_next_chunk)]
mod data_with_header;
mod header;
mod ciphertext;

pub use ciphertext::{
    CipherText,
    CipherTextBlock,
    left::LeftCiphertext,
    right::RightCiphertext,
    combined::CombinedCiphertext
};
pub use data_with_header::DataWithHeader;

#[derive(Debug)]
pub struct ParseError {}
