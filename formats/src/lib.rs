#![feature(iter_next_chunk)]
mod data_with_header;
mod header;
mod ciphertext;

#[derive(Debug)]
pub struct ParseError {}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum CtType {
    Left = 0,
    Right = 1,
    Combined = 2,
}

impl From<u8> for CtType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Left,
            1 => Self::Right,
            2 => Self::Combined,
            _ => panic!("Unknown Ciphertext Type")
        }
    }
}







pub struct LeftBlock([u8; 16], u8);

