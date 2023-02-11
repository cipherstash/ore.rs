pub mod hash;
pub mod prf;
pub mod prp;

use aes::cipher::{consts::U16, generic_array::GenericArray};
use aes::Block;
use thiserror::Error;
pub type AesBlock = Block;
pub type PRFKey = GenericArray<u8, U16>;
pub type HashKey = GenericArray<u8, U16>;
pub const NONCE_SIZE: usize = 16;

pub trait Prf {
    fn new(key: &PRFKey) -> Self;
    fn encrypt_all(&self, data: &mut [AesBlock]);
}

pub trait Hash {
    fn new(key: &HashKey) -> Self;
    fn hash(&self, data: &[u8]) -> u8;
    fn hash_all(&self, input: &mut [AesBlock]) -> Vec<u8>;
}

#[derive(Debug, Error)]
#[error("PRP Error")]
pub struct PRPError;
pub type PRPResult<T> = Result<T, PRPError>;

pub trait Prp<T>: Sized {
    fn new(key: &[u8]) -> PRPResult<Self>;
    fn permute(&self, data: T) -> PRPResult<T>;
    fn invert(&self, data: T) -> PRPResult<T>;
}
