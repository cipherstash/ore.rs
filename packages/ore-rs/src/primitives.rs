pub mod cmac;
pub mod hash;
pub mod prf;
pub mod prp;
pub mod simd;

use aes::cipher::{consts::U16, generic_array::GenericArray};
use aes::Block;
use thiserror::Error;
pub type AesBlock = Block;
pub type PrfKey = GenericArray<u8, U16>;
pub type HashKey = GenericArray<u8, U16>;
pub const NONCE_SIZE: usize = 16;

pub trait Prf {
    fn new(key: &PrfKey) -> Self;
    fn encrypt_all(&self, data: &mut [AesBlock]);
}

pub trait Hash {
    fn new(key: &HashKey) -> Self;
    fn hash(&self, data: &[u8]) -> u8;
    /// Hash every block in `input` (in place, trashing it) and pack the
    /// 1-bit outputs LSB-first into `out`: bit `j` of `out` is the hash of
    /// `input[j]`. `out.len() * 8` must equal `input.len()`.
    fn hash_all_into(&self, input: &mut [AesBlock], out: &mut [u8]);
}

#[derive(Debug, Error)]
#[error("PRP Error")]
pub struct PrpError;
pub type PrpResult<T> = Result<T, PrpError>;

pub trait Prp<T>: Sized {
    fn new(key: &[u8]) -> PrpResult<Self>;
    fn permute(&self, data: T) -> PrpResult<T>;
    /// Inverse of [`Self::permute`]. The encrypt path uses the bulk
    /// [`Self::indicator_mask_xor`] instead; this remains the per-value
    /// reference (used by the mask equivalence tests).
    #[allow(dead_code)]
    fn invert(&self, data: T) -> PrpResult<T>;

    /// XOR the indicator mask for `data` into `out`: bit `j` of the mask is
    /// `1` iff `invert(j) > data`. Bit order matches
    /// `RightBitVec::set_bit` (LSB-first within each byte). `out.len() * 8`
    /// must equal the permutation domain.
    ///
    /// This is the bulk form of the per-`j` `invert`-and-compare loop the
    /// right-ciphertext encoder needs; implementations walk their inverse
    /// table linearly instead of doing `DOMAIN` indexed lookups.
    fn indicator_mask_xor(&self, data: T, out: &mut [u8]);
}
