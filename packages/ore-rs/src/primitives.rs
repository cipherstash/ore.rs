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

/// A value of a `D`-element PRP domain: a byte known to be `< D`, for a
/// power-of-two `D ≤ 256`.
///
/// The type carries the domain check, so [`Prp::permute`] and
/// [`Prp::invert`] are infallible and the oblivious table lookup behind them
/// has no range branch on the (secret) symbol. A symbol is made by
/// [`Self::from_low_bits`], which masks and never branches, or (for the
/// 256-element domain, where every byte is a symbol) by `From<u8>`. Callers
/// that take symbols from outside validate them first; see
/// `scheme::decompose::Blocks6`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Symbol<const D: usize>(u8);

impl<const D: usize> Symbol<D> {
    const DOMAIN_OK: () = assert!(
        D.is_power_of_two() && D <= 256,
        "Symbol: the domain must be a power of two no larger than 256"
    );

    /// The low `log2(D)` bits of `b`: `b mod D`, by masking. Branch-free, and
    /// the identity on any `b < D`.
    #[inline]
    #[allow(clippy::let_unit_value)]
    pub fn from_low_bits(b: u8) -> Self {
        let () = Self::DOMAIN_OK;
        // `D - 1` is at most 255, so the mask fits a byte.
        Self(b & (D - 1) as u8)
    }

    #[inline]
    pub fn get(self) -> u8 {
        self.0
    }
}

/// Every byte is a symbol of the 256-element domain.
impl From<u8> for Symbol<256> {
    #[inline]
    fn from(b: u8) -> Self {
        Self(b)
    }
}

/// A pseudo-random permutation over the domain whose values are `S` (a
/// [`Symbol`]). Only key setup can fail; a symbol is in the domain by type.
pub trait Prp<S>: Sized {
    fn new(key: &[u8]) -> PrpResult<Self>;
    fn permute(&self, data: S) -> S;
    /// Inverse of [`Self::permute`]. The encrypt path uses the bulk
    /// [`Self::indicator_mask_xor`] instead; this remains the per-value
    /// reference (used by the mask equivalence tests).
    #[allow(dead_code)]
    fn invert(&self, data: S) -> S;

    /// XOR the indicator mask for `data` into `out`: bit `j` of the mask is
    /// `1` iff `invert(j) > data`. Bit order matches
    /// `RightBlock32::set_bit` (LSB-first within each byte). `out.len() * 8`
    /// must equal the permutation domain.
    ///
    /// This is the bulk form of the per-`j` `invert`-and-compare loop the
    /// right-ciphertext encoder needs; implementations walk their inverse
    /// table linearly instead of doing `DOMAIN` indexed lookups.
    fn indicator_mask_xor(&self, data: S, out: &mut [u8]);
}
