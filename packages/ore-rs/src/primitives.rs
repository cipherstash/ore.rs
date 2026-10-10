pub mod hash;
pub mod prf;
pub mod prp;

use aes::cipher::{consts::U16, generic_array::GenericArray};
use aes::Block;
use thiserror::Error;
pub type AesBlock = Block;
pub type PrfKey = GenericArray<u8, U16>;
pub type HashKey = GenericArray<u8, U16>;
pub const NONCE_SIZE: usize = 16;

/// Pack one bit per element of `src` into `out`, LSB-first, eight elements per
/// byte: the bit derived from `src[j]` lands in `out[j / 8]` at position
/// `j % 8` — the bit order used by `RightBlock32::set_bit`. `bit` extracts the
/// 0/1 value of each element; `merge` folds each packed byte into the existing
/// `out` byte (assign for a fresh buffer, XOR to overlay). This is the single
/// home of the right-ciphertext bit-packing convention, shared by
/// [`Hash::hash_all_into`] and [`Prp::indicator_mask_xor`].
///
/// Panics unless `out.len() * 8 == src.len()`, which also guarantees
/// `chunks_exact(8)` consumes `src` with no dropped remainder.
pub(crate) fn pack_bits_lsb_first<T>(
    out: &mut [u8],
    src: &[T],
    bit: impl Fn(&T) -> u8,
    merge: impl Fn(&mut u8, u8),
) {
    assert_eq!(
        out.len() * 8,
        src.len(),
        "pack_bits_lsb_first: out.len()*8 must equal src.len()"
    );
    for (slot, chunk) in out.iter_mut().zip(src.chunks_exact(8)) {
        let mut byte = 0u8;
        for (i, elem) in chunk.iter().enumerate() {
            byte |= (bit(elem) & 1) << i;
        }
        merge(slot, byte);
    }
}

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
    /// `1` iff `invert(j) > data`. Bit order matches `RightBlock32::set_bit`
    /// (LSB-first within each byte). `out.len() * 8` must equal the
    /// permutation domain.
    ///
    /// This is the bulk form of the per-`j` `invert`-and-compare loop the
    /// right-ciphertext encoder needs; implementations walk their inverse
    /// table linearly instead of doing `DOMAIN` indexed lookups.
    fn indicator_mask_xor(&self, data: T, out: &mut [u8]);
}
