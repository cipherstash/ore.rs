//! Block-width abstraction for BlockORE schemes.
//!
//! A [`BlockWidth`] fixes the number of plaintext bits consumed per ORE
//! block and everything that follows from it: the block domain size, the
//! right-ciphertext bitvector type, the PRP over the domain, and the
//! random-oracle key buffer. Widths are sealed: the comparator and wire
//! format are width-specific, so downstream crates must not add widths.
//!
//! Stable Rust cannot express `[u8; 1 << BITS]` for a generic width
//! (`generic_const_exprs`), so the width carries its domain-sized buffers
//! as associated types instead.

use crate::ciphertext::CipherTextBlock;
use crate::primitives::{AesBlock, Prp};
use crate::scheme::bit2::block_types::RightBlock32;
use crate::scheme::bit2_w6::block_types::RightBlock8;

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Bit8 {}
    impl Sealed for super::Bit6 {}
    impl Sealed for [super::AesBlock; 256] {}
    impl Sealed for [super::AesBlock; 64] {}
}

/// A domain-sized buffer of AES blocks used for per-block random-oracle
/// keys. Implemented for `[AesBlock; DOMAIN]` arrays (which have no
/// `Default` for large N on stable Rust).
pub trait AesBlockBuf: sealed::Sealed {
    /// A zeroed buffer.
    fn zeroed() -> Self;
    /// View as a mutable slice for batched PRF passes. (Concrete `[T; N]`
    /// callers resolve to the inherent array method; this exists for
    /// width-generic code, which arrives with the Bit6 scheme.)
    #[allow(dead_code)]
    fn as_mut_slice(&mut self) -> &mut [AesBlock];
    /// Overwrite `self` with `other` (a domain-sized memcpy).
    fn copy_from(&mut self, other: &Self);
}

macro_rules! impl_aes_block_buf {
    ($n:literal) => {
        impl AesBlockBuf for [AesBlock; $n] {
            fn zeroed() -> Self {
                [AesBlock::default(); $n]
            }
            fn as_mut_slice(&mut self) -> &mut [AesBlock] {
                self
            }
            fn copy_from(&mut self, other: &Self) {
                self.clone_from_slice(other);
            }
        }
    };
}

impl_aes_block_buf!(256);
impl_aes_block_buf!(64);

/// Per-block bitvector operations on a Right ciphertext block, one bit per
/// value in the block domain.
pub trait RightBitVec {
    /// Set bit `bit` to `value` (`0` or `1`). (Bulk encoding writes via
    /// [`Self::as_mut_bytes`]; this remains for width-generic callers.)
    #[allow(dead_code)]
    fn set_bit(&mut self, bit: usize, value: u8);
    /// Read bit `bit`. (The width-generic comparator lands with the Bit6
    /// scheme; the legacy comparator calls the inherent method.)
    #[allow(dead_code)]
    fn get_bit(&self, bit: usize) -> u8;
    /// The raw bitvector bytes, LSB-first within each byte (the same bit
    /// order as [`Self::set_bit`]), for bulk mask construction.
    fn as_mut_bytes(&mut self) -> &mut [u8];
}

impl RightBitVec for RightBlock32 {
    fn set_bit(&mut self, bit: usize, value: u8) {
        RightBlock32::set_bit(self, bit, value)
    }
    fn get_bit(&self, bit: usize) -> u8 {
        RightBlock32::get_bit(self, bit)
    }
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        self.bytes_mut()
    }
}

/// The number of plaintext bits consumed per ORE block, and the types that
/// depend on it. See the module docs.
pub trait BlockWidth: sealed::Sealed + 'static {
    /// Bits of plaintext per block.
    const BITS: usize;
    /// Block domain size: `1 << BITS`. Block values are `0..DOMAIN`.
    const DOMAIN: usize;
    /// Right-ciphertext block: a `DOMAIN`-bit masked truth-table row.
    type RightBlock: CipherTextBlock + RightBitVec;
    /// PRP over the block domain.
    type Prp: Prp<u8>;
    /// Buffer holding `DOMAIN` random-oracle keys.
    type RoKeyBuf: AesBlockBuf;
}

/// The 8-bit block width used by the legacy [`crate::scheme::bit2`] scheme:
/// one plaintext byte per block, domain 256.
#[derive(Debug)]
pub struct Bit8;

impl BlockWidth for Bit8 {
    const BITS: usize = 8;
    const DOMAIN: usize = 256;
    type RightBlock = RightBlock32;
    type Prp = crate::primitives::prp::KnuthShufflePRP<u8, 256>;
    type RoKeyBuf = [AesBlock; 256];
}

/// The 6-bit block width used by [`crate::scheme::bit2_w6`]: six plaintext
/// bits per block, domain 64. Right blocks are 8 bytes (vs 32) and each
/// block costs 64 RO evaluations (vs 256).
#[derive(Debug)]
pub struct Bit6;

impl BlockWidth for Bit6 {
    const BITS: usize = 6;
    const DOMAIN: usize = 64;
    type RightBlock = RightBlock8;
    // Fixed-draw Fisher–Yates, not the rejection-sampled Knuth shuffle:
    // Bit6's wire format is not frozen, so it adopts the constant-time,
    // ~9×-faster PRP construction. See `LemireFyPrp`.
    type Prp = crate::primitives::prp::LemireFyPrp<64>;
    type RoKeyBuf = [AesBlock; 64];
}
