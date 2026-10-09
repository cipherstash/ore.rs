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

/// Oblivious byte read: returns `block[idx]` while touching **every** byte of
/// `block`, so the memory-access address is independent of `idx`.
///
/// The comparators read the right-ciphertext block at `bit / 8` where `bit` is
/// the secret permuted symbol (`a[l]`, the left ciphertext's permuted index at
/// the first differing block). A direct `block[bit / 8]` index makes the
/// touched address secret-dependent, which is a cache-line timing channel — and
/// because the block fits within a line, even an aligned direct index would
/// still leak at sub-line (4-byte) granularity to a MemJam-class attacker on
/// SMT-enabled Intel. Scanning the whole block removes the data-dependent
/// address entirely, closing both. The block is ≤ 32 bytes, so the scan is
/// cheap relative to the per-comparison AES hash.
///
/// See `docs/reviews/2026-06-14-ore-v2-crypto-review-brief.md` (A4, compare
/// side). The bit within the selected byte is then extracted with [`ct_bit`],
/// which avoids a shift by the secret amount.
#[inline]
pub(crate) fn ct_select_byte(block: &[u8], idx: usize) -> u8 {
    use subtle_ng::{ConditionallySelectable, ConstantTimeEq};
    let mut acc = 0u8;
    for (i, &b) in block.iter().enumerate() {
        // `i` is the public loop counter; `idx` is secret. Both index a block
        // or table of ≤ 256 bytes, so the u8 cast is lossless.
        acc.conditional_assign(&b, (i as u8).ct_eq(&(idx as u8)));
    }
    acc
}

/// Oblivious conditional copy: `dst = src` when `choice` is set, otherwise
/// `dst` is left as it was; every byte of both is touched either way.
///
/// The comparators use this to *latch* the first differing block while the
/// constant-time prefix scan is still running: at each block `n` the scan
/// knows whether `n` is the first difference, and copies that block's left
/// tag, permuted symbol and right bitvector under that choice. Nothing after
/// the scan is then loaded at an address derived from the position of the
/// first difference. A direct `right[l]` after the scan would be the one load
/// whose cache state depends on `l` (the scan never touches the right blocks),
/// which a timing attacker can read; `docs/reviews/` records the measurement.
#[inline]
pub(crate) fn ct_assign_bytes(dst: &mut [u8], src: &[u8], choice: subtle_ng::Choice) {
    use subtle_ng::ConditionallySelectable;
    debug_assert_eq!(dst.len(), src.len());
    for (d, s) in dst.iter_mut().zip(src) {
        d.conditional_assign(s, choice);
    }
}

/// Oblivious extraction of bit `pos` (`0..8`) of `byte` — used right after
/// [`ct_select_byte`] to read the target bit of the selected right-block byte.
///
/// `byte >> pos` would be a shift by a *secret* amount; that is constant-time
/// on x86_64/aarch64 (the targets ore.rs ships to) but not guaranteed so on
/// every architecture. Here every candidate shift is a compile-time constant
/// and the result is chosen with a constant-time select, so the timing is
/// data-independent on all targets — defence-in-depth matching the oblivious
/// byte read above.
#[inline]
pub(crate) fn ct_bit(byte: u8, pos: u8) -> u8 {
    use subtle_ng::{ConditionallySelectable, ConstantTimeEq};
    let mut out = 0u8;
    out.conditional_assign(&(byte & 1), pos.ct_eq(&0));
    out.conditional_assign(&((byte >> 1) & 1), pos.ct_eq(&1));
    out.conditional_assign(&((byte >> 2) & 1), pos.ct_eq(&2));
    out.conditional_assign(&((byte >> 3) & 1), pos.ct_eq(&3));
    out.conditional_assign(&((byte >> 4) & 1), pos.ct_eq(&4));
    out.conditional_assign(&((byte >> 5) & 1), pos.ct_eq(&5));
    out.conditional_assign(&((byte >> 6) & 1), pos.ct_eq(&6));
    out.conditional_assign(&((byte >> 7) & 1), pos.ct_eq(&7));
    out
}

/// Per-block bitvector operations on a Right ciphertext block, one bit per
/// value in the block domain.
pub trait RightBitVec {
    /// Read bit `bit`. (The width-generic comparator lands with the Bit6
    /// scheme; the legacy comparator calls the inherent method.)
    #[allow(dead_code)]
    fn get_bit(&self, bit: usize) -> u8;
    /// The raw bitvector bytes, LSB-first within each byte (the same bit
    /// order as `RightBlock32::set_bit`), for bulk mask construction.
    fn as_mut_bytes(&mut self) -> &mut [u8];
}

impl RightBitVec for RightBlock32 {
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
    /// Block domain size. Block values are `0..DOMAIN`. Derived from
    /// [`BITS`](Self::BITS) so the two cannot disagree.
    const DOMAIN: usize = 1 << Self::BITS;
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
    type RightBlock = RightBlock8;
    // Fixed-draw Fisher–Yates, not the rejection-sampled Knuth shuffle:
    // Bit6's wire format is not frozen, so it adopts the constant-time,
    // ~9×-faster PRP construction. See `LemireFyPrp`.
    type Prp = crate::primitives::prp::LemireFyPrp<64>;
    type RoKeyBuf = [AesBlock; 64];
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// `ct_select_byte(block, idx) == block[idx]` for every block of length
    /// 1..=256 (the stated domain) and every in-range `idx`.
    #[kani::proof]
    #[kani::unwind(257)]
    fn ct_select_byte_equals_index_up_to_256() {
        let buf: [u8; 256] = kani::any();
        let len: usize = kani::any();
        kani::assume(len >= 1 && len <= 256);
        let idx: usize = kani::any();
        kani::assume(idx < len);
        let block = &buf[..len];
        assert_eq!(ct_select_byte(block, idx), block[idx]);
    }

    /// `ct_select_byte(block, idx) == block[idx]` for the two right-block
    /// sizes the comparators use (8 and 32 bytes), all contents, all
    /// in-range `idx`.
    #[kani::proof]
    #[kani::unwind(33)]
    fn ct_select_byte_equals_index_right_blocks() {
        let b8: [u8; 8] = kani::any();
        let i8: usize = kani::any();
        kani::assume(i8 < 8);
        assert_eq!(ct_select_byte(&b8, i8), b8[i8]);

        let b32: [u8; 32] = kani::any();
        let i32: usize = kani::any();
        kani::assume(i32 < 32);
        assert_eq!(ct_select_byte(&b32, i32), b32[i32]);
    }

    /// `ct_bit(byte, pos) == (byte >> pos) & 1` for every byte and every
    /// `pos` in `0..8`, and is 0 for every `pos >= 8` (exhaustive).
    #[kani::proof]
    fn ct_bit_equals_shift() {
        let byte: u8 = kani::any();
        let pos: u8 = kani::any();
        if pos < 8 {
            assert_eq!(ct_bit(byte, pos), (byte >> pos) & 1);
        } else {
            assert_eq!(ct_bit(byte, pos), 0);
        }
    }
}
