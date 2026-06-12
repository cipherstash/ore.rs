//! Vectorised kernels for the data-parallel inner loops of right-ciphertext
//! encoding, with portable scalar fallbacks (v2 plan §3).
//!
//! Two operations are covered:
//!
//! - **`gt_mask_xor_256`** — XOR the indicator mask `bit j = (table[j] > x)`
//!   into a 32-byte bitvector. This is the bulk form of the per-block
//!   unary encoding (a bytewise compare against a broadcast value, packed
//!   to a bitmask — `cmgt`+pack on NEON, `vpcmpgtb`+`vpmovmskb` on AVX2).
//! - **`lsb_mask_256`** — pack `bit j = blocks[j][0] & 1` (a stride-16
//!   gather over AES outputs) into a 32-byte bitvector.
//!
//! Bit order everywhere is LSB-first within each byte, matching
//! `RightBitVec::set_bit`.
//!
//! # Dispatch
//!
//! - **aarch64:** NEON is baseline — compile-time dispatch, no detection.
//! - **x86_64:** AVX2 via `is_x86_feature_detected!` (cached by `std`) for
//!   the indicator mask; the LSB gather stays scalar (the stride-16 gather
//!   doesn't pay on AVX2 without AVX-512 VBMI, and the scalar form is
//!   already branch-free and fast).
//! - **everything else:** scalar.
//!
//! # Constant-time discipline
//!
//! Every path in this module — scalar and vector — has a fixed trip count,
//! no data-dependent branches, and no data-dependent memory addressing
//! (the NEON `tbl` indices are compile-time constants). Equivalence
//! between scalar and vector paths is pinned by tests below; equivalence
//! against the per-bit reference is pinned in `prp.rs`.

use super::AesBlock;

/// XOR the indicator mask for `x` over `table` into `out`:
/// `out[j/8] ^= ((table[j] > x) as u8) << (j%8)`.
#[inline]
pub(crate) fn gt_mask_xor_256(table: &[u8; 256], x: u8, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 32);

    #[cfg(target_arch = "aarch64")]
    // SAFETY: NEON is baseline on aarch64; `out` length asserted above.
    unsafe {
        neon::gt_mask_xor_256(table, x, out);
        return;
    }

    #[cfg(target_arch = "x86_64")]
    if is_x86_feature_detected!("avx2") {
        // SAFETY: AVX2 presence just checked; `out` length asserted above.
        unsafe {
            avx2::gt_mask_xor_256(table, x, out);
            return;
        }
    }

    #[allow(unreachable_code)]
    scalar::gt_mask_xor_256(table, x, out);
}

/// Pack the LSB of byte 0 of each of 256 AES blocks into `out`:
/// `out[j/8] |= (blocks[j][0] & 1) << (j%8)` over zeroed positions
/// (callers pass `out` slots they own; bits are assigned, not accumulated).
#[inline]
pub(crate) fn lsb_mask_256(blocks: &[AesBlock], out: &mut [u8]) {
    debug_assert_eq!(blocks.len(), 256);
    debug_assert_eq!(out.len(), 32);

    #[cfg(target_arch = "aarch64")]
    // SAFETY: NEON is baseline on aarch64; lengths asserted above.
    unsafe {
        neon::lsb_mask_256(blocks, out);
        return;
    }

    #[allow(unreachable_code)]
    scalar::lsb_mask(blocks, out);
}

pub(crate) mod scalar {
    use super::AesBlock;

    pub(crate) fn gt_mask_xor_256(table: &[u8; 256], x: u8, out: &mut [u8]) {
        for (slot, chunk) in out.iter_mut().zip(table.chunks_exact(8)) {
            let mut byte = 0u8;
            for (bit, &p) in chunk.iter().enumerate() {
                byte |= u8::from(p > x) << bit;
            }
            *slot ^= byte;
        }
    }

    /// Length-generic scalar LSB pack: `blocks.len()` must be a multiple
    /// of 8 and equal to `out.len() * 8`.
    pub(crate) fn lsb_mask(blocks: &[AesBlock], out: &mut [u8]) {
        for (slot, chunk) in out.iter_mut().zip(blocks.chunks_exact(8)) {
            let mut byte = 0u8;
            for (bit, block) in chunk.iter().enumerate() {
                byte |= (block[0] & 1u8) << bit;
            }
            *slot = byte;
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod neon {
    use super::AesBlock;
    use core::arch::aarch64::*;

    /// Lane k holds `1 << (k % 8)`: the movemask bit-position vector.
    const BITPOS: [u8; 16] = [1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128];

    /// Pack a 16-lane 0x00/0xFF compare mask into 2 bytes, LSB-first. Each
    /// lane contributes a distinct power of two within its 8-lane half, so
    /// the horizontal add is exactly the movemask byte.
    #[inline(always)]
    unsafe fn pack_addv(m: uint8x16_t) -> (u8, u8) {
        let mb = vandq_u8(m, vld1q_u8(BITPOS.as_ptr()));
        (vaddv_u8(vget_low_u8(mb)), vaddv_u8(vget_high_u8(mb)))
    }

    #[target_feature(enable = "neon")]
    pub(super) unsafe fn gt_mask_xor_256(table: &[u8; 256], x: u8, out: &mut [u8]) {
        let xv = vdupq_n_u8(x);
        for i in 0..16 {
            let t = vld1q_u8(table.as_ptr().add(i * 16));
            let (lo, hi) = pack_addv(vcgtq_u8(t, xv));
            out[2 * i] ^= lo;
            out[2 * i + 1] ^= hi;
        }
    }

    /// `IDX[g]` places the 4 block-start bytes of 64-byte group `g`
    /// (offsets 0, 16, 32, 48) at lanes 4g..4g+3; all other lanes are 0xFF
    /// (out-of-range, yielding 0 in `tbl`).
    const TBL_IDX: [[u8; 16]; 4] = {
        let mut idx = [[0xFFu8; 16]; 4];
        let mut g = 0;
        while g < 4 {
            let mut k = 0;
            while k < 4 {
                idx[g][4 * g + k] = (16 * k) as u8;
                k += 1;
            }
            g += 1;
        }
        idx
    };

    /// Gather byte 0 of 16 consecutive 16-byte blocks (256 contiguous
    /// bytes) into one vector via constant-index 4-register table lookups.
    #[inline(always)]
    unsafe fn gather_block0_x16(base: *const u8) -> uint8x16_t {
        let r0 = vqtbl4q_u8(vld1q_u8_x4(base), vld1q_u8(TBL_IDX[0].as_ptr()));
        let r1 = vqtbl4q_u8(vld1q_u8_x4(base.add(64)), vld1q_u8(TBL_IDX[1].as_ptr()));
        let r2 = vqtbl4q_u8(vld1q_u8_x4(base.add(128)), vld1q_u8(TBL_IDX[2].as_ptr()));
        let r3 = vqtbl4q_u8(vld1q_u8_x4(base.add(192)), vld1q_u8(TBL_IDX[3].as_ptr()));
        vorrq_u8(vorrq_u8(r0, r1), vorrq_u8(r2, r3))
    }

    #[target_feature(enable = "neon")]
    pub(super) unsafe fn lsb_mask_256(blocks: &[AesBlock], out: &mut [u8]) {
        let p = blocks.as_ptr() as *const u8;
        let one = vdupq_n_u8(1);
        for i in 0..16 {
            let m = vtstq_u8(gather_block0_x16(p.add(i * 256)), one);
            let (lo, hi) = pack_addv(m);
            out[2 * i] = lo;
            out[2 * i + 1] = hi;
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use core::arch::x86_64::*;

    /// AVX2 has only *signed* byte compares; XOR-ing 0x80 into both sides
    /// maps unsigned `>` onto signed `>`.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn gt_mask_xor_256(table: &[u8; 256], x: u8, out: &mut [u8]) {
        let bias = _mm256_set1_epi8(i8::MIN);
        let xv = _mm256_xor_si256(_mm256_set1_epi8(x as i8), bias);
        for i in 0..8 {
            let t = _mm256_loadu_si256(table.as_ptr().add(i * 32) as *const __m256i);
            let gt = _mm256_cmpgt_epi8(_mm256_xor_si256(t, bias), xv);
            let mask = _mm256_movemask_epi8(gt) as u32;
            let m = mask.to_le_bytes();
            out[4 * i] ^= m[0];
            out[4 * i + 1] ^= m[1];
            out[4 * i + 2] ^= m[2];
            out[4 * i + 3] ^= m[3];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn rand_table(rng: &mut ChaCha20Rng) -> [u8; 256] {
        let mut t = [0u8; 256];
        rng.fill(&mut t[..]);
        t
    }

    #[test]
    fn gt_mask_dispatched_matches_scalar() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        for _ in 0..5_000 {
            let table = rand_table(&mut rng);
            let x: u8 = rng.gen();
            // Random starting contents so the XOR semantics are exercised.
            let mut a = [0u8; 32];
            rng.fill(&mut a[..]);
            let mut b = a;

            gt_mask_xor_256(&table, x, &mut a);
            scalar::gt_mask_xor_256(&table, x, &mut b);
            assert_eq!(a, b);
        }
    }

    #[test]
    fn lsb_mask_dispatched_matches_scalar() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        for _ in 0..5_000 {
            let mut blocks = [AesBlock::default(); 256];
            for block in blocks.iter_mut() {
                rng.fill(block.as_mut_slice());
            }
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];

            lsb_mask_256(&blocks, &mut a);
            scalar::lsb_mask(&blocks, &mut b);
            assert_eq!(a, b);
        }
    }
}
