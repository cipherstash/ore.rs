//! Oblivious Fisher–Yates builders for [`LemireFyPrp<64>`](super::LemireFyPrp).
//!
//! Each builder produces exactly the `permutation` and `inverse` tables of
//! the textbook builder (`reference`, test-only) for the same stream: the
//! same 63 Lemire-reduced draws, the same swap sequence. What changes is the
//! memory access pattern. The textbook builder swaps at the draw-derived
//! index `j` and fills `inverse` at the permutation's values, so the
//! *offsets* of its loads and stores within the table's cache line depend on
//! the key-derived stream. Those offsets stay inside one cache line, so the
//! cache does not see them, but dudect on Apple M4 measured the build time
//! depending on the swap sequence (the swaps carry it, the inverse fill does
//! not), consistent with store-to-load forwarding and memory disambiguation
//! on byte-granular accesses at secret offsets. The builders here never use
//! a secret value as an address:
//!
//! - `swar` holds each table as eight `u64` words and does every
//!   secret-indexed read and write as a masked pass over the words, with
//!   exact SWAR byte-equality masks. Portable fallback.
//! - `scalar` (tests and benches only) is the same construction a byte at
//!   a time with `subtle_ng` choices.
//! - `neon` (aarch64) holds both tables in eight 16-byte registers for the
//!   whole build: `tbl` fetches `perm[j]` by a broadcast index, and
//!   compare-and-select against a constant index vector writes back.
//!   Nothing touches memory but the stream reads until the two final
//!   stores.
//! - `ssse3` (x86_64, runtime detected) is the same register-resident shape
//!   with `pshufb` over four 16-byte chunks, the chunk chosen by a mask.
//!
//! The swap of `perm[i]` and `perm[j]`, with `a = perm[i]` and
//! `b = perm[j]` before it, moves `a` to position `j` and `b` to position
//! `i`; the inverse therefore changes at exactly two points,
//! `inverse[a] = j` and `inverse[b] = i`. Starting both tables at the
//! identity and applying that update with every swap keeps `inverse` the
//! inverse of `perm` throughout, so no separate fill is needed. When
//! `i == j`, `a == b` and both updates write the same value. `scalar`
//! applies the update in that form. The other builders use the equivalent
//! value-side form: the new inverse is `s ∘ inverse` with `s` the
//! transposition of `i` and `j`, so they exchange the *values* `i` and `j`
//! wherever they occur in `inverse`, which needs neither `a` nor `b`.
//!
//! Step `i` is public and `j <= i`, so `perm[j]` can only be in the part of
//! the table at or below `i`. `swar`, `neon` and `ssse3` search and rewrite
//! only the words or 16-byte chunks that cover `0..=i`, a bound that
//! depends on `i` alone.
//!
//! The draw arithmetic (`umulh` / `mul` on the 64-bit draw) is data
//! independent on the targets this crate ships to; the loop trip count is
//! fixed. The only secret-dependent values are register operands.

use zeroize::Zeroize;

/// The domain the oblivious builders support.
pub(crate) const DOMAIN: usize = 64;

/// Bytes of stream the builders consume: one 8-byte draw per step.
pub(crate) const STREAM_BYTES: usize = (DOMAIN - 1) * 8;

/// The Lemire-reduced draw for Fisher–Yates step `i` (`1..64`): draw
/// `63 - i`, as a little-endian u64, mapped to `0..=i` by multiply-high.
/// Identical to the indexed builder's reduction.
#[inline(always)]
fn lemire_draw(stream: &[u8], i: usize) -> u8 {
    let d = DOMAIN - 1 - i;
    let mut draw = [0u8; 8];
    draw.copy_from_slice(&stream[d * 8..d * 8 + 8]);
    let mut x = u64::from_le_bytes(draw);
    let j = ((x as u128 * (i as u128 + 1)) >> 64) as u8;
    // `draw` and `x` are copies of the key-derived keystream; the caller
    // wipes `stream`, so wipe these too (as the indexed builder does).
    draw.zeroize();
    x.zeroize();
    j
}

/// Build `perm` and `inverse` from `stream` (at least [`STREAM_BYTES`]
/// bytes) with a data-independent memory access pattern, using the fastest
/// oblivious builder for the target.
#[inline]
pub(crate) fn build(stream: &[u8], perm: &mut [u8; DOMAIN], inverse: &mut [u8; DOMAIN]) {
    assert!(stream.len() >= STREAM_BYTES);

    #[cfg(target_arch = "aarch64")]
    // SAFETY: NEON is baseline on aarch64; `stream` length asserted above.
    unsafe {
        neon::build(stream, perm, inverse)
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        #[cfg(target_arch = "x86_64")]
        if is_x86_feature_detected!("ssse3") {
            // SAFETY: SSSE3 presence just checked; `stream` length asserted.
            unsafe { ssse3::build(stream, perm, inverse) };
            return;
        }

        swar::build(stream, perm, inverse);
    }
}

/// The reference builder: textbook Fisher–Yates, swapping at the
/// draw-derived index, then `inverse[perm[k]] = k`. Both use a secret value
/// as an address, which is the timing channel the oblivious builders close,
/// so it is never compiled into a shipped build: it exists only as the
/// specification the oblivious builders are tested against, and for the
/// `ct-bench` before/after timing hooks.
#[cfg(any(test, feature = "ct-bench"))]
pub(crate) mod reference {
    use super::*;

    pub(crate) fn build(stream: &[u8], perm: &mut [u8; DOMAIN], inverse: &mut [u8; DOMAIN]) {
        assert!(stream.len() >= STREAM_BYTES);
        for (k, p) in perm.iter_mut().enumerate() {
            *p = k as u8;
        }
        for i in (1..DOMAIN).rev() {
            perm.swap(i, usize::from(lemire_draw(stream, i)));
        }
        for (k, v) in perm.iter().enumerate() {
            inverse[usize::from(*v)] = k as u8;
        }
    }
}

/// Byte-at-a-time oblivious builder with `subtle_ng` choices: full-scan
/// reads and masked full-table writes, the inverse maintained alongside.
/// The most direct form of the construction, kept as a second reference
/// for the tests and the timing benches; `subtle_ng`'s per-choice
/// optimisation barrier makes it about 17x slower than [`swar`], which the
/// dispatcher uses instead.
#[cfg(any(test, feature = "ct-bench"))]
pub(crate) mod scalar {
    use super::*;
    use subtle_ng::{ConditionallySelectable, ConstantTimeEq};

    pub(crate) fn build(stream: &[u8], perm: &mut [u8; DOMAIN], inverse: &mut [u8; DOMAIN]) {
        assert!(stream.len() >= STREAM_BYTES);
        for (k, (p, v)) in perm.iter_mut().zip(inverse.iter_mut()).enumerate() {
            *p = k as u8;
            *v = k as u8;
        }

        for i in (1..DOMAIN).rev() {
            let j = lemire_draw(stream, i);
            let i8_ = i as u8;
            // `i` is public: a direct read at it is not secret-indexed.
            let a = perm[i];
            let mut b = 0u8;
            for (k, p) in perm.iter().enumerate() {
                b.conditional_assign(p, (k as u8).ct_eq(&j));
            }

            // perm[j] = a, then perm[i] = b (public address).
            for (k, p) in perm.iter_mut().enumerate() {
                p.conditional_assign(&a, (k as u8).ct_eq(&j));
            }
            perm[i] = b;

            // inverse[a] = j, then inverse[b] = i.
            for (k, v) in inverse.iter_mut().enumerate() {
                let k = k as u8;
                v.conditional_assign(&j, k.ct_eq(&a));
                v.conditional_assign(&i8_, k.ct_eq(&b));
            }
        }
    }
}

/// Portable oblivious builder in 64-bit SWAR form: each table is eight
/// `u64` words, byte equality against a broadcast key is exact zero-byte
/// detection, and every secret-indexed read and write is a masked pass
/// over every word that could hold the entry (words `0..=i/8` at step `i`,
/// a public bound). The inverse is updated on the value side, as in the
/// NEON builder. Pure integer arithmetic with no `subtle_ng` optimisation barrier
/// per byte, so the compiler can keep the tables in registers.
#[cfg(any(not(target_arch = "aarch64"), test, feature = "ct-bench"))]
pub(crate) mod swar {
    use super::*;

    const LO7: u64 = 0x7f7f_7f7f_7f7f_7f7f;
    const ONES: u64 = 0x0101_0101_0101_0101;

    /// `0xff` in each byte of `x` that equals `key`, `0x00` elsewhere.
    /// Exact (no false positives from borrows): the high bit of
    /// `(z & 0x7f) + 0x7f` is set iff the low seven bits of `z` are not all
    /// zero, and OR-ing `z` adds the eighth.
    #[inline(always)]
    fn eq_mask(x: u64, key: u64) -> u64 {
        let z = x ^ key;
        let t = (z & LO7).wrapping_add(LO7);
        let m = !(t | z | LO7);
        (m >> 7).wrapping_mul(0xff)
    }

    /// Read `table[k]` from every word of `table`; `kb` is `k` in every
    /// byte.
    #[inline(always)]
    fn fetch(table: &[u64], index: &[u64], kb: u64) -> u8 {
        let mut r = 0u64;
        for (w, idx) in table.iter().zip(index) {
            r |= w & eq_mask(*idx, kb);
        }
        r |= r >> 32;
        r |= r >> 16;
        r |= r >> 8;
        r as u8
    }

    /// `table[k] = value` for the one `k` with `index[k] == key`.
    #[inline(always)]
    fn put(table: &mut [u64], index: &[u64], kb: u64, value: u64) {
        for (w, idx) in table.iter_mut().zip(index) {
            let m = eq_mask(*idx, kb);
            *w = (*w & !m) | (value & m);
        }
    }

    pub(crate) fn build(stream: &[u8], perm: &mut [u8; DOMAIN], inverse: &mut [u8; DOMAIN]) {
        assert!(stream.len() >= STREAM_BYTES);
        let mut index = [0u64; 8];
        for (w, word) in index.iter_mut().enumerate() {
            let mut b = [0u8; 8];
            for (k, byte) in b.iter_mut().enumerate() {
                *byte = (w * 8 + k) as u8;
            }
            *word = u64::from_le_bytes(b);
        }
        let mut p = index;
        let mut v = index;

        for i in (1..DOMAIN).rev() {
            // `i` is public, so are its word `w` and byte `lane`, and so is
            // every bound below; `j <= i` puts perm[j] in words `0..=w`.
            let (w, lane) = (i / 8, 8 * (i % 8));
            let ib = (i as u64).wrapping_mul(ONES);
            let jb = u64::from(lemire_draw(stream, i)).wrapping_mul(ONES);
            let a = (p[w] >> lane) & 0xff;
            let bb = u64::from(fetch(&p[..=w], &index[..=w], jb)).wrapping_mul(ONES);
            // perm[j] = a, then perm[i] = b.
            put(&mut p[..=w], &index[..=w], jb, a.wrapping_mul(ONES));
            p[w] = (p[w] & !(0xff << lane)) | ((bb & 0xff) << lane);
            // inverse = s ∘ inverse: exchange the values i and j.
            let flip = ib ^ jb;
            for word in v.iter_mut() {
                let m = eq_mask(*word, ib) | eq_mask(*word, jb);
                *word ^= flip & m;
            }
        }

        for (k, (pw, vw)) in p.iter().zip(v.iter()).enumerate() {
            perm[k * 8..k * 8 + 8].copy_from_slice(&pw.to_le_bytes());
            inverse[k * 8..k * 8 + 8].copy_from_slice(&vw.to_le_bytes());
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod neon {
    use super::{lemire_draw, DOMAIN};
    use core::arch::aarch64::*;

    /// `0, 1, …, 63`: the lane index of each table entry.
    const INDEX: [u8; DOMAIN] = {
        let mut t = [0u8; DOMAIN];
        let mut k = 0;
        while k < DOMAIN {
            t[k] = k as u8;
            k += 1;
        }
        t
    };

    /// Exchange the lane values `x` and `y` wherever they occur in `t`.
    #[inline(always)]
    unsafe fn swap_values(t: uint8x16_t, x: uint8x16_t, y: uint8x16_t) -> uint8x16_t {
        let to_y = vceqq_u8(t, x);
        let to_x = vceqq_u8(t, y);
        vbslq_u8(to_y, y, vbslq_u8(to_x, x, t))
    }

    /// The Fisher–Yates steps whose `i` lies in 16-lane chunk `C`
    /// (`i` from `16C + 15` down to `max(16C, 1)`).
    ///
    /// `C` is public, and so is everything it decides: `perm[i]` is read
    /// from chunk `C` by a one-register `tbl` at a public lane, and since
    /// `j <= i`, `perm[j]` lies in chunks `0..=C`, so it is fetched with a
    /// `(C + 1)`-register `tbl` and written back with a masked select over
    /// those chunks only. Chunks above `C` are final and not touched again.
    ///
    /// The inverse is updated on the value side. The swap moves the value at
    /// position `i` to `j` and vice versa, so the new inverse is
    /// `s ∘ inverse` with `s` the transposition of `i` and `j`: exchange the
    /// *values* `i` and `j` wherever they occur in `inverse`. That needs
    /// neither `perm[i]` nor `perm[j]`, so it stays off the loop-carried
    /// dependency through `perm`. It covers all four chunks.
    #[inline(always)]
    unsafe fn steps<const C: usize>(
        stream: &[u8],
        p: &mut [uint8x16_t; 4],
        v: &mut [uint8x16_t; 4],
        index: &[uint8x16_t; 4],
    ) {
        let low = if C == 0 { 1 } else { 16 * C };
        for i in (low..16 * (C + 1)).rev() {
            let iv = vdupq_n_u8(i as u8);
            let jv = vdupq_n_u8(lemire_draw(stream, i));
            // Every lane of `a` holds perm[i], every lane of `b` perm[j]:
            // register-table lookups, not memory accesses.
            let a = vqtbl1q_u8(p[C], vdupq_n_u8((i - 16 * C) as u8));
            let b = match C {
                0 => vqtbl1q_u8(p[0], jv),
                1 => vqtbl2q_u8(uint8x16x2_t(p[0], p[1]), jv),
                2 => vqtbl3q_u8(uint8x16x3_t(p[0], p[1], p[2]), jv),
                _ => vqtbl4q_u8(uint8x16x4_t(p[0], p[1], p[2], p[3]), jv),
            };
            // perm[j] = a, then perm[i] = b.
            for (chunk, idx) in p.iter_mut().zip(index).take(C + 1) {
                *chunk = vbslq_u8(vceqq_u8(*idx, jv), a, *chunk);
            }
            p[C] = vbslq_u8(vceqq_u8(index[C], iv), b, p[C]);
            // inverse = s ∘ inverse.
            for chunk in v.iter_mut() {
                *chunk = swap_values(*chunk, iv, jv);
            }
        }
    }

    /// # Safety
    ///
    /// Requires NEON (baseline on aarch64) and `stream.len() >=
    /// STREAM_BYTES` (asserted by the caller). The only memory operations
    /// are the load of the constant `INDEX`, the bounds-checked stream reads
    /// in `lemire_draw`, and the two 64-byte stores into `perm` and
    /// `inverse`, which are exclusive references to 64-byte arrays. Both
    /// tables live in vector registers in between: every `p[k]` / `v[k]`
    /// index is a compile-time constant after inlining.
    #[target_feature(enable = "neon")]
    pub(super) unsafe fn build(stream: &[u8], perm: &mut [u8; DOMAIN], inverse: &mut [u8; DOMAIN]) {
        let ix = vld1q_u8_x4(INDEX.as_ptr());
        let index = [ix.0, ix.1, ix.2, ix.3];
        let mut p = index;
        let mut v = index;

        steps::<3>(stream, &mut p, &mut v, &index);
        steps::<2>(stream, &mut p, &mut v, &index);
        steps::<1>(stream, &mut p, &mut v, &index);
        steps::<0>(stream, &mut p, &mut v, &index);

        vst1q_u8_x4(perm.as_mut_ptr(), uint8x16x4_t(p[0], p[1], p[2], p[3]));
        vst1q_u8_x4(inverse.as_mut_ptr(), uint8x16x4_t(v[0], v[1], v[2], v[3]));
    }
}

#[cfg(target_arch = "x86_64")]
mod ssse3 {
    use super::{lemire_draw, DOMAIN};
    use core::arch::x86_64::*;

    /// `select(m, x, y)`: `x` where the mask lane is all ones, else `y`.
    #[inline(always)]
    unsafe fn sel(m: __m128i, x: __m128i, y: __m128i) -> __m128i {
        _mm_or_si128(_mm_and_si128(m, x), _mm_andnot_si128(m, y))
    }

    /// Broadcast `table[k]` to every lane, `kv` holding `k` in every lane:
    /// `pshufb` each 16-byte chunk by `k & 15` and keep the chunk `k >> 4`
    /// by mask. Only the chunks in `t` are searched.
    #[inline(always)]
    unsafe fn fetch(t: &[__m128i], kv: __m128i) -> __m128i {
        let lo = _mm_and_si128(kv, _mm_set1_epi8(15));
        let hi = _mm_and_si128(_mm_srli_epi16(kv, 4), _mm_set1_epi8(15));
        let mut r = _mm_setzero_si128();
        for (c, chunk) in t.iter().enumerate() {
            let m = _mm_cmpeq_epi8(hi, _mm_set1_epi8(c as i8));
            r = _mm_or_si128(r, _mm_and_si128(m, _mm_shuffle_epi8(*chunk, lo)));
        }
        r
    }

    /// Exchange the lane values `x` and `y` wherever they occur in `t`.
    #[inline(always)]
    unsafe fn swap_values(t: __m128i, x: __m128i, y: __m128i) -> __m128i {
        let m = _mm_or_si128(_mm_cmpeq_epi8(t, x), _mm_cmpeq_epi8(t, y));
        _mm_xor_si128(t, _mm_and_si128(m, _mm_xor_si128(x, y)))
    }

    /// The steps whose `i` lies in chunk `C`; the same shape as the NEON
    /// builder's `steps` (public chunk bounds, value-side inverse).
    #[inline(always)]
    unsafe fn steps<const C: usize>(
        stream: &[u8],
        p: &mut [__m128i; 4],
        v: &mut [__m128i; 4],
        index: &[__m128i; 4],
    ) {
        let low = if C == 0 { 1 } else { 16 * C };
        for i in (low..16 * (C + 1)).rev() {
            let iv = _mm_set1_epi8(i as i8);
            let jv = _mm_set1_epi8(lemire_draw(stream, i) as i8);
            let a = _mm_shuffle_epi8(p[C], _mm_set1_epi8((i - 16 * C) as i8));
            let b = fetch(&p[..=C], jv);
            // perm[j] = a, then perm[i] = b.
            for (chunk, idx) in p.iter_mut().zip(index).take(C + 1) {
                *chunk = sel(_mm_cmpeq_epi8(*idx, jv), a, *chunk);
            }
            p[C] = sel(_mm_cmpeq_epi8(index[C], iv), b, p[C]);
            // inverse = s ∘ inverse.
            for chunk in v.iter_mut() {
                *chunk = swap_values(*chunk, iv, jv);
            }
        }
    }

    /// # Safety
    ///
    /// Requires SSSE3 (checked by the caller) and `stream.len() >=
    /// STREAM_BYTES` (asserted by the caller). Unaligned stores cover
    /// exactly the 64-byte `perm` and `inverse` arrays.
    #[target_feature(enable = "ssse3")]
    pub(super) unsafe fn build(stream: &[u8], perm: &mut [u8; DOMAIN], inverse: &mut [u8; DOMAIN]) {
        let mut index = [_mm_setzero_si128(); 4];
        for (c, chunk) in index.iter_mut().enumerate() {
            *chunk = _mm_add_epi8(
                _mm_set1_epi8((c * 16) as i8),
                _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            );
        }
        let mut p = index;
        let mut v = index;

        steps::<3>(stream, &mut p, &mut v, &index);
        steps::<2>(stream, &mut p, &mut v, &index);
        steps::<1>(stream, &mut p, &mut v, &index);
        steps::<0>(stream, &mut p, &mut v, &index);

        for (c, (pc, vc)) in p.iter().zip(v.iter()).enumerate() {
            _mm_storeu_si128(perm.as_mut_ptr().add(c * 16) as *mut __m128i, *pc);
            _mm_storeu_si128(inverse.as_mut_ptr().add(c * 16) as *mut __m128i, *vc);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Tables = ([u8; DOMAIN], [u8; DOMAIN]);

    fn run(builder: fn(&[u8], &mut [u8; DOMAIN], &mut [u8; DOMAIN]), stream: &[u8]) -> Tables {
        let mut perm = [0u8; DOMAIN];
        let mut inverse = [0u8; DOMAIN];
        builder(stream, &mut perm, &mut inverse);
        (perm, inverse)
    }

    /// Spread an arbitrary-length seed over a full stream so every draw is
    /// exercised, not only the prefix quickcheck happens to fill.
    fn stream_from(seed: &[u8]) -> [u8; STREAM_BYTES] {
        let mut s = [0u8; STREAM_BYTES];
        let mut rng = <rand_chacha::ChaCha20Rng as rand::SeedableRng>::seed_from_u64(
            seed.iter()
                .fold(0u64, |h, &b| h.wrapping_mul(131).wrapping_add(u64::from(b))),
        );
        rand::RngCore::fill_bytes(&mut rng, &mut s);
        for (d, b) in s.iter_mut().zip(seed) {
            *d ^= *b;
        }
        s
    }

    quickcheck! {
        /// The dispatched builder (NEON on aarch64, SSSE3 or SWAR on
        /// x86_64, SWAR elsewhere) builds the reference tables.
        fn dispatched_matches_reference(seed: Vec<u8>) -> bool {
            let s = stream_from(&seed);
            run(build, &s) == run(reference::build, &s)
        }

        /// The portable SWAR builder builds the reference tables on every
        /// target, not only where it is dispatched.
        fn swar_matches_reference(seed: Vec<u8>) -> bool {
            let s = stream_from(&seed);
            run(swar::build, &s) == run(reference::build, &s)
        }

        /// So does the byte-at-a-time `subtle_ng` builder.
        fn scalar_matches_reference(seed: Vec<u8>) -> bool {
            let s = stream_from(&seed);
            run(scalar::build, &s) == run(reference::build, &s)
        }
    }

    /// Edge streams: all-zero draws (every `j = 0`), all-ones draws (every
    /// `j = i`, the identity swaps), and alternating patterns.
    #[test]
    fn builders_match_reference_on_edge_streams() {
        for fill in [0x00u8, 0xff, 0x55, 0xaa, 0x80] {
            let s = [fill; STREAM_BYTES];
            let want = run(reference::build, &s);
            assert_eq!(run(build, &s), want, "dispatched, fill {fill:#04x}");
            assert_eq!(run(swar::build, &s), want, "swar, fill {fill:#04x}");
            assert_eq!(run(scalar::build, &s), want, "scalar, fill {fill:#04x}");
        }
    }

    /// The reference tables are a permutation of `0..64` and its inverse,
    /// so matching them means every builder builds one.
    #[test]
    fn reference_builds_a_permutation_and_its_inverse() {
        let (perm, inverse) = run(reference::build, &stream_from(b"reference"));
        for (k, p) in perm.iter().enumerate() {
            assert_eq!(usize::from(inverse[usize::from(*p)]), k);
        }
    }

    /// One byte short of a full stream is refused.
    #[test]
    #[should_panic]
    fn build_rejects_a_short_stream() {
        run(build, &[0u8; STREAM_BYTES - 1]);
    }
}
