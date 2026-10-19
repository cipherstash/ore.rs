#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
// Library code does not panic: it returns an error or carries the invariant
// in a type. Tests may. Clippy has no lint for `assert!`;
// `scripts/no-runtime-asserts.py` covers that in CI.
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic_in_result_fn
    )
)]

mod ciphertext;
mod primitives;
pub mod scheme;
mod term;
#[cfg(test)]
pub(crate) mod testing;
pub mod vitaminc;
pub(crate) use crate::ciphertext::*;
pub use crate::term::{Query, Term};

/// Timing-measurement entry points to private primitives, for the detached
/// `ct-dudect` crate. Enabled only by the `ct-bench` feature; not public API.
#[cfg(feature = "ct-bench")]
#[doc(hidden)]
pub mod ct_bench {
    use crate::primitives::prp::{oblivious, LemireFyPrp};
    use crate::primitives::{Prp, Symbol};

    /// Build the 64-element Bit6 PRP from a 512-byte draw stream and return
    /// one permuted value, so the construction is observably used. This is
    /// the builder the schemes use (the target's oblivious builder).
    pub fn lemire_fy_prp_from_stream(stream: &[u8; 512]) -> u8 {
        LemireFyPrp::<64>::from_stream(stream)
            .permute(Symbol::from_low_bits(0))
            .get()
    }

    fn from_stream_with(
        stream: &[u8; 512],
        build: fn(&[u8; 512], &mut [u8; 64], &mut [u8; 64]),
    ) -> u8 {
        LemireFyPrp::<64>::from_stream_with(stream, build)
            .permute(Symbol::from_low_bits(0))
            .get()
    }

    /// As [`lemire_fy_prp_from_stream`], through the reference builder:
    /// textbook Fisher–Yates with secret-indexed swaps and inverse fill.
    /// Not used by any scheme; here for before/after timing.
    pub fn lemire_fy_prp_from_stream_reference(stream: &[u8; 512]) -> u8 {
        from_stream_with(stream, oblivious::reference::build)
    }

    /// As [`lemire_fy_prp_from_stream`], through the byte-at-a-time
    /// `subtle_ng` oblivious builder whatever the target.
    pub fn lemire_fy_prp_from_stream_scalar_oblivious(stream: &[u8; 512]) -> u8 {
        from_stream_with(stream, oblivious::scalar::build)
    }

    /// As [`lemire_fy_prp_from_stream`], through the portable SWAR
    /// oblivious builder whatever the target.
    pub fn lemire_fy_prp_from_stream_swar_oblivious(stream: &[u8; 512]) -> u8 {
        from_stream_with(stream, oblivious::swar::build)
    }

    // -----------------------------------------------------------------
    // Mechanism isolation: the two halves of the reference builder, and a
    // control for each with the same work at public addresses. Each keeps
    // its table in one 64-byte-aligned line, as `LemireFyPrp<64>` does.
    // -----------------------------------------------------------------

    /// One 64-byte, line-aligned table.
    #[repr(C, align(64))]
    pub struct Line(pub [u8; 64]);

    /// Lemire draw for step `i`, reduced to `0..=i`: the builders' own
    /// [`oblivious::lemire_draw`], so the benches cannot drift from it.
    #[inline(always)]
    fn draw(stream: &[u8; 512], i: usize) -> usize {
        usize::from(oblivious::lemire_draw(stream, i))
    }

    /// The reference builder's Fisher–Yates swap loop alone (no inverse
    /// fill): swaps at the secret draw-derived index. The loop is
    /// `oblivious::reference::build`'s, restated so it can be timed
    /// without the fill; a test pins it to that builder's permutation.
    #[inline(never)]
    pub fn fy_swaps_only(stream: &[u8; 512], out: &mut Line) {
        for (k, p) in out.0.iter_mut().enumerate() {
            *p = k as u8;
        }
        for i in (1..64).rev() {
            let j = draw(stream, i);
            out.0.swap(i, j);
        }
    }

    /// Control for [`fy_swaps_only`]: the same draws and the same swaps,
    /// but at the public index `i - 1` (the draw is computed and kept live,
    /// then not used as an address).
    #[inline(never)]
    pub fn fy_swaps_public(stream: &[u8; 512], out: &mut Line) {
        for (k, p) in out.0.iter_mut().enumerate() {
            *p = k as u8;
        }
        for i in (1..64).rev() {
            core::hint::black_box(draw(stream, i));
            out.0.swap(i, i - 1);
        }
    }

    /// The permutation the builders build for `stream`, computed outside
    /// any measured region by the reference builder itself, to feed
    /// [`inverse_fill_only`].
    pub fn permutation_for(stream: &[u8; 512]) -> Line {
        let mut l = Line([0u8; 64]);
        let mut inverse = [0u8; 64];
        oblivious::reference::build(stream, &mut l.0, &mut inverse);
        l
    }

    /// The reference builder's inverse fill alone: `inverse[perm[k]] = k`,
    /// stores at secret offsets.
    #[inline(never)]
    pub fn inverse_fill_only(perm: &Line, out: &mut Line) {
        for (index, val) in perm.0.iter().enumerate() {
            out.0[*val as usize & 63] = index as u8;
        }
    }

    /// Control for [`inverse_fill_only`]: the same loads and stores, at the
    /// public offset `index` (the loaded value is kept live, not used as an
    /// address).
    #[inline(never)]
    pub fn inverse_fill_public(perm: &Line, out: &mut Line) {
        for (index, val) in perm.0.iter().enumerate() {
            core::hint::black_box(*val);
            out.0[index] = index as u8;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The isolated swap loop and inverse fill build exactly what the
        /// reference builder builds, so the isolation benches time the real
        /// construction.
        #[test]
        fn isolation_halves_match_the_reference_builder() {
            for seed in 0u8..16 {
                let stream: [u8; 512] =
                    core::array::from_fn(|k| (k as u8).wrapping_mul(167) ^ seed.wrapping_mul(29));
                let mut want_perm = [0u8; 64];
                let mut want_inverse = [0u8; 64];
                oblivious::reference::build(&stream, &mut want_perm, &mut want_inverse);

                let mut swaps = Line([0u8; 64]);
                fy_swaps_only(&stream, &mut swaps);
                assert_eq!(swaps.0, want_perm);

                let mut inverse = Line([0u8; 64]);
                inverse_fill_only(&permutation_for(&stream), &mut inverse);
                assert_eq!(inverse.0, want_inverse);
            }
        }
    }
}
use primitives::PrpError;
use std::cmp::Ordering;
use thiserror::Error;
use vitaminc_ore::OrderPlaintext;

/// Fixed-size block array, the input to the fixed-N encryption routines.
/// `N` is the block count. For the legacy scheme a block is a plaintext
/// byte; for Bit6 a 6-bit symbol. The fixed-N path caps `N` at 15 (legacy)
/// or 14 (Bit6) by the AES-as-PRF input packing.
pub(crate) type PlainText<const N: usize> = [u8; N];

/// Errors returned by scheme initialisation and encryption.
///
/// New schemes and policies add variants, so the enum is non-exhaustive.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OreError {
    /// Cipher initialisation failed (e.g., key material rejected by an
    /// underlying primitive).
    #[error("Failed to initialize cipher")]
    InitFailed,
    /// A pseudo-random permutation primitive returned an error.
    #[error(transparent)]
    PrpError(#[from] PrpError),
    /// The OS random number generator could not seed the scheme's
    /// generator, from which every per-ciphertext nonce is drawn.
    #[error("Randomness Error")]
    Random(#[from] vitaminc_random::RandomError),
    /// A text or bytes plaintext, whose width varies, on a fixed-width
    /// scheme. Only the chained scheme takes them.
    #[error("Variable-length plaintext on a fixed-width scheme")]
    VariableLength,
    /// The plaintext exceeds the maximum block count the wire format can
    /// represent (the chained scheme encodes the block count as a `u16`).
    #[error("Too many blocks")]
    TooManyBlocks,
    /// A string longer than the fixed length its padding policy pads to.
    #[error("String longer than its padding")]
    ExceedsPadding,
    /// A string longer than the cipher's ceiling
    /// (`scheme::chained::Options::max_bytes`).
    #[error("String longer than the cipher's maximum")]
    TooLong,
    /// A string that ends in NUL, refused by a padding policy: padded with
    /// NULs, it would encrypt the same as the string without them.
    #[error("String ends in NUL")]
    TrailingNul,
}

mod sealed {
    pub trait Sealed {}
}

/// An ORE scheme: encrypts a sealed [`OrderPlaintext`] to a stored
/// [`Term`] or a [`Query`], and compares the serialised bytes of either
/// without a key.
///
/// The plaintext comes from vitaminc-ore, which owns the encodings:
/// `vitaminc_ore::order()` makes one from a value and a target, and
/// [`vitaminc::BlockOre`] is the typed way in, which routes a plaintext to
/// the right engine by its width. A scheme here takes nothing else, so no
/// caller can hand it bytes that skipped the encoding.
///
/// Sealed: the schemes are this crate's. [`scheme::bit2_w6::OreAes128Bit6`]
/// takes fixed-width plaintexts of up to 10 bytes,
/// [`scheme::chained::OreAes128Bit6Chained`] takes any plaintext, and the
/// legacy [`scheme::bit2::OreAes128`] takes fixed-width plaintexts of up to
/// 15 bytes.
pub trait OreScheme: sealed::Sealed {
    /// Encrypt `plaintext` to a full ciphertext, for storage. Carries a
    /// random nonce, so one value has many terms, which compare `Equal`.
    fn encrypt_plaintext(&self, plaintext: &OrderPlaintext) -> Result<Term, OreError>;

    /// Encrypt `plaintext` to a query: the left half alone, which is what
    /// a comparison against a stored term needs from the other side.
    /// Deterministic under one key and salt.
    fn encrypt_query_plaintext(&self, plaintext: &OrderPlaintext) -> Result<Query, OreError>;

    /// Compare two serialised full ciphertexts (the bytes of two
    /// [`Term`]s) without a key. `None` if either is not a well-formed
    /// ciphertext of this scheme, or the two were not made to compare (a
    /// different block count, or for the chained scheme a different
    /// padding policy).
    fn compare_raw_slices(a: &[u8], b: &[u8]) -> Option<Ordering>;

    /// Compare a serialised query (the bytes of a [`Query`]) with a
    /// serialised full ciphertext: the order of the queried value against
    /// the stored one, `Less` when the query sorts first. `None` as
    /// [`compare_raw_slices`](Self::compare_raw_slices) is `None`, and
    /// for a full ciphertext passed as the query or a query as the term.
    fn compare_left_to_full(left: &[u8], full: &[u8]) -> Option<Ordering>;
}

/// A fixed-N BlockORE engine: encrypts `N` blocks to typed halves whose
/// serialised bytes compare in plaintext order. Crate-private: the block
/// count is only known when a plaintext arrives, so the public surface is
/// [`OreScheme`], over sealed plaintexts and bytes.
pub(crate) trait OreCipher: Sized {
    /// Block type for the Left half of a ciphertext (per-block PRF tag plus
    /// permuted plaintext byte).
    type LeftBlockType: CipherTextBlock;
    /// Block type for the Right half of a ciphertext (per-block masked
    /// truth-table row).
    type RightBlockType: CipherTextBlock;

    /// Wire-format header for this scheme's serialised artifacts, or
    /// `None` for the legacy headerless format. Schemes introduced from
    /// ORE v2 onwards must set this; see [`WireHeader`].
    const WIRE_HEADER: Option<WireHeader> = None;

    /// Number of distinct per-block symbols (`xt` values) the scheme
    /// produces: 256 for the byte-wide legacy scheme, 64 for Bit6. Parsers
    /// reject a ciphertext whose `xt` holds a symbol outside `0..SYMBOL_DOMAIN`,
    /// since the comparator indexes the right block by it.
    const SYMBOL_DOMAIN: usize = 256;

    /// Encrypt `input` and return only the Left half of the ciphertext:
    /// the query side.
    fn encrypt_left<const N: usize>(&self, input: &PlainText<N>)
        -> Result<Left<Self, N>, OreError>;

    /// Encrypt `input` and return the full Left+Right ciphertext suitable
    /// for storage and subsequent comparison against any other ciphertext.
    fn encrypt<const N: usize>(
        &self,
        input: &PlainText<N>,
    ) -> Result<CipherText<Self, N>, OreError>;
}

#[cfg(test)]
#[macro_use]
extern crate quickcheck;
