//! ore-rs is a Rust library for Order-Revealing Encryption (ORE). It lets you compare
//! encrypted values without the encryption key, so you can sort them and run range
//! queries.
//!
//! The library is based on the Block-ORE scheme by
//! [Lewi and Wu (2016)](https://eprint.iacr.org/2016/612.pdf) and is used in the
//! [CipherStash](https://cipherstash.com) searchable encryption platform.
//!
//! # Usage
//! ```toml
//! [dependencies]
//! ore-rs = "0.9"
//! ```
//!
//! # Choosing a scheme
//!
//! - [`scheme::bit2_w6`] (`OreAes128Bit6`) is recommended for new fixed-width data.
//!   It supports `bool`, integers up to 64 bits, `char`, `f32` and `f64`.
//! - [`scheme::chained`] (`OreAes128Bit6Chained`) supports strings, other
//!   variable-length data, and `u128` and `i128`. Strings are padded to a power of
//!   two by default, with a minimum of 16 bytes, to hide their exact length.
//! - [`scheme::bit2`] (`OreAes128`) is the legacy scheme. Use it for existing legacy
//!   ciphertexts or the `chrono` and `rust_decimal` types, enabled by the `chrono`
//!   and `decimal` features.
//!
//! Bit6 uses 6-bit blocks. It encrypts a `u64` about twice as fast as the legacy
//! scheme and produces a 28% smaller full ciphertext, measured on an Apple M1 Max
//! with hardware AES for 0.9.0. It also avoids the legacy scheme's leakage of
//! zero-byte runs.
//!
//! All three ciphertext formats are frozen. Bit6 and chained each take one 16-byte
//! key and an optional salt, such as a dataset or tenant identifier. The legacy
//! scheme requires two keys through `init(k1, k2)`.
//!
//! # Example: encrypt and compare
//!
//! Create a cipher with `init`, then use the [`OreEncrypt`] trait to encrypt values:
//!
//! ```rust
//! use ore_rs::{OreEncrypt, scheme::bit2_w6::OreAes128Bit6ChaCha20};
//!
//! // In production, use a random 16-byte key from your key management system.
//! let key = [0x2b; 16];
//! let ore = OreAes128Bit6ChaCha20::init(&key).unwrap();
//!
//! let a = 456u64.encrypt(&ore).unwrap();
//! let b = 1024u64.encrypt(&ore).unwrap();
//! assert!(a < b);
//! ```
//!
//! The result is a [`CipherText<S, N>`], where `S` is the scheme and `N` is the block
//! count. A `u64` uses 11 blocks under Bit6. Comparing ciphertexts with different
//! schemes or block counts is a compile error:
//!
//! ```compile_fail
//! # use ore_rs::{OreEncrypt, scheme::bit2_w6::OreAes128Bit6ChaCha20};
//! # let ore = OreAes128Bit6ChaCha20::init(&[0x2b; 16]).unwrap();
//! let a = 456u64.encrypt(&ore).unwrap();
//! let b = 1024u32.encrypt(&ore).unwrap(); // a u32 is 6 blocks
//!
//! let result = a > b; // compilation error
//! ```
//!
//! # Serialising and parsing
//!
//! Use [`OreOutput::to_bytes`] to serialise a ciphertext. When parsing it, specify
//! the scheme and block count. You can also compare serialised ciphertexts directly
//! with [`OreCipher::compare_raw_slices`]:
//!
//! ```rust
//! use ore_rs::{CipherText, OreCipher, OreEncrypt, OreOutput};
//! use ore_rs::scheme::bit2_w6::OreAes128Bit6ChaCha20;
//! use std::cmp::Ordering;
//!
//! let ore = OreAes128Bit6ChaCha20::init(&[0x2b; 16]).unwrap();
//! let a = 456u64.encrypt(&ore).unwrap();
//! let bytes: Vec<u8> = a.to_bytes();
//!
//! let parsed = CipherText::<OreAes128Bit6ChaCha20, 11>::from_slice(&bytes).unwrap();
//! assert!(parsed == a);
//!
//! let b = 1024u64.encrypt(&ore).unwrap().to_bytes();
//! assert_eq!(
//!     OreAes128Bit6ChaCha20::compare_raw_slices(&bytes, &b),
//!     Some(Ordering::Less)
//! );
//! ```
//!
//! Serde is not supported; use `to_bytes` and `from_slice` for serialisation.
//!
//! # Example: strings
//!
//! ```rust
//! use ore_rs::scheme::chained::OreAes128Bit6ChainedChaCha20;
//! use std::cmp::Ordering;
//!
//! let ore = OreAes128Bit6ChainedChaCha20::init(&[0x2b; 16]).unwrap();
//! let alice = ore.encrypt_str("alice").unwrap().to_bytes();
//! let bob = ore.encrypt_str("bob").unwrap().to_bytes();
//! assert_eq!(
//!     OreAes128Bit6ChainedChaCha20::compare_raw_slices(&alice, &bob),
//!     Some(Ordering::Less)
//! );
//! ```
//!
//! See [`scheme::chained`] for padding options, length limits and the information
//! revealed by comparisons.

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

#[cfg(feature = "chrono")]
mod chrono;
mod ciphertext;
#[cfg(feature = "decimal")]
mod decimal;
mod encrypt;
mod primitives;
pub mod scheme;
#[cfg(feature = "vitaminc")]
pub mod vitaminc;
pub use crate::ciphertext::*;

// Test the README examples with both default features and --all-features.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

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
pub use crate::encrypt::OreEncrypt;
use primitives::PrpError;
use std::cmp::Ordering;
use thiserror::Error;

/// Fixed-size byte array used as the input to the BlockORE encryption
/// routines. `N` is the number of plaintext bytes (one byte per ORE block).
/// The fixed-N encryption path caps `N` at 15 due to the AES-as-PRF input
/// packing in [`scheme::bit2`].
pub type PlainText<const N: usize> = [u8; N];

/// Errors returned by [`OreCipher`] initialisation and encryption.
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
    /// The OS or seeded RNG failed to produce random bytes (used for the
    /// per-ciphertext nonce).
    #[error("Randomness Error")]
    RandError(#[from] rand::Error),
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

/// A BlockORE cipher: a key-bound object that can encrypt fixed-N plaintexts
/// to ciphertexts whose byte-wise comparison matches the plaintext order.
///
/// Implementations associate concrete block types for the Left and Right
/// halves of a ciphertext (see [`Left`], [`Right`], [`CipherText`]) and
/// expose [`encrypt_left`](Self::encrypt_left)
/// for query-side ciphertexts, [`encrypt`](Self::encrypt) for indexable
/// ciphertexts, and [`compare_raw_slices`](Self::compare_raw_slices) for
/// comparing serialised ciphertext bytes without round-tripping through
/// typed values.
pub trait OreCipher: Sized {
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

    /// Encrypt `input` and return only the Left half of the ciphertext.
    /// Useful for query plaintexts compared against stored ciphertexts —
    /// the Left alone is enough to drive the comparator.
    fn encrypt_left<const N: usize>(&self, input: &PlainText<N>)
        -> Result<Left<Self, N>, OreError>;

    /// Encrypt `input` and return the full Left+Right ciphertext suitable
    /// for storage and subsequent comparison against any other ciphertext.
    fn encrypt<const N: usize>(
        &self,
        input: &PlainText<N>,
    ) -> Result<CipherText<Self, N>, OreError>;

    /// Compare two serialised ciphertexts (as produced by
    /// [`OreOutput::to_bytes`]) byte-for-byte without deserialising. Returns
    /// `None` if the slice lengths disagree (i.e., they encode ciphertexts
    /// over different `N`).
    fn compare_raw_slices(a: &[u8], b: &[u8]) -> Option<Ordering>;
}

#[cfg(test)]
#[macro_use]
extern crate quickcheck;
