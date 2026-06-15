//! Variable-length / chained-prefix BlockORE over 6-bit blocks.
//!
//! Lifts the fixed-N packed-prefix cap (≤ 14 blocks) by deriving every
//! per-block secret from an incremental **AES-CMAC accumulator** over the
//! prefix, instead of packing the raw prefix into one AES block. This enables
//! arbitrary-length plaintexts — strings in particular. Design:
//! `docs/plans/2026-06-15-ore-v2-cmac-accumulator-spec.md` (the A2 gate).
//!
//! Per block `n` (prefix `x[0..n-1]`, accumulator state `S_n`):
//! - **PRP** `π_n` (shape ii): keystream = `STREAM_BLOCKS` CMAC tags on the
//!   `PRP_STREAM` branch → `LemireFyPrp::from_stream` (no per-block key
//!   schedule).
//! - **left tag** `f[n] = ro(n, xt[n])` — the `RO_KEY` branch at the permuted
//!   symbol (so the left/right masks cancel at compare time).
//! - **right block**: `H(ro(n, j), nonce) ⊕ indicator`, as the fixed-N scheme.
//!
//! Comparison is lexicographic: scan `min(len_a, len_b)` blocks; if a prefix
//! matches throughout, the shorter sorts first. Common-prefix-length leakage is
//! the intended, query-time-scoped leakage (plan §5b).

use std::cell::RefCell;
use std::cmp::Ordering;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use subtle_ng::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;

use crate::ciphertext::{parse_header, ParseError};
use crate::primitives::cmac::{
    final_block, prefix_block, CmacAccumulator, BRANCH_PRP_STREAM, BRANCH_RO_KEY, WIDTH_BIT6,
};
use crate::primitives::hash::FixedPiZ2Hash;
use crate::primitives::prp::LemireFyPrp;
use crate::primitives::{AesBlock, Hash, HashKey, Prp};
use crate::scheme::decompose::{decompose_6bit, num_blocks_6bit};
use crate::scheme::width::ct_select_byte;
use crate::OreError;

const VERSION: u8 = 0x02;
const SCHEME_ID: u8 = 0x03;
const DOMAIN: usize = 64;
/// CMAC tags per block for the PRP keystream: ⌈(DOMAIN−1)·8 / 16⌉ = 32.
const STREAM_BLOCKS: usize = 32;
const F_LEN: usize = 16;
const RIGHT_LEN: usize = DOMAIN / 8; // 8
const HEADER_LEN: usize = 4;
const NONCE_LEN: usize = 16;

/// Domain-separation label for deriving the accumulator key (spec §3).
const ACC_KEY_LABEL: [u8; 16] = *b"ORE.v2.chain.acc";

/// Serialised length of a full ciphertext with `count` blocks.
#[inline]
fn total_len(count: usize) -> usize {
    HEADER_LEN + count + count * F_LEN + NONCE_LEN + count * RIGHT_LEN
}

// Raw-byte accessors into a serialised full ciphertext (see `to_bytes`).
#[inline]
fn xt_at(s: &[u8], i: usize) -> u8 {
    s[HEADER_LEN + i]
}
#[inline]
fn f_at(s: &[u8], count: usize, i: usize) -> &[u8] {
    let o = HEADER_LEN + count + i * F_LEN;
    &s[o..o + F_LEN]
}
#[inline]
fn nonce_at(s: &[u8], count: usize) -> &[u8] {
    let o = HEADER_LEN + count + count * F_LEN;
    &s[o..o + NONCE_LEN]
}
#[inline]
fn right_at(s: &[u8], count: usize, i: usize) -> &[u8] {
    let o = HEADER_LEN + count + count * F_LEN + NONCE_LEN + i * RIGHT_LEN;
    &s[o..o + RIGHT_LEN]
}

/// Left half of a chained ciphertext: per-block permuted symbol + tag.
#[derive(Clone, Debug)]
pub struct VarLeft {
    xt: Vec<u8>,
    f: Vec<[u8; F_LEN]>,
}

/// Right half: per-ciphertext nonce + per-block masked bitvectors.
#[derive(Clone, Debug)]
pub struct VarRight {
    nonce: [u8; NONCE_LEN],
    blocks: Vec<[u8; RIGHT_LEN]>,
}

/// Full variable-length ciphertext.
#[derive(Clone, Debug)]
pub struct VarCipherText {
    left: VarLeft,
    right: VarRight,
}

impl VarLeft {
    /// `header ‖ xt ‖ f` (no nonce/right half).
    pub fn to_bytes(&self) -> Vec<u8> {
        let count = self.xt.len();
        let mut out = Vec::with_capacity(HEADER_LEN + count + count * F_LEN);
        out.extend_from_slice(&[VERSION, SCHEME_ID]);
        out.extend_from_slice(&(count as u16).to_be_bytes());
        out.extend_from_slice(&self.xt);
        for fb in &self.f {
            out.extend_from_slice(fb);
        }
        out
    }
}

impl VarCipherText {
    /// `header ‖ xt ‖ f ‖ nonce ‖ right`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let count = self.left.xt.len();
        let mut out = Vec::with_capacity(total_len(count));
        out.extend_from_slice(&[VERSION, SCHEME_ID]);
        out.extend_from_slice(&(count as u16).to_be_bytes());
        out.extend_from_slice(&self.left.xt);
        for fb in &self.left.f {
            out.extend_from_slice(fb);
        }
        out.extend_from_slice(&self.right.nonce);
        for rb in &self.right.blocks {
            out.extend_from_slice(rb);
        }
        out
    }

    /// Parse the bytes produced by [`Self::to_bytes`].
    pub fn from_slice(data: &[u8]) -> Result<Self, ParseError> {
        let ((ver, sid, count), _body) = parse_header(data)?;
        if ver != VERSION || sid != SCHEME_ID {
            return Err(ParseError);
        }
        if data.len() != total_len(count) {
            return Err(ParseError);
        }
        let xt = data[HEADER_LEN..HEADER_LEN + count].to_vec();
        let mut f = Vec::with_capacity(count);
        for n in 0..count {
            let mut fb = [0u8; F_LEN];
            fb.copy_from_slice(f_at(data, count, n));
            f.push(fb);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_at(data, count));
        let mut blocks = Vec::with_capacity(count);
        for n in 0..count {
            let mut rb = [0u8; RIGHT_LEN];
            rb.copy_from_slice(right_at(data, count, n));
            blocks.push(rb);
        }
        Ok(VarCipherText {
            left: VarLeft { xt, f },
            right: VarRight { nonce, blocks },
        })
    }
}

/// Variable-length / chained-prefix ORE cipher (6-bit blocks).
pub struct OreAes128Bit6Chained<R: Rng + SeedableRng> {
    /// Dedicated CMAC accumulator key (subsumes the fixed-N `prf1`/`prf2`).
    k_acc: [u8; 16],
    rng: RefCell<R>,
}

/// Convenience alias backed by `ChaCha20Rng`.
pub type OreAes128Bit6ChainedChaCha20 = OreAes128Bit6Chained<ChaCha20Rng>;

impl<R: Rng + SeedableRng> OreAes128Bit6Chained<R> {
    /// Initialise from two 16-byte keys. The accumulator key is derived from
    /// `k1` by a labelled AES call (spec §3 open question 1: `k2` is currently
    /// unused for this scheme).
    pub fn init(k1: &[u8; 16], _k2: &[u8; 16]) -> Result<Self, OreError> {
        let cipher = Aes128::new(GenericArray::from_slice(k1));
        let mut k_acc = ACC_KEY_LABEL;
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut k_acc));
        Ok(Self {
            k_acc,
            rng: RefCell::new(R::from_entropy()),
        })
    }

    /// Derive the per-block PRP from the accumulator's `PRP_STREAM` branch.
    fn prp_at(&self, acc: &CmacAccumulator, n: u16) -> Result<LemireFyPrp<DOMAIN>, OreError> {
        let mut stream = [0u8; STREAM_BLOCKS * 16];
        for (c, chunk) in stream.chunks_mut(16).enumerate() {
            chunk.copy_from_slice(&acc.finalize(&final_block(
                BRANCH_PRP_STREAM,
                n,
                c as u16,
                WIDTH_BIT6,
            )));
        }
        let prp = LemireFyPrp::<DOMAIN>::from_stream(&stream)?;
        stream.zeroize();
        Ok(prp)
    }

    /// Full Left+Right ciphertext for `x` (one 6-bit symbol per element).
    pub fn encrypt_var(&self, x: &[u8]) -> Result<VarCipherText, OreError> {
        let count = x.len();
        debug_assert!(x.iter().all(|&b| (b as usize) < DOMAIN));
        debug_assert!(count <= u16::MAX as usize);

        let mut acc = CmacAccumulator::new(&self.k_acc);
        let mut nonce = [0u8; NONCE_LEN];
        self.rng.borrow_mut().try_fill(&mut nonce)?;
        let hasher = FixedPiZ2Hash::new(HashKey::from_slice(&nonce));

        let mut xt = Vec::with_capacity(count);
        let mut f = Vec::with_capacity(count);
        let mut blocks = Vec::with_capacity(count);

        for (n, &sym) in x.iter().enumerate() {
            let n16 = n as u16;
            let prp = self.prp_at(&acc, n16)?;
            let permuted = prp.permute(sym)?;
            xt.push(permuted);

            // ro_key for every domain value; f[n] = ro(n, xt[n]).
            let mut ro = [AesBlock::default(); DOMAIN];
            for (j, blk) in ro.iter_mut().enumerate() {
                blk.copy_from_slice(&acc.finalize(&final_block(
                    BRANCH_RO_KEY,
                    n16,
                    j as u16,
                    WIDTH_BIT6,
                )));
            }
            let mut fb = [0u8; F_LEN];
            fb.copy_from_slice(ro[permuted as usize].as_slice());
            f.push(fb);

            // right block = H-mask ⊕ indicator (trashes `ro`).
            let mut rb = [0u8; RIGHT_LEN];
            hasher.hash_all_into(&mut ro, &mut rb);
            prp.indicator_mask_xor(sym, &mut rb);
            blocks.push(rb);

            acc.absorb(&prefix_block(n16, sym));
        }

        Ok(VarCipherText {
            left: VarLeft { xt, f },
            right: VarRight { nonce, blocks },
        })
    }

    /// Left-only ciphertext (smaller; for query plaintexts).
    pub fn encrypt_left_var(&self, x: &[u8]) -> Result<VarLeft, OreError> {
        let count = x.len();
        debug_assert!(x.iter().all(|&b| (b as usize) < DOMAIN));

        let mut acc = CmacAccumulator::new(&self.k_acc);
        let mut xt = Vec::with_capacity(count);
        let mut f = Vec::with_capacity(count);

        for (n, &sym) in x.iter().enumerate() {
            let n16 = n as u16;
            let prp = self.prp_at(&acc, n16)?;
            let permuted = prp.permute(sym)?;
            xt.push(permuted);
            f.push(acc.finalize(&final_block(
                BRANCH_RO_KEY,
                n16,
                permuted as u16,
                WIDTH_BIT6,
            )));
            acc.absorb(&prefix_block(n16, sym));
        }
        Ok(VarLeft { xt, f })
    }

    /// Encrypt a string (UTF-8 bytes → MSB-first 6-bit blocks).
    pub fn encrypt_str(&self, s: &str) -> Result<VarCipherText, OreError> {
        self.encrypt_var(&str_to_blocks(s))
    }

    /// Left-only string ciphertext.
    pub fn encrypt_left_str(&self, s: &str) -> Result<VarLeft, OreError> {
        self.encrypt_left_var(&str_to_blocks(s))
    }

    /// Compare two serialised full ciphertexts (lexicographic; shorter prefix
    /// sorts first). `None` if either is not a well-formed ciphertext of this
    /// scheme.
    pub fn compare_raw_slices(a: &[u8], b: &[u8]) -> Option<Ordering> {
        let ((va, sa, ca), _) = parse_header(a).ok()?;
        let ((vb, sb, cb), _) = parse_header(b).ok()?;
        if va != VERSION || sa != SCHEME_ID || vb != VERSION || sb != SCHEME_ID {
            return None;
        }
        if a.len() != total_len(ca) || b.len() != total_len(cb) {
            return None;
        }

        // Constant-time scan of the shared prefix for the first differing block.
        let min_count = ca.min(cb);
        let mut is_equal = Choice::from(1u8);
        let mut l: u64 = 0;
        for n in 0..min_count {
            let differs = !xt_at(a, n).ct_eq(&xt_at(b, n)) | !f_at(a, ca, n).ct_eq(f_at(b, cb, n));
            l.conditional_assign(&(n as u64), is_equal & differs);
            is_equal.conditional_assign(&Choice::from(0u8), is_equal & differs);
        }

        if bool::from(is_equal) {
            // Shared prefix matches throughout — shorter sorts first.
            return Some(ca.cmp(&cb));
        }

        let l = l as usize;
        let hasher = FixedPiZ2Hash::new(HashKey::from_slice(nonce_at(b, cb)));
        let h = hasher.hash(f_at(a, ca, l));
        let permuted = xt_at(a, l);
        let byte = ct_select_byte(right_at(b, cb, l), (permuted / 8) as usize);
        let test = ((byte >> (permuted % 8)) & 1) ^ h;
        Some(if test == 1 {
            Ordering::Greater
        } else {
            Ordering::Less
        })
    }
}

impl<R: Rng + SeedableRng> Drop for OreAes128Bit6Chained<R> {
    fn drop(&mut self) {
        self.k_acc.zeroize();
    }
}

fn str_to_blocks(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let nb = num_blocks_6bit(bytes.len());
    let mut blocks = vec![0u8; nb];
    if nb > 0 {
        decompose_6bit(bytes, &mut blocks);
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ore() -> OreAes128Bit6ChainedChaCha20 {
        OreAes128Bit6Chained::init(&[0x11; 16], &[0x22; 16]).unwrap()
    }

    fn cmp(c: &OreAes128Bit6ChainedChaCha20, a: &str, b: &str) -> Ordering {
        let ca = c.encrypt_str(a).unwrap().to_bytes();
        let cb = c.encrypt_str(b).unwrap().to_bytes();
        OreAes128Bit6ChainedChaCha20::compare_raw_slices(&ca, &cb).unwrap()
    }

    #[test]
    fn string_total_order_matches_lexicographic() {
        let c = ore();
        // Includes shared prefixes of different lengths and beyond 14 blocks.
        let mut words = [
            "",
            "a",
            "ab",
            "abc",
            "abd",
            "ac",
            "b",
            "banana",
            "bananas",
            "the quick brown fox jumps over the lazy dog",
            "the quick brown fox jumps over the lazy dog.",
            "zzz",
        ];
        for &a in &words {
            for &b in &words {
                assert_eq!(cmp(&c, a, b), a.cmp(b), "order mismatch for {a:?} vs {b:?}");
            }
        }
        words.sort();
        // sanity: sort is stable and the list is what we expect
        assert_eq!(words[0], "");
    }

    #[test]
    fn equality_same_plaintext_across_nonces() {
        let c = ore();
        let a = c.encrypt_str("hello world").unwrap().to_bytes();
        let b = c.encrypt_str("hello world").unwrap().to_bytes();
        assert_ne!(a, b, "nonces should differ"); // different nonce streams
        assert_eq!(
            OreAes128Bit6ChainedChaCha20::compare_raw_slices(&a, &b),
            Some(Ordering::Equal)
        );
    }

    #[test]
    fn serialize_roundtrip() {
        let c = ore();
        let ct = c.encrypt_str("roundtrip me").unwrap();
        let bytes = ct.to_bytes();
        let parsed = VarCipherText::from_slice(&bytes).unwrap();
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn beyond_packed_cap() {
        // > 14 6-bit blocks (the fixed-N cap) must work and order correctly.
        let c = ore();
        let long_a = "aaaaaaaaaaaaaaaaaaaaaaaa"; // 24 bytes -> 32 blocks
        let long_b = "aaaaaaaaaaaaaaaaaaaaaaab";
        assert_eq!(cmp(&c, long_a, long_b), Ordering::Less);
        assert_eq!(cmp(&c, long_a, long_a), Ordering::Equal);
    }

    #[test]
    fn cross_scheme_bytes_rejected() {
        let c = ore();
        let mut bytes = c.encrypt_str("x").unwrap().to_bytes();
        bytes[1] = 0x02; // pretend it's the fixed-N scheme id
        assert_eq!(
            OreAes128Bit6ChainedChaCha20::compare_raw_slices(&bytes, &bytes),
            None
        );
    }

    #[test]
    fn empty_string_sorts_first() {
        let c = ore();
        assert_eq!(cmp(&c, "", "a"), Ordering::Less);
        assert_eq!(cmp(&c, "", ""), Ordering::Equal);
    }
}
