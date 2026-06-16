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
use crate::primitives::cmac::{final_block, prefix_block, Branch, CmacAccumulator, WIDTH_BIT6};
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

/// Serialised length of a left-only ciphertext (`header ‖ xt ‖ f`) — the prefix
/// of a full ciphertext, with no nonce/right half. Matches `VarLeft::to_bytes`.
#[inline]
fn left_len(count: usize) -> usize {
    HEADER_LEN + count + count * F_LEN
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
    /// Initialise from a single 16-byte key. Unlike the fixed-N schemes (which
    /// key two PRFs), the chained scheme is **single-key by design**: the CMAC
    /// accumulator derives every per-block secret from one key via branch tags
    /// (spec §3), so there is no second key. The accumulator key is `k1` run
    /// through a labelled AES call for domain separation.
    pub fn init(k1: &[u8; 16]) -> Result<Self, OreError> {
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
                Branch::PrpStream,
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
        if count > u16::MAX as usize {
            return Err(OreError::TooManyBlocks);
        }

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
                    Branch::RoKey,
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

            // `ro` held the key-derived RO_KEY tags (then the H outputs); wipe
            // it before the next block (matches the bit2_w6 scratch-buffer wipe).
            for blk in ro.iter_mut() {
                blk.as_mut_slice().zeroize();
            }

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
        if count > u16::MAX as usize {
            return Err(OreError::TooManyBlocks);
        }

        let mut acc = CmacAccumulator::new(&self.k_acc);
        let mut xt = Vec::with_capacity(count);
        let mut f = Vec::with_capacity(count);

        for (n, &sym) in x.iter().enumerate() {
            let n16 = n as u16;
            let prp = self.prp_at(&acc, n16)?;
            let permuted = prp.permute(sym)?;
            xt.push(permuted);
            f.push(acc.finalize(&final_block(
                Branch::RoKey,
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
        // Only `a`'s left half and `b`'s right half are read (Lewi-Wu
        // asymmetry); the left-only query path is `compare_left_to_full`.
        Some(Self::compare_views(a, ca, b, cb))
    }

    /// Compare a left-only (query) ciphertext `left` — produced by
    /// [`Self::encrypt_left_var`]/[`Self::encrypt_left_str`] — against a stored
    /// full ciphertext `full`. This is the Lewi-Wu query path: a comparison
    /// needs only the query's left half (`xt`/`f`) and the stored ciphertext's
    /// right half, so the smaller left-only artifact suffices and the stored
    /// right half reveals nothing at rest. Returns `left`'s order relative to
    /// `full` (`Less` ⇒ the query plaintext sorts before the stored one).
    /// `None` if either input is malformed.
    pub fn compare_left_to_full(left: &[u8], full: &[u8]) -> Option<Ordering> {
        let ((vl, sl, cl), _) = parse_header(left).ok()?;
        let ((vf, sf, cf), _) = parse_header(full).ok()?;
        if vl != VERSION || sl != SCHEME_ID || vf != VERSION || sf != SCHEME_ID {
            return None;
        }
        // `left` is `header ‖ xt ‖ f` (no nonce/right); `full` is complete.
        if left.len() != left_len(cl) || full.len() != total_len(cf) {
            return None;
        }
        Some(Self::compare_views(left, cl, full, cf))
    }

    /// Core comparator. `a` supplies the **left view** (`header ‖ xt ‖ f` — the
    /// layout is identical for a `VarLeft` and the left prefix of a full
    /// ciphertext, so the `xt_at`/`f_at` accessors work on either); `b` supplies
    /// the **right half**. Constant-time scan of the shared prefix; if it
    /// matches throughout, the shorter sorts first; otherwise the first
    /// differing block is resolved via the random oracle against `b`'s right
    /// block. `a` reads only `xt`/`f`, `b` reads `xt`/`f`/`nonce`/`right`.
    fn compare_views(a: &[u8], ca: usize, b: &[u8], cb: usize) -> Ordering {
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
            return ca.cmp(&cb);
        }

        let l = l as usize;
        let hasher = FixedPiZ2Hash::new(HashKey::from_slice(nonce_at(b, cb)));
        let h = hasher.hash(f_at(a, ca, l));
        let permuted = xt_at(a, l);
        let byte = ct_select_byte(right_at(b, cb, l), (permuted / 8) as usize);
        let test = ((byte >> (permuted % 8)) & 1) ^ h;
        if test == 1 {
            Ordering::Greater
        } else {
            Ordering::Less
        }
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
        OreAes128Bit6Chained::init(&[0x11; 16]).unwrap()
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
    fn left_query_path_and_artifact_rejection() {
        let c = ore();
        let left = c.encrypt_left_str("hi").unwrap().to_bytes();
        let full = c.encrypt_str("hi").unwrap().to_bytes();
        // The query path accepts (left, full) and reports the order.
        assert_eq!(
            OreAes128Bit6ChainedChaCha20::compare_left_to_full(&left, &full),
            Some(Ordering::Equal)
        );
        // A left-only artifact is not a full ciphertext, and vice versa, so the
        // length checks reject the swapped/mismatched cases.
        assert_eq!(
            OreAes128Bit6ChainedChaCha20::compare_raw_slices(&left, &full),
            None
        );
        assert_eq!(
            OreAes128Bit6ChainedChaCha20::compare_left_to_full(&full, &full),
            None
        );
    }

    #[test]
    fn empty_string_sorts_first() {
        let c = ore();
        assert_eq!(cmp(&c, "", "a"), Ordering::Less);
        assert_eq!(cmp(&c, "", ""), Ordering::Equal);
    }

    // --- Property tests --------------------------------------------------
    //
    // The contract under test is "the comparator reproduces the lexicographic
    // order of the plaintext", over arbitrary inputs and (independent) lengths —
    // not just the hand-picked words above. Lengths are capped so each case
    // stays cheap (~97 AES ops/block) while still routinely exceeding the
    // 14-block fixed-N packed-prefix cap.
    const PROP_MAX_BLOCKS: usize = 32;

    /// Map arbitrary bytes into the 6-bit block domain, length-capped.
    fn to_domain(v: &[u8]) -> Vec<u8> {
        v.iter().take(PROP_MAX_BLOCKS).map(|b| b & 0x3f).collect()
    }

    fn enc(c: &OreAes128Bit6ChainedChaCha20, x: &[u8]) -> Vec<u8> {
        c.encrypt_var(x).unwrap().to_bytes()
    }

    quickcheck! {
        /// Headline contract: the comparator reproduces the lexicographic order
        /// of the underlying 6-bit block sequences, for arbitrary blocks and
        /// arbitrary (independent) lengths — the full domain `0..64`, including
        /// values that string inputs never produce.
        fn prop_block_order_matches_lex(a: Vec<u8>, b: Vec<u8>) -> bool {
            let c = ore();
            let (a, b) = (to_domain(&a), to_domain(&b));
            let (ea, eb) = (enc(&c, &a), enc(&c, &b));
            OreAes128Bit6ChainedChaCha20::compare_raw_slices(&ea, &eb) == Some(a.cmp(&b))
        }

        /// Lewi-Wu query path: a left-only (query) ciphertext compared against a
        /// stored full ciphertext reproduces the plaintext order —
        /// `compare_left_to_full(left(a), full(b)) == a.cmp(b)`.
        fn prop_left_query_matches_full(a: Vec<u8>, b: Vec<u8>) -> bool {
            let c = ore();
            let (a, b) = (to_domain(&a), to_domain(&b));
            let left_a = c.encrypt_left_var(&a).unwrap().to_bytes();
            let full_b = enc(&c, &b);
            OreAes128Bit6ChainedChaCha20::compare_left_to_full(&left_a, &full_b)
                == Some(a.cmp(&b))
        }

        /// Same, with a forced shared prefix — exercises the constant-time
        /// prefix scan and first-differing-block selection at controlled common
        /// lengths (independent random inputs almost never share a prefix).
        fn prop_shared_prefix_order(prefix: Vec<u8>, sa: Vec<u8>, sb: Vec<u8>) -> bool {
            let c = ore();
            let p = to_domain(&prefix);
            let mut a = p.clone();
            a.extend(to_domain(&sa));
            a.truncate(PROP_MAX_BLOCKS);
            let mut b = p;
            b.extend(to_domain(&sb));
            b.truncate(PROP_MAX_BLOCKS);
            let (ea, eb) = (enc(&c, &a), enc(&c, &b));
            OreAes128Bit6ChainedChaCha20::compare_raw_slices(&ea, &eb) == Some(a.cmp(&b))
        }

        /// String comparison matches `str::cmp` across arbitrary Unicode and
        /// independent lengths: the MSB-first 6-bit packing is order-preserving
        /// even with tail zero-padding (cross-length prefix case included).
        fn prop_string_order_matches_str(a: String, b: String) -> bool {
            let c = ore();
            let a: String = a.chars().take(12).collect();
            let b: String = b.chars().take(12).collect();
            let ea = c.encrypt_str(&a).unwrap().to_bytes();
            let eb = c.encrypt_str(&b).unwrap().to_bytes();
            OreAes128Bit6ChainedChaCha20::compare_raw_slices(&ea, &eb) == Some(a.cmp(&b))
        }

        /// Two encryptions of one plaintext (fresh nonces each) compare Equal,
        /// and never produce identical bytes (the nonce streams differ).
        fn prop_equality_across_nonces(x: Vec<u8>) -> bool {
            let c = ore();
            let x = to_domain(&x);
            let (a, b) = (enc(&c, &x), enc(&c, &x));
            let equal = OreAes128Bit6ChainedChaCha20::compare_raw_slices(&a, &b)
                == Some(Ordering::Equal);
            // Empty plaintexts have no right blocks, so their bytes can collide;
            // only require nonce divergence when there is masked material.
            let distinct = x.is_empty() || a != b;
            equal && distinct
        }

        /// The left ciphertext is deterministic (it has no nonce) and is
        /// byte-identical to the left half embedded in a full ciphertext — the
        /// two encrypt paths must not drift.
        fn prop_left_deterministic_and_consistent(x: Vec<u8>) -> bool {
            let c = ore();
            let x = to_domain(&x);
            let l1 = c.encrypt_left_var(&x).unwrap().to_bytes();
            let l2 = c.encrypt_left_var(&x).unwrap().to_bytes();
            let full = c.encrypt_var(&x).unwrap();
            l1 == l2 && full.left.to_bytes() == l1
        }

        /// Serialised full ciphertexts round-trip through `from_slice`.
        fn prop_serialize_roundtrip(x: Vec<u8>) -> bool {
            let c = ore();
            let x = to_domain(&x);
            let bytes = enc(&c, &x);
            match VarCipherText::from_slice(&bytes) {
                Ok(ct) => ct.to_bytes() == bytes,
                Err(_) => false,
            }
        }
    }
}
