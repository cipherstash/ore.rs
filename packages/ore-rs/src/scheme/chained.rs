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
//! matches throughout, the shorter sorts first. A comparison reveals the
//! common-prefix length.
//!
//! **Stored rows compare offline.** A full ciphertext carries its
//! deterministic left half (`xt`, `f`), so anyone holding two stored full
//! ciphertexts can run `compare_raw_slices` with no
//! query and learn their order and common-prefix length. The legacy scheme
//! has the same exposure. There is no right-only storage path yet (plan
//! §5(b)).

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
use crate::scheme::decompose::{num_blocks_6bit, Blocks6};
use crate::scheme::width::FirstDiff;
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
        // Same rule as the comparators (and the fixed-width parsers): a symbol
        // outside the 6-bit domain is not a ciphertext of this scheme.
        if !symbols_in_domain(data, count) {
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

    /// Full Left+Right ciphertext for `x` (one 6-bit symbol per element). A
    /// value `>= 64` returns [`OreError::PrpError`].
    pub fn encrypt_var(&self, x: &[u8]) -> Result<VarCipherText, OreError> {
        self.encrypt_blocks(&Blocks6::check(x)?)
    }

    /// [`Self::encrypt_var`] over blocks already known to be in the 6-bit
    /// domain.
    fn encrypt_blocks<B: AsRef<[u8]>>(&self, x: &Blocks6<B>) -> Result<VarCipherText, OreError> {
        let count = x.len();
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

        // Scratch for the RO_KEY tags (then the H outputs) of one block. Every
        // entry is rewritten by the next block, so it is wiped once after the
        // loop rather than once per block.
        let mut ro = [AesBlock::default(); DOMAIN];

        for n in 0..count {
            let sym = x.symbol(n);
            let n16 = n as u16;
            let prp = self.prp_at(&acc, n16)?;
            let permuted = prp.permute(sym).get();
            xt.push(permuted);

            // ro_key for every domain value; f[n] = ro(n, xt[n]).
            for (j, blk) in ro.iter_mut().enumerate() {
                blk.copy_from_slice(&acc.finalize(&final_block(
                    Branch::RoKey,
                    n16,
                    j as u16,
                    WIDTH_BIT6,
                )));
            }
            // f[n] = ro(n, xt[n]), derived directly rather than read from `ro`
            // at the secret index `permuted` (a 1 KiB table spans many cache
            // lines). Same bytes as `encrypt_left_var`.
            f.push(acc.finalize(&final_block(
                Branch::RoKey,
                n16,
                permuted as u16,
                WIDTH_BIT6,
            )));

            // right block = H-mask ⊕ indicator (trashes `ro`).
            let mut rb = [0u8; RIGHT_LEN];
            hasher.hash_all_into(&mut ro, &mut rb);
            prp.indicator_mask_xor(sym, &mut rb);
            blocks.push(rb);

            acc.absorb(&prefix_block(n16, sym.get()));
        }

        // `ro` held key-derived RO_KEY tags (then H outputs) for the last block.
        for blk in ro.iter_mut() {
            blk.as_mut_slice().zeroize();
        }

        Ok(VarCipherText {
            left: VarLeft { xt, f },
            right: VarRight { nonce, blocks },
        })
    }

    /// Left-only ciphertext (smaller; for query plaintexts). A value `>= 64`
    /// returns [`OreError::PrpError`].
    pub fn encrypt_left_var(&self, x: &[u8]) -> Result<VarLeft, OreError> {
        self.encrypt_left_blocks(&Blocks6::check(x)?)
    }

    /// [`Self::encrypt_left_var`] over blocks already known to be in the
    /// 6-bit domain.
    fn encrypt_left_blocks<B: AsRef<[u8]>>(&self, x: &Blocks6<B>) -> Result<VarLeft, OreError> {
        let count = x.len();
        if count > u16::MAX as usize {
            return Err(OreError::TooManyBlocks);
        }

        let mut acc = CmacAccumulator::new(&self.k_acc);
        let mut xt = Vec::with_capacity(count);
        let mut f = Vec::with_capacity(count);

        for n in 0..count {
            let sym = x.symbol(n);
            let n16 = n as u16;
            let prp = self.prp_at(&acc, n16)?;
            let permuted = prp.permute(sym).get();
            xt.push(permuted);
            f.push(acc.finalize(&final_block(
                Branch::RoKey,
                n16,
                permuted as u16,
                WIDTH_BIT6,
            )));
            acc.absorb(&prefix_block(n16, sym.get()));
        }
        Ok(VarLeft { xt, f })
    }

    /// Encrypt a string (UTF-8 bytes → MSB-first 6-bit blocks). Strings
    /// longer than [`MAX_STR_BYTES`] return [`OreError::TooManyBlocks`].
    pub fn encrypt_str(&self, s: &str) -> Result<VarCipherText, OreError> {
        self.encrypt_blocks(&str_to_blocks(s)?)
    }

    /// Left-only string ciphertext. Strings longer than [`MAX_STR_BYTES`]
    /// return [`OreError::TooManyBlocks`].
    pub fn encrypt_left_str(&self, s: &str) -> Result<VarLeft, OreError> {
        self.encrypt_left_blocks(&str_to_blocks(s)?)
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
        if !symbols_in_domain(a, ca) || !symbols_in_domain(b, cb) {
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
    /// right half, so the smaller left-only artifact suffices. This does not
    /// make stored data safe at rest: a stored *full* ciphertext also carries
    /// its left half, so two stored rows compare offline (see the module docs). Returns `left`'s order relative to
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
        if !symbols_in_domain(left, cl) || !symbols_in_domain(full, cf) {
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
    ///
    /// The scan reads every block of the shared prefix, including `b`'s right
    /// blocks, and latches the first differing block's `xt`, `f` and `right`
    /// as it goes; the resolution step works from the latched copies, so no
    /// load is indexed by the position of the first difference. A direct
    /// `right_at(b, cb, l)` after the scan was the one load whose cache state
    /// depended on `l` (the scan never needed the right blocks), and dudect
    /// measured it as a timing signal; see `docs/reviews/`.
    fn compare_views(a: &[u8], ca: usize, b: &[u8], cb: usize) -> Ordering {
        let min_count = ca.min(cb);
        let mut is_equal = Choice::from(1u8);
        let mut diff = FirstDiff::<RIGHT_LEN>::new();
        for n in 0..min_count {
            let differs = !xt_at(a, n).ct_eq(&xt_at(b, n)) | !f_at(a, ca, n).ct_eq(f_at(b, cb, n));
            // Set for exactly one `n`: the first differing block.
            let first = is_equal & differs;
            diff.latch(xt_at(a, n), f_at(a, ca, n), right_at(b, cb, n), first);
            is_equal.conditional_assign(&Choice::from(0u8), first);
        }

        if bool::from(is_equal) {
            // Shared prefix matches throughout — shorter sorts first.
            return ca.cmp(&cb);
        }

        let hasher = FixedPiZ2Hash::new(HashKey::from_slice(nonce_at(b, cb)));
        if diff.resolve(&hasher) == 1 {
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

/// Whether every `xt` symbol of a serialised view is inside the 64-element
/// domain. The comparator reads the right block at `xt[l]`; a symbol of 64 or
/// more would select no byte and silently read 0. `xt` is public, so this may
/// branch.
fn symbols_in_domain(view: &[u8], count: usize) -> bool {
    (0..count).all(|i| usize::from(xt_at(view, i)) < DOMAIN)
}

/// Longest string, in UTF-8 bytes, whose block count fits the wire format's
/// `u16`: `⌈8n/6⌉ ≤ 65_535` gives `n ≤ 49_151`.
pub const MAX_STR_BYTES: usize = u16::MAX as usize * 6 / 8;

const _: () = assert!(num_blocks_6bit(MAX_STR_BYTES) <= u16::MAX as usize);
const _: () = assert!(num_blocks_6bit(MAX_STR_BYTES + 1) > u16::MAX as usize);

/// Decompose `s` into 6-bit blocks, refusing a string too long for the wire
/// format *before* allocating or decomposing it.
fn str_to_blocks(s: &str) -> Result<Blocks6<Vec<u8>>, OreError> {
    let bytes = s.as_bytes();
    if bytes.len() > MAX_STR_BYTES {
        return Err(OreError::TooManyBlocks);
    }
    Ok(Blocks6::decompose(
        bytes,
        vec![0u8; num_blocks_6bit(bytes.len())],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ore() -> OreAes128Bit6ChainedChaCha20 {
        OreAes128Bit6Chained::init(&[0x11; 16]).unwrap()
    }

    /// Symbols passed straight to `encrypt_var` / `encrypt_left_var` are
    /// checked: a value outside the 6-bit domain is refused, and in-domain
    /// symbols encrypt exactly as the string path's decomposition does.
    #[test]
    fn raw_symbols_are_checked() {
        let c = ore();
        assert!(matches!(
            c.encrypt_var(&[1, 64, 2]),
            Err(OreError::PrpError(_))
        ));
        assert!(matches!(
            c.encrypt_left_var(&[1, 64, 2]),
            Err(OreError::PrpError(_))
        ));

        let blocks = str_to_blocks("alice").unwrap();
        assert_eq!(
            c.encrypt_left_var(blocks.as_bytes()).unwrap().to_bytes(),
            c.encrypt_left_str("alice").unwrap().to_bytes()
        );
    }

    #[test]
    fn strings_over_the_wire_limit_are_rejected() {
        let c = ore();
        let too_long = "a".repeat(MAX_STR_BYTES + 1);
        assert!(matches!(
            c.encrypt_str(&too_long),
            Err(OreError::TooManyBlocks)
        ));
        assert!(matches!(
            c.encrypt_left_str(&too_long),
            Err(OreError::TooManyBlocks)
        ));
    }

    #[test]
    fn comparators_reject_out_of_domain_symbols() {
        let c = ore();
        let a = c.encrypt_str("apple").unwrap().to_bytes();
        let b = c.encrypt_str("apricot").unwrap().to_bytes();
        let q = c.encrypt_left_str("apple").unwrap().to_bytes();
        assert!(OreAes128Bit6Chained::<ChaCha20Rng>::compare_raw_slices(&a, &b).is_some());

        // First `xt` byte follows the 4-byte header.
        let mut bad = a.clone();
        bad[HEADER_LEN] = DOMAIN as u8;
        let mut bad_q = q.clone();
        bad_q[HEADER_LEN] = DOMAIN as u8;

        type C = OreAes128Bit6Chained<ChaCha20Rng>;
        assert_eq!(C::compare_raw_slices(&bad, &b), None);
        assert_eq!(C::compare_raw_slices(&b, &bad), None);
        assert_eq!(C::compare_left_to_full(&bad_q, &b), None);
        assert_eq!(C::compare_left_to_full(&q, &bad), None);
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
