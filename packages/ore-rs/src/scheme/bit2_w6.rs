//! BlockORE with **6-bit input blocks** (domain 64): the `(Bit6, packed
//! prefix, fixed-N)` scheme from the ORE v2 plan.
//!
//! Plaintext bytes are decomposed MSB-first into 6-bit block values (see
//! the crate-private `scheme::decompose`); `N` in the types below counts *blocks*,
//! not bytes (a `u64` is 11 blocks). Compared to the legacy 8-bit scheme,
//! each block costs 64 random-oracle evaluations instead of 256 and stores
//! an 8-byte right block instead of 32 — a `u64` ciphertext is 295 bytes
//! (vs 408) including the 4-byte v2 wire header.
//!
//! The packed prefix caps `N` at 14 (`prefix ≤ 13 ‖ value ‖ index` plus
//! the block count in byte 15 must fit one AES block; seeds also use byte
//! 14 for the block index), which is ten bytes of plaintext: every
//! vitaminc target up to 64 bits, `f64` and dates. A timestamp (12
//! bytes), a decimal (14), a 128-bit integer or uuid (16), text and bytes
//! are refused ([`crate::OreError::TooManyBlocks`], [`crate::OreError::VariableLength`])
//! and belong to [`crate::scheme::chained`]; [`crate::vitaminc::BlockOre`]
//! routes between the two by width.
//!
//! The scheme takes a sealed `OrderPlaintext` through [`crate::OreScheme`]. The
//! plaintext bytes are the target's encoding, whose byte order is the
//! value's order, and this scheme decomposes them into 6-bit blocks.
//!
//! **Status: wire format frozen as of 0.9.0.** `tests/compat_w6_vectors.rs`
//! pins the bytes; a change that alters them breaks every stored Bit6
//! ciphertext. The Z2 hash is the BHKR σ-MMO over a fixed public AES
//! permutation (plan §6, review brief A1).
//!
//! **Keys:** one 16-byte key and an optional salt. PRF₁ and PRF₂ run under
//! keys derived through the crate-private `scheme::keys` stages (root
//! label, salt, per-PRF label), never the raw key, so sharing a key with
//! the legacy scheme does not let legacy ciphertexts reveal Bit6 masking
//! keys, and ciphertexts under different salts share no key material.

use crate::scheme::decompose::num_blocks_6bit;
use crate::{
    ciphertext::*,
    primitives::{
        hash::FixedPiZ2Hash, prf::Aes128Prf, stack, AesBlock, Hash, HashKey, Prf, Prp, NONCE_SIZE,
    },
    scheme::decompose::Blocks6,
    scheme::keys,
    scheme::width::{AesBlockBuf, Bit6, BlockWidth, FirstDiff},
    OreCipher, OreError, OreScheme, PlainText, Query, Term,
};

use aes::cipher::generic_array::GenericArray;
use rand::TryRng;
use std::cmp::Ordering;
use std::sync::Mutex;
use subtle_ng::{Choice, ConditionallySelectable, ConstantTimeEq};
use vitaminc_context::Context;
use vitaminc_ore::OrderPlaintext;
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::SafeRand;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Per-block ciphertext component types for this scheme.
pub(crate) mod block_types;
pub(crate) use self::block_types::*;

/// The Z2 random-oracle instantiation for this scheme (plan §6, option 3 —
/// pending review; option 2 fallback is `Aes128Z2Hash` with an extra
/// feedforward, and the legacy construction is `Aes128Z2Hash`).
type Z2Hash = FixedPiZ2Hash;

/// Maximum number of blocks: the packed prefix (`prefix ‖ value ‖ index`)
/// plus the block count at byte 15 must fit one 16-byte AES input.
pub const MAX_BLOCKS: usize = 14;

/// AES-128 BlockORE cipher over 6-bit blocks. Keys are zeroised on drop.
///
/// Per-encryption nonces come from a [`SafeRand`] seeded from the OS when
/// the cipher is made, behind a mutex, so the cipher is `Send + Sync` and
/// one instance serves every thread.
#[derive(ZeroizeOnDrop)]
pub struct OreAes128Bit6 {
    prf1: Aes128Prf,
    prf2: Aes128Prf,
    #[zeroize(skip)]
    rng: Mutex<SafeRand>,
}

// Opaque Debug: never render key material (OpaqueDebug discipline).
impl std::fmt::Debug for OreAes128Bit6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OreAes128Bit6").finish_non_exhaustive()
    }
}

type EncryptLeftResult<const N: usize> = Result<Left<OreAes128Bit6, N>, OreError>;
type EncryptResult<const N: usize> = Result<CipherText<OreAes128Bit6, N>, OreError>;

/// v2 wire header for this scheme: version 2, scheme id 0x02
/// (= AES-128 suite, 6-bit blocks, packed prefix).
pub(crate) const WIRE: WireHeader = WireHeader {
    version: 0x02,
    scheme_id: 0x02,
};

/// PRP seeds are key-equivalent material; see the bit2 sibling for the
/// full rationale. Zeroized on drop.
struct SeedBuf<const N: usize>([AesBlock; N]);

impl<const N: usize> Drop for SeedBuf<N> {
    fn drop(&mut self) {
        for seed in self.0.iter_mut() {
            seed.zeroize();
        }
    }
}

/// The only input the caller's key is evaluated on: `k_root = AES_key(ROOT_LABEL)`.
///
/// Bit6 must not evaluate PRF₁/PRF₂ under the caller's raw key, because
/// the legacy scheme does, and its inputs cover Bit6's: a legacy `N = 15`
/// left ciphertext publishes exactly the PRF₁ outputs Bit6 uses as its
/// masking keys. Deriving separate keys separates the schemes.
///
/// The label itself must never be a legacy PRF input, or a legacy
/// ciphertext would publish the root key. Every legacy PRF₁ input has
/// byte 15 in `0..=14` (the block index at `N = 15`, else `0`) and every
/// legacy PRF₂ input has byte 15 `= 0`; this label ends in ASCII `'t'`
/// (`0x74`), so it is outside both. See `scheme::keys`.
const ROOT_LABEL: [u8; 16] = *b"ORE.v2.bit6.root";
const _: () = assert!(
    ROOT_LABEL[15] > 14,
    "root label collides with a legacy PRF input"
);

/// Labels for the two PRF keys under the salted key:
/// `prf1 = AES_{k_salt}(PRF1_LABEL)`, `prf2 = AES_{k_salt}(PRF2_LABEL)`.
const PRF1_LABEL: [u8; 16] = *b"ORE.v2.bit6.prf1";
const PRF2_LABEL: [u8; 16] = *b"ORE.v2.bit6.prf2";

impl OreAes128Bit6 {
    /// Per-block PRP seeds: `PRF₂(x[0..n] ‖ 0… ‖ n@14 ‖ N@15)`. The block
    /// count in byte 15 separates plaintext shapes (plan §4); the block
    /// index in byte 14 separates positions, so a prefix padded with zero
    /// blocks no longer collides with a shorter prefix (which gave every
    /// position of an all-zero plaintext the same permutation). Prefixes
    /// equal up to block `n` still share `seed_n`, as the comparator needs.
    /// `N ≤ 14` puts the prefix in bytes `0..=12`, so byte 14 is free.
    fn derive_prp_seeds<const N: usize>(&self, x: &PlainText<N>) -> SeedBuf<N> {
        let mut seeds = [AesBlock::default(); N];
        for (n, block) in seeds.iter_mut().enumerate() {
            block[0..n].clone_from_slice(&x[0..n]);
            block[14] = n as u8;
            block[15] = N as u8;
        }
        self.prf2.encrypt_all(&mut seeds);
        SeedBuf(seeds)
    }

    /// [`OreCipher::encrypt_left`] over blocks already known to be in the
    /// 6-bit domain, without the stack scrub. Every caller runs it inside
    /// [`stack::scrubbed`]: building a block's PRP leaves its seed and tables
    /// in dead stack (see `primitives::stack`).
    pub(crate) fn encrypt_left_blocks<const N: usize>(
        &self,
        x: &Blocks6<PlainText<N>>,
    ) -> EncryptLeftResult<N> {
        if N > MAX_BLOCKS {
            return Err(OreError::TooManyBlocks);
        }

        let mut output = Left::<Self, N>::init();
        let seeds = self.derive_prp_seeds(x.inner());

        for n in 0..N {
            let prp: <Bit6 as BlockWidth>::Prp = Prp::new(&seeds.0[n])?;
            output.xt[n] = prp.permute(x.symbol(n)).get();

            output.f[n][0..n].clone_from_slice(&x.as_bytes()[0..n]);
            output.f[n][n] = output.xt[n];
            output.f[n][N] = n as u8;
            output.f[n][15] = N as u8;
        }
        self.prf1.encrypt_all(&mut output.f);

        Ok(output)
    }

    /// [`OreCipher::encrypt`] over blocks already known to be in the 6-bit
    /// domain, without the stack scrub; see [`Self::encrypt_left_blocks`].
    pub(crate) fn encrypt_blocks<const N: usize>(
        &self,
        x: &Blocks6<PlainText<N>>,
    ) -> EncryptResult<N> {
        if N > MAX_BLOCKS {
            return Err(OreError::TooManyBlocks);
        }

        let mut left = Left::<Self, N>::init();
        let mut right = Right::<Self, N>::init();

        self.fill_nonce(&mut right.nonce);

        let seeds = self.derive_prp_seeds(x.inner());
        let hasher: Z2Hash = Hash::new(HashKey::from_slice(&right.nonce));

        // RO key template, maintained incrementally (see the bit2 sibling).
        // Entry j for block n is (x[0..n] ‖ j ‖ 0… ‖ n@N ‖ N@15).
        let mut template = <Bit6 as BlockWidth>::RoKeyBuf::zeroed();
        for (j, entry) in template.iter_mut().enumerate() {
            entry[0] = j as u8;
            entry[15] = N as u8;
        }
        let mut work = <Bit6 as BlockWidth>::RoKeyBuf::zeroed();

        for n in 0..N {
            let prp: <Bit6 as BlockWidth>::Prp = Prp::new(&seeds.0[n])?;
            left.xt[n] = prp.permute(x.symbol(n)).get();

            left.f[n][0..n].clone_from_slice(&x.as_bytes()[0..n]);
            left.f[n][n] = left.xt[n];
            left.f[n][N] = n as u8;
            left.f[n][15] = N as u8;

            if n > 0 {
                for (j, entry) in template.iter_mut().enumerate() {
                    entry[n - 1] = x.as_bytes()[n - 1];
                    entry[n] = j as u8;
                    entry[N] = n as u8;
                }
            }

            work.copy_from(&template);
            self.prf1.encrypt_all(work.as_mut_slice());

            crate::scheme::bit2::encode_right_block::<Bit6, _>(
                &mut right.data[n],
                &prp,
                x.symbol(n),
                &hasher,
                &mut work,
            );
        }

        self.prf1.encrypt_all(&mut left.f);

        for entry in template.iter_mut() {
            entry.zeroize();
        }
        for entry in work.as_mut_slice() {
            entry.zeroize();
        }

        Ok(CipherText { left, right })
    }
}

// Right-block encoding is the width-/hash-generic helper shared with the
// legacy scheme: `crate::scheme::bit2::encode_right_block::<Bit6, Z2Hash>`.

impl OreAes128Bit6 {
    /// Initialise the cipher from one 16-byte key, with the empty salt:
    /// `init_with_salt(key, &Context::empty())`.
    pub fn init(key: Protected<[u8; 16]>) -> Result<Self, OreError> {
        Self::init_with_salt(key, &Context::empty())
    }

    /// Initialise the cipher from one 16-byte key and a salt naming what
    /// the key is for: the context a vitaminc space derives, or any bytes
    /// as `Context::from_encoded(bytes)`. PRF₁ and PRF₂ are keyed by
    /// `AES_{k_salt}(label)` with `k_salt = CMAC_{AES_key(ROOT_LABEL)}(salt)`
    /// over the context's bytes; see the crate-private `scheme::keys` for
    /// the stages and their argument.
    ///
    /// Ciphertexts under different salts share no key material, but
    /// nothing on the wire records the salt, so the comparators cannot
    /// refuse a mismatched pair: they return a confident, meaningless
    /// result, `Equal` included (a typed comparison of zero blocks is
    /// `Equal` under any salts), so no result confirms that two salts
    /// match. Keep the salt with the identity of the stored data, as you
    /// keep the key.
    ///
    /// Fails ([`OreError::Random`]) only if the OS random number generator
    /// could not seed the nonce generator.
    pub fn init_with_salt(key: Protected<[u8; 16]>, salt: &Context<'_>) -> Result<Self, OreError> {
        Self::init_with_rng(key, salt, SafeRand::from_entropy()?)
    }

    /// [`Self::init_with_salt`] with every nonce drawn from `seed`, so a
    /// test can pin a full ciphertext's bytes. Two values encrypted under
    /// one seed share their nonces, which the scheme's security assumes
    /// they never do: never ship a seeded cipher.
    #[cfg(any(test, feature = "test-support"))]
    pub fn init_seeded(
        key: Protected<[u8; 16]>,
        salt: &Context<'_>,
        seed: [u8; 32],
    ) -> Result<Self, OreError> {
        use vitaminc_random::SeedableRng;
        Self::init_with_rng(key, salt, SafeRand::from_seed(seed))
    }

    fn init_with_rng(
        key: Protected<[u8; 16]>,
        salt: &Context<'_>,
        rng: SafeRand,
    ) -> Result<Self, OreError> {
        let k_salt = keys::salted(&keys::root(key.risky_ref(), &ROOT_LABEL), salt.as_bytes());
        let prf1 = Prf::new(GenericArray::from_slice(&*keys::subkey(
            &k_salt,
            &PRF1_LABEL,
        )));
        let prf2 = Prf::new(GenericArray::from_slice(&*keys::subkey(
            &k_salt,
            &PRF2_LABEL,
        )));
        Ok(OreAes128Bit6 {
            prf1,
            prf2,
            rng: Mutex::new(rng),
        })
    }

    /// Draw one nonce. The generator is infallible once seeded, and a
    /// thread that panicked while holding the lock left a generator that
    /// is still a generator, so a poisoned lock is taken as it is.
    fn fill_nonce(&self, nonce: &mut [u8; NONCE_SIZE]) {
        let mut rng = self
            .rng
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match rng.try_fill_bytes(nonce) {
            Ok(()) => {}
            Err(never) => match never {},
        }
    }
}

/// The bytes of a fixed-width plaintext this scheme takes: up to ten,
/// so at most [`MAX_BLOCKS`] blocks. Text and bytes, whose width varies,
/// are [`OreError::VariableLength`]; a wider fixed-width plaintext is
/// [`OreError::TooManyBlocks`]. Decided by the width, never by a byte.
fn fixed_width_bytes(plaintext: &OrderPlaintext) -> Result<&[u8], OreError> {
    match plaintext.width() {
        None => Err(OreError::VariableLength),
        Some(width) if width > MAX_BYTES => Err(OreError::TooManyBlocks),
        Some(_) => Ok(plaintext.bytes().risky_ref().as_slice()),
    }
}

/// Most plaintext bytes this scheme takes: [`MAX_BLOCKS`] six-bit blocks
/// hold ten bytes (`⌈8·10/6⌉ = 14`).
pub const MAX_BYTES: usize = 10;
const _: () = assert!(num_blocks_6bit(MAX_BYTES) == MAX_BLOCKS);
const _: () = assert!(num_blocks_6bit(MAX_BYTES + 1) > MAX_BLOCKS);

impl OreAes128Bit6 {
    /// Encrypt bytes already encoded so that byte order is value order
    /// (MSB-first 6-bit blocks, `⌈8n/6⌉` of them). Up to ten bytes fit the
    /// [`MAX_BLOCKS`] cap; more returns [`OreError::TooManyBlocks`].
    ///
    /// The block count depends on the length, which is only known at
    /// runtime, so the result is the serialised full ciphertext rather
    /// than a `CipherText<_, N>`; compare it with
    /// [`OreScheme::compare_raw_slices`].
    ///
    /// Crate-private on purpose: the only encoded bytes this scheme takes
    /// arrive sealed, as an `OrderPlaintext` through [`OreScheme`], so a
    /// caller cannot hand it bytes that skipped the encoding.
    pub(crate) fn encrypt_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>, OreError> {
        match bytes.len() {
            0 => self.encrypt_bytes_as::<0, 0>(bytes),
            1 => self.encrypt_bytes_as::<1, 2>(bytes),
            2 => self.encrypt_bytes_as::<2, 3>(bytes),
            3 => self.encrypt_bytes_as::<3, 4>(bytes),
            4 => self.encrypt_bytes_as::<4, 6>(bytes),
            5 => self.encrypt_bytes_as::<5, 7>(bytes),
            6 => self.encrypt_bytes_as::<6, 8>(bytes),
            7 => self.encrypt_bytes_as::<7, 10>(bytes),
            8 => self.encrypt_bytes_as::<8, 11>(bytes),
            9 => self.encrypt_bytes_as::<9, 12>(bytes),
            10 => self.encrypt_bytes_as::<10, 14>(bytes),
            _ => Err(OreError::TooManyBlocks),
        }
    }

    /// [`Self::encrypt_bytes`], for the left (query) half alone.
    pub(crate) fn encrypt_left_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>, OreError> {
        match bytes.len() {
            0 => self.encrypt_left_bytes_as::<0, 0>(bytes),
            1 => self.encrypt_left_bytes_as::<1, 2>(bytes),
            2 => self.encrypt_left_bytes_as::<2, 3>(bytes),
            3 => self.encrypt_left_bytes_as::<3, 4>(bytes),
            4 => self.encrypt_left_bytes_as::<4, 6>(bytes),
            5 => self.encrypt_left_bytes_as::<5, 7>(bytes),
            6 => self.encrypt_left_bytes_as::<6, 8>(bytes),
            7 => self.encrypt_left_bytes_as::<7, 10>(bytes),
            8 => self.encrypt_left_bytes_as::<8, 11>(bytes),
            9 => self.encrypt_left_bytes_as::<9, 12>(bytes),
            10 => self.encrypt_left_bytes_as::<10, 14>(bytes),
            _ => Err(OreError::TooManyBlocks),
        }
    }

    /// [`Self::encrypt_bytes`] for `N` bytes, which the caller has matched
    /// to the length, as `B` blocks. `B` must be `num_blocks_6bit(N)`,
    /// checked at compile time. The plaintext's blocks are a copy in this
    /// frame, so they are made inside the scrub.
    #[allow(clippy::let_unit_value)]
    fn encrypt_bytes_as<const N: usize, const B: usize>(
        &self,
        bytes: &[u8],
    ) -> Result<Vec<u8>, OreError> {
        let () = BlocksFor::<N, B>::OK;
        stack::scrubbed(|| {
            let blocks = Blocks6::decompose(bytes, [0u8; B]);
            self.encrypt_blocks(&blocks).map(|ct| ct.to_bytes())
        })
    }

    /// [`Self::encrypt_bytes_as`], for the left half.
    #[allow(clippy::let_unit_value)]
    fn encrypt_left_bytes_as<const N: usize, const B: usize>(
        &self,
        bytes: &[u8],
    ) -> Result<Vec<u8>, OreError> {
        let () = BlocksFor::<N, B>::OK;
        stack::scrubbed(|| {
            let blocks = Blocks6::decompose(bytes, [0u8; B]);
            self.encrypt_left_blocks(&blocks)
                .map(|left| left.to_bytes())
        })
    }
}

impl crate::sealed::Sealed for OreAes128Bit6 {}

impl OreScheme for OreAes128Bit6 {
    fn encrypt_plaintext(&self, plaintext: &OrderPlaintext) -> Result<Term, OreError> {
        self.encrypt_bytes(fixed_width_bytes(plaintext)?)
            .map(Term::new)
    }

    fn encrypt_query_plaintext(&self, plaintext: &OrderPlaintext) -> Result<Query, OreError> {
        self.encrypt_left_bytes(fixed_width_bytes(plaintext)?)
            .map(Query::new)
    }

    fn compare_raw_slices(a: &[u8], b: &[u8]) -> Option<Ordering> {
        if a.len() != b.len() {
            return None;
        }
        let (num_blocks, a, b) = parse_pair(a, b)?;
        if a.len() != full_body_len(num_blocks) {
            return None;
        }
        compare_bodies(a, b, num_blocks)
    }

    /// Compare a serialised left (query) ciphertext with a serialised full
    /// one: the order of `left`'s plaintext against `full`'s, as
    /// `compare_raw_slices` gives it for two full ciphertexts. A query
    /// needs only the left half; the comparison reads `full`'s left and
    /// right halves.
    ///
    /// `None` if either input is malformed (including a full ciphertext
    /// passed as `left`, or a left one as `full`), if their headers or
    /// block counts differ, or if a symbol is outside the 6-bit domain.
    fn compare_left_to_full(left: &[u8], full: &[u8]) -> Option<Ordering> {
        let (num_blocks, left, full) = parse_pair(left, full)?;
        if left.len() != left_body_len(num_blocks) {
            return None;
        }
        compare_bodies(left, full, num_blocks)
    }
}

/// `N` bytes are `B` six-bit blocks: [`Self::OK`] fails to compile
/// otherwise.
struct BlocksFor<const N: usize, const B: usize>;

impl<const N: usize, const B: usize> BlocksFor<N, B> {
    const OK: () = assert!(
        B == num_blocks_6bit(N),
        "BlocksFor: B is not num_blocks_6bit(N)"
    );
}

impl OreCipher for OreAes128Bit6 {
    type LeftBlockType = LeftBlock16;
    type RightBlockType = RightBlock8;

    const WIRE_HEADER: Option<WireHeader> = Some(WIRE);
    const SYMBOL_DOMAIN: usize = <Bit6 as BlockWidth>::DOMAIN;

    /// Encrypt `x`, whose entries are **6-bit block values** (`< 64`, as
    /// the crate-private `scheme::decompose` produces); `N` is the block count
    /// (≤ [`MAX_BLOCKS`]; more returns [`OreError::TooManyBlocks`]). The
    /// byte paths above decompose and skip the check below. A value
    /// `>= 64` returns [`OreError::PrpError`].
    fn encrypt_left<const N: usize>(&self, x: &PlainText<N>) -> EncryptLeftResult<N> {
        stack::scrubbed(|| self.encrypt_left_blocks(&Blocks6::check(*x)?))
    }

    /// As [`Self::encrypt_left`], for the full ciphertext.
    fn encrypt<const N: usize>(&self, x: &PlainText<N>) -> EncryptResult<N> {
        stack::scrubbed(|| self.encrypt_blocks(&Blocks6::check(*x)?))
    }
}

/// Check two headered Bit6 slices against each other and the scheme:
/// the same version, scheme id and block count, and a count from 1 to
/// [`MAX_BLOCKS`]. Returns the count and the two bodies. Lengths are the
/// caller's to check.
fn parse_pair<'a>(a: &'a [u8], b: &'a [u8]) -> Option<(usize, &'a [u8], &'a [u8])> {
    let (header_a, a) = parse_header(a).ok()?;
    let (header_b, b) = parse_header(b).ok()?;
    if header_a != header_b || (header_a.0, header_a.1) != (WIRE.version, WIRE.scheme_id) {
        return None;
    }
    let num_blocks = header_a.2;
    // Reject a degenerate count=0 header: no plaintext is empty, so no
    // ciphertext has zero blocks, and an empty scan would otherwise return
    // Equal for any pair of crafted 0-block ciphertexts.
    if num_blocks == 0 || num_blocks > MAX_BLOCKS {
        return None;
    }
    Some((num_blocks, a, b))
}

/// Body length (after the header) of a left ciphertext: `xt ‖ f`.
fn left_body_len(num_blocks: usize) -> usize {
    num_blocks * (LeftBlock16::BLOCK_SIZE + 1)
}

/// Body length (after the header) of a full ciphertext:
/// `xt ‖ f ‖ nonce ‖ right`.
fn full_body_len(num_blocks: usize) -> usize {
    left_body_len(num_blocks) + NONCE_SIZE + num_blocks * RightBlock8::BLOCK_SIZE
}

/// Compare the bodies of `a` and `b`, which share `num_blocks`. `a` may be
/// a left or a full body: only its left view (`xt ‖ f`, the same prefix in
/// both) is read. `b` must be a full body of `full_body_len(num_blocks)`
/// bytes; `a` at least `left_body_len(num_blocks)`. Refuses (`None`) a
/// symbol outside the 6-bit domain in either.
fn compare_bodies(a: &[u8], b: &[u8], num_blocks: usize) -> Option<Ordering> {
    if b.len() != full_body_len(num_blocks) || a.len() < left_body_len(num_blocks) {
        return None;
    }
    // Reject symbols outside the 64-element domain: the scan below reads
    // the right block at `a[l]`, which must index one of its 64 bits.
    // `xt` is public, so this may branch.
    if a[..num_blocks]
        .iter()
        .chain(&b[..num_blocks])
        .any(|&s| usize::from(s) >= <Bit6 as BlockWidth>::DOMAIN)
    {
        return None;
    }

    let mut is_equal = Choice::from(1);
    // What the resolution step needs from the first differing block `l`:
    // `a`'s permuted symbol and PRF tag, and `b`'s right bitvector. All
    // three are latched *inside* the scan, under the choice "this is the
    // first difference", so no load after the loop is indexed by `l`.
    // The right blocks are the one region the scan would otherwise never
    // touch, so a direct `right[l]` afterwards hits or misses the cache
    // according to `l`; measured as a timing signal, see `docs/reviews/`.
    let mut diff = FirstDiff::<{ RightBlock8::BLOCK_SIZE }>::new();

    // Slices for the PRF ("f") blocks and `b`'s right half.
    let a_f = &a[num_blocks..];
    let b_f = &b[num_blocks..];
    let b_right = &b[left_body_len(num_blocks)..];
    let b_right_blocks = &b_right[NONCE_SIZE..];

    for n in 0..num_blocks {
        let prp_eq: Choice = !a[n].ct_eq(&b[n]);
        let left_block_comparison: Choice = !left_block(a_f, n).ct_eq(left_block(b_f, n));
        let condition: Choice = prp_eq | left_block_comparison;
        // Set for exactly one `n`: the first differing block.
        let first = is_equal & condition;

        diff.latch(
            a[n],
            left_block(a_f, n),
            right_block(b_right_blocks, n),
            first,
        );
        is_equal.conditional_assign(&Choice::from(0), first);
    }

    if bool::from(is_equal) {
        return Some(Ordering::Equal);
    }

    let hash: Z2Hash = Hash::new(HashKey::from_slice(&b_right[0..NONCE_SIZE]));

    if diff.resolve(&hash) == 1 {
        return Some(Ordering::Greater);
    }

    Some(Ordering::Less)
}

#[inline]
fn left_block(input: &[u8], n: usize) -> &[u8] {
    let f_pos = n * LeftBlock16::BLOCK_SIZE;
    &input[f_pos..(f_pos + LeftBlock16::BLOCK_SIZE)]
}

#[inline]
fn right_block(input: &[u8], n: usize) -> &[u8] {
    let f_pos = n * RightBlock8::BLOCK_SIZE;
    &input[f_pos..(f_pos + RightBlock8::BLOCK_SIZE)]
}

impl<const N: usize> PartialEq for CipherText<OreAes128Bit6, N> {
    fn eq(&self, b: &Self) -> bool {
        matches!(self.cmp(b), Ordering::Equal)
    }
}

impl<const N: usize> Ord for CipherText<OreAes128Bit6, N> {
    fn cmp(&self, b: &Self) -> Ordering {
        compare_typed(&self.left, b)
    }
}

#[cfg(test)]
impl<const N: usize> Left<OreAes128Bit6, N> {
    /// The order of this left (query) ciphertext's plaintext against
    /// `full`'s: the typed form of
    /// [`OreScheme::compare_left_to_full`], and what `Ord` on
    /// [`CipherText`] computes from the first ciphertext's left half.
    pub(crate) fn compare_to_full(&self, full: &CipherText<OreAes128Bit6, N>) -> Ordering {
        compare_typed(self, full)
    }
}

/// The typed comparator: `left`'s plaintext against `b`'s. Reads only
/// `left` and `b`, as the raw comparator reads only `a`'s left view.
fn compare_typed<const N: usize>(
    left: &Left<OreAes128Bit6, N>,
    b: &CipherText<OreAes128Bit6, N>,
) -> Ordering {
    let mut is_equal = Choice::from(1);
    // Latch the first differing block during the scan, as in
    // `compare_raw_slices`: no load after the loop is indexed by its
    // position.
    let mut diff = FirstDiff::<{ RightBlock8::BLOCK_SIZE }>::new();

    for n in 0..N {
        let condition: Choice =
            !(left.xt[n].ct_eq(&b.left.xt[n])) | !(left.f[n].ct_eq(&b.left.f[n]));
        // Set for exactly one `n`: the first differing block.
        let first = is_equal & condition;

        diff.latch(left.xt[n], &left.f[n], b.right.data[n].bytes(), first);
        is_equal.conditional_assign(&Choice::from(0), first);
    }

    if bool::from(is_equal) {
        return Ordering::Equal;
    }

    let hash: Z2Hash = Hash::new(HashKey::from_slice(&b.right.nonce));
    if diff.resolve(&hash) == 1 {
        return Ordering::Greater;
    }

    Ordering::Less
}

impl<const N: usize> PartialOrd for CipherText<OreAes128Bit6, N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize> Eq for CipherText<OreAes128Bit6, N> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::bit2::OreAes128;
    use crate::testing::{
        date_pt, f64_pt, fixed_key, key, salt, text_pt, timestamp_pt, u32_pt, u64_pt,
    };
    use quickcheck::TestResult;

    type Ore = OreAes128Bit6;

    fn init_ore() -> Ore {
        Ore::init(key()).unwrap()
    }

    /// A full ciphertext of `plaintext`, typed by its block count.
    fn full<const N: usize>(ore: &Ore, plaintext: &OrderPlaintext) -> CipherText<Ore, N> {
        let term = ore.encrypt_plaintext(plaintext).unwrap();
        CipherText::from_slice(term.as_bytes()).unwrap()
    }

    /// A left (query) ciphertext of `plaintext`, typed by its block count.
    fn left<const N: usize>(ore: &Ore, plaintext: &OrderPlaintext) -> Left<Ore, N> {
        let query = ore.encrypt_query_plaintext(plaintext).unwrap();
        Left::from_slice(query.as_bytes()).unwrap()
    }

    fn full_u64(ore: &Ore, x: u64) -> CipherText<Ore, 11> {
        full(ore, &u64_pt(x))
    }

    fn left_u64(ore: &Ore, x: u64) -> Left<Ore, 11> {
        left(ore, &u64_pt(x))
    }

    fn term_bytes(ore: &Ore, plaintext: &OrderPlaintext) -> Vec<u8> {
        ore.encrypt_plaintext(plaintext).unwrap().into_bytes()
    }

    fn query_bytes(ore: &Ore, plaintext: &OrderPlaintext) -> Vec<u8> {
        ore.encrypt_query_plaintext(plaintext).unwrap().into_bytes()
    }

    /// `init` is the empty salt; another salt gives unrelated ciphertexts,
    /// and the same salt reproduces them. The two salts have equal
    /// lengths, so the length prefix alone cannot separate them.
    #[test]
    fn salt_separates_keys() {
        let plain = Ore::init(fixed_key(0x42)).unwrap();
        let empty = Ore::init_with_salt(fixed_key(0x42), &Context::empty()).unwrap();
        let col_a = Ore::init_with_salt(fixed_key(0x42), &salt(b"users.age")).unwrap();
        let col_a2 = Ore::init_with_salt(fixed_key(0x42), &salt(b"users.age")).unwrap();
        let col_b = Ore::init_with_salt(fixed_key(0x42), &salt(b"users.dob")).unwrap();

        let query = |c: &Ore| query_bytes(c, &u64_pt(456));
        assert_eq!(query(&plain), query(&empty));
        assert_eq!(query(&col_a), query(&col_a2));
        assert_ne!(query(&plain), query(&col_a));
        assert_ne!(query(&col_a), query(&col_b));

        let a = term_bytes(&col_a, &u64_pt(456));
        let b = term_bytes(&col_b, &u64_pt(456));
        assert_ne!(Ore::compare_raw_slices(&a, &b), Some(Ordering::Equal));
        assert_eq!(
            Ore::compare_raw_slices(&a, &term_bytes(&col_a2, &u64_pt(456))),
            Some(Ordering::Equal)
        );
    }

    /// The scheme takes a fixed-width plaintext of up to ten bytes and
    /// refuses the rest by width: a timestamp (12 bytes) is too many
    /// blocks, and text has no fixed width. Refused before any block is
    /// made, so a refusal costs nothing.
    #[test]
    fn plaintexts_are_taken_by_width() {
        let ore = init_ore();
        assert_eq!(
            term_bytes(&ore, &date_pt(19_000)).len(),
            4 + 6 + 96 + 16 + 48
        );
        assert_eq!(term_bytes(&ore, &u64_pt(1)).len(), 295);
        assert!(matches!(
            ore.encrypt_plaintext(&timestamp_pt(1)),
            Err(OreError::TooManyBlocks)
        ));
        assert!(matches!(
            ore.encrypt_query_plaintext(&timestamp_pt(1)),
            Err(OreError::TooManyBlocks)
        ));
        assert!(matches!(
            ore.encrypt_plaintext(&text_pt("alice")),
            Err(OreError::VariableLength)
        ));
        assert!(matches!(
            ore.encrypt_query_plaintext(&text_pt("alice")),
            Err(OreError::VariableLength)
        ));
    }

    /// A block count past `MAX_BLOCKS` through the block-level path is an
    /// error, as on the legacy scheme, not a panic (review of #113).
    #[test]
    fn too_many_blocks_is_an_error_not_a_panic() {
        let ore = init_ore();
        assert!(matches!(
            OreCipher::encrypt(&ore, &[0u8; MAX_BLOCKS + 1]),
            Err(OreError::TooManyBlocks)
        ));
        assert!(matches!(
            OreCipher::encrypt_left(&ore, &[0u8; MAX_BLOCKS + 1]),
            Err(OreError::TooManyBlocks)
        ));
        assert!(OreCipher::encrypt(&ore, &[0u8; MAX_BLOCKS]).is_ok());
        assert!(OreCipher::encrypt_left(&ore, &[0u8; MAX_BLOCKS]).is_ok());
    }

    /// Blocks passed straight to the block-level path are checked: a value
    /// outside the 6-bit domain is refused, and an in-domain array
    /// encrypts exactly as the decomposing byte path does.
    #[test]
    fn raw_blocks_are_checked() {
        let ore = init_ore();
        let mut blocks = [0u8; 11];
        blocks[3] = 64;
        assert!(matches!(
            OreCipher::encrypt(&ore, &blocks),
            Err(OreError::PrpError(_))
        ));
        assert!(matches!(
            OreCipher::encrypt_left(&ore, &blocks),
            Err(OreError::PrpError(_))
        ));

        let x = 0x0123_4567_89ab_cdefu64;
        let decomposed = Blocks6::decompose(&x.to_be_bytes(), [0u8; 11]);
        let raw = OreCipher::encrypt_left(&ore, decomposed.inner()).unwrap();
        assert_eq!(raw.to_bytes(), query_bytes(&ore, &u64_pt(x)));
    }

    /// Cross-scheme regression (review of #82): under keys shared with the
    /// legacy scheme, a legacy `N = 15` left ciphertext must never publish
    /// one of Bit6's PRF₁ tags. Bit6's `f[0]` for an 11-block value has PRF₁
    /// input `xt[0] ‖ 0×10 ‖ 0@11 ‖ 0×3 ‖ 11@15`; legacy block 11 of
    /// `(xt[0], 0×10, c, 0×3)` has input `xt[0] ‖ 0×10 ‖ xt'[11] ‖ 0×3 ‖
    /// 11@15`, which matches whenever `c` permutes to 0. Search every `c`.
    #[test]
    fn legacy_ciphertexts_never_publish_bit6_tags() {
        let k1 = key();
        let bit6 = Ore::init(k1.clone()).unwrap();
        let legacy = OreAes128::init(k1, key()).unwrap();

        let target = OreCipher::encrypt_left(&bit6, &[0u8; 11]).unwrap();
        let tag = target.f[0];

        let mut probe = [0u8; 15];
        probe[0] = target.xt[0];
        for c in 0..=255u8 {
            probe[11] = c;
            let left = OreCipher::encrypt_left(&legacy, &probe).unwrap();
            assert!(
                !bool::from(left.f[11].ct_eq(&tag)),
                "legacy block 11 reproduced a Bit6 tag (c = {})",
                c
            );
        }
    }

    /// Position-binding regression (review of #82): every position of an
    /// all-zero plaintext must get its own permutation, so its `xt` bytes
    /// are not all equal (they were, when seeds bound only the count).
    #[test]
    fn zero_blocks_use_distinct_permutations_per_position() {
        let ore = init_ore();
        let left = OreCipher::encrypt_left(&ore, &[0u8; 11]).unwrap();
        let first = left.xt[0];
        assert!(
            left.xt.iter().any(|&s| s != first),
            "all 11 positions produced the same symbol"
        );
    }

    /// A query is the left half of a term: deterministic, and the same
    /// bytes as the left half of every full ciphertext of its value.
    #[test]
    fn a_query_is_the_left_half_of_a_term() {
        let ore = init_ore();
        let query = query_bytes(&ore, &u64_pt(456));
        assert_eq!(query, query_bytes(&ore, &u64_pt(456)));
        let term = full_u64(&ore, 456);
        assert_eq!(query, term.left.to_bytes());
        assert_eq!(query.len(), 4 + 11 + 176);
    }

    /// A left ciphertext against a full one, raw: what each kind of
    /// malformed or mismatched pair returns (#120).
    #[test]
    fn left_to_full_refuses_what_is_not_a_left_and_a_full() {
        let ore = init_ore();
        let left = query_bytes(&ore, &u64_pt(7));
        let full = term_bytes(&ore, &u64_pt(7));
        assert_eq!(
            Ore::compare_left_to_full(&left, &full),
            Some(Ordering::Equal)
        );
        // Swapped, or two of a kind.
        assert_eq!(Ore::compare_left_to_full(&full, &left), None);
        assert_eq!(Ore::compare_left_to_full(&full, &full), None);
        assert_eq!(Ore::compare_left_to_full(&left, &left), None);
        // Another block count: a `u32` is 6 blocks.
        let left_u32 = query_bytes(&ore, &u32_pt(7));
        assert_eq!(Ore::compare_left_to_full(&left_u32, &full), None);
        // Truncated, or a symbol outside the 6-bit domain (the first `xt`
        // byte, after the 4-byte header).
        assert_eq!(
            Ore::compare_left_to_full(&left[..left.len() - 1], &full),
            None
        );
        let mut bad = left.clone();
        bad[4] = 64;
        assert_eq!(Ore::compare_left_to_full(&bad, &full), None);
    }

    /// The scheme is shared across threads as it is: one instance, one
    /// nonce generator behind a lock.
    #[test]
    fn the_scheme_is_send_and_sync() {
        fn is_send_sync<X: Send + Sync>(_: &X) {}
        let ore = init_ore();
        is_send_sync(&ore);
        let shared = &ore;
        let terms: Vec<Vec<u8>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4u64)
                .map(|i| scope.spawn(move || term_bytes(shared, &u64_pt(i))))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        for pair in terms.windows(2) {
            assert_eq!(
                Ore::compare_raw_slices(&pair[0], &pair[1]),
                Some(Ordering::Less)
            );
        }
    }

    quickcheck! {
        /// A left (query) ciphertext orders against a full one as the
        /// plaintexts do, raw and typed, and agrees with the full-vs-full
        /// comparators (#120).
        fn left_to_full_orders_as_the_plaintexts(a: u64, b: u64) -> bool {
            let ore = init_ore();
            let left = left_u64(&ore, a);
            let full_a = full_u64(&ore, a);
            let full_b = full_u64(&ore, b);
            let want = a.cmp(&b);
            Ore::compare_left_to_full(&left.to_bytes(), &full_b.to_bytes()) == Some(want)
                && left.compare_to_full(&full_b) == want
                && full_a.cmp(&full_b) == want
                && Ore::compare_raw_slices(&full_a.to_bytes(), &full_b.to_bytes()) == Some(want)
        }

        fn compare_u64(x: u64, y: u64) -> bool {
            let ore = init_ore();
            let a = full_u64(&ore, x);
            let b = full_u64(&ore, y);

            match x.cmp(&y) {
                Ordering::Greater => a > b,
                Ordering::Less    => a < b,
                Ordering::Equal   => a == b
            }
        }

        fn compare_u64_raw_slices(x: u64, y: u64) -> bool {
            let ore = init_ore();
            let a = term_bytes(&ore, &u64_pt(x));
            let b = term_bytes(&ore, &u64_pt(y));

            match Ore::compare_raw_slices(&a, &b) {
                Some(Ordering::Greater) => x > y,
                Some(Ordering::Less)    => x < y,
                Some(Ordering::Equal)   => x == y,
                None                    => false
            }
        }

        fn equality_u64(x: u64) -> bool {
            let ore = init_ore();
            let a = full_u64(&ore, x);
            let b = full_u64(&ore, x);

            a == b
        }

        fn compare_u32(x: u32, y: u32) -> bool {
            let ore = init_ore();
            let a: CipherText<Ore, 6> = full(&ore, &u32_pt(x));
            let b: CipherText<Ore, 6> = full(&ore, &u32_pt(y));

            match x.cmp(&y) {
                Ordering::Greater => a > b,
                Ordering::Less    => a < b,
                Ordering::Equal   => a == b
            }
        }

        fn compare_f64(x: f64, y: f64) -> TestResult {
            if x.is_nan() || x.is_infinite() || y.is_nan() || y.is_infinite() {
                return TestResult::discard();
            }

            let ore = init_ore();
            let a: CipherText<Ore, 11> = full(&ore, &f64_pt(x));
            let b: CipherText<Ore, 11> = full(&ore, &f64_pt(y));

            match x.partial_cmp(&y) {
                Some(Ordering::Greater) => TestResult::from_bool(a > b),
                Some(Ordering::Less)    => TestResult::from_bool(a < b),
                Some(Ordering::Equal)   => TestResult::from_bool(a == b),
                None                    => TestResult::failed()
            }
        }

        fn serialize_roundtrip_u64(x: u64) -> bool {
            let ore = init_ore();
            let a = full_u64(&ore, x);
            let bytes = a.to_bytes();
            let b = CipherText::<Ore, 11>::from_slice(&bytes).unwrap();
            a == b
        }
    }

    #[test]
    fn ciphertext_sizes() {
        // u64: 11 blocks. header(4) + xt(11) + f(11*16) + nonce(16) + right(11*8)
        assert_eq!(CipherText::<Ore, 11>::size(), 4 + 11 + 176 + 16 + 88);
        let ore = init_ore();
        assert_eq!(term_bytes(&ore, &u64_pt(456)).len(), 295);
    }

    #[test]
    fn header_emitted_and_validated() {
        let ore = init_ore();
        let mut bytes = term_bytes(&ore, &u64_pt(456));
        assert_eq!(&bytes[0..4], &[0x02, 0x02, 0x00, 11]);

        // Corrupt each header field; parsing must fail.
        for i in 0..4 {
            let mut bad = bytes.clone();
            bad[i] ^= 0xff;
            assert!(CipherText::<Ore, 11>::from_slice(&bad).is_err());
        }

        // Truncation fails.
        bytes.pop();
        assert!(CipherText::<Ore, 11>::from_slice(&bytes).is_err());
    }

    #[test]
    fn cross_scheme_comparison_rejected() {
        let legacy = OreAes128::init(fixed_key(1), fixed_key(2)).unwrap();
        let bit6 = Ore::init(fixed_key(1)).unwrap();

        let a = legacy.encrypt_plaintext(&u64_pt(456)).unwrap().into_bytes();
        let b = term_bytes(&bit6, &u64_pt(456));

        assert_eq!(Ore::compare_raw_slices(&a, &b), None);
        assert_eq!(Ore::compare_raw_slices(&b, &a), None);
        // The legacy comparator infers block count from length; a Bit6
        // u64 ciphertext (295 bytes) never matches a legacy length for
        // equal-length inputs, and unequal lengths return None up front.
        assert_eq!(OreAes128::compare_raw_slices(&a, &b), None);
    }

    #[test]
    fn cross_block_count_comparison_rejected() {
        let ore = init_ore();
        let a = term_bytes(&ore, &u64_pt(456));
        let b = term_bytes(&ore, &u32_pt(456));
        assert_eq!(Ore::compare_raw_slices(&a, &b), None);
    }

    #[test]
    fn smallest_to_largest() {
        let ore = init_ore();
        assert!(full_u64(&ore, 0) < full_u64(&ore, u64::MAX));
    }

    #[test]
    fn comparisons_in_last_block() {
        let ore = init_ore();
        let a = full_u64(&ore, 10);
        let b = full_u64(&ore, 73);

        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn different_keys_not_equal() {
        let ore1 = Ore::init(fixed_key(1)).unwrap();
        let ore2 = Ore::init(fixed_key(3)).unwrap();

        let a = term_bytes(&ore1, &u32_pt(1000));
        let b = term_bytes(&ore2, &u32_pt(1000));

        assert_ne!(Some(Ordering::Equal), Ore::compare_raw_slices(&a, &b));
    }

    /// The PRP seeds and permutation tables of every block, which must not
    /// survive an encryption in dead stack (review of #82).
    fn block_secrets(ore: &Ore, blocks: &[u8; 11]) -> Vec<Vec<u8>> {
        let seeds = ore.derive_prp_seeds(blocks);
        let mut needles = Vec::new();
        for seed in seeds.0.iter() {
            let prp: <Bit6 as BlockWidth>::Prp = Prp::new(seed).unwrap();
            needles.push(seed.to_vec());
            let symbols = (0..64).map(crate::primitives::Symbol::<64>::from_low_bits);
            needles.push(symbols.clone().map(|i| prp.permute(i).get()).collect());
            needles.push(symbols.map(|i| prp.invert(i).get()).collect());
        }
        needles
    }

    fn assert_no_block_secrets(encrypt: fn(&Ore, u64), unscrubbed: fn(&Ore, u64)) {
        use crate::primitives::stack::{residue, SCRUB_BYTES};
        let x = 0x0123_4567_89ab_cdefu64;
        let needles = block_secrets(&Ore::init(fixed_key(0x3c)).unwrap(), u64_blocks(x).inner());

        // Positive control and depth: without the scrub the secrets are
        // there, and the scrub must reach deeper than the encryption did.
        let ore = Ore::init(fixed_key(0x3c)).unwrap();
        let dead = residue::after(move || unscrubbed(&ore, x));
        assert!(needles.iter().any(|n| residue::contains(&dead, n)));
        let depth = residue::depth(&dead);
        assert!(
            depth < SCRUB_BYTES,
            "encryption reached {} bytes of stack, past the {}-byte scrub",
            depth,
            SCRUB_BYTES
        );

        let ore = Ore::init(fixed_key(0x3c)).unwrap();
        let dead = residue::after(move || encrypt(&ore, x));
        for (i, needle) in needles.iter().enumerate() {
            assert!(
                !residue::contains(&dead, needle),
                "block {} {} left in dead stack",
                i / 3,
                ["seed", "permutation", "inverse"][i % 3]
            );
        }
    }

    fn u64_blocks(x: u64) -> Blocks6<[u8; 11]> {
        Blocks6::decompose(&x.to_be_bytes(), [0u8; 11])
    }

    #[test]
    fn encrypt_leaves_no_prp_secrets_on_the_stack() {
        assert_no_block_secrets(
            |ore, x| {
                core::hint::black_box(ore.encrypt_plaintext(&u64_pt(x)).unwrap());
            },
            |ore, x| {
                core::hint::black_box(ore.encrypt_blocks(&u64_blocks(x)).unwrap());
            },
        );
    }

    #[test]
    fn encrypt_left_leaves_no_prp_secrets_on_the_stack() {
        assert_no_block_secrets(
            |ore, x| {
                core::hint::black_box(ore.encrypt_query_plaintext(&u64_pt(x)).unwrap());
            },
            |ore, x| {
                core::hint::black_box(ore.encrypt_left_blocks(&u64_blocks(x)).unwrap());
            },
        );
    }
}
