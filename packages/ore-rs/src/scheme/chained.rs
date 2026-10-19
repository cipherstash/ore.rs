//! Variable-length / chained-prefix BlockORE over 6-bit blocks.
//!
//! Lifts the fixed-N packed-prefix cap (≤ 14 blocks) by deriving every
//! per-block secret from an incremental **AES-CMAC accumulator** over the
//! prefix, instead of packing the raw prefix into one AES block. This enables
//! arbitrary-length plaintexts — strings in particular. Design:
//! `docs/plans/2026-06-15-ore-v2-cmac-accumulator-spec.md` (the A2 gate).
//!
//! **Status: wire format (scheme id `0x03`) frozen as of 0.9.0.**
//! `tests/compat_chained_vectors.rs` pins the bytes, padded and unpadded; a
//! change that alters them breaks every stored chained ciphertext.
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
//! **Length.** The header stores the block count, and the size is
//! `7 + 25*count + 16` bytes for a full ciphertext (`7 + 17*count` for a
//! left), so every ciphertext gives its block count with no comparison or
//! query. Unpadded, a string of `n` UTF-8 bytes has `count = ⌈8n/6⌉`, which
//! is strictly increasing in `n`, so the ciphertext gives `n` exactly. The
//! string encryptors therefore pad by default
//! ([`Padding`](crate::scheme::chained::Padding)): the string is extended
//! with NUL bytes to a length bucket, and a ciphertext reveals only the
//! bucket. The default is powers of two with a 16-byte floor: 16, 32, 64
//! bytes and so on
//! ([`Padding::PowerOfTwo`](crate::scheme::chained::Padding::PowerOfTwo)).
//! Padmé (Nikitin et al., PETS 2019) was considered and set aside: at
//! database string lengths it hides little (see the variant docs and
//! <https://github.com/cipherstash/ore.rs/issues/104>).
//!
//! Padding with NUL bytes keeps order and equality for strings that do not
//! end in NUL. NUL bytes decompose to zero blocks, the same zero bits the
//! decomposition already fills a final partial block with. Where the shorter
//! of two strings ends, the longer one has a non-zero bit somewhere in its
//! remaining bytes (its last byte is not NUL, though bytes before it may
//! be), and the shorter string has only zeros there, so the shorter sorts
//! first, as "shorter sorts first" requires. Equal strings have equal
//! lengths, so they pad to the same bucket. A string that ends in NUL would
//! pad to the same blocks as the string without it, so the padded encryptors
//! refuse it ([`OreError::TrailingNul`](crate::OreError::TrailingNul)).
//! Postgres `text` and `jsonb` cannot hold NUL. Pad blocks cannot be told
//! apart from the string's own blocks in a ciphertext: each block's PRP is
//! keyed by its position and prefix.
//!
//! The header also carries the padding policy, and the comparators return
//! `None` for two ciphertexts made under different policies: an unpadded
//! `"abc"` and a padded `"abc"` have different blocks, and would compare
//! unequal. Stored values and the queries that compare with them must use
//! one policy.
//!
//! A cipher also has a longest string it encrypts
//! ([`Options::with_max_bytes`](crate::scheme::chained::Options::with_max_bytes),
//! default [`DEFAULT_MAX_STR_BYTES`](crate::scheme::chained::DEFAULT_MAX_STR_BYTES)
//! = 1024 bytes); a longer one is refused
//! ([`OreError::TooLong`](crate::OreError::TooLong)). Ciphertext size and
//! encryption time grow with the padded length, and the string comes from
//! the caller, so without a ceiling one 1025-byte string costs a 2048-byte
//! bucket, 2731 blocks and a 68 KB ciphertext. The ceiling is not on the
//! wire: the comparators accept any block count the policy admits.
//!
//! Strings are the only public plaintext. The scheme encrypts any sequence of
//! 6-bit symbols, and the tests use that entry point directly (symbols a
//! string never produces, unpadded), but raw symbols cannot be padded with
//! zero symbols, since a trailing zero symbol is a real value there, so they
//! are not offered as an API (#110).
//!
//! **Fixed-width plaintexts.** A sealed `OrderPlaintext` of any fixed
//! width goes in unpadded (every value of its target has one width, so
//! there is nothing to hide): a `u128`, a decimal, a timestamp, a uuid. The
//! ciphertext is tagged [`Padding::None`](crate::scheme::chained::Padding::None), and the string ceiling is not
//! checked. The block count is a length, not a type: a `u128` and an
//! unpadded 16-byte string are both 22 blocks, and under one key an equal
//! encoding gives an equal ciphertext. vitaminc's salt carries the target,
//! so a space of one target never meets another's terms.
//!
//! The scheme takes a sealed plaintext through [`crate::OreScheme`] and nothing
//! else. Text (`OrderTarget::Text`) is padded under the cipher's
//! [`Options`](crate::scheme::chained::Options); bytes (`OrderTarget::Bytes`) are not, since NUL padding
//! would refuse every value that ends in a zero byte, but are refused past
//! the ceiling as text is; a fixed-width target is neither padded nor
//! bounded, its length being the target's. vitaminc's text and bytes encodings start with a marker byte, so
//! no plaintext is empty and every term has a keyed block.
//!
//! **Stored rows compare offline.** A full ciphertext carries its
//! deterministic left half (`xt`, `f`), so anyone holding two stored full
//! ciphertexts can run `compare_raw_slices` with no
//! query and learn their order and common-prefix length. The legacy scheme
//! has the same exposure. There is no right-only storage path yet (plan
//! §5(b)).

use std::cmp::Ordering;
use std::convert::TryFrom;
use std::sync::Mutex;

use rand::TryRng;
use subtle_ng::{Choice, ConditionallySelectable, ConstantTimeEq};
use vitaminc_context::Context;
use vitaminc_ore::{OrderPlaintext, OrderTarget};
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::SafeRand;
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
use crate::ciphertext::ParseError;
use crate::ciphertext::{parse_header, WireHeader, WIRE_HEADER_LEN};
use crate::primitives::cmac::{final_block, prefix_block, Branch, CmacAccumulator, WIDTH_BIT6};
use crate::primitives::hash::FixedPiZ2Hash;
use crate::primitives::prp::LemireFyPrp;
use crate::primitives::{stack, AesBlock, Hash, HashKey, Prp};
use crate::scheme::decompose::{num_blocks_6bit, Blocks6};
use crate::scheme::keys;
use crate::scheme::width::FirstDiff;
use crate::{OreError, OreScheme, Query, Term};

const VERSION: u8 = 0x02;
pub(crate) const SCHEME_ID: u8 = 0x03;
/// The common wire header of this scheme.
const WIRE: WireHeader = WireHeader {
    version: VERSION,
    scheme_id: SCHEME_ID,
};
const DOMAIN: usize = 64;
/// CMAC tags per block for the PRP keystream: ⌈(DOMAIN−1)·8 / 16⌉ = 32.
const STREAM_BLOCKS: usize = 32;
const F_LEN: usize = 16;
const RIGHT_LEN: usize = DOMAIN / 8; // 8
/// The padding policy tag after the common wire header: a kind byte and a
/// big-endian `u16` (see [`Padding`]).
const PADDING_LEN: usize = 3;
const HEADER_LEN: usize = WIRE_HEADER_LEN + PADDING_LEN;
const NONCE_LEN: usize = 16;

/// The only input the caller's key is evaluated on (spec §3): ends in
/// `'t'` (`0x74`), outside every legacy PRF input's byte 15. See
/// `scheme::keys`.
const ROOT_LABEL: [u8; 16] = *b"ORE.v2.chainroot";
const _: () = assert!(
    ROOT_LABEL[15] > 14,
    "root label collides with a legacy PRF input"
);
/// Label for the accumulator key under the salted key (spec §3).
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

/// How the string encryptors pad a string before encrypting it, so that a
/// ciphertext reveals a length bucket rather than the exact length (see the
/// module docs).
///
/// Lengths are in UTF-8 bytes. The policy belongs with the key: stored
/// values and the queries that compare with them must use the same one,
/// and changing it means re-encrypting the stored values. The comparators refuse to compare ciphertexts
/// made under different policies.
///
/// Padding hides the exact length in the ciphertext only: the time the
/// encryptor takes still depends on the exact length of the string.
///
/// More policies may follow (a growth ratio between buckets, boundaries
/// fitted to the data), so the enum is non-exhaustive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Padding {
    /// No padding: the ciphertext reveals the exact length.
    None,
    /// Pad to `min_bytes` if the string fits, and otherwise to the smallest
    /// power of two that holds it. With the default 16-byte floor the
    /// buckets are 16, 32, 64, 128 bytes and so on: a ciphertext reveals
    /// about `log₂ L` of a length `L`, every string up to `min_bytes` long
    /// pads to the same length, and above the floor padding less than
    /// doubles a length. A
    /// string that would pad past [`MAX_STR_BYTES`] is refused
    /// ([`OreError::TooManyBlocks`]), so with the default floor the longest
    /// bucket is 32768 bytes; the cipher's own ceiling
    /// ([`Options::with_max_bytes`]) is usually far lower.
    ///
    /// Chosen over Padmé (Nikitin et al., PETS 2019). Padmé leaves only
    /// `O(log log L)` bits of the length and adds under 12.5%, but it was
    /// designed for kilobyte-to-gigabyte messages. At database string
    /// lengths its buckets are narrow: below 9 bytes it changes nothing,
    /// from 9 to 31 bytes it rounds only to an even length, and from 32 to
    /// 63 to a multiple of 4. Powers of two cost more blocks and leak more
    /// in theory, but their buckets are far wider where strings actually
    /// are. The simulation behind the choice is in
    /// <https://github.com/cipherstash/ore.rs/issues/104>.
    PowerOfTwo {
        /// Floor below which every string pads to one bucket.
        min_bytes: u16,
    },
    /// Pad every string to `max_bytes`, so ciphertexts reveal nothing of
    /// the length. Longer strings are refused
    /// ([`OreError::ExceedsPadding`]).
    Fixed {
        /// The length every string pads to.
        max_bytes: u16,
    },
}

impl Default for Padding {
    /// Powers of two with a 16-byte floor.
    fn default() -> Self {
        Padding::PowerOfTwo { min_bytes: 16 }
    }
}

impl Padding {
    /// The length in bytes a string of `len` bytes pads to, which is what a
    /// ciphertext reveals of it. Errors as the string encryptors do:
    /// [`OreError::ExceedsPadding`] if `len` exceeds a fixed length, and
    /// [`OreError::TooManyBlocks`] if the padded string has more blocks than
    /// the wire format can number.
    pub fn padded_len(self, len: usize) -> Result<usize, OreError> {
        let padded = match self {
            Padding::None => len,
            Padding::PowerOfTwo { min_bytes } if len <= min_bytes.into() => min_bytes.into(),
            Padding::PowerOfTwo { .. } => len
                .checked_next_power_of_two()
                .ok_or(OreError::TooManyBlocks)?,
            Padding::Fixed { max_bytes } if len <= max_bytes.into() => max_bytes.into(),
            Padding::Fixed { .. } => return Err(OreError::ExceedsPadding),
        };
        if padded > MAX_STR_BYTES {
            return Err(OreError::TooManyBlocks);
        }
        Ok(padded)
    }

    /// The policy as it appears in the wire header.
    fn to_wire(self) -> [u8; PADDING_LEN] {
        let (kind, n) = match self {
            Padding::None => (0, 0),
            Padding::PowerOfTwo { min_bytes } => (1, min_bytes),
            Padding::Fixed { max_bytes } => (2, max_bytes),
        };
        let [hi, lo] = n.to_be_bytes();
        [kind, hi, lo]
    }

    /// Parse a policy written by [`Self::to_wire`]. A policy no cipher
    /// could have been initialised with is refused, as is an unknown kind.
    fn from_wire(tag: [u8; PADDING_LEN]) -> Option<Self> {
        let [kind, hi, lo] = tag;
        let n = u16::from_be_bytes([hi, lo]);
        let padding = match kind {
            0 if n == 0 => Padding::None,
            1 => Padding::PowerOfTwo { min_bytes: n },
            2 => Padding::Fixed { max_bytes: n },
            _ => return None,
        };
        padding.padded_len(0).ok().map(|_| padding)
    }

    /// Whether a ciphertext of `count` blocks can have been made under this
    /// policy: the block count of some length the policy pads to. The
    /// parsers and comparators refuse a header whose count and policy no
    /// cipher could have produced together.
    fn admits_count(self, count: usize) -> bool {
        match self {
            Padding::None => true,
            Padding::Fixed { max_bytes } => count == num_blocks_6bit(max_bytes.into()),
            Padding::PowerOfTwo { min_bytes } => {
                let min_bytes = usize::from(min_bytes);
                count == num_blocks_6bit(min_bytes)
                    || (0..=MAX_STR_BYTES.ilog2()).any(|k| {
                        let bucket = 1usize << k;
                        bucket > min_bytes && count == num_blocks_6bit(bucket)
                    })
            }
        }
    }
}

/// The longest string a cipher encrypts unless [`Options::with_max_bytes`]
/// says otherwise: 1024 UTF-8 bytes, a 1024-byte bucket under the default
/// padding.
pub const DEFAULT_MAX_STR_BYTES: usize = 1024;

/// Per-cipher settings, passed to [`OreAes128Bit6Chained::init_with`]:
/// the salt the key is derived under, and the string encryptors' padding
/// policy and ceiling. Like the key, they belong to the values that are
/// compared together: stored values and the queries that compare with them
/// use the same ones.
///
/// ```rust
/// use ore_rs::scheme::chained::{OreAes128Bit6Chained, Options, Padding};
/// use ore_rs::OreScheme;
/// use vitaminc_context::Context;
/// use vitaminc_ore::{order, OrderTarget, Physical};
/// use vitaminc_protected::Protected;
///
/// let options = Options::default()
///     .with_salt(&Context::from_encoded(&b"users.email"[..]))
///     .with_padding(Padding::PowerOfTwo { min_bytes: 32 })
///     .with_max_bytes(256);
/// let ore = OreAes128Bit6Chained::init_with(Protected::new([0u8; 16]), options).unwrap();
/// let text = |s: &str| order(OrderTarget::Text, None, Physical::Text(s)).unwrap();
/// // The ceiling counts the marker byte vitaminc puts before the text.
/// assert!(ore.encrypt_plaintext(&text(&"a".repeat(255))).is_ok());
/// assert!(ore.encrypt_plaintext(&text(&"a".repeat(256))).is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    salt: Vec<u8>,
    padding: Padding,
    max_bytes: usize,
}

impl Default for Options {
    /// An empty salt, [`Padding::default`] and [`DEFAULT_MAX_STR_BYTES`].
    fn default() -> Self {
        Self {
            salt: Vec::new(),
            padding: Padding::default(),
            max_bytes: DEFAULT_MAX_STR_BYTES,
        }
    }
}

impl Options {
    /// The defaults; see [`Default`].
    pub fn new() -> Self {
        Self::default()
    }

    /// The salt the key is derived under: a name for what the key is for
    /// (a data set, a tenant, a plaintext type). Ciphertexts under different
    /// salts share no key material; nothing on the wire records the salt,
    /// so a mismatched pair compares to a confident, meaningless result,
    /// `Equal` included. The default is empty. The context a vitaminc
    /// space derives, or any bytes as `Context::from_encoded(bytes)`. See
    /// [`OreAes128Bit6Chained::init_with`].
    pub fn with_salt(self, salt: &Context<'_>) -> Self {
        Self {
            salt: salt.as_bytes().to_vec(),
            ..self
        }
    }

    /// The padding policy the string encryptors apply.
    pub fn with_padding(self, padding: Padding) -> Self {
        Self { padding, ..self }
    }

    /// The longest string, in UTF-8 bytes, the cipher encrypts; a longer
    /// one returns [`OreError::TooLong`]. Bounds what one input can cost in
    /// ciphertext size and encryption time, and how many length buckets the
    /// ciphertexts can show. Under [`Padding::Fixed`] the fixed length is also a
    /// ceiling, and the lower of the two applies. `init_with` refuses a
    /// ceiling of 0 or one that pads past [`MAX_STR_BYTES`].
    pub fn with_max_bytes(self, max_bytes: usize) -> Self {
        Self { max_bytes, ..self }
    }

    /// The salt; see [`Self::with_salt`].
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// The padding policy.
    pub fn padding(&self) -> Padding {
        self.padding
    }

    /// The longest string the cipher encrypts; see [`Self::with_max_bytes`].
    pub fn max_bytes(&self) -> usize {
        self.ceiling()
    }

    /// `max_bytes`, or the fixed length if that is lower.
    fn ceiling(&self) -> usize {
        match self.padding {
            Padding::Fixed { max_bytes } => self.max_bytes.min(usize::from(max_bytes)),
            _ => self.max_bytes,
        }
    }

    /// Why a cipher cannot be initialised with these options, if it cannot.
    fn check(&self) -> Result<(), OreError> {
        if self.max_bytes == 0 {
            return Err(OreError::InitFailed);
        }
        // The policy must pad the empty string and the longest string.
        self.padding
            .padded_len(0)
            .map_err(|_| OreError::InitFailed)?;
        self.padding
            .padded_len(self.ceiling())
            .map_err(|_| OreError::InitFailed)?;
        Ok(())
    }
}

/// Left half of a chained ciphertext: per-block permuted symbol + tag.
/// Crate-private: a [`Query`] carries its bytes.
#[derive(Clone, Debug)]
pub(crate) struct VarLeft {
    xt: Vec<u8>,
    f: Vec<[u8; F_LEN]>,
    padding: Padding,
}

/// Right half: per-ciphertext nonce + per-block masked bitvectors.
#[derive(Clone, Debug)]
pub(crate) struct VarRight {
    nonce: [u8; NONCE_LEN],
    blocks: Vec<[u8; RIGHT_LEN]>,
}

/// Full variable-length ciphertext. Crate-private: a [`Term`] carries its
/// bytes.
#[derive(Clone, Debug)]
pub(crate) struct VarCipherText {
    left: VarLeft,
    right: VarRight,
}

impl VarLeft {
    /// `header ‖ xt ‖ f` (no nonce/right half).
    pub fn to_bytes(&self) -> Vec<u8> {
        let count = self.xt.len();
        let mut out = Vec::with_capacity(left_len(count));
        write_header(count, self.padding, &mut out);
        out.extend_from_slice(&self.xt);
        for fb in &self.f {
            out.extend_from_slice(fb);
        }
        out
    }

    /// The padding policy the plaintext was encrypted under, for the tests.
    #[cfg(test)]
    pub fn padding(&self) -> Padding {
        self.padding
    }
}

/// Read `xt` and `f` out of a validated left view (a `VarLeft` or the
/// prefix of a full ciphertext) of `count` blocks, tagged `padding`.
#[cfg(test)]
fn parse_left_view(data: &[u8], count: usize, padding: Padding) -> VarLeft {
    let xt = data[HEADER_LEN..HEADER_LEN + count].to_vec();
    let mut f = Vec::with_capacity(count);
    for n in 0..count {
        let mut fb = [0u8; F_LEN];
        fb.copy_from_slice(f_at(data, count, n));
        f.push(fb);
    }
    VarLeft { xt, f, padding }
}

impl VarCipherText {
    /// `header ‖ xt ‖ f ‖ nonce ‖ right`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let count = self.left.xt.len();
        let mut out = Vec::with_capacity(total_len(count));
        write_header(count, self.left.padding, &mut out);
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

    /// The padding policy the plaintext was encrypted under, for the tests.
    #[cfg(test)]
    pub fn padding(&self) -> Padding {
        self.left.padding
    }

    /// Parse the bytes produced by [`Self::to_bytes`], for the tests.
    #[cfg(test)]
    pub fn from_slice(data: &[u8]) -> Result<Self, ParseError> {
        let (count, padding) = parse_chained_header(data).ok_or(ParseError)?;
        if data.len() != total_len(count) {
            return Err(ParseError);
        }
        // Same rule as the comparators (and the fixed-width parsers): a symbol
        // outside the 6-bit domain is not a ciphertext of this scheme.
        if !symbols_in_domain(data, count) {
            return Err(ParseError);
        }
        let left = parse_left_view(data, count, padding);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_at(data, count));
        let mut blocks = Vec::with_capacity(count);
        for n in 0..count {
            let mut rb = [0u8; RIGHT_LEN];
            rb.copy_from_slice(right_at(data, count, n));
            blocks.push(rb);
        }
        Ok(VarCipherText {
            left,
            right: VarRight { nonce, blocks },
        })
    }
}

/// Write the wire header: version, scheme id, block count, padding policy.
///
/// Every ciphertext has at most `u16::MAX` blocks: encryption refuses more
/// ([`OreError::TooManyBlocks`]) and parsing reads the count from a `u16`.
/// Were a longer one made, the saturated count would not match its body, so
/// every parser would refuse the bytes.
fn write_header(count: usize, padding: Padding, out: &mut Vec<u8>) {
    WIRE.write(u16::try_from(count).unwrap_or(u16::MAX), out);
    out.extend_from_slice(&padding.to_wire());
}

/// The block count and padding policy of a serialised view, if its header
/// is this scheme's and the count is one the policy can produce.
fn parse_chained_header(view: &[u8]) -> Option<(usize, Padding)> {
    let ((ver, sid, count), body) = parse_header(view).ok()?;
    if ver != VERSION || sid != SCHEME_ID {
        return None;
    }
    let tag = <[u8; PADDING_LEN]>::try_from(body.get(..PADDING_LEN)?).ok()?;
    let padding = Padding::from_wire(tag)?;
    padding.admits_count(count).then_some((count, padding))
}

/// The block counts of two serialised views, if both headers are this
/// scheme's and they share a padding policy. The comparators refuse
/// ciphertexts made under different policies (see the module docs).
fn parse_pair(a: &[u8], b: &[u8]) -> Option<(usize, usize)> {
    let (ca, pa) = parse_chained_header(a)?;
    let (cb, pb) = parse_chained_header(b)?;
    (pa == pb).then_some((ca, cb))
}

/// Variable-length / chained-prefix ORE cipher (6-bit blocks).
///
/// Per-encryption nonces come from a [`SafeRand`] seeded from the OS when
/// the cipher is made, behind a mutex, so the cipher is `Send + Sync`.
pub struct OreAes128Bit6Chained {
    /// Dedicated CMAC accumulator key (subsumes the fixed-N `prf1`/`prf2`).
    k_acc: [u8; 16],
    /// The salt the key was derived under, and the string encryptors'
    /// padding policy and ceiling.
    options: Options,
    rng: Mutex<SafeRand>,
}

// Opaque Debug: never render key material.
impl std::fmt::Debug for OreAes128Bit6Chained {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OreAes128Bit6Chained")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl OreAes128Bit6Chained {
    /// Initialise from one 16-byte key with the default [`Options`]: an
    /// empty salt, text padded with powers of two from a 16-byte floor,
    /// and at most [`DEFAULT_MAX_STR_BYTES`] long.
    pub fn init(key: Protected<[u8; 16]>) -> Result<Self, OreError> {
        Self::init_with(key, Options::default())
    }

    /// Initialise from one 16-byte key and a salt, with the other options
    /// at their defaults: `init_with(key, Options::default().with_salt(salt))`.
    /// The same constructor as [`OreAes128Bit6::init_with_salt`](crate::scheme::bit2_w6::OreAes128Bit6::init_with_salt).
    pub fn init_with_salt(key: Protected<[u8; 16]>, salt: &Context<'_>) -> Result<Self, OreError> {
        Self::init_with(key, Options::default().with_salt(salt))
    }

    /// Initialise from one 16-byte key and the given [`Options`]: the salt
    /// naming what the key is for, the string padding policy and the
    /// string ceiling. Returns [`OreError::InitFailed`] for a ceiling of
    /// 0, or a policy that would pad the empty string or the longest
    /// string past [`MAX_STR_BYTES`].
    ///
    /// The CMAC accumulator derives every per-block secret from one key
    /// via branch tags (spec §3), keyed by `AES_{k_salt}(ACC_KEY_LABEL)`
    /// with `k_salt = CMAC_{AES_key(ROOT_LABEL)}(salt)`; see the
    /// crate-private `scheme::keys` for the stages and their argument.
    ///
    /// Ciphertexts under different salts share no key material, but
    /// nothing on the wire records the salt, so the comparators cannot
    /// refuse a mismatched pair: they return a confident, meaningless
    /// result, `Equal` included (the unpadded empty string has no blocks
    /// and compares `Equal` under any salts), so no result confirms that
    /// two salts match. Keep the salt with the identity of the stored
    /// data, as you keep the key.
    ///
    /// Fails ([`OreError::Random`]) if the OS random number generator could
    /// not seed the nonce generator.
    pub fn init_with(key: Protected<[u8; 16]>, options: Options) -> Result<Self, OreError> {
        Self::init_with_rng(key, options, SafeRand::from_entropy()?)
    }

    /// [`Self::init_with`] with every nonce drawn from `seed`, so a test can
    /// pin a full ciphertext's bytes. Never ship a seeded cipher: two values
    /// encrypted under one seed share their nonces.
    #[cfg(any(test, feature = "test-support"))]
    pub fn init_seeded(
        key: Protected<[u8; 16]>,
        options: Options,
        seed: [u8; 32],
    ) -> Result<Self, OreError> {
        use vitaminc_random::SeedableRng;
        Self::init_with_rng(key, options, SafeRand::from_seed(seed))
    }

    fn init_with_rng(
        key: Protected<[u8; 16]>,
        options: Options,
        rng: SafeRand,
    ) -> Result<Self, OreError> {
        options.check()?;
        let k_salt = keys::salted(&keys::root(key.risky_ref(), &ROOT_LABEL), options.salt());
        let k_acc = *keys::subkey(&k_salt, &ACC_KEY_LABEL);
        Ok(Self {
            k_acc,
            options,
            rng: Mutex::new(rng),
        })
    }

    /// Draw one nonce; see the Bit6 sibling.
    fn fill_nonce(&self, nonce: &mut [u8; NONCE_LEN]) {
        let mut rng = self
            .rng
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match rng.try_fill_bytes(nonce) {
            Ok(()) => {}
            Err(never) => match never {},
        }
    }

    /// The options this cipher was initialised with.
    pub fn options(&self) -> &Options {
        &self.options
    }

    /// The padding policy the string encryptors apply.
    pub fn padding(&self) -> Padding {
        self.options.padding()
    }

    /// Derive the per-block PRP from the accumulator's `PRP_STREAM` branch.
    fn prp_at(&self, acc: &CmacAccumulator, n: u16) -> LemireFyPrp<DOMAIN> {
        let mut stream = [0u8; STREAM_BLOCKS * 16];
        for (c, chunk) in stream.chunks_mut(16).enumerate() {
            chunk.copy_from_slice(&acc.finalize(&final_block(
                Branch::PrpStream,
                n,
                c as u16,
                WIDTH_BIT6,
            )));
        }
        let prp = LemireFyPrp::<DOMAIN>::from_stream(&stream);
        stream.zeroize();
        prp
    }

    /// Full Left+Right ciphertext for raw symbols `x` (one 6-bit symbol per
    /// element), for the tests: symbols a string never produces, over the
    /// whole domain. A value `>= 64` returns [`OreError::PrpError`]. The
    /// symbols are not padded, and the ciphertext is tagged
    /// [`Padding::None`]. Not public; see the module docs.
    #[cfg(test)]
    pub(crate) fn encrypt_var(&self, x: &[u8]) -> Result<VarCipherText, OreError> {
        stack::scrubbed(|| self.encrypt_blocks(&check_symbols(x)?, Padding::None))
    }

    /// Full ciphertext over blocks already known to be in the 6-bit
    /// domain, without the stack scrub. Every caller runs it inside
    /// [`stack::scrubbed`]: building a block's PRP and running the
    /// accumulator leave their secrets in dead stack (see
    /// `primitives::stack`).
    /// `padding` is the policy `x` was padded under, for the header.
    fn encrypt_blocks<B: AsRef<[u8]>>(
        &self,
        x: &Blocks6<B>,
        padding: Padding,
    ) -> Result<VarCipherText, OreError> {
        let count = x.len();
        if count > u16::MAX as usize {
            return Err(OreError::TooManyBlocks);
        }

        let mut acc = CmacAccumulator::new(&self.k_acc);
        let mut nonce = [0u8; NONCE_LEN];
        self.fill_nonce(&mut nonce);
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
            let prp = self.prp_at(&acc, n16);
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
            left: VarLeft { xt, f, padding },
            right: VarRight { nonce, blocks },
        })
    }

    /// Left-only ciphertext for raw symbols, for the tests; see
    /// [`Self::encrypt_var`].
    #[cfg(test)]
    pub(crate) fn encrypt_left_var(&self, x: &[u8]) -> Result<VarLeft, OreError> {
        stack::scrubbed(|| self.encrypt_left_blocks(&check_symbols(x)?, Padding::None))
    }

    /// Left-only ciphertext over blocks already known to be in the 6-bit
    /// domain, without the stack scrub; see [`Self::encrypt_blocks`].
    fn encrypt_left_blocks<B: AsRef<[u8]>>(
        &self,
        x: &Blocks6<B>,
        padding: Padding,
    ) -> Result<VarLeft, OreError> {
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
            let prp = self.prp_at(&acc, n16);
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
        Ok(VarLeft { xt, f, padding })
    }

    /// Encrypt a string (UTF-8 bytes → MSB-first 6-bit blocks), padded under
    /// the cipher's [`Padding`] policy: the text path over raw UTF-8, for
    /// the tests. The sealed path, [`OreScheme::encrypt_plaintext`], runs
    /// the same code over vitaminc's text encoding.
    #[cfg(test)]
    pub(crate) fn encrypt_str(&self, s: &str) -> Result<VarCipherText, OreError> {
        self.encrypt_padded_bytes(s.as_bytes())
    }

    /// Left-only string ciphertext, padded and refused as
    /// [`Self::encrypt_str`] does.
    #[cfg(test)]
    pub(crate) fn encrypt_left_str(&self, s: &str) -> Result<VarLeft, OreError> {
        self.encrypt_left_padded_bytes(s.as_bytes())
    }

    /// Encrypt bytes already encoded so that byte order is value order,
    /// padded with NUL bytes under the cipher's [`Padding`] policy and
    /// refused past its ceiling: the text path.
    ///
    /// Errors:
    /// - [`OreError::TrailingNul`] if the policy pads and the bytes end in
    ///   NUL;
    /// - [`OreError::ExceedsPadding`] if the policy is [`Padding::Fixed`]
    ///   and the bytes are longer;
    /// - [`OreError::TooManyBlocks`] if the padded bytes are longer than
    ///   [`MAX_STR_BYTES`];
    /// - [`OreError::TooLong`] if the bytes are longer than the cipher's
    ///   [`Options::max_bytes`].
    ///
    /// The ciphertext reveals the length bucket under the policy (the
    /// exact length for [`Padding::None`]), and comparisons reveal the
    /// order and common-prefix length; see the module docs. Crate-private:
    /// the only bytes this scheme takes arrive sealed.
    pub(crate) fn encrypt_padded_bytes(&self, bytes: &[u8]) -> Result<VarCipherText, OreError> {
        stack::scrubbed(|| {
            self.encrypt_blocks(
                &padded_bytes_to_blocks(bytes, &self.options)?,
                self.padding(),
            )
        })
    }

    /// [`Self::encrypt_padded_bytes`], for the left half.
    pub(crate) fn encrypt_left_padded_bytes(&self, bytes: &[u8]) -> Result<VarLeft, OreError> {
        stack::scrubbed(|| {
            self.encrypt_left_blocks(
                &padded_bytes_to_blocks(bytes, &self.options)?,
                self.padding(),
            )
        })
    }

    /// Encrypt bytes already encoded so that byte order is value order,
    /// unpadded: the path for a fixed-width plaintext and for vitaminc's
    /// bytes target. The cipher's [`Options`] do not apply; the ciphertext
    /// is tagged [`Padding::None`]. Bytes longer than [`MAX_STR_BYTES`]
    /// return [`OreError::TooManyBlocks`] before any block is made. The
    /// bytes are borrowed, so a large plaintext is never copied onto the
    /// stack.
    pub(crate) fn encrypt_unpadded_bytes(&self, bytes: &[u8]) -> Result<VarCipherText, OreError> {
        stack::scrubbed(|| self.encrypt_blocks(&bytes_to_blocks(bytes)?, Padding::None))
    }

    /// [`Self::encrypt_unpadded_bytes`], for the left half.
    pub(crate) fn encrypt_left_unpadded_bytes(&self, bytes: &[u8]) -> Result<VarLeft, OreError> {
        stack::scrubbed(|| self.encrypt_left_blocks(&bytes_to_blocks(bytes)?, Padding::None))
    }
}

impl crate::sealed::Sealed for OreAes128Bit6Chained {}

/// How a sealed plaintext goes in: text padded under the cipher's options
/// and refused past its ceiling; bytes unpadded but refused past the
/// ceiling too, since their length is the caller's; a fixed-width target
/// unpadded, with no ceiling, since its length is the target's.
enum Path {
    Padded,
    Unpadded,
}

impl OreAes128Bit6Chained {
    fn path(&self, plaintext: &OrderPlaintext) -> Result<Path, OreError> {
        match plaintext.target() {
            OrderTarget::Text => Ok(Path::Padded),
            OrderTarget::Bytes => {
                if plaintext.bytes().risky_ref().len() > self.options.max_bytes() {
                    return Err(OreError::TooLong);
                }
                Ok(Path::Unpadded)
            }
            _ => Ok(Path::Unpadded),
        }
    }
}

impl OreScheme for OreAes128Bit6Chained {
    /// Text is padded under the cipher's [`Options`]; bytes and
    /// fixed-width plaintexts go in unpadded. Text and bytes are refused
    /// past the cipher's ceiling ([`OreError::TooLong`]).
    fn encrypt_plaintext(&self, plaintext: &OrderPlaintext) -> Result<Term, OreError> {
        let bytes = plaintext.bytes().risky_ref();
        let ct = match self.path(plaintext)? {
            Path::Padded => self.encrypt_padded_bytes(bytes)?,
            Path::Unpadded => self.encrypt_unpadded_bytes(bytes)?,
        };
        Ok(Term::new(ct.to_bytes()))
    }

    fn encrypt_query_plaintext(&self, plaintext: &OrderPlaintext) -> Result<Query, OreError> {
        let bytes = plaintext.bytes().risky_ref();
        let left = match self.path(plaintext)? {
            Path::Padded => self.encrypt_left_padded_bytes(bytes)?,
            Path::Unpadded => self.encrypt_left_unpadded_bytes(bytes)?,
        };
        Ok(Query::new(left.to_bytes()))
    }

    /// Compare two serialised full ciphertexts (lexicographic; shorter prefix
    /// sorts first). `None` if either is not a well-formed ciphertext of this
    /// scheme, or if they were padded under different policies.
    fn compare_raw_slices(a: &[u8], b: &[u8]) -> Option<Ordering> {
        let (ca, cb) = parse_pair(a, b)?;
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
    /// [`OreScheme::encrypt_query_plaintext`] — against a stored
    /// full ciphertext `full`. This is the Lewi-Wu query path: a comparison
    /// needs only the query's left half (`xt`/`f`) and the stored ciphertext's
    /// right half, so the smaller left-only artifact suffices. This does not
    /// make stored data safe at rest: a stored *full* ciphertext also carries
    /// its left half, so two stored rows compare offline (see the module docs). Returns `left`'s order relative to
    /// `full` (`Less` ⇒ the query plaintext sorts before the stored one).
    /// `None` if either input is malformed, or if they were padded under
    /// different policies.
    fn compare_left_to_full(left: &[u8], full: &[u8]) -> Option<Ordering> {
        let (cl, cf) = parse_pair(left, full)?;
        // `left` is `header ‖ xt ‖ f` (no nonce/right); `full` is complete.
        if left.len() != left_len(cl) || full.len() != total_len(cf) {
            return None;
        }
        if !symbols_in_domain(left, cl) || !symbols_in_domain(full, cf) {
            return None;
        }
        Some(Self::compare_views(left, cl, full, cf))
    }
}

impl OreAes128Bit6Chained {
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

impl Drop for OreAes128Bit6Chained {
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

/// Check raw symbols for the tests' `encrypt_var` and `encrypt_left_var`,
/// refusing more blocks than the wire format can number *before* scanning
/// them.
#[cfg(test)]
fn check_symbols(x: &[u8]) -> Result<Blocks6<&[u8]>, OreError> {
    if x.len() > u16::MAX as usize {
        return Err(OreError::TooManyBlocks);
    }
    Blocks6::check(x)
}

/// Decompose `s`, padded with NUL bytes under `padding`, into 6-bit blocks,
/// refusing a string too long for the policy or the wire format *before*
/// allocating or decomposing it. The decomposition is the whole plaintext
/// (it inverts), so the buffer is wiped when dropped. For the tests.
#[cfg(test)]
fn str_to_blocks(s: &str, options: &Options) -> Result<Blocks6<Zeroizing<Vec<u8>>>, OreError> {
    padded_bytes_to_blocks(s.as_bytes(), options)
}

/// Decompose `bytes`, padded with NUL bytes under `options`, into 6-bit
/// blocks; see [`str_to_blocks`].
fn padded_bytes_to_blocks(
    bytes: &[u8],
    options: &Options,
) -> Result<Blocks6<Zeroizing<Vec<u8>>>, OreError> {
    if bytes.len() > MAX_STR_BYTES {
        return Err(OreError::TooManyBlocks);
    }
    let padding = options.padding();
    let padded = padding.padded_len(bytes.len())?;
    if bytes.len() > options.max_bytes() {
        return Err(OreError::TooLong);
    }
    if padding != Padding::None {
        refuse_trailing_nul(bytes)?;
    }
    Ok(Blocks6::decompose_padded(
        bytes,
        Zeroizing::new(vec![0u8; num_blocks_6bit(padded)]),
    ))
}

/// Decompose `bytes` into 6-bit blocks, unpadded, refusing input too long
/// for the wire format *before* allocating or decomposing it. The fixed-
/// width and bytes path: the decomposition is the whole plaintext (it inverts), so
/// the buffer is wiped when dropped.
fn bytes_to_blocks(bytes: &[u8]) -> Result<Blocks6<Zeroizing<Vec<u8>>>, OreError> {
    if bytes.len() > MAX_STR_BYTES {
        return Err(OreError::TooManyBlocks);
    }
    Ok(Blocks6::decompose(
        bytes,
        Zeroizing::new(vec![0u8; num_blocks_6bit(bytes.len())]),
    ))
}

/// Refuse a string that ends in NUL: padded, it would encrypt to the same
/// blocks as the string without it. One branch on the last byte, which
/// reveals only whether the encryption is refused.
///
/// The branch must be taken here, not left to the caller. Compiled to a
/// select, the check would hand back a `Result` that depends on the secret
/// byte, and every caller's `?` would branch on it. `black_box` on the error
/// cannot be hoisted above the condition, so the compiler has to branch,
/// and each path returns a constant. Kept out of line so that the one
/// branch, which the taint harness accepts, has a frame of its own
/// (`packages/ct-taint/valgrind.supp`).
#[inline(never)]
fn refuse_trailing_nul(bytes: &[u8]) -> Result<(), OreError> {
    if bytes.last() == Some(&0) {
        return Err(core::hint::black_box(OreError::TrailingNul));
    }
    Ok(())
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// For every floor and every length the wire format can hold, the
    /// power-of-two rule never shrinks a string, stays within the wire
    /// limit, and maps a padded length to itself. Order and equality under
    /// padding need exactly the first of these (the module docs).
    #[kani::proof]
    fn power_of_two_never_shrinks_and_is_idempotent() {
        let min_bytes: u16 = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX_STR_BYTES);
        let padding = Padding::PowerOfTwo { min_bytes };
        if let Ok(padded) = padding.padded_len(len) {
            assert!(padded >= len);
            assert!(padded <= MAX_STR_BYTES);
            assert!(padded.is_power_of_two() || padded == usize::from(min_bytes));
            assert!(matches!(padding.padded_len(padded), Ok(again) if again == padded));
        }
    }

    /// The power-of-two rule is monotone: a longer string never pads to a
    /// shorter length, so bucket sizes order like lengths.
    #[kani::proof]
    fn power_of_two_is_monotone() {
        let min_bytes: u16 = kani::any();
        let a: usize = kani::any();
        let b: usize = kani::any();
        kani::assume(a <= b && b <= MAX_STR_BYTES);
        let padding = Padding::PowerOfTwo { min_bytes };
        if let (Ok(pa), Ok(pb)) = (padding.padded_len(a), padding.padded_len(b)) {
            assert!(pa <= pb);
        }
    }

    /// A fixed length accepts exactly the strings that fit, and pads them
    /// all to that length.
    #[kani::proof]
    fn fixed_pads_everything_that_fits() {
        let max_bytes: u16 = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX_STR_BYTES);
        let padding = Padding::Fixed { max_bytes };
        match padding.padded_len(len) {
            Ok(padded) => {
                assert!(len <= usize::from(max_bytes) && padded == usize::from(max_bytes))
            }
            Err(OreError::ExceedsPadding) => assert!(len > usize::from(max_bytes)),
            Err(OreError::TooManyBlocks) => assert!(usize::from(max_bytes) > MAX_STR_BYTES),
            Err(_) => assert!(false),
        }
    }
}

#[cfg(test)]
mod compat_vectors;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{bytes_pt, fixed_key, i128_pt, salt, text_pt, u128_pt};

    fn ore() -> OreAes128Bit6Chained {
        OreAes128Bit6Chained::init(fixed_key(0x11)).unwrap()
    }

    fn ore_with(padding: Padding) -> OreAes128Bit6Chained {
        OreAes128Bit6Chained::init_with(fixed_key(0x11), Options::default().with_padding(padding))
            .unwrap()
    }

    /// `ore_with`, with its own ceiling.
    fn ore_with_max(padding: Padding, max_bytes: usize) -> OreAes128Bit6Chained {
        let options = Options::default()
            .with_padding(padding)
            .with_max_bytes(max_bytes);
        OreAes128Bit6Chained::init_with(fixed_key(0x11), options).unwrap()
    }

    /// The ceiling: the default is 1024 bytes, a cipher can set its own, a
    /// fixed padding length is also a ceiling, and a ceiling of 0 or one
    /// the policy cannot pad is refused at init.
    #[test]
    fn strings_over_the_ceiling_are_refused() {
        type C = OreAes128Bit6Chained;
        let c = ore();
        assert_eq!(c.options().max_bytes(), DEFAULT_MAX_STR_BYTES);
        assert!(c.encrypt_str(&"a".repeat(1024)).is_ok());
        assert!(matches!(
            c.encrypt_str(&"a".repeat(1025)),
            Err(OreError::TooLong)
        ));
        assert!(matches!(
            c.encrypt_left_str(&"a".repeat(1025)),
            Err(OreError::TooLong)
        ));

        let small = C::init_with(fixed_key(0x11), Options::default().with_max_bytes(100)).unwrap();
        assert!(small.encrypt_str(&"a".repeat(100)).is_ok());
        assert!(matches!(
            small.encrypt_str(&"a".repeat(101)),
            Err(OreError::TooLong)
        ));
        // A refused string costs nothing: the ceiling is checked before
        // any block is derived, and under `None` too.
        let unpadded = C::init_with(
            fixed_key(0x11),
            Options::default()
                .with_padding(Padding::None)
                .with_max_bytes(8),
        )
        .unwrap();
        assert!(unpadded.encrypt_str("12345678").is_ok());
        assert!(matches!(
            unpadded.encrypt_str("123456789"),
            Err(OreError::TooLong)
        ));

        // Under a fixed length the lower of the two applies, and a string
        // past the fixed length is still `ExceedsPadding`.
        let fixed = ore_with(Padding::Fixed { max_bytes: 200 });
        assert_eq!(fixed.options().max_bytes(), 200);
        assert!(fixed.encrypt_str(&"a".repeat(200)).is_ok());
        assert!(matches!(
            fixed.encrypt_str(&"a".repeat(201)),
            Err(OreError::ExceedsPadding)
        ));
        let fixed_low = C::init_with(
            fixed_key(0x11),
            Options::default()
                .with_padding(Padding::Fixed { max_bytes: 200 })
                .with_max_bytes(50),
        )
        .unwrap();
        assert_eq!(fixed_low.options().max_bytes(), 50);
        assert!(matches!(
            fixed_low.encrypt_str(&"a".repeat(51)),
            Err(OreError::TooLong)
        ));
        // The fixed length still sets the ciphertext size.
        assert_eq!(
            fixed_low.encrypt_str("abc").unwrap().to_bytes().len(),
            total_len(num_blocks_6bit(200))
        );

        // Refused at init: nothing could be encrypted, or the longest
        // string would pad past the wire limit.
        assert!(matches!(
            C::init_with(fixed_key(0x11), Options::default().with_max_bytes(0)),
            Err(OreError::InitFailed)
        ));
        assert!(matches!(
            C::init_with(fixed_key(0x11), Options::default().with_max_bytes(32769)),
            Err(OreError::InitFailed)
        ));
        assert!(C::init_with(fixed_key(0x11), Options::default().with_max_bytes(32768)).is_ok());
        assert!(C::init_with(
            fixed_key(0x11),
            Options::default()
                .with_padding(Padding::None)
                .with_max_bytes(MAX_STR_BYTES)
        )
        .is_ok());
        assert!(matches!(
            C::init_with(
                fixed_key(0x11),
                Options::default()
                    .with_padding(Padding::None)
                    .with_max_bytes(MAX_STR_BYTES + 1)
            ),
            Err(OreError::InitFailed)
        ));
    }

    /// One of each kind of policy, with a floor and a fixed length that the
    /// tests' strings cross.
    const POLICIES: [Padding; 4] = [
        Padding::None,
        Padding::PowerOfTwo { min_bytes: 16 },
        Padding::PowerOfTwo { min_bytes: 0 },
        Padding::Fixed { max_bytes: 48 },
    ];

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

        let unpadded = ore_with(Padding::None);
        let blocks =
            str_to_blocks("alice", &Options::default().with_padding(Padding::None)).unwrap();
        assert_eq!(
            unpadded
                .encrypt_left_var(blocks.as_bytes())
                .unwrap()
                .to_bytes(),
            unpadded.encrypt_left_str("alice").unwrap().to_bytes()
        );
    }

    /// `init` is the empty salt; another salt gives unrelated ciphertexts,
    /// and the same salt reproduces them. The two salts have equal
    /// lengths, so the length prefix alone cannot separate them.
    #[test]
    fn salt_separates_keys() {
        type C = OreAes128Bit6Chained;
        let plain = C::init(fixed_key(0x42)).unwrap();
        let empty = C::init_with_salt(fixed_key(0x42), &Context::empty()).unwrap();
        let col_a = C::init_with_salt(fixed_key(0x42), &salt(b"users.email")).unwrap();
        let col_a2 = C::init_with_salt(fixed_key(0x42), &salt(b"users.email")).unwrap();
        let col_b = C::init_with_salt(fixed_key(0x42), &salt(b"users.phone")).unwrap();
        let col_a_opts = C::init_with(
            fixed_key(0x42),
            Options::default().with_salt(&salt(b"users.email")),
        )
        .unwrap();
        assert_eq!(col_a.options().salt(), b"users.email");

        let left = |c: &C| c.encrypt_left_str("alice").unwrap().to_bytes();
        assert_eq!(left(&plain), left(&empty));
        assert_eq!(left(&col_a), left(&col_a2));
        assert_eq!(left(&col_a), left(&col_a_opts));
        assert_ne!(left(&plain), left(&col_a));
        assert_ne!(left(&col_a), left(&col_b));

        let a = col_a.encrypt_str("alice").unwrap().to_bytes();
        let b = col_b.encrypt_str("alice").unwrap().to_bytes();
        assert_ne!(C::compare_raw_slices(&a, &b), Some(Ordering::Equal));
        assert_eq!(
            C::compare_raw_slices(&a, &col_a2.encrypt_str("alice").unwrap().to_bytes()),
            Some(Ordering::Equal)
        );
        // Fixed-width plaintexts too.
        assert_ne!(
            col_a.encrypt_query_plaintext(&u128_pt(7)).unwrap(),
            col_b.encrypt_query_plaintext(&u128_pt(7)).unwrap()
        );
    }

    /// A cross-salt comparison can answer `Equal`: the unpadded empty
    /// string has no blocks, so there is no key material to differ.
    /// The docs therefore promise nothing about cross-salt results.
    #[test]
    fn cross_salt_empty_strings_compare_equal() {
        type C = OreAes128Bit6Chained;
        let options = Options::default().with_padding(Padding::None);
        let a = C::init_with(
            fixed_key(0x42),
            options.clone().with_salt(&salt(b"users.email")),
        )
        .unwrap();
        let b = C::init_with(fixed_key(0x42), options.with_salt(&salt(b"users.phone"))).unwrap();
        let a = a.encrypt_str("").unwrap().to_bytes();
        let b = b.encrypt_str("").unwrap().to_bytes();
        assert_eq!(C::compare_raw_slices(&a, &b), Some(Ordering::Equal));
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

    /// Raw symbols over the wire limit are refused on their length, before
    /// any symbol is checked: out-of-domain symbols give `TooManyBlocks`,
    /// not `PrpError`.
    #[test]
    fn raw_symbols_over_the_wire_limit_are_rejected() {
        let c = ore();
        let too_many = vec![64u8; u16::MAX as usize + 1];
        assert!(matches!(
            c.encrypt_var(&too_many),
            Err(OreError::TooManyBlocks)
        ));
        assert!(matches!(
            c.encrypt_left_var(&too_many),
            Err(OreError::TooManyBlocks)
        ));
    }

    #[test]
    fn comparators_reject_out_of_domain_symbols() {
        let c = ore();
        let a = c.encrypt_str("apple").unwrap().to_bytes();
        let b = c.encrypt_str("apricot").unwrap().to_bytes();
        let q = c.encrypt_left_str("apple").unwrap().to_bytes();
        assert!(OreAes128Bit6Chained::compare_raw_slices(&a, &b).is_some());

        // First `xt` byte follows the header.
        let mut bad = a.clone();
        bad[HEADER_LEN] = DOMAIN as u8;
        let mut bad_q = q.clone();
        bad_q[HEADER_LEN] = DOMAIN as u8;

        type C = OreAes128Bit6Chained;
        assert_eq!(C::compare_raw_slices(&bad, &b), None);
        assert_eq!(C::compare_raw_slices(&b, &bad), None);
        assert_eq!(C::compare_left_to_full(&bad_q, &b), None);
        assert_eq!(C::compare_left_to_full(&q, &bad), None);
    }

    fn cmp(c: &OreAes128Bit6Chained, a: &str, b: &str) -> Ordering {
        let ca = c.encrypt_str(a).unwrap().to_bytes();
        let cb = c.encrypt_str(b).unwrap().to_bytes();
        OreAes128Bit6Chained::compare_raw_slices(&ca, &cb).unwrap()
    }

    #[test]
    fn string_total_order_matches_lexicographic() {
        // Includes shared prefixes of different lengths, beyond 14 blocks,
        // across power-of-two buckets (16 and 17 bytes, 32 and 33), within
        // one (43 and 44), and interior NULs, which padding allows.
        let words = [
            "",
            "a",
            "a\0b",
            "ab",
            "abc",
            "abd",
            "ac",
            "b",
            "banana",
            "bananas",
            "sixteen bytes ok",
            "sixteen bytes ok!",
            "thirty-two bytes, on the nose!!!",
            "thirty-two bytes, on the nose!!!!",
            "the quick brown fox jumps over the lazy dog",
            "the quick brown fox jumps over the lazy dog.",
            "zzz",
        ];
        for padding in POLICIES {
            let c = ore_with(padding);
            for &a in &words {
                for &b in &words {
                    assert_eq!(
                        cmp(&c, a, b),
                        a.cmp(b),
                        "order mismatch for {a:?} vs {b:?} under {padding:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn power_of_two_lengths() {
        let p = |min_bytes, len| Padding::PowerOfTwo { min_bytes }.padded_len(len).unwrap();
        // Everything up to the floor is one bucket; above it, each bucket
        // doubles.
        for len in 0..=16 {
            assert_eq!(p(16, len), 16);
        }
        assert_eq!(p(16, 17), 32);
        assert_eq!(p(16, 32), 32);
        assert_eq!(p(16, 33), 64);
        assert_eq!(p(16, 1000), 1024);
        assert_eq!(p(16, 1025), 2048);
        // Without a floor the empty string stays empty, and a floor need
        // not be a power of two: it is one bucket below the powers of two.
        assert_eq!(p(0, 0), 0);
        assert_eq!(p(0, 1), 1);
        assert_eq!(p(0, 3), 4);
        assert_eq!(p(24, 20), 24);
        assert_eq!(p(24, 24), 24);
        assert_eq!(p(24, 25), 32);
        // The last bucket within the wire limit is 32768 bytes; longer
        // strings would pad past it.
        assert_eq!(p(16, 32768), 32768);
        for len in [32769, MAX_STR_BYTES] {
            assert!(matches!(
                Padding::PowerOfTwo { min_bytes: 16 }.padded_len(len),
                Err(OreError::TooManyBlocks)
            ));
        }
    }

    #[test]
    fn padded_ciphertexts_reveal_only_the_bucket() {
        let c = ore();
        let size = |s: &str| c.encrypt_str(s).unwrap().to_bytes().len();
        let left_size = |s: &str| c.encrypt_left_str(s).unwrap().to_bytes().len();
        // Everything up to the 16-byte floor is one bucket of 22 blocks.
        for s in ["", "a", "abc", "sixteen bytes ok"] {
            assert_eq!(size(s), total_len(num_blocks_6bit(16)), "{s:?}");
            assert_eq!(left_size(s), left_len(num_blocks_6bit(16)), "{s:?}");
        }
        // 17 and 32 bytes share the next bucket; 33 starts another.
        assert_eq!(size("seventeen bytes!!"), total_len(num_blocks_6bit(32)));
        assert_eq!(
            size("thirty-two bytes, on the nose!!!"),
            total_len(num_blocks_6bit(32))
        );
        assert_eq!(
            size("thirty-two bytes, on the nose!!!!"),
            total_len(num_blocks_6bit(64))
        );

        let fixed = ore_with(Padding::Fixed { max_bytes: 48 });
        for s in ["", "abc", &"x".repeat(48)] {
            assert_eq!(
                fixed.encrypt_str(s).unwrap().to_bytes().len(),
                total_len(num_blocks_6bit(48))
            );
        }
    }

    #[test]
    fn padded_strings_must_not_end_in_nul() {
        for padding in POLICIES {
            let c = ore_with(padding);
            let full = c.encrypt_str("a\0");
            let left = c.encrypt_left_str("a\0");
            if padding == Padding::None {
                // Unpadded, the length tells "a\0" from "a".
                assert_eq!(cmp(&c, "a", "a\0"), Ordering::Less);
            } else {
                assert!(matches!(full, Err(OreError::TrailingNul)), "{:?}", padding);
                assert!(matches!(left, Err(OreError::TrailingNul)), "{:?}", padding);
            }
            // An interior NUL is fine either way.
            assert!(c.encrypt_str("a\0b").is_ok());
        }
    }

    #[test]
    fn fixed_padding_refuses_longer_strings() {
        let c = ore_with(Padding::Fixed { max_bytes: 8 });
        assert!(c.encrypt_str("12345678").is_ok());
        assert!(matches!(
            c.encrypt_str("123456789"),
            Err(OreError::ExceedsPadding)
        ));
        assert!(matches!(
            c.encrypt_left_str("123456789"),
            Err(OreError::ExceedsPadding)
        ));
    }

    #[test]
    fn padding_policies_past_the_wire_limit_are_refused() {
        type C = OreAes128Bit6Chained;
        let max = MAX_STR_BYTES as u16;
        let with = |padding| Options::default().with_padding(padding);
        assert!(C::init_with(fixed_key(0x11), with(Padding::Fixed { max_bytes: max })).is_ok());
        assert!(matches!(
            C::init_with(fixed_key(0x11), with(Padding::Fixed { max_bytes: max + 1 })),
            Err(OreError::InitFailed)
        ));
        // A floor at the limit is allowed, one past it is not.
        assert!(C::init_with(
            fixed_key(0x11),
            with(Padding::PowerOfTwo { min_bytes: max })
        )
        .is_ok());
        assert!(matches!(
            C::init_with(
                fixed_key(0x11),
                with(Padding::PowerOfTwo { min_bytes: max + 1 })
            ),
            Err(OreError::InitFailed)
        ));
        // Under the default policy, a string past the last power of two
        // within the limit would pad past it, and is refused before any
        // work is done (and before the ceiling is consulted).
        let c = ore_with_max(Padding::default(), 32768);
        for len in [32769, MAX_STR_BYTES] {
            assert!(matches!(
                c.encrypt_str(&"a".repeat(len)),
                Err(OreError::TooManyBlocks)
            ));
        }
    }

    /// Ciphertexts under different policies do not compare: an unpadded and
    /// a padded "abc" would compare unequal.
    #[test]
    fn comparators_refuse_mixed_policies() {
        type C = OreAes128Bit6Chained;
        for pa in POLICIES {
            for pb in POLICIES {
                let a = ore_with(pa);
                let b = ore_with(pb);
                let full_a = a.encrypt_str("abc").unwrap().to_bytes();
                let full_b = b.encrypt_str("abc").unwrap().to_bytes();
                let left_a = a.encrypt_left_str("abc").unwrap().to_bytes();
                let expected = (pa == pb).then_some(Ordering::Equal);
                assert_eq!(C::compare_raw_slices(&full_a, &full_b), expected);
                assert_eq!(C::compare_left_to_full(&left_a, &full_b), expected);
            }
        }
    }

    #[test]
    fn padding_tag_round_trips_and_rejects_unknown_kinds() {
        let c = ore();
        let bytes = c.encrypt_str("abc").unwrap().to_bytes();
        let ct = VarCipherText::from_slice(&bytes).unwrap();
        assert_eq!(ct.padding(), Padding::default());
        assert_eq!(
            c.encrypt_left_str("abc").unwrap().padding(),
            Padding::default()
        );

        type C = OreAes128Bit6Chained;
        let tag = WIRE_HEADER_LEN;
        let tampered = |at: usize, value: u8| {
            let mut t = bytes.clone();
            t[at] = value;
            t
        };
        for bad in [
            tampered(tag, 3),        // unknown kind
            tampered(tag, 0),        // Padding::None with a non-zero length
            tampered(tag + 1, 0xff), // a floor past the wire limit
        ] {
            assert!(VarCipherText::from_slice(&bad).is_err());
            assert_eq!(C::compare_raw_slices(&bad, &bad), None);
        }
    }

    /// Every string over {NUL, 'a', 'b'} of up to four bytes that a padding
    /// policy accepts (no trailing NUL), plus strings at the 16- and 32-byte
    /// bucket edges, each also with a two-byte character straddling the edge.
    fn small_alphabet_strings() -> Vec<String> {
        let mut out = vec![String::new()];
        let mut layer = vec![String::new()];
        for _ in 0..4 {
            layer = layer
                .iter()
                .flat_map(|s| ["\0", "a", "b"].iter().map(move |c| format!("{s}{c}")))
                .collect();
            out.extend(layer.iter().cloned());
        }
        out.retain(|s| !s.ends_with('\0'));
        for n in [15, 16, 17, 31, 32, 33] {
            out.push("a".repeat(n));
            // `n - 1` ASCII bytes and a two-byte character: `n + 1` bytes.
            out.push(format!("{}é", "a".repeat(n - 1)));
        }
        out
    }

    /// Both comparators reproduce byte order over every pair of the small
    /// alphabet's strings, under every policy: interior NULs, prefixes that
    /// end at every block position, and both sides of each bucket edge.
    #[test]
    fn small_alphabet_total_order_under_every_policy() {
        type C = OreAes128Bit6Chained;
        let strings = small_alphabet_strings();
        for padding in POLICIES {
            let c = ore_with(padding);
            let fulls: Vec<Vec<u8>> = strings
                .iter()
                .map(|s| c.encrypt_str(s).unwrap().to_bytes())
                .collect();
            let lefts: Vec<Vec<u8>> = strings
                .iter()
                .map(|s| c.encrypt_left_str(s).unwrap().to_bytes())
                .collect();
            for (i, a) in strings.iter().enumerate() {
                for (j, b) in strings.iter().enumerate() {
                    let expected = Some(a.as_bytes().cmp(b.as_bytes()));
                    assert_eq!(
                        C::compare_raw_slices(&fulls[i], &fulls[j]),
                        expected,
                        "full {a:?} vs {b:?} under {padding:?}"
                    );
                    assert_eq!(
                        C::compare_left_to_full(&lefts[i], &fulls[j]),
                        expected,
                        "left {a:?} vs {b:?} under {padding:?}"
                    );
                }
            }
        }
    }

    /// Under the default policy, every length from 0 to 70 bytes lands in
    /// its bucket, and each string sorts below the next longer one and
    /// below itself with one more byte, across every bucket edge.
    #[test]
    fn default_buckets_at_every_length() {
        type C = OreAes128Bit6Chained;
        let c = ore();
        let bucket = |n: usize| if n <= 16 { 16 } else { n.next_power_of_two() };
        let mut prev: Option<Vec<u8>> = None;
        for n in 0..=70 {
            let s = "a".repeat(n);
            let full = c.encrypt_str(&s).unwrap().to_bytes();
            let left = c.encrypt_left_str(&s).unwrap().to_bytes();
            assert_eq!(
                full.len(),
                total_len(num_blocks_6bit(bucket(n))),
                "{n} bytes"
            );
            assert_eq!(
                left.len(),
                left_len(num_blocks_6bit(bucket(n))),
                "{n} bytes"
            );
            let longer = c.encrypt_str(&format!("{s}b")).unwrap().to_bytes();
            assert_eq!(
                C::compare_raw_slices(&full, &longer),
                Some(Ordering::Less),
                "{n} bytes"
            );
            assert_eq!(
                C::compare_left_to_full(&left, &longer),
                Some(Ordering::Less),
                "{n} bytes"
            );
            if let Some(prev) = &prev {
                assert_eq!(
                    C::compare_raw_slices(prev, &full),
                    Some(Ordering::Less),
                    "{n} bytes"
                );
            }
            prev = Some(full);
        }
    }

    /// Two policies that pad a string to the same length produce the same
    /// blocks, since padding is only NUL extension, and the tag alone keeps
    /// their ciphertexts from comparing.
    #[test]
    fn same_blocks_under_different_policies_do_not_compare() {
        type C = OreAes128Bit6Chained;
        let cases = [
            (
                Padding::PowerOfTwo { min_bytes: 16 },
                Padding::Fixed { max_bytes: 16 },
                "sixteen bytes ok",
            ),
            (
                Padding::PowerOfTwo { min_bytes: 16 },
                Padding::PowerOfTwo { min_bytes: 8 },
                "seventeen bytes!!",
            ),
            (
                Padding::Fixed { max_bytes: 4 },
                Padding::PowerOfTwo { min_bytes: 0 },
                "abc",
            ),
        ];
        for (pa, pb, s) in cases {
            let (a, b) = (ore_with(pa), ore_with(pb));
            let left_a = a.encrypt_left_str(s).unwrap().to_bytes();
            let left_b = b.encrypt_left_str(s).unwrap().to_bytes();
            assert_eq!(
                left_a[..WIRE_HEADER_LEN],
                left_b[..WIRE_HEADER_LEN],
                "{s:?}"
            );
            assert_ne!(left_a[..HEADER_LEN], left_b[..HEADER_LEN], "{s:?}");
            assert_eq!(left_a[HEADER_LEN..], left_b[HEADER_LEN..], "{s:?}");
            let full_b = b.encrypt_str(s).unwrap().to_bytes();
            assert_eq!(C::compare_left_to_full(&left_a, &full_b), None, "{s:?}");
            let full_a = a.encrypt_str(s).unwrap().to_bytes();
            assert_eq!(C::compare_raw_slices(&full_a, &full_b), None, "{s:?}");
        }
    }

    /// The longest fixed length the wire format allows, 65535 blocks,
    /// encrypts, round trips and compares. About ten seconds unoptimised,
    /// so it runs only on request:
    /// `cargo test -p ore-rs fixed_padding_at_the_wire_limit -- --ignored`.
    #[test]
    #[ignore = "65535-block ciphertexts: about ten seconds unoptimised"]
    fn fixed_padding_at_the_wire_limit() {
        type C = OreAes128Bit6Chained;
        let c = ore_with_max(
            Padding::Fixed {
                max_bytes: MAX_STR_BYTES as u16,
            },
            MAX_STR_BYTES,
        );
        let full = c.encrypt_str("alice").unwrap().to_bytes();
        assert_eq!(full.len(), total_len(u16::MAX as usize));
        assert_eq!(VarCipherText::from_slice(&full).unwrap().to_bytes(), full);
        let left = c.encrypt_left_str("alicf").unwrap().to_bytes();
        assert_eq!(left.len(), left_len(u16::MAX as usize));
        assert_eq!(
            C::compare_left_to_full(&left, &full),
            Some(Ordering::Greater)
        );
    }

    /// A header's block count must be one its policy can produce.
    #[test]
    fn policies_admit_only_their_own_block_counts() {
        let blocks = num_blocks_6bit;
        let pow16 = Padding::PowerOfTwo { min_bytes: 16 };
        for count in [blocks(16), blocks(32), blocks(64), blocks(32768)] {
            assert!(pow16.admits_count(count), "{}", count);
        }
        for count in [0, blocks(8), blocks(16) + 1, blocks(48), blocks(65536)] {
            assert!(!pow16.admits_count(count), "{}", count);
        }
        // A floor that is not a power of two is a bucket of its own.
        let pow24 = Padding::PowerOfTwo { min_bytes: 24 };
        assert!(pow24.admits_count(blocks(24)));
        assert!(pow24.admits_count(blocks(32)));
        assert!(!pow24.admits_count(blocks(16)));
        // Without a floor: 0, 1, 2, 4, 8, ... bytes.
        let pow0 = Padding::PowerOfTwo { min_bytes: 0 };
        for len in [0, 1, 2, 4, 8, 1024] {
            assert!(pow0.admits_count(blocks(len)), "{}", len);
        }
        assert!(!pow0.admits_count(blocks(3)));
        let fixed = Padding::Fixed { max_bytes: 48 };
        assert!(fixed.admits_count(blocks(48)));
        assert!(!fixed.admits_count(blocks(48) - 1));
        for count in [0, 1, 1000, u16::MAX as usize] {
            assert!(Padding::None.admits_count(count));
        }
    }

    /// A ciphertext whose tag names a policy that cannot produce its block
    /// count was made by no cipher, and is refused: rewriting an unpadded
    /// ciphertext's tag does not smuggle it in among padded ciphertexts.
    #[test]
    fn parsers_reject_counts_the_policy_cannot_produce() {
        type C = OreAes128Bit6Chained;
        let retag = |bytes: &[u8], padding: Padding| {
            let mut t = bytes.to_vec();
            t[WIRE_HEADER_LEN..HEADER_LEN].copy_from_slice(&padding.to_wire());
            t
        };
        // 4 blocks, claimed to be padded to 16 bytes (22 blocks).
        let unpadded = ore_with(Padding::None)
            .encrypt_str("abc")
            .unwrap()
            .to_bytes();
        let forged = retag(&unpadded, Padding::default());
        assert!(VarCipherText::from_slice(&forged).is_err());
        let genuine = ore().encrypt_str("abc").unwrap().to_bytes();
        assert_eq!(C::compare_raw_slices(&forged, &genuine), None);
        assert_eq!(C::compare_raw_slices(&forged, &forged), None);
        let left = retag(
            &ore_with(Padding::None)
                .encrypt_left_str("abc")
                .unwrap()
                .to_bytes(),
            Padding::default(),
        );
        assert_eq!(C::compare_left_to_full(&left, &genuine), None);

        // 22 blocks claimed as a fixed 48 bytes (64 blocks): refused. As a
        // fixed 16 bytes (22 blocks): a count that policy produces, accepted.
        assert!(
            VarCipherText::from_slice(&retag(&genuine, Padding::Fixed { max_bytes: 48 })).is_err()
        );
        assert!(
            VarCipherText::from_slice(&retag(&genuine, Padding::Fixed { max_bytes: 16 })).is_ok()
        );
    }

    #[test]
    fn equality_same_plaintext_across_nonces() {
        let c = ore();
        let a = c.encrypt_str("hello world").unwrap().to_bytes();
        let b = c.encrypt_str("hello world").unwrap().to_bytes();
        assert_ne!(a, b, "nonces should differ"); // different nonce streams
        assert_eq!(
            OreAes128Bit6Chained::compare_raw_slices(&a, &b),
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

    /// A fixed-width plaintext is an unpadded ciphertext of its width's
    /// block count on the wire: a `u128` is 22 blocks, as an unpadded
    /// 16-byte string is, and the comparators order the two. The count
    /// is a length, not a type; vitaminc's salt keeps targets apart.
    #[test]
    fn fixed_width_plaintexts_are_unpadded_terms() {
        let c = ore();
        let n = c.encrypt_plaintext(&u128_pt(7)).unwrap();
        let n_left = c.encrypt_query_plaintext(&u128_pt(7)).unwrap();
        assert_eq!(n.as_bytes().len(), total_len(22));
        assert_eq!(n_left.as_bytes().len(), left_len(22));
        assert_eq!(
            parse_chained_header(n.as_bytes()),
            Some((22, Padding::None))
        );
        // The same bytes as the unpadded bytes path over the encoding.
        assert_eq!(
            n_left.as_bytes(),
            c.encrypt_left_unpadded_bytes(&7u128.to_be_bytes())
                .unwrap()
                .to_bytes()
        );
        assert_eq!(
            OreAes128Bit6Chained::compare_left_to_full(n_left.as_bytes(), n.as_bytes()),
            Some(Ordering::Equal)
        );
        // Padded text of 22 blocks carries another policy tag, which the
        // comparators refuse; an unpadded 16-byte string compares.
        let s16_padded = c.encrypt_str("0123456789abcdef").unwrap().to_bytes();
        let s16 = ore_with(Padding::None)
            .encrypt_str("0123456789abcdef")
            .unwrap()
            .to_bytes();
        assert_eq!(
            parse_chained_header(&s16_padded).map(|(count, _)| count),
            Some(22)
        );
        assert_eq!(
            OreAes128Bit6Chained::compare_raw_slices(n.as_bytes(), &s16_padded),
            None
        );
        assert!(OreAes128Bit6Chained::compare_raw_slices(n.as_bytes(), &s16).is_some());
    }

    /// Text goes in padded under the cipher's options; bytes and
    /// fixed-width plaintexts do not, whatever the options say.
    #[test]
    fn only_text_is_padded() {
        let c = ore();
        let text = c.encrypt_plaintext(&text_pt("alice")).unwrap();
        assert_eq!(
            parse_chained_header(text.as_bytes()),
            Some((num_blocks_6bit(16), Padding::default()))
        );
        let bytes = c.encrypt_plaintext(&bytes_pt(b"alice")).unwrap();
        assert_eq!(
            parse_chained_header(bytes.as_bytes()),
            Some((num_blocks_6bit(6), Padding::None))
        );
        let n = c.encrypt_plaintext(&i128_pt(-1)).unwrap();
        assert_eq!(
            parse_chained_header(n.as_bytes()),
            Some((22, Padding::None))
        );
        // Bytes ending in NUL are taken: nothing pads them.
        assert!(c.encrypt_plaintext(&bytes_pt(b"\0")).is_ok());
        // Text is checked against the ceiling, counting vitaminc's marker.
        let small = ore_with_max(Padding::None, 8);
        assert!(small.encrypt_plaintext(&text_pt("1234567")).is_ok());
        assert!(matches!(
            small.encrypt_plaintext(&text_pt("12345678")),
            Err(OreError::TooLong)
        ));
        // Bytes are checked against it too, marker included; a fixed-width
        // plaintext is not.
        assert!(small.encrypt_plaintext(&bytes_pt(&[0u8; 7])).is_ok());
        assert!(matches!(
            small.encrypt_plaintext(&bytes_pt(&[0u8; 8])),
            Err(OreError::TooLong)
        ));
        assert!(matches!(
            small.encrypt_query_plaintext(&bytes_pt(&[0u8; 8])),
            Err(OreError::TooLong)
        ));
        assert!(small.encrypt_plaintext(&u128_pt(u128::MAX)).is_ok());
    }

    /// Unpadded bytes past the wire limit are refused by their length,
    /// before any block is made, and the longest that fit are taken.
    #[test]
    fn unpadded_bytes_past_the_wire_limit_are_refused_by_length() {
        let c = ore();
        let too_wide = vec![0u8; MAX_STR_BYTES + 1];
        assert!(matches!(
            c.encrypt_unpadded_bytes(&too_wide),
            Err(OreError::TooManyBlocks)
        ));
        assert!(matches!(
            c.encrypt_left_unpadded_bytes(&too_wide),
            Err(OreError::TooManyBlocks)
        ));
        assert!(c
            .encrypt_left_unpadded_bytes(&too_wide[..MAX_STR_BYTES])
            .is_ok());
    }

    #[test]
    fn signed_128_orders_across_zero() {
        let c = ore();
        let vals = [i128::MIN, -1, 0, 1, i128::MAX];
        let cts: Vec<Vec<u8>> = vals
            .iter()
            .map(|&v| c.encrypt_plaintext(&i128_pt(v)).unwrap().into_bytes())
            .collect();
        for (i, a) in cts.iter().enumerate() {
            for (j, b) in cts.iter().enumerate() {
                assert_eq!(
                    OreAes128Bit6Chained::compare_raw_slices(a, b),
                    Some(vals[i].cmp(&vals[j])),
                    "{} vs {}",
                    vals[i],
                    vals[j]
                );
            }
        }
    }

    #[test]
    fn cross_scheme_bytes_rejected() {
        let c = ore();
        let mut bytes = c.encrypt_str("x").unwrap().to_bytes();
        bytes[1] = 0x02; // pretend it's the fixed-N scheme id
        assert_eq!(
            OreAes128Bit6Chained::compare_raw_slices(&bytes, &bytes),
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
            OreAes128Bit6Chained::compare_left_to_full(&left, &full),
            Some(Ordering::Equal)
        );
        // A left-only artifact is not a full ciphertext, and vice versa, so the
        // length checks reject the swapped/mismatched cases.
        assert_eq!(OreAes128Bit6Chained::compare_raw_slices(&left, &full), None);
        assert_eq!(
            OreAes128Bit6Chained::compare_left_to_full(&full, &full),
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

    fn enc(c: &OreAes128Bit6Chained, x: &[u8]) -> Vec<u8> {
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
            OreAes128Bit6Chained::compare_raw_slices(&ea, &eb) == Some(a.cmp(&b))
        }

        /// Lewi-Wu query path: a left-only (query) ciphertext compared against a
        /// stored full ciphertext reproduces the plaintext order —
        /// `compare_left_to_full(left(a), full(b)) == a.cmp(b)`.
        fn prop_left_query_matches_full(a: Vec<u8>, b: Vec<u8>) -> bool {
            let c = ore();
            let (a, b) = (to_domain(&a), to_domain(&b));
            let left_a = c.encrypt_left_var(&a).unwrap().to_bytes();
            let full_b = enc(&c, &b);
            OreAes128Bit6Chained::compare_left_to_full(&left_a, &full_b)
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
            OreAes128Bit6Chained::compare_raw_slices(&ea, &eb) == Some(a.cmp(&b))
        }

        /// String comparison matches `str::cmp` across arbitrary Unicode and
        /// independent lengths, under every padding policy: the MSB-first
        /// 6-bit packing is order-preserving with tail zero-padding, whether
        /// the decomposition's own or a padding policy's (cross-length and
        /// cross-bucket prefix cases included). A padding policy refuses a
        /// trailing NUL, so those are trimmed.
        fn prop_string_order_matches_str(a: String, b: String) -> bool {
            let a: String = a.chars().take(12).collect();
            let b: String = b.chars().take(12).collect();
            let (a, b) = (a.trim_end_matches('\0'), b.trim_end_matches('\0'));
            POLICIES.iter().all(|&padding| {
                let c = ore_with(padding);
                let ea = c.encrypt_str(a).unwrap().to_bytes();
                let eb = c.encrypt_str(b).unwrap().to_bytes();
                OreAes128Bit6Chained::compare_raw_slices(&ea, &eb) == Some(a.cmp(b))
            })
        }

        /// A string sharing a prefix with another: the case where padding
        /// meets real blocks. Covers both strings in one bucket and in
        /// different ones.
        fn prop_padded_prefix_order(prefix: String, tail: String) -> bool {
            let a: String = prefix.chars().take(20).collect();
            let a = a.trim_end_matches('\0');
            let b: String = a.chars().chain(tail.chars().take(8)).collect();
            let b = b.trim_end_matches('\0');
            POLICIES[1..3].iter().all(|&padding| {
                let c = ore_with(padding);
                let ea = c.encrypt_str(a).unwrap().to_bytes();
                let eb = c.encrypt_str(b).unwrap().to_bytes();
                OreAes128Bit6Chained::compare_raw_slices(&ea, &eb) == Some(a.cmp(b))
            })
        }

        /// A power-of-two bucket never shrinks a length, less than doubles
        /// it, is monotone, and maps a bucket length to itself.
        fn prop_power_of_two_buckets(a: u16, b: u16) -> bool {
            // Halved, so that every length is within the wire limit.
            let (a, b) = (usize::from(a) / 2, usize::from(b) / 2);
            let p = |n| Padding::PowerOfTwo { min_bytes: 0 }.padded_len(n).unwrap();
            let pa = p(a);
            pa >= a && pa < 2 * a.max(1) && (a > b || pa <= p(b)) && p(pa) == pa
        }

        /// A padded string encrypts to the blocks of the string extended with
        /// NULs to its bucket under no padding: only the header tag differs.
        /// Padding is NUL extension and nothing more. A string too long for a
        /// fixed length is refused.
        fn prop_padding_is_nul_extension(s: String) -> bool {
            let s: String = s.chars().take(40).collect();
            let s = s.trim_end_matches('\0');
            let unpadded = ore_with(Padding::None);
            POLICIES.iter().all(|&padding| {
                let c = ore_with(padding);
                let Ok(padded) = padding.padded_len(s.len()) else {
                    return matches!(padding, Padding::Fixed { .. })
                        && matches!(c.encrypt_left_str(s), Err(OreError::ExceedsPadding))
                        && matches!(c.encrypt_str(s), Err(OreError::ExceedsPadding));
                };
                let mut extended = s.to_owned();
                extended.extend(std::iter::repeat_n('\0', padded - s.len()));
                let left = c.encrypt_left_str(s).unwrap();
                let a = left.to_bytes();
                let b = unpadded.encrypt_left_str(&extended).unwrap().to_bytes();
                left.padding() == padding
                    && a[..WIRE_HEADER_LEN] == b[..WIRE_HEADER_LEN]
                    && a[HEADER_LEN..] == b[HEADER_LEN..]
            })
        }

        /// Under every policy, two encryptions of a string compare Equal to
        /// each other and to its left ciphertext, and the full ciphertext
        /// round trips with its policy.
        fn prop_string_equality_under_every_policy(s: String) -> bool {
            type C = OreAes128Bit6Chained;
            let s: String = s.chars().take(12).collect();
            let s = s.trim_end_matches('\0');
            POLICIES.iter().all(|&padding| {
                let c = ore_with(padding);
                let a = c.encrypt_str(s).unwrap().to_bytes();
                let b = c.encrypt_str(s).unwrap().to_bytes();
                let l = c.encrypt_left_str(s).unwrap().to_bytes();
                C::compare_raw_slices(&a, &b) == Some(Ordering::Equal)
                    && C::compare_left_to_full(&l, &b) == Some(Ordering::Equal)
                    && VarCipherText::from_slice(&a)
                        .map(|ct| ct.to_bytes() == a && ct.padding() == padding)
                        .unwrap_or(false)
            })
        }

        /// A padding policy refuses exactly the strings that end in NUL; no
        /// padding accepts them all.
        fn prop_padding_refuses_exactly_trailing_nul(s: String, nul: bool) -> bool {
            let mut s: String = s.chars().take(11).collect();
            if nul {
                s.push('\0');
            }
            let ends_in_nul = s.ends_with('\0');
            POLICIES.iter().all(|&padding| {
                let c = ore_with(padding);
                let (full, left) = (c.encrypt_str(&s), c.encrypt_left_str(&s));
                if padding != Padding::None && ends_in_nul {
                    matches!(full, Err(OreError::TrailingNul))
                        && matches!(left, Err(OreError::TrailingNul))
                } else {
                    full.is_ok() && left.is_ok()
                }
            })
        }

        /// Arbitrary bytes, and a valid ciphertext with one byte changed, are
        /// parsed and compared without panicking.
        fn prop_parsers_never_panic(bytes: Vec<u8>, at: usize, value: u8) -> bool {
            type C = OreAes128Bit6Chained;
            let good = ore().encrypt_str("alice").unwrap().to_bytes();
            let mut changed = good.clone();
            changed[at % good.len()] = value;
            for x in [&bytes, &changed] {
                let _ = VarCipherText::from_slice(x);
                let _ = C::compare_raw_slices(x, x);
                let _ = C::compare_raw_slices(x, &good);
                let _ = C::compare_left_to_full(x, &good);
                let _ = C::compare_left_to_full(&good, x);
            }
            true
        }

        /// `u128` plaintexts order as the integers, on both the full and
        /// the query path.
        fn prop_u128_order(a: u128, b: u128) -> bool {
            let c = ore();
            let ca = c.encrypt_plaintext(&u128_pt(a)).unwrap();
            let cb = c.encrypt_plaintext(&u128_pt(b)).unwrap();
            let la = c.encrypt_query_plaintext(&u128_pt(a)).unwrap();
            OreAes128Bit6Chained::compare_raw_slices(ca.as_bytes(), cb.as_bytes()) == Some(a.cmp(&b))
                && OreAes128Bit6Chained::compare_left_to_full(la.as_bytes(), cb.as_bytes()) == Some(a.cmp(&b))
        }

        fn prop_i128_order(a: i128, b: i128) -> bool {
            let c = ore();
            let ca = c.encrypt_plaintext(&i128_pt(a)).unwrap();
            let cb = c.encrypt_plaintext(&i128_pt(b)).unwrap();
            let la = c.encrypt_query_plaintext(&i128_pt(a)).unwrap();
            OreAes128Bit6Chained::compare_raw_slices(ca.as_bytes(), cb.as_bytes()) == Some(a.cmp(&b))
                && OreAes128Bit6Chained::compare_left_to_full(la.as_bytes(), cb.as_bytes()) == Some(a.cmp(&b))
        }

        /// Two encryptions of one plaintext (fresh nonces each) compare Equal,
        /// and never produce identical bytes (the nonce streams differ).
        fn prop_equality_across_nonces(x: Vec<u8>) -> bool {
            let c = ore();
            let x = to_domain(&x);
            let (a, b) = (enc(&c, &x), enc(&c, &x));
            let equal = OreAes128Bit6Chained::compare_raw_slices(&a, &b)
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

    /// Every block's PRP tables for `s`, which must not survive an
    /// encryption in dead stack (review of #82 and #83).
    fn block_tables(ore: &OreAes128Bit6Chained, s: &str) -> Vec<Vec<u8>> {
        let blocks = str_to_blocks(s, &ore.options).unwrap();
        let mut acc = CmacAccumulator::new(&ore.k_acc);
        let mut needles = Vec::new();
        for (n, &sym) in blocks.as_bytes().iter().enumerate() {
            let prp = ore.prp_at(&acc, n as u16);
            let symbols = (0..64).map(crate::primitives::Symbol::<64>::from_low_bits);
            needles.push(symbols.clone().map(|i| prp.permute(i).get()).collect());
            needles.push(symbols.map(|i| prp.invert(i).get()).collect());
            acc.absorb(&prefix_block(n as u16, sym));
        }
        needles
    }

    fn assert_no_block_tables(
        encrypt: fn(&OreAes128Bit6Chained, &str),
        unscrubbed: fn(&OreAes128Bit6Chained, &str),
    ) {
        use crate::primitives::stack::{residue, SCRUB_BYTES};
        const S: &str = "a chained residue test string";
        let needles = block_tables(&ore(), S);

        // Positive control and depth, as in the Bit6 residue tests.
        let dead = residue::after(move || unscrubbed(&ore(), S));
        assert!(needles.iter().any(|n| residue::contains(&dead, n)));
        let depth = residue::depth(&dead);
        assert!(
            depth < SCRUB_BYTES,
            "encryption reached {} bytes of stack, past the {}-byte scrub",
            depth,
            SCRUB_BYTES
        );

        let dead = residue::after(move || encrypt(&ore(), S));
        for (i, needle) in needles.iter().enumerate() {
            assert!(
                !residue::contains(&dead, needle),
                "block {} {} left in dead stack",
                i / 2,
                ["permutation", "inverse"][i % 2]
            );
        }
    }

    #[test]
    fn encrypt_str_leaves_no_prp_tables_on_the_stack() {
        assert_no_block_tables(
            |ore, s| {
                core::hint::black_box(ore.encrypt_str(s).unwrap());
            },
            |ore, s| {
                let blocks = str_to_blocks(s, &ore.options).unwrap();
                core::hint::black_box(ore.encrypt_blocks(&blocks, ore.padding()).unwrap());
            },
        );
    }

    /// A bytes plaintext as large as the wire format allows, on the heap:
    /// the unpadded encryptors must borrow it. A copy on the stack would be
    /// larger than the optimised scrub and leave plaintext in dead stack.
    fn assert_no_large_plaintext(encrypt: fn(&OreAes128Bit6Chained, &OrderPlaintext)) {
        use crate::primitives::stack::{residue, SCRUB_BYTES};
        // vitaminc puts a marker byte before the bytes, so one less fits.
        const LEN: usize = MAX_STR_BYTES - 1;
        fn raw() -> Vec<u8> {
            (0..LEN).map(|i| (i * 37 + 11) as u8).collect()
        }
        // Windows from the start, middle and end of the array; a copy
        // that outgrew the scrub leaves at least its deepest part behind.
        let p = raw();
        let needles: Vec<Vec<u8>> = [0, LEN / 2, LEN - 64]
            .iter()
            .map(|&at| p[at..at + 64].to_vec())
            .collect();

        // Positive control: a copy made under the scrub survives it when
        // it is larger than the scrub (optimised builds).
        if LEN > SCRUB_BYTES {
            let dead = residue::after(|| {
                let p = raw();
                stack::scrubbed(|| {
                    let mut copy = [0u8; LEN];
                    copy.copy_from_slice(&p);
                    core::hint::black_box(&copy);
                });
            });
            assert!(needles.iter().any(|n| residue::contains(&dead, n)));
        }

        // A cipher whose ceiling admits the plaintext.
        let dead = residue::after(move || {
            encrypt(
                &ore_with_max(Padding::None, MAX_STR_BYTES),
                &bytes_pt(&raw()),
            )
        });
        for needle in &needles {
            assert!(
                !residue::contains(&dead, needle),
                "plaintext left in dead stack"
            );
        }
    }

    #[test]
    fn encrypt_plaintext_leaves_no_large_array_on_the_stack() {
        assert_no_large_plaintext(|ore, p| {
            core::hint::black_box(ore.encrypt_plaintext(p).unwrap());
        });
    }

    #[test]
    fn encrypt_query_plaintext_leaves_no_large_array_on_the_stack() {
        assert_no_large_plaintext(|ore, p| {
            core::hint::black_box(ore.encrypt_query_plaintext(p).unwrap());
        });
    }

    #[test]
    fn encrypt_left_str_leaves_no_prp_tables_on_the_stack() {
        assert_no_block_tables(
            |ore, s| {
                core::hint::black_box(ore.encrypt_left_str(s).unwrap());
            },
            |ore, s| {
                let blocks = str_to_blocks(s, &ore.options).unwrap();
                core::hint::black_box(ore.encrypt_left_blocks(&blocks, ore.padding()).unwrap());
            },
        );
    }
}
