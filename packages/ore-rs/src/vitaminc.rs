//! [`OrderScheme`] for the block ORE schemes, so a vitaminc order index
//! can encrypt its sealed order plaintexts here. Behind the `vitaminc`
//! feature; nothing else in this crate depends on vitaminc.
//!
//! vitaminc decides the encoding of every kind of value and seals it as an
//! [`OrderPlaintext`] that only it can build, so a scheme here is never
//! handed bytes that skipped the encoding. This module decides the rest:
//! which scheme takes which plaintext, how a term is stored and compared,
//! and how the scheme's keys are bound to the term's domain and the
//! caller's context.
//!
//! Three schemes implement the trait:
//!
//! - [`Bit6BlockOre`], the ORE v2 fixed-width scheme
//!   ([`OreAes128Bit6ChaCha20`]), the one to prefer for new data: every
//!   fixed-width target up to ten bytes, so the integers to 64 bits,
//!   `f64` and dates. Timestamps and decimals are too wide for it.
//! - [`BlockOre`], the frozen fixed-width scheme ([`OreAes128ChaCha20`]),
//!   for every fixed-width target up to 15 bytes: the integers to 64 bits,
//!   `f64`, dates, timestamps and decimals. It refuses text and
//!   bytes, whose length varies, and the 16-byte kinds (`i128`, `u128`,
//!   uuid), which are beyond its block cap.
//! - [`ChainedBlockOre`], the variable-length scheme
//!   ([`OreAes128Bit6ChainedChaCha20`]), for every kind, text and bytes
//!   included. Not yet frozen: see the scheme's own docs for its review
//!   status and what a ciphertext reveals.
//!
//! vitaminc hands every term the salt of the terms it compares with,
//! `PAE("vitaminc/ore/v1", scheme, domain, context)`: one salt per scheme,
//! target and context. The two v2 schemes bind it through ore-rs's own
//! salt stage ([`OreAes128Bit6ChaCha20::init_with_salt`], and the salt in
//! the chained scheme's [`Options`]), under a 16-byte
//! ORE key derived once from the scheme key with HMAC-SHA256 when the
//! scheme is made. The frozen [`BlockOre`] takes no salt, so it derives its
//! two keys for every term with HMAC-SHA256 under the salt. Either way two
//! targets or two contexts never share a key, and a term compares only
//! with terms of its own target and context.
//!
//! The chained scheme takes text and bytes, the targets whose length
//! varies, behind one marker byte, [`VARIABLE_WIDTH_MARKER`]. Without it
//! an empty bytes value would encrypt to a ciphertext of no blocks: a
//! header and a random nonce, made without the key, which anyone could
//! write in among any terms. With it every term holds at least one keyed
//! block. A constant leading byte keeps the order. Text, which the
//! default padding never leaves empty, takes the marker too, so the two
//! variable-width targets share one rule. Fixed-width targets are never
//! empty and go in as they are.
//!
//! # Examples
//!
//! ```
//! use std::cmp::Ordering;
//! use ore_rs::vitaminc::Bit6BlockOre;
//! use vitaminc_ore::{Int, Logical, OrderEncrypt, OrderKeyInit, OrderTarget, Physical, Raw};
//! use vitaminc_protected::Protected;
//! # let key_bytes = [7u8; 32];
//!
//! // Key the scheme; `try_from_bytes` takes material of runtime length.
//! let scheme = Bit6BlockOre::new(Protected::new(key_bytes));
//!
//! // Terms of `i32`s under one context: four bytes, six blocks, whatever
//! // width a value arrives at. The caller never sees the encoding.
//! // (`column` is vitaminc 0.6's name for opening them.)
//! let quantity = scheme.column(OrderTarget::I32, ("orders", "quantity"));
//! let term = quantity.encrypt(42i64)?;
//! // They compare with each other; a term alone has no order.
//! assert_eq!(quantity.compare(&quantity.encrypt(41i8)?, &term), Some(Ordering::Less));
//! let stored: &[u8] = term.as_ref();
//!
//! // A typed scalar goes in under a target of its type.
//! let birthdays = scheme.column(OrderTarget::Date, "birthdays");
//! let day = Raw(Some(Logical::Date), Physical::Int(Int::I32(19_000)));
//! let birthday = birthdays.encrypt(day)?;
//! # let _ = (stored, birthday);
//! # Ok::<(), vitaminc_ore::OrderError<ore_rs::OreError>>(())
//! ```

use std::cmp::Ordering;
use std::convert::TryInto;

use vitaminc_hmac::{HmacSha256Prf, WeakKeyError};
use vitaminc_ore::{Context, OrderError, OrderKeyInit, OrderPlaintext, OrderScheme, OrderTarget};
use vitaminc_prf::{BlockVisitor, Prf, PrfEncoding, PrfKeyInit};
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroizing;

use crate::scheme::bit2::OreAes128ChaCha20;
use crate::scheme::bit2_w6::OreAes128Bit6ChaCha20;
use crate::scheme::chained::{Options, OreAes128Bit6ChainedChaCha20, Padding};
use crate::{OreCipher, OreError, OreOutput};

/// The PRF domain the fixed-width scheme's two keys are derived under.
const BLOCK_ORE_KEYS: PrfEncoding = PrfEncoding::new("vitaminc/ore/block-ore/keys/v1");

/// The PRF domain the ORE v2 six-bit scheme's ORE key is derived under,
/// once per scheme key. (`v1` derived a key per term under the salt.)
const BIT6_KEY: PrfEncoding = PrfEncoding::new("vitaminc/ore/block-ore-bit6/key/v2");

/// The byte a variable-width plaintext (text or bytes) is encrypted
/// behind by [`ChainedBlockOre`], so that an empty one still makes a keyed
/// block. Part of the stored format: changing it changes every text and
/// bytes term.
pub const VARIABLE_WIDTH_MARKER: u8 = 0x01;

/// Call `encrypt` with what [`ChainedBlockOre`] encrypts for `plaintext`:
/// its bytes as they are for a fixed-width target, and behind
/// [`VARIABLE_WIDTH_MARKER`] for text and bytes. The framed copy is sized
/// exactly, so it never reallocates, and is wiped when it drops.
fn with_input<T>(plaintext: &OrderPlaintext, encrypt: impl FnOnce(&[u8]) -> T) -> T {
    let bytes = plaintext.bytes().risky_ref();
    if plaintext.width().is_some() {
        return encrypt(bytes);
    }
    let mut framed = Zeroizing::new(Vec::with_capacity(bytes.len() + 1));
    framed.push(VARIABLE_WIDTH_MARKER);
    framed.extend_from_slice(bytes);
    encrypt(&framed)
}

/// The PRF domain the chained scheme's ORE key is derived under, once per
/// scheme key. (`v1` derived a key per term under the salt.)
const CHAINED_KEY: PrfEncoding = PrfEncoding::new("vitaminc/ore/chained-block-ore/key/v2");

/// The 16-byte ORE key a v2 scheme is keyed with: the scheme key through
/// HMAC-SHA256 under `encoding`, with no salt. Made once, with the scheme;
/// each term's salt is bound afterwards by `init_with_salt`. `None` only
/// if HMAC refused, which it cannot once keyed: the scheme then refuses
/// every term ([`ore_key_or_refuse`]) rather than panic.
fn ore_key(prf: &HmacSha256Prf, encoding: PrfEncoding) -> Option<Zeroizing<[u8; 16]>> {
    let material = prf
        .prf_bytes_vec(
            Protected::new(Vec::new()),
            encoding,
            Context::empty(),
            BlockVisitor,
        )
        .into_result()
        .ok()
        .map(Zeroizing::new)?;
    let mut key = Zeroizing::new([0u8; 16]);
    key.copy_from_slice(&material[..16]);
    Some(key)
}

/// The scheme's ORE key, or the refusal [`ore_key`] stands for.
fn ore_key_or_refuse(key: &Option<Zeroizing<[u8; 16]>>) -> Result<&[u8; 16], OrderError<OreError>> {
    key.as_deref()
        .ok_or(OrderError::Backend(OreError::InitFailed))
}

/// Thirty-two bytes of key material for one [`BlockOre`] term: the scheme
/// key through HMAC-SHA256 under `encoding` and the term's salt. Wiped on
/// drop.
fn derive(
    prf: &HmacSha256Prf,
    encoding: PrfEncoding,
    salt: &Context<'_>,
) -> Result<Zeroizing<[u8; 32]>, OrderError<OreError>> {
    let salt = salt.clone().into_owned();
    prf.prf_bytes_vec(Protected::new(Vec::new()), encoding, salt, BlockVisitor)
        .into_result()
        .map(Zeroizing::new)
        // HMAC cannot fail once keyed; keep the refusal rather than a panic.
        .map_err(|_| OrderError::Backend(OreError::InitFailed))
}

/// The frozen fixed-width block ORE scheme as a vitaminc order scheme.
///
/// Takes every fixed-width target of at most 15 bytes, at its width: an
/// `i32` is four blocks, a decimal fourteen. Refuses text,
/// bytes and the 16-byte kinds as [`OrderError::Unsupported`].
///
/// The term keeps the whole serialised ciphertext, left and right halves,
/// and compares with the scheme's comparator. The right half carries a
/// random nonce, so one plaintext encrypts to different bytes each time,
/// and those terms compare equal.
pub struct BlockOre {
    prf: HmacSha256Prf,
}

/// A [`BlockOre`] term: the serialised ciphertext. Compared by the
/// scheme's comparator, [`OrderScheme::compare`], rather than byte by
/// byte, and only with terms of its own target and context.
#[derive(Debug, Clone)]
pub struct BlockOreTerm(Vec<u8>);

impl AsRef<[u8]> for BlockOreTerm {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl BlockOre {
    /// The scheme keyed for one term.
    fn cipher(&self, salt: &Context<'_>) -> Result<OreAes128ChaCha20, OrderError<OreError>> {
        let material = derive(&self.prf, BLOCK_ORE_KEYS, salt)?;
        let mut k1 = Zeroizing::new([0u8; 16]);
        let mut k2 = Zeroizing::new([0u8; 16]);
        k1.copy_from_slice(&material[..16]);
        k2.copy_from_slice(&material[16..]);
        OreAes128ChaCha20::init(&k1, &k2).map_err(OrderError::Backend)
    }
}

/// Encrypt `bytes`, which are exactly `N` long, as `N` blocks.
fn fixed<const N: usize>(
    cipher: &OreAes128ChaCha20,
    bytes: &[u8],
) -> Result<Vec<u8>, OrderError<OreError>> {
    let input: &[u8; N] = bytes
        .try_into()
        // vitaminc's plaintext is sealed, so its length is its width; this
        // is unreachable, and refused rather than unwrapped.
        .map_err(|_| OrderError::Backend(OreError::InitFailed))?;
    Ok(cipher
        .encrypt(input)
        .map_err(OrderError::Backend)?
        .to_bytes())
}

impl OrderScheme for BlockOre {
    const NAME: &'static str = "block-ore";
    type Term = BlockOreTerm;
    type Error = OreError;

    fn encrypt_plaintext(
        &self,
        plaintext: &OrderPlaintext,
        salt: &Context<'_>,
    ) -> Result<BlockOreTerm, OrderError<OreError>> {
        // The widths vitaminc's targets have. Stable Rust cannot pick `N`
        // from a runtime value, so each is named; one above the block cap
        // (16) is refused with the variable-length kinds.
        let width = match plaintext.width() {
            Some(w @ (1 | 2 | 4 | 8 | 12 | 14)) => w,
            _ => return Err(OrderError::unsupported::<Self>(plaintext)),
        };
        let cipher = self.cipher(salt)?;
        let bytes = plaintext.bytes().risky_ref().as_slice();
        let term = match width {
            1 => fixed::<1>(&cipher, bytes)?,
            2 => fixed::<2>(&cipher, bytes)?,
            4 => fixed::<4>(&cipher, bytes)?,
            8 => fixed::<8>(&cipher, bytes)?,
            12 => fixed::<12>(&cipher, bytes)?,
            _ => fixed::<14>(&cipher, bytes)?,
        };
        Ok(BlockOreTerm(term))
    }

    /// The scheme's comparison. `None` for a term that is not a
    /// well-formed `OreAes128ChaCha20` ciphertext. Two well-formed
    /// terms of different targets or contexts compare as noise, which the
    /// scheme cannot tell; a caller keeps such terms apart.
    fn compare(a: &BlockOreTerm, b: &BlockOreTerm) -> Option<Ordering> {
        OreAes128ChaCha20::compare_raw_slices(&a.0, &b.0)
    }
}

impl OrderKeyInit for BlockOre {
    type Key = Protected<[u8; 32]>;
    type KeyError = WeakKeyError;

    fn new(key: Self::Key) -> Self {
        Self {
            prf: HmacSha256Prf::new(key),
        }
    }

    fn try_from_bytes(key: Protected<Vec<u8>>) -> Result<Self, WeakKeyError> {
        Ok(Self {
            prf: HmacSha256Prf::try_from_bytes(key)?,
        })
    }
}

/// The ORE v2 six-bit block ORE scheme as a vitaminc order scheme, the
/// one to prefer for new fixed-width data.
///
/// Takes every fixed-width target of at most ten bytes (its fourteen
/// six-bit blocks), so the integers to 64 bits, `f64` and dates.
/// Refuses timestamps (12 bytes), decimals (14), the 16-byte kinds, text
/// and bytes as [`OrderError::Unsupported`].
///
/// Keyed by [`OreAes128Bit6ChaCha20::init_with_salt`] under the term's
/// salt, from an ORE key derived once when the scheme is made.
pub struct Bit6BlockOre {
    key: Option<Zeroizing<[u8; 16]>>,
}

/// A [`Bit6BlockOre`] term: the serialised ciphertext. Compared by the
/// scheme's comparator, [`OrderScheme::compare`], rather than byte by
/// byte, and only with terms of its own target and context.
#[derive(Debug, Clone)]
pub struct Bit6BlockOreTerm(Vec<u8>);

impl AsRef<[u8]> for Bit6BlockOreTerm {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl OrderScheme for Bit6BlockOre {
    const NAME: &'static str = "block-ore-bit6";
    type Term = Bit6BlockOreTerm;
    type Error = OreError;

    fn encrypt_plaintext(
        &self,
        plaintext: &OrderPlaintext,
        salt: &Context<'_>,
    ) -> Result<Bit6BlockOreTerm, OrderError<OreError>> {
        match plaintext.width() {
            Some(1..=10) => {}
            _ => return Err(OrderError::unsupported::<Self>(plaintext)),
        }
        let key = ore_key_or_refuse(&self.key)?;
        let cipher = OreAes128Bit6ChaCha20::init_with_salt(key, salt.as_bytes())
            .map_err(OrderError::Backend)?;
        cipher
            .encrypt_bytes(plaintext.bytes().risky_ref())
            .map(Bit6BlockOreTerm)
            .map_err(OrderError::Backend)
    }

    /// The scheme's comparison. `None` for a term that is not a
    /// well-formed `OreAes128Bit6ChaCha20` ciphertext. Two well-formed
    /// terms of different targets or contexts compare as noise, which the
    /// scheme cannot tell; a caller keeps such terms apart.
    fn compare(a: &Bit6BlockOreTerm, b: &Bit6BlockOreTerm) -> Option<Ordering> {
        OreAes128Bit6ChaCha20::compare_raw_slices(&a.0, &b.0)
    }
}

impl OrderKeyInit for Bit6BlockOre {
    type Key = Protected<[u8; 32]>;
    type KeyError = WeakKeyError;

    fn new(key: Self::Key) -> Self {
        Self {
            key: ore_key(&HmacSha256Prf::new(key), BIT6_KEY),
        }
    }

    fn try_from_bytes(key: Protected<Vec<u8>>) -> Result<Self, WeakKeyError> {
        Ok(Self {
            key: ore_key(&HmacSha256Prf::try_from_bytes(key)?, BIT6_KEY),
        })
    }
}

/// The chained, variable-length block ORE scheme as a vitaminc order
/// scheme: every target, text and bytes included, at six bits per block.
///
/// Not yet frozen. Text and bytes go in behind [`VARIABLE_WIDTH_MARKER`],
/// one byte that counts towards the length below. Text is padded under the
/// default policy ([`Padding::default`]), so a text ciphertext reveals the
/// length bucket, and text that ends in NUL is refused
/// ([`OreError::TrailingNul`]).
/// Bytes are not padded, since padding would refuse every value that ends
/// in a zero byte, so a bytes ciphertext reveals the exact length. Nor are
/// fixed-width targets, whose length is the target's and public already.
/// A comparison reveals the common-prefix length; see
/// [`crate::scheme::chained`].
///
/// Text and bytes are refused past 1023 bytes, as
/// `OrderError::Backend(`[`OreError::TooLong`]`)`: the scheme's default
/// ceiling ([`DEFAULT_MAX_STR_BYTES`](crate::scheme::chained::DEFAULT_MAX_STR_BYTES),
/// 1024) counts the marker byte. The
/// ceiling bounds what one value can cost: a 1023-byte value is already a
/// term of about 34 KB.
///
/// Keyed by [`OreAes128Bit6ChainedChaCha20::init_with`] with the term's
/// salt in its [`Options`], from an ORE key derived once when the scheme
/// is made.
pub struct ChainedBlockOre {
    key: Option<Zeroizing<[u8; 16]>>,
}

/// A [`ChainedBlockOre`] term: the serialised ciphertext. Compared by the
/// scheme's comparator, [`OrderScheme::compare`], and only with terms
/// of its own target and context.
#[derive(Debug, Clone)]
pub struct ChainedBlockOreTerm(Vec<u8>);

impl AsRef<[u8]> for ChainedBlockOreTerm {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ChainedBlockOre {
    /// The scheme keyed for the terms of `target` under `salt`.
    fn cipher(
        &self,
        target: OrderTarget,
        salt: &Context<'_>,
    ) -> Result<OreAes128Bit6ChainedChaCha20, OrderError<OreError>> {
        let key = ore_key_or_refuse(&self.key)?;
        // Terms that compare together share their target, so the policy is
        // the same for all of them, and terms made under different
        // policies never meet in a comparison.
        let options = match target {
            OrderTarget::Text => Options::default(),
            _ => Options::default().with_padding(Padding::None),
        };
        OreAes128Bit6ChainedChaCha20::init_with(key, options.with_salt(salt.as_bytes()))
            .map_err(OrderError::Backend)
    }
}

impl OrderScheme for ChainedBlockOre {
    const NAME: &'static str = "chained-block-ore";
    type Term = ChainedBlockOreTerm;
    type Error = OreError;

    fn encrypt_plaintext(
        &self,
        plaintext: &OrderPlaintext,
        salt: &Context<'_>,
    ) -> Result<ChainedBlockOreTerm, OrderError<OreError>> {
        let cipher = self.cipher(plaintext.target(), salt)?;
        let term = with_input(plaintext, |input| cipher.encrypt_bytes(input))
            .map_err(OrderError::Backend)?;
        Ok(ChainedBlockOreTerm(term.to_bytes()))
    }

    /// The scheme's comparison. `None` for a term that is not a
    /// well-formed `OreAes128Bit6ChainedChaCha20` ciphertext,
    /// or for two terms padded under different policies (text against
    /// bytes). Two well-formed
    /// terms of different targets or contexts compare as noise, which the
    /// scheme cannot tell; a caller keeps such terms apart.
    fn compare(a: &ChainedBlockOreTerm, b: &ChainedBlockOreTerm) -> Option<Ordering> {
        OreAes128Bit6ChainedChaCha20::compare_raw_slices(&a.0, &b.0)
    }
}

impl OrderKeyInit for ChainedBlockOre {
    type Key = Protected<[u8; 32]>;
    type KeyError = WeakKeyError;

    fn new(key: Self::Key) -> Self {
        Self {
            key: ore_key(&HmacSha256Prf::new(key), CHAINED_KEY),
        }
    }

    fn try_from_bytes(key: Protected<Vec<u8>>) -> Result<Self, WeakKeyError> {
        Ok(Self {
            key: ore_key(&HmacSha256Prf::try_from_bytes(key)?, CHAINED_KEY),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_ore::{
        domain, order, Float, Int, Logical, NormalizeError, OrderEncrypt, OrderTarget, Physical,
        Raw, TimeUnit,
    };

    use OrderTarget as T;

    fn key() -> Protected<[u8; 32]> {
        Protected::new([7; 32])
    }

    /// `a` below `b` as `target`s, and `a` twice compares equal.
    fn ordered<S: OrderScheme>(
        scheme: &S,
        target: OrderTarget,
        ty: Option<Logical>,
        a: Physical<'_>,
        b: Physical<'_>,
    ) {
        let space = scheme.column(target, ());
        let (x, y) = (order(target, ty, a).unwrap(), order(target, ty, b).unwrap());
        let (left, right) = (
            space.encrypt_term(&x).unwrap(),
            space.encrypt_term(&y).unwrap(),
        );
        assert_eq!(
            space.compare(&left, &right),
            Some(Ordering::Less),
            "{}",
            x.domain()
        );
        assert_eq!(
            space.compare(&right, &left),
            Some(Ordering::Greater),
            "{}",
            x.domain()
        );
        assert_eq!(
            space.compare(&left, &space.encrypt_term(&x).unwrap()),
            Some(Ordering::Equal),
            "{}",
            x.domain()
        );
    }

    /// `target` refused by `scheme` by its domain.
    fn refused<S: OrderScheme>(scheme: &S, target: OrderTarget, value: Raw<'_>) {
        let name = S::NAME;
        assert!(
            matches!(
                scheme.column(target, ()).encrypt(value),
                Err(OrderError::Unsupported { scheme, domain: d }) if scheme == name && d == target.domain()
            ),
            "{} {:?}",
            name,
            target
        );
    }

    #[test]
    fn block_ore_orders_every_fixed_width_target_at_its_width() {
        use Physical::{Float as F, Int as I};
        let block = BlockOre::new(key());
        ordered(&block, T::I8, None, I(Int::I8(-1)), I(Int::I8(1)));
        ordered(&block, T::U8, None, I(Int::U8(0)), I(Int::U8(255)));
        ordered(
            &block,
            T::I16,
            None,
            I(Int::I16(i16::MIN)),
            I(Int::I16(i16::MAX)),
        );
        ordered(&block, T::U16, None, I(Int::U16(0)), I(Int::U16(u16::MAX)));
        ordered(
            &block,
            T::I32,
            None,
            I(Int::I32(i32::MIN)),
            I(Int::I32(i32::MAX)),
        );
        ordered(&block, T::U32, None, I(Int::U32(0)), I(Int::U32(u32::MAX)));
        ordered(
            &block,
            T::I64,
            None,
            I(Int::I64(i64::MIN)),
            I(Int::I64(i64::MAX)),
        );
        ordered(&block, T::U64, None, I(Int::U64(0)), I(Int::U64(u64::MAX)));
        ordered(
            &block,
            T::F64,
            None,
            F(Float::F32(-1.5)),
            F(Float::F32(f32::NAN)),
        );
        ordered(
            &block,
            T::F64,
            None,
            F(Float::F64(f64::NEG_INFINITY)),
            F(Float::F64(0.0)),
        );
        ordered(
            &block,
            T::Date,
            Some(Logical::Date),
            I(Int::I32(-1)),
            I(Int::I32(19_000)),
        );
        ordered(
            &block,
            T::Timestamp,
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            I(Int::I64(-1)),
            I(Int::I64(0)),
        );
        ordered(
            &block,
            T::Decimal,
            Some(Logical::Decimal { scale: 2 }),
            I(Int::I64(-150)),
            I(Int::I64(150)),
        );
        // One block per byte of the target: an `i32` term is the
        // fixed-4 ciphertext, even for a value that arrived as an `i8`.
        let term = block.column(T::I32, ()).encrypt(1i8).unwrap();
        assert_eq!(
            term.as_ref().len(),
            <crate::CipherText<OreAes128ChaCha20, 4> as OreOutput>::size()
        );
    }

    #[test]
    fn block_ore_refuses_variable_length_and_sixteen_byte_targets_by_name() {
        let block = BlockOre::new(key());
        refused(&block, T::Text, Raw(None, Physical::Text("abcd")));
        refused(
            &block,
            T::Bytes,
            Raw(None, Physical::Bytes(&[1, 2, 3, 4][..])),
        );
        refused(&block, T::I128, Raw(None, Physical::Int(Int::I8(1))));
        refused(&block, T::U128, Raw(None, Physical::Int(Int::U8(1))));
        refused(
            &block,
            T::Uuid,
            Raw(Some(Logical::Uuid), Physical::Bytes(&[0; 16][..])),
        );
    }

    #[test]
    fn chained_orders_every_target_including_text_and_bytes() {
        use Physical::{Bytes, Int as I, Text};
        let chained = ChainedBlockOre::new(key());
        ordered(&chained, T::I32, None, I(Int::I32(-7)), I(Int::I32(7)));
        ordered(
            &chained,
            T::I128,
            None,
            I(Int::I128(i128::MIN)),
            I(Int::I128(i128::MAX)),
        );
        ordered(
            &chained,
            T::U128,
            None,
            I(Int::U128(0)),
            I(Int::U128(u128::MAX)),
        );
        ordered(
            &chained,
            T::Uuid,
            Some(Logical::Uuid),
            Bytes(&[0; 16][..]),
            Bytes(&[1; 16][..]),
        );
        ordered(&chained, T::Text, None, Text("apple"), Text("Banana"));
        ordered(&chained, T::Text, None, Text("École"), Text("ecolf"));
        ordered(&chained, T::Bytes, None, Bytes(&[][..]), Bytes(&[0][..]));
        ordered(
            &chained,
            T::Bytes,
            None,
            Bytes(&[1][..]),
            Bytes(&[1, 0][..]),
        );
        // Text that folds together is one term.
        let names = chained.column(T::Text, ());
        assert_eq!(
            names.compare(
                &names.encrypt("Straße").unwrap(),
                &names.encrypt("strasse").unwrap()
            ),
            Some(Ordering::Equal)
        );
    }

    /// The JavaScript host hands each BigInt over at the narrowest width
    /// that holds it. Under one target they all take its width, so
    /// fixed-width block ORE compares them.
    #[test]
    fn narrowest_width_integers_compare_under_one_fixed_width_target() {
        let bit6 = Bit6BlockOre::new(key());
        let space = bit6.column(T::I32, ("orders", "total"));
        let (hundred, two_hundred, three_hundred) = (
            space
                .encrypt(Raw(None, Physical::Int(Int::I8(100))))
                .unwrap(),
            space
                .encrypt(Raw(None, Physical::Int(Int::U8(200))))
                .unwrap(),
            space
                .encrypt(Raw(None, Physical::Int(Int::I16(300))))
                .unwrap(),
        );
        assert_eq!(space.compare(&hundred, &two_hundred), Some(Ordering::Less));
        assert_eq!(
            space.compare(&two_hundred, &three_hundred),
            Some(Ordering::Less)
        );
        assert_eq!(
            space.compare(
                &hundred,
                &space
                    .encrypt(Raw(None, Physical::Int(Int::U64(100))))
                    .unwrap()
            ),
            Some(Ordering::Equal)
        );
        // A value the target cannot hold is refused before the scheme.
        assert!(matches!(
            space.encrypt(1i64 << 40),
            Err(OrderError::Term(NormalizeError::OutOfRange))
        ));
    }

    #[test]
    fn terms_compare_only_within_one_scheme_key_target_and_context() {
        let tenant = |n: u64| ("tenant", n);
        let block = BlockOre::new(key());
        // Terms of two contexts have no order between them, so this compares
        // their bytes: another context, key or target gives other bytes.
        let under = |n: u64| block.column(T::I8, tenant(n)).encrypt(0i8).unwrap();
        assert_ne!(under(1).as_ref(), under(2).as_ref());
        assert_ne!(
            under(1).as_ref(),
            BlockOre::new(Protected::new([8; 32]))
                .column(T::I8, tenant(1))
                .encrypt(0i8)
                .unwrap()
                .as_ref()
        );
        // The same bytes under another target: a different key, so not equal.
        let as_u8 = block.column(T::U8, ()).encrypt(0x80i16).unwrap();
        let as_i8 = block.column(T::I8, ()).encrypt(0i8).unwrap();
        assert_eq!(
            order(T::I8, None, Physical::Int(Int::I8(0)))
                .unwrap()
                .bytes()
                .risky_ref(),
            order(T::U8, None, Physical::Int(Int::U8(0x80)))
                .unwrap()
                .bytes()
                .risky_ref()
        );
        assert_ne!(as_u8.as_ref(), as_i8.as_ref());
        let chained = ChainedBlockOre::new(key());
        assert_ne!(
            chained
                .column(T::I8, tenant(1))
                .encrypt(0i8)
                .unwrap()
                .as_ref(),
            chained
                .column(T::I8, tenant(2))
                .encrypt(0i8)
                .unwrap()
                .as_ref()
        );
    }

    #[test]
    fn a_scheme_is_keyed_like_a_prf() {
        let from_bytes = BlockOre::try_from_bytes(Protected::new(vec![7; 32])).unwrap();
        let term = |s: &BlockOre| s.column(T::I8, ()).encrypt(1i8).unwrap();
        assert_eq!(
            BlockOre::compare(&term(&from_bytes), &term(&BlockOre::new(key()))),
            Some(Ordering::Equal)
        );
        assert!(BlockOre::try_from_bytes(Protected::new(vec![7; 8])).is_err());
        assert!(ChainedBlockOre::try_from_bytes(Protected::new(vec![7; 8])).is_err());
    }

    #[test]
    fn a_value_with_no_term_is_refused() {
        let block = BlockOre::new(key());
        assert!(matches!(
            block.column(T::I8, ()).encrypt(true),
            Err(OrderError::Term(NormalizeError::NoDomain))
        ));
        assert!(matches!(
            block.column(T::I32, ()).encrypt("42"),
            Err(OrderError::Term(NormalizeError::Mismatch))
        ));
    }

    #[test]
    fn terms_of_two_widths_have_no_order() {
        let block = BlockOre::new(key());
        let one = block.column(T::I8, ()).encrypt(1i8).unwrap();
        let four = block.column(T::I32, ()).encrypt(1i8).unwrap();
        assert_eq!(BlockOre::compare(&one, &four), None);
        assert_eq!(BlockOre::compare(&four, &one), None);
        let bit6 = Bit6BlockOre::new(key());
        let one = bit6.column(T::I8, ()).encrypt(1i8).unwrap();
        let four = bit6.column(T::I32, ()).encrypt(1i8).unwrap();
        assert_eq!(Bit6BlockOre::compare(&one, &four), None);
    }

    #[test]
    fn chained_text_and_bytes_terms_have_no_order() {
        // Text is padded and bytes are not, so the comparator refuses the
        // pair rather than ordering their headers.
        let chained = ChainedBlockOre::new(key());
        let text = chained.column(T::Text, "col").encrypt("z").unwrap();
        let bytes = chained
            .column(T::Bytes, "col")
            .encrypt(Raw(None, Physical::Bytes(&[1; 20])))
            .unwrap();
        assert_eq!(ChainedBlockOre::compare(&text, &bytes), None);
        assert_eq!(ChainedBlockOre::compare(&bytes, &text), None);
    }

    #[test]
    fn bit6_orders_every_target_up_to_ten_bytes_and_refuses_the_rest_by_name() {
        use Physical::{Float as F, Int as I};
        let bit6 = Bit6BlockOre::new(key());
        ordered(&bit6, T::I8, None, I(Int::I8(-1)), I(Int::I8(1)));
        ordered(&bit6, T::U16, None, I(Int::U16(0)), I(Int::U16(u16::MAX)));
        ordered(
            &bit6,
            T::I32,
            None,
            I(Int::I32(i32::MIN)),
            I(Int::I32(i32::MAX)),
        );
        ordered(
            &bit6,
            T::I64,
            None,
            I(Int::I64(i64::MIN)),
            I(Int::I64(i64::MAX)),
        );
        ordered(&bit6, T::U64, None, I(Int::U64(0)), I(Int::U64(u64::MAX)));
        ordered(
            &bit6,
            T::F64,
            None,
            F(Float::F32(-1.5)),
            F(Float::F32(f32::NAN)),
        );
        ordered(
            &bit6,
            T::F64,
            None,
            F(Float::F64(f64::NEG_INFINITY)),
            F(Float::F64(0.0)),
        );
        ordered(
            &bit6,
            T::Date,
            Some(Logical::Date),
            I(Int::I32(-1)),
            I(Int::I32(19_000)),
        );
        refused(
            &bit6,
            T::Timestamp,
            Raw(
                Some(Logical::Timestamp(TimeUnit::Nanos)),
                Physical::Int(Int::I64(0)),
            ),
        );
        refused(
            &bit6,
            T::Decimal,
            Raw(
                Some(Logical::Decimal { scale: 2 }),
                Physical::Int(Int::I64(150)),
            ),
        );
        refused(&bit6, T::I128, Raw(None, Physical::Int(Int::I128(1))));
        refused(&bit6, T::Text, Raw(None, Physical::Text("abcd")));
        refused(&bit6, T::Bytes, Raw(None, Physical::Bytes(&[1, 2][..])));
        assert_eq!(domain::INT32, T::I32.domain());
        // Bound to key, context and target like the other schemes.
        assert_ne!(
            bit6.column(T::I8, ("tenant", 1u64))
                .encrypt(0i8)
                .unwrap()
                .as_ref(),
            bit6.column(T::I8, ("tenant", 2u64))
                .encrypt(0i8)
                .unwrap()
                .as_ref()
        );
        assert_ne!(
            bit6.column(T::I8, ()).encrypt(0i8).unwrap().as_ref(),
            bit6.column(T::U8, ()).encrypt(0x80i16).unwrap().as_ref()
        );
        assert!(Bit6BlockOre::try_from_bytes(Protected::new(vec![7; 8])).is_err());
    }

    #[test]
    fn chained_pads_text_but_not_bytes() {
        let chained = ChainedBlockOre::new(key());
        let text = chained.column(T::Text, "col");
        let (a, b) = (
            text.encrypt("a").unwrap(),
            text.encrypt("abcdefgh").unwrap(),
        );
        assert_eq!(
            a.as_ref().len(),
            b.as_ref().len(),
            "text of one bucket encrypts to one length"
        );
        assert!(
            matches!(
                text.encrypt("a\0"),
                Err(OrderError::Backend(OreError::TrailingNul))
            ),
            "padded text that ends in NUL is refused"
        );

        let bytes = chained.column(T::Bytes, "col");
        let under = |v: &[u8]| bytes.encrypt(Raw(None, Physical::Bytes(v))).unwrap();
        assert!(
            under(&[1]).as_ref().len() < under(&[1; 8]).as_ref().len(),
            "bytes are not padded"
        );
        assert_eq!(
            bytes.compare(&under(&[1]), &under(&[1, 0])),
            Some(Ordering::Less),
            "a trailing zero byte is kept"
        );
    }

    /// The v2 schemes key a term with ore-rs's salt stage under the salt
    /// vitaminc derives, from an ORE key derived once from the scheme key:
    /// the same plaintext through `init_with_salt` / `init_with` directly
    /// compares `Equal`.
    #[test]
    fn v2_terms_are_keyed_through_the_ore_salt_stage() {
        let ore_key_for = |encoding| ore_key(&HmacSha256Prf::new(key()), encoding).unwrap();
        let x = order(T::I32, None, Physical::Int(Int::I32(42))).unwrap();

        let bit6_scheme = Bit6BlockOre::new(key());
        let bit6 = bit6_scheme.column(T::I32, ("orders", "total"));
        let term = bit6.encrypt_term(&x).unwrap();
        let direct =
            OreAes128Bit6ChaCha20::init_with_salt(&ore_key_for(BIT6_KEY), bit6.salt().as_bytes())
                .unwrap()
                .encrypt_bytes(x.bytes().risky_ref())
                .unwrap();
        assert_eq!(
            OreAes128Bit6ChaCha20::compare_raw_slices(term.as_ref(), &direct),
            Some(Ordering::Equal)
        );

        let chained_scheme = ChainedBlockOre::new(key());
        let chained = chained_scheme.column(T::I32, ("orders", "total"));
        let term = chained.encrypt_term(&x).unwrap();
        let options = Options::default()
            .with_padding(Padding::None)
            .with_salt(chained.salt().as_bytes());
        let direct = OreAes128Bit6ChainedChaCha20::init_with(&ore_key_for(CHAINED_KEY), options)
            .unwrap()
            .encrypt_bytes(x.bytes().risky_ref())
            .unwrap()
            .to_bytes();
        assert_eq!(
            OreAes128Bit6ChainedChaCha20::compare_raw_slices(term.as_ref(), &direct),
            Some(Ordering::Equal)
        );
    }

    /// The deterministic left halves of two v2 terms, pinned: a change to
    /// the ORE key derivation, the salt vitaminc derives or the salt stage
    /// changes every stored term and must fail here. (The right halves
    /// carry a random nonce.)
    #[test]
    fn v2_term_left_halves_are_pinned() {
        let x = order(T::I32, None, Physical::Int(Int::I32(42))).unwrap();
        // Header, six `xt` bytes and six 16-byte `f` blocks.
        let bit6_scheme = Bit6BlockOre::new(key());
        let bit6 = bit6_scheme.column(T::I32, ("orders", "total"));
        let term = bit6.encrypt_term(&x).unwrap();
        let bit6_left = hex::encode(&term.as_ref()[..4 + 6 + 6 * 16]);
        let chained_scheme = ChainedBlockOre::new(key());
        let chained = chained_scheme.column(T::I32, ("orders", "total"));
        let term = chained.encrypt_term(&x).unwrap();
        let chained_left = hex::encode(&term.as_ref()[..7 + 6 + 6 * 16]);
        assert_eq!(bit6_left, PINNED_BIT6_LEFT);
        assert_eq!(chained_left, PINNED_CHAINED_LEFT);
    }

    const PINNED_BIT6_LEFT: &str = "02020006043037243a2740c5e5e509f4921d05c4d854c63ef638be957f784126069fbdbe37cbf2961c494d0e8d71074cfa6a76c6f94686720215142725611ee4cbe4240b500c2cde0b00a5121107f52e6d1317b7550a381394a581a7b617711b443a88c0889a6f3a07ee";
    const PINNED_CHAINED_LEFT: &str = "020300060000003511332a1f10f65025a6c69fd98c42894b3c40affbaae54679e6d004e6a9905d5a8c1faadbd5b86396f03779830295aa7bb6b186e934f580c50cbf5c050b3b20705091e00d196cda6f7fb402d5ef5e60a2c8434698a03e4e25ffc204162fbaefee3b998b94fd";

    /// Text and bytes up to 1023 bytes encrypt, and 1024 is refused as
    /// `TooLong`: the scheme's 1024-byte default ceiling counts the
    /// marker byte (review of #115).
    #[test]
    fn chained_refuses_text_and_bytes_past_1023_bytes() {
        let chained = ChainedBlockOre::new(key());
        let bytes = chained.column(T::Bytes, ());
        let long = vec![b'a'; 1024];
        assert!(bytes
            .encrypt(Raw(None, Physical::Bytes(&long[..1023])))
            .is_ok());
        assert!(matches!(
            bytes.encrypt(Raw(None, Physical::Bytes(&long))),
            Err(OrderError::Backend(OreError::TooLong))
        ));
        let text = chained.column(T::Text, ());
        let long = "a".repeat(1024);
        assert!(text.encrypt(&long[..1023]).is_ok());
        assert!(matches!(
            text.encrypt(long.as_str()),
            Err(OrderError::Backend(OreError::TooLong))
        ));
    }

    /// The stored format of text and bytes: the encryption of the marker
    /// byte `0x01`, then the value. The expected inputs are written out
    /// rather than built from the plaintext, so this fails if the marker
    /// is ever added twice: for example by this crate and by a vitaminc
    /// release whose own encoding starts with it. An empty bytes value
    /// therefore makes a keyed block, not a ciphertext of none.
    #[test]
    fn chained_encrypts_text_and_bytes_behind_the_marker() {
        let chained = ChainedBlockOre::new(key());
        let cases: [(OrderTarget, Physical<'_>, &[u8]); 4] = [
            (T::Bytes, Physical::Bytes(&[][..]), &[0x01]),
            (T::Text, Physical::Text(""), &[0x01]),
            (T::Bytes, Physical::Bytes(&[0xAB][..]), &[0x01, 0xAB]),
            (T::Text, Physical::Text("a"), &[0x01, b'a']),
        ];
        for (target, value, input) in cases {
            let space = chained.column(target, "col");
            let term = space
                .encrypt_term(&order(target, None, value).unwrap())
                .unwrap();
            let cipher = chained.cipher(target, space.salt()).unwrap();
            let direct =
                |input: &[u8]| ChainedBlockOreTerm(cipher.encrypt_bytes(input).unwrap().to_bytes());
            assert_eq!(
                space.compare(&term, &direct(input)),
                Some(Ordering::Equal),
                "{target:?}: the marker once, then the value"
            );
            assert_eq!(
                term.as_ref().len(),
                direct(input).as_ref().len(),
                "{target:?}"
            );
            // Unpadded bytes are where an empty value made no block at
            // all; padded text is already one bucket long.
            if input.len() == 1 && target == T::Bytes {
                assert!(
                    term.as_ref().len() > direct(&[]).as_ref().len(),
                    "an empty bytes value still makes a keyed block"
                );
            }
        }
    }

    quickcheck! {
        fn bit6_order_is_integer_order(a: i64, b: i32) -> bool {
            let bit6 = Bit6BlockOre::new(key());
            let space = bit6.column(T::I64, "col");
            space.compare(&space.encrypt(a).unwrap(), &space.encrypt(b).unwrap()) == Some(a.cmp(&i64::from(b)))
        }
    }

    quickcheck! {
        fn block_order_is_integer_order(a: i64, b: i64) -> bool {
            let block = BlockOre::new(key());
            let space = block.column(T::I64, "col");
            space.compare(&space.encrypt(a).unwrap(), &space.encrypt(b).unwrap()) == Some(a.cmp(&b))
        }

        fn chained_order_is_byte_order(a: Vec<u8>, b: Vec<u8>) -> bool {
            let chained = ChainedBlockOre::new(key());
            let space = chained.column(T::Bytes, "col");
            let under = |v: &[u8]| space.encrypt(Raw(None, Physical::Bytes(v))).unwrap();
            space.compare(&under(&a), &under(&b)) == Some(a.cmp(&b))
        }
    }
}
