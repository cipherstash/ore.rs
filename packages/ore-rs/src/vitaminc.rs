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
//!   fixed-width kind up to ten bytes, so the integers to 64 bits, both
//!   floats and dates. Timestamps and decimals are too wide for it.
//! - [`BlockOre`], the frozen fixed-width scheme ([`OreAes128ChaCha20`]),
//!   for every fixed-width kind up to 15 bytes: the integers to 64 bits,
//!   both floats, dates, timestamps and decimals. It refuses text and
//!   bytes, whose length varies, and the 16-byte kinds (`i128`, `u128`,
//!   uuid), which are beyond its block cap.
//! - [`ChainedBlockOre`], the variable-length scheme
//!   ([`OreAes128Bit6ChainedChaCha20`]), for every kind, text and bytes
//!   included. Not yet frozen: see the scheme's own docs for its review
//!   status and what a ciphertext reveals.
//!
//! None of the schemes takes a salt, so each derives its keys for every
//! term from its own key with HMAC-SHA256 under the salt vitaminc derives,
//! `PAE("vitaminc/ore/v1", scheme, domain, context)`. Two columns, two
//! kinds or two contexts therefore never share a key, and a term compares
//! only within its own column.
//!
//! # Examples
//!
//! ```
//! use ore_rs::vitaminc::Bit6BlockOre;
//! use vitaminc_ore::{Int, Logical, OrderKeyInit, OrderScheme, Physical, Raw};
//! use vitaminc_protected::Protected;
//! # let key_bytes = [7u8; 32];
//!
//! // Key the scheme; `try_from_bytes` takes material of runtime length.
//! let scheme = Bit6BlockOre::new(Protected::new(key_bytes));
//!
//! // Encrypt a value. Its kind decides the domain and the width: a u32 is
//! // four bytes, six blocks. The caller never sees the encoding.
//! let term = scheme.encrypt(42u32)?;
//! assert!(scheme.encrypt(41u32)? < term);
//!
//! // Under a context, so the term compares only within its column.
//! let quantity = scheme.encrypt_with_context(42u32, ("orders", "quantity"))?;
//! let stored: &[u8] = quantity.as_ref();
//!
//! // A typed scalar goes in as `Raw`.
//! let day = Raw(Some(Logical::Date), Physical::Int(Int::I32(19_000)));
//! let birthday = scheme.encrypt_with_context(day, "birthdays")?;
//! # let _ = (stored, birthday);
//! # Ok::<(), vitaminc_ore::OrderError<ore_rs::OreError>>(())
//! ```

use std::cmp::Ordering;
use std::convert::TryInto;

use vitaminc_hmac::{HmacSha256Prf, WeakKeyError};
use vitaminc_ore::{Context, OrderError, OrderKeyInit, OrderPlaintext, OrderScheme};
use vitaminc_prf::{BlockVisitor, Prf, PrfEncoding, PrfKeyInit};
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroizing;

use crate::scheme::bit2::OreAes128ChaCha20;
use crate::scheme::bit2_w6::OreAes128Bit6ChaCha20;
use crate::scheme::chained::OreAes128Bit6ChainedChaCha20;
use crate::{OreCipher, OreError, OreOutput};

/// The PRF domain the fixed-width scheme's two keys are derived under.
const BLOCK_ORE_KEYS: PrfEncoding = PrfEncoding::new("vitaminc/ore/block-ore/keys/v1");

/// The PRF domain the ORE v2 six-bit scheme's key is derived under.
const BIT6_KEYS: PrfEncoding = PrfEncoding::new("vitaminc/ore/block-ore-bit6/keys/v1");

/// The PRF domain the chained scheme's key is derived under.
const CHAINED_KEYS: PrfEncoding = PrfEncoding::new("vitaminc/ore/chained-block-ore/keys/v1");

/// Thirty-two bytes of key material for one term: the scheme key through
/// HMAC-SHA256 under `encoding` and the term's salt. Wiped on drop.
fn derive(
    prf: &HmacSha256Prf,
    encoding: PrfEncoding,
    salt: Context<'static>,
) -> Result<Zeroizing<[u8; 32]>, OrderError<OreError>> {
    prf.prf_bytes_vec(Protected::new(Vec::new()), encoding, salt, BlockVisitor)
        .into_result()
        .map(Zeroizing::new)
        // HMAC cannot fail once keyed; keep the refusal rather than a panic.
        .map_err(|_| OrderError::Backend(OreError::InitFailed))
}

/// The frozen fixed-width block ORE scheme as a vitaminc order scheme.
///
/// Takes every fixed-width plaintext of at most 15 bytes, at its own
/// width: an `i32` is four blocks, a decimal fourteen. Refuses text,
/// bytes and the 16-byte kinds as [`OrderError::Unsupported`].
///
/// The term keeps the whole serialised ciphertext, left and right halves,
/// and compares with the scheme's comparator. The right half carries a
/// random nonce, so one plaintext encrypts to different bytes each time,
/// and those terms compare equal.
pub struct BlockOre {
    prf: HmacSha256Prf,
}

/// A [`BlockOre`] term: the serialised ciphertext, compared by the
/// scheme's comparator rather than byte by byte.
#[derive(Debug, Clone)]
pub struct BlockOreTerm(Vec<u8>);

impl AsRef<[u8]> for BlockOreTerm {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Ord for BlockOreTerm {
    /// The scheme's comparison. Two terms of different widths come from
    /// different columns and have no order between them; they are ordered
    /// by width, then bytes, so the order is still total.
    fn cmp(&self, other: &Self) -> Ordering {
        OreAes128ChaCha20::compare_raw_slices(&self.0, &other.0).unwrap_or_else(|| {
            self.0
                .len()
                .cmp(&other.0.len())
                .then_with(|| self.0.cmp(&other.0))
        })
    }
}

impl PartialOrd for BlockOreTerm {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for BlockOreTerm {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for BlockOreTerm {}

impl BlockOre {
    /// The scheme keyed for one term.
    fn cipher(
        &self,
        plaintext: &OrderPlaintext,
        context: &Context<'_>,
    ) -> Result<OreAes128ChaCha20, OrderError<OreError>> {
        let material = derive(&self.prf, BLOCK_ORE_KEYS, self.salt(plaintext, context))?;
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
        context: &Context<'_>,
    ) -> Result<BlockOreTerm, OrderError<OreError>> {
        // The widths vitaminc's kinds have. Stable Rust cannot pick `N`
        // from a runtime value, so each is named; one above the block cap
        // (16) is refused with the variable-length kinds.
        let width = match plaintext.width() {
            Some(w @ (1 | 2 | 4 | 8 | 12 | 14)) => w,
            _ => return Err(OrderError::unsupported::<Self>(plaintext)),
        };
        let cipher = self.cipher(plaintext, context)?;
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
/// Takes every fixed-width plaintext of at most ten bytes (its fourteen
/// six-bit blocks), so the integers to 64 bits, both floats and dates.
/// Refuses timestamps (12 bytes), decimals (14), the 16-byte kinds, text
/// and bytes as [`OrderError::Unsupported`].
pub struct Bit6BlockOre {
    prf: HmacSha256Prf,
}

/// A [`Bit6BlockOre`] term: the serialised ciphertext, compared by the
/// scheme's comparator rather than byte by byte.
#[derive(Debug, Clone)]
pub struct Bit6BlockOreTerm(Vec<u8>);

impl AsRef<[u8]> for Bit6BlockOreTerm {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Ord for Bit6BlockOreTerm {
    /// The scheme's comparison. Two terms of different widths come from
    /// different columns and have no order between them; they are ordered
    /// by width, then bytes, so the order is still total.
    fn cmp(&self, other: &Self) -> Ordering {
        OreAes128Bit6ChaCha20::compare_raw_slices(&self.0, &other.0).unwrap_or_else(|| {
            self.0
                .len()
                .cmp(&other.0.len())
                .then_with(|| self.0.cmp(&other.0))
        })
    }
}

impl PartialOrd for Bit6BlockOreTerm {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Bit6BlockOreTerm {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Bit6BlockOreTerm {}

impl OrderScheme for Bit6BlockOre {
    const NAME: &'static str = "block-ore-bit6";
    type Term = Bit6BlockOreTerm;
    type Error = OreError;

    fn encrypt_plaintext(
        &self,
        plaintext: &OrderPlaintext,
        context: &Context<'_>,
    ) -> Result<Bit6BlockOreTerm, OrderError<OreError>> {
        match plaintext.width() {
            Some(1..=10) => {}
            _ => return Err(OrderError::unsupported::<Self>(plaintext)),
        }
        let material = derive(&self.prf, BIT6_KEYS, self.salt(plaintext, context))?;
        let mut k1 = Zeroizing::new([0u8; 16]);
        k1.copy_from_slice(&material[..16]);
        let cipher = OreAes128Bit6ChaCha20::init(&k1).map_err(OrderError::Backend)?;
        cipher
            .encrypt_bytes(plaintext.bytes().risky_ref())
            .map(Bit6BlockOreTerm)
            .map_err(OrderError::Backend)
    }
}

impl OrderKeyInit for Bit6BlockOre {
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

/// The chained, variable-length block ORE scheme as a vitaminc order
/// scheme: every kind, text and bytes included, at six bits per block.
///
/// Not yet frozen. A ciphertext reveals its plaintext's exact length, and
/// a comparison reveals the common-prefix length; see
/// [`crate::scheme::chained`].
pub struct ChainedBlockOre {
    prf: HmacSha256Prf,
}

/// A [`ChainedBlockOre`] term: the serialised ciphertext, compared by the
/// scheme's comparator.
#[derive(Debug, Clone)]
pub struct ChainedBlockOreTerm(Vec<u8>);

impl AsRef<[u8]> for ChainedBlockOreTerm {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Ord for ChainedBlockOreTerm {
    /// The scheme's comparison, which handles terms of any two lengths. A
    /// malformed term has no order; bytes order it so the order is total.
    fn cmp(&self, other: &Self) -> Ordering {
        OreAes128Bit6ChainedChaCha20::compare_raw_slices(&self.0, &other.0)
            .unwrap_or_else(|| self.0.cmp(&other.0))
    }
}

impl PartialOrd for ChainedBlockOreTerm {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ChainedBlockOreTerm {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for ChainedBlockOreTerm {}

impl OrderScheme for ChainedBlockOre {
    const NAME: &'static str = "chained-block-ore";
    type Term = ChainedBlockOreTerm;
    type Error = OreError;

    fn encrypt_plaintext(
        &self,
        plaintext: &OrderPlaintext,
        context: &Context<'_>,
    ) -> Result<ChainedBlockOreTerm, OrderError<OreError>> {
        let material = derive(&self.prf, CHAINED_KEYS, self.salt(plaintext, context))?;
        let mut k1 = Zeroizing::new([0u8; 16]);
        k1.copy_from_slice(&material[..16]);
        let cipher = OreAes128Bit6ChainedChaCha20::init(&k1).map_err(OrderError::Backend)?;
        let term = cipher
            .encrypt_bytes(plaintext.bytes().risky_ref())
            .map_err(OrderError::Backend)?;
        Ok(ChainedBlockOreTerm(term.to_bytes()))
    }
}

impl OrderKeyInit for ChainedBlockOre {
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

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_ore::{
        domain, order, Float, Int, IntoContext, Logical, NormalizeError, Physical, Raw, TimeUnit,
    };

    fn key() -> Protected<[u8; 32]> {
        Protected::new([7; 32])
    }

    fn no_context() -> Context<'static> {
        ().into_context().encode()
    }

    /// `a` below `b` under the scheme, and `a` twice compares equal.
    fn ordered<S: OrderScheme>(scheme: &S, ty: Option<Logical>, a: Physical<'_>, b: Physical<'_>) {
        let context = no_context();
        let (x, y) = (order(ty, a).unwrap(), order(ty, b).unwrap());
        let (left, right) = (
            scheme.encrypt_plaintext(&x, &context).unwrap(),
            scheme.encrypt_plaintext(&y, &context).unwrap(),
        );
        assert_eq!(left.cmp(&right), Ordering::Less, "{}", x.domain());
        assert_eq!(right.cmp(&left), Ordering::Greater, "{}", x.domain());
        assert_eq!(
            left.cmp(&scheme.encrypt_plaintext(&x, &context).unwrap()),
            Ordering::Equal,
            "{}",
            x.domain()
        );
    }

    #[test]
    fn block_ore_orders_every_fixed_width_kind_at_its_width() {
        use Physical::{Float as F, Int as I};
        let block = BlockOre::new(key());
        ordered(&block, None, I(Int::I8(-1)), I(Int::I8(1)));
        ordered(&block, None, I(Int::U8(0)), I(Int::U8(255)));
        ordered(&block, None, I(Int::I16(i16::MIN)), I(Int::I16(i16::MAX)));
        ordered(&block, None, I(Int::U16(0)), I(Int::U16(u16::MAX)));
        ordered(&block, None, I(Int::I32(i32::MIN)), I(Int::I32(i32::MAX)));
        ordered(&block, None, I(Int::U32(0)), I(Int::U32(u32::MAX)));
        ordered(&block, None, I(Int::I64(i64::MIN)), I(Int::I64(i64::MAX)));
        ordered(&block, None, I(Int::U64(0)), I(Int::U64(u64::MAX)));
        ordered(&block, None, F(Float::F32(-1.5)), F(Float::F32(f32::NAN)));
        ordered(
            &block,
            None,
            F(Float::F64(f64::NEG_INFINITY)),
            F(Float::F64(0.0)),
        );
        ordered(
            &block,
            Some(Logical::Date),
            I(Int::I32(-1)),
            I(Int::I32(19_000)),
        );
        ordered(
            &block,
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            I(Int::I64(-1)),
            I(Int::I64(0)),
        );
        ordered(
            &block,
            Some(Logical::Decimal { scale: 2 }),
            I(Int::I64(-150)),
            I(Int::I64(150)),
        );
        // One block per byte: the term is exactly the fixed-N ciphertext.
        let four = order(None, Physical::Int(Int::I32(1))).unwrap();
        let term = block.encrypt_plaintext(&four, &no_context()).unwrap();
        assert_eq!(
            term.as_ref().len(),
            <crate::CipherText<OreAes128ChaCha20, 4> as OreOutput>::size()
        );
    }

    #[test]
    fn block_ore_refuses_variable_length_and_sixteen_byte_kinds_by_name() {
        let block = BlockOre::new(key());
        let context = no_context();
        for (ty, v, domain) in [
            (None, Physical::Text("abcd"), domain::TEXT),
            (None, Physical::Bytes(&[1, 2, 3, 4][..]), domain::BYTES),
            (None, Physical::Int(Int::I128(1)), domain::INT128),
            (None, Physical::Int(Int::U128(1)), domain::UINT128),
            (
                Some(Logical::Uuid),
                Physical::Bytes(&[0; 16][..]),
                domain::UUID,
            ),
        ] {
            let plaintext = order(ty, v).unwrap();
            assert!(
                matches!(
                    block.encrypt_plaintext(&plaintext, &context),
                    Err(OrderError::Unsupported { scheme: "block-ore", domain: d }) if d == domain
                ),
                "{}",
                domain
            );
        }
    }

    #[test]
    fn chained_orders_every_kind_including_text_and_bytes() {
        use Physical::{Bytes, Int as I, Text};
        let chained = ChainedBlockOre::new(key());
        ordered(&chained, None, I(Int::I32(-7)), I(Int::I32(7)));
        ordered(
            &chained,
            None,
            I(Int::I128(i128::MIN)),
            I(Int::I128(i128::MAX)),
        );
        ordered(&chained, None, I(Int::U128(0)), I(Int::U128(u128::MAX)));
        ordered(
            &chained,
            Some(Logical::Uuid),
            Bytes(&[0; 16][..]),
            Bytes(&[1; 16][..]),
        );
        ordered(&chained, None, Text("apple"), Text("Banana"));
        ordered(&chained, None, Text("École"), Text("ecolf"));
        ordered(&chained, None, Bytes(&[][..]), Bytes(&[0][..]));
        ordered(&chained, None, Bytes(&[1][..]), Bytes(&[1, 0][..]));
        // Text that folds together is one term.
        let context = no_context();
        let (a, b) = (
            order(None, Text("Straße")).unwrap(),
            order(None, Text("strasse")).unwrap(),
        );
        assert_eq!(
            chained.encrypt_plaintext(&a, &context).unwrap(),
            chained.encrypt_plaintext(&b, &context).unwrap()
        );
    }

    #[test]
    fn terms_compare_only_within_one_scheme_key_domain_and_context() {
        let zero = Physical::Int(Int::I8(0));
        let tenant = |n: u64| ("tenant", n);
        let block = BlockOre::new(key());
        let under = |n: u64| {
            block
                .encrypt_with_context(Raw(None, zero), tenant(n))
                .unwrap()
        };
        assert_ne!(under(1), under(2));
        assert_ne!(
            under(1),
            BlockOre::new(Protected::new([8; 32]))
                .encrypt_with_context(Raw(None, zero), tenant(1))
                .unwrap()
        );
        // The same bytes under another domain: a different key, so not equal.
        let as_u8 = block
            .encrypt(Raw(None, Physical::Int(Int::U8(0x80))))
            .unwrap();
        let as_i8 = block.encrypt(Raw(None, zero)).unwrap();
        assert_eq!(
            order(None, zero).unwrap().bytes().risky_ref(),
            order(None, Physical::Int(Int::U8(0x80)))
                .unwrap()
                .bytes()
                .risky_ref()
        );
        assert_ne!(as_u8, as_i8);
        let chained = ChainedBlockOre::new(key());
        assert_ne!(
            chained
                .encrypt_with_context(Raw(None, zero), tenant(1))
                .unwrap(),
            chained
                .encrypt_with_context(Raw(None, zero), tenant(2))
                .unwrap()
        );
    }

    #[test]
    fn a_scheme_is_keyed_like_a_prf() {
        let from_bytes = BlockOre::try_from_bytes(Protected::new(vec![7; 32])).unwrap();
        let term = |s: &BlockOre| s.encrypt(Raw(None, Physical::Int(Int::I8(1)))).unwrap();
        assert_eq!(term(&from_bytes), term(&BlockOre::new(key())));
        assert!(BlockOre::try_from_bytes(Protected::new(vec![7; 8])).is_err());
        assert!(ChainedBlockOre::try_from_bytes(Protected::new(vec![7; 8])).is_err());
    }

    #[test]
    fn the_scalar_path_refuses_what_has_no_term() {
        let block = BlockOre::new(key());
        assert!(matches!(
            block.encrypt(Raw(None, Physical::Bool(true))),
            Err(OrderError::Term(NormalizeError::NoDomain))
        ));
    }

    #[test]
    fn a_term_of_another_width_still_orders_totally() {
        let block = BlockOre::new(key());
        let one = block.encrypt(Raw(None, Physical::Int(Int::I8(1)))).unwrap();
        let four = block
            .encrypt(Raw(None, Physical::Int(Int::I32(1))))
            .unwrap();
        assert_eq!(one.cmp(&four), Ordering::Less);
        assert_eq!(four.cmp(&one), Ordering::Greater);
    }

    #[test]
    fn bit6_orders_every_kind_up_to_ten_bytes_and_refuses_the_rest_by_name() {
        use Physical::{Float as F, Int as I};
        let bit6 = Bit6BlockOre::new(key());
        ordered(&bit6, None, I(Int::I8(-1)), I(Int::I8(1)));
        ordered(&bit6, None, I(Int::U16(0)), I(Int::U16(u16::MAX)));
        ordered(&bit6, None, I(Int::I32(i32::MIN)), I(Int::I32(i32::MAX)));
        ordered(&bit6, None, I(Int::I64(i64::MIN)), I(Int::I64(i64::MAX)));
        ordered(&bit6, None, I(Int::U64(0)), I(Int::U64(u64::MAX)));
        ordered(&bit6, None, F(Float::F32(-1.5)), F(Float::F32(f32::NAN)));
        ordered(
            &bit6,
            None,
            F(Float::F64(f64::NEG_INFINITY)),
            F(Float::F64(0.0)),
        );
        ordered(
            &bit6,
            Some(Logical::Date),
            I(Int::I32(-1)),
            I(Int::I32(19_000)),
        );
        let context = no_context();
        for (ty, v, domain) in [
            (
                Some(Logical::Timestamp(TimeUnit::Nanos)),
                Physical::Int(Int::I64(0)),
                domain::TIMESTAMP,
            ),
            (
                Some(Logical::Decimal { scale: 2 }),
                Physical::Int(Int::I64(150)),
                domain::DECIMAL,
            ),
            (None, Physical::Int(Int::I128(1)), domain::INT128),
            (None, Physical::Text("abcd"), domain::TEXT),
            (None, Physical::Bytes(&[1, 2][..]), domain::BYTES),
        ] {
            let plaintext = order(ty, v).unwrap();
            assert!(
                matches!(
                    bit6.encrypt_plaintext(&plaintext, &context),
                    Err(OrderError::Unsupported { scheme: "block-ore-bit6", domain: d }) if d == domain
                ),
                "{}",
                domain
            );
        }
        // Bound to key, context and domain like the other schemes.
        let zero = Physical::Int(Int::I8(0));
        assert_ne!(
            bit6.encrypt_with_context(Raw(None, zero), ("tenant", 1u64))
                .unwrap(),
            bit6.encrypt_with_context(Raw(None, zero), ("tenant", 2u64))
                .unwrap()
        );
        assert_ne!(
            bit6.encrypt(Raw(None, zero)).unwrap(),
            bit6.encrypt(Raw(None, Physical::Int(Int::U8(0x80))))
                .unwrap()
        );
        assert!(Bit6BlockOre::try_from_bytes(Protected::new(vec![7; 8])).is_err());
    }

    quickcheck! {
        fn bit6_order_is_integer_order(a: i64, b: i64) -> bool {
            let bit6 = Bit6BlockOre::new(key());
            let under = |v: i64| bit6.encrypt_with_context(Raw(None, Physical::Int(Int::I64(v))), "col").unwrap();
            under(a).cmp(&under(b)) == a.cmp(&b)
        }
    }

    quickcheck! {
        fn block_order_is_integer_order(a: i64, b: i64) -> bool {
            let block = BlockOre::new(key());
            let under = |v: i64| block.encrypt_with_context(Raw(None, Physical::Int(Int::I64(v))), "col").unwrap();
            under(a).cmp(&under(b)) == a.cmp(&b)
        }

        fn chained_order_is_byte_order(a: Vec<u8>, b: Vec<u8>) -> bool {
            let chained = ChainedBlockOre::new(key());
            let under = |v: &[u8]| chained.encrypt_with_context(Raw(None, Physical::Bytes(v)), "col").unwrap();
            under(&a).cmp(&under(&b)) == a.cmp(&b)
        }
    }
}
