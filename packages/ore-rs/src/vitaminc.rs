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
//! None of the schemes takes a salt, so each derives its keys for every
//! term from its own key with HMAC-SHA256 under the salt the column hands
//! it, `PAE("vitaminc/ore/v1", scheme, domain, context)`. Two columns, two
//! targets or two contexts therefore never share a key, and a term
//! compares only within its own column.
//!
//! # Examples
//!
//! ```
//! use ore_rs::vitaminc::Bit6BlockOre;
//! use vitaminc_ore::{Int, Logical, OrderEncrypt, OrderKeyInit, OrderTarget, Physical, Raw};
//! use vitaminc_protected::Protected;
//! # let key_bytes = [7u8; 32];
//!
//! // Key the scheme; `try_from_bytes` takes material of runtime length.
//! let scheme = Bit6BlockOre::new(Protected::new(key_bytes));
//!
//! // A column of `i32`s: four bytes, six blocks, whatever width a value
//! // arrives at. The caller never sees the encoding.
//! let quantity = scheme.column(OrderTarget::I32, ("orders", "quantity"));
//! let term = quantity.encrypt(42i64)?;
//! assert!(quantity.encrypt(41i8)? < term);
//! let stored: &[u8] = term.as_ref();
//!
//! // A typed scalar goes into a column of its type.
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

/// The PRF domain the ORE v2 six-bit scheme's key is derived under.
const BIT6_KEYS: PrfEncoding = PrfEncoding::new("vitaminc/ore/block-ore-bit6/keys/v1");

/// The PRF domain the chained scheme's key is derived under.
const CHAINED_KEYS: PrfEncoding = PrfEncoding::new("vitaminc/ore/chained-block-ore/keys/v1");

/// Thirty-two bytes of key material for one term: the scheme key through
/// HMAC-SHA256 under `encoding` and the term's salt. Wiped on drop.
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
/// `i32` column is four blocks, a decimal fourteen. Refuses text,
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
    /// The scheme's comparison. A column has one target, so its terms have
    /// one width; two terms of different widths come from different
    /// columns and have no order between them, so they are ordered by
    /// width, then bytes, to keep the order total.
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
    /// The scheme's comparison. A column has one target, so its terms have
    /// one width; two terms of different widths come from different
    /// columns and have no order between them, so they are ordered by
    /// width, then bytes, to keep the order total.
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
        salt: &Context<'_>,
    ) -> Result<Bit6BlockOreTerm, OrderError<OreError>> {
        match plaintext.width() {
            Some(1..=10) => {}
            _ => return Err(OrderError::unsupported::<Self>(plaintext)),
        }
        let material = derive(&self.prf, BIT6_KEYS, salt)?;
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
/// scheme: every target, text and bytes included, at six bits per block.
///
/// Not yet frozen. Text is padded under the default policy
/// ([`Padding::default`]), so a text ciphertext reveals the length bucket,
/// and text that ends in NUL is refused ([`OreError::TrailingNul`]).
/// Bytes are not padded, since padding would refuse every value that ends
/// in a zero byte, so a bytes ciphertext reveals the exact length. Nor are
/// fixed-width targets, whose length is the target's and public already.
/// A comparison reveals the common-prefix length; see
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
        salt: &Context<'_>,
    ) -> Result<ChainedBlockOreTerm, OrderError<OreError>> {
        let material = derive(&self.prf, CHAINED_KEYS, salt)?;
        let mut k1 = Zeroizing::new([0u8; 16]);
        k1.copy_from_slice(&material[..16]);
        // Every term of a column shares its target, so the policy is the
        // same for all of them, and terms made under different policies
        // never meet in a comparison.
        let options = match plaintext.target() {
            OrderTarget::Text => Options::default(),
            _ => Options::default().with_padding(Padding::None),
        };
        let cipher =
            OreAes128Bit6ChainedChaCha20::init_with(&k1, options).map_err(OrderError::Backend)?;
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
        domain, order, Float, Int, Logical, NormalizeError, OrderEncrypt, OrderTarget, Physical,
        Raw, TimeUnit,
    };

    use OrderTarget as T;

    fn key() -> Protected<[u8; 32]> {
        Protected::new([7; 32])
    }

    /// `a` below `b` in a `target` column, and `a` twice compares equal.
    fn ordered<S: OrderScheme>(
        scheme: &S,
        target: OrderTarget,
        ty: Option<Logical>,
        a: Physical<'_>,
        b: Physical<'_>,
    ) {
        let column = scheme.column(target, ());
        let (x, y) = (order(target, ty, a).unwrap(), order(target, ty, b).unwrap());
        let (left, right) = (
            column.encrypt_term(&x).unwrap(),
            column.encrypt_term(&y).unwrap(),
        );
        assert_eq!(left.cmp(&right), Ordering::Less, "{}", x.domain());
        assert_eq!(right.cmp(&left), Ordering::Greater, "{}", x.domain());
        assert_eq!(
            left.cmp(&column.encrypt_term(&x).unwrap()),
            Ordering::Equal,
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
        // One block per byte of the target: an `i32` column's term is the
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
            names.encrypt("Straße").unwrap(),
            names.encrypt("strasse").unwrap()
        );
    }

    /// The JavaScript host hands each BigInt over at the narrowest width
    /// that holds it. In one column they all become the column's width, so
    /// fixed-width block ORE compares them.
    #[test]
    fn narrowest_width_integers_compare_in_one_fixed_width_column() {
        let bit6 = Bit6BlockOre::new(key());
        let column = bit6.column(T::I32, ("orders", "total"));
        let (hundred, two_hundred, three_hundred) = (
            column
                .encrypt(Raw(None, Physical::Int(Int::I8(100))))
                .unwrap(),
            column
                .encrypt(Raw(None, Physical::Int(Int::U8(200))))
                .unwrap(),
            column
                .encrypt(Raw(None, Physical::Int(Int::I16(300))))
                .unwrap(),
        );
        assert!(hundred < two_hundred && two_hundred < three_hundred);
        assert_eq!(
            hundred,
            column
                .encrypt(Raw(None, Physical::Int(Int::U64(100))))
                .unwrap()
        );
        // A value the column cannot hold is refused before the scheme.
        assert!(matches!(
            column.encrypt(1i64 << 40),
            Err(OrderError::Term(NormalizeError::OutOfRange))
        ));
    }

    #[test]
    fn terms_compare_only_within_one_scheme_key_target_and_context() {
        let tenant = |n: u64| ("tenant", n);
        let block = BlockOre::new(key());
        let under = |n: u64| block.column(T::I8, tenant(n)).encrypt(0i8).unwrap();
        assert_ne!(under(1), under(2));
        assert_ne!(
            under(1),
            BlockOre::new(Protected::new([8; 32]))
                .column(T::I8, tenant(1))
                .encrypt(0i8)
                .unwrap()
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
        assert_ne!(as_u8, as_i8);
        let chained = ChainedBlockOre::new(key());
        assert_ne!(
            chained.column(T::I8, tenant(1)).encrypt(0i8).unwrap(),
            chained.column(T::I8, tenant(2)).encrypt(0i8).unwrap()
        );
    }

    #[test]
    fn a_scheme_is_keyed_like_a_prf() {
        let from_bytes = BlockOre::try_from_bytes(Protected::new(vec![7; 32])).unwrap();
        let term = |s: &BlockOre| s.column(T::I8, ()).encrypt(1i8).unwrap();
        assert_eq!(term(&from_bytes), term(&BlockOre::new(key())));
        assert!(BlockOre::try_from_bytes(Protected::new(vec![7; 8])).is_err());
        assert!(ChainedBlockOre::try_from_bytes(Protected::new(vec![7; 8])).is_err());
    }

    #[test]
    fn the_column_refuses_what_has_no_term() {
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
    fn terms_of_two_widths_still_order_totally() {
        let block = BlockOre::new(key());
        let one = block.column(T::I8, ()).encrypt(1i8).unwrap();
        let four = block.column(T::I32, ()).encrypt(1i8).unwrap();
        assert_eq!(one.cmp(&four), Ordering::Less);
        assert_eq!(four.cmp(&one), Ordering::Greater);
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
            bit6.column(T::I8, ("tenant", 1u64)).encrypt(0i8).unwrap(),
            bit6.column(T::I8, ("tenant", 2u64)).encrypt(0i8).unwrap()
        );
        assert_ne!(
            bit6.column(T::I8, ()).encrypt(0i8).unwrap(),
            bit6.column(T::U8, ()).encrypt(0x80i16).unwrap()
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
            under(&[1]).cmp(&under(&[1, 0])),
            Ordering::Less,
            "a trailing zero byte is kept"
        );
    }

    quickcheck! {
        fn bit6_order_is_integer_order(a: i64, b: i32) -> bool {
            let bit6 = Bit6BlockOre::new(key());
            let column = bit6.column(T::I64, "col");
            column.encrypt(a).unwrap().cmp(&column.encrypt(b).unwrap()) == a.cmp(&i64::from(b))
        }
    }

    quickcheck! {
        fn block_order_is_integer_order(a: i64, b: i64) -> bool {
            let block = BlockOre::new(key());
            let column = block.column(T::I64, "col");
            column.encrypt(a).unwrap().cmp(&column.encrypt(b).unwrap()) == a.cmp(&b)
        }

        fn chained_order_is_byte_order(a: Vec<u8>, b: Vec<u8>) -> bool {
            let chained = ChainedBlockOre::new(key());
            let column = chained.column(T::Bytes, "col");
            let under = |v: &[u8]| column.encrypt(Raw(None, Physical::Bytes(v))).unwrap();
            under(&a).cmp(&under(&b)) == a.cmp(&b)
        }
    }
}
