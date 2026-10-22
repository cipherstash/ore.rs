//! [`BlockOre`]: block ORE as a vitaminc order scheme, and the routing of
//! each space to an engine.

use std::cmp::Ordering;
use std::num::NonZeroUsize;

use vitaminc_context::Context;
use vitaminc_hmac::{HmacSha256Prf, WeakKeyError};
use vitaminc_ore::{OrderKeyInit, OrderPlaintext, OrderQuery, OrderScheme, OrderTarget};
use vitaminc_prf::{BlockVisitor, Prf, PrfEncoding, PrfKeyInit};
use vitaminc_protected::Protected;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::ciphertext::parse_header;
use crate::scheme::bit2_w6::{OreAes128Bit6, MAX_BYTES};
use crate::scheme::chained::{Options, OreAes128Bit6Chained, Padding, DEFAULT_MAX_STR_BYTES};
use crate::{OreError, OreScheme, Query, Term};

/// The PRF domain the ORE key is derived under, once per scheme key.
pub const ORE_KEY: &str = "vitaminc/ore/block-ore/key/v2";

/// The 16-byte ORE key the scheme is keyed with: the scheme key through
/// HMAC-SHA256 under [`ORE_KEY`], with no salt. Made once, with the
/// scheme; each space's salt is bound afterwards by the engines. `None`
/// only if HMAC refused, which it cannot once keyed: the scheme then
/// refuses every space ([`OreError::InitFailed`]) rather than panic.
fn ore_key(prf: &HmacSha256Prf) -> Option<Zeroizing<[u8; 16]>> {
    let material = prf
        .prf_bytes_vec(
            Protected::new(Vec::new()),
            PrfEncoding::new(ORE_KEY),
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

/// Block ORE as a vitaminc order scheme, the typed front door: every
/// target, routed to the engine its width wants when a space is opened.
///
/// vitaminc decides the encoding of every kind of value and seals it as an
/// [`OrderPlaintext`] that only it can build, so a scheme here is never
/// handed bytes that skipped the encoding. A caller opens a space on
/// [`BlockOre`] with a target and a context, encrypts values there, and
/// compares terms and queries through the space; it never names an engine.
///
/// One scheme, two engines. [`BlockOre`] routes a space to an engine by
/// its target's width, once, when the space is opened:
///
/// - up to ten bytes, the packed-prefix Bit6 engine
///   ([`OreAes128Bit6`]): the integers to 64 bits, `f64` and dates;
/// - wider, or of no fixed width, the chained engine
///   ([`OreAes128Bit6Chained`]): 128-bit integers, uuids, timestamps,
///   decimals, text and bytes.
///
/// Every term carries its engine in its wire header, so a comparison
/// dispatches on the bytes and refuses a pair from two engines, which no
/// space produces. The legacy scheme has no adapter: it is for stored data,
/// and the README says not to put new data on it.
///
/// **Keys.** [`OrderKeyInit`] keys the scheme from a 32-byte key, from
/// which one 16-byte ORE key is derived with HMAC-SHA256 under
/// [`ORE_KEY`] when the scheme is made. Each space is then keyed from that
/// key under the salt vitaminc derives, `PAE("vitaminc/ore/v1",
/// "block-ore", domain, context)`, through the engines' own salt stage, so
/// two targets or two contexts never share key material.
///
/// **Padding.** Text is padded under the scheme's policy
/// ([`BlockOre::with_text_padding`], [`Padding::default`] unless set), so a
/// text term reveals a length bucket, and text that ends in NUL is refused
/// ([`OreError::TrailingNul`]). Bytes are never padded, since NUL padding
/// would refuse every value that ends in a zero byte, so a bytes term
/// reveals the exact length. Fixed-width targets have nothing to hide.
/// Text and bytes are refused past the scheme's ceiling
/// ([`BlockOre::with_max_bytes`], [`DEFAULT_MAX_STR_BYTES`] unless set),
/// which counts the marker byte vitaminc puts before them.
///
/// A term is the serialised ciphertext, left and right halves; a query is
/// the left half alone. Both are compared by the scheme, never byte by
/// byte: a term carries a random nonce, so one value has many terms,
/// which compare `Equal`.
///
/// # Examples
///
/// ```
/// use std::cmp::Ordering;
/// use ore_rs::BlockOre;
/// use vitaminc_ore::target::{I32, Text};
/// use vitaminc_ore::{OrderEncrypt, OrderKeyInit};
/// use vitaminc_protected::Protected;
/// # let key_bytes = [7u8; 32];
///
/// let scheme = BlockOre::new(Protected::new(key_bytes));
///
/// // A space of `i32`s under one context, keyed once for all its terms.
/// let quantity = scheme.target(I32).context(("orders", "quantity"));
/// let stored = quantity.encrypt(42i16)?;
/// let query = quantity.encrypt_query(41i16)?;
/// assert_eq!(quantity.compare_query(&query, &stored), Some(Ordering::Less));
/// let bytes: &[u8] = stored.as_ref();
///
/// // Text goes to the chained engine; the caller does not choose.
/// let names = scheme.target(Text).context("names");
/// let alice = names.encrypt_checked("alice")?;
/// let bob = names.encrypt_checked("bob")?;
/// assert_eq!(names.compare(&alice, &bob), Some(Ordering::Less));
/// # let _ = bytes;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct BlockOre {
    key: Option<Zeroizing<[u8; 16]>>,
    text_padding: Padding,
    max_bytes: NonZeroUsize,
}

impl BlockOre {
    /// The padding policy of every `Text` space this scheme opens;
    /// [`Padding::default`] unless set. Stored terms and the queries that
    /// compare with them must share a policy, so set it once, with the
    /// key.
    pub fn with_text_padding(mut self, padding: Padding) -> Self {
        self.text_padding = padding;
        self
    }

    /// The longest text or bytes value, in bytes, every space of this
    /// scheme encrypts, counting the marker byte vitaminc puts before it;
    /// [`DEFAULT_MAX_STR_BYTES`] unless set. A longer one is refused
    /// ([`OreError::TooLong`]). Fixed-width spaces are not bounded by it.
    ///
    /// The ceiling must be one the chained engine accepts: no longer than
    /// the space's padding can pad within the wire format's limit, [`MAX_STR_BYTES`](crate::scheme::chained::MAX_STR_BYTES)
    /// (49151 bytes). A `Bytes` space is unpadded, so it takes any ceiling
    /// from 1 to 49151. A `Text` space pads the ceiling under
    /// [`Self::with_text_padding`]. Under [`Padding::PowerOfTwo`], the
    /// default, the longest is 32768 (or the floor, if that is higher),
    /// since a longer value would pad to 65536 bytes. Under
    /// [`Padding::Fixed`] the lower of the ceiling and the fixed length
    /// applies, so any ceiling opens while the fixed length is itself
    /// within the wire format's limit. Outside that range a `Text`
    /// or `Bytes` space fails to open ([`OreError::InitFailed`]), and so
    /// does every encryption in it; the scheme does not check the ceiling
    /// when it is set.
    pub fn with_max_bytes(mut self, max_bytes: NonZeroUsize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// The padding policy of this scheme's text spaces.
    pub fn text_padding(&self) -> Padding {
        self.text_padding
    }

    /// The ceiling on text and bytes values.
    pub fn max_bytes(&self) -> NonZeroUsize {
        self.max_bytes
    }

    /// The ORE key, or the refusal [`ore_key`] stands for.
    fn key(&self) -> Result<Protected<[u8; 16]>, OreError> {
        self.key
            .as_deref()
            .map(|key| Protected::new(*key))
            .ok_or(OreError::InitFailed)
    }
}

// Opaque Debug: never render key material.
impl std::fmt::Debug for BlockOre {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockOre")
            .field("text_padding", &self.text_padding)
            .field("max_bytes", &self.max_bytes)
            .finish_non_exhaustive()
    }
}

/// What [`BlockOre`] keeps for one space: the engine the space's target
/// wants, keyed under the space's salt, and the target, so a plaintext of
/// another is refused. `Send + Sync`, so a space is shared across threads
/// as it is. Wiped on drop: each engine wipes its keys.
pub struct BlockOreSpace {
    engine: Engine,
    target: OrderTarget,
}

enum Engine {
    // Boxed: an engine holds AES key schedules and a nonce generator, and
    // a space is opened once, so the pointer costs nothing per term.
    Bit6(Box<OreAes128Bit6>),
    Chained(Box<OreAes128Bit6Chained>),
}

// Dropping a space drops its boxed engine, which wipes its own keys. The
// derive cannot see through the `Box`, so the match below names every
// engine instead: one added without `ZeroizeOnDrop` does not compile.
impl ZeroizeOnDrop for BlockOreSpace {}

#[allow(dead_code)]
fn engines_wipe_on_drop(engine: &Engine) {
    fn wipes<T: ZeroizeOnDrop>(_: &T) {}
    match engine {
        Engine::Bit6(e) => wipes(&**e),
        Engine::Chained(e) => wipes(&**e),
    }
}

impl std::fmt::Debug for BlockOreSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let engine = match &self.engine {
            Engine::Bit6(_) => "Bit6",
            Engine::Chained(_) => "Chained",
        };
        f.debug_struct("BlockOreSpace")
            .field("engine", &engine)
            .field("target", &self.target)
            .finish()
    }
}

impl BlockOreSpace {
    /// [`OreError::TargetMismatch`] unless `plaintext` was encoded as the
    /// space's target. Without it, text handed to a `U128` space would be
    /// padded under that space's defaults, not the scheme's policy.
    fn check_target(&self, plaintext: &OrderPlaintext) -> Result<(), OreError> {
        if plaintext.target() == self.target {
            Ok(())
        } else {
            Err(OreError::TargetMismatch)
        }
    }
}

/// Which engine a target's terms are made by: Bit6 for a fixed width of
/// up to [`MAX_BYTES`], chained for the rest.
fn engine_for(target: OrderTarget) -> EngineKind {
    match target.width() {
        Some(width) if width <= MAX_BYTES => EngineKind::Bit6,
        _ => EngineKind::Chained,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EngineKind {
    Bit6,
    Chained,
}

/// The engine a serialised term or query was made by, from its wire
/// header. `None` for bytes with no v2 header, the legacy scheme's
/// included.
fn engine_of(bytes: &[u8]) -> Option<EngineKind> {
    let ((version, scheme_id, _), _) = parse_header(bytes).ok()?;
    if version != crate::scheme::bit2_w6::WIRE.version {
        return None;
    }
    if scheme_id == crate::scheme::bit2_w6::WIRE.scheme_id {
        Some(EngineKind::Bit6)
    } else if scheme_id == crate::scheme::chained::SCHEME_ID {
        Some(EngineKind::Chained)
    } else {
        None
    }
}

impl OrderScheme for BlockOre {
    const NAME: &'static str = "block-ore";
    type Term = Term;
    type Error = OreError;
    type Space = BlockOreSpace;

    /// Key the engine the target's width wants under `salt`. A `Bytes`
    /// space never pads, and a `Text` space pads under the scheme's
    /// policy, as does any other target of no fixed width, so one vitaminc
    /// adds later cannot reveal its exact length. All of them keep the
    /// scheme's ceiling, and fail to open ([`OreError::InitFailed`]) under
    /// a ceiling the chained engine refuses (see
    /// [`BlockOre::with_max_bytes`]). A fixed-width space on the chained
    /// engine takes neither the padding nor the ceiling, so no setting of
    /// either keeps it from opening.
    fn open(&self, target: OrderTarget, salt: &Context<'_>) -> Result<BlockOreSpace, OreError> {
        let key = self.key()?;
        let engine = match engine_for(target) {
            EngineKind::Bit6 => Engine::Bit6(Box::new(OreAes128Bit6::init_with_salt(key, salt)?)),
            EngineKind::Chained => {
                let options = match target {
                    OrderTarget::Bytes => Options::default()
                        .with_salt(salt)
                        .with_padding(Padding::None)
                        .with_max_bytes(self.max_bytes),
                    // A fixed width: the engine goes in unpadded with no
                    // ceiling, so the defaults are only there to pass
                    // the engine's own check.
                    target if target.width().is_some() => Options::default().with_salt(salt),
                    // Text, and any target of no fixed width.
                    _ => Options::default()
                        .with_salt(salt)
                        .with_padding(self.text_padding)
                        .with_max_bytes(self.max_bytes),
                };
                Engine::Chained(Box::new(OreAes128Bit6Chained::init_with(key, options)?))
            }
        };
        Ok(BlockOreSpace { engine, target })
    }

    /// A plaintext of another target than the space's is refused
    /// ([`OreError::TargetMismatch`]): the space's engine is keyed and
    /// configured for its own target alone. [`vitaminc_ore::OrderSpace`]
    /// never hands one over; a direct call can.
    fn encrypt_plaintext(
        &self,
        space: &BlockOreSpace,
        plaintext: &OrderPlaintext,
    ) -> Result<Term, OreError> {
        space.check_target(plaintext)?;
        match &space.engine {
            Engine::Bit6(engine) => engine.encrypt_plaintext(plaintext),
            Engine::Chained(engine) => engine.encrypt_plaintext(plaintext),
        }
    }

    /// The engine's comparison, chosen by the terms' wire headers. `None`
    /// for a term that is not a well-formed v2 ciphertext, or two terms
    /// of different engines, which no space makes. Two well-formed terms
    /// of different targets or contexts under one engine compare as
    /// noise, which the scheme cannot tell; a space keeps its terms
    /// together.
    fn compare(a: &Term, b: &Term) -> Option<Ordering> {
        match (engine_of(a.as_bytes()), engine_of(b.as_bytes())) {
            (Some(EngineKind::Bit6), Some(EngineKind::Bit6)) => {
                OreAes128Bit6::compare_raw_slices(a.as_bytes(), b.as_bytes())
            }
            (Some(EngineKind::Chained), Some(EngineKind::Chained)) => {
                OreAes128Bit6Chained::compare_raw_slices(a.as_bytes(), b.as_bytes())
            }
            _ => None,
        }
    }
}

impl OrderQuery for BlockOre {
    type Query = Query;

    /// Refuses a plaintext of another target, as
    /// [`OrderScheme::encrypt_plaintext`] does.
    fn encrypt_query(
        &self,
        space: &BlockOreSpace,
        plaintext: &OrderPlaintext,
    ) -> Result<Query, OreError> {
        space.check_target(plaintext)?;
        match &space.engine {
            Engine::Bit6(engine) => engine.encrypt_query_plaintext(plaintext),
            Engine::Chained(engine) => engine.encrypt_query_plaintext(plaintext),
        }
    }

    /// The order of the queried value against the stored one, through the
    /// engine the two wire headers name; `None` as [`OrderScheme::compare`]
    /// is `None`.
    fn compare_query(query: &Query, term: &Term) -> Option<Ordering> {
        match (engine_of(query.as_bytes()), engine_of(term.as_bytes())) {
            (Some(EngineKind::Bit6), Some(EngineKind::Bit6)) => {
                OreAes128Bit6::compare_left_to_full(query.as_bytes(), term.as_bytes())
            }
            (Some(EngineKind::Chained), Some(EngineKind::Chained)) => {
                OreAes128Bit6Chained::compare_left_to_full(query.as_bytes(), term.as_bytes())
            }
            _ => None,
        }
    }
}

vitaminc_ore::supports_every_target!(BlockOre);

impl OrderKeyInit for BlockOre {
    type Key = Protected<[u8; 32]>;
    type KeyError = WeakKeyError;

    fn new(key: Self::Key) -> Self {
        Self {
            key: ore_key(&HmacSha256Prf::new(key)),
            text_padding: Padding::default(),
            max_bytes: DEFAULT_MAX_STR_BYTES,
        }
    }

    fn try_from_bytes(key: Protected<Vec<u8>>) -> Result<Self, WeakKeyError> {
        Ok(Self {
            key: ore_key(&HmacSha256Prf::try_from_bytes(key)?),
            text_padding: Padding::default(),
            max_bytes: DEFAULT_MAX_STR_BYTES,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::chained::MAX_STR_BYTES;
    use crate::scheme::decompose::num_blocks_6bit;
    use crate::testing::{ceiling, fixed_padding, salt, text_pt, u128_pt, u64_pt};
    use vitaminc_ore::target::{Bytes, Date, Decimal, Text, I32, I64, U128};
    use vitaminc_ore::{test_support, OrderEncrypt, OrderError, OrderTerm, QueryTerm};

    use OrderTarget as T;

    fn key() -> Protected<[u8; 32]> {
        Protected::new([7; 32])
    }

    fn other_key() -> Protected<[u8; 32]> {
        Protected::new([8; 32])
    }

    fn scheme() -> BlockOre {
        BlockOre::new(key())
    }

    /// The engine named by a term's or query's header.
    fn engine(bytes: &[u8]) -> EngineKind {
        engine_of(bytes).expect("a v2 header")
    }

    /// The checks vitaminc-ore asks of a real scheme: every target it
    /// takes orders, keys and salts separate, nothing is empty, and the
    /// query side agrees with the term side.
    #[test]
    fn the_scheme_keeps_the_order_scheme_contract() {
        test_support::conformance(&scheme(), &BlockOre::new(other_key()));
        test_support::query_conformance(&scheme(), &BlockOre::new(other_key()));
        test_support::static_target::<BlockOre, I32>();
        test_support::static_target::<BlockOre, Text>();
        test_support::static_target::<BlockOre, U128>();
    }

    /// A space's target picks the engine, by width: up to ten bytes is
    /// Bit6, the rest chained. The caller never names one.
    #[test]
    fn spaces_are_routed_to_an_engine_by_width() {
        let s = scheme();
        let bit6 = [
            T::I16,
            T::U16,
            T::I32,
            T::U32,
            T::I64,
            T::U64,
            T::F64,
            T::Date,
        ];
        let chained = [
            T::I128,
            T::U128,
            T::Uuid,
            T::Timestamp,
            T::Decimal,
            T::Text,
            T::Bytes,
        ];
        for t in bit6 {
            assert_eq!(engine_for(t), EngineKind::Bit6, "{t:?}");
            s.target(t).context("c").open().expect("block ore");
        }
        for t in chained {
            assert_eq!(engine_for(t), EngineKind::Chained, "{t:?}");
            s.target(t).context("c").open().expect("block ore");
        }
        for t in OrderTarget::ALL {
            assert!(
                bit6.contains(t) || chained.contains(t),
                "{:?} is unrouted",
                t
            );
        }

        let i64s = s.target(I64).context("c");
        let term = i64s.encrypt(42i64).expect("block ore");
        assert_eq!(engine(term.as_bytes()), EngineKind::Bit6);
        assert_eq!(term.as_bytes().len(), 295);
        let query = i64s.encrypt_query(42i64).expect("block ore");
        assert_eq!(engine(query.as_bytes()), EngineKind::Bit6);

        let wide = s.target(U128).context("c");
        let term = wide.encrypt(42u128).expect("block ore");
        assert_eq!(engine(term.as_bytes()), EngineKind::Chained);
        assert_eq!(term.as_bytes().len(), 7 + 25 * 22 + 16);
    }

    /// Terms compare within a space as the values do, through both
    /// comparators, and a query is deterministic where a term is not.
    #[test]
    fn terms_and_queries_compare_within_a_space() {
        let s = scheme();
        let prices = s.target(Decimal).context(("orders", "total"));
        let values = [
            rust_decimal::Decimal::MIN,
            rust_decimal::Decimal::new(-150, 2),
            rust_decimal::Decimal::ZERO,
            rust_decimal::Decimal::new(150, 2),
            rust_decimal::Decimal::MAX,
        ];
        let terms: Vec<OrderTerm<Term, Decimal>> = values
            .iter()
            .map(|v| prices.encrypt(*v).expect("block ore"))
            .collect();
        let queries: Vec<QueryTerm<Query, Decimal>> = values
            .iter()
            .map(|v| prices.encrypt_query(*v).expect("block ore"))
            .collect();
        for (i, a) in terms.iter().enumerate() {
            for (j, b) in terms.iter().enumerate() {
                assert_eq!(prices.compare(a, b), Some(i.cmp(&j)), "{i} vs {j}");
                assert_eq!(
                    prices.compare_query(&queries[i], b),
                    Some(i.cmp(&j)),
                    "query {i} vs {j}"
                );
            }
            assert_eq!(
                queries[i],
                prices.encrypt_query(values[i]).expect("block ore")
            );
            assert_ne!(
                a.as_bytes(),
                prices.encrypt(values[i]).expect("block ore").as_bytes()
            );
        }

        let dates = s.target(Date).context("d");
        let day = |d: i32| chrono::NaiveDate::from_num_days_from_ce_opt(d).expect("a date");
        let (a, b) = (
            dates.encrypt(day(19_000)).expect("block ore"),
            dates.encrypt(day(19_001)).expect("block ore"),
        );
        assert_eq!(dates.compare(&a, &b), Some(Ordering::Less));
    }

    /// A comparison dispatches on the wire header: two engines' terms
    /// never meet, and bytes with no v2 header are not terms at all.
    #[test]
    fn comparisons_dispatch_on_the_header_and_refuse_a_mix() {
        let s = scheme();
        let narrow = s
            .target(T::I64)
            .context("c")
            .encrypt_checked(1i64)
            .expect("block ore");
        let wide = s
            .target(T::U128)
            .context("c")
            .encrypt_checked(1u128)
            .expect("block ore");
        let narrow_query = s
            .target(T::I64)
            .context("c")
            .encrypt_query_checked(1i64)
            .expect("block ore");
        assert_eq!(BlockOre::compare(narrow.raw(), wide.raw()), None);
        assert_eq!(BlockOre::compare(wide.raw(), narrow.raw()), None);
        assert_eq!(
            BlockOre::compare_query(narrow_query.raw(), wide.raw()),
            None
        );
        assert_eq!(
            BlockOre::compare(narrow.raw(), narrow.raw()),
            Some(Ordering::Equal)
        );
        assert_eq!(
            BlockOre::compare_query(narrow_query.raw(), narrow.raw()),
            Some(Ordering::Equal)
        );
        let headerless = Term::from_bytes(vec![0u8; 16]);
        assert_eq!(BlockOre::compare(&headerless, narrow.raw()), None);
        assert_eq!(BlockOre::compare(narrow.raw(), &headerless), None);
        let mut other_version = narrow.raw().clone().into_bytes();
        other_version[0] = 0x03;
        assert_eq!(
            BlockOre::compare(&Term::from_bytes(other_version), narrow.raw()),
            None
        );
    }

    /// Text is padded under the scheme's policy and bytes are not, and
    /// both are refused past the ceiling, which counts vitaminc's marker.
    #[test]
    fn text_is_padded_and_bytes_are_not() {
        let s = scheme();
        let text = s.target(Text).context("c");
        let bytes = s.target(Bytes).context("c");
        let text_len = |v: &str| text.encrypt_checked(v).expect("block ore").as_bytes().len();
        let bytes_len = |v: &[u8]| bytes.encrypt(v).expect("block ore").as_bytes().len();
        let chained_len = |n: usize| 7 + 25 * num_blocks_6bit(n) + 16;
        // Text: the 16-byte floor, then powers of two, counting the marker.
        assert_eq!(text_len(""), chained_len(16));
        assert_eq!(text_len("alice"), chained_len(16));
        assert_eq!(text_len(&"a".repeat(15)), chained_len(16));
        assert_eq!(text_len(&"a".repeat(16)), chained_len(32));
        // Bytes: the exact length, marker included; a trailing NUL is fine.
        assert_eq!(bytes_len(b""), chained_len(1));
        assert_eq!(bytes_len(b"alice"), chained_len(6));
        assert!(bytes.encrypt(&b"x\0"[..]).is_ok());
        assert!(matches!(
            text.encrypt_checked("x\0"),
            Err(OrderError::Backend(OreError::TrailingNul))
        ));

        let unpadded = BlockOre::new(key()).with_text_padding(Padding::None);
        assert_eq!(unpadded.text_padding(), Padding::None);
        let text = unpadded.target(Text).context("c");
        assert_eq!(
            text.encrypt_checked("alice")
                .expect("block ore")
                .as_bytes()
                .len(),
            chained_len(6)
        );

        let small = BlockOre::new(key()).with_max_bytes(ceiling(8));
        assert_eq!(small.max_bytes().get(), 8);
        let text = small.target(Text).context("c");
        let bytes = small.target(Bytes).context("c");
        assert!(text.encrypt_checked("1234567").is_ok());
        assert!(matches!(
            text.encrypt_checked("12345678"),
            Err(OrderError::Backend(OreError::TooLong))
        ));
        assert!(bytes.encrypt(&[0u8; 7][..]).is_ok());
        assert!(matches!(
            bytes.encrypt(&[0u8; 8][..]),
            Err(OreError::TooLong)
        ));
        // Fixed-width spaces are not subject to the ceiling.
        assert!(small.target(U128).context("c").encrypt(u128::MAX).is_ok());
    }

    /// A ceiling the chained engine refuses closes the text and bytes
    /// spaces, with the documented error, and no fixed-width space: those
    /// take no ceiling.
    #[test]
    fn a_ceiling_out_of_range_closes_only_text_and_bytes_spaces() {
        for max in [MAX_STR_BYTES + 1, 60000] {
            let s = BlockOre::new(key()).with_max_bytes(ceiling(max));
            for t in [T::U128, T::I128, T::Uuid, T::Timestamp, T::Decimal] {
                if let Err(e) = s.target(t).context("c").open() {
                    panic!("{:?} under {}: {:?}", t, max, e);
                }
            }
            assert!(s.target(U128).context("c").encrypt(u128::MAX).is_ok());
            for t in [T::Text, T::Bytes] {
                assert!(
                    matches!(s.target(t).context("c").open(), Err(OreError::InitFailed)),
                    "{:?} under {}",
                    t,
                    max
                );
            }
        }
        // The edges the docs give: unpadded bytes take up to 49151, text
        // under the default padding up to 32768.
        let s = BlockOre::new(key()).with_max_bytes(ceiling(MAX_STR_BYTES));
        s.target(Bytes)
            .context("c")
            .open()
            .expect("bytes at the wire limit");
        assert!(matches!(
            s.target(Text).context("c").open(),
            Err(OreError::InitFailed)
        ));
        let s = BlockOre::new(key()).with_max_bytes(ceiling(32768));
        s.target(Text).context("c").open().expect("text at 32768");
        let s = BlockOre::new(key()).with_max_bytes(ceiling(32769));
        assert!(matches!(
            s.target(Text).context("c").open(),
            Err(OreError::InitFailed)
        ));
    }

    /// The text padding goes to `Text` spaces alone: a policy the chained
    /// engine refuses closes the text space and nothing else, and a fixed
    /// length bounds text under a ceiling no other policy could pad.
    #[test]
    fn the_text_padding_closes_only_text_spaces() {
        let s = BlockOre::new(key()).with_text_padding(Padding::PowerOfTwo {
            min_bytes: u16::MAX,
        });
        assert!(matches!(
            s.target(Text).context("c").open(),
            Err(OreError::InitFailed)
        ));
        for t in [
            T::Bytes,
            T::U128,
            T::I128,
            T::Uuid,
            T::Timestamp,
            T::Decimal,
        ] {
            if let Err(e) = s.target(t).context("c").open() {
                panic!("{:?} under an unpaddable text policy: {:?}", t, e);
            }
        }

        let s = BlockOre::new(key())
            .with_text_padding(fixed_padding(8))
            .with_max_bytes(ceiling(60000));
        let text = s.target(Text).context("c");
        assert!(text.encrypt_checked("1234567").is_ok());
        assert!(matches!(
            text.encrypt_checked("12345678"),
            Err(OrderError::Backend(OreError::ExceedsPadding))
        ));
    }

    /// A space refuses a plaintext of another target, so a direct trait
    /// call cannot put text through a `U128` space's defaults. vitaminc's
    /// own spaces never hand one over.
    #[test]
    fn a_space_refuses_a_plaintext_of_another_target() {
        let s = BlockOre::new(key()).with_text_padding(fixed_padding(64));
        let ctx = salt(b"c");
        let wide = OrderScheme::open(&s, T::U128, &ctx).unwrap();
        let narrow = OrderScheme::open(&s, T::I64, &ctx).unwrap();
        let text = OrderScheme::open(&s, T::Text, &ctx).unwrap();
        for space in [&wide, &narrow] {
            assert!(matches!(
                s.encrypt_plaintext(space, &text_pt("alice")),
                Err(OreError::TargetMismatch)
            ));
            assert!(matches!(
                s.encrypt_query(space, &text_pt("alice")),
                Err(OreError::TargetMismatch)
            ));
        }
        assert!(matches!(
            s.encrypt_plaintext(&text, &u128_pt(5)),
            Err(OreError::TargetMismatch)
        ));
        assert!(matches!(
            s.encrypt_plaintext(&narrow, &u64_pt(5)),
            Err(OreError::TargetMismatch)
        ));
        assert!(s.encrypt_plaintext(&wide, &u128_pt(5)).is_ok());
        assert!(s.encrypt_query(&wide, &u128_pt(5)).is_ok());
        assert!(s.encrypt_plaintext(&text, &text_pt("alice")).is_ok());
    }

    /// The default ceiling is 1024 bytes with the marker, so 1023 of value.
    #[test]
    fn text_and_bytes_are_refused_past_1023_bytes() {
        let s = scheme();
        let text = s.target(Text).context("c");
        let bytes = s.target(Bytes).context("c");
        assert!(text.encrypt_checked("a".repeat(1023).as_str()).is_ok());
        assert!(matches!(
            text.encrypt_checked("a".repeat(1024).as_str()),
            Err(OrderError::Backend(OreError::TooLong))
        ));
        assert!(bytes.encrypt(&vec![1u8; 1023][..]).is_ok());
        assert!(matches!(
            bytes.encrypt(&vec![1u8; 1024][..]),
            Err(OreError::TooLong)
        ));
    }

    /// Terms of two spaces never compare `Equal`: another target, another
    /// context or another key is another salt, through the engines' own
    /// salt stage.
    #[test]
    fn terms_compare_only_within_one_scheme_key_target_and_context() {
        let s = scheme();
        let a = s
            .target(T::I32)
            .context("c")
            .encrypt_checked(1i32)
            .expect("block ore");
        let other_target = s
            .target(T::U32)
            .context("c")
            .encrypt_checked(1u32)
            .expect("block ore");
        let other_context = s
            .target(T::I32)
            .context("d")
            .encrypt_checked(1i32)
            .expect("block ore");
        let other_key = BlockOre::new(other_key())
            .target(T::I32)
            .context("c")
            .encrypt_checked(1i32)
            .expect("block ore");
        for other in [&other_target, &other_context, &other_key] {
            assert_ne!(
                BlockOre::compare(a.raw(), other.raw()),
                Some(Ordering::Equal)
            );
        }
        let same = s
            .target(T::I32)
            .context("c")
            .encrypt_checked(1i32)
            .expect("block ore");
        assert_eq!(
            BlockOre::compare(a.raw(), same.raw()),
            Some(Ordering::Equal)
        );
    }

    /// The bytes of a query under a fixed key and context are pinned, so
    /// the key derivation (HMAC under [`ORE_KEY`], then the engines' salt
    /// stage under the space's salt) cannot drift without this failing.
    #[test]
    fn queries_under_a_fixed_key_are_pinned() {
        let s = scheme();
        let narrow = s
            .target(I32)
            .context("pinned")
            .encrypt_query(1i32)
            .expect("block ore");
        let wide = s
            .target(U128)
            .context("pinned")
            .encrypt_query(1u128)
            .expect("block ore");
        assert_eq!(hex::encode(narrow.as_bytes()), PINNED_BIT6_QUERY);
        assert_eq!(hex::encode(wide.as_bytes()), PINNED_CHAINED_QUERY);
    }

    const PINNED_BIT6_QUERY: &str = "0202000634253e3a0f361d11a1e27e55c72c1525ac3ffe1a36a3bbb1bb643141e98603df6b5a25da12f46901b6b637bb7aed66d4d4a76be3ce72496bc48fa83d17112c74f7a61caa32d176ae7eeb5471898519f199ae79a74418ca5b9717455df9637516f3fe3a60b4de";
    const PINNED_CHAINED_QUERY: &str = "0203001600000033112033270b3037360909143b3315002330121f171068031d6c3431c9e1c1daf685de3fb173bb12f9c71ea7c9f565e9cb85fc2cc3646b890ce0b376aba6a79411da2b86ca300c8b4ba04b50c8740751b104772292236a5dc099d4fe537cadcdc048d70da884a4220976c3337777023933f38b33280b9ca99619da619597f5ee558913b5a1ce3a02a91c2c550c2488c6ba9ac71017bb1598978b2a991d82bbfeed0155b8fc616cf7f4c58a191b85d42d74383089ae8a9a2d930ca7495b3c8b9c4282e01cbacbbe98aa38d6ade89c6288479cf2ae0ecfd1abda089bf13b91b3506967dc6b4b2acdf366442f8c3c39df57b1a1be6745a445c79c24a71a2a7a175e06d2f67e375b08b6f5c854d132cc954d447dc6abfd05da818a58fa1852b8fc936633aced31052f4caf9a5373d238f7ba3fd6f38d147caaab184ffb50dc125d447e1ca3153321eb76ec4e6414e6e3ec566a2992add3ee02f5d0a68123b708c25fe675521ea600188475076ff3de8effb700c603df81b7";

    /// A short key is refused as a PRF refuses it; a scheme that could not
    /// derive its key refuses every space rather than panic.
    #[test]
    fn a_scheme_is_keyed_like_a_prf() {
        assert!(BlockOre::try_from_bytes(Protected::new(vec![7u8; 8])).is_err());
        let from_bytes = BlockOre::try_from_bytes(Protected::new(vec![7u8; 32])).expect("32 bytes");
        let a = scheme()
            .target(I32)
            .context("c")
            .encrypt_query(1i32)
            .expect("block ore");
        let b = from_bytes
            .target(I32)
            .context("c")
            .encrypt_query(1i32)
            .expect("block ore");
        assert_eq!(a, b, "the same key material keys the same scheme");

        let keyless = BlockOre {
            key: None,
            text_padding: Padding::default(),
            max_bytes: DEFAULT_MAX_STR_BYTES,
        };
        assert!(matches!(
            keyless.target(I32).context("c").open(),
            Err(OreError::InitFailed)
        ));
        assert!(matches!(
            keyless.target(I32).context("c").encrypt(1i32),
            Err(OreError::InitFailed)
        ));
    }

    /// A space is `Send + Sync` and opens its engine once; the scheme and
    /// its space never show key material.
    #[test]
    fn a_space_is_shared_across_threads_and_debugs_without_the_key() {
        fn is_send_sync<X: Send + Sync>(_: &X) {}
        let s = scheme();
        is_send_sync(&s);
        let space = s.target(I64).context("c");
        is_send_sync(&space);
        space.open().expect("block ore");
        let shared = &space;
        let terms: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4i64)
                .map(|i| scope.spawn(move || shared.encrypt(i).expect("block ore")))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("a thread"))
                .collect()
        });
        for pair in terms.windows(2) {
            assert_eq!(space.compare(&pair[0], &pair[1]), Some(Ordering::Less));
        }
        let shown = format!("{s:?} {space:?}");
        assert!(!shown.contains("key"), "{}", shown);
        assert!(shown.contains("BlockOre"), "{}", shown);
    }

    /// A value with no order term as the space's target is refused by
    /// vitaminc before the scheme sees it.
    #[test]
    fn a_value_with_no_term_is_refused() {
        let s = scheme();
        assert!(matches!(
            s.target(T::I32).context("c").encrypt_checked(true),
            Err(OrderError::Term(_))
        ));
        assert!(matches!(
            s.target(Date).context("c").encrypt_checked("not a date"),
            Err(OrderError::Term(_))
        ));
    }
}
