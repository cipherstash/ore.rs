//! [`ClwwOre`] and [`ClwwOpe`]: CLWW ORE and OPE as vitaminc order schemes
//! (see the crate docs for their use). A sealed [`OrderPlaintext`] is
//! encrypted as it is, one plaintext bit to one term byte.
//!
//! The salt the space hands the scheme, `PAE("vitaminc/ore/v1", NAME,
//! domain, context)`, goes in as the CLWW salt, so a term compares only
//! within its own space. Text and bytes come from vitaminc behind its
//! variable-width marker, so no plaintext is empty and every term runs the
//! keyed PRF at least once.
//!
//! A CLWW term is its own query, so [`OrderQuery`] is implemented with
//! `Query = Term`.

use std::cmp::Ordering;

use vitaminc_ore::{Context, OrderKeyInit, OrderPlaintext, OrderQuery, OrderScheme, OrderTarget};
use vitaminc_protected::{Controlled, Protected};

use crate::impls::{encrypt_ope_bytes, encrypt_ore_bytes};
use crate::{Error, Key, OpeClww8VariableV1, OreClww8VariableV1};

/// Why key material of a length only known at runtime was refused: a CLWW
/// key is exactly thirty-two bytes.
#[derive(Debug, thiserror::Error)]
#[error("a CLWW key is thirty-two bytes, not {0}")]
pub struct KeyLengthError(pub usize);

/// The key from a protected array. `[u8; 32]` is `Copy`: [`Key::from`]
/// wipes the copy it is handed, and the `Protected` wipes the original when
/// it drops here.
fn key_from(key: Protected<[u8; 32]>) -> Key {
    Key::from(*key.risky_ref())
}

/// The key from bytes of a length only known at runtime.
fn key_try_from(key: Protected<Vec<u8>>) -> Result<Key, KeyLengthError> {
    let bytes: &[u8; 32] = key
        .risky_ref()
        .as_slice()
        .try_into()
        .map_err(|_| KeyLengthError(key.risky_ref().len()))?;
    Ok(Key::from(*bytes))
}

/// The salt's bytes, which is all a CLWW scheme keeps for a space: the PRF
/// takes the salt directly, so there is nothing to derive.
fn open_space(salt: &Context<'_>) -> Protected<Vec<u8>> {
    Protected::new(salt.as_bytes().to_vec())
}

/// Whether `bytes` could be an ORE term of these schemes: one byte per
/// plaintext bit over at least one whole byte, since no plaintext vitaminc
/// seals is empty.
fn is_ore_term(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.len().is_multiple_of(8)
}

/// Whether `bytes` could be an OPE term of these schemes: a leading carry
/// of 0 or 1, then one byte per plaintext bit over at least one whole byte.
fn is_ope_term(bytes: &[u8]) -> bool {
    bytes.len() > 1 && bytes.len() % 8 == 1 && bytes[0] <= 1
}

/// CLWW order-revealing encryption as a vitaminc order scheme: one
/// ciphertext byte per plaintext bit, compared by the scheme's own
/// comparator, never byte by byte.
///
/// A `Text` or `Bytes` term shows the exact length of its value, with no
/// padding and no length limit (see the [crate docs](crate)).
///
/// # Examples
///
/// ```
/// use std::cmp::Ordering;
/// use clww_ore::{ClwwOpe, ClwwOre};
/// use vitaminc_ore::target::{Text, I32};
/// use vitaminc_ore::{OrderEncrypt, OrderKeyInit};
/// use vitaminc_protected::Protected;
/// # let key_bytes = [7u8; 32];
///
/// // ORE: terms compare with the scheme's comparator.
/// let ore = ClwwOre::new(Protected::new(key_bytes));
/// let names = ore.target(Text).context(("users", "name"));
/// let (a, b) = (names.encrypt_checked("apple")?, names.encrypt_checked("Banana")?);
/// assert_eq!(names.compare(&a, &b), Some(Ordering::Less));
///
/// // OPE: terms compare in plain byte order, so the database needs no
/// // comparator of its own.
/// let ope = ClwwOpe::new(Protected::new(key_bytes));
/// let quantity = ope.target(I32).context(("orders", "quantity"));
/// let (a, b) = (quantity.encrypt(41i8)?, quantity.encrypt(42i16)?);
/// assert!(a.as_ref() < b.as_ref());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct ClwwOre {
    key: Key,
}

impl std::fmt::Debug for ClwwOre {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClwwOre").finish_non_exhaustive()
    }
}

impl OrderScheme for ClwwOre {
    const NAME: &'static str = "clww-ore";
    type Term = OreClww8VariableV1;
    type Error = Error;
    type Space = Protected<Vec<u8>>;

    /// Every target's sealed bytes are encrypted as they are, so the target
    /// is not needed here.
    fn open(&self, _: OrderTarget, salt: &Context<'_>) -> Result<Self::Space, Error> {
        Ok(open_space(salt))
    }

    fn encrypt_plaintext(
        &self,
        space: &Self::Space,
        plaintext: &OrderPlaintext,
    ) -> Result<OreClww8VariableV1, Error> {
        encrypt_ore_bytes(
            plaintext.bytes().risky_ref(),
            &self.key,
            Some(space.risky_ref()),
        )
    }

    /// The scheme's comparison. `None` for bytes no term of these schemes
    /// has (empty, or not a whole number of plaintext bytes), and for two
    /// terms whose first difference is not the ±1 by which two terms of one
    /// space differ: the comparator then gives the same answer in both
    /// directions, so the two answers disagree. Two well-formed terms of
    /// different spaces can still compare as noise, which the scheme cannot
    /// tell; a caller keeps a space's terms together.
    fn compare(a: &OreClww8VariableV1, b: &OreClww8VariableV1) -> Option<Ordering> {
        if !is_ore_term(a.as_ref()) || !is_ore_term(b.as_ref()) {
            return None;
        }
        let forward = a.cmp(b);
        (forward == b.cmp(a).reverse()).then_some(forward)
    }
}

impl OrderQuery for ClwwOre {
    type Query = OreClww8VariableV1;

    /// A CLWW term is its own query.
    fn encrypt_query(
        &self,
        space: &Self::Space,
        plaintext: &OrderPlaintext,
    ) -> Result<OreClww8VariableV1, Error> {
        self.encrypt_plaintext(space, plaintext)
    }

    fn compare_query(query: &OreClww8VariableV1, term: &OreClww8VariableV1) -> Option<Ordering> {
        Self::compare(query, term)
    }
}

vitaminc_ore::supports_every_target!(ClwwOre);

impl OrderKeyInit for ClwwOre {
    type Key = Protected<[u8; 32]>;
    type KeyError = KeyLengthError;

    fn new(key: Self::Key) -> Self {
        Self { key: key_from(key) }
    }

    fn try_from_bytes(key: Protected<Vec<u8>>) -> Result<Self, KeyLengthError> {
        Ok(Self {
            key: key_try_from(key)?,
        })
    }
}

/// CLWW order-preserving encryption as a vitaminc order scheme: the terms
/// compare in plain byte order, so a database needs no comparator of its
/// own. Encrypt-only.
///
/// A `Text` or `Bytes` term shows the exact length of its value, with no
/// padding and no length limit (see [`ClwwOre`] for an example).
pub struct ClwwOpe {
    key: Key,
}

impl std::fmt::Debug for ClwwOpe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClwwOpe").finish_non_exhaustive()
    }
}

impl OrderScheme for ClwwOpe {
    const NAME: &'static str = "clww-ope";
    type Term = OpeClww8VariableV1;
    type Error = Error;
    type Space = Protected<Vec<u8>>;

    /// Every target's sealed bytes are encrypted as they are, so the target
    /// is not needed here.
    fn open(&self, _: OrderTarget, salt: &Context<'_>) -> Result<Self::Space, Error> {
        Ok(open_space(salt))
    }

    fn encrypt_plaintext(
        &self,
        space: &Self::Space,
        plaintext: &OrderPlaintext,
    ) -> Result<OpeClww8VariableV1, Error> {
        encrypt_ope_bytes(
            plaintext.bytes().risky_ref(),
            &self.key,
            Some(space.risky_ref()),
        )
    }

    /// Byte order, which is the terms' order. `None` for bytes no term of
    /// these schemes has: a length other than `8n + 1` for `n` of at least
    /// one, or a leading carry other than 0 or 1. Two well-formed terms of
    /// different spaces compare as noise, which the scheme cannot tell; a
    /// caller keeps a space's terms together.
    fn compare(a: &OpeClww8VariableV1, b: &OpeClww8VariableV1) -> Option<Ordering> {
        if !is_ope_term(a.as_ref()) || !is_ope_term(b.as_ref()) {
            return None;
        }
        Some(a.as_ref().cmp(b.as_ref()))
    }
}

impl OrderQuery for ClwwOpe {
    type Query = OpeClww8VariableV1;

    /// A CLWW term is its own query.
    fn encrypt_query(
        &self,
        space: &Self::Space,
        plaintext: &OrderPlaintext,
    ) -> Result<OpeClww8VariableV1, Error> {
        self.encrypt_plaintext(space, plaintext)
    }

    fn compare_query(query: &OpeClww8VariableV1, term: &OpeClww8VariableV1) -> Option<Ordering> {
        Self::compare(query, term)
    }
}

vitaminc_ore::supports_every_target!(ClwwOpe);

impl OrderKeyInit for ClwwOpe {
    type Key = Protected<[u8; 32]>;
    type KeyError = KeyLengthError;

    fn new(key: Self::Key) -> Self {
        Self { key: key_from(key) }
    }

    fn try_from_bytes(key: Protected<Vec<u8>>) -> Result<Self, KeyLengthError> {
        Ok(Self {
            key: key_try_from(key)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_ore::target::{Bytes, Text, I32, U128, U16};
    use vitaminc_ore::{
        order, test_support, Float, Int, Logical, NormalizeError, OrderEncrypt, OrderError,
        Physical, Raw, TimeUnit,
    };

    use OrderTarget as T;

    fn key() -> Protected<[u8; 32]> {
        Protected::new([7; 32])
    }

    fn other_key() -> Protected<[u8; 32]> {
        Protected::new([8; 32])
    }

    #[test]
    fn both_schemes_meet_vitaminc_contract() {
        test_support::conformance(&ClwwOre::new(key()), &ClwwOre::new(other_key()));
        test_support::query_conformance(&ClwwOre::new(key()), &ClwwOre::new(other_key()));
        test_support::conformance(&ClwwOpe::new(key()), &ClwwOpe::new(other_key()));
        test_support::query_conformance(&ClwwOpe::new(key()), &ClwwOpe::new(other_key()));
        test_support::static_target::<ClwwOre, I32>();
        test_support::static_target::<ClwwOre, Text>();
        test_support::static_target::<ClwwOre, U128>();
        test_support::static_target::<ClwwOpe, Bytes>();
    }

    /// `a` below `b` in a `target` space under both schemes, and a term is
    /// deterministic.
    fn ordered(target: OrderTarget, ty: Option<Logical>, a: Physical<'_>, b: Physical<'_>) {
        let (x, y) = (order(target, ty, a).unwrap(), order(target, ty, b).unwrap());
        let ore = ClwwOre::new(key());
        let space = ore.target(target);
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
        assert_eq!(left, space.encrypt_term(&x).unwrap());
        let ope = ClwwOpe::new(key());
        let space = ope.target(target);
        let (left, right) = (
            space.encrypt_term(&x).unwrap(),
            space.encrypt_term(&y).unwrap(),
        );
        assert!(
            left.as_ref() < right.as_ref(),
            "{}: OPE is plain byte order",
            x.domain()
        );
        assert_eq!(left, space.encrypt_term(&x).unwrap());
    }

    #[test]
    fn every_target_orders_under_both_schemes() {
        use Physical::{Bytes, Float as F, Int as I, Text};
        ordered(T::I16, None, I(Int::I16(-1)), I(Int::I16(1)));
        ordered(T::U64, None, I(Int::U64(0)), I(Int::U64(u64::MAX)));
        ordered(
            T::I128,
            None,
            I(Int::I128(i128::MIN)),
            I(Int::I128(i128::MAX)),
        );
        ordered(T::F64, None, F(Float::F64(-1.5)), F(Float::F64(f64::NAN)));
        ordered(
            T::F64,
            None,
            F(Float::F64(f64::NEG_INFINITY)),
            F(Float::F64(0.0)),
        );
        ordered(T::Text, None, Text("apple"), Text("Banana"));
        ordered(T::Text, None, Text(""), Text("a"));
        ordered(T::Text, None, Text("a"), Text("a\0"));
        ordered(T::Bytes, None, Bytes(&[]), Bytes(&[0]));
        ordered(
            T::Date,
            Some(Logical::Date),
            I(Int::I32(-1)),
            I(Int::I32(19_000)),
        );
        ordered(
            T::Timestamp,
            Some(Logical::Timestamp(TimeUnit::Micros)),
            I(Int::I64(-1)),
            I(Int::I64(0)),
        );
        ordered(
            T::Decimal,
            Some(Logical::Decimal { scale: 2 }),
            I(Int::I64(-150)),
            I(Int::I64(150)),
        );
        ordered(
            T::Uuid,
            Some(Logical::Uuid),
            Bytes(&[0; 16]),
            Bytes(&[1; 16]),
        );
    }

    /// A JavaScript host hands each BigInt over at the narrowest width that
    /// holds it; in one space they all become the space's width and compare.
    #[test]
    fn narrowest_width_integers_compare_in_one_space() {
        let ope = ClwwOpe::new(key());
        let space = ope.target(T::I32).context(("orders", "total"));
        let terms = [
            space
                .encrypt_checked(Raw(None, Physical::Int(Int::I16(100))))
                .unwrap(),
            space
                .encrypt_checked(Raw(None, Physical::Int(Int::U16(200))))
                .unwrap(),
            space
                .encrypt_checked(Raw(None, Physical::Int(Int::I32(300))))
                .unwrap(),
        ];
        assert!(terms[0].as_ref() < terms[1].as_ref());
        assert!(terms[1].as_ref() < terms[2].as_ref());
        assert!(matches!(
            space.encrypt_checked(1i64 << 40),
            Err(OrderError::Term(NormalizeError::OutOfRange))
        ));
    }

    #[test]
    fn text_that_folds_together_is_one_term() {
        let ore = ClwwOre::new(key());
        let names = ore.target(Text);
        assert_eq!(
            names.encrypt_checked("École").unwrap().as_ref(),
            names.encrypt_checked("ecole").unwrap().as_ref()
        );
    }

    /// The stored format: a plaintext's sealed bytes, as vitaminc encodes
    /// them, encrypted as they are under the space's salt.
    #[test]
    fn a_term_is_the_byte_slice_encryption_of_the_sealed_bytes() {
        let ore = ClwwOre::new(key());
        let space = ore.target(T::Bytes).context("col");
        let plaintext = order(T::Bytes, None, Physical::Bytes(&[0xAB])).unwrap();
        let direct = encrypt_ore_bytes(
            plaintext.bytes().risky_ref(),
            &key_from(key()),
            Some(space.salt().as_bytes()),
        )
        .unwrap();
        assert_eq!(space.encrypt_term(&plaintext).unwrap().raw(), &direct);
        let ope = ClwwOpe::new(key());
        let space = ope.target(T::Text).context("col");
        let plaintext = order(T::Text, None, Physical::Text("a")).unwrap();
        let direct = encrypt_ope_bytes(
            plaintext.bytes().risky_ref(),
            &key_from(key()),
            Some(space.salt().as_bytes()),
        )
        .unwrap();
        assert_eq!(space.encrypt_term(&plaintext).unwrap().raw(), &direct);
    }

    /// ORE and OPE terms of one value in one context are bound under
    /// different salts, since each scheme's name is in its salt, as well as
    /// drawing from different keystreams.
    #[test]
    fn ore_and_ope_terms_of_one_value_differ() {
        let (ore, ope) = (ClwwOre::new(key()), ClwwOpe::new(key()));
        let ore_term = ore.target(I32).encrypt(7i32).unwrap();
        let ope_term = ope.target(I32).encrypt(7i32).unwrap();
        assert_ne!(ore_term.as_ref(), &ope_term.as_ref()[1..]);
    }

    #[test]
    fn a_scheme_is_keyed_from_exactly_thirty_two_bytes() {
        let from_bytes = ClwwOre::try_from_bytes(Protected::new(vec![7; 32])).unwrap();
        let term = |s: &ClwwOre| s.target(I32).encrypt(1i32).unwrap();
        assert_eq!(term(&from_bytes), term(&ClwwOre::new(key())));
        let short = ClwwOre::try_from_bytes(Protected::new(vec![7; 16]))
            .err()
            .unwrap();
        assert_eq!(short.0, 16);
    }

    #[test]
    fn an_ope_scheme_is_keyed_from_exactly_thirty_two_bytes() {
        let from_bytes = ClwwOpe::try_from_bytes(Protected::new(vec![7; 32])).unwrap();
        let term = |s: &ClwwOpe| s.target(I32).encrypt(1i32).unwrap();
        assert_eq!(term(&from_bytes), term(&ClwwOpe::new(key())));
        for len in [0, 31, 33] {
            let refused = ClwwOpe::try_from_bytes(Protected::new(vec![7; len]))
                .err()
                .unwrap();
            assert_eq!(refused.0, len);
        }
    }

    /// Terms made through a vitaminc space under a fixed key and context.
    /// Every stored term depends on the scheme's `NAME`, vitaminc's salt
    /// label and its encodings (the marker byte, text folding, the null
    /// policy), so a change to any of them fails here.
    const ORE_I32: &str = "a0ba9bc03546e23843a84858a147fccafae65d9bc5daa24c09bbedbd78189948";
    const ORE_TEXT: &str = "edf1f47c1896380675fb75b5d2a059bfac833f3cedaab5dd7e8a5a4eee05bc8ff9303f75c02514b2a3705c0116702e11";
    const OPE_I32: &str = "0102a4549fd1e81a592023d178662df56730d15c970fdc4110870db086de19db1a";
    const OPE_TEXT: &str = "001a24a73753b3ce1355f3a5236070172b416b8f42046920c1f4dffb2cd51d17e43b894fd12e8a90a174da169e8b7aee69";
    const OPE_I32_NULLS: &str =
        "008eca5455932e0ac4f238110aa3052544b44a62cf304457709cc8f5f28e03dc4a";

    #[test]
    fn terms_under_a_fixed_key_are_pinned() {
        let (ore, ope) = (ClwwOre::new(key()), ClwwOpe::new(key()));
        let ore_int = ore.target(I32).context(("t", "c")).encrypt(42i32).unwrap();
        let ore_text = ore
            .target(Text)
            .context(("t", "c"))
            .encrypt_checked("École")
            .unwrap();
        let ope_int = ope.target(I32).context(("t", "c")).encrypt(42i32).unwrap();
        let ope_text = ope
            .target(Text)
            .context(("t", "c"))
            .encrypt_checked("École")
            .unwrap();
        let ope_nulls = ope
            .target(I32)
            .context(("t", "c"))
            .nulls(vitaminc_ore::target::Last)
            .encrypt_checked(42i32)
            .unwrap();
        for (name, term, expected) in [
            ("ore i32", hex::encode(ore_int.as_ref()), ORE_I32),
            ("ore text", hex::encode(ore_text.as_ref()), ORE_TEXT),
            ("ope i32", hex::encode(ope_int.as_ref()), OPE_I32),
            ("ope text", hex::encode(ope_text.as_ref()), OPE_TEXT),
            (
                "ope i32 nulls",
                hex::encode(ope_nulls.as_ref()),
                OPE_I32_NULLS,
            ),
        ] {
            assert_eq!(term, expected, "{name}");
        }
    }

    /// Bytes no term of these schemes has, and two terms whose first
    /// difference no space produces, do not compare.
    #[test]
    fn malformed_terms_do_not_compare() {
        let ore_term = |b: Vec<u8>| OreClww8VariableV1::from_bytes_unchecked(b);
        let valid = ClwwOre::new(key()).target(I32).encrypt(1i32).unwrap();
        let valid = valid.raw();
        assert_eq!(ClwwOre::compare(valid, valid), Some(Ordering::Equal));
        for bad in [vec![], vec![0; 7], vec![0; 9]] {
            assert_eq!(
                ClwwOre::compare(&ore_term(bad.clone()), valid),
                None,
                "{bad:?}"
            );
            assert_eq!(ClwwOre::compare(valid, &ore_term(bad)), None);
        }
        // A first difference of 2: each direction alone answers `Less`.
        let (x, y) = (ore_term(vec![0; 8]), ore_term(vec![2; 8]));
        assert_eq!(x.cmp(&y), y.cmp(&x));
        assert_eq!(ClwwOre::compare(&x, &y), None);
        assert_eq!(ClwwOre::compare(&y, &x), None);
        // A difference of 1 either way is the one a space produces.
        let z = ore_term(vec![1; 8]);
        assert_eq!(ClwwOre::compare(&x, &z), Some(Ordering::Less));
        assert_eq!(ClwwOre::compare(&z, &x), Some(Ordering::Greater));

        let ope_term = |b: Vec<u8>| OpeClww8VariableV1::from_bytes_unchecked(b);
        let valid = ClwwOpe::new(key()).target(I32).encrypt(1i32).unwrap();
        let valid = valid.raw();
        assert_eq!(ClwwOpe::compare(valid, valid), Some(Ordering::Equal));
        let mut carry_two = vec![0; 9];
        carry_two[0] = 2;
        for bad in [
            vec![],
            vec![0],
            vec![0; 8],
            vec![0; 10],
            carry_two,
            vec![2; 9],
        ] {
            assert_eq!(
                ClwwOpe::compare(&ope_term(bad.clone()), valid),
                None,
                "{bad:?}"
            );
            assert_eq!(ClwwOpe::compare(valid, &ope_term(bad)), None);
        }
        let mut carry_one = vec![0; 9];
        carry_one[0] = 1;
        assert_eq!(
            ClwwOpe::compare(&ope_term(vec![0; 9]), &ope_term(carry_one)),
            Some(Ordering::Less)
        );
    }

    quickcheck::quickcheck! {
        fn order_is_byte_order(a: Vec<u8>, b: Vec<u8>) -> bool {
            let a: Vec<u8> = a.into_iter().take(32).collect();
            let b: Vec<u8> = b.into_iter().take(32).collect();
            let (ore, ope) = (ClwwOre::new(key()), ClwwOpe::new(key()));
            let (ore, ope) = (ore.target(Bytes).context("col"), ope.target(Bytes).context("col"));
            let under_ore = |v: &[u8]| ore.encrypt_checked(Raw(None, Physical::Bytes(v))).unwrap();
            let under_ope = |v: &[u8]| ope.encrypt_checked(Raw(None, Physical::Bytes(v))).unwrap();
            ore.compare(&under_ore(&a), &under_ore(&b)) == Some(a.cmp(&b))
                && ope.compare(&under_ope(&a), &under_ope(&b)) == Some(a.cmp(&b))
        }
    }

    /// The backward-carry encoding with the bit at the top of its byte gives
    /// exact OPE: byte order on the terms always agrees with the plaintext
    /// order (see `docs/backward-carry-ope.md`). Checked exhaustively on every
    /// adjacent `u16` pair under twenty keys, the worst case for the older
    /// `+1` variant, which had a residual error rate of about 7.7e-6 per
    /// pair. Slow, so run with `cargo test --release -- --ignored`.
    #[test]
    #[ignore = "exhaustive exactness check — slow; run with `cargo test --release -- --ignored`"]
    fn ope_exactness_adjacent_u16() {
        let mut errors = 0u64;
        for key_seed in 0..20u64 {
            let mut key_bytes = [0u8; 32];
            key_bytes[..8].copy_from_slice(&key_seed.to_le_bytes());
            let scheme = ClwwOpe::new(Protected::new(key_bytes));
            let space = scheme.target(U16).context("exactness");
            let mut prev = space.encrypt(0u16).unwrap();
            for x in 1..=u16::MAX {
                let next = space.encrypt(x).unwrap();
                if prev.as_ref() >= next.as_ref() {
                    errors += 1;
                }
                prev = next;
            }
        }
        assert_eq!(errors, 0, "exact OPE violated on {errors} adjacent pairs");
    }
}
