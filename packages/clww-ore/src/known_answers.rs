//! Known-answer digests for every encrypt path.
//!
//! Stored ORE and OPE terms are built on this crate's output, and the order
//! and round-trip tests elsewhere pass for a changed encoding just as well.
//! These pin the bytes: a BLAKE3 digest of each type's ciphertexts, unsalted
//! and salted, under a fixed key. The digests were recorded from the code as
//! it came over from cipherstash-suite (`cllw-ore` 0.5.1), so a change here
//! is a change to every stored term.

use crate::{encrypt_ope_bits, encrypt_ore_bits, ClwwOpeEncrypt, ClwwOreEncrypt, Key};

const SALT: &[u8] = b"clww-ore/known-answers";

fn key() -> Key {
    Key::from(core::array::from_fn(|i| i as u8))
}

/// A running digest of ciphertexts, each length-prefixed so that the
/// boundaries between them are part of what is pinned.
struct Digest(blake3::Hasher);

impl Digest {
    fn new() -> Self {
        Self(blake3::Hasher::new())
    }

    fn add(&mut self, ciphertext: &[u8]) {
        self.0.update(&(ciphertext.len() as u64).to_be_bytes());
        self.0.update(ciphertext);
    }

    fn hex(&self) -> String {
        self.0.finalize().to_hex().to_string()
    }
}

/// The digest of `values` under ORE, unsalted then salted.
fn ore<T>(values: &[T]) -> String
where
    T: ClwwOreEncrypt + Clone,
    T::Output: AsRef<[u8]>,
{
    let key = key();
    let mut digest = Digest::new();
    for salt in [None, Some(SALT)] {
        for value in values {
            let ct = value
                .clone()
                .encrypt_with_salt(&key, salt)
                .expect("encrypts");
            digest.add(ct.as_ref());
        }
    }
    digest.hex()
}

/// The digest of `values` under OPE, unsalted then salted.
fn ope<T>(values: &[T]) -> String
where
    T: ClwwOpeEncrypt + Clone,
    T::Output: AsRef<[u8]>,
{
    let key = key();
    let mut digest = Digest::new();
    for salt in [None, Some(SALT)] {
        for value in values {
            let ct = value
                .clone()
                .encrypt_ope_with_salt(&key, salt)
                .expect("encrypts");
            digest.add(ct.as_ref());
        }
    }
    digest.hex()
}

macro_rules! ints {
    ($($t:ty),*) => {
        [$(
            (
                stringify!($t),
                ore::<$t>(&[<$t>::MIN, 0, 1, 42, <$t>::MAX / 2, <$t>::MAX]),
                ope::<$t>(&[<$t>::MIN, 0, 1, 42, <$t>::MAX / 2, <$t>::MAX]),
            ),
        )*]
    };
}

#[test]
fn integers() {
    let got = ints!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);
    let want = [
        (
            "u8",
            "af9ff6ad05e6b831c5e38d38ca5ff520913114c81db8c04acf44c7e81a822d62",
            "87b997a0b67285253fac6dc04f09f77a1e9a4c039ae96172e4c0383fd910a8b3",
        ),
        (
            "u16",
            "6d43253d5dbb442352673c81fc98f24453a048a014029229aa2603c5d5f6179f",
            "66f417f7c9ec3aa4cf8a380de1453d10dc4eecf21a7dd1087504d9804e7aa2c7",
        ),
        (
            "u32",
            "3d02dd383d3fc11f22f48c658ae09790d45b841965da97a943ab885cfb1fb806",
            "e19fb6fb74cdd3cf53beaac662e268439e9b43aef74bedf968b090eb262ca509",
        ),
        (
            "u64",
            "cc0cc567b2e9ec2ad514ede4df01ea3632100bc38c5c8ce76bf5603d9cb54900",
            "ced26531d8bca3763678f0ebf18fae51ada9a03d294a3f1eb76cdd49efcbf683",
        ),
        (
            "u128",
            "11fcbc0540cbee481b5483a48c77d290fbaba29ce9522a62dea851e2f0f57998",
            "372890ef81a30f8c78ffaa3148f964cd59760cea5199c5ce006c9d2e0136366d",
        ),
        (
            "i8",
            "1edeac5e1d41419c634fc0cfb4801a394d3dc2ff2a895a34b5fb85ae7d7615d7",
            "e63e4e242234156a805b84a47f2385215bfdd0805c2a2c4d9e6e81373424f454",
        ),
        (
            "i16",
            "b9854c082964234a64e5a7e2c03723a863835162a554c4b9fed23d25a77fcdb5",
            "ab45fd61c3dd2e3d48f06be4f594f5fb28cff61020a35064e4006fcacdda1a2b",
        ),
        (
            "i32",
            "3cb7031ae6ed4a32db4fb4eb323c2ceb540c5c08bcf631bbdd8307c826f6b00e",
            "aa5a7b520b488dc276c33c3e794105a7656cd659a123aed87a4399ce47a885eb",
        ),
        (
            "i64",
            "4e668760934924ed412c6e13bbffa601e66d051be540eebc5c5e33bbef5b8a95",
            "6da6c9d5dc3ef9fa7742a7f6a4d3d8d6b0268d96f5dc86253dbba180a51e4033",
        ),
        (
            "i128",
            "4aadaf5b4456bb243343262ba4173c7484bf7b5213879eac71817d65ecc649ea",
            "2fd997ff5b54c161a623156f0a6be61fdfd60c3dbf02587cc0a122ce82486349",
        ),
    ];
    for ((name, ore, ope), (want_name, want_ore, want_ope)) in got.iter().zip(want.iter()) {
        assert_eq!(name, want_name);
        assert_eq!(ore, want_ore, "ORE {name}");
        assert_eq!(ope, want_ope, "OPE {name}");
    }
}

#[test]
fn floats_and_bool() {
    let f32s = [
        f32::NEG_INFINITY,
        f32::MIN,
        -1.5,
        0.0,
        1.5,
        f32::MAX,
        f32::INFINITY,
    ];
    let f64s = [
        f64::NEG_INFINITY,
        f64::MIN,
        -1.5,
        0.0,
        1.5,
        f64::MAX,
        f64::INFINITY,
    ];
    assert_eq!(
        ore(&f32s),
        "46bf22263acc51cca40bb079afd16bd335b3806a6f2f59251274abcdefb804ea",
        "ORE f32"
    );
    assert_eq!(
        ope(&f32s),
        "9386fddb701348fa99a8015e530beda4527ab852cac30cd8ec6afe4daca1e8a3",
        "OPE f32"
    );
    assert_eq!(
        ore(&f64s),
        "9f270222c5ce413e38a79223c642972a149f0fc40b440b055021cd1bdc254149",
        "ORE f64"
    );
    assert_eq!(
        ope(&f64s),
        "382d9e7365b45e77b7930c9cb623361e5dca418fe4a85f4763d5ca47513688d3",
        "OPE f64"
    );
    assert_eq!(
        ore(&[false, true]),
        "af26103e68beaf44d406d76734376e04e1faed94d398168c268aa937ac510b17",
        "ORE bool"
    );
    assert_eq!(
        ope(&[false, true]),
        "30b35e2b1599edf3c525c79498b3d48e57cb8759bf79661f316544090b7b9b5c",
        "OPE bool"
    );
}

#[test]
fn strings_and_bytes() {
    let strs = ["", "a", "Alice", "alice", "hello world", "Émile"];
    assert_eq!(
        ore(&strs),
        "7dec47d2bccd1421d0da28d62a0fea52dc167e5160392cc83a760a8d90f33359",
        "ORE &str"
    );
    assert_eq!(
        ope(&strs),
        "0b87cc782f68260e5e94ed4bfaaa6137e7e23da037dcedc9177658ec5272e281",
        "OPE &str"
    );
    let bytes: [&[u8]; 4] = [&[], &[0], &[1, 2, 3], &[255, 0, 255, 0, 1]];
    assert_eq!(
        ore(&bytes),
        "82fca3427b6ca013d879c884beaac57e86935bdd0f8d24ed225a1f24bcc89909",
        "ORE &[u8]"
    );
    assert_eq!(
        ope(&bytes),
        "b5c2fb4bfdbde0467cadda56dd4555a25c7dd1d0708e19671376bfef297d085e",
        "OPE &[u8]"
    );
}

/// The fixed byte arrays the `chrono` and `decimal` encodings go through.
#[cfg(any(feature = "chrono", feature = "decimal"))]
#[test]
fn byte_arrays() {
    assert_eq!(
        ope(&[[0u8; 4], [1, 2, 3, 4]]),
        "32b47ca391fc49261f959fe0ef31e29da642124b1b29c3346bbff2210a404211",
        "OPE [u8; 4]"
    );
    assert_eq!(
        ope(&[[0u8; 12], [7; 12]]),
        "e62bfbcb8ec1562f6b918d0cc0c59c65779c15586bf8597394cc59a9ceb99460",
        "OPE [u8; 12]"
    );
    assert_eq!(
        ope(&[[0u8; 14], [9; 14]]),
        "23c7233a8aaac6a5e53aa451ceb21b10952604180e389ed4dc89de26e81ecc69",
        "OPE [u8; 14]"
    );
}

#[test]
fn bit_streams() {
    let bits = [1u8, 0, 1, 1, 0, 0, 0, 1, 1, 1];
    let key = key();
    let mut digest = Digest::new();
    for salt in [None, Some(SALT)] {
        digest.add(&encrypt_ore_bits(bits, &key, salt));
        digest.add(&encrypt_ope_bits(bits, bits.len(), &key, salt));
    }
    assert_eq!(
        digest.hex(),
        "d333141fb1a8ee19cbb50157f62da59741f59634197b786133453b8b7b61e912"
    );
}

#[cfg(feature = "decimal")]
#[test]
fn decimals() {
    use rust_decimal::Decimal;
    let values = [
        Decimal::MIN,
        Decimal::new(-150, 2),
        Decimal::ZERO,
        Decimal::new(150, 2),
        Decimal::MAX,
    ];
    assert_eq!(
        ope(&values),
        "6c8447b0742b00f2fdc74d1d1f6070b00e234017b8407c1458571491497949b1",
        "OPE Decimal"
    );
}

#[cfg(feature = "chrono")]
#[test]
fn dates_and_times() {
    use chrono::{DateTime, NaiveDate, Utc};
    let dates = [
        NaiveDate::MIN,
        NaiveDate::from_ymd_opt(1970, 1, 1).expect("a date"),
        NaiveDate::from_ymd_opt(2026, 10, 20).expect("a date"),
        NaiveDate::MAX,
    ];
    assert_eq!(
        ope(&dates),
        "0d4d5e664a7a1bf53225550233db99c8638a1722ae379016faf9ffd919c12e94",
        "OPE NaiveDate"
    );
    let times = [
        DateTime::<Utc>::from_timestamp(0, 0).expect("a time"),
        DateTime::<Utc>::from_timestamp(1_760_000_000, 123_456_789).expect("a time"),
    ];
    assert_eq!(
        ope(&times),
        "8cca83832115f59edbded43b424c134a2440c0d9f0ad43cd9a4778fcf9965bbd",
        "OPE DateTime<Utc>"
    );
}
