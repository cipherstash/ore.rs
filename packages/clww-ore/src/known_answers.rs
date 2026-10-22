//! Known-answer digests for every encrypt path.
//!
//! Stored ORE and OPE terms are built on this crate's output, and the order
//! and round-trip tests elsewhere pass for a changed encoding just as well.
//! These pin the bytes: a BLAKE3 digest of each type's ciphertexts, unsalted
//! and salted, under a fixed key. A change here is a change to every stored
//! term. The digests were recorded from the code as it came over from
//! cipherstash-suite (`cllw-ore` 0.5.1), and recorded again when 0.6.0 gave
//! ORE and OPE their own keystreams and framed the salt (see
//! `keystream_separation`), which changed every term.

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
            "b8cb2da864ad317a8d1b61b12d285d544e7aad16a9ab5a4a8089720045636440",
            "1ddc2081671d48a70c2ac86a31d0c59768b2b279d181d41d28a65da17df88734",
        ),
        (
            "u16",
            "fd9b0578e39e8828f0224fe210349b217ed507607400c41dca3f10d3460750c4",
            "78b320eb24e5ed717cf2d154a2b6dee4af54681392ae2f9bbabd41d7d799c826",
        ),
        (
            "u32",
            "eccc0d903767325eb92970b97df890a0bfbb157bab2c414a21307cb5c3a8a99b",
            "f03c3eb33391f6a97450ec31f664adc4da60587e0835c25f0c250448aa118350",
        ),
        (
            "u64",
            "9ddcd6fabce8eb5c0c8eee6349a261ac27ab4d8c9f6984f45fb0086f2f5a8598",
            "a081ad0f0fec5d962e595291a2fda48d06a5281fd33e3e600a5ddc58e24be726",
        ),
        (
            "u128",
            "6c09004da921239f111ee73463621bd24438f61d7bd7580ffeed24534a4f1dcd",
            "ba0b2be66415e0a2a362f9ad72f34b8e6031dd01d658ce5e7bc0cecf83b74bd1",
        ),
        (
            "i8",
            "7c5819e9c06713e2639f6370a7f51d2b808d61edec0e0c208d98673d740028d6",
            "e5991563eac894d44b150a6528e671f1b6e0b7be9eb8a086dd45f86e0b447003",
        ),
        (
            "i16",
            "d82f1958c6baa7a2d63199209fcf75f7da94fdf5394676b93b57920a416657af",
            "f3d1d8ee2b113103fe54de71dde3cd0aaa3afa577bb6dab4cd254c1ae34e3095",
        ),
        (
            "i32",
            "ced1616bf6a6866cc9cfb905f84e666e1d0590f5af33774e654919812feb20bb",
            "96ebe264d5b399eeaa35a5d6c9c8a18b5d5d29f8de73f42fc1484206272af64c",
        ),
        (
            "i64",
            "ae8afe114f4fbdf64dde4045fc814f09b11b92be167cd8c711f8ce7a85b40b4c",
            "9377f94f357f7d8665f4a72a7fb8d9cc65d7c5647106d999ce1a425eb1269ea8",
        ),
        (
            "i128",
            "332c82ab41de4d401d2492a7ad3fefa8c9ca90c719b3997e34a811cc3d74faf6",
            "a6eddd23311e417e332f2dc3bb4b8b43d74734e08eec551ad944ce1c37f2e74d",
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
        "8835cc5e62f4be3116312579ee0485edaa852b20e084479e3e64b545f6d55041",
        "ORE f32"
    );
    assert_eq!(
        ope(&f32s),
        "3bc6e9ea8dcfac42401b56344fd2fbd6d0e8a80b9b9ea1309c4ec758d10d309e",
        "OPE f32"
    );
    assert_eq!(
        ore(&f64s),
        "b4d83e7eab24cec8bfacb37b69b08602ba64e724005d9805aecc5802872b503c",
        "ORE f64"
    );
    assert_eq!(
        ope(&f64s),
        "22c2edffdf75c08471b213a8395caad43ffde3b3ebbc4d4f55ae8eac31fbe117",
        "OPE f64"
    );
    assert_eq!(
        ore(&[false, true]),
        "8b8d0d0cd04acd410e38a6478cc26b6c2af14b05a6f609e984ce8bdbf5363b22",
        "ORE bool"
    );
    assert_eq!(
        ope(&[false, true]),
        "9e642dc3893a953c4f2cb714011f4cb54bff5b2eea77524ce9d0891c53406f44",
        "OPE bool"
    );
}

#[test]
fn strings_and_bytes() {
    let strs = ["", "a", "Alice", "alice", "hello world", "Émile"];
    assert_eq!(
        ore(&strs),
        "5e94affec000d89d63f45f2addd4e401e3510779a54e133c4d6a51ff357b8e69",
        "ORE &str"
    );
    assert_eq!(
        ope(&strs),
        "97c8386aec6d90b59c374fc713c03bb044bb52ff413296d5d4621e6d1c88cb72",
        "OPE &str"
    );
    let bytes: [&[u8]; 4] = [&[], &[0], &[1, 2, 3], &[255, 0, 255, 0, 1]];
    assert_eq!(
        ore(&bytes),
        "47303e361f959d1e0ea4421b06f6d75a2f2dec23b97c8e3c8b0e0b956a91f0e6",
        "ORE &[u8]"
    );
    assert_eq!(
        ope(&bytes),
        "0ffb08bf9d472f2577edce7bc56e3f5f43df28dce9ffd1ab7c1fbcc77b2b4ff3",
        "OPE &[u8]"
    );
}

/// The digest of fixed byte arrays under the crate-private OPE the `chrono`
/// and `decimal` encodings go through, unsalted then salted.
#[cfg(any(feature = "chrono", feature = "decimal"))]
fn ope_array<A>(values: &[A]) -> String
where
    A: crate::impls::byte_array::OpeByteArray + Copy,
    A::Output: AsRef<[u8]>,
{
    let key = key();
    let mut digest = Digest::new();
    for salt in [None, Some(SALT)] {
        for value in values {
            let ct = value.encrypt_ope_array(&key, salt).expect("encrypts");
            digest.add(ct.as_ref());
        }
    }
    digest.hex()
}

/// The fixed byte arrays the `chrono` and `decimal` encodings go through.
#[cfg(any(feature = "chrono", feature = "decimal"))]
#[test]
fn byte_arrays() {
    assert_eq!(
        ope_array(&[[0u8; 4], [1, 2, 3, 4]]),
        "d34cc406f9be4456666b7796194cbb2d498743569b82b94dc63c0fcc8a634db4",
        "OPE [u8; 4]"
    );
    assert_eq!(
        ope_array(&[[0u8; 12], [7; 12]]),
        "2f39e3ffd333a8ead867852dab8841e2ea3193bbc8314f24fc10d94eef6f6c35",
        "OPE [u8; 12]"
    );
    assert_eq!(
        ope_array(&[[0u8; 14], [9; 14]]),
        "5bfe5e87e002b9f8e2289a0d34372172d456044169f9ce12f4077234f979b0a4",
        "OPE [u8; 14]"
    );
}

#[test]
fn bit_streams() {
    let bits = [1u8, 0, 1, 1, 0, 0, 0, 1, 1, 1];
    let key = key();
    let mut digest = Digest::new();
    for salt in [None, Some(SALT)] {
        digest.add(&encrypt_ore_bits(bits, &key, salt).unwrap());
        digest.add(&encrypt_ope_bits(bits, &key, salt).unwrap());
    }
    assert_eq!(
        digest.hex(),
        "d58e2ee9a850583789886a0b54159522589b831be92553e4f513604fbdf5b1ae"
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
        "2f64ba05658e57885cb9924a458b09e3fd6ad4a8d4c879d61a53b4ba5ab71078",
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
        "3e1b39d8f9da7d60a195551bc3ce7bde8f035d14e456f80450ebba8b97fe92ba",
        "OPE NaiveDate"
    );
    let times = [
        DateTime::<Utc>::from_timestamp(0, 0).expect("a time"),
        DateTime::<Utc>::from_timestamp(1_760_000_000, 123_456_789).expect("a time"),
    ];
    assert_eq!(
        ope(&times),
        "8f9f5d6f96ec82a358f98c7b456faef67d41c25ba108492b17d2090a0ced8714",
        "OPE DateTime<Utc>"
    );
}
