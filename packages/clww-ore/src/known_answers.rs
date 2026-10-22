//! Known-answer digests for the encryption every term goes through.
//!
//! Stored ORE and OPE terms are built on this crate's output, and the order
//! tests elsewhere pass for a changed encoding just as well. These pin the
//! bytes: a BLAKE3 digest of the terms of fixed plaintexts, unsalted and
//! salted, under a fixed key. A change here is a change to every stored term.
//!
//! The digests were recorded from the code as it came over from
//! cipherstash-suite (`cllw-ore` 0.5.1), and recorded again when 0.6.0 gave
//! ORE and OPE their own keystreams and framed the salt (see
//! `keystream_separation`), which changed every term. 0.10 removed the typed
//! entry points: every term now goes through the byte path. An unsigned
//! integer's typed term was the term of its big-endian bytes, so its digests
//! are kept and now pin the byte path. Encodings of other types are
//! vitaminc's, pinned through the schemes in `order_scheme`.

use crate::impls::{encrypt_ope_bits, encrypt_ope_bytes, encrypt_ore_bits, encrypt_ore_bytes};
use crate::Key;

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

/// The digest of the ORE terms of `values`, unsalted then salted.
fn ore<B: AsRef<[u8]>>(values: &[B]) -> String {
    let key = key();
    let mut digest = Digest::new();
    for salt in [None, Some(SALT)] {
        for value in values {
            let ct = encrypt_ore_bytes(value.as_ref(), &key, salt).expect("encrypts");
            digest.add(ct.as_ref());
        }
    }
    digest.hex()
}

/// The digest of the OPE terms of `values`, unsalted then salted.
fn ope<B: AsRef<[u8]>>(values: &[B]) -> String {
    let key = key();
    let mut digest = Digest::new();
    for salt in [None, Some(SALT)] {
        for value in values {
            let ct = encrypt_ope_bytes(value.as_ref(), &key, salt).expect("encrypts");
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
                ore(&[<$t>::MIN, 0, 1, 42, <$t>::MAX / 2, <$t>::MAX].map(<$t>::to_be_bytes)),
                ope(&[<$t>::MIN, 0, 1, 42, <$t>::MAX / 2, <$t>::MAX].map(<$t>::to_be_bytes)),
            ),
        )*]
    };
}

/// The big-endian bytes of unsigned integers, whose digests were recorded
/// from the typed entry points 0.6 had.
#[test]
fn unsigned_integers() {
    let got = ints!(u8, u16, u32, u64, u128);
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
    ];
    for ((name, ore, ope), (want_name, want_ore, want_ope)) in got.iter().zip(want.iter()) {
        assert_eq!(name, want_name);
        assert_eq!(ore, want_ore, "ORE {name}");
        assert_eq!(ope, want_ope, "OPE {name}");
    }
}

#[test]
fn bytes() {
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
