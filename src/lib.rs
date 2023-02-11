//! ore-rs is a library to encrypt numeric types in a way that allows the numeric ordering
//! of the unencrypted values to be "revealed" during a query enabling range queries to be performed
//! on encrypted data.
//!
//! This is an implementation of the BlockORE Encryption scheme developed by
//! [Lewi-Wu in 2016](https://eprint.iacr.org/2016/612.pdf). It is used extensively in the
//! [CipherStash](https://cipherstash.com) searchable encryption platform.
//!
//!
//! # Usage
//! This crate is [on crates.io](https://crates.io/crates/ore-rs) and can be
//! used by adding `ore-rs` to your dependencies in your project's `Cargo.toml`.
//! ```toml
//! [dependencies]
//! ore-rs = "0.1"
//! ```
//!
//! ## Example: Encrypt a number with ORE.
//!
//! To encrypt a number you need to initalize an [`OreCipher`] as well as `use` the [`OreEncrypt`] trait
//! which comes with implementations for `u32` and `u64`.
//!
//! To initalize the Cipher, you must decide on the scheme you want to use. There is only one ORE
//! Scheme right now so that's easy but in the future more schemes will become available.
//!
//! An `OreCipher` also requires 2 keys (16-bytes each) and an 8-byte seed.
//!
//! ```rust
//! use ore_rs::{
//!     OreCipher,  // Main ORE Cipher trait
//!     OreEncrypt, // Traits for encrypting primitive types (e.g. u64)
//!     scheme::bit2::OreAes128ChaCha20 // Specific scheme we want to use
//! };
//! use hex_literal::hex;
//!
//! // Initalize an ORE Cipher with the OreAes128ChaCha20 scheme
//! let k1: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! let k2: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! let ore: OreAes128ChaCha20 = OreCipher::init(&k1, &k2).unwrap();
//!
//! // Encryption takes a mutable reference to the cipher and returns a `Result`
//! let a = 456u64.encrypt(&ore).unwrap();
//! ```
//!
//! *Note that a cipher must be mutable as it manages internal state*.
//!
//!
//! ## Example: Comparing 2 CipherTexts
//!
//! The result of an encryption is called a CipherText and is represented by the type
//! [`CipherText<S, N>`] where `S` is the scheme used and `N` is the number of blocks is the size
//! of the input type (in bytes) divided by 8. (e.g. for `u64` N=8).
//!
//! Comparisons can only be performed between ciphertexts of the same size and underlying scheme.
//!
//! ```rust
//! # use ore_rs::{
//! #     CipherText,
//! #     OreCipher,  // Main ORE Cipher trait
//! #     OreEncrypt, // Traits for encrypting primitive types (e.g. u64)
//! #     scheme::bit2::OreAes128ChaCha20 // Specific scheme we want to use
//! # };
//! # use hex_literal::hex;
//! # let k1: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! # let k2: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! # let ore: OreAes128ChaCha20 = OreCipher::init(&k1, &k2).unwrap();
//! let a = 456u64.encrypt(&ore).unwrap();
//! let b = 1024u64.encrypt(&ore).unwrap();
//!
//! // This is fine
//! let result = a > b; // false because 456 < 1024
//! ```
//!
//! ```compile_fail
//! # use ore_rs::{
//! #     CipherText,
//! #     OreCipher,  // Main ORE Cipher trait
//! #     OreEncrypt, // Traits for encrypting primitive types (e.g. u64)
//! #     scheme::bit2::OreAes128ChaCha20 // Specific scheme we want to use
//! # };
//! # use hex_literal::hex;
//! # let k1: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! # let k2: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! # let ore: OreAes128ChaCha20 = OreCipher::init(&k1, &k2).unwrap();
//! // This isn't
//! let a = 456u64.encrypt(&ore).unwrap();
//! let b = 1024u32.encrypt(&ore).unwrap(); // note the u32
//!
//! let result = a > b; // compilation error
//! ```
//!
//! ## Serializing/Deserializing
//!
//! *Note: this library doesn't use [Serde](https://crates.io/crates/serde) due to some complexities
//! with GenericArray used in the [AES](https://crates.io/crates/aes) library. This may change in the future.*
//!
//! To serialize a [`CipherText<S, N>`] to a vector of bytes:
//!
//! ```rust
//! # use ore_rs::{
//! #     CipherText,
//! #     OreCipher,  // Main ORE Cipher trait
//! #     OreEncrypt, // Traits for encrypting primitive types (e.g. u64)
//! #     OreOutput,
//! #     scheme::bit2::OreAes128ChaCha20 // Specific scheme we want to use
//! # };
//! # use hex_literal::hex;
//! # let k1: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! # let k2: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! # let ore: OreAes128ChaCha20 = OreCipher::init(&k1, &k2).unwrap();
//! let a = 456u64.encrypt(&ore).unwrap();
//! let bytes: Vec<u8> = a.to_bytes();
//! ```
//!
//! To deserialize, you must specify the CipherText type (including number of blocks) you
//! are deserializing into:
//!
//! ```rust
//! # use ore_rs::{
//! #     CipherText,
//! #     OreCipher,  // Main ORE Cipher trait
//! #     OreEncrypt, // Traits for encrypting primitive types (e.g. u64)
//! #     OreOutput,
//! #     scheme::bit2::OreAes128ChaCha20 // Specific scheme we want to use
//! # };
//! # use hex_literal::hex;
//! # let k1: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! # let k2: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
//! # let ore: OreAes128ChaCha20 = OreCipher::init(&k1, &k2).unwrap();
//! # let a = 456u64.encrypt(&ore).unwrap();
//! # let bytes: Vec<u8> = a.to_bytes();
//!
//! let ct = CipherText::<OreAes128ChaCha20, 8>::from_bytes(&bytes).unwrap();
//! # assert!(ct == a);
//! ```

mod ciphertext;
mod convert;
mod encrypt;
mod primitives;
pub mod scheme;
pub use crate::ciphertext::*;
pub use crate::encrypt::OreEncrypt;
use primitives::PrpError;
use std::cmp::Ordering;
use thiserror::Error;

pub type PlainText<const N: usize> = [u8; N];

#[derive(Debug, Error)]
pub enum OreError {
    #[error("Failed to initialize cipher")]
    InitFailed,
    #[error(transparent)]
    PrpError(#[from] PrpError),
    #[error("Randomness Error")]
    RandError(#[from] rand::Error),
}

pub trait OreCipher: Sized {
    type LeftBlockType: CipherTextBlock;
    type RightBlockType: CipherTextBlock;

    fn init(k1: &[u8; 16], k2: &[u8; 16]) -> Result<Self, OreError>;

    fn encrypt_left<const N: usize>(&self, input: &PlainText<N>)
        -> Result<Left<Self, N>, OreError>;

    fn encrypt<const N: usize>(
        &self,
        input: &PlainText<N>,
    ) -> Result<CipherText<Self, N>, OreError>;

    fn compare_raw_slices(a: &[u8], b: &[u8]) -> Option<Ordering>;
}

#[cfg(test)]
#[macro_use]
extern crate quickcheck;
