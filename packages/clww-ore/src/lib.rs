#![doc(html_no_source)]
#![doc(html_favicon_url = "https://cipherstash.com/favicon.ico")]
#![doc = include_str!("../README.md")]
//
// Security-focused lints
//
// Deny unsafe code to ensure memory safety
#![deny(unsafe_code)]
// Deny missing documentation for public API
#![deny(missing_docs)]
// Catch potential security issues from unused results
#![warn(unused_results)]
// Ensure proper error handling
#![warn(unreachable_pub)]
// Memory safety warnings
#![warn(clippy::mem_forget)]
#![warn(clippy::missing_safety_doc)]
// Note: clippy::arithmetic_side_effects is available but too strict for cryptographic code
// where bit shifts and arithmetic are fundamental operations. Consider enabling it and
// using #[allow] annotations on specific crypto functions if needed.
// Ensure proper error propagation
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::panic)]
// Allow these lints in test code where they are acceptable
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::expect_used))]
#![cfg_attr(test, allow(clippy::panic))]
#![cfg_attr(test, allow(unused_results))]
#![cfg_attr(test, allow(unused_must_use))]
// Security: avoid potential data leaks
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]
#![warn(clippy::dbg_macro)]
// Code quality lints that help prevent bugs
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::todo)]
#![warn(clippy::unimplemented)]
// Ensure we use constant-time comparisons where appropriate
#![warn(clippy::if_then_some_else_none)]
//! ## Features
//!
//! - **Order-Revealing**: Relative order of plaintexts can be determined at query time
//! - **Deterministic**: The same plaintext always produces the same ciphertext for a given key
//! - **Constant-Time**: Operations use constant-time algorithms to prevent timing attacks
//! - **Multiple Types**: Support for integers (`u16`, `u32`, `u64`, `u128`), strings, and byte slices
//!
//! ## Basic Usage
//!
//! ```
//! use cllw_ore::Key;
//! use std::cmp::Ordering;
//!
//! // Create an encryption key
//! let key = Key::from([0u8; 32]);
//!
//! // Encrypt integers
//! let ct1 = key.encrypt(10u32).unwrap();
//! let ct2 = key.encrypt(20u32).unwrap();
//!
//! // Compare encrypted values
//! assert_eq!(ct1.cmp(&ct2), Ordering::Less);
//!
//! // Decrypt values
//! assert_eq!(key.decrypt(ct1).unwrap(), 10u32);
//! assert_eq!(key.decrypt(ct2).unwrap(), 20u32);
//! ```
//!
//! ## Supported Types
//!
//! ### Unsigned Integers
//!
//! ```
//! use cllw_ore::Key;
//!
//! let key = Key::from([0u8; 32]);
//!
//! // u16, u32, u64, u128 are all supported
//! let ct16 = key.encrypt(100u16).unwrap();
//! let ct32 = key.encrypt(1000u32).unwrap();
//! let ct64 = key.encrypt(10000u64).unwrap();
//! let ct128 = key.encrypt(100000u128).unwrap();
//!
//! assert_eq!(key.decrypt(ct32).unwrap(), 1000u32);
//! ```
//!
//! ### Strings
//!
//! ```
//! use cllw_ore::Key;
//!
//! let key = Key::from([0u8; 32]);
//!
//! let ct1 = key.encrypt("alice").unwrap();
//! let ct2 = key.encrypt("bob").unwrap();
//!
//! assert!(ct1 < ct2);
//! assert_eq!(key.decrypt(ct1).unwrap(), "alice");
//! ```
//!
//! ### Byte Slices
//!
//! ```
//! use cllw_ore::Key;
//!
//! let key = Key::from([0u8; 32]);
//! let data: &[u8] = &[0xFF, 0x00, 0xAB];
//!
//! let ciphertext = key.encrypt(data).unwrap();
//! let decrypted = ciphertext.decrypt_to_bytes(&key, None).unwrap();
//!
//! assert_eq!(data, decrypted.as_slice());
//! ```
//!
//! ## Using Salts for Domain Separation
//!
//! ```
//! use cllw_ore::{Key, CllwOreEncrypt, CllwOreDecrypt};
//!
//! let key = Key::from([0u8; 32]);
//! let salt = b"my-domain";
//!
//! // Encrypt with a salt
//! let ct = 42u32.encrypt_with_salt(&key, Some(salt)).unwrap();
//!
//! // Must use the same salt to decrypt
//! let pt = ct.decrypt_with_salt(&key, Some(salt)).unwrap();
//! assert_eq!(pt, 42u32);
//! ```
use thiserror::Error;
mod biterator;
mod impls;
mod nibble_iterator;

pub use impls::num::{OpeCllw8V1, OreCllw8V1};
pub use impls::string::{OpeCllw8VariableV1, OreCllw8VariableV1};

/// An error occurred during encryption or decryption.
///
/// This error is intentionally vague to prevent oracle attacks where
/// specific error messages could leak information about the plaintext.
#[derive(Debug, Error)]
#[error("Operation failed")]
pub struct Error;

/// A 256-bit encryption key for CLLW Order-Revealing Encryption.
///
/// The key is used to encrypt and decrypt values while preserving their ordering.
/// All encryption operations are deterministic for a given key.
///
/// # Examples
///
/// ```
/// use cllw_ore::Key;
///
/// // Create a key from a 32-byte array
/// let key = Key::from([0u8; 32]);
///
/// // Encrypt an integer
/// let plaintext: u32 = 42;
/// let ciphertext = key.encrypt(plaintext).unwrap();
///
/// // Decrypt back to the original value
/// let decrypted = key.decrypt(ciphertext).unwrap();
/// assert_eq!(plaintext, decrypted);
/// ```
pub struct Key([u8; 32]);

impl Key {
    /// Encrypts a value using CLLW Order-Revealing Encryption.
    ///
    /// The encryption is deterministic and preserves the ordering of values.
    /// Supported types: `u16`, `u32`, `u64`, `u128`, `&str`, `&[u8]`
    ///
    /// # Examples
    ///
    /// ```
    /// use cllw_ore::Key;
    /// use std::cmp::Ordering;
    ///
    /// let key = Key::from([0u8; 32]);
    ///
    /// // Order is preserved
    /// let a = key.encrypt(10u32).unwrap();
    /// let b = key.encrypt(20u32).unwrap();
    /// assert_eq!(a.cmp(&b), Ordering::Less);
    ///
    /// // Encryption is deterministic
    /// let c = key.encrypt(10u32).unwrap();
    /// assert_eq!(a, c);
    /// ```
    pub fn encrypt<T>(&self, input: T) -> Result<<T as CllwOreEncrypt>::Output, Error>
    where
        T: CllwOreEncrypt,
    {
        input.encrypt(self)
    }

    /// Decrypts a ciphertext back to its original value.
    ///
    /// # Examples
    ///
    /// ```
    /// use cllw_ore::Key;
    ///
    /// let key = Key::from([0u8; 32]);
    /// let plaintext = 12345u64;
    ///
    /// let ciphertext = key.encrypt(plaintext).unwrap();
    /// let decrypted = key.decrypt(ciphertext).unwrap();
    ///
    /// assert_eq!(plaintext, decrypted);
    /// ```
    pub fn decrypt<T>(&self, input: T) -> Result<<T as CllwOreDecrypt>::Output, Error>
    where
        T: CllwOreDecrypt,
    {
        input.decrypt(self)
    }

    /// Encrypts a value using CLLW Order-Preserving Encryption.
    ///
    /// Ciphertexts can be compared with standard lexicographic byte ordering, without a
    /// custom comparison function. The encoding applies a right-to-left carry pass to
    /// the CLLW keystream-plus-plaintext sum, which dramatically reduces the ordering
    /// error relative to the paper's naive base-256 interpretation: the per-comparison
    /// error rate drops from ~1/256 (~3.9 × 10⁻³) to ~(1/255)² / 2 (~7.7 × 10⁻⁶) for
    /// the worst-case "adjacent plaintext" pairs, and essentially zero for well-
    /// separated plaintexts. Lex ordering is *not* strictly exact — the residual
    /// error is inherent to the CLLW construction (the PRF chain is plaintext-
    /// dependent, so low-order PRF divergence can occasionally flip the comparison).
    ///
    /// **Encrypt-only**: OPE ciphertexts cannot be decrypted. Pair with an ORE
    /// ciphertext when round-trip is required.
    ///
    /// # Examples
    ///
    /// ```
    /// use cllw_ore::Key;
    ///
    /// let key = Key::from([0u8; 32]);
    ///
    /// let a = key.encrypt_ope(10u32).unwrap();
    /// let b = key.encrypt_ope(20u32).unwrap();
    /// assert!(a < b);
    /// ```
    pub fn encrypt_ope<T>(&self, input: T) -> Result<<T as CllwOpeEncrypt>::Output, Error>
    where
        T: CllwOpeEncrypt,
    {
        input.encrypt_ope(self)
    }
}

impl From<[u8; 32]> for Key {
    fn from(key: [u8; 32]) -> Self {
        Self(key)
    }
}

/// Trait for types that can be encrypted using CLLW Order-Revealing Encryption.
///
/// This trait is implemented for unsigned integer types (`u16`, `u32`, `u64`, `u128`),
/// strings (`&str`), and byte slices (`&[u8]`).
///
/// # Examples
///
/// ```
/// use cllw_ore::{Key, CllwOreEncrypt};
///
/// let key = Key::from([0u8; 32]);
///
/// // Using the trait directly
/// let ciphertext = 42u32.encrypt(&key).unwrap();
///
/// // Using the Key::encrypt method (more ergonomic)
/// let ciphertext2 = key.encrypt(42u32).unwrap();
/// assert_eq!(ciphertext, ciphertext2);
/// ```
pub trait CllwOreEncrypt: Sized {
    /// The output type of the encryption operation.
    type Output;

    /// Encrypts the value without a salt.
    fn encrypt(self, key: &Key) -> Result<Self::Output, Error> {
        self.encrypt_with_salt(key, None)
    }

    /// Encrypts the value with an optional salt for domain separation.
    fn encrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error>;
}

/// Trait for types that can be decrypted from CLLW Order-Revealing Encryption.
///
/// This trait is implemented for the ciphertext types `OreCllw8V1<N>` and `OreCllw8VariableV1`.
///
/// # Examples
///
/// ```
/// use cllw_ore::{Key, CllwOreDecrypt};
///
/// let key = Key::from([0u8; 32]);
/// let ciphertext = key.encrypt(100u32).unwrap();
///
/// // Using the trait directly
/// let plaintext = ciphertext.decrypt(&key).unwrap();
/// assert_eq!(plaintext, 100u32);
/// ```
pub trait CllwOreDecrypt: Sized {
    /// The output type of the decryption operation.
    type Output;

    /// Decrypts the ciphertext without a salt.
    fn decrypt(self, key: &Key) -> Result<Self::Output, Error> {
        self.decrypt_with_salt(key, None)
    }

    /// Decrypts the ciphertext with an optional salt (must match the salt used during encryption).
    fn decrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error>;
}

/// Trait for types that can be encrypted using CLLW Order-Preserving Encryption.
///
/// This is the OPE variant from Section 3.2 of the CLWW paper. The encryption is identical
/// to ORE, but the resulting ciphertext type uses standard lexicographic comparison instead
/// of the ORE comparison function.
///
/// **Correctness**: OPE comparison is correct with probability `1 - 1/256 ~ 99.6%` per
/// comparison. See [`CllwOreEncrypt`] for the always-correct ORE variant.
///
/// # Examples
///
/// ```
/// use cllw_ore::{Key, CllwOpeEncrypt};
///
/// let key = Key::from([0u8; 32]);
///
/// let ct = 42u32.encrypt_ope(&key).unwrap();
/// ```
pub trait CllwOpeEncrypt: Sized {
    /// The output type of the encryption operation.
    type Output;

    /// Encrypts the value without a salt.
    fn encrypt_ope(self, key: &Key) -> Result<Self::Output, Error> {
        self.encrypt_ope_with_salt(key, None)
    }

    /// Encrypts the value with an optional salt for domain separation.
    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen};
    use std::{
        array,
        fmt::{self, Debug, Formatter},
    };

    impl Clone for Key {
        fn clone(&self) -> Self {
            Key(self.0)
        }
    }

    impl Arbitrary for Key {
        fn arbitrary(g: &mut Gen) -> Self {
            Self(array::from_fn(|_| u8::arbitrary(g)))
        }
    }

    impl Debug for Key {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
}
