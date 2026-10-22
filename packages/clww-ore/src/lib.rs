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
use thiserror::Error;
use zeroize::Zeroize;
mod impls;
#[cfg(test)]
mod keystream_separation;
#[cfg(test)]
mod known_answers;
mod order_scheme;

pub use impls::variable::{OpeClww8VariableV1, OreClww8VariableV1};
pub use order_scheme::{ClwwOpe, ClwwOre, KeyLengthError};

/// An error occurred during encryption, or stored bytes were not a term.
///
/// This error is intentionally vague to prevent oracle attacks where
/// specific error messages could leak information about the plaintext.
#[derive(Debug, Error)]
#[error("Operation failed")]
pub struct Error;

/// The 256-bit key a scheme keeps: the PRF key of both keystreams.
///
/// The key material is wiped on drop (`ZeroizeOnDrop`), and [`Key::from`]
/// wipes the by-value copy it is handed.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub(crate) struct Key([u8; 32]);

impl From<[u8; 32]> for Key {
    /// Move the bytes into a self-wiping `Key`. `[u8; 32]` is `Copy`, so the
    /// argument is a copy: it is wiped here before returning, but the caller's
    /// own array is the caller's to wipe.
    fn from(mut key: [u8; 32]) -> Self {
        let wrapped = Key(key);
        key.zeroize();
        wrapped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::impls::{encrypt_ope_bits, encrypt_ope_bytes, encrypt_ore_bits, encrypt_ore_bytes};

    /// A stream with a byte that is not a bit is refused, wherever the byte
    /// sits; the bits alone encrypt as their byte does.
    #[test]
    fn bit_streams_refuse_bytes_that_are_not_bits() {
        let key = Key::from([3; 32]);
        let bits = [1u8, 0, 1, 1, 0, 0, 1, 0];
        for (at, bad) in [(0, 2u8), (3, 0x80), (7, 0xff)] {
            let mut stream = bits;
            stream[at] = bad;
            assert!(
                encrypt_ope_bits(stream, &key, None).is_err(),
                "OPE {bad} at {at}"
            );
            assert!(
                encrypt_ore_bits(stream, &key, None).is_err(),
                "ORE {bad} at {at}"
            );
        }
        let ope = encrypt_ope_bits(bits, &key, None).unwrap();
        let ore = encrypt_ore_bits(bits, &key, None).unwrap();
        assert_eq!(
            ope,
            encrypt_ope_bytes(&[0xb2], &key, None).unwrap().as_ref()
        );
        assert_eq!(
            ore,
            encrypt_ore_bytes(&[0xb2], &key, None).unwrap().as_ref()
        );
    }
}
