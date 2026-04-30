#![deny(missing_docs)]
//! Canonical order-preserving pre-encoders for plaintext types fed into the
//! `ore-rs` BlockORE machinery.
//!
//! Each module exposes a `pre_encode` function that maps a value of its
//! target type to a fixed-length byte array whose byte-wise lexicographic
//! order agrees with the type's natural total order, and whose byte equality
//! agrees with the type's value equality. The resulting bytes are intended
//! to be fed into the fixed-N ORE machinery (`ore_rs::OreCipher::encrypt`)
//! so that the ciphertexts inherit the same order and equality properties.
//!
//! Encoders are gated behind per-type feature flags so callers only pay for
//! the dependencies they actually use.

#[cfg(feature = "decimal")]
pub mod decimal;
