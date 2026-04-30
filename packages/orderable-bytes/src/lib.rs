#![deny(missing_docs)]
//! Canonical, order-preserving fixed-length byte encodings for plaintext
//! types.
//!
//! Each module exposes a `to_orderable_bytes` function that maps a value of
//! its target type to a fixed-length byte array whose byte-wise
//! lexicographic order agrees with the type's natural total order, and
//! whose byte equality agrees with the type's value equality. The
//! resulting bytes are scheme-agnostic — they're intended for any
//! comparison-as-bytes scheme that wants to preserve plaintext order on
//! ciphertexts (e.g. `ore-rs` BlockORE, an OPE construction, an ordered
//! hash).
//!
//! Encoders are gated behind per-type feature flags so callers only pay
//! for the dependencies they actually use.

#[cfg(feature = "chrono")]
pub mod chrono;
#[cfg(feature = "decimal")]
pub mod decimal;
