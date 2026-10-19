//! Concrete BlockORE schemes. Use [`bit2_w6`] for fixed-length values up to
//! 10 bytes, or [`chained`] for wider values and strings. The legacy
//! [`bit2`] scheme remains available for compatibility with existing data.

/// 2-bit-indicator BlockORE with AES-128 PRF and Knuth-shuffle PRP.
pub mod bit2;

/// 6-bit-block variant of [`bit2`]: 4x less AES work per block and 4x
/// smaller right blocks. Wire format v2 (headered), frozen as of 0.9.0.
pub mod bit2_w6;

/// Variable-length / chained-prefix scheme (6-bit blocks): lifts the packed
/// 14-block cap via an AES-CMAC accumulator, enabling string encryption. Wire
/// format v2 (scheme id 0x03). See
/// `docs/plans/2026-06-15-ore-v2-cmac-accumulator-spec.md`.
pub mod chained;

pub(crate) mod keys;

pub(crate) mod decompose;
pub(crate) mod width;
