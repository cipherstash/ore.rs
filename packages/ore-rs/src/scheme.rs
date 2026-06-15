//! Concrete BlockORE schemes. The crate currently exposes one scheme,
//! [`bit2`], which uses a 2-bit indicator function with AES-128 as the PRF
//! and Knuth-shuffle as the per-block PRP. Future schemes (different
//! indicator widths or primitive choices) would land alongside it as
//! sibling submodules.

/// 2-bit-indicator BlockORE with AES-128 PRF and Knuth-shuffle PRP.
pub mod bit2;

/// 6-bit-block variant of [`bit2`]: 4x less AES work per block and 4x
/// smaller right blocks. Wire format v2 (headered). Not yet frozen —
/// pending crypto review of the Z2 hash (v2 plan, section 6).
pub mod bit2_w6;

/// Variable-length / chained-prefix scheme (6-bit blocks): lifts the packed
/// 14-block cap via an AES-CMAC accumulator, enabling string encryption. Wire
/// format v2 (scheme id 0x03). See
/// `docs/plans/2026-06-15-ore-v2-cmac-accumulator-spec.md`.
pub mod chained;

pub(crate) mod decompose;
pub(crate) mod width;
