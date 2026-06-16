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

pub(crate) mod decompose;
pub(crate) mod width;
