//! Concrete BlockORE schemes. The crate currently exposes one scheme,
//! [`bit2`], which uses a 2-bit indicator function with AES-128 as the PRF
//! and Knuth-shuffle as the per-block PRP. Future schemes (different
//! indicator widths or primitive choices) would land alongside it as
//! sibling submodules.

/// 2-bit-indicator BlockORE with AES-128 PRF and Knuth-shuffle PRP.
pub mod bit2;
