//! Self-contained re-export of constant-time-sensitive functions for static
//! analysis. Build with:
//!
//!     cargo rustc --release --example ct_extract -- --emit=asm
//!
//! Then point the constant-time-analysis tool at the emitted .s file under
//! `target/release/examples/ct_extract-*.s`. See `ct-analysis/README.md`.
//!
//! These wrappers exist so the analyzer can find stable demangled symbols.
//! Without them every comparison call site would be a different mangled
//! generic, and the analyzer would have to grep across many functions.

use std::cmp::Ordering;

use ore_rs::{scheme::bit2::OreAes128ChaCha20, CipherText, OreCipher};

#[no_mangle]
pub extern "Rust" fn ct_compare_raw_slices(a: &[u8], b: &[u8]) -> Option<Ordering> {
    OreAes128ChaCha20::compare_raw_slices(a, b)
}

#[no_mangle]
pub extern "Rust" fn ct_ciphertext_cmp_n8(
    a: &CipherText<OreAes128ChaCha20, 8>,
    b: &CipherText<OreAes128ChaCha20, 8>,
) -> Ordering {
    a.cmp(b)
}

fn main() {
    // The example only exists so cargo emits asm for the wrappers.
    // Touch each symbol so dead-code elimination can't remove them.
    let _ = ct_compare_raw_slices(&[], &[]);
}
