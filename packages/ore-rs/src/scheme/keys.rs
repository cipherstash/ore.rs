//! Key derivation for the v2 schemes: one caller key, an optional salt,
//! and labelled subkeys.
//!
//! Every v2 cipher is keyed from a single 16-byte key:
//!
//! ```text
//! k_root = AES_key( ROOT_LABEL )                         scheme separation
//! k_salt = CMAC_{k_root}( len(salt) ‖ salt ‖ 0… ‖ SALT_FINAL )   salt separation
//! k_i    = AES_{k_salt}( LABEL_i )                       one per PRF the scheme runs
//! ```
//!
//! `key` is evaluated exactly once, on the scheme's root label, so the
//! scheme learns nothing about any other use of the key. The legacy scheme
//! evaluates its raw keys on block inputs whose byte 15 is `0..=14` (PRF₁)
//! or `0` (PRF₂), and a legacy left ciphertext publishes those outputs; a
//! root label therefore ends in a byte outside that set, so a key shared
//! with the legacy scheme never publishes a v2 root key.
//!
//! The salt is any byte string the caller uses to name what the key is for:
//! a column, a tenant, a plaintext type. Ciphertexts under different salts
//! share no key material. Nothing on the wire records the salt, so the
//! comparators cannot detect a mismatch: two ciphertexts under different
//! salts compare to a confident, meaningless answer. The caller keeps the
//! salt with the identity of the stored data, as it keeps the key. An
//! empty salt is a salt like any other: [`init`](crate::scheme::bit2_w6::OreAes128Bit6::init)
//! is `init_with_salt(key, &[])`.
//!
//! The salt is absorbed as full blocks of a CMAC chain, length-prefixed so
//! the encoding is injective, and finalised with a constant label block, so
//! `k_salt` is a CMAC tag (NIST SP 800-38B) over a prefix-free message.

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128Enc;
use zeroize::Zeroizing;

use crate::primitives::cmac::CmacAccumulator;

/// A 16-byte key that is wiped when dropped.
pub(crate) type DerivedKey = Zeroizing<[u8; 16]>;

/// The final CMAC block of the salt derivation.
const SALT_FINAL: [u8; 16] = *b"ORE.v2.salt.done";

/// `AES_k(label)`, wiping nothing of `k` (the caller owns it).
fn aes_block(k: &[u8; 16], label: &[u8; 16]) -> DerivedKey {
    let cipher = Aes128Enc::new(GenericArray::from_slice(k));
    let mut out = Zeroizing::new(*label);
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut *out));
    out
}

/// The scheme's root key: `AES_key(label)`. `label` must be a 16-byte
/// constant whose byte 15 is outside `0..=14` (see the module docs).
pub(crate) fn root(key: &[u8; 16], label: &[u8; 16]) -> DerivedKey {
    debug_assert!(
        label[15] > 14,
        "root label collides with a legacy PRF input"
    );
    aes_block(key, label)
}

/// The salted key: a CMAC tag under `root` over the length-prefixed salt.
pub(crate) fn salted(root: &DerivedKey, salt: &[u8]) -> DerivedKey {
    let mut acc = CmacAccumulator::new(root);
    // `len ‖ salt`, zero-padded to whole blocks. The length prefix makes
    // the encoding injective, so the padding cannot be confused with salt.
    let mut block = Zeroizing::new([0u8; 16]);
    block[..8].copy_from_slice(&(salt.len() as u64).to_be_bytes());
    let mut filled = 8;
    for &byte in salt {
        if filled == 16 {
            acc.absorb(&block);
            *block = [0u8; 16];
            filled = 0;
        }
        block[filled] = byte;
        filled += 1;
    }
    acc.absorb(&block);
    Zeroizing::new(acc.finalize(&SALT_FINAL))
}

/// A PRF key under the salted key: `AES_{k_salt}(label)`.
pub(crate) fn subkey(k_salt: &DerivedKey, label: &[u8; 16]) -> DerivedKey {
    aes_block(k_salt, label)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: [u8; 16] = *b"ORE.v2.test.root";

    #[test]
    fn stages_are_deterministic_and_distinct() {
        let key = [7u8; 16];
        let r = root(&key, &ROOT);
        assert_eq!(*r, *root(&key, &ROOT));
        assert_ne!(*r, *root(&[8u8; 16], &ROOT));
        assert_ne!(*r, *root(&key, b"ORE.v2.other.rt!"));

        let s0 = salted(&r, &[]);
        assert_eq!(*s0, *salted(&r, &[]));
        assert_ne!(*s0, *salted(&r, b"x"));
        assert_ne!(*s0, *r);

        let a = subkey(&s0, b"ORE.v2.bit6.prf1");
        let b = subkey(&s0, b"ORE.v2.bit6.prf2");
        assert_ne!(*a, *b);
        assert_eq!(*a, *subkey(&s0, b"ORE.v2.bit6.prf1"));
    }

    /// The length prefix keeps a salt apart from the same bytes plus the
    /// zero padding, and the block loop handles every alignment.
    #[test]
    fn salt_encoding_is_injective_across_padding_and_block_edges() {
        let r = root(&[1u8; 16], &ROOT);
        assert_ne!(*salted(&r, b"a"), *salted(&r, b"a\0"));
        assert_ne!(*salted(&r, &[]), *salted(&r, &[0]));
        let mut seen = std::collections::HashSet::new();
        for len in 0..40 {
            let salt = vec![0x5au8; len];
            assert!(seen.insert(*salted(&r, &salt)), "collision at len {}", len);
        }
        // 8 + 8 bytes fills the first block exactly; 9 spills into a second.
        assert_ne!(*salted(&r, &[1u8; 8]), *salted(&r, &[1u8; 9]));
    }

    #[test]
    fn root_labels_end_outside_the_legacy_input_range() {
        for label in [b"ORE.v2.bit6.root", b"ORE.v2.chainroot"] {
            assert!(label[15] > 14, "{:?}", std::str::from_utf8(label));
            assert_eq!(label.len(), 16);
        }
    }
}
