use crate::primitives::{AesBlock, Hash, HashKey};
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct Aes128Z2Hash {
    cipher: Aes128,
}

impl Hash for Aes128Z2Hash {
    fn new(key: &HashKey) -> Self {
        let key_array = GenericArray::from_slice(key);
        let cipher = Aes128::new(key_array);
        Self { cipher }
    }

    fn hash(&self, data: &[u8]) -> u8 {
        /*
         * Slice size is not known at compile time so we assert here
         * We could do this with compile checks but this would require an additional
         * copy (and doesn't entirely avoid runtime checks anyway)
         * See https://stackoverflow.com/questions/38168956/take-slice-of-certain-length-known-at-compile-time
         */
        assert_eq!(data.len(), 16);
        // Can we clone into GenericArray directly? Are we doing an extra copy?
        let mut output = [0u8; 16];
        output.clone_from_slice(data);
        let block = GenericArray::from_mut_slice(&mut output);
        self.cipher.encrypt_block(block);
        output[0] & 1u8
    }

    fn hash_all_into(&self, data: &mut [AesBlock], out: &mut [u8]) {
        debug_assert_eq!(out.len() * 8, data.len());
        self.cipher.encrypt_blocks(data);

        // Pack the Z2 (1-bit) outputs LSB-first, eight blocks per byte —
        // the same bit order as `RightBitVec::set_bit`. The 256-block case
        // (Bit8's per-block RO output) has a vectorised gather; other sizes
        // use the scalar pack.
        if data.len() == 256 {
            crate::primitives::simd::lsb_mask_256(data, out);
        } else {
            crate::primitives::simd::scalar::lsb_mask(data, out);
        }
    }
}

/// Z2 hash instantiated as `LSB(π(x ⊕ r) ⊕ x)` with `π` a *fixed public*
/// AES-128 permutation and `r` the per-ciphertext nonce — the
/// fixed-key-AES MMO construction proposed in the v2 plan §6 (option 3),
/// analysed in the random-permutation model (cf. BHKR13 / GKWY20).
///
/// The `Hash::new` "key" parameter carries the **nonce** (same calling
/// convention as [`Aes128Z2Hash`], which uses the nonce as an AES key);
/// the AES key here is the public constant [`PI_KEY`] and is expanded
/// once per process.
///
/// **Status: pending crypto review** (v2 plan §6) — used only by post-v2
/// schemes whose wire format is not yet frozen.
pub struct FixedPiZ2Hash {
    nonce: AesBlock,
}

/// The public, fixed AES key for `π`. Nothing-up-my-sleeve: the ASCII
/// bytes of `"ORE-rs.v2.H-pi.1"`. This key is deliberately *not* secret —
/// the construction's security rests on AES being a good public random
/// permutation, not on key secrecy (the comparator must be able to
/// evaluate H with no key material).
pub const PI_KEY: [u8; 16] = *b"ORE-rs.v2.H-pi.1";

fn pi() -> &'static Aes128 {
    use std::sync::OnceLock;
    static PI: OnceLock<Aes128> = OnceLock::new();
    PI.get_or_init(|| Aes128::new(GenericArray::from_slice(&PI_KEY)))
}

impl Hash for FixedPiZ2Hash {
    fn new(nonce: &HashKey) -> Self {
        Self { nonce: *nonce }
    }

    fn hash(&self, data: &[u8]) -> u8 {
        assert_eq!(data.len(), 16);
        let x_lsb = data[0] & 1u8;
        let mut block = [0u8; 16];
        for (slot, (&x, &r)) in block.iter_mut().zip(data.iter().zip(self.nonce.iter())) {
            *slot = x ^ r;
        }
        let block = GenericArray::from_mut_slice(&mut block);
        pi().encrypt_block(block);
        (block[0] & 1u8) ^ x_lsb
    }

    fn hash_all_into(&self, data: &mut [AesBlock], out: &mut [u8]) {
        debug_assert_eq!(out.len() * 8, data.len());

        // Feedforward: capture the x LSBs before overwriting, then
        // out = lsb(x) ^ lsb(π(x ⊕ r)).
        if data.len() == 256 {
            crate::primitives::simd::lsb_mask_256(data, out);
        } else {
            crate::primitives::simd::scalar::lsb_mask(data, out);
        }

        for block in data.iter_mut() {
            for (slot, &r) in block.iter_mut().zip(self.nonce.iter()) {
                *slot ^= r;
            }
        }
        pi().encrypt_blocks(data);

        let mut pi_mask = [0u8; 32];
        let pi_mask = &mut pi_mask[..out.len()];
        if data.len() == 256 {
            crate::primitives::simd::lsb_mask_256(data, pi_mask);
        } else {
            crate::primitives::simd::scalar::lsb_mask(data, pi_mask);
        }
        for (slot, &m) in out.iter_mut().zip(pi_mask.iter()) {
            *slot ^= m;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn init_hash() -> Aes128Z2Hash {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        let key_array = GenericArray::from_slice(&key);
        Hash::new(key_array)
    }

    #[test]
    fn hash_test_1() {
        let hash = init_hash();
        let input: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0eaa");

        assert_eq!(1u8, hash.hash(&input));
    }

    #[test]
    fn hash_test_2() {
        let hash = init_hash();
        let input: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");

        assert_eq!(0u8, hash.hash(&input));
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn hash_test_input_too_small() {
        let hash = init_hash();
        let input: [u8; 8] = hex!("00010203 04050607");

        assert_eq!(0u8, hash.hash(&input));
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn hash_test_input_too_large() {
        let hash = init_hash();
        let input: [u8; 24] = hex!("00010203 04050607 ffffffff bbbbbbbb cccccccc abababab");

        hash.hash(&input);
    }
}
