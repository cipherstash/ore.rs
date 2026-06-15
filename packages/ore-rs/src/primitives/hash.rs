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

/// Z2 hash instantiated as the BHKR fixed-key-AES **σ-MMO** construction:
/// `H(x, r) = LSB(π(σ(x) ⊕ r) ⊕ σ(x) ⊕ r)`, where `π` is a *fixed public*
/// AES-128 permutation (public key [`PI_KEY`]), `r` is the per-ciphertext
/// nonce, and `σ(x) = 2·x` is the GF(2^128) doubling orthomorphism (the
/// BHKR/Zahur linear orthomorphism; both `σ` and `σ ⊕ id` are permutations).
/// v2 plan §6 option 3 — **A1 resolved 2026-06-15** — analysed in the
/// random-permutation model (BHKR13; GKWY20; Guo–Katz–Wang–Weng–Yu, eprint
/// 2019/1168).
///
/// The orthomorphism `σ` is the only departure from plain MMO and is adopted
/// as cheap defense-in-depth, not to fix a present weakness: the known attacks
/// on fixed-key MMO (GKWY; the half-gates attack of eprint 2019/1168) require
/// *known, Free-XOR-correlated* hash inputs plus a recoverable global offset —
/// neither of which ORE has, since its `H` inputs are independent **secret**
/// PRF outputs and there is no global offset. `σ` makes the construction
/// secure by matching the named BHKR/Zahur hash rather than by a usage
/// argument. The cryptanalysis of round-reduced AES hashing (eprint 2025/792)
/// targets collision/preimage/one-wayness — properties this 1-bit hash does
/// not rely on — and never reaches full-round AES-128.
///
/// The `Hash::new` "key" parameter carries the **nonce** `r`; the AES key is
/// the public constant [`PI_KEY`], expanded once per process.
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

/// In-place GF(2^128) doubling `b ← 2·b` — the BHKR/Zahur orthomorphism `σ`
/// (the same "multiply by x" used for CMAC subkey derivation; reduction
/// polynomial x^128 + x^7 + x^2 + x + 1, constant `0x87`). Constant-time:
/// fixed trip count, branch-free reduction, no secret-dependent control flow.
/// `b` must be exactly 16 bytes (big-endian field element).
#[inline]
fn gf128_double(b: &mut [u8]) {
    debug_assert_eq!(b.len(), 16);
    let msb = b[0] >> 7; // bit shifted out of the top; capture before mutating
    let mut carry = 0u8;
    for i in (0..16).rev() {
        let next = (b[i] << 1) | carry;
        carry = b[i] >> 7;
        b[i] = next;
    }
    b[15] ^= msb.wrapping_mul(0x87); // conditional reduction, branch-free
}

impl Hash for FixedPiZ2Hash {
    fn new(nonce: &HashKey) -> Self {
        Self { nonce: *nonce }
    }

    fn hash(&self, data: &[u8]) -> u8 {
        assert_eq!(data.len(), 16);
        // BHKR σ-MMO: m = σ(x) ⊕ r; return lsb(π(m) ⊕ m).
        let mut block = [0u8; 16];
        block.copy_from_slice(data);
        gf128_double(&mut block); // σ(x) = 2x
        for (slot, &r) in block.iter_mut().zip(self.nonce.iter()) {
            *slot ^= r; // m = σ(x) ⊕ r
        }
        let m_lsb = block[0] & 1u8;
        let block = GenericArray::from_mut_slice(&mut block);
        pi().encrypt_block(block);
        (block[0] & 1u8) ^ m_lsb
    }

    fn hash_all_into(&self, data: &mut [AesBlock], out: &mut [u8]) {
        debug_assert_eq!(out.len() * 8, data.len());

        // BHKR σ-MMO: m = σ(x) ⊕ r, then out = lsb(m) ^ lsb(π(m)), with
        // σ(x) = 2x in GF(2^128). Form m in place first so the feedforward
        // captures lsb(m) rather than lsb(x).
        for block in data.iter_mut() {
            gf128_double(block.as_mut_slice()); // σ(x)
            for (slot, &r) in block.iter_mut().zip(self.nonce.iter()) {
                *slot ^= r; // m = σ(x) ⊕ r
            }
        }

        // feedforward lsb(m)
        if data.len() == 256 {
            crate::primitives::simd::lsb_mask_256(data, out);
        } else {
            crate::primitives::simd::scalar::lsb_mask(data, out);
        }

        pi().encrypt_blocks(data); // π(m)

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

    // The comparator uses the scalar `hash`; encryption uses the bulk
    // `hash_all_into`. For the BHKR σ-MMO they must agree bit-for-bit, over
    // both the scalar (n=64, the Bit6 domain) and SIMD (n=256) `lsb_mask`
    // backends.
    #[test]
    fn fixed_pi_scalar_matches_bulk() {
        let nonce: [u8; 16] = hex!("0f0e0d0c 0b0a0908 07060504 03020100");
        let h: FixedPiZ2Hash = Hash::new(GenericArray::from_slice(&nonce));

        for &n in &[64usize, 256usize] {
            let mut blocks: Vec<AesBlock> = (0..n)
                .map(|i| {
                    let mut b = [0u8; 16];
                    for (j, slot) in b.iter_mut().enumerate() {
                        *slot = (i.wrapping_mul(31).wrapping_add(j)) as u8;
                    }
                    *GenericArray::from_slice(&b)
                })
                .collect();

            let mut expected = vec![0u8; n / 8];
            for (i, b) in blocks.iter().enumerate() {
                expected[i / 8] |= h.hash(b.as_slice()) << (i % 8);
            }

            let mut out = vec![0u8; n / 8];
            h.hash_all_into(&mut blocks, &mut out);
            assert_eq!(out, expected, "scalar vs bulk mismatch for n={}", n);
        }
    }

    // σ(x) = 2x must be an orthomorphism: both σ and σ⊕id are permutations.
    // Spot-check the GF(2^128) doubling against the textbook shift/0x87 rule.
    #[test]
    fn gf128_double_reduction() {
        // High bit clear: pure left shift.
        let mut b = [0u8; 16];
        b[15] = 0x01;
        gf128_double(&mut b);
        let mut want = [0u8; 16];
        want[15] = 0x02;
        assert_eq!(b, want);

        // High bit set: shift then XOR 0x87 into the low byte.
        let mut b = [0u8; 16];
        b[0] = 0x80;
        gf128_double(&mut b);
        let mut want = [0u8; 16];
        want[15] = 0x87;
        assert_eq!(b, want);
    }
}
