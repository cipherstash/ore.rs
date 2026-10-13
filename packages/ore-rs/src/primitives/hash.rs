use crate::primitives::{AesBlock, Hash, HashKey};
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128Enc;
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct Aes128Z2Hash {
    cipher: Aes128Enc,
}

impl Hash for Aes128Z2Hash {
    fn new(key: &HashKey) -> Self {
        let key_array = GenericArray::from_slice(key);
        let cipher = Aes128Enc::new(key_array);
        Self { cipher }
    }

    fn hash(&self, data: &[u8; 16]) -> u8 {
        let mut block = AesBlock::from(*data);
        self.cipher.encrypt_block(&mut block);
        block[0] & 1u8
    }

    fn hash_all_into<const D: usize, const B: usize>(
        &self,
        data: &mut [AesBlock; D],
        out: &mut [u8; B],
    ) {
        self.cipher.encrypt_blocks(data);

        // Pack the Z2 (1-bit) outputs LSB-first, eight blocks per byte —
        // the same bit order as `RightBlock32::set_bit`.
        crate::primitives::simd::lsb_mask(data, out);
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
/// `H`'s first input is not always secret: a left ciphertext publishes the RO
/// key at its own symbol, and the comparator hashes it. For the *unrevealed*
/// RO keys, `σ(k) ⊕ r` is a secret shared across ciphertexts plus public
/// per-ciphertext nonces, which is the BHKR correlation-robustness setting;
/// security rests on its multi-instance bound (about `p·C/2^128` for `p`
/// offline `π` queries against `C` targeted keys), not on the inputs being
/// secret. The orthomorphism `σ` is what puts the construction in that named
/// setting. See review brief A1 (restated, pending sign-off). The cryptanalysis of round-reduced AES hashing (eprint 2025/792)
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

fn pi() -> &'static Aes128Enc {
    use std::sync::OnceLock;
    static PI: OnceLock<Aes128Enc> = OnceLock::new();
    PI.get_or_init(|| Aes128Enc::new(GenericArray::from_slice(&PI_KEY)))
}

/// GF(2^128) doubling `2·x` on a big-endian field element packed in a `u128`
/// — the BHKR/Zahur orthomorphism `σ` ("multiply by x"; reduction polynomial
/// x^128 + x^7 + x^2 + x + 1, constant `0x87`). A single shift plus a
/// branch-free conditional XOR, replacing the per-byte carry loop that
/// dominated the σ-MMO hot path (≈704 doublings per Bit6 u64 encrypt).
/// Constant-time: no secret-dependent control flow.
#[inline]
pub(crate) fn gf128_double_u128(x: u128) -> u128 {
    // `x << 1` discards the top bit (the GF reduction trigger); fold 0x87 into
    // the low byte iff that bit was set. `x >> 127` is 0 or 1. Also the CMAC
    // subkey doubling (`crate::primitives::cmac`).
    (x << 1) ^ ((x >> 127) * 0x87)
}

/// In-place GF(2^128) doubling `b ← 2·b` on a big-endian field element.
/// Used by the scalar comparator path; the bulk
/// encrypt path folds the doubling and nonce XOR into one `u128` pass (see
/// `hash_all_into`).
#[inline]
fn gf128_double(b: &mut [u8; 16]) {
    *b = gf128_double_u128(u128::from_be_bytes(*b)).to_be_bytes();
}

impl Hash for FixedPiZ2Hash {
    fn new(nonce: &HashKey) -> Self {
        Self { nonce: *nonce }
    }

    fn hash(&self, data: &[u8; 16]) -> u8 {
        // BHKR σ-MMO: m = σ(x) ⊕ r; return lsb(π(m) ⊕ m).
        let mut block = *data;
        gf128_double(&mut block); // σ(x) = 2x
        for (slot, &r) in block.iter_mut().zip(self.nonce.iter()) {
            *slot ^= r; // m = σ(x) ⊕ r
        }
        let m_lsb = block[0] & 1u8;
        let mut block = AesBlock::from(block);
        pi().encrypt_block(&mut block);
        (block[0] & 1u8) ^ m_lsb
    }

    fn hash_all_into<const D: usize, const B: usize>(
        &self,
        data: &mut [AesBlock; D],
        out: &mut [u8; B],
    ) {
        // BHKR σ-MMO: m = σ(x) ⊕ r, then out = lsb(m) ^ lsb(π(m)), with
        // σ(x) = 2x in GF(2^128). Form m in place first so the feedforward
        // captures lsb(m) rather than lsb(x). Doubling and nonce XOR are fused
        // into one u128 pass per block — this is the 704-evals/u64 hot loop.
        let nonce = u128::from_be_bytes(self.nonce.into());
        for block in data.iter_mut() {
            let m = gf128_double_u128(u128::from_be_bytes((*block).into())) ^ nonce;
            *block = m.to_be_bytes().into();
        }

        // feedforward lsb(m)
        crate::primitives::simd::lsb_mask(data, out);

        pi().encrypt_blocks(data); // π(m)

        let mut pi_mask = [0u8; B];
        crate::primitives::simd::lsb_mask(data, &mut pi_mask);
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

    // The comparator uses the scalar `hash`; encryption uses the bulk
    // `hash_all_into`. For the BHKR σ-MMO they must agree bit-for-bit, over
    // both the scalar (n=64, the Bit6 domain) and SIMD (n=256) `lsb_mask`
    // backends.
    #[test]
    fn fixed_pi_scalar_matches_bulk() {
        let nonce: [u8; 16] = hex!("0f0e0d0c 0b0a0908 07060504 03020100");
        let h: FixedPiZ2Hash = Hash::new(GenericArray::from_slice(&nonce));

        check::<64, 8>(&h);
        check::<256, 32>(&h);

        fn check<const D: usize, const B: usize>(h: &FixedPiZ2Hash) {
            let mut blocks = [AesBlock::default(); D];
            for (i, block) in blocks.iter_mut().enumerate() {
                for (j, slot) in block.iter_mut().enumerate() {
                    *slot = (i.wrapping_mul(31).wrapping_add(j)) as u8;
                }
            }

            let mut expected = [0u8; B];
            for (i, b) in blocks.iter().enumerate() {
                expected[i / 8] |= h.hash(&(*b).into()) << (i % 8);
            }

            let mut out = [0u8; B];
            h.hash_all_into(&mut blocks, &mut out);
            assert_eq!(out, expected, "scalar vs bulk mismatch for n={}", D);
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

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Reference GF(2^128) doubling on a big-endian byte string (NIST SP
    /// 800-38B `dbl`): shift left one bit across bytes, then XOR `0x87`
    /// into the last byte iff the dropped MSB was set.
    fn dbl_reference(b: [u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        for k in 0..16 {
            let next_msb = if k + 1 < 16 { b[k + 1] >> 7 } else { 0 };
            out[k] = (b[k] << 1) | next_msb;
        }
        if b[0] & 0x80 != 0 {
            out[15] ^= 0x87;
        }
        out
    }

    /// `gf128_double_u128` and the in-place `gf128_double` both equal the
    /// bytewise reference `dbl` for every 128-bit input (full domain).
    #[kani::proof]
    #[kani::unwind(17)]
    fn gf128_double_matches_reference() {
        let b: [u8; 16] = kani::any();
        let expected = dbl_reference(b);
        assert_eq!(
            gf128_double_u128(u128::from_be_bytes(b)).to_be_bytes(),
            expected
        );
        let mut in_place = b;
        gf128_double(&mut in_place);
        assert_eq!(in_place, expected);
    }
}
