//! Chained-prefix AES-CMAC accumulator for the variable-length ORE scheme.
//!
//! Implements the design in `docs/plans/2026-06-15-ore-v2-cmac-accumulator-spec.md`
//! (plan §5b, the A2 gate). Every per-block secret of the chained scheme is a
//! `finalize(prefix-state, final_block)` — a bona fide AES-CMAC (NIST SP
//! 800-38B) tag of `P_0 ‖ … ‖ P_{n-1} ‖ final_block`, where the prefix CBC
//! state is cached and extended incrementally (`clone-state-then-finalize`
//! *is* incremental CMAC).
//!
//! All accumulator messages are exact 16-byte multiples, so only subkey `K1`
//! is ever used (the `K2`/padding path never occurs). `K1 = dbl(E_k(0))` reuses
//! the σ-MMO GF(2^128) doubling.

use crate::primitives::hash::gf128_double_u128;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use zeroize::Zeroize;

/// Block-width tag in the final block (domain separation; see the spec §4).
pub(crate) const WIDTH_BIT6: u8 = 6;

/// Output-family ("branch") tag carried in byte 0 of a final block. Encoded as
/// a non-zero enum: prefix blocks use byte 0 = `0x00`, so making this a type
/// (rather than a `u8`) removes any way to construct a final block whose byte 0
/// is `0x00` and collides with a prefix block — the disjointness is the basis
/// of the encoding's injectivity (spec §4), now guaranteed at compile time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Branch {
    RoKey = 0x01,
    PrpStream = 0x02,
}

/// Prefix block `P_t` carrying symbol `sym` at position `pos` (spec §4):
/// `[0x00 ‖ pos(u16 BE) ‖ sym ‖ 0…]`.
#[inline]
pub(crate) fn prefix_block(pos: u16, sym: u8) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[1..3].copy_from_slice(&pos.to_be_bytes());
    b[3] = sym;
    b
}

/// Final block `F(branch, n, s)` (spec §4):
/// `[branch ‖ n(u16 BE) ‖ s(u16 BE) ‖ width ‖ 0…]`. `s` is the domain value
/// `j` (or the permuted symbol `xt[n]` for the left tag) for `RoKey`, and the
/// keystream counter `c` for `PrpStream`. `branch` is a [`Branch`] (always
/// non-zero), so byte 0 can never collide with a prefix block.
#[inline]
pub(crate) fn final_block(branch: Branch, n: u16, s: u16, width: u8) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0] = branch as u8;
    b[1..3].copy_from_slice(&n.to_be_bytes());
    b[3..5].copy_from_slice(&s.to_be_bytes());
    b[5] = width;
    b
}

/// Incremental AES-CMAC over a prefix of 16-byte blocks.
///
/// `state` is the CBC-MAC chain over the prefix blocks absorbed so far (no
/// subkey applied — those are never the last block). [`finalize`](Self::finalize)
/// produces the CMAC tag of `prefix ‖ final_block` without mutating the chain;
/// [`absorb`](Self::absorb) extends the prefix.
pub(crate) struct CmacAccumulator {
    cipher: Aes128,
    k1: [u8; 16],
    state: [u8; 16],
}

impl CmacAccumulator {
    /// Schedule AES under `key`, derive `K1 = dbl(E_k(0))`, and start the chain
    /// at the all-zero CBC IV (empty prefix).
    pub(crate) fn new(key: &[u8; 16]) -> Self {
        let cipher = Aes128::new(GenericArray::from_slice(key));
        let mut acc = Self {
            cipher,
            k1: [0u8; 16],
            state: [0u8; 16],
        };
        let mut l = acc.encrypt([0u8; 16]); // L = E_k(0)
        acc.k1 = gf128_double_u128(u128::from_be_bytes(l)).to_be_bytes();
        l.zeroize(); // L is K1's source; don't leave it on the stack (spec §9)
        acc
    }

    #[inline]
    fn encrypt(&self, mut b: [u8; 16]) -> [u8; 16] {
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut b));
        b
    }

    /// Extend the prefix chain: `S ← E_k(S ⊕ block)` (a CBC step, no subkey —
    /// not a published tag).
    #[inline]
    pub(crate) fn absorb(&mut self, block: &[u8; 16]) {
        let mixed = u128::from_be_bytes(self.state) ^ u128::from_be_bytes(*block);
        self.state = self.encrypt(mixed.to_be_bytes());
    }

    /// CMAC tag of `prefix-so-far ‖ final_block`: `E_k(S ⊕ final_block ⊕ K1)`.
    /// Does not change the chain, so all outputs at a given position finalize
    /// from the one cached `S`.
    #[inline]
    pub(crate) fn finalize(&self, final_block: &[u8; 16]) -> [u8; 16] {
        let mixed = u128::from_be_bytes(self.state)
            ^ u128::from_be_bytes(*final_block)
            ^ u128::from_be_bytes(self.k1);
        self.encrypt(mixed.to_be_bytes())
    }

    #[cfg(test)]
    pub(crate) fn subkey1(&self) -> [u8; 16] {
        self.k1
    }
}

impl Drop for CmacAccumulator {
    fn drop(&mut self) {
        // `cipher` zeroizes its own key schedule (aes "zeroize" feature).
        self.k1.zeroize();
        self.state.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use quickcheck::TestResult;

    // NIST SP 800-38B, AES-128 CMAC examples (Appendix D.1). Validates that
    // this is real CMAC: the K1 subkey, the single-full-block tag, and the
    // multi-block CBC chain + finalize.
    #[test]
    fn nist_sp800_38b_aes128() {
        let k = hex!("2b7e151628aed2a6abf7158809cf4f3c");

        let acc = CmacAccumulator::new(&k);
        assert_eq!(acc.subkey1(), hex!("fbeed618357133667c85e08f7236a8de"));

        // CMAC of one full block (the block is the final block; empty prefix).
        let m1 = hex!("6bc1bee22e409f96e93d7e117393172a");
        assert_eq!(acc.finalize(&m1), hex!("070a16b46b4d4144f79bdd9dd04a287c"));

        // CMAC of four full blocks: absorb the first three, finalize the last.
        let mut acc = CmacAccumulator::new(&k);
        acc.absorb(&hex!("6bc1bee22e409f96e93d7e117393172a"));
        acc.absorb(&hex!("ae2d8a571e03ac9c9eb76fac45af8e51"));
        acc.absorb(&hex!("30c81c46a35ce411e5fbc1191a0a52ef"));
        assert_eq!(
            acc.finalize(&hex!("f69f2445df4f9b17ad2b417be66c3710")),
            hex!("51f0bebf7e3b9d92fc49741779363cfe")
        );
    }

    #[test]
    fn encoding_is_injective_on_block_type() {
        // Prefix blocks have byte 0 == 0x00; final blocks have byte 0 != 0x00.
        assert_eq!(prefix_block(7, 0x3f)[0], 0x00);
        assert_ne!(final_block(Branch::RoKey, 7, 9, WIDTH_BIT6)[0], 0x00);
        assert_ne!(final_block(Branch::PrpStream, 7, 9, WIDTH_BIT6)[0], 0x00);
        // Distinct branches / positions / sub-indices give distinct blocks.
        assert_ne!(
            final_block(Branch::RoKey, 1, 2, WIDTH_BIT6),
            final_block(Branch::PrpStream, 1, 2, WIDTH_BIT6)
        );
        assert_ne!(
            final_block(Branch::RoKey, 1, 2, WIDTH_BIT6),
            final_block(Branch::RoKey, 1, 3, WIDTH_BIT6)
        );
        assert_ne!(prefix_block(1, 2), prefix_block(2, 2));
    }

    // finalize must not disturb the cached chain: many outputs from one state.
    #[test]
    fn finalize_does_not_mutate_state() {
        let mut acc = CmacAccumulator::new(&[0x11u8; 16]);
        acc.absorb(&prefix_block(0, 5));
        let a = acc.finalize(&final_block(Branch::RoKey, 1, 0, WIDTH_BIT6));
        let _ = acc.finalize(&final_block(Branch::PrpStream, 1, 0, WIDTH_BIT6));
        let a_again = acc.finalize(&final_block(Branch::RoKey, 1, 0, WIDTH_BIT6));
        assert_eq!(a, a_again);
    }

    /// Independent from-scratch CMAC of a whole-block message: CBC-MAC chain
    /// over all but the last block, then `E_k(state ⊕ last ⊕ K1)`. Mirrors the
    /// NIST construction without reusing the accumulator's state threading, so
    /// it can validate that threading for any block count (not just t∈{1,4}).
    fn reference_cmac(key: &[u8; 16], blocks: &[[u8; 16]]) -> [u8; 16] {
        let cipher = Aes128::new(GenericArray::from_slice(key));
        let enc = |mut b: [u8; 16]| {
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut b));
            b
        };
        let k1 = gf128_double_u128(u128::from_be_bytes(enc([0u8; 16]))).to_be_bytes();
        let (last, prefix) = blocks.split_last().expect("at least one block");
        let mut state = 0u128;
        for blk in prefix {
            state = u128::from_be_bytes(enc((state ^ u128::from_be_bytes(*blk)).to_be_bytes()));
        }
        enc((state ^ u128::from_be_bytes(*last) ^ u128::from_be_bytes(k1)).to_be_bytes())
    }

    quickcheck! {
        /// Incremental absorb-then-finalize over an arbitrary number of full
        /// blocks equals a from-scratch CMAC. Validates the chain threading and
        /// subkey use for every block count, well beyond the two fixed vectors.
        fn prop_incremental_matches_reference(key: Vec<u8>, msg: Vec<u8>) -> TestResult {
            if key.len() < 16 {
                return TestResult::discard();
            }
            let mut k = [0u8; 16];
            k.copy_from_slice(&key[..16]);

            // 1..=8 full blocks, derived from `msg` (deterministic, never empty).
            let nblocks = 1 + (msg.len() % 8);
            let mut blocks = Vec::with_capacity(nblocks);
            for i in 0..nblocks {
                let mut b = [0u8; 16];
                for (j, slot) in b.iter_mut().enumerate() {
                    *slot = msg
                        .get(i * 16 + j)
                        .copied()
                        .unwrap_or((i as u8).wrapping_mul(31).wrapping_add(j as u8));
                }
                blocks.push(b);
            }

            let mut acc = CmacAccumulator::new(&k);
            let (last, prefix) = blocks.split_last().unwrap();
            for blk in prefix {
                acc.absorb(blk);
            }
            TestResult::from_bool(acc.finalize(last) == reference_cmac(&k, &blocks))
        }

        /// Final blocks injectively encode `(branch, n, s, width)`: the tuple is
        /// recoverable from the bytes and byte 0 is always non-zero, so distinct
        /// inputs give distinct blocks (and none collide with a prefix block).
        fn prop_final_block_injective(n: u16, s: u16, width: u8) -> bool {
            [Branch::RoKey, Branch::PrpStream].iter().copied().all(|branch| {
                let fb = final_block(branch, n, s, width);
                fb[0] == branch as u8
                    && fb[0] != 0x00
                    && u16::from_be_bytes([fb[1], fb[2]]) == n
                    && u16::from_be_bytes([fb[3], fb[4]]) == s
                    && fb[5] == width
            })
        }

        /// Prefix blocks carry byte0 == 0x00 (never colliding with a final
        /// block) and injectively encode `(pos, sym)`.
        fn prop_prefix_block_injective(pos: u16, sym: u8) -> bool {
            let pb = prefix_block(pos, sym);
            pb[0] == 0x00 && u16::from_be_bytes([pb[1], pb[2]]) == pos && pb[3] == sym
        }
    }
}
