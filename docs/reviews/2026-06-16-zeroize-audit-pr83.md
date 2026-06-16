# Zeroize Audit — ore-rs PR #83 (chained-prefix variable-length scheme)

**Date:** 2026-06-16
**Skill:** Trail of Bits `zeroize-audit` (preflight → Rust source analysis)
**Branch:** `feat/ore-v2-chained` (#83), aarch64 host, `--cfg aes_armv8`
**Verdict:** two new gaps found and **fixed** in `f498990`; no remaining new gaps.

## Scope

#83 adds the CMAC accumulator (`primitives/cmac.rs`) and the chained
variable-length scheme (`scheme/chained.rs`), plus `LemireFyPrp::from_stream`.
The audit checked whether the new key-derived material — the accumulator subkeys
and state, the per-block RO-key tags, the PRP keystream, and the cipher key — is
wiped, on the struct Drop and in the per-block local buffers.

## Source analysis

| Item | Status |
|---|---|
| `CmacAccumulator` Drop (`k1`, `state`) | ✅ wiped; `cipher` via aes `ZeroizeOnDrop` |
| chained `k_acc` Drop | ✅ wiped |
| chained `stream` (PRP keystream, `prp_at`) | ✅ `stream.zeroize()` |
| `from_stream` consumed stream | ✅ caller-owned; both callers wipe |
| **`L = E_k(0)` in `CmacAccumulator::new`** | ❌→✅ **was a gap** — `K1 = dbl(L)`'s source, left on the stack. **Fixed:** `l.zeroize()` after deriving `k1`. |
| **chained `ro` RO-tag buffer (`encrypt_var`)** | ❌→✅ **was a gap** — 64 key-derived CMAC tags, never wiped (the sibling `bit2_w6` wipes its `template`/`work`). **Fixed:** per-block `ro` wipe after the right block is built. |

Dangerous-API scan: 0 hits (`mem::forget`/`ManuallyDrop`/`Box::leak`/`transmute`/
`write_bytes`/`mem::take`/secret-across-`.await`), grep-confirmed. No `Copy` on
secret types; `Clone`/`Debug` only on published-ciphertext containers.

`FixedPiZ2Hash` `PI_KEY` correctly not flagged (fixed public key). **ZA-0001**
(legacy `Aes128Prng`) re-surfaced — pre-existing, fixed on **PR #84**, inherited
on rebase.

## Compiler/PoC phases

Skipped: the two findings were *missing*-wipe (source-conclusive, nothing for an
IR diff to do), and the existing wipes use the same `zeroize`-crate volatile+fence
API already IR-verified surviving `-O2` on #79/#82. After the fix, the new `L`/`ro`
wipes use that same API.

## Related

- Code review + constant-time on #83 (left-vs-right comparator added; Branch
  enum; single-key init): see PR #83 discussion.
- ZA-0001 fix: `docs/reviews/2026-06-16-zeroize-audit-pr79.md`, PR #84.
- #82 zeroize audit: `docs/reviews/2026-06-16-zeroize-audit-pr82.md`.
