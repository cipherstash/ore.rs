# Zeroize Audit — ore-rs PR #83 (chained-prefix variable-length scheme)

**Date:** 2026-06-16
**Skill:** Trail of Bits `zeroize-audit` (preflight → Rust source analysis)
**Branch:** `feat/ore-v2-chained` (#83), aarch64 host, `--cfg aes_armv8`
**Verdict:** two new gaps found and **fixed** in `f498990`; no remaining new gaps.

> **Amended 2026-10-08** (review of #90): the verdict missed two more gaps.
> `CmacAccumulator::absorb` and `finalize` each build an owned `mixed` value
> from the chain state (and, in `finalize`, `K1`) and returned without
> wiping it; and `from_stream`'s per-draw keystream copy (see the #82 audit)
> applies here too. Both are fixed: on #83 in "harden(cmac): wipe the mixed
> state temporaries in absorb and finalize", and on #82. The wipes remove the
> source-level copies; they cannot rule out copies the compiler keeps in
> registers or spills, and no IR evidence was gathered for them.

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
| **`CmacAccumulator::absorb` / `finalize` `mixed` temporaries** | ❌→✅ **was a gap** (missed by this audit) — state/`K1`-derived values left on the stack. **Fixed** on #83 (see the note above). |
| chained `k_acc` Drop | ✅ wiped |
| chained `stream` (PRP keystream, `prp_at`) | ✅ `stream.zeroize()` |
| `from_stream` consumed stream | ✅ caller-owned; both callers wipe. **Amended:** the per-draw `draw`/`x` copies inside `from_stream` were not wiped; fixed on #82. |
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
