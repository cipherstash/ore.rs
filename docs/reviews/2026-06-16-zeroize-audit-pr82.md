# Zeroize Audit — ore-rs PR #82 (Bit6 scheme + v2 wire format)

**Date:** 2026-06-16
**Skill:** Trail of Bits `zeroize-audit` (preflight → Rust source → MIR/LLVM-IR/asm)
**Branch:** `feat/ore-v2-bit6` (#82), aarch64 host, `--cfg aes_armv8` (hardware AES)
**Verdict:** **Clean — no new zeroization gaps in #82's crypto code.**

## Scope

#82 adds the crypto core: `LemireFyPrp` (`primitives/prp.rs`), the `OreAes128Bit6`
cipher (`scheme/bit2_w6.rs`), the σ-MMO hash `FixedPiZ2Hash` (`primitives/hash.rs`),
and the v2 wire header. The audit asked whether the new key-derived material is
wiped on drop, and whether those wipes survive compiler optimization.

## Source analysis (Phase 1)

All new secret-bearing code zeroizes correctly:

| Type | Status |
|---|---|
| `LemireFyPrp<N>` (`prp.rs`) | OK — `Zeroize` + manual `Drop` + `ZeroizeOnDrop` marker (matches `KnuthShufflePRP`). The AES-CTR keystream built in `new()` is wiped after the permutation is constructed (`stream.zeroize()` + per-block `as_mut_slice().zeroize()`); the AES key schedule is covered by the `aes` crate's own `ZeroizeOnDrop`. |
| `OreAes128Bit6` (`bit2_w6.rs`) | OK — `#[derive(ZeroizeOnDrop)]` over `prf1`/`prf2`; `rng` correctly `#[zeroize(skip)]`. `SeedBuf` wipes each seed `AesBlock` on `Drop`. |
| Bit6 encrypt scratch | OK — per-block `template`/`work` RO-key buffers zeroized after the encrypt loop. |
| `FixedPiZ2Hash` (`hash.rs`) | Correctly **not** flagged — `PI_KEY` is a fixed, public nothing-up-my-sleeve AES key; the `Hash::new` parameter is a per-ciphertext nonce. Neither is a secret. |

Dangerous-API scan (`mem::forget` / `ManuallyDrop` / `Box::leak` / `transmute` /
`ptr::write_bytes` / `mem::take` / secret-across-`.await`): **0 hits**, grep-confirmed.

## Compiler analysis (Phase 2) — wipes survive `-O2`

Crate-wide `store volatile` count rises **2 (O0) → 6 (O1) → 384 (O2)** and
`compiler_fence` **8 → 296**: the wipes *multiply* under inlining, they do not
disappear. **Zero `OPTIMIZED_AWAY_ZEROIZE`** (the 3 "volatile dropped" IR diffs
are un-inlined zeroize wrappers that fully inline at O2; the 204 other `memset`
hits are non-volatile init/alloc, no O0→O2 diff).

Confirmed surviving at O2:
1. `LemireFyPrp::new` — 41 volatile stores + 26 `seq_cst` fences (keystream byte
   wipes + the AES-block zeroize); Drop-triggered `permutation`/`inverse` wipe via
   `drop_in_place` (22 volatile stores).
2. `OreAes128Bit6` — `template`/`work` + `SeedBuf` drop wipes inlined into callers.
3. `aes::Aes128` key schedule under `--cfg aes_armv8` — `drop_in_place::<…armv8…>`
   retains volatile-store + fence at O2 (matches the #79 run).

Assembly (aarch64, **experimental** backend): 0 `STACK_RETENTION` / `REGISTER_SPILL`.
MIR: 5 `needs_review` name-matches, all on the already-verified legacy bit2 path.

## Findings

| ID | Severity | Status |
|---|---|---|
| **ZA-0001** — legacy `Aes128Prng` lacks `Drop`/`ZeroizeOnDrop` | medium | Pre-existing, **not** a #82 issue. Fixed on **PR #84** (off `main`); the stack inherits it on rebase. |
| `SECRET_COPY` — `#[derive(Debug)]` on `OreAes128Bit6` | low | Benign (matches the bit2 sibling; `Aes128` Debug is opaque). **Addressed in #82** by replacing the derive with an explicit opaque `Debug` impl. |

**No PoC phase:** the only exploitable finding (ZA-0001) is already PoC-verified
and fixed on #84.

## Related

- Constant-time analysis (v2 applicability): `docs/reviews/2026-06-16-constant-time-analysis-pr79.md`
- ZA-0001 zeroize audit + fix: `docs/reviews/2026-06-16-zeroize-audit-pr79.md`, PR #84
