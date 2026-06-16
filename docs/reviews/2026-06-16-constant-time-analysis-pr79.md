# Constant-Time Analysis — ore-rs (PR #79 sweep, with v2 applicability)

**Date:** 2026-06-16
**Skill:** Trail of Bits `constant-time-testing` (Phase 1 — static analysis)
**Primary scope:** `feat/ore-v2-core-refactor` (#79) — the legacy `bit2`/`Bit8`
scheme (`KnuthShufflePRP` + `Aes128Prng`).
**Cross-checked against:** `feat/ore-v2-chained` (#83) — the new v2 schemes
(`bit2_w6`/Bit6 + chained), which use `LemireFyPrp<64>`.

> Phase 2 (dudect statistical) and Phase 3 (timecop/Valgrind dynamic) were **not**
> run: Valgrind has no Apple-Silicon support, and dudect would require adding a
> dev-dependency + a CI-pinned core for stable signal. The static pass below is
> conclusive for the structural channels; dudect would empirically confirm CT-1.

## Method

Manual review of the comparator and permutation paths for the three classic
constant-time violation classes: secret-dependent branches, secret-indexed
array/memory accesses, and data-dependent loop bounds. Targets: `scheme/bit2.rs`
(comparator + encrypt), `primitives/prp.rs`, `primitives/prp/prng.rs`,
`scheme/width.rs`.

## What is correct (legacy and v2)

The comparator's first-differing-block **prefix scan is genuinely constant-time**
(`bit2.rs:240-247` on #79): it runs all `num_blocks` with `ct_eq` +
`conditional_assign`, **no early exit**, updating `l`/`is_equal` obliviously. The
branch *after* the scan (`if is_equal { return Equal }`) is on the comparison
**result**, which ORE reveals by design — not a secret-dependent timing branch.

## Findings (legacy `bit2`/Bit8 on #79)

| ID | Location (#79) | Class | Secret leaked | Severity |
|----|----------------|-------|---------------|----------|
| **CT-1** | `prp/prng.rs:54` `gen_range` rejection loop, driving the shuffle at `prp.rs:43` | data-dependent loop count | PRP seed = `PRF₂(x[0..n])` → **plaintext via encrypt timing** | High |
| **CT-2** | `prp.rs:64` `permute` → `inverse.get(input)` (and `invert` → `permutation.get`) | secret-indexed table read | plaintext byte `x[n]` | Med-High |
| **CT-3** | `prp.rs:44` `permutation.swap(i, j)` (j from `gen_range`) | secret-indexed array write | PRP seed (via keystream `j`) | Medium |
| **CT-4** | `bit2.rs:261` & `:323` `get_bit(block, xt[l])` | data-dependent array index | `xt[l]` (compare-side) | Medium |
| **CT-5** | `bit2.rs:258,260,261` accesses indexed by `l` | index by first-differing block | common-prefix length `l` | Low / by-design |

Notes:
- **CT-1** is the "shuffle that leaked time": `gen_range` loops `next_byte()` until
  `candidate <= max`, and `next_byte` triggers a fresh 16-block AES `generate()`
  every 256 draws — so rejection count *and* re-keying frequency depend on the
  key/plaintext-derived keystream.
- **CT-2** is mislabeled in source: `permute`/`invert` carry an "in constant time"
  comment (`prp.rs:58,70`) but perform plaintext-indexed lookups into a 256-byte
  (= 4 cache-line) table.
- **CT-5** is the inherent ORE *online* leakage (common-prefix length), not a defect.

## Applicability to the new v2 schemes (Bit6 + chained, `LemireFyPrp<64>`)

Verified against `feat/ore-v2-chained` (#83).

| Finding | Applies to v2? | Evidence |
|---------|----------------|----------|
| **CT-1** rejection-sampling encrypt-timing | **No — fixed** | `LemireFyPrp` uses fixed-draw Fisher-Yates + Lemire multiply-high; **no rejection loop, no `%`** (`prp.rs:120-130`, `from_stream`). Still present in Bit8/`KnuthShufflePRP` (wire-frozen legacy). |
| **CT-4** compare-side cache-line leak | **No — fixed** | All comparator byte reads route through the oblivious `width::ct_select_byte` (`width.rs:77`): the free `get_bit` in `compare_raw_slices` for bit2/bit2_w6/chained (`bit2.rs:285`, `bit2_w6.rs:294`, `chained.rs:325`) **and** `RightBlock32::get_bit` used by typed `Ord::cmp` (`block_types.rs:45`). The `>> (bit%8)` is a constant-time variable shift. |
| **CT-2** plaintext-indexed `permute` lookup | **Partially — mitigated** | `permute` still does `inverse[input]` (`prp.rs:255`), but `#[repr(C, align(64))]` + `N=64` places `inverse` on exactly one 64-byte cache line → cache-line-constant access. Residual: MemJam 4-byte sub-line only. |
| **CT-3** secret-indexed FY swap (keygen) | **Partially — mitigated** | `permutation.swap(i, j)` (secret `j`) and `inverse[val]=…` (secret `val`) still exist (`prp.rs:211-215`); each `[u8;64]` table is one cache line under `align(64)`, so writes stay line-uniform. Same MemJam sub-line residual. |
| **CT-5** index by first-differing block | **Yes — by design** | Inherent ORE online leakage; applies to every scheme. Not a defect. |

## Bottom line

- The two **genuinely actionable** legacy findings — **CT-1** (encrypt-timing) and
  **CT-4** (compare-side cache leak) — **do not apply to the new v2 schemes.** They
  are precisely what the `LemireFyPrp` switch and the `ct_select_byte` hardening
  were built to close.
- What remains in v2 (**CT-2 / CT-3**) is **structural-but-mitigated**: the PRP still
  performs secret-indexed table accesses, reduced from cache-line leaks to the
  **MemJam sub-cache-line** residual (Intel-SMT co-resident attacker only;
  ARM/AMD/non-SMT unaffected). This is the documented, deliberate default, with
  **oblivious-swap-FY** as the wire-compatible high-assurance opt-in.

## Caveats / follow-ups

1. **The mitigation is load-bearing on `LemireFyPrp` staying at `N ≤ 64`.** If a
   future width pushed it past 64 — or a `repr` change reordered the
   `permutation`/`inverse` fields — CT-2/CT-3 would silently regress from
   MemJam-only back to full cache-line leaks. The `const _: () = assert!(domain <= 64)`
   (`prp.rs:176`) guards the width; **nothing guards against a `repr` change.**
   Consider a comment / test pinning the field layout assumption.
2. **Correct the legacy "constant time" comment.** The
   "performs the inverse permutation in constant time" comment is fair for
   `LemireFyPrp<64>` at cache-line granularity, but the **identical comment on
   `KnuthShufflePRP<256>` (`prp.rs:83` on #83 / `:70` on #79) is inaccurate** — the
   256-byte, unaligned table is a real 4-line lookup. Qualify or remove it so it
   doesn't imply a guarantee the legacy type doesn't provide.
3. **dudect (Phase 2)** would empirically confirm CT-1 on the legacy scheme
   (fixed-vs-random plaintext encrypt timing, Welch's t-test). Optional; needs a
   `dudect-bencher` dev-dep and a pinned core.

## Related

- Zeroize audit of the same crate: `docs/reviews/2026-06-16-zeroize-audit-pr79.md`
  (ZA-0001: `Aes128Prng` keystream not wiped on drop — a memory-hygiene, not
  timing, issue, but in the same `prp/prng.rs`).
- v2 architecture / leakage model: `docs/plans/2026-06-12-ore-v2-architecture.md`.
