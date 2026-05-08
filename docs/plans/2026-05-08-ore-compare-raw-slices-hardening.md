# `compare_raw_slices` malformed-input hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use cipherpowers:executing-plans to implement this plan task-by-task.

**Goal:** Convert `compare_raw_slices` from "parser by faith" into "parser with bounds check" — validate that the byte-length is structurally well-formed before computing `num_blocks`. Kills the 3 mutation-testing survivors on `bit2.rs:211` and closes a real defensive gap (current code silently wraps `usize` if `a.len() < NONCE_SIZE`).

**Architecture:** Add two early-return checks at the top of `compare_raw_slices`: (1) `a.len() >= NONCE_SIZE`, (2) `(a.len() - NONCE_SIZE) % (left_size + right_size + 1) == 0`. Both return `Option::None` on failure. Add unit tests for each rejection path. Broaden property-test coverage with `u32` raw-slice variants. Re-run the constant-time analyzer to confirm the new public-data branches don't introduce secret-data leaks.

**Tech Stack:** Rust 2018, existing `quickcheck` dep. No new dependencies.

---

## Background

A genotoxic triage run (cargo-mutants 27.0.0, necessist 2.2.0, trailmark 0.8.1) reported 21/24-viable (87.5%) mutation kill rate on the comparison logic. The 3 survivors all mutate one expression at `bit2.rs:211`:

```rust
let num_blocks = (a.len() - NONCE_SIZE) / (left_size + right_size + 1);
```

| # | Mutation | For u64 ciphertext (a.len() = 408) |
|---|---|---|
| 1 | `-` → `+`: `(a.len() + 16) / 49` | `424 / 49 = 8` (truncates) — same as original |
| 2 | `+` → `-`: divisor becomes `48` | `392 / 48 = 8` (truncates) — same |
| 3 | `+` → `*`: divisor becomes `48` | same as #2 |

All three produce `num_blocks == 8` by integer truncation, so property tests on u64 inputs run identically. The expression's "boundary" — where mutated values diverge from the original — is never exercised by the existing test suite.

**The precondition fix kills all three.** Mutant 1's `424` is no longer divisible by `49` and would be rejected. Mutant 2/3's divisor of `48` causes `392 / 48 ≠ 392 / 49`, but more importantly the divisibility check `(a.len() - NONCE_SIZE) % 49 == 0` uses the unmutated divisor and rejects malformed inputs the mutated computation would accept.

**The fix also addresses an unrelated defensive gap.** The current code does `a.len() - NONCE_SIZE` on `usize` — if `a.len() < 16`, this wraps to a huge value, the division produces a junk `num_blocks`, and downstream slice indexing panics or produces garbage. The precondition makes this an explicit `None` return.

---

## Task 1: Add the length-divisibility precondition + malformed-input unit tests

**Files:**
- Modify: `packages/ore-rs/src/scheme/bit2.rs` — the body of `compare_raw_slices` (around line 188).
- Modify: `packages/ore-rs/src/scheme/bit2.rs` — the `mod tests` block (around line 514) — add two new unit tests.

**Step 1: Apply the precondition**

Replace the existing prelude of `compare_raw_slices`:

```rust
fn compare_raw_slices(a: &[u8], b: &[u8]) -> Option<Ordering> {
    if a.len() != b.len() {
        return None;
    };
    let left_size = Self::LeftBlockType::BLOCK_SIZE;
    let right_size = Self::RightBlockType::BLOCK_SIZE;

    // TODO: This calculation slows things down a bit - maybe store the number of blocks in the
    // first byte?
    let num_blocks = (a.len() - NONCE_SIZE) / (left_size + right_size + 1);
```

with:

```rust
fn compare_raw_slices(a: &[u8], b: &[u8]) -> Option<Ordering> {
    if a.len() != b.len() {
        return None;
    };
    let left_size = Self::LeftBlockType::BLOCK_SIZE;
    let right_size = Self::RightBlockType::BLOCK_SIZE;
    let block_total = left_size + right_size + 1;

    // Reject malformed ciphertexts. The byte layout is
    // `num_blocks * block_total + NONCE_SIZE`, so a.len() must be at
    // least NONCE_SIZE and the remainder must divide evenly. Without
    // this check, `a.len() - NONCE_SIZE` would wrap on undersized
    // input and `num_blocks` would be silently wrong on non-canonical
    // sizes (the latter is what cargo-mutants used to find a coverage
    // gap on this function).
    if a.len() < NONCE_SIZE {
        return None;
    }
    let body_len = a.len() - NONCE_SIZE;
    if body_len % block_total != 0 {
        return None;
    }
    let num_blocks = body_len / block_total;
```

The remaining body of the function (the `subtle_ng` prefix scan, the oblivious post-loop, and the `Ordering` encoding) is unchanged.

**Step 2: Add malformed-input unit tests**

Append next to the existing `compare_raw_slices_mismatched_lengths` test:

```rust
#[test]
fn compare_raw_slices_too_short() {
    // Both inputs equal length but shorter than NONCE_SIZE — malformed.
    // Without the precondition, a.len() - NONCE_SIZE would wrap.
    let short = vec![0u8; 8];
    assert_eq!(Ore::compare_raw_slices(&short, &short), None);
}

#[test]
fn compare_raw_slices_non_divisible_body() {
    // a.len() = 17 -> body_len = 1, not divisible by 49. Malformed.
    let weird = vec![0u8; 17];
    assert_eq!(Ore::compare_raw_slices(&weird, &weird), None);
}
```

(Both tests use `vec![0u8; ...]` directly — no encryption needed; we're exercising the precondition only.)

**Step 3: Verify**

Run: `cargo test --manifest-path packages/ore-rs/Cargo.toml`

Expected: all existing tests pass, plus the two new unit tests pass.

Run: `cargo clippy --manifest-path packages/ore-rs/Cargo.toml --all-targets -- -D warnings`

Expected: clean.

Run: `cargo fmt --manifest-path packages/ore-rs/Cargo.toml --check`

Expected: clean (the precondition's edits should be naturally fmt-compliant; if not, run `cargo fmt` and include in the same commit).

**Step 4: Commit**

```bash
git add packages/ore-rs/src/scheme/bit2.rs
git commit -m "fix(ore-rs): reject malformed ciphertext lengths in compare_raw_slices

Add an explicit length-divisibility precondition so non-canonical
byte-strings return None instead of computing a silently-wrong
num_blocks (which could underflow usize on a < NONCE_SIZE input or
produce wrong slice boundaries on lengths not in the form
N * 49 + 16).

Closes the 3 surviving cargo-mutants findings on bit2.rs:211, all of
which mutated the num_blocks expression in ways that happened to
produce the correct value for u64 inputs (the only test width).
After this change, the precondition rejects the inputs the mutated
expression would accept, and the boundary becomes test-observable.

Also closes an unrelated defensive gap: the current code's
\`a.len() - NONCE_SIZE\` wraps on undersized input."
```

---

## Task 2: Broaden raw-slice property-test coverage to `u32`

**Files:**
- Modify: `packages/ore-rs/src/scheme/bit2.rs` `quickcheck!` block in `mod tests`.

**Step 1: Add the two property-test functions**

Inside the `quickcheck! { ... }` block, after the existing `equality_u64_raw_slices` (around line 364), add:

```rust
fn compare_u32_raw_slices(x: u32, y: u32) -> bool {
    let ore = init_ore();
    let a = x.encrypt(&ore).unwrap().to_bytes();
    let b = y.encrypt(&ore).unwrap().to_bytes();

    match Ore::compare_raw_slices(&a, &b) {
        Some(Ordering::Greater) => x > y,
        Some(Ordering::Less)    => x < y,
        Some(Ordering::Equal)   => x == y,
        None                    => false
    }
}

fn equality_u32_raw_slices(x: u32) -> bool {
    let ore = init_ore();
    let a = x.encrypt(&ore).unwrap().to_bytes();
    let b = x.encrypt(&ore).unwrap().to_bytes();

    matches!(Ore::compare_raw_slices(&a, &b), Some(Ordering::Equal))
}
```

These mirror the existing u64 versions exactly. They exercise `compare_raw_slices` over a 4-block ciphertext (`u32::encrypt` produces `a.len() = 4*49 + 16 = 212`), giving the function a width that wasn't previously tested through the raw-slice path.

**Step 2: Verify**

Run: `cargo test --manifest-path packages/ore-rs/Cargo.toml`

Expected: all tests pass; the two new quickcheck properties run their default 100 iterations.

**Step 3: Commit**

```bash
git add packages/ore-rs/src/scheme/bit2.rs
git commit -m "test(ore-rs): add u32 quickcheck property tests for compare_raw_slices

Mirrors the existing u64 raw-slice properties. Exercises
compare_raw_slices over a 4-block ciphertext (a.len() = 212), giving
us property-test coverage on a width other than u64 (8 blocks).

Recommended by the genotoxic triage report: \"property tests over
varying widths\". Strictly weaker than a fuzz harness over arbitrary
&[u8] (which would also benefit the precondition added in the
previous commit), but cheap to add now."
```

---

## Task 3: Re-run the constant-time analyzer and update the baseline

The precondition adds two new branches on public input (`a.len() < NONCE_SIZE` and `body_len % block_total != 0`). These should appear as -O2 WARNs in the same category as the existing `a.len() != b.len()` warning. Re-run the analyzer and update the baseline so future regression checks have the correct reference.

**Files:**
- Modify: `packages/ore-rs/ct-analysis/baseline.O2.log` (regenerated)
- Modify: `packages/ore-rs/ct-analysis/baseline.O0.log` (regenerated)
- Modify: `packages/ore-rs/ct-analysis/README.md` (warning count + categorization)

**Step 1: Run the harness**

```bash
./packages/ore-rs/ct-analysis/run.sh \
  ~/.claude/plugins/marketplaces/trailofbits/plugins/constant-time-analysis/ct_analyzer/analyzer.py
```

**Step 2: Audit the new -O2 log**

Count the new warnings vs the previous 14. Expectation: the count goes up by ~2 for the new precondition branches. Both should be in `_ct_compare_raw_slices` at the function entry (similar to the existing `Lfunc_begin0` length-mismatch warning).

If the count goes up by more than ~2, or new warnings appear in unexpected functions, that's a regression — investigate before continuing.

**Step 3: Audit the new -O0 log**

The 1 ERROR (UDIV at line 211) should still be present at -O0 — the precondition doesn't remove it (the actual `body_len / block_total` division is still there, just guarded by the divisibility check). Confirm no NEW errors appear.

**Step 4: Update the baseline files**

```bash
cp packages/ore-rs/ct-analysis/analyzer-output/analyzer.O2.log \
   packages/ore-rs/ct-analysis/baseline.O2.log
cp packages/ore-rs/ct-analysis/analyzer-output/analyzer.O0.log \
   packages/ore-rs/ct-analysis/baseline.O0.log
```

**Step 5: Update the README's category-1 description**

In `packages/ore-rs/ct-analysis/README.md`, the "Length-mismatch early return" bullet (Category 1 in the Baseline section) should be expanded to cover all the structural-precondition branches. Replace:

```
1. **Length-mismatch early return** (1 warning, `Lfunc_begin0` in
   `compare_raw_slices`). The `if a.len() != b.len() { return None; }`
   check at `bit2.rs:189`. `a.len()` and `b.len()` are structural
   ciphertext byte-lengths, always knowable to anyone who can see
   the bytes.
```

with:

```
1. **Structural-shape preconditions** (~3 warnings in
   `compare_raw_slices`). The function rejects malformed inputs at
   entry: `a.len() != b.len()`, `a.len() < NONCE_SIZE`, and
   `(a.len() - NONCE_SIZE) % block_total != 0`. All three branch on
   public ciphertext byte-lengths (always knowable to anyone who
   can see the bytes).
```

Update the total warning count near the top of the section to match the new -O2 result.

**Step 6: Commit**

```bash
git add packages/ore-rs/ct-analysis/baseline.O2.log \
        packages/ore-rs/ct-analysis/baseline.O0.log \
        packages/ore-rs/ct-analysis/README.md
git commit -m "docs(ore-rs): refresh CT analyzer baseline after malformed-length precondition

The new precondition branches (a.len() < NONCE_SIZE and
divisibility check) add ~2 -O2 WARNs in the same category as the
existing a.len() != b.len() warning. All on public structural
input — security category unchanged.

-O2: <BEFORE> -> <AFTER> warnings, still 0 errors.
-O0: 1 error (the num_blocks division at line 213, now guarded by
the precondition) remains as before. Not security-relevant."
```

(Fill in the actual `<BEFORE>` and `<AFTER>` numbers.)

---

## Final verification

After all three tasks land:

1. `cargo test --manifest-path packages/ore-rs/Cargo.toml` — all pass.
2. `cargo clippy --manifest-path packages/ore-rs/Cargo.toml --all-targets -- -D warnings` — clean.
3. `cargo fmt --manifest-path packages/ore-rs/Cargo.toml --check` — clean.
4. Optional: re-run `cargo mutants --file packages/ore-rs/src/scheme/bit2.rs --function compare_raw_slices` and confirm the 3 line-211 mutants are now caught. (Not required if you trust the report's analysis.)

## Out of scope (for a future plan)

- **`cargo-fuzz` harness over `compare_raw_slices(a: &[u8], b: &[u8])`** — recommended by the triage report. Would catch additional malformed-input bugs that property tests miss. Significant new tooling integration; warrants its own plan.

## Skills referenced

- @cipherpowers:test-driven-development — Task 1's unit tests should be written and watched fail (without the precondition) before the precondition is added; this is what makes them meaningful regression guards.
- @cipherpowers:requesting-code-review — recommended after Task 1 (the only code change) before merging.
