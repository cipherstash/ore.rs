# ORE bit2 constant-time remediation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use cipherpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close out the remaining constant-time gaps in `OreAes128`'s comparison and encryption paths so a timing observer learns nothing beyond the `Ordering` result that ORE intentionally exposes.

**Architecture:** Refactor `compare_raw_slices` and `CipherText::cmp` to (a) eliminate the data-dependent post-loop lookup on the unequal-block index `l` by hashing all `N` blocks and selecting via `subtle_ng::ConditionallySelectable`, (b) replace the final `if test == 1` branch with a branchless `Ordering` selection, and (c) make `get_bit`/`set_bit` and the encrypt-side `cmp(a,b)` UDIV-free and branchless at every optimization level. Stay on the existing `subtle-ng` dependency. Commit a reproducible analyzer harness (cargo example + script) so the constant-time property can be re-checked after future changes.

**Tech Stack:** Rust 2018 edition, `subtle-ng = 2.5.0` (already a dep), `aes 0.8`, `criterion 0.5` (existing benches), `quickcheck 1.0` (existing tests). Static analyzer: Trail of Bits `constant-time-analysis` (external; the repo just provides a reproducible build target for it).

---

## Background — what is and isn't already done

The report this plan responds to assumes the original (pre-`subtle_ng`) code. The current code at `packages/ore-rs/src/scheme/bit2.rs` has already partially mitigated **Findings 1 & 2** (the prefix-equality scan):

- The early `break` is gone — both `compare_raw_slices` and `CipherText::cmp` iterate the full block range.
- The first-differing-block index `l` and `is_equal` flag are accumulated via `subtle_ng::Choice::conditional_assign`.
- The PRP byte (`a[n] / xt[n]`) and PRF block (16-byte `LeftBlock16` / `f[n]`) are compared with `subtle_ng::ConstantTimeEq::ct_eq` rather than `!=` / `slice::eq`, so within-block byte short-circuit and OR short-circuit between PRP/PRF are gone.

What remains:

| Finding | Status | Where | Severity |
|---|---|---|---|
| 1 — early break leaks `l` | **Done** (verify in re-audit) | `bit2.rs:206-213`, `:272-278` | HIGH |
| 2 — within-block short-circuit | **Done** (verify in re-audit) | same | MEDIUM |
| 3 — data-dep post-loop lookup | **Open** | `bit2.rs:221-227`, `:286-289` | LOW (cache-line bounded) |
| 4 — final order branch | **Open** | `bit2.rs:229-233`, `:290-294` | LOW (intrinsic, but reduce footprint) |
| 5 — UDIV in `get_bit`/`set_bit` | **Open** | `bit2.rs:251-259`, `block_types.rs:23-41` | MEDIUM at -O0 |
| Bonus — `cmp(a,b)` on encrypt path | **Open** | `bit2.rs:50-52` | LOW (encryptor holds plaintext) |

Decisions baked into this plan:
- **Stay on `subtle-ng`** — already wired through the dep tree; both forks are interface-compatible. No churn.
- **Hide block index `l`, accept within-block byte index from `a[l]`** — every `RightBlock32` fits in a single 64-byte cache line, and the report categorizes the within-block leak as LOW. Going fully oblivious on the byte-within-block index would require reading all 256 bits of every block per comparison, which is a much larger perf hit than the user has signed up for.
- **Reproducible analyzer harness** — committed as a cargo example with `#[no_mangle]` wrappers, plus a shell script. No CI gate (per user choice).

---

## Task 1: Set up reproducible constant-time analyzer harness

Why first: gives every later task an objective check ("did this make the analyzer happier?") and locks the verification recipe so anyone can re-run it.

**Files:**
- Create: `packages/ore-rs/examples/ct_extract.rs`
- Create: `packages/ore-rs/ct-analysis/run.sh`
- Create: `packages/ore-rs/ct-analysis/README.md`
- Modify: `packages/ore-rs/Cargo.toml` (add `[[example]]` entry)
- Modify: `.gitignore` (ignore analyzer output `*.s`, `analyzer-output/`)

**Step 1: Create the cargo example with `#[no_mangle]` wrappers**

The wrappers force stable, demangled symbols the analyzer can find by name regardless of generic monomorphization. They reference the public surface of `OreAes128ChaCha20` so the analyzer sees the real (post-monomorphization, post-inlining) machine code.

Write `packages/ore-rs/examples/ct_extract.rs`:

```rust
//! Self-contained re-export of constant-time-sensitive functions for static
//! analysis. Build with:
//!
//!     cargo rustc --release --example ct_extract -- --emit=asm
//!
//! Then point the constant-time-analysis tool at the emitted .s file under
//! `target/release/examples/ct_extract-*.s`. See `ct-analysis/README.md`.
//!
//! These wrappers exist so the analyzer can find stable demangled symbols.
//! Without them every comparison call site would be a different mangled
//! generic, and the analyzer would have to grep across many functions.

use std::cmp::Ordering;

use ore_rs::{scheme::bit2::OreAes128ChaCha20, CipherText, OreCipher};

#[no_mangle]
pub extern "Rust" fn ct_compare_raw_slices(a: &[u8], b: &[u8]) -> Option<Ordering> {
    OreAes128ChaCha20::compare_raw_slices(a, b)
}

#[no_mangle]
pub extern "Rust" fn ct_ciphertext_cmp_n8(
    a: &CipherText<OreAes128ChaCha20, 8>,
    b: &CipherText<OreAes128ChaCha20, 8>,
) -> Ordering {
    a.cmp(b)
}

fn main() {
    // The example only exists so cargo emits asm for the wrappers.
    // Touch each symbol so dead-code elimination can't remove them.
    let _ = ct_compare_raw_slices(&[], &[]);
}
```

**Step 2: Add the example entry to `Cargo.toml`**

Modify `packages/ore-rs/Cargo.toml`, adding under the existing `[[example]]` section near line 63-64:

```toml
[[example]]
name = "ct_extract"
```

(Keep the existing `[[example]] name = "encrypt"` entry intact.)

**Step 3: Write the analyzer driver script**

Write `packages/ore-rs/ct-analysis/run.sh`:

```bash
#!/usr/bin/env bash
# Reproducibility harness for the Trail of Bits constant-time-analysis tool.
#
# Prereqs:
#   - The constant-time-analysis tool checked out somewhere on disk.
#     Pass its analyzer.py path as $CT_ANALYZER, or as $1.
#   - rustc / cargo for the project's pinned toolchain.
#
# Usage:
#   ./run.sh /path/to/ct_analyzer/analyzer.py
#
# Or with env var:
#   CT_ANALYZER=/path/to/analyzer.py ./run.sh
#
# Output goes to ct-analysis/analyzer-output/.

set -euo pipefail

ANALYZER="${1:-${CT_ANALYZER:-}}"
if [[ -z "$ANALYZER" ]]; then
  echo "ERROR: pass the analyzer.py path as \$1 or set \$CT_ANALYZER." >&2
  exit 2
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

OUT="packages/ore-rs/ct-analysis/analyzer-output"
mkdir -p "$OUT"

# The analyzer is host-arch sensitive. Default to the host triple; allow override.
HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
TARGET="${CT_TARGET:-$HOST_TRIPLE}"

# Map rustc target -> analyzer arch flag. Extend as needed.
case "$TARGET" in
  aarch64-*) ANALYZER_ARCH=arm64 ;;
  x86_64-*)  ANALYZER_ARCH=x86_64 ;;
  *) echo "ERROR: unsupported target $TARGET" >&2; exit 2 ;;
esac

emit_asm () {
  local profile="$1"  # "release" or "dev"
  local opt_label="$2" # "O2" or "O0"
  local rustflags=()
  if [[ "$profile" == "release" ]]; then
    rustflags+=(-C opt-level=2)
  else
    rustflags+=(-C opt-level=0)
  fi
  echo "==> Building ct_extract example with $opt_label ($TARGET)..."
  RUSTFLAGS="${rustflags[*]}" cargo rustc \
    --manifest-path packages/ore-rs/Cargo.toml \
    --target "$TARGET" \
    $([[ "$profile" == "release" ]] && echo --release) \
    --example ct_extract \
    -- --emit=asm
  # Locate the emitted .s. Cargo names it with a hash suffix.
  local asm
  asm=$(find target/"$TARGET"/$([[ "$profile" == "release" ]] && echo release || echo debug)/examples \
        -maxdepth 1 -name 'ct_extract-*.s' -print -quit)
  cp "$asm" "$OUT/ct_extract.$opt_label.s"
}

emit_asm release O2
emit_asm dev O0

echo "==> Running analyzer (-O2)..."
uv run --quiet "$ANALYZER" --assembly --arch "$ANALYZER_ARCH" --warnings \
  "$OUT/ct_extract.O2.s" | tee "$OUT/analyzer.O2.log"

echo "==> Running analyzer (-O0)..."
uv run --quiet "$ANALYZER" --assembly --arch "$ANALYZER_ARCH" --warnings \
  "$OUT/ct_extract.O0.s" | tee "$OUT/analyzer.O0.log"

echo
echo "Output written to: $OUT/"
```

Make it executable: `chmod +x packages/ore-rs/ct-analysis/run.sh` (the commit will preserve the bit).

**Step 4: Write the README**

Write `packages/ore-rs/ct-analysis/README.md`:

```markdown
# Constant-time analysis harness

This directory holds the reproducibility harness for static-analyzing the
`OreAes128` comparison code with the Trail of Bits
[`constant-time-analysis`](https://github.com/trailofbits/skills/tree/main/plugins/constant-time-analysis)
Claude Code skill (a plugin in the `trailofbits/skills` monorepo, not a
standalone repo).

## Why

`compare_raw_slices` and `CipherText::cmp` are the two functions a
timing-side-channel attacker can probe. The body of each one was rewritten
to use `subtle_ng::Choice` / `ConstantTimeEq` so the prefix-equality scan
is data-independent, and the post-loop block lookup was made oblivious in
the unequal-block index. This harness lets us re-check that property
after future edits.

## Running

1. Clone the Trail of Bits skills monorepo:
   ```
   git clone https://github.com/trailofbits/skills.git ~/tools/trailofbits-skills
   ```
2. From the repo root, point the harness at the plugin's `analyzer.py`:
   ```
   ./packages/ore-rs/ct-analysis/run.sh \
     ~/tools/trailofbits-skills/plugins/constant-time-analysis/analyzer.py
   ```
3. Inspect `packages/ore-rs/ct-analysis/analyzer-output/`:
   - `analyzer.O2.log` — release-equivalent. Should contain **0 ERROR** findings.
     A small number of WARN-level conditional branches in the final
     `Ordering` selection are intrinsic to the comparison's contract.
   - `analyzer.O0.log` — debug. Will have UDIV findings in loop bookkeeping
     that the optimizer removes; only ERRORs in `get_bit` / `set_bit` /
     `cmp(u8, u8)` are security-relevant.

## Targets

Defaults to the host triple. Cross-compile with `CT_TARGET=...`. The script
maps rustc targets to analyzer arch flags (`arm64`, `x86_64`).
```

**Step 5: Update `.gitignore`**

Modify `.gitignore` to add the analyzer output directory:

```
# constant-time-analysis output (regenerated by ct-analysis/run.sh)
packages/ore-rs/ct-analysis/analyzer-output/
```

**Step 6: Verify the example builds**

Run: `cargo build --manifest-path packages/ore-rs/Cargo.toml --example ct_extract`

Expected: clean build, no warnings.

Run: `cargo rustc --manifest-path packages/ore-rs/Cargo.toml --release --example ct_extract -- --emit=asm`

Expected: produces an `.s` file under `target/release/examples/ct_extract-*.s`.

**Step 7: Commit**

```bash
git add packages/ore-rs/examples/ct_extract.rs \
        packages/ore-rs/ct-analysis/ \
        packages/ore-rs/Cargo.toml \
        .gitignore
git commit -m "chore(ore-rs): add reproducible constant-time analyzer harness

Adds a cargo example exposing #[no_mangle] wrappers around
compare_raw_slices and CipherText::cmp, plus a script that emits asm at
-O0 and -O2 and runs the Trail of Bits constant-time-analysis tool.
This is the verification harness used in subsequent commits to confirm
constant-time fixes."
```

---

## Task 2: Finding 5 — replace `bit / 8` and `bit % 8` with shift/mask

The optimizer rewrites `/8` and `%8` to shifts at `-O2`, but emits `UDIV` (and on ARM Cortex-A, that's data-dependent timing) at `-O0`. Three sites have the pattern; this task fixes all three in one commit.

**Files:**
- Modify: `packages/ore-rs/src/scheme/bit2.rs:251-259` (`get_bit` free fn)
- Modify: `packages/ore-rs/src/scheme/bit2/block_types.rs:22-29` (`RightBlock32::set_bit`)
- Modify: `packages/ore-rs/src/scheme/bit2/block_types.rs:33-41` (`RightBlock32::get_bit`)
- Modify: `packages/ore-rs/src/scheme/bit2/block_types.rs` tests — strengthen `set_and_get_bit`

**Step 1: Strengthen the existing test to cover all 256 bit positions**

The current test at `block_types.rs:92-103` only checks bits 17, 180, 255. Make it cover the full range so any indexing regression is caught.

In `packages/ore-rs/src/scheme/bit2/block_types.rs`, replace the `set_and_get_bit` test:

```rust
#[test]
fn set_and_get_bit() {
    for bit in 0..256usize {
        let mut block: RightBlock32 = Default::default();
        block.set_bit(bit, 1);
        assert_eq!(block.get_bit(bit), 1, "set+get bit {bit}");
        // Other positions are untouched.
        for other in (0..256usize).filter(|&i| i != bit) {
            assert_eq!(block.get_bit(other), 0, "bit {other} after setting bit {bit}");
        }
    }
}
```

Run: `cargo test --manifest-path packages/ore-rs/Cargo.toml --lib scheme::bit2::block_types::tests::set_and_get_bit`

Expected: PASS (the current implementation is correct, just compiler-sensitive).

**Step 2: Replace divisions in `RightBlock32::set_bit` and `get_bit`**

In `packages/ore-rs/src/scheme/bit2/block_types.rs`, change `set_bit`:

```rust
#[inline]
pub fn set_bit(&mut self, bit: usize, value: u8) {
    debug_assert!(bit < 256);
    let byte_index = bit >> 3;
    let position = bit & 0b111;
    let v = value << position;
    self.data[byte_index] |= v;
}
```

Note: rename `mask` to `position` for naming consistency with `get_bit` (the value is the bit *position*, not a *mask*).

Change `get_bit`:

```rust
#[inline]
pub fn get_bit(&self, bit: usize) -> u8 {
    debug_assert!(bit < 256);
    let byte_index = bit >> 3;
    let position = bit & 0b111;
    (self.data[byte_index] >> position) & 1
}
```

The shift-then-AND form is one less instruction than `(byte & (1 << pos)) >> pos` and survives at every opt level.

**Step 3: Replace divisions in the free `get_bit` in `bit2.rs`**

In `packages/ore-rs/src/scheme/bit2.rs:251-259`, change to:

```rust
#[inline]
fn get_bit(block: &[u8], bit: usize) -> u8 {
    debug_assert!(block.len() == RightBlock32::BLOCK_SIZE);
    debug_assert!(bit < 256);
    let byte_index = bit >> 3;
    let position = bit & 0b111;
    (block[byte_index] >> position) & 1
}
```

**Step 4: Run all tests**

Run: `cargo test --manifest-path packages/ore-rs/Cargo.toml`

Expected: all existing tests pass. The strengthened `set_and_get_bit` runs ~65k assertions but should complete in milliseconds.

**Step 5: Re-run the analyzer**

Run: `./packages/ore-rs/ct-analysis/run.sh /path/to/analyzer.py`

Expected: the `analyzer.O0.log` shows `get_bit` and `set_bit` no longer flagged with UDIV ERRORs. Loop-counter UDIVs unrelated to security may persist; document any that remain in the commit message.

**Step 6: Commit**

```bash
git add packages/ore-rs/src/scheme/bit2.rs \
        packages/ore-rs/src/scheme/bit2/block_types.rs
git commit -m "fix(ore-rs): make get_bit/set_bit constant-time at -O0 (Finding 5)

Replace bit/8 and bit%8 with >>3 and &0b111 in RightBlock32::set_bit,
RightBlock32::get_bit, and the free get_bit in bit2.rs. With -O2 the
compiler folded the divisions into shifts, but at -O0 (cargo test
without --release, debug downstream consumers) it emitted UDIV, which
on ARM Cortex-A has data-dependent execution time.

Also broaden the set_and_get_bit unit test to cover all 256 positions
so any future indexing regression is caught."
```

---

## Task 3: Bonus — branchless `cmp(a, b)` on encrypt path

The encryptor already holds the plaintext, but in a shared-CPU multi-tenant setting the branch leaks plaintext bits to a co-resident attacker.

**Files:**
- Modify: `packages/ore-rs/src/scheme/bit2.rs:50-52`

**Step 1: Replace the branch with `subtle_ng::ConstantTimeGreater`**

`subtle-ng 2.5` provides `ConstantTimeGreater::ct_gt(&self, other: &Self) -> Choice` for `u8`. This is the cleanest way and matches the rest of the file's idiom.

Modify `bit2.rs:50-52`:

```rust
fn cmp(a: u8, b: u8) -> u8 {
    use subtle_ng::ConstantTimeGreater;
    a.ct_gt(&b).unwrap_u8()
}
```

(`Choice::unwrap_u8` returns the underlying `0u8`/`1u8` byte — same shape as the original return.)

**Step 2: Run all tests**

Run: `cargo test --manifest-path packages/ore-rs/Cargo.toml`

Expected: all pass. The `compare_u64`, `compare_u32`, `compare_f64` quickcheck properties exercise this `cmp` indirectly via every encryption.

**Step 3: Re-run the analyzer**

Expected: WARN/ERROR findings related to `scheme_bit2_cmp` (the free function, distinct from `CipherText::cmp`) are gone. The function should compile to a few arithmetic ops with no `B.NE`/`B.HI`/`CBZ`.

**Step 4: Commit**

```bash
git add packages/ore-rs/src/scheme/bit2.rs
git commit -m "fix(ore-rs): make encrypt-path cmp(u8, u8) branchless (Bonus)

Replace u8::from(a > b) with subtle_ng::ConstantTimeGreater::ct_gt.
The encryptor already holds the plaintext, but a shared-CPU co-resident
attacker can observe the branch via timing. ct_gt compiles to a fixed
sequence of arithmetic ops at every optimization level."
```

---

## Task 4: Finding 4 — branchless final `Ordering` selection

The two functions both end with:

```rust
if test == 1 { return Some(Ordering::Greater); }
Some(Ordering::Less)
```

`test` is a single bit derived from the comparison; the branch on it can compile to either a `cmov` (constant-time) or a `b.eq`/`b.ne` (data-dependent). We make the selection explicit and branchless via `subtle_ng::ConditionallySelectable` on an `i8` encoding, then convert to `Ordering` at the very end. The `is_equal` short-circuit (`if bool::from(is_equal) { return Equal }`) folds into the same branchless selection.

Encoding: `Greater = 1`, `Equal = 0`, `Less = -1` (an `i8`). The final `match` on a 3-valued integer is necessarily a control-flow construct, but its argument is the comparison's externally visible output — that's the "intrinsic" branch the report acknowledges. We're shrinking the branchful surface to that one final lookup.

**Files:**
- Modify: `packages/ore-rs/src/scheme/bit2.rs:188-234` (`compare_raw_slices`)
- Modify: `packages/ore-rs/src/scheme/bit2.rs:267-295` (`CipherText::cmp`)

**Step 1: Add a small helper to convert `i8 ∈ {-1, 0, 1}` to `Ordering`**

Place near the top of `bit2.rs`, after the existing `cmp(a, b)` helper (around line 53):

```rust
/// Branchless-friendly conversion from a tristate i8 (`-1` = Less,
/// `0` = Equal, `1` = Greater) to `std::cmp::Ordering`. This is the
/// single observable branch in the comparison's externally visible
/// contract; everything before it is constant-time.
#[inline]
fn ordering_from_i8(t: i8) -> Ordering {
    match t {
        1 => Ordering::Greater,
        0 => Ordering::Equal,
        _ => Ordering::Less,
    }
}
```

**Step 2: Rewrite the tail of `compare_raw_slices`**

Replace the current tail (the section starting at `if bool::from(is_equal)` through the final `Some(Ordering::Less)`):

```rust
let l: usize = l as usize;

let b_right = &b[num_blocks * (left_size + 1)..];
let hash_key = HashKey::from_slice(&b_right[0..NONCE_SIZE]);
let hash: Aes128Z2Hash = Hash::new(hash_key);
let h = hash.hash(left_block(a_f, l));
let target_block = right_block(&b_right[NONCE_SIZE..], l);
let test = get_bit(target_block, a[l] as usize) ^ h;

// Encode as i8: 1 = Greater, -1 = Less, 0 = Equal.
// `test` is 0 or 1, so (test as i8) * 2 - 1 is +1 or -1.
let mut order: i8 = (test as i8) * 2 - 1;
order.conditional_assign(&0i8, is_equal);

Some(ordering_from_i8(order))
```

> NOTE: this step still uses `l` and `a[l]` for the post-loop hash and bit lookup. **Finding 3** (Task 5) replaces that with the oblivious form. We split the work because the branchless ordering change is mechanically separable and individually verifiable.

**Step 3: Rewrite the tail of `CipherText::cmp`**

Replace the current tail similarly:

```rust
let l: usize = l as usize;

let hash: Aes128Z2Hash = Hash::new(AesBlock::from_slice(&b.right.nonce));
let h = hash.hash(&self.left.f[l]);
let test = b.right.data[l].get_bit(self.left.xt[l] as usize) ^ h;

let mut order: i8 = (test as i8) * 2 - 1;
order.conditional_assign(&0i8, is_equal);

ordering_from_i8(order)
```

**Step 4: Run all tests**

Run: `cargo test --manifest-path packages/ore-rs/Cargo.toml`

Expected: all pass. Pay special attention to:
- `equality_u64`, `equality_u32`, `equality_f64` (the `is_equal` arm)
- `compare_u64`, `compare_u32`, `compare_f64` (Greater/Less arms)
- `smallest_to_largest`, `largest_to_smallest`, `smallest_to_smallest`, `largest_to_largest`
- `signed_zeros_compare_equal` (the +0/-0 regression test)

**Step 5: Re-run the analyzer**

Expected: the WARN list shrinks. The branches inside `compare_raw_slices` and `ciphertext_cmp` collapse to a single match in `ordering_from_i8` (the intrinsic branch). Document the remaining WARN count in the commit message.

**Step 6: Run benchmarks (sanity, not gating)**

Run: `cargo bench --manifest-path packages/ore-rs/Cargo.toml --bench oreaes128 -- compare`

Expected: `compare-8`, `compare-8-slice`, `compare-4` are within noise of pre-change numbers (this change shouldn't move them — it's the same number of arithmetic ops, just shaped differently).

**Step 7: Commit**

```bash
git add packages/ore-rs/src/scheme/bit2.rs
git commit -m "refactor(ore-rs): branchless final Ordering selection (Finding 4)

Encode the comparison result as i8 (1=Greater, 0=Equal, -1=Less),
combine with subtle_ng::ConditionallySelectable for the is_equal
short-circuit, and only branch in a single helper that converts the
i8 to Ordering. The remaining branch is on the comparison's externally
visible output and is intrinsic to its contract.

Both compare_raw_slices and CipherText::cmp share the new shape."
```

---

## Task 5: Finding 3 — oblivious post-loop block lookup

This is the most consequential change. Currently the tail of each comparison reads exactly one `LeftBlock16` (at index `l`) and one `RightBlock32` (at index `l`), and reads one bit (at offset `a[l]` / `xt[l]`) from the right block. The block index `l` is data-dependent, so an attacker with cache-set or controlled-channel observation can learn it. We hide `l` by hashing **all** blocks and using `subtle_ng::ConditionallySelectable` to pick the contribution at index `l`.

We do **not** hide the byte-within-block index from `a[l] / xt[l]`. Each `RightBlock32` is 32 bytes — well inside a 64-byte cache line — so the within-block index is unlikely to leak via cache timing. The report categorizes this as LOW risk and recommends only the block-level fix. Hiding the within-block index too would require reading all 256 bits of every block per comparison, which doubles the perf cost again.

Perf cost: comparison goes from 1 hash to `num_blocks` hashes (8 for `u64`, 15 max). Encryption is unaffected. The user-facing benches (`compare-8`, `compare-4`, `compare-8-slice`) will show the regression.

**Files:**
- Modify: `packages/ore-rs/src/scheme/bit2.rs` (`compare_raw_slices` tail; `CipherText::cmp` tail)

**Step 1: Capture a benchmark baseline**

Before the change, save current numbers:

```bash
cargo bench --manifest-path packages/ore-rs/Cargo.toml --bench oreaes128 -- compare \
  | tee /tmp/ore-compare-baseline.txt
```

Note the `compare-8`, `compare-8-slice`, `compare-4` numbers.

**Step 2: Make `compare_raw_slices` oblivious in `l`**

Replace the post-loop section (after `let l: usize = l as usize;` from Task 4) with:

```rust
let l: usize = l as usize;

let b_right = &b[num_blocks * (left_size + 1)..];
let hash_key = HashKey::from_slice(&b_right[0..NONCE_SIZE]);
let hash: Aes128Z2Hash = Hash::new(hash_key);
let right_data = &b_right[NONCE_SIZE..];

// Hash every block, use subtle_ng to pick the contribution at index l.
// `test` ends up holding the masked bit from the unequal block; for all
// other blocks it stays 0. Constant-time because the conditional_assign
// is byte-wise CT and the loop runs unconditionally over num_blocks.
let mut test: u8 = 0;
for n in 0..num_blocks {
    let is_target: Choice = (n as u64).ct_eq(&(l as u64));
    let h_n = hash.hash(left_block(a_f, n));
    let target_block_n = right_block(right_data, n);
    let bit_n = get_bit(target_block_n, a[n] as usize);
    let candidate = bit_n ^ h_n;
    test.conditional_assign(&candidate, is_target);
}

let mut order: i8 = (test as i8) * 2 - 1;
order.conditional_assign(&0i8, is_equal);

Some(ordering_from_i8(order))
```

`a[n] as usize` is now indexed by the loop counter `n`, not by ciphertext-derived `l`. The index `a[n]` is still ciphertext-derived (selecting one of 32 bytes within `target_block_n`), but per the threat-model decision above we accept that.

`u8: ConditionallySelectable` is provided by `subtle-ng`, so `test.conditional_assign(&candidate, is_target)` compiles.

**Step 3: Make `CipherText::cmp` oblivious in `l`**

Replace the post-loop section similarly:

```rust
let l: usize = l as usize;

let hash: Aes128Z2Hash = Hash::new(AesBlock::from_slice(&b.right.nonce));

let mut test: u8 = 0;
for n in 0..N {
    let is_target: Choice = (n as u64).ct_eq(&(l as u64));
    let h_n = hash.hash(&self.left.f[n]);
    let bit_n = b.right.data[n].get_bit(self.left.xt[n] as usize);
    let candidate = bit_n ^ h_n;
    test.conditional_assign(&candidate, is_target);
}

let mut order: i8 = (test as i8) * 2 - 1;
order.conditional_assign(&0i8, is_equal);

ordering_from_i8(order)
```

`N` is a compile-time const so the loop unrolls.

**Step 4: Run all tests**

Run: `cargo test --manifest-path packages/ore-rs/Cargo.toml`

Expected: all pass. Special attention to the long-form quickchecks — they cover differing-block-positions across the entire range.

**Step 5: Run benchmarks and record the regression**

```bash
cargo bench --manifest-path packages/ore-rs/Cargo.toml --bench oreaes128 -- compare \
  | tee /tmp/ore-compare-after-finding3.txt
```

Compare against baseline. Expect:
- `compare-8` and `compare-8-slice`: roughly 8× slower (one hash per block, eight blocks).
- `compare-4`: roughly 4× slower.

Document the actual numbers in the commit message.

**Step 6: Re-run the analyzer**

Expected: the cluster of WARN findings related to the post-loop indexing in `ciphertext_cmp` and `compare_raw_slices` is gone (the block lookup is now a CT-masked accumulator, not a `B.NE`-driven branch).

**Step 7: Commit**

```bash
git add packages/ore-rs/src/scheme/bit2.rs
git commit -m "fix(ore-rs): oblivious post-loop block lookup (Finding 3)

Iterate every block in compare_raw_slices and CipherText::cmp,
combining each block's hash-XOR-bit contribution into the test result
via subtle_ng::ConditionallySelectable. Hides the unequal-block index
\`l\` from cache-set and controlled-channel observers.

Within-block byte index from a[n]/xt[n] is intentionally not hidden —
RightBlock32 fits in a single cache line and the report categorizes
the within-block leak as LOW.

Perf: comparison cost grows from 1 hash to N hashes (N = 8 for u64,
15 max). Encryption is unchanged.

Bench delta vs main on aarch64-apple-darwin:
  compare-8       <BEFORE> -> <AFTER>  (~Nx)
  compare-8-slice <BEFORE> -> <AFTER>
  compare-4       <BEFORE> -> <AFTER>"
```

(Fill in the actual `<BEFORE>`/`<AFTER>` numbers from Step 5 before committing.)

---

## Task 6: Re-audit Findings 1 & 2; document the analyzer baseline

> **Status:** Complete. `aarch64-apple-darwin` baseline captured after rebasing onto `feat/trailmark` (which provides the Trail of Bits Claude Code plugins). Result: -O2 PASSED (0 errors, 14 intrinsic warnings); -O0 FAILED with 1 ERROR — the `num_blocks` UDIV at `bit2.rs:211` on public inputs only, optimizer-folded at -O2, not security-relevant.

Run the analyzer one more time on the post-fix code, confirm the prefix-equality scan has no remaining ERRORs and only intrinsic WARNs (the final `match` in `ordering_from_i8`), and commit the analyzer's clean baseline log so future PRs can diff against it.

**Files:**
- Create: `packages/ore-rs/ct-analysis/baseline.O2.log` (analyzer output, post-fix)
- Create: `packages/ore-rs/ct-analysis/baseline.O0.log` (analyzer output, post-fix)
- Modify: `packages/ore-rs/ct-analysis/README.md` (add a "What the baseline contains" section)
- Modify: `.gitignore` (un-ignore `baseline.*.log`, keep `analyzer-output/` ignored)

**Step 1: Run the analyzer harness clean**

```bash
./packages/ore-rs/ct-analysis/run.sh /path/to/analyzer.py
```

**Step 2: Audit the `-O2` log**

For each WARN in `analyzer-output/analyzer.O2.log`, classify by hand. Acceptable categories:
- The final `match` inside `ordering_from_i8` (the intrinsic branch).
- Compiler-inserted bounds checks on slice indexing where the index is a public input (e.g. loop counter `n` in `0..num_blocks`).

Anything that does NOT fit one of those categories is a regression — go back to the relevant Task and fix.

**Step 3: Audit the `-O0` log**

Confirm the only ERRORs left are loop-counter UDIVs (which the optimizer removes at -O2 and which are not security-relevant — they index loop counters, not ciphertext). All `get_bit`/`set_bit`/`cmp` UDIVs should be gone after Tasks 2 and 3.

**Step 4: Save and commit the baseline logs**

Copy the cleaned-up logs to versioned locations:

```bash
cp packages/ore-rs/ct-analysis/analyzer-output/analyzer.O2.log \
   packages/ore-rs/ct-analysis/baseline.O2.log
cp packages/ore-rs/ct-analysis/analyzer-output/analyzer.O0.log \
   packages/ore-rs/ct-analysis/baseline.O0.log
```

**Step 5: Update `.gitignore`**

Modify the entry added in Task 1 to keep `baseline.*.log` tracked while still ignoring `analyzer-output/`:

```
packages/ore-rs/ct-analysis/analyzer-output/
```

(No change needed if the existing rule is precisely `analyzer-output/`. If you instead used a broader pattern like `*.log`, replace it with the directory pattern above.)

**Step 6: Add a "What the baseline contains" section to the README**

Append to `packages/ore-rs/ct-analysis/README.md`:

```markdown

## Baseline

`baseline.O2.log` and `baseline.O0.log` are the analyzer outputs from the
last clean run. To check whether your change regressed the constant-time
property:

1. Run `./run.sh ...`
2. Diff `analyzer-output/analyzer.O2.log` against `baseline.O2.log`.
3. New WARNs/ERRORs are regressions and need root-cause analysis before
   merging. (The plan in `docs/plans/2026-05-08-ore-constant-time-remediation.md`
   documents the categorization of acceptable WARNs.)
```

**Step 7: Commit**

```bash
git add packages/ore-rs/ct-analysis/baseline.O2.log \
        packages/ore-rs/ct-analysis/baseline.O0.log \
        packages/ore-rs/ct-analysis/README.md \
        .gitignore
git commit -m "docs(ore-rs): commit constant-time analyzer baseline

After Findings 3, 4, 5, and Bonus are fixed and Findings 1 and 2 are
re-verified, capture the analyzer's clean baseline output for both
opt levels. Future PRs that touch bit2.rs or block_types.rs should
diff against this baseline; new ERRORs or unrecognized WARNs are
regressions and need root-cause analysis before merging."
```

---

## Final verification (no commit, just sanity)

After all six tasks land:

1. `cargo test --manifest-path packages/ore-rs/Cargo.toml` — all pass.
2. `cargo clippy --manifest-path packages/ore-rs/Cargo.toml --all-targets -- -D warnings` — clean.
3. `cargo bench --manifest-path packages/ore-rs/Cargo.toml --bench oreaes128` — record the final numbers and update CHANGELOG with the perf delta on `compare-*`.
4. `./packages/ore-rs/ct-analysis/run.sh ...` — diff against baseline; expect no diff.

## Why the order

| Task | Risk | Reversibility | Why before/after neighbors |
|---|---|---|---|
| 1 — Harness | None | Trivially revert | Lets every later task be objectively verified. |
| 2 — Bit shifts | None (mech.) | Trivial | Independent; cheap; touches different files than 3-5. |
| 3 — `cmp(a,b)` | None (mech.) | Trivial | Independent of 4 and 5; cheap. |
| 4 — Branchless ordering | Low | Easy | Must precede 5 — Task 5 builds on the i8 encoding. |
| 5 — Oblivious lookup | Medium (perf) | Easy | The semantically heavy change. Bench-gated. |
| 6 — Re-audit | None | N/A | Verification only. |

## Skills referenced

- @cipherpowers:test-driven-development — Task 2 follows the failing-test-first cycle (extended unit test runs first; existing tests stay green throughout).
- @cipherpowers:systematic-debugging — if any task's analyzer run shows unexpected new WARNs, use this to trace the regression to its source before adding follow-up patches.
- @cipherpowers:requesting-code-review — recommended after Tasks 4 and 5 (the two semantically meaningful changes) before merging.
