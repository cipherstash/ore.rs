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
     A small number of WARN-level conditional branches remain — see the
     "Baseline" section below for the categorization.
   - `analyzer.O0.log` — debug. Will have UDIV findings in loop bookkeeping
     that the optimizer removes; only ERRORs in `get_bit` / `set_bit` /
     `cmp(u8, u8)` are security-relevant.

## Targets

Defaults to the host triple. Cross-compile with `CT_TARGET=...`. The script
maps rustc targets to analyzer arch flags (`arm64`, `x86_64`).

## Baseline

`baseline.O2.log` and `baseline.O0.log` are the analyzer outputs from
the last clean run on `aarch64-apple-darwin`.

**`baseline.O2.log` — release-equivalent (the security-relevant one):**
- Result: PASSED
- 0 errors, 15 warnings.
- All 15 WARNs are conditional branches on **public structural data** —
  not on secrets. They fall into four categories (decoded by reading
  the asm; rustc emits no `.loc` markers in `--release --emit=asm`,
  so labels were mapped to source semantically):

  1. **Structural-shape preconditions** (2 flagged warnings, both at
     `Lfunc_begin0` in `compare_raw_slices`). The function rejects
     malformed inputs at entry: `a.len() != b.len()` (B.NE), `a.len()
     < NONCE_SIZE` (B.LO — the analyzer doesn't flag this opcode but
     it's there in the asm), and `(a.len() - NONCE_SIZE) %
     block_total != 0` (CBNZ). All branch on public ciphertext
     byte-lengths (always knowable to anyone who can see the bytes).
  2. **Loop continuation/termination on public counters** (~5 warnings).
     The prefix-equality scan and the oblivious post-loop walk both
     iterate `0..num_blocks`; the loop-back conditions and the
     iterator's `take()` upper-bound checks branch on `n` vs
     `num_blocks` / `a.len()` — all public.
  3. **Compiler-inserted slice bounds-check panic paths** (~4 warnings).
     `a[n]`, `b[n]`, and `right_data[n*32 + ...]` indexing emits a
     panic-if-out-of-bounds branch. `n` is the public loop counter;
     these branches are dead code in practice (the indices are always
     in range by construction) but the compiler keeps them.
  4. **Zeroize-on-drop loops** (~2 warnings, `;MEMBARRIER` annotated
     in the asm). The `subtle_ng::Choice` and AES key state are
     zeroized when going out of scope; the zeroize loop's continuation
     branch is on the buffer size — public/structural.

  The 11/3 split between `compare_raw_slices` and `CipherText::cmp`
  reflects the iterator-form loop in the former (`a.iter().enumerate().take(num_blocks)`)
  introducing extra take-bound + iterator-end checks vs the const-N
  loop in the latter (`for n in 0..N`).

  Notably absent: the `ordering_from_i8` 3-arm match. It was inlined
  and elided — `t ∈ {-1, 0, 1}` already matches `Ordering`'s
  `#[repr(i8)]` discriminants (`Less=-1, Equal=0, Greater=1`), so the
  match compiles to a no-op cast. The comparison's externally visible
  `Ordering` output is still the externally observable result, but
  there's no residual branch attributable to it in this asm.

**`baseline.O0.log` — debug builds:**
- Result: FAILED (2 errors, 39 warnings).
- Both ERRORs are `UDIV` instructions in the precondition + body of
  `compare_raw_slices`: `body_len % block_total` (the divisibility
  check) and `body_len / block_total` (the actual `num_blocks`
  computation). Both have the same security profile: operands are
  `a.len() - NONCE_SIZE` (structural ciphertext length, public) and
  the compile-time constant `49`. The optimizer folds both to
  multiply-by-magic-number at -O2 (hence -O2 passes). Not
  security-relevant.
- WARN-level findings at -O0 are dominated by loop-counter arithmetic
  the optimizer removes at -O2.

To check whether your change regressed the constant-time property:

1. Run `./run.sh ~/.claude/plugins/marketplaces/trailofbits/plugins/constant-time-analysis/ct_analyzer/analyzer.py`
   (or whatever path your plugin install resolves to).
2. Diff `analyzer-output/analyzer.O2.log` against `baseline.O2.log`.
3. New WARNs/ERRORs are regressions and need root-cause analysis before
   merging. Acceptable categories are documented in the four-bullet list
   above; anything outside those four is a regression.

The companion [`trailmark`](https://github.com/trailofbits/trailmark)
tool can be used to determine the blast radius of any newly-flagged
function (which callers would be affected).
