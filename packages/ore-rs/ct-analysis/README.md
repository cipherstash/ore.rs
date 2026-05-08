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

## Baseline

`baseline.O2.log` and `baseline.O0.log` are the analyzer outputs from
the last clean run on `aarch64-apple-darwin`.

**`baseline.O2.log` — release-equivalent (the security-relevant one):**
- Result: PASSED
- 0 errors, 14 warnings.
- The 14 WARNs are intrinsic to the comparison's contract: the final
  3-arm `match` in `ordering_from_i8` (the externally visible
  `Ordering` output is necessarily branchful) and a few compiler-inserted
  slice bounds checks where the index is a public-input loop counter.

**`baseline.O0.log` — debug builds:**
- Result: FAILED (1 error, 37 warnings).
- The 1 ERROR is a `UDIV` at `bit2.rs:211` (`(a.len() - NONCE_SIZE) /
  (left_size + right_size + 1)`). Both operands are public: `a.len()`
  is the structural ciphertext length (always knowable to anyone who
  sees the bytes), and the divisor is a compile-time constant `49`.
  The optimizer folds it to a multiply at -O2 (hence O2 passes).
  Not security-relevant.
- WARN-level findings at -O0 are dominated by loop-counter arithmetic
  the optimizer removes at -O2.

To check whether your change regressed the constant-time property:

1. Run `./run.sh ~/.claude/plugins/marketplaces/trailofbits/plugins/constant-time-analysis/ct_analyzer/analyzer.py`
   (or whatever path your plugin install resolves to).
2. Diff `analyzer-output/analyzer.O2.log` against `baseline.O2.log`.
3. New WARNs/ERRORs are regressions and need root-cause analysis before
   merging. The plan in `docs/plans/2026-05-08-ore-constant-time-remediation.md`
   documents the categorization of acceptable findings.

The companion [`trailmark`](https://github.com/trailofbits/trailmark)
tool can be used to determine the blast radius of any newly-flagged
function (which callers would be affected).
