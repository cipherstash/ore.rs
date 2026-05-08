# Constant-time analysis harness

This directory holds the reproducibility harness for static-analyzing the
`OreAes128` comparison code with the Trail of Bits
[`constant-time-analysis`](https://github.com/trailofbits/constant-time-analysis)
tool.

## Why

`compare_raw_slices` and `CipherText::cmp` are the two functions a
timing-side-channel attacker can probe. The body of each one was rewritten
to use `subtle_ng::Choice` / `ConstantTimeEq` so the prefix-equality scan
is data-independent, and the post-loop block lookup was made oblivious in
the unequal-block index. This harness lets us re-check that property
after future edits.

## Running

1. Clone the analyzer:
   ```
   git clone https://github.com/trailofbits/constant-time-analysis.git ~/tools/ct-analyzer
   ```
2. From the repo root:
   ```
   ./packages/ore-rs/ct-analysis/run.sh ~/tools/ct-analyzer/analyzer.py
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
