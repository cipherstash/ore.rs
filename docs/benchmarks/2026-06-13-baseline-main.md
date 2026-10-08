# Benchmark baseline — main @ 3f92c45

Recorded as the reference point for the ORE v2 performance work
(`docs/plans/2026-06-12-ore-v2-architecture.md`, PR 1). Criterion baseline
name: `main-baseline` (in `target/criterion`, not committed — these numbers
are the durable record).

**Machine:** Apple M1 Max (aarch64, NEON + ARMv8 crypto extensions), macOS,
rustc 1.87.0, `cargo bench --bench oreaes128`.

| Benchmark | Median | Notes |
|---|---|---|
| encrypt-8 (u64) | 381.1 µs | full Left+Right, 8 blocks |
| encrypt-left-8 (u64) | 91.1 µs | Left only |
| compare-8 | 738.8 ns | typed `Ord` |
| compare-8-slice | 743.5 ns | `compare_raw_slices` |
| serialize-8 | 472.5 ns | |
| deserialize-8 | 34.0 ns | |
| encrypt-4 (u32) | 187.2 µs | |
| encrypt-left-4 (u32) | 45.1 µs | |
| compare-4 | 671.8 ns | |

## Observations

- Per-block costs are ~11 µs for the Left path (PRP setup dominated: Knuth
  shuffle with rejection-sampled PRNG, 512-byte permutation buffers zeroized
  per drop) and ~36 µs for the Right path on top of that. The raw AES work
  per block (~512 batched encryptions) should be well under 1 µs on this
  hardware, so the overwhelming majority of encrypt time is construction
  overhead around AES, not AES itself — consistent with the v2 plan's cost
  model and a large headroom signal for PRs 3–5.
- `serialize-8` at ~472 ns reflects the per-block `Vec` allocations in
  `to_bytes`; not a target of this program but cheap to improve in passing.

## Addendum (2026-10-08): result elimination check

The benchmark helpers in `benches/oreaes128.rs` returned `()`, so no result
reached Criterion's `black_box` and the inputs were literal constants. That
permits the optimiser to elide work whose result is unused. The helpers now
return their results and the inputs are black-boxed.

The M1 Max above is not available to re-record on, so the effect was measured
as an A/B on one machine instead (Apple M4, same commit, `--warm-up-time 2
--measurement-time 5`, old helpers saved as a Criterion baseline, then the
fixed helpers compared against it):

| Benchmark | Old helpers | Fixed helpers | Change |
|---|---|---|---|
| encrypt-8 | 475.3 µs | 479.8 µs | +0.9% |
| encrypt-left-8 | 107.2 µs | 111.3 µs | +3.3% |
| compare-8 | 1.023 µs | 1.023 µs | no change (p = 0.33) |
| compare-8-slice | 1.028 µs | 1.030 µs | +0.4% |
| serialize-8 | 658.4 ns | 656.9 ns | +0.5% |
| deserialize-8 | 72.2 ns | 133.6 ns | **+82.8%** |
| encrypt-4 | 236.2 µs | 238.3 µs | +0.8% |
| encrypt-left-4 | 53.6 µs | 55.8 µs | +4.0% |
| compare-4 | 922.3 ns | 931.6 ns | no change (p = 0.35) |

The encrypt, compare and serialize figures above are not materially affected:
the 0–4% moves are the cost of producing and dropping each result inside the
timed loop. **`deserialize-8` was under-measured by about 1.8×**: scaled by the
ratio measured here, roughly 60 ns on the M1 Max rather than the 34 ns
recorded above. Later PRs' benchmark results
were taken with the old helpers; the same caveat applies to their
deserialization figures only.

