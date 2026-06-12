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
