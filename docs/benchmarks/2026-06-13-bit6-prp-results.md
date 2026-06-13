# Benchmark results — Bit6 PRP swap to fixed-draw Fisher–Yates

Apple M1 Max, rustc 1.87.0, hardware AES (`--cfg aes_armv8`), criterion
medians. Change: Bit6's per-block PRP moved from the rejection-sampled
Knuth shuffle to `LemireFyPrp` (fixed-count wide draws + Lemire reduction),
**seed-keyed shape (i)** — the drop-in replacement that fits the existing
`Prp::new(seed)` signature.

| Bit6 benchmark | before (Knuth) | after (Lemire FY, shape i) |
|---|---:|---:|
| encrypt-u64 (11 blocks) | 11.5 µs | **8.6 µs** |
| encrypt-left-u64 | ~8.9 µs | **5.7 µs** |
| encrypt-u32 (6 blocks) | ~7.8 µs | **4.8 µs** |
| compare-u64 | 182 ns | 183 ns (unchanged) |

## Why not the spike's 3.3 µs yet

The spike's headline (153 ns/block, ≈3.3 µs encrypt) is the **pre-scheduled
stream, shape (ii)** — the PRP keystream produced under an already-scheduled
cipher, eliminating the AES key schedule per block (~172 ns × 11 ≈ 1.9 µs).
Shape (i), shipped here, still keys a fresh AES from each block's seed, so it
pays those 11 schedules — hence ~8.6 µs, not 3.3 µs.

Shape (i) is the right increment for this PR: it fits the `Prp` trait with no
architectural change, and its security story is "identical key-usage
structure to the old PRP, with rejection sampling replaced by fixed-count
Lemire draws." Shape (ii) requires deriving the PRP stream under k2 / as a
PRF branch family, which is exactly the structure the §5(b) CMAC accumulator
introduces — so it lands with PR 6, under the same crypto review, and takes
Bit6 u64 encrypt from 8.6 µs to a projected ~3.3 µs.

## What this PR's change actually buys now

1. **Closes the timing channel.** Draw count is fixed and seed-independent;
   no rejection loop. Encryption time no longer varies with the (plaintext-
   derived) PRP seed. This is the security-relevant part and it ships now.
2. **Removes modulo/​rejection bias** in favour of a provable ≤ 2⁻⁵⁵
   statistical distance from uniform — a clean statistical term in the
   Lewi-Wu argument.
3. **25% faster encrypt** even in shape (i), before the larger shape-(ii)
   win.

## End-to-end (u64 encrypt, for context)

| Build | encrypt-u64 |
|---|---:|
| pre-v2 default (Bit8, software AES) | 381 µs |
| Bit8, hardware AES + bulk encoding (#80) | 25.1 µs |
| Bit6, Knuth PRP (#82 initial) | 11.5 µs |
| **Bit6, Lemire FY shape (i) (this change)** | **8.6 µs** |
| Bit6, Lemire FY shape (ii) (projected, PR 6) | ~3.3 µs |
