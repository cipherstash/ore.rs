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

## Addendum (2026-10-08) — sort-by-random-key builder, benchmarked and rejected

vitaminc's `permutation` crate adopted an oblivious sort-by-random-key builder
(one random 64-bit word per index, Batcher odd–even merge network, 543
compare-exchanges at N = 64). It was prototyped as alternative bodies of
`LemireFyPrp::from_stream`, so the schemes are otherwise unchanged, and
benchmarked as a candidate for the A4 high-assurance tier. Apple M4,
rustc 1.94.1, `--release`, criterion means with 95% intervals. Both callers
already supply 512 bytes of stream; Lemire FY consumes 504, the sorts 512.

| `from_stream`, N = 64 | mean | vs Lemire FY |
|---|---:|---:|
| Lemire FY (shipped) | 210 ns [209, 212] | — |
| sort u64, `(w<<8)\|i` (56-bit key, vitaminc's packing) | 494 ns [493, 496] | +135% |
| sort u128, `(w<<8)\|i` (64-bit key, index tie-break) | 663 ns [661, 666] | +215% |
| sort `(u64 key, u8 idx)` pair, two-level compare | 647 ns [643, 651] | +208% |

| Bit6 benchmark | Lemire FY | sort, 56-bit key | sort, 64-bit key |
|---|---:|---:|---:|
| encrypt-u64 (11 blocks) | 8.39 µs | 11.80 µs (+41%) | 14.37 µs (+73%) |
| encrypt-left-u64 | 6.12 µs | 9.82 µs (+61%) | 12.39 µs (+102%) |
| encrypt-u32 (6 blocks) | 4.91 µs | 6.69 µs (+34%) | 8.00 µs (+61%) |

The end-to-end deltas are the builder delta times the block count (11 × 284 ns
≈ 3.1 µs predicted, 3.4 µs measured for encrypt-u64). Left-only encryption
suffers most because the builder is a larger share of its cost. Masking the
gate indices to remove bounds checks made the sort slower (557 ns) and was
reverted. All three sort variants produce a valid, deterministic permutation
and match a reference stable sort; with either sort 8 of the 14 Bit6 compat
vectors fail, as a different permutation must. Decision and reasoning: review
brief A4, "Alternative considered for the tier".

## Addendum (2026-10-09) — oblivious builder, now the default

A dudect run measured the indexed builder's time depending on which
permutation it builds (review brief A4, "Status"), so key generation now goes
through oblivious builders with the same draws and swaps and byte-identical
tables (`primitives/prp/oblivious.rs`): NEON on aarch64, SSSE3 on x86_64 when
present, u64 SWAR elsewhere. Apple M4 on mains power (Low Power Mode off),
rustc 1.94.1, `--release`, hardware AES, criterion medians.

The builder alone, per 512-byte stream, averaged over 256 random streams
(`benches/prp_build.rs`, `--features ct-bench`; each figure includes building
the struct, one oblivious `permute` and the wipe on drop):

| builder | median | vs indexed |
|---|---:|---:|
| indexed (textbook FY; now a test-only reference) | 248 ns | — |
| **NEON (dispatched on aarch64)** | **199 ns** | **−20%** |
| SWAR (portable fallback) | 710 ns | +186% |
| byte-at-a-time `subtle_ng` (test reference only) | 12.0 µs | 48× |

End to end, the same build with the dispatcher pointed at each builder in
turn (the indexed column by a temporary, uncommitted edit). A second run of
the NEON build agreed within 2%.

| Bit6 benchmark | indexed | NEON | SWAR |
|---|---:|---:|---:|
| encrypt-u64 (11 blocks) | 8.59 µs | **7.89 µs** (−8%) | 13.55 µs (+58%) |
| encrypt-left-u64 | 6.33 µs | **5.77 µs** (−9%) | 11.32 µs (+79%) |
| encrypt-u32 (6 blocks) | 4.75 µs | **4.44 µs** (−7%) | 7.67 µs (+61%) |
| compare-u64 | 151 ns | 149 ns | — (builds no PRP) |

The saving is the builder saving times the block count (11 × ~50 ns ≈
0.55 µs, 0.70 µs measured for encrypt-u64). The indexed figure of 8.59 µs
matches the 8.39 µs recorded above for the same code on the same machine.
SSSE3 has not been timed on real x86 hardware; under Rosetta 2 it passes the
equivalence tests only.
