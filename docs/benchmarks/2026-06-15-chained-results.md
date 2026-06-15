# Chained variable-length scheme — benchmark results

**Date:** 2026-06-15
**Machine:** Apple M1 Max, hardware AES (`aes_armv8`)
**Scheme:** `OreAes128Bit6Chained` (PR 6) — 6-bit blocks, AES-CMAC accumulator,
shape-(ii) PRP (keystream from the accumulator, no per-block key schedule).
**Command:** `cargo bench -p ore-rs --bench chained`

| benchmark | input | blocks | time |
|---|---|---:|---:|
| `chained-encrypt-str-5` | `"alice"` | 7 | **5.05 µs** |
| `chained-encrypt-str-17` | `"alice@example.com"` | 23 | **15.97 µs** |
| `chained-encrypt-str-43` | 43-char sentence | 58 | **40.18 µs** |
| `chained-encrypt-left-str-17` | 17 chars | 23 | 10.09 µs |
| `chained-compare-str-17` | 17 chars | 23 | **402 ns** |

## Reading

- **~0.69 µs/block** for full encryption, scaling linearly with length
  (5.05/7, 15.97/23, 40.18/58 all ≈ 0.69). 
- This is *below* fixed-N Bit6's **~0.81 µs/block** (≈8.9 µs for an 11-block
  u64) — the shape-(ii) payoff: the accumulator is keyed once per ciphertext, so
  there is **no per-block AES key schedule**. Per-block work is
  ~32 (`PRP_STREAM`) + 64 (`RO_KEY`) + 1 (`absorb`) ≈ 97 AES ops + the 64
  σ-MMO H evals, all under the already-scheduled accumulator cipher.
- `encrypt_left` is ~63% of full encrypt (it skips the 64 `RO_KEY` finalizes and
  the right-block masking per block, keeping only the PRP + the single left tag).
- Comparison (~402 ns at 23 blocks) is a constant-time prefix scan plus one H
  eval and one oblivious right-block read.

## Caveats

- CMAC subkey `K1` and the per-block doubling reuse the vectorized
  `gf128_double`; the accumulator XORs are `u128` word ops.
- Numbers are from a 3 s criterion measurement on a developer machine (some
  thermal variance); treat as indicative, not a regression gate.
