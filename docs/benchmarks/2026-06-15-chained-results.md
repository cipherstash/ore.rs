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

## Addendum (2026-10-08) — review hardening cost, and the sort-by-random-key builder

Apple M4, rustc 1.94.1, criterion means, `--release`. Same bench file.

**Review hardening.** Two of the #83 review-response changes were first
written as per-call wipes and cost more than everything else in the scheme:

| commit | str-5 | str-17 | str-43 | left-str-17 |
|---|---:|---:|---:|---:|
| before the review hardening | 4.60 µs | 14.88 µs | 37.00 µs | 11.23 µs |
| + `ro` wiped per block (64 zeroizes, 64 fences, per block) | 5.50 µs | 17.74 µs | 44.87 µs | 11.50 µs |
| + `mixed.zeroize()` per `finalize`/`absorb` (≈97 per block) | 7.89 µs | 25.65 µs | 64.30 µs | 13.94 µs |
| **as merged:** `mixed` encrypted in place; `ro` hoisted, wiped once | **4.76 µs** | **15.09 µs** | **38.13 µs** | **11.43 µs** |

The per-call `zeroize` is a volatile store plus a compiler fence; ~97 of them
per block stop the independent AES ops from pipelining. Encrypting `mixed` in
place leaves no plaintext temporary, so there is nothing to wipe, and `ro` is
fully overwritten by each block, so wiping it once after the loop is
equivalent. Bytes are unchanged by either.

**Sort-by-random-key PRP builder** (rejected; see
`docs/benchmarks/2026-06-13-bit6-prp-results.md` and review brief A4). Measured
against the pre-fix tip above (25.93 µs for str-17), swapped into `prp_at`'s
`from_stream`; the accumulator's 32 `PRP_STREAM` tags (512 bytes) already cover
the sort's 64 words, so the cost is the network alone:

| benchmark | Lemire FY | sort, 56-bit key | sort, 64-bit key |
|---|---:|---:|---:|
| chained-encrypt-str-5 | 7.91 µs | 9.95 µs (+26%) | 11.83 µs (+50%) |
| chained-encrypt-str-17 | 25.93 µs | 32.77 µs (+29%) | 38.27 µs (+49%) |
| chained-encrypt-str-43 | 65.06 µs | 81.27 µs (+26%) | 95.24 µs (+48%) |
| chained-encrypt-left-str-17 | 13.49 µs | 20.71 µs (+52%) | 27.31 µs (+98%) |

The absolute deltas (≈ +0.30 µs and +0.54 µs per block) carry over to the
fixed baseline unchanged. Chained has no known-answer vectors, so a builder
change here would not be caught by a test; only the Bit6 vectors failed.

## Addendum (2026-10-09) — oblivious PRP builder

`from_stream` now builds through the oblivious builder (review brief A4,
"Status"; NEON on aarch64, SSSE3 on x86_64 when present, SWAR elsewhere),
with byte-identical tables, so the chained vectors are unchanged. Apple M4 on
mains power, rustc 1.94.1, criterion medians, `--release`; the same build
with the dispatcher pointed at each builder in turn (the indexed column by a
temporary, uncommitted edit). A second run of the NEON build agreed within 3%.

| benchmark | indexed | NEON | SWAR |
|---|---:|---:|---:|
| chained-encrypt-str-5 | 4.67 µs | **4.37 µs** (−7%) | 7.86 µs (+68%) |
| chained-encrypt-str-17 | 15.20 µs | **13.70 µs** (−10%) | 25.18 µs (+66%) |
| chained-encrypt-str-43 | 36.88 µs | **34.12 µs** (−7%) | 64.47 µs (+75%) |
| chained-encrypt-left-str-17 | 11.29 µs | **10.21 µs** (−10%) | 22.05 µs (+95%) |
| chained-compare-str-17 | 318 ns | 316 ns | — (builds no PRP) |

The indexed column agrees with the "as merged" row above (15.09 µs for
str-17, 15.20 µs here). The saving is roughly the builder saving times the
block count: about 50 ns per block (248 ns indexed, 199 ns NEON, per
512-byte stream) × 23 blocks ≈ 1.1 µs predicted for str-17, 1.5 µs
measured.
