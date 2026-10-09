# ORE v2 — dynamic and formal verification results

**Date:** 2026-10-09
**Scope:** the v2 schemes (`OreAes128Bit6`, `OreAes128Bit6Chained`), their
primitives, and the legacy `OreAes128` parsers and comparator.
**Machine for timing work:** Apple M4, macOS; Valgrind in an arm64 Linux
container (valgrind 3.19); rustc 1.94.1.

This complements the static work (the crypto review brief A1–A4, the
constant-time analysis, the zeroize audits) with four kinds of evidence,
each reproducible from the repository:

| what | where | gate |
|---|---|---|
| Valgrind taint (ctgrind technique) | `packages/ct-taint`, `scripts/ct-taint.sh` | CI (`verify.yml`), fails on any undocumented report |
| libFuzzer targets | `packages/ore-rs/fuzz`, `scripts/fuzz.sh` | CI, 120 s per target per PR |
| Kani proof harnesses | `#[cfg(kani)]` modules in `ore-rs` | CI (`cargo kani -p ore-rs`) |
| dudect timing tests | `packages/ct-dudect` | by hand; results below |

## 1. Valgrind taint — secret-dependent branches and addresses

The harness marks the key and the plaintext as undefined memory and runs each
v2 encryptor (Bit6 full and left-only, chained full and left-only). Memcheck
then reports every conditional jump and every memory address that depends on
them. All four modes are clean except for two report classes, each listed
with its reason in `packages/ct-taint/valgrind.supp`:

1. **`oblivious_lookup`'s range check** (`index >= table.len()`) and its
   callers' test of the returned `Result`. A comparison on the plaintext
   symbol against a public length, whose direction is the same for every
   in-domain symbol, so it carries no information; the static analysis had
   not listed it. Removing it means an infallible `permute` over a typed
   in-domain symbol, which is an API change and is not done here.
2. (Harness only, fixed.) `str::from_utf8`'s validation of the tainted
   string; the harness now builds the `&str` unchecked.

Nothing is reported from the 6-bit decomposition, the CMAC accumulator, the
σ-MMO hash, the SIMD indicator kernels, `ct_select_byte`, or AES. With the
suppressions removed every mode fails, so the gate is live.

A third class, the Fisher–Yates swap at a keystream-derived index in
`LemireFyPrp::from_stream` (a pointer-sized use of an undefined value), was
suppressed when this run was first made; it was the secret-indexed write the
brief's A4 accepted under the one-cache-line argument. §4.2 is why it went:
the PRP builder is now oblivious, and its suppression has been removed. The
oblivious builders use the secret draws only as register operands (`tbl` /
`pshufb` indices, compare-and-select masks, SWAR arithmetic), which memcheck
propagates as undefined data without reporting, and touch memory only at
public offsets (the stream reads and the two final 64-byte stores), so the
run is expected to stay clean without it. That has not been run locally (no
Valgrind on macOS, no container here); the `verify.yml` ct-taint job, on
x86_64 Linux where the SSSE3 builder is dispatched, is the check.

The comparators are not tainted: their inputs are ciphertexts, which are
public. Their timing question is §4's.

## 2. Fuzzing — parsers and raw comparators on untrusted bytes

Four targets, each asserting "never panics; an accepted ciphertext re-encodes
to the same bytes" (and for the comparators, "answers any pair"). First runs,
45 s each on the M4:

| target | runs | result |
|---|---:|---|
| `chained_parse` (`VarCipherText::from_slice`) | 43.0 M | clean |
| `chained_compare` (`compare_raw_slices`, `compare_left_to_full`) | 37.6 M | clean |
| `bit6_parse` (`CipherText`/`Left::from_slice` at N = 11 and 6, `compare_raw_slices`) | 23.0 M | clean |
| `bit8_parse` (legacy, N = 8 and 4) | — | **panic on the first input** |

The legacy `OreAes128::compare_raw_slices` inferred the block count from the
length without checking it: two empty slices underflowed the nonce
subtraction, and a partial block sliced past the end. Fixed (`None` for any
length that is not `n·(1 + 16 + 32) + 16`), with a regression test; 16.5 M
runs clean afterwards. `n = 0` is included: a nonce-only input is the valid
ciphertext of a zero-byte plaintext, which the parser also accepts, and both
comparators return `Equal` on it. This is a pre-existing bug in the frozen legacy
scheme, not a v2 regression, and it reaches any caller that compares stored
bytes without parsing them first.

The corpora from these runs are committed as seeds.

## 3. Kani — proofs for the pure building blocks

Eighteen harnesses, all verified (full run 1 324 s before the oblivious PRP
builder; the two exhaustive-length harnesses, 16 minutes of that, run only
with the `kani-full` feature; the PRP harnesses were re-timed one at a time
after it, and the default set now takes about 25 minutes). Kani cannot execute AES symbolically, so nothing keyed
is in scope; these are the pieces where a wrong implementation would hide
behind matching known-answer vectors.

| property | domain | time |
|---|---|---:|
| `ct_select_byte(block, i) == block[i]` | every length ≤ 256, every `i` (`kani-full`); the 8- and 32-byte right blocks | 519 s; 1 s |
| `ct_bit(byte, pos) == (byte >> pos) & 1`, and 0 for `pos ≥ 8` | exhaustive | < 1 s |
| `oblivious_lookup(table, i)` is `Ok(table[i])` for `i < len`, `Err` otherwise | every 64- and 256-entry table; every length ≤ 256 (`kani-full`) | 2 s; 17 s; 439 s |
| Lemire reduction `((x·(i+1)) >> 64) ≤ i` | every `u64` `x`, `i < 64` | < 1 s |
| the reference (textbook Fisher–Yates) builder yields a permutation of 0..64 with a correct inverse | first 6 of 63 draws symbolic, the rest fixed (all 63 symbolic did not finish in 30 min) | 200 s |
| the SWAR oblivious builder's `permutation` and `inverse` equal the reference builder's (under Kani `from_stream` dispatches to SWAR: Kani cannot model the NEON or SSSE3 intrinsics) | same stream shape | 872 s |
| `from_stream` rejects streams shorter than 504 bytes | every short length | 335 s (101 s before the oblivious builder) |
| `num_blocks_6bit(n)` is the least `b` with `6b ≥ 8n` | every `n ≤ usize::MAX / 8` | < 1 s |
| `decompose_6bit`: symbols < 64, bit `5−t` of block `i` is plaintext bit `6i+t`; injective; order-preserving for equal lengths | inputs ≤ 16 bytes | 5 s; 8 s; 9 s |
| `final_block` and `prefix_block` injective, and disjoint from each other | full domains | < 1 s each |
| `gf128_double` matches the byte-wise NIST SP 800-38B `dbl` | every 128-bit input | < 1 s |

No harness found a bug.

## 4. dudect — timing leakage

Welch's t-test over two interleaved input classes; `|t| < 5` after millions
of samples means no distinguishable timing. `max tau` is the effect size in
units of the timing spread. Quiet machine, release build, hardware AES.

### 4.1 Comparators: does the time reveal where the inputs first differ?

Class `Left`: pairs differing in the first block. Class `Right`: pairs
sharing every block but the last.

Before the fix described below:

| bench | samples | t | tau |
|---|---:|---:|---:|
| `bit6_compare_first_vs_last_block` (u64, 11 blocks) | 151 M | +10.2 | +0.0008 |
| `chained_compare_first_vs_last_byte` (17 chars, 23 blocks) | 154 M | **−248** | **−0.020** |
| same, inputs held in L1 (`CT_DUDECT_POOL=4`) | 72 M | +25 | +0.003 |

After it (same machine, same binary apart from the comparators):

| bench | samples | t | tau |
|---|---:|---:|---:|
| `bit6_compare_first_vs_last_block` | 91 M | −7.1 | −0.0008 |
| `chained_compare_first_vs_last_byte` | 70 M | +12.5 | +0.0015 |

**Finding.** The chained comparator's time depended on the position of the
first differing block. The prefix scan is constant-time, but the resolution
step after it loaded `f[l]`, `xt[l]` and the right block `right[l]` by the
secret-derived index `l`. The right block is the one region the scan never
touched, so whether its cache line was already present depended on `l`: with
inputs arriving from memory the effect was 2 % of the timing spread (t = −248
over 154 M samples); with every input held in L1 it all but vanished
(tau 0.003). Bit6 was barely affected because its whole ciphertext spans five
cache lines, which the hardware prefetcher covers.

What it leaked is `l`, the first differing block. In the Lewi–Wu model that
position is already revealed to whoever holds both ciphertexts (the left
tags are deterministic), so this did not widen the scheme's leakage
profile; it moved part of it from "the ciphertext holder" to "anyone who can
time the comparison", which the constant-time scan was written to prevent.

**Fix (applied to the Bit6 raw and chained comparators in their scheme
commits; in this PR to the Bit6 typed `Ord` and to both legacy `OreAes128`
comparators, raw and typed).** The scan now
latches `xt[l]`, `f[l]` and `right[l]` as it runs, with
`width::ct_assign_bytes` under the choice "this is the first differing
block" (set for exactly one `n`), and the resolution step hashes and
bit-selects from the latched copies. Every load is now indexed by the public
loop counter. Every comparator (legacy and Bit6, raw and typed, and
chained) shares the latch as `width::FirstDiff`, which zeroizes the copies
on drop. The added cost is one 8-byte right-block read and about 25
masked byte copies per block, against a scan already comparing 17 bytes per
block; the chained benchmarks in `docs/benchmarks/` were not re-run, since
the comparator is not on the encrypt path they time. The legacy comparator
had the same post-scan `l`-indexed loads and takes the same fix, which
leaves its frozen wire format unchanged; it has no dudect bench, so the
legacy fix rests on the same reasoning, not a measurement.

The chained effect size fell from 0.020 to 0.0015, below the L1-resident
control measured before the fix, so the cache component is gone. What
remains (t ≈ 12 at 70 M samples) is the same order as the Bit6 figure, which
the fix did not change (0.0008 before and after, sign flipped): a floor the
test resolves at these sample counts but whose source is not the
`l`-indexed loads. Both comparators keep the two branches that reveal only
the result the caller receives anyway: the early return on equality and the
final `test == 1`.

### 4.2 Encryptors: does the time depend on the plaintext?

As first measured, with the PRP builder that swapped at secret indices:

| bench | classes | runs (100 k samples each) | t |
|---|---|---|---:|
| `bit6_encrypt_zero_vs_random` | 0 vs random u64 | 2 | +2.7, −3.0 |
| `bit6_encrypt_const_vs_random` | one random-looking constant vs random | 2 | +14.7, −7.0 |
| `bit6_encrypt_left_const_vs_random` | same, left-only | 2 | +5.6, +8.0 |
| `bit6_encrypt_left_fixed_a_vs_fixed_b` | two fixed values (fresh pair per run) | 2 | +21.6, +11.5 |
| `chained_encrypt_fixed_vs_random` | 17 × `a` vs random lowercase | 2 | −5.5, −5.3 |
| `prp_build_const_vs_random` | one fixed 512-byte stream vs random | 2 | −4.8, −7.8 |
| `prp_build_fixed_a_vs_fixed_b` | two fixed streams (fresh pair per run) | 2 | +65.5, −3.6 |
| `prp_build_fixed_a_vs_fixed_b`, continuous, pairs re-drawn | | 138 M | −16.4 (tau −0.0014) |

**Finding (fixed).** The PRP builder's time depended on *which* permutation
it builds: for some pairs of draw streams the two were clearly
distinguishable (t = +65 at 100 k samples), for others not, and at population
level the effect was real but very small (tau −0.0014). The only
secret-dependent memory traffic in the builder was the Fisher–Yates swap at
the draw-derived index and the inverse-table fill, so this was the A4 access
pattern showing up as a within-process timing signature, on a core with no
SMT and no co-tenant. Setting the ARM DIT bit changed nothing, so it is not
the data-dependent prefetcher. The one-cache-line argument addresses
line-granularity cache leakage and says nothing about this.

**Mechanism isolation.** Each half of the old builder, timed alone on two
fixed streams, next to a control doing the same work at public addresses
(the swap at `i, i−1` with the draw still computed; the fill at `k`). Apple
M4 on mains power, release build, three runs of 100 k samples, a fresh pair
per run:

| bench | t, 3 runs |
|---|---|
| `iso_swap_secret` (swap loop, secret index) | −41.0, −17.6, −49.9 |
| `iso_swap_public` (control) | +1.1, −0.8, −1.5 |
| `iso_fill_secret` (inverse fill, secret offsets) | −0.8, −0.3, +0.5 |
| `iso_fill_public` (control) | +3.0, −0.7, −1.9 |

The swap loop carries the whole signal; the fill carries none. Each swap
loads `perm[j]` and `perm[i]` just after the previous step stored to
`perm[i+1]` and `perm[j']`, so whether a load overlaps a store still in
flight depends on the draws, and with it whether the core forwards the
stored byte, waits, or speculates and replays. The fill only stores, to 64
distinct offsets, with no load depending on those stores. Store-to-load
forwarding and memory disambiguation on byte-granular accesses at secret
offsets inside one L1-resident line is consistent with that; the
measurement does not prove it.

**Fix.** The builder is now oblivious (`primitives/prp/oblivious.rs`): both
tables stay in registers, `perm[j]` is fetched by a table lookup on a
broadcast `j` and written back by compare-and-select, and the inverse is
kept by exchanging the values `i` and `j` in it at each step instead of a
fill. Same draws and swaps, byte-identical tables, no vector change. NEON on
aarch64, SSSE3 on x86_64 when present, SWAR elsewhere; on the M4 the NEON
builder is 20% faster than the one it replaced (199 ns against 248 ns).
Details and costs: `docs/benchmarks/2026-10-09-oblivious-prp-results.md`.

**After**, same session and binary (`prp_build_reference_*` is the old
builder, kept as a test-only reference):

| bench | before (old builder) | after |
|---|---|---|
| `prp_build_fixed_a_vs_fixed_b`, 5 runs | +57.7, +17.2, −26.7, +83.4, −38.8 | +1.9, −1.8, −1.1, +1.3, +1.5 |
| same, continuous 150 s, pairs re-drawn | +8.6 at 281 M (tau +0.0005) | −0.8 at 92 M (tau −0.0001) |
| `prp_build_swar_obl_fixed_a_vs_fixed_b`, 5 runs | — | −1.5, −0.8, −1.8, −1.7, +1.6 |
| `bit6_encrypt_left_fixed_a_vs_fixed_b`, 3 runs | +21.6, +11.5 (table above) | −2.4, −0.9, +1.2 |
| `chained_encrypt_fixed_vs_random`, 2 runs | −5.5, −5.3 (table above) | −1.8, +2.3 |
| `prp_build_const_vs_random`, continuous 150 s | — | +7.7 at 239 M (tau +0.0005) |

The pooled continuous figure is weak evidence either way: each 100 k-sample
pair has its own sign, so pooling dilutes it (the old builder's +8.6 here,
against |t| up to 83 in a single pair). The per-pair runs are the test, and
there the dependence is gone. `prp_build_const_vs_random` keeps a small
residual (tau 0.0005); that test compares one repeated input against a pool
of 512 streams (256 KB, larger than L1), so its classes differ in where
their *input* comes from, and the fixed-A-versus-fixed-B test that removes
that difference shows nothing. The first pass of these measurements, in Low
Power Mode on battery, gave the same per-pair picture (its pooled old-builder
figure was larger, −45 at 135 M).

Encryption time does not depend on the plaintext *value* in any way the test
could see once the inputs are symmetric (`zero_vs_random`: t ≈ 3); the
`const_vs_random` signals in the first table were the builder effect above,
seen through a fixed versus varying permutation sequence.

## 5. What is not covered

- The cryptographic argument (Lewi–Wu leakage, the BHKR bound for H, CMAC
  branch separation) is reviewed by reading the brief, not by any tool here.
- Kani does not reach anything keyed; the end-to-end comparator and
  encryptor correctness rest on the property tests and known-answer vectors.
- The taint run uses memcheck's definedness tracking, which does not follow
  taint through a load at a tainted address (the loaded byte is "defined").
  Secret-indexed *reads* after the first one are therefore invisible to it;
  that is exactly why the comparators are measured with dudect instead.
- dudect was run on one Apple M4. x86 (with and without SMT, where the
  SSSE3 builder runs) and Graviton would be worth a run; the SSSE3
  builder's timing has not been measured on real x86 hardware.
