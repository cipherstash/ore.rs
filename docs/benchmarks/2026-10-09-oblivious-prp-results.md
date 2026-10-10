# Oblivious PRP builder — NEON, SSSE3 and SWAR

The dynamic verification (`docs/reviews/2026-10-09-ore-v2-dynamic-verification.md`,
§4.2) found that the Bit6 PRP builder's time depended on which permutation
it built. This note records which part of the builder carried that signal,
the oblivious builders that replaced it, and their cost and timing.

All the oblivious builders produce the same `permutation` and `inverse`
tables as the old one for the same 512-byte stream, so every ciphertext is
unchanged. The old builder survives as the test-only *reference* builder.

## Machine and method

- Apple M4 (4 performance, 6 efficiency cores), macOS, on mains power with
  Low Power Mode off; rustc 1.94.1, `--release`, hardware AES
  (`--cfg aes_armv8`). Nothing else heavy ran during a measurement.
- A first pass was taken in Low Power Mode on battery (about half the
  clock). Every figure here is from the rerun on mains power; the ratios
  between builders and the dudect picture matched the first pass.
- Timings are criterion medians. The builder benchmark
  (`benches/prp_build.rs`, `--features ct-bench`) cycles through 256
  precomputed random streams, because the reference builder's time depends
  on the stream. Each call goes through a `ct_bench` hook that also builds
  the struct, does one oblivious `permute` and wipes the struct on drop;
  that fixed cost is in every builder figure.
- End-to-end figures come from `benches/bit6.rs` and `benches/chained.rs`,
  all built with `--features ct-bench`, with the dispatcher pointed at each
  builder in turn by a temporary, uncommitted edit to
  `oblivious::build`. The NEON build was benchmarked twice, before and after
  the others; the two runs agree within 3%, and the first is reported.
- dudect (`packages/ct-dudect`): "batch" is one run of 100,000 samples with a
  freshly drawn pair of inputs; "continuous" runs for 150 s, redrawing the
  pair every 100,000 samples and pooling the statistics. The figure is
  dudect's `max t`.

## 1. Which half of the old builder carries the signal

The old builder does two things with secret addresses: the Fisher–Yates
swap at the draw-derived index `j`, and the `inverse[perm[k]] = k` fill.
Each half was timed alone on two fixed streams (fixed A against fixed B),
next to a control doing the same work at public addresses (the swap at
`i, i-1` with the draw still computed; the fill at `k`).

| bench | batch t, 3 runs |
|---|---|
| `iso_swap_secret` (swap loop, secret index) | −41.0, −17.6, −49.9 |
| `iso_swap_public` (control) | +1.1, −0.8, −1.5 |
| `iso_fill_secret` (inverse fill, secret offsets) | −0.8, −0.3, +0.5 |
| `iso_fill_public` (control) | +3.0, −0.7, −1.9 |
| whole old builder, same session (`prp_build_reference_fixed_a_vs_fixed_b`, 5 runs) | +57.7, +17.2, −26.7, +83.4, −38.8 |

**The swap loop carries the signal; the inverse fill carries none.** The
secret-index swap reaches |t| = 18 to 50 against at most 1.5 for its
control, and the fill sits with its control.

Each swap loads `perm[j]` and `perm[i]` just after the previous step stored
to `perm[i+1]` and `perm[j']`. Whether a load overlaps a store still in
flight depends on the draws, and so does whether the core forwards the
stored byte, waits for it, or speculates past it and has to replay. The fill
only stores, to 64 distinct offsets, with no load depending on those stores,
so it has nothing to forward or mispredict. The measurement is consistent
with that mechanism (store-to-load forwarding and memory disambiguation on
byte-granular accesses at secret offsets within one L1-resident line); it
does not prove it.

## 2. The builders

All of them run the same 63 Lemire-reduced draws in the same order and apply
the same swaps. Code: `packages/ore-rs/src/primitives/prp/oblivious.rs`.

- **NEON (aarch64, dispatched there).** Both tables live in eight 16-byte
  vector registers for the whole build. `perm[j]` is fetched with a `tbl`
  table lookup on a broadcast `j`; the swapped entries are written back with
  compare-against-a-constant-index-vector and bitwise select. The only memory
  traffic is the stream reads (at public offsets) and the two final 64-byte
  stores. NEON is part of the aarch64 baseline, so there is no runtime check.
- **SSSE3 (x86_64, runtime detected).** The same shape with `pshufb` on each
  16-byte chunk, the right chunk picked by a mask.
- **SWAR (every other target, and under Kani).** Each table is eight `u64`
  words. Byte equality against a broadcast value is exact zero-byte
  detection, and every secret-indexed read or write is a masked pass over
  the words.
- **Byte-at-a-time with `subtle_ng` (tests and benches only).** The most
  literal form: a full-scan select for `perm[j]`, masked passes over all 64
  bytes for both writes and both inverse updates.
- **Reference (tests, Kani and benches only).** The old textbook builder,
  which the others are pinned to.

Two things make the vector and SWAR forms cheaper than the literal one, and
neither depends on a secret:

1. **The inverse is updated on the value side.** Swapping positions `i` and
   `j` changes the inverse by exchanging the values `i` and `j` wherever they
   appear in it. That needs neither swapped entry, so it runs alongside the
   permutation rather than after it, and there is no separate fill.
2. **Only the part of the table at or below `i` is searched.** Step `i` is
   public and `j <= i`, so the builders search and rewrite only the 16-byte
   chunks (or 8-byte words) covering `0..=i`. In the NEON form the fetch
   becomes a 1-, 2-, 3- or 4-register `tbl`.

In the first pass, a NEON version with full 64-byte passes and the inverse
updated through the swapped values was about 13% slower than the shipped one;
one applying the swap as a lane permutation (four 4-register `tbl`s per step)
was slower again, as was one computing the inverse after the loop.

`from_stream` calls the dispatched builder, so Bit6 (through `Prp::new`) and
the chained scheme (through its `PRP_STREAM` branch) both use it with no
change at the call sites.

### Byte-identical tables

- Property tests (quickcheck, random streams) assert that the dispatched,
  SWAR and `subtle_ng` builders produce exactly the reference builder's
  `permutation` and `inverse`; edge streams (all `0x00`, all `0xff` and
  others) are tested as well.
- Kani proves the SWAR builder equal to the reference for every stream whose
  first 6 draws are symbolic (the rest fixed), and the reference a
  permutation with a correct inverse over the same streams.
- The Bit6 (`compat_w6_vectors`) and chained (`compat_chained_vectors`)
  known-answer vectors pass unchanged, which shows identical ciphertexts end
  to end.
- `cargo test -p ore-rs --all-features` passes on aarch64, and under
  Rosetta 2 for `--target x86_64-apple-darwin`, where SSSE3 is reported and
  the dispatched test therefore exercises the SSSE3 builder.

## 3. Cost

### The builder alone (per 512-byte stream)

| builder | median | vs reference |
|---|---:|---:|
| reference (old, secret-indexed) | 248 ns | — |
| **NEON (dispatched on aarch64)** | **199 ns** | **−20%** |
| SWAR (portable fallback) | 710 ns | +186% |
| byte-at-a-time, `subtle_ng` | 12.0 µs | 48× |

Both the reference and the new builders wipe their 8-byte copy of each draw
with `zeroize`; in the first pass that wipe was about half the reference
builder's time and about a tenth of the NEON builder's. So against the
reference *without* the wipe the NEON builder would be slower; as shipped,
with the wipe in both, it is 20% faster.

The `subtle_ng` form is slow because every `Choice` passes through a volatile
read, about 16,000 of them per build. It is kept only as a second reference
in the tests.

### End to end

| benchmark | reference | NEON | SWAR |
|---|---:|---:|---:|
| bit6-encrypt-u64 | 8.59 µs | **7.89 µs** (−8%) | 13.55 µs (+58%) |
| bit6-encrypt-left-u64 | 6.33 µs | **5.77 µs** (−9%) | 11.32 µs (+79%) |
| bit6-encrypt-u32 | 4.75 µs | **4.44 µs** (−7%) | 7.67 µs (+61%) |
| bit6-compare-u64 | 151 ns | 149 ns | — |
| chained-encrypt-str-5 | 4.67 µs | **4.37 µs** (−7%) | 7.86 µs (+68%) |
| chained-encrypt-str-17 | 15.20 µs | **13.70 µs** (−10%) | 25.18 µs (+66%) |
| chained-encrypt-str-43 | 36.88 µs | **34.12 µs** (−7%) | 64.47 µs (+75%) |
| chained-encrypt-left-str-17 | 11.29 µs | **10.21 µs** (−10%) | 22.05 µs (+95%) |
| chained-compare-str-17 | 318 ns | 316 ns | — |

For Bit6 u64 the saving is the builder saving times the block count
(11 × ~50 ns ≈ 0.55 µs predicted, 0.70 µs measured). Left-only encryption
gains or loses most because the builder is a larger share of it.
Comparison is untouched (it builds no PRP).

## 4. Timing after

Same session, one binary; the reference builder's benches give the before.

| bench | before: reference builder | after: NEON (dispatched) |
|---|---|---|
| `prp_build_*_fixed_a_vs_fixed_b`, batch, 5 runs | +57.7, +17.2, −26.7, +83.4, −38.8 | +1.9, −1.8, −1.1, +1.3, +1.5 |
| same, continuous 150 s | +8.6 at 281 M (tau +0.0005) | **−0.8 at 92 M (tau −0.0001)** |
| `bit6_encrypt_left_fixed_a_vs_fixed_b`, batch | +21.6, +11.5 (verification doc) | −2.4, −0.9, +1.2 |
| `chained_encrypt_fixed_vs_random`, batch | −5.5, −5.3 (verification doc) | −1.8, +2.3 |
| `prp_build_const_vs_random`, continuous 150 s | (batch: −4.8, −7.8, verification doc) | +7.7 at 239 M (tau +0.0005) |

The portable builders, from the same binary:

| builder | `fixed_a_vs_fixed_b` batch |
|---|---|
| SWAR, 5 runs | −1.5, −0.8, −1.8, −1.7, +1.6 |
| `subtle_ng`, 3 runs | −2.1, +2.0, +2.4 |

**The dependence on which permutation is built is gone.** Fixed A against
fixed B, which reached |t| = 83 for the reference builder in a single pair,
stays under 2 for the NEON builder in every run and pools to −0.8 over
92 M samples. The end-to-end left-only encryption test, which showed +21.6
and +11.5 before, shows nothing.

The pooled continuous figure is weak evidence for the reference builder
(+8.6): each pair has its own sign, so pooling over re-drawn pairs dilutes
it. In the Low Power Mode pass the same test gave −45 at 135 M. The batch
runs are the stronger evidence in both directions.

`prp_build_const_vs_random` showed a small difference (t = +7.7,
tau 0.0005). It came from the bench, not the builder: the classes' inputs
sat in separate heap allocations, and dudect's percentile cropping, on a
24 MHz timer that gives a one-build sample only a handful of values,
exaggerates the difference that makes. With both classes in one pool,
slots assigned at random, and 16 builds per sample, it is gone (uncropped
t = −0.04, M1 Max); details in the verification doc, §4.2. The rest of
this paragraph is the record of how that was found. An earlier version of this paragraph
said the classes differ in where their input comes from, one repeated input
against a 256 KB pool. They do not: the `Left` pool is 512 copies of the
fixed stream, indexed at random like the `Right` pool of 512 random streams,
so the classes have the same footprint and access pattern and differ only
in content. (Shrinking the pool to 4, which in the Low Power Mode pass cut
the residual by more than half, shrinks both classes.) The NEON builder has
no secret address or branch for it to come from, so the candidate is
content-dependent microarchitecture such as the data memory-dependent
prefetcher. DIT disables that on M3 and later, but the harness did not apply
DIT to the builder benches until the verification review. It has now been
tested, at `daf0344`: continuous, 150 s per run, DIT off and on alternately,
on the same M4 (macOS 26.5.2, mains power, Low Power Mode off).

| run, in order | DIT | n | max t | max tau |
|---|---|---|---|---|
| off-1 | off | 240 M | +20.4 | +0.0013 |
| on-1 | on | 189 M | +21.6 | +0.0016 |
| off-2 | off | 251 M | +19.6 | +0.0012 |
| on-2 | on | 191 M | +21.8 | +0.0016 |

DIT does not remove or reduce it, so on four runs it is not the prefetcher. The figures are larger than the +7.7 above, but
the commit that measured +7.7 (`6760707`), rerun in the same session, gave
+31.4 at 215 M, so the change is in the session, not the code. Fixed A
against fixed B stays under 2.5 both ways (five batch runs each). Details:
verification doc, §4.2.

## Not measured

- **x86_64 timing.** The SSSE3 builder compiles, passes clippy (stable and
  1.78) and passes the tests under Rosetta 2, which translates it to Arm
  code; its speed and its timing behaviour on a real x86 core (with and
  without SMT) are unknown.
- **Graviton or other Arm cores.**
- **The Valgrind taint run** without the swap suppression was not run in
  this pass. It has since been run, clean, for both the NEON and the SSSE3
  builders; see the verification doc, §1.
- **AVX2.** An AVX2 form (two 32-byte registers per table) is a natural next
  step for x86_64 and was not tried.

## Outcome

The NEON builder is the default on aarch64: it removes the measured
dependence on the permutation and is faster than the builder it replaced, by
20% for the builder and 7 to 10% end to end. On x86_64 the SSSE3 builder,
present on every x86_64 CPU of the last fifteen years, has the same
register-resident shape; benchmark it and rerun the dudect tests on real x86
hardware, with and without SMT, before relying on either its speed or its
timing. The SWAR builder is the portable fallback for every other target: it
is oblivious and showed no timing dependence, at about 2.9 times the builder
cost and 58 to 95% end to end. The `subtle_ng` byte-at-a-time form ships
nowhere.
