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
them. All four modes are clean, and `packages/ct-taint/valgrind.supp` is
empty. Two report classes came up along the way:

1. **`oblivious_lookup`'s range check** (`index >= table.len()`) and its
   callers' test of the returned `Result`. A comparison on the plaintext
   symbol against a public length, whose direction is the same for every
   in-domain symbol, so it carries no information; the static analysis had
   not listed it. It was suppressed in the first runs, which needed a glob
   over every `?` on a `Result<u8, PrpError>`. It is now removed at the
   root: `permute` and `invert` take a `Symbol<D>`, a byte that is in the
   domain by type, so they are infallible and the lookup has no range
   branch. The encryptors take their symbols from the 6-bit decomposition,
   which masks rather than checks. Callers that pass raw symbols
   (`OreCipher::encrypt` for Bit6, chained `encrypt_var`) are checked once at
   entry by `Blocks6::check`, still returning `OreError::PrpError`; no
   harness mode takes that path.
2. (Harness only, fixed.) `str::from_utf8`'s validation of the tainted
   string; the harness now builds the `&str` unchecked.

Nothing is reported from the 6-bit decomposition, the CMAC accumulator, the
σ-MMO hash, the SIMD indicator kernels, `ct_select_byte`, or AES. The gate
is live: the commit before the `Symbol` change, run with the same empty
suppression file, fails on exactly the range check.

A third class, the Fisher–Yates swap at a keystream-derived index in
`LemireFyPrp::from_stream` (a pointer-sized use of an undefined value), was
suppressed when this run was first made; it was the secret-indexed write the
brief's A4 accepted under the one-cache-line argument. §4.2 is why it went:
the PRP builder is now oblivious, and its suppression has been removed. The
oblivious builders use the secret draws only as register operands (`tbl` /
`pshufb` indices, compare-and-select masks, SWAR arithmetic), which memcheck
propagates as undefined data without reporting, and touch memory only at
public offsets (the stream reads and the two final 64-byte stores). The run
is clean without it on both shipping builders: NEON in an arm64 container,
and SSSE3 in an amd64 container under emulation (the emulated CPU reports
SSSE3, so the dispatcher picks it). The left-only ciphertexts from the two
runs are byte-identical, as they must be. The `verify.yml` ct-taint job now
runs on native x86_64 and aarch64 runners, so each builder is checked on its
own target.

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

`bit6_parse` and `bit8_parse` now also parse every input as a right-only
ciphertext (`Right::from_slice`), which no target covered before; 20 s per
target in an arm64 container, all four clean (5.7 M to 13.1 M runs). The
chained left-only query has no parser: `compare_left_to_full` reads it as
raw bytes, and `chained_compare` fuzzes that.

## 3. Kani — proofs for the pure building blocks

Seventeen harnesses, all verified. Fifteen run in CI; the two heaviest run
only with the `kani-full` feature, by hand: the exhaustive-length
`ct_select_byte` harness (about 9 minutes) and the SWAR-builder equivalence
harness (872 s on the M4). The latter is out of CI because it never fit:
on GitHub's `ubuntu-latest` runners it was cancelled 26 to 32 minutes in on
five of six runs, and the sixth took 57 minutes. The default set takes
8 m 50 s on an M1 Max (about 15 minutes expected in CI, which runs about
1.7 times slower); the job has a 30-minute timeout. With `Symbol`, the
out-of-range `oblivious_lookup` cases no longer exist to prove, so the
any-length lookup harness was dropped and a `Symbol` harness added; the
`from_stream` length check, a 335 s harness (552 s in CI) for 504 cases, is
now an exhaustive unit test. Kani cannot execute AES symbolically, so nothing keyed
is in scope; these are the pieces where a wrong implementation would hide
behind matching known-answer vectors.

| property | domain | time |
|---|---|---:|
| `ct_select_byte(block, i) == block[i]` | every length ≤ 256, every `i` (`kani-full`); the 8- and 32-byte right blocks | 519 s; 1 s |
| `ct_bit(byte, pos) == (byte >> pos) & 1`, and 0 for `pos ≥ 8` | exhaustive | < 1 s |
| `oblivious_lookup(table, i) == table[i]` for every symbol `i` | every 64-entry table of in-domain values; every 256-entry table | 10 s; 29 s (M1 Max) |
| `Symbol::<64>::from_low_bits(b)` is `< 64`, and is `b` for `b < 64` | every `u8` | < 1 s |
| `oblivious::lemire_draw` itself reads step `i`'s draw from bytes `(63−i)·8 ..+ 8` (little-endian) and returns `(x·(i+1)) >> 64 ≤ i` | every 504-byte stream, every step `1..64` | 113 s (M1 Max) |
| the reference (textbook Fisher–Yates) builder yields a permutation of 0..64 with a correct inverse | first 6 of 63 draws symbolic, the rest fixed (all 63 symbolic did not finish in 30 min) | 200 s |
| the SWAR oblivious builder's `permutation` and `inverse` equal the reference builder's (under Kani `from_stream` dispatches to SWAR: Kani cannot model the NEON or SSSE3 intrinsics) | same stream shape (`kani-full`) | 872 s |
| `num_blocks_6bit(n)` is the least `b` with `6b ≥ 8n` | every `n ≤ usize::MAX / 8` | < 1 s |
| `decompose_6bit`: symbols < 64, bit `5−t` of block `i` is plaintext bit `6i+t`; injective; order-preserving for any two lengths (a proper prefix sorts first, the chained scheme's string order) | inputs ≤ 16 bytes | 5 s; 8 s; 31 s (M1 Max; equal lengths only, 9 s, before) |
| `final_block` and `prefix_block` injective, and disjoint from each other | full domains | < 1 s each |
| `gf128_double` matches the byte-wise NIST SP 800-38B `dbl` | every 128-bit input | < 1 s |

No harness found a bug.

The NEON and SSSE3 builders, the ones that ship, are outside Kani: it cannot
model their intrinsics, so under `cargo kani` the dispatcher picks SWAR,
which is what the equivalence harness proves. Their evidence is tests against
the reference builder: random and edge streams, and every step `i` with every
swap index `j ≤ i` (2 079 forced draws, each inside a full build). Those run
on x86_64 in `test.yml` (SSSE3) and on an aarch64 runner in `verify.yml`
(NEON). Until the `lemire_draw` harness above, the draw was proved only as a
restated formula.

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
SMT and no co-tenant. Setting the ARM DIT bit was taken to rule out the
data memory-dependent prefetcher, but the harness only applied DIT through
the cipher constructors, so the `prp_build_*` and `iso_*` benches ran
without it whatever the environment said; for the builder-only measurements
the prefetcher was not ruled out. The harness now applies DIT in every bench
and fails if the bit does not stick. The one-cache-line argument addresses
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
there the dependence is gone.

`prp_build_const_vs_random` keeps a small residual (tau 0.0005 in the table
above, 0.0012–0.0016 in the DIT runs below), and it is not explained. An earlier version of this paragraph put it down to the
classes' footprints, one repeated input against a 256 KB pool. That is
wrong: the `Left` pool is 512 copies of the fixed stream, indexed at random
exactly as the `Right` pool of 512 random streams is, so the two classes
have the same footprint and access pattern and differ only in content. The
NEON builder has no secret-dependent branch or address (§1), so the
candidates are content-dependent microarchitecture, the data
memory-dependent prefetcher first.

**DIT test: not the prefetcher.** DIT disables the prefetcher on M3 and
later, and this bench did not get DIT before (above), so it was run
continuously at `daf0344`, 150 s per run, DIT off and on alternately. Apple
M4 (`FEAT_DIT` = 1), macOS 26.5.2 (25F84), mains power with the battery
charged, Low Power Mode off; one other Claude Code session was open but
idle. With `CT_DUDECT_DIT=1` the harness reads the bit back and panics if it
did not stick; both DIT runs completed.

| run, in order | DIT | n | max t | max tau |
|---|---|---|---|---|
| off-1 | off | 240 M | +20.4 | +0.0013 |
| on-1 | on | 189 M | +21.6 | +0.0016 |
| off-2 | off | 251 M | +19.6 | +0.0012 |
| on-2 | on | 191 M | +21.8 | +0.0016 |

The residual is there both ways and DIT does not reduce it; tau is a
little higher with DIT on, which also runs about 20% slower (fewer samples
in the same 150 s). So on this evidence the data memory-dependent
prefetcher does not explain it. Four runs are evidence, not proof, and the
residual stays open. tau holds steady through each run from 50 M samples
on (0.0013–0.0014 off, 0.0015–0.0017 on), so t grows with √n: a constant
offset, not drift. The signal is larger than the first measurement (+7.7 at
239 M, tau 0.0005), but the builder and harness at the commit of that
measurement (`6760707`), run in the same session with DIT off, gave +31.4
at 215 M (tau 0.0021). The larger figures therefore come from this
session's conditions, not from the code changes since `6760707`.

Fixed A against fixed B, where both classes repeat one input, shows nothing
either way: five batch runs each, DIT off −0.9, +2.3, −2.0, +1.5, +2.2, DIT
on −2.4, −1.6, −1.7, +0.4, +1.6. The first pass of these measurements, in Low
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
  builder's timing has not been measured on real x86 hardware. The harness
  now builds on aarch64 Linux (the DIT write uses the generic system
  register encoding), so Graviton needs no changes.
- The `prp_build_const_vs_random` residual on the NEON builder (§4.2) is
  open. On the M4 it is the same with DIT on and off (t ≈ +20, tau
  0.0012–0.0016, four 150 s runs), so on that evidence it is not the data
  memory-dependent prefetcher. A run on another core would show whether it
  is specific to Apple's.
