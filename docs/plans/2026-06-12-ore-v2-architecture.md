# ORE v2: generalised block widths, efficient unary encoding, SIMD, variable-length plaintexts

**Date:** 2026-06-12
**Status:** Draft
**Scope:** `packages/ore-rs` (with small additions to `packages/orderable-bytes`)

## Context

`ore-rs` implements Lewi-Wu (2016) BlockORE with:

- **8-bit input blocks only.** Each plaintext byte is one ORE block over a domain of 256.
- **Fixed block counts via const generics.** `CipherText<S, N>` where `N` is the plaintext
  byte length; the Left tag packs `(prefix ‖ xt[i] ‖ block_index)` into one 16-byte AES
  input, which hard-caps `N ≤ 15`.
- **A naive iterative right-ciphertext encoder.** Per block: 256 random-oracle keys are
  rebuilt byte-by-byte, hashed into a heap-allocated `Vec<u8>`, and the indicator bits are
  set one at a time through `prp.invert(j)` table lookups (`scheme/bit2.rs:147-177`).
- **No wire-format header.** `compare_raw_slices` infers the block count from the slice
  length; ciphertexts of different schemes/sizes are distinguishable only by length.

This plan covers four goals, structured as a sequence of PRs:

1. **Efficient unary encoding** — replace the per-bit iterative right-block construction
   with bulk, allocation-free encoding.
2. **SIMD implementations** — vectorise the data-parallel inner loops on x86_64 and
   aarch64 with a scalar fallback.
3. **6-bit block width** — a second block width with 4× less AES work and a 4× smaller
   right block, with the 8-bit scheme retained byte-for-byte for backwards compatibility.
4. **Fixed and variable block counts** — keep the const-generic fast path for numerics;
   add a variable-length ciphertext (Vec-backed) for strings, which requires a new
   prefix-binding construction to lift the `N ≤ 15` cap.

## Non-goals

- No change to the underlying Lewi-Wu construction for the existing 8-bit fixed-N scheme.
  `OreAes128ChaCha20` ciphertexts must remain byte-identical and comparable against
  existing stored data.
- No serde support, no no_std, no key-management/rotation work.
- No alternative PRP algorithm for the 8-bit scheme (the Knuth shuffle is part of the
  ciphertext-compatible key schedule). A cheaper PRP for *new* schemes is an open option.

## Cost model (why these goals, in this order)

Per 8-bit block, `encrypt` today costs roughly:

| Step | Work |
|---|---|
| PRP setup (Knuth shuffle) | ~256 swaps + rejection-sampled AES-CTR PRNG bytes |
| `ro_keys` rebuild | 256 × 16-byte writes (4 KiB) per block, then re-zeroed |
| PRF₁ over `ro_keys` | 256 AES encryptions |
| Random oracle (`hash_all`) | 256 AES encryptions + a 256-byte `Vec` allocation |
| Indicator loop | 256 × (`prp.invert` lookup + branchy bit set) |

For a `u64` (8 blocks) that is ~4096 AES block encryptions plus ~8 KiB of redundant
buffer traffic and 8 heap allocations. AES is already hardware-accelerated via the `aes`
crate; the headroom is in everything around it. A 6-bit block divides the dominant
AES count by 4 **and** shrinks the stored right block from 32 to 8 bytes — for `u64`,
ciphertexts go from 408 bytes (8 blocks × 49 + 16) to roughly 291 bytes (11 blocks × 25
+ 16), and encryption does ~700 RO evaluations instead of ~2048.

## Architecture

### 1. Core abstractions (the refactor everything else hangs off)

Introduce three orthogonal axes, today all hard-coded into `scheme/bit2.rs`:

```text
block width   ×   prefix binding   ×   block count
(Bit8, Bit6)      (Packed, Chained)    (fixed const N, variable)
```

**`BlockWidth` trait** (stable-Rust trait-with-associated-items; `generic_const_exprs`
is not available so we cannot write `[u8; 1 << W]` generically):

```rust
pub trait BlockWidth: private::Sealed {
    /// Bits per input block (8 or 6).
    const BITS: usize;
    /// Block domain size (256 or 64).
    const DOMAIN: usize;
    /// Right-block bitvector: 32 bytes for Bit8, 8 bytes for Bit6.
    type RightBlock: CipherTextBlock + BitVec;
    /// PRP over the block domain.
    type Prp: Prp<u8>;
}

pub struct Bit8;
pub struct Bit6;
```

**`BlockDecomposer`** — turns canonical plaintext bytes (from `orderable-bytes`) into a
sequence of block values `< DOMAIN`:

- `Bit8`: identity (one byte per block), exactly today's behaviour.
- `Bit6`: MSB-first bit-packing. `N` bytes become `M = ceil(8N / 6)` blocks; the final
  block is zero-padded in its low bits. MSB-first packing preserves lexicographic order,
  and for fixed-length inputs trailing zero-padding is order-neutral. The decomposer is
  pure bit logic and lives in `ore-rs` (not `orderable-bytes`, which stays about value
  canonicalisation).

Because `M` cannot be computed from `N` at the type level on stable Rust, the
`OreEncrypt` impls name both as consts — the same idiom `encrypt.rs` already uses for
`ENCODED_LEN` (e.g. `u64` → `N = 8`, `M = 11`), with a `const` assertion that
`M == (8 * N).div_ceil(6)`.

**`IndicatorEncoder`** — the unary-encoding engine (see §2). One scalar implementation,
optionally overridden by SIMD backends (§3).

**Prefix binding** stays packed (`prefix ‖ xt[i] ‖ i` in one AES block) for all fixed-N
schemes; a chained construction is introduced only for the variable-length scheme (§5).

The existing `OreAes128<R>` is then re-expressed as the `(Bit8, Packed, fixed-N)` corner
of this space.

**Seed/tag buffer separation.** Today `left.f` is reused for two cryptographically
different values: the PRF₂ outputs (per-block PRP seeds — key-equivalent material that
must never be serialized) and, after an in-place overwrite, the PRF₁ left tags (the
publishable ciphertext component). The only thing preventing seed exposure is statement
ordering inside `encrypt`. The refactor makes this structural: seeds are computed into a
separate short-lived `ZeroizeOnDrop` buffer, and the `Left` type only ever holds tag
material. Cost is one 16×N-byte stack array and an extra zeroize — noise against the
AES floor (the original reuse was a historical perf choice that measurably buys
nothing). Output bytes are unaffected. The refactor must be **byte-identical** — verified against pinned test
vectors (PR 1) — because the Knuth-shuffle PRP, the PRNG byte order, the `ro_keys`
layout, and the wire format are all observable in stored ciphertexts.

`OreCipher`'s associated types will need to change shape (e.g. gaining a
`type Width: BlockWidth`). We are pre-1.0, so this is a semver-minor bump under the 0.x
convention, but downstream CipherStash crates should be checked before merge.

### 2. Efficient unary encoding (goal 1)

The key observation: `prp.invert(j)` is `permutation[j]`, so the indicator bitvector for
block value `x` is simply

```text
bit j  =  (permutation[j] > x)        for j in 0..DOMAIN
```

i.e. a bulk byte-wise greater-than compare of the permutation table against a broadcast
`x`, packed to a bitmask. The right block is then `indicator_mask XOR hash_mask`, where
`hash_mask` packs the LSB of byte 0 of each RO output. Restructured per block:

1. **Indicator mask:** one pass over the (already key-derived) permutation table:
   `mask[j/8] |= ((perm[j] > x) as u8) << (j%8)`. No `Result` per bit, no `invert` calls,
   cache-linear. This is the scalar form of a SIMD `cmpgt + movemask` (§3).
2. **Hash mask:** `hash_all` writes LSBs directly into a stack bitvector
   (`[u8; DOMAIN/8]`) instead of returning `Vec<u8>`. Zero allocations on the encrypt
   path. Also hoist the nonce-keyed hasher out of the block loop — today the AES key
   schedule for the nonce is rebuilt once per block (`bit2.rs:169`) when once per
   encryption suffices.
3. **Right block:** `right.data[n] = indicator_mask ^ hash_mask`. The bit-at-a-time
   `set_bit` loop disappears.
4. **`ro_keys` as template + work buffer:** keep a *template* array whose prefix region
   is extended by one byte per block iteration (instead of rebuilt from zero), and
   `memcpy` it into a work buffer that PRF₁/the RO encrypt in place. Halves the buffer
   traffic and removes the `lazy_static` zero-block dance. Zeroize both buffers once at
   the end of `encrypt` (matching the existing "zeroize at the end is fine" decision in
   TODO).

None of this changes ciphertext bytes — it computes the same masks a different way —
so it lands as a pure performance PR against the refactored core, gated by the PR 1
vectors. Expected win: removal of ~8 allocations and ~8 KiB of redundant writes per
`u64` encrypt, plus a much tighter indicator loop. (Criterion will tell us the real
number; AES remains the floor.)

### 3. SIMD backends (goal 2)

**What vectorises** (all data-parallel, no plaintext-dependent control flow):

| Op | Shape | x86_64 | aarch64 |
|---|---|---|---|
| Indicator mask | bytewise `>` vs broadcast, pack to bitmask | `vpcmpgtb` + `vpmovmskb` (AVX2: 8 iters for 256 lanes; SSE2 fallback: 16) | `cmgt.16b` + bit-narrowing (no movemask; use `ushr`+`addv` or the `vshrn` trick) |
| Hash-LSB mask | strided bit gather from AES output blocks | shifts + `vpmovmskb` on gathered bytes | shifts + narrowing |
| Compare: first-differing-block scan | 16-byte tag equality across blocks | `vpcmpeqb` + movemask, branch-free fold | `cmeq` + fold |

AES itself uses AES-NI automatically on x86_64. **On aarch64 the `aes` crate (v0.8)
requires `--cfg aes_armv8` in RUSTFLAGS to use the ARMv8 Cryptography Extensions;
without it the software backend runs ~60× slower per block** (measured on M1 Max).
The workspace now sets this in `.cargo/config.toml` (PR 3) and the README documents
it for downstream builds — by far the largest single performance lever in this
program for ARM users.

**Mechanism:**

- A small `backend` module: `trait OreBackend { fn gt_mask(table: &[u8], x: u8, out: &mut [u8]); fn lsb_mask(blocks: &[AesBlock], out: &mut [u8]); ... }`
  with `Scalar`, `Avx2` (runtime-detected via `is_x86_feature_detected!` once at
  `OreCipher::init`, stored as an enum/fn-table on the cipher), and `Neon`
  (compile-time: NEON is baseline on aarch64). SSE2 is baseline on x86_64 and can be the
  "scalar" floor there if autovectorisation doesn't already get it.
- `unsafe` confined to `#[target_feature]`-annotated leaf functions in one module;
  everything above the trait is safe.
- **No cargo feature flag.** Runtime dispatch + scalar fallback keeps the build matrix
  trivial and avoids untested feature combinations. Tests parameterise over backends and
  assert bit-identical output vs scalar (and vs PR 1 vectors).
- **Constant-time discipline:** all SIMD ops are fixed-trip-count and branch-free with
  respect to plaintext/key data. The comparator keeps its `subtle-ng` conditional-select
  structure; SIMD only accelerates the per-block equality tests feeding it, and the fold
  stays branch-free. Document this invariant in the module.

### 4. 6-bit block width (goal 3)

A new fixed-N scheme instantiating `(Bit6, Packed, fixed-N)`:

- **PRP:** Knuth shuffle over 64 elements — same algorithm, ~4× cheaper setup, and the
  rejection sampling rejects far less (max 63 vs 255 against a uniform byte).
- **Right block:** 8 bytes (64 bits). 64 RO keys per block → 64+64 AES ops per block
  vs 256+256.
- **Left tag packing:** block values are stored one-per-byte in the prefix region, so a
  `u64` (11 six-bit blocks) packs `11 prefix bytes + xt + index = 13 ≤ 16`. The packed
  construction caps Bit6 at **14 blocks** (= 10 plaintext bytes), which covers every
  primitive up to 64-bit and dates, but **not** `u128`/`i128` (22 blocks) or `Decimal`
  (19 blocks) — those remain on the 8-bit scheme (or wait for the chained prefix, §5).
  This constraint must be a compile-time assertion.
- **Naming:** new module `scheme::bit2_w6` exposing `OreAes128Bit6ChaCha20` (exact name
  bikesheddable in the PR). The existing `scheme::bit2` module and types are untouched.
- **Wire format v2 with a header** (new schemes only — the legacy scheme keeps its
  headerless format forever):

```text
byte 0      : version        (0x02)
byte 1      : scheme id      (width | prefix mode | cipher suite, packed enum)
bytes 2..4  : block count    (u16, big-endian)
bytes 4..   : left ‖ right   (existing layout per block width)
```

  `compare_raw_slices` on v2 schemes validates version + scheme id and returns `None` on
  mismatch — cross-scheme and cross-width comparisons must fail loudly, not silently
  mis-order. Legacy v1 slices are only ever handled by the legacy type. (A v1 ciphertext
  could in principle collide with a v2 length; since each *type* only parses its own
  format, no runtime ambiguity arises.)
- **Domain separation:** the scheme id byte is also mixed into the PRF input layout
  decision space — concretely, Bit6 writes `block_count` into the otherwise-unused byte
  15 of the left-tag input so that identical prefixes under Bit6 and Bit8 can never
  produce related tags under the same keys. (Cheap insurance; needs a nod from crypto
  review.)

### 5. Variable block counts / string encryption (goal 4)

The hard part: the packed prefix cannot represent plaintexts longer than ~14 blocks.
Two changes, deliberately isolated in the final PRs:

**(a) Vec-backed ciphertext types.** `VarCipherText<S>` / `VarLeft<S>` / `VarRight<S>`
mirroring the const-generic types but with `Vec<...>` storage and the v2 header carrying
the block count. The comparator generalises to different lengths: scan for the first
differing block over `min(n_a, n_b)`; if none, the shorter ciphertext sorts first
(correct lexicographic semantics for strings; numerics keep using fixed-N types where
length never varies). The scan stays constant-time *within* the compared range; total
length is public anyway (it's in the header).

**(b) Chained prefix binding.** The packed prefix cannot exceed one AES block, so the
variable-length scheme needs an *accumulator*: absorb the prefix incrementally, and at
each block position derive the per-block secrets/outputs (PRP seed, left tag, RO keys)
from the accumulated state. Every viable design has this shape; the candidates differ
in **what the chain state is** and **how per-position branch outputs are
domain-separated**. Three candidates go to crypto review:

**Candidate A — Cascade/GGM (chain through the key slot).**

```text
t₀           = E_k(CONST)                    — master key never used as a chain key
tᵢ           = E_{t_{i-1}}(0x00 ‖ xᵢ  ‖ i)   — chain step
prp_seedᵢ    = E_{t_{i-1}}(0x01 ‖ 0   ‖ i)   — keys the block-i PRP
fᵢ           = E_{t_{i-1}}(0x02 ‖ xtᵢ ‖ i)   — published left tag
ro_key(i,j)  = E_{t_{i-1}}(0x03 ‖ j   ‖ i)   — RO keys, j ∈ 0..DOMAIN
```

(16-byte inputs: tag byte, value byte, u16 index, zero padding — trivially injective.)

The state after prefix `p` is a GGM *constrained key* for the subtree of plaintexts
extending `p` — exactly the semantic object ORE prefix logic wants. Everything
published at position `i` lives under key `t_{i-1}`; the next chain state is one of
that key's outputs at a tag-separated point, so the "published outputs vs chaining
values" interaction vanishes structurally. Security is a textbook hybrid over chain
depth (`q·n·ε_PRP` plus a `(total blocks)²/2^129` state-collision term), with no
related-key assumptions (keys are PRF outputs; nothing is ever XORed into a key).
Bonus: the `prp_seed` branch **subsumes PRF₂** — single master key — and is
per-`(prefix, i)`, fixing the repeated-PRP-seed TODO (`bit2.rs:78-81`) for new schemes.
Cost: one AES-128 key expansion per block — cheap on x86_64 (`AESKEYGENASSIST`),
software on aarch64 (no key-schedule instruction); estimated 5–20% overhead against
Bit6's ~130 batched AES ops per block. **Benchmark gate:** measure NEON key-expansion
overhead before committing.

**Candidate B — CMAC with cached prefix state.** Every published value is a *bona
fide* AES-CMAC (NIST SP 800-38B) tag of an injectively encoded message — for block
`i`: `enc(x₀‖0) ‖ … ‖ enc(x_{i-1}‖i−1) ‖ final_block(branch, value, i)` — and the
per-prefix chaining-state cache is purely an implementation optimization (CMAC is CBC
inside; clone-state-then-finalize *is* incremental CMAC). Security then reduces to
CMAC's PRF security plus three auditable claims: (1) the message encoding is injective
across blocks/branches/widths, (2) the incremental implementation is faithful to
one-shot CMAC (tested against the `cmac` crate's vectors), (3) cached secret states
are zeroized. One key schedule total (plus CMAC's two subkeys). PRF₂ remains separate
(or becomes another branch family).

**Candidate C — XE-style masked single-key chaining.** The original sketch with ad-hoc
tag bytes replaced by Rogaway `2ⁱ3ʲ·L` masks in GF(2^128): `L = E_k(0¹⁶)`,
`tᵢ = E_k(t_{i-1} ⊕ Δᵢ ⊕ enc(xᵢ))` with `Δᵢ = 2ⁱ·L`, branches under `3·Δᵢ` and
`3²·Δᵢ`. One key schedule and one GF doubling per block — strictly fastest. Caveat:
masks and tag bytes are analytically equivalent here (both give within-node
disjointness; cross-node collisions are birthday-bounded either way), and the
PMAC-lineage analyses publish only a final tag — so the many-outputs-per-state
argument remains bespoke. Weakest off-the-shelf story relative to its speed advantage;
the doubling must be constant-time.

| | A: Cascade/GGM | B: CMAC cached-state | C: XE masked CBC |
|---|---|---|---|
| Chain state | AES key | 128-bit CBC value | 128-bit XOR value |
| Key schedules | 1 per block | 1 (+2 subkeys) | 1 |
| Branch separation | re-key per node + tag bytes | each output a full CMAC tag | GF(2^128) masks |
| Security story | constrained-PRF/GGM hybrid — cleanest | citable, if outputs are genuine tags | PMAC-lineage techniques, bespoke composition |
| Review surface | hybrid writeup only | encoding injectivity + impl faithfulness | many-outputs-per-state argument |
| Perf risk | key expansion on aarch64 | none | none (CT doubling) |
| Bonus | subsumes PRF₂, fixes PRP-seed TODO | standards citation | — |

**Decision rule:** Candidate A if the NEON key-schedule benchmark comes in under
~10–15% on Bit6-width strings; otherwise Candidate B. Candidate C only if profiling
rules out both. Whichever wins, **internal crypto review happens before PR 6 is
written, not after.** The fixed-N schemes never use the accumulator, so review risk
doesn't block goals 1–3.

> **Benchmark gate result (2026-06-13, Apple M1 Max, hardware AES):** key expansion
> costs ~172 ns ≈ 160 batched block encryptions (no key-schedule instruction on
> aarch64), making Candidate A's per-block overhead **~84%** at Bit6 width (~35% at
> Bit8) — roughly 6× over the threshold. The CMAC/XE-style control (one extra
> encryption per block) measured ~0%. **The decision rule selects Candidate B (CMAC
> with cached prefix state).** Spike code preserved at `/tmp/ore-keyexp-spike`
> (re-runnable; numbers recorded here are the durable record).

Cost shape is preserved in all candidates: the prefix is absorbed once per block, and
the `DOMAIN` RO keys per block remain a single batched `encrypt_all` under one cipher
instance, so right-encryption throughput stays comparable to the packed scheme.

**String semantics and leakage.** Strings are encoded as their UTF-8 bytes (optionally
case-folded/normalised upstream — out of scope here), decomposed by the chosen width.
Lewi-Wu leaks the index of the first differing block; for strings that is **the length
of the common prefix**, which is materially more revealing than for fixed-width numerics.
This must be documented prominently on the string API, and is a product-level decision
about acceptable leakage, not something the library can engineer away.

### 6. Random-oracle instantiation (the 1-bit hash H)

Lewi-Wu models the right-ciphertext mask as a random oracle `H(ro_key, nonce) → Z₂`.
Today it is instantiated as `LSB(AES_nonce(ro_key))` — the **nonce as the AES key** —
and the code has carried a TODO questioning that construction since the beginning
(`bit2.rs:158-168`). The original C implementation used SHA-256 here and was
measurably slower. Because Bit6 (PR 5) is a new scheme with no compatibility
constraint, the H decision must be made **before PR 5** — Bit6 should ship with the
chosen H rather than inherit nonce-as-key. The legacy Bit8 scheme keeps the status quo
forever.

Hard constraint: H is computed by a **keyless comparator** (e.g. inside Postgres) from
two public ciphertexts — it may use the nonce and published left tag, but no long-term
secret. Any "PRF under a third key" design is therefore out. Candidates (`x` = RO
key / left tag, `r` = nonce):

| # | Construction | Security model | Cost vs today | Notes |
|---|---|---|---|---|
| 1 | `LSB(AES_r(x))` — status quo | ideal cipher | — | key is public, so AES's standard PRP assumption gives nothing; security is an ideal-cipher assertion |
| 2 | `LSB(AES_r(x) ⊕ x)` — MMO feedforward | ideal cipher | +1 XOR | matches the analyzed blockcipher-hashing shape; feedforward removes the invertible-public-permutation structure; the minimal upgrade |
| 3 | `LSB(π(x ⊕ r) ⊕ x)`, `π = AES_{K₀}`, K₀ public constant | random permutation | **faster** — zero key schedules ever | fixed-key-AES hashing (BHKR13); mine GKWY20 for known `x ⊕ r` tweaking pitfalls (our requirements are weaker than garbling's — no circularity, no correlated keys) |
| 4 | `LSB(AES_x(r))` — RO key as AES key | **standard model** (PRF) | ~2–4× right-encryption: one key schedule per `(i, j)` | what the old TODO was reaching for; the honest price of standard-model security; composes poorly with accumulator Candidate A (both pay per-block schedules) |
| 5 | SHA-256 (HW) / Blake3 over `x ‖ r` | random oracle | 2–5× encrypt path | comparator computes H once per comparison, so query latency is unaffected — only encryption throughput pays |

Proposal into review: **#3, with #2 as the conservative fallback**, and #4 written up
with its *measured* cost so the standard-model option is accepted or declined with the
price visible. The 1-bit truncation (LSB of a pseudorandom block) is uncontroversial
in every model.

## PR roadmap

| PR | Title | Depends on | Size | Risk |
|---|---|---|---|---|
| 1 | **Compatibility vectors + bench baselines.** Pin hex test vectors for `encrypt_left` (deterministic) and `encrypt` (via seeded RNG through the existing `OreAes128<R>` generic) for known keys/plaintexts, plus serialised-format and comparison fixtures. Record criterion baselines. | — | S | none |
| 2 | **Core refactor.** Introduce `BlockWidth`, `BlockDecomposer`, `IndicatorEncoder` (scalar), template-based `ro_keys`; re-express `OreAes128` on top. Byte-identical per PR 1 vectors. | 1 | L | medium (mitigated by vectors) |
| 3 | **Efficient unary encoding.** Permutation-direct indicator mask, bit-packed hash mask, allocation-free encrypt path. Bench deltas in PR description. | 2 | M | low |
| 4 | **SIMD backends.** AVX2 + NEON (+ SSE2 floor) behind runtime dispatch; backend-equivalence tests; CI coverage for both arches. | 3 | M | low |
| 5 | **Bit6 fixed-N scheme + wire format v2.** New scheme type, 64-domain PRP, v2 header, cross-scheme comparison rejection, `OreEncrypt` impls for primitives ≤ 64-bit + chrono. Ships with the H construction chosen in §6. Includes the NEON key-expansion benchmark spike that feeds the §5(b) decision rule. | 2 (parallel with 3/4); §6 H decision | M | medium |
| 6 | **Chained prefix + variable-length ciphertexts + string encryption.** Implements the §5(b) candidate selected by the decision rule. Includes leakage documentation. | 5; §5(b) benchmark gate + crypto review | L | high (crypto) |
| 7 | **Docs, examples, migration guide, README perf table refresh.** | 4, 5, 6 | S | none |

PRs 3/4 and 5 are independent after PR 2, so they can proceed in parallel. Each PR keeps
`main` releasable; release-plz handles version bumps (all semver-minor under 0.x except
PR 2's trait change, which should be called out in the changelog).

## Testing strategy

- **Vectors (PR 1) as the refactor contract:** every later PR runs them unchanged for
  the legacy scheme.
- **Property tests:** extend the existing quickcheck suite to Bit6 and variable-length
  (order-agreement, equality, serialisation round-trip, cross-length string ordering vs
  `str::cmp` on random strings).
- **Backend equivalence:** scalar vs SIMD byte-identical ciphertexts over randomised
  inputs, run on both x86_64 and aarch64 CI runners.
- **Negative tests:** cross-scheme/cross-width `compare_raw_slices` returns `None`;
  malformed v2 headers return `ParseError`.
- **Benchmarks:** criterion groups per scheme × operation (encrypt, encrypt_left,
  compare, serialise); baselines recorded in PR 1 so each PR reports a real delta.

## Security review checklist (tracked across PRs)

- [ ] Constant-time invariants preserved in SIMD paths and the variable-length scan
      (PR 4, 6).
- [ ] Zeroization coverage of new buffers: PRP-seed buffer, `ro_keys` template/work
      buffer, decomposer output, accumulator state (PR 2, 3, 6).
- [ ] PRP seeds (PRF₂ outputs) structurally separated from serializable `Left` state;
      no code path can write seed material into a ciphertext (PR 2).
- [ ] Domain separation between Bit8/Bit6/chained schemes under shared keys (PR 5, 6).
- [ ] H instantiation (§6) selected and signed off, with its security model
      (ideal-cipher / random-permutation / standard) recorded (before PR 5).
- [ ] Selected §5(b) accumulator candidate reviewed and signed off (before PR 6).
- [ ] Accumulator chain state treated as key material: zeroized, never serialized,
      never reachable from `Left`/`Right` types (PR 6).
- [ ] GF(2^128) doubling constant-time, if Candidate C is chosen (PR 6).
- [ ] String leakage profile documented and acknowledged at product level (PR 6).

## Decisions taken (revisit if needed)

1. **Trait-based `BlockWidth` over const-generic width** — `generic_const_exprs` is
   unstable; sealed traits with associated consts/types are the stable idiom.
2. **No SIMD cargo feature** — runtime dispatch with scalar fallback; smaller test
   matrix beats opt-in vectorisation.
3. **Legacy scheme stays headerless forever; only new schemes get the v2 header** —
   avoids any migration of stored data.
4. **Bit6 fixed-N keeps the packed prefix** (capped at 14 blocks) rather than waiting
   for the chained construction — ships goal 3 without the crypto-review dependency;
   `u128`/`Decimal` on Bit6 arrive with PR 6 if wanted.
5. **Strings use the chained-prefix variable-length scheme regardless of width**; width
   choice (6 vs 8) for strings is a ciphertext-size trade-off left to the PR 6 design.
6. **H decision is pulled forward to before PR 5** (not PR 6): Bit6 is a new scheme and
   should ship with the chosen H rather than inherit nonce-as-key for compatibility's
   sake. Proposal: fixed-public-permutation MMO (§6 option 3), conservative fallback
   MMO-with-nonce-key (option 2).
7. **Accumulator choice is a decision rule, not a fixed pick:** cascade/GGM if NEON
   key-expansion overhead measures under ~10–15% on Bit6 strings, else CMAC with
   cached state; XE only if profiling eliminates both (§5(b)).

## Open questions

1. **Cheaper PRP for new schemes:** for Bit6's 64-element domain, a small-domain
   constant-time PRP (e.g. swap-or-not or a sorting network) could beat the Knuth
   shuffle and be SIMD-friendly. New schemes have no compatibility constraint — worth a
   spike during PR 5, not a blocker.
2. **`u16` vs `u8` block count in the v2 header:** u16 chosen for strings; confirm no
   need for >65 535 blocks (≈48 KiB plaintext at Bit6).
3. **Should Bit6 become the default scheme** recommended in the README once shipped, with
   Bit8 positioned as the legacy/compat scheme? Affects docs tone in PR 7.
4. **Pending review outcomes:** the §5(b) accumulator and §6 H selections await the
   NEON benchmark spike (PR 5) and internal crypto review; decision rules and
   candidate write-ups are inline in those sections.
