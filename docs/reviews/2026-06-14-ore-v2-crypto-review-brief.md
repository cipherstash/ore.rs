# ORE v2 — crypto review brief (decisions A1–A4)

**Date:** 2026-06-14
**Author:** Dan Draper (via Claude Code)
**Audience:** crypto sign-off reviewer (internal)
**Source of truth:** `docs/plans/2026-06-12-ore-v2-architecture.md` (§5b, §6, Open Q1).
This brief is self-contained; section/line refs let you drill in.

---

## 0. What you're being asked to sign off (TL;DR)

Four crypto decisions gate the v2 work. Two block a PR that is already open
(#82); two block PR 6 (not yet written).

| # | Decision | Model claimed | Status in code | Blocks |
|---|----------|---------------|----------------|--------|
| **A1** | 1-bit hash `H` instantiation | random-permutation (BHKR σ-MMO) | ✅ **RESOLVED** — `FixedPiZ2Hash` = `LSB(π(σ(x)⊕r)⊕σ(x)⊕r)`, σ(x)=2x | — (was the Bit6-vector gate; now cleared) |
| **A2** | Chained-prefix accumulator = AES-CMAC cached-state | CMAC PRF (standard) + 3 auditable claims | designed, not yet coded | PR 6 (variable-length / strings) |
| **A3** | PRP keystream from the accumulator (shape ii) | statistical (≤2⁻⁵⁵) + branch-family soundness | shape (i) shipped; (ii) deferred | PR 6 perf; couples to A2 |
| **A4** | Secret-indexed swap in PRP key-gen — ratify alignment + MemJam posture? | ~~constant-time / cache-line (sub-line = oblivious tier)~~ **oblivious key generation, every target** (2026-10-09) | oblivious builder (NEON / SSSE3 / SWAR) is the default, byte-identical tables; oblivious table reads and compare read; `N = 64` guard | nothing — fixes are byte-stable; A1 alone gates vectors |

**Recommended sequencing:** **A1 is resolved** (BHKR σ-MMO) — Bit6 vectors can now
be generated and pinned against it. **A4 is a ratification** of changes already
applied (none of which alter ciphertexts); the MemJam posture call it carried
was overtaken on 2026-10-09, when a measured timing dependence made the
oblivious builder the default rather than a tier (§5, "Status"). Then
**A2 + A3 as one pass** (they gate PR 6, and A3 only exists inside A2's
accumulator).

**What is explicitly *not* in scope:** the legacy Bit8 scheme is wire-frozen and
byte-identical to v1 (`tests/compat_vectors`); it keeps all status-quo
constructions forever and is out of review. Everything below concerns *new,
not-yet-frozen* schemes only.

---

## 1. Construction primer (the parts these decisions touch)

ORE here is **Lewi-Wu (2016) small-domain "BlockORE"**, a *left/right* scheme:

- A plaintext is decomposed into blocks. Bit8 → blocks over `DOMAIN = 256`;
  the new **Bit6** scheme → `DOMAIN = 64`.
- Per block, a **PRP** `π` permutes the `DOMAIN` symbols (keyed per block from a
  prefix-dependent seed — this is **A3/A4**).
- The **right ciphertext** of a block is a length-`DOMAIN` vector: for each
  permuted symbol `j`, a comparison result `cmp(π⁻¹(j), x)` masked by a 1-bit
  value `H(ro_key(i,j), nonce)` (this is **A1**).
- The **left ciphertext** of a block is the permuted index of the plaintext
  symbol plus a published tag.
- **Comparison** is evaluated by a *keyless* comparator (e.g. in Postgres)
  between one left and one right ciphertext; it recomputes `H` from public
  material only — hence H may use the nonce and published tags but **no
  long-term secret** (this constraint drives **A1**).
- For plaintexts longer than one packed AES block (~14 Bit6 blocks), the
  per-block secrets must be derived from an **accumulator** over the prefix
  (this is **A2**, which also hosts **A3**).

Leakage (for completeness, not under review): a comparison reveals the index of
the first differing block. For strings that is common-prefix length. This is a
property of *comparison*, not stored data — right-only-at-rest reveals nothing;
the disclosure is query-time/online only (plan §5b, "String semantics and
leakage").

---

## 2. A1 — the 1-bit hash `H`  (§6) — ✅ RESOLVED 2026-06-15

### The question
`H(x, r) → Z₂` where `x` = RO key / left tag, `r` = per-ciphertext nonce. It must
be computable by a **keyless** comparator from public ciphertext material (no
long-term secret), so any "PRF under a third key" design is out.

### Resolution
**Keep option 3 (fixed public-key AES), upgraded with the BHKR orthomorphism.**
Shipped construction (`packages/ore-rs/src/primitives/hash.rs`, `FixedPiZ2Hash`):

```
H(x, r) = LSB( π(σ(x) ⊕ r) ⊕ σ(x) ⊕ r ),   π = AES-128_{K₀},  σ(x) = 2·x in GF(2^128)
```

i.e. the **BHKR/Zahur fixed-key σ-MMO** with output truncated to 1 bit.

- `K₀ = PI_KEY = b"ORE-rs.v2.H-pi.1"` — nothing-up-my-sleeve, deliberately
  public; security rests on AES as a good *public random permutation*, not key
  secrecy. Expanded once per process.
- `σ(x) = 2x` is the GF(2^128) doubling orthomorphism (same "multiply by x" as
  CMAC subkeys; constant `0x87`), constant-time, branch-free (`gf128_double`).
  Both `σ` and `σ⊕id` are permutations.
- `hash` (comparator) and `hash_all_into` (encryptor, scalar + SIMD `lsb_mask`)
  verified equivalent (`fixed_pi_scalar_matches_bulk`); doubling checked against
  the textbook shift/0x87 rule (`gf128_double_reduction`).

### Why this is sound for ORE (the core justification)
The known attacks on fixed-key MMO **do not port to ORE**, and we now have the
exact reason from the literature:

- **eprint 2019/1168** (Guo–Katz–Wang–Weng–Yu, *Better Concrete Security for
  Half-Gates*) attacks the fixed-key construction `π(2x⊕i)⊕2x⊕i` in the
  multi-instance garbling setting with success `O(p·C/2^k)` — but the attack
  works by **recovering a global Free-XOR offset `R` from *known* hash inputs**
  (the evaluator holds wire labels `Wa` and gate ids `j`, learns
  `H(Wa⊕R, j)`, then meet-in-the-middles over `π`).

  > **Restated 2026-10-08 — signed off 2026-10-09 (Dan Draper)** (review of #82). The original
  > text said ORE has neither precondition because its `H` inputs are secret
  > and the adversary never learns them. That premise is false: `Left.f[n]`
  > *is* the RO key at the published symbol `xt[n]`, and the comparator feeds
  > it straight to `H`. Every left ciphertext or query token reveals one `H`
  > input per block, by design: those are the bits it exists to unmask.
  >
  > The right model: for block `n` with prefix `p`, each candidate `j` has an
  > RO key `k_{p,j}`, a secret PRF output shared by every ciphertext with that
  > prefix; each stored ciphertext `i` has a public nonce `r_i`; the right block
  > publishes `ind_j ⊕ H(k_{p,j}, r_i)`. Revealed tags are independent PRF
  > outputs, so they say nothing about the *unrevealed* keys. For an
  > unrevealed `k`, since `σ` is linear, `σ(k) ⊕ r_i` is a secret shared across
  > instances plus known per-instance offsets: exactly the BHKR
  > correlation-robustness setting, with `k` in the role of the global offset
  > `R`. So GKWY's multi-instance shape **is** present, not structurally
  > absent, and the honest statement is their bound: an attacker making `p`
  > offline `π` queries against `C` targeted unrevealed keys succeeds with
  > probability about `p·C/2^128`. Testing a guess needs known indicator bits
  > (known or chosen plaintexts) for that key, since `H` outputs one bit.
  > Success against one key unmasks candidate `j` in every stored ciphertext
  > with that prefix, the same capability as one extra query token.
  >
  > The conclusion stands for realistic `p` and `C` (for example `p = 2^80`,
  > `C = 2^32` gives `2^-16`, and the per-key verification cost rises with the
  > one-bit output), but it rests on that bound, not on the inputs being
  > secret. Theorem 2's re-keyed variant would remove the multi-instance
  > factor; it is still declined for the comparator-speed reason below, now as
  > a trade-off against a stated bound rather than against a non-issue.
- Their tight fix (Theorem 2, `E(i, σ(x))⊕σ(x)` — tweak as the AES *key*) is
  **deliberately not adopted**: it requires rekeying per evaluation, which breaks
  the keyless-comparator/performance requirement, and it fixes a degradation ORE
  doesn't suffer. **Do not chase Theorem 2.**
- **eprint 2025/792** (Chen–Guo–List–Shi–Zhang, *Scrutinizing AES-based Hashing*)
  is cryptanalysis of **collision / preimage / one-wayness** — properties this
  1-bit hash does not rely on — and its best AES-128 results are **round-reduced**
  (7/10 collision on AES-MMO/MP at 2⁶⁰, 4/10 on AES-DM), never reaching full AES.
  Mild evidence *for* the random-permutation assumption at full rounds.

### Why the orthomorphism (the only change from the original draft)
Plain MMO (`σ = id`) would already be fine for ORE's independent-secret-input
setting. `σ(x)=2x` is adopted as **cheap defense-in-depth** (a few branch-free
ops) so security holds **by matching the named BHKR/Zahur construction** rather
than by a usage argument about input independence — robust-by-construction vs
robust-by-argument. The 1-bit truncation is uncontroversial in every model.

### Status
Resolved. `FixedPiZ2Hash` updated. This **changes Bit6 right ciphertexts**, so
Bit6 byte vectors are (re)generated against this construction when pinned — A1 is
the gate that was holding that, and it is now cleared.

---

## 3. A2 — chained-prefix accumulator = CMAC cached-state  (§5b; blocks PR 6)

> **Full design spec (2026-06-15):** `docs/plans/2026-06-15-ore-v2-cmac-accumulator-spec.md`
> — pins the injective message encoding, per-block algorithm, security argument,
> and test plan that this section summarises.

### The question
PR 6 (variable-length / strings) needs an accumulator that absorbs the prefix
incrementally and, at each block position, derives the per-block secrets/outputs
(PRP seed, left tag, RO keys). **Candidate B — AES-CMAC with cached prefix
state** was selected by a benchmark gate; sign off its design before PR 6 is
written.

### Why B (the gate result, durable record in §5b)
- **Candidate A (Cascade/GGM, chain through the AES key slot)** — cleanest
  security story (constrained-PRF/GGM hybrid, no related-key assumptions) but
  **rejected on performance**: on Apple M1 Max with hardware AES, an AES-128 key
  expansion costs ~172 ns ≈ 160 batched block encryptions (no key-schedule
  instruction on aarch64), making per-block overhead **~84%** at Bit6 — ~6× over
  the ~10–15% threshold. (Spike at `/tmp/ore-keyexp-spike`.)
- **Candidate C (XE-style GF(2¹²⁸) masked single-key CBC)** — fastest, but the
  many-outputs-per-state argument is bespoke (PMAC-lineage analyses publish only
  a final tag). Held in reserve.
- **Candidate B** — control measured ~0% overhead and has a citable standards
  basis.

### The design to review
Every published value is a *bona fide* **AES-CMAC (NIST SP 800-38B)** tag of an
injectively encoded message. For block `i`:

```
msg(branch, i) = enc(x₀‖0) ‖ enc(x₁‖1) ‖ … ‖ enc(x_{i-1}‖i−1) ‖ final(branch, value, i)
tag            = CMAC_k( msg(branch, i) )
```

with separate **branch families**: chain step, `prp_seed` (this hosts A3),
left tag `f`, and `ro_key(i, j)` for `j ∈ 0..DOMAIN`. The per-prefix
chaining-state cache (clone-CBC-state-then-finalize) is **purely an
implementation optimization** — incremental CMAC, not a new primitive.

Security reduces to **CMAC's PRF security** plus three auditable claims:
1. **Encoding injectivity** — `msg(branch, i)` is injective across blocks,
   branches, and block widths (so no two distinct logical outputs share a CMAC
   input).
2. **Implementation faithfulness** — the incremental/cached implementation is
   bit-identical to one-shot CMAC (will be tested against the `cmac` crate's
   vectors).
3. **Zeroization** — cached secret states are zeroized; never serialized; never
   reachable from `Left`/`Right` types.

### What needs scrutiny
1. **The injective encoding is currently a sketch** — it must be specified
   exactly (field widths, the `enc(·)` block format, the `final(branch,…)`
   block, domain-separation tags between the 4 branch families) and then checked
   injective. This is the load-bearing claim.
2. **Many outputs per prefix state.** Standard CMAC analyses publish one tag;
   here we publish chain + seed + tag + `DOMAIN` RO keys per position. This is
   sound iff all inputs are distinct (claim 1) and CMAC is used purely as a PRF —
   confirm there's no subtlety in deriving the *next chain state* from a tag that
   is itself published (the GGM design made this vanish structurally; CMAC needs
   the chain-state branch domain-separated from published branches).
3. **PRF₂ disposition** — does PRF₂ remain a separate key or become another
   branch family? (Either is claimed fine; pick one.)

### Decision & what it unblocks
Sign off the CMAC design (after the encoding is fully specified) → PR 6 can be
written. Fixed-N schemes never touch the accumulator, so this does **not** block
goals 1–3 or #82.

---

## 4. A3 — PRP keystream from the accumulator, "shape (ii)"  (Open Q1; rides with A2)

### Background: the PRP question is otherwise resolved
Open Q1 (cheaper PRP for new schemes) is **resolved by spike**
(`/tmp/ore-prp-spike`, RESULTS.md). Winner: **fixed-draw Fisher–Yates with
Lemire-reduced wide draws** — `N−1` fixed draws, each a 64-bit value reduced by
multiply-high `((x·m) >> 64)`, zero rejection sampling, branch-free. Security:
exact statistical distance **≤ 2⁻⁵⁵** (for N=64) from a uniformly random
permutation — the object Lewi-Wu already models — so it adds a *pure statistical
term*, no new assumption.

This is **shipped as `LemireFyPrp<64>`** for Bit6 (PR 5),
`packages/ore-rs/src/primitives/prp.rs:135-229`. It already (a) closes a
plaintext-dependent timing channel in the old rejection-sampled PRNG and (b)
removes a power-of-two modulo bias, and takes Bit6 u64 encrypt 11.5 → 8.6 µs.
**Swap-or-not was rejected** (its `8N^{3/2}/(r+4)` bound is vacuous at q=N, and
ORE exposes a block PRP's full codebook). Bit8 stays on the Knuth shuffle
(wire-frozen).

### The narrow question for review
Shipped **shape (i)** keys a *fresh AES-128 key schedule per block* to produce
the FY keystream (`prp.rs:164-169`: `Aes128::new(seed)` then 32 CTR blocks).
**Shape (ii)** produces the same keystream from the *already-scheduled
accumulator cipher* (a `prp_seed` branch family of A2's CMAC), eliminating the
per-block key schedule — the ~1.9 µs that separates 8.6 µs from the projected
≈3.3 µs.

The math (FY + Lemire, ≤2⁻⁵⁵) is unchanged. The **only new question** is whether
sourcing the PRP keystream from the accumulator's PRF output is sound:
1. The `prp_seed` branch must be **domain-separated** from the chain/tag/ro_key
   branches (no keystream reuse across roles).
2. The keystream-as-PRP-randomness reuse pattern must not interact badly with
   the same cipher's other outputs.

This is **why A3 is reviewed inside A2** rather than as a bespoke key-reuse hack
bolted onto PR 5.

### Decision & what it unblocks
Approve (or reject) deriving the PRP stream as a CMAC branch family. Unblocks the
PR 6 PRP perf target (~3.3 µs). No effect on #82 (which ships shape (i)).

---

## 5. A4 — secret-indexed swap in PRP key generation  (Open Q1; couples to Bit6 vectors)

### Status (2026-10-09): superseded — oblivious key generation is the default
The rest of this section records what was believed and decided before
2026-10-09; read it as history. What changed:

- **Measured.** A dudect run on Apple M4 (2026-10-09,
  `docs/reviews/2026-10-09-ore-v2-dynamic-verification.md` §4.2) found the
  builder's time depending on *which* permutation it builds, on a core with no
  SMT sibling and no co-tenant: fixed stream A against fixed stream B reached
  |t| = 65 at 100 k samples. Isolating the two halves of the builder put the
  whole signal in the Fisher–Yates swap loop; the inverse fill alone, and both
  halves redone at public addresses, showed none. That is consistent with
  store-to-load forwarding and memory disambiguation on byte-granular accesses
  at secret offsets inside one L1-resident line: whether a load overlaps a
  store still in flight depends on the draws. The one-cache-line argument
  below is about which *line* is touched and does not cover it, and "ARM: this
  mechanism does not apply" in the MemJam analysis is true of MemJam but not
  of this: it needs no co-tenant, only a clock.
- **Changed.** Key generation now goes through oblivious builders that never
  use a secret value as an address (`primitives/prp/oblivious.rs`): both
  tables live in registers, `perm[j]` is fetched by a table lookup on a
  broadcast `j` and written back by compare-and-select, and the inverse is kept
  by exchanging the *values* `i` and `j` in it at each step, which needs
  neither swapped entry and replaces the separate fill. Step `i` is public and
  `j ≤ i`, so only the chunks covering `0..=i` are searched. The draws and the
  swap sequence are the same, so the tables are **byte-identical** and no
  vector moves. Dispatch: **NEON** on aarch64 (baseline, no runtime check),
  **SSSE3** (`pshufb`) on x86_64 when the CPU reports it, a **u64 SWAR** form
  everywhere else. The textbook builder survives only as a test-only
  reference that the others are property-tested (and, for SWAR, Kani-proved)
  equal to.
- **Cost.** On aarch64 the oblivious builder is *faster* than the indexed one
  it replaced, so there is no tier and nothing for a deployment to opt into.
  Apple M4 on mains power, criterion medians, per 512-byte stream: indexed
  248 ns, **NEON 199 ns (−20%)**, SWAR 710 ns (2.9×). End to end the NEON
  builder takes 6–10% off every encrypt (Bit6 u64 8.59 → 7.89 µs, left-only
  6.33 → 5.77 µs; full tables in
  `docs/benchmarks/2026-06-13-bit6-prp-results.md`, addendum 2026-10-09).
  The SWAR fallback costs 58–95% end to end on targets with neither NEON nor
  SSSE3. SSSE3 timing on real x86 hardware has not been measured.
- **After.** dudect, same machine and session, fixed A against fixed B with a
  fresh pair per 100 k-sample run: the indexed builder |t| = 17 to 83 over
  five runs, the NEON builder at most 1.9 (and −0.8 pooled over 92 M samples
  in 150 s); the end-to-end left-only Bit6 test that showed |t| = 21.6 now
  stays under 2.4. Figures in the verification doc.

So the recommendation below (default = line-granularity; oblivious-swap FY as
a paranoid tier at ~3×) is **withdrawn**: the oblivious builder is the only
builder, on every target. Sort-by-random-key stays rejected (see its
subsection). The checklist item is resolved accordingly.

### The question
FY key generation performs a swap whose **address is secret-derived**:

`prp.rs:189-196`:
```rust
for i in (1..$domain).rev() {
    let d = $domain - 1 - i;
    let x = u64::from_le_bytes(stream[d*8 .. d*8+8]);
    let j = ((x as u128 * (i as u128 + 1)) >> 64) as usize;  // secret j
    perm.permutation.swap(i, j);                              // secret-indexed write
}
```

`j` depends on the (secret, prefix-derived) keystream, so the *memory address
written* is secret. Do we accept the **one-cache-line argument** (the whole
permutation table fits in a single cache line, so the access pattern leaks
nothing through the cache), or require the strictly-constant-time fallback?

### Discrepancy found, now fixed (pending scrutiny)
The plan (Open Q1) stated the mitigation is a **64-byte cache-line-aligned
table**, but the originally shipped struct had **no alignment** (default
alignment 1), so the 64-byte `permutation` array could straddle two lines —
weakening, not establishing, the one-cache-line argument. There are in fact
**two** secret-indexed writes during key generation that the argument must
cover, not one:
- the Fisher–Yates `permutation.swap(i, j)` — secret `j` (`prp.rs:195`);
- the inverse fill `inverse[val] = …` — secret `val` (`prp.rs:198-200`).

**Fix applied** (uncommitted, pending this review): `#[repr(C, align(64))]` on
`LemireFyPrp` (`prp.rs:135-139`). `repr(C)` pins field order so `permutation` is
at offset 0; `align(64)` puts the struct on a line boundary. At `N = 64` each
`[u8; 64]` table is exactly one line — `permutation` → line 0, `inverse` →
line 1 — so both secret-indexed writes are line-uniform. The argument holds only
for **N ≤ 64**; the sole instantiation is `LemireFyPrp<64>`. A `const _ =
assert!(N <= 64)` guard is proposed to make a larger instantiation a compile
error.

### Context
- The **read** paths were *not* all constant-time, contrary to what this item
  first said (review of #82). `indicator_mask_xor` scans the *entire*
  permutation table via a branch-free `gt_mask` kernel, but `permute` read
  `inverse[x[n]]` indexed by the **plaintext symbol**, and `invert` read
  `permutation[j]`. Alignment defends only cache-line granularity, and the
  sub-line MemJam channel below would reveal plaintext bits directly through
  `permute`. Both now read every entry and select in constant time
  (`oblivious_lookup` in `prp.rs`, also applied to the legacy Bit8 PRP with
  identical output). The **key-generation writes** (above) remain the
  secret-indexed accesses, and the high-assurance tier must cover both the
  writes and these reads: an oblivious-swap builder alone would not make the
  tier oblivious if the reads were left indexed.
- Same class of issue exists in **vitaminc** (filed cipherstash/vitaminc#198)
  and in the legacy Bit8 Knuth path (wire-frozen — documented, not fixed).
- **Two fallback forms, only one is wire-compatible** (this matters — see "MemJam
  & the oblivious tier" below): an **oblivious-swap Fisher–Yates** (same FY, same
  Lemire draws, constant-time `swap`/inverse-fill via full-scan conditional
  select) produces the **identical permutation** → identical ciphertext →
  drop-in, vectors unchanged, ~O(N²) swap cost. A **different construction**
  (swap-or-not) produces a *different* permutation → incompatible wire format,
  and was rejected on the q=N proof anyway. The oblivious-swap form is the one to
  reach for.
- **MemJam caveat (full analysis below):** cache-line alignment defends only at
  *line* granularity; the sub-line (4-byte) MemJam channel on SMT-enabled Intel
  is closed only by an oblivious construction.

### Block-width asymmetry — the one-cache-line property is Bit6-only
The construction-time argument does **not** scale to a hypothetical
`LemireFyPrp<256>` (8-bit width), and the asymmetry is a positive argument for
Bit6 as the default (open question 3):
- **Construction (encryptor host) — strictly worse at D = 256.** The table is
  256 bytes = **4 cache lines**, so each swap leaks ~2 bits (which-of-4-lines).
  And there are more swaps per block (D−1 = **255 vs 63**): a u64 is **8 blocks ×
  255 = 2040** secret-indexed swaps at Bit8 vs **11 × 63 = 693** at Bit6. Larger
  domain grows swaps faster than it shrinks block count, so the "fewer blocks"
  intuition inverts. No offsetting benefit on this axis.
- **Comparison (comparator host) — tied.** The compare-side secret-indexed
  access is `get_bit(target_block, a[l])` (next subsection). The right block is
  256 bits = **32 bytes** at Bit8 and 64 bits = **8 bytes** at Bit6; both are
  ≤ 64, so both fit within one cache line given alignment. Bit8 is **not** better
  here — both widths are line-uniform.
- These two leaks are on **different machines** (encryptor vs comparator) and
  different trust domains, so neither offsets the other; each is evaluated
  per-host. Net: 8-bit would be worse on construction and tied on compare — Bit6
  has the stronger constant-time story end to end.

### Compare-side: oblivious `get_bit` — FIXED (uncommitted, pending review)
Comparison has its own secret-indexed access on the comparator host. After the
constant-time scan finds the first differing block `l` (`bit2.rs:235-242`, done
with `Choice`/`conditional_assign`), it reads byte `a[l] / 8` of the right block,
where `a[l]` (the permuted symbol) is sensitive. The block base was at an
arbitrary buffer offset, so the read could straddle a line.

**Fix applied:** all four `get_bit` sites (`bit2.rs`, `bit2_w6.rs`, and the
`RightBlock32`/`RightBlock8` inherent methods) now route the byte read through a
new oblivious helper `width::ct_select_byte`, which scans the *entire* block and
constant-time-selects the target byte, so the access address is independent of
`a[l]`. This was chosen over mere alignment deliberately: an aligned direct index
still leaks at sub-line (MemJam) granularity, whereas the full scan closes both
line and sub-line channels. Cost is ≤ 32 byte-ops per comparison — negligible
beside the per-comparison AES hash. Results are unchanged (compat + comparison
vectors pass), so it does **not** touch the wire format.

The block-*selection* index `l` was at first left as a direct index, on the
argument that `l` (first-differing-block) is leaked by ORE's definition anyway.
That argument is about who holds the ciphertexts; it says nothing about who can
only *time* the comparator. A dudect run (2026-10-09, recorded in
`docs/reviews/2026-10-09-ore-v2-dynamic-verification.md`) found that the
post-scan loads at `l` do leak it through timing: the scan reads every left
block, so `f[l]` and `a[l]` are cache-resident whatever `l` is, but it never
touches the right blocks, so whether `right[l]` hits depends on `l`. On a
23-block chained ciphertext that was 2 % of the timing spread; on Bit6, whose
whole ciphertext spans five lines, it was at the edge of detection.

**Fix applied (2026-10-09):** the scan now *latches* `a[l]`, `f[l]` and
`right[l]` while it runs, with `width::ct_assign_bytes` under the choice "this
block is the first difference" (true for exactly one block). The resolution
step hashes and bit-selects from the latched copies, so no load after the scan
is indexed by `l`. Cost is one 8-byte right-block read and ≈ 25 masked byte
copies per block, on a scan that already compares 17 bytes per block.
- **Severity of both compare-side channels was low** (`l` and `a[l]` are in
  the ciphertexts the comparator holds; the channels only matter to an attacker
  who can time the comparator but not read its memory), but the oblivious forms
  are cheap and remove the question entirely.
- **Scope note:** production comparison runs in the Postgres extension / proxy
  (separate codebase) and must adopt the same oblivious read (or `ore.rs`'s
  comparator) — tracked separately; this repo's `compare_raw_slices` and typed
  `cmp` are now fixed.

### MemJam & the oblivious tier — risk, CPU scope, and wire compatibility
> **Superseded (2026-10-09).** The analysis below stands as an account of
> MemJam, but it is no longer the deciding argument: a timing dependence on
> the swaps was measured on Apple M4 with no co-tenant, and the oblivious
> builder is now the default everywhere (see "Status" at the top of §5).
> Kept for the record of what was believed and why.

This is the one open judgement call on the construction-side (encryptor) swap.
The shipped `#[repr(C, align(64))]` fix makes the swap **line-uniform**, which
closes the broad cache-line channel for everyone (AMD, ARM, and non-SMT Intel).
It does **not** close MemJam.

**What MemJam is.** 4K aliasing: Intel's memory disambiguation predicts
store→load dependencies from only the low address bits, so an attacker who writes
to an aliasing address forces a false read-after-write dependency and times the
victim's load at **4-byte granularity within a cache line**. That is exactly why
alignment (a 64-byte property) is insufficient.

**CPU scope.**
- **Intel x86 — effectively all generations, incl. modern parts and SGX.** The
  MemJam paper's headline is that it applies to "all major Intel processors
  including the latest generations," unlike its predecessor.
- **Older Intel (pre-Haswell)** also fall to **CacheBleed** (cache-bank
  conflicts, sub-line). Between the two, treat "intra-line is safe on Intel" as
  false across the line.
- **AMD** — not the MemJam target; no demonstrated equivalent, but not provably
  immune.
- **ARM (Apple Silicon, AWS Graviton)** — this mechanism does not apply.
  Relevant: our benchmarks (M1 Max) and likely Graviton production are unaffected.

**Threat model — co-residence required.** MemJam is **not remote**: the spy must
run on the **sibling hyperthread (same physical core, SMT enabled)** of the
victim, hammering the aliasing address throughout the computation. So the surface
is: Intel **+** SMT on **+** attacker code on the same core as the *encryptor*
**+** an attacker who cannot already read the victim's memory. Disabling SMT or
core-isolation neutralizes it with no code change; running the encryptor on ARM
sidesteps it entirely. Marginal leakage is small regardless — the swap addresses
reveal partial info about a permutation whose codebook the ciphertext already
largely exposes (the same fact that sank swap-or-not).

**Recommendation (withdrawn 2026-10-09 — the oblivious builder is now the
default on every target, and faster on aarch64 than the indexed one).**
1. **Default:** ship the `#[repr(C, align(64))]` fix; document that the
   constant-time guarantee is at **cache-line granularity**, and that sub-line
   (MemJam/CacheBleed) resistance on SMT-enabled Intel needs either SMT-off /
   core-isolation **or** the oblivious build.
2. **High-assurance tier:** offer the **oblivious-swap Fisher–Yates** builder
   (~3× slower, already spiked) for threat models that include a malicious
   co-tenant on Intel with SMT.

This matches field practice — aligned-constant-time is the standard bar,
oblivious is the paranoid tier — and lets the deployment, not the library, pay
the 3× only when it needs to.

The "~3×" was the byte-at-a-time full-scan form. The register-resident form
that shipped instead (value-side inverse update, public `0..=i` search bound)
costs 199 ns against the indexed builder's 248 ns on the M4, so the trade the
tier existed to offer no longer exists.

### Alternative considered for the tier: sort-by-random-key — rejected (2026-10-08)
vitaminc's `permutation` crate now builds its keys the djbsort / NTRU Prime
way: tag each index with a random 64-bit word, sort the words through a Batcher
odd–even merge network of branchless compare-exchanges, and read the
permutation off the sorted order. Its instruction and memory trace is a function
of N alone, so it was prototyped inside `LemireFyPrp::from_stream` and
benchmarked as a candidate for the tier in place of oblivious-swap FY (Apple M4,
rustc 1.94.1, criterion, N = 64, 543 gates; full tables in
`docs/benchmarks/2026-06-13-bit6-prp-results.md`, addendum).

| builder | `from_stream` | bit6-encrypt-u64 | bit6-encrypt-left-u64 |
|---|---:|---:|---:|
| `LemireFyPrp` (shipped) | 210 ns | 8.39 µs | 6.12 µs |
| sort, 56-bit key `(w<<8)\|i` (vitaminc's packing) | 494 ns (+135%) | +41% | +61% |
| sort, 64-bit key + index tie-break | 663 ns (+215%) | +73% | +102% |

**Still rejected after the oblivious builder shipped (2026-10-09).** The
sort removes a secret address by the same means the oblivious FY builder does,
running every compare-exchange whatever the data, so it buys no stronger
property; and the FY form is now cheaper still (199 ns against the sort's
494–663 ns, both on the M4), keeps the inverse maintained alongside the swaps
rather than needing a second pass, and leaves every ciphertext unchanged.

Rejected, for three reasons that compound:
1. **It costs what oblivious-swap FY costs and buys less.** 2.3–3.2× on the
   builder is the same band as the ~3× spiked for oblivious-swap FY (the
   register-resident form that shipped later is faster than either), but the
   sort removes only the secret-indexed *swaps*: the inverse-table fill
   (`inverse[perm[i]] = i`) is still a secret-indexed write, and making it
   oblivious needs a second network or an O(N²) scatter — at which point it is
   slower than oblivious-swap FY, which already covers both.
2. **It changes the permutation,** so it changes every Bit6 and chained
   ciphertext (8 of 14 Bit6 compat vectors fail). Oblivious-swap FY is
   byte-identical and can be enabled per build with no re-pin — the property
   "Relationship to vector pinning" below relies on.
3. **Uniformity is no better.** With a 64-bit key the only deviation from
   uniform is a key tie broken by index, C(64,2)·2⁻⁶⁴ ≈ 2⁻⁵³ per permutation,
   marginally worse than Lemire FY's ≤ 2⁻⁵⁵. vitaminc's 56-bit packing is
   ≈ 2⁻⁴⁵, which is why it restarts on a collision.

One rule from it **is** adopted, for every PRP builder including the
oblivious-swap tier: **no retry path.** vitaminc redraws from its RNG when two
keys collide. Here a query's left half and a stored value's right half are
produced in separate calls from `(key, prefix, n)` alone and must agree, so the
stream→permutation map must be a deterministic function with a trace fixed by N.
A tie, or any other "bad draw", is resolved by a fixed, documented rule
(ascending index), never by consuming more stream, and the resulting deviation is
stated as a statistical term as above. A reimplementation (Go, Node) has to
reproduce that rule exactly, or its left halves will not compare against ours.

### Relationship to vector pinning (revised)
The MemJam tier does **not** gate Bit6 vector pinning, *provided the oblivious
fallback is the oblivious-swap FY form* (recommended): it yields the identical
permutation, so ciphertexts are byte-stable whether or not it is enabled. Vectors
can be pinned after the A1/H decision, and the oblivious builder added later as a
build option with no re-pin. (Only a *different-construction* fallback such as
swap-or-not would change ciphertexts and force a re-pin — another reason to
prefer oblivious-swap FY.)

### Decision & what it unblocks
*(As first proposed; (a) and (d) are overtaken by the oblivious builder, see
"Status" at the top of this section. (b) and the guard stand, the guard now
pinning `N = 64`, the width the oblivious builders are written for.)*
Ratify: (a) `#[repr(C, align(64))]` as the default construction-side fix; (b) the
oblivious compare-side read; (c) the `N≤64` compile guard; and (d) the MemJam
posture (document scope + offer oblivious-swap FY as the high-assurance build).
None of (a)–(d) changes ciphertexts, so Bit6 vectors are gated only by A1.

---

## 6. Sign-off checklist

**Gate 1 — before #82 merges / Bit6 vectors pinned:**
- [x] **A1** H construction resolved (2026-06-15): keep fixed public-key AES,
      upgraded to the BHKR σ-MMO `LSB(π(σ(x)⊕r)⊕σ(x)⊕r)`, σ(x)=2x. Argument
      restated 2026-10-08 (published left tags are `H` inputs, so the GKWY
      multi-instance shape applies; security rests on the `≈ p·C/2^128` bound)
      and signed off 2026-10-09;
      tweak-as-key (2019/1168 Thm 2) explicitly declined; 2025/792 targets
      properties we don't use and is round-reduced.
- [x] **A4** ~~ratify the applied construction-side fix `#[repr(C, align(64))]`
      (covers both secret-indexed writes; line-uniform at N ≤ 64).~~
      Superseded 2026-10-09: key generation has no secret-indexed write left
      (oblivious builder); the alignment stays as layout only.
- [x] **A4** compile guard (applied), now `assert!(N == 64)`: the oblivious
      builders are written for 64 entries.
- [ ] **A4** ratify the oblivious compare-side read `width::ct_select_byte`
      (applied; all four `get_bit` sites; results unchanged).
- [x] **A4** MemJam posture — **resolved 2026-10-09, not as proposed.** A
      dudect run measured a timing dependence on the swaps with no co-tenant,
      so the oblivious builder (NEON / SSSE3 / SWAR, byte-identical tables)
      is the default on every target, not a tier; on aarch64 it is faster than
      the indexed builder. Sort-by-random-key stays rejected (2026-10-08); its
      no-retry rule is adopted — see A4.
- [ ] Bit6 byte vectors regenerated and pinned **after A1** (all A4 fixes are
      byte-stable; production comparator adopts `ct_select_byte` separately).

**Gate 2 — before PR 6 is written:**
- [ ] **A2** CMAC encoding fully specified and checked injective; many-outputs
      / chain-state-from-published-tag interaction cleared; impl-faithfulness +
      zeroization test plan agreed.
- [ ] **A3** PRP-stream-as-CMAC-branch-family domain separation approved.

---

## 7. References / pointers
- Plan: `docs/plans/2026-06-12-ore-v2-architecture.md` — §5b (accumulator),
  §6 (H), Open Q1 (PRP), Security checklist.
- Code: `primitives/hash.rs` (A1), `primitives/prp.rs` (A3/A4),
  `scheme/bit2_w6.rs` (Bit6 wiring), `tests/compat_vectors` (Bit8 frozen).
- Spikes: `/tmp/ore-keyexp-spike` (A2 gate), `/tmp/ore-prp-spike` (A3/A4).
- Benchmarks: `docs/benchmarks/2026-06-13-*.md`.
- Lit: Lewi-Wu 2016 (BlockORE); BHKR13 / GKWY20 (fixed-key AES hashing);
  NIST SP 800-38B (CMAC); HMR12 + Morris-Rogaway 2014 (swap-or-not); Lemire 2019
  (nearly-divisionless bounded random); Moghimi et al. CT-RSA 2018 (MemJam,
  arXiv:1711.08002) + Yarom et al. 2016 (CacheBleed) for the sub-line channels.
