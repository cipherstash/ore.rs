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
| **A1** | 1-bit hash `H` instantiation | random-permutation (option 3) / ideal-cipher (option 2 fallback) | **shipped as default in #82** (`FixedPiZ2Hash`) | #82 merge + Bit6 vector pinning |
| **A2** | Chained-prefix accumulator = AES-CMAC cached-state | CMAC PRF (standard) + 3 auditable claims | designed, not yet coded | PR 6 (variable-length / strings) |
| **A3** | PRP keystream from the accumulator (shape ii) | statistical (≤2⁻⁵⁵) + branch-family soundness | shape (i) shipped; (ii) deferred | PR 6 perf; couples to A2 |
| **A4** | Secret-indexed swap in PRP key-gen — ratify alignment + MemJam posture? | constant-time / cache-line (sub-line = oblivious tier) | `#[repr(C, align(64))]` + oblivious compare read + `N≤64` guard **applied** (uncommitted) | nothing — fixes are byte-stable; A1 alone gates vectors |

**Recommended sequencing:** do **A1 first** — it is now the sole gate on freezing
Bit6 and its test vectors. **A4 is a ratification** of changes already applied
(none of which alter ciphertexts), plus a posture call on MemJam; it no longer
couples to vector pinning. Then **A2 + A3 as one pass** (they gate PR 6, and A3
only exists inside A2's accumulator).

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

## 2. A1 — the 1-bit hash `H`  (§6; blocks #82)

### The question
`H(x, r) → Z₂` where `x` = RO key / left tag (public), `r` = per-ciphertext
nonce (public). It must be computable by a keyless comparator from public
ciphertext material. Which construction?

### What is shipped (the default to ratify or change)
`packages/ore-rs/src/primitives/hash.rs:50-124`, `FixedPiZ2Hash`:

```
H(x, r) = LSB( π(x ⊕ r) ⊕ x ),   π = AES-128_{K₀},  K₀ public constant
```

- `K₀ = PI_KEY = b"ORE-rs.v2.H-pi.1"` — nothing-up-my-sleeve, **deliberately
  public**; security rests on AES being a good *public random permutation*, not
  on key secrecy (`hash.rs:66-71`). Expanded once per process.
- This is **§6 option 3**: fixed-key-AES MMO hashing, analysed in the
  **random-permutation model** (cf. BHKR13; GKWY20).
- The feedforward `⊕ x` is implemented as: capture `LSB(x)` before overwriting,
  then XOR with `LSB(π(x⊕r))` (`hash.rs:96-123`; SIMD `lsb_mask` path verified
  equivalent to scalar).
- A conservative fallback is also coded — **§6 option 2**, `Aes128Z2Hash` =
  `LSB(AES_r(x) ⊕ x)` (MMO with nonce-as-key, **ideal-cipher model**). Switching
  is a one-line `type Z2Hash = …` flip in the Bit6 scheme.

### The candidate menu (full table, plan §6)
| # | Construction | Model | Cost vs today |
|---|---|---|---|
| 1 | `LSB(AES_r(x))` (status quo, Bit8) | ideal cipher | — |
| 2 | `LSB(AES_r(x) ⊕ x)` MMO feedforward (**fallback**) | ideal cipher | +1 XOR |
| 3 | `LSB(π(x⊕r) ⊕ x)`, fixed public `π` (**shipped default**) | random permutation | **faster — zero key schedules** |
| 4 | `LSB(AES_x(r))` RO-key-as-key | **standard model (PRF)** | ~2–4× right-encryption |
| 5 | SHA-256/Blake3 over `x‖r` | random oracle | 2–5× encrypt path |

### What needs scrutiny
1. **The fixed-key-AES-hashing argument in *our* setting.** Mine GKWY20 for the
   known `x ⊕ r` tweaking pitfalls. The claim to confirm: our requirements are
   *weaker* than garbling's (no circularity, no correlated keys), so the
   construction is sound here. Is that right, and are there ORE-specific
   correlations between `x` (RO keys / left tags) and `r` (nonce) that break the
   random-permutation reduction?
2. **Is option 3 worth it over option 2?** Option 3 is faster (no key schedule)
   but assumes a random *permutation*; option 2 is the "minimal upgrade" in the
   ideal-cipher model. If the random-permutation argument is shaky, fall back.
3. **Standard-model alternative (option 4):** do we want to pay 2–4× for
   standard-model PRF security instead of an idealised-model assertion? Cost is
   measured and on the table by design.
4. **The 1-bit LSB truncation** (LSB of a pseudorandom block) — believed
   uncontroversial in every model; confirm.
5. **Nothing-up-my-sleeve constant** `K₀` — acceptable as-is?

### Decision & what it unblocks
Pick the H for new schemes (default option 3, or fall back to 2, or escalate to
4). **#82 must not merge and Bit6 byte vectors must not be pinned until this is
signed off** — the choice changes every Bit6 right ciphertext. Implementation is
already a one-line type flip either way.

---

## 3. A2 — chained-prefix accumulator = CMAC cached-state  (§5b; blocks PR 6)

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
- The **read** paths are already constant-time: `permute`/`invert` are table
  lookups returning the value, and `indicator_mask_xor` scans the *entire*
  permutation table via a branch-free `gt_mask` kernel (`prp.rs:225-228`). Only
  the **key-generation writes** (above) are secret-indexed.
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
vectors pass), so it does **not** touch the wire format. The block-*selection*
index `l` is left as a direct index because `l` (first-differing-block) is leaked
by ORE's definition anyway.
- **Severity it addressed was low** (both `l` and `a[l]` are already in the
  ciphertexts the comparator holds; the channel only matters to an attacker who
  can time the comparator's cache but not read its memory), but the oblivious
  read is cheap and removes the question entirely.
- **Scope note:** production comparison runs in the Postgres extension / proxy
  (separate codebase) and must adopt the same oblivious read (or `ore.rs`'s
  comparator) — tracked separately; this repo's `compare_raw_slices` and typed
  `cmp` are now fixed.

### MemJam & the oblivious tier — risk, CPU scope, and wire compatibility
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

**Recommendation.**
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

### Relationship to vector pinning (revised)
The MemJam tier does **not** gate Bit6 vector pinning, *provided the oblivious
fallback is the oblivious-swap FY form* (recommended): it yields the identical
permutation, so ciphertexts are byte-stable whether or not it is enabled. Vectors
can be pinned after the A1/H decision, and the oblivious builder added later as a
build option with no re-pin. (Only a *different-construction* fallback such as
swap-or-not would change ciphertexts and force a re-pin — another reason to
prefer oblivious-swap FY.)

### Decision & what it unblocks
Ratify: (a) `#[repr(C, align(64))]` as the default construction-side fix; (b) the
oblivious compare-side read; (c) the `N≤64` compile guard; and (d) the MemJam
posture (document scope + offer oblivious-swap FY as the high-assurance build).
None of (a)–(d) changes ciphertexts, so Bit6 vectors are gated only by A1.

---

## 6. Sign-off checklist

**Gate 1 — before #82 merges / Bit6 vectors pinned:**
- [ ] **A1** H construction selected (default option 3 ratified, or fall back to
      2 / escalate to 4); fixed-key-AES tweaking pitfalls (GKWY20) cleared for
      our setting. **This is the sole gate on Bit6 vector pinning.**
- [ ] **A4** ratify the applied construction-side fix `#[repr(C, align(64))]`
      (covers both secret-indexed writes; line-uniform at N ≤ 64).
- [ ] **A4** ratify the `const _ = assert!(N <= 64)` compile guard (applied).
- [ ] **A4** ratify the oblivious compare-side read `width::ct_select_byte`
      (applied; all four `get_bit` sites; results unchanged).
- [ ] **A4** MemJam posture: accept "default = line-granularity CT; sub-line
      resistance via SMT-off / core-isolation or the oblivious-swap-FY build."
      Decide whether to build the oblivious-swap-FY tier now or on demand.
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
