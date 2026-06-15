# ORE v2 — chained-prefix CMAC accumulator: design spec (A2)

**Date:** 2026-06-15
**Status:** DRAFT for crypto review — the **A2 gate** that must pass before PR 6
(chained prefix / variable-length / strings) is written.
**Companions:** plan §5(b) (`docs/plans/2026-06-12-ore-v2-architecture.md`),
review brief A2/A3 (`docs/reviews/2026-06-14-ore-v2-crypto-review-brief.md`).

This is the precise specification the review brief flagged as "still a sketch."
It pins the message encoding (the injectivity-critical part), the per-block
algorithm, the security argument, and the test plan.

---

## 1. What this replaces, and why

The fixed-N Bit6 scheme (#82) derives every per-block secret by packing the
**prefix** `x[0..n-1]` into one 16-byte AES block and encrypting it:

- **PRP seed** (`derive_prp_seeds`, key `prf2`): `seed_n = E_{prf2}( x[0..n-1] ‖ 0… ‖ N@[15] )`
- **RO key / left tag** (key `prf1`): `ro(n, v) = E_{prf1}( x[0..n-1] ‖ v@[n] ‖ n@[N] ‖ N@[15] )`,
  where `v = j` for the right-vector mask at domain position `j`, and `v = xt[n]`
  (the permuted current symbol) for the published left tag `f[n]`. **So
  `f[n] = ro(n, xt[n])`** — the same function at the value's permuted position;
  this is what makes the masks cancel at compare time.

Packing the raw prefix into one block caps the plaintext at **≤ 14 blocks**
(`MAX_BLOCKS`). PR 6 needs arbitrary length (strings; also `u128`/`Decimal`
which exceed 14 Bit6 blocks). The fix is an **accumulator**: absorb the prefix
incrementally into a fixed 16-byte state, and derive the per-block secrets by
**CMAC-finalising** that state with a per-output final block — instead of
packing the raw prefix. Candidate B (CMAC, NIST SP 800-38B) was selected by the
§5(b) benchmark gate (cascade/GGM rejected on aarch64 key-expansion cost; XE
held in reserve).

---

## 2. Construction

Let `E_k` be AES-128 under the accumulator key `k` (§3). Standard CMAC:

```
L  = E_k(0^128)
K1 = dbl(L)            # dbl = GF(2^128) "multiply by x" — the same gf128_double
K2 = dbl(K1)           # (reused from the σ-MMO hash; constant 0x87)
```

All accumulator messages are an exact multiple of 16 bytes, so **only K1 is ever
used** (K2/padding never occurs). Define, over a running CBC state `S`:

```
absorb(S, B)   = E_k(S ⊕ B)              # extend the prefix chain (no subkey)
finalize(S, F) = E_k(S ⊕ F ⊕ K1)         # a published CMAC tag (full last block)
```

For a plaintext of blocks `x[0..N-1]`, maintain `S_n` = the CBC chain over the
prefix blocks `P_0 ‖ … ‖ P_{n-1}` (`S_0 = 0^128`). Every per-block secret is a
`finalize(S_n, F)` for a final block `F` that injectively names the output. The
prefix chain is cached and extended incrementally — `clone-state-then-finalize`
*is* incremental CMAC, so each published value is a *bona fide* one-shot CMAC tag
of `P_0 ‖ … ‖ P_{n-1} ‖ F`.

---

## 3. Key derivation & domain separation

The accumulator uses a **dedicated key `k`**, derived from the master ORE key by
a labelled KDF distinct from every other use (the fixed-N `prf1`/`prf2`, H's
public `π`, the nonce RNG):

```
k = E_{k_master}( "ORE.v2.chain.acc\x00" )      # 16-byte ASCII label, single AES call
```

(`k_master` = one of the `init(k1, k2)` keys; concrete slot TBD in review.) A
dedicated key makes the accumulator's PRF security self-contained: no cross-use
collisions with the fixed-N schemes or with H. The chained scheme therefore
**unifies the old `prf1` and `prf2`** into one key, domain-separated by the
**branch tag** (the `RO_KEY` / `PRP_STREAM` output families defined in §4) —
PRF₂ is subsumed.

**Key inventory.** The chained scheme has exactly **one secret key — `k`** —
which produces *both* branches. Branch-tag domain separation under a good PRF is
equivalent to independent per-branch keys (the injectivity argument of §4 + the
CMAC-PRF reduction of §8), and is cheaper: one AES key schedule and one CMAC
subkey pair (`L, K1, K2`) rather than two. The only other key-shaped material is
**public** (H's fixed `π` constant `K₀`) or non-key (the per-ciphertext nonce).
Two consequences for review:

- **vs fixed-N (#82):** that scheme keeps two secret keys (`prf1`/`prf2`); the
  unification is a *chained-scheme* choice, not retroactive.
- **vs the `init(k1, k2)` API:** `k` is KDF-derived, so a single master input
  suffices here — `k2` is redundant for this scheme unless retained for API
  compatibility (open question 1). The alternative design — two keys, one per
  branch, no branch tag — is equivalent in security but costs a second key
  schedule/subkey pair; the single-key choice should be explicitly blessed.

---

## 4. Message encoding (injectivity-critical)

A **branch** names which output family a `finalize` derives. There are two:

- **`RO_KEY`** (tag `0x01`) — the right-vector mask values `ro(n, j)`, and the
  left tag `f[n] = ro(n, xt[n])`;
- **`PRP_STREAM`** (tag `0x02`) — the Fisher–Yates keystream that builds `π_n`.

These replace the fixed-N scheme's separate `prf1` (ro/f) and `prf2` (PRP) keys
(§3); the branch is carried as the **byte-0 branch tag** of the final block, and
is the `branch` argument in `F(branch, n, s)` below.

Every block is exactly 16 bytes. Two block types, distinguished by byte 0.

**Prefix block `P_t`** (absorbed into the chain; carries symbol `x[t]`):

| byte | 0 | 1–2 | 3 | 4–15 |
|------|---|-----|---|------|
| value | `0x00` (TYPE_PREFIX) | `t` (u16 BE) | `x[t]` | `0x00` |

**Final block `F(branch, n, s)`** (the last block of a `finalize` message):

| byte | 0 | 1–2 | 3–4 | 5 | 6–15 |
|------|---|-----|-----|---|------|
| value | branch tag | `n` (u16 BE) | `s` (u16 BE) | `width` (`0x06`) | `0x00` |

- **branch tag** ∈ `{ 0x01 = RO_KEY, 0x02 = PRP_STREAM }` (both ≠ `0x00`).
- **`n`** = block position being derived.
- **`s`** = sub-index: for `RO_KEY`, the domain value `j` (or `xt[n]` for the
  left tag); for `PRP_STREAM`, the keystream counter `c`.
- **`width`** = block width (6) → domain separation from any future Bit8-chained
  scheme.

**No total-length (`N`) binding** — deliberately, and unlike the fixed-N packed
scheme (§7).

### Injectivity
Every prefix block has `byte0 = 0x00`; every final block has `byte0 ∈ {0x01,
0x02}`. In a message `P_0 ‖ … ‖ P_{i-1} ‖ F`, the final block is the unique
non-`0x00`-byte0 block (and it is last), so the message parses unambiguously into
`((x[0],0),…,(x[i-1],i-1), (branch,n,s,width))`. Hence the map

```
(prefix values x[0..i-1], branch, n, s, width) ⟼ message bytes
```

is **injective**: distinct logical inputs ⇒ distinct messages. (Claim 1.)

---

## 5. Per-block algorithm

`STREAM_BLOCKS` = ⌈(DOMAIN−1)·8 / 16⌉ = 32 for Bit6 (63 wide draws → 504 B → 32
× 16 B). `nonce` is a fresh per-ciphertext random value (unchanged from fixed-N).

```
S ← 0^128
for n in 0..N:
    # PRP for block n (shape (ii), A3): keystream straight from the accumulator
    stream ← ‖_{c=0}^{STREAM_BLOCKS-1} finalize(S, F(PRP_STREAM, n, c))
    π_n    ← LemireFyPrp::from_stream(stream)         # new ctor; FY math unchanged
    xt[n]  ← π_n.permute(x[n])

    # left tag  f[n] = ro(n, xt[n])  — RO_KEY branch at s = xt[n]
    f[n]   ← finalize(S, F(RO_KEY, n, xt[n]))

    # right block: ro_key per domain value, then mask exactly as fixed-N
    for j in 0..DOMAIN:
        ro[j] ← finalize(S, F(RO_KEY, n, j))
    encode_right_block(right[n], π_n, x[n], H_nonce, ro)   # unchanged: H-mask ⊕ indicator

    # extend the prefix chain
    S ← absorb(S, P_n(x[n]))                          # S_{n+1}
zeroize(S, stream, ro, K1, K2, L, k)
```

- `encode_right_block`, `H` (the BHKR σ-MMO, A1), `indicator_mask_xor`, and the
  comparator are **unchanged** — only the derivation of `ro`/`f`/PRP changes from
  packed-AES to CMAC. `f[n]` reuses the `RO_KEY` finalize at `s = xt[n]`, so the
  left/right masks cancel exactly as today.
- Left-only encryption (queries) runs the `PRP_STREAM` + `f[n]` steps only.
- Per-block AES count ≈ `1 (absorb) + 32 (stream) + DOMAIN (ro) ≈ 97` at Bit6,
  comparable to the packed scheme's ~130; **no per-block key schedule** (this is
  the shape-(ii) win, A3).

---

## 6. Incremental CMAC ↔ one-shot equivalence (Claim 2)

`finalize(S_n, F)` with `S_n` the CBC chain of `P_0..P_{n-1}` equals one-shot
`CMAC_k(P_0 ‖ … ‖ P_{n-1} ‖ F)` because `F` is a full 16-byte final block (→ K1)
and `S_n` is the standard CBC state. The chain extension `absorb(S_n, P_n)` is a
CBC step with **no subkey**, so it is *not* a published tag. **Test:** assert the
incremental implementation byte-matches the `cmac` crate's one-shot output over
the exact `P/F` messages, across positions/branches/sub-indices.

---

## 7. No length binding — required for cross-length comparison

The fixed-N scheme binds `N` (byte 15) into every derivation; that is safe
because only equal-length (same-type) ciphertexts are ever compared. The chained
scheme **must not** bind `N`: two strings sharing a prefix (`"app"` vs `"apple"`)
must produce **identical** per-block secrets for the shared blocks so the
comparator finds the first differing block correctly (shorter sorts first). The
per-block secrets therefore depend on `(prefix values, position n, branch, s)`
but **not** total length.

Length **comparability** is enforced at the comparator, not in the derivation:

- **Strings:** different lengths allowed; scan `min(len_a, len_b)` blocks; if
  equal throughout, the shorter sorts first (lexicographic). Common-prefix-length
  leakage is the intended, query-time-scoped leakage (plan §5(b)).
- **Fixed-length types** (`u128`/`Decimal` via the accumulator): the header
  carries the block count; the comparator **rejects** mismatched lengths
  (cross-type comparison), exactly as fixed-N does.

---

## 8. Security argument

1. **`k` is a uniform AES key** used *only* by the accumulator (§3), so its PRF
   security is self-contained.
2. **CMAC is a secure variable-input-length PRF** in the PRP model (NIST SP
   800-38B; Iwata–Kurosawa OMAC), advantage `≈ (σ)² / 2^128` for `σ` total
   blocks processed under `k`, plus the AES PRP term.
3. **Every published secret is `CMAC_k(msg)`** for an injectively-encoded `msg`
   (Claim 1). Distinct logical outputs ⇒ distinct messages ⇒ jointly
   indistinguishable from independent uniform values. These are precisely the
   independent PRF outputs the Lewi-Wu analysis assumes for `ro`/`f`/PRP; ORE
   security then follows from the existing Lewi-Wu argument.
4. **The chain state is never published.** `S_n` is an internal CBC value; the
   only outputs are `finalize(S_n, F)` with the K1-treated final block. So the
   "published-outputs-vs-chaining-value" interaction that complicates cascade/GGM
   does **not** arise — it is subsumed by the CMAC PRF abstraction. (`absorb`
   and `finalize` from the same `S_n` are E_k at different points: `S_n⊕P_n` vs
   `S_n⊕F⊕K1`, with `P_n` byte0=`0x00` and `F` byte0≠`0x00`.)
5. **Many outputs per state** (32 stream + DOMAIN ro per block) is sound for the
   same reason: distinct final blocks ⇒ distinct messages ⇒ independent tags.
6. **Birthday budget.** `σ ≈ q · L · (DOMAIN + STREAM + 1)`. For `q = 2^32`
   ciphertexts, `L = 14`, Bit6: `σ ≈ 2^44`, term `≈ 2^{88-128} = 2^{-40}` —
   comfortable. `log()` the assumption if a deployment expects `q ≫ 2^32`.

Auditable claims for sign-off: **(1)** encoding injectivity (§4), **(2)**
incremental-vs-one-shot faithfulness (§6), **(3)** zeroization (§9).

---

## 9. State hygiene (Claim 3)

`k`, `L`, `K1`, `K2`, the cached chain states `S_n`, the `stream` buffer, and the
`ro` buffer are all secret key-equivalent material (anyone holding `S_n` can
derive every output for that prefix). All must be: zeroized on drop; never
serialized; never reachable from `Left`/`Right`/`CipherText` types. (Mirrors the
existing `SeedBuf`/template zeroization in #82.)

---

## 10. Test plan

- **CMAC faithfulness:** incremental impl == `cmac` crate one-shot, over many
  `(prefix, branch, n, s)` (§6).
- **Subkey KAT:** `L/K1/K2` against NIST SP 800-38B AES-128 CMAC test vectors
  (also exercises the shared `gf128_double`).
- **Cross-length comparison:** strings sharing a prefix of every length compare
  correctly (shorter sorts first); fixed-length mismatches are rejected (§7).
- **Order/roundtrip quickcheck** for the chained scheme (as bit2_w6 has).
- **Shape-(ii) PRP equivalence:** `from_stream(accumulator stream)` yields the
  same permutation as the spec's FY over that stream; statistical-distance bound
  unchanged (A3).
- **Wire vectors pinned** once the encoding is signed off (mirror
  `compat_w6_vectors`), incl. a variable-length string set.
- **Zeroization** assertions / `Drop` coverage.

---

## 11. Open questions for review

1. **Key slot for `k`** (§3): which `init` key + exact label; confirm the KDF
   (single labelled AES call) is acceptable.
2. **`width`/scheme tag** (§4): is a 1-byte width enough domain separation, or
   should the final block also carry a scheme id (as the wire header does)?
3. **PRP_STREAM vs a single seed:** spec derives the full FY stream as 32 CMAC
   tags (shape ii). Alternative: one `PRP_SEED` tag that keys a fresh AES-CTR
   (shape i) — simpler, but reintroduces a per-block key schedule. Confirm shape
   (ii) is wanted here (it is the A3 perf rationale).
4. **Birthday budget** (§8.6): acceptable `q` ceiling; whether to document a
   re-key guidance for very large datasets.
5. **`u128`/`Decimal`** ride this accumulator purely to exceed 14 blocks — they
   are fixed-length; confirm the comparator's length-rejection (§7) is the right
   place to keep them non-comparable with strings/other types.
