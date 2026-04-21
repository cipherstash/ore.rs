# Fixing the 1/256 Ordering Bug in CLLW OPE via Backward Carry

*An engineering note on the order-preserving variant of CLLW ORE.*

---

## TL;DR

The CLLW order-revealing encryption scheme has a natural "order-preserving"
(OPE) interpretation described in Section 3.2 of the
[original paper](https://eprint.iacr.org/2016/612.pdf): take the ORE
ciphertext bytes and compare them lexicographically. It almost works, but
wraps around `mod 256` — so roughly 1 in 256 comparisons disagree with the
true plaintext order.

We fix that by reinterpreting the ciphertext as a big-endian multi-byte
integer and propagating the plaintext's `+bit` contribution right-to-left
as an arithmetic carry, absorbing any overflow into a reserved leading byte.
The result is a per-comparison error rate of approximately
`1 / (2 × 255²) ≈ 7.7 × 10⁻⁶` on worst-case adjacent plaintext pairs — about
**500× better than the naive scheme** — and essentially zero for any pair
that isn't structurally adjacent. The cost is one extra ciphertext byte and
a single linear pass during encryption.

This note covers why we'd want OPE-over-ORE in the first place, walks
through the base CLLW construction and its wrap-around bug, explains the
backward-carry fix with a worked example, and derives the new error rate.

---

## 1. OPE vs ORE: why we care about lex compare

**Order-revealing encryption (ORE)** produces ciphertexts that can be
compared with a custom function `CMP(c₁, c₂)` that reveals the plaintext
ordering without revealing the plaintexts themselves. CLLW's comparator is a
byte scan with a `mod 256` check (details below); it's fast and constant-
time, but it's also a non-standard comparison, which means you can't just
put ORE ciphertexts into a database index and expect `ORDER BY` to do the
right thing.

**Order-preserving encryption (OPE)** goes further: ciphertexts are ordered
the same way as the plaintexts under *standard byte-lexicographic compare*.
That's the comparison every system already knows how to do — `<`, `>`,
B-tree key compare, `ORDER BY`, `memcmp`. A valid OPE ciphertext is a drop-
in replacement for an encrypted column that you can still range-query over.

The tradeoff: OPE is generally harder to build securely than ORE (it reveals
strictly *at most* as much information as ORE, but typically a bit more than
the comparator-based variant, because the adversary gets exact byte order
for free). For the CLLW family the difference is small, which is why
reinterpreting CLLW ORE as OPE is attractive.

---

## 2. How CLLW ORE works

CLLW is a bit-by-bit construction. For an n-bit plaintext `p = b₀ b₁ … bₙ₋₁`
(MSB-first), the encryptor walks the bits left-to-right feeding them into a
keyed hasher. At each step it pulls out one pseudorandom byte and adds the
current bit:

```text
fn encrypt_ore(K, p):              # returns n ciphertext bytes
    hasher = keyed_hasher(K)       # e.g. BLAKE3::new_keyed(K)
    out = []
    for bit in bits_msb_first(p):
        prf = hasher.next_byte()   # PRFᵢ = F_K(b₀ ‖ … ‖ bᵢ₋₁)
        out.push((prf + bit) mod 256)
        hasher.update(bit)         # fold this bit into the chain
    return out
```

Two properties matter:

1. **The PRF chain is plaintext-dependent.** `PRFᵢ` is a function of the
   *previous* plaintext bits `b₀ … bᵢ₋₁`. For two plaintexts X and Y that
   agree up to position k−1 and first differ at bit k, the PRFs at
   positions 0…k are identical (same chain input); at positions k+1…n−1
   the PRFs are independent pseudorandom values.
2. **The encrypted bit lives in the low-order bit of the byte.** `cᵢ =
   (PRFᵢ + bᵢ) mod 256`. If you knew `PRFᵢ` you could recover `bᵢ` by
   subtraction — but nobody except the key holder does.

The comparator exploits property 1:

```text
fn compare_ore(c1, c2):
    for i in 0..n:
        if c1[i] != c2[i]:
            if c2[i] == (c1[i] + 1) mod 256:
                return Less          # c1 < c2
            else:
                return Greater       # c1 > c2
    return Equal
```

When the plaintexts first differ at bit k, the PRF terms cancel at position
k (`PRFₖ^X = PRFₖ^Y`), so `c_k^Y − c_k^X = b_k^Y − b_k^X`. In a bit-level
plaintext encoding, that difference is ±1, which is exactly what the `mod
256` check tests. Bytes after k look independent-random and the comparator
correctly stops at the first differing byte.

### Leakage

CLLW ORE's ciphertext reveals the **first differing bit position** (i.e. a
common prefix length), and nothing else beyond ordering. This is a standard
IND-OCPA-style leakage — weaker than full plaintext but non-trivial,
especially on low-entropy data like integers in a narrow range. For
production use cases with richer threat models we pair CLLW with additional
primitives; see the package README.

---

## 3. The paper's OPE interpretation — and the 1/256 bug

Section 3.2 of the CLLW paper observes that if you just treat the ORE
ciphertext as a byte string and sort it, you almost get an OPE. Informally:
at the first differing byte, c_Y = c_X + 1 — so lexicographic compare puts
the larger plaintext's ciphertext last. "Almost" is doing a lot of work.

The failure mode: `c_Y = (c_X + 1) mod 256`. If `c_X = 0xFF`, then `c_Y =
0x00`. Lex compare sees `0x00 < 0xFF` and concludes Y < X, but the plaintext
order is Y > X. The comparator's `mod 256` check papers over this; a raw
byte compare cannot.

### Worked example

Take 8-bit plaintexts X = 0 and Y = 1. All bits of X are 0; bits of Y are
0000 0001. Because the PRF chain for Y sees only zeros up to bit 6, the
first seven PRFs are identical in both; they diverge only at bit 7 (the
LSB), and at that position we only care about `PRF₇` itself.

Suppose by chance `PRF₇ = 0xFF` — a 1-in-256 event:

| Byte index | PRF       | X's bit | Y's bit | `c^X`  | `c^Y`                |
|-----------:|-----------|---------|---------|--------|----------------------|
| 0–6        | PRF₀..₆   | 0       | 0       | PRF_i  | PRF_i                |
| 7 (LSB)    | `0xFF`    | 0       | 1       | `0xFF` | `(0xFF + 1) mod 256 = 0x00` |

Lex compare: bytes 0..6 equal, byte 7 has `0x00 < 0xFF`, so the comparator
says `c^Y < c^X`. Wrong.

### Error rate: ~1/256

Over uniformly random keys, `PRFᵢ` at the first differing bit position is
uniform on `{0, …, 255}`, and the wrap happens iff `PRFᵢ` is exactly
`0xFF` (for the side that was supposed to add `+1`). That's

$$
\Pr[\text{error}] \approx \frac{1}{256} \approx 3.9 \times 10^{-3}.
$$

For a single comparison that's fine; for any application that issues even a
modest number of ORDER BY / range-scan comparisons, the cumulative hit rate
is unacceptable.

---

## 4. The backward-carry fix

The fix reframes the ciphertext as arithmetic rather than a byte stream.

### Intuition

The CLLW keystream gives us an n-byte pseudorandom number `P`:

```text
P = PRF₀ · 256ⁿ⁻¹ + PRF₁ · 256ⁿ⁻² + … + PRFₙ₋₁ · 256⁰
```

The plaintext bits form a second n-byte number `B`:

```text
B = b₀ · 256ⁿ⁻¹ + b₁ · 256ⁿ⁻² + … + bₙ₋₁ · 256⁰        (each bᵢ ∈ {0, 1})
```

and the OPE ciphertext is their sum:

```text
C = P + B
```

Computed bytewise with a right-to-left carry pass, exactly like schoolbook
long addition. The reserved leading byte is just the overflow digit in case
`P + B ≥ 256ⁿ`. That's it.

### Pseudocode

```text
fn encrypt_ope(K, p):
    hasher = keyed_hasher(K)

    # Pass 1 — same PRF chain as ORE, recording bits as we go.
    prfs = []
    bits = []
    for bit in bits_msb_first(p):
        prfs.push(hasher.next_byte())
        bits.push(bit)
        hasher.update(bit)

    # Pass 2 — compute P + B as big-endian integer arithmetic,
    # propagating carry right-to-left into a reserved leading byte.
    out = [0] + prfs                  # reserved byte at index 0
    carry = 0
    for i in reversed(0..n):
        total       = out[i + 1] + bits[i] + carry
        out[i + 1]  = total mod 256
        carry       = total >> 8       # 0 or 1
    out[0] = carry                     # 0 or 1
    return out                         # length n + 1
```

Comparison is a plain byte-lex compare — no custom comparator needed:

```text
fn compare_ope(c1, c2):
    return c1.as_bytes().cmp(c2.as_bytes())   # e.g. memcmp
```

The actual Rust implementation is in `src/impls/mod.rs::encrypt_ope_bits`.

### Replaying the worked example

Same X = 0, Y = 1, with `PRF₇ = 0xFF`.

For X (bits all zero): nothing gets added anywhere, so the output is
`[0, PRF₀, …, PRF₆, 0xFF]`. No carry escapes position 7.

For Y (bits 0000 0001): the carry pass starts at position 7:

- i = 7, bit = 1: `total = 0xFF + 1 + 0 = 0x100`.
  → byte 7 = `0x00`, carry = 1.
- i = 6, bit = 0: `total = PRF₆ + 0 + 1 = PRF₆ + 1`.
  Assuming `PRF₆ < 0xFF`, → byte 6 = `PRF₆ + 1`, carry = 0.
- i = 5..0, bit = 0, carry = 0: bytes unchanged.
- Reserved byte stays 0.

So `c^Y = [0, PRF₀, …, PRF₅, PRF₆ + 1, 0x00]` and `c^X =
[0, PRF₀, …, PRF₅, PRF₆, 0xFF]`. Lex compare: bytes 0..6 equal *except*
byte `7` (of `c`), where `c^Y` has `PRF₆ + 1` vs `c^X`'s `PRF₆`. Y beats X
there. ✓

The carry "moved" the `+1` that would have wrapped into a more-significant
byte, where it correctly dominates the lex comparison.

---

## 5. Error rate derivation

The construction isn't free of errors — it can still go wrong, just *much*
less often. This section derives how often.

### 5.1 Where the scheme can still fail

Consider two plaintexts X and Y with **first differing bit at position k**
(so `b₀^X = b₀^Y, …, b_{k-1}^X = b_{k-1}^Y`). Assume X < Y — i.e. `b_k^X = 0`
and `b_k^Y = 1` — so that the later ciphertext ordering is the one we
expect lex compare to report. The X > Y case is symmetric: swap the labels
and every argument below still holds.

**PRF agreement.** For i ≤ k, the PRF chain input is identical in X and Y,
so `PRFᵢ^X = PRFᵢ^Y`. For i > k, the chain inputs diverge (at bit k), so
`PRFᵢ^X` and `PRFᵢ^Y` are independent uniform pseudorandom bytes.

**Decompose the ciphertext difference.** Treating ciphertexts as
(n+1)-byte big-endian integers:

```text
C^Y − C^X = (P^Y − P^X) + (B^Y − B^X)
```

- `P^Y − P^X` has zero contribution from bytes 0..k (PRFs match) and, from
  bytes k+1..n−1, a contribution of `V − U` where U and V are independent
  uniform integers on `{0, 1, …, S − 1}` and `S = 256^{n-1-k}`.
- `B^Y − B^X` contributes `+S` from bit k (the first differing bit, 0→1),
  plus `±1 · 256^{n-1-i}` from each differing bit i > k.

The answer to "how often do we err" depends on `B^Y − B^X`. We'll focus on
the **worst case**, which is adjacent plaintexts (pairs like X, X+1), and
then extend.

### 5.2 Worst case: adjacent integer plaintexts

For X and Y = X + 1, the carry in the plaintext's `+1` flips bits k..n−1
wholesale: position k goes 0→1, and all positions k+1..n−1 go 1→0. So:

```text
B^Y − B^X = +S − ∑_{i=k+1}^{n-1} 256^{n-1-i}
          = +S − (S − 1) / 255
          = (254·S + 1) / 255
```

Intuitively, `B^Y − B^X` is very close to `S` but slightly less — about
`254/255 · S`. That's still huge: the first-differing-bit position
dominates everything that comes after it.

**Error condition.** `C^Y − C^X ≤ 0` iff `U − V ≥ (254·S + 1) / 255`. Call
that threshold `T`. The gap `S − T = (S − 1) / 255 ≈ S/255`.

For U and V iid uniform on `{0, …, S − 1}`, the distribution of `U − V` is
triangular with peak at 0 and P(U − V = d) = (S − |d|) / S². Tail
probability:

```text
P(U − V ≥ T) = (S − T)(S − T + 1) / (2·S²)
            ≈ (S / 255)² / (2·S²)
            = 1 / (2 · 255²)
            ≈ 7.69 × 10⁻⁶
```

**This is independent of `m = n − k` for `m ≥ 2`.** Whether the first
differing bit is two positions in or twenty, the error rate per adjacent
pair at that position is the same.

For `m = 1` (only the LSB differs), the PRF chain never diverges, so `V =
U = 0` deterministically and `P(error) = 0`.

### 5.3 Non-adjacent pairs

For pairs that aren't integer-adjacent, `B^Y − B^X` is larger than in the
worst case, which makes the error threshold `T` *closer to* `S` (harder to
exceed) — so error rates drop fast. In practice, most non-adjacent pairs
the system will ever compare have error rates many orders of magnitude
lower than `7.7 × 10⁻⁶`.

### 5.4 Averaging over random adjacent pairs

For a uniform random X, the position k (first differing bit in the X ↔
X+1 comparison) is determined by the number of trailing 1s in X. Cases:

| Condition                       | Probability | Rate at that k                   |
|---------------------------------|:-----------:|----------------------------------|
| X's LSB is 0 (m = 1)            |    1/2      | 0                                |
| X ends in `...01` (m = 2)       |    1/4      | `1/65 536 ≈ 1.5 × 10⁻⁵`          |
| X ends in `...011` (m ≥ 3)      |    1/4      | `~7.7 × 10⁻⁶`                    |

Putting it together, the expected error rate over random adjacent u16 pairs
is:

```text
E[rate] ≈ 0 · (1/2) + 1.5e-5 · (1/4) + 7.7e-6 · (1/4)
       ≈ 5.7 × 10⁻⁶
```

The m = 2 case is noticeably higher than the m ≥ 3 asymptote because
there's less room in the triangular distribution's tail when `S = 256`.

### 5.5 The block-size knob

The `1 / (2·255²) ≈ 7.7 × 10⁻⁶` error floor comes directly from the
signal-to-noise ratio at the first differing bit: the plaintext's
contribution there has the same order of magnitude as the PRF noise from
the blocks below it. If we want a smaller error floor the obvious knob is
to make each block *wider* — more PRF bits per plaintext bit — so the bit
contribution gets less diluted by subsequent PRF mass.

**Generalization.** Let `β` be the number of bits per block (`β = 8` in the
shipping scheme). Each plaintext bit now consumes `β` bits of PRF output
instead of 8, and the ciphertext body grows from `n` bytes to `n·β/8`
bytes. The error analysis from §5.1–§5.4 generalizes just by swapping the
arithmetic base `M = 256` for `M = 2^β`. The worst-case per-comparison
error rate for adjacent pairs at first-differing position `m` becomes:

```text
P(error, m = 1)  = 0
P(error, m = 2)  = 1 / M²
P(error, m ≥ 3)  ≈ 1 / (2·(M−1)²)  ≈  1 / (2·M²)
```

Averaging over random adjacent u16 pairs, the same distribution argument
as §5.4 gives:

```text
E[rate] ≈ 3 / (8·M²)
```

**Tradeoff table.** For a u16 plaintext (16 bits):

| Block size β | `M = 2^β` | Ciphertext bytes | Avg. adjacent-pair rate | Relative to β=8 |
|-------------:|----------:|-----------------:|------------------------:|----------------:|
| 8 bits       |       256 |               17 | `5.7 × 10⁻⁶`           | 1×              |
| 12 bits      |     4 096 |               25 | `~2.2 × 10⁻⁸`          | ~260× better    |
| 16 bits      |    65 536 |               33 | `~8.7 × 10⁻¹¹`         | ~65 000× better |
| 24 bits      | ~16.78 M  |               49 | `~3 × 10⁻¹⁶`           | ~10¹⁰× better   |

Each doubling of the block width squares the error floor (inverse-
quadratic in `M`) for only a linear increase in ciphertext size.

**Implementation complexity.** `β = 16` is the natural next step: 2-byte
blocks are byte-aligned, so the encryption loop just pulls two PRF bytes
per bit instead of one and the backward-carry pass is the same arithmetic
over a longer integer. No new representation machinery.

`β = 12` (nibble-aligned) is substantially more work. The ciphertext body
is no longer byte-aligned, so storage needs bit-packed 12-bit blocks (3
blocks per 4.5 bytes). The backward carry walks through 12-bit blocks
rather than bytes; the PRF stream is pulled 12 bits at a time. None of
this is conceptually hard but it adds enough bit-twiddling that it's
probably not worth the engineering cost for a ~260× improvement when
jumping to `β = 16` gives 65 000× at the same 2× storage ratio.

**The ceiling.** Driving `β` higher drives the error rate to zero only
asymptotically — "bit at the low end of the block" plateaus at roughly
`1/M²`. If you actually need *exact* OPE (zero residual error), there's a
free upgrade at any `β ≥ 9`: place the plaintext bit at the **high** byte
of its block instead of the low byte. That changes the signal from `M^{n-1-k}`
to `2^{β-1}·M^{n-1-k}` while leaving the noise bound unchanged, so for
`β ≥ 9` the signal strictly exceeds the noise and lex compare is correct
on every input. Backward carry is still needed (to handle the
within-block byte wrap when the high byte is `0xFF`), but the residual
error is identically zero. Same storage cost as the LSB variant. We
haven't wired this up because the β=8 probabilistic regime has been
adequate for our use cases, but it's the obvious next move if a consumer
ever needs proof-level correctness.

---

## 6. Empirical verification

The crate ships an `#[ignore]`-gated empirical test, runnable with:

```bash
mise x --env test -- cargo nextest run -p cllw-ore -- \
    --ignored ope_empirical --nocapture
```

It enumerates all adjacent `u16` pairs (65 535 of them) under 200 random
keys — 13.1 million trials — and measures the empirical rate.

Most recent run measured **~6.4 × 10⁻⁶**, matching the theoretical
~5.7 × 10⁻⁶ within the expected noise (Poisson SE at 75 expected errors is
roughly ±0.7 × 10⁻⁶). For comparison, the naive-OPE rate under the same
test harness would be ~3.9 × 10⁻³ — 500–600× higher.

---

## 7. Security properties

### 7.1 Leakage relative to CLLW ORE

The OPE ciphertext is a deterministic function of the same PRF chain and
plaintext bits as the ORE ciphertext. Everything the ORE comparator reveals
(ordering, first differing bit position) is derivable from the OPE
ciphertext via plain lex compare. In the other direction, the OPE
ciphertext reveals slightly less information than the ORE ciphertext on the
rare error cases (where lex compare disagrees with the true order).
Informally: **OPE leakage ≤ ORE leakage**. We get a weaker observation tool
for free; we don't gain an adversary any new power.

### 7.2 IND-OCPA

The scheme is deterministic and maintains the same PRF-chain structure as
CLLW ORE, so it inherits CLLW's IND-OCPA (indistinguishability under
ordered chosen-plaintext attack) guarantee — conditioned on the PRF being a
secure PRF. No new security proof is required for the backward-carry
variant; the carry pass is a public, plaintext-independent function of the
ORE output (modulo the plaintext bits, which the adversary gets to know
under OCPA anyway).

The standard CLLW caveats still apply: low-entropy plaintexts (small
integer ranges, sparse buckets, etc.) leak meaningfully. Don't use this as
your only encryption layer for such data — pair it with a properly-keyed
authenticated symmetric cipher (e.g. AES-GCM) over the same plaintext, and
only use the OPE ciphertext for the order-preserving index column.

### 7.3 What it does not give you

- **Exact OPE.** `7.7 × 10⁻⁶` per worst-case comparison is small but not
  zero. If your application is extraordinarily sensitive to any ordering
  error — say, cryptographic protocols that must not fail with non-
  negligible probability — this is not the right primitive.
- **Decryption.** The backward carry entangles the plaintext bits with
  adjacent PRF bytes in a way that makes recovering the exact plaintext
  cost O(N²) in the worst case. We don't support decryption; pair with
  AES-GCM when round-trip is required.
- **Homomorphic updates.** Incrementing or adding ciphertexts is not
  supported. The PRF chain is plaintext-dependent, which means any update
  that flips plaintext bits re-randomizes downstream PRFs.

---

## 8. Practical considerations

- **Ciphertext overhead.** Variable-length inputs become `8·N + 1` bytes
  (one ciphertext byte per plaintext bit plus the reserved byte). Fixed-
  width numerics go from `N` bytes (ORE) to `N + 1` bytes (OPE): `u32`
  becomes 33 bytes, `u64` becomes 65 bytes.
- **Indexing.** Because standard byte compare works, you can put these
  into any B-tree index (Postgres btree, SQLite, LMDB) and range-scan
  over them directly. That's the whole point of OPE.
- **Determinism.** Encryption is deterministic under a given (key, salt,
  plaintext). This is the right behaviour for an index column.
- **When to reach for this vs. ORE.** If you need the custom comparator's
  100% correctness (no residual error), use `CllwOreEncrypt`. If you'd
  rather drop ciphertexts into an off-the-shelf ordered index and live
  with the `~10⁻⁵`-order error, use `CllwOpeEncrypt`.

---

## 9. References

- **CLLW.** Nathan Chenette, Kevin Lewi, Stephen A. Weis, David J. Wu.
  *Practical Order-Revealing Encryption with Limited Leakage.* FSE 2016.
  The OPE interpretation lives in Section 3.2.
- **Lewi–Wu Block ORE.** Kevin Lewi, David J. Wu. *Order-Revealing
  Encryption: New Constructions, Applications, and Lower Bounds.* CCS 2016.
  Stronger leakage profile; we use it for most production paths. See the
  [`ore.rs`](https://ore.rs) crate.
- **BCLO (hypergeometric OPE).** Alexandra Boldyreva, Nathan Chenette,
  Younho Lee, Adam O'Neill. *Order-Preserving Symmetric Encryption.*
  EUROCRYPT 2009. The classical baseline; different leakage/security
  trade-off.
- **Implementation.** The backward-carry encryption and its tests live in
  `packages/cllw-ore/src/impls/mod.rs::encrypt_ope_bits`. The empirical
  error-rate measurement is in
  `packages/cllw-ore/src/impls/num.rs::ope_empirical_error_rate_adjacent_u16`.
