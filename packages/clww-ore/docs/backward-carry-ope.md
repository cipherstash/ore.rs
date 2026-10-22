# Exact OPE from CLWW ORE via Backward Carry + MSB-Bit Placement

*An engineering note on the order-preserving variant of CLWW ORE.*

---

## TL;DR

The CLWW order-revealing encryption scheme has a natural "order-preserving"
(OPE) interpretation described in Section 3.2 of the original paper: take
the ORE ciphertext bytes and compare them lexicographically. It almost
works, but wraps around `mod 256` — so roughly 1 in 256 comparisons
disagree with the true plaintext order.

This note walks through two successive fixes that compose:

1. **Backward carry with a reserved byte** (§5). Reinterpret the ciphertext
   as a big-endian integer and propagate the plaintext's `+bit` contribution
   right-to-left as an arithmetic carry, absorbing overflow into a reserved
   leading byte. Drops the per-comparison error rate from ~1/256 to
   ~7.7 × 10⁻⁶ worst case — a ~500× improvement — but still not exact.

2. **MSB-bit placement of the plaintext signal** (§6). Instead of adding
   `+1` to each byte when the plaintext bit is 1, add `+128` — placing the
   signal at the MSB of the byte. This makes the signal 128× larger than
   any noise the backward carry can propagate, killing the residual error
   entirely. The scheme becomes **exactly** order-preserving.

Cost vs the naive paper scheme: one extra ciphertext byte (the reserved
leading byte) and a single additional linear pass during encryption. Same
number of PRF evaluations. Same leakage profile as CLWW ORE.

---

## 1. OPE vs ORE: why we care about lex compare

**Order-revealing encryption (ORE)** produces ciphertexts that can be
compared with a custom function `CMP(c₁, c₂)` that reveals the plaintext
ordering without revealing the plaintexts themselves. CLWW's comparator is
a byte scan with a `mod 256` check (details below); it's fast and
constant-time, but it's also a non-standard comparison, which means you
can't just put ORE ciphertexts into a database index and expect `ORDER BY`
to do the right thing.

**Order-preserving encryption (OPE)** goes further: ciphertexts are ordered
the same way as the plaintexts under *standard byte-lexicographic compare*.
That's the comparison every system already knows how to do — `<`, `>`,
B-tree key compare, `ORDER BY`, `memcmp`. A valid OPE ciphertext is a
drop-in replacement for an encrypted column that you can still range-query
over.

The tradeoff: OPE is generally harder to build securely than ORE (it
reveals strictly *at most* as much information as ORE, but typically a bit
more than the comparator-based variant, because the adversary gets exact
byte order for free). For the CLWW family the difference is small, which
is why reinterpreting CLWW ORE as OPE is attractive.

---

## 2. How CLWW ORE works

CLWW is a bit-by-bit construction. For an n-bit plaintext `p = b₀ b₁ … bₙ₋₁`
(MSB-first), the encryptor walks the bits left-to-right feeding them into
a keyed hasher. At each step it pulls out one pseudorandom byte and adds
the current bit:

```text
fn encrypt_ore(K, p):              # returns n ciphertext bytes
    hasher = keyed_hasher(K, "ore") # BLAKE3::new_keyed(K), then the
                                    # scheme tag and the framed salt
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
2. **The encrypted bit lives at the byte level.** `cᵢ = (PRFᵢ + bᵢ) mod 256`.
   If you knew `PRFᵢ` you could recover `bᵢ` by subtraction — but nobody
   except the key holder does.

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
plaintext encoding, that difference is ±1, which is exactly what the
`mod 256` check tests. Bytes after k look independent-random and the
comparator correctly stops at the first differing byte.

### Leakage

CLWW ORE's ciphertext reveals the **first differing bit position** (i.e. a
common prefix length), and nothing else beyond ordering. This is a
standard IND-OCPA-style leakage — weaker than full plaintext but
non-trivial, especially on low-entropy data like integers in a narrow
range. For production use cases with richer threat models we pair CLWW
with additional primitives; see the package README.

---

## 3. The paper's OPE interpretation — and the 1/256 bug

Section 3.2 of the CLWW paper observes that if you just treat the ORE
ciphertext as a byte string and sort it, you almost get an OPE. Informally:
at the first differing byte, `c_Y = c_X + 1` — so lexicographic compare
puts the larger plaintext's ciphertext last. "Almost" is doing a lot of
work.

The failure mode: `c_Y = (c_X + 1) mod 256`. If `c_X = 0xFF`, then
`c_Y = 0x00`. Lex compare sees `0x00 < 0xFF` and concludes Y < X, but the
plaintext order is Y > X. The ORE comparator's `mod 256` check papers over
this; a raw byte compare cannot.

### Worked example

Take 8-bit plaintexts X = 0 and Y = 1. All bits of X are 0; bits of Y are
`0000 0001`. The PRF chain for Y sees only zeros up to bit 6, so the first
seven PRFs are identical in both; they diverge only at bit 7 (the LSB),
and at that position we only care about `PRF₇` itself.

Suppose by chance `PRF₇ = 0xFF` — a 1-in-256 event:

| Byte index | PRF       | X's bit | Y's bit | `c^X`  | `c^Y`                |
|-----------:|-----------|---------|---------|--------|----------------------|
| 0–6        | `PRF₀..₆` | 0       | 0       | `PRFᵢ` | `PRFᵢ`               |
| 7 (LSB)    | `0xFF`    | 0       | 1       | `0xFF` | `(0xFF + 1) mod 256 = 0x00` |

Lex compare: bytes 0..6 equal, byte 7 has `0x00 < 0xFF`, so the comparator
says `c^Y < c^X`. Wrong.

### Error rate: ~1/256

Over uniformly random keys, `PRFᵢ` at the first differing bit position is
uniform on `{0, …, 255}`, and the wrap happens iff `PRFᵢ` is exactly
`0xFF` (for the side that was supposed to add `+1`). That's

```text
Pr[error] ≈ 1/256 ≈ 3.9 × 10⁻³
```

For a single comparison that's fine; for any application that issues even
a modest number of ORDER BY / range-scan comparisons, the cumulative hit
rate is unacceptable.

---

## 4. First fix: backward carry

The idea is to reframe the ciphertext as arithmetic rather than a byte
stream. When a `+bit` addition wraps a byte, we don't lose the `+1` — we
propagate it right-to-left as a carry, eventually landing it in a reserved
leading byte that guarantees there's always room to absorb the overflow.

### Intuition

The CLWW keystream gives us an n-byte pseudorandom number `P`:

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
long addition. The reserved leading byte is the overflow digit in case
`P + B ≥ 256ⁿ` (which, as we'll see in §5.5, it never is by more than 1).

### Pseudocode (first-fix variant)

```text
fn encrypt_ope_v1(K, p):
    hasher = keyed_hasher(K)

    # Pass 1 — same PRF chain as ORE, recording bits as we go.
    prfs = []; bits = []
    for bit in bits_msb_first(p):
        prfs.push(hasher.next_byte())
        bits.push(bit)
        hasher.update(bit)

    # Pass 2 — compute P + B with backward carry.
    out = [0] + prfs                  # reserved byte at index 0
    carry = 0
    for i in reversed(0..n):
        total       = out[i + 1] + bits[i] + carry         # <-- note the +bit
        out[i + 1]  = total mod 256
        carry       = total >> 8       # 0 or 1
    out[0] = carry                     # 0 or 1
    return out                         # length n + 1
```

Comparison is plain byte-lex compare — no custom comparator needed:

```text
fn compare_ope(c1, c2):
    return c1.as_bytes().cmp(c2.as_bytes())   # e.g. memcmp
```

### Replaying the §3 example

Same X = 0, Y = 1, `PRF₇ = 0xFF`. The ciphertext is a 9-byte array
`out[0..=8]`, with `out[0]` reserved and `out[i+1]` encoding plaintext
bit `i`.

For X (bits all zero): pass 2 adds nothing anywhere and no carry is
generated. `ct_X = [0, PRF₀, PRF₁, …, PRF₆, 0xFF]`.

For Y (bits `0000 0001`): pass 2 starts at `i = 7` and walks left:

- `i = 7` (bit 7 = 1, writes to `out[8]`): `total = 0xFF + 1 + 0 = 0x100`
  → `out[8] = 0x00`, carry = 1.
- `i = 6` (bit 6 = 0, writes to `out[7]`): `total = PRF₆ + 0 + 1 = PRF₆ + 1`.
  Assuming `PRF₆ < 0xFF` → `out[7] = PRF₆ + 1`, carry = 0.
- `i = 5..0` (bit = 0, carry = 0): `out[1..=6]` unchanged.
- Final carry 0 lands in `out[0]`.

So `ct_Y = [0, PRF₀, …, PRF₅, PRF₆ + 1, 0x00]` (in array-index terms:
`out[7]` changed from `PRF₆` to `PRF₆ + 1` and `out[8]` wrapped from
`0xFF` to `0x00`).

Lex compare:

- `out[0..=6]` equal in both (reserved = 0, then shared PRFs).
- `out[7]`: `ct_X` has `PRF₆`, `ct_Y` has `PRF₆ + 1` — Y is larger here.

Lex compare resolves at `out[7]` with `ct_X < ct_Y`. ✓

The carry "moved" the `+1` that would have wrapped into a more-significant
byte, where it correctly dominates the lex comparison. But we'll see in §5
that this fix isn't quite exact — the carry can occasionally be cancelled
out by PRF divergence at bytes *after* the first differing bit.

---

## 5. Why the first fix isn't exact

The construction isn't free of errors — it can still go wrong, just *much*
less often. This section derives how often.

### 5.1 Setup

Consider two plaintexts X and Y with **first differing bit at position k**
(so `b₀^X = b₀^Y, …, b_{k-1}^X = b_{k-1}^Y`). Assume X < Y — i.e.
`b_k^X = 0` and `b_k^Y = 1` — so that the later ciphertext ordering is the
one we expect lex compare to report. The X > Y case is symmetric.

**PRF agreement.** For i ≤ k, the PRF chain input is identical in X and Y,
so `PRFᵢ^X = PRFᵢ^Y`. For i > k, the chain inputs diverge (at bit k), so
`PRFᵢ^X` and `PRFᵢ^Y` are independent uniform pseudorandom bytes.

**Decompose the ciphertext difference.** Treating ciphertexts as
(n+1)-byte big-endian integers:

```text
C^Y − C^X = (P^Y − P^X) + (B^Y − B^X)
```

- `P^Y − P^X` has zero contribution from bytes 0..k (PRFs match) and,
  from bytes k+1..n−1, a contribution of `V − U` where U and V are
  independent uniform integers on `{0, 1, …, S − 1}` and `S = 256^{n-1-k}`.
- `B^Y − B^X` contributes `+S` from bit k (the first differing bit, 0→1),
  plus `±1 · 256^{n-1-i}` from each differing bit i > k.

The answer to "how often do we err" depends on `B^Y − B^X`. We'll focus on
the **worst case**, which is adjacent integer plaintexts (pairs like X,
X+1), and then extend.

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

**Independent of `m = n − k` for `m ≥ 2`.** Whether the first differing
bit is two positions in or twenty, the per-pair error rate is the same.

For `m = 1` (only the LSB differs), the PRF chain never diverges, so
`V = U = 0` deterministically and `P(error) = 0`.

### 5.3 The root cause: signal ≈ noise at the first differing byte

The derivation above has a clean physical interpretation. Stripped of
algebra:

- The plaintext's **signal** at the first differing byte is `+1` (we added
  exactly one to that byte when `bit = 1`).
- The backward-carry **noise** from the byte to its right is `±1` (carry
  is always 0 or 1, but it can go either way across X and Y because they
  see independent PRFs there).
- Signal and noise are the same order of magnitude. In a tight corner
  case — specifically when `PRFₖ = 255` AND the PRF at byte k+1 aligns
  unfavourably — they cancel exactly and the two ciphertexts tie. That's
  the `~7.7 × 10⁻⁶` residual.

The next section fixes this by making the signal much larger without
changing the noise.

### 5.4 Averaging over random adjacent pairs

For a uniform random X, the position k (first differing bit in X ↔ X+1)
is determined by the number of trailing 1s in X:

| Condition                       | Probability | Rate at that k                |
|---------------------------------|:-----------:|-------------------------------|
| X's LSB is 0 (m = 1)            |    1/2      | 0                             |
| X ends in `...01` (m = 2)       |    1/4      | `1/65 536 ≈ 1.5 × 10⁻⁵`       |
| X ends in `...011` (m ≥ 3)      |    1/4      | `~7.7 × 10⁻⁶`                 |

Putting it together:

```text
E[rate] ≈ 0 · (1/2) + 1.5e-5 · (1/4) + 7.7e-6 · (1/4)
       ≈ 5.7 × 10⁻⁶
```

The m = 2 case is noticeably higher than the m ≥ 3 asymptote because
there's less room in the triangular distribution's tail when `S = 256`.

### 5.5 Bookkeeping: the reserved byte only ever holds 0 or 1

It's worth briefly noting why a single reserved byte is always enough to
absorb the carry. Each byte of the carry pass adds `byte + bit + carry_in`
with `byte ≤ 255`, `bit ∈ {0, 1}`, `carry_in ∈ {0, 1}` — total `≤ 257`.
So outgoing carry is always 0 or 1, and by induction the final carry
landing in the reserved byte is 0 or 1. Arithmetically,
`P + B ≤ 256ⁿ · (256/255) < 2 · 256ⁿ`, so the (n+1)-byte integer always
has a reserved byte of 0 or 1, never more.

(This also holds for the MSB-bit variant in §6: `P + 128·B ≤ 1.5 · 256ⁿ`,
still < `2 · 256ⁿ`. The reserved byte is `0` or `1` either way.)

---

## 6. Second fix: place the plaintext bit at the MSB of its byte

The residual in §5 comes from the signal and noise being the same order
of magnitude at the first differing byte. The fix is to make the signal
larger without changing the noise — by placing the plaintext bit at a
higher-weight position within its byte.

### The change

Instead of adding `+bit` to each byte (which puts the signal at the LSB
of the byte, weight 1), add `+bit · 128` (which puts the signal at the
MSB of the byte, weight 128). Same ciphertext size. Same PRF chain. Same
carry mechanism. One line of code.

```text
fn encrypt_ope(K, p):
    hasher = keyed_hasher(K)

    prfs = []; bits = []
    for bit in bits_msb_first(p):
        prfs.push(hasher.next_byte())
        bits.push(bit)
        hasher.update(bit)

    out = [0] + prfs
    carry = 0
    for i in reversed(0..n):
        total       = out[i + 1] + bits[i] * 128 + carry   # <-- +bit becomes +bit·128
        out[i + 1]  = total mod 256
        carry       = total >> 8
    out[0] = carry
    return out
```

### Why it's now exact

At the first differing bit (position k, which is encoded at ciphertext
byte `out[k+1]`), X and Y share the same PRF and differ only in which
bit they added:

- X's byte: `(PRFₖ + 0·128 + carry_X_in) mod 256 = (PRFₖ + carry_X_in) mod 256`
- Y's byte: `(PRFₖ + 1·128 + carry_Y_in) mod 256 = (PRFₖ + 128 + carry_Y_in) mod 256`

The difference between these two values, before any modular reduction,
is `128 + (carry_Y_in − carry_X_in)` — a number in `{127, 128, 129}`.
**Never zero.**

Compare to the first-fix variant, where the same difference was
`1 + (carry_Y_in − carry_X_in) ∈ {0, 1, 2}` — which *can* be zero, and
that's exactly the ~7.7 × 10⁻⁶ tie case from §5.

When `PRFₖ + 128` wraps (i.e. `PRFₖ ≥ 128`), the backward carry deposits
a clean `+1` into `out[k]` instead — which sits at 256× the integer
weight of `out[k+1]` — and lex compare resolves there by a margin of 1.
Either way, some byte at or before `out[k+1]` strictly distinguishes
the two ciphertexts in the correct direction.

There's no PRF outcome the adversary can construct that flips the
comparison. Ordering is **exactly** preserved.

### Worked example

Take X = 1 (`0000 0001`) and Y = 2 (`0000 0010`), two adjacent integers
whose first differing bit is at `k = 6`. PRF chain agrees through
`PRF₆`; call `PRF₀..PRF₆ = A₀..A₆`. `PRF₇^X` and `PRF₇^Y` diverge —
pick the worst case `PRF₇^X = 0xFF`, `PRF₇^Y = 0x00` so that byte
`out[8]`'s PRF values are maximally adversarial.

**Encrypt X** — pass 2 walks `i = 7, 6, …, 0`:

- `i = 7` (bit 7 = 1, writes `out[8]`): `total = 0xFF + 128 + 0 = 0x17F`
  → `out[8] = 0x7F`, carry = 1.
- `i = 6` (bit 6 = 0, writes `out[7]`): `total = A₆ + 0 + 1 = A₆ + 1`
  (assuming `A₆ < 255`) → `out[7] = A₆ + 1`, carry = 0.
- `i = 5..0` (bit = 0, carry = 0): `out[1..=6]` unchanged.
- `out[0] = 0`.

`ct_X = [0, A₀, A₁, …, A₅, A₆ + 1, 0x7F]`.

**Encrypt Y** — pass 2:

- `i = 7` (bit 7 = 0, writes `out[8]`): `total = 0x00 + 0 + 0 = 0`
  → `out[8] = 0x00`, carry = 0.
- `i = 6` (bit 6 = 1, writes `out[7]`): `total = A₆ + 128 + 0`, result
  depends on whether this wraps.

Two cases on `A₆`:

- **Case 1: `A₆ < 128`** (no wrap).
  `out[7] = A₆ + 128`, carry = 0. `out[1..=6]` unchanged. `out[0] = 0`.
  `ct_Y = [0, A₀, …, A₅, A₆ + 128, 0x00]`.
  Compare `ct_X` vs `ct_Y`:
  - `out[0..=6]` equal.
  - `out[7]`: `ct_X` has `A₆ + 1`, `ct_Y` has `A₆ + 128`. Difference 127.
  - Lex resolves at `out[7]` with `ct_X < ct_Y`. ✓
- **Case 2: `A₆ ≥ 128`** (wrap).
  `out[7] = A₆ − 128`, carry = 1 → propagates to `i = 5`.
  `out[6] = A₅ + 0 + 1 = A₅ + 1` (assuming `A₅ < 255`), carry = 0.
  `ct_Y = [0, A₀, …, A₄, A₅ + 1, A₆ − 128, 0x00]`.
  Compare `ct_X` vs `ct_Y`:
  - `out[0..=5]` equal.
  - `out[6]`: `ct_X` has `A₅`, `ct_Y` has `A₅ + 1`. Difference 1.
  - Lex resolves at `out[6]` with `ct_X < ct_Y`. ✓

Both cases resolve correctly, regardless of `PRF₇`'s maximally adversarial
values. The comparison never even looks at `out[8]`.

### Aside: the 2's-complement flavour

`(x + 128) mod 256 = x XOR 128`. This is specific to `128 = 2⁷`, because
adding to the top bit has no higher bit to carry into at the byte level.
So "add 128 when bit=1" is literally the same as "flip the top bit when
bit=1" — which is a sign-flip operation under the signed interpretation
of the byte.

That's a pleasant connection but not the reason the scheme works.
Ordering works because `128 > 1` (the max carry-propagation noise at any
byte). If we added anything from 2 to 128, the same argument goes
through. 128 is the natural maximum: it's the largest signal a single
bit can encode within a single byte.

---

## 7. Empirical verification

The crate ships an `#[ignore]`-gated exactness check that runs every
adjacent `u16` pair (65 535 of them) under 20 random keys — 1 310 700
comparisons total — and asserts zero ordering errors:

```bash
cargo test -p clww-ore --release -- --ignored ope_exactness
```

Most recent run: **0 / 1 310 700** errors. Under the first-fix variant
(`+1` instead of `+128`), the same harness would produce about 7
ordering errors on average — matching the §5.4 theoretical prediction of
`~5.7 × 10⁻⁶`. With MSB-bit placement the residual is eliminated.

---

## 8. Block size as an orthogonal knob

The derivation above treats "one PRF byte per plaintext bit" (β = 8 bits
per block) as a given. You could in principle widen that: β = 16 gives
you 2 PRF bytes per plaintext bit, β = 24 three bytes, and so on, with
the ciphertext growing linearly in β.

For the **first-fix variant** (`+bit`), widening blocks quadratically
drops the error floor (`~1/(2·M²)` with `M = 2^β`), because the
same-order signal/noise argument now plays out at a larger scale. β = 12
gives ~3 × 10⁻⁸, β = 16 gives ~1 × 10⁻¹⁰. That would be a viable path to
(near-)exact OPE if we were stuck with the `+bit` formulation.

For the **MSB-bit variant** in §6, block size is orthogonal to
correctness — ordering is already exact at β = 8. Widening blocks is
purely a *security* tradeoff: more PRF bits per plaintext bit means a
stronger pseudorandomness guarantee for each ciphertext byte, at the cost
of proportionally larger ciphertexts.

We ship β = 8 because it gives exact ordering at the smallest storage
cost, and the CLWW security properties are already what the CLWW paper
analyses at this block size.

---

## 9. Security properties

### 9.1 Leakage relative to CLWW ORE

The OPE ciphertext has the shape of an ORE ciphertext over a PRF chain of
its own — both the backward carry and the MSB-bit placement are
plaintext-independent public transforms. Everything the ORE comparator
reveals (ordering, first differing bit position) is derivable from the OPE
ciphertext via plain lex compare. In the other direction, the OPE
ciphertext reveals nothing the ORE ciphertext doesn't.
**OPE leakage ≤ ORE leakage.**

The chain must be its own. ORE and OPE terms of one value built on one PRF
chain differ byte by byte by `{0, 1}` where a plaintext bit is 0 and by
`{127, 128}` where it is 1, so the pair gives the plaintext away without
the key. clww-ore up to 0.5 had that flaw. From 0.6 the keyed PRF input
opens with a sixteen-byte tag for the scheme (`clww-ore/ore/v1` or
`clww-ore/ope/v1`, NUL-padded), then the salt's length as a big-endian
`u64`, then the salt, then the plaintext bits. The tag keeps the two
chains independent under one key and salt, and the length keeps one salt
from being a shifted copy of another (`s` after a 1 bit against
`s ‖ 0x01`).

### 9.2 IND-OCPA

The scheme is deterministic and maintains CLWW's PRF-chain structure, so
it inherits CLWW's IND-OCPA (indistinguishability under ordered
chosen-plaintext attack) guarantee — conditioned on the PRF being a
secure PRF. No new security proof is required; the carry pass and the
MSB-bit placement are public, plaintext-independent functions of the ORE
output (modulo the plaintext bits, which the adversary gets to know under
OCPA anyway).

The standard CLWW caveats still apply: low-entropy plaintexts (small
integer ranges, sparse buckets, etc.) leak meaningfully via the
first-differing-bit-position signal. Don't use this as your only
encryption layer for such data — pair it with a properly-keyed
authenticated symmetric cipher (e.g. AES-GCM) over the same plaintext,
and only use the OPE ciphertext for the order-preserving index column.

### 9.3 The reserved byte

The reserved byte is initialised to `0` and is only ever written to by
the final carry of the backward pass, which is bit-valued (0 or 1). It's
never mixed with a PRF byte, so there's no chance of a random oracle
pushing it to overflow. Its value is a deterministic function of the
plaintext and the key — pseudorandom under the PRF assumption, but
without any exploitable structure on its own (seen in isolation, it's one
bit per ciphertext).

### 9.4 What it does not give you

- **Decryption.** The MSB-bit placement and backward carry entangle the
  plaintext bits with adjacent PRF bytes in a way that makes recovering
  the exact plaintext cost O(N²) in the worst case. The crate supports
  decryption for neither scheme, ORE included; pair with AES-GCM when
  round-trip is required.
- **Homomorphic updates.** Incrementing or adding ciphertexts is not
  supported. The PRF chain is plaintext-dependent, which means any update
  that flips plaintext bits re-randomizes downstream PRFs.

---

## 10. Practical considerations

- **Ciphertext overhead.** Variable-length inputs become `8·N + 1` bytes
  (one ciphertext byte per plaintext bit plus the reserved byte).
  Fixed-width numerics go from `N` bytes (ORE) to `N + 1` bytes (OPE):
  `u32` becomes 33 bytes, `u64` becomes 65 bytes.
- **Indexing.** Because standard byte compare works, you can put these
  into any B-tree index (Postgres btree, SQLite, LMDB) and range-scan
  over them directly. That's the whole point of OPE.
- **Determinism.** Encryption is deterministic under a given
  `(key, salt, plaintext)`. This is the right behaviour for an index
  column.
- **When to reach for this vs. ORE.** Use `ClwwOpeEncrypt` when you want
  to put ciphertexts into an off-the-shelf ordered index. Use
  `ClwwOreEncrypt` when you're happy with a custom comparator (no
  reserved-byte overhead, slightly smaller ciphertexts).

---

## 11. References

- **CLWW.** Nathan Chenette, Kevin Lewi, Stephen A. Weis, David J. Wu.
  *Practical Order-Revealing Encryption with Limited Leakage.* FSE 2016.
  The OPE interpretation lives in Section 3.2.
- **Lewi–Wu Block ORE.** Kevin Lewi, David J. Wu. *Order-Revealing
  Encryption: New Constructions, Applications, and Lower Bounds.*
  CCS 2016. Stronger leakage profile; we use it for most production
  paths. See the [`ore.rs`](https://ore.rs) crate.
- **BCLO (hypergeometric OPE).** Alexandra Boldyreva, Nathan Chenette,
  Younho Lee, Adam O'Neill. *Order-Preserving Symmetric Encryption.*
  EUROCRYPT 2009. The classical baseline; different leakage/security
  trade-off.
- **Implementation.** The encryption and its tests live in
  `packages/clww-ore/src/impls/mod.rs::encrypt_ope_bits`. The exhaustive
  exactness check is
  `packages/clww-ore/src/impls/primitives.rs::ope_exactness_adjacent_u16`.
