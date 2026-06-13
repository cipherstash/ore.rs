# A timing channel in a random shuffle — and how we made ORE faster by removing it

*Draft for the CipherStash research blog — 2026-06-13. Follows
`cipherstash-js-suite/prompts/_shared/writing-guidelines.md`. Code samples are Rust
(the library is `ore-rs`), not the TypeScript default — this is an engine-internals
post, so the product-doc conventions for TS examples and CTAs are adapted accordingly.*

**Title options**
1. A timing channel in a random shuffle — and how we made ORE faster by removing it
2. Rejection sampling leaks time: a constant-time fix for our ORE permutation
3. Faster *and* safer: replacing rejection sampling in order-revealing encryption

**Meta description** (152 chars)
> A rejection-sampling shuffle in our order-revealing encryption leaked timing. The fix — fixed-count wide draws — is constant-time and ~9× faster. Here's how.

---

## What this is about

We rewrote `ore-rs`, the order-revealing encryption (ORE) library behind CipherStash's
searchable encryption, for speed. While benchmarking we found a small **timing
side-channel inside a random shuffle**, and a build setting that was running our AES in
software — **60× slower** than the hardware path — without warning.

This post covers the shuffle. The fix is a good reminder that the textbook "correct"
way to draw an unbiased random number (rejection sampling) can be both slower *and*
less safe than a slightly smarter one — and that the smarter one has a cleaner security
proof.

> **Note:** The cryptographic constructions here are under internal review before
> release. This is an engineering write-up, not a security advisory — we have no
> evidence of a practical attack, and we fixed the channel as a matter of discipline.

## Background: the shuffle inside ORE

ORE lets you compare encrypted values — "is A < B?" — without decrypting them. We use
the Lewi–Wu construction: it splits a plaintext into small blocks and, per block,
applies a **pseudo-random permutation (PRP)** — a keyed, secret reordering of the
block's value space.

We build that PRP with a **Fisher–Yates shuffle** (what Knuth popularized as
Algorithm P). To shuffle `n` items you walk from the top down and, at each position `i`,
draw a uniform index `j` in `0..=i` and swap. So the whole construction depends on one
operation: **draw a uniform integer in a range.**

## Why it matters: drawing a bounded integer can leak time

Your randomness gives you uniform *bits*. But `i+1` is rarely a power of two, so folding,
say, 256 equally likely bytes into 3 equally likely outcomes doesn't divide evenly —
`byte % 3` is biased. For a permutation, that bias makes some orderings more likely than
others, which a PRP must not do.

The standard fix is **rejection sampling**: draw, and if the value lands in the biased
tail, throw it away and draw again. It's unbiased and correct. It also draws a
**variable** number of values — and how many depends on the bytes you happen to get.

Here is the problem. Those bytes come from a seed, and the seed is derived from the
**plaintext**. So the time the shuffle takes depends, weakly, on the secret being
encrypted.

> **Warning:** A loop whose iteration count depends on secret-derived data is a timing
> side-channel. The leak here is tiny and noisy, and we know of no practical attack —
> but constant-time execution is a discipline, not a cost-benefit call. Timing channels
> have a habit of going from "theoretical" to "exploited" once someone finds the right
> amplification.

## How the fix works: wide draws + Lemire reduction

Two ideas, both about *how you draw the index* — the shuffle itself doesn't change.

**1. Draw wide.** Use a full 64-bit value instead of a byte. The leftover bias from
splitting a power-of-two range into `n` buckets is always "at most one bucket is one
element larger." What matters is that ±1 *relative to bucket size*:

- A byte (256 values) into 63 buckets: 4 buckets over-represented → bias ≈ **1.5%**.
- A 64-bit value into 63 buckets: ~63 buckets over-represented out of 2⁶⁴ → bias ≈ **2⁻⁵⁸**.

The wide draw doesn't remove the bias; it shrinks it to a rounding error — small enough
that you no longer need rejection to hide it. Drop the retry loop, and the draw count
becomes **fixed**.

**2. Reduce with Lemire's multiply-high.** Map a 64-bit `x` into `0..range` with one
widening multiply and a shift — no division, no branch:

```rust
// uniform index in [0, range): no rejection loop, no modulo
let j = ((x as u128 * range as u128) >> 64) as u64;
```

Together: a fixed sequence of wide draws, each reduced with a multiply-high, replaces a
variable-length rejection loop.

```rust
// Before: variable draw count — leaks time
let mut v = rng.next_u32() % cap;
while v > max { v = rng.next_u32() % cap; }   // retries depend on the seed

// After: exactly one draw per index — constant-time
let j = ((rng.next_u64() as u128 * (i as u128 + 1)) >> 64) as usize;
```

**Expected outcome:** identical shuffle, seed-independent runtime, branch-free, and no
division.

## The security trade is in our favour

Rejection sampling gives an *exactly* uniform permutation. The wide-draw version is
uniform to within a **statistical distance of ~2⁻⁵⁵** of perfect.

That's not a loss, because the Lewi–Wu analysis already models each block's permutation
as a uniformly random permutation. Our construction instantiates exactly that object, up
to a 2⁻⁵⁵ term — so the change adds **one small number to the existing security bound**:
no new assumption, no new model, nothing to argue about.

> **Tip:** For secret-dependent draws, "uniform to 2⁻⁵⁵ in constant time" is a better
> property than "exactly uniform in variable time." Reach for a fixed-count method
> whenever you draw bounded random integers near secret data.

## We tried the fancy option and rejected it

For small domains there's an elegant constant-time PRP, **swap-or-not**. It vectorizes
beautifully and looks like the "right" primitive. We prototyped it — and rejected it on
the *proof*, not on speed (our shuffle was faster anyway).

Swap-or-not's security bound is strong only when an attacker can query a small fraction
of the value space. But in ORE, a block's ciphertext effectively exposes its **entire**
permutation, so the honest assumption is "the attacker sees everything" — and there the
bound becomes meaningless on a 64-element domain at any practical setting. The known fix
reintroduces data-dependent control flow (a timing channel), defeating the point. A
humble shuffle with a one-line proof beat the sophisticated primitive.

## The other finding: check that your AES is hardware AES

While benchmarking we found the Rust `aes` crate (v0.8) does **not** auto-enable the
ARMv8 crypto extensions — you opt in with `RUSTFLAGS="--cfg aes_armv8"`. Without it you
silently get software AES, ~60× slower per block. Setting the flag alone took a `u64`
encryption from 381 µs to 39 µs.

> **Tip:** If you ship cryptography on ARM servers (Graviton, Apple CI), confirm your
> AES is hardware-accelerated. It's an easy 60× to leave on the table.

## Results

| Change | `u64` encrypt (M1 Max) |
|---|---:|
| Starting point (software AES) | 381 µs |
| Hardware AES enabled | 39 µs |
| Full v2 rewrite + constant-time PRP | **8.6 µs** |

The PRP construction alone dropped from ~1.36 µs to 153 ns — about **9× faster** —
while *removing* a timing channel rather than adding risk.

## We found the same pattern in our own code

Once we'd named it, we went looking. The same rejection-sampling shape lives in
`vitaminc`, our Rust cryptography toolkit, in its bounded-random helper (which feeds a
permutation-key generator and a password generator). Same root cause, same fix — plus
two correctness bugs the audit surfaced along the way. We've filed an issue and are
fixing it.

## Why this matters for CipherStash

Constant-time discipline is part of what "searchable encryption you can trust" means.
This work makes ORE measurably faster — helping searchable-encryption queries meet
real-time performance needs — and removes a side-channel before it can ever matter.
Finding and fixing the same class of issue across two of our libraries is the kind of
continuous, proactive security posture our customers are buying, not a point-in-time
checkbox.

## Related

- `ore-rs` (the ORE library) and its v2 architecture plan
- CipherStash searchable encryption: [cipherstash.com](https://cipherstash.com)
- Daniel Lemire, "Fast Random Integer Generation in an Interval" (2019)
- Lewi–Wu, "Order-Revealing Encryption: New Constructions, Applications, and Lower
  Bounds" (2016)

## Takeaways

1. **Rejection sampling is a timing channel** when the rejection count depends on
   secret-derived randomness.
2. **Wide draws + Lemire multiply-high** give fixed-count, branch-free, bounded integers
   biased only to ~2⁻⁵⁵ — negligible, and a clean term in a proof.
3. **"Exact via rejection" isn't automatically safer** for secret-dependent draws.
4. **The most sophisticated primitive isn't always right** — swap-or-not's proof didn't
   fit our threat model.
5. **Check that your AES is hardware AES.** A build flag can be worth 60×.
