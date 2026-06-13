# The shuffle that leaked time: making order-revealing encryption constant-time *and* faster

*Draft for the CipherStash research blog — 2026-06-13*

We've been rewriting `ore-rs`, the order-revealing encryption (ORE) library at the
heart of CipherStash's searchable encryption. The goal was speed. Along the way we
found two things worth writing down: a build-configuration trap that was making our
cryptography run **60× slower** than it should on a whole class of hardware, and a
small **timing side-channel hiding inside a random shuffle** — one that turns out to
be a general-purpose footgun we then found in a second codebase of our own.

The fix for the second one is a nice example of a recurring theme in applied
cryptography: the "obviously correct" textbook approach (rejection sampling for
unbiased random numbers) was both slower *and* less safe than a slightly cleverer
one, and the cleverer one has a cleaner security proof. Let's walk through it.

## Background: what the shuffle is doing in ORE

ORE lets you encrypt numbers so that ciphertexts can be *compared* — you can ask "is
A < B?" on encrypted data — without being able to decrypt them. We use the Lewi–Wu
construction, which breaks a plaintext into small blocks and, for each block,
applies a **pseudo-random permutation (PRP)**: a keyed bijection that shuffles the
block's value space (e.g. all 64 values of a 6-bit block) into a secret order.

The PRP is built with a **Fisher–Yates shuffle** — the standard in-place shuffle
(what Knuth popularized as Algorithm P). To shuffle `n` items, you walk from the top
down and, at each position `i`, pick a uniformly random index `j` in `0..=i` and swap.
The shuffle is seeded from a key derived (via a PRF) from the plaintext prefix, so
that two values sharing a prefix get the same permutation for the block where they
first differ — that's what makes the comparison work.

So the whole thing hinges on drawing **a uniform random integer in `0..=i`**. And
that is where the trouble was.

## The trap: uniform integers in an awkward range

Your randomness source gives you uniform *bits* — say, a uniform byte in `0..=255`.
But `i+1` is almost never a power of two, so there's no clean way to fold 256 equally
likely bytes into, say, 3 equally likely outcomes. 256 isn't divisible by 3.

If you just take `byte % 3`, you get **modulo bias**: the values 0..255 don't split
evenly, so some results are slightly more likely than others. For a permutation, that
bias is a real defect — it makes some permutations more probable than others, which is
exactly what a PRP must not do.

The textbook cure is **rejection sampling**: figure out the largest in-range value you
can accept without bias, and if your draw lands above it, throw it away and draw again.
That's what our code did, and what virtually every "draw a bounded random integer"
helper does. It's unbiased and correct.

It also has a problem.

## The problem: rejection sampling leaks time

Rejection sampling draws a **variable** number of random values. Most of the time you
accept on the first try; sometimes you reject and loop. How many times you loop
depends on the random bytes you happen to draw.

In our setting those bytes come from a seed, and the seed is a deterministic function
of the **plaintext**. So the number of loop iterations — and therefore the time the
shuffle takes — depends, weakly, on the secret being encrypted. That is a textbook
**timing side-channel**: secret-dependent control flow.

How exploitable is it, really? Honestly: not very. The variation is tens of
nanoseconds, buried in noise, smeared across many blocks, and an attacker would need an
enormous number of timed samples of chosen or known plaintexts to extract anything. We
are not aware of a practical attack.

But "we couldn't find an attack" is not the bar we hold cryptographic code to.
Constant-time execution — runtime independent of secret data — is a *discipline*, not a
cost-benefit calculation, precisely because timing channels have a long history of
going from "theoretically interesting" to "practically devastating" when someone finds
the right amplification. A shuffle whose duration depends on the plaintext violates the
discipline. So we fixed it — and the fix happened to make it dramatically faster too.

## The fix: wide draws and Lemire's multiply-high

Two ideas, both about *how you draw the random index*, neither touching the shuffle
itself.

**Idea 1 — draw wide.** Instead of a single byte, draw a full 64-bit value. The
irreducible bias from squeezing a power-of-two range into `n` buckets is always "at
most one bucket is one element bigger than the others." What matters is that ±1
*relative to the bucket size*:

- A byte (256 values) split into 63 buckets: 256 = 4·63 + 4, so 4 buckets are
  over-represented. Bias ≈ 4/256 ≈ **1.5%**. Significant.
- A 64-bit value split into 63 buckets: still ~63 buckets over-represented, but out of
  2⁶⁴. Bias ≈ 63/2⁶⁴ ≈ **2⁻⁵⁸**. A rounding error.

The wide draw doesn't remove the bias — it makes it so small that you no longer need
rejection sampling to hide it. That's the unlock: drop the retry loop, and the draw
count becomes **fixed**. No secret-dependent branches, no timing channel.

**Idea 2 — Lemire's multiply-high.** That still leaves *how* to map a 64-bit value `x`
into `0..=i` without a division (modulo is not only biased but also a variable-latency
instruction on many CPUs). Daniel Lemire's trick: treat `x` as a fraction of the way
through the 64-bit range and scale it into the target range with a single widening
multiply and a shift:

```rust
// uniform-ish index in [0, range), no division, no rejection
let j = ((x as u128 * range as u128) >> 64) as u64;
```

This is `floor(range · x / 2⁶⁴)` — it drops `x` into one of `range` near-equal buckets
using a multiply and a shift, both constant-latency. No loop, no `%`, no branch.

Put together: a fixed sequence of 63 wide draws, each reduced with a multiply-high,
replaces a variable-length loop of byte draws with rejection. The shuffle is identical;
only the randomness plumbing changed.

## The security argument: trading "exact" for "constant-time + provable"

Here's the part a cryptographer cares about. Rejection sampling gives you an *exactly*
uniform permutation. Our replacement gives you one that is uniform up to a **statistical
distance of about 2⁻⁵⁵** from perfectly uniform (we computed the exact bound by summing
the per-draw deviations; the power-of-two ranges contribute exactly zero).

Is giving up "exact" a loss? No — and this is the elegant part. The Lewi–Wu security
analysis already models each block's permutation as a **uniformly random permutation**
(realized via a PRF). Our construction instantiates exactly that object, up to a
2⁻⁵⁵ statistical term. So the change adds a single, tiny number to the existing
security bound — **no new assumption, no new idealized model, no round-count to argue
about.** A reviewer consumes it as one inequality.

We were tempted by a fancier option, and rejecting it is instructive.

## The road not taken: swap-or-not

For small domains there's a beautiful constant-time PRP called **swap-or-not**
(Hoang–Morris–Rogaway). It's branch-free by construction and vectorizes wonderfully —
on paper it's the "right" cryptographic object for an enciphering problem like ours. We
prototyped it at several round counts.

We rejected it, and not on speed (though our fixed-draw shuffle was actually faster).
We rejected it on the *proof*. The swap-or-not security bound is excellent when the
adversary can query only a small fraction of the domain. But in ORE, the right-hand
ciphertext of a block effectively exposes the **entire codebook** of that block's
permutation: a single ciphertext reveals an ordered constraint for every value, and
across encryptions sharing a prefix an adversary can reconstruct the whole table. So
the honest query budget is "the adversary sees all N points" — and at full codebook the
swap-or-not bound becomes *vacuous* for any practical number of rounds on a 64-element
domain. The known fix (the "sometimes-recurse" shuffle) reintroduces data-dependent
control flow — a timing channel — which defeats the entire reason we liked it.

So: a more sophisticated primitive, slower in practice, that we'd have had to ship on a
*heuristic* security argument. Versus a humble shuffle with fixed-count wide draws,
faster, with a one-line proof that plugs into the model we already use. The humble
option wins. (We kept the swap-or-not prototype around as a strictly-constant-time
fallback in case review ever rejects the cache-line argument for the shuffle's one
remaining secret-indexed memory access — but that's a story for another post.)

## The other finding: your hardware AES might be asleep

While benchmarking, we noticed our AES was running suspiciously slowly on Apple Silicon
and other ARM64 hardware. The cause: the Rust `aes` crate (v0.8) does **not**
automatically use the ARMv8 cryptography extensions. You have to opt in with a build
flag (`RUSTFLAGS="--cfg aes_armv8"`). Without it, you silently get a software AES
implementation that is roughly **60× slower per block** — and nothing warns you.

For a u64 encryption in `ore-rs`, just setting that flag took us from 381 µs to 39 µs —
a 9.7× speedup before we changed a single line of algorithm. If you ship cryptography
that runs on ARM servers (gravitons, Apple CI, etc.), check whether your AES is
actually hardware-accelerated. It's an easy and enormous win, and an easy and enormous
thing to miss.

## Results

Combining the hardware-AES fix, an allocation-free bulk encoding rewrite, SIMD
kernels, the new 6-bit block scheme, and the constant-time PRP, a `u64` encryption went
from **381 µs to 8.6 µs** on an M1 Max, with a further drop to a projected ~3.3 µs once
the PRP keystream is derived without a per-block key schedule (a change that rides along
with other work in flight). The PRP construction alone went from ~1.36 µs to 153 ns —
about **9× faster** — while *removing* a timing channel rather than adding risk.

## Responsible disclosure, internally

The rejection-sampling-as-timing-channel pattern is general. Once we'd named it, we went
looking — and found the same shape in a second CipherStash library, `vitaminc`, in its
bounded-random helper (which feeds both a permutation key generator and a password
generator). Same root cause; same fix. While there we also found that the helper's
power-of-two code path silently broke its own "inclusive range" contract — biasing the
permutation — and that the inclusive bound could drive a reachable out-of-bounds panic
in password generation. All three are resolved by the same move: a single fixed-count,
half-open, wide-draw helper. We've filed an issue and are fixing it.

## Takeaways

1. **Rejection sampling is a timing channel** whenever the rejection count depends on
   secret-derived randomness. If you draw bounded random integers anywhere near secret
   data, prefer a fixed-count method.
2. **Wide draws + Lemire multiply-high** give you fixed-count, branch-free, division-free
   bounded integers, biased only to ~2⁻⁵⁵ — negligible, and a clean statistical term in
   a security proof rather than a heuristic.
3. **"Exact uniform via rejection" is not automatically the safer choice.** For
   secret-dependent draws, "uniform-to-2⁻⁵⁵ in constant time" beats "exactly uniform in
   variable time."
4. **The most sophisticated primitive is not always the right one.** Swap-or-not is
   lovely; its proof doesn't fit our threat model, so the humble shuffle wins.
5. **Check that your AES is actually hardware AES.** A build flag can be worth 60×.

*The constant-time PRP and the wide-draw helper are in the `ore-rs` v2 work; the
`vitaminc` fix is tracked in its issue tracker. The cryptographic constructions
described here are under internal review before release.*
