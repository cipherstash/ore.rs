<!-- Draft for the CipherStash research blog. Written to .claude/skills/blog-writing-voice
     (Dan Draper profile) from cipherstash-js-suite@main. Meta description (153 chars):
     "I set out to make our order-revealing encryption faster and found it leaking timing
      from a random shuffle. The fix was constant-time and 9x faster." -->

# The shuffle that told the time

Years ago I wrote a little function to shuffle 64 numbers into a secret order. It was part of the first real Rust I ever shipped, the order-revealing encryption that lets CipherStash compare encrypted values without decrypting them. I was proud of it. It was textbook correct.

Last week I set out to make it faster, and discovered it had been quietly telling anyone who cared to measure roughly how long it took to encrypt your data. Which, it turns out, is a function of your data.

This is the story of that bug, the surprisingly elegant fix, and a second surprise that was costing us 60x on half our hardware. There's a moral at the end about reading your own old code.

## The secret reshuffle at the heart of ORE

Quick orientation, then we'll get to the crime scene.

Order-revealing encryption lets you ask "is A less than B?" on ciphertexts, without ever holding the plaintext. We use the Lewi-Wu construction. It chops a value into small blocks and, for each block, scrambles its possible values into a secret keyed order. That scramble is a pseudo-random permutation, a PRP, and we build it with a Fisher-Yates shuffle. It's the same shuffle Knuth taught a generation of us: walk down the array, and at each spot `i` pick a random index `j` somewhere at or below it, then swap.

So the whole edifice rests on one humble operation. Pick a uniform random number in a range. That's where the leak was hiding.

## ...wait, what's wrong with picking a random number?

Your randomness arrives as uniform *bits*. A byte is a number from 0 to 255. But the range you want, say 0 to 62, almost never divides 256 evenly, so if you just take `byte % 63` some answers come up slightly more often than others. That skew is called modulo bias, and for a permutation it's poison. It makes some orderings more likely than others, and a secret shuffle that prefers certain orders isn't very secret.

The proper fix, the one every textbook teaches, is rejection sampling. Draw a byte. If it landed in the biased tail, throw it away and draw another. Keep going until you get a clean one. It's correct, it's unbiased, and I used it without a second thought.

The counterintuitive part kept me up at night. Rejection sampling, the proper unbiased method, was the bug.

## What the timing whispered

Think about what "keep going until you get a clean one" actually does. It draws a *variable* number of times. Sometimes one draw, sometimes five, depending entirely on the random bytes it happens to see.

And where do those bytes come from? A seed. And the seed is derived from the plaintext you're encrypting.

Follow the thread. The number of loops depends on the bytes, the bytes depend on the seed, the seed depends on your data. So the *time* the shuffle takes depends, faintly, on the secret it's meant to protect. That is the textbook definition of a timing side-channel: secret data steering how long the code runs.

How exploitable is it really? Barely. The wobble is tens of nanoseconds, smeared across many blocks and buried in noise, and I know of no practical attack against it. But "I couldn't break it" is not the bar. Constant-time execution is a discipline you keep precisely because timing leaks have a long history of looking harmless right up until someone finds the lever. A shuffle whose duration tracks the plaintext breaks that discipline. So it had to go.

The lovely thing is that closing the channel also made it nearly nine times faster.

## Drawing dice from a firehose

The fix is two ideas, and neither one touches the shuffle. They change only how it draws a number.

**First, draw wide.** Instead of a single byte, take a full 64-bit value. The leftover bias from squeezing a power-of-two range into 63 buckets is always at most "one bucket is one item bigger than the rest". What matters is how big that one item is *relative* to the bucket:

- A byte into 63 buckets: about a 1.5% lean toward some values.
- A 64-bit value into 63 buckets: about a 2⁻⁵⁸ lean. A rounding error.

The wide draw doesn't erase the bias. It shrinks it until it's too small to bother hiding, which means you can throw away the rejection loop entirely. No loop, no variable timing.

**Second, reduce with a multiply, not a modulo.** Daniel Lemire's trick maps a 64-bit `x` into a range with one widening multiply and a shift. Picture `x` as how far along the number line you landed, then scale that fraction up into your range:

```rust
// uniform in [0, range): no loop, no modulo, no branch
let j = ((x as u128 * range as u128) >> 64) as u64;
```

Put together, a fixed run of wide draws each reduced by a multiply replaces a ragged loop of byte draws and retries. Same shuffle. Fixed timing. Faster.

```rust
// Before: the number of iterations depends on the seed, which depends on the plaintext
let mut v = rng.next_u32() % cap;
while v > max { v = rng.next_u32() % cap; }

// After: exactly one draw, every time, whatever the data
let j = ((rng.next_u64() as u128 * (i as u128 + 1)) >> 64) as usize;
```

## Giving up "perfect" to gain "constant"

A cryptographer reading this just flinched. Rejection sampling gives you an *exactly* uniform shuffle. My version is only uniform to within about 2⁻⁵⁵ of perfect. Did I just trade away rigor for speed?

No, and this is the part I find genuinely satisfying. The Lewi-Wu security proof already models each block's permutation as a uniformly random one. My shuffle *is* that object, give or take 2⁻⁵⁵. So the change adds a single tiny number to a bound that was already there. No new assumption, no new model, nothing to argue about in review. For a draw that touches secret data, "uniform to 2⁻⁵⁵ in constant time" is a better thing to own than "exactly uniform, in variable time".

## The fancy option I threw away

I'll admit I wanted to use something cleverer. There's a beautiful constant-time PRP for small domains called swap-or-not. It vectorizes like a dream and looks like the *proper* cryptographic answer. I built it.

Then I read its security proof more carefully and threw it away. Swap-or-not is strong only when an attacker can see a small slice of the value space. But in ORE a block's ciphertext effectively hands over the *whole* permutation, so the honest assumption is that the attacker sees everything, and at that point the proof gives you nothing on a 64-element domain at any practical setting. The known patch reintroduces data-dependent branching, the very timing channel I was trying to kill. A humble shuffle with a one-line proof beat the elegant primitive with a vacuous one. There's a lesson in that I keep relearning.

## Your AES might be asleep

While I had the profiler open, a second thing nagged at me. AES was crawling on Apple Silicon and our ARM servers.

The cause was almost insulting in its simplicity. The Rust `aes` crate doesn't switch on the ARMv8 hardware crypto instructions unless you ask, with a build flag. Leave it off, and you silently get a software fallback that runs about 60x slower per block, with nothing to warn you. Setting one flag took a `u64` encryption from 381µs to 39µs, before I'd improved a single line of algorithm. If you ship crypto onto ARM, go and check this today. It's the cheapest 60x you'll ever find. 🎉

## Where it landed

Stack it all up, the hardware AES, an allocation-free rewrite, SIMD, and the constant-time shuffle, and a `u64` encryption went from 381µs to 8.6µs on an M1 Max. The shuffle alone dropped from roughly 1.36µs to 153ns, about nine times quicker, while *losing* a side-channel rather than gaining a risk.

## Then I went looking in our own house

Once you've named a pattern you start seeing it everywhere. So I went hunting through our other Rust crates, and found the same rejection-sampling shape in vitaminc, our cryptography toolkit, feeding both a permutation generator and a password generator. Same root cause. The audit turned up two more bugs riding alongside it for free, including a draw that could index one past the end of an array and panic. Same fix closes all of it, and it's filed.

That's the bit I'd underline. The original shuffle was correct by the textbook, written by someone (me) who cared, and it still carried a quiet flaw for years. Speeding it up was the accident that made me look closely enough to see it. Performance work and security work are far more often the same work than we pretend, and the code most worth re-reading with fresh eyes is usually your own.

*Go back and read the thing you were proud of. It has more to teach you than you think.*

:wq
