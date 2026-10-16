# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `OreAes128Bit6Chained::init_with(key, Options)`: `Options` carries the string `Padding`
  policy (#110) and `max_bytes`, the longest string the cipher encrypts (default 1024
  bytes, `DEFAULT_MAX_STR_BYTES`). A longer string returns `OreError::TooLong`. Ciphertext
  size and encryption time grow with the padded length and the string is caller-supplied,
  so a ceiling bounds what one input can cost; it also bounds the number of length buckets
  a column can show. `init_with_padding` is replaced by `init_with`.

## [0.9.0-rc.1] - 2026-10-12

Pre-release for testing with external projects. The Bit6 (`scheme::bit2_w6`) and chained
wire formats are not frozen yet: do not store their ciphertexts until 0.9.0.

### Highlights

**New: `OreAes128Bit6` (`scheme::bit2_w6`), a 6-bit block scheme, recommended for new data.**

- **Smaller and faster.** Plaintexts are split into 6-bit blocks, so each block costs 64
  random-oracle evaluations instead of 256 and stores an 8-byte right block instead of 32.
  A `u64` ciphertext is 295 bytes (legacy: 408). Encrypting a `u64` measured 8.6 µs
  against 25.1 µs for the legacy scheme, both with hardware AES on an Apple M1 Max
  (`docs/benchmarks/2026-06-13-bit6-prp-results.md`).
- **Less leakage than the legacy scheme.** PRP seeds bind the block index and the block
  count, so a ciphertext no longer reveals its runs of zero bytes (for an integer, its
  order of magnitude). A comparison reveals the order and the first differing 6-bit block.
- **Key separation.** PRF keys are derived from the caller's keys under scheme-specific
  labels, so using the same keys for both schemes can't expose Bit6 masking keys
  through legacy ciphertexts.
- **v2 wire format.** A 4-byte header carries the format version, scheme id and block
  count. Parsers and the raw comparator reject bad headers, lengths and out-of-domain
  symbols instead of panicking.
- **Side-channel hardening.** The permutation is built with no secret-dependent memory
  addresses, table reads and the comparator are constant-time scans, and the stack an
  encryption used is zeroed afterwards so PRP seeds and tables don't linger in memory.
- **Coverage.** `bool`, integers up to 64 bits, `char`, `f32` and `f64` (at most 14
  blocks). `Decimal` stays on `OreAes128`. `u128`/`i128` are supported by neither scheme
  (#105).

**New: chained-prefix scheme (`scheme::chained`) for variable-length data and strings.**
Per-block secrets come from a CMAC accumulator over the prefix, so plaintexts aren't
limited to 14 blocks. Every ciphertext reveals the exact plaintext length; padding is
tracked in #104.

**Legacy `OreAes128`.** Ciphertexts are byte-for-byte unchanged (pinned by compatibility
vectors). Encryption is much faster (hardware AES on aarch64 and bulk encoding: a `u64`
went from 381 µs to 25.1 µs in the same benchmarks), the comparator is hardened, and
malformed input is refused. The README now documents the scheme's zero-run leakage.

**Hardware AES on ARM.** On aarch64, including Apple Silicon, the `aes` crate uses
hardware AES only when built with `--cfg aes_armv8`. Downstream projects must set it in
their own build configuration (see the README); without it, AES falls back to software
and is far slower.

### Benchmarks

- black-box every result and input, and record the effect
- criterion bench for the Bit6 PRP builder alone

### CI

- make the default harness set fit CI; time-limit the job

### Documentation

- document the legacy zero-run seed leakage
- restate A1 on a correct exposure model; correct A4's read paths
- correct the CMAC spec, and recommend Bit6 for new data
- u128/i128 fit neither scheme; stop recommending OreAes128 for them
- every ciphertext reveals the exact plaintext length

### Features

- 6-bit block width scheme (OreAes128Bit6) with v2 wire format
- CMAC accumulator primitive + LemireFyPrp::from_stream (PR 6 foundation)
- chained-prefix variable-length scheme + string encryption (PR 6)

### Fixes

- derive scheme-separated PRF keys and bind the block index
- refuse malformed lengths in the legacy raw comparator
- refuse oversized raw symbols before scanning them

### Miscellaneous

- update the detached lockfiles to orderable-bytes 0.2

### Performance

- bulk unary encoding, allocation-free encrypt path, hardware AES on aarch64
- NEON and AVX2 kernels for indicator and hash-bit masks
- Bit6 PRP via fixed-draw Fisher-Yates (closes timing channel)
- vectorize GF(2^128) doubling in the sigma-MMO hash

### Refactoring

- width abstraction, seed/tag separation, template RO keys
- derive BlockWidth::DOMAIN from BITS
- address #80 self-review (shared bit-packer, drop dead code)
- from_stream delegates to one from_stream_with
- reuse lemire_draw and the reference builder in the isolation hooks

### Testing

- pin compatibility vectors and bench baseline for ORE v2 refactor
- name the generator's real output path
- pin cross-nonce comparison fixtures
- pin v2 Bit6 wire-format vectors
- pin cross-nonce comparison fixtures
- property tests for ORE comparator, left/full consistency, and CMAC accumulator
- pin wire-format vectors
- libFuzzer targets for the ciphertext parsers and comparators
- dudect timing benches for the comparators and encryptors
- kani harnesses for the pure building blocks
- run the two exhaustive-length Kani harnesses only with kani-full
- prove order preservation across different lengths
- round-trip Right::from_slice for Bit6 and legacy
- prove lemire_draw itself; test every swap of the shipped builders on their targets

### Ct-taint

- refuse a vacuous pass; cover more types and the raw entry points

### Fuzz

- check that the raw comparator and the typed Ord agree

### Harden

- assert gather length; precise dispatch cfg (#81 self-review)
- real length asserts; set_bit assigns
- count=0 guard, shared encoder, ct bit-extract, opaque Debug (#82 review)
- restore the #81 review hardening that #82 overwrote
- build the Bit6 permutation with no secret-dependent address
- reject out-of-domain symbols; assert the 64-lane mask length
- read permute/invert tables obliviously; latch the comparator's block
- scrub the stack after each encryption
- size the scrub by optimisation level, not debug_assertions
- zeroize L/ro, Branch enum, count guard, single-key init, left-query comparator (#83 review)
- encrypt the mixed state in place in absorb and finalize
- oblivious tag and bit reads, string length guard, symbol checks; correct at-rest leakage docs
- scrub the stack after each encryption; wipe the decomposed string
- latch first differing block in legacy and Bit6 typed comparators; accept zero-block legacy input
- zeroize the latched first-difference copies
- typed in-domain Symbol; infallible permute; drop taint suppressions

### Ore

- harden PRP/comparator constant-time, add N<=64 guard
- resolve A1 — adopt BHKR sigma-MMO for the 1-bit hash H

### Style

- rustfmt
- rustfmt the orderable-bytes 0.2 port

## [0.8.4] and earlier

Entries for 0.4.0 to 0.8.4, which were released without per-version headings.

### Documentation

- refresh crates.io/docs.rs-facing docs and crate metadata
- fix 'initalize' typo in crate-level rustdoc

### Fixes

- zeroize Aes128Prng keystream on drop (ZA-0001)

### Miscellaneous

- release

### Refactoring

- read block lengths through FixedOrderableBytes
- import OrderableBytes and derive the bench's block length

### Testing

- make ZeroizeOnDrop marker check compile-time

### Harden

- make the ZA-0001 wipe guarantee self-enforcing


### Features

- impl OreEncrypt for all primitives via ToOrderableBytes

### Miscellaneous

- release

### Refactoring

- introduce ToOrderableBytes trait
- drop dead convert module


### Features

- impl OreEncrypt for all primitives via ToOrderableBytes

### Refactoring

- introduce ToOrderableBytes trait
- drop dead convert module


### Build

- bump rand from 0.8.5 to 0.8.6


### Benchmarks

- add criterion suite for Decimal ORE encryption
- add criterion suite for chrono types

### Documentation

- add rustdoc for all public items; deny missing_docs

### Miscellaneous

- clear pre-existing build warnings in ore-rs
- move hex-literal to dev-deps; add James to authors

### Refactoring

- convert to workspace; extract pre-encoders into ore-encoders crate
- move chrono pre-encoders into ore-encoders crate
- rename ore-encoders → orderable-bytes; pre_encode → to_orderable_bytes

## [0.3.0]

* ORE Ciphers no longer need to be mutable!
* Defined OreAes128 to be generic on Rng
* OREAES128 implementation now uses ChaCha20Rng

## [0.2.0]

### Added

* Copy and Clone trait implementations for CipherText, Left and Right types
* Added encrypt trait for f64 type
* Added `compare_raw_slices` function

## [0.1.0]

First public release!

### Added

* Basic encryption and comparison
* OREAES128 scheme implementation
* Encryption Trait implementations for u32 and u64
* Serialization to and from Vec<u8>
* Basic documentation
