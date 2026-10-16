# ore-rs

Part of the [ore.rs](https://github.com/cipherstash/ore.rs) workspace _(pronounced "auras")_, alongside [`orderable-bytes`](https://crates.io/crates/orderable-bytes).

[![Test](https://github.com/cipherstash/ore.rs/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/ore.rs/actions/workflows/test.yml)

This is an Order Revealing Encryption (ORE) library written in Rust and based on the Block-ORE Encryption scheme
developed by [Lewi-Wu in 2016](https://eprint.iacr.org/2016/612.pdf).

It makes the following improvements on the original scheme:

* Use of a Knuth (Fisher-Yates) Shuffle for the PRP (instead of a Feistel Network which was found to be insecure for small domains (see [Bogatov et al](https://eprint.iacr.org/2018/953.pdf))
* Exclusive use of AES as a Random Oracle
* Pipeline optimisations, for higher throughput
* Hardware AES acceleration on `x86_64` and ARM (via the [`aes`](https://crates.io/crates/aes) crate's runtime detection, on stable Rust)
* Inclusion of the block number in the left-tag (PRF₁) input, to avoid repeated tags. The PRP seed input does not include it: see [Known leakage](#known-leakage-of-oreaes128)

## Usage Documentation

Reference documentation is on [docs.rs/ore-rs](https://docs.rs/ore-rs).

## Supported plaintext types

`OreEncrypt` is implemented for `bool`, all integer widths (`u8`–`u128`, `i8`–`i128`), `char`, `f32`, and `f64`. `u128` and `i128` cannot be encrypted yet: `OreAes128` takes at most 15 bytes (its left-tag input puts the block index at byte `N` of one AES block), so encrypting a 16-byte value panics, and `OreAes128Bit6` covers types up to 64 bits. Two optional features extend this via the sibling [`orderable-bytes`](https://crates.io/crates/orderable-bytes) crate:

- `chrono` — ORE support for `chrono::NaiveDate` and `chrono::DateTime<Utc>`
- `decimal` — ORE support for `rust_decimal::Decimal`

## Need help?

Please [open an issue](https://github.com/cipherstash/ore.rs/issues) and we'll get back to you.

## Build, Test and Bench

To build, run:

```
cargo build
```

To test, run:

```
cargo test
```

To run the benchmarks, run:

```
cargo bench
```

Example benchmark results below (from December 2021):

![Benchmark](https://user-images.githubusercontent.com/12306/145158987-9846bd94-24c7-4163-b655-1cb3ad686dd9.png)

## ARMv8 and Apple Silicon support

ARMv8 and Apple Silicon Macs work out of the box but will default to AES in
software, which is dramatically slower than the hardware backend (~60x per
AES block on an M1 Max). To use the ARMv8 Cryptography Extensions, enable
the `aes` crate's cfg flag — stable Rust is fine (1.61+):

```toml
# .cargo/config.toml in your project
[target.'cfg(target_arch = "aarch64")']
rustflags = ["--cfg", "aes_armv8"]
```

This repository's own workspace sets this already (tests, benches and
examples get hardware AES); the flag is per-final-binary, so downstream
projects need it in their own build configuration. x86_64 AES-NI is
auto-detected and needs no flag.

A `RUSTFLAGS` environment variable (common in CI, Docker and dev shells)
replaces the `rustflags` in `.cargo/config.toml`, so the flag can disappear
without any error. To catch that, assert `ore_rs::hardware_aes()` at
startup or in a test: it returns `true` only when the build will use
hardware AES on the current CPU.

`aes` 0.9 removes the need for this flag, but 0.9.3, the current release,
is 2–2.5x slower per AES call on aarch64 than 0.8 with the flag, so ore-rs
stays on 0.8 for now. See `docs/benchmarks/2026-10-13-aes-0.9-root-cause.md`.

## Security

The underlying scheme (Lewi-Wu Block-ORE) has been well studied, but this implementation has not had a public third-party audit. Evaluate it against your own threat model before using it in production.

### Known leakage of `OreAes128`

Beyond the order and the first differing block of a compared pair, an `OreAes128` ciphertext shows its runs of zero bytes. The PRP seed for block `n` is derived from the bytes before it, padded with zeros, and binds neither the block index nor the block count. Blocks inside a run of zero bytes therefore share a permutation and encrypt to the same value. One ciphertext (a Left alone is enough) gives away:

* the number of leading zero bytes of an integer, which is its order of magnitude, as the same value in every ciphertext under a key;
* other runs of zero bytes, such as the trailing zero mantissa bytes of a round float.

The wire format of `OreAes128` is frozen, so this cannot change for existing data. For new data, use `OreAes128Bit6` (`scheme::bit2_w6`, ORE v2), which binds the block index and the block count into its seeds. It covers types up to 64 bits; `Decimal` stays on `OreAes128` for now. `u128` and `i128` are supported by neither scheme (see [Supported plaintext types](#supported-plaintext-types)). See "Known leakage of the legacy scheme" in [the v2 plan](https://github.com/cipherstash/ore.rs/blob/main/docs/plans/2026-06-12-ore-v2-architecture.md).

To report a security issue, see [SECURITY.md](https://github.com/cipherstash/ore.rs/blob/main/SECURITY.md) or email security@cipherstash.com.

## License

ore.rs is available under the CipherStash Client Library Licence Agreement.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, shall be licensed as above, without any additional terms or conditions.
