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

`OreEncrypt` is implemented for `bool`, integers up to 64 bits (`u8`–`u64`, `i8`–`i64`), `char`, `f32`, and `f64` on both `OreAes128` and `OreAes128Bit6`. `u128` and `i128` are implemented on the chained scheme only (`OreAes128Bit6Chained`, `scheme::chained`): at 16 bytes they exceed both the 15-byte limit of `OreAes128` and the 14-block packed prefix of `OreAes128Bit6`, and the chained scheme's CMAC accumulator has no length cap. Their ciphertexts are `ChainedCipherText<22>` / `ChainedLeft<22>`, which pin the block count: the typed parsers and comparators refuse a ciphertext of another length. That is a length guard, not a type guard; a 16-byte string or an `i128` is 22 blocks too, and under one key equal encodings (`0u128`, `i128::MIN`) encrypt identically, so use one key per kind of value. Two optional features extend this via the sibling [`orderable-bytes`](https://crates.io/crates/orderable-bytes) crate:

- `chrono` — ORE support for `chrono::NaiveDate` and `chrono::DateTime<Utc>`
- `decimal` — ORE support for `rust_decimal::Decimal`

## Keys

The v2 schemes (`OreAes128Bit6`, `OreAes128Bit6Chained`) take **one 16-byte key** and an optional **salt**: `init(key)` or `init_with_salt(key, salt)`; on the chained scheme the salt is also an `Options` field (`Options::with_salt`), beside the padding policy and the ceiling, for `init_with(key, options)`. The salt is any byte string naming what the key is for, such as a data set or a tenant. Ciphertexts under different salts share no key material, but nothing on the wire records the salt, so a comparison across salts returns a confident, meaningless result. That includes `Equal`: two empty values (zero blocks) compare `Equal` under any salts, so no comparison result can confirm that two salts match. Keep the salt with the data's identity, as you keep the key. Use one key or salt per kind of value: under one key and salt, values of different types whose order-preserving encodings coincide (`0u64` and `i64::MIN`, say) encrypt to the same bytes. The legacy `OreAes128` keeps its frozen two-key `init(k1, k2)`.

## Use from vitaminc

The `vitaminc` feature implements [`vitaminc-ore`](https://docs.rs/vitaminc-ore)'s
`OrderScheme` for three schemes, so a vitaminc order index can encrypt
the sealed order plaintexts it builds here. `vitaminc::Bit6BlockOre` is
the ORE v2 fixed-width six-bit scheme (`OreAes128Bit6`) at each kind's
own width, up to ten bytes, the one to prefer for new fixed-width data;
`vitaminc::ChainedBlockOre` is the chained, variable-length scheme, which
takes every kind, text and bytes included, and is not yet frozen;
`vitaminc::BlockOre` is the legacy eight-bit scheme (`OreAes128`) up to
15 bytes. None of them takes a salt, so each derives its keys per term
with HMAC-SHA256 under the salt vitaminc binds (scheme, domain and the
caller's context). The feature is off by default, changes nothing in the
typed API above, and needs Rust 1.88. This is a trial against vitaminc's
`feat/ore-crate` branch; it moves to the published release when that
lands.

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

## Security

The underlying scheme (Lewi-Wu Block-ORE) has been well studied, but this implementation has not had a public third-party audit. Evaluate it against your own threat model before using it in production.

### Known leakage of `OreAes128`

Beyond the order and the first differing block of a compared pair, an `OreAes128` ciphertext shows its runs of zero bytes. The PRP seed for block `n` is derived from the bytes before it, padded with zeros, and binds neither the block index nor the block count. Blocks inside a run of zero bytes therefore share a permutation and encrypt to the same value. One ciphertext (a Left alone is enough) gives away:

* the number of leading zero bytes of an integer, which is its order of magnitude, as the same value in every ciphertext under a key;
* other runs of zero bytes, such as the trailing zero mantissa bytes of a round float.

The wire format of `OreAes128` is frozen, so this cannot change for existing data. For new data, use `OreAes128Bit6` (`scheme::bit2_w6`, ORE v2), which binds the block index and the block count into its seeds. It covers types up to 64 bits; `Decimal` stays on `OreAes128` for now. `u128` and `i128` use the chained scheme (see [Supported plaintext types](#supported-plaintext-types)). See "Known leakage of the legacy scheme" in [the v2 plan](https://github.com/cipherstash/ore.rs/blob/main/docs/plans/2026-06-12-ore-v2-architecture.md).

To report a security issue, see [SECURITY.md](https://github.com/cipherstash/ore.rs/blob/main/SECURITY.md) or email security@cipherstash.com.

## License

ore.rs is available under the CipherStash Client Library Licence Agreement.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, shall be licensed as above, without any additional terms or conditions.
