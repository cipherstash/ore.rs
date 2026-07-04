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
* Inclusion of the block number in block prefixes, to avoid repeated prefixes

## Usage Documentation

Reference documentation is on [docs.rs/ore-rs](https://docs.rs/ore-rs).

## Supported plaintext types

`OreEncrypt` is implemented for `bool`, all integer widths (`u8`–`u128`, `i8`–`i128`), `char`, `f32`, and `f64`. Two optional features extend this via the sibling [`orderable-bytes`](https://crates.io/crates/orderable-bytes) crate:

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

Hardware AES is provided by the [`aes`](https://crates.io/crates/aes) crate, which uses runtime CPU-feature detection on both `x86_64` (AES-NI) and ARMv8 (NEON AES intrinsics) — on stable Rust, with no special configuration required.

## Security

The underlying scheme (Lewi-Wu Block-ORE) has been well studied, but this implementation has not had a public third-party audit. Evaluate it against your own threat model before using it in production.

To report a security issue, see [SECURITY.md](https://github.com/cipherstash/ore.rs/blob/main/SECURITY.md) or email security@cipherstash.com.

## License

ore.rs is available under the CipherStash Client Library Licence Agreement.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, shall be licensed as above, without any additional terms or conditions.
