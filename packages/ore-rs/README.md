# ore.rs

_(pronounced "auras")_

[![Test](https://github.com/cipherstash/ore.rs/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/ore.rs/actions/workflows/test.yml)

This is an Order Revealing Encryption (ORE) library written in Rust and based on the Block-ORE Encryption scheme
developed by [Lewi-Wu in 2016](https://eprint.iacr.org/2016/612.pdf).

It makes the following improvements on the original scheme:

* Use of a Knuth (Fisher-Yates) Shuffle for the PRP (instead of a Feistel Network which was found to be insecure for small domains (see [Bogatov et al](https://eprint.iacr.org/2018/953.pdf))
* Exclusive use of AES as a Random Oracle
* Pipeline optimisations, for higher throughput
* Both SIMD and Neon intrinsic support for `x86_64` and `ARM`
* Inclusion of the block number in block prefixes, to avoid repeated prefixes

## Usage Documentation

Reference documentation is on [docs.rs/ore-rs](https://docs.rs/ore-rs).

## Need help?

Head over to our [support forum](https://discuss.cipherstash.com/), and we'll get back to you super quick! 

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

Example benchmark results below:

![Benchmark](https://user-images.githubusercontent.com/12306/145158987-9846bd94-24c7-4163-b655-1cb3ad686dd9.png)

## ARMv8 and M1 Support

ARMv8 and M1 Macs work out of the box but will default to AES in software which is around 4x slower than AES-NI (at least on the test machine using an Intel i7 8700K).

To take advantage of hardware AES using NEON Intrinsics on ARM, you need to use Rust nightly.

```
asdf install rust nightly
asdf local rust nightly
cargo +nightly bench
```

## Security Warning

This package is a pre-1.0 release and has not yet had significant scrutiny (although ORE generally has been quite well studied).
We are planning to have a 3rd party audit performed prior to the release of 1.0.

In the mean-time: Use at your own risk!

## 1.0 Roadmap

- External Audit
- Simpler ciphertext internals (which should improve performance)
- Further constant time improvements
- Additional block sizes
- Trinary indicator function support (avoids needing to store left-ciphertexts)

## License

ore.rs is available under the CipherStash Client Library Licence Agreement.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, shall be licensed as above, without any additional terms or conditions.
