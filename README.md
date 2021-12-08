# ORE

This is an Order Revealing Encryption (ORE) library written in Rust and based on the BlockORE Encryption scheme
developed by [Lewi-Wu in 2016](https://eprint.iacr.org/2016/612.pdf).

It makes the following improvements on the original scheme:

* Use of a Knuth (Fisher-Yates) Shuffle for the PRP (instead of a Feistel Network which was found to be insecure for
  small domains, see [Bogatov et al](https://eprint.iacr.org/2018/953.pdf)
* Exclusive use of AES as a Random Oracle
* Pipeline optimisations for higher throughput
* Both SIMD and Neon intrinsic support for `X86_64` and `ARM`
* Inclusion of the block number in block prefixes to avoid repeated prefixes

## Usage Documentation

Full documentation is available via [docs.rs](https://docs.rs/ore-rs).

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

ARMv8 and M1 Macs work out of the box but will default to AES in software which is around 4x slower than AES-NI
(at least on the test machine using an Intel i7 8700K).

To take advantage of hardware AES using NEON Intrinsics on ARM, you need to use Rust nightly.

```
asdf install rust nightly
asdf local rust nightly
cargo +nightly bench
```

## TODO

- Constant time analysis to ensure that encryption or comparison time does not vary with input size
- Zeroing and careful cleaning up of memory where appropriate
- Support longer AES keys for the PRF and hash (if possible)
- Get rid of GenericArray and replace with const generics (blocked by support in the AES crate)
