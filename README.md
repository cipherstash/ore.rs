# ore.rs

_(pronounced "auras")_

[![Test](https://github.com/cipherstash/ore.rs/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/ore.rs/actions/workflows/test.yml)

A Rust workspace providing Order-Revealing Encryption (ORE) primitives used in the [CipherStash](https://cipherstash.com) searchable encryption platform.

## Crates

| Crate | Description |
|-------|-------------|
| [`ore-rs`](packages/ore-rs) | Block-ORE encryption library based on the [Lewi-Wu 2016](https://eprint.iacr.org/2016/612.pdf) scheme |
| [`orderable-bytes`](packages/orderable-bytes) | Canonical, order-preserving byte encodings for plaintext types — feeds into ORE/OPE schemes |

See each crate's README for usage, supported types, and feature flags.

## Build & Test

```
cargo build
cargo test
```

## Security

Please review our [security policy](SECURITY.md) before reporting vulnerabilities.

## License

Copyright &copy; 2024-2026 CipherStash, Inc. All rights reserved.

Use of this software is governed by the [CipherStash Client Library Licence Agreement](LICENCE).
