# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`ClwwOre` and `ClwwOpe`, vitaminc order schemes.** Both implement vitaminc-ore 0.8's
  `OrderScheme`, `OrderQuery` (a CLWW term is its own query, `Query = Term`), `OrderKeyInit`
  (from a protected 32-byte key, or bytes of runtime length with a `KeyLengthError` for any
  other length) and `Supports` for every target. The space's salt,
  `PAE("vitaminc/ore/v1", NAME, domain, context)`, is the CLWW salt, and the names are
  `clww-ore` and `clww-ope`. `compare` refuses bytes no term has, and ORE pairs whose first
  difference is not ±1. Ported from cipherstash-suite#2316, which was written against
  vitaminc 0.6 behind a `vitaminc` feature (published as `cllw-ore` 0.5.2-rc.1). Here
  vitaminc is a dependency, as it is for ore-rs 0.10, the names follow the crate's, and the
  marker byte that suite PR put before text and bytes is gone, since vitaminc 0.7 seals them
  behind its own.

### Security

- **ORE and OPE draw from separate keystreams.** Up to 0.5 the ORE and OPE terms of one
  value under one key and salt were built on one keystream. Their byte-wise difference is 0
  or 1 where a plaintext bit is 0 and 127 or 128 where it is 1, so anyone holding both terms
  of a value could read the value off them without the key. Each scheme now opens the keyed
  PRF with a tag of its own (`clww-ore/ore/v1` or `clww-ore/ope/v1`, NUL-padded to sixteen
  bytes), so the two keystreams are independent. Nothing for the caller to choose: every
  encrypt path takes its scheme's tag.
- **Salts are length-prefixed.** The salt went into the PRF as it is, directly ahead of the
  plaintext bits, so the keystream for salt `s` after a first bit `b` was the keystream for
  salt `s ‖ b`, and terms under the two salts were linked. The salt now goes in behind its
  length as a big-endian `u64`. No salt and an empty salt remain the same domain.
- **Every ciphertext changes.** ORE and OPE terms written by `cllw-ore` 0.5 or earlier do not
  compare with terms of this release: re-encrypt them. The known-answer digests
  were recorded again, and `keystream_separation` runs both attacks against the old
  construction, where they succeed, and against this one, where they fail.

### Removed

- **The typed API.** vitaminc is the only way in, as it is for ore-rs 0.10: it encodes every
  value as its space's target and seals the bytes, and `ClwwOre` and `ClwwOpe` encrypt
  them. Gone: the `ClwwOreEncrypt` and `ClwwOpeEncrypt` traits and every impl of them
  (integers, `bool`, floats, `&str`, `String`, `&[u8]`, byte arrays), `Key::encrypt` and
  `Key::encrypt_ope`, the fixed-width terms `OreClww8V1<N>` and `OpeClww8V1<N>`,
  `orderize_string`, and the `chrono` and `decimal` features with the `orderable-bytes`,
  `chrono`, `rust_decimal` and `unicode-normalization` dependencies. `Key` is
  crate-private: a scheme is keyed from a `Protected<[u8; 32]>`. Every term is an
  `OreClww8VariableV1` or an `OpeClww8VariableV1`, and the bytes of a plaintext encrypt
  as they did: an unsigned integer's term is its big-endian bytes' term, and the
  known-answer digests of those and of byte slices still hold. Other types now take
  vitaminc's encodings, so their terms differ from the typed ones (strings were folded by
  `orderize_string`, now by vitaminc's `Text`).
- **`encrypt_ore_bits` and `encrypt_ope_bits` are crate-private.** They took any bit
  stream, so a caller could encrypt bytes that skipped the encoding.
- **Unchecked term constructors.** `from_bytes_unchecked` is crate-private, and `from_hex`
  checks the length as `from_bytes` and `TryFrom` do (an ORE term is a multiple of 8
  bytes, an OPE term `8n + 1`). Both were open for tagged bit streams, which no public
  path makes now.
- **Decryption.** `Key::decrypt`, the `ClwwOreDecrypt` trait (for `OreClww8V1` and
  `OreClww8VariableV1`) and `OreClww8VariableV1::decrypt_to_bytes` are gone, so the
  crate has no decryption API. The key is still a decryption key: whoever holds it can
  recompute the keystream and read any term's plaintext, so protect it as one. An order term is an index term, not a store of the value: a
  decrypt path made the order key a decryption key for every term, and with no
  authenticity check a corrupted or forged term decrypted to a wrong plaintext without
  error. A caller that needs the plaintext back stores it under an authenticated cipher
  such as AES-GCM alongside the term, as OPE callers already had to. No ciphertext
  changes.

### Changed

- **Renamed from `cllw-ore` to `clww-ore`**, the authors' initials as they are (Chenette,
  Lewi, Weis and Wu), and moved from cipherstash-suite to the ore.rs workspace with its
  history. The version starts at 0.6.0. The term types that remain follow:
  `OreCllw8VariableV1` and `OpeCllw8VariableV1` are `OreClww8VariableV1` and
  `OpeClww8VariableV1`.
- **No SQL or Postgres type changes.** The rename changes no key derivation or encoding.
  The SQL objects in `install.sql` and `uninstall.sql` and the Postgres type names
  the `postgres-types` feature maps to (`ore_cllw_8_v1`, `ore_cllw_8_variable_v1`,
  `ore_cllw_8_ope_v1`, `ore_cllw_8_ope_variable_v1`) keep their spelling: they are
  installed in databases and named by EQL, so renaming them would break every
  installation.
- **`postgres-types` is off by default.** A caller that binds terms as Postgres
  parameters turns it on. The e2e SQL tests declare
  `required-features = ["postgres-types"]`, and CI runs them against Postgres.
- **MSRV 1.88**, vitaminc's floor, declared in `Cargo.toml`.
- **The PRF state and plaintext bits are wiped.** The keyed BLAKE3 hasher, each keystream
  block, and the OPE encryption's copy of the plaintext bits and its keystream before the
  carry pass are zeroized on drop (blake3's `zeroize` feature is on). Both buffers grow by
  moving to a new one and wiping the old, so no buffer they outgrow is freed with its
  contents. This changes no ciphertext: the known-answer digests, recorded from 0.5.1,
  held through it.

## Up to 0.4.2

release-plz wrote the sections below without a version heading. All of them shipped by
0.4.2.

### Documentation

- correct OPE correctness claim; add empirical error-rate test
- add backward-carry OPE engineering note
- rewrite engineering note around exact OPE
- correct scheme name from CLLW to CLWW

### Features

- add OPE variant of CLWW order-revealing encryption
- MSB-bit placement → exact OPE
- add OPE support for `Decimal` behind `decimal` feature
- add OPE support for `chrono` types behind `chrono` feature
- add OPE support for `serde_json::Value` scalars behind `serde_json` feature
- ✨ add ORE and OPE encryption for signed integers, bool, f32, f64

### Fixes

- make variable-length OPE ordering exact
- make numeric OPE ordering exact
- allow println in ignored empirical error-rate test

### Refactoring

- colocate OPE impls with their plaintext-type modules
- simplify OPE encoding helper and tighten hot path
- split variable-length ciphertext types into `variable` module
- switch chrono OPE outputs to fixed-size variants
- ♻️ adopt orderable-bytes for fixed-length encoders

### Testing

- convert NaiveDate equal-inputs test to a quickcheck prop

### Review

- address OPE PR feedback


### Documentation

- 📝 reflect OPE support and missing crates in suite + cllw-ore READMEs
- 📝 clarify cllw-ore OPE is a fallback when operator classes are unavailable

### Features

- ✨ add OPE encryption for serde_json::Value scalars
- ✨ extend JSON OPE encoding to nested arrays and objects

### Miscellaneous

- remove unused dev-dependencies from cllw-ore

### Refactoring

- 🔥 remove serde_json JSON OPE impl
- reinstate the cllw_ore json support
- ♻️ plaintext-side domain separation for orderable terms

## [0.5.1] - 2026-10-05


### Miscellaneous

- update Cargo.toml dependencies

## [0.5.0] - 2026-10-01

### ⚠ Breaking changes

- `OreCllw8VariableV1` no longer implements `From<Vec<u8>>` and `OpeCllw8VariableV1::from_bytes` is now fallible. Decode stored ciphertexts with `from_bytes` / `TryFrom<&[u8]>` (length-checked); wrap tagged-bit-stream ciphertexts, whose lengths the whole-byte rules do not describe, with `from_bytes_unchecked`. The `FromHex` hex wire decoder is unchanged and deliberately unchecked.


### Features

- freeze the byte formats the crate owns (phase 2)
- length-checked decoding for variable-length ciphertexts

### Fixes

- address phase-2 review findings on the frozen byte formats
- wipe the plaintext operand on the ORE/OPE term paths
- keep orderize_string's public signature
- remove stale nested Cargo.lock files pinning rand 0.8.5

### Miscellaneous

- version the variable-ciphertext API change as 0.5.0

## [0.34.0] - 2026-03-04

### Changed
- Consolidated all publishable crate versions to 0.34.0; version is now centralized via `workspace.package.version`

## [0.3.0] - 2026-01-18

### Added

- **Decryption Support**: Implemented `CllwOreDecrypt` trait and decryption methods for all supported types
  - `decrypt()` and `decrypt_with_salt()` methods for `u16`, `u32`, `u64`, `u128`
  - `decrypt()` and `decrypt_with_salt()` methods for strings (`&str`)
  - `decrypt_to_bytes()` method for byte slices (`&[u8]`)
- **Extended Type Support**: Added encryption and decryption for `u16` and `u128` types
- **Salt Support**: Added optional salt parameter to `encrypt_with_salt()` and `decrypt_with_salt()` methods for domain separation
- **Clone Implementations**: Added `Clone` derive to `OreCllw8VariableV1` and `Clone + Copy` to `OreCllw8V1<N>`
- **Comprehensive Benchmarks**: Added benchmarks for encryption and decryption operations across all supported types
  - Integer types: u16, u32, u64, u128
  - String types: short, medium, and long strings
  - Byte arrays: small and large byte slices
- **Feature Flags**: Added `postgres-types` feature flag (currently default, but will be opt-in in future versions)
  - ⚠️ WARNING: The `postgres-types` feature is enabled by default for backwards compatibility but will not be default in a future major version

### Changed

- **Security Enhancements**: 
  - Implemented constant-time comparison operations to prevent timing side-channel attacks
  - Enhanced constant-time operations in comparison functions
  - Added comprehensive security-focused lints
- **Documentation**: Enhanced documentation with usage examples for encryption, decryption, and salt usage
- **Dependencies**: Made `postgres-types` an optional dependency behind the `postgres-types` feature flag

### Fixed

- Fixed clippy warnings for unreachable `pub` items (changed to `pub(crate)`)
- Fixed clippy warnings for unused results from `hasher.update()` calls
- Removed unused dependencies

### Internal

- Refactored encryption/decryption implementations using macros for better code reuse
- Added property-based tests for decryption correctness
- Improved test coverage for all numeric types

## [0.2.0] - Previous Release

Intermediate release.

## [0.1.0] - Initial Release

Initial release with encryption support for `u32`, `u64`, strings, and byte slices.

[0.3.0]: https://github.com/cipherstash/cipherstash-suite/compare/cllw-ore-v0.2.0...cllw-ore-v0.3.0
[0.2.0]: https://github.com/cipherstash/cipherstash-suite/compare/cllw-ore-v0.1.0...cllw-ore-v0.2.0
[0.1.0]: https://github.com/cipherstash/cipherstash-suite/releases/tag/cllw-ore-v0.1.0
