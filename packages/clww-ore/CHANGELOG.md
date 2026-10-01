# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


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
