# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
