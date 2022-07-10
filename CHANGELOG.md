# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
