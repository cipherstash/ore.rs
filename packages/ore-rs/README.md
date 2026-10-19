# ore-rs

Part of the [ore.rs](https://github.com/cipherstash/ore.rs) workspace _(pronounced "auras")_, alongside [`orderable-bytes`](https://crates.io/crates/orderable-bytes).

[![Test](https://github.com/cipherstash/ore.rs/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/ore.rs/actions/workflows/test.yml)

ore-rs is a Rust library for Order-Revealing Encryption (ORE). It lets you compare encrypted values without the encryption key, so you can sort them and run range queries.

The library is based on the Block-ORE scheme by [Lewi and Wu (2016)](https://eprint.iacr.org/2016/612.pdf) and is used in the [CipherStash](https://cipherstash.com) searchable encryption platform.

Reference documentation is on [docs.rs/ore-rs](https://docs.rs/ore-rs).

## Choosing a scheme

| Scheme | When to use it |
|---|---|
| `OreAes128Bit6` ([`scheme::bit2_w6`](https://docs.rs/ore-rs/latest/ore_rs/scheme/bit2_w6/index.html)) | The recommended choice for booleans, integers up to 64 bits, characters, floats and `chrono::NaiveDate`. |
| `OreAes128Bit6Chained` ([`scheme::chained`](https://docs.rs/ore-rs/latest/ore_rs/scheme/chained/index.html)) | Strings, other variable-length data, 128-bit integers, `Decimal` and `chrono::DateTime<Utc>`. Also supports all of the Bit6 types. |

The [legacy `OreAes128` scheme](#the-legacy-scheme-oreaes128) remains available for compatibility with existing ciphertexts. It is not recommended for new data.

Bit6 and chained are the v2 schemes. Both use 6-bit blocks. Their ciphertext formats are frozen as of 0.9.0, with compatibility tests to check that stored ciphertexts remain readable across releases. The [legacy format](#the-legacy-scheme-oreaes128) is also frozen.

## Quick start

```toml
[dependencies]
ore-rs = "0.9"
```

ore-rs requires Rust 1.78 or later. The `vitaminc` feature requires Rust 1.88 or later.

Use `OreEncrypt` to encrypt a value. You can compare ciphertexts directly or pass their serialised bytes to `compare_raw_slices`:

```rust
use ore_rs::scheme::bit2_w6::OreAes128Bit6ChaCha20;
use ore_rs::{CipherText, OreCipher, OreEncrypt, OreOutput};
use std::cmp::Ordering;

// In production, use a random 16-byte key from your key management system.
let key = [0x2b; 16];
let ore = OreAes128Bit6ChaCha20::init(&key).unwrap();

let a = 456u64.encrypt(&ore).unwrap();
let b = 1024u64.encrypt(&ore).unwrap();
assert!(a < b);

// A u64 ciphertext has 11 six-bit blocks.
let bytes = a.to_bytes();
assert_eq!(bytes.len(), 295);
let parsed = CipherText::<OreAes128Bit6ChaCha20, 11>::from_slice(&bytes).unwrap();
assert_eq!(parsed.cmp(&b), Ordering::Less);

// Or compare serialised ciphertexts without parsing them.
assert_eq!(
    OreAes128Bit6ChaCha20::compare_raw_slices(&bytes, &b.to_bytes()),
    Some(Ordering::Less)
);
```

Strings use the chained scheme:

```rust
use ore_rs::scheme::chained::OreAes128Bit6ChainedChaCha20;
use std::cmp::Ordering;

let key = [0x2b; 16];
let ore = OreAes128Bit6ChainedChaCha20::init(&key).unwrap();

let alice = ore.encrypt_str("alice").unwrap().to_bytes();
let bob = ore.encrypt_str("bob").unwrap().to_bytes();
assert_eq!(
    OreAes128Bit6ChainedChaCha20::compare_raw_slices(&alice, &bob),
    Some(Ordering::Less)
);

// A query needs only the left half of a ciphertext.
let query = ore.encrypt_left_str("alice").unwrap().to_bytes();
assert_eq!(
    OreAes128Bit6ChainedChaCha20::compare_left_to_full(&query, &alice),
    Some(Ordering::Equal)
);
```

## Ciphertext types and serialisation

Bit6 returns a `CipherText<S, N>`, where `S` is the scheme and `N` is the block count. A `u64` uses 11 blocks. Comparing ciphertexts with different schemes or block counts is a compile error:

```compile_fail
use ore_rs::{OreEncrypt, scheme::bit2_w6::OreAes128Bit6ChaCha20};

let ore = OreAes128Bit6ChaCha20::init(&[0x2b; 16]).unwrap();
let a = 456u64.encrypt(&ore).unwrap();
let b = 1024u32.encrypt(&ore).unwrap(); // a u32 is 6 blocks

let result = a > b; // compilation error
```

Use `to_bytes` to serialise a ciphertext and `from_slice` to parse it, specifying the scheme and block count as in the quick start. You can also compare serialised ciphertexts directly with `compare_raw_slices`. Serde is not supported.

## Plaintext types

The following types implement `OreEncrypt`, which provides `value.encrypt(&cipher)` and `value.encrypt_left(&cipher)`:

| Scheme | Types |
|---|---|
| `OreAes128Bit6` | `bool`, `u8`–`u64`, `i8`–`i64`, `char`, `f32`, `f64`, plus `chrono::NaiveDate` with the `chrono` feature |
| `OreAes128Bit6Chained` | The Bit6 types, plus `u128`, `i128`, `rust_decimal::Decimal` with the `decimal` feature, and `chrono::DateTime<Utc>` with the `chrono` feature |
| `OreAes128` (legacy) | The Bit6 types, plus `rust_decimal::Decimal` with the `decimal` feature, and `chrono::DateTime<Utc>` with the `chrono` feature |

The chained scheme also provides `encrypt_str` for strings and `encrypt_fixed` / `encrypt_left_fixed` for other fixed-length `orderable-bytes` types, such as byte arrays.

Decimal and timestamp encodings are 14 and 12 bytes respectively, exceeding Bit6's 10-byte limit. Use the chained scheme for them. `NaiveDate` uses 4 bytes and works with either v2 scheme.

The plaintext encodings come from the sibling [`orderable-bytes`](https://crates.io/crates/orderable-bytes) crate.

### Decimals

Enable the `decimal` feature to encrypt `rust_decimal::Decimal` values:

```rust
# #[cfg(feature = "decimal")]
# {
use ore_rs::scheme::chained::{ChainedCipherText, OreAes128Bit6ChainedChaCha20, DECIMAL_BLOCKS};
use ore_rs::{OreEncrypt, OreOutput};
use rust_decimal::Decimal;
use std::cmp::Ordering;

let ore = OreAes128Bit6ChainedChaCha20::init_with_salt(&[0x2b; 16], b"prices").unwrap();
let price = Decimal::new(1999, 2); // 19.99
let stored = price.encrypt(&ore).unwrap();
let query = price.encrypt_left(&ore).unwrap();
assert_eq!(
    ChainedCipherText::<DECIMAL_BLOCKS>::compare_left_to_full(
        &query.to_bytes(), &stored.to_bytes()
    ),
    Some(Ordering::Equal)
);
# }
```

### Dates and timestamps

Enable the `chrono` feature for `NaiveDate` and `DateTime<Utc>`. Dates fit Bit6; timestamps use chained. Use a separate key or salt for each plaintext type:

```rust
# #[cfg(feature = "chrono")]
# {
use chrono::{DateTime, NaiveDate, Utc};
use ore_rs::scheme::bit2_w6::OreAes128Bit6ChaCha20;
use ore_rs::scheme::chained::{ChainedCipherText, OreAes128Bit6ChainedChaCha20, DATETIME_UTC_BLOCKS};
use ore_rs::{OreEncrypt, OreOutput};
use std::cmp::Ordering;

let key = [0x2b; 16];
let dates = OreAes128Bit6ChaCha20::init_with_salt(&key, b"dates").unwrap();
let yesterday = NaiveDate::from_ymd_opt(2026, 10, 18).unwrap();
let today = NaiveDate::from_ymd_opt(2026, 10, 19).unwrap();
assert!(yesterday.encrypt(&dates).unwrap() < today.encrypt(&dates).unwrap());

let timestamps = OreAes128Bit6ChainedChaCha20::init_with_salt(&key, b"timestamps").unwrap();
let timestamp = DateTime::<Utc>::from_timestamp(0, 123).unwrap();
let stored = timestamp.encrypt(&timestamps).unwrap();
let query = timestamp.encrypt_left(&timestamps).unwrap();
assert_eq!(
    ChainedCipherText::<DATETIME_UTC_BLOCKS>::compare_left_to_full(
        &query.to_bytes(), &stored.to_bytes()
    ),
    Some(Ordering::Equal)
);
# }
```

## Bit6 performance and limits

For a `u64`, Bit6 encrypts about twice as fast as the legacy scheme and produces a 28% smaller full ciphertext. These measurements are from the 0.9.0 benchmarks on an Apple M1 Max with hardware AES:

| | `OreAes128Bit6` | `OreAes128` (legacy) |
|---|---|---|
| Full encryption time | 11.3 µs | 21.8 µs |
| Query encryption time (left only) | 8.3 µs | 15.0 µs |
| Full ciphertext | 295 bytes | 408 bytes |
| Right half | 104 bytes | 272 bytes |
| Left ciphertext | 191 bytes | 136 bytes |

The smaller blocks account for much of the difference: each needs 64 random-oracle evaluations, compared with 256 in the legacy scheme, and its right half takes 8 bytes instead of 32. The left ciphertext for a `u64` is larger because it includes a header and 11 blocks rather than 8.

Bit6 also avoids the legacy scheme's [zero-byte leakage](#known-leakage-of-oreaes128). The permutation builder avoids secret-dependent memory addresses, and table lookups and comparisons use constant-time scans. Temporary encryption state is zeroed after use. Parsers and comparators reject malformed input without panicking.

Bit6 supports at most 14 blocks (10 bytes of plaintext) because it packs the prefix into a single AES block. Use the chained scheme for wider values.

## Strings and the chained scheme

Use `OreAes128Bit6Chained` for strings and other values too wide for Bit6. It uses an AES-CMAC accumulator to track the preceding blocks, removing Bit6's 14-block limit. Strings compare lexicographically: `"alice"` sorts before `"bob"`, and `"a"` sorts before `"alice"`.

### Padding and length limits

By default, string lengths are rounded up to a power of two, with a minimum of 16 bytes: 16, 32, 64 and so on. Padding uses NUL bytes, and the ciphertext's size reveals the padded length. You can disable padding with `Padding::None` or choose a fixed length with `Padding::Fixed { max_bytes }`.

Stored values and queries must use the same padding policy. Comparators return `None` if the policies differ. With padding enabled, strings ending in NUL are rejected with `OreError::TrailingNul`: padding would make `"alice"` and `"alice\0"` indistinguishable, for example.

Strings longer than 1024 bytes are rejected with `OreError::TooLong` by default. Encryption time and ciphertext size grow with the padded length, so the limit bounds the cost of encrypting one value.

Set the padding policy, length limit and salt through `Options`:

```rust
use ore_rs::scheme::chained::{OreAes128Bit6ChainedChaCha20, Options, Padding};

let key = [0x2b; 16];
let options = Options::default()
    .with_padding(Padding::PowerOfTwo { min_bytes: 32 })
    .with_max_bytes(256)
    .with_salt(b"customers");
let ore = OreAes128Bit6ChainedChaCha20::init_with(&key, options).unwrap();
let ct = ore.encrypt_str("alice@example.com").unwrap();
```

### Fixed-length types

The chained scheme's `OreEncrypt` implementations return `ChainedCipherText<N>` or `ChainedLeft<N>`, where `N` is the block count. For example, `u128` and `i128` use 22 blocks, decimals use 19, timestamps use 16 and dates use 6. Their parsers and comparators require exactly that count.

The block count does not identify the plaintext type: both integer types and a 16-byte string use 22 blocks. Use a separate key or salt for each type, as described in [Keys and salts](#keys-and-salts).

Use `encrypt_fixed` for other fixed-length types from `orderable-bytes`.

## Keys and salts

Bit6 and chained take one 16-byte key and an optional salt through `init(key)` or `init_with_salt(key, salt)`. The chained scheme also accepts a salt through `Options::with_salt`. A salt can be any byte string, such as a dataset or tenant identifier. Different salts produce separate derived keys.

Only compare values encrypted with the same key and salt. Ciphertexts do not record the salt, so the library cannot detect a mismatch and may return any ordering, including `Equal`. For example, two unpadded empty values compare equal even when their salts differ. Keep track of which key and salt belong to each dataset.

Use a separate key or salt for each plaintext type. Some types encode different values as the same bytes: `0u64` and `i64::MIN`, for example, produce ciphertexts that compare equal under the same key and salt.

The v2 schemes use the supplied key only to derive a root key from a fixed label. They then derive separate internal keys using the salt and labels specific to each scheme. This prevents legacy ciphertexts from exposing v2 keys if the same key is used with both schemes. Legacy `OreAes128` still requires two keys: `init(k1, k2)`.

## Using ore-rs with vitaminc

Enable the optional `vitaminc` feature to use ore-rs through [`vitaminc-ore`](https://docs.rs/vitaminc-ore)'s `OrderScheme` trait. It uses vitaminc 0.6.1 and requires Rust 1.88 or later.

Choose a target type and a context with `scheme.column(OrderTarget::I32, context)`. For fixed-width targets, vitaminc encodes every value at the target's width so the ciphertexts can be compared.

- `vitaminc::Bit6BlockOre` supports fixed-width targets up to 10 bytes.
- `vitaminc::ChainedBlockOre` supports all targets, including text and bytes.
- `vitaminc::BlockOre` uses the legacy scheme and supports fixed-width targets up to 15 bytes.

The chained adapter adds a byte (`vitaminc::VARIABLE_WIDTH_MARKER`) before text and byte values so even an empty value produces an encrypted block. The marker counts towards the default 1024-byte limit, leaving 1023 bytes for the value. Longer values return `OrderError::Backend(OreError::TooLong)`.

vitaminc derives a salt for each combination of scheme, target and context. The v2 adapters derive an ORE key from the scheme key once, using HMAC-SHA256, and apply the salt through `init_with_salt`. The legacy adapter derives its two keys for each term using HMAC-SHA256 and the salt.

## Hardware AES on ARM

On aarch64, including Apple Silicon, enable hardware AES by adding this flag to your project's build configuration. It works on stable Rust:

```toml
# .cargo/config.toml in your project
[target.'cfg(target_arch = "aarch64")']
rustflags = ["--cfg", "aes_armv8"]
```

Without this flag, the `aes` crate uses software AES, which is about 60 times slower per block on an M1 Max. This repository already sets the flag for its own builds, but projects that depend on ore-rs need to set it themselves. On x86_64, AES-NI is detected at run time and needs no flag.

## Security

The Lewi-Wu Block-ORE scheme has been well studied, but this implementation has not had a public third-party audit. Evaluate it against your threat model before using it in production. The v2 designs and review notes are in [`docs/`](https://github.com/cipherstash/ore.rs/tree/main/docs).

Anyone with two full ciphertexts can compare them without a key or a query. The information revealed depends on the scheme:

- Bit6 reveals the order and the position of the first differing 6-bit block.
- Chained reveals the order and the common-prefix length in 6-bit blocks. A ciphertext also reveals the padded length, or the exact byte length if padding is disabled.
- Legacy `OreAes128` reveals the order and the first differing byte. A single ciphertext also reveals runs of zero bytes, as described below.

To report a security issue, see [SECURITY.md](https://github.com/cipherstash/ore.rs/blob/main/SECURITY.md) or email security@cipherstash.com.

## The legacy scheme: `OreAes128`

`OreAes128` (`scheme::bit2`) uses 8-bit blocks and was the only scheme available before 0.9. It remains available for compatibility with existing legacy ciphertexts, but is not recommended for new data. Its format remains frozen so existing ciphertexts stay readable. Use a v2 scheme for new data, including decimal and chrono values, as described in [Plaintext types](#plaintext-types).

```rust
use ore_rs::scheme::bit2::OreAes128ChaCha20;
use ore_rs::OreEncrypt;

let (k1, k2) = ([0x2b; 16], [0x7e; 16]);
let ore = OreAes128ChaCha20::init(&k1, &k2).unwrap();
assert!(456u64.encrypt(&ore).unwrap() < 1024u64.encrypt(&ore).unwrap());
```

The legacy implementation uses a Knuth (Fisher-Yates) shuffle for its pseudorandom permutation (PRP), avoiding the weaknesses of small-domain Feistel networks described by [Bogatov et al.](https://eprint.iacr.org/2018/953.pdf). Other changes from the original Lewi-Wu scheme include using AES as the random oracle and including the block number in the left-tag (PRF₁) input to avoid repeated tags.

### Known leakage of `OreAes128`

An `OreAes128` ciphertext also reveals runs of zero bytes in the plaintext. Each block's PRP seed comes from the preceding bytes, padded with zeros. The seed does not include the block position or total block count, so blocks within a run of zeros share a permutation and produce the same permuted byte.

Even a left ciphertext on its own reveals these patterns. Leading zero bytes in an integer expose its approximate magnitude and produce the same repeated value across ciphertexts under one key. Other zero runs are visible too, including trailing zero bytes in a float's mantissa.

Fixing this would break compatibility with existing ciphertexts. Bit6 avoids it by including the block position and count in its seeds. See "Known leakage of the legacy scheme" in [the v2 plan](https://github.com/cipherstash/ore.rs/blob/main/docs/plans/2026-06-12-ore-v2-architecture.md).

## Build, test and bench

```sh
cargo build
cargo test
cargo bench
```

## Need help?

Please [open an issue](https://github.com/cipherstash/ore.rs/issues) and we'll get back to you.

## License

ore.rs is available under the CipherStash Client Library Licence Agreement.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, shall be licensed as above, without any additional terms or conditions.
