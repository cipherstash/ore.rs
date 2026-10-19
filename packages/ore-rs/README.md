# ore-rs

Part of the [ore.rs](https://github.com/cipherstash/ore.rs) workspace _(pronounced "auras")_, alongside [`orderable-bytes`](https://crates.io/crates/orderable-bytes).

[![Test](https://github.com/cipherstash/ore.rs/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/ore.rs/actions/workflows/test.yml)

Order-Revealing Encryption (ORE) in Rust, based on the Block-ORE scheme of [Lewi and Wu (2016)](https://eprint.iacr.org/2016/612.pdf). Anyone can compare two ciphertexts and learn the order of their plaintexts, without the key. It is used in the [CipherStash](https://cipherstash.com) searchable encryption platform.

Reference documentation is on [docs.rs/ore-rs](https://docs.rs/ore-rs).

## Choosing a scheme

| Scheme | Use it for | Plaintexts |
|---|---|---|
| **`OreAes128Bit6`** (`scheme::bit2_w6`) | **New fixed-width data.** The recommended scheme. | `bool`, integers up to 64 bits, `char`, `f32`, `f64` |
| **`OreAes128Bit6Chained`** (`scheme::chained`) | Strings and other variable-length data, and 128-bit integers | strings, `u128`, `i128` |
| `OreAes128` (`scheme::bit2`) | Data already encrypted with it, and `Decimal` and `chrono` types | as Bit6, plus `Decimal`, `NaiveDate`, `DateTime<Utc>` |

The two v2 schemes, Bit6 and chained, split plaintexts into 6-bit blocks. Their wire formats are frozen as of 0.9.0: compatibility vectors pin the bytes, so stored ciphertexts stay readable across releases. The legacy `OreAes128` scheme is frozen too; see [The legacy scheme](#the-legacy-scheme-oreaes128).

## Quick start

```toml
[dependencies]
ore-rs = "0.9"
```

Encrypt with `OreEncrypt`, then compare the ciphertexts, or serialise them and compare the bytes:

```rust
use ore_rs::scheme::bit2_w6::OreAes128Bit6ChaCha20;
use ore_rs::{CipherText, OreCipher, OreEncrypt, OreOutput};
use std::cmp::Ordering;

// One 16-byte key. Use a random key from your key management system.
let key = [0x2b; 16];
let ore = OreAes128Bit6ChaCha20::init(&key).unwrap();

let a = 456u64.encrypt(&ore).unwrap();
let b = 1024u64.encrypt(&ore).unwrap();
assert!(a < b);

// Serialise to bytes; a `u64` is 11 six-bit blocks.
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

## Why Bit6

Against the legacy scheme, for a `u64` (Apple M1 Max, hardware AES, measured for 0.9.0):

| | `OreAes128Bit6` | `OreAes128` (legacy) |
|---|---|---|
| Encrypt, full ciphertext | 11.3 µs | 21.8 µs |
| Encrypt, left (query) ciphertext | 8.3 µs | 15.0 µs |
| Full ciphertext | 295 bytes | 408 bytes |
| Right half | 104 bytes | 272 bytes |
| Left ciphertext | 191 bytes | 136 bytes |

- **About twice as fast to encrypt.** Each 6-bit block costs 64 random-oracle evaluations instead of 256.
- **28% less to store.** A block's right half is 8 bytes instead of 32. A left ciphertext is larger, since it carries a header and 11 blocks rather than 8.
- **Less leakage.** A comparison reveals the order and the first differing 6-bit block, and a ciphertext alone does not show its runs of zero bytes (the legacy scheme's [known leakage](#known-leakage-of-oreaes128)).
- **Hardened.** The permutation is built with no secret-dependent memory address, table reads and the comparator are constant-time scans, and the stack an encryption used is zeroed afterwards. Parsers and comparators refuse malformed input instead of panicking.

Bit6 packs a plaintext's prefix into one AES block, so it takes at most 14 blocks (10 bytes). Wider values use the chained scheme.

## Strings and variable-length data: the chained scheme

`OreAes128Bit6Chained` derives each block's secrets from an AES-CMAC accumulator over the prefix, so a plaintext has no length cap. Comparison is lexicographic: a value sorts before any longer value it is a prefix of.

- **Padding.** A ciphertext's size gives its block count. Strings are padded with NUL bytes to a length bucket by default (powers of two with a 16-byte floor: 16, 32, 64 bytes and so on), so a ciphertext reveals the bucket, not the exact length. `Padding::None` and `Padding::Fixed { max_bytes }` are the alternatives. Stored values and the queries that compare with them must use one policy; the comparators return `None` for two ciphertexts made under different policies. A string that ends in NUL is refused (`OreError::TrailingNul`), since it would encrypt like the string without it.
- **A length ceiling.** A cipher refuses strings longer than its ceiling (`OreError::TooLong`), 1024 bytes by default. Ciphertext size and encryption time grow with the padded length, so the ceiling bounds what one input can cost.
- **128-bit integers.** `u128` and `i128` implement `OreEncrypt` here, as `ChainedCipherText<22>` / `ChainedLeft<22>`. Those types pin the block count, so the typed parsers and comparators refuse a ciphertext of another length. That is a length guard, not a type guard: a 16-byte string or an `i128` is 22 blocks too. `encrypt_fixed` takes any other fixed-length `orderable-bytes` type.

Settings go in `Options`, passed to `init_with(key, options)`:

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

A comparison reveals the common-prefix length (in 6-bit blocks) as well as the order. A full ciphertext carries its left half, so anyone holding two stored full ciphertexts can compare them, with no query.

## Keys and salts

The v2 schemes take **one 16-byte key** and an optional **salt**: `init(key)` or `init_with_salt(key, salt)`. On the chained scheme the salt is also an `Options` field (`Options::with_salt`). The salt is any byte string that names what the key is for, such as a data set or a tenant.

- Ciphertexts under different salts share no key material.
- Nothing on the wire records the salt, so a comparison across salts gives a confident, meaningless result, `Equal` included: two empty values compare `Equal` under any salts. No comparison can confirm that two salts match. Keep the salt with the data's identity, as you keep the key.
- Use one key or salt per kind of value. Under one key and salt, values of different types whose order-preserving encodings coincide (`0u64` and `i64::MIN`, say) encrypt to the same bytes.

The caller's key is evaluated on one fixed label only, and every PRF key is derived from it under scheme-specific labels, so sharing a key with the legacy scheme cannot expose Bit6 or chained keys through legacy ciphertexts. The legacy `OreAes128` keeps its two-key `init(k1, k2)`.

## Plaintext types

`OreEncrypt` covers:

- **`OreAes128Bit6`:** `bool`, `u8`–`u64`, `i8`–`i64`, `char`, `f32`, `f64`.
- **`OreAes128Bit6Chained`:** `u128`, `i128`; strings through `encrypt_str`; any fixed-length `orderable-bytes` type through `encrypt_fixed`.
- **`OreAes128`:** the Bit6 types, plus `rust_decimal::Decimal` (feature `decimal`) and `chrono::NaiveDate` and `chrono::DateTime<Utc>` (feature `chrono`).

The plaintext encodings come from the sibling [`orderable-bytes`](https://crates.io/crates/orderable-bytes) crate.

## Use from vitaminc

The `vitaminc` feature implements [`vitaminc-ore`](https://docs.rs/vitaminc-ore)'s `OrderScheme` for three schemes, so vitaminc can encrypt the sealed order plaintexts it builds here. A caller names the type its values are encoded as and the context they compare within (`scheme.column(OrderTarget::I32, context)` in vitaminc 0.6), and every value is encoded at that type's width, so terms that compare together always have one width.

- `vitaminc::Bit6BlockOre` is the Bit6 scheme, for targets up to ten bytes: the one to prefer for new fixed-width data.
- `vitaminc::ChainedBlockOre` is the chained scheme, which takes every target, text and bytes included. Text and bytes go in behind one marker byte (`vitaminc::VARIABLE_WIDTH_MARKER`), so an empty value still makes a keyed block, and are refused past 1023 bytes (`OrderError::Backend(OreError::TooLong)`): the default 1024-byte ceiling counts the marker.
- `vitaminc::BlockOre` is the legacy scheme, up to 15 bytes.

vitaminc derives one salt per scheme, target and context. The two v2 schemes bind it with `init_with_salt`, under an ORE key derived once from the scheme key with HMAC-SHA256 when the scheme is made. The legacy scheme takes no salt, so it derives its two keys for every term with HMAC-SHA256 under the salt. The feature is off by default, changes nothing in the typed API above, and needs Rust 1.88 and vitaminc 0.6.1.

## Hardware AES on ARM

On aarch64, including Apple Silicon, the `aes` crate uses the ARMv8 Cryptography Extensions only when built with its `aes_armv8` cfg. Without it AES falls back to software, about 60 times slower per block on an M1 Max. Stable Rust is fine:

```toml
# .cargo/config.toml in your project
[target.'cfg(target_arch = "aarch64")']
rustflags = ["--cfg", "aes_armv8"]
```

The flag applies per final binary, so a downstream project needs it in its own build configuration; this repository's workspace sets it for its own tests and benches. x86_64 AES-NI is detected at run time and needs no flag.

## Security

Block-ORE (Lewi-Wu) has been well studied, but this implementation has not had a public third-party audit. Evaluate it against your own threat model before using it in production. The v2 constructions and their review are documented under [`docs/`](https://github.com/cipherstash/ore.rs/tree/main/docs).

What a ciphertext reveals, by scheme:

- **Bit6:** a comparison reveals the order and the position of the first differing 6-bit block.
- **Chained:** a comparison reveals the order and the common-prefix length; a ciphertext reveals its length bucket (or its exact length, unpadded).
- **Legacy `OreAes128`:** a comparison reveals the order and the first differing byte, and a single ciphertext reveals its runs of zero bytes (below).

To report a security issue, see [SECURITY.md](https://github.com/cipherstash/ore.rs/blob/main/SECURITY.md) or email security@cipherstash.com.

## The legacy scheme: `OreAes128`

`OreAes128` (`scheme::bit2`) is the original 8-bit-block scheme, and the only one before 0.9. Its wire format is frozen, and compatibility vectors pin it, so existing ciphertexts stay readable. Use it for data already encrypted with it, and for `Decimal` and the `chrono` types, which have no v2 implementation yet. Use Bit6 for new data.

```rust
use ore_rs::scheme::bit2::OreAes128ChaCha20;
use ore_rs::OreEncrypt;

let (k1, k2) = ([0x2b; 16], [0x7e; 16]);
let ore = OreAes128ChaCha20::init(&k1, &k2).unwrap();
assert!(456u64.encrypt(&ore).unwrap() < 1024u64.encrypt(&ore).unwrap());
```

It improves on the original scheme by using a Knuth (Fisher-Yates) shuffle for the PRP instead of a Feistel network, which is insecure for small domains ([Bogatov et al.](https://eprint.iacr.org/2018/953.pdf)); AES alone as the random oracle; and the block number in the left-tag (PRF₁) input, to avoid repeated tags.

### Known leakage of `OreAes128`

Beyond the order and the first differing block of a compared pair, an `OreAes128` ciphertext shows its runs of zero bytes. The PRP seed for block `n` is derived from the bytes before it, padded with zeros, and binds neither the block index nor the block count. Blocks inside a run of zero bytes therefore share a permutation and encrypt to the same value. One ciphertext (a left alone is enough) gives away:

* the number of leading zero bytes of an integer, which is its order of magnitude, as the same value in every ciphertext under a key;
* other runs of zero bytes, such as the trailing zero mantissa bytes of a round float.

The wire format is frozen, so this cannot change for existing data. Bit6 binds the block index and the block count into its seeds. See "Known leakage of the legacy scheme" in [the v2 plan](https://github.com/cipherstash/ore.rs/blob/main/docs/plans/2026-06-12-ore-v2-architecture.md).

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
