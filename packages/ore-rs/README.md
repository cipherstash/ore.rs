# ore-rs

Part of the [ore.rs](https://github.com/cipherstash/ore.rs) workspace _(pronounced "auras")_.

[![Test](https://github.com/cipherstash/ore.rs/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/ore.rs/actions/workflows/test.yml)

ore-rs is a Rust library for Order-Revealing Encryption (ORE). It lets you compare encrypted values without the encryption key, so you can sort them and run range queries.

The library is based on the Block-ORE scheme by [Lewi and Wu (2016)](https://eprint.iacr.org/2016/612.pdf) and is used in the [CipherStash](https://cipherstash.com) searchable encryption platform.

Reference documentation is on [docs.rs/ore-rs](https://docs.rs/ore-rs).

## How it fits together

ore-rs is a scheme crate for [`vitaminc-ore`](https://docs.rs/vitaminc-ore), which owns the plaintext data model: for each kind of value, vitaminc decides how it becomes bytes that sort the way the value does, and seals the result as an `OrderPlaintext` that only it can build. ore-rs encrypts those plaintexts. You never hand it bytes of your own.

The typed API is vitaminc's. You open a **space** on the scheme with a **target** (the type every value in it is encoded as) and a **context** (what the terms compare within), and encrypt values there. A term compares only with terms of its own space.

One scheme, `BlockOre`, covers every target. It routes each space to one of two engines by the target's width when the space is opened, and you never name an engine:

| Engine | Targets | What a term reveals |
|---|---|---|
| Bit6 (`scheme::bit2_w6`) | `I16`–`U64`, `F64`, `Date` (up to 10 bytes) | Order, and the position of the first differing 6-bit block |
| Chained (`scheme::chained`) | `I128`, `U128`, `Uuid`, `Timestamp`, `Decimal`, `Text`, `Bytes` | Order, the common-prefix length in 6-bit blocks, and the padded length |

Both engines are the v2 schemes from 0.9.0 and their ciphertext formats are frozen, with compatibility tests to check that stored ciphertexts remain readable across releases. The [legacy `OreAes128` scheme](#the-legacy-scheme-oreaes128) remains available for compatibility with existing ciphertexts.

## Quick start

```toml
[dependencies]
ore-rs = "0.10"
vitaminc-ore = "0.7"
vitaminc-protected = "0.7"
```

ore-rs requires Rust 1.88 or later.

```rust
use std::cmp::Ordering;
use ore_rs::vitaminc::BlockOre;
use vitaminc_ore::target::{I64, Text};
use vitaminc_ore::{OrderEncrypt, OrderKeyInit};
use vitaminc_protected::Protected;

// In production, a random 32-byte key from your key management system.
let scheme = BlockOre::new(Protected::new([0x2b; 32]));

// A space of `i64`s under one context. The compiler checks that a value
// always fits the target: an `i32` goes in as it is, an `i64` into an
// `I32` space needs `encrypt_checked`.
let quantities = scheme.target(I64).context(("orders", "quantity"));
let a = quantities.encrypt(456i64)?;
let b = quantities.encrypt(1024i64)?;
assert_eq!(quantities.compare(&a, &b), Some(Ordering::Less));

// A query is the half of a ciphertext a comparison needs from the
// searching side: smaller than a stored term, and never stored.
let query = quantities.encrypt_query(1000i64)?;
assert_eq!(quantities.compare_query(&query, &a), Some(Ordering::Greater));
assert_eq!(quantities.compare_query(&query, &b), Some(Ordering::Less));

// A term is stored as bytes, and read back through its space.
let stored: Vec<u8> = a.as_bytes().to_vec();
let read_back = quantities.term(ore_rs::Term::from_bytes(stored));
assert_eq!(quantities.compare(&read_back, &b), Some(Ordering::Less));

// Text goes to the chained engine. The caller does not choose.
let names = scheme.target(Text).context(("users", "name"));
let alice = names.encrypt_checked("alice")?;
let bob = names.encrypt_checked("bob")?;
assert_eq!(names.compare(&alice, &bob), Some(Ordering::Less));
# Ok::<(), Box<dyn std::error::Error>>(())
```

`encrypt` takes a value that always fits the target, as vitaminc's `FitsIn` table says; `encrypt_checked` takes any value of the data model and checks it while the program runs. The `vitaminc-ore` README describes the chain, the targets and the encodings.

## Keys and contexts

`BlockOre::new` takes a 32-byte key and derives one 16-byte ORE key from it with HMAC-SHA256. Each space is then keyed from that key under the salt vitaminc derives, `PAE("vitaminc/ore/v1", "block-ore", domain, context)`, through the engines' own salt stage. Two targets or two contexts never share key material, so `0i64` and `i64::MIN` in two spaces are not the same term, and a term of one space never compares `Equal` to a term of another.

Only compare terms of one space. Terms do not record their space, so the scheme cannot detect a mismatch and may return any ordering. Keep a space's terms together, as the vitaminc docs say.

## Padding and length limits

Text is padded with NUL bytes to a length bucket before encryption, so a text term reveals the bucket rather than the exact length. The default rounds up to a power of two with a 16-byte floor: 16, 32, 64 and so on. Stored terms and the queries that compare with them must share a policy, and text that ends in NUL is refused (`OreError::TrailingNul`), since padding would make `"alice"` and `"alice\0"` the same term. Bytes are never padded, because NUL padding would refuse every value that ends in a zero byte, so a bytes term reveals the exact length. Fixed-width targets have nothing to hide.

Text and bytes are refused past a ceiling, 1024 bytes by default, counting the marker byte vitaminc puts before them. Encryption time and term size grow with the padded length, so the ceiling bounds what one value can cost. Set both on the scheme:

```rust
use ore_rs::scheme::chained::Padding;
use ore_rs::vitaminc::BlockOre;
use vitaminc_ore::target::Text;
use vitaminc_ore::{OrderEncrypt, OrderKeyInit};
use vitaminc_protected::Protected;

let scheme = BlockOre::new(Protected::new([0x2b; 32]))
    .with_text_padding(Padding::PowerOfTwo { min_bytes: 32 })
    .with_max_bytes(256);
let emails = scheme.target(Text).context("customers");
let term = emails.encrypt_checked("alice@example.com")?;
# let _ = term;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Using the engines directly

The engines and the legacy scheme are public, through the `OreScheme` trait, for compatibility tests, the stored-bytes comparators and anyone who holds serialised ciphertexts. They take a sealed plaintext, made with `vitaminc_ore::order`, and nothing else, and they take the key and salt a space would derive for them.

```rust
use std::cmp::Ordering;
use ore_rs::scheme::bit2_w6::OreAes128Bit6;
use ore_rs::OreScheme;
use vitaminc_context::Context;
use vitaminc_ore::{order, Int, OrderTarget, Physical};
use vitaminc_protected::Protected;

let ore = OreAes128Bit6::init_with_salt(
    Protected::new([0x2b; 16]),
    &Context::from_encoded(&b"orders.quantity"[..]),
)?;
let plaintext = |x: u64| order(OrderTarget::U64, None, Physical::Int(Int::U64(x))).unwrap();

let a = ore.encrypt_plaintext(&plaintext(456))?;
let b = ore.encrypt_plaintext(&plaintext(1024))?;
let query = ore.encrypt_query_plaintext(&plaintext(456))?;

// A u64 ciphertext has 11 six-bit blocks.
assert_eq!(a.as_bytes().len(), 295);
assert_eq!(
    OreAes128Bit6::compare_raw_slices(a.as_bytes(), b.as_bytes()),
    Some(Ordering::Less)
);
assert_eq!(
    OreAes128Bit6::compare_left_to_full(query.as_bytes(), a.as_bytes()),
    Some(Ordering::Equal)
);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`compare_raw_slices` and `compare_left_to_full` take serialised bytes and need no key, so a comparison can run wherever the bytes are, a database included. They return `None` for bytes that are not a ciphertext of the scheme, or for two chained ciphertexts made under different padding policies. Bit6 and the legacy scheme also return `None` for two ciphertexts of different block counts. The chained engine compares different block counts lexicographically, as it compares two strings: the first differing block decides, and when the shorter ciphertext's blocks all match the longer one's, the shorter sorts first. Serde is not supported.

The chained engine takes `Options` for its salt, padding policy and ceiling: `OreAes128Bit6Chained::init_with(key, options)`. The legacy scheme takes two 16-byte keys: `OreAes128::init(k1, k2)`.

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

Bit6 supports at most 14 blocks (10 bytes of plaintext) because it packs the prefix into a single AES block. The chained engine takes wider values: it uses an AES-CMAC accumulator to track the preceding blocks, removing the limit, at about the same cost per block.

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

Anyone with two full ciphertexts can compare them without a key or a query. The information revealed depends on the engine:

- Bit6 reveals the order and the position of the first differing 6-bit block.
- Chained reveals the order and the common-prefix length in 6-bit blocks. A ciphertext also reveals the padded length, or the exact byte length if padding is disabled.
- Legacy `OreAes128` reveals the order and the first differing byte. A single ciphertext also reveals runs of zero bytes, as described below.

To report a security issue, see [SECURITY.md](https://github.com/cipherstash/ore.rs/blob/main/SECURITY.md) or email security@cipherstash.com.

## The legacy scheme: `OreAes128`

`OreAes128` (`scheme::bit2`) uses 8-bit blocks and was the only scheme available before 0.9. It remains available for compatibility with existing legacy ciphertexts, but is not recommended for new data and has no vitaminc adapter. Its format remains frozen so existing ciphertexts stay readable. It takes fixed-width plaintexts of up to 15 bytes.

```rust
use std::cmp::Ordering;
use ore_rs::scheme::bit2::OreAes128;
use ore_rs::OreScheme;
use vitaminc_ore::{order, Int, OrderTarget, Physical};
use vitaminc_protected::Protected;

let ore = OreAes128::init(Protected::new([0x2b; 16]), Protected::new([0x7e; 16]))?;
let plaintext = |x: u64| order(OrderTarget::U64, None, Physical::Int(Int::U64(x))).unwrap();
let a = ore.encrypt_plaintext(&plaintext(456))?;
let b = ore.encrypt_plaintext(&plaintext(1024))?;
assert_eq!(
    OreAes128::compare_raw_slices(a.as_bytes(), b.as_bytes()),
    Some(Ordering::Less)
);
# Ok::<(), Box<dyn std::error::Error>>(())
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
