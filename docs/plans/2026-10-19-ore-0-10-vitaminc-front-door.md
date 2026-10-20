# ore-rs 0.10: vitaminc is the front door

**Date:** 2026-10-19
**Status:** Agreed
**Scope:** `packages/ore-rs`, the vitaminc-ore 0.7 release series, and the `cllw-ore` crate, which moves into this workspace as `clww-ore`
**Supersedes:** the typed `OreEncrypt` surface described in [the v2 plan](2026-06-12-ore-v2-architecture.md) and the proposals in issues #124 and #127

## Context

ore-rs 0.9 asks the caller to choose a scheme before choosing a value. A `u64` or an `i32` wants `OreAes128Bit6`; a `Decimal`, a `u128` or a string wants `OreAes128Bit6Chained`. The wrong choice is a compile error that names a trait rather than the fix. Strings do not go through the trait at all (`encrypt_str`), byte arrays go through `encrypt_fixed`, and there are three ways to spell a comparison. The README repeats "use a separate key or salt for each plaintext type" because the cipher does not know its type.

The scheme is a function of the plaintext's width and whether it is fixed or variable. The library already knows that function. The API makes the caller compute it.

We first designed a plaintext-indexed cipher inside ore-rs, `Ore<T>`, with a trait that picked the scheme from the type. Comparing it with vitaminc-ore 0.7 (PRs 480 to 483 on cipherstash/vitaminc) showed that it was `OrderSpace` under another name: a scheme, a target, a context and derived keys, with terms labelled by their target. Keeping both would mean two typed APIs for one engine and two copies of the type-to-target table. So the decision is to keep none in ore-rs.

## Decision

vitaminc is a dependency of ore-rs, not a feature. vitaminc-ore's typed API is the only typed way to encrypt with ore-rs:

```rust
let scheme = BlockOre::new(key);
let prices = scheme.target(Decimal).context(("orders", "total"));
let term = prices.encrypt(dec!(19.99))?;
let query = prices.encrypt_query(dec!(20))?;
prices.compare_query(&query, &term);
```

ore-rs exports one v2 scheme, `vitaminc::BlockOre`, which implements `OrderScheme`, `OrderQuery` and `Supports` for every target. It routes inside: targets of up to ten bytes (`I16` to `U64`, `F64`, `Date`) go to the Bit6 packed-prefix engine; `I128`, `U128`, `Uuid`, `Timestamp`, `Decimal`, `Text` and `Bytes` go to the chained engine. `compare` dispatches on the wire header, which carries the scheme id. The stored bytes of both engines are unchanged from 0.9.

Type separation comes from vitaminc's salt, `PAE("vitaminc/ore/v1", "block-ore", domain, context)`, whose domain is the target's. No ore-rs label is added.

### What ore-rs keeps

- The two v2 engines and the legacy scheme as public types, at the scheme level, for compatibility tests, the pl/pgSQL comparator and anyone who holds serialised ciphertexts. They take a sealed `OrderPlaintext` only: `encrypt_plaintext` and `encrypt_query_plaintext`. A caller using an engine directly builds the plaintext with `vitaminc_ore::order()`.
- The byte comparators, `compare_raw_slices` and `compare_left_to_full`, on all three schemes. Bit6 gains the latter (#120).
- `OreError`, as the scheme's `Error`.

### What ore-rs loses

- The public `OreEncrypt` and `OreCipher` traits. A sealed `OreScheme` trait replaces them, with `init`, the two sealed-plaintext entry points, the two comparators and associated `Term` and `Query` output types. `PlainText<N>` and the block-level `encrypt<const N>` leave the public surface.
- `encrypt_str`, `encrypt_fixed`, `encrypt_left_str`, `encrypt_left_fixed`, and every per-type `OreEncrypt<Cipher>` implementation.
- `CipherText<S, N>`, `Left<S, N>`, `Right<S, N>`, `ChainedCipherText<N>` and `ChainedLeft<N>` as public types. They become crate-private or `#[doc(hidden)]`. The plaintext type now lives on vitaminc's `OrderTerm<_, T>`, which closes #127 by removal.
- The `orderable-bytes` dependency and the `chrono` and `decimal` features. vitaminc owns the encodings, ported byte for byte, and ore-rs only ever sees sealed bytes. The compatibility vector tests guard that nothing stored changes.
- The `R: Rng + SeedableRng` generic and the `*ChaCha20` aliases. `OreAes128Bit6`, `OreAes128Bit6Chained` and `OreAes128` are concrete and hold a `Mutex<SafeRand>`, so a scheme is `Send + Sync`. A seeded constructor lives behind a `test-support` feature.
- The 8-bit plaintext types. vitaminc has no `I8` or `U8` target (vitaminc PR 483): 256 values make an order term a frequency table.
- The `Bit6BlockOre` and `ChainedBlockOre` adapters and the legacy adapter. The `vitaminc` feature is unreleased, so no stored term names any of them. The legacy scheme has no adapter at all: the README says not to use it for new data, and an adapter would invite it.

### Keys, contexts and options

- Keys enter through `OrderKeyInit`: `BlockOre::new(Protected<[u8; 32]>)` or `try_from_bytes(Protected<Vec<u8>>)`, deriving the 16-byte ORE key with HMAC-SHA256 as the adapter does today. Scheme-level `init` takes `Protected<[u8; 16]>` and `impl IntoContext`.
- The context may be empty, as vitaminc's `OrderSpace` allows. `nonempty!` is for ore-rs's own fixed labels.
- Padding and the length ceiling are configured on the `BlockOre` value, `with_text_padding` and `with_max_bytes`, and apply to every `Text` space it opens. `Bytes` is never padded, since NUL padding would refuse every value ending in a zero byte. A space with a different policy is a different scheme value.

### What vitaminc-ore gains

A fifth PR on the 0.7 stack, after PRs 482 and 483:

- `OrderQuery: OrderScheme`, with `type Query: AsRef<[u8]>`, `encrypt_query(&self, space, plaintext) -> Result<Query, Error>` and `compare_query(query, term) -> Option<Ordering>`.
- `QueryTerm<R, T>`, mirroring `OrderTerm`.
- `OrderSpace::encrypt_query`, `encrypt_query_checked`, `compare_query` and `query(raw)` to relabel a query read back.
- A trivial implementation for the CLWW schemes, with `Query = Term`, so code generic over `OrderQuery` runs on either family.

And one change to PR 482: `open` takes the target, `fn open(&self, target: OrderTarget, salt: &Context<'_>)`. The salt is opaque PAE bytes, so without the target a routing scheme cannot tell at `open` which engine to key, and a `Text` space cannot apply its padding. With it, the adapter's `Space` is exactly one keyed engine, chosen once per space.

### clww-ore

`cllw-ore` moves from cipherstash-suite into this workspace as `packages/clww-ore`, the authors' initials spelt as they are (Chenette, Lewi, Weis and Wu):

- `git filter-repo` keeps its 98 commits of history.
- The crate and its identifiers (`CllwOreEncrypt`, `CllwOpeEncrypt`, `OreCllw8V1`, `OpeCllw8V1`) are renamed. `clww-ore` is published fresh at 0.6.0. `cllw-ore` gets one last 0.5.2 release pointing at it and is not yanked, since stack-encrypt pins `=0.5.0`.
- It adopts the workspace licence, subject to sign-off from whoever owns licensing. It is PolyForm Internal Use today.
- A second PR gives it the same treatment as ore-rs 0.10: vitaminc mandatory, orderable-bytes and the typed `CllwOreEncrypt` API gone, `OrderQuery` implemented, `postgres-types` off by default, MSRV 1.88.
- `packages/orderable-bytes` is then removed from the workspace. Its 0.2.1 stays on crates.io for old releases.

## Consequences

- MSRV becomes 1.88, vitaminc's floor. #121 changes from "declare 1.78" to "declare 1.88".
- ore-rs 0.10 is built against the vitaminc git branch until 0.7 is on crates.io, and published after it, as #115 did with 0.6.
- cipherstash-client is on vitaminc 0.5 and is being replaced by stack-encrypt, so it is not a blocker. stack-encrypt moves to `clww-ore` and ore-rs 0.10 when it takes vitaminc 0.7, tracked in cipherstash/stack.
- #117 (build each scheme's cipher once per space) is closed by `open`.
- The ore.rs README gains a third crate. The repository keeps its name.

## Alternatives considered

- **A plaintext-indexed cipher in ore-rs, `Ore<T>`.** Right shape, wrong layer. It duplicated `OrderSpace` and the type-to-target table.
- **A `Supports`-style bound on the cipher, `cipher.encrypt<T: SupportedBy<Self>>`.** Moves the compile error, keeps the problem.
- **Chained for everything.** Chained is faster per block (0.69 µs against 0.81) and the leakage is the same for fixed widths. Rejected only because 0.9 Bit6 ciphertexts exist and routing is internal, so it can change later without touching callers.
- **Keeping a legacy adapter.** No stored term needs it, and it would put new data on a scheme the README warns against.
- **The value as the receiver, `10u32.encrypt(&quantity)`.** This is how 0.9 reads, and it goes: the space is the receiver, `quantity.encrypt(10u32)`, as vitaminc spells it everywhere (`encrypt` on a space, `seal` on a cipher; a value only implements `Encrypt::visit`). Deferred, not ruled out. If it is wanted later, the shape is an extension trait in vitaminc-ore over every `V: Encrypt`, `value.encrypt_in(&space)`, under a name that cannot shadow a type's own `encrypt`. It is additive and belongs in vitaminc, so it does not need to be decided here.

## Roadmap

1. vitaminc: amend PR 482 (`open` takes the target); add the `OrderQuery` PR to the 0.7 stack.
2. ore-rs: close #126, #124, #122 and #103. #123 closed without a 0.9.1: its Bit6 `compare_left_to_full` ships in 0.10, carried by #130.
3. ore-rs 0.10: (a) sealed `OreScheme`, sealed-plaintext entry points, deletions, `Mutex<SafeRand>`, `Protected` keys, MSRV; (b) the single `BlockOre` adapter with routing, padding config and `OrderQuery`; (c) README, crate docs and CHANGELOG. (a) and (b) are one PR, #130, rather than a stack: porting the three 0.9 adapters to vitaminc 0.7 only to delete them was waste. #130 does (c) as well.
4. clww-ore: the move and rename; the 0.10 treatment; remove orderable-bytes.
