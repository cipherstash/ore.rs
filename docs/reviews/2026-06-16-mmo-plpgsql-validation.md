# Validation: v2 σ-MMO comparison in pl/pgSQL + pgcrypto

**Date:** 2026-06-16
**Question:** can the v2 (Bit6/chained) σ-MMO comparison function be implemented
in pl/pgSQL / SQL using only the `pgcrypto` extension, as an interim before the
Rust TLE lands? (The legacy bit2 comparator already lives in
`cipherstash/encrypt-query-language`; domain types separate the operators, so
this work targets the **new v2/MMO scheme**.)
**Answer: yes — validated empirically (12/12 vectors match Rust).**

## Key finding: the comparison needs no CMAC / PRP / key derivation

Those are all **encryption-side** (client/Rust). The comparator (`compare_views`
in `scheme/chained.rs`; the Bit6/bit2 `compare_raw_slices`) uses only:

1. a byte-equality prefix scan over `xt` + the 16-byte `f` tags,
2. the σ-MMO 1-bit hash of the first differing block's left tag `f[l]` under the
   stored nonce, and
3. an oblivious bit read of the right block at index `xt[l]`.

So `pgcrypto` not providing CMAC is irrelevant — CMAC only derives per-block
secrets during encryption.

## Primitive mapping

| Need | Implementation |
|---|---|
| π (fixed public-key AES-128) | `encrypt(m, 'ORE-rs.v2.H-pi.1'::bytea, 'aes-ecb/pad:none')` (pgcrypto) — `pad:none` for a raw single block; the `PI_KEY` is public, so it's embedded |
| σ = GF(2¹²⁸) doubling | ~10 lines of pl/pgSQL: byte-wise shift-left-1 + conditional `# 0x87` (`gf128_double` below) — the only non-pgcrypto-native op |
| `m = σ(f) ⊕ nonce`, feedforward, LSB | byte XOR (`get_byte`/`set_byte`/`#`) + `& 1` |
| prefix scan, bit read | plain SQL (`substring`, `get_bit`) |

## Empirical result

The pl/pgSQL `mmo_hash_bit(f, nonce)` (see
`2026-06-16-mmo-plpgsql-validation.sql`) was checked against ground-truth from
the Rust `FixedPiZ2Hash::hash` on 12 `(f, nonce)` vectors (H mix
`1,0,0,0,0,1,0,0,0,0,1,0`):

```
 total | matches | mismatches
    12 |      12 |          0
```

Byte-for-byte agreement. (Postgres 15.12 + pgcrypto.)

## Caveat — constant-time

The pl/pgSQL comparator computes the correct order, but pl/pgSQL is **not a
constant-time environment**: the cache-line/sub-line obliviousness the Rust
comparator gets from `ct_select_byte`/`ct_bit` and the no-early-exit prefix scan
is not realistically achievable in SQL. The interim SQL comparator therefore
trades that hardening away; the Rust TLE restores it. Whether that's acceptable
is a threat-model call for the interim (server-side comparison over stored
ciphertexts) — flagged, not decided here.

## Conclusion

The requirement is met: the v2 σ-MMO comparison is implementable in pl/pgSQL with
pgcrypto. The encryption-side work (single-key derivation, CMAC accumulator, PRP)
is unaffected by it. Safe to resume the single-key change + Bit6 vector regen.
