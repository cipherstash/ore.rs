# Decimal support for ore.rs (fixed-length scientific-form encoding)

**Date:** 2026-04-30
**Status:** Approved, in progress
**Branch:** `feat/decimal-support`

## Context

`ore.rs` implements Lewi-Wu BlockORE with fixed-N plaintexts via const generics. Today's `OreEncrypt` impls cover `u32`, `u64`, `f64` (via order-preserving f64→u64 mapping), and `chrono::NaiveDate` / `chrono::DateTime<Utc>` (gated behind `chrono`).

Goal: maintain feature parity between ORE and OPE, so any application can pick a scheme up front and encrypt the same set of types with either. There is **no legacy ORE-encrypted Decimal data in the wild**, so we have a free hand.

## Decision

1. Add a `decimal` feature gating `Decimal` support. The feature pulls `rust_decimal`.
2. Pre-encode each `Decimal` to a fixed 14-byte plaintext in *signed scientific form* (sign + biased leading-digit exponent + 29-digit-padded significand) and feed it to the existing fixed-N ORE machinery with `N = 14`.
3. Implement the encoder in `src/decimal.rs`.

## Pre-encoding layout

Each non-zero `Decimal` is re-expressed as:

```text
value = ±significand × 10^(leading_exp − digits(significand) + 1)
```

where `significand` is the mantissa with trailing zeros stripped (after `Decimal::normalize`) and `leading_exp` is the decimal exponent of the leading significant digit. For `Decimal`, `leading_exp ∈ [-28, 28]`.

The 14-byte plaintext is bit-packed:

```text
byte 0       : [sign:1][biased_exp:7]
bytes 1..=13 : padded_significand (104 bits, big-endian)
```

- **Sign bit** (top bit of byte 0): `1` for positive and zero, `0` for negative. Negative ciphertexts sort lex-less than zero, which sorts lex-less than any positive.
- **Biased exponent** (low 7 bits of byte 0): `leading_exp + 64`. Non-zero inputs land in `[36, 92]`; zero uses `0`, which is unreachable for any non-zero positive — so zero is unambiguous.
- **Padded significand** (104-bit big-endian field, bytes 1..13): `significand × 10^(29 − digits(significand))` — the significand left-justified to a fixed 29-digit width by appending trailing zeros. This is the integer reading of the value's normalised fractional significand at 29 digits of decimal precision. `Decimal`'s u96 mantissa has at most 29 decimal digits, so the padded value reaches up to ~10^29 (just under 97 bits) and fits comfortably in 104 bits.

For negatives, the low 7 bits of byte 0 and the 104-bit mantissa region are bitwise inverted so within the negative class a larger magnitude maps to smaller bytes. Combined with the sign-bit class ordering, this gives a total order over the full `Decimal` range.

### Why scientific form

Raw `(sign, scale, mantissa)` packing — even after `Decimal::normalize` — does *not* preserve `Decimal::cmp` order under byte-wise lex compare. Example: `1.5` is `(scale=1, mantissa=15)` and `1.05` is `(scale=2, mantissa=105)`; lex says `1.5 < 1.05` because `0x01 < 0x02`, but numerically `1.5 > 1.05`. Aligning the two values under a common scale — i.e. expressing both in scientific form with leading-digit-aligned significands — is what makes lex compare match numeric compare.

### Why 104-bit mantissa

To make same-exponent comparisons across different significand digit counts byte-wise correct, the significand must be left-justified to a fixed digit count `K`. `K` must be ≥ max significand digit count = 29. The worst-case padded value is ~`10^29`, which needs ~97 bits. 104 bits aligns cleanly to a byte boundary while leaving room. The natural `1 + 8 + 96 = 105` field widths (matching `Decimal`'s internal struct) cannot fit the padded significand losslessly: `9 × 10^28 = 9e28` overflows u96 (max ≈ `7.92e28`) for ~87% of u96 mantissas. Reframing the field widths as `1 + 7 + 104` keeps the same 14-byte plaintext while preserving full Decimal precision.

## Equivalence semantics

- `1`, `1.0`, `1.00`, `1.000` reduce to the same `(significand, leading_exp)` and therefore to identical plaintext bytes.
- `+0` and `-0` reduce to the same canonical zero plaintext.

These match `Decimal::cmp` / `Decimal::eq` exactly.

## Type and trait shape

```rust
// decimal feature
impl<T: OreCipher> OreEncrypt<T> for Decimal {
    type LeftOutput = Left<T, 14>;
    type FullOutput = CipherText<T, 14>;
    fn encrypt_left(&self, cipher: &T) -> Result<Self::LeftOutput, OreError>;
    fn encrypt(&self, cipher: &T) -> Result<Self::FullOutput, OreError>;
}

pub(crate) fn pre_encode(d: &Decimal) -> [u8; 14] { ... }
```

`OreCipher` and the existing `OreEncrypt` trait are untouched. The fixed-N ciphertext format, comparator, and serialization are unchanged.

## Compatibility with existing fixed-N path

The `bit2` ORE construction uses AES-128 directly as its PRF and packs `(prefix ‖ xt[i] ‖ block_index)` into a single 16-byte AES input block. That construction caps plaintext length at **15 bytes** (`output.f[n][n] = output.xt[n]` requires `n ≤ 15`, `output.f[n][N] = n as u8` requires `N ≤ 15`). 14-byte Decimal plaintexts sit comfortably under that cap.

## Test strategy

- Worked-example pre-encode tests: zero canonicalisation, signed-zero collision, equivalent-form collision, sign-byte and exponent-byte structure for a few worked positives and negatives, mantissa-byte inversion for negatives.
- Pre-encode byte-order test: `pre_encode` itself sorts consistently with `Decimal::cmp` across a dramatic-magnitude sweep including `Decimal::MIN` and `Decimal::MAX`.
- Ciphertext-level order tests:
  - Order across dramatic magnitudes.
  - Sign-class ordering at extremes (`MIN < -1 < 0 < 1 < MAX`).
  - Smallest positive (`1e-28`) sorts above zero.
  - Vec sort consistency between plaintext sort and ciphertext sort.
- Hex round-trip via `OreOutput::to_bytes` / `OreOutput::from_slice`.
- Quickcheck:
  - `prop_decimal_cmp_consistent` — ORE matches `Decimal::cmp`.
  - `prop_decimal_cmp_antisymmetric`.
  - `prop_decimal_negation_symmetry`.
  - `prop_decimal_sign_class`.
  - `prop_decimal_equivalent_forms_collide` — distinct `(mantissa, scale)` representations of the same value collide.

## Out of scope

Decryption of `Decimal` ciphertexts. BlockORE is encrypt-only by construction.

## References

- Lewi & Wu, *Order-Revealing Encryption: New Constructions, Applications, and Lower Bounds* (2016) — `https://eprint.iacr.org/2016/612.pdf`.
