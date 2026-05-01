# orderable-bytes

Pre-encryption byte encodings for **order-revealing encryption** (ORE) and **order-preserving encryption** (OPE) schemes.

ORE and OPE both produce ciphertexts whose byte-wise comparison reveals the order of the underlying plaintexts. To exploit that property you first need to convert your plaintext — a `Decimal`, a `NaiveDate`, a `DateTime<Utc>`, … — into a canonical byte sequence whose lexicographic order already matches the value's natural total order. **That conversion is what this crate does.** Plug the bytes into an ORE or OPE primitive and the resulting ciphertext inherits the same order and equality semantics as the original plaintext.

Each module exposes a `to_orderable_bytes` function and an `ENCODED_LEN` constant. The bytes have two guarantees:

- **byte-wise lexicographic order agrees with the type's natural total order**
- **byte equality agrees with value equality**

The crate is scheme-agnostic — the encodings drop into `ore-rs` BlockORE (this workspace), any OPE construction, an ordered hash, or anything else that compares as bytes.

## Supported types

Encoders are gated behind per-type feature flags so callers only pay for the dependencies they actually use.

| Feature  | Path                                            | Type                       | `ENCODED_LEN` |
|----------|-------------------------------------------------|----------------------------|---------------|
| `decimal`| `decimal::to_orderable_bytes`                   | `rust_decimal::Decimal`    | 14            |
| `chrono` | `chrono::naive_date::to_orderable_bytes`        | `chrono::NaiveDate`        | 4             |
| `chrono` | `chrono::datetime_utc::to_orderable_bytes`      | `chrono::DateTime<Utc>`    | 12            |

Each encoding canonicalises equivalent values to identical bytes — `1` ≡ `1.0` ≡ `1.00` for `Decimal`, `±0` collide, `NaiveDate` and `DateTime<Utc>` byte-equality matches their respective `Eq` impls — so consumers inherit value-equality semantics on the encoded form.

## Usage

```toml
[dependencies]
orderable-bytes = { version = "0.1", features = ["decimal", "chrono"] }
```

```rust
use orderable_bytes::decimal;
use rust_decimal::Decimal;
use std::str::FromStr;

let bytes = decimal::to_orderable_bytes(&Decimal::from_str("1.5").unwrap());
assert_eq!(bytes.len(), decimal::ENCODED_LEN);

// Byte-wise comparison matches Decimal::cmp
let a = decimal::to_orderable_bytes(&Decimal::from_str("1.05").unwrap());
let b = decimal::to_orderable_bytes(&Decimal::from_str("1.5").unwrap());
assert!(a < b);
```

## How the encoding works

Worked examples build the most reliable intuition. Byte values below are shown in decimal (0–255).

### `Decimal` — scientific-form encoding

A `Decimal` carries three fields internally — sign, scale (an unsigned exponent in `0..=28`), and a 96-bit mantissa — encoding the value `±mantissa × 10^(-scale)`. Crucially, the same numeric value can be stored multiple ways: `1` is `(0, 1)`, `1.0` is `(1, 10)`, `1.00` is `(2, 100)`. The encoder collapses these to one canonical form.

Pipeline:

1. **Strip trailing zeros.** Take `|mantissa|`, divide by 10 while the trailing digit is zero. This yields `(significand, trailing_count)` where `mantissa = significand × 10^trailing_count`. Now `1`, `1.0`, `1.00` all have `significand = 1`.
2. **Compute the leading-digit exponent:** `leading_exp = digits(significand) − 1 + trailing_count − scale`. This is the decimal position of the most significant digit. For `Decimal`, `leading_exp ∈ [-28, 28]`.
3. **Bias and pack the exponent.** `biased_exp = leading_exp + 64` lands in `[36, 92]`, fitting in 7 bits. Combined with a 1-bit sign flag, byte 0 = `(sign_bit << 7) | biased_exp`. For positives, byte 0 ∈ `[128 + 36, 128 + 92] = [164, 220]`.
4. **Pad the significand to 29 decimal digits.** `padded = significand × 10^(29 − digits(significand))`. This is the trick that makes byte ordering work — see below.
5. **Pack `padded` as a 104-bit big-endian integer** in bytes 1..=13.
6. **For negatives:** bitwise-NOT byte 0's low 7 bits and all of bytes 1..=13. Sign bit stays clear.
7. **Zero** short-circuits to `128 0 0 … 0` (sign bit set, everything else zero) — distinct from any non-zero plaintext (which has biased_exp ≥ 36).

#### Equivalent forms collide

`1`, `1.0`, `1.00` all become the same canonical `(significand=1, leading_exp=0)`:

```
1     :  (scale=0, mantissa=1)    → significand=1, trailing=0, leading_exp=0
1.0   :  (scale=1, mantissa=10)   → significand=1, trailing=1, leading_exp = 1-1+1-1 = 0
1.00  :  (scale=2, mantissa=100)  → significand=1, trailing=2, leading_exp = 1-1+2-2 = 0
```

All three produce the identical byte sequence:

```
192   0  32  79 206  94  62  37   2  97  16   0   0   0
```

Byte 0 = 192 = 128 + 64 (sign bit + biased_exp 64 = leading_exp 0). Bytes 1..=13 hold `1 × 10^28 = 10000000000000000000000000000` as a 104-bit big-endian integer.

`±0` collide too — the zero short-circuit ignores the sign field, so `+0` and `-0` both land on `128 0 0 … 0`.

#### Why the significand needs padding to 29 digits

This is the subtle part. Consider `1`, `1.05`, `1.5` — all three have `leading_exp = 0`, so they share byte 0. The discriminator is the mantissa region. If we packed the *raw* significand (right-justified) we'd get:

```
1     →  significand=1   →  …   0   0   1
1.05  →  significand=105 →  …   0   0 105
1.5   →  significand=15  →  …   0   0  15
```

Byte-compare those: `1 < 15 < 105`, but numerically `1 < 1.05 < 1.5`. **Wrong order** — `1.5` would land below `1.05`.

Padding fixes it. We multiply each significand by `10^(29 − digit_count)`, left-justifying the leading digit at decimal position 28:

```
1    × 10^28  =  10000000000000000000000000000
1.05 × 10^27  ×  ... (i.e. 105 × 10^26 = 10500000000000000000000000000)
1.5  × 10^27  ×  ... (i.e. 15  × 10^27 = 15000000000000000000000000000)
```

These three now compare correctly as plain unsigned integers. In bytes:

```
1     :  192   0 |  32  79 206  94  62  37   2  97  16   0   0   0
1.05  :  192   0 |  33 237 101 124 142  13  66 127 132   0   0   0
1.5   :  192   0 |  48 119 181 141  93  55 131 145 152   0   0   0
```

Byte 2: `32 < 33 < 48` ✓ — exactly the order we want.

The `Decimal` mantissa is u96 (29 decimal digits max), and `10^29` needs ~97 bits, so we use 104 bits (13 bytes) for the padded mantissa rather than 96 — a 96-bit field would overflow for ~87% of u96 mantissas.

#### Same significand, different exponent — only byte 0 differs

`0.001`, `1`, `100` all have `significand = 1` and so share the same mantissa region. Only byte 0 distinguishes them:

```
0.001 :  189   0 |  32  79 ...     biased_exp = 61   (leading_exp = -3)
1     :  192   0 |  32  79 ...     biased_exp = 64   (leading_exp =  0)
100   :  194   0 |  32  79 ...     biased_exp = 66   (leading_exp =  2)
```

Byte 0 strictly increases with the value.

#### Decimal::MAX

`Decimal::MAX = 79228162514264337593543950335` — a 29-digit positive integer. `leading_exp = 28`, biased = 92, byte 0 = 220. The 96-bit mantissa nearly fills the 13-byte region:

```
220   0 | 255 255 255 255 255 255 255 255 255 255 255 255
```

#### Negatives are byte-complements

`-1` is the bitwise NOT of `1` everywhere except the sign bit:

```
+1 :  192   0 |  32  79 206  94  62  37   2  97  16   0   0   0
-1 :   63 255 | 223 176  49 161 193 218 253 158 239 255 255 255
```

Bytes 1..=13: each `-1` byte equals `255 − (corresponding +1 byte)`. Byte 0: `192 = 128 + 64` for `+1`; `63 = 0 + (127 − 64)` for `-1` — the sign bit flips to 0 and the low 7 bits get inverted.

This automatic mirroring is what makes "more negative ⇒ smaller bytes" work for free, without any branchy "if negative then …" logic.

#### Sign-class separation

Byte 0 alone separates the three sign classes — they never overlap:

| Class | Byte 0 range |
|---|---|
| Negatives | `[35, 91]` (= `127 − [36, 92]`) |
| Zero | `128` |
| Positives | `[164, 220]` (= `128 + [36, 92]`) |

So `byte0 < 128 ⇔ negative`, `byte0 == 128 ⇔ zero`, `byte0 > 128 ⇔ positive`.

### `NaiveDate` — sign-flipped day count

Much simpler. `NaiveDate::num_days_from_ce()` returns an `i32` whose ordering matches chronological order. We sign-flip to `u32` (XOR with `1u32 << 31`) so big-endian byte serialisation gives a 4-byte plaintext where lex order = chronological order.

```
NaiveDate::MIN  →  i32 = -95,746,129  →  u32 = 0x7A4B07AF  →  bytes [122,  75,   7, 175]
year 1, day 1   →  i32 = 1            →  u32 = 0x80000001  →  bytes [128,   0,   0,   1]
1970-01-01      →  i32 = 719,163      →  u32 = 0x800AF93B  →  bytes [128,  10, 249,  59]
NaiveDate::MAX  →  i32 = 95,745,399   →  u32 = 0x85B4F577  →  bytes [133, 180, 245, 119]
```

The sign-flip puts the most-negative valid `i32` (the lower bound of `chrono`'s date range, around year -262144) at byte 0 = `122`, year 1 just above the `0x80` boundary, and the latest representable date (around year +262143) at byte 0 = `133`. Strictly increasing throughout.

### `DateTime<Utc>` — sign-flipped seconds, then nanos

`(secs: i64, subsec_nanos: u32)` becomes 12 bytes:

- Bytes 0..=7: `secs ^ (1u64 << 63)` as big-endian — sign-flips the i64 timestamp the same way `NaiveDate` does, putting all valid timestamps in `[0, u64::MAX]` ordered chronologically.
- Bytes 8..=11: `subsec_nanos` as big-endian — strict tiebreaker within a whole second. `chrono` returns values in `0..2_000_000_000` (the upper half is for leap-second moments), which fits in `u32` and preserves order.

```
1970-01-01T00:00:00Z              →  secs=0, nanos=0          →  [128,0,0,0,0,0,0,0,   0,0,0,0]
1970-01-01T00:00:00.000000001Z    →  secs=0, nanos=1          →  [128,0,0,0,0,0,0,0,   0,0,0,1]
1970-01-01T00:00:01Z              →  secs=1, nanos=0          →  [128,0,0,0,0,0,0,1,   0,0,0,0]
1969-12-31T23:59:59.999999999Z    →  secs=-1, nanos=999999999 →  [127,255,255,255,255,255,255,255, 59,154,201,255]
```

The encoding is just two concatenated big-endian integers, both already in the right monotone form.

## Constant time

The `Decimal` encoder is constant-time with respect to its input: straight-line code with fixed-iteration loops, branchless mask arithmetic, no hardware integer division (`udiv` has data-dependent latency on several real ISAs), no early returns on zero, no calls to `Decimal::normalize`. Timing does not distinguish the input's sign, zero-ness, digit count, trailing-zero count, or scale.

The `chrono` encoders are likewise straight-line — `NaiveDate` is two arithmetic ops on an `i32` and a big-endian byte conversion; `DateTime<Utc>` is a sign-flip on the `i64` timestamp and two BE serialisations. Hardware-level constant-time properties depend on the underlying chrono getters being CT (`timestamp`, `timestamp_subsec_nanos`, `num_days_from_ce`), which they are on tier-1 ISAs.

## License

See [LICENCE](../../LICENCE).
