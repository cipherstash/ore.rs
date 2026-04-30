# orderable-bytes

Canonical, order-preserving fixed-length byte encodings for plaintext types.

Each module exposes a `to_orderable_bytes` function and an `ENCODED_LEN` constant. The bytes returned have the property that **byte-wise lexicographic order agrees with the type's natural total order**, and **byte equality agrees with value equality**. The crate is scheme-agnostic — these encodings are intended for any comparison-as-bytes consumer that wants to preserve plaintext order on ciphertexts or digests:

- `ore-rs` BlockORE (this workspace)
- An order-preserving encryption (OPE) construction
- An ordered hash

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

## Constant time

The `Decimal` encoder is constant-time with respect to its input: straight-line code with fixed-iteration loops, branchless mask arithmetic, no hardware integer division (`udiv` has data-dependent latency on several real ISAs), no early returns on zero, no calls to `Decimal::normalize`. Timing does not distinguish the input's sign, zero-ness, digit count, trailing-zero count, or scale.

The `chrono` encoders are likewise straight-line — `NaiveDate` is two arithmetic ops on an `i32` and a big-endian byte conversion; `DateTime<Utc>` is a sign-flip on the `i64` timestamp and two BE serialisations. Hardware-level constant-time properties depend on the underlying chrono getters being CT (`timestamp`, `timestamp_subsec_nanos`, `num_days_from_ce`), which they are on tier-1 ISAs.

## License

See [LICENCE](../../LICENCE).
