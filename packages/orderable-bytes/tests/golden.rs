//! Golden vectors: the exact bytes `to_orderable_bytes` produces today.
//!
//! These encodings are a storage format. Order terms derived from them are
//! stored in customer databases (cipherstash-client builds its ORE terms on
//! this crate), so any change to these bytes silently breaks range queries
//! over existing data. A failing vector here means a released encoding
//! changed: fix the code, never the vector.
//!
//! The variable-length encodings are the value's own bytes; their rows
//! pin that no transform or normalisation is ever added.
//!
//! The NaN rows pin current behaviour, not a promise about NaN ordering (see
//! the `primitive` module docs): the raw bit pattern passes through.

use orderable_bytes::{FixedOrderableBytes, OrderableBytes};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn check<T: FixedOrderableBytes>(label: &str, value: T, expected: &str) {
    let actual = value.to_fixed_orderable_bytes();
    assert_eq!(
        actual.as_ref().len(),
        T::ENCODED_LEN,
        "{label}: encoded length"
    );
    assert_eq!(hex(actual.as_ref()), expected, "{label}");
    assert_eq!(
        value.to_orderable_bytes().as_ref(),
        actual.as_ref(),
        "{label}: to_orderable_bytes and to_fixed_orderable_bytes agree"
    );
}

#[test]
fn u8_golden() {
    for (value, expected) in [(0u8, "00"), (1u8, "01"), (90u8, "5a"), (255u8, "ff")] {
        check(&value.to_string(), value, expected);
    }
}

#[test]
fn i8_golden() {
    for (value, expected) in [
        (i8::MIN, "00"),
        (0i8, "80"),
        (1i8, "81"),
        (90i8, "da"),
        (127i8, "ff"),
        (-1i8, "7f"),
    ] {
        check(&value.to_string(), value, expected);
    }
}

#[test]
fn u16_golden() {
    for (value, expected) in [
        (0u16, "0000"),
        (1u16, "0001"),
        (90u16, "005a"),
        (65535u16, "ffff"),
    ] {
        check(&value.to_string(), value, expected);
    }
}

#[test]
fn i16_golden() {
    for (value, expected) in [
        (i16::MIN, "0000"),
        (0i16, "8000"),
        (1i16, "8001"),
        (90i16, "805a"),
        (32767i16, "ffff"),
        (-1i16, "7fff"),
    ] {
        check(&value.to_string(), value, expected);
    }
}

#[test]
fn u32_golden() {
    for (value, expected) in [
        (0u32, "00000000"),
        (1u32, "00000001"),
        (90u32, "0000005a"),
        (u32::MAX, "ffffffff"),
    ] {
        check(&value.to_string(), value, expected);
    }
}

#[test]
fn i32_golden() {
    for (value, expected) in [
        (i32::MIN, "00000000"),
        (0i32, "80000000"),
        (1i32, "80000001"),
        (90i32, "8000005a"),
        (i32::MAX, "ffffffff"),
        (-1i32, "7fffffff"),
    ] {
        check(&value.to_string(), value, expected);
    }
}

#[test]
fn u64_golden() {
    for (value, expected) in [
        (0u64, "0000000000000000"),
        (1u64, "0000000000000001"),
        (90u64, "000000000000005a"),
        (u64::MAX, "ffffffffffffffff"),
    ] {
        check(&value.to_string(), value, expected);
    }
}

#[test]
fn i64_golden() {
    for (value, expected) in [
        (i64::MIN, "0000000000000000"),
        (0i64, "8000000000000000"),
        (1i64, "8000000000000001"),
        (90i64, "800000000000005a"),
        (i64::MAX, "ffffffffffffffff"),
        (-1i64, "7fffffffffffffff"),
    ] {
        check(&value.to_string(), value, expected);
    }
}

#[test]
fn u128_golden() {
    for (value, expected) in [
        (0u128, "00000000000000000000000000000000"),
        (1u128, "00000000000000000000000000000001"),
        (90u128, "0000000000000000000000000000005a"),
        (u128::MAX, "ffffffffffffffffffffffffffffffff"),
    ] {
        check(&value.to_string(), value, expected);
    }
}

#[test]
fn i128_golden() {
    for (value, expected) in [
        (i128::MIN, "00000000000000000000000000000000"),
        (0i128, "80000000000000000000000000000000"),
        (1i128, "80000000000000000000000000000001"),
        (90i128, "8000000000000000000000000000005a"),
        (i128::MAX, "ffffffffffffffffffffffffffffffff"),
        (-1i128, "7fffffffffffffffffffffffffffffff"),
    ] {
        check(&value.to_string(), value, expected);
    }
}

#[test]
fn bool_golden() {
    check("false", false, "00");
    check("true", true, "01");
}

#[test]
fn char_golden() {
    for (value, expected) in [
        ('\u{0000}', "00000000"),
        ('\u{0061}', "00000061"),
        ('\u{007A}', "0000007a"),
        ('\u{00E9}', "000000e9"),
        ('\u{FFFF}', "0000ffff"),
        ('\u{10FFFF}', "0010ffff"),
    ] {
        check(&format!("U+{:04X}", value as u32), value, expected);
    }
}

#[test]
fn f32_golden() {
    for (label, value, expected) in [
        ("-inf", f32::NEG_INFINITY, "007fffff"),
        ("min", f32::MIN, "00800000"),
        ("-1", -1.0_f32, "407fffff"),
        ("-min_positive", -f32::MIN_POSITIVE, "7f7fffff"),
        ("-subnormal", -f32::from_bits(1), "7ffffffe"),
        ("-0", -0.0_f32, "80000000"),
        ("0", 0.0_f32, "80000000"),
        ("subnormal", f32::from_bits(1), "80000001"),
        ("min_positive", f32::MIN_POSITIVE, "80800000"),
        ("1", 1.0_f32, "bf800000"),
        ("max", f32::MAX, "ff7fffff"),
        ("inf", f32::INFINITY, "ff800000"),
        ("nan", f32::NAN, "ffc00000"),
        ("-nan", f32::from_bits(0xffc0_0000), "003fffff"),
    ] {
        check(label, value, expected);
    }
}

#[test]
fn f64_golden() {
    for (label, value, expected) in [
        ("-inf", f64::NEG_INFINITY, "000fffffffffffff"),
        ("min", f64::MIN, "0010000000000000"),
        ("-1", -1.0_f64, "400fffffffffffff"),
        ("-min_positive", -f64::MIN_POSITIVE, "7fefffffffffffff"),
        ("-subnormal", -f64::from_bits(1), "7ffffffffffffffe"),
        ("-0", -0.0_f64, "8000000000000000"),
        ("0", 0.0_f64, "8000000000000000"),
        ("subnormal", f64::from_bits(1), "8000000000000001"),
        ("min_positive", f64::MIN_POSITIVE, "8010000000000000"),
        ("1", 1.0_f64, "bff0000000000000"),
        ("max", f64::MAX, "ffefffffffffffff"),
        ("inf", f64::INFINITY, "fff0000000000000"),
        ("nan", f64::NAN, "fff8000000000000"),
        (
            "-nan",
            f64::from_bits(0xfff8_0000_0000_0000),
            "0007ffffffffffff",
        ),
    ] {
        check(label, value, expected);
    }
}

#[cfg(feature = "decimal")]
#[test]
fn decimal_golden() {
    use rust_decimal::Decimal;
    use std::str::FromStr;

    // `1`, `1.0` and `1.00` share bytes, as do `0` and `-0`: the encoding
    // canonicalises scale and the sign of zero.
    for (value, expected) in [
        ("0", "8000000000000000000000000000"),
        ("-0", "8000000000000000000000000000"),
        ("1", "c000204fce5e3e25026110000000"),
        ("1.0", "c000204fce5e3e25026110000000"),
        ("1.00", "c000204fce5e3e25026110000000"),
        ("-1", "3fffdfb031a1c1dafd9eefffffff"),
        ("0.1", "bf00204fce5e3e25026110000000"),
        ("1.05", "c00021ed657c8e0d427f84000000"),
        ("1.5", "c0003077b58d5d37839198000000"),
        ("123.456", "c20027e40a7d082776daa0000000"),
        ("-123.456", "3dffd81bf582f7d889255fffffff"),
        (
            "0.0000000000000000000000000001",
            "a400204fce5e3e25026110000000",
        ),
        (
            "-0.0000000000000000000000000001",
            "5bffdfb031a1c1dafd9eefffffff",
        ),
        (
            "79228162514264337593543950335",
            "dc00ffffffffffffffffffffffff",
        ),
        (
            "-79228162514264337593543950335",
            "23ff000000000000000000000000",
        ),
    ] {
        check(value, Decimal::from_str(value).unwrap(), expected);
    }
}

#[cfg(feature = "chrono")]
#[test]
fn naive_date_golden() {
    use chrono::NaiveDate;

    for (label, value, expected) in [
        ("MIN", NaiveDate::MIN, "7a4b07af"),
        (
            "0001-01-01",
            NaiveDate::from_ymd_opt(1, 1, 1).unwrap(),
            "80000001",
        ),
        (
            "1970-01-01",
            NaiveDate::from_ymd_opt(1970, 1, 1).unwrap(),
            "800af93b",
        ),
        (
            "2000-02-29",
            NaiveDate::from_ymd_opt(2000, 2, 29).unwrap(),
            "800b2443",
        ),
        (
            "9999-12-31",
            NaiveDate::from_ymd_opt(9999, 12, 31).unwrap(),
            "8037b9db",
        ),
        ("MAX", NaiveDate::MAX, "85b4f577"),
    ] {
        check(label, value, expected);
    }
}

#[cfg(feature = "chrono")]
#[test]
fn datetime_utc_golden() {
    use chrono::{DateTime, TimeZone, Utc};

    for (label, value, expected) in [
        (
            "MIN_UTC",
            DateTime::<Utc>::MIN_UTC,
            "7ffff86b730dee0000000000",
        ),
        (
            "epoch-1ns",
            Utc.timestamp_opt(-1, 999_999_999).unwrap(),
            "7fffffffffffffff3b9ac9ff",
        ),
        (
            "epoch",
            Utc.timestamp_opt(0, 0).unwrap(),
            "800000000000000000000000",
        ),
        (
            "2026-10-08T12:41:36.789012345Z",
            Utc.timestamp_opt(1_791_463_296, 789_012_345).unwrap(),
            "800000006ac78f802f075f79",
        ),
        (
            "2016-12-31T23:59:60.5Z (leap second)",
            Utc.timestamp_opt(1_483_228_799, 1_500_000_000).unwrap(),
            "800000005868467f59682f00",
        ),
        (
            "MAX_UTC",
            DateTime::<Utc>::MAX_UTC,
            "800007779a0a6b7f3b9ac9ff",
        ),
    ] {
        check(label, value, expected);
    }
}

#[test]
fn str_golden() {
    for (value, expected) in [
        ("", ""),
        ("a", "61"),
        ("a\0", "6100"),
        ("\u{e9}", "c3a9"),
        ("e\u{301}", "65cc81"),
        ("\u{10ffff}", "f48fbfbf"),
    ] {
        assert_eq!(hex(value.to_orderable_bytes()), expected, "{value:?}");
        assert_eq!(
            hex(String::from(value).to_orderable_bytes()),
            expected,
            "{value:?}"
        );
    }
}

#[test]
fn bytes_golden() {
    for value in [&b""[..], b"\0", b"\xff\x00\x01"] {
        assert_eq!(value.to_orderable_bytes(), value);
        assert_eq!(value.to_vec().to_orderable_bytes(), value);
    }
}

#[test]
fn byte_array_golden() {
    check("[u8; 0]", [0u8; 0], "");
    check("[u8; 3]", [0x00u8, 0x7f, 0xff], "007fff");
    check("[u8; 16]", [0xabu8; 16], "abababababababababababababababab");
}
