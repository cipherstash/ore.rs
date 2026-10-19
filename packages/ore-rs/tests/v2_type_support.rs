//! Public API checks for the fixed-length types added in issue #124.

use ore_rs::scheme::chained::{ChainedCipherText, ChainedLeft, OreAes128Bit6ChainedChaCha20};
use ore_rs::{OreEncrypt, OreOutput};
use std::fmt::Debug;

fn check_chained_order<T, const BLOCKS: usize>(values: &[T])
where
    T: Debug
        + PartialOrd
        + OreEncrypt<
            OreAes128Bit6ChainedChaCha20,
            FullOutput = ChainedCipherText<BLOCKS>,
            LeftOutput = ChainedLeft<BLOCKS>,
        >,
{
    let cipher =
        OreAes128Bit6ChainedChaCha20::init_with_salt(&[0x2b; 16], b"type-support").unwrap();
    let full: Vec<_> = values
        .iter()
        .map(|value| value.encrypt(&cipher).unwrap().to_bytes())
        .collect();
    let left: Vec<_> = values
        .iter()
        .map(|value| value.encrypt_left(&cipher).unwrap().to_bytes())
        .collect();
    for (i, a) in values.iter().enumerate() {
        for (j, b) in values.iter().enumerate() {
            let expected = a.partial_cmp(b);
            assert!(expected.is_some());
            assert_eq!(
                ChainedCipherText::<BLOCKS>::compare_raw_slices(&full[i], &full[j]),
                expected,
                "full: {a:?} vs {b:?}"
            );
            assert_eq!(
                ChainedCipherText::<BLOCKS>::compare_left_to_full(&left[i], &full[j]),
                expected,
                "query: {a:?} vs {b:?}"
            );
        }
    }
}

#[test]
fn chained_floats_preserve_order_and_signed_zero_equality() {
    check_chained_order::<_, 6>(&[
        f32::NEG_INFINITY,
        -1.0,
        -0.0,
        0.0,
        f32::MIN_POSITIVE,
        1.0,
        f32::INFINITY,
    ]);
    check_chained_order::<_, 11>(&[
        f64::NEG_INFINITY,
        -1.0,
        -0.0,
        0.0,
        f64::MIN_POSITIVE,
        1.0,
        f64::INFINITY,
    ]);
}

#[cfg(feature = "decimal")]
#[test]
fn chained_decimals_preserve_order_and_equivalent_representations() {
    use rust_decimal::Decimal;

    check_chained_order::<_, 19>(&[
        Decimal::MIN,
        Decimal::new(-100, 2),
        Decimal::new(-1, 0),
        Decimal::from_parts(0, 0, 0, true, 5),
        Decimal::ZERO,
        Decimal::new(1, 28),
        Decimal::new(1, 0),
        Decimal::new(10, 1),
        Decimal::new(100, 2),
        Decimal::new(101, 2),
        Decimal::MAX,
    ]);
}

#[cfg(feature = "chrono")]
fn dates() -> [chrono::NaiveDate; 8] {
    use chrono::NaiveDate;

    [
        NaiveDate::MIN,
        NaiveDate::from_ymd_opt(-1, 12, 31).unwrap(),
        NaiveDate::from_ymd_opt(1, 1, 1).unwrap(),
        NaiveDate::from_ymd_opt(1969, 12, 31).unwrap(),
        NaiveDate::from_ymd_opt(1970, 1, 1).unwrap(),
        NaiveDate::from_ymd_opt(2000, 2, 29).unwrap(),
        NaiveDate::from_ymd_opt(2000, 3, 1).unwrap(),
        NaiveDate::MAX,
    ]
}

#[cfg(feature = "chrono")]
#[test]
fn chained_dates_preserve_order() {
    check_chained_order::<_, 6>(&dates());
}

#[cfg(feature = "chrono")]
#[test]
fn bit6_dates_preserve_order_and_use_six_blocks() {
    use chrono::Datelike;
    use ore_rs::scheme::bit2_w6::OreAes128Bit6ChaCha20;
    use ore_rs::{CipherText, Left};

    let cipher = OreAes128Bit6ChaCha20::init_with_salt(&[0x2b; 16], b"dates").unwrap();
    let dates = dates();
    let encrypted: Vec<CipherText<OreAes128Bit6ChaCha20, 6>> = dates
        .iter()
        .map(|date| date.encrypt(&cipher).unwrap())
        .collect();
    for (i, a) in dates.iter().enumerate() {
        for (j, b) in dates.iter().enumerate() {
            assert_eq!(encrypted[i].cmp(&encrypted[j]), a.cmp(b));
        }
        let full = encrypted[i].to_bytes();
        let left: Left<OreAes128Bit6ChaCha20, 6> = a.encrypt_left(&cipher).unwrap();
        assert_eq!(
            CipherText::<OreAes128Bit6ChaCha20, 6>::from_slice(&full)
                .unwrap()
                .to_bytes(),
            full
        );
        assert_eq!(
            Left::<OreAes128Bit6ChaCha20, 6>::from_slice(&left.to_bytes())
                .unwrap()
                .to_bytes(),
            left.to_bytes()
        );
        assert!(CipherText::<OreAes128Bit6ChaCha20, 11>::from_slice(&full).is_err());
        assert!(Left::<OreAes128Bit6ChaCha20, 11>::from_slice(&left.to_bytes()).is_err());
        // NaiveDate's canonical encoding is its signed day number.
        assert_eq!(
            left.to_bytes(),
            a.num_days_from_ce()
                .encrypt_left(&cipher)
                .unwrap()
                .to_bytes()
        );
    }
}

#[cfg(feature = "chrono")]
#[test]
fn chained_timestamps_preserve_subseconds_and_leap_seconds() {
    use chrono::{DateTime, Utc};

    check_chained_order::<_, 16>(&[
        DateTime::<Utc>::MIN_UTC,
        DateTime::from_timestamp(-1, 999_999_999).unwrap(),
        DateTime::from_timestamp(0, 0).unwrap(),
        DateTime::from_timestamp(0, 1).unwrap(),
        DateTime::from_timestamp(0, 2).unwrap(),
        DateTime::from_timestamp(59, 999_999_999).unwrap(),
        DateTime::from_timestamp(59, 1_000_000_000).unwrap(),
        DateTime::from_timestamp(59, 1_500_000_000).unwrap(),
        DateTime::from_timestamp(60, 0).unwrap(),
        DateTime::<Utc>::MAX_UTC,
    ]);
}
