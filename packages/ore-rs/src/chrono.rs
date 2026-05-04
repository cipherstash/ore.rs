//! ORE encryption for `chrono::NaiveDate` and `chrono::DateTime<Utc>`,
//! gated behind the `chrono` feature.
//!
//! Wraps the canonical fixed-length byte encodings from
//! [`orderable_bytes::chrono`] in [`OreEncrypt`] impls, feeding the
//! plaintext bytes through the existing fixed-N ORE machinery (`N = 4` for
//! `NaiveDate`, `N = 12` for `DateTime<Utc>`). See the
//! `orderable_bytes::chrono` module docs for encoding details and
//! ordering properties.

use crate::ciphertext::*;
use crate::{OreCipher, OreEncrypt, OreError};
use ::chrono::{DateTime, NaiveDate, Utc};
use orderable_bytes::ToOrderableBytes;

const NAIVE_DATE_LEN: usize = <NaiveDate as ToOrderableBytes>::ENCODED_LEN;
const DATETIME_UTC_LEN: usize = <DateTime<Utc> as ToOrderableBytes>::ENCODED_LEN;

impl<T: OreCipher> OreEncrypt<T> for NaiveDate {
    type LeftOutput = Left<T, NAIVE_DATE_LEN>;
    type FullOutput = CipherText<T, NAIVE_DATE_LEN>;

    fn encrypt_left(&self, cipher: &T) -> Result<Self::LeftOutput, OreError> {
        cipher.encrypt_left(&self.to_orderable_bytes())
    }

    fn encrypt(&self, cipher: &T) -> Result<Self::FullOutput, OreError> {
        cipher.encrypt(&self.to_orderable_bytes())
    }
}

impl<T: OreCipher> OreEncrypt<T> for DateTime<Utc> {
    type LeftOutput = Left<T, DATETIME_UTC_LEN>;
    type FullOutput = CipherText<T, DATETIME_UTC_LEN>;

    fn encrypt_left(&self, cipher: &T) -> Result<Self::LeftOutput, OreError> {
        cipher.encrypt_left(&self.to_orderable_bytes())
    }

    fn encrypt(&self, cipher: &T) -> Result<Self::FullOutput, OreError> {
        cipher.encrypt(&self.to_orderable_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::bit2::OreAes128ChaCha20;
    use ::chrono::{NaiveDate, TimeZone, Utc};
    use hex_literal::hex;
    use quickcheck::{Arbitrary, Gen};

    fn cipher() -> OreAes128ChaCha20 {
        let k1: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        let k2: [u8; 16] = hex!("0f0e0d0c 0b0a0908 07060504 03020100");
        OreCipher::init(&k1, &k2).unwrap()
    }

    // ============================================================
    // NaiveDate
    // ============================================================

    fn ymd(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).unwrap()
    }

    #[test]
    fn naive_date_pre_ce_sorts_below_ce() {
        let ore = cipher();
        let bce = ymd(-1, 12, 31).encrypt(&ore).unwrap();
        let ce = ymd(1, 1, 1).encrypt(&ore).unwrap();
        assert!(bce < ce);
    }

    #[test]
    fn naive_date_preserves_order_across_dramatic_span() {
        let ore = cipher();
        let ascending = [
            NaiveDate::MIN,
            ymd(-10000, 1, 1),
            ymd(-1, 1, 1),
            ymd(1, 1, 1),
            ymd(1970, 1, 1),
            ymd(2000, 1, 1),
            ymd(2026, 4, 29),
            ymd(10000, 1, 1),
            NaiveDate::MAX,
        ];
        let cts: Vec<_> = ascending.iter().map(|d| d.encrypt(&ore).unwrap()).collect();
        for window in cts.windows(2) {
            assert!(window[0] < window[1]);
        }
    }

    #[test]
    fn naive_date_vec_sort_consistent_with_plaintext_sort() {
        let ore = cipher();
        let values = vec![
            ymd(2000, 1, 1),
            ymd(1, 1, 1),
            ymd(1970, 1, 1),
            ymd(-100, 6, 15),
            ymd(2026, 4, 29),
            NaiveDate::MIN,
            NaiveDate::MAX,
            ymd(-1, 12, 31),
        ];
        let mut sorted_plain = values.clone();
        sorted_plain.sort();
        let mut paired: Vec<_> = values
            .iter()
            .copied()
            .map(|v| (v.encrypt(&ore).unwrap(), v))
            .collect();
        paired.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        let sorted_via_ct: Vec<_> = paired.into_iter().map(|(_, v)| v).collect();
        assert_eq!(sorted_via_ct, sorted_plain);
    }

    #[derive(Debug, Clone)]
    struct ArbDate(NaiveDate);

    impl Arbitrary for ArbDate {
        fn arbitrary(g: &mut Gen) -> Self {
            use ::chrono::Datelike;
            let valid_min = NaiveDate::MIN.num_days_from_ce();
            let valid_max = NaiveDate::MAX.num_days_from_ce();
            let days = i32::arbitrary(g).clamp(valid_min, valid_max);
            ArbDate(NaiveDate::from_num_days_from_ce_opt(days).expect("clamped"))
        }
    }

    quickcheck! {
        fn prop_date_cmp_consistent(x: ArbDate, y: ArbDate) -> bool {
            let ore = cipher();
            let a = x.0.encrypt(&ore).unwrap();
            let b = y.0.encrypt(&ore).unwrap();
            a.partial_cmp(&b).unwrap() == x.0.cmp(&y.0)
        }
    }

    // ============================================================
    // DateTime<Utc>
    // ============================================================

    fn dt(secs: i64, nanos: u32) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, nanos).single().unwrap()
    }

    #[test]
    fn datetime_utc_pre_epoch_sorts_below_post_epoch() {
        let ore = cipher();
        let pre = dt(-1, 999_999_999).encrypt(&ore).unwrap();
        let post = dt(0, 0).encrypt(&ore).unwrap();
        assert!(pre < post);
    }

    #[test]
    fn datetime_utc_subsecond_ordering() {
        let ore = cipher();
        let a = dt(100, 100).encrypt(&ore).unwrap();
        let b = dt(100, 200).encrypt(&ore).unwrap();
        let c = dt(101, 0).encrypt(&ore).unwrap();
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn datetime_utc_dramatic_span_preserves_order() {
        let ore = cipher();
        let ascending = [
            DateTime::<Utc>::MIN_UTC,
            dt(-1_000_000_000_000, 0),
            dt(-1_000_000_000, 0),
            dt(-1, 999_999_999),
            dt(0, 0),
            dt(0, 1),
            dt(1_000_000_000, 0),
            dt(1_000_000_000_000, 0),
            DateTime::<Utc>::MAX_UTC,
        ];
        let cts: Vec<_> = ascending.iter().map(|d| d.encrypt(&ore).unwrap()).collect();
        for window in cts.windows(2) {
            assert!(window[0] < window[1]);
        }
    }

    #[derive(Debug, Clone)]
    struct ArbDateTime(DateTime<Utc>);

    impl Arbitrary for ArbDateTime {
        fn arbitrary(g: &mut Gen) -> Self {
            let secs = i64::arbitrary(g);
            let nanos = u32::arbitrary(g) % 2_000_000_000;
            let dt = DateTime::<Utc>::from_timestamp(secs, nanos)
                .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap());
            ArbDateTime(dt)
        }
    }

    quickcheck! {
        fn prop_datetime_cmp_consistent(x: ArbDateTime, y: ArbDateTime) -> bool {
            let ore = cipher();
            let a = x.0.encrypt(&ore).unwrap();
            let b = y.0.encrypt(&ore).unwrap();
            a.partial_cmp(&b).unwrap() == x.0.cmp(&y.0)
        }
    }
}
