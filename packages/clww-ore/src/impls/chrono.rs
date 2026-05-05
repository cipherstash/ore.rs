//! OPE encryption for `chrono::NaiveDate` and `chrono::DateTime<Utc>`, gated
//! behind the `chrono` feature.
//!
//! Both impls delegate to the shared `[u8; N]` impl in [`super::byte_array`]
//! after canonicalising via the matching [`orderable_bytes::chrono`]
//! encoders. See those modules for encoding details and ordering
//! guarantees.
//!
//! - `NaiveDate` → `OpeCllw8V1<33>` (4 plaintext bytes × 8 + 1)
//! - `DateTime<Utc>` → `OpeCllw8V1<97>` (12 plaintext bytes × 8 + 1)

use crate::{CllwOpeEncrypt, Error, Key, OpeCllw8V1};
use ::chrono::{DateTime, NaiveDate, Utc};
use orderable_bytes::ToOrderableBytes;

impl CllwOpeEncrypt for NaiveDate {
    type Output = OpeCllw8V1<{ <Self as ToOrderableBytes>::ENCODED_LEN * 8 + 1 }>;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        self.to_orderable_bytes().encrypt_ope_with_salt(key, salt)
    }
}

impl CllwOpeEncrypt for DateTime<Utc> {
    type Output = OpeCllw8V1<{ <Self as ToOrderableBytes>::ENCODED_LEN * 8 + 1 }>;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        self.to_orderable_bytes().encrypt_ope_with_salt(key, salt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::chrono::{Datelike, NaiveDate, TimeZone, Utc};
    use hex::FromHex;
    use quickcheck::{quickcheck, Arbitrary, Gen};
    use std::cmp::Ordering;

    fn key() -> Key {
        Key::from([7u8; 32])
    }

    // ============================================================
    // NaiveDate
    // ============================================================

    fn ymd(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).unwrap()
    }

    fn encrypt_date(d: NaiveDate) -> OpeCllw8V1<33> {
        key().encrypt_ope(d).unwrap()
    }

    #[test]
    fn naive_date_pre_ce_sorts_below_ce() {
        let bce = ymd(-1, 12, 31);
        let ce = ymd(1, 1, 1);
        assert!(encrypt_date(bce) < encrypt_date(ce));
    }

    #[test]
    fn naive_date_preserves_order_across_dramatic_span() {
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
        let cts: Vec<_> = ascending.iter().copied().map(encrypt_date).collect();
        for window in cts.windows(2) {
            assert!(window[0] < window[1]);
        }
    }

    #[test]
    fn naive_date_vec_sort_consistent_with_plaintext_sort() {
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
            .map(|v| (encrypt_date(v), v))
            .collect();
        paired.sort_by_key(|a| a.0);
        let sorted_via_ct: Vec<_> = paired.into_iter().map(|(_, v)| v).collect();
        assert_eq!(sorted_via_ct, sorted_plain);
    }

    #[derive(Debug, Clone)]
    struct ArbDate(NaiveDate);

    impl Arbitrary for ArbDate {
        fn arbitrary(g: &mut Gen) -> Self {
            let valid_min = NaiveDate::MIN.num_days_from_ce();
            let valid_max = NaiveDate::MAX.num_days_from_ce();
            let days = i32::arbitrary(g).clamp(valid_min, valid_max);
            ArbDate(NaiveDate::from_num_days_from_ce_opt(days).expect("clamped"))
        }
    }

    quickcheck! {
        fn prop_date_equal_inputs_produce_equal_ciphertexts(x: ArbDate) -> bool {
            let a = encrypt_date(x.0);
            let b = encrypt_date(x.0);
            a == b
        }

        fn prop_date_cmp_consistent(x: ArbDate, y: ArbDate) -> bool {
            let key = key();
            let a = key.encrypt_ope(x.0).unwrap();
            let b = key.encrypt_ope(y.0).unwrap();
            a.cmp(&b) == x.0.cmp(&y.0)
        }

        fn prop_date_cmp_antisymmetric(x: ArbDate, y: ArbDate) -> bool {
            let key = key();
            let a = key.encrypt_ope(x.0).unwrap();
            let b = key.encrypt_ope(y.0).unwrap();
            a.cmp(&b) == b.cmp(&a).reverse()
        }

        fn prop_date_length_invariant(x: ArbDate) -> bool {
            let ct = key().encrypt_ope(x.0).unwrap();
            ct.as_ref().len() == 33
        }

        fn prop_date_length_independent_of_key(x: ArbDate) -> bool {
            let a = Key::from([0u8; 32]).encrypt_ope(x.0).unwrap();
            let b = Key::from([255u8; 32]).encrypt_ope(x.0).unwrap();
            a.as_ref().len() == b.as_ref().len()
        }

        fn prop_date_hex_round_trip(x: ArbDate) -> bool {
            let ct = key().encrypt_ope(x.0).unwrap();
            let hex_str = hex::encode(ct.as_ref());
            let ct2 = OpeCllw8V1::<33>::from_hex(&hex_str).unwrap();
            ct == ct2
        }

        fn prop_date_salt_differs(x: ArbDate) -> bool {
            let key = key();
            let a = x.0.encrypt_ope_with_salt(&key, Some(b"domain1")).unwrap();
            let b = x.0.encrypt_ope_with_salt(&key, Some(b"domain2")).unwrap();
            a != b
        }

        fn prop_date_salt_preserves_order(x: ArbDate, y: ArbDate) -> bool {
            let key = key();
            let salt = b"some-domain";
            let a = x.0.encrypt_ope_with_salt(&key, Some(salt)).unwrap();
            let b = y.0.encrypt_ope_with_salt(&key, Some(salt)).unwrap();
            a.cmp(&b) == x.0.cmp(&y.0)
        }
    }

    // ============================================================
    // DateTime<Utc>
    // ============================================================

    fn dt(secs: i64, nanos: u32) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, nanos).single().unwrap()
    }

    fn encrypt_dt(d: DateTime<Utc>) -> OpeCllw8V1<97> {
        key().encrypt_ope(d).unwrap()
    }

    #[test]
    fn datetime_utc_pre_epoch_sorts_below_post_epoch() {
        let pre = dt(-1, 999_999_999);
        let post = dt(0, 0);
        assert!(encrypt_dt(pre) < encrypt_dt(post));
    }

    #[test]
    fn datetime_utc_subsecond_ordering() {
        let a = dt(100, 100);
        let b = dt(100, 200);
        let c = dt(101, 0);
        let cts = [encrypt_dt(a), encrypt_dt(b), encrypt_dt(c)];
        assert!(cts[0] < cts[1]);
        assert!(cts[1] < cts[2]);
    }

    #[test]
    fn datetime_utc_equal_inputs_produce_equal_ciphertexts() {
        let a = encrypt_dt(dt(123_456, 789));
        let b = encrypt_dt(dt(123_456, 789));
        assert_eq!(a, b);
    }

    #[test]
    fn datetime_utc_dramatic_span_preserves_order() {
        // Range bounded by what chrono accepts (~year ±262143). We use
        // DateTime::MIN_UTC / MAX_UTC for the extremes and varied magnitudes
        // in between.
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
        let cts: Vec<_> = ascending.iter().copied().map(encrypt_dt).collect();
        for window in cts.windows(2) {
            assert!(window[0] < window[1]);
        }
    }

    #[test]
    fn datetime_utc_vec_sort_consistent_with_plaintext_sort() {
        let values = vec![
            dt(0, 0),
            dt(-1, 999_999_999),
            dt(1_000_000_000, 0),
            dt(0, 1),
            dt(-1_000_000_000, 0),
            dt(1_000_000_000, 1),
        ];
        let mut sorted_plain = values.clone();
        sorted_plain.sort();
        let mut paired: Vec<_> = values.iter().copied().map(|v| (encrypt_dt(v), v)).collect();
        paired.sort_by_key(|a| a.0);
        let sorted_via_ct: Vec<_> = paired.into_iter().map(|(_, v)| v).collect();
        assert_eq!(sorted_via_ct, sorted_plain);
    }

    #[derive(Debug, Clone)]
    struct ArbDateTime(DateTime<Utc>);

    impl Arbitrary for ArbDateTime {
        fn arbitrary(g: &mut Gen) -> Self {
            // chrono accepts a wide i64 seconds range. Generate any i64 then
            // fall back to the epoch if it lands outside the supported range.
            let secs = i64::arbitrary(g);
            // Subsec in 0..2e9 to cover leap-second second-half values too.
            let nanos = u32::arbitrary(g) % 2_000_000_000;
            let dt = DateTime::<Utc>::from_timestamp(secs, nanos)
                .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap());
            ArbDateTime(dt)
        }
    }

    quickcheck! {
        fn prop_datetime_determinism(x: ArbDateTime) -> bool {
            let key = key();
            let a = key.encrypt_ope(x.0).unwrap();
            let b = key.encrypt_ope(x.0).unwrap();
            a == b
        }

        fn prop_datetime_cmp_consistent(x: ArbDateTime, y: ArbDateTime) -> bool {
            let key = key();
            let a = key.encrypt_ope(x.0).unwrap();
            let b = key.encrypt_ope(y.0).unwrap();
            a.cmp(&b) == x.0.cmp(&y.0)
        }

        fn prop_datetime_cmp_antisymmetric(x: ArbDateTime, y: ArbDateTime) -> bool {
            let key = key();
            let a = key.encrypt_ope(x.0).unwrap();
            let b = key.encrypt_ope(y.0).unwrap();
            a.cmp(&b) == b.cmp(&a).reverse()
        }

        fn prop_datetime_sign_class(x: ArbDateTime) -> bool {
            let key = key();
            let epoch = key.encrypt_ope(DateTime::<Utc>::from_timestamp(0, 0).unwrap()).unwrap();
            let ct = key.encrypt_ope(x.0).unwrap();
            let epoch_dt = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
            match x.0.cmp(&epoch_dt) {
                Ordering::Less => ct < epoch,
                Ordering::Equal => ct == epoch,
                Ordering::Greater => ct > epoch,
            }
        }

        fn prop_datetime_length_invariant(x: ArbDateTime) -> bool {
            let ct = key().encrypt_ope(x.0).unwrap();
            ct.as_ref().len() == 97
        }

        fn prop_datetime_length_independent_of_key(x: ArbDateTime) -> bool {
            let a = Key::from([0u8; 32]).encrypt_ope(x.0).unwrap();
            let b = Key::from([255u8; 32]).encrypt_ope(x.0).unwrap();
            a.as_ref().len() == b.as_ref().len()
        }

        fn prop_datetime_hex_round_trip(x: ArbDateTime) -> bool {
            let ct = key().encrypt_ope(x.0).unwrap();
            let hex_str = hex::encode(ct.as_ref());
            let ct2 = OpeCllw8V1::<97>::from_hex(&hex_str).unwrap();
            ct == ct2
        }

        fn prop_datetime_salt_differs(x: ArbDateTime) -> bool {
            let key = key();
            let a = x.0.encrypt_ope_with_salt(&key, Some(b"domain1")).unwrap();
            let b = x.0.encrypt_ope_with_salt(&key, Some(b"domain2")).unwrap();
            a != b
        }

        fn prop_datetime_salt_preserves_order(x: ArbDateTime, y: ArbDateTime) -> bool {
            let key = key();
            let salt = b"some-domain";
            let a = x.0.encrypt_ope_with_salt(&key, Some(salt)).unwrap();
            let b = y.0.encrypt_ope_with_salt(&key, Some(salt)).unwrap();
            a.cmp(&b) == x.0.cmp(&y.0)
        }
    }
}
