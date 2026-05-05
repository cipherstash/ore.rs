//! Canonical, order-preserving fixed-length byte encodings for the
//! `chrono` types `NaiveDate` and `DateTime<Utc>`.
//!
//! Each submodule exposes an `ENCODED_LEN` constant and an
//! [`crate::ToOrderableBytes`] impl on its target type. The bytes
//! returned have the property that byte-wise lex comparison agrees with
//! chronological ordering (and byte equality with value equality), so
//! any comparison-as-bytes scheme (`ore-rs` BlockORE, OPE, an ordered
//! hash) inherits those properties on the resulting digest.

/// Order-preserving byte encoding for [`::chrono::NaiveDate`].
pub mod naive_date {
    use crate::ToOrderableBytes;
    use ::chrono::{Datelike, NaiveDate};

    /// Build the canonical, order-preserving byte encoding of a `NaiveDate`.
    ///
    /// `NaiveDate::num_days_from_ce()` returns an `i32` whose ordering
    /// matches chronological order. Sign-flipping `i32 → u32` (XOR with
    /// `1u32 << 31`) preserves order while making the value unsigned, then
    /// big-endian byte serialisation gives a 4-byte sequence whose lex
    /// order matches the natural date order.
    impl ToOrderableBytes for NaiveDate {
        const ENCODED_LEN: usize = 4;
        type Bytes = [u8; Self::ENCODED_LEN];

        fn to_orderable_bytes(&self) -> [u8; Self::ENCODED_LEN] {
            let biased = (self.num_days_from_ce() as u32) ^ (1u32 << 31);
            biased.to_be_bytes()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn ymd(year: i32, month: u32, day: u32) -> NaiveDate {
            NaiveDate::from_ymd_opt(year, month, day).unwrap()
        }

        #[test]
        fn year_one_biases_to_known_u32() {
            // Year 1 day 1 has num_days_from_ce = 1 ⇒ sign-flipped u32 = 0x8000_0001.
            assert_eq!(ymd(1, 1, 1).to_orderable_bytes(), [0x80, 0x00, 0x00, 0x01]);
        }

        #[test]
        fn byte_order_matches_chronological_order() {
            let ascending = [
                NaiveDate::MIN,
                ymd(-10000, 1, 1),
                ymd(-1, 12, 31),
                ymd(1, 1, 1),
                ymd(1970, 1, 1),
                ymd(2000, 1, 1),
                ymd(2026, 4, 29),
                ymd(10000, 1, 1),
                NaiveDate::MAX,
            ];
            for window in ascending.windows(2) {
                let a = window[0].to_orderable_bytes();
                let b = window[1].to_orderable_bytes();
                assert!(
                    a < b,
                    "to_orderable_bytes({}) < to_orderable_bytes({}) failed",
                    window[0],
                    window[1]
                );
            }
        }
    }
}

/// Order-preserving byte encoding for [`::chrono::DateTime<::chrono::Utc>`].
pub mod datetime_utc {
    use crate::ToOrderableBytes;
    use ::chrono::{DateTime, Utc};

    /// Number of bytes in the canonical orderable-bytes form. Mirrors
    /// `<DateTime<Utc> as ToOrderableBytes>::ENCODED_LEN` for use in
    /// const contexts that can't easily name the trait impl.
    pub const ENCODED_LEN: usize = 12;

    /// Build the canonical, order-preserving byte encoding of a
    /// `DateTime<Utc>`.
    ///
    /// Layout: a sign-flipped `i64` Unix timestamp (8 bytes BE) followed by
    /// the `u32` subsecond nanosecond count (4 bytes BE). Sign-flipping the
    /// timestamp via `XOR (1u64 << 63)` makes the bias-encoded value sort
    /// chronologically as an unsigned big-endian integer; appending the
    /// subsecond field gives a strict tiebreaker on nanos within the same
    /// whole second. `timestamp_subsec_nanos` returns values in
    /// `0..2_000_000_000` (the upper half encodes leap-second moments),
    /// which fits in `u32` and preserves chronological order.
    impl ToOrderableBytes for DateTime<Utc> {
        const ENCODED_LEN: usize = ENCODED_LEN;
        type Bytes = [u8; ENCODED_LEN];

        fn to_orderable_bytes(&self) -> [u8; ENCODED_LEN] {
            let secs = self.timestamp();
            let nanos = self.timestamp_subsec_nanos();
            let secs_biased = (secs as u64) ^ (1u64 << 63);
            let mut out = [0u8; ENCODED_LEN];
            out[..8].copy_from_slice(&secs_biased.to_be_bytes());
            out[8..].copy_from_slice(&nanos.to_be_bytes());
            out
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ::chrono::TimeZone;

        fn dt(secs: i64, nanos: u32) -> DateTime<Utc> {
            Utc.timestamp_opt(secs, nanos).single().unwrap()
        }

        #[test]
        fn unix_epoch_canonical_bytes() {
            // 1970-01-01T00:00:00Z: timestamp = 0, subsec = 0. Sign-flip on
            // `0_i64` gives `0x8000_0000_0000_0000`.
            assert_eq!(
                dt(0, 0).to_orderable_bytes(),
                [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            );
        }

        #[test]
        fn byte_order_matches_chronological_order() {
            let ascending = [
                DateTime::<Utc>::MIN_UTC,
                dt(-1_000_000_000_000, 0),
                dt(-1_000_000_000, 0),
                dt(-1, 999_999_999),
                dt(0, 0),
                dt(0, 1),
                dt(100, 100),
                dt(100, 200),
                dt(101, 0),
                dt(1_000_000_000, 0),
                dt(1_000_000_000_000, 0),
                DateTime::<Utc>::MAX_UTC,
            ];
            for window in ascending.windows(2) {
                let a = window[0].to_orderable_bytes();
                let b = window[1].to_orderable_bytes();
                assert!(
                    a < b,
                    "to_orderable_bytes({}) < to_orderable_bytes({}) failed",
                    window[0],
                    window[1]
                );
            }
        }
    }
}
