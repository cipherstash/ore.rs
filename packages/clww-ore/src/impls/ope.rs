use crate::{
    impls::num::OreCllw8V1,
    impls::string::{encrypt_ope_variable_bytes, encrypt_ope_variable_str},
    CllwOpeDecrypt, CllwOpeEncrypt, CllwOreDecrypt, CllwOreEncrypt, Error, Key,
};
use hex::FromHex;
#[cfg(feature = "postgres-types")]
use postgres_types::ToSql;
use std::cmp::Ordering;

/// Fixed-size CLLW OPE ciphertext for unsigned integer types.
///
/// This is the Order-Preserving Encryption variant of [`OreCllw8V1`]. The underlying bytes
/// are identical to the ORE ciphertext, but comparison uses standard lexicographic byte
/// ordering instead of the ORE comparison function. This means ciphertexts can be compared
/// using normal numeric/byte comparison without a custom comparison function.
///
/// **Correctness**: OPE comparison is correct with probability `1 - 1/256 ~ 99.6%` per
/// comparison. The error occurs when the PRF output at the first differing bit position
/// wraps around modulo 256. See Section 3.2 of the CLWW paper for details.
///
/// The size `N` corresponds to the number of bits in the plaintext (one byte per bit).
///
/// - `OpeCllw8V1<8>` encrypts `u8` (8 bytes)
/// - `OpeCllw8V1<16>` encrypts `u16` (16 bytes)
/// - `OpeCllw8V1<32>` encrypts `u32` (32 bytes)
/// - `OpeCllw8V1<64>` encrypts `u64` (64 bytes)
/// - `OpeCllw8V1<128>` encrypts `u128` (128 bytes)
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "postgres-types", derive(ToSql))]
#[cfg_attr(feature = "postgres-types", postgres(name = "ore_cllw_8_ope_v1"))]
pub struct OpeCllw8V1<const N: usize> {
    pub(super) bytes: [u8; N],
}

impl<const N: usize> AsRef<[u8]> for OpeCllw8V1<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<const N: usize> FromHex for OpeCllw8V1<N> {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, <Self as FromHex>::Error> {
        let mut out = [0u8; N];
        hex::decode_to_slice(hex, &mut out as &mut [u8]).map_err(|_| Error)?;
        Ok(Self { bytes: out })
    }
}

impl<const N: usize> TryFrom<&[u8]> for OpeCllw8V1<N> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != N {
            return Err(Error);
        }

        let mut bytes: [u8; N] = [0; N];
        bytes.copy_from_slice(value);
        Ok(OpeCllw8V1 { bytes })
    }
}

impl<const N: usize> From<OreCllw8V1<N>> for OpeCllw8V1<N> {
    fn from(ore: OreCllw8V1<N>) -> Self {
        Self { bytes: ore.bytes }
    }
}

impl<const N: usize> From<OpeCllw8V1<N>> for OreCllw8V1<N> {
    fn from(ope: OpeCllw8V1<N>) -> Self {
        Self { bytes: ope.bytes }
    }
}

// OPE comparison: standard lexicographic byte comparison.
// This is the base-256 numeric interpretation from Section 3.2 of the CLWW paper.
impl<const N: usize> Ord for OpeCllw8V1<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl<const N: usize> PartialOrd for OpeCllw8V1<N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize> PartialEq for OpeCllw8V1<N> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<const N: usize> Eq for OpeCllw8V1<N> {}

/// Macro to implement CllwOpeEncrypt and CllwOpeDecrypt for unsigned integer types.
/// Delegates to the ORE encryption and converts the result.
macro_rules! impl_cllw_ope_uint {
    ($uint_type:ty, $array_size:expr) => {
        impl CllwOpeEncrypt for $uint_type {
            type Output = OpeCllw8V1<$array_size>;

            fn encrypt_ope_with_salt(
                self,
                key: &Key,
                salt: Option<&[u8]>,
            ) -> Result<Self::Output, Error> {
                let ore: OreCllw8V1<$array_size> = self.encrypt_with_salt(key, salt)?;
                Ok(OpeCllw8V1::from(ore))
            }
        }

        impl CllwOpeDecrypt for OpeCllw8V1<$array_size> {
            type Output = $uint_type;

            fn decrypt_ope_with_salt(
                self,
                key: &Key,
                salt: Option<&[u8]>,
            ) -> Result<Self::Output, Error> {
                let ore: OreCllw8V1<$array_size> = OreCllw8V1::from(self);
                ore.decrypt_with_salt(key, salt)
            }
        }
    };
}

impl_cllw_ope_uint!(u8, 8);
impl_cllw_ope_uint!(u16, 16);
impl_cllw_ope_uint!(u32, 32);
impl_cllw_ope_uint!(u64, 64);
impl_cllw_ope_uint!(u128, 128);

// --- Variable-length OPE ---

/// Variable-length CLLW OPE ciphertext for strings and byte slices.
///
/// Ciphertexts are compared with standard lexicographic byte ordering.
/// Encryption uses the CLLW keystream from Section 3.2 of the paper, but
/// propagates the `+1` addition as a right-to-left carry into a reserved
/// leading byte, which eliminates the ~1/256 ordering error the paper's
/// naive OPE construction exhibits.
///
/// **Correctness**: OPE comparison is exact (100%) — lex ordering of two
/// ciphertexts under the same key and salt always matches the plaintext
/// ordering.
///
/// **Encrypt-only**: this type intentionally does not support decryption.
/// OPE is used for ordered lookups; callers that need round-trip should
/// pair it with an ORE (`OreCllw8VariableV1`) ciphertext.
///
/// The ciphertext length is `8 * plaintext_bytes + 1` (one reserved leading
/// byte plus one byte per plaintext bit).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres-types", derive(ToSql))]
#[cfg_attr(
    feature = "postgres-types",
    postgres(name = "ore_cllw_8_ope_variable_v1")
)]
pub struct OpeCllw8VariableV1 {
    bytes: Vec<u8>,
}

impl AsRef<[u8]> for OpeCllw8VariableV1 {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for OpeCllw8VariableV1 {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl hex::FromHex for OpeCllw8VariableV1 {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: hex::decode(hex)?,
        })
    }
}

// OPE comparison: standard lexicographic byte comparison with length tiebreaker.
impl Ord for OpeCllw8VariableV1 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl PartialOrd for OpeCllw8VariableV1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for OpeCllw8VariableV1 {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for OpeCllw8VariableV1 {}

impl CllwOpeEncrypt for &str {
    type Output = OpeCllw8VariableV1;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let bytes = encrypt_ope_variable_str(self, key, salt);
        Ok(OpeCllw8VariableV1 { bytes })
    }
}

impl CllwOpeEncrypt for &[u8] {
    type Output = OpeCllw8VariableV1;

    fn encrypt_ope_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Result<Self::Output, Error> {
        let bytes = encrypt_ope_variable_bytes(self, key, salt);
        Ok(OpeCllw8VariableV1 { bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Key;
    use std::cmp::Ordering;

    // --- Determinism tests (always pass) ---

    #[test]
    fn test_ope_u32_deterministic() {
        let key = Key::from([0u8; 32]);
        let a = key.encrypt_ope(42u32).unwrap();
        let b = key.encrypt_ope(42u32).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_ope_u64_deterministic() {
        let key = Key::from([1u8; 32]);
        let a = key.encrypt_ope(12345u64).unwrap();
        let b = key.encrypt_ope(12345u64).unwrap();
        assert_eq!(a, b);
    }

    // --- Conversion round-trip tests (always pass) ---

    #[test]
    fn test_ore_to_ope_to_ore_round_trip_u32() {
        let key = Key::from([0u8; 32]);
        let ore = key.encrypt(42u32).unwrap();
        let ope = OpeCllw8V1::from(ore);
        let ore_back: OreCllw8V1<32> = OreCllw8V1::from(ope);
        assert_eq!(ore.as_ref(), ore_back.as_ref());
    }

    // --- Decrypt round-trip tests (always pass) ---

    #[test]
    fn test_ope_decrypt_u8() {
        let key = Key::from([0u8; 32]);
        let value: u8 = 200;
        let ct = key.encrypt_ope(value).unwrap();
        let pt: u8 = key.decrypt_ope(ct).unwrap();
        assert_eq!(value, pt);
    }

    #[test]
    fn test_ope_decrypt_u16() {
        let key = Key::from([0u8; 32]);
        let value: u16 = 12345;
        let ct = key.encrypt_ope(value).unwrap();
        let pt: u16 = key.decrypt_ope(ct).unwrap();
        assert_eq!(value, pt);
    }

    #[test]
    fn test_ope_decrypt_u32() {
        let key = Key::from([0u8; 32]);
        let value: u32 = 999999;
        let ct = key.encrypt_ope(value).unwrap();
        let pt: u32 = key.decrypt_ope(ct).unwrap();
        assert_eq!(value, pt);
    }

    #[test]
    fn test_ope_decrypt_u64() {
        let key = Key::from([0u8; 32]);
        let value: u64 = 1_000_000_000;
        let ct = key.encrypt_ope(value).unwrap();
        let pt: u64 = key.decrypt_ope(ct).unwrap();
        assert_eq!(value, pt);
    }

    #[test]
    fn test_ope_decrypt_u128() {
        let key = Key::from([0u8; 32]);
        let value: u128 = u128::MAX / 2;
        let ct = key.encrypt_ope(value).unwrap();
        let pt: u128 = key.decrypt_ope(ct).unwrap();
        assert_eq!(value, pt);
    }

    // --- Salt tests (always pass) ---

    #[test]
    fn test_ope_salt_decrypt_round_trip() {
        let key = Key::from([0u8; 32]);
        let salt = b"my-domain";
        let ct = 42u32.encrypt_ope_with_salt(&key, Some(salt)).unwrap();
        let pt = ct.decrypt_ope_with_salt(&key, Some(salt)).unwrap();
        assert_eq!(42u32, pt);
    }

    #[test]
    fn test_ope_different_salts_different_ciphertexts() {
        let key = Key::from([0u8; 32]);
        let ct1 = 42u32.encrypt_ope_with_salt(&key, Some(b"domain1")).unwrap();
        let ct2 = 42u32.encrypt_ope_with_salt(&key, Some(b"domain2")).unwrap();
        assert_ne!(ct1, ct2);
    }

    // --- Statistical ordering tests ---
    // OPE comparison is correct with probability 255/256 ~ 99.6%.
    // We test with a large sample and verify the success rate.

    #[test]
    fn test_ope_u32_ordering_statistical() {
        let key = Key::from([42u8; 32]);
        let n = 10_000;
        let mut correct = 0usize;

        // Use a simple deterministic sequence of test pairs
        for i in 0..n {
            let x = (i * 7 + 13) as u32;
            let y = (i * 11 + 29) as u32;
            if x == y {
                continue;
            }

            let ct_x = key.encrypt_ope(x).unwrap();
            let ct_y = key.encrypt_ope(y).unwrap();

            if ct_x.cmp(&ct_y) == x.cmp(&y) {
                correct += 1;
            }
        }

        let rate = correct as f64 / n as f64;
        assert!(
            rate >= 0.99,
            "OPE ordering correct rate {rate:.4} is below 99% threshold (expected ~99.6%)"
        );
    }

    #[test]
    fn test_ope_u64_ordering_statistical() {
        let key = Key::from([77u8; 32]);
        let n = 10_000;
        let mut correct = 0usize;

        for i in 0..n {
            let x = (i as u64) * 997 + 1;
            let y = (i as u64) * 991 + 3;
            if x == y {
                continue;
            }

            let ct_x = key.encrypt_ope(x).unwrap();
            let ct_y = key.encrypt_ope(y).unwrap();

            if ct_x.cmp(&ct_y) == x.cmp(&y) {
                correct += 1;
            }
        }

        let rate = correct as f64 / n as f64;
        assert!(
            rate >= 0.99,
            "OPE ordering correct rate {rate:.4} is below 99% threshold (expected ~99.6%)"
        );
    }


    // --- OPE matches ORE for equal values ---

    #[test]
    fn test_ope_equal_values_always_equal() {
        let key = Key::from([0u8; 32]);
        for x in [0u32, 1, 42, 1000, u32::MAX / 2, u32::MAX] {
            let ct1 = key.encrypt_ope(x).unwrap();
            let ct2 = key.encrypt_ope(x).unwrap();
            assert_eq!(ct1.cmp(&ct2), Ordering::Equal, "failed for x={x}");
        }
    }

    // --- Hex round-trip ---

    #[test]
    fn test_ope_hex_round_trip_fixed() {
        let key = Key::from([0u8; 32]);
        let ct = key.encrypt_ope(42u32).unwrap();
        let hex_str = hex::encode(ct.as_ref());
        let ct2 = OpeCllw8V1::<32>::from_hex(&hex_str).unwrap();
        assert_eq!(ct, ct2);
    }

    #[test]
    fn test_ope_hex_round_trip_variable() {
        let key = Key::from([0u8; 32]);
        let ct = key.encrypt_ope("hello").unwrap();
        let hex_str = hex::encode(ct.as_ref());
        let ct2 = OpeCllw8VariableV1::from_hex(&hex_str).unwrap();
        assert_eq!(ct, ct2);
    }

    // --- TryFrom round-trip ---

    #[test]
    fn test_ope_try_from_bytes_fixed() {
        let key = Key::from([0u8; 32]);
        let ct = key.encrypt_ope(42u32).unwrap();
        let bytes = ct.as_ref();
        let ct2 = OpeCllw8V1::<32>::try_from(bytes).unwrap();
        assert_eq!(ct, ct2);
    }

    #[test]
    fn test_ope_try_from_wrong_length_fails() {
        let bytes = [0u8; 16];
        let result = OpeCllw8V1::<32>::try_from(bytes.as_slice());
        assert!(result.is_err());
    }

    // --- Domain-specific error rate analysis ---
    //
    // These tests measure the exact OPE comparison error rate for realistic plaintext
    // domains with a fixed key. Since the PRF is deterministic for a given key, each
    // pair is either always-correct or always-incorrect. The error rate over all pairs
    // should converge to ~1/256 ≈ 0.39%.
    //
    // Run with: cargo test -p cllw-ore -- --ignored ope_error_rate --nocapture

    /// Days from 1940-01-01 to 2010-12-31, encoded as days-since-1940-01-01.
    /// Encrypt all dates, compare every pair with both ORE (ground truth) and OPE.
    #[test]
    #[ignore = "expensive analysis test — run with --ignored --nocapture"]
    fn ope_error_rate_birthdates_1940_2010() {
        fn days_in_month(year: u32, month: u32) -> u32 {
            match month {
                1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
                4 | 6 | 9 | 11 => 30,
                2 => {
                    if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                        29
                    } else {
                        28
                    }
                }
                _ => unreachable!(),
            }
        }

        // Generate all dates as days-since-1940-01-01
        let mut dates: Vec<u32> = Vec::new();
        let mut day_count: u32 = 0;
        for year in 1940..=2010 {
            for month in 1..=12 {
                for _day in 1..=days_in_month(year, month) {
                    dates.push(day_count);
                    day_count += 1;
                }
            }
        }

        let num_keys = 1000;
        println!("\n=== OPE Error Rate: Birthdates 1940-2010 ===");
        println!("Domain size: {} dates", dates.len());
        println!(
            "Total pairs: {}",
            dates.len() as u64 * (dates.len() as u64 - 1) / 2
        );

        // Sample to keep runtime reasonable: take every Nth date
        let sample_size = 2000;
        let step = dates.len() / sample_size;
        let sampled: Vec<u32> = dates.iter().step_by(step.max(1)).copied().collect();
        let total_pairs = sampled.len() as u64 * (sampled.len() as u64 - 1) / 2;
        println!("Sampled: {} dates ({} pairs)", sampled.len(), total_pairs);
        println!("Keys: {num_keys}\n");

        let mut all_error_rates: Vec<f64> = Vec::with_capacity(num_keys);
        let mut total_errors_all_keys = 0u64;
        let mut total_pairs_all_keys = 0u64;

        for key_seed in 0..num_keys {
            // Use a varied key — spread the seed across the key bytes
            let mut key_bytes = [0u8; 32];
            let seed_bytes = (key_seed as u64).to_le_bytes();
            key_bytes[..8].copy_from_slice(&seed_bytes);
            let key = Key::from(key_bytes);

            // Encrypt all sampled dates
            let ope_cts: Vec<OpeCllw8V1<32>> = sampled
                .iter()
                .map(|&d| key.encrypt_ope(d).unwrap())
                .collect();
            let ore_cts: Vec<OreCllw8V1<32>> =
                sampled.iter().map(|&d| key.encrypt(d).unwrap()).collect();

            let mut errors = 0u64;
            let mut total = 0u64;

            for i in 0..sampled.len() {
                for j in (i + 1)..sampled.len() {
                    let ore_ord = ore_cts[i].cmp(&ore_cts[j]);
                    let ope_ord = ope_cts[i].cmp(&ope_cts[j]);
                    total += 1;
                    if ore_ord != ope_ord {
                        errors += 1;
                    }
                }
            }

            let error_rate = errors as f64 / total as f64;
            all_error_rates.push(error_rate);
            total_errors_all_keys += errors;
            total_pairs_all_keys += total;
        }

        // Aggregate statistics
        let mean_rate = all_error_rates.iter().sum::<f64>() / all_error_rates.len() as f64;
        let global_rate = total_errors_all_keys as f64 / total_pairs_all_keys as f64;
        let max_rate = all_error_rates
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);
        let min_rate = all_error_rates
            .iter()
            .cloned()
            .fold(f64::INFINITY, f64::min);
        let keys_with_zero = all_error_rates.iter().filter(|&&r| r == 0.0).count();
        let variance = all_error_rates
            .iter()
            .map(|r| (r - mean_rate).powi(2))
            .sum::<f64>()
            / all_error_rates.len() as f64;
        let stddev = variance.sqrt();

        println!("--- Results across {num_keys} keys ---");
        println!(
            "Global error rate: {total_errors_all_keys}/{total_pairs_all_keys} ({:.4}%)",
            global_rate * 100.0
        );
        println!("Mean per-key rate: {:.4}%", mean_rate * 100.0);
        println!("Std dev:           {:.4}%", stddev * 100.0);
        println!("Min per-key rate:  {:.4}%", min_rate * 100.0);
        println!("Max per-key rate:  {:.4}%", max_rate * 100.0);
        println!(
            "Keys with 0 errors: {keys_with_zero}/{num_keys} ({:.1}%)",
            keys_with_zero as f64 / num_keys as f64 * 100.0
        );
        println!("\nExpected error rate: {:.4}% (1/256)", 100.0 / 256.0);
    }

    // --- Variable-length exact-ordering tests (100%, backward-carry design) ---

    #[test]
    fn test_ope_variable_reserved_byte_and_length() {
        let key = Key::from([0u8; 32]);
        // Empty plaintext is a single reserved byte.
        let empty = key.encrypt_ope("").unwrap();
        assert_eq!(empty.as_ref().len(), 1);
        // A single character is 8 bits + 1 reserved byte.
        let single = key.encrypt_ope("a").unwrap();
        assert_eq!(single.as_ref().len(), 9);
        // Byte-slice path: length = 8 * N + 1.
        let five: &[u8] = b"hello";
        let ct = key.encrypt_ope(five).unwrap();
        assert_eq!(ct.as_ref().len(), 8 * five.len() + 1);
    }

    #[test]
    fn test_ope_variable_empty_less_than_nonempty() {
        for k in 0..32u8 {
            let key = Key::from([k; 32]);
            let empty = key.encrypt_ope("").unwrap();
            for s in ["a", "hello", "zebra", "   ", "~"] {
                let ct = key.encrypt_ope(s).unwrap();
                assert!(empty < ct, "empty should be less than {s:?} under key {k}");
            }
        }
    }

    #[test]
    fn test_ope_variable_adjacent_single_bytes() {
        for seed in [0u8, 1, 17, 99, 200] {
            let key = Key::from([seed; 32]);
            for x in 0u8..=254 {
                let a: &[u8] = &[x];
                let b: &[u8] = &[x + 1];
                let ca = key.encrypt_ope(a).unwrap();
                let cb = key.encrypt_ope(b).unwrap();
                assert!(
                    ca < cb,
                    "seed {seed}, x={x}: expected ct({x}) < ct({})",
                    x + 1
                );
            }
        }
    }

    #[test]
    fn test_ope_variable_prefix_ordering() {
        for seed in [0u8, 7, 42] {
            let key = Key::from([seed; 32]);
            // Prefix strictly less than its extension.
            let pairs: &[(&[u8], &[u8])] = &[
                (b"a", b"ab"),
                (b"abc", b"abcd"),
                (b"", b"x"),
                (b"hello", b"hello!"),
                (b"\x00", b"\x00\x00"),
                (b"\xff", b"\xff\x00"),
            ];
            for (shorter, longer) in pairs {
                let cs = key.encrypt_ope(*shorter).unwrap();
                let cl = key.encrypt_ope(*longer).unwrap();
                assert!(
                    cs < cl,
                    "seed {seed}: expected ct({shorter:?}) < ct({longer:?})"
                );
            }
        }
    }

    #[test]
    fn test_ope_variable_carry_across_byte_boundary() {
        // Plaintexts chosen to force a multi-byte carry chain: the PRF-
        // dependent part is identical for the first byte (both are 0x00),
        // so the first difference lands in bit 7 of byte 0 vs bit 0 of
        // byte 1 under MSB-first processing. Any carry from the later bits
        // must walk left across the byte boundary to preserve order.
        for seed in 0..64u8 {
            let key = Key::from([seed; 32]);
            // [0x00, 0xFF] < [0x01, 0x00] as plaintext byte sequences.
            let a: &[u8] = &[0x00, 0xFF];
            let b: &[u8] = &[0x01, 0x00];
            let ca = key.encrypt_ope(a).unwrap();
            let cb = key.encrypt_ope(b).unwrap();
            assert!(
                ca < cb,
                "seed {seed}: ct([0x00,0xFF]) should be < ct([0x01,0x00])"
            );
        }
    }

    #[test]
    fn test_ope_variable_exhaustive_boundary_pairs() {
        // Enumerate every 2-byte plaintext built from boundary values
        // {0x00, 0x01, 0xFE, 0xFF} and every pair of them across several
        // keys. The backward-carry design must give exact ordering for all
        // of them.
        let boundary: [u8; 4] = [0x00, 0x01, 0xFE, 0xFF];
        let mut plaintexts: Vec<[u8; 2]> = Vec::new();
        for &a in &boundary {
            for &b in &boundary {
                plaintexts.push([a, b]);
            }
        }
        for seed in [0u8, 1, 13, 127, 255] {
            let key = Key::from([seed; 32]);
            let cts: Vec<OpeCllw8VariableV1> = plaintexts
                .iter()
                .map(|p| key.encrypt_ope(p.as_slice()).unwrap())
                .collect();
            for i in 0..plaintexts.len() {
                for j in 0..plaintexts.len() {
                    assert_eq!(
                        cts[i].cmp(&cts[j]),
                        plaintexts[i].cmp(&plaintexts[j]),
                        "seed {seed}: ct({:?}) vs ct({:?})",
                        plaintexts[i],
                        plaintexts[j],
                    );
                }
            }
        }
    }

    #[test]
    fn test_ope_variable_determinism() {
        let key = Key::from([3u8; 32]);
        for input in [b"".as_slice(), b"a", b"hello", b"\x00\xff\x01"] {
            let a = key.encrypt_ope(input).unwrap();
            let b = key.encrypt_ope(input).unwrap();
            assert_eq!(a, b);
        }
    }

    // --- Property tests ---

    use quickcheck::{quickcheck, Arbitrary, Gen};

    #[derive(Debug, Clone)]
    struct KeyBytes([u8; 32]);

    impl Arbitrary for KeyBytes {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut k = [0u8; 32];
            for b in k.iter_mut() {
                *b = u8::arbitrary(g);
            }
            KeyBytes(k)
        }
    }

    #[derive(Debug, Clone)]
    struct ShortBytes(Vec<u8>);

    impl Arbitrary for ShortBytes {
        fn arbitrary(g: &mut Gen) -> Self {
            // Keep plaintexts short so quickcheck stays fast.
            let len = usize::arbitrary(g) % 12;
            let v: Vec<u8> = (0..len).map(|_| u8::arbitrary(g)).collect();
            ShortBytes(v)
        }
    }

    /// Characters that survive `orderize_string` unchanged: ASCII alphanumeric,
    /// space, and ASCII punctuation. Using these means `orderize_string(s) == s`
    /// for any `SafeString`, so the property tests can compare raw strings
    /// against ciphertext order without re-running the normaliser.
    const ORDERIZE_SAFE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

    #[derive(Debug, Clone)]
    struct SafeString(String);

    impl Arbitrary for SafeString {
        fn arbitrary(g: &mut Gen) -> Self {
            let len = usize::arbitrary(g) % 16;
            let s: String = (0..len)
                .map(|_| {
                    let idx = usize::arbitrary(g) % ORDERIZE_SAFE_CHARS.len();
                    ORDERIZE_SAFE_CHARS[idx] as char
                })
                .collect();
            SafeString(s)
        }
    }

    quickcheck! {
        /// Regression property for the 1/256 wrap-around bug. Under the old
        /// scheme, a small fraction of keys would report ct(0x00) > ct(0x01)
        /// because PRF_7 = 0xFF makes the wrapped byte 0x00 compare less than
        /// the un-wrapped peer's 0xFF. The backward-carry design must give
        /// the correct order for every key.
        fn prop_ope_variable_single_bit_difference(key: KeyBytes) -> bool {
            let k = Key::from(key.0);
            let c1 = k.encrypt_ope([0x00u8].as_slice()).unwrap();
            let c2 = k.encrypt_ope([0x01u8].as_slice()).unwrap();
            c1 < c2
        }

        fn prop_ope_variable_ordering_matches_plaintext(a: ShortBytes, b: ShortBytes, key: KeyBytes) -> bool {
            let k = Key::from(key.0);
            let ca = k.encrypt_ope(a.0.as_slice()).unwrap();
            let cb = k.encrypt_ope(b.0.as_slice()).unwrap();
            ca.cmp(&cb) == a.0.cmp(&b.0)
        }

        fn prop_ope_variable_length_invariant(a: ShortBytes, key: KeyBytes) -> bool {
            let k = Key::from(key.0);
            let ct = k.encrypt_ope(a.0.as_slice()).unwrap();
            ct.as_ref().len() == 8 * a.0.len() + 1
        }

        fn prop_ope_variable_determinism_bytes(a: ShortBytes, key: KeyBytes) -> bool {
            let k = Key::from(key.0);
            let c1 = k.encrypt_ope(a.0.as_slice()).unwrap();
            let c2 = k.encrypt_ope(a.0.as_slice()).unwrap();
            c1 == c2
        }

        fn prop_ope_variable_string_ordering(a: SafeString, b: SafeString, key: KeyBytes) -> bool {
            let k = Key::from(key.0);
            let ca = k.encrypt_ope(a.0.as_str()).unwrap();
            let cb = k.encrypt_ope(b.0.as_str()).unwrap();
            ca.cmp(&cb) == a.0.cmp(&b.0)
        }

        fn prop_ope_variable_string_determinism(a: SafeString, key: KeyBytes) -> bool {
            let k = Key::from(key.0);
            let c1 = k.encrypt_ope(a.0.as_str()).unwrap();
            let c2 = k.encrypt_ope(a.0.as_str()).unwrap();
            c1 == c2
        }

        fn prop_ope_variable_string_length_invariant(a: SafeString, key: KeyBytes) -> bool {
            let k = Key::from(key.0);
            let ct = k.encrypt_ope(a.0.as_str()).unwrap();
            ct.as_ref().len() == 8 * a.0.len() + 1
        }
    }
}
