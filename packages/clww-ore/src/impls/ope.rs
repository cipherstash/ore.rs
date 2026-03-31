use crate::{
    impls::num::OreCllw8V1, impls::string::OreCllw8VariableV1, CllwOpeDecrypt, CllwOpeEncrypt,
    CllwOreDecrypt, CllwOreEncrypt, Error, Key,
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
/// This is the Order-Preserving Encryption variant of [`OreCllw8VariableV1`]. The underlying
/// bytes are identical to the ORE ciphertext, but comparison uses standard lexicographic
/// byte ordering instead of the ORE comparison function.
///
/// **Correctness**: OPE comparison is correct with probability `1 - 1/256 ~ 99.6%` per
/// comparison at the first differing bit position. See Section 3.2 of the CLWW paper.
///
/// The ciphertext length is proportional to the input length (8 bytes per input byte).
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

impl From<OreCllw8VariableV1> for OpeCllw8VariableV1 {
    fn from(ore: OreCllw8VariableV1) -> Self {
        Self {
            bytes: ore.as_ref().to_vec(),
        }
    }
}

impl From<OpeCllw8VariableV1> for OreCllw8VariableV1 {
    fn from(ope: OpeCllw8VariableV1) -> Self {
        OreCllw8VariableV1::from(ope.bytes)
    }
}

impl OpeCllw8VariableV1 {
    /// Decrypt the ciphertext to raw bytes.
    pub fn decrypt_to_bytes(&self, key: &Key, salt: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        let ore = OreCllw8VariableV1::from(self.bytes.clone());
        ore.decrypt_to_bytes(key, salt)
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

    fn encrypt_ope_with_salt(
        self,
        key: &Key,
        salt: Option<&[u8]>,
    ) -> Result<Self::Output, Error> {
        let ore: OreCllw8VariableV1 = self.encrypt_with_salt(key, salt)?;
        Ok(OpeCllw8VariableV1::from(ore))
    }
}

impl CllwOpeEncrypt for &[u8] {
    type Output = OpeCllw8VariableV1;

    fn encrypt_ope_with_salt(
        self,
        key: &Key,
        salt: Option<&[u8]>,
    ) -> Result<Self::Output, Error> {
        let ore: OreCllw8VariableV1 = self.encrypt_with_salt(key, salt)?;
        Ok(OpeCllw8VariableV1::from(ore))
    }
}

impl CllwOpeDecrypt for OpeCllw8VariableV1 {
    type Output = String;

    fn decrypt_ope_with_salt(
        self,
        key: &Key,
        salt: Option<&[u8]>,
    ) -> Result<Self::Output, Error> {
        let ore: OreCllw8VariableV1 = OreCllw8VariableV1::from(self);
        ore.decrypt_with_salt(key, salt)
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

    #[test]
    fn test_ope_string_deterministic() {
        let key = Key::from([0u8; 32]);
        let a = key.encrypt_ope("hello").unwrap();
        let b = key.encrypt_ope("hello").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_ope_bytes_deterministic() {
        let key = Key::from([0u8; 32]);
        let data: &[u8] = &[0xFF, 0x00, 0xAB];
        let a = key.encrypt_ope(data).unwrap();
        let b = key.encrypt_ope(data).unwrap();
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

    #[test]
    fn test_ore_to_ope_to_ore_round_trip_variable() {
        let key = Key::from([0u8; 32]);
        let ore = key.encrypt("hello").unwrap();
        let ore_bytes = ore.as_ref().to_vec();
        let ope = OpeCllw8VariableV1::from(ore);
        let ore_back: OreCllw8VariableV1 = OreCllw8VariableV1::from(ope);
        assert_eq!(ore_bytes, ore_back.as_ref());
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

    #[test]
    fn test_ope_decrypt_string() {
        let key = Key::from([0u8; 32]);
        let ct = key.encrypt_ope("hello world").unwrap();
        let pt: String = key.decrypt_ope(ct).unwrap();
        assert_eq!("hello world", pt);
    }

    #[test]
    fn test_ope_decrypt_bytes() {
        let key = Key::from([0u8; 32]);
        let data: &[u8] = &[0xFF, 0x00, 0xAB, 0xCD];
        let ct = key.encrypt_ope(data).unwrap();
        let pt = ct.decrypt_to_bytes(&key, None).unwrap();
        assert_eq!(data, pt.as_slice());
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
        let ct1 = 42u32
            .encrypt_ope_with_salt(&key, Some(b"domain1"))
            .unwrap();
        let ct2 = 42u32
            .encrypt_ope_with_salt(&key, Some(b"domain2"))
            .unwrap();
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

    #[test]
    fn test_ope_string_ordering_statistical() {
        let key = Key::from([55u8; 32]);
        let strings: Vec<String> = (0..200).map(|i| format!("string{i:04}")).collect();
        let mut correct = 0usize;
        let mut total = 0usize;

        for i in 0..strings.len() {
            for j in (i + 1)..strings.len() {
                let ct_a = key.encrypt_ope(strings[i].as_str()).unwrap();
                let ct_b = key.encrypt_ope(strings[j].as_str()).unwrap();

                total += 1;
                if ct_a.cmp(&ct_b) == strings[i].cmp(&strings[j]) {
                    correct += 1;
                }
            }
        }

        let rate = correct as f64 / total as f64;
        assert!(
            rate >= 0.99,
            "OPE string ordering correct rate {rate:.4} is below 99% threshold (expected ~99.6%)"
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
        println!(
            "Sampled: {} dates ({} pairs)",
            sampled.len(),
            total_pairs
        );
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
        let mean_rate =
            all_error_rates.iter().sum::<f64>() / all_error_rates.len() as f64;
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

    /// Top 100 US family names — exhaustive pairwise comparison.
    #[test]
    #[ignore = "expensive analysis test — run with --ignored --nocapture"]
    fn ope_error_rate_top_100_us_names() {
        let names = [
            "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
            "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
            "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
            "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker",
            "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
            "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
            "Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Diaz", "Parker",
            "Cruz", "Edwards", "Collins", "Reyes", "Stewart", "Morris", "Morales", "Murphy",
            "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan", "Cooper", "Peterson", "Bailey",
            "Reed", "Kelly", "Howard", "Ramos", "Kim", "Cox", "Ward", "Richardson", "Watson",
            "Brooks", "Chavez", "Wood", "James", "Bennett", "Gray", "Mendoza", "Ruiz",
            "Hughes", "Price", "Alvarez", "Castillo", "Sanders", "Patel", "Myers", "Long",
            "Ross", "Foster", "Jimenez", "Powell",
        ];

        let total_pairs = names.len() as u64 * (names.len() as u64 - 1) / 2;
        let num_keys = 5;

        println!("\n=== OPE Error Rate: Top 100 US Family Names ===");
        println!("Domain size: {} names", names.len());
        println!("Total pairs: {total_pairs}\n");

        for key_seed in 0..num_keys {
            let key = Key::from([key_seed as u8; 32]);

            let ope_cts: Vec<OpeCllw8VariableV1> = names
                .iter()
                .map(|&n| key.encrypt_ope(n).unwrap())
                .collect();
            let ore_cts: Vec<OreCllw8VariableV1> =
                names.iter().map(|&n| key.encrypt(n).unwrap()).collect();

            let mut errors = 0u64;
            let mut total = 0u64;

            for i in 0..names.len() {
                for j in (i + 1)..names.len() {
                    let ore_ord = ore_cts[i].cmp(&ore_cts[j]);
                    let ope_ord = ope_cts[i].cmp(&ope_cts[j]);
                    total += 1;
                    if ore_ord != ope_ord {
                        errors += 1;
                    }
                }
            }

            let error_rate = errors as f64 / total as f64;
            println!(
                "Key {key_seed}: {errors}/{total} incorrect ({:.4}%)",
                error_rate * 100.0
            );
        }

        println!("\nExpected error rate: {:.4}% (1/256)", 100.0 / 256.0);
    }
}
