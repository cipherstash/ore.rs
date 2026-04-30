use ::chrono::{DateTime, NaiveDate, TimeZone, Utc};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hex_literal::hex;
use ore_rs::{scheme::bit2::OreAes128ChaCha20, CipherText, OreCipher, OreEncrypt, OreOutput};

#[inline]
fn do_encrypt_date(input: NaiveDate, ore: &mut OreAes128ChaCha20) {
    input.encrypt(ore).unwrap();
}

#[inline]
fn do_encrypt_left_date(input: NaiveDate, ore: &mut OreAes128ChaCha20) {
    input.encrypt_left(ore).unwrap();
}

#[inline]
fn do_encrypt_datetime(input: DateTime<Utc>, ore: &mut OreAes128ChaCha20) {
    input.encrypt(ore).unwrap();
}

#[inline]
fn do_encrypt_left_datetime(input: DateTime<Utc>, ore: &mut OreAes128ChaCha20) {
    input.encrypt_left(ore).unwrap();
}

#[inline]
fn do_compare<const N: usize>(
    a: &CipherText<OreAes128ChaCha20, N>,
    b: &CipherText<OreAes128ChaCha20, N>,
) {
    let _ret = a.partial_cmp(b);
}

#[inline]
fn do_compare_slice(a: &[u8], b: &[u8]) {
    let _ret = OreAes128ChaCha20::compare_raw_slices(a, b);
}

#[inline]
fn do_serialize<const N: usize>(a: &CipherText<OreAes128ChaCha20, N>) {
    let _ret = a.to_bytes();
}

#[inline]
fn do_deserialize<const N: usize>(bytes: &[u8]) {
    let _ret = CipherText::<OreAes128ChaCha20, N>::from_slice(bytes).unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let k1 = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let k2 = hex!("d0d007a5 3f9a6848 83bc1f21 0f6595a3");

    let mut ore: OreAes128ChaCha20 = OreCipher::init(&k1, &k2).unwrap();

    // --- NaiveDate (4-byte plaintext) ---

    let date_a = NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();
    let date_b = NaiveDate::from_ymd_opt(2024, 6, 15).unwrap();
    let date_a_ct = date_a.encrypt(&ore).unwrap();
    let date_b_ct = date_b.encrypt(&ore).unwrap();
    let date_a_bytes = date_a_ct.to_bytes();
    let date_b_bytes = date_b_ct.to_bytes();

    c.bench_function("encrypt-date", |b| {
        b.iter(|| do_encrypt_date(black_box(date_a), black_box(&mut ore)))
    });
    c.bench_function("encrypt-left-date", |b| {
        b.iter(|| do_encrypt_left_date(black_box(date_a), black_box(&mut ore)))
    });
    c.bench_function("compare-date", |b| {
        b.iter(|| do_compare(black_box(&date_a_ct), black_box(&date_b_ct)))
    });
    c.bench_function("compare-date-slice", |b| {
        b.iter(|| do_compare_slice(black_box(&date_a_bytes), black_box(&date_b_bytes)))
    });
    c.bench_function("serialize-date", |b| {
        b.iter(|| do_serialize(black_box(&date_a_ct)))
    });
    c.bench_function("deserialize-date", |b| {
        b.iter(|| do_deserialize::<4>(black_box(&date_a_bytes)))
    });

    // --- DateTime<Utc> (12-byte plaintext) ---

    let dt_a: DateTime<Utc> = Utc.timestamp_opt(0, 0).single().unwrap();
    let dt_b: DateTime<Utc> = Utc
        .timestamp_opt(1_700_000_000, 123_456_789)
        .single()
        .unwrap();
    let dt_a_ct = dt_a.encrypt(&ore).unwrap();
    let dt_b_ct = dt_b.encrypt(&ore).unwrap();
    let dt_a_bytes = dt_a_ct.to_bytes();
    let dt_b_bytes = dt_b_ct.to_bytes();

    c.bench_function("encrypt-datetime", |b| {
        b.iter(|| do_encrypt_datetime(black_box(dt_a), black_box(&mut ore)))
    });
    c.bench_function("encrypt-left-datetime", |b| {
        b.iter(|| do_encrypt_left_datetime(black_box(dt_a), black_box(&mut ore)))
    });
    c.bench_function("compare-datetime", |b| {
        b.iter(|| do_compare(black_box(&dt_a_ct), black_box(&dt_b_ct)))
    });
    c.bench_function("compare-datetime-slice", |b| {
        b.iter(|| do_compare_slice(black_box(&dt_a_bytes), black_box(&dt_b_bytes)))
    });
    c.bench_function("serialize-datetime", |b| {
        b.iter(|| do_serialize(black_box(&dt_a_ct)))
    });
    c.bench_function("deserialize-datetime", |b| {
        b.iter(|| do_deserialize::<12>(black_box(&dt_a_bytes)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
