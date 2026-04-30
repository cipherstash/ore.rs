use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hex_literal::hex;
use ore_rs::{scheme::bit2::OreAes128ChaCha20, CipherText, OreCipher, OreEncrypt, OreOutput};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;

/// Number of plaintext bytes produced by the `Decimal` pre-encoder
/// (matches `ore_encoders::decimal::PRE_ENCODED_LEN`).
const PRE_ENCODED_LEN: usize = 14;

#[inline]
fn do_encrypt_decimal(input: Decimal, ore: &mut OreAes128ChaCha20) {
    input.encrypt(ore).unwrap();
}

#[inline]
fn do_encrypt_left_decimal(input: Decimal, ore: &mut OreAes128ChaCha20) {
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
fn do_deserialize(bytes: &[u8]) {
    let _ret = CipherText::<OreAes128ChaCha20, PRE_ENCODED_LEN>::from_slice(bytes).unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let k1 = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let k2 = hex!("d0d007a5 3f9a6848 83bc1f21 0f6595a3");

    let mut ore: OreAes128ChaCha20 = OreCipher::init(&k1, &k2).unwrap();
    let x = dec!(123.456).encrypt(&ore).unwrap();
    let y = dec!(987654321.1234567890).encrypt(&ore).unwrap();

    let x_bytes = x.to_bytes();
    let y_bytes = y.to_bytes();

    c.bench_function("encrypt-decimal", |b| {
        b.iter(|| do_encrypt_decimal(black_box(dec!(123.456)), black_box(&mut ore)))
    });
    c.bench_function("encrypt-left-decimal", |b| {
        b.iter(|| do_encrypt_left_decimal(black_box(dec!(123.456)), black_box(&mut ore)))
    });
    c.bench_function("compare-decimal", |b| {
        b.iter(|| do_compare(black_box(&x), black_box(&y)))
    });
    c.bench_function("compare-decimal-slice", |b| {
        b.iter(|| do_compare_slice(black_box(&x_bytes), black_box(&y_bytes)))
    });
    c.bench_function("serialize-decimal", |b| {
        b.iter(|| do_serialize(black_box(&x)))
    });
    c.bench_function("deserialize-decimal", |b| {
        b.iter(|| do_deserialize(black_box(&x_bytes)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
