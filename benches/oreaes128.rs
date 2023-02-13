use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hex_literal::hex;
use ore_rs::{scheme::bit2::OreAes128ChaCha20, CipherText, OreCipher, OreEncrypt, OreOutput};

#[inline]
fn do_encrypt_64(input: u64, ore: &mut OreAes128ChaCha20) {
    input.encrypt(ore).unwrap();
}

#[inline]
fn do_encrypt_left_64(input: u64, ore: &mut OreAes128ChaCha20) {
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
fn do_deserialize(bytes: &Vec<u8>) {
    let _ret = CipherText::<OreAes128ChaCha20, 8>::from_bytes(bytes).unwrap();
}

#[inline]
fn do_encrypt_32(input: u32, ore: &mut OreAes128ChaCha20) {
    input.encrypt(ore).unwrap();
}

#[inline]
fn do_encrypt_left_32(input: u32, ore: &mut OreAes128ChaCha20) {
    input.encrypt_left(ore).unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let k1 = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let k2 = hex!("d0d007a5 3f9a6848 83bc1f21 0f6595a3");

    let mut ore: OreAes128ChaCha20 = OreCipher::init(&k1, &k2).unwrap();
    let x_u64 = 100_u64.encrypt(&mut ore).unwrap();
    let y_u64 = 100983939290192_u64.encrypt(&mut ore).unwrap();

    let x_bytes = x_u64.to_bytes();
    let y_bytes = y_u64.to_bytes();

    let x_u32 = 100_u32.encrypt(&mut ore).unwrap();
    let y_u32 = 10098393_u32.encrypt(&mut ore).unwrap();

    c.bench_function("encrypt-8", |b| {
        b.iter(|| do_encrypt_64(25u64, black_box(&mut ore)))
    });
    c.bench_function("encrypt-left-8", |b| {
        b.iter(|| do_encrypt_left_64(25u64, black_box(&mut ore)))
    });
    c.bench_function("compare-8", |b| {
        b.iter(|| do_compare(black_box(&x_u64), black_box(&y_u64)))
    });
    c.bench_function("compare-8-slice", |b| {
        b.iter(|| do_compare_slice(black_box(&x_bytes), black_box(&y_bytes)))
    });
    c.bench_function("serialize-8", |b| {
        b.iter(|| do_serialize(black_box(&x_u64)))
    });
    c.bench_function("deserialize-8", |b| {
        b.iter(|| do_deserialize(black_box(&x_bytes)))
    });

    c.bench_function("encrypt-4", |b| {
        b.iter(|| do_encrypt_32(25u32, black_box(&mut ore)))
    });
    c.bench_function("encrypt-left-4", |b| {
        b.iter(|| do_encrypt_left_32(25u32, black_box(&mut ore)))
    });
    c.bench_function("compare-4", |b| {
        b.iter(|| do_compare(black_box(&x_u32), black_box(&y_u32)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
