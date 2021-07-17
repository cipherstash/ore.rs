use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hex_literal::hex;

use small_prp::ore_large::OreLarge;
use aes::cipher::generic_array::arr;

#[inline]
fn do_encrypt(ore: &mut OreLarge) {
  ore.encrypt(25);
}

#[inline]
fn do_encrypt_left(ore: &mut OreLarge) {
  ore.encrypt_left(25);
}

fn criterion_benchmark(c: &mut Criterion) {
    let prf_key = arr![u8; 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let prp_key = arr![u8; 0xd0, 0xd0, 0x07, 0xa5, 0x3f, 0x9a, 0x68, 0x48, 0x83, 0xbc, 0x1f, 0x21, 0x0f, 0x65, 0x95, 0xa3];
    let mut ore = OreLarge::init(prf_key, prp_key);

    c.bench_function("ore_large8", |b| b.iter(|| do_encrypt(black_box(&mut ore))));
    c.bench_function("ore_large8_left", |b| b.iter(|| do_encrypt_left(black_box(&mut ore))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
