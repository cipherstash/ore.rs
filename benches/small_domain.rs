use criterion::{black_box, criterion_group, criterion_main, Criterion};
use small_prp::Ore;
use hex_literal::hex;

#[inline]
fn do_encrypt(ore: &mut Ore) {
  ore.encrypt(25);
}

#[inline]
fn do_encrypt_left(ore: &mut Ore) {
  ore.encrypt_left(25);
}

fn criterion_benchmark(c: &mut Criterion) {
    let prf_key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let prp_key: [u8; 16] = hex!("d0d007a5 3f9a6848 83bc1f21 0f6595a3");
    let mut ore = Ore::init(prf_key, prp_key);

    c.bench_function("ore_small8", |b| b.iter(|| do_encrypt(black_box(&mut ore))));
    c.bench_function("ore_small8_left", |b| b.iter(|| do_encrypt_left(black_box(&mut ore))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
