use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hex_literal::hex;

use small_prp::prp::prng::Prng;
use aes::cipher::generic_array::arr;

#[inline]
fn do_prng_byte(prng: &mut Prng) {
  prng.next_byte();
}

fn criterion_benchmark(c: &mut Criterion) {
    //let key = arr![u8; 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let key: [u8; 16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let mut prng = Prng::init(&key);

    c.bench_function("prng_byte", |b| b.iter(|| do_prng_byte(black_box(&mut prng))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
