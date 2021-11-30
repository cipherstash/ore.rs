use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hex_literal::hex;
use ore::{
    ORECipher,
    OREEncrypt,
    bit2::{
        OREAES128,
        OREAES128CipherText
    }
};

#[inline]
fn do_encrypt(ore: &mut OREAES128) {
  25u64.encrypt(ore).unwrap();
}

#[inline]
fn do_encrypt_left(ore: &mut OREAES128) {
  25u64.encrypt_left(ore).unwrap();
}

#[inline]
fn do_compare<const N: usize>(a: &OREAES128CipherText<N>, b: &OREAES128CipherText<N>) {
    a.partial_cmp(b);
}

fn criterion_benchmark(c: &mut Criterion) {
    let k1 = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let k2 = hex!("d0d007a5 3f9a6848 83bc1f21 0f6595a3");
    let seed = hex!("d0d007a5 3f9a6848");

    let mut ore: OREAES128 = ORECipher::init(k1, k2, &seed).unwrap();
    let x = 100_u64.encrypt(&mut ore).unwrap();
    let y = 100983939290192_u64.encrypt(&mut ore).unwrap();

    c.bench_function("ore_large8", |b| b.iter(|| do_encrypt(black_box(&mut ore))));
    c.bench_function("ore_large8_left", |b| b.iter(|| do_encrypt_left(black_box(&mut ore))));
    c.bench_function("ore_large8_compare", |b| b.iter(|| do_compare(black_box(&x), black_box(&y))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
