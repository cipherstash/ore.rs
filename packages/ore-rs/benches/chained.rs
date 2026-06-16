use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hex_literal::hex;
use ore_rs::scheme::chained::{OreAes128Bit6Chained, OreAes128Bit6ChainedChaCha20};

fn init_ore() -> OreAes128Bit6ChainedChaCha20 {
    let k1: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    OreAes128Bit6Chained::init(&k1).unwrap()
}

fn criterion_benchmark(c: &mut Criterion) {
    let ore = init_ore();

    // Short (~8 chars ≈ 11 blocks) and long (~40 chars ≈ 54 blocks) strings.
    let short = "alice";
    let medium = "alice@example.com";
    let long = "the quick brown fox jumps over the lazy dog";

    c.bench_function("chained-encrypt-str-5", |b| {
        b.iter(|| ore.encrypt_str(black_box(short)).unwrap())
    });
    c.bench_function("chained-encrypt-str-17", |b| {
        b.iter(|| ore.encrypt_str(black_box(medium)).unwrap())
    });
    c.bench_function("chained-encrypt-str-43", |b| {
        b.iter(|| ore.encrypt_str(black_box(long)).unwrap())
    });
    c.bench_function("chained-encrypt-left-str-17", |b| {
        b.iter(|| ore.encrypt_left_str(black_box(medium)).unwrap())
    });

    let a = ore.encrypt_str(medium).unwrap().to_bytes();
    let b_ct = ore.encrypt_str("alice@example.org").unwrap().to_bytes();
    c.bench_function("chained-compare-str-17", |bench| {
        bench.iter(|| {
            OreAes128Bit6ChainedChaCha20::compare_raw_slices(black_box(&a), black_box(&b_ct))
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
