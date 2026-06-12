use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hex_literal::hex;
use ore_rs::{scheme::bit2_w6::OreAes128Bit6ChaCha20, OreCipher, OreEncrypt, OreOutput};

fn init_ore() -> OreAes128Bit6ChaCha20 {
    let k1: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let k2: [u8; 16] = hex!("d0d1d2d3 d4d5d6d7 d8d9dadb dcdddedf");
    OreCipher::init(&k1, &k2).unwrap()
}

fn criterion_benchmark(c: &mut Criterion) {
    let ore = init_ore();

    c.bench_function("bit6-encrypt-u64", |b| {
        b.iter(|| black_box(25u64).encrypt(&ore).unwrap())
    });

    c.bench_function("bit6-encrypt-left-u64", |b| {
        b.iter(|| black_box(25u64).encrypt_left(&ore).unwrap())
    });

    c.bench_function("bit6-encrypt-u32", |b| {
        b.iter(|| black_box(25u32).encrypt(&ore).unwrap())
    });

    let a = 25u64.encrypt(&ore).unwrap();
    let b_ct = 1025u64.encrypt(&ore).unwrap();
    c.bench_function("bit6-compare-u64", |bench| {
        bench.iter(|| black_box(&a).partial_cmp(black_box(&b_ct)))
    });

    let a_bytes = a.to_bytes();
    let b_bytes = b_ct.to_bytes();
    c.bench_function("bit6-compare-u64-slice", |bench| {
        bench.iter(|| {
            OreAes128Bit6ChaCha20::compare_raw_slices(black_box(&a_bytes), black_box(&b_bytes))
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
