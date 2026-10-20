use clww_ore::Key;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    let key = Key::from([0; 32]);

    // u16 encryption/decryption benchmarks
    c.bench_function("encrypt-u16", |b| {
        let input: u16 = u16::MAX - 1234;
        b.iter(|| key.encrypt(black_box(input)))
    });
    c.bench_function("decrypt-u16", |b| {
        let input: u16 = u16::MAX - 1234;
        let ciphertext = key.encrypt(input).unwrap();
        b.iter(|| key.decrypt::<_>(black_box(ciphertext)).unwrap())
    });

    // u32 encryption/decryption benchmarks
    c.bench_function("encrypt-u32", |b| {
        let input: u32 = u32::MAX - 35454646;
        b.iter(|| key.encrypt(black_box(input)))
    });
    c.bench_function("decrypt-u32", |b| {
        let input: u32 = u32::MAX - 35454646;
        let ciphertext = key.encrypt(input).unwrap();
        b.iter(|| key.decrypt::<_>(black_box(ciphertext)).unwrap())
    });

    // u64 encryption/decryption benchmarks
    c.bench_function("encrypt-u64", |b| {
        let input: u64 = u64::MAX - 35454646;
        b.iter(|| key.encrypt(black_box(input)))
    });
    c.bench_function("decrypt-u64", |b| {
        let input: u64 = u64::MAX - 35454646;
        let ciphertext = key.encrypt(input).unwrap();
        b.iter(|| key.decrypt::<_>(black_box(ciphertext)).unwrap())
    });

    // u128 encryption/decryption benchmarks
    c.bench_function("encrypt-u128", |b| {
        let input: u128 = u128::MAX - 35454646;
        b.iter(|| key.encrypt(black_box(input)))
    });
    c.bench_function("decrypt-u128", |b| {
        let input: u128 = u128::MAX - 35454646;
        let ciphertext = key.encrypt(input).unwrap();
        b.iter(|| key.decrypt::<_>(black_box(ciphertext)).unwrap())
    });

    // String encryption/decryption benchmarks
    c.bench_function("encrypt-string-short", |b| {
        let input = "hello";
        b.iter(|| key.encrypt(black_box(input)))
    });
    c.bench_function("decrypt-string-short", |b| {
        let input = "hello";
        let ciphertext = key.encrypt(input).unwrap();
        b.iter(|| key.decrypt(black_box(ciphertext.clone())).unwrap())
    });

    c.bench_function("encrypt-string-medium", |b| {
        let input = "alice.smith@example.com";
        b.iter(|| key.encrypt(black_box(input)))
    });
    c.bench_function("decrypt-string-medium", |b| {
        let input = "alice.smith@example.com";
        let ciphertext = key.encrypt(input).unwrap();
        b.iter(|| key.decrypt(black_box(ciphertext.clone())).unwrap())
    });

    c.bench_function("encrypt-string-long", |b| {
        let input = "The quick brown fox jumps over the lazy dog";
        b.iter(|| key.encrypt(black_box(input)))
    });
    c.bench_function("decrypt-string-long", |b| {
        let input = "The quick brown fox jumps over the lazy dog";
        let ciphertext = key.encrypt(input).unwrap();
        b.iter(|| key.decrypt(black_box(ciphertext.clone())).unwrap())
    });

    // Byte slice encryption/decryption benchmarks
    c.bench_function("encrypt-bytes-small", |b| {
        let input: &[u8] = &[0xFF, 0x00, 0xAB, 0xCD];
        b.iter(|| key.encrypt(black_box(input)))
    });
    c.bench_function("decrypt-bytes-small", |b| {
        let input: &[u8] = &[0xFF, 0x00, 0xAB, 0xCD];
        let ciphertext = key.encrypt(input).unwrap();
        b.iter(|| black_box(&ciphertext).decrypt_to_bytes(&key, None).unwrap())
    });

    c.bench_function("encrypt-bytes-large", |b| {
        let input: &[u8] = &[0x42; 64];
        b.iter(|| key.encrypt(black_box(input)))
    });
    c.bench_function("decrypt-bytes-large", |b| {
        let input: &[u8] = &[0x42; 64];
        let ciphertext = key.encrypt(input).unwrap();
        b.iter(|| black_box(&ciphertext).decrypt_to_bytes(&key, None).unwrap())
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
