use clww_ore::{ClwwOpe, ClwwOre};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use vitaminc_ore::target::{Bytes, Text, U128, U16, U32, U64};
use vitaminc_ore::{OrderEncrypt, OrderKeyInit};
use vitaminc_protected::Protected;

const KEY: [u8; 32] = [0; 32];

fn ore(c: &mut Criterion) {
    let scheme = ClwwOre::new(Protected::new(KEY));

    let u16s = scheme.target(U16).context("bench");
    c.bench_function("encrypt-u16", |b| {
        b.iter(|| u16s.encrypt(black_box(u16::MAX - 1234)))
    });
    let u32s = scheme.target(U32).context("bench");
    c.bench_function("encrypt-u32", |b| {
        b.iter(|| u32s.encrypt(black_box(u32::MAX - 35454646)))
    });
    let u64s = scheme.target(U64).context("bench");
    c.bench_function("encrypt-u64", |b| {
        b.iter(|| u64s.encrypt(black_box(u64::MAX - 35454646)))
    });
    let u128s = scheme.target(U128).context("bench");
    c.bench_function("encrypt-u128", |b| {
        b.iter(|| u128s.encrypt(black_box(u128::MAX - 35454646)))
    });

    let text = scheme.target(Text).context("bench");
    for (name, input) in [
        ("encrypt-string-short", "hello"),
        ("encrypt-string-medium", "alice.smith@example.com"),
        (
            "encrypt-string-long",
            "The quick brown fox jumps over the lazy dog",
        ),
    ] {
        c.bench_function(name, |b| b.iter(|| text.encrypt_checked(black_box(input))));
    }

    let bytes = scheme.target(Bytes).context("bench");
    let small: &[u8] = &[0xFF, 0x00, 0xAB, 0xCD];
    let large: &[u8] = &[0x42; 64];
    c.bench_function("encrypt-bytes-small", |b| {
        b.iter(|| bytes.encrypt(black_box(small)))
    });
    c.bench_function("encrypt-bytes-large", |b| {
        b.iter(|| bytes.encrypt(black_box(large)))
    });
}

fn ope(c: &mut Criterion) {
    let scheme = ClwwOpe::new(Protected::new(KEY));
    let u64s = scheme.target(U64).context("bench");
    c.bench_function("encrypt-ope-u64", |b| {
        b.iter(|| u64s.encrypt(black_box(u64::MAX - 35454646)))
    });
    let text = scheme.target(Text).context("bench");
    c.bench_function("encrypt-ope-string-medium", |b| {
        b.iter(|| text.encrypt_checked(black_box("alice.smith@example.com")))
    });
}

criterion_group!(benches, ore, ope);
criterion_main!(benches);
