use cllw_ore::Key;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    let key = Key::from([0; 32]);
    c.bench_function("encrypt-u32-u8", |b| {
        let input: u32 = u32::MAX - 35454646;
        b.iter(|| key.encrypt(black_box(input)))
    });
    c.bench_function("encrypt-u64-u8", |b| {
        let input: u64 = u64::MAX - 35454646;
        b.iter(|| key.encrypt(black_box(input)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
