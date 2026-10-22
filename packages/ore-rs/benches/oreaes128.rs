use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hex_literal::hex;
use ore_rs::{scheme::bit2::OreAes128, OreScheme};
use vitaminc_ore::{order, Int, OrderPlaintext, OrderTarget, Physical};
use vitaminc_protected::Protected;

fn u64_pt(x: u64) -> OrderPlaintext {
    order(OrderTarget::U64, None, Physical::Int(Int::U64(x))).unwrap()
}

fn u32_pt(x: u32) -> OrderPlaintext {
    order(OrderTarget::U32, None, Physical::Int(Int::U32(x))).unwrap()
}

fn criterion_benchmark(c: &mut Criterion) {
    let k1 = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let k2 = hex!("d0d007a5 3f9a6848 83bc1f21 0f6595a3");

    let ore = OreAes128::init(Protected::new(k1), Protected::new(k2)).unwrap();
    let (p64, p32) = (u64_pt(25), u32_pt(25));
    let x_bytes = ore.encrypt_plaintext(&u64_pt(100)).unwrap().into_bytes();
    let y_bytes = ore
        .encrypt_plaintext(&u64_pt(100983939290192))
        .unwrap()
        .into_bytes();
    let x_query = ore
        .encrypt_query_plaintext(&u64_pt(100))
        .unwrap()
        .into_bytes();

    c.bench_function("encrypt-8", |b| {
        b.iter(|| ore.encrypt_plaintext(black_box(&p64)).unwrap())
    });
    c.bench_function("encrypt-left-8", |b| {
        b.iter(|| ore.encrypt_query_plaintext(black_box(&p64)).unwrap())
    });
    c.bench_function("compare-8-slice", |b| {
        b.iter(|| OreAes128::compare_raw_slices(black_box(&x_bytes), black_box(&y_bytes)))
    });
    c.bench_function("compare-8-query", |b| {
        b.iter(|| OreAes128::compare_left_to_full(black_box(&x_query), black_box(&y_bytes)))
    });

    c.bench_function("encrypt-4", |b| {
        b.iter(|| ore.encrypt_plaintext(black_box(&p32)).unwrap())
    });
    c.bench_function("encrypt-left-4", |b| {
        b.iter(|| ore.encrypt_query_plaintext(black_box(&p32)).unwrap())
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
