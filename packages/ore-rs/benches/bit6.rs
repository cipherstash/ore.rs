use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hex_literal::hex;
use ore_rs::{scheme::bit2_w6::OreAes128Bit6, OreScheme};
use vitaminc_ore::{order, Int, OrderPlaintext, OrderTarget, Physical};
use vitaminc_protected::Protected;

fn init_ore() -> OreAes128Bit6 {
    let k1: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    OreAes128Bit6::init(Protected::new(k1)).unwrap()
}

fn u64_pt(x: u64) -> OrderPlaintext {
    order(OrderTarget::U64, None, Physical::Int(Int::U64(x))).unwrap()
}

fn u32_pt(x: u32) -> OrderPlaintext {
    order(OrderTarget::U32, None, Physical::Int(Int::U32(x))).unwrap()
}

fn criterion_benchmark(c: &mut Criterion) {
    let ore = init_ore();
    let (p64, p32) = (u64_pt(25), u32_pt(25));

    c.bench_function("bit6-encrypt-u64", |b| {
        b.iter(|| ore.encrypt_plaintext(black_box(&p64)).unwrap())
    });

    c.bench_function("bit6-encrypt-left-u64", |b| {
        b.iter(|| ore.encrypt_query_plaintext(black_box(&p64)).unwrap())
    });

    c.bench_function("bit6-encrypt-u32", |b| {
        b.iter(|| ore.encrypt_plaintext(black_box(&p32)).unwrap())
    });

    let a_bytes = ore.encrypt_plaintext(&u64_pt(25)).unwrap().into_bytes();
    let b_bytes = ore.encrypt_plaintext(&u64_pt(1025)).unwrap().into_bytes();
    let query = ore
        .encrypt_query_plaintext(&u64_pt(25))
        .unwrap()
        .into_bytes();
    c.bench_function("bit6-compare-u64-slice", |bench| {
        bench.iter(|| OreAes128Bit6::compare_raw_slices(black_box(&a_bytes), black_box(&b_bytes)))
    });
    c.bench_function("bit6-compare-u64-query", |bench| {
        bench.iter(|| OreAes128Bit6::compare_left_to_full(black_box(&query), black_box(&b_bytes)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
