use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hex_literal::hex;
use ore_rs::scheme::chained::{Options, OreAes128Bit6Chained, Padding};
use ore_rs::OreScheme;
use vitaminc_ore::{order, OrderPlaintext, OrderTarget, Physical};
use vitaminc_protected::Protected;

/// Unpadded, so that a bench encrypts the length its name implies. A name
/// gives the characters, and each text encrypts one byte more (vitaminc's
/// marker, see [`text`]) after folding, so these do not compare one for one
/// with 0.9's runs of the same names, which encrypted the raw string. The
/// padded benches below use the default policy.
fn init_ore(padding: Padding) -> OreAes128Bit6Chained {
    let k1: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    OreAes128Bit6Chained::init_with(Protected::new(k1), Options::default().with_padding(padding))
        .unwrap()
}

/// Text as vitaminc encodes it: a marker byte, then the folded string, so
/// a bench named for `n` characters encrypts `n + 1` bytes.
fn text(s: &str) -> OrderPlaintext {
    order(OrderTarget::Text, None, Physical::Text(s)).unwrap()
}

fn criterion_benchmark(c: &mut Criterion) {
    let ore = init_ore(Padding::None);
    let padded = init_ore(Padding::default());

    // 6, 18 and 44 bytes with the marker: 8, 24 and 59 blocks.
    let short = text("alice");
    let medium = text("alice@example.com");
    let long = text("the quick brown fox jumps over the lazy dog");

    c.bench_function("chained-encrypt-str-5", |b| {
        b.iter(|| ore.encrypt_plaintext(black_box(&short)).unwrap())
    });
    c.bench_function("chained-encrypt-str-17", |b| {
        b.iter(|| ore.encrypt_plaintext(black_box(&medium)).unwrap())
    });
    c.bench_function("chained-encrypt-str-43", |b| {
        b.iter(|| ore.encrypt_plaintext(black_box(&long)).unwrap())
    });
    c.bench_function("chained-encrypt-left-str-17", |b| {
        b.iter(|| ore.encrypt_query_plaintext(black_box(&medium)).unwrap())
    });

    // The default policy pads 6 bytes to 16 and 18 bytes to 32.
    c.bench_function("chained-encrypt-str-5-padded", |b| {
        b.iter(|| padded.encrypt_plaintext(black_box(&short)).unwrap())
    });
    c.bench_function("chained-encrypt-str-17-padded", |b| {
        b.iter(|| padded.encrypt_plaintext(black_box(&medium)).unwrap())
    });

    let a = ore.encrypt_plaintext(&medium).unwrap().into_bytes();
    let b_ct = ore
        .encrypt_plaintext(&text("alice@example.org"))
        .unwrap()
        .into_bytes();
    c.bench_function("chained-compare-str-17", |bench| {
        bench.iter(|| OreAes128Bit6Chained::compare_raw_slices(black_box(&a), black_box(&b_ct)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
