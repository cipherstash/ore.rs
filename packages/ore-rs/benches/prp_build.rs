//! The Bit6 PRP builder alone, per 512-byte draw stream: the reference
//! builder (textbook Fisher–Yates, secret-indexed; not used by any scheme),
//! the byte-at-a-time `subtle_ng` and SWAR oblivious builders, and the
//! target's dispatched oblivious builder (NEON on aarch64, SSSE3 or SWAR on
//! x86_64, SWAR elsewhere), which is what the schemes call. Each goes
//! through a `ct_bench` hook that also builds the struct, does one oblivious
//! `permute` and wipes the struct on drop, a fixed cost common to all.
//!
//! Each iteration takes the next of 256 precomputed random streams, so the
//! figure is an average over swap sequences rather than one sequence's
//! (the reference builder's time depends on the sequence).
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ore_rs::ct_bench;

const STREAMS: usize = 256;

/// A `ct_bench` builder hook: one stream in, one permuted value out.
type Builder = fn(&[u8; 512]) -> u8;

fn streams() -> Vec<[u8; 512]> {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    (0..STREAMS)
        .map(|_| {
            let mut s = [0u8; 512];
            for b in s.iter_mut() {
                // xorshift64: fixed, random-looking streams.
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = (x >> 24) as u8;
            }
            s
        })
        .collect()
}

fn criterion_benchmark(c: &mut Criterion) {
    let s = streams();
    let builders: [(&str, Builder); 4] = [
        (
            "prp-build-reference",
            ct_bench::lemire_fy_prp_from_stream_reference,
        ),
        (
            "prp-build-scalar-oblivious",
            ct_bench::lemire_fy_prp_from_stream_scalar_oblivious,
        ),
        (
            "prp-build-swar-oblivious",
            ct_bench::lemire_fy_prp_from_stream_swar_oblivious,
        ),
        (
            "prp-build-dispatched-oblivious",
            ct_bench::lemire_fy_prp_from_stream,
        ),
    ];
    for (name, build) in builders {
        c.bench_function(name, |b| {
            let mut n = 0usize;
            b.iter(|| {
                n = (n + 1) % STREAMS;
                build(black_box(&s[n]))
            })
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
