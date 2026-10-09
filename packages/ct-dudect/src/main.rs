//! dudect timing-leakage benches for the v2 ORE comparators and encryptors.
//!
//! dudect feeds two input classes to the same function, interleaved, and
//! runs Welch's t-test on the timing distributions. `|t| < 5` after a few
//! million samples means no leakage was detected between the classes.
//!
//! The comparator benches ask the question the constant-time prefix scan is
//! meant to answer: does the time to compare two ciphertexts depend on
//! *where* they first differ? Class `Left` pairs differ in the first block;
//! class `Right` pairs share every block but the last. The encryptor benches
//! ask whether encryption time depends on the plaintext: `Left` is the
//! all-zero value, `Right` a random one.
//!
//! Run on a quiet machine: `cargo run --release -- --continuous` (all
//! benches, until interrupted) or `cargo run --release -- <name>`.

use dudect_bencher::rand::RngExt;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use ore_rs::ct_bench::{self, Line};
use ore_rs::scheme::bit2_w6::OreAes128Bit6ChaCha20;
use ore_rs::scheme::chained::{OreAes128Bit6Chained, OreAes128Bit6ChainedChaCha20};
use ore_rs::{OreCipher, OreEncrypt, OreOutput};
use std::hint::black_box;

const K1: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const K2: [u8; 16] = [
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
];

/// Inputs per class, precomputed so the measured region is the call alone.
/// `CT_DUDECT_POOL` overrides it: a pool of a few entries keeps every input
/// in L1, which separates cache effects from arithmetic ones.
fn pool_size() -> usize {
    std::env::var("CT_DUDECT_POOL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512)
}
/// Measurements per invocation of a bench (dudect's `--continuous` loops).
const SAMPLES: usize = 100_000;

/// With `CT_DUDECT_DIT=1`, set the ARMv8.4 DIT (data-independent timing)
/// bit for this thread before measuring, and fail if it does not stick. On
/// Apple M3 and later this also disables the data memory-dependent
/// prefetcher, whose behaviour depends on whether loaded *values* look like
/// pointers; a difference that disappears under DIT is that
/// microarchitectural effect, not a data-dependent code path. (On M1 and M2
/// DIT does not affect the prefetcher.)
///
/// Every bench calls this first, so the setting covers all of them.
fn data_independent_timing() {
    if std::env::var_os("CT_DUDECT_DIT").is_none() {
        return;
    }
    #[cfg(target_arch = "aarch64")]
    {
        assert!(
            std::arch::is_aarch64_feature_detected!("dit"),
            "CT_DUDECT_DIT is set but this CPU does not implement FEAT_DIT"
        );
        // PSTATE.DIT is bit 24 of system register S3_3_C4_C2_5. The generic
        // encoding assembles without the ARMv8.4 `dit` target feature, which
        // aarch64 Linux targets do not enable (only Apple's baseline does).
        const DIT: u64 = 1 << 24;
        let mut v: u64;
        // SAFETY: reads and sets the per-thread timing control bit only; it
        // touches no memory and has no other architectural effect. FEAT_DIT
        // is checked above, so the register exists.
        unsafe {
            std::arch::asm!("mrs {v}, s3_3_c4_c2_5", v = out(reg) v, options(nomem, nostack));
            std::arch::asm!("msr s3_3_c4_c2_5, {v}", v = in(reg) v | DIT, options(nomem, nostack));
            std::arch::asm!("mrs {v}, s3_3_c4_c2_5", v = out(reg) v, options(nomem, nostack));
        }
        assert!(v & DIT != 0, "CT_DUDECT_DIT: the DIT bit did not stick");
    }
    #[cfg(not(target_arch = "aarch64"))]
    panic!("CT_DUDECT_DIT is set, but DIT is an aarch64 feature");
}

fn bit6() -> OreAes128Bit6ChaCha20 {
    data_independent_timing();
    OreCipher::init(&K1, &K2).unwrap()
}

fn chained() -> OreAes128Bit6ChainedChaCha20 {
    data_independent_timing();
    OreAes128Bit6Chained::init(&K1).unwrap()
}

/// Random class assignment, so the two classes interleave.
fn class(rng: &mut BenchRng) -> Class {
    if rng.random::<bool>() {
        Class::Left
    } else {
        Class::Right
    }
}

/// Bit6 u64 comparator: first block differs (`Left`) versus only the last
/// 6-bit block differs (`Right`).
fn bit6_compare_first_vs_last_block(runner: &mut CtRunner, rng: &mut BenchRng) {
    let ore = bit6();
    let mut left = Vec::with_capacity(pool_size());
    let mut right = Vec::with_capacity(pool_size());
    for _ in 0..pool_size() {
        let x: u64 = rng.random::<u64>();
        // Flip the top bit: block 0 differs.
        let y0 = x ^ (1 << 63);
        // Flip the bottom bit: only the last block differs.
        let y1 = x ^ 1;
        left.push((
            x.encrypt(&ore).unwrap().to_bytes(),
            y0.encrypt(&ore).unwrap().to_bytes(),
        ));
        right.push((
            x.encrypt(&ore).unwrap().to_bytes(),
            y1.encrypt(&ore).unwrap().to_bytes(),
        ));
    }
    for _ in 0..SAMPLES {
        let c = class(rng);
        let pool = if matches!(c, Class::Left) {
            &left
        } else {
            &right
        };
        let (a, b) = &pool[rng.random_range(0..pool_size())];
        runner.run_one(c, || {
            black_box(OreAes128Bit6ChaCha20::compare_raw_slices(
                black_box(a),
                black_box(b),
            ))
        });
    }
}

/// Chained string comparator over 17-character strings: first byte differs
/// (`Left`) versus only the last byte differs (`Right`).
fn chained_compare_first_vs_last_byte(runner: &mut CtRunner, rng: &mut BenchRng) {
    let ore = chained();
    let mut left = Vec::with_capacity(pool_size());
    let mut right = Vec::with_capacity(pool_size());
    for _ in 0..pool_size() {
        let mut s = [0u8; 17];
        for b in s.iter_mut() {
            *b = rng.random_range(b'a'..=b'z');
        }
        let mut first = s;
        first[0] ^= 0x01;
        let mut last = s;
        last[16] ^= 0x01;
        let enc = |bytes: &[u8]| {
            ore.encrypt_str(std::str::from_utf8(bytes).unwrap())
                .unwrap()
                .to_bytes()
        };
        left.push((enc(&s), enc(&first)));
        right.push((enc(&s), enc(&last)));
    }
    for _ in 0..SAMPLES {
        let c = class(rng);
        let pool = if matches!(c, Class::Left) {
            &left
        } else {
            &right
        };
        let (a, b) = &pool[rng.random_range(0..pool_size())];
        runner.run_one(c, || {
            black_box(OreAes128Bit6ChainedChaCha20::compare_raw_slices(
                black_box(a),
                black_box(b),
            ))
        });
    }
}

/// Bit6 u64 encryption: all-zero plaintext (`Left`) versus random (`Right`).
/// Both classes draw from a precomputed pool, so the work between two
/// measurements is the same whichever class comes next.
fn bit6_encrypt_zero_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    let ore = bit6();
    let left = vec![0u64; pool_size()];
    let right: Vec<u64> = (0..pool_size()).map(|_| rng.random::<u64>()).collect();
    for _ in 0..SAMPLES {
        let c = class(rng);
        let pool = if matches!(c, Class::Left) {
            &left
        } else {
            &right
        };
        let x = pool[rng.random_range(0..pool_size())];
        runner.run_one(c, || black_box(black_box(x).encrypt(&ore).unwrap()));
    }
}

/// Bit6 u64 encryption: one fixed random-looking plaintext (`Left`) versus
/// fresh random ones (`Right`). Separates "the value is constant" from "the
/// value is zero": a constant with the shape of a random word isolates the
/// zero class's other property, that it never looks like a pointer.
fn bit6_encrypt_const_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    let ore = bit6();
    let left = vec![0x1234_5678_9abc_def0u64; pool_size()];
    let right: Vec<u64> = (0..pool_size()).map(|_| rng.random::<u64>()).collect();
    for _ in 0..SAMPLES {
        let c = class(rng);
        let pool = if matches!(c, Class::Left) {
            &left
        } else {
            &right
        };
        let x = pool[rng.random_range(0..pool_size())];
        runner.run_one(c, || black_box(black_box(x).encrypt(&ore).unwrap()));
    }
}

/// Bit6 u64 *left-only* encryption, constant versus random plaintext. The
/// left path is the prefix PRF, the PRP build and the oblivious `permute`;
/// no random-oracle keys, hashing or right blocks.
fn bit6_encrypt_left_const_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    let ore = bit6();
    let left = vec![0x1234_5678_9abc_def0u64; pool_size()];
    let right: Vec<u64> = (0..pool_size()).map(|_| rng.random::<u64>()).collect();
    for _ in 0..SAMPLES {
        let c = class(rng);
        let pool = if matches!(c, Class::Left) {
            &left
        } else {
            &right
        };
        let x = pool[rng.random_range(0..pool_size())];
        runner.run_one(c, || black_box(black_box(x).encrypt_left(&ore).unwrap()));
    }
}

/// The PRP builder alone (`LemireFyPrp::from_stream`, the oblivious builder
/// the schemes use, through the `ct-bench` hook): one fixed 512-byte draw
/// stream (`Left`) versus fresh random streams (`Right`). The draw stream
/// decides every Fisher–Yates swap, so this isolates the builder from
/// everything else in the encryptor.
fn prp_build_const_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    data_independent_timing();
    let mut fixed = [0u8; 512];
    for b in fixed.iter_mut() {
        *b = rng.random::<u8>();
    }
    let left = vec![fixed; pool_size()];
    let right: Vec<[u8; 512]> = (0..pool_size())
        .map(|_| {
            let mut s = [0u8; 512];
            for b in s.iter_mut() {
                *b = rng.random::<u8>();
            }
            s
        })
        .collect();
    for _ in 0..SAMPLES {
        let c = class(rng);
        let pool = if matches!(c, Class::Left) {
            &left
        } else {
            &right
        };
        let s = &pool[rng.random_range(0..pool_size())];
        runner.run_one(c, || {
            black_box(ore_rs::ct_bench::lemire_fy_prp_from_stream(black_box(s)))
        });
    }
}

/// The PRP builder on two *different fixed* streams, `A` (`Left`) and `B`
/// (`Right`). Both classes repeat their input, so predictor training is the
/// same for each; a difference here means the time depends on *which*
/// permutation is built, not merely on whether the input repeats.
fn prp_build_fixed_a_vs_fixed_b(runner: &mut CtRunner, rng: &mut BenchRng) {
    data_independent_timing();
    let mut a = [0u8; 512];
    let mut b = [0u8; 512];
    for x in a.iter_mut().chain(b.iter_mut()) {
        *x = rng.random::<u8>();
    }
    for _ in 0..SAMPLES {
        let c = class(rng);
        let s = if matches!(c, Class::Left) { &a } else { &b };
        runner.run_one(c, || {
            black_box(ore_rs::ct_bench::lemire_fy_prp_from_stream(black_box(s)))
        });
    }
}

/// Bit6 u64 left-only encryption of two different fixed plaintexts: the
/// same question as `prp_build_fixed_a_vs_fixed_b`, end to end.
fn bit6_encrypt_left_fixed_a_vs_fixed_b(runner: &mut CtRunner, rng: &mut BenchRng) {
    let ore = bit6();
    let a: u64 = rng.random();
    let b: u64 = rng.random();
    for _ in 0..SAMPLES {
        let c = class(rng);
        let x = if matches!(c, Class::Left) { a } else { b };
        runner.run_one(c, || black_box(black_box(x).encrypt_left(&ore).unwrap()));
    }
}

/// Chained encryption of 17 bytes: all-`a` plaintext (`Left`) versus random
/// lowercase (`Right`), both from precomputed pools.
fn chained_encrypt_fixed_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    let ore = chained();
    let left: Vec<String> = vec!["a".repeat(17); pool_size()];
    let right: Vec<String> = (0..pool_size())
        .map(|_| {
            (0..17)
                .map(|_| char::from(rng.random_range(b'a'..=b'z')))
                .collect()
        })
        .collect();
    for _ in 0..SAMPLES {
        let c = class(rng);
        let pool = if matches!(c, Class::Left) {
            &left
        } else {
            &right
        };
        let s = pool[rng.random_range(0..pool_size())].as_str();
        runner.run_one(c, || black_box(ore.encrypt_str(black_box(s)).unwrap()));
    }
}

/// Two fixed random 512-byte draw streams for the isolation benches.
fn stream_pair(rng: &mut BenchRng) -> ([u8; 512], [u8; 512]) {
    let mut a = [0u8; 512];
    let mut b = [0u8; 512];
    for x in a.iter_mut().chain(b.iter_mut()) {
        *x = rng.random::<u8>();
    }
    (a, b)
}

/// Mechanism isolation, swap half: the Fisher–Yates swap loop alone, at
/// the secret draw-derived index, on two fixed streams.
fn iso_swap_secret_fixed_a_vs_fixed_b(runner: &mut CtRunner, rng: &mut BenchRng) {
    data_independent_timing();
    let (a, b) = stream_pair(rng);
    for _ in 0..SAMPLES {
        let c = class(rng);
        let s = if matches!(c, Class::Left) { &a } else { &b };
        runner.run_one(c, || {
            let mut out = Line([0u8; 64]);
            ct_bench::fy_swaps_only(black_box(s), &mut out);
            black_box(out.0[0])
        });
    }
}

/// Control for the swap half: the same draws and swaps at a public index.
fn iso_swap_public_fixed_a_vs_fixed_b(runner: &mut CtRunner, rng: &mut BenchRng) {
    data_independent_timing();
    let (a, b) = stream_pair(rng);
    for _ in 0..SAMPLES {
        let c = class(rng);
        let s = if matches!(c, Class::Left) { &a } else { &b };
        runner.run_one(c, || {
            let mut out = Line([0u8; 64]);
            ct_bench::fy_swaps_public(black_box(s), &mut out);
            black_box(out.0[0])
        });
    }
}

/// Mechanism isolation, inverse half: the inverse fill alone, from the two
/// permutations two fixed streams build (computed outside the measurement).
fn iso_fill_secret_fixed_a_vs_fixed_b(runner: &mut CtRunner, rng: &mut BenchRng) {
    data_independent_timing();
    let (a, b) = stream_pair(rng);
    let (pa, pb) = (ct_bench::permutation_for(&a), ct_bench::permutation_for(&b));
    for _ in 0..SAMPLES {
        let c = class(rng);
        let p = if matches!(c, Class::Left) { &pa } else { &pb };
        runner.run_one(c, || {
            let mut out = Line([0u8; 64]);
            ct_bench::inverse_fill_only(black_box(p), &mut out);
            black_box(out.0[0])
        });
    }
}

/// Control for the inverse half: the same loads and stores at public offsets.
fn iso_fill_public_fixed_a_vs_fixed_b(runner: &mut CtRunner, rng: &mut BenchRng) {
    data_independent_timing();
    let (a, b) = stream_pair(rng);
    let (pa, pb) = (ct_bench::permutation_for(&a), ct_bench::permutation_for(&b));
    for _ in 0..SAMPLES {
        let c = class(rng);
        let p = if matches!(c, Class::Left) { &pa } else { &pb };
        runner.run_one(c, || {
            let mut out = Line([0u8; 64]);
            ct_bench::inverse_fill_public(black_box(p), &mut out);
            black_box(out.0[0])
        });
    }
}

/// `prp_build_fixed_a_vs_fixed_b` through the reference builder (textbook
/// Fisher–Yates, secret-indexed), for before/after comparison in one binary.
fn prp_build_reference_fixed_a_vs_fixed_b(runner: &mut CtRunner, rng: &mut BenchRng) {
    data_independent_timing();
    let (a, b) = stream_pair(rng);
    for _ in 0..SAMPLES {
        let c = class(rng);
        let s = if matches!(c, Class::Left) { &a } else { &b };
        runner.run_one(c, || {
            black_box(ct_bench::lemire_fy_prp_from_stream_reference(black_box(s)))
        });
    }
}

/// `prp_build_fixed_a_vs_fixed_b` through the portable scalar oblivious
/// builder.
fn prp_build_scalar_obl_fixed_a_vs_fixed_b(runner: &mut CtRunner, rng: &mut BenchRng) {
    data_independent_timing();
    let (a, b) = stream_pair(rng);
    for _ in 0..SAMPLES {
        let c = class(rng);
        let s = if matches!(c, Class::Left) { &a } else { &b };
        runner.run_one(c, || {
            black_box(ct_bench::lemire_fy_prp_from_stream_scalar_oblivious(
                black_box(s),
            ))
        });
    }
}

/// `prp_build_fixed_a_vs_fixed_b` through the portable SWAR oblivious
/// builder (the fallback on targets with neither NEON nor SSSE3).
fn prp_build_swar_obl_fixed_a_vs_fixed_b(runner: &mut CtRunner, rng: &mut BenchRng) {
    data_independent_timing();
    let (a, b) = stream_pair(rng);
    for _ in 0..SAMPLES {
        let c = class(rng);
        let s = if matches!(c, Class::Left) { &a } else { &b };
        runner.run_one(c, || {
            black_box(ct_bench::lemire_fy_prp_from_stream_swar_oblivious(
                black_box(s),
            ))
        });
    }
}

ctbench_main!(
    bit6_compare_first_vs_last_block,
    chained_compare_first_vs_last_byte,
    bit6_encrypt_zero_vs_random,
    bit6_encrypt_const_vs_random,
    bit6_encrypt_left_const_vs_random,
    bit6_encrypt_left_fixed_a_vs_fixed_b,
    prp_build_const_vs_random,
    prp_build_fixed_a_vs_fixed_b,
    chained_encrypt_fixed_vs_random,
    iso_swap_secret_fixed_a_vs_fixed_b,
    iso_swap_public_fixed_a_vs_fixed_b,
    iso_fill_secret_fixed_a_vs_fixed_b,
    iso_fill_public_fixed_a_vs_fixed_b,
    prp_build_reference_fixed_a_vs_fixed_b,
    prp_build_scalar_obl_fixed_a_vs_fixed_b,
    prp_build_swar_obl_fixed_a_vs_fixed_b
);
