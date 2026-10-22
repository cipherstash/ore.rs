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
use ore_rs::scheme::bit2_w6::OreAes128Bit6;
use ore_rs::scheme::chained::{Options, OreAes128Bit6Chained, Padding};
use ore_rs::OreScheme;
use std::hint::black_box;
use vitaminc_ore::{order, Int, OrderPlaintext, OrderTarget, Physical};
use vitaminc_protected::Protected;

const K1: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
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

fn bit6() -> OreAes128Bit6 {
    data_independent_timing();
    OreAes128Bit6::init(Protected::new(K1)).unwrap()
}

/// The sealed `u64` plaintext of `x`: what the encryptor takes. Made
/// outside the measured region, so the region is the encryption alone.
fn u64_pt(x: u64) -> OrderPlaintext {
    order(OrderTarget::U64, None, Physical::Int(Int::U64(x))).unwrap()
}

/// The sealed `u128` plaintext of `x`.
fn u128_pt(x: u128) -> OrderPlaintext {
    order(OrderTarget::U128, None, Physical::Int(Int::U128(x))).unwrap()
}

/// The sealed text plaintext of `s`: vitaminc's marker byte, then the
/// folded text, which for lowercase ASCII is the text itself.
fn text_pt(s: &str) -> OrderPlaintext {
    order(OrderTarget::Text, None, Physical::Text(s)).unwrap()
}

/// The chained cipher under `padding`. A harness that places the differing
/// byte at a chosen block must pass [`Padding::None`]: a padded 17-byte
/// string becomes 32 bytes, and its last byte is no longer the last block.
fn chained(padding: Padding) -> OreAes128Bit6Chained {
    data_independent_timing();
    OreAes128Bit6Chained::init_with(
        Protected::new(K1),
        Options::default().with_padding(padding),
    )
    .unwrap()
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
        let enc = |v: u64| ore.encrypt_plaintext(&u64_pt(v)).unwrap().into_bytes();
        left.push((enc(x), enc(y0)));
        right.push((enc(x), enc(y1)));
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
            black_box(OreAes128Bit6::compare_raw_slices(
                black_box(a),
                black_box(b),
            ))
        });
    }
}

/// Chained comparator, first byte differs (`Left`) versus only the last
/// byte differs (`Right`), over `u128`s: 16 bytes, 22 blocks, the
/// difference in block 0 or block 21. Not text: vitaminc puts a constant
/// marker byte before every text, so no two texts differ in block 0. The
/// comparator is the same for every target (it reads the bytes and the
/// header, not the target), and fixed-width plaintexts go in unpadded, so
/// the last byte is in the last block.
fn chained_compare_first_vs_last_byte(runner: &mut CtRunner, rng: &mut BenchRng) {
    let ore = chained(Padding::None);
    let mut left = Vec::with_capacity(pool_size());
    let mut right = Vec::with_capacity(pool_size());
    for _ in 0..pool_size() {
        let x: u128 = rng.random();
        let first = x ^ (1 << 127);
        let last = x ^ 1;
        let enc = |x: u128| ore.encrypt_plaintext(&u128_pt(x)).unwrap().into_bytes();
        left.push((enc(x), enc(first)));
        right.push((enc(x), enc(last)));
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
            black_box(OreAes128Bit6Chained::compare_raw_slices(
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
    let left: Vec<OrderPlaintext> = (0..pool_size()).map(|_| u64_pt(0)).collect();
    let right: Vec<OrderPlaintext> = (0..pool_size()).map(|_| u64_pt(rng.random())).collect();
    for _ in 0..SAMPLES {
        let c = class(rng);
        let pool = if matches!(c, Class::Left) {
            &left
        } else {
            &right
        };
        let x = &pool[rng.random_range(0..pool_size())];
        runner.run_one(c, || black_box(ore.encrypt_plaintext(black_box(x)).unwrap()));
    }
}

/// Bit6 u64 encryption: one fixed random-looking plaintext (`Left`) versus
/// fresh random ones (`Right`). Separates "the value is constant" from "the
/// value is zero": a constant with the shape of a random word isolates the
/// zero class's other property, that it never looks like a pointer.
fn bit6_encrypt_const_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    let ore = bit6();
    let left: Vec<OrderPlaintext> = (0..pool_size())
        .map(|_| u64_pt(0x1234_5678_9abc_def0))
        .collect();
    let right: Vec<OrderPlaintext> = (0..pool_size()).map(|_| u64_pt(rng.random())).collect();
    for _ in 0..SAMPLES {
        let c = class(rng);
        let pool = if matches!(c, Class::Left) {
            &left
        } else {
            &right
        };
        let x = &pool[rng.random_range(0..pool_size())];
        runner.run_one(c, || black_box(ore.encrypt_plaintext(black_box(x)).unwrap()));
    }
}

/// Bit6 u64 *left-only* encryption, constant versus random plaintext. The
/// left path is the prefix PRF, the PRP build and the oblivious `permute`;
/// no random-oracle keys, hashing or right blocks.
fn bit6_encrypt_left_const_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    let ore = bit6();
    let left: Vec<OrderPlaintext> = (0..pool_size())
        .map(|_| u64_pt(0x1234_5678_9abc_def0))
        .collect();
    let right: Vec<OrderPlaintext> = (0..pool_size()).map(|_| u64_pt(rng.random())).collect();
    for _ in 0..SAMPLES {
        let c = class(rng);
        let pool = if matches!(c, Class::Left) {
            &left
        } else {
            &right
        };
        let x = &pool[rng.random_range(0..pool_size())];
        runner.run_one(c, || {
            black_box(ore.encrypt_query_plaintext(black_box(x)).unwrap())
        });
    }
}

/// Builds timed per sample by `prp_build_const_vs_random` and
/// `prp_build_fixed_a_vs_fixed_b`. One build takes about 200 ns, five ticks
/// of Apple's 24 MHz counter, so a one-build sample takes only a handful of
/// values and a class difference is a sliver of samples crossing a tick
/// boundary, which dudect's percentile cropping (cut exactly at those tick
/// values) exaggerates. Sixteen builds per sample span about eighty ticks.
const BUILDS_PER_SAMPLE: usize = 16;

/// A fresh random 512-byte draw stream.
fn random_stream(rng: &mut BenchRng) -> [u8; 512] {
    let mut s = [0u8; 512];
    for b in s.iter_mut() {
        *b = rng.random::<u8>();
    }
    s
}

/// The PRP builder alone (`LemireFyPrp::from_stream`, the oblivious builder
/// the schemes use, through the `ct-bench` hook): one fixed 512-byte draw
/// stream (`Left`) versus fresh random streams (`Right`). The draw stream
/// decides every Fisher–Yates swap, so this isolates the builder from
/// everything else in the encryptor.
///
/// Both classes share one pool of `2 * pool` streams, and a random half of
/// its slots, redrawn every batch, holds the fixed stream, so the classes
/// differ in content only. With a separate pool per class they also differ
/// in where their inputs sit, and that alone moved t from -13 to +55 with
/// the layout (`prp_build_const_vs_random_separate_pools` and the
/// interleaved controls below). Each sample times `BUILDS_PER_SAMPLE`
/// builds over streams from the class's slots.
fn prp_build_const_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    data_independent_timing();
    let fixed = random_stream(rng);
    let n = 2 * pool_size();
    // Fisher–Yates over slot indices: the first half are `Left`.
    let mut order: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        order.swap(i, rng.random_range(0..=i));
    }
    let (left_idx, right_idx) = order.split_at(pool_size());
    let mut pool = vec![[0u8; 512]; n];
    for &k in left_idx {
        pool[k] = fixed;
    }
    for &k in right_idx {
        pool[k] = random_stream(rng);
    }
    for _ in 0..SAMPLES {
        let c = class(rng);
        let idx = if matches!(c, Class::Left) {
            left_idx
        } else {
            right_idx
        };
        let picks: [&[u8; 512]; BUILDS_PER_SAMPLE] =
            std::array::from_fn(|_| &pool[idx[rng.random_range(0..pool_size())]]);
        runner.run_one(c, || {
            let mut acc = 0u8;
            for s in picks {
                acc ^= ore_rs::ct_bench::lemire_fy_prp_from_stream(black_box(s));
            }
            black_box(acc)
        });
    }
}

/// Artifact control: `prp_build_const_vs_random` as first written, one
/// build per sample and a separate pool per class (`Left`'s, 512 copies of
/// the fixed stream, allocated first). This is the bench behind the +7.7 to
/// +31 residuals; it is kept to show that they come from the harness.
fn prp_build_const_vs_random_separate_pools(runner: &mut CtRunner, rng: &mut BenchRng) {
    data_independent_timing();
    let fixed = random_stream(rng);
    let left = vec![fixed; pool_size()];
    let right: Vec<[u8; 512]> = (0..pool_size()).map(|_| random_stream(rng)).collect();
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

/// Artifact control: one build per sample, both classes in one pool,
/// interleaved, `Left` at the slots of parity `left_parity`. Placement is
/// systematic but differs only by a 512-byte offset; the result's sign
/// follows the parity.
fn interleaved(runner: &mut CtRunner, rng: &mut BenchRng, left_parity: usize) {
    data_independent_timing();
    let fixed = random_stream(rng);
    let mut pool = vec![[0u8; 512]; 2 * pool_size()];
    for (k, s) in pool.iter_mut().enumerate() {
        *s = if k % 2 == left_parity {
            fixed
        } else {
            random_stream(rng)
        };
    }
    for _ in 0..SAMPLES {
        let c = class(rng);
        let parity = if matches!(c, Class::Left) {
            left_parity
        } else {
            1 - left_parity
        };
        let s = &pool[2 * rng.random_range(0..pool_size()) + parity];
        runner.run_one(c, || {
            black_box(ore_rs::ct_bench::lemire_fy_prp_from_stream(black_box(s)))
        });
    }
}

/// [`interleaved`] with the fixed stream at even slots.
fn prp_build_const_vs_random_interleaved_even(runner: &mut CtRunner, rng: &mut BenchRng) {
    interleaved(runner, rng, 0);
}

/// [`interleaved`] with the fixed stream at odd slots.
fn prp_build_const_vs_random_interleaved_odd(runner: &mut CtRunner, rng: &mut BenchRng) {
    interleaved(runner, rng, 1);
}

/// The PRP builder on two *different fixed* streams, `A` (`Left`) and `B`
/// (`Right`). Both classes repeat their input, so predictor training is the
/// same for each; a difference here means the time depends on *which*
/// permutation is built, not merely on whether the input repeats. Each
/// sample times `BUILDS_PER_SAMPLE` builds.
fn prp_build_fixed_a_vs_fixed_b(runner: &mut CtRunner, rng: &mut BenchRng) {
    data_independent_timing();
    let (a, b) = (random_stream(rng), random_stream(rng));
    for _ in 0..SAMPLES {
        let c = class(rng);
        let s = if matches!(c, Class::Left) { &a } else { &b };
        runner.run_one(c, || {
            let mut acc = 0u8;
            for _ in 0..BUILDS_PER_SAMPLE {
                acc ^= ore_rs::ct_bench::lemire_fy_prp_from_stream(black_box(s));
            }
            black_box(acc)
        });
    }
}

/// Bit6 u64 left-only encryption of two different fixed plaintexts: the
/// same question as `prp_build_fixed_a_vs_fixed_b`, end to end.
fn bit6_encrypt_left_fixed_a_vs_fixed_b(runner: &mut CtRunner, rng: &mut BenchRng) {
    let ore = bit6();
    let a = u64_pt(rng.random());
    let b = u64_pt(rng.random());
    for _ in 0..SAMPLES {
        let c = class(rng);
        let x = if matches!(c, Class::Left) { &a } else { &b };
        runner.run_one(c, || {
            black_box(ore.encrypt_query_plaintext(black_box(x)).unwrap())
        });
    }
}

/// Chained encryption of 17 bytes: all-`a` plaintext (`Left`) versus random
/// lowercase (`Right`), both from precomputed pools. Under the default
/// padding, so the padding path (32 bytes, the trailing-NUL check) is what
/// is timed.
fn chained_encrypt_fixed_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    let ore = chained(Padding::default());
    let left: Vec<OrderPlaintext> = (0..pool_size())
        .map(|_| text_pt(&"a".repeat(17)))
        .collect();
    let right: Vec<OrderPlaintext> = (0..pool_size())
        .map(|_| {
            let s: String = (0..17)
                .map(|_| char::from(rng.random_range(b'a'..=b'z')))
                .collect();
            text_pt(&s)
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
        runner.run_one(c, || black_box(ore.encrypt_plaintext(black_box(s)).unwrap()));
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
    prp_build_const_vs_random_separate_pools,
    prp_build_const_vs_random_interleaved_even,
    prp_build_const_vs_random_interleaved_odd,
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
