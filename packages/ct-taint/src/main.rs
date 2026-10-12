//! Valgrind taint harness for the v2 ORE encryptors (ctgrind technique).
//!
//! Each mode marks the key material and the plaintext as *undefined* memory
//! (Valgrind client request), runs one operation, marks the output defined,
//! and prints a checksum. Under `valgrind --tool=memcheck`, every conditional
//! jump and every memory address that depends on the undefined bytes is
//! reported: those are the secret-dependent branches and secret-indexed
//! accesses. The expected ones are listed, with their reasons, in
//! `valgrind.supp`; `scripts/ct-taint.sh` fails on anything else.
//!
//! Only the encryptors are tainted. The comparators take ciphertexts, which are
//! public, so there is nothing to mark on that path; the comparator's timing
//! behaviour on *equal-prefix versus differing* inputs is a statistical
//! question (dudect), not a taint one.
//!
//! Outside Valgrind the marks are no-ops and the modes just run.
//!
//! **Gate mode** (`CT_TAINT_GATE=1`, set by `scripts/ct-taint.sh`) refuses a
//! vacuous pass. Every taint request must succeed, and each mode checks,
//! before untainting, that its output is still partly undefined: the taint
//! reached the ciphertext, so a clean run means the path really is free of
//! secret-dependent branches and addresses. The `canary` mode branches on a
//! tainted byte and indexes memory with it, and the script requires memcheck
//! to fail it.
//!
//! Scope: the v2 encryptors only. The legacy `OreAes128` encryptor is not
//! run: its Knuth-shuffle PRP rejection-samples and swaps at secret indices
//! by design, and its wire format is frozen (v2 plan, Non-goals).

use std::env;
use std::process::exit;

use crabgrind::memcheck::{mark_memory, vbits, MemState};
use hex_literal::hex;
use ore_rs::scheme::bit2_w6::OreAes128Bit6ChaCha20;
use ore_rs::scheme::chained::{OreAes128Bit6Chained, OreAes128Bit6ChainedChaCha20};
use ore_rs::{OreCipher, OreEncrypt, OreOutput};

/// Whether this run is the gate (`CT_TAINT_GATE` set), which must run under
/// memcheck and must not pass vacuously.
fn gate() -> bool {
    env::var_os("CT_TAINT_GATE").is_some()
}

/// Mark `bytes` undefined: from here on, anything computed from them is
/// tracked as tainted by memcheck.
fn taint(bytes: &mut [u8]) {
    let marked = mark_memory(
        bytes.as_mut_ptr() as *const _,
        bytes.len(),
        MemState::Undefined,
    );
    // Outside Valgrind the request fails and the run is a plain exercise of
    // the path. In the gate that would make every mode pass while checking
    // nothing, so it is fatal there.
    if gate() && marked.is_err() {
        eprintln!("ct-taint: mark_memory failed; the gate must run under memcheck");
        exit(3);
    }
}

/// Fail the gate if every byte of `out` is defined. The ciphertext is
/// computed from the tainted key and plaintext, so some of it must be
/// undefined; if none is, the taint was lost (a request that did nothing, or
/// a key the optimiser kept in a register past the mark) and a clean run
/// proves nothing.
fn assert_tainted(out: &[u8]) {
    if !gate() {
        return;
    }
    // GET_VBITS wants 4-byte-aligned buffers whose length is a multiple of 4.
    let words = out.len() / 4;
    let mut src = vec![0u32; words];
    let mut bits = vec![0u32; words];
    // SAFETY: both buffers hold `words` u32s; the byte views cover them exactly.
    let (src_bytes, bits_bytes) = unsafe {
        (
            std::slice::from_raw_parts_mut(src.as_mut_ptr() as *mut u8, words * 4),
            std::slice::from_raw_parts_mut(bits.as_mut_ptr() as *mut u8, words * 4),
        )
    };
    // The copy carries the V bits with it.
    src_bytes.copy_from_slice(&out[..words * 4]);
    if let Err(e) = vbits(src_bytes.as_ptr() as *const _, bits_bytes) {
        eprintln!("ct-taint: reading V bits failed ({e:?}); the gate must run under memcheck");
        exit(3);
    }
    if bits_bytes.iter().all(|&b| b == 0) {
        eprintln!("ct-taint: the output is fully defined, so the taint never reached it");
        exit(4);
    }
    // Let the copy be dropped without memcheck tracking it as tainted.
    untaint(src_bytes);
}

/// Mark `bytes` defined again, so that using the *output* of an operation
/// (printing it, hashing it) is not itself reported. Checks first, in the
/// gate, that the taint reached it.
fn untaint_output(bytes: &mut [u8]) {
    assert_tainted(bytes);
    untaint(bytes);
}

fn untaint(bytes: &mut [u8]) {
    let _ = mark_memory(
        bytes.as_mut_ptr() as *const _,
        bytes.len(),
        MemState::DefinedIfAddressable,
    );
}

/// FNV-1a over the output, so the result is observably used and the
/// optimiser cannot drop the computation.
fn checksum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn keys() -> ([u8; 16], [u8; 16]) {
    (
        hex!("000102030405060708090a0b0c0d0e0f"),
        hex!("d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"),
    )
}

/// `x` with its bytes marked undefined.
fn tainted<T: Copy>(mut x: T) -> T {
    // SAFETY: `T` is plain `Copy` data; this views its bytes to mark them.
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(&mut x as *mut T as *mut u8, std::mem::size_of::<T>())
    };
    taint(bytes);
    x
}

fn bit6() -> OreAes128Bit6ChaCha20 {
    let (mut k1, mut k2) = keys();
    taint(&mut k1);
    taint(&mut k2);
    OreCipher::init(&k1, &k2).expect("init")
}

/// Full Bit6 encryption of a tainted `x` through `OreEncrypt`, which runs the
/// type's own `to_orderable_bytes` transform on the secret.
fn bit6_typed<T: Copy + OreEncrypt<OreAes128Bit6ChaCha20>>(x: T) -> Vec<u8> {
    let ore = bit6();
    let mut out = tainted(x).encrypt(&ore).expect("encrypt").to_bytes();
    untaint_output(&mut out);
    out
}

fn bit6_full() -> Vec<u8> {
    bit6_typed(0x1234_5678_9abc_def0u64)
}

fn bit6_left() -> Vec<u8> {
    let ore = bit6();
    let x = tainted(0x1234_5678_9abc_def0u64);
    let mut out = x.encrypt_left(&ore).expect("encrypt_left").to_bytes();
    untaint_output(&mut out);
    out
}

fn bit6_i64() -> Vec<u8> {
    bit6_typed(-0x1234_5678_9abc_def0i64)
}

fn bit6_f64() -> Vec<u8> {
    bit6_typed(-1234.5678f64)
}

/// `u32` is 6 blocks, a different `N` from the 64-bit types' 11.
fn bit6_u32() -> Vec<u8> {
    bit6_typed(0x89ab_cdefu32)
}

/// The 11 six-bit blocks of a u64, as a caller of the raw-block entry points
/// would pass them.
const RAW_BLOCKS: [u8; 11] = [4, 35, 5, 22, 15, 9, 43, 60, 55, 59, 48];

fn bit6_raw() -> Vec<u8> {
    let ore = bit6();
    let x = tainted(RAW_BLOCKS);
    let mut out = OreCipher::encrypt(&ore, &x).expect("encrypt").to_bytes();
    untaint_output(&mut out);
    out
}

fn bit6_raw_left() -> Vec<u8> {
    let ore = bit6();
    let x = tainted(RAW_BLOCKS);
    let mut out = OreCipher::encrypt_left(&ore, &x)
        .expect("encrypt_left")
        .to_bytes();
    untaint_output(&mut out);
    out
}

/// The plaintext string, tainted. Built with `from_utf8_unchecked` because
/// `from_utf8`'s validation branches on every byte, which would report the
/// harness rather than the encryptor; the bytes are ASCII.
fn tainted_str(buf: &mut [u8; 17]) -> &str {
    *buf = *b"alice@example.com";
    taint(buf);
    // SAFETY: the buffer was just filled with ASCII.
    unsafe { std::str::from_utf8_unchecked(buf) }
}

fn chained() -> OreAes128Bit6ChainedChaCha20 {
    let (mut k1, _) = keys();
    taint(&mut k1);
    OreAes128Bit6Chained::init(&k1).expect("init")
}

fn chained_full() -> Vec<u8> {
    let ore = chained();
    let mut buf = [0u8; 17];
    let s = tainted_str(&mut buf);
    let mut out = ore.encrypt_str(s).expect("encrypt_str").to_bytes();
    untaint_output(&mut out);
    out
}

fn chained_left() -> Vec<u8> {
    let ore = chained();
    let mut buf = [0u8; 17];
    let s = tainted_str(&mut buf);
    let mut out = ore
        .encrypt_left_str(s)
        .expect("encrypt_left_str")
        .to_bytes();
    untaint_output(&mut out);
    out
}

fn chained_raw() -> Vec<u8> {
    let ore = chained();
    let x = tainted(RAW_BLOCKS);
    let mut out = ore.encrypt_var(&x).expect("encrypt_var").to_bytes();
    untaint_output(&mut out);
    out
}

fn chained_raw_left() -> Vec<u8> {
    let ore = chained();
    let x = tainted(RAW_BLOCKS);
    let mut out = ore
        .encrypt_left_var(&x)
        .expect("encrypt_left_var")
        .to_bytes();
    untaint_output(&mut out);
    out
}

/// Positive control: branches on a tainted byte and indexes memory with it.
/// Memcheck must report both, so `scripts/ct-taint.sh` requires this mode to
/// fail. If it passes, the gate cannot see a secret-dependent branch.
fn canary() -> Vec<u8> {
    let secret = tainted(std::hint::black_box(0x5au8));
    let table = std::hint::black_box([0u8; 256]);
    let mut out = vec![table[usize::from(secret)]];
    if secret & 1 == 0 {
        out.push(std::hint::black_box(1));
    }
    untaint(&mut out);
    out
}

const MODES: &[(&str, fn() -> Vec<u8>)] = &[
    ("bit6-encrypt", bit6_full),
    ("bit6-encrypt-left", bit6_left),
    ("bit6-encrypt-i64", bit6_i64),
    ("bit6-encrypt-f64", bit6_f64),
    ("bit6-encrypt-u32", bit6_u32),
    ("bit6-encrypt-raw", bit6_raw),
    ("bit6-encrypt-left-raw", bit6_raw_left),
    ("chained-encrypt", chained_full),
    ("chained-encrypt-left", chained_left),
    ("chained-encrypt-raw", chained_raw),
    ("chained-encrypt-left-raw", chained_raw_left),
    ("canary", canary),
];

fn main() {
    let mode = env::args().nth(1).unwrap_or_default();
    let Some((name, run)) = MODES.iter().find(|(n, _)| *n == mode) else {
        eprintln!("usage: ct-taint <mode>\nmodes:");
        for (n, _) in MODES {
            eprintln!("  {n}");
        }
        exit(2);
    };
    let out = run();
    println!(
        "{name}: {} bytes, checksum {:016x}",
        out.len(),
        checksum(&out)
    );
}
