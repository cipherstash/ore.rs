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

use std::env;
use std::process::exit;

use crabgrind::memcheck::{mark_memory, MemState};
use hex_literal::hex;
use ore_rs::scheme::bit2_w6::OreAes128Bit6ChaCha20;
use ore_rs::scheme::chained::{OreAes128Bit6Chained, OreAes128Bit6ChainedChaCha20};
use ore_rs::{OreCipher, OreEncrypt, OreOutput};

/// Mark `bytes` undefined: from here on, anything computed from them is
/// tracked as tainted by memcheck.
fn taint(bytes: &mut [u8]) {
    // `Err(NoValgrind)` means the binary is not running under Valgrind; the
    // run is then a plain exercise of the path, which is still useful.
    let _ = mark_memory(bytes.as_ptr() as *const _, bytes.len(), MemState::Undefined);
}

/// Mark `bytes` defined again, so that using the *output* of an operation
/// (printing it, hashing it) is not itself reported.
fn untaint(bytes: &mut [u8]) {
    let _ = mark_memory(
        bytes.as_ptr() as *const _,
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

fn bit6_full() -> Vec<u8> {
    let (mut k1, mut k2) = keys();
    taint(&mut k1);
    taint(&mut k2);
    let ore: OreAes128Bit6ChaCha20 = OreCipher::init(&k1, &k2).expect("init");
    let mut x = 0x1234_5678_9abc_def0u64.to_le_bytes();
    taint(&mut x);
    let x = u64::from_le_bytes(x);
    let mut out = x.encrypt(&ore).expect("encrypt").to_bytes();
    untaint(&mut out);
    out
}

fn bit6_left() -> Vec<u8> {
    let (mut k1, mut k2) = keys();
    taint(&mut k1);
    taint(&mut k2);
    let ore: OreAes128Bit6ChaCha20 = OreCipher::init(&k1, &k2).expect("init");
    let mut x = 0x1234_5678_9abc_def0u64.to_le_bytes();
    taint(&mut x);
    let x = u64::from_le_bytes(x);
    let mut out = x.encrypt_left(&ore).expect("encrypt_left").to_bytes();
    untaint(&mut out);
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

fn chained_full() -> Vec<u8> {
    let (mut k1, _) = keys();
    taint(&mut k1);
    let ore: OreAes128Bit6ChainedChaCha20 = OreAes128Bit6Chained::init(&k1).expect("init");
    let mut buf = [0u8; 17];
    let s = tainted_str(&mut buf);
    let mut out = ore.encrypt_str(s).expect("encrypt_str").to_bytes();
    untaint(&mut out);
    out
}

fn chained_left() -> Vec<u8> {
    let (mut k1, _) = keys();
    taint(&mut k1);
    let ore: OreAes128Bit6ChainedChaCha20 = OreAes128Bit6Chained::init(&k1).expect("init");
    let mut buf = [0u8; 17];
    let s = tainted_str(&mut buf);
    let mut out = ore
        .encrypt_left_str(s)
        .expect("encrypt_left_str")
        .to_bytes();
    untaint(&mut out);
    out
}

const MODES: &[(&str, fn() -> Vec<u8>)] = &[
    ("bit6-encrypt", bit6_full),
    ("bit6-encrypt-left", bit6_left),
    ("chained-encrypt", chained_full),
    ("chained-encrypt-left", chained_left),
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
