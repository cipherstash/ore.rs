//! The keystreams of different schemes and different salts are independent.
//!
//! Up to 0.5 the ORE and OPE terms of one value under one key and salt were
//! drawn from one keystream, and the salt went into the PRF raw, just ahead of
//! the plaintext bits. Two attacks followed, and each is run here twice:
//! against that construction, rebuilt below, where it must succeed, and
//! against this crate, where it must fail. The first run keeps the second from
//! passing because the attack itself is broken.
//!
//! 1. Holding the ORE and OPE terms of one value, subtract them byte by byte.
//!    The difference is 0 or 1 where the plaintext bit is 0 and 127 or 128
//!    where it is 1, so every bit can be read off without the key.
//! 2. The keystream for salt `s` after a first bit `b` is the keystream for
//!    salt `s ‖ b` from the start, so terms under the two salts are linked.

use crate::{encrypt_ope_bits, encrypt_ore_bits, ClwwOpeEncrypt, ClwwOreEncrypt, Key};

const KEY: [u8; 32] = [0x5a; 32];
const SALT: &[u8] = b"clww-ore/keystream-separation";

fn key() -> Key {
    Key::from(KEY)
}

/// The construction up to 0.5: BLAKE3 keyed with the key, the salt absorbed
/// as it is, one keystream for both schemes.
mod unseparated {
    use super::KEY;

    fn hasher(salt: &[u8]) -> blake3::Hasher {
        let mut hasher = blake3::Hasher::new_keyed(&KEY);
        hasher.update(salt);
        hasher
    }

    fn prf_byte(hasher: &blake3::Hasher) -> u8 {
        let mut buf = [0u8; 16];
        hasher.finalize_xof().fill(&mut buf);
        buf[15]
    }

    pub(super) fn ore(bits: &[u8], salt: &[u8]) -> Vec<u8> {
        let mut hasher = hasher(salt);
        bits.iter()
            .map(|&bit| {
                let byte = prf_byte(&hasher).wrapping_add(bit);
                hasher.update(&[bit]);
                byte
            })
            .collect()
    }

    pub(super) fn ope(bits: &[u8], salt: &[u8]) -> Vec<u8> {
        let mut hasher = hasher(salt);
        let mut out = vec![0];
        for &bit in bits {
            out.push(prf_byte(&hasher));
            hasher.update(&[bit]);
        }
        let mut carry = 0u16;
        for (byte, &bit) in out[1..].iter_mut().rev().zip(bits.iter().rev()) {
            let sum = *byte as u16 + ((bit as u16) << 7) + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
        out[0] = carry as u8;
        out
    }
}

/// Attack 1: the plaintext bits read off an ORE term and an OPE term of one
/// value, assuming they share a keystream. `ope` has its leading carry byte.
fn read_bits(ore: &[u8], ope: &[u8]) -> Vec<u8> {
    ore.iter()
        .zip(&ope[1..])
        .map(|(&o, &p)| u8::from(p.wrapping_sub(o) >= 64))
        .collect()
}

/// The share of `read` that matches `bits`.
fn hit_rate(read: &[u8], bits: &[u8]) -> f64 {
    let hits = read.iter().zip(bits).filter(|(r, b)| r == b).count();
    hits as f64 / bits.len() as f64
}

/// Sixty-four pseudorandom `u64`s (SplitMix64 from a fixed seed), so the
/// sample is the same on every run.
fn values() -> Vec<u64> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    (0..64)
        .map(|_| {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        })
        .collect()
}

fn bits_of(value: u64) -> Vec<u8> {
    (0..64).rev().map(|i| ((value >> i) & 1) as u8).collect()
}

/// Every bit of every value, and the bits attack 1 reads off the terms
/// `encrypt` gives for it.
fn attack_1(encrypt: impl Fn(u64) -> (Vec<u8>, Vec<u8>)) -> (Vec<u8>, Vec<u8>) {
    let (mut bits, mut read) = (Vec::new(), Vec::new());
    for value in values() {
        let (ore, ope) = encrypt(value);
        bits.extend(bits_of(value));
        read.extend(read_bits(&ore, &ope));
    }
    (bits, read)
}

/// Whether attack 1 did no better than a coin toss: within five points of
/// half over 4,096 bits, where a sound keystream lands within about two. The
/// share read is returned for the failure message.
fn coin_toss(bits: &[u8], read: &[u8]) -> (bool, f64) {
    let rate = hit_rate(read, bits);
    (
        read.len() == bits.len() && (0.45..=0.55).contains(&rate),
        rate,
    )
}

#[test]
fn attack_1_reads_every_bit_of_the_unseparated_construction() {
    for salt in [&[][..], SALT] {
        let (bits, read) = attack_1(|v| {
            let bits = bits_of(v);
            (unseparated::ore(&bits, salt), unseparated::ope(&bits, salt))
        });
        assert_eq!(read, bits);
    }
}

#[test]
fn attack_1_fails_on_bit_streams() {
    let key = key();
    for salt in [None, Some(SALT)] {
        let (bits, read) = attack_1(|v| {
            (
                encrypt_ore_bits(bits_of(v), &key, salt),
                encrypt_ope_bits(bits_of(v), &key, salt),
            )
        });
        let (fair, rate) = coin_toss(&bits, &read);
        assert!(
            fair,
            "bit streams: attack 1 read {:.1}% of the bits",
            rate * 100.0
        );
    }
}

#[test]
fn attack_1_fails_on_integers() {
    let key = key();
    for salt in [None, Some(SALT)] {
        let (bits, read) = attack_1(|v| {
            (
                v.encrypt_with_salt(&key, salt).unwrap().as_ref().to_vec(),
                v.encrypt_ope_with_salt(&key, salt)
                    .unwrap()
                    .as_ref()
                    .to_vec(),
            )
        });
        let (fair, rate) = coin_toss(&bits, &read);
        assert!(fair, "u64: attack 1 read {:.1}% of the bits", rate * 100.0);
    }
}

#[test]
fn attack_1_fails_on_bytes() {
    let key = key();
    for salt in [None, Some(SALT)] {
        let (bits, read) = attack_1(|v| {
            let bytes = v.to_be_bytes();
            let bytes = bytes.as_slice();
            (
                bytes
                    .encrypt_with_salt(&key, salt)
                    .unwrap()
                    .as_ref()
                    .to_vec(),
                bytes
                    .encrypt_ope_with_salt(&key, salt)
                    .unwrap()
                    .as_ref()
                    .to_vec(),
            )
        });
        let (fair, rate) = coin_toss(&bits, &read);
        assert!(
            fair,
            "&[u8]: attack 1 read {:.1}% of the bits",
            rate * 100.0
        );
    }
}

/// A salt and a bit to append to it, and a plaintext that starts with that
/// bit: under the unseparated construction, the term of `bits` under `salt`
/// runs on from the first byte as the term of `bits[1..]` under `salt ‖ bit`.
const SHIFTS: [(&[u8], u8); 4] = [(b"", 0), (b"", 1), (b"tenant-1", 0), (b"tenant-1", 1)];

fn shifted(bit: u8) -> Vec<u8> {
    let mut bits = vec![bit];
    bits.extend(bits_of(0x0123_4567_89ab_cdef));
    bits
}

/// `bit` then sixty-four zero bits. A zero bit adds nothing to its OPE byte
/// and no carry, so past the first byte the OPE term is the bare keystream.
fn then_zeros(bit: u8) -> Vec<u8> {
    let mut bits = vec![bit];
    bits.extend([0; 64]);
    bits
}

fn appended(salt: &[u8], bit: u8) -> Vec<u8> {
    let mut salt = salt.to_vec();
    salt.push(bit);
    salt
}

#[test]
fn attack_2_links_salts_in_the_unseparated_construction() {
    for (salt, bit) in SHIFTS {
        let bits = shifted(bit);
        let longer = appended(salt, bit);
        assert_eq!(
            unseparated::ore(&bits, salt)[1..],
            unseparated::ore(&bits[1..], &longer)[..]
        );
        let zeros = then_zeros(bit);
        assert_eq!(
            unseparated::ope(&zeros, salt)[2..],
            unseparated::ope(&zeros[1..], &longer)[1..]
        );
    }
}

#[test]
fn attack_2_fails() {
    let key = key();
    for (salt, bit) in SHIFTS {
        let bits = shifted(bit);
        let longer = appended(salt, bit);
        let ore = encrypt_ore_bits(bits.iter().copied(), &key, Some(salt));
        let ore_longer = encrypt_ore_bits(bits[1..].iter().copied(), &key, Some(&longer));
        assert_ne!(ore[1..], ore_longer[..], "ORE, salt {salt:?} then {bit}");
        let zeros = then_zeros(bit);
        let ope = encrypt_ope_bits(zeros.iter().copied(), &key, Some(salt));
        let ope_longer = encrypt_ope_bits(zeros[1..].iter().copied(), &key, Some(&longer));
        assert_ne!(ope[2..], ope_longer[1..], "OPE, salt {salt:?} then {bit}");
    }
}

#[test]
fn no_salt_and_an_empty_salt_are_one_domain() {
    let key = key();
    let bits = bits_of(42);
    assert_eq!(
        encrypt_ore_bits(bits.iter().copied(), &key, None),
        encrypt_ore_bits(bits.iter().copied(), &key, Some(&[]))
    );
    assert_eq!(
        encrypt_ope_bits(bits.iter().copied(), &key, None),
        encrypt_ope_bits(bits.iter().copied(), &key, Some(&[]))
    );
}
