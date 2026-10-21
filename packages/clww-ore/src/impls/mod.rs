use crate::Key;
use std::cmp::Ordering;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

#[cfg(any(feature = "chrono", feature = "decimal"))]
pub(crate) mod byte_array;
#[cfg(feature = "chrono")]
pub(crate) mod chrono;
#[cfg(feature = "decimal")]
pub(crate) mod decimal;
pub(crate) mod primitives;
pub(crate) mod string;
pub(crate) mod variable;

/// The scheme a keystream is drawn for. ORE and OPE each read their own
/// domain of the keyed PRF, so their terms of one value under one key and
/// salt share no keystream. If they shared one, the byte-wise difference of
/// the two terms would be `{0, 1}` where a plaintext bit is 0 and
/// `{127, 128}` where it is 1, and anyone holding both terms would read the
/// plaintext off them without the key.
#[derive(Clone, Copy)]
pub(crate) enum Scheme {
    Ore,
    Ope,
}

impl Scheme {
    /// The tag that opens the scheme's PRF input. Both tags are the same
    /// length, so neither scheme's input is a prefix of the other's.
    const fn tag(self) -> &'static [u8; 16] {
        match self {
            Scheme::Ore => b"clww-ore/ore/v1\0",
            Scheme::Ope => b"clww-ore/ope/v1\0",
        }
    }
}

/// The keyed PRF every scheme here draws from: BLAKE3 keyed with `key`, then
/// the scheme's tag, the salt's length as a big-endian `u64`, and the salt.
/// The plaintext bits follow, one byte each. The length prefix keeps salts
/// apart: without it the input for salt `s` after a 1 bit would be the input
/// for salt `s ‖ 0x01`. No salt and an empty salt are the same domain.
///
/// Wiped on drop, so the key words and chaining values do not outlive the
/// call.
pub(crate) fn keyed_hasher(
    key: &Key,
    scheme: Scheme,
    salt: Option<&[u8]>,
) -> Zeroizing<blake3::Hasher> {
    let salt = salt.unwrap_or_default();
    let mut hasher = Zeroizing::new(blake3::Hasher::new_keyed(&key.0));
    let _ = hasher.update(scheme.tag());
    let _ = hasher.update(&(salt.len() as u64).to_be_bytes());
    let _ = hasher.update(salt);
    hasher
}

/// The next keystream byte: the last of the first 16 bytes the hasher
/// outputs. The output block and its reader are wiped before they are freed.
pub(crate) fn prf_byte(hasher: &blake3::Hasher) -> u8 {
    let mut buf = Zeroizing::new([0u8; 16]);
    let mut reader = Zeroizing::new(hasher.finalize_xof());
    reader.fill(&mut buf[..]);
    buf[15]
}

/// Encrypts a bit stream into an OPE ciphertext whose lex order matches the
/// plaintext order exactly.
///
/// The output is `n + 1` bytes, for the `n` bits `bits` yields: a reserved
/// leading byte absorbs any carry
/// that propagates past the MSB, followed by one byte per plaintext bit
/// (MSB-first).
///
/// Encryption computes the CLWW keystream `PRF_0 … PRF_{n-1}` and then forms
/// `C = P + 128·B` as a big-endian `(n+1)`-byte integer, where `P` is the PRF
/// stream and `B` is the plaintext bits laid out one-per-byte. The `·128`
/// places the plaintext's single-bit contribution at the top bit of its
/// byte, giving the signal a 128× edge over the maximum backward-carry
/// noise (±1 per byte). This makes lex comparison of the ciphertext
/// **exact** — it always agrees with the true plaintext order.
///
/// Without the backward carry we'd lose the wrap on `PRF_i + 128 ≥ 256`
/// (≈ half of PRF values); the carry propagates that `+1` one byte
/// leftward where the signal re-emerges at the next shared-PRF byte and
/// lex compare resolves cleanly.
///
/// `bits` is an iterator of one byte per plaintext bit, each `0` or `1`. The
/// MSB-first byte form of an integer or string is just one convenient producer
/// — callers may freely pack their own tagged bit streams.
pub fn encrypt_ope_bits<I>(bits: I, key: &Key, salt: Option<&[u8]>) -> Vec<u8>
where
    I: IntoIterator<Item = u8>,
{
    let bits = bits.into_iter();
    let n = bits.size_hint().0;
    let mut hasher = keyed_hasher(key, Scheme::Ope, salt);

    let mut out: Vec<u8> = Vec::with_capacity(n + 1);
    out.push(0);
    // One byte per plaintext bit, kept for the carry pass: wiped on drop.
    let mut plain_bits: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(n));
    for bit in bits {
        out.push(prf_byte(&hasher));
        plain_bits.push(bit);
        let _ = hasher.update(&[bit]);
    }

    // Each sum is at most 255 + 128 + 1, so the carry out of it is 0 or 1.
    let mut carry: u16 = 0;
    for (byte, &bit) in out[1..].iter_mut().rev().zip(plain_bits.iter().rev()) {
        // Place the plaintext bit at the MSB of the byte (weight 128) so the
        // signal dominates any carry-propagated noise at this position.
        let sum = *byte as u16 + ((bit as u16) << 7) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
    out[0] = carry as u8;

    out
}

/// Compare two CLWW ORE ciphertexts in constant time, given as their
/// bytes paired position by position: the first differing pair decides.
fn compare_pairs<'a>(pairs: impl Iterator<Item = (&'a u8, &'a u8)>) -> Ordering {
    // Track the first differing pair in a constant-time manner
    let mut diff_x: u8 = 0;
    let mut diff_y: u8 = 0;
    let mut found_diff = Choice::from(0u8);

    for (x, y) in pairs {
        let is_diff = !x.ct_eq(y);
        let not_found_yet = !found_diff;
        let should_record = is_diff & not_found_yet;

        // Conditionally assign using constant-time selection
        diff_x = u8::conditional_select(&diff_x, x, should_record);
        diff_y = u8::conditional_select(&diff_y, y, should_record);
        found_diff = Choice::conditional_select(&found_diff, &is_diff, should_record);
    }

    // Perform comparison in constant time
    let is_greater = diff_y.wrapping_add(1).ct_eq(&diff_x);
    let is_equal = !found_diff;

    // Convert to Ordering - this final step is not constant-time, but the
    // secret data has already been processed in constant time
    if bool::from(is_equal) {
        Ordering::Equal
    } else if bool::from(is_greater) {
        Ordering::Greater
    } else {
        Ordering::Less
    }
}
