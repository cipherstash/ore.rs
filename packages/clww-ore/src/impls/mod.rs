use crate::{Error, Key};
use std::cmp::Ordering;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

pub(crate) mod variable;

use variable::{OpeClww8VariableV1, OreClww8VariableV1};

/// The bits of `bytes`, one byte each, most significant first.
fn bits_of(bytes: &[u8]) -> impl Iterator<Item = u8> + '_ {
    bytes
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1))
}

/// The ORE term of `bytes`: one ciphertext byte per plaintext bit. The
/// entry point both vitaminc schemes encrypt their sealed bytes through.
pub(crate) fn encrypt_ore_bytes(
    bytes: &[u8],
    key: &Key,
    salt: Option<&[u8]>,
) -> Result<OreClww8VariableV1, Error> {
    encrypt_ore_bits(bits_of(bytes), key, salt).map(OreClww8VariableV1::from_bytes_unchecked)
}

/// The OPE term of `bytes`: a carry byte, then one byte per plaintext bit.
pub(crate) fn encrypt_ope_bytes(
    bytes: &[u8],
    key: &Key,
    salt: Option<&[u8]>,
) -> Result<OpeClww8VariableV1, Error> {
    encrypt_ope_bits(bits_of(bytes), key, salt).map(OpeClww8VariableV1::from_bytes_unchecked)
}

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
/// `bits` is an iterator of one byte per plaintext bit, each `0` or `1`.
///
/// # Errors
///
/// [`Error`](struct@crate::Error) if any byte of `bits` is not `0` or `1`. Such a byte would carry
/// more than one into the byte above it, and the terms would no longer sort as
/// their plaintexts. The whole stream is read first, so the error does not
/// tell where the bad byte was.
pub(crate) fn encrypt_ope_bits<I>(bits: I, key: &Key, salt: Option<&[u8]>) -> Result<Vec<u8>, Error>
where
    I: IntoIterator<Item = u8>,
{
    let mut hasher = keyed_hasher(key, Scheme::Ope, salt);

    // Both buffers hold secrets until the carry pass: `out` the bare
    // keystream, `plain_bits` one byte per plaintext bit. Each is wiped on
    // drop, and grows through `push_secret`, so no buffer it outgrows is
    // freed with its contents.
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut plain_bits: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut invalid = 0u8;
    push_secret(&mut out, 0);
    for bit in bits {
        invalid |= bit >> 1;
        push_secret(&mut out, prf_byte(&hasher));
        push_secret(&mut plain_bits, bit);
        let _ = hasher.update(&[bit]);
    }
    if invalid != 0 {
        return Err(Error);
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

    // The carry pass is done, so `out` is the ciphertext: hand over its
    // buffer, not a copy.
    Ok(std::mem::take(&mut *out))
}

/// Push `byte` onto a buffer of secrets. When the buffer is full it moves to
/// one twice the size, and the old one is wiped as it drops; `Vec::push`
/// would free it as it is.
pub(crate) fn push_secret(buf: &mut Zeroizing<Vec<u8>>, byte: u8) {
    if buf.len() == buf.capacity() {
        let mut grown = Zeroizing::new(Vec::with_capacity((buf.capacity() * 2).max(64)));
        grown.extend_from_slice(buf);
        *buf = grown;
    }
    buf.push(byte);
}

/// Encrypts a bit stream into a CLWW ORE ciphertext.
///
/// `bits` is an iterator of one byte per plaintext bit, each `0` or `1`. Each
/// ciphertext byte is `(PRF_i + bit_i) mod 256`, one byte per bit, and the
/// bytes compare under the ORE comparison (first differing byte, `y + 1 ==
/// x`), **not** plain lex order. See [`OreClww8VariableV1`].
///
/// # Errors
///
/// [`Error`](struct@crate::Error) if any byte of `bits` is not `0` or `1`: the comparison reads a
/// difference of exactly one as the order, so any other byte gives terms that
/// sort wrong. The whole stream is read first, so the error does not tell
/// where the bad byte was.
pub(crate) fn encrypt_ore_bits<I>(bits: I, key: &Key, salt: Option<&[u8]>) -> Result<Vec<u8>, Error>
where
    I: IntoIterator<Item = u8>,
{
    let mut hasher = keyed_hasher(key, Scheme::Ore, salt);
    let mut invalid = 0u8;
    let out = bits.into_iter().fold(Vec::new(), |mut out, bit| {
        invalid |= bit >> 1;
        out.push(prf_byte(&hasher).wrapping_add(bit));
        let _ = hasher.update(&[bit]);
        out
    });
    if invalid != 0 {
        return Err(Error);
    }
    Ok(out)
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
