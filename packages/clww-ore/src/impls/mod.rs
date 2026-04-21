use crate::Key;
use std::cmp::Ordering;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

pub(crate) mod num;
pub(crate) mod string;

/// Encrypts a bit stream into an OPE ciphertext whose lex order matches the
/// plaintext order exactly.
///
/// The output is `n + 1` bytes: a reserved leading byte absorbs any carry
/// that propagates past the MSB, followed by one byte per plaintext bit
/// (MSB-first).
///
/// Encryption computes the CLLW keystream `PRF_0 … PRF_{n-1}` and then forms
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
/// `n` is the number of plaintext bits, which must equal the number of items
/// yielded by `bits` (debug-checked).
pub(super) fn encrypt_ope_bits<I>(bits: I, n: usize, key: &Key, salt: Option<&[u8]>) -> Vec<u8>
where
    I: IntoIterator<Item = u8>,
{
    let mut hasher = blake3::Hasher::new_keyed(&key.0);
    if let Some(salt) = salt {
        let _ = hasher.update(salt);
    }

    let mut out: Vec<u8> = Vec::with_capacity(n + 1);
    out.push(0);
    let mut plain_bits: Vec<u8> = Vec::with_capacity(n);
    for bit in bits {
        let mut buf: [u8; 16] = [0; 16];
        hasher.finalize_xof().fill(&mut buf);
        let prf = (u128::from_be_bytes(buf) & 0xFF) as u8;
        out.push(prf);
        plain_bits.push(bit);
        let _ = hasher.update(&[bit]);
    }
    debug_assert_eq!(plain_bits.len(), n);

    let mut carry: u16 = 0;
    for (byte, &bit) in out[1..].iter_mut().rev().zip(plain_bits.iter().rev()) {
        // Place the plaintext bit at the MSB of the byte (weight 128) so the
        // signal dominates any carry-propagated noise at this position.
        let sum = *byte as u16 + ((bit as u16) << 7) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
    debug_assert!(carry <= 1);
    out[0] = carry as u8;

    out
}

/// Compare 2 CLLW ORE encrypted slices of the same length in constant time
fn compare_slice(a: &[u8], b: &[u8]) -> Ordering {
    assert_eq!(a.len(), b.len());

    // Track the first differing pair in a constant-time manner
    let mut diff_x: u8 = 0;
    let mut diff_y: u8 = 0;
    let mut found_diff = Choice::from(0u8);

    for (x, y) in a.iter().zip(b.iter()) {
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
