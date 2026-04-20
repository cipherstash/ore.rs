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
/// The CLLW ORE encryption computes `c_i = (PRF_i + bit_i) mod 256` per bit.
/// When `PRF_i = 0xFF` and `bit_i = 1`, the byte wraps to `0x00`, making lex
/// comparison disagree with the true order. Here we do the wrap but propagate
/// the carry **right-to-left** (toward more-significant lex positions),
/// reserving a leading byte so the carry never falls off the front. This
/// eliminates the ~1/256 ordering error at the cost of one extra byte.
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
        let sum = *byte as u16 + bit as u16 + carry;
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
