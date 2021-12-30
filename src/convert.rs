/*
  This following function implement an order-preserving translation of 64 bit
  floats to 64 bit doubles (and the reverse operation - although that is just
  used for verifying correctness).

  The 64 bit integer that is produced is a plaintext that will be ORE encrypted
  later on.

  The mapping is such that the ordering of the floats will be preserved when
  mapped to an unsigned integer, for example, an array of unsigned integers
  dervived from a sorted array of doubles will result in no change to its
  ordering when it itself is sorted.

  The mapping does not preserve any notion of the previous value after the
  conversion - only ordering is preserved.

  Caveat: NaN and -ve & +ve infinity will also be mapped and ordering is not
  well-defined with those values. Those values should be discarded before
  converting arrays of those values.

  This post was used as a reference for building this implementation:
  https://lemire.me/blog/2020/12/14/converting-floating-point-numbers-to-integers-while-preserving-order
*/

use core::mem;

pub(crate) trait ToOrderedInteger<T> {
    fn map_to(&self) -> T;
}

trait FromOrderedInteger<T> {
    fn map_from(input: T) -> Self;
}

impl ToOrderedInteger<u64> for f64 {
    fn map_to(&self) -> u64 {
        let num: u64 = self.to_bits();
        let signed: i64 = -(unsafe { mem::transmute(num >> 63) });
        let mut mask: u64 = unsafe { mem::transmute(signed) };
        mask |= 0x8000000000000000;
        num ^ mask
    }
}

impl FromOrderedInteger<u64> for f64 {
    fn map_from(input: u64) -> f64 {
        let i = (((input >> 63) as i64) - 1) as u64;
        let mask: u64 = i | 0x8000000000000000;
        f64::from_bits(input ^ mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::TestResult;

    quickcheck! {
        fn roundtrip(x: f64) -> TestResult {
            if !x.is_nan() && x.is_finite() {
                TestResult::from_bool(x == f64::map_from(x.map_to()))
            } else {
                TestResult::discard()
            }
        }
    }
}
