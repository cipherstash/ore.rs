use biterator::{string_biter, Biterator};
use std::cmp::Ordering;
mod biterator;
mod nibble_iterator;

pub struct Key([u8; 32]);

impl Key {
    pub fn encrypt<T>(&self, input: T) -> Output<u8>
    where
        T: CllwOreEncrypt,
    {
        input.encrypt(&self)
    }
}

impl From<[u8; 32]> for Key {
    fn from(key: [u8; 32]) -> Self {
        Self(key)
    }
}

pub trait CllwOreEncrypt: Sized {
    fn encrypt(self, key: &Key) -> Output<u8> {
        self.encrypt_with_salt(key, None)
    }

    fn encrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Output<u8>;
}

pub struct Output<Elem> {
    bytes: Vec<u8>,
    _elem: std::marker::PhantomData<Elem>,
}

impl Output<u8> {
    fn new(num_elements: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(num_elements),
            _elem: std::marker::PhantomData,
        }
    }

    fn push_into(mut self, elem: u8) -> Self {
        self.bytes.push(elem);
        self
    }
}

impl AsRef<[u8]> for &Output<u8> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl CllwOreEncrypt for u32 {
    fn encrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Output<u8> {
        let mut hasher = blake3::Hasher::new_keyed(&key.0);
        if let Some(salt) = salt {
            hasher.update(salt);
        }
        Biterator::new(self).fold(Output::new(u32::BITS as usize), |out, bit| {
            let mut buf: [u8; 16] = [0; 16];
            hasher.finalize_xof().fill(&mut buf);
            let byte = u128::from_be_bytes(buf).wrapping_add(bit as u128) & 0xFF;
            hasher.update(&[bit]);
            out.push_into(byte as u8)
        })
    }
}

impl CllwOreEncrypt for u64 {
    fn encrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Output<u8> {
        let mut hasher = blake3::Hasher::new_keyed(&key.0);
        if let Some(salt) = salt {
            hasher.update(salt);
        }
        Biterator::new(self).fold(Output::new(Self::BITS as usize), |out, bit| {
            let mut buf: [u8; 16] = [0; 16];
            hasher.finalize_xof().fill(&mut buf);
            let byte = u128::from_be_bytes(buf).wrapping_add(bit as u128) & 0xFF;
            hasher.update(&[bit]);
            out.push_into(byte as u8)
        })
    }
}

impl CllwOreEncrypt for &str {
    fn encrypt_with_salt(self, key: &Key, salt: Option<&[u8]>) -> Output<u8> {
        let len = self.as_bytes().len() * u8::BITS as usize;
        let mut hasher = blake3::Hasher::new_keyed(&key.0);
        if let Some(salt) = salt {
            hasher.update(salt);
        }
        string_biter(self).fold(Output::new(len), |out, bit| {
            let mut buf: [u8; 16] = [0; 16];
            hasher.finalize_xof().fill(&mut buf);
            let byte = u128::from_be_bytes(buf).wrapping_add(bit as u128) & 0xFF;
            hasher.update(&[bit]);
            out.push_into(byte as u8)
        })
    }
}

pub fn compare(a: &Output<u8>, b: &Output<u8>) -> Ordering {
    // TODO: Add some compile time checks to ensure that the two outputs are the same length
    // Only do the length check if we are comparing integers
    //assert_eq!(a.as_ref().len(), b.as_ref().len(), "Outputs must be the same length");

    let mut differing: Option<(u8, u8)> = None;
    for (x, y) in a.as_ref().iter().zip(b.as_ref().iter()) {
        differing = differing.or_else(|| if x != y { Some((*x, *y)) } else { None });
    }

    if let Some((x, y)) = differing {
        if y.wrapping_add(1) == x {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    } else {
        Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paste::paste;
    use quickcheck::{quickcheck, Arbitrary, Gen, TestResult};
    use std::{
        array,
        fmt::{self, Debug, Formatter},
    };

    impl Clone for Key {
        fn clone(&self) -> Self {
            Key(self.0)
        }
    }

    impl Arbitrary for Key {
        fn arbitrary(g: &mut Gen) -> Self {
            Self(array::from_fn(|_| u8::arbitrary(g)))
        }
    }

    impl Debug for Key {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }

    macro_rules! quickcheck_type {
        ($ty:ident) => {
            paste! {
                quickcheck! {
                    fn [<prop_eq_ $ty>](key: Key, x: $ty) -> bool {
                        let a = key.encrypt(x);
                        let b = key.encrypt(x);

                        compare(&a, &b) == Ordering::Equal
                    }


                    fn [<prop_cmp_ $ty>](key: Key, x: $ty, y: $ty) -> bool {
                        let a = key.encrypt(x);
                        let b = key.encrypt(y);

                        compare(&a, &b) == x.cmp(&y)
                    }

                    fn [<prop_low_order_bit_greater_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt(1 as $ty);
                        let x2 = key.encrypt(0 as $ty);
                        compare(&x1, &x2) == Ordering::Greater
                    }

                    fn [<prop_high_order_bit_greater_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt::<$ty>(1 << ($ty::BITS - 1));
                        let x2 = key.encrypt::<$ty>(0);
                        compare(&x1, &x2) == Ordering::Greater
                    }

                    fn [<prop_high_order_bit_less_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt::<$ty>(0);
                        let x2 = key.encrypt::<$ty>(1 << ($ty::BITS - 1));
                        compare(&x1, &x2) == Ordering::Less
                    }

                    fn [<prop_high_order_bit_eq_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt::<$ty>(1 << ($ty::BITS - 1));
                        let x2 = key.encrypt::<$ty>(1 << ($ty::BITS - 1));
                        compare(&x1, &x2) == Ordering::Equal
                    }

                    fn [<prop_low_order_bit_less_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt::<$ty>(0);
                        let x2 = key.encrypt::<$ty>(1);
                        compare(&x1, &x2) == Ordering::Less
                    }

                    fn [<prop_low_order_bit_eq_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt::<$ty>(1);
                        let x2 = key.encrypt::<$ty>(1);
                        compare(&x1, &x2) == Ordering::Equal
                    }

                    fn [<prop_zero_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt::<$ty>(0);
                        let x2 = key.encrypt::<$ty>(0);
                        compare(&x1, &x2) == Ordering::Equal
                    }

                    fn [<prop_max_ $ty>](key: Key) -> bool {
                        let x1 = key.encrypt($ty::MAX);
                        let x2 = key.encrypt($ty::MAX);
                        compare(&x1, &x2) == Ordering::Equal
                    }

                    fn [<prop_less_than_max_right_ $ty>](key: Key, x: $ty) -> TestResult {
                        if x == $ty::MAX {
                            return TestResult::discard();
                        }
                        let x1 = key.encrypt(x);
                        let x2 = key.encrypt($ty::MAX);
                        TestResult::from_bool(compare(&x1, &x2) == Ordering::Less)
                    }

                    fn [<prop_more_than_max_left_ $ty>](key: Key, x: $ty) -> TestResult {
                        if x == $ty::MAX {
                            return TestResult::discard();
                        }
                        let x1 = key.encrypt($ty::MAX);
                        let x2 = key.encrypt::<$ty>(0);
                        TestResult::from_bool(compare(&x1, &x2) == Ordering::Greater)
                    }

                    fn [<prop_more_than_zero_left_ $ty>](key: Key, x: $ty) -> TestResult {
                        if x == 0 {
                            return TestResult::discard();
                        }
                        let x1 = key.encrypt::<$ty>(0);
                        let x2 = key.encrypt(x);
                        TestResult::from_bool(compare(&x1, &x2) == Ordering::Less)
                    }

                    fn [<prop_more_than_zero_right_ $ty>](key: Key, x: $ty) -> TestResult {
                        if x == 0 {
                            return TestResult::discard();
                        }
                        let x1 = key.encrypt(x);
                        let x2 = key.encrypt::<$ty>(0);
                        TestResult::from_bool(compare(&x1, &x2) == Ordering::Greater)
                    }

                    fn [<prop_one_less_than_ $ty>](key: Key, x: $ty) -> TestResult {
                        if x <= 1 {
                            return TestResult::discard();
                        }
                        let x1 = key.encrypt(x - 1);
                        let x2 = key.encrypt(x);
                        TestResult::from_bool(compare(&x1, &x2) == Ordering::Less)
                    }
                }
            }
        };
    }

    #[test]
    fn test_string() {
        let key = Key::from([0; 32]);
        let input = "hello";
        let a = key.encrypt(input);
        let b = key.encrypt(input);
        assert_eq!(compare(&a, &b), Ordering::Equal);
    }

    #[test]
    fn test_string_cmp_less() {
        let key = Key::from([0; 32]);
        let a = key.encrypt("cat");
        let b = key.encrypt("dog");
        assert_eq!(compare(&a, &b), Ordering::Less);
    }

    #[test]
    fn test_string_cmp_prefix() {
        let key = Key::from([0; 32]);
        let a = key.encrypt("cat");
        let b = key.encrypt("catskills");
        assert_eq!(compare(&a, &b), Ordering::Greater);
    }

    quickcheck_type!(u32);
    quickcheck_type!(u64);
}
