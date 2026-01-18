pub struct Biterator<T> {
    input: T,
    count: u32,
}

impl<T> Biterator<T> {
    pub fn new(input: T) -> Self
    where
        T: BitSize,
    {
        Self {
            count: input.msb(),
            input,
        }
    }
}

pub trait BitSize {
    fn msb(&self) -> u32;
}

impl BitSize for u8 {
    fn msb(&self) -> u32 {
        Self::BITS - 1
    }
}

impl BitSize for u16 {
    fn msb(&self) -> u32 {
        Self::BITS - 1
    }
}

impl BitSize for u32 {
    fn msb(&self) -> u32 {
        Self::BITS - 1
    }
}

impl BitSize for u64 {
    fn msb(&self) -> u32 {
        Self::BITS - 1
    }
}

impl BitSize for u128 {
    fn msb(&self) -> u32 {
        Self::BITS - 1
    }
}

impl Iterator for Biterator<u16> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count ^ u32::MAX == 0 {
            return None;
        }
        let bit = (self.input & (1 << self.count)) >> self.count;
        self.count = self.count.wrapping_sub(1);
        Some(bit as u8)
    }
}

impl Iterator for Biterator<u32> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count ^ u32::MAX == 0 {
            return None;
        }
        let bit = (self.input & (1 << self.count)) >> self.count;
        self.count = self.count.wrapping_sub(1);
        Some(bit as u8)
    }
}

impl Iterator for Biterator<u64> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count ^ u32::MAX == 0 {
            return None;
        }
        let bit = (self.input & (1 << self.count)) >> self.count;
        self.count = self.count.wrapping_sub(1);
        Some(bit as u8)
    }
}

impl Iterator for Biterator<u128> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count ^ u32::MAX == 0 {
            return None;
        }
        let bit = (self.input & (1 << self.count)) >> self.count;
        self.count = self.count.wrapping_sub(1);
        Some(bit as u8)
    }
}

impl Iterator for Biterator<u8> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count ^ u32::MAX == 0 {
            return None;
        }
        let bit = (self.input & (1 << self.count)) >> self.count;
        self.count = self.count.wrapping_sub(1);
        Some(bit)
    }
}

pub struct StringBiterator<I>
where
    I: Iterator<Item = u8>,
{
    iter: I,
}

pub fn string_biter(input: &str) -> StringBiterator<impl Iterator<Item = u8> + '_> {
    let iter = input
        .as_bytes()
        .iter()
        .flat_map(|byte| Biterator::new(*byte));

    StringBiterator { iter }
}

impl<I> Iterator for StringBiterator<I>
where
    I: Iterator<Item = u8>,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

pub struct VecBiterator<I>
where
    I: Iterator<Item = u8>,
{
    iter: I,
}

#[allow(dead_code)]
pub fn vec_biter(input: Vec<u8>) -> VecBiterator<impl Iterator<Item = u8>> {
    let iter = input.into_iter().flat_map(Biterator::new);

    VecBiterator { iter }
}

impl<I> Iterator for VecBiterator<I>
where
    I: Iterator<Item = u8>,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use quickcheck::quickcheck;

    quickcheck! {
        fn test_biterator_size_u8(input: u8) -> bool {
            let biter = Biterator::new(input);
            biter.count() == u8::BITS as usize
        }

        fn test_biterator_size_u32(input: u32) -> bool {
            let biter = Biterator::new(input);
            biter.count() == u32::BITS as usize
        }

        fn test_biterator_size_u64(input: u64) -> bool {
            let biter = Biterator::new(input);
            biter.count() == u64::BITS as usize
        }
    }

    #[test]
    fn test_biterator_u8() {
        let input: u8 = 0b1010_0101;
        let mut biter = Biterator::new(input);
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));

        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));

        assert_eq!(biter.next(), None);
    }

    #[test]
    fn test_biterator_u32() {
        let input: u32 = 0b1010_1010_1010_1010_1010_1010_1010_1010;
        let mut biter = Biterator::new(input);
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));

        assert_eq!(biter.next(), None);
    }

    #[test]
    fn test_biterator_u64() {
        let input: u64 =
            0b1010_1111_1010_1111_1010_1111_1010_1111_1010_1111_1010_1111_1010_1111_1010_1111;
        let mut biter = Biterator::new(input);
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));

        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));

        assert_eq!(biter.next(), None);
    }

    #[test]
    fn test_string_biterator() {
        let input = "hello";
        let mut biter = string_biter(input);
        // h
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(0));
        // e
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        // l
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(0));
        // l
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(0));
        // o
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));

        assert_eq!(biter.next(), None);
    }

    #[test]
    fn test_vec_biterator() {
        let input: Vec<u8> = vec![0b0110_1000, 0b0110_0101];
        let mut biter = vec_biter(input);

        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(0));

        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));
        assert_eq!(biter.next(), Some(0));
        assert_eq!(biter.next(), Some(1));

        assert_eq!(biter.next(), None);
    }
}
