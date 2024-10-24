#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Nibble(u8);

impl Nibble {
    #[allow(dead_code)]
    pub fn one_more_than(&self, other: Self) -> bool {
        self.wrapping_add(&Self(1)) == other
    }

    #[allow(dead_code)]
    pub fn wrapping_add(&self, other: &Self) -> Self {
        Self((self.0 + other.0) & 0xF)
    }
}

pub struct NibbleIterator<'s> {
    slice_iter: std::slice::Iter<'s, u8>,
    curr: Option<u8>,
}

impl<'s> NibbleIterator<'s> {
    #[allow(dead_code)]
    pub fn new(slice: &'s [u8]) -> Self {
        Self {
            slice_iter: slice.iter(),
            curr: None,
        }
    }
}

impl<'s> Iterator for NibbleIterator<'s> {
    type Item = Nibble;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(byte) = self.curr.take() {
            Some(Nibble(byte & 0x0F))
        } else {
            self.slice_iter.next().map(|byte| {
                self.curr = Some(*byte);
                Nibble((byte & 0xF0) >> 4)
            })
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_nibble_iterator() {
        let input = [0xAB, 0x34, 0x56, 0x78];
        let mut nibble_iter = NibbleIterator::new(&input);
        assert_eq!(nibble_iter.next(), Some(Nibble(0x0A)));
        assert_eq!(nibble_iter.next(), Some(Nibble(0x0B)));
        assert_eq!(nibble_iter.next(), Some(Nibble(0x03)));
        assert_eq!(nibble_iter.next(), Some(Nibble(0x04)));
        assert_eq!(nibble_iter.next(), Some(Nibble(0x05)));
        assert_eq!(nibble_iter.next(), Some(Nibble(0x06)));
        assert_eq!(nibble_iter.next(), Some(Nibble(0x07)));
        assert_eq!(nibble_iter.next(), Some(Nibble(0x08)));
        assert_eq!(nibble_iter.next(), None);
    }

    #[test]
    fn test_wrapping_add() {
        assert_eq!(Nibble(0x0A).wrapping_add(&Nibble(0x01)), Nibble(0x0B));
        assert_eq!(Nibble(0x0F).wrapping_add(&Nibble(0x01)), Nibble(0x00));
        assert_eq!(Nibble(0x0F).wrapping_add(&Nibble(0x09)), Nibble(0x08));
        assert_eq!(Nibble(0x0D).wrapping_add(&Nibble(0x09)), Nibble(0x06));
    }

    #[test]
    fn test_nibble_one_more_than() {
        let a = Nibble(0x0A);
        let b = Nibble(0x0B);
        assert!(a.one_more_than(b));
    }

    #[test]
    fn test_nibble_not_one_more_than() {
        let a = Nibble(0x0A);
        let b = Nibble(0x0A);
        assert!(!a.one_more_than(b));
    }

    #[test]
    fn test_nibble_one_more_than_upper_bound() {
        let a = Nibble(0x0E);
        let b = Nibble(0x0F);
        assert!(a.one_more_than(b));
    }

    #[test]
    fn test_nibble_not_one_more_than_upper_bound() {
        let a = Nibble(0x0D);
        let b = Nibble(0x0F);
        assert!(!a.one_more_than(b));
    }

    #[test]
    fn test_nibble_one_more_than_wrapping() {
        let a = Nibble(0x0F);
        let b = Nibble(0x00);
        assert!(a.one_more_than(b));
    }

    #[test]
    fn test_nibble_not_one_more_than_wrapping() {
        let a = Nibble(0x0F);
        let b = Nibble(0x01);
        assert!(!a.one_more_than(b));
    }
}
