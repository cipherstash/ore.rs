use crate::header::Header;

pub struct DataWithHeader {
    data: Vec<u8>
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum CtType {
    Left = 0,
    Right = 1,
    Combined = 2,
}

impl From<u8> for CtType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Left,
            1 => Self::Right,
            2 => Self::Combined,
            _ => panic!("Unknown Ciphertext Type")
        }
    }
}

impl DataWithHeader {
    pub(crate) fn new(header: Header, body_len: usize) -> Self {
        let mut data = Vec::with_capacity(Header::HEADER_LEN + body_len);
        data.extend(header.to_vec());
        Self { data }
    }

    pub(crate) fn header(&self) -> Header {
        Header::from_slice(&self.data)
    }

    pub(crate) fn set_header(&mut self, hdr: &Header) {
        self.data[0..Header::HEADER_LEN].copy_from_slice(&hdr.to_vec());
    }

    /// Returns a slice to the body of the ciphertext.
    /// That is, everything after the header.
    pub(crate) fn body(&self) -> &[u8] {
        &self.data[Header::HEADER_LEN..]
    }

    pub fn extend<I>(&mut self, iter: I)
        where
            I: IntoIterator<Item = u8>
    {
        self.data.extend(iter)
    }

    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.data.extend_from_slice(slice);
    }
}

impl AsRef<[u8]> for DataWithHeader {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl From<&[u8]> for DataWithHeader {
    fn from(data: &[u8]) -> Self {
        assert!(data.len() >= Header::HEADER_LEN);
        // TODO: It would be nice if we could avoid this copy!
        Self { data: data.to_vec() }
    }
}