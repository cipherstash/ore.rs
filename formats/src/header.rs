use crate::data_with_header::CtType;

#[derive(PartialEq, Debug)]
pub struct Header {
    pub version: u16,
    pub scheme: u8,
    pub ct_type: CtType,
    pub num_blocks: u16
}

impl Header {
    pub(super) const HEADER_LEN: usize = 6;

    pub(super) fn new(ct_type: CtType, num_blocks: usize) -> Self {
        assert!(num_blocks < (u16::MAX as usize));

        Self {
            // Hardcode version and scheme for now
            version: 0,
            scheme: 0,
            ct_type,
            num_blocks: num_blocks as u16
        }
    }

    /// Indicates if this ciphertext header is comparable to another.
    /// This means the version and scheme must be the same.
    /// Specific schemes may impose additional restrictions (such as matching lengths).
    pub(super) fn comparable(&self, other: &Header) -> bool {
        use CtType::*;
        if self.version != other.version { return false }
        if self.scheme != self.scheme { return  false }

        match (self.ct_type, other.ct_type) {
            (Combined, Combined) => true,
            (Left, Right) => true,
            _ => false
        }
    }

    pub(super) fn to_vec(&self) -> Vec<u8> {
        let mut hdr: Vec<u8> = Vec::with_capacity(Self::HEADER_LEN);
        hdr.extend(self.version.to_be_bytes());
        hdr.push(self.scheme);
        hdr.push(*&self.ct_type as u8);
        hdr.extend(self.num_blocks.to_be_bytes());
        hdr 
    }

    pub(super) fn from_slice(hdr: &[u8]) -> Self { // TODO: Handle error
        assert!(hdr.len() >= Self::HEADER_LEN, "Header cannot be read from slice of less than {} bytes", Self::HEADER_LEN);
        let mut iter = hdr.into_iter();
        let version: u16 = u16::from_be_bytes(iter.next_chunk::<2>().unwrap().map(|c| *c));
        let scheme: u8 = *iter.next().unwrap();
        let ct_type: CtType = (*iter.next().unwrap()).into();
        let num_blocks: u16 = u16::from_be_bytes(iter.next_chunk::<2>().unwrap().map(|c| *c));

        Self { version, scheme, ct_type, num_blocks }
    }
}

#[cfg(test)]
mod tests {
    use crate::data_with_header::CtType;
    use super::Header;

    #[test]
    fn test_new() {
        let header = Header::new(CtType::Right, 12);
        assert_eq!(header.version, 0);
        assert_eq!(header.scheme, 0);
        assert_eq!(header.ct_type, CtType::Right);
        assert_eq!(header.num_blocks, 12);
    }

    #[test]
    fn test_roundtrip() {
        let header = Header::new(CtType::Left, 8);
        let bytes = header.to_vec();
        assert_eq!(header, Header::from_slice(&bytes));
    }

    #[test]
    fn test_roundtrip_with_ignored_trailing_bytes() {
        let header = Header::new(CtType::Left, 8);
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend(header.to_vec());
        bytes.extend(vec![1, 2, 3, 4]);
        assert_eq!(header, Header::from_slice(&bytes));
    }
}
