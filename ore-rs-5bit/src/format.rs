use std::slice::Iter;

use self::header::Header;
mod header;

// TODO: make the new and add_block functions a separate trait

pub trait CipherText<B> {
    fn comparable<C>(&self, to: &impl CipherText<C>) -> bool {
        self.header().comparable(&to.header())
    }
    fn header(&self) -> Header;

    fn blocks(&self) -> Iter<B>;
}

#[derive(Debug)]
pub struct ParseError {}

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

struct DataWithHeader {
    data: Vec<u8>
}

impl DataWithHeader {
    fn new(header: Header, body_len: usize) -> Self {
        let mut data = Vec::with_capacity(Header::HEADER_LEN + body_len);
        data.extend(header.to_vec());
        Self { data }
    }

    fn header(&self) -> Header {
        Header::from_slice(&self.data)
    }

    fn set_header(&mut self, hdr: &Header) {
        self.data[0..Header::HEADER_LEN].copy_from_slice(&hdr.to_vec());
    }

    /// Returns a slice to the body of the ciphertext.
    /// That is, everything after the header.
    pub fn body(&self) -> &[u8] {
        &self.data[Header::HEADER_LEN..]
    }

    fn extend<I>(&mut self, iter: I)
        where
            I: IntoIterator<Item = u8>
    {
        self.data.extend(iter)
    }

    fn extend_from_slice(&mut self, slice: &[u8]) {
        self.data.extend_from_slice(slice);
    }
}

pub struct LeftCiphertext<B> {
    data: DataWithHeader
}

pub struct RightCiphertext {
    data: DataWithHeader
}

pub struct CombinedCiphertext<B> {
    data: DataWithHeader
}

impl<B> CipherText<B> for LeftCiphertext<B> {
    fn header(&self) -> Header {
        self.data.header()
    }
}

impl<B> CipherText<B> for CombinedCiphertext<B> {
    fn header(&self) -> Header {
        self.data.header()
    }
}

impl<B> TryFrom<&[u8]> for LeftCiphertext<B> {
    type Error = ParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let hdr = Header::from_slice(data);
        if matches!(hdr.ct_type, CtType::Left) {
            // TODO: It would be nice if we could avoid this copy!
            let raw = DataWithHeader { data: data.to_vec() };
            Ok(LeftCiphertext { data: raw })
        } else {
            Err(ParseError {  })
        }
    }
}

impl<B> TryFrom<&[u8]> for CombinedCiphertext<B> {
    type Error = ParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let hdr = Header::from_slice(data);
        if matches!(hdr.ct_type, CtType::Combined) {
            // TODO: It would be nice if we could avoid this copy!
            let raw = DataWithHeader { data: data.to_vec() };
            Ok(Self { data: raw })
        } else {
            Err(ParseError {  })
        }
    }
}

impl AsRef<[u8]> for DataWithHeader {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<B> AsRef<[u8]> for LeftCiphertext<B> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl AsRef<[u8]> for RightCiphertext {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<B> AsRef<[u8]> for CombinedCiphertext<B> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

pub struct LeftBlock([u8; 16], u8);

pub struct CombinedBlock(LeftBlock, u32);

// TODO: Should we include a scheme and/or version number?
/// Wrapper to a structured byte array representing a Left ciphertext.
/// 
/// ## Format
/// 
/// | Field | Number of Bytes |
/// |-------|-----------------|
/// | type  | 1               |
/// | num_blocks | 2 (up to 65535 blocks) |
/// | block* | 17 |
/// 
/// * There are `num_blocks` blocks of 17 bytes.
/// 
impl LeftCiphertext<LeftBlock> {
    // TODO: Self::from() should take an AsRef<[u8]> (not a slice)
    const BLOCK_SIZE: usize = 17;

    pub fn new(num_blocks: usize) -> Self {
        let hdr = Header::new(CtType::Left, num_blocks);

        Self { data: DataWithHeader::new(hdr, num_blocks * Self::BLOCK_SIZE) }
    }

    pub fn add_block(&mut self, block: &[u8; 16], permuted: u8) {
        self.data.extend_from_slice(block);
        self.data.extend([permuted]);
    }

}

impl RightCiphertext {
    // TODO: This could be generic
    const BLOCKSIZE: usize = 32;
    const NONCE_SIZE: usize = 16;

    pub fn new(num_blocks: usize, nonce: &[u8; 16]) -> Self {
        let hdr = Header::new(CtType::Left, num_blocks);
        let mut data = DataWithHeader::new(hdr, Self::NONCE_SIZE + (num_blocks * Self::BLOCKSIZE));
        data.extend_from_slice(nonce);
        Self { data }
    }

    pub fn add_block(&mut self, block: u32) {
        self.data.extend(block.to_be_bytes().into_iter());
    }
}

impl CombinedCiphertext<CombinedBlock> {
    /// Creates a new CombinedCiphertext by merging (and consuming) the given left and right Ciphertexts.
    /// The headers must be comparable (See [Header]) and have the same block length.
    /// The resulting Ciphertext has a single header representing both ciphertexts.
    pub fn new(mut left: LeftCiphertext<LeftBlock>, right: RightCiphertext) -> Self {
        let mut l_hdr = left.data.header();
        let r_hdr = right.data.header();

        if !l_hdr.comparable(&r_hdr) || l_hdr.num_blocks != r_hdr.num_blocks {
            panic!("Cannot combine incompatible ciphertexts");
        }

        // Steal and reuse the left
        l_hdr.ct_type = CtType::Combined;
        left.data.set_header(&l_hdr);
        left.data.extend_from_slice(right.data.body());

        Self { data: left.data }
    }
}