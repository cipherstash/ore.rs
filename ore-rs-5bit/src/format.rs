use self::header::Header;

mod header;

const LEFT_BLOCKSIZE: usize = 16;
const RIGHT_BLOCKSIZE: usize = 32;
const NONCE_SIZE: usize = 16;

#[derive(Clone, Copy, PartialEq, Debug)]
enum CtType {
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

struct RawCiphertext {
    data: Vec<u8>
}

impl RawCiphertext {
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

pub struct LeftCiphertext {
    data: RawCiphertext
}

pub struct RightCiphertext {
    data: RawCiphertext
}

pub struct CombinedCiphertext {
    data: RawCiphertext
}

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
impl LeftCiphertext {
    const BLOCK_SIZE: usize = 17;

    pub fn new(num_blocks: usize) -> Self {
        let hdr = Header::new(CtType::Left, num_blocks);

        Self { data: RawCiphertext::new(hdr, num_blocks * Self::BLOCK_SIZE) }
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
        let mut data = RawCiphertext::new(hdr, Self::NONCE_SIZE + (num_blocks * Self::BLOCKSIZE));
        data.extend_from_slice(nonce);
        Self { data }
    }

    pub fn add_block(&mut self, block: u32) {
        self.data.extend(block.to_be_bytes().into_iter());
    }
}

impl CombinedCiphertext {
    /// Creates a new CombinedCiphertext by merging (and consuming) the given left and right Ciphertexts.
    /// The headers must be comparable (See [Header]) and have the same block length.
    /// The resulting Ciphertext has a single header representing both ciphertexts.
    pub fn new(mut left: LeftCiphertext, right: RightCiphertext) -> Self {
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