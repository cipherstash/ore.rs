use thiserror::Error;

use crate::primitives::NONCE_SIZE;
pub use crate::OreCipher;

/// Wire-format header prepended to every serialised artifact (Left, Right
/// or combined ciphertext) of schemes introduced from ORE v2 onwards.
///
/// Layout: `version ‖ scheme_id ‖ block_count (u16 BE)` — 4 bytes. The
/// legacy [`crate::scheme::bit2`] scheme predates headers and remains
/// headerless forever ([`OreCipher::WIRE_HEADER`] is `None` for it);
/// ciphertexts of headered schemes can never be confused with each other
/// (version + scheme id are validated on parse and compare), and each
/// *type* only ever parses its own format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireHeader {
    /// Wire format version. `0x02` is the first headered format.
    pub version: u8,
    /// Scheme identifier (encodes block width, prefix mode and cipher
    /// suite). See the scheme modules for assigned values.
    pub scheme_id: u8,
}

/// Serialised size of a [`WireHeader`] plus the block count it carries.
pub(crate) const WIRE_HEADER_LEN: usize = 4;

impl WireHeader {
    pub(crate) fn write(&self, num_blocks: usize, out: &mut Vec<u8>) {
        debug_assert!(num_blocks <= u16::MAX as usize);
        out.push(self.version);
        out.push(self.scheme_id);
        out.extend_from_slice(&(num_blocks as u16).to_be_bytes());
    }

    /// Validate `data`'s header against `self` and an expected block count,
    /// returning the payload after the header.
    pub(crate) fn strip<'a>(
        &self,
        num_blocks: usize,
        data: &'a [u8],
    ) -> Result<&'a [u8], ParseError> {
        let (header, body) = parse_header(data)?;
        if header != (self.version, self.scheme_id, num_blocks) {
            return Err(ParseError);
        }
        Ok(body)
    }
}

/// `(version, scheme_id, block_count)` as parsed from a wire header.
pub(crate) type ParsedHeader = (u8, u8, usize);

/// Split a headered slice into `((version, scheme_id, block_count), body)`.
pub(crate) fn parse_header(data: &[u8]) -> Result<(ParsedHeader, &[u8]), ParseError> {
    if data.len() < WIRE_HEADER_LEN {
        return Err(ParseError);
    }
    let count = u16::from_be_bytes([data[2], data[3]]) as usize;
    Ok(((data[0], data[1], count), &data[WIRE_HEADER_LEN..]))
}

fn header_len<S: OreCipher>() -> usize {
    if S::WIRE_HEADER.is_some() {
        WIRE_HEADER_LEN
    } else {
        0
    }
}

/// The trait of any encryption output (either Left, Right or combined).
pub trait OreOutput: Sized {
    /// The size (in bytes) of this encrypted value
    fn size() -> usize;

    /// Convert to bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Try to deserialize from a slice
    fn from_slice(data: &[u8]) -> Result<Self, ParseError>;

    /// Deserialise from a byte slice.
    #[deprecated(since = "0.8.0", note = "please use `from_slice` instead")]
    fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        Self::from_slice(data)
    }
}

/// The Left half of a fixed-N BlockORE ciphertext: the per-block PRF₁ tags
/// `f` and the per-block PRP outputs `xt`. Sufficient on its own to act as
/// the "query" side of the comparator.
#[derive(Debug, Copy, Clone)]
pub struct Left<S: OreCipher, const N: usize> {
    /// Per-block PRF₁ tag binding `(prefix ‖ xt[i] ‖ block_index)`.
    pub f: [S::LeftBlockType; N],

    /// Per-block PRP output `xt[i] = π_i(x[i])`.
    pub xt: [u8; N],
}

/// The Right half of a fixed-N BlockORE ciphertext: a per-ciphertext nonce
/// and per-block masked truth-table rows. Combined with a Left from another
/// ciphertext this drives the comparator.
#[derive(Debug, Copy, Clone)]
pub struct Right<S: OreCipher, const N: usize> {
    /// 16-byte random nonce, shared across all blocks of this ciphertext.
    pub nonce: [u8; NONCE_SIZE],
    /// Per-block masked truth tables.
    pub data: [S::RightBlockType; N],
}

/// A complete fixed-N BlockORE ciphertext: Left + Right.
#[derive(Debug, Copy, Clone)]
pub struct CipherText<S: OreCipher, const N: usize> {
    /// Left half (PRF tags + permuted plaintext bytes).
    pub left: Left<S, N>,
    /// Right half (nonce + masked truth tables).
    pub right: Right<S, N>,
}

/// Trait implemented by per-block ciphertext components (Left and Right
/// blocks). Provides a fixed serialised size and byte conversions used by
/// [`OreOutput`].
pub trait CipherTextBlock: Default + Copy + std::fmt::Debug {
    /// Serialised size of one block in bytes.
    const BLOCK_SIZE: usize;

    /// Serialise this block to bytes.
    fn to_bytes(self) -> Vec<u8>;

    /// Deserialise a block from a byte slice. Returns [`ParseError`] if the
    /// slice is malformed or the wrong length.
    fn from_bytes(data: &[u8]) -> Result<Self, ParseError>;

    /// Reset this block to its default value in place.
    fn default_in_place(&mut self);
}

/// Error returned when a serialised ciphertext can't be parsed (wrong
/// length, malformed block, bad or mismatched wire header, etc.).
#[derive(Debug, Error)]
#[error("Unable to parse ORE Ciphertext")]
pub struct ParseError;

impl<S: OreCipher, const N: usize> Left<S, N> {
    pub(crate) fn init() -> Self {
        Self {
            xt: [0; N],
            f: [S::LeftBlockType::default(); N],
        }
    }

    /// Serialised size of the headerless body.
    pub(crate) fn body_size() -> usize {
        N * (S::LeftBlockType::BLOCK_SIZE + 1)
    }

    fn write_body(&self, vec: &mut Vec<u8>) {
        vec.extend_from_slice(&self.xt);
        self.f
            .iter()
            .for_each(|&block| vec.append(&mut block.to_bytes()));
    }

    fn from_body(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() != Self::body_size() {
            return Err(ParseError);
        }
        let mut out = Self::init();
        out.xt.copy_from_slice(&data[0..N]);
        for i in 0..N {
            let block_start_index = N + (i * S::LeftBlockType::BLOCK_SIZE);
            out.f[i] = S::LeftBlockType::from_bytes(
                &data[block_start_index..(block_start_index + S::LeftBlockType::BLOCK_SIZE)],
            )?;
        }

        Ok(out)
    }
}

impl<S: OreCipher, const N: usize> OreOutput for Left<S, N> {
    fn size() -> usize {
        header_len::<S>() + Self::body_size()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(Self::size());
        if let Some(header) = S::WIRE_HEADER {
            header.write(N, &mut vec);
        }
        self.write_body(&mut vec);
        vec
    }

    fn from_slice(data: &[u8]) -> Result<Self, ParseError> {
        let body = match S::WIRE_HEADER {
            Some(header) => header.strip(N, data)?,
            None => data,
        };
        Self::from_body(body)
    }
}

impl<S: OreCipher, const N: usize> Right<S, N> {
    pub(crate) fn init() -> Self {
        Self {
            nonce: Default::default(),
            data: [Default::default(); N],
        }
    }

    /// Serialised size of the headerless body.
    pub(crate) fn body_size() -> usize {
        (N * S::RightBlockType::BLOCK_SIZE) + NONCE_SIZE
    }

    fn write_body(&self, vec: &mut Vec<u8>) {
        vec.extend_from_slice(&self.nonce);
        self.data
            .iter()
            .for_each(|&block| vec.append(&mut block.to_bytes()));
    }

    fn from_body(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() != Self::body_size() {
            return Err(ParseError);
        }
        let mut out = Self::init();
        out.nonce.copy_from_slice(&data[0..NONCE_SIZE]);
        for i in 0..N {
            let block_start_index = NONCE_SIZE + (i * S::RightBlockType::BLOCK_SIZE);
            out.data[i] = S::RightBlockType::from_bytes(
                &data[block_start_index..(block_start_index + S::RightBlockType::BLOCK_SIZE)],
            )?;
        }
        Ok(out)
    }
}

impl<S: OreCipher, const N: usize> OreOutput for Right<S, N> {
    fn size() -> usize {
        header_len::<S>() + Self::body_size()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(Self::size());
        if let Some(header) = S::WIRE_HEADER {
            header.write(N, &mut vec);
        }
        self.write_body(&mut vec);
        vec
    }

    fn from_slice(data: &[u8]) -> Result<Self, ParseError> {
        let body = match S::WIRE_HEADER {
            Some(header) => header.strip(N, data)?,
            None => data,
        };
        Self::from_body(body)
    }
}

impl<S: OreCipher, const N: usize> OreOutput for CipherText<S, N> {
    fn size() -> usize {
        header_len::<S>() + Left::<S, N>::body_size() + Right::<S, N>::body_size()
    }

    /// Serialize the ciphertext into a vector of bytes. Headered schemes
    /// emit exactly one header for the combined artifact (not one per
    /// half).
    fn to_bytes(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(Self::size());
        if let Some(header) = S::WIRE_HEADER {
            header.write(N, &mut vec);
        }
        self.left.write_body(&mut vec);
        self.right.write_body(&mut vec);
        vec
    }

    /// Deserialize from a slice of bytes
    fn from_slice(data: &[u8]) -> Result<Self, ParseError> {
        let body = match S::WIRE_HEADER {
            Some(header) => header.strip(N, data)?,
            None => data,
        };
        if body.len() != Left::<S, N>::body_size() + Right::<S, N>::body_size() {
            return Err(ParseError);
        }
        let (left, right) = body.split_at(Left::<S, N>::body_size());
        let left = Left::<S, N>::from_body(left)?;
        let right = Right::<S, N>::from_body(right)?;

        Ok(Self { left, right })
    }
}
