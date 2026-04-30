use thiserror::Error;

use crate::primitives::NONCE_SIZE;
pub use crate::OreCipher;

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
/// length, malformed block, etc.).
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
}

impl<S: OreCipher, const N: usize> OreOutput for Left<S, N> {
    fn size() -> usize {
        N * (S::LeftBlockType::BLOCK_SIZE + 1)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(N * S::LeftBlockType::BLOCK_SIZE);
        self.f
            .iter()
            .for_each(|&block| vec.append(&mut block.to_bytes()));

        [self.xt.to_vec(), vec].concat()
    }

    fn from_slice(data: &[u8]) -> Result<Self, ParseError> {
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

impl<S: OreCipher, const N: usize> Right<S, N> {
    pub(crate) fn init() -> Self {
        Self {
            nonce: Default::default(),
            data: [Default::default(); N],
        }
    }
}

impl<S: OreCipher, const N: usize> OreOutput for Right<S, N> {
    fn size() -> usize {
        (N * S::RightBlockType::BLOCK_SIZE) + NONCE_SIZE
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(N * S::RightBlockType::BLOCK_SIZE);
        self.data
            .iter()
            .for_each(|&block| vec.append(&mut block.to_bytes()));

        [self.nonce.to_vec(), vec].concat()
    }

    fn from_slice(data: &[u8]) -> Result<Self, ParseError> {
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

impl<S: OreCipher, const N: usize> OreOutput for CipherText<S, N> {
    fn size() -> usize {
        Left::<S, N>::size() + Right::<S, N>::size()
    }

    /// Serialize the ciphertext into a vector of bytes
    fn to_bytes(&self) -> Vec<u8> {
        [self.left.to_bytes(), self.right.to_bytes()].concat()
    }

    /// Deserialize from a slice of bytes
    fn from_slice(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() != (Left::<S, N>::size() + Right::<S, N>::size()) {
            return Err(ParseError);
        }
        let (left, right) = data.split_at(Left::<S, N>::size());
        let left = Left::<S, N>::from_slice(left)?;
        let right = Right::<S, N>::from_slice(right)?;

        Ok(Self { left, right })
    }
}
