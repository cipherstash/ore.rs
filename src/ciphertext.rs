use crate::primitives::NONCE_SIZE;
pub use crate::OreCipher;

#[derive(Debug, Copy, Clone)]
pub struct Left<S: OreCipher, const N: usize> {
    /* Array of Left blocks of size N */
    pub f: [S::LeftBlockType; N],

    /* Transformed input array of size N (x̃ = π(F (k_2 , x|i−1 ), x_i )) */
    pub xt: [u8; N],
}

#[derive(Debug, Copy, Clone)]
pub struct Right<S: OreCipher, const N: usize> {
    pub nonce: [u8; NONCE_SIZE],
    pub data: [S::RightBlockType; N],
}

#[derive(Debug, Copy, Clone)]
pub struct CipherText<S: OreCipher, const N: usize> {
    pub left: Left<S, N>,
    pub right: Right<S, N>,
}

pub trait CipherTextBlock: Default + Copy + std::fmt::Debug {
    const BLOCK_SIZE: usize;

    fn to_bytes(self) -> Vec<u8>;

    fn from_bytes(data: &[u8]) -> Result<Self, ParseError>;

    fn default_in_place(&mut self);
}

#[derive(Debug)]
pub struct ParseError;

impl<S: OreCipher, const N: usize> Left<S, N> {
    pub(crate) fn init() -> Self {
        Self {
            xt: [0; N],
            f: [S::LeftBlockType::default(); N],
        }
    }

    pub fn size() -> usize {
        N * (S::LeftBlockType::BLOCK_SIZE + 1)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(N * S::LeftBlockType::BLOCK_SIZE);
        self.f
            .iter()
            .for_each(|&block| vec.append(&mut block.to_bytes()));

        [self.xt.to_vec(), vec].concat()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
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

    pub fn size() -> usize {
        (N * S::RightBlockType::BLOCK_SIZE) + NONCE_SIZE
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(N * S::RightBlockType::BLOCK_SIZE);
        self.data
            .iter()
            .for_each(|&block| vec.append(&mut block.to_bytes()));

        [self.nonce.to_vec(), vec].concat()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
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

impl<S: OreCipher, const N: usize> CipherText<S, N> {
    pub fn to_bytes(&self) -> Vec<u8> {
        [self.left.to_bytes(), self.right.to_bytes()].concat()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() != (Left::<S, N>::size() + Right::<S, N>::size()) {
            return Err(ParseError);
        }
        let (left, right) = data.split_at(Left::<S, N>::size());
        let left = Left::<S, N>::from_bytes(left)?;
        let right = Right::<S, N>::from_bytes(right)?;

        Ok(Self { left, right })
    }
}
