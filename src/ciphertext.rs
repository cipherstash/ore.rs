use crate::primitives::{AesBlock, NONCE_SIZE};
pub use crate::ORECipher;

#[derive(Debug)]
pub struct Left<S: ORECipher, const N: usize>
where <S as ORECipher>::LeftBlockType: CipherTextBlock
{
    /* Array of Left blocks of size N */
    pub f: [S::LeftBlockType; N],

    /* Transformed input array of size N (x̃ = π(F (k_2 , x|i−1 ), x_i )) */
    pub xt: [u8; N]
}

#[derive(Debug)]
pub struct Right<T: CipherTextBlock, const N: usize> {
    pub nonce: AesBlock,
    pub data: [T; N]
}

#[derive(Debug)]
pub struct CipherText<S: ORECipher, const N: usize>
where <S as ORECipher>::LeftBlockType: CipherTextBlock,
      <S as ORECipher>::RightBlockType: CipherTextBlock
{
    pub left: Left<S, N>,
    pub right: Right<S::RightBlockType, N>
}

pub trait CipherTextBlock: Default + Copy + std::fmt::Debug {
    const BLOCK_SIZE: usize;

    // TODO: I wonder if we should be using &[u8] slices with lifetimes? (See pgx for inspo)
    fn to_bytes(self) -> Vec<u8>;
    fn from_bytes(data: &[u8]) -> Result<Self, ParseError>;
}

#[derive(Debug)]
pub struct ParseError;

impl<S: ORECipher, const N: usize> Left<S, N>
where <S as ORECipher>::LeftBlockType: CipherTextBlock
{
    pub(crate) fn init() -> Self {
        Self {
            xt: [0; N],
            f: [S::LeftBlockType::default(); N]
        }
    }

    pub fn size() -> usize {
        N * (S::LeftBlockType::BLOCK_SIZE + 1)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(N * S::LeftBlockType::BLOCK_SIZE);
        self.f.iter().for_each(|&block| vec.append(&mut block.to_bytes()));
        return [self.xt.to_vec(), vec].concat();
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        let mut out = Self::init();
        out.xt.copy_from_slice(&data[0..N]);
        for i in 0..N {
            let block_start_index = N + (i * S::LeftBlockType::BLOCK_SIZE);
            out.f[i] = S::LeftBlockType::from_bytes(&data[block_start_index..(block_start_index + S::LeftBlockType::BLOCK_SIZE)])?;
        }
        return Ok(out);
    }
}

impl<T: CipherTextBlock, const N: usize> Right<T, N> {
    pub(crate) fn init() -> Self {
        Self {
            nonce: Default::default(),
            data: [Default::default(); N]
        }
    }

    pub fn size() -> usize {
        N * T::BLOCK_SIZE + NONCE_SIZE
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(N * T::BLOCK_SIZE);
        self.data.iter().for_each(|&block| vec.append(&mut block.to_bytes()));
        return [self.nonce.to_vec(), vec].concat();
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        let mut out = Self::init();
        out.nonce.copy_from_slice(&data[0..NONCE_SIZE]);
        for i in 0..N {
            let block_start_index = NONCE_SIZE + (i * T::BLOCK_SIZE);
            out.data[i] = T::from_bytes(&data[block_start_index..(block_start_index + T::BLOCK_SIZE)])?;
        }
        return Ok(out);
    }
}

impl <S: ORECipher, const N: usize> CipherText<S, N>
where <S as ORECipher>::LeftBlockType: CipherTextBlock,
      <S as ORECipher>::RightBlockType: CipherTextBlock
{
    pub fn to_bytes(&self) -> Vec<u8> {
        return [self.left.to_bytes(), self.right.to_bytes()].concat();
    }

    pub fn from_bytes(data: &Vec<u8>) -> Result<Self, ParseError> {
        if data.len() != (Left::<S, N>::size() + Right::<S::RightBlockType, N>::size()) {
            return Err(ParseError);
        }
        let (left, right) = data.split_at(Left::<S, N>::size());
        let left = Left::<S, N>::from_bytes(&left)?;
        let right = Right::<S::RightBlockType, N>::from_bytes(&right)?;

        return Ok(Self { left: left, right: right });
    }
}
