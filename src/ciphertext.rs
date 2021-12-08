use crate::primitives::{AesBlock, NONCE_SIZE};
pub use crate::ORECipher;

#[derive(Debug)]
pub struct Left<T: CipherTextBlock, const N: usize> {
    /* Array of Left blocks of size N */
    pub f: [T; N],

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
    pub left: Left<S::LeftBlockType, N>,
    pub right: Right<S::RightBlockType, N>
}

pub trait CipherTextBlock: Default + Copy {
    const BLOCK_SIZE: usize;

    // TODO: I wonder if we should be using &[u8] slices with lifetimes? (See pgx for inspo)
    fn to_bytes(self) -> Vec<u8>;
    fn from_bytes(data: &[u8]) -> Result<Self, ParseError>;
}

#[derive(Debug)]
pub struct ParseError;

// TODO: Change Left and Right to be generic on the ORECipher type instead of L and R block types
// TODO: Make sure the generic is type bound to ORECipher
impl<T: CipherTextBlock, const N: usize> Left<T, N> {
    pub(crate) fn init() -> Self {
        Self {
            xt: [0; N],
            f: [T::default(); N]
        }
    }

    pub fn size() -> usize {
        N * (T::BLOCK_SIZE + 1)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(N * T::BLOCK_SIZE);
        self.f.iter().for_each(|&block| vec.append(&mut block.to_bytes()));
        return [self.xt.to_vec(), vec].concat();
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        let mut out = Self::init();
        out.xt.copy_from_slice(&data[0..N]);
        for i in 0..N {
            let block_start_index = N + (i * T::BLOCK_SIZE);
            out.f[i] = T::from_bytes(&data[block_start_index..(block_start_index + T::BLOCK_SIZE)])?;
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

// TODO: This should really compose Left and Right and only actually be Generic in N
// Left and Right are themselves generic
impl <S: ORECipher, const N: usize> CipherText<S, N>
where <S as ORECipher>::LeftBlockType: CipherTextBlock,
      <S as ORECipher>::RightBlockType: CipherTextBlock
{
    pub fn to_bytes(&self) -> Vec<u8> {
        return [self.left.to_bytes(), self.right.to_bytes()].concat();
    }

    // TODO: Can we use an associated type here to store the Left and Right types?
    pub fn from_bytes(data: &Vec<u8>) -> Result<Self, ParseError> {
        if data.len() != (Left::<S::LeftBlockType, N>::size() + Right::<S::RightBlockType, N>::size()) {
            return Err(ParseError);
        }
        let (left, right) = data.split_at(Left::<S::LeftBlockType, N>::size());
        let left = Left::<S::LeftBlockType, N>::from_bytes(&left)?;
        let right = Right::<S::RightBlockType, N>::from_bytes(&right)?;

        return Ok(Self { left: left, right: right });
    }
}
