
use crate::primitives::AesBlock;

#[derive(Debug)]
pub struct Left<T, const N: usize> { // TODO: add a Trait bound for a Left Block
    /* Array of Left blocks of size N */
    pub f: [T; N],

    /* Transformed input array of size N (x̃ = π(F (k_2 , x|i−1 ), x_i )) */
    pub xt: [u8; N]
}

#[derive(Debug)]
pub struct Right<T, const N: usize> { // TODO: add a Trait bound for a Right Block
    pub nonce: AesBlock,
    pub data: [T; N]
}

#[derive(Debug)]
pub struct CipherText<L, R, const N: usize> {
    pub left: Left<L, N>,
    pub right: Right<R, N>
}
