use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, NewBlockCipher, BlockCipher,
    generic_array::{GenericArray, ArrayLength},
};

type BlockSize = <Aes128 as BlockCipher>::BlockSize;

pub trait PRF {
    fn new(key: &[u8]) -> Self;
    fn encrypt_all(&self, data: &mut [u8]);
}

#[derive(Debug)]
pub struct AES128PRF {
    cipher: Aes128
}

impl PRF for AES128PRF {
    fn new(key: &[u8]) -> Self {
        let key_array = GenericArray::from_slice(key);
        let cipher = Aes128::new(&key_array);
        return Self { cipher };
    }

    fn encrypt_all(&self, data: &mut [u8]) {
        let mut blocks = to_blocks::<BlockSize>(&mut data[..]);
        self.cipher.encrypt_blocks(&mut blocks);
    }
}

fn to_blocks<N>(data: &mut [u8]) -> &mut [GenericArray<u8, N>]
where
    N: ArrayLength<u8>,
{
    use core::slice;
    let n = N::to_usize();
    debug_assert!(data.len() % n == 0);

    #[allow(unsafe_code)]
    unsafe {
        slice::from_raw_parts_mut(data.as_ptr() as *mut GenericArray<u8, N>, data.len() / n)
    }
}

