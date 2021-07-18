use aes::{Aes128, Block};
use aes::cipher::{
    consts::{U8, U16},
    BlockEncrypt, NewBlockCipher, BlockCipher,
    generic_array::{GenericArray, ArrayLength},
};
use block_modes::{BlockMode, Ecb};
use block_modes::block_padding::NoPadding; // TODO: Probs better to do ZeroPadding but check performance

type Aes128Ecb = Ecb<Aes128, NoPadding>;
type BlockSize = <Aes128 as BlockCipher>::BlockSize;

pub struct Prf {
    cipher: Aes128
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

pub fn encrypt(key: &GenericArray<u8, <Aes128 as NewBlockCipher>::KeySize>, block: &mut GenericArray<u8, U16>) {
    let cipher = Aes128::new(key);
    cipher.encrypt_block(block);
}

pub fn encrypt_all(key: &GenericArray<u8, <Aes128 as NewBlockCipher>::KeySize>, data: &mut [u8]) {
    // TODO: Don't use unwrap
    //let mut cipher = Aes128Ecb::new_from_slices(&key).unwrap();
    let cipher = Aes128::new(key);
    let mut blocks = to_blocks::<BlockSize>(&mut data[..]);
    let ciphertext = cipher.encrypt_blocks(&mut blocks);
}

// TODO: Make some type aliases!
pub fn encrypt8(key: &GenericArray<u8, <Aes128 as NewBlockCipher>::KeySize>, blocks: &mut [GenericArray<u8, U16>]) {
    let cipher = Aes128::new(key);
    cipher.encrypt_blocks(blocks);
}

impl Prf {
    pub fn init(key: &[u8]) -> Prf {
        let key_array = GenericArray::from_slice(key);
        let cipher = Aes128::new(&key_array);
        return Prf { cipher };
    }

    /* Encrypts the input block in place */
    pub fn encrypt(&self, output: &mut [u8]) {
        let mut block = GenericArray::from_mut_slice(output);
        self.cipher.encrypt_block(&mut block);
    }

    pub fn encrypt_par_block(&self, input: [u8; 8], output: &mut [Block]) {
        for i in 0..7 {
            output[i][0] = input[i];
        }
        let mut block8 = GenericArray::from_mut_slice(output);
        self.cipher.encrypt_par_blocks(&mut block8);
    }
}


