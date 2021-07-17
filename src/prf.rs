use aes::{Aes128, Block};
use aes::cipher::{
    consts::U16,
    BlockEncrypt, NewBlockCipher, BlockCipher,
    generic_array::GenericArray,
};

pub struct Prf {
    cipher: Aes128
}

pub fn encrypt(key: &GenericArray<u8, <Aes128 as NewBlockCipher>::KeySize>, block: &mut GenericArray<u8, U16>) {
    let cipher = Aes128::new(key);
    cipher.encrypt_block(block);
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


