use aes::{Aes128, Block};
use aes::cipher::{
    BlockEncrypt, NewBlockCipher,
    generic_array::GenericArray,
};

pub struct Prf {
    cipher: Aes128
}

//pub fn encrypt(key: &GenericArray<u8, <Aes128 as NewBlockCipher>::KeySize>, block: &mut Block) {
pub fn encrypt(key: &GenericArray<u8, <Aes128 as NewBlockCipher>::KeySize>, block: &mut [u8]) {
    let cipher = Aes128::new(key);
    // FIXME: We really don't want to be calling from_mut_slice as it is super slow!
    let ga = GenericArray::from_mut_slice(block);
    cipher.encrypt_block(ga);
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


