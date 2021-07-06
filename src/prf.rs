use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, NewBlockCipher,
    generic_array::GenericArray,
};

pub struct Prf {
    cipher: Aes128
}

impl Prf {
    pub fn init(key: &[u8]) -> Prf {
        let key_array = GenericArray::from_slice(key);
        let cipher = Aes128::new(&key_array);
        return Prf { cipher };
    }

    pub fn encrypt(&self, input: u8, output: &mut [u8]) {
        // FIXME: Do we need to consider padding here?
        //BigEndian::write_u8(&mut buf, input);
        output[0] = input;

        let mut block = GenericArray::from_mut_slice(output);
        self.cipher.encrypt_block(&mut block);
    }
}


