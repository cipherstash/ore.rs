use std::slice;
use crate::{AesBlock, Hash, HashKey};
use aes::cipher::KeyInit;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt};
use aes::Aes128;
use zeroize::ZeroizeOnDrop;

pub type HashBlock = [u8; 16];

fn convert_slice<'a>(input: &'a [HashBlock]) -> &'a mut [AesBlock] {
    let ptr = input.as_ptr() as *mut AesBlock;
    unsafe { slice::from_raw_parts_mut(ptr, input.len()) }
}

#[derive(ZeroizeOnDrop)]
pub struct Aes128Z2Hash {
    cipher: Aes128,
}

impl Aes128Z2Hash {
    pub fn hash_all_onto_u32(&self, data: &[HashBlock]) -> u32 {
        assert!(data.len() <= 32);
        let mut out: u32 = 0;
        let mut blocks = convert_slice(data);
        self.cipher.encrypt_blocks(&mut blocks);

        for (i, block) in blocks.iter().enumerate() {
            out |= ((block[0] & 1u8) as u32) << i;
        }

        out
    }
}

impl Hash for Aes128Z2Hash {
    fn new(key: &HashKey) -> Self {
        let cipher = Aes128::new_from_slice(&key).unwrap();
        Self { cipher }
    }

    fn hash(&self, data: &[u8]) -> u8 {
        /*
         * Slice size is not known at compile time so we assert here
         * We could do this with compile checks but this would require an additional
         * copy (and doesn't entirely avoid runtime checks anyway)
         * See https://stackoverflow.com/questions/38168956/take-slice-of-certain-length-known-at-compile-time
         */
        assert_eq!(data.len(), 16);
        // Can we clone into GenericArray directly? Are we doing an extra copy?
        let mut output = [0u8; 16];
        output.clone_from_slice(data);
        let block = GenericArray::from_mut_slice(&mut output);
        self.cipher.encrypt_block(block);
        output[0] & 1u8
    }

    // TODO: this mutates - see how much a copy effects performance (clone_from_slice)
    fn hash_all(&self, data: &mut [HashBlock]) -> Vec<u8> {
        let mut blocks = convert_slice(data);
        self.cipher.encrypt_blocks(&mut blocks);

        let mut vec = Vec::with_capacity(blocks.len());
        for &mut block in data {
            // Output is Z2 (1-bit)
            vec.push(block[0] & 1u8);
        }

        vec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn init_hash() -> Aes128Z2Hash {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        let key_array = GenericArray::from_slice(&key);
        Hash::new(key_array)
    }

    #[test]
    fn hash_test_1() {
        let hash = init_hash();
        let input: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0eaa");

        assert_eq!(1u8, hash.hash(&input));
    }

    #[test]
    fn hash_test_2() {
        let hash = init_hash();
        let input: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");

        assert_eq!(0u8, hash.hash(&input));
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn hash_test_input_too_small() {
        let hash = init_hash();
        let input: [u8; 8] = hex!("00010203 04050607");

        assert_eq!(0u8, hash.hash(&input));
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn hash_test_input_too_large() {
        let hash = init_hash();
        let input: [u8; 24] = hex!("00010203 04050607 ffffffff bbbbbbbb cccccccc abababab");

        hash.hash(&input);
    }

    #[test]
    fn hash_all_onto_u32_one_elem() {
        let hash = init_hash();

        let mut input: [[u8; 16]; 1] = [
            hex!("00110211 04050607 08090a0b 0c0d0e0f"),
        ];
        let res = hash.hash_all_onto_u32(&mut input);
        assert_eq!(
            res,
            0b1,
        );
    }

    #[test]
    fn hash_all_onto_u32_three_elems() {
        let hash = init_hash();

        let mut input: [[u8; 16]; 3] = [
            hex!("00110211 04050607 08090a0b 0c0d0e0f"),
            hex!("00000000 04050607 08090a0b 0c0d0e0f"),
            hex!("00110211 04050607 08090a0b 0c0d0e0f"),
        ];
        let res = hash.hash_all_onto_u32(&mut input);
        assert_eq!(
            res,
            0b101,
        );
    }

    #[test]
    fn hash_all_onto_u32_16_elems() {
        let hash = init_hash();

        let mut input: [[u8; 16]; 16] = [
            hex!("00110211 04050607 08090a0b 0c0d0e0f"),
            hex!("00000000 04050607 08090a0b 0c0d0e0f"),
            hex!("00110211 04050607 08090a0b 0c0d0e0f"),
            hex!("00000000 04050607 08090a0b 0c0d0e0f"),
            hex!("00110211 04050607 08090a0b 0c0d0e0f"),
            hex!("00000000 04050607 08090a0b 0c0d0e0f"),
            hex!("00110211 04050607 08090a0b 0c0d0e0f"),
            hex!("00000000 04050607 08090a0b 0c0d0e0f"),
            hex!("00110211 04050607 08090a0b 0c0d0e0f"),
            hex!("00000000 04050607 08090a0b 0c0d0e0f"),
            hex!("00110211 04050607 08090a0b 0c0d0e0f"),
            hex!("00000000 04050607 08090a0b 0c0d0e0f"),
            hex!("00110211 04050607 08090a0b 0c0d0e0f"),
            hex!("00000000 04050607 08090a0b 0c0d0e0f"),
            hex!("00110211 04050607 08090a0b 0c0d0e0f"),
            hex!("00110211 04050607 08090a0b 0c0d0e0f"),
        ];
        let res = hash.hash_all_onto_u32(&mut input);
        println!("{res:b}");
        assert_eq!(
            res,
            0b1101_0101_0101_0101,
        );
    }
}
