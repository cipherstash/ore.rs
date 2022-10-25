use sha2::{Digest, Sha256};
use super::Hash;

pub struct Sha256Z2Hash {

}

impl Sha256Z2Hash {
    pub fn new() -> Self {
        Self {}
    }
}

impl Hash for Sha256Z2Hash {
    fn hash(&self, data: &[u8]) -> u8 {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result: Vec<u8> = hasher.finalize().to_vec();
        println!("VEC {:?}", result);
        result[0] & 1u8
    }

    fn hash_all(&self, input: &mut [super::AesBlock]) -> Vec<u8> {
        input.iter().map(|f| {
            self.hash(f)
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_case_1() {
        let hash = Sha256Z2Hash::new();
        let input: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        assert_eq!(0u8, hash.hash(&input));
    }
}
