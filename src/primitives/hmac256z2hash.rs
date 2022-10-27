use super::Hash;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/* This module uses AES in GCM mode as a Random-Oracle.
 * While GCM mode may seem uneccessary, it is common in target
 * systems where ECB is increasingly less-so (for good reason!).
*/
#[derive(Debug)]
pub struct HmacSha256Z2Hash {
    key: super::HashKey
}

impl Hash for HmacSha256Z2Hash {
    fn new(key: &super::HashKey) -> Self {
        Self { key: *key }
    }

    fn hash(&self, data: &[u8]) -> u8 {
        let mut cipher = Hmac::<Sha256>::new_from_slice(&self.key).unwrap(); // TODO: Make new return a result
        cipher.update(data);
        let ret = cipher.finalize().into_bytes()[0];
        ret & 1u8
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
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        let hash = HmacSha256Z2Hash::new(&key.into());
        let input: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        assert_eq!(1u8, hash.hash(&input));
    }
}
