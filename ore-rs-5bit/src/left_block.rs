use std::{cmp::Ordering, ops::BitAnd};
use formats::{CipherTextBlock, DataWithHeader, LeftBlockEq, LeftCipherTextBlock, OreBlockOrd};
use primitives::{hash::Aes128Z2Hash, Hash};
use subtle_ng::ConstantTimeEq;
use crate::right_block::RightBlock;

// TODO: We could make the array a reference
// That way we can encrypt it externally but just pass the prefix to an init function
#[derive(Debug)]
pub struct LeftBlock(pub(super) [u8; 16], pub(super) u8);


impl<'a> CipherTextBlock<'a> for LeftBlock {
    fn byte_size() -> usize {
        17
    }

    fn extend_into(&self, out: &mut DataWithHeader) {
        out.extend_from_slice(&self.0);
        out.extend([self.1]);
    }
}


impl<'a> LeftBlockEq<'a, LeftBlock> for LeftBlock {
    fn constant_eq(&self, other: &Self) -> subtle_ng::Choice {
        self.0.ct_eq(&other.0).bitand(self.1.ct_eq(&other.1))
    }
}

impl<'a> OreBlockOrd<'a, RightBlock> for LeftBlock {
    // FIXME: Nonce *must* be 16-bytes
    fn ore_compare(&self, nonce: &[u8], right: &RightBlock) -> Ordering {
        // TODO: This would be cleaner if we defined a method on RightBlock
        let hasher: Aes128Z2Hash = Hash::new(nonce.into());
        // TODO: Use conditional_select
        //if ((right << self.1) as u8 & 1u8) ^ hasher.hash(&self.0) == 1 {
        let mask = hasher.hash(&self.0);
        if (right.get_bit(self.1) ^ mask) == 1 {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    }
}

// TODO: Derive macro?
impl<'a> LeftCipherTextBlock<'a> for LeftBlock {}


impl From<&[u8]> for LeftBlock {
    fn from(value: &[u8]) -> Self {
        assert!(value.len() == Self::byte_size());
        let mut buf: [u8; 16] = Default::default();
        buf.copy_from_slice(&value[0..16]);
        LeftBlock(buf, value[16])
    }
}

#[cfg(test)]
mod tests {
    use primitives::{NewPrp, KnuthShuffleGenerator, PrpGenerator};
    use rand::{thread_rng, Fill};
    use super::*;

    #[test]
    fn test_ore_compare_block() {
        let mut rng = thread_rng();
        let mut prefix: [u8; 16] = Default::default();
        let mut nonce: [u8; 16] = Default::default();
        //prefix.try_fill(&mut rng).unwrap();
        nonce.try_fill(&mut rng).unwrap();
        let prp: NewPrp<u8, 32> = KnuthShuffleGenerator::new(&prefix).generate();
        let mut right = RightBlock::init(10).shuffle(&prp);

        let mut ro_keys: [[u8; 16]; 32] = Default::default();
            
        for (j, ro_key) in ro_keys.iter_mut().enumerate() {
            ro_key.copy_from_slice(&prefix);
            ro_key[15] = j as u8;
        }
        let hasher: Aes128Z2Hash = Hash::new(&nonce.into());
        //self.prf1.encrypt_all(&mut ro_keys);
        let mask = hasher.hash_all_onto_u32(&ro_keys);

        println!("MASK: {mask:b}");
        println!("PERMUTE plaintext 10 becomes {}", prp.inverse_permute(10u8));
        println!("PERMUTE plaintext 5 becomes {}", prp.inverse_permute(5u8));
        println!("PERMUTE plaintext 24 becomes {}", prp.inverse_permute(24u8));

        right ^= mask;

        assert_eq!(
            LeftBlock(
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, prp.inverse_permute(10u8)],
                prp.inverse_permute(10u8)
            ).ore_compare(&nonce, &right),
            Ordering::Greater
        );

        assert_eq!(
            LeftBlock(
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, prp.inverse_permute(5u8)],
                prp.inverse_permute(5u8)
            ).ore_compare(&nonce, &right),
            Ordering::Less
        );
        
        assert_eq!(
            LeftBlock(
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, prp.inverse_permute(24u8)],
                prp.inverse_permute(24u8)
            ).ore_compare(&nonce, &right),
            Ordering::Greater
        );
    }
}