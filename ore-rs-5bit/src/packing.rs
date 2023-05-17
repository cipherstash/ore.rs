use bit_vec::BitVec;
use primitives::prf::PrfBlock;


pub fn prefixes(slice: &[u8]) -> Vec<PrfBlock> {
    let mut prefixes: Vec<PrfBlock> = Vec::with_capacity(slice.len());
    for i in 0..slice.len() {
        let mut fblock: PrfBlock = Default::default();
        fblock[0..i].copy_from_slice(&slice[0..i]);
        prefixes.push(fblock);
    }

    prefixes
}

// TODO: Probably more efficient to code by hand
// Or use bitvec or bitvec-simd
// TODO: Also include the index (like in the original implementation)
pub fn packed_prefixes(slice: &[u8]) -> Vec<PrfBlock> {
    let mut bit_vec = BitVec::new();
    let mut prefixes: Vec<PrfBlock> = Vec::with_capacity((slice.len() * 8 / 5) + 1);
    for &value in slice {
        let mut fblock: PrfBlock = Default::default();
        for i in 0..5 {
            bit_vec.push(value & (1 << i) != 0);
        }
        let bytes = bit_vec.to_bytes();
        fblock[0..bytes.len()].copy_from_slice(&bytes);
        prefixes.push(fblock);
    }
    prefixes
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_unpack() {
        let input = vec![7, 23, 30, 2, 19, 1];
        let packed = packed_prefixes(&input);
        println!("Prefixes: {:?}", packed);

        assert!(false);
        //assert_eq!(input, unpack_u8_slice_bitvec(&packed, input.len()));
    }

    fn unpack_u8_slice_bitvec(packed: &[u8], count: usize) -> Vec<u8> {
        let bit_vec = BitVec::from_bytes(packed);
        let mut unpacked = Vec::with_capacity(count);
    
        for i in 0..count {
            let mut value = 0u8;
            for j in 0..5 {
                if bit_vec[i * 5 + j] {
                    value |= 1 << j;
                }
            }
            unpacked.push(value);
        }
    
        unpacked
    }
}

