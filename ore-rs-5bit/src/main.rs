use hex_literal::hex;
use ore_rs_5bit::{Ore5BitChaCha20, packing::packed_prefixes};

fn permute_u32(input: u32, perm: &[usize; 32]) -> u32 {
    let mut output: u32 = 0;

    for (i, &p) in perm.iter().enumerate() {
        // Extract the bit from the input value at the index specified by the permutation array
        let bit = (input >> p) & 1;

        // Set the bit in the output value at the corresponding index
        output |= bit << i;
    }

    output
}

fn main() {
    let k1 = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let k2 = hex!("d0d007a5 3f9a6848 83bc1f21 0f6595a3");

    let input = vec![7, 23, 30, 2];
    let ore = Ore5BitChaCha20::init(&k1, &k2).unwrap();
    let left = ore.encrypt_left(&input);
    println!("Left encrypt: {}", hex::encode(&left));
    //println!("{}, {}, {}", left.len(), right.len(), hex::encode(right));
}