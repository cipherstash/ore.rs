use hex_literal::hex;
use ore_rs_5bit::{Ore5BitChaCha20, cmac, packing::packed_prefixes};

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
    let input: u32 = 0b11010101_10101010_11001100_00110011;
    let permutation: [usize; 32] = [
        31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16,
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
    ];

    let output = permute_u32(input, &permutation);
    println!("Input: {:032b}", input);
    println!("Output: {:032b}", output);
}

/*
fn main() {
    let k1 = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let k2 = hex!("d0d007a5 3f9a6848 83bc1f21 0f6595a3");

    let input = vec![7, 23, 30, 2, 13, 6];
    let ore = Ore5BitChaCha20::init(&k1, &k2).unwrap();
    let o = ore.encrypt_left(&input);
    println!("{}", hex::encode(o));
}*/