use hex_literal::hex;
use ore_rs_5bit::Ore5BitChaCha20;

// TODO: Revise the Main ORE traits
// TODO: Add PartialOrd implementations for CipherText variants

fn main() {
    let k1 = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let k2 = hex!("d0d007a5 3f9a6848 83bc1f21 0f6595a3");

    let a = vec![7, 1];
    let b = vec![7, 2];
    let ore = Ore5BitChaCha20::init(&k1, &k2).unwrap();
    let left = ore.encrypt_left(&a);
    let combined = ore.encrypt(&b);
    println!("Left encrypt: {}", hex::encode(&left));
    println!("Combines    : {}", hex::encode(&combined));
    
    // TODO:
    // Can we use a derive macro for types to implement LeftCipherTextBlock and RightCipherTextBlock
    // Also, those names are very long
    dbg!(Ore5BitChaCha20::compare_slices(&left, &combined));
    //println!("{}, {}, {}", left.len(), right.len(), hex::encode(right));
}