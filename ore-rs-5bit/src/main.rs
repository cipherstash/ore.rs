use hex_literal::hex;
use ore_rs_5bit::Ore5BitChaCha20;
use formats::CipherText;

// TODO: Revise the Main ORE traits
// TODO: Add PartialOrd implementations for CipherText variants

fn main() {
    let k1 = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let k2 = hex!("d0d007a5 3f9a6848 83bc1f21 0f6595a3");

    let a = vec![7, 10, 2];
    let b = vec![7, 6, 1];
    let ore = Ore5BitChaCha20::init(&k1, &k2).unwrap();
    let left = ore.encrypt_left(&a);
    let combined = ore.encrypt(&b);
    println!("Left encrypt: [{} bytes] {}", left.len(), hex::encode(&left));
    println!("Combined    : [{} bytes] {}", left.len(), hex::encode(&combined));
    
    // TODO:
    // Can we use a derive macro for types to implement LeftCipherTextBlock and RightCipherTextBlock
    // Also, those names are very long
    // * I think we only need the forward PRP now
    // * Could the test failures be due to the changes I made to prefix generation?
    // TODO: Tests and benchmarks
    // TODO: create a plaintext trait for the ORE trait methods
    // For the 5-bit scheme, create a U5/Packed variant
    // TODO: Consider using Heapless https://docs.rs/heapless/0.7.16/heapless/
    // Input would need to be done in batches (let SIMD width help us decide).
    // TODO: Try a SIMD PRP
    dbg!(Ore5BitChaCha20::compare_slices(&left, &combined));
    //println!("{}, {}, {}", left.len(), right.len(), hex::encode(right));
}