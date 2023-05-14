use hex_literal::hex;
use ore_rs_5bit::Ore5BitChaCha20;

fn main() {
    let k1 = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let k2 = hex!("d0d007a5 3f9a6848 83bc1f21 0f6595a3");

    let input = vec![7];
    let ore = Ore5BitChaCha20::init(&k1, &k2).unwrap();
    let left = ore.encrypt_left(&input);
    let (l1, r) = ore.encrypt(&input);
    println!("Left encrypt: {}", hex::encode(&left));
    println!("Left encrypt: {}", hex::encode(&l1));
    //println!("{}, {}, {}", left.len(), right.len(), hex::encode(right));
}