
use ore_rs::{
    scheme::bit2::OREAES128,
    OREEncrypt,
    ORECipher,
};
use hex_literal::hex;

fn main() {
    let k1: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let k2: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let k3: [u8; 16] = hex!("04050607 08090a0b 0c0d0e0f 11111111");
    let seed = hex!("00010203 04050607");

    let mut ore1: OREAES128 = ORECipher::init(k1, k2, &seed).unwrap();
    let mut ore2: OREAES128 = ORECipher::init(k3, k2, &seed).unwrap();

    let cta = 0u32.encrypt(&mut ore1).unwrap();
    let ctb = 0u32.encrypt(&mut ore2).unwrap();


    let bytes1 = cta.to_bytes();
    let bytes2 = ctb.to_bytes();
    println!("BY1 {:?}\n\n", bytes1);
    println!("BY2 {:?}\n\n", bytes2);
    println!("RET = {:?}", OREAES128::compare_raw_slices(&bytes1, &bytes2));
}
