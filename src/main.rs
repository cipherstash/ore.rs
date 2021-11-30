
use ore::{bit2::OREAES128, OREEncrypt, ORECipher};
use hex_literal::hex;

fn main() {
    let k1: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let k2: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let seed = hex!("00010203 04050607");

    //let x: u64 = 37;

    let mut ore: OREAES128 = ORECipher::init(k1, k2, &seed).unwrap();
    //println!("LEFT = {:?}", x.encrypt_left(&mut ore).unwrap());
    //println!("FULL = {:?}", x.encrypt(&mut ore).unwrap());

    let cta = 47u64.encrypt(&mut ore).unwrap();
    let ctb = 50u64.encrypt(&mut ore).unwrap();

    println!("FULL = {:?}", cta);

    println!("CMP = {}", cta < ctb);
}
