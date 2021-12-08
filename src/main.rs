
use ore::{
    scheme::bit2::OREAES128,
    OREEncrypt,
    ORECipher,
    CipherText
};
use hex_literal::hex;

fn main() {
    let k1: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let k2: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let seed = hex!("00010203 04050607");

    let mut ore: OREAES128 = ORECipher::init(k1, k2, &seed).unwrap();

    let cta = 1u64.encrypt(&mut ore).unwrap();
    let ctb = 50u64.encrypt(&mut ore).unwrap();
    println!("1 > 50 = {}", cta > ctb);

    let bytes = cta.to_bytes();
    let _ct = CipherText::<OREAES128, 8>::from_bytes(&bytes).unwrap();
}
