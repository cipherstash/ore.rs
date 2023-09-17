use hex_literal::hex;
use ore_rs::{scheme::bit2::OreAes128ChaCha20, OreCipher, OreEncrypt, OreOutput};

fn main() {
    let k1 = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let k2 = hex!("d0d007a5 3f9a6848 83bc1f21 0f6595a3");

    let ore: OreAes128ChaCha20 = OreCipher::init(&k1, &k2).unwrap();

    let i = 10000u64;
    let x_u64 = i.encrypt(&ore).unwrap().to_bytes();
    println!("CT = {};", hex::encode(&x_u64));
}
