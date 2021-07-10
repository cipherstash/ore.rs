
mod ore_large;
use ore_large::OreLarge;
use hex_literal::hex;

fn main() {
    let prf_key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let prp_key: [u8; 16] = hex!("d0d007a5 3f9a6848 83bc1f21 0f6595a3");

    let ore = OreLarge::init(prf_key, prp_key);
    ore.encrypt_left(100);
}
