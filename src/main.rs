
mod ore_large;
mod prf;
use ore_large::OreLarge;
use hex_literal::hex;

// TODO: Create type aliases inside the PRF module
use aes::{Aes128, Block};
use aes::cipher::generic_array::arr;

fn main() {
    let prf_key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let prp_key: [u8; 16] = hex!("d0d007a5 3f9a6848 83bc1f21 0f6595a3");

    let key = arr![u8; 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let mut block = Default::default();

    prf::aes_prf(&key, &mut block);

    println!("block = {}", block[0]);

    //let ore = OreLarge::init(prf_key, prp_key);
    //ore.encrypt_left(100);
}
