
use small_prp::ore_large::OreLarge;
use aes::cipher::generic_array::arr;

fn main() {
    let prf_key = arr![u8; 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let prp_key = arr![u8; 0xd0, 0xd0, 0x07, 0xa5, 0x3f, 0x9a, 0x68, 0x48, 0x83, 0xbc, 0x1f, 0x21, 0x0f, 0x65, 0x95, 0xa3];

    let mut ore = OreLarge::init(prf_key, prp_key);
    /*let ct2 = ore.encrypt(18);
    let ct3 = ore.encrypt(15);
    println!("COMPARE = {} should be 1", OreLarge::compare(&ct2, &ct3));*/

    println!("------");

    //let ct4 = ore.encrypt(7061644215716937728);
    //let ct4 = ore.encrypt(7133701809754865663);
    let ct5 = ore.encrypt(7);
    println!("OUT = {:?}", ct5);
    //println!("COMPARE = {} should be 1", OreLarge::compare(&ct4, &ct5));
}
