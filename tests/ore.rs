use small_prp::Ore;
use hex_literal::hex;

#[test]
#[ignore]
fn init_ore() {
    let prf_key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let prp_key: [u8; 16] = hex!("d0d007a5 3f9a6848 83bc1f21 0f6595a3");
    let ore = Ore::init(prf_key, prp_key);

    assert_eq!(1, 1);
}

#[test]
fn encrypt_left() {
    let prf_key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let prp_key: [u8; 16] = hex!("d0d007a5 3f9a6848 83bc1f21 0f6595a3");
    let ore = Ore::init(prf_key, prp_key);

    let left: [u8; 17] = ore.encrypt_left(10);
  
    assert_eq!(left, hex!("d41f92006e5a48c20022f08b56001bb176"));
}

#[test]
fn encrypt_right() {
    let prf_key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let prp_key: [u8; 16] = hex!("d0d007a5 3f9a6848 83bc1f21 0f6595a3");
    let mut ore = Ore::init(prf_key, prp_key);

    let right: [u8; 48] = ore.encrypt_right(170);
  
    assert_eq!(right, hex!("4754573e35422d904e187e411e8a1222a51404b1605604d32a9f0f7dd10b20524a2d866e48342067a3d7aa2361c178f3"));
}

