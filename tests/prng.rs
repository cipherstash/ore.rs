use small_prp::prp::prng::Prng;
use hex_literal::hex;

#[test]
fn prg_next_byte() {
    let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");

    let mut prg = Prng::init(&key);
    assert_eq!(198, prg.next_byte());
    assert_eq!(115, prg.next_byte());
}

