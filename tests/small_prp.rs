use small_prp::Prp;
use small_prp::prng::Prng;
use hex_literal::hex;

#[test]
fn init_prp() {
    let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");

    let mut prg = Prng::init(&key);
    let prp = Prp::init(&mut prg);

    // TODO: Test all numbers in the block
    println!("15 -> {}", prp.permute(15));
    println!("75 -> {}", prp.permute(75));
    assert_eq!(15, prp.inverse(prp.permute(15)));
}

