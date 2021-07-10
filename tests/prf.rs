use small_prp::prf::Prf;
use hex_literal::hex;

#[test]
fn prf_encrypt() {
    let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let prf = Prf::init(&key);

    let mut output: [u8; 16] = [0u8; 16];
    output[0] = 10;
    prf.encrypt(&mut output);

    assert_eq!(output, hex!("0d1933062742fe018cfe06e1a81aa001"));
}

// TODO: Add tests for the different valid block sizes
