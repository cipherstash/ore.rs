use small_prp::Prp;
use small_prp::prng::Prng;

#[test]
fn init_prp() {
    let key: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let mut prg = Prng::init(&key);
    let prp = Prp::init(&mut prg);

    // TODO: Test all numbers in the block
    println!("15 -> {}", prp.permute(15));
    println!("75 -> {}", prp.permute(75));
    assert_eq!(15, prp.inverse(prp.permute(15)));
}

