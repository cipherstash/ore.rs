pub mod prng;
use crate::primitives::prp::prng::AES128PRNG;
use zeroize::Zeroize;

fn cmp(a: u8, b: u8) -> u8 {
    if a > b {
        1u8
    } else {
        0u8
    }
}

// FIXME: To get this right, we need to change the "Left" type to be a Vec
pub(crate) fn block_shuffle(key: &[u8], forward_target: u8) -> (u8, Vec<u8>) {
    let mut input = [0u8; 256];
    for i in 0..=255 {
        input[i] = i as u8;
    }

    // 96 is the number of pre-generated AES blocks
    // Performance tuned to minimize the need for regeneration
    let mut rng: AES128PRNG<96> = AES128PRNG::init(key); // TODO: Use Result type here, too

    // Knuth Shuffle
    (0..=255usize).into_iter().rev().for_each(|i| {
        let j = rng.gen_range(i as u8);
        input.swap(i, j as usize);
    });

    // Generate permuted comparison bits
    let block: Vec<u8> = input
        .chunks(8)
        .map(|chunk| {
            let mut out: u8 = 0;
            // Build a u8
            for &jstar in chunk[1..].iter().rev() {
                out |= cmp(jstar, forward_target);
                out <<= 1;
            }
            out | cmp(chunk[0], forward_target)
        })
        .collect();

    // Find the permutation of target in constant time
    let mut forward_permuted = None;
    for (index, val) in input.iter().enumerate() {
        match forward_permuted {
            None => {
                if (*val as u8) == forward_target {
                    forward_permuted = Some(index as u8)
                }
            }
            _ => (),
        };
    }

    input.zeroize();

    (forward_permuted.unwrap(), block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_block_shuffle() {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0eaa");

        let (permuted, _) = block_shuffle(&key, 10);
        assert_eq!(170, permuted);
    }
}
