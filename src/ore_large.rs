
use small_prp::prp::Prp;
use small_prp::prf::Prf;

use rand;
use rand::{Rng};
use rand::os::{OsRng};

use byteorder::{ByteOrder, BigEndian};

pub struct OreLarge {
    prf: Prf,
    prp: Prp,
    // OsRng uses /dev/urandom but we may want to look at
    // ChaCha20 rng and HC128
    rng: OsRng
}

const LEFT_CHUNK_SIZE: usize = 17;

type Left = [u8; LEFT_CHUNK_SIZE * 8]; // 1 small-domain block times the number of blocks
type Right = [u8; 48];

pub struct CipherText {
    left: Left,
    right: Right
}

type Key = [u8; 16];

trait Initialise {
    fn init() -> Self;
}

impl Initialise for Left {
    fn init() -> Self {
        [0u8; LEFT_CHUNK_SIZE * 8]
    }
}

impl Initialise for Right {
    fn init() -> Self {
        [0u8; 48]
    }
}

fn cmp(a: u8, b: u8) -> u128 {
    if a > b {
        return 1u128;
    } else {
        return 0u128;
    }
}

impl OreLarge {

    pub fn init(prf_key: Key, prp_key: Key) -> OreLarge {
      return Self {
          prf: Prf::init(&prf_key),
          prp: Prp::init(&prp_key),
          rng: OsRng::new().unwrap() // TODO: Don't use unwrap
      }
    }

    pub fn encrypt_left(&self, input: u64) -> Left {
        let mut x_prp_key: Key = [0u8; 16];
        let mut output = Left::init();

        for n in 0..7 {
            BigEndian::write_uint(&mut x_prp_key, input, n + 1);
            let xi: u8 = x_prp_key[n];
            // TODO: This prf should be k2
            self.prf.encrypt(&mut x_prp_key);

            let position = n * LEFT_CHUNK_SIZE;
            //let mut chunk = left_chunk(&mut output, n); // FIXME: Not sure why this doesn't work
            BigEndian::write_uint(&mut output[position..(position + LEFT_CHUNK_SIZE)], input, n + 1);

            let prp = Prp::init(&x_prp_key);
            let xip = prp.permute(xi);
            // ui = (F(k1, x_{i-1} || xip) xip)
            output[position + n + 1] = xip;
            output[position + LEFT_CHUNK_SIZE] = xip;
            // TODO: this prf should be k1
            self.prf.encrypt(&mut output[position..n + 1]);
        }

        return output;
    }

    pub fn encrypt_right(&self, input: u64) -> Right {
        return Right::init();
    }

}

#[inline]
fn left_chunk(left: &Left, index: usize) -> &[u8] {
    let position = index * LEFT_CHUNK_SIZE;
    return &left[position..(position + LEFT_CHUNK_SIZE)];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_left_chunk() {
        let left: Left = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
            5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
            6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
            7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7
        ];

        assert_eq!(left_chunk(&left, 0), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(left_chunk(&left, 1), [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
        assert_eq!(left_chunk(&left, 7), [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]);
        // TODO: How should we handle this?
        //assert_eq!(left_chunk(&left, 8), []);
    }
}
