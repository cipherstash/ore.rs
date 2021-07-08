
//pub mod prng;
pub mod prp;
pub mod prf;
mod hash;
//use prng::Prng;
use prp::Prp;
use prf::Prf;

use rand;
use rand::{Rng};
use rand::os::{OsRng};

use byteorder::{ByteOrder, BigEndian};

pub struct Ore {
    prf: Prf,
    prp: Prp,
    // OsRng uses /dev/urandom but we may want to look at
    // ChaCha20 rng and HC128
    rng: OsRng
}

fn cmp(a: u8, b: u8) -> u128 {
    if a > b {
        return 1u128;
    } else {
        return 0u128;
    }
}

impl Ore {

    pub fn init(prf_key: [u8; 16], prp_key: [u8; 16]) -> Ore {
      return Ore {
          prf: Prf::init(&prf_key),
          prp: Prp::init(&prp_key),
          rng: OsRng::new().unwrap()
      }
    }

    pub fn encrypt_left(&self, input: u8) -> [u8; 17] {
        let px: u8 = self.prp.permute(input);
        let mut output: [u8; 17] = [0u8; 17];
        self.prf.encrypt(px, &mut output[0..16]);
        output[16] = px;
        return output;
    }

    pub fn encrypt_right(&mut self, input: u8) -> [u8; 48] {
        let mut output: [u8; 48] = [0u8; 48];
        // Generate a 16-byte random nonce
        self.rng.fill_bytes(&mut output[0..16]);

        let mut word: u128 = 0;

        // Low-order word
        for i in 0..=127 {
            let ii = self.prp.inverse(i);
            let indicator: u128 = cmp(ii, input);
            // prf(i) - we could probably do this in blocks of 8 using Aes crate
            let mut ro_key: [u8; 16] = [0u8; 16];
            self.prf.encrypt(i, &mut ro_key);
            let h = hash::hash(&ro_key, &output[0..16]);
            let bit: u128 = (indicator ^ h) << i;
            word |= bit;
        }

        BigEndian::write_u128(&mut output[16..32], word);

        word = 0;

        // Low-order word
        for i in 0..=127 {
            let ii = self.prp.inverse(i);
            let indicator: u128 = cmp(ii, input);
            // prf(i) - we could probably do this in blocks of 8 using Aes crate
            let mut ro_key: [u8; 16] = [0u8; 16];
            self.prf.encrypt(i, &mut ro_key);
            let h = hash::hash(&ro_key, &output[0..16]);
            let bit: u128 = (indicator ^ h) << i;
            word |= bit;
        }

        BigEndian::write_u128(&mut output[32..48], word);

        return output;
    }

    pub fn compare(self, a: ([u8; 17], [u8; 48]), b: ([u8; 17], [u8; 48])) -> i8 {
        if a.0 == b.0 {
            return 0;
        }
        let h: u8 = a.0[16];
        if h < 128 {
            // TODO: Can we define these slices as macros or a type or something?
            // Even better - define types for left and right and use (inline) functions
            // This is an get_bit function (make it an inline func)
            let vh = (BigEndian::read_u128(&b.1[16..32]) & (1 << h)) >> h;
            println!("In small, vh = {}", vh);

            if hash::hash(&a.0[0..16], &b.1[0..16]) ^ vh == 1 {
                return 1;
            } else {
                return -1;
            }
        } else {
            let vh = (BigEndian::read_u128(&b.1[32..48]) & (1 << h)) >> h;
            println!("In large, vh = {}", vh);

            if hash::hash(&a.0[0..16], &b.1[0..16]) ^ vh == 1 {
                return 1;
            } else {
                return -1;
            }

        }
    }
}
