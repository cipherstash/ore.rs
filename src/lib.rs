
//pub mod prng;
pub mod prp;
pub mod prf;
//use prng::Prng;
use prp::Prp;
use prf::Prf;

use rand;
use rand::{Rng};
use rand::os::{OsRng};

pub struct Ore {
    prf: Prf,
    prp: Prp,
    // OsRng uses /dev/urandom but we may want to look at
    // ChaCha20 rng and HC128
    rng: OsRng
}

fn cmp(a: u8, b: u8) -> u8 {
    if a > b {
        return 1;
    } else {
        return 0;
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

        for i in 0..=255 {
            let ii = self.prp.inverse(i);
            let indicator = cmp(ii, input);
            // prf(i) - we could probably do this in blocks of 8 using Aes crate
            let mut tmp: [u8; 16] = [0u8; 16];
            self.prf.encrypt(i, &mut tmp);
            // Next: keyed hash (Random oracle) of the prf values
            // Use AES with the nonce as the Key
            // Once again can probably be done in chunks

        }
        return output;
    }
}
