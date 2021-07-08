
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

type Left = [u8; 17];
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
        [0u8; 17]
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

impl Ore {

    pub fn init(prf_key: Key, prp_key: Key) -> Ore {
      return Ore {
          prf: Prf::init(&prf_key),
          prp: Prp::init(&prp_key),
          rng: OsRng::new().unwrap() // TODO: Don't use unwrap
      }
    }

    pub fn encrypt(&mut self, input: u8) -> CipherText {
        CipherText {
            left: self.encrypt_left(input),
            right: self.encrypt_right(input)
        }
    }

    pub fn encrypt_left(&self, input: u8) -> Left {
        let px: u8 = self.prp.permute(input);
        let mut output = Left::init();
        self.prf.encrypt(px, &mut output[0..16]);
        output[16] = px;
        return output;
    }

    pub fn encrypt_right(&mut self, input: u8) -> Right {
        let mut output = Right::init();
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

    pub fn compare(self, a: CipherText, b: CipherText) -> i8 {
        if a.left == b.left {
            return 0;
        }
        let h: u8 = a.left[16];
        if h < 128 {
            // TODO: Can we define these slices as macros or a type or something?
            // Even better - define types for left and right and use (inline) functions
            // This is an get_bit function (make it an inline func)
            let vh = (BigEndian::read_u128(&b.right[16..32]) & (1 << h)) >> h;
            println!("In small, vh = {}", vh);

            if hash::hash(&a.left[0..16], &b.right[0..16]) ^ vh == 1 {
                return 1;
            } else {
                return -1;
            }
        } else {
            let vh = (BigEndian::read_u128(&b.right[32..48]) & (1 << h)) >> h;
            println!("In large, vh = {}", vh);

            if hash::hash(&a.left[0..16], &b.right[0..16]) ^ vh == 1 {
                return 1;
            } else {
                return -1;
            }

        }
    }
}
