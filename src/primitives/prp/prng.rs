use aes::cipher::{consts::U16, generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use zeroize::Zeroize;

/* Struct representing a PRNG based on AES in counter mode.
 * For performance, P blocks of AES are generated a time using AES pipelining.
 * Careful tuning of P can avoid multiple calls to generate (see `gen_range` for more info).
 */
pub struct AES128PRNG<const P: usize = 32> {
    cipher: Aes128,
    data: [GenericArray<u8, U16>; P],
    ptr: (usize, usize), // ptr to block and byte within block
    pub ctr: u32,        // increments with each new encryption
    pub used: u32,
}

impl Zeroize for AES128PRNG {
    fn zeroize(&mut self) {
        for d in self.data.iter_mut() {
            d.as_mut_slice().zeroize();
        }
    }
}

impl<const P: usize> AES128PRNG<P> {
    pub fn init(key: &[u8]) -> Self {
        let key_array = GenericArray::from_slice(key);
        let cipher = Aes128::new(key_array);
        let mut prng = Self {
            cipher,
            data: [GenericArray::<u8, U16>::default(); P],
            ctr: 0,
            ptr: (0, 0),
            used: 0,
        };
        prng.generate();
        prng
    }

    /*
     * Generates the next byte of the random number sequence.
     */
    pub fn next_byte(&mut self) -> u8 {
        debug_assert!(self.ptr.0 < P && self.ptr.1 < 16);
        let value: u8 = self.data[self.ptr.0][self.ptr.1];
        self.inc_ptr();
        self.used += 1;
        value
    }

    /*
     * Find a uniform random number between 0 and (including) max.
     * 
     * This function calls `next_byte` to sample an 8-bit random value
     * and uses the modulo of the max value to find a random number in the target range.
     * Rejection sampling is used to avoid modulo bias by finding the largest multiple of max
     * that is less than 255. If no such multiple is found (i.e for numbers 128 or greater),
     * rejection sampling is used alone until a suitable random number is generated.
     * 
     * This approach minimizes the number of rejections required and also generates
     * random numbers with good uniformity, including for small values of max.
     * 
     * Calling this function with a max of 0 will return 0.
     */
    pub fn gen_range(&mut self, max: u8) -> u8 {
        if max < 1 {
            return max;
        }

        let mut target: Option<u8> = None;

        // Find the largest multiple of max that is less than 255
        if max < 128 {
            target = Some(255u8.div_floor(max));
        }
        loop {
            let candidate = self.next_byte();

            // Divide candidate in Z_max where t is an integer multiple of max
            // We wish to use the largest possible value of t to maximize entropy
            // and ensure decent levels of uniformity for small max values
            if let Some(t) = target {
                if candidate < t * max {
                    return candidate % max;
                }
            } else if candidate <= max {
                return candidate;
            }
        }
    }

    fn generate(&mut self) {
        self.ptr = (0, 0);
        for i in 0..P {
            // Counter
            self.data[i][0..4].copy_from_slice(&self.ctr.to_be_bytes());
            self.ctr += 1;
        }
        self.cipher.encrypt_blocks(&mut self.data);
    }

    #[inline]
    fn inc_ptr(&mut self) {
        if self.ptr == (P - 1, 15) {
            self.generate();
        }
        if self.ptr.1 < 15 {
            self.ptr.1 += 1;
        } else {
            self.ptr.1 = 0;
            self.ptr.0 += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use rand::{thread_rng, Rng};
    use std::collections::HashMap;

    fn init_prng() -> AES128PRNG {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");

        AES128PRNG::init(&key)
    }

    #[test]
    fn prg_next_byte() {
        let mut prg = init_prng();
        assert_eq!(198, prg.next_byte());
        assert_eq!(161, prg.next_byte());

        for _i in 3..=255 {
            prg.next_byte();
        }
        assert_eq!((15, 15), prg.ptr);
    }

    #[test]
    fn prg_many_generations() {
        let mut prg = init_prng();

        /* Ask for enough bytes that more data needs to be generated */
        for _i in 0..=100_000 {
            prg.next_byte();
        }
    }

    #[test]
    fn uniformity() {
        // Test uniformity of the PRNG for all possible values of max
        // by calculation of the Root-Mean-Square Error (RMSE)
        // and asserting that it remains below some arbitrary threshold
        let mut key = [0u8; 16];
        thread_rng().try_fill(&mut key).unwrap();

        let mut rng: AES128PRNG<96> = AES128PRNG::init(&key);

        // Test count per max value
        let n = 100_000i32;

        for k in 1..=255 {
            let mut hist: HashMap<u8, usize> = HashMap::new();

            for _i in 0..n {
                let v = rng.gen_range(k);

                match hist.get(&v) {
                    Some(count) => hist.insert(v, count + 1),
                    None => hist.insert(v, 1),
                };
            }

            let mut sum: f64 = 0.0;

            for (_key, count) in hist.iter() {
                sum += (*count as f64 - (n as f64 / k as f64)).powf(2.0);
            }

            // RMSE within 0.5%
            assert!((sum.sqrt() as i32) < 500);
        }
    }
}
