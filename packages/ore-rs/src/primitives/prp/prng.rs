use aes::cipher::{consts::U16, generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub struct Aes128Prng {
    cipher: Aes128,
    data: [GenericArray<u8, U16>; 16],
    ptr: (usize, usize), // ptr to block and byte within block
    ctr: u32,            // increments with each new encryption
}

impl Zeroize for Aes128Prng {
    fn zeroize(&mut self) {
        for d in self.data.iter_mut() {
            d.as_mut_slice().zeroize();
        }
        // Also clear the keystream position/counter state (ZA-0001).
        self.ptr.0.zeroize();
        self.ptr.1.zeroize();
        self.ctr.zeroize();
    }
}

// `Aes128Prng` is built per-block inside the PRP and dropped without an
// explicit `zeroize()` call, so its key-derived keystream (`data`) must be
// wiped on drop (ZA-0001). The `cipher` field's AES key schedule is already
// wiped by the `aes` crate's own `ZeroizeOnDrop` (the `zeroize` feature) when
// it drops after this. As with `KnuthShufflePRP`, the `ZeroizeOnDrop` derive
// does not apply cleanly here, so impl `Drop` manually and assert the marker.
impl Drop for Aes128Prng {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Aes128Prng {}

/*
 * To aid in performance this PRNG can only generate 256 random numbers
 * before it panics. Should _only_ be used inside the PRP.
 */
impl Aes128Prng {
    pub fn init(key: &[u8]) -> Self {
        let key_array = GenericArray::from_slice(key);
        let cipher = Aes128::new(key_array);
        let mut prng = Self {
            cipher,
            data: Default::default(),
            ctr: 0,
            ptr: (0, 0),
        };
        prng.generate();
        prng
    }

    /*
     * Generates the next byte of the random number sequence.
     */
    pub fn next_byte(&mut self) -> u8 {
        debug_assert!(self.ptr.0 < 16 && self.ptr.1 < 16);
        let value: u8 = self.data[self.ptr.0][self.ptr.1];
        self.inc_ptr();
        value
    }

    /* Find a uniform random number up to and including max */
    pub fn gen_range(&mut self, max: u8) -> u8 {
        loop {
            let candidate = self.next_byte();

            // If next_byte is less than the max we return
            if candidate <= max {
                return candidate;
            }
        }
    }

    fn generate(&mut self) {
        self.ptr = (0, 0);
        for i in 0..16 {
            // Counter
            self.data[i][0..4].copy_from_slice(&self.ctr.to_be_bytes());
            self.ctr += 1;
        }
        self.cipher.encrypt_blocks(&mut self.data);
    }

    #[inline]
    fn inc_ptr(&mut self) {
        if self.ptr == (15, 15) {
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

    fn init_prng() -> Aes128Prng {
        let key: [u8; 16] = hex!("00010203 04050607 08090a0b 0c0d0e0f");

        Aes128Prng::init(&key)
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

    // ZA-0001 regression: `zeroize()` must wipe the key-derived keystream
    // *and* the position/counter state, and the type must be `ZeroizeOnDrop`
    // so the wipe is triggered on drop (it is never called explicitly by the
    // PRP). The `cipher` AES key schedule is wiped separately by the `aes`
    // crate's own `ZeroizeOnDrop` when it drops.
    #[test]
    fn zeroize_clears_keystream_and_state() {
        let mut prng = init_prng();
        for _ in 0..20 {
            let _ = prng.next_byte();
        }
        // Precondition: there is real state to wipe.
        assert_ne!(prng.ctr, 0);
        assert!(prng.data.iter().any(|b| b.iter().any(|&x| x != 0)));

        prng.zeroize();

        assert!(
            prng.data.iter().all(|b| b.iter().all(|&x| x == 0)),
            "keystream not cleared"
        );
        assert_eq!(prng.ptr, (0, 0), "position not cleared");
        assert_eq!(prng.ctr, 0, "counter not cleared");
    }

    // Compile-time proof that the wipe runs on drop (not only on an explicit
    // `zeroize()` the PRP never makes).
    #[test]
    fn impls_zeroize_on_drop() {
        fn assert_zod<T: ZeroizeOnDrop>() {}
        assert_zod::<Aes128Prng>();
    }
}
