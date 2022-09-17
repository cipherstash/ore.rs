/*
 * Block CRE Implemenation using a 2-bit indicator function
 */

use crate::{
    ciphertext::*,
    primitives::{
        hash::AES128Z2Hash, prf::AES128PRF, prp::KnuthShufflePRP, AesBlock, Hash, Prf,
        Prp, SEED64,
    },
    CRECipherInit, CRECipher, CREError, PlainText,
};

use aes::cipher::generic_array::GenericArray;
use rand::{Rng, SeedableRng};
use std::cell::RefCell;

mod ore;
pub use self::ore::OREAES128;

pub mod block_types;
pub use self::block_types::*;

/* Define our scheme */
#[derive(Debug)]
pub struct CreAes128<R: Rng + SeedableRng> {
    prf1: AES128PRF,
    prf2: AES128PRF,
    rng: RefCell<R>,
    prp_seed: SEED64,
    cmp: fn(u8, u8) -> u8,
}

/* Define some convenience types */
type EncryptLeftResult<R, const N: usize> = Result<Left<CreAes128<R>, N>, CREError>;
type EncryptResult<R, const N: usize> = Result<CipherText<CreAes128<R>, N>, CREError>;

impl<R: Rng + SeedableRng> CRECipherInit for CreAes128<R> {
    fn init(k1: [u8; 16], k2: [u8; 16], seed: &SEED64, cmp: fn(u8, u8) -> u8) -> Result<Self, CREError> {
        // TODO: k1 and k2 should be Key types and we should have a set of traits to abstract the
        // behaviour ro parsing/loading etc

        let rng: R = SeedableRng::from_entropy();

        return Ok(CreAes128 {
            prf1: Prf::new(GenericArray::from_slice(&k1)),
            prf2: Prf::new(GenericArray::from_slice(&k2)),
            rng: RefCell::new(rng),
            prp_seed: *seed,
            cmp: cmp,
        });
    }
}

impl<R: Rng + SeedableRng> CRECipher for CreAes128<R> {
    type LeftBlockType = LeftBlock16;
    type RightBlockType = RightBlock32;

    fn encrypt_left<const N: usize>(&self, x: &PlainText<N>) -> EncryptLeftResult<R, N> {
        let mut output = Left::<Self, N>::init();

        // Build the prefixes
        // TODO: Don't modify struct values directly - use a function on a "Left" trait
        output.f.iter_mut().enumerate().for_each(|(n, block)| {
            block[0..n].clone_from_slice(&x[0..n]);
            // TODO: Include the block number in the prefix to avoid repeating values for common
            // blocks in a long prefix
            // e.g. when plaintext is 4700 (2-bytes/blocks)
            // xt = [17, 17, 17, 17, 17, 17, 223, 76]
        });

        self.prf2.encrypt_all(&mut output.f);

        for (n, xn) in x.iter().enumerate().take(N) {
            // Set prefix and create PRP for the block
            let prp: KnuthShufflePRP<u8, 256> =
                Prp::new(&output.f[n], &self.prp_seed).map_err(|_| CREError)?;

            output.xt[n] = prp.permute(*xn).map_err(|_| CREError)?;
        }

        // Reset the f block
        // TODO: Should we use Zeroize? We don't actually need to clear sensitive data here, we
        // just need fast "zero set". Reassigning the value will drop the old one and allocate new
        // data to the stack
        output.f = [Default::default(); N];

        for n in 0..N {
            output.f[n][0..n].clone_from_slice(&x[0..n]);
            output.f[n][n] = output.xt[n];
            // Include the block number in the value passed to the Random Oracle
            output.f[n][N] = n as u8;
        }
        self.prf1.encrypt_all(&mut output.f);

        Ok(output)
    }

    fn encrypt<const N: usize>(&self, x: &PlainText<N>) -> EncryptResult<R, N> {
        let mut left = Left::<Self, N>::init();
        let mut right = Right::<Self, N>::init();

        // Generate a 16-byte random nonce
        self.rng.borrow_mut().try_fill(&mut right.nonce).map_err(|_| CREError)?;

        // Build the prefixes
        // TODO: Don't modify struct values directly - use a function on a "Left"
        left.f.iter_mut().enumerate().for_each(|(n, block)| {
            block[0..n].clone_from_slice(&x[0..n]);
        });

        self.prf2.encrypt_all(&mut left.f);

        for n in 0..N {
            // Set prefix and create PRP for the block
            let prp: KnuthShufflePRP<u8, 256> =
                Prp::new(&left.f[n], &self.prp_seed).map_err(|_| CREError)?;

            left.xt[n] = prp.permute(x[n]).map_err(|_| CREError)?;

            // Reset the f block
            // TODO: Do we need to zeroize the old data before it is dropped due to de-assignment?
            left.f[n] = Default::default();

            left.f[n][0..n].clone_from_slice(&x[0..n]);
            left.f[n][n] = left.xt[n];
            // Include the block number in the value passed to the Random Oracle
            left.f[n][N] = n as u8;

            let mut ro_keys: [AesBlock; 256] = [Default::default(); 256];

            for (j, ro_key) in ro_keys.iter_mut().enumerate() {
                /*
                 * The output of F in H(F(k1, y|i-1||j), r)
                 */
                ro_key[0..n].clone_from_slice(&x[0..n]);
                ro_key[n] = j as u8;
                ro_key[N] = n as u8;
            }

            self.prf1.encrypt_all(&mut ro_keys);

            /* TODO: This seems to work but it is technically using the nonce as the key
             * (instead of using it as the plaintext). This appears to be how the original
             * ORE implementation does it but it feels a bit wonky to me. Should check with David.
             * It is useful though because the AES crate makes it easy to encrypt groups of 8
             * plaintexts under the same key. We really want the ability to encrypt the same
             * plaintext (i.e. the nonce) under different keys but this may be an acceptable
             * approximation.
             *
             * If not, we will probably need to implement our own parallel encrypt using intrisics
             * like in the AES crate: https://github.com/RustCrypto/block-ciphers/blob/master/aes/src/ni/aes128.rs#L26
             */
            let hasher: AES128Z2Hash = Hash::new(AesBlock::from_slice(&right.nonce));
            let hashes = hasher.hash_all(&mut ro_keys);

            // FIXME: force casting to u8 from usize could cause a panic
            for (j, h) in hashes.iter().enumerate() {
                let jstar = prp.invert(j as u8).map_err(|_| CREError)?;
                let indicator = (self.cmp)(jstar, x[n]);
                right.data[n].set_bit(j, indicator ^ h);
            }
        }
        self.prf1.encrypt_all(&mut left.f);

        // TODO: Do we need to do any zeroing? See https://lib.rs/crates/zeroize
        // Zeroize the RO Keys before re-assigning them

        Ok(CipherText { left, right })
    }
}

// TODO: Move these to block_types
#[inline]
fn left_block<T: CipherTextBlock>(input: &[u8], n: usize) -> &[u8] {
    let f_pos = n * T::BLOCK_SIZE;
    &input[f_pos..(f_pos + T::BLOCK_SIZE)]
}

#[inline]
fn right_block<T: CipherTextBlock>(input: &[u8], n: usize) -> &[u8] {
    let f_pos = n * T::BLOCK_SIZE;
    &input[f_pos..(f_pos + T::BLOCK_SIZE)]
}

#[inline]
fn get_bit<T: CipherTextBlock>(block: &[u8], bit: usize) -> u8 {
    debug_assert!(block.len() == T::BLOCK_SIZE);
    debug_assert!(bit < 256);
    let byte_index = bit / 8;
    let position = bit % 8;
    let v = 1 << position;

    (block[byte_index] & v) >> position
}
