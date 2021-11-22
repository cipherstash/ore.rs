
use small_prp::ore_large::OreLarge;
use aes::cipher::generic_array::{ArrayLength, GenericArray, arr};
use aes::cipher::BlockCipher;

use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use hex_literal::hex;

// create an alias for convenience
type Aes128Cbc = Cbc<Aes128, Pkcs7>;
type BlockSize = <Aes128 as BlockCipher>::BlockSize;

fn to_blocks<N>(data: &mut [u8]) -> &mut [GenericArray<u8, N>]
where
    N: ArrayLength<u8>,
{
    use core::slice;
    let n = N::to_usize();
    debug_assert!(data.len() % n == 0);

    #[allow(unsafe_code)]
    unsafe {
        slice::from_raw_parts_mut(data.as_ptr() as *mut GenericArray<u8, N>, data.len() / n)
    }
}

fn main() {
    let key = hex!("000102030405060708090a0b0c0d0e0f");

    let prf_key = arr![u8; 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let prp_key = arr![u8; 0xd0, 0xd0, 0x07, 0xa5, 0x3f, 0x9a, 0x68, 0x48, 0x83, 0xbc, 0x1f, 0x21, 0x0f, 0x65, 0x95, 0xa3];

    let mut ore = OreLarge::init(prf_key, prp_key);

    /*let ct2 = ore.encrypt(18);
    let ct3 = ore.encrypt(15);
    println!("COMPARE = {} should be 1", OreLarge::compare(&ct2, &ct3));*/

    //let ct4 = ore.encrypt(7061644215716937728);
    //let ct4 = ore.encrypt(7133701809754865663);
    //let ct5 = ore.encrypt(7);

    /*let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let plaintext = b"Hello world!";
    let mut cipher = Aes128Cbc::new_from_slices(&key, &iv).unwrap();

    let mut buffer = [0u8; 32 * 8];
    // copy message to the buffer
    let pos = plaintext.len();
    buffer[..pos].copy_from_slice(plaintext);
    buffer[32..(32 + pos)].copy_from_slice(plaintext);
    buffer[64..(64 + pos)].copy_from_slice(plaintext);
    buffer[96..(96 + pos)].copy_from_slice(plaintext);
    buffer[128..(128 + pos)].copy_from_slice(plaintext);
    buffer[160..(160 + pos)].copy_from_slice(plaintext);
    buffer[192..(192 + pos)].copy_from_slice(plaintext);
    buffer[224..(224 + pos)].copy_from_slice(plaintext);

    let mut blocks = to_blocks::<BlockSize>(&mut buffer[..]);
    println!("blocks = {:?}", blocks);
    let ciphertext = cipher.encrypt_blocks(&mut blocks);

    println!("CT = {:?}", ciphertext);
    println!("blocks = {:?}", blocks);*/
}
