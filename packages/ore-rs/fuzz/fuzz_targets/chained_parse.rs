#![no_main]

use libfuzzer_sys::fuzz_target;
use ore_rs::scheme::chained::VarCipherText;

// Ciphertexts are read back from storage, so the parser sees untrusted bytes:
// it must never panic (the block count is read from the header and drives
// every slice index), and anything it accepts must re-encode to the same
// bytes, or the stored form and the parsed form would disagree.
fuzz_target!(|data: &[u8]| {
    if let Ok(ct) = VarCipherText::from_slice(data) {
        assert_eq!(
            ct.to_bytes(),
            data,
            "accepted ciphertext did not round-trip"
        );
    }
});
