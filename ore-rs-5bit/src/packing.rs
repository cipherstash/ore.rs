use primitives::prf::PrfBlock;


pub fn prefixes(slice: &[u8]) -> Vec<PrfBlock> {
    let mut prefixes: Vec<PrfBlock> = Vec::with_capacity(slice.len());
    for i in 0..slice.len() {
        let mut fblock: PrfBlock = Default::default();
        fblock[0..i].copy_from_slice(&slice[0..i]);
        prefixes.push(fblock);
    }

    prefixes
}
