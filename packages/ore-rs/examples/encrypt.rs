//! Encrypt a few values through vitaminc, the typed way in, and compare
//! them. Run with `cargo run --example encrypt`.

use std::cmp::Ordering;

use ore_rs::BlockOre;
use vitaminc_ore::target::{Text, I64};
use vitaminc_ore::{OrderEncrypt, OrderKeyInit};
use vitaminc_protected::Protected;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // In production, a random 32-byte key from your key management system.
    let scheme = BlockOre::new(Protected::new([0x2b; 32]));

    // A space of `i64`s under one context. The target picks the engine.
    let quantities = scheme.target(I64).context(("orders", "quantity"));
    let stored = quantities.encrypt(10_000i64)?;
    let query = quantities.encrypt_query(9_999i64)?;
    println!("term  = {}", hex::encode(stored.as_bytes()));
    println!("query = {}", hex::encode(query.as_bytes()));
    assert_eq!(
        quantities.compare_query(&query, &stored),
        Some(Ordering::Less)
    );

    // Text goes to the chained engine, padded to a length bucket.
    let names = scheme.target(Text).context(("users", "name"));
    let alice = names.encrypt_checked("alice")?;
    let bob = names.encrypt_checked("bob")?;
    assert_eq!(names.compare(&alice, &bob), Some(Ordering::Less));
    println!("text term is {} bytes", alice.as_bytes().len());
    Ok(())
}
