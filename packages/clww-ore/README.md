# CLWW ORE

[![Crates.io Version](https://img.shields.io/crates/v/clww-ore?style=for-the-badge)](https://crates.io/crates/clww-ore)
[![docs.rs](https://img.shields.io/docsrs/clww-ore?style=for-the-badge)](https://docs.rs/clww-ore/)
[![Built by CipherStash](https://raw.githubusercontent.com/cipherstash/meta/refs/heads/main/csbadge.svg)](https://cipherstash.com)

 [Website](https://cipherstash.com) | [Docs](https://cipherstash.com/docs) | [Discussions](https://github.com/orgs/cipherstash/discussions)

## Fast, efficient Order-Revealing and Order-Preserving Encryption

This crate implements the Order-Revealing Encryption (ORE) and Order-Preserving Encryption (OPE)
schemes from Chenette, Lewi, Weis and Wu (Stanford, 2015 — hence "CLWW").

Both schemes are faster and more space efficient than the "Block" ORE scheme developed by Lewi and
Wu a year later, but have weaker security properties. The OPE variant additionally produces
ciphertexts that compare under standard lexicographic byte ordering, with no custom comparator
required — making it usable directly with operators like `<`, `>` and `BETWEEN` in databases that
already know how to compare opaque byte strings.

At CipherStash, we use the ORE variant for encrypting terms in our encrypted JSON indexer. For
ordered range queries on encrypted columns we prefer ORE with a custom operator family/class,
falling back to the OPE variant only when the database doesn't provide those. For everything else
we use the Block scheme; see [ore.rs](https://ore.rs) for more information.

## Use from vitaminc

`ClwwOre` and `ClwwOpe` implement [`vitaminc-ore`](https://docs.rs/vitaminc-ore)'s
`OrderScheme` and `OrderQuery`, so a vitaminc order space can encrypt the sealed plaintexts it
builds here. A caller opens a space with a target and a context
(`scheme.target(I32).context(("orders", "quantity"))`), and every value is encoded as that
target. Both schemes take every target at any length through the byte-slice entry points, with
the salt the space derives (scheme, domain and the caller's context) as the CLWW salt. A CLWW
term is its own query. Requires vitaminc-ore 0.8.

A `Text` or `Bytes` term shows the exact length of its value: there is no padding and no length
limit. An ORE term is 8 bytes per plaintext byte, an OPE term the same plus 1 carry byte, so a
very large value gives a term 8 times its size. This differs from `ore_rs::BlockOre`, which pads
text to a power of two and refuses text over its maximum. A caller who needs a limit checks the
value before it encrypts it.

## CipherStash

CLWW ORE is brought to you by the team at [CipherStash](https://cipherstash.com).

