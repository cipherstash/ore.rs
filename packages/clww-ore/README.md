# CLWW ORE

[![Crates.io Version](https://img.shields.io/crates/v/cllw-ore?style=for-the-badge)](https://crates.io/crates/cllw-ore)
[![docs.rs](https://img.shields.io/docsrs/cllw-ore?style=for-the-badge)](https://docs.rs/cllw-ore/)
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

## CipherStash

CLWW ORE is brought to you by the team at [CipherStash](https://cipherstash.com).

