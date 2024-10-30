# CLLW ORE

[![Crates.io Version](https://img.shields.io/crates/v/cllw-ore?style=for-the-badge)](https://crates.io/crates/cllw-ore)
[![docs.rs](https://img.shields.io/docsrs/cllw-ore?style=for-the-badge)](https://docs.rs/cllw-orw/)
[![Built by CipherStash](https://raw.githubusercontent.com/cipherstash/meta/refs/heads/main/csbadge.svg)](https://cipherstash.com)

 [Website](https://cipherstash.com) | [Docs](https://cipherstash.com/docs) | [Discussions](https://github.com/orgs/cipherstash/discussions)

## Fast, efficient Order-Revealing Encryption

This crate implements the Order Revealing Encryption scheme developed by Chenette, Lewi, Weis and Wu
at Stanford in 2015 (hence "CLLW").

It is faster and more space efficient than the "Block" ORE scheme developed by Lewi and Wu a year later
however has weaker security properties.

At CipherStash, we use this crate for encrypting terms in our encrypted JSON indexer but for everything else
we use the Block scheme.
See [ore.rs](https://ore.rs) for more information.

## CipherStash

CLLW ORE is brought to you by the team at [CipherStash](https://cipherstash.com).

