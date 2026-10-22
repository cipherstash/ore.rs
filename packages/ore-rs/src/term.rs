//! What the schemes give back: a stored term and a query, each the
//! serialised bytes of a ciphertext.
//!
//! The block count of a ciphertext is the plaintext's width, known only
//! when the plaintext arrives, so a scheme cannot give back a ciphertext
//! typed by its block count. It gives back the bytes, under a type that
//! says which half they are: a [`Term`] is a full ciphertext, left and
//! right halves, and is what is stored; a [`Query`] is the left half
//! alone, made from the value searched for, and is what a comparison
//! needs from the other side. The bytes carry their scheme and block
//! count in the wire header, and the comparators parse and check them.
//!
//! The plaintext type is not in the bytes. vitaminc's `OrderTerm` and
//! `QueryTerm` label a term with its target; here a `Term` is whatever
//! the caller says it is, and the comparators refuse only what they can
//! tell apart (another scheme; on a fixed-width scheme another block
//! count; on the chained scheme another padding policy), as the scheme
//! docs say.

/// A full ciphertext, serialised: left and right halves, with the wire
/// header. What a scheme stores. Compared with the scheme's
/// `compare_raw_slices`, or against a [`Query`] with
/// `compare_left_to_full`; never byte by byte, since a full ciphertext
/// carries a random nonce and one value has many. So no `PartialEq`:
/// `==` on two terms of one value would be `false`.
#[derive(Debug, Clone)]
pub struct Term(Vec<u8>);

/// A left (query) ciphertext, serialised: the per-block permuted
/// symbols and tags, with the wire header, and no nonce or right half.
/// Made from the value searched for, and compared against a stored
/// [`Term`] with the scheme's `compare_left_to_full`. Deterministic:
/// one value under one key and salt gives one query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query(Vec<u8>);

macro_rules! bytes_newtype {
    ($type:ident) => {
        impl $type {
            /// The serialised bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// The serialised bytes, owned.
            pub fn into_bytes(self) -> Vec<u8> {
                self.0
            }

            /// Bytes read back from storage, as this type. Nothing is
            /// checked here: the comparators parse the bytes and return
            /// `None` for ones that are not a ciphertext of their scheme.
            pub fn from_bytes(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }

            pub(crate) fn new(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }
        }

        impl AsRef<[u8]> for $type {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<$type> for Vec<u8> {
            fn from(value: $type) -> Vec<u8> {
                value.0
            }
        }
    };
}

bytes_newtype!(Term);
bytes_newtype!(Query);
