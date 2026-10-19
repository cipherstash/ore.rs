//! Helpers for this crate's tests: keys, salts and sealed plaintexts of
//! each kind, made the way a caller makes them, through
//! `vitaminc_ore::order`.

use vitaminc_context::Context;
use vitaminc_ore::{order, Float, Int, Logical, OrderPlaintext, OrderTarget, Physical};
use vitaminc_protected::Protected;
use vitaminc_random::SafeRand;

/// A fresh random 16-byte key.
pub(crate) fn key() -> Protected<[u8; 16]> {
    use rand::TryRng;
    let mut rng = SafeRand::from_entropy().expect("the OS random number generator");
    let mut key = [0u8; 16];
    match rng.try_fill_bytes(&mut key) {
        Ok(()) => {}
        Err(never) => match never {},
    }
    Protected::new(key)
}

/// A key of one repeated byte, for tests that must be reproducible.
pub(crate) fn fixed_key(byte: u8) -> Protected<[u8; 16]> {
    Protected::new([byte; 16])
}

/// A salt from raw bytes: the bytes are the context, verbatim, as a
/// 0.9 caller's `init_with_salt(key, bytes)` had them.
pub(crate) fn salt(bytes: &[u8]) -> Context<'static> {
    Context::from_encoded(bytes.to_vec())
}

/// A sealed plaintext of `value` as `target`.
pub(crate) fn plaintext(
    target: OrderTarget,
    ty: Option<Logical>,
    value: Physical<'_>,
) -> OrderPlaintext {
    order(target, ty, value).expect("the value encodes as its target")
}

pub(crate) fn u64_pt(x: u64) -> OrderPlaintext {
    plaintext(OrderTarget::U64, None, Physical::Int(Int::U64(x)))
}

pub(crate) fn u32_pt(x: u32) -> OrderPlaintext {
    plaintext(OrderTarget::U32, None, Physical::Int(Int::U32(x)))
}

pub(crate) fn u128_pt(x: u128) -> OrderPlaintext {
    plaintext(OrderTarget::U128, None, Physical::Int(Int::U128(x)))
}

pub(crate) fn i128_pt(x: i128) -> OrderPlaintext {
    plaintext(OrderTarget::I128, None, Physical::Int(Int::I128(x)))
}

pub(crate) fn f64_pt(x: f64) -> OrderPlaintext {
    plaintext(OrderTarget::F64, None, Physical::Float(Float::F64(x)))
}

/// A date, as days from the Common Era, as vitaminc's `Date` target.
pub(crate) fn date_pt(days: i32) -> OrderPlaintext {
    plaintext(
        OrderTarget::Date,
        Some(Logical::Date),
        Physical::Int(Int::I32(days)),
    )
}

/// A timestamp in nanoseconds, as vitaminc's 12-byte `Timestamp` target.
pub(crate) fn timestamp_pt(nanos: i64) -> OrderPlaintext {
    use vitaminc_ore::TimeUnit;
    plaintext(
        OrderTarget::Timestamp,
        Some(Logical::Timestamp(TimeUnit::Nanos)),
        Physical::Int(Int::I64(nanos)),
    )
}

/// Text, as vitaminc encodes it: the marker byte, then case and accents
/// folded.
pub(crate) fn text_pt(s: &str) -> OrderPlaintext {
    plaintext(OrderTarget::Text, None, Physical::Text(s))
}

/// Bytes, as vitaminc encodes them: the marker byte, then the bytes.
pub(crate) fn bytes_pt(b: &[u8]) -> OrderPlaintext {
    plaintext(OrderTarget::Bytes, None, Physical::Bytes(b))
}
