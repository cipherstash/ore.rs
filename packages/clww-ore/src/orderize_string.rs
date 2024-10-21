use regex::Regex;
use std::sync::OnceLock;

use crate::Error;

static NON_ALPHANUMERIC_OR_SPACE_REGEX: OnceLock<Regex> = OnceLock::new();
static SPACE_REGEX: OnceLock<Regex> = OnceLock::new();

pub fn orderize_string(s: &str) -> Result<String, Error> {
    if !s.is_ascii() {
        return Err(Error::NotAscii);
    }

    let non_alphanumeric_or_space_regex =
        NON_ALPHANUMERIC_OR_SPACE_REGEX.get_or_init(|| Regex::new("[^a-z0-9[:space:]]+").unwrap());

    let space_regex = SPACE_REGEX.get_or_init(|| Regex::new("[[:space:]]+").unwrap());

    // This all very much relies on ASCII character numbering.  A copy of `ascii`(7)
    // up on a convenient terminal may assist in understanding what's going
    // on here.

    // First up, let's transmogrify the string we were given into one that only contains
    // a controlled subset of characters, that we can easily map into a smaller numeric
    // space.

    let mut s = s.to_lowercase();

    // Any group of rando characters sort at the end.
    s = non_alphanumeric_or_space_regex
        .replace_all(&s, "~")
        .to_string();

    // Any amount of whitespace comes immediately after letters.
    s = space_regex.replace_all(&s, "{").to_string();

    Ok(s)
}
