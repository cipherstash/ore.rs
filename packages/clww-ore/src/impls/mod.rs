use std::cmp::Ordering;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

pub mod num;
pub mod string;

/// Compare 2 CLLW ORE encrypted slices of the same length in constant time
fn compare_slice(a: &[u8], b: &[u8]) -> Ordering {
    assert_eq!(a.len(), b.len());

    // Track the first differing pair in a constant-time manner
    let mut diff_x: u8 = 0;
    let mut diff_y: u8 = 0;
    let mut found_diff = Choice::from(0u8);

    for (x, y) in a.iter().zip(b.iter()) {
        let is_diff = !x.ct_eq(y);
        let not_found_yet = !found_diff;
        let should_record = is_diff & not_found_yet;

        // Conditionally assign using constant-time selection
        diff_x = u8::conditional_select(&diff_x, x, should_record);
        diff_y = u8::conditional_select(&diff_y, y, should_record);
        found_diff = Choice::conditional_select(&found_diff, &is_diff, should_record);
    }

    // Perform comparison in constant time
    let is_greater = diff_y.wrapping_add(1).ct_eq(&diff_x);
    let is_equal = !found_diff;

    // Convert to Ordering - this final step is not constant-time, but the
    // secret data has already been processed in constant time
    if bool::from(is_equal) {
        Ordering::Equal
    } else if bool::from(is_greater) {
        Ordering::Greater
    } else {
        Ordering::Less
    }
}
