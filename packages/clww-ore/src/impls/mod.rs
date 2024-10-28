use std::cmp::Ordering;

pub mod num;
pub mod string;

/// Compare 2 CLLW ORE encrypted slices of the same length
fn compare_slice(a: &[u8], b: &[u8]) -> Ordering {
    assert_eq!(a.len(), b.len());

    let mut differing: Option<(u8, u8)> = None;
    for (x, y) in a.iter().zip(b.iter()) {
        // TODO: More work required to make this constant time
        differing = differing.or_else(|| if x != y { Some((*x, *y)) } else { None });
    }

    if let Some((x, y)) = differing {
        if y.wrapping_add(1) == x {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    } else {
        Ordering::Equal
    }
}
