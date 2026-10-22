//! `encrypt_ope_bits` frees no buffer that still holds a secret.
//!
//! The function grows two buffers as it reads the bits: one holds the
//! keystream until the carry pass, the other one byte per plaintext bit. A
//! `Vec` that outgrows its buffer frees the old one as it is. This binary's
//! allocator scans every buffer freed while it is armed for the two secrets,
//! so a buffer freed unwiped fails the test. It is its own test binary, so the
//! allocator sees no other test's buffers.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use clww_ore::{encrypt_ope_bits, Key};

const NEEDLE_LEN: usize = 32;

/// Scans each buffer freed while `ARMED` for the needles.
struct Scanning;

static ARMED: AtomicBool = AtomicBool::new(false);
static FOUND: AtomicBool = AtomicBool::new(false);
static NEEDLES: Mutex<[[u8; NEEDLE_LEN]; 2]> = Mutex::new([[0; NEEDLE_LEN]; 2]);

unsafe impl GlobalAlloc for Scanning {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded as it was given.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) && layout.size() >= NEEDLE_LEN {
            // SAFETY: `ptr` is a live allocation of `layout.size()` bytes
            // until it is freed below.
            let freed = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            // `try_lock`: the lock never allocates, and a scan that would
            // wait on it is skipped rather than deadlock.
            if let Ok(needles) = NEEDLES.try_lock() {
                if needles
                    .iter()
                    .any(|n| freed.windows(NEEDLE_LEN).any(|w| w == n))
                {
                    FOUND.store(true, Ordering::SeqCst);
                }
            }
        }
        // SAFETY: forwarded as it was given.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Scanning = Scanning;

/// `bits`, through an iterator that gives no size hint, as the crate's own
/// bit iterators do, so the buffers start empty and grow.
fn unhinted(bits: &[u8]) -> impl Iterator<Item = u8> + '_ {
    bits.iter().copied().filter(|_| true)
}

#[test]
fn no_buffer_is_freed_with_the_keystream_or_the_plaintext_bits() {
    let key = Key::from([0x5a; 32]);
    let salt = Some(&b"freed-buffers"[..]);

    // All zero bits add nothing and carry nothing, so this term past its
    // leading byte is the bare keystream: what `out` holds before the carry
    // pass.
    let zeros = [0u8; 300];
    let keystream = encrypt_ope_bits(unhinted(&zeros), &key, salt).unwrap();
    // Bits of a pattern no keystream or zero buffer will hold.
    let pattern: Vec<u8> = (0..300u32).map(|i| u8::from(i % 3 == 0)).collect();

    {
        let mut needles = NEEDLES.lock().unwrap();
        needles[0].copy_from_slice(&keystream[1..=NEEDLE_LEN]);
        needles[1].copy_from_slice(&pattern[..NEEDLE_LEN]);
    }

    ARMED.store(true, Ordering::SeqCst);
    let a = encrypt_ope_bits(unhinted(&zeros), &key, salt);
    let b = encrypt_ope_bits(unhinted(&pattern), &key, salt);
    ARMED.store(false, Ordering::SeqCst);

    // Checked once disarmed: `a` is the keystream needle itself.
    assert_eq!(a.unwrap(), keystream);
    assert!(b.is_ok());
    assert!(
        !FOUND.load(Ordering::SeqCst),
        "a buffer was freed with the keystream or the plaintext bits in it"
    );
}
