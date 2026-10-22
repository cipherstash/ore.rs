//! OPE encryption frees no buffer that still holds a secret.
//!
//! The encryption grows two buffers as it reads the plaintext bits: one holds
//! the keystream until the carry pass, the other one byte per plaintext bit.
//! A `Vec` that outgrows its buffer frees the old one as it is. This binary's
//! allocator scans every buffer freed while it is armed for the two secrets,
//! so a buffer freed unwiped fails the test. It is its own test binary, so the
//! allocator sees no other test's buffers.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use clww_ore::ClwwOpe;
use vitaminc_ore::target::Bytes;
use vitaminc_ore::{OrderEncrypt, OrderKeyInit};
use vitaminc_protected::Protected;

const NEEDLE_LEN: usize = 32;

/// Where the bits of a `Bytes` value start in its OPE term: one carry byte,
/// then the eight bits of vitaminc's marker byte.
const VALUE_BITS_AT: usize = 1 + 8;

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

/// The bits of `bytes`, one byte each, most significant first: what the
/// plaintext-bits buffer holds. A copy of the crate-private `bits_of`, which
/// an integration test cannot reach.
fn bits_of(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|&b| (0..8).rev().map(move |i| (b >> i) & 1))
        .collect()
}

#[test]
fn no_buffer_is_freed_with_the_keystream_or_the_plaintext_bits() {
    let scheme = ClwwOpe::new(Protected::new([0x5a; 32]));
    let space = scheme.target(Bytes).context("freed-buffers");

    // vitaminc puts one marker byte before the bytes. Past its eight bits,
    // zero bits add nothing and carry nothing, so this term past its carry
    // byte and the marker's bits is the bare keystream: what the buffer holds
    // before the carry pass.
    let zeros = [0u8; 40];
    let keystream = space.encrypt(&zeros[..]).unwrap();
    // A pattern no keystream or zero buffer will hold, as bits.
    let pattern = [0xa5u8; 40];

    {
        let mut needles = NEEDLES.lock().unwrap();
        needles[0].copy_from_slice(&keystream.as_ref()[VALUE_BITS_AT..VALUE_BITS_AT + NEEDLE_LEN]);
        needles[1].copy_from_slice(&bits_of(&pattern)[..NEEDLE_LEN]);
    }

    ARMED.store(true, Ordering::SeqCst);
    let a = space.encrypt(&zeros[..]);
    let b = space.encrypt(&pattern[..]);
    ARMED.store(false, Ordering::SeqCst);

    // Checked once disarmed: `a` holds the keystream needle itself.
    assert_eq!(a.unwrap().as_ref(), keystream.as_ref());
    assert!(b.is_ok());
    assert!(
        !FOUND.load(Ordering::SeqCst),
        "a buffer was freed with the keystream or the plaintext bits in it"
    );
}
