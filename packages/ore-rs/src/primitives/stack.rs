//! Stack scrubbing for the encrypt entry points.
//!
//! Wiping a value on drop does not wipe the copies the compiler made of it.
//! Building a PRP leaves its seed-keyed AES schedule (round key 0 is the
//! seed) and its permutation tables in stack slots that moves and returns
//! left behind, and `ZeroizeOnDrop` only reaches the final location. Those
//! slots outlive the call, until something else overwrites them.
//!
//! [`scrubbed`] runs the encryption in a frame of its own and then zeroes
//! [`SCRUB_BYTES`] of the stack below the caller's frame, which covers every
//! frame the encryption used. Each scheme's residue tests measure the depth
//! its encrypt paths reach, check that the scrub covers it, and search the
//! dead stack for the secrets.

/// Bytes of stack zeroed after each encryption. On aarch64 the Bit6 encrypt
/// paths reach about 6 KiB in a release build and about 49 KiB in a debug
/// build. The residue tests in each scheme measure the depth and fail if a
/// change takes it past this.
pub(crate) const SCRUB_BYTES: usize = if cfg!(debug_assertions) {
    96 * 1024
} else {
    16 * 1024
};

/// Run `f` in its own stack frame, then zero the stack it used.
///
/// The work must happen inside `f`. Secrets the caller holds in its own
/// frame are above the scrubbed region and are not wiped.
#[inline(always)]
pub(crate) fn scrubbed<T>(f: impl FnOnce() -> T) -> T {
    let out = isolate(f);
    scrub();
    out
}

/// Not inlined, so that `f` runs below the caller's frame.
#[inline(never)]
fn isolate<T>(f: impl FnOnce() -> T) -> T {
    f()
}

/// Zero `SCRUB_BYTES` of stack below the caller's frame.
///
/// One `memset` of the whole buffer: per-word volatile stores (`Zeroize`)
/// added 5–12% to a Bit6 encryption on an M1 Max; this adds about 1%. `black_box` takes the buffer's
/// address after the stores, so the compiler must assume it reads them and
/// cannot drop them as dead.
#[inline(never)]
fn scrub() {
    let mut buf = core::mem::MaybeUninit::<[u8; SCRUB_BYTES]>::uninit();
    // SAFETY: writes `SCRUB_BYTES` bytes into a buffer of that size.
    unsafe { core::ptr::write_bytes(buf.as_mut_ptr() as *mut u8, 0, SCRUB_BYTES) };
    core::hint::black_box(&mut buf);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Helpers for tests that look for secrets left in dead stack.
#[cfg(test)]
pub(crate) mod residue {
    use std::thread;

    /// Bytes of dead stack [`after`] copies and searches.
    pub(crate) const SCAN_BYTES: usize = super::SCRUB_BYTES + 64 * 1024;

    /// Fill the stack below the caller with a marker byte, so that the depth
    /// a later call reaches can be read from what it overwrote.
    #[inline(never)]
    fn paint() {
        let mut buf = [0xa5u8; SCAN_BYTES + 4096];
        core::hint::black_box(&mut buf);
    }

    /// Copy the `SCAN_BYTES` of stack below this frame into `out`, using
    /// only volatile reads, so that the copy calls no function that would
    /// overwrite the region first.
    #[inline(never)]
    fn snapshot(out: &mut [u8]) {
        let marker = 0u8;
        let top = core::hint::black_box(&marker as *const u8);
        // Start a little below `marker`, clear of this frame's own slots.
        let start = top.wrapping_sub(256 + out.len());
        for (i, slot) in out.iter_mut().enumerate() {
            // SAFETY: the region is inside this thread's stack (which
            // `after` sizes well beyond `SCAN_BYTES`), below the live
            // frames, and mapped. It is read as plain bytes.
            *slot = unsafe { core::ptr::read_volatile(start.wrapping_add(i)) };
        }
    }

    /// The dead stack left by `f`, run on a fresh thread: `SCAN_BYTES`,
    /// ordered from the deepest address up.
    pub(crate) fn after<F: FnOnce() + Send + 'static>(f: F) -> Vec<u8> {
        thread::Builder::new()
            .stack_size(4 * 1024 * 1024)
            .spawn(move || {
                let mut out = vec![0u8; SCAN_BYTES];
                paint();
                run(f);
                snapshot(&mut out);
                out
            })
            .unwrap()
            .join()
            .unwrap()
    }

    #[inline(never)]
    fn run<F: FnOnce()>(f: F) {
        f()
    }

    /// How far below the caller `f` wrote: bytes from the deepest address
    /// that no longer holds the paint marker to the top of the scan.
    pub(crate) fn depth(dead: &[u8]) -> usize {
        dead.windows(16)
            .position(|w| w.iter().any(|&b| b != 0xa5))
            .map_or(0, |deepest| dead.len() - deepest)
    }

    /// Whether `needle` occurs anywhere in `dead`.
    pub(crate) fn contains(dead: &[u8], needle: &[u8]) -> bool {
        dead.windows(needle.len()).any(|w| w == needle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_zeroes_the_region_a_call_used() {
        let dead = residue::after(|| {
            scrubbed(|| {
                let mut secret = [0x5cu8; 4096];
                core::hint::black_box(&mut secret);
            })
        });
        assert!(!residue::contains(&dead, &[0x5cu8; 64]));
    }

    #[test]
    fn unscrubbed_residue_is_visible() {
        // Positive control for the scan: without the scrub the secret stays.
        let dead = residue::after(|| {
            isolate(|| {
                let mut secret = [0x5cu8; 4096];
                core::hint::black_box(&mut secret);
            })
        });
        assert!(residue::contains(&dead, &[0x5cu8; 64]));
    }
}
