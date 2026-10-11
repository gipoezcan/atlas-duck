//! I-37: the §6.4 classifier's heap over a release-cap-sized string. A read candidate's strings
//! are classified while the read holds a fetch slot (header counts, §6.1), outside the candidate
//! cache's accounting, so the classifier must not multiply a string's size. Own test binary: the
//! counting allocator is process-wide.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use atlas_duck_preview::invisible::{count, flags};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(n: usize) {
    let live = LIVE.fetch_add(n, Ordering::SeqCst) + n;
    PEAK.fetch_max(live, Ordering::SeqCst);
}

// SAFETY: every call forwards to `System` with the caller's arguments; the counters only observe.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        // SAFETY: the caller's contract for `alloc` is passed through unchanged.
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            grew(l.size());
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: the caller's contract for `dealloc` is passed through unchanged.
        unsafe { System.dealloc(p, l) };
        LIVE.fetch_sub(l.size(), Ordering::SeqCst);
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        // SAFETY: the caller's contract for `realloc` is passed through unchanged.
        let q = unsafe { System.realloc(p, l, new) };
        if !q.is_null() {
            if new >= l.size() {
                grew(new - l.size());
            } else {
                LIVE.fetch_sub(l.size() - new, Ordering::SeqCst);
            }
        }
        q
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Peak heap above the live bytes at the start of `f`.
fn peak_during(f: impl FnOnce()) -> usize {
    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    f();
    PEAK.load(Ordering::SeqCst) - base
}

#[test]
fn classifying_a_16_mib_string_allocates_at_most_its_size() {
    // The I-37 fixture's shape: one ~16 MiB summary of a single letter.
    let s = "m".repeat(16 << 20);
    let mut counted = (1, 1);
    let peak = peak_during(|| counted = count(&s));
    assert_eq!(counted, (0, 0));
    // At most the flags (one `bool` a char, with `Vec` growth slack); never a per-char index.
    assert!(
        peak <= 2 * s.len(),
        "count allocated {peak} bytes for {}",
        s.len()
    );
    let peak = peak_during(|| assert!(flags(&s).iter().all(|f| !f)));
    assert!(
        peak <= 2 * s.len(),
        "flags allocated {peak} bytes for {}",
        s.len()
    );
}
