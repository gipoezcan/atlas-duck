#![cfg(feature = "async")]
//! M-1: `read_frame_async` grows its body buffer with the bytes that arrive, so a header that
//! announces up to 24 MiB costs nothing until the body is actually sent. Its own test binary,
//! because the counting allocator sees every allocation in the process.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use atlas_duck_ipc::rpc::frame::{FrameError, read_frame_async};
use atlas_duck_ipc::sandbox::MAX_FRAME_BYTES;

/// Records the largest single allocation while armed.
struct Peak;

static ARMED: AtomicBool = AtomicBool::new(false);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn note(size: usize) {
    if ARMED.load(Ordering::Relaxed) {
        PEAK.fetch_max(size, Ordering::Relaxed);
    }
}

// SAFETY: every call is forwarded unchanged to `System`; only sizes are recorded.
unsafe impl GlobalAlloc for Peak {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: the caller's contract is passed through.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: as above.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        // SAFETY: as above.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as above.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Peak = Peak;

#[tokio::test(flavor = "current_thread")]
async fn announced_length_is_not_allocated_up_front() {
    let announced = u32::try_from(MAX_FRAME_BYTES).expect("fits u32");
    let mut wire = announced.to_be_bytes().to_vec();
    wire.extend_from_slice(&[7u8; 10]);
    let mut r = &wire[..];

    PEAK.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    let got = read_frame_async(&mut r, MAX_FRAME_BYTES).await;
    ARMED.store(false, Ordering::Relaxed);

    assert!(matches!(got, Err(FrameError::Truncated)), "{got:?}");
    let peak = PEAK.load(Ordering::Relaxed);
    assert!(
        peak <= 64 * 1024,
        "a 10-byte body under a 24 MiB header allocated {peak} bytes at once"
    );
}
