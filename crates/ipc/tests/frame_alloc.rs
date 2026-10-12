#![cfg(feature = "async")]
//! M-1: `read_frame_async` grows its body buffer with the bytes that arrive, so a header that
//! announces up to 24 MiB costs nothing until the body is actually sent, and the buffer never
//! grows past the announced length. Its own test binary, because the counting allocator sees
//! every allocation in the process.

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

/// The wire bytes of one frame: a header announcing `announced`, then `body`.
fn wire(announced: usize, body: usize) -> Vec<u8> {
    let mut wire = u32::try_from(announced)
        .expect("fits u32")
        .to_be_bytes()
        .to_vec();
    wire.resize(4 + body, 7);
    wire
}

/// Reads one frame (`wire(announced, body)`) and returns the result and the largest single
/// allocation during the read. The tests take turns (one lock) and build their wire bytes
/// under it, so `PEAK` sees no other test's allocations.
async fn read_counting(
    announced: usize,
    body: usize,
) -> (Result<Option<Vec<u8>>, FrameError>, usize) {
    static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _one = ONE_AT_A_TIME.lock().await;
    let wire = wire(announced, body);
    let mut r = &wire[..];
    PEAK.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    let got = read_frame_async(&mut r, MAX_FRAME_BYTES).await;
    ARMED.store(false, Ordering::Relaxed);
    (got, PEAK.load(Ordering::Relaxed))
}

#[tokio::test(flavor = "current_thread")]
async fn announced_length_is_not_allocated_up_front() {
    let (got, peak) = read_counting(MAX_FRAME_BYTES, 10).await;
    assert!(matches!(got, Err(FrameError::Truncated)), "{got:?}");
    assert!(
        peak <= 64 * 1024,
        "a 10-byte body under a 24 MiB header allocated {peak} bytes at once"
    );
}

/// The buffer grows with what arrives: at most twice the bytes received.
#[tokio::test(flavor = "current_thread")]
async fn buffer_grows_with_the_bytes_received() {
    let received = 100 * 1024;
    let (got, peak) = read_counting(MAX_FRAME_BYTES, received).await;
    assert!(matches!(got, Err(FrameError::Truncated)), "{got:?}");
    assert!(
        peak <= 2 * received,
        "{received} bytes under a 24 MiB header allocated {peak} bytes at once"
    );
}

/// A full 24 MiB body is held in one buffer of exactly its length: growth never doubles past
/// the announced length (no 32 MiB buffer for a 24 MiB frame).
#[tokio::test(flavor = "current_thread")]
async fn full_body_capacity_is_bounded_by_its_length() {
    let (got, peak) = read_counting(MAX_FRAME_BYTES, MAX_FRAME_BYTES).await;
    let body = got.expect("frame").expect("not EOF");
    assert_eq!(body.len(), MAX_FRAME_BYTES);
    assert!(
        body.capacity() <= MAX_FRAME_BYTES,
        "capacity {} for a {MAX_FRAME_BYTES}-byte body",
        body.capacity()
    );
    assert!(
        peak <= MAX_FRAME_BYTES,
        "a {MAX_FRAME_BYTES}-byte body allocated {peak} bytes at once"
    );
}
