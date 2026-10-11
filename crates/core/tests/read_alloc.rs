//! I-37: the heap one read stage takes over a release-cap-sized body. A read holds its fetch slot
//! through recording and candidate building, outside the candidate cache's accounting, and up to
//! eight reads do so at once (§5.2 memory budget): a stage may hold what it builds, but no
//! second full-size copy and no `Vec` that doubled past its contents.
//!
//! Own test binary: the counting allocator is process-wide, so this file has a single `#[test]`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use atlas_duck_atlassian::UpstreamResponse;
use atlas_duck_core::engine::cache::Candidate;
use atlas_duck_core::payloads::response_json;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

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

/// `f`'s result and its peak heap above the live bytes at its start.
fn peak_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let out = f();
    (out, PEAK.load(Ordering::SeqCst) - base)
}

/// Room for keys, small values and the allocator's rounding beside the one full-size buffer.
const SLACK: usize = 64 * 1024;

#[test]
fn read_stages_hold_one_copy_of_a_16_mib_body() -> TestResult {
    // The I-37 fixture's shape: an issue whose summary is ~16 MiB of one letter.
    let summary = "m".repeat((16 << 20) - 4096);
    let body = json!({ "key": "ABC-1", "fields": { "summary": summary } }).to_string();
    drop(summary);

    // The record's `{status, content_type, body}`: the body text once, not serialized into a
    // second `Value`.
    let r = UpstreamResponse {
        status: 200,
        content_type: Some("application/json".into()),
        body: body.clone().into_bytes(),
    };
    let (rec, peak) = peak_during(|| response_json(&r));
    assert_eq!(rec["body"]["text"].as_str(), Some(body.as_str()));
    assert!(
        peak <= body.len() + SLACK,
        "response_json took {peak} bytes for a {} byte body",
        body.len()
    );
    drop((r, rec));

    // The candidate: its bytes in one allocation of their length (the tree is moved in).
    let v: Value = serde_json::from_str(&body)?;
    let (c, peak) = peak_during(|| Candidate::from_value(v));
    let c = c?;
    assert_eq!(&c.bytes()[..], body.as_bytes());
    assert!(
        peak <= body.len() + SLACK,
        "Candidate::from_value took {peak} bytes for {} serialized bytes",
        body.len()
    );
    Ok(())
}
