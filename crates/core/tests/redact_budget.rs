//! The canonical-form work budget (review T14 I-1, N-1, N-2), measured: peak heap during one
//! text's expansion stays within the documented per-text limit, and a candidate made of many
//! small crafted texts is bounded in total and blocks instead of stalling.
//!
//! Own test binary: the counting allocator sees every thread of the process, so this file has a
//! single `#[test]`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use atlas_duck_core::redact::views::{TEXT_CEIL, TEXT_FACTOR, TEXT_FLOOR, views};
use atlas_duck_core::redact::{BlockReason, RedactionOp, apply};
use atlas_duck_registry::RedactionRules;
use serde_json::{Map, Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to `System` unchanged; only counts the bytes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let now = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            if new_size >= layout.size() {
                let now = LIVE.fetch_add(new_size - layout.size(), Ordering::Relaxed) + new_size
                    - layout.size();
                PEAK.fetch_max(now, Ordering::Relaxed);
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Peak heap above the level at the start of `f`.
fn peak_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let out = f();
    (out, PEAK.load(Ordering::Relaxed).saturating_sub(base))
}

fn text_limit(len: usize) -> usize {
    len.saturating_mul(TEXT_FACTOR).clamp(TEXT_FLOOR, TEXT_CEIL)
}

/// The review's 64-byte unit that expands to about 112 forms.
const BLOWUP: &str = "%E2%80%8B&&amp%253B%%32%35u\u{308}\u{200b}&uuml&amp;%41+&#43;&#x200B;&uuml";

const NO_RULES: RedactionRules = RedactionRules {
    copies: &[],
    mirrors: &[],
    url_fields: &[],
};

fn mask(text: &str) -> RedactionOp {
    RedactionOp::MaskText {
        text: text.into(),
        every_occurrence: true,
        at: None,
    }
}

#[test]
fn work_budget_bounds_memory_and_time() -> TestResult {
    // N-1: one text's expansion never holds more than its per-text limit, crafted or not.
    for (name, value) in [
        ("crafted", BLOWUP.repeat(32 * 1024)),
        ("entities", "&lt;".repeat(512 * 1024)),
        ("numeric", "&#65;".repeat(400 * 1024)),
        (
            "mixed",
            "<p>Grüße an M&uuml;ller &amp; Co, 50% + 3</p>\n".repeat(40 * 1024),
        ),
    ] {
        let (v, peak) = peak_during(|| views(&value));
        let limit = text_limit(value.len());
        eprintln!(
            "{name}: len {} peak {peak} limit {limit} over_budget {}",
            value.len(),
            v.over_budget
        );
        assert!(
            peak <= limit,
            "{name}: peak {peak} > limit {limit} (len {}, over_budget {})",
            value.len(),
            v.over_budget
        );
    }
    let (out, peak) = peak_during(|| {
        apply(
            &json!({"v": "&lt;M&uuml;ller&gt; ".repeat(100 * 1024)}),
            &NO_RULES,
            None,
            &[mask("Müller")],
        )
    });
    assert!(out.blocked.is_empty(), "{:?}", out.blocked);
    let len = 20 * 100 * 1024;
    // The candidate, its released copy and one text's canonical-form work.
    eprintln!("apply: len {len} peak {peak}");
    assert!(peak <= 4 * len + text_limit(len), "apply peak {peak}");

    // N-2: many small crafted texts share one budget per `apply`; once it is spent, the rest
    // block with their paths instead of each expanding in full.
    let mut doc = Map::new();
    for i in 0..1000 {
        doc.insert(format!("t{i:04}"), Value::from(BLOWUP.repeat(32)));
    }
    // A harmless text that is not plain ASCII: alone it costs a few bytes of work.
    doc.insert("zz_after".into(), Value::from("caf{e9} &amp; co"));
    let candidate = Value::Object(doc);
    let started = Instant::now();
    let out = apply(&candidate, &NO_RULES, None, &[mask("zzz")]);
    let elapsed = started.elapsed();
    eprintln!("1001 texts: {elapsed:?}, {} blocked", out.blocked.len());
    let unstable: Vec<&BlockReason> = out
        .blocked
        .iter()
        .filter(|b| matches!(b, BlockReason::UnstableEncoding { .. }))
        .collect();
    // Every crafted text blocks with its path; the harmless one after them blocks too, only
    // because the shared budget is spent by then.
    assert_eq!(unstable.len(), 1001, "{} blocked", unstable.len());
    assert!(unstable.iter().any(|b| b.path() == "zz_after"));
    let alone = apply(
        &json!({"zz_after": "caf{e9} &amp; co"}),
        &NO_RULES,
        None,
        &[mask("zzz")],
    );
    assert!(alone.blocked.is_empty());
    assert!(elapsed < Duration::from_secs(120), "{elapsed:?}");
    Ok(())
}
