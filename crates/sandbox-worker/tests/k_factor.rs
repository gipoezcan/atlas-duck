//! Heap expansion factor `k`, Jira half (plan M8 Task 25; spec §9.4 `k`, §15 V16; PD-131, PD-140).
//!
//! In process, through the real `Engine::deliver` path: a run makes one `atlas.all` call and holds
//! the answer; the host's frame text (the whole of it is a QuickJS string while `JSON.parse`
//! builds the tree, PD-131) is delivered, and the allocator's count gives the peak during the
//! delivery (`k_peak`, the figure invariant 1 uses, PD-140) and what stays after a GC
//! (`k_retained`). The limit is 4 GiB so the peak is observable, never clipped. No child process
//! starts and `confine::apply` is never called. Every body runs on an 8 MiB thread (the worker's
//! main-thread stack).
//!
//! The 1 and 4 MiB sizes run everywhere; the 16 MiB size is `#[ignore]`d and runs in the CI step
//! "M8 k measurement" (Linux leg). Run with `--nocapture` to see the `K` lines.

#[path = "common/fixtures.rs"]
mod fixtures;

use std::io;

use atlas_duck_ipc::sandbox::script::{InstanceInfo, WorkerInit, encode_response};
use atlas_duck_ipc::sandbox::{HostCall, HostCallResult, ScriptLimits};
use atlas_duck_sandbox_worker::script::{Engine, HostPort, Settled};
use fixtures::{MIB, TextMix, jira_dense_search, jira_star_all_search};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Runs `body` on an 8 MiB thread and turns its `Err(String)` into a test failure.
fn big_stack(body: impl FnOnce() -> Result<(), String> + Send + 'static) -> TestResult {
    let handle = std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(body)?;
    match handle.join() {
        Ok(result) => result.map_err(Into::into),
        Err(_) => Err("the test body panicked".into()),
    }
}

fn e<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

/// A `HostPort` that drops every frame: the measurement needs only the call's id (1).
struct NullHost;

impl HostPort for NullHost {
    fn send_call(&mut self, _id: u64, _call: &HostCall) -> io::Result<()> {
        Ok(())
    }

    fn send_log(&mut self, _line: &str) -> io::Result<()> {
        Ok(())
    }
}

/// One measurement: sizes in bytes, the factors derived from them.
struct Measured {
    fixture: String,
    /// UTF-8 length of the result's JSON text.
    bytes: usize,
    /// Peak count during `deliver`, minus the count before it.
    heap_peak: usize,
    /// Count after the GC, minus the count before `deliver`.
    retained: usize,
}

impl Measured {
    fn k_peak(&self) -> f64 {
        self.heap_peak as f64 / self.bytes.max(1) as f64
    }

    fn k_retained(&self) -> f64 {
        self.retained as f64 / self.bytes.max(1) as f64
    }
}

/// The line the CI step greps: `K fixture=.. bytes=.. heap_peak=.. k_peak=.. k_retained=..`.
fn k_line(m: &Measured) -> String {
    format!(
        "K fixture={} bytes={} heap_peak={} k_peak={:.2} k_retained={:.2}",
        m.fixture,
        m.bytes,
        m.heap_peak,
        m.k_peak(),
        m.k_retained()
    )
}

/// The run: one `atlas.all` call (id 1), whose answer `main` stores in a global before it
/// returns, so the parsed tree stays reachable through the GC. (A local kept alive by a
/// never-settling promise would not: nothing references that promise, so QuickJS collects it.)
const HOLD: &str = "globalThis.held = await atlas.all('jira.search', { jql: 'project = KFAC', fields: ['*all'] });\n\
                    return 1;";

/// Delivers `value` as the answer of the run's one `atlas.all` call and measures the heap.
fn measure(fixture: &str, value: &Value) -> Result<Measured, String> {
    let bytes = serde_json::to_string(value).map_err(e)?.len();
    let frame =
        String::from_utf8(encode_response(1, &HostCallResult::Ok(value.clone()))).map_err(e)?;
    let mut engine = Engine::new(&init(HOLD), NullHost).map_err(e)?;
    engine.start().map_err(e)?;
    match engine.drain_jobs() {
        Settled::Pending { outstanding: 1 } => {}
        other => return Err(format!("after start: {other:?}")),
    }
    let meter = engine.meter().clone();
    let before = meter.in_use();
    meter.reset_peak();
    engine.deliver(&frame).map_err(e)?;
    // Read before any GC and before the continuation runs.
    let heap_peak = meter.peak().saturating_sub(before);
    match engine.drain_jobs() {
        Settled::Result(text) if text == "1" => {}
        other => return Err(format!("after deliver: {other:?}")),
    }
    engine.run_gc();
    let retained = meter.in_use().saturating_sub(before);
    Ok(Measured {
        fixture: fixture.to_owned(),
        bytes,
        heap_peak,
        retained,
    })
}

fn init(source: &str) -> WorkerInit {
    WorkerInit {
        source: source.to_owned(),
        args: json!({}),
        // 4 GiB: far above any fixture, so the allocator never refuses and the peak is the real one.
        limits: ScriptLimits {
            heap_mb: 4096,
            ..ScriptLimits::default()
        },
        read_op_ids: vec!["jira.search".to_owned()],
        instances: vec![InstanceInfo {
            alias: "prod".to_owned(),
            product: "jira".to_owned(),
            is_default: true,
        }],
    }
}

/// Every shape (text-heavy `all`, small-object `dense`) and text mix at every size, one `K` line
/// each. Asserts `k_retained > 1` (the held answer is in the tree) and `k_peak - k_retained >=
/// 0.5`: the peak is a running maximum, so only the gap proves that the host frame's text was
/// live next to the tree at the peak (PD-131; the ascii mix measures about 1.0, one frame).
fn run_sizes(mibs: &'static [usize]) -> TestResult {
    big_stack(move || {
        for &mib in mibs {
            for (shape, make) in [
                (
                    "all",
                    jira_star_all_search as fn(u64, TextMix, usize) -> Value,
                ),
                ("dense", jira_dense_search),
            ] {
                for mix in TextMix::ALL {
                    let value = make(0x5eed, mix, mib * MIB);
                    let name = format!("jira-{shape}-{}", mix.name());
                    let m = measure(&name, &value)?;
                    println!("{}", k_line(&m));
                    if !whole_frame_live(&m) {
                        return Err(format!("{}: {}", name, k_line(&m)));
                    }
                }
            }
        }
        Ok(())
    })
}

/// `k_retained > 1` and the peak exceeds what stays by at least half the result's size.
fn whole_frame_live(m: &Measured) -> bool {
    m.k_retained() > 1.0 && m.k_peak() - m.k_retained() >= 0.5
}

#[test]
fn k_jira_star_all_search_1_and_4_mib() -> TestResult {
    run_sizes(&[1, 4])
}

#[test]
#[ignore = "CI step M8 k measurement"]
fn k_jira_star_all_search_16_mib() -> TestResult {
    run_sizes(&[16])
}

#[test]
fn k_records_line_format() {
    let m = Measured {
        fixture: "jira-all-mixed".to_owned(),
        bytes: 1000,
        heap_peak: 12_000,
        retained: 9_500,
    };
    assert_eq!(
        k_line(&m),
        "K fixture=jira-all-mixed bytes=1000 heap_peak=12000 k_peak=12.00 k_retained=9.50"
    );
}

#[test]
fn k_fixture_has_non_latin1_text() {
    let target = MIB;
    let mixed = jira_star_all_search(7, TextMix::Mixed, target);
    let text = serde_json::to_string(&mixed).unwrap_or_default();
    // Under the target by less than one issue, and not empty.
    assert!(
        text.len() <= target && text.len() > target - 64 * 1024,
        "{}",
        text.len()
    );
    assert_eq!(
        mixed["issues"].as_array().map(Vec::len),
        mixed["total"].as_u64().map(|n| n as usize)
    );
    let issue = &mixed["issues"][0];
    let customs = issue["fields"].as_object().map_or(0, |f| {
        f.keys().filter(|k| k.starts_with("customfield_")).count()
    });
    assert_eq!(customs, 50);
    assert!(issue["renderedFields"]["description"].is_string());
    // Text beyond Latin-1 (CJK), a supplementary-plane character (emoji: a surrogate pair in
    // QuickJS's 16-bit strings) and Latin-1 umlauts are all there.
    assert!(text.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)));
    assert!(text.chars().any(|c| c > '\u{ffff}'));
    assert!(text.chars().any(|c| matches!(c, 'ä' | 'ö' | 'ü')));
    // The same seed gives the same text; the ASCII mix has no character above U+007F.
    assert_eq!(
        text,
        serde_json::to_string(&jira_star_all_search(7, TextMix::Mixed, target)).unwrap_or_default()
    );
    let ascii =
        serde_json::to_string(&jira_star_all_search(7, TextMix::Ascii, target)).unwrap_or_default();
    assert!(!ascii.is_empty() && ascii.is_ascii());
    // Sparse and wide frames really hold non-Latin-1 text, in both shapes; ascii never does.
    for make in [jira_star_all_search, jira_dense_search] {
        for mix in [TextMix::Sparse, TextMix::Wide] {
            let text = serde_json::to_string(&make(7, mix, target)).unwrap_or_default();
            assert!(
                text.chars().any(|c| c > '\u{ff}'),
                "{} has no non-Latin-1 text",
                mix.name()
            );
        }
        let ascii = serde_json::to_string(&make(7, TextMix::Ascii, target)).unwrap_or_default();
        assert!(ascii.is_ascii());
    }
}

#[test]
fn k_sparse_texts_each_have_a_wide_character() {
    // Every long string of the sparse fixture (descriptions and comment bodies, 40+ words) is
    // 16-bit in QuickJS, not 98 % of them.
    let value = jira_star_all_search(7, TextMix::Sparse, MIB);
    let mut long = 0;
    for issue in value["issues"].as_array().into_iter().flatten() {
        let mut texts = vec![issue["fields"]["description"].as_str()];
        for c in issue["fields"]["comment"]["comments"]
            .as_array()
            .into_iter()
            .flatten()
        {
            texts.push(c["body"].as_str());
        }
        for t in texts {
            let t = t.unwrap_or_default();
            assert!(t.split(' ').count() >= 40);
            assert!(t.chars().any(|c| c > '\u{ff}'), "8-bit text: {t}");
            long += 1;
        }
    }
    assert!(long > 20, "{long}");
}

#[test]
fn k_dense_fixture_is_dense_and_sized() {
    let target = MIB;
    let value = jira_dense_search(7, TextMix::Mixed, target);
    let text = serde_json::to_string(&value).unwrap_or_default();
    assert!(
        text.len() <= target && text.len() > target - 64 * 1024,
        "{}",
        text.len()
    );
    let issue = &value["issues"][0];
    assert!(issue["changelog"]["histories"][0]["items"][0]["field"].is_string());
    assert!(issue["fields"]["issuelinks"][0]["outwardIssue"]["key"].is_string());
    assert!(issue["fields"]["worklog"]["worklogs"][0]["timeSpentSeconds"].is_u64());
    assert_eq!(
        issue["fields"]["watcherIds"].as_array().map(Vec::len),
        Some(100)
    );
    // Null-heavy, and the same seed gives the same text.
    assert!(text.matches("null").count() > 500);
    assert_eq!(
        text,
        serde_json::to_string(&jira_dense_search(7, TextMix::Mixed, target)).unwrap_or_default()
    );
}

/// The whole-frame assertion bites: a measurement whose peak is only what stays (a delivery that
/// parsed from a Rust buffer or freed the text early) is refused, a frame-sized gap is accepted.
#[test]
fn k_whole_frame_assertion_bites() {
    let m = |heap_peak, retained| Measured {
        fixture: "x".to_owned(),
        bytes: 1000,
        heap_peak,
        retained,
    };
    assert!(whole_frame_live(&m(3500, 2500)));
    assert!(!whole_frame_live(&m(2500, 2500)));
    assert!(!whole_frame_live(&m(2900, 2500)));
    assert!(!whole_frame_live(&m(900, 800)));
}
