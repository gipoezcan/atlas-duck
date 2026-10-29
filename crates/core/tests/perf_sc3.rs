#![cfg(feature = "testing")]
//! SC3 performance (§1.4, §13 Performance) and M3 M-15: the Rust half of the preview budget, the
//! 16 MiB candidate's paging bound and the read-to-queued latency of a release-cap body.
//!
//! The thresholds are regression bounds, not targets, and apply in the optimized run (a CI step
//! of its own, see `enforced`). A debug build asserts the results are right and prints the
//! numbers. A bound is only ever widened, with a ledger note. The rest of the first-screen budget (~700 ms) belongs to the webview and is
//! measured by `p01_first_screen_under_1s` in the end-to-end suite.

mod common;

use std::time::{Duration, Instant};

use atlas_duck_atlassian::testing::{MockDc, fixtures};
use atlas_duck_core::RunEnd;
use atlas_duck_core::testing::{FakeScriptRunner, Harness, ScriptPlan, host_call};
use atlas_duck_preview::{Platform, Preview, render};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::confluence::{mount_attachments, mount_page, mount_users, page_with_storage};
use common::jira::{full_issue, mount_create_stages, mount_issue, mount_search};
use common::{TestError, TestResult, de, request_id};
use serde_json::{Value, json};

/// Preview build and `render::document` each (P-01).
const P01_BUDGET: Duration = Duration::from_millis(300);
/// Open plus the first raw page of a 16 MiB candidate (P-02).
const P02_BUDGET: Duration = Duration::from_secs(2);
/// Submit to queued of a 16 MiB read (M3 M-15).
const M15_BUDGET: Duration = Duration::from_secs(10);

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

/// Whether the bounds apply. The `testing` features refuse to compile without debug assertions
/// (`compile_error!` in core, audit and atlassian), so the optimized run of this file is a
/// release build with `CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true` (an environment override, so
/// no profile in a `Cargo.toml` carries them) and `ATLAS_DUCK_PERF_ENFORCE=1`. A plain debug run
/// checks the results and prints the numbers only.
fn enforced() -> bool {
    !cfg!(debug_assertions) || std::env::var_os("ATLAS_DUCK_PERF_ENFORCE").is_some_and(|v| v == "1")
}

/// Prints `what`'s time; when the bounds are enforced it must be within `budget`.
fn within(what: &str, took: Duration, budget: Duration) {
    let enforce = enforced();
    println!(
        "perf_sc3 {what}: {:.1} ms (bound {} ms, {})",
        took.as_secs_f64() * 1000.0,
        budget.as_millis(),
        if enforce { "enforced" } else { "not enforced" }
    );
    assert!(
        !enforce || took <= budget,
        "{what} took {took:?}, over the regression bound {budget:?}"
    );
}

async fn queued(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
    let id = request_id(&env)?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    Ok(id)
}

/// Opens `id` (which commits `PREVIEW_SHOWN`), then times the build of the already-opened
/// revision (no audit append) and `render::document` over it.
fn build_and_render(h: &Harness, id: &str, what: &str) -> Result<Preview, TestError> {
    let decisions = h.decisions();
    let t = Instant::now();
    let first = decisions.preview_fetch(id, None).map_err(de)?;
    println!(
        "perf_sc3 {what} open (build + PREVIEW_SHOWN append): {:.1} ms",
        t.elapsed().as_secs_f64() * 1000.0
    );
    let t = Instant::now();
    let built = decisions.preview_fetch(id, None).map_err(de)?;
    within(&format!("{what} preview build"), t.elapsed(), P01_BUDGET);
    assert_eq!(built.preview.candidate_rev, first.preview.candidate_rev);

    let t = Instant::now();
    let doc = render::document(
        atlas_duck_preview::Lang::En,
        &built.preview,
        Platform::current(),
    );
    within(&format!("{what} render::document"), t.elapsed(), P01_BUDGET);
    assert!(doc.contains("<html"), "{what}: not a document");
    Ok(built.preview)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p01_rust_preview_build_and_document_under_budget() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;

    // The default `jira.issue.get`: a parent, links and a custom field.
    mount_issue(mock, "ABC-7", &full_issue("ABC-7")).await;
    let id = queued(&h, "jira.issue.get", json!({ "key": "ABC-7" })).await?;
    let p = build_and_render(&h, &id, "jira.issue.get")?;
    assert!(
        render::document(atlas_duck_preview::Lang::En, &p, Platform::current())
            .contains("Login page times out"),
        "the issue card shows the summary"
    );

    // `jira.search`, a full page of 50 rows.
    mount_search(mock, 50, |n| {
        json!({
            "summary": format!("Issue {n}: login page times out under load"),
            "status": {"id": "3", "name": "In Progress"},
            "assignee": {"name": "jdoe", "key": "JIRAUSER1", "displayName": "Jane Doe"},
            "labels": ["web", "perf"]
        })
    })
    .await;
    let id = queued(
        &h,
        "jira.search",
        json!({ "jql": "project = ABC", "max": 50 }),
    )
    .await?;
    build_and_render(&h, &id, "jira.search 50 rows")?;

    // `jira.issue.create` with a description (a write: enrichment ran before it queued).
    mount_create_stages(mock).await;
    let description =
        "h1. Steps\n\n* Open the *login* page.\n* Wait for the _spinner_.\n\n".repeat(40);
    let id = queued(
        &h,
        "jira.issue.create",
        json!({ "project": "ABC", "issuetype": "Bug", "summary": "Login page times out",
                "description": description }),
    )
    .await?;
    build_and_render(&h, &id, "jira.issue.create")?;
    Ok(())
}

/// P-01 for scripts (§1.4 SC3, "a 200-row script result"): a script that read one Jira search page
/// returns 200 issue summaries with 6 fields each, through the fake runner. The preview build and
/// `render::document` are bounded like the other scenarios; the script does not need Confluence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p01_script_200_rows_preview_under_budget() -> TestResult {
    let rows: Vec<Value> = (0..200)
        .map(|n| {
            json!({
                "key": format!("ABC-{}", n + 1),
                "summary": format!("Issue {n}: login page times out under load"),
                "status": "In Progress",
                "assignee": "Jane Doe",
                "priority": "High",
                "labels": "web, perf"
            })
        })
        .collect();
    let runner = FakeScriptRunner::new(vec![ScriptPlan::new(
        vec![host_call(
            1,
            "jira.search",
            json!({ "jql": "project = ABC", "max": 50 }),
        )],
        RunEnd::Result {
            value: Value::Array(rows),
            logs: Vec::new(),
            stderr: String::new(),
        },
    )]);
    let h = Harness::builder()
        .jira("jira-main")
        .scripts(runner)
        .start()
        .await?;
    mount_search(jira(&h)?, 50, |n| {
        json!({
            "summary": format!("Issue {n}: login page times out under load"),
            "status": {"id": "3", "name": "In Progress"},
            "assignee": {"name": "jdoe", "key": "JIRAUSER1", "displayName": "Jane Doe"},
            "labels": ["web", "perf"]
        })
    })
    .await;

    let env = h
        .submit_script(json!({ "source": "return 1;", "args": {} }))
        .await;
    let id = request_id(&env)?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let p = build_and_render(&h, &id, "script 200 rows")?;
    let doc = render::document(atlas_duck_preview::Lang::En, &p, Platform::current());
    assert!(
        doc.contains("Issue 0: login page times out"),
        "the card shows the first row"
    );
    assert!(
        doc.contains("Issue 199: login page times out"),
        "the card shows the last row"
    );
    // All 6 fields reach the card, not just the key and the summary.
    for field in ["ABC-200", "In Progress", "Jane Doe", "High", "web, perf"] {
        assert!(doc.contains(field), "the card shows the field {field}");
    }
    Ok(())
}

fn wiki(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("wiki").ok_or_else(|| "no confluence mock".into())
}

/// P-01 for Confluence (§1.4 SC3): a ~5,000-word `confluence.page.get` (default Markdown, the four
/// mentions resolved) and a small `confluence.page.update` diff.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p01_confluence_page_and_update_diff_under_budget() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;

    let storage = fixtures::confluence_page_5000_words(7);
    mount_page(mock, "65537", &page_with_storage(&storage)).await;
    let users: Vec<(&str, Option<&str>)> = fixtures::PAGE_5000_MENTION_KEYS
        .iter()
        .map(|k| (*k, Some("jdoe")))
        .collect();
    mount_users(mock, &users).await;
    let id = queued(&h, "confluence.page.get", json!({ "id": "65537" })).await?;
    let p = build_and_render(&h, &id, "confluence.page.get 5000 words")?;
    let doc = render::document(atlas_duck_preview::Lang::En, &p, Platform::current());
    assert!(
        doc.contains("Release checklist"),
        "the card shows the title"
    );
    assert!(doc.contains("Section 1"), "the card shows the body");

    // A short page: two of its three paragraphs change.
    let mut short =
        page_with_storage("<p>Check the build.</p><p>Tag the release.</p><p>Notify the team.</p>");
    short["id"] = json!("65538");
    mount_page(mock, "65538", &short).await;
    let id = queued(
        &h,
        "confluence.page.update",
        json!({ "id": "65538", "base_version": 7,
                "body": "Check the build twice.\n\nTag the release.\n\nNotify the whole team." }),
    )
    .await?;
    let p = build_and_render(&h, &id, "confluence.page.update small diff")?;
    let doc = render::document(atlas_duck_preview::Lang::En, &p, Platform::current());
    assert!(
        doc.contains("Release checklist"),
        "the card shows the title"
    );
    assert!(
        doc.contains("Check the build twice"),
        "the diff shows the changed line"
    );
    Ok(())
}

/// T23 measurements (T15 m-3, T20a m-6), print-only, no bound: the card of a page update near
/// the 16 MiB body limit and of a 10 MiB upload. Every enrichment builds the same card once more
/// for the queue row's caution count (off the entry lock since T23b). Ignored (T23 review I-3):
/// in a debug build it takes about a minute and waits up to 60 s for each enrichment, which must
/// not make the enforced P-01 test red. Run it alone:
/// `cargo test -p atlas-duck-core --features testing --test perf_sc3 -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "print-only measurement of the largest bodies; about a minute in a debug build"]
async fn t23_largest_page_update_and_upload_measured() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let mut big = page_with_storage(&"<p>Release note line.</p>".repeat(15 * 1024 * 1024 / 26));
    big["id"] = json!("65539");
    println!(
        "perf_sc3 big page storage: {} bytes",
        big["body"]["storage"]["value"].as_str().map_or(0, str::len)
    );
    mount_page(mock, "65539", &big).await;
    let id = queued_within(
        &h,
        "confluence.page.update",
        json!({ "id": "65539", "base_version": 7, "body": "Release note line." }),
        "confluence.page.update ~15 MiB page",
    )
    .await?;
    measure(&h, &id, "confluence.page.update ~15 MiB page")?;

    mount_page(mock, "65537", &page_with_storage("<p>Attachments.</p>")).await;
    mount_attachments(
        mock,
        "65537",
        &json!({"results": [], "start": 0, "limit": 50, "size": 0, "_links": {}}),
    )
    .await;
    let file: Vec<u8> = (0..10 * 1024 * 1024u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    let id = queued_within(
        &h,
        "confluence.attachment.upload",
        json!({ "id": "65537", "filename": "big.bin", "content_base64": STANDARD.encode(&file) }),
        "confluence.attachment.upload 10 MiB",
    )
    .await?;
    measure(&h, &id, "confluence.attachment.upload 10 MiB")?;
    Ok(())
}

/// [`queued`] with a 60 s wait for the enrichment of a large body, printing its submit-to-queued
/// time.
async fn queued_within(
    h: &Harness,
    op: &str,
    params: Value,
    what: &str,
) -> Result<String, TestError> {
    let t = Instant::now();
    let env = h.submit(op, params).await;
    let id = request_id(&env)?;
    h.queued(&id, 60_000).await.ok_or("never queued")?;
    println!(
        "perf_sc3 {what} submit to queued: {:.1} ms",
        t.elapsed().as_secs_f64() * 1000.0
    );
    Ok(id)
}

/// Prints the open, the build and `render::document` of `id` (no bound: see
/// [`build_and_render`] for the bounded form).
fn measure(h: &Harness, id: &str, what: &str) -> Result<(), TestError> {
    let decisions = h.decisions();
    let t = Instant::now();
    decisions.preview_fetch(id, None).map_err(de)?;
    println!(
        "perf_sc3 {what} open: {:.1} ms",
        t.elapsed().as_secs_f64() * 1000.0
    );
    let t = Instant::now();
    let built = decisions.preview_fetch(id, None).map_err(de)?;
    println!(
        "perf_sc3 {what} preview build: {:.1} ms",
        t.elapsed().as_secs_f64() * 1000.0
    );
    let t = Instant::now();
    let doc = render::document(
        atlas_duck_preview::Lang::En,
        &built.preview,
        Platform::current(),
    );
    println!(
        "perf_sc3 {what} render::document: {:.1} ms ({} bytes)",
        t.elapsed().as_secs_f64() * 1000.0,
        doc.len()
    );
    Ok(())
}

/// A Jira issue just under the 16 MiB release cap: a summary of one letter.
fn big_issue_body() -> String {
    let summary = "m".repeat(16 * 1024 * 1024 - 4096);
    json!({ "key": "ABC-1", "fields": { "summary": summary } }).to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p02_16mib_candidate_open_under_threshold() -> TestResult {
    let h = Harness::jira().await?;
    jira(&h)?
        .json("/rest/api/2/issue/ABC-1", 200, &big_issue_body())
        .await;
    let id = queued(&h, "jira.issue.get", json!({ "key": "ABC-1" })).await?;
    let rev = h
        .approver()
        .item(&id)
        .ok_or("not in the queue")?
        .candidate_rev;

    let decisions = h.decisions();
    let t = Instant::now();
    let opened = decisions.preview_fetch(&id, Some(rev)).map_err(de)?;
    let open = t.elapsed();
    let t = Instant::now();
    let page = decisions.raw_page(&id, rev, 0).map_err(de)?;
    let first_page = t.elapsed();
    println!(
        "perf_sc3 p02 open {:.1} ms, first raw page {:.1} ms",
        open.as_secs_f64() * 1000.0,
        first_page.as_secs_f64() * 1000.0
    );
    within("p02 open + first raw page", open + first_page, P02_BUDGET);

    // Correct full-candidate counts: the pager is over all of it, the page is a slice.
    let raw = &opened.preview.raw;
    assert_eq!(raw.page_count, 64);
    assert!(raw.total_bytes > 16 * 1024 * 1024 - 4096);
    assert_eq!((page.page, page.page_count), (0, 64));
    assert_eq!(page.total_bytes, raw.total_bytes);
    assert!(!page.bytes.is_empty());
    assert!((page.bytes.len() as u64) < raw.total_bytes);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m15_16mib_read_to_queued_latency() -> TestResult {
    let h = Harness::jira().await?;
    jira(&h)?
        .json("/rest/api/2/issue/ABC-1", 200, &big_issue_body())
        .await;
    let t = Instant::now();
    let env = h.submit("jira.issue.get", json!({ "key": "ABC-1" })).await;
    let id = request_id(&env)?;
    let item = h.queued(&id, 60_000).await.ok_or("never queued")?;
    let took = t.elapsed();
    assert_eq!(item.candidate_rev.counter, 1);
    within("m15 16 MiB read to queued", took, M15_BUDGET);
    Ok(())
}
