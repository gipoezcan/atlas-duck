#![cfg(feature = "testing")]
//! `atlas.all` (M8 Task 13, PD-144, §9.2, §13 I-21/I-22 Jira half): one host call that pages
//! through a paginated read op, one committed `SCRIPT_CALL {call_id, page}` per page before the
//! next request, every page counted against `max_calls`/`max_fetch_mb`, catchable rejections that
//! carry no partial data, and the op's native shape on success.

mod common;

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use atlas_duck_audit::EventType;
use atlas_duck_core::audit_port::AuditPort;
use atlas_duck_core::testing::{FakeScriptRunner, Harness, ScriptPlan, host_call};
use atlas_duck_core::{KillReason, RunEnd};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_ipc::sandbox::{HostCall, HostCallResult};
use common::{TestError, TestResult, request_id};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, Request, Respond, ResponseTemplate};

const SRC: &str = "return 1;";

fn result_end(value: Value) -> RunEnd {
    RunEnd::Result {
        value,
        logs: Vec::new(),
        stderr: String::new(),
    }
}

/// `atlas.all("jira.search", params)`.
fn all_call(id: u64, params: Value) -> HostCall {
    let mut call = host_call(id, "jira.search", params);
    call.all = true;
    call
}

fn search_all(id: u64, max: u64) -> HostCall {
    all_call(id, json!({ "jql": "project = ABC", "max": max }))
}

/// What the search mock saw of one page request.
#[derive(Debug, Clone, Copy)]
struct Hit {
    start_at: u64,
    max_results: u64,
    /// `SCRIPT_CALL` records committed when the request arrived.
    committed: usize,
}

/// The paged `POST /rest/api/2/search` answer, keyed on the body's `startAt`: `total` issues
/// (`ABC-<n>`), at most `page` per request (fewer when the request asks fewer), each with a
/// summary of `pad` bytes. Page 0 reports `first_total` (when set) instead of `total`, so a test
/// tells the first page's totals from the last page's. `server_max` clamps the page size as a
/// server does (the page then reports it as `maxResults`). `exact` pads every page body with
/// trailing whitespace to that many bytes. `stall_at` delays the answer at that offset.
#[derive(Clone)]
struct Pages {
    port: Arc<dyn AuditPort>,
    template: ResponseTemplate,
    total: u64,
    first_total: Option<u64>,
    server_max: Option<u64>,
    pad: usize,
    exact: Option<usize>,
    stall_at: Option<(u64, Duration)>,
    /// Answers this status (no body) at that offset.
    status_at: Option<(u64, u16)>,
    hits: Arc<Mutex<Vec<Hit>>>,
}

impl Pages {
    fn new(h: &Harness, total: u64) -> Result<Pages, TestError> {
        let mock = h.mock("jira-main").ok_or("no jira mock")?;
        Ok(Pages {
            port: h.port(),
            template: mock.response(200),
            total,
            first_total: None,
            server_max: None,
            pad: 0,
            exact: None,
            stall_at: None,
            status_at: None,
            hits: Arc::new(Mutex::new(Vec::new())),
        })
    }

    async fn mount(self, h: &Harness) -> Result<Arc<Mutex<Vec<Hit>>>, TestError> {
        let mock = h.mock("jira-main").ok_or("no jira mock")?;
        let hits = self.hits.clone();
        Mock::given(method("POST"))
            .and(path(mock.path("/rest/api/2/search")))
            .respond_with(self)
            .with_priority(1)
            .mount(mock.server())
            .await;
        Ok(hits)
    }

    fn committed_calls(&self) -> usize {
        self.port
            .recent_headers(Duration::from_secs(3600))
            .map(|hs| {
                hs.iter()
                    .filter(|h| h.event_type == EventType::SCRIPT_CALL)
                    .count()
            })
            .unwrap_or(usize::MAX)
    }
}

impl Respond for Pages {
    fn respond(&self, r: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        let start = body["startAt"].as_u64().unwrap_or(0);
        let asked = body["maxResults"].as_u64().unwrap_or(50);
        self.hits
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Hit {
                start_at: start,
                max_results: asked,
                committed: self.committed_calls(),
            });
        if let Some((at, status)) = self.status_at
            && at == start
        {
            return ResponseTemplate::new(status);
        }
        let size = self.server_max.map_or(asked, |m| m.min(asked));
        let count = size.min(self.total.saturating_sub(start));
        let total = match self.first_total {
            Some(t) if start == 0 => t,
            _ => self.total,
        };
        let issues: Vec<Value> = (start..start + count)
            .map(|i| {
                json!({
                    "id": (10_001 + i).to_string(),
                    "key": format!("ABC-{}", i + 1),
                    "fields": { "summary": format!("{}{}", i + 1, "s".repeat(self.pad)) }
                })
            })
            .collect();
        let mut text = json!({
            "expand": "schema,names",
            "startAt": start,
            "maxResults": size,
            "total": total,
            "issues": issues,
        })
        .to_string();
        if let Some(n) = self.exact {
            let fill = n.saturating_sub(text.len());
            text.push_str(&" ".repeat(fill));
        }
        let t = self.template.clone().set_body_raw(text, "application/json");
        match self.stall_at {
            Some((at, d)) if at == start => t.set_delay(d),
            _ => t,
        }
    }
}

async fn harness(plans: Vec<ScriptPlan>) -> Result<(Harness, Arc<FakeScriptRunner>), TestError> {
    let runner = FakeScriptRunner::new(plans);
    let h = Harness::builder()
        .jira("jira-main")
        .scripts(runner.clone())
        .start()
        .await?;
    h.mock("jira-main")
        .ok_or("no jira mock")?
        .json(
            "/rest/api/2/issue/ABC-1",
            200,
            atlas_duck_atlassian::testing::fixtures::JIRA_ISSUE,
        )
        .await;
    Ok((h, runner))
}

async fn submit(h: &Harness, params: Value) -> Result<String, TestError> {
    let env = h.submit_script(params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    request_id(&env)
}

async fn wait_for<F: Fn() -> bool>(what: &str, f: F) -> TestResult {
    for _ in 0..1000 {
        if f() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("timed out waiting for {what}").into())
}

fn hits_of(hits: &Mutex<Vec<Hit>>) -> Vec<Hit> {
    hits.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

/// The `SCRIPT_CALL` records of a request, in order.
async fn script_calls(h: &Harness, id: &str) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(t, _)| *t == EventType::SCRIPT_CALL)
        .map(|(_, p)| p)
        .collect())
}

/// The answers as `ok` or the rejection class (an answer can be megabytes of issues).
fn outline(results: &[HostCallResult]) -> Vec<String> {
    results
        .iter()
        .map(|r| match r {
            HostCallResult::Ok(_) => "ok".to_owned(),
            HostCallResult::Rejected { class, .. } => class.clone(),
        })
        .collect()
}

/// The single answer of a run as `(class, details)` of a rejection.
fn single_rejection(results: &[HostCallResult]) -> Result<(String, Value), TestError> {
    match results {
        [HostCallResult::Rejected { class, details }] => Ok((class.clone(), details.clone())),
        other => Err(format!("expected one rejection, got {:?}", outline(other)).into()),
    }
}

fn keys(result: &Value) -> Vec<String> {
    result["issues"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|i| i["key"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i22_all_native_shape_items_concatenated_totals_unchanged() -> TestResult {
    let (h, runner) = harness(vec![ScriptPlan::new(
        vec![search_all(1, 100)],
        result_end(json!(1)),
    )])
    .await?;
    let mut pages = Pages::new(&h, 700)?;
    pages.first_total = Some(750);
    let hits = pages.mount(&h).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    assert_eq!(hits_of(&hits).len(), 7);
    let result = match runner.results().as_slice() {
        [HostCallResult::Ok(v)] => v.clone(),
        other => return Err(format!("unexpected answers: {:?}", outline(other)).into()),
    };
    // The native shape: the first page's object, the items of every page under `issues` in
    // order, the server total as the last page sent it, every other key from the first page.
    let want: Vec<String> = (1..=700).map(|n| format!("ABC-{n}")).collect();
    assert_eq!(keys(&result), want);
    assert_eq!(result["total"], 700);
    assert_eq!(result["startAt"], 0);
    assert_eq!(result["maxResults"], 100);
    assert_eq!(result["expand"], "schema,names");
    let mut names: Vec<&String> = result.as_object().ok_or("not an object")?.keys().collect();
    names.sort();
    assert_eq!(
        names,
        ["expand", "issues", "maxResults", "startAt", "total"]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_each_page_is_a_script_call_counted() -> TestResult {
    let (h, runner) = harness(vec![
        ScriptPlan::new(vec![search_all(1, 100)], result_end(json!(1))).holding(30_000),
    ])
    .await?;
    let hits = Pages::new(&h, 700)?.mount(&h).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    wait_for("the answer", || !runner.results().is_empty()).await?;
    // Audit before effect, per page: page n's request arrived after n `SCRIPT_CALL`s committed.
    let seen = hits_of(&hits);
    assert_eq!(
        seen.iter()
            .map(|s| (s.start_at, s.committed))
            .collect::<Vec<_>>(),
        (0..7u64)
            .map(|n| (n * 100, usize::try_from(n).unwrap_or(0)))
            .collect::<Vec<_>>(),
    );
    assert!(seen.iter().all(|s| s.max_results == 100), "{seen:?}");
    let calls = script_calls(&h, &id).await?;
    assert_eq!(calls.len(), 7);
    for (n, c) in calls.iter().enumerate() {
        assert_eq!(c["call_id"], 1, "{c}");
        assert_eq!(c["page"], n, "{c}");
        assert_eq!(c["op"], "jira.search");
        assert_eq!(c["rejection"], Value::Null);
        assert_eq!(c["pages"], 1, "one response per page record");
        assert_eq!(c["responses"].as_array().map(Vec::len), Some(1));
    }
    // `RunShared.calls` counts pages (the Running list's host calls).
    let running = h.core().running_scripts();
    assert_eq!(running.len(), 1);
    assert_eq!(running[0].host_calls, 7);
    // `SCRIPT_CALL_SENT` once, before the first page.
    let types = h.event_types(&id).await?;
    assert_eq!(
        types,
        [
            EventType::REQUEST_RECEIVED,
            EventType::SCRIPT_STARTED,
            EventType::SCRIPT_CALL_SENT,
            EventType::SCRIPT_CALL,
            EventType::SCRIPT_CALL,
            EventType::SCRIPT_CALL,
            EventType::SCRIPT_CALL,
            EventType::SCRIPT_CALL,
            EventType::SCRIPT_CALL,
            EventType::SCRIPT_CALL,
        ]
    );
    h.handler().cancel(&id).await;
    Ok(())
}

/// The pages count against `max_calls` like calls: a plain call after a 7-page `atlas.all` is the
/// eighth call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_pages_count_against_max_calls_of_later_calls() -> TestResult {
    let plain = host_call(2, "jira.issue.get", json!({ "key": "ABC-1" }));
    let (h, runner) = harness(vec![
        ScriptPlan::new(
            vec![search_all(1, 100), plain.clone()],
            result_end(json!(1)),
        ),
        ScriptPlan::new(vec![search_all(1, 100), plain], result_end(json!(1))),
    ])
    .await?;
    Pages::new(&h, 700)?.mount(&h).await?;
    let fits = submit(&h, json!({ "source": SRC, "limits": { "max_calls": 8 } })).await?;
    h.queued(&fits, 20_000).await.ok_or("never queued")?;
    let over = submit(&h, json!({ "source": SRC, "limits": { "max_calls": 7 } })).await?;
    h.queued(&over, 20_000).await.ok_or("never queued")?;
    match runner.results().as_slice() {
        [
            HostCallResult::Ok(_),
            HostCallResult::Ok(_),
            HostCallResult::Ok(_),
            HostCallResult::Rejected { class, .. },
        ] => assert_eq!(class, "script_limit"),
        other => return Err(format!("unexpected answers: {:?}", outline(other)).into()),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i21_all_over_max_call_result_rejects_without_partial_data() -> TestResult {
    let (h, runner) = harness(vec![ScriptPlan::new(
        vec![search_all(1, 100)],
        result_end(json!(1)),
    )])
    .await?;
    // About 260 KB per page: each page fits 1 MiB alone, four of them together do, five do not.
    let mut pages = Pages::new(&h, 700)?;
    pages.pad = 2500;
    let hits = pages.mount(&h).await?;
    let id = submit(
        &h,
        json!({ "source": SRC, "limits": { "max_call_result_mb": 1 } }),
    )
    .await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let (class, details) = single_rejection(&runner.results())?;
    assert_eq!(class, "result_too_large");
    // No partial data: the rejection carries a message and nothing of the pages.
    assert!(details.get("issues").is_none(), "{details}");
    assert!(!details.to_string().contains("ABC-"), "{details}");
    // Rejected before concatenating the page that would exceed the limit: the later pages are
    // never requested.
    let seen = hits_of(&hits);
    assert_eq!(seen.len(), 5, "{seen:?}");
    // Every page fetched so far stays in the audit log; the last one names the rejection.
    let calls = script_calls(&h, &id).await?;
    assert_eq!(calls.len(), 5);
    for (n, c) in calls.iter().enumerate() {
        assert_eq!(c["page"], n, "{c}");
        let want = if n == 4 {
            json!("result_too_large")
        } else {
            Value::Null
        };
        assert_eq!(c["rejection"], want, "{c}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i21_all_next_page_over_max_calls_rejects_script_limit() -> TestResult {
    let (h, runner) = harness(vec![
        ScriptPlan::new(vec![search_all(1, 100)], result_end(json!(1))).holding(30_000),
    ])
    .await?;
    let hits = Pages::new(&h, 700)?.mount(&h).await?;
    let id = submit(&h, json!({ "source": SRC, "limits": { "max_calls": 3 } })).await?;
    wait_for("the answer", || !runner.results().is_empty()).await?;
    let (class, details) = single_rejection(&runner.results())?;
    assert_eq!(class, "script_limit");
    assert_eq!(details["message"], "the run would exceed max_calls");
    // Three pages fetched, the fourth never requested.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        hits_of(&hits)
            .iter()
            .map(|s| s.start_at)
            .collect::<Vec<_>>(),
        [0, 100, 200]
    );
    let calls = script_calls(&h, &id).await?;
    assert_eq!(calls.len(), 3);
    assert!(calls.iter().all(|c| c["rejection"].is_null()));
    // The refused page is not counted.
    assert_eq!(h.core().running_scripts()[0].host_calls, 3);
    h.handler().cancel(&id).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i21_all_fetch_bytes_reach_max_fetch_mb_rejects() -> TestResult {
    let (h, runner) = harness(vec![ScriptPlan::new(
        vec![search_all(1, 100)],
        result_end(json!(1)),
    )])
    .await?;
    // Every page body is exactly 512 KiB: after two pages the run fetched 1 MiB.
    let mut pages = Pages::new(&h, 700)?;
    pages.exact = Some(512 * 1024);
    let hits = pages.mount(&h).await?;
    let id = submit(
        &h,
        json!({ "source": SRC, "limits": { "max_fetch_mb": 1 } }),
    )
    .await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let (class, _) = single_rejection(&runner.results())?;
    assert_eq!(class, "script_limit");
    // The fetched bytes reached `max_fetch_mb` with page 1: page 2 is never requested.
    assert_eq!(hits_of(&hits).len(), 2);
    let calls = script_calls(&h, &id).await?;
    assert_eq!(calls.len(), 2);
    assert!(calls.iter().all(|c| c["bytes"] == 512 * 1024), "{calls:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i21_max_above_hard_cap_rejected_validation() -> TestResult {
    let (h, runner) = harness(vec![ScriptPlan::new(
        vec![search_all(1, 501)],
        result_end(json!(1)),
    )])
    .await?;
    let hits = Pages::new(&h, 700)?.mount(&h).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let (class, _) = single_rejection(&runner.results())?;
    assert_eq!(class, "validation");
    assert!(hits_of(&hits).is_empty());
    let types = h.event_types(&id).await?;
    assert!(!types.contains(&EventType::SCRIPT_CALL_SENT), "{types:?}");
    assert!(!types.contains(&EventType::SCRIPT_CALL), "{types:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_cancel_mid_page_records_cancelled_in_flight_page() -> TestResult {
    let (h, runner) = harness(vec![ScriptPlan::new(
        vec![search_all(1, 100)],
        result_end(json!(1)),
    )])
    .await?;
    let mut pages = Pages::new(&h, 700)?;
    pages.stall_at = Some((200, Duration::from_secs(10)));
    let hits = pages.mount(&h).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    wait_for("the third page", || hits_of(&hits).len() == 3).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let env = h.handler().cancel(&id).await;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    assert_eq!(runner.kills(), [Some(KillReason::Client)]);
    let events = h.events(&id).await?;
    let types: Vec<EventType> = events.iter().map(|(t, _)| *t).collect();
    assert_eq!(
        types,
        [
            EventType::REQUEST_RECEIVED,
            EventType::SCRIPT_STARTED,
            EventType::SCRIPT_CALL_SENT,
            EventType::SCRIPT_CALL,
            EventType::SCRIPT_CALL,
            EventType::SCRIPT_CALL,
            EventType::SCRIPT_FAILED,
            EventType::CANCELLED,
        ]
    );
    for (n, (_, c)) in events[3..5].iter().enumerate() {
        assert_eq!(c["page"], n, "{c}");
        assert!(c.get("outcome").is_none(), "{c}");
    }
    let in_flight = &events[5].1;
    assert_eq!(in_flight["outcome"], "cancelled_in_flight");
    assert_eq!(in_flight["reason"], "by_client");
    assert_eq!(in_flight["call_id"], 1);
    assert_eq!(in_flight["page"], 2);
    // No page after the cancel, no record after the terminal one.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(hits_of(&hits).len(), 3);
    assert_eq!(h.event_types(&id).await?.len(), 8);
    Ok(())
}

/// The run ends by itself (a timeout) with a page in flight and the glue keeps the call future:
/// the page is recorded `cancelled_in_flight` (`run_ended`) and no further page is requested.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_run_end_mid_page_records_the_page_and_stops_paging() -> TestResult {
    let end = RunEnd::HostLimit {
        name: "timeout_s".to_owned(),
    };
    let (h, _runner) = harness(vec![
        ScriptPlan::new(vec![search_all(1, 100)], result_end(json!(1)))
            .interrupted(1500, end)
            .keeping_calls(),
    ])
    .await?;
    let mut pages = Pages::new(&h, 700)?;
    pages.stall_at = Some((100, Duration::from_secs(10)));
    let hits = pages.mount(&h).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let events = h.events(&id).await?;
    let types: Vec<EventType> = events.iter().map(|(t, _)| *t).collect();
    assert_eq!(
        types,
        [
            EventType::REQUEST_RECEIVED,
            EventType::SCRIPT_STARTED,
            EventType::SCRIPT_CALL_SENT,
            EventType::SCRIPT_CALL,
            EventType::SCRIPT_CALL,
            EventType::SCRIPT_FAILED,
        ]
    );
    assert_eq!(events[3].1["page"], 0);
    assert_eq!(events[4].1["page"], 1);
    assert_eq!(events[4].1["outcome"], "cancelled_in_flight");
    assert_eq!(events[4].1["reason"], "run_ended");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(hits_of(&hits).len(), 2);
    assert_eq!(h.event_types(&id).await?.len(), types.len());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_on_non_paginated_op_rejected() -> TestResult {
    let mut call = host_call(1, "jira.issue.get", json!({ "key": "ABC-1" }));
    call.all = true;
    let (h, runner) = harness(vec![ScriptPlan::new(vec![call], result_end(json!(1)))]).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let (class, details) = single_rejection(&runner.results())?;
    assert_eq!(class, "validation");
    assert_eq!(
        details["message"],
        "this op is not paginated; use atlas.call"
    );
    let types = h.event_types(&id).await?;
    assert!(!types.contains(&EventType::SCRIPT_CALL_SENT), "{types:?}");
    assert!(
        common::test_hits(h.mock("jira-main").ok_or("no jira mock")?)
            .await
            .is_empty()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_dispatch_record_once_per_run() -> TestResult {
    let (h, runner) = harness(vec![ScriptPlan::new(
        vec![search_all(1, 100), search_all(2, 100)],
        result_end(json!(1)),
    )])
    .await?;
    let hits = Pages::new(&h, 200)?.mount(&h).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    assert!(
        runner
            .results()
            .iter()
            .all(|r| matches!(r, HostCallResult::Ok(_)))
    );
    assert_eq!(hits_of(&hits).len(), 4);
    let types = h.event_types(&id).await?;
    let sent = types
        .iter()
        .filter(|t| **t == EventType::SCRIPT_CALL_SENT)
        .count();
    assert_eq!(sent, 1, "{types:?}");
    let calls = script_calls(&h, &id).await?;
    assert_eq!(
        calls
            .iter()
            .map(|c| (c["call_id"].clone(), c["page"].clone()))
            .collect::<Vec<_>>(),
        [
            (json!(1), json!(0)),
            (json!(1), json!(1)),
            (json!(2), json!(0)),
            (json!(2), json!(1)),
        ]
    );
    Ok(())
}

/// A server that applies a smaller page size than asked: still one request per page, each page
/// committed before the next request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_clamped_pages_are_one_request_per_record() -> TestResult {
    let (h, runner) = harness(vec![ScriptPlan::new(
        vec![search_all(1, 100)],
        result_end(json!(1)),
    )])
    .await?;
    let mut pages = Pages::new(&h, 200)?;
    pages.server_max = Some(50);
    let hits = pages.mount(&h).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let result = match runner.results().as_slice() {
        [HostCallResult::Ok(v)] => v.clone(),
        other => return Err(format!("unexpected answers: {:?}", outline(other)).into()),
    };
    assert_eq!(keys(&result).len(), 200);
    let seen = hits_of(&hits);
    assert_eq!(
        seen.iter()
            .map(|s| (s.start_at, s.committed))
            .collect::<Vec<_>>(),
        [(0, 0), (50, 1), (100, 2), (150, 3)]
    );
    let calls = script_calls(&h, &id).await?;
    assert_eq!(calls.len(), 4);
    assert!(calls.iter().all(|c| c["pages"] == 1), "{calls:?}");
    Ok(())
}

/// M3 T27 ruling 5 per page: a refusal decided from status and headers on a later page is a
/// gated outcome in its record (as on a direct read's later page), never a direct `unavailable`;
/// the script sees the rejection and none of the pages before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_later_page_refusal_is_a_gated_outcome() -> TestResult {
    let (h, runner) = harness(vec![ScriptPlan::new(
        vec![search_all(1, 100)],
        result_end(json!(1)),
    )])
    .await?;
    let mut pages = Pages::new(&h, 700)?;
    pages.status_at = Some((100, 302));
    let hits = pages.mount(&h).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let (class, details) = single_rejection(&runner.results())?;
    assert_eq!(class, "upstream_unavailable");
    assert!(!details.to_string().contains("ABC-"), "{details}");
    assert_eq!(hits_of(&hits).len(), 2);
    let calls = script_calls(&h, &id).await?;
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0]["rejection"], Value::Null);
    let refused = &calls[1];
    assert_eq!(refused["page"], 1);
    assert_eq!(refused["outcome"], "unparsable", "{refused}");
    assert!(refused.get("unavailable").is_none(), "{refused}");
    assert_eq!(refused["rejection"], "upstream_unavailable");
    Ok(())
}

/// Dry runs answer `atlas.all` from the op's example (§9.5), as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_dry_run_answers_from_the_example() -> TestResult {
    let (h, runner) = harness(vec![ScriptPlan::new(
        vec![search_all(1, 100)],
        result_end(json!(1)),
    )])
    .await?;
    let id = submit(&h, json!({ "source": SRC, "dry_run": true })).await?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let search = atlas_duck_registry::get("jira.search").ok_or("no op")?;
    assert_eq!(
        runner.results(),
        [HostCallResult::Ok(search.result_example_json())]
    );
    assert!(
        common::test_hits(h.mock("jira-main").ok_or("no jira mock")?)
            .await
            .is_empty()
    );
    Ok(())
}
