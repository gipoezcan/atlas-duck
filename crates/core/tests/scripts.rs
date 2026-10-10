#![cfg(feature = "testing")]
//! The script lifecycle against a fake `ScriptRunner` (Task 27, master Placement (3)): states,
//! release flow and `SCRIPT_*` records (§9.1, §9.5, §8.3), the direct rule, client cancel, dry
//! runs and the host-call path (Read class only, `SCRIPT_CALL_SENT` before the first send).

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use atlas_duck_audit::EventType;
use atlas_duck_core::testing::{FakeScriptRunner, FaultPlan, Harness, ScriptPlan, host_call};
use atlas_duck_core::{HostCalls, KillReason, RunEnd, RunnerError, TestHooks};
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_ipc::sandbox::{HostCall, HostCallResult};
use common::{TestError, TestResult, code, de, detail, exit, request_id};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, Request, Respond, ResponseTemplate};

const SRC: &str = "return 1;";

fn issue_call(id: u64) -> HostCall {
    host_call(id, "jira.issue.get", json!({ "key": "ABC-1" }))
}

fn result_end(value: Value) -> RunEnd {
    RunEnd::Result {
        value,
        logs: Vec::new(),
        stderr: String::new(),
    }
}

fn error_end() -> RunEnd {
    RunEnd::Error {
        class: "TypeError".to_owned(),
        message: "x is not a function".to_owned(),
        stack: "at main (script:3)".to_owned(),
        elapsed_ms: 12,
        logs: vec!["step 1".to_owned()],
        stderr: String::new(),
    }
}

async fn harness(plans: Vec<ScriptPlan>) -> Result<(Harness, Arc<FakeScriptRunner>), TestError> {
    harness_with(plans, TestHooks::none(), FaultPlan::new()).await
}

async fn harness_with(
    plans: Vec<ScriptPlan>,
    hooks: TestHooks,
    faults: Arc<FaultPlan>,
) -> Result<(Harness, Arc<FakeScriptRunner>), TestError> {
    let runner = FakeScriptRunner::new(plans);
    let h = Harness::builder()
        .jira("jira-main")
        .scripts(runner.clone())
        .hooks(hooks)
        .faults(faults)
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

async fn record(h: &Harness, id: &str, t: EventType) -> Result<Value, TestError> {
    h.events(id)
        .await?
        .into_iter()
        .find(|(e, _)| *e == t)
        .map(|(_, p)| p)
        .ok_or_else(|| format!("no {t:?} record").into())
}

fn requests_of(h: &Harness) -> Result<&atlas_duck_atlassian::testing::MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p3_script_result_release_flow() -> TestResult {
    let (h, _runner) = harness(vec![ScriptPlan::new(
        vec![issue_call(1)],
        result_end(json!({ "n": 1 })),
    )])
    .await?;
    let id = submit(&h, json!({ "source": SRC, "args": { "a": 1 } })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    // Waiting for release the agent sees `pending` and nothing else (§4.5).
    let st = h.status(&id).await;
    assert_eq!(st.status, Status::Pending);
    assert_eq!(st.data, None);
    assert_eq!(
        h.event_types(&id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::SCRIPT_STARTED,
            EventType::SCRIPT_CALL_SENT,
            EventType::SCRIPT_CALL,
            EventType::SCRIPT_FINISHED,
        ]
    );
    let started = record(&h, &id, EventType::SCRIPT_STARTED).await?;
    assert_eq!(started["queued"], false);
    assert_eq!(started["source"], SRC);
    assert_eq!(started["args"], json!({ "a": 1 }));
    let call = record(&h, &id, EventType::SCRIPT_CALL).await?;
    assert_eq!(call["op"], "jira.issue.get");
    assert_eq!(call["params"], json!({ "key": "ABC-1" }));
    let item = h.approver().item(&id).ok_or("not in the queue")?;
    assert_eq!(item.class, "script");
    assert!(item.approvable && !item.opened);
    h.approver().release(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    assert_eq!(exit(&env), 0);
    assert_eq!(env.instance, None);
    assert_eq!(env.op_id.as_deref(), Some("script.run"));
    assert_eq!(
        env.data.clone().ok_or("no data")?["result"],
        json!({ "n": 1 })
    );
    assert_eq!(
        h.event_types(&id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::SCRIPT_STARTED,
            EventType::SCRIPT_CALL_SENT,
            EventType::SCRIPT_CALL,
            EventType::SCRIPT_FINISHED,
            EventType::PREVIEW_SHOWN,
            EventType::SCRIPT_RELEASED,
            EventType::DELIVERED,
        ]
    );
    assert_eq!(requests_of(&h)?.received().await.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p3_direct_syntax_failure() -> TestResult {
    let (h, runner) = harness(vec![ScriptPlan::syntax_error(3, 7, "unexpected token")]).await?;
    let id = submit(&h, json!({ "source": "let = ;" })).await?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(exit(&env), 8);
    assert_eq!(code(&env), "script_syntax");
    assert_eq!(detail(&env, "line"), json!(3));
    assert_eq!(detail(&env, "column"), json!(7));
    assert_eq!(detail(&env, "message"), json!("unexpected token"));
    let types = h.event_types(&id).await?;
    assert!(!types.contains(&EventType::SCRIPT_STARTED), "{types:?}");
    assert_eq!(
        types[..2],
        [EventType::REQUEST_RECEIVED, EventType::SCRIPT_FAILED]
    );
    let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "script_syntax");
    assert_eq!(failed["direct"], true);
    assert_eq!(failed["queued"], false);
    assert_eq!(failed["dispatched"], false);
    assert_eq!(failed["data_free"], true);
    assert_eq!(runner.starts(), 0);
    // The same answer for `status` (reduced) and nothing in the queue.
    assert_eq!(h.status(&id).await.status, Status::Failed);
    assert!(h.approver().item(&id).is_none());
    Ok(())
}

/// Answers the issue GET and notes whether `SCRIPT_CALL_SENT` was already committed when the
/// request arrived (audit-before-effect, §5.1 inv. 1).
struct Probe {
    port: Arc<dyn atlas_duck_core::audit_port::AuditPort>,
    template: ResponseTemplate,
    sent_first: Arc<AtomicBool>,
    hits: Arc<std::sync::atomic::AtomicU32>,
}

impl Respond for Probe {
    fn respond(&self, _r: &Request) -> ResponseTemplate {
        self.hits.fetch_add(1, Ordering::SeqCst);
        let committed = self
            .port
            .recent_headers(Duration::from_secs(3600))
            .map(|hs| {
                hs.iter()
                    .any(|h| h.event_type == EventType::SCRIPT_CALL_SENT)
            })
            .unwrap_or(false);
        self.sent_first.store(committed, Ordering::SeqCst);
        self.template.clone()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p3_dispatched_call_commits_call_sent_first() -> TestResult {
    let (h, _runner) = harness(vec![ScriptPlan::new(
        vec![issue_call(1)],
        result_end(json!(1)),
    )])
    .await?;
    let mock = requests_of(&h)?;
    let sent_first = Arc::new(AtomicBool::new(false));
    let hits = Arc::new(std::sync::atomic::AtomicU32::new(0));
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/2/issue/ABC-1")))
        .respond_with(Probe {
            port: h.port(),
            template: mock.response(200).set_body_raw(
                atlas_duck_atlassian::testing::fixtures::JIRA_ISSUE,
                "application/json",
            ),
            sent_first: sent_first.clone(),
            hits: hits.clone(),
        })
        .with_priority(1)
        .mount(mock.server())
        .await;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert!(
        sent_first.load(Ordering::SeqCst),
        "the request reached the server before SCRIPT_CALL_SENT committed"
    );
    let types = h.event_types(&id).await?;
    let sent = types
        .iter()
        .position(|t| *t == EventType::SCRIPT_CALL_SENT)
        .ok_or("no SCRIPT_CALL_SENT")?;
    let call = types
        .iter()
        .position(|t| *t == EventType::SCRIPT_CALL)
        .ok_or("no SCRIPT_CALL")?;
    assert!(sent < call);
    let sent_rec = record(&h, &id, EventType::SCRIPT_CALL_SENT).await?;
    assert_eq!(sent_rec["call_id"], 1);
    assert_eq!(sent_rec["op_id"], "jira.issue.get");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_sent_append_failure_sends_nothing_and_ends_audit_failure() -> TestResult {
    let faults = FaultPlan::new();
    faults.fail_nth(EventType::SCRIPT_CALL_SENT, 1);
    let (h, runner) = harness_with(
        vec![ScriptPlan::new(vec![issue_call(1)], result_end(json!(1))).holding(30_000)],
        TestHooks::none(),
        faults,
    )
    .await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "audit_failure");
    assert_eq!(exit(&env), 1);
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    assert_eq!(env.data, None);
    assert!(requests_of(&h)?.received().await.is_empty());
    wait_for("the kill", || runner.kills().iter().any(Option::is_some)).await?;
    assert_eq!(runner.kills(), [Some(KillReason::AuditFailure)]);
    let types = h.event_types(&id).await?;
    assert!(!types.contains(&EventType::SCRIPT_CALL_SENT), "{types:?}");
    assert!(!types.contains(&EventType::SCRIPT_FINISHED));
    assert!(!types.contains(&EventType::SCRIPT_RELEASED));
    Ok(())
}

fn without_ids(mut e: Envelope) -> Envelope {
    e.request_id = None;
    e.op_id = None;
    e.instance = None;
    e
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p3_cancel_running_kills_and_cancels() -> TestResult {
    let (h, runner) = harness(vec![
        ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(5000),
    ])
    .await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    wait_for("the run to start", || runner.starts() == 1).await?;
    wait_for("SCRIPT_STARTED", || runner.starts() == 1).await?;
    let t = Instant::now();
    let env = h.handler().cancel(&id).await;
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "cancel waited for the worker"
    );
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    assert_eq!(exit(&env), 7);
    assert_eq!(detail(&env, "reason"), json!("by_client"));
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    assert_eq!(runner.kills(), [Some(KillReason::Client)]);
    let events = h.events(&id).await?;
    let types: Vec<EventType> = events.iter().map(|(t, _)| *t).collect();
    assert_eq!(
        types,
        [
            EventType::REQUEST_RECEIVED,
            EventType::SCRIPT_STARTED,
            EventType::SCRIPT_FAILED,
            EventType::CANCELLED,
        ]
    );
    let failed = &events[2].1;
    assert_eq!(failed["reason"], "cancelled_by_client");
    assert_eq!(failed["direct"], false);
    assert_eq!(h.status(&id).await.status, Status::Cancelled);
    // The same envelope as cancelling a read that waits for release (§4.4).
    requests_of(&h)?
        .json(
            "/rest/api/2/issue/ABC-2",
            200,
            atlas_duck_atlassian::testing::fixtures::JIRA_ISSUE,
        )
        .await;
    let read = h.submit("jira.issue.get", json!({ "key": "ABC-2" })).await;
    let rid = request_id(&read)?;
    h.queued(&rid, 20_000).await.ok_or("read never queued")?;
    let read_env = h.handler().cancel(&rid).await;
    assert_eq!(without_ids(env), without_ids(read_env));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_waiting_for_a_slot_logs_only_cancelled() -> TestResult {
    let hold = || ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(30_000);
    let (h, runner) = harness(vec![hold(), hold(), hold()]).await?;
    let first = submit(&h, json!({ "source": SRC })).await?;
    let second = submit(&h, json!({ "source": SRC })).await?;
    wait_for("both slots", || runner.starts() == 2).await?;
    let third = submit(&h, json!({ "source": SRC })).await?;
    // Compiled (the dry pool) but waiting for a real slot.
    wait_for("the third compile check", || runner.compile_checks() == 3).await?;
    let env = h.handler().cancel(&third).await;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    assert_eq!(
        h.event_types(&third).await?,
        [EventType::REQUEST_RECEIVED, EventType::CANCELLED]
    );
    assert_eq!(runner.starts(), 2);
    for id in [&first, &second] {
        h.handler().cancel(id).await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p3_dry_run_backend_answers_from_examples() -> TestResult {
    let calls = vec![
        issue_call(1),
        host_call(2, "jira.search", json!({ "jql": "project = ABC" })),
    ];
    let end = RunEnd::Result {
        value: json!({ "ok": true }),
        logs: vec!["two calls".to_owned()],
        stderr: String::new(),
    };
    let (h, runner) = harness(vec![ScriptPlan::new(calls, end)]).await?;
    let id = submit(&h, json!({ "source": SRC, "dry_run": true })).await?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert_eq!(exit(&env), 0);
    assert_eq!(env.meta.clone().ok_or("no meta")?["dry_run"], true);
    let data = env.data.clone().ok_or("no data")?;
    assert_eq!(data["result"], json!({ "ok": true }));
    assert_eq!(data["logs"], json!(["two calls"]));
    let issue = atlas_duck_registry::get("jira.issue.get").ok_or("no op")?;
    let search = atlas_duck_registry::get("jira.search").ok_or("no op")?;
    assert_eq!(
        runner.results(),
        [
            HostCallResult::Ok(issue.result_example_json()),
            HostCallResult::Ok(search.result_example_json()),
        ]
    );
    assert!(requests_of(&h)?.received().await.is_empty());
    // No `SCRIPT_STARTED`, no `SCRIPT_CALL`: the only record besides the request's own and its
    // delivery is the dry run's.
    assert_eq!(
        h.event_types(&id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::SCRIPT_DRY_RUN,
            EventType::DELIVERED,
        ]
    );
    let dry = record(&h, &id, EventType::SCRIPT_DRY_RUN).await?;
    assert_eq!(dry["mode"], "full");
    assert_eq!(dry["outcome"], "result");
    assert_eq!(dry["calls"].as_array().map(Vec::len), Some(2));
    assert_eq!(dry["calls"][0]["op_id"], "jira.issue.get");
    assert_eq!(
        runner.specs().iter().map(|s| s.dry_run).collect::<Vec<_>>(),
        [true]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dry_run_sparse_and_error_outcome() -> TestResult {
    let (h, runner) = harness(vec![ScriptPlan::new(vec![issue_call(1)], error_end())]).await?;
    let id = submit(&h, json!({ "source": SRC, "dry_run": "sparse" })).await?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert_eq!(exit(&env), 8);
    let err = env.data.clone().ok_or("no data")?["script_error"].clone();
    assert_eq!(err["class"], "TypeError");
    assert_eq!(err["message"], "x is not a function");
    let issue = atlas_duck_registry::get("jira.issue.get").ok_or("no op")?;
    assert_eq!(
        runner.results(),
        [HostCallResult::Ok(issue.result_example_sparse_json())]
    );
    let dry = record(&h, &id, EventType::SCRIPT_DRY_RUN).await?;
    assert_eq!(dry["mode"], "sparse");
    assert_eq!(dry["outcome"], "error");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dry_run_validates_every_call_like_a_real_run() -> TestResult {
    let calls = vec![
        host_call(
            1,
            "jira.comment.add",
            json!({ "key": "ABC-1", "body": "x" }),
        ),
        host_call(2, "jira.issue.get", json!({ "nope": 1 })),
    ];
    let (h, runner) = harness(vec![ScriptPlan::new(calls, result_end(json!(null)))]).await?;
    let id = submit(&h, json!({ "source": SRC, "dry_run": true })).await?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let classes: Vec<String> = runner
        .results()
        .iter()
        .map(|r| match r {
            HostCallResult::Rejected { class, .. } => class.clone(),
            HostCallResult::Ok(_) => "ok".to_owned(),
        })
        .collect();
    assert_eq!(classes, ["validation", "validation"]);
    assert!(requests_of(&h)?.received().await.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dry_run_compile_error_is_a_dry_run_outcome() -> TestResult {
    let (h, _runner) = harness(vec![ScriptPlan::syntax_error(1, 2, "bad")]).await?;
    let id = submit(&h, json!({ "source": "x", "dry_run": true })).await?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(exit(&env), 8);
    assert_eq!(code(&env), "script_syntax");
    assert_eq!(detail(&env, "line"), json!(1));
    assert_eq!(
        h.event_types(&id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::SCRIPT_DRY_RUN,
            EventType::DELIVERED,
        ]
    );
    let dry = record(&h, &id, EventType::SCRIPT_DRY_RUN).await?;
    assert_eq!(dry["outcome"], "script_syntax");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_op_rejected_in_script() -> TestResult {
    let calls = vec![host_call(
        1,
        "jira.comment.add",
        json!({ "key": "ABC-1", "body": "hi" }),
    )];
    let (h, runner) = harness(vec![ScriptPlan::new(calls, result_end(json!(null)))]).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let results = runner.results();
    assert_eq!(results.len(), 1);
    match &results[0] {
        HostCallResult::Rejected { class, .. } => assert_eq!(class, "validation"),
        other => return Err(format!("not rejected: {other:?}").into()),
    }
    assert!(requests_of(&h)?.received().await.is_empty());
    // Never validated, so the run never dispatched.
    let types = h.event_types(&id).await?;
    assert!(!types.contains(&EventType::SCRIPT_CALL_SENT), "{types:?}");
    assert!(!types.contains(&EventType::SCRIPT_CALL), "{types:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queued_limit_goes_to_release() -> TestResult {
    let hold = || ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(1500);
    let limited = ScriptPlan::new(
        Vec::new(),
        RunEnd::HostLimit {
            name: "timeout_s".to_owned(),
        },
    );
    let (h, runner) = harness(vec![hold(), hold(), limited]).await?;
    let first = submit(&h, json!({ "source": SRC })).await?;
    let second = submit(&h, json!({ "source": SRC })).await?;
    wait_for("both slots", || runner.starts() == 2).await?;
    let third = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&third, 30_000).await.ok_or("third never queued")?;
    // Not direct: it waited for a slot, so even a data-free limit goes through release.
    assert_eq!(h.status(&third).await.status, Status::Pending);
    let started = record(&h, &third, EventType::SCRIPT_STARTED).await?;
    assert_eq!(started["queued"], true);
    let failed = record(&h, &third, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "timeout_s");
    assert_eq!(failed["queued"], true);
    assert_eq!(failed["dispatched"], false);
    assert_eq!(failed["direct"], false);
    assert_eq!(failed["candidate"]["class"], "script_limit");
    let item = h.approver().item(&third).ok_or("not in the queue")?;
    assert!(item.approvable);
    // §9.5: the "keep error class only" preset is pre-selected for it.
    assert!(
        h.engine()
            .entry(&third)
            .ok_or("no entry")?
            .state()
            .script
            .as_ref()
            .is_some_and(|s| s.preselect_error_class_only)
    );
    h.approver()
        .release_redacted(
            &third,
            vec![atlas_duck_core::RedactionOp::Preset(
                atlas_duck_core::RedactionPreset::ErrorClassOnly,
            )],
        )
        .map_err(de)?;
    let env = h.await_(&third, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    assert_eq!(exit(&env), 8);
    assert!(env.redacted);
    let data = env.data.clone().ok_or("no data")?;
    assert_eq!(data["script_error"], json!({ "class": "script_limit" }));
    for id in [&first, &second] {
        let _ = h.await_(id, 100).await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_limit_of_a_run_that_neither_queued_nor_dispatched() -> TestResult {
    let (h, _runner) = harness(vec![ScriptPlan::new(
        Vec::new(),
        RunEnd::HostLimit {
            name: "timeout_s".to_owned(),
        },
    )])
    .await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(exit(&env), 8);
    assert_eq!(code(&env), "script_limit");
    let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["direct"], true);
    assert_eq!(failed["data_free"], true);
    assert!(h.approver().item(&id).is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn error_details_release_and_deny() -> TestResult {
    let (h, _runner) = harness(vec![
        ScriptPlan::new(vec![issue_call(1)], error_end()),
        ScriptPlan::new(Vec::new(), result_end(json!([1, 2]))),
    ])
    .await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    assert_eq!(h.status(&id).await.status, Status::Pending);
    h.approver().release(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    assert_eq!(exit(&env), 8);
    let err = env.data.clone().ok_or("no data")?["script_error"].clone();
    assert_eq!(err["class"], "TypeError");
    assert_eq!(err["message"], "x is not a function");
    assert_eq!(err["logs"], json!(["step 1"]));
    // A result, denied.
    let id2 = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id2, 20_000).await.ok_or("never queued")?;
    h.approver().deny(&id2, "no thanks").map_err(de)?;
    let env = h.await_(&id2, 5000).await;
    assert_eq!(env.status, Status::Denied, "{}", env.to_json_line());
    assert_eq!(exit(&env), 3);
    assert_eq!(
        h.event_types(&id2).await?.last().copied(),
        Some(EventType::DELIVERED)
    );
    assert!(
        h.event_types(&id2)
            .await?
            .contains(&EventType::SCRIPT_DENIED)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn static_validation_rejects_before_compiling() -> TestResult {
    let (h, runner) = harness(Vec::new()).await?;
    // Rejected inline, like a read that fails its static checks: `failed` with the request id.
    let env = h
        .submit_script(json!({ "source": SRC, "limits": { "timeout_s": 100000 } }))
        .await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    let id = request_id(&env)?;
    assert_eq!(exit(&env), 2);
    assert_eq!(code(&env), "validation");
    assert_eq!(
        h.event_types(&id).await?,
        [EventType::REQUEST_RECEIVED, EventType::REQUEST_REJECTED]
    );
    assert_eq!(runner.compile_checks(), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_runner_scripts_are_unavailable() -> TestResult {
    let h = Harness::builder().jira("jira-main").start().await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(exit(&env), 8);
    assert_eq!(code(&env), "sandbox_unavailable");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spawn_time_sandbox_unavailable_is_direct() -> TestResult {
    let (h, runner) = harness(vec![ScriptPlan::new(Vec::new(), result_end(json!(1)))]).await?;
    runner.fail_start(RunnerError::SandboxUnavailable {
        app_upgraded: false,
    });
    let id = submit(&h, json!({ "source": SRC })).await?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(exit(&env), 8);
    assert_eq!(code(&env), "sandbox_unavailable");
    let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["direct"], true);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiry_during_running_expires_on_release_item() -> TestResult {
    let hooks = TestHooks {
        expiry: Some(Duration::from_millis(300)),
        ..TestHooks::none()
    };
    let plan = ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(1200);
    let (h, runner) = harness_with(vec![plan], hooks, FaultPlan::new()).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    wait_for("the run to start", || runner.starts() == 1).await?;
    // The timer fires while the run cannot expire: the request stays pending.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(h.status(&id).await.status, Status::Pending);
    // The run ends: SCRIPT_FINISHED, then the request expires on the release item.
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Expired, "{}", env.to_json_line());
    assert_eq!(exit(&env), 7);
    assert_eq!(
        h.event_types(&id).await?[..4],
        [
            EventType::REQUEST_RECEIVED,
            EventType::SCRIPT_STARTED,
            EventType::SCRIPT_FINISHED,
            EventType::EXPIRED,
        ]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn worker_crash_and_protocol_violation_go_to_release() -> TestResult {
    let (h, _runner) = harness(vec![
        ScriptPlan::new(Vec::new(), RunEnd::Crashed),
        ScriptPlan::new(Vec::new(), RunEnd::ProtocolViolation),
    ])
    .await?;
    for reason in ["worker_crash", "protocol_violation"] {
        let id = submit(&h, json!({ "source": SRC })).await?;
        h.queued(&id, 20_000).await.ok_or("never queued")?;
        let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
        assert_eq!(failed["reason"], reason);
        assert_eq!(failed["direct"], false);
        assert_eq!(h.status(&id).await.status, Status::Pending);
    }
    Ok(())
}

/// C.0 type-level rule: the dry-run backend is built from a registry mode and a validator and
/// has no client handle to reach Atlassian with.
#[expect(dead_code)]
fn dry_run_backend_takes_only_a_mode_and_a_validator(
    mode: atlas_duck_core::engine::script::ExampleMode,
    validator: Arc<dyn atlas_duck_core::engine::script::CallValidator>,
) -> Arc<dyn HostCalls> {
    Arc::new(atlas_duck_core::engine::script::DryRunBackend::new(
        mode, validator,
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn product_is_not_needed_for_a_script() -> TestResult {
    // A script without any Atlassian instance configured still runs (calls then fail routing).
    let runner = FakeScriptRunner::new(vec![ScriptPlan::new(
        vec![issue_call(1)],
        result_end(json!(1)),
    )]);
    let h = Harness::builder().scripts(runner.clone()).start().await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    assert!(matches!(
        runner.results().first(),
        Some(HostCallResult::Rejected { .. })
    ));
    Ok(())
}
