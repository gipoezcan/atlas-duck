#![cfg(feature = "testing")]
//! The script lifecycle against a fake `ScriptRunner` (Task 27, master Placement (3)): states,
//! release flow and `SCRIPT_*` records (§9.1, §9.5, §8.3), the direct rule, client cancel, dry
//! runs and the host-call path (Read class only, `SCRIPT_CALL_SENT` before the first send).

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use atlas_duck_atlassian::Timeouts;
use atlas_duck_atlassian::testing::{
    RawHttpServer, RawStep, TEST_USER, TEST_USER_KEY, XAuser, fixtures,
};
use atlas_duck_audit::EventType;
use atlas_duck_core::engine::cancel::{CancelCause, ShutdownReason};
use atlas_duck_core::testing::{
    FakeScriptRunner, FaultPlan, Harness, InstanceAt, ScriptPlan, host_call,
};
use atlas_duck_core::{
    BatchItem, CompileFailure, ConfinementMode, Confirm, HostCalls, KillReason, Pause,
    RunConfinement, RunEnd, RunPolicy, RunnerError, TestHooks, UnavailableReason,
};
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_ipc::sandbox::probe::ConfinementReport;
use atlas_duck_ipc::sandbox::{HostCall, HostCallResult};
use atlas_duck_registry::Product;
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
    assert_eq!(common::test_hits(requests_of(&h)?).await.len(), 1);
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
    assert!(common::test_hits(requests_of(&h)?).await.is_empty());
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
    assert!(common::test_hits(requests_of(&h)?).await.is_empty());
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
    assert!(common::test_hits(requests_of(&h)?).await.is_empty());
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
    assert!(common::test_hits(requests_of(&h)?).await.is_empty());
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
        reason: UnavailableReason::FloorNotMet,
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

// ---- more of the lifecycle ----------------------------------------------------------------------

fn raw_answer(body: &[u8], content_length: usize) -> Vec<u8> {
    let mut v = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\nX-AUSERNAME: {TEST_USER}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    v.extend_from_slice(body);
    v
}

fn secret(s: &str) -> secrecy::SecretString {
    secrecy::SecretString::from(s.to_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_call_identity_failure_runs_the_recheck_and_rejects_needs_token() -> TestResult {
    let (h, runner) = harness(vec![ScriptPlan::new(
        vec![issue_call(1)],
        result_end(json!(1)),
    )])
    .await?;
    let mock = requests_of(&h)?;
    // The answer is attributed to `anonymous`, and the re-check says the token is dead (§7.1).
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/2/issue/ABC-1")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-AUSERNAME", "anonymous")
                .set_body_raw(fixtures::JIRA_ISSUE, "application/json"),
        )
        .with_priority(1)
        .mount(mock.server())
        .await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Anonymous)
        .await;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    match runner.results().first() {
        Some(HostCallResult::Rejected { class, .. }) => assert_eq!(class, "needs_token"),
        other => return Err(format!("not rejected: {other:?}").into()),
    }
    assert_eq!(
        h.instances().list().first().map(|i| i.state),
        Some("needs_token")
    );
    let rechecks: Vec<Value> = h
        .events_of(EventType::SYSTEM_FETCH)
        .await?
        .into_iter()
        .filter(|p| p["purpose"] == "token_recheck")
        .collect();
    assert_eq!(rechecks.len(), 2, "start and result records");
    // The answer behind the rejection is audit-only: in `SCRIPT_CALL`, never in the result.
    let call = record(&h, &id, EventType::SCRIPT_CALL).await?;
    assert!(call.to_string().contains("Login page times out"));
    assert_eq!(call["rejection"], "needs_token");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_with_a_call_in_flight_records_cancelled_in_flight() -> TestResult {
    let server = RawHttpServer::serve_sequence(vec![vec![
        RawStep::Send(raw_answer(br#"{"key":"ABC-1","fi"#, 1_000_000)),
        RawStep::Sleep(120_000),
    ]])
    .await?;
    let runner = FakeScriptRunner::new(vec![ScriptPlan::new(
        vec![issue_call(1)],
        result_end(json!(1)),
    )]);
    let h = Harness::builder()
        .instance_at(
            "jira-main",
            Product::Jira,
            InstanceAt {
                base_url: server.base_url(),
                ..InstanceAt::default()
            },
        )
        .timeouts(Timeouts {
            per_call: Duration::from_secs(300),
            ..Timeouts::default()
        })
        .scripts(runner.clone())
        .start()
        .await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    wait_for("the connection", || server.connections() >= 1).await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let env = h.handler().cancel(&id).await;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    let events = h.events(&id).await?;
    let types: Vec<EventType> = events.iter().map(|(t, _)| *t).collect();
    assert_eq!(
        types,
        [
            EventType::REQUEST_RECEIVED,
            EventType::SCRIPT_STARTED,
            EventType::SCRIPT_CALL_SENT,
            EventType::SCRIPT_CALL,
            EventType::SCRIPT_FAILED,
            EventType::CANCELLED,
        ]
    );
    let call = &events[3].1;
    assert_eq!(call["outcome"], "cancelled_in_flight");
    assert_eq!(call["reason"], "by_client");
    assert!(
        call["partial"]["text"]
            .as_str()
            .is_some_and(|t| t.contains("ABC-1")),
        "the bytes received are recorded: {call}"
    );
    assert_eq!(events[4].1["reason"], "cancelled_by_client");
    assert_eq!(events[4].1["dispatched"], true);
    // The run's own late answer to the call is never committed after the terminal record.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(h.event_types(&id).await?.len(), 6);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_kills_a_running_script_and_cancels_it() -> TestResult {
    let (h, runner) = harness(vec![
        ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(30_000),
    ])
    .await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    wait_for("the run to start", || runner.starts() == 1).await?;
    let env = h
        .engine()
        .cancel_and_wait(&id, CancelCause::Shutdown(ShutdownReason::AppQuit))
        .await;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    assert_eq!(runner.kills(), [Some(KillReason::Shutdown)]);
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
    assert_eq!(events[2].1["reason"], "app_quit");
    assert_eq!(events[2].1["direct"], false);
    assert_eq!(events[3].1["reason"], "app_quit");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn user_kill_becomes_a_release_item() -> TestResult {
    let (h, runner) = harness(vec![
        ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(30_000),
    ])
    .await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    wait_for("the run to start", || runner.starts() == 1).await?;
    assert!(h.engine().kill_script(&id));
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    assert_eq!(h.status(&id).await.status, Status::Pending);
    let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "killed_by_user");
    assert_eq!(failed["direct"], false);
    assert_eq!(failed["candidate"]["class"], "killed_by_user");
    h.approver().release(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    assert_eq!(exit(&env), 8);
    assert_eq!(
        env.data.clone().ok_or("no data")?["script_error"]["class"],
        "killed_by_user"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn running_list_empty_and_one() -> TestResult {
    let (h, runner) = harness(vec![
        ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(30_000),
    ])
    .await?;
    assert!(h.core().running_scripts().is_empty());
    let id = submit(&h, json!({ "source": SRC })).await?;
    wait_for("the run to start", || runner.starts() == 1).await?;
    let rows = h.core().running_scripts();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].request_id, id);
    assert_eq!(rows[0].host_calls, 0);
    assert!(!rows[0].started_at.is_empty());
    // The kill goes through the run's own audited path; an unknown id kills nothing.
    assert!(!h.core().kill_script("no-such-request"));
    assert!(h.core().kill_script(&id));
    // The row is gone at once: the end record is appended later, and a page that re-reads right
    // after the kill answer must not see a run with an enabled Kill button.
    assert!(h.core().running_scripts().is_empty());
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    assert!(h.core().running_scripts().is_empty());
    assert!(!h.core().kill_script(&id), "a run that ended is not killed");
    let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "killed_by_user");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn running_list_leaves_out_dry_runs_and_kill_ignores_non_scripts() -> TestResult {
    let (h, runner) = harness(vec![
        ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(30_000),
    ])
    .await?;
    let dry = submit(&h, json!({ "source": SRC, "dry_run": true })).await?;
    wait_for("the dry run to start", || runner.starts() == 1).await?;
    assert!(
        h.core().running_scripts().is_empty(),
        "a dry run is not listed"
    );
    assert!(!h.core().kill_script(&dry), "a dry run has no kill");
    // A read request (finished) names no script run either.
    let read = h.submit("jira.issue.get", json!({ "key": "ABC-1" })).await;
    assert!(!h.core().kill_script(&request_id(&read)?));
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_append_failure_ends_audit_failure_after_the_send() -> TestResult {
    let faults = FaultPlan::new();
    faults.fail_nth(EventType::SCRIPT_CALL, 1);
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
    assert_eq!(env.data, None);
    // The request left before its record failed; nothing of the answer reached the script.
    assert_eq!(common::test_hits(requests_of(&h)?).await.len(), 1);
    wait_for("the kill", || runner.kills().iter().any(Option::is_some)).await?;
    assert_eq!(runner.kills(), [Some(KillReason::AuditFailure)]);
    assert!(
        !h.event_types(&id)
            .await?
            .contains(&EventType::SCRIPT_FINISHED)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn token_replacement_invalidates_a_script_candidate_that_called_the_instance() -> TestResult {
    let runner = FakeScriptRunner::new(vec![ScriptPlan::new(
        vec![issue_call(1)],
        result_end(json!({ "n": 1 })),
    )]);
    let h = Harness::builder()
        .jira("jira-main")
        .scripts(runner.clone())
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let mock = requests_of(&h)?;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    h.approver().open(&id).map_err(de)?;
    let before = h.approver().item(&id).ok_or("not queued")?;
    assert!(before.opened);
    // Another user's token replaces the stored one (§7.1).
    mock.server().reset().await;
    mock.jira_myself("bob", "JIRAUSER2", XAuser::Same).await;
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/2/serverInfo")))
        .respond_with(
            mock.response(200)
                .insert_header("X-AUSERNAME", "bob")
                .set_body_raw(fixtures::jira_server_info("9.12.0"), "application/json"),
        )
        .mount(mock.server())
        .await;
    h.instances()
        .set_token("jira-main", secret("bobs-token"), None)
        .await?;
    let mut after = None;
    for _ in 0..400 {
        if let Some(item) = h.approver().item(&id)
            && item.candidate_rev.counter > before.candidate_rev.counter
        {
            after = Some(item);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let after = after.ok_or("the revision never advanced")?;
    // A new revision that must be opened again; the bytes are the same.
    assert!(!after.opened && after.approvable);
    assert_eq!(
        after.candidate_rev.candidate_hash,
        before.candidate_rev.candidate_hash
    );
    match h.approver().release_unopened(&id) {
        Err(atlas_duck_core::DecisionError::Invalid(_)) => {}
        other => return Err(format!("released without reopening: {other:?}").into()),
    }
    h.approver().release(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn truncated_host_calls_warn_in_the_preview() -> TestResult {
    let calls = vec![host_call(
        1,
        "jira.search",
        json!({ "jql": "project = ABC", "max": 1 }),
    )];
    let (h, runner) = harness(vec![ScriptPlan::new(calls, result_end(json!(1)))]).await?;
    requests_of(&h)?
        .json(
            "/rest/api/2/search",
            200,
            &fixtures::jira_search_page(0, 1, 5, 1),
        )
        .await;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    assert!(matches!(
        runner.results().first(),
        Some(HostCallResult::Ok(_))
    ));
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert_eq!(preview.header.class, "script");
    let lossy: Vec<_> = preview
        .warnings
        .iter()
        .filter(|w| w.id == atlas_duck_preview::warning::WarningId::HostCallsLossy)
        .collect();
    assert_eq!(lossy.len(), 1, "{:?}", preview.warnings);
    assert_eq!(
        lossy[0].text,
        "1 host calls returned truncated or lossy data"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_page_and_redacted_release_of_a_result() -> TestResult {
    let value = json!({ "keep": 1, "secret": "hunter2" });
    let (h, _runner) =
        harness(vec![ScriptPlan::new(Vec::new(), result_end(value.clone()))]).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let rev = h.approver().open(&id).map_err(de)?.preview.candidate_rev;
    let page = h.decisions().raw_page(&id, rev, 0).map_err(de)?;
    assert_eq!(
        serde_json::from_slice::<Value>(&page.bytes)?,
        json!({ "result": value })
    );
    h.approver()
        .release_redacted(
            &id,
            vec![atlas_duck_core::RedactionOp::DropField {
                path: "result.secret".to_owned(),
                scope: atlas_duck_core::DropScope::PerItem,
            }],
        )
        .map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    assert!(env.redacted);
    assert_eq!(
        env.data.clone().ok_or("no data")?["result"],
        json!({ "keep": 1 })
    );
    let released = record(&h, &id, EventType::SCRIPT_RELEASED).await?;
    assert_eq!(released["redaction_ops"].as_array().map(Vec::len), Some(1));
    // A redacted release carries `meta.redactions`, as a read's does (§4.2).
    let meta = env.meta.clone().ok_or("no meta")?;
    assert_eq!(meta["redactions"]["fields_dropped"], json!(["secret"]));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scripts_release_in_a_batch() -> TestResult {
    let runner = FakeScriptRunner::new(vec![
        ScriptPlan::new(Vec::new(), result_end(json!("a"))),
        ScriptPlan::new(Vec::new(), result_end(json!("b"))),
    ]);
    let h = Harness::builder()
        .jira("jira-main")
        .scripts(runner)
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let mut ids = Vec::new();
    for _ in 0..2 {
        let id = submit(&h, json!({ "source": SRC })).await?;
        h.queued(&id, 20_000).await.ok_or("never queued")?;
        h.approver().open(&id).map_err(de)?;
        ids.push(id);
    }
    let items: Vec<BatchItem> = ids
        .iter()
        .map(|id| {
            Ok(BatchItem {
                request_id: id.clone(),
                candidate_rev: h.approver().rev(id).map_err(de)?,
            })
        })
        .collect::<Result<_, TestError>>()?;
    let confirmed: Vec<Value> = items
        .iter()
        .map(|i| json!({ "counter": i.candidate_rev.counter, "candidate_hash": hex::encode(i.candidate_rev.candidate_hash) }))
        .collect();
    let out = h.decisions().decide_batch(items).map_err(de)?;
    assert!(out.items.iter().all(|i| i.status == Status::Released));
    for ((id, want), confirmed) in ids.iter().zip(["a", "b"]).zip(&confirmed) {
        let env = h.await_(id, 5000).await;
        assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
        assert_eq!(env.data.clone().ok_or("no data")?["result"], json!(want));
        assert!(
            h.event_types(id)
                .await?
                .contains(&EventType::SCRIPT_RELEASED)
        );
        // Exact U-32: the release names the revision the batch confirmed for this item.
        let released = record(&h, id, EventType::SCRIPT_RELEASED).await?;
        assert_eq!(released["candidate_rev"], *confirmed);
    }
    let texts = h.confirmer().texts();
    assert_eq!(texts.len(), 1);
    assert!(texts[0].contains("release 2 scripts"), "{}", texts[0]);
    assert!(!texts[0].contains("write"), "{}", texts[0]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evicted_script_candidates_are_rebuilt_from_their_records() -> TestResult {
    let limited = RunEnd::HostLimit {
        name: "timeout_s".to_owned(),
    };
    let (h, runner) = harness(vec![
        ScriptPlan::new(vec![issue_call(1)], result_end(json!({ "n": 7 }))),
        ScriptPlan::new(vec![issue_call(1)], error_end()),
        // Dispatched, so a limit is a release item whose candidate is in `SCRIPT_FAILED`.
        ScriptPlan::new(vec![issue_call(1)], limited),
    ])
    .await?;
    let mut ids = Vec::new();
    for _ in 0..3 {
        let id = submit(&h, json!({ "source": SRC })).await?;
        h.queued(&id, 20_000).await.ok_or("never queued")?;
        h.evict_candidate(&id);
        ids.push(id);
    }
    assert_eq!(runner.starts(), 3);
    for id in &ids {
        h.approver().release(id).map_err(de)?;
    }
    let results = [
        h.await_(&ids[0], 5000).await,
        h.await_(&ids[1], 5000).await,
        h.await_(&ids[2], 5000).await,
    ];
    assert_eq!(
        results[0].data.clone().ok_or("no data")?["result"],
        json!({ "n": 7 })
    );
    assert_eq!(exit(&results[1]), 8);
    assert_eq!(
        results[1].data.clone().ok_or("no data")?["script_error"]["class"],
        "TypeError"
    );
    assert_eq!(
        results[2].data.clone().ok_or("no data")?["script_error"]["class"],
        "script_limit"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_list_shows_a_script_without_an_instance() -> TestResult {
    let (h, _runner) = harness(vec![ScriptPlan::new(Vec::new(), result_end(json!(1)))]).await?;
    let id = submit(&h, json!({ "source": "a\nb\nc" })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let env = h
        .handler()
        .requests_list(None, Some(atlas_duck_ipc::proto::ListState::Pending), None)
        .await;
    let rows = env.data.clone().ok_or("no data")?["requests"].clone();
    let row = rows
        .as_array()
        .and_then(|r| r.iter().find(|r| r["request_id"] == id.as_str()))
        .ok_or("the script is not listed")?;
    assert_eq!(row["op_id"], "script.run");
    assert_eq!(row["instance"], Value::Null);
    assert_eq!(row["target_display"], "script · 3 lines");
    assert_eq!(row["status"], "pending");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_result_over_max_result_mb_is_a_host_measured_limit() -> TestResult {
    // `max_result_mb` is lowered by the agent; 2 MiB of result is over 1 MiB.
    let (h, _runner) = harness(vec![
        ScriptPlan::new(Vec::new(), result_end(json!("x".repeat(2 * 1024 * 1024)))),
        ScriptPlan::new(Vec::new(), result_end(json!("x".repeat(512 * 1024)))),
    ])
    .await?;
    // Neither queued nor dispatched, so the limit is direct (§9.5).
    let id = submit(
        &h,
        json!({ "source": SRC, "limits": { "max_result_mb": 1 } }),
    )
    .await?;
    let env = h.await_(&id, 20_000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "script_limit");
    let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "max_result_mb");
    assert_eq!(failed["direct"], true);
    // Under it, the result is a release item.
    let id2 = submit(
        &h,
        json!({ "source": SRC, "limits": { "max_result_mb": 1 } }),
    )
    .await?;
    h.queued(&id2, 20_000).await.ok_or("never queued")?;
    assert!(
        h.event_types(&id2)
            .await?
            .contains(&EventType::SCRIPT_FINISHED)
    );
    Ok(())
}

// ---- Task 27 fix round: kill binding, in-flight calls at a run's own end, candidate bounds ------

fn pause() -> Arc<Pause> {
    Pause::new()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_during_the_dry_run_compile_check_never_starts_the_worker() -> TestResult {
    let hold = pause();
    let (h, runner) = harness(vec![
        ScriptPlan::new(Vec::new(), result_end(json!(1))).with_compile_pause(hold.clone()),
    ])
    .await?;
    let id = submit(&h, json!({ "source": SRC, "dry_run": true })).await?;
    hold.reached.notified().await;
    let env = h.handler().cancel(&id).await;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    hold.release.notify_one();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(runner.starts(), 0, "a cancelled dry run must not start");
    assert_eq!(
        h.event_types(&id).await?,
        [EventType::REQUEST_RECEIVED, EventType::CANCELLED]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_while_the_worker_is_being_started_kills_it_when_it_appears() -> TestResult {
    let hold = pause();
    let (h, runner) = harness(vec![
        ScriptPlan::new(Vec::new(), result_end(json!(1)))
            .holding(30_000)
            .with_start_pause(hold.clone()),
    ])
    .await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    hold.reached.notified().await;
    let env = h.handler().cancel(&id).await;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    hold.release.notify_one();
    wait_for("the late worker to be killed", || {
        runner.kills() == [Some(KillReason::Client)]
    })
    .await?;
    assert_eq!(
        h.event_types(&id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::SCRIPT_STARTED,
            EventType::SCRIPT_FAILED,
            EventType::CANCELLED,
        ]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_right_after_the_slot_is_taken_logs_the_failure_and_kills_or_never_starts()
-> TestResult {
    let hold = pause();
    let hooks = TestHooks {
        pause_in_transition: Some(hold.clone()),
        ..TestHooks::none()
    };
    let (h, runner) = harness_with(
        vec![ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(30_000)],
        hooks,
        FaultPlan::new(),
    )
    .await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    // `SCRIPT_STARTED` is committed, the model not yet applied: the gate is held.
    hold.reached.notified().await;
    let canceller = {
        let (handler, id) = (h.handler(), id.clone());
        tokio::spawn(async move { handler.cancel(&id).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    hold.release.notify_one();
    let env = canceller.await?;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Either no worker was started, or the one that was is killed (the run task and the cancel
    // race for the gate right after the transition).
    assert!(
        runner
            .kills()
            .iter()
            .all(|k| *k == Some(KillReason::Client)),
        "a started worker is killed: {:?}",
        runner.kills()
    );
    assert_eq!(
        h.event_types(&id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::SCRIPT_STARTED,
            EventType::SCRIPT_FAILED,
            EventType::CANCELLED,
        ]
    );
    Ok(())
}

/// A run with one host call that never finishes (the server stalls after a partial answer),
/// ended by the worker's own death or a user kill; returns the events.
async fn run_ended_with_a_call_in_flight(
    end: Option<RunEnd>,
    keep_calls: bool,
) -> Result<Vec<(EventType, Value)>, TestError> {
    let server = RawHttpServer::serve_sequence(vec![vec![
        RawStep::Send(raw_answer(br#"{"key":"ABC-1","fi"#, 1_000_000)),
        RawStep::Sleep(120_000),
    ]])
    .await?;
    let mut plan = ScriptPlan::new(vec![issue_call(1)], result_end(json!(1)));
    if let Some(end) = end.clone() {
        plan = plan.interrupted(1500, end);
    }
    if keep_calls {
        plan = plan.keeping_calls();
    }
    let runner = FakeScriptRunner::new(vec![plan]);
    let h = Harness::builder()
        .instance_at(
            "jira-main",
            Product::Jira,
            InstanceAt {
                base_url: server.base_url(),
                ..InstanceAt::default()
            },
        )
        .timeouts(Timeouts {
            per_call: Duration::from_secs(300),
            ..Timeouts::default()
        })
        .scripts(runner.clone())
        .start()
        .await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    wait_for("the connection", || server.connections() >= 1).await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    if end.is_none() {
        assert!(h.engine().kill_script(&id));
    }
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    h.events(&id).await
}

fn assert_in_flight_then_failed(events: &[(EventType, Value)], reason: &str) -> TestResult {
    let types: Vec<EventType> = events.iter().map(|(t, _)| *t).collect();
    assert_eq!(
        types,
        [
            EventType::REQUEST_RECEIVED,
            EventType::SCRIPT_STARTED,
            EventType::SCRIPT_CALL_SENT,
            EventType::SCRIPT_CALL,
            EventType::SCRIPT_FAILED,
        ]
    );
    let call = &events[3].1;
    assert_eq!(call["outcome"], "cancelled_in_flight");
    assert_eq!(call["reason"], "run_ended");
    assert!(
        call["partial"]["text"]
            .as_str()
            .is_some_and(|t| t.contains("ABC-1")),
        "the bytes received are recorded: {call}"
    );
    assert_eq!(events[4].1["reason"], reason);
    assert_eq!(events[4].1["dispatched"], true);
    assert_eq!(events[4].1["direct"], false);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_timeout_with_a_call_in_flight_records_the_call() -> TestResult {
    let events = run_ended_with_a_call_in_flight(
        Some(RunEnd::HostLimit {
            name: "timeout_s".to_owned(),
        }),
        false,
    )
    .await?;
    assert_in_flight_then_failed(&events, "timeout_s")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_crash_with_a_call_whose_future_lives_on_records_the_call_once() -> TestResult {
    let events = run_ended_with_a_call_in_flight(Some(RunEnd::Crashed), true).await?;
    assert_in_flight_then_failed(&events, "worker_crash")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_user_kill_with_a_call_in_flight_records_the_call() -> TestResult {
    let events = run_ended_with_a_call_in_flight(None, false).await?;
    assert_in_flight_then_failed(&events, "killed_by_user")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_huge_error_candidate_is_bounded_and_marked() -> TestResult {
    let mib = 1024 * 1024;
    let end = RunEnd::Error {
        class: "Error".to_owned(),
        message: "m".repeat(mib),
        stack: "s".repeat(mib),
        elapsed_ms: 5,
        logs: vec!["l".repeat(mib); 6],
        stderr: "e".repeat(20 * mib),
    };
    let (h, _runner) = harness(vec![ScriptPlan::new(Vec::new(), end)]).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    h.approver().release(&id).map_err(de)?;
    let env = h.await_(&id, 20_000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    let data = env.data.clone().ok_or("no data")?;
    assert!(
        serde_json::to_vec(&data)?.len() < 4 * mib,
        "the released error is bounded"
    );
    let err = &data["script_error"];
    assert_eq!(err["class"], "Error");
    assert_eq!(err["truncated"], true);
    assert!(
        err["stderr"]
            .as_str()
            .is_some_and(|s| s.contains("[truncated")),
        "a marker says what was cut"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_result_that_cannot_be_released_under_the_cap_is_a_limit() -> TestResult {
    // Under `max_result_mb` (16) but its candidate would exceed the 16 MiB release cap.
    let big = "x".repeat(16 * 1024 * 1024 - 5);
    let (h, _runner) = harness(vec![ScriptPlan::new(Vec::new(), result_end(json!(big)))]).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    let env = h.await_(&id, 20_000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "script_limit");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_call_params_over_a_megabyte_are_rejected() -> TestResult {
    let big = "A".repeat(2 * 1024 * 1024);
    let (h, runner) = harness(vec![ScriptPlan::new(
        vec![host_call(1, "jira.issue.get", json!({ "key": big }))],
        result_end(json!(1)),
    )])
    .await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    match runner.results().as_slice() {
        [HostCallResult::Rejected { class, details }] => {
            assert_eq!(class, "validation");
            assert_eq!(details["param"], "params");
        }
        other => return Err(format!("unexpected answers: {other:?}").into()),
    }
    assert!(
        !h.event_types(&id)
            .await?
            .contains(&EventType::SCRIPT_CALL_SENT)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fetch_cap_overrun_is_a_script_limit_inside_the_script() -> TestResult {
    let mut call = host_call(
        1,
        "jira.search",
        json!({ "jql": "project = ABC", "max": 1 }),
    );
    call.all = true;
    let (h, runner) = harness(vec![ScriptPlan::new(vec![call], result_end(json!(1)))]).await?;
    let page = json!({
        "startAt": 0, "maxResults": 1, "total": 100_000,
        "issues": [{ "id": "1", "key": "ABC-1", "fields": { "summary": "s".repeat(600 * 1024) } }]
    })
    .to_string();
    requests_of(&h)?
        .json("/rest/api/2/search", 200, &page)
        .await;
    let id = submit(
        &h,
        json!({ "source": SRC, "limits": { "max_fetch_mb": 1 } }),
    )
    .await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    match runner.results().as_slice() {
        [HostCallResult::Rejected { class, .. }] => assert_eq!(class, "script_limit"),
        other => return Err(format!("unexpected answers: {other:?}").into()),
    }
    Ok(())
}

// ---- Task 12 (M8 Δ3): submit-time availability, compile failures, run policy, `app_upgraded` --

fn retryable(env: &Envelope) -> Option<bool> {
    env.error.as_ref().map(|e| e.retryable)
}

fn unavailable(reason: UnavailableReason) -> RunnerError {
    RunnerError::SandboxUnavailable { reason }
}

fn host_limit(name: &str) -> RunEnd {
    RunEnd::HostLimit {
        name: name.to_owned(),
    }
}

/// `failed`, exit 8, `sandbox_unavailable`; `details.reason = app_upgraded` and `retryable: true`
/// only for an upgrade (§4.3 exit-8 row).
fn assert_unavailable(env: &Envelope, app_upgraded: bool) {
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(exit(env), 8);
    assert_eq!(code(env), "sandbox_unavailable");
    assert_eq!(retryable(env), Some(app_upgraded), "{}", env.to_json_line());
    let reason = detail(env, "reason");
    if app_upgraded {
        assert_eq!(reason, json!("app_upgraded"), "{}", env.to_json_line());
    } else {
        assert_eq!(reason, Value::Null, "{}", env.to_json_line());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn submit_time_identity_mismatch_is_direct_app_upgraded_retryable() -> TestResult {
    let (h, runner) = harness(Vec::new()).await?;
    runner.fail_available(unavailable(UnavailableReason::AppUpgraded));
    for params in [
        json!({ "source": SRC }),
        json!({ "source": SRC, "dry_run": true }),
    ] {
        let id = submit(&h, params).await?;
        let env = h.await_(&id, 5000).await;
        assert_unavailable(&env, true);
        // Direct: neither queued nor dispatched, no worker and no compile check.
        assert_eq!(
            h.event_types(&id).await?,
            [
                EventType::REQUEST_RECEIVED,
                EventType::SCRIPT_FAILED,
                EventType::DELIVERED
            ]
        );
        let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
        assert_eq!(failed["reason"], "sandbox_unavailable");
        assert_eq!(failed["direct"], true);
        assert_eq!(failed["queued"], false);
        assert_eq!(failed["dispatched"], false);
        assert_eq!(failed["details"], json!({ "reason": "app_upgraded" }));
        assert!(h.approver().item(&id).is_none());
    }
    assert_eq!(runner.availability_checks(), 2);
    assert_eq!(runner.compile_checks(), 0);
    assert_eq!(runner.starts(), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queued_run_spawn_time_app_upgraded_goes_to_release() -> TestResult {
    let hold = || ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(1500);
    let (h, runner) = harness(vec![
        hold(),
        hold(),
        ScriptPlan::new(Vec::new(), result_end(json!(1))),
    ])
    .await?;
    let first = submit(&h, json!({ "source": SRC })).await?;
    let second = submit(&h, json!({ "source": SRC })).await?;
    wait_for("both slots", || runner.starts() == 2).await?;
    // The binary is replaced while the third run waits for a slot: its spawn finds it.
    runner.fail_start(unavailable(UnavailableReason::AppUpgraded));
    let third = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&third, 30_000).await.ok_or("third never queued")?;
    // Through the release flow: before a decision the agent sees only `pending` (§3.4, §10.2).
    let st = h.status(&third).await;
    assert_eq!(st.status, Status::Pending);
    assert_eq!(st.error, None);
    let started = record(&h, &third, EventType::SCRIPT_STARTED).await?;
    assert_eq!(started["queued"], true);
    let failed = record(&h, &third, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "sandbox_unavailable");
    assert_eq!(failed["details"], json!({ "reason": "app_upgraded" }));
    assert_eq!(failed["queued"], true);
    assert_eq!(failed["dispatched"], false);
    assert_eq!(failed["direct"], false);
    assert_eq!(failed["candidate"]["class"], "sandbox_unavailable");
    let item = h.approver().item(&third).ok_or("not in the queue")?;
    assert!(item.approvable);
    // §9.5: the error-class preset is pre-selected for the data-free end of a queued run.
    assert!(
        h.engine()
            .entry(&third)
            .ok_or("no entry")?
            .state()
            .script
            .as_ref()
            .is_some_and(|s| s.preselect_error_class_only)
    );
    // Released under the pre-selected preset: exit 8, only the class (review M-5).
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
    assert_eq!(
        data["script_error"],
        json!({ "class": "sandbox_unavailable" })
    );
    for id in [&first, &second] {
        let _ = h.await_(id, 100).await;
    }
    Ok(())
}

/// A queued run whose `start` refuses for the floor (non-direct, the cause from `start`): a
/// release item with the generic sandbox message, the cause kept in the record (review M-5).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queued_run_spawn_time_floor_not_met_goes_to_release() -> TestResult {
    let hold = || ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(1500);
    let (h, runner) = harness(vec![
        hold(),
        hold(),
        ScriptPlan::new(Vec::new(), result_end(json!(1))),
    ])
    .await?;
    let first = submit(&h, json!({ "source": SRC })).await?;
    let second = submit(&h, json!({ "source": SRC })).await?;
    wait_for("both slots", || runner.starts() == 2).await?;
    runner.fail_start(unavailable(UnavailableReason::FloorNotMet));
    let third = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&third, 30_000).await.ok_or("third never queued")?;
    let st = h.status(&third).await;
    assert_eq!(st.status, Status::Pending);
    assert_eq!(st.error, None);
    let failed = record(&h, &third, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "sandbox_unavailable");
    assert_eq!(failed["details"], json!({ "reason": "floor_not_met" }));
    assert_eq!(failed["queued"], true);
    assert_eq!(failed["dispatched"], false);
    assert_eq!(failed["direct"], false);
    assert_eq!(failed["candidate"]["class"], "sandbox_unavailable");
    assert_eq!(
        failed["candidate"]["message"],
        "scripts are not available: the sandbox cannot be started on this system"
    );
    assert!(
        h.engine()
            .entry(&third)
            .ok_or("no entry")?
            .state()
            .script
            .as_ref()
            .is_some_and(|s| s.preselect_error_class_only)
    );
    for id in [&first, &second] {
        let _ = h.await_(id, 100).await;
    }
    Ok(())
}

/// A dry run whose compile check finds no sandbox: a direct `SCRIPT_FAILED sandbox_unavailable`,
/// never a `SCRIPT_DRY_RUN` outcome, and the dry-pool permit is freed (review M-5).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dry_run_compile_unavailable_is_direct_sandbox_unavailable() -> TestResult {
    let unavailable_compile = || {
        ScriptPlan::compile_failure(CompileFailure::Unavailable(unavailable(
            UnavailableReason::SpawnFailed,
        )))
    };
    // More failures than the dry pool has permits (2): a leaked permit would starve the last run.
    let (h, runner) = harness(vec![
        unavailable_compile(),
        unavailable_compile(),
        unavailable_compile(),
        ScriptPlan::new(Vec::new(), result_end(json!(7))),
    ])
    .await?;
    for _ in 0..3 {
        let id = submit(&h, json!({ "source": SRC, "dry_run": true })).await?;
        let env = h.await_(&id, 5000).await;
        assert_unavailable(&env, false);
        assert_eq!(
            h.event_types(&id).await?,
            [
                EventType::REQUEST_RECEIVED,
                EventType::SCRIPT_FAILED,
                EventType::DELIVERED
            ]
        );
        let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
        assert_eq!(failed["reason"], "sandbox_unavailable");
        assert_eq!(failed["direct"], true);
        assert_eq!(failed["details"], json!({ "reason": "spawn_failed" }));
    }
    let id = submit(&h, json!({ "source": SRC, "dry_run": true })).await?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert_eq!(runner.starts(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn floor_not_met_without_degraded_is_sandbox_unavailable() -> TestResult {
    let (h, runner) = harness(Vec::new()).await?;
    runner.fail_available(unavailable(UnavailableReason::FloorNotMet));
    let id = submit(&h, json!({ "source": SRC })).await?;
    let env = h.await_(&id, 5000).await;
    assert_unavailable(&env, false);
    let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["direct"], true);
    // The cause stays in the record; only `app_upgraded` reaches the wire (PD-138).
    assert_eq!(failed["details"], json!({ "reason": "floor_not_met" }));
    assert_eq!(
        runner.policies(),
        [(
            "available",
            RunPolicy {
                allow_degraded: false
            }
        )]
    );
    assert_eq!(runner.compile_checks(), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn degraded_policy_passed_to_runner() -> TestResult {
    let degraded = Arc::new(AtomicBool::new(true));
    let compile_hold = pause();
    let hooks = TestHooks {
        allow_degraded_scripts: Some(degraded.clone()),
        ..TestHooks::none()
    };
    let available_hold = pause();
    let (h, runner) = harness_with(
        vec![
            ScriptPlan::new(Vec::new(), result_end(json!(1))),
            ScriptPlan::new(Vec::new(), result_end(json!(2)))
                .with_compile_pause(compile_hold.clone()),
            ScriptPlan::new(Vec::new(), result_end(json!(3))),
        ],
        hooks,
        FaultPlan::new(),
    )
    .await?;
    let on = RunPolicy {
        allow_degraded: true,
    };
    let off = RunPolicy {
        allow_degraded: false,
    };
    // The toggle on: every step that checks, states the confinement or spawns gets it.
    let first = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&first, 20_000).await.ok_or("never queued")?;
    assert_eq!(
        runner.policies(),
        [
            ("available", on),
            ("compile", on),
            ("confinement", on),
            ("start", on)
        ]
    );
    assert_eq!(runner.specs()[0].policy, on);
    // Revoked while the second run compiles: its slot-time read sees the new value (never
    // captured at submit, PD-141).
    let second = submit(&h, json!({ "source": SRC })).await?;
    compile_hold.reached.notified().await;
    degraded.store(false, Ordering::SeqCst);
    compile_hold.release.notify_one();
    h.queued(&second, 20_000).await.ok_or("never queued")?;
    assert_eq!(
        runner.policies()[4..],
        [
            ("available", on),
            ("compile", on),
            ("confinement", off),
            ("start", off)
        ]
    );
    assert_eq!(runner.specs()[1].policy, off);
    // Revoked while the third run's availability check runs: the compile check reads it anew.
    degraded.store(true, Ordering::SeqCst);
    runner.pause_available(Some(available_hold.clone()));
    let third = submit(&h, json!({ "source": SRC })).await?;
    available_hold.reached.notified().await;
    degraded.store(false, Ordering::SeqCst);
    runner.pause_available(None);
    available_hold.release.notify_one();
    h.queued(&third, 20_000).await.ok_or("never queued")?;
    assert_eq!(
        runner.policies()[8..],
        [
            ("available", on),
            ("compile", off),
            ("confinement", off),
            ("start", off)
        ]
    );
    Ok(())
}

/// The compile check's policy is read once a dry-pool permit is held, not before the wait for
/// one (review M-2): a revocation while a real and a dry run wait for the pool reaches both.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_policy_is_read_after_the_dry_pool_wait() -> TestResult {
    let degraded = Arc::new(AtomicBool::new(true));
    let (a, b) = (pause(), pause());
    let hooks = TestHooks {
        allow_degraded_scripts: Some(degraded.clone()),
        ..TestHooks::none()
    };
    let (h, runner) = harness_with(
        vec![
            ScriptPlan::new(Vec::new(), result_end(json!(1))).with_compile_pause(a.clone()),
            ScriptPlan::new(Vec::new(), result_end(json!(2))).with_compile_pause(b.clone()),
            ScriptPlan::new(Vec::new(), result_end(json!(3))),
            ScriptPlan::new(Vec::new(), result_end(json!(4))),
        ],
        hooks,
        FaultPlan::new(),
    )
    .await?;
    let on = RunPolicy {
        allow_degraded: true,
    };
    let off = RunPolicy {
        allow_degraded: false,
    };
    // Both dry-pool permits are held by paused compile checks.
    let first = submit(&h, json!({ "source": SRC })).await?;
    a.reached.notified().await;
    let second = submit(&h, json!({ "source": SRC })).await?;
    b.reached.notified().await;
    let third = submit(&h, json!({ "source": SRC })).await?;
    let fourth = submit(&h, json!({ "source": SRC, "dry_run": true })).await?;
    wait_for("both availability checks", || {
        runner.availability_checks() == 4
    })
    .await?;
    // Both now wait for a permit; the setting is revoked meanwhile.
    tokio::time::sleep(Duration::from_millis(300)).await;
    degraded.store(false, Ordering::SeqCst);
    a.release.notify_one();
    b.release.notify_one();
    for id in [&first, &second, &third] {
        h.queued(id, 20_000).await.ok_or("never queued")?;
    }
    let env = h.await_(&fourth, 5000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let compiles: Vec<RunPolicy> = runner
        .policies()
        .into_iter()
        .filter(|(step, _)| *step == "compile")
        .map(|(_, p)| p)
        .collect();
    assert_eq!(compiles, [on, on, off, off]);
    Ok(())
}

/// `check_available` holds no dry-pool permit (review M-1): with both permits held by paused
/// compile checks, an unavailable sandbox still answers a real and a dry run at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_availability_check_holds_no_dry_pool_permit() -> TestResult {
    let (a, b) = (pause(), pause());
    let (h, runner) = harness(vec![
        ScriptPlan::new(Vec::new(), result_end(json!(1))).with_compile_pause(a.clone()),
        ScriptPlan::new(Vec::new(), result_end(json!(2))).with_compile_pause(b.clone()),
    ])
    .await?;
    let first = submit(&h, json!({ "source": SRC })).await?;
    a.reached.notified().await;
    let second = submit(&h, json!({ "source": SRC })).await?;
    b.reached.notified().await;
    runner.fail_available(unavailable(UnavailableReason::ProbePending));
    for params in [
        json!({ "source": SRC }),
        json!({ "source": SRC, "dry_run": true }),
    ] {
        let id = submit(&h, params).await?;
        let env = h.await_(&id, 5000).await;
        assert_unavailable(&env, false);
        assert_eq!(
            h.event_types(&id).await?,
            [
                EventType::REQUEST_RECEIVED,
                EventType::SCRIPT_FAILED,
                EventType::DELIVERED
            ]
        );
        let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
        assert_eq!(failed["details"], json!({ "reason": "probe_pending" }));
    }
    assert_eq!(runner.compile_checks(), 2);
    a.release.notify_one();
    b.release.notify_one();
    for id in [&first, &second] {
        h.queued(id, 20_000).await.ok_or("never queued")?;
    }
    Ok(())
}

/// A cancel during `check_available` ends the request; no compile worker is spawned for it
/// afterwards (review M-3). The dry pool is free, so an unbiased wait for a permit would race
/// the end: the scenario repeats to make that race show.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_during_the_availability_check_never_compiles() -> TestResult {
    let hold = pause();
    let (h, runner) = harness(Vec::new()).await?;
    runner.pause_available(Some(hold.clone()));
    for _ in 0..10 {
        for params in [
            json!({ "source": SRC }),
            json!({ "source": SRC, "dry_run": true }),
        ] {
            let id = submit(&h, params).await?;
            hold.reached.notified().await;
            let env = h.handler().cancel(&id).await;
            assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
            hold.release.notify_one();
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert_eq!(
                h.event_types(&id).await?,
                [EventType::REQUEST_RECEIVED, EventType::CANCELLED]
            );
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(runner.availability_checks(), 20);
    assert_eq!(runner.compile_checks(), 0, "a compile for an ended request");
    assert_eq!(runner.starts(), 0);
    Ok(())
}

fn confinement_report() -> ConfinementReport {
    ConfinementReport {
        applied: false,
        mechanism: "none".to_owned(),
        no_new_privs: None,
        landlock_abi: None,
        seccomp: None,
        lpac: Some(false),
        os_error: Some(5),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn script_started_records_confinement() -> TestResult {
    let (h, runner) = harness(vec![
        ScriptPlan::new(Vec::new(), result_end(json!(1))),
        ScriptPlan::new(Vec::new(), result_end(json!(2))),
    ])
    .await?;
    runner.set_confinement(Some(RunConfinement {
        mode: ConfinementMode::Degraded,
        worker_version: "0.8.0+abc".to_owned(),
        probe_report: confinement_report(),
    }));
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let started = record(&h, &id, EventType::SCRIPT_STARTED).await?;
    // The report is the startup probe's, and the key says so (review I-1): the worker's own
    // ready-frame report does not exist yet when the run is admitted.
    assert_eq!(
        started["confinement"],
        json!({
            "mode": "degraded",
            "worker_version": "0.8.0+abc",
            "probe_report": serde_json::to_value(confinement_report())?,
        })
    );
    // A runner that states nothing: the key is absent, never invented.
    runner.set_confinement(None);
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let started = record(&h, &id, EventType::SCRIPT_STARTED).await?;
    assert!(started.get("confinement").is_none(), "{started}");
    Ok(())
}

#[test]
fn sandbox_unavailable_envelope_details_reason() -> TestResult {
    use atlas_duck_core::engine::envelope::record_status;
    let failed = |details: Option<Value>| {
        let mut p = json!({
            "reason": "sandbox_unavailable", "queued": false, "dispatched": false,
            "data_free": true, "direct": true,
        });
        if let Some(d) = details {
            p["details"] = d;
        }
        record_status(EventType::SCRIPT_FAILED, Some(&p), Some("script"))
    };
    let (status, err) = failed(Some(json!({ "reason": "app_upgraded" })));
    assert_eq!(status, Status::Failed);
    let err = err.ok_or("no error")?;
    assert_eq!(
        serde_json::to_value(err.code)?,
        json!("sandbox_unavailable")
    );
    assert!(err.retryable);
    // §3.3's upgrade text, not "the sandbox cannot be started on this system".
    assert_eq!(
        err.message.as_deref(),
        Some("atlas-duck was upgraded; restart the app")
    );
    assert_eq!(
        err.details.map(Value::Object),
        Some(json!({ "reason": "app_upgraded" }))
    );
    for details in [
        None,
        Some(json!({ "reason": "floor_not_met" })),
        Some(json!({ "reason": "probe_pending" })),
        Some(json!({ "reason": "spawn_failed" })),
    ] {
        let (status, err) = failed(details.clone());
        assert_eq!(status, Status::Failed);
        let err = err.ok_or("no error")?;
        assert!(!err.retryable, "{details:?}");
        assert_eq!(err.details, None, "{details:?}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compile_unavailable_is_direct_and_never_takes_a_real_slot() -> TestResult {
    let hold = || ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(30_000);
    let (h, runner) = harness(vec![
        hold(),
        hold(),
        ScriptPlan::compile_failure(CompileFailure::Unavailable(unavailable(
            UnavailableReason::SpawnFailed,
        ))),
    ])
    .await?;
    let first = submit(&h, json!({ "source": SRC })).await?;
    let second = submit(&h, json!({ "source": SRC })).await?;
    wait_for("both slots", || runner.starts() == 2).await?;
    // Both real slots are busy for 30 s: the answer comes from the compile step alone.
    let began = Instant::now();
    let id = submit(&h, json!({ "source": SRC })).await?;
    let env = h.await_(&id, 5000).await;
    assert!(began.elapsed() < Duration::from_secs(10));
    assert_unavailable(&env, false);
    assert_eq!(
        h.event_types(&id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::SCRIPT_FAILED,
            EventType::DELIVERED
        ]
    );
    let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "sandbox_unavailable");
    assert_eq!(failed["direct"], true);
    assert_eq!(failed["details"], json!({ "reason": "spawn_failed" }));
    assert_eq!(runner.starts(), 2);
    for id in [&first, &second] {
        h.handler().cancel(id).await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compile_timeout_frees_the_dry_slot_and_is_direct() -> TestResult {
    let timeout = || ScriptPlan::compile_failure(CompileFailure::Timeout { timeout_s: 10 });
    // More compile timeouts than the dry pool has permits (2): a leaked permit would starve the
    // dry run at the end.
    let (h, runner) = harness(vec![
        timeout(),
        timeout(),
        timeout(),
        ScriptPlan::new(Vec::new(), result_end(json!(7))),
    ])
    .await?;
    for _ in 0..2 {
        let id = submit(&h, json!({ "source": SRC })).await?;
        let env = h.await_(&id, 5000).await;
        assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
        assert_eq!(exit(&env), 8);
        // A data-free limit, never a syntax error (PD-135).
        assert_eq!(code(&env), "script_limit");
        assert_eq!(
            h.event_types(&id).await?,
            [
                EventType::REQUEST_RECEIVED,
                EventType::SCRIPT_FAILED,
                EventType::DELIVERED
            ]
        );
        let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
        assert_eq!(failed["reason"], "timeout_s");
        assert_eq!(failed["direct"], true);
    }
    // A dry run's compile timeout is its own `script_limit` outcome.
    let id = submit(&h, json!({ "source": SRC, "dry_run": true })).await?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "script_limit");
    let dry = record(&h, &id, EventType::SCRIPT_DRY_RUN).await?;
    assert_eq!(dry["outcome"], "script_limit");
    assert_eq!(dry["details"], json!({ "limit": "timeout_s" }));
    // The dry pool is free again: the next dry run answers.
    let id = submit(&h, json!({ "source": SRC, "dry_run": true })).await?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert_eq!(runner.starts(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nonqueued_run_spawn_time_app_upgraded_is_direct_sandbox_unavailable_retryable()
-> TestResult {
    let (h, runner) = harness(vec![ScriptPlan::new(
        Vec::new(),
        host_limit("app_upgraded"),
    )])
    .await?;
    // The glue's end for a mismatch found at spawn, and `start` refusing with the reason.
    let id = submit(&h, json!({ "source": SRC })).await?;
    let env = h.await_(&id, 5000).await;
    assert_unavailable(&env, true);
    let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "sandbox_unavailable");
    assert_eq!(failed["direct"], true);
    assert_eq!(failed["details"], json!({ "reason": "app_upgraded" }));
    runner.fail_start(unavailable(UnavailableReason::AppUpgraded));
    let id = submit(&h, json!({ "source": SRC })).await?;
    let env = h.await_(&id, 5000).await;
    assert_unavailable(&env, true);
    let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "sandbox_unavailable");
    assert_eq!(failed["direct"], true);
    // A dry run whose spawn finds the upgrade: the same direct answer.
    let id = submit(&h, json!({ "source": SRC, "dry_run": true })).await?;
    let env = h.await_(&id, 5000).await;
    assert_unavailable(&env, true);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nonqueued_run_spawn_time_floor_not_met_is_direct_sandbox_unavailable() -> TestResult {
    let (h, runner) = harness(vec![
        ScriptPlan::new(Vec::new(), host_limit("sandbox_unavailable")),
        ScriptPlan::new(Vec::new(), host_limit("sandbox_unavailable")),
    ])
    .await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    let env = h.await_(&id, 5000).await;
    assert_unavailable(&env, false);
    let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "sandbox_unavailable");
    assert_eq!(failed["direct"], true);
    // A dry run ending the same way.
    let id = submit(&h, json!({ "source": SRC, "dry_run": true })).await?;
    let env = h.await_(&id, 5000).await;
    assert_unavailable(&env, false);
    // `start` refusing for the floor: the cause stays in the record.
    runner.fail_start(unavailable(UnavailableReason::FloorNotMet));
    let id = submit(&h, json!({ "source": SRC })).await?;
    let env = h.await_(&id, 5000).await;
    assert_unavailable(&env, false);
    let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["details"], json!({ "reason": "floor_not_met" }));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn worker_reported_limit_never_direct_when_dispatched() -> TestResult {
    let (h, _runner) = harness(vec![
        ScriptPlan::new(vec![issue_call(1)], host_limit("app_upgraded")),
        ScriptPlan::new(vec![issue_call(1)], host_limit("heap_mb")),
    ])
    .await?;
    for (reason, details) in [
        ("sandbox_unavailable", json!({ "reason": "app_upgraded" })),
        ("heap_mb", Value::Null),
    ] {
        let id = submit(&h, json!({ "source": SRC })).await?;
        h.queued(&id, 20_000).await.ok_or("never queued")?;
        assert_eq!(h.status(&id).await.status, Status::Pending);
        let types = h.event_types(&id).await?;
        let sent = types
            .iter()
            .position(|t| *t == EventType::SCRIPT_CALL_SENT)
            .ok_or("no SCRIPT_CALL_SENT")?;
        let ended = types
            .iter()
            .position(|t| *t == EventType::SCRIPT_FAILED)
            .ok_or("no SCRIPT_FAILED")?;
        assert!(sent < ended, "{types:?}");
        let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
        assert_eq!(failed["reason"], reason);
        assert_eq!(
            failed.get("details").cloned().unwrap_or(Value::Null),
            details
        );
        assert_eq!(failed["dispatched"], true);
        assert_eq!(failed["direct"], false);
        // Dispatched: no "keep error class only" pre-selection.
        assert!(
            !h.engine()
                .entry(&id)
                .ok_or("no entry")?
                .state()
                .script
                .as_ref()
                .is_some_and(|s| s.preselect_error_class_only)
        );
    }
    Ok(())
}
