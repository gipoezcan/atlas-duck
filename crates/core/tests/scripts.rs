#![cfg(feature = "testing")]
//! The script lifecycle against a fake `ScriptRunner` (Task 27, master Placement (3)): states,
//! release flow and `SCRIPT_*` records (§9.1, §9.5, §8.3), the direct rule, client cancel, dry
//! runs and the host-call path (Read class only, `SCRIPT_CALL_SENT` before the first send).

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use atlas_duck_atlassian::testing::{
    RawHttpServer, RawStep, TEST_USER, TEST_USER_KEY, XAuser, fixtures,
};
use atlas_duck_atlassian::{CredentialProvider, Timeouts};
use atlas_duck_audit::EventType;
use atlas_duck_core::engine::cancel::{CancelCause, ShutdownReason};
use atlas_duck_core::running::KillAnswer;
use atlas_duck_core::testing::{
    FakeScriptRunner, FaultPlan, Harness, InstanceAt, ScriptPlan, host_call,
};
use atlas_duck_core::{
    BatchItem, CompileFailure, ConfinementMode, Confirm, HostCalls, KillReason, Pause,
    RunConfinement, RunEnd, RunPolicy, RunnerError, SettingChangeReq, TestHooks, UnavailableReason,
};
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_ipc::sandbox::probe::ConfinementReport;
use atlas_duck_ipc::sandbox::{HostCall, HostCallResult};
use atlas_duck_registry::Product;
use common::jira::{
    comment, comment_page, comments_path, gets_on, mount_comment_page_delayed, mount_comments,
};
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
    assert_eq!(h.engine().kill_script(&id), KillAnswer::Killed);
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
    assert_eq!(
        h.core().kill_script("no-such-request"),
        KillAnswer::NotRunning
    );
    assert_eq!(h.core().kill_script(&id), KillAnswer::Killed);
    // The row is gone at once: the end record is appended later, and a page that re-reads right
    // after the kill answer must not see a run with an enabled Kill button.
    assert!(h.core().running_scripts().is_empty());
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    assert!(h.core().running_scripts().is_empty());
    assert_eq!(
        h.core().kill_script(&id),
        KillAnswer::NotRunning,
        "a run that ended is not killed"
    );
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
    assert_eq!(
        h.core().kill_script(&dry),
        KillAnswer::NotRunning,
        "a dry run has no kill"
    );
    // A read request (finished) names no script run either.
    let read = h.submit("jira.issue.get", json!({ "key": "ABC-1" })).await;
    assert_eq!(
        h.core().kill_script(&request_id(&read)?),
        KillAnswer::NotRunning
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x11_running_view_lists_agent_instances_started_elapsed_calls_bytes() -> TestResult {
    let (h, runner) = harness(vec![
        ScriptPlan::new(vec![issue_call(1)], result_end(json!(1))).holding(30_000),
    ])
    .await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    wait_for("the run to start", || runner.starts() == 1).await?;
    wait_for("the host call to be counted", || {
        h.core()
            .running_scripts()
            .first()
            .is_some_and(|r| r.host_calls == 1 && r.bytes_fetched > 0)
    })
    .await?;
    h.clock().advance(Duration::from_millis(2500));
    let rows = h.core().running_scripts();
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!(row.request_id, id);
    assert_eq!(row.instances, ["jira-main"], "aliases, not instance ids");
    assert_eq!(row.host_calls, 1);
    assert!(row.bytes_fetched >= 1, "{row:?}");
    assert_eq!(row.elapsed_ms, 2500, "host clock since the slot");
    assert!(row.started_at.ends_with('Z'), "{}", row.started_at);
    // The serialized keys are the Δ4 set.
    let keys: Vec<String> = serde_json::to_value(row)?
        .as_object()
        .ok_or("not an object")?
        .keys()
        .cloned()
        .collect();
    for k in [
        "request_id",
        "agent_name",
        "instances",
        "started_at",
        "elapsed_ms",
        "host_calls",
        "bytes_fetched",
    ] {
        assert!(keys.iter().any(|x| x == k), "missing {k}: {keys:?}");
    }
    assert_eq!(keys.len(), 7, "{keys:?}");
    assert_eq!(h.core().kill_script(&id), KillAnswer::Killed);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn started_at_is_slot_time_not_submit_time() -> TestResult {
    let hold = |ms| ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(ms);
    let (h, runner) = harness(vec![hold(700), hold(700), hold(30_000)]).await?;
    let first = submit(&h, json!({ "source": SRC })).await?;
    let second = submit(&h, json!({ "source": SRC })).await?;
    wait_for("both slots", || runner.starts() == 2).await?;
    let third = submit(&h, json!({ "source": SRC })).await?;
    wait_for("the third compile check", || runner.compile_checks() == 3).await?;
    let submitted = h
        .engine()
        .entry(&third)
        .ok_or("no entry")?
        .submitted_at
        .clone();
    // The queued run waits 40 s on the host clock before a slot frees.
    h.clock().advance(Duration::from_secs(40));
    wait_for("the third run to get a slot", || {
        h.core()
            .running_scripts()
            .iter()
            .any(|r| r.request_id == third)
    })
    .await?;
    h.clock().advance(Duration::from_secs(3));
    let rows = h.core().running_scripts();
    let row = rows
        .iter()
        .find(|r| r.request_id == third)
        .ok_or("third not listed")?;
    assert!(
        row.started_at > submitted,
        "slot time {} must be after submit time {submitted}",
        row.started_at
    );
    assert_eq!(
        row.elapsed_ms, 3000,
        "elapsed counts from the slot, not the submit"
    );
    for id in [&first, &second, &third] {
        h.handler().cancel(id).await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x11_user_kill_is_killed_by_user_direct_false_release_item() -> TestResult {
    // Before the first host call, and after one.
    for with_call in [false, true] {
        let calls = if with_call {
            vec![issue_call(1)]
        } else {
            Vec::new()
        };
        let (h, runner) = harness(vec![
            ScriptPlan::new(calls, result_end(json!(1))).holding(30_000),
        ])
        .await?;
        let id = submit(&h, json!({ "source": SRC })).await?;
        wait_for("the run to start", || runner.starts() == 1).await?;
        if with_call {
            wait_for("the call", || {
                h.core()
                    .running_scripts()
                    .first()
                    .is_some_and(|r| r.host_calls == 1)
            })
            .await?;
        }
        assert_eq!(h.core().kill_script(&id), KillAnswer::Killed);
        h.queued(&id, 20_000).await.ok_or("never queued")?;
        let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
        assert_eq!(failed["reason"], "killed_by_user");
        assert_eq!(failed["direct"], false);
        assert_eq!(failed["candidate"]["class"], "killed_by_user");
        assert_eq!(runner.kills(), [Some(KillReason::User)]);
        let item = h.approver().item(&id).ok_or("not in the queue")?;
        assert!(item.approvable);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kill_answer_not_running_vs_already_stopping() -> TestResult {
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
    assert_eq!(h.core().kill_script("no-such"), KillAnswer::NotRunning);
    let id = submit(&h, json!({ "source": SRC })).await?;
    // `SCRIPT_STARTED` is committed, the model not yet applied: not running yet.
    hold.reached.notified().await;
    hold.release.notify_one();
    wait_for("the run to start", || runner.starts() == 1).await?;
    wait_for("the run to be listed", || {
        !h.core().running_scripts().is_empty()
    })
    .await?;
    assert_eq!(h.core().kill_script(&id), KillAnswer::Killed);
    // The end record is committed, its model transition is held: the worker is being stopped.
    wait_for_record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert_eq!(h.core().kill_script(&id), KillAnswer::AlreadyStopping);
    assert_eq!(h.core().kill_script(&id), KillAnswer::AlreadyStopping);
    hold.release.notify_one();
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    assert_eq!(h.core().kill_script(&id), KillAnswer::NotRunning);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kill_answer_after_an_agent_cancel_is_not_running() -> TestResult {
    // The cancel path commits its kill, its records and the model move under one gate hold with
    // no test hook inside it, so "kill asked, record not yet applied" is only reachable through
    // the run task's end transition (the test above). Once the cancel answered, the request is
    // terminal: the click is `NotRunning`, never `Killed`.
    let (h, runner) = harness(vec![
        ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(30_000),
    ])
    .await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    wait_for("the run to start", || runner.starts() == 1).await?;
    let env = h.handler().cancel(&id).await;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    assert_eq!(h.core().kill_script(&id), KillAnswer::NotRunning);
    assert_eq!(runner.kills(), [Some(KillReason::Client)]);
    Ok(())
}

async fn wait_for_record(h: &Harness, id: &str, t: EventType) -> TestResult {
    for _ in 0..1000 {
        if h.events(id).await?.iter().any(|(e, _)| *e == t) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("timed out waiting for the {t:?} record").into())
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

/// §5.2 (M8 T19c): a script result whose rebuild does not reproduce its hash fails closed for
/// good: no redaction is previewed or taken (a new revision built from the record would switch
/// Release back on), only Deny remains.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hash_mismatch_script_takes_no_redaction() -> TestResult {
    use atlas_duck_core::DecisionError;
    use atlas_duck_core::payloads::InvalidReason;
    let value = json!({ "keep": 1, "secret": "hunter2" });
    let (h, _runner) = harness(vec![ScriptPlan::new(Vec::new(), result_end(value))]).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let ap = h.approver();
    ap.open(&id).map_err(de)?;
    assert!(h.corrupt_candidate_hash(&id));
    let res = ap.release_unopened(&id);
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    let rev = ap.rev(&id).map_err(de)?;
    let ops = vec![atlas_duck_core::RedactionOp::DropField {
        path: "result.secret".to_owned(),
        scope: atlas_duck_core::DropScope::PerItem,
    }];
    let res = ap.redaction_preview(&id, &ops);
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    let invalid = || async {
        let events = h.events(&id).await?;
        Ok::<_, TestError>(
            events
                .into_iter()
                .filter(|(t, _)| *t == EventType::DECISION_INVALID)
                .map(|(_, p)| p)
                .collect::<Vec<Value>>(),
        )
    };
    let before = invalid().await?.len();
    let res = ap.redact(&id, ops);
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    let logged = invalid().await?;
    assert_eq!(logged.len(), before + 1, "the refused redaction is logged");
    let last = logged.last().ok_or("no DECISION_INVALID")?;
    assert_eq!(
        (
            &last["reason"],
            &last["decision"],
            &last["submitted_rev"],
            &last["batch"]
        ),
        (
            &json!("not_approvable"),
            &json!("release"),
            &json!(rev.counter),
            &json!(false)
        )
    );
    assert_eq!(ap.rev(&id).map_err(de)?, rev, "no new revision");
    assert!(!ap.item(&id).ok_or("not queued")?.approvable);
    ap.deny_unopened(&id, "rebuild failed").map_err(de)?;
    assert_eq!(h.await_(&id, 5000).await.status, Status::Denied);
    Ok(())
}

/// Review T19c m-2 for a script result: a rebuild failure marked while a redaction that passed
/// the failed-closed gate waits for the transition gate refuses it at the step.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn script_failure_marked_before_the_redaction_step_refuses_it() -> TestResult {
    use atlas_duck_core::DecisionError;
    use atlas_duck_core::payloads::InvalidReason;
    let value = json!({ "keep": 1, "secret": "hunter2" });
    let (h, _runner) = harness(vec![ScriptPlan::new(Vec::new(), result_end(value))]).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let ap = h.approver();
    ap.open(&id).map_err(de)?;
    let rev = ap.rev(&id).map_err(de)?;
    let entry = h.engine().entry(&id).ok_or("not in memory")?;
    let gate = entry.hold_gate().await;
    let (waiting, at) = (h.approver(), id.clone());
    let ops = vec![atlas_duck_core::RedactionOp::DropField {
        path: "result.secret".to_owned(),
        scope: atlas_duck_core::DropScope::PerItem,
    }];
    let pending = tokio::task::spawn_blocking(move || waiting.redact(&at, ops));
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(!pending.is_finished(), "the redaction waits for the gate");
    {
        let mut st = entry.state();
        st.rebuild_failed = true;
        st.model.set_approvable(false);
    }
    drop(gate);
    let res = tokio::time::timeout(std::time::Duration::from_secs(10), pending).await??;
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    assert_eq!(ap.rev(&id).map_err(de)?, rev, "no new revision");
    assert!(!ap.item(&id).ok_or("not queued")?.approvable);
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
    let (h, id, _server) = queued_with_a_call_in_flight(end, keep_calls).await?;
    h.events(&id).await
}

/// [`run_ended_with_a_call_in_flight`] up to the queued item: the harness, the request id and
/// the stalling server (kept alive by the caller).
async fn queued_with_a_call_in_flight(
    end: Option<RunEnd>,
    keep_calls: bool,
) -> Result<(Harness, String, RawHttpServer), TestError> {
    queued_with_the_call_in_flight(issue_call(1), end, keep_calls).await
}

/// [`queued_with_a_call_in_flight`] for the run's first call `call`.
async fn queued_with_the_call_in_flight(
    call: HostCall,
    end: Option<RunEnd>,
    keep_calls: bool,
) -> Result<(Harness, String, RawHttpServer), TestError> {
    let server = RawHttpServer::serve_sequence(vec![vec![
        RawStep::Send(raw_answer(br#"{"key":"ABC-1","fi"#, 1_000_000)),
        RawStep::Sleep(120_000),
    ]])
    .await?;
    let mut plan = ScriptPlan::new(vec![call], result_end(json!(1)));
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
        assert_eq!(h.engine().kill_script(&id), KillAnswer::Killed);
    }
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    Ok((h, id, server))
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
        ScriptPlan::new(Vec::new(), result_end(json!(3))),
    ])
    .await?;
    runner.set_confinement(Some(RunConfinement {
        mode: ConfinementMode::Degraded,
        worker_version: "0.8.0+abc".to_owned(),
        probe_report: Some(confinement_report()),
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
    // Degraded with no probe worker's ready frame (M8 T20 ruling): the record still says
    // `degraded`, and the probe's report is `null`, never a fabricated one.
    runner.set_confinement(Some(RunConfinement {
        mode: ConfinementMode::Degraded,
        worker_version: "0.8.0+abc".to_owned(),
        probe_report: None,
    }));
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let started = record(&h, &id, EventType::SCRIPT_STARTED).await?;
    assert_eq!(
        started["confinement"],
        json!({ "mode": "degraded", "worker_version": "0.8.0+abc", "probe_report": null })
    );
    // A runner that states nothing: the key is absent, never invented.
    runner.set_confinement(None);
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let started = record(&h, &id, EventType::SCRIPT_STARTED).await?;
    assert!(started.get("confinement").is_none(), "{started}");
    Ok(())
}

/// M8 T20 (Δ1, R9, PD-152): `atlas.instances()`'s list is the `instances.list` rows without
/// `state` (and so never a URL).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn script_instances_are_the_instances_list_rows_without_state() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .confluence("wiki")
        .start()
        .await?;
    let listed = h.handler().instances_list().await;
    let rows = listed.data.ok_or("no data")?["instances"].clone();
    let expected: Vec<Value> = rows
        .as_array()
        .ok_or("no rows")?
        .iter()
        .map(|r| json!({ "alias": r["alias"], "product": r["product"], "is_default": r["is_default"] }))
        .collect();
    assert_eq!(expected.len(), 2, "{rows}");
    assert_eq!(
        serde_json::to_value(h.core().script_instances())?,
        Value::Array(expected)
    );
    Ok(())
}

/// M8 T20 (PD-141 (c), T12 review I-1 (c)): the end record of a run whose worker answered its
/// ready frame names that worker's own report (`worker_confinement`), beside `SCRIPT_STARTED`'s
/// `probe_report`; a run with no worker has no such key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn end_records_carry_the_workers_own_confinement_report() -> TestResult {
    let (h, runner) = harness(vec![
        ScriptPlan::new(Vec::new(), result_end(json!(1))),
        ScriptPlan::new(vec![issue_call(1)], error_end()),
        ScriptPlan::new(Vec::new(), RunEnd::Crashed),
        ScriptPlan::new(Vec::new(), host_limit("timeout_s")),
        ScriptPlan::new(Vec::new(), result_end(json!(2))),
        ScriptPlan::new(Vec::new(), result_end(json!(3))),
    ])
    .await?;
    let worker = ConfinementReport {
        mechanism: "lockdown_token".to_owned(),
        ..confinement_report()
    };
    let expected = serde_json::to_value(&worker)?;
    runner.set_worker_confinement(Some(worker));
    // A result and a worker-reported error: `SCRIPT_FINISHED`.
    for _ in 0..2 {
        let id = submit(&h, json!({ "source": SRC })).await?;
        h.queued(&id, 20_000).await.ok_or("never queued")?;
        let finished = record(&h, &id, EventType::SCRIPT_FINISHED).await?;
        assert_eq!(finished["worker_confinement"], expected, "{finished}");
    }
    // A crash: a non-direct `SCRIPT_FAILED`.
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["direct"], false);
    assert_eq!(failed["worker_confinement"], expected, "{failed}");
    // A host-measured limit before any call: a direct `SCRIPT_FAILED`.
    let id = submit(&h, json!({ "source": SRC })).await?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["direct"], true);
    assert_eq!(failed["worker_confinement"], expected, "{failed}");
    // A runner that states no worker report: the key is absent, never invented.
    runner.set_worker_confinement(None);
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let finished = record(&h, &id, EventType::SCRIPT_FINISHED).await?;
    assert!(finished.get("worker_confinement").is_none(), "{finished}");
    // No worker at all (`start` refused): nothing to name.
    runner.set_worker_confinement(Some(confinement_report()));
    runner.fail_start(unavailable(UnavailableReason::SpawnFailed));
    let id = submit(&h, json!({ "source": SRC })).await?;
    let env = h.await_(&id, 5000).await;
    assert_unavailable(&env, false);
    let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert!(failed.get("worker_confinement").is_none(), "{failed}");
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

// ---- M8 Task 15: the degraded toggle is read when the run's slot is taken (PD-141) ----------

/// The "Allow scripts with degraded confinement" setting through Settings (on: the native
/// confirmation is answered OK).
async fn set_degraded(h: &Harness, on: bool) -> TestResult {
    if on {
        h.confirmer().push(Confirm::Ok);
    }
    let s = h.core().settings();
    tokio::task::spawn_blocking(move || s.apply(vec![SettingChangeReq::AllowDegradedScripts(on)]))
        .await?
        .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

/// The policies one kind of runner call was handed, in call order.
fn policies_of(runner: &FakeScriptRunner, call: &str) -> Vec<bool> {
    runner
        .policies()
        .into_iter()
        .filter(|(c, _)| *c == call)
        .map(|(_, p)| p.allow_degraded)
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn degraded_off_after_submit_refuses_the_queued_spawn() -> TestResult {
    // Each of the first two runs holds its slot inside `start` until the test releases it.
    let gates = [pause(), pause()];
    let hold = |g: &Arc<Pause>| {
        ScriptPlan::new(Vec::new(), result_end(json!(1))).with_start_pause(g.clone())
    };
    let (h, runner) = harness(vec![
        hold(&gates[0]),
        hold(&gates[1]),
        ScriptPlan::new(Vec::new(), result_end(json!(3))),
    ])
    .await?;
    // The startup probe said `NotMet`: a worker spawns only under a policy that allows it.
    runner.require_degraded();
    set_degraded(&h, true).await?;
    let first = submit(&h, json!({ "source": SRC })).await?;
    let second = submit(&h, json!({ "source": SRC })).await?;
    for g in &gates {
        g.reached.notified().await;
    }
    assert_eq!(runner.starts(), 2, "both slots");
    // The third run passes its submit-time checks with the toggle on, then waits for a slot.
    let third = submit(&h, json!({ "source": SRC })).await?;
    wait_for("the third compile check", || runner.compile_checks() == 3).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !h.event_types(&third)
            .await?
            .contains(&EventType::SCRIPT_STARTED),
        "the third run waits for a slot"
    );
    set_degraded(&h, false).await?;
    // A slot frees: the spawn reads the setting as it is now, not as it was at submit.
    for g in &gates {
        g.release.notify_one();
    }
    h.queued(&third, 30_000).await.ok_or("third never queued")?;
    assert_eq!(policies_of(&runner, "available"), [true, true, true]);
    assert_eq!(policies_of(&runner, "compile"), [true, true, true]);
    assert_eq!(policies_of(&runner, "start"), [true, true, false]);
    assert_eq!(runner.specs()[2].policy, RunPolicy::default());
    // The spawn-time unavailability of a queued run: through the release flow (§3.4, §9.5).
    let st = h.status(&third).await;
    assert_eq!(st.status, Status::Pending);
    assert_eq!(st.error, None);
    let started = record(&h, &third, EventType::SCRIPT_STARTED).await?;
    assert_eq!(started["queued"], true);
    let failed = record(&h, &third, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "sandbox_unavailable");
    assert_eq!(failed["details"], json!({ "reason": "floor_not_met" }));
    assert_eq!(failed["queued"], true);
    assert_eq!(failed["dispatched"], false);
    assert_eq!(failed["direct"], false);
    assert_eq!(failed["candidate"]["class"], "sandbox_unavailable");
    assert!(h.approver().item(&third).is_some_and(|i| i.approvable));
    assert!(
        h.engine()
            .entry(&third)
            .ok_or("no entry")?
            .state()
            .script
            .as_ref()
            .is_some_and(|s| s.preselect_error_class_only)
    );
    // The runs that spawned while it was on are unaffected.
    for id in [&first, &second] {
        h.queued(id, 30_000).await.ok_or("never queued")?;
        assert!(record(&h, id, EventType::SCRIPT_FINISHED).await.is_ok());
    }
    Ok(())
}

/// The seq of every record of `t` the store holds (any request, system records too).
fn seqs_of(h: &Harness, t: EventType) -> Result<Vec<u64>, TestError> {
    Ok(h.store()
        .recent_headers(Duration::from_secs(24 * 3600))?
        .iter()
        .filter(|e| e.event_type == t)
        .map(|e| e.seq)
        .collect())
}

/// T15 review I-1: the policy is read again once `SCRIPT_STARTED` is committed, and only narrows
/// the slot's: a revocation logged before that record is honoured, a grant made since is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn degraded_toggle_changed_before_script_started_only_narrows_the_spawn() -> TestResult {
    let hold = pause();
    let hooks = TestHooks {
        pause_before_script_started: Some(hold.clone()),
        ..TestHooks::none()
    };
    let (h, runner) = harness_with(
        vec![
            ScriptPlan::new(Vec::new(), result_end(json!(1))),
            ScriptPlan::new(Vec::new(), result_end(json!(2))),
        ],
        hooks,
        FaultPlan::new(),
    )
    .await?;
    runner.require_degraded();
    // What the runner states for the slot's policy (the fake states it for any policy).
    runner.set_confinement(Some(RunConfinement {
        mode: ConfinementMode::Degraded,
        worker_version: "0.8.0+abc".to_owned(),
        probe_report: Some(confinement_report()),
    }));

    // Revoked: the slot is taken with the toggle on, the off commits before `SCRIPT_STARTED`.
    set_degraded(&h, true).await?;
    let revoked = submit(&h, json!({ "source": SRC })).await?;
    hold.reached.notified().await;
    set_degraded(&h, false).await?;
    hold.release.notify_one();
    let env = h.await_(&revoked, 10_000).await;
    let off_seq = seqs_of(&h, EventType::CONFIG_CHANGED)?
        .into_iter()
        .max()
        .ok_or("no CONFIG_CHANGED")?;
    let started_seq = seqs_of(&h, EventType::SCRIPT_STARTED)?
        .into_iter()
        .max()
        .ok_or("no SCRIPT_STARTED")?;
    assert!(off_seq < started_seq, "{off_seq} < {started_seq}");
    assert_eq!(policies_of(&runner, "start"), [false]);
    assert_eq!(runner.specs()[0].policy, RunPolicy::default());
    // `confinement` is the slot-time admission; the refusal that follows keeps the trail true.
    let started = record(&h, &revoked, EventType::SCRIPT_STARTED).await?;
    assert_eq!(started["confinement"]["mode"], "degraded");
    assert_eq!(started["queued"], false);
    assert_unavailable(&env, false);
    let failed = record(&h, &revoked, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "sandbox_unavailable");
    assert_eq!(failed["details"], json!({ "reason": "floor_not_met" }));
    assert_eq!(failed["direct"], true);

    // Granted: the slot is taken with the toggle off, the on commits before `SCRIPT_STARTED`;
    // it never widens what the slot admitted.
    let granted = submit(&h, json!({ "source": SRC })).await?;
    hold.reached.notified().await;
    set_degraded(&h, true).await?;
    hold.release.notify_one();
    let env = h.await_(&granted, 10_000).await;
    assert_eq!(policies_of(&runner, "start"), [false, false]);
    assert_unavailable(&env, false);
    let failed = record(&h, &granted, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["details"], json!({ "reason": "floor_not_met" }));
    Ok(())
}

// ---- the release preview model (Task 17: X-12, PD-145, PD-146, R8) --------------------------------

use atlas_duck_preview::warning::{TEXT_SCRIPT_RENDERED_COPIES, WarningId};
use atlas_duck_preview::{Preselect, Preview, PreviewBody, ProvenanceRow, ScriptItemKind};

/// The script preview of `id`, opened as the approver does.
fn script_preview(h: &Harness, id: &str) -> Result<Preview, TestError> {
    Ok(h.approver().open(id).map_err(de)?.preview)
}

/// A `PreviewBody::Script` taken apart.
struct ScriptBody {
    item: ScriptItemKind,
    view: PreviewBody,
    source: String,
    provenance: Vec<ProvenanceRow>,
    logs: Vec<String>,
    logs_note: Option<String>,
    stderr: String,
}

fn script_body(p: &Preview) -> Result<ScriptBody, TestError> {
    match &p.body {
        PreviewBody::Script {
            item,
            view,
            source,
            provenance,
            logs,
            logs_note,
            stderr,
        } => Ok(ScriptBody {
            item: *item,
            view: (**view).clone(),
            source: source.clone(),
            provenance: provenance.clone(),
            logs: logs.clone(),
            logs_note: logs_note.clone(),
            stderr: stderr.clone(),
        }),
        other => Err(format!("not a script body: {other:?}").into()),
    }
}

fn row(call_id: u64, op: &str, target: &str, outcome: &str) -> ProvenanceRow {
    ProvenanceRow {
        call_id,
        op_id: op.to_owned(),
        instance: "jira-main".to_owned(),
        target_display: target.to_owned(),
        outcome: outcome.to_owned(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn script_preview_has_source_provenance_logs_stderr() -> TestResult {
    let end = RunEnd::Result {
        value: json!({ "n": 1 }),
        logs: vec!["first line".to_owned(), "second line".to_owned()],
        stderr: "a warning on stderr".to_owned(),
    };
    let (h, _runner) = harness(vec![ScriptPlan::new(vec![issue_call(1)], end)]).await?;
    let source = "const r = await atlas.call('jira.issue.get', {key: 'ABC-1'});\nreturn {n: 1};";
    let id = submit(&h, json!({ "source": source })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let p = script_preview(&h, &id)?;
    let b = script_body(&p)?;
    assert_eq!(b.item, ScriptItemKind::Result);
    assert!(
        matches!(b.view, PreviewBody::JsonTree { .. }),
        "{:?}",
        b.view
    );
    assert_eq!(b.source, source);
    assert_eq!(b.provenance, [row(1, "jira.issue.get", "ABC-1", "ok")]);
    assert_eq!(b.logs, ["first line", "second line"]);
    assert_eq!(b.logs_note, None);
    assert_eq!(b.stderr, "a warning on stderr");
    assert_eq!(p.header.class, "script");
    assert_eq!(p.preselect, None);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provenance_from_request_params_never_responses() -> TestResult {
    let (h, _runner) = harness(vec![ScriptPlan::new(
        vec![issue_call(1)],
        result_end(json!({ "n": 1 })),
    )])
    .await?;
    // The server answers with an issue whose key, summary and self link carry a canary. The
    // request named ABC-1; the script's call params never include a fetched value.
    let mut issue: Value = serde_json::from_str(fixtures::JIRA_ISSUE)?;
    issue["key"] = json!("CANARY-KEY-9");
    issue["self"] = json!("https://jira.corp.example/rest/api/2/issue/CANARY-SELF-9");
    issue["fields"]["summary"] = json!("CANARY-SUMMARY-9");
    // Above the harness's own answer for this path (priority 1 beats the default).
    let mock = requests_of(&h)?;
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/2/issue/ABC-1")))
        .respond_with(
            mock.response(200)
                .set_body_raw(issue.to_string(), "application/json"),
        )
        .with_priority(1)
        .mount(mock.server())
        .await;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let p = script_preview(&h, &id)?;
    // The positive control: the call is there, labelled from the request.
    assert_eq!(
        script_body(&p)?.provenance,
        [row(1, "jira.issue.get", "ABC-1", "ok")]
    );
    // The response, however, is nowhere in the preview, not even in the candidate view (the
    // script returned a value of its own).
    let shown = serde_json::to_string(&p)?;
    assert!(
        !shown.contains("CANARY"),
        "a response value reached the preview: {shown}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x12_lossy_count_only_truncated_or_lossy_meta_jira_half() -> TestResult {
    let calls = vec![
        // A truncated page: five issues exist, one came back.
        host_call(
            1,
            "jira.search",
            json!({ "jql": "project = ABC", "max": 1 }),
        ),
        // A full answer.
        issue_call(2),
        // A 4xx: the script saw a rejection, no data.
        host_call(3, "jira.issue.get", json!({ "key": "ABC-404" })),
    ];
    let (h, runner) = harness(vec![ScriptPlan::new(calls, result_end(json!(1)))]).await?;
    let mock = requests_of(&h)?;
    mock.json(
        "/rest/api/2/search",
        200,
        &fixtures::jira_search_page(0, 1, 5, 1),
    )
    .await;
    mock.json("/rest/api/2/issue/ABC-404", 404, fixtures::JIRA_ERROR_400)
        .await;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let results = runner.results();
    assert_eq!(results.len(), 3, "{results:?}");
    assert!(matches!(&results[0], HostCallResult::Ok(_)));
    assert!(matches!(&results[1], HostCallResult::Ok(_)));
    assert!(matches!(&results[2], HostCallResult::Rejected { .. }));
    let p = script_preview(&h, &id)?;
    let lossy: Vec<_> = p
        .warnings
        .iter()
        .filter(|w| w.id == WarningId::HostCallsLossy)
        .collect();
    assert_eq!(lossy.len(), 1, "{:?}", p.warnings);
    assert_eq!(
        lossy[0].text,
        "1 host calls returned truncated or lossy data"
    );
    // The rejection is a provenance row, not a lossy call.
    let b = script_body(&p)?;
    let outcomes: Vec<&str> = b.provenance.iter().map(|r| r.outcome.as_str()).collect();
    assert_eq!(outcomes, ["ok", "ok", "rejected:upstream_http"]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preselect_error_class_only_surfaced_for_queued_limit() -> TestResult {
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
    let p = script_preview(&h, &third)?;
    assert_eq!(p.preselect, Some(Preselect::ErrorClassOnly));
    let wire = serde_json::to_value(&p)?;
    assert_eq!(wire["preselect"], "error_class_only");
    assert_eq!(script_body(&p)?.item, ScriptItemKind::ErrorDetails);
    for id in [&first, &second] {
        let _ = h.await_(id, 100).await;
    }
    // A result that is not that limit outcome pre-selects nothing (`null` on the wire).
    let (h, _runner) = harness(vec![ScriptPlan::new(Vec::new(), result_end(json!(1)))]).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let wire = serde_json::to_value(script_preview(&h, &id)?)?;
    assert_eq!(wire["preselect"], Value::Null);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn error_details_preview_has_class_message_stack_elapsed() -> TestResult {
    let end = RunEnd::Error {
        class: "TypeError".to_owned(),
        message: "x is not a function".to_owned(),
        stack: "at main (script:3)".to_owned(),
        elapsed_ms: 12,
        logs: vec!["step 1".to_owned()],
        stderr: "boom".to_owned(),
    };
    let (h, _runner) = harness(vec![ScriptPlan::new(vec![issue_call(1)], end)]).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let p = script_preview(&h, &id)?;
    let b = script_body(&p)?;
    assert_eq!(b.item, ScriptItemKind::ErrorDetails);
    let view = serde_json::to_string(&b.view)?;
    for part in [
        "TypeError",
        "x is not a function",
        "at main (script:3)",
        "\"elapsed\"",
        "\"12\"",
    ] {
        assert!(view.contains(part), "{part} missing from {view}");
    }
    assert_eq!(b.logs, ["step 1"]);
    assert_eq!(b.stderr, "boom");
    assert_eq!(b.provenance, [row(1, "jira.issue.get", "ABC-1", "ok")]);
    assert_eq!(b.source, SRC);
    Ok(())
}

/// The header's §6.4 counts of `p` and the texts of its bidi / other-invisible Cautions.
fn invisible_counts(p: &Preview) -> ((u64, u64), Vec<String>) {
    let cautions = p
        .warnings
        .iter()
        .filter(|w| matches!(w.id, WarningId::BidiControls | WarningId::OtherInvisible))
        .map(|w| w.text.clone())
        .collect();
    ((p.header.bidi_controls, p.header.other_invisible), cautions)
}

/// T18 review I-3: the §6.4 counts and their Cautions cover what the script document shows
/// beyond the candidate: the source, the provenance, and a result's logs and stderr (from its
/// record). An error item's logs and stderr are in its candidate already and count once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bidi_counts_cover_source_provenance_logs_and_stderr() -> TestResult {
    use atlas_duck_preview::warning::{bidi_controls, other_invisible};
    let error_end = RunEnd::Error {
        class: "Error".to_owned(),
        message: "failed".to_owned(),
        stack: String::new(),
        elapsed_ms: 1,
        logs: vec!["error log \u{202E}".to_owned()],
        stderr: String::new(),
    };
    let output_end = RunEnd::Result {
        value: json!(1),
        logs: vec!["log \u{202E}".to_owned()],
        stderr: "stderr \u{200B}".to_owned(),
    };
    // A search whose JQL carries a soft hyphen (Cf: the registry's label filter keeps it).
    let search = host_call(
        1,
        "jira.search",
        json!({ "jql": "summary ~ \"x\u{00AD}y\"", "max": 1 }),
    );
    let (h, _runner) = harness(vec![
        ScriptPlan::new(Vec::new(), result_end(json!(1))),
        ScriptPlan::new(Vec::new(), output_end),
        ScriptPlan::new(Vec::new(), error_end),
        ScriptPlan::new(vec![search], result_end(json!(1))),
    ])
    .await?;
    let mut previews = Vec::new();
    for source in [
        "return 1; // \u{202E}\u{2066}",
        SRC,
        SRC,
        "return await atlas.call('jira.search', {});",
    ] {
        let id = submit(&h, json!({ "source": source })).await?;
        h.queued(&id, 20_000).await.ok_or("never queued")?;
        previews.push(script_preview(&h, &id)?);
    }
    // The source: two bidi controls.
    assert_eq!(
        invisible_counts(&previews[0]),
        ((2, 0), vec![bidi_controls(2)])
    );
    // A result's log and stderr, read from its record.
    assert_eq!(
        invisible_counts(&previews[1]),
        ((1, 1), vec![bidi_controls(1), other_invisible(1)])
    );
    // An error item's log: in its candidate and in atlas.log, counted once.
    assert_eq!(
        invisible_counts(&previews[2]),
        ((1, 0), vec![bidi_controls(1)])
    );
    // The provenance row's target.
    let b = script_body(&previews[3])?;
    assert!(
        b.provenance
            .iter()
            .any(|r| r.target_display.contains('\u{00AD}')),
        "{:?}",
        b.provenance
    );
    assert_eq!(
        invisible_counts(&previews[3]),
        ((0, 1), vec![other_invisible(1)])
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn result_logs_read_from_committed_record() -> TestResult {
    let end = RunEnd::Result {
        value: json!({ "n": 1 }),
        logs: vec!["from the record".to_owned()],
        stderr: "stderr from the record".to_owned(),
    };
    let (h, _runner) = harness(vec![ScriptPlan::new(vec![issue_call(1)], end)]).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let hits = common::test_hits(requests_of(&h)?).await.len();
    h.evict_candidate(&id);
    let p = script_preview(&h, &id)?;
    let b = script_body(&p)?;
    assert_eq!(b.logs, ["from the record"]);
    assert_eq!(b.stderr, "stderr from the record");
    // The rebuild reads the audit record only.
    assert_eq!(common::test_hits(requests_of(&h)?).await.len(), hits);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn result_logs_over_the_bound_are_cut_with_a_note() -> TestResult {
    let long = "x".repeat(600 * 1024);
    let end = RunEnd::Result {
        value: json!(1),
        logs: vec![long.clone(), long],
        stderr: String::new(),
    };
    let (h, _runner) = harness(vec![ScriptPlan::new(Vec::new(), end)]).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let b = script_body(&script_preview(&h, &id)?)?;
    let shown: usize = b.logs.iter().map(String::len).sum();
    assert!(shown < 1200 * 1024, "{shown}");
    assert!(b.logs.last().is_some_and(|l| l.contains("[truncated")));
    assert!(b.logs_note.is_some());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m13_rendered_fields_caution_when_run_called_rendered() -> TestResult {
    let (h, _runner) = harness(vec![
        ScriptPlan::new(
            vec![host_call(
                1,
                "jira.issue.get",
                json!({ "key": "ABC-1", "rendered": true }),
            )],
            result_end(json!(1)),
        ),
        ScriptPlan::new(
            vec![host_call(
                1,
                "jira.issue.get",
                json!({ "key": "ABC-1", "expand": ["renderedFields"] }),
            )],
            result_end(json!(1)),
        ),
        ScriptPlan::new(vec![issue_call(1)], result_end(json!(1))),
    ])
    .await?;
    let caution = |p: &Preview| {
        p.warnings
            .iter()
            .filter(|w| w.id == WarningId::ScriptRenderedCopies)
            .map(|w| w.text.clone())
            .collect::<Vec<_>>()
    };
    for _ in 0..2 {
        let id = submit(&h, json!({ "source": SRC })).await?;
        h.queued(&id, 20_000).await.ok_or("never queued")?;
        let p = script_preview(&h, &id)?;
        assert_eq!(caution(&p), [TEXT_SCRIPT_RENDERED_COPIES]);
    }
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let p = script_preview(&h, &id)?;
    assert!(caution(&p).is_empty(), "{:?}", p.warnings);
    Ok(())
}

/// T17 review I-2 (X-12): an answer that is a complete page does not count as lossy; only a
/// truncated page (a next start) does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x12_a_full_page_does_not_count_as_lossy() -> TestResult {
    let calls = vec![host_call(
        1,
        "jira.search",
        json!({ "jql": "project = ABC", "max": 50 }),
    )];
    let (h, _runner) = harness(vec![ScriptPlan::new(calls, result_end(json!(1)))]).await?;
    requests_of(&h)?
        .json(
            "/rest/api/2/search",
            200,
            &fixtures::jira_search_page(0, 50, 1, 1),
        )
        .await;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let p = script_preview(&h, &id)?;
    assert!(
        !p.warnings.iter().any(|w| w.id == WarningId::HostCallsLossy),
        "{:?}",
        p.warnings
    );
    let b = script_body(&p)?;
    assert_eq!(b.provenance.len(), 1, "{:?}", b.provenance);
    assert_eq!(b.provenance[0].outcome, "ok");
    Ok(())
}

/// T17 review I-3: a call still in flight when the run ends is a `cancelled_in_flight` row,
/// labelled from its request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_cancelled_in_flight_is_a_provenance_row() -> TestResult {
    let (h, id, _server) = queued_with_a_call_in_flight(
        Some(RunEnd::HostLimit {
            name: "timeout_s".to_owned(),
        }),
        false,
    )
    .await?;
    let p = script_preview(&h, &id)?;
    assert_eq!(
        script_body(&p)?.provenance,
        [row(1, "jira.issue.get", "ABC-1", "cancelled_in_flight")]
    );
    Ok(())
}

/// T17 review M-1: an error item's logs were bounded once, by the candidate; the preview shows
/// the candidate's own markers (the real counts), not a second cut of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn error_item_logs_keep_the_candidates_truncation_markers() -> TestResult {
    let long = "x".repeat(600 * 1024);
    let end = RunEnd::Error {
        class: "Error".to_owned(),
        message: "boom".to_owned(),
        stack: String::new(),
        elapsed_ms: 1,
        logs: vec![long.clone(), long.clone(), long.clone(), long],
        stderr: String::new(),
    };
    let (h, _runner) = harness(vec![ScriptPlan::new(Vec::new(), end)]).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let b = script_body(&script_preview(&h, &id)?)?;
    assert_eq!(b.item, ScriptItemKind::ErrorDetails);
    assert_eq!(b.logs.len(), 3, "{}", b.logs.len());
    assert!(
        b.logs[1].ends_with("\n[truncated 180224 bytes]"),
        "{}",
        &b.logs[1][b.logs[1].len().saturating_sub(40)..]
    );
    assert_eq!(b.logs[2], "[truncated 2 log lines]");
    assert!(b.logs_note.is_some());
    Ok(())
}

// ---- Task 19a: cancel, slots and dispatch sweep (I-10, I-13, I-14, M3 M-1) -----------------------
//
// Structural checks only (L26): every wait below is a hang guard, no test asserts how long
// something took. Runs that must not end hold for ten minutes and are cancelled or killed.

use std::sync::atomic::AtomicU32;
use std::sync::{Mutex, PoisonError};

use async_trait::async_trait;
use atlas_duck_core::lifecycle::model::Phase;
use atlas_duck_core::{RunHandle, RunSpec, ScriptRunner};
use atlas_duck_ipc::sandbox::ScriptLimits;

/// A check run inside `RunHandle::kill`.
type KillProbe = Box<dyn Fn() + Send + Sync>;

/// The fake runner with the two things a [`ScriptPlan`] cannot say: from the `hang_from`th start
/// on, `wait` never settles (a reaper that never comes), and a probe runs inside every `kill`.
struct WrappedRunner {
    inner: Arc<FakeScriptRunner>,
    hang_from: u32,
    started: AtomicU32,
    on_kill: Arc<Mutex<Option<KillProbe>>>,
}

impl WrappedRunner {
    fn new(plans: Vec<ScriptPlan>, hang_from: u32) -> Arc<WrappedRunner> {
        Arc::new(WrappedRunner {
            inner: FakeScriptRunner::new(plans),
            hang_from,
            started: AtomicU32::new(0),
            on_kill: Arc::new(Mutex::new(None)),
        })
    }

    fn probe_kill(&self, probe: KillProbe) {
        *self.on_kill.lock().unwrap_or_else(PoisonError::into_inner) = Some(probe);
    }
}

#[async_trait]
impl ScriptRunner for WrappedRunner {
    async fn check_available(&self, policy: RunPolicy) -> Result<(), RunnerError> {
        self.inner.check_available(policy).await
    }

    async fn compile_check(
        &self,
        source: &str,
        limits: &ScriptLimits,
        policy: RunPolicy,
    ) -> Result<(), CompileFailure> {
        self.inner.compile_check(source, limits, policy).await
    }

    fn confinement(&self, policy: RunPolicy) -> Option<RunConfinement> {
        self.inner.confinement(policy)
    }

    async fn start(
        &self,
        run: RunSpec,
        calls: Arc<dyn HostCalls>,
    ) -> Result<Arc<dyn RunHandle>, RunnerError> {
        let inner = self.inner.start(run, calls).await?;
        let n = self.started.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(WrappedRun {
            inner,
            hang: n >= self.hang_from,
            on_kill: self.on_kill.clone(),
        }))
    }
}

struct WrappedRun {
    inner: Arc<dyn RunHandle>,
    hang: bool,
    on_kill: Arc<Mutex<Option<KillProbe>>>,
}

#[async_trait]
impl RunHandle for WrappedRun {
    fn kill(&self, why: KillReason) {
        if let Some(probe) = self
            .on_kill
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            probe();
        }
        self.inner.kill(why);
    }

    async fn wait(&self) -> RunEnd {
        if self.hang {
            std::future::pending::<()>().await;
        }
        self.inner.wait().await
    }
}

/// `fut`, or an error after a minute: a hang guard, never a speed assertion.
async fn bounded<T>(what: &str, fut: impl std::future::Future<Output = T>) -> Result<T, TestError> {
    tokio::time::timeout(Duration::from_secs(60), fut)
        .await
        .map_err(|_| format!("{what} hung").into())
}

async fn wait_slot_wait(h: &Harness, id: &str) -> TestResult {
    wait_for("the wait for a real slot", || {
        h.engine()
            .entry(id)
            .is_some_and(|e| matches!(e.state().model.phase(), Phase::SlotWait))
    })
    .await
}

/// A Jira instance at a raw server (`steps[i]` answers connection `i`) and `runner`; calls
/// never time out on their own unless `per_call` says so.
async fn raw_scripts(
    steps: Vec<Vec<RawStep>>,
    runner: Arc<dyn ScriptRunner>,
    per_call: Duration,
) -> Result<(Harness, RawHttpServer), TestError> {
    let server = RawHttpServer::serve_sequence(steps).await?;
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
            per_call,
            ..Timeouts::default()
        })
        .scripts(runner)
        .start()
        .await?;
    Ok((h, server))
}

/// Waits until the fetch of `id` has received at least `bytes` of a body.
async fn wait_partial(h: &Harness, id: &str, bytes: usize) -> TestResult {
    wait_for("the fetch's bytes", || {
        h.engine()
            .entry(id)
            .and_then(|e| e.fetch_control())
            .is_some_and(|c| c.take_captured().partial.len() >= bytes)
    })
    .await
}

fn assert_cancelled(env: &Envelope) {
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    assert_eq!(exit(env), 7);
    assert_eq!(code(env), "cancelled");
    assert_eq!(detail(env, "reason"), json!("by_client"));
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
}

/// I-10 (§13 Cancel, §4.4): cancelling a running script, a script waiting for a slot, a finished
/// script in `AwaitingRelease`, a read in `Fetching` and a read in `AwaitingRelease` gives one
/// envelope; no release item appears; the killed run logs `SCRIPT_FAILED {cancelled_by_client}`
/// then `CANCELLED`. The reaper never answers here (`wait` of the two running scripts never
/// settles), and every cancel still answers: no response path waits on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i10_cancel_identical_running_slotwait_awaiting_release_reads() -> TestResult {
    let issue = fixtures::JIRA_ISSUE.as_bytes();
    let steps = vec![
        vec![
            RawStep::Send(raw_answer(br#"{"key":"#, 1_000_000)),
            RawStep::Sleep(120_000),
        ],
        vec![RawStep::Send(raw_answer(issue, issue.len()))],
    ];
    let hold = || ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(600_000);
    // The first run finishes (its `wait` answers); the next two hang in `wait`.
    let runner = WrappedRunner::new(
        vec![
            ScriptPlan::new(Vec::new(), result_end(json!(1))),
            hold(),
            hold(),
            hold(),
        ],
        1,
    );
    let (h, server) = raw_scripts(steps, runner.clone(), Duration::from_secs(300)).await?;
    let finished = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&finished, 20_000).await.ok_or("never queued")?;
    let running_a = submit(&h, json!({ "source": SRC })).await?;
    let running_b = submit(&h, json!({ "source": SRC })).await?;
    wait_for("both real slots", || runner.inner.starts() == 3).await?;
    let waiting = submit(&h, json!({ "source": SRC })).await?;
    wait_slot_wait(&h, &waiting).await?;
    let fetching = request_id(&h.submit("jira.issue.get", json!({ "key": "ABC-1" })).await)?;
    wait_for("the connection", || server.connections() >= 1).await?;
    wait_partial(&h, &fetching, 1).await?;
    let read_item = request_id(&h.submit("jira.issue.get", json!({ "key": "ABC-2" })).await)?;
    h.queued(&read_item, 20_000).await.ok_or("never queued")?;
    let ids = [
        &running_a, &running_b, &waiting, &finished, &fetching, &read_item,
    ];
    let mut lines = Vec::new();
    for id in ids {
        let env = bounded("cancel", h.handler().cancel(id)).await?;
        assert_cancelled(&env);
        lines.push(without_ids(env).to_json_line());
        assert_eq!(h.status(id).await.status, Status::Cancelled);
        assert!(h.approver().item(id).is_none(), "{id} is still queued");
    }
    assert!(lines.iter().all(|l| *l == lines[0]), "{lines:?}");
    // The killed runs: `SCRIPT_FAILED {cancelled_by_client}`, then `CANCELLED`, no release item.
    for id in [&running_a, &running_b] {
        let events = h.events(id).await?;
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
        assert_eq!(events[2].1["reason"], "cancelled_by_client");
        assert_eq!(events[2].1["direct"], false);
    }
    assert_eq!(
        runner.inner.kills(),
        [None, Some(KillReason::Client), Some(KillReason::Client)]
    );
    assert_eq!(
        h.event_types(&waiting).await?,
        [EventType::REQUEST_RECEIVED, EventType::CANCELLED]
    );
    assert_eq!(
        h.event_types(&finished).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::SCRIPT_STARTED,
            EventType::SCRIPT_FINISHED,
            EventType::CANCELLED,
        ]
    );
    for id in ids {
        let types = h.event_types(id).await?;
        assert!(
            !types.contains(&EventType::SCRIPT_RELEASED)
                && !types.contains(&EventType::READ_RELEASED),
            "{types:?}"
        );
        assert_eq!(types.last(), Some(&EventType::CANCELLED));
    }
    Ok(())
}

/// I-13 (§13 Script slots): with both real slots held by runs that never end, a dry run, a
/// submit-time syntax failure, a compile timeout and an unavailability still answer: none of
/// them waits on a real-run slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i13_dry_runs_compile_and_direct_failures_never_wait_on_real_slot() -> TestResult {
    let hold = || ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(600_000);
    let (h, runner) = harness(vec![
        hold(),
        hold(),
        ScriptPlan::new(vec![issue_call(1)], result_end(json!({ "dry": true }))),
        ScriptPlan::syntax_error(1, 1, "unexpected token"),
        ScriptPlan::compile_failure(CompileFailure::Timeout { timeout_s: 10 }),
    ])
    .await?;
    let first = submit(&h, json!({ "source": SRC })).await?;
    let second = submit(&h, json!({ "source": SRC })).await?;
    wait_for("both real slots", || runner.starts() == 2).await?;
    // A dry run.
    let id = submit(&h, json!({ "source": SRC, "dry_run": true })).await?;
    let env = h.await_(&id, 30_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    assert_eq!(
        runner.specs().iter().map(|s| s.dry_run).collect::<Vec<_>>(),
        [false, false, true]
    );
    // A syntax failure.
    let id = submit(&h, json!({ "source": SRC })).await?;
    let env = h.await_(&id, 30_000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "script_syntax");
    // A compile timeout: a data-free `script_limit`.
    let id = submit(&h, json!({ "source": SRC })).await?;
    let env = h.await_(&id, 30_000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "script_limit");
    // An unavailable sandbox, before any compile.
    runner.fail_available(unavailable(UnavailableReason::FloorNotMet));
    let id = submit(&h, json!({ "source": SRC })).await?;
    let env = h.await_(&id, 30_000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "sandbox_unavailable");
    assert_eq!(runner.compile_checks(), 5);
    // The two real runs held their slots throughout and no other real run started.
    assert_eq!(runner.starts(), 3);
    for id in [&first, &second] {
        assert_eq!(h.status(id).await.status, Status::Pending);
        let types = h.event_types(id).await?;
        assert!(!types.contains(&EventType::SCRIPT_FINISHED), "{types:?}");
    }
    for id in [&first, &second] {
        h.handler().cancel(id).await;
    }
    Ok(())
}

/// I-13: a real run that waited for a slot and then hits `timeout_s` before any host call is
/// `pending` and a release item with "keep error class only" pre-selected (§9.5).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i13_queued_timeout_before_call_is_release_with_preset() -> TestResult {
    let hold = || ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(600_000);
    let limited = ScriptPlan::new(
        Vec::new(),
        RunEnd::HostLimit {
            name: "timeout_s".to_owned(),
        },
    );
    let (h, runner) = harness(vec![hold(), hold(), limited]).await?;
    let first = submit(&h, json!({ "source": SRC })).await?;
    let second = submit(&h, json!({ "source": SRC })).await?;
    wait_for("both real slots", || runner.starts() == 2).await?;
    let third = submit(&h, json!({ "source": SRC })).await?;
    wait_slot_wait(&h, &third).await?;
    // A slot frees: the waiting run starts and hits its limit before any call.
    h.handler().cancel(&first).await;
    h.queued(&third, 30_000).await.ok_or("never queued")?;
    assert_eq!(h.status(&third).await.status, Status::Pending);
    let started = record(&h, &third, EventType::SCRIPT_STARTED).await?;
    assert_eq!(started["queued"], true);
    let failed = record(&h, &third, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "timeout_s");
    assert_eq!(failed["queued"], true);
    assert_eq!(failed["dispatched"], false);
    assert_eq!(failed["direct"], false);
    assert_eq!(failed["candidate"]["class"], "script_limit");
    let types = h.event_types(&third).await?;
    assert!(!types.contains(&EventType::SCRIPT_CALL_SENT), "{types:?}");
    assert_eq!(types.last(), Some(&EventType::SCRIPT_FAILED));
    let p = script_preview(&h, &third)?;
    assert_eq!(p.preselect, Some(Preselect::ErrorClassOnly));
    h.approver()
        .release_redacted(
            &third,
            vec![atlas_duck_core::RedactionOp::Preset(
                atlas_duck_core::RedactionPreset::ErrorClassOnly,
            )],
        )
        .map_err(de)?;
    let env = h.await_(&third, 10_000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    assert_eq!(exit(&env), 8);
    assert!(env.redacted);
    assert_eq!(
        env.data.clone().ok_or("no data")?["script_error"],
        json!({ "class": "script_limit" })
    );
    h.handler().cancel(&second).await;
    Ok(())
}

/// I-13: slot saturation never yields `busy`: more scripts than slots are all `pending` and the
/// ones past the slots wait for one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i13_slot_saturation_never_busy() -> TestResult {
    let hold = || ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(600_000);
    let (h, runner) = harness((0..8).map(|_| hold()).collect()).await?;
    let mut ids = Vec::new();
    for _ in 0..8 {
        let env = h.submit_script(json!({ "source": SRC })).await;
        assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
        assert_ne!(code(&env), "busy");
        ids.push(request_id(&env)?);
    }
    wait_for("both real slots", || runner.starts() == 2).await?;
    wait_for("every compile check", || runner.compile_checks() == 8).await?;
    for id in &ids[2..] {
        wait_slot_wait(&h, id).await?;
    }
    assert_eq!(runner.starts(), 2);
    for id in &ids {
        assert_eq!(h.status(id).await.status, Status::Pending);
    }
    // The waiting runs first, so no cancel hands a slot on.
    for id in ids.iter().rev() {
        let env = h.handler().cancel(id).await;
        assert_cancelled(&env);
    }
    Ok(())
}

/// I-14 case 1 (§9.5): `timeout_s` fires while the first host call is in flight.
async fn dispatch_case_1() -> TestResult {
    let (h, id, _server) = queued_with_a_call_in_flight(
        Some(RunEnd::HostLimit {
            name: "timeout_s".to_owned(),
        }),
        false,
    )
    .await?;
    assert_eq!(h.status(&id).await.status, Status::Pending);
    assert_in_flight_then_failed(&h.events(&id).await?, "timeout_s")?;
    let item = h.approver().item(&id).ok_or("no release item")?;
    assert!(item.approvable);
    Ok(())
}

/// I-14 case 2: the first call fails (a network error, or the per-call timeout), the script
/// catches it and spins until `timeout_s`.
async fn dispatch_case_2(close: bool) -> TestResult {
    let (steps, per_call) = if close {
        (vec![vec![RawStep::Close]; 4], Duration::from_secs(300))
    } else {
        (
            vec![vec![RawStep::Sleep(120_000)]; 4],
            Duration::from_millis(300),
        )
    };
    let limited = RunEnd::HostLimit {
        name: "timeout_s".to_owned(),
    };
    let runner = FakeScriptRunner::new(vec![ScriptPlan::new(vec![issue_call(1)], limited)]);
    let (h, _server) = raw_scripts(steps, runner.clone(), per_call).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 60_000).await.ok_or("never queued")?;
    assert_eq!(h.status(&id).await.status, Status::Pending);
    assert!(
        matches!(
            runner.results().as_slice(),
            [HostCallResult::Rejected { .. }]
        ),
        "{:?}",
        runner.results()
    );
    let types = h.event_types(&id).await?;
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
    let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "timeout_s");
    assert_eq!(failed["dispatched"], true);
    assert_eq!(failed["queued"], false);
    assert_eq!(failed["direct"], false);
    assert!(h.approver().item(&id).is_some());
    Ok(())
}

/// I-14 case 3: a `max_fetch_mb` overrun on the first response, of a paged op (paged reads
/// apply the run's remaining fetch budget to a response: the call itself is refused).
async fn dispatch_case_3() -> TestResult {
    let end = RunEnd::HostLimit {
        name: "max_fetch_mb".to_owned(),
    };
    let search = host_call(
        1,
        "jira.search",
        json!({ "jql": "project = ABC", "max": 1 }),
    );
    let (h, runner) = harness(vec![ScriptPlan::new(vec![search], end)]).await?;
    let page = json!({
        "startAt": 0, "maxResults": 1, "total": 100_000,
        "issues": [{ "id": "1", "key": "ABC-1", "fields": { "summary": "s".repeat(1_300_000) } }]
    });
    requests_of(&h)?
        .json("/rest/api/2/search", 200, &page.to_string())
        .await;
    let id = submit(
        &h,
        json!({ "source": SRC, "limits": { "max_fetch_mb": 1 } }),
    )
    .await?;
    h.queued(&id, 30_000).await.ok_or("never queued")?;
    assert_eq!(h.status(&id).await.status, Status::Pending);
    match runner.results().as_slice() {
        [HostCallResult::Rejected { class, .. }] => assert_eq!(class, "script_limit"),
        other => return Err(format!("unexpected answers: {other:?}").into()),
    }
    let types = h.event_types(&id).await?;
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
    let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "max_fetch_mb");
    assert_eq!(failed["dispatched"], true);
    assert_eq!(failed["direct"], false);
    Ok(())
}

/// I-14 case 3 for a plain (non-paged) call: the first response of a `jira.issue.get` is over
/// the run's remaining `max_fetch_mb`. Its body is cut there (T19d): the call answers
/// `script_limit` and its record keeps the bytes received up to the cut, not the 4 MiB body.
/// They take the run's fetched bytes to `max_fetch_mb`, so the next call is refused
/// `script_limit` before it is sent, and the run ends `pending`, then a release item.
async fn dispatch_case_3_plain() -> TestResult {
    let end = RunEnd::HostLimit {
        name: "max_fetch_mb".to_owned(),
    };
    let (h, runner) = harness(vec![ScriptPlan::new(
        vec![issue_call(1), issue_call(2)],
        end,
    )])
    .await?;
    mount_big_issue(&h, "ABC-1", BIG_BODY).await?;
    let id = submit(
        &h,
        json!({ "source": SRC, "limits": { "max_fetch_mb": 1 } }),
    )
    .await?;
    h.queued(&id, 30_000).await.ok_or("never queued")?;
    assert_eq!(h.status(&id).await.status, Status::Pending);
    match runner.results().as_slice() {
        [
            HostCallResult::Rejected { class: first, .. },
            HostCallResult::Rejected { class, .. },
        ] => {
            assert_eq!(first, "script_limit");
            assert_eq!(class, "script_limit");
        }
        other => return Err(format!("unexpected answers: {:?}", outline(other)).into()),
    }
    assert_eq!(sent_to(&h, "ABC-1").await?, 1, "the refused call was sent");
    let call = record(&h, &id, EventType::SCRIPT_CALL).await?;
    assert_cut(&call, "max_fetch_mb", "fetch_cap_50mib", MIB)?;
    let types = h.event_types(&id).await?;
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
    let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "max_fetch_mb");
    assert_eq!(failed["dispatched"], true);
    assert_eq!(failed["direct"], false);
    Ok(())
}

/// I-14 case 4:a compile error, or a host-measured limit before any request was sent by a run
/// that did not wait for a slot, is direct, exit 8.
async fn dispatch_case_4() -> TestResult {
    let limited = RunEnd::HostLimit {
        name: "max_calls".to_owned(),
    };
    let (h, _runner) = harness(vec![
        ScriptPlan::syntax_error(1, 2, "unexpected token"),
        ScriptPlan::new(Vec::new(), limited),
    ])
    .await?;
    for (reason, want) in [
        ("script_syntax", "script_syntax"),
        ("max_calls", "script_limit"),
    ] {
        let id = submit(&h, json!({ "source": SRC })).await?;
        let env = h.await_(&id, 30_000).await;
        assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
        assert_eq!(exit(&env), 8);
        assert_eq!(code(&env), want);
        let failed = record(&h, &id, EventType::SCRIPT_FAILED).await?;
        assert_eq!(failed["reason"], reason);
        assert_eq!(failed["direct"], true);
        assert_eq!(failed["queued"], false);
        assert_eq!(failed["dispatched"], false);
        assert!(h.approver().item(&id).is_none());
    }
    Ok(())
}

/// I-14 case 5: a user kill of a non-queued run before its first host call is `pending` and a
/// release item with `SCRIPT_FAILED {direct: false}` and no terminal event; a crash before the
/// decision gives `ABANDONED`; the evicted candidates of that kill and of a `queued` run's
/// pre-dispatch limit rebuild from their `SCRIPT_FAILED` payloads with matching hashes.
async fn dispatch_case_5() -> TestResult {
    let hold = || ScriptPlan::new(Vec::new(), result_end(json!(1))).holding(600_000);
    let limited = ScriptPlan::new(
        Vec::new(),
        RunEnd::HostLimit {
            name: "timeout_s".to_owned(),
        },
    );
    let (mut h, runner) = harness(vec![hold(), hold(), hold(), limited]).await?;
    // The kill of a run that never queued and never called.
    let killed = submit(&h, json!({ "source": SRC })).await?;
    wait_for("the run", || runner.starts() == 1).await?;
    assert_eq!(h.engine().kill_script(&killed), KillAnswer::Killed);
    h.queued(&killed, 30_000).await.ok_or("never queued")?;
    let failed = record(&h, &killed, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "killed_by_user");
    assert_eq!(failed["direct"], false);
    assert_eq!(failed["queued"], false);
    assert_eq!(failed["dispatched"], false);
    // A queued run's limit before its first call.
    let holder_a = submit(&h, json!({ "source": SRC })).await?;
    wait_for("the second run", || runner.starts() == 2).await?;
    let holder_b = submit(&h, json!({ "source": SRC })).await?;
    wait_for("the third run", || runner.starts() == 3).await?;
    let queued = submit(&h, json!({ "source": SRC })).await?;
    wait_slot_wait(&h, &queued).await?;
    assert_eq!(h.engine().kill_script(&holder_a), KillAnswer::Killed);
    h.queued(&queued, 30_000).await.ok_or("never queued")?;
    let failed = record(&h, &queued, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "timeout_s");
    assert_eq!(failed["queued"], true);
    assert_eq!(failed["dispatched"], false);
    assert_eq!(failed["direct"], false);
    // No terminal event until release or deny.
    for id in [&killed, &queued] {
        assert_eq!(h.status(id).await.status, Status::Pending);
        assert_eq!(
            h.event_types(id).await?.last(),
            Some(&EventType::SCRIPT_FAILED)
        );
    }
    // Evicted, both rebuild from the `SCRIPT_FAILED` payload with the hash they had.
    for id in [&killed, &queued] {
        let before = h.approver().rev(id).map_err(de)?;
        h.evict_candidate(id);
        let delivery = h.approver().open(id).map_err(de)?;
        assert!(delivery.preview.approvable, "{id} is not releasable");
        let after = h.approver().rev(id).map_err(de)?;
        assert_eq!(before.candidate_hash, after.candidate_hash, "{id}");
    }
    // A crash before any decision: every one of them is `ABANDONED`.
    h.reopen_and_restart().await?;
    for id in [&killed, &queued, &holder_a, &holder_b] {
        assert_eq!(
            h.event_types(id).await?.last(),
            Some(&EventType::ABANDONED),
            "{id}"
        );
    }
    Ok(())
}

/// I-14 (§13 Dispatch rule, §9.5): the five cases, one subtest each.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i14_dispatch_rule_cases_1_to_5() -> TestResult {
    let results = [
        (
            "case 1: timeout while the first call is in flight",
            dispatch_case_1().await,
        ),
        (
            "case 2: the first call fails with a network error",
            dispatch_case_2(true).await,
        ),
        (
            "case 2: the first call fails with the per-call timeout",
            dispatch_case_2(false).await,
        ),
        (
            "case 3: max_fetch_mb overrun on the first response",
            dispatch_case_3().await,
        ),
        (
            "case 3: max_fetch_mb overrun on a plain call's first response",
            dispatch_case_3_plain().await,
        ),
        (
            "case 4: compile error or direct limit",
            dispatch_case_4().await,
        ),
        (
            "case 5: user kill before the first call",
            dispatch_case_5().await,
        ),
    ];
    for (name, result) in results {
        if let Err(e) = result {
            return Err(format!("{name}: {e}").into());
        }
    }
    Ok(())
}

// ---- T19d: a plain call's body is cut at the run's fetch budget and the call's result cap -----

const MIB: u64 = 1024 * 1024;

/// The summary of an issue far larger than any cut below plus its tolerance.
const BIG_BODY: usize = 4 * 1024 * 1024;

/// How far past a cut a record's bytes may reach: the chunk that crossed it is kept, and one
/// read of the mock's body can return up to two of its 512 KiB writes (atlassian
/// `pagination.rs`, `FETCH_CAP_TOLERANCE`).
const CUT_TOLERANCE: u64 = 1024 * 1024;

/// The answers as `ok` or the rejection class (an answer can be megabytes).
fn outline(results: &[HostCallResult]) -> Vec<String> {
    results
        .iter()
        .map(|r| match r {
            HostCallResult::Ok(_) => "ok".to_owned(),
            HostCallResult::Rejected { class, .. } => class.clone(),
        })
        .collect()
}

/// `key`'s issue with a summary of `summary` bytes, ahead of the harness's fixture.
async fn mount_big_issue(h: &Harness, key: &str, summary: usize) -> TestResult {
    let mut issue: Value = serde_json::from_str(fixtures::JIRA_ISSUE)?;
    issue["key"] = json!(key);
    issue["fields"]["summary"] = json!("s".repeat(summary));
    let mock = requests_of(h)?;
    Mock::given(method("GET"))
        .and(path(mock.path(&format!("/rest/api/2/issue/{key}"))))
        .respond_with(
            mock.response(200)
                .set_body_raw(issue.to_string(), "application/json"),
        )
        .with_priority(1)
        .mount(mock.server())
        .await;
    Ok(())
}

/// The requests the mock received for `key`'s issue.
async fn sent_to(h: &Harness, key: &str) -> Result<usize, TestError> {
    let mock = requests_of(h)?;
    let want = mock.path(&format!("/rest/api/2/issue/{key}"));
    Ok(mock
        .received()
        .await
        .iter()
        .filter(|r| r.url.path() == want)
        .count())
}

/// A `SCRIPT_CALL` record of a body cut with `left` bytes of budget: rejected as `rejection`,
/// naming `cap`, no complete answer, and the bytes received up to the cut, not the whole body.
fn assert_cut(call: &Value, rejection: &str, cap: &str, left: u64) -> TestResult {
    assert_eq!(call["rejection"], rejection, "{call}");
    assert_eq!(call["cap_or_budget"], cap, "{call}");
    assert_eq!(call["outcome"], "too_large", "{call}");
    let bytes = call["bytes"].as_u64().ok_or("no bytes")?;
    assert!(bytes > left, "{bytes} vs {left}");
    assert!(bytes <= left + CUT_TOLERANCE, "{bytes} vs {left}");
    Ok(())
}

async fn script_calls(h: &Harness, id: &str) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(t, _)| *t == EventType::SCRIPT_CALL)
        .map(|(_, p)| p)
        .collect())
}

/// §9.5 "`max_call_result_mb` overrun on a streaming body": a plain call's body is cut at
/// `max_call_result_mb` (`result_too_large`), not read whole and measured afterwards. The run's
/// fetch budget is far away, so the next call is sent and cut the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plain_call_body_is_cut_at_max_call_result_mb() -> TestResult {
    let (h, runner) = harness(vec![ScriptPlan::new(
        vec![issue_call(1), issue_call(2)],
        result_end(json!(1)),
    )])
    .await?;
    mount_big_issue(&h, "ABC-1", BIG_BODY).await?;
    let id = submit(
        &h,
        json!({ "source": SRC, "limits": { "max_call_result_mb": 1 } }),
    )
    .await?;
    h.queued(&id, 30_000).await.ok_or("never queued")?;
    assert_eq!(
        outline(&runner.results()),
        ["result_too_large", "result_too_large"]
    );
    assert_eq!(sent_to(&h, "ABC-1").await?, 2);
    let calls = script_calls(&h, &id).await?;
    assert_eq!(calls.len(), 2, "{calls:?}");
    for call in &calls {
        assert_cut(call, "result_too_large", "response_cap_32mib", MIB)?;
    }
    Ok(())
}

/// A plain call's fetch budget is `max_fetch_mb` minus the bytes the run already fetched: after
/// a 600 KiB answer, the next body is cut with about 424 KiB left (`script_limit`), below the
/// 1 MiB `max_call_result_mb` (with the full cap as its budget it would be cut at the result cap,
/// `result_too_large`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plain_call_fetch_budget_is_the_cap_minus_the_bytes_fetched() -> TestResult {
    let second = host_call(2, "jira.issue.get", json!({ "key": "ABC-2" }));
    let (h, runner) = harness(vec![ScriptPlan::new(
        vec![issue_call(1), second],
        result_end(json!(1)),
    )])
    .await?;
    mount_big_issue(&h, "ABC-1", 600 * 1024).await?;
    mount_big_issue(&h, "ABC-2", BIG_BODY).await?;
    let id = submit(
        &h,
        json!({ "source": SRC, "limits": { "max_fetch_mb": 1, "max_call_result_mb": 1 } }),
    )
    .await?;
    h.queued(&id, 30_000).await.ok_or("never queued")?;
    assert_eq!(outline(&runner.results()), ["ok", "script_limit"]);
    let calls = script_calls(&h, &id).await?;
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert_eq!(calls[0]["rejection"], Value::Null, "{}", calls[0]);
    let first = calls[0]["bytes"].as_u64().ok_or("no bytes")?;
    assert!(first > 600 * 1024 && first < MIB, "{first}");
    assert_cut(&calls[1], "max_fetch_mb", "fetch_cap_50mib", MIB - first)?;
    Ok(())
}

/// `jira.issue.get` with `comments: true` (a composite read): its issue GET is a plain GET, cut
/// at the run's fetch budget like any other; no comment page is requested.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plain_call_with_comments_cuts_the_issue_at_the_fetch_budget() -> TestResult {
    let call = host_call(
        1,
        "jira.issue.get",
        json!({ "key": "ABC-1", "comments": true }),
    );
    let (h, runner) = harness(vec![ScriptPlan::new(vec![call], result_end(json!(1)))]).await?;
    mount_big_issue(&h, "ABC-1", BIG_BODY).await?;
    let id = submit(
        &h,
        json!({ "source": SRC, "limits": { "max_fetch_mb": 1 } }),
    )
    .await?;
    h.queued(&id, 30_000).await.ok_or("never queued")?;
    assert_eq!(outline(&runner.results()), ["script_limit"]);
    let calls = script_calls(&h, &id).await?;
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_cut(&calls[0], "max_fetch_mb", "fetch_cap_50mib", MIB)?;
    let comment_pages = requests_of(&h)?
        .received()
        .await
        .iter()
        .filter(|r| r.url.path().ends_with("/comment"))
        .count();
    assert_eq!(comment_pages, 0);
    Ok(())
}

/// `key`'s issue as a body of exactly `len` bytes (the summary takes up the rest).
fn issue_of_len(key: &str, len: usize) -> Result<String, TestError> {
    let mut issue: Value = serde_json::from_str(fixtures::JIRA_ISSUE)?;
    issue["key"] = json!(key);
    issue["fields"]["summary"] = json!("");
    let rest = len
        .checked_sub(issue.to_string().len())
        .ok_or("the issue is longer than len")?;
    issue["fields"]["summary"] = json!("s".repeat(rest));
    let body = issue.to_string();
    assert_eq!(body.len(), len);
    Ok(body)
}

/// `GET` of `key`'s issue answers `body`, ahead of the harness's fixture.
async fn mount_issue_body(h: &Harness, key: &str, body: String) -> TestResult {
    let mock = requests_of(h)?;
    Mock::given(method("GET"))
        .and(path(mock.path(&format!("/rest/api/2/issue/{key}"))))
        .respond_with(mock.response(200).set_body_raw(body, "application/json"))
        .with_priority(1)
        .mount(mock.server())
        .await;
    Ok(())
}

/// T19d review M-7: a plain call's body of exactly the run's remaining fetch budget is read
/// whole (`ok`, the cut is past the budget, not at it), and it leaves nothing: the next call is
/// refused before it is sent. One byte more is cut (`script_limit`), every byte kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plain_call_body_of_exactly_the_fetch_budget_is_read_whole() -> TestResult {
    let at = |id, key: &str| host_call(id, "jira.issue.get", json!({ "key": key }));
    let budget = usize::try_from(MIB)?;
    let (h, runner) = harness(vec![
        ScriptPlan::new(vec![at(1, "ABC-5"), at(2, "ABC-7")], result_end(json!(1))),
        ScriptPlan::new(vec![at(1, "ABC-6")], result_end(json!(1))),
    ])
    .await?;
    mount_issue_body(&h, "ABC-5", issue_of_len("ABC-5", budget)?).await?;
    mount_issue_body(&h, "ABC-6", issue_of_len("ABC-6", budget + 1)?).await?;
    let limits = json!({ "max_fetch_mb": 1, "max_call_result_mb": 2 });
    let exact = submit(&h, json!({ "source": SRC, "limits": limits.clone() })).await?;
    h.queued(&exact, 30_000).await.ok_or("never queued")?;
    assert_eq!(outline(&runner.results()), ["ok", "script_limit"]);
    assert_eq!(sent_to(&h, "ABC-7").await?, 0, "the refused call was sent");
    let calls = script_calls(&h, &exact).await?;
    let [call] = calls.as_slice() else {
        return Err(format!("{} SCRIPT_CALL records", calls.len()).into());
    };
    assert_eq!(call["rejection"], Value::Null, "{call}");
    assert_eq!(call["bytes"], MIB, "{call}");
    let over = submit(&h, json!({ "source": SRC, "limits": limits })).await?;
    h.queued(&over, 30_000).await.ok_or("never queued")?;
    assert_eq!(
        outline(runner.results().get(2..).ok_or("no third answer")?),
        ["script_limit"]
    );
    let calls = script_calls(&h, &over).await?;
    let [call] = calls.as_slice() else {
        return Err(format!("{} SCRIPT_CALL records", calls.len()).into());
    };
    assert_eq!(call["rejection"], "max_fetch_mb", "{call}");
    assert_eq!(call["cap_or_budget"], "fetch_cap_50mib", "{call}");
    assert_eq!(call["bytes"], MIB + 1, "{call}");
    Ok(())
}

/// T19d review I-1: a rename seen on a call's first answer (§7.1) re-fetches it once. The
/// first answer's bytes were received (they are in its `identity_check_retried` record), so
/// they count against `max_fetch_mb`, and the re-fetch is cut at what is left after them
/// (`script_limit`), not at the budget the first attempt had: with `max_call_result_mb` equal to
/// `max_fetch_mb`, that stale budget would be a cut at the result cap, `result_too_large`. The
/// run's next call is refused before it is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rename_refetch_counts_the_first_answer_and_is_cut_at_the_rest() -> TestResult {
    let second = host_call(2, "jira.issue.get", json!({ "key": "ABC-2" }));
    let (h, runner) = harness(vec![ScriptPlan::new(
        vec![issue_call(1), second],
        result_end(json!(1)),
    )])
    .await?;
    let first = issue_of_len("ABC-1", 600 * 1024)?;
    mount_renamed(&h, first, issue_of_len("ABC-1", BIG_BODY)?).await?;
    let id = submit(
        &h,
        json!({ "source": SRC, "limits": { "max_fetch_mb": 1, "max_call_result_mb": 1 } }),
    )
    .await?;
    h.queued(&id, 30_000).await.ok_or("never queued")?;
    assert_eq!(renames(&h).await?, 1, "the first answer was not a rename");
    assert_eq!(outline(&runner.results()), ["script_limit", "script_limit"]);
    assert_eq!(sent_to(&h, "ABC-1").await?, 2);
    assert_eq!(sent_to(&h, "ABC-2").await?, 0, "the refused call was sent");
    let calls = script_calls(&h, &id).await?;
    let [retried, refetched] = calls.as_slice() else {
        return Err(format!("{} SCRIPT_CALL records", calls.len()).into());
    };
    assert_eq!(retried["rejection"], "identity_check_retried", "{retried}");
    assert_eq!(retried["bytes"], 600 * 1024, "{retried}");
    let left = MIB - 600 * 1024;
    assert_cut(refetched, "max_fetch_mb", "fetch_cap_50mib", left)?;
    Ok(())
}

/// I-1 at the edge: a first answer of exactly the run's fetch budget leaves nothing. The
/// re-fetch is still sent (the call was dispatched, §9.5) and cut at its first bytes
/// (`script_limit`, a committed record), not read under the budget the first attempt had.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rename_refetch_with_no_budget_left_is_sent_and_cut() -> TestResult {
    let (h, runner) = harness(vec![ScriptPlan::new(
        vec![issue_call(1)],
        result_end(json!(1)),
    )])
    .await?;
    let budget = usize::try_from(MIB)?;
    let first = issue_of_len("ABC-1", budget)?;
    mount_renamed(&h, first, issue_of_len("ABC-1", BIG_BODY)?).await?;
    let id = submit(
        &h,
        json!({ "source": SRC, "limits": { "max_fetch_mb": 1, "max_call_result_mb": 2 } }),
    )
    .await?;
    h.queued(&id, 30_000).await.ok_or("never queued")?;
    assert_eq!(renames(&h).await?, 1, "the first answer was not a rename");
    assert_eq!(outline(&runner.results()), ["script_limit"]);
    assert_eq!(sent_to(&h, "ABC-1").await?, 2, "the re-fetch was not sent");
    let calls = script_calls(&h, &id).await?;
    let [retried, refetched] = calls.as_slice() else {
        return Err(format!("{} SCRIPT_CALL records", calls.len()).into());
    };
    assert_eq!(retried["rejection"], "identity_check_retried", "{retried}");
    assert_eq!(retried["bytes"], MIB, "{retried}");
    assert_cut(refetched, "max_fetch_mb", "fetch_cap_50mib", 0)?;
    Ok(())
}

/// The mock renamed the user (same key, §7.1): the first `GET` of `ABC-1` answers `first`, every
/// later one `then`, and every answer, `/myself` too, names the new user.
async fn mount_renamed(h: &Harness, first: String, then: String) -> TestResult {
    let mock = requests_of(h)?;
    let answer = |body: String| {
        ResponseTemplate::new(200)
            .insert_header("X-AUSERNAME", "jdoe2")
            .set_body_raw(body, "application/json")
    };
    let get = || Mock::given(method("GET")).and(path(mock.path("/rest/api/2/issue/ABC-1")));
    get()
        .respond_with(answer(first))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(mock.server())
        .await;
    get()
        .respond_with(answer(then))
        .with_priority(2)
        .mount(mock.server())
        .await;
    mock.jira_myself("jdoe2", TEST_USER_KEY, XAuser::Same).await;
    Ok(())
}

/// The `user_renamed` records of the harness's instances.
async fn renames(h: &Harness) -> Result<usize, TestError> {
    Ok(h.events_of(EventType::INSTANCE_STATE_CHANGED)
        .await?
        .into_iter()
        .filter(|c| c["state"] == "user_renamed")
        .count())
}

/// T19d review M-1: a script's `jira.issue.get {comments: true}` under its budgets answers the
/// issue with the comment pages merged; its record counts the issue and every page.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plain_call_with_comments_merges_the_pages() -> TestResult {
    let call = host_call(
        1,
        "jira.issue.get",
        json!({ "key": "ABC-1", "comments": true }),
    );
    let (h, runner) = harness(vec![ScriptPlan::new(vec![call], result_end(json!(1)))]).await?;
    let pages = [
        comment_page(0, 50, 70, 50, false),
        comment_page(50, 50, 70, 20, false),
    ];
    mount_comments(requests_of(&h)?, "ABC-1", &pages).await;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 30_000).await.ok_or("never queued")?;
    let results = runner.results();
    let [HostCallResult::Ok(issue)] = results.as_slice() else {
        return Err(format!("unexpected answers: {:?}", outline(&results)).into());
    };
    let comments = issue["fields"]["comment"]["comments"]
        .as_array()
        .ok_or("no merged comments")?;
    assert_eq!(comments.len(), 70);
    assert_eq!(comments[69]["id"], "30069");
    assert_eq!(issue["key"], "ABC-1");
    let asked = gets_on(requests_of(&h)?, &comments_path("ABC-1")).await;
    assert_eq!(asked.len(), 2);
    let calls = script_calls(&h, &id).await?;
    let [call] = calls.as_slice() else {
        return Err(format!("{} SCRIPT_CALL records", calls.len()).into());
    };
    assert_eq!(call["rejection"], Value::Null, "{call}");
    let want =
        fixtures::JIRA_ISSUE.len() + pages.iter().map(|p| p.to_string().len()).sum::<usize>();
    assert_eq!(call["bytes"], want, "{call}");
    Ok(())
}

/// T19d review M-1: a script composite's comment pages are read under the run's fetch budget
/// minus the issue's bytes: a 600 KiB issue and a 600 KiB page with `max_fetch_mb: 1` cut the
/// page (`script_limit`); under the whole budget the page would be read and the call answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plain_call_with_comments_reads_the_pages_under_the_rest_of_the_budget() -> TestResult {
    let call = host_call(
        1,
        "jira.issue.get",
        json!({ "key": "ABC-1", "comments": true }),
    );
    let (h, runner) = harness(vec![ScriptPlan::new(vec![call], result_end(json!(1)))]).await?;
    mount_big_issue(&h, "ABC-1", 600 * 1024).await?;
    let page = json!({
        "startAt": 0, "maxResults": 50, "total": 1,
        "comments": [comment(30_000, &"c".repeat(600 * 1024))]
    });
    mount_comments(requests_of(&h)?, "ABC-1", &[page]).await;
    let id = submit(
        &h,
        json!({ "source": SRC, "limits": { "max_fetch_mb": 1 } }),
    )
    .await?;
    h.queued(&id, 30_000).await.ok_or("never queued")?;
    assert_eq!(outline(&runner.results()), ["script_limit"]);
    let calls = script_calls(&h, &id).await?;
    let [call] = calls.as_slice() else {
        return Err(format!("{} SCRIPT_CALL records", calls.len()).into());
    };
    assert_cut(call, "max_fetch_mb", "fetch_cap_50mib", MIB)?;
    Ok(())
}

/// T19d review M-1: a cancel while a script's composite read waits for its comment page records
/// the call `cancelled_in_flight` with the issue it already received (kept in the call's
/// control), not only the bytes of the page in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_during_the_comment_pages_records_the_issue() -> TestResult {
    let call = host_call(
        1,
        "jira.issue.get",
        json!({ "key": "ABC-1", "comments": true }),
    );
    let (h, _runner) = harness(vec![ScriptPlan::new(vec![call], result_end(json!(1)))]).await?;
    let mock = requests_of(&h)?;
    let page = comment_page(0, 50, 70, 50, false);
    mount_comment_page_delayed(mock, "ABC-1", &page, Duration::from_secs(120)).await;
    let id = submit(&h, json!({ "source": SRC })).await?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while gets_on(mock, &comments_path("ABC-1")).await.is_empty() {
        if Instant::now() > deadline {
            return Err("the comment page was never requested".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let env = h.handler().cancel(&id).await;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    let call = record(&h, &id, EventType::SCRIPT_CALL).await?;
    assert_eq!(call["outcome"], "cancelled_in_flight", "{call}");
    assert_eq!(call["reason"], "by_client", "{call}");
    assert!(
        call.to_string().contains("Login page times out"),
        "the issue received is recorded: {call}"
    );
    let bytes = call["bytes"].as_u64().ok_or("no bytes")?;
    assert!(bytes >= fixtures::JIRA_ISSUE.len() as u64, "{bytes}");
    Ok(())
}

/// M3 final review M-1: a worker is killed after the request's state lock is dropped. The
/// `kill` of the fake handle takes the lock on another thread and must get it, on each path
/// that kills a live run: the end of its request by an audit failure, a client cancel and a
/// user kill.
#[derive(Clone, Copy)]
enum KillPath {
    AuditFailure,
    ClientCancel,
    UserKill,
}

async fn kill_does_not_hold_the_state_lock(path: KillPath) -> TestResult {
    let faults = FaultPlan::new();
    let start = pause();
    let mut plan = ScriptPlan::new(vec![issue_call(1)], result_end(json!(1))).holding(600_000);
    if matches!(path, KillPath::AuditFailure) {
        faults.fail_nth(EventType::SCRIPT_CALL_SENT, 1);
        plan = plan.with_start_pause(start.clone());
    }
    let runner = WrappedRunner::new(vec![plan], u32::MAX);
    let h = Harness::builder()
        .jira("jira-main")
        .scripts(runner.clone())
        .faults(faults)
        .start()
        .await?;
    requests_of(&h)?
        .json(
            "/rest/api/2/issue/ABC-1",
            200,
            atlas_duck_atlassian::testing::fixtures::JIRA_ISSUE,
        )
        .await;
    let id = submit(&h, json!({ "source": SRC })).await?;
    if matches!(path, KillPath::AuditFailure) {
        start.reached.notified().await;
    } else {
        wait_for("the run", || runner.inner.starts() == 1).await?;
    }
    let entry = h.engine().entry(&id).ok_or("no entry")?;
    let (got, missed) = (Arc::new(AtomicU32::new(0)), Arc::new(AtomicU32::new(0)));
    runner.probe_kill({
        let (got, missed) = (got.clone(), missed.clone());
        Box::new(move || {
            let (tx, rx) = std::sync::mpsc::channel();
            let probed = entry.clone();
            std::thread::spawn(move || {
                let _lock = probed.state();
                let _ = tx.send(());
            });
            let counter = if rx.recv_timeout(Duration::from_secs(10)).is_ok() {
                &got
            } else {
                &missed
            };
            counter.fetch_add(1, Ordering::SeqCst);
        })
    });
    match path {
        KillPath::AuditFailure => {
            start.release.notify_one();
            let env = h.await_(&id, 30_000).await;
            assert_eq!(code(&env), "audit_failure", "{}", env.to_json_line());
        }
        KillPath::ClientCancel => {
            let env = h.handler().cancel(&id).await;
            assert_cancelled(&env);
        }
        KillPath::UserKill => {
            assert_eq!(h.engine().kill_script(&id), KillAnswer::Killed);
        }
    }
    wait_for("the kill", || {
        got.load(Ordering::SeqCst) + missed.load(Ordering::SeqCst) >= 1
    })
    .await?;
    assert_eq!(
        missed.load(Ordering::SeqCst),
        0,
        "kill ran under the state lock"
    );
    assert!(got.load(Ordering::SeqCst) >= 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m1_kill_not_under_state_lock() -> TestResult {
    kill_does_not_hold_the_state_lock(KillPath::AuditFailure).await?;
    kill_does_not_hold_the_state_lock(KillPath::ClientCancel).await?;
    kill_does_not_hold_the_state_lock(KillPath::UserKill).await
}

// ---- T19a (added scope): the Caution count everywhere the preview's Cautions are read ------------

/// The number of Caution-level warnings of `p`: what the queue's `caution_count` stands for.
fn caution_warnings(p: &Preview) -> u32 {
    let n = p
        .warnings
        .iter()
        .filter(|w| w.level == atlas_duck_preview::warning::Level::Caution)
        .count();
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// A result item's logs and stderr are in its record, not its candidate: a bidi control in them
/// raises the Caution in the opened preview, and so in the queue's `caution_count` and in the
/// batch dialog's line of the item (the same preview, one count).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn result_output_bidi_raises_the_queue_count_and_the_batch_line() -> TestResult {
    use atlas_duck_preview::warning::bidi_controls;
    let end = RunEnd::Result {
        value: json!(1),
        logs: vec!["log \u{202E}".to_owned()],
        stderr: String::new(),
    };
    let runner = FakeScriptRunner::new(vec![ScriptPlan::new(Vec::new(), end)]);
    let h = Harness::builder()
        .jira("jira-main")
        .scripts(runner)
        .confirm(vec![Confirm::Ok])
        .start()
        .await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    let item = h.queued(&id, 20_000).await.ok_or("never queued")?;
    let preview = script_preview(&h, &id)?;
    assert!(
        preview
            .warnings
            .iter()
            .any(|w| w.id == WarningId::BidiControls),
        "{:?}",
        preview.warnings
    );
    assert!(caution_warnings(&preview) >= 1);
    assert_eq!(item.caution_count, caution_warnings(&preview));
    let rev = h.approver().rev(&id).map_err(de)?;
    h.decisions()
        .decide_batch(vec![BatchItem {
            request_id: id.clone(),
            candidate_rev: rev,
        }])
        .map_err(de)?;
    let texts = h.confirmer().texts();
    assert_eq!(texts.len(), 1);
    assert!(texts[0].contains(&bidi_controls(1)), "{}", texts[0]);
    Ok(())
}

/// The same after a redaction: the new revision's `caution_count` still counts the result's
/// logs, which a redaction of the candidate never touches.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn result_output_bidi_stays_in_the_count_after_a_redaction() -> TestResult {
    let end = RunEnd::Result {
        value: json!({ "keep": 1, "secret": "x" }),
        logs: vec!["log \u{202E}".to_owned()],
        stderr: String::new(),
    };
    let (h, _runner) = harness(vec![ScriptPlan::new(Vec::new(), end)]).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    h.approver().open(&id).map_err(de)?;
    h.approver()
        .redact(
            &id,
            vec![atlas_duck_core::RedactionOp::DropField {
                path: "result.secret".to_owned(),
                scope: atlas_duck_core::DropScope::PerItem,
            }],
        )
        .map_err(de)?;
    let item = h.approver().item(&id).ok_or("not in the queue")?;
    let p = script_preview(&h, &id)?;
    assert!(
        p.warnings.iter().any(|w| w.id == WarningId::BidiControls),
        "{:?}",
        p.warnings
    );
    assert!(caution_warnings(&p) >= 1);
    assert_eq!(item.caution_count, caution_warnings(&p));
    Ok(())
}

/// A call the end of the run cancelled in flight is a provenance row of the preview, and its
/// text counts for the Cautions (§6.4) in the queue's `caution_count` as it does in the opened
/// preview.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_call_row_invisible_text_raises_the_queue_count() -> TestResult {
    let search = host_call(
        1,
        "jira.search",
        json!({ "jql": "summary ~ \"x\u{00AD}y\"", "max": 1 }),
    );
    let (h, id, _server) = queued_with_the_call_in_flight(
        search,
        Some(RunEnd::HostLimit {
            name: "timeout_s".to_owned(),
        }),
        false,
    )
    .await?;
    let item = h.queued(&id, 20_000).await.ok_or("never queued")?;
    let p = script_preview(&h, &id)?;
    let b = script_body(&p)?;
    assert_eq!(b.provenance.len(), 1, "{:?}", b.provenance);
    assert_eq!(b.provenance[0].outcome, "cancelled_in_flight");
    assert!(
        b.provenance[0].target_display.contains('\u{00AD}'),
        "{:?}",
        b.provenance
    );
    assert!(
        p.warnings.iter().any(|w| w.id == WarningId::OtherInvisible),
        "{:?}",
        p.warnings
    );
    assert!(caution_warnings(&p) >= 1);
    assert_eq!(item.caution_count, caution_warnings(&p));
    Ok(())
}

// ---- Task 19b: availability on the script-call path, dry runs, redaction ------------------------------

/// The rejection classes the script saw, in call order.
fn rejected_classes(runner: &FakeScriptRunner) -> Vec<String> {
    runner
        .results()
        .iter()
        .map(|r| match r {
            HostCallResult::Rejected { class, .. } => class.clone(),
            HostCallResult::Ok(_) => "ok".to_owned(),
        })
        .collect()
}

/// The `rejection` of every `SCRIPT_CALL` record of `id`, in order.
async fn call_rejections(h: &Harness, id: &str) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(t, _)| *t == EventType::SCRIPT_CALL)
        .map(|(_, p)| p["rejection"].clone())
        .collect())
}

fn instance_state(h: &Harness) -> &'static str {
    h.instances().list().first().map_or("?", |i| i.state)
}

/// I-23 on the script-call path (§7.2, RF-2): an answer decided from status and headers alone (a
/// 3xx, an HTML 200, a non-JSON 401) rejects the call inside the script as
/// `upstream_unavailable`. Nothing about the instance or its token changes, the answer's body is
/// in the `SCRIPT_CALL` record only, and the run still ends in a release item.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i23_script_call_3xx_html_nonjson401_upstream_unavailable_token_unchanged() -> TestResult {
    let calls: Vec<HostCall> = ["R-1", "H-1", "U-1"]
        .iter()
        .zip(1..)
        .map(|(key, id)| host_call(id, "jira.issue.get", json!({ "key": key })))
        .collect();
    let (h, runner) = harness(vec![ScriptPlan::new(calls, result_end(json!(1)))]).await?;
    let mock = requests_of(&h)?;
    mock.redirect("/rest/api/2/issue/R-1", "https://sso.corp.example/login")
        .await;
    mock.html("/rest/api/2/issue/H-1", 200).await;
    mock.html("/rest/api/2/issue/U-1", 401).await;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    assert_eq!(rejected_classes(&runner), ["upstream_unavailable"; 3]);
    // The record names why, per call; the page is audit-only.
    assert_eq!(
        call_rejections(&h, &id).await?,
        [
            json!("redirect_3xx"),
            json!("non_json_2xx"),
            json!("non_json_401")
        ]
    );
    for r in runner.results() {
        assert!(
            !format!("{r:?}").contains("Please log in"),
            "the page reached the script: {r:?}"
        );
    }
    let page = h
        .events(&id)
        .await?
        .into_iter()
        .filter(|(t, _)| *t == EventType::SCRIPT_CALL)
        .any(|(_, p)| p.to_string().contains("Please log in"));
    assert!(page, "the HTML page is in a SCRIPT_CALL record");
    // Not a token failure (§7.2): the instance is `ok`, the PAT is stored, no re-check ran.
    assert_eq!(instance_state(&h), "ok");
    let inst = h.instance("jira-main").ok_or("no instance")?;
    assert!(h.credentials().load(&inst.id)?.is_some());
    let rechecks = h
        .events_of(EventType::SYSTEM_FETCH)
        .await?
        .into_iter()
        .filter(|p| p["purpose"] == "token_recheck")
        .count();
    assert_eq!(rechecks, 0);
    // The run is release-gated whatever the script did with the rejections.
    let item = h.approver().item(&id).ok_or("not in the queue")?;
    assert_eq!(item.class, "script");
    assert_eq!(h.status(&id).await.status, Status::Pending);
    Ok(())
}

/// A Jira JSON 401 for `ABC-1`: it carries `X-AUSERNAME: anonymous` by nature.
async fn mount_json_401(h: &Harness) -> Result<&atlas_duck_atlassian::testing::MockDc, TestError> {
    let mock = requests_of(h)?;
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/2/issue/ABC-1")))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header("X-AUSERNAME", "anonymous")
                .set_body_raw(
                    r#"{"errorMessages":["You are not authenticated"],"errors":{}}"#,
                    "application/json",
                ),
        )
        .with_priority(1)
        .mount(mock.server())
        .await;
    Ok(mock)
}

/// I-23, JSON 401 (§7.1): the call is `needs_token` for the script only when the token re-check
/// fails; when it passes, the 401 is an ordinary upstream error and the token state is untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i23_script_call_json401_needs_token_only_after_recheck() -> TestResult {
    let (h, runner) = harness(vec![
        ScriptPlan::new(vec![issue_call(1)], result_end(json!(1))),
        ScriptPlan::new(vec![issue_call(1)], result_end(json!(1))),
    ])
    .await?;
    // The re-check passes: an ordinary 4xx, the token is fine.
    let mock = mount_json_401(&h).await?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    let first = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&first, 20_000).await.ok_or("never queued")?;
    assert_eq!(rejected_classes(&runner), ["upstream_http"]);
    assert_eq!(call_rejections(&h, &first).await?, [json!("upstream_http")]);
    assert_eq!(instance_state(&h), "ok");
    let sid = h.instance("jira-main").ok_or("instance")?.id.clone();
    assert!(h.credentials().load(&sid)?.is_some());
    // The re-check fails too: `needs_token`, the PAT stays.
    mock.server().reset().await;
    let mock = mount_json_401(&h).await?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Anonymous)
        .await;
    let second = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&second, 20_000).await.ok_or("never queued")?;
    assert_eq!(rejected_classes(&runner), ["upstream_http", "needs_token"]);
    assert_eq!(call_rejections(&h, &second).await?, [json!("needs_token")]);
    assert_eq!(instance_state(&h), "needs_token");
    assert!(h.credentials().load(&sid)?.is_some());
    Ok(())
}

/// U-03 (dry-run clause, §13): a script dry run makes no HTTP call at all (no read, no identity
/// check, no re-check), commits no `SCRIPT_STARTED`, `SCRIPT_CALL_SENT` or `SCRIPT_CALL`, and
/// leaves the instance's state alone. Every mode, a paged `atlas.all` call, a failing op and a
/// script error included.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u03_dry_run_no_http_no_script_call() -> TestResult {
    let mut all = host_call(2, "jira.search", json!({ "jql": "project = ABC" }));
    all.all = true;
    let calls = || {
        vec![
            issue_call(1),
            all.clone(),
            host_call(3, "jira.issue.get", json!({ "key": "NOPE-9" })),
            host_call(
                4,
                "jira.comment.add",
                json!({ "key": "ABC-1", "body": "x" }),
            ),
        ]
    };
    let (h, runner) = harness(vec![
        ScriptPlan::new(calls(), result_end(json!({ "ok": true }))),
        ScriptPlan::new(calls(), result_end(json!({ "ok": true }))),
        ScriptPlan::new(calls(), error_end()),
    ])
    .await?;
    assert!(h.field_cache_filled().await);
    let mock = requests_of(&h)?;
    let before = mock.received().await.len();
    // Positive control: `received` falls back to an empty list when recording fails, which would
    // make the "no request" check below vacuous. The startup requests prove the counter counts.
    assert!(before > 0, "the request counter saw no startup request");
    let fetches = h.events_of(EventType::SYSTEM_FETCH).await?.len();
    let mut ids = Vec::new();
    for dry in [json!(true), json!("sparse"), json!(true)] {
        let id = submit(&h, json!({ "source": SRC, "dry_run": dry })).await?;
        let env = h.await_(&id, 10_000).await;
        assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
        assert_eq!(env.meta.clone().ok_or("no meta")?["dry_run"], true);
        ids.push(id);
    }
    // Four answered calls per run, none of them from the instance.
    assert_eq!(runner.results().len(), 12);
    assert_eq!(
        mock.received().await.len(),
        before,
        "a dry run sent a request"
    );
    assert_eq!(h.events_of(EventType::SYSTEM_FETCH).await?.len(), fetches);
    for t in [
        EventType::SCRIPT_STARTED,
        EventType::SCRIPT_CALL_SENT,
        EventType::SCRIPT_CALL,
    ] {
        assert!(h.events_of(t).await?.is_empty(), "{t:?} was committed");
    }
    for id in &ids {
        assert_eq!(
            h.event_types(id).await?,
            [
                EventType::REQUEST_RECEIVED,
                EventType::SCRIPT_DRY_RUN,
                EventType::DELIVERED,
            ]
        );
    }
    assert_eq!(runner.specs().iter().filter(|s| s.dry_run).count(), 3);
    assert_eq!(instance_state(&h), "ok");
    Ok(())
}

/// U-29 through the engine (§5.3): a script result released with drops keeps the `null`s the
/// script itself returned, and a dropped field is absent, not `null`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u29_script_release_redacted_keeps_upstream_null() -> TestResult {
    let value = json!({
        "assignee": null,
        "labels": [null, "x"],
        "nested": { "due": null, "secret": "hunter2" },
        "secret": "hunter2"
    });
    let (h, _runner) = harness(vec![ScriptPlan::new(Vec::new(), result_end(value))]).await?;
    let id = submit(&h, json!({ "source": SRC })).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    let drop = |p: &str| atlas_duck_core::RedactionOp::DropField {
        path: p.to_owned(),
        scope: atlas_duck_core::DropScope::PerItem,
    };
    h.approver()
        .release_redacted(
            &id,
            vec![drop("result.secret"), drop("result.nested.secret")],
        )
        .map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    assert_eq!(
        env.data.clone().ok_or("no data")?["result"],
        json!({
            "assignee": null,
            "labels": [null, "x"],
            "nested": { "due": null }
        })
    );
    Ok(())
}
