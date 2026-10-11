#![cfg(feature = "testing")]
//! The shutdown path (§2.5 steps 1-5, Task 28): I-40 (new submits refused, everything not yet
//! executing cancelled with the app reason, executing writes awaited, `APP_STOP` last), I-11
//! (a read stopped in `Fetching` commits what arrived first) and the quiet next start.

mod common;

use std::time::Duration;

use atlas_duck_atlassian::Timeouts;
use atlas_duck_atlassian::testing::{
    MockDc, RawHttpServer, RawStep, TEST_USER, TEST_USER_KEY, XAuser, fixtures,
};
use atlas_duck_audit::EventType;
use atlas_duck_core::testing::{FakeScriptRunner, FaultPlan, Harness, InstanceAt, ScriptPlan};
use atlas_duck_core::{Pause, RunEnd, ShutdownReason, ShutdownReport, TestHooks};
use atlas_duck_ipc::envelope::Envelope;
use atlas_duck_ipc::envelope::Status;
use atlas_duck_registry::Product;
use common::{TestError, TestResult, code, de, detail, exit, request_id};
use serde_json::{Value, json};
use wiremock::Mock;
use wiremock::matchers::{method, path};

const ISSUE: &str = "jira.issue.get";
const SEARCH: &str = "jira.search";
const COMMENT: &str = "jira.comment.add";

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
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

async fn queued(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    Ok(id)
}

async fn submit_pending(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    request_id(&env)
}

async fn types(h: &Harness, id: &str) -> Result<Vec<EventType>, TestError> {
    h.event_types(id).await
}

async fn record(h: &Harness, id: &str, t: EventType) -> Result<Value, TestError> {
    h.events(id)
        .await?
        .into_iter()
        .find(|(e, _)| *e == t)
        .map(|(_, p)| p)
        .ok_or_else(|| format!("no {t:?} record").into())
}

/// `cancelled`, exit 7, `retryable: true`, with the app's reason.
async fn assert_cancelled(h: &Harness, id: &str, reason: &str) -> TestResult {
    let env = h.status(id).await;
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    assert_eq!(exit(&env), 7);
    assert_eq!(code(&env), "cancelled");
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    assert_eq!(record(h, id, EventType::CANCELLED).await?["reason"], reason);
    Ok(())
}

/// The newest record of the log.
fn last_event(h: &Harness) -> Result<EventType, TestError> {
    h.store()
        .recent_headers(Duration::from_secs(3600))?
        .last()
        .map(|e| e.event_type)
        .ok_or_else(|| "empty log".into())
}

async fn app_stop_reason(h: &Harness) -> Result<Value, TestError> {
    let stops = h.events_of(EventType::APP_STOP).await?;
    assert_eq!(stops.len(), 1, "{stops:?}");
    Ok(stops
        .first()
        .map(|p| p["reason"].clone())
        .unwrap_or(Value::Null))
}

/// A Jira harness with a script runner, one write already `executing` (the POST of its comment
/// takes `post_ms`), one read in the queue, one read stalled in `Fetching`, one opened write in
/// `AwaitingApproval` and one running script.
struct Busy {
    h: Harness,
    executing: String,
    queued_read: String,
    fetching_read: String,
    open_write: String,
    script: String,
}

async fn busy(post_ms: u64, hooks: TestHooks) -> Result<Busy, TestError> {
    let runner = FakeScriptRunner::new(vec![
        ScriptPlan::new(Vec::new(), RunEnd::Crashed).holding(60_000),
    ]);
    let h = Harness::builder()
        .jira("jira-main")
        .scripts(runner.clone())
        .hooks(hooks)
        .start()
        .await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    // ABC-9 never answers in time: its read stays in `Fetching`.
    Mock::given(path(mock.path("/rest/api/2/issue/ABC-9")))
        .respond_with(
            mock.response(200)
                .set_body_raw(fixtures::JIRA_ISSUE, "application/json")
                .set_delay(Duration::from_secs(60)),
        )
        .mount(mock.server())
        .await;
    for key in ["ABC-1", "ABC-2"] {
        Mock::given(method("POST"))
            .and(path(mock.path(&format!("/rest/api/2/issue/{key}/comment"))))
            .respond_with(
                mock.response(201)
                    .set_body_raw(fixtures::JIRA_COMMENT, "application/json")
                    .set_delay(Duration::from_millis(post_ms)),
            )
            .mount(mock.server())
            .await;
    }
    let comment = |key: &str| json!({ "key": key, "body": "Reproduced.", "body_format": "wiki" });
    let queued_read = queued(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
    let open_write = queued(&h, COMMENT, comment("ABC-2")).await?;
    h.approver().open(&open_write).map_err(de)?;
    let executing = queued(&h, COMMENT, comment("ABC-1")).await?;
    h.approver().approve(&executing).map_err(de)?;
    for _ in 0..1000 {
        let posts = jira(&h)?
            .received()
            .await
            .iter()
            .filter(|r| r.method.as_str() == "POST")
            .count();
        if posts > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let fetching_read = submit_pending(&h, ISSUE, json!({ "key": "ABC-9" })).await?;
    let script = {
        let env = h.submit_script(json!({ "source": "return 1;" })).await;
        assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
        request_id(&env)?
    };
    wait_for("the script to start", || runner.starts() == 1).await?;
    // The stalled read has sent its request.
    for _ in 0..1000 {
        let gets = jira(&h)?
            .received()
            .await
            .iter()
            .filter(|r| r.url.path().ends_with("/ABC-9"))
            .count();
        if gets > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        h.status(&executing).await.status,
        Status::Executing,
        "the write must be executing"
    );
    Ok(Busy {
        h,
        executing,
        queued_read,
        fetching_read,
        open_write,
        script,
    })
}

/// A submit that arrives while the shutdown runs: refused, retryable.
async fn refused_submit(h: &Harness) -> Result<atlas_duck_ipc::envelope::Envelope, TestError> {
    wait_for("the shutdown to start", || h.engine().is_shutting_down()).await?;
    Ok(h.submit(ISSUE, json!({ "key": "ABC-1" })).await)
}

async fn shutdown_with_refused_submit(
    b: &Busy,
    reason: ShutdownReason,
) -> Result<ShutdownReport, TestError> {
    let (report, refused) = tokio::join!(b.h.core().shutdown(reason), refused_submit(&b.h));
    let refused = refused?;
    assert_eq!(refused.status, Status::Failed, "{}", refused.to_json_line());
    assert_eq!(exit(&refused), 5);
    assert_eq!(code(&refused), "unreachable");
    assert_eq!(detail(&refused, "reason"), json!("app_shutting_down"));
    assert_eq!(refused.error.as_ref().map(|e| e.retryable), Some(true));
    Ok(report)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i40_quit_refuses_cancels_finishes_write() -> TestResult {
    let b = busy(500, TestHooks::none()).await?;
    let h = &b.h;
    let report = shutdown_with_refused_submit(&b, ShutdownReason::Quit).await?;
    assert_eq!(
        report,
        ShutdownReport {
            cancelled: 4,
            writes_waited: 1,
            app_stop_logged: true
        }
    );
    // The read in the queue, the read in flight, the opened write and the script: cancelled.
    for id in [&b.queued_read, &b.fetching_read, &b.open_write, &b.script] {
        assert_cancelled(h, id, "app_quit").await?;
    }
    // The stalled read committed what it had before its `CANCELLED` (I-11).
    let t = types(h, &b.fetching_read).await?;
    assert_eq!(
        t,
        [
            EventType::REQUEST_RECEIVED,
            EventType::READ_FETCHED,
            EventType::CANCELLED
        ]
    );
    let fetched = record(h, &b.fetching_read, EventType::READ_FETCHED).await?;
    assert_eq!(fetched["outcome"], "cancelled_in_flight");
    assert_eq!(fetched["reason"], "app_quit");
    // The script: a non-terminal `SCRIPT_FAILED` first.
    assert_eq!(
        types(h, &b.script).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::SCRIPT_STARTED,
            EventType::SCRIPT_FAILED,
            EventType::CANCELLED
        ]
    );
    let failed = record(h, &b.script, EventType::SCRIPT_FAILED).await?;
    assert_eq!(
        (failed["reason"].clone(), failed["direct"].clone()),
        (json!("app_quit"), json!(false))
    );
    // The executing write ran to its end and logged it.
    let env = h.status(&b.executing).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let t = types(h, &b.executing).await?;
    assert!(t.contains(&EventType::WRITE_EXECUTED), "{t:?}");
    assert!(!t.contains(&EventType::CANCELLED));
    // Nothing follows `APP_STOP`.
    assert_eq!(last_event(h)?, EventType::APP_STOP);
    assert_eq!(app_stop_reason(h).await?, "quit");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i40_installer_reason() -> TestResult {
    let b = busy(100, TestHooks::none()).await?;
    let report = shutdown_with_refused_submit(&b, ShutdownReason::Installer).await?;
    assert_eq!(report.cancelled, 4);
    // The installer path cancels with the app's own reason.
    for id in [&b.queued_read, &b.fetching_read, &b.open_write, &b.script] {
        assert_cancelled(&b.h, id, "app_quit").await?;
    }
    assert_eq!(last_event(&b.h)?, EventType::APP_STOP);
    assert_eq!(app_stop_reason(&b.h).await?, "installer");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i40_os_shutdown_reason() -> TestResult {
    let b = busy(100, TestHooks::none()).await?;
    let report = shutdown_with_refused_submit(&b, ShutdownReason::OsShutdown).await?;
    assert_eq!(report.cancelled, 4);
    for id in [&b.queued_read, &b.fetching_read, &b.open_write, &b.script] {
        assert_cancelled(&b.h, id, "os_shutdown").await?;
    }
    let failed = record(&b.h, &b.script, EventType::SCRIPT_FAILED).await?;
    assert_eq!(failed["reason"], "os_shutdown");
    let fetched = record(&b.h, &b.fetching_read, EventType::READ_FETCHED).await?;
    assert_eq!(fetched["reason"], "os_shutdown");
    assert_eq!(last_event(&b.h)?, EventType::APP_STOP);
    assert_eq!(app_stop_reason(&b.h).await?, "os_shutdown");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i40_nothing_left_to_reconcile() -> TestResult {
    let mut b = busy(100, TestHooks::none()).await?;
    b.h.core().shutdown(ShutdownReason::Quit).await;
    // The store's own predicate finds nothing open.
    let report = b.h.store().reconcile_after_crash()?;
    assert!(
        report.outcome_unknown.is_empty() && report.abandoned.is_empty(),
        "{report:?}"
    );
    // And so does the next start.
    b.h.restart().await?;
    assert!(b.h.core().startup_notice().is_empty());
    assert!(b.h.events_of(EventType::ABANDONED).await?.is_empty());
    assert!(
        b.h.events_of(EventType::WRITE_OUTCOME_UNKNOWN)
            .await?
            .is_empty()
    );
    assert_eq!(b.h.events_of(EventType::APP_START).await?.len(), 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i40_a_write_over_its_budget_is_left_to_the_next_start() -> TestResult {
    // The budget is scaled down: the POST outlives it.
    let mut b = busy(
        30_000,
        TestHooks {
            shutdown_write_wait: Some(Duration::from_millis(300)),
            ..TestHooks::none()
        },
    )
    .await?;
    let report = b.h.core().shutdown(ShutdownReason::Quit).await;
    assert_eq!(report.writes_waited, 1);
    // `APP_STOP` is written anyway; the write has no outcome yet.
    assert_eq!(last_event(&b.h)?, EventType::APP_STOP);
    let t = types(&b.h, &b.executing).await?;
    assert!(
        !t.contains(&EventType::WRITE_EXECUTED) && !t.contains(&EventType::CANCELLED),
        "{t:?}"
    );
    // The next start reconciles it like a crash (§11.3).
    b.h.crash_and_restart().await?;
    let env = b.h.await_(&b.executing, 10_000).await;
    assert_eq!(env.status, Status::OutcomeUnknown, "{}", env.to_json_line());
    assert_eq!(b.h.core().startup_notice().len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_shutdown_changes_nothing() -> TestResult {
    let b = busy(100, TestHooks::none()).await?;
    let first = b.h.core().shutdown(ShutdownReason::Quit).await;
    assert_eq!(first.cancelled, 4);
    let second = b.h.core().shutdown(ShutdownReason::OsShutdown).await;
    assert_eq!(second, first);
    assert_eq!(b.h.events_of(EventType::APP_STOP).await?.len(), 1);
    assert_eq!(app_stop_reason(&b.h).await?, "quit");
    Ok(())
}

/// Review I-3: a second call while the first still waits for an executing write does not return
/// before `APP_STOP` is in the log, and gets the first call's report.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_concurrent_second_shutdown_waits_for_the_first() -> TestResult {
    let b = busy(1_500, TestHooks::none()).await?;
    let h = &b.h;
    let (first, second) = tokio::join!(h.core().shutdown(ShutdownReason::Quit), async {
        wait_for("the shutdown to start", || h.engine().is_shutting_down()).await?;
        // The first call is in its wait for the executing write.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(h.events_of(EventType::APP_STOP).await?.is_empty());
        let report = h.core().shutdown(ShutdownReason::OsShutdown).await;
        // It returned: the first call's work is complete.
        assert_eq!(last_event(h)?, EventType::APP_STOP);
        Ok::<_, TestError>(report)
    });
    assert_eq!(second?, first);
    assert!(
        first.app_stop_logged && first.writes_waited == 1,
        "{first:?}"
    );
    assert_eq!(h.events_of(EventType::APP_STOP).await?.len(), 1);
    assert_eq!(app_stop_reason(h).await?, "quit");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_app_stop_append_is_in_the_report() -> TestResult {
    let plan = FaultPlan::new();
    let h = Harness::builder()
        .jira("jira-main")
        .faults(plan.clone())
        .start()
        .await?;
    plan.fail_nth(EventType::APP_STOP, 1);
    let report = h.core().shutdown(ShutdownReason::Quit).await;
    assert!(!report.app_stop_logged, "{report:?}");
    assert!(h.events_of(EventType::APP_STOP).await?.is_empty());
    Ok(())
}

// ---- review I-1: a submit racing the shutdown ----------------------------------------------

/// The Jira read of ABC-9 never answers in time: a registered read stays in `Fetching`.
async fn stalled_jira(h: &Harness) -> TestResult {
    let mock = jira(h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    Mock::given(path(mock.path("/rest/api/2/issue/ABC-9")))
        .respond_with(
            mock.response(200)
                .set_body_raw(fixtures::JIRA_ISSUE, "application/json")
                .set_delay(Duration::from_secs(60)),
        )
        .mount(mock.server())
        .await;
    Ok(())
}

/// A submit paused after its shutdown check, before `REQUEST_RECEIVED`; the shutdown starts and
/// must wait for it. Then the request is registered, swept, and `APP_STOP` is the last record.
async fn racing_submit(
    h: &Harness,
    pause: &Pause,
    submit: impl std::future::Future<Output = Envelope>,
) -> TestResult {
    tokio::pin!(submit);
    tokio::select! {
        _ = &mut submit => return Err("the submit finished while paused".into()),
        _ = pause.reached.notified() => {}
    }
    let release = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        // The shutdown waits for the submit: it has not refused anything yet, nor stopped.
        assert!(!h.engine().is_shutting_down());
        assert!(h.events_of(EventType::APP_STOP).await?.is_empty());
        pause.release.notify_one();
        Ok::<_, TestError>(())
    };
    let (report, released, env) = tokio::join!(
        h.core().shutdown(ShutdownReason::Quit),
        release,
        &mut submit
    );
    released?;
    assert!(report.app_stop_logged, "{report:?}");
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    assert_cancelled(h, &id, "app_quit").await?;
    // Nothing after `APP_STOP`, in particular no `REQUEST_RECEIVED`.
    assert_eq!(last_event(h)?, EventType::APP_STOP);
    assert_eq!(report.cancelled, 1);
    // And now submits are refused.
    let refused = h.submit(ISSUE, json!({ "key": "ABC-1" })).await;
    assert_eq!(code(&refused), "unreachable");
    assert_eq!(detail(&refused, "reason"), json!("app_shutting_down"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i1_a_submit_racing_the_shutdown_is_swept() -> TestResult {
    let pause = Pause::new();
    let h = Harness::builder()
        .jira("jira-main")
        .hooks(TestHooks {
            pause_before_received: Some(pause.clone()),
            ..TestHooks::none()
        })
        .start()
        .await?;
    stalled_jira(&h).await?;
    racing_submit(&h, &pause, h.submit(ISSUE, json!({ "key": "ABC-9" }))).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i1_a_script_submit_racing_the_shutdown_is_swept() -> TestResult {
    let pause = Pause::new();
    let runner = FakeScriptRunner::new(vec![
        ScriptPlan::new(Vec::new(), RunEnd::Crashed).holding(60_000),
    ]);
    let h = Harness::builder()
        .jira("jira-main")
        .scripts(runner)
        .hooks(TestHooks {
            pause_before_received: Some(pause.clone()),
            ..TestHooks::none()
        })
        .start()
        .await?;
    racing_submit(
        &h,
        &pause,
        h.submit_script(json!({ "source": "return 1;" })),
    )
    .await
}

// ---- a write in `StaleCheck` (only the shutdown path can cancel it) --------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_in_stale_check_is_cancelled_by_the_shutdown() -> TestResult {
    let pause = Pause::new();
    let h = Harness::builder()
        .jira("jira-main")
        .hooks(TestHooks {
            pause_after_get: Some(pause.clone()),
            ..TestHooks::none()
        })
        .start()
        .await?;
    jira(&h)?
        .jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    let id = queued(
        &h,
        COMMENT,
        json!({ "key": "ABC-1", "body": "Reproduced.", "body_format": "wiki" }),
    )
    .await?;
    h.approver().approve(&id).map_err(de)?;
    pause.reached.notified().await;
    let release = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        pause.release.notify_one();
    };
    let (report, ()) = tokio::join!(h.core().shutdown(ShutdownReason::Quit), release);
    assert_eq!(report.cancelled, 1, "{report:?}");
    assert_cancelled(&h, &id, "app_quit").await?;
    let t = types(&h, &id).await?;
    let tail: Vec<_> = t.iter().rev().take(2).rev().copied().collect();
    assert_eq!(
        tail,
        [EventType::PREVIEW_FETCH, EventType::CANCELLED],
        "{t:?}"
    );
    let fetch = record(&h, &id, EventType::PREVIEW_FETCH).await?;
    assert_eq!(fetch["purpose"], "stale_check");
    assert_eq!(last_event(&h)?, EventType::APP_STOP);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn other_methods_keep_working_during_the_shutdown() -> TestResult {
    let b = busy(800, TestHooks::none()).await?;
    let id = b.queued_read.clone();
    let (_, seen) = tokio::join!(b.h.core().shutdown(ShutdownReason::Quit), async {
        wait_for("the shutdown to start", || b.h.engine().is_shutting_down()).await?;
        // The executing write is still awaited: `status` and `await` answer meanwhile.
        let env = b.h.status(&b.executing).await;
        assert_ne!(env.status, Status::Failed, "{}", env.to_json_line());
        let env = b.h.await_(&id, 10_000).await;
        Ok::<_, TestError>(env.status)
    });
    assert_eq!(seen?, Status::Cancelled);
    Ok(())
}

// ---- I-11: the Quit case ----------------------------------------------------------------------

fn raw_answer(body: &[u8], content_length: usize) -> Vec<u8> {
    let mut v = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\nX-AUSERNAME: {TEST_USER}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    v.extend_from_slice(body);
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i11_quit_during_page3_commits_partial() -> TestResult {
    let page = |start| fixtures::jira_search_page(start, 50, 1000, 50);
    let (p1, p2, p3) = (page(0), page(50), page(100));
    let cut = p3.as_bytes().get(..500).ok_or("cut")?;
    let stalled = vec![
        RawStep::Send(raw_answer(cut, 1_000_000)),
        RawStep::Sleep(120_000),
    ];
    let server = RawHttpServer::serve_sequence(vec![
        vec![RawStep::Send(raw_answer(p1.as_bytes(), p1.len()))],
        vec![RawStep::Send(raw_answer(p2.as_bytes(), p2.len()))],
        stalled,
    ])
    .await?;
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
        .start()
        .await?;
    let id = submit_pending(&h, SEARCH, json!({ "jql": "project = ABC", "max": 150 })).await?;
    for _ in 0..1000 {
        if server.connections() >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    for _ in 0..1000 {
        let got = h
            .engine()
            .entry(&id)
            .and_then(|e| e.fetch_control())
            .map(|c| c.take_captured().partial.len());
        if got.is_some_and(|n| n >= 400) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let report = h.core().shutdown(ShutdownReason::Quit).await;
    assert_eq!(report.cancelled, 1);
    assert_cancelled(&h, &id, "app_quit").await?;
    assert_eq!(
        types(&h, &id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::READ_FETCHED,
            EventType::CANCELLED
        ]
    );
    let f = record(&h, &id, EventType::READ_FETCHED).await?;
    assert_eq!(f["outcome"], "cancelled_in_flight");
    assert_eq!(f["reason"], "app_quit");
    assert_eq!(f["pages"], 2);
    let partial = f["partial"]["text"].as_str().ok_or("no partial text")?;
    assert!(partial.len() >= 400 && p3.starts_with(partial), "{partial}");
    assert_eq!(last_event(&h)?, EventType::APP_STOP);
    Ok(())
}
