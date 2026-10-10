#![cfg(feature = "testing")]
//! Cancel, expiry and `cancelled_in_flight` (Task 24): the state-independent client cancel
//! (I-09 core half, I-10 non-script), the in-flight records (I-11), the expiry timer and the
//! expiry re-check after a phase that cannot expire (Task 12 review I-4).

mod common;

use std::time::Duration;

use atlas_duck_atlassian::Timeouts;
use atlas_duck_atlassian::testing::{
    MockDc, RawHttpServer, RawStep, TEST_USER, TEST_USER_KEY, XAuser, fixtures,
};
use atlas_duck_audit::EventType;
use atlas_duck_core::TestHooks;
use atlas_duck_core::engine::Engine;
use atlas_duck_core::engine::cancel::CancelCause;
use atlas_duck_core::engine::queue::Limits;
use atlas_duck_core::testing::{Harness, InstanceAt};
use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_registry::Product;
use common::{TestError, TestResult, code, de, detail, exit, json, request_id};
use serde_json::{Value, json};
use wiremock::Mock;
use wiremock::matchers::{method, path, query_param};

const ISSUE: &str = "jira.issue.get";
const SEARCH: &str = "jira.search";
const COMMENT: &str = "jira.comment.add";
const TRANSITION: &str = "jira.issue.transition";

/// Compile-time check (I-09): `cancel_now` is synchronous. It compiles only because it is not
/// `async`: an `async fn` would return a future here, not an `Envelope`.
#[allow(dead_code)]
fn assert_cancel_now_is_sync(e: &Engine, id: &str) -> Envelope {
    e.cancel_now(id, CancelCause::Client)
}

fn raw_answer(body: &[u8], content_length: usize) -> Vec<u8> {
    let mut v = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\nX-AUSERNAME: {TEST_USER}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    v.extend_from_slice(body);
    v
}

/// The head of a 200 answer that promises more body than it ever sends.
fn stalled(body: &[u8]) -> Vec<RawStep> {
    vec![
        RawStep::Send(raw_answer(body, 1_000_000)),
        RawStep::Sleep(120_000),
    ]
}

/// A Jira instance at a raw server (`scripts[i]` answers connection `i`), calls that never time
/// out on their own.
async fn raw_jira(
    scripts: Vec<Vec<RawStep>>,
    limits: Option<Limits>,
    hooks: TestHooks,
) -> Result<(Harness, RawHttpServer), TestError> {
    let server = RawHttpServer::serve_sequence(scripts).await?;
    let mut b = Harness::builder()
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
        .hooks(hooks);
    if let Some(l) = limits {
        b = b.limits(l);
    }
    Ok((b.start().await?, server))
}

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

fn wiki(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("wiki").ok_or_else(|| "no confluence mock".into())
}

async fn submit_pending(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    request_id(&env)
}

async fn queued(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let id = submit_pending(h, op, params).await?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    Ok(id)
}

/// Waits until the read's fetch has received at least `bytes` of a body.
async fn wait_partial(h: &Harness, id: &str, bytes: usize) -> TestResult {
    for _ in 0..1000 {
        let got = h
            .engine()
            .entry(id)
            .and_then(|e| e.fetch_control())
            .map(|c| c.take_captured().partial.len());
        if got.is_some_and(|n| n >= bytes) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("the fetch never received its bytes".into())
}

async fn wait_connections(server: &RawHttpServer, n: usize) -> TestResult {
    for _ in 0..1000 {
        if server.connections() >= n {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("the server never got the connection".into())
}

fn same(id: &str, env: &Envelope) -> String {
    env.to_json_line().replace(id, "<id>")
}

async fn records(h: &Harness, id: &str, t: EventType) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(e, _)| *e == t)
        .map(|(_, p)| p)
        .collect())
}

fn assert_cancelled(env: &Envelope) {
    assert_eq!(env.status, Status::Cancelled, "{}", env.to_json_line());
    assert_eq!(exit(env), 7);
    assert_eq!(code(env), "cancelled");
    assert_eq!(detail(env, "reason"), json!("by_client"));
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
}

// ---- I-10 -----------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i10_cancel_identical_fetching_vs_awaiting_release() -> TestResult {
    let issue = fixtures::JIRA_ISSUE.as_bytes();
    let (h, server) = raw_jira(
        vec![
            stalled(b"{\"key\":"),
            vec![RawStep::Send(raw_answer(issue, issue.len()))],
        ],
        None,
        TestHooks::none(),
    )
    .await?;
    let a = submit_pending(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
    wait_connections(&server, 1).await?;
    wait_partial(&h, &a, 1).await?;
    let b = queued(&h, ISSUE, json!({ "key": "ABC-2" })).await?;
    let (ea, eb) = (h.handler().cancel(&a).await, h.handler().cancel(&b).await);
    assert_cancelled(&ea);
    assert_eq!(same(&a, &ea), same(&b, &eb));
    assert_eq!(h.status(&a).await.status, Status::Cancelled);
    assert_eq!(h.status(&b).await.status, Status::Cancelled);
    // The in-flight bytes of A are committed before its terminal record, B has none.
    let a_types = h.event_types(&a).await?;
    assert_eq!(
        a_types,
        [
            EventType::REQUEST_RECEIVED,
            EventType::READ_FETCHED,
            EventType::CANCELLED
        ]
    );
    assert!(!h.event_types(&b).await?.contains(&EventType::READ_RELEASED));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i11_cancel_during_page3_commits_partial() -> TestResult {
    let page = |start| fixtures::jira_search_page(start, 50, 1000, 50);
    let (p1, p2, p3) = (page(0), page(50), page(100));
    let (a, b) = (
        raw_answer(p1.as_bytes(), p1.len()),
        raw_answer(p2.as_bytes(), p2.len()),
    );
    let cut = p3.as_bytes().get(..500).ok_or("cut")?;
    let (h, server) = raw_jira(
        vec![vec![RawStep::Send(a)], vec![RawStep::Send(b)], stalled(cut)],
        None,
        TestHooks::none(),
    )
    .await?;
    let id = submit_pending(&h, SEARCH, json!({ "jql": "project = ABC", "max": 150 })).await?;
    wait_connections(&server, 3).await?;
    wait_partial(&h, &id, 400).await?;
    let env = h.handler().cancel(&id).await;
    assert_cancelled(&env);
    let types = h.event_types(&id).await?;
    assert_eq!(
        types,
        [
            EventType::REQUEST_RECEIVED,
            EventType::READ_FETCHED,
            EventType::CANCELLED
        ]
    );
    let fetched = records(&h, &id, EventType::READ_FETCHED).await?;
    let f = fetched.first().ok_or("no READ_FETCHED")?;
    assert_eq!(f["outcome"], "cancelled_in_flight");
    assert_eq!(f["reason"], "by_client");
    assert_eq!(f["pages"], 2);
    let partial = f["partial"]["text"].as_str().ok_or("no partial text")?;
    assert!(partial.len() >= 400 && p3.starts_with(partial), "{partial}");
    assert!(
        f["size"]
            .as_u64()
            .is_some_and(|s| s >= (p1.len() + p2.len() + partial.len()) as u64)
    );
    // The same envelope as a cancel in `AwaitingRelease`.
    let (h2, _s2) = raw_jira(
        vec![vec![RawStep::Send(raw_answer(p1.as_bytes(), p1.len()))]],
        None,
        TestHooks::none(),
    )
    .await?;
    let id2 = queued(&h2, SEARCH, json!({ "jql": "project = ABC", "max": 10 })).await?;
    let env2 = h2.handler().cancel(&id2).await;
    assert_eq!(same(&id, &env), same(&id2, &env2));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i11_cancel_during_enrichment_commits_partial() -> TestResult {
    let body = fixtures::JIRA_TRANSITIONS.as_bytes();
    let cut = body.get(..body.len() / 2).ok_or("cut")?;
    let (h, server) = raw_jira(vec![stalled(cut)], None, TestHooks::none()).await?;
    let id = submit_pending(
        &h,
        TRANSITION,
        json!({ "key": "ABC-1", "transition": "Done" }),
    )
    .await?;
    wait_connections(&server, 1).await?;
    wait_partial(&h, &id, cut.len()).await?;
    let env = h.handler().cancel(&id).await;
    assert_cancelled(&env);
    assert_eq!(
        h.event_types(&id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::PREVIEW_FETCH,
            EventType::CANCELLED
        ]
    );
    let fetch = records(&h, &id, EventType::PREVIEW_FETCH).await?;
    let f = fetch.first().ok_or("no PREVIEW_FETCH")?;
    // The transition op resolves the name through its transitions list (the enrichment GET).
    assert_eq!(f["purpose"], "resolve");
    assert_eq!(f["outcome"], "cancelled_in_flight");
    assert_eq!(f["reason"], "by_client");
    assert!(f["received"].to_string().contains("Start Progress"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i11_cancel_before_send_logs_nothing_extra() -> TestResult {
    let limits = Limits {
        fetching: 1,
        ..Limits::default()
    };
    let (h, server) = raw_jira(vec![stalled(b"{")], Some(limits), TestHooks::none()).await?;
    let a = submit_pending(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
    wait_connections(&server, 1).await?;
    // The only slot is held by `a`: `b` waits for it and has sent nothing.
    let b = submit_pending(&h, ISSUE, json!({ "key": "ABC-2" })).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_cancelled(&h.handler().cancel(&b).await);
    assert_eq!(
        h.event_types(&b).await?,
        [EventType::REQUEST_RECEIVED, EventType::CANCELLED]
    );
    assert_eq!(server.connections(), 1);
    assert_cancelled(&h.handler().cancel(&a).await);
    Ok(())
}

// ---- I-09 -----------------------------------------------------------------------------------------

async fn probe_cancel(h: &Harness, params: Value) -> Result<(String, Vec<String>), TestError> {
    let id = queued(h, SEARCH, params).await?;
    let env = h.handler().cancel(&id).await;
    assert_cancelled(&env);
    let status = h.status(&id).await;
    Ok((same(&id, &env), vec![same(&id, &status)]))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i09_probe_cancel_envelopes_identical() -> TestResult {
    // One probe whose answer crosses the 16 MiB release cap (an outcome item), one that
    // matches nothing: a cancel tells them apart no more than `status` would.
    let big = Harness::jira().await?;
    let huge = json!({
        "startAt": 0, "maxResults": 50, "total": 1,
        "issues": [{ "id": "1", "key": "ABC-1", "fields": { "summary": "x".repeat(17 << 20) } }]
    });
    Mock::given(method("POST"))
        .and(path(jira(&big)?.path("/rest/api/2/search")))
        .respond_with(
            jira(&big)?
                .response(200)
                .set_body_raw(huge.to_string(), "application/json"),
        )
        .mount(jira(&big)?.server())
        .await;
    let empty = Harness::jira().await?;
    jira(&empty)?
        .json(
            "/rest/api/2/search",
            200,
            r#"{"startAt":0,"maxResults":50,"total":0,"issues":[]}"#,
        )
        .await;
    let params = json!({ "jql": "project = NONE", "max": 10 });
    let (e1, s1) = probe_cancel(&big, params.clone()).await?;
    let (e2, s2) = probe_cancel(&empty, params).await?;
    assert_eq!(e1, e2);
    assert_eq!(s1, s2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn i09_cancel_path_never_awaits_network() -> TestResult {
    let (h, server) = raw_jira(vec![stalled(b"{\"issues\":")], None, TestHooks::none()).await?;
    let id = submit_pending(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
    wait_connections(&server, 1).await?;
    wait_partial(&h, &id, 5).await?;
    // The server never completes the answer and never closes the socket.
    let env = tokio::time::timeout(Duration::from_secs(2), h.handler().cancel(&id))
        .await
        .map_err(|_| "cancel waited for the network")?;
    assert_cancelled(&env);
    assert_eq!(server.closed(), 0);
    let again = h.engine().cancel_now(&id, CancelCause::Client);
    // Terminal now: the reduced status, never a second record.
    assert_eq!(again.status, Status::Cancelled);
    assert_eq!(h.event_types(&id).await?.len(), 3);
    Ok(())
}

// ---- expiry ---------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiry_commits_partial_before_expired() -> TestResult {
    let (h, server) = raw_jira(vec![stalled(b"{\"key\":\"ABC")], None, TestHooks::none()).await?;
    let id = submit_pending(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
    wait_connections(&server, 1).await?;
    wait_partial(&h, &id, 10).await?;
    assert!(h.expire_now(&id).await);
    assert_eq!(
        h.event_types(&id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::READ_FETCHED,
            EventType::EXPIRED
        ]
    );
    let fetched = records(&h, &id, EventType::READ_FETCHED).await?;
    let f = fetched.first().ok_or("no READ_FETCHED")?;
    assert_eq!(f["outcome"], "cancelled_in_flight");
    assert_eq!(f["reason"], "expired");
    let env = h.status(&id).await;
    assert_eq!((env.status, exit(&env)), (Status::Expired, 7));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_expiry_timer_expires_a_pending_request() -> TestResult {
    let hooks = TestHooks {
        expiry: Some(Duration::from_millis(300)),
        ..TestHooks::none()
    };
    let (h, _server) = raw_jira(vec![stalled(b"{")], None, hooks).await?;
    let id = submit_pending(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
    assert!(h.settled(&id, 10_000).await, "never expired");
    let env = h.status(&id).await;
    assert_eq!((env.status, exit(&env)), (Status::Expired, 7));
    assert_eq!(h.event_types(&id).await?.last(), Some(&EventType::EXPIRED));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_decided_request_is_not_expired_by_its_old_timer() -> TestResult {
    let hooks = TestHooks {
        expiry: Some(Duration::from_millis(400)),
        ..TestHooks::none()
    };
    let issue = fixtures::JIRA_ISSUE.as_bytes();
    let (h, _server) = raw_jira(
        vec![vec![RawStep::Send(raw_answer(issue, issue.len()))]],
        None,
        hooks,
    )
    .await?;
    let id = queued(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
    h.approver().release(&id).map_err(de)?;
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(h.await_(&id, 5000).await.status, Status::Released);
    assert!(!h.event_types(&id).await?.contains(&EventType::EXPIRED));
    Ok(())
}

// ---- writes ---------------------------------------------------------------------------------------

/// `comment_add` approved, its POST answering after `delay`.
async fn executing_write(delay: Duration) -> Result<(Harness, String), TestError> {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    Mock::given(method("POST"))
        .and(path(mock.path("/rest/api/2/issue/ABC-1/comment")))
        .respond_with(
            mock.response(201)
                .set_body_raw(fixtures::JIRA_COMMENT, "application/json")
                .set_delay(delay),
        )
        .mount(mock.server())
        .await;
    let id = queued(
        &h,
        COMMENT,
        json!({ "key": "ABC-1", "body": "Reproduced.", "body_format": "wiki" }),
    )
    .await?;
    h.approver().approve(&id).map_err(de)?;
    // The POST reached the server.
    for _ in 0..1000 {
        let posts = jira(&h)?
            .received()
            .await
            .iter()
            .filter(|r| r.method.as_str() == "POST")
            .count();
        if posts > 0 {
            return Ok((h, id));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("the write was never sent".into())
}

fn assert_executing(env: &Envelope) {
    assert_eq!(env.status, Status::Executing, "{}", env.to_json_line());
    assert_eq!(exit(env), 4);
    assert_eq!(env.error, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_executing_returns_executing() -> TestResult {
    let (h, id) = executing_write(Duration::from_secs(20)).await?;
    let env = h.handler().cancel(&id).await;
    assert_executing(&env);
    assert!(!h.event_types(&id).await?.contains(&EventType::CANCELLED));
    assert_eq!(h.status(&id).await.status, Status::Executing);
    Ok(())
}

fn page_at(version: u64) -> String {
    let mut page: Value = serde_json::from_str(fixtures::CONFLUENCE_PAGE).unwrap_or(Value::Null);
    page["version"]["number"] = json!(version);
    page.to_string()
}

async fn confluence_identity_ok(mock: &MockDc) {
    mock.confluence_user_current(
        atlas_duck_atlassian::testing::UserKind::Known,
        TEST_USER,
        TEST_USER_KEY,
    )
    .await;
}

const PAGE_PARAMS: &str =
    r#"{"id":"65537","base_version":5,"body":"<p>New text.</p>","body_format":"storage"}"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_after_version_conflict_returns_executing() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    confluence_identity_ok(mock).await;
    let content = mock.path("/rest/api/content/65537");
    let enrich_q = "body.storage,version,space";
    for (version, once, priority) in [(5, true, 1u8), (6, false, 2u8)] {
        let mut m = Mock::given(method("GET"))
            .and(path(content.clone()))
            .and(query_param("expand", enrich_q))
            .respond_with(
                mock.response(200)
                    .set_body_raw(page_at(version), "application/json"),
            )
            .with_priority(priority);
        if once {
            m = m.up_to_n_times(1);
        }
        m.mount(mock.server()).await;
    }
    Mock::given(method("GET"))
        .and(path(content.clone()))
        .and(query_param("expand", "version"))
        .respond_with(
            mock.response(200)
                .set_body_raw(page_at(5), "application/json"),
        )
        .mount(mock.server())
        .await;
    Mock::given(method("PUT"))
        .and(path(content))
        .respond_with(mock.response(409).set_body_raw(
            fixtures::CONFLUENCE_VERSION_CONFLICT_409,
            "application/json",
        ))
        .mount(mock.server())
        .await;
    let params: Value = serde_json::from_str(PAGE_PARAMS)?;
    let id = queued(&h, "confluence.page.update", params).await?;
    let rev1 = h.approver().rev(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    for _ in 0..500 {
        if h.approver()
            .item(&id)
            .is_some_and(|i| i.candidate_rev.counter > rev1.counter + 1)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Back in the queue with `executing` still shown: a client cancel answers `executing`.
    assert_eq!(h.status(&id).await.status, Status::Executing);
    let env = h.handler().cancel(&id).await;
    assert_executing(&env);
    assert!(!h.event_types(&id).await?.contains(&EventType::CANCELLED));
    // Identical to a cancel during a stalled execution.
    let (h2, id2) = executing_write(Duration::from_secs(20)).await?;
    let env2 = h2.handler().cancel(&id2).await;
    let strip = |e: &Envelope| -> Result<Value, TestError> {
        let mut v = json(e)?;
        for k in ["request_id", "op_id", "instance"] {
            v[k] = Value::Null;
        }
        Ok(v)
    };
    assert_eq!(strip(&env)?, strip(&env2)?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_terminal_returns_terminal() -> TestResult {
    let h = Harness::jira().await?;
    jira(&h)?
        .json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    let id = queued(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
    h.approver().release(&id).map_err(de)?;
    assert_eq!(h.await_(&id, 5000).await.status, Status::Released);
    let before = h.event_types(&id).await?;
    let env = h.handler().cancel(&id).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    assert_eq!(env.data, None);
    assert_eq!(h.event_types(&id).await?, before);
    // An unknown id is `unknown_request`, exit 2.
    let gone = h.handler().cancel("no-such-request").await;
    assert_eq!((code(&gone), exit(&gone)), ("unknown_request".into(), 2));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiry_during_stale_check_expires_on_return() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    confluence_identity_ok(mock).await;
    let content = mock.path("/rest/api/content/65537");
    Mock::given(method("GET"))
        .and(path(content.clone()))
        .and(query_param("expand", "body.storage,version,space"))
        .respond_with(
            mock.response(200)
                .set_body_raw(page_at(5), "application/json"),
        )
        .mount(mock.server())
        .await;
    // The stale check sees another version, after a delay the test expires the request in.
    Mock::given(method("GET"))
        .and(path(content))
        .and(query_param("expand", "version"))
        .respond_with(
            mock.response(200)
                .set_body_raw(page_at(6), "application/json")
                .set_delay(Duration::from_millis(1500)),
        )
        .mount(mock.server())
        .await;
    let params: Value = serde_json::from_str(PAGE_PARAMS)?;
    let id = queued(&h, "confluence.page.update", params).await?;
    h.approver().approve(&id).map_err(de)?;
    for _ in 0..1000 {
        let seen = wiki(&h)?
            .received()
            .await
            .iter()
            .any(|r| r.url.query().is_some_and(|q| q.contains("expand=version")));
        if seen {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let before = h.event_types(&id).await?;
    // The stale check cannot expire (it is bounded by its own budget): nothing is logged.
    assert!(!h.expire_now(&id).await);
    assert_eq!(h.event_types(&id).await?, before);
    assert_eq!(h.status(&id).await.status, Status::Pending);
    assert!(h.settled(&id, 10_000).await, "never expired");
    let types = h.event_types(&id).await?;
    let tail: Vec<_> = types.iter().rev().take(2).rev().copied().collect();
    assert_eq!(tail, [EventType::WRITE_STALE, EventType::EXPIRED]);
    let stale = records(&h, &id, EventType::WRITE_STALE).await?;
    assert_eq!(
        stale.first().map(|s| s["reason"].clone()),
        Some(json!("changed"))
    );
    // No decision between the return and the expiry.
    assert!(
        !types
            .iter()
            .skip_while(|t| **t != EventType::WRITE_STALE)
            .any(|t| *t == EventType::PREVIEW_SHOWN || *t == EventType::DECISION_STALE)
    );
    let env = h.status(&id).await;
    assert_eq!((env.status, exit(&env)), (Status::Expired, 7));
    Ok(())
}

// ---- the gate and the configuration ---------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_waits_for_the_transition_gate_and_sees_its_result() -> TestResult {
    let pause = atlas_duck_core::Pause::new();
    let hooks = TestHooks {
        pause_in_transition: Some(pause.clone()),
        ..TestHooks::none()
    };
    let issue = fixtures::JIRA_ISSUE.as_bytes();
    let (h, _server) = raw_jira(
        vec![vec![RawStep::Send(raw_answer(issue, issue.len()))]],
        None,
        hooks,
    )
    .await?;
    let id = submit_pending(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
    // The fetch's own transition passes through the same hook.
    pause.reached.notified().await;
    pause.release.notify_one();
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    // A release commits and then holds inside the gated section.
    let approver = h.approver();
    let rid = id.clone();
    let decision = std::thread::spawn(move || approver.release(&rid).map(|_| ()));
    // Opening the item (`PREVIEW_SHOWN`) is a transition of its own; the release follows it.
    pause.reached.notified().await;
    pause.release.notify_one();
    pause.reached.notified().await;
    let handler = h.handler();
    let cid = id.clone();
    let cancel = tokio::spawn(async move { handler.cancel(&cid).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!cancel.is_finished(), "cancel did not wait for the gate");
    pause.release.notify_one();
    let env = cancel.await?;
    decision
        .join()
        .map_err(|_| "decision thread panicked")?
        .map_err(de)?;
    // The release won: the cancel answers the terminal status and logs nothing.
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    let types = h.event_types(&id).await?;
    assert!(types.contains(&EventType::READ_RELEASED));
    assert!(!types.contains(&EventType::CANCELLED));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiry_hours_come_from_config_and_fall_back_to_24() -> TestResult {
    let hours = |cfg: &str| {
        let cfg = cfg.to_owned();
        async move {
            let h = Harness::builder()
                .jira("jira-main")
                .extra_config(&cfg)
                .start()
                .await?;
            Ok::<_, TestError>(h.engine().expiry())
        }
    };
    let h = |n: u64| Duration::from_secs(n * 3600);
    assert_eq!(hours("").await?, h(24));
    assert_eq!(hours("[requests]\nexpiry_hours = 2\n").await?, h(2));
    assert_eq!(hours("[requests]\nexpiry_hours = 168\n").await?, h(168));
    for bad in ["0", "169", "-1", "\"3\"", "1.5"] {
        let cfg = format!("[requests]\nexpiry_hours = {bad}\n");
        assert_eq!(hours(&cfg).await?, h(24), "{bad}");
    }
    Ok(())
}
