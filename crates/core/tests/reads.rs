#![cfg(feature = "testing")]
//! The read lifecycle end to end (Task 21): fetch, release items (result, upstream error,
//! outcome), the human decisions through the scripted approver, and `await` delivery from the
//! committed records (I-08, I-38, §4.4 delivery window, §5.2, §7.5, L38).

mod common;

use std::time::Duration;

use atlas_duck_atlassian::testing::{MockDc, RawHttpServer, RawStep, TestTlsServer, fixtures};
use atlas_duck_atlassian::{ReadBudget, Timeouts};
use atlas_duck_audit::EventType;
use atlas_duck_core::engine::read::{HINT_PROXY, HINT_TLS_UNKNOWN_ISSUER, OUTCOME_HINT};
use atlas_duck_core::testing::{Harness, InstanceAt};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_preview::{OutcomeKind, PreviewBody};
use atlas_duck_registry::Product;
use common::{TestError, TestResult, code, de, detail, exit, message, request_id};
use serde_json::{Value, json};
use wiremock::Mock;
use wiremock::matchers::{method, path};

const ISSUE: &str = "jira.issue.get";
const SEARCH: &str = "jira.search";

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

/// Submits, expects `pending`, and waits until the read waits for release.
async fn queued(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 20_000).await.ok_or("never queued")?;
    Ok(id)
}

async fn types(h: &Harness, id: &str) -> Result<Vec<EventType>, TestError> {
    h.event_types(id).await
}

/// The payload of the first record of `t`.
async fn record(h: &Harness, id: &str, t: EventType) -> Result<Value, TestError> {
    h.events(id)
        .await?
        .into_iter()
        .find(|(e, _)| *e == t)
        .map(|(_, p)| p)
        .ok_or_else(|| format!("no {t:?}").into())
}

/// A Jira issue body whose summary is `n` bytes of `c`.
fn issue_body(key: &str, n: usize, c: char) -> String {
    let summary: String = std::iter::repeat_n(c, n).collect();
    json!({ "key": key, "fields": { "summary": summary } }).to_string()
}

/// One raw HTTP/1.1 answer as Jira sends it (`X-AUSERNAME` of the harness user).
fn raw_answer(status: &str, content_type: &str, body: &[u8], content_length: usize) -> Vec<u8> {
    let mut v = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {content_length}\r\nX-AUSERNAME: {}\r\nConnection: close\r\n\r\n",
        atlas_duck_atlassian::testing::TEST_USER
    )
    .into_bytes();
    v.extend_from_slice(body);
    v
}

/// The released outcome envelope: `failed`, exit 6, `code`, the fixed hint, nothing else.
fn assert_outcome_delivery(env: &atlas_duck_ipc::envelope::Envelope, want: &str) -> TestResult {
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(exit(env), 6);
    assert_eq!(code(env), want);
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    assert_eq!(message(env), OUTCOME_HINT);
    assert_eq!(env.data, None);
    assert_eq!(env.meta, None);
    assert!(env.error.as_ref().is_some_and(|e| e.details.is_none()));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_release_roundtrip() -> TestResult {
    let h = Harness::jira().await?;
    jira(&h)?
        .json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    let id = queued(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
    // Waiting for release: still only `pending`.
    assert_eq!(h.status(&id).await.status, Status::Pending);
    let item = h.approver().item(&id).ok_or("not in the queue")?;
    assert_eq!(item.candidate_rev.counter, 1);
    assert!(item.approvable && !item.opened);
    h.approver().release(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    assert_eq!(exit(&env), 0);
    assert_eq!(env.error, None);
    assert!(!env.redacted);
    let data = env.data.clone().ok_or("no data")?;
    assert_eq!(data["result"]["key"], "ABC-1");
    assert_eq!(
        data["result"],
        serde_json::from_str::<Value>(fixtures::JIRA_ISSUE)?
    );
    let meta = env.meta.clone().ok_or("no meta")?;
    assert!(meta["fetched_at"].is_string() && meta["released_at"].is_string());
    assert_eq!(
        types(&h, &id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::READ_FETCHED,
            EventType::PREVIEW_SHOWN,
            EventType::READ_RELEASED,
            EventType::DELIVERED
        ]
    );
    // Inv. 2 / PD-23: the delivery names the released bytes' hash.
    let released = record(&h, &id, EventType::READ_RELEASED).await?;
    let delivered = record(&h, &id, EventType::DELIVERED).await?;
    assert_eq!(delivered["payload_sha256"], released["released_sha256"]);
    assert_eq!(delivered["agent_name"], "test-agent");
    // Within the hour: delivered again, logged again.
    let again = h.await_(&id, 5000).await;
    assert_eq!(again.data, env.data);
    let t = types(&h, &id).await?;
    assert_eq!(
        t.iter().filter(|e| **e == EventType::DELIVERED).count(),
        2,
        "{t:?}"
    );
    // `status` never delivers and is never logged.
    let st = h.status(&id).await;
    assert_eq!((st.status, st.data), (Status::Released, None));
    assert_eq!(types(&h, &id).await?.len(), t.len());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i08_release_cap_is_outcome_item() -> TestResult {
    let h = Harness::jira().await?;
    let body = issue_body("ABC-1", 17 * 1024 * 1024, 'z');
    jira(&h)?.json("/rest/api/2/issue/ABC-1", 200, &body).await;
    let id = queued(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    match &preview.body {
        PreviewBody::Outcome { outcome, .. } => assert_eq!(*outcome, OutcomeKind::ReleaseCap16),
        other => return Err(format!("not an outcome card: {other:?}").into()),
    }
    // The candidate is the outcome itself, never the 17 MiB.
    assert!(preview.raw.total_bytes < 1024);
    let fetched = record(&h, &id, EventType::READ_FETCHED).await?;
    assert_eq!(fetched["outcome"], "too_large");
    assert_eq!(fetched["cap_or_budget"], "release_cap_16mib");
    assert!(
        fetched["size"]
            .as_u64()
            .is_some_and(|s| s > 17 * 1024 * 1024)
    );
    h.approver().release_unopened(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_outcome_delivery(&env, "result_too_large")?;
    let line = env.to_json_line();
    assert!(!line.contains("1782") && !line.contains("17 MiB"), "{line}");
    Ok(())
}

/// A `jira.search` page of `count` issues of about `issue_bytes` each, from a server that has
/// many more.
fn big_search_page(issue_bytes: usize, count: u64) -> String {
    let filler: String = std::iter::repeat_n('b', issue_bytes).collect();
    let issues: Vec<Value> = (0..count)
        .map(|i| json!({ "id": i.to_string(), "key": format!("BIG-{i}"), "fields": { "summary": filler } }))
        .collect();
    json!({ "startAt": 0, "maxResults": count, "total": 100_000, "issues": issues }).to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i08_fetch_cap_is_outcome_item() -> TestResult {
    let h = Harness::jira().await?;
    // 20 MiB pages: the third one crosses the 50 MiB fetch cap.
    let page = big_search_page(420 * 1024, 50);
    assert!(page.len() > 20 * 1024 * 1024);
    jira(&h)?.json("/rest/api/2/search", 200, &page).await;
    let id = queued(&h, SEARCH, json!({ "jql": "project = BIG", "max": 500 })).await?;
    match h.approver().open(&id).map_err(de)?.preview.body {
        PreviewBody::Outcome { outcome, .. } => assert_eq!(outcome, OutcomeKind::FetchCap50),
        other => return Err(format!("not an outcome card: {other:?}").into()),
    }
    let fetched = record(&h, &id, EventType::READ_FETCHED).await?;
    assert_eq!(fetched["cap_or_budget"], "fetch_cap_50mib");
    assert_eq!(fetched["pages"], 2);
    h.approver().release_unopened(&id).map_err(de)?;
    assert_outcome_delivery(&h.await_(&id, 5000).await, "result_too_large")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i08_read_budget_is_outcome_item() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .read_budget(ReadBudget {
            total: Duration::from_millis(300),
            ..ReadBudget::default()
        })
        .start()
        .await?;
    let mock = jira(&h)?;
    // Full pages, each 200 ms late: the second one outlives the 300 ms budget.
    Mock::given(path(mock.path("/rest/api/2/search")))
        .respond_with(
            mock.response(200)
                .set_body_raw(
                    fixtures::jira_search_page(0, 50, 1000, 50),
                    "application/json",
                )
                .set_delay(Duration::from_millis(200)),
        )
        .mount(mock.server())
        .await;
    let id = queued(&h, SEARCH, json!({ "jql": "project = ABC", "max": 500 })).await?;
    match h.approver().open(&id).map_err(de)?.preview.body {
        PreviewBody::Outcome { outcome, .. } => assert_eq!(outcome, OutcomeKind::ReadBudget120),
        other => return Err(format!("not an outcome card: {other:?}").into()),
    }
    h.approver().release_unopened(&id).map_err(de)?;
    assert_outcome_delivery(&h.await_(&id, 5000).await, "upstream_network")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i08_per_call_timeout_after_send_is_outcome_item() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .timeouts(Timeouts {
            per_call: Duration::from_millis(300),
            ..Timeouts::default()
        })
        .start()
        .await?;
    let mock = jira(&h)?;
    Mock::given(method("GET"))
        .and(path(mock.path("/rest/api/2/issue/SLOW-1")))
        .respond_with(
            mock.response(200)
                .set_body_raw(fixtures::JIRA_ISSUE, "application/json")
                .set_delay(Duration::from_secs(3)),
        )
        .mount(mock.server())
        .await;
    let id = queued(&h, ISSUE, json!({ "key": "SLOW-1" })).await?;
    match h.approver().open(&id).map_err(de)?.preview.body {
        PreviewBody::Outcome { outcome, .. } => {
            assert_eq!(outcome, OutcomeKind::PerCallTimeout30)
        }
        other => return Err(format!("not an outcome card: {other:?}").into()),
    }
    let fetched = record(&h, &id, EventType::READ_FETCHED).await?;
    assert_eq!(fetched["outcome"], "timeout");
    assert_eq!(fetched["cap_or_budget"], "call_timeout_30s");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i08_network_error_after_first_page_is_outcome_item() -> TestResult {
    let page1 = fixtures::jira_board_page(0, 50, Some(1000), 50);
    let page2 = fixtures::jira_board_page(50, 50, Some(1000), 50);
    let cut = page2.len() / 3;
    let server = RawHttpServer::serve_sequence(vec![
        vec![RawStep::Send(raw_answer(
            "200 OK",
            "application/json",
            page1.as_bytes(),
            page1.len(),
        ))],
        vec![
            RawStep::Send(raw_answer(
                "200 OK",
                "application/json",
                page2.as_bytes().get(..cut).ok_or("cut")?,
                page2.len(),
            )),
            RawStep::Close,
        ],
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
        .start()
        .await?;
    let id = queued(&h, "jira.board.list", json!({ "max": 100 })).await?;
    assert_eq!(server.connections(), 2);
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert!(
        matches!(preview.body, PreviewBody::Outcome { .. }),
        "{:?}",
        preview.body
    );
    let fetched = record(&h, &id, EventType::READ_FETCHED).await?;
    assert_eq!(fetched["outcome"], "network");
    // Every byte received: the first page and the cut one.
    assert!(
        fetched["size"]
            .as_u64()
            .is_some_and(|s| s >= (page1.len() + cut) as u64)
    );
    h.approver().release_unopened(&id).map_err(de)?;
    assert_outcome_delivery(&h.await_(&id, 5000).await, "upstream_network")
}

/// An outcome item from a per-call timeout (`upstream_network`).
async fn timeout_outcome() -> Result<(Harness, String), TestError> {
    let h = Harness::builder()
        .jira("jira-main")
        .timeouts(Timeouts {
            per_call: Duration::from_millis(200),
            ..Timeouts::default()
        })
        .start()
        .await?;
    let mock = jira(&h)?;
    Mock::given(path(mock.path("/rest/api/2/issue/SLOW-1")))
        .respond_with(
            mock.response(200)
                .set_body_raw(fixtures::JIRA_ISSUE, "application/json")
                .set_delay(Duration::from_secs(3)),
        )
        .mount(mock.server())
        .await;
    let id = queued(&h, ISSUE, json!({ "key": "SLOW-1" })).await?;
    Ok((h, id))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i08_release_outcome_delivers_failed_exit6() -> TestResult {
    let (h, id) = timeout_outcome().await?;
    let out = h.approver().release(&id).map_err(de)?;
    assert_eq!(out.status, Status::Failed);
    let env = h.await_(&id, 5000).await;
    assert_outcome_delivery(&env, "upstream_network")?;
    // The outcome-only payload (§8.3).
    let released = record(&h, &id, EventType::READ_RELEASED).await?;
    assert_eq!(
        released,
        json!({ "code": "upstream_network", "hint": OUTCOME_HINT })
    );
    // An outcome item takes no redactions.
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i08_deny_outcome_exit3() -> TestResult {
    let (h, id) = timeout_outcome().await?;
    // The human reason reaches the agent with flagged characters stripped (M-1 ruling).
    h.approver().deny(&id, "not\u{202E} now").map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Denied);
    assert_eq!(exit(&env), 3);
    assert_eq!(code(&env), "denied");
    assert_eq!(message(&env), "not now");
    assert_eq!(env.data, None);
    assert_eq!(
        types(&h, &id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::READ_FETCHED,
            EventType::PREVIEW_SHOWN,
            EventType::READ_DENIED,
            EventType::DELIVERED
        ]
    );
    Ok(())
}

/// A direct pre-send failure: `failed`, exit 6, `upstream_network`, `retryable: true`, the
/// class hint, logged `[REQUEST_RECEIVED, READ_FAILED]`, never a release item.
async fn assert_presend(h: &Harness, alias: &str, hint: Option<&str>) -> TestResult {
    let env = h
        .submit_with(
            h.default_conn(),
            ISSUE,
            json!({ "key": "ABC-1" }),
            Some(alias),
        )
        .await;
    assert_eq!(env.status, Status::Pending);
    let id = request_id(&env)?;
    assert!(h.settled(&id, 30_000).await, "{alias} never settled");
    let env = h.await_(&id, 1000).await;
    assert_eq!(
        env.status,
        Status::Failed,
        "{alias}: {}",
        env.to_json_line()
    );
    assert_eq!(exit(&env), 6, "{alias}");
    assert_eq!(code(&env), "upstream_network", "{alias}");
    assert_eq!(
        env.error.as_ref().map(|e| e.retryable),
        Some(true),
        "{alias}"
    );
    if let Some(hint) = hint {
        assert_eq!(message(&env), hint, "{alias}");
    }
    // A fixed text: no host, port or URL of the instance (§4.5).
    let msg = message(&env);
    assert!(!msg.is_empty(), "{alias}");
    for leak in ["127.0.0.1", "nonexistent", "http", "://"] {
        assert!(!msg.contains(leak), "{alias}: {msg}");
    }
    assert_eq!(env.data, None);
    assert_eq!(
        types(h, &id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::READ_FAILED,
            EventType::DELIVERED
        ],
        "{alias}"
    );
    assert!(h.approver().item(&id).is_none());
    // Never announced to the queue.
    assert!(
        !h.capture()
            .on(atlas_duck_core::testing::Channel::UiEvent)
            .iter()
            .any(|c| c.json.contains(&id))
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i08_presend_failures_direct_exit6() -> TestResult {
    let closed = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let tls = TestTlsServer::start().await?;
    let tls_for_proxy = TestTlsServer::start().await?;
    let proxy = RawHttpServer::serve(vec![
        RawStep::Send(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
        ),
        RawStep::Close,
    ])
    .await?;
    let h = Harness::builder()
        .instance_at(
            "dns",
            Product::Jira,
            InstanceAt {
                base_url: "http://nonexistent.invalid".to_owned(),
                ..InstanceAt::default()
            },
        )
        .instance_at(
            "refused",
            Product::Jira,
            InstanceAt {
                base_url: format!("http://127.0.0.1:{closed}"),
                ..InstanceAt::default()
            },
        )
        .instance_at(
            "tls",
            Product::Jira,
            InstanceAt {
                base_url: tls.base_url(),
                ..InstanceAt::default()
            },
        )
        .instance_at(
            "proxied",
            Product::Jira,
            InstanceAt {
                base_url: tls_for_proxy.base_url(),
                proxy: Some(format!("127.0.0.1:{}", proxy.addr().port())),
                ca_pem: Some(tls_for_proxy.ca_pem().to_owned()),
            },
        )
        .start()
        .await?;
    assert_presend(&h, "dns", None).await?;
    assert_presend(&h, "refused", None).await?;
    assert_presend(&h, "tls", Some(HINT_TLS_UNKNOWN_ISSUER)).await?;
    assert_presend(&h, "proxied", Some(HINT_PROXY)).await?;
    // The READ_FAILED record names the class (audit only).
    Ok(())
}

/// A Jira 404 upstream error with `errorMessages`.
async fn not_found_item() -> Result<(Harness, String), TestError> {
    let h = Harness::jira().await?;
    jira(&h)?
        .json(
            "/rest/api/2/issue/NOPE-1",
            404,
            r#"{"errorMessages":["Issue does not exist"],"errors":{}}"#,
        )
        .await;
    let id = queued(&h, ISSUE, json!({ "key": "NOPE-1" })).await?;
    Ok((h, id))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i38_release_status_only() -> TestResult {
    let (h, id) = not_found_item().await?;
    match h.approver().open(&id).map_err(de)?.preview.body {
        PreviewBody::UpstreamError {
            status,
            error_messages_text,
        } => assert_eq!(
            (status, error_messages_text.as_str()),
            (404, "Issue does not exist")
        ),
        other => return Err(format!("not an upstream-error card: {other:?}").into()),
    }
    let out = h.approver().release_status_only(&id).map_err(de)?;
    assert_eq!(out.status, Status::Failed);
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(exit(&env), 6);
    assert_eq!(code(&env), "upstream_http");
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    let details = env
        .error
        .as_ref()
        .and_then(|e| e.details.clone())
        .ok_or("no details")?;
    assert_eq!(Value::Object(details), json!({ "status": 404 }));
    assert!(env.redacted);
    let meta = env.meta.clone().ok_or("no meta")?;
    assert_eq!(
        meta["redactions"]["fields_dropped"],
        json!(["error_messages"])
    );
    assert!(!env.to_json_line().contains("Issue does not exist"));
    assert_eq!(
        types(&h, &id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::READ_FETCHED,
            EventType::PREVIEW_SHOWN,
            EventType::PREVIEW_SHOWN,
            EventType::READ_RELEASED,
            EventType::DELIVERED
        ]
    );
    // `status` agrees without details (§4.4).
    let st = h.status(&id).await;
    assert_eq!(
        (st.status, code(&st)),
        (Status::Failed, "upstream_http".to_owned())
    );
    assert_eq!(detail(&st, "status"), Value::Null);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn released_upstream_error_full() -> TestResult {
    let (h, id) = not_found_item().await?;
    h.approver().release(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Failed);
    assert_eq!(exit(&env), 6);
    assert_eq!(code(&env), "upstream_http");
    assert_eq!(detail(&env, "status"), json!(404));
    assert_eq!(
        detail(&env, "error_messages"),
        json!("Issue does not exist")
    );
    assert!(!env.redacted);
    assert_eq!(env.data, None);
    // `requests list` says what `status` says.
    let list = h.handler().requests_list(None, None, None).await;
    let rows = list.data.ok_or("no rows")?;
    let row = rows["requests"]
        .as_array()
        .and_then(|r| r.iter().find(|r| r["request_id"] == json!(id)))
        .cloned()
        .ok_or("no row")?;
    assert_eq!(row["status"], "failed");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delivery_window_evicts_after_1h() -> TestResult {
    let h = Harness::jira().await?;
    jira(&h)?
        .json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    let id = queued(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
    h.approver().release(&id).map_err(de)?;
    assert_eq!(h.await_(&id, 5000).await.status, Status::Released);
    h.clock().advance(Duration::from_secs(61 * 60));
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    assert_eq!(code(&env), "result_evicted");
    assert_eq!(exit(&env), 10);
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    assert_eq!(env.data, None);
    assert_eq!(env.meta, None);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn search_target_is_query_tag() -> TestResult {
    let h = Harness::jira().await?;
    jira(&h)?
        .json("/rest/api/2/search", 200, fixtures::JIRA_SEARCH_PAGE)
        .await;
    let env = h
        .submit(
            SEARCH,
            json!({ "jql": "project = SECRETPROJ ORDER BY key" }),
        )
        .await;
    let id = request_id(&env)?;
    let store = h.store();
    let headers = tokio::task::spawn_blocking(move || store.headers_for_request(&id)).await??;
    let start = headers.first().ok_or("no records")?;
    assert_eq!(start.event_type, EventType::REQUEST_RECEIVED);
    let target = start.target.clone().ok_or("no target")?;
    assert!(target.starts_with("jql:"), "{target}");
    assert!(!target.contains("SECRETPROJ"), "{target}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paged_release_meta_page() -> TestResult {
    let h = Harness::jira().await?;
    jira(&h)?
        .json(
            "/rest/agile/1.0/board",
            200,
            &fixtures::jira_board_page(0, 50, Some(3), 3),
        )
        .await;
    let id = queued(&h, "jira.board.list", json!({ "max": 10 })).await?;
    h.approver().release(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    let meta = env.meta.clone().ok_or("no meta")?;
    assert_eq!(
        meta["page"],
        json!({ "start": 0, "returned": 3, "total": 3, "truncated": false, "next_start": null })
    );
    assert_eq!(
        env.data
            .as_ref()
            .map(|d| d["result"]["values"].as_array().map(Vec::len)),
        Some(Some(3))
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn search_results_without_content_dropped() -> TestResult {
    let h = Harness::confluence().await?;
    let mut page: Value = serde_json::from_str(fixtures::CONFLUENCE_SEARCH_PAGE)?;
    let first = page["results"][0].clone();
    let mut bare = first.clone();
    if let Some(o) = bare.as_object_mut() {
        o.remove("content");
        o.insert("title".into(), json!("a space, not content"));
    }
    page["results"] = json!([first.clone(), bare, first]);
    page["size"] = json!(3);
    page["totalSize"] = json!(3);
    h.mock("wiki")
        .ok_or("no mock")?
        .json("/rest/api/search", 200, &page.to_string())
        .await;
    let id = queued(&h, "confluence.search", json!({ "cql": "space = DOC" })).await?;
    // The approver sees the effective CQL (§6.3).
    let preview = h.approver().open(&id).map_err(de)?.preview;
    let q = preview.header.query.clone().ok_or("no query")?;
    assert!(q.contains("space = DOC"), "{q}");
    assert!(q.contains("page,blogpost"), "{q}");
    h.approver().release_unopened(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Released, "{}", env.to_json_line());
    let results = env
        .data
        .as_ref()
        .and_then(|d| d["result"]["results"].as_array().cloned())
        .ok_or("no results")?;
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|r| r["content"].is_object()));
    let meta = env.meta.clone().ok_or("no meta")?;
    assert_eq!(meta["redactions"]["items_dropped"], 1);
    // §7.5: returned + items_dropped = items fetched.
    assert_eq!(meta["page"]["returned"], 2);
    // Server totals pass through unchanged.
    assert_eq!(
        env.data.as_ref().map(|d| d["result"]["totalSize"].clone()),
        Some(json!(3))
    );
    Ok(())
}

/// §5.1 inv. 1 at `await`: a `DELIVERED` that does not commit hands nothing over.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delivered_append_failure_hands_over_nothing() -> TestResult {
    let plan = atlas_duck_core::testing::FaultPlan::new();
    let h = Harness::builder()
        .jira("jira-main")
        .faults(plan.clone())
        .start()
        .await?;
    jira(&h)?
        .json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    let id = queued(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
    h.approver().release(&id).map_err(de)?;
    plan.fail_nth(EventType::DELIVERED, 1);
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(exit(&env), 1);
    assert_eq!(code(&env), "audit_failure");
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    assert_eq!((&env.data, &env.meta), (&None, &None));
    assert!(!env.to_json_line().contains("ABC-1\""));
    assert!(!types(&h, &id).await?.contains(&EventType::DELIVERED));
    // The next `await` delivers (and logs it).
    let again = h.await_(&id, 5000).await;
    assert_eq!(again.status, Status::Released);
    assert!(types(&h, &id).await?.contains(&EventType::DELIVERED));
    Ok(())
}

/// §5.1 inv. 2 at `await`: released bytes that do not match their committed hash are refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_release_is_not_delivered() -> TestResult {
    let plan = atlas_duck_core::testing::FaultPlan::new();
    let h = Harness::builder()
        .jira("jira-main")
        .faults(plan.clone())
        .start()
        .await?;
    jira(&h)?
        .json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    let id = queued(&h, ISSUE, json!({ "key": "ABC-1" })).await?;
    plan.tamper_released_text(EventType::READ_RELEASED);
    h.approver().release(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "internal");
    assert_eq!(exit(&env), 1);
    assert_eq!((&env.data, &env.meta), (&None, &None));
    assert!(!env.to_json_line().contains("Login page"));
    Ok(())
}

/// Ruling 3: an outcome answer is fixed text and stays deliverable after the hour.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delivery_window_keeps_outcome_answers() -> TestResult {
    let (h, id) = timeout_outcome().await?;
    h.approver().release(&id).map_err(de)?;
    h.clock().advance(Duration::from_secs(61 * 60));
    let env = h.await_(&id, 5000).await;
    assert_outcome_delivery(&env, "upstream_network")?;
    assert_eq!(exit(&env), 6);
    Ok(())
}

/// Ruling 3: released upstream-error details are released data and leave after the hour.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delivery_window_evicts_upstream_error_details() -> TestResult {
    let (h, id) = not_found_item().await?;
    h.approver().release(&id).map_err(de)?;
    h.clock().advance(Duration::from_secs(61 * 60));
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "result_evicted");
    assert_eq!(exit(&env), 10);
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    assert!(env.error.as_ref().is_some_and(|e| e.details.is_none()));
    assert!(!env.to_json_line().contains("Issue does not exist"));
    Ok(())
}
