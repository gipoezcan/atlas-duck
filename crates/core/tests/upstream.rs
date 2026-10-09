#![cfg(feature = "testing")]
//! Upstream availability on the read path (Task 21: I-23 and I-24 read halves, RF-2a). Answers
//! decided from status and headers alone are direct (`failed`, exit 6, `retryable: true`) with
//! the body in the audit record only; every failure after a JSON 2xx head is a release-gated
//! outcome item (Review Focus 2). The write half (Task 22): enrichment, stale check and execution.

mod common;

use atlas_duck_atlassian::CredentialProvider;
use atlas_duck_atlassian::testing::{
    MockDc, RawHttpServer, RawStep, TEST_USER, TEST_USER_KEY, XAuser, fixtures,
};
use atlas_duck_audit::EventType;
use atlas_duck_core::testing::{Channel, Harness, InstanceAt};
use atlas_duck_ipc::envelope::Status;
use atlas_duck_preview::PreviewBody;
use atlas_duck_registry::Product;
use common::{TestError, TestResult, code, de, exit, request_id};
use serde_json::{Value, json};
use wiremock::Mock;
use wiremock::matchers::{body_string_contains, path};

const ISSUE: &str = "jira.issue.get";

fn jira(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("jira-main").ok_or_else(|| "no jira mock".into())
}

async fn types(h: &Harness, id: &str) -> Result<Vec<EventType>, TestError> {
    h.event_types(id).await
}

/// A direct `upstream_unavailable`: `failed`, exit 6, `retryable: true`, the answer recorded in
/// `READ_FETCHED` only, never a release item. Returns the `READ_FETCHED` payload.
async fn assert_unavailable_direct(h: &Harness, id: &str) -> Result<Value, TestError> {
    assert!(h.settled(id, 10_000).await, "never settled");
    let env = h.await_(id, 1000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(exit(&env), 6);
    assert_eq!(code(&env), "upstream_unavailable");
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    assert_eq!(env.data, None);
    assert!(env.error.as_ref().is_some_and(|e| e.details.is_none()));
    assert_eq!(
        types(h, id).await?,
        [
            EventType::REQUEST_RECEIVED,
            EventType::READ_FETCHED,
            EventType::READ_FAILED,
            EventType::DELIVERED
        ]
    );
    assert!(h.approver().item(id).is_none());
    h.events(id)
        .await?
        .into_iter()
        .find(|(t, _)| *t == EventType::READ_FETCHED)
        .map(|(_, p)| p)
        .ok_or_else(|| "no READ_FETCHED".into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i23_read_3xx_html_nonjson401_direct() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.redirect("/rest/api/2/issue/R-1", "https://sso.corp.example/login")
        .await;
    mock.html("/rest/api/2/issue/H-1", 200).await;
    mock.html("/rest/api/2/issue/U-1", 401).await;
    for (key, reason) in [
        ("R-1", "redirect_3xx"),
        ("H-1", "non_json_2xx"),
        ("U-1", "non_json_401"),
    ] {
        let env = h.submit(ISSUE, json!({ "key": key })).await;
        assert_eq!(env.status, Status::Pending);
        let id = request_id(&env)?;
        let fetched = assert_unavailable_direct(&h, &id).await?;
        assert_eq!(fetched["unavailable"], reason, "{key}");
        let failed = h
            .events(&id)
            .await?
            .into_iter()
            .find(|(t, _)| *t == EventType::READ_FAILED)
            .map(|(_, p)| p)
            .ok_or("no READ_FAILED")?;
        assert_eq!(failed["reason"], reason, "{key}");
    }
    // Nothing about the instance or its token changed (§7.2: not a token failure).
    let list = h.handler().instances_list().await;
    assert_eq!(
        list.data
            .as_ref()
            .map(|d| d["instances"][0]["state"].clone()),
        Some(json!("ok"))
    );
    let inst = h.instance("jira-main").ok_or("no instance")?;
    assert!(h.credentials().load(&inst.id)?.is_some());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i24_text_html_200_direct() -> TestResult {
    let h = Harness::jira().await?;
    jira(&h)?.html("/rest/api/2/issue/H-1", 200).await;
    let id = request_id(&h.submit(ISSUE, json!({ "key": "H-1" })).await)?;
    let fetched = assert_unavailable_direct(&h, &id).await?;
    // The page is audit-only: in the record, in no envelope.
    assert!(fetched.to_string().contains("Please log in"));
    assert!(
        !h.capture()
            .on(Channel::Envelope)
            .iter()
            .any(|c| c.json.contains("Please log in"))
    );
    Ok(())
}

/// A raw server answering `200 application/json` whose body stops early, then closing.
async fn gated_by(answer: Vec<u8>) -> TestResult {
    let server = RawHttpServer::serve(vec![RawStep::Send(answer), RawStep::Close]).await?;
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
    let env = h.submit(ISSUE, json!({ "key": "ABC-1" })).await;
    let id = request_id(&env)?;
    // Gated: a release item, `pending` meanwhile (§5.2 step 6, never direct).
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    assert_eq!(h.status(&id).await.status, Status::Pending);
    match h.approver().open(&id).map_err(de)?.preview.body {
        PreviewBody::Outcome { .. } => {}
        other => return Err(format!("not an outcome card: {other:?}").into()),
    }
    h.approver().release_unopened(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!(env.status, Status::Failed);
    assert_eq!(exit(&env), 6);
    assert!(matches!(
        code(&env).as_str(),
        "upstream_network" | "upstream_unavailable"
    ));
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    assert!(!env.to_json_line().contains("ABC-1\",\"fields"));
    Ok(())
}

fn head(extra: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-AUSERNAME: {TEST_USER}\r\nConnection: close\r\n{extra}\r\n"
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i24_truncated_json_body_is_gated_read() -> TestResult {
    let body = fixtures::JIRA_ISSUE.as_bytes();
    let mut answer = head(&format!("Content-Length: {}\r\n", body.len())).into_bytes();
    answer.extend_from_slice(body.get(..body.len() / 2).ok_or("cut")?);
    gated_by(answer).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i24_chunked_cutoff_is_gated() -> TestResult {
    let chunk = r#"{"key":"ABC-1","fields":{"summary":"#;
    // One chunk, then the connection closes before the terminating `0` chunk.
    let mut answer = head("Transfer-Encoding: chunked\r\n").into_bytes();
    answer.extend_from_slice(format!("{:x}\r\n{chunk}\r\n", chunk.len()).as_bytes());
    gated_by(answer).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rf2a_intermediary_conditioned_status() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    // An intermediary that redirects only queries naming the canary.
    Mock::given(path(mock.path("/rest/api/2/search")))
        .and(body_string_contains("CANARYRF2"))
        .respond_with(
            mock.response(302)
                .insert_header("Location", "https://sso.corp.example/login")
                .set_body_raw("<html>session for CANARYRF2 expired</html>", "text/html"),
        )
        .with_priority(1)
        .mount(mock.server())
        .await;
    mock.json("/rest/api/2/search", 200, fixtures::JIRA_SEARCH_PAGE)
        .await;
    let probe = request_id(
        &h.submit("jira.search", json!({ "jql": "text ~ \"CANARYRF2\"" }))
            .await,
    )?;
    let control = request_id(
        &h.submit("jira.search", json!({ "jql": "project = ABC" }))
            .await,
    )?;
    // Status/header-decided: direct, `retryable: true` (L44); the other query waits for release.
    let fetched = assert_unavailable_direct(&h, &probe).await?;
    assert!(fetched.to_string().contains("CANARYRF2"));
    h.queued(&control, 10_000).await.ok_or("never queued")?;
    assert_eq!(h.status(&control).await.status, Status::Pending);
    // No agent-visible byte and no UI event carries the intermediary's body.
    for c in h.capture().records() {
        if matches!(
            c.channel,
            Channel::Envelope | Channel::Progress | Channel::UiEvent
        ) {
            assert!(!c.json.contains("CANARYRF2"), "{:?}: {}", c.channel, c.json);
        }
    }
    Ok(())
}

/// Review I-1: a later page answered with a redirect is gated (whether a page 2 is requested
/// depends on the results), never a direct failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i23_later_page_redirect_is_gated() -> TestResult {
    let page1 = fixtures::jira_board_page(0, 50, Some(1000), 50);
    let mut first = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-AUSERNAME: {TEST_USER}\r\nConnection: close\r\n\r\n",
        page1.len()
    )
    .into_bytes();
    first.extend_from_slice(page1.as_bytes());
    let html = "<html>session expired</html>";
    let second = format!(
        "HTTP/1.1 302 Found\r\nLocation: https://sso.corp.example/login\r\nContent-Type: text/html\r\nContent-Length: {}\r\nX-AUSERNAME: {TEST_USER}\r\nConnection: close\r\n\r\n{html}",
        html.len()
    )
    .into_bytes();
    let server = RawHttpServer::serve_sequence(vec![
        vec![RawStep::Send(first)],
        vec![RawStep::Send(second)],
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
    let id = request_id(&h.submit("jira.board.list", json!({ "max": 100 })).await)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    assert_eq!(server.connections(), 2);
    assert_eq!(h.status(&id).await.status, Status::Pending);
    match h.approver().open(&id).map_err(de)?.preview.body {
        PreviewBody::Outcome { outcome, .. } => {
            assert_eq!(outcome, atlas_duck_preview::OutcomeKind::LaterPageRefused)
        }
        other => return Err(format!("not an outcome card: {other:?}").into()),
    }
    let fetched = h
        .events(&id)
        .await?
        .into_iter()
        .find(|(t, _)| *t == EventType::READ_FETCHED)
        .map(|(_, p)| p)
        .ok_or("no READ_FETCHED")?;
    assert_eq!(fetched["reason"], "redirect_3xx");
    assert!(fetched.to_string().contains("session expired"));
    h.approver().release_unopened(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!((env.status, exit(&env)), (Status::Failed, 6));
    assert_eq!(code(&env), "upstream_unavailable");
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    assert!(env.error.as_ref().is_some_and(|e| e.details.is_none()));
    Ok(())
}

/// Review I-2: a 2xx JSON body the client accepts but `serde_json::Value` cannot hold (nested
/// deeper than 128) is gated like any unreadable JSON body, never a direct `internal`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i24_deeply_nested_json_is_gated() -> TestResult {
    let h = Harness::jira().await?;
    let body = format!("{{\"a\":{}{}}}", "[".repeat(200), "]".repeat(200));
    jira(&h)?.json("/rest/api/2/issue/DEEP-1", 200, &body).await;
    let id = request_id(&h.submit(ISSUE, json!({ "key": "DEEP-1" })).await)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    match h.approver().open(&id).map_err(de)?.preview.body {
        PreviewBody::Outcome { outcome, .. } => {
            assert_eq!(outcome, atlas_duck_preview::OutcomeKind::JsonBodyUnreadable)
        }
        other => return Err(format!("not an outcome card: {other:?}").into()),
    }
    h.approver().release_unopened(&id).map_err(de)?;
    let env = h.await_(&id, 5000).await;
    assert_eq!((env.status, exit(&env)), (Status::Failed, 6));
    assert_eq!(code(&env), "upstream_unavailable");
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    Ok(())
}

// ---- write half (Task 22) ---------------------------------------------------------------------

const TRANSITION: &str = "jira.issue.transition";
const COMMENT: &str = "jira.comment.add";

async fn payloads_of(h: &Harness, id: &str, t: EventType) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(e, _)| *e == t)
        .map(|(_, p)| p)
        .collect())
}

/// Requests other than `GET` the mock received.
async fn writes_sent(mock: &MockDc) -> usize {
    mock.received()
        .await
        .iter()
        .filter(|r| r.method.as_str() != "GET")
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i23_enrichment_3xx_html_nonjson401_direct() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.redirect(
        "/rest/api/2/issue/R-1/transitions",
        "https://sso.corp.example/login",
    )
    .await;
    mock.html("/rest/api/2/issue/H-1/transitions", 200).await;
    mock.html("/rest/api/2/issue/U-1/transitions", 401).await;
    for (key, reason) in [
        ("R-1", "redirect_3xx"),
        ("H-1", "non_json_2xx"),
        ("U-1", "non_json_401"),
    ] {
        let env = h
            .submit(TRANSITION, json!({ "key": key, "transition": "Done" }))
            .await;
        assert_eq!(env.status, Status::Pending);
        let id = request_id(&env)?;
        assert!(h.settled(&id, 10_000).await, "{key} never settled");
        let env = h.await_(&id, 1000).await;
        assert_eq!((env.status, exit(&env)), (Status::Failed, 6), "{key}");
        assert_eq!(code(&env), "upstream_unavailable");
        assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
        assert!(env.error.as_ref().is_some_and(|e| e.details.is_none()));
        assert!(
            !env.to_json_line().contains("log in"),
            "{key}: body is audit-only"
        );
        assert_eq!(
            types(&h, &id).await?,
            [
                EventType::REQUEST_RECEIVED,
                EventType::PREVIEW_FETCH,
                EventType::REQUEST_FAILED,
                EventType::DELIVERED
            ]
        );
        let fetch = payloads_of(&h, &id, EventType::PREVIEW_FETCH).await?;
        assert_eq!(fetch[0]["class"], reason, "{key}");
        let failed = payloads_of(&h, &id, EventType::REQUEST_FAILED).await?;
        assert_eq!(failed[0]["reason"], reason, "{key}");
        assert!(h.approver().item(&id).is_none());
    }
    // Nothing about the token changed (§7.2: not a token failure).
    let inst = h.instance("jira-main").ok_or("no instance")?;
    assert!(h.credentials().load(&inst.id)?.is_some());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i23_stale_check_503_recheck_failed() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.html("/rest/api/2/myself", 503).await;
    let id = request_id(
        &h.submit(
            COMMENT,
            json!({ "key": "ABC-1", "body": "Done.", "body_format": "wiki" }),
        )
        .await,
    )?;
    let before = h.queued(&id, 10_000).await.ok_or("never queued")?;
    h.approver().approve(&id).map_err(de)?;
    // Back in the queue: a new revision, not opened, approvable again later (§5.4 step 5).
    let mut after = None;
    for _ in 0..500 {
        if let Some(i) = h.approver().item(&id)
            && i.candidate_rev.counter > before.candidate_rev.counter
        {
            after = Some(i);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let after = after.ok_or("never back in the queue")?;
    assert_eq!(
        after.candidate_rev.counter,
        before.candidate_rev.counter + 1
    );
    assert!(!after.opened && after.approvable && after.stale);
    let stale = payloads_of(&h, &id, EventType::WRITE_STALE).await?;
    assert_eq!(
        stale,
        [json!({ "reason": "recheck_failed", "class": "http_503" })]
    );
    let fetch = payloads_of(&h, &id, EventType::PREVIEW_FETCH).await?;
    assert_eq!(fetch.len(), 1);
    assert_eq!(fetch[0]["purpose"], "stale_check");
    assert_eq!(fetch[0]["status"], 503);
    // Nothing was sent, and the agent still sees `pending` (§4.5).
    assert_eq!(writes_sent(mock).await, 0);
    assert_eq!(h.status(&id).await.status, Status::Pending);
    match h.approver().open(&id).map_err(de)?.preview.warnings.first() {
        Some(w) => assert_eq!(
            w.id,
            atlas_duck_preview::warning::WarningId::CouldNotRecheck
        ),
        None => return Err("the re-review does not lead with the re-check".into()),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i23_write_3xx_failed_html200_outcome_unknown() -> TestResult {
    let h = Harness::jira().await?;
    let mock = jira(&h)?;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mock.redirect(
        "/rest/api/2/issue/ABC-1/comment",
        "https://sso.corp.example/login",
    )
    .await;
    mock.html("/rest/api/2/issue/ABC-2/comment", 200).await;
    let mut ids = Vec::new();
    for key in ["ABC-1", "ABC-2"] {
        let id = request_id(
            &h.submit(
                COMMENT,
                json!({ "key": key, "body": "Done.", "body_format": "wiki" }),
            )
            .await,
        )?;
        h.queued(&id, 10_000).await.ok_or("never queued")?;
        h.approver().approve(&id).map_err(de)?;
        ids.push(id);
    }
    // A redirect is never followed and never a success: `failed`, exit 6.
    let env = h.await_(&ids[0], 10_000).await;
    assert_eq!(
        (env.status, exit(&env)),
        (Status::Failed, 6),
        "{}",
        env.to_json_line()
    );
    assert_eq!(code(&env), "upstream_unavailable");
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    assert!(!env.to_json_line().contains("moved"));
    // A 2xx HTML page on a JSON op is not the declared success: `outcome_unknown`.
    let env = h.await_(&ids[1], 10_000).await;
    assert_eq!(
        (env.status, exit(&env)),
        (Status::OutcomeUnknown, 6),
        "{}",
        env.to_json_line()
    );
    assert_eq!(code(&env), "upstream_unknown_outcome");
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    assert_eq!(env.data, Some(json!({ "target": "ABC-2" })));
    assert!(!env.to_json_line().contains("log in"));
    for id in &ids {
        assert!(
            payloads_of(&h, id, EventType::WRITE_EXECUTED)
                .await?
                .is_empty(),
            "never WRITE_EXECUTED"
        );
    }
    let unknown = payloads_of(&h, &ids[1], EventType::WRITE_OUTCOME_UNKNOWN).await?;
    assert_eq!(unknown[0]["reason"], "undeclared_success");
    // The page is in the record (audit-only).
    assert!(unknown[0]["received"].to_string().contains("Please log in"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i24_truncated_json_body_enrichment_failed() -> TestResult {
    let chunk = r#"{"expand":"transitions","transitions":[{"id":"21","#;
    let mut answer = head("Transfer-Encoding: chunked\r\n").into_bytes();
    answer.extend_from_slice(format!("{:x}\r\n{chunk}\r\n", chunk.len()).as_bytes());
    let server = RawHttpServer::serve(vec![RawStep::Send(answer), RawStep::Close]).await?;
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
    let id = request_id(
        &h.submit(TRANSITION, json!({ "key": "ABC-1", "transition": "Done" }))
            .await,
    )?;
    // Gated: the "enrichment failed" hold, `pending` meanwhile, never a direct failure.
    let item = h.queued(&id, 10_000).await.ok_or("never queued")?;
    assert!(!item.approvable);
    assert_eq!(h.status(&id).await.status, Status::Pending);
    match h.approver().open(&id).map_err(de)?.preview.body {
        PreviewBody::EnrichmentError { outcome, .. } => assert_eq!(
            outcome,
            Some(atlas_duck_preview::OutcomeKind::JsonBodyUnreadable)
        ),
        other => return Err(format!("not the enrichment-error card: {other:?}").into()),
    }
    assert!(
        payloads_of(&h, &id, EventType::REQUEST_FAILED)
            .await?
            .is_empty()
    );
    Ok(())
}
