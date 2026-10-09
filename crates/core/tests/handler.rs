#![cfg(feature = "testing")]
//! The core's `RequestHandler` through validation (Task 19): routing (PD-01…PD-03), the
//! `REQUEST_RECEIVED`-then-validate order (§5.2 step 1 / §5.4 step 1), the opacity of the pending
//! envelope (§4.5), `status` (§4.4), `requests list`, `instances.list`, `ops.*`, `doctor`, and
//! audit-before-effect at the start record (§5.1 inv. 1).

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use atlas_duck_audit::EventType;
use atlas_duck_core::ShutdownReason;
use atlas_duck_core::testing::{FaultPlan, Harness, NoProgress};
use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::envelope::Status;
use atlas_duck_ipc::proto::{
    AgentNameSource, AwaitParams, ClientKind, ConnectionMeta, Hello, ListState, MatchParams,
    PeerInfo, ProgressNotification, ProgressSink, SubmitParams,
};
use common::{TestResult, code, detail, exit, json, request_id};
use serde_json::{Value, json};

fn issue_get(key: &str) -> Value {
    json!({ "key": key })
}

fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default()
}

/// Every key of the envelope except the four routing fields is null/false.
fn only_routing_fields(v: &Value) -> bool {
    v.as_object().is_some_and(|o| {
        o.iter().all(|(k, val)| match k.as_str() {
            "request_id" | "op_id" | "instance" | "status" => true,
            "edited" | "redacted" => val == &Value::Bool(false),
            _ => val.is_null(),
        })
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn validation_rejected_logs_received_then_rejected() -> TestResult {
    let h = Harness::jira().await?;
    let env = h.submit("jira.issue.get", json!({})).await;
    assert_eq!(env.status, Status::Failed);
    assert_eq!(code(&env), "validation");
    assert_eq!(exit(&env), 2);
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    assert_eq!(detail(&env, "param"), json!("key"));
    let id = request_id(&env)?;
    assert_eq!(env.op_id.as_deref(), Some("jira.issue.get"));
    assert_eq!(env.instance.as_deref(), Some("jira-main"));
    let events = h.events(&id).await?;
    let types: Vec<EventType> = events.iter().map(|(t, _)| *t).collect();
    assert_eq!(
        types,
        [EventType::REQUEST_RECEIVED, EventType::REQUEST_REJECTED]
    );
    let rejected = &events[1].1;
    assert_eq!(rejected["code"], "validation");
    assert_eq!(rejected["details"]["param"], "key");
    // Rejected requests are never cover-ready (no request is ever sent under this id).
    assert!(!h.engine().committed().request_committed(&id));
    // Answered from the log afterwards: failed, reduced error.
    let st = h.status(&id).await;
    assert_eq!(st.status, Status::Failed);
    assert_eq!(code(&st), "validation");
    assert_eq!(
        st.error.as_ref().map(|e| e.message.as_str()),
        Some("use await for details")
    );
    assert_eq!(detail(&st, "param"), Value::Null);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pd01_no_instance_is_not_configured() -> TestResult {
    let h = Harness::jira().await?;
    let before = h.event_count().await?;
    let env = h
        .submit("confluence.page.get", json!({ "id": "65537" }))
        .await;
    assert_eq!(env.status, Status::Failed);
    assert_eq!(code(&env), "not_configured");
    assert_eq!(exit(&env), 9);
    assert_eq!(detail(&env, "reason"), json!("no_instance"));
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    assert_eq!(
        env.error.as_ref().map(|e| e.message.as_str()),
        Some("no Confluence instance is configured in atlas-duck")
    );
    assert_eq!(env.request_id, None);
    assert_eq!(h.event_count().await?, before, "nothing logged");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pd01_no_instance_at_all_names_the_product() -> TestResult {
    // The window between `GENESIS` and the first added instance (L56).
    let h = Harness::builder()
        .config_text("schema_version = 1\n")
        .start()
        .await?;
    let env = h.submit("jira.issue.get", issue_get("ABC-1")).await;
    assert_eq!(detail(&env, "reason"), json!("no_instance"));
    assert_eq!(
        env.error.as_ref().map(|e| e.message.as_str()),
        Some("no Jira instance is configured in atlas-duck")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pd02_unknown_alias_validation() -> TestResult {
    let h = Harness::both().await?;
    let before = h.event_count().await?;
    let conn = h.default_conn().clone();
    for alias in ["nope", "wiki"] {
        // `wiki` exists but is a Confluence instance.
        let env = h
            .submit_with(&conn, "jira.issue.get", issue_get("ABC-1"), Some(alias))
            .await;
        assert_eq!(code(&env), "validation", "{alias}");
        assert_eq!(exit(&env), 2);
        assert_eq!(detail(&env, "param"), json!("instance"));
        assert_eq!(detail(&env, "value"), json!(alias));
        assert_eq!(env.request_id, None);
    }
    assert_eq!(h.event_count().await?, before, "nothing logged");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pd09_markdown_body_rejected() -> TestResult {
    let h = Harness::jira().await?;
    for params in [
        json!({ "key": "ABC-1", "body": "**hi**" }),
        json!({ "key": "ABC-1", "body": "**hi**", "body_format": "markdown" }),
    ] {
        let env = h.submit("jira.comment.add", params).await;
        assert_eq!(code(&env), "validation");
        assert_eq!(exit(&env), 2);
        assert_eq!(detail(&env, "param"), json!("body_format"));
        assert_eq!(
            detail(&env, "message"),
            json!("markdown conversion is not available in this build")
        );
        let id = request_id(&env)?;
        assert_eq!(
            h.event_types(&id).await?,
            [EventType::REQUEST_RECEIVED, EventType::REQUEST_REJECTED]
        );
    }
    // Wiki passes validation and waits.
    let env = h
        .submit(
            "jira.comment.add",
            json!({ "key": "ABC-1", "body": "hi", "body_format": "wiki" }),
        )
        .await;
    assert_eq!(env.status, Status::Pending);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn not_in_this_build_rejected_internal() -> TestResult {
    let h = Harness::jira().await?;
    let env = h
        .submit(
            "jira.issue.assign",
            json!({ "key": "ABC-1", "assignee": "jdoe" }),
        )
        .await;
    assert_eq!(env.status, Status::Failed);
    assert_eq!(code(&env), "internal");
    assert_eq!(exit(&env), 1);
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    assert_eq!(
        env.error.as_ref().map(|e| e.message.as_str()),
        Some("operation not available in this build")
    );
    let id = request_id(&env)?;
    assert_eq!(
        h.event_types(&id).await?,
        [EventType::REQUEST_RECEIVED, EventType::REQUEST_REJECTED]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cql_rejected_at_the_dry_executor_call() -> TestResult {
    let h = Harness::confluence().await?;
    let env = h
        .submit(
            "confluence.search",
            json!({ "cql": "space=A) OR (type=space" }),
        )
        .await;
    assert_eq!(code(&env), "validation");
    assert_eq!(detail(&env, "param"), json!("cql"));
    let text = env.to_json_line();
    assert!(!text.contains("type=space"), "no echo of the CQL: {text}");
    let id = request_id(&env)?;
    assert_eq!(
        h.event_types(&id).await?,
        [EventType::REQUEST_RECEIVED, EventType::REQUEST_REJECTED]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn valid_read_is_pending_with_four_fields() -> TestResult {
    let h = Harness::jira().await?;
    let env = h.submit("jira.issue.get", issue_get("ABC-1")).await;
    assert_eq!(env.status, Status::Pending);
    assert_eq!(exit(&env), 4);
    let v = json(&env)?;
    assert!(only_routing_fields(&v), "{v}");
    assert!(request_id(&env)?.starts_with("req_"));
    assert_eq!(v["op_id"], "jira.issue.get");
    assert_eq!(v["instance"], "jira-main");
    let id = request_id(&env)?;
    let events = h.events(&id).await?;
    assert_eq!(events.len(), 1);
    let (t, payload) = &events[0];
    assert_eq!(*t, EventType::REQUEST_RECEIVED);
    assert_eq!(payload["params"], issue_get("ABC-1"));
    assert_eq!(payload["connection"]["agent_name"], "test-agent");
    // The request is cover-ready (its start record committed) and nothing was fetched yet.
    assert!(h.engine().committed().request_committed(&id));
    assert!(
        h.mock("jira-main")
            .ok_or("mock")?
            .received()
            .await
            .is_empty()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn search_target_column_is_the_query_tag() -> TestResult {
    let h = Harness::jira().await?;
    let env = h
        .submit("jira.search", json!({ "jql": "project = SECRETPROJ" }))
        .await;
    let id = request_id(&env)?;
    let store = h.store();
    let headers = tokio::task::spawn_blocking(move || store.headers_for_request(&id)).await??;
    let target = headers
        .first()
        .and_then(|h| h.target.clone())
        .ok_or("no target")?;
    assert!(target.starts_with("jql:"), "{target}");
    assert!(!target.contains("SECRETPROJ"));
    // A keyed op shows its key.
    let env = h.submit("jira.issue.get", issue_get("ABC-7")).await;
    let id = request_id(&env)?;
    let store = h.store();
    let headers = tokio::task::spawn_blocking(move || store.headers_for_request(&id)).await??;
    assert_eq!(
        headers.first().and_then(|h| h.target.as_deref()),
        Some("ABC-7")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn status_never_blocks_never_delivers() -> TestResult {
    let h = Harness::jira().await?;
    let id = request_id(&h.submit("jira.issue.get", issue_get("ABC-1")).await)?;
    let st = tokio::time::timeout(Duration::from_secs(2), h.status(&id)).await?;
    assert_eq!(st.status, Status::Pending);
    // (`status` exits 0 for any known id, §4.4: the CLI's override, M4; not the matrix.)
    assert!(only_routing_fields(&json(&st)?));
    assert_eq!(h.event_types(&id).await?, [EventType::REQUEST_RECEIVED]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn status_unknown_id_exit_2() -> TestResult {
    let h = Harness::jira().await?;
    let st = h.status("req_00000000000000000000000000000000").await;
    assert_eq!(st.status, Status::Failed);
    assert_eq!(code(&st), "unknown_request");
    assert_eq!(exit(&st), 2);
    assert_eq!(st.request_id, None);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn await_times_out_pending_then_wakes_on_expiry() -> TestResult {
    let h = Harness::jira().await?;
    let id = request_id(&h.submit("jira.issue.get", issue_get("ABC-1")).await)?;
    // `0`: the current status at once.
    let now = tokio::time::timeout(Duration::from_secs(2), h.await_(&id, 0)).await?;
    assert_eq!(now.status, Status::Pending);
    let short = h.await_(&id, 50).await;
    assert!(only_routing_fields(&json(&short)?));

    struct Rec(std::sync::Mutex<Vec<ProgressNotification>>);
    impl ProgressSink for Rec {
        fn progress(&self, n: ProgressNotification) {
            if let Ok(mut v) = self.0.lock() {
                v.push(n);
            }
        }
    }
    let rec = Rec(std::sync::Mutex::new(Vec::new()));
    let handler = h.handler();
    let conn = h.default_conn().clone();
    let waiting = handler.await_request(
        &conn,
        AwaitParams {
            request_id: id.clone(),
            timeout_ms: Some(10_000),
        },
        &rec,
    );
    let expire = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        h.expire_now(&id).await
    };
    let (env, expired) = tokio::join!(waiting, expire);
    assert!(expired);
    assert_eq!(env.status, Status::Expired);
    assert_eq!(exit(&env), 7);
    assert_eq!(code(&env), "expired");
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    let seen: Vec<Status> = rec
        .0
        .lock()
        .map(|v| v.iter().map(|n| n.status).collect())
        .unwrap_or_default();
    assert_eq!(seen, [Status::Expired]);
    assert_eq!(
        h.event_types(&id).await?,
        [EventType::REQUEST_RECEIVED, EventType::EXPIRED]
    );
    // Gone from memory, answered from the log; the id is no longer cover-ready.
    assert!(h.engine().entry(&id).is_none());
    assert!(!h.engine().committed().request_committed(&id));
    let st = h.status(&id).await;
    assert_eq!(st.status, Status::Expired);
    assert_eq!(code(&st), "expired");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_pending_is_cancelled_by_client() -> TestResult {
    let h = Harness::jira().await?;
    let id = request_id(&h.submit("jira.issue.get", issue_get("ABC-1")).await)?;
    let env = h.handler().cancel(&id).await;
    assert_eq!(env.status, Status::Cancelled);
    assert_eq!(exit(&env), 7);
    assert_eq!(detail(&env, "reason"), json!("by_client"));
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(false));
    assert_eq!(env.data, None);
    assert_eq!(
        h.event_types(&id).await?,
        [EventType::REQUEST_RECEIVED, EventType::CANCELLED]
    );
    // Afterwards it returns the current status (§4.4).
    let again = h.handler().cancel(&id).await;
    assert_eq!(again.status, Status::Cancelled);
    assert_eq!(h.event_types(&id).await?.len(), 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_list_metadata_only() -> TestResult {
    let h = Harness::jira().await?;
    let pending = request_id(&h.submit("jira.issue.get", issue_get("ABC-1")).await)?;
    let rejected = request_id(&h.submit("jira.issue.get", json!({ "key": "abc" })).await)?;
    let env = h.handler().requests_list(None, None, None).await;
    assert_eq!(env.status, Status::Succeeded);
    let rows = json(&env)?["data"]["requests"].clone();
    let rows = rows.as_array().ok_or("rows")?;
    assert_eq!(rows.len(), 2);
    let want: BTreeSet<String> = [
        "request_id",
        "op_id",
        "instance",
        "target_display",
        "params_sha256",
        "status",
        "submitted_at",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    for r in rows {
        assert_eq!(keys(r), want, "{r}");
        assert_eq!(r["instance"], "jira-main");
        assert_eq!(r["params_sha256"].as_str().map(str::len), Some(64));
    }
    let by_id = |id: &str| rows.iter().find(|r| r["request_id"] == id).cloned();
    let p = by_id(&pending).ok_or("pending row")?;
    assert_eq!(p["status"], "pending");
    assert_eq!(p["target_display"], "ABC-1");
    let r = by_id(&rejected).ok_or("rejected row")?;
    assert_eq!(r["status"], "failed");
    assert_eq!(r["target_display"], "abc");

    let pending_only = h
        .handler()
        .requests_list(None, Some(ListState::Pending), None)
        .await;
    let rows = json(&pending_only)?["data"]["requests"].clone();
    assert_eq!(rows.as_array().map(Vec::len), Some(1));
    let recent = h
        .handler()
        .requests_list(None, Some(ListState::Recent), None)
        .await;
    let rows = json(&recent)?["data"]["requests"].clone();
    assert_eq!(rows[0]["request_id"], rejected.as_str());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_list_filters_by_normalized_agent() -> TestResult {
    let h = Harness::jira().await?;
    let other = h.conn("other\u{200B}-agent").await?;
    h.submit("jira.issue.get", issue_get("ABC-1")).await;
    h.submit_with(&other, "jira.issue.get", issue_get("ABC-2"), None)
        .await;
    let env = h
        .handler()
        .requests_list(Some("other-agent"), None, None)
        .await;
    let rows = json(&env)?["data"]["requests"].clone();
    let rows = rows.as_array().ok_or("rows")?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["target_display"], "ABC-2");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_list_match_params() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .jira("jira-two")
        .start()
        .await?;
    let params = json!({ "jql": "project = ABC", "max": 10 });
    let id = request_id(&h.submit("jira.search", params).await)?;
    // A terminal one too (answered from the log).
    let rejected = request_id(
        &h.submit("jira.search", json!({ "jql": "x", "max": 0 }))
            .await,
    )?;
    let list = |m: MatchParams| {
        let handler = h.handler();
        async move { handler.requests_list(None, None, Some(m)).await }
    };
    // Same params, other key order, default instance → match.
    let reordered: Value = serde_json::from_str(r#"{"max":10,"jql":"project = ABC"}"#)?;
    let env = list(MatchParams {
        op_id: "jira.search".into(),
        params: reordered.clone(),
        instance: None,
    })
    .await;
    let rows = json(&env)?["data"]["requests"].clone();
    assert_eq!(rows.as_array().map(Vec::len), Some(1));
    assert_eq!(rows[0]["request_id"], id.as_str());
    // Named default instance: same hash.
    let env = list(MatchParams {
        op_id: "jira.search".into(),
        params: reordered.clone(),
        instance: Some("jira-main".into()),
    })
    .await;
    assert_eq!(
        json(&env)?["data"]["requests"].as_array().map(Vec::len),
        Some(1)
    );
    // Other instance → no match.
    let env = list(MatchParams {
        op_id: "jira.search".into(),
        params: reordered,
        instance: Some("jira-two".into()),
    })
    .await;
    assert_eq!(
        json(&env)?["data"]["requests"].as_array().map(Vec::len),
        Some(0)
    );
    // The rejected (terminal) request matches by its own params.
    let env = list(MatchParams {
        op_id: "jira.search".into(),
        params: json!({ "jql": "x", "max": 0 }),
        instance: None,
    })
    .await;
    let rows = json(&env)?["data"]["requests"].clone();
    assert_eq!(rows[0]["request_id"], rejected.as_str());
    // An integer JCS cannot represent matches nothing.
    let env = list(MatchParams {
        op_id: "jira.search".into(),
        params: json!({ "jql": "x", "max": 9_007_199_254_740_993_u64 }),
        instance: None,
    })
    .await;
    assert_eq!(env.status, Status::Succeeded);
    assert_eq!(
        json(&env)?["data"]["requests"].as_array().map(Vec::len),
        Some(0)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn instances_list_no_urls() -> TestResult {
    let h = Harness::both().await?;
    let env = h.handler().instances_list().await;
    assert_eq!(env.status, Status::Succeeded);
    let text = env.to_json_line();
    assert!(
        !text.contains("https://") && !text.contains("http://"),
        "{text}"
    );
    assert!(
        !text.contains("127.0.0.1") && !text.contains("jdoe"),
        "{text}"
    );
    let rows = json(&env)?["data"]["instances"].clone();
    assert_eq!(
        rows,
        json!([
            {"alias": "jira-main", "product": "jira", "is_default": true, "state": "ok"},
            {"alias": "wiki", "product": "confluence", "is_default": true, "state": "ok"},
        ])
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ops_describe_instance_available() -> TestResult {
    let h = Harness::both().await?;
    let env = h
        .handler()
        .ops_describe("jira.issue.get", Some("jira-main"))
        .await;
    assert_eq!(env.status, Status::Succeeded);
    let d = json(&env)?["data"].clone();
    assert_eq!(d["available"], true);
    assert_eq!(d["limits_source"], "effective");
    assert_eq!(d["op_id"], "jira.issue.get");
    // Without an instance: the local answer.
    let local = json(&h.handler().ops_describe("jira.issue.get", None).await)?;
    assert_eq!(local["data"]["limits_source"], "default");
    assert!(local["data"].get("available").is_none());
    // Unknown alias, other product, unknown op.
    let env = h
        .handler()
        .ops_describe("jira.issue.get", Some("wiki"))
        .await;
    assert_eq!(code(&env), "validation");
    let env = h.handler().ops_describe("nope.op", Some("wiki")).await;
    assert_eq!(code(&env), "usage");
    // `ops.list` for an instance: its product's ops, each available.
    let list = json(&h.handler().ops_list(Some("wiki")).await)?;
    let ops = list["data"]["ops"].as_array().ok_or("ops")?;
    assert_eq!(ops.len(), 18);
    assert!(ops.iter().all(|o| {
        o["available"] == true
            && o["op_id"]
                .as_str()
                .is_some_and(|s| s.starts_with("confluence."))
    }));
    let all = json(&h.handler().ops_list(None).await)?;
    assert_eq!(all["data"]["ops"].as_array().map(Vec::len), Some(46));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audit_failure_on_received_returns_audit_failure() -> TestResult {
    let plan = FaultPlan::new();
    plan.fail_nth(EventType::REQUEST_RECEIVED, 1);
    plan.fail_nth(EventType::REQUEST_RECEIVED, 2);
    let h = Harness::builder()
        .jira("jira-main")
        .faults(plan.clone())
        .start()
        .await?;
    let before = h.event_count().await?;
    let read = h.submit("jira.issue.get", issue_get("ABC-1")).await;
    assert_eq!(read.status, Status::Failed);
    assert_eq!(code(&read), "audit_failure");
    assert_eq!(exit(&read), 1);
    assert_eq!(read.error.as_ref().map(|e| e.retryable), Some(true));
    assert_eq!(read.request_id, None);
    let write = h
        .submit(
            "jira.comment.add",
            json!({ "key": "ABC-1", "body": "hi", "body_format": "wiki" }),
        )
        .await;
    assert_eq!(code(&write), "audit_failure");
    assert_eq!(write.error.as_ref().map(|e| e.retryable), Some(false));
    assert_eq!(write.request_id, None);
    assert_eq!(h.event_count().await?, before, "nothing committed");
    assert!(h.engine().pending_entries().is_empty(), "nothing queued");
    assert!(
        h.mock("jira-main")
            .ok_or("mock")?
            .received()
            .await
            .is_empty()
    );
    // The third attempt goes through.
    let ok = h.submit("jira.issue.get", issue_get("ABC-1")).await;
    assert_eq!(ok.status, Status::Pending);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audit_failure_on_rejected_keeps_failed_in_memory() -> TestResult {
    let plan = FaultPlan::new();
    plan.fail_nth(EventType::REQUEST_REJECTED, 1);
    let h = Harness::builder()
        .jira("jira-main")
        .faults(plan)
        .start()
        .await?;
    let env = h.submit("jira.issue.get", json!({})).await;
    assert_eq!(code(&env), "audit_failure");
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    let id = request_id(&env)?;
    assert_eq!(h.event_types(&id).await?, [EventType::REQUEST_RECEIVED]);
    assert!(!h.engine().committed().request_committed(&id));
    let st = h.status(&id).await;
    assert_eq!(st.status, Status::Failed);
    assert_eq!(code(&st), "audit_failure");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn submit_without_hello_is_protocol_error() -> TestResult {
    let h = Harness::jira().await?;
    let before = h.event_count().await?;
    let conn = ConnectionMeta {
        connection_id: "never-said-hello".into(),
        peer: PeerInfo::default(),
    };
    let env = h
        .submit_with(&conn, "jira.issue.get", issue_get("ABC-1"), None)
        .await;
    assert_eq!(code(&env), "protocol_error");
    assert_eq!(exit(&env), 1);
    // A refused hello stores no session either.
    let bad = Hello {
        build_id: "0.0.0+000000000000".into(),
        client_kind: ClientKind::Cli,
        agent_name: None,
        agent_name_source: AgentNameSource::None,
        cwd_basename: "w".into(),
    };
    let reply = h.handler().hello(&conn, bad).await;
    assert!(reply.is_err());
    let env = h
        .submit_with(&conn, "jira.issue.get", issue_get("ABC-1"), None)
        .await;
    assert_eq!(code(&env), "protocol_error");
    assert_eq!(h.event_count().await?, before);
    let good = Hello {
        build_id: BUILD_ID.into(),
        client_kind: ClientKind::Cli,
        agent_name: None,
        agent_name_source: AgentNameSource::None,
        cwd_basename: "w".into(),
    };
    assert!(h.handler().hello(&conn, good).await.is_ok());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_op_and_script_run_are_usage_nothing_logged() -> TestResult {
    let h = Harness::jira().await?;
    let before = h.event_count().await?;
    for op in ["jira.nope", "script.run"] {
        let env = h.submit(op, json!({})).await;
        assert_eq!(code(&env), "usage", "{op}");
        assert_eq!(exit(&env), 2);
        assert_eq!(detail(&env, "op_id"), json!(op));
        assert_eq!(env.request_id, None);
    }
    assert_eq!(h.event_count().await?, before);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pd27_integer_out_of_range_is_validation_nothing_logged() -> TestResult {
    let h = Harness::jira().await?;
    let before = h.event_count().await?;
    let env = h
        .submit(
            "jira.search",
            json!({ "jql": "x", "max": 9_007_199_254_740_993_u64 }),
        )
        .await;
    assert_eq!(code(&env), "validation");
    assert_eq!(exit(&env), 2);
    assert_eq!(detail(&env, "message"), json!("integer outside ±(2^53−1)"));
    assert_eq!(env.request_id, None);
    assert_eq!(h.event_count().await?, before);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutting_down_refuses_submit_other_methods_answer() -> TestResult {
    let h = Harness::jira().await?;
    let id = request_id(&h.submit("jira.issue.get", issue_get("ABC-1")).await)?;
    h.core().shutdown(ShutdownReason::Quit).await;
    let env = h.submit("jira.issue.get", issue_get("ABC-2")).await;
    assert_eq!(code(&env), "unreachable");
    assert_eq!(exit(&env), 5);
    assert_eq!(detail(&env, "reason"), json!("app_shutting_down"));
    assert_eq!(env.error.as_ref().map(|e| e.retryable), Some(true));
    let script = h
        .handler()
        .submit_script(
            h.default_conn(),
            SubmitParams {
                op_id: "script.run".into(),
                params: json!({}),
                instance: None,
                reason: None,
            },
        )
        .await;
    assert_eq!(detail(&script, "reason"), json!("app_shutting_down"));
    assert_eq!(h.status(&id).await.status, Status::Pending);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn config_unreadable_answers_not_configured() -> TestResult {
    let h = Harness::builder()
        .jira("jira-main")
        .config_text("schema_version = 1\n[[instances]]\nalias = \"bad alias\"\nproduct = \"jira\"\nbase_url = \"https://x\"\n")
        .start()
        .await?;
    let env = h.submit("jira.issue.get", issue_get("ABC-1")).await;
    assert_eq!(code(&env), "not_configured");
    assert_eq!(exit(&env), 9);
    assert_eq!(detail(&env, "reason"), json!("config_unreadable"));
    let list = h.handler().instances_list().await;
    assert_eq!(detail(&list, "reason"), json!("config_unreadable"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hand_written_instance_gets_an_id_and_routes() -> TestResult {
    // PD-04: a `[[instances]]` table without `id` gets one written back at start.
    let h = Harness::builder()
        .jira("jira-main")
        .omit_ids()
        .start()
        .await?;
    let env = h.submit("jira.issue.get", issue_get("ABC-1")).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    let store = h.store();
    let headers = tokio::task::spawn_blocking(move || store.headers_for_request(&id)).await??;
    let ins = headers
        .first()
        .and_then(|h| h.instance_id.clone())
        .ok_or("no instance id")?;
    assert!(ins.starts_with("ins_") && ins.len() == 36, "{ins}");
    assert_ne!(
        Some(ins.as_str()),
        h.instance("jira-main").map(|i| i.id.as_str())
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doctor_reports_per_alias_without_urls() -> TestResult {
    let h = Harness::both().await?;
    let env = h.handler().doctor().await;
    assert_eq!(env.status, Status::Succeeded);
    let text = env.to_json_line();
    assert!(!text.contains("http") && !text.contains("jdoe"), "{text}");
    let d = json(&env)?["data"].clone();
    assert_eq!(d["pac_configured"], false);
    let jira = &d["instances"]["jira-main"];
    let want: BTreeSet<String> = [
        "configured",
        "config_error",
        "reachable",
        "needs_token",
        "locked",
        "tls_error",
        "proxy_error",
        "identity_header",
        "version_supported",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    assert_eq!(keys(jira), want);
    assert_eq!(jira["configured"], true);
    assert_eq!(jira["config_error"], Value::Null);
    assert_eq!(jira["needs_token"], false);
    assert_eq!(jira["locked"], Value::Null, "unknown until Task 25");
    assert!(d["instances"]["wiki"].is_object());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn await_unknown_and_restarted_ids_from_the_log() -> TestResult {
    let h = Harness::jira().await?;
    let env = h
        .handler()
        .await_request(
            h.default_conn(),
            AwaitParams {
                request_id: "req_ffffffffffffffffffffffffffffffff".into(),
                timeout_ms: Some(10),
            },
            &NoProgress,
        )
        .await;
    assert_eq!(code(&env), "unknown_request");
    // A rejected request awaited later: its full error from the log.
    let id = request_id(&h.submit("jira.issue.get", json!({})).await)?;
    let env = h.await_(&id, 10).await;
    assert_eq!(env.status, Status::Failed);
    assert_eq!(code(&env), "validation");
    assert_eq!(detail(&env, "param"), json!("key"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_request_known_only_to_the_log_is_pending_with_four_fields() -> TestResult {
    use atlas_duck_core::payloads::{EventCtx, request_received};
    // E.g. a request of an earlier run before crash reconciliation (Task 28) ended it.
    let h = Harness::jira().await?;
    let instance_id = h.instance("jira-main").ok_or("instance")?.id.clone();
    let id = "req_0123456789abcdef0123456789abcdef".to_owned();
    let ctx = EventCtx {
        request_id: Some(id.clone()),
        op_id: Some("jira.issue.get".into()),
        op_class: Some("read".into()),
        instance_id: Some(instance_id),
        target: Some("ABC-1".into()),
        actor: Default::default(),
    };
    let hello = Hello {
        build_id: BUILD_ID.into(),
        client_kind: ClientKind::Cli,
        agent_name: None,
        agent_name_source: AgentNameSource::None,
        cwd_basename: "w".into(),
    };
    let ev = request_received(
        &ctx,
        &issue_get("ABC-1"),
        &[0; 32],
        &hello,
        h.default_conn(),
        None,
    );
    let store = h.store();
    tokio::task::spawn_blocking(move || store.append(ev)).await??;
    for env in [h.status(&id).await, h.await_(&id, 10).await] {
        assert_eq!(env.status, Status::Pending);
        let v = json(&env)?;
        assert!(only_routing_fields(&v), "{v}");
        assert_eq!(v["instance"], "jira-main");
        assert_eq!(v["op_id"], "jira.issue.get");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dry_call_enrichment_required_passes_and_op_checks_reject() -> TestResult {
    let h = Harness::both().await?;
    // Writes that need enrichment before they can render: `EnrichmentRequired` passes.
    for (op, params) in [
        (
            "jira.issue.create",
            json!({ "project": "ABC", "issuetype": "Bug", "summary": "s" }),
        ),
        (
            "jira.issue.transition",
            json!({ "key": "ABC-1", "transition": "Done" }),
        ),
        (
            "confluence.page.update",
            json!({ "id": "65537", "base_version": 5, "body": "<p>x</p>", "body_format": "storage" }),
        ),
    ] {
        let env = h.submit(op, params).await;
        assert_eq!(env.status, Status::Pending, "{op}: {}", env.to_json_line());
        assert_eq!(
            h.event_types(&request_id(&env)?).await?,
            [EventType::REQUEST_RECEIVED]
        );
    }
    // An op-owned static check (the executor as validator hook): edit with nothing to edit.
    let env = h
        .submit(
            "jira.issue.edit",
            json!({ "key": "ABC-1", "expected": { "summary": "Old" } }),
        )
        .await;
    assert_eq!(code(&env), "validation", "{}", env.to_json_line());
    assert_eq!(exit(&env), 2);
    assert_eq!(
        h.event_types(&request_id(&env)?).await?,
        [EventType::REQUEST_RECEIVED, EventType::REQUEST_REJECTED]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_of_a_decided_request_says_no_more_than_status() -> TestResult {
    let h = Harness::jira().await?;
    let id = request_id(&h.submit("jira.issue.get", json!({})).await)?;
    let env = h.handler().cancel(&id).await;
    assert_eq!(env.status, Status::Failed);
    assert_eq!(code(&env), "validation");
    assert_eq!(
        env.error.as_ref().map(|e| e.message.as_str()),
        Some("use await for details")
    );
    assert_eq!(env.error.as_ref().and_then(|e| e.details.clone()), None);
    assert_eq!(env.data, None);
    assert_eq!(env.to_json_line(), h.status(&id).await.to_json_line());
    // A cancelled request cancelled again: the status form, no `details`.
    let id = request_id(&h.submit("jira.issue.get", issue_get("ABC-1")).await)?;
    let first = h.handler().cancel(&id).await;
    assert_eq!(detail(&first, "reason"), json!("by_client"));
    let again = h.handler().cancel(&id).await;
    assert_eq!(again.status, Status::Cancelled);
    assert_eq!(again.error.as_ref().and_then(|e| e.details.clone()), None);
    assert_eq!(h.event_types(&id).await?.len(), 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_terminal_events_commit_one_terminal_record() -> TestResult {
    let h = Harness::jira().await?;
    let terminal = |t: &EventType| matches!(t, EventType::CANCELLED | EventType::EXPIRED);
    for round in 0..10 {
        // Two cancels.
        let id = request_id(&h.submit("jira.issue.get", issue_get("ABC-1")).await)?;
        let handler = h.handler();
        let (a, b) = tokio::join!(handler.cancel(&id), handler.cancel(&id));
        assert_eq!(
            (a.status, b.status),
            (Status::Cancelled, Status::Cancelled),
            "{round}"
        );
        let types = h.event_types(&id).await?;
        assert_eq!(types.iter().filter(|t| terminal(t)).count(), 1, "{types:?}");
        // Exactly one of them is the cancel that happened.
        let by_client = [&a, &b]
            .iter()
            .filter(|e| detail(e, "reason") == json!("by_client"))
            .count();
        assert_eq!(by_client, 1);
        assert!(h.engine().entry(&id).is_none(), "memory follows the log");
        // A cancel against an expiry.
        let id = request_id(&h.submit("jira.issue.get", issue_get("ABC-2")).await)?;
        let (c, expired) = tokio::join!(handler.cancel(&id), h.expire_now(&id));
        let types = h.event_types(&id).await?;
        assert_eq!(types.iter().filter(|t| terminal(t)).count(), 1, "{types:?}");
        let logged = if types.contains(&EventType::CANCELLED) {
            Status::Cancelled
        } else {
            Status::Expired
        };
        assert_eq!(h.status(&id).await.status, logged);
        assert_eq!(c.status, logged);
        assert_eq!(expired, logged == Status::Expired);
    }
    assert_eq!(
        h.engine().admission().pending_total(),
        0,
        "every place given back once"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn submit_dropped_after_the_commit_still_lands() -> TestResult {
    use atlas_duck_core::{Pause, TestHooks};
    let pause = Pause::new();
    let h = Harness::builder()
        .jira("jira-main")
        .hooks(TestHooks {
            pause_after_received: Some(pause.clone()),
            ..TestHooks::none()
        })
        .start()
        .await?;
    let before = h.event_count().await?;
    {
        let submit = h.submit("jira.issue.get", issue_get("ABC-1"));
        tokio::select! {
            _ = submit => return Err("submit finished while paused".into()),
            _ = pause.reached.notified() => {}
        }
        // `submit` is dropped here, right after `REQUEST_RECEIVED` committed.
    }
    assert_eq!(h.event_count().await?, before + 1);
    pause.release.notify_one();
    let mut entries = Vec::new();
    for _ in 0..200 {
        entries = h.engine().pending_entries();
        if !entries.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let entry = entries
        .first()
        .ok_or("the committed request never reached memory")?;
    assert_eq!(entry.agent_status(), Status::Pending);
    let id = entry.head.request_id.clone();
    assert!(h.engine().committed().request_committed(&id));
    assert_eq!(h.status(&id).await.status, Status::Pending);
    // A dropped submit whose request is rejected still logs the rejection.
    let submit = h.submit("jira.issue.get", json!({}));
    tokio::select! {
        _ = submit => return Err("submit finished while paused".into()),
        _ = pause.reached.notified() => {}
    }
    pause.release.notify_one();
    for _ in 0..200 {
        if h.event_count().await? == before + 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        h.event_count().await?,
        before + 3,
        "REQUEST_RECEIVED + REQUEST_REJECTED"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn await_bound_is_capped_and_the_reason_excerpt_short() -> TestResult {
    let h = Harness::jira().await?;
    let reason = "r".repeat(300);
    let env = h
        .handler()
        .submit(
            h.default_conn(),
            SubmitParams {
                op_id: "jira.issue.get".into(),
                params: issue_get("ABC-1"),
                instance: None,
                reason: Some(reason),
            },
        )
        .await;
    let id = request_id(&env)?;
    let entry = h.engine().entry(&id).ok_or("entry")?;
    let excerpt = entry.reason_excerpt.clone().ok_or("excerpt")?;
    assert_eq!(
        excerpt.chars().count(),
        61,
        "60 characters and the ellipsis"
    );
    // An absurd bound does not overflow; the wait still ends with the request.
    let handler = h.handler();
    let conn = h.default_conn().clone();
    let waiting = handler.await_request(
        &conn,
        AwaitParams {
            request_id: id.clone(),
            timeout_ms: Some(u64::MAX),
        },
        &NoProgress,
    );
    let expire = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        h.expire_now(&id).await
    };
    let (env, _) = tokio::join!(waiting, expire);
    assert_eq!(env.status, Status::Expired);
    Ok(())
}
