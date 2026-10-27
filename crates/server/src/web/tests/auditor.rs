//! M14 T17 (SM-6.4, SM-6.5, SM-2.5; PD-257, PD-258): auditors read any user's chain through
//! `/api/auditor/*`, every read is recorded first in the auditor's chain and the anchor op-log,
//! and the target's chain gains nothing (no core is started for a read).

use super::*;
use crate::clock::Clock as _;
use crate::runtime::UserCtx;

const CANARY: &str = "alice-auditor-canary";

impl H {
    async fn auditor_get(&self, (c, _): &(String, String), path: &str) -> (StatusCode, Value) {
        let res = self
            .send(
                Request::builder()
                    .uri(path)
                    .header(header::COOKIE, format!("__Host-atlas_duck_session={c}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        let s = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 22)
            .await
            .unwrap();
        (s, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn auditor_read(
        &self,
        (c, t): &(String, String),
        target: &str,
        command: &str,
        body: Value,
    ) -> (StatusCode, String) {
        let res = self
            .send(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/auditor/users/{target}/{command}"))
                    .header(header::COOKIE, format!("__Host-atlas_duck_session={c}"))
                    .header("x-csrf-token", t)
                    .header(header::ORIGIN, ORIGIN)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await;
        let s = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 22)
            .await
            .unwrap();
        (s, String::from_utf8_lossy(&bytes).into_owned())
    }

    async fn rt_of(&self, name: &str) -> std::sync::Arc<crate::runtime::UserRuntime> {
        self.registry
            .runtime(&UserCtx::from_authenticated(&user_id_for(name)))
            .await
            .unwrap()
    }

    /// `(kind, payload)` of every record of `name`'s chain (through the auditor-free path).
    async fn kinds_of(&self, name: &str) -> Vec<(atlas_duck_audit::EventType, Value)> {
        let rt = self.rt_of(name).await;
        self.chain_kinds(&rt)
    }
}

/// Alice's store with a canary record, then every runtime closed (her chain is cold).
async fn cold_alice(h: &H) -> u64 {
    h.session("alice", PW_CANARY).await;
    let rt = h.rt_of("alice").await;
    rt.append_server_record(
        atlas_duck_audit::EventType::API_KEY_CREATED,
        crate::audit_kinds::api_key_created("key_c", CANARY, "abcd1234", &["read"], "t"),
    )
    .await
    .unwrap();
    let canary = rt.head().1;
    drop(rt);
    // Closing appends APP_STOP; the canary record stays where it was.
    h.registry.close_all().await;
    canary
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_auditor_reads_a_cold_chain_and_every_read_is_recorded_first() {
    let h = H::new();
    let audrey = h.session("vera", "pw-vera").await;
    let head = cold_alice(&h).await;
    let alice = user_id_for("alice");
    let (s, body) = h
        .auditor_read(&audrey, &alice, "audit_query", json!({"filter": {}}))
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let page: Value = serde_json::from_str(&body).unwrap();
    assert!(
        page["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["event_type"] == "API_KEY_CREATED")
    );
    // The canary payload, through the payload read.
    let (s, body) = h
        .auditor_read(&audrey, &alice, "audit_payload", json!({"seq": head}))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains(CANARY));
    let (s, _) = h
        .auditor_read(&audrey, &alice, "audit_status", json!({}))
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = h
        .auditor_read(
            &audrey,
            &alice,
            "audit_trail",
            json!({"request_id": "req_0123456789abcdefghij"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    // A view without a core was used: alice's chain did not move (no APP_START).
    assert!(h.registry.has_audit_view(&alice));
    let view = h.registry.audit_view(&alice).await.unwrap();
    // The close appended APP_STOP after the canary; nothing after that.
    assert_eq!(
        view.head().0,
        head + 1,
        "an audit read appended to the target's chain"
    );
    // Audrey's chain holds one AUDITOR_READ per read, naming alice and the action.
    let mine = h.kinds_of("vera").await;
    // chain_kinds lists newest first.
    let reads: Vec<&Value> = mine
        .iter()
        .rev()
        .filter(|(k, _)| *k == atlas_duck_audit::EventType::AUDITOR_READ)
        .map(|(_, p)| p)
        .collect();
    let actions: Vec<&str> = reads
        .iter()
        .map(|p| p["action"].as_str().unwrap())
        .collect();
    assert_eq!(actions, ["query", "payload", "query", "trail"], "{reads:?}");
    assert!(reads.iter().all(|p| p["target_user_id"] == alice.as_str()));
    assert_eq!(reads[1]["seq"], head);
    assert_eq!(reads[3]["request_id"], "req_0123456789abcdefghij");
    // The filter text never: only the summary.
    assert!(reads[0]["range"].get("event_types").is_some());
    // The anchor op-log has a row per read too.
    let rows: Vec<Value> = h
        .store
        .anchor_all()
        .unwrap()
        .into_iter()
        .filter(|r| r.kind == "AUDITOR_READ")
        .map(|r| serde_json::from_slice(&r.body_jcs).unwrap())
        .collect();
    assert_eq!(rows.len(), 4);
    assert!(
        rows.iter()
            .all(|r| r["auditor_user_id"] == user_id_for("vera").as_str()
                && r["target_user_id"] == alice.as_str())
    );
    // Five minutes idle: the view closes.
    h.clock.advance(crate::runtime::VIEW_IDLE_SECS);
    assert_eq!(h.registry.close_idle_views().await, 1);
    assert!(!h.registry.has_audit_view(&alice));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_runtimes_share_and_adopt_the_store() {
    let h = H::new();
    let audrey = h.session("vera", "pw-vera").await;
    cold_alice(&h).await;
    let alice = user_id_for("alice");
    // A view is held, then alice's runtime opens: it adopts the store (no lock error).
    let (s, _) = h
        .auditor_read(&audrey, &alice, "audit_status", json!({}))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(h.registry.has_audit_view(&alice));
    let rt = h.rt_of("alice").await;
    assert!(
        !h.registry.has_audit_view(&alice),
        "the runtime adopted the view"
    );
    rt.append_server_record(atlas_duck_audit::EventType::LOGIN, Default::default())
        .await
        .unwrap();
    // With the runtime open the auditor reads through its store.
    let (s, body) = h
        .auditor_read(&audrey, &alice, "audit_query", json!({"filter": {}}))
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert!(!h.registry.has_audit_view(&alice));
    assert!(body.contains("LOGIN"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refusals_unknown_users_and_unrecorded_reads() {
    let h = H::new();
    let audrey = h.session("vera", "pw-vera").await;
    let alice_s = h.session("alice", PW_CANARY).await;
    let bob_s = h.session("bob", "pw-bob").await; // an admin
    cold_alice(&h).await;
    let alice = user_id_for("alice");
    // Users and admins have no auditor route.
    for who in [&alice_s, &bob_s] {
        let (s, v) = h.auditor_get(who, "/api/auditor/users").await;
        assert_eq!(
            (s, v["error"]["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("auth/role_required"))
        );
        let (s, _) = h
            .auditor_read(who, &alice, "audit_query", json!({"filter": {}}))
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
    }
    // Unknown and malformed targets.
    for target in ["0".repeat(32), "nope".into(), "A".repeat(32)] {
        let (s, body) = h
            .auditor_read(&audrey, &target, "audit_status", json!({}))
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{target}: {body}");
        assert!(body.contains("audit/user_unknown"));
    }
    // An unknown command and a bad body are refused before anything is recorded.
    let (s, _) = h
        .auditor_read(&audrey, &alice, "queue_list", json!({}))
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = h
        .auditor_read(&audrey, &alice, "audit_payload", json!({"seq": "x"}))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // The auditor's chain cannot take the record: 503 and no target data.
    let rt = h.rt_of("vera").await;
    rt.fail_next_append
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (s, body) = h
        .auditor_read(&audrey, &alice, "audit_payload", json!({"seq": 5}))
        .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains("audit/read_not_recorded"));
    assert!(!body.contains(CANARY) && !body.contains("srcdoc"));
    let reads = h
        .kinds_of("vera")
        .await
        .into_iter()
        .filter(|(k, _)| *k == atlas_duck_audit::EventType::AUDITOR_READ)
        .count();
    assert_eq!(reads, 0, "only refused requests so far");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_user_list_is_recorded_and_carries_no_secret() {
    let h = H::new();
    let audrey = h.session("vera", "pw-vera").await;
    h.session("alice", PW_CANARY).await;
    let (s, v) = h.auditor_get(&audrey, "/api/auditor/users").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let rows = v.as_array().unwrap();
    let alice = rows.iter().find(|r| r["username"] == "alice").unwrap();
    assert_eq!(alice["user_id"], user_id_for("alice").as_str());
    assert_eq!(alice["state"], "active");
    let text = v.to_string();
    assert!(!text.contains("data_key") && !text.contains("wrapped"));
    let reads: Vec<Value> = h
        .kinds_of("vera")
        .await
        .into_iter()
        .filter(|(k, _)| *k == atlas_duck_audit::EventType::AUDITOR_READ)
        .map(|(_, p)| p)
        .collect();
    assert_eq!(reads, [json!({"action": "list_users"})]);
    let _ = h.clock.now();
}
