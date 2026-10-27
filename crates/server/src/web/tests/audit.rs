//! M14 T16 (SM-6.4 first sentence, PD-251): every user reads their own chain through the desktop's
//! four audit commands; nothing reaches another user's store, and a bearer cannot read at all.

use super::*;
use crate::runtime::UserCtx;

async fn query(h: &H, (c, t): &(String, String)) -> (StatusCode, Value) {
    let res = cmd(h, c, t, "audit_query", json!({"filter": {}})).await;
    let s = res.status();
    (s, json_body(res).await)
}

/// Every chain id of a page.
fn chains(page: &Value) -> std::collections::BTreeSet<String> {
    page["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["chain_id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_user_reads_only_their_own_chain() {
    let h = H::new();
    let alice = h.session("alice", PW_CANARY).await;
    let bob = h.session("bob", "pw-bob").await;
    // A record only alice's chain holds: an API key whose name is a canary.
    let rt_a = h
        .registry
        .runtime(&UserCtx::from_authenticated(&user_id_for("alice")))
        .await
        .unwrap();
    rt_a.append_server_record(
        atlas_duck_audit::EventType::API_KEY_CREATED,
        crate::audit_kinds::api_key_created(
            "key_x",
            "alice-canary-key",
            "abcd1234",
            &["read"],
            "t",
        ),
    )
    .await
    .unwrap();
    let (chain_a, head_a, _) = rt_a.head();
    let (s, pa) = query(&h, &alice).await;
    assert_eq!(s, StatusCode::OK, "{pa}");
    assert_eq!(chains(&pa), [chain_a.clone()].into());
    let (s, pb) = query(&h, &bob).await;
    assert_eq!(s, StatusCode::OK, "{pb}");
    assert!(!chains(&pb).contains(&chain_a), "bob sees alice's chain");
    // Alice's canary payload is readable by alice at its seq ...
    let (c, t) = &alice;
    let res = cmd(&h, c, t, "audit_payload", json!({"seq": head_a})).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        json_body(res)
            .await
            .to_string()
            .contains("alice-canary-key")
    );
    // ... while the same seq asked by bob is bob's own record or nothing: never alice's.
    let (c, t) = &bob;
    for seq in 1..=head_a + 2 {
        let res = cmd(&h, c, t, "audit_payload", json!({"seq": seq})).await;
        let body = json_body(res).await.to_string();
        assert!(!body.contains("alice-canary-key"), "seq {seq}: {body}");
    }
    // A request id of alice's chain is unknown in bob's.
    let res = cmd(
        &h,
        c,
        t,
        "audit_trail",
        json!({"request_id": "req_0123456789abcdefghij"}),
    )
    .await;
    let trail = json_body(res).await;
    assert!(
        trail["headers"].as_array().is_none_or(|a| a.is_empty()),
        "{trail}"
    );
    // audit_status answers for the user's own store.
    let res = cmd(&h, &alice.0, &alice.1, "audit_status", json!({})).await;
    assert_eq!(res.status(), StatusCode::OK);
    let st = json_body(res).await;
    assert_eq!(st["incident_count"], 0, "{st}");
}

#[tokio::test]
async fn audit_reads_refuse_a_bearer_and_bad_arguments() {
    let h = H::new();
    let (c, t) = h.session("alice", PW_CANARY).await;
    let res = h
        .send(
            Request::builder()
                .method(Method::POST)
                .uri("/api/cmd/audit_query")
                .header(header::COOKIE, format!("__Host-atlas_duck_session={c}"))
                .header("x-csrf-token", &t)
                .header(header::ORIGIN, ORIGIN)
                .header(header::AUTHORIZATION, "Bearer adk_x")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"filter": {}}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = cmd(
        &h,
        &c,
        &t,
        "audit_query",
        json!({"filter": {"payload": "x"}}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(res).await["kind"], "invalid_argument");
    let res = cmd(&h, &c, &t, "audit_payload", json!({"seq": 999_999})).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
