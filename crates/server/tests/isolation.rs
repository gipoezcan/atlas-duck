//! Per-user isolation (T23; master plan M12 exit criterion, SM-2.5, SM-3.4, SM-6.1, SM-6.4):
//! user B never reaches user A's queue, decisions, events, requests, sessions, keys, PATs or
//! stores; the admin role reaches no user data; agents never approve. Each test runs against
//! the full router on `127.0.0.1:0` with real cookies, CSRF tokens and Origin headers.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::time::Duration;

use atlas_duck_atlassian::testing::TEST_PAT;
use atlas_duck_audit::keystore::{EntryName, KeyStore};
use atlas_duck_server::cmd::SERVER_COMMANDS;
use atlas_duck_server::keystore::ServerKeyStore;
use atlas_duck_server::master_key::{MasterKey, WrappedKey};
use atlas_duck_server::mcp::tools_for;
use atlas_duck_server::users::{user_dir, user_id_for};
use atlas_duck_server::web::{Access, ROUTES};
use futures::StreamExt as _;
use reqwest::Method;
use serde_json::{Value, json};
use support::*;

/// A's agent proposes a comment; answers A's browser, A's key and the request id (pending).
async fn a_pending_write(s: &TestServer) -> (Browser, String, String, tokio::task::JoinHandle<()>) {
    s.add_work().await;
    let a = s.login(ALICE).await;
    s.store_pat(&a, TEST_PAT).await;
    let (_, key) = s.api_key(&a, &["read", "propose_write"]).await;
    let agent = s.mcp(&key).await;
    let waiting = tokio::spawn(async move {
        let _ = call(&agent, "jira_comment_add", comment_args()).await;
    });
    let q = s.queue_of(&a, 1).await;
    let id = q[0]["request_id"].as_str().unwrap().to_owned();
    (a, key, id, waiting)
}

fn writes_seen(reqs: &[wiremock::Request]) -> usize {
    reqs.iter().filter(|r| r.method.as_str() != "GET").count()
}

/// A's candidate revision of `id`, from A's own preview (the body B replays).
async fn rev_of(s: &TestServer, a: &Browser, id: &str) -> Value {
    let (status, p) = s.cmd(a, "preview_fetch", json!({"request_id": id})).await;
    assert_eq!(status, 200, "{p}");
    let rev = p["preview"]["candidate_rev"].clone();
    assert!(rev["candidate_hash"].is_string(), "{rev}");
    rev
}

const NOBODY: &str = "req_00000000000000000000000000000000";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b_cannot_see_a_queue() {
    let s = TestServer::start().await;
    let (a, _key, id, waiting) = a_pending_write(&s).await;
    let rev = rev_of(&s, &a, &id).await;
    let b = s.login(BOB).await;
    assert_eq!(s.cmd(&b, "queue_list", json!({})).await, (200, json!([])));
    // Valid bodies (A's own revision), so the lookup runs: B gets 404 for A's id, exactly what B
    // gets for an id nobody has. Batch-4b review C1/I1: a 400 would mean the probe never looked.
    let bodies = |rid: &str| {
        [
            ("queue_get", json!({"request_id": rid})),
            ("preview_fetch", json!({"request_id": rid})),
            (
                "raw_page",
                json!({"request_id": rid, "candidate_rev": rev, "page": 0}),
            ),
        ]
    };
    for ((name, body), (_, unknown)) in bodies(&id).into_iter().zip(bodies(NOBODY)) {
        let got = s.cmd(&b, name, body.clone()).await;
        assert_ne!(
            got.0, 400,
            "{name}: the body was refused before any lookup: {got:?}"
        );
        assert_eq!(got, s.cmd(&b, name, unknown).await, "{name}");
        assert!(matches!(got.0, 404 | 409), "{name}: {got:?}");
        assert!(
            !got.1.to_string().contains("ABC-1"),
            "{name} leaked: {got:?}"
        );
        // Positive control: the same body from A succeeds.
        let mine = s.cmd(&a, name, body).await;
        assert_eq!(mine.0, 200, "{name} for A: {mine:?}");
    }
    waiting.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b_cannot_decide_a_request() {
    let s = TestServer::start().await;
    let (a, _key, id, waiting) = a_pending_write(&s).await;
    let rev = rev_of(&s, &a, &id).await;
    let b = s.login(BOB).await;
    let decide =
        |rid: &str| json!({"request_id": rid, "decision": "approve", "candidate_rev": rev});
    let got = s.cmd(&b, "decide", decide(&id)).await;
    assert_ne!(got.0, 400, "decide body refused before lookup: {got:?}");
    // Core answers an id it does not hold with 409 not_decidable (as for any unknown id).
    assert!(matches!(got.0, 404 | 409), "{got:?}");
    assert_eq!(got, s.cmd(&b, "decide", decide(NOBODY)).await);
    let deny = |rid: &str| json!({"request_ids": [rid], "reason": "not mine"});
    let got = s.cmd(&b, "deny_batch", deny(&id)).await;
    assert_ne!(got.0, 400, "deny_batch body refused before lookup: {got:?}");
    assert_eq!(got, s.cmd(&b, "deny_batch", deny(NOBODY)).await);
    assert_eq!(got.1["denied"], 0, "{got:?}");
    let q = s.cmd(&a, "queue_list", json!({})).await.1;
    assert_eq!(q[0]["request_id"], id, "A's item is still pending");
    assert_eq!(
        writes_seen(&s.mock.received().await),
        0,
        "no write reached the instance"
    );
    // Positive control: A's own approve with the same body lands the write.
    let mine = s.cmd(&a, "decide", decide(&id)).await;
    assert_eq!(mine.0, 200, "{mine:?}");
    for _ in 0..200 {
        if writes_seen(&s.mock.received().await) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        writes_seen(&s.mock.received().await),
        1,
        "A's approve wrote once"
    );
    waiting.abort();
}
/// Reads the SSE body until `needle` appears; `None` when `within` passes first.
async fn sse_until(res: reqwest::Response, needle: &str, within: Duration) -> Option<String> {
    let mut stream = res.bytes_stream();
    let mut buf = String::new();
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(Some(Ok(chunk))) => {
                buf.push_str(&String::from_utf8_lossy(&chunk));
                if buf.contains(needle) {
                    return Some(buf);
                }
            }
            Ok(_) | Err(_) => return None,
        }
    }
}

async fn events(s: &TestServer, b: &Browser) -> reqwest::Response {
    let res = s
        .http
        .get(s.url("/api/events"))
        .header("cookie", format!("{COOKIE}={}", b.cookie))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    res
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b_sse_never_sees_a_events() {
    let s = TestServer::start().await;
    s.add_work().await;
    let a = s.login(ALICE).await;
    let b = s.login(BOB).await;
    s.store_pat(&a, TEST_PAT).await;
    let (_, key) = s.api_key(&a, &["read", "propose_write"]).await;
    let a_stream = events(&s, &a).await;
    let b_stream = events(&s, &b).await;
    let agent = s.mcp(&key).await;
    let waiting = tokio::spawn(async move {
        let _ = call(&agent, "jira_comment_add", comment_args()).await;
    });
    let a_saw = tokio::spawn(sse_until(a_stream, "event: queue_changed", LIMIT));
    let b_saw = sse_until(b_stream, "event: queue_changed", Duration::from_secs(3)).await;
    assert!(
        a_saw.await.unwrap().is_some(),
        "A's stream got queue_changed"
    );
    assert!(b_saw.is_none(), "B's stream saw A's event: {b_saw:?}");
    waiting.abort();
}

fn not_found_envelope(v: &Value) -> bool {
    v["status"] == "failed" && v["error"]["code"] == "unknown_request"
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b_key_cannot_reach_a() {
    let s = TestServer::start().await;
    let (_a, a_key, id, waiting) = a_pending_write(&s).await;
    let b = s.login(BOB).await;
    let (_, b_key) = s.api_key(&b, &["read", "propose_write"]).await;
    let agent = s.mcp(&b_key).await;
    for tool in ["request_status", "request_await", "request_cancel"] {
        // A foreign id is unknown at once; a wait here would mean B reached A's request.
        let r = tokio::time::timeout(
            Duration::from_secs(10),
            call(&agent, tool, json!({"request_id": id})),
        )
        .await
        .expect("{tool} waited on a foreign request");
        let env = envelope(&r);
        assert!(not_found_envelope(&env), "{tool}: {env}");
    }
    let list = envelope(&call(&agent, "request_list", json!({})).await);
    assert!(!list.to_string().contains(&id), "{list}");
    // A's MCP session id with B's key.
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}"#;
    let res = s
        .http
        .post(s.url("/mcp"))
        .bearer_auth(&a_key)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(init)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let sid = res.headers()["mcp-session-id"].to_str().unwrap().to_owned();
    let res = s
        .http
        .post(s.url("/mcp"))
        .bearer_auth(&b_key)
        .header("mcp-session-id", &sid)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let body = res.text().await.unwrap();
    assert!(!body.contains(&id) && !body.contains("ABC-1"), "{body}");
    // A's request is untouched.
    let a = s.login(ALICE).await;
    assert_eq!(s.queue_of(&a, 1).await[0]["request_id"], id);
    waiting.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b_cannot_use_a_session() {
    let s = TestServer::start().await;
    let a = s.login(ALICE).await;
    let b = s.login(BOB).await;
    let mixed = Browser {
        cookie: b.cookie.clone(),
        csrf: a.csrf.clone(),
    };
    let (status, v) = s.cmd(&mixed, "queue_list", json!({})).await;
    assert_eq!(
        (status, v["error"]["code"].as_str()),
        (403, Some("auth/csrf_mismatch"))
    );
    let (status, _) = s.send(Method::POST, "/api/logout", Some(&a), None).await;
    assert_eq!(status, 204);
    let (status, v) = s.send(Method::GET, "/api/session", Some(&a), None).await;
    assert_eq!(status, 401, "{v}");
    let (status, _) = s.cmd(&a, "queue_list", json!({})).await;
    assert_eq!(status, 401);
    // B's session is unaffected.
    assert_eq!(
        s.send(Method::GET, "/api/session", Some(&b), None).await.0,
        200
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b_cannot_list_or_revoke_a_keys() {
    let s = TestServer::start().await;
    let a = s.login(ALICE).await;
    let b = s.login(BOB).await;
    let (a_id, a_key) = s.api_key(&a, &["read"]).await;
    let (_, list) = s
        .send(Method::GET, "/api/me/api-keys", Some(&b), None)
        .await;
    assert_eq!(list, json!([]));
    let (status, _) = s
        .send(
            Method::DELETE,
            &format!("/api/me/api-keys/{a_id}"),
            Some(&b),
            None,
        )
        .await;
    assert_eq!(status, 404);
    let agent = s.mcp(&a_key).await;
    let ops = envelope(&call(&agent, "ops_list", json!({})).await);
    assert_eq!(ops["status"], "succeeded", "A's key still works: {ops}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b_cannot_read_a_pat_state_or_use_a_pat() {
    let s = TestServer::start().await;
    s.add_work().await;
    let a = s.login(ALICE).await;
    let b = s.login(BOB).await;
    s.store_pat(&a, TEST_PAT).await;
    let (_, rows) = s.send(Method::GET, "/api/instances", Some(&b), None).await;
    assert_eq!(rows[0]["alias"], "work");
    assert_eq!(rows[0]["pat"], "none", "{rows}");
    assert_eq!(rows[0]["identity"], Value::Null);
    let before = s.mock.received().await.len();
    let (_, b_key) = s.api_key(&b, &["read"]).await;
    let agent = s.mcp(&b_key).await;
    let env = envelope(&call(&agent, "jira_issue_get", json!({"key": "ABC-1"})).await);
    // The base spec's code for an instance without the caller's token (the plan's "credential_missing").
    assert_eq!(env["error"]["code"], "needs_token", "{env}");
    let after = s.mock.received().await;
    assert_eq!(
        after.len(),
        before,
        "B's read reached the instance: {:?}",
        &after[before..]
    );
}

/// A concrete path for a ROUTES pattern.
fn concrete(path: &str) -> String {
    path.replace("{name}", "x.js")
        .replace("{alias}", "work")
        .replace("{command}", "queue_list")
        .replace("{id}", "key_00000000000000000000000000000000")
        .replace("{user_id}", &user_id_for(BOB.0))
        .replace("{req}", "consentrequestprobe")
}

/// A well-formed body for a state-changing row (so a refusal is the guard's, not the parser's).
fn body_for(method: &str, path: &str) -> Option<Value> {
    match (method, path) {
        ("POST", "/api/cmd/{command}") => Some(json!({})),
        ("PUT", "/api/me/pats/{alias}") => Some(json!({"pat": "x"})),
        ("POST", "/api/me/api-keys") => Some(json!({"name": "probe", "scopes": ["read"]})),
        ("POST", "/api/admin/instances") => Some(json!({"alias": "probe", "product": "jira",
            "base_url": "https://probe.example.test"})),
        ("POST", "/api/login") => Some(json!({"username": "nobody", "password": "x"})),
        ("POST" | "PUT" | "DELETE", _) => None,
        _ => None,
    }
}

fn reqwest_method(m: &str) -> Method {
    Method::from_bytes(m.as_bytes()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_route_enforces_its_access_class() {
    // Batch-4b review I3: driven from ROUTES (which builds the router). Without credentials a
    // Session or Admin row answers 401, a non-admin gets 403 on Admin rows, a Bearer row (/mcp)
    // answers 401 to a cookie, and the approval commands refuse a bearer even with a cookie.
    let s = TestServer::start().await;
    let alice = s.login(ALICE).await;
    let carol = s.login(CAROL).await;
    let (_, key) = s.api_key(&alice, &["read", "propose_write"]).await;
    for (method, path, access) in ROUTES {
        let url = concrete(path);
        let m = reqwest_method(method);
        let body = body_for(method, path);
        match access {
            Access::Public => {}
            Access::Session | Access::Admin => {
                // An Origin, no cookie: the session check answers.
                let anon = Browser {
                    cookie: "none".into(),
                    csrf: "none".into(),
                };
                let (status, v) = s.send(m.clone(), &url, Some(&anon), body.clone()).await;
                assert_eq!(status, 401, "{method} {path} without a session: {v}");
                if *access == Access::Admin {
                    let (status, v) = s.send(m.clone(), &url, Some(&alice), body.clone()).await;
                    assert_eq!(status, 403, "{method} {path} as a non-admin: {v}");
                    assert_eq!(v["error"]["code"], "auth/role_required", "{method} {path}");
                }
            }
            Access::Bearer => {
                let (status, _) = s.send(m.clone(), &url, Some(&alice), body.clone()).await;
                assert_eq!(status, 401, "{method} {path} with a cookie only");
            }
            // M14 PD-257: without a session 401; a plain user and an admin get 403.
            Access::Auditor => {
                let anon = Browser {
                    cookie: "none".into(),
                    csrf: "none".into(),
                };
                let (status, v) = s.send(m.clone(), &url, Some(&anon), body.clone()).await;
                assert_eq!(status, 401, "{method} {path} without a session: {v}");
                for who in [&alice, &carol] {
                    let (status, v) = s.send(m.clone(), &url, Some(who), body.clone()).await;
                    assert_eq!(status, 403, "{method} {path} as a non-auditor: {v}");
                    assert_eq!(v["error"]["code"], "auth/role_required", "{method} {path}");
                }
            }
        }
        // Session-only rows under /api/cmd, /api/me and /api/auditor refuse a bearer before
        // anything else.
        if path.starts_with("/api/cmd/")
            || path.starts_with("/api/me/")
            || path.starts_with("/api/auditor/")
        {
            let auth = format!("Bearer {key}");
            let (status, v) = s
                .send_with(
                    m.clone(),
                    &url,
                    Some(&alice),
                    body.clone(),
                    &[("authorization", &auth)],
                )
                .await;
            assert_eq!(status, 403, "{method} {path} with a bearer: {v}");
            assert_eq!(
                v["error"]["code"], "auth/bearer_not_accepted",
                "{method} {path}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_user_never_comes_from_the_request() {
    // Batch-4b review I2: B's session plus every spoofing channel naming A answers exactly what
    // B's session alone answers.
    let s = TestServer::start().await;
    let (a, _key, id, waiting) = a_pending_write(&s).await;
    let (a_key_id, _) = s.api_key(&a, &["read"]).await;
    let b = s.login(BOB).await;
    let a_uid = user_id_for(ALICE.0);
    let headers: Vec<(&str, &str)> = vec![
        ("x-user", ALICE.0),
        ("x-user-id", &a_uid),
        ("x-forwarded-user", ALICE.0),
        ("x-remote-user", ALICE.0),
        ("remote-user", ALICE.0),
    ];
    for (method, path, access) in ROUTES {
        if *method != "GET" || *access != Access::Session || *path == "/api/events" {
            continue;
        }
        let url = concrete(path);
        let plain = s.send(Method::GET, &url, Some(&b), None).await;
        let spoofed_url = format!("{url}?user={}&user_id={a_uid}&as={}", ALICE.0, ALICE.0);
        let spoofed = s
            .send_with(Method::GET, &spoofed_url, Some(&b), None, &headers)
            .await;
        assert_eq!(spoofed, plain, "GET {path}");
        let text = spoofed.1.to_string();
        assert!(
            !text.contains(&a_key_id) && !text.contains(&id),
            "GET {path}: {text}"
        );
    }
    // Commands: query and headers change nothing; a body naming a user is refused, not obeyed.
    let plain = s.cmd(&b, "queue_list", json!({})).await;
    assert_eq!(plain, (200, json!([])));
    let spoofed = s
        .send_with(
            Method::POST,
            &format!("/api/cmd/queue_list?user_id={a_uid}"),
            Some(&b),
            Some(json!({})),
            &headers,
        )
        .await;
    assert_eq!(spoofed, plain);
    let body = s.cmd(&b, "queue_list", json!({"user_id": a_uid})).await;
    assert_eq!(body.0, 400, "{body:?}");
    assert!(!body.1.to_string().contains(&id));
    waiting.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_has_no_user_data() {
    // Batch-4b review I4: alice has a stored PAT, an API key and a pending request; carol, the
    // admin, walks every row (admin rows with their writes too) and sees none of it.
    let s = TestServer::start().await;
    let (a, a_key, id, waiting) = a_pending_write(&s).await;
    let (a_key_id, _) = s.api_key(&a, &["read"]).await;
    let a_prefix = a_key.split('_').nth(1).unwrap().to_owned();
    let (_, mine) = s.send(Method::GET, "/api/instances", Some(&a), None).await;
    assert_eq!(mine[0]["pat"], "stored", "alice has user data: {mine}");
    let carol = s.login(CAROL).await;
    let secrets = [
        id.as_str(),
        a_key_id.as_str(),
        a_prefix.as_str(),
        TEST_PAT,
        "ABC-1",
    ];
    let leaked = |what: &str, v: &Value| {
        let text = v.to_string();
        for sec in secrets {
            assert!(!text.contains(sec), "{what} shows alice's {sec}: {text}");
        }
    };
    const INSTANCE_FIELDS: [&str; 6] = [
        "alias",
        "base_url",
        "ca_ref",
        "is_default",
        "product",
        "proxy",
    ];
    for (method, path, access) in ROUTES {
        let url = concrete(path);
        match (access, *method) {
            (Access::Admin, "GET") => {
                let (status, v) = s.send(Method::GET, &url, Some(&carol), None).await;
                assert_eq!(status, 200, "{path}");
                for row in v.as_array().unwrap() {
                    let keys: Vec<&String> = row.as_object().unwrap().keys().collect();
                    assert_eq!(keys, INSTANCE_FIELDS, "{path} answers instance fields only");
                }
                leaked(path, &v);
            }
            (Access::Admin, "POST") => {
                let (status, v) = s
                    .send(
                        Method::POST,
                        &url,
                        Some(&carol),
                        Some(json!({"alias": "wiki",
                        "product": "confluence", "base_url": "https://wiki.example.test"})),
                    )
                    .await;
                assert_eq!(status, 201, "{v}");
                let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
                assert_eq!(keys, INSTANCE_FIELDS);
                leaked(path, &v);
            }
            (Access::Admin, "DELETE") => {
                let (status, v) = s
                    .send(
                        Method::DELETE,
                        "/api/admin/instances/wiki",
                        Some(&carol),
                        None,
                    )
                    .await;
                assert_eq!(status, 204, "{v}");
                leaked(path, &v);
            }
            (Access::Session, "GET") if *path != "/api/events" => {
                let (_, v) = s.send(Method::GET, &url, Some(&carol), None).await;
                leaked(path, &v);
            }
            _ => {}
        }
    }
    for name in SERVER_COMMANDS {
        let (_, v) = s.cmd(&carol, name, json!({"request_id": id})).await;
        leaked(name, &v);
    }
    assert_eq!(s.cmd(&carol, "queue_list", json!({})).await.1, json!([]));
    // Alice's data is intact after the admin's walk.
    assert_eq!(s.queue_of(&a, 1).await[0]["request_id"], id);
    waiting.abort();
}
#[test]
fn no_cross_user_audit_route_without_auditor_role() {
    // Δ-M14-5: no route returns another user's audit data unless it requires role `auditor`.
    // M14: the auditor routes are exactly the `/api/auditor/` rows and all need the role; every
    // other audit or chain route is the session user's own (`/api/me/...`).
    let mut auditor_rows = 0;
    for (_, path, access) in ROUTES {
        if path.starts_with("/api/auditor/") {
            assert_eq!(*access, Access::Auditor, "{path}");
            auditor_rows += 1;
        } else if path.contains("audit") || path.contains("chain") {
            assert!(
                path.starts_with("/api/me/") && *access == Access::Session,
                "{path} ({access:?}) needs the auditor role or must be the user's own"
            );
        }
        assert!(
            *access != Access::Auditor || path.starts_with("/api/auditor/"),
            "{path}: an auditor route outside /api/auditor/"
        );
    }
    assert!(auditor_rows >= 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stores_are_separate_dirs_and_keys() {
    let s = TestServer::start().await;
    s.login(ALICE).await;
    s.login(BOB).await;
    let (a, b) = (user_id_for(ALICE.0), user_id_for(BOB.0));
    let data = s.dir.path().join("data");
    let (da, db) = (user_dir(&data, &a), user_dir(&data, &b));
    assert!(da.join("audit.db").is_file() && db.join("audit.db").is_file());
    assert_ne!(da, db);
    let master = MasterKey::for_tests("k1", MASTER_BYTES);
    let wrapped = |uid: &str| {
        WrappedKey::from_json(&s.store.user(uid).unwrap().unwrap().data_key_wrapped).unwrap()
    };
    assert!(
        master.unwrap(&b, &wrapped(&a)).is_err(),
        "A's data key unwraps only for A"
    );
    let a_dk = master.unwrap(&a, &wrapped(&a)).unwrap();
    let b_dk = master.unwrap(&b, &wrapped(&b)).unwrap();
    // A's keystore opens with A's key only; B's keystore does not see A's entries.
    let own = ServerKeyStore::new(s.store.clone(), &a, a_dk);
    assert!(own.get(&EntryName::Kek).unwrap().is_some());
    let crossed = ServerKeyStore::new(s.store.clone(), &a, b_dk);
    assert!(
        crossed.get(&EntryName::Kek).is_err(),
        "A's KEK opens only with A's data key"
    );
    let b_dk = master.unwrap(&b, &wrapped(&b)).unwrap();
    let b_ks = ServerKeyStore::new(s.store.clone(), &b, b_dk);
    let a_kek = s
        .store
        .ks_get(&a, &EntryName::Kek.account())
        .unwrap()
        .unwrap();
    let b_kek = s
        .store
        .ks_get(&b, &EntryName::Kek.account())
        .unwrap()
        .unwrap();
    assert_ne!(a_kek.ct, b_kek.ct);
    assert!(b_ks.get(&EntryName::Kek).unwrap().is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_cannot_approve() {
    let s = TestServer::start().await;
    let a = s.login(ALICE).await;
    let (_, key) = s.api_key(&a, &["read", "propose_write", "scripts"]).await;
    for name in SERVER_COMMANDS {
        let res = s
            .http
            .post(s.url(&format!("/api/cmd/{name}")))
            .bearer_auth(&key)
            .header("origin", &s.base)
            .header("x-csrf-token", &a.csrf)
            .header("cookie", format!("{COOKIE}={}", a.cookie))
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403, "{name}");
        let v: Value = res.json().await.unwrap();
        assert_eq!(v["error"]["code"], "auth/bearer_not_accepted", "{name}");
    }
    let all: Vec<String> = tools_for(&["read".into(), "propose_write".into(), "scripts".into()])
        .into_iter()
        .map(|t| t.name.into_owned())
        .collect();
    for t in &all {
        for word in ["decide", "approve", "release", "deny"] {
            assert!(!t.contains(word), "{t}");
        }
    }
    let agent = s.mcp(&key).await;
    let listed = agent.list_all_tools().await.unwrap();
    assert_eq!(listed.len(), all.len());
}
