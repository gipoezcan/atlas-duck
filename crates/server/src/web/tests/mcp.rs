//! `/mcp` (T19) through the full router on `127.0.0.1:0` with rmcp's streamable-HTTP client:
//! bearer refusal, scope-filtered tools, an in-process read through the user's PAT with the
//! approval URL, `scope_missing`, and session ids bound to their creator.

use std::net::SocketAddr;

use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::RunningService;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::{RoleClient, ServiceExt as _};

use super::*;
use crate::runtime::UserCtx;

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}"#;

/// Serves the harness router on a loopback port; answers the `/mcp` URL.
async fn serve(h: &H) -> String {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = h
        .router
        .clone()
        .into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}/mcp")
}

fn key_for(h: &H, user: &str, scopes: &[&str]) -> String {
    let ctx = UserCtx::from_authenticated(&user_id_for(user));
    let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
    let created = h
        .state
        .api_keys
        .create(&ctx, "agent", &scopes, None)
        .unwrap();
    secrecy::ExposeSecret::expose_secret(&created.key).to_owned()
}

async fn client(url: &str, key: &str) -> RunningService<RoleClient, ()> {
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(url.to_owned()).auth_header(key.to_owned()),
    );
    tokio::time::timeout(LIMIT, ().serve(transport))
        .await
        .expect("initialize hung")
        .unwrap()
}

async fn call(c: &RunningService<RoleClient, ()>, tool: &str, args: Value) -> CallToolResult {
    let params = CallToolRequestParams::new(tool.to_owned())
        .with_arguments(args.as_object().cloned().unwrap_or_default());
    tokio::time::timeout(LIMIT, c.call_tool(params))
        .await
        .expect("tool call hung")
        .unwrap()
}

fn envelope(r: &CallToolResult) -> Value {
    r.structured_content.clone().unwrap_or(Value::Null)
}

async fn names(c: &RunningService<RoleClient, ()>) -> Vec<String> {
    tokio::time::timeout(LIMIT, c.list_all_tools())
        .await
        .expect("tools/list hung")
        .unwrap()
        .into_iter()
        .map(|t| t.name.into_owned())
        .collect()
}

fn mcp_post(body: &str, auth: Option<&str>, session: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(header::HOST, "duck.example.test")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream");
    if let Some(a) = auth {
        b = b.header(header::AUTHORIZATION, format!("Bearer {a}"));
    }
    if let Some(s) = session {
        b = b.header(crate::mcp::SESSION_HEADER, s);
    }
    b.body(Body::from(body.to_owned())).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_bearer_or_a_cookie_only_is_401_with_www_authenticate() {
    let h = H::new();
    let (cookie, _) = h.session("alice", PW_CANARY).await;
    let res = h.send(mcp_post(INIT, None, None)).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    // M14 PD-243: the challenge names the protected-resource metadata (RFC 9728 §5.1).
    assert_eq!(
        res.headers()[header::WWW_AUTHENTICATE],
        "Bearer realm=\"atlas-duck\", resource_metadata=\"https://duck.example.test/.well-known/oauth-protected-resource/mcp\""
    );
    let mut req = mcp_post(INIT, None, None);
    req.headers_mut().insert(
        header::COOKIE,
        format!("__Host-atlas_duck_session={cookie}")
            .parse()
            .unwrap(),
    );
    let res = h.send(req).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let res = h.send(mcp_post(INIT, Some("adk_nope"), None)).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    // A presented token adds error="invalid_token" (RFC 6750 §3.1).
    assert!(
        res.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .ends_with(", error=\"invalid_token\"")
    );
    // With OAuth off: M12's challenge, no metadata.
    let off = H::with_oauth(crate::oauth::OAuthConfig {
        enabled: false,
        ..crate::oauth::OAuthConfig::DEFAULT
    });
    let res = off.send(mcp_post(INIT, None, None)).await;
    assert_eq!(
        res.headers()[header::WWW_AUTHENTICATE],
        "Bearer realm=\"atlas-duck\""
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_key_lists_read_tools_only_and_cannot_propose() {
    let h = H::new();
    h.session("alice", PW_CANARY).await;
    let url = serve(&h).await;
    let read = client(&url, &key_for(&h, "alice", &["read"])).await;
    let got = names(&read).await;
    let want: Vec<String> = crate::mcp::tools_for(&["read".to_owned()])
        .into_iter()
        .map(|t| t.name.into_owned())
        .collect();
    assert_eq!(got, want);
    assert!(got.contains(&"jira_issue_get".to_owned()));
    assert!(got.contains(&"ops_list".to_owned()));
    for absent in ["jira_issue_edit", "request_cancel", "script_run", "call"] {
        assert!(!got.contains(&absent.to_owned()), "{absent} listed");
    }
    // ops_list works (no instance: the registry's own list).
    let ops = call(&read, "ops_list", json!({})).await;
    assert_eq!(envelope(&ops)["status"], "succeeded", "{ops:?}");
    // The write tool exists, but not for this key.
    let w = call(
        &read,
        "jira_issue_edit",
        json!({"key": "ABC-1", "fields": {"summary": "x"}}),
    )
    .await;
    assert_eq!(w.is_error, Some(true));
    assert_eq!(envelope(&w)["error"]["code"], "scope_missing", "{w:?}");
    // A full key lists the write tools too, never `script_run`.
    let full = client(&url, &key_for(&h, "alice", &["read", "propose_write"])).await;
    let all = names(&full).await;
    assert!(all.contains(&"jira_issue_edit".to_owned()));
    assert!(all.contains(&"request_cancel".to_owned()));
    assert!(!all.contains(&"script_run".to_owned()));
    let _ = read.cancel().await;
    let _ = full.cancel().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_through_the_users_pat_pends_with_an_approval_url_and_returns_the_data() {
    let h = H::new();
    let mock = jira_mock().await;
    put_work(&h, &mock.base_url());
    let (ca, ta) = h.session("alice", PW_CANARY).await;
    store_pat(&h, "alice", &mock);
    let url = serve(&h).await;
    let agent = std::sync::Arc::new(client(&url, &key_for(&h, "alice", &["read"])).await);
    let waiting = {
        let agent = agent.clone();
        tokio::spawn(async move { call(&agent, "jira_issue_get", json!({"key": "ABC-1"})).await })
    };
    let mut q = json!([]);
    for _ in 0..200 {
        q = json_body(cmd(&h, &ca, &ta, "queue_list", json!({})).await).await;
        if !q.as_array().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let id = q[0]["request_id"].as_str().expect("queued").to_owned();
    let status = call(&agent, "request_status", json!({"request_id": id})).await;
    let env = envelope(&status);
    assert_eq!(env["status"], "pending", "{env}");
    assert_eq!(
        env["meta"]["approval_url"],
        format!("{ORIGIN}/approvals?item={id}")
    );
    let preview =
        json_body(cmd(&h, &ca, &ta, "preview_fetch", json!({"request_id": id})).await).await;
    let rev = preview["preview"]["candidate_rev"].clone();
    let out = cmd(
        &h,
        &ca,
        &ta,
        "decide",
        json!({"request_id": id, "decision": "release", "candidate_rev": rev}),
    )
    .await;
    assert_eq!(out.status(), StatusCode::OK);
    let done = tokio::time::timeout(LIMIT, waiting)
        .await
        .expect("the call did not end")
        .unwrap();
    let env = envelope(&done);
    assert_eq!(env["status"], "released", "{env}");
    assert!(env["data"].to_string().contains("ABC-1"), "{env}");
    assert!(env["meta"].get("approval_url").is_none());
    // The mock saw alice's PAT.
    let auth: Vec<String> = mock
        .received()
        .await
        .iter()
        .filter(|r| r.url.path() == "/rest/api/2/issue/ABC-1")
        .filter_map(|r| {
            r.headers
                .get("authorization")
                .map(|v| v.to_str().unwrap_or("").to_owned())
        })
        .collect();
    assert_eq!(
        auth,
        vec![format!(
            "Bearer {}",
            atlas_duck_atlassian::testing::TEST_PAT
        )]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_users_key_cannot_use_a_session() {
    let h = H::new();
    h.session("alice", PW_CANARY).await;
    h.session("bob", "pw-bob").await;
    let (ka, kb) = (
        key_for(&h, "alice", &["read"]),
        key_for(&h, "bob", &["read"]),
    );
    let res = h.send(mcp_post(INIT, Some(&ka), None)).await;
    let status = res.status();
    if status != StatusCode::OK {
        let b = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        panic!("{status}: {}", String::from_utf8_lossy(&b));
    }
    let sid = res.headers()[crate::mcp::SESSION_HEADER]
        .to_str()
        .unwrap()
        .to_owned();
    let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
    let res = h.send(mcp_post(list, Some(&kb), Some(&sid))).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let res = h.send(mcp_post(list, Some(&ka), Some(&sid))).await;
    assert_ne!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_sessions_and_oversized_bodies_are_refused() {
    let h = H::new();
    h.session("alice", PW_CANARY).await;
    let k = key_for(&h, "alice", &["read"]);
    let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
    let res = h.send(mcp_post(list, Some(&k), Some("never-issued"))).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let mut big = mcp_post(INIT, Some(&k), None);
    big.headers_mut().insert(
        header::CONTENT_LENGTH,
        (crate::mcp::BODY_LIMIT + 1).to_string().parse().unwrap(),
    );
    let res = h.send(big).await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
