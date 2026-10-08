//! The one-request engine against wiremock and raw sockets (§7.2, §11.2, §13 I-01, I-23/I-24
//! client classification, RF-2a client half, U-04 client half).

use std::sync::Arc;
use std::time::Duration;

use atlas_duck_atlassian::testing::fixtures::{FIXTURE_DATE, JIRA_9_12_VERSION, JIRA_SEARCH_PAGE};
use atlas_duck_atlassian::testing::{
    AllCommitted, MockDc, RawHttpServer, RawStep, StaticCredentials, TEST_INSTANCE, TEST_PAT,
    TEST_USER_KEY, TestClient, TestTlsServer, XAuser, test_client, test_client_with, test_config,
    test_cover, user_agent,
};
use atlas_duck_atlassian::{
    BodyFailure, CommitProbe, ConnClass, CoverIssuer, CredentialProvider, FetchControl,
    FetchFailure, FetchOutcome, GetCall, IdentityObserved, NotCommitted, PostSendKind, Product,
    ProxyChoice, SearchCall, UnavailableReason, UpstreamResponse, normalize_base_url, url_hash,
};
use serde_json::json;
use wiremock::matchers::{path, query_param_contains};
use wiremock::{Mock, ResponseTemplate};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn call(template: &str) -> GetCall {
    GetCall {
        endpoint_template: template.into(),
        params: json!({}),
        query: vec![],
    }
}

fn response(o: FetchOutcome) -> Result<UpstreamResponse, Box<dyn std::error::Error>> {
    match o {
        FetchOutcome::Response(r) => Ok(r),
        other => Err(format!("expected a response, got {other:?}").into()),
    }
}

fn failure(o: FetchOutcome) -> Result<FetchFailure, Box<dyn std::error::Error>> {
    match o {
        FetchOutcome::Failed(f) => Ok(f),
        other => Err(format!("expected a failure, got {other:?}").into()),
    }
}

fn raw_head(content_type: &str, content_length: usize) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {content_length}\r\n\r\n"
    )
    .into_bytes()
}

fn raw_ok() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
        .to_vec()
}

fn raw_client(server: &RawHttpServer) -> Result<TestClient, Box<dyn std::error::Error>> {
    Ok(test_client(test_config(
        Product::Confluence,
        &server.base_url(),
    )?)?)
}

/// Polls `cond` every 10 ms for up to 5 s.
async fn wait_for(mut cond: impl FnMut() -> bool) -> TestResult {
    for _ in 0..500 {
        if cond() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("condition not reached within 5 s".into())
}

#[tokio::test]
async fn i01_jira_myself_roundtrip() -> TestResult {
    let dc = MockDc::start(Product::Jira, "/jira").await;
    dc.jira_server_info(JIRA_9_12_VERSION).await;
    dc.jira_myself("jdoe", TEST_USER_KEY, XAuser::Same).await;
    let t = test_client(dc.client_config())?;

    let r = response(
        t.client
            .get(&test_cover()?, &call("/rest/api/2/myself"))
            .await,
    )?;
    assert_eq!(r.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&r.body)?;
    assert_eq!(body["name"], "jdoe");

    let got = dc.received().await;
    assert_eq!(got.len(), 1);
    let req = &got[0];
    assert_eq!(req.method.as_str(), "GET");
    assert_eq!(req.url.path(), "/jira/rest/api/2/myself");
    let h = |name: &str| req.headers.get(name).and_then(|v| v.to_str().ok());
    let bearer = format!("Bearer {TEST_PAT}");
    assert_eq!(h("authorization"), Some(bearer.as_str()));
    assert_eq!(h("user-agent"), Some(user_agent().as_str()));
    assert!(user_agent().starts_with("atlas-duck/"));
    assert_eq!(h("accept"), Some("application/json"));
    assert_eq!(h("x-atlassian-token"), None);
    Ok(())
}

#[derive(Default)]
struct NothingCommitted;

impl CommitProbe for NothingCommitted {
    fn request_committed(&self, _: &str) -> bool {
        false
    }
    fn system_fetch_started(&self, _: &str) -> bool {
        false
    }
}

/// The compile-time half (no `AuditCover` outside `CoverIssuer`) is the `compile_fail` doctest on
/// `InstanceClient::get` and on `AuditCover`.
#[tokio::test]
async fn no_cover_no_request() -> TestResult {
    let issuer = CoverIssuer::new(Arc::new(NothingCommitted));
    assert_eq!(issuer.for_request("req_a").err(), Some(NotCommitted));
    assert_eq!(issuer.for_system_fetch("fetch_a").err(), Some(NotCommitted));
    assert!(
        CoverIssuer::new(Arc::new(AllCommitted))
            .for_request("req_a")
            .is_ok()
    );
    Ok(())
}

#[tokio::test]
async fn status_header_decided_classes() -> TestResult {
    let dc = MockDc::start(Product::Jira, "").await;
    dc.redirect("/rest/api/2/r", "/login.jsp?os_destination=x")
        .await;
    dc.html("/rest/api/2/h", 200).await;
    Mock::given(path("/rest/api/2/n"))
        .respond_with(dc.response(200).set_body_bytes(b"plain".to_vec()))
        .mount(dc.server())
        .await;
    dc.html("/rest/api/2/u", 401).await;
    dc.json(
        "/rest/api/2/j",
        401,
        r#"{"errorMessages":["login required"]}"#,
    )
    .await;
    let t = test_client(dc.client_config())?;
    let cover = test_cover()?;

    let cases = [
        (
            "/rest/api/2/r",
            UnavailableReason::Redirect3xx,
            &b"<html>moved</html>"[..],
        ),
        (
            "/rest/api/2/h",
            UnavailableReason::NonJson2xx,
            b"<html><body>Please log in</body></html>",
        ),
        ("/rest/api/2/n", UnavailableReason::NonJson2xx, b"plain"),
        (
            "/rest/api/2/u",
            UnavailableReason::NonJson401,
            b"<html><body>Please log in</body></html>",
        ),
    ];
    for (p, want, body) in cases {
        match failure(t.client.get(&cover, &call(p)).await)? {
            FetchFailure::StatusHeaderDecided { reason, response } => {
                assert_eq!(reason, want, "{p}");
                assert_eq!(response.body, body, "{p}");
            }
            other => return Err(format!("{p}: {other:?}").into()),
        }
    }
    let r = response(t.client.get(&cover, &call("/rest/api/2/j")).await)?;
    assert_eq!(r.status, 401);
    assert_eq!(r.body, br#"{"errorMessages":["login required"]}"#);

    // Five calls, five requests: the redirect target was never requested.
    let got = dc.received().await;
    assert_eq!(got.len(), 5);
    assert!(got.iter().all(|r| r.url.path() != "/login.jsp"));
    Ok(())
}

#[tokio::test]
async fn body_decided_truncated_content_length() -> TestResult {
    let mut head = raw_head("application/json", 100);
    head.extend_from_slice(br#"{"a":"#);
    let server = RawHttpServer::serve(vec![RawStep::Send(head), RawStep::Close]).await?;
    let t = raw_client(&server)?;
    match failure(t.client.get(&test_cover()?, &call("/rest/api/space")).await)? {
        FetchFailure::BodyDecided { kind, response } => {
            assert_eq!(kind, BodyFailure::ReadError);
            assert_eq!(response.status, 200);
            assert_eq!(response.body, br#"{"a":"#);
        }
        other => return Err(format!("{other:?}").into()),
    }
    Ok(())
}

#[tokio::test]
async fn i24_chunked_cutoff_is_gated() -> TestResult {
    let bytes =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n\
                  6\r\n{\"a\":1\r\n3\r\n,\"b\r\n"
            .to_vec();
    let server = RawHttpServer::serve(vec![RawStep::Send(bytes), RawStep::Close]).await?;
    let t = raw_client(&server)?;
    match failure(t.client.get(&test_cover()?, &call("/rest/api/space")).await)? {
        FetchFailure::BodyDecided { kind, response } => {
            assert_eq!(kind, BodyFailure::ReadError);
            assert_eq!(response.body, br#"{"a":1,"b"#);
        }
        other => return Err(format!("{other:?}").into()),
    }
    Ok(())
}

#[tokio::test]
async fn body_decided_parse_failure() -> TestResult {
    let mut bytes = raw_head("application/json; charset=utf-8", 6);
    bytes.extend_from_slice(br#"{"a":}"#);
    let server = RawHttpServer::serve(vec![RawStep::Send(bytes), RawStep::Close]).await?;
    let t = raw_client(&server)?;
    assert_eq!(
        failure(t.client.get(&test_cover()?, &call("/rest/api/space")).await)?,
        FetchFailure::BodyDecided {
            kind: BodyFailure::ParseFailure,
            response: UpstreamResponse {
                status: 200,
                content_type: Some("application/json; charset=utf-8".into()),
                body: br#"{"a":}"#.to_vec(),
            },
        }
    );
    Ok(())
}

#[tokio::test]
async fn error_status_with_invalid_json_is_content() -> TestResult {
    let dc = MockDc::start(Product::Confluence, "").await;
    dc.json("/rest/api/space", 500, "not json").await;
    let t = test_client(dc.client_config())?;
    let r = response(t.client.get(&test_cover()?, &call("/rest/api/space")).await)?;
    assert_eq!((r.status, r.body.as_slice()), (500, &b"not json"[..]));
    Ok(())
}

#[tokio::test]
async fn post_send_timeout_and_cap() -> TestResult {
    let mut head = raw_head("application/json", 100);
    head.extend_from_slice(b"0123456789");
    let server = RawHttpServer::serve(vec![
        RawStep::Send(head),
        RawStep::Sleep(2000),
        RawStep::Close,
    ])
    .await?;
    let mut cfg = test_config(Product::Confluence, &server.base_url())?;
    cfg.timeouts.per_call = Duration::from_millis(500);
    let t = test_client(cfg)?;
    match failure(t.client.get(&test_cover()?, &call("/rest/api/space")).await)? {
        FetchFailure::PostSend { kind, received } => {
            assert_eq!(kind, PostSendKind::PerCallTimeout);
            assert_eq!(received, b"0123456789");
        }
        other => return Err(format!("{other:?}").into()),
    }

    // A stalled server before any header byte is a per-call timeout as well.
    let silent = RawHttpServer::serve(vec![RawStep::Sleep(2000), RawStep::Close]).await?;
    let mut cfg = test_config(Product::Confluence, &silent.base_url())?;
    cfg.timeouts.per_call = Duration::from_millis(300);
    let t = test_client(cfg)?;
    assert_eq!(
        failure(t.client.get(&test_cover()?, &call("/rest/api/space")).await)?,
        FetchFailure::PostSend {
            kind: PostSendKind::PerCallTimeout,
            received: vec![],
        }
    );

    const MIB: usize = 1024 * 1024;
    let dc = MockDc::start(Product::Confluence, "").await;
    Mock::given(path("/rest/api/content"))
        .respond_with(
            dc.response(200)
                .set_body_raw(vec![b' '; 33 * MIB], "application/json"),
        )
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    match failure(
        t.client
            .get(&test_cover()?, &call("/rest/api/content"))
            .await,
    )? {
        FetchFailure::PostSend { kind, received } => {
            assert_eq!(kind, PostSendKind::ResponseCap32MiB);
            // The chunk that crossed the cap is kept; hyper's read buffer bounds it (~400 KiB).
            assert!(received.len() > 32 * MIB, "{}", received.len());
            assert!(
                received.len() <= 32 * MIB + 512 * 1024,
                "{}",
                received.len()
            );
        }
        other => return Err(format!("{other:?}").into()),
    }
    Ok(())
}

#[tokio::test]
async fn presend_connection_classes() -> TestResult {
    let cover = test_cover()?;

    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let t = test_client(test_config(
        Product::Confluence,
        &format!("http://127.0.0.1:{port}"),
    )?)?;
    assert_eq!(
        t.client.get(&cover, &call("/rest/api/space")).await,
        FetchOutcome::Failed(FetchFailure::PreSendConnection(ConnClass::Connect))
    );

    let t = test_client(test_config(
        Product::Confluence,
        "http://nonexistent.invalid",
    )?)?;
    assert_eq!(
        t.client.get(&cover, &call("/rest/api/space")).await,
        FetchOutcome::Failed(FetchFailure::PreSendConnection(ConnClass::Dns))
    );

    // https needs CONNECT through the proxy; the proxy refuses it with 407.
    let tls = TestTlsServer::start().await?;
    let proxy = RawHttpServer::serve(vec![
        RawStep::Send(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
        ),
        RawStep::Close,
    ])
    .await?;
    let mut cfg = test_config(Product::Confluence, &tls.base_url())?;
    cfg.custom_ca_pem = Some(tls.ca_pem().as_bytes().to_vec());
    cfg.proxy = ProxyChoice::Proxy {
        host: "127.0.0.1".into(),
        port: proxy.addr().port(),
    };
    let t = test_client(cfg)?;
    assert_eq!(
        t.client.get(&cover, &call("/rest/api/space")).await,
        FetchOutcome::Failed(FetchFailure::PreSendConnection(ConnClass::ProxyConnect407))
    );
    let heads = proxy.request_heads();
    assert_eq!(heads.len(), 1);
    let head = String::from_utf8_lossy(&heads[0]);
    assert!(head.starts_with("CONNECT localhost:"), "{head}");
    // No credential ever reaches the proxy, and the server was never reached.
    assert!(
        !head.to_ascii_lowercase().contains("authorization"),
        "{head}"
    );
    assert_eq!(tls.handshakes(), 0);
    Ok(())
}

#[tokio::test]
async fn retry_429_then_success() -> TestResult {
    let dc = MockDc::start(Product::Confluence, "").await;
    Mock::given(path("/rest/api/space"))
        .respond_with(
            dc.response(429)
                .insert_header("Retry-After", "0")
                .set_body_raw(r#"{"message":"slow down"}"#, "application/json"),
        )
        .up_to_n_times(2)
        .mount(dc.server())
        .await;
    dc.json("/rest/api/space", 200, r#"{"results":[]}"#).await;
    let t = test_client(dc.client_config())?;
    let r = response(t.client.get(&test_cover()?, &call("/rest/api/space")).await)?;
    assert_eq!(r.status, 200);
    assert_eq!(dc.received().await.len(), 3);

    let dc = MockDc::start(Product::Confluence, "").await;
    Mock::given(path("/rest/api/space"))
        .respond_with(
            dc.response(429)
                .insert_header("Retry-After", "0")
                .set_body_raw(r#"{"message":"slow down"}"#, "application/json"),
        )
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    let r = response(t.client.get(&test_cover()?, &call("/rest/api/space")).await)?;
    assert_eq!(r.status, 429);
    assert_eq!(r.body, br#"{"message":"slow down"}"#);
    assert_eq!(dc.received().await.len(), 4);
    Ok(())
}

#[tokio::test]
async fn limiter_caps_concurrency_at_4() -> TestResult {
    let server = RawHttpServer::serve(vec![
        RawStep::Sleep(300),
        RawStep::Send(raw_ok()),
        RawStep::Close,
    ])
    .await?;
    let t = raw_client(&server)?;
    let cover = test_cover()?;
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let (client, cover) = (t.client.clone(), cover.clone());
        tasks.push(tokio::spawn(async move {
            client.get(&cover, &call("/rest/api/space")).await
        }));
    }
    for task in tasks {
        assert_eq!(response(task.await?)?.status, 200);
    }
    assert_eq!(server.connections(), 10);
    assert_eq!(server.max_concurrent(), 4);
    Ok(())
}

#[tokio::test]
async fn identity_header_check_jira() -> TestResult {
    async fn myself_with(
        header: XAuser,
        stored_user: &str,
    ) -> Result<FetchOutcome, Box<dyn std::error::Error>> {
        let dc = MockDc::start(Product::Jira, "").await;
        dc.jira_myself("jdoe", TEST_USER_KEY, header).await;
        let cfg = dc.client_config();
        let creds = Arc::new(StaticCredentials::for_config(&cfg));
        creds.set_user(stored_user);
        let t = test_client_with(cfg, creds)?;
        Ok(t.client
            .get(&test_cover()?, &call("/rest/api/2/myself"))
            .await)
    }

    assert_eq!(
        response(myself_with(XAuser::Same, "jdoe").await?)?.status,
        200
    );
    match failure(myself_with(XAuser::Missing, "jdoe").await?)? {
        FetchFailure::IdentityCheckFailed { observed, response } => {
            assert_eq!(observed, IdentityObserved::Missing);
            assert_eq!(response.status, 200);
            assert!(!response.body.is_empty());
        }
        other => return Err(format!("{other:?}").into()),
    }
    let observed = |o: FetchOutcome| match o {
        FetchOutcome::Failed(FetchFailure::IdentityCheckFailed { observed, .. }) => Some(observed),
        _ => None,
    };
    assert_eq!(
        observed(myself_with(XAuser::Anonymous, "jdoe").await?),
        Some(IdentityObserved::Anonymous)
    );
    assert_eq!(
        observed(myself_with(XAuser::Other("bob".into()), "jdoe").await?),
        Some(IdentityObserved::Other("bob".into()))
    );
    let pct = myself_with(
        XAuser::Raw("jdoe%40corp.example".into()),
        "jdoe@corp.example",
    )
    .await?;
    assert_eq!(response(pct)?.status, 200);

    // A Jira error status with a JSON body is checked too.
    let dc = MockDc::start(Product::Jira, "").await;
    Mock::given(path("/rest/api/2/issue/ABC-9"))
        .respond_with(ResponseTemplate::new(404).set_body_raw(
            r#"{"errorMessages":["Issue does not exist"]}"#,
            "application/json",
        ))
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    assert_eq!(
        observed(
            t.client
                .get(&test_cover()?, &call("/rest/api/2/issue/ABC-9"))
                .await
        ),
        Some(IdentityObserved::Missing)
    );

    // Confluence responses are never header-checked.
    let dc = MockDc::start(Product::Confluence, "/wiki").await;
    Mock::given(path("/wiki/rest/api/user/current"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-AUSERNAME", "anonymous")
                .set_body_raw("{}", "application/json"),
        )
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    let r = response(
        t.client
            .get(&test_cover()?, &call("/rest/api/user/current"))
            .await,
    )?;
    assert_eq!(r.status, 200);
    Ok(())
}

#[tokio::test]
async fn rf2a_client_half() -> TestResult {
    let dc = MockDc::start(Product::Jira, "/jira").await;
    Mock::given(path(dc.path("/rest/api/2/search")))
        .and(query_param_contains("jql", "CANARY_X"))
        .respond_with(
            dc.response(302)
                .insert_header("Location", "https://sso.corp.example/login")
                .set_body_raw("<html>blocked: CANARY_X</html>", "text/html"),
        )
        .mount(dc.server())
        .await;
    dc.json("/rest/api/2/search", 200, JIRA_SEARCH_PAGE).await;
    let t = test_client(dc.client_config())?;
    let cover = test_cover()?;
    let with_jql = |jql: &str| GetCall {
        endpoint_template: "/rest/api/2/search".into(),
        params: json!({}),
        query: vec![("jql".into(), jql.into())],
    };

    match failure(t.client.get(&cover, &with_jql("text ~ CANARY_X")).await)? {
        FetchFailure::StatusHeaderDecided { reason, response } => {
            assert_eq!(reason, UnavailableReason::Redirect3xx);
            assert_eq!(response.status, 302);
            assert!(String::from_utf8_lossy(&response.body).contains("CANARY_X"));
        }
        other => return Err(format!("{other:?}").into()),
    }
    let r = response(t.client.get(&cover, &with_jql("project = ABC")).await)?;
    assert_eq!(r.status, 200);
    Ok(())
}

#[tokio::test]
async fn cancel_during_body_captures_partial() -> TestResult {
    let mut bytes = raw_head("application/json", 5000);
    bytes.extend(std::iter::repeat_n(b'x', 1000));
    let server = RawHttpServer::serve(vec![
        RawStep::Send(bytes),
        RawStep::Sleep(10_000),
        RawStep::Close,
    ])
    .await?;
    let t = raw_client(&server)?;
    let ctl = FetchControl::new();
    let task = {
        let (client, cover, ctl) = (t.client.clone(), test_cover()?, ctl.clone());
        tokio::spawn(async move { client.get_ctl(&cover, &call("/rest/api/space"), &ctl).await })
    };
    wait_for(|| ctl.take_captured().partial.len() == 1000).await?;

    // Both are plain functions: they return while the server still holds the socket.
    ctl.cancel();
    let snap = ctl.take_captured();
    assert_eq!(server.closed(), 0);
    assert!(snap.sent);
    assert_eq!(snap.partial.len(), 1000);

    match failure(task.await?)? {
        FetchFailure::CancelledInFlight { bytes_received } => {
            assert_eq!(bytes_received.len(), 1000);
        }
        other => return Err(format!("{other:?}").into()),
    }
    Ok(())
}

#[tokio::test]
async fn cancel_while_waiting_for_permit() -> TestResult {
    let server = RawHttpServer::serve(vec![
        RawStep::Sleep(1500),
        RawStep::Send(raw_ok()),
        RawStep::Close,
    ])
    .await?;
    let t = raw_client(&server)?;
    let cover = test_cover()?;
    let mut held = Vec::new();
    for _ in 0..4 {
        let (client, cover) = (t.client.clone(), cover.clone());
        held.push(tokio::spawn(async move {
            client.get(&cover, &call("/rest/api/space")).await
        }));
    }
    wait_for(|| server.connections() == 4).await?;

    let ctl = FetchControl::new();
    let fifth = {
        let (client, cover, ctl) = (t.client.clone(), cover.clone(), ctl.clone());
        tokio::spawn(async move { client.get_ctl(&cover, &call("/rest/api/space"), &ctl).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    ctl.cancel();
    assert_eq!(
        fifth.await?,
        FetchOutcome::Failed(FetchFailure::CancelledBeforeSend)
    );
    assert!(!ctl.take_captured().sent);

    for task in held {
        assert_eq!(response(task.await?)?.status, 200);
    }
    assert_eq!(server.connections(), 4);
    Ok(())
}

#[tokio::test]
async fn date_header_observed() -> TestResult {
    let dc = MockDc::start(Product::Jira, "")
        .await
        .with_date(FIXTURE_DATE);
    dc.jira_myself("jdoe", TEST_USER_KEY, XAuser::Same).await;
    let t = test_client(dc.client_config())?;
    response(
        t.client
            .get(&test_cover()?, &call("/rest/api/2/myself"))
            .await,
    )?;
    assert_eq!(
        t.dates.calls(),
        vec![(
            TEST_INSTANCE.to_owned(),
            httpdate::parse_http_date(FIXTURE_DATE)?
        )]
    );
    Ok(())
}

#[tokio::test]
async fn u04_refused_is_never_sent_unauthenticated() -> TestResult {
    let dc = MockDc::start(Product::Jira, "/jira").await;
    dc.jira_myself("jdoe", TEST_USER_KEY, XAuser::Same).await;
    let cfg = dc.client_config();
    let other = url_hash(&normalize_base_url("https://jira.other.example/jira")?);
    let creds = Arc::new(StaticCredentials::new(
        &cfg.instance_id,
        TEST_PAT,
        other,
        "jdoe",
        TEST_USER_KEY,
    ));
    let t = test_client_with(cfg, creds)?;
    assert_eq!(
        t.client
            .get(&test_cover()?, &call("/rest/api/2/myself"))
            .await,
        FetchOutcome::Failed(FetchFailure::OriginGuardRefused)
    );
    // A template that would leave the base is refused the same way.
    let t = test_client(dc.client_config())?;
    let escape = GetCall {
        endpoint_template: "/rest/api/2/issue/{key}".into(),
        params: json!({"key": ".."}),
        query: vec![],
    };
    assert_eq!(
        t.client.get(&test_cover()?, &escape).await,
        FetchOutcome::Failed(FetchFailure::OriginGuardRefused)
    );
    assert!(dc.received().await.is_empty());
    Ok(())
}

#[tokio::test]
async fn needs_token_when_no_pat_is_stored() -> TestResult {
    let dc = MockDc::start(Product::Jira, "").await;
    dc.jira_myself("jdoe", TEST_USER_KEY, XAuser::Same).await;
    let t = test_client(dc.client_config())?;
    t.creds.delete(TEST_INSTANCE)?;
    assert_eq!(
        t.client
            .get(&test_cover()?, &call("/rest/api/2/myself"))
            .await,
        FetchOutcome::Failed(FetchFailure::NeedsToken)
    );
    assert!(dc.received().await.is_empty());
    Ok(())
}

#[tokio::test]
async fn post_search_is_the_one_read_post() -> TestResult {
    let dc = MockDc::start(Product::Jira, "/jira").await;
    dc.json("/rest/api/2/search", 200, JIRA_SEARCH_PAGE).await;
    let t = test_client(dc.client_config())?;
    let cover = test_cover()?;
    let body = json!({"jql": "project = ABC", "startAt": 0, "maxResults": 50});
    let search = SearchCall {
        endpoint_template: "/rest/api/2/search".into(),
        body: body.clone(),
    };
    let r = response(t.client.post_search(&cover, &search).await)?;
    assert_eq!(r.status, 200);

    let got = dc.received().await;
    assert_eq!(got.len(), 1);
    let req = &got[0];
    assert_eq!(req.method.as_str(), "POST");
    assert_eq!(req.url.path(), "/jira/rest/api/2/search");
    let h = |name: &str| req.headers.get(name).and_then(|v| v.to_str().ok());
    assert_eq!(h("x-atlassian-token"), Some("no-check"));
    assert_eq!(h("content-type"), Some("application/json"));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&req.body)?,
        body
    );

    let other = SearchCall {
        endpoint_template: "/rest/api/2/issue".into(),
        body,
    };
    assert_eq!(
        t.client.post_search(&cover, &other).await,
        FetchOutcome::Failed(FetchFailure::MethodGuardRefused)
    );
    assert_eq!(dc.received().await.len(), 1);
    Ok(())
}
