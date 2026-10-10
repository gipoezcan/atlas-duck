//! Approved writes (§5.1 inv. 3, §5.4 step 6, §7.2 declared success, U-03 client half, I-25):
//! the wire equals the approved list byte for byte, and every response class maps to its outcome.

use std::time::Duration;

use atlas_duck_atlassian::testing::fixtures::{
    CONFLUENCE_ERROR_400, CONFLUENCE_PAGE_UPDATED, CONFLUENCE_VERSION_CONFLICT_400,
    CONFLUENCE_VERSION_CONFLICT_409, JIRA_COMMENT, JIRA_ERROR_400, JIRA_ISSUE_CREATED,
};
use atlas_duck_atlassian::testing::{
    MockDc, RawHttpServer, RawStep, TEST_PAT, TestTlsServer, XAuser, test_client, test_config,
    test_cover,
};
use atlas_duck_atlassian::{
    ApprovedWrite, ConnClass, ExpectedBody, FetchControl, GetCall, HttpRequestSpec, NotSentReason,
    Product, ProxyChoice, SuccessExpectation, UnknownReason, UpstreamResponse, WriteOutcome,
    build_url,
};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn spec(method: &str, url: &str, content_type: Option<&str>, body: &[u8]) -> HttpRequestSpec {
    HttpRequestSpec {
        index: 0,
        method: method.into(),
        resolved_url: url.into(),
        content_type: content_type.map(str::to_owned),
        body: body.to_vec(),
    }
}

fn json_op(s: HttpRequestSpec) -> ApprovedWrite {
    ApprovedWrite {
        requests: vec![s],
        success: SuccessExpectation {
            statuses: None,
            body: ExpectedBody::Json,
        },
    }
}

fn empty_op(s: HttpRequestSpec, status: u16) -> ApprovedWrite {
    ApprovedWrite {
        requests: vec![s],
        success: SuccessExpectation {
            statuses: Some(vec![status]),
            body: ExpectedBody::Empty,
        },
    }
}

/// The resolved URL exactly as `core` builds it (`build_url`, then `Url::as_str`).
fn url_for(
    dc: &MockDc,
    template: &str,
    params: serde_json::Value,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(build_url(&dc.base(), template, &params, &[])?.to_string())
}

/// The URL a request reached wiremock with: wiremock rebuilds `Request::url` on
/// `http://localhost`, so the authority comes from the `Host` header.
fn wire_url(req: &wiremock::Request) -> String {
    let host = req
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let query = req.url.query().map(|q| format!("?{q}")).unwrap_or_default();
    format!("http://{host}{}{query}", req.url.path())
}

/// An outcome of an answered request: the head's status is part of it (Δ C.4, Task 26).
fn unknown_status(reason: UnknownReason, status: impl Into<Option<u16>>) -> WriteOutcome {
    WriteOutcome::OutcomeUnknown {
        reason,
        request_index: 0,
        status: status.into(),
    }
}

const COMMENT_BODY: &[u8] = "{\"body\":\"Grüße, h{noformat}\\n\"}".as_bytes();

/// U-03 (client half): the one request on the wire equals the list entry in method, full URL,
/// `Content-Type` and body, byte for byte; query values are form-urlencoded (`a b+c` is
/// `a+b%2Bc`, Task 8) and are sent as approved.
#[tokio::test]
async fn u03_send_approved_sends_exactly_the_list() -> TestResult {
    let dc = MockDc::start(Product::Jira, "/jira").await;
    Mock::given(method("POST"))
        .and(path(dc.path("/rest/api/2/issue/ABC-1/comment")))
        .respond_with(
            dc.response(201)
                .set_body_raw(JIRA_COMMENT, "application/json"),
        )
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    let query = vec![("expand".to_owned(), "a b+c".to_owned())];
    let url = build_url(
        &dc.base(),
        "/rest/api/2/issue/{key}/comment",
        &json!({"key": "ABC-1"}),
        &query,
    )?;
    let url = url.as_str().to_owned();
    assert!(
        url.ends_with("/jira/rest/api/2/issue/ABC-1/comment?expand=a+b%2Bc"),
        "{url}"
    );
    let s = HttpRequestSpec {
        index: 3,
        ..spec(
            "POST",
            &url,
            Some("application/json; charset=utf-8"),
            COMMENT_BODY,
        )
    };

    let out = t
        .client
        .send_approved(&test_cover()?, &json_op(s.clone()))
        .await;
    assert_eq!(
        out,
        WriteOutcome::Executed {
            response: UpstreamResponse {
                status: 201,
                content_type: Some("application/json".into()),
                body: JIRA_COMMENT.as_bytes().to_vec(),
            },
            server_user: Some("jdoe".into()),
            request_index: 3,
        }
    );

    let got = dc.received().await;
    assert_eq!(got.len(), 1);
    let req = &got[0];
    assert_eq!(req.method.as_str(), s.method);
    assert_eq!(wire_url(req), s.resolved_url);
    let ct: Vec<&[u8]> = req
        .headers
        .get_all("content-type")
        .iter()
        .map(|v| v.as_bytes())
        .collect();
    assert_eq!(ct, [s.content_type.as_deref().unwrap_or("").as_bytes()]);
    assert_eq!(req.body, s.body);
    let h = |name: &str| req.headers.get(name).and_then(|v| v.to_str().ok());
    assert_eq!(h("x-atlassian-token"), Some("no-check"));
    let bearer = format!("Bearer {TEST_PAT}");
    assert_eq!(h("authorization"), Some(bearer.as_str()));
    assert_eq!(h("accept"), Some("application/json"));
    Ok(())
}

/// The same, at the byte level on a raw socket: request line, `Host`, `Content-Type` and body
/// are exactly the list entry's, and no second `Content-Type` is added.
#[tokio::test]
async fn u03_wire_bytes_equal_the_list_entry() -> TestResult {
    let server = RawHttpServer::serve(vec![
        RawStep::Send(
            b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
                .to_vec(),
        ),
        RawStep::Close,
    ])
    .await?;
    let t = test_client(test_config(
        Product::Confluence,
        &format!("{}/wiki", server.base_url()),
    )?)?;
    let query = vec![
        ("expand".to_owned(), "a b+c~*".to_owned()),
        ("é".to_owned(), "x&y=z".to_owned()),
    ];
    let url = build_url(
        t.client.base(),
        "/rest/api/content/{id}/label",
        &json!({"id": "65537"}),
        &query,
    )?;
    let s = spec(
        "POST",
        url.as_str(),
        Some("application/json; charset=utf-8"),
        COMMENT_BODY,
    );
    let out = t
        .client
        .send_approved(&test_cover()?, &json_op(s.clone()))
        .await;
    assert!(matches!(out, WriteOutcome::Executed { .. }), "{out:?}");

    let heads = server.request_heads();
    assert_eq!(heads.len(), 1);
    let head = String::from_utf8(heads[0].clone())?;
    let mut lines = head.split("\r\n");
    let target = &s.resolved_url[server.base_url().len()..];
    assert_eq!(
        lines.next(),
        Some(format!("POST {target} HTTP/1.1").as_str())
    );
    let fields: Vec<(String, &str)> = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_ascii_lowercase(), v))
        .collect();
    let values = |name: &str| -> Vec<&str> {
        fields
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| *v)
            .collect()
    };
    assert_eq!(
        values("content-type"),
        [s.content_type.as_deref().unwrap_or("")]
    );
    assert_eq!(values("host"), [server.addr().to_string().as_str()]);
    assert_eq!(values("x-atlassian-token"), ["no-check"]);
    assert_eq!(server.request_bodies(), std::slice::from_ref(&s.body));
    Ok(())
}

/// A list entry the `url` crate would serialize differently is refused before anything leaves:
/// the wire would differ from what was approved. So are entries that cannot be written at all.
#[tokio::test]
async fn mismatch_is_not_sent() -> TestResult {
    let dc = MockDc::start(Product::Jira, "/jira").await;
    dc.json("/rest/api/2/issue/ABC-1/comment", 201, JIRA_COMMENT)
        .await;
    let t = test_client(dc.client_config())?;
    let cover = test_cover()?;
    let good = url_for(
        &dc,
        "/rest/api/2/issue/{key}/comment",
        json!({"key": "ABC-1"}),
    )?;
    let origin = good.split("/jira/").next().unwrap_or("").to_owned();

    // Each of these parses, but `Url::as_str` is not the listed text.
    let normalized = [
        format!("{origin}/jira/rest/api/2/issue/ABC-1/./comment"),
        format!("{origin}/jira/rest/api/2/issue/ABC-1/x/../comment"),
        format!("{origin}/jira/rest/api/2/issue/ABC 1/comment"),
        format!("{origin}/jira/rest/api/2/issue/ABC-1/comment?expand=a b"),
        format!("{origin}/jira/rest/api/2/issue/ABC-1\\comment"),
        format!("{origin}/jira/rest/api/2/issue/Ä-1/comment"),
        good.replacen("http://", "HTTP://", 1),
    ];
    for raw in &normalized {
        let parsed = url::Url::parse(raw)?;
        assert_ne!(
            parsed.as_str(),
            raw,
            "{raw} must be one the url crate rewrites"
        );
    }
    // Not among them: the `url` crate keeps percent-escapes as written (`%7e` stays `%7e`, it is
    // not decoded to `~`), so such an entry is sent byte for byte as listed.
    let escaped = format!("{origin}/jira/rest/api/2/issue/ABC%7e1/comment");
    assert_eq!(url::Url::parse(&escaped)?.as_str(), escaped);
    let mut cases: Vec<HttpRequestSpec> = normalized
        .iter()
        .map(|u| spec("POST", u, Some("application/json"), b"{}"))
        .collect();
    cases.extend([
        // A fragment is never written, so it can never be what was approved.
        spec(
            "POST",
            &format!("{good}#x"),
            Some("application/json"),
            b"{}",
        ),
        spec("PO ST", &good, Some("application/json"), b"{}"),
        spec("POST", &good, Some("application/json\r\nX-Evil: 1"), b"{}"),
        spec("POST", "not a url", Some("application/json"), b"{}"),
        // Userinfo parses and serializes unchanged, but reqwest moves it into a Basic
        // `Authorization` header and out of the URL, so the request is not the listed one.
        spec(
            "POST",
            &good.replacen("http://", "http://u:p@", 1),
            Some("application/json"),
            b"{}",
        ),
    ]);
    for s in cases {
        let s = HttpRequestSpec { index: 7, ..s };
        assert_eq!(
            t.client
                .send_approved(&test_cover()?, &json_op(s.clone()))
                .await,
            WriteOutcome::RefusedMismatch { request_index: 7 },
            "{:?} {}",
            s,
            s.resolved_url
        );
    }
    assert!(dc.received().await.is_empty());

    // The control: the same entry with the URL `build_url` produced is sent.
    let ok = t
        .client
        .send_approved(
            &cover,
            &json_op(spec("POST", &good, Some("application/json"), b"{}")),
        )
        .await;
    assert!(matches!(ok, WriteOutcome::Executed { .. }), "{ok:?}");
    assert_eq!(dc.received().await.len(), 1);
    Ok(())
}

/// §5.1 inv. 3: one request per v1 write. A list `atlassian` cannot report on request by request
/// (empty, or more than one entry) is refused whole; nothing leaves.
#[tokio::test]
async fn lists_other_than_one_request_are_refused() -> TestResult {
    let dc = MockDc::start(Product::Confluence, "").await;
    dc.json("/rest/api/content/1/label", 200, r#"{"results":[]}"#)
        .await;
    let t = test_client(dc.client_config())?;
    let url = url_for(&dc, "/rest/api/content/{id}/label", json!({"id": "1"}))?;
    let one = spec("POST", &url, Some("application/json"), br#"[{"name":"x"}]"#);
    let mut w = json_op(one.clone());
    w.requests.clear();
    assert_eq!(
        t.client.send_approved(&test_cover()?, &w).await,
        WriteOutcome::RefusedMismatch { request_index: 0 }
    );
    w.requests = vec![one.clone(), HttpRequestSpec { index: 1, ..one }];
    assert_eq!(
        t.client.send_approved(&test_cover()?, &w).await,
        WriteOutcome::RefusedMismatch { request_index: 0 }
    );
    assert!(dc.received().await.is_empty());
    Ok(())
}

#[tokio::test]
async fn origin_guard_refuses_an_approved_url_outside_the_base() -> TestResult {
    let dc = MockDc::start(Product::Confluence, "/wiki").await;
    let t = test_client(dc.client_config())?;
    let inside = url_for(&dc, "/rest/api/content/{id}", json!({"id": "1"}))?;
    let outside = inside.replacen("/wiki/", "/other/", 1);
    let out = t
        .client
        .send_approved(
            &test_cover()?,
            &json_op(spec("PUT", &outside, Some("application/json"), b"{}")),
        )
        .await;
    assert_eq!(out, WriteOutcome::OriginGuardRefused);
    assert!(dc.received().await.is_empty());
    Ok(())
}

/// I-25: `{[201], Empty}` (`jira.issuelink.create`; Jira 10 answers `text/html`).
#[tokio::test]
async fn i25_declared_empty_201_executed() -> TestResult {
    let dc = MockDc::start(Product::Jira, "").await;
    dc.empty(
        "/rest/api/2/issueLink",
        201,
        Some("text/html;charset=UTF-8"),
    )
    .await;
    let t = test_client(dc.client_config())?;
    let url = url_for(&dc, "/rest/api/2/issueLink", json!({}))?;
    let s = spec(
        "POST",
        &url,
        Some("application/json"),
        br#"{"type":{"name":"Blocks"}}"#,
    );
    assert_eq!(
        t.client
            .send_approved(&test_cover()?, &empty_op(s, 201))
            .await,
        WriteOutcome::Executed {
            response: UpstreamResponse {
                status: 201,
                content_type: Some("text/html;charset=UTF-8".into()),
                body: vec![],
            },
            server_user: Some("jdoe".into()),
            request_index: 0,
        }
    );
    Ok(())
}

/// Task 9 review minor 7: a declared `{204, Empty}` answered with a JSON `Content-Type` and no
/// body is the declared success, not a JSON parse failure.
#[tokio::test]
async fn i25_declared_empty_204_with_json_content_type_executed() -> TestResult {
    let dc = MockDc::start(Product::Jira, "").await;
    dc.empty(
        "/rest/api/2/issue/ABC-1",
        204,
        Some("application/json;charset=UTF-8"),
    )
    .await;
    let t = test_client(dc.client_config())?;
    let url = url_for(&dc, "/rest/api/2/issue/{key}", json!({"key": "ABC-1"}))?;
    let s = spec(
        "PUT",
        &url,
        Some("application/json"),
        br#"{"fields":{"summary":"x"}}"#,
    );
    match t
        .client
        .send_approved(&test_cover()?, &empty_op(s, 204))
        .await
    {
        WriteOutcome::Executed { response, .. } => {
            assert_eq!((response.status, response.body.len()), (204, 0));
        }
        other => return Err(format!("{other:?}").into()),
    }
    Ok(())
}

#[tokio::test]
async fn i25_html_body_on_empty_op_outcome_unknown() -> TestResult {
    let dc = MockDc::start(Product::Jira, "").await;
    dc.html("/rest/api/2/issueLink", 201).await;
    let t = test_client(dc.client_config())?;
    let url = url_for(&dc, "/rest/api/2/issueLink", json!({}))?;
    let s = spec("POST", &url, Some("application/json"), b"{}");
    assert_eq!(
        t.client
            .send_approved(&test_cover()?, &empty_op(s, 201))
            .await,
        unknown_status(UnknownReason::UndeclaredSuccess, 201)
    );
    Ok(())
}

#[tokio::test]
async fn i25_empty_200_on_json_op_outcome_unknown() -> TestResult {
    let dc = MockDc::start(Product::Confluence, "").await;
    dc.empty("/rest/api/content", 200, Some("application/json"))
        .await;
    dc.html("/rest/api/content/2", 200).await;
    dc.json("/rest/api/content/3", 200, "{not json").await;
    dc.empty("/rest/api/content/4/label/x", 200, None).await;
    let t = test_client(dc.client_config())?;
    let cover = test_cover()?;
    for p in [
        "/rest/api/content",
        "/rest/api/content/2",
        "/rest/api/content/3",
    ] {
        let s = spec(
            "POST",
            &url_for(&dc, p, json!({}))?,
            Some("application/json"),
            b"{}",
        );
        assert_eq!(
            t.client.send_approved(&cover, &json_op(s)).await,
            unknown_status(UnknownReason::UndeclaredSuccess, 200),
            "{p}"
        );
    }
    // An undeclared status on an `Empty` op (200 where 204 is declared).
    let s = spec(
        "DELETE",
        &url_for(&dc, "/rest/api/content/4/label/x", json!({}))?,
        None,
        b"",
    );
    assert_eq!(
        t.client.send_approved(&cover, &empty_op(s, 204)).await,
        unknown_status(UnknownReason::UndeclaredSuccess, 200)
    );
    Ok(())
}

#[tokio::test]
async fn write_3xx_unavailable() -> TestResult {
    let dc = MockDc::start(Product::Jira, "").await;
    dc.redirect("/rest/api/2/issue", "/login.jsp").await;
    let t = test_client(dc.client_config())?;
    let s = spec(
        "POST",
        &url_for(&dc, "/rest/api/2/issue", json!({}))?,
        Some("application/json"),
        b"{}",
    );
    assert_eq!(
        t.client.send_approved(&test_cover()?, &json_op(s)).await,
        WriteOutcome::Unavailable3xx { request_index: 0 }
    );
    let got = dc.received().await;
    assert_eq!(got.len(), 1);
    assert!(got.iter().all(|r| r.url.path() != "/login.jsp"));
    Ok(())
}

fn page_update(dc: &MockDc) -> Result<HttpRequestSpec, Box<dyn std::error::Error>> {
    let url = url_for(dc, "/rest/api/content/{id}", json!({"id": "65537"}))?;
    Ok(spec(
        "PUT",
        &url,
        Some("application/json"),
        br#"{"version":{"number":8}}"#,
    ))
}

#[tokio::test]
async fn write_409_version_conflict() -> TestResult {
    let dc = MockDc::start(Product::Confluence, "").await;
    dc.json(
        "/rest/api/content/65537",
        409,
        CONFLUENCE_VERSION_CONFLICT_409,
    )
    .await;
    let t = test_client(dc.client_config())?;
    assert_eq!(
        t.client
            .send_approved(&test_cover()?, &json_op(page_update(&dc)?))
            .await,
        WriteOutcome::VersionConflict { request_index: 0 }
    );
    Ok(())
}

#[tokio::test]
async fn write_400_version_message_conflict() -> TestResult {
    let cover = test_cover()?;
    for body in [
        CONFLUENCE_VERSION_CONFLICT_400,
        r#"{"errorMessages":["Version conflict: the page was changed"]}"#,
        r#"{"message":"STALE VERSION of the page"}"#,
    ] {
        let dc = MockDc::start(Product::Confluence, "").await;
        dc.json("/rest/api/content/65537", 400, body).await;
        let t = test_client(dc.client_config())?;
        assert_eq!(
            t.client
                .send_approved(&cover, &json_op(page_update(&dc)?))
                .await,
            WriteOutcome::VersionConflict { request_index: 0 },
            "{body}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn write_400_other_failed4xx() -> TestResult {
    let cover = test_cover()?;
    let dc = MockDc::start(Product::Confluence, "").await;
    dc.json("/rest/api/content/65537", 400, CONFLUENCE_ERROR_400)
        .await;
    let t = test_client(dc.client_config())?;
    assert_eq!(
        t.client
            .send_approved(&cover, &json_op(page_update(&dc)?))
            .await,
        WriteOutcome::Failed4xx {
            response: UpstreamResponse {
                status: 400,
                content_type: Some("application/json".into()),
                body: CONFLUENCE_ERROR_400.as_bytes().to_vec(),
            },
            request_index: 0,
        }
    );

    // "version" alone is not a conflict.
    let dc = MockDc::start(Product::Confluence, "").await;
    dc.json(
        "/rest/api/content/65537",
        400,
        r#"{"message":"Invalid version format"}"#,
    )
    .await;
    let t = test_client(dc.client_config())?;
    assert!(matches!(
        t.client
            .send_approved(&cover, &json_op(page_update(&dc)?))
            .await,
        WriteOutcome::Failed4xx { .. }
    ));

    // Version conflicts are a Confluence notion (§5.4 step 6): Jira 400/409 are plain failures.
    for (status, body) in [
        (400, JIRA_ERROR_400),
        (400, r#"{"errorMessages":["version conflict"]}"#),
        (409, "{}"),
    ] {
        let dc = MockDc::start(Product::Jira, "").await;
        dc.json("/rest/api/2/issue", status, body).await;
        let t = test_client(dc.client_config())?;
        let s = spec(
            "POST",
            &url_for(&dc, "/rest/api/2/issue", json!({}))?,
            Some("application/json"),
            b"{}",
        );
        match t.client.send_approved(&cover, &json_op(s)).await {
            WriteOutcome::Failed4xx {
                response,
                request_index: 0,
            } => {
                assert_eq!(
                    (response.status, response.body.as_slice()),
                    (status, body.as_bytes())
                );
            }
            other => return Err(format!("{status} {body}: {other:?}").into()),
        }
    }
    Ok(())
}

/// Pins the outcome the Task 22 handoff relies on: a non-JSON 401 (an SSO page) on a write is
/// `Failed4xx` with the page as its body; core maps it to `upstream_unavailable` (§11.2) and
/// keeps the body out of the agent's view.
#[tokio::test]
async fn write_non_json_401_is_failed4xx() -> TestResult {
    let dc = MockDc::start(Product::Confluence, "").await;
    dc.html("/rest/api/content/65537", 401).await;
    let t = test_client(dc.client_config())?;
    assert_eq!(
        t.client
            .send_approved(&test_cover()?, &json_op(page_update(&dc)?))
            .await,
        WriteOutcome::Failed4xx {
            response: UpstreamResponse {
                status: 401,
                content_type: Some("text/html; charset=UTF-8".into()),
                body: b"<html><body>Please log in</body></html>".to_vec(),
            },
            request_index: 0,
        }
    );
    Ok(())
}

/// What `outcome_bodies_stay_in_the_control` sends: one write answered by `answer`.
async fn write_answered(
    product: Product,
    answer: ResponseTemplate,
    op: fn(HttpRequestSpec) -> ApprovedWrite,
) -> Result<(WriteOutcome, Vec<u8>), Box<dyn std::error::Error>> {
    let dc = MockDc::start(product, "").await;
    Mock::given(path("/rest/api/x"))
        .respond_with(answer)
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    let s = spec(
        "POST",
        &url_for(&dc, "/rest/api/x", json!({}))?,
        Some("application/json"),
        b"{}",
    );
    let ctl = FetchControl::new();
    let out = t
        .client
        .send_approved_ctl(&test_cover()?, &op(s), &ctl)
        .await;
    Ok((out, ctl.take_captured().partial))
}

fn empty_201(s: HttpRequestSpec) -> ApprovedWrite {
    empty_op(s, 201)
}

/// Review I-1: outcomes without a response field leave the answer's bytes in the control, where
/// core takes them for the outcome event (§7.2: such bodies are audit-only); the two outcomes
/// that carry the response take it out of the control.
#[tokio::test]
async fn outcome_bodies_stay_in_the_control() -> TestResult {
    const HTML: &[u8] = b"<html><body>Please log in</body></html>";
    let jdoe = |status: u16| ResponseTemplate::new(status).insert_header("X-AUSERNAME", "jdoe");

    // Undeclared 2xx: an HTML 201 on an `Empty` op.
    let answer = jdoe(201).set_body_raw(HTML, "text/html");
    let (out, kept) = write_answered(Product::Jira, answer, empty_201).await?;
    assert_eq!(out, unknown_status(UnknownReason::UndeclaredSuccess, 201));
    assert_eq!(kept, HTML);

    // 5xx.
    let answer =
        ResponseTemplate::new(503).set_body_raw(r#"{"message":"down"}"#, "application/json");
    let (out, kept) = write_answered(Product::Confluence, answer, json_op).await?;
    assert_eq!(out, unknown_status(UnknownReason::ServerError5xx, 503));
    assert_eq!(kept, br#"{"message":"down"}"#);

    // A Jira 201 attributed to another user: the created issue is named only here.
    let answer = ResponseTemplate::new(201)
        .insert_header("X-AUSERNAME", "bob")
        .set_body_raw(JIRA_ISSUE_CREATED, "application/json");
    let (out, kept) = write_answered(Product::Jira, answer, json_op).await?;
    assert_eq!(
        out,
        unknown_status(
            UnknownReason::IdentityMismatch {
                server_user: Some("bob".into())
            },
            201
        )
    );
    assert_eq!(kept, JIRA_ISSUE_CREATED.as_bytes());

    // JSON 401.
    let answer =
        ResponseTemplate::new(401).set_body_raw(r#"{"statusCode":401}"#, "application/json");
    let (out, kept) = write_answered(Product::Confluence, answer, json_op).await?;
    assert_eq!(out, WriteOutcome::NeedsToken);
    assert_eq!(kept, br#"{"statusCode":401}"#);

    // 3xx: the body is read for the audit record; the redirect is never followed.
    let answer = ResponseTemplate::new(302)
        .insert_header("Location", "/login.jsp")
        .set_body_raw("<html>moved</html>", "text/html");
    let (out, kept) = write_answered(Product::Confluence, answer, json_op).await?;
    assert_eq!(out, WriteOutcome::Unavailable3xx { request_index: 0 });
    assert_eq!(kept, b"<html>moved</html>");

    // The control: `Executed` and `Failed4xx` carry the body and leave the control empty.
    let answer = jdoe(201).set_body_raw(JIRA_ISSUE_CREATED, "application/json");
    let (out, kept) = write_answered(Product::Jira, answer, json_op).await?;
    match out {
        WriteOutcome::Executed { response, .. } => {
            assert_eq!(response.body, JIRA_ISSUE_CREATED.as_bytes());
        }
        other => return Err(format!("{other:?}").into()),
    }
    assert!(kept.is_empty());
    let answer = ResponseTemplate::new(400).set_body_raw(CONFLUENCE_ERROR_400, "application/json");
    let (out, kept) = write_answered(Product::Confluence, answer, json_op).await?;
    match out {
        WriteOutcome::Failed4xx { response, .. } => {
            assert_eq!(response.body, CONFLUENCE_ERROR_400.as_bytes());
        }
        other => return Err(format!("{other:?}").into()),
    }
    assert!(kept.is_empty());
    Ok(())
}

/// A cancel while the answer's body arrives: the request was sent, so the outcome is unknown,
/// and the bytes received so far stay in the control.
#[tokio::test]
async fn write_cancelled_during_the_response_body_is_unknown() -> TestResult {
    const PARTIAL: &[u8] = br#"{"id":"1","#;
    let mut head =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n"
            .to_vec();
    head.extend_from_slice(PARTIAL);
    let server = RawHttpServer::serve(vec![
        RawStep::Send(head),
        RawStep::Sleep(10_000),
        RawStep::Close,
    ])
    .await?;
    let t = test_client(test_config(Product::Confluence, &server.base_url())?)?;
    let url = format!("{}/rest/api/content/1", server.base_url());
    let w = json_op(spec("PUT", &url, Some("application/json"), b"{}"));
    let ctl = FetchControl::new();
    let task = {
        let (client, cover, ctl) = (t.client.clone(), test_cover()?, ctl.clone());
        tokio::spawn(async move { client.send_approved_ctl(&cover, &w, &ctl).await })
    };
    let mut arrived = false;
    for _ in 0..500 {
        if ctl.take_captured().partial == PARTIAL {
            arrived = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(arrived, "the partial body never arrived");
    ctl.cancel();
    assert_eq!(task.await?, unknown_status(UnknownReason::Cancelled, 200));
    let snap = ctl.take_captured();
    assert!(snap.sent);
    assert_eq!(snap.partial, PARTIAL);
    Ok(())
}

/// §5.4 step 6: the one pre-send retry, when it succeeds, writes the request exactly once.
#[tokio::test]
async fn write_presend_retry_succeeds() -> TestResult {
    // The first connection is closed before the TLS handshake (a connection-level failure).
    let tls = TestTlsServer::start_dropping_first(1).await?;
    let mut cfg = test_config(Product::Confluence, &tls.base_url())?;
    cfg.custom_ca_pem = Some(tls.ca_pem().as_bytes().to_vec());
    let t = test_client(cfg)?;
    let url = format!("{}/rest/api/content/1", tls.base_url());
    let w = json_op(spec("PUT", &url, Some("application/json"), b"{}"));
    let out = t.client.send_approved(&test_cover()?, &w).await;
    assert!(matches!(out, WriteOutcome::Executed { .. }), "{out:?}");
    assert_eq!(tls.connections(), 2);
    assert_eq!(tls.handshakes(), 1);
    Ok(())
}

#[tokio::test]
async fn write_json_401_needs_token() -> TestResult {
    let cover = test_cover()?;
    let dc = MockDc::start(Product::Confluence, "").await;
    dc.json(
        "/rest/api/content/65537",
        401,
        r#"{"statusCode":401,"message":"Unauthorized"}"#,
    )
    .await;
    let t = test_client(dc.client_config())?;
    assert_eq!(
        t.client
            .send_approved(&cover, &json_op(page_update(&dc)?))
            .await,
        WriteOutcome::NeedsToken
    );

    // Jira answers a rejected PAT with a JSON 401 and `X-AUSERNAME: anonymous`.
    let dc = MockDc::start(Product::Jira, "").await;
    Mock::given(path("/rest/api/2/issue"))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header("X-AUSERNAME", "anonymous")
                .set_body_raw(
                    r#"{"errorMessages":["You are not authenticated."]}"#,
                    "application/json",
                ),
        )
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    let s = spec(
        "POST",
        &url_for(&dc, "/rest/api/2/issue", json!({}))?,
        Some("application/json"),
        b"{}",
    );
    assert_eq!(
        t.client.send_approved(&cover, &json_op(s)).await,
        WriteOutcome::NeedsToken
    );
    Ok(())
}

#[tokio::test]
async fn write_5xx_outcome_unknown() -> TestResult {
    let cover = test_cover()?;
    let dc = MockDc::start(Product::Confluence, "").await;
    dc.json("/rest/api/content/65537", 503, r#"{"message":"down"}"#)
        .await;
    dc.html("/rest/api/content/2", 500).await;
    let t = test_client(dc.client_config())?;
    assert_eq!(
        t.client
            .send_approved(&cover, &json_op(page_update(&dc)?))
            .await,
        unknown_status(UnknownReason::ServerError5xx, 503)
    );
    let s = spec(
        "PUT",
        &url_for(&dc, "/rest/api/content/2", json!({}))?,
        Some("application/json"),
        b"{}",
    );
    assert_eq!(
        t.client.send_approved(&cover, &json_op(s)).await,
        unknown_status(UnknownReason::ServerError5xx, 500)
    );
    Ok(())
}

#[tokio::test]
async fn write_timeout_after_send_outcome_unknown() -> TestResult {
    // The server reads the whole request, then stalls past the (shortened) 60 s write budget.
    let silent = RawHttpServer::serve(vec![RawStep::Sleep(2000), RawStep::Close]).await?;
    let mut cfg = test_config(Product::Confluence, &silent.base_url())?;
    cfg.timeouts.write = Duration::from_millis(300);
    let t = test_client(cfg)?;
    let url = format!("{}/rest/api/content/1", silent.base_url());
    let ctl = FetchControl::new();
    assert_eq!(
        t.client
            .send_approved_ctl(
                &test_cover()?,
                &json_op(spec("PUT", &url, Some("application/json"), b"{}")),
                &ctl
            )
            .await,
        unknown_status(UnknownReason::Timeout, None)
    );
    assert!(ctl.take_captured().sent);
    let heads = silent.request_heads();
    assert_eq!(heads.len(), 1);
    assert!(heads[0].starts_with(b"PUT /rest/api/content/1 HTTP/1.1\r\n"));

    // The write budget, not the 30 s per-call one, bounds a write: a 600 ms answer with a
    // 300 ms per-call timeout and a 2 s write budget executes.
    let slow = RawHttpServer::serve(vec![
        RawStep::Sleep(600),
        RawStep::Send(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
                .to_vec(),
        ),
        RawStep::Close,
    ])
    .await?;
    let mut cfg = test_config(Product::Confluence, &slow.base_url())?;
    cfg.timeouts.per_call = Duration::from_millis(300);
    cfg.timeouts.write = Duration::from_secs(2);
    let t = test_client(cfg)?;
    let url = format!("{}/rest/api/content/1", slow.base_url());
    let out = t
        .client
        .send_approved(
            &test_cover()?,
            &json_op(spec("PUT", &url, Some("application/json"), b"{}")),
        )
        .await;
    assert!(matches!(out, WriteOutcome::Executed { .. }), "{out:?}");

    // Headers arrived, the body stalls: still unknown.
    let partial = RawHttpServer::serve(vec![
        RawStep::Send(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{\"a\"".to_vec()),
        RawStep::Sleep(2000),
        RawStep::Close,
    ])
    .await?;
    let mut cfg = test_config(Product::Confluence, &partial.base_url())?;
    cfg.timeouts.write = Duration::from_millis(300);
    let t = test_client(cfg)?;
    let url = format!("{}/rest/api/content/1", partial.base_url());
    assert_eq!(
        t.client
            .send_approved(
                &test_cover()?,
                &json_op(spec("PUT", &url, Some("application/json"), b"{}"))
            )
            .await,
        unknown_status(UnknownReason::Timeout, 200)
    );
    Ok(())
}

#[tokio::test]
async fn write_identity_anonymous_outcome_unknown() -> TestResult {
    async fn jira_write(
        header: XAuser,
        status: u16,
        body: Option<&str>,
        success: ApprovedWrite,
    ) -> Result<WriteOutcome, Box<dyn std::error::Error>> {
        let dc = MockDc::start(Product::Jira, "").await;
        let mut t = ResponseTemplate::new(status);
        t = match &header {
            XAuser::Same => t.insert_header("X-AUSERNAME", "jdoe"),
            XAuser::Missing => t,
            XAuser::Anonymous => t.insert_header("X-AUSERNAME", "anonymous"),
            XAuser::Other(v) | XAuser::Raw(v) => t.insert_header("X-AUSERNAME", v.as_str()),
        };
        if let Some(b) = body {
            t = t.set_body_raw(b, "application/json");
        }
        Mock::given(path("/rest/api/2/issue"))
            .respond_with(t)
            .mount(dc.server())
            .await;
        let c = test_client(dc.client_config())?;
        let mut w = success;
        w.requests[0].resolved_url = url_for(&dc, "/rest/api/2/issue", json!({}))?;
        Ok(c.client.send_approved(&test_cover()?, &w).await)
    }
    let s = spec("POST", "", Some("application/json"), b"{}");
    let mismatch = |u: Option<&str>, status: u16| {
        unknown_status(
            UnknownReason::IdentityMismatch {
                server_user: u.map(str::to_owned),
            },
            status,
        )
    };

    assert_eq!(
        jira_write(
            XAuser::Anonymous,
            201,
            Some(JIRA_ISSUE_CREATED),
            json_op(s.clone())
        )
        .await?,
        mismatch(Some("anonymous"), 201)
    );
    assert_eq!(
        jira_write(
            XAuser::Other("bob".into()),
            201,
            Some(JIRA_ISSUE_CREATED),
            json_op(s.clone())
        )
        .await?,
        mismatch(Some("bob"), 201)
    );
    // A declared-empty success is checked too, whatever its content type.
    assert_eq!(
        jira_write(XAuser::Missing, 204, None, empty_op(s.clone(), 204)).await?,
        mismatch(None, 204)
    );
    // An error answer not attributed to the PAT's user is audit-only, never a plain failure.
    assert_eq!(
        jira_write(
            XAuser::Missing,
            400,
            Some(JIRA_ERROR_400),
            json_op(s.clone())
        )
        .await?,
        mismatch(None, 400)
    );
    // The control: the PAT's user (the comparison folds case); the raw header is reported.
    assert!(matches!(
        jira_write(XAuser::Raw("JDoe".into()), 201, Some(JIRA_ISSUE_CREATED), json_op(s.clone())).await?,
        WriteOutcome::Executed { server_user: Some(u), .. } if u == "JDoe"
    ));

    // Confluence write responses are not header-checked (§7.2).
    let dc = MockDc::start(Product::Confluence, "").await;
    dc.json("/rest/api/content/65537", 200, CONFLUENCE_PAGE_UPDATED)
        .await;
    let t = test_client(dc.client_config())?;
    assert!(matches!(
        t.client
            .send_approved(&test_cover()?, &json_op(page_update(&dc)?))
            .await,
        WriteOutcome::Executed {
            server_user: None,
            request_index: 0,
            ..
        }
    ));
    Ok(())
}

/// §5.4 step 6: a connection error before any byte was sent is retried once; when it persists,
/// nothing left and the write is `NotSent`.
#[tokio::test]
async fn write_presend_connection_not_sent() -> TestResult {
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
    let url = format!("{}/rest/api/content/1", tls.base_url());
    let ctl = FetchControl::new();
    assert_eq!(
        t.client
            .send_approved_ctl(
                &test_cover()?,
                &json_op(spec("PUT", &url, Some("application/json"), b"{}")),
                &ctl
            )
            .await,
        WriteOutcome::NotSent {
            reason: NotSentReason::Connection(ConnClass::ProxyConnect407)
        }
    );
    // One retry: two CONNECTs, and the server never saw a handshake.
    assert_eq!(proxy.request_heads().len(), 2);
    assert_eq!(tls.handshakes(), 0);

    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let base = format!("http://127.0.0.1:{port}");
    let t = test_client(test_config(Product::Confluence, &base)?)?;
    assert_eq!(
        t.client
            .send_approved(
                &test_cover()?,
                &json_op(spec(
                    "PUT",
                    &format!("{base}/rest/api/content/1"),
                    None,
                    b""
                ))
            )
            .await,
        WriteOutcome::NotSent {
            reason: NotSentReason::Connection(ConnClass::Connect)
        }
    );
    Ok(())
}

#[tokio::test]
async fn write_429_retried() -> TestResult {
    let dc = MockDc::start(Product::Jira, "").await;
    Mock::given(path("/rest/api/2/issue"))
        .respond_with(
            dc.response(429)
                .insert_header("Retry-After", "0")
                .set_body_raw(r#"{"message":"slow down"}"#, "application/json"),
        )
        .up_to_n_times(1)
        .mount(dc.server())
        .await;
    Mock::given(path("/rest/api/2/issue"))
        .respond_with(
            dc.response(201)
                .set_body_raw(JIRA_ISSUE_CREATED, "application/json"),
        )
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    let s = spec(
        "POST",
        &url_for(&dc, "/rest/api/2/issue", json!({}))?,
        Some("application/json"),
        br#"{"fields":{}}"#,
    );
    assert!(matches!(
        t.client
            .send_approved(&test_cover()?, &json_op(s.clone()))
            .await,
        WriteOutcome::Executed { .. }
    ));
    let got = dc.received().await;
    assert_eq!(got.len(), 2);
    for r in &got {
        assert_eq!(
            (r.method.as_str(), wire_url(r), r.body.as_slice()),
            (s.method.as_str(), s.resolved_url.clone(), s.body.as_slice())
        );
    }

    // Four 429s: the last one is the answer, a plain failure.
    let dc = MockDc::start(Product::Confluence, "").await;
    Mock::given(path("/rest/api/content/65537"))
        .respond_with(
            dc.response(429)
                .insert_header("Retry-After", "0")
                .set_body_raw("{}", "application/json"),
        )
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    match t
        .client
        .send_approved(&test_cover()?, &json_op(page_update(&dc)?))
        .await
    {
        WriteOutcome::Failed4xx { response, .. } => assert_eq!(response.status, 429),
        other => return Err(format!("{other:?}").into()),
    }
    assert_eq!(dc.received().await.len(), 4);
    Ok(())
}

/// Nothing of the write left: its budget ran out, or it was cancelled, while every limiter permit
/// was taken. Never `OutcomeUnknown`.
#[tokio::test]
async fn write_waiting_for_a_permit_is_not_sent() -> TestResult {
    let server = RawHttpServer::serve(vec![
        RawStep::Sleep(1500),
        RawStep::Send(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
                .to_vec(),
        ),
        RawStep::Close,
    ])
    .await?;
    let mut cfg = test_config(Product::Confluence, &server.base_url())?;
    cfg.timeouts.write = Duration::from_millis(200);
    let t = test_client(cfg)?;
    let cover = test_cover()?;
    let mut held = Vec::new();
    for _ in 0..4 {
        let (client, cover) = (t.client.clone(), cover.clone());
        held.push(tokio::spawn(async move {
            let call = GetCall {
                endpoint_template: "/rest/api/space".into(),
                params: json!({}),
                query: vec![],
            };
            client.get(&cover, &call).await
        }));
    }
    for _ in 0..500 {
        if server.connections() == 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(server.connections(), 4);
    let url = format!("{}/rest/api/content/1", server.base_url());
    let w = json_op(spec("PUT", &url, Some("application/json"), b"{}"));

    let ctl = FetchControl::new();
    assert_eq!(
        t.client.send_approved_ctl(&cover, &w, &ctl).await,
        WriteOutcome::NotSent {
            reason: NotSentReason::BudgetExpired
        }
    );
    assert!(!ctl.take_captured().sent);

    let ctl = FetchControl::new();
    ctl.cancel();
    assert_eq!(
        t.client.send_approved_ctl(&cover, &w, &ctl).await,
        WriteOutcome::NotSent {
            reason: NotSentReason::Cancelled
        }
    );

    for task in held {
        task.await?;
    }
    assert_eq!(server.connections(), 4);
    Ok(())
}
