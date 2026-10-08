//! Offset pagination (§7.2, §7.5): server arithmetic, end signals, `next_start`, the context path
//! (U-04 / I-22 half), the 50 MiB fetch cap, the read budget and cancel capture.

use std::time::Duration;

use atlas_duck_atlassian::testing::fixtures::{
    confluence_space_page, confluence_space_page_padded, jira_board_page, jira_search_page,
};
use atlas_duck_atlassian::testing::{
    MockDc, RawHttpServer, RawStep, TestClient, test_client, test_config, test_cover,
};
use atlas_duck_atlassian::{
    FetchControl, FetchFailure, GetCall, IdentityObserved, PageEnd, PagedCall, PostSendKind,
    Product, ReadBudget, SearchCall,
};
use serde_json::{Value, json};
use wiremock::matchers::{any, method, path};
use wiremock::{Mock, Request, ResponseTemplate};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MIB: usize = 1024 * 1024;
const NEXT: &str = "/rest/api/space?limit=25&start=25";

fn space_call(page_size: u32, start: u64) -> PagedCall {
    PagedCall {
        get: GetCall {
            endpoint_template: "/rest/api/space".into(),
            params: json!({}),
            query: vec![("type".into(), "global".into())],
        },
        items_key: "results".into(),
        offset_param: "start".into(),
        limit_param: "limit".into(),
        page_size,
        start,
    }
}

fn board_call(page_size: u32, start: u64) -> PagedCall {
    PagedCall {
        get: GetCall {
            endpoint_template: "/rest/agile/1.0/board".into(),
            params: json!({}),
            query: vec![],
        },
        items_key: "values".into(),
        offset_param: "startAt".into(),
        limit_param: "maxResults".into(),
        page_size,
        start,
    }
}

fn param(req: &Request, key: &str) -> Option<u64> {
    req.url
        .query_pairs()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| v.parse().ok())
}

/// `(offset, limit)` of every received request, from the query.
fn offsets(got: &[Request], offset: &str, limit: &str) -> Vec<(Option<u64>, Option<u64>)> {
    got.iter()
        .map(|r| (param(r, offset), param(r, limit)))
        .collect()
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

/// Answers `/rest/api/space` pages from the request's `start`/`limit`: `total` spaces in all,
/// `_links.next` (origin-relative, as Confluence DC sends it) on every page but the last.
fn space_pages(
    dc: &MockDc,
    total: u64,
    pad: usize,
) -> impl Fn(&Request) -> ResponseTemplate + Send + Sync + 'static {
    let ok = dc.response(200);
    move |req: &Request| {
        let start = param(req, "start").unwrap_or(0);
        let limit = param(req, "limit").unwrap_or(25);
        let size = limit.min(total.saturating_sub(start));
        let next = (start + size < total)
            .then(|| format!("/rest/api/space?limit={limit}&start={}", start + size));
        ok.clone().set_body_raw(
            confluence_space_page_padded(start, limit, size, next.as_deref(), pad),
            "application/json",
        )
    }
}

#[tokio::test]
async fn jira_search_offset_arithmetic() -> TestResult {
    let dc = MockDc::start(Product::Jira, "/jira").await;
    let ok = dc.response(200);
    Mock::given(method("POST"))
        .and(path(dc.path("/rest/api/2/search")))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let start = body["startAt"].as_u64().unwrap_or(0);
            let max = body["maxResults"].as_u64().unwrap_or(0);
            // Three pages of (at most) 50 over 120 issues.
            let count = max.min(120u64.saturating_sub(start));
            ok.clone()
                .set_body_raw(jira_search_page(start, max, 120, count), "application/json")
        })
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    let call = SearchCall {
        endpoint_template: "/rest/api/2/search".into(),
        body: json!({"jql": "project = ABC", "fields": ["summary"], "startAt": 0, "maxResults": 50}),
    };
    let ctl = FetchControl::new();
    let out = t
        .client
        .read_paginated_search_ctl(
            &test_cover()?,
            &call,
            "issues",
            &ReadBudget::default(),
            500,
            &ctl,
        )
        .await;

    assert_eq!(out.end, PageEnd::ResultsEnded);
    assert_eq!(out.failure, None);
    assert_eq!(out.items_fetched, 120);
    assert_eq!(out.next_start, None);
    assert_eq!(out.server_total, Some(120));
    assert_eq!(out.pages.len(), 3);
    assert_eq!(ctl.take_captured().pages, out.pages);

    let got = dc.received().await;
    let bodies: Vec<Value> = got
        .iter()
        .map(|r| serde_json::from_slice(&r.body))
        .collect::<Result<_, _>>()?;
    let starts: Vec<&Value> = bodies.iter().map(|b| &b["startAt"]).collect();
    assert_eq!(starts, [&json!(0), &json!(50), &json!(100)]);
    for (r, b) in got.iter().zip(&bodies) {
        assert_eq!(r.method.as_str(), "POST");
        assert_eq!(r.url.path(), "/jira/rest/api/2/search");
        // The rest of the body template is kept on every page.
        assert_eq!(b["jql"], "project = ABC");
        assert_eq!(b["fields"], json!(["summary"]));
        assert_eq!(b["maxResults"], 50);
    }
    Ok(())
}

#[tokio::test]
async fn jira_agile_pages_until_is_last() -> TestResult {
    let dc = MockDc::start(Product::Jira, "").await;
    let ok = dc.response(200);
    Mock::given(path("/rest/agile/1.0/board"))
        .respond_with(move |req: &Request| {
            let start = param(req, "startAt").unwrap_or(0);
            // No `total`; only `isLast` on the second page says the results ended.
            let page = json!({
                "maxResults": 2,
                "startAt": start,
                "isLast": start >= 2,
                "values": [{"id": start + 1}, {"id": start + 2}]
            });
            ok.clone()
                .set_body_raw(page.to_string(), "application/json")
        })
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    let out = t
        .client
        .read_paginated(&test_cover()?, &board_call(2, 0), &ReadBudget::default())
        .await;
    assert_eq!(out.end, PageEnd::ResultsEnded);
    assert_eq!(out.items_fetched, 4);
    assert_eq!(out.next_start, None);
    assert_eq!(out.server_total, None);
    assert_eq!(
        offsets(&dc.received().await, "startAt", "maxResults"),
        [(Some(0), Some(2)), (Some(2), Some(2))]
    );
    Ok(())
}

#[tokio::test]
async fn confluence_size_arithmetic() -> TestResult {
    let dc = MockDc::start(Product::Confluence, "").await;
    Mock::given(path("/rest/api/space"))
        .respond_with(space_pages(&dc, 35, 0))
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    let out = t
        .client
        .read_paginated(&test_cover()?, &space_call(25, 0), &ReadBudget::default())
        .await;
    assert_eq!(out.end, PageEnd::ResultsEnded);
    assert_eq!(out.items_fetched, 35);
    assert_eq!(out.next_start, None);
    assert_eq!(out.pages.len(), 2);

    let got = dc.received().await;
    // `start` 0 then 0 + size(25); the second page's size 10 < limit 25 ends the results.
    assert_eq!(
        offsets(&got, "start", "limit"),
        [(Some(0), Some(25)), (Some(25), Some(25))]
    );
    // The call's own query pairs come first and stay on every page.
    for r in &got {
        assert!(
            r.url.query().unwrap_or("").starts_with("type=global&"),
            "{}",
            r.url
        );
    }

    // `start` advances by the server's `size` field, not by what was asked for.
    let dc = MockDc::start(Product::Confluence, "").await;
    let ok = dc.response(200);
    Mock::given(path("/rest/api/space"))
        .respond_with(move |req: &Request| {
            let start = param(req, "start").unwrap_or(0);
            let size = if start == 0 { 20 } else { 3 };
            ok.clone().set_body_raw(
                confluence_space_page(start, 20, size, (start == 0).then_some(NEXT)),
                "application/json",
            )
        })
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    let out = t
        .client
        .read_paginated(&test_cover()?, &space_call(25, 0), &ReadBudget::default())
        .await;
    assert_eq!((out.end, out.items_fetched), (PageEnd::ResultsEnded, 23));
    let got = dc.received().await;
    // The server clamped the page to 20, so the second page starts at 20 and asks for 20.
    assert_eq!(
        offsets(&got, "start", "limit"),
        [(Some(0), Some(25)), (Some(20), Some(20))]
    );
    Ok(())
}

#[tokio::test]
async fn max_reached_sets_next_start() -> TestResult {
    let dc = MockDc::start(Product::Jira, "").await;
    let ok = dc.response(200);
    Mock::given(path("/rest/agile/1.0/board"))
        .respond_with(move |req: &Request| {
            let start = param(req, "startAt").unwrap_or(0);
            let max = param(req, "maxResults").unwrap_or(0);
            let count = max.min(500u64.saturating_sub(start));
            ok.clone().set_body_raw(
                jira_board_page(start, max, Some(500), count),
                "application/json",
            )
        })
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    let cover = test_cover()?;
    let ctl = FetchControl::new();
    let out = t
        .client
        .read_paginated_ctl(&cover, &board_call(50, 0), &ReadBudget::default(), 60, &ctl)
        .await;
    assert_eq!(out.end, PageEnd::MaxReached);
    assert_eq!(out.failure, None);
    assert_eq!(out.items_fetched, 60);
    assert_eq!(out.next_start, Some(60));
    assert_eq!(out.server_total, Some(500));
    // The last page asks only for what is left of `max`.
    assert_eq!(
        offsets(&dc.received().await, "startAt", "maxResults"),
        [(Some(0), Some(50)), (Some(50), Some(10))]
    );

    // From the agent's `start`: next_start = start + items the server returned.
    let out = t
        .client
        .read_paginated_ctl(
            &cover,
            &board_call(50, 100),
            &ReadBudget::default(),
            60,
            &FetchControl::new(),
        )
        .await;
    assert_eq!((out.end, out.next_start), (PageEnd::MaxReached, Some(160)));

    // Results that end exactly at `max` are not truncated.
    let out = t
        .client
        .read_paginated_ctl(
            &cover,
            &board_call(50, 450),
            &ReadBudget::default(),
            50,
            &FetchControl::new(),
        )
        .await;
    assert_eq!(
        (out.end, out.next_start, out.items_fetched),
        (PageEnd::ResultsEnded, None, 50)
    );
    Ok(())
}

/// U-04 / I-22: Confluence DC's `_links.next` is origin-relative without the context path; it is
/// never followed, and every page is rebuilt from the template under the configured base URL.
#[tokio::test]
async fn u04_pagination_stays_under_context_path() -> TestResult {
    let dc = MockDc::start(Product::Confluence, "/confluence").await;
    Mock::given(path("/confluence/rest/api/space"))
        .respond_with(space_pages(&dc, 53, 0))
        .with_priority(1)
        .mount(dc.server())
        .await;
    // Whatever a followed `_links.next` would reach.
    Mock::given(any())
        .respond_with(
            dc.response(200)
                .set_body_raw(r#"{"results":[]}"#, "application/json"),
        )
        .with_priority(10)
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    let out = t
        .client
        .read_paginated(&test_cover()?, &space_call(25, 0), &ReadBudget::default())
        .await;
    assert_eq!((out.end, out.items_fetched), (PageEnd::ResultsEnded, 53));

    let got = dc.received().await;
    assert_eq!(got.len(), 3);
    assert!(
        got.iter()
            .all(|r| r.url.path() == "/confluence/rest/api/space"),
        "{:?}",
        got.iter().map(|r| r.url.to_string()).collect::<Vec<_>>()
    );
    assert_eq!(
        offsets(&got, "start", "limit"),
        [
            (Some(0), Some(25)),
            (Some(25), Some(25)),
            (Some(50), Some(25))
        ]
    );
    // The page answers did carry the origin-relative link.
    let first: Value = serde_json::from_slice(&out.pages[0].body)?;
    assert_eq!(first["_links"]["next"], NEXT);
    Ok(())
}

#[tokio::test]
async fn fetch_cap_50mib() -> TestResult {
    let dc = MockDc::start(Product::Confluence, "").await;
    Mock::given(path("/rest/api/space"))
        .respond_with(space_pages(&dc, 1000, 20 * MIB))
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    let ctl = FetchControl::new();
    let out = t
        .client
        .read_paginated_ctl(
            &test_cover()?,
            &space_call(25, 0),
            &ReadBudget::default(),
            1000,
            &ctl,
        )
        .await;
    assert_eq!(out.end, PageEnd::FetchCap50MiB);
    assert_eq!(out.pages.len(), 2);
    assert_eq!(out.items_fetched, 50);
    assert_eq!(out.next_start, Some(50));
    assert_eq!(ctl.take_captured().pages.len(), 2);
    let complete: usize = out.pages.iter().map(|p| p.body.len()).sum();
    assert!(complete <= 50 * MIB);
    match out.failure {
        Some(FetchFailure::PostSend { kind, received }) => {
            assert_eq!(kind, PostSendKind::FetchCap50MiB);
            // Page 3 was cut where the 50 MiB were exceeded, by at most one read chunk.
            let left = 50 * MIB - complete;
            assert!(received.len() > left, "{} vs {left}", received.len());
            assert!(
                received.len() <= left + 512 * 1024,
                "{} vs {left}",
                received.len()
            );
        }
        other => return Err(format!("{other:?}").into()),
    }
    assert_eq!(dc.received().await.len(), 3);
    Ok(())
}

#[tokio::test]
async fn read_budget_120s_is_configurable_in_tests() -> TestResult {
    let dc = MockDc::start(Product::Confluence, "").await;
    let pages = space_pages(&dc, 1000, 0);
    // Page 1 ends at ~1 s, inside the 1.5 s budget; page 2 cannot end before ~2 s.
    Mock::given(path("/rest/api/space"))
        .respond_with(move |req: &Request| pages(req).set_delay(Duration::from_millis(1000)))
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    let budget = ReadBudget {
        total: Duration::from_millis(1500),
        ..ReadBudget::default()
    };
    let out = t
        .client
        .read_paginated(&test_cover()?, &space_call(25, 0), &budget)
        .await;
    assert_eq!(out.end, PageEnd::ReadBudget120s);
    assert_eq!(out.pages.len(), 1);
    assert_eq!(out.next_start, Some(25));
    assert_eq!(
        out.failure,
        Some(FetchFailure::PostSend {
            kind: PostSendKind::ReadBudget120s,
            received: vec![],
        })
    );
    Ok(())
}

fn raw_page(body: &str) -> Vec<RawStep> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    vec![
        RawStep::Send([head.as_bytes(), body.as_bytes()].concat()),
        RawStep::Close,
    ]
}

fn raw_client(server: &RawHttpServer) -> Result<TestClient, Box<dyn std::error::Error>> {
    Ok(test_client(test_config(
        Product::Confluence,
        &server.base_url(),
    )?)?)
}

#[tokio::test]
async fn cancel_mid_page3_captures_pages_and_partial() -> TestResult {
    let page3 = confluence_space_page(50, 25, 25, Some(NEXT));
    let mut partial = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        page3.len()
    )
    .into_bytes();
    partial.extend_from_slice(&page3.as_bytes()[..1000]);
    let server = RawHttpServer::serve_sequence(vec![
        raw_page(&confluence_space_page(0, 25, 25, Some(NEXT))),
        raw_page(&confluence_space_page(25, 25, 25, Some(NEXT))),
        vec![
            RawStep::Send(partial),
            RawStep::Sleep(10_000),
            RawStep::Close,
        ],
    ])
    .await?;
    let t = raw_client(&server)?;
    let ctl = FetchControl::new();
    let task = {
        let (client, cover, ctl) = (t.client.clone(), test_cover()?, ctl.clone());
        tokio::spawn(async move {
            client
                .read_paginated_ctl(
                    &cover,
                    &space_call(25, 0),
                    &ReadBudget::default(),
                    1000,
                    &ctl,
                )
                .await
        })
    };
    wait_for(|| {
        let c = ctl.take_captured();
        c.pages.len() == 2 && c.partial.len() == 1000
    })
    .await?;

    ctl.cancel();
    let snap = ctl.take_captured();
    assert!(snap.sent);
    assert_eq!(snap.pages.len(), 2);
    assert_eq!(snap.partial.len(), 1000);

    let out = task.await?;
    assert_eq!(out.end, PageEnd::Failed);
    assert_eq!(out.pages, snap.pages);
    assert_eq!(out.items_fetched, 50);
    assert_eq!(out.next_start, Some(50));
    match out.failure {
        Some(FetchFailure::CancelledInFlight { bytes_received }) => {
            assert_eq!(bytes_received, &page3.as_bytes()[..1000]);
        }
        other => return Err(format!("{other:?}").into()),
    }
    assert_eq!(server.connections(), 3);
    Ok(())
}

#[tokio::test]
async fn upstream_error_on_page_2_ends_failed() -> TestResult {
    let dc = MockDc::start(Product::Confluence, "").await;
    let pages = space_pages(&dc, 1000, 0);
    let gone = dc.response(404).set_body_raw(
        r#"{"statusCode":404,"message":"No space"}"#,
        "application/json",
    );
    Mock::given(path("/rest/api/space"))
        .respond_with(move |req: &Request| {
            if param(req, "start") == Some(25) {
                gone.clone()
            } else {
                pages(req)
            }
        })
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    let out = t
        .client
        .read_paginated(&test_cover()?, &space_call(25, 0), &ReadBudget::default())
        .await;
    // The error response is the last page; there is no `failure`.
    assert_eq!(out.end, PageEnd::Failed);
    assert_eq!(out.failure, None);
    assert_eq!(out.pages.len(), 2);
    assert_eq!(out.pages[1].status, 404);
    assert_eq!(out.items_fetched, 25);
    assert_eq!(out.next_start, Some(25));
    Ok(())
}

/// Every page of a Jira read is identity-checked (§7.2).
#[tokio::test]
async fn jira_identity_is_checked_on_every_page() -> TestResult {
    let dc = MockDc::start(Product::Jira, "").await;
    let ok = dc.response(200);
    Mock::given(path("/rest/agile/1.0/board"))
        .respond_with(move |req: &Request| {
            let start = param(req, "startAt").unwrap_or(0);
            let body = jira_board_page(start, 2, Some(10), 2);
            if start == 0 {
                ok.clone().set_body_raw(body, "application/json")
            } else {
                // A reverse proxy stripped the header on page 2.
                ResponseTemplate::new(200).set_body_raw(body, "application/json")
            }
        })
        .mount(dc.server())
        .await;
    let t = test_client(dc.client_config())?;
    let out = t
        .client
        .read_paginated(&test_cover()?, &board_call(2, 0), &ReadBudget::default())
        .await;
    assert_eq!(out.end, PageEnd::Failed);
    assert_eq!(out.pages.len(), 1);
    assert_eq!(out.next_start, Some(2));
    match out.failure {
        Some(FetchFailure::IdentityCheckFailed { observed, .. }) => {
            assert_eq!(observed, IdentityObserved::Missing);
        }
        other => return Err(format!("{other:?}").into()),
    }
    Ok(())
}
