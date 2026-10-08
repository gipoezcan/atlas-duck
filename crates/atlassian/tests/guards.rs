use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use atlas_duck_atlassian::{
    CommitProbe, CoverIssuer, FetchFailure, GetCall, HttpRequestSpec, NotCommitted, PagedCall,
    PostSendKind, ReadBudget, SearchCall, TemplateError, UpstreamResponse, build_url,
    normalize_base_url,
};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Default)]
struct SetProbe {
    requests: Mutex<HashSet<String>>,
    fetches: Mutex<HashSet<String>>,
}

impl CommitProbe for SetProbe {
    fn request_committed(&self, request_id: &str) -> bool {
        self.requests
            .lock()
            .map(|s| s.contains(request_id))
            .unwrap_or(false)
    }
    fn system_fetch_started(&self, fetch_id: &str) -> bool {
        self.fetches
            .lock()
            .map(|s| s.contains(fetch_id))
            .unwrap_or(false)
    }
}

#[test]
fn cover_refused_until_committed() -> TestResult {
    let probe = Arc::new(SetProbe::default());
    let issuer = CoverIssuer::new(probe.clone());
    assert_eq!(issuer.for_request("req_a").err(), Some(NotCommitted));
    assert_eq!(issuer.for_system_fetch("fetch_a").err(), Some(NotCommitted));

    probe
        .requests
        .lock()
        .map_err(|_| "poisoned")?
        .insert("req_a".to_owned());
    let cover = issuer.for_request("req_a")?;
    assert_eq!(cover.request_id(), Some("req_a"));
    assert_eq!(cover.fetch_id(), None);
    // The two sets are separate: a committed request is not a started system fetch.
    assert!(issuer.for_system_fetch("req_a").is_err());

    probe
        .fetches
        .lock()
        .map_err(|_| "poisoned")?
        .insert("fetch_a".to_owned());
    let cover = issuer.for_system_fetch("fetch_a")?;
    assert_eq!(cover.fetch_id(), Some("fetch_a"));
    assert_eq!(cover.request_id(), None);
    assert!(issuer.for_request("fetch_a").is_err());
    Ok(())
}

fn base() -> Result<atlas_duck_atlassian::NormalizedBaseUrl, Box<dyn std::error::Error>> {
    Ok(normalize_base_url("https://jira.corp/jira")?)
}

#[test]
fn build_url_rules() -> TestResult {
    let b = base()?;
    let u = build_url(&b, "/rest/api/2/issue/{key}", &json!({"key": "ABC-1"}), &[])?;
    assert_eq!(u.as_str(), "https://jira.corp/jira/rest/api/2/issue/ABC-1");

    let u = build_url(&b, "/rest/api/2/issue/{key}", &json!({"key": "a/b"}), &[])?;
    assert_eq!(u.as_str(), "https://jira.corp/jira/rest/api/2/issue/a%2Fb");

    assert_eq!(
        build_url(&b, "/rest/api/2/issue/{key}", &json!({"key": ".."}), &[]).err(),
        Some(TemplateError::BadParam("key".into()))
    );
    assert_eq!(
        build_url(&b, "/rest/api/2/issue/{key}", &json!({}), &[]).err(),
        Some(TemplateError::MissingParam("key".into()))
    );

    let q = vec![("jql".to_owned(), "a&b=c#d".to_owned())];
    let u = build_url(&b, "/rest/api/2/field", &json!({}), &q)?;
    assert_eq!(u.query(), Some("jql=a%26b%3Dc%23d"));
    assert_eq!(u.fragment(), None);

    let c = normalize_base_url("https://wiki.corp")?;
    let u = build_url(
        &c,
        "/rest/api/content/{id}/label/{label}",
        &json!({"id": 123, "label": "x y"}),
        &[],
    )?;
    assert_eq!(
        u.as_str(),
        "https://wiki.corp/rest/api/content/123/label/x%20y"
    );
    Ok(())
}

#[test]
fn build_url_refuses_traversal_and_bad_values() -> TestResult {
    let b = base()?;
    let t = "/rest/api/2/issue/{key}";
    for bad in [
        json!({"key": ""}),
        json!({"key": "."}),
        json!({"key": "a/.."}),
        json!({"key": "%2e%2e"}),
        json!({"key": "..;x"}),
        json!({"key": "a\\.."}),
        json!({"key": 1.5}),
        json!({"key": true}),
        json!({"key": ["a"]}),
        json!({"key": {"a": 1}}),
    ] {
        assert!(
            matches!(build_url(&b, t, &bad, &[]), Err(TemplateError::BadParam(_))),
            "{bad}"
        );
    }
    assert_eq!(
        build_url(&b, t, &json!({"key": null}), &[]).err(),
        Some(TemplateError::MissingParam("key".into()))
    );
    // Integers render as decimal; the result stays under the context path.
    let u = build_url(&b, t, &json!({"key": -7}), &[])?;
    assert_eq!(u.path(), "/jira/rest/api/2/issue/-7");
    // Never a full URL, query, fragment, protocol-relative path, or traversal in the template.
    for bad in [
        "https://evil.example/x",
        "rest/api/2/x",
        "//evil.example/x",
        "/rest/api/2/x?y=1",
        "/rest/api/2/x#f",
        "/rest/../x",
        "/rest/%2e%2e/x",
        "/rest/{key",
        "/rest/key}",
        "/rest/{k{ey}",
    ] {
        assert!(
            build_url(&b, bad, &json!({"key": "a"}), &[]).is_err(),
            "{bad}"
        );
    }
    // A value cannot escape the host or the context path.
    let u = build_url(&b, t, &json!({"key": "@evil.example"}), &[])?;
    assert_eq!(u.host_str(), Some("jira.corp"));
    assert_eq!(u.path(), "/jira/rest/api/2/issue/%40evil.example");
    Ok(())
}

#[test]
fn debug_is_redacted() {
    let r = UpstreamResponse {
        status: 200,
        content_type: Some("application/json".into()),
        body: b"secret-canary".to_vec(),
    };
    let s = format!("{r:?}");
    assert!(!s.contains("secret-canary"), "{s}");
    assert!(s.contains("200") && s.contains("len=13"), "{s}");

    let spec = HttpRequestSpec {
        index: 0,
        method: "POST".into(),
        resolved_url: "https://jira.corp/rest/api/2/issue?canary=1".into(),
        content_type: Some("application/json".into()),
        body: b"secret-canary".to_vec(),
    };
    let s = format!("{spec:?}");
    assert!(!s.contains("canary"), "{s}");
    assert!(s.contains("POST") && s.contains("len=13"), "{s}");

    let get = GetCall {
        endpoint_template: "/rest/api/2/issue/{key}".into(),
        params: json!({"jql": "canary"}),
        query: vec![("jql".into(), "canary".into())],
    };
    let s = format!("{get:?}");
    assert!(!s.contains("canary"), "{s}");

    let paged = PagedCall {
        get: get.clone(),
        items_key: "issues".into(),
        offset_param: "startAt".into(),
        limit_param: "maxResults".into(),
        page_size: 50,
        start: 0,
    };
    assert!(!format!("{paged:?}").contains("canary"));

    let search = SearchCall {
        endpoint_template: "/rest/api/2/search".into(),
        body: json!({"jql": "canary"}),
    };
    assert!(!format!("{search:?}").contains("canary"));

    let f = FetchFailure::PostSend {
        kind: PostSendKind::NetworkError,
        received: b"secret-canary".to_vec(),
    };
    assert!(!format!("{f:?}").contains("canary"));
    let f = FetchFailure::CancelledInFlight {
        bytes_received: b"secret-canary".to_vec(),
    };
    assert!(!format!("{f:?}").contains("canary"));
    let f = FetchFailure::BodyDecided {
        kind: atlas_duck_atlassian::BodyFailure::ParseFailure,
        response: r,
    };
    assert!(!format!("{f:?}").contains("canary"));
}

#[test]
fn read_budget_default() {
    let b = ReadBudget::default();
    assert_eq!(b.total.as_secs(), 120);
    assert_eq!(b.max_bytes, 50 * 1024 * 1024);
    assert_eq!(b.max_response_bytes, 32 * 1024 * 1024);
}
