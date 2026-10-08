//! I-01: the fixture sets of Jira 9.12 / 10.x and Confluence 8.5 / 9.x answer like Data Center
//! for the fields the M3 tests read. `atlassian` has no `registry` edge, so this checks JSON
//! validity and field presence; `core`'s Task 18 test validates the bodies against the registry
//! result schemas.

use atlas_duck_atlassian::testing::fixtures::{
    CONFLUENCE_8_5_VERSION, CONFLUENCE_9_VERSION, FIXTURE_DATE, JIRA_9_12_VERSION, JIRA_10_VERSION,
};
use atlas_duck_atlassian::testing::{
    MockDc, TEST_INSTANCE, TEST_USER, TEST_USER_KEY, TestClient, test_client, test_cover,
};
use atlas_duck_atlassian::{FetchOutcome, GetCall, Product, SearchCall};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn fetch(t: &TestClient, template: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let call = GetCall {
        endpoint_template: template.into(),
        params: json!({}),
        query: vec![],
    };
    json_of(t.client.get(&test_cover()?, &call).await, template)
}

/// A Jira `Response` also proves the `X-AUSERNAME` header: without a matching one the client
/// returns `IdentityCheckFailed`.
fn json_of(o: FetchOutcome, what: &str) -> Result<Value, Box<dyn std::error::Error>> {
    match o {
        FetchOutcome::Response(r) if r.status == 200 => Ok(serde_json::from_slice(&r.body)?),
        other => Err(format!("{what}: {other:?}").into()),
    }
}

#[tokio::test]
async fn i01_fixtures_answer_like_dc() -> TestResult {
    for version in [JIRA_9_12_VERSION, JIRA_10_VERSION] {
        let dc = MockDc::start(Product::Jira, "/jira")
            .await
            .with_date(FIXTURE_DATE);
        dc.mount_fixture_set(version).await;
        let t = test_client(dc.client_config())?;

        let me = fetch(&t, "/rest/api/2/myself").await?;
        assert_eq!(
            (me["name"].as_str(), me["key"].as_str()),
            (Some(TEST_USER), Some(TEST_USER_KEY))
        );
        let info = fetch(&t, "/rest/api/2/serverInfo").await?;
        assert_eq!(info["version"], version);
        assert!(info["versionNumbers"].is_array());
        let issue = fetch(&t, "/rest/api/2/issue/ABC-1").await?;
        assert_eq!(issue["key"], "ABC-1");
        assert!(issue["fields"]["summary"].is_string());
        let search = SearchCall {
            endpoint_template: "/rest/api/2/search".into(),
            body: json!({"jql": "project = ABC", "startAt": 0, "maxResults": 50}),
        };
        let page = json_of(
            t.client.post_search(&test_cover()?, &search).await,
            "search",
        )?;
        assert!(page["issues"].as_array().is_some_and(|a| !a.is_empty()));
        assert!(page["total"].is_u64());

        // Every response carried `Date`.
        let dates = t.dates.calls();
        assert_eq!(dates.len(), 4, "{version}");
        let fixed = httpdate::parse_http_date(FIXTURE_DATE)?;
        assert!(
            dates
                .iter()
                .all(|(id, d)| id == TEST_INSTANCE && *d == fixed)
        );
    }

    for version in [CONFLUENCE_8_5_VERSION, CONFLUENCE_9_VERSION] {
        let dc = MockDc::start(Product::Confluence, "/confluence")
            .await
            .with_date(FIXTURE_DATE);
        dc.mount_fixture_set(version).await;
        let t = test_client(dc.client_config())?;

        let me = fetch(&t, "/rest/api/user/current").await?;
        assert_eq!(me["type"], "known");
        assert_eq!(me["username"], TEST_USER);
        assert!(me["userKey"].is_string());
        let manifest = fetch(&t, "/rest/applinks/1.0/manifest").await?;
        assert_eq!(manifest["version"], version);
        let page = fetch(&t, "/rest/api/content/65537").await?;
        assert_eq!(page["type"], "page");
        assert!(page["version"]["number"].is_u64());
        let search = fetch(&t, "/rest/api/search").await?;
        assert!(search["results"].as_array().is_some_and(|a| !a.is_empty()));
        assert_eq!(t.dates.calls().len(), 4, "{version}");
    }
    Ok(())
}
