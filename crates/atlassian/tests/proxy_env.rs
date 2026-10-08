//! I-20 client half: the process proxy environment is never consulted (§7.2, L42). Alone in its
//! own test binary because it sets environment variables.

use atlas_duck_atlassian::testing::{
    MockDc, RawHttpServer, RawStep, TEST_USER_KEY, XAuser, test_client, test_cover,
};
use atlas_duck_atlassian::{FetchOutcome, GetCall, Product};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test(flavor = "current_thread")]
async fn i20_client_ignores_proxy_env() -> TestResult {
    let proxy = RawHttpServer::serve(vec![
        RawStep::Send(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".to_vec()),
        RawStep::Close,
    ])
    .await?;
    let proxy_url = proxy.base_url();
    for var in [
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "https_proxy",
        "http_proxy",
    ] {
        // SAFETY: single test in this binary, set before any thread starts.
        unsafe { std::env::set_var(var, &proxy_url) };
    }
    for var in ["NO_PROXY", "no_proxy"] {
        // SAFETY: as above.
        unsafe { std::env::remove_var(var) };
    }

    let dc = MockDc::start(Product::Jira, "").await;
    dc.jira_myself("jdoe", TEST_USER_KEY, XAuser::Same).await;
    let t = test_client(dc.client_config())?;
    let call = GetCall {
        endpoint_template: "/rest/api/2/myself".into(),
        params: json!({}),
        query: vec![],
    };
    match t.client.get(&test_cover()?, &call).await {
        FetchOutcome::Response(r) => assert_eq!(r.status, 200),
        other => return Err(format!("{other:?}").into()),
    }
    assert_eq!(dc.received().await.len(), 1);
    assert_eq!(proxy.connections(), 0);

    // Control: a default reqwest client in the same process does read the environment, so the
    // assertion above is not vacuous.
    let default = reqwest::Client::builder().build()?;
    let r = default
        .get(format!("{}/control", dc.base_url()))
        .send()
        .await?;
    assert_eq!(r.status().as_u16(), 502);
    assert_eq!(proxy.connections(), 1);
    Ok(())
}
