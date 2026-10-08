//! I-20 core half: the process proxy environment is never consulted by `HttpFactory` or the
//! OS readers (§7.2, L42). Alone in its own test binary because it sets environment variables.

use std::sync::Arc;

use atlas_duck_atlassian::testing::{
    MockDc, RawHttpServer, RawStep, RecordingDates, StaticCredentials, TEST_USER_KEY, XAuser,
    test_cover,
};
use atlas_duck_atlassian::{FetchOutcome, GetCall, Product};
use atlas_duck_core::http_factory::{HttpFactory, InstanceHttpSpec};
use atlas_duck_core::proxy::{OsProxy, OsProxySource, ProxySetting, SystemProxySource};
use atlas_duck_core::proxy::{os_linux, os_windows};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct FakeOsProxy(OsProxy);

impl OsProxySource for FakeOsProxy {
    fn read(&self) -> OsProxy {
        self.0.clone()
    }
}

struct EmptyRegistry;

impl os_windows::RegistryReader for EmptyRegistry {
    fn dword(&self, _: &str, _: &str) -> Option<u32> {
        None
    }
    fn string(&self, _: &str, _: &str) -> Option<String> {
        None
    }
    fn binary(&self, _: &str, _: &str) -> Option<Vec<u8>> {
        None
    }
}

struct NoGsettings;

impl os_linux::Gsettings for NoGsettings {
    fn get(&self, _: &str, _: &str) -> os_linux::GsOutcome {
        os_linux::GsOutcome::Missing
    }
}

#[tokio::test(flavor = "current_thread")]
async fn i20_env_proxy_never_used() -> TestResult {
    let fake_proxy = RawHttpServer::serve(vec![
        RawStep::Send(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".to_vec()),
        RawStep::Close,
    ])
    .await?;
    let proxy_url = fake_proxy.base_url();
    for var in [
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "https_proxy",
        "http_proxy",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        // SAFETY: single test in this binary, set before any thread starts.
        unsafe { std::env::set_var(var, &proxy_url) };
    }

    let dc = MockDc::start(Product::Jira, "").await;
    dc.jira_myself("jdoe", TEST_USER_KEY, XAuser::Same).await;
    let cfg = dc.client_config();
    let factory = HttpFactory::new(
        Arc::new(FakeOsProxy(OsProxy::default())),
        Arc::new(StaticCredentials::for_config(&cfg)),
        Arc::new(RecordingDates::default()),
    );
    let spec = InstanceHttpSpec {
        instance_id: cfg.instance_id,
        product: Product::Jira,
        base: dc.base(),
        ca_pem: None,
        proxy: ProxySetting::Os,
    };
    let (client, resolved) = factory.build(&spec)?;
    assert_eq!(resolved.effective, "direct");
    let call = GetCall {
        endpoint_template: "/rest/api/2/myself".into(),
        params: json!({}),
        query: vec![],
    };
    match client.get(&test_cover()?, &call).await {
        FetchOutcome::Response(r) => assert_eq!(r.status, 200),
        other => return Err(format!("{other:?}").into()),
    }
    assert_eq!(dc.received().await.len(), 1);
    assert_eq!(fake_proxy.connections(), 0);

    // The readers over empty machine state (injected: no real registry or gsettings is read)
    // do not pick the environment up either, through the cached source or directly.
    let port = fake_proxy.addr().port().to_string();
    let source = SystemProxySource::with_reader(Box::new(|| os_windows::read_with(&EmptyRegistry)));
    let all = [
        source.read(),
        os_windows::read_with(&EmptyRegistry),
        os_linux::read_with(&NoGsettings, None),
    ];
    for r in all {
        assert!(r.https.is_none() && r.bypass.is_empty(), "{r:?}");
        assert!(!format!("{r:?}").contains(&port));
    }
    Ok(())
}
