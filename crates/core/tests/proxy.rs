//! L42 proxy resolution and `HttpFactory` (V17). No test reads the machine's proxy settings.

use std::sync::Arc;

use atlas_duck_atlassian::testing::{
    MockDc, RawHttpServer, RawStep, RecordingDates, StaticCredentials, TEST_USER_KEY, XAuser,
    test_cover,
};
use atlas_duck_atlassian::{FetchOutcome, GetCall, Product, ProxyChoice};
use atlas_duck_core::http_factory::{HttpFactory, InstanceHttpSpec};
use atlas_duck_core::proxy::{
    OsProxy, OsProxySource, ProxyParseError, ProxySetting, SystemProxySource, bypass_matches,
    resolve_proxy,
};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct FakeOsProxy(OsProxy);

impl OsProxySource for FakeOsProxy {
    fn read(&self) -> OsProxy {
        self.0.clone()
    }
}

fn os_proxy() -> OsProxy {
    OsProxy {
        https: Some(("os.proxy".to_owned(), 8080)),
        bypass: vec![],
        pac_configured: false,
        read_failed: false,
    }
}

fn proxy(host: &str, port: u16) -> ProxyChoice {
    ProxyChoice::Proxy {
        host: host.to_owned(),
        port,
    }
}

#[test]
fn l42_bypass_matching_table() {
    let table = [
        ("jira", "<local>", true),
        ("jira.corp", "<local>", false),
        ("a.corp", "*.corp", true),
        ("x.a.corp", "*.corp", true),
        ("corp", "*.corp", false),
        ("a.corp", ".corp", true),
        ("JIRA.Corp", "jira.corp", true),
        ("jira.corp", "jira.corp:8080", true),
        ("10.0.0.5", "10.0.0.5", true),
        ("10.0.0.5", "10.0.0.0/8", false),
        ("jira.corp", "*", false),
        ("xn--mnchen-3ya.de", "xn--mnchen-3ya.de", true),
        ("jira.corp.", "jira.corp", true),
        ("jira.corp", "https://jira.corp", true),
        ("[::1]", "::1", true),
        ("[::1]", "[::1]", true),
        ("[::1]", "[::1]:8080", true),
        ("[::2]", "::1", false),
    ];
    for (host, entry, want) in table {
        assert_eq!(bypass_matches(host, entry), want, "{host} vs {entry}");
    }
}

#[test]
fn l42_per_instance_host_port() {
    let s = ProxySetting::HostPort {
        host: "proxy.corp".into(),
        port: 3128,
    };
    let r = resolve_proxy(&s, "jira.example", &os_proxy());
    assert_eq!(r.choice, proxy("proxy.corp", 3128));
    assert_eq!(r.effective, "proxy.corp:3128");
    // The instance's proxy applies even to a host on the OS bypass list.
    let mut os = os_proxy();
    os.bypass = vec!["*.corp".into()];
    let r = resolve_proxy(&s, "jira.corp", &os);
    assert_eq!(r.choice, proxy("proxy.corp", 3128));
}

#[test]
fn l42_per_instance_direct_beats_os_proxy() {
    let r = resolve_proxy(&ProxySetting::Direct, "jira.example", &os_proxy());
    assert_eq!(r.choice, ProxyChoice::Direct);
    assert_eq!(r.effective, "direct");
}

#[test]
fn l42_os_static_with_bypass() {
    let mut os = os_proxy();
    os.bypass = vec!["*.corp".into()];
    let r = resolve_proxy(&ProxySetting::Os, "jira.corp", &os);
    assert_eq!(r.choice, ProxyChoice::Direct);
    assert_eq!(r.effective, "direct");
    let r = resolve_proxy(&ProxySetting::Os, "jira.example", &os);
    assert_eq!(r.choice, proxy("os.proxy", 8080));
    assert_eq!(r.effective, "os.proxy:8080");
}

#[test]
fn l42_pac_ignored_reports_pac_configured() {
    let os = OsProxy {
        https: None,
        bypass: vec![],
        pac_configured: true,
        read_failed: false,
    };
    let r = resolve_proxy(&ProxySetting::Os, "jira.example", &os);
    assert_eq!(r.choice, ProxyChoice::Direct);
    assert!(r.pac_configured && r.uses_os);
    // An instance with its own proxy or `direct` already did what the hint asks for.
    let own = resolve_proxy(&ProxySetting::Direct, "jira.example", &os);
    assert!(own.pac_configured && !own.uses_os);
    assert_eq!(
        atlas_duck_core::proxy::PAC_HINT,
        "your system uses a proxy auto-config script, which atlas-duck does not evaluate: set this instance's proxy (host:port or direct) in Settings"
    );
}

#[test]
fn proxy_setting_parse() -> TestResult {
    assert_eq!(ProxySetting::parse("")?, ProxySetting::Os);
    assert_eq!(ProxySetting::parse("direct")?, ProxySetting::Direct);
    assert_eq!(
        ProxySetting::parse("h:1")?,
        ProxySetting::HostPort {
            host: "h".into(),
            port: 1
        }
    );
    assert_eq!(
        ProxySetting::parse("[::1]:3128")?,
        ProxySetting::HostPort {
            host: "::1".into(),
            port: 3128
        }
    );
    for bad in [
        "h",
        "h:x",
        ":1",
        "h:0",
        "h:70000",
        "http://h:1",
        "h :1",
        "::1:3",
    ] {
        assert_eq!(
            ProxySetting::parse(bad),
            Err(ProxyParseError::Malformed),
            "{bad}"
        );
    }
    assert_eq!(
        ProxySetting::parse("user:pw@h:1"),
        Err(ProxyParseError::Userinfo)
    );
    for s in ["direct", "h:1", "[::1]:3128"] {
        assert_eq!(ProxySetting::parse(s)?.as_config_str(), s);
    }
    Ok(())
}

#[test]
fn system_source_caches_readings() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let n = Arc::new(AtomicUsize::new(0));
    let counter = n.clone();
    let src = SystemProxySource::with_reader(Box::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        OsProxy::default()
    }));
    src.read();
    src.read();
    assert_eq!(n.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn factory_applies_resolved_proxy_and_reports_it() -> TestResult {
    let fake = RawHttpServer::serve(vec![
        RawStep::Send(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".to_vec()),
        RawStep::Close,
    ])
    .await?;
    let dc = MockDc::start(Product::Jira, "").await;
    dc.jira_myself("jdoe", TEST_USER_KEY, XAuser::Same).await;
    let cfg = dc.client_config();
    let creds = Arc::new(StaticCredentials::for_config(&cfg));
    let os = OsProxy {
        https: Some(("127.0.0.1".to_owned(), fake.addr().port())),
        bypass: vec![],
        pac_configured: true,
        read_failed: false,
    };
    let factory = HttpFactory::new(
        Arc::new(FakeOsProxy(os)),
        creds,
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
    assert!(resolved.pac_configured);
    assert_eq!(
        resolved.effective,
        format!("127.0.0.1:{}", fake.addr().port())
    );
    let call = GetCall {
        endpoint_template: "/rest/api/2/myself".into(),
        params: json!({}),
        query: vec![],
    };
    let out = client.get(&test_cover()?, &call).await;
    // The fake proxy's 502 is what came back: the request went through it.
    match out {
        FetchOutcome::Response(r) => assert_eq!(r.status, 502),
        other => return Err(format!("{other:?}").into()),
    }
    assert_eq!(fake.connections(), 1);
    assert!(dc.received().await.is_empty());
    Ok(())
}

#[test]
fn os_read_failure_is_reported_and_not_cached() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let n = Arc::new(AtomicUsize::new(0));
    let counter = n.clone();
    let src = SystemProxySource::with_reader(Box::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        OsProxy {
            read_failed: true,
            ..OsProxy::default()
        }
    }));
    let os = src.read();
    src.read();
    assert_eq!(n.load(Ordering::SeqCst), 2);
    let r = resolve_proxy(&ProxySetting::Os, "jira.example", &os);
    assert!(r.os_read_failed);
    assert_eq!(r.choice, ProxyChoice::Direct);
    assert!(!resolve_proxy(&ProxySetting::Direct, "jira.example", &os).os_read_failed);
}

#[test]
#[cfg(feature = "testing")]
fn cache_expires_after_ttl() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    let n = Arc::new(AtomicUsize::new(0));
    let counter = n.clone();
    let src = SystemProxySource::with_reader(Box::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        OsProxy::default()
    }))
    .with_ttl(Duration::from_millis(30));
    src.read();
    std::thread::sleep(Duration::from_millis(60));
    src.read();
    assert_eq!(n.load(Ordering::SeqCst), 2);
}
