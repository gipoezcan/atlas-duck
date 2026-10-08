//! Review Focus 1: a custom CA is merged with the OS roots through the platform verifier.
//! Runs on every CI leg (Windows, macOS, Ubuntu) with `--features testing`.

use std::sync::Arc;

use atlas_duck_atlassian::testing::{
    StaticCredentials, TestTlsServer, generate_ca_pem, test_client_with, test_config, test_cover,
};
use atlas_duck_atlassian::{
    BuildError, ConnClass, FetchFailure, FetchOutcome, GetCall, InstanceClient, Product,
};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn myself() -> GetCall {
    GetCall {
        endpoint_template: "/rest/api/2/myself".into(),
        params: json!({}),
        query: vec![],
    }
}

fn client(base: &str, ca: Option<&str>) -> Result<Arc<InstanceClient>, Box<dyn std::error::Error>> {
    let mut cfg = test_config(Product::Jira, base)?;
    cfg.custom_ca_pem = ca.map(|p| p.as_bytes().to_vec());
    let creds = Arc::new(StaticCredentials::for_config(&cfg));
    Ok(test_client_with(cfg, creds)?.client)
}

#[tokio::test]
async fn custom_ca_merges_with_os_roots() -> TestResult {
    let server = TestTlsServer::start().await?;
    let cover = test_cover()?;

    // A: the server's CA merged with the OS roots; building must not fail.
    let a = client(&server.base_url(), Some(server.ca_pem()))?;
    match a.get(&cover, &myself()).await {
        FetchOutcome::Response(r) => assert_eq!(r.status, 200),
        other => return Err(format!("client A: {other:?}").into()),
    }

    // B: OS roots only.
    let b = client(&server.base_url(), None)?;
    assert_eq!(
        b.get(&cover, &myself()).await,
        FetchOutcome::Failed(FetchFailure::PreSendConnection(ConnClass::TlsUnknownIssuer))
    );

    // C: some other CA merged with the OS roots.
    let other = generate_ca_pem()?;
    let c = client(&server.base_url(), Some(&other))?;
    assert_eq!(
        c.get(&cover, &myself()).await,
        FetchOutcome::Failed(FetchFailure::PreSendConnection(ConnClass::TlsUnknownIssuer))
    );
    Ok(())
}

#[tokio::test]
async fn invalid_ca_bundle_is_a_build_error() -> TestResult {
    let server = TestTlsServer::start().await?;
    let err = client(
        &server.base_url(),
        Some("-----BEGIN CERTIFICATE-----\nnope\n"),
    );
    let err = err.err().ok_or("expected a build error")?;
    assert!(
        matches!(err.downcast_ref::<BuildError>(), Some(BuildError::CaPem(_))),
        "{err}"
    );
    Ok(())
}
