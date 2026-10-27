//! The HTTPS Jira the server under test reaches (M14 PD-260, `ATLAS_DUCK_E2E_JIRA=mock`): the
//! atlassian test mock (plain HTTP on loopback) behind a TLS front whose leaf for `127.0.0.1` is
//! signed by a throwaway test CA. The CA is made before the server starts
//! (`ATLAS_DUCK_E2E_MAKE_CA=<dir>` writes `ca.pem` and `ca.key.pem`; the server gets `ca.pem` as
//! its CA bundle) and loaded here from the same directory. Test material only: the CA lives for
//! one CI run and signs nothing else.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use atlas_duck_atlassian::Product;
use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser, fixtures};
use tokio::net::{TcpListener, TcpStream};

use super::client::{Ctx, R};

const CA_NAME: &str = "atlas-duck e2e throwaway test CA";

/// The CA's parameters; the same every time, so a key loaded from disk issues under the
/// certificate written next to it (same subject, key identifier from the key).
fn ca_params() -> R<rcgen::CertificateParams> {
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).ctx("CA params")?;
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    p.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    p.distinguished_name
        .push(rcgen::DnType::CommonName, CA_NAME);
    validity(&mut p);
    Ok(p)
}

/// Yesterday to 30 days ahead.
fn validity(p: &mut rcgen::CertificateParams) {
    let now = SystemTime::now();
    p.not_before = (now - Duration::from_secs(86_400)).into();
    p.not_after = (now + Duration::from_secs(30 * 86_400)).into();
}

/// `ATLAS_DUCK_E2E_MAKE_CA=<dir>`: writes `ca.pem` (for the server's CA bundle) and `ca.key.pem`.
pub fn make_ca(dir: &Path) -> R<()> {
    let key = rcgen::KeyPair::generate().ctx("CA key")?;
    let cert = ca_params()?.self_signed(&key).ctx("CA cert")?;
    std::fs::create_dir_all(dir).ctx("CA dir")?;
    std::fs::write(dir.join("ca.pem"), cert.pem()).ctx("ca.pem")?;
    std::fs::write(dir.join("ca.key.pem"), key.serialize_pem()).ctx("ca.key.pem")?;
    Ok(())
}

/// The mock and its HTTPS front.
pub struct Jira {
    pub mock: MockDc,
    /// `https://127.0.0.1:<port>`.
    pub base_url: String,
}

impl Jira {
    /// Starts the mock (identity, server info, issue `ABC-1` and its comments, as the in-process
    /// suites) and the TLS front with a leaf issued by the CA in `ca_dir`.
    pub async fn start(ca_dir: &Path) -> R<Jira> {
        let mock = MockDc::start(Product::Jira, "").await;
        mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
            .await;
        mock.jira_server_info("9.12.0").await;
        mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
            .await;
        mock.json(
            "/rest/api/2/issue/ABC-1/comment",
            201,
            r#"{"id":"10100","body":"Seen on staging.","author":{"name":"jdoe"}}"#,
        )
        .await;
        let backend = mock
            .base_url()
            .strip_prefix("http://")
            .ctx("the mock is not plain HTTP")?
            .trim_end_matches('/')
            .to_owned();

        let ca_key = rcgen::KeyPair::from_pem(
            &std::fs::read_to_string(ca_dir.join("ca.key.pem")).ctx("ca.key.pem")?,
        )
        .ctx("CA key PEM")?;
        let ca = ca_params()?;
        let issuer = rcgen::Issuer::new(ca, &ca_key);
        let leaf_key = rcgen::KeyPair::generate().ctx("leaf key")?;
        let mut leaf =
            rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).ctx("leaf params")?;
        leaf.distinguished_name
            .push(rcgen::DnType::CommonName, "127.0.0.1");
        leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        leaf.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        validity(&mut leaf);
        let leaf_cert = leaf.signed_by(&leaf_key, &issuer).ctx("leaf cert")?;
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
        );
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .ctx("TLS versions")?
        .with_no_client_auth()
        .with_single_cert(vec![leaf_cert.der().clone()], key)
        .ctx("TLS config")?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .ctx("TLS front bind")?;
        let port = listener.local_addr().ctx("TLS front addr")?.port();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let (acceptor, backend) = (acceptor.clone(), backend.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(sock).await else {
                        return;
                    };
                    let Ok(mut plain) = TcpStream::connect(backend.as_str()).await else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut plain).await;
                });
            }
        });
        Ok(Jira {
            mock,
            base_url: format!("https://127.0.0.1:{port}"),
        })
    }

    /// The requests the mock received other than reads.
    pub async fn writes(&self) -> Vec<wiremock::Request> {
        self.mock
            .received()
            .await
            .into_iter()
            .filter(|r| r.method.as_str() != "GET")
            .collect()
    }
}
