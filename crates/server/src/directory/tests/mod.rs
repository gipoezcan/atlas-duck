//! Directory tests: the stub, the TLS configuration and the LDAPS client against an in-test fake
//! LDAPS server (tokio-rustls with an `rcgen` CA, hand-encoded BER for bind, search, unbind).
//! No test touches a real directory.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use secrecy::SecretString;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::ldap::LdapDirectory;
use super::stub::StubDirectory;
use super::tls::{TlsConfigError, client_config, roots_from_pem};
use super::{Directory, DirectoryError};

const LIMIT: Duration = Duration::from_secs(30);

fn pw(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

// ---- stub ----------------------------------------------------------------------------------

const STUB: &str = r#"{"users": [
  {"username": "Alice", "password": "pw-alice", "groups": ["cn=users,dc=t", "CN=Admins,dc=t"]},
  {"username": "dora", "password": "pw-dora", "groups": ["cn=users,dc=t"], "disabled": true}
]}"#;

#[tokio::test]
async fn stub_right_and_wrong_password() {
    let d = StubDirectory::from_json(STUB).unwrap();
    assert_eq!(d.kind(), "stub");
    let u = d.authenticate("alice", &pw("pw-alice")).await.unwrap();
    assert_eq!(u.username, "alice");
    assert_eq!(u.groups, ["cn=users,dc=t", "CN=Admins,dc=t"]);
    assert!(!u.disabled);
    for (user, pass) in [
        ("alice", "pw-dora"),
        ("alice", ""),
        ("nobody", "pw-alice"),
        ("alice", "pw-alice "),
    ] {
        assert_eq!(
            d.authenticate(user, &pw(pass)).await.unwrap_err(),
            DirectoryError::InvalidCredentials,
            "{user}/{pass}"
        );
    }
    assert!(
        d.authenticate("dora", &pw("pw-dora"))
            .await
            .unwrap()
            .disabled
    );
    assert_eq!(d.calls(), 6);
    d.probe().await.unwrap();
}

#[test]
fn stub_file_errors() {
    assert!(StubDirectory::from_json("{\"users\": [{\"username\": \"a\"}]}").is_err());
    assert!(StubDirectory::from_json("{\"users\": [], \"x\": 1}").is_err());
    assert!(StubDirectory::from_file(std::path::Path::new("/no/such/stub-m12.json")).is_err());
}

// ---- TLS configuration ---------------------------------------------------------------------

#[test]
fn bundle_must_hold_a_certificate() {
    assert_eq!(
        roots_from_pem(b"").unwrap_err(),
        TlsConfigError::BundleInvalid
    );
    assert_eq!(
        roots_from_pem(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
            .unwrap_err(),
        TlsConfigError::BundleInvalid
    );
    let missing = client_config(Some(std::path::Path::new("/no/such/bundle-m12.pem")));
    assert_eq!(missing.unwrap_err(), TlsConfigError::BundleUnreadable);
    assert!(client_config(None).is_ok());
}

// ---- fake LDAPS server ----------------------------------------------------------------------

fn rc(e: rcgen::Error) -> io::Error {
    io::Error::other(e.to_string())
}

fn validity(p: &mut rcgen::CertificateParams) {
    let now = SystemTime::now();
    p.not_before = (now - Duration::from_secs(86_400)).into();
    p.not_after = (now + Duration::from_secs(30 * 86_400)).into();
}

struct Ca {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    pem: String,
}

fn ca(name: &str) -> io::Result<Ca> {
    let key = rcgen::KeyPair::generate().map_err(rc)?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(rc)?;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    validity(&mut params);
    let pem = params.self_signed(&key).map_err(rc)?.pem();
    Ok(Ca { params, key, pem })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Bind succeeds; the search finds the entry with this `userAccountControl`.
    Entry { uac: u32 },
    /// Bind succeeds; the entry has this `userAccountControl` text (`None`: no such attribute).
    EntryUacText(Option<&'static str>),
    /// Bind succeeds; the search finds nothing.
    NoEntry,
    /// Bind answers this result code.
    BindRc(u8),
    /// Closes the connection right after the TLS handshake.
    CloseAfterTls,
}

struct FakeLdap {
    port: u16,
    ca_file: PathBuf,
    binds: Arc<Mutex<Vec<String>>>,
    filters: Arc<Mutex<Vec<Vec<u8>>>>,
    _dir: tempfile::TempDir,
}

/// A BER TLV with a definite length.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend([0x81, n as u8]);
    } else {
        out.extend([0x82, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn ldap_result(app_tag: u8, rc: u8) -> Vec<u8> {
    let mut c = tlv(0x0a, &[rc]);
    c.extend(tlv(0x04, b""));
    c.extend(tlv(0x04, b""));
    tlv(app_tag, &c)
}

fn message(msgid_tlv: &[u8], op: &[u8]) -> Vec<u8> {
    let mut c = msgid_tlv.to_vec();
    c.extend_from_slice(op);
    tlv(0x30, &c)
}

fn attribute(name: &str, values: &[&str]) -> Vec<u8> {
    let mut vals = Vec::new();
    for v in values {
        vals.extend(tlv(0x04, v.as_bytes()));
    }
    let mut c = tlv(0x04, name.as_bytes());
    c.extend(tlv(0x31, &vals));
    tlv(0x30, &c)
}

/// Reads one TLV: `(tag, content)`; `None` at EOF.
async fn read_tlv<R: AsyncRead + Unpin>(r: &mut R) -> Option<(u8, Vec<u8>)> {
    let tag = r.read_u8().await.ok()?;
    let first = r.read_u8().await.ok()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let mut n = 0usize;
        for _ in 0..(first & 0x7f) {
            n = (n << 8) | usize::from(r.read_u8().await.ok()?);
        }
        n
    };
    let mut content = vec![0; len];
    r.read_exact(&mut content).await.ok()?;
    Some((tag, content))
}

/// Splits the first TLV off `b`: `(tag, content, rest)`.
fn split_tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let first = *b.get(1)?;
    let (len, start) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let k = usize::from(first & 0x7f);
        let mut n = 0usize;
        for i in 0..k {
            n = (n << 8) | usize::from(*b.get(2 + i)?);
        }
        (n, 2 + k)
    };
    Some((tag, b.get(start..start + len)?, b.get(start + len..)?))
}

impl FakeLdap {
    async fn start(mode: Mode) -> FakeLdap {
        Self::start_signed_by(mode, &ca("fake LDAPS CA").unwrap(), None).await
    }

    /// The server's leaf is signed by `signer`; the client trusts `trusted` (default: signer).
    async fn start_signed_by(mode: Mode, signer: &Ca, trusted: Option<&str>) -> FakeLdap {
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let mut leaf = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        validity(&mut leaf);
        let issuer = rcgen::Issuer::from_params(&signer.params, &signer.key);
        let leaf_cert = leaf.signed_by(&leaf_key, &issuer).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
        );
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf_cert.der().clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let binds = Arc::new(Mutex::new(Vec::new()));
        let filters = Arc::new(Mutex::new(Vec::new()));
        let (b, f) = (binds.clone(), filters.clone());
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let (acceptor, b, f) = (acceptor.clone(), b.clone(), f.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(sock).await else {
                        return;
                    };
                    if mode == Mode::CloseAfterTls {
                        let _ = tls.shutdown().await;
                        return;
                    }
                    while let Some((0x30, msg)) = read_tlv(&mut tls).await {
                        let Some((0x02, id, rest)) = split_tlv(&msg) else {
                            return;
                        };
                        let msgid = tlv(0x02, id);
                        let Some((op, body, _)) = split_tlv(rest) else {
                            return;
                        };
                        let out = match op {
                            // BindRequest: version, name, [0] simple password.
                            0x60 => {
                                if let Some((_, _, after_version)) = split_tlv(body)
                                    && let Some((_, name, _)) = split_tlv(after_version)
                                {
                                    b.lock().unwrap().push(String::from_utf8_lossy(name).into());
                                }
                                let code = match mode {
                                    Mode::BindRc(c) => c,
                                    _ => 0,
                                };
                                message(&msgid, &ldap_result(0x61, code))
                            }
                            // SearchRequest: record it, answer the entry (or none) and done.
                            0x63 => {
                                f.lock().unwrap().push(body.to_vec());
                                let mut out = Vec::new();
                                let uac_text = match mode {
                                    Mode::Entry { uac } => Some(Some(uac.to_string())),
                                    Mode::EntryUacText(t) => Some(t.map(str::to_owned)),
                                    _ => None,
                                };
                                if let Some(uac_text) = uac_text {
                                    let mut attrs = attribute(
                                        "memberOf",
                                        &[
                                            "CN=Duck Users,DC=example,DC=test",
                                            "CN=Duck Admins,DC=example,DC=test",
                                        ],
                                    );
                                    if let Some(text) = uac_text {
                                        attrs.extend(attribute("userAccountControl", &[&text]));
                                    }
                                    attrs.extend(attribute("displayName", &["Alice Example"]));
                                    let mut entry = tlv(0x04, b"CN=alice,DC=example,DC=test");
                                    entry.extend(tlv(0x30, &attrs));
                                    out.extend(message(&msgid, &tlv(0x64, &entry)));
                                }
                                out.extend(message(&msgid, &ldap_result(0x65, 0)));
                                out
                            }
                            // UnbindRequest or anything else: close.
                            _ => return,
                        };
                        if tls.write_all(&out).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let ca_file = dir.path().join("bundle.pem");
        std::fs::write(&ca_file, trusted.unwrap_or(&signer.pem)).unwrap();
        FakeLdap {
            port,
            ca_file,
            binds,
            filters,
            _dir: dir,
        }
    }

    fn directory(&self) -> LdapDirectory {
        LdapDirectory::new(
            url::Url::parse(&format!("ldaps://localhost:{}", self.port)).unwrap(),
            "@example.test".into(),
            "DC=example,DC=test".into(),
            client_config(Some(&self.ca_file)).unwrap(),
        )
    }
}

async fn auth(
    d: &LdapDirectory,
    user: &str,
    pass: &str,
) -> Result<super::DirectoryUser, DirectoryError> {
    tokio::time::timeout(LIMIT, d.authenticate(user, &pw(pass)))
        .await
        .expect("authenticate hung")
}

#[tokio::test]
async fn ldap_bind_and_search_return_groups() {
    let fake = FakeLdap::start(Mode::Entry { uac: 512 }).await;
    let d = fake.directory();
    assert_eq!(d.kind(), "ldap");
    let u = auth(&d, "alice", "pw-canary").await.unwrap();
    assert_eq!(u.username, "alice");
    assert_eq!(u.display_name.as_deref(), Some("Alice Example"));
    assert_eq!(
        u.groups,
        [
            "CN=Duck Users,DC=example,DC=test",
            "CN=Duck Admins,DC=example,DC=test"
        ]
    );
    assert!(!u.disabled);
    assert_eq!(*fake.binds.lock().unwrap(), ["alice@example.test"]);
    // The filter carries the UPN (escaped) and objectClass=user.
    let filters = fake.filters.lock().unwrap();
    let f = String::from_utf8_lossy(&filters[0]);
    assert!(
        f.contains("alice@example.test") && f.contains("userPrincipalName"),
        "{f}"
    );
    assert!(f.contains("objectClass") && f.contains("user"), "{f}");
}

#[tokio::test]
async fn ldap_disabled_account_is_surfaced() {
    let fake = FakeLdap::start(Mode::Entry { uac: 514 }).await;
    assert!(
        auth(&fake.directory(), "alice", "pw")
            .await
            .unwrap()
            .disabled
    );
}

#[tokio::test]
async fn ldap_rc_49_is_invalid_credentials_other_rc_unavailable() {
    let fake = FakeLdap::start(Mode::BindRc(49)).await;
    assert_eq!(
        auth(&fake.directory(), "alice", "wrong").await.unwrap_err(),
        DirectoryError::InvalidCredentials
    );
    let busy = FakeLdap::start(Mode::BindRc(51)).await;
    assert_eq!(
        auth(&busy.directory(), "alice", "pw").await.unwrap_err(),
        DirectoryError::Unavailable
    );
}

#[tokio::test]
async fn ldap_no_entry_is_not_found() {
    let fake = FakeLdap::start(Mode::NoEntry).await;
    assert_eq!(
        auth(&fake.directory(), "alice", "pw").await.unwrap_err(),
        DirectoryError::NotFound
    );
}

#[tokio::test]
async fn ldap_empty_password_never_binds() {
    let fake = FakeLdap::start(Mode::Entry { uac: 512 }).await;
    assert_eq!(
        auth(&fake.directory(), "alice", "").await.unwrap_err(),
        DirectoryError::InvalidCredentials
    );
    assert!(fake.binds.lock().unwrap().is_empty());
}

#[tokio::test]
async fn ldap_close_after_tls_is_unavailable() {
    let fake = FakeLdap::start(Mode::CloseAfterTls).await;
    assert_eq!(
        auth(&fake.directory(), "alice", "pw").await.unwrap_err(),
        DirectoryError::Unavailable
    );
}

/// The server's certificate comes from a CA the bundle does not hold: verification refuses it.
#[tokio::test]
async fn ldap_foreign_ca_is_unavailable() {
    let signer = ca("server CA").unwrap();
    let other = ca("other CA").unwrap();
    let fake = FakeLdap::start_signed_by(Mode::Entry { uac: 512 }, &signer, Some(&other.pem)).await;
    let d = fake.directory();
    assert_eq!(
        auth(&d, "alice", "pw").await.unwrap_err(),
        DirectoryError::Unavailable
    );
    assert!(
        fake.binds.lock().unwrap().is_empty(),
        "no bind over an unverified channel"
    );
    assert_eq!(d.probe().await.unwrap_err(), DirectoryError::Unavailable);
}

#[tokio::test]
async fn ldap_probe_handshakes_without_binding() {
    let fake = FakeLdap::start(Mode::Entry { uac: 512 }).await;
    tokio::time::timeout(LIMIT, fake.directory().probe())
        .await
        .unwrap()
        .unwrap();
    assert!(fake.binds.lock().unwrap().is_empty());
}

#[tokio::test]
async fn ldap_closed_port_is_unavailable_within_11s() {
    // The fake server first, then a port that refuses: a port freed before the fake started
    // could be the one it binds (the flake of CI run 40517478906's rerun). A listener that
    // closes every connection at once keeps the port this test's own: no other test can bind it.
    let any = FakeLdap::start(Mode::Entry { uac: 512 }).await;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let closer = tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            drop(sock);
        }
    });
    let d = LdapDirectory::new(
        url::Url::parse(&format!("ldaps://localhost:{port}")).unwrap(),
        "@example.test".into(),
        "DC=example,DC=test".into(),
        client_config(Some(&any.ca_file)).unwrap(),
    );
    let started = Instant::now();
    assert_eq!(
        auth(&d, "alice", "pw").await.unwrap_err(),
        DirectoryError::Unavailable
    );
    assert!(
        started.elapsed() < Duration::from_secs(11),
        "{:?}",
        started.elapsed()
    );
    closer.abort();
}

/// Review M3: a missing or unreadable `userAccountControl` is a disabled account (fail closed).
#[tokio::test]
async fn ldap_missing_or_bad_uac_is_disabled() {
    for text in [None, Some("not-a-number"), Some("")] {
        let fake = FakeLdap::start(Mode::EntryUacText(text)).await;
        let u = auth(&fake.directory(), "alice", "pw").await.unwrap();
        assert!(u.disabled, "{text:?}");
    }
    let fake = FakeLdap::start(Mode::EntryUacText(Some("512"))).await;
    assert!(
        !auth(&fake.directory(), "alice", "pw")
            .await
            .unwrap()
            .disabled
    );
}
