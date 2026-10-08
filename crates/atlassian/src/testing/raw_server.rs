//! Raw-socket servers: `RawHttpServer` answers every connection with scripted bytes (truncated
//! bodies, stalls, proxy refusals); `TestTlsServer` terminates TLS with a leaf signed by a CA
//! generated per server.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// One step of the per-connection script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawStep {
    Send(Vec<u8>),
    /// Milliseconds.
    Sleep(u64),
    Close,
}

#[derive(Default)]
struct Stats {
    accepted: AtomicUsize,
    active: AtomicUsize,
    max_active: AtomicUsize,
    closed: AtomicUsize,
    heads: Mutex<Vec<Vec<u8>>>,
    bodies: Mutex<Vec<Vec<u8>>>,
}

/// Each accepted connection: read the request head (and a `Content-Length` body), then run the
/// script; the connection closes at `Close` or at the end of the script.
pub struct RawHttpServer {
    addr: SocketAddr,
    stats: Arc<Stats>,
    task: JoinHandle<()>,
}

impl RawHttpServer {
    /// The same script for every connection.
    pub async fn serve(script: Vec<RawStep>) -> io::Result<RawHttpServer> {
        Self::serve_sequence(vec![script]).await
    }

    /// Connection `i` runs `scripts[i]`; connections after the last script run the last one again
    /// (multi-page reads: one connection per page when every answer says `Connection: close`).
    pub async fn serve_sequence(scripts: Vec<Vec<RawStep>>) -> io::Result<RawHttpServer> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let stats = Arc::new(Stats::default());
        let s = stats.clone();
        let scripts: Arc<Vec<Vec<RawStep>>> = Arc::new(scripts);
        let task = tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let n = s.accepted.fetch_add(1, Ordering::SeqCst);
                let now = s.active.fetch_add(1, Ordering::SeqCst) + 1;
                s.max_active.fetch_max(now, Ordering::SeqCst);
                let (s, scripts) = (s.clone(), scripts.clone());
                tokio::spawn(async move {
                    let script = scripts
                        .get(n)
                        .or_else(|| scripts.last())
                        .map_or(&[][..], Vec::as_slice);
                    if let Ok((head, body)) = read_request(&mut sock).await {
                        s.heads
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push(head);
                        s.bodies
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push(body);
                        run_script(&mut sock, script).await;
                    }
                    let _ = sock.shutdown().await;
                    drop(sock);
                    s.active.fetch_sub(1, Ordering::SeqCst);
                    s.closed.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        Ok(RawHttpServer { addr, stats, task })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://127.0.0.1:<port>`.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Connections accepted so far.
    pub fn connections(&self) -> usize {
        self.stats.accepted.load(Ordering::SeqCst)
    }

    /// The most connections open at the same time.
    pub fn max_concurrent(&self) -> usize {
        self.stats.max_active.load(Ordering::SeqCst)
    }

    /// Connections the server has finished with.
    pub fn closed(&self) -> usize {
        self.stats.closed.load(Ordering::SeqCst)
    }

    /// Request heads received, in arrival order.
    pub fn request_heads(&self) -> Vec<Vec<u8>> {
        self.stats
            .heads
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The `Content-Length` bodies of the requests, in the order of `request_heads`.
    pub fn request_bodies(&self) -> Vec<Vec<u8>> {
        self.stats
            .bodies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Drop for RawHttpServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn run_script<S: AsyncWrite + Unpin>(sock: &mut S, script: &[RawStep]) {
    for step in script {
        match step {
            RawStep::Send(bytes) => {
                if sock.write_all(bytes).await.is_err() || sock.flush().await.is_err() {
                    return;
                }
            }
            RawStep::Sleep(ms) => tokio::time::sleep(Duration::from_millis(*ms)).await,
            RawStep::Close => return,
        }
    }
}

/// Reads up to the end of the head and then the `Content-Length` body, so closing the socket
/// never resets a connection with unread request bytes. Returns the head and the body.
async fn read_request<S: AsyncRead + Unpin>(sock: &mut S) -> io::Result<(Vec<u8>, Vec<u8>)> {
    const MAX_HEAD: usize = 64 * 1024;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::other("request head too long"));
        }
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = buf[..head_end].to_vec();
    let body_len = String::from_utf8_lossy(&head)
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < body_len {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    Ok((head, body))
}

/// A self-signed CA certificate (PEM) that signs nothing: the "wrong CA" for TLS tests.
pub fn generate_ca_pem() -> io::Result<String> {
    Ok(TestCa::generate("atlas-duck other test CA")?.cert_pem)
}

struct TestCa {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    cert_pem: String,
}

fn rc(e: rcgen::Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// Validity from yesterday to 30 days ahead: inside Apple's 825-day TLS limit.
fn validity(p: &mut rcgen::CertificateParams) {
    let now = SystemTime::now();
    p.not_before = (now - Duration::from_secs(86_400)).into();
    p.not_after = (now + Duration::from_secs(30 * 86_400)).into();
}

impl TestCa {
    fn generate(name: &str) -> io::Result<TestCa> {
        let key = rcgen::KeyPair::generate().map_err(rc)?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(rc)?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        validity(&mut params);
        let cert_pem = params.self_signed(&key).map_err(rc)?.pem();
        Ok(TestCa {
            params,
            key,
            cert_pem,
        })
    }
}

/// An HTTPS server for `localhost` whose leaf is signed by a fresh CA; every request gets
/// `200 application/json {}` with `X-AUSERNAME: jdoe` and `Connection: close`.
pub struct TestTlsServer {
    addr: SocketAddr,
    ca_pem: String,
    accepted: Arc<AtomicUsize>,
    handshakes: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl TestTlsServer {
    pub async fn start() -> io::Result<TestTlsServer> {
        Self::start_dropping_first(0).await
    }

    /// Closes the first `drop` connections right after accepting them, before any TLS byte: the
    /// client sees a handshake failure, a connection-level (pre-send) error.
    pub async fn start_dropping_first(drop: usize) -> io::Result<TestTlsServer> {
        crate::client::ensure_provider();
        let ca = TestCa::generate("atlas-duck test CA")?;
        let leaf_key = rcgen::KeyPair::generate().map_err(rc)?;
        let mut leaf =
            rcgen::CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
                .map_err(rc)?;
        leaf.distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        leaf.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        validity(&mut leaf);
        let issuer = rcgen::Issuer::from_params(&ca.params, &ca.key);
        let leaf_cert = leaf.signed_by(&leaf_key, &issuer).map_err(rc)?;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
        );
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(vec![leaf_cert.der().clone()], key)
            .map_err(io::Error::other)?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let handshakes = Arc::new(AtomicUsize::new(0));
        let (a, h) = (accepted.clone(), handshakes.clone());
        let task = tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                if a.fetch_add(1, Ordering::SeqCst) < drop {
                    std::mem::drop(sock);
                    continue;
                }
                let (acceptor, h) = (acceptor.clone(), h.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(sock).await else {
                        return;
                    };
                    h.fetch_add(1, Ordering::SeqCst);
                    if read_request(&mut tls).await.is_ok() {
                        let _ = tls
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                  X-AUSERNAME: jdoe\r\nContent-Length: 2\r\n\
                                  Connection: close\r\n\r\n{}",
                            )
                            .await;
                    }
                    let _ = tls.shutdown().await;
                });
            }
        });
        Ok(TestTlsServer {
            addr,
            ca_pem: ca.cert_pem,
            accepted,
            handshakes,
            task,
        })
    }

    /// The CA that signed the server's leaf.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// `https://localhost:<port>`.
    pub fn base_url(&self) -> String {
        format!("https://localhost:{}", self.addr.port())
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// TCP connections accepted, dropped ones included.
    pub fn connections(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// Completed TLS handshakes.
    pub fn handshakes(&self) -> usize {
        self.handshakes.load(Ordering::SeqCst)
    }
}

impl Drop for TestTlsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
