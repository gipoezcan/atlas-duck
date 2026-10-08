//! The per-instance HTTP client (§7.2): reqwest over rustls (ring) with OS roots plus an optional
//! custom CA, no system or environment proxy and at most one explicit proxy, no redirects, and the
//! one-request engine in `send.rs` behind the audit, method, origin and identity guards.

mod classify;
mod limiter;
mod paginate;
mod send;
mod tls;
mod write;

#[cfg(feature = "testing")]
pub(crate) use tls::ensure_provider;

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use reqwest::header::{ACCEPT, HeaderMap, HeaderValue};
use tokio_util::sync::CancellationToken;

use crate::cover::{AuditCover, DateObserver};
use crate::credentials::CredentialProvider;
use crate::types::{
    FetchFailure, FetchOutcome, GetCall, PostSendKind, SearchCall, UpstreamResponse,
};
use crate::url::NormalizedBaseUrl;

/// `atlassian`'s own product tag (no `registry` edge); only Jira responses are identity-checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Product {
    Jira,
    Confluence,
}

/// The one proxy decision `core` resolved for the instance (Task 11, L42).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyChoice {
    Direct,
    Proxy { host: String, port: u16 },
}

/// §7.2 time budgets this crate enforces itself; the 120 s read budget is `ReadBudget` (Task 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    pub connect: Duration,
    /// Per HTTP call: from handing the request to the connection pool to the last body byte.
    pub per_call: Duration,
    pub write: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            connect: Duration::from_secs(10),
            per_call: Duration::from_secs(30),
            write: Duration::from_secs(60),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub instance_id: String,
    pub product: Product,
    pub base: NormalizedBaseUrl,
    pub custom_ca_pem: Option<Vec<u8>>,
    pub proxy: ProxyChoice,
    /// `atlas-duck/<APP_VERSION>`, built by `core`.
    pub user_agent: String,
    pub timeouts: Timeouts,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildError {
    Tls(String),
    Proxy(String),
    CaPem(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::Tls(m) => write!(f, "TLS client setup failed: {m}"),
            BuildError::Proxy(m) => write!(f, "invalid proxy: {m}"),
            BuildError::CaPem(m) => write!(f, "invalid custom CA bundle: {m}"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Cancel handle and shared capture of one call (Δ C.4, PD-07). Clones share state.
#[derive(Clone, Default)]
pub struct FetchControl {
    inner: Arc<ControlInner>,
}

#[derive(Default)]
struct ControlInner {
    token: CancellationToken,
    state: Mutex<CaptureState>,
}

#[derive(Default)]
struct CaptureState {
    sent: bool,
    pages: Vec<UpstreamResponse>,
    partial: Vec<u8>,
}

/// What a call had received when `take_captured` ran.
#[derive(Clone, PartialEq, Eq)]
pub struct Captured {
    /// The request was handed to the connection (or was about to be): the conservative side.
    pub sent: bool,
    /// Completed pages of a paginated read (Task 10).
    pub pages: Vec<UpstreamResponse>,
    /// Bytes of the response body being read.
    pub partial: Vec<u8>,
}

impl fmt::Debug for Captured {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Captured")
            .field("sent", &self.sent)
            .field("pages", &self.pages)
            .field("partial", &format_args!("len={}", self.partial.len()))
            .finish()
    }
}

impl FetchControl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Never awaits; the call notices at its next await point.
    pub fn cancel(&self) {
        self.inner.token.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.token.is_cancelled()
    }

    /// A synchronous snapshot. The control keeps its state, so repeated calls and the call's own
    /// `CancelledInFlight { bytes_received }` see the same bytes.
    pub fn take_captured(&self) -> Captured {
        let s = self.state();
        Captured {
            sent: s.sent,
            pages: s.pages.clone(),
            partial: s.partial.clone(),
        }
    }

    pub(crate) async fn cancelled(&self) {
        self.inner.token.cancelled().await;
    }

    pub(crate) fn mark_sent(&self) {
        self.state().sent = true;
    }

    pub(crate) fn is_sent(&self) -> bool {
        self.state().sent
    }

    pub(crate) fn clear_partial(&self) {
        self.state().partial.clear();
    }

    /// Appends a body chunk; returns the new partial length.
    pub(crate) fn append_partial(&self, chunk: &[u8]) -> usize {
        let mut s = self.state();
        s.partial.extend_from_slice(chunk);
        s.partial.len()
    }

    pub(crate) fn snapshot_partial(&self) -> Vec<u8> {
        self.state().partial.clone()
    }

    pub(crate) fn take_partial(&self) -> Vec<u8> {
        std::mem::take(&mut self.state().partial)
    }

    /// A completed page of a paginated read (kept for `take_captured`).
    pub(crate) fn push_page(&self, page: UpstreamResponse) {
        self.state().pages.push(page);
    }

    /// Never held across an `.await`: every caller above locks, mutates and drops in one statement.
    fn state(&self) -> MutexGuard<'_, CaptureState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl fmt::Debug for FetchControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchControl")
            .field("cancelled", &self.is_cancelled())
            .field("sent", &self.is_sent())
            .finish_non_exhaustive()
    }
}

/// One configured instance. Every PAT-bearing request goes through `send.rs`.
pub struct InstanceClient {
    http: reqwest::Client,
    cfg: ClientConfig,
    limiter: limiter::Limiter,
    creds: Arc<dyn CredentialProvider>,
    dates: Arc<dyn DateObserver>,
}

impl fmt::Debug for InstanceClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstanceClient")
            .field("instance_id", &self.cfg.instance_id)
            .field("product", &self.cfg.product)
            .finish_non_exhaustive()
    }
}

impl InstanceClient {
    pub fn build(
        cfg: ClientConfig,
        creds: Arc<dyn CredentialProvider>,
        dates: Arc<dyn DateObserver>,
    ) -> Result<InstanceClient, BuildError> {
        tls::ensure_provider();
        let mut default_headers = HeaderMap::new();
        default_headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        let mut b = reqwest::Client::builder()
            .no_proxy() // never system/env proxies (§7.2, L42)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(cfg.timeouts.connect)
            .user_agent(cfg.user_agent.clone())
            .default_headers(default_headers)
            .http1_only()
            .pool_idle_timeout(Duration::from_secs(60));
        #[cfg(not(feature = "insecure-test-http"))]
        {
            b = b.https_only(true);
        }
        if let ProxyChoice::Proxy { host, port } = &cfg.proxy {
            b = b.proxy(proxy(host, *port)?);
        }
        if let Some(pem) = &cfg.custom_ca_pem {
            b = b.tls_certs_merge(tls::ca_certs(pem)?);
        }
        let http = b.build().map_err(|e| BuildError::Tls(e.to_string()))?;
        Ok(InstanceClient {
            http,
            cfg,
            limiter: limiter::Limiter::new(),
            creds,
            dates,
        })
    }

    /// `get_ctl` with a fresh control. The cover is the proof of a committed start record; the API
    /// has no way to send without one:
    ///
    /// ```compile_fail,E0451
    /// # async fn f(c: &atlas_duck_atlassian::InstanceClient, call: &atlas_duck_atlassian::GetCall) {
    /// let _ = c.get(&atlas_duck_atlassian::AuditCover { kind: todo!() }, call).await;
    /// # }
    /// ```
    pub async fn get(&self, cover: &AuditCover, call: &GetCall) -> FetchOutcome {
        self.get_ctl(cover, call, &FetchControl::new()).await
    }

    pub async fn get_ctl(
        &self,
        cover: &AuditCover,
        call: &GetCall,
        ctl: &FetchControl,
    ) -> FetchOutcome {
        let req = send::OneRequest {
            target: send::Target::Template {
                method: reqwest::Method::GET,
                template: &call.endpoint_template,
                params: &call.params,
                query: &call.query,
                json_body: None,
            },
            overall: None,
            max_response_bytes: send::MAX_RESPONSE_BYTES,
            cap_kind: PostSendKind::ResponseCap32MiB,
        };
        self.send_one(cover, req, ctl).await
    }

    pub async fn post_search(&self, cover: &AuditCover, call: &SearchCall) -> FetchOutcome {
        self.post_search_ctl(cover, call, &FetchControl::new())
            .await
    }

    /// The one allowlisted read `POST` (`jira.search`); the method guard refuses any other path.
    pub async fn post_search_ctl(
        &self,
        cover: &AuditCover,
        call: &SearchCall,
        ctl: &FetchControl,
    ) -> FetchOutcome {
        let Ok(body) = serde_json::to_vec(&call.body) else {
            return FetchOutcome::Failed(FetchFailure::MethodGuardRefused);
        };
        let req = send::OneRequest {
            target: send::Target::Template {
                method: reqwest::Method::POST,
                template: &call.endpoint_template,
                params: &serde_json::Value::Null,
                query: &[],
                json_body: Some(body),
            },
            overall: None,
            max_response_bytes: send::MAX_RESPONSE_BYTES,
            cap_kind: PostSendKind::ResponseCap32MiB,
        };
        self.send_one(cover, req, ctl).await
    }

    pub fn base(&self) -> &NormalizedBaseUrl {
        &self.cfg.base
    }
}

/// `http://host:port` with nothing else: a host that would smuggle userinfo, a path or a query
/// into the proxy URL is refused (no proxy credentials are ever sent, §7.2).
fn proxy(host: &str, port: u16) -> Result<reqwest::Proxy, BuildError> {
    let bad = |why: &str| BuildError::Proxy(why.to_owned());
    if host.is_empty() || host.contains(['@', '/', '\\', '?', '#', ' ']) {
        return Err(bad("host"));
    }
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let raw = format!("http://{host}:{port}");
    let u = url::Url::parse(&raw).map_err(|_| bad("host"))?;
    if !u.username().is_empty() || u.password().is_some() || u.path() != "/" || u.query().is_some()
    {
        return Err(bad("host"));
    }
    reqwest::Proxy::all(u.as_str()).map_err(|e| BuildError::Proxy(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_host_validation() {
        assert!(proxy("proxy.corp", 3128).is_ok());
        assert!(proxy("10.0.0.1", 8080).is_ok());
        assert!(proxy("::1", 8080).is_ok());
        for bad in ["", "user:pw@proxy", "proxy/x", "proxy?x", "proxy#x", "a b"] {
            assert!(matches!(proxy(bad, 1), Err(BuildError::Proxy(_))), "{bad}");
        }
    }

    #[test]
    fn control_snapshot_keeps_state() {
        let ctl = FetchControl::new();
        let other = ctl.clone();
        assert!(!ctl.take_captured().sent);
        ctl.mark_sent();
        assert_eq!(ctl.append_partial(b"abc"), 3);
        let snap = other.take_captured();
        assert!(snap.sent);
        assert_eq!(snap.partial, b"abc");
        assert_eq!(other.take_captured().partial, b"abc");
        other.cancel();
        assert!(ctl.is_cancelled());
        assert_eq!(ctl.take_partial(), b"abc");
        assert!(ctl.take_captured().partial.is_empty());
    }

    #[test]
    fn captured_debug_is_redacted() {
        let c = Captured {
            sent: true,
            pages: vec![],
            partial: b"secret-canary".to_vec(),
        };
        let s = format!("{c:?}");
        assert!(!s.contains("canary") && s.contains("len=13"), "{s}");
    }
}

/// Without the test feature there is no plain-http path at all (§7.1, §13).
#[cfg(all(test, not(feature = "insecure-test-http")))]
mod https_only_tests {
    use super::*;
    use crate::cover::{CommitProbe, CoverIssuer};
    use crate::credentials::{CredentialError, PatSecret, StoredCredential, StoredIdentity};
    use crate::url::url_hash;

    struct OneCred(NormalizedBaseUrl);

    impl CredentialProvider for OneCred {
        fn load(&self, _: &str) -> Result<Option<StoredCredential>, CredentialError> {
            Ok(Some(StoredCredential {
                pat: PatSecret::new("pat".to_owned()),
                base_url_hash: url_hash(&self.0),
                identity: StoredIdentity {
                    atlassian_user: "jdoe".to_owned(),
                    atlassian_user_key: "JIRAUSER1".to_owned(),
                },
                expires_at: None,
            }))
        }
        fn store(&self, _: &str, _: StoredCredential) -> Result<(), CredentialError> {
            Ok(())
        }
        fn delete(&self, _: &str) -> Result<(), CredentialError> {
            Ok(())
        }
    }

    struct NoDates;

    impl DateObserver for NoDates {
        fn observe(&self, _: &str, _: std::time::SystemTime, _: std::time::Instant) {}
    }

    struct Yes;

    impl CommitProbe for Yes {
        fn request_committed(&self, _: &str) -> bool {
            true
        }
        fn system_fetch_started(&self, _: &str) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn http_base_is_refused_and_nothing_connects() -> Result<(), Box<dyn std::error::Error>> {
        assert!(crate::url::normalize_base_url("http://127.0.0.1").is_err());
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        // Only constructible inside the crate: the public parser refuses http here.
        let base = NormalizedBaseUrl {
            scheme: "http".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: Some(listener.local_addr()?.port()),
            context_path: String::new(),
        };
        let cfg = ClientConfig {
            instance_id: "ins_x".to_owned(),
            product: Product::Jira,
            base: base.clone(),
            custom_ca_pem: None,
            proxy: ProxyChoice::Direct,
            user_agent: "atlas-duck/test".to_owned(),
            timeouts: Timeouts::default(),
        };
        let client = InstanceClient::build(cfg, Arc::new(OneCred(base)), Arc::new(NoDates))?;
        let cover = CoverIssuer::new(Arc::new(Yes)).for_request("req_x")?;
        let call = GetCall {
            endpoint_template: "/rest/api/2/myself".to_owned(),
            params: serde_json::json!({}),
            query: vec![],
        };
        assert_eq!(
            client.get(&cover, &call).await,
            FetchOutcome::Failed(FetchFailure::OriginGuardRefused)
        );
        assert_eq!(
            listener.accept().err().map(|e| e.kind()),
            Some(std::io::ErrorKind::WouldBlock)
        );
        Ok(())
    }
}
