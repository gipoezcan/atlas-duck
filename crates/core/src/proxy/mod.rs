//! Proxy resolution (L42, §7.2). Order: the instance's own setting (`direct` or `host:port`),
//! else the OS static HTTPS proxy unless the host is on its bypass list, else direct. A PAC or
//! WPAD configuration is never evaluated: it only sets `pac_configured` so the UI can say so
//! (`PAC_HINT`). The process environment (`HTTPS_PROXY`, `NO_PROXY`, ...) is never read, here or
//! by the per-OS readers (I-20). There are no proxy credentials: a `407` is `auth_required`.

use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub use atlas_duck_atlassian::ProxyChoice;

pub mod os_linux;
pub mod os_macos;
pub mod os_windows;

/// §7.2 verbatim.
pub const PAC_HINT: &str = "your system uses a proxy auto-config script, which atlas-duck does not evaluate: set this instance's proxy (host:port or direct) in Settings";

/// How long `SystemProxySource` keeps a reading. A change applies to clients built later.
pub const OS_CACHE_TTL: Duration = Duration::from_secs(60);

/// Per-instance value (M2 `InstancePolicy.proxy`): absent (= `Os`), `"direct"` or `"host:port"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxySetting {
    Os,
    Direct,
    HostPort { host: String, port: u16 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyParseError {
    /// `user:pw@host:port`: L42 has no proxy credentials.
    Userinfo,
    /// Not `host:port` (missing or bad port, empty host, scheme, path, whitespace).
    Malformed,
}

impl fmt::Display for ProxyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyParseError::Userinfo => {
                f.write_str("a proxy takes no user name or password (use host:port)")
            }
            ProxyParseError::Malformed => f.write_str("expected `direct` or `host:port`"),
        }
    }
}

impl std::error::Error for ProxyParseError {}

impl ProxySetting {
    /// `""` is the OS setting; `"direct"` bypasses every proxy; otherwise `host:port`.
    pub fn parse(s: &str) -> Result<ProxySetting, ProxyParseError> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(ProxySetting::Os);
        }
        if s.eq_ignore_ascii_case("direct") {
            return Ok(ProxySetting::Direct);
        }
        if s.contains('@') {
            return Err(ProxyParseError::Userinfo);
        }
        if s.contains(|c: char| c.is_whitespace() || matches!(c, '/' | '\\' | '?' | '#')) {
            return Err(ProxyParseError::Malformed);
        }
        let (host, port) = split_host_port(s).ok_or(ProxyParseError::Malformed)?;
        Ok(ProxySetting::HostPort { host, port })
    }

    /// The value stored in `config.toml`; `None` for `Os` is the caller's (key absent).
    pub fn as_config_str(&self) -> String {
        match self {
            ProxySetting::Os => String::new(),
            ProxySetting::Direct => "direct".to_owned(),
            ProxySetting::HostPort { host, port } => host_port(host, *port),
        }
    }
}

/// `host:port` or `[v6]:port`; the host comes back without brackets.
fn split_host_port(s: &str) -> Option<(String, u16)> {
    let (h, p) = s.rsplit_once(':')?;
    if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port: u16 = p.parse().ok().filter(|p| *p != 0)?;
    let host = match h.strip_prefix('[') {
        Some(inner) => inner.strip_suffix(']')?,
        None if h.contains(':') => return None,
        None => h,
    };
    if host.is_empty() || host.contains(['[', ']']) {
        return None;
    }
    Some((host.to_owned(), port))
}

fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// What the OS says, reduced to what L42 uses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OsProxy {
    pub https: Option<(String, u16)>,
    pub bypass: Vec<String>,
    pub pac_configured: bool,
}

pub trait OsProxySource: Send + Sync {
    fn read(&self) -> OsProxy;
}

type Reader = Box<dyn Fn() -> OsProxy + Send + Sync>;

/// The per-OS reader behind a 60 s cache. Never consults the process environment.
pub struct SystemProxySource {
    reader: Reader,
    ttl: Duration,
    cache: Mutex<Option<(Instant, OsProxy)>>,
}

impl SystemProxySource {
    pub fn new() -> Self {
        Self::with_reader(Box::new(platform_read))
    }

    /// A source over any reader (tests inject fake registries and `gsettings` runners).
    pub fn with_reader(reader: Reader) -> Self {
        SystemProxySource {
            reader,
            ttl: OS_CACHE_TTL,
            cache: Mutex::new(None),
        }
    }

    #[cfg(feature = "testing")]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }
}

impl Default for SystemProxySource {
    fn default() -> Self {
        Self::new()
    }
}

impl OsProxySource for SystemProxySource {
    fn read(&self) -> OsProxy {
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((at, v)) = cache.as_ref()
            && at.elapsed() < self.ttl
        {
            return v.clone();
        }
        let v = (self.reader)();
        *cache = Some((Instant::now(), v.clone()));
        v
    }
}

#[cfg(windows)]
fn platform_read() -> OsProxy {
    os_windows::read_with(&os_windows::WinInetRegistry)
}

#[cfg(target_os = "macos")]
fn platform_read() -> OsProxy {
    os_macos::read()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_read() -> OsProxy {
    os_linux::read()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedProxy {
    pub choice: ProxyChoice,
    pub pac_configured: bool,
    /// `"host:port"` or `"direct"`, for `APP_START` / `CONFIG_CHANGED`.
    pub effective: String,
}

pub fn resolve_proxy(setting: &ProxySetting, host: &str, os: &OsProxy) -> ResolvedProxy {
    let (choice, effective) = match setting {
        ProxySetting::Direct => (ProxyChoice::Direct, "direct".to_owned()),
        ProxySetting::HostPort { host: h, port } => (
            ProxyChoice::Proxy {
                host: h.clone(),
                port: *port,
            },
            host_port(h, *port),
        ),
        ProxySetting::Os => match &os.https {
            Some((h, p)) if !os.bypass.iter().any(|e| bypass_matches(host, e)) => (
                ProxyChoice::Proxy {
                    host: h.clone(),
                    port: *p,
                },
                host_port(h, *p),
            ),
            _ => (ProxyChoice::Direct, "direct".to_owned()),
        },
    };
    ResolvedProxy {
        choice,
        pac_configured: os.pac_configured,
        effective,
    }
}

/// One OS bypass entry against a host (PD-18): `<local>`, `*.suffix`, `.suffix`, an exact name or
/// address, each with an optional scheme and port that are ignored. CIDR ranges and inner
/// wildcards are not supported and never match.
pub fn bypass_matches(host: &str, entry: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let mut e = entry.trim().to_ascii_lowercase();
    if e == "<local>" {
        return !host.contains('.');
    }
    if let Some(stripped) = e
        .strip_prefix("http://")
        .or_else(|| e.strip_prefix("https://"))
    {
        e = stripped.to_owned();
    }
    if let Some((h, port)) = e.rsplit_once(':')
        && port.chars().all(|c| c.is_ascii_digit())
        && !h.contains(']')
    {
        e = h.to_owned();
    }
    if let Some(suffix) = e.strip_prefix("*.") {
        return host.ends_with(&format!(".{suffix}"));
    }
    if let Some(suffix) = e.strip_prefix('.') {
        return host.ends_with(&format!(".{suffix}"));
    }
    if e.contains('*') || e.contains('/') {
        return false;
    }
    host == e
}
