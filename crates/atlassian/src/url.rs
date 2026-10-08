//! Base-URL normalization and the URL hash a PAT is bound to (§7.1).

use std::fmt;

use sha2::{Digest, Sha256};

/// A validated instance base URL: `scheme://host[:port]context_path`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedBaseUrl {
    pub(crate) scheme: String,
    pub(crate) host: String,
    pub(crate) port: Option<u16>,
    pub(crate) context_path: String,
}

impl NormalizedBaseUrl {
    /// `scheme://host[:port]context_path`, no trailing slash.
    pub fn as_str(&self) -> String {
        let port = self.port.map(|p| format!(":{p}")).unwrap_or_default();
        format!(
            "{}://{}{}{}",
            self.scheme, self.host, port, self.context_path
        )
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Empty, or starting with `/` and without a trailing slash.
    pub fn context_path(&self) -> &str {
        &self.context_path
    }

    pub fn is_https(&self) -> bool {
        self.scheme == "https"
    }
}

impl fmt::Display for NormalizedBaseUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BaseUrlError {
    /// `http://` (§7.1: https only).
    InsecureScheme,
    Invalid(&'static str),
}

impl fmt::Display for BaseUrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BaseUrlError::InsecureScheme => f.write_str("base URL must use https"),
            BaseUrlError::Invalid(why) => write!(f, "invalid base URL: {why}"),
        }
    }
}

impl std::error::Error for BaseUrlError {}

pub fn normalize_base_url(raw: &str) -> Result<NormalizedBaseUrl, BaseUrlError> {
    let u = url::Url::parse(raw.trim()).map_err(|_| BaseUrlError::Invalid("unparsable"))?;
    match u.scheme() {
        "https" => {}
        #[cfg(feature = "insecure-test-http")]
        "http" => {}
        #[cfg(not(feature = "insecure-test-http"))]
        "http" => return Err(BaseUrlError::InsecureScheme),
        _ => return Err(BaseUrlError::Invalid("scheme")),
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(BaseUrlError::Invalid("userinfo"));
    }
    if u.query().is_some() || u.fragment().is_some() {
        return Err(BaseUrlError::Invalid("query or fragment"));
    }
    let host = u
        .host_str()
        .ok_or(BaseUrlError::Invalid("host"))?
        .to_ascii_lowercase();
    let port = u.port(); // `url` already drops the scheme's default port
    let path = u.path().trim_end_matches('/');
    if path.split('/').any(|seg| {
        seg == "."
            || seg == ".."
            || seg.eq_ignore_ascii_case("%2e")
            || seg.eq_ignore_ascii_case("%2e%2e")
    }) {
        return Err(BaseUrlError::Invalid("dot segment"));
    }
    Ok(NormalizedBaseUrl {
        scheme: u.scheme().to_owned(),
        host,
        port,
        context_path: path.to_owned(),
    })
}

/// SHA-256 over the domain-separated normalized base URL; the PAT is bound to it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UrlHash(pub [u8; 32]);

impl UrlHash {
    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push(HEX[usize::from(b >> 4)] as char);
            s.push(HEX[usize::from(b & 15)] as char);
        }
        s
    }

    /// 64 hex digits (either case); anything else is `None`.
    pub fn from_hex(s: &str) -> Option<UrlHash> {
        let b = s.as_bytes();
        if b.len() != 64 {
            return None;
        }
        let nib = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        };
        let mut out = [0u8; 32];
        for (i, pair) in b.chunks_exact(2).enumerate() {
            out[i] = (nib(pair[0])? << 4) | nib(pair[1])?;
        }
        Some(UrlHash(out))
    }
}

impl fmt::Debug for UrlHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UrlHash({})", self.to_hex())
    }
}

pub fn url_hash(u: &NormalizedBaseUrl) -> UrlHash {
    let mut h = Sha256::new();
    h.update(b"atlas-duck/base-url/v1\0");
    h.update(u.as_str().as_bytes());
    UrlHash(h.finalize().into())
}
