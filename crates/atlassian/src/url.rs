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

    /// `scheme://host[:port]`, without the context path.
    fn origin_str(&self) -> String {
        let port = self.port.map(|p| format!(":{p}")).unwrap_or_default();
        format!("{}://{}{}", self.scheme, self.host, port)
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
    let raw = raw.trim();
    // The `url` crate resolves `.`/`..`/`%2e%2e` while parsing, so the check has to see the raw
    // text; a base URL that only works through traversal resolution is refused (plan decision).
    if has_dot_segment(raw_path(raw)) {
        return Err(BaseUrlError::Invalid("dot segment"));
    }
    let u = url::Url::parse(raw).map_err(|_| BaseUrlError::Invalid("unparsable"))?;
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
    Ok(NormalizedBaseUrl {
        scheme: u.scheme().to_owned(),
        host,
        port,
        context_path: path.to_owned(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TemplateError {
    MissingParam(String),
    BadParam(String),
    /// The template itself is malformed (not rooted at `/`, query, fragment, unbalanced braces,
    /// a dot segment) or does not build a URL under the base. Never caused by a parameter value.
    BadTemplate,
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TemplateError::MissingParam(n) => write!(f, "missing path parameter `{n}`"),
            TemplateError::BadParam(n) => write!(f, "bad path parameter `{n}`"),
            TemplateError::BadTemplate => f.write_str("malformed endpoint template"),
        }
    }
}

impl std::error::Error for TemplateError {}

/// Everything except ALPHA / DIGIT / `-` `.` `_` `~`.
const PATH_VALUE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Builds the request URL from an endpoint template (`/rest/api/2/issue/{key}`) under the base
/// URL including its context path (§7.2). Never accepts a full URL and never reads `_links.next`.
/// A placeholder value that is empty, `.`/`..` or would act as a dot segment is `BadParam`.
pub fn build_url(
    base: &NormalizedBaseUrl,
    template: &str,
    params: &serde_json::Value,
    query: &[(String, String)],
) -> Result<url::Url, TemplateError> {
    if !template.starts_with('/') || template.starts_with("//") || template.contains(['?', '#', BS])
    {
        return Err(TemplateError::BadTemplate);
    }
    let mut path = String::from(base.context_path());
    let mut rest = template;
    while let Some(open) = rest.find(['{', '}']) {
        if rest.as_bytes()[open] == b'}' {
            return Err(TemplateError::BadTemplate);
        }
        path.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let close = after
            .find(['{', '}'])
            .filter(|&i| after.as_bytes()[i] == b'}')
            .ok_or(TemplateError::BadTemplate)?;
        let name = &after[..close];
        let value = match params.get(name) {
            None | Some(serde_json::Value::Null) => {
                return Err(TemplateError::MissingParam(name.to_owned()));
            }
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Number(n)) => n
                .as_i64()
                .map(|i| i.to_string())
                .or_else(|| n.as_u64().map(|u| u.to_string()))
                .ok_or_else(|| TemplateError::BadParam(name.to_owned()))?,
            Some(_) => return Err(TemplateError::BadParam(name.to_owned())),
        };
        if value.is_empty() || has_dot_segment(&value) {
            return Err(TemplateError::BadParam(name.to_owned()));
        }
        path.extend(percent_encoding::utf8_percent_encode(&value, PATH_VALUE));
        rest = &after[close + 1..];
    }
    path.push_str(rest);
    // Literal template text is registry data, but a dot segment must never leave this function.
    if has_dot_segment(&path) {
        return Err(TemplateError::BadTemplate);
    }
    let mut u = url::Url::parse(&format!("{}{}", base.origin_str(), path))
        .map_err(|_| TemplateError::BadTemplate)?;
    // The parser must not have rewritten the path (dot segments, backslashes).
    if u.path() != path {
        return Err(TemplateError::BadTemplate);
    }
    if !query.is_empty() {
        u.query_pairs_mut()
            .extend_pairs(query.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    }
    Ok(u)
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

/// The path part of a raw `scheme://authority/path?query#fragment` string.
fn raw_path(raw: &str) -> &str {
    let rest = raw.split_once("://").map_or(raw, |(_, r)| r);
    let rest = rest.split(['?', '#']).next().unwrap_or("");
    rest.find(['/', BS]).map_or("", |i| &rest[i..])
}

/// True if any path segment is `.` or `..` in any spelling a server or proxy may act on:
/// percent-encoded (`%2e`, `%2F`, `%5c`), with a path parameter (`..;x`), or separated by a backslash.
pub(crate) fn has_dot_segment(path: &str) -> bool {
    path.split(['/', BS]).any(|seg| {
        let decoded = percent_encoding::percent_decode_str(seg).decode_utf8_lossy();
        let decoded = decoded.split(';').next().unwrap_or("");
        decoded
            .split(['/', BS])
            .any(|piece| piece == "." || piece == "..")
    })
}

const BS: char = '\\';
