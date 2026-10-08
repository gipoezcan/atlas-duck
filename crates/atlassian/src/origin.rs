//! The origin guard (§7.2): no request, and so no PAT, leaves for a URL that is
//! not https, not under the bound base URL, or carries userinfo.

use crate::url::{NormalizedBaseUrl, UrlHash, url_hash};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginRefused {
    NotHttps,
    /// The base URL no longer hashes to the URL the PAT was bound to.
    BoundHashMismatch,
    OutsideBase,
    Userinfo,
}

pub fn origin_guard(
    url: &url::Url,
    base: &NormalizedBaseUrl,
    bound: &UrlHash,
) -> Result<(), OriginRefused> {
    let https = url.scheme() == "https";
    #[cfg(feature = "insecure-test-http")]
    let https = https || url.scheme() == "http";
    if !https {
        return Err(OriginRefused::NotHttps);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(OriginRefused::Userinfo);
    }
    if url_hash(base) != *bound {
        return Err(OriginRefused::BoundHashMismatch);
    }
    let same_origin = url.scheme() == base.scheme
        && url.host_str().map(str::to_ascii_lowercase).as_deref() == Some(base.host.as_str())
        && url.port() == base.port;
    if !same_origin {
        return Err(OriginRefused::OutsideBase);
    }
    // Segment-wise prefix: "/confluence" covers "/confluence/rest/..." but not "/confluence2/...".
    let path = url.path();
    let ctx = base.context_path.as_str();
    let under = ctx.is_empty() || path == ctx || path.starts_with(&format!("{ctx}/"));
    if !under || path.split('/').any(|s| s == "." || s == "..") {
        return Err(OriginRefused::OutsideBase);
    }
    Ok(())
}
