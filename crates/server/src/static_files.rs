//! Static `dist-server` files (PD-220) from `ATLAS_DUCK_WEB_DIR`: a fixed route table (no
//! directory listing, no path built from the URL beyond `/assets/<name>` with
//! `<name>` = `[A-Za-z0-9._-]+` not starting with a dot), the desktop CSP adapted for a web
//! origin, `nosniff`, `no-referrer`, `no-store` for HTML and `immutable` for the hashed assets.

use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// PD-220.
pub const CSP: &str = "default-src 'self'; frame-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/// URL path → HTML file of the server build.
pub const PAGES: [(&str, &str); 10] = [
    ("/", "index.html"),
    ("/login", "login.html"),
    ("/approvals", "approvals.html"),
    ("/credentials", "credentials.html"),
    ("/api-keys", "api-keys.html"),
    ("/admin", "admin.html"),
    // M14 T9.
    ("/oauth/consent", "oauth-consent.html"),
    ("/connected-apps", "connected-apps.html"),
    // M14 T16.
    ("/audit", "audit.html"),
    // M14 T20.
    ("/auditor", "auditor.html"),
];

#[derive(Clone)]
pub struct WebDir(pub PathBuf);

pub fn valid_asset_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn content_type(name: &str) -> &'static str {
    match name.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("json") => "application/json",
        Some("map") => "application/json",
        _ => "application/octet-stream",
    }
}

fn not_found() -> Response {
    let mut r = (StatusCode::NOT_FOUND, "not found").into_response();
    common_headers(&mut r);
    r
}

fn common_headers(r: &mut Response) {
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}

async fn file(path: &Path, name: &str, cache: &'static str) -> Response {
    match tokio::fs::read(path).await {
        Ok(bytes) => {
            let mut r = Response::new(Body::from(bytes));
            common_headers(&mut r);
            let h = r.headers_mut();
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(content_type(name)),
            );
            h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
            r
        }
        Err(_) => not_found(),
    }
}

/// One of [`PAGES`].
pub async fn page(dir: &WebDir, url_path: &str) -> Response {
    match PAGES.iter().find(|(p, _)| *p == url_path) {
        Some((_, html)) => file(&dir.0.join(html), html, "no-store").await,
        None => not_found(),
    }
}

/// `GET /assets/{name}`.
pub async fn asset(dir: &WebDir, name: &str) -> Response {
    if !valid_asset_name(name) {
        return not_found();
    }
    file(
        &dir.0.join("assets").join(name),
        name,
        "public, max-age=31536000, immutable",
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_names() {
        for ok in ["index-AbC123.js", "a.css", "x_y-z.woff2"] {
            assert!(valid_asset_name(ok), "{ok}");
        }
        for bad in [
            "", "..", ".env", "../x", "a/b", "a\\b", "%2e%2e", "a b", "é.js",
        ] {
            assert!(!valid_asset_name(bad), "{bad}");
        }
    }
}
