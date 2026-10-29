//! Static `dist-server` files (PD-220) from `ATLAS_DUCK_WEB_DIR`: a fixed route table (no
//! directory listing, no path built from the URL beyond `/assets/<name>` with
//! `<name>` = `[A-Za-z0-9._-]+` not starting with a dot), the desktop CSP adapted for a web
//! origin, `nosniff`, `no-referrer`, `no-store` for HTML and `immutable` for the hashed assets.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use atlas_duck_core::Lang;
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

/// The web dir and the user guide's page table (`<dir>/docs/<lang>/manifest.json`, read once).
#[derive(Clone)]
pub struct WebDir(pub PathBuf, pub DocsIndex);

impl WebDir {
    pub fn new(path: PathBuf) -> WebDir {
        let docs = DocsIndex::load(&path);
        WebDir(path, docs)
    }
}

/// The guide's languages (M16, PD-323); the first is the fallback of `/docs`.
pub const DOC_LANGS: [&str; 2] = ["en", "de"];

/// Page id → file, per language, from the generated `manifest.json` files. Only a page listed
/// here is served, so no part of the URL ever reaches the file system unchecked.
#[derive(Clone, Default)]
pub struct DocsIndex(Arc<HashMap<&'static str, HashMap<String, String>>>);

impl DocsIndex {
    /// Reads the manifests under `web/docs`. A missing or unreadable one leaves that language
    /// without pages (404) and is logged once; the server starts regardless.
    pub fn load(web: &Path) -> DocsIndex {
        let mut langs = HashMap::new();
        let mut missing: Vec<&str> = Vec::new();
        for lang in DOC_LANGS {
            let path = web.join("docs").join(lang).join("manifest.json");
            match Self::read(&path) {
                Some(pages) => {
                    langs.insert(lang, pages);
                }
                None => missing.push(lang),
            }
        }
        if !missing.is_empty() {
            tracing::warn!(event = "docs_unavailable", langs = %missing.join(","));
        }
        DocsIndex(Arc::new(langs))
    }

    fn read(path: &Path) -> Option<HashMap<String, String>> {
        let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
        let mut pages = HashMap::new();
        for p in doc.get("pages")?.as_array()? {
            let id = p.get("id")?.as_str()?;
            let file = p.get("file")?.as_str()?;
            if valid_asset_name(id) && valid_asset_name(file) {
                pages.insert(id.to_owned(), file.to_owned());
            }
        }
        Some(pages)
    }

    pub fn file(&self, lang: &str, page: &str) -> Option<&str> {
        self.0.get(lang)?.get(page).map(String::as_str)
    }

    fn has_lang(&self, lang: &str) -> bool {
        self.0.contains_key(lang)
    }
}

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

/// The plain 404 of the static files (also for `/docs` paths no route names).
pub fn not_found() -> Response {
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

/// `GET /docs` and `/docs/`: to the guide in `lang`, the language the caller's `Accept-Language`
/// prefers (`pref_routes::accept_language`, the rule the UI language on `auto` follows).
pub fn docs_redirect(lang: Lang) -> Response {
    let lang = match lang {
        Lang::De => "de",
        Lang::En => "en",
    };
    let mut r = Response::new(Body::empty());
    *r.status_mut() = StatusCode::FOUND;
    r.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&format!("/docs/{lang}/"))
            .unwrap_or(HeaderValue::from_static("/docs/en/")),
    );
    r.headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Accept-Language"));
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    common_headers(&mut r);
    r
}

/// `GET /docs/{lang}` (no slash): the guide's relative links need the slash, so a known language
/// is sent there.
pub fn docs_add_slash(dir: &WebDir, lang: &str) -> Response {
    if !dir.1.has_lang(lang) {
        return not_found();
    }
    let mut r = Response::new(Body::empty());
    *r.status_mut() = StatusCode::MOVED_PERMANENTLY;
    if let Ok(v) = HeaderValue::from_str(&format!("/docs/{lang}/")) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(DOCS_CACHE));
    common_headers(&mut r);
    r
}

/// `GET /docs/{lang}/` (`page` = `None`: the index) and `/docs/{lang}/{page}`.
pub async fn docs_page(dir: &WebDir, lang: &str, page: Option<&str>) -> Response {
    let Some(file_name) = dir.1.file(lang, page.unwrap_or("index")) else {
        return not_found();
    };
    file(
        &dir.0.join("docs").join(lang).join(file_name),
        file_name,
        DOCS_CACHE,
    )
    .await
}

/// `GET /docs/{lang}/assets/{name}`.
pub async fn docs_asset(dir: &WebDir, lang: &str, name: &str) -> Response {
    if !dir.1.has_lang(lang) || !valid_asset_name(name) {
        return not_found();
    }
    file(
        &dir.0.join("docs").join(lang).join("assets").join(name),
        name,
        DOCS_CACHE,
    )
    .await
}

/// The guide's files are not content-hashed: the browser asks again each time.
const DOCS_CACHE: &str = "no-cache";

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
