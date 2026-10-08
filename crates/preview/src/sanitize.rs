//! §6.4 rendering safety: the sanitizer and the sandboxed-iframe document.
//!
//! This is the XSS boundary for agent- and Atlassian-controlled HTML. The output never carries
//! `style`/`class` attributes, `<style>`, scripts, links, event handlers or remote resources.

use std::collections::HashSet;
use std::sync::OnceLock;

/// Platform-specific app origin (§6.4): where `preview.css` is served from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOsLinux,
    Windows,
}

/// §6.4 (verbatim): `tauri://localhost` on macOS/Linux, `http://tauri.localhost` on Windows.
pub fn app_origin(p: Platform) -> &'static str {
    match p {
        Platform::MacOsLinux => "tauri://localhost",
        Platform::Windows => "http://tauri.localhost",
    }
}

fn builder() -> ammonia::Builder<'static> {
    let mut b = ammonia::Builder::default();
    b.rm_generic_attributes(["style", "class", "id", "title", "lang", "dir"])
        // Links are text (§6.4): the element goes, its children stay.
        .rm_tags(["a", "style", "script"])
        .url_schemes(HashSet::from(["data"]))
        .url_relative(ammonia::UrlRelative::Deny)
        .link_rel(None)
        .attribute_filter(|element, attribute, value| {
            if element == "img" && attribute == "src" {
                is_inline_raster(value).then(|| value.into())
            } else {
                Some(value.into())
            }
        });
    b
}

/// Only `data:image/{png,jpeg,gif,webp};base64,` survives as an image source.
fn is_inline_raster(src: &str) -> bool {
    let s = src.trim_start().to_ascii_lowercase();
    ["png", "jpeg", "gif", "webp"]
        .iter()
        .any(|t| s.starts_with(&format!("data:image/{t};base64,")))
}

/// Allowlist sanitizer (`ammonia`); never keeps `style`/`class` or `<style>`.
pub fn sanitize_html(html: &str) -> String {
    static B: OnceLock<ammonia::Builder<'static>> = OnceLock::new();
    B.get_or_init(builder).clean(html).to_string()
}

/// The `srcdoc` document: meta CSP is the first `<head>` element, then the bundled stylesheet.
/// The body is sanitized again here (idempotent), so a caller that forgot cannot open a hole.
/// The UI sets `sandbox=""` on the iframe.
pub fn iframe_document(body_html: &str, platform: Platform) -> String {
    let origin = app_origin(platform);
    let body = sanitize_html(body_html);
    format!(
        "<!doctype html><html><head><meta http-equiv=\"Content-Security-Policy\" \
         content=\"default-src 'none'; style-src {origin}/preview.css; img-src data:\">\
         <link rel=\"stylesheet\" href=\"{origin}/preview.css\"></head><body>{body}</body></html>"
    )
}
