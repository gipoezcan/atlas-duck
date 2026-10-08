//! §6.4 rendering safety: the sanitizer and the sandboxed-iframe document.
//!
//! This is the XSS boundary for agent- and Atlassian-controlled HTML. The output never carries
//! `style`/`class` attributes, `<style>`, scripts, links, event handlers or remote resources.

use std::collections::{HashMap, HashSet};
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

/// Tags that may survive (§6.4): semantic text, lists, tables, code, quotes, `<img>` (data: only).
/// `<bdi>` is the one isolation element the spec asks renderers to emit; `<bdo>`, `dir`,
/// `<details>`, `<summary>`, `<ruby>`/`<rp>`/`<rt>`, `<center>`, `<font>`, `<small>`/`<sub>`/`<sup>`
/// are out: they can reorder, hide or shrink text. Removed tags keep their children.
const TAGS: &[&str] = &[
    "p",
    "br",
    "hr",
    "div",
    "span",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "b",
    "strong",
    "i",
    "em",
    "u",
    "s",
    "del",
    "ins",
    "code",
    "pre",
    "kbd",
    "samp",
    "var",
    "blockquote",
    "ul",
    "ol",
    "li",
    "dl",
    "dt",
    "dd",
    "table",
    "thead",
    "tbody",
    "tfoot",
    "tr",
    "td",
    "th",
    "caption",
    "bdi",
    "img",
];

fn builder(keep_links: bool) -> ammonia::Builder<'static> {
    let mut tags: HashSet<&'static str> = TAGS.iter().copied().collect();
    let mut attrs: HashMap<&'static str, HashSet<&'static str>> = HashMap::from([
        ("img", HashSet::from(["src", "alt"])),
        ("td", HashSet::from(["colspan", "rowspan"])),
        ("th", HashSet::from(["colspan", "rowspan"])),
        ("ol", HashSet::from(["start"])),
    ]);
    if keep_links {
        // Link pass only: the anchors are turned into text by `links_to_text` right after.
        tags.insert("a");
        attrs.insert("a", HashSet::from(["href"]));
    }
    let mut b = ammonia::Builder::default();
    b.tags(tags)
        .tag_attributes(attrs)
        .generic_attributes(HashSet::new())
        .generic_attribute_prefixes(HashSet::new())
        .tag_attribute_values(HashMap::new())
        .set_tag_attribute_values(HashMap::new())
        .allowed_classes(HashMap::new())
        .clean_content_tags(HashSet::from(["script", "style"]))
        .url_schemes(if keep_links {
            LINK_PASS_SCHEMES.iter().copied().collect()
        } else {
            HashSet::from(["data"])
        })
        .url_relative(if keep_links {
            ammonia::UrlRelative::PassThrough
        } else {
            ammonia::UrlRelative::Deny
        })
        .link_rel(None)
        .strip_comments(true)
        .attribute_filter(|element, attribute, value| match (element, attribute) {
            ("img", "src") => is_inline_raster(value).then(|| value.into()),
            _ => Some(value.into()),
        });
    b
}

/// The link pass must keep an `href` for `links_to_text` to show it, but ammonia drops URLs with
/// a scheme outside this set before any filter runs. Listing the schemes seen in practice (inert
/// ones included, they only ever become text) means a link with an exotic scheme or an
/// unparseable URL shows its text without the URL. `img src` is still restricted by the filter
/// above and, in the final pass, by the `data`-only scheme set.
const LINK_PASS_SCHEMES: &[&str] = &[
    "http",
    "https",
    "mailto",
    "tel",
    "sms",
    "javascript",
    "vbscript",
    "data",
    "file",
    "ftp",
    "ftps",
    "sftp",
    "ssh",
    "ws",
    "wss",
    "blob",
    "about",
    "cid",
    "callto",
    "geo",
    "news",
    "nntp",
    "irc",
    "ircs",
    "xmpp",
    "sip",
    "sips",
    "magnet",
    "urn",
    "view-source",
    "intent",
    "git",
    "svn",
    "smb",
    "afp",
    "ldap",
    "ldaps",
    "gopher",
    "webcal",
    "tauri",
    "isolation",
    "ipc",
];

/// Only `data:image/{png,jpeg,gif,webp};base64,` survives as an image source.
fn is_inline_raster(src: &str) -> bool {
    let s = src.trim_start().to_ascii_lowercase();
    ["png", "jpeg", "gif", "webp"]
        .iter()
        .any(|t| s.starts_with(&format!("data:image/{t};base64,")))
}

/// Rewrites `<a href="U">T</a>` to `T (U)` (§6.4 "links are text, URL visible"); `T` alone when
/// `U` is empty or equals `T`. Works on ammonia's canonical output: there `<` in text is always
/// `&lt;`, so `<a>`/`<a href="` can only be a real anchor start, and anchors cannot nest.
fn links_to_text(clean: &str) -> String {
    let mut out = String::with_capacity(clean.len());
    let mut rest = clean;
    while let Some(i) = rest.find("<a") {
        let after = &rest[i + 2..];
        let (url, tag_len) = if after.starts_with('>') {
            ("", 3)
        } else if let Some(v) = after.strip_prefix(" href=\"") {
            match v.find("\">") {
                Some(end) => (&v[..end], 2 + 7 + end + 2),
                None => break,
            }
        } else {
            out.push_str(&rest[..i + 2]);
            rest = after;
            continue;
        };
        out.push_str(&rest[..i]);
        let body = &rest[i + tag_len..];
        let Some(close) = body.find("</a>") else {
            break;
        };
        let inner = &body[..close];
        out.push_str(inner);
        if !url.trim().is_empty() && inner != url {
            out.push_str(" (");
            out.push_str(&url.replace('<', "&lt;").replace('>', "&gt;"));
            out.push(')');
        }
        rest = &body[close + 4..];
    }
    out.push_str(rest);
    out
}

/// Allowlist sanitizer (`ammonia`, explicit tag and attribute lists); never keeps
/// `style`/`class`/`id`/`dir` or `<style>`. Links become text with the URL visible.
/// Renderers must use `<bdi>` for bidi isolation: `dir` is dropped.
pub fn sanitize_html(html: &str) -> String {
    static LINKS: OnceLock<ammonia::Builder<'static>> = OnceLock::new();
    static FINAL: OnceLock<ammonia::Builder<'static>> = OnceLock::new();
    let first = LINKS.get_or_init(|| builder(true)).clean(html).to_string();
    FINAL
        .get_or_init(|| builder(false))
        .clean(&links_to_text(&first))
        .to_string()
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
