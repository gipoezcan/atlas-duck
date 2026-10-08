//! The method guard (§5.1 invariant 3, §7.2): outside `send_approved` the client sends only
//! `GET`, plus `POST` to the one allowlisted search path; inside it, only the exact request of
//! the approved list entry.

use std::fmt;

use crate::types::HttpRequestSpec;

/// The only `POST` that is not an approved write (`jira.search`).
pub const ALLOWED_READ_POSTS: &[&str] = &["/rest/api/2/search"];

pub(crate) enum SendMode<'a> {
    /// `path_template` is the endpoint template the URL was built from.
    Read { path_template: &'a str },
    /// The approved list entry being sent: the outgoing request must equal it byte for byte.
    ApprovedWrite(&'a HttpRequestSpec),
}

/// The request as it will be written, read off the built `reqwest::Request` (`client/send.rs`).
pub(crate) struct Outgoing<'a> {
    pub(crate) method: &'a str,
    pub(crate) url: &'a str,
    /// Every `Content-Type` header value, in order.
    pub(crate) content_types: &'a [&'a [u8]],
    /// `None`: the request has no body at all.
    pub(crate) body: Option<&'a [u8]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MethodRefused;

impl fmt::Display for MethodRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("method not allowed outside an approved write")
    }
}

impl std::error::Error for MethodRefused {}

pub(crate) fn method_guard(mode: &SendMode<'_>, out: &Outgoing<'_>) -> Result<(), MethodRefused> {
    let allowed = match mode {
        // Exact, case-sensitive comparison: "get", "Post", "search/" and "/REST/..." fail.
        SendMode::Read { path_template } => {
            out.method == "GET"
                || (out.method == "POST" && ALLOWED_READ_POSTS.contains(path_template))
        }
        SendMode::ApprovedWrite(spec) => matches_approved(spec, out),
    };
    if allowed { Ok(()) } else { Err(MethodRefused) }
}

/// The five §5.1 invariant 3 fields, byte for byte: method, resolved URL, `Content-Type` (absent
/// in the list means no header at all), body. A URL with a fragment never matches: the fragment
/// is not written, so the wire would differ from what was approved.
fn matches_approved(spec: &HttpRequestSpec, out: &Outgoing<'_>) -> bool {
    let content_type = match (spec.content_type.as_deref(), out.content_types) {
        (None, []) => true,
        (Some(want), [one]) => want.as_bytes() == *one,
        _ => false,
    };
    out.method == spec.method
        && out.url == spec.resolved_url
        && !out.url.contains('#')
        && content_type
        && out.body == Some(spec.body.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The distinct endpoint path templates of `registry` (jira/reads.rs, jira/writes.rs,
    /// confluence/reads.rs, confluence/writes.rs; the 46 registry entries share some paths),
    /// copied by hand because `atlassian` has no `registry` edge. When an endpoint is added
    /// there, add its path here.
    const REGISTRY_PATHS: &[&str] = &[
        "/rest/api/2/myself",
        "/rest/api/2/project",
        "/rest/api/2/project/{key}",
        "/rest/api/2/issue",
        "/rest/api/2/issue/{key}",
        "/rest/api/2/search",
        "/rest/api/2/issue/{key}/comment",
        "/rest/api/2/issue/{key}/worklog",
        "/rest/api/2/issue/{key}/transitions",
        "/rest/api/2/issue/{key}/editmeta",
        "/rest/api/2/issue/{key}/assignee",
        "/rest/api/2/issue/createmeta/{project}/issuetypes",
        "/rest/api/2/issue/createmeta/{project}/issuetypes/{typeId}",
        "/rest/api/2/field",
        "/rest/api/2/issueLinkType",
        "/rest/api/2/issueLink",
        "/rest/api/2/attachment/{id}",
        "/rest/api/2/user/assignable/search",
        "/rest/agile/1.0/board",
        "/rest/agile/1.0/board/{id}/sprint",
        "/rest/agile/1.0/sprint/{id}/issue",
        "/rest/agile/1.0/board/{id}/backlog",
        "/rest/agile/1.0/backlog/issue",
        "/rest/api/user/current",
        "/rest/api/space",
        "/rest/api/space/{key}",
        "/rest/api/content",
        "/rest/api/content/{id}",
        "/rest/api/search",
        "/rest/api/content/{id}/child/page",
        "/rest/api/content/{id}/child/comment",
        "/rest/api/content/{id}/child/attachment",
        "/rest/api/content/{id}/label",
        "/rest/api/content/{id}/label/{label}",
        "/rest/api/content/{id}/history",
    ];

    const EXTRA_PATHS: &[&str] = &[
        "/rest/api/2/search/",
        "/rest/api/2/search?x",
        "/REST/api/2/search",
    ];

    const METHODS: &[&str] = &[
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "get", "Post",
    ];

    const JSON: &[u8] = b"application/json";

    fn out<'a>(
        method: &'a str,
        url: &'a str,
        content_types: &'a [&'a [u8]],
        body: Option<&'a [u8]>,
    ) -> Outgoing<'a> {
        Outgoing {
            method,
            url,
            content_types,
            body,
        }
    }

    fn read(method: &str, path: &str) -> Result<(), MethodRefused> {
        let url = format!("https://jira.corp{path}");
        method_guard(
            &SendMode::Read {
                path_template: path,
            },
            &out(method, &url, &[], None),
        )
    }

    #[test]
    fn u03_method_guard_exhaustive() {
        for path in REGISTRY_PATHS.iter().chain(EXTRA_PATHS) {
            let url = format!("https://jira.corp/jira{path}");
            for method in METHODS {
                let expect_ok =
                    *method == "GET" || (*method == "POST" && *path == "/rest/api/2/search");
                assert_eq!(
                    read(method, path).is_ok(),
                    expect_ok,
                    "Read {method} {path}"
                );

                // An approved write passes only for its own entry, byte for byte.
                let spec = HttpRequestSpec {
                    index: 0,
                    method: (*method).to_owned(),
                    resolved_url: url.clone(),
                    content_type: Some("application/json".to_owned()),
                    body: br#"{"a":1}"#.to_vec(),
                };
                let mode = SendMode::ApprovedWrite(&spec);
                let body = &br#"{"a":1}"#[..];
                assert!(
                    method_guard(&mode, &out(method, &url, &[JSON], Some(body))).is_ok(),
                    "ApprovedWrite {method} {path}"
                );
                for other in METHODS.iter().filter(|m| *m != method) {
                    assert_eq!(
                        method_guard(&mode, &out(other, &url, &[JSON], Some(body))),
                        Err(MethodRefused),
                        "ApprovedWrite {method} sent as {other} {path}"
                    );
                }
            }
        }
    }

    #[test]
    fn u03_approved_write_is_byte_exact() {
        let url = "https://wiki.corp/rest/api/content/1?a=b+c";
        let spec = HttpRequestSpec {
            index: 0,
            method: "PUT".to_owned(),
            resolved_url: url.to_owned(),
            content_type: Some("application/json".to_owned()),
            body: b"{}".to_vec(),
        };
        let mode = SendMode::ApprovedWrite(&spec);
        let ok = |o: Outgoing<'_>| method_guard(&mode, &o).is_ok();
        assert!(ok(out("PUT", url, &[JSON], Some(b"{}"))));
        // Each of the five fields, one byte off.
        assert!(!ok(out("PUT ", url, &[JSON], Some(b"{}"))));
        assert!(!ok(out("put", url, &[JSON], Some(b"{}"))));
        assert!(!ok(out(
            "PUT",
            "https://wiki.corp/rest/api/content/1?a=b%20c",
            &[JSON],
            Some(b"{}")
        )));
        assert!(!ok(out(
            "PUT",
            "https://wiki.corp/rest/api/content/1?a=b+c/",
            &[JSON],
            Some(b"{}")
        )));
        assert!(!ok(out(
            "PUT",
            url,
            &[b"application/json; charset=UTF-8"],
            Some(b"{}")
        )));
        assert!(!ok(out("PUT", url, &[], Some(b"{}"))));
        assert!(!ok(out("PUT", url, &[JSON, JSON], Some(b"{}"))));
        assert!(!ok(out("PUT", url, &[JSON], Some(b"{} "))));
        assert!(!ok(out("PUT", url, &[JSON], None)));

        // No Content-Type in the list: none may be sent; an empty body is still a body.
        let bare = HttpRequestSpec {
            index: 0,
            method: "DELETE".to_owned(),
            resolved_url: url.to_owned(),
            content_type: None,
            body: Vec::new(),
        };
        let mode = SendMode::ApprovedWrite(&bare);
        assert!(method_guard(&mode, &out("DELETE", url, &[], Some(b""))).is_ok());
        assert!(method_guard(&mode, &out("DELETE", url, &[JSON], Some(b""))).is_err());
        assert!(method_guard(&mode, &out("DELETE", url, &[], None)).is_err());

        // A fragment never matches, even when the list entry carries it.
        let frag = HttpRequestSpec {
            resolved_url: format!("{url}#x"),
            ..bare.clone()
        };
        let mode = SendMode::ApprovedWrite(&frag);
        assert!(method_guard(&mode, &out("DELETE", &frag.resolved_url, &[], Some(b""))).is_err());
    }

    #[test]
    fn u03_post_only_search_path() {
        assert_eq!(read("POST", "/rest/api/2/issue"), Err(MethodRefused));
        assert!(read("POST", "/rest/api/2/search").is_ok());
    }
}
