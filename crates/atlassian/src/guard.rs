//! The method guard (§5.1 invariant 3, §7.2): outside `send_approved` the client sends only
//! `GET`, plus `POST` to the one allowlisted search path.

use std::fmt;

use crate::types::ApprovedWrite;

/// The only `POST` that is not an approved write (`jira.search`).
pub const ALLOWED_READ_POSTS: &[&str] = &["/rest/api/2/search"];

#[expect(dead_code, reason = "constructed by the write path (Task 10)")]
pub(crate) enum SendMode<'a> {
    Read,
    /// The write path compares every request byte for byte with its entry in the approved
    /// list (Task 10); the guard has nothing to add there.
    ApprovedWrite(&'a ApprovedWrite),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MethodRefused;

impl fmt::Display for MethodRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("method not allowed outside an approved write")
    }
}

impl std::error::Error for MethodRefused {}

pub(crate) fn method_guard(
    mode: &SendMode<'_>,
    method: &str,
    path_template: &str,
) -> Result<(), MethodRefused> {
    match mode {
        SendMode::ApprovedWrite(_) => Ok(()),
        SendMode::Read => {
            // Exact, case-sensitive comparison: "get", "Post", "search/" and "/REST/..." fail.
            if method == "GET" || (method == "POST" && ALLOWED_READ_POSTS.contains(&path_template))
            {
                Ok(())
            } else {
                Err(MethodRefused)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ExpectedBody, SuccessExpectation};

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

    fn empty_write() -> ApprovedWrite {
        ApprovedWrite {
            requests: Vec::new(),
            success: SuccessExpectation {
                statuses: None,
                body: ExpectedBody::Json,
            },
        }
    }

    #[test]
    fn u03_method_guard_exhaustive() {
        let w = empty_write();
        for path in REGISTRY_PATHS.iter().chain(EXTRA_PATHS) {
            for method in METHODS {
                let expect_ok =
                    *method == "GET" || (*method == "POST" && *path == "/rest/api/2/search");
                assert_eq!(
                    method_guard(&SendMode::Read, method, path).is_ok(),
                    expect_ok,
                    "Read {method} {path}"
                );
                assert!(
                    method_guard(&SendMode::ApprovedWrite(&w), method, path).is_ok(),
                    "ApprovedWrite {method} {path}"
                );
            }
        }
    }

    #[test]
    fn u03_post_only_search_path() {
        assert_eq!(
            method_guard(&SendMode::Read, "POST", "/rest/api/2/issue"),
            Err(MethodRefused)
        );
        assert!(method_guard(&SendMode::Read, "POST", "/rest/api/2/search").is_ok());
    }
}
