//! Jira operation specs (§7.3), one `pub(crate) const` per op, listed once in `lib.rs`.

use crate::RELEASE_CAP_BYTES;
use crate::model::{Caps, CopyRule, Mirror, RedactionRules, StatusSet, SuccessBody, SuccessShape};

pub(crate) mod reads;
mod schemas;
pub(crate) mod writes;

/// §7.3: `fields` when `jira.issue.get` is called without one. Documented in `describe` `defaults`.
pub const ISSUE_GET_DEFAULT_FIELDS: &[&str] = &[
    "summary",
    "status",
    "issuetype",
    "priority",
    "assignee",
    "reporter",
    "created",
    "updated",
    "labels",
    "components",
    "fixVersions",
    "parent",
    "description",
    "issuelinks",
    "security",
];

/// §7.3: `fields` when `jira.search` is called without one.
pub const SEARCH_DEFAULT_FIELDS: &[&str] = &[
    "summary",
    "status",
    "assignee",
    "priority",
    "issuetype",
    "updated",
];

pub(crate) const NO_CAPS: Caps = Caps {
    max: None,
    move_limit: None,
    comments_cap: None,
    upload_max_bytes: None,
    static_result_cap_bytes: RELEASE_CAP_BYTES,
};

pub(crate) const NO_REDACTION: RedactionRules = RedactionRules {
    copies: &[],
    mirrors: &[],
    url_fields: &[],
};

pub(crate) const DEFAULT_SUCCESS: SuccessShape = SuccessShape {
    statuses: StatusSet::Any2xx,
    body: SuccessBody::Json,
};

/// §7.2: declared empty success of the 204 writes.
pub(crate) const EMPTY_204: SuccessShape = SuccessShape {
    statuses: StatusSet::Exactly(&[204]),
    body: SuccessBody::Empty,
};

/// §5.3 copies of a dropped field in an expanded `jira.issue.get` result.
pub(crate) const ISSUE_COPIES: &[CopyRule] = &[
    CopyRule::Path("renderedFields.{field}"),
    CopyRule::Path("names.{field}"),
    CopyRule::Path("schema.{field}"),
    CopyRule::Path("editmeta.fields.{field}"),
    CopyRule::ChangelogItems {
        items_path: "changelog.histories[].items",
        key_fields: &["field", "fieldId"],
    },
];

/// The same copies for each element of the `jira.search` `issues` array.
pub(crate) const SEARCH_COPIES: &[CopyRule] = &[
    CopyRule::Path("issues[].renderedFields.{field}"),
    CopyRule::Path("issues[].names.{field}"),
    CopyRule::Path("issues[].schema.{field}"),
    CopyRule::Path("issues[].editmeta.fields.{field}"),
    CopyRule::ChangelogItems {
        items_path: "issues[].changelog.histories[].items",
        key_fields: &["field", "fieldId"],
    },
];

pub(crate) const ISSUE_MIRRORS: &[Mirror] = &[
    Mirror {
        src: "fields.comment.comments",
        dst: "renderedFields.comment.comments",
        key: "id",
    },
    Mirror {
        src: "fields.worklog.worklogs",
        dst: "renderedFields.worklog.worklogs",
        key: "id",
    },
];

pub(crate) const SEARCH_MIRRORS: &[Mirror] = &[
    Mirror {
        src: "issues[].fields.comment.comments",
        dst: "issues[].renderedFields.comment.comments",
        key: "id",
    },
    Mirror {
        src: "issues[].fields.worklog.worklogs",
        dst: "issues[].renderedFields.worklog.worklogs",
        key: "id",
    },
];

/// `expand` values allowed for `jira.issue.get` and `jira.search`.
pub(crate) const EXPAND_ALLOW: &[&str] = &["renderedFields", "changelog", "names", "schema"];
