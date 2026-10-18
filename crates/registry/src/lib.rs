//! Pure-data operation specs (§2.3): no fn pointers, no I/O.
//!
//! §2.2: `registry` depends on nothing in the workspace. Static validation code lives in
//! `core::validate`, driven by this data.

mod confluence;
mod describe;
mod display;
mod jira;
mod model;
mod script;

pub use describe::{
    DescribeEnv, GENERIC_COMMANDS, GenericCommand, LimitsSource, describe, ops_list_json,
    usage as op_usage,
};
pub use display::target_display;
pub use jira::{ISSUE_GET_DEFAULT_FIELDS, SEARCH_DEFAULT_FIELDS};
pub use model::*;
pub use script::{SCRIPT_RUN, ScriptRunSpec, script_target_display};

/// §2.3 / §5.2: the largest result the app releases in one piece.
pub const RELEASE_CAP_BYTES: u64 = 16 * 1024 * 1024;

/// §2.3 (verbatim, without the internal "(§5.4 step 2)" reference): the sentence `describe` adds
/// to every Write op.
pub const WRITE_GUIDANCE: &str = "Submit human names (project, issue type, transition, user, link type, parent page); the app resolves and validates them. Do not pre-read createmeta, transitions or assignable users; if you need metadata, fetch it in one script.";

/// plan text (PD-42): the sentence `describe` adds after [`WRITE_GUIDANCE`] to every Jira write
/// (which params convert from Markdown, which are sent verbatim).
pub const JIRA_VERBATIM_GUIDANCE: &str = "Text in `fields`, `update` and `comment` is sent as Jira wiki markup unchanged; only `description`/`body` with `body_format=markdown` are converted.";

/// plan text (PD-112): the sentence `describe` adds to `confluence.search` (§7.4 "`ops describe`
/// documents the rewrite"), with the nesting limit of core's CQL tokenizer (`CQL_MAX_DEPTH`, M7
/// T30 review I-1; core's `op_table` test checks the number).
pub const CONFLUENCE_CQL_GUIDANCE: &str = "The CQL is sent as `(<your CQL>) AND type in (page,blogpost,comment,attachment)` plus your trailing ORDER BY; an ORDER BY elsewhere, an unterminated quote, a backslash outside a quoted string, unbalanced parentheses or parentheses nested deeper than 64 levels are rejected.";

/// plan text (PD-112; §12.4 onboarding sentence, verbatim): the sentence `describe` adds to the
/// Confluence ops that take a Markdown body (§7.6 "`ops describe` for these ops documents the
/// check").
pub const CONFLUENCE_PLACEHOLDER_GUIDANCE: &str = "A Markdown body that still contains `page get` placeholders (`[macro: …]`, `confluence:` links or images, `@user:<key>`) is rejected with `markdown_placeholders`: fetch with `--format storage` and submit `body_format=storage`.";

/// plan text (PD-112): the sentence `describe` adds to `confluence.page.update` (§7.6 "advises
/// `body_format=storage`").
pub const CONFLUENCE_LOSSY_GUIDANCE: &str = "If `page get` reported `meta.conversion.lossy = true`, edit with `body_format=storage`; a Markdown update that would remove macros (task lists included), images or links (mentions included) is flagged to the approver.";

/// §7.5 (verbatim): the rule `describe` states for paginated ops.
pub const PAGINATION_GUIDANCE: &str = "continue only from meta.page.next_start";

/// Jira then Confluence, each in §7.3/§7.4 table order. Each spec is a `pub(crate) const` in its
/// product module, listed here once (compile time, no allocation).
static ALL: &[OperationSpec] = &[
    jira::reads::MYSELF,
    jira::reads::PROJECT_LIST,
    jira::reads::PROJECT_GET,
    jira::reads::ISSUE_GET,
    jira::reads::SEARCH,
    jira::reads::COMMENT_LIST,
    jira::reads::WORKLOG_LIST,
    jira::reads::TRANSITION_LIST,
    jira::reads::ISSUE_EDITMETA,
    jira::reads::CREATEMETA_ISSUETYPES,
    jira::reads::CREATEMETA_FIELDS,
    jira::reads::FIELD_LIST,
    jira::reads::ISSUELINKTYPE_LIST,
    jira::reads::ATTACHMENT_META,
    jira::reads::USER_ASSIGNABLE,
    jira::reads::BOARD_LIST,
    jira::reads::SPRINT_LIST,
    jira::reads::SPRINT_ISSUES,
    jira::reads::BACKLOG_ISSUES,
    jira::writes::ISSUE_CREATE,
    jira::writes::ISSUE_EDIT,
    jira::writes::COMMENT_ADD,
    jira::writes::ISSUE_TRANSITION,
    jira::writes::ISSUE_ASSIGN,
    jira::writes::WORKLOG_ADD,
    jira::writes::ISSUELINK_CREATE,
    jira::writes::SPRINT_MOVE_ISSUES,
    jira::writes::BACKLOG_MOVE_ISSUES,
    confluence::reads::USER_CURRENT,
    confluence::reads::SPACE_LIST,
    confluence::reads::SPACE_GET,
    confluence::reads::PAGE_GET,
    confluence::reads::PAGE_FIND,
    confluence::reads::SEARCH,
    confluence::reads::PAGE_CHILDREN,
    confluence::reads::COMMENT_LIST,
    confluence::reads::LABEL_LIST,
    confluence::reads::ATTACHMENT_LIST,
    confluence::reads::PAGE_HISTORY,
    confluence::writes::PAGE_CREATE,
    confluence::writes::PAGE_UPDATE,
    confluence::writes::PAGE_MOVE,
    confluence::writes::COMMENT_ADD,
    confluence::writes::LABEL_ADD,
    confluence::writes::LABEL_REMOVE,
    confluence::writes::ATTACHMENT_UPLOAD,
];

/// Every registry operation (46: 28 Jira, 18 Confluence).
pub fn all() -> &'static [OperationSpec] {
    ALL
}

pub fn get(id: &str) -> Option<&'static OperationSpec> {
    ALL.iter().find(|spec| spec.id == id)
}

/// Sent in `WorkerInit.read_op_ids` (§9.1 step 3).
pub fn read_op_ids() -> Vec<&'static str> {
    ALL.iter()
        .filter(|spec| spec.class == OpClass::Read)
        .map(|spec| spec.id)
        .collect()
}
