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

pub use describe::{DescribeEnv, LimitsSource, describe};
pub use display::target_display;
pub use jira::{ISSUE_GET_DEFAULT_FIELDS, SEARCH_DEFAULT_FIELDS};
pub use model::*;
pub use script::{SCRIPT_RUN, ScriptRunSpec, script_target_display};

/// §2.3 / §5.2: the largest result the app releases in one piece.
pub const RELEASE_CAP_BYTES: u64 = 16 * 1024 * 1024;

/// §2.3 (verbatim, without the internal "(§5.4 step 2)" reference): the sentence `describe` adds
/// to every Write op.
pub const WRITE_GUIDANCE: &str = "Submit human names (project, issue type, transition, user, link type, parent page); the app resolves and validates them. Do not pre-read createmeta, transitions or assignable users; if you need metadata, fetch it in one script.";

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
];

/// Every registry operation (46 once the catalogs are in: 28 Jira, 18 Confluence).
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
