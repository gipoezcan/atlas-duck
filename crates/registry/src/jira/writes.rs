//! The 9 Jira write specs (§7.3), in table order. Every write is one HTTP request (§7.2); the
//! declared success shape decides whether the receipt is projected or `{}`.

use super::{DEFAULT_SUCCESS, EMPTY_204, NO_CAPS, NO_REDACTION, schemas};
use crate::model::*;

const FIELDS_FLAG: FlagBinding = FlagBinding {
    param: "fields",
    flag: "--field",
    kind: FlagKind::KeyJsonPairs,
    file_variant: true,
};

const BODY_FORMAT_FLAG: FlagBinding = FlagBinding {
    param: "body_format",
    flag: "--body-format",
    kind: FlagKind::Str,
    file_variant: false,
};

const COMMENT_FLAG: FlagBinding = FlagBinding {
    param: "comment",
    flag: "--comment",
    kind: FlagKind::Str,
    file_variant: true,
};

const ISSUES_FLAG: FlagBinding = FlagBinding {
    param: "issues",
    flag: "--issues",
    kind: FlagKind::CsvList,
    file_variant: false,
};

const fn post(path: &'static str) -> Endpoint {
    Endpoint {
        method: Method::Post,
        path,
        query: &[],
        body: BodySource::OpSpecific,
    }
}

const fn put(path: &'static str) -> Endpoint {
    Endpoint {
        method: Method::Put,
        ..post(path)
    }
}

pub(crate) const ISSUE_CREATE: OperationSpec = OperationSpec {
    id: "jira.issue.create",
    product: Product::Jira,
    class: OpClass::Write,
    endpoint: post("/rest/api/2/issue"),
    alt_endpoint: None,
    params_schema: schemas::ISSUE_CREATE_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "issue", "create"],
        positional: None,
        flags: &[
            FlagBinding {
                param: "project",
                flag: "--project",
                kind: FlagKind::Str,
                file_variant: false,
            },
            FlagBinding {
                param: "issuetype",
                flag: "--type",
                kind: FlagKind::Str,
                file_variant: false,
            },
            FlagBinding {
                param: "summary",
                flag: "--summary",
                kind: FlagKind::Str,
                file_variant: false,
            },
            FlagBinding {
                param: "description",
                flag: "--description",
                kind: FlagKind::Str,
                file_variant: true,
            },
            BODY_FORMAT_FLAG,
            FIELDS_FLAG,
        ],
    },
    target_params: &["project"],
    conflict_baselines: &[],
    target_display: TargetDisplay::CreateIn("project"),
    similarity: Similarity::Create,
    field_rules: Some(FieldRules {
        fields_param: None,
        fields_map_param: Some("fields"),
        expand_param: None,
        expand_allow: &[],
        default_fields: &[],
    }),
    caps: NO_CAPS,
    min_version: None,
    paginated: None,
    result_projection: Projection::Fields(&["id", "key"]),
    success: DEFAULT_SUCCESS,
    redaction_rules: NO_REDACTION,
    result_example: schemas::ISSUE_CREATE_EXAMPLE,
    result_example_sparse: schemas::ISSUE_CREATE_EXAMPLE_SPARSE,
    result_schema: schemas::ISSUE_CREATE_RESULT,
    write_guidance: true,
};

pub(crate) const ISSUE_EDIT: OperationSpec = OperationSpec {
    id: "jira.issue.edit",
    endpoint: put("/rest/api/2/issue/{key}"),
    params_schema: schemas::ISSUE_EDIT_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "issue", "edit"],
        positional: Some("key"),
        flags: &[
            FIELDS_FLAG,
            FlagBinding {
                param: "update",
                flag: "--update",
                kind: FlagKind::Json,
                file_variant: true,
            },
            FlagBinding {
                param: "expected",
                flag: "--expected",
                kind: FlagKind::Json,
                file_variant: true,
            },
        ],
    },
    target_params: &["key"],
    conflict_baselines: &["expected"],
    target_display: TargetDisplay::Param("key"),
    similarity: Similarity::Target,
    field_rules: Some(FieldRules {
        fields_param: None,
        fields_map_param: Some("fields"),
        expand_param: None,
        expand_allow: &[],
        default_fields: &[],
    }),
    success: EMPTY_204,
    result_projection: Projection::Empty,
    result_example: schemas::EMPTY_RECEIPT_EXAMPLE,
    result_example_sparse: schemas::EMPTY_RECEIPT_EXAMPLE,
    result_schema: schemas::EMPTY_RECEIPT_RESULT,
    ..ISSUE_CREATE
};

pub(crate) const COMMENT_ADD: OperationSpec = OperationSpec {
    id: "jira.comment.add",
    endpoint: post("/rest/api/2/issue/{key}/comment"),
    params_schema: schemas::COMMENT_ADD_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "comment", "add"],
        positional: Some("key"),
        flags: &[
            FlagBinding {
                param: "body",
                flag: "--body",
                kind: FlagKind::Str,
                file_variant: true,
            },
            BODY_FORMAT_FLAG,
            FlagBinding {
                param: "visibility",
                flag: "--visibility",
                kind: FlagKind::Json,
                file_variant: false,
            },
        ],
    },
    target_params: &["key"],
    target_display: TargetDisplay::Param("key"),
    similarity: Similarity::Target,
    field_rules: None,
    result_projection: Projection::Fields(&["id"]),
    result_example: schemas::COMMENT_ADD_EXAMPLE,
    result_example_sparse: schemas::COMMENT_ADD_EXAMPLE_SPARSE,
    result_schema: schemas::COMMENT_ADD_RESULT,
    ..ISSUE_CREATE
};

pub(crate) const ISSUE_TRANSITION: OperationSpec = OperationSpec {
    id: "jira.issue.transition",
    endpoint: post("/rest/api/2/issue/{key}/transitions"),
    params_schema: schemas::ISSUE_TRANSITION_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "issue", "transition"],
        positional: Some("key"),
        flags: &[
            FlagBinding {
                param: "transition",
                flag: "--transition",
                kind: FlagKind::Str,
                file_variant: false,
            },
            FIELDS_FLAG,
            COMMENT_FLAG,
        ],
    },
    target_params: &["key"],
    target_display: TargetDisplay::Param("key"),
    similarity: Similarity::Target,
    field_rules: None,
    success: EMPTY_204,
    result_projection: Projection::Empty,
    result_example: schemas::EMPTY_RECEIPT_EXAMPLE,
    result_example_sparse: schemas::EMPTY_RECEIPT_EXAMPLE,
    result_schema: schemas::EMPTY_RECEIPT_RESULT,
    ..ISSUE_CREATE
};

pub(crate) const ISSUE_ASSIGN: OperationSpec = OperationSpec {
    id: "jira.issue.assign",
    endpoint: put("/rest/api/2/issue/{key}/assignee"),
    params_schema: schemas::ISSUE_ASSIGN_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "issue", "assign"],
        positional: Some("key"),
        flags: &[FlagBinding {
            param: "assignee",
            flag: "--assignee",
            kind: FlagKind::Str,
            file_variant: false,
        }],
    },
    ..ISSUE_TRANSITION
};

pub(crate) const WORKLOG_ADD: OperationSpec = OperationSpec {
    id: "jira.worklog.add",
    endpoint: post("/rest/api/2/issue/{key}/worklog"),
    params_schema: schemas::WORKLOG_ADD_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "worklog", "add"],
        positional: Some("key"),
        flags: &[
            FlagBinding {
                param: "time_spent",
                flag: "--time-spent",
                kind: FlagKind::Str,
                file_variant: false,
            },
            COMMENT_FLAG,
            FlagBinding {
                param: "started",
                flag: "--started",
                kind: FlagKind::Str,
                file_variant: false,
            },
        ],
    },
    result_example: schemas::WORKLOG_ADD_EXAMPLE,
    result_example_sparse: schemas::WORKLOG_ADD_EXAMPLE_SPARSE,
    result_schema: schemas::WORKLOG_ADD_RESULT,
    ..COMMENT_ADD
};

pub(crate) const ISSUELINK_CREATE: OperationSpec = OperationSpec {
    id: "jira.issuelink.create",
    endpoint: post("/rest/api/2/issueLink"),
    params_schema: schemas::ISSUELINK_CREATE_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "issuelink", "create"],
        positional: None,
        flags: &[
            FlagBinding {
                param: "type",
                flag: "--type",
                kind: FlagKind::Str,
                file_variant: false,
            },
            FlagBinding {
                param: "inward",
                flag: "--inward",
                kind: FlagKind::Str,
                file_variant: false,
            },
            FlagBinding {
                param: "outward",
                flag: "--outward",
                kind: FlagKind::Str,
                file_variant: false,
            },
            COMMENT_FLAG,
        ],
    },
    target_params: &["inward", "outward"],
    target_display: TargetDisplay::Pair("inward", "outward"),
    success: SuccessShape {
        statuses: StatusSet::Exactly(&[201]),
        body: SuccessBody::Empty,
    },
    ..ISSUE_TRANSITION
};

const MOVE_CAPS: Caps = Caps {
    move_limit: Some(50),
    ..NO_CAPS
};

pub(crate) const SPRINT_MOVE_ISSUES: OperationSpec = OperationSpec {
    id: "jira.sprint.move_issues",
    endpoint: post("/rest/agile/1.0/sprint/{id}/issue"),
    params_schema: schemas::SPRINT_MOVE_ISSUES_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "sprint", "move-issues"],
        positional: Some("id"),
        flags: &[ISSUES_FLAG],
    },
    target_params: &["id", "issues"],
    target_display: TargetDisplay::MoveInto {
        sprint_param: Some("id"),
        issues_param: "issues",
    },
    similarity: Similarity::MoveIssues,
    caps: MOVE_CAPS,
    success: EMPTY_204,
    ..ISSUE_TRANSITION
};

pub(crate) const BACKLOG_MOVE_ISSUES: OperationSpec = OperationSpec {
    id: "jira.backlog.move_issues",
    endpoint: post("/rest/agile/1.0/backlog/issue"),
    params_schema: schemas::BACKLOG_MOVE_ISSUES_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "backlog", "move-issues"],
        positional: None,
        flags: &[ISSUES_FLAG],
    },
    target_params: &["issues"],
    target_display: TargetDisplay::MoveInto {
        sprint_param: None,
        issues_param: "issues",
    },
    ..SPRINT_MOVE_ISSUES
};
