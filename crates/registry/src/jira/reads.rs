//! The 19 Jira read specs (§7.3), in table order.

use super::{
    DEFAULT_SUCCESS, EXPAND_ALLOW, ISSUE_COPIES, ISSUE_MIRRORS, NO_CAPS, NO_REDACTION,
    SEARCH_COPIES, SEARCH_MIRRORS, schemas,
};
use crate::RELEASE_CAP_BYTES;
use crate::model::*;

const START_FLAG: FlagBinding = FlagBinding {
    param: "start",
    flag: "--start",
    kind: FlagKind::Int,
    file_variant: false,
};

const MAX_FLAG: FlagBinding = FlagBinding {
    param: "max",
    flag: "--max",
    kind: FlagKind::Int,
    file_variant: false,
};

const JQL_FLAG: FlagBinding = FlagBinding {
    param: "jql",
    flag: "--jql",
    kind: FlagKind::Str,
    file_variant: false,
};

const FIELDS_FLAG: FlagBinding = FlagBinding {
    param: "fields",
    flag: "--fields",
    kind: FlagKind::CsvList,
    file_variant: false,
};

const EXPAND_FLAG: FlagBinding = FlagBinding {
    param: "expand",
    flag: "--expand",
    kind: FlagKind::CsvList,
    file_variant: false,
};

/// Search and agile issue lists share the `fields` rules; only `jira.search` takes `expand`.
const SEARCH_FIELD_RULES: FieldRules = FieldRules {
    fields_param: Some("fields"),
    fields_map_param: None,
    expand_param: Some("expand"),
    expand_allow: EXPAND_ALLOW,
};

const AGILE_FIELD_RULES: FieldRules = FieldRules {
    fields_param: Some("fields"),
    fields_map_param: None,
    expand_param: None,
    expand_allow: &[],
};

const AGILE_PAGE: PageSpec = PageSpec {
    items_key: "values",
    offset_param: "startAt",
    limit_param: "maxResults",
};

const AGILE_ISSUES_PAGE: PageSpec = PageSpec {
    items_key: "issues",
    offset_param: "startAt",
    limit_param: "maxResults",
};

const MAX_50_500: Caps = Caps {
    max: Some(MaxCap {
        param: "max",
        default: 50,
        hard_cap_default: 500,
        configurable: true,
    }),
    ..NO_CAPS
};

const MIN_8_4: Version = Version {
    major: 8,
    minor: 4,
    patch: 0,
};

/// A read with no query, body, caps or redaction: the common skeleton is filled in per spec.
const fn get(path: &'static str) -> Endpoint {
    Endpoint {
        method: Method::Get,
        path,
        query: &[],
        body: BodySource::None,
    }
}

pub(crate) const MYSELF: OperationSpec = OperationSpec {
    id: "jira.myself",
    product: Product::Jira,
    class: OpClass::Read,
    endpoint: get("/rest/api/2/myself"),
    alt_endpoint: None,
    params_schema: schemas::EMPTY_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "myself"],
        positional: None,
        flags: &[],
    },
    target_params: &[],
    conflict_baselines: &[],
    target_display: TargetDisplay::None,
    similarity: Similarity::None,
    field_rules: None,
    caps: NO_CAPS,
    min_version: None,
    paginated: None,
    result_projection: Projection::Empty,
    success: DEFAULT_SUCCESS,
    redaction_rules: NO_REDACTION,
    result_example: schemas::MYSELF_EXAMPLE,
    result_example_sparse: schemas::MYSELF_EXAMPLE_SPARSE,
    result_schema: schemas::MYSELF_RESULT,
    write_guidance: false,
};

pub(crate) const PROJECT_LIST: OperationSpec = OperationSpec {
    id: "jira.project.list",
    endpoint: get("/rest/api/2/project"),
    cli: CliBinding {
        noun_path: &["jira", "project", "list"],
        positional: None,
        flags: &[],
    },
    result_example: schemas::PROJECT_LIST_EXAMPLE,
    result_example_sparse: schemas::PROJECT_LIST_EXAMPLE_SPARSE,
    result_schema: schemas::PROJECT_LIST_RESULT,
    ..MYSELF
};

pub(crate) const PROJECT_GET: OperationSpec = OperationSpec {
    id: "jira.project.get",
    endpoint: get("/rest/api/2/project/{key}"),
    params_schema: schemas::PROJECT_GET_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "project", "get"],
        positional: Some("key"),
        flags: &[],
    },
    target_params: &["key"],
    target_display: TargetDisplay::Param("key"),
    similarity: Similarity::Target,
    result_example: schemas::PROJECT_GET_EXAMPLE,
    result_example_sparse: schemas::PROJECT_GET_EXAMPLE_SPARSE,
    result_schema: schemas::PROJECT_GET_RESULT,
    ..MYSELF
};

pub(crate) const ISSUE_GET: OperationSpec = OperationSpec {
    id: "jira.issue.get",
    product: Product::Jira,
    class: OpClass::Read,
    endpoint: Endpoint {
        method: Method::Get,
        path: "/rest/api/2/issue/{key}",
        query: &[
            QueryParam {
                name: "fields",
                value: QueryValue::Param("fields"),
            },
            QueryParam {
                name: "expand",
                value: QueryValue::Param("expand"),
            },
        ],
        body: BodySource::None,
    },
    alt_endpoint: None,
    params_schema: schemas::ISSUE_GET_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "issue", "get"],
        positional: Some("key"),
        flags: &[
            FIELDS_FLAG,
            FlagBinding {
                param: "comments",
                flag: "--comments",
                kind: FlagKind::Bool,
                file_variant: false,
            },
            FlagBinding {
                param: "changelog",
                flag: "--changelog",
                kind: FlagKind::Bool,
                file_variant: false,
            },
            FlagBinding {
                param: "rendered",
                flag: "--rendered",
                kind: FlagKind::Bool,
                file_variant: false,
            },
        ],
    },
    target_params: &["key"],
    conflict_baselines: &[],
    target_display: TargetDisplay::Param("key"),
    similarity: Similarity::Target,
    field_rules: Some(FieldRules {
        fields_param: Some("fields"),
        fields_map_param: None,
        expand_param: Some("expand"),
        expand_allow: EXPAND_ALLOW,
    }),
    caps: Caps {
        max: None,
        move_limit: None,
        comments_cap: Some(100),
        upload_max_bytes: None,
        static_result_cap_bytes: RELEASE_CAP_BYTES,
    },
    min_version: None,
    paginated: None,
    result_projection: Projection::Empty,
    success: DEFAULT_SUCCESS,
    redaction_rules: RedactionRules {
        copies: ISSUE_COPIES,
        mirrors: ISSUE_MIRRORS,
        url_fields: &[
            "self",
            "fields.*.self",
            "fields.attachment[].content",
            "fields.attachment[].thumbnail",
        ],
    },
    result_example: schemas::ISSUE_GET_EXAMPLE,
    result_example_sparse: schemas::ISSUE_GET_EXAMPLE_SPARSE,
    result_schema: schemas::ISSUE_GET_RESULT,
    write_guidance: false,
};

pub(crate) const SEARCH: OperationSpec = OperationSpec {
    id: "jira.search",
    endpoint: Endpoint {
        method: Method::Post,
        path: "/rest/api/2/search",
        query: &[],
        body: BodySource::ParamsAsJson,
    },
    params_schema: schemas::SEARCH_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "search"],
        positional: Some("jql"),
        flags: &[FIELDS_FLAG, EXPAND_FLAG, START_FLAG, MAX_FLAG],
    },
    target_display: TargetDisplay::Query { param: "jql" },
    field_rules: Some(SEARCH_FIELD_RULES),
    caps: MAX_50_500,
    paginated: Some(PageSpec {
        items_key: "issues",
        offset_param: "startAt",
        limit_param: "maxResults",
    }),
    redaction_rules: RedactionRules {
        copies: SEARCH_COPIES,
        mirrors: SEARCH_MIRRORS,
        url_fields: &[
            "issues[].self",
            "issues[].fields.*.self",
            "issues[].fields.attachment[].content",
            "issues[].fields.attachment[].thumbnail",
        ],
    },
    result_example: schemas::SEARCH_EXAMPLE,
    result_example_sparse: schemas::SEARCH_EXAMPLE_SPARSE,
    result_schema: schemas::SEARCH_RESULT,
    ..MYSELF
};

pub(crate) const COMMENT_LIST: OperationSpec = OperationSpec {
    id: "jira.comment.list",
    endpoint: Endpoint {
        method: Method::Get,
        path: "/rest/api/2/issue/{key}/comment",
        query: &[QueryParam {
            name: "orderBy",
            value: QueryValue::Const("created"),
        }],
        body: BodySource::None,
    },
    params_schema: schemas::COMMENT_LIST_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "comment", "list"],
        positional: Some("key"),
        flags: &[START_FLAG, MAX_FLAG],
    },
    target_params: &["key"],
    target_display: TargetDisplay::Param("key"),
    similarity: Similarity::Target,
    caps: Caps {
        max: Some(MaxCap {
            param: "max",
            default: 50,
            hard_cap_default: 100,
            configurable: true,
        }),
        ..NO_CAPS
    },
    paginated: Some(PageSpec {
        items_key: "comments",
        offset_param: "startAt",
        limit_param: "maxResults",
    }),
    redaction_rules: RedactionRules {
        copies: &[],
        mirrors: &[],
        url_fields: &["comments[].self"],
    },
    result_example: schemas::COMMENT_LIST_EXAMPLE,
    result_example_sparse: schemas::COMMENT_LIST_EXAMPLE_SPARSE,
    result_schema: schemas::COMMENT_LIST_RESULT,
    ..MYSELF
};

pub(crate) const WORKLOG_LIST: OperationSpec = OperationSpec {
    id: "jira.worklog.list",
    endpoint: get("/rest/api/2/issue/{key}/worklog"),
    params_schema: schemas::KEY_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "worklog", "list"],
        positional: Some("key"),
        flags: &[],
    },
    target_params: &["key"],
    target_display: TargetDisplay::Param("key"),
    similarity: Similarity::Target,
    redaction_rules: RedactionRules {
        copies: &[],
        mirrors: &[],
        url_fields: &["worklogs[].self"],
    },
    result_example: schemas::WORKLOG_LIST_EXAMPLE,
    result_example_sparse: schemas::WORKLOG_LIST_EXAMPLE_SPARSE,
    result_schema: schemas::WORKLOG_LIST_RESULT,
    ..MYSELF
};

pub(crate) const TRANSITION_LIST: OperationSpec = OperationSpec {
    id: "jira.transition.list",
    endpoint: Endpoint {
        method: Method::Get,
        path: "/rest/api/2/issue/{key}/transitions",
        query: &[QueryParam {
            name: "expand",
            value: QueryValue::Const("transitions.fields"),
        }],
        body: BodySource::None,
    },
    params_schema: schemas::KEY_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "transition", "list"],
        positional: Some("key"),
        flags: &[],
    },
    target_params: &["key"],
    target_display: TargetDisplay::Param("key"),
    similarity: Similarity::Target,
    result_example: schemas::TRANSITION_LIST_EXAMPLE,
    result_example_sparse: schemas::TRANSITION_LIST_EXAMPLE_SPARSE,
    result_schema: schemas::TRANSITION_LIST_RESULT,
    ..MYSELF
};

pub(crate) const ISSUE_EDITMETA: OperationSpec = OperationSpec {
    id: "jira.issue.editmeta",
    endpoint: get("/rest/api/2/issue/{key}/editmeta"),
    params_schema: schemas::KEY_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "issue", "editmeta"],
        positional: Some("key"),
        flags: &[],
    },
    target_params: &["key"],
    target_display: TargetDisplay::Param("key"),
    similarity: Similarity::Target,
    result_example: schemas::EDITMETA_EXAMPLE,
    result_example_sparse: schemas::EDITMETA_EXAMPLE_SPARSE,
    result_schema: schemas::EDITMETA_RESULT,
    ..MYSELF
};

pub(crate) const CREATEMETA_ISSUETYPES: OperationSpec = OperationSpec {
    id: "jira.createmeta.issuetypes",
    endpoint: get("/rest/api/2/issue/createmeta/{project}/issuetypes"),
    params_schema: schemas::CREATEMETA_ISSUETYPES_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "createmeta", "issuetypes"],
        positional: Some("project"),
        flags: &[],
    },
    target_params: &["project"],
    target_display: TargetDisplay::Param("project"),
    similarity: Similarity::Target,
    min_version: Some(MIN_8_4),
    result_example: schemas::CREATEMETA_ISSUETYPES_EXAMPLE,
    result_example_sparse: schemas::CREATEMETA_ISSUETYPES_EXAMPLE_SPARSE,
    result_schema: schemas::CREATEMETA_ISSUETYPES_RESULT,
    ..MYSELF
};

pub(crate) const CREATEMETA_FIELDS: OperationSpec = OperationSpec {
    id: "jira.createmeta.fields",
    endpoint: get("/rest/api/2/issue/createmeta/{project}/issuetypes/{typeId}"),
    params_schema: schemas::CREATEMETA_FIELDS_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "createmeta", "fields"],
        positional: Some("project"),
        flags: &[FlagBinding {
            param: "typeId",
            flag: "--type-id",
            kind: FlagKind::Str,
            file_variant: false,
        }],
    },
    target_params: &["project", "typeId"],
    target_display: TargetDisplay::Pair("project", "typeId"),
    similarity: Similarity::Target,
    min_version: Some(MIN_8_4),
    result_example: schemas::CREATEMETA_FIELDS_EXAMPLE,
    result_example_sparse: schemas::CREATEMETA_FIELDS_EXAMPLE_SPARSE,
    result_schema: schemas::CREATEMETA_FIELDS_RESULT,
    ..MYSELF
};

pub(crate) const FIELD_LIST: OperationSpec = OperationSpec {
    id: "jira.field.list",
    endpoint: get("/rest/api/2/field"),
    cli: CliBinding {
        noun_path: &["jira", "field", "list"],
        positional: None,
        flags: &[],
    },
    result_example: schemas::FIELD_LIST_EXAMPLE,
    result_example_sparse: schemas::FIELD_LIST_EXAMPLE_SPARSE,
    result_schema: schemas::FIELD_LIST_RESULT,
    ..MYSELF
};

pub(crate) const ISSUELINKTYPE_LIST: OperationSpec = OperationSpec {
    id: "jira.issuelinktype.list",
    endpoint: get("/rest/api/2/issueLinkType"),
    cli: CliBinding {
        noun_path: &["jira", "issuelinktype", "list"],
        positional: None,
        flags: &[],
    },
    result_example: schemas::ISSUELINKTYPE_LIST_EXAMPLE,
    result_example_sparse: schemas::ISSUELINKTYPE_LIST_EXAMPLE_SPARSE,
    result_schema: schemas::ISSUELINKTYPE_LIST_RESULT,
    ..MYSELF
};

pub(crate) const ATTACHMENT_META: OperationSpec = OperationSpec {
    id: "jira.attachment.meta",
    endpoint: get("/rest/api/2/attachment/{id}"),
    params_schema: schemas::ATTACHMENT_META_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "attachment", "meta"],
        positional: Some("id"),
        flags: &[],
    },
    target_params: &["id"],
    target_display: TargetDisplay::Param("id"),
    similarity: Similarity::Target,
    redaction_rules: RedactionRules {
        copies: &[],
        mirrors: &[],
        url_fields: &["self", "content", "thumbnail"],
    },
    result_example: schemas::ATTACHMENT_META_EXAMPLE,
    result_example_sparse: schemas::ATTACHMENT_META_EXAMPLE_SPARSE,
    result_schema: schemas::ATTACHMENT_META_RESULT,
    ..MYSELF
};

pub(crate) const USER_ASSIGNABLE: OperationSpec = OperationSpec {
    id: "jira.user.assignable",
    endpoint: Endpoint {
        method: Method::Get,
        path: "/rest/api/2/user/assignable/search",
        query: &[
            QueryParam {
                name: "username",
                value: QueryValue::Param("username"),
            },
            QueryParam {
                name: "project",
                value: QueryValue::Param("project"),
            },
            QueryParam {
                name: "issueKey",
                value: QueryValue::Param("issueKey"),
            },
            QueryParam {
                name: "maxResults",
                value: QueryValue::Param("max"),
            },
        ],
        body: BodySource::None,
    },
    params_schema: schemas::USER_ASSIGNABLE_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "user", "assignable"],
        positional: Some("username"),
        flags: &[
            FlagBinding {
                param: "project",
                flag: "--project",
                kind: FlagKind::Str,
                file_variant: false,
            },
            FlagBinding {
                param: "issueKey",
                flag: "--issue-key",
                kind: FlagKind::Str,
                file_variant: false,
            },
            MAX_FLAG,
        ],
    },
    caps: Caps {
        max: Some(MaxCap {
            param: "max",
            default: 50,
            hard_cap_default: 1000,
            configurable: true,
        }),
        ..NO_CAPS
    },
    redaction_rules: RedactionRules {
        copies: &[],
        mirrors: &[],
        url_fields: &["[].self"],
    },
    result_example: schemas::USER_ASSIGNABLE_EXAMPLE,
    result_example_sparse: schemas::USER_ASSIGNABLE_EXAMPLE_SPARSE,
    result_schema: schemas::USER_ASSIGNABLE_RESULT,
    ..MYSELF
};

pub(crate) const BOARD_LIST: OperationSpec = OperationSpec {
    id: "jira.board.list",
    endpoint: Endpoint {
        method: Method::Get,
        path: "/rest/agile/1.0/board",
        query: &[QueryParam {
            name: "name",
            value: QueryValue::Param("name"),
        }],
        body: BodySource::None,
    },
    params_schema: schemas::BOARD_LIST_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "board", "list"],
        positional: None,
        flags: &[
            FlagBinding {
                param: "name",
                flag: "--name",
                kind: FlagKind::Str,
                file_variant: false,
            },
            START_FLAG,
            MAX_FLAG,
        ],
    },
    caps: MAX_50_500,
    paginated: Some(AGILE_PAGE),
    redaction_rules: RedactionRules {
        copies: &[],
        mirrors: &[],
        url_fields: &["values[].self"],
    },
    result_example: schemas::BOARD_LIST_EXAMPLE,
    result_example_sparse: schemas::BOARD_LIST_EXAMPLE_SPARSE,
    result_schema: schemas::BOARD_LIST_RESULT,
    ..MYSELF
};

pub(crate) const SPRINT_LIST: OperationSpec = OperationSpec {
    id: "jira.sprint.list",
    endpoint: Endpoint {
        method: Method::Get,
        path: "/rest/agile/1.0/board/{id}/sprint",
        query: &[QueryParam {
            name: "state",
            value: QueryValue::Param("state"),
        }],
        body: BodySource::None,
    },
    params_schema: schemas::SPRINT_LIST_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "sprint", "list"],
        positional: Some("id"),
        flags: &[
            FlagBinding {
                param: "state",
                flag: "--state",
                kind: FlagKind::Str,
                file_variant: false,
            },
            START_FLAG,
            MAX_FLAG,
        ],
    },
    target_params: &["id"],
    target_display: TargetDisplay::Param("id"),
    similarity: Similarity::Target,
    caps: MAX_50_500,
    paginated: Some(AGILE_PAGE),
    redaction_rules: RedactionRules {
        copies: &[],
        mirrors: &[],
        url_fields: &["values[].self"],
    },
    result_example: schemas::SPRINT_LIST_EXAMPLE,
    result_example_sparse: schemas::SPRINT_LIST_EXAMPLE_SPARSE,
    result_schema: schemas::SPRINT_LIST_RESULT,
    ..MYSELF
};

pub(crate) const SPRINT_ISSUES: OperationSpec = OperationSpec {
    id: "jira.sprint.issues",
    endpoint: Endpoint {
        method: Method::Get,
        path: "/rest/agile/1.0/sprint/{id}/issue",
        query: &[
            QueryParam {
                name: "jql",
                value: QueryValue::Param("jql"),
            },
            QueryParam {
                name: "fields",
                value: QueryValue::Param("fields"),
            },
        ],
        body: BodySource::None,
    },
    params_schema: schemas::AGILE_ISSUES_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "sprint", "issues"],
        positional: Some("id"),
        flags: &[JQL_FLAG, FIELDS_FLAG, START_FLAG, MAX_FLAG],
    },
    target_params: &["id"],
    target_display: TargetDisplay::Param("id"),
    similarity: Similarity::Target,
    field_rules: Some(AGILE_FIELD_RULES),
    caps: MAX_50_500,
    paginated: Some(AGILE_ISSUES_PAGE),
    redaction_rules: RedactionRules {
        copies: &[],
        mirrors: &[],
        url_fields: &[
            "issues[].self",
            "issues[].fields.*.self",
            "issues[].fields.attachment[].content",
            "issues[].fields.attachment[].thumbnail",
        ],
    },
    result_example: schemas::AGILE_ISSUES_EXAMPLE,
    result_example_sparse: schemas::AGILE_ISSUES_EXAMPLE_SPARSE,
    result_schema: schemas::AGILE_ISSUES_RESULT,
    ..MYSELF
};

pub(crate) const BACKLOG_ISSUES: OperationSpec = OperationSpec {
    id: "jira.backlog.issues",
    endpoint: Endpoint {
        path: "/rest/agile/1.0/board/{id}/backlog",
        ..SPRINT_ISSUES.endpoint
    },
    cli: CliBinding {
        noun_path: &["jira", "backlog", "issues"],
        ..SPRINT_ISSUES.cli
    },
    ..SPRINT_ISSUES
};
