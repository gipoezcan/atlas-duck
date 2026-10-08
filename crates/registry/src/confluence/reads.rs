//! The 11 Confluence read specs (§7.4), in table order.

use super::{DEFAULT_SUCCESS, NO_CAPS, NO_REDACTION, schemas};
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

const FORMAT_FLAG: FlagBinding = FlagBinding {
    param: "format",
    flag: "--format",
    kind: FlagKind::Str,
    file_variant: false,
};

/// §7.4: the server's own page parameters; `start`/`max` are agent params and core adds them.
const RESULTS_PAGE: PageSpec = PageSpec {
    items_key: "results",
    offset_param: "start",
    limit_param: "limit",
};

const fn max_caps(default: u32, hard_cap_default: u32) -> Caps {
    Caps {
        max: Some(MaxCap {
            param: "max",
            default,
            hard_cap_default,
            configurable: true,
        }),
        ..NO_CAPS
    }
}

/// `_links.*` of every result item (webui, download, self).
const ITEM_LINKS: RedactionRules = RedactionRules {
    copies: &[],
    mirrors: &[],
    url_fields: &["results[]._links.*"],
};

const EXPAND_PAGE: QueryParam = QueryParam {
    name: "expand",
    value: QueryValue::Const("body.storage,version,space,ancestors"),
};

const fn get(path: &'static str) -> Endpoint {
    Endpoint {
        method: Method::Get,
        path,
        query: &[],
        body: BodySource::None,
    }
}

pub(crate) const USER_CURRENT: OperationSpec = OperationSpec {
    id: "confluence.user.current",
    product: Product::Confluence,
    class: OpClass::Read,
    endpoint: get("/rest/api/user/current"),
    alt_endpoint: None,
    params_schema: schemas::EMPTY_PARAMS,
    cli: CliBinding {
        noun_path: &["confluence", "user", "current"],
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
    result_example: schemas::USER_CURRENT_EXAMPLE,
    result_example_sparse: schemas::USER_CURRENT_EXAMPLE_SPARSE,
    result_schema: schemas::USER_CURRENT_RESULT,
    write_guidance: false,
};

pub(crate) const SPACE_LIST: OperationSpec = OperationSpec {
    id: "confluence.space.list",
    endpoint: Endpoint {
        method: Method::Get,
        path: "/rest/api/space",
        query: &[QueryParam {
            name: "type",
            value: QueryValue::Param("type"),
        }],
        body: BodySource::None,
    },
    params_schema: schemas::SPACE_LIST_PARAMS,
    cli: CliBinding {
        noun_path: &["confluence", "space", "list"],
        positional: None,
        flags: &[
            START_FLAG,
            MAX_FLAG,
            FlagBinding {
                param: "type",
                flag: "--type",
                kind: FlagKind::Str,
                file_variant: false,
            },
        ],
    },
    caps: max_caps(25, 500),
    paginated: Some(RESULTS_PAGE),
    redaction_rules: ITEM_LINKS,
    result_example: schemas::SPACE_LIST_EXAMPLE,
    result_example_sparse: schemas::SPACE_LIST_EXAMPLE_SPARSE,
    result_schema: schemas::SPACE_LIST_RESULT,
    ..USER_CURRENT
};

pub(crate) const SPACE_GET: OperationSpec = OperationSpec {
    id: "confluence.space.get",
    endpoint: get("/rest/api/space/{key}"),
    params_schema: schemas::SPACE_GET_PARAMS,
    cli: CliBinding {
        noun_path: &["confluence", "space", "get"],
        positional: Some("key"),
        flags: &[],
    },
    target_params: &["key"],
    target_display: TargetDisplay::Param("key"),
    similarity: Similarity::Target,
    redaction_rules: RedactionRules {
        copies: &[],
        mirrors: &[],
        url_fields: &["_links.*"],
    },
    result_example: schemas::SPACE_GET_EXAMPLE,
    result_example_sparse: schemas::SPACE_GET_EXAMPLE_SPARSE,
    result_schema: schemas::SPACE_GET_RESULT,
    ..USER_CURRENT
};

pub(crate) const PAGE_GET: OperationSpec = OperationSpec {
    id: "confluence.page.get",
    endpoint: Endpoint {
        method: Method::Get,
        path: "/rest/api/content/{id}",
        // `format=view` swaps `body.storage` for `body.view` (core, from the param).
        query: &[EXPAND_PAGE],
        body: BodySource::None,
    },
    params_schema: schemas::PAGE_GET_PARAMS,
    cli: CliBinding {
        noun_path: &["confluence", "page", "get"],
        positional: Some("id"),
        flags: &[FORMAT_FLAG],
    },
    target_params: &["id"],
    target_display: TargetDisplay::Param("id"),
    similarity: Similarity::Target,
    redaction_rules: RedactionRules {
        copies: &[],
        mirrors: &[],
        url_fields: &["_links.*", "ancestors[]._links.*", "space._links.*", "self"],
    },
    result_example: schemas::PAGE_GET_EXAMPLE,
    result_example_sparse: schemas::PAGE_GET_EXAMPLE_SPARSE,
    result_schema: schemas::PAGE_GET_RESULT,
    ..USER_CURRENT
};

pub(crate) const PAGE_FIND: OperationSpec = OperationSpec {
    id: "confluence.page.find",
    endpoint: Endpoint {
        method: Method::Get,
        path: "/rest/api/content",
        query: &[
            QueryParam {
                name: "spaceKey",
                value: QueryValue::Param("space"),
            },
            QueryParam {
                name: "title",
                value: QueryValue::Param("title"),
            },
            QueryParam {
                name: "type",
                value: QueryValue::Const("page"),
            },
        ],
        body: BodySource::None,
    },
    params_schema: schemas::PAGE_FIND_PARAMS,
    cli: CliBinding {
        noun_path: &["confluence", "page", "find"],
        positional: None,
        flags: &[
            FlagBinding {
                param: "space",
                flag: "--space",
                kind: FlagKind::Str,
                file_variant: false,
            },
            FlagBinding {
                param: "title",
                flag: "--title",
                kind: FlagKind::Str,
                file_variant: false,
            },
        ],
    },
    redaction_rules: ITEM_LINKS,
    result_example: schemas::STUB_LIST_EXAMPLE,
    result_example_sparse: schemas::STUB_LIST_EXAMPLE_SPARSE,
    result_schema: schemas::STUB_LIST_RESULT,
    ..USER_CURRENT
};

pub(crate) const SEARCH: OperationSpec = OperationSpec {
    id: "confluence.search",
    endpoint: Endpoint {
        method: Method::Get,
        path: "/rest/api/search",
        query: &[
            QueryParam {
                name: "cql",
                value: QueryValue::Param("cql"),
            },
            QueryParam {
                name: "excerpt",
                value: QueryValue::Param("excerpt"),
            },
        ],
        body: BodySource::None,
    },
    params_schema: schemas::SEARCH_PARAMS,
    cli: CliBinding {
        noun_path: &["confluence", "search"],
        positional: Some("cql"),
        flags: &[
            START_FLAG,
            MAX_FLAG,
            FlagBinding {
                param: "excerpt",
                flag: "--excerpt",
                kind: FlagKind::Str,
                file_variant: false,
            },
        ],
    },
    target_display: TargetDisplay::Query { param: "cql" },
    caps: max_caps(25, 200),
    paginated: Some(RESULTS_PAGE),
    redaction_rules: RedactionRules {
        copies: &[],
        mirrors: &[],
        url_fields: &[
            "results[].url",
            "results[].content._links.*",
            "results[].resultGlobalContainer.displayUrl",
        ],
    },
    result_example: schemas::SEARCH_EXAMPLE,
    result_example_sparse: schemas::SEARCH_EXAMPLE_SPARSE,
    result_schema: schemas::SEARCH_RESULT,
    ..USER_CURRENT
};

pub(crate) const PAGE_CHILDREN: OperationSpec = OperationSpec {
    id: "confluence.page.children",
    endpoint: get("/rest/api/content/{id}/child/page"),
    params_schema: schemas::ID_PAGED_PARAMS,
    cli: CliBinding {
        noun_path: &["confluence", "page", "children"],
        positional: Some("id"),
        flags: &[START_FLAG, MAX_FLAG],
    },
    target_params: &["id"],
    target_display: TargetDisplay::Param("id"),
    similarity: Similarity::Target,
    caps: max_caps(25, 200),
    paginated: Some(RESULTS_PAGE),
    redaction_rules: ITEM_LINKS,
    result_example: schemas::STUB_LIST_EXAMPLE,
    result_example_sparse: schemas::STUB_LIST_EXAMPLE_SPARSE,
    result_schema: schemas::STUB_LIST_RESULT,
    ..USER_CURRENT
};

pub(crate) const COMMENT_LIST: OperationSpec = OperationSpec {
    id: "confluence.comment.list",
    endpoint: Endpoint {
        method: Method::Get,
        path: "/rest/api/content/{id}/child/comment",
        query: &[
            QueryParam {
                name: "expand",
                value: QueryValue::Const("body.storage,history,ancestors,version"),
            },
            QueryParam {
                name: "depth",
                value: QueryValue::Const("all"),
            },
        ],
        body: BodySource::None,
    },
    redaction_rules: RedactionRules {
        copies: &[],
        mirrors: &[],
        url_fields: &["results[]._links.*", "results[].ancestors[]._links.*"],
    },
    result_example: schemas::COMMENT_LIST_EXAMPLE,
    result_example_sparse: schemas::COMMENT_LIST_EXAMPLE_SPARSE,
    result_schema: schemas::COMMENT_LIST_RESULT,
    cli: CliBinding {
        noun_path: &["confluence", "comment", "list"],
        positional: Some("id"),
        flags: &[START_FLAG, MAX_FLAG],
    },
    ..PAGE_CHILDREN
};

pub(crate) const LABEL_LIST: OperationSpec = OperationSpec {
    id: "confluence.label.list",
    endpoint: get("/rest/api/content/{id}/label"),
    params_schema: schemas::ID_PARAMS,
    cli: CliBinding {
        noun_path: &["confluence", "label", "list"],
        positional: Some("id"),
        flags: &[],
    },
    caps: NO_CAPS,
    paginated: None,
    redaction_rules: NO_REDACTION,
    result_example: schemas::LABEL_LIST_EXAMPLE,
    result_example_sparse: schemas::LABEL_LIST_EXAMPLE_SPARSE,
    result_schema: schemas::LABEL_LIST_RESULT,
    ..PAGE_CHILDREN
};

/// Metadata only: the attachment bytes are never fetched.
pub(crate) const ATTACHMENT_LIST: OperationSpec = OperationSpec {
    id: "confluence.attachment.list",
    endpoint: get("/rest/api/content/{id}/child/attachment"),
    cli: CliBinding {
        noun_path: &["confluence", "attachment", "list"],
        positional: Some("id"),
        flags: &[],
    },
    redaction_rules: ITEM_LINKS,
    result_example: schemas::ATTACHMENT_LIST_EXAMPLE,
    result_example_sparse: schemas::ATTACHMENT_LIST_EXAMPLE_SPARSE,
    result_schema: schemas::ATTACHMENT_LIST_RESULT,
    ..LABEL_LIST
};

/// Exactly one call: the history summary, or with `version` the historical content (`alt_endpoint`).
pub(crate) const PAGE_HISTORY: OperationSpec = OperationSpec {
    id: "confluence.page.history",
    endpoint: Endpoint {
        method: Method::Get,
        path: "/rest/api/content/{id}/history",
        query: &[QueryParam {
            name: "expand",
            value: QueryValue::Const("lastUpdated,previousVersion,contributors.publishers"),
        }],
        body: BodySource::None,
    },
    alt_endpoint: Some(AltEndpoint {
        when_param_present: "version",
        endpoint: Endpoint {
            method: Method::Get,
            path: "/rest/api/content/{id}",
            query: &[
                QueryParam {
                    name: "version",
                    value: QueryValue::Param("version"),
                },
                QueryParam {
                    name: "status",
                    value: QueryValue::Const("historical"),
                },
                QueryParam {
                    name: "expand",
                    value: QueryValue::Const("body.storage,version"),
                },
            ],
            body: BodySource::None,
        },
    }),
    params_schema: schemas::PAGE_HISTORY_PARAMS,
    cli: CliBinding {
        noun_path: &["confluence", "page", "history"],
        positional: Some("id"),
        flags: &[
            FlagBinding {
                param: "version",
                flag: "--version",
                kind: FlagKind::Int,
                file_variant: false,
            },
            FORMAT_FLAG,
        ],
    },
    redaction_rules: RedactionRules {
        copies: &[],
        mirrors: &[],
        url_fields: &["_links.*", "self"],
    },
    result_example: schemas::PAGE_HISTORY_EXAMPLE,
    result_example_sparse: schemas::PAGE_HISTORY_EXAMPLE_SPARSE,
    result_schema: schemas::PAGE_HISTORY_RESULT,
    ..LABEL_LIST
};
